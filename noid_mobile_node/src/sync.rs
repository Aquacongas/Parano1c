// SPDX-License-Identifier: Apache-2.0

//! Mobile full-node synchronization core.
//!
//! This intentionally reuses the full-node networking primitives.
//!
//! Authority:
//!   durable MDBX canonical chain
//!       -> bounded HeaderDag
//!       -> cumulative-work fork choice
//!       -> immutable SyncPlan
//!       -> exact-object multi-peer fetch
//!
//! Transport identities never become consensus authority.

use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use libp2p::PeerId;
use tokio::sync::{Mutex, RwLock};

use noid_chain::{block_header::block_id, storage::MdbxChainContext};

use noid_networking::{
    chain_committer::ChainCommitter,
    header_dag::{HeaderDag, ValidatedHeader},
    suffix_sync::{ExactObjectRequest, FetchedSuffix, SuffixOffer, SuffixSync},
    types::{ChainPoint, FailureDomain},
};

use noid_p2p::{
    header_protocol::HeaderInventoryRecord,
    object_protocol::{ObjectId, ObjectPayload},
};

const HEADER_DAG_MAX_NODES: usize = 1024;

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

// ============================================================================
// DURABLE HEADER DAG
// ============================================================================

/// Reconstruct the exact bounded HeaderDag from durable canonical MDBX.
///
/// This mirrors the full-node startup path.
///
/// IMPORTANT:
/// A normal restart starts from the already verified LOCAL canonical chain.
/// Snapshot sync is NOT the normal restart authority.
pub fn canonical_header_dag(context: &MdbxChainContext) -> Result<HeaderDag> {
    let finalized = context.finalized_checkpoint();

    let finalized_work = context
        .store
        .get_chain_work(finalized.height)
        .context("load finalized mobile HeaderDag work")?
        .context("finalized mobile HeaderDag work is missing")?;

    let mut dag = HeaderDag::new(
        ChainPoint::new(finalized.height, finalized.hash),
        finalized_work,
        HEADER_DAG_MAX_NODES,
    );

    for height in finalized.height.saturating_add(1)..=context.tip_height() {
        let header = context
            .get_header_from_store(height)
            .with_context(|| format!("load canonical mobile HeaderDag row {height}"))?
            .with_context(|| format!("canonical mobile HeaderDag row {height} is missing"))?;

        let cumulative_work = context
            .store
            .get_chain_work(height)
            .with_context(|| format!("load canonical mobile HeaderDag work {height}"))?
            .with_context(|| format!("canonical mobile HeaderDag work {height} is missing"))?;

        dag.insert(ValidatedHeader::new_after_consensus_checks(
            header,
            cumulative_work,
        ))
        .map_err(|error| anyhow::anyhow!("reconstruct mobile HeaderDag at {height}: {error}"))?;
    }

    Ok(dag)
}

/// Reconcile a canonical MDBX commit with HeaderDag without throwing away
/// validated competing branches.
///
/// This follows the same full-node policy:
///
/// ordinary advancement/reorg:
///     incrementally update DAG
///
/// unusually large finalized jump:
///     reconstruct bounded DAG from durable canonical chain
pub fn reconcile_canonical_header_dag(
    context: &MdbxChainContext,
    dag: &mut HeaderDag,
) -> Result<()> {
    let finalized = context.finalized_checkpoint();

    let finalized_point = ChainPoint::new(finalized.height, finalized.hash);

    if finalized.height < dag.finalized().height
        || (finalized.height == dag.finalized().height && finalized_point != dag.finalized())
    {
        anyhow::bail!("durable finalized checkpoint conflicts with HeaderDag authority");
    }

    const MAX_INCREMENTAL_FINALITY_ADVANCE: u64 = 64;

    if finalized.height.saturating_sub(dag.finalized().height) > MAX_INCREMENTAL_FINALITY_ADVANCE {
        *dag = canonical_header_dag(context)?;

        return Ok(());
    }

    for height in dag.finalized().height.saturating_add(1)..=context.tip_height() {
        let header = context
            .get_header_from_store(height)
            .with_context(|| format!("load canonical mobile HeaderDag row {height}"))?
            .with_context(|| format!("canonical mobile HeaderDag row {height} is missing"))?;

        let hash = block_id(&header);

        if dag.get(&hash).is_some() {
            continue;
        }

        let cumulative_work = context
            .store
            .get_chain_work(height)
            .with_context(|| format!("load canonical mobile HeaderDag work {height}"))?
            .with_context(|| format!("canonical mobile HeaderDag work {height} is missing"))?;

        dag.insert(ValidatedHeader::new_after_consensus_checks(
            header,
            cumulative_work,
        ))
        .map_err(|error| {
            anyhow::anyhow!("advance canonical mobile HeaderDag at {height}: {error}")
        })?;
    }

    let finalized_work = context
        .store
        .get_chain_work(finalized.height)
        .context("load advanced finalized mobile HeaderDag work")?
        .context("advanced finalized mobile HeaderDag work is missing")?;

    dag.advance_finalized(finalized_point, finalized_work)
        .map_err(|error| {
            anyhow::anyhow!("advance finalized mobile HeaderDag checkpoint: {error}")
        })?;

    Ok(())
}

// ============================================================================
// EXACT SUFFIX ADMISSION
// ============================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MobileSuffixAdmission {
    Started,
    Merged,
    Duplicate,
    DeferredExtension,
    Replaced,
    KeptStrongerActive,
}

/// Control-plane + exact-object synchronization state.
///
/// This contains no miner, GUI or RPC responsibilities.
pub struct MobileSyncCoordinator {
    pub header_dag: Arc<RwLock<HeaderDag>>,

    active_suffix: Mutex<Option<SuffixSync>>,

    committer: Mutex<ChainCommitter>,
}

impl MobileSyncCoordinator {
    pub fn new(header_dag: Arc<RwLock<HeaderDag>>, committed_tip: ChainPoint) -> Self {
        Self {
            header_dag,
            active_suffix: Mutex::new(None),
            committer: Mutex::new(ChainCommitter::new(committed_tip)),
        }
    }

    /// Refresh control-plane authority after a successful canonical commit.
    pub async fn reconcile_from_chain(&self, context: &MdbxChainContext) -> Result<()> {
        {
            let mut dag = self.header_dag.write().await;

            reconcile_canonical_header_dag(context, &mut dag)?;
        }

        let tip = ChainPoint::new(context.tip_height(), context.tip_hash());

        self.committer.lock().await.observe_committed_tip(tip);

        Ok(())
    }

    pub async fn active_plan(&self) -> Option<noid_networking::sync_plan::SyncPlan> {
        self.active_suffix
            .lock()
            .await
            .as_ref()
            .map(|sync| sync.plan().clone())
    }

    pub async fn is_active(&self) -> bool {
        self.active_suffix.lock().await.is_some()
    }

    pub async fn clear_active(&self) {
        *self.active_suffix.lock().await = None;
    }

    /// Admit an immutable exact suffix selected by validated HeaderDag
    /// authority.
    ///
    /// Same ancestry extension does NOT discard already downloaded verified
    /// bytes. A genuinely stronger competing branch may replace the plan.
    pub async fn admit_offer(
        &self,
        peer: PeerId,
        failure_domain: FailureDomain,
        offer: SuffixOffer,
    ) -> Result<MobileSuffixAdmission> {
        use noid_chain::consensus::fork_choice::ChainChoice;

        let mut active = self.active_suffix.lock().await;

        let Some(current) = active.as_mut() else {
            *active = Some(
                SuffixSync::from_offer(peer, failure_domain, offer)
                    .map_err(|error| anyhow::anyhow!("{error}"))?,
            );

            return Ok(MobileSuffixAdmission::Started);
        };

        if current.plan_id() == offer.plan().id() {
            let added = current
                .add_offer(peer, failure_domain, offer)
                .map_err(|error| anyhow::anyhow!("{error}"))?;

            return Ok(if added > 0 {
                MobileSuffixAdmission::Merged
            } else {
                MobileSuffixAdmission::Duplicate
            });
        }

        // Do not throw away an immutable in-progress target merely because
        // HeaderDag has already learned about its descendant.
        //
        // IMPORTANT FOR LIVE FOLLOW:
        // the transport runtime must keep discovering providers for `current`
        // and must merge inventories using `current.plan().headers()`. The
        // descendant becomes eligible only after the current plan commits.
        if offer.plan().target() != current.plan().target()
            && offer.plan().contains_point(current.plan().target())
        {
            return Ok(MobileSuffixAdmission::DeferredExtension);
        }

        let candidate_work = offer
            .plan()
            .target_work()
            .context("candidate mobile suffix has no cumulative work")?;

        let active_work = current
            .plan()
            .target_work()
            .context("active mobile suffix has no cumulative work")?;

        if !matches!(
            noid_chain::choose_chain_by_work(
                &candidate_work,
                &offer.plan().target().hash,
                &active_work,
                &current.plan().target().hash,
            ),
            ChainChoice::A
        ) {
            return Ok(MobileSuffixAdmission::KeptStrongerActive);
        }

        *active = Some(
            SuffixSync::from_offer(peer, failure_domain, offer)
                .map_err(|error| anyhow::anyhow!("{error}"))?,
        );

        Ok(MobileSuffixAdmission::Replaced)
    }

    /// Convenience builder for a normal canonical extension.
    pub async fn admit_live_suffix(
        &self,
        peer: PeerId,
        failure_domain: FailureDomain,
        base: ChainPoint,
        headers: Vec<ValidatedHeader>,
        inventory: &[HeaderInventoryRecord],
    ) -> Result<MobileSuffixAdmission> {
        let offer = SuffixOffer::live(base, headers, inventory)
            .map_err(|error| anyhow::anyhow!("{error}"))?;

        self.admit_offer(peer, failure_domain, offer).await
    }

    /// Convenience builder for a non-final canonical reorganization.
    pub async fn admit_reorg_suffix(
        &self,
        peer: PeerId,
        failure_domain: FailureDomain,
        old_tip: ChainPoint,
        ancestor: ChainPoint,
        headers: Vec<ValidatedHeader>,
        inventory: &[HeaderInventoryRecord],
    ) -> Result<MobileSuffixAdmission> {
        let offer = SuffixOffer::reorg(old_tip, ancestor, headers, inventory)
            .map_err(|error| anyhow::anyhow!("{error}"))?;

        self.admit_offer(peer, failure_domain, offer).await
    }

    /// Merge another peer's exact-object availability into the SAME immutable
    /// plan.
    pub async fn add_inventory(
        &self,
        peer: PeerId,
        failure_domain: FailureDomain,
        headers: &[ValidatedHeader],
        records: &[HeaderInventoryRecord],
    ) -> Result<usize> {
        let mut active = self.active_suffix.lock().await;

        let sync = active.as_mut().context("no active mobile suffix")?;

        sync.add_inventory(peer, failure_domain, headers, records)
            .map_err(|error| anyhow::anyhow!("{error}"))
    }

    /// Produce all currently schedulable exact-object requests.
    ///
    /// Bodies and terminal may come from DIFFERENT peers.
    pub async fn schedule(&self) -> Vec<ExactObjectRequest> {
        let mut active = self.active_suffix.lock().await;

        match active.as_mut() {
            Some(sync) => sync.schedule(now_ms()),
            None => Vec::new(),
        }
    }

    // ========================================================================
    // NETWORK RESULT HANDLING
    // ========================================================================

    pub async fn accept_response(
        &self,
        token: u64,
        peer: PeerId,
        payloads: Vec<ObjectPayload>,
    ) -> Result<usize> {
        let mut active = self.active_suffix.lock().await;

        let sync = active.as_mut().context("no active mobile suffix")?;

        sync.accept_response(token, peer, payloads, None)
            .map_err(|error| anyhow::anyhow!("{error}"))
    }

    pub async fn request_busy(
        &self,
        token: u64,
        peer: PeerId,
        objects: &[ObjectId],
        retry_after_ms: u64,
    ) -> Result<()> {
        let mut active = self.active_suffix.lock().await;

        let sync = active.as_mut().context("no active mobile suffix")?;

        let retry_at = now_ms().saturating_add(retry_after_ms.max(100));

        sync.request_busy(token, peer, objects, retry_at)
            .map_err(|error| anyhow::anyhow!("{error}"))
    }

    pub async fn request_failed(
        &self,
        token: u64,
        peer: PeerId,
        objects: &[ObjectId],
    ) -> Result<()> {
        let mut active = self.active_suffix.lock().await;

        let sync = active.as_mut().context("no active mobile suffix")?;

        sync.request_failed(token, peer, objects, now_ms())
            .map_err(|error| anyhow::anyhow!("{error}"))
    }

    pub async fn request_unavailable(
        &self,
        token: u64,
        peer: PeerId,
        objects: &[ObjectId],
    ) -> Result<()> {
        let mut active = self.active_suffix.lock().await;

        let sync = active.as_mut().context("no active mobile suffix")?;

        sync.request_unavailable(token, peer, objects)
            .map_err(|error| anyhow::anyhow!("{error}"))
    }

    pub async fn defer_request(
        &self,
        token: u64,
        peer: PeerId,
        objects: &[ObjectId],
    ) -> Result<()> {
        let mut active = self.active_suffix.lock().await;

        let sync = active.as_mut().context("no active mobile suffix")?;

        sync.defer_request(token, peer, objects)
            .map_err(|error| anyhow::anyhow!("{error}"))
    }

    pub async fn disconnect(&self, peer: PeerId) {
        if let Some(sync) = self.active_suffix.lock().await.as_mut() {
            // IMPORTANT:
            // disconnect rotates transport only.
            // It does NOT erase the immutable plan or verified bytes.
            sync.disconnect(peer);
        }
    }

    pub async fn quarantine_provider(&self, peer: PeerId) {
        if let Some(sync) = self.active_suffix.lock().await.as_mut() {
            sync.quarantine_provider(peer);
        }
    }

    pub async fn is_complete(&self) -> bool {
        self.active_suffix
            .lock()
            .await
            .as_ref()
            .is_some_and(|sync| sync.is_complete())
    }

    /// Seal a completely fetched suffix.
    ///
    /// The caller then performs expensive recursive verification and atomic
    /// MDBX commit. No transport peer has authority at this point.
    pub async fn take_fetched(&self) -> Result<Option<FetchedSuffix>> {
        let mut active = self.active_suffix.lock().await;

        if !active.as_ref().is_some_and(|sync| sync.is_complete()) {
            return Ok(None);
        }

        let sync = active.take().context("complete suffix disappeared")?;

        let fetched = sync
            .into_fetched()
            .map_err(|error| anyhow::anyhow!("{error}"))?;

        Ok(Some(fetched))
    }

    pub async fn transport_stalled(&self) -> bool {
        self.active_suffix
            .lock()
            .await
            .as_ref()
            .is_some_and(|sync| sync.unfinished_transport_is_stalled(now_ms()))
    }

    pub async fn transport_extinct(&self) -> bool {
        self.active_suffix
            .lock()
            .await
            .as_ref()
            .is_some_and(SuffixSync::unfinished_transport_is_extinct)
    }
}
