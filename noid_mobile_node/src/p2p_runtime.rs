// SPDX-License-Identifier: Apache-2.0

//! Mobile full-node P2P transport runtime.
//!
//! This layer does NOT decide consensus.
//!
//! HeaderDag / SyncPlan decide WHAT to fetch.
//! This runtime only:
//! - maintains peers
//! - dispatches exact-object jobs
//! - correlates responses/failures
//! - preserves immutable suffix progress
//! - applies a complete fetched suffix

#[cfg(target_os = "android")]
fn android_sync_log(message: impl AsRef<str>) {
    use std::ffi::CString;
    use std::os::raw::{c_char, c_int};

    #[link(name = "log")]
    unsafe extern "C" {
        fn __android_log_write(prio: c_int, tag: *const c_char, text: *const c_char) -> c_int;
    }

    const ANDROID_LOG_INFO: c_int = 4;

    let Ok(tag) = CString::new("NOID_SYNC") else {
        return;
    };

    let message = message.as_ref().replace('\0', "?");

    let Ok(text) = CString::new(message) else {
        return;
    };

    unsafe {
        __android_log_write(ANDROID_LOG_INFO, tag.as_ptr(), text.as_ptr());
    }
}

#[cfg(not(target_os = "android"))]
#[inline]
fn android_sync_log(_message: impl AsRef<str>) {}

use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use libp2p::{gossipsub::MessageAcceptance, PeerId};
use tokio::sync::{Mutex, RwLock};

use noid_networking::{
    snapshot_header_staging::{
        CanonicalHeaderBoundary, SnapshotHeaderStaging, ValidatedSnapshotHeaderStaging,
    },
    snapshot_sync::SnapshotOffer,
    FailureDomain,
};

use noid_p2p::{NetworkCommand, NetworkEvent, NetworkEventRecvError, P2PNetwork};

use crate::MobileNodeRuntime;

const SCHEDULER_TICK_MS: u64 = 200;

#[derive(Debug, Clone, Copy)]
pub struct MobileP2PStatusSnapshot {
    pub peers: usize,
    pub phase: &'static str,
    pub syncing: bool,
}

static MOBILE_P2P_PEERS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

static MOBILE_P2P_PHASE: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);

pub fn mobile_p2p_status() -> MobileP2PStatusSnapshot {
    use std::sync::atomic::Ordering;

    let peers = MOBILE_P2P_PEERS.load(Ordering::Acquire);

    let phase_id = MOBILE_P2P_PHASE.load(Ordering::Acquire);

    let phase = match phase_id {
        1 => "MANIFEST",
        2 => "HEADERS",
        3 => "STATE",
        4 => "TAIL",
        5 => "SYNCED",
        _ if peers == 0 => "WAITING",
        _ => "CONNECTING",
    };

    MobileP2PStatusSnapshot {
        peers,
        phase,
        syncing: !matches!(phase, "WAITING" | "SYNCED"),
    }
}

fn publish_mobile_sync_phase(phase: u8) {
    MOBILE_P2P_PHASE.store(phase, std::sync::atomic::Ordering::Release);
}

fn publish_mobile_peer_count(peers: usize) {
    MOBILE_P2P_PEERS.store(peers, std::sync::atomic::Ordering::Release);
}

/// Resolve manual GossipSub validation only after authoritative local
/// mempool admission has completed.
///
/// Direct request/response relays carry `None` and therefore require no
/// GossipSub result.
fn resolve_tx_gossip(
    p2p_cmd: &noid_p2p::NetworkCommandSender,
    propagation_source: PeerId,
    message_id: Option<libp2p::gossipsub::MessageId>,
    acceptance: MessageAcceptance,
) {
    let Some(message_id) = message_id else {
        return;
    };

    if let Err(error) = p2p_cmd.try_send(NetworkCommand::ResolveTxGossip {
        message_id,
        propagation_source,
        acceptance,
    }) {
        tracing::debug!(
            peer = %propagation_source,
            %error,
            "mobile tx gossip validation result could not be queued"
        );
    }
}

/// Map mempool admission failures to GossipSub validation semantics.
///
/// Soft failures do not prove that the peer sent an invalid transaction.
/// Examples:
///
/// - already present locally;
/// - local pool currently full;
/// - local byte capacity exhausted;
/// - transient slot conflict.
///
/// These are ignored rather than penalizing the peer.
///
/// Hard failures such as malformed wire data, invalid authorization or
/// consensus-invalid semantics are rejected.
fn gossip_acceptance_for_submit_error(error: &noid_mempool::SubmitError) -> MessageAcceptance {
    if error.is_soft() {
        MessageAcceptance::Ignore
    } else {
        MessageAcceptance::Reject
    }
}

#[inline]
fn gap_requires_snapshot_sync(local_height: u64, peer_height: u64) -> bool {
    peer_height
        > local_height.saturating_add(noid_chain::consensus::params::RETAINED_BLOCK_SERVING_DEPTH)
}

#[derive(Clone, Copy, Debug)]
pub struct MobilePeer {
    pub failure_domain: FailureDomain,
    pub locally_selected: bool,
}

#[derive(Debug, Clone)]
enum MobileBootstrapStage {
    Idle,

    WaitingManifest {
        generation: u64,
        peer: PeerId,
    },

    ManifestReceived {
        generation: u64,
        peer: PeerId,
        boundary_height: u64,
        boundary_hash: [u8; 32],
        manifest_digest: [u8; 32],
    },

    StagingHeaders {
        generation: u64,
        token: u64,
        peer: PeerId,
        next_height: u64,
        boundary_height: u64,
        boundary_hash: [u8; 32],
        boundary_chainwork: [u8; 32],
        manifest_digest: [u8; 32],
    },

    WaitingTerminal {
        generation: u64,
        peer: PeerId,
        boundary_height: u64,
        boundary_hash: [u8; 32],
        manifest_digest: [u8; 32],
    },

    SyncingSnapshot {
        generation: u64,
        boundary_height: u64,
        boundary_hash: [u8; 32],
    },

    Installing,

    TailSync {
        boundary_height: u64,
        peer: PeerId,

        /// Exactly one forward header request owned by TailSync.
        inflight_start: Option<u64>,
        inflight_since: Option<Instant>,

        /// A non-empty TailSync batch was accepted from `waiting_start`, but
        /// canonical MDBX has not advanced through that start height yet.
        /// While this is set, provider discovery / exact-object sync owns the
        /// next step and the tail driver must not spam the same range.
        waiting_start: Option<u64>,
        waiting_since: Option<Instant>,

        /// Highest network height observed from a correlated tail batch or a
        /// live header announcement. This is a hint, never consensus authority.
        observed_frontier: u64,

        /// Empty response to the exact probe at this start height. Bootstrap
        /// completes only if it is still `local_height + 1` and no higher
        /// frontier has been observed.
        empty_probe_start: Option<u64>,
    },

    Complete,
}

impl Default for MobileBootstrapStage {
    fn default() -> Self {
        Self::Idle
    }
}

pub struct MobileP2PRuntime {
    node: Arc<MobileNodeRuntime>,

    network: Arc<P2PNetwork>,

    peers: Arc<RwLock<HashMap<PeerId, MobilePeer>>>,

    /// Initial state bootstrap state machine.
    bootstrap: Mutex<MobileBootstrapStage>,

    /// True only after authenticated snapshot + exact tail catch-up.
    bootstrap_complete_flag: Arc<std::sync::atomic::AtomicBool>,

    /// Writable native-validated snapshot header candidate.
    snapshot_header_staging: Mutex<Option<SnapshotHeaderStaging>>,

    /// Sealed authenticated snapshot header candidate.
    validated_snapshot_headers: Mutex<Option<ValidatedSnapshotHeaderStaging>>,

    /// Immutable manifest selected for the active bootstrap.
    snapshot_offer: Mutex<Option<SnapshotOffer>>,

    /// Fully verified HistoryStep authority for the selected snapshot.
    verified_snapshot_boundary: Mutex<Option<noid_chain::VerifiedSnapshotBoundary>>,

    /// Exact immutable State-segment transport plan.
    active_snapshot_sync: Mutex<Option<noid_networking::snapshot_sync::SnapshotSync>>,

    /// Authenticated State segments staged on disk before atomic MDBX install.
    active_snapshot_staging: Mutex<Option<noid_chain::storage::SnapshotStagingSession>>,

    /// Monotonic local correlation generation for snapshot requests.
    bootstrap_generation: Mutex<u64>,

    /// Prevent two event-loop branches from racing a complete suffix into
    /// apply_exact_suffix().
    apply_inflight: Mutex<bool>,

    /// Deduplicate bounded provider-discovery header probes for the active
    /// immutable suffix in both bootstrap TailSync and steady-state live follow.
    ///
    /// Key = (base_height, target_height).
    tail_provider_probes: Mutex<HashMap<(u64, u64), Instant>>,
}

impl MobileP2PRuntime {
    pub fn new(node: Arc<MobileNodeRuntime>, network: Arc<P2PNetwork>) -> Self {
        Self {
            node,
            network,
            peers: Arc::new(RwLock::new(HashMap::new())),
            bootstrap: Mutex::new(MobileBootstrapStage::Idle),
            bootstrap_complete_flag: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            snapshot_header_staging: Mutex::new(None),
            validated_snapshot_headers: Mutex::new(None),
            snapshot_offer: Mutex::new(None),
            verified_snapshot_boundary: Mutex::new(None),
            active_snapshot_sync: Mutex::new(None),
            active_snapshot_staging: Mutex::new(None),
            bootstrap_generation: Mutex::new(0),
            apply_inflight: Mutex::new(false),
            tail_provider_probes: Mutex::new(HashMap::new()),
        }
    }

    pub fn network(&self) -> &Arc<P2PNetwork> {
        &self.network
    }

    pub async fn peer_count(&self) -> usize {
        self.peers.read().await.len()
    }

    pub async fn peer_failure_domain(&self, peer: PeerId) -> Option<FailureDomain> {
        self.peers
            .read()
            .await
            .get(&peer)
            .map(|entry| entry.failure_domain)
    }

    async fn begin_snapshot_bootstrap(&self, peer: PeerId) -> Result<()> {
        let local_height = self.node.tip_height().await;

        let generation = {
            let mut generation = self.bootstrap_generation.lock().await;
            *generation = generation.saturating_add(1);
            *generation
        };

        {
            let mut stage = self.bootstrap.lock().await;

            if matches!(
                *stage,
                MobileBootstrapStage::WaitingManifest { .. }
                    | MobileBootstrapStage::ManifestReceived { .. }
                    | MobileBootstrapStage::StagingHeaders { .. }
                    | MobileBootstrapStage::WaitingTerminal { .. }
                    | MobileBootstrapStage::SyncingSnapshot { .. }
                    | MobileBootstrapStage::Installing
            ) {
                return Ok(());
            }

            *stage = MobileBootstrapStage::WaitingManifest { generation, peer };
        }

        self.bootstrap_complete_flag
            .store(false, std::sync::atomic::Ordering::Release);
        self.tail_provider_probes.lock().await.clear();
        publish_mobile_sync_phase(1);

        let requested_manifest_digest = [0u8; 32];

        android_sync_log(format!(
            "SNAPSHOT SWITCH manifest_request generation={} peer={} local_height={}",
            generation, peer, local_height
        ));

        if let Err(error) = self
            .network
            .cmd_tx
            .send(NetworkCommand::RequestStateManifest {
                generation,
                peer,
                requester_height: local_height,
                requested_manifest_digest,
            })
            .await
        {
            let mut stage = self.bootstrap.lock().await;
            if matches!(
                *stage,
                MobileBootstrapStage::WaitingManifest {
                    generation: active_generation,
                    peer: active_peer,
                } if active_generation == generation && active_peer == peer
            ) {
                *stage = MobileBootstrapStage::Idle;
            }

            return Err(error).context("queue mobile State manifest request");
        }

        tracing::info!(
            generation,
            peer = %peer,
            requester_height = local_height,
            "mobile snapshot manifest requested"
        );

        Ok(())
    }

    async fn begin_initial_bootstrap(&self, peer: PeerId) -> Result<()> {
        let local_height = self.node.tip_height().await;

        if local_height == 0 {
            return self.begin_snapshot_bootstrap(peer).await;
        }

        let mut stage = self.bootstrap.lock().await;

        if !matches!(*stage, MobileBootstrapStage::Idle) {
            return Ok(());
        }

        let start_height = local_height.saturating_add(1);

        *stage = MobileBootstrapStage::TailSync {
            boundary_height: local_height,
            peer,
            inflight_start: None,
            inflight_since: None,
            waiting_start: None,
            waiting_since: None,
            observed_frontier: local_height,
            empty_probe_start: None,
        };

        self.bootstrap_complete_flag
            .store(false, std::sync::atomic::Ordering::Release);
        publish_mobile_sync_phase(4);

        android_sync_log(format!(
            "TAIL RESUME durable_height={} start={} peer={}",
            local_height, start_height, peer
        ));

        Ok(())
    }

    async fn dispatch_next_snapshot_segment(&self) -> Result<()> {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let mut sync_guard = self.active_snapshot_sync.lock().await;

        let Some(sync) = sync_guard.as_mut() else {
            return Ok(());
        };

        // Full node deliberately keeps one large State response
        // in flight at a time.
        for request in sync.schedule(now_ms, 1) {
            let command = NetworkCommand::RequestStateSegment {
                peer: request.peer,

                segment_id: request.segment.segment_id,

                expected_tip_height: request.segment.snapshot.boundary.height,

                expected_tip_hash: request.segment.snapshot.boundary.hash,

                manifest_digest: request.segment.snapshot.manifest_digest,
            };

            if self.network.cmd_tx.try_send(command).is_err() {
                sync.defer_request(request)
                    .context("defer mobile State segment behind local P2P capacity")?;
            }
        }

        Ok(())
    }

    async fn install_completed_snapshot(&self, observer_peer: PeerId) -> Result<u64> {
        // --------------------------------------------------------
        // The transport plan must say that every exact segment was
        // authenticated before State can enter canonical MDBX.
        // --------------------------------------------------------

        {
            let sync_guard = self.active_snapshot_sync.lock().await;

            let Some(sync) = sync_guard.as_ref() else {
                anyhow::bail!("mobile snapshot transport disappeared before install");
            };

            if !sync.all_segments_verified() {
                anyhow::bail!(
                    "mobile snapshot install attempted before every segment was verified"
                );
            }
        }

        *self.bootstrap.lock().await = MobileBootstrapStage::Installing;

        // Transport authority is no longer needed after every required
        // object reached Verified state.
        let _completed_sync = self
            .active_snapshot_sync
            .lock()
            .await
            .take()
            .ok_or_else(|| anyhow::anyhow!("completed mobile SnapshotSync missing"))?;

        let staging = self
            .active_snapshot_staging
            .lock()
            .await
            .take()
            .ok_or_else(|| anyhow::anyhow!("completed mobile State staging missing"))?;

        let boundary = self
            .verified_snapshot_boundary
            .lock()
            .await
            .take()
            .ok_or_else(|| anyhow::anyhow!("verified mobile snapshot boundary missing"))?;

        let mut headers = self
            .validated_snapshot_headers
            .lock()
            .await
            .take()
            .ok_or_else(|| anyhow::anyhow!("validated mobile snapshot headers missing"))?;

        // --------------------------------------------------------
        // Finalize re-opens every staged segment and independently
        // rebuilds exact State root + active count.
        // --------------------------------------------------------

        let finalized = tokio::task::spawn_blocking(move || staging.finalize())
            .await
            .context("join mobile State snapshot finalization")?
            .context("finalize mobile State snapshot")?;

        let target_height = finalized.metadata().header().height;

        let target_hash = finalized.metadata().tip_hash();

        tracing::info!(
            target_height,
            target_hash =
                %hex::encode(
                    target_hash
                ),
            "mobile snapshot State fully finalized"
        );

        // --------------------------------------------------------
        // Sole canonical writer gate.
        //
        // SEND and exact suffix commits cannot cross this install.
        // --------------------------------------------------------

        let _apply = self.node.apply_gate.lock().await;

        {
            let mut chain = self.node.chain.write().await;

            // Fresh mobile bootstrap is a direct continuation from
            // the locally authenticated base. We do not permit an
            // arbitrary non-final replacement here.
            chain
                .apply_staged_state_snapshot(&finalized, &boundary, &mut headers, false)
                .context("atomically install authenticated mobile snapshot into MDBX")?;

            tracing::info!(
                height =
                    chain.tip_height(),
                hash =
                    %hex::encode(
                        chain.tip_hash()
                    ),
                "mobile MDBX snapshot install COMMITTED"
            );
        }

        // finalized/header/boundary handles can now fall out of scope;
        // canonical durable state owns the installed snapshot.

        // --------------------------------------------------------
        // Refresh every runtime view from the new canonical MDBX.
        // --------------------------------------------------------

        self.node.refresh_mempool_chain_view().await;

        self.node
            .reconcile_sync_after_commit()
            .await
            .context("reconcile mobile HeaderDag after snapshot install")?;

        // --------------------------------------------------------
        // Reload the ACTIVE wallet owner from verified MDBX.
        //
        // AVAILABLE BALANCE is discovered separately; SEND remains
        // active-address-only.
        // --------------------------------------------------------

        let (reserved_inputs, reserved_outputs) = self.node.mempool.reserved_slots().await;

        let (active_index, next_index, owner) = {
            let wallet_guard = self
                .node
                .wallet
                .lock()
                .map_err(|_| anyhow::anyhow!("wallet state lock is poisoned"))?;

            let wallet = wallet_guard
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("wallet is not loaded"))?;

            (
                wallet.active_index,
                wallet.next_index,
                wallet.active_address().0,
            )
        };

        let owner_snapshot = {
            let chain = self.node.chain.read().await;

            chain
                .store
                .get_verified_utxos_by_owner(&owner)
                .map_err(|error| {
                    anyhow::anyhow!("reload active wallet owner after snapshot install: {error}")
                })?
        };

        {
            let mut wallet_guard = self
                .node
                .wallet
                .lock()
                .map_err(|_| anyhow::anyhow!("wallet state lock is poisoned"))?;

            let wallet = wallet_guard
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("wallet is not loaded"))?;

            wallet
                .commit_verified_activation(
                    active_index,
                    next_index,
                    active_index,
                    owner,
                    owner_snapshot,
                    &reserved_inputs,
                    &reserved_outputs,
                )
                .map_err(|error| {
                    anyhow::anyhow!("reload active wallet after snapshot install: {error}")
                })?;
        }

        tracing::info!(
            target_height,
            "mobile wallet/mempool/HeaderDag refreshed after snapshot"
        );

        // --------------------------------------------------------
        // Immediately begin post-snapshot exact tail.
        //
        // Do not wait for a future gossip announcement.
        // Existing HeaderInventoryBatch -> exact suffix code takes
        // over from here.
        // --------------------------------------------------------

        let start_height = target_height.saturating_add(1);

        android_sync_log(format!(
            "TAIL START boundary={} start={} peer={}",
            target_height, start_height, observer_peer
        ));

        let queued = self
            .network
            .cmd_tx
            .try_send(NetworkCommand::FetchHeaders {
                peer: observer_peer,
                start_height,
                count: 512,
            })
            .is_ok();

        *self.bootstrap.lock().await = MobileBootstrapStage::TailSync {
            boundary_height: target_height,
            peer: observer_peer,
            inflight_start: queued.then_some(start_height),
            inflight_since: queued.then(Instant::now),
            waiting_start: None,
            waiting_since: None,
            observed_frontier: target_height,
            empty_probe_start: None,
        };

        publish_mobile_sync_phase(4);

        if queued {
            android_sync_log(format!(
                "TAIL REQUEST QUEUED start={} count=512 peer={}",
                start_height, observer_peer
            ));
        } else {
            android_sync_log(format!(
                "TAIL REQUEST LOCAL CAPACITY start={} - ticker will retry",
                start_height
            ));
        }

        tracing::info!(
            peer = %observer_peer,
            start_height,
            queued,
            "mobile post-snapshot exact tail started"
        );

        Ok(target_height)
    }

    pub fn bootstrap_complete_flag(&self) -> Arc<std::sync::atomic::AtomicBool> {
        Arc::clone(&self.bootstrap_complete_flag)
    }

    async fn note_tail_header_batch(
        &self,
        from: PeerId,
        records: &[noid_p2p::header_protocol::HeaderInventoryRecord],
    ) {
        let mut stage = self.bootstrap.lock().await;

        let MobileBootstrapStage::TailSync {
            peer,
            inflight_start,
            inflight_since,
            waiting_start,
            waiting_since,
            observed_frontier,
            empty_probe_start,
            ..
        } = &mut *stage
        else {
            return;
        };

        // The dedicated tail peer is intentionally kept out of provider
        // discovery, so only a currently outstanding TailSync request may
        // consume a batch from this peer. Any stale/unsolicited batch is left
        // to the normal header planner but must not mutate TailSync state.
        if *peer != from {
            return;
        }

        let Some(expected_start) = *inflight_start else {
            android_sync_log(format!(
                "TAIL BATCH UNCORRELATED peer={} records={} - planner only",
                from,
                records.len()
            ));
            return;
        };

        if let Some(first) = records.first() {
            if first.header.height != expected_start {
                android_sync_log(format!(
                    "TAIL BATCH UNCORRELATED peer={} expected_start={} received_start={} records={}",
                    from,
                    expected_start,
                    first.header.height,
                    records.len()
                ));
                return;
            }
        }

        *inflight_start = None;
        *inflight_since = None;

        if records.is_empty() {
            *waiting_start = None;
            *waiting_since = None;
            *empty_probe_start = Some(expected_start);

            android_sync_log(format!(
                "TAIL EMPTY PROBE peer={} start={}",
                from, expected_start
            ));
            return;
        }

        let returned_height = records
            .last()
            .map(|record| record.header.height)
            .unwrap_or(expected_start.saturating_sub(1));

        *observed_frontier = (*observed_frontier).max(returned_height);
        *waiting_start = Some(expected_start);
        *waiting_since = Some(Instant::now());
        *empty_probe_start = None;

        android_sync_log(format!(
            "TAIL BATCH ACCEPTED peer={} start={} end={} records={}",
            from,
            expected_start,
            returned_height,
            records.len()
        ));
    }

    /// Return true while authenticated snapshot bootstrap owns the control
    /// plane. Header/tail events from an older generation must not replace it.
    async fn snapshot_bootstrap_active(&self) -> bool {
        matches!(
            *self.bootstrap.lock().await,
            MobileBootstrapStage::WaitingManifest { .. }
                | MobileBootstrapStage::ManifestReceived { .. }
                | MobileBootstrapStage::StagingHeaders { .. }
                | MobileBootstrapStage::WaitingTerminal { .. }
                | MobileBootstrapStage::SyncingSnapshot { .. }
                | MobileBootstrapStage::Installing
        )
    }

    /// Ask a small bounded peer set for the exact header/inventory range of
    /// the CURRENT immutable suffix. This is provider recovery, not a new sync
    /// plan: verified bytes and the active target remain untouched.
    async fn probe_active_suffix_providers(&self, reason: &'static str) {
        let Some(plan) = self.node.sync.active_plan().await else {
            return;
        };

        let headers = plan.headers();
        let Some(first) = headers.first() else {
            return;
        };

        let base_height = first.point().height.saturating_sub(1);

        let target_height = plan.target().height;

        let probe_key = (base_height, target_height);

        let now = Instant::now();

        {
            let mut probes = self.tail_provider_probes.lock().await;

            probes.retain(|_, sent| now.duration_since(*sent) < Duration::from_secs(20));

            if probes
                .get(&probe_key)
                .is_some_and(|sent| now.duration_since(*sent) < Duration::from_secs(3))
            {
                return;
            }

            probes.insert(probe_key, now);
        }

        let peers = self.peers.read().await.keys().copied().collect::<Vec<_>>();

        let count = headers.len().saturating_add(1).min(512) as u16;

        let mut queued = 0usize;

        // Keep this deliberately small. The full-node model relies on bounded
        // provider discovery, not fanout to every connected peer.
        for peer in peers.into_iter().take(4) {
            if self
                .network
                .cmd_tx
                .try_send(NetworkCommand::FetchHeaders {
                    peer,
                    start_height: base_height,
                    count,
                })
                .is_ok()
            {
                queued += 1;
            }
        }

        android_sync_log(format!(
            "LIVE PROVIDER PROBE reason={} base={} target={} queued={}",
            reason, base_height, target_height, queued
        ));
    }

    /// Steady-state exact-tip recovery.
    ///
    /// Once bootstrap is complete, announcements are only hints about a newer
    /// frontier while an immutable suffix is active. If transport for that
    /// suffix stalls or loses all providers, rediscover providers for the SAME
    /// range instead of launching competing header plans.
    async fn drive_live_suffix_recovery(&self) {
        let bootstrap_complete =
            matches!(*self.bootstrap.lock().await, MobileBootstrapStage::Complete);

        if !bootstrap_complete {
            return;
        }

        if self.node.sync.active_plan().await.is_none() {
            return;
        }

        if self.node.sync.transport_stalled().await {
            self.probe_active_suffix_providers("stalled").await;
        } else if self.node.sync.transport_extinct().await {
            self.probe_active_suffix_providers("extinct").await;
        }
    }

    async fn drive_bootstrap_tail(&self) -> Result<()> {
        // Immutable exact-object sync and canonical application always outrank
        // further header probing. Header acquisition resumes only after that
        // plan has committed or failed/retired.
        if self.node.sync.active_plan().await.is_some() {
            return Ok(());
        }

        if *self.apply_inflight.lock().await {
            return Ok(());
        }

        let local_height = self.node.tip_height().await;
        let now = Instant::now();

        let (
            preferred_peer,
            inflight_start,
            inflight_since,
            waiting_start,
            waiting_since,
            observed_frontier,
            empty_probe_start,
        ) = {
            let stage = self.bootstrap.lock().await;

            let MobileBootstrapStage::TailSync {
                peer,
                inflight_start,
                inflight_since,
                waiting_start,
                waiting_since,
                observed_frontier,
                empty_probe_start,
                ..
            } = *stage
            else {
                return Ok(());
            };

            (
                peer,
                inflight_start,
                inflight_since,
                waiting_start,
                waiting_since,
                observed_frontier,
                empty_probe_start,
            )
        };

        // Exact suffix bodies are only guaranteed inside the retained serving
        // window. The desktop full node switches to authenticated snapshot sync
        // when the selected/observed peer tip is farther away than that window.
        if gap_requires_snapshot_sync(local_height, observed_frontier) {
            android_sync_log(format!(
                "TAIL GAP REQUIRES SNAPSHOT local_height={} observed_frontier={} retained_depth={}",
                local_height,
                observed_frontier,
                noid_chain::consensus::params::RETAINED_BLOCK_SERVING_DEPTH
            ));

            {
                let mut stage = self.bootstrap.lock().await;
                if matches!(*stage, MobileBootstrapStage::TailSync { .. }) {
                    *stage = MobileBootstrapStage::Idle;
                }
            }

            return self.begin_snapshot_bootstrap(preferred_peer).await;
        }

        // An empty exact probe is completion evidence only if the probe is
        // still immediately above our durable tip and no higher network height
        // has been observed meanwhile. A stale peer cannot mark us SYNCED.
        if let Some(probe_start) = empty_probe_start {
            if probe_start == local_height.saturating_add(1) && observed_frontier <= local_height {
                android_sync_log(format!(
                    "TAIL COMPLETE local_height={} empty_probe_start={}",
                    local_height, probe_start
                ));

                self.network
                    .cmd_tx
                    .send(NetworkCommand::BootstrapComplete)
                    .await
                    .context("publish mobile BootstrapComplete")?;

                *self.bootstrap.lock().await = MobileBootstrapStage::Complete;

                self.bootstrap_complete_flag
                    .store(true, std::sync::atomic::Ordering::Release);

                publish_mobile_sync_phase(5);

                // Bootstrap is finished; mempool synchronization may now use
                // spare request capacity without competing with chain catch-up.
                let peers = self
                    .peers
                    .read()
                    .await
                    .keys()
                    .copied()
                    .take(4)
                    .collect::<Vec<_>>();
                for peer in peers {
                    let _ = self
                        .network
                        .cmd_tx
                        .try_send(NetworkCommand::RequestMempoolSync { peer });
                }

                tracing::info!(local_height, "MOBILE INITIAL SYNC COMPLETE");
                return Ok(());
            }

            let mut stage = self.bootstrap.lock().await;
            if let MobileBootstrapStage::TailSync {
                empty_probe_start, ..
            } = &mut *stage
            {
                *empty_probe_start = None;
            }
        }

        // A correlated non-empty batch has already been handed to the native
        // planner. Give provider discovery / suffix admission time to make
        // canonical progress instead of re-requesting the same range every
        // scheduler tick. As soon as MDBX advances into that range we can
        // request again from local_height + 1, which naturally drives planner
        // chunking across consensus boundaries.
        if let Some(start) = waiting_start {
            if local_height >= start {
                let mut stage = self.bootstrap.lock().await;
                if let MobileBootstrapStage::TailSync {
                    waiting_start,
                    waiting_since,
                    ..
                } = &mut *stage
                {
                    *waiting_start = None;
                    *waiting_since = None;
                }

                android_sync_log(format!(
                    "TAIL CANONICAL PROGRESS start={} local_height={}",
                    start, local_height
                ));
            } else if waiting_since
                .is_some_and(|since| now.duration_since(since) < Duration::from_secs(15))
            {
                return Ok(());
            } else {
                // No suffix was admitted/committed for this batch. Release the
                // wait and retry the exact header start, preferably through a
                // different connected peer. This is bounded recovery, not a
                // per-tick retry loop.
                let mut stage = self.bootstrap.lock().await;
                if let MobileBootstrapStage::TailSync {
                    waiting_start,
                    waiting_since,
                    peer,
                    ..
                } = &mut *stage
                {
                    *waiting_start = None;
                    *waiting_since = None;

                    if let Some(alternate) = self
                        .peers
                        .read()
                        .await
                        .keys()
                        .copied()
                        .find(|candidate| *candidate != *peer)
                    {
                        *peer = alternate;
                    }
                }

                android_sync_log(format!(
                    "TAIL RETAINED PLAN RETRY start={} local_height={}",
                    start, local_height
                ));
            }
        }

        if let Some(start) = inflight_start {
            if match inflight_since {
                None => true,
                Some(since) => now.duration_since(since) < Duration::from_secs(10),
            } {
                return Ok(());
            }

            let mut stage = self.bootstrap.lock().await;
            if let MobileBootstrapStage::TailSync {
                inflight_start,
                inflight_since,
                ..
            } = &mut *stage
            {
                if *inflight_start == Some(start) {
                    *inflight_start = None;
                    *inflight_since = None;
                }
            }

            android_sync_log(format!("TAIL REQUEST TIMEOUT start={} - retrying", start));
        }

        let peer = {
            let peers = self.peers.read().await;

            if peers.contains_key(&preferred_peer) {
                Some(preferred_peer)
            } else {
                peers.keys().copied().next()
            }
        };

        let Some(peer) = peer else {
            return Ok(());
        };

        let start_height = local_height.saturating_add(1);

        let queued = self
            .network
            .cmd_tx
            .try_send(NetworkCommand::FetchHeaders {
                peer,
                start_height,
                count: 512,
            })
            .is_ok();

        {
            let mut stage = self.bootstrap.lock().await;

            if let MobileBootstrapStage::TailSync {
                peer: active_peer,
                inflight_start,
                inflight_since,
                empty_probe_start,
                ..
            } = &mut *stage
            {
                *active_peer = peer;
                *inflight_start = queued.then_some(start_height);
                *inflight_since = queued.then(Instant::now);
                *empty_probe_start = None;
            }
        }

        if queued {
            android_sync_log(format!("TAIL REQUEST start={} peer={}", start_height, peer));
        }

        Ok(())
    }

    /// Send every currently schedulable immutable exact-object job.
    ///
    /// If the bounded P2P command lane is full, undo only that local request.
    /// The semantic suffix and already verified bytes remain intact.
    pub async fn dispatch_exact_requests(&self) {
        let requests = self.node.sync.schedule().await;

        for request in requests {
            if self
                .network
                .cmd_tx
                .try_send(NetworkCommand::FetchObjects {
                    token: request.token,
                    peer: request.peer,
                    objects: request.objects.clone(),
                })
                .is_err()
            {
                if let Err(error) = self
                    .node
                    .sync
                    .defer_request(request.token, request.peer, &request.objects)
                    .await
                {
                    tracing::debug!(
                        token = request.token,
                        peer = %request.peer,
                        %error,
                        "mobile exact-object defer failed"
                    );
                }
            }
        }
    }

    async fn maybe_apply_complete_suffix(&self) -> Result<()> {
        if !self.node.sync.is_complete().await {
            return Ok(());
        }

        {
            let mut inflight = self.apply_inflight.lock().await;

            if *inflight {
                return Ok(());
            }

            *inflight = true;
        }

        let result = async {
            let Some(fetched) = self.node.sync.take_fetched().await? else {
                return Ok(());
            };

            let announcement = fetched.tip_announcement();

            let applied = self
                .node
                .apply_fetched_suffix(fetched)
                .await
                .context("mobile exact suffix verification/commit failed")?;

            match &applied {
                noid_sync_apply::AppliedExactSuffix::Live(result) => {
                    android_sync_log(format!(
                        "TAIL EXACT COMMIT height={} blocks={}",
                        result.height, result.applied_blocks
                    ));

                    tracing::info!(
                        height = result.height,
                        hash = %hex::encode(result.block_hash),
                        blocks = result.applied_blocks,
                        payload_bytes = result.payload_bytes,
                        "mobile live exact suffix committed"
                    );
                }

                noid_sync_apply::AppliedExactSuffix::Reorg(result) => {
                    android_sync_log(format!(
                        "TAIL EXACT REORG COMMIT height={}",
                        result.view.tip_height
                    ));

                    tracing::info!(
                        height = result.view.tip_height,
                        hash = %hex::encode(result.view.tip_hash),
                        "mobile atomic exact reorg committed"
                    );
                }
            }

            // Canonical progress retires the batch wait. The scheduler will
            // continue from the new durable tip on its next tick.
            let committed_height = self.node.tip_height().await;
            {
                let mut stage = self.bootstrap.lock().await;
                if let MobileBootstrapStage::TailSync {
                    waiting_start,
                    waiting_since,
                    empty_probe_start,
                    observed_frontier,
                    ..
                } = &mut *stage
                {
                    if waiting_start.is_some_and(|start| committed_height >= start) {
                        *waiting_start = None;
                        *waiting_since = None;
                    }
                    *empty_probe_start = None;
                    *observed_frontier = (*observed_frontier).max(committed_height);
                }
            }

            self.tail_provider_probes.lock().await.clear();

            // We now serve these exact objects locally. Availability is
            // transport metadata only; HeaderDag remains consensus authority.
            let _ = self
                .network
                .cmd_tx
                .send(NetworkCommand::AnnounceAvailability { announcement })
                .await;

            Ok(())
        }
        .await;

        *self.apply_inflight.lock().await = false;

        result
    }

    async fn handle_event(&self, event: NetworkEvent) -> Result<()> {
        match event {
            // ================================================================
            // PEER LIFECYCLE
            // ================================================================
            NetworkEvent::PeerConnected {
                peer,
                locally_selected,
                failure_domain,
            } => {
                android_sync_log(format!(
                    "MOBILE EVENT PEER peer={} selected={} domain={}",
                    peer, locally_selected, failure_domain
                ));

                self.peers.write().await.insert(
                    peer,
                    MobilePeer {
                        failure_domain: FailureDomain(failure_domain),
                        locally_selected,
                    },
                );

                publish_mobile_peer_count(self.peers.read().await.len());

                tracing::info!(
                    peer = %peer,
                    failure_domain,
                    locally_selected,
                    "mobile sync peer connected"
                );

                if let Err(error) = self.begin_initial_bootstrap(peer).await {
                    tracing::warn!(
                        peer = %peer,
                        %error,
                        "mobile initial bootstrap could not start"
                    );
                }

                // Mempool sync is intentionally postponed until initial chain
                // catch-up completes. It must not compete with snapshot/tail
                // requests for bounded local P2P capacity.
                let bootstrap_complete =
                    matches!(*self.bootstrap.lock().await, MobileBootstrapStage::Complete);

                if bootstrap_complete {
                    let _ = self
                        .network
                        .cmd_tx
                        .try_send(NetworkCommand::RequestMempoolSync { peer });
                }

                // Do not wait for the next block gossip before discovering
                // the remote canonical frontier.
                //
                // During TailSync the dedicated tail driver owns forward
                // header acquisition. Newly connected peers must not create
                // another redundant 512-header request here.
                let tail_active = {
                    let stage = self.bootstrap.lock().await;
                    matches!(*stage, MobileBootstrapStage::TailSync { .. })
                };

                let exact_active = self.node.sync.active_plan().await.is_some();

                if tail_active || exact_active {
                    android_sync_log(format!(
                        "LIVE PEER HEADER FETCH SUPPRESSED peer={} tail_active={} exact_active={}",
                        peer, tail_active, exact_active
                    ));

                    if exact_active {
                        self.probe_active_suffix_providers("peer-connected").await;
                    }
                } else {
                    let local_height = self.node.tip_height().await;
                    let start_height = local_height.saturating_add(1);

                    let _ = self
                        .network
                        .cmd_tx
                        .send(NetworkCommand::FetchHeaders {
                            peer,
                            start_height,
                            count: 512,
                        })
                        .await;

                    tracing::debug!(
                        peer = %peer,
                        start_height,
                        count = 512,
                        "mobile live/bootstrap header request sent"
                    );
                }
            }

            NetworkEvent::PeerDisconnected(peer) => {
                {
                    let mut stage = self.bootstrap.lock().await;

                    if let MobileBootstrapStage::TailSync {
                        peer: tail_peer,
                        inflight_start,
                        inflight_since,
                        waiting_start,
                        waiting_since,
                        empty_probe_start,
                        ..
                    } = &mut *stage
                    {
                        if *tail_peer == peer {
                            *inflight_start = None;
                            *inflight_since = None;
                            *waiting_start = None;
                            *waiting_since = None;
                            *empty_probe_start = None;

                            tracing::debug!(
                                peer = %peer,
                                "mobile TailSync transport lease released"
                            );
                        }
                    }
                }

                self.peers.write().await.remove(&peer);

                publish_mobile_peer_count(self.peers.read().await.len());

                {
                    let mut dag = self.node.header_dag.write().await;

                    dag.remove_inventory_provider(peer);
                }

                self.node.sync.disconnect(peer).await;

                tracing::info!(
                    peer = %peer,
                    "mobile sync peer disconnected"
                );

                self.dispatch_exact_requests().await;
            }

            // ================================================================
            // EXACT OBJECT RESPONSES
            // ================================================================
            NetworkEvent::ObjectsResponse {
                token,
                from,
                objects,
                inbound_memory_permit,
            } => {
                // SuffixSync itself keeps received object permits alive when
                // appropriate. The network event permit belongs to this
                // transport response; dropping it after admission is correct.
                let result = self.node.sync.accept_response(token, from, objects).await;

                drop(inbound_memory_permit);

                match result {
                    Ok(accepted) => {
                        tracing::debug!(
                            token,
                            peer = %from,
                            accepted,
                            "mobile exact-object response accepted"
                        );
                    }

                    Err(error) => {
                        tracing::warn!(
                            token,
                            peer = %from,
                            %error,
                            "mobile exact-object response rejected"
                        );

                        // Malformed correlated data removes this provider from
                        // the active suffix without poisoning HeaderDag.
                        self.node.sync.quarantine_provider(from).await;
                    }
                }

                self.maybe_apply_complete_suffix().await?;
                self.dispatch_exact_requests().await;
            }

            NetworkEvent::ObjectsRequestBusy {
                token,
                from,
                objects,
                retry_after_ms,
            } => {
                match self
                    .node
                    .sync
                    .request_busy(token, from, &objects, u64::from(retry_after_ms))
                    .await
                {
                    Ok(()) => {}

                    Err(error) => {
                        tracing::debug!(
                            token,
                            peer = %from,
                            %error,
                            "mobile busy correlation ignored"
                        );
                    }
                }

                self.dispatch_exact_requests().await;
            }

            NetworkEvent::ObjectsRequestFailed {
                token,
                from,
                objects,
                kind,
            } => {
                if let Err(error) = self.node.sync.request_failed(token, from, &objects).await {
                    tracing::debug!(
                        token,
                        peer = %from,
                        ?kind,
                        %error,
                        "mobile exact-object failure correlation ignored"
                    );
                }

                self.dispatch_exact_requests().await;
            }

            // ================================================================
            // HEADER CONTROL PLANE
            //
            // Header validation/planning is deliberately NOT performed here
            // ad-hoc. HeaderDag must receive only native-validated headers.
            //
            // The next HeaderInventory planner layer calls:
            //     node.sync.admit_live_suffix()
            //     node.sync.admit_reorg_suffix()
            //     node.sync.add_inventory()
            //
            // Once admitted, this runtime immediately handles transport.
            // ================================================================
            NetworkEvent::HeaderAnnouncement {
                from,
                announcement,
                source_has_objects,
            } => {
                tracing::debug!(
                    peer = %from,
                    height = announcement.header.height,
                    source_has_objects,
                    "mobile header announcement received"
                );

                let local_height = self.node.tip_height().await;

                let local_hash = self.node.tip_hash().await;

                let announced_hash = noid_chain::block_id(&announcement.header);

                if announcement.header.height > local_height {
                    let tail_active = {
                        let stage = self.bootstrap.lock().await;
                        matches!(*stage, MobileBootstrapStage::TailSync { .. })
                    };

                    if tail_active {
                        {
                            let mut stage = self.bootstrap.lock().await;
                            if let MobileBootstrapStage::TailSync {
                                observed_frontier,
                                empty_probe_start,
                                ..
                            } = &mut *stage
                            {
                                *observed_frontier =
                                    (*observed_frontier).max(announcement.header.height);
                                if announcement.header.height > local_height {
                                    *empty_probe_start = None;
                                }
                            }
                        }

                        android_sync_log(format!(
                            "TAIL ANNOUNCEMENT peer={} height={} local_height={}",
                            from, announcement.header.height, local_height
                        ));
                    } else if self.node.sync.active_plan().await.is_some() {
                        // Steady-state exact sync already owns canonical
                        // progress. A newer announcement is only a frontier
                        // hint until the current immutable suffix commits.
                        //
                        // Do NOT create another overlapping FetchHeaders plan:
                        // recover providers for the pinned exact range instead.
                        android_sync_log(format!(
                            "LIVE ANNOUNCEMENT DEFERRED peer={} height={} local_height={} exact_active=true",
                            from,
                            announcement.header.height,
                            local_height
                        ));

                        self.probe_active_suffix_providers("announcement").await;
                    } else {
                        // No exact plan is active: discover the next canonical
                        // range normally.
                        let start_height = local_height.saturating_add(1);

                        let gap = announcement
                            .header
                            .height
                            .saturating_sub(start_height)
                            .saturating_add(1);

                        let count = gap.min(512) as u16;

                        let _ = self
                            .network
                            .cmd_tx
                            .send(NetworkCommand::FetchHeaders {
                                peer: from,
                                start_height,
                                count,
                            })
                            .await;
                    }
                } else if announcement.header.height == local_height && announced_hash == local_hash
                {
                    // Same canonical tip.
                    //
                    // If this direct origin serves exact objects, the
                    // subsequent inventory path may still enrich an already
                    // active immutable suffix. No chain action is required.
                    tracing::debug!(
                        peer = %from,
                        height = local_height,
                        "mobile peer announced current canonical tip"
                    );
                } else {
                    // Possible competing non-final branch.
                    //
                    // Pull one bounded ancestry window. The native planner
                    // decides whether it:
                    //
                    // - beats our chain by cumulative work,
                    // - is merely behind,
                    // - needs an older range,
                    // - diverges below finality.
                    let start_height = local_height.saturating_sub(511);

                    let count = local_height
                        .saturating_sub(start_height)
                        .saturating_add(1)
                        .min(512) as u16;

                    let _ = self
                        .network
                        .cmd_tx
                        .send(NetworkCommand::FetchHeaders {
                            peer: from,
                            start_height,
                            count,
                        })
                        .await;
                }
            }

            NetworkEvent::HeaderInventoryBatch {
                from,
                records,
                snapshot_boundary: _,
            } => {
                self.note_tail_header_batch(from, &records).await;

                use noid_networking::header_planner::{
                    advertise_inventory_for_known_headers, plan_header_inventory,
                    record_validated_headers, source_independent_suffix_offer, HeaderInventoryPlan,
                };

                let domain = self
                    .peer_failure_domain(from)
                    .await
                    .unwrap_or(FailureDomain(0));

                let store = {
                    let chain = self.node.chain.read().await;

                    chain.store.clone()
                };

                // --------------------------------------------------------
                // CONSENSUS BOUNDARY
                //
                // The shared planner was extracted from the current
                // full-node v1.0.3 implementation after the git pull.
                //
                // No body request is made before native header validation
                // and cumulative-work comparison succeeds.
                // --------------------------------------------------------

                let plan = {
                    let dag = self.node.header_dag.read().await;

                    plan_header_inventory(&self.node.chain, &store, &dag, records.clone()).await
                };

                match plan {
                    // ====================================================
                    // SAME TIP
                    // ====================================================
                    Ok(HeaderInventoryPlan::Confirmed { tip }) => {
                        {
                            let mut dag = self.node.header_dag.write().await;

                            if let Err(error) =
                                advertise_inventory_for_known_headers(&mut dag, from, &records)
                            {
                                tracing::debug!(
                                    peer = %from,
                                    %error,
                                    "mobile confirmed inventory advertisement rejected"
                                );
                            }
                        }

                        // Even a repeated range can provide exact objects
                        // required by a previously pinned immutable suffix.
                        if let Some(active_plan) = self.node.sync.active_plan().await {
                            let headers = active_plan.headers().to_vec();

                            if let Err(error) = self
                                .node
                                .sync
                                .add_inventory(from, domain, &headers, &records)
                                .await
                            {
                                tracing::debug!(
                                    peer = %from,
                                    %error,
                                    "mobile confirmed inventory did not extend active suffix"
                                );
                            }
                        }

                        tracing::debug!(
                            peer = %from,
                            height = tip.height,
                            "mobile peer confirms canonical tip"
                        );
                    }

                    // ====================================================
                    // PEER/RANGE BEHIND US
                    // ====================================================
                    Ok(HeaderInventoryPlan::Behind) => {
                        {
                            let mut dag = self.node.header_dag.write().await;

                            if let Err(error) =
                                advertise_inventory_for_known_headers(&mut dag, from, &records)
                            {
                                tracing::debug!(
                                    peer = %from,
                                    %error,
                                    "mobile behind inventory advertisement rejected"
                                );
                            }
                        }

                        // Behind headers may still carry exactly the body
                        // source needed by our currently pinned suffix.
                        if let Some(active_plan) = self.node.sync.active_plan().await {
                            let headers = active_plan.headers().to_vec();

                            if let Err(error) = self
                                .node
                                .sync
                                .add_inventory(from, domain, &headers, &records)
                                .await
                            {
                                tracing::debug!(
                                    peer = %from,
                                    %error,
                                    "mobile behind inventory did not extend active suffix"
                                );
                            }
                        }
                    }

                    // ====================================================
                    // NEED MORE ANCESTRY
                    // ====================================================
                    Ok(HeaderInventoryPlan::NeedOlder {
                        start_height,
                        count,
                    }) => {
                        tracing::debug!(
                            peer = %from,
                            start_height,
                            count,
                            "mobile planner requests older header ancestry"
                        );

                        let _ = self
                            .network
                            .cmd_tx
                            .send(NetworkCommand::FetchHeaders {
                                peer: from,
                                start_height,
                                count,
                            })
                            .await;
                    }

                    // ====================================================
                    // VALIDATED CANDIDATE BRANCH
                    // ====================================================
                    Ok(HeaderInventoryPlan::Candidate {
                        headers,
                        records,
                        old_tip,
                        target,
                    }) => {
                        if headers.is_empty() {
                            tracing::warn!(
                                peer = %from,
                                "mobile planner returned empty candidate"
                            );

                            return Ok(());
                        }

                        // ------------------------------------------------
                        // HeaderDag admission
                        // ------------------------------------------------

                        {
                            let mut dag = self.node.header_dag.write().await;

                            record_validated_headers(&mut dag, &headers).map_err(|error| {
                                anyhow::anyhow!("record validated mobile headers: {error}")
                            })?;

                            advertise_inventory_for_known_headers(&mut dag, from, &records)
                                .map_err(|error| {
                                    anyhow::anyhow!("advertise mobile exact inventory: {error}")
                                })?;
                        }

                        // Match the desktop node: once native validation has
                        // updated HeaderDag, freeze the ENTIRE selected path from
                        // the durable canonical tip. Do not build a new exact plan
                        // from whichever fragment happened to arrive last.
                        let (base, selected_headers, selected_target) = {
                            let dag = self.node.header_dag.read().await;

                            if dag.best_tip() != target {
                                tracing::debug!(
                                    peer = %from,
                                    candidate_target = target.height,
                                    selected_target = dag.best_tip().height,
                                    "mobile candidate is not the HeaderDag-selected tip"
                                );
                                return Ok(());
                            }

                            let (base, selected_headers) =
                                dag.selected_path_from(old_tip).map_err(|error| {
                                    anyhow::anyhow!(
                                        "load HeaderDag-selected mobile suffix: {error}"
                                    )
                                })?;

                            let selected_target = selected_headers
                                .last()
                                .map(|header| header.point())
                                .unwrap_or(base);

                            (base, selected_headers, selected_target)
                        };

                        if selected_headers.is_empty() {
                            return Ok(());
                        }

                        // The normal full node never tries to exact-fetch bodies
                        // beyond RETAINED_BLOCK_SERVING_DEPTH. Those bodies are
                        // not guaranteed to be served anymore; switch to the
                        // authenticated State snapshot path instead.
                        if gap_requires_snapshot_sync(old_tip.height, selected_target.height)
                            && self.node.sync.active_plan().await.is_none()
                        {
                            android_sync_log(format!(
                                "TAIL SELECTED GAP REQUIRES SNAPSHOT base={} target={} retained_depth={} peer={}",
                                old_tip.height,
                                selected_target.height,
                                noid_chain::consensus::params::RETAINED_BLOCK_SERVING_DEPTH,
                                from
                            ));

                            if self.snapshot_bootstrap_active().await {
                                tracing::debug!(
                                    peer = %from,
                                    "mobile snapshot bootstrap already active; stale candidate cannot replace it"
                                );
                                return Ok(());
                            }

                            self.begin_snapshot_bootstrap(from).await?;
                            return Ok(());
                        }

                        // ------------------------------------------------
                        // Build one source-independent immutable exact plan from
                        // the HeaderDag-selected path. Terminal and block bodies
                        // may come from different peers.
                        // ------------------------------------------------

                        let exact = {
                            let dag = self.node.header_dag.read().await;

                            source_independent_suffix_offer(
                                &dag,
                                from,
                                old_tip,
                                base,
                                selected_headers.clone(),
                            )
                        };

                        match exact {
                            Ok((terminal_peer, offer, inventories)) => {
                                let terminal_domain = self
                                    .peer_failure_domain(terminal_peer)
                                    .await
                                    .unwrap_or(domain);

                                let admission = self
                                    .node
                                    .sync
                                    .admit_offer(terminal_peer, terminal_domain, offer)
                                    .await?;

                                use crate::sync::MobileSuffixAdmission;

                                match admission {
                                    MobileSuffixAdmission::Started
                                    | MobileSuffixAdmission::Merged
                                    | MobileSuffixAdmission::Duplicate
                                    | MobileSuffixAdmission::Replaced => {
                                        self.tail_provider_probes
                                            .lock()
                                            .await
                                            .remove(&(base.height, selected_target.height));

                                        android_sync_log(format!(
                                            "TAIL EXACT SUFFIX ACTIVE admission={:?} base={} target={} terminal_peer={}",
                                            admission,
                                            base.height,
                                            selected_target.height,
                                            terminal_peer
                                        ));
                                    }

                                    MobileSuffixAdmission::DeferredExtension => {
                                        android_sync_log(format!(
                                            "LIVE EXACT EXTENSION DEFERRED candidate_base={} candidate_target={} active_target={}",
                                            base.height,
                                            selected_target.height,
                                            self.node
                                                .sync
                                                .active_plan()
                                                .await
                                                .map(|plan| plan.target().height)
                                                .unwrap_or(0)
                                        ));
                                    }

                                    MobileSuffixAdmission::KeptStrongerActive => {
                                        android_sync_log(format!(
                                            "LIVE STRONGER ACTIVE KEPT candidate_base={} candidate_target={}",
                                            base.height,
                                            selected_target.height
                                        ));
                                    }
                                }

                                tracing::info!(
                                    peer = %from,
                                    terminal_peer = %terminal_peer,
                                    base_height = base.height,
                                    target_height = selected_target.height,
                                    ?admission,
                                    "mobile immutable exact suffix admission evaluated"
                                );

                                // IMPORTANT:
                                // If the descendant candidate was deferred or a
                                // stronger active suffix was kept, inventories
                                // must be projected onto the CURRENT immutable
                                // plan, not onto `selected_headers` belonging to
                                // the newer candidate.
                                let merge_headers = self
                                    .node
                                    .sync
                                    .active_plan()
                                    .await
                                    .map(|plan| plan.headers().to_vec())
                                    .unwrap_or_else(|| selected_headers.clone());

                                for (peer, inventory) in inventories {
                                    let peer_domain =
                                        self.peer_failure_domain(peer).await.unwrap_or(domain);

                                    if let Err(error) = self
                                        .node
                                        .sync
                                        .add_inventory(
                                            peer,
                                            peer_domain,
                                            &merge_headers,
                                            &inventory,
                                        )
                                        .await
                                    {
                                        tracing::debug!(
                                            peer = %peer,
                                            %error,
                                            "mobile independent inventory merge ignored"
                                        );
                                    }
                                }

                                // A deferred descendant is useful evidence that
                                // the network moved forward, but the pinned
                                // suffix must finish first. Refresh its provider
                                // set immediately.
                                if matches!(
                                    admission,
                                    MobileSuffixAdmission::DeferredExtension
                                        | MobileSuffixAdmission::KeptStrongerActive
                                ) {
                                    self.probe_active_suffix_providers("deferred-candidate")
                                        .await;
                                }

                                self.dispatch_exact_requests().await;
                            }

                            Err(error) => {
                                // Consensus branch is valid; only data-plane
                                // availability is incomplete.
                                //
                                // KEEP the branch in HeaderDag and ask other
                                // connected peers about precisely this range.
                                tracing::debug!(
                                    peer = %from,
                                    base_height = base.height,
                                    target_height = selected_target.height,
                                    %error,
                                    "mobile validated branch waiting for exact-object providers"
                                );

                                let (tail_active, dedicated_tail_peer) = {
                                    let stage = self.bootstrap.lock().await;
                                    match *stage {
                                        MobileBootstrapStage::TailSync { peer, .. } => {
                                            (true, Some(peer))
                                        }
                                        _ => (false, None),
                                    }
                                };

                                // Repeated candidate inventories can arrive from
                                // many peers. Deduplicate provider probes for the
                                // same immutable range so they cannot flood the
                                // bounded request lane.
                                let probe_key = (base.height, selected_target.height);
                                let now = Instant::now();
                                let should_probe = {
                                    let mut probes = self.tail_provider_probes.lock().await;

                                    probes.retain(|_, sent| {
                                        now.duration_since(*sent) < Duration::from_secs(20)
                                    });

                                    match probes.get(&probe_key) {
                                        Some(sent)
                                            if now.duration_since(*sent)
                                                < Duration::from_secs(3) =>
                                        {
                                            false
                                        }

                                        _ => {
                                            probes.insert(probe_key, now);
                                            true
                                        }
                                    }
                                };

                                if should_probe {
                                    let peers = self
                                        .peers
                                        .read()
                                        .await
                                        .keys()
                                        .copied()
                                        .filter(|peer| *peer != from)
                                        .filter(|peer| Some(*peer) != dedicated_tail_peer)
                                        .collect::<Vec<_>>();

                                    let count =
                                        selected_headers.len().saturating_add(1).min(512) as u16;
                                    let fanout = 4usize;
                                    let mut queued = 0usize;

                                    for peer in peers.into_iter().take(fanout) {
                                        if self
                                            .network
                                            .cmd_tx
                                            .try_send(NetworkCommand::FetchHeaders {
                                                peer,
                                                start_height: base.height,
                                                count,
                                            })
                                            .is_ok()
                                        {
                                            queued += 1;
                                        }
                                    }

                                    android_sync_log(format!(
                                        "{} PROVIDER PROBE base={} target={} queued={}",
                                        if tail_active { "TAIL" } else { "LIVE" },
                                        base.height,
                                        selected_target.height,
                                        queued
                                    ));
                                }
                            }
                        }
                    }

                    // ====================================================
                    // BELOW ACCEPTED FINALITY
                    // ====================================================
                    Ok(HeaderInventoryPlan::FinalizedDivergence) => {
                        tracing::warn!(
                            peer = %from,
                            "mobile peer diverges below accepted finality"
                        );

                        {
                            let mut dag = self.node.header_dag.write().await;

                            dag.remove_inventory_provider(from);
                        }

                        self.node.sync.disconnect(from).await;

                        // IMPORTANT:
                        //
                        // Do NOT automatically install a snapshot here.
                        // A healthy local MDBX chain remains authoritative.
                        //
                        // Snapshot recovery will be an explicitly armed
                        // bootstrap/recovery mode.
                    }

                    // ====================================================
                    // INVALID HEADER BRANCH
                    // ====================================================
                    Err(error) => {
                        tracing::warn!(
                            peer = %from,
                            %error,
                            "mobile header inventory failed native validation"
                        );

                        let mut dag = self.node.header_dag.write().await;

                        dag.remove_inventory_provider(from);
                    }
                }

                self.dispatch_exact_requests().await;
            }

            NetworkEvent::HeadersRequestFailed {
                from,
                start_height,
                count,
                kind,
            } => {
                android_sync_log(format!(
                    "TAIL/HEADERS FAILED peer={} start={} count={} kind={:?}",
                    from, start_height, count, kind
                ));

                // A failed TailSync header request must release the local
                // in-flight marker. Otherwise drive_bootstrap_tail() sees
                // Some(start_height) forever and never retries.
                {
                    let mut stage = self.bootstrap.lock().await;

                    if let MobileBootstrapStage::TailSync {
                        peer,
                        inflight_start,
                        inflight_since,
                        ..
                    } = &mut *stage
                    {
                        if *peer == from && *inflight_start == Some(start_height) {
                            *inflight_start = None;
                            *inflight_since = None;

                            android_sync_log(format!(
                                "TAIL REQUEST RELEASED start={} for retry",
                                start_height
                            ));
                        }
                    }
                }

                tracing::debug!(
                    peer = %from,
                    start_height,
                    count,
                    ?kind,
                    "mobile header request failed"
                );
            }

            // ================================================================
            // MEMPOOL
            // ================================================================
            NetworkEvent::NewTx {
                from,
                intent_bytes,
                gossip_message_id,
                inbound_memory_permit,
            } => {
                use noid_chain::consensus::wire_limits::MAX_TX_INTENT_BYTES_GLOBAL;

                // --------------------------------------------------------
                // Cheap hard wire bound before decoding/proof work.
                // --------------------------------------------------------

                if intent_bytes.len() > MAX_TX_INTENT_BYTES_GLOBAL {
                    tracing::debug!(
                        peer = %from,
                        size = intent_bytes.len(),
                        max = MAX_TX_INTENT_BYTES_GLOBAL,
                        "mobile tx rejected: wire size limit"
                    );

                    resolve_tx_gossip(
                        &self.network.cmd_tx,
                        from,
                        gossip_message_id,
                        MessageAcceptance::Reject,
                    );

                    drop(inbound_memory_permit);

                    return Ok(());
                }

                // --------------------------------------------------------
                // Admission may perform expensive authorization verification.
                //
                // Do not block the authoritative P2P event actor while that
                // proof verification runs.
                // --------------------------------------------------------

                let mempool = self.node.mempool.clone();

                let p2p_cmd = self.network.cmd_tx.clone();

                tokio::spawn(async move {
                    let acceptance = match noid_tx::PagedSpendIntent::from_bytes(&intent_bytes) {
                        Ok(intent) => match mempool.submit(intent, intent_bytes).await {
                            Ok(hash) => {
                                tracing::debug!(
                                    peer = %from,
                                    txid = %hex::encode(hash.0),
                                    "mobile remote tx admitted"
                                );

                                MessageAcceptance::Accept
                            }

                            Err(error) => {
                                let acceptance = gossip_acceptance_for_submit_error(&error);

                                tracing::debug!(
                                    peer = %from,
                                    %error,
                                    ?acceptance,
                                    "mobile remote tx not admitted"
                                );

                                acceptance
                            }
                        },

                        Err(error) => {
                            tracing::debug!(
                                peer = %from,
                                ?error,
                                "mobile remote tx decode rejected"
                            );

                            MessageAcceptance::Reject
                        }
                    };

                    resolve_tx_gossip(&p2p_cmd, from, gossip_message_id, acceptance);

                    // Direct relay owns one inbound-memory reservation.
                    // Gossip carries None.
                    drop(inbound_memory_permit);
                });
            }

            NetworkEvent::MempoolSyncResponse {
                from,
                txs,
                inbound_memory_permit,
            } => {
                use noid_chain::consensus::wire_limits::MAX_TX_INTENT_BYTES_GLOBAL;

                tracing::debug!(
                    peer = %from,
                    count = txs.len(),
                    "mobile mempool sync response received"
                );

                let mempool = self.node.mempool.clone();

                // A mempool response can contain multiple expensive proofs.
                // Keep it entirely outside the authoritative event actor.
                tokio::spawn(async move {
                    let mut admitted = 0usize;
                    let mut already_known = 0usize;
                    let mut rejected = 0usize;

                    for intent_bytes in txs {
                        if intent_bytes.len() > MAX_TX_INTENT_BYTES_GLOBAL {
                            rejected = rejected.saturating_add(1);

                            tracing::debug!(
                                peer = %from,
                                bytes = intent_bytes.len(),
                                max = MAX_TX_INTENT_BYTES_GLOBAL,
                                "mobile mempool-sync tx exceeds wire cap"
                            );

                            continue;
                        }

                        let intent = match noid_tx::PagedSpendIntent::from_bytes(&intent_bytes) {
                            Ok(intent) => intent,

                            Err(error) => {
                                rejected = rejected.saturating_add(1);

                                tracing::debug!(
                                    peer = %from,
                                    ?error,
                                    "mobile mempool-sync tx decode rejected"
                                );

                                continue;
                            }
                        };

                        match mempool.submit(intent, intent_bytes).await {
                            Ok(hash) => {
                                admitted = admitted.saturating_add(1);

                                tracing::debug!(
                                    peer = %from,
                                    txid = %hex::encode(hash.0),
                                    "mobile mempool-sync tx admitted"
                                );
                            }

                            Err(noid_mempool::SubmitError::AlreadyAdmitted(_)) => {
                                already_known = already_known.saturating_add(1);
                            }

                            Err(error) => {
                                rejected = rejected.saturating_add(1);

                                tracing::debug!(
                                    peer = %from,
                                    %error,
                                    soft = error.is_soft(),
                                    "mobile mempool-sync tx not admitted"
                                );
                            }
                        }
                    }

                    tracing::debug!(
                        peer = %from,
                        admitted,
                        already_known,
                        rejected,
                        "mobile mempool sync admission finished"
                    );

                    // Keep the process-global decoded response reservation
                    // alive until every included transaction has either been
                    // admitted or rejected.
                    drop(inbound_memory_permit);
                });
            }

            // ================================================================
            // SNAPSHOT EVENTS
            //
            // Snapshot is intentionally NOT ordinary mobile restart authority.
            // These events are ignored until explicit bootstrap/recovery mode
            // is armed by a higher layer.
            // ================================================================
            NetworkEvent::StateManifest {
                generation,
                from,
                requester_height: _,
                manifest,
            } => {
                android_sync_log(format!(
                    "MANIFEST RECEIVED generation={} peer={} tip_height={}",
                    generation, from, manifest.tip_height
                ));

                let expected = {
                    let stage = self.bootstrap.lock().await;

                    matches!(
                        *stage,
                        MobileBootstrapStage::WaitingManifest {
                            generation: expected_generation,
                            peer: expected_peer,
                        }
                        if
                            expected_generation == generation &&
                            expected_peer == from
                    )
                };

                if !expected {
                    tracing::debug!(
                        generation,
                        peer = %from,
                        "discarding stale mobile State manifest"
                    );

                    return Ok(());
                }

                if manifest.tip_height == 0 {
                    anyhow::bail!("mobile bootstrap peer returned empty snapshot manifest");
                }

                android_sync_log("MANIFEST 01 SnapshotOffer BEGIN");

                let offer = SnapshotOffer::from_verified_manifest(manifest.clone())
                    .context("validate mobile snapshot offer")?;

                android_sync_log("MANIFEST 02 SnapshotOffer OK");

                let boundary_height = manifest.tip_height;

                let boundary_hash = manifest.tip_hash;

                let boundary_chainwork = manifest.cumulative_chainwork;

                let manifest_digest = manifest.manifest_digest;

                // --------------------------------------------------------
                // Build a native header staging candidate from our exact
                // current canonical tip.
                // --------------------------------------------------------

                android_sync_log("MANIFEST 03 tip_height BEGIN");

                let local_height = self.node.tip_height().await;

                android_sync_log(format!(
                    "MANIFEST 04 tip_height OK local_height={}",
                    local_height
                ));

                android_sync_log("MANIFEST 05 chain.read BEGIN");

                let store = {
                    let chain = self.node.chain.read().await;

                    android_sync_log("MANIFEST 06 chain.read ACQUIRED");

                    chain.store.clone()
                };

                android_sync_log("MANIFEST 07 chain.read RELEASED");
                android_sync_log("MANIFEST 08 CanonicalHeaderBoundary::load BEGIN");

                let base = CanonicalHeaderBoundary::load(&store, local_height)
                    .context("load mobile canonical snapshot-header base")?;

                android_sync_log("MANIFEST 09 CanonicalHeaderBoundary::load OK");

                let staging_path = self.node.data_dir().join("mobile-snapshot-headers.staging");

                android_sync_log(format!(
                    "MANIFEST 10 staging path={}",
                    staging_path.display()
                ));

                // Remove only our disposable staging candidate.
                // Never touch canonical MDBX data.
                let _ = std::fs::remove_file(&staging_path);

                android_sync_log("MANIFEST 11 old staging removed");
                android_sync_log("MANIFEST 12 SnapshotHeaderStaging::create BEGIN");

                let staging = if boundary_height == local_height {
                    SnapshotHeaderStaging::create_at_canonical_boundary(&staging_path, &store, base)
                } else {
                    SnapshotHeaderStaging::create(&staging_path, &store, base)
                }
                .context("create mobile snapshot header staging")?;

                android_sync_log("MANIFEST 13 SnapshotHeaderStaging::create OK");

                *self.snapshot_header_staging.lock().await = Some(staging);

                android_sync_log("MANIFEST 14 header staging stored");

                *self.snapshot_offer.lock().await = Some(offer);

                android_sync_log("MANIFEST 15 snapshot offer stored");

                *self.bootstrap.lock().await = MobileBootstrapStage::ManifestReceived {
                    generation,
                    peer: from,
                    boundary_height,
                    boundary_hash,
                    manifest_digest,
                };

                publish_mobile_sync_phase(2);

                android_sync_log(format!(
                    "MANIFEST 16 accepted boundary_height={} -> HEADERS",
                    boundary_height
                ));

                tracing::info!(
                    generation,
                    peer = %from,
                    local_height,
                    boundary_height,
                    boundary_hash =
                        %hex::encode(boundary_hash),
                    "mobile snapshot manifest accepted; authenticating headers"
                );

                // --------------------------------------------------------
                // Zero missing headers: seal immediately.
                // Otherwise pull first bounded range.
                // --------------------------------------------------------

                if boundary_height == local_height {
                    let staging = self
                        .snapshot_header_staging
                        .lock()
                        .await
                        .take()
                        .ok_or_else(|| {
                            anyhow::anyhow!("mobile snapshot header staging disappeared")
                        })?;

                    let validated = staging
                        .validate_complete(
                            &store,
                            boundary_height,
                            boundary_hash,
                            boundary_chainwork,
                        )
                        .context("seal mobile snapshot header boundary")?;

                    *self.validated_snapshot_headers.lock().await = Some(validated);

                    let token = generation;

                    self.network
                        .cmd_tx
                        .send(NetworkCommand::RequestHistoryStepTerminal {
                            token,
                            peer: from,
                            height: boundary_height,
                            block_hash: boundary_hash,
                        })
                        .await
                        .context("queue mobile HistoryStep terminal request")?;

                    *self.bootstrap.lock().await = MobileBootstrapStage::WaitingTerminal {
                        generation,
                        peer: from,
                        boundary_height,
                        boundary_hash,
                        manifest_digest,
                    };

                    return Ok(());
                }

                let start_height = local_height.saturating_add(1);

                let remaining = boundary_height
                    .saturating_sub(start_height)
                    .saturating_add(1);

                let count = remaining.min(512) as u16;

                let token = generation;

                android_sync_log(format!(
                    "MANIFEST 17 FetchSnapshotHeaders BEGIN start={} count={}",
                    start_height, count
                ));

                self.network
                    .cmd_tx
                    .send(NetworkCommand::FetchSnapshotHeaders {
                        generation,
                        token,
                        peer: from,
                        start_height,
                        count,
                    })
                    .await
                    .context("queue mobile snapshot headers")?;

                android_sync_log("MANIFEST 18 FetchSnapshotHeaders QUEUED");

                *self.bootstrap.lock().await = MobileBootstrapStage::StagingHeaders {
                    generation,
                    token,
                    peer: from,
                    next_height: start_height,
                    boundary_height,
                    boundary_hash,
                    boundary_chainwork,
                    manifest_digest,
                };
            }

            NetworkEvent::StateManifestRequestFailed {
                generation, from, ..
            } => {
                android_sync_log(format!(
                    "MANIFEST REQUEST FAILED generation={} peer={}",
                    generation, from
                ));

                let mut stage = self.bootstrap.lock().await;

                if matches!(
                    *stage,
                    MobileBootstrapStage::WaitingManifest {
                        generation: expected_generation,
                        peer: expected_peer,
                    }
                    if
                        expected_generation == generation &&
                        expected_peer == from
                ) {
                    *stage = MobileBootstrapStage::Idle;

                    tracing::warn!(
                        generation,
                        peer = %from,
                        "mobile initial State manifest request failed"
                    );
                }
            }

            NetworkEvent::HistoryStepTerminal {
                token,
                from,
                height,
                block_hash,
                terminal_bytes,
                inbound_memory_permit,
            } => {
                android_sync_log(format!(
                    "HISTORY TERMINAL RECEIVED token={} peer={} height={} bytes={}",
                    token,
                    from,
                    height,
                    terminal_bytes.len()
                ));
                // --------------------------------------------------------
                // Exact local correlation.
                // --------------------------------------------------------

                let (generation, boundary_height, boundary_hash) = {
                    let stage = self.bootstrap.lock().await;

                    match *stage {
                        MobileBootstrapStage::WaitingTerminal {
                            generation,
                            peer,
                            boundary_height,
                            boundary_hash,
                            ..
                        } if generation == token
                            && peer == from
                            && boundary_height == height
                            && boundary_hash == block_hash =>
                        {
                            (generation, boundary_height, boundary_hash)
                        }

                        _ => {
                            tracing::debug!(
                                token,
                                peer = %from,
                                "discarding stale mobile HistoryStep terminal"
                            );

                            return Ok(());
                        }
                    }
                };

                if terminal_bytes.is_empty() {
                    anyhow::bail!("mobile bootstrap peer returned empty HistoryStep terminal");
                }

                // --------------------------------------------------------
                // Headers were already native-consensus validated and sealed.
                // --------------------------------------------------------

                let validated_headers = self
                    .validated_snapshot_headers
                    .lock()
                    .await
                    .take()
                    .ok_or_else(|| anyhow::anyhow!("validated mobile snapshot headers missing"))?;

                let header_boundary = validated_headers.boundary();

                if header_boundary.tip_header.height != boundary_height
                    || header_boundary.tip_hash != boundary_hash
                {
                    let _ = validated_headers.discard();

                    anyhow::bail!(
                        "validated mobile snapshot boundary does not match terminal request"
                    );
                }

                // --------------------------------------------------------
                // Recursive HistoryStep verifier.
                // --------------------------------------------------------

                let history_runtime =
                    self.node.history_step_runtime.clone().ok_or_else(|| {
                        anyhow::anyhow!("embedded HistoryStep verifier unavailable")
                    })?;

                android_sync_log("HISTORY VERIFY BEGIN");

                let verified_boundary = {
                    let chain = self.node.chain.read().await;

                    android_sync_log("HISTORY VERIFY chain.read ACQUIRED");

                    chain
                        .verify_snapshot_boundary(
                            header_boundary.tip_header,
                            header_boundary.epoch_anchor_header,
                            terminal_bytes,
                            |claim| {
                                noid_recursive::acceptance::history_step::
                                    decode_verify_history_step_terminal(
                                        history_runtime.as_ref(),
                                        claim.terminal_bytes,
                                        &claim.header,
                                        &claim.epoch_anchor_header,
                                    )
                                    .map(|_| ())
                                    .map_err(
                                        |error| {
                                            format!(
                                                "HistoryStep terminal rejected: {error}"
                                            )
                                        }
                                    )
                            },
                        )
                        .context("verify mobile snapshot HistoryStep boundary")?
                };

                android_sync_log("HISTORY VERIFY OK");

                // The recursive verifier consumed the terminal bytes.
                drop(inbound_memory_permit);

                // --------------------------------------------------------
                // Immutable manifest selected for this generation.
                // --------------------------------------------------------

                android_sync_log("STATE PREP 01 snapshot offer BEGIN");

                let offer = self.snapshot_offer.lock().await.take().ok_or_else(|| {
                    anyhow::anyhow!("mobile snapshot offer missing after HistoryStep verification")
                })?;

                let manifest = offer.manifest();

                android_sync_log(format!(
                    "STATE PREP 02 manifest segments={}",
                    manifest.segment_ids.len()
                ));

                let authenticated_header = *verified_boundary.header();

                // --------------------------------------------------------
                // Exact manifest <-> authenticated-header binding.
                //
                // Same checks as the full-node snapshot staging path.
                // --------------------------------------------------------

                if noid_chain::block_header::block_id(&authenticated_header) != manifest.tip_hash
                    || authenticated_header.height != manifest.tip_height
                    || authenticated_header.state_root != manifest.state_root
                    || authenticated_header.log_slots != manifest.log_slots
                    || authenticated_header.active_slot_count != manifest.active_slot_count
                    || authenticated_header.alloc_counter != manifest.alloc_counter
                {
                    let _ = validated_headers.discard();

                    anyhow::bail!(
                        "mobile snapshot manifest metadata does not match authenticated boundary header"
                    );
                }

                if manifest.segment_ids.len() != manifest.segment_roots.len()
                    || manifest.segment_ids.len() != manifest.segment_lengths.len()
                {
                    let _ = validated_headers.discard();

                    anyhow::bail!(
                        "mobile snapshot manifest segment descriptor vectors are malformed"
                    );
                }

                // --------------------------------------------------------
                // Prepare authenticated on-disk State staging.
                // --------------------------------------------------------

                android_sync_log("STATE PREP 03 metadata BEGIN");

                let metadata =
                    noid_chain::storage::AuthenticatedSnapshotMetadata::from_authenticated_header(
                        authenticated_header,
                        manifest.tip_hash,
                        manifest.eff_log,
                    )
                    .context("create mobile authenticated snapshot metadata")?;

                android_sync_log("STATE PREP 04 metadata OK");

                let descriptors = manifest
                    .segment_ids
                    .iter()
                    .copied()
                    .zip(manifest.segment_roots.iter().copied())
                    .zip(manifest.segment_lengths.iter().copied())
                    .map(|((segment_id, segment_root), encoded_len)| {
                        noid_chain::storage::SnapshotSegmentDescriptor {
                            segment_id,
                            segment_root,
                            encoded_len,
                        }
                    })
                    .collect::<Vec<_>>();

                let staging_root = self.node.data_dir().join("mobile-snapshot-state");

                std::fs::create_dir_all(&staging_root)
                    .context("create mobile snapshot staging root")?;

                let snapshot_staging = noid_chain::storage::SnapshotStagingSession::new(
                    &staging_root,
                    metadata,
                    descriptors,
                )
                .context("create mobile State snapshot staging session")?;

                // --------------------------------------------------------
                // Snapshot transport plan.
                //
                // SnapshotSync checks that the terminal metadata binds the
                // semantic header id of the authenticated boundary.
                // --------------------------------------------------------

                let semantic_header_id =
                    noid_chain::block_header::semantic_header_id(&authenticated_header);

                let failure_domain = self
                    .peer_failure_domain(from)
                    .await
                    .unwrap_or(FailureDomain(0));

                let mut snapshot_sync = noid_networking::snapshot_sync::SnapshotSync::new(
                    from,
                    failure_domain,
                    offer,
                    verified_boundary.history_step_terminal_bytes(),
                    semantic_header_id,
                )
                .context("create mobile authenticated SnapshotSync")?;

                tracing::info!(
                    generation,
                    peer = %from,
                    height = boundary_height,
                    hash = %hex::encode(boundary_hash),
                    segments =
                        snapshot_sync
                            .manifest()
                            .segment_ids
                            .len(),
                    "mobile snapshot HistoryStep boundary VERIFIED"
                );

                // Keep all three non-cloneable authorities alive until
                // atomic MDBX install.
                *self.validated_snapshot_headers.lock().await = Some(validated_headers);

                *self.verified_snapshot_boundary.lock().await = Some(verified_boundary);

                *self.active_snapshot_staging.lock().await = Some(snapshot_staging);

                // --------------------------------------------------------
                // Schedule exactly one large State response.
                //
                // Full node intentionally keeps one large segment in flight.
                // --------------------------------------------------------

                let now_ms = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64;

                let requests = snapshot_sync.schedule(now_ms, 1);

                android_sync_log(format!("STATE SYNC schedule requests={}", requests.len()));

                for request in requests {
                    android_sync_log(format!(
                        "STATE SEGMENT REQUEST segment={} peer={}",
                        request.segment.segment_id, request.peer
                    ));
                    let command = NetworkCommand::RequestStateSegment {
                        peer: request.peer,

                        segment_id: request.segment.segment_id,

                        expected_tip_height: request.segment.snapshot.boundary.height,

                        expected_tip_hash: request.segment.snapshot.boundary.hash,

                        manifest_digest: request.segment.snapshot.manifest_digest,
                    };

                    if self.network.cmd_tx.try_send(command).is_err() {
                        snapshot_sync
                            .defer_request(request)
                            .context("defer mobile State segment request")?;
                    }
                }

                *self.active_snapshot_sync.lock().await = Some(snapshot_sync);

                *self.bootstrap.lock().await = MobileBootstrapStage::SyncingSnapshot {
                    generation,
                    boundary_height,
                    boundary_hash,
                };

                publish_mobile_sync_phase(3);

                android_sync_log(format!(
                    "STATE SYNC STARTED generation={} boundary_height={}",
                    generation, boundary_height
                ));

                tracing::info!(
                    generation,
                    boundary_height,
                    "mobile authenticated State segment sync started"
                );
            }

            NetworkEvent::HistoryStepTerminalRequestFailed {
                token, from, kind, ..
            } => {
                android_sync_log(format!(
                    "HISTORY TERMINAL FAILED token={} peer={} kind={:?}",
                    token, from, kind
                ));

                let mut stage = self.bootstrap.lock().await;

                if matches!(
                    *stage,
                    MobileBootstrapStage::WaitingTerminal {
                        generation,
                        peer,
                        ..
                    }
                    if
                        generation == token &&
                        peer == from
                ) {
                    *stage = MobileBootstrapStage::Idle;
                }
            }

            NetworkEvent::HistoryStepTerminalRequestBusy {
                token,
                from,
                retry_after_ms,
                ..
            } => {
                android_sync_log(format!(
                    "HISTORY TERMINAL BUSY token={} peer={} retry_after_ms={}",
                    token, from, retry_after_ms
                ));

                let mut stage = self.bootstrap.lock().await;

                if matches!(
                    *stage,
                    MobileBootstrapStage::WaitingTerminal {
                        generation,
                        peer,
                        ..
                    }
                    if
                        generation == token &&
                        peer == from
                ) {
                    *stage = MobileBootstrapStage::Idle;
                }
            }

            NetworkEvent::SnapshotHeadersBatch {
                generation,
                token,
                from,
                start_height,
                requested_count,
                headers,
                snapshot_boundary: _,
            } => {
                android_sync_log(format!(
                    "SNAPSHOT HEADERS RECEIVED generation={} token={} peer={} start={} requested={} received={}",
                    generation,
                    token,
                    from,
                    start_height,
                    requested_count,
                    headers.len()
                ));
                let (
                    expected_token,
                    expected_peer,
                    expected_start,
                    boundary_height,
                    boundary_hash,
                    boundary_chainwork,
                    manifest_digest,
                ) = {
                    let stage = self.bootstrap.lock().await;

                    match *stage {
                        MobileBootstrapStage::StagingHeaders {
                            generation: expected_generation,
                            token,
                            peer,
                            next_height,
                            boundary_height,
                            boundary_hash,
                            boundary_chainwork,
                            manifest_digest,
                        } if expected_generation == generation => (
                            token,
                            peer,
                            next_height,
                            boundary_height,
                            boundary_hash,
                            boundary_chainwork,
                            manifest_digest,
                        ),

                        _ => {
                            tracing::debug!(
                                generation,
                                token,
                                peer = %from,
                                "discarding stale mobile snapshot header batch"
                            );

                            return Ok(());
                        }
                    }
                };

                if token != expected_token
                    || from != expected_peer
                    || start_height != expected_start
                {
                    anyhow::bail!("mobile snapshot header response correlation mismatch");
                }

                if headers.is_empty() {
                    anyhow::bail!("mobile snapshot header peer returned empty range");
                }

                let store = {
                    let chain = self.node.chain.read().await;

                    chain.store.clone()
                };

                let next_height = {
                    let mut guard = self.snapshot_header_staging.lock().await;

                    let staging = guard
                        .as_mut()
                        .ok_or_else(|| anyhow::anyhow!("mobile snapshot header staging missing"))?;

                    staging
                        .append_batch(&store, &headers)
                        .context("append mobile snapshot headers")?
                };

                tracing::info!(
                    generation,
                    peer = %from,
                    received = headers.len(),
                    next_height,
                    boundary_height,
                    "mobile snapshot headers authenticated"
                );

                if next_height > boundary_height {
                    let staging = self
                        .snapshot_header_staging
                        .lock()
                        .await
                        .take()
                        .ok_or_else(|| {
                            anyhow::anyhow!("mobile completed snapshot header staging missing")
                        })?;

                    let validated = staging
                        .validate_complete(
                            &store,
                            boundary_height,
                            boundary_hash,
                            boundary_chainwork,
                        )
                        .context("validate complete mobile snapshot header chain")?;

                    *self.validated_snapshot_headers.lock().await = Some(validated);

                    android_sync_log(format!(
                        "HISTORY TERMINAL REQUEST generation={} peer={} height={}",
                        generation, from, boundary_height
                    ));

                    self.network
                        .cmd_tx
                        .send(NetworkCommand::RequestHistoryStepTerminal {
                            token: generation,
                            peer: from,
                            height: boundary_height,
                            block_hash: boundary_hash,
                        })
                        .await
                        .context("queue authenticated mobile HistoryStep terminal")?;

                    android_sync_log("HISTORY TERMINAL REQUEST QUEUED");

                    *self.bootstrap.lock().await = MobileBootstrapStage::WaitingTerminal {
                        generation,
                        peer: from,
                        boundary_height,
                        boundary_hash,
                        manifest_digest,
                    };

                    return Ok(());
                }

                let remaining = boundary_height
                    .saturating_sub(next_height)
                    .saturating_add(1);

                let count = remaining.min(512) as u16;

                let next_token = token.saturating_add(1);

                self.network
                    .cmd_tx
                    .send(NetworkCommand::FetchSnapshotHeaders {
                        generation,
                        token: next_token,
                        peer: from,
                        start_height: next_height,
                        count,
                    })
                    .await
                    .context("queue next mobile snapshot header range")?;

                *self.bootstrap.lock().await = MobileBootstrapStage::StagingHeaders {
                    generation,
                    token: next_token,
                    peer: from,
                    next_height,
                    boundary_height,
                    boundary_hash,
                    boundary_chainwork,
                    manifest_digest,
                };
            }

            NetworkEvent::SnapshotHeadersRequestFailed {
                generation,
                token,
                from,
                start_height,
                count,
                kind,
            } => {
                android_sync_log(format!(
                    "SNAPSHOT HEADERS FAILED generation={} token={} peer={} start={} count={} kind={:?}",
                    generation,
                    token,
                    from,
                    start_height,
                    count,
                    kind
                ));

                // LocalCapacity is NOT a remote/provider failure.
                //
                // Keep the already authenticated header staging intact and
                // retry the exact same correlated range after a short local
                // backoff. Resetting to Idle here would throw away potentially
                // thousands of authenticated headers and restart bootstrap.
                if matches!(kind, noid_p2p::RequestFailureKind::LocalCapacity) {
                    let cmd_tx = self.network.cmd_tx.clone();

                    android_sync_log(format!(
                        "SNAPSHOT HEADERS LOCAL CAPACITY: retaining progress and retrying token={} start={} count={}",
                        token,
                        start_height,
                        count
                    ));

                    tokio::spawn(async move {
                        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

                        let _ = cmd_tx
                            .send(NetworkCommand::FetchSnapshotHeaders {
                                generation,
                                token,
                                peer: from,
                                start_height,
                                count,
                            })
                            .await;
                    });

                    return Ok(());
                }

                let mut stage = self.bootstrap.lock().await;

                let correlated = matches!(
                    *stage,
                    MobileBootstrapStage::StagingHeaders {
                        generation:
                            expected_generation,
                        token:
                            expected_token,
                        peer:
                            expected_peer,
                        ..
                    }
                    if
                        expected_generation ==
                            generation &&
                        expected_token ==
                            token &&
                        expected_peer ==
                            from
                );

                if correlated {
                    *stage = MobileBootstrapStage::Idle;

                    if let Some(staging) = self.snapshot_header_staging.lock().await.take() {
                        let _ = staging.discard();
                    }

                    *self.snapshot_offer.lock().await = None;

                    tracing::warn!(
                        generation,
                        token,
                        peer = %from,
                        "mobile snapshot header request failed"
                    );
                }
            }

            NetworkEvent::StateSegment { from, response } => {
                use noid_p2p::object_protocol::DataResponseStatus;

                let segment_id = response.segment_id;

                android_sync_log(format!(
                    "STATE SEGMENT RECEIVED peer={} segment={}",
                    from, segment_id
                ));

                // ----------------------------------------------------
                // Exact immutable-generation correlation.
                // ----------------------------------------------------

                let segment = {
                    let sync_guard = self.active_snapshot_sync.lock().await;

                    let Some(sync) = sync_guard.as_ref() else {
                        tracing::debug!(
                            peer = %from,
                            segment = segment_id,
                            "dropping State response without active mobile snapshot"
                        );

                        drop(response);
                        return Ok(());
                    };

                    let Some(segment) = sync.segment(segment_id) else {
                        tracing::warn!(
                            peer = %from,
                            segment = segment_id,
                            "mobile peer returned unknown State segment"
                        );

                        drop(response);
                        return Ok(());
                    };

                    if segment.snapshot.boundary.height != response.expected_tip_height
                        || segment.snapshot.boundary.hash != response.expected_tip_hash
                        || segment.snapshot.manifest_digest != response.manifest_digest
                    {
                        tracing::warn!(
                            peer = %from,
                            segment = segment_id,
                            "mobile peer returned stale/mismatched State segment"
                        );

                        drop(response);
                        return Ok(());
                    }

                    segment
                };

                // Busy can legally preserve the exact provider/plan.
                if let DataResponseStatus::Busy { retry_after_ms } = response.status {
                    let retry_at_ms = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as u64
                        + u64::from(retry_after_ms);

                    {
                        let mut sync_guard = self.active_snapshot_sync.lock().await;

                        if let Some(sync) = sync_guard.as_mut() {
                            sync.request_busy(from, segment, retry_at_ms)
                                .context("record mobile State provider busy response")?;
                        }
                    }

                    drop(response);

                    self.dispatch_next_snapshot_segment().await?;

                    return Ok(());
                }

                android_sync_log(format!(
                    "STATE SEGMENT DATA CHECK segment={} status={:?} bytes={}",
                    segment_id,
                    response.status,
                    response.data.as_ref().map(|d| d.len()).unwrap_or(0)
                ));

                let Some(data) = response.data.as_deref() else {
                    {
                        let mut sync_guard = self.active_snapshot_sync.lock().await;

                        if let Some(sync) = sync_guard.as_mut() {
                            sync.unavailable(from, segment)
                                .context("record unavailable mobile State segment")?;
                        }
                    }

                    drop(response);

                    self.dispatch_next_snapshot_segment().await?;

                    return Ok(());
                };

                // ----------------------------------------------------
                // Transport-level exact length/correlation admission.
                // ----------------------------------------------------

                {
                    let mut sync_guard = self.active_snapshot_sync.lock().await;

                    let sync = sync_guard.as_mut().ok_or_else(|| {
                        anyhow::anyhow!("mobile SnapshotSync disappeared during State response")
                    })?;

                    android_sync_log(format!(
                        "STATE ACCEPT_RESPONSE BEGIN segment={} bytes={}",
                        segment_id,
                        data.len()
                    ));

                    let accept_result = sync.accept_response(from, segment, data.len());

                    android_sync_log(format!(
                        "STATE ACCEPT_RESPONSE END segment={} ok={}",
                        segment_id,
                        accept_result.is_ok()
                    ));

                    if let Err(error) = accept_result {
                        let _ = sync.reject_provider(from, segment);

                        tracing::warn!(
                            peer = %from,
                            segment = segment_id,
                            %error,
                            "mobile State response failed immutable transport admission"
                        );

                        drop(sync_guard);
                        drop(response);

                        self.dispatch_next_snapshot_segment().await?;

                        return Ok(());
                    }
                }

                // ----------------------------------------------------
                // Cryptographic State authentication + atomic disk seal.
                //
                // accept_segment_recoverable verifies:
                // - exact descriptor
                // - exact encoded length
                // - canonical sparse encoding
                // - exact subtree root
                //
                // A malicious provider loses only its generation lease;
                // already verified segments survive.
                // ----------------------------------------------------

                let stage_result = {
                    let mut staging_guard = self.active_snapshot_staging.lock().await;

                    let staging = staging_guard
                        .as_mut()
                        .ok_or_else(|| anyhow::anyhow!("mobile State staging disappeared"))?;

                    android_sync_log(format!(
                        "STATE STAGING BEGIN segment={} eff_log={} bytes={}",
                        segment_id,
                        response.eff_log,
                        data.len()
                    ));

                    let result =
                        staging.accept_segment_recoverable(segment_id, response.eff_log, data);

                    android_sync_log(format!(
                        "STATE STAGING END segment={} ok={}",
                        segment_id,
                        result.is_ok()
                    ));

                    result
                };

                if let Err(error) = stage_result {
                    android_sync_log(format!(
                        "STATE STAGING ERROR segment={} eff_log={} error={:#}",
                        segment_id, response.eff_log, error
                    ));

                    {
                        let mut sync_guard = self.active_snapshot_sync.lock().await;

                        if let Some(sync) = sync_guard.as_mut() {
                            let _ = sync.reject_provider(from, segment);
                        }
                    }

                    tracing::warn!(
                        peer = %from,
                        segment = segment_id,
                        %error,
                        "mobile State segment failed authenticated root/encoding verification; provider quarantined"
                    );

                    drop(response);

                    self.dispatch_next_snapshot_segment().await?;

                    return Ok(());
                }

                android_sync_log(format!(
                    "STATE SEGMENT VERIFY/STAGING COMPLETE segment={}",
                    segment_id
                ));

                let (complete, counts) = {
                    let mut sync_guard = self.active_snapshot_sync.lock().await;

                    let sync = sync_guard.as_mut().ok_or_else(|| {
                        anyhow::anyhow!("mobile SnapshotSync disappeared after State staging")
                    })?;

                    android_sync_log(format!("STATE MARK VERIFIED BEGIN segment={}", segment_id));

                    sync.mark_verified(segment)
                        .context("mark authenticated mobile State segment verified")?;

                    android_sync_log(format!("STATE MARK VERIFIED OK segment={}", segment_id));

                    (sync.all_segments_verified(), sync.counts())
                };

                // Releasing response releases the inbound byte permit too.
                drop(response);

                tracing::info!(
                    peer = %from,
                    segment = segment_id,
                    verified =
                        counts.verified,
                    pending =
                        counts.wanted,
                    "mobile State segment VERIFIED"
                );

                android_sync_log(format!(
                    "STATE COUNTS segment={} complete={} verified={} wanted={}",
                    segment_id, complete, counts.verified, counts.wanted
                ));

                if complete {
                    android_sync_log(format!(
                        "SNAPSHOT INSTALL BEGIN segment={} peer={}",
                        segment_id, from
                    ));

                    let height = self.install_completed_snapshot(from).await?;

                    android_sync_log(format!("SNAPSHOT INSTALL OK height={}", height));

                    tracing::info!(height, "mobile authenticated snapshot bootstrap installed");
                } else {
                    self.dispatch_next_snapshot_segment().await?;
                }
            }

            NetworkEvent::StateSegmentRequestFailed {
                from,
                segment_id,
                expected_tip_height,
                expected_tip_hash,
                manifest_digest,
                kind,
            } => {
                let now_ms = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64;

                let mut correlated = false;

                {
                    let mut sync_guard = self.active_snapshot_sync.lock().await;

                    if let Some(sync) = sync_guard.as_mut() {
                        if let Some(segment) = sync.segment(segment_id) {
                            if segment.snapshot.boundary.height == expected_tip_height
                                && segment.snapshot.boundary.hash == expected_tip_hash
                                && segment.snapshot.manifest_digest == manifest_digest
                            {
                                correlated = true;

                                match kind {
                                    noid_p2p::RequestFailureKind::LocalCapacity => {
                                        sync
                                            .defer_request(
                                                noid_networking::
                                                    snapshot_sync::
                                                    SnapshotSegmentRequest {
                                                        peer:
                                                            from,
                                                        segment,
                                                    }
                                            )
                                            .context(
                                                "defer locally saturated mobile State request"
                                            )?;
                                    }

                                    noid_p2p::RequestFailureKind::Unavailable => {
                                        sync.unavailable(from, segment)
                                            .context("record unavailable mobile State provider")?;
                                    }

                                    noid_p2p::RequestFailureKind::InvalidResponse => {
                                        sync.reject_provider(from, segment).context(
                                            "quarantine malformed mobile State provider",
                                        )?;
                                    }

                                    _ => {
                                        sync.request_failed(from, segment, now_ms)
                                            .context("rotate failed mobile State provider")?;
                                    }
                                }
                            }
                        }
                    }
                }

                if correlated {
                    tracing::warn!(
                        peer = %from,
                        segment = segment_id,
                        ?kind,
                        "mobile State request failed; authenticated progress retained"
                    );

                    self.dispatch_next_snapshot_segment().await?;
                } else {
                    tracing::debug!(
                        peer = %from,
                        segment = segment_id,
                        "ignoring stale mobile State request failure"
                    );
                }
            }

            NetworkEvent::StateSegmentRequestBusy {
                from,
                segment_id,
                expected_tip_height,
                expected_tip_hash,
                manifest_digest,
                retry_after_ms,
            } => {
                let retry_at_ms = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64
                    + u64::from(retry_after_ms);

                let mut correlated = false;

                {
                    let mut sync_guard = self.active_snapshot_sync.lock().await;

                    if let Some(sync) = sync_guard.as_mut() {
                        if let Some(segment) = sync.segment(segment_id) {
                            if segment.snapshot.boundary.height == expected_tip_height
                                && segment.snapshot.boundary.hash == expected_tip_hash
                                && segment.snapshot.manifest_digest == manifest_digest
                            {
                                sync.request_busy(from, segment, retry_at_ms)
                                    .context("record busy mobile State provider")?;

                                correlated = true;
                            }
                        }
                    }
                }

                if correlated {
                    tracing::debug!(
                        peer = %from,
                        segment = segment_id,
                        retry_after_ms,
                        "mobile State provider busy; exact plan retained"
                    );

                    self.dispatch_next_snapshot_segment().await?;
                }
            }
        }

        Ok(())
    }

    fn spawn_mempool_relay(&self) {
        let mut events = self.node.mempool.subscribe();

        let p2p_cmd = self.network.cmd_tx.clone();

        tokio::spawn(async move {
            loop {
                match events.recv().await {
                    Ok(noid_mempool::MempoolEvent::TxAdmitted { intent_bytes, .. }) => {
                        if let Err(error) = p2p_cmd
                            .send(noid_p2p::NetworkCommand::BroadcastTx { intent_bytes })
                            .await
                        {
                            tracing::warn!(
                                %error,
                                "mobile mempool relay command failed"
                            );

                            break;
                        }
                    }

                    Ok(_) => {}

                    Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                        tracing::warn!(skipped, "mobile mempool relay lagged");
                    }

                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        });
    }

    pub async fn run(self: Arc<Self>) -> Result<()> {
        self.spawn_mempool_relay();
        let mut events = self.network.subscribe();

        let mut ticker = tokio::time::interval(Duration::from_millis(SCHEDULER_TICK_MS));

        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    self.dispatch_exact_requests().await;

                    if let Err(error) =
                        self.maybe_apply_complete_suffix().await
                    {
                        tracing::warn!(
                            %error,
                            "mobile exact suffix apply failed"
                        );
                    }

                    if let Err(error) =
                        self
                            .drive_bootstrap_tail()
                            .await
                    {
                        tracing::warn!(
                            %error,
                            "mobile post-snapshot tail driver failed"
                        );
                    }

                    self
                        .drive_live_suffix_recovery()
                        .await;
                }

                received = events.recv() => {
                    match received {
                        Ok(event) => {
                            if let Err(error) =
                                self.handle_event(event).await
                            {
                                android_sync_log(format!(
                                    "EVENT ERROR: {:#}",
                                    error
                                ));

                                tracing::warn!(
                                    %error,
                                    "mobile P2P event failed"
                                );
                            }
                        }

                        Err(NetworkEventRecvError::Lagged(skipped)) => {
                            // Required exact-object responses are on the
                            // backpressured queue and are NOT lost here.
                            tracing::warn!(
                                skipped,
                                "mobile replaceable P2P gossip lagged"
                            );
                        }

                        Err(NetworkEventRecvError::Closed) => {
                            anyhow::bail!(
                                "mobile P2P event stream closed"
                            );
                        }
                    }
                }
            }
        }
    }
}
