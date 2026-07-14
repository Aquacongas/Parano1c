// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Block template management.
//!
//! A `BlockTemplate` is a fully computed block ready for PoW + proving:
//! - Transaction set selected, conflict-resolved, ordered
//! - State applied to scratch → `state_root` known
//! - Coinbase constructed
//! - Correct ASERT difficulty target computed
//! - All semantic header fields set except `nonce`
//!
//! ## Template refresh triggers
//!
//! 1. Heartbeat every `refresh_interval_secs` seconds (safety net)
//! 2. First `TxAdmitted` while a coinbase-only no-proof block is being mined
//! 3. New chain tip from P2P (block received or snapshot applied via `sync_ready`)

use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
};

use noid_chain::block::Block;
use noid_chain::block_header::BlockHeader;
use noid_chain::consensus::difficulty::next_target;
use noid_chain::consensus::pow::block_id;
use noid_chain::consensus::template::BlockTemplate as ChainTemplate;
use noid_chain::consensus::AnchorInfo;
use noid_chain::state::ChainState;
use noid_chain::storage::{MdbxChainContext, MdbxContextError, MdbxStore};
use noid_mempool::AsyncMempool;
use noid_poseidon2b::primitives::Address;

use crate::cpu_budget::install_process_proof_cpu;
use crate::topology_gate::{ProofTopologyGate, ProofTopologyReservation};

/// Shared one-shot capability. All immutable template clones race on the same
/// owning reservation, so at most one caller may assemble the detached proof
/// payload and the topology slot cannot disappear between build and proof.
#[derive(Clone)]
struct ProofTemplateAuthorization {
    reservation: Arc<Mutex<Option<ProofTopologyReservation>>>,
}

impl ProofTemplateAuthorization {
    fn new(reservation: ProofTopologyReservation) -> Self {
        Self {
            reservation: Arc::new(Mutex::new(Some(reservation))),
        }
    }

    fn consume(&self) -> Option<ProofTopologyReservation> {
        self.reservation
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
    }
}

/// Owns the global heavy-proof admission for exactly the template build.
/// Dropping this guard on any early return releases the reservation.
struct TopologyAdmittedTemplateBuild {
    reservation: Option<ProofTopologyReservation>,
}

impl TopologyAdmittedTemplateBuild {
    fn new(reservation: Option<ProofTopologyReservation>) -> Self {
        Self { reservation }
    }

    /// Finish the budgeted build and transfer its owning reservation into the
    /// shared one-shot template capability. The reservation is atomically
    /// narrowed from the selection cap to the exact finalized native tier;
    /// it then lives until proof return/unwind or the last template clone drop.
    fn finish<T>(
        mut self,
        user_txs: usize,
        complete: impl FnOnce(Option<ProofTemplateAuthorization>) -> T,
    ) -> Result<T, &'static str> {
        let authorization = match (user_txs, self.reservation.take()) {
            (0, reservation) => {
                drop(reservation);
                None
            }
            (_, None) => {
                return Err("tx-bearing template completed without proof-stage admission");
            }
            (_, Some(reservation)) => Some(ProofTemplateAuthorization::new(
                reservation
                    .narrow_for_native_user_txs(user_txs)?
                    .ok_or("tx-bearing template lost its proof-stage admission")?,
            )),
        };
        Ok(complete(authorization))
    }
}

/// Why the template was refreshed (carried in `MinerEvent::TemplateRefreshed`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TemplateRefreshTrigger {
    /// Regular heartbeat (safety net — fires every `refresh_interval_secs`).
    Heartbeat,
    /// First `TxAdmitted` event while prove was already done (Sealed state).
    /// The miner immediately rebuilds to include the new tx in the current block.
    TxAdmitted,
    /// New chain tip available: P2P block applied or state snapshot synced.
    SyncReady,
    /// Node startup — generate the very first template.
    Startup,
}

/// A `BlockTemplate` ready for parallel PoW + block-certificate assembly.
///
/// Security: `state_root` is in the Poseidon2b PoW field schedule.
/// An external miner CANNOT change the coinbase without regenerating the
/// block certificate — they only brute-force the nonce.
#[derive(Clone)]
pub struct BlockTemplate {
    /// Inner chain-level template with tx ordering and coinbase.
    pub inner: ChainTemplate,
    /// Correctly computed ASERT difficulty target for the new block.
    pub difficulty_target: [u8; 32],
    /// Miner address (coinbase recipient).
    pub miner_address: Address,
    /// Timestamp used for this template.
    pub timestamp: u64,
    /// Parent header.
    pub parent: BlockHeader,
    /// Cached WalletAuthorizationBundle bytes for each non-coinbase tx (same order as inner.txs).
    pub authorization_bytes: Vec<Option<Vec<u8>>>,
    /// Exact authenticated state transition proof for user-transaction blocks.
    pub exact_state_transition: Option<noid_block::ExactStateTransitionProof>,
    /// Serialized Link terminal envelope attached when this template advances
    /// `header.attested_coverage` beyond the parent's. Empty when the header
    /// keeps the parent's coverage.
    pub coverage_attestation_bytes: Vec<u8>,
    /// One-shot owning admission minted only after tx-bearing template
    /// construction completes under the process-wide proof topology gate.
    /// Shared clones transfer the same private reservation exactly once.
    proof_template_authorization: Option<ProofTemplateAuthorization>,
}

impl BlockTemplate {
    /// Build the partial header for PoW search.
    ///
    /// The miner hashes the fixed semantic header field schedule.
    pub fn header_for_pow(&self, nonce: u128) -> BlockHeader {
        self.inner.to_pow_header(nonce)
    }

    /// Assemble the final sealed block after PoW and certificate assembly complete.
    pub fn seal(&self, nonce: u128) -> Block {
        let header = self.inner.clone().into_header(nonce);
        Block {
            header,
            transactions: self.inner.all_txs(),
        }
    }

    /// Number of non-coinbase transactions.
    pub fn n_user_txs(&self) -> usize {
        self.inner.txs.len()
    }

    /// Transfer the one owning proof reservation shared by every clone of this
    /// immutable template. Exactly one caller can cross this edge.
    pub(crate) fn take_proof_topology_reservation(&self) -> Option<ProofTopologyReservation> {
        self.proof_template_authorization
            .as_ref()
            .and_then(ProofTemplateAuthorization::consume)
    }
}

/// Immutable chain view used for template construction.
///
/// Capture this under the chain lock, then drop the lock before awaiting mempool
/// selection or doing proof/template work. Raw segment columns are deliberately
/// excluded; selected transaction segments are faulted in from the cloned MDBX
/// handle only after the topology gate admits the job.
pub struct TemplateChainSnapshot {
    pub parent: BlockHeader,
    pub prev_active_counts: Vec<u64>,
    pub prev_timestamps: Vec<u64>,
    pub anchor: AnchorInfo,
    pub state: ChainState,
    /// Local durable coverage advancement to attest in the new block:
    /// `(coverage_height, serialized Link terminal envelope)`. `None` when the
    /// local proven frontier does not exceed the parent's attested coverage.
    pub coverage_attachment: Option<(u64, Vec<u8>)>,
    user_epoch_anchor: [u8; 32],
    store: MdbxStore,
}

impl TemplateChainSnapshot {
    pub fn from_context(ctx: &mut MdbxChainContext) -> Result<Self, MdbxContextError> {
        let parent = *ctx.tip_header();
        let anchor_height =
            noid_chain::consensus::tx_epoch_anchor_height_for_child(parent.height + 1);
        let user_epoch_anchor = ctx
            .get_header_from_store(anchor_height)?
            .map(|header| block_id(&header))
            .ok_or(MdbxContextError::Corrupt(
                "transaction epoch anchor header missing",
            ))?;
        let coverage_attachment = local_coverage_attachment(ctx, &parent);

        Ok(Self {
            parent,
            prev_active_counts: ctx.prev_active_counts(),
            prev_timestamps: ctx.prev_timestamps(),
            anchor: ctx.anchor_info(),
            state: ctx
                .state
                .durable_metadata_clone()
                .ok_or(MdbxContextError::Corrupt(
                    "template snapshot requested outside durable state boundary",
                ))?,
            coverage_attachment,
            user_epoch_anchor,
            store: ctx.store.clone(),
        })
    }

    /// Coverage the new header will attest: the attachment's height when the
    /// local proven frontier advanced, otherwise the parent's value.
    pub fn template_attested_coverage(&self) -> u64 {
        self.coverage_attachment
            .as_ref()
            .map(|(height, _)| *height)
            .unwrap_or(self.parent.attested_coverage)
    }

    pub fn prev_state_root(&self) -> [u8; 32] {
        self.parent.state_root
    }

    fn hydrate_transaction_segments(
        &self,
        state: &mut ChainState,
        txs: &[noid_tx::Transaction],
    ) -> Result<(), MdbxContextError> {
        let effective_log = state.state.effective_log_segment_size();
        let mut needed = HashSet::new();
        for tx in txs {
            for (_, input) in tx.body.live_inputs() {
                needed.insert((input.slot_index >> effective_log) as u16);
            }
            for (_, output) in tx.body.live_outputs() {
                needed.insert((output.slot_index >> effective_log) as u16);
            }
        }
        self.hydrate_segments(state, needed)
    }

    /// The coinbase allocator probes a bounded virgin-zone hint window that
    /// touches at most two segments for the snapshot's `alloc_counter`. A
    /// freshly committed chain evicts exactly those segments — only
    /// block-dirty segments stay resident — so without hydrating them every
    /// hint fails the template's residency filter and mining halts with
    /// `NoCoinbaseSlot` on the next block while the state is almost empty
    /// (live-test finding, 2026-07-12). The needed segments are derived from
    /// the production hint stream itself, so any future allocator change
    /// keeps this in lockstep; the cost is bounded by two 3-MiB segments.
    fn hydrate_coinbase_allocator_segments(
        &self,
        state: &mut ChainState,
    ) -> Result<(), MdbxContextError> {
        let effective_log = state.state.effective_log_segment_size();
        let log_slots = state.state.log_slots() as u32;
        let needed: HashSet<u16> =
            noid_chain::consensus::generate_slot_hints(state.alloc_counter, log_slots, 65_536)
                .into_iter()
                .map(|slot| (slot >> effective_log) as u16)
                .collect();
        self.hydrate_segments(state, needed)
    }

    fn hydrate_segments(
        &self,
        state: &mut ChainState,
        needed: HashSet<u16>,
    ) -> Result<(), MdbxContextError> {
        for segment_id in needed {
            if !state.state.is_evicted(segment_id) {
                continue;
            }
            let (_, columns) =
                self.store
                    .get_segment(segment_id)?
                    .ok_or(MdbxContextError::Corrupt(
                        "template segment is missing from durable state",
                    ))?;
            state
                .restore_evicted_segment(segment_id, columns)
                .map_err(|_| {
                    MdbxContextError::Corrupt("template segment exact summary mismatch")
                })?;
        }
        Ok(())
    }
}

/// Read the local durable selected-history coverage pointer and, when it
/// advances past the parent's attested coverage, load the matching Link
/// terminal envelope for attachment.
///
/// Mining must never be throttled by the proof pipeline: every failure or
/// inconsistency here degrades to `None` (build a non-attesting template)
/// instead of erroring.
fn local_coverage_attachment(
    ctx: &MdbxChainContext,
    parent: &BlockHeader,
) -> Option<(u64, Vec<u8>)> {
    let coverage = match ctx.store.get_selected_history_coverage() {
        Ok(Some(coverage)) => coverage,
        Ok(None) => return None,
        Err(error) => {
            tracing::warn!(err = %error, "template coverage pointer read failed");
            return None;
        }
    };
    // Consensus bounds: strictly advancing and provable within the parent
    // chain (C <= parent.height). Coverage can never exceed the tip, but a
    // racing rewind makes this a cheap fail-open guard.
    if coverage.height <= parent.attested_coverage || coverage.height > parent.height {
        return None;
    }
    // The envelope must bind the CANONICAL header at C; a stale pointer left
    // by a reorg rewind would fail block validation, so skip attaching it.
    match ctx.get_header_from_store(coverage.height) {
        Ok(Some(header)) if noid_chain::hash_block_header(&header) == coverage.block_hash => {}
        Ok(_) => return None,
        Err(error) => {
            tracing::warn!(err = %error, "template coverage header read failed");
            return None;
        }
    }
    match ctx
        .store
        .get_selected_history_terminal_result_at(coverage.height, coverage.block_hash)
    {
        Ok(Some(result))
            if !result.bytes.is_empty()
                && result.bytes.len()
                    <= noid_chain::consensus::wire_limits::MAX_COVERAGE_ATTESTATION_BYTES =>
        {
            Some((coverage.height, result.bytes))
        }
        Ok(_) => None,
        Err(error) => {
            tracing::warn!(err = %error, "template coverage terminal read failed");
            None
        }
    }
}

/// Builds `BlockTemplate` from a chain snapshot and top-fee mempool txs.
pub struct TemplateBuilder {
    pub mempool: AsyncMempool,
}

impl TemplateBuilder {
    pub fn new(mempool: AsyncMempool) -> Self {
        Self { mempool }
    }

    /// Build a new template using a pre-captured chain snapshot and top-fee mempool txs.
    ///
    /// Computes the ASERT difficulty target correctly using `next_target()`.
    pub async fn build_from_snapshot(
        &self,
        snapshot: &TemplateChainSnapshot,
        miner_address: Address,
        now_unix: u64,
    ) -> Option<BlockTemplate> {
        self.build_from_snapshot_with_limit(
            snapshot,
            miner_address,
            now_unix,
            noid_chain::consensus::params::BLOCK_MAX_USER_TXS,
        )
        .await
    }

    /// Build a template while capping non-coinbase transactions.
    /// Internal miners use this for adaptive block sizing; external mining keeps
    /// the consensus maximum via `build_from_snapshot`.
    pub async fn build_from_snapshot_with_limit(
        &self,
        snapshot: &TemplateChainSnapshot,
        miner_address: Address,
        now_unix: u64,
        max_user_txs: usize,
    ) -> Option<BlockTemplate> {
        use noid_chain::consensus::median_time_past;

        let parent = &snapshot.parent;
        let prev_active_counts = &snapshot.prev_active_counts;
        let prev_timestamps = &snapshot.prev_timestamps;

        // Compute the minimum valid timestamp for the new block:
        //   timestamp MUST be strictly greater than MTP (median of last 11 blocks).
        //   See validate_timestamp in noid_chain::consensus::timestamps.
        // This prevents BadTimestamp when blocks are found faster than 1 second
        // (genesis target is trivial; multiple blocks per second are possible).
        let mtp = median_time_past(prev_timestamps);
        let min_valid_ts = mtp + 1;
        let timestamp = now_unix.max(min_valid_ts);

        // Compute the correct ASERT target for the new block.
        // MUST match what validate_header computes; wrong target = block rejected.
        let anchor = &snapshot.anchor;
        let difficulty_target = next_target(
            anchor.anchor_height,
            anchor.anchor_timestamp,
            &anchor.anchor_target,
            parent.height + 1,
            timestamp,
        );

        // Select top txs from mempool (coinbase is added separately by the chain template).
        let consensus_max = noid_chain::consensus::params::BLOCK_MAX_USER_TXS;
        let topology_gate = ProofTopologyGate::global();
        let max_user_txs = max_user_txs
            .min(consensus_max)
            .min(topology_gate.max_user_txs_now());
        let proof_build_admission = match topology_gate.try_admit_native_user_txs(max_user_txs) {
            Ok(reservation) => reservation,
            Err(error) => {
                tracing::warn!(
                    max_user_txs,
                    error = %error,
                    "proof template deferred by process proof topology"
                );
                return None;
            }
        };
        let proof_build_admission = TopologyAdmittedTemplateBuild::new(proof_build_admission);
        // Filter against the captured anchor while entries are still borrowed
        // under the mempool lock. This preserves the same fee-ordered prefix
        // but clones only the proof bundles admitted by the active topology.
        let entries = self
            .mempool
            .select_for_block_at_anchor(max_user_txs, snapshot.user_epoch_anchor)
            .await;
        // Single-pass: move authorization bytes and transactions together (no clone).
        let (authorization_bytes, txs): (Vec<Option<Vec<u8>>>, Vec<_>) = entries
            .into_iter()
            .map(|e| (e.cached_authorization, e.tx))
            .unzip();

        // Recheck exact start-of-block anchor after selection. A boundary may
        // have advanced while the transaction waited in the mempool.
        // Re-check proof-gated coinbase maturity the same way: admission used
        // the tip coverage at submit time, but the block being built attests
        // `template_attested_coverage()` (same-block attestation counts).
        let template_coverage = snapshot.template_attested_coverage();
        let (authorization_bytes, txs): (Vec<_>, Vec<_>) = authorization_bytes
            .into_iter()
            .zip(txs)
            .filter(|(_, tx)| tx.body.epoch_anchor == snapshot.user_epoch_anchor)
            .filter(|(_, tx)| {
                !tx.body.live_inputs().any(|(_, input)| {
                    noid_chain::consensus::params::is_coinbase_creation_id(input.creation_id)
                        && noid_chain::consensus::params::coinbase_creation_height(
                            input.creation_id,
                        ) > template_coverage
                })
            })
            .take(max_user_txs)
            .unzip();
        let mut proof_by_hash: HashMap<noid_poseidon2b::primitives::TxBodyHash, Option<Vec<u8>>> =
            authorization_bytes
                .into_iter()
                .zip(txs.iter().map(|tx| tx.txid()))
                .map(|(proof, hash)| (hash, proof))
                .collect();

        // Fault in only segments referenced by the admitted transaction set.
        // The canonical snapshot itself remains metadata-only, so template
        // construction never clones unrelated UTXO columns.
        let mut state = snapshot.state.clone();
        if let Err(error) = snapshot.hydrate_transaction_segments(&mut state, &txs) {
            tracing::warn!(err = %error, "template touched-segment hydration failed");
            return None;
        }
        if let Err(error) = snapshot.hydrate_coinbase_allocator_segments(&mut state) {
            tracing::warn!(err = %error, "template allocator-segment hydration failed");
            return None;
        }
        let template_cpu_result = install_process_proof_cpu(|| {
            let inner = match noid_chain::consensus::template::build_block_template_with_coverage(
                parent,
                &state,
                prev_active_counts,
                txs,
                miner_address,
                timestamp,
                difficulty_target,
                template_coverage,
            ) {
                Ok(inner) => inner,
                Err(error) => {
                    tracing::warn!(err = ?error, "template build failed");
                    return None;
                }
            };
            let exact_state_transition = if inner.txs.is_empty() {
                None
            } else {
                // Expansion blocks are coinbase-only (template building
                // clears user txs when log_slots grows), so a tx-bearing
                // template always shares the snapshot state's log_slots
                // and the action surface builds against the snapshot
                // directly — no expanded whole-state copy.
                if inner.log_slots as usize != state.state.log_slots() {
                    tracing::warn!(
                        template_log_slots = inner.log_slots,
                        state_log_slots = state.state.log_slots(),
                        "tx-bearing template log_slots diverges from snapshot state"
                    );
                    return None;
                }
                let bodies: Vec<_> = std::iter::once(inner.coinbase.body.clone())
                    .chain(inner.txs.iter().map(|tx| tx.body.clone()))
                    .collect();
                let commitments: Vec<[u8; 32]> = bodies
                    .iter()
                    .map(noid_tx::compute_claims_commitment)
                    .collect();
                let surface = match noid_chain::build_exact_action_surface(
                    &state.state,
                    &bodies,
                    &commitments,
                    state.alloc_counter,
                    inner.height,
                ) {
                    Ok(surface) => surface,
                    Err(error) => {
                        tracing::warn!(err = ?error, "exact state surface build failed");
                        return None;
                    }
                };
                let siblings = match state
                    .exact_frontier_siblings(&surface.touched_indices, inner.log_slots)
                {
                    Ok(siblings) => siblings,
                    Err(error) => {
                        tracing::warn!(err = %error, "compact exact frontier build failed");
                        return None;
                    }
                };
                match noid_block::build_exact_state_transition_proof_from_siblings(
                    &surface,
                    siblings,
                    inner.log_slots,
                ) {
                    Ok(proof) => Some(proof),
                    Err(error) => {
                        tracing::warn!(err = ?error, "bounded exact state proof build failed");
                        return None;
                    }
                }
            };
            Some((inner, exact_state_transition))
        });
        let (inner, exact_state_transition) = match template_cpu_result {
            Ok(Some(result)) => result,
            Ok(None) => return None,
            Err(error) => {
                tracing::error!(
                    %error,
                    "template exact-state CPU admission failed closed"
                );
                return None;
            }
        };

        let authorization_bytes = inner
            .txs
            .iter()
            .map(|tx| proof_by_hash.remove(&tx.txid()).unwrap_or(None))
            .collect();
        let coverage_attestation_bytes = snapshot
            .coverage_attachment
            .as_ref()
            .map(|(_, bytes)| bytes.clone())
            .unwrap_or_default();
        let actual_user_txs = inner.txs.len();
        match proof_build_admission.finish(actual_user_txs, |proof_template_authorization| {
            BlockTemplate {
                inner,
                difficulty_target,
                miner_address,
                timestamp,
                parent: *parent,
                authorization_bytes,
                exact_state_transition,
                coverage_attestation_bytes,
                proof_template_authorization,
            }
        }) {
            Ok(template) => Some(template),
            Err(error) => {
                tracing::error!(%error, "proof template authorization failed closed");
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn synthetic_transaction(is_coinbase: bool) -> noid_tx::Transaction {
        noid_tx::Transaction::new(noid_tx::TxBody {
            epoch_anchor: [0u8; 32],
            fee: 0,
            input_owner: Address([0u8; 32]),
            inputs: [noid_tx::TxInput::dummy(); noid_tx::TX_INPUTS],
            outputs: [noid_tx::TxOutput::dummy(); noid_tx::TX_OUTPUTS],
            validity_bitmap: 0,
            is_coinbase,
        })
    }

    fn synthetic_template(
        user_txs: usize,
        proof_template_authorization: Option<ProofTemplateAuthorization>,
    ) -> BlockTemplate {
        let miner_address = Address([7u8; 32]);
        let inner = ChainTemplate {
            coinbase: synthetic_transaction(true),
            txs: (0..user_txs)
                .map(|_| synthetic_transaction(false))
                .collect(),
            state_root: [2u8; 32],
            tx_root: [3u8; 32],
            active_slot_count: 0,
            alloc_counter: 0,
            log_slots: 8,
            height: 1,
            timestamp: 1,
            miner_address,
            difficulty_target: [0xff; 32],
            prev_block_hash: [0u8; 32],
            attested_coverage: 0,
        };
        BlockTemplate {
            inner,
            difficulty_target: [0xff; 32],
            miner_address,
            timestamp: 1,
            parent: BlockHeader {
                prev_block_hash: [0u8; 32],
                state_root: [1u8; 32],
                tx_root: [0u8; 32],
                timestamp: 0,
                height: 0,
                miner_address: Address([0u8; 32]),
                nonce: 0,
                difficulty_target: [0xff; 32],
                log_slots: 8,
                active_slot_count: 0,
                alloc_counter: 0,
                attested_coverage: 0,
            },
            authorization_bytes: vec![None; user_txs],
            exact_state_transition: None,
            coverage_attestation_bytes: Vec::new(),
            proof_template_authorization,
        }
    }

    fn native_test_reservation(
        gate: &ProofTopologyGate,
        user_txs: usize,
    ) -> ProofTopologyReservation {
        gate.try_admit_native_user_txs(user_txs)
            .expect("native proof admission")
            .expect("tx-bearing native reservation")
    }

    #[test]
    fn max_b255_selection_cap_downgrades_to_owned_native_b8() {
        let governor = ProofTopologyGate::for_tests();
        let admission =
            TopologyAdmittedTemplateBuild::new(Some(native_test_reservation(&governor, 255)));
        assert!(governor.try_admit_selected_history_session(64).is_err());

        let authorization = admission
            .finish(1, |authorization| {
                assert!(governor.try_admit_selected_history_session(64).is_ok());
                authorization
            })
            .expect("budgeted tx template")
            .expect("tx proof authorization");
        assert!(governor.try_admit_native_user_txs(9).is_err());
        let reservation = authorization.consume().expect("owning native B8 admission");
        assert!(authorization.consume().is_none());
        drop(reservation);
        drop(native_test_reservation(&governor, 9));
    }

    #[test]
    fn failed_or_empty_template_build_releases_native_admission() {
        let governor = ProofTopologyGate::for_tests();
        let abandoned_build =
            TopologyAdmittedTemplateBuild::new(Some(native_test_reservation(&governor, 255)));

        drop(abandoned_build);
        drop(native_test_reservation(&governor, 255));

        let empty =
            TopologyAdmittedTemplateBuild::new(Some(native_test_reservation(&governor, 255)))
                .finish(0, |authorization| authorization)
                .expect("empty template completion");
        assert!(empty.is_none());
        drop(native_test_reservation(&governor, 255));

        assert!(TopologyAdmittedTemplateBuild::new(None)
            .finish(1, |_| ())
            .is_err());
    }

    #[test]
    fn template_clones_transfer_one_reservation_held_through_error() {
        let governor = ProofTopologyGate::for_tests();
        let authorization =
            TopologyAdmittedTemplateBuild::new(Some(native_test_reservation(&governor, 8)))
                .finish(1, |authorization| authorization)
                .expect("budgeted tx template")
                .expect("tx proof authorization");
        let template = synthetic_template(1, Some(authorization));
        let cloned_template = template.clone();

        let first = crate::miner::run_prove_block(&template, [1u8; 32])
            .expect_err("synthetic template has no authorization bundle");
        assert!(first.contains("missing WalletAuthorizationBundle"));
        assert_eq!(
            crate::miner::run_prove_block(&cloned_template, [1u8; 32]),
            Err("unadmitted or already-consumed proof template rejected".to_string())
        );
        drop(native_test_reservation(&governor, 9));
    }

    #[test]
    fn unadmitted_tx_is_rejected_but_coinbase_only_needs_no_marker() {
        assert_eq!(
            crate::miner::run_prove_block(&synthetic_template(1, None), [1u8; 32]),
            Err("unadmitted or already-consumed proof template rejected".to_string())
        );
        assert_eq!(
            crate::miner::run_prove_block(&synthetic_template(0, None), [1u8; 32]),
            Ok((Vec::new(), Vec::new()))
        );
    }
}
