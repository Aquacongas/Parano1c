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

use crate::memory_governor::{ProofMemoryGovernor, ProofMemoryReservation};

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
    /// Process-wide proof-memory reservation acquired before cached proof bytes
    /// or exact-state artifacts are cloned into this template. Shared clones
    /// keep the reservation alive until the blocking prover actually exits.
    proof_memory_reservation: Option<Arc<Mutex<Option<ProofMemoryReservation>>>>,
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

    /// Consume the one proof-job reservation shared by every clone of this
    /// immutable template. Exactly one blocking worker can cross this edge.
    pub(crate) fn take_proof_memory_reservation(&self) -> Option<ProofMemoryReservation> {
        self.proof_memory_reservation.as_ref()?.lock().ok()?.take()
    }
}

/// Immutable chain view used for template construction.
///
/// Capture this under the chain lock, then drop the lock before awaiting mempool
/// selection or doing proof/template work. Raw segment columns are deliberately
/// excluded; selected transaction segments are faulted in from the cloned MDBX
/// handle only after the memory governor admits the job.
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
        let needed: HashSet<u16> = noid_chain::consensus::generate_slot_hints(
            state.alloc_counter,
            log_slots,
            65_536,
        )
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
        Ok(Some(header))
            if noid_chain::hash_block_header(&header) == coverage.block_hash => {}
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
        let memory_governor = ProofMemoryGovernor::global(0);
        let max_user_txs = max_user_txs
            .min(consensus_max)
            .min(memory_governor.max_user_txs_now());
        let proof_memory_reservation = match memory_governor.try_reserve_for_user_txs(max_user_txs)
        {
            Ok(reservation) => reservation,
            Err(pressure) => {
                tracing::warn!(
                    max_user_txs,
                    required_mib = pressure.required_mib,
                    available_mib = pressure.available_mib,
                    "proof template rejected by process memory governor"
                );
                return None;
            }
        };
        // Filter against the captured anchor while entries are still borrowed
        // under the mempool lock. This preserves the same fee-ordered prefix
        // but clones only the proof bundles admitted by the runtime budget.
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
        match noid_chain::consensus::template::build_block_template_with_coverage(
            parent,
            &state,
            prev_active_counts,
            txs,
            miner_address,
            timestamp,
            difficulty_target,
            template_coverage,
        ) {
            Ok(inner) => {
                let proof_memory_reservation = if inner.txs.is_empty() {
                    None
                } else {
                    proof_memory_reservation
                        .map(|reservation| Arc::new(Mutex::new(Some(reservation))))
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
                        Err(e) => {
                            tracing::warn!(err = ?e, "exact state surface build failed");
                            return None;
                        }
                    };
                    let siblings = match state
                        .exact_frontier_siblings(&surface.touched_indices, inner.log_slots)
                    {
                        Ok(siblings) => siblings,
                        Err(e) => {
                            tracing::warn!(err = %e, "compact exact frontier build failed");
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
                Some(BlockTemplate {
                    inner,
                    difficulty_target,
                    miner_address,
                    timestamp,
                    parent: *parent,
                    authorization_bytes,
                    exact_state_transition,
                    coverage_attestation_bytes,
                    proof_memory_reservation,
                })
            }
            Err(e) => {
                tracing::warn!("template build failed: {:?}", e);
                None
            }
        }
    }
}
