// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Block template management.
//!
//! A `BlockTemplate` is a fully computed block ready for PoW + proving:
//! - Transaction set selected, conflict-resolved, ordered
//! - State applied to scratch → `state_root` known
//! - Coinbase constructed
//! - Correct ASERT difficulty target computed
//! - All header fields set except `nonce` and `proof_transcript_hash`
//!
//! ## Template refresh triggers
//!
//! 1. Heartbeat every `refresh_interval_secs` seconds (safety net)
//! 2. First `TxAdmitted` while a coinbase-only marker proof is done
//! 3. New chain tip from P2P (block received or snapshot applied via `sync_ready`)

use std::collections::HashMap;

use noid_chain::block::Block;
use noid_chain::block_header::BlockHeader;
use noid_chain::consensus::difficulty::next_target;
use noid_chain::consensus::pow::full_block_hash;
use noid_chain::consensus::template::BlockTemplate as ChainTemplate;
use noid_chain::consensus::AnchorInfo;
use noid_chain::segmented_state::SegmentColumns;
use noid_chain::state::ChainState;
use noid_chain::storage::{MdbxChainContext, MdbxContextError};
use noid_mempool::AsyncMempool;
use noid_poseidon2b::primitives::Address;
use noid_tx::TxShape;

/// Shapes that the current cryptographic block prover can include directly in a block.
#[inline]
fn is_current_block_provable_shape(shape: TxShape) -> bool {
    matches!(shape, TxShape::Standard4x8 | TxShape::Sweep25x2)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_block_template_policy_accepts_current_zk_bound_shapes() {
        assert!(is_current_block_provable_shape(TxShape::Standard4x8));
        assert!(is_current_block_provable_shape(TxShape::Sweep25x2));
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

/// A `BlockTemplate` ready for parallel PoW + BlockProof generation.
///
/// Security: `state_root` is in `header_core` which is the PoW input.
/// An external miner CANNOT change the coinbase without regenerating the
/// entire BlockProof — they only brute-force the nonce.
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
    /// Cached WalletProofBundle bytes for each non-coinbase tx (same order as inner.txs).
    pub proof_bytes: Vec<Option<Vec<u8>>>,
    /// Pre-state segment columns for every segment touched by this block's transactions.
    /// Captured at template-build time (before `apply_block`), keyed by seg_id.
    /// Used by the BlockProof generator for FRI state openings.
    pub pre_segs: HashMap<u16, SegmentColumns>,
}

impl BlockTemplate {
    /// Build the partial header for PoW search.
    ///
    /// `proof_transcript_hash` and `witness_root` are zero — they are NOT in
    /// the PoW hash (`header_core`). The miner only hashes `header_core`.
    pub fn header_for_pow(&self, nonce: u128) -> BlockHeader {
        self.inner.to_pow_header(nonce)
    }

    /// Assemble the final sealed block after PoW and BlockProof generation complete.
    pub fn seal(
        &self,
        nonce: u128,
        proof_transcript_hash: [u8; 32],
        witness_root: [u8; 32],
    ) -> Block {
        let header = self
            .inner
            .clone()
            .into_header(nonce, proof_transcript_hash, witness_root);
        Block {
            header,
            transactions: self.inner.all_txs(),
        }
    }

    /// Number of non-coinbase transactions.
    pub fn n_user_txs(&self) -> usize {
        self.inner.txs.len()
    }
}

/// Immutable chain view used for template construction.
///
/// Capture this under the chain lock, then drop the lock before awaiting mempool
/// selection or doing proof/template work. `from_context()` preloads evicted
/// segments before cloning so the scratch state used by block assembly sees the
/// same slots as the durable chain state.
pub struct TemplateChainSnapshot {
    pub parent: BlockHeader,
    pub prev_active_counts: Vec<u64>,
    pub prev_timestamps: Vec<u64>,
    pub anchor: AnchorInfo,
    pub state: ChainState,
    fresh_anchor_hashes: Vec<[u8; 32]>,
}

impl TemplateChainSnapshot {
    pub fn from_context(ctx: &mut MdbxChainContext) -> Result<Self, MdbxContextError> {
        ctx.preload_all_evicted_segments()?;

        let parent = ctx.tip_header().clone();
        let tip_height = parent.height;
        let lo = tip_height.saturating_sub(noid_chain::consensus::params::ANCHOR_DEPTH);
        let fresh_anchor_hashes = (lo..=tip_height)
            .filter_map(|h| ctx.header(h).map(full_block_hash))
            .collect();

        Ok(Self {
            parent,
            prev_active_counts: ctx.prev_active_counts(),
            prev_timestamps: ctx.prev_timestamps(),
            anchor: ctx.anchor_info(),
            state: ctx.state.clone(),
            fresh_anchor_hashes,
        })
    }

    pub fn prev_state_root(&self) -> [u8; 32] {
        self.parent.state_root
    }

    fn is_anchor_fresh(&self, anchor_hash: &[u8; 32]) -> bool {
        self.fresh_anchor_hashes.iter().any(|h| h == anchor_hash)
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
            noid_chain::consensus::params::BLOCK_MAX_TXS - 1,
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
        use noid_chain::consensus::template::build_block_template;

        let parent = &snapshot.parent;
        let prev_active_counts = &snapshot.prev_active_counts;
        let prev_timestamps = &snapshot.prev_timestamps;

        // Compute the minimum valid timestamp for the new block:
        //   timestamp MUST be strictly greater than MTP (median of last 11 blocks).
        //   See validate_timestamp in noid_chain::consensus::timestamps.
        // This prevents BadTimestamp when blocks are found faster than 1 second
        // (genesis target is trivial; multiple blocks per second are possible).
        let mtp = median_time_past(&prev_timestamps);
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
        let consensus_max = noid_chain::consensus::params::BLOCK_MAX_TXS - 1;
        let max_user_txs = max_user_txs.min(consensus_max);
        let entries = self.mempool.select_for_block(consensus_max).await;
        // Single-pass: move proof bytes and transactions together (no clone).
        let (proof_bytes, txs): (Vec<Option<Vec<u8>>>, Vec<_>) = entries
            .into_iter()
            .map(|e| (e.cached_algebraic_proof, e.tx))
            .unzip();

        // Filter out transactions whose epoch_anchor has expired since mempool
        // admission. Without this, the miner wastes proving time on txs that
        // will be rejected by peers during full block validation.
        let (proof_bytes, txs): (Vec<_>, Vec<_>) = proof_bytes
            .into_iter()
            .zip(txs)
            .filter(|(_, tx)| {
                is_current_block_provable_shape(tx.body.shape)
                    && (tx.body.is_coinbase || snapshot.is_anchor_fresh(&tx.body.epoch_anchor))
            })
            .take(max_user_txs)
            .unzip();
        let mut proof_by_hash: HashMap<noid_poseidon2b::primitives::TxBodyHash, Option<Vec<u8>>> =
            proof_bytes
                .into_iter()
                .zip(txs.iter().map(|tx| tx.tx_body_hash))
                .map(|(proof, hash)| (hash, proof))
                .collect();

        let state = &snapshot.state;
        match build_block_template(
            parent,
            state,
            prev_active_counts,
            txs,
            miner_address,
            timestamp,
            difficulty_target,
        ) {
            Ok(inner) => {
                // Capture pre-state columns for FRI openings.
                let eff_log = snapshot.state.state.effective_log_segment_size();
                let mut touched_segs = std::collections::HashSet::new();
                for tx in inner.txs.iter().chain(std::iter::once(&inner.coinbase)) {
                    for inp in tx.body.inputs.iter().filter(|i| i.valid) {
                        touched_segs.insert((inp.slot_index >> eff_log) as u16);
                    }
                    for out in tx.body.outputs.iter().filter(|o| o.valid) {
                        touched_segs.insert((out.slot_index >> eff_log) as u16);
                    }
                }
                let mut pre_segs: HashMap<u16, SegmentColumns> =
                    HashMap::with_capacity(touched_segs.len());
                for seg_id in touched_segs {
                    // Fast path: read from RAM if segment is loaded (avoids MDBX I/O).
                    let cols = snapshot
                        .state
                        .state
                        .try_get_segment_columns(seg_id)
                        .cloned()
                        .unwrap_or_else(|| SegmentColumns::new_zero(1usize << eff_log));
                    pre_segs.insert(seg_id, cols);
                }
                let proof_bytes = inner
                    .txs
                    .iter()
                    .map(|tx| proof_by_hash.remove(&tx.tx_body_hash).unwrap_or(None))
                    .collect();
                Some(BlockTemplate {
                    inner,
                    difficulty_target,
                    miner_address,
                    timestamp,
                    parent: parent.clone(),
                    proof_bytes,
                    pre_segs,
                })
            }
            Err(e) => {
                tracing::warn!("template build failed: {:?}", e);
                None
            }
        }
    }
}
