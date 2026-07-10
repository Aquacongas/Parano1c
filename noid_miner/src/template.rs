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

use std::collections::HashMap;

use noid_chain::block::Block;
use noid_chain::block_header::BlockHeader;
use noid_chain::consensus::difficulty::next_target;
use noid_chain::consensus::pow::block_id;
use noid_chain::consensus::template::BlockTemplate as ChainTemplate;
use noid_chain::consensus::AnchorInfo;
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

        let parent = *ctx.tip_header();
        let tip_height = parent.height;
        let lo = tip_height.saturating_sub(noid_chain::consensus::params::ANCHOR_DEPTH);
        let fresh_anchor_hashes = (lo..=tip_height)
            .filter_map(|h| ctx.header(h).map(block_id))
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
        let consensus_max = noid_chain::consensus::params::BLOCK_MAX_TXS - 1;
        let max_user_txs = max_user_txs.min(consensus_max);
        let entries = self.mempool.select_for_block(consensus_max).await;
        // Single-pass: move authorization bytes and transactions together (no clone).
        let (authorization_bytes, txs): (Vec<Option<Vec<u8>>>, Vec<_>) = entries
            .into_iter()
            .map(|e| (e.cached_authorization, e.tx))
            .unzip();

        // Filter out transactions whose epoch_anchor has expired since mempool
        // admission. Without this, the miner wastes proving time on txs that
        // will be rejected by peers during full block validation.
        let (authorization_bytes, txs): (Vec<_>, Vec<_>) = authorization_bytes
            .into_iter()
            .zip(txs)
            .filter(|(_, tx)| {
                is_current_block_provable_shape(tx.body.shape)
                    && (tx.body.is_coinbase || snapshot.is_anchor_fresh(&tx.body.epoch_anchor))
            })
            .take(max_user_txs)
            .unzip();
        let mut proof_by_hash: HashMap<noid_poseidon2b::primitives::TxBodyHash, Option<Vec<u8>>> =
            authorization_bytes
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
                let exact_state_transition = if inner.txs.is_empty() {
                    None
                } else {
                    // Expansion blocks are coinbase-only (template building
                    // clears user txs when log_slots grows), so a tx-bearing
                    // template always shares the snapshot state's log_slots
                    // and the action surface builds against the snapshot
                    // directly — no expanded whole-state copy.
                    if inner.log_slots as usize != snapshot.state.state.log_slots() {
                        tracing::warn!(
                            template_log_slots = inner.log_slots,
                            state_log_slots = snapshot.state.state.log_slots(),
                            "tx-bearing template log_slots diverges from snapshot state"
                        );
                        return None;
                    }
                    let bodies: Vec<_> = std::iter::once(inner.coinbase.body.clone())
                        .chain(inner.txs.iter().map(|tx| tx.body.clone()))
                        .collect();
                    let commitments: Vec<[u8; 32]> = bodies
                        .iter()
                        .map(|body| noid_tx::compute_claims_commitment(&body.inputs, &body.outputs))
                        .collect();
                    let surface = match noid_chain::build_exact_action_surface(
                        &snapshot.state.state,
                        &bodies,
                        &commitments,
                        snapshot.state.alloc_counter,
                    ) {
                        Ok(surface) => surface,
                        Err(e) => {
                            tracing::warn!(err = ?e, "exact state surface build failed");
                            return None;
                        }
                    };
                    let cache = match snapshot.state.state.exact_sparse_cache() {
                        Ok(cache) => cache,
                        Err(e) => {
                            tracing::warn!(err = %e, "exact parent sparse cache build failed");
                            return None;
                        }
                    };
                    match noid_block::build_exact_state_transition_proof(
                        &cache,
                        &surface,
                        &snapshot.state.reuse_guard,
                        inner.height,
                    ) {
                        Ok(proof) => Some(proof),
                        Err(e) => {
                            tracing::warn!(err = ?e, "exact state proof build failed");
                            return None;
                        }
                    }
                };

                let authorization_bytes = inner
                    .txs
                    .iter()
                    .map(|tx| proof_by_hash.remove(&tx.tx_body_hash).unwrap_or(None))
                    .collect();
                Some(BlockTemplate {
                    inner,
                    difficulty_target,
                    miner_address,
                    timestamp,
                    parent: *parent,
                    authorization_bytes,
                    exact_state_transition,
                })
            }
            Err(e) => {
                tracing::warn!("template build failed: {:?}", e);
                None
            }
        }
    }
}
