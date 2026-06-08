// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

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
//! 2. First `TxAdmitted` while prove is done (Sealed state — semaphore free, PoW still running)
//! 3. New chain tip from P2P (block received or snapshot applied via `sync_ready`)

use std::collections::HashMap;

use noid_chain::block::Block;
use noid_chain::block_header::BlockHeader;
use noid_chain::consensus::difficulty::next_target;
use noid_chain::consensus::template::BlockTemplate as ChainTemplate;
use noid_chain::segmented_state::SegmentColumns;
use noid_chain::storage::MdbxChainContext;
use noid_mempool::AsyncMempool;
use noid_poseidon2b::primitives::Address;

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

/// A `BlockTemplate` ready for parallel PoW + ZK prove.
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
    /// Used by the ZK block prover for FRI state openings (Step 2).
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

    /// Assemble the final sealed block after PoW and ZK proof complete.
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

/// Builds `BlockTemplate` from the current chain state and mempool.
pub struct TemplateBuilder {
    pub mempool: AsyncMempool,
}

impl TemplateBuilder {
    pub fn new(mempool: AsyncMempool) -> Self {
        Self { mempool }
    }

    /// Build a new template using the current chain state and top-fee mempool txs.
    ///
    /// Computes the ASERT difficulty target correctly using `next_target()`.
    pub async fn build(
        &self,
        ctx: &MdbxChainContext,
        miner_address: Address,
        now_unix: u64,
    ) -> Option<BlockTemplate> {
        use noid_chain::consensus::median_time_past;
        use noid_chain::consensus::template::build_block_template;

        let parent = ctx.tip_header().clone();
        let prev_active_counts = ctx.prev_active_counts();
        let prev_timestamps = ctx.prev_timestamps();

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
        let anchor = ctx.anchor_info();
        let difficulty_target = next_target(
            anchor.anchor_height,
            anchor.anchor_timestamp,
            &anchor.anchor_target,
            parent.height + 1,
            timestamp,
        );

        // Select top txs from mempool (leave one slot for coinbase).
        let entries = self
            .mempool
            .select_for_block(noid_chain::consensus::params::BLOCK_MAX_TXS - 1)
            .await;
        // Single-pass: move proof bytes and transactions together (no clone).
        let (proof_bytes, txs): (Vec<Option<Vec<u8>>>, Vec<_>) = entries
            .into_iter()
            .map(|e| (e.cached_algebraic_proof, e.tx))
            .unzip();

        let state = &ctx.state;
        match build_block_template(
            &parent,
            state,
            &prev_active_counts,
            txs,
            miner_address,
            timestamp,
            difficulty_target,
        ) {
            Ok(inner) => {
                // Capture pre-state columns for Step 2 FRI openings.
                let eff_log = ctx.state.state.effective_log_segment_size();
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
                    let cols = match ctx.store.get_segment(seg_id) {
                        Ok(Some((_eff, c))) => c,
                        _ => SegmentColumns::new_zero(1usize << eff_log),
                    };
                    pre_segs.insert(seg_id, cols);
                }
                Some(BlockTemplate {
                    inner,
                    difficulty_target,
                    miner_address,
                    timestamp,
                    parent,
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
