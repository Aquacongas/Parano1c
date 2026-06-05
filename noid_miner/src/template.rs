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
//! 1. Every 15 seconds (wall clock)
//! 2. ≥100 new txs admitted to mempool
//! 3. New block received from P2P — prev_hash changes

use noid_chain::block::Block;
use noid_chain::block_header::BlockHeader;
use noid_chain::consensus::difficulty::next_target;
use noid_chain::consensus::template::BlockTemplate as ChainTemplate;
use noid_chain::storage::MdbxChainContext;
use noid_mempool::AsyncMempool;
use noid_poseidon2b::primitives::Address;

/// Why the template was refreshed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TemplateRefreshTrigger {
    /// Regular 15-second heartbeat.
    Heartbeat,
    /// ≥100 new txs admitted since last refresh.
    MempoolGrowth,
    /// New block received from P2P — prev_hash changed.
    NewBlock,
    /// Node startup — generate first template.
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
    /// `None` when a tx was admitted without a proof (e.g. external miner submission).
    /// Used by the ZK block prover; blocks without bundles fall back to marker hashes.
    pub proof_bytes: Vec<Option<Vec<u8>>>,
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
            Ok(inner) => Some(BlockTemplate {
                inner,
                difficulty_target,
                miner_address,
                timestamp,
                parent,
                proof_bytes,
            }),
            Err(e) => {
                tracing::warn!("template build failed: {:?}", e);
                None
            }
        }
    }
}
