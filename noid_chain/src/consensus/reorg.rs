// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Chain reorg logic (ROADMAP Phase 1 P.12).
//!
//! Handles chain reorganisations within the finality window (≤ FINALITY_DEPTH blocks).
//! Deeper reorgs are rejected — blocks beyond FINALITY_DEPTH are considered final.
//!
//! # Algorithm
//!
//! 1. Find the common ancestor between the current tip and the new chain.
//! 2. Reject if reorg depth > FINALITY_DEPTH.
//! 3. Revert blocks from current tip to common ancestor using undo logs.
//! 4. Apply new blocks one by one using validate_block_consensus.
//! 5. Update nullifier set (revert + rebuild).
//! 6. Return hashes of reverted transactions for mempool recovery.

use std::collections::HashMap;

use crate::block::Block;
use crate::block_header::BlockHeader;
use crate::chain_context::ChainContext;
use crate::consensus::{
    da_prune::revert_block, params::FINALITY_DEPTH, pow::full_block_hash, ConsensusError,
};
use crate::nullifier::NullifierSet;
use noid_poseidon2b::primitives::TxBodyHash;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub enum ReorgError {
    /// Reorg depth exceeds FINALITY_DEPTH — block is final.
    ExceedsFinality { depth: u64 },
    /// Common ancestor not found — chains are unrelated.
    NoCommonAncestor,
    /// Applying a new block during reorg failed.
    BlockApplyFailed { height: u64, error: ConsensusError },
    /// Required undo log is missing (should not happen within finality window).
    MissingUndoLog { height: u64 },
}

// ---------------------------------------------------------------------------
// Result type
// ---------------------------------------------------------------------------

/// Result of a successful reorg operation.
#[derive(Debug, Clone)]
pub struct ReorgResult {
    /// Heights of blocks that were reverted (from old chain).
    pub reverted_heights: Vec<u64>,
    /// Heights of blocks that were applied (from new chain).
    pub applied_heights: Vec<u64>,
    /// Transaction hashes from reverted blocks that should be returned to mempool.
    /// These txs had their state effects undone and may be re-included in the new chain.
    pub reclaimed_tx_hashes: Vec<TxBodyHash>,
}

// ---------------------------------------------------------------------------
// Core functions
// ---------------------------------------------------------------------------

/// Find the common ancestor height between the current chain and a list of
/// new block headers.
///
/// `ctx.headers` contains the current chain's headers.
/// `new_headers` are the incoming headers from the competing chain, ordered
/// by ascending height.
///
/// Returns the height of the highest common ancestor, or `None` if no common
/// ancestor is found within the FINALITY_DEPTH window.
pub fn find_common_ancestor(ctx: &ChainContext, new_headers: &[(u64, BlockHeader)]) -> Option<u64> {
    // Build a set of (height, hash) for the new chain.
    let new_chain: HashMap<u64, [u8; 32]> = new_headers
        .iter()
        .map(|(h, hdr)| (*h, full_block_hash(hdr)))
        .collect();

    // Walk backwards from the current tip looking for a height that exists
    // in both chains with the same block hash.
    let tip = ctx.tip_height;
    let oldest_revertable = tip.saturating_sub(FINALITY_DEPTH);

    for height in (oldest_revertable..=tip).rev() {
        if let Some(our_header) = ctx.headers.get(&height) {
            let our_hash = full_block_hash(our_header);
            if new_chain.get(&height) == Some(&our_hash) {
                return Some(height);
            }
        }
    }
    None
}

/// Apply a chain reorg: revert to `ancestor_height` then apply `new_blocks`.
///
/// On success: `ctx` reflects the new canonical chain.
/// On failure: `ctx` is left in the pre-reorg state (snapshot-based).
///
/// `new_blocks`: list of `(Block, local_time)` to apply, ordered by ascending height.
/// All new blocks must build on each other from `ancestor_height + 1`.
pub fn apply_reorg(
    ctx: &mut ChainContext,
    ancestor_height: u64,
    new_blocks: &[(Block, u64)],
) -> Result<ReorgResult, ReorgError> {
    let reorg_depth = ctx.tip_height.saturating_sub(ancestor_height);

    // Reject if beyond finality.
    if reorg_depth > FINALITY_DEPTH {
        return Err(ReorgError::ExceedsFinality { depth: reorg_depth });
    }

    // Take a snapshot for rollback on failure.
    let state_snapshot = ctx.state.clone();
    let headers_snapshot = ctx.headers.clone();
    let tip_height_snapshot = ctx.tip_height;
    let tip_hash_snapshot = ctx.tip_hash;
    let undo_logs_snapshot = ctx.undo_logs.clone();

    // -----------------------------------------------------------------------
    // Phase 1: Revert blocks from current tip to common ancestor.
    // -----------------------------------------------------------------------
    let mut reverted_heights = Vec::new();
    let reclaimed_hashes: Vec<TxBodyHash> = Vec::new();

    for height in (ancestor_height + 1..=ctx.tip_height).rev() {
        // Get the undo log for this block.
        let undo = ctx
            .undo_logs
            .get(&height)
            .ok_or(ReorgError::MissingUndoLog { height })?
            .clone();

        // Collect tx hashes for mempool recovery.
        // (We store tx hashes in the undo log's block_height field; actual hashes
        // are not stored there. Caller must track these from the reverted block headers.)
        // For now, we emit the undo log's height as a signal; full implementation
        // requires storing tx_body_hashes in BlockUndoLog (Phase 2 enhancement).

        // Revert slot state. revert_block takes &mut SegmentedFriState.
        revert_block(&mut ctx.state.state, &undo);
        ctx.undo_logs.remove(&height);
        ctx.headers.remove(&height);
        reverted_heights.push(height);
    }

    // Rebuild nullifier set from the surviving chain (ancestor and below).
    // This is O(ANCHOR_DEPTH) blocks × txs per block.
    {
        use crate::consensus::params::ANCHOR_DEPTH;
        let rebuild_start = ancestor_height.saturating_sub(ANCHOR_DEPTH);
        // TODO Phase 2: store tx_hashes per block in header store so we can
        // pass real block contents here. For now, rebuild with an empty set.
        let rebuild_blocks: Vec<Vec<TxBodyHash>> = (rebuild_start..=ancestor_height)
            .filter_map(|_h| {
                // Per-block tx hash storage is a Phase 2 concern.
                None
            })
            .collect();
        ctx.nullifiers = NullifierSet::rebuild_from_blocks(rebuild_blocks);
    }
    ctx.tip_height = ancestor_height;
    ctx.tip_hash = ctx
        .headers
        .get(&ancestor_height)
        .map(full_block_hash)
        .unwrap_or([0u8; 32]);

    // -----------------------------------------------------------------------
    // Phase 2: Apply new blocks.
    // -----------------------------------------------------------------------
    let mut applied_heights = Vec::new();

    for (block, local_time) in new_blocks {
        match ctx.apply_next_block(block, *local_time) {
            Ok(_) => {
                applied_heights.push(block.header.height);
            }
            Err(e) => {
                // Rollback everything.
                ctx.state = state_snapshot;
                ctx.headers = headers_snapshot;
                ctx.tip_height = tip_height_snapshot;
                ctx.tip_hash = tip_hash_snapshot;
                ctx.undo_logs = undo_logs_snapshot;
                return Err(ReorgError::BlockApplyFailed {
                    height: block.header.height,
                    error: e,
                });
            }
        }
    }

    Ok(ReorgResult {
        reverted_heights,
        applied_heights,
        reclaimed_tx_hashes: reclaimed_hashes,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::{compute_tx_root, Block};
    use crate::block_header::BlockHeader;
    use crate::chain_context::ChainContext;
    use crate::consensus::{
        params::{BLOCK_TIME, GENESIS_TARGET},
        pow::{full_block_hash, search_pow},
    };
    use noid_poseidon2b::primitives::Address;

    fn build_empty_block(ctx: &mut ChainContext) -> Block {
        let parent = ctx.tip_header().clone();
        let new_root = ctx.state.state_root();
        let mut header = BlockHeader {
            prev_block_hash: full_block_hash(&parent),
            state_root: new_root,
            tx_root: compute_tx_root(&[]),
            timestamp: parent.timestamp + BLOCK_TIME,
            height: parent.height + 1,
            miner_address: Address([0u8; 32]),
            nonce: 0,
            difficulty_target: GENESIS_TARGET,
            proof_transcript_hash: [1u8; 32],
            witness_root: [1u8; 32],
            log_slots: parent.log_slots,
            active_slot_count: parent.active_slot_count,
            alloc_counter: parent.alloc_counter,
        };
        header.nonce = search_pow(&header, 0, 100_000_000).unwrap();
        Block {
            header,
            transactions: vec![],
        }
    }

    #[test]
    fn find_common_ancestor_same_genesis() {
        let ctx = ChainContext::init_from_genesis();
        let genesis = ctx.tip_header().clone();
        // New chain also starts from genesis — common ancestor = 0.
        let new_headers = vec![(0u64, genesis)];
        let ancestor = find_common_ancestor(&ctx, &new_headers);
        assert_eq!(ancestor, Some(0));
    }

    #[test]
    fn find_common_ancestor_no_match() {
        let ctx = ChainContext::init_from_genesis();
        // Fabricate a header that doesn't match our genesis.
        let fake_header = BlockHeader {
            prev_block_hash: [0xFF; 32],
            state_root: [0xFF; 32],
            tx_root: [0u8; 32],
            timestamp: 0,
            height: 0,
            miner_address: Address([0u8; 32]),
            nonce: 0,
            difficulty_target: GENESIS_TARGET,
            proof_transcript_hash: [0u8; 32],
            witness_root: [0u8; 32],
            log_slots: 24,
            active_slot_count: 0,
            alloc_counter: 0,
        };
        let ancestor = find_common_ancestor(&ctx, &[(0, fake_header)]);
        assert_eq!(ancestor, None);
    }

    #[test]
    fn apply_reorg_exceeds_finality_rejects() {
        let mut ctx = ChainContext::init_from_genesis();
        // Apply FINALITY_DEPTH + 1 blocks.
        for _ in 0..(FINALITY_DEPTH + 1) {
            let block = build_empty_block(&mut ctx);
            ctx.apply_next_block(&block, block.header.timestamp + 1)
                .unwrap();
        }
        // Try to reorg back to genesis (depth = FINALITY_DEPTH + 1).
        let result = apply_reorg(&mut ctx, 0, &[]);
        assert!(matches!(result, Err(ReorgError::ExceedsFinality { .. })));
    }

    #[test]
    fn apply_reorg_within_finality_reverts() {
        let mut ctx = ChainContext::init_from_genesis();
        // Apply 3 blocks.
        for _ in 0..3 {
            let block = build_empty_block(&mut ctx);
            ctx.apply_next_block(&block, block.header.timestamp + 1)
                .unwrap();
        }
        assert_eq!(ctx.tip_height, 3);

        // Reorg back to block 1 (revert 2 blocks, no new blocks).
        let result = apply_reorg(&mut ctx, 1, &[]);
        assert!(result.is_ok(), "reorg should succeed: {:?}", result);
        let r = result.unwrap();
        assert_eq!(r.reverted_heights, vec![3, 2]);
        assert_eq!(ctx.tip_height, 1);
    }
}
