// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Chain reorg logic .
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
//! 5. Rebuild nullifier set from the surviving chain's undo logs.
//! 6. Return hashes of reverted transactions for mempool re-admission.

use std::collections::HashMap;

use crate::block::Block;
use crate::block_header::BlockHeader;
use crate::chain_context::ChainContext;
use crate::consensus::{
    da_prune::{revert_block, BlockUndoLog},
    params::FINALITY_DEPTH,
    pow::full_block_hash,
    ConsensusError,
};
use crate::fri_state::SlotValue;
use crate::nullifier::NullifierSet;
use crate::state::ChainState;
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
    /// Transaction hashes from reverted blocks whose state effects were undone.
    /// The caller should re-admit these if their epoch_anchor
    /// is still within the valid window and the tx was not included in the new chain.
    pub reclaimed_tx_hashes: Vec<TxBodyHash>,
}

// ---------------------------------------------------------------------------
// Core functions
// ---------------------------------------------------------------------------

/// Find the common ancestor height between the current chain and a list of
/// new block headers.
///
/// Returns the height of the highest common ancestor, or `None` if no common
/// ancestor is found within the FINALITY_DEPTH window.
pub fn find_common_ancestor(ctx: &ChainContext, new_headers: &[(u64, BlockHeader)]) -> Option<u64> {
    let new_chain: HashMap<u64, [u8; 32]> = new_headers
        .iter()
        .map(|(h, hdr)| (*h, full_block_hash(hdr)))
        .collect();

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

/// Revert `active_slot_count` and `alloc_counter` to their pre-block values.
///
/// Each `slot_change` entry in the undo log records the slot's **pre-block** value:
/// - `prev == EMPTY` → the slot was **minted** in this block (was empty before).
///   Reverting: decrement active_slot_count by 1, decrement alloc_counter by 1.
/// - `prev != EMPTY` → the slot was **spent** in this block (was live before).
///   Reverting: increment active_slot_count by 1.
///
/// Slots that appear twice (minted then spent in the same block) produce a net
/// delta of zero on active_slot_count and -1 on alloc_counter, which is correct.
pub fn revert_state_counters(state: &mut ChainState, undo: &BlockUndoLog) {
    for (_, prev_value) in &undo.slot_changes {
        if *prev_value == SlotValue::EMPTY {
            // Reverting a mint: the slot was empty before the block, live after.
            state.active_slot_count = state.active_slot_count.saturating_sub(1);
            state.alloc_counter = state.alloc_counter.saturating_sub(1);
        } else {
            // Reverting a spend: the slot was live before the block, empty after.
            state.active_slot_count += 1;
        }
    }
}

/// Apply a chain reorg: revert to `ancestor_height` then apply `new_blocks`.
///
/// On success: `ctx` reflects the new canonical chain.
/// On failure: `ctx` is left in the pre-reorg state (snapshot-based).
///
/// `new_blocks`: `(Block, local_time)` pairs, ordered by ascending height,
/// building on each other from `ancestor_height + 1`.
pub fn apply_reorg(
    ctx: &mut ChainContext,
    ancestor_height: u64,
    new_blocks: &[(Block, u64)],
) -> Result<ReorgResult, ReorgError> {
    let reorg_depth = ctx.tip_height.saturating_sub(ancestor_height);

    if reorg_depth > FINALITY_DEPTH {
        return Err(ReorgError::ExceedsFinality { depth: reorg_depth });
    }

    // Snapshot for rollback on Phase 2 failure.
    let state_snapshot = ctx.state.clone();
    let headers_snapshot = ctx.headers.clone();
    let tip_height_snapshot = ctx.tip_height;
    let tip_hash_snapshot = ctx.tip_hash;
    let undo_logs_snapshot = ctx.undo_logs.clone();

    // -----------------------------------------------------------------------
    // Phase 1: Revert blocks from current tip to common ancestor.
    // -----------------------------------------------------------------------
    let mut reverted_heights = Vec::new();
    let mut reclaimed_hashes: Vec<TxBodyHash> = Vec::new();

    for height in (ancestor_height + 1..=ctx.tip_height).rev() {
        let undo = ctx
            .undo_logs
            .get(&height)
            .ok_or(ReorgError::MissingUndoLog { height })?
            .clone();

        // Collect tx hashes for mempool re-admission.
        reclaimed_hashes.extend_from_slice(&undo.tx_hashes);

        // Revert UTXO slot data.
        revert_block(&mut ctx.state.state, &undo);

        // Revert active_slot_count and alloc_counter.
        // Without this, the counters stay at the post-reorg tip values and the
        // next validate_block_consensus call would fail HeaderActiveSlotCountMismatch.
        revert_state_counters(&mut ctx.state, &undo);

        ctx.undo_logs.remove(&height);
        ctx.headers.remove(&height);
        reverted_heights.push(height);
    }

    // Rebuild nullifier set from the surviving chain.
    //
    // tx_hashes are stored in undo logs (added in Phase 2).  Undo logs are kept
    // for FINALITY_DEPTH = 18 blocks; blocks older than that in the surviving
    // chain produce empty entries.  This is safe: those older blocks' txs are
    // protected by the UTXO state itself — their input slots are already EMPTY
    // ("unknown or spent") and output slots are LIVE ("output slot not empty"),
    // so native apply_tx would reject re-inclusion regardless of the nullifier set.
    {
        use crate::consensus::params::ANCHOR_DEPTH;
        let rebuild_start = ancestor_height.saturating_sub(ANCHOR_DEPTH);
        let rebuild_blocks: Vec<Vec<TxBodyHash>> = (rebuild_start..=ancestor_height)
            .map(|h| {
                ctx.undo_logs
                    .get(&h)
                    .map(|u| u.tx_hashes.clone())
                    .unwrap_or_default() // empty for blocks beyond FINALITY_DEPTH
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
                // Roll back to pre-reorg state.
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
        let new_headers = vec![(0u64, genesis)];
        let ancestor = find_common_ancestor(&ctx, &new_headers);
        assert_eq!(ancestor, Some(0));
    }

    #[test]
    fn find_common_ancestor_no_match() {
        let ctx = ChainContext::init_from_genesis();
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
        for _ in 0..(FINALITY_DEPTH + 1) {
            let block = build_empty_block(&mut ctx);
            ctx.apply_next_block(&block, block.header.timestamp + 1)
                .unwrap();
        }
        let result = apply_reorg(&mut ctx, 0, &[]);
        assert!(matches!(result, Err(ReorgError::ExceedsFinality { .. })));
    }

    #[test]
    fn apply_reorg_within_finality_reverts() {
        let mut ctx = ChainContext::init_from_genesis();
        for _ in 0..3 {
            let block = build_empty_block(&mut ctx);
            ctx.apply_next_block(&block, block.header.timestamp + 1)
                .unwrap();
        }
        assert_eq!(ctx.tip_height, 3);

        let result = apply_reorg(&mut ctx, 1, &[]);
        assert!(result.is_ok(), "reorg should succeed: {:?}", result);
        let r = result.unwrap();
        assert_eq!(r.reverted_heights, vec![3, 2]);
        assert_eq!(ctx.tip_height, 1);
    }

    #[test]
    fn revert_state_counters_mint_decrements() {
        use crate::fri_state::SlotValue;
        // One minted slot (prev == EMPTY): active -1, alloc -1
        let undo = BlockUndoLog {
            block_height: 5,
            slot_changes: vec![(10, SlotValue::EMPTY)],
            tx_hashes: vec![],
        };
        let mut state = crate::state::ChainState::with_log_slots(6);
        state.active_slot_count = 3;
        state.alloc_counter = 7;
        revert_state_counters(&mut state, &undo);
        assert_eq!(state.active_slot_count, 2);
        assert_eq!(state.alloc_counter, 6);
    }

    #[test]
    fn revert_state_counters_spend_increments() {
        use crate::fri_state::SlotValue;
        use noid_core::{Block128, TowerField};
        // One spent slot (prev != EMPTY): active +1, alloc unchanged
        let prev = SlotValue {
            value: Block128::from(100u128),
            owner_hi: Block128::ZERO,
            owner_lo: Block128::ZERO,
        };
        let undo = BlockUndoLog {
            block_height: 5,
            slot_changes: vec![(10, prev)],
            tx_hashes: vec![],
        };
        let mut state = crate::state::ChainState::with_log_slots(6);
        state.active_slot_count = 5;
        state.alloc_counter = 10;
        revert_state_counters(&mut state, &undo);
        assert_eq!(state.active_slot_count, 6);
        assert_eq!(state.alloc_counter, 10); // unchanged
    }

    #[test]
    fn reorg_preserves_state_root_after_revert() {
        let mut ctx = ChainContext::init_from_genesis();
        let root_at_genesis = ctx.state.state_root();

        // Apply 3 blocks.
        for _ in 0..3 {
            let block = build_empty_block(&mut ctx);
            ctx.apply_next_block(&block, block.header.timestamp + 1)
                .unwrap();
        }

        // Revert all 3 blocks back to genesis.
        apply_reorg(&mut ctx, 0, &[]).expect("reorg to genesis");

        // State root must match genesis state root.
        assert_eq!(
            ctx.state.state_root(),
            root_at_genesis,
            "state root must return to genesis after full reorg"
        );
        assert_eq!(ctx.state.active_slot_count, 0);
        assert_eq!(ctx.tip_height, 0);
    }
}
