// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Chain reorg logic .
//!
//! Handles chain reorganisations within the finality window.
//! Production hard-finality enforcement lives in the MDBX-backed context.
//!
//! # Algorithm
//!
//! 1. Find the common ancestor between the current tip and the new chain.
//! 2. Reject if reorg depth > CONSENSUS_FINALITY_DEPTH.
//! 3. Revert blocks from current tip to common ancestor using undo logs.
//! 4. Apply new blocks one by one using the in-memory sequential interpreter.
//! 5. Return hashes of reverted transactions for mempool re-admission.

use std::collections::HashMap;

use crate::block::Block;
use crate::block_header::BlockHeader;
use crate::chain_context::ChainContext;
use crate::consensus::{
    da_prune::{revert_block, BlockUndoLog},
    params::CONSENSUS_FINALITY_DEPTH,
    pow::block_id,
    ConsensusError,
};
use crate::state::ChainState;
use noid_poseidon2b::primitives::TxBodyHash;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub enum ReorgError {
    /// Reorg depth exceeds CONSENSUS_FINALITY_DEPTH — block is final.
    ExceedsFinality { depth: u64 },
    /// Common ancestor not found — chains are unrelated.
    NoCommonAncestor,
    /// Applying a new block during reorg failed.
    BlockApplyFailed { height: u64, error: ConsensusError },
    /// Required undo log is missing (should not happen within finality window).
    MissingUndoLog { height: u64 },
    /// Reverted slots did not leave an empty upper half, or the exact parent
    /// root could not be rebuilt.
    StateRollbackFailed { height: u64 },
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
    /// The caller should re-admit these only if their epoch anchor equals the
    /// new branch's current exact epoch id and they were not re-included.
    pub reclaimed_tx_hashes: Vec<TxBodyHash>,
}

// ---------------------------------------------------------------------------
// Core functions
// ---------------------------------------------------------------------------

/// Find the common ancestor height between the current chain and a list of
/// new block headers.
///
/// Returns the height of the highest common ancestor, or `None` if no common
/// ancestor is found within the consensus finality window.
pub fn find_common_ancestor(ctx: &ChainContext, new_headers: &[(u64, BlockHeader)]) -> Option<u64> {
    let new_chain: HashMap<u64, [u8; 32]> = new_headers
        .iter()
        .map(|(h, hdr)| (*h, block_id(hdr)))
        .collect();

    let tip = ctx.tip_height;
    let oldest_revertable = tip.saturating_sub(CONSENSUS_FINALITY_DEPTH);

    for height in (oldest_revertable..=tip).rev() {
        if let Some(our_header) = ctx.headers.get(&height) {
            let our_hash = block_id(our_header);
            if new_chain.get(&height) == Some(&our_hash) {
                return Some(height);
            }
        }
    }
    None
}

/// Restore `active_slot_count` and `alloc_counter` to their exact pre-block
/// values. Counter deltas cannot be inferred safely from final slot pre-images:
/// a slot may be minted and then spent within the same block.
pub fn revert_state_counters(state: &mut ChainState, undo: &BlockUndoLog) {
    state.active_slot_count = undo.active_slot_count_before;
    state.alloc_counter = undo.alloc_counter_before;
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
    if ancestor_height > ctx.tip_height {
        return Err(ReorgError::NoCommonAncestor);
    }
    let reorg_depth = ctx.tip_height.saturating_sub(ancestor_height);

    if reorg_depth > CONSENSUS_FINALITY_DEPTH {
        return Err(ReorgError::ExceedsFinality { depth: reorg_depth });
    }

    // Snapshot for rollback on failure.
    let state_snapshot = ctx.state.clone();
    let headers_snapshot = ctx.headers.clone();
    let tip_height_snapshot = ctx.tip_height;
    let tip_hash_snapshot = ctx.tip_hash;
    let undo_logs_snapshot = ctx.undo_logs.clone();

    // -----------------------------------------------------------------------
    // Revert blocks from current tip to common ancestor.
    // -----------------------------------------------------------------------
    let mut reverted_heights = Vec::new();
    let mut reclaimed_hashes: Vec<TxBodyHash> = Vec::new();

    let revert_result = (|| -> Result<(), ReorgError> {
        for height in (ancestor_height + 1..=ctx.tip_height).rev() {
            let undo = ctx
                .undo_logs
                .get(&height)
                .ok_or(ReorgError::MissingUndoLog { height })?
                .clone();

            reclaimed_hashes.extend_from_slice(&undo.tx_hashes);
            revert_block(&mut ctx.state.state, &undo);
            ctx.state
                .state
                .shrink_to_log_slots(undo.log_slots_before as usize)
                .map_err(|_| ReorgError::StateRollbackFailed { height })?;
            ctx.state
                .rebuild_exact_utxo_root_loaded()
                .map_err(|_| ReorgError::StateRollbackFailed { height })?;
            revert_state_counters(&mut ctx.state, &undo);
            let parent = ctx
                .headers
                .get(&(height - 1))
                .ok_or(ReorgError::StateRollbackFailed { height })?;
            if undo.log_slots_before != parent.log_slots
                || ctx.state.state.log_slots() as u32 != parent.log_slots
                || ctx.state.utxo_root != parent.state_root
                || ctx.state.active_slot_count != parent.active_slot_count
                || ctx.state.alloc_counter != parent.alloc_counter
            {
                return Err(ReorgError::StateRollbackFailed { height });
            }

            ctx.undo_logs.remove(&height);
            ctx.headers.remove(&height);
            reverted_heights.push(height);
        }
        Ok(())
    })();
    if let Err(error) = revert_result {
        ctx.state = state_snapshot;
        ctx.headers = headers_snapshot;
        ctx.tip_height = tip_height_snapshot;
        ctx.tip_hash = tip_hash_snapshot;
        ctx.undo_logs = undo_logs_snapshot;
        return Err(error);
    }

    ctx.tip_height = ancestor_height;
    ctx.tip_hash = ctx
        .headers
        .get(&ancestor_height)
        .map(block_id)
        .unwrap_or([0u8; 32]);

    // -----------------------------------------------------------------------
    // Apply new blocks.
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
    use crate::chain_context::ChainContext;

    #[test]
    fn common_ancestor_uses_canonical_header_ids() {
        let ctx = ChainContext::init_from_easy_genesis();
        let genesis = *ctx.header(0).unwrap();
        assert_eq!(find_common_ancestor(&ctx, &[(0, genesis)]), Some(0));

        let mut unrelated = genesis;
        unrelated.nonce ^= 1;
        assert_eq!(find_common_ancestor(&ctx, &[(0, unrelated)]), None);
    }

    #[test]
    fn counter_rollback_uses_exact_pre_block_values() {
        let mut state = ChainState::with_log_slots(8);
        state.active_slot_count = 99;
        state.alloc_counter = 101;
        let mut undo = BlockUndoLog::empty(1, 8);
        undo.active_slot_count_before = 7;
        undo.alloc_counter_before = 11;
        revert_state_counters(&mut state, &undo);
        assert_eq!(state.active_slot_count, 7);
        assert_eq!(state.alloc_counter, 11);
    }

    #[test]
    fn ancestor_above_tip_rejects_without_mutation() {
        let mut ctx = ChainContext::init_from_easy_genesis();
        let tip = ctx.tip_hash;
        assert!(matches!(
            apply_reorg(&mut ctx, 1, &[]),
            Err(ReorgError::NoCommonAncestor)
        ));
        assert_eq!(ctx.tip_hash, tip);
    }
}
