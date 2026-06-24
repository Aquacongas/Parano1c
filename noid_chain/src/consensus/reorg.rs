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
    pow::full_block_hash,
    ConsensusError,
};
use crate::fri_state::SlotValue;
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
/// ancestor is found within the consensus finality window.
pub fn find_common_ancestor(ctx: &ChainContext, new_headers: &[(u64, BlockHeader)]) -> Option<u64> {
    let new_chain: HashMap<u64, [u8; 32]> = new_headers
        .iter()
        .map(|(h, hdr)| (*h, full_block_hash(hdr)))
        .collect();

    let tip = ctx.tip_height;
    let oldest_revertable = tip.saturating_sub(CONSENSUS_FINALITY_DEPTH);

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

pub fn revert_reuse_guard(state: &mut ChainState, undo: &BlockUndoLog) {
    state.reuse_guard =
        crate::reuse_guard::ReuseGuard::from_buckets(undo.reuse_guard_before.clone())
            .expect("undo log must contain canonical ReuseGuard buckets");
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
        ctx.state
            .rebuild_exact_utxo_root_loaded()
            .expect("in-memory reorg state must be fully loaded");
        revert_reuse_guard(&mut ctx.state, &undo);

        // Revert active_slot_count and alloc_counter.
        // Without this, the counters stay at the post-reorg tip values and the
        // next validate_block_consensus call would fail HeaderActiveSlotCountMismatch.
        revert_state_counters(&mut ctx.state, &undo);

        ctx.undo_logs.remove(&height);
        ctx.headers.remove(&height);
        reverted_heights.push(height);
    }

    ctx.tip_height = ancestor_height;
    ctx.tip_hash = ctx
        .headers
        .get(&ancestor_height)
        .map(full_block_hash)
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
    use crate::block::{compute_tx_root, Block, STUB_PROOF_MARKER};
    use crate::block_header::BlockHeader;
    use crate::chain_context::ChainContext;
    use crate::consensus::{
        fees::required_fee_for_tx_body,
        params::{BLOCK_TIME, GENESIS_TARGET},
        pow::full_block_hash,
    };
    use crate::fri_state::SlotValue;
    use crate::state::{apply_tx, ChainState};
    use noid_core::Block128;
    use noid_poseidon2b::primitives::{Address, SpendSecret};
    use noid_tx::{hash_tx_body_for_shape, Transaction, TxBody, TxInput, TxOutput, TxShape};
    const TEST_TARGET: [u8; 32] = [0xFF; 32];
    const TEST_LOG_SLOTS: usize = 8;

    fn build_empty_block(ctx: &mut ChainContext) -> Block {
        let parent = *ctx.tip_header();
        let new_root = ctx.state.state_root();
        let mut header = BlockHeader {
            prev_block_hash: full_block_hash(&parent),
            state_root: new_root,
            tx_root: compute_tx_root(&[]),
            timestamp: parent.timestamp + BLOCK_TIME,
            height: parent.height + 1,
            miner_address: Address([0u8; 32]),
            nonce: 0,
            difficulty_target: TEST_TARGET,
            proof_transcript_hash: [1u8; 32],
            witness_root: [1u8; 32],
            log_slots: parent.log_slots,
            active_slot_count: parent.active_slot_count,
            alloc_counter: parent.alloc_counter,
        };
        header.nonce = 0; // TEST_TARGET: any nonce works
        Block {
            header,
            transactions: vec![],
        }
    }

    fn init_small_easy_context() -> ChainContext {
        let mut ctx = ChainContext::init_from_easy_genesis();
        ctx.state = ChainState::with_log_slots(TEST_LOG_SLOTS);
        let root = ctx.state.state_root();
        let genesis = ctx.headers.get_mut(&0).expect("genesis header");
        genesis.state_root = root;
        genesis.log_slots = TEST_LOG_SLOTS as u32;
        genesis.active_slot_count = 0;
        genesis.alloc_counter = 0;
        genesis.difficulty_target = TEST_TARGET;
        genesis.nonce = 0;
        ctx.tip_hash = full_block_hash(genesis);
        ctx
    }

    fn output(slot: u32, value: u64, seed: u8) -> TxOutput {
        TxOutput {
            slot_index: slot,
            value,
            owner: Address([seed; 32]),
            valid: true,
        }
    }

    fn input_from_output(out: &TxOutput) -> TxInput {
        TxInput {
            slot_index: out.slot_index,
            value: out.value,
            owner: out.owner,
            spend_secret: SpendSecret([0x55; 32]),
            valid: true,
        }
    }

    fn tx_from_body(body: TxBody) -> Transaction {
        let tx_body_hash = hash_tx_body_for_shape(
            body.shape,
            &body.epoch_anchor,
            body.fee,
            &body.inputs,
            &body.outputs,
            body.is_coinbase,
        );
        Transaction { body, tx_body_hash }
    }

    fn build_block(ctx: &ChainContext, txs: Vec<Transaction>) -> Block {
        let parent = *ctx.tip_header();
        let mut dry = ctx.state.clone();
        for tx in &txs {
            apply_tx(&mut dry, &tx.body).expect("test tx applies to dry state");
        }
        let has_user_txs = txs.iter().any(|tx| !tx.body.is_coinbase);
        let header = BlockHeader {
            prev_block_hash: full_block_hash(&parent),
            state_root: dry.state_root(),
            tx_root: compute_tx_root(&txs),
            timestamp: parent.timestamp + BLOCK_TIME,
            height: parent.height + 1,
            miner_address: Address([0u8; 32]),
            nonce: 0,
            difficulty_target: TEST_TARGET,
            proof_transcript_hash: if has_user_txs {
                [0xAA; 32]
            } else {
                STUB_PROOF_MARKER
            },
            witness_root: [0xBB; 32],
            log_slots: dry.state.log_slots() as u32,
            active_slot_count: dry.active_slot_count,
            alloc_counter: dry.alloc_counter,
        };
        Block {
            header,
            transactions: txs,
        }
    }

    fn coinbase_tx(parent_hash: [u8; 32], slot: u32, value: u64, seed: u8) -> Transaction {
        tx_from_body(TxBody {
            shape: TxShape::Standard4x8,
            epoch_anchor: parent_hash,
            fee: 0,
            inputs: vec![],
            outputs: vec![output(slot, value, seed)],
            is_coinbase: true,
        })
    }

    fn apply_funding_outputs(ctx: &mut ChainContext, n: usize) -> Vec<TxOutput> {
        let mut outs = Vec::with_capacity(n);
        for i in 0..n {
            let slot = 1 + i as u32;
            let out = output(slot, 10_000_000, 0x10u8.wrapping_add(i as u8));
            let parent_hash = full_block_hash(ctx.tip_header());
            let block = build_block(
                ctx,
                vec![coinbase_tx(
                    parent_hash,
                    slot,
                    out.value,
                    0x10u8.wrapping_add(i as u8),
                )],
            );
            ctx.apply_next_block(&block, block.header.timestamp + 1)
                .expect("funding block applies");
            outs.push(out);
        }
        outs
    }

    fn user_tx(
        ctx: &ChainContext,
        shape: TxShape,
        inputs: &[TxOutput],
        outputs: Vec<TxOutput>,
    ) -> Transaction {
        let mut body = TxBody {
            shape,
            epoch_anchor: [0x42; 32],
            fee: 0,
            inputs: inputs.iter().map(input_from_output).collect(),
            outputs,
            is_coinbase: false,
        };
        body.fee = required_fee_for_tx_body(
            &body,
            ctx.tip_header().active_slot_count,
            ctx.tip_header().log_slots,
        ) as u128;
        tx_from_body(body)
    }

    fn slot_value(state: &ChainState, slot: u32) -> SlotValue {
        state.state.slot(slot)
    }

    fn assert_live_slot(state: &ChainState, out: &TxOutput) {
        assert_eq!(
            slot_value(state, out.slot_index),
            SlotValue {
                value: Block128::from(out.value as u128),
                owner_hi: out.owner.as_fields()[0],
                owner_lo: out.owner.as_fields()[1],
            }
        );
    }

    fn assert_empty_slot(state: &ChainState, slot: u32) {
        assert_eq!(slot_value(state, slot), SlotValue::EMPTY);
    }

    #[test]
    fn find_common_ancestor_same_genesis() {
        let ctx = ChainContext::init_from_genesis();
        let genesis = *ctx.tip_header();
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
        let mut ctx = ChainContext::init_from_easy_genesis();
        for _ in 0..(CONSENSUS_FINALITY_DEPTH + 1) {
            let block = build_empty_block(&mut ctx);
            ctx.apply_next_block(&block, block.header.timestamp + 1)
                .unwrap();
        }
        let result = apply_reorg(&mut ctx, 0, &[]);
        assert!(matches!(result, Err(ReorgError::ExceedsFinality { .. })));
    }

    #[test]
    fn apply_reorg_within_finality_reverts() {
        let mut ctx = ChainContext::init_from_easy_genesis();
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
            reuse_guard_before: std::array::from_fn(|_| crate::reuse_guard::GuardBucket::Empty),
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
            reuse_guard_before: std::array::from_fn(|_| crate::reuse_guard::GuardBucket::Empty),
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
        let mut ctx = ChainContext::init_from_easy_genesis();
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

    fn apply_user_block_and_reorg(ctx: &mut ChainContext, txs: Vec<Transaction>) -> ReorgResult {
        let ancestor_height = ctx.tip_height;
        let ancestor_root = ctx.state.state_root();
        let block = build_block(ctx, txs.clone());
        let tx_hashes: Vec<_> = txs.iter().map(|tx| tx.tx_body_hash).collect();
        ctx.apply_next_block(&block, block.header.timestamp + 1)
            .expect("user block applies before reorg");
        let result = apply_reorg(ctx, ancestor_height, &[]).expect("shape block reorg succeeds");
        assert_eq!(ctx.tip_height, ancestor_height);
        assert_eq!(ctx.state.state_root(), ancestor_root);
        for h in &tx_hashes {
            assert!(
                result.reclaimed_tx_hashes.contains(h),
                "reorg reports reclaimed tx hash"
            );
        }
        result
    }

    #[test]
    fn reorg_after_standard_only_restores_inputs_and_removes_outputs() {
        let mut ctx = init_small_easy_context();
        let funding = apply_funding_outputs(&mut ctx, 4);
        let out = output(90, 30_000_000, 0x91);
        let tx = user_tx(&ctx, TxShape::Standard4x8, &funding[..4], vec![out]);

        apply_user_block_and_reorg(&mut ctx, vec![tx]);
        for restored in &funding[..4] {
            assert_live_slot(&ctx.state, restored);
        }
        assert_empty_slot(&ctx.state, out.slot_index);
    }

    #[test]
    fn reorg_after_single_sweep_restores_inputs_and_removes_outputs() {
        let mut ctx = init_small_easy_context();
        let funding = apply_funding_outputs(&mut ctx, 5);
        let out_a = output(100, 24_000_000, 0xA1);
        let out_b = output(101, 25_000_000, 0xA2);
        let tx = user_tx(&ctx, TxShape::Sweep25x2, &funding[..5], vec![out_a, out_b]);

        let block = build_block(&ctx, vec![tx.clone()]);
        ctx.apply_next_block(&block, block.header.timestamp + 1)
            .expect("sweep applies");
        for spent in &funding[..5] {
            assert_empty_slot(&ctx.state, spent.slot_index);
        }
        assert_live_slot(&ctx.state, &out_a);
        assert_live_slot(&ctx.state, &out_b);

        apply_reorg(&mut ctx, block.header.height - 1, &[]).expect("sweep reorg succeeds");
        for restored in &funding[..5] {
            assert_live_slot(&ctx.state, restored);
        }
        assert_empty_slot(&ctx.state, out_a.slot_index);
        assert_empty_slot(&ctx.state, out_b.slot_index);
    }

    #[test]
    fn reorg_after_mixed_standard_and_sweep_block_restores_all_slots() {
        let mut ctx = init_small_easy_context();
        let funding = apply_funding_outputs(&mut ctx, 9);
        let std_out = output(110, 18_000_000, 0xB1);
        let sweep_out = output(111, 42_000_000, 0xB2);
        let std_tx = user_tx(&ctx, TxShape::Standard4x8, &funding[..4], vec![std_out]);
        let sweep_tx = user_tx(&ctx, TxShape::Sweep25x2, &funding[4..9], vec![sweep_out]);

        apply_user_block_and_reorg(&mut ctx, vec![std_tx, sweep_tx]);
        for restored in &funding[..9] {
            assert_live_slot(&ctx.state, restored);
        }
        assert_empty_slot(&ctx.state, std_out.slot_index);
        assert_empty_slot(&ctx.state, sweep_out.slot_index);
    }

    #[test]
    fn reorg_after_split_chunks_restores_sweep_and_standard_chunks() {
        let mut ctx = init_small_easy_context();
        let funding = apply_funding_outputs(&mut ctx, 26);
        let sweep_chunk_out = output(130, 200_000_000, 0xC1);
        let standard_tail_out = output(131, 8_000_000, 0xC2);
        let sweep_chunk = user_tx(
            &ctx,
            TxShape::Sweep25x2,
            &funding[..25],
            vec![sweep_chunk_out],
        );
        let standard_tail = user_tx(
            &ctx,
            TxShape::Standard4x8,
            &funding[25..26],
            vec![standard_tail_out],
        );

        apply_user_block_and_reorg(&mut ctx, vec![sweep_chunk, standard_tail]);
        for restored in &funding[..26] {
            assert_live_slot(&ctx.state, restored);
        }
        assert_empty_slot(&ctx.state, sweep_chunk_out.slot_index);
        assert_empty_slot(&ctx.state, standard_tail_out.slot_index);
    }

    #[test]
    fn reorg_after_sweep_consolidation_restores_fragmented_inputs() {
        let mut ctx = init_small_easy_context();
        let funding = apply_funding_outputs(&mut ctx, 18);
        let consolidated = output(150, 179_000_000, 0xD1);
        let consolidation = user_tx(&ctx, TxShape::Sweep25x2, &funding[..18], vec![consolidated]);

        apply_user_block_and_reorg(&mut ctx, vec![consolidation]);
        for restored in &funding[..18] {
            assert_live_slot(&ctx.state, restored);
        }
        assert_empty_slot(&ctx.state, consolidated.slot_index);
    }
}
