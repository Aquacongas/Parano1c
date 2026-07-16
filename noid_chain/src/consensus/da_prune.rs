// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! DA retention and undo-log management .
//!
//! Compact per-block undo logs record the pre-image of every UTXO slot
//! mutated by a block. This allows short-range reorgs (up to
//! `UNDO_RETENTION_DEPTH` blocks deep) to be resolved without any network
//! access — the node simply replays the undo entries in reverse to
//! restore the prior UTXO state.
//!
//! After `UNDO_RETENTION_DEPTH` confirmations, the undo log for a block is
//! pruned (`prune_undo_logs`). MDBX retains the matching recent accepted-block
//! bundle suffix and one additional HistoryStep boundary terminal.

use std::collections::{HashMap, HashSet};

use crate::block::Block;
use crate::consensus::params::UNDO_RETENTION_DEPTH;
use crate::fri_state::SlotValue;
use crate::segmented_state::SegmentedFriState;
use crate::state::ChainState;
use noid_poseidon2b::primitives::TxBodyHash;

/// Per-block undo log. Records the pre-image value of every UTXO slot
/// mutated by the block, enabling reversion without the full block data.
///
/// Maximum size is bounded by the consensus semantic action budget plus the
/// single coinbase output, not by the raw decoded transaction cap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockUndoLog {
    /// Height of the block this undo log was produced for.
    pub block_height: u64,
    /// Slot-domain depth before this block. Reorg rollback must undo any
    /// expansion performed by the block before restoring the parent root.
    pub log_slots_before: u32,
    /// Exact active-slot counter before this block was applied.
    pub active_slot_count_before: u64,
    /// Exact allocator counter before this block was applied.
    pub alloc_counter_before: u64,
    /// `(slot_index, value_before_block)` pairs for every slot mutated by
    /// this block, recorded once at the slot's first occurrence in application
    /// order. Replaying these restores the pre-block UTXO state.
    pub slot_changes: Vec<(u32, SlotValue)>,
    /// Canonical transaction-tree leaves for this block (coinbase first,
    /// followed by one logical txid per complete PagedSpend group).
    /// Used to restore the mempool after a reorg: txs that are no longer
    /// on the canonical chain can be re-admitted.
    pub tx_hashes: Vec<TxBodyHash>,
}

impl BlockUndoLog {
    /// Create an empty undo log for the given block height.
    pub fn empty(block_height: u64, log_slots_before: u32) -> Self {
        Self {
            block_height,
            log_slots_before,
            active_slot_count_before: 0,
            alloc_counter_before: 0,
            slot_changes: vec![],
            tx_hashes: vec![],
        }
    }
}

/// Produce an undo log by recording the pre-block value of every slot that
/// `block` touches. Only bitmap-live inputs and outputs are recorded.
///
/// `state_before` must be the chain state *before* the block is applied.
///
/// # Panics
///
/// Does not panic. Slots outside both the parent domain and a legal one-level
/// child domain are skipped; outputs in the newly-created upper half are
/// recorded with the canonical parent pre-image [`SlotValue::EMPTY`].
pub fn build_undo_log(
    state_before: &ChainState,
    block: &Block,
) -> Result<BlockUndoLog, crate::block::BlockPageStreamError> {
    let tx_hashes = crate::block::try_compute_logical_txids(&block.transactions)?;
    let mut slot_changes = Vec::new();
    let mut touched_slots = HashSet::new();

    for tx in &block.transactions {
        // Record pre-image of each spent input slot.
        for (_, inp) in tx.body.live_inputs() {
            if (inp.slot_index as u64) < state_before.state.num_slots()
                && touched_slots.insert(inp.slot_index)
            {
                let prev = state_before.state.slot(inp.slot_index);
                slot_changes.push((inp.slot_index, prev));
            }
        }
        // Record pre-image of each minted output slot (should be EMPTY before mint).
        for (_, out) in tx.body.live_outputs() {
            if touched_slots.insert(out.slot_index) {
                if (out.slot_index as u64) < state_before.state.num_slots() {
                    slot_changes.push((out.slot_index, state_before.state.slot(out.slot_index)));
                } else {
                    // An expansion block may mint into its newly-created upper
                    // half. Those slots are canonically EMPTY in the parent and
                    // still need an undo entry so shrink can prove the discarded
                    // half is empty after rollback.
                    let parent_log_slots = state_before.state.log_slots() as u32;
                    let parent_slots = state_before.state.num_slots();
                    let child_slots =
                        if block.header.log_slots == parent_log_slots.saturating_add(1) {
                            parent_slots.checked_mul(2).unwrap_or(parent_slots)
                        } else {
                            parent_slots
                        };
                    if (out.slot_index as u64) < child_slots {
                        slot_changes.push((out.slot_index, SlotValue::EMPTY));
                    }
                }
            }
        }
    }

    Ok(BlockUndoLog {
        block_height: block.header.height,
        log_slots_before: state_before.state.log_slots() as u32,
        active_slot_count_before: state_before.active_slot_count,
        alloc_counter_before: state_before.alloc_counter,
        slot_changes,
        tx_hashes,
    })
}

/// Revert the UTXO state to what it was before a block was applied by
/// replaying `undo.slot_changes`. Each physical slot occurs exactly once.
///
/// Only the `SegmentedFriState` is modified; the caller is responsible for
/// updating `ChainState::active_slot_count` and `alloc_counter` if needed.
///
/// After this call, `state.root()` should match the pre-block state root
/// assuming no other mutations occurred between `build_undo_log` and here.
pub fn revert_block(state: &mut SegmentedFriState, undo: &BlockUndoLog) {
    for (slot_index, prev_value) in undo.slot_changes.iter().rev() {
        if (*slot_index as u64) < state.num_slots() {
            // Ignore errors — out-of-range is already guarded above.
            let _ = state.set_slot(*slot_index, *prev_value);
        }
    }
}

/// Remove undo logs older than `UNDO_RETENTION_DEPTH` blocks from `logs`.
/// After this call only logs for heights in
/// `(current_height - UNDO_RETENTION_DEPTH, current_height]` are retained.
pub fn prune_undo_logs(logs: &mut HashMap<u64, BlockUndoLog>, current_height: u64) {
    let cutoff = current_height.saturating_sub(UNDO_RETENTION_DEPTH);
    logs.retain(|&h, _| h > cutoff);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block_header::BlockHeader;
    use crate::consensus::params::GENESIS_TARGET;
    use noid_poseidon2b::primitives::Address;
    use noid_tx::{
        output_bitmap_bit, Transaction, TxBody, TxInput, TxOutput, TX_INPUTS, TX_OUTPUTS,
    };

    fn mint_block(slot: u32) -> Block {
        let mut outputs = [TxOutput::dummy(); TX_OUTPUTS];
        outputs[0] = TxOutput {
            slot_index: slot,
            amount: 50,
            owner: Address([1u8; 32]),
        };
        let tx = Transaction::new(TxBody {
            epoch_anchor: [1u8; 32],
            fee: 0,
            input_owner: Address([0u8; 32]),
            inputs: [TxInput::dummy(); TX_INPUTS],
            outputs,
            validity_bitmap: output_bitmap_bit(0),
            is_coinbase: true,
        });
        Block {
            header: BlockHeader {
                prev_block_hash: [0u8; 32],
                state_root: [0u8; 32],
                tx_root: crate::block::compute_tx_root(std::slice::from_ref(&tx)),
                timestamp: 1,
                height: 1,
                miner_address: Address([1u8; 32]),
                nonce: 0,
                difficulty_target: GENESIS_TARGET,
                log_slots: 8,
                active_slot_count: 1,
                alloc_counter: 1,
            },
            transactions: vec![tx],
        }
    }

    #[test]
    fn undo_log_uses_derived_txid_and_records_first_preimage() {
        let state = ChainState::with_log_slots(8);
        let block = mint_block(7);
        let undo = build_undo_log(&state, &block).unwrap();
        assert_eq!(undo.tx_hashes, vec![block.transactions[0].txid()]);
        assert_eq!(undo.slot_changes, vec![(7, SlotValue::EMPTY)]);
        assert_eq!(undo.active_slot_count_before, 0);
        assert_eq!(undo.alloc_counter_before, 0);
    }

    #[test]
    fn pruning_keeps_only_retention_window() {
        let mut logs = HashMap::new();
        for height in 0..=UNDO_RETENTION_DEPTH + 2 {
            logs.insert(height, BlockUndoLog::empty(height, 8));
        }
        prune_undo_logs(&mut logs, UNDO_RETENTION_DEPTH + 2);
        assert!(!logs.contains_key(&0));
        assert!(logs.contains_key(&(UNDO_RETENTION_DEPTH + 2)));
    }
}
