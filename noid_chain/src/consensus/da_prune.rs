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
//! pruned (`prune_undo_logs`). MDBX keeps raw block bytes for the shallow
//! reorg/peer-sync window. BlockProof bytes are kept until the block is both
//! finalized and covered by the stored recursive proof height, so the recursive
//! updater cannot race pruning. Older history is represented by headers, the
//! current state, and the recursive chain proof rather than by full block bodies.

use std::collections::HashMap;

use crate::block::Block;
use crate::consensus::params::UNDO_RETENTION_DEPTH;
use crate::fri_state::SlotValue;
use crate::segmented_state::SegmentedFriState;
use crate::state::ChainState;
use noid_poseidon2b::primitives::TxBodyHash;

/// Per-block undo log. Records the pre-image value of every UTXO slot
/// mutated by the block, enabling reversion without the full block data.
///
/// Maximum size: `BLOCK_MAX_TXS × (MAX_INPUTS + MAX_OUTPUTS) × sizeof(SlotValue)`
/// ≈ 147 KB at genesis parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockUndoLog {
    /// Height of the block this undo log was produced for.
    pub block_height: u64,
    /// `(slot_index, value_before_block)` pairs for every slot mutated by
    /// this block, recorded in application order. Replaying these in
    /// *reverse* order restores the pre-block UTXO state.
    pub slot_changes: Vec<(u32, SlotValue)>,
    /// tx_body_hashes of all transactions in this block (coinbase first).
    /// Used to restore the mempool after a reorg: txs that are no longer
    /// on the canonical chain can be re-admitted.
    pub tx_hashes: Vec<TxBodyHash>,
}

impl BlockUndoLog {
    /// Create an empty undo log for the given block height.
    pub fn empty(block_height: u64) -> Self {
        Self {
            block_height,
            slot_changes: vec![],
            tx_hashes: vec![],
        }
    }
}

/// Produce an undo log by recording the pre-block value of every slot that
/// `block` touches. Only valid inputs and outputs are recorded; dummy slots
/// (`valid = false`) are skipped.
///
/// `state_before` must be the chain state *before* the block is applied.
///
/// # Panics
///
/// Does not panic; slots outside the current state range are silently
/// skipped (the block pipeline will have already rejected them via
/// `apply_block`).
pub fn build_undo_log(state_before: &ChainState, block: &Block) -> BlockUndoLog {
    let tx_hashes: Vec<TxBodyHash> = block.transactions.iter().map(|t| t.tx_body_hash).collect();
    let mut slot_changes = Vec::new();

    for tx in &block.transactions {
        // Record pre-image of each spent input slot.
        for inp in &tx.body.inputs {
            if !inp.valid {
                continue;
            }
            if (inp.slot_index as u64) < state_before.state.num_slots() {
                let prev = state_before.state.slot(inp.slot_index);
                slot_changes.push((inp.slot_index, prev));
            }
        }
        // Record pre-image of each minted output slot (should be EMPTY before mint).
        for out in &tx.body.outputs {
            if !out.valid {
                continue;
            }
            if (out.slot_index as u64) < state_before.state.num_slots() {
                let prev = state_before.state.slot(out.slot_index);
                slot_changes.push((out.slot_index, prev));
            }
        }
    }

    BlockUndoLog {
        block_height: block.header.height,
        slot_changes,
        tx_hashes,
    }
}

/// Revert the UTXO state to what it was before a block was applied by
/// replaying `undo.slot_changes` in **reverse** order.
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
    use crate::block::{compute_tx_root, Block};
    use crate::block_header::BlockHeader;
    use crate::consensus::params::GENESIS_TARGET;
    use crate::state::{apply_tx, ChainState};
    use noid_poseidon2b::primitives::Address;
    use noid_tx::{hash_tx_body, TxBody, TxOutput};

    const TEST_LOG_SLOTS: usize = 6;

    fn fresh() -> ChainState {
        ChainState::with_log_slots(TEST_LOG_SLOTS)
    }

    fn mk_output(slot: u32) -> TxOutput {
        TxOutput {
            slot_index: slot,
            value: 100,
            owner: Address([1u8; 32]),
            valid: true,
        }
    }

    fn empty_block_at(height: u64, state_root: [u8; 32]) -> Block {
        let header = BlockHeader {
            prev_block_hash: [0u8; 32],
            state_root,
            tx_root: compute_tx_root(&[]),
            timestamp: 1_767_225_600 + height * 60,
            height,
            miner_address: Address([0u8; 32]),
            nonce: 0,
            difficulty_target: GENESIS_TARGET,
            proof_transcript_hash: [1u8; 32],
            witness_root: [1u8; 32],
            log_slots: TEST_LOG_SLOTS as u32,
            active_slot_count: 0,
            alloc_counter: 0,
        };
        Block {
            header,
            transactions: vec![],
        }
    }

    #[test]
    fn prune_removes_old_logs() {
        use crate::consensus::params::UNDO_RETENTION_DEPTH;
        let n = UNDO_RETENTION_DEPTH + 5; // 23 blocks
        let mut logs: HashMap<u64, BlockUndoLog> = HashMap::new();
        for h in 0..n {
            logs.insert(h, BlockUndoLog::empty(h));
        }
        let current = n - 1;
        prune_undo_logs(&mut logs, current);
        // cutoff = current - UNDO_RETENTION_DEPTH; keep heights > cutoff
        let cutoff = current.saturating_sub(UNDO_RETENTION_DEPTH);
        for h in 0..=cutoff {
            assert!(
                !logs.contains_key(&h),
                "height {} should be pruned (cutoff={})",
                h,
                cutoff
            );
        }
        for h in (cutoff + 1)..n {
            assert!(logs.contains_key(&h), "height {} should be kept", h);
        }
    }

    #[test]
    fn build_empty_undo_log() {
        let state = fresh();
        let block = empty_block_at(1, state.clone().state_root());
        let undo = build_undo_log(&state, &block);
        assert_eq!(undo.block_height, 1);
        assert!(undo.slot_changes.is_empty());
    }

    #[test]
    fn revert_restores_state_after_mint() {
        let mut state = fresh();
        let pre_root = state.state_root();

        // Mint one output at slot 1.
        let body = TxBody {
            shape: noid_tx::TxShape::Standard4x8,
            epoch_anchor: [0u8; 32],
            fee: 0,
            inputs: vec![],
            outputs: vec![mk_output(1)],
            is_coinbase: false,
        };
        let state_before = state.clone();
        apply_tx(&mut state, &body).unwrap();
        assert_ne!(
            state.state_root(),
            pre_root,
            "state root must change after mint"
        );

        // Build the block that contains the tx (for undo log recording).
        let hash = hash_tx_body(
            &body.epoch_anchor,
            body.fee,
            &body.inputs,
            &body.outputs,
            body.is_coinbase,
        );
        let tx = noid_tx::Transaction {
            body,
            tx_body_hash: hash,
        };
        let post_root = state.state_root();
        let header = BlockHeader {
            prev_block_hash: [0u8; 32],
            state_root: post_root,
            tx_root: compute_tx_root(&[tx.clone()]),
            timestamp: 1_767_225_600 + 60,
            height: 1,
            miner_address: Address([0u8; 32]),
            nonce: 0,
            difficulty_target: GENESIS_TARGET,
            proof_transcript_hash: [1u8; 32],
            witness_root: [1u8; 32],
            log_slots: TEST_LOG_SLOTS as u32,
            active_slot_count: 1,
            alloc_counter: 1,
        };
        let block = Block {
            header,
            transactions: vec![tx],
        };

        let undo = build_undo_log(&state_before, &block);
        // One output → one slot recorded.
        assert_eq!(undo.slot_changes.len(), 1);
        assert_eq!(undo.slot_changes[0].0, 1); // slot index 1
        assert_eq!(undo.slot_changes[0].1, SlotValue::EMPTY); // was empty before

        // Revert the state.
        revert_block(&mut state.state, &undo);
        assert_eq!(
            state.state_root(),
            pre_root,
            "state root must be restored after revert"
        );
    }
}
