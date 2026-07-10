// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Mempool admission checks.
//!
//! `validate_tx_for_mempool` enforces all native checks a node performs
//! before admitting a transaction to the mempool. This is a SUPERSET of
//! `validate_tx_consensus` — it adds state-dependent checks that require
//! knowing the current UTXO state and current transaction-epoch anchor.
//!
//! Wallet authorization verification is intentionally NOT performed here.
//! It runs as a background verification task after admission.
//!
//! # Check order (cheapest first)
//!
//! 0. P.16 min fee: base + I/O + occupancy-scaled net-new-state fee (coinbase exempt)
//! 1. Basic canonical body checks
//! 2. epoch_anchor equals the single current transaction-epoch anchor
//! 3. No slot conflict with currently admitted mempool transactions
//! 4. Input slots are live in state with matching (value, owner)
//! 5. Output slots are empty in state

use std::collections::HashSet;

use crate::chain_context::ChainContext;
use crate::consensus::{
    checks::validate_tx_consensus, epoch_anchor::tx_epoch_anchor_height_for_child,
    fees::required_fee_for_tx_body, pow::block_id, ConsensusError,
};
use crate::fri_state::SlotValue;
use noid_tx::Transaction;

/// Validate a transaction for mempool admission.
///
/// `ctx` provides the current chain state and stored headers.
/// `mempool_txs` is the current set of already-admitted transactions (used
/// for cross-tx slot conflict detection within the mempool).
///
/// Returns `Ok(())` if the transaction passes all native admission checks.
/// Wallet authorization verification is performed separately (async).
pub fn validate_tx_for_mempool(
    tx: &Transaction,
    ctx: &ChainContext,
    mempool_txs: &[Transaction],
) -> Result<(), ConsensusError> {
    // --- Minimum fee ---
    // Coinbase is exempt: it's built by the miner, not submitted by a wallet.
    if !tx.body.is_coinbase {
        let required = required_fee_for_tx_body(
            &tx.body,
            ctx.state.active_slot_count,
            ctx.state.state.log_slots() as u32,
        );
        let actual = tx.body.fee;
        if actual < required {
            return Err(ConsensusError::BelowMinFee { required, actual });
        }
    }

    // --- Basic consensus checks ---
    validate_tx_consensus(tx)?;

    // --- User anchor must equal the one start-of-next-block epoch anchor ---
    if !tx.body.is_coinbase {
        let anchor_height = tx_epoch_anchor_height_for_child(ctx.tip_height + 1);
        let expected_anchor = ctx
            .headers
            .get(&anchor_height)
            .map(block_id)
            .ok_or(ConsensusError::BadEpochAnchor)?;
        if tx.body.epoch_anchor != expected_anchor {
            return Err(ConsensusError::BadEpochAnchor);
        }
    }

    // --- Strict pending-set disjointness (packages are not supported) ---
    let mut mempool_touched: HashSet<u32> = HashSet::new();
    for admitted in mempool_txs {
        for (_, inp) in admitted.body.live_inputs() {
            mempool_touched.insert(inp.slot_index);
        }
        for (_, out) in admitted.body.live_outputs() {
            mempool_touched.insert(out.slot_index);
        }
    }
    for (_, inp) in tx.body.live_inputs() {
        if mempool_touched.contains(&inp.slot_index) {
            return Err(ConsensusError::SlotConflict);
        }
    }
    for (_, out) in tx.body.live_outputs() {
        if mempool_touched.contains(&out.slot_index) {
            return Err(ConsensusError::SlotConflict);
        }
    }

    // --- Input slots live in state with matching (value, owner) ---
    for (_, inp) in tx.body.live_inputs() {
        let idx = inp.slot_index;
        if (idx as u64) >= ctx.state.state.num_slots() {
            return Err(ConsensusError::ShapeMismatch(format!(
                "input slot {} out of range (max {})",
                idx,
                ctx.state.state.num_slots()
            )));
        }
        let expected = SlotValue::with_owner_fields(
            inp.amount,
            inp.creation_id,
            tx.body.input_owner.as_fields(),
        );
        if ctx.state.state.slot(idx) != expected {
            return Err(ConsensusError::BadStateRoot); // closest existing error
        }
    }

    // --- Output slots empty in state ---
    for (_, out) in tx.body.live_outputs() {
        let idx = out.slot_index;
        if (idx as u64) >= ctx.state.state.num_slots() {
            return Err(ConsensusError::ShapeMismatch(format!(
                "output slot {} out of range",
                idx
            )));
        }
        if ctx.state.state.slot(idx) != SlotValue::EMPTY {
            return Err(ConsensusError::SlotConflict);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain_context::ChainContext;
    use noid_poseidon2b::primitives::Address;
    use noid_tx::{
        output_bitmap_bit, Transaction, TxBody, TxInput, TxOutput, TX_INPUTS, TX_OUTPUTS,
    };

    fn tx(anchor: [u8; 32], fee: u64, input_slot: u32, output_slot: u32) -> Transaction {
        let mut inputs = [TxInput::dummy(); TX_INPUTS];
        inputs[0] = TxInput {
            slot_index: input_slot,
            amount: 100 + fee,
            creation_id: 1,
        };
        let mut outputs = [TxOutput::dummy(); TX_OUTPUTS];
        outputs[0] = TxOutput {
            slot_index: output_slot,
            amount: 100,
            owner: Address([2u8; 32]),
        };
        Transaction::new(TxBody {
            epoch_anchor: anchor,
            fee,
            input_owner: Address([1u8; 32]),
            inputs,
            outputs,
            validity_bitmap: 1 | output_bitmap_bit(0),
            is_coinbase: false,
        })
    }

    fn funded_context(fee: u64) -> ChainContext {
        let mut ctx = ChainContext::init_from_easy_genesis();
        ctx.state
            .state
            .set_slot(
                1,
                SlotValue::with_owner_fields(100 + fee, 1, Address([1u8; 32]).as_fields()),
            )
            .unwrap();
        ctx.state.active_slot_count = 1;
        ctx.state.alloc_counter = 1;
        ctx
    }

    #[test]
    fn exact_current_anchor_and_state_are_required() {
        let probe = tx([1u8; 32], 0, 1, 2);
        let ctx0 = funded_context(0);
        let required = required_fee_for_tx_body(
            &probe.body,
            ctx0.state.active_slot_count,
            ctx0.state.state.log_slots() as u32,
        );
        let ctx = funded_context(required);
        let good = tx(ctx.tip_hash, required, 1, 2);
        assert_eq!(validate_tx_for_mempool(&good, &ctx, &[]), Ok(()));

        let bad_anchor = tx([9u8; 32], required, 1, 2);
        assert_eq!(
            validate_tx_for_mempool(&bad_anchor, &ctx, &[]),
            Err(ConsensusError::BadEpochAnchor)
        );

        let bad_state = tx(ctx.tip_hash, required, 3, 2);
        assert_eq!(
            validate_tx_for_mempool(&bad_state, &ctx, &[]),
            Err(ConsensusError::BadStateRoot)
        );
    }

    #[test]
    fn pending_cross_slot_conflict_rejects() {
        let probe = tx([1u8; 32], 0, 1, 2);
        let ctx0 = funded_context(0);
        let required = required_fee_for_tx_body(
            &probe.body,
            ctx0.state.active_slot_count,
            ctx0.state.state.log_slots() as u32,
        );
        let ctx = funded_context(required);
        let admitted = tx(ctx.tip_hash, required, 3, 1);
        let candidate = tx(ctx.tip_hash, required, 1, 2);
        assert_eq!(
            validate_tx_for_mempool(&candidate, &ctx, &[admitted]),
            Err(ConsensusError::SlotConflict)
        );
    }
}
