// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Mempool admission checks (SPECIFICATION.md §6, ROADMAP Phase 1 P.10).
//!
//! `validate_tx_for_mempool` enforces all native checks a node performs
//! before admitting a transaction to the mempool. This is a SUPERSET of
//! `validate_tx_consensus` — it adds state-dependent checks that require
//! knowing the current UTXO state and the last ANCHOR_DEPTH block headers.
//!
//! ZK verification (`verify_logic`) is intentionally NOT performed here.
//! It runs as a background pre-proving task after admission.
//!
//! # Check order (cheapest first)
//!
//! 1. Basic consensus checks: fee overflow, body_hash, anchor non-zero, nullifier
//! 2. epoch_anchor hash is a known block header within the ANCHOR_DEPTH window
//! 3. No slot conflict with currently admitted mempool transactions
//! 4. Input slots are live in state with matching (value, owner)
//! 5. Output slots are empty in state

use std::collections::HashSet;

use crate::chain_context::ChainContext;
use crate::consensus::{
    checks::validate_tx_consensus, params::ANCHOR_DEPTH, pow::full_block_hash, ConsensusError,
};
use crate::fri_state::SlotValue;
use noid_core::Block128;
use noid_tx::Transaction;

/// Validate a transaction for mempool admission.
///
/// `ctx` provides the current chain state, nullifier set, and stored headers.
/// `mempool_txs` is the current set of already-admitted transactions (used
/// for cross-tx slot conflict detection within the mempool).
///
/// Returns `Ok(())` if the transaction passes all native admission checks.
/// ZK proof verification is performed separately (async, pre-proving).
pub fn validate_tx_for_mempool(
    tx: &Transaction,
    ctx: &ChainContext,
    mempool_txs: &[Transaction],
) -> Result<(), ConsensusError> {
    // --- Step 1: basic consensus checks ---
    validate_tx_consensus(tx, ctx.tip_height + 1, &ctx.nullifiers)?;

    // --- Step 2: epoch_anchor hash must be a known header within window ---
    if !tx.body.is_coinbase {
        let anchor_hash = tx.body.epoch_anchor;
        let tip = ctx.tip_height;
        let lo = tip.saturating_sub(ANCHOR_DEPTH);
        let anchor_valid = (lo..=tip).any(|h| {
            ctx.headers
                .get(&h)
                .map(|hdr| full_block_hash(hdr) == anchor_hash)
                .unwrap_or(false)
        });
        if !anchor_valid {
            return Err(ConsensusError::BadEpochAnchor);
        }
    }

    // --- Step 3: no slot conflict with mempool ---
    let mut mempool_inputs: HashSet<u32> = HashSet::new();
    let mut mempool_outputs: HashSet<u32> = HashSet::new();
    for admitted in mempool_txs {
        for inp in &admitted.body.inputs {
            if inp.valid {
                mempool_inputs.insert(inp.slot_index);
            }
        }
        for out in &admitted.body.outputs {
            if out.valid {
                mempool_outputs.insert(out.slot_index);
            }
        }
    }
    for inp in &tx.body.inputs {
        if inp.valid && mempool_inputs.contains(&inp.slot_index) {
            return Err(ConsensusError::SlotConflict);
        }
    }
    for out in &tx.body.outputs {
        if out.valid && mempool_outputs.contains(&out.slot_index) {
            return Err(ConsensusError::SlotConflict);
        }
    }

    // --- Step 4: input slots live in state with matching (value, owner) ---
    for inp in &tx.body.inputs {
        if !inp.valid {
            continue;
        }
        let idx = inp.slot_index;
        if (idx as u64) >= ctx.state.state.num_slots() {
            return Err(ConsensusError::ShapeMismatch(format!(
                "input slot {} out of range (max {})",
                idx,
                ctx.state.state.num_slots()
            )));
        }
        let expected = SlotValue {
            value: Block128::from(inp.value as u128),
            owner_hi: inp.owner.as_fields()[0],
            owner_lo: inp.owner.as_fields()[1],
        };
        if ctx.state.state.slot(idx) != expected {
            return Err(ConsensusError::BadStateRoot); // closest existing error
        }
    }

    // --- Step 5: output slots empty in state ---
    for out in &tx.body.outputs {
        if !out.valid {
            continue;
        }
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
    use noid_tx::{Transaction, TxBody, TxOutput};

    fn make_coinbase(slot: u32) -> Transaction {
        let body = TxBody {
            epoch_anchor: [0u8; 32],
            fee: 0,
            inputs: vec![],
            outputs: vec![TxOutput {
                slot_index: slot,
                value: 50_000_000,
                owner: Address([0u8; 32]),
                valid: true,
            }],
            is_coinbase: true,
        };
        let hash = noid_tx::hash_tx_body(
            &body.epoch_anchor,
            body.fee,
            &body.inputs,
            &body.outputs,
            body.is_coinbase,
        );
        Transaction {
            body,
            tx_body_hash: hash,
        }
    }

    #[test]
    fn coinbase_passes_without_anchor_check() {
        let ctx = ChainContext::init_from_genesis();
        let cb = make_coinbase(100);
        // Coinbase skips anchor and slot checks.
        // It has zero epoch_anchor which is valid for coinbase.
        // Coinbase output slot 100 is empty in fresh state.
        let result = validate_tx_for_mempool(&cb, &ctx, &[]);
        assert!(result.is_ok(), "coinbase should pass: {:?}", result);
    }

    #[test]
    fn slot_conflict_with_mempool_detected() {
        let ctx = ChainContext::init_from_genesis();
        let tx1 = make_coinbase(50); // admitted to mempool
        let tx2 = make_coinbase(50); // conflict: same output slot

        // tx2 conflicts with already-admitted tx1 on slot 50.
        let result = validate_tx_for_mempool(&tx2, &ctx, &[tx1]);
        assert_eq!(result, Err(ConsensusError::SlotConflict));
    }

    #[test]
    fn output_slot_occupied_in_state_rejected() {
        // First mint to a slot; then try minting again.
        let mut ctx = ChainContext::init_from_genesis();

        // Directly write to state to simulate an occupied slot.
        ctx.state
            .state
            .set_slot(
                7,
                SlotValue {
                    value: Block128::from(100u128),
                    owner_hi: Block128(0),
                    owner_lo: Block128(0),
                },
            )
            .unwrap();

        let tx = make_coinbase(7); // tries to mint to occupied slot 7
        let result = validate_tx_for_mempool(&tx, &ctx, &[]);
        assert_eq!(result, Err(ConsensusError::SlotConflict));
    }
}
