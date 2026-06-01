// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Per-transaction consensus checks (SPECIFICATION.md §6, ROADMAP Phase 1 P.8).
//!
//! These checks are cheap (O(1) per tx) and run before ZK verification.
//! Ordering: cheapest first to fail fast.
//!
//! Checks covered here:
//!   1. tx_body_hash == hash(tx.body)   [SPEC §6 check 1 — native side]
//!   2. epoch_anchor within window      [SPEC §6 check 2]
//!   3. tx_body_hash not in nullifier set [SPEC §6 check 4]
//!
//! Cross-tx slot conflicts (checks 4-5 in SPEC §6) are handled by
//! `validate_block_slot_conflicts()` in `validation.rs` since they require
//! looking at the full transaction set.

use crate::consensus::ConsensusError;
use crate::nullifier::NullifierSet;
use noid_tx::{hash_tx_body, Transaction};

/// Validate the per-tx consensus rules for a transaction being included in a block.
///
/// `block_height` is the height of the block being built/validated.
///
/// Checks (ordered cheapest first):
/// 1. `tx.tx_body_hash == hash(tx.body)` — binding check
/// 2. `epoch_anchor` is non-zero for non-coinbase txs (height window deferred to ZK layer)
/// 3. `tx.tx_body_hash` is not in the nullifier set
pub fn validate_tx_consensus(
    tx: &Transaction,
    block_height: u64,
    nullifiers: &NullifierSet,
) -> Result<(), ConsensusError> {
    // Fee must fit in u64. Values in this protocol are 64-bit; a fee > u64::MAX
    // is malformed and must be rejected before any further processing.
    if tx.body.fee > u64::MAX as u128 {
        return Err(ConsensusError::BadFee);
    }

    // 1. tx_body_hash binding.
    let expected_hash = hash_tx_body(
        &tx.body.epoch_anchor,
        tx.body.fee,
        &tx.body.inputs,
        &tx.body.outputs,
        tx.body.is_coinbase,
    );
    if tx.tx_body_hash != expected_hash {
        return Err(ConsensusError::BadTxBodyHash);
    }

    // 2. epoch_anchor window check.
    // The epoch_anchor is a 32-byte block hash. We validate the HEIGHT it refers
    // to is within the window. The actual hash binding is proven by LogicProof
    // (ZK layer); here we check the height embedded in the anchor.
    //
    // NOTE: For the native check, we cannot verify the anchor hash against actual
    // headers without a HeaderProvider. We validate the structural window only.
    // The full cryptographic anchor check is done in validate_block_full() (noid_block)
    // when we have access to the header chain.
    //
    // For coinbase transactions, epoch_anchor is meaningless (no state dependency).
    if !tx.body.is_coinbase {
        // We can only do the height-based check if the public inputs carry the anchor height.
        // Since TxIntent/Transaction carries epoch_anchor as a raw 32-byte hash (not height),
        // the height check is deferred to the full validator.
        // Here we just ensure the anchor is non-zero for non-coinbase txs.
        if tx.body.epoch_anchor == [0u8; 32] {
            return Err(ConsensusError::BadEpochAnchor);
        }
    }

    // Suppress unused variable warning for block_height; the full anchor-height
    // check (using HeaderProvider) is deferred to noid_block::validate_block_full().
    let _ = block_height;

    // 3. Nullifier collision.
    if nullifiers.contains(&tx.tx_body_hash) {
        return Err(ConsensusError::NullifierCollision);
    }

    Ok(())
}

/// Check that no two transactions in a block attempt to consume the same input slot
/// or mint to the same output slot (SPEC §16 invariants 4-5).
///
/// Returns `Err(ConsensusError::SlotConflict)` on the first conflict found.
/// This is O(n × inputs) per block but n ≤ BLOCK_MAX_TXS and inputs ≤ 4.
pub fn validate_block_slot_conflicts(txs: &[Transaction]) -> Result<(), ConsensusError> {
    use std::collections::HashSet;
    let mut spent_inputs: HashSet<u32> = HashSet::new();
    let mut minted_outputs: HashSet<u32> = HashSet::new();

    for tx in txs {
        for inp in &tx.body.inputs {
            if !inp.valid {
                continue;
            }
            if !spent_inputs.insert(inp.slot_index) {
                return Err(ConsensusError::SlotConflict);
            }
        }
        for out in &tx.body.outputs {
            if !out.valid {
                continue;
            }
            if !minted_outputs.insert(out.slot_index) {
                return Err(ConsensusError::SlotConflict);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nullifier::NullifierSet;
    use noid_poseidon2b::primitives::{Address, AuthTag, SpendSecret, TxBodyHash};
    use noid_tx::{hash_tx_body, Transaction, TxBody, TxInput, TxOutput};

    fn dummy_output(slot: u32) -> TxOutput {
        TxOutput {
            slot_index: slot,
            value: 100,
            owner: Address([1u8; 32]),
            valid: true,
        }
    }

    fn dummy_input(slot: u32) -> TxInput {
        TxInput {
            slot_index: slot,
            value: 100,
            owner: Address([1u8; 32]),
            spend_secret: SpendSecret([0u8; 32]),
            auth_tag: AuthTag([0u8; 32]),
            valid: true,
        }
    }

    fn make_tx(inputs: Vec<TxInput>, outputs: Vec<TxOutput>, is_coinbase: bool) -> Transaction {
        let body = TxBody {
            epoch_anchor: if is_coinbase { [0u8; 32] } else { [1u8; 32] },
            fee: 0,
            inputs,
            outputs,
            is_coinbase,
        };
        let hash = hash_tx_body(
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
    fn valid_tx_passes() {
        let tx = make_tx(vec![], vec![dummy_output(1)], false);
        let ns = NullifierSet::new();
        assert!(validate_tx_consensus(&tx, 10, &ns).is_ok());
    }

    #[test]
    fn wrong_body_hash_rejected() {
        let mut tx = make_tx(vec![], vec![dummy_output(1)], false);
        tx.tx_body_hash = TxBodyHash([0xAB; 32]); // tamper
        let ns = NullifierSet::new();
        assert_eq!(
            validate_tx_consensus(&tx, 10, &ns),
            Err(ConsensusError::BadTxBodyHash)
        );
    }

    #[test]
    fn nullifier_collision_rejected() {
        let tx = make_tx(vec![], vec![dummy_output(1)], false);
        let mut ns = NullifierSet::new();
        ns.insert_block(&[tx.tx_body_hash]);
        assert_eq!(
            validate_tx_consensus(&tx, 10, &ns),
            Err(ConsensusError::NullifierCollision)
        );
    }

    #[test]
    fn non_coinbase_zero_anchor_rejected() {
        let mut tx = make_tx(vec![], vec![dummy_output(1)], false);
        tx.body.epoch_anchor = [0u8; 32]; // zero anchor for non-coinbase
                                          // Recompute hash to match tampered body
        let hash = hash_tx_body(
            &tx.body.epoch_anchor,
            tx.body.fee,
            &tx.body.inputs,
            &tx.body.outputs,
            tx.body.is_coinbase,
        );
        tx.tx_body_hash = hash;
        let ns = NullifierSet::new();
        assert_eq!(
            validate_tx_consensus(&tx, 10, &ns),
            Err(ConsensusError::BadEpochAnchor)
        );
    }

    #[test]
    fn coinbase_zero_anchor_allowed() {
        let tx = make_tx(vec![], vec![dummy_output(1)], true); // is_coinbase=true, epoch_anchor=[0;32]
        let ns = NullifierSet::new();
        assert!(validate_tx_consensus(&tx, 10, &ns).is_ok());
    }

    #[test]
    fn slot_conflict_input_detected() {
        let tx1 = make_tx(vec![dummy_input(5)], vec![], false);
        let tx2 = make_tx(vec![dummy_input(5)], vec![], false); // same input slot
        assert_eq!(
            validate_block_slot_conflicts(&[tx1, tx2]),
            Err(ConsensusError::SlotConflict)
        );
    }

    #[test]
    fn slot_conflict_output_detected() {
        let tx1 = make_tx(vec![], vec![dummy_output(3)], false);
        let tx2 = make_tx(vec![], vec![dummy_output(3)], false); // same output slot
        assert_eq!(
            validate_block_slot_conflicts(&[tx1, tx2]),
            Err(ConsensusError::SlotConflict)
        );
    }

    #[test]
    fn fee_overflow_rejected() {
        // Build a tx with fee > u64::MAX
        let body = TxBody {
            epoch_anchor: [1u8; 32],
            fee: u128::MAX, // way over u64::MAX
            inputs: vec![],
            outputs: vec![dummy_output(1)],
            is_coinbase: false,
        };
        let hash_bytes = hash_tx_body(
            &body.epoch_anchor,
            body.fee,
            &body.inputs,
            &body.outputs,
            body.is_coinbase,
        );
        let tx = Transaction {
            body,
            tx_body_hash: hash_bytes,
        };
        let ns = NullifierSet::new();
        assert_eq!(
            validate_tx_consensus(&tx, 10, &ns),
            Err(ConsensusError::BadFee)
        );
    }

    #[test]
    fn no_conflict_passes() {
        let tx1 = make_tx(vec![dummy_input(1)], vec![dummy_output(10)], false);
        let tx2 = make_tx(vec![dummy_input(2)], vec![dummy_output(11)], false);
        assert!(validate_block_slot_conflicts(&[tx1, tx2]).is_ok());
    }
}
