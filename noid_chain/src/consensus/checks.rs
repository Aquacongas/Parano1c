// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Per-transaction consensus checks.
//!
//! These checks are cheap (O(1) per tx) and run before wallet authorization verification.
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
use noid_tx::{hash_tx_body_for_shape, Transaction};

/// Validate the per-tx consensus rules for a transaction.
///
/// Checks (ordered cheapest first):
/// 0. Fee fits in u64; coinbase fee == 0; coinbase output count == 1.
/// 1. `tx.tx_body_hash == hash(tx.body)` — binding check
///    (skip when called from `validate_block_consensus` because `apply_block`
///    already verifies this, avoiding double Poseidon2b computation per tx).
/// 2. `epoch_anchor` is non-zero for non-coinbase txs.
/// 3. `tx.tx_body_hash` is not in the nullifier set.
///
/// `check_body_hash = false` skips check 1, reducing Poseidon2b work by
/// ~59 permutations per tx (used by `validate_block_consensus`).
pub fn validate_tx_consensus(
    tx: &Transaction,
    nullifiers: &NullifierSet,
) -> Result<(), ConsensusError> {
    validate_tx_consensus_inner(tx, nullifiers, true)
}

/// Same as `validate_tx_consensus` but skips the tx_body_hash recomputation.
///
/// Called by `validate_block_consensus` because `apply_block` already
/// verifies tx_body_hash for every transaction in the block, making the
/// recomputation here redundant.
/// At 256 txs × 59-perm Poseidon2b, this saves ~15 ms per block application.
#[inline]
pub(crate) fn validate_tx_consensus_skip_hash(
    tx: &Transaction,
    nullifiers: &NullifierSet,
) -> Result<(), ConsensusError> {
    validate_tx_consensus_inner(tx, nullifiers, false)
}

fn validate_tx_consensus_inner(
    tx: &Transaction,
    nullifiers: &NullifierSet,
    check_body_hash: bool,
) -> Result<(), ConsensusError> {
    // 0. Fee must fit in u64 (values are 64-bit in this protocol).
    if tx.body.fee > u64::MAX as u128 {
        return Err(ConsensusError::BadFee);
    }

    // 0a. Only shapes with complete wallet/mempool proof support are admitted.
    if !tx.body.shape.proof_supported() {
        return Err(ConsensusError::ShapeMismatch(format!(
            "unsupported tx shape {:?}",
            tx.body.shape
        )));
    }
    if tx.body.inputs.len() > tx.body.shape.max_inputs() {
        return Err(ConsensusError::ShapeMismatch(format!(
            "inputs exceed {:?} max {}",
            tx.body.shape,
            tx.body.shape.max_inputs()
        )));
    }
    if tx.body.outputs.len() > tx.body.shape.max_outputs() {
        return Err(ConsensusError::ShapeMismatch(format!(
            "outputs exceed {:?} max {}",
            tx.body.shape,
            tx.body.shape.max_outputs()
        )));
    }

    // 0b. Coinbase fee must be zero.
    if tx.body.is_coinbase && tx.body.fee != 0 {
        return Err(ConsensusError::BadFee);
    }

    // 0c. Coinbase must have exactly one valid output.
    if tx.body.is_coinbase {
        let n_valid_outputs = tx.body.outputs.iter().filter(|o| o.valid).count();
        if n_valid_outputs != 1 {
            return Err(ConsensusError::ShapeMismatch(format!(
                "coinbase must have exactly 1 valid output, got {n_valid_outputs}"
            )));
        }
    }

    // 1. tx_body_hash binding (skipped when called from validate_block_consensus
    //    because apply_block already verifies this for every tx in the block).
    if check_body_hash {
        let expected_hash = hash_tx_body_for_shape(
            tx.body.shape,
            &tx.body.epoch_anchor,
            tx.body.fee,
            &tx.body.inputs,
            &tx.body.outputs,
            tx.body.is_coinbase,
        );
        if tx.tx_body_hash != expected_hash {
            return Err(ConsensusError::BadTxBodyHash);
        }
    }

    // 2. epoch_anchor: non-zero for non-coinbase (structural check).
    //    The full cryptographic check (anchor hash ∈ known headers within window)
    //    is done at mempool admission (`mempool_checks.rs`) and at full block
    //    validation in `noid_block::validate_block_full()` where a HeaderProvider
    //    is available.
    if !tx.body.is_coinbase && tx.body.epoch_anchor == [0u8; 32] {
        return Err(ConsensusError::BadEpochAnchor);
    }

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
    use noid_tx::{hash_tx_body, hash_tx_body_for_shape, Transaction, TxBody, TxInput, TxOutput};

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
            shape: noid_tx::TxShape::Standard4x8,
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
        assert!(validate_tx_consensus(&tx, &ns).is_ok());
    }

    #[test]
    fn sweep_shape_is_consensus_admitted() {
        let body = TxBody {
            shape: noid_tx::TxShape::Sweep25x2,
            epoch_anchor: [1u8; 32],
            fee: 0,
            inputs: (0..5).map(dummy_input).collect(),
            outputs: vec![dummy_output(1), dummy_output(2)],
            is_coinbase: false,
        };
        let tx_body_hash = hash_tx_body_for_shape(
            body.shape,
            &body.epoch_anchor,
            body.fee,
            &body.inputs,
            &body.outputs,
            body.is_coinbase,
        );
        let tx = Transaction { body, tx_body_hash };
        let ns = NullifierSet::new();
        assert_eq!(validate_tx_consensus(&tx, &ns), Ok(()));
    }

    #[test]
    fn sweep_shape_limits_are_enforced() {
        let body = TxBody {
            shape: noid_tx::TxShape::Sweep25x2,
            epoch_anchor: [1u8; 32],
            fee: 0,
            inputs: (0..26).map(dummy_input).collect(),
            outputs: vec![dummy_output(1)],
            is_coinbase: false,
        };
        let tx = Transaction {
            body,
            tx_body_hash: TxBodyHash([0u8; 32]),
        };
        let ns = NullifierSet::new();
        assert!(matches!(
            validate_tx_consensus(&tx, &ns),
            Err(ConsensusError::ShapeMismatch(_))
        ));
    }

    #[test]
    fn wrong_body_hash_rejected() {
        let mut tx = make_tx(vec![], vec![dummy_output(1)], false);
        tx.tx_body_hash = TxBodyHash([0xAB; 32]); // tamper
        let ns = NullifierSet::new();
        assert_eq!(
            validate_tx_consensus(&tx, &ns),
            Err(ConsensusError::BadTxBodyHash)
        );
    }

    #[test]
    fn nullifier_collision_rejected() {
        let tx = make_tx(vec![], vec![dummy_output(1)], false);
        let mut ns = NullifierSet::new();
        ns.insert_block(&[tx.tx_body_hash]);
        assert_eq!(
            validate_tx_consensus(&tx, &ns),
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
            validate_tx_consensus(&tx, &ns),
            Err(ConsensusError::BadEpochAnchor)
        );
    }

    #[test]
    fn coinbase_zero_anchor_allowed() {
        let tx = make_tx(vec![], vec![dummy_output(1)], true); // is_coinbase=true, epoch_anchor=[0;32]
        let ns = NullifierSet::new();
        assert!(validate_tx_consensus(&tx, &ns).is_ok());
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
            shape: noid_tx::TxShape::Standard4x8,
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
        assert_eq!(validate_tx_consensus(&tx, &ns), Err(ConsensusError::BadFee));
    }

    #[test]
    fn coinbase_must_have_exactly_one_output() {
        // 0 outputs: rejected
        let body_no_output = TxBody {
            shape: noid_tx::TxShape::Standard4x8,
            epoch_anchor: [0u8; 32],
            fee: 0,
            inputs: vec![],
            outputs: vec![],
            is_coinbase: true,
        };
        let h0 = hash_tx_body(
            &body_no_output.epoch_anchor,
            body_no_output.fee,
            &body_no_output.inputs,
            &body_no_output.outputs,
            body_no_output.is_coinbase,
        );
        let tx0 = Transaction {
            body: body_no_output,
            tx_body_hash: h0,
        };
        let ns = NullifierSet::new();
        assert!(
            matches!(
                validate_tx_consensus(&tx0, &ns),
                Err(ConsensusError::ShapeMismatch(_))
            ),
            "coinbase with 0 outputs must be rejected"
        );

        // 2 outputs: rejected
        let body_two = TxBody {
            shape: noid_tx::TxShape::Standard4x8,
            epoch_anchor: [0u8; 32],
            fee: 0,
            inputs: vec![],
            outputs: vec![dummy_output(1), dummy_output(2)],
            is_coinbase: true,
        };
        let h2 = hash_tx_body(
            &body_two.epoch_anchor,
            body_two.fee,
            &body_two.inputs,
            &body_two.outputs,
            body_two.is_coinbase,
        );
        let tx2 = Transaction {
            body: body_two,
            tx_body_hash: h2,
        };
        assert!(
            matches!(
                validate_tx_consensus(&tx2, &ns),
                Err(ConsensusError::ShapeMismatch(_))
            ),
            "coinbase with 2 outputs must be rejected"
        );
    }

    #[test]
    fn coinbase_nonzero_fee_rejected() {
        let body = TxBody {
            shape: noid_tx::TxShape::Standard4x8,
            epoch_anchor: [0u8; 32],
            fee: 1,
            inputs: vec![],
            outputs: vec![dummy_output(5)],
            is_coinbase: true,
        };
        let h = hash_tx_body(
            &body.epoch_anchor,
            body.fee,
            &body.inputs,
            &body.outputs,
            body.is_coinbase,
        );
        let tx = Transaction {
            body,
            tx_body_hash: h,
        };
        assert_eq!(
            validate_tx_consensus(&tx, &NullifierSet::new()),
            Err(ConsensusError::BadFee),
            "coinbase with non-zero fee must be rejected"
        );
    }

    #[test]
    fn no_conflict_passes() {
        let tx1 = make_tx(vec![dummy_input(1)], vec![dummy_output(10)], false);
        let tx2 = make_tx(vec![dummy_input(2)], vec![dummy_output(11)], false);
        assert!(validate_block_slot_conflicts(&[tx1, tx2]).is_ok());
    }
}
