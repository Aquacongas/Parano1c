// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Block-level state binding: bridges LogicProofs to on-chain state.
//!
//! In the two-layer architecture, each wallet produces a stateless
//! `LogicProof` that binds to a `claims_commitment` (C_claimed) — a
//! Poseidon2b sponge over the wallet's declared `(slot_index, value,
//! owner)` tuples. The miner's `BlockStateBinding` opens the actual
//! FRI-committed state at each claimed slot and verifies:
//!
//! - **Pre-state inputs**: the opened `(value, owner)` at each input
//!   slot matches the wallet's claim (UTXO exists and is spendable).
//! - **Pre-state outputs**: the opened slot is empty `(0, 0, 0)` — the
//!   wallet-chosen destination is not already occupied.
//! - **Post-state**: after zeroing inputs and filling outputs, the
//!   resulting state root matches the block header's `new_state_root`.
//! - **C_claimed bridge**: the claims commitment derived from the opened
//!   slots matches the `C_claimed` in each tx's `PublicInputs`.
//!
//! # Architecture
//!
//! The binding operates per-block. For each transaction in the block:
//! 1. Collect all live input/output slots from `TxBody`.
//! 2. Open them against `prev_state` (the state BEFORE this tx).
//! 3. Verify input slots contain the claimed values.
//! 4. Verify output slots are empty (pre-mint).
//! 5. Recompute `C_claimed` from opened values and verify it matches.
//! 6. Apply the state transition (zero inputs, fill outputs).
//!
//! After all txs are processed, the final state root must equal the
//! block header's declared `new_state_root`.

use std::collections::HashMap;

use noid_core::Block128;
use noid_poseidon2b::primitives::Digest;
use noid_tx::{compute_claims_commitment, TxBody, TxInput, TxOutput};

use crate::fri_state::{SlotValue, StateRoot};
use crate::segmented_state::SegmentedFriState;

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Errors during block-level state binding verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateBindingError {
    /// An input slot in the state does not contain the claimed value/owner.
    InputMismatch { tx_index: usize, input_index: usize },
    /// An output slot is not empty in the pre-state (occupied).
    OutputSlotOccupied {
        tx_index: usize,
        output_index: usize,
    },
    /// The recomputed C_claimed from opened slots does not match the
    /// tx's PublicInputs.claims_commitment.
    ClaimsCommitmentMismatch { tx_index: usize },
    /// Two outputs within the same tx target the same slot_index.
    DuplicateOutputSlot { tx_index: usize },
    /// A slot index is out of range for the current state vector.
    SlotOutOfRange { tx_index: usize },
    /// The final state root after all txs does not match the expected value.
    FinalRootMismatch,
}

// ---------------------------------------------------------------------------
// Per-transaction opened slot data
// ---------------------------------------------------------------------------

/// Opened state for a single transaction within a block.
#[derive(Debug, Clone)]
pub struct TxStateOpening {
    /// The opened pre-state values for each live input slot.
    pub input_openings: Vec<SlotValue>,
    /// The opened pre-state values for each live output slot (must all be EMPTY).
    pub output_openings: Vec<SlotValue>,
}

// ---------------------------------------------------------------------------
// Block state binding
// ---------------------------------------------------------------------------

/// Block-level state binding: verifies that all transactions' claimed
/// slots match the actual FRI-committed state.
#[derive(Debug, Clone)]
pub struct BlockStateBinding {
    /// Per-tx state openings in block order.
    pub tx_openings: Vec<TxStateOpening>,
    /// State root before any tx in this block is applied.
    pub prev_state_root: StateRoot,
    /// State root after all txs are applied.
    pub new_state_root: StateRoot,
    /// Poseidon2b Merkle siblings for each dirty segment at PRE-state.
    /// Key = seg_id. Empty when `num_segments == 1` (single-segment / test mode).
    pub pre_seg_siblings: HashMap<u16, Vec<StateRoot>>,
    /// Poseidon2b Merkle siblings for each dirty segment at POST-state.
    pub post_seg_siblings: HashMap<u16, Vec<StateRoot>>,
    /// Depth of the segment Merkle tree (= log2(num_segments)). 0 = single-segment.
    pub tree_depth: usize,
}

impl BlockStateBinding {
    /// Build and verify the state binding for a block of transactions.
    ///
    /// Opens each tx's claimed slots against `state` (a `SegmentedFriState`),
    /// verifies the pre-conditions, applies the state transition, and checks
    /// the claims commitment bridge.
    ///
    /// On success, `state` is mutated to reflect all applied txs and
    /// the returned binding contains the opening data.
    ///
    /// `expected_commitments[i]` is the `claims_commitment` from the
    /// i-th transaction's `PublicInputs` (carried inside the LogicProof).
    ///
    /// # epoch_anchor freshness
    ///
    /// `epoch_anchor` is verified at mempool admission in `noid_mempool::pool::submit`
    /// The anchor hash must be a known block header within the ANCHOR_DEPTH
    /// window. Invalid anchors are rejected before the tx enters the pool.
    pub fn build(
        state: &mut SegmentedFriState,
        bodies: &[TxBody],
        expected_commitments: &[Digest],
    ) -> Result<Self, StateBindingError> {
        assert_eq!(bodies.len(), expected_commitments.len());

        let prev_state_root = state.root(); // ensures all roots up to date
        let mut tx_openings = Vec::with_capacity(bodies.len());

        for (tx_idx, body) in bodies.iter().enumerate() {
            let opening = verify_and_apply_tx(state, body, expected_commitments[tx_idx], tx_idx)?;
            tx_openings.push(opening);
        }

        let new_state_root = state.root();

        // Merkle siblings require access to the pre-state tree (before mutation).
        // build_block_template() populates them after coinbase apply.
        Ok(Self {
            tx_openings,
            prev_state_root,
            new_state_root,
            pre_seg_siblings: HashMap::new(),
            post_seg_siblings: HashMap::new(),
            tree_depth: 0,
        })
    }

    /// Verify a pre-built binding against an expected final state root.
    /// Used by the verifier path when the binding is received as part
    /// of a block proof.
    pub fn verify_final_root(&self, expected: &StateRoot) -> Result<(), StateBindingError> {
        if self.new_state_root != *expected {
            return Err(StateBindingError::FinalRootMismatch);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Verify pre-conditions for one tx, apply the state transition, and
/// verify the claims commitment bridge.
fn verify_and_apply_tx(
    state: &mut SegmentedFriState,
    body: &TxBody,
    expected_commitment: Digest,
    tx_idx: usize,
) -> Result<TxStateOpening, StateBindingError> {
    let n_slots = state.num_slots();

    // Check output slot uniqueness within this tx
    let mut seen_output_slots = std::collections::HashSet::new();
    for out in body.outputs.iter().filter(|o| o.valid) {
        if !seen_output_slots.insert(out.slot_index) {
            return Err(StateBindingError::DuplicateOutputSlot { tx_index: tx_idx });
        }
    }

    // Open and verify input slots
    let mut input_openings = Vec::new();
    for (i, inp) in body.inputs.iter().enumerate() {
        if !inp.valid {
            continue;
        }
        if (inp.slot_index as u64) >= n_slots {
            return Err(StateBindingError::SlotOutOfRange { tx_index: tx_idx });
        }
        let opened = state.slot(inp.slot_index);
        let expected = slot_value_from_input(inp);
        if opened != expected {
            return Err(StateBindingError::InputMismatch {
                tx_index: tx_idx,
                input_index: i,
            });
        }
        input_openings.push(opened);
    }

    // Open and verify output slots (must be empty)
    let mut output_openings = Vec::new();
    for (j, out) in body.outputs.iter().enumerate() {
        if !out.valid {
            continue;
        }
        if (out.slot_index as u64) >= n_slots {
            return Err(StateBindingError::SlotOutOfRange { tx_index: tx_idx });
        }
        let opened = state.slot(out.slot_index);
        if opened != SlotValue::EMPTY {
            return Err(StateBindingError::OutputSlotOccupied {
                tx_index: tx_idx,
                output_index: j,
            });
        }
        output_openings.push(opened);
    }

    // Verify C_claimed bridge: recompute from the tx body and check
    let recomputed = compute_claims_commitment(&body.inputs, &body.outputs);
    if recomputed != expected_commitment {
        return Err(StateBindingError::ClaimsCommitmentMismatch { tx_index: tx_idx });
    }

    // Apply state transition: zero inputs, fill outputs
    for inp in body.inputs.iter().filter(|i| i.valid) {
        state
            .set_slot(inp.slot_index, SlotValue::EMPTY)
            .expect("bounds checked above");
    }
    for out in body.outputs.iter().filter(|o| o.valid) {
        let slot = slot_value_from_output(out);
        state
            .set_slot(out.slot_index, slot)
            .expect("bounds checked above");
    }

    Ok(TxStateOpening {
        input_openings,
        output_openings,
    })
}

#[inline]
fn slot_value_from_input(inp: &TxInput) -> SlotValue {
    let [owner_hi, owner_lo] = inp.owner.as_fields();
    SlotValue {
        value: Block128::from(inp.value as u128),
        owner_hi,
        owner_lo,
    }
}

#[inline]
fn slot_value_from_output(out: &TxOutput) -> SlotValue {
    let [owner_hi, owner_lo] = out.owner.as_fields();
    SlotValue {
        value: Block128::from(out.value as u128),
        owner_hi,
        owner_lo,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use noid_poseidon2b::primitives::{Address, AuthTag, SpendSecret};

    fn mk_state() -> SegmentedFriState {
        SegmentedFriState::new_empty(4) // 16 slots for testing
    }

    fn mk_input(slot: u32, value: u64, owner: Address) -> TxInput {
        TxInput {
            slot_index: slot,
            value,
            owner,
            spend_secret: SpendSecret([0x22; 32]),
            auth_tag: AuthTag([0x33; 32]),
            valid: true,
        }
    }

    fn mk_output(slot: u32, value: u64, owner: Address) -> TxOutput {
        TxOutput {
            slot_index: slot,
            value,
            owner,
            valid: true,
        }
    }

    fn seed_slot(state: &mut SegmentedFriState, slot: u32, value: u64, owner: &Address) {
        let [hi, lo] = owner.as_fields();
        state
            .set_slot(
                slot,
                SlotValue {
                    value: Block128::from(value as u128),
                    owner_hi: hi,
                    owner_lo: lo,
                },
            )
            .unwrap();
    }

    #[test]
    fn single_tx_binding_roundtrip() {
        let mut state = mk_state();
        let alice = Address([0x11; 32]);
        let bob = Address([0x44; 32]);

        // Seed: Alice owns slot 3 with value 1000
        seed_slot(&mut state, 3, 1000, &alice);

        let body = TxBody {
            shape: noid_tx::TxShape::Standard4x8,
            epoch_anchor: [0xAA; 32],
            fee: 100,
            inputs: vec![
                mk_input(3, 1000, alice),
                TxInput::dummy(),
                TxInput::dummy(),
                TxInput::dummy(),
            ],
            outputs: vec![
                mk_output(7, 900, bob),
                TxOutput::dummy(),
                TxOutput::dummy(),
                TxOutput::dummy(),
                TxOutput::dummy(),
                TxOutput::dummy(),
                TxOutput::dummy(),
                TxOutput::dummy(),
            ],
            is_coinbase: false,
        };

        let commitment = compute_claims_commitment(&body.inputs, &body.outputs);
        let binding = BlockStateBinding::build(&mut state, &[body], &[commitment]).unwrap();

        assert_eq!(binding.tx_openings.len(), 1);
        assert_eq!(binding.tx_openings[0].input_openings.len(), 1);
        assert_eq!(binding.tx_openings[0].output_openings.len(), 1);

        // After apply: slot 3 is empty, slot 7 has Bob's value
        assert_eq!(state.slot(3), SlotValue::EMPTY);
        let bob_slot = state.slot(7);
        assert_eq!(bob_slot.value, Block128::from(900u128));
    }

    #[test]
    fn multi_tx_binding_roundtrip() {
        let mut state = mk_state();
        let alice = Address([0x11; 32]);
        let bob = Address([0x22; 32]);
        let carol = Address([0x33; 32]);

        seed_slot(&mut state, 1, 500, &alice);
        seed_slot(&mut state, 2, 700, &bob);

        let tx1 = TxBody {
            shape: noid_tx::TxShape::Standard4x8,
            epoch_anchor: [0xAA; 32],
            fee: 0,
            inputs: vec![
                mk_input(1, 500, alice),
                TxInput::dummy(),
                TxInput::dummy(),
                TxInput::dummy(),
            ],
            outputs: vec![
                mk_output(5, 500, carol),
                TxOutput::dummy(),
                TxOutput::dummy(),
                TxOutput::dummy(),
                TxOutput::dummy(),
                TxOutput::dummy(),
                TxOutput::dummy(),
                TxOutput::dummy(),
            ],
            is_coinbase: false,
        };

        let tx2 = TxBody {
            shape: noid_tx::TxShape::Standard4x8,
            epoch_anchor: [0xAA; 32],
            fee: 0,
            inputs: vec![
                mk_input(2, 700, bob),
                TxInput::dummy(),
                TxInput::dummy(),
                TxInput::dummy(),
            ],
            outputs: vec![
                mk_output(6, 700, alice),
                TxOutput::dummy(),
                TxOutput::dummy(),
                TxOutput::dummy(),
                TxOutput::dummy(),
                TxOutput::dummy(),
                TxOutput::dummy(),
                TxOutput::dummy(),
            ],
            is_coinbase: false,
        };

        let c1 = compute_claims_commitment(&tx1.inputs, &tx1.outputs);
        let c2 = compute_claims_commitment(&tx2.inputs, &tx2.outputs);

        let binding = BlockStateBinding::build(&mut state, &[tx1, tx2], &[c1, c2]).unwrap();

        assert_eq!(binding.tx_openings.len(), 2);
        // Slot 1, 2 now empty; 5, 6 filled
        assert_eq!(state.slot(1), SlotValue::EMPTY);
        assert_eq!(state.slot(2), SlotValue::EMPTY);
        assert_ne!(state.slot(5), SlotValue::EMPTY);
        assert_ne!(state.slot(6), SlotValue::EMPTY);
    }

    #[test]
    fn rejects_input_mismatch() {
        let mut state = mk_state();
        let alice = Address([0x11; 32]);

        seed_slot(&mut state, 3, 1000, &alice);

        // Claim wrong value
        let body = TxBody {
            shape: noid_tx::TxShape::Standard4x8,
            epoch_anchor: [0xAA; 32],
            fee: 0,
            inputs: vec![
                mk_input(3, 999, alice), // wrong value
                TxInput::dummy(),
                TxInput::dummy(),
                TxInput::dummy(),
            ],
            outputs: vec![
                TxOutput::dummy(),
                TxOutput::dummy(),
                TxOutput::dummy(),
                TxOutput::dummy(),
                TxOutput::dummy(),
                TxOutput::dummy(),
                TxOutput::dummy(),
                TxOutput::dummy(),
            ],
            is_coinbase: false,
        };

        let commitment = compute_claims_commitment(&body.inputs, &body.outputs);
        let err = BlockStateBinding::build(&mut state, &[body], &[commitment]).unwrap_err();
        assert_eq!(
            err,
            StateBindingError::InputMismatch {
                tx_index: 0,
                input_index: 0
            }
        );
    }

    #[test]
    fn rejects_output_slot_occupied() {
        let mut state = mk_state();
        let alice = Address([0x11; 32]);
        let bob = Address([0x22; 32]);

        // Slot 7 is already occupied
        seed_slot(&mut state, 7, 999, &bob);

        let body = TxBody {
            shape: noid_tx::TxShape::Standard4x8,
            epoch_anchor: [0xAA; 32],
            fee: 0,
            inputs: vec![
                TxInput::dummy(),
                TxInput::dummy(),
                TxInput::dummy(),
                TxInput::dummy(),
            ],
            outputs: vec![
                mk_output(7, 500, alice), // occupied!
                TxOutput::dummy(),
                TxOutput::dummy(),
                TxOutput::dummy(),
                TxOutput::dummy(),
                TxOutput::dummy(),
                TxOutput::dummy(),
                TxOutput::dummy(),
            ],
            is_coinbase: true,
        };

        let commitment = compute_claims_commitment(&body.inputs, &body.outputs);
        let err = BlockStateBinding::build(&mut state, &[body], &[commitment]).unwrap_err();
        assert_eq!(
            err,
            StateBindingError::OutputSlotOccupied {
                tx_index: 0,
                output_index: 0
            }
        );
    }

    #[test]
    fn rejects_claims_commitment_mismatch() {
        let mut state = mk_state();
        let alice = Address([0x11; 32]);

        seed_slot(&mut state, 3, 1000, &alice);

        let body = TxBody {
            shape: noid_tx::TxShape::Standard4x8,
            epoch_anchor: [0xAA; 32],
            fee: 0,
            inputs: vec![
                mk_input(3, 1000, alice),
                TxInput::dummy(),
                TxInput::dummy(),
                TxInput::dummy(),
            ],
            outputs: vec![
                TxOutput::dummy(),
                TxOutput::dummy(),
                TxOutput::dummy(),
                TxOutput::dummy(),
                TxOutput::dummy(),
                TxOutput::dummy(),
                TxOutput::dummy(),
                TxOutput::dummy(),
            ],
            is_coinbase: false,
        };

        // Pass a wrong commitment
        let wrong_commitment = [0xDE; 32];
        let err = BlockStateBinding::build(&mut state, &[body], &[wrong_commitment]).unwrap_err();
        assert_eq!(
            err,
            StateBindingError::ClaimsCommitmentMismatch { tx_index: 0 }
        );
    }

    #[test]
    fn rejects_duplicate_output_slot() {
        let mut state = mk_state();
        let alice = Address([0x11; 32]);

        let body = TxBody {
            shape: noid_tx::TxShape::Standard4x8,
            epoch_anchor: [0xAA; 32],
            fee: 0,
            inputs: vec![
                TxInput::dummy(),
                TxInput::dummy(),
                TxInput::dummy(),
                TxInput::dummy(),
            ],
            outputs: vec![
                mk_output(5, 100, alice),
                mk_output(5, 200, alice), // duplicate!
                TxOutput::dummy(),
                TxOutput::dummy(),
                TxOutput::dummy(),
                TxOutput::dummy(),
                TxOutput::dummy(),
                TxOutput::dummy(),
            ],
            is_coinbase: true,
        };

        let commitment = compute_claims_commitment(&body.inputs, &body.outputs);
        let err = BlockStateBinding::build(&mut state, &[body], &[commitment]).unwrap_err();
        assert_eq!(err, StateBindingError::DuplicateOutputSlot { tx_index: 0 });
    }

    #[test]
    fn sequential_txs_see_intermediate_state() {
        let mut state = mk_state();
        let alice = Address([0x11; 32]);
        let bob = Address([0x22; 32]);

        seed_slot(&mut state, 1, 1000, &alice);

        // Tx1: Alice spends slot 1 into slot 5
        let tx1 = TxBody {
            shape: noid_tx::TxShape::Standard4x8,
            epoch_anchor: [0xAA; 32],
            fee: 0,
            inputs: vec![
                mk_input(1, 1000, alice),
                TxInput::dummy(),
                TxInput::dummy(),
                TxInput::dummy(),
            ],
            outputs: vec![
                mk_output(5, 1000, bob),
                TxOutput::dummy(),
                TxOutput::dummy(),
                TxOutput::dummy(),
                TxOutput::dummy(),
                TxOutput::dummy(),
                TxOutput::dummy(),
                TxOutput::dummy(),
            ],
            is_coinbase: false,
        };

        // Tx2: Bob spends slot 5 (filled by tx1) into slot 9
        let tx2 = TxBody {
            shape: noid_tx::TxShape::Standard4x8,
            epoch_anchor: [0xAA; 32],
            fee: 0,
            inputs: vec![
                mk_input(5, 1000, bob),
                TxInput::dummy(),
                TxInput::dummy(),
                TxInput::dummy(),
            ],
            outputs: vec![
                mk_output(9, 1000, alice),
                TxOutput::dummy(),
                TxOutput::dummy(),
                TxOutput::dummy(),
                TxOutput::dummy(),
                TxOutput::dummy(),
                TxOutput::dummy(),
                TxOutput::dummy(),
            ],
            is_coinbase: false,
        };

        let c1 = compute_claims_commitment(&tx1.inputs, &tx1.outputs);
        let c2 = compute_claims_commitment(&tx2.inputs, &tx2.outputs);

        // This works because tx2 sees the intermediate state after tx1
        let binding = BlockStateBinding::build(&mut state, &[tx1, tx2], &[c1, c2]).unwrap();

        assert_eq!(binding.tx_openings.len(), 2);
        assert_eq!(state.slot(1), SlotValue::EMPTY);
        assert_eq!(state.slot(5), SlotValue::EMPTY);
        assert_ne!(state.slot(9), SlotValue::EMPTY);
    }

    #[test]
    fn verify_final_root_catches_mismatch() {
        let mut state = mk_state();
        let alice = Address([0x11; 32]);

        seed_slot(&mut state, 0, 100, &alice);

        let body = TxBody {
            shape: noid_tx::TxShape::Standard4x8,
            epoch_anchor: [0; 32],
            fee: 0,
            inputs: vec![
                mk_input(0, 100, alice),
                TxInput::dummy(),
                TxInput::dummy(),
                TxInput::dummy(),
            ],
            outputs: vec![
                TxOutput::dummy(),
                TxOutput::dummy(),
                TxOutput::dummy(),
                TxOutput::dummy(),
                TxOutput::dummy(),
                TxOutput::dummy(),
                TxOutput::dummy(),
                TxOutput::dummy(),
            ],
            is_coinbase: false,
        };

        let commitment = compute_claims_commitment(&body.inputs, &body.outputs);
        let binding = BlockStateBinding::build(&mut state, &[body], &[commitment]).unwrap();

        // Correct root passes
        assert!(binding.verify_final_root(&binding.new_state_root).is_ok());

        // Wrong root fails
        let wrong = [0xFF; 32];
        assert_eq!(
            binding.verify_final_root(&wrong),
            Err(StateBindingError::FinalRootMismatch)
        );
    }
}
