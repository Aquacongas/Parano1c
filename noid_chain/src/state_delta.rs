// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Canonical native model for the exact block state-transition surface.
//!
//! This module formalizes the ordered touched-slot relation used to build the
//! exact authenticated state transition proof:
//!
//! ```text
//! read(slot, tx_index) = latest previous write in the block prefix, if any
//!                    else pre_state(slot)
//!
//! spend: require read(slot) == claimed input; write(slot) = EMPTY
//! mint:  require read(slot) == EMPTY;         write(slot) = claimed output
//! ```
//!
//! Because transactions are processed in block order, outputs of earlier
//! transactions are spendable by later transactions, while future/cyclic
//! dependencies are rejected by prefix reads.  The returned witness is a compact
//! ordered delta surface: roots + touched-slot actions, not full pre/post segment
//! columns.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use noid_poseidon2b::primitives::Digest;
use noid_tx::{compute_claims_commitment, TxBody, TxInput, TxOutput};

use crate::fri_state::{SlotValue, StateRoot};
use crate::segmented_state::SegmentedFriState;

/// Direction of one touched-slot update in the ordered state-delta surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateDeltaActionKind {
    /// A valid input consumes an existing UTXO: `pre != EMPTY`, `post = EMPTY`.
    Spend,
    /// A valid output creates a UTXO in an empty slot: `pre = EMPTY`, `post != EMPTY`.
    Mint,
}

/// One ordered touched-slot transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StateDeltaAction {
    /// Transaction index in the block-order body slice.
    pub tx_index: u32,
    /// Input/output index inside the transaction body.
    pub op_index: u8,
    /// Global state slot index.
    pub slot_index: u32,
    /// Prefix-read value before this action.
    pub pre: SlotValue,
    /// Value written by this action.
    pub post: SlotValue,
    pub kind: StateDeltaActionKind,
}

/// Ordered touched-slot action surface without root recomputation.
///
/// This is the canonical lightweight surface used by proof adapters.  It checks
/// the same prefix-overlay semantics as [`StateDeltaWitness`] but does not
/// mutate state and does not compute the post root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateDeltaActionSurface {
    /// Ordered touched-slot updates: inputs first, then outputs for each tx.
    pub actions: Vec<StateDeltaAction>,
    /// Number of spend actions. Future header-counter checks can derive
    /// `active_slot_count' = active_slot_count - spends + mints` from these.
    pub spends: u32,
    /// Number of mint actions. Future header-counter checks can derive
    /// `alloc_counter' = alloc_counter + mints` from this.
    pub mints: u32,
}

impl StateDeltaActionSurface {
    /// Net change in live UTXO count induced by this delta.
    #[inline]
    pub fn active_slot_delta(&self) -> i64 {
        self.mints as i64 - self.spends as i64
    }
}

/// Canonical exact-state action surface derived from the ordered prefix overlay.
///
/// `touched_indices`, `old_slots` and `new_slots` are index-aligned and sorted
/// by slot index. `actions` remains in canonical tx/op order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExactActionSurface {
    pub actions: Vec<StateDeltaAction>,
    pub touched_indices: Vec<u32>,
    pub old_slots: Vec<SlotValue>,
    pub new_slots: Vec<SlotValue>,
    pub spent_slots: Vec<u32>,
    pub spends: u32,
    pub mints: u32,
}

/// Native state-delta witness for a block body sequence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateDeltaWitness {
    /// Root before applying any action in this witness.
    pub prev_state_root: StateRoot,
    /// Root after applying all actions in order.
    pub post_state_root: StateRoot,
    /// Ordered touched-slot updates: inputs first, then outputs for each tx.
    pub actions: Vec<StateDeltaAction>,
    /// Number of spend actions. Future header-counter checks can derive
    /// `active_slot_count' = active_slot_count - spends + mints` from these.
    pub spends: u32,
    /// Number of mint actions. Future header-counter checks can derive
    /// `alloc_counter' = alloc_counter + mints` from this.
    pub mints: u32,
}

impl StateDeltaWitness {
    /// Net change in live UTXO count induced by this delta.
    #[inline]
    pub fn active_slot_delta(&self) -> i64 {
        self.mints as i64 - self.spends as i64
    }
}

/// Errors during native state-delta witness construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateDeltaError {
    /// A valid input slot does not match the tx body's claimed `(value, owner)`.
    InputMismatch { tx_index: usize, input_index: usize },
    /// A valid output slot is not empty in the prefix state.
    OutputSlotOccupied {
        tx_index: usize,
        output_index: usize,
    },
    /// The tx body's slot claims do not match the expected public commitment.
    ClaimsCommitmentMismatch { tx_index: usize },
    /// One tx tries to spend the same slot more than once.
    DuplicateInputSlot { tx_index: usize },
    /// One tx tries to mint two outputs into the same slot.
    DuplicateOutputSlot { tx_index: usize },
    /// One tx tries to spend and mint the same slot in the same body.
    InputOutputSlotOverlap { tx_index: usize },
    /// A valid input/output references a slot outside the current state domain.
    SlotOutOfRange { tx_index: usize },
    /// Assigning the next live output's creation ID would overflow the
    /// consensus allocation counter.
    AllocationCounterOverflow {
        tx_index: usize,
        output_index: usize,
    },
    /// The compact action counters cannot represent the supplied body list.
    ActionCountOverflow,
}

/// Build the canonical ordered state-delta action surface without mutating state
/// or recomputing roots.
///
/// This is the cheap verifier/proof-adapter view. It enforces the same
/// prefix-overlay relation as [`build_state_delta_witness`]: earlier writes in
/// the block are visible to later transactions, future writes are not, and
/// inputs are processed before outputs inside one transaction.
pub fn build_state_delta_action_surface(
    state: &SegmentedFriState,
    bodies: &[TxBody],
    expected_commitments: &[Digest],
    parent_alloc_counter: u64,
) -> Result<StateDeltaActionSurface, StateDeltaError> {
    assert_eq!(
        bodies.len(),
        expected_commitments.len(),
        "one claims commitment per tx body required"
    );

    let n_slots = state.num_slots();
    let mut overlay: HashMap<u32, SlotValue> = HashMap::new();
    let mut actions = Vec::new();
    let mut spends = 0u32;
    let mut mints = 0u32;
    let mut alloc_counter = parent_alloc_counter;

    for (tx_idx, body) in bodies.iter().enumerate() {
        check_tx_slot_shape(body, tx_idx)?;

        let recomputed = compute_claims_commitment(&body.inputs, &body.outputs);
        if recomputed != expected_commitments[tx_idx] {
            return Err(StateDeltaError::ClaimsCommitmentMismatch { tx_index: tx_idx });
        }

        for (i, input) in body.inputs.iter().enumerate() {
            if !input.valid {
                continue;
            }
            if (input.slot_index as u64) >= n_slots {
                return Err(StateDeltaError::SlotOutOfRange { tx_index: tx_idx });
            }

            let pre = overlay
                .get(&input.slot_index)
                .copied()
                .unwrap_or_else(|| state.slot(input.slot_index));
            let post = SlotValue::EMPTY;
            if pre != slot_value_from_input(input) {
                return Err(StateDeltaError::InputMismatch {
                    tx_index: tx_idx,
                    input_index: i,
                });
            }

            actions.push(StateDeltaAction {
                tx_index: tx_idx as u32,
                op_index: i as u8,
                slot_index: input.slot_index,
                pre,
                post,
                kind: StateDeltaActionKind::Spend,
            });
            overlay.insert(input.slot_index, post);
            spends = spends
                .checked_add(1)
                .ok_or(StateDeltaError::ActionCountOverflow)?;
        }

        for (j, output) in body.outputs.iter().enumerate() {
            if !output.valid {
                continue;
            }
            if (output.slot_index as u64) >= n_slots {
                return Err(StateDeltaError::SlotOutOfRange { tx_index: tx_idx });
            }

            let pre = overlay
                .get(&output.slot_index)
                .copied()
                .unwrap_or_else(|| state.slot(output.slot_index));
            if pre != SlotValue::EMPTY {
                return Err(StateDeltaError::OutputSlotOccupied {
                    tx_index: tx_idx,
                    output_index: j,
                });
            }
            let creation_id =
                alloc_counter
                    .checked_add(1)
                    .ok_or(StateDeltaError::AllocationCounterOverflow {
                        tx_index: tx_idx,
                        output_index: j,
                    })?;
            let post = slot_value_from_output(output, creation_id);

            actions.push(StateDeltaAction {
                tx_index: tx_idx as u32,
                op_index: j as u8,
                slot_index: output.slot_index,
                pre,
                post,
                kind: StateDeltaActionKind::Mint,
            });
            overlay.insert(output.slot_index, post);
            mints = mints
                .checked_add(1)
                .ok_or(StateDeltaError::ActionCountOverflow)?;
            alloc_counter = creation_id;
        }
    }

    Ok(StateDeltaActionSurface {
        actions,
        spends,
        mints,
    })
}

/// Build the exact-state surface that a Merkle frontier verifier consumes.
pub fn build_exact_action_surface(
    state: &SegmentedFriState,
    bodies: &[TxBody],
    expected_commitments: &[Digest],
    parent_alloc_counter: u64,
) -> Result<ExactActionSurface, StateDeltaError> {
    let surface = build_state_delta_action_surface(
        state,
        bodies,
        expected_commitments,
        parent_alloc_counter,
    )?;
    Ok(exact_action_surface_from_surface(surface))
}

/// Convert the ordered action surface into sorted old/new leaves and spend set.
pub fn exact_action_surface_from_surface(surface: StateDeltaActionSurface) -> ExactActionSurface {
    let mut touched: BTreeMap<u32, (SlotValue, SlotValue)> = BTreeMap::new();
    let mut spent = BTreeSet::new();

    for action in &surface.actions {
        touched
            .entry(action.slot_index)
            .and_modify(|(_, new_slot)| *new_slot = action.post)
            .or_insert((action.pre, action.post));
        if action.kind == StateDeltaActionKind::Spend {
            spent.insert(action.slot_index);
        }
    }

    let mut touched_indices = Vec::with_capacity(touched.len());
    let mut old_slots = Vec::with_capacity(touched.len());
    let mut new_slots = Vec::with_capacity(touched.len());
    for (idx, (old, new)) in touched {
        touched_indices.push(idx);
        old_slots.push(old);
        new_slots.push(new);
    }

    ExactActionSurface {
        actions: surface.actions,
        touched_indices,
        old_slots,
        new_slots,
        spent_slots: spent.into_iter().collect(),
        spends: surface.spends,
        mints: surface.mints,
    }
}

/// Build a compact ordered state-delta witness and apply it to `state` on success.
///
/// On `Err`, the input state is left untouched. This mirrors the atomic behavior
/// required from consensus validation and gives the proof system a single
/// canonical native relation.
pub fn build_state_delta_witness(
    state: &mut SegmentedFriState,
    bodies: &[TxBody],
    expected_commitments: &[Digest],
    parent_alloc_counter: u64,
) -> Result<StateDeltaWitness, StateDeltaError> {
    let mut snap = state.clone();
    let prev_state_root = snap.root();
    let surface = build_state_delta_action_surface(
        &snap,
        bodies,
        expected_commitments,
        parent_alloc_counter,
    )?;

    let deltas: Vec<_> = surface
        .actions
        .iter()
        .map(|action| (action.slot_index, action.post))
        .collect();
    snap.apply_delta(&deltas)
        .expect("state-delta action surface bounds checked every slot");
    let post_state_root = snap.root();
    *state = snap;

    Ok(StateDeltaWitness {
        prev_state_root,
        post_state_root,
        actions: surface.actions,
        spends: surface.spends,
        mints: surface.mints,
    })
}

fn check_tx_slot_shape(body: &TxBody, tx_idx: usize) -> Result<(), StateDeltaError> {
    let mut seen_inputs = HashSet::new();
    let mut seen_outputs = HashSet::new();

    for input in body.inputs.iter().filter(|input| input.valid) {
        if !seen_inputs.insert(input.slot_index) {
            return Err(StateDeltaError::DuplicateInputSlot { tx_index: tx_idx });
        }
    }

    for output in body.outputs.iter().filter(|output| output.valid) {
        if !seen_outputs.insert(output.slot_index) {
            return Err(StateDeltaError::DuplicateOutputSlot { tx_index: tx_idx });
        }
        if seen_inputs.contains(&output.slot_index) {
            return Err(StateDeltaError::InputOutputSlotOverlap { tx_index: tx_idx });
        }
    }

    Ok(())
}

#[inline]
fn slot_value_from_input(input: &TxInput) -> SlotValue {
    SlotValue::with_owner_fields(input.value, input.creation_id, input.owner.as_fields())
}

#[inline]
fn slot_value_from_output(output: &TxOutput, creation_id: u64) -> SlotValue {
    SlotValue::with_owner_fields(output.value, creation_id, output.owner.as_fields())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{apply_tx, ChainState};
    use noid_poseidon2b::primitives::{Address, SpendSecret};
    use noid_tx::TxShape;

    const TEST_LOG_SLOTS: usize = 6;

    fn fresh_segmented() -> SegmentedFriState {
        SegmentedFriState::new_empty(TEST_LOG_SLOTS)
    }

    fn owner(seed: u8) -> Address {
        Address([seed; 32])
    }

    fn mk_input(slot: u32, value: u64, owner: Address) -> TxInput {
        mk_input_with_id(slot, value, 0, owner)
    }

    fn mk_input_with_id(slot: u32, value: u64, creation_id: u64, owner: Address) -> TxInput {
        TxInput {
            slot_index: slot,
            value,
            creation_id,
            owner,
            spend_secret: SpendSecret([0xA0; 32]),
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

    fn body(inputs: Vec<TxInput>, outputs: Vec<TxOutput>) -> TxBody {
        TxBody {
            shape: TxShape::Standard4x8,
            epoch_anchor: [1u8; 32],
            fee: 0,
            inputs,
            outputs,
            is_coinbase: false,
        }
    }

    fn commitments(bodies: &[TxBody]) -> Vec<Digest> {
        bodies
            .iter()
            .map(|body| compute_claims_commitment(&body.inputs, &body.outputs))
            .collect()
    }

    fn seed_slot(state: &mut SegmentedFriState, slot: u32, value: u64, owner: Address) {
        state
            .set_slot(
                slot,
                slot_value_from_output(&mk_output(slot, value, owner), 0),
            )
            .unwrap();
    }

    #[test]
    fn accepts_independent_txs_and_records_ordered_actions() {
        let mut state = fresh_segmented();
        let alice = owner(0x11);
        let bob = owner(0x22);
        let carol = owner(0x33);
        let dave = owner(0x44);
        seed_slot(&mut state, 1, 500, alice);
        seed_slot(&mut state, 2, 700, bob);

        let tx0 = body(
            vec![mk_input(1, 500, alice)],
            vec![mk_output(5, 450, carol)],
        );
        let tx1 = body(vec![mk_input(2, 700, bob)], vec![mk_output(6, 650, dave)]);
        let bodies = vec![tx0, tx1];
        let cs = commitments(&bodies);

        let witness = build_state_delta_witness(&mut state, &bodies, &cs, 0).unwrap();

        assert_eq!(witness.spends, 2);
        assert_eq!(witness.mints, 2);
        assert_eq!(witness.active_slot_delta(), 0);
        assert_eq!(witness.actions.len(), 4);
        assert_eq!(witness.actions[0].kind, StateDeltaActionKind::Spend);
        assert_eq!(witness.actions[0].tx_index, 0);
        assert_eq!(witness.actions[0].slot_index, 1);
        assert_eq!(witness.actions[1].kind, StateDeltaActionKind::Mint);
        assert_eq!(witness.actions[1].tx_index, 0);
        assert_eq!(witness.actions[1].slot_index, 5);
        assert_eq!(witness.actions[2].kind, StateDeltaActionKind::Spend);
        assert_eq!(witness.actions[2].tx_index, 1);
        assert_eq!(witness.actions[3].kind, StateDeltaActionKind::Mint);
        assert_eq!(witness.actions[3].tx_index, 1);
        assert_eq!(state.slot(1), SlotValue::EMPTY);
        assert_eq!(state.slot(2), SlotValue::EMPTY);
        assert_eq!(
            state.slot(5),
            slot_value_from_output(&mk_output(5, 450, carol), 1)
        );
        assert_eq!(
            state.slot(6),
            slot_value_from_output(&mk_output(6, 650, dave), 2)
        );
        assert_eq!(witness.post_state_root, state.root());
    }

    #[test]
    fn accepts_spending_output_from_earlier_tx() {
        let mut state = fresh_segmented();
        let alice = owner(0x11);
        let bob = owner(0x22);

        let tx0 = body(vec![], vec![mk_output(10, 123, alice)]);
        let tx1 = body(
            vec![mk_input_with_id(10, 123, 1, alice)],
            vec![mk_output(11, 100, bob)],
        );
        let bodies = vec![tx0, tx1];
        let cs = commitments(&bodies);

        let witness = build_state_delta_witness(&mut state, &bodies, &cs, 0).unwrap();

        assert_eq!(witness.spends, 1);
        assert_eq!(witness.mints, 2);
        assert_eq!(witness.active_slot_delta(), 1);
        assert_eq!(state.slot(10), SlotValue::EMPTY);
        assert_eq!(
            state.slot(11),
            slot_value_from_output(&mk_output(11, 100, bob), 2)
        );
    }

    #[test]
    fn parent_counter_assigns_canonical_output_prefix_ids() {
        let state = fresh_segmented();
        let alice = owner(0x11);
        let bob = owner(0x22);
        let bodies = vec![
            body(vec![], vec![mk_output(10, 123, alice)]),
            body(vec![], vec![mk_output(11, 456, bob)]),
        ];
        let cs = commitments(&bodies);

        let surface = build_state_delta_action_surface(&state, &bodies, &cs, 41).unwrap();
        assert_eq!(surface.actions[0].post.creation_id(), 42);
        assert_eq!(surface.actions[1].post.creation_id(), 43);
    }

    #[test]
    fn allocation_counter_overflow_rejects_before_mutation() {
        let mut state = fresh_segmented();
        let body = body(vec![], vec![mk_output(10, 123, owner(0x11))]);
        let cs = commitments(std::slice::from_ref(&body));
        let before = state.root();

        assert_eq!(
            build_state_delta_witness(&mut state, &[body], &cs, u64::MAX),
            Err(StateDeltaError::AllocationCounterOverflow {
                tx_index: 0,
                output_index: 0,
            })
        );
        assert_eq!(state.root(), before);
    }

    #[test]
    fn rejects_future_dependency() {
        let mut state = fresh_segmented();
        let alice = owner(0x11);
        let bob = owner(0x22);

        let tx0 = body(
            vec![mk_input(10, 123, alice)],
            vec![mk_output(11, 100, bob)],
        );
        let tx1 = body(vec![], vec![mk_output(10, 123, alice)]);
        let bodies = vec![tx0, tx1];
        let cs = commitments(&bodies);
        let before = state.root();

        let err = build_state_delta_witness(&mut state, &bodies, &cs, 0).unwrap_err();

        assert_eq!(
            err,
            StateDeltaError::InputMismatch {
                tx_index: 0,
                input_index: 0,
            }
        );
        assert_eq!(state.root(), before, "state must remain unchanged on error");
    }

    #[test]
    fn rejects_cyclic_dependency_by_prefix_read() {
        let mut state = fresh_segmented();
        let alice = owner(0x11);
        let bob = owner(0x22);

        let tx0 = body(vec![mk_input(20, 1, alice)], vec![mk_output(21, 1, bob)]);
        let tx1 = body(vec![mk_input(21, 1, bob)], vec![mk_output(20, 1, alice)]);
        let bodies = vec![tx0, tx1];
        let cs = commitments(&bodies);

        let err = build_state_delta_witness(&mut state, &bodies, &cs, 0).unwrap_err();

        assert_eq!(
            err,
            StateDeltaError::InputMismatch {
                tx_index: 0,
                input_index: 0,
            }
        );
    }

    #[test]
    fn rejects_duplicate_input_in_same_tx() {
        let mut state = fresh_segmented();
        let alice = owner(0x11);
        seed_slot(&mut state, 3, 100, alice);

        let tx = body(
            vec![mk_input(3, 100, alice), mk_input(3, 100, alice)],
            vec![],
        );
        let bodies = vec![tx];
        let cs = commitments(&bodies);

        let err = build_state_delta_witness(&mut state, &bodies, &cs, 0).unwrap_err();

        assert_eq!(err, StateDeltaError::DuplicateInputSlot { tx_index: 0 });
    }

    #[test]
    fn rejects_duplicate_output_in_same_tx() {
        let mut state = fresh_segmented();
        let alice = owner(0x11);

        let tx = body(
            vec![],
            vec![mk_output(4, 100, alice), mk_output(4, 200, alice)],
        );
        let bodies = vec![tx];
        let cs = commitments(&bodies);

        let err = build_state_delta_witness(&mut state, &bodies, &cs, 0).unwrap_err();

        assert_eq!(err, StateDeltaError::DuplicateOutputSlot { tx_index: 0 });
    }

    #[test]
    fn rejects_input_output_overlap_in_same_tx() {
        let mut state = fresh_segmented();
        let alice = owner(0x11);
        seed_slot(&mut state, 7, 100, alice);

        let tx = body(
            vec![mk_input(7, 100, alice)],
            vec![mk_output(7, 90, owner(0x22))],
        );
        let bodies = vec![tx];
        let cs = commitments(&bodies);

        let err = build_state_delta_witness(&mut state, &bodies, &cs, 0).unwrap_err();

        assert_eq!(err, StateDeltaError::InputOutputSlotOverlap { tx_index: 0 });
    }

    #[test]
    fn rejects_input_mismatch() {
        let mut state = fresh_segmented();
        let alice = owner(0x11);
        seed_slot(&mut state, 3, 100, alice);

        let tx = body(vec![mk_input(3, 101, alice)], vec![]);
        let bodies = vec![tx];
        let cs = commitments(&bodies);

        let err = build_state_delta_witness(&mut state, &bodies, &cs, 0).unwrap_err();

        assert_eq!(
            err,
            StateDeltaError::InputMismatch {
                tx_index: 0,
                input_index: 0,
            }
        );
    }

    #[test]
    fn rejects_output_occupied() {
        let mut state = fresh_segmented();
        let alice = owner(0x11);
        seed_slot(&mut state, 5, 100, alice);

        let tx = body(vec![], vec![mk_output(5, 200, owner(0x22))]);
        let bodies = vec![tx];
        let cs = commitments(&bodies);

        let err = build_state_delta_witness(&mut state, &bodies, &cs, 0).unwrap_err();

        assert_eq!(
            err,
            StateDeltaError::OutputSlotOccupied {
                tx_index: 0,
                output_index: 0,
            }
        );
    }

    #[test]
    fn rejects_claims_commitment_mismatch() {
        let mut state = fresh_segmented();
        let tx = body(vec![], vec![mk_output(5, 200, owner(0x22))]);
        let mut cs = commitments(std::slice::from_ref(&tx));
        cs[0][0] ^= 1;

        let err = build_state_delta_witness(&mut state, &[tx], &cs, 0).unwrap_err();

        assert_eq!(
            err,
            StateDeltaError::ClaimsCommitmentMismatch { tx_index: 0 }
        );
    }

    #[test]
    fn action_surface_matches_witness_and_does_not_mutate_state() {
        let alice = owner(0x11);
        let bob = owner(0x22);
        let carol = owner(0x33);

        let mut segmented = fresh_segmented();
        seed_slot(&mut segmented, 1, 500, alice);

        let tx0 = body(vec![mk_input(1, 500, alice)], vec![mk_output(5, 450, bob)]);
        let tx1 = body(
            vec![mk_input_with_id(5, 450, 1, bob)],
            vec![mk_output(6, 400, carol)],
        );
        let bodies = vec![tx0, tx1];
        let cs = commitments(&bodies);

        let mut state_for_root = segmented.clone();
        let before_root = state_for_root.root();
        let surface = build_state_delta_action_surface(&segmented, &bodies, &cs, 0).unwrap();
        let mut state_after_surface = segmented.clone();
        assert_eq!(state_after_surface.root(), before_root);

        let mut witness_state = segmented;
        let witness = build_state_delta_witness(&mut witness_state, &bodies, &cs, 0).unwrap();

        assert_eq!(surface.actions, witness.actions);
        assert_eq!(surface.spends, witness.spends);
        assert_eq!(surface.mints, witness.mints);
        assert_eq!(surface.active_slot_delta(), witness.active_slot_delta());
    }

    #[test]
    fn exact_surface_derives_sorted_old_new_and_spent_slots() {
        let alice = owner(0x11);
        let bob = owner(0x22);
        let carol = owner(0x33);

        let mut segmented = fresh_segmented();
        seed_slot(&mut segmented, 1, 500, alice);

        let tx0 = body(vec![mk_input(1, 500, alice)], vec![mk_output(5, 450, bob)]);
        let tx1 = body(
            vec![mk_input_with_id(5, 450, 1, bob)],
            vec![mk_output(6, 400, carol)],
        );
        let bodies = vec![tx0, tx1];
        let cs = commitments(&bodies);

        let exact = build_exact_action_surface(&segmented, &bodies, &cs, 0).unwrap();

        assert_eq!(exact.touched_indices, vec![1, 5, 6]);
        assert_eq!(
            exact.old_slots[0],
            slot_value_from_output(&mk_output(1, 500, alice), 0)
        );
        assert_eq!(exact.new_slots[0], SlotValue::EMPTY);
        assert_eq!(exact.old_slots[1], SlotValue::EMPTY);
        assert_eq!(exact.new_slots[1], SlotValue::EMPTY);
        assert_eq!(exact.old_slots[2], SlotValue::EMPTY);
        assert_eq!(
            exact.new_slots[2],
            slot_value_from_output(&mk_output(6, 400, carol), 2)
        );
        assert_eq!(exact.spent_slots, vec![1, 5]);
        assert_eq!(exact.spends, 2);
        assert_eq!(exact.mints, 2);
    }

    #[test]
    fn exact_surface_keeps_transient_empty_mint_spend_empty_slot() {
        let alice = owner(0x11);

        let segmented = fresh_segmented();
        let tx0 = body(vec![], vec![mk_output(10, 123, alice)]);
        let tx1 = body(vec![mk_input_with_id(10, 123, 1, alice)], vec![]);
        let bodies = vec![tx0, tx1];
        let cs = commitments(&bodies);

        let exact = build_exact_action_surface(&segmented, &bodies, &cs, 0).unwrap();

        assert_eq!(exact.spends, 1);
        assert_eq!(exact.mints, 1);
        assert_eq!(exact.touched_indices, vec![10]);
        assert_eq!(exact.old_slots, vec![SlotValue::EMPTY]);
        assert_eq!(exact.new_slots, vec![SlotValue::EMPTY]);
        assert_eq!(exact.spent_slots, vec![10]);
        assert_eq!(exact.actions.len(), 2);
        assert_eq!(exact.actions[0].kind, StateDeltaActionKind::Mint);
        assert_eq!(exact.actions[0].tx_index, 0);
        assert_eq!(exact.actions[0].slot_index, 10);
        assert_eq!(exact.actions[0].pre, SlotValue::EMPTY);
        assert_eq!(
            exact.actions[0].post,
            slot_value_from_output(&mk_output(10, 123, alice), 1)
        );
        assert_eq!(exact.actions[1].kind, StateDeltaActionKind::Spend);
        assert_eq!(exact.actions[1].tx_index, 1);
        assert_eq!(exact.actions[1].slot_index, 10);
        assert_eq!(exact.actions[1].pre, exact.actions[0].post);
        assert_eq!(exact.actions[1].post, SlotValue::EMPTY);
    }

    #[test]
    fn final_root_matches_apply_tx_sequence() {
        let alice = owner(0x11);
        let bob = owner(0x22);
        let carol = owner(0x33);

        let mut segmented = fresh_segmented();
        seed_slot(&mut segmented, 1, 500, alice);
        seed_slot(&mut segmented, 2, 700, bob);

        let tx0 = body(
            vec![mk_input(1, 500, alice)],
            vec![mk_output(5, 450, carol)],
        );
        let tx1 = body(vec![mk_input(2, 700, bob)], vec![mk_output(1, 650, alice)]);
        let bodies = vec![tx0, tx1];
        let cs = commitments(&bodies);

        let mut delta_state = segmented.clone();
        let delta = build_state_delta_witness(&mut delta_state, &bodies, &cs, 0).unwrap();

        let mut chain = ChainState::with_log_slots(TEST_LOG_SLOTS);
        chain.state = segmented;
        chain.active_slot_count = 2;
        for body in &bodies {
            apply_tx(&mut chain, body).unwrap();
        }
        assert_eq!(delta.post_state_root, chain.state.root());
        assert_ne!(delta.post_state_root, chain.state_root());
    }
}
