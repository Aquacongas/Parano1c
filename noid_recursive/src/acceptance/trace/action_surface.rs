// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Hash-bound transaction selectors shared by the C' semantic relation.
//!
//! The standard tx-body spine already exposes the reserved validity leaf and
//! every input/output quad as statement wires. This module makes that leaf the
//! only in-trace liveness source, enforces the canonical zero form of dead
//! entries, and binds every live input owner to the one-owner authorization
//! address. Ordered actions and the exact-state overlay build on these wires in
//! the next C' slice.

use super::tx_body_spine::SpineInputsTrace;
use super::{mul, pin_eq, pin_zero, range_check_bits, FieldR1csBuilder, LinExpr, F128};

pub const STANDARD_INPUT_SELECTORS: usize = noid_poseidon2b::primitives::TXBODY_INPUTS;
pub const STANDARD_OUTPUT_SELECTORS: usize = noid_poseidon2b::primitives::TXBODY_OUTPUTS;
pub const STANDARD_VALIDITY_BITS: usize = STANDARD_INPUT_SELECTORS + STANDARD_OUTPUT_SELECTORS;

/// Selector surface of one Standard4x8 body.
///
/// `raw_*` are committed by `pad_leaf`; `selected_* = tx_live * raw_*`
/// additionally gate tier-padding ghost transactions out of block resource
/// totals without changing their canonical ghost body or authorization proof.
pub struct ActionSurfaceTrace {
    pub raw_inputs: [LinExpr; STANDARD_INPUT_SELECTORS],
    pub raw_outputs: [LinExpr; STANDARD_OUTPUT_SELECTORS],
    pub selected_inputs: [LinExpr; STANDARD_INPUT_SELECTORS],
    pub selected_outputs: [LinExpr; STANDARD_OUTPUT_SELECTORS],
}

/// Bind a Standard4x8 user body's validity bitmap, canonical dead entries,
/// and mandatory one-owner address to already allocated spine statement
/// wires. Coinbase has different semantic obligations and deliberately gets
/// no permissive `Option<owner>` entry point here.
pub fn bind_standard_user_action_surface(
    b: &mut FieldR1csBuilder,
    spine: &SpineInputsTrace,
    tx_live: &LinExpr,
    expected_owner: &[LinExpr; 2],
) -> ActionSurfaceTrace {
    assert_eq!(spine.input_leaves.len(), STANDARD_INPUT_SELECTORS);
    assert_eq!(spine.output_leaves.len(), STANDARD_OUTPUT_SELECTORS);

    // Capacity builds already constrain their shared liveness wires. Keeping
    // this local booleanity also makes the component sound in isolation.
    let tx_live_sq = mul(b, tx_live, tx_live);
    pin_eq(b, &tx_live_sq, tx_live);

    // The first validity-leaf lane contains exactly 12 little-endian bits;
    // range_check_bits also forces every higher tower bit to zero. The second
    // lane is the canonical all-zero half of validity_leaf().
    let bits = range_check_bits(b, &spine.pad_leaf[0], STANDARD_VALIDITY_BITS);
    pin_zero(b, &spine.pad_leaf[1]);
    let raw: [LinExpr; STANDARD_VALIDITY_BITS] =
        std::array::from_fn(|i| LinExpr::from_wire(bits[i]));
    let raw_inputs: [LinExpr; STANDARD_INPUT_SELECTORS] = std::array::from_fn(|i| raw[i].clone());
    let raw_outputs: [LinExpr; STANDARD_OUTPUT_SELECTORS] =
        std::array::from_fn(|i| raw[STANDARD_INPUT_SELECTORS + i].clone());

    let bind_dead_quad = |b: &mut FieldR1csBuilder, live: &LinExpr, quad: &[LinExpr; 4]| {
        // Characteristic two: 1 + live is the boolean NOT of live.
        let dead = live.add_const(F128::ONE);
        for lane in quad {
            let dead_lane = mul(b, &dead, lane);
            pin_zero(b, &dead_lane);
        }
    };

    for (live, quad) in raw_inputs.iter().zip(&spine.input_leaves) {
        bind_dead_quad(b, live, quad);
        // Input quad = [slot_index, packed(amount, creation_id),
        // owner_hi, owner_lo]. Equality is required exactly when the
        // body-committed input selector is one.
        for lane in 0..2 {
            let owner_delta = quad[2 + lane].add(&expected_owner[lane]);
            let gated_delta = mul(b, live, &owner_delta);
            pin_zero(b, &gated_delta);
        }
    }
    for (live, quad) in raw_outputs.iter().zip(&spine.output_leaves) {
        bind_dead_quad(b, live, quad);
    }

    let selected_inputs = std::array::from_fn(|i| mul(b, tx_live, &raw_inputs[i]));
    let selected_outputs = std::array::from_fn(|i| mul(b, tx_live, &raw_outputs[i]));

    ActionSurfaceTrace {
        raw_inputs,
        raw_outputs,
        selected_inputs,
        selected_outputs,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acceptance::trace::tx_body_spine::SpineInputsTrace;
    use crate::acceptance::trace::{alloc_block, const_block};
    use noid_core::{Block128, TowerField};
    use noid_gkr::{spine_statement::spine_inputs_from_body, SpineInputs};
    use noid_poseidon2b::primitives::{Address, SpendSecret};
    use noid_tx::{TxBody, TxInput, TxOutput, TxShape};

    fn body(owner: Address) -> TxBody {
        TxBody {
            shape: TxShape::Standard4x8,
            epoch_anchor: [0x42; 32],
            fee: 1,
            inputs: vec![TxInput {
                slot_index: 7,
                value: 20,
                creation_id: 3,
                owner,
                spend_secret: SpendSecret([0x11; 32]),
                valid: true,
            }],
            outputs: vec![TxOutput {
                slot_index: 9,
                value: 19,
                owner: Address([0x77; 32]),
                valid: true,
            }],
            is_coinbase: false,
        }
    }

    fn relation_satisfies(
        native: &SpineInputs,
        expected_owner: [Block128; 2],
        tx_live: Block128,
    ) -> bool {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut b = FieldR1csBuilder::new();
            let spine = SpineInputsTrace::alloc(&mut b, native);
            let expected = std::array::from_fn(|i| alloc_block(&mut b, expected_owner[i]));
            let tx_live = alloc_block(&mut b, tx_live);
            let _ = bind_standard_user_action_surface(&mut b, &spine, &tx_live, &expected);
            let (r1cs, z) = b.build();
            r1cs.satisfies(&z)
        }))
        .unwrap_or(false)
    }

    #[test]
    fn bitmap_drives_selectors_and_one_owner_pin() {
        let owner = Address([0x33; 32]);
        let native = spine_inputs_from_body(&body(owner)).unwrap();
        let mut b = FieldR1csBuilder::new();
        let spine = SpineInputsTrace::alloc(&mut b, &native);
        let owner_fields = owner.as_fields();
        let expected = std::array::from_fn(|i| alloc_block(&mut b, owner_fields[i]));
        let surface = bind_standard_user_action_surface(
            &mut b,
            &spine,
            &const_block(Block128::ONE),
            &expected,
        );
        let (r1cs, z) = b.build();
        assert!(r1cs.satisfies(&z));
        assert_eq!(surface.raw_inputs[0].eval(&z), F128::ONE);
        assert_eq!(surface.raw_outputs[0].eval(&z), F128::ONE);
        assert!(surface.raw_inputs[1..]
            .iter()
            .all(|selector| selector.eval(&z) == F128::ZERO));
    }

    #[test]
    fn owner_recombination_is_unsatisfied() {
        let native = spine_inputs_from_body(&body(Address([0x33; 32]))).unwrap();
        let wrong_owner = Address([0x44; 32]).as_fields();
        assert!(!relation_satisfies(&native, wrong_owner, Block128::ONE));
    }

    #[test]
    fn outer_inactive_gates_counts() {
        let owner = Address([0x33; 32]);
        let native = spine_inputs_from_body(&body(owner)).unwrap();
        let owner_fields = owner.as_fields();
        let mut b = FieldR1csBuilder::new();
        let spine = SpineInputsTrace::alloc(&mut b, &native);
        let expected = std::array::from_fn(|i| alloc_block(&mut b, owner_fields[i]));
        let surface = bind_standard_user_action_surface(
            &mut b,
            &spine,
            &const_block(Block128::ZERO),
            &expected,
        );
        let (r1cs, z) = b.build();
        assert!(r1cs.satisfies(&z));
        assert!(surface
            .selected_inputs
            .iter()
            .chain(&surface.selected_outputs)
            .all(|selector| selector.eval(&z) == F128::ZERO));
    }

    #[test]
    fn dead_nonzero_quad_is_rejected() {
        let owner = Address([0x33; 32]);
        let mut native = spine_inputs_from_body(&body(owner)).unwrap();
        native.input_leaves[1][1] = Block128::ONE;
        let owner_fields = owner.as_fields();
        assert!(!relation_satisfies(&native, owner_fields, Block128::ONE));
    }

    #[test]
    fn dead_nonzero_output_quad_is_rejected() {
        let owner = Address([0x33; 32]);
        let mut native = spine_inputs_from_body(&body(owner)).unwrap();
        native.output_leaves[1][0] = Block128::ONE;
        assert!(!relation_satisfies(
            &native,
            owner.as_fields(),
            Block128::ONE
        ));
    }

    #[test]
    fn nonzero_second_validity_lane_is_rejected() {
        let owner = Address([0x33; 32]);
        let mut native = spine_inputs_from_body(&body(owner)).unwrap();
        native.pad_leaf[1] = Block128::ONE;
        assert!(!relation_satisfies(
            &native,
            owner.as_fields(),
            Block128::ONE
        ));
    }

    #[test]
    fn unused_high_validity_bit_is_rejected() {
        let owner = Address([0x33; 32]);
        let mut native = spine_inputs_from_body(&body(owner)).unwrap();
        native.pad_leaf[0] += Block128::from(1u128 << STANDARD_VALIDITY_BITS);
        assert!(!relation_satisfies(
            &native,
            owner.as_fields(),
            Block128::ONE
        ));
    }

    #[test]
    fn outer_liveness_must_be_boolean() {
        let owner = Address([0x33; 32]);
        let native = spine_inputs_from_body(&body(owner)).unwrap();
        assert!(!relation_satisfies(
            &native,
            owner.as_fields(),
            Block128::from(2u128)
        ));
    }
}
