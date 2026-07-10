// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Hash-bound transaction selectors shared by the C' semantic relation.
//!
//! The final Tx8x2 spine exposes all 16 raw body-hash leaves as statement
//! wires. This module makes the flags leaf the only in-trace liveness source,
//! enforces the canonical zero form of dead entries, and binds the body-level
//! input owner to the one-owner authorization address. Ordered actions and the
//! exact-state overlay build on these wires in the next C' slice.

use super::tx_body_spine::SpineInputsTrace;
use super::{mul, pin_eq, pin_zero, range_check_bits, FieldR1csBuilder, LinExpr, F128};
pub use noid_tx::body_hash::{
    TX8X2_LEAF_EPOCH_ANCHOR as LEAF_EPOCH_ANCHOR, TX8X2_LEAF_FEE as LEAF_FEE,
    TX8X2_LEAF_FLAGS as LEAF_FLAGS, TX8X2_LEAF_INPUT_BASE as LEAF_INPUT_BASE,
    TX8X2_LEAF_INPUT_OWNER as LEAF_INPUT_OWNER, TX8X2_LEAF_OUTPUT0_DATA as LEAF_OUTPUT0_DATA,
    TX8X2_LEAF_OUTPUT0_OWNER as LEAF_OUTPUT0_OWNER, TX8X2_LEAF_OUTPUT1_DATA as LEAF_OUTPUT1_DATA,
    TX8X2_LEAF_OUTPUT1_OWNER as LEAF_OUTPUT1_OWNER,
};

pub const INPUT_SELECTORS: usize = noid_tx::TX_INPUTS;
pub const OUTPUT_SELECTORS: usize = noid_tx::TX_OUTPUTS;
pub const VALIDITY_BITS: usize = INPUT_SELECTORS + OUTPUT_SELECTORS;

const _: () = assert!(LEAF_INPUT_BASE + INPUT_SELECTORS == LEAF_OUTPUT0_DATA);
const _: () = assert!(LEAF_OUTPUT1_OWNER + 1 == LEAF_FLAGS);
const _: () = assert!(LEAF_FLAGS + 1 == super::tx_body_spine::TX_BODY_RAW_LEAVES);

/// Selector surface of one Tx8x2 body.
///
/// `raw_*` are committed by `L15`; `selected_* = tx_live * raw_*`
/// additionally gate tier-padding ghost transactions out of block resource
/// totals without changing their canonical ghost body or authorization proof.
pub struct ActionSurfaceTrace {
    pub raw_inputs: [LinExpr; INPUT_SELECTORS],
    pub raw_outputs: [LinExpr; OUTPUT_SELECTORS],
    pub selected_inputs: [LinExpr; INPUT_SELECTORS],
    pub selected_outputs: [LinExpr; OUTPUT_SELECTORS],
}

/// Bind a Tx8x2 user body's validity bitmap, canonical dead entries,
/// and mandatory one-owner address to already allocated spine statement
/// wires. Coinbase has different semantic obligations and deliberately gets
/// no permissive `Option<owner>` entry point here.
pub fn bind_user_action_surface(
    b: &mut FieldR1csBuilder,
    spine: &SpineInputsTrace,
    tx_live: &LinExpr,
    expected_owner: &[LinExpr; 2],
) -> ActionSurfaceTrace {
    // Capacity builds already constrain their shared liveness wires. Keeping
    // this local booleanity also makes the component sound in isolation.
    let tx_live_sq = mul(b, tx_live, tx_live);
    pin_eq(b, &tx_live_sq, tx_live);

    // L15 = [validity_bitmap, is_coinbase]. A user transaction's bitmap has
    // exactly ten little-endian bits, and its coinbase flag is zero.
    let bits = range_check_bits(b, &spine.leaves[LEAF_FLAGS][0], VALIDITY_BITS);
    pin_zero(b, &spine.leaves[LEAF_FLAGS][1]);
    let raw: [LinExpr; VALIDITY_BITS] = std::array::from_fn(|i| LinExpr::from_wire(bits[i]));
    let raw_inputs: [LinExpr; INPUT_SELECTORS] = std::array::from_fn(|i| raw[i].clone());
    let raw_outputs: [LinExpr; OUTPUT_SELECTORS] =
        std::array::from_fn(|i| raw[INPUT_SELECTORS + i].clone());

    let bind_dead_pair = |b: &mut FieldR1csBuilder, live: &LinExpr, pair: &[LinExpr; 2]| {
        // Characteristic two: 1 + live is the boolean NOT of live.
        let dead = live.add_const(F128::ONE);
        for lane in pair {
            let dead_lane = mul(b, &dead, lane);
            pin_zero(b, &dead_lane);
        }
    };

    // L2 is the body-level input owner, committed exactly once and pinned
    // directly to the one OwnerAuth statement; input records L3..L10 carry
    // only slot/value data.
    for lane in 0..2 {
        pin_eq(
            b,
            &spine.leaves[LEAF_INPUT_OWNER][lane],
            &expected_owner[lane],
        );
    }
    for (index, live) in raw_inputs.iter().enumerate() {
        bind_dead_pair(b, live, &spine.leaves[LEAF_INPUT_BASE + index]);
    }
    for (index, live) in raw_outputs.iter().enumerate() {
        let data_leaf = LEAF_OUTPUT0_DATA + 2 * index;
        bind_dead_pair(b, live, &spine.leaves[data_leaf]);
        bind_dead_pair(b, live, &spine.leaves[data_leaf + 1]);
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
    use noid_poseidon2b::primitives::Address;
    use noid_tx::{output_bitmap_bit, TxBody, TxInput, TxOutput, TX_INPUTS, TX_OUTPUTS};

    fn body(owner: Address) -> TxBody {
        let mut inputs = [TxInput::dummy(); TX_INPUTS];
        inputs[0] = TxInput {
            slot_index: 7,
            amount: 20,
            creation_id: 3,
        };
        let mut outputs = [TxOutput::dummy(); TX_OUTPUTS];
        outputs[0] = TxOutput {
            slot_index: 9,
            amount: 19,
            owner: Address([0x77; 32]),
        };
        TxBody {
            epoch_anchor: [0x42; 32],
            fee: 1,
            input_owner: owner,
            inputs,
            outputs,
            validity_bitmap: 1 | output_bitmap_bit(0),
            is_coinbase: false,
        }
    }

    fn edge_body(owner: Address) -> TxBody {
        let mut inputs = [TxInput::dummy(); TX_INPUTS];
        inputs[TX_INPUTS - 1] = TxInput {
            slot_index: 17,
            amount: 41,
            creation_id: 5,
        };
        let mut outputs = [TxOutput::dummy(); TX_OUTPUTS];
        outputs[TX_OUTPUTS - 1] = TxOutput {
            slot_index: 19,
            amount: 40,
            owner: Address([0x88; 32]),
        };
        TxBody {
            epoch_anchor: [0x52; 32],
            fee: 1,
            input_owner: owner,
            inputs,
            outputs,
            validity_bitmap: (1 << (TX_INPUTS - 1)) | output_bitmap_bit(TX_OUTPUTS - 1),
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
            let _ = bind_user_action_surface(&mut b, &spine, &tx_live, &expected);
            let (r1cs, z) = b.build();
            r1cs.satisfies(&z)
        }))
        .unwrap_or(false)
    }

    #[test]
    fn bitmap_drives_selectors_and_one_owner_pin() {
        let owner = Address([0x33; 32]);
        let native = spine_inputs_from_body(&body(owner));
        let mut b = FieldR1csBuilder::new();
        let spine = SpineInputsTrace::alloc(&mut b, &native);
        let owner_fields = owner.as_fields();
        let expected = std::array::from_fn(|i| alloc_block(&mut b, owner_fields[i]));
        let surface =
            bind_user_action_surface(&mut b, &spine, &const_block(Block128::ONE), &expected);
        let (r1cs, z) = b.build();
        assert!(r1cs.satisfies(&z));
        assert_eq!(surface.raw_inputs[0].eval(&z), F128::ONE);
        assert_eq!(surface.raw_outputs[0].eval(&z), F128::ONE);
        assert!(surface.raw_inputs[1..]
            .iter()
            .all(|selector| selector.eval(&z) == F128::ZERO));
    }

    #[test]
    fn final_input_and_output_selectors_map_to_l10_and_l14() {
        let owner = Address([0x35; 32]);
        let native = spine_inputs_from_body(&edge_body(owner));
        let mut b = FieldR1csBuilder::new();
        let spine = SpineInputsTrace::alloc(&mut b, &native);
        let owner_fields = owner.as_fields();
        let expected = std::array::from_fn(|i| alloc_block(&mut b, owner_fields[i]));
        let surface =
            bind_user_action_surface(&mut b, &spine, &const_block(Block128::ONE), &expected);
        let (r1cs, z) = b.build();
        assert!(r1cs.satisfies(&z));
        assert_eq!(surface.raw_inputs[TX_INPUTS - 1].eval(&z), F128::ONE);
        assert_eq!(surface.raw_outputs[TX_OUTPUTS - 1].eval(&z), F128::ONE);
        assert!(surface.raw_inputs[..TX_INPUTS - 1]
            .iter()
            .chain(&surface.raw_outputs[..TX_OUTPUTS - 1])
            .all(|selector| selector.eval(&z) == F128::ZERO));
    }

    #[test]
    fn owner_recombination_is_unsatisfied() {
        let native = spine_inputs_from_body(&body(Address([0x33; 32])));
        let wrong_owner = Address([0x44; 32]).as_fields();
        assert!(!relation_satisfies(&native, wrong_owner, Block128::ONE));
    }

    #[test]
    fn input_leaf_recombination_is_unsatisfied() {
        let owner = Address([0x35; 32]);
        let mut native = spine_inputs_from_body(&edge_body(owner));
        native
            .leaves
            .swap(LEAF_INPUT_BASE + TX_INPUTS - 1, LEAF_INPUT_BASE);
        assert!(!relation_satisfies(
            &native,
            owner.as_fields(),
            Block128::ONE
        ));
    }

    #[test]
    fn output_leaf_recombination_is_unsatisfied() {
        let owner = Address([0x35; 32]);
        let mut native = spine_inputs_from_body(&edge_body(owner));
        native.leaves.swap(LEAF_OUTPUT1_DATA, LEAF_OUTPUT0_DATA);
        native.leaves.swap(LEAF_OUTPUT1_OWNER, LEAF_OUTPUT0_OWNER);
        assert!(!relation_satisfies(
            &native,
            owner.as_fields(),
            Block128::ONE
        ));
    }

    #[test]
    fn outer_inactive_gates_counts() {
        let owner = Address([0x33; 32]);
        let native = spine_inputs_from_body(&body(owner));
        let owner_fields = owner.as_fields();
        let mut b = FieldR1csBuilder::new();
        let spine = SpineInputsTrace::alloc(&mut b, &native);
        let expected = std::array::from_fn(|i| alloc_block(&mut b, owner_fields[i]));
        let surface =
            bind_user_action_surface(&mut b, &spine, &const_block(Block128::ZERO), &expected);
        let (r1cs, z) = b.build();
        assert!(r1cs.satisfies(&z));
        assert!(surface
            .selected_inputs
            .iter()
            .chain(&surface.selected_outputs)
            .all(|selector| selector.eval(&z) == F128::ZERO));
    }

    #[test]
    fn dead_nonzero_input_leaf_is_rejected() {
        let owner = Address([0x33; 32]);
        let mut native = spine_inputs_from_body(&body(owner));
        native.leaves[LEAF_INPUT_BASE + 1][1] = Block128::ONE;
        let owner_fields = owner.as_fields();
        assert!(!relation_satisfies(&native, owner_fields, Block128::ONE));
    }

    #[test]
    fn dead_nonzero_output_data_leaf_is_rejected() {
        let owner = Address([0x33; 32]);
        let mut native = spine_inputs_from_body(&body(owner));
        native.leaves[LEAF_OUTPUT1_DATA][0] = Block128::ONE;
        assert!(!relation_satisfies(
            &native,
            owner.as_fields(),
            Block128::ONE
        ));
    }

    #[test]
    fn dead_nonzero_output_owner_is_rejected() {
        let owner = Address([0x33; 32]);
        let mut native = spine_inputs_from_body(&body(owner));
        native.leaves[LEAF_OUTPUT1_OWNER][1] = Block128::ONE;
        assert!(!relation_satisfies(
            &native,
            owner.as_fields(),
            Block128::ONE
        ));
    }

    #[test]
    fn user_coinbase_flag_is_rejected() {
        let owner = Address([0x33; 32]);
        let mut native = spine_inputs_from_body(&body(owner));
        native.leaves[LEAF_FLAGS][1] = Block128::ONE;
        assert!(!relation_satisfies(
            &native,
            owner.as_fields(),
            Block128::ONE
        ));
    }

    #[test]
    fn unused_high_validity_bit_is_rejected() {
        let owner = Address([0x33; 32]);
        let mut native = spine_inputs_from_body(&body(owner));
        native.leaves[LEAF_FLAGS][0] += Block128::from(1u128 << VALIDITY_BITS);
        assert!(!relation_satisfies(
            &native,
            owner.as_fields(),
            Block128::ONE
        ));
    }

    #[test]
    fn outer_liveness_must_be_boolean() {
        let owner = Address([0x33; 32]);
        let native = spine_inputs_from_body(&body(owner));
        assert!(!relation_satisfies(
            &native,
            owner.as_fields(),
            Block128::from(2u128)
        ));
    }
}
