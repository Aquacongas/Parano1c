// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Layered-witness cross-check for every slot of the final 31-slot spine.

use noid_core::Block128;
use noid_gkr::layers::evaluate_permutation;
use noid_gkr::oracle::evaluate_spine;
use noid_gkr::{SpineCircuit, SpineInputs};
use noid_poseidon2b::primitives::hash_tx8x2_leaves;

#[test]
fn every_spine_slot_matches_the_layered_evaluator() {
    let inputs = SpineInputs {
        leaves: std::array::from_fn(|leaf| {
            [
                Block128::from((3 * leaf + 1) as u128),
                Block128::from((3 * leaf + 2) as u128),
            ]
        }),
    };
    let circuit = SpineCircuit::build();
    let witness = evaluate_spine(&circuit, &inputs);

    assert_eq!(witness.slots.len(), 31);
    for (slot, state) in witness.slots.iter().enumerate() {
        assert_eq!(
            evaluate_permutation(state.state_in).final_state(),
            state.state_out,
            "layered/native permutation drift at slot {slot}"
        );
    }
    assert_eq!(
        witness.tx_body_hash_bytes(),
        hash_tx8x2_leaves(&inputs.leaves).0
    );
}
