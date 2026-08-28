// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Differential tests for the canonical raw-leaf Tx8x2 spine.

use noid_core::{Block128, TowerField};
use noid_gkr::oracle::evaluate_spine;
use noid_gkr::{SpineCircuit, SpineInputs, N_SPINE_SLOTS};
use noid_poseidon2b::native::{capacity_iv, TAG_COMPRESS, TAG_TX8X2};
use noid_poseidon2b::primitives::hash_tx8x2_leaves;

fn fixture() -> SpineInputs {
    SpineInputs {
        leaves: std::array::from_fn(|leaf| {
            [
                Block128::from((0x100 + 2 * leaf) as u128),
                Block128::from((0x101 + 2 * leaf) as u128),
            ]
        }),
    }
}

#[test]
fn oracle_matches_native_tx8x2_hash() {
    let inputs = fixture();
    let witness = evaluate_spine(&SpineCircuit::build(), &inputs);
    assert_eq!(
        witness.tx_body_hash_bytes(),
        hash_tx8x2_leaves(&inputs.leaves).0
    );
}

#[test]
fn every_raw_statement_lane_reaches_the_wrap() {
    let circuit = SpineCircuit::build();
    let inputs = fixture();
    let baseline = evaluate_spine(&circuit, &inputs).tx_body_hash;
    for leaf in 0..inputs.leaves.len() {
        for lane in 0..2 {
            let mut changed = inputs.clone();
            changed.leaves[leaf][lane] += Block128::ONE;
            assert_ne!(
                evaluate_spine(&circuit, &changed).tx_body_hash,
                baseline,
                "unbound raw statement lane L{leaf}[{lane}]"
            );
        }
    }
}

#[test]
fn exact_geometry_and_domains_are_pinned() {
    let circuit = SpineCircuit::build();
    assert_eq!(N_SPINE_SLOTS, 31);
    assert_eq!(circuit.slots.len(), 31);
    assert_eq!(circuit.wrap_id(), 30);
    assert_eq!(circuit.slots[30].capacity_iv, capacity_iv(TAG_TX8X2));
    assert_ne!(capacity_iv(TAG_COMPRESS), capacity_iv(TAG_TX8X2));
}
