// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Kill-Shot differential against the canonical Tx8x2 native hash.

use noid_core::{Block128, CanonicalSerialize, TowerField};
use noid_gkr::{
    build_unified_from_inputs, compute_tx_body_hash, discharge_reductions_native,
    prove_spine_killshot, verify_spine_killshot, SpineCircuit, SpineInputs,
};
use noid_poseidon2b::channel::Poseidon2bChannel;
use noid_poseidon2b::primitives::hash_tx8x2_leaves;

fn fixture() -> SpineInputs {
    SpineInputs {
        leaves: std::array::from_fn(|leaf| {
            [
                Block128::from((0x500 + 2 * leaf) as u128),
                Block128::from((0x501 + 2 * leaf) as u128),
            ]
        }),
    }
}

#[test]
fn killshot_wrap_pin_matches_native_hash() {
    let inputs = fixture();
    let circuit = SpineCircuit::build();
    let claimed = compute_tx_body_hash(&circuit, &inputs);
    let native = hash_tx8x2_leaves(&inputs.leaves).0;
    assert_eq!(claimed[0].to_bytes(), native[..16]);
    assert_eq!(claimed[1].to_bytes(), native[16..]);
}

#[test]
fn killshot_reductions_consistent_with_native_mle() {
    let inputs = fixture();
    let circuit = SpineCircuit::build();
    let claimed = compute_tx_body_hash(&circuit, &inputs);
    let mut channel = Poseidon2bChannel::new();
    let (_proof, reductions) = prove_spine_killshot(&circuit, &inputs, claimed, &mut channel);
    assert!(discharge_reductions_native(&circuit, &inputs, &reductions));

    let mle = build_unified_from_inputs(&circuit, &inputs);
    assert_eq!(
        noid_core::mle::evaluate::evaluate_slice(&mle.state, &reductions.state.point),
        reductions.state.value
    );
    assert_eq!(
        noid_core::mle::evaluate::evaluate_slice(&mle.s_in, &reductions.sin.point),
        reductions.sin.value
    );
    assert_eq!(
        noid_core::mle::evaluate::evaluate_slice(&mle.s_out, &reductions.sout.point),
        reductions.sout.value
    );
}

#[test]
fn killshot_prover_and_verifier_agree() {
    let inputs = fixture();
    let circuit = SpineCircuit::build();
    let claimed = compute_tx_body_hash(&circuit, &inputs);
    let mut prover_channel = Poseidon2bChannel::new();
    let (proof, prover_reductions) =
        prove_spine_killshot(&circuit, &inputs, claimed, &mut prover_channel);
    let mut verifier_channel = Poseidon2bChannel::new();
    let verifier_reductions =
        verify_spine_killshot(&proof, &circuit, &inputs, claimed, &mut verifier_channel)
            .expect("honest proof verifies");
    assert_eq!(prover_reductions, verifier_reductions);
}

#[test]
fn post_proof_raw_leaf_mutation_breaks_native_discharge() {
    let mut inputs = fixture();
    let circuit = SpineCircuit::build();
    let claimed = compute_tx_body_hash(&circuit, &inputs);
    let mut channel = Poseidon2bChannel::new();
    let (_proof, reductions) = prove_spine_killshot(&circuit, &inputs, claimed, &mut channel);
    inputs.leaves[7][1] += Block128::ONE;
    assert!(!discharge_reductions_native(&circuit, &inputs, &reductions));
}
