// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Stage G acceptance tests for `noid_block`.
//!
//! These are heavy integration tests that run a full block prove/verify
//! roundtrip with realistic fixtures.  Marked `#[ignore]` to keep
//! ordinary `cargo test` runs quick; run with `--ignored` or via the
//! release-mode bench harness.

#![allow(clippy::needless_range_loop)]

use noid_air::composition::tx_validity_with_spine::fixture;
use noid_block::{prove_block, verify_block, TxBlockWitness};
use noid_core::{Block128, TowerField};
use noid_core::mle::split::split_mle_into_slices;
use noid_gkr::{
    auth_gkr_channel, build_auth_unified_from_inputs, compute_auth_boundary, prove_auth_killshot,
    AuthCircuit, AuthInputs, AuthProofKillShot, AuthPublicInputs, SpineInputs, N_AUTH_INPUTS,
    N_AUTH_UNIFIED_VARS,
};

fn spine_inputs_from_composite(
    comp: &noid_air::composition::tx_validity_with_spine::TxValidityCompositeWithSpine,
) -> SpineInputs {
    let pins = comp.boundary_pins();
    SpineInputs {
        epoch_anchor: pins.epoch_anchor,
        fee_leaf: pins.fee_leaf,
        input_leaves: pins.input_leaf_absorb,
        output_leaves: pins.output_leaf_absorb,
        is_coinbase_leaf: pins.is_coinbase_leaf,
        pad_leaf: [Block128::ZERO; 2],
    }
}

/// Simulates what the wallet does: generates auth proof locally with secrets,
/// then returns only public data + proof + slices (no secrets leak).
fn wallet_auth_for_composite(
    comp: &noid_air::composition::tx_validity_with_spine::TxValidityCompositeWithSpine,
) -> (AuthPublicInputs, AuthProofKillShot, Vec<Vec<Block128>>) {
    use fixture::mk_secret;
    let circuit = AuthCircuit::build();
    let pi = comp.public_inputs();
    let n_live = pi.n_live_inputs as usize;
    let secrets = [
        mk_secret(0xA1),
        mk_secret(0xB2),
        mk_secret(0xC3),
        mk_secret(0xD4),
    ];
    let mut spend_secret = [[Block128::ZERO; 2]; N_AUTH_INPUTS];
    for i in 0..n_live {
        spend_secret[i] = secrets[i];
    }
    let tx_body_hash = comp.tx_body_hash_fields();
    let (addr, tag) = compute_auth_boundary(&circuit, spend_secret, tx_body_hash);
    let auth_inputs = AuthInputs {
        spend_secret,
        tx_body_hash,
        expected_address: addr,
        expected_auth_tag: tag,
    };

    // Wallet generates auth proof locally (uses spend_secret internally).
    let mut ch = auth_gkr_channel();
    let (proof, _reductions) = prove_auth_killshot(&circuit, &auth_inputs, &mut ch);

    // Wallet builds auth MLE slices (needs secret for MLE construction).
    let auth_mle = build_auth_unified_from_inputs(&circuit, &auth_inputs);
    let auth_slices = split_mle_into_slices(&auth_mle.state, N_AUTH_UNIFIED_VARS, 13);

    // Only public data + proof + slices leave the wallet.
    (auth_inputs.to_public(), proof, auth_slices)
}

#[test]
#[ignore = "stage_g_roundtrip: heavy (full block prove); run with --ignored"]
fn block_one_tx_roundtrip() {
    let comp = fixture::build_honest_realistic();
    let trace = comp.build_trace();
    let pi = comp.public_inputs();
    let spine_inputs = spine_inputs_from_composite(&comp);
    let (auth_public, auth_proof, auth_slices) = wallet_auth_for_composite(&comp);

    let witness = TxBlockWitness {
        air: comp.air(),
        trace: &trace,
        pi: &pi,
        spine_inputs: &spine_inputs,
        auth_public: &auth_public,
        auth_proof: &auth_proof,
        auth_slices: &auth_slices,
    };

    let prev_state_root = pi.epoch_anchor;
    let proof = prove_block(prev_state_root, std::slice::from_ref(&witness), None)
        .expect("prove_block must succeed on a valid single-tx block");

    assert_eq!(proof.meta.n_tx, 1);
    assert_eq!(proof.meta.n_slice_per_tx, 6);
    assert_eq!(proof.tx_pis.len(), 1);
    assert_eq!(proof.tx_algebraic.len(), 1);

    let air_ref: &dyn noid_air::Air = comp.air();
    verify_block(
        &[air_ref],
        &proof,
        std::slice::from_ref(&spine_inputs),
        std::slice::from_ref(&auth_public),
        None,
    )
    .expect("verify_block must succeed on an honest block proof");
}

#[test]
#[ignore = "stage_g_roundtrip: heavy (full block prove); run with --ignored"]
fn block_verify_rejects_tampered_epoch_anchor() {
    let comp = fixture::build_honest_realistic();
    let trace = comp.build_trace();
    let pi = comp.public_inputs();
    let spine_inputs = spine_inputs_from_composite(&comp);
    let (auth_public, auth_proof, auth_slices) = wallet_auth_for_composite(&comp);

    let witness = TxBlockWitness {
        air: comp.air(),
        trace: &trace,
        pi: &pi,
        spine_inputs: &spine_inputs,
        auth_public: &auth_public,
        auth_proof: &auth_proof,
        auth_slices: &auth_slices,
    };

    let prev_block_state_root = pi.epoch_anchor;
    let mut proof = prove_block(prev_block_state_root, std::slice::from_ref(&witness), None)
        .expect("honest prove_block must succeed");

    proof.tx_pis[0].epoch_anchor[0] ^= 0x01;

    let air_ref: &dyn noid_air::Air = comp.air();
    let result = verify_block(
        &[air_ref],
        &proof,
        std::slice::from_ref(&spine_inputs),
        std::slice::from_ref(&auth_public),
        None,
    );
    assert!(
        result.is_err(),
        "verify_block must reject tampered epoch_anchor, got Ok(())"
    );
}
