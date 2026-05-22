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
use noid_block::{prove_block, verify_block, TxBlockWitness, VerifyBlockError};
use noid_core::{Block128, TowerField};
use noid_gkr::{compute_auth_boundary, AuthCircuit, AuthInputs, SpineInputs, N_AUTH_INPUTS};

fn spine_inputs_from_composite(
    comp: &noid_air::composition::tx_validity_with_spine::TxValidityCompositeWithSpine,
) -> SpineInputs {
    let pins = comp.boundary_pins();
    SpineInputs {
        prev_state_root: pins.prev_state_root,
        fee_leaf: pins.fee_leaf,
        input_leaves: pins.input_leaf_absorb,
        output_leaves: pins.output_leaf_absorb,
        is_coinbase_leaf: pins.is_coinbase_leaf,
        pad_leaf: [Block128::ZERO; 2],
    }
}

fn auth_inputs_for_composite(
    comp: &noid_air::composition::tx_validity_with_spine::TxValidityCompositeWithSpine,
) -> AuthInputs {
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
    AuthInputs {
        spend_secret,
        tx_body_hash,
        expected_address: addr,
        expected_auth_tag: tag,
    }
}

#[test]
#[ignore = "stage_g_roundtrip: heavy (full block prove); run with --ignored"]
fn block_one_tx_roundtrip() {
    let comp = fixture::build_honest_realistic();
    let trace = comp.build_trace();
    let pi = comp.public_inputs();
    let spine_inputs = spine_inputs_from_composite(&comp);
    let auth_inputs = auth_inputs_for_composite(&comp);

    let witness = TxBlockWitness {
        air: comp.air(),
        trace: &trace,
        pi: &pi,
        spine_inputs: &spine_inputs,
        auth_inputs: &auth_inputs,
    };

    let prev_state_root = pi.prev_state_root;
    let proof = prove_block(prev_state_root, std::slice::from_ref(&witness))
        .expect("prove_block must succeed on a valid single-tx block");

    assert_eq!(proof.meta.n_tx, 1);
    assert_eq!(proof.meta.n_slice_per_tx, 6);
    assert_eq!(proof.tx_pis.len(), 1);
    assert_eq!(proof.tx_algebraic.len(), 1);

    verify_block(
        comp.air(),
        &proof,
        std::slice::from_ref(&spine_inputs),
        std::slice::from_ref(&auth_inputs),
    )
    .expect("verify_block must succeed on an honest block proof");
}

#[test]
#[ignore = "stage_g_roundtrip: heavy (full block prove); run with --ignored"]
fn block_rejects_tampered_state_continuity() {
    let comp = fixture::build_honest_realistic();
    let trace = comp.build_trace();
    let pi = comp.public_inputs();
    let spine_inputs = spine_inputs_from_composite(&comp);
    let auth_inputs = auth_inputs_for_composite(&comp);

    let witness = TxBlockWitness {
        air: comp.air(),
        trace: &trace,
        pi: &pi,
        spine_inputs: &spine_inputs,
        auth_inputs: &auth_inputs,
    };

    // Wrong prev_block_state_root: prove_block must reject up-front.
    let mut wrong_prev = pi.prev_state_root;
    wrong_prev[0] ^= 0xFF;
    let result = prove_block(wrong_prev, std::slice::from_ref(&witness));
    assert!(
        matches!(
            result,
            Err(noid_block::ProveBlockError::TxContinuityViolation(0))
        ),
        "prove_block must reject mismatched prev_block_state_root, got {:?}",
        result.as_ref().map(|_| "ok").unwrap_or("err")
    );
}

#[test]
#[ignore = "stage_g_roundtrip: heavy (full block prove); run with --ignored"]
fn block_verify_rejects_tampered_pi_continuity() {
    let comp = fixture::build_honest_realistic();
    let trace = comp.build_trace();
    let pi = comp.public_inputs();
    let spine_inputs = spine_inputs_from_composite(&comp);
    let auth_inputs = auth_inputs_for_composite(&comp);

    let witness = TxBlockWitness {
        air: comp.air(),
        trace: &trace,
        pi: &pi,
        spine_inputs: &spine_inputs,
        auth_inputs: &auth_inputs,
    };

    let prev_state_root = pi.prev_state_root;
    let mut proof = prove_block(prev_state_root, std::slice::from_ref(&witness))
        .expect("honest prove_block must succeed");

    // Tamper with the first tx's prev_state_root in the public inputs:
    // the verifier's state-continuity check must reject before the
    // algebraic STARK replay even starts.
    proof.tx_pis[0].prev_state_root[0] ^= 0x01;

    let result = verify_block(
        comp.air(),
        &proof,
        std::slice::from_ref(&spine_inputs),
        std::slice::from_ref(&auth_inputs),
    );
    assert!(
        matches!(result, Err(VerifyBlockError::ContinuityViolation(0))),
        "verify_block must reject tampered continuity, got {:?}",
        result
    );
}
