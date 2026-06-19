// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Full block prove/verify roundtrip acceptance tests.
//!
//! Uses the production TxLogicAir path.
//! Marked `#[ignore]` to keep ordinary `cargo test` runs quick.

use noid_air::composition::tx_logic::{boundary_pins_from_body, witness_from_body, TxLogicAir};
use noid_air::Air;
use noid_block::{prove_block, verify_block, TxBlockWitness, VerifyBlockError};
use noid_core::{Block128, TowerField};
use noid_gkr::{
    auth_gkr_channel, compute_auth_boundary, prove_auth_killshot, AuthCircuit, AuthInputs,
    AuthProofKillShot, AuthPublicInputs, SpineInputs, N_AUTH_INPUTS,
};
use noid_poseidon2b::primitives::{derive_address, hash_auth_tag, SpendSecret, TxBodyHash};
use noid_tx::{PublicInputs, TxBody, TxInput, TxOutput, MAX_INPUTS, MAX_OUTPUTS};

fn mk_secret(seed: u128) -> [Block128; 2] {
    [
        Block128::from(seed.wrapping_mul(0x9E3779B97F4A7C15) ^ 0xA5A5_A5A5_A5A5_A5A5),
        Block128::from(seed.wrapping_mul(0xBF58476D1CE4E5B9) ^ 0x5A5A_5A5A_5A5A_5A5A),
    ]
}

fn fields_to_bytes(f: [Block128; 2]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[..16].copy_from_slice(&f[0].to_u128().to_le_bytes());
    out[16..].copy_from_slice(&f[1].to_u128().to_le_bytes());
    out
}

/// Build a minimal balanced TxBody for test purposes.
fn mk_test_body() -> TxBody {
    let secrets = [mk_secret(0xA1), mk_secret(0xB2)];
    let addrs: Vec<_> = secrets
        .iter()
        .map(|s| derive_address(&SpendSecret(fields_to_bytes(*s))))
        .collect();

    let mut inputs = vec![
        TxInput {
            slot_index: 0,
            value: 100,
            owner: addrs[0],
            spend_secret: SpendSecret(fields_to_bytes(secrets[0])),
            auth_tag: noid_poseidon2b::primitives::AuthTag([0u8; 32]),
            valid: true,
        },
        TxInput {
            slot_index: 1,
            value: 50,
            owner: addrs[1],
            spend_secret: SpendSecret(fields_to_bytes(secrets[1])),
            auth_tag: noid_poseidon2b::primitives::AuthTag([0u8; 32]),
            valid: true,
        },
    ];
    while inputs.len() < MAX_INPUTS {
        inputs.push(TxInput::dummy());
    }

    let mut outputs = vec![
        TxOutput {
            slot_index: 10,
            value: 80,
            owner: addrs[0],
            valid: true,
        },
        TxOutput {
            slot_index: 11,
            value: 60,
            owner: addrs[1],
            valid: true,
        },
    ];
    while outputs.len() < MAX_OUTPUTS {
        outputs.push(TxOutput::dummy());
    }

    let mut body = TxBody {
        shape: noid_tx::TxShape::Standard4x8,
        epoch_anchor: [0xAA; 32],
        fee: 10,
        inputs,
        outputs,
        is_coinbase: false,
    };

    // Fill in auth_tags now that we have the body hash.
    let pins = boundary_pins_from_body(&body);
    let tx_body_hash = pins.tx_body_hash;
    for i in 0..2 {
        let tag = hash_auth_tag(
            &SpendSecret(fields_to_bytes(secrets[i])),
            &TxBodyHash(fields_to_bytes(tx_body_hash)),
        );
        body.inputs[i].auth_tag = tag;
    }
    body
}

/// Build TxLogicAir + trace + PublicInputs + SpineInputs from a body.
fn build_fixture(body: &TxBody) -> (TxLogicAir, noid_air::Trace, PublicInputs, SpineInputs) {
    use noid_tx::compute_claims_commitment;

    let pins = boundary_pins_from_body(body);
    let air = TxLogicAir::new(pins);
    let witness = witness_from_body(body);
    let trace = air.build_trace(&witness);

    let n_live_inputs = body.inputs.iter().filter(|i| i.valid).count() as u8;
    let n_live_outputs = body.outputs.iter().filter(|o| o.valid).count() as u8;
    let claims = compute_claims_commitment(&body.inputs, &body.outputs);

    let mut is_activation = [false; MAX_OUTPUTS];
    for (j, o) in body.outputs.iter().enumerate().take(MAX_OUTPUTS) {
        is_activation[j] = o.valid;
    }
    let mut is_deactivation = [false; MAX_INPUTS];
    for (i, inp) in body.inputs.iter().enumerate().take(MAX_INPUTS) {
        is_deactivation[i] = inp.valid;
    }

    let pi = PublicInputs {
        epoch_anchor: body.epoch_anchor,
        tx_body_hash: TxBodyHash(fields_to_bytes(pins.tx_body_hash)),
        shape_id: body.shape.id(),
        fee: body.fee,
        n_live_inputs,
        n_live_outputs,
        coinbase_credit: 0,
        log_slots: 24,
        claims_commitment: claims,
        is_activation,
        is_deactivation,
    };

    let spine_inputs = SpineInputs {
        epoch_anchor: pins.epoch_anchor,
        fee_leaf: pins.fee_leaf,
        input_leaves: pins.input_leaf_absorb,
        output_leaves: pins.output_leaf_absorb,
        is_coinbase_leaf: pins.is_coinbase_leaf,
        pad_leaf: [Block128::ZERO; 2],
    };

    (air, trace, pi, spine_inputs)
}

/// Wallet-side: generate self-contained auth proof capsule from the body secrets.
fn wallet_auth(
    body: &TxBody,
    tx_body_hash: [Block128; 2],
) -> (AuthPublicInputs, AuthProofKillShot) {
    let secrets = [
        mk_secret(0xA1),
        mk_secret(0xB2),
        mk_secret(0xC3),
        mk_secret(0xD4),
    ];
    let circuit = AuthCircuit::build();
    let n_live = body.inputs.iter().filter(|i| i.valid).count();

    let mut spend_secret = [[Block128::ZERO; 2]; N_AUTH_INPUTS];
    for i in 0..n_live {
        spend_secret[i] = secrets[i];
    }

    let (expected_address, expected_auth_tag) =
        compute_auth_boundary(&circuit, spend_secret, tx_body_hash);
    let auth_inputs = AuthInputs {
        spend_secret,
        tx_body_hash,
        expected_address,
        expected_auth_tag,
    };

    let mut ch = auth_gkr_channel();
    let (proof, _) = prove_auth_killshot(&circuit, &auth_inputs, &mut ch);

    (auth_inputs.to_public(), proof)
}

#[test]
#[ignore = "stage_g_roundtrip: heavy (full block prove); run with --ignored"]
fn block_one_tx_roundtrip() {
    let body = mk_test_body();
    let (air, trace, pi, spine_inputs) = build_fixture(&body);
    let tx_body_hash = pi.tx_body_hash.as_fields();
    let (auth_public, auth_proof) = wallet_auth(&body, tx_body_hash);

    let witness = TxBlockWitness {
        block_tx_index: 1,
        air: &air as &dyn Air,
        trace: &trace,
        pi: &pi,
        spine_inputs: &spine_inputs,
        auth_public: &auth_public,
        auth_proof: &auth_proof,
    };

    let prev_state_root = pi.epoch_anchor;
    let proof = prove_block(
        prev_state_root,
        [0u8; 32],
        std::slice::from_ref(&witness),
        &[],
    )
    .expect("prove_block must succeed on a valid single-tx block");

    assert_eq!(proof.meta.n_tx, 1);
    assert_eq!(proof.meta.n_auth_slices_per_tx, 0);

    let air_ref: &dyn Air = &air;
    verify_block(
        &[air_ref],
        &proof,
        std::slice::from_ref(&spine_inputs),
        std::slice::from_ref(&auth_public),
        &[],
    )
    .expect("verify_block must succeed on an honest block proof");
}

#[test]
#[ignore = "stage_g_roundtrip: heavy (full block prove); run with --ignored"]
fn block_verify_rejects_tampered_bucket_opening_at_algebraic_terminal() {
    let body = mk_test_body();
    let (air, trace, pi, spine_inputs) = build_fixture(&body);
    let tx_body_hash = pi.tx_body_hash.as_fields();
    let (auth_public, auth_proof) = wallet_auth(&body, tx_body_hash);

    let witness = TxBlockWitness {
        block_tx_index: 1,
        air: &air as &dyn Air,
        trace: &trace,
        pi: &pi,
        spine_inputs: &spine_inputs,
        auth_public: &auth_public,
        auth_proof: &auth_proof,
    };

    let prev_state_root = pi.epoch_anchor;
    let mut proof = prove_block(
        prev_state_root,
        [0u8; 32],
        std::slice::from_ref(&witness),
        &[],
    )
    .expect("honest prove_block must succeed");

    proof
        .standard_bucket
        .as_mut()
        .expect("standard bucket")
        .block_col_openings[0] += Block128::ONE;

    let air_ref: &dyn Air = &air;
    let err = verify_block(
        &[air_ref],
        &proof,
        std::slice::from_ref(&spine_inputs),
        std::slice::from_ref(&auth_public),
        &[],
    )
    .expect_err("tampered bucket opening must reject");
    assert!(
        matches!(err, VerifyBlockError::AlgebraicTerminal(0)),
        "unexpected error: {err:?}"
    );
}

#[test]
#[ignore = "stage_g_roundtrip: heavy (full block prove); run with --ignored"]
fn block_verify_rejects_tampered_epoch_anchor() {
    let body = mk_test_body();
    let (air, trace, pi, spine_inputs) = build_fixture(&body);
    let tx_body_hash = pi.tx_body_hash.as_fields();
    let (auth_public, auth_proof) = wallet_auth(&body, tx_body_hash);

    let witness = TxBlockWitness {
        block_tx_index: 1,
        air: &air as &dyn Air,
        trace: &trace,
        pi: &pi,
        spine_inputs: &spine_inputs,
        auth_public: &auth_public,
        auth_proof: &auth_proof,
    };

    let prev_state_root = pi.epoch_anchor;
    let mut proof = prove_block(
        prev_state_root,
        [0u8; 32],
        std::slice::from_ref(&witness),
        &[],
    )
    .expect("honest prove_block must succeed");

    proof
        .standard_bucket
        .as_mut()
        .expect("standard bucket")
        .tx_pis[0]
        .epoch_anchor[0] ^= 0x01;

    let air_ref: &dyn Air = &air;
    let result = verify_block(
        &[air_ref],
        &proof,
        std::slice::from_ref(&spine_inputs),
        std::slice::from_ref(&auth_public),
        &[],
    );
    assert!(
        result.is_err(),
        "verify_block must reject tampered epoch_anchor"
    );
}
