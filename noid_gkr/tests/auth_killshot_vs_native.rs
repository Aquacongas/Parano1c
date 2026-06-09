// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! AuthGKR Kill-Shot differential against the native
//! reference oracle.
//!
//! Three guarantees this suite pins:
//!
//! 1. Honest `AuthInputs` (boundary computed via `compute_auth_boundary`)
//!    survive a prove/verify round-trip with the native discharge
//!    accepting every reduction.
//! 2. Reductions returned by prover and verifier are bit-identical
//!    (transcript determinism).
//! 3. A tamper of any public boundary (Address, AuthTag, tx_body_hash)
//!    forces the verifier to reject deterministically.

use noid_core::{Block128, TowerField};
use noid_gkr::{
    auth_gkr_channel, build_auth_unified_from_inputs, compute_auth_boundary,
    discharge_auth_reductions_native, prove_auth_killshot, verify_auth_killshot, AuthCircuit,
    AuthInputs, N_AUTH_INPUTS,
};
use noid_poseidon2b::primitives::{SpendSecret, TxBodyHash};

fn digest_to_fields(d: &[u8; 32]) -> [Block128; 2] {
    let mut a = [0u8; 16];
    let mut b = [0u8; 16];
    a.copy_from_slice(&d[..16]);
    b.copy_from_slice(&d[16..]);
    [
        Block128::from(u128::from_le_bytes(a)),
        Block128::from(u128::from_le_bytes(b)),
    ]
}

fn build_inputs(seed: u8) -> AuthInputs {
    let circuit = AuthCircuit::build();
    let secrets: [SpendSecret; N_AUTH_INPUTS] = std::array::from_fn(|i| {
        let mut bytes = [0u8; 32];
        for (j, b) in bytes.iter_mut().enumerate() {
            *b = seed.wrapping_add(((i + 1) as u8).wrapping_mul((j + 7) as u8));
        }
        SpendSecret(bytes)
    });
    let tbh = TxBodyHash([seed.wrapping_add(0x5A); 32]);

    let mut spend_secret = [[Block128::ZERO; 2]; N_AUTH_INPUTS];
    for (i, s) in secrets.iter().enumerate() {
        spend_secret[i] = s.as_fields();
    }
    let tx_body_hash = digest_to_fields(&tbh.into_bytes());

    let (expected_address, expected_auth_tag) =
        compute_auth_boundary(&circuit, spend_secret, tx_body_hash);

    AuthInputs {
        spend_secret,
        tx_body_hash,
        expected_address,
        expected_auth_tag,
    }
}

#[test]
fn auth_killshot_reductions_consistent_with_native_mle() {
    let circuit = AuthCircuit::build();
    let inputs = build_inputs(0x11);

    let mut ch = auth_gkr_channel();
    let (_proof, reductions) = prove_auth_killshot(&circuit, &inputs, &mut ch);

    assert!(discharge_auth_reductions_native(
        &circuit,
        &inputs,
        &reductions
    ));

    let mle = build_auth_unified_from_inputs(&circuit, &inputs);
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
fn auth_killshot_prover_and_verifier_agree_on_reductions() {
    let circuit = AuthCircuit::build();
    let inputs = build_inputs(0x22);
    let public = inputs.to_public();

    let mut ch_p = auth_gkr_channel();
    let (proof, prover_red) = prove_auth_killshot(&circuit, &inputs, &mut ch_p);

    let mut ch_v = auth_gkr_channel();
    let verifier_red = verify_auth_killshot(&proof, &circuit, &public, &mut ch_v).expect("verify");

    assert_eq!(prover_red, verifier_red);
}

#[test]
fn auth_killshot_rejects_address_tamper_after_proof() {
    let circuit = AuthCircuit::build();
    let inputs = build_inputs(0x33);

    let mut ch_p = auth_gkr_channel();
    let (proof, _) = prove_auth_killshot(&circuit, &inputs, &mut ch_p);

    let mut public = inputs.to_public();
    public.expected_address[1][0] += Block128::ONE;

    let mut ch_v = auth_gkr_channel();
    assert!(verify_auth_killshot(&proof, &circuit, &public, &mut ch_v).is_none());
}

#[test]
fn auth_killshot_rejects_auth_tag_tamper_after_proof() {
    let circuit = AuthCircuit::build();
    let inputs = build_inputs(0x44);

    let mut ch_p = auth_gkr_channel();
    let (proof, _) = prove_auth_killshot(&circuit, &inputs, &mut ch_p);

    let mut public = inputs.to_public();
    public.expected_auth_tag[3][1] += Block128::ONE;

    let mut ch_v = auth_gkr_channel();
    assert!(verify_auth_killshot(&proof, &circuit, &public, &mut ch_v).is_none());
}

#[test]
fn auth_killshot_rejects_tx_body_hash_tamper_after_proof() {
    let circuit = AuthCircuit::build();
    let inputs = build_inputs(0x55);

    let mut ch_p = auth_gkr_channel();
    let (proof, _) = prove_auth_killshot(&circuit, &inputs, &mut ch_p);

    let mut public = inputs.to_public();
    public.tx_body_hash[0] += Block128::ONE;

    let mut ch_v = auth_gkr_channel();
    assert!(verify_auth_killshot(&proof, &circuit, &public, &mut ch_v).is_none());
}
