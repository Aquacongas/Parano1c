// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

use noid_core::{Block128, TowerField};
use noid_gkr::{
    compute_sweep_auth_boundary, discharge_sweep_auth_reductions_native, prove_sweep_auth_killshot,
    sweep_auth_gkr_channel, verify_sweep_auth_killshot, SweepAuthCircuit, SweepAuthInputs,
    N_SWEEP_AUTH_INPUTS,
};
use noid_poseidon2b::primitives::{hash_auth_tag, SpendSecret, TxBodyHash};

const SWEEP_AUTH_PROOF_BYTES: usize = 5_920;

fn mk_secret(seed: u8) -> SpendSecret {
    let mut bytes = [0u8; 32];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = seed.wrapping_mul(17).wrapping_add(i as u8).wrapping_add(3);
    }
    SpendSecret(bytes)
}

fn tx_body_hash_fields(seed: u8) -> [Block128; 2] {
    let bytes = [seed; 32];
    let mut lo = [0u8; 16];
    let mut hi = [0u8; 16];
    lo.copy_from_slice(&bytes[..16]);
    hi.copy_from_slice(&bytes[16..]);
    [
        Block128::from(u128::from_le_bytes(lo)),
        Block128::from(u128::from_le_bytes(hi)),
    ]
}

fn build_inputs(n_live: usize) -> SweepAuthInputs {
    assert!(n_live <= N_SWEEP_AUTH_INPUTS);
    let circuit = SweepAuthCircuit::build();
    let mut spend_secret = [[Block128::ZERO; 2]; N_SWEEP_AUTH_INPUTS];
    for i in 0..n_live {
        spend_secret[i] = mk_secret(i as u8 + 1).as_fields();
    }
    let tx_body_hash = tx_body_hash_fields(0xA5);
    let (expected_address, expected_auth_tag) =
        compute_sweep_auth_boundary(&circuit, spend_secret, tx_body_hash);

    SweepAuthInputs {
        spend_secret,
        tx_body_hash,
        expected_address,
        expected_auth_tag,
    }
}

fn prove_verify(inputs: &SweepAuthInputs) -> usize {
    let circuit = SweepAuthCircuit::build();
    let public = inputs.to_public();

    let mut prover_ch = sweep_auth_gkr_channel();
    let (proof, reductions) = prove_sweep_auth_killshot(&circuit, inputs, &mut prover_ch);

    let mut verifier_ch = sweep_auth_gkr_channel();
    let verified = verify_sweep_auth_killshot(&proof, &circuit, &public, &mut verifier_ch)
        .expect("sweep auth verifier accepts honest proof");
    assert_eq!(verified, reductions);
    assert!(discharge_sweep_auth_reductions_native(
        &circuit, inputs, &verified
    ));

    proof.byte_len()
}

#[test]
fn sweep_auth_killshot_roundtrip_5_live_inputs() {
    let inputs = build_inputs(5);
    let proof_len = prove_verify(&inputs);
    assert_eq!(proof_len, SWEEP_AUTH_PROOF_BYTES);

    let zero_secret = SpendSecret([0u8; 32]);
    let zero_tag = hash_auth_tag(&zero_secret, &TxBodyHash([0xA5; 32]));
    assert_eq!(inputs.spend_secret[5], [Block128::ZERO; 2]);
    assert_eq!(inputs.expected_auth_tag[5], zero_tag.as_fields());
}

#[test]
fn sweep_auth_killshot_roundtrip_25_live_inputs() {
    let inputs = build_inputs(N_SWEEP_AUTH_INPUTS);
    let proof_len = prove_verify(&inputs);
    assert_eq!(proof_len, SWEEP_AUTH_PROOF_BYTES);
}

#[test]
fn sweep_auth_killshot_rejects_tampered_expected_address() {
    let inputs = build_inputs(5);
    let circuit = SweepAuthCircuit::build();

    let mut prover_ch = sweep_auth_gkr_channel();
    let (proof, _) = prove_sweep_auth_killshot(&circuit, &inputs, &mut prover_ch);

    let mut public = inputs.to_public();
    public.expected_address[4][0] += Block128::ONE;

    let mut verifier_ch = sweep_auth_gkr_channel();
    assert!(verify_sweep_auth_killshot(&proof, &circuit, &public, &mut verifier_ch).is_none());
}

#[test]
fn sweep_auth_killshot_rejects_tampered_expected_auth_tag() {
    let inputs = build_inputs(25);
    let circuit = SweepAuthCircuit::build();

    let mut prover_ch = sweep_auth_gkr_channel();
    let (proof, _) = prove_sweep_auth_killshot(&circuit, &inputs, &mut prover_ch);

    let mut public = inputs.to_public();
    public.expected_auth_tag[24][1] += Block128::ONE;

    let mut verifier_ch = sweep_auth_gkr_channel();
    assert!(verify_sweep_auth_killshot(&proof, &circuit, &public, &mut verifier_ch).is_none());
}
