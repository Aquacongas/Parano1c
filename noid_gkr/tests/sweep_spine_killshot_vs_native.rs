// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Sweep25x2 tx-body spine Kill-Shot differential against the native hash.
//!
//! This pins the dedicated 142-slot / 17-variable sweep spine family to the
//! canonical `hash_tx_body_sweep25x2` layout:
//!
//! ```text
//! L0          epoch_anchor
//! L1          fee_leaf(fee)
//! L2          tx_shape_leaf(1)
//! L3..L27     25 input leaves
//! L28..L29    2 output leaves
//! L30         is_coinbase_leaf
//! L31         reserved/pad
//! ```

use noid_core::{Block128, CanonicalSerialize, TowerField};
use noid_gkr::{
    build_sweep_spine_unified_from_inputs, compute_sweep_tx_body_hash,
    discharge_sweep_spine_reductions_native, prove_sweep_spine_killshot,
    verify_sweep_spine_killshot, SweepSpineCircuit, SweepSpineInputs,
};
use noid_poseidon2b::channel::Poseidon2bChannel;
use noid_poseidon2b::primitives::{
    fee_leaf, hash_input_leaf, hash_output_leaf, hash_tx_body_sweep25x2, is_coinbase_leaf,
    tx_shape_leaf, Address, Digest, TxBodyHash, SWEEP_TXBODY_INPUTS, SWEEP_TXBODY_OUTPUTS,
};

fn digest_to_fields(d: &Digest) -> [Block128; 2] {
    let mut a = [0u8; 16];
    let mut b = [0u8; 16];
    a.copy_from_slice(&d[..16]);
    b.copy_from_slice(&d[16..]);
    [
        Block128::from(u128::from_le_bytes(a)),
        Block128::from(u128::from_le_bytes(b)),
    ]
}

fn fields_to_digest(fields: [Block128; 2]) -> Digest {
    let mut out = [0u8; 32];
    out[..16].copy_from_slice(&fields[0].to_bytes());
    out[16..].copy_from_slice(&fields[1].to_bytes());
    out
}

fn tx_hash_matches_fields(fields: [Block128; 2], native: &TxBodyHash) -> bool {
    fields_to_digest(fields) == native.0
}

fn payload(slot: u32, value: u64, owner: &Address) -> [Block128; 4] {
    let [owner_hi, owner_lo] = owner.as_fields();
    [
        Block128::from(slot as u128),
        Block128::from(value as u128),
        owner_hi,
        owner_lo,
    ]
}

fn fixture(is_coinbase: bool) -> (SweepSpineInputs, TxBodyHash) {
    let epoch_anchor = [0x5Au8; 32];
    let fee = 123u128;

    let mut input_payloads = [[Block128::ZERO; 4]; SWEEP_TXBODY_INPUTS];
    let mut input_leaves = [[0u8; 32]; SWEEP_TXBODY_INPUTS];
    for i in 0..SWEEP_TXBODY_INPUTS {
        let owner = Address([i as u8 + 1; 32]);
        let slot = 10 + i as u32;
        let value = 1_000 + i as u64;
        input_payloads[i] = payload(slot, value, &owner);
        input_leaves[i] = hash_input_leaf(slot, value, &owner);
    }

    let mut output_payloads = [[Block128::ZERO; 4]; SWEEP_TXBODY_OUTPUTS];
    let mut output_leaves = [[0u8; 32]; SWEEP_TXBODY_OUTPUTS];
    for i in 0..SWEEP_TXBODY_OUTPUTS {
        let owner = Address([0xA0 + i as u8; 32]);
        let slot = 100 + i as u32;
        let value = 9_000 + i as u64;
        output_payloads[i] = payload(slot, value, &owner);
        output_leaves[i] = hash_output_leaf(slot, value, &owner);
    }

    let inputs = SweepSpineInputs {
        epoch_anchor: digest_to_fields(&epoch_anchor),
        fee_leaf: digest_to_fields(&fee_leaf(fee)),
        shape_leaf: digest_to_fields(&tx_shape_leaf(1)),
        input_leaves: input_payloads,
        output_leaves: output_payloads,
        is_coinbase_leaf: digest_to_fields(&is_coinbase_leaf(is_coinbase)),
        pad_leaf: [Block128::ZERO, Block128::ZERO],
    };
    let native = hash_tx_body_sweep25x2(
        &epoch_anchor,
        fee,
        &input_leaves,
        &output_leaves,
        is_coinbase,
    );
    (inputs, native)
}

#[test]
fn sweep_spine_wrap_pin_matches_native_hash() {
    let (inputs, native) = fixture(false);
    let circuit = SweepSpineCircuit::build();
    let claimed = compute_sweep_tx_body_hash(&circuit, &inputs);
    assert!(tx_hash_matches_fields(claimed, &native));
}

#[test]
fn sweep_spine_killshot_reductions_consistent_with_native_mle() {
    let (inputs, native) = fixture(false);
    let circuit = SweepSpineCircuit::build();
    let claimed = compute_sweep_tx_body_hash(&circuit, &inputs);
    assert!(tx_hash_matches_fields(claimed, &native));

    let mut ch = Poseidon2bChannel::new();
    let (_proof, reductions) = prove_sweep_spine_killshot(&circuit, &inputs, claimed, &mut ch);

    assert!(discharge_sweep_spine_reductions_native(
        &circuit,
        &inputs,
        &reductions
    ));

    let mle = build_sweep_spine_unified_from_inputs(&circuit, &inputs);
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
fn sweep_spine_killshot_prover_and_verifier_agree_on_reductions() {
    let (inputs, _) = fixture(true);
    let circuit = SweepSpineCircuit::build();
    let claimed = compute_sweep_tx_body_hash(&circuit, &inputs);

    let mut ch_p = Poseidon2bChannel::new();
    let (proof, prover_red) = prove_sweep_spine_killshot(&circuit, &inputs, claimed, &mut ch_p);

    let mut ch_v = Poseidon2bChannel::new();
    let verifier_red = verify_sweep_spine_killshot(&proof, &circuit, &inputs, claimed, &mut ch_v)
        .expect("verifier accepts honest sweep spine proof");

    assert_eq!(prover_red, verifier_red);
}

#[test]
fn sweep_spine_native_discharge_rejects_shape_leaf_tamper_after_proof() {
    let (mut inputs, _) = fixture(false);
    let circuit = SweepSpineCircuit::build();
    let claimed = compute_sweep_tx_body_hash(&circuit, &inputs);

    let mut ch = Poseidon2bChannel::new();
    let (_proof, reductions) = prove_sweep_spine_killshot(&circuit, &inputs, claimed, &mut ch);

    inputs.shape_leaf[0] += Block128::ONE;
    assert!(!discharge_sweep_spine_reductions_native(
        &circuit,
        &inputs,
        &reductions
    ));
}

#[test]
fn sweep_spine_native_discharge_rejects_last_input_tamper_after_proof() {
    let (mut inputs, _) = fixture(false);
    let circuit = SweepSpineCircuit::build();
    let claimed = compute_sweep_tx_body_hash(&circuit, &inputs);

    let mut ch = Poseidon2bChannel::new();
    let (_proof, reductions) = prove_sweep_spine_killshot(&circuit, &inputs, claimed, &mut ch);

    inputs.input_leaves[24][1] += Block128::ONE;
    assert!(!discharge_sweep_spine_reductions_native(
        &circuit,
        &inputs,
        &reductions
    ));
}

#[test]
fn sweep_spine_native_discharge_rejects_second_output_tamper_after_proof() {
    let (mut inputs, _) = fixture(false);
    let circuit = SweepSpineCircuit::build();
    let claimed = compute_sweep_tx_body_hash(&circuit, &inputs);

    let mut ch = Poseidon2bChannel::new();
    let (_proof, reductions) = prove_sweep_spine_killshot(&circuit, &inputs, claimed, &mut ch);

    inputs.output_leaves[1][1] += Block128::ONE;
    assert!(!discharge_sweep_spine_reductions_native(
        &circuit,
        &inputs,
        &reductions
    ));
}
