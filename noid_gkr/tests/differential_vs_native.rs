// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Stage G0 differential test.
//!
//! Runs the reference spine oracle in `noid_gkr` on a handful of
//! fixtures and asserts its output byte-equals
//! `noid_poseidon2b::primitives::hash_tx_body`. This is the contract
//! every later GKR stage must preserve.
//!
//! Note: the Stage G0 oracle always hashes payload pre-images for
//! every leaf slot (it doesn't model "dummy slots with zero digest").
//! Every test therefore fills all 4 input + 8 output slots with real
//! payloads — which is also the most adversarial shape (full tree).

use noid_core::Block128;
use noid_gkr::circuit::{SpineCircuit, SpineInputs};
use noid_gkr::oracle::evaluate_spine;
use noid_poseidon2b::native::domain::{capacity_iv, TAG_LEAF, TAG_OUTLEAF, TAG_TXBODY};
use noid_poseidon2b::native::permutation::Poseidon2bPermutation;
use noid_poseidon2b::primitives::{
    derive_address, fee_leaf, hash_input_leaf, hash_output_leaf, hash_tx_body, is_coinbase_leaf,
    Address, Digest, SpendSecret, TxBodyHash, TXBODY_INPUTS, TXBODY_OUTPUTS,
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

fn input_payload_u128(slot: u32, value: u64, owner: &Address) -> [u128; 4] {
    let mut hi = [0u8; 16];
    let mut lo = [0u8; 16];
    hi.copy_from_slice(&owner.0[..16]);
    lo.copy_from_slice(&owner.0[16..]);
    [
        slot as u128,
        value as u128,
        u128::from_le_bytes(hi),
        u128::from_le_bytes(lo),
    ]
}

fn payload_to_lanes(p: [u128; 4]) -> [Block128; 4] {
    [
        Block128::from(p[0]),
        Block128::from(p[1]),
        Block128::from(p[2]),
        Block128::from(p[3]),
    ]
}

fn make_full_inputs(
    prev: &Digest,
    fee: u128,
    inputs_leaf_payload: [[u128; 4]; TXBODY_INPUTS],
    outputs_leaf_payload: [[u128; 4]; TXBODY_OUTPUTS],
    is_coinbase: bool,
) -> SpineInputs {
    SpineInputs {
        prev_state_root: digest_to_fields(prev),
        fee_leaf: digest_to_fields(&fee_leaf(fee)),
        input_leaves: [
            payload_to_lanes(inputs_leaf_payload[0]),
            payload_to_lanes(inputs_leaf_payload[1]),
            payload_to_lanes(inputs_leaf_payload[2]),
            payload_to_lanes(inputs_leaf_payload[3]),
        ],
        output_leaves: [
            payload_to_lanes(outputs_leaf_payload[0]),
            payload_to_lanes(outputs_leaf_payload[1]),
            payload_to_lanes(outputs_leaf_payload[2]),
            payload_to_lanes(outputs_leaf_payload[3]),
            payload_to_lanes(outputs_leaf_payload[4]),
            payload_to_lanes(outputs_leaf_payload[5]),
            payload_to_lanes(outputs_leaf_payload[6]),
            payload_to_lanes(outputs_leaf_payload[7]),
        ],
        is_coinbase_leaf: digest_to_fields(&is_coinbase_leaf(is_coinbase)),
        pad_leaf: [Block128::from(0u128), Block128::from(0u128)],
    }
}

fn fixture_full(is_coinbase: bool) -> (SpineInputs, TxBodyHash) {
    let addrs: Vec<Address> = (0..4)
        .map(|i| derive_address(&SpendSecret([i as u8 + 1; 32])))
        .collect();

    let inputs_payload: [[u128; 4]; TXBODY_INPUTS] = [
        input_payload_u128(0, 100, &addrs[0]),
        input_payload_u128(1, 200, &addrs[1]),
        input_payload_u128(2, 300, &addrs[2]),
        input_payload_u128(3, 400, &addrs[3]),
    ];
    let outputs_payload: [[u128; 4]; TXBODY_OUTPUTS] = [
        input_payload_u128(10, 50, &addrs[0]),
        input_payload_u128(11, 70, &addrs[1]),
        input_payload_u128(12, 90, &addrs[2]),
        input_payload_u128(13, 110, &addrs[3]),
        input_payload_u128(14, 130, &addrs[0]),
        input_payload_u128(15, 150, &addrs[1]),
        input_payload_u128(16, 170, &addrs[2]),
        input_payload_u128(17, 190, &addrs[3]),
    ];

    // Native leaves:
    let ins_d: [Digest; TXBODY_INPUTS] = [
        hash_input_leaf(0, 100, &addrs[0]),
        hash_input_leaf(1, 200, &addrs[1]),
        hash_input_leaf(2, 300, &addrs[2]),
        hash_input_leaf(3, 400, &addrs[3]),
    ];
    let outs_d: [Digest; TXBODY_OUTPUTS] = [
        hash_output_leaf(10, 50, &addrs[0]),
        hash_output_leaf(11, 70, &addrs[1]),
        hash_output_leaf(12, 90, &addrs[2]),
        hash_output_leaf(13, 110, &addrs[3]),
        hash_output_leaf(14, 130, &addrs[0]),
        hash_output_leaf(15, 150, &addrs[1]),
        hash_output_leaf(16, 170, &addrs[2]),
        hash_output_leaf(17, 190, &addrs[3]),
    ];

    let prev = [0xAAu8; 32];
    let fee = 7u128;
    let native = hash_tx_body(&prev, fee, &ins_d, &outs_d, is_coinbase);

    let inputs = make_full_inputs(&prev, fee, inputs_payload, outputs_payload, is_coinbase);
    (inputs, native)
}

#[test]
fn full_tx_matches_native() {
    let (inputs, native) = fixture_full(false);
    let circuit = SpineCircuit::build();
    let wit = evaluate_spine(&circuit, &inputs);

    assert_eq!(
        wit.tx_body_hash_bytes(),
        native.0,
        "GKR oracle output must byte-equal native hash_tx_body",
    );
}

#[test]
fn is_coinbase_flag_propagates_end_to_end() {
    let (inp_reg, native_reg) = fixture_full(false);
    let (inp_cb, native_cb) = fixture_full(true);
    assert_ne!(native_reg.0, native_cb.0);

    let circuit = SpineCircuit::build();
    let wit_reg = evaluate_spine(&circuit, &inp_reg);
    let wit_cb = evaluate_spine(&circuit, &inp_cb);
    assert_eq!(wit_reg.tx_body_hash_bytes(), native_reg.0);
    assert_eq!(wit_cb.tx_body_hash_bytes(), native_cb.0);
    assert_ne!(wit_reg.tx_body_hash_bytes(), wit_cb.tx_body_hash_bytes());
}

#[test]
fn mutating_input_value_changes_hash_in_both_paths() {
    let (mut inputs, _native) = fixture_full(false);

    // Baseline oracle result.
    let circuit = SpineCircuit::build();
    let wit_a = evaluate_spine(&circuit, &inputs);

    // Flip the value on input leaf 2 (lane 1 of that payload).
    let original = inputs.input_leaves[2][1];
    inputs.input_leaves[2][1] = original + Block128::from(1u128);
    let wit_b = evaluate_spine(&circuit, &inputs);
    assert_ne!(wit_a.tx_body_hash, wit_b.tx_body_hash);
}

#[test]
fn wrap_stage_is_tag_txbody() {
    let (inputs, _native) = fixture_full(false);
    let circuit = SpineCircuit::build();
    let wit = evaluate_spine(&circuit, &inputs);

    let wrap_idx = circuit.wrap_id();
    let wrap = wit.slots[wrap_idx];
    let iv = capacity_iv(TAG_TXBODY);
    assert_eq!(wrap.state_in[2], iv[0]);
    assert_eq!(wrap.state_in[3], iv[1]);

    let root_lanes = [wrap.state_in[0], wrap.state_in[1]];
    let mut state = [root_lanes[0], root_lanes[1], iv[0], iv[1]];
    Poseidon2bPermutation.permute_mut(&mut state);
    assert_eq!([state[0], state[1]], wit.tx_body_hash);

    // Domain separation between input-leaf and output-leaf IVs.
    assert_ne!(capacity_iv(TAG_LEAF), capacity_iv(TAG_OUTLEAF));
}

#[test]
fn slot_count_is_59() {
    let circuit = SpineCircuit::build();
    assert_eq!(circuit.slots.len(), 59);
}
