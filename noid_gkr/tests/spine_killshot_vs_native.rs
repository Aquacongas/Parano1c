// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Kill-Shot differential against the native oracle.
//!
//! Three guarantees this suite pins:
//!
//! 1. The Kill-Shot prover honours `claimed_tx_body_hash` against the
//!    native `hash_tx_body` (extends `differential_vs_native.rs`).
//! 2. Every reduction returned by the prover (`state`, `s_in`, `s_out`)
//!    is consistent with native MLE evaluation. Equivalent to running
//!    `discharge_reductions_native` end-to-end.
//! 3. Every reduction returned by the verifier matches what the
//!    prover emitted bit-for-bit (transcript determinism).
//!
//! Tamper coverage lives in `spine_killshot.rs` unit tests; this
//! integration test focuses on the native cross-check.

use noid_core::Block128;
use noid_gkr::{
    build_unified_from_inputs, compute_tx_body_hash, discharge_reductions_native,
    prove_spine_killshot, verify_spine_killshot, SpineCircuit, SpineInputs,
};
use noid_poseidon2b::channel::Poseidon2bChannel;
use noid_poseidon2b::primitives::{
    derive_address, fee_leaf, hash_input_leaf_packed, hash_output_leaf, hash_tx_body,
    is_coinbase_leaf, Address, Digest, SpendSecret, TxBodyHash, TXBODY_INPUTS, TXBODY_OUTPUTS,
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

fn fixture(is_coinbase: bool) -> (SpineInputs, TxBodyHash) {
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

    let ins_d: [Digest; TXBODY_INPUTS] = [
        hash_input_leaf_packed(0, Block128::from(100u128), &addrs[0]),
        hash_input_leaf_packed(1, Block128::from(200u128), &addrs[1]),
        hash_input_leaf_packed(2, Block128::from(300u128), &addrs[2]),
        hash_input_leaf_packed(3, Block128::from(400u128), &addrs[3]),
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
    let native = hash_tx_body(&prev, fee, &ins_d, &outs_d, is_coinbase, 0);

    let inputs = SpineInputs {
        epoch_anchor: digest_to_fields(&prev),
        fee_leaf: digest_to_fields(&fee_leaf(fee)),
        input_leaves: [
            payload_to_lanes(inputs_payload[0]),
            payload_to_lanes(inputs_payload[1]),
            payload_to_lanes(inputs_payload[2]),
            payload_to_lanes(inputs_payload[3]),
        ],
        output_leaves: [
            payload_to_lanes(outputs_payload[0]),
            payload_to_lanes(outputs_payload[1]),
            payload_to_lanes(outputs_payload[2]),
            payload_to_lanes(outputs_payload[3]),
            payload_to_lanes(outputs_payload[4]),
            payload_to_lanes(outputs_payload[5]),
            payload_to_lanes(outputs_payload[6]),
            payload_to_lanes(outputs_payload[7]),
        ],
        is_coinbase_leaf: digest_to_fields(&is_coinbase_leaf(is_coinbase)),
        pad_leaf: [Block128::from(0u128), Block128::from(0u128)],
    };
    (inputs, native)
}

fn lanes_match_native_digest(lanes: &[Block128; 2], digest: &Digest) -> bool {
    let mut a = [0u8; 16];
    let mut b = [0u8; 16];
    a.copy_from_slice(&digest[..16]);
    b.copy_from_slice(&digest[16..]);
    lanes[0] == Block128::from(u128::from_le_bytes(a))
        && lanes[1] == Block128::from(u128::from_le_bytes(b))
}

#[test]
fn killshot_wrap_pin_matches_native_hash() {
    let (inputs, native) = fixture(false);
    let circuit = SpineCircuit::build();
    let claimed = compute_tx_body_hash(&circuit, &inputs);
    assert!(lanes_match_native_digest(&claimed, &native.0));
}

#[test]
fn killshot_reductions_consistent_with_native_mle() {
    let (inputs, native) = fixture(false);
    let circuit = SpineCircuit::build();
    let claimed = compute_tx_body_hash(&circuit, &inputs);
    assert!(lanes_match_native_digest(&claimed, &native.0));

    let mut ch = Poseidon2bChannel::new();
    let (_proof, reductions) = prove_spine_killshot(&circuit, &inputs, claimed, &mut ch);

    // Native discharge must accept every reduction.
    assert!(discharge_reductions_native(&circuit, &inputs, &reductions));

    // And the underlying MLE values must equal what the reductions
    // claim — covered by `discharge_reductions_native`, but we
    // re-evaluate explicitly to pin the contract.
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
fn killshot_prover_and_verifier_agree_on_reductions() {
    let (inputs, _) = fixture(true);
    let circuit = SpineCircuit::build();
    let claimed = compute_tx_body_hash(&circuit, &inputs);

    let mut ch_p = Poseidon2bChannel::new();
    let (proof, prover_red) = prove_spine_killshot(&circuit, &inputs, claimed, &mut ch_p);

    let mut ch_v = Poseidon2bChannel::new();
    let verifier_red =
        verify_spine_killshot(&proof, &circuit, &inputs, claimed, &mut ch_v).expect("verify");

    assert_eq!(prover_red, verifier_red);
}

#[test]
fn killshot_rejects_input_payload_tamper_after_proof() {
    // Build an honest proof, then mutate `inputs` (simulating a
    // man-in-the-middle who swapped the underlying tx-body).
    //
    // In debug builds the verifier's belt-and-braces check
    // `compute_tx_body_hash(circuit, inputs) == claimed` catches it.
    // In release builds the GKR verifier alone cannot detect this —
    // input binding is enforced by the FRI commitment to the boundary
    // MLE in production. The native discharge check below works in
    // both profiles.
    let (mut inputs, _native) = fixture(false);
    let circuit = SpineCircuit::build();
    let claimed = compute_tx_body_hash(&circuit, &inputs);

    let mut ch_p = Poseidon2bChannel::new();
    let (_proof, reductions) = prove_spine_killshot(&circuit, &inputs, claimed, &mut ch_p);

    // Flip one lane after proof generation.
    inputs.input_leaves[2][1] += Block128::from(1u128);

    // Native discharge with tampered inputs must reject — the
    // reductions were computed from the honest MLE, not the tampered one.
    assert!(
        !discharge_reductions_native(&circuit, &inputs, &reductions),
        "native discharge must reject tampered inputs"
    );
}
