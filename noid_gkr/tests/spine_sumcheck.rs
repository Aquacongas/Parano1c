// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Stage G2 tests — full-spine sumcheck.
//!
//! Covers:
//!
//! - Honest round-trip on the full 2in/4out-style fixture.
//! - Mutation at 10 different slots (one per distinct role-class).
//! - Mutation on the public output cell (the `claimed_tx_body_hash`
//!   the verifier is told to believe).
//! - Mutation in the boundary inputs (verifier's reconstructed witness
//!   diverges).
//! - Transcript determinism.

use noid_core::transcript::FiatShamir;
use noid_core::Block128;
use noid_gkr::circuit::{SpineCircuit, SpineInputs};
use noid_gkr::spine_sumcheck::{
    compute_tx_body_hash, discharge_boundary_native, prove_spine, verify_spine, SpineProof,
};
use noid_poseidon2b::channel::Poseidon2bChannel;
use noid_poseidon2b::primitives::{
    derive_address, fee_leaf, is_coinbase_leaf, Address, SpendSecret, TXBODY_INPUTS, TXBODY_OUTPUTS,
};

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

fn input_payload(slot: u32, value: u64, owner: &Address) -> [Block128; 4] {
    let mut hi = [0u8; 16];
    let mut lo = [0u8; 16];
    hi.copy_from_slice(&owner.0[..16]);
    lo.copy_from_slice(&owner.0[16..]);
    [
        Block128::from(slot as u128),
        Block128::from(value as u128),
        Block128::from(u128::from_le_bytes(hi)),
        Block128::from(u128::from_le_bytes(lo)),
    ]
}

fn fixture_inputs() -> SpineInputs {
    let addrs: Vec<Address> = (0..4)
        .map(|i| derive_address(&SpendSecret([i as u8 + 1; 32])))
        .collect();

    let input_leaves: [[Block128; 4]; TXBODY_INPUTS] = [
        input_payload(0, 100, &addrs[0]),
        input_payload(1, 200, &addrs[1]),
        input_payload(2, 300, &addrs[2]),
        input_payload(3, 400, &addrs[3]),
    ];
    let output_leaves: [[Block128; 4]; TXBODY_OUTPUTS] = [
        input_payload(10, 50, &addrs[0]),
        input_payload(11, 70, &addrs[1]),
        input_payload(12, 90, &addrs[2]),
        input_payload(13, 110, &addrs[3]),
        input_payload(14, 130, &addrs[0]),
        input_payload(15, 150, &addrs[1]),
        input_payload(16, 170, &addrs[2]),
        input_payload(17, 190, &addrs[3]),
    ];

    let prev = [0xAAu8; 32];
    SpineInputs {
        prev_state_root: digest_to_fields(&prev),
        fee_leaf: digest_to_fields(&fee_leaf(7u128)),
        input_leaves,
        output_leaves,
        is_coinbase_leaf: digest_to_fields(&is_coinbase_leaf(false)),
        pad_leaf: [Block128::from(0u128), Block128::from(0u128)],
    }
}

fn fresh_channel(seed: u64) -> Poseidon2bChannel {
    let mut ch = Poseidon2bChannel::new();
    ch.absorb(Block128::from(seed as u128));
    ch
}

#[test]
fn honest_roundtrip_full_spine() {
    let circuit = SpineCircuit::build();
    let inputs = fixture_inputs();
    let hash = compute_tx_body_hash(&circuit, &inputs);

    let mut p_ch = fresh_channel(1);
    let (proof, _red) = prove_spine(&circuit, &inputs, hash, &mut p_ch);

    let mut v_ch = fresh_channel(1);
    let red = verify_spine(&proof, &circuit, &inputs, hash, &mut v_ch).unwrap();
    assert!(discharge_boundary_native(&circuit, &inputs, &red));
}

#[test]
fn mutation_output_cell_rejects() {
    // Prover honestly proves `hash`; verifier is handed `hash + 1`.
    // The boundary-absorption diverges → verifier recomputes different
    // slot states, and the wrap cross-check disagrees.
    let circuit = SpineCircuit::build();
    let inputs = fixture_inputs();
    let hash = compute_tx_body_hash(&circuit, &inputs);

    let mut p_ch = fresh_channel(2);
    let (proof, _red) = prove_spine(&circuit, &inputs, hash, &mut p_ch);

    let mut bad_hash = hash;
    bad_hash[0] += Block128::from(1u128);

    let mut v_ch = fresh_channel(2);
    assert!(verify_spine(&proof, &circuit, &inputs, bad_hash, &mut v_ch).is_none());
}

#[test]
fn mutation_boundary_input_rejects() {
    // Verifier's view of inputs differs from the prover's → per-slot
    // reconstructed `state_in` diverges → sumcheck claims mismatch.
    let circuit = SpineCircuit::build();
    let inputs = fixture_inputs();
    let hash = compute_tx_body_hash(&circuit, &inputs);

    let mut p_ch = fresh_channel(3);
    let (proof, _red) = prove_spine(&circuit, &inputs, hash, &mut p_ch);

    let mut bad_inputs = inputs.clone();
    bad_inputs.input_leaves[2][1] += Block128::from(1u128);

    // γ₄: no more `absorb_inputs`. Tampered inputs now reach
    // `verify_perm` via reconstructed `state_in`; the verifier's
    // natively-derived `v0 = sout_mle(r0)` diverges from the prover's
    // claim so the per-slot product sumcheck rejects OR the native
    // boundary discharge disagrees. Cover both outcomes.
    let mut v_ch = fresh_channel(3);
    let red = verify_spine(&proof, &circuit, &bad_inputs, hash, &mut v_ch);
    match red {
        None => {}
        Some(r) => assert!(!discharge_boundary_native(&circuit, &bad_inputs, &r)),
    }
}

#[test]
fn mutation_forged_hash_with_consistent_but_wrong_inputs_rejects() {
    // Forging both sides consistently is only possible if the
    // "alternative" inputs actually hash to the forged value. If the
    // attacker picks a forged hash and swaps inputs to something they
    // control, the tx-body spine still pins the two together — we just
    // demonstrate that tampering a single leaf is not enough to
    // rescue the proof.
    let circuit = SpineCircuit::build();
    let inputs = fixture_inputs();
    let hash_a = compute_tx_body_hash(&circuit, &inputs);

    let mut p_ch = fresh_channel(4);
    let (proof, _red) = prove_spine(&circuit, &inputs, hash_a, &mut p_ch);

    let mut bad_inputs = inputs.clone();
    bad_inputs.output_leaves[5][0] += Block128::from(1u128);
    let hash_b = compute_tx_body_hash(&circuit, &bad_inputs);
    assert_ne!(hash_a, hash_b);

    // Mismatched pair A: either verify_spine rejects outright or the
    // native boundary discharge disagrees.
    let mut v1 = fresh_channel(4);
    match verify_spine(&proof, &circuit, &bad_inputs, hash_a, &mut v1) {
        None => {}
        Some(r) => assert!(!discharge_boundary_native(&circuit, &bad_inputs, &r)),
    }
    // Mismatched pair B.
    let mut v2 = fresh_channel(4);
    assert!(verify_spine(&proof, &circuit, &inputs, hash_b, &mut v2).is_none());
}

#[test]
fn mutation_per_slot_proof_rejects() {
    // Tamper each of 10 different slots' sout_x4x3.a_final; every
    // mutation must be caught. This spans input-leaf, output-leaf,
    // compress, and wrap slots.
    let circuit = SpineCircuit::build();
    let inputs = fixture_inputs();
    let hash = compute_tx_body_hash(&circuit, &inputs);

    let mut p_ch = fresh_channel(5);
    let (base, _red) = prove_spine(&circuit, &inputs, hash, &mut p_ch);

    let targets = [0usize, 1, 2, 3, 10, 20, 30, 40, 50, 58];
    for &slot_id in &targets {
        let mut tampered: SpineProof = base.clone();
        tampered.slots[slot_id].sout_x4x3.a_final += Block128::from(1u128);

        let mut v_ch = fresh_channel(5);
        let outcome = verify_spine(&tampered, &circuit, &inputs, hash, &mut v_ch);
        let rejected = match outcome {
            None => true,
            Some(r) => !discharge_boundary_native(&circuit, &inputs, &r),
        };
        assert!(rejected, "mutation on slot {slot_id} must be rejected");
    }
}

#[test]
fn mutation_shuffled_slot_proofs_rejects() {
    // Swap two slot proofs. Either the transcript diverges (verifier
    // rejects at sumcheck) or the reduced claims no longer match the
    // reconstructed per-slot state MLE.
    let circuit = SpineCircuit::build();
    let inputs = fixture_inputs();
    let hash = compute_tx_body_hash(&circuit, &inputs);

    let mut p_ch = fresh_channel(6);
    let (mut proof, _red) = prove_spine(&circuit, &inputs, hash, &mut p_ch);

    proof.slots.swap(5, 25);

    let mut v_ch = fresh_channel(6);
    let outcome = verify_spine(&proof, &circuit, &inputs, hash, &mut v_ch);
    let rejected = match outcome {
        None => true,
        Some(r) => !discharge_boundary_native(&circuit, &inputs, &r),
    };
    assert!(rejected);
}

#[test]
fn transcript_determinism_full_spine() {
    let circuit = SpineCircuit::build();
    let inputs = fixture_inputs();
    let hash = compute_tx_body_hash(&circuit, &inputs);

    let mut c1 = fresh_channel(7);
    let (p1, r1) = prove_spine(&circuit, &inputs, hash, &mut c1);
    let mut c2 = fresh_channel(7);
    let (p2, r2) = prove_spine(&circuit, &inputs, hash, &mut c2);

    assert_eq!(p1, p2);
    assert_eq!(r1, r2);
}

#[test]
fn slot_count_matches_circuit() {
    let circuit = SpineCircuit::build();
    let inputs = fixture_inputs();
    let hash = compute_tx_body_hash(&circuit, &inputs);

    let mut p_ch = fresh_channel(8);
    let (proof, _red) = prove_spine(&circuit, &inputs, hash, &mut p_ch);
    assert_eq!(proof.slots.len(), circuit.slots.len());
    assert_eq!(proof.slots.len(), 59);
}
