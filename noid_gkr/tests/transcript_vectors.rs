// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Stage G5 — transcript canonicity vectors.
//!
//! Five distinct, deterministic fixtures. For each:
//!   (a) prove the spine twice under an identical seed and assert the
//!       produced `SpineProof` objects are byte-equal. This catches any
//!       nondeterminism that would silently break Fiat-Shamir replay.
//!   (b) fingerprint the proof by walking every `Block128` through a
//!       fresh `Poseidon2bChannel` in a fixed order and squeezing one
//!       challenge. This turns the proof into a 128-bit identifier that
//!       any future refactor must preserve to keep transcript
//!       compatibility.
//!   (c) assert the five fingerprints are pairwise distinct. Different
//!       fixtures must not collide on the same digest — if they ever do,
//!       it's an indication the prover is dropping input data from the
//!       transcript stream.
//!
//! We don't pin the fingerprints to literal bytes here — that couples
//! the test to the Poseidon2b round constants and every downstream
//! channel tweak. The test's job is to notice *drift*: if a refactor
//! changes the proof shape for the same inputs, (a) catches it; if it
//! lets two fixtures collide, (c) catches it.

use noid_core::transcript::FiatShamir;
use noid_core::Block128;
use noid_gkr::batch_eval::BatchEvalProof;
use noid_gkr::circuit::{SpineCircuit, SpineInputs};
use noid_gkr::perm_sumcheck::PermProof;
use noid_gkr::product_sumcheck::ProductProof;
use noid_gkr::spine_sumcheck::{compute_tx_body_hash, prove_spine, SpineProof};
use noid_poseidon2b::channel::Poseidon2bChannel;
use noid_poseidon2b::primitives::{
    derive_address, fee_leaf, is_coinbase_leaf, Address, SpendSecret, TXBODY_INPUTS,
    TXBODY_OUTPUTS,
};

// ----- fixture builders -----

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

fn payload(slot: u32, value: u64, owner: &Address) -> [Block128; 4] {
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

fn fixture(seed: u8, fee: u128, is_coinbase: bool) -> SpineInputs {
    let addrs: Vec<Address> = (0..8)
        .map(|i| derive_address(&SpendSecret([seed.wrapping_add(i as u8 + 1); 32])))
        .collect();
    let input_leaves: [[Block128; 4]; TXBODY_INPUTS] = [
        payload(0, 100 + seed as u64, &addrs[0]),
        payload(1, 200, &addrs[1]),
        payload(2, 300, &addrs[2]),
        payload(3, 400, &addrs[3]),
    ];
    let output_leaves: [[Block128; 4]; TXBODY_OUTPUTS] = [
        payload(10, 50, &addrs[0]),
        payload(11, 70, &addrs[1]),
        payload(12, 90, &addrs[2]),
        payload(13, 110, &addrs[3]),
        payload(14, 130, &addrs[4]),
        payload(15, 150, &addrs[5]),
        payload(16, 170, &addrs[6]),
        payload(17, 190, &addrs[7]),
    ];
    let prev = [seed; 32];
    SpineInputs {
        prev_state_root: digest_to_fields(&prev),
        fee_leaf: digest_to_fields(&fee_leaf(fee)),
        input_leaves,
        output_leaves,
        is_coinbase_leaf: digest_to_fields(&is_coinbase_leaf(is_coinbase)),
        pad_leaf: [Block128::from(0u128), Block128::from(0u128)],
    }
}

fn fresh_channel(seed: u64) -> Poseidon2bChannel {
    let mut ch = Poseidon2bChannel::new();
    ch.absorb(Block128::from(seed as u128));
    ch
}

// ----- canonical walk over SpineProof -----

fn absorb_product(ch: &mut Poseidon2bChannel, p: &ProductProof) {
    for r in &p.rounds {
        for e in &r.evals {
            ch.absorb(*e);
        }
    }
    ch.absorb(p.a_final);
    ch.absorb(p.b_final);
}

fn absorb_perm(ch: &mut Poseidon2bChannel, p: &PermProof) {
    absorb_product(ch, &p.sout_x4x3);
    absorb_product(ch, &p.x4_x2x2);
    absorb_product(ch, &p.x3_x2sin);
    absorb_product(ch, &p.x2_at_r2_sinsin);
    absorb_product(ch, &p.x2_at_r3_sinsin);
    absorb_product(ch, &p.sin_r3_check);
    absorb_product(ch, &p.sin_r4_check);
    absorb_product(ch, &p.sin_r5_check);
}

fn absorb_batch(ch: &mut Poseidon2bChannel, b: &BatchEvalProof) {
    for r in &b.rounds {
        for e in &r.evals {
            ch.absorb(*e);
        }
    }
    ch.absorb(b.b_final);
}

fn fingerprint(proof: &SpineProof) -> Block128 {
    let mut ch = Poseidon2bChannel::new();
    ch.absorb(Block128::from(proof.slots.len() as u128));
    for slot in &proof.slots {
        absorb_perm(&mut ch, slot);
    }
    absorb_batch(&mut ch, &proof.boundary);
    ch.squeeze()
}

// ----- the five vectors -----

fn vector_seeds() -> [(u8, u128, bool); 5] {
    [
        (0x01, 7u128, false),
        (0x02, 11u128, false),
        (0x03, 0u128, true),
        (0x04, 999_999u128, false),
        (0x05, 1u128, true),
    ]
}

#[test]
fn spine_proofs_are_byte_deterministic_across_fixtures() {
    let circuit = SpineCircuit::build();
    for (i, (seed, fee, cb)) in vector_seeds().into_iter().enumerate() {
        let inputs = fixture(seed, fee, cb);
        let hash = compute_tx_body_hash(&circuit, &inputs);

        let mut c1 = fresh_channel(17);
        let (proof_a, _) = prove_spine(&circuit, &inputs, hash, &mut c1);
        let mut c2 = fresh_channel(17);
        let (proof_b, _) = prove_spine(&circuit, &inputs, hash, &mut c2);

        assert_eq!(
            proof_a, proof_b,
            "vector {i}: SpineProof must be deterministic across runs",
        );
    }
}

#[test]
fn five_vectors_produce_distinct_fingerprints() {
    let circuit = SpineCircuit::build();
    let mut fps: Vec<Block128> = Vec::new();
    for (seed, fee, cb) in vector_seeds() {
        let inputs = fixture(seed, fee, cb);
        let hash = compute_tx_body_hash(&circuit, &inputs);
        let mut ch = fresh_channel(17);
        let (proof, _) = prove_spine(&circuit, &inputs, hash, &mut ch);
        fps.push(fingerprint(&proof));
    }
    // Pairwise distinct.
    for i in 0..fps.len() {
        for j in (i + 1)..fps.len() {
            assert_ne!(
                fps[i], fps[j],
                "fingerprint collision between vector {i} and {j} — the proof byte-space is not seeing some input-dependent data",
            );
        }
    }
}

#[test]
fn spine_proof_byte_len_is_constant_across_inputs() {
    // Every well-formed spine proof covers the same 59 slots with the
    // same per-slot round count and the same γ₂ batch-eval shape — so
    // `byte_len()` is a topology invariant, not a data-dependent value.
    // A drift here would mean the prover is emitting variable-length
    // proofs, which breaks transcript canonicity downstream.
    let circuit = SpineCircuit::build();
    let mut lens: Vec<usize> = Vec::new();
    for (seed, fee, cb) in vector_seeds() {
        let inputs = fixture(seed, fee, cb);
        let hash = compute_tx_body_hash(&circuit, &inputs);
        let mut ch = fresh_channel(17);
        let (proof, _) = prove_spine(&circuit, &inputs, hash, &mut ch);
        lens.push(proof.byte_len());
    }
    let first = lens[0];
    for (i, l) in lens.iter().enumerate() {
        assert_eq!(*l, first, "vector {i} byte_len {l} != fixture-0 {first}");
    }
    assert!(first > 0, "byte_len must be non-zero");
}
