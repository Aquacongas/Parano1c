// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Stage G5 fuzz — topology-preserving random inputs compared
//! native vs GKR oracle.
//!
//! Each iteration rolls fresh: epoch_anchor, fee, is_coinbase, 4
//! input leaves (slot/value/owner), 8 output leaves (slot/value/owner).
//! The GKR oracle re-executes the 59-slot spine via the native
//! Poseidon2b implementation; we assert byte-equality against
//! `primitives::hash_tx_body`. Any drift between the two paths shows
//! up as a mismatched digest.
//!
//! Default iteration count is 1024 to keep `cargo test` under a
//! minute on the reference machine. The spec target is 10_000 — set
//! `GKR_FUZZ_ITERS=10000` (or any positive integer) to raise the
//! iteration count.

use std::env;

use noid_core::Block128;
use noid_gkr::circuit::{SpineCircuit, SpineInputs};
use noid_gkr::oracle::evaluate_spine;
use noid_poseidon2b::primitives::{
    derive_address, fee_leaf, hash_input_leaf, hash_output_leaf, hash_tx_body, is_coinbase_leaf,
    Address, Digest, SpendSecret, TxBodyHash, TXBODY_INPUTS, TXBODY_OUTPUTS,
};
use rand::rngs::StdRng;
use rand::{Rng, RngCore, SeedableRng};

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

fn payload_lanes(slot: u32, value: u64, owner: &Address) -> [Block128; 4] {
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

fn rand_secret(rng: &mut StdRng) -> SpendSecret {
    let mut b = [0u8; 32];
    rng.fill_bytes(&mut b);
    SpendSecret(b)
}

fn rand_digest(rng: &mut StdRng) -> Digest {
    let mut b = [0u8; 32];
    rng.fill_bytes(&mut b);
    b
}

fn iters() -> usize {
    match env::var("GKR_FUZZ_ITERS") {
        Ok(v) => v.parse::<usize>().unwrap_or(1024).max(1),
        Err(_) => 1024,
    }
}

#[test]
fn gkr_oracle_matches_native_over_random_fixtures() {
    let mut rng = StdRng::seed_from_u64(0xD1FF_E7E7_71A1_11A1u64);
    let circuit = SpineCircuit::build();
    let n = iters();

    for i in 0..n {
        let prev = rand_digest(&mut rng);
        let fee: u128 = rng.gen();
        let is_coinbase: bool = rng.gen();

        let owners: Vec<Address> = (0..8)
            .map(|_| derive_address(&rand_secret(&mut rng)))
            .collect();

        let mut in_slots = [0u32; TXBODY_INPUTS];
        let mut in_values = [0u64; TXBODY_INPUTS];
        let mut out_slots = [0u32; TXBODY_OUTPUTS];
        let mut out_values = [0u64; TXBODY_OUTPUTS];
        for k in 0..TXBODY_INPUTS {
            in_slots[k] = rng.gen();
            in_values[k] = rng.gen();
        }
        for k in 0..TXBODY_OUTPUTS {
            out_slots[k] = rng.gen();
            out_values[k] = rng.gen();
        }

        let input_leaves_payload: [[Block128; 4]; TXBODY_INPUTS] = [
            payload_lanes(in_slots[0], in_values[0], &owners[0]),
            payload_lanes(in_slots[1], in_values[1], &owners[1]),
            payload_lanes(in_slots[2], in_values[2], &owners[2]),
            payload_lanes(in_slots[3], in_values[3], &owners[3]),
        ];
        let output_leaves_payload: [[Block128; 4]; TXBODY_OUTPUTS] = [
            payload_lanes(out_slots[0], out_values[0], &owners[0]),
            payload_lanes(out_slots[1], out_values[1], &owners[1]),
            payload_lanes(out_slots[2], out_values[2], &owners[2]),
            payload_lanes(out_slots[3], out_values[3], &owners[3]),
            payload_lanes(out_slots[4], out_values[4], &owners[4]),
            payload_lanes(out_slots[5], out_values[5], &owners[5]),
            payload_lanes(out_slots[6], out_values[6], &owners[6]),
            payload_lanes(out_slots[7], out_values[7], &owners[7]),
        ];

        let ins_d: [Digest; TXBODY_INPUTS] = [
            hash_input_leaf(in_slots[0], in_values[0], &owners[0]),
            hash_input_leaf(in_slots[1], in_values[1], &owners[1]),
            hash_input_leaf(in_slots[2], in_values[2], &owners[2]),
            hash_input_leaf(in_slots[3], in_values[3], &owners[3]),
        ];
        let outs_d: [Digest; TXBODY_OUTPUTS] = [
            hash_output_leaf(out_slots[0], out_values[0], &owners[0]),
            hash_output_leaf(out_slots[1], out_values[1], &owners[1]),
            hash_output_leaf(out_slots[2], out_values[2], &owners[2]),
            hash_output_leaf(out_slots[3], out_values[3], &owners[3]),
            hash_output_leaf(out_slots[4], out_values[4], &owners[4]),
            hash_output_leaf(out_slots[5], out_values[5], &owners[5]),
            hash_output_leaf(out_slots[6], out_values[6], &owners[6]),
            hash_output_leaf(out_slots[7], out_values[7], &owners[7]),
        ];

        let native: TxBodyHash = hash_tx_body(&prev, fee, &ins_d, &outs_d, is_coinbase);

        let inputs = SpineInputs {
            epoch_anchor: digest_to_fields(&prev),
            fee_leaf: digest_to_fields(&fee_leaf(fee)),
            input_leaves: input_leaves_payload,
            output_leaves: output_leaves_payload,
            is_coinbase_leaf: digest_to_fields(&is_coinbase_leaf(is_coinbase)),
            pad_leaf: [Block128::from(0u128), Block128::from(0u128)],
        };

        let wit = evaluate_spine(&circuit, &inputs);
        assert_eq!(
            wit.tx_body_hash_bytes(),
            native.0,
            "GKR oracle drift at iteration {i}",
        );
    }
}
