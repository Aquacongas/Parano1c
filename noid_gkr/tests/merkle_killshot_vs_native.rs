// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Integration test: Merkle Kill-Shot GKR produces the same root as
//! native `noid_poseidon2b::native::compress` and the proof verifies.

use noid_core::{Block128, CanonicalSerialize, TowerField};
use noid_gkr::merkle_circuit::MerklePathInputs;
use noid_gkr::merkle_circuit::{MerkleCircuit, MAX_MERKLE_DEPTH};
use noid_gkr::merkle_killshot::{
    discharge_merkle_reductions_native, prove_merkle_killshot, verify_merkle_killshot,
};
use noid_gkr::merkle_oracle::compute_merkle_root;
use noid_poseidon2b::channel::Poseidon2bChannel;
use noid_poseidon2b::native::compress;

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

fn fields_to_digest(f: [Block128; 2]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[..16].copy_from_slice(&f[0].to_bytes());
    out[16..].copy_from_slice(&f[1].to_bytes());
    out
}

fn build_path(leaf: &[u8; 32], siblings: &[[u8; 32]], depth: usize) -> MerklePathInputs {
    let mut current = *leaf;
    for i in 0..depth {
        current = compress(&current, &siblings[i]);
    }
    let mut sibling_fields = [[Block128::ZERO; 2]; MAX_MERKLE_DEPTH];
    for i in 0..depth {
        sibling_fields[i] = digest_to_fields(&siblings[i]);
    }
    MerklePathInputs {
        leaf: digest_to_fields(leaf),
        siblings: sibling_fields,
        expected_root: digest_to_fields(&current),
        active_depth: depth,
    }
}

#[test]
fn oracle_matches_native_compress_chain() {
    let circuit = MerkleCircuit::build();
    let leaf = [0x01u8; 32];
    let siblings: Vec<[u8; 32]> = (0..8).map(|i| [(i + 10) as u8; 32]).collect();

    let mut native_root = leaf;
    for s in &siblings {
        native_root = compress(&native_root, s);
    }

    let sibling_fields: Vec<[Block128; 2]> = siblings.iter().map(|s| digest_to_fields(s)).collect();
    let gkr_root = compute_merkle_root(&circuit, digest_to_fields(&leaf), &sibling_fields, 8);

    assert_eq!(fields_to_digest(gkr_root), native_root);
}

#[test]
fn killshot_prove_verify_depth_8() {
    let circuit = MerkleCircuit::build();
    let leaf = [0x77u8; 32];
    let siblings: Vec<[u8; 32]> = (0..8).map(|i| [(i * 3 + 5) as u8; 32]).collect();
    let inputs = build_path(&leaf, &siblings, 8);

    let mut ch_p = Poseidon2bChannel::new();
    let (proof, reductions) = prove_merkle_killshot(&circuit, &inputs, &mut ch_p);

    let mut ch_v = Poseidon2bChannel::new();
    let v_red =
        verify_merkle_killshot(&proof, &inputs, &mut ch_v).expect("verifier accepts honest proof");

    assert_eq!(v_red, reductions);
    assert!(discharge_merkle_reductions_native(
        &circuit, &inputs, &v_red
    ));
}

#[test]
fn killshot_prove_verify_depth_1() {
    let circuit = MerkleCircuit::build();
    let leaf = [0xFFu8; 32];
    let siblings: Vec<[u8; 32]> = vec![[0xEEu8; 32]];
    let inputs = build_path(&leaf, &siblings, 1);

    let mut ch_p = Poseidon2bChannel::new();
    let (proof, reductions) = prove_merkle_killshot(&circuit, &inputs, &mut ch_p);

    let mut ch_v = Poseidon2bChannel::new();
    let v_red =
        verify_merkle_killshot(&proof, &inputs, &mut ch_v).expect("verifier accepts honest proof");

    assert_eq!(v_red, reductions);
    assert!(discharge_merkle_reductions_native(
        &circuit, &inputs, &v_red
    ));
}

#[test]
fn killshot_prove_verify_depth_16() {
    let circuit = MerkleCircuit::build();
    let leaf = [0xABu8; 32];
    let siblings: Vec<[u8; 32]> = (0..16).map(|i| [(i * 7 + 13) as u8; 32]).collect();
    let inputs = build_path(&leaf, &siblings, 16);

    let mut ch_p = Poseidon2bChannel::new();
    let (proof, reductions) = prove_merkle_killshot(&circuit, &inputs, &mut ch_p);

    let mut ch_v = Poseidon2bChannel::new();
    let v_red =
        verify_merkle_killshot(&proof, &inputs, &mut ch_v).expect("verifier accepts honest proof");

    assert_eq!(v_red, reductions);
    assert!(discharge_merkle_reductions_native(
        &circuit, &inputs, &v_red
    ));
}

#[test]
fn killshot_rejects_wrong_sibling() {
    let circuit = MerkleCircuit::build();
    let leaf = [0x33u8; 32];
    let siblings: Vec<[u8; 32]> = (0..4).map(|i| [(i + 20) as u8; 32]).collect();
    let inputs = build_path(&leaf, &siblings, 4);

    let mut ch_p = Poseidon2bChannel::new();
    let (proof, _) = prove_merkle_killshot(&circuit, &inputs, &mut ch_p);

    // Tamper with a sibling → channel diverges
    let mut bad_inputs = inputs.clone();
    bad_inputs.siblings[1][0] += Block128::ONE;

    let mut ch_v = Poseidon2bChannel::new();
    assert!(verify_merkle_killshot(&proof, &bad_inputs, &mut ch_v).is_none());
}

#[test]
fn killshot_rejects_wrong_root() {
    let circuit = MerkleCircuit::build();
    let leaf = [0x55u8; 32];
    let siblings: Vec<[u8; 32]> = (0..6).map(|i| [(i + 40) as u8; 32]).collect();
    let inputs = build_path(&leaf, &siblings, 6);

    let mut ch_p = Poseidon2bChannel::new();
    let (proof, _) = prove_merkle_killshot(&circuit, &inputs, &mut ch_p);

    let mut bad_inputs = inputs.clone();
    bad_inputs.expected_root[1] += Block128::ONE;

    let mut ch_v = Poseidon2bChannel::new();
    assert!(verify_merkle_killshot(&proof, &bad_inputs, &mut ch_v).is_none());
}
