// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Canonical transaction-body hash. CRYPTO.md §5.7 and §7.1.
//!
//! Leaf order (all 32-byte canonical values, passthrough into the
//! COMPRESS-domain Merkle tree):
//!
//! 1. `prev_state_root`
//! 2. `fee_leaf = le_bytes_u128(fee) || [0u8; 16]`
//! 3. `input.commitment` for each input (passthrough)
//! 4. `output_leaf = compress(commitment, compress(salt_leaf, scan_tag))`
//!    for each output — §7.1 binding extension. `salt_leaf =
//!    le_bytes_u128(salt.to_u128()) || [0u8; 16]`.
//!
//! The leaf set is padded with `ZERO_DIGEST` to the next power of two
//! (minimum 2), reduced by `compress`, and wrapped once under
//! `TXBODY__`.

use noid_core::{Block128, CanonicalSerialize};
use noid_poseidon2b::native::compress;
use noid_poseidon2b::native::domain::{capacity_iv, TAG_TXBODY};
use noid_poseidon2b::native::permutation::Poseidon2bPermutation;
use noid_poseidon2b::primitives::{Digest, TxBodyHash};

use crate::types::{TxInput, TxOutput};

/// Encode a 128-bit scalar as a 32-byte canonical Merkle leaf.
/// `le_bytes(scalar) || [0u8; 16]`. CRYPTO.md §4.
fn scalar_leaf_u128(v: u128) -> Digest {
    let mut out = [0u8; 32];
    out[..16].copy_from_slice(&v.to_le_bytes());
    out
}

/// Per-output leaf for the tx-body Merkle. CRYPTO.md §7.1.
fn output_leaf(out: &TxOutput) -> Digest {
    let salt_leaf = scalar_leaf_u128(out.salt.to_u128());
    let inner = compress(&salt_leaf, out.scan_tag.as_bytes());
    compress(out.commitment.as_bytes(), &inner)
}

/// Compute the canonical transaction-body hash.
///
/// Inputs are passthrough 32-byte commitments. Outputs are bound as
/// per §7.1 so a relay cannot swap `(salt, scan_tag)` without
/// invalidating the hash.
pub fn hash_tx_body(
    prev_state_root: &Digest,
    fee: u128,
    inputs: &[TxInput],
    outputs: &[TxOutput],
) -> TxBodyHash {
    let n = 2 + inputs.len() + outputs.len();
    let target = n.next_power_of_two().max(2);

    let mut leaves: Vec<Digest> = Vec::with_capacity(target);
    leaves.push(*prev_state_root);
    leaves.push(scalar_leaf_u128(fee));
    for i in inputs {
        leaves.push(i.commitment.0);
    }
    for o in outputs {
        leaves.push(output_leaf(o));
    }
    leaves.resize(target, [0u8; 32]);

    // Merkle reduce with compress (§5.1). Sequential — tx sizes are
    // bounded (≤4 inputs, ≤8 outputs, so ≤16 leaves after padding) and
    // parallelism is noise at this scale.
    while leaves.len() > 1 {
        let mut next = Vec::with_capacity(leaves.len() / 2);
        for pair in leaves.chunks_exact(2) {
            next.push(compress(&pair[0], &pair[1]));
        }
        leaves = next;
    }

    // Final TXBODY wrap (§5.7 step 3): single permutation with capacity
    // IV = `TXBODY__`.
    let root = leaves[0];
    let r0 = Block128::from(u128::from_le_bytes(root[..16].try_into().unwrap()));
    let r1 = Block128::from(u128::from_le_bytes(root[16..].try_into().unwrap()));
    let [iv_hi, iv_lo] = capacity_iv(TAG_TXBODY);
    let mut state = [r0, r1, iv_hi, iv_lo];
    Poseidon2bPermutation.permute_mut(&mut state);

    let mut out = [0u8; 32];
    out[..16].copy_from_slice(&state[0].to_bytes());
    out[16..].copy_from_slice(&state[1].to_bytes());
    TxBodyHash(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use noid_core::TowerField;
    use noid_poseidon2b::primitives::{
        hash_commitment, hash_scan_tag, Address, Commitment, Nullifier, ScanTag,
    };

    fn mk_input(seed: u8) -> TxInput {
        let addr = Address([seed; 32]);
        let c = hash_commitment(
            seed as u128,
            &addr,
            Block128::from(seed as u128),
            Block128::ZERO,
        );
        TxInput {
            commitment: c,
            nullifier: Nullifier([seed; 32]),
            valid: true,
        }
    }

    fn mk_output(seed: u8, salt: u128) -> TxOutput {
        let addr = Address([seed; 32]);
        let c = hash_commitment(
            seed as u128,
            &addr,
            Block128::from(seed as u128),
            Block128::ZERO,
        );
        let vk = noid_poseidon2b::primitives::derive_view_key(
            &noid_poseidon2b::primitives::MasterSecret([seed; 32]),
        );
        let salt = Block128::from(salt);
        let tag = hash_scan_tag(&vk, salt);
        TxOutput {
            commitment: c,
            salt,
            scan_tag: tag,
            valid: true,
        }
    }

    #[test]
    fn determinism() {
        let prev = [0xABu8; 32];
        let i = [mk_input(1)];
        let o = [mk_output(2, 7), mk_output(3, 9)];
        assert_eq!(
            hash_tx_body(&prev, 5, &i, &o),
            hash_tx_body(&prev, 5, &i, &o)
        );
    }

    #[test]
    fn salt_flip_changes_body_hash() {
        let prev = [0u8; 32];
        let o1 = mk_output(1, 100);
        let mut o2 = o1;
        o2.salt = Block128::from(101u128);
        // Intentionally keep scan_tag and commitment identical to prove
        // §7.1 binds salt independently.
        assert_ne!(o1.salt, o2.salt);
        let h1 = hash_tx_body(&prev, 0, &[], &[o1]);
        let h2 = hash_tx_body(&prev, 0, &[], &[o2]);
        assert_ne!(h1, h2);
    }

    #[test]
    fn scan_tag_flip_changes_body_hash() {
        let prev = [0u8; 32];
        let o1 = mk_output(1, 100);
        let mut o2 = o1;
        o2.scan_tag = ScanTag([0xFFu8; 32]);
        let h1 = hash_tx_body(&prev, 0, &[], &[o1]);
        let h2 = hash_tx_body(&prev, 0, &[], &[o2]);
        assert_ne!(h1, h2);
    }

    #[test]
    fn commitment_flip_changes_body_hash() {
        let prev = [0u8; 32];
        let o1 = mk_output(1, 100);
        let mut o2 = o1;
        o2.commitment = Commitment([0x11u8; 32]);
        let h1 = hash_tx_body(&prev, 0, &[], &[o1]);
        let h2 = hash_tx_body(&prev, 0, &[], &[o2]);
        assert_ne!(h1, h2);
    }

    #[test]
    fn differs_from_legacy_commitment_only_hash() {
        // The §7.1 binding hash must not equal the commitment-only
        // hash in `noid_poseidon2b` — if it did, the binding would be
        // a no-op.
        let prev = [0u8; 32];
        let o = mk_output(1, 42);
        let bound = hash_tx_body(&prev, 0, &[], &[o]);
        let legacy = noid_poseidon2b::primitives::hash_tx_body(&prev, 0, &[], &[o.commitment]);
        assert_ne!(bound.0, legacy.0);
    }

    #[test]
    fn ordering_and_fee_sensitive() {
        let prev = [0u8; 32];
        let i1 = mk_input(1);
        let i2 = mk_input(2);
        let h_a = hash_tx_body(&prev, 10, &[i1, i2], &[]);
        let h_b = hash_tx_body(&prev, 10, &[i2, i1], &[]);
        let h_c = hash_tx_body(&prev, 11, &[i1, i2], &[]);
        assert_ne!(h_a, h_b);
        assert_ne!(h_a, h_c);
    }
}
