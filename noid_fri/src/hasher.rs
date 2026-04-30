// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Cryptographic hasher trait + concrete implementations used by the FRI
//! Merkle layer.
//!
//! Two tiers are supported:
//!
//! - [`Blake3Hasher`] — the default "fast" Merkle hasher. Commitment hashing
//!   dominates prover wall-clock (~90% of `commit` at log_n = 20); Blake3 is
//!   byte-native and ~20-50x faster than Poseidon2b for this workload. Used
//!   for FRI Merkle leaves + inner nodes when recursion is not on the critical
//!   path.
//! - Poseidon2b (`Poseidon2bSponge` from `noid_poseidon2b`) — the
//!   arithmetization-friendly hasher. Reserved for the Fiat-Shamir transcript
//!   and (future) the recursion boundary where Merkle verification must
//!   happen in-circuit.
//!
//! Both implement [`CryptographicHasher`]; the FRI prover/verifier take any
//! `&dyn CryptographicHasher`.

pub use noid_poseidon2b::hasher::{CryptographicHasher, HashOutput};

use noid_core::{Block128, CanonicalSerialize};

/// Blake3-backed hasher. Zero-state (the Blake3 function is keyless; domain
/// separation for the Merkle leaf/compress layer comes from the fixed input
/// widths of the two calls — 32 bytes for leaves, 64 bytes for compress —
/// and the transcript-level Fiat-Shamir IV sits in the Poseidon2b channel,
/// not here).
#[derive(Clone, Copy, Default, Debug)]
pub struct Blake3Hasher;

impl Blake3Hasher {
    pub const fn new() -> Self {
        Self
    }
}

fn block128_to_bytes(x: &Block128) -> [u8; 16] {
    let mut b = [0u8; 16];
    x.serialize(&mut b).expect("Block128 serialises to 16 bytes");
    b
}

impl CryptographicHasher for Blake3Hasher {
    fn hash_pair(&self, a: &Block128, b: &Block128) -> HashOutput {
        let mut buf = [0u8; 32];
        buf[..16].copy_from_slice(&block128_to_bytes(a));
        buf[16..].copy_from_slice(&block128_to_bytes(b));
        *blake3::hash(&buf).as_bytes()
    }

    fn hash_field(&self, elem: &Block128) -> HashOutput {
        let buf = block128_to_bytes(elem);
        *blake3::hash(&buf).as_bytes()
    }

    fn hash_concatenation(&self, a: &HashOutput, b: &HashOutput) -> HashOutput {
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(a);
        buf[32..].copy_from_slice(b);
        *blake3::hash(&buf).as_bytes()
    }

    fn compress(&self, a: &HashOutput, b: &HashOutput) -> HashOutput {
        self.hash_concatenation(a, b)
    }

    fn batch_hash_pair(&self, pairs: &[Block128], out: &mut [HashOutput]) {
        assert_eq!(pairs.len(), 2 * out.len());
        // Tight serial loop: the caller (`compute_leaf_hashes`) already
        // distributes chunks across the rayon pool; nesting another par_iter
        // here only adds task-graph overhead.
        let mut buf = [0u8; 32];
        for (i, slot) in out.iter_mut().enumerate() {
            buf[..16].copy_from_slice(&block128_to_bytes(&pairs[2 * i]));
            buf[16..].copy_from_slice(&block128_to_bytes(&pairs[2 * i + 1]));
            *slot = *blake3::hash(&buf).as_bytes();
        }
    }

    fn batch_compress(&self, pairs: &[HashOutput], out: &mut [HashOutput]) {
        assert_eq!(pairs.len(), 2 * out.len());
        // Serial loop for the same reason as `batch_hash_pair`.
        let mut buf = [0u8; 64];
        for (i, slot) in out.iter_mut().enumerate() {
            buf[..32].copy_from_slice(&pairs[2 * i]);
            buf[32..].copy_from_slice(&pairs[2 * i + 1]);
            *slot = *blake3::hash(&buf).as_bytes();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blake3_determinism() {
        let h = Blake3Hasher::new();
        let a = Block128::from(1u128);
        let b = Block128::from(2u128);
        assert_eq!(h.hash_pair(&a, &b), h.hash_pair(&a, &b));
        let d0 = [0u8; 32];
        let d1 = [1u8; 32];
        assert_eq!(h.compress(&d0, &d1), h.compress(&d0, &d1));
        assert_ne!(h.compress(&d0, &d1), h.compress(&d1, &d0));
    }

    #[test]
    fn blake3_batch_matches_scalar() {
        let h = Blake3Hasher::new();
        let n = 32usize;
        let pairs: Vec<Block128> = (0..2 * n).map(|i| Block128::from(i as u128 + 1)).collect();
        let mut batch_out = vec![[0u8; 32]; n];
        h.batch_hash_pair(&pairs, &mut batch_out);
        for i in 0..n {
            assert_eq!(
                batch_out[i],
                h.hash_pair(&pairs[2 * i], &pairs[2 * i + 1])
            );
        }

        let digs: Vec<HashOutput> = (0..2 * n).map(|i| [i as u8; 32]).collect();
        let mut bc_out = vec![[0u8; 32]; n];
        h.batch_compress(&digs, &mut bc_out);
        for i in 0..n {
            assert_eq!(bc_out[i], h.compress(&digs[2 * i], &digs[2 * i + 1]));
        }
    }
}
