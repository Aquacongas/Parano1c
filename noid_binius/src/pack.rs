// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero. All rights reserved.

//! Bit and byte packing into Block128 words.
//!
//! The packing basis matches Binius: the `k`-th subfield element sits in the
//! `k`-th coordinate of the GF(2^128) vector space over GF(2) (for bits) or
//! GF(2^8) (for bytes). For the bit case this is simply the little-endian
//! bit layout of the underlying `u128`. For the byte case, bytes 0..16 of
//! the `u128` hold the 16 GF(2^8) elements.
//!
//! This layout commits to exactly the same bit/byte sequence that the prover
//! uses in constraints, so there is no re-interpretation between the
//! DA layer, the commitment layer, and the AIR.

use noid_core::{Block128, TowerField};

/// The basis used to re-expand a packed Block128 into 128 GF(2)-coordinates:
///   `BETA[k]` = `Block128::from(1u128 << k)`
///
/// For any packed word `p = Σ_k b_k · BETA[k]` with `b_k ∈ {0,1}`, the
/// inner product `<p, BETA> == p` (in the canonical GF(2) embedding) —
/// that is, the bits are stored literally in the u128.
///
/// This lazy-static lookup lets callers avoid recomputing the basis in
/// hot loops.
#[allow(non_snake_case)]
pub fn BETA() -> [Block128; 128] {
    let mut out = [Block128::ZERO; 128];
    for (k, slot) in out.iter_mut().enumerate() {
        *slot = Block128::from(1u128 << k);
    }
    out
}

// ---------------------------------------------------------------------------
// Bit packing (128x compression)
// ---------------------------------------------------------------------------

/// Pack a bit vector into Block128 words, 128 bits per word.
///
/// Input length must be a multiple of 128. Bit `i` of the input lands in
/// bit `i % 128` of word `i / 128`.
pub fn pack_bits(bits: &[u8]) -> Vec<Block128> {
    assert!(
        bits.len().is_multiple_of(128),
        "bit vector length must be a multiple of 128 (got {})",
        bits.len()
    );
    assert!(
        bits.iter().all(|&b| b <= 1),
        "pack_bits: all inputs must be 0 or 1"
    );

    let n_words = bits.len() / 128;
    let mut out = vec![Block128::ZERO; n_words];
    for (w, chunk) in bits.chunks_exact(128).enumerate() {
        let mut acc: u128 = 0;
        for (k, &bit) in chunk.iter().enumerate() {
            acc |= (bit as u128) << k;
        }
        out[w] = Block128(acc);
    }
    out
}

/// Inverse of `pack_bits`: expand each Block128 into 128 bits.
pub fn unpack_bits(packed: &[Block128]) -> Vec<u8> {
    let mut out = vec![0u8; packed.len() * 128];
    for (w, word) in packed.iter().enumerate() {
        let v = word.0;
        for k in 0..128 {
            out[w * 128 + k] = ((v >> k) & 1) as u8;
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Byte packing (16x compression) — GF(2^8) embedded in GF(2^128)
// ---------------------------------------------------------------------------

/// Pack a byte vector (semantically GF(2^8) elements) into Block128 words,
/// 16 bytes per word.
///
/// Byte `i` lands in the `(i % 16)`-th byte of word `i / 16`. The embedding
/// matches the tower basis `Block8 → Block128`: each byte occupies exactly
/// 8 of the 128 bits of its word, in the canonical position.
pub fn pack_bytes(bytes: &[u8]) -> Vec<Block128> {
    assert!(
        bytes.len().is_multiple_of(16),
        "byte vector length must be a multiple of 16 (got {})",
        bytes.len()
    );

    let n_words = bytes.len() / 16;
    let mut out = vec![Block128::ZERO; n_words];
    for (w, chunk) in bytes.chunks_exact(16).enumerate() {
        let mut acc: u128 = 0;
        for (i, &byte) in chunk.iter().enumerate() {
            acc |= (byte as u128) << (i * 8);
        }
        out[w] = Block128(acc);
    }
    out
}

/// Inverse of `pack_bytes`.
pub fn unpack_bytes(packed: &[Block128]) -> Vec<u8> {
    let mut out = vec![0u8; packed.len() * 16];
    for (w, word) in packed.iter().enumerate() {
        let v = word.0;
        for i in 0..16 {
            out[w * 16 + i] = ((v >> (i * 8)) & 0xFF) as u8;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;

    #[test]
    fn bit_roundtrip() {
        let mut rng = rand::thread_rng();
        for log_n in [7, 10, 14] {
            let n = 1 << log_n;
            let bits: Vec<u8> = (0..n).map(|_| rng.gen::<bool>() as u8).collect();
            let packed = pack_bits(&bits);
            assert_eq!(packed.len() * 128, n);
            let back = unpack_bits(&packed);
            assert_eq!(bits, back);
        }
    }

    #[test]
    fn byte_roundtrip() {
        let mut rng = rand::thread_rng();
        let n = 1 << 12;
        let bytes: Vec<u8> = (0..n).map(|_| rng.gen::<u8>()).collect();
        let packed = pack_bytes(&bytes);
        assert_eq!(packed.len() * 16, n);
        let back = unpack_bytes(&packed);
        assert_eq!(bytes, back);
    }

    #[test]
    fn compression_ratio() {
        // Committing 1M bits used to require 1M * 16 B = 16 MiB of trace.
        // Packed: 1M / 128 = 8192 words * 16 B = 128 KiB. 128x reduction.
        let bits = vec![0u8; 1 << 20];
        let packed = pack_bits(&bits);
        let compressed_bytes = packed.len() * 16;
        let raw_bytes = bits.len() * 16; // one Block128 per bit if unpacked
        assert_eq!(raw_bytes / compressed_bytes, 128);
    }

    #[test]
    fn beta_is_canonical() {
        let beta = BETA();
        // BETA[k] = 2^k; sum with bit b_k should reconstruct the literal u128.
        let mut bits = [0u8; 128];
        bits[0] = 1;
        bits[3] = 1;
        bits[127] = 1;
        let packed = pack_bits(&bits);
        let expected = (1u128 << 0) | (1u128 << 3) | (1u128 << 127);
        assert_eq!(packed[0].0, expected);
        // And the k-th BETA is literally 2^k.
        assert_eq!(beta[0], Block128::ONE);
        assert_eq!(beta[3].0, 1u128 << 3);
        assert_eq!(beta[127].0, 1u128 << 127);
    }
}
