// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero. All rights reserved.

//! Typed witness vectors that carry their packed DA representation.
//!
//! `BitWitness` / `ByteWitness` own the logical small-field content and
//! expose:
//!   - `as_packed()`      — Block128 words for FRI commitment / DA serialisation.
//!   - `as_expanded()`    — the original bit/byte stream for constraint checking.
//!   - `as_expanded_field()` — each bit/byte lifted into Block128 for MLE ops.
//!
//! The DA / bandwidth saving is literal: a block that ships `as_packed()`
//! instead of the Block128-expanded vector is 128x / 16x smaller on the
//! wire and on disk.

use noid_core::{Block128, TowerField};

use crate::pack::{pack_bits, pack_bytes, unpack_bits, unpack_bytes};

/// A length-N GF(2) witness, stored packed at 128 bits per Block128 word.
#[derive(Clone, Debug)]
pub struct BitWitness {
    packed: Vec<Block128>,
    n_bits: usize,
}

impl BitWitness {
    /// Build from a bit stream. Length must be a power of two and at least 128.
    pub fn from_bits(bits: &[u8]) -> Self {
        assert!(
            bits.len().is_power_of_two(),
            "bit witness length must be a power of two"
        );
        assert!(bits.len() >= 128, "bit witness must hold at least 128 bits");
        let packed = pack_bits(bits);
        Self {
            packed,
            n_bits: bits.len(),
        }
    }

    /// Rebuild from the packed representation (e.g. after DA deserialisation).
    pub fn from_packed(packed: Vec<Block128>) -> Self {
        assert!(
            packed.len().is_power_of_two(),
            "packed length must be a power of two"
        );
        let n_bits = packed.len() * 128;
        Self { packed, n_bits }
    }

    pub fn n_bits(&self) -> usize {
        self.n_bits
    }

    pub fn n_packed(&self) -> usize {
        self.packed.len()
    }

    /// DA / commitment payload.
    pub fn as_packed(&self) -> &[Block128] {
        &self.packed
    }

    /// Expanded bit stream (0/1 bytes).
    pub fn as_expanded(&self) -> Vec<u8> {
        unpack_bits(&self.packed)
    }

    /// Expanded field-lifted stream: each bit as Block128 (ZERO or ONE).
    pub fn as_expanded_field(&self) -> Vec<Block128> {
        let bits = self.as_expanded();
        bits.into_iter()
            .map(|b| {
                if b == 0 {
                    Block128::ZERO
                } else {
                    Block128::ONE
                }
            })
            .collect()
    }
}

/// A length-N GF(2^8) witness, stored packed at 16 bytes per Block128 word.
#[derive(Clone, Debug)]
pub struct ByteWitness {
    packed: Vec<Block128>,
    n_bytes: usize,
}

impl ByteWitness {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        assert!(
            bytes.len().is_power_of_two(),
            "byte witness length must be a power of two"
        );
        assert!(
            bytes.len() >= 16,
            "byte witness must hold at least 16 bytes"
        );
        let packed = pack_bytes(bytes);
        Self {
            packed,
            n_bytes: bytes.len(),
        }
    }

    pub fn from_packed(packed: Vec<Block128>) -> Self {
        assert!(packed.len().is_power_of_two());
        let n_bytes = packed.len() * 16;
        Self { packed, n_bytes }
    }

    pub fn n_bytes(&self) -> usize {
        self.n_bytes
    }

    pub fn n_packed(&self) -> usize {
        self.packed.len()
    }

    pub fn as_packed(&self) -> &[Block128] {
        &self.packed
    }

    pub fn as_expanded(&self) -> Vec<u8> {
        unpack_bytes(&self.packed)
    }

    /// Expanded field-lifted stream: each byte as Block128 (low byte of u128).
    pub fn as_expanded_field(&self) -> Vec<Block128> {
        let bytes = self.as_expanded();
        bytes
            .into_iter()
            .map(|b| Block128::from(b as u128))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;

    #[test]
    fn bit_witness_roundtrip() {
        let mut rng = rand::thread_rng();
        let bits: Vec<u8> = (0..1024).map(|_| rng.gen::<bool>() as u8).collect();
        let w = BitWitness::from_bits(&bits);
        assert_eq!(w.n_bits(), 1024);
        assert_eq!(w.n_packed(), 8);
        assert_eq!(w.as_expanded(), bits);
    }

    #[test]
    fn byte_witness_roundtrip() {
        let mut rng = rand::thread_rng();
        let bytes: Vec<u8> = (0..1024).map(|_| rng.gen::<u8>()).collect();
        let w = ByteWitness::from_bytes(&bytes);
        assert_eq!(w.n_bytes(), 1024);
        assert_eq!(w.n_packed(), 64);
        assert_eq!(w.as_expanded(), bytes);
    }
}
