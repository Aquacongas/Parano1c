// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! `CryptographicHasher` implementation backed by Poseidon2b.

use crate::compression::Poseidon2bSponge;
use crate::hasher::{CryptographicHasher, HashOutput};
use noid_core::Block128;

impl CryptographicHasher for Poseidon2bSponge {
    fn hash_pair(&self, a: &Block128, b: &Block128) -> HashOutput {
        let mut sponge = Poseidon2bSponge::new();
        sponge.absorb_pair(*a, *b);
        sponge.finalize()
    }

    fn hash_field(&self, _elem: &Block128) -> HashOutput {
        let mut sponge = Poseidon2bSponge::new();
        sponge.absorb(*_elem);
        sponge.finalize()
    }

    fn hash_concatenation(&self, a: &HashOutput, b: &HashOutput) -> HashOutput {
        let mut sponge = Poseidon2bSponge::new();
        sponge.update(a);
        sponge.update(b);
        sponge.finalize()
    }

    fn compress(&self, a: &HashOutput, b: &HashOutput) -> HashOutput {
        crate::native::compress(a, b)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use noid_core::TowerField;

    #[test]
    fn test_hasher_pair() {
        let sponge = Poseidon2bSponge::new();
        let h1 = sponge.hash_pair(&Block128::ONE, &Block128::ZERO);
        let h2 = sponge.hash_pair(&Block128::ONE, &Block128::ZERO);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_hasher_concatenation() {
        let sponge = Poseidon2bSponge::new();
        let a = [1u8; 32];
        let b = [2u8; 32];
        let h1 = sponge.hash_concatenation(&a, &b);
        let h2 = sponge.hash_concatenation(&a, &b);
        assert_eq!(h1, h2);
    }
}
