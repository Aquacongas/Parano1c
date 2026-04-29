// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Cryptographic hasher trait for FRI Merkle trees.

use noid_core::Block128;

/// 32-byte hash output used throughout the Merkle tree and FRI layer.
pub type HashOutput = [u8; 32];

/// Trait for cryptographic hashing used in Merkle trees and transcripts.
///
/// Implementations are expected to be collision-resistant and deterministic.
pub trait CryptographicHasher: Send + Sync {
    /// Hash a pair of field elements (used for Merkle leaf construction).
    fn hash_pair(&self, a: &Block128, b: &Block128) -> HashOutput;

    /// Hash a single field element.
    fn hash_field(&self, elem: &Block128) -> HashOutput;

    /// Hash the concatenation of two 32-byte digests.
    fn hash_concatenation(&self, a: &HashOutput, b: &HashOutput) -> HashOutput;

    /// Fixed-width 2-to-1 compression of two digests — used for Merkle
    /// inner nodes. Default falls back to `hash_concatenation`. See
    /// CRYPTO.md §4.1.
    fn compress(&self, a: &HashOutput, b: &HashOutput) -> HashOutput {
        self.hash_concatenation(a, b)
    }
}
