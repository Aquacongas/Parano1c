// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Poseidon2b sponge / compression function.
//!
//! Sponge parameters: t=4, rate=2, cap=2.

use super::permutation::Poseidon2bPermutation;
use noid_core::{Block128, CanonicalSerialize, TowerField};

const STATE_SIZE: usize = 4;
const RATE: usize = 2;

const PADDING_START: u8 = 0x80;
const PADDING_END: u8 = 0x01;

/// Poseidon2b sponge with t=4, rate=2, capacity=2.
#[derive(Debug, Clone)]
pub struct Poseidon2bSponge {
    state: [Block128; STATE_SIZE],
    buffer: [u8; 32],
    filled_bytes: usize,
    permutation: Poseidon2bPermutation,
}

impl Default for Poseidon2bSponge {
    fn default() -> Self {
        Self::new()
    }
}

impl Poseidon2bSponge {
    pub fn new() -> Self {
        Self {
            state: [Block128::ZERO; STATE_SIZE],
            buffer: [0u8; 32],
            filled_bytes: 0,
            permutation: Poseidon2bPermutation,
        }
    }

    /// Construct a sponge seeded with a capacity IV. See CRYPTO.md §3.
    /// `state[0]`, `state[1]` are zeroed (rate); `state[2]`, `state[3]`
    /// carry the IV.
    pub fn with_iv(iv: [Block128; 2]) -> Self {
        Self {
            state: [Block128::ZERO, Block128::ZERO, iv[0], iv[1]],
            buffer: [0u8; 32],
            filled_bytes: 0,
            permutation: Poseidon2bPermutation,
        }
    }

    /// Absorb raw bytes into the sponge.
    pub fn update(&mut self, mut data: &[u8]) {
        if self.filled_bytes != 0 {
            let to_copy = std::cmp::min(data.len(), 32 - self.filled_bytes);
            self.buffer[self.filled_bytes..self.filled_bytes + to_copy]
                .copy_from_slice(&data[..to_copy]);
            data = &data[to_copy..];
            self.filled_bytes += to_copy;

            if self.filled_bytes == 32 {
                self.permute_buffer();
                self.filled_bytes = 0;
            }
        }

        for chunk in data.chunks_exact(32) {
            self.buffer.copy_from_slice(chunk);
            self.permute_buffer();
        }

        let remaining = data.chunks_exact(32).remainder();
        if !remaining.is_empty() {
            self.buffer[..remaining.len()].copy_from_slice(remaining);
            self.filled_bytes = remaining.len();
        }
    }

    /// Absorb a single field element.
    pub fn absorb(&mut self, elem: Block128) {
        let bytes = elem.to_bytes();
        self.update(&bytes);
    }

    /// Absorb two field elements (one rate block).
    pub fn absorb_pair(&mut self, a: Block128, b: Block128) {
        let mut bytes = [0u8; 32];
        bytes[..16].copy_from_slice(&a.to_bytes());
        bytes[16..].copy_from_slice(&b.to_bytes());
        self.update(&bytes);
    }

    /// Finalize and squeeze a 32-byte digest.
    pub fn finalize(mut self) -> [u8; 32] {
        fill_padding(&mut self.buffer[self.filled_bytes..]);
        self.permute_buffer();
        self.squeeze_32()
    }

    /// Squeeze two field elements without finalizing (for streaming).
    pub fn squeeze(&mut self) -> [Block128; 2] {
        let out = [self.state[0], self.state[1]];
        self.permutation.permute_mut(&mut self.state);
        out
    }

    /// Flush any buffered absorb bytes into the state via one padded
    /// permutation, so subsequent `squeeze()` calls are guaranteed to
    /// commit to everything absorbed so far.
    ///
    /// Idempotent when no data is pending *and* the caller has not yet
    /// squeezed. Always safe to call before switching from absorb to
    /// squeeze mode.
    pub fn flush_to_squeeze(&mut self) {
        if self.filled_bytes != 0 {
            fill_padding(&mut self.buffer[self.filled_bytes..]);
            self.permute_buffer();
            self.filled_bytes = 0;
        }
    }

    fn permute_buffer(&mut self) {
        // XOR buffer into rate portion of state
        for i in 0..RATE {
            let mut word = [0u8; 16];
            word.copy_from_slice(&self.buffer[i * 16..(i + 1) * 16]);
            let elem = Block128::from(u128::from_le_bytes(word));
            self.state[i] += elem;
        }
        self.permutation.permute_mut(&mut self.state);
    }

    fn squeeze_32(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[..16].copy_from_slice(&self.state[0].to_bytes());
        out[16..].copy_from_slice(&self.state[1].to_bytes());
        out
    }
}

/// 2-to-1 fixed-width compression of two 32-byte digests via a single
/// Poseidon2b permutation. See CRYPTO.md §4.1.
///
/// The input is fixed width (64 bytes). There is no padding and no IV:
/// the permutation is applied to `[a0, a1, b0, b1]` directly, and the
/// first two rate words of the output state are returned. Saves two
/// permutations over sponge-mode `hash_concatenation`.
#[inline]
pub fn compress(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let a0 = Block128::from(u128::from_le_bytes(a[..16].try_into().unwrap()));
    let a1 = Block128::from(u128::from_le_bytes(a[16..].try_into().unwrap()));
    let b0 = Block128::from(u128::from_le_bytes(b[..16].try_into().unwrap()));
    let b1 = Block128::from(u128::from_le_bytes(b[16..].try_into().unwrap()));

    let mut state = [a0, a1, b0, b1];
    Poseidon2bPermutation.permute_mut(&mut state);

    let mut out = [0u8; 32];
    out[..16].copy_from_slice(&state[0].to_bytes());
    out[16..].copy_from_slice(&state[1].to_bytes());
    out
}

#[inline(always)]
fn fill_padding(data: &mut [u8]) {
    debug_assert!(!data.is_empty() && data.len() <= 32);
    data.fill(0);
    data[0] |= PADDING_START;
    data[data.len() - 1] |= PADDING_END;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sponge_deterministic() {
        let mut s1 = Poseidon2bSponge::new();
        s1.update(b"hello world");
        let d1 = s1.finalize();

        let mut s2 = Poseidon2bSponge::new();
        s2.update(b"hello world");
        let d2 = s2.finalize();

        assert_eq!(d1, d2);
    }

    #[test]
    fn test_sponge_different_inputs() {
        let mut s1 = Poseidon2bSponge::new();
        s1.update(b"hello");
        let d1 = s1.finalize();

        let mut s2 = Poseidon2bSponge::new();
        s2.update(b"world");
        let d2 = s2.finalize();

        assert_ne!(d1, d2);
    }

    #[test]
    fn test_compress_deterministic() {
        let a = [7u8; 32];
        let b = [42u8; 32];
        assert_eq!(compress(&a, &b), compress(&a, &b));
    }

    #[test]
    fn test_compress_distinguishes_order() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        assert_ne!(compress(&a, &b), compress(&b, &a));
    }

    #[test]
    fn test_absorb_field_elements() {
        let mut sponge = Poseidon2bSponge::new();
        sponge.absorb(Block128::from(42u8));
        sponge.absorb(Block128::from(123u8));
        let _digest = sponge.finalize();
        // Just ensure it doesn't panic
    }
}
