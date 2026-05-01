// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Fiat–Shamir transcript for the FRI protocol.
//!
//! Keccak256 is replaced by a Poseidon2b sponge in *duplex* mode: absorbs go
//! through the sponge as byte-streaming; squeezes use the sponge's native
//! two-Block128-per-permutation rate output. One permutation yields two
//! challenges, amortising the hash cost over challenge-heavy phases
//! (folding rounds, query index generation).

use noid_core::{Block128, CanonicalSerialize};
use noid_poseidon2b::native::compression::Poseidon2bSponge;

use crate::merkle::VectorCommitment;
use crate::prover::FriCommitment;

/// Number of FRI queries. With code rate R = 4 each query contributes
/// `log2(R) = 2` bits of proven soundness (JACM FRI bound). We target
/// **128-bit proven soundness**, which requires `ceil(128 / 2) = 64`
/// queries.
///
/// Previous values (96, 144) were sized for 192/288-bit conjectured
/// soundness — over-provisioned for any realistic threat model and
/// costing unnecessary prover/verifier work. See CRYPTO.md §8.
///
/// In test/debug builds we use a much smaller count so the test suite
/// runs in seconds rather than minutes — the protocol is still exercised
/// fully end-to-end.
#[cfg(not(any(test, debug_assertions)))]
pub const NUM_QUERIES: usize = 64;
#[cfg(any(test, debug_assertions))]
pub const NUM_QUERIES: usize = 10;

/// Base-2 log of the extension degree used for soundness amplification.
pub const TAU: usize = 7;

/// Fiat–Shamir channel backed by a Poseidon2b sponge (duplex mode).
pub struct Channel {
    sponge: Poseidon2bSponge,
    /// One rate block (two Block128s) of buffered squeeze output.
    /// `None` if the next squeeze needs to trigger a permutation.
    pending: Option<Block128>,
    /// `true` once we've started squeezing; absorbs after this reset
    /// the pending block and re-enter absorb mode.
    squeezing: bool,
}

impl Channel {
    pub fn new() -> Self {
        Self {
            sponge: Poseidon2bSponge::new(),
            pending: None,
            squeezing: false,
        }
    }

    // -----------------------------------------------------------------------
    // Observe (absorb)
    // -----------------------------------------------------------------------

    fn enter_absorb_mode(&mut self) {
        if self.squeezing {
            // Any pending rate output is invalidated — future squeezes
            // must reflect the new state.
            self.pending = None;
            self.squeezing = false;
        }
    }

    /// Absorb a single field element.
    pub fn observe_field_elem(&mut self, elem: Block128) {
        self.enter_absorb_mode();
        let mut bytes = [0u8; 16];
        elem.serialize(&mut bytes)
            .expect("Block128 serializes into 16 bytes");
        self.sponge.update(&bytes);
    }

    /// Absorb a slice of field elements.
    pub fn observe_field_elems(&mut self, elems: &[Block128]) {
        self.enter_absorb_mode();
        for &elem in elems {
            let mut bytes = [0u8; 16];
            elem.serialize(&mut bytes)
                .expect("Block128 serializes into 16 bytes");
            self.sponge.update(&bytes);
        }
    }

    /// Absorb a `VectorCommitment` (root hash + depth).
    pub fn observe_vector_commitment(&mut self, commitment: &VectorCommitment) {
        self.enter_absorb_mode();
        self.sponge.update(&commitment.root);
        self.sponge.update(&(commitment.depth as u64).to_le_bytes());
    }

    /// Absorb a `FriCommitment` (vector commitment + packing factor).
    pub fn observe_fri_commitment(&mut self, commitment: &FriCommitment) {
        self.observe_vector_commitment(&commitment.vector_commitment);
        self.sponge
            .update(&(commitment.packing_factor as u64).to_le_bytes());
    }

    // -----------------------------------------------------------------------
    // Squeeze (challenge derivation)
    // -----------------------------------------------------------------------

    fn squeeze_block(&mut self) -> Block128 {
        if !self.squeezing {
            self.sponge.flush_to_squeeze();
            self.squeezing = true;
        }
        if let Some(b) = self.pending.take() {
            return b;
        }
        let [a, b] = self.sponge.squeeze();
        self.pending = Some(b);
        a
    }

    /// Squeeze a single random `Block128` challenge.
    pub fn get_random_point(&mut self) -> Block128 {
        self.squeeze_block()
    }

    /// Squeeze `n` random challenges.
    pub fn get_random_points(&mut self, n: usize) -> Vec<Block128> {
        (0..n).map(|_| self.squeeze_block()).collect()
    }

    /// Generate query indices for the query phase.
    ///
    /// For 96-bit security with R = 4 we draw 144 random field elements
    /// and reduce each modulo the domain size. If the domain is smaller
    /// than 144 we query every index once.
    pub fn gen_queries(&mut self, log_max_len: usize) -> Vec<usize> {
        let Some(domain_size) = 1usize.checked_shl(log_max_len as u32) else {
            // Out-of-range log size (malformed input): return no queries so
            // higher-level verifiers can fail shape checks cleanly.
            return vec![];
        };

        if domain_size == 0 {
            return vec![];
        }

        if domain_size < NUM_QUERIES {
            return (0..domain_size).collect();
        }

        let bit_mask = (domain_size - 1) as u128;
        let random_elems = self.get_random_points(NUM_QUERIES);
        random_elems
            .iter()
            .map(|elem| (elem.0 & bit_mask) as usize)
            .collect()
    }
}

impl Default for Channel {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_channel_deterministic() {
        let mut c1 = Channel::new();
        c1.observe_field_elem(Block128::from(42u8));
        let p1 = c1.get_random_point();

        let mut c2 = Channel::new();
        c2.observe_field_elem(Block128::from(42u8));
        let p2 = c2.get_random_point();

        assert_eq!(p1, p2);
    }

    #[test]
    fn test_channel_different_obs() {
        let mut c1 = Channel::new();
        c1.observe_field_elem(Block128::from(1u8));
        let p1 = c1.get_random_point();

        let mut c2 = Channel::new();
        c2.observe_field_elem(Block128::from(2u8));
        let p2 = c2.get_random_point();

        assert_ne!(p1, p2);
    }

    #[test]
    fn test_gen_queries() {
        let mut c = Channel::new();
        c.observe_field_elem(Block128::from(99u8));
        let queries = c.gen_queries(10); // domain 1024
        assert_eq!(queries.len(), NUM_QUERIES);
        for &q in &queries {
            assert!(q < 1024);
        }
    }

    #[test]
    fn test_interleaved_absorb_squeeze() {
        let mut c1 = Channel::new();
        c1.observe_field_elem(Block128::from(1u8));
        let a1 = c1.get_random_point();
        c1.observe_field_elem(Block128::from(2u8));
        let b1 = c1.get_random_point();

        let mut c2 = Channel::new();
        c2.observe_field_elem(Block128::from(1u8));
        let a2 = c2.get_random_point();
        c2.observe_field_elem(Block128::from(2u8));
        let b2 = c2.get_random_point();

        assert_eq!(a1, a2);
        assert_eq!(b1, b2);
        assert_ne!(a1, b1);
    }

    #[test]
    fn test_squeeze_commits_to_later_absorb() {
        let mut c = Channel::new();
        c.observe_field_elem(Block128::from(1u8));
        let a = c.get_random_point();
        let b_no_obs = c.get_random_point();

        let mut c2 = Channel::new();
        c2.observe_field_elem(Block128::from(1u8));
        let a2 = c2.get_random_point();
        c2.observe_field_elem(Block128::from(99u8));
        let b_with_obs = c2.get_random_point();

        assert_eq!(a, a2);
        assert_ne!(b_no_obs, b_with_obs);
    }
}
