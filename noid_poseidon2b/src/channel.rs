// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero. All rights reserved.

//! Poseidon2b-backed Fiat-Shamir channel implementing
//! [`noid_core::transcript::FiatShamir`].
//!
//! This is the *production* transcript for protocols in `noid_core` that
//! previously used the insecure XOR-sum placeholder. Every squeeze advances
//! the sponge by one permutation and emits one Block128 challenge.
//!
//! The channel is seeded with its own capacity IV (`KSCHANNL`) so its
//! transcript states are not replayable across the other Fiat-Shamir
//! families (byte challenger, lane challenger, FRI channel). Any pinned
//! test vectors downstream (notably in `noid_fri` prover/verifier and
//! sumcheck transcripts) must be regenerated in the same commit that
//! changes the seed.

use noid_core::transcript::FiatShamir;
use noid_core::{Block128, TowerField};

use crate::native::compression::Poseidon2bSponge;
use crate::native::domain::{capacity_iv, TAG_KSCHANNL};

/// Fiat-Shamir channel backed by a Poseidon2b sponge.
#[derive(Debug, Clone)]
pub struct Poseidon2bChannel {
    sponge: Poseidon2bSponge,
    /// When we squeeze a rate block (two Block128s) we hand out the second
    /// one on the next call before advancing the sponge again.
    pending: Option<Block128>,
}

impl Default for Poseidon2bChannel {
    fn default() -> Self {
        Self::new()
    }
}

impl Poseidon2bChannel {
    pub fn new() -> Self {
        Self {
            sponge: Poseidon2bSponge::with_iv(capacity_iv(TAG_KSCHANNL)),
            pending: None,
        }
    }

    /// Consume the transcript and return an exact four-lane bridge state.
    ///
    /// The construction-specific `close_tag` and a fixed zero lane form one
    /// complete final rate block, forcing exactly one final permutation. Any
    /// buffered second challenge is invalidated by the absorb. Returning all
    /// four lanes avoids introducing an unproved compression boundary between
    /// independently replayed transcript channels.
    pub fn close_into_bridge(mut self, close_tag: Block128) -> [Block128; 4] {
        assert!(
            self.sponge.absorb_is_aligned(),
            "bridge close must start at a fresh rate block"
        );
        self.absorb(close_tag);
        self.absorb(Block128::ZERO);
        self.sponge.full_state_after_aligned_absorb()
    }
}

impl FiatShamir<Block128> for Poseidon2bChannel {
    fn absorb(&mut self, elem: Block128) {
        // Absorbing invalidates any buffered challenge — future squeezes
        // must reflect the new state.
        self.pending = None;
        self.sponge.absorb(elem);
    }

    fn squeeze(&mut self) -> Block128 {
        if let Some(b) = self.pending.take() {
            return b;
        }
        // Commit any buffered absorb bytes to state before reading.
        self.sponge.flush_to_squeeze();
        let [a, b] = self.sponge.squeeze();
        self.pending = Some(b);
        a
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channel_is_deterministic() {
        let mut c1 = Poseidon2bChannel::new();
        c1.absorb(Block128::from(42u128));
        let a1 = c1.squeeze();
        let b1 = c1.squeeze();

        let mut c2 = Poseidon2bChannel::new();
        c2.absorb(Block128::from(42u128));
        let a2 = c2.squeeze();
        let b2 = c2.squeeze();

        assert_eq!(a1, a2);
        assert_eq!(b1, b2);
    }

    #[test]
    fn distinct_inputs_distinct_challenges() {
        let mut c1 = Poseidon2bChannel::new();
        c1.absorb(Block128::from(1u128));
        let a = c1.squeeze();

        let mut c2 = Poseidon2bChannel::new();
        c2.absorb(Block128::from(2u128));
        let b = c2.squeeze();

        assert_ne!(a, b);
    }

    #[test]
    fn channel_iv_diverges_from_bare_sponge() {
        // Same absorb, different IV => different squeezes.
        let mut c = Poseidon2bChannel::new();
        c.absorb(Block128::from(1u128));
        let iv_challenge = c.squeeze();

        let mut bare = Poseidon2bSponge::new();
        bare.absorb(Block128::from(1u128));
        bare.flush_to_squeeze();
        let [bare_a, _] = bare.squeeze();

        assert_ne!(iv_challenge, bare_a);
    }

    #[test]
    fn consuming_bridge_closes_with_one_exact_full_block() {
        let close_tag = Block128::from(0x5A4B_BA1D_0000_0001u128);
        let mut channel = Poseidon2bChannel::new();
        channel.absorb(Block128::from(7u128));
        channel.absorb(Block128::from(9u128));
        let _eta = channel.squeeze();

        let bridge = channel.clone().close_into_bridge(close_tag);
        let same = channel.close_into_bridge(close_tag);
        assert_eq!(bridge, same);

        let mut changed = Poseidon2bChannel::new();
        changed.absorb(Block128::from(7u128));
        changed.absorb(Block128::from(10u128));
        let _eta = changed.squeeze();
        assert_ne!(bridge, changed.close_into_bridge(close_tag));
        assert!(bridge.iter().any(|&lane| lane != Block128::ZERO));
    }

    #[test]
    #[should_panic(expected = "bridge close must start at a fresh rate block")]
    fn consuming_bridge_rejects_a_half_filled_close_schedule() {
        let mut channel = Poseidon2bChannel::new();
        channel.absorb(Block128::from(7u128));
        let _ = channel.close_into_bridge(Block128::from(0x5A4B_BA1D_0000_0001u128));
    }
}
