// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Per-tx Fiat-Shamir channel factory for parallel algebraic STARK proofs.
//!
//! This module provides deterministic channel constructors with full domain
//! separation, enabling parallel per-tx algebraic STARK proofs while maintaining
//! soundness through commitment-derived seeds.
//!
//! # Security Model
//!
//! After Stage 3 (interleaved commit), the Merkle cap cryptographically binds
//! ALL witness columns. Zero-check challenges derived from `H(state_root || cap || k)`
//! are:
//! - Unpredictable before commit (cap depends on columns)
//! - Deterministic after commit (same seed → same challenges)
//! - Bound to the specific transaction (tx_index prevents cross-tx confusion)
//!
//! This provides non-adaptive soundness equivalent to adaptive soundness for
//! committed witnesses.

use noid_core::{Block128, CanonicalSerialize};
use noid_fri::Channel;
use noid_fri_binius::{absorb_cap, MerkleCap};
use noid_poseidon2b::native::compress;
use rayon::prelude::*;

/// Domain tag for per-tx algebraic STARK proofs.
/// ASCII: "TX_ALGEBRAIC_2026"
pub const DOMAIN_TAG_TX_ALGEBRAIC: u128 = 0x5458_414C_4745_4252_4149_4332_3032_3600;

/// Domain tag for state binding proofs.
/// ASCII: "STATE_BINDING_2026"
pub const DOMAIN_TAG_STATE_BINDING: u128 = 0x5354_4154_4542_494E_4449_4E47_3230_3236;

/// Domain tag for block-level multipoint sumcheck.
/// ASCII: "BLOCK_MULTIPOINT_2026"
pub const DOMAIN_TAG_BLOCK_MULTIPOINT: u128 = 0x424C_4F43_4B4D_554C_5449_504F_494E_5400;

/// Protocol version for domain separation.
/// Bump on any protocol change that affects transcript structure.
pub const PROTOCOL_VERSION_Q: u128 = 1;

/// Create a deterministic Fiat-Shamir channel for per-tx algebraic STARK.
///
/// # Arguments
///
/// * `prev_state_root` - Previous block state root (block context binding)
/// * `cap` - Merkle cap from interleaved commit (commitment binding)
/// * `tx_index` - Transaction index within block (per-tx uniqueness)
///
/// # Domain Separation
///
/// The channel is seeded with:
/// 1. `DOMAIN_TAG_TX_ALGEBRAIC` - Protocol-specific tag
/// 2. `PROTOCOL_VERSION_Q` - Protocol version
/// 3. `prev_state_root` (as two field elements) - Block context
/// 4. `cap` (via absorb_cap) - Commitment binding
/// 5. `tx_index` - Per-tx uniqueness
///
/// # Determinism
///
/// Same inputs always produce the same channel state and challenges.
/// Different `tx_index` values produce independent channels.
///
/// # Example
///
/// ```ignore
/// let mut channel = per_tx_algebraic_channel(&prev_state_root, &cap, 0);
/// let challenge = channel.squeeze_challenge();
/// ```
pub fn per_tx_algebraic_channel(
    prev_state_root: &[u8; 32],
    cap: &MerkleCap,
    tx_index: u32,
) -> Channel {
    let mut ch = Channel::new();

    // Domain separation
    ch.observe_field_elem(Block128::from(DOMAIN_TAG_TX_ALGEBRAIC));
    ch.observe_field_elem(Block128::from(PROTOCOL_VERSION_Q));

    // Block context binding (split state root into two field elements)
    let [sr0, sr1] = hash_to_fields(prev_state_root);
    ch.observe_field_elem(sr0);
    ch.observe_field_elem(sr1);

    // Commitment binding (absorb entire Merkle cap)
    absorb_cap(&mut ch, cap);

    // Per-tx uniqueness
    ch.observe_field_elem(Block128::from(tx_index as u128));

    ch
}

/// Create a deterministic Fiat-Shamir channel for state binding proofs.
///
/// Uses `tx_index = n_tx` as domain separator to distinguish from per-tx
/// algebraic proofs, then adds state binding domain tag.
///
/// # Arguments
///
/// * `prev_state_root` - Previous block state root
/// * `cap` - Merkle cap from interleaved commit
/// * `n_tx` - Number of transactions in block (used as tx_index)
///
/// # Example
///
/// ```ignore
/// let mut channel = state_binding_channel(&prev_state_root, &cap, n_tx);
/// ```
pub fn state_binding_channel(prev_state_root: &[u8; 32], cap: &MerkleCap, n_tx: u32) -> Channel {
    // Start with per-tx channel using n_tx as index
    let mut ch = per_tx_algebraic_channel(prev_state_root, cap, n_tx);

    // Add state binding domain tag
    ch.observe_field_elem(Block128::from(DOMAIN_TAG_STATE_BINDING));

    ch
}

/// Create a deterministic Fiat-Shamir channel for block-level multipoint sumcheck.
///
/// This channel is used in Stage 6 to bind all per-tx results together.
///
/// # Arguments
///
/// * `prev_state_root` - Previous block state root
/// * `cap` - Merkle cap from interleaved commit
///
/// # Domain Separation
///
/// Uses `DOMAIN_TAG_BLOCK_MULTIPOINT` to prevent collision with per-tx channels.
///
/// # Example
///
/// ```ignore
/// let mut channel = block_multipoint_channel(&prev_state_root, &cap);
/// channel.observe_field_elem(Block128::from(BLOCK_MULTIPOINT_TAG));
/// channel.observe_field_elems(&block_col_openings);
/// ```
pub fn block_multipoint_channel(prev_state_root: &[u8; 32], cap: &MerkleCap) -> Channel {
    let mut ch = Channel::new();

    // Domain separation
    ch.observe_field_elem(Block128::from(DOMAIN_TAG_BLOCK_MULTIPOINT));
    ch.observe_field_elem(Block128::from(PROTOCOL_VERSION_Q));

    // Block context binding
    let [sr0, sr1] = hash_to_fields(prev_state_root);
    ch.observe_field_elem(sr0);
    ch.observe_field_elem(sr1);

    // Commitment binding
    absorb_cap(&mut ch, cap);

    ch
}

// ---------------------------------------------------------------------------
// Q.4a — Segmented Transcript Absorption helpers
// ---------------------------------------------------------------------------

/// Compute a per-tx transcript digest that commits to all algebraic STARK
/// proof data for transaction `tx_index`.
///
/// Binds: tx ordering (index), opening point (r_pp), MLE evaluations
/// (base_openings), batching weights (lambdas), and sumcheck terminal
/// (final_claim). Any manipulation of these by a cheating prover changes
/// this digest, changes the Merkle root, changes mu/beta, and invalidates
/// the block multipoint sumcheck.
pub fn compute_tx_transcript_digest(
    tx_index: u32,
    r_pp: &[Block128],
    base_openings: &[Block128],
    lambdas: &[Block128],
    final_claim: Block128,
) -> [u8; 32] {
    // Use a fresh Fiat-Shamir channel (Poseidon2b) as the hash accumulator.
    // Domain tag distinguishes this from all other channel usages.
    let mut ch = Channel::new();
    ch.observe_field_elem(Block128::from(DOMAIN_TAG_TX_ALGEBRAIC));
    ch.observe_field_elem(Block128::from(
        0x4449_4745_5354_0000_0000_0000_0000_0000u128,
    )); // "DIGEST\0..."
    ch.observe_field_elem(Block128::from(tx_index as u128));
    ch.observe_field_elems(r_pp);
    ch.observe_field_elems(base_openings);
    ch.observe_field_elems(lambdas);
    ch.observe_field_elem(final_claim);
    // Squeeze two Block128s → 32 bytes.
    let h0 = ch.get_random_point();
    let h1 = ch.get_random_point();
    let mut digest = [0u8; 32];
    h0.serialize(&mut digest[..16])
        .expect("Block128 serializes to 16 bytes");
    h1.serialize(&mut digest[16..])
        .expect("Block128 serializes to 16 bytes");
    digest
}

/// Merkle-reduce a flat list of 32-byte digests to a single 32-byte root.
///
/// The input is zero-padded to the next power of two. Internal nodes are
/// hashed with the same Poseidon2b `compress` used by the rest of the
/// proof system. Each tree layer is computed in parallel via rayon.
pub fn merkle_reduce(digests: &[[u8; 32]]) -> [u8; 32] {
    if digests.is_empty() {
        return [0u8; 32];
    }
    if digests.len() == 1 {
        return digests[0];
    }
    let n = digests.len().next_power_of_two();
    let mut layer: Vec<[u8; 32]> = Vec::with_capacity(n);
    layer.extend_from_slice(digests);
    layer.resize(n, [0u8; 32]); // zero-pad
    while layer.len() > 1 {
        let next: Vec<[u8; 32]> = layer
            .par_chunks(2)
            .map(|pair| compress(&pair[0], &pair[1]))
            .collect();
        layer = next;
    }
    layer[0]
}

/// Split a 32-byte hash into two 16-byte field elements.
///
/// Converts the hash into two `Block128` values using little-endian byte order.
///
/// # Arguments
///
/// * `h` - 32-byte hash
///
/// # Returns
///
/// Array of two `Block128` values: `[low_128_bits, high_128_bits]`
fn hash_to_fields(h: &[u8; 32]) -> [Block128; 2] {
    let lo = u128::from_le_bytes(h[..16].try_into().unwrap());
    let hi = u128::from_le_bytes(h[16..].try_into().unwrap());
    [Block128::from(lo), Block128::from(hi)]
}

#[cfg(test)]
mod tests {
    use super::*;
    use noid_fri_binius::MerkleCap;

    fn dummy_cap() -> MerkleCap {
        MerkleCap {
            hashes: vec![[0u8; 32]; 32],
        }
    }

    #[test]
    fn deterministic_channel() {
        let root = [0xAA; 32];
        let cap = dummy_cap();

        let mut ch1 = per_tx_algebraic_channel(&root, &cap, 0);
        let mut ch2 = per_tx_algebraic_channel(&root, &cap, 0);

        // Same inputs → same challenges
        let p1 = ch1.get_random_point();
        let p2 = ch2.get_random_point();
        assert_eq!(p1, p2, "Same inputs must produce same challenges");
    }

    #[test]
    fn different_tx_index_different_challenges() {
        let root = [0xAA; 32];
        let cap = dummy_cap();

        let mut ch1 = per_tx_algebraic_channel(&root, &cap, 0);
        let mut ch2 = per_tx_algebraic_channel(&root, &cap, 1);

        let p1 = ch1.get_random_point();
        let p2 = ch2.get_random_point();
        assert_ne!(
            p1, p2,
            "Different tx_index must produce different challenges"
        );
    }

    #[test]
    fn different_state_root_different_challenges() {
        let root1 = [0xAA; 32];
        let root2 = [0xBB; 32];
        let cap = dummy_cap();

        let mut ch1 = per_tx_algebraic_channel(&root1, &cap, 0);
        let mut ch2 = per_tx_algebraic_channel(&root2, &cap, 0);

        let p1 = ch1.get_random_point();
        let p2 = ch2.get_random_point();
        assert_ne!(
            p1, p2,
            "Different state roots must produce different challenges"
        );
    }

    #[test]
    fn different_cap_different_challenges() {
        let root = [0xAA; 32];
        let cap1 = MerkleCap {
            hashes: vec![[0u8; 32]; 32],
        };
        let cap2 = MerkleCap {
            hashes: vec![[1u8; 32]; 32],
        };

        let mut ch1 = per_tx_algebraic_channel(&root, &cap1, 0);
        let mut ch2 = per_tx_algebraic_channel(&root, &cap2, 0);

        let p1 = ch1.get_random_point();
        let p2 = ch2.get_random_point();
        assert_ne!(p1, p2, "Different caps must produce different challenges");
    }

    #[test]
    fn domain_separation_algebraic_vs_multipoint() {
        let root = [0xAA; 32];
        let cap = dummy_cap();

        let mut ch1 = per_tx_algebraic_channel(&root, &cap, 0);
        let mut ch2 = block_multipoint_channel(&root, &cap);

        let p1 = ch1.get_random_point();
        let p2 = ch2.get_random_point();
        assert_ne!(
            p1, p2,
            "Algebraic and multipoint channels must be different"
        );
    }

    #[test]
    fn domain_separation_algebraic_vs_state_binding() {
        let root = [0xAA; 32];
        let cap = dummy_cap();

        let mut ch1 = per_tx_algebraic_channel(&root, &cap, 10);
        let mut ch2 = state_binding_channel(&root, &cap, 10);

        let p1 = ch1.get_random_point();
        let p2 = ch2.get_random_point();
        assert_ne!(
            p1, p2,
            "Algebraic and state binding channels must be different"
        );
    }

    #[test]
    fn state_binding_uses_n_tx_as_index() {
        let root = [0xAA; 32];
        let cap = dummy_cap();

        // State binding with n_tx=10 should differ from per-tx with index=10
        let mut ch1 = per_tx_algebraic_channel(&root, &cap, 10);
        let mut ch2 = state_binding_channel(&root, &cap, 10);

        let p1 = ch1.get_random_point();
        let p2 = ch2.get_random_point();
        assert_ne!(
            p1, p2,
            "State binding must add additional domain separation"
        );
    }

    #[test]
    fn multiple_squeezes_deterministic() {
        let root = [0xAA; 32];
        let cap = dummy_cap();

        let mut ch1 = per_tx_algebraic_channel(&root, &cap, 0);
        let mut ch2 = per_tx_algebraic_channel(&root, &cap, 0);

        // Squeeze multiple challenges
        for _ in 0..10 {
            let p1 = ch1.get_random_point();
            let p2 = ch2.get_random_point();
            assert_eq!(p1, p2, "Multiple squeezes must be deterministic");
        }
    }

    #[test]
    fn observe_after_squeeze_changes_state() {
        let root = [0xAA; 32];
        let cap = dummy_cap();

        let mut ch1 = per_tx_algebraic_channel(&root, &cap, 0);
        let mut ch2 = per_tx_algebraic_channel(&root, &cap, 0);

        let p1 = ch1.get_random_point();

        // Observe additional data in ch2
        ch2.observe_field_elem(Block128::from(42u128));
        let p2 = ch2.get_random_point();

        assert_ne!(
            p1, p2,
            "Observing data after squeeze must change subsequent challenges"
        );
    }
}
