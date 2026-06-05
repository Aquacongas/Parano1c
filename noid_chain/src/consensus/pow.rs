// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Blake3 Proof-of-Work validation (SPECIFICATION.md §18.1-18.2).
//!
//! PoW is computed over `header_core` which does NOT include
//! `proof_transcript_hash`. This allows PoW search and ZK proving to run
//! in parallel: both are committed to the chain (the next block's
//! `prev_block_hash` = Blake3 of the FULL header), but miners only need
//! `header_core` to start searching.
//!
//! # Wire layout of header_core (256 bytes)
//!
//! ```text
//! prev_block_hash       [32B]
//! state_root            [32B]
//! tx_root               [32B]
//! timestamp             [ 8B]  LE u64
//! height                [ 8B]  LE u64
//! miner_address         [32B]
//! nonce                 [16B]  LE u128
//! difficulty_target     [32B]
//! log_slots             [ 4B]  LE u32
//! active_slot_count     [ 8B]  LE u64
//! alloc_counter         [ 8B]  LE u64
//! ---
//! Total: 212 bytes
//! ```

use crate::block_header::BlockHeader;
use crate::consensus::{difficulty::le256_lt, ConsensusError};

/// 212-byte `header_core` — the bytes that PoW is computed over.
/// Does NOT include `proof_transcript_hash` or `witness_root`.
pub type HeaderCoreBytes = Vec<u8>;

/// Byte offset of the `nonce` field in the 212-byte `header_core` buffer.
/// Layout: prev_block_hash(32) + state_root(32) + tx_root(32)
///        + timestamp(8) + height(8) + miner_address(32) = 144 bytes before nonce.
pub const NONCE_OFFSET: usize = 144;

/// Write `header_core` into a pre-allocated 212-byte stack buffer (zero allocation).
/// Call once per thread before the nonce loop, then patch only
/// `buf[NONCE_OFFSET..NONCE_OFFSET+16]` on each iteration.
pub fn header_core_bytes_into(h: &BlockHeader, buf: &mut [u8; 212]) {
    buf[0..32].copy_from_slice(&h.prev_block_hash);
    buf[32..64].copy_from_slice(&h.state_root);
    buf[64..96].copy_from_slice(&h.tx_root);
    buf[96..104].copy_from_slice(&h.timestamp.to_le_bytes());
    buf[104..112].copy_from_slice(&h.height.to_le_bytes());
    buf[112..144].copy_from_slice(h.miner_address.as_bytes());
    buf[144..160].copy_from_slice(&h.nonce.to_le_bytes());
    buf[160..192].copy_from_slice(&h.difficulty_target);
    buf[192..196].copy_from_slice(&h.log_slots.to_le_bytes());
    buf[196..204].copy_from_slice(&h.active_slot_count.to_le_bytes());
    buf[204..212].copy_from_slice(&h.alloc_counter.to_le_bytes());
    debug_assert_eq!(buf.len(), 212);
}

/// Full block hash (Blake3 of the complete block header, including proof fields).
pub type BlockHash = [u8; 32];

/// Serialize `header_core` (PoW input) from a `BlockHeader`.
///
/// The nonce is included; changing the nonce changes the hash.
/// `proof_transcript_hash` and `witness_root` are excluded so that
/// ZK proving and PoW search can proceed in parallel.
pub fn header_core_bytes(h: &BlockHeader) -> HeaderCoreBytes {
    let mut buf = Vec::with_capacity(212);
    buf.extend_from_slice(&h.prev_block_hash);
    buf.extend_from_slice(&h.state_root);
    buf.extend_from_slice(&h.tx_root);
    buf.extend_from_slice(&h.timestamp.to_le_bytes());
    buf.extend_from_slice(&h.height.to_le_bytes());
    buf.extend_from_slice(h.miner_address.as_bytes());
    buf.extend_from_slice(&h.nonce.to_le_bytes());
    buf.extend_from_slice(&h.difficulty_target);
    buf.extend_from_slice(&h.log_slots.to_le_bytes());
    buf.extend_from_slice(&h.active_slot_count.to_le_bytes());
    buf.extend_from_slice(&h.alloc_counter.to_le_bytes());
    debug_assert_eq!(buf.len(), 212);
    buf
}

/// Compute the full block hash (used as `prev_block_hash` in the next block).
///
/// This covers the COMPLETE header including `proof_transcript_hash`.
/// Different from the PoW hash: `proof_transcript_hash` is included here
/// so the full header is committed to the chain.
pub fn full_block_hash(h: &BlockHeader) -> BlockHash {
    use blake3::Hasher;
    let mut hasher = Hasher::new();
    // Full header: header_core + proof_transcript_hash + witness_root
    hasher.update(&header_core_bytes(h));
    hasher.update(&h.proof_transcript_hash);
    hasher.update(&h.witness_root);
    *hasher.finalize().as_bytes()
}

/// Validate that the block satisfies the declared PoW target.
///
/// Computes `pow_hash = Blake3(header_core_bytes(header))` and checks
/// `pow_hash < header.difficulty_target` (both as 256-bit LE integers).
///
/// Returns `Ok(pow_hash)` on success.
pub fn validate_pow(header: &BlockHeader) -> Result<BlockHash, ConsensusError> {
    let core = header_core_bytes(header);
    let hash = *blake3::hash(&core).as_bytes();

    // Compare as 256-bit little-endian integers: byte 31 is most significant.
    if le256_lt(&hash, &header.difficulty_target) {
        Ok(hash)
    } else {
        Err(ConsensusError::InvalidPoW)
    }
}

/// Search for a valid PoW nonce in `[start, start + range)`.
///
/// Returns `Some(nonce)` if a valid nonce is found, `None` otherwise.
/// This is called by the mining engine in parallel across thread ranges.
///
/// Uses a pre-allocated 212-byte stack buffer and patches only the 16 nonce
/// bytes per iteration — no heap allocation in the inner loop.
pub fn search_pow(header_template: &BlockHeader, start_nonce: u128, range: u128) -> Option<u128> {
    let mut buf = [0u8; 212];
    header_core_bytes_into(header_template, &mut buf);
    let target = &header_template.difficulty_target;
    for nonce in start_nonce..start_nonce.saturating_add(range) {
        buf[NONCE_OFFSET..NONCE_OFFSET + 16].copy_from_slice(&nonce.to_le_bytes());
        let hash = *blake3::hash(&buf).as_bytes();
        if le256_lt(&hash, target) {
            return Some(nonce);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block_header::BlockHeader;
    use noid_poseidon2b::primitives::Address;
    // Trivially-satisfiable test target: any Blake3 hash < [0xFF;32].
    const TEST_TARGET: [u8; 32] = [0xFF; 32];

    fn dummy_header() -> BlockHeader {
        BlockHeader {
            prev_block_hash: [0u8; 32],
            state_root: [1u8; 32],
            tx_root: [2u8; 32],
            timestamp: 1_700_000_000,
            height: 1,
            miner_address: Address([3u8; 32]),
            nonce: 0,
            difficulty_target: TEST_TARGET,
            proof_transcript_hash: [4u8; 32],
            witness_root: [5u8; 32],
            log_slots: 24,
            active_slot_count: 0,
            alloc_counter: 0,
        }
    }

    #[test]
    fn header_core_bytes_length() {
        let h = dummy_header();
        assert_eq!(header_core_bytes(&h).len(), 212);
    }

    #[test]
    fn header_core_excludes_proof_fields() {
        let mut h1 = dummy_header();
        let mut h2 = dummy_header();
        // Different proof_transcript_hash should NOT affect header_core.
        h1.proof_transcript_hash = [0xAA; 32];
        h2.proof_transcript_hash = [0xBB; 32];
        assert_eq!(header_core_bytes(&h1), header_core_bytes(&h2));
        // But they should produce different full_block_hash.
        assert_ne!(full_block_hash(&h1), full_block_hash(&h2));
    }

    #[test]
    fn nonce_change_changes_pow_hash() {
        let mut h = dummy_header();
        let bytes1 = header_core_bytes(&h);
        h.nonce = 42;
        let bytes2 = header_core_bytes(&h);
        assert_ne!(bytes1, bytes2);
    }

    #[test]
    fn genesis_target_trivially_satisfiable() {
        // GENESIS_TARGET = 2^228: avg 2^28 ≈ 268 M attempts.
        // Use a header with the real GENESIS_TARGET (dummy_header uses TEST_TARGET now).
        use crate::consensus::params::GENESIS_TARGET;
        use rayon::prelude::*;
        let mut h = dummy_header();
        h.difficulty_target = GENESIS_TARGET;
        // Parallel search: 12 cores × 19 MH/s ≈ 228 MH/s → avg ~1.2 s.
        let chunk = 10_000_000u128;
        let nonce = (0u64..300)
            .into_par_iter()
            .find_map_any(|i| search_pow(&h, i as u128 * chunk, chunk))
            .expect("genesis_target_trivially_satisfiable: no nonce in 3 B attempts");
        h.nonce = nonce;
        assert!(validate_pow(&h).is_ok());
    }

    #[test]
    fn validate_pow_rejects_wrong_nonce() {
        // Use a very tight target that a random nonce won't satisfy.
        let mut h = dummy_header();
        h.difficulty_target = [0u8; 32]; // impossible target (0)
        assert_eq!(validate_pow(&h), Err(ConsensusError::InvalidPoW));
    }

    #[test]
    fn validate_pow_accepts_valid_nonce() {
        // dummy_header uses TEST_TARGET = [0xFF;32]: nonce=0 trivially satisfies it.
        let mut h = dummy_header();
        h.nonce = 0;
        assert!(validate_pow(&h).is_ok());
    }

    #[test]
    fn le256_lt_correctness() {
        let zero = [0u8; 32];
        let mut one = [0u8; 32];
        one[0] = 1;
        let mut big = [0u8; 32];
        big[31] = 1; // = 2^248

        assert!(le256_lt(&zero, &one));
        assert!(le256_lt(&one, &big));
        assert!(!le256_lt(&big, &zero));
        assert!(!le256_lt(&one, &one)); // equal → false
    }
}
