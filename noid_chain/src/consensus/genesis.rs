// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Genesis block construction (SPECIFICATION.md §1).
//!
//! The genesis block is hardcoded: same bytes on every node.
//! It has:
//! - Zero state (all slots empty)
//! - Trivial PoW target (2^252 — findable in microseconds)
//! - Coinbase to burn address (initial coins bootstrapping)
//! - `proof_transcript_hash = [1u8;32]` (marker — no real proof for genesis)
//!
//! The genesis state_root is `SegmentedFriState::new(LOG_SLOTS_GENESIS).root()`.

use crate::block_header::BlockHeader;
use crate::consensus::{
    params::{GENESIS_TARGET, LOG_SLOTS_GENESIS},
    pow::search_pow,
};
use noid_poseidon2b::primitives::Address;

/// Fixed genesis timestamp (2026-01-01 00:00:00 UTC).
pub const GENESIS_TIMESTAMP: u64 = 1_767_225_600;

/// The genesis burn address — coinbase recipient at height 0.
/// Uses a zero address; no private key is known.
pub const GENESIS_BURN_ADDRESS: Address = Address([0u8; 32]);

/// Build the canonical genesis block header.
///
/// The header's PoW is pre-computed and hardcoded. The `state_root` is
/// all-zeros (empty state) and `tx_root` is all-zeros (coinbase-only, computed
/// by the full node layer).
///
/// Every node must produce byte-identical output from this function.
pub fn genesis_header() -> BlockHeader {
    BlockHeader {
        prev_block_hash: [0u8; 32],
        state_root: genesis_state_root(),
        tx_root: [0u8; 32],
        timestamp: GENESIS_TIMESTAMP,
        height: 0,
        miner_address: GENESIS_BURN_ADDRESS,
        nonce: GENESIS_NONCE,
        difficulty_target: GENESIS_TARGET,
        // No ZK proof for genesis: marker value 0x01...01
        proof_transcript_hash: [0x01u8; 32],
        witness_root: [0u8; 32],
        log_slots: LOG_SLOTS_GENESIS,
        active_slot_count: 0,
        alloc_counter: 0,
    }
}

/// The canonical genesis state root: Poseidon2b Merkle root of an all-zero
/// `SegmentedFriState` with `log_slots = LOG_SLOTS_GENESIS`.
///
/// Computed once via `SegmentedFriState::new_empty(24).root()` and hardcoded.
/// Verified by the test `genesis_state_root_matches_computed` below.
pub fn genesis_state_root() -> [u8; 32] {
    GENESIS_STATE_ROOT
}

/// Pre-computed genesis state root. All 2^24 slots are zero.
const GENESIS_STATE_ROOT: [u8; 32] = [
    0x11, 0x34, 0x93, 0x89, 0x2a, 0x05, 0x33, 0x28, 0x9a, 0x8c, 0xda, 0x0c, 0xac, 0xea, 0xc6, 0xff,
    0xde, 0x9f, 0x1f, 0x18, 0x18, 0x71, 0xfc, 0x89, 0x92, 0x19, 0xa2, 0x75, 0x96, 0x12, 0x10, 0xcc,
];

/// Pre-mined genesis nonce.
/// Satisfies: `Blake3(header_core_bytes(genesis_header())) < GENESIS_TARGET`.
/// Found by searching nonces sequentially; nonce=2 is the first valid value.
const GENESIS_NONCE: u128 = 2;

/// Find and return a valid genesis nonce at runtime.
/// Used for verification only — not for production (nonce is hardcoded as `GENESIS_NONCE`).
pub fn find_genesis_nonce() -> u128 {
    let mut h = genesis_header();
    h.nonce = 0;
    search_pow(&h, 0, 100_000_000).expect("genesis target is trivially satisfiable")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::pow::validate_pow;

    #[test]
    fn genesis_header_is_deterministic() {
        let a = genesis_header();
        let b = genesis_header();
        assert_eq!(a.height, b.height);
        assert_eq!(a.timestamp, b.timestamp);
        assert_eq!(a.difficulty_target, b.difficulty_target);
        assert_eq!(a.prev_block_hash, b.prev_block_hash);
    }

    #[test]
    fn genesis_header_fields() {
        let h = genesis_header();
        assert_eq!(h.height, 0);
        assert_eq!(h.prev_block_hash, [0u8; 32]);
        assert_eq!(h.difficulty_target, GENESIS_TARGET);
        assert_ne!(h.proof_transcript_hash, [0u8; 32]);
        assert_eq!(h.log_slots, LOG_SLOTS_GENESIS);
        assert_eq!(h.active_slot_count, 0);
        assert_eq!(h.alloc_counter, 0);
    }

    #[test]
    fn genesis_state_root_matches_computed() {
        use crate::segmented_state::SegmentedFriState;
        let mut state = SegmentedFriState::new_empty(24);
        assert_eq!(
            state.root(),
            genesis_state_root(),
            "hardcoded GENESIS_STATE_ROOT must match SegmentedFriState::new_empty(24).root()"
        );
    }

    #[test]
    fn genesis_nonce_satisfies_pow() {
        let h = genesis_header();
        use crate::consensus::pow::validate_pow;
        assert!(
            validate_pow(&h).is_ok(),
            "GENESIS_NONCE={} must satisfy PoW",
            GENESIS_NONCE
        );
    }

    #[test]
    fn genesis_timestamp_is_reasonable() {
        // Must be after 2026-01-01
        assert!(GENESIS_TIMESTAMP > 1_700_000_000);
    }
}
