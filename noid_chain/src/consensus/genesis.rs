// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Genesis block construction.
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

/// Fixed genesis timestamp (2026-06-05 09:37:02 UTC).
pub const GENESIS_TIMESTAMP: u64 = 1_780_652_222;

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
/// Computed via compact interleaved FRI (`noid_fri_binius`).
const GENESIS_STATE_ROOT: [u8; 32] = [
    0x6e, 0x7e, 0xb7, 0x14, 0x15, 0xb4, 0xbe, 0xea, 0x72, 0x39, 0xac, 0xa4, 0x09, 0xed, 0x0a, 0x80,
    0x6b, 0x3b, 0x21, 0xd2, 0xf2, 0xb5, 0x3f, 0x96, 0x38, 0xff, 0x2f, 0x48, 0xcb, 0xcd, 0xbd, 0x34,
];

/// Pre-mined genesis nonce.
/// Satisfies: `Blake3(header_core_bytes(genesis_header())) < GENESIS_TARGET`.
/// Recomputed after GENESIS_TARGET changed to 2^229 (halved difficulty).
const GENESIS_NONCE: u128 = 15_108_031;

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

    /// Print the new genesis state root and a valid nonce for it.
    /// Run with: cargo test -p noid_chain --lib -- consensus::genesis::tests::print_new_genesis --nocapture
    #[test]
    fn print_new_genesis() {
        use crate::segmented_state::SegmentedFriState;
        let mut state = SegmentedFriState::new_empty(24);
        let new_root = state.root();
        println!("\nNew GENESIS_STATE_ROOT:");
        print!("const GENESIS_STATE_ROOT: [u8; 32] = [");
        for (i, b) in new_root.iter().enumerate() {
            if i % 16 == 0 {
                print!("\n    ");
            }
            print!("0x{:02x}, ", b);
        }
        println!("\n];");
        let new_nonce = find_genesis_nonce_for(&new_root);
        println!("New GENESIS_NONCE: {}", new_nonce);
    }

    fn find_genesis_nonce_for(state_root: &[u8; 32]) -> u128 {
        use crate::block_header::BlockHeader;
        use crate::consensus::params::{GENESIS_TARGET, LOG_SLOTS_GENESIS};
        use crate::consensus::pow::search_pow;
        let h = BlockHeader {
            prev_block_hash: [0u8; 32],
            state_root: *state_root,
            tx_root: [0u8; 32],
            timestamp: GENESIS_TIMESTAMP,
            height: 0,
            miner_address: GENESIS_BURN_ADDRESS,
            nonce: 0,
            difficulty_target: GENESIS_TARGET,
            proof_transcript_hash: [0x01u8; 32],
            witness_root: [0u8; 32],
            log_slots: LOG_SLOTS_GENESIS,
            active_slot_count: 0,
            alloc_counter: 0,
        };
        search_pow(&h, 0, 200_000_000).expect("genesis target is trivially satisfiable")
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
        assert!(GENESIS_TIMESTAMP > 1_700_000_000);
    }
}
