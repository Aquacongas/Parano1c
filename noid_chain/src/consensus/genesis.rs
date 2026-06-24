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
//! The genesis state_root is the exact composite root of an empty chain state.

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
/// The header's PoW is pre-computed and hardcoded. The `state_root` is the
/// canonical empty-state root and `tx_root` is all-zeros (coinbase-only,
/// computed by the full node layer).
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
        // No BlockProof for genesis: marker value 0x01...01
        proof_transcript_hash: [0x01u8; 32],
        witness_root: [0u8; 32],
        log_slots: LOG_SLOTS_GENESIS,
        active_slot_count: 0,
        alloc_counter: 0,
    }
}

/// The canonical genesis state root: exact composite root of an all-zero UTXO
/// tree and empty ReuseGuard with `log_slots = LOG_SLOTS_GENESIS`.
///
/// Computed once via `SegmentedFriState::new_empty(24).root()` and hardcoded.
/// Verified by the test `genesis_state_root_matches_computed` below.
pub fn genesis_state_root() -> [u8; 32] {
    GENESIS_STATE_ROOT
}

/// Pre-computed genesis state root. All 2^24 slots are zero and the ReuseGuard is empty.
const GENESIS_STATE_ROOT: [u8; 32] = [
    0x1e, 0x88, 0xc2, 0xd9, 0xa5, 0x60, 0x86, 0x20, 0x1d, 0x57, 0xd1, 0x38, 0x4f, 0xda, 0xa6, 0xfc,
    0xe5, 0x56, 0xc0, 0x3a, 0x90, 0x1a, 0x45, 0x16, 0xed, 0xd6, 0x15, 0x0c, 0xf5, 0xcb, 0x65, 0x28,
];

/// Pre-mined genesis nonce.
/// Satisfies: `Blake3(header_core_bytes(genesis_header())) < GENESIS_TARGET`.
/// Recomputed after the source-binding Merkle hash width changed to 256 bits.
const GENESIS_NONCE: u128 = 447_551_453;

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
        let mut state = crate::state::ChainState::with_log_slots(24);
        assert_eq!(state.state_root(), genesis_state_root());
    }

    /// Print the new genesis state root and a valid nonce for it.
    /// Run with: cargo test -p noid_chain --lib -- consensus::genesis::tests::print_new_genesis --nocapture
    #[test]
    #[ignore]
    fn print_new_genesis() {
        let mut state = crate::state::ChainState::with_log_slots(24);
        let new_root = state.state_root();
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
        search_pow(&h, 0, 2_000_000_000).expect("genesis target is trivially satisfiable")
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
    #[allow(clippy::assertions_on_constants)]
    fn genesis_timestamp_is_reasonable() {
        assert!(GENESIS_TIMESTAMP > 1_700_000_000);
    }
}
