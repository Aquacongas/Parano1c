// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Header chain validation (SPECIFICATION.md §16.2–16.7).
//!
//! Validates a candidate block header against its parent and the expected
//! ASERT difficulty target. Pure, I/O-free — the caller provides all data.
//!
//! Reference: Reth `crates/consensus/consensus/src/lib.rs` for structure.

use crate::block_header::BlockHeader;
use crate::consensus::{
    difficulty::next_target,
    params::{ANCHOR_DEPTH, EPOCH_LENGTH, FINALITY_DEPTH, LOG_SLOTS_MAX},
    pow::{full_block_hash, validate_pow},
    timestamps::validate_timestamp,
    ConsensusError,
};

/// Validate a candidate block header against its parent and recent timestamps.
///
/// Checks (in order):
/// 1. `prev_block_hash` == Blake3(full parent header)
/// 2. `height` == parent.height + 1
/// 3. `difficulty_target` == ASERT-computed target
/// 4. Timestamp rules (MTP + future drift)
/// 5. Blake3 PoW satisfies difficulty_target
/// 6. `proof_transcript_hash != [0;32]` (block has a ZK proof)
/// 7. `log_slots >= parent.log_slots` (slot space monotone)
///
/// `prev_timestamps`: timestamps of the last ≤11 ancestors, oldest-first.
/// `local_time`: current wall-clock seconds (for future drift check).
/// `anchor_*`: epoch anchor values for ASERT.
pub fn validate_header(
    header: &BlockHeader,
    parent: &BlockHeader,
    prev_timestamps: &[u64],
    local_time: u64,
    anchor_height: u64,
    anchor_timestamp: u64,
    anchor_target: &[u8; 32],
) -> Result<(), ConsensusError> {
    // 1. Parent hash linkage.
    let expected_parent_hash = full_block_hash(parent);
    if header.prev_block_hash != expected_parent_hash {
        return Err(ConsensusError::BadParentHash);
    }

    // 2. Height.
    if header.height != parent.height + 1 {
        return Err(ConsensusError::BadHeight);
    }

    // 3. Difficulty target matches ASERT expectation.
    let expected_target = next_target(
        anchor_height,
        anchor_timestamp,
        anchor_target,
        header.height,
        header.timestamp,
    );
    if header.difficulty_target != expected_target {
        return Err(ConsensusError::BadDifficultyTarget);
    }

    // 4. Timestamp rules.
    validate_timestamp(header.timestamp, prev_timestamps, local_time)
        .map_err(|_| ConsensusError::BadTimestamp)?;

    // 5. PoW over header_core.
    validate_pow(header)?;

    // 6. Proof must be attached (non-zero proof_transcript_hash).
    if header.proof_transcript_hash == [0u8; 32] {
        return Err(ConsensusError::MissingProof);
    }

    // 7. Slot space monotone.
    if header.log_slots < parent.log_slots {
        return Err(ConsensusError::BadLogSlots);
    }
    if header.log_slots > LOG_SLOTS_MAX {
        return Err(ConsensusError::ShapeMismatch(format!(
            "log_slots {} exceeds max {}",
            header.log_slots, LOG_SLOTS_MAX
        )));
    }

    Ok(())
}

/// Determine the ASERT anchor for a given chain tip.
///
/// The anchor is the block at the most recent epoch boundary:
/// `anchor_height = largest H ≤ current_height where H % EPOCH_LENGTH == 0`.
pub fn epoch_anchor_height(current_height: u64) -> u64 {
    (current_height / EPOCH_LENGTH) * EPOCH_LENGTH
}

/// Check whether a block at `height` is within the valid epoch anchor window
/// for a transaction (i.e., `epoch_anchor` hash must be from a header at
/// `[height - ANCHOR_DEPTH - 1, height - 1]`).
pub fn is_anchor_height_valid(tx_anchor_height: u64, block_height: u64) -> bool {
    if block_height == 0 {
        return tx_anchor_height == 0;
    }
    let lo = block_height.saturating_sub(ANCHOR_DEPTH + 1);
    let hi = block_height - 1;
    tx_anchor_height >= lo && tx_anchor_height <= hi
}

/// Returns `true` if a block at `height` is considered final (cannot be reorged).
pub fn is_final(block_height: u64, tip_height: u64) -> bool {
    tip_height >= block_height + FINALITY_DEPTH
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::params::BLOCK_TIME;
    use noid_poseidon2b::primitives::Address;
    // Any hash satisfies this target — nonce=0 always works, no search needed.
    const TEST_TARGET: [u8; 32] = [0xFF; 32];

    fn make_header(height: u64, timestamp: u64, parent: Option<&BlockHeader>) -> BlockHeader {
        let prev_hash = parent.map(full_block_hash).unwrap_or([0u8; 32]);
        BlockHeader {
            prev_block_hash: prev_hash,
            state_root: [0u8; 32],
            tx_root: [0u8; 32],
            timestamp,
            height,
            miner_address: Address([0u8; 32]),
            nonce: 0,
            difficulty_target: TEST_TARGET,
            proof_transcript_hash: [1u8; 32], // non-zero
            witness_root: [0u8; 32],
            log_slots: 24,
            active_slot_count: 0,
            alloc_counter: 0,
        }
    }

    fn mine(header: &mut BlockHeader) {
        // TEST_TARGET: nonce=0 trivially satisfies any target of [0xFF;32].
        // search_pow(header, 0, 1) would always return Some(0).
        header.nonce = 0;
    }

    #[test]
    fn valid_header_accepts() {
        let genesis = make_header(0, 1_000_000, None);
        let mut h1 = make_header(1, 1_000_000 + BLOCK_TIME, Some(&genesis));
        mine(&mut h1);
        let prev_ts = vec![genesis.timestamp];
        let result = validate_header(
            &h1,
            &genesis,
            &prev_ts,
            h1.timestamp + 1,
            0,
            genesis.timestamp,
            &genesis.difficulty_target,
        );
        assert!(result.is_ok(), "valid header should accept: {:?}", result);
    }

    #[test]
    fn wrong_parent_hash_rejects() {
        let genesis = make_header(0, 1_000_000, None);
        let mut h1 = make_header(1, 1_000_000 + BLOCK_TIME, Some(&genesis));
        mine(&mut h1);
        h1.prev_block_hash = [0xAB; 32]; // tamper
        let result = validate_header(
            &h1,
            &genesis,
            &[genesis.timestamp],
            h1.timestamp + 1,
            0,
            genesis.timestamp,
            &genesis.difficulty_target,
        );
        assert_eq!(result, Err(ConsensusError::BadParentHash));
    }

    #[test]
    fn wrong_height_rejects() {
        let genesis = make_header(0, 1_000_000, None);
        let mut h1 = make_header(2, 1_000_000 + BLOCK_TIME, Some(&genesis)); // height=2 wrong
        h1.prev_block_hash = full_block_hash(&genesis);
        mine(&mut h1);
        let result = validate_header(
            &h1,
            &genesis,
            &[genesis.timestamp],
            h1.timestamp + 1,
            0,
            genesis.timestamp,
            &genesis.difficulty_target,
        );
        assert_eq!(result, Err(ConsensusError::BadHeight));
    }

    #[test]
    fn missing_proof_rejects() {
        let genesis = make_header(0, 1_000_000, None);
        let mut h1 = make_header(1, 1_000_000 + BLOCK_TIME, Some(&genesis));
        h1.proof_transcript_hash = [0u8; 32]; // no proof
        mine(&mut h1);
        let result = validate_header(
            &h1,
            &genesis,
            &[genesis.timestamp],
            h1.timestamp + 1,
            0,
            genesis.timestamp,
            &genesis.difficulty_target,
        );
        assert_eq!(result, Err(ConsensusError::MissingProof));
    }

    #[test]
    fn decreasing_log_slots_rejects() {
        let genesis = make_header(0, 1_000_000, None);
        let mut h1 = make_header(1, 1_000_000 + BLOCK_TIME, Some(&genesis));
        h1.log_slots = 23; // less than genesis 24
        mine(&mut h1);
        let result = validate_header(
            &h1,
            &genesis,
            &[genesis.timestamp],
            h1.timestamp + 1,
            0,
            genesis.timestamp,
            &genesis.difficulty_target,
        );
        assert_eq!(result, Err(ConsensusError::BadLogSlots));
    }

    #[test]
    fn epoch_anchor_height_examples() {
        assert_eq!(epoch_anchor_height(0), 0);
        assert_eq!(epoch_anchor_height(5), 0);
        assert_eq!(epoch_anchor_height(6), 6);
        assert_eq!(epoch_anchor_height(11), 6);
        assert_eq!(epoch_anchor_height(12), 12);
        assert_eq!(epoch_anchor_height(100), 96); // 100/6*6 = 96
    }

    #[test]
    fn anchor_window_validation() {
        // With ANCHOR_DEPTH=144, for block at height 10:
        // lo = 10 - 145 = 0 (saturated), hi = 9 → anchors [0, 9] all valid.
        assert!(is_anchor_height_valid(9, 10));
        assert!(is_anchor_height_valid(5, 10));
        assert!(is_anchor_height_valid(3, 10));
        assert!(is_anchor_height_valid(0, 10)); // genesis anchor valid (depth=144 >> 10)
        assert!(!is_anchor_height_valid(10, 10)); // current height not valid (must be past block)

        // Test at a height where the window actually truncates.
        // For block at height = ANCHOR_DEPTH + 50:
        let h = ANCHOR_DEPTH + 50; // e.g. height=194
        let lo = h - ANCHOR_DEPTH - 1; // = 49
        assert!(is_anchor_height_valid(lo, h)); // just inside
        assert!(!is_anchor_height_valid(lo - 1, h)); // just outside
        assert!(!is_anchor_height_valid(h, h)); // current height not valid
        assert!(is_anchor_height_valid(h - 1, h)); // latest valid
    }

    #[test]
    fn finality_check() {
        assert!(is_final(0, 18));
        assert!(!is_final(0, 17));
        assert!(is_final(100, 118));
    }
}
