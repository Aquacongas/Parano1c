// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Header chain validation.
//!
//! Validates a candidate block header against its parent and the expected
//! ASERT difficulty target. Pure, I/O-free — the caller provides all data.
//!
//! Reference: Reth `crates/consensus/consensus/src/lib.rs` for structure.

use crate::block_header::BlockHeader;
use crate::consensus::{
    difficulty::next_target,
    expected_child_log_slots,
    params::{CONSENSUS_FINALITY_DEPTH, EPOCH_LENGTH},
    pow::{block_id, validate_pow},
    timestamps::{validate_future_drift, validate_median_time_past},
    ConsensusError,
};

/// Validate a candidate block header against its parent and recent timestamps.
///
/// Checks (in order):
/// 1. `prev_block_hash` == semantic Poseidon2b block id of the parent
/// 2. `height` == parent.height + 1
/// 3. `difficulty_target` == ASERT-computed target
/// 4. Timestamp rules (MTP + future drift)
/// 5. Poseidon2b PoW satisfies difficulty_target
/// 6. `log_slots` equals the exact median-window expansion result
///
/// Detached validation witness presence is checked by the block acceptance
/// path, not by semantic header validation.
///
/// `prev_timestamps`: timestamps of the last ≤11 ancestors, oldest-first.
/// `prev_active_counts`: active-slot counts of the last expansion-window
/// ancestors ending at the parent, oldest-first.
/// `local_time`: current wall-clock seconds (for future drift check).
/// `anchor_*`: epoch anchor values for ASERT.
pub fn validate_header(
    header: &BlockHeader,
    parent: &BlockHeader,
    prev_timestamps: &[u64],
    prev_active_counts: &[u64],
    local_time: u64,
    anchor_height: u64,
    anchor_timestamp: u64,
    anchor_target: &[u8; 32],
) -> Result<(), ConsensusError> {
    validate_header_inner(
        header,
        parent,
        prev_timestamps,
        prev_active_counts,
        Some(local_time),
        anchor_height,
        anchor_timestamp,
        anchor_target,
    )
}

/// Validate deterministic header consensus rules that can be proven for
/// historical recursive checkpoints.
///
/// This excludes only the local wall-clock future-drift admission policy.
pub fn validate_header_timeless(
    header: &BlockHeader,
    parent: &BlockHeader,
    prev_timestamps: &[u64],
    prev_active_counts: &[u64],
    anchor_height: u64,
    anchor_timestamp: u64,
    anchor_target: &[u8; 32],
) -> Result<(), ConsensusError> {
    validate_header_inner(
        header,
        parent,
        prev_timestamps,
        prev_active_counts,
        None,
        anchor_height,
        anchor_timestamp,
        anchor_target,
    )
}

fn validate_header_inner(
    header: &BlockHeader,
    parent: &BlockHeader,
    prev_timestamps: &[u64],
    prev_active_counts: &[u64],
    local_time: Option<u64>,
    anchor_height: u64,
    anchor_timestamp: u64,
    anchor_target: &[u8; 32],
) -> Result<(), ConsensusError> {
    // 1. Parent hash linkage.
    let expected_parent_hash = block_id(parent);
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
    validate_median_time_past(header.timestamp, prev_timestamps)
        .map_err(|_| ConsensusError::BadTimestamp)?;
    if let Some(local_time) = local_time {
        validate_future_drift(header.timestamp, local_time)
            .map_err(|_| ConsensusError::BadTimestamp)?;
    }

    // 5. Poseidon2b PoW over semantic header fields.
    validate_pow(header)?;

    // 6. Exact slot-space expansion.
    let expected_log_slots = expected_child_log_slots(
        parent.log_slots,
        parent.active_slot_count,
        prev_active_counts,
    );
    if header.log_slots != expected_log_slots {
        return Err(ConsensusError::BadLogSlotsExpansion);
    }

    // 7. Structural attested-coverage advancement rule.
    //
    // A header either repeats its parent's coverage or advances it to at most
    // `parent.height`. The exact rule (advanced iff a natively verified Link
    // envelope for exactly this height accompanies the block) is enforced by
    // the block acceptance path, which has the detached attestation payload.
    if header.attested_coverage < parent.attested_coverage
        || (header.attested_coverage > parent.attested_coverage
            && header.attested_coverage > parent.height)
    {
        return Err(ConsensusError::BadAttestedCoverage {
            parent_coverage: parent.attested_coverage,
            parent_height: parent.height,
            attested_coverage: header.attested_coverage,
        });
    }

    Ok(())
}

/// Determine the ASERT anchor for a given chain tip.
///
/// The anchor is the block at the most recent epoch boundary:
/// `anchor_height = largest H ≤ current_height where H % EPOCH_LENGTH == 0`.
pub fn asert_anchor_height(current_height: u64) -> u64 {
    (current_height / EPOCH_LENGTH) * EPOCH_LENGTH
}

/// Returns `true` if a block at `height` is considered final (cannot be reorged).
pub fn is_final(block_height: u64, tip_height: u64) -> bool {
    tip_height >= block_height + CONSENSUS_FINALITY_DEPTH
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::params::BLOCK_TIME;
    use noid_poseidon2b::primitives::Address;
    // Any hash satisfies this target — nonce=0 always works, no search needed.
    const TEST_TARGET: [u8; 32] = [0xFF; 32];

    fn make_header(height: u64, timestamp: u64, parent: Option<&BlockHeader>) -> BlockHeader {
        let prev_hash = parent.map(block_id).unwrap_or([0u8; 32]);
        BlockHeader {
            prev_block_hash: prev_hash,
            state_root: [0u8; 32],
            tx_root: [0u8; 32],
            timestamp,
            height,
            miner_address: Address([0u8; 32]),
            nonce: 0,
            difficulty_target: TEST_TARGET,
            log_slots: 24,
            active_slot_count: 0,
            alloc_counter: 0,
            attested_coverage: 0,
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
        let prev_active = vec![genesis.active_slot_count];
        let result = validate_header(
            &h1,
            &genesis,
            &prev_ts,
            &prev_active,
            h1.timestamp + 1,
            0,
            genesis.timestamp,
            &genesis.difficulty_target,
        );
        assert!(result.is_ok(), "valid header should accept: {:?}", result);
    }

    #[test]
    fn timeless_header_excludes_local_future_drift_policy() {
        let genesis = make_header(0, 1_000_000, None);
        let mut h1 = make_header(1, 1_000_000 + BLOCK_TIME, Some(&genesis));
        mine(&mut h1);
        let prev_ts = vec![genesis.timestamp];
        let prev_active = vec![genesis.active_slot_count];

        assert_eq!(
            validate_header(
                &h1,
                &genesis,
                &prev_ts,
                &prev_active,
                1,
                0,
                genesis.timestamp,
                &genesis.difficulty_target,
            ),
            Err(ConsensusError::BadTimestamp)
        );
        assert!(validate_header_timeless(
            &h1,
            &genesis,
            &prev_ts,
            &prev_active,
            0,
            genesis.timestamp,
            &genesis.difficulty_target,
        )
        .is_ok());
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
            &[genesis.active_slot_count],
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
        h1.prev_block_hash = block_id(&genesis);
        mine(&mut h1);
        let result = validate_header(
            &h1,
            &genesis,
            &[genesis.timestamp],
            &[genesis.active_slot_count],
            h1.timestamp + 1,
            0,
            genesis.timestamp,
            &genesis.difficulty_target,
        );
        assert_eq!(result, Err(ConsensusError::BadHeight));
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
            &[genesis.active_slot_count],
            h1.timestamp + 1,
            0,
            genesis.timestamp,
            &genesis.difficulty_target,
        );
        assert_eq!(result, Err(ConsensusError::BadLogSlotsExpansion));
    }

    #[test]
    fn attested_coverage_must_stay_monotone_and_below_parent_height() {
        let mut genesis = make_header(0, 1_000_000, None);
        genesis.attested_coverage = 0;
        let mut parent = make_header(5, 1_000_000, None);
        parent.attested_coverage = 3;

        let child = |coverage: u64| {
            // Perfect BLOCK_TIME spacing keeps ASERT at the anchor target.
            let mut h = make_header(6, 1_000_000 + 6 * BLOCK_TIME, Some(&parent));
            h.attested_coverage = coverage;
            mine(&mut h);
            h
        };
        let validate = |h: &BlockHeader| {
            validate_header(
                h,
                &parent,
                &[parent.timestamp],
                &[parent.active_slot_count],
                h.timestamp + 1,
                0,
                genesis.timestamp,
                &genesis.difficulty_target,
            )
        };

        // Keeping the parent's coverage is always structurally valid.
        assert!(validate(&child(3)).is_ok());
        // Advancing within (parent_coverage, parent.height] is structurally valid.
        assert!(validate(&child(4)).is_ok());
        assert!(validate(&child(5)).is_ok());
        // Regression is rejected.
        assert_eq!(
            validate(&child(2)),
            Err(ConsensusError::BadAttestedCoverage {
                parent_coverage: 3,
                parent_height: 5,
                attested_coverage: 2,
            })
        );
        // Advancing past the parent height is rejected.
        assert_eq!(
            validate(&child(6)),
            Err(ConsensusError::BadAttestedCoverage {
                parent_coverage: 3,
                parent_height: 5,
                attested_coverage: 6,
            })
        );
    }

    #[test]
    fn asert_anchor_height_examples() {
        assert_eq!(asert_anchor_height(0), 0);
        assert_eq!(asert_anchor_height(5), 0);
        assert_eq!(asert_anchor_height(6), 6);
        assert_eq!(asert_anchor_height(11), 6);
        assert_eq!(asert_anchor_height(12), 12);
        assert_eq!(asert_anchor_height(100), 96);
    }

    #[test]
    fn finality_check() {
        assert!(is_final(0, 18));
        assert!(!is_final(0, 17));
        assert!(is_final(100, 118));
    }
}
