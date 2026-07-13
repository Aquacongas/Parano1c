// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Direct recursive-chain continuity boundary.

use noid_chain::block_header::BlockHeader;
use noid_chain::consensus::{
    checked_tx_epoch_height_decomposition, genesis_header, params::TX_EPOCH_BLOCKS,
};
use noid_chain::fri_state::StateRoot;
use noid_chain::hash_block_header;
use noid_core::Block128;
use noid_poseidon2b::primitives::Digest;

/// Canonical number of `Block128` lanes in [`ChainAccumulator`].
pub const CHAIN_ACCUMULATOR_LANES: usize = 11;

/// Direct recursive continuity state.
///
/// The lane order is consensus-significant and is centralized in
/// [`ChainAccumulator::to_lanes`] and [`ChainAccumulator::from_lanes`]:
///
/// ```text
/// height
/// tip_block_id[2]
/// state_root[2]
/// log_slots
/// active_slot_count
/// alloc_counter
/// epoch_anchor_id[2]
/// attested_coverage
/// ```
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ChainAccumulator {
    pub height: u64,
    pub tip_block_id: Digest,
    pub state_root: StateRoot,
    pub log_slots: u32,
    pub active_slot_count: u64,
    pub alloc_counter: u64,
    pub epoch_anchor_id: Digest,
    /// Proof-gated coinbase-maturity frontier carried by the tip header.
    pub attested_coverage: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainAccumulatorLaneError {
    HeightOutOfRange,
    LogSlotsOutOfRange,
    ActiveSlotCountOutOfRange,
    AllocCounterOutOfRange,
    AttestedCoverageOutOfRange,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainAccumulatorAdvanceError {
    HeightOverflow,
    BadHeight {
        expected: u64,
        actual: u64,
    },
    BadParentTip,
    /// Twin of consensus header rule 7 (`consensus::header`): the child must
    /// repeat the parent's coverage or advance it to at most `parent.height`.
    BadAttestedCoverage {
        parent_coverage: u64,
        parent_height: u64,
        attested_coverage: u64,
    },
}

/// Mismatch between a recovered recursive boundary and the node's locally
/// selected canonical header chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainAccumulatorLocalBoundaryError {
    Height,
    TipBlockId,
    StateRoot,
    LogSlots,
    ActiveSlotCount,
    AllocCounter,
    AttestedCoverage,
    EpochAnchorHeight { expected: u64, actual: u64 },
    EpochAnchorId,
}

impl core::fmt::Display for ChainAccumulatorLocalBoundaryError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Height => write!(f, "accumulator height does not match local tip"),
            Self::TipBlockId => write!(f, "accumulator tip id does not match local tip header"),
            Self::StateRoot => write!(f, "accumulator state root does not match local tip"),
            Self::LogSlots => write!(f, "accumulator log_slots does not match local tip"),
            Self::ActiveSlotCount => {
                write!(f, "accumulator active count does not match local tip")
            }
            Self::AllocCounter => {
                write!(f, "accumulator allocation counter does not match local tip")
            }
            Self::AttestedCoverage => {
                write!(f, "accumulator attested coverage does not match local tip")
            }
            Self::EpochAnchorHeight { expected, actual } => write!(
                f,
                "local epoch-anchor header has height {actual}, expected {expected}"
            ),
            Self::EpochAnchorId => write!(
                f,
                "accumulator epoch anchor does not match the local canonical epoch header"
            ),
        }
    }
}

impl std::error::Error for ChainAccumulatorLocalBoundaryError {}

impl ChainAccumulator {
    /// Encode the canonical eleven-lane recursive boundary.
    pub fn to_lanes(&self) -> [Block128; CHAIN_ACCUMULATOR_LANES] {
        let tip = digest_to_lanes(self.tip_block_id);
        let state = digest_to_lanes(self.state_root);
        let epoch = digest_to_lanes(self.epoch_anchor_id);
        [
            Block128::from(self.height),
            tip[0],
            tip[1],
            state[0],
            state[1],
            Block128::from(self.log_slots),
            Block128::from(self.active_slot_count),
            Block128::from(self.alloc_counter),
            epoch[0],
            epoch[1],
            Block128::from(self.attested_coverage),
        ]
    }

    /// Decode the canonical eleven-lane recursive boundary.
    ///
    /// Scalar lanes are range-checked before conversion. In particular, this
    /// API never truncates a field lane with `as u64`/`as u32`.
    pub fn from_lanes(
        lanes: [Block128; CHAIN_ACCUMULATOR_LANES],
    ) -> Result<Self, ChainAccumulatorLaneError> {
        Ok(Self {
            height: u64::try_from(lanes[0].to_u128())
                .map_err(|_| ChainAccumulatorLaneError::HeightOutOfRange)?,
            tip_block_id: digest_from_lanes([lanes[1], lanes[2]]),
            state_root: digest_from_lanes([lanes[3], lanes[4]]),
            log_slots: u32::try_from(lanes[5].to_u128())
                .map_err(|_| ChainAccumulatorLaneError::LogSlotsOutOfRange)?,
            active_slot_count: u64::try_from(lanes[6].to_u128())
                .map_err(|_| ChainAccumulatorLaneError::ActiveSlotCountOutOfRange)?,
            alloc_counter: u64::try_from(lanes[7].to_u128())
                .map_err(|_| ChainAccumulatorLaneError::AllocCounterOutOfRange)?,
            epoch_anchor_id: digest_from_lanes([lanes[8], lanes[9]]),
            attested_coverage: u64::try_from(lanes[10].to_u128())
                .map_err(|_| ChainAccumulatorLaneError::AttestedCoverageOutOfRange)?,
        })
    }

    /// Advance by one canonical child header.
    ///
    /// The child must link to the current tip and increment height exactly.
    /// Its direct state/depth/counters become the new boundary. The transaction
    /// epoch switches to the child id exactly at a 144-block boundary.
    pub fn advance(
        &self,
        child_header: &BlockHeader,
    ) -> Result<Self, ChainAccumulatorAdvanceError> {
        if child_header.prev_block_hash != self.tip_block_id {
            return Err(ChainAccumulatorAdvanceError::BadParentTip);
        }
        let expected_height = self
            .height
            .checked_add(1)
            .ok_or(ChainAccumulatorAdvanceError::HeightOverflow)?;
        if child_header.height != expected_height {
            return Err(ChainAccumulatorAdvanceError::BadHeight {
                expected: expected_height,
                actual: child_header.height,
            });
        }
        // Structural attested-coverage advancement rule — the exact twin of
        // `consensus::header::validate_header_inner` step 7: repeat the
        // parent's coverage or advance it to at most the parent height. The
        // "advanced iff a verified Link envelope accompanies the block" rule
        // stays with native block acceptance (it needs the detached payload).
        if child_header.attested_coverage < self.attested_coverage
            || (child_header.attested_coverage > self.attested_coverage
                && child_header.attested_coverage > self.height)
        {
            return Err(ChainAccumulatorAdvanceError::BadAttestedCoverage {
                parent_coverage: self.attested_coverage,
                parent_height: self.height,
                attested_coverage: child_header.attested_coverage,
            });
        }

        let child_id = hash_block_header(child_header);
        Ok(Self {
            height: child_header.height,
            tip_block_id: child_id,
            state_root: child_header.state_root,
            log_slots: child_header.log_slots,
            active_slot_count: child_header.active_slot_count,
            alloc_counter: child_header.alloc_counter,
            epoch_anchor_id: if checked_tx_epoch_height_decomposition(child_header.height)
                .expect("every u64 height has a checked transaction-epoch decomposition")
                .is_boundary()
            {
                child_id
            } else {
                self.epoch_anchor_id
            },
            attested_coverage: child_header.attested_coverage,
        })
    }

    /// Bind all ten recursive lanes to the locally selected canonical chain.
    ///
    /// `tip_header` and `epoch_anchor_header` must come from the node's native
    /// header store on the selected fork. The latter is the header at
    /// `floor(tip_height / 144) * 144`. Recomputing both ids makes the direct
    /// boundary sufficient; no rolling header projection is needed.
    pub fn validate_local_header_boundary(
        &self,
        tip_header: &BlockHeader,
        epoch_anchor_header: &BlockHeader,
    ) -> Result<(), ChainAccumulatorLocalBoundaryError> {
        if self.height != tip_header.height {
            return Err(ChainAccumulatorLocalBoundaryError::Height);
        }
        if self.tip_block_id != hash_block_header(tip_header) {
            return Err(ChainAccumulatorLocalBoundaryError::TipBlockId);
        }
        if self.state_root != tip_header.state_root {
            return Err(ChainAccumulatorLocalBoundaryError::StateRoot);
        }
        if self.log_slots != tip_header.log_slots {
            return Err(ChainAccumulatorLocalBoundaryError::LogSlots);
        }
        if self.active_slot_count != tip_header.active_slot_count {
            return Err(ChainAccumulatorLocalBoundaryError::ActiveSlotCount);
        }
        if self.alloc_counter != tip_header.alloc_counter {
            return Err(ChainAccumulatorLocalBoundaryError::AllocCounter);
        }
        if self.attested_coverage != tip_header.attested_coverage {
            return Err(ChainAccumulatorLocalBoundaryError::AttestedCoverage);
        }

        let expected_epoch_height = (tip_header.height / TX_EPOCH_BLOCKS) * TX_EPOCH_BLOCKS;
        if epoch_anchor_header.height != expected_epoch_height {
            return Err(ChainAccumulatorLocalBoundaryError::EpochAnchorHeight {
                expected: expected_epoch_height,
                actual: epoch_anchor_header.height,
            });
        }
        if self.epoch_anchor_id != hash_block_header(epoch_anchor_header) {
            return Err(ChainAccumulatorLocalBoundaryError::EpochAnchorId);
        }
        Ok(())
    }
}

/// Canonical blockless bootstrap boundary.
pub fn genesis_accumulator() -> ChainAccumulator {
    let header = genesis_header();
    let block_id = hash_block_header(&header);
    ChainAccumulator {
        height: header.height,
        tip_block_id: block_id,
        state_root: header.state_root,
        log_slots: header.log_slots,
        active_slot_count: header.active_slot_count,
        alloc_counter: header.alloc_counter,
        epoch_anchor_id: block_id,
        attested_coverage: header.attested_coverage,
    }
}

fn digest_to_lanes(digest: Digest) -> [Block128; 2] {
    [
        Block128::from(u128::from_le_bytes(digest[..16].try_into().unwrap())),
        Block128::from(u128::from_le_bytes(digest[16..].try_into().unwrap())),
    ]
}

fn digest_from_lanes(lanes: [Block128; 2]) -> Digest {
    let mut digest = [0u8; 32];
    digest[..16].copy_from_slice(&lanes[0].to_u128().to_le_bytes());
    digest[16..].copy_from_slice(&lanes[1].to_u128().to_le_bytes());
    digest
}

#[cfg(test)]
mod tests {
    use super::*;
    use noid_chain::consensus::params::GENESIS_TARGET;
    use noid_poseidon2b::primitives::Address;

    fn child(parent: &ChainAccumulator, height: u64) -> BlockHeader {
        BlockHeader {
            attested_coverage: 0,
            prev_block_hash: parent.tip_block_id,
            state_root: [height as u8; 32],
            tx_root: [0x33; 32],
            timestamp: height,
            height,
            miner_address: Address([0x44; 32]),
            nonce: height as u128,
            difficulty_target: GENESIS_TARGET,
            log_slots: 24 + u32::from(height >= 145),
            active_slot_count: height * 2,
            alloc_counter: height * 3,
        }
    }

    #[test]
    fn genesis_is_the_canonical_header_boundary() {
        let header = genesis_header();
        let id = hash_block_header(&header);
        assert_eq!(
            genesis_accumulator(),
            ChainAccumulator {
                height: 0,
                tip_block_id: id,
                state_root: header.state_root,
                log_slots: header.log_slots,
                active_slot_count: 0,
                alloc_counter: 0,
                epoch_anchor_id: id,
                attested_coverage: 0,
            }
        );
    }

    #[test]
    fn lanes_roundtrip_without_truncation() {
        let accumulator = ChainAccumulator {
            height: u64::MAX,
            tip_block_id: [0x11; 32],
            state_root: [0x22; 32],
            log_slots: u32::MAX,
            active_slot_count: u64::MAX - 1,
            alloc_counter: u64::MAX - 2,
            epoch_anchor_id: [0x33; 32],
            attested_coverage: u64::MAX - 3,
        };
        assert_eq!(
            ChainAccumulator::from_lanes(accumulator.to_lanes()),
            Ok(accumulator)
        );
    }

    #[test]
    fn lane_decoder_rejects_every_oversized_scalar() {
        let base = genesis_accumulator().to_lanes();
        for (lane, expected) in [
            (0, ChainAccumulatorLaneError::HeightOutOfRange),
            (5, ChainAccumulatorLaneError::LogSlotsOutOfRange),
            (6, ChainAccumulatorLaneError::ActiveSlotCountOutOfRange),
            (7, ChainAccumulatorLaneError::AllocCounterOutOfRange),
            (10, ChainAccumulatorLaneError::AttestedCoverageOutOfRange),
        ] {
            let mut lanes = base;
            lanes[lane] = if lane == 5 {
                Block128::from(u32::MAX as u128 + 1)
            } else {
                Block128::from(u64::MAX as u128 + 1)
            };
            assert_eq!(ChainAccumulator::from_lanes(lanes), Err(expected));
        }
    }

    #[test]
    fn advance_checks_link_and_exact_height() {
        let start = genesis_accumulator();
        let valid = child(&start, 1);
        let end = start.advance(&valid).unwrap();
        assert_eq!(end.height, 1);
        assert_eq!(end.tip_block_id, hash_block_header(&valid));
        assert_eq!(end.state_root, valid.state_root);
        assert_eq!(end.log_slots, valid.log_slots);
        assert_eq!(end.active_slot_count, valid.active_slot_count);
        assert_eq!(end.alloc_counter, valid.alloc_counter);
        assert_eq!(end.epoch_anchor_id, start.epoch_anchor_id);

        let mut bad_parent = valid;
        bad_parent.prev_block_hash = [0x99; 32];
        assert_eq!(
            start.advance(&bad_parent),
            Err(ChainAccumulatorAdvanceError::BadParentTip)
        );

        let bad_height = child(&start, 2);
        assert_eq!(
            start.advance(&bad_height),
            Err(ChainAccumulatorAdvanceError::BadHeight {
                expected: 1,
                actual: 2,
            })
        );

        let max = ChainAccumulator {
            height: u64::MAX,
            ..start
        };
        let overflow_child = child(&max, 0);
        assert_eq!(
            max.advance(&overflow_child),
            Err(ChainAccumulatorAdvanceError::HeightOverflow)
        );
    }

    /// Exact twin of `consensus::header` rule 7: the accumulator accepts a
    /// repeated coverage or a bounded advancement and rejects regression and
    /// beyond-parent-height jumps.
    #[test]
    fn advance_keeps_attested_coverage_monotone_and_below_parent_height() {
        let mut parent = genesis_accumulator();
        // Reach parent height 5 with coverage 3 by valid successions.
        for height in 1..=5u64 {
            let mut header = child(&parent, height);
            header.attested_coverage = (parent.attested_coverage + 1).min(parent.height).min(3);
            parent = parent.advance(&header).unwrap();
        }
        assert_eq!(parent.height, 5);
        assert_eq!(parent.attested_coverage, 3);

        let advance_with = |coverage: u64| {
            let mut header = child(&parent, 6);
            header.attested_coverage = coverage;
            parent.advance(&header)
        };
        // Repeating and bounded advancement are valid.
        assert_eq!(advance_with(3).unwrap().attested_coverage, 3);
        assert_eq!(advance_with(4).unwrap().attested_coverage, 4);
        assert_eq!(advance_with(5).unwrap().attested_coverage, 5);
        // Regression is rejected.
        assert_eq!(
            advance_with(2),
            Err(ChainAccumulatorAdvanceError::BadAttestedCoverage {
                parent_coverage: 3,
                parent_height: 5,
                attested_coverage: 2,
            })
        );
        // Advancing past the parent height is rejected.
        assert_eq!(
            advance_with(6),
            Err(ChainAccumulatorAdvanceError::BadAttestedCoverage {
                parent_coverage: 3,
                parent_height: 5,
                attested_coverage: 6,
            })
        );
    }

    #[test]
    fn epoch_changes_only_at_exact_boundary() {
        let mut accumulator = genesis_accumulator();
        let genesis_epoch = accumulator.epoch_anchor_id;
        let mut boundary_id = None;
        for height in 1..=145 {
            let header = child(&accumulator, height);
            let child_id = hash_block_header(&header);
            accumulator = accumulator.advance(&header).unwrap();
            match height {
                1..=143 => assert_eq!(accumulator.epoch_anchor_id, genesis_epoch),
                144 => {
                    boundary_id = Some(child_id);
                    assert_eq!(accumulator.epoch_anchor_id, child_id);
                }
                145 => assert_eq!(accumulator.epoch_anchor_id, boundary_id.unwrap()),
                _ => unreachable!(),
            }
        }
    }

    #[test]
    fn local_header_boundary_covers_epoch_edges_and_every_lane() {
        let genesis = genesis_header();
        let mut headers = vec![genesis];
        let mut accumulator = genesis_accumulator();
        let mut edge_boundaries = Vec::new();
        for height in 1..=145 {
            let header = child(&accumulator, height);
            accumulator = accumulator.advance(&header).unwrap();
            headers.push(header);
            if matches!(height, 143..=145) {
                edge_boundaries.push(accumulator.clone());
            }
        }

        for (boundary, epoch_height) in edge_boundaries.iter().zip([0usize, 144, 144]) {
            boundary
                .validate_local_header_boundary(
                    &headers[boundary.height as usize],
                    &headers[epoch_height],
                )
                .unwrap();
        }

        let honest = &edge_boundaries[2];
        let tip = &headers[145];
        let epoch = &headers[144];
        for lane in 0..CHAIN_ACCUMULATOR_LANES {
            let mut lanes = honest.to_lanes();
            lanes[lane] = Block128::from(lanes[lane].to_u128() ^ 1);
            let bad = ChainAccumulator::from_lanes(lanes).unwrap();
            assert!(
                bad.validate_local_header_boundary(tip, epoch).is_err(),
                "mutated accumulator lane {lane} accepted"
            );
        }

        let mut competing_tip = *tip;
        competing_tip.nonce = competing_tip.nonce.wrapping_add(1);
        assert_eq!(
            honest.validate_local_header_boundary(&competing_tip, epoch),
            Err(ChainAccumulatorLocalBoundaryError::TipBlockId)
        );

        assert_eq!(
            honest.validate_local_header_boundary(tip, &headers[143]),
            Err(ChainAccumulatorLocalBoundaryError::EpochAnchorHeight {
                expected: 144,
                actual: 143,
            })
        );
        let mut competing_epoch = *epoch;
        competing_epoch.nonce = competing_epoch.nonce.wrapping_add(1);
        assert_eq!(
            honest.validate_local_header_boundary(tip, &competing_epoch),
            Err(ChainAccumulatorLocalBoundaryError::EpochAnchorId)
        );
    }
}
