// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Header integer transition relation.
//!
//! This module deliberately does not compute Poseidon2b header hashes. The
//! companion `HeaderHashProofKillShot` proves that `pow_digest` and `block_id`
//! are derived from the canonical header fields. This relation consumes those
//! already-bound values and checks the exact integer consensus semantics.

use noid_chain::consensus::difficulty::{add_work, block_work, le256_lt, next_target};
use noid_chain::consensus::expected_child_log_slots;
use noid_chain::consensus::header::asert_anchor_height;
use noid_chain::consensus::pow::pow_header_fields;
use noid_chain::consensus::timestamps::median_time_past;
use noid_chain::consensus::ConsensusError;

use crate::pow_header::{HeaderWitness, RecursiveConsensusState};

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HeaderIntegerStepTrace {
    pub expected_target: [u8; 32],
    pub median_time_past: u64,
    pub expected_log_slots: u32,
    pub block_work: [u8; 32],
    pub cumulative_chainwork_after: [u8; 32],
    pub asert_anchor_height_after: u64,
    pub asert_anchor_timestamp_after: u64,
    pub asert_anchor_target_after: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HeaderIntegerBatchTrace {
    pub steps: Vec<HeaderIntegerStepTrace>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeaderIntegerTraceError {
    EmptyBatch,
    StepCountMismatch { headers: usize, steps: usize },
    BadPowFields { index: usize },
    BadTargetField { index: usize },
    BadParentLink { index: usize },
    BadHeight { index: usize },
    BadDifficultyTarget { index: usize },
    BadMedianTimePast { index: usize },
    BadPowTarget { index: usize },
    BadLogSlots { index: usize },
    BadAttestedCoverage { index: usize },
    BadBlockWork { index: usize },
    BadChainwork { index: usize },
    BadAsertAnchor { index: usize },
}

pub fn build_header_integer_trace(
    start: &RecursiveConsensusState,
    witnesses: &[HeaderWitness],
) -> Result<HeaderIntegerBatchTrace, HeaderIntegerTraceError> {
    if witnesses.is_empty() {
        return Err(HeaderIntegerTraceError::EmptyBatch);
    }

    let mut state = start.clone();
    let mut steps = Vec::with_capacity(witnesses.len());
    for witness in witnesses {
        let header = &witness.header;
        let expected_target = next_target(
            state.asert_anchor_height,
            state.asert_anchor_timestamp,
            &state.asert_anchor_target,
            header.height,
            header.timestamp,
        );
        let mtp = median_time_past(state.timestamps());
        let expected_log_slots = expected_child_log_slots(
            state.log_slots,
            state.active_slot_count,
            state.active_counts(),
        );
        let work = block_work(&header.difficulty_target);
        let cumulative_after = add_work(&state.cumulative_chainwork, &work);

        let mut anchor_height_after = state.asert_anchor_height;
        let mut anchor_timestamp_after = state.asert_anchor_timestamp;
        let mut anchor_target_after = state.asert_anchor_target;
        if asert_anchor_height(header.height) == header.height {
            anchor_height_after = header.height;
            anchor_timestamp_after = header.timestamp;
            anchor_target_after = header.difficulty_target;
        }

        steps.push(HeaderIntegerStepTrace {
            expected_target,
            median_time_past: mtp,
            expected_log_slots,
            block_work: work,
            cumulative_chainwork_after: cumulative_after,
            asert_anchor_height_after: anchor_height_after,
            asert_anchor_timestamp_after: anchor_timestamp_after,
            asert_anchor_target_after: anchor_target_after,
        });

        advance_state_from_step(&mut state, witness, steps.last().expect("step just pushed"));
    }

    Ok(HeaderIntegerBatchTrace { steps })
}

pub fn verify_header_integer_trace(
    start: &RecursiveConsensusState,
    witnesses: &[HeaderWitness],
    trace: &HeaderIntegerBatchTrace,
) -> Result<RecursiveConsensusState, HeaderIntegerTraceError> {
    if witnesses.is_empty() {
        return Err(HeaderIntegerTraceError::EmptyBatch);
    }
    if witnesses.len() != trace.steps.len() {
        return Err(HeaderIntegerTraceError::StepCountMismatch {
            headers: witnesses.len(),
            steps: trace.steps.len(),
        });
    }

    let mut state = start.clone();
    for (index, (witness, step)) in witnesses.iter().zip(trace.steps.iter()).enumerate() {
        let header = &witness.header;

        if witness.pow_fields != pow_header_fields(header) {
            return Err(HeaderIntegerTraceError::BadPowFields { index });
        }
        if witness.target != header.difficulty_target {
            return Err(HeaderIntegerTraceError::BadTargetField { index });
        }
        if header.prev_block_hash != state.block_id {
            return Err(HeaderIntegerTraceError::BadParentLink { index });
        }
        if header.height != state.height + 1 {
            return Err(HeaderIntegerTraceError::BadHeight { index });
        }

        let expected_target = next_target(
            state.asert_anchor_height,
            state.asert_anchor_timestamp,
            &state.asert_anchor_target,
            header.height,
            header.timestamp,
        );
        if step.expected_target != expected_target || header.difficulty_target != expected_target {
            return Err(HeaderIntegerTraceError::BadDifficultyTarget { index });
        }

        let mtp = median_time_past(state.timestamps());
        if step.median_time_past != mtp || header.timestamp <= mtp {
            return Err(HeaderIntegerTraceError::BadMedianTimePast { index });
        }

        if !le256_lt(&witness.pow_digest, &header.difficulty_target) {
            return Err(HeaderIntegerTraceError::BadPowTarget { index });
        }

        let expected_log_slots = expected_child_log_slots(
            state.log_slots,
            state.active_slot_count,
            state.active_counts(),
        );
        if step.expected_log_slots != expected_log_slots || header.log_slots != expected_log_slots {
            return Err(HeaderIntegerTraceError::BadLogSlots { index });
        }

        // Structural attested-coverage advancement rule — the exact twin of
        // `consensus::header::validate_header_inner` step 7: repeat the
        // parent's coverage or advance it to at most the parent height.
        if header.attested_coverage < state.attested_coverage
            || (header.attested_coverage > state.attested_coverage
                && header.attested_coverage > state.height)
        {
            return Err(HeaderIntegerTraceError::BadAttestedCoverage { index });
        }

        let work = block_work(&header.difficulty_target);
        if step.block_work != work {
            return Err(HeaderIntegerTraceError::BadBlockWork { index });
        }
        let cumulative_after = add_work(&state.cumulative_chainwork, &work);
        if step.cumulative_chainwork_after != cumulative_after {
            return Err(HeaderIntegerTraceError::BadChainwork { index });
        }

        let mut anchor_height_after = state.asert_anchor_height;
        let mut anchor_timestamp_after = state.asert_anchor_timestamp;
        let mut anchor_target_after = state.asert_anchor_target;
        if asert_anchor_height(header.height) == header.height {
            anchor_height_after = header.height;
            anchor_timestamp_after = header.timestamp;
            anchor_target_after = header.difficulty_target;
        }
        if step.asert_anchor_height_after != anchor_height_after
            || step.asert_anchor_timestamp_after != anchor_timestamp_after
            || step.asert_anchor_target_after != anchor_target_after
        {
            return Err(HeaderIntegerTraceError::BadAsertAnchor { index });
        }

        advance_state_from_step(&mut state, witness, step);
    }

    Ok(state)
}

fn advance_state_from_step(
    state: &mut RecursiveConsensusState,
    witness: &HeaderWitness,
    step: &HeaderIntegerStepTrace,
) {
    let header = &witness.header;
    state.height = header.height;
    state.block_id = witness.block_id;
    state.state_root = header.state_root;
    state.cumulative_chainwork = step.cumulative_chainwork_after;
    state.log_slots = header.log_slots;
    state.active_slot_count = header.active_slot_count;
    state.alloc_counter = header.alloc_counter;
    state.attested_coverage = header.attested_coverage;
    state.push_timestamp(header.timestamp);
    state.push_active_count(header.active_slot_count);
    state.asert_anchor_height = step.asert_anchor_height_after;
    state.asert_anchor_timestamp = step.asert_anchor_timestamp_after;
    state.asert_anchor_target = step.asert_anchor_target_after;
}

impl From<HeaderIntegerTraceError> for ConsensusError {
    fn from(error: HeaderIntegerTraceError) -> Self {
        match error {
            HeaderIntegerTraceError::BadParentLink { .. } => ConsensusError::BadParentHash,
            HeaderIntegerTraceError::BadHeight { .. } => ConsensusError::BadHeight,
            HeaderIntegerTraceError::BadDifficultyTarget { .. } => {
                ConsensusError::BadDifficultyTarget
            }
            HeaderIntegerTraceError::BadMedianTimePast { .. } => ConsensusError::BadTimestamp,
            HeaderIntegerTraceError::BadPowTarget { .. } => ConsensusError::InvalidPoW,
            HeaderIntegerTraceError::BadLogSlots { .. } => ConsensusError::BadLogSlotsExpansion,
            _ => ConsensusError::ShapeMismatch(format!("{error:?}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use noid_chain::block_header::BlockHeader;
    use noid_chain::consensus::difficulty::block_work;
    use noid_chain::consensus::params::{BLOCK_TIME, MAX_TARGET};
    use noid_chain::consensus::pow::block_id;
    use noid_poseidon2b::primitives::Address;

    fn genesis() -> BlockHeader {
        BlockHeader {
            attested_coverage: 0,
            prev_block_hash: [0u8; 32],
            state_root: [0u8; 32],
            tx_root: [0u8; 32],
            timestamp: 1_000_000,
            height: 0,
            miner_address: Address([0u8; 32]),
            nonce: 0,
            difficulty_target: MAX_TARGET,
            log_slots: 8,
            active_slot_count: 0,
            alloc_counter: 0,
        }
    }

    fn start_state(g: &BlockHeader) -> RecursiveConsensusState {
        RecursiveConsensusState::from_header(
            g,
            block_work(&g.difficulty_target),
            0,
            g.timestamp,
            g.difficulty_target,
            &[g.timestamp],
            &[g.active_slot_count],
        )
    }

    fn child(state: &RecursiveConsensusState, timestamp: u64) -> BlockHeader {
        let height = state.height + 1;
        BlockHeader {
            attested_coverage: 0,
            prev_block_hash: state.block_id,
            state_root: [height as u8; 32],
            tx_root: [0u8; 32],
            timestamp,
            height,
            miner_address: Address([0x22; 32]),
            nonce: height as u128,
            difficulty_target: next_target(
                state.asert_anchor_height,
                state.asert_anchor_timestamp,
                &state.asert_anchor_target,
                height,
                timestamp,
            ),
            log_slots: expected_child_log_slots(
                state.log_slots,
                state.active_slot_count,
                state.active_counts(),
            ),
            active_slot_count: state.active_slot_count,
            alloc_counter: state.alloc_counter,
        }
    }

    fn integer_witness(header: &BlockHeader) -> HeaderWitness {
        let mut witness = HeaderWitness::from_header(header);
        witness.pow_digest = [0u8; 32];
        witness
    }

    #[test]
    fn header_integer_trace_roundtrip_without_native_hashing() {
        let g = genesis();
        let start = start_state(&g);
        let h1 = child(&start, g.timestamp + BLOCK_TIME);
        let w1 = integer_witness(&h1);
        let mut mid = start.clone();
        mid.height = h1.height;
        mid.block_id = w1.block_id;
        mid.state_root = h1.state_root;
        mid.cumulative_chainwork = add_work(
            &mid.cumulative_chainwork,
            &block_work(&h1.difficulty_target),
        );
        mid.push_timestamp(h1.timestamp);
        mid.push_active_count(h1.active_slot_count);
        let h2 = child(&mid, h1.timestamp + BLOCK_TIME);
        let witnesses = vec![w1, integer_witness(&h2)];
        let trace = build_header_integer_trace(&start, &witnesses).unwrap();
        let end = verify_header_integer_trace(&start, &witnesses, &trace).unwrap();
        assert_eq!(end.height, 2);
        assert_eq!(end.block_id, block_id(&h2));
    }

    #[test]
    fn header_integer_trace_rejects_pow_equality() {
        let g = genesis();
        let start = start_state(&g);
        let h1 = child(&start, g.timestamp + BLOCK_TIME);
        let mut witness = integer_witness(&h1);
        witness.pow_digest = h1.difficulty_target;
        let trace = build_header_integer_trace(&start, &[witness.clone()]).unwrap();
        assert_eq!(
            verify_header_integer_trace(&start, &[witness], &trace),
            Err(HeaderIntegerTraceError::BadPowTarget { index: 0 })
        );
    }

    #[test]
    fn header_integer_trace_rejects_attested_coverage_violations() {
        let g = genesis();
        let mut start = start_state(&g);
        start.height = 5;
        start.attested_coverage = 3;
        let child_with = |coverage: u64| {
            let mut h = child(&start, g.timestamp + BLOCK_TIME);
            h.attested_coverage = coverage;
            integer_witness(&h)
        };
        for valid in [3u64, 4, 5] {
            let witness = child_with(valid);
            let trace = build_header_integer_trace(&start, &[witness.clone()]).unwrap();
            let end = verify_header_integer_trace(&start, &[witness], &trace)
                .expect("repeat or bounded advancement accepts");
            assert_eq!(end.attested_coverage, valid);
        }
        for invalid in [2u64, 6] {
            let witness = child_with(invalid);
            let trace = build_header_integer_trace(&start, &[witness.clone()]).unwrap();
            assert_eq!(
                verify_header_integer_trace(&start, &[witness], &trace),
                Err(HeaderIntegerTraceError::BadAttestedCoverage { index: 0 })
            );
        }
    }

    #[test]
    fn header_integer_trace_rejects_untriggered_log_jump() {
        let g = genesis();
        let start = start_state(&g);
        let mut h1 = child(&start, g.timestamp + BLOCK_TIME);
        h1.log_slots += 1;
        let witness = integer_witness(&h1);
        let trace = build_header_integer_trace(&start, &[witness.clone()]).unwrap();
        assert_eq!(
            verify_header_integer_trace(&start, &[witness], &trace),
            Err(HeaderIntegerTraceError::BadLogSlots { index: 0 })
        );
    }
}
