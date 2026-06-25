// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Timeless header-work batch relation for checkpoint recursion.
//!
//! This module is the deterministic specification boundary for header work.
//! Local wall-clock future-drift policy is excluded and remains node admission
//! policy.

use noid_chain::block_header::BlockHeader;
use noid_chain::consensus::difficulty::le256_lt;
use noid_chain::consensus::difficulty::{add_work, block_work, next_target};
use noid_chain::consensus::expected_child_log_slots;
use noid_chain::consensus::header::epoch_anchor_height;
use noid_chain::consensus::params::{EXPANSION_WINDOW, MEDIAN_TIME_BLOCKS};
use noid_chain::consensus::pow::{
    poseidon_pow_digest, pow_header_fields, validate_pow, PowHeaderFields,
};
use noid_chain::consensus::timestamps::median_time_past;
use noid_core::Block128;
use noid_gkr::HeaderHashInputs;

pub const EXPANSION_WINDOW_LEN: usize = EXPANSION_WINDOW as usize;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RecursiveConsensusState {
    pub height: u64,
    pub block_id: [u8; 32],
    pub state_root: [u8; 32],
    pub cumulative_chainwork: [u8; 32],
    pub log_slots: u32,
    pub active_slot_count: u64,
    pub alloc_counter: u64,
    pub asert_anchor_height: u64,
    pub asert_anchor_timestamp: u64,
    pub asert_anchor_target: [u8; 32],
    /// Oldest-first recent timestamp ring, padded with zeros after `mtp_len`.
    pub mtp_timestamps: [u64; MEDIAN_TIME_BLOCKS],
    pub mtp_len: u8,
    /// Oldest-first recent active-slot-count ring for exact log-slot expansion.
    pub expansion_counts: [u64; EXPANSION_WINDOW_LEN],
    pub expansion_len: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderWitness {
    pub header: BlockHeader,
    pub pow_fields: PowHeaderFields,
    pub pow_digest: [u8; 32],
    pub block_id: [u8; 32],
    pub target: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderWitnessError {
    BadPowFields,
    BadPowDigest,
    BadBlockId,
    BadTarget,
    BadPow,
}

impl HeaderWitness {
    pub fn from_header(header: &BlockHeader) -> Self {
        let pow_fields = pow_header_fields(header);
        Self {
            header: header.clone(),
            pow_fields,
            pow_digest: poseidon_pow_digest(header),
            block_id: noid_chain::hash_block_header(header),
            target: header.difficulty_target,
        }
    }

    pub fn verify(&self) -> Result<(), HeaderWitnessError> {
        if self.pow_fields != pow_header_fields(&self.header) {
            return Err(HeaderWitnessError::BadPowFields);
        }
        if self.pow_digest != poseidon_pow_digest(&self.header) {
            return Err(HeaderWitnessError::BadPowDigest);
        }
        if self.block_id != noid_chain::hash_block_header(&self.header) {
            return Err(HeaderWitnessError::BadBlockId);
        }
        if self.target != self.header.difficulty_target {
            return Err(HeaderWitnessError::BadTarget);
        }
        if !le256_lt(&self.pow_digest, &self.target) {
            return Err(HeaderWitnessError::BadPow);
        }
        Ok(())
    }
}

pub fn verify_header_witness(witness: &HeaderWitness) -> Result<(), HeaderWitnessError> {
    witness.verify()
}

fn digest_to_fields(hash: [u8; 32]) -> [Block128; 2] {
    [
        Block128::from(u128::from_le_bytes(hash[..16].try_into().unwrap())),
        Block128::from(u128::from_le_bytes(hash[16..].try_into().unwrap())),
    ]
}

pub fn header_hash_proof_inputs(witnesses: &[HeaderWitness]) -> Vec<HeaderHashInputs> {
    witnesses
        .iter()
        .map(|witness| HeaderHashInputs {
            fields: witness.pow_fields,
            expected_pow_digest: digest_to_fields(witness.pow_digest),
            expected_block_id: digest_to_fields(witness.block_id),
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PowHeaderBatchError {
    EmptyBatch,
    BadParentLink {
        index: usize,
    },
    BadHeight {
        index: usize,
    },
    BadDifficultyTarget {
        index: usize,
    },
    BadMedianTimePast {
        index: usize,
    },
    BadPow {
        index: usize,
    },
    BadHeaderWitness {
        index: usize,
        reason: HeaderWitnessError,
    },
    BadLogSlots {
        index: usize,
    },
}

impl RecursiveConsensusState {
    pub fn from_header(
        header: &BlockHeader,
        cumulative_chainwork: [u8; 32],
        asert_anchor_height: u64,
        asert_anchor_timestamp: u64,
        asert_anchor_target: [u8; 32],
        prev_timestamps_oldest_first: &[u64],
        prev_active_counts_oldest_first: &[u64],
    ) -> Self {
        let mut mtp_timestamps = [0u64; MEDIAN_TIME_BLOCKS];
        let keep = prev_timestamps_oldest_first.len().min(MEDIAN_TIME_BLOCKS);
        let start = prev_timestamps_oldest_first.len().saturating_sub(keep);
        mtp_timestamps[..keep].copy_from_slice(&prev_timestamps_oldest_first[start..]);
        let mut expansion_counts = [0u64; EXPANSION_WINDOW_LEN];
        let active_keep = prev_active_counts_oldest_first
            .len()
            .min(EXPANSION_WINDOW_LEN);
        let active_start = prev_active_counts_oldest_first
            .len()
            .saturating_sub(active_keep);
        expansion_counts[..active_keep]
            .copy_from_slice(&prev_active_counts_oldest_first[active_start..]);
        Self {
            height: header.height,
            block_id: noid_chain::hash_block_header(header),
            state_root: header.state_root,
            cumulative_chainwork,
            log_slots: header.log_slots,
            active_slot_count: header.active_slot_count,
            alloc_counter: header.alloc_counter,
            asert_anchor_height,
            asert_anchor_timestamp,
            asert_anchor_target,
            mtp_timestamps,
            mtp_len: keep as u8,
            expansion_counts,
            expansion_len: active_keep as u8,
        }
    }

    pub fn timestamps(&self) -> &[u64] {
        &self.mtp_timestamps[..self.mtp_len as usize]
    }

    pub fn active_counts(&self) -> &[u64] {
        &self.expansion_counts[..self.expansion_len as usize]
    }

    pub(crate) fn push_timestamp(&mut self, timestamp: u64) {
        let len = self.mtp_len as usize;
        if len < MEDIAN_TIME_BLOCKS {
            self.mtp_timestamps[len] = timestamp;
            self.mtp_len += 1;
            return;
        }
        self.mtp_timestamps.copy_within(1..MEDIAN_TIME_BLOCKS, 0);
        self.mtp_timestamps[MEDIAN_TIME_BLOCKS - 1] = timestamp;
    }

    pub(crate) fn push_active_count(&mut self, active_count: u64) {
        let len = self.expansion_len as usize;
        if len < EXPANSION_WINDOW_LEN {
            self.expansion_counts[len] = active_count;
            self.expansion_len += 1;
            return;
        }
        self.expansion_counts
            .copy_within(1..EXPANSION_WINDOW_LEN, 0);
        self.expansion_counts[EXPANSION_WINDOW_LEN - 1] = active_count;
    }

    fn expected_next_log_slots(&self) -> u32 {
        expected_child_log_slots(self.log_slots, self.active_slot_count, self.active_counts())
    }
}

/// Verify a non-empty consecutive header batch and return the resulting state.
///
/// This is the canonical native relation that the recursive header-work proof
/// must implement exactly.
pub fn verify_pow_header_batch_native(
    start: &RecursiveConsensusState,
    headers: &[BlockHeader],
) -> Result<RecursiveConsensusState, PowHeaderBatchError> {
    verify_pow_header_batch_inner(start, headers, true)
}

/// Verify a consecutive header batch through explicit canonical header witnesses.
///
/// This is the T1 boundary used by later recursive composition: each subrelation
/// must read PoW fields, target, block id, chain linkage, and integer consensus
/// fields from the same witness.
pub fn verify_pow_header_witness_batch_native(
    start: &RecursiveConsensusState,
    witnesses: &[HeaderWitness],
) -> Result<RecursiveConsensusState, PowHeaderBatchError> {
    let mut headers = Vec::with_capacity(witnesses.len());
    for (index, witness) in witnesses.iter().enumerate() {
        witness
            .verify()
            .map_err(|reason| PowHeaderBatchError::BadHeaderWitness { index, reason })?;
        headers.push(witness.header.clone());
    }

    verify_pow_header_batch_inner(start, &headers, false)
}

fn verify_pow_header_batch_inner(
    start: &RecursiveConsensusState,
    headers: &[BlockHeader],
    check_pow: bool,
) -> Result<RecursiveConsensusState, PowHeaderBatchError> {
    if headers.is_empty() {
        return Err(PowHeaderBatchError::EmptyBatch);
    }

    let mut state = start.clone();
    for (index, header) in headers.iter().enumerate() {
        if header.prev_block_hash != state.block_id {
            return Err(PowHeaderBatchError::BadParentLink { index });
        }
        if header.height != state.height + 1 {
            return Err(PowHeaderBatchError::BadHeight { index });
        }

        let expected_target = next_target(
            state.asert_anchor_height,
            state.asert_anchor_timestamp,
            &state.asert_anchor_target,
            header.height,
            header.timestamp,
        );
        if header.difficulty_target != expected_target {
            return Err(PowHeaderBatchError::BadDifficultyTarget { index });
        }

        if header.timestamp <= median_time_past(state.timestamps()) {
            return Err(PowHeaderBatchError::BadMedianTimePast { index });
        }

        if check_pow && validate_pow(header).is_err() {
            return Err(PowHeaderBatchError::BadPow { index });
        }

        if header.log_slots != state.expected_next_log_slots() {
            return Err(PowHeaderBatchError::BadLogSlots { index });
        }

        state.height = header.height;
        state.block_id = noid_chain::hash_block_header(header);
        state.state_root = header.state_root;
        state.cumulative_chainwork = add_work(
            &state.cumulative_chainwork,
            &block_work(&header.difficulty_target),
        );
        state.log_slots = header.log_slots;
        state.active_slot_count = header.active_slot_count;
        state.alloc_counter = header.alloc_counter;
        state.push_timestamp(header.timestamp);
        state.push_active_count(header.active_slot_count);

        if epoch_anchor_height(header.height) == header.height {
            state.asert_anchor_height = header.height;
            state.asert_anchor_timestamp = header.timestamp;
            state.asert_anchor_target = header.difficulty_target;
        }
    }

    Ok(state)
}

#[cfg(test)]
fn verify_pow_header_batch_native_without_pow_for_tests(
    start: &RecursiveConsensusState,
    headers: &[BlockHeader],
) -> Result<RecursiveConsensusState, PowHeaderBatchError> {
    verify_pow_header_batch_inner(start, headers, false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use noid_chain::consensus::difficulty::block_work;
    use noid_chain::consensus::params::{BLOCK_TIME, EPOCH_LENGTH, LOG_SLOTS_MAX, MAX_TARGET};
    use noid_chain::consensus::pow::block_id;
    use noid_gkr::{prove_header_hash_killshot, verify_header_hash_killshot};
    use noid_poseidon2b::channel::Poseidon2bChannel;
    use noid_poseidon2b::primitives::Address;

    fn header_from_state(state: &RecursiveConsensusState, timestamp: u64) -> BlockHeader {
        let height = state.height + 1;
        let difficulty_target = next_target(
            state.asert_anchor_height,
            state.asert_anchor_timestamp,
            &state.asert_anchor_target,
            height,
            timestamp,
        );
        BlockHeader {
            prev_block_hash: state.block_id,
            state_root: [height as u8; 32],
            tx_root: [0u8; 32],
            timestamp,
            height,
            miner_address: Address([0u8; 32]),
            nonce: 0,
            difficulty_target,
            log_slots: state.expected_next_log_slots(),
            active_slot_count: state.active_slot_count,
            alloc_counter: state.alloc_counter,
        }
    }

    fn genesis() -> BlockHeader {
        BlockHeader {
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

    #[test]
    fn verifies_32_header_batch_and_chainwork() {
        let g = genesis();
        let start = RecursiveConsensusState::from_header(
            &g,
            block_work(&g.difficulty_target),
            0,
            g.timestamp,
            g.difficulty_target,
            &[g.timestamp],
            &[g.active_slot_count],
        );
        let mut rolling = start.clone();
        let mut headers = Vec::new();
        for i in 1..=32 {
            let h = header_from_state(&rolling, g.timestamp + i * BLOCK_TIME);
            rolling = verify_pow_header_batch_native_without_pow_for_tests(&rolling, &[h])
                .expect("single header advances");
            headers.push(h);
        }

        let end = verify_pow_header_batch_native_without_pow_for_tests(&start, &headers)
            .expect("valid header batch");
        assert_eq!(end.height, 32);
        assert_eq!(end.block_id, block_id(headers.last().unwrap()));
        let expected = headers
            .iter()
            .fold(block_work(&g.difficulty_target), |acc, h| {
                add_work(&acc, &block_work(&h.difficulty_target))
            });
        assert_eq!(end.cumulative_chainwork, expected);
    }

    #[test]
    fn rejects_bad_parent_link() {
        let g = genesis();
        let start = RecursiveConsensusState::from_header(
            &g,
            block_work(&g.difficulty_target),
            0,
            g.timestamp,
            g.difficulty_target,
            &[g.timestamp],
            &[g.active_slot_count],
        );
        let mut h = header_from_state(&start, g.timestamp + BLOCK_TIME);
        h.prev_block_hash[0] ^= 1;
        assert_eq!(
            verify_pow_header_batch_native_without_pow_for_tests(&start, &[h]),
            Err(PowHeaderBatchError::BadParentLink { index: 0 })
        );
    }

    #[test]
    fn rejects_mtp_violation() {
        let g = genesis();
        let start = RecursiveConsensusState::from_header(
            &g,
            block_work(&g.difficulty_target),
            0,
            g.timestamp,
            g.difficulty_target,
            &[g.timestamp],
            &[g.active_slot_count],
        );
        let h = header_from_state(&start, g.timestamp);
        assert_eq!(
            verify_pow_header_batch_native_without_pow_for_tests(&start, &[h]),
            Err(PowHeaderBatchError::BadMedianTimePast { index: 0 })
        );
    }

    #[test]
    fn rejects_bad_difficulty_target() {
        let g = genesis();
        let start = RecursiveConsensusState::from_header(
            &g,
            block_work(&g.difficulty_target),
            0,
            g.timestamp,
            g.difficulty_target,
            &[g.timestamp],
            &[g.active_slot_count],
        );
        let mut h = header_from_state(&start, g.timestamp + BLOCK_TIME);
        h.difficulty_target[0] ^= 1;
        assert_eq!(
            verify_pow_header_batch_native_without_pow_for_tests(&start, &[h]),
            Err(PowHeaderBatchError::BadDifficultyTarget { index: 0 })
        );
    }

    #[test]
    fn mtp_uses_exact_recent_window_boundary() {
        let mut g = genesis();
        g.timestamp = 1_000;
        let prev: Vec<u64> = (0..MEDIAN_TIME_BLOCKS as u64)
            .map(|i| 1_000 + i * 10)
            .collect();
        let start = RecursiveConsensusState::from_header(
            &g,
            block_work(&g.difficulty_target),
            0,
            g.timestamp,
            g.difficulty_target,
            &prev,
            &[g.active_slot_count],
        );
        let mtp = median_time_past(&prev);

        let equal = header_from_state(&start, mtp);
        assert_eq!(
            verify_pow_header_batch_native_without_pow_for_tests(&start, &[equal]),
            Err(PowHeaderBatchError::BadMedianTimePast { index: 0 })
        );

        let above = header_from_state(&start, mtp + 1);
        verify_pow_header_batch_native_without_pow_for_tests(&start, &[above])
            .expect("timestamp exactly one second above MTP accepts");
    }

    #[test]
    fn epoch_boundary_updates_asert_anchor_exactly() {
        let g = genesis();
        let start = RecursiveConsensusState::from_header(
            &g,
            block_work(&g.difficulty_target),
            0,
            g.timestamp,
            g.difficulty_target,
            &[g.timestamp],
            &[g.active_slot_count],
        );
        let mut rolling = start;
        let mut boundary = None;
        for i in 1..=EPOCH_LENGTH {
            let h = header_from_state(&rolling, g.timestamp + i * BLOCK_TIME);
            rolling = verify_pow_header_batch_native_without_pow_for_tests(&rolling, &[h.clone()])
                .expect("epoch header advances");
            boundary = Some(h);
        }
        let boundary = boundary.expect("epoch boundary header");
        assert_eq!(rolling.asert_anchor_height, EPOCH_LENGTH);
        assert_eq!(rolling.asert_anchor_timestamp, boundary.timestamp);
        assert_eq!(rolling.asert_anchor_target, boundary.difficulty_target);
    }

    #[test]
    fn header_witness_accepts_matching_easy_header() {
        let g = genesis();
        let start = RecursiveConsensusState::from_header(
            &g,
            block_work(&g.difficulty_target),
            0,
            g.timestamp,
            g.difficulty_target,
            &[g.timestamp],
            &[g.active_slot_count],
        );
        let mut h = header_from_state(&start, g.timestamp + BLOCK_TIME);
        h.difficulty_target = [0xffu8; 32];
        let witness = HeaderWitness::from_header(&h);
        verify_header_witness(&witness).expect("matching header witness verifies");
    }

    #[test]
    fn header_witness_binds_pow_fields_digest_target_and_block_id() {
        let g = genesis();
        let start = RecursiveConsensusState::from_header(
            &g,
            block_work(&g.difficulty_target),
            0,
            g.timestamp,
            g.difficulty_target,
            &[g.timestamp],
            &[g.active_slot_count],
        );
        let mut h = header_from_state(&start, g.timestamp + BLOCK_TIME);
        h.difficulty_target = [0xffu8; 32];
        let witness = HeaderWitness::from_header(&h);

        assert_eq!(verify_header_witness(&witness), Ok(()));
        assert_eq!(witness.pow_fields, pow_header_fields(&h));
        assert_eq!(witness.pow_digest, poseidon_pow_digest(&h));
        assert_eq!(witness.block_id, noid_chain::hash_block_header(&h));
        assert_eq!(witness.target, h.difficulty_target);
    }

    #[test]
    fn header_witness_feeds_header_hash_killshot() {
        let g = genesis();
        let start = RecursiveConsensusState::from_header(
            &g,
            block_work(&g.difficulty_target),
            0,
            g.timestamp,
            g.difficulty_target,
            &[g.timestamp],
            &[g.active_slot_count],
        );
        let mut h1 = header_from_state(&start, g.timestamp + BLOCK_TIME);
        h1.difficulty_target = [0xffu8; 32];
        let mut mid = start.clone();
        mid.height = h1.height;
        mid.block_id = block_id(&h1);
        mid.state_root = h1.state_root;
        mid.push_timestamp(h1.timestamp);
        mid.push_active_count(h1.active_slot_count);
        let mut h2 = header_from_state(&mid, h1.timestamp + BLOCK_TIME);
        h2.difficulty_target = [0xffu8; 32];

        let witnesses = vec![
            HeaderWitness::from_header(&h1),
            HeaderWitness::from_header(&h2),
        ];
        let inputs = header_hash_proof_inputs(&witnesses);
        let mut ch_p = Poseidon2bChannel::new();
        let (proof, reductions) = prove_header_hash_killshot(&inputs, &mut ch_p);
        let mut ch_v = Poseidon2bChannel::new();
        let verified = verify_header_hash_killshot(&proof, &inputs, &mut ch_v)
            .expect("header hash proof verifies");
        assert_eq!(verified, reductions);
    }

    #[test]
    fn header_witness_rejects_pow_fields_from_other_nonce() {
        let g = genesis();
        let start = RecursiveConsensusState::from_header(
            &g,
            block_work(&g.difficulty_target),
            0,
            g.timestamp,
            g.difficulty_target,
            &[g.timestamp],
            &[g.active_slot_count],
        );
        let h = header_from_state(&start, g.timestamp + BLOCK_TIME);
        let mut mutated = h.clone();
        mutated.nonce = mutated.nonce.wrapping_add(1);
        let mut witness = HeaderWitness::from_header(&h);
        witness.pow_fields = pow_header_fields(&mutated);

        assert_eq!(
            verify_header_witness(&witness),
            Err(HeaderWitnessError::BadPowFields)
        );
    }

    #[test]
    fn header_witness_rejects_block_id_from_other_header() {
        let g = genesis();
        let start = RecursiveConsensusState::from_header(
            &g,
            block_work(&g.difficulty_target),
            0,
            g.timestamp,
            g.difficulty_target,
            &[g.timestamp],
            &[g.active_slot_count],
        );
        let h = header_from_state(&start, g.timestamp + BLOCK_TIME);
        let mut other = h.clone();
        other.state_root[0] ^= 1;
        let mut witness = HeaderWitness::from_header(&h);
        witness.block_id = noid_chain::hash_block_header(&other);

        assert_eq!(
            verify_header_witness(&witness),
            Err(HeaderWitnessError::BadBlockId)
        );
    }

    #[test]
    fn header_witness_rejects_target_endian_mutation() {
        let g = genesis();
        let start = RecursiveConsensusState::from_header(
            &g,
            block_work(&g.difficulty_target),
            0,
            g.timestamp,
            g.difficulty_target,
            &[g.timestamp],
            &[g.active_slot_count],
        );
        let mut h = header_from_state(&start, g.timestamp + BLOCK_TIME);
        for (i, byte) in h.difficulty_target.iter_mut().enumerate() {
            *byte = i as u8;
        }
        let mut witness = HeaderWitness::from_header(&h);
        witness.target.reverse();

        assert_eq!(
            verify_header_witness(&witness),
            Err(HeaderWitnessError::BadTarget)
        );
    }

    #[test]
    fn header_witness_rejects_pow_digest_from_other_nonce() {
        let g = genesis();
        let start = RecursiveConsensusState::from_header(
            &g,
            block_work(&g.difficulty_target),
            0,
            g.timestamp,
            g.difficulty_target,
            &[g.timestamp],
            &[g.active_slot_count],
        );
        let h = header_from_state(&start, g.timestamp + BLOCK_TIME);
        let mut other = h.clone();
        other.nonce = other.nonce.wrapping_add(1);
        let mut witness = HeaderWitness::from_header(&h);
        witness.pow_digest = poseidon_pow_digest(&other);

        assert_eq!(
            verify_header_witness(&witness),
            Err(HeaderWitnessError::BadPowDigest)
        );
    }

    #[test]
    fn witness_batch_rejects_corrupt_block_id_witness() {
        let g = genesis();
        let start = RecursiveConsensusState::from_header(
            &g,
            block_work(&g.difficulty_target),
            0,
            g.timestamp,
            g.difficulty_target,
            &[g.timestamp],
            &[g.active_slot_count],
        );
        let h = header_from_state(&start, g.timestamp + BLOCK_TIME);
        let mut witness = HeaderWitness::from_header(&h);
        witness.block_id[0] ^= 1;

        assert_eq!(
            verify_pow_header_witness_batch_native(&start, &[witness]),
            Err(PowHeaderBatchError::BadHeaderWitness {
                index: 0,
                reason: HeaderWitnessError::BadBlockId
            })
        );
    }

    #[test]
    fn witness_batch_rejects_invalid_pow_digest() {
        let g = genesis();
        let start = RecursiveConsensusState::from_header(
            &g,
            block_work(&g.difficulty_target),
            0,
            g.timestamp,
            g.difficulty_target,
            &[g.timestamp],
            &[g.active_slot_count],
        );
        let mut h = header_from_state(&start, g.timestamp + BLOCK_TIME);
        h.difficulty_target = [0u8; 32];
        let witness = HeaderWitness::from_header(&h);
        assert_eq!(
            verify_pow_header_witness_batch_native(&start, &[witness]),
            Err(PowHeaderBatchError::BadHeaderWitness {
                index: 0,
                reason: HeaderWitnessError::BadPow
            })
        );
    }

    #[test]
    fn rejects_untriggered_log_slots_jump() {
        let g = genesis();
        let start = RecursiveConsensusState::from_header(
            &g,
            block_work(&g.difficulty_target),
            0,
            g.timestamp,
            g.difficulty_target,
            &[g.timestamp],
            &[0; EXPANSION_WINDOW_LEN],
        );
        assert_eq!(start.expected_next_log_slots(), g.log_slots);
        let mut h = header_from_state(&start, g.timestamp + BLOCK_TIME);
        h.log_slots = g.log_slots + 1;
        assert_eq!(
            verify_pow_header_batch_native_without_pow_for_tests(&start, &[h]),
            Err(PowHeaderBatchError::BadLogSlots { index: 0 })
        );
    }

    #[test]
    fn accepts_triggered_log_slots_expansion() {
        let mut g = genesis();
        g.active_slot_count = 192;
        let start = RecursiveConsensusState::from_header(
            &g,
            block_work(&g.difficulty_target),
            0,
            g.timestamp,
            g.difficulty_target,
            &[g.timestamp],
            &[192; EXPANSION_WINDOW_LEN],
        );
        assert_eq!(start.expected_next_log_slots(), g.log_slots + 1);
        let h = header_from_state(&start, g.timestamp + BLOCK_TIME);
        let end = verify_pow_header_batch_native_without_pow_for_tests(&start, &[h])
            .expect("triggered expansion is valid");
        assert_eq!(end.log_slots, g.log_slots + 1);
    }

    #[test]
    fn triggered_log_slots_expansion_saturates_at_max() {
        let mut g = genesis();
        g.log_slots = LOG_SLOTS_MAX;
        g.active_slot_count = u64::MAX;
        let start = RecursiveConsensusState::from_header(
            &g,
            block_work(&g.difficulty_target),
            0,
            g.timestamp,
            g.difficulty_target,
            &[g.timestamp],
            &[u64::MAX; EXPANSION_WINDOW_LEN],
        );
        assert_eq!(start.expected_next_log_slots(), LOG_SLOTS_MAX);

        let h = header_from_state(&start, g.timestamp + BLOCK_TIME);
        let end = verify_pow_header_batch_native_without_pow_for_tests(&start, &[h])
            .expect("max log_slots remains valid under trigger");
        assert_eq!(end.log_slots, LOG_SLOTS_MAX);

        let mut lower = header_from_state(&start, g.timestamp + BLOCK_TIME);
        lower.log_slots = LOG_SLOTS_MAX - 1;
        assert_eq!(
            verify_pow_header_batch_native_without_pow_for_tests(&start, &[lower]),
            Err(PowHeaderBatchError::BadLogSlots { index: 0 })
        );
    }

    #[test]
    fn rejects_missing_triggered_log_slots_expansion() {
        let mut g = genesis();
        g.active_slot_count = 192;
        let start = RecursiveConsensusState::from_header(
            &g,
            block_work(&g.difficulty_target),
            0,
            g.timestamp,
            g.difficulty_target,
            &[g.timestamp],
            &[192; EXPANSION_WINDOW_LEN],
        );
        let mut h = header_from_state(&start, g.timestamp + BLOCK_TIME);
        h.log_slots = g.log_slots;
        assert_eq!(
            verify_pow_header_batch_native_without_pow_for_tests(&start, &[h]),
            Err(PowHeaderBatchError::BadLogSlots { index: 0 })
        );
    }

    #[test]
    fn active_count_window_keeps_exact_consensus_depth() {
        let g = genesis();
        let mut start = RecursiveConsensusState::from_header(
            &g,
            block_work(&g.difficulty_target),
            0,
            g.timestamp,
            g.difficulty_target,
            &[g.timestamp],
            &[1; EXPANSION_WINDOW_LEN + 4],
        );
        assert_eq!(start.active_counts().len(), EXPANSION_WINDOW_LEN);
        assert!(start.active_counts().iter().all(|&count| count == 1));
        start.push_active_count(7);
        assert_eq!(start.active_counts().len(), EXPANSION_WINDOW_LEN);
        assert_eq!(start.active_counts()[0], 1);
        assert_eq!(start.active_counts()[EXPANSION_WINDOW_LEN - 1], 7);
    }

    #[test]
    fn chainwork_saturates_without_wrapping() {
        let g = genesis();
        let mut near_max = [0xFFu8; 32];
        near_max[0] = 0;
        let start = RecursiveConsensusState::from_header(
            &g,
            near_max,
            0,
            g.timestamp,
            g.difficulty_target,
            &[g.timestamp],
            &[g.active_slot_count],
        );
        let h = header_from_state(&start, g.timestamp + BLOCK_TIME);
        let end = verify_pow_header_batch_native_without_pow_for_tests(&start, &[h])
            .expect("header advances with saturated chainwork");
        assert_eq!(end.cumulative_chainwork, [0xFFu8; 32]);
    }
}
