// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Accepted-block claim batch relation.
//!
//! This is the native specification boundary for the production O(1) batch
//! step: a consecutive header-work batch plus one canonical accepted-block
//! claim per header. The optimized recursive implementation must prove exactly
//! this transition, then replace the native verifier as public authority.

use noid_core::Block128;
use noid_core::TowerField;
use noid_gkr::{
    discharge_fixed_field_hash_reductions_native, prove_fixed_field_hash_killshot,
    verify_fixed_field_hash_killshot, FixedFieldHashInputs, FixedFieldHashParams,
    FixedFieldHashProofKillShot,
};
use noid_poseidon2b::channel::Poseidon2bChannel;
use noid_poseidon2b::native::domain::{capacity_iv, TAG_HISTPRF};
use noid_poseidon2b::native::Poseidon2bSponge;
use noid_poseidon2b::primitives::Digest;

use crate::accumulator::{ChainAccumulator, ChainAccumulatorAdvanceError, CHAIN_ACCUMULATOR_LANES};
use crate::checkpoint_proof::HISTORY_CHECKPOINT_BATCH_TARGET_BLOCKS;
use crate::header_integer::{
    verify_header_integer_trace, HeaderIntegerBatchTrace, HeaderIntegerTraceError,
};
use crate::pow_header::{
    verify_pow_header_witness_batch_native, HeaderWitness, PowHeaderBatchError,
    RecursiveConsensusState, EXPANSION_WINDOW_LEN,
};
use noid_chain::consensus::params::MEDIAN_TIME_BLOCKS;
use noid_chain::consensus::pow::POW_HEADER_FIELD_COUNT;

pub const ACCEPTED_CLAIM_BATCH_DIGEST_HEADER_WITNESS_FIELDS: usize = POW_HEADER_FIELD_COUNT + 6;
pub const ACCEPTED_CLAIM_BATCH_DIGEST_CLAIM_FIELDS: usize = 2;
pub const ACCEPTED_CLAIM_BATCH_DIGEST_CONSENSUS_FIELDS: usize =
    17 + MEDIAN_TIME_BLOCKS + EXPANSION_WINDOW_LEN;
pub const ACCEPTED_CLAIM_BATCH_DIGEST_ACCUMULATOR_FIELDS: usize = CHAIN_ACCUMULATOR_LANES;
pub const ACCEPTED_CLAIM_BATCH_DIGEST_SLOT_FIELDS: usize =
    ACCEPTED_CLAIM_BATCH_DIGEST_HEADER_WITNESS_FIELDS + ACCEPTED_CLAIM_BATCH_DIGEST_CLAIM_FIELDS;
pub const ACCEPTED_CLAIM_BATCH_DIGEST_PAYLOAD_FIELDS: usize = 1
    + 1
    + ACCEPTED_CLAIM_BATCH_DIGEST_CONSENSUS_FIELDS
    + ACCEPTED_CLAIM_BATCH_DIGEST_ACCUMULATOR_FIELDS
    + HISTORY_CHECKPOINT_BATCH_TARGET_BLOCKS as usize * ACCEPTED_CLAIM_BATCH_DIGEST_SLOT_FIELDS
    + 3;
pub const ACCEPTED_CLAIM_BATCH_DIGEST_HASH_FIELDS: usize =
    2 + ACCEPTED_CLAIM_BATCH_DIGEST_PAYLOAD_FIELDS;

const _: () = assert!(ACCEPTED_CLAIM_BATCH_DIGEST_HASH_FIELDS % 2 == 0);

const ACB_DIG1: u128 = 0x4143_425F_4449_4731; // "ACB_DIG1"

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AcceptedClaimBatchWitness {
    pub headers: Vec<HeaderWitness>,
    pub accepted_block_claims: Vec<[Block128; 2]>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AcceptedClaimBatchOutput {
    pub consensus_state: RecursiveConsensusState,
    pub accumulator: ChainAccumulator,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcceptedClaimBatchError {
    EmptyBatch,
    ClaimCountMismatch {
        headers: usize,
        claims: usize,
    },
    StartStateMismatch,
    EndStateMismatch,
    HeaderWork(PowHeaderBatchError),
    HeaderInteger(HeaderIntegerTraceError),
    AccumulatorAdvance {
        index: usize,
        source: ChainAccumulatorAdvanceError,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcceptedClaimBatchDigestError {
    EmptyBatch,
    TooManyClaims { actual: usize },
    ClaimCountMismatch { headers: usize, claims: usize },
    DigestFieldCountMismatch { actual: usize },
    NonCanonicalHeader,
    NonCanonicalSlotPadding,
    NonCanonicalPadding,
    DigestMismatch,
    BadDigestProof,
    BadDigestDischarge,
}

impl std::fmt::Display for AcceptedClaimBatchDigestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyBatch => write!(f, "empty accepted-claim batch digest"),
            Self::TooManyClaims { actual } => {
                write!(f, "too many accepted-claim batch digest slots: {actual}")
            }
            Self::ClaimCountMismatch { headers, claims } => write!(
                f,
                "accepted-claim batch digest count mismatch: {headers} headers, {claims} claims"
            ),
            Self::DigestFieldCountMismatch { actual } => write!(
                f,
                "accepted-claim batch digest field count mismatch: {actual}"
            ),
            Self::NonCanonicalHeader => {
                write!(f, "accepted-claim batch digest has a non-canonical header")
            }
            Self::NonCanonicalSlotPadding => write!(
                f,
                "accepted-claim batch digest has non-zero unused slot fields"
            ),
            Self::NonCanonicalPadding => {
                write!(
                    f,
                    "accepted-claim batch digest has non-zero trailing padding"
                )
            }
            Self::DigestMismatch => write!(f, "accepted-claim batch digest mismatch"),
            Self::BadDigestProof => write!(f, "bad accepted-claim batch digest proof"),
            Self::BadDigestDischarge => {
                write!(
                    f,
                    "accepted-claim batch digest proof failed native discharge"
                )
            }
        }
    }
}

impl std::error::Error for AcceptedClaimBatchDigestError {}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AcceptedClaimBatchDigestProof {
    pub digest_hash: FixedFieldHashProofKillShot,
}

impl AcceptedClaimBatchDigestProof {
    pub fn byte_len(&self) -> usize {
        bincode::serialized_size(self)
            .expect("serialized AcceptedClaimBatchDigestProof length fits usize") as usize
    }
}

fn digest_to_fields(hash: [u8; 32]) -> [Block128; 2] {
    [
        Block128::from(u128::from_le_bytes(hash[..16].try_into().unwrap())),
        Block128::from(u128::from_le_bytes(hash[16..].try_into().unwrap())),
    ]
}

pub fn accepted_claim_batch_digest(
    witness: &AcceptedClaimBatchWitness,
    output: &AcceptedClaimBatchOutput,
) -> Result<Digest, AcceptedClaimBatchDigestError> {
    Ok(digest_fixed_no_pad_from_fields(
        &accepted_claim_batch_digest_hash_fields(witness, output)?,
    ))
}

pub fn accepted_claim_batch_digest_hash_fields(
    witness: &AcceptedClaimBatchWitness,
    output: &AcceptedClaimBatchOutput,
) -> Result<[Block128; ACCEPTED_CLAIM_BATCH_DIGEST_HASH_FIELDS], AcceptedClaimBatchDigestError> {
    validate_accepted_claim_batch_digest_shape(witness)?;
    let mut fields = [Block128::ZERO; ACCEPTED_CLAIM_BATCH_DIGEST_HASH_FIELDS];
    let mut index = 0usize;
    fields[index] = Block128::from(ACB_DIG1);
    index += 1;
    fields[index] = Block128::from(ACCEPTED_CLAIM_BATCH_DIGEST_PAYLOAD_FIELDS as u128);
    index += 1;
    fields[index] = Block128::from(witness.headers.len() as u128);
    index += 1;
    fields[index] = Block128::from(HISTORY_CHECKPOINT_BATCH_TARGET_BLOCKS as u128);
    index += 1;
    push_consensus_fields(&mut fields, &mut index, &output.consensus_state);
    push_accumulator_fields(&mut fields, &mut index, &output.accumulator);
    for slot in 0..HISTORY_CHECKPOINT_BATCH_TARGET_BLOCKS as usize {
        if slot < witness.headers.len() {
            push_header_witness_fields(&mut fields, &mut index, &witness.headers[slot]);
            push_claim_fields(&mut fields, &mut index, witness.accepted_block_claims[slot]);
        } else {
            index += ACCEPTED_CLAIM_BATCH_DIGEST_SLOT_FIELDS;
        }
    }
    // The fixed no-pad hash consumes field pairs. These three canonical zero
    // lanes keep the complete schedule even: the eleven-lane accumulator plus
    // the seventeen-scalar consensus section grew in lockstep (+2), so the
    // historical pad width still closes the pairing.
    for _ in 0..3 {
        fields[index] = Block128::ZERO;
        index += 1;
    }
    debug_assert_eq!(index, ACCEPTED_CLAIM_BATCH_DIGEST_HASH_FIELDS);
    Ok(fields)
}

pub fn accepted_claim_batch_digest_hash_params() -> FixedFieldHashParams {
    FixedFieldHashParams::with_default_relation_tag(
        TAG_HISTPRF,
        ACCEPTED_CLAIM_BATCH_DIGEST_HASH_FIELDS,
    )
    .expect("accepted-claim batch digest hash schedule is valid")
}

pub fn prove_accepted_claim_batch_digest(
    witness: &AcceptedClaimBatchWitness,
    output: &AcceptedClaimBatchOutput,
) -> Result<AcceptedClaimBatchDigestProof, AcceptedClaimBatchDigestError> {
    let fields = accepted_claim_batch_digest_hash_fields(witness, output)?;
    let expected_digest = digest_fixed_no_pad_from_fields(&fields);
    let input = fixed_hash_input(&fields, &expected_digest);
    let params = accepted_claim_batch_digest_hash_params();
    let mut channel = Poseidon2bChannel::new();
    let inputs = [input];
    let (digest_hash, reductions) = prove_fixed_field_hash_killshot(params, &inputs, &mut channel);
    if !discharge_fixed_field_hash_reductions_native(params, &inputs, &reductions) {
        return Err(AcceptedClaimBatchDigestError::BadDigestDischarge);
    }
    Ok(AcceptedClaimBatchDigestProof { digest_hash })
}

pub fn accepted_claim_batch_digest_from_hash_fields(
    fields: &[Block128],
) -> Result<Digest, AcceptedClaimBatchDigestError> {
    if fields.len() != ACCEPTED_CLAIM_BATCH_DIGEST_HASH_FIELDS {
        return Err(AcceptedClaimBatchDigestError::DigestFieldCountMismatch {
            actual: fields.len(),
        });
    }
    if fields[0] != Block128::from(ACB_DIG1)
        || fields[1] != Block128::from(ACCEPTED_CLAIM_BATCH_DIGEST_PAYLOAD_FIELDS as u128)
        || fields[3] != Block128::from(HISTORY_CHECKPOINT_BATCH_TARGET_BLOCKS as u128)
    {
        return Err(AcceptedClaimBatchDigestError::NonCanonicalHeader);
    }
    let slot_count = usize::try_from(fields[2].to_u128())
        .map_err(|_| AcceptedClaimBatchDigestError::NonCanonicalHeader)?;
    if slot_count == 0 || slot_count > HISTORY_CHECKPOINT_BATCH_TARGET_BLOCKS as usize {
        return Err(AcceptedClaimBatchDigestError::NonCanonicalHeader);
    }
    let slots_offset = 4
        + ACCEPTED_CLAIM_BATCH_DIGEST_CONSENSUS_FIELDS
        + ACCEPTED_CLAIM_BATCH_DIGEST_ACCUMULATOR_FIELDS;
    let unused_slots_start = slots_offset + slot_count * ACCEPTED_CLAIM_BATCH_DIGEST_SLOT_FIELDS;
    let slot_region_end = slots_offset
        + HISTORY_CHECKPOINT_BATCH_TARGET_BLOCKS as usize * ACCEPTED_CLAIM_BATCH_DIGEST_SLOT_FIELDS;
    if fields[unused_slots_start..slot_region_end]
        .iter()
        .any(|field| *field != Block128::ZERO)
    {
        return Err(AcceptedClaimBatchDigestError::NonCanonicalSlotPadding);
    }
    if fields[fields.len() - 3..]
        .iter()
        .any(|field| *field != Block128::ZERO)
    {
        return Err(AcceptedClaimBatchDigestError::NonCanonicalPadding);
    }
    Ok(digest_fixed_no_pad_from_fields(fields))
}

pub fn verify_accepted_claim_batch_digest_hash_fields(
    fields: &[Block128],
    expected_digest: Digest,
    proof: &AcceptedClaimBatchDigestProof,
) -> Result<(), AcceptedClaimBatchDigestError> {
    if accepted_claim_batch_digest_from_hash_fields(fields)? != expected_digest {
        return Err(AcceptedClaimBatchDigestError::DigestMismatch);
    }
    let input = fixed_hash_input(fields, &expected_digest);
    let params = accepted_claim_batch_digest_hash_params();
    let mut channel = Poseidon2bChannel::new();
    let inputs = [input];
    let reductions =
        verify_fixed_field_hash_killshot(params, &proof.digest_hash, &inputs, &mut channel)
            .ok_or(AcceptedClaimBatchDigestError::BadDigestProof)?;
    if discharge_fixed_field_hash_reductions_native(params, &inputs, &reductions) {
        Ok(())
    } else {
        Err(AcceptedClaimBatchDigestError::BadDigestDischarge)
    }
}

pub fn verify_accepted_claim_batch_digest(
    witness: &AcceptedClaimBatchWitness,
    output: &AcceptedClaimBatchOutput,
    proof: &AcceptedClaimBatchDigestProof,
) -> Result<(), AcceptedClaimBatchDigestError> {
    let fields = accepted_claim_batch_digest_hash_fields(witness, output)?;
    let expected_digest = digest_fixed_no_pad_from_fields(&fields);
    let input = fixed_hash_input(&fields, &expected_digest);
    let params = accepted_claim_batch_digest_hash_params();
    let mut channel = Poseidon2bChannel::new();
    let inputs = [input];
    let reductions =
        verify_fixed_field_hash_killshot(params, &proof.digest_hash, &inputs, &mut channel)
            .ok_or(AcceptedClaimBatchDigestError::BadDigestProof)?;
    if discharge_fixed_field_hash_reductions_native(params, &inputs, &reductions) {
        Ok(())
    } else {
        Err(AcceptedClaimBatchDigestError::BadDigestDischarge)
    }
}

fn validate_accepted_claim_batch_digest_shape(
    witness: &AcceptedClaimBatchWitness,
) -> Result<(), AcceptedClaimBatchDigestError> {
    if witness.headers.is_empty() {
        return Err(AcceptedClaimBatchDigestError::EmptyBatch);
    }
    if witness.headers.len() > HISTORY_CHECKPOINT_BATCH_TARGET_BLOCKS as usize {
        return Err(AcceptedClaimBatchDigestError::TooManyClaims {
            actual: witness.headers.len(),
        });
    }
    if witness.headers.len() != witness.accepted_block_claims.len() {
        return Err(AcceptedClaimBatchDigestError::ClaimCountMismatch {
            headers: witness.headers.len(),
            claims: witness.accepted_block_claims.len(),
        });
    }
    Ok(())
}

fn push_header_witness_fields<const N: usize>(
    fields: &mut [Block128; N],
    index: &mut usize,
    witness: &HeaderWitness,
) {
    for field in witness.pow_fields {
        fields[*index] = field;
        *index += 1;
    }
    push_digest_fields(fields, index, &witness.pow_digest);
    push_digest_fields(fields, index, &witness.block_id);
    push_digest_fields(fields, index, &witness.target);
}

fn push_consensus_fields<const N: usize>(
    fields: &mut [Block128; N],
    index: &mut usize,
    consensus: &RecursiveConsensusState,
) {
    fields[*index] = Block128::from(consensus.height as u128);
    *index += 1;
    push_digest_fields(fields, index, &consensus.block_id);
    push_digest_fields(fields, index, &consensus.state_root);
    push_digest_fields(fields, index, &consensus.cumulative_chainwork);
    fields[*index] = Block128::from(consensus.log_slots as u128);
    *index += 1;
    fields[*index] = Block128::from(consensus.active_slot_count as u128);
    *index += 1;
    fields[*index] = Block128::from(consensus.alloc_counter as u128);
    *index += 1;
    fields[*index] = Block128::from(consensus.attested_coverage as u128);
    *index += 1;
    fields[*index] = Block128::from(consensus.asert_anchor_height as u128);
    *index += 1;
    fields[*index] = Block128::from(consensus.asert_anchor_timestamp as u128);
    *index += 1;
    push_digest_fields(fields, index, &consensus.asert_anchor_target);
    fields[*index] = Block128::from(consensus.mtp_len as u128);
    *index += 1;
    for timestamp in consensus.mtp_timestamps {
        fields[*index] = Block128::from(timestamp as u128);
        *index += 1;
    }
    fields[*index] = Block128::from(consensus.expansion_len as u128);
    *index += 1;
    for count in consensus.expansion_counts {
        fields[*index] = Block128::from(count as u128);
        *index += 1;
    }
}

fn push_accumulator_fields<const N: usize>(
    fields: &mut [Block128; N],
    index: &mut usize,
    accumulator: &ChainAccumulator,
) {
    for lane in accumulator.to_lanes() {
        fields[*index] = lane;
        *index += 1;
    }
}

fn push_claim_fields<const N: usize>(
    fields: &mut [Block128; N],
    index: &mut usize,
    claim: [Block128; 2],
) {
    fields[*index] = claim[0];
    *index += 1;
    fields[*index] = claim[1];
    *index += 1;
}

fn push_digest_fields<const N: usize>(
    fields: &mut [Block128; N],
    index: &mut usize,
    digest: &Digest,
) {
    let [lo, hi] = digest_to_fields(*digest);
    fields[*index] = lo;
    *index += 1;
    fields[*index] = hi;
    *index += 1;
}

fn digest_fixed_no_pad_from_fields(fields: &[Block128]) -> Digest {
    assert_eq!(
        fields.len() % 2,
        0,
        "fixed no-pad hash input must contain complete field pairs"
    );
    let mut sponge = Poseidon2bSponge::with_iv(capacity_iv(TAG_HISTPRF));
    for pair in fields.chunks_exact(2) {
        sponge.absorb_pair(pair[0], pair[1]);
    }
    sponge.finalize_no_pad()
}

fn fixed_hash_input(fields: &[Block128], expected_digest: &Digest) -> FixedFieldHashInputs {
    FixedFieldHashInputs {
        fields: fields.to_vec(),
        expected_digest: digest_to_fields(*expected_digest),
    }
}

pub fn verify_accepted_claim_batch_native(
    start_consensus: &RecursiveConsensusState,
    start_accumulator: &ChainAccumulator,
    witness: &AcceptedClaimBatchWitness,
) -> Result<AcceptedClaimBatchOutput, AcceptedClaimBatchError> {
    if witness.headers.is_empty() {
        return Err(AcceptedClaimBatchError::EmptyBatch);
    }
    if witness.headers.len() != witness.accepted_block_claims.len() {
        return Err(AcceptedClaimBatchError::ClaimCountMismatch {
            headers: witness.headers.len(),
            claims: witness.accepted_block_claims.len(),
        });
    }
    if !accumulator_matches_consensus(start_accumulator, start_consensus) {
        return Err(AcceptedClaimBatchError::StartStateMismatch);
    }

    let consensus_state = verify_pow_header_witness_batch_native(start_consensus, &witness.headers)
        .map_err(AcceptedClaimBatchError::HeaderWork)?;

    let mut accumulator = start_accumulator.clone();
    for (index, header_witness) in witness.headers.iter().enumerate() {
        accumulator = accumulator
            .advance(&header_witness.header)
            .map_err(|source| AcceptedClaimBatchError::AccumulatorAdvance { index, source })?;
    }

    if !accumulator_matches_consensus(&accumulator, &consensus_state) {
        return Err(AcceptedClaimBatchError::EndStateMismatch);
    }

    Ok(AcceptedClaimBatchOutput {
        consensus_state,
        accumulator,
    })
}

/// Verify the accepted-claim batch using the split header-work boundary.
///
/// This function does not recompute Poseidon2b header hashes. It is valid only
/// when paired with `HeaderHashProofKillShot` over the same header witnesses.
pub fn verify_accepted_claim_batch_with_header_trace(
    start_consensus: &RecursiveConsensusState,
    start_accumulator: &ChainAccumulator,
    witness: &AcceptedClaimBatchWitness,
    header_trace: &HeaderIntegerBatchTrace,
) -> Result<AcceptedClaimBatchOutput, AcceptedClaimBatchError> {
    if witness.headers.is_empty() {
        return Err(AcceptedClaimBatchError::EmptyBatch);
    }
    if witness.headers.len() != witness.accepted_block_claims.len() {
        return Err(AcceptedClaimBatchError::ClaimCountMismatch {
            headers: witness.headers.len(),
            claims: witness.accepted_block_claims.len(),
        });
    }
    if !accumulator_matches_consensus(start_accumulator, start_consensus) {
        return Err(AcceptedClaimBatchError::StartStateMismatch);
    }

    let consensus_state =
        verify_header_integer_trace(start_consensus, &witness.headers, header_trace)
            .map_err(AcceptedClaimBatchError::HeaderInteger)?;

    let mut accumulator = start_accumulator.clone();
    for (index, header_witness) in witness.headers.iter().enumerate() {
        accumulator = accumulator
            .advance(&header_witness.header)
            .map_err(|source| AcceptedClaimBatchError::AccumulatorAdvance { index, source })?;
    }

    if !accumulator_matches_consensus(&accumulator, &consensus_state) {
        return Err(AcceptedClaimBatchError::EndStateMismatch);
    }

    Ok(AcceptedClaimBatchOutput {
        consensus_state,
        accumulator,
    })
}

fn accumulator_matches_consensus(
    accumulator: &ChainAccumulator,
    consensus: &RecursiveConsensusState,
) -> bool {
    accumulator.height == consensus.height
        && accumulator.tip_block_id == consensus.block_id
        && accumulator.state_root == consensus.state_root
        && accumulator.log_slots == consensus.log_slots
        && accumulator.active_slot_count == consensus.active_slot_count
        && accumulator.alloc_counter == consensus.alloc_counter
        && accumulator.attested_coverage == consensus.attested_coverage
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header_integer::build_header_integer_trace;
    use noid_chain::consensus::difficulty::{add_work, block_work, next_target};
    use noid_chain::consensus::params::BLOCK_TIME;
    use noid_chain::consensus::{asert_anchor_height, genesis_header};
    use noid_poseidon2b::primitives::Address;

    fn verify_without_pow_for_tests(
        start_consensus: &RecursiveConsensusState,
        start_accumulator: &ChainAccumulator,
        witness: &AcceptedClaimBatchWitness,
    ) -> Result<AcceptedClaimBatchOutput, AcceptedClaimBatchError> {
        if witness.headers.len() != witness.accepted_block_claims.len() {
            return Err(AcceptedClaimBatchError::ClaimCountMismatch {
                headers: witness.headers.len(),
                claims: witness.accepted_block_claims.len(),
            });
        }
        let mut consensus = start_consensus.clone();
        let mut accumulator = start_accumulator.clone();
        for (index, header_witness) in witness.headers.iter().enumerate() {
            if header_witness.header.prev_block_hash != consensus.block_id {
                return Err(AcceptedClaimBatchError::HeaderWork(
                    PowHeaderBatchError::BadParentLink { index },
                ));
            }
            if header_witness.header.height != consensus.height + 1 {
                return Err(AcceptedClaimBatchError::HeaderWork(
                    PowHeaderBatchError::BadHeight { index },
                ));
            }
            if header_witness.block_id != noid_chain::hash_block_header(&header_witness.header) {
                return Err(AcceptedClaimBatchError::HeaderWork(
                    PowHeaderBatchError::BadHeaderWitness {
                        index,
                        reason: crate::pow_header::HeaderWitnessError::BadBlockId,
                    },
                ));
            }
            consensus.height = header_witness.header.height;
            consensus.block_id = header_witness.block_id;
            consensus.state_root = header_witness.header.state_root;
            consensus.log_slots = header_witness.header.log_slots;
            consensus.active_slot_count = header_witness.header.active_slot_count;
            consensus.alloc_counter = header_witness.header.alloc_counter;
            accumulator = accumulator
                .advance(&header_witness.header)
                .map_err(|source| AcceptedClaimBatchError::AccumulatorAdvance { index, source })?;
        }
        if !accumulator_matches_consensus(&accumulator, &consensus) {
            return Err(AcceptedClaimBatchError::EndStateMismatch);
        }
        Ok(AcceptedClaimBatchOutput {
            consensus_state: consensus,
            accumulator,
        })
    }

    fn next_header(state: &RecursiveConsensusState, state_seed: u8) -> noid_chain::BlockHeader {
        let height = state.height + 1;
        let timestamp = state.mtp_timestamps[(state.mtp_len - 1) as usize] + BLOCK_TIME;
        noid_chain::BlockHeader {
            attested_coverage: 0,
            prev_block_hash: state.block_id,
            state_root: [state_seed; 32],
            tx_root: [state_seed ^ 0x55; 32],
            timestamp,
            height,
            miner_address: Address([0x55; 32]),
            nonce: height as u128,
            difficulty_target: next_target(
                state.asert_anchor_height,
                state.asert_anchor_timestamp,
                &state.asert_anchor_target,
                height,
                timestamp,
            ),
            log_slots: state.log_slots,
            active_slot_count: state.active_slot_count,
            alloc_counter: state.alloc_counter,
        }
    }

    fn start_pair() -> (RecursiveConsensusState, ChainAccumulator) {
        let header = genesis_header();
        let start_consensus = RecursiveConsensusState::from_header(
            &header,
            block_work(&header.difficulty_target),
            0,
            header.timestamp,
            header.difficulty_target,
            &[header.timestamp],
            &[header.active_slot_count],
        );
        let start_accumulator = crate::accumulator::genesis_accumulator();
        (start_consensus, start_accumulator)
    }

    fn advance_consensus_for_tests(
        state: &RecursiveConsensusState,
        header: &noid_chain::BlockHeader,
        block_id: [u8; 32],
    ) -> RecursiveConsensusState {
        let mut next = state.clone();
        next.height = header.height;
        next.block_id = block_id;
        next.state_root = header.state_root;
        next.cumulative_chainwork = add_work(
            &next.cumulative_chainwork,
            &block_work(&header.difficulty_target),
        );
        next.log_slots = header.log_slots;
        next.active_slot_count = header.active_slot_count;
        next.alloc_counter = header.alloc_counter;
        next.push_timestamp(header.timestamp);
        next.push_active_count(header.active_slot_count);
        if asert_anchor_height(header.height) == header.height {
            next.asert_anchor_height = header.height;
            next.asert_anchor_timestamp = header.timestamp;
            next.asert_anchor_target = header.difficulty_target;
        }
        next
    }

    fn integer_witness(header: &noid_chain::BlockHeader) -> HeaderWitness {
        let mut witness = HeaderWitness::from_header(header);
        witness.pow_digest = [0u8; 32];
        witness
    }

    #[test]
    fn accepted_claim_batch_updates_consensus_and_accumulator() {
        let (start_consensus, start_accumulator) = start_pair();
        let h1 = next_header(&start_consensus, 2);
        let mut mid = start_consensus.clone();
        mid.height = h1.height;
        mid.block_id = noid_chain::hash_block_header(&h1);
        mid.state_root = h1.state_root;
        let h2 = next_header(&mid, 3);
        let claims = vec![
            [Block128::from(0xA1u128), Block128::from(0xA2u128)],
            [Block128::from(0xB1u128), Block128::from(0xB2u128)],
        ];
        let witness = AcceptedClaimBatchWitness {
            headers: vec![
                HeaderWitness::from_header(&h1),
                HeaderWitness::from_header(&h2),
            ],
            accepted_block_claims: claims.clone(),
        };

        let out =
            verify_without_pow_for_tests(&start_consensus, &start_accumulator, &witness).unwrap();
        assert_eq!(out.consensus_state.height, 2);
        assert_eq!(out.consensus_state.state_root, h2.state_root);
        assert_eq!(
            accepted_claim_batch_digest_hash_fields(&witness, &out)
                .expect("digest fields")
                .len(),
            ACCEPTED_CLAIM_BATCH_DIGEST_HASH_FIELDS
        );
        assert_ne!(
            accepted_claim_batch_digest(&witness, &out).expect("digest"),
            [0u8; 32]
        );
        let digest_proof = prove_accepted_claim_batch_digest(&witness, &out).expect("digest proof");
        verify_accepted_claim_batch_digest(&witness, &out, &digest_proof)
            .expect("digest proof verifies");

        for lane_index in 0..CHAIN_ACCUMULATOR_LANES {
            let mut tampered_out = out.clone();
            let mut lanes = tampered_out.accumulator.to_lanes();
            lanes[lane_index] += Block128::ONE;
            tampered_out.accumulator = ChainAccumulator::from_lanes(lanes).unwrap();
            assert_eq!(
                verify_accepted_claim_batch_digest(&witness, &tampered_out, &digest_proof),
                Err(AcceptedClaimBatchDigestError::BadDigestProof),
                "accumulator lane {lane_index} must be digest-bound"
            );
        }

        let expected = start_accumulator
            .advance(&h1)
            .unwrap()
            .advance(&h2)
            .unwrap();
        assert_eq!(out.accumulator, expected);

        let fields = accepted_claim_batch_digest_hash_fields(&witness, &out).unwrap();
        assert_eq!(fields.len() % 2, 0);
        assert_eq!(
            &fields[fields.len() - 3..],
            &[Block128::ZERO, Block128::ZERO, Block128::ZERO]
        );
        let mut bad_padding = fields;
        let last = bad_padding.len() - 1;
        bad_padding[last] = Block128::ONE;
        assert_eq!(
            accepted_claim_batch_digest_from_hash_fields(&bad_padding),
            Err(AcceptedClaimBatchDigestError::NonCanonicalPadding)
        );

        let mut bad_header = fields;
        bad_header[0] += Block128::ONE;
        assert_eq!(
            accepted_claim_batch_digest_from_hash_fields(&bad_header),
            Err(AcceptedClaimBatchDigestError::NonCanonicalHeader)
        );

        let mut bad_slot_padding = fields;
        let slots_offset = 4
            + ACCEPTED_CLAIM_BATCH_DIGEST_CONSENSUS_FIELDS
            + ACCEPTED_CLAIM_BATCH_DIGEST_ACCUMULATOR_FIELDS;
        let first_unused =
            slots_offset + witness.headers.len() * ACCEPTED_CLAIM_BATCH_DIGEST_SLOT_FIELDS;
        bad_slot_padding[first_unused] = Block128::ONE;
        assert_eq!(
            accepted_claim_batch_digest_from_hash_fields(&bad_slot_padding),
            Err(AcceptedClaimBatchDigestError::NonCanonicalSlotPadding)
        );
    }

    #[test]
    fn accepted_claim_batch_with_header_trace_updates_consensus_and_accumulator() {
        let (start_consensus, start_accumulator) = start_pair();
        let h1 = next_header(&start_consensus, 2);
        let w1 = integer_witness(&h1);
        let mid = advance_consensus_for_tests(&start_consensus, &h1, w1.block_id);
        let h2 = next_header(&mid, 3);
        let w2 = integer_witness(&h2);
        let witness = AcceptedClaimBatchWitness {
            headers: vec![w1, w2],
            accepted_block_claims: vec![
                [Block128::from(0xA1u128), Block128::from(0xA2u128)],
                [Block128::from(0xB1u128), Block128::from(0xB2u128)],
            ],
        };
        let trace = build_header_integer_trace(&start_consensus, &witness.headers).unwrap();

        let out = verify_accepted_claim_batch_with_header_trace(
            &start_consensus,
            &start_accumulator,
            &witness,
            &trace,
        )
        .unwrap();

        assert_eq!(out.consensus_state.height, h2.height);
        assert_eq!(
            out.consensus_state.block_id,
            noid_chain::hash_block_header(&h2)
        );
        assert_eq!(out.consensus_state.state_root, h2.state_root);
        assert_eq!(out.accumulator.height, h2.height);
        assert_eq!(out.accumulator.state_root, h2.state_root);
    }

    #[test]
    fn accepted_claim_batch_with_header_trace_rejects_pow_equality() {
        let (start_consensus, start_accumulator) = start_pair();
        let h1 = next_header(&start_consensus, 2);
        let mut witness_header = HeaderWitness::from_header(&h1);
        witness_header.pow_digest = h1.difficulty_target;
        let witness = AcceptedClaimBatchWitness {
            headers: vec![witness_header],
            accepted_block_claims: vec![[Block128::from(1u128), Block128::from(2u128)]],
        };
        let trace = build_header_integer_trace(&start_consensus, &witness.headers).unwrap();

        assert_eq!(
            verify_accepted_claim_batch_with_header_trace(
                &start_consensus,
                &start_accumulator,
                &witness,
                &trace,
            ),
            Err(AcceptedClaimBatchError::HeaderInteger(
                HeaderIntegerTraceError::BadPowTarget { index: 0 }
            ))
        );
    }

    #[test]
    fn accepted_claim_batch_rejects_every_consensus_overlap_mismatch() {
        let (start_consensus, start_accumulator) = start_pair();
        let h1 = next_header(&start_consensus, 2);
        let witness = AcceptedClaimBatchWitness {
            headers: vec![integer_witness(&h1)],
            accepted_block_claims: vec![[Block128::from(1u128), Block128::from(2u128)]],
        };
        let trace = build_header_integer_trace(&start_consensus, &witness.headers).unwrap();

        // height, tip id, state root, log_slots, active count and allocation
        // counter are the complete overlap with RecursiveConsensusState.
        for lane_index in 0..8 {
            let mut lanes = start_accumulator.to_lanes();
            lanes[lane_index] += Block128::ONE;
            let bad = ChainAccumulator::from_lanes(lanes).unwrap();
            assert_eq!(
                verify_accepted_claim_batch_with_header_trace(
                    &start_consensus,
                    &bad,
                    &witness,
                    &trace,
                ),
                Err(AcceptedClaimBatchError::StartStateMismatch),
                "consensus-overlap lane {lane_index} must be pinned"
            );
        }
    }

    #[test]
    fn accepted_claim_batch_rejects_claim_count_mismatch() {
        let (start_consensus, start_accumulator) = start_pair();
        let h1 = next_header(&start_consensus, 2);
        let witness = AcceptedClaimBatchWitness {
            headers: vec![HeaderWitness::from_header(&h1)],
            accepted_block_claims: vec![],
        };
        assert!(matches!(
            verify_without_pow_for_tests(&start_consensus, &start_accumulator, &witness),
            Err(AcceptedClaimBatchError::ClaimCountMismatch {
                headers: 1,
                claims: 0
            })
        ));
    }

    #[test]
    fn accepted_claim_batch_rejects_bad_parent_link() {
        let (start_consensus, start_accumulator) = start_pair();
        let mut h1 = next_header(&start_consensus, 2);
        h1.prev_block_hash = [9u8; 32];
        let witness = AcceptedClaimBatchWitness {
            headers: vec![HeaderWitness::from_header(&h1)],
            accepted_block_claims: vec![[Block128::from(1u128), Block128::from(2u128)]],
        };
        assert!(matches!(
            verify_without_pow_for_tests(&start_consensus, &start_accumulator, &witness),
            Err(AcceptedClaimBatchError::HeaderWork(
                PowHeaderBatchError::BadParentLink { index: 0 }
            ))
        ));
    }
}
