// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Local history-proof envelope and recursive-boundary experiments.
//!
//! Nodes validate and store canonical headers from genesis.  History proving
//! therefore treats header consensus as native node work. The objects in this
//! module are useful for local cache folding, component testing, and shape
//! measurement, but they are not public snapshot authority until the recursive
//! backend verifies previous-proof validity and the full accepted-block
//! relation. Untrusted verification must remain fail-closed for incomplete
//! backends.

use noid_chain::block_header::BlockHeader;
use noid_chain::header_anchor::{header_projection_digest, HeaderChainAnchor};
use noid_core::{sumcheck::RoundPolynomial, transcript::FiatShamir, Block128, TowerField};
use noid_gkr::batch_eval::LinearEvalProof;
use noid_gkr::{
    discharge_chain_accumulator_reductions_native_padded,
    discharge_fixed_field_hash_reductions_native, discharge_header_hash_reductions_native_padded,
    discharge_history_claim_hash_reductions_native, prove_fixed_field_hash_killshot,
    prove_history_claim_hash_killshot, verify_chain_accumulator_killshot_padded,
    verify_fixed_field_hash_killshot, verify_header_hash_killshot_padded,
    verify_history_claim_hash_killshot, BatchEvalRound, BlockSpineKillShotProof,
    BlockSpineShiftProof, BlockSpineUnifiedProof, FixedFieldHashInputs, FixedFieldHashParams,
    FixedFieldHashProofKillShot, HistoryClaimHashInputs, HistoryClaimHashProofKillShot,
    HistoryClaimHashReductions, MultiBatchEvalProof, HISTORY_CLAIM_FIELDS,
};
use noid_poseidon2b::native::domain::{capacity_iv, TAG_HDRANCH, TAG_HISTCLM, TAG_HISTPRF};
use noid_poseidon2b::native::{compress_with_tag, Poseidon2bSponge};
use noid_poseidon2b::primitives::{Address, Digest};

use crate::accepted_batch::{chain_accumulator_proof_inputs, AcceptedClaimBatchWitness};
use crate::accumulator::ChainAccumulator;
use crate::authorization::FiatShamirTraceOp;
use crate::checkpoint::{
    prove_checkpoint_poseidon_padded, verify_checkpoint_poseidon_padded, CheckpointPoseidonError,
    CheckpointPoseidonProof,
};
use crate::fs_transcript::{
    discharge_fiat_shamir_transcript_batch_reductions_native,
    prove_fiat_shamir_transcript_batch_killshot, verify_fiat_shamir_transcript_batch_killshot,
    FiatShamirTranscriptBatchProofKillShot, FiatShamirTranscriptError,
    FiatShamirTranscriptReductions,
};
use crate::pow_header::{header_hash_proof_inputs, HeaderWitness};

pub const HISTORY_PROOF_VERSION: u32 = 1;
pub const HISTORY_CHAIN_ACCUMULATOR_FIELDS: usize = 5;
pub const HISTORY_ACCUMULATION_STATE_FIELDS: usize = 14;
pub const HISTORY_STEP_STATEMENT_FIELDS: usize = 25;
pub const HISTORY_PCD_STEP_STATEMENT_FIELDS: usize = 54;
pub const HISTORY_ARC_PCD_ACCUMULATOR_FIELDS: usize = 12;
pub const HISTORY_ARC_PCD_RECURSIVE_STEP_FIELDS: usize = 12;
pub const HISTORY_ARC_PCD_RECURSIVE_CHUNK_STEP_FIELDS: usize = 12;
pub const HISTORY_ARC_PCD_CHUNK_MAX_STEPS: usize = 18;
pub const HISTORY_ACCUMULATION_STATE_HASH_FIELDS: usize = HISTORY_ACCUMULATION_STATE_FIELDS + 2;
pub const HISTORY_PCD_STEP_HASH_FIELDS: usize = HISTORY_PCD_STEP_STATEMENT_FIELDS + 2;
pub const HISTORY_ARC_PCD_ACCUMULATOR_HASH_FIELDS: usize = HISTORY_ARC_PCD_ACCUMULATOR_FIELDS + 2;
pub const HISTORY_ARC_PCD_RECURSIVE_STEP_HASH_FIELDS: usize =
    HISTORY_ARC_PCD_RECURSIVE_STEP_FIELDS + 2;
pub const HISTORY_ARC_PCD_RECURSIVE_CHUNK_STEP_HASH_FIELDS: usize =
    HISTORY_ARC_PCD_RECURSIVE_CHUNK_STEP_FIELDS + 2;
pub const HISTORY_TAGGED_PAIR_HASH_FIELDS: usize = 6;

const HISTORY_ACCUMULATION_STATE_HASH_MARKER: u128 = 0x4849_5354_4153_5431; // "HISTAST1"
const HISTORY_PCD_STEP_HASH_MARKER: u128 = 0x4849_5354_5043_4431; // "HISTPCD1"
const HISTORY_ARC_PCD_ACCUMULATOR_HASH_MARKER: u128 = 0x4849_5354_4152_4331; // "HISTARC1"
const HISTORY_ARC_PCD_RECURSIVE_STEP_HASH_MARKER: u128 = 0x4849_5354_5245_4331; // "HISTREC1"
const HISTORY_ARC_PCD_RECURSIVE_CHUNK_STEP_HASH_MARKER: u128 = 0x4849_5354_5243_4831; // "HISTRCH1"
const HISTAR01: u128 = 0x4849_5354_4152_3031;
const HISTARA1: u128 = 0x4849_5354_4152_4131;
const HISTART1: u128 = 0x4849_5354_4152_5431;
const HISTRCB1: u128 = 0x4849_5354_5243_4231;
const HISTRCN1: u128 = 0x4849_5354_5243_4E31;
const HISTRKN1: u128 = 0x4849_5354_524B_4E31;
const HISTACC1: u128 = 0x4849_5354_4143_4331;
const HISTSTP1: u128 = 0x4849_5354_5354_5031;
const HISTPCS1: u128 = 0x4849_5354_5043_5331;
const HISTOPN1: u128 = 0x4849_5354_4F50_4E31;
const HISTDST1: u128 = 0x4849_5354_4453_5431;
const HISTNUL1: u128 = 0x4849_5354_4E55_4C31;
const HISTSOM1: u128 = 0x4849_5354_534F_4D31;
const HISTRPY1: u128 = 0x4849_5354_5250_5931;
const HISTBEV1: u128 = 0x4849_5354_4245_5631;
const HISTMBV1: u128 = 0x4849_5354_4D42_5631;
const HISTLEV1: u128 = 0x4849_5354_4C45_5631;
const HISTBKU1: u128 = 0x4849_5354_424B_5531;
const HISTBKS1: u128 = 0x4849_5354_424B_5331;
const HISTBKK1: u128 = 0x4849_5354_424B_4B31;
const HISTFXH1: u128 = 0x4849_5354_4658_4831;
const HISTHCH1: u128 = 0x4849_5354_4843_4831;
const HISTDHP1: u128 = 0x4849_5354_4448_5031;
const HISTOSD1: u128 = 0x4849_5354_4F53_4431;
const HISTCSD1: u128 = 0x4849_5354_4353_4431;
const HISTHSP1: u128 = 0x4849_5354_4853_5031;
const HISTASP1: u128 = 0x4849_5354_4153_5031;
const HISTHRP1: u128 = 0x4849_5354_4852_5031;
const HISTHCP1: u128 = 0x4849_5354_4843_5031;
const HISTHRH1: u128 = 0x4849_5354_4852_4831;
const HISTHCK1: u128 = 0x4849_5354_4843_4B31;
const HISTFST1: u128 = 0x4849_5354_4653_5431;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum HistoryProofBackend {
    /// Native folded-statement envelope.  This fixes the public proof language;
    /// the optimized recursive backend must prove the same folded statement.
    NativeFoldV1,
    /// Final hash-based accumulation/PCD backend target.  This variant is
    /// reserved until the verifier is implemented and must fail closed.
    ArcPcdV1,
}

impl HistoryProofBackend {
    #[inline]
    fn id(self) -> u32 {
        match self {
            Self::NativeFoldV1 => 1,
            Self::ArcPcdV1 => 2,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HistoryProof {
    pub version: u32,
    pub backend: HistoryProofBackend,
    pub start_anchor: HeaderChainAnchor,
    pub end_anchor: HeaderChainAnchor,
    pub start_accumulator: ChainAccumulator,
    pub end_accumulator: ChainAccumulator,
    pub folded_witness_root: Digest,
    pub step_count: u64,
    pub decider: HistoryDeciderProof,
    pub proof_digest: Digest,
}

impl HistoryProof {
    pub fn byte_len(&self) -> usize {
        bincode::serialized_size(self)
            .expect("HistoryProof serialization is fixed-size")
            .try_into()
            .expect("serialized proof length fits usize")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HistoryDeciderStatement {
    pub version: u32,
    pub backend: HistoryProofBackend,
    pub step_count: u64,
    pub start_anchor_digest: Digest,
    pub end_anchor_digest: Digest,
    pub start_accumulator_digest: Digest,
    pub end_accumulator_digest: Digest,
    pub folded_witness_root: Digest,
}

impl HistoryDeciderStatement {
    pub fn byte_len(&self) -> usize {
        bincode::serialized_size(self)
            .expect("HistoryDeciderStatement serialization is fixed-size")
            .try_into()
            .expect("serialized decider statement length fits usize")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HistoryArcPcdAccumulator {
    pub version: u32,
    pub step_count: u64,
    pub start_state_digest: Digest,
    pub current_state_digest: Digest,
    pub pcd_root: Digest,
    pub step_relation_digest: Digest,
    pub transcript_digest: Digest,
}

impl HistoryArcPcdAccumulator {
    pub fn byte_len(&self) -> usize {
        bincode::serialized_size(self)
            .expect("HistoryArcPcdAccumulator serialization is fixed-size")
            .try_into()
            .expect("serialized ARC/PCD accumulator length fits usize")
    }

    pub(crate) fn zero() -> Self {
        Self {
            version: HISTORY_PROOF_VERSION,
            step_count: 0,
            start_state_digest: [0u8; 32],
            current_state_digest: [0u8; 32],
            pcd_root: [0u8; 32],
            step_relation_digest: history_arc_pcd_step_relation_digest(),
            transcript_digest: [0u8; 32],
        }
    }

    pub fn from_start_state(state: &HistoryAccumulationState) -> Result<Self, HistoryProofError> {
        validate_accumulation_state_shape(state)?;
        let state_digest = history_accumulation_state_digest(state);
        let relation_digest = history_arc_pcd_step_relation_digest();
        let transcript_digest = tagged_pair_digest(HISTAR01, &state_digest, &relation_digest);
        Ok(Self {
            version: HISTORY_PROOF_VERSION,
            step_count: state.step_count,
            start_state_digest: state_digest,
            current_state_digest: state_digest,
            pcd_root: [0u8; 32],
            step_relation_digest: relation_digest,
            transcript_digest,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HistoryDeciderProof {
    pub statement_digest: Digest,
    pub pcd_accumulator: HistoryArcPcdAccumulator,
    pub accumulator_commitment: Digest,
    pub step_relation_commitment: Digest,
    pub pcs_commitment: Digest,
    pub opening_digest: Digest,
    pub transcript_digest: Digest,
    pub hash_proofs_digest: Digest,
    pub hash_proofs: Option<HistoryDeciderHashProofs>,
    pub one_step_proof_digest: Digest,
    pub one_step_proof: Option<HistoryArcPcdOneStepProof>,
    pub recursive_head_digest: Digest,
    pub recursive_head: Option<HistoryArcPcdRecursiveChainHead>,
    pub recursive_chunk_head_digest: Digest,
    pub recursive_chunk_head: Option<HistoryArcPcdRecursiveChunkChainHead>,
    pub reserved: [Digest; 1],
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HistoryDeciderHashProofs {
    pub arc_accumulator_hash: FixedFieldHashProofKillShot,
    pub tagged_pair_hashes: FixedFieldHashProofKillShot,
}

impl HistoryDeciderHashProofs {
    pub fn byte_len(&self) -> usize {
        self.arc_accumulator_hash.byte_len() + self.tagged_pair_hashes.byte_len()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HistoryArcPcdStepProof {
    pub state_hashes: FixedFieldHashProofKillShot,
    pub pcd_step_hash: FixedFieldHashProofKillShot,
    pub accumulator_update_hashes: FixedFieldHashProofKillShot,
}

impl HistoryArcPcdStepProof {
    pub fn byte_len(&self) -> usize {
        self.state_hashes.byte_len()
            + self.pcd_step_hash.byte_len()
            + self.accumulator_update_hashes.byte_len()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HistoryArcPcdOneStepProof {
    pub step: HistoryStepProof,
    pub arc_step: HistoryArcPcdStepProof,
}

impl HistoryArcPcdOneStepProof {
    pub fn byte_len(&self) -> usize {
        self.step.byte_len() + self.arc_step.byte_len()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HistoryArcPcdChunkStepProof {
    pub chunk_len: u32,
    pub checkpoint_poseidon: CheckpointPoseidonProof,
    pub claim_hash: HistoryClaimHashProofKillShot,
    pub state_hashes: FixedFieldHashProofKillShot,
    pub pcd_step_hashes: FixedFieldHashProofKillShot,
    pub accumulator_update_hashes: FixedFieldHashProofKillShot,
}

impl HistoryArcPcdChunkStepProof {
    pub fn byte_len(&self) -> usize {
        self.checkpoint_poseidon.byte_len()
            + self.claim_hash.byte_len()
            + self.state_hashes.byte_len()
            + self.pcd_step_hashes.byte_len()
            + self.accumulator_update_hashes.byte_len()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HistoryArcPcdRecursiveStepStatement {
    pub version: u32,
    pub step_count: u64,
    pub previous_proof_digest: Digest,
    pub previous_accumulator_digest: Digest,
    pub pcd_step_digest: Digest,
    pub one_step_proof_digest: Digest,
    pub next_accumulator_digest: Digest,
}

impl HistoryArcPcdRecursiveStepStatement {
    pub fn byte_len(&self) -> usize {
        bincode::serialized_size(self)
            .expect("HistoryArcPcdRecursiveStepStatement serialization is fixed-size")
            .try_into()
            .expect("serialized recursive step statement length fits usize")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HistoryArcPcdRecursiveStepProof {
    pub recursive_hashes: FixedFieldHashProofKillShot,
    pub next_proof_digest_hash: FixedFieldHashProofKillShot,
}

impl HistoryArcPcdRecursiveStepProof {
    pub fn byte_len(&self) -> usize {
        self.recursive_hashes.byte_len() + self.next_proof_digest_hash.byte_len()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HistoryArcPcdRecursiveChainHead {
    pub version: u32,
    pub step_count: u64,
    pub base_proof_digest: Digest,
    pub final_proof_digest: Digest,
    pub previous_accumulator: HistoryArcPcdAccumulator,
    pub final_step_statement: HistoryArcPcdRecursiveStepStatement,
    pub final_step_proof: HistoryArcPcdRecursiveStepProof,
}

impl HistoryArcPcdRecursiveChainHead {
    pub fn byte_len(&self) -> usize {
        bincode::serialized_size(self)
            .expect("HistoryArcPcdRecursiveChainHead serialization is fixed-size")
            .try_into()
            .expect("serialized recursive chain head length fits usize")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HistoryArcPcdRecursiveChunkStepStatement {
    pub version: u32,
    pub chunk_len: u32,
    pub previous_step_count: u64,
    pub step_count: u64,
    pub previous_proof_digest: Digest,
    pub previous_accumulator_digest: Digest,
    pub chunk_step_proof_digest: Digest,
    pub next_accumulator_digest: Digest,
}

impl HistoryArcPcdRecursiveChunkStepStatement {
    pub fn byte_len(&self) -> usize {
        bincode::serialized_size(self)
            .expect("HistoryArcPcdRecursiveChunkStepStatement serialization is fixed-size")
            .try_into()
            .expect("serialized recursive chunk step statement length fits usize")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HistoryArcPcdRecursiveChunkStepProof {
    pub recursive_hashes: FixedFieldHashProofKillShot,
    pub next_proof_digest_hash: FixedFieldHashProofKillShot,
}

impl HistoryArcPcdRecursiveChunkStepProof {
    pub fn byte_len(&self) -> usize {
        self.recursive_hashes.byte_len() + self.next_proof_digest_hash.byte_len()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HistoryArcPcdRecursiveChunkChainHead {
    pub version: u32,
    pub step_count: u64,
    pub chunk_count: u64,
    pub base_proof_digest: Digest,
    pub final_proof_digest: Digest,
    pub previous_accumulator: HistoryArcPcdAccumulator,
    pub final_chunk_statement: HistoryArcPcdRecursiveChunkStepStatement,
    pub final_chunk_proof: HistoryArcPcdRecursiveChunkStepProof,
    pub final_chunk_verifier_transcript: FiatShamirTranscriptBatchProofKillShot,
}

impl HistoryArcPcdRecursiveChunkChainHead {
    pub fn byte_len(&self) -> usize {
        bincode::serialized_size(self)
            .expect("HistoryArcPcdRecursiveChunkChainHead serialization is fixed-size")
            .try_into()
            .expect("serialized recursive chunk chain head length fits usize")
    }
}

impl HistoryDeciderProof {
    pub fn byte_len(&self) -> usize {
        bincode::serialized_size(self)
            .expect("HistoryDeciderProof serialization is fixed-size")
            .try_into()
            .expect("serialized decider proof length fits usize")
    }

    pub(crate) fn zero() -> Self {
        Self {
            statement_digest: [0u8; 32],
            pcd_accumulator: HistoryArcPcdAccumulator::zero(),
            accumulator_commitment: [0u8; 32],
            step_relation_commitment: [0u8; 32],
            pcs_commitment: [0u8; 32],
            opening_digest: [0u8; 32],
            transcript_digest: [0u8; 32],
            hash_proofs_digest: [0u8; 32],
            hash_proofs: None,
            one_step_proof_digest: [0u8; 32],
            one_step_proof: None,
            recursive_head_digest: [0u8; 32],
            recursive_head: None,
            recursive_chunk_head_digest: [0u8; 32],
            recursive_chunk_head: None,
            reserved: [[0u8; 32]; 1],
        }
    }

    pub(crate) fn native_fold_v1(
        statement: &HistoryDeciderStatement,
        pcd_accumulator: &HistoryArcPcdAccumulator,
    ) -> Result<Self, HistoryProofError> {
        let commitments = history_decider_commitments_v1(statement, pcd_accumulator)?;
        let hash_proofs = HistoryDeciderHashProofs::prove(
            statement,
            pcd_accumulator,
            &commitments.pcd_accumulator_digest,
            &commitments.accumulator_commitment,
            &commitments.step_relation_commitment,
            &commitments.pcs_commitment,
            &commitments.opening_digest,
            &commitments.transcript_digest,
        )?;
        let hash_proofs = Some(hash_proofs);
        let hash_proofs_digest = history_decider_hash_proofs_digest(&hash_proofs)?;
        let one_step_proof = None;
        let one_step_proof_digest = history_arc_pcd_one_step_proof_digest(&one_step_proof)?;
        let recursive_head = None;
        let recursive_head_digest = history_arc_pcd_recursive_head_digest(&recursive_head)?;
        let recursive_chunk_head = None;
        let recursive_chunk_head_digest =
            history_arc_pcd_recursive_chunk_head_digest(&recursive_chunk_head)?;
        Ok(Self {
            statement_digest: commitments.statement_digest,
            pcd_accumulator: pcd_accumulator.clone(),
            accumulator_commitment: commitments.accumulator_commitment,
            step_relation_commitment: commitments.step_relation_commitment,
            pcs_commitment: commitments.pcs_commitment,
            opening_digest: commitments.opening_digest,
            transcript_digest: commitments.transcript_digest,
            hash_proofs_digest,
            hash_proofs,
            one_step_proof_digest,
            one_step_proof,
            recursive_head_digest,
            recursive_head,
            recursive_chunk_head_digest,
            recursive_chunk_head,
            reserved: [[0u8; 32]; 1],
        })
    }

    fn arc_pcd_one_step_v1(
        statement: &HistoryDeciderStatement,
        pcd_accumulator: &HistoryArcPcdAccumulator,
        one_step_proof: HistoryArcPcdOneStepProof,
    ) -> Result<Self, HistoryProofError> {
        let commitments = history_decider_commitments_v1(statement, pcd_accumulator)?;
        let hash_proofs = None;
        let hash_proofs_digest = history_decider_hash_proofs_digest(&hash_proofs)?;
        let one_step_proof = Some(one_step_proof);
        let one_step_proof_digest = history_arc_pcd_one_step_proof_digest(&one_step_proof)?;
        let recursive_head = None;
        let recursive_head_digest = history_arc_pcd_recursive_head_digest(&recursive_head)?;
        let recursive_chunk_head = None;
        let recursive_chunk_head_digest =
            history_arc_pcd_recursive_chunk_head_digest(&recursive_chunk_head)?;
        Ok(Self {
            statement_digest: commitments.statement_digest,
            pcd_accumulator: pcd_accumulator.clone(),
            accumulator_commitment: commitments.accumulator_commitment,
            step_relation_commitment: commitments.step_relation_commitment,
            pcs_commitment: commitments.pcs_commitment,
            opening_digest: commitments.opening_digest,
            transcript_digest: commitments.transcript_digest,
            hash_proofs_digest,
            hash_proofs,
            one_step_proof_digest,
            one_step_proof,
            recursive_head_digest,
            recursive_head,
            recursive_chunk_head_digest,
            recursive_chunk_head,
            reserved: [[0u8; 32]; 1],
        })
    }

    pub(crate) fn arc_pcd_recursive_head_v1(
        statement: &HistoryDeciderStatement,
        pcd_accumulator: &HistoryArcPcdAccumulator,
        recursive_head: HistoryArcPcdRecursiveChainHead,
    ) -> Result<Self, HistoryProofError> {
        let commitments = history_decider_commitments_v1(statement, pcd_accumulator)?;
        let hash_proofs = None;
        let hash_proofs_digest = history_decider_hash_proofs_digest(&hash_proofs)?;
        let one_step_proof = None;
        let one_step_proof_digest = history_arc_pcd_one_step_proof_digest(&one_step_proof)?;
        let recursive_head = Some(recursive_head);
        let recursive_head_digest = history_arc_pcd_recursive_head_digest(&recursive_head)?;
        let recursive_chunk_head = None;
        let recursive_chunk_head_digest =
            history_arc_pcd_recursive_chunk_head_digest(&recursive_chunk_head)?;
        Ok(Self {
            statement_digest: commitments.statement_digest,
            pcd_accumulator: pcd_accumulator.clone(),
            accumulator_commitment: commitments.accumulator_commitment,
            step_relation_commitment: commitments.step_relation_commitment,
            pcs_commitment: commitments.pcs_commitment,
            opening_digest: commitments.opening_digest,
            transcript_digest: commitments.transcript_digest,
            hash_proofs_digest,
            hash_proofs,
            one_step_proof_digest,
            one_step_proof,
            recursive_head_digest,
            recursive_head,
            recursive_chunk_head_digest,
            recursive_chunk_head,
            reserved: [[0u8; 32]; 1],
        })
    }

    pub(crate) fn arc_pcd_recursive_chunk_head_v1(
        statement: &HistoryDeciderStatement,
        pcd_accumulator: &HistoryArcPcdAccumulator,
        recursive_chunk_head: HistoryArcPcdRecursiveChunkChainHead,
    ) -> Result<Self, HistoryProofError> {
        let commitments = history_decider_commitments_v1(statement, pcd_accumulator)?;
        let hash_proofs = None;
        let hash_proofs_digest = history_decider_hash_proofs_digest(&hash_proofs)?;
        let one_step_proof = None;
        let one_step_proof_digest = history_arc_pcd_one_step_proof_digest(&one_step_proof)?;
        let recursive_head = None;
        let recursive_head_digest = history_arc_pcd_recursive_head_digest(&recursive_head)?;
        let recursive_chunk_head = Some(recursive_chunk_head);
        let recursive_chunk_head_digest =
            history_arc_pcd_recursive_chunk_head_digest(&recursive_chunk_head)?;
        Ok(Self {
            statement_digest: commitments.statement_digest,
            pcd_accumulator: pcd_accumulator.clone(),
            accumulator_commitment: commitments.accumulator_commitment,
            step_relation_commitment: commitments.step_relation_commitment,
            pcs_commitment: commitments.pcs_commitment,
            opening_digest: commitments.opening_digest,
            transcript_digest: commitments.transcript_digest,
            hash_proofs_digest,
            hash_proofs,
            one_step_proof_digest,
            one_step_proof,
            recursive_head_digest,
            recursive_head,
            recursive_chunk_head_digest,
            recursive_chunk_head,
            reserved: [[0u8; 32]; 1],
        })
    }
}

struct HistoryDeciderCommitments {
    statement_digest: Digest,
    pcd_accumulator_digest: Digest,
    accumulator_commitment: Digest,
    step_relation_commitment: Digest,
    pcs_commitment: Digest,
    opening_digest: Digest,
    transcript_digest: Digest,
}

fn history_decider_commitments_v1(
    statement: &HistoryDeciderStatement,
    pcd_accumulator: &HistoryArcPcdAccumulator,
) -> Result<HistoryDeciderCommitments, HistoryProofError> {
    if pcd_accumulator.version != HISTORY_PROOF_VERSION
        || pcd_accumulator.step_relation_digest != history_arc_pcd_step_relation_digest()
    {
        return Err(HistoryProofError::BadDeciderProof);
    }

    let statement_digest = history_decider_statement_digest(statement);
    let pcd_accumulator_digest = history_arc_pcd_accumulator_digest(pcd_accumulator);
    let accumulator_commitment = tagged_pair_digest(
        HISTACC1,
        &pcd_accumulator_digest,
        &statement.end_accumulator_digest,
    );
    let step_relation_commitment = tagged_pair_digest(
        HISTSTP1,
        &pcd_accumulator.step_relation_digest,
        &statement_digest,
    );
    let pcs_commitment = tagged_pair_digest(
        HISTPCS1,
        &pcd_accumulator.pcd_root,
        &pcd_accumulator.transcript_digest,
    );
    let opening_digest = tagged_pair_digest(HISTOPN1, &accumulator_commitment, &pcs_commitment);
    let transcript_digest = tagged_pair_digest(HISTDST1, &statement_digest, &opening_digest);

    Ok(HistoryDeciderCommitments {
        statement_digest,
        pcd_accumulator_digest,
        accumulator_commitment,
        step_relation_commitment,
        pcs_commitment,
        opening_digest,
        transcript_digest,
    })
}

impl HistoryDeciderHashProofs {
    #[allow(clippy::too_many_arguments)]
    fn prove(
        statement: &HistoryDeciderStatement,
        pcd_accumulator: &HistoryArcPcdAccumulator,
        pcd_accumulator_digest: &Digest,
        accumulator_commitment: &Digest,
        step_relation_commitment: &Digest,
        pcs_commitment: &Digest,
        opening_digest: &Digest,
        transcript_digest: &Digest,
    ) -> Result<Self, HistoryProofError> {
        let statement_digest = history_decider_statement_digest(statement);
        let arc_accumulator_hash = prove_fixed_hash(
            history_arc_pcd_accumulator_hash_params(),
            &history_arc_pcd_accumulator_hash_fields(pcd_accumulator),
            pcd_accumulator_digest,
        )?;
        let accumulator_commitment_hash_fields = history_tagged_pair_hash_fields(
            HISTACC1,
            pcd_accumulator_digest,
            &statement.end_accumulator_digest,
        );
        let step_relation_commitment_hash_fields = history_tagged_pair_hash_fields(
            HISTSTP1,
            &pcd_accumulator.step_relation_digest,
            &statement_digest,
        );
        let pcs_commitment_hash_fields = history_tagged_pair_hash_fields(
            HISTPCS1,
            &pcd_accumulator.pcd_root,
            &pcd_accumulator.transcript_digest,
        );
        let opening_digest_hash_fields =
            history_tagged_pair_hash_fields(HISTOPN1, accumulator_commitment, pcs_commitment);
        let transcript_digest_hash_fields =
            history_tagged_pair_hash_fields(HISTDST1, &statement_digest, opening_digest);
        let tagged_pair_hashes = prove_fixed_hash_batch(
            history_tagged_pair_hash_params(),
            &[
                (
                    accumulator_commitment_hash_fields.as_slice(),
                    accumulator_commitment,
                ),
                (
                    step_relation_commitment_hash_fields.as_slice(),
                    step_relation_commitment,
                ),
                (pcs_commitment_hash_fields.as_slice(), pcs_commitment),
                (opening_digest_hash_fields.as_slice(), opening_digest),
                (transcript_digest_hash_fields.as_slice(), transcript_digest),
            ],
        )?;

        Ok(Self {
            arc_accumulator_hash,
            tagged_pair_hashes,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HistoryAccumulationState {
    pub version: u32,
    pub height: u64,
    pub block_id: Digest,
    pub projection_root: Digest,
    pub accumulator: ChainAccumulator,
    pub folded_witness_root: Digest,
    pub step_count: u64,
}

impl HistoryAccumulationState {
    pub fn from_anchor(
        anchor: &HeaderChainAnchor,
        accumulator: ChainAccumulator,
    ) -> Result<Self, HistoryProofError> {
        if accumulator.height != anchor.height || accumulator.state_root != anchor.state_root {
            return Err(HistoryProofError::StartAccumulatorMismatch);
        }
        Ok(Self {
            version: HISTORY_PROOF_VERSION,
            height: anchor.height,
            block_id: anchor.block_id,
            projection_root: anchor.projection_root,
            accumulator,
            folded_witness_root: [0u8; 32],
            step_count: 0,
        })
    }

    pub fn byte_len(&self) -> usize {
        bincode::serialized_size(self)
            .expect("HistoryAccumulationState serialization is fixed-size")
            .try_into()
            .expect("serialized accumulation state length fits usize")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryProofWitness {
    pub items: Vec<HistoryTransitionWitnessItem>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HistoryStepStatement {
    pub version: u32,
    pub previous_block_id: Digest,
    pub next_block_id: Digest,
    pub previous_projection_root: Digest,
    pub next_projection_root: Digest,
    pub previous_accumulator: ChainAccumulator,
    pub next_accumulator: ChainAccumulator,
    pub header_projection_digest: Digest,
    pub claim_digest: Digest,
    pub folded_item_digest: Digest,
}

impl HistoryStepStatement {
    pub fn byte_len(&self) -> usize {
        bincode::serialized_size(self)
            .expect("HistoryStepStatement serialization is fixed-size")
            .try_into()
            .expect("serialized step statement length fits usize")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryStepProof {
    pub statement: HistoryStepStatement,
    pub claim_fields: [Block128; HISTORY_CLAIM_FIELDS],
    pub claim_hash: HistoryClaimHashProofKillShot,
}

impl HistoryStepProof {
    pub fn byte_len(&self) -> usize {
        self.statement.byte_len() + self.claim_fields.len() * 16 + self.claim_hash.byte_len()
    }
}

impl serde::Serialize for HistoryStepProof {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;

        let mut state = serializer.serialize_struct("HistoryStepProof", 3)?;
        state.serialize_field("statement", &self.statement)?;
        state.serialize_field("claim_fields", self.claim_fields.as_slice())?;
        state.serialize_field("claim_hash", &self.claim_hash)?;
        state.end()
    }
}

impl<'de> serde::Deserialize<'de> for HistoryStepProof {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        struct HistoryStepProofSerde {
            statement: HistoryStepStatement,
            claim_fields: Vec<Block128>,
            claim_hash: HistoryClaimHashProofKillShot,
        }

        let decoded = HistoryStepProofSerde::deserialize(deserializer)?;
        let claim_fields = decoded
            .claim_fields
            .try_into()
            .map_err(|fields: Vec<Block128>| {
                serde::de::Error::invalid_length(fields.len(), &"42 history claim fields")
            })?;
        Ok(Self {
            statement: decoded.statement,
            claim_fields,
            claim_hash: decoded.claim_hash,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HistoryPcdStepStatement {
    pub version: u32,
    pub previous_state: HistoryAccumulationState,
    pub step_statement: HistoryStepStatement,
    pub next_state: HistoryAccumulationState,
}

impl HistoryPcdStepStatement {
    pub fn byte_len(&self) -> usize {
        bincode::serialized_size(self)
            .expect("HistoryPcdStepStatement serialization is fixed-size")
            .try_into()
            .expect("serialized PCD step statement length fits usize")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryTransitionWitnessItem {
    pub header: BlockHeader,
    pub block_id: Digest,
    pub parent_state_root: Digest,
    pub child_state_root: Digest,
    pub claim_fields: [Block128; HISTORY_CLAIM_FIELDS],
    pub chain_claim: [Block128; 2],
    pub claim_digest: Digest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HistoryProofError {
    UnsupportedVersion { version: u32 },
    StartAnchorMismatch,
    EndAnchorMismatch,
    StartAccumulatorMismatch,
    EndAccumulatorMismatch,
    BadWitnessHeight { expected: u64, actual: u64 },
    BadWitnessParentBlock { height: u64 },
    BadWitnessParentState { height: u64 },
    BadWitnessChildState { height: u64 },
    BadWitnessClaimDigest { height: u64 },
    BadHeaderProjectionRoot,
    BadEndBlockId,
    BadStepVersion { version: u32 },
    BadStepClaimDigest,
    BadStepClaimFields,
    BadStepAccumulator,
    BadStepProjectionRoot,
    BadStepClaimHashProof,
    BadStepClaimHashDischarge,
    BadCheckpointPoseidon,
    BadStepCount,
    BadDeciderStatement,
    BadDeciderProof,
    BadDeciderHashProof,
    BadDeciderHashDischarge,
    BadPcdStepState,
    BackendNotTrustless,
    BackendVerifierMissing,
    BadProofDigest,
}

impl std::fmt::Display for HistoryProofError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedVersion { version } => {
                write!(f, "unsupported history proof version {version}")
            }
            Self::StartAnchorMismatch => write!(f, "history proof start anchor mismatch"),
            Self::EndAnchorMismatch => write!(f, "history proof end anchor mismatch"),
            Self::StartAccumulatorMismatch => {
                write!(f, "history proof start accumulator mismatch")
            }
            Self::EndAccumulatorMismatch => write!(f, "history proof end accumulator mismatch"),
            Self::BadWitnessHeight { expected, actual } => write!(
                f,
                "history witness height mismatch: expected {expected}, got {actual}"
            ),
            Self::BadWitnessParentBlock { height } => {
                write!(f, "history witness bad parent block link at h={height}")
            }
            Self::BadWitnessParentState { height } => {
                write!(f, "history witness bad parent state root at h={height}")
            }
            Self::BadWitnessChildState { height } => {
                write!(f, "history witness bad child state root at h={height}")
            }
            Self::BadWitnessClaimDigest { height } => {
                write!(f, "history witness bad claim digest at h={height}")
            }
            Self::BadHeaderProjectionRoot => {
                write!(f, "history witness bad header projection root")
            }
            Self::BadEndBlockId => write!(f, "history witness bad end block id"),
            Self::BadStepVersion { version } => {
                write!(f, "unsupported history step version {version}")
            }
            Self::BadStepClaimDigest => write!(f, "history step bad claim digest"),
            Self::BadStepClaimFields => write!(f, "history step bad claim fields"),
            Self::BadStepAccumulator => write!(f, "history step bad accumulator transition"),
            Self::BadStepProjectionRoot => write!(f, "history step bad projection root transition"),
            Self::BadStepClaimHashProof => write!(f, "history step bad claim hash proof"),
            Self::BadStepClaimHashDischarge => write!(f, "history step bad claim hash discharge"),
            Self::BadCheckpointPoseidon => write!(f, "history step bad checkpoint Poseidon proof"),
            Self::BadStepCount => write!(f, "history proof bad step count"),
            Self::BadDeciderStatement => write!(f, "history proof bad decider statement"),
            Self::BadDeciderProof => write!(f, "history proof bad decider proof"),
            Self::BadDeciderHashProof => write!(f, "history proof bad decider hash proof"),
            Self::BadDeciderHashDischarge => {
                write!(f, "history proof bad decider hash discharge")
            }
            Self::BadPcdStepState => write!(f, "history PCD step bad state transition"),
            Self::BackendNotTrustless => write!(f, "history proof backend is not trustless"),
            Self::BackendVerifierMissing => {
                write!(f, "history proof backend verifier is not implemented")
            }
            Self::BadProofDigest => write!(f, "history proof digest mismatch"),
        }
    }
}

impl std::error::Error for HistoryProofError {}

pub fn build_history_step_statement(
    previous_accumulator: &ChainAccumulator,
    previous_block_id: Digest,
    previous_projection_root: Digest,
    item: &HistoryTransitionWitnessItem,
) -> Result<HistoryStepStatement, HistoryProofError> {
    let expected_height = previous_accumulator.height.saturating_add(1);
    if item.header.height != expected_height {
        return Err(HistoryProofError::BadWitnessHeight {
            expected: expected_height,
            actual: item.header.height,
        });
    }
    if item.header.prev_block_hash != previous_block_id {
        return Err(HistoryProofError::BadWitnessParentBlock {
            height: item.header.height,
        });
    }
    if item.parent_state_root != previous_accumulator.state_root {
        return Err(HistoryProofError::BadWitnessParentState {
            height: item.header.height,
        });
    }
    if item.child_state_root != item.header.state_root {
        return Err(HistoryProofError::BadWitnessChildState {
            height: item.header.height,
        });
    }
    let claim_digest = history_claim_digest_from_fields(&item.claim_fields);
    if claim_digest != item.claim_digest || digest_to_fields(&claim_digest) != item.chain_claim {
        return Err(HistoryProofError::BadWitnessClaimDigest {
            height: item.header.height,
        });
    }

    let header_projection = header_projection_digest(&item.header, &item.block_id);
    let next_projection_root = extend_projection_root_from_digest(
        &previous_projection_root,
        &header_projection,
        item.header.height,
    );
    let next_accumulator = previous_accumulator.extend(
        item.child_state_root,
        item.block_id,
        item.header.height,
        item.chain_claim,
    );
    let folded_item_digest = history_transition_witness_item_digest(item, &header_projection);

    let statement = HistoryStepStatement {
        version: HISTORY_PROOF_VERSION,
        previous_block_id,
        next_block_id: item.block_id,
        previous_projection_root,
        next_projection_root,
        previous_accumulator: previous_accumulator.clone(),
        next_accumulator,
        header_projection_digest: header_projection,
        claim_digest,
        folded_item_digest,
    };
    verify_step_claim_fields(&statement, &item.claim_fields)?;
    Ok(statement)
}

pub fn prove_history_step_native(
    previous_accumulator: &ChainAccumulator,
    previous_block_id: Digest,
    previous_projection_root: Digest,
    item: &HistoryTransitionWitnessItem,
) -> Result<(HistoryStepProof, HistoryClaimHashReductions), HistoryProofError> {
    let statement = build_history_step_statement(
        previous_accumulator,
        previous_block_id,
        previous_projection_root,
        item,
    )?;
    let input = history_claim_hash_input(&item.claim_fields, &statement.claim_digest);
    let mut channel = noid_poseidon2b::channel::Poseidon2bChannel::new();
    let (claim_hash, reductions) =
        prove_history_claim_hash_killshot(std::slice::from_ref(&input), &mut channel);
    Ok((
        HistoryStepProof {
            statement,
            claim_fields: item.claim_fields,
            claim_hash,
        },
        reductions,
    ))
}

pub fn verify_history_step_native(
    proof: &HistoryStepProof,
) -> Result<HistoryClaimHashReductions, HistoryProofError> {
    let statement = &proof.statement;
    if statement.version != HISTORY_PROOF_VERSION {
        return Err(HistoryProofError::BadStepVersion {
            version: statement.version,
        });
    }

    let claim_digest = history_claim_digest_from_fields(&proof.claim_fields);
    if claim_digest != statement.claim_digest {
        return Err(HistoryProofError::BadStepClaimDigest);
    }
    verify_step_claim_fields(statement, &proof.claim_fields)?;
    let chain_claim = digest_to_fields(&claim_digest);
    if statement.next_accumulator.height != statement.previous_accumulator.height.saturating_add(1)
    {
        return Err(HistoryProofError::BadStepAccumulator);
    }
    let expected_next_accumulator = statement.previous_accumulator.extend(
        statement.next_accumulator.state_root,
        statement.next_block_id,
        statement.next_accumulator.height,
        chain_claim,
    );
    if expected_next_accumulator != statement.next_accumulator {
        return Err(HistoryProofError::BadStepAccumulator);
    }
    let expected_next_projection_root = extend_projection_root_from_digest(
        &statement.previous_projection_root,
        &statement.header_projection_digest,
        statement.next_accumulator.height,
    );
    if expected_next_projection_root != statement.next_projection_root {
        return Err(HistoryProofError::BadStepProjectionRoot);
    }

    let input = history_claim_hash_input(&proof.claim_fields, &statement.claim_digest);
    let mut channel = noid_poseidon2b::channel::Poseidon2bChannel::new();
    verify_history_claim_hash_killshot(
        &proof.claim_hash,
        std::slice::from_ref(&input),
        &mut channel,
    )
    .ok_or(HistoryProofError::BadStepClaimHashProof)
}

pub fn discharge_history_step_native(
    proof: &HistoryStepProof,
    reductions: &HistoryClaimHashReductions,
) -> Result<(), HistoryProofError> {
    let input = history_claim_hash_input(&proof.claim_fields, &proof.statement.claim_digest);
    if discharge_history_claim_hash_reductions_native(std::slice::from_ref(&input), reductions) {
        Ok(())
    } else {
        Err(HistoryProofError::BadStepClaimHashDischarge)
    }
}

pub fn build_history_pcd_step_statement_native(
    previous_state: &HistoryAccumulationState,
    proof: &HistoryStepProof,
    reductions: &HistoryClaimHashReductions,
) -> Result<HistoryPcdStepStatement, HistoryProofError> {
    let verified = verify_history_step_native(proof)?;
    if &verified != reductions {
        return Err(HistoryProofError::BadStepClaimHashProof);
    }
    discharge_history_step_native(proof, reductions)?;

    build_history_pcd_step_statement_from_step(previous_state, &proof.statement)
}

pub fn build_history_pcd_step_statement_from_step(
    previous_state: &HistoryAccumulationState,
    step: &HistoryStepStatement,
) -> Result<HistoryPcdStepStatement, HistoryProofError> {
    let next_state = next_state_from_step(previous_state, step)?;
    let statement = HistoryPcdStepStatement {
        version: HISTORY_PROOF_VERSION,
        previous_state: previous_state.clone(),
        step_statement: step.clone(),
        next_state,
    };
    Ok(statement)
}

pub fn verify_history_pcd_step_statement_shape(
    statement: &HistoryPcdStepStatement,
) -> Result<(), HistoryProofError> {
    if statement.version != HISTORY_PROOF_VERSION {
        return Err(HistoryProofError::UnsupportedVersion {
            version: statement.version,
        });
    }
    let expected_next = next_state_from_step(&statement.previous_state, &statement.step_statement)?;
    if expected_next != statement.next_state {
        return Err(HistoryProofError::BadPcdStepState);
    }
    Ok(())
}

pub fn history_pcd_step_statement_digest(statement: &HistoryPcdStepStatement) -> Digest {
    history_pcd_step_statement_digest_from_fields(&history_pcd_step_statement_fields(statement))
}

pub fn history_pcd_step_statement_digest_from_fields(
    fields: &[Block128; HISTORY_PCD_STEP_STATEMENT_FIELDS],
) -> Digest {
    history_pcd_step_statement_digest_from_hash_fields(
        &history_pcd_step_statement_hash_fields_from_fields(fields),
    )
}

pub fn history_pcd_step_statement_digest_from_hash_fields(
    fields: &[Block128; HISTORY_PCD_STEP_HASH_FIELDS],
) -> Digest {
    digest_fixed_no_pad_from_fields(fields)
}

pub fn history_arc_pcd_step_relation_digest() -> Digest {
    let mut sponge = Poseidon2bSponge::with_iv(capacity_iv(TAG_HISTPRF));
    sponge.absorb(Block128::from(0x4849_5354_5245_4C31u128)); // "HISTREL1"
    sponge.absorb(Block128::from(HISTORY_PROOF_VERSION as u128));
    sponge.absorb(Block128::from(HISTORY_CLAIM_FIELDS as u128));
    sponge.absorb(Block128::from(0x5043_445F_5354_4550u128)); // "PCD_STEP"
    sponge.finalize()
}

pub fn history_arc_pcd_accumulator_digest(accumulator: &HistoryArcPcdAccumulator) -> Digest {
    history_arc_pcd_accumulator_digest_from_fields(&history_arc_pcd_accumulator_fields(accumulator))
}

pub fn history_arc_pcd_accumulator_digest_from_fields(
    fields: &[Block128; HISTORY_ARC_PCD_ACCUMULATOR_FIELDS],
) -> Digest {
    history_arc_pcd_accumulator_digest_from_hash_fields(
        &history_arc_pcd_accumulator_hash_fields_from_fields(fields),
    )
}

pub fn history_arc_pcd_accumulator_digest_from_hash_fields(
    fields: &[Block128; HISTORY_ARC_PCD_ACCUMULATOR_HASH_FIELDS],
) -> Digest {
    digest_fixed_no_pad_from_fields(fields)
}

pub fn history_arc_pcd_recursive_step_statement_digest(
    statement: &HistoryArcPcdRecursiveStepStatement,
) -> Digest {
    history_arc_pcd_recursive_step_statement_digest_from_fields(
        &history_arc_pcd_recursive_step_statement_fields(statement),
    )
}

pub fn history_arc_pcd_recursive_step_statement_digest_from_fields(
    fields: &[Block128; HISTORY_ARC_PCD_RECURSIVE_STEP_FIELDS],
) -> Digest {
    history_arc_pcd_recursive_step_statement_digest_from_hash_fields(
        &history_arc_pcd_recursive_step_statement_hash_fields_from_fields(fields),
    )
}

pub fn history_arc_pcd_recursive_step_statement_digest_from_hash_fields(
    fields: &[Block128; HISTORY_ARC_PCD_RECURSIVE_STEP_HASH_FIELDS],
) -> Digest {
    digest_fixed_no_pad_from_fields(fields)
}

pub fn history_arc_pcd_recursive_chunk_step_statement_digest(
    statement: &HistoryArcPcdRecursiveChunkStepStatement,
) -> Digest {
    history_arc_pcd_recursive_chunk_step_statement_digest_from_fields(
        &history_arc_pcd_recursive_chunk_step_statement_fields(statement),
    )
}

pub fn history_arc_pcd_recursive_chunk_step_statement_digest_from_fields(
    fields: &[Block128; HISTORY_ARC_PCD_RECURSIVE_CHUNK_STEP_FIELDS],
) -> Digest {
    history_arc_pcd_recursive_chunk_step_statement_digest_from_hash_fields(
        &history_arc_pcd_recursive_chunk_step_statement_hash_fields_from_fields(fields),
    )
}

pub fn history_arc_pcd_recursive_chunk_step_statement_digest_from_hash_fields(
    fields: &[Block128; HISTORY_ARC_PCD_RECURSIVE_CHUNK_STEP_HASH_FIELDS],
) -> Digest {
    digest_fixed_no_pad_from_fields(fields)
}

pub fn history_accumulation_state_digest(state: &HistoryAccumulationState) -> Digest {
    history_accumulation_state_digest_from_fields(&history_accumulation_state_fields(state))
}

pub fn history_accumulation_state_digest_from_fields(
    fields: &[Block128; HISTORY_ACCUMULATION_STATE_FIELDS],
) -> Digest {
    history_accumulation_state_digest_from_hash_fields(
        &history_accumulation_state_hash_fields_from_fields(fields),
    )
}

pub fn history_accumulation_state_digest_from_hash_fields(
    fields: &[Block128; HISTORY_ACCUMULATION_STATE_HASH_FIELDS],
) -> Digest {
    digest_fixed_no_pad_from_fields(fields)
}

pub fn history_accumulation_state_hash_params() -> FixedFieldHashParams {
    FixedFieldHashParams::with_default_relation_tag(
        TAG_HISTPRF,
        HISTORY_ACCUMULATION_STATE_HASH_FIELDS,
    )
    .expect("history accumulation state hash schedule is valid")
}

pub fn history_pcd_step_hash_params() -> FixedFieldHashParams {
    FixedFieldHashParams::with_default_relation_tag(TAG_HISTPRF, HISTORY_PCD_STEP_HASH_FIELDS)
        .expect("history PCD step hash schedule is valid")
}

pub fn history_arc_pcd_accumulator_hash_params() -> FixedFieldHashParams {
    FixedFieldHashParams::with_default_relation_tag(
        TAG_HISTPRF,
        HISTORY_ARC_PCD_ACCUMULATOR_HASH_FIELDS,
    )
    .expect("history ARC accumulator hash schedule is valid")
}

pub fn history_arc_pcd_recursive_step_hash_params() -> FixedFieldHashParams {
    FixedFieldHashParams::with_default_relation_tag(
        TAG_HISTPRF,
        HISTORY_ARC_PCD_RECURSIVE_STEP_HASH_FIELDS,
    )
    .expect("history ARC recursive step hash schedule is valid")
}

pub fn history_arc_pcd_recursive_chunk_step_hash_params() -> FixedFieldHashParams {
    FixedFieldHashParams::with_default_relation_tag(
        TAG_HISTPRF,
        HISTORY_ARC_PCD_RECURSIVE_CHUNK_STEP_HASH_FIELDS,
    )
    .expect("history ARC recursive chunk step hash schedule is valid")
}

pub fn history_tagged_pair_hash_params() -> FixedFieldHashParams {
    FixedFieldHashParams::with_default_relation_tag(TAG_HISTPRF, HISTORY_TAGGED_PAIR_HASH_FIELDS)
        .expect("history tagged-pair hash schedule is valid")
}

pub fn advance_history_arc_pcd_accumulator_native(
    accumulator: &HistoryArcPcdAccumulator,
    statement: &HistoryPcdStepStatement,
) -> Result<HistoryArcPcdAccumulator, HistoryProofError> {
    verify_history_pcd_step_statement_shape(statement)?;
    advance_history_arc_pcd_accumulator_verified(accumulator, statement, true)
}

pub fn prove_history_arc_pcd_step_native(
    accumulator: &HistoryArcPcdAccumulator,
    statement: &HistoryPcdStepStatement,
) -> Result<(HistoryArcPcdAccumulator, HistoryArcPcdStepProof), HistoryProofError> {
    verify_history_pcd_step_statement_shape(statement)?;
    let next_accumulator =
        advance_history_arc_pcd_accumulator_verified(accumulator, statement, true)?;
    let previous_state_hash_fields =
        history_accumulation_state_hash_fields(&statement.previous_state);
    let next_state_hash_fields = history_accumulation_state_hash_fields(&statement.next_state);
    let state_hashes = prove_fixed_hash_batch(
        history_accumulation_state_hash_params(),
        &[
            (
                previous_state_hash_fields.as_slice(),
                &accumulator.current_state_digest,
            ),
            (
                next_state_hash_fields.as_slice(),
                &next_accumulator.current_state_digest,
            ),
        ],
    )?;
    let step_digest = history_pcd_step_statement_digest(statement);
    let pcd_step_hash = prove_fixed_hash(
        history_pcd_step_hash_params(),
        &history_pcd_step_statement_hash_fields(statement),
        &step_digest,
    )?;
    let pcd_root_hash_fields =
        history_tagged_pair_hash_fields(HISTARA1, &accumulator.pcd_root, &step_digest);
    let transcript_hash_fields =
        history_tagged_pair_hash_fields(HISTART1, &accumulator.transcript_digest, &step_digest);
    let accumulator_update_hashes = prove_fixed_hash_batch(
        history_tagged_pair_hash_params(),
        &[
            (pcd_root_hash_fields.as_slice(), &next_accumulator.pcd_root),
            (
                transcript_hash_fields.as_slice(),
                &next_accumulator.transcript_digest,
            ),
        ],
    )?;
    Ok((
        next_accumulator,
        HistoryArcPcdStepProof {
            state_hashes,
            pcd_step_hash,
            accumulator_update_hashes,
        },
    ))
}

pub fn verify_history_arc_pcd_step_proof_native(
    accumulator: &HistoryArcPcdAccumulator,
    statement: &HistoryPcdStepStatement,
    next_accumulator: &HistoryArcPcdAccumulator,
    proof: &HistoryArcPcdStepProof,
) -> Result<(), HistoryProofError> {
    verify_history_pcd_step_statement_shape(statement)?;
    let expected_next = advance_history_arc_pcd_accumulator_verified(accumulator, statement, true)?;
    if &expected_next != next_accumulator {
        return Err(HistoryProofError::BadPcdStepState);
    }
    let previous_state_hash_fields =
        history_accumulation_state_hash_fields(&statement.previous_state);
    let next_state_hash_fields = history_accumulation_state_hash_fields(&statement.next_state);
    verify_and_discharge_fixed_hash_batch(
        history_accumulation_state_hash_params(),
        &proof.state_hashes,
        &[
            (
                previous_state_hash_fields.as_slice(),
                &accumulator.current_state_digest,
            ),
            (
                next_state_hash_fields.as_slice(),
                &next_accumulator.current_state_digest,
            ),
        ],
    )?;
    let step_digest = history_pcd_step_statement_digest(statement);
    verify_and_discharge_fixed_hash(
        history_pcd_step_hash_params(),
        &proof.pcd_step_hash,
        &history_pcd_step_statement_hash_fields(statement),
        &step_digest,
    )?;
    let pcd_root_hash_fields =
        history_tagged_pair_hash_fields(HISTARA1, &accumulator.pcd_root, &step_digest);
    let transcript_hash_fields =
        history_tagged_pair_hash_fields(HISTART1, &accumulator.transcript_digest, &step_digest);
    verify_and_discharge_fixed_hash_batch(
        history_tagged_pair_hash_params(),
        &proof.accumulator_update_hashes,
        &[
            (pcd_root_hash_fields.as_slice(), &next_accumulator.pcd_root),
            (
                transcript_hash_fields.as_slice(),
                &next_accumulator.transcript_digest,
            ),
        ],
    )?;
    Ok(())
}

type OwnedFixedHashInput = (Vec<Block128>, Digest);

#[allow(clippy::type_complexity)]
fn build_history_arc_pcd_chunk_step_inputs(
    accumulator: &HistoryArcPcdAccumulator,
    previous_state: &HistoryAccumulationState,
    items: &[HistoryTransitionWitnessItem],
) -> Result<
    (
        HistoryAccumulationState,
        HistoryArcPcdAccumulator,
        Vec<HistoryClaimHashInputs>,
        Vec<OwnedFixedHashInput>,
        Vec<OwnedFixedHashInput>,
        Vec<OwnedFixedHashInput>,
    ),
    HistoryProofError,
> {
    if items.is_empty() || items.len() > HISTORY_ARC_PCD_CHUNK_MAX_STEPS {
        return Err(HistoryProofError::BadStepCount);
    }
    validate_accumulation_state_shape(previous_state)?;
    if accumulator.step_count != previous_state.step_count {
        return Err(HistoryProofError::BadStepCount);
    }

    let mut state = previous_state.clone();
    let mut arc_accumulator = accumulator.clone();
    let mut claim_inputs = Vec::with_capacity(HISTORY_ARC_PCD_CHUNK_MAX_STEPS);
    let mut state_hash_inputs = Vec::with_capacity(HISTORY_ARC_PCD_CHUNK_MAX_STEPS * 2);
    let mut pcd_step_hash_inputs = Vec::with_capacity(HISTORY_ARC_PCD_CHUNK_MAX_STEPS);
    let mut accumulator_update_hash_inputs =
        Vec::with_capacity(HISTORY_ARC_PCD_CHUNK_MAX_STEPS * 2);

    for item in items {
        let step = build_history_step_statement(
            &state.accumulator,
            state.block_id,
            state.projection_root,
            item,
        )?;
        claim_inputs.push(history_claim_hash_input(
            &item.claim_fields,
            &step.claim_digest,
        ));

        let pcd_step = build_history_pcd_step_statement_from_step(&state, &step)?;
        let next_accumulator =
            advance_history_arc_pcd_accumulator_native(&arc_accumulator, &pcd_step)?;
        let step_digest = history_pcd_step_statement_digest(&pcd_step);

        state_hash_inputs.push((
            history_accumulation_state_hash_fields(&pcd_step.previous_state).to_vec(),
            arc_accumulator.current_state_digest,
        ));
        state_hash_inputs.push((
            history_accumulation_state_hash_fields(&pcd_step.next_state).to_vec(),
            next_accumulator.current_state_digest,
        ));
        pcd_step_hash_inputs.push((
            history_pcd_step_statement_hash_fields(&pcd_step).to_vec(),
            step_digest,
        ));
        accumulator_update_hash_inputs.push((
            history_tagged_pair_hash_fields(HISTARA1, &arc_accumulator.pcd_root, &step_digest)
                .to_vec(),
            next_accumulator.pcd_root,
        ));
        accumulator_update_hash_inputs.push((
            history_tagged_pair_hash_fields(
                HISTART1,
                &arc_accumulator.transcript_digest,
                &step_digest,
            )
            .to_vec(),
            next_accumulator.transcript_digest,
        ));

        state = pcd_step.next_state;
        arc_accumulator = next_accumulator;
    }

    let padding_steps = HISTORY_ARC_PCD_CHUNK_MAX_STEPS - items.len();
    if padding_steps > 0 {
        let zero_claim_fields = [Block128::ZERO; HISTORY_CLAIM_FIELDS];
        let zero_claim_digest = history_claim_digest_from_fields(&zero_claim_fields);
        let zero_state_fields = vec![Block128::ZERO; HISTORY_ACCUMULATION_STATE_HASH_FIELDS];
        let zero_state_digest = digest_fixed_no_pad_from_fields(&zero_state_fields);
        let zero_pcd_fields = vec![Block128::ZERO; HISTORY_PCD_STEP_HASH_FIELDS];
        let zero_pcd_digest = digest_fixed_no_pad_from_fields(&zero_pcd_fields);
        let zero_pair_fields = vec![Block128::ZERO; HISTORY_TAGGED_PAIR_HASH_FIELDS];
        let zero_pair_digest = digest_fixed_no_pad_from_fields(&zero_pair_fields);

        for _ in 0..padding_steps {
            claim_inputs.push(history_claim_hash_input(
                &zero_claim_fields,
                &zero_claim_digest,
            ));
            state_hash_inputs.push((zero_state_fields.clone(), zero_state_digest));
            state_hash_inputs.push((zero_state_fields.clone(), zero_state_digest));
            pcd_step_hash_inputs.push((zero_pcd_fields.clone(), zero_pcd_digest));
            accumulator_update_hash_inputs.push((zero_pair_fields.clone(), zero_pair_digest));
            accumulator_update_hash_inputs.push((zero_pair_fields.clone(), zero_pair_digest));
        }
    }

    Ok((
        state,
        arc_accumulator,
        claim_inputs,
        state_hash_inputs,
        pcd_step_hash_inputs,
        accumulator_update_hash_inputs,
    ))
}

fn fixed_hash_input_refs(inputs: &[OwnedFixedHashInput]) -> Vec<(&[Block128], &Digest)> {
    inputs
        .iter()
        .map(|(fields, digest)| (fields.as_slice(), digest))
        .collect()
}

fn map_checkpoint_poseidon_error(_: CheckpointPoseidonError) -> HistoryProofError {
    HistoryProofError::BadCheckpointPoseidon
}

fn accepted_claim_batch_witness_from_history_items(
    items: &[HistoryTransitionWitnessItem],
) -> AcceptedClaimBatchWitness {
    AcceptedClaimBatchWitness {
        headers: items
            .iter()
            .map(|item| HeaderWitness::from_header(&item.header))
            .collect(),
        accepted_block_claims: items.iter().map(|item| item.chain_claim).collect(),
    }
}

fn verify_checkpoint_poseidon_for_history_items(
    start_accumulator: &ChainAccumulator,
    end_accumulator: &ChainAccumulator,
    items: &[HistoryTransitionWitnessItem],
    proof: &CheckpointPoseidonProof,
) -> Result<AcceptedClaimBatchWitness, HistoryProofError> {
    let accepted_witness = accepted_claim_batch_witness_from_history_items(items);
    verify_checkpoint_poseidon_padded(
        start_accumulator,
        end_accumulator,
        &accepted_witness,
        proof,
        HISTORY_ARC_PCD_CHUNK_MAX_STEPS,
    )
    .map_err(map_checkpoint_poseidon_error)?;
    Ok(accepted_witness)
}

fn checkpoint_poseidon_verifier_traces(
    start_accumulator: &ChainAccumulator,
    end_accumulator: &ChainAccumulator,
    accepted_witness: &AcceptedClaimBatchWitness,
    proof: &CheckpointPoseidonProof,
) -> Result<Vec<Vec<FiatShamirTraceOp>>, HistoryProofError> {
    verify_checkpoint_poseidon_padded(
        start_accumulator,
        end_accumulator,
        accepted_witness,
        proof,
        HISTORY_ARC_PCD_CHUNK_MAX_STEPS,
    )
    .map_err(map_checkpoint_poseidon_error)?;

    let header_inputs = header_hash_proof_inputs(&accepted_witness.headers);
    let chain_inputs =
        chain_accumulator_proof_inputs(start_accumulator, accepted_witness, end_accumulator);
    let mut traces = Vec::with_capacity(2);

    let mut header_channel = HistoryTracingPoseidon2bChannel::new();
    let header_reductions = verify_header_hash_killshot_padded(
        &proof.header_hash,
        &header_inputs,
        HISTORY_ARC_PCD_CHUNK_MAX_STEPS,
        &mut header_channel,
    )
    .ok_or(HistoryProofError::BadCheckpointPoseidon)?;
    if !discharge_header_hash_reductions_native_padded(
        &header_inputs,
        &header_reductions,
        HISTORY_ARC_PCD_CHUNK_MAX_STEPS,
    ) {
        return Err(HistoryProofError::BadCheckpointPoseidon);
    }
    traces.push(header_channel.into_transcript());

    let mut chain_channel = HistoryTracingPoseidon2bChannel::new();
    let chain_reductions = verify_chain_accumulator_killshot_padded(
        &proof.chain_accumulator,
        &chain_inputs,
        HISTORY_ARC_PCD_CHUNK_MAX_STEPS,
        &mut chain_channel,
    )
    .ok_or(HistoryProofError::BadCheckpointPoseidon)?;
    if !discharge_chain_accumulator_reductions_native_padded(
        &chain_inputs,
        &chain_reductions,
        HISTORY_ARC_PCD_CHUNK_MAX_STEPS,
    ) {
        return Err(HistoryProofError::BadCheckpointPoseidon);
    }
    traces.push(chain_channel.into_transcript());

    Ok(traces)
}

pub fn prove_history_arc_pcd_chunk_step_native(
    accumulator: &HistoryArcPcdAccumulator,
    previous_state: &HistoryAccumulationState,
    items: &[HistoryTransitionWitnessItem],
) -> Result<
    (
        HistoryAccumulationState,
        HistoryArcPcdAccumulator,
        HistoryArcPcdChunkStepProof,
    ),
    HistoryProofError,
> {
    let (
        next_state,
        next_accumulator,
        claim_inputs,
        state_hash_inputs,
        pcd_step_hash_inputs,
        accumulator_update_hash_inputs,
    ) = build_history_arc_pcd_chunk_step_inputs(accumulator, previous_state, items)?;

    let accepted_witness = accepted_claim_batch_witness_from_history_items(items);
    let checkpoint_poseidon = prove_checkpoint_poseidon_padded(
        &previous_state.accumulator,
        &next_state.accumulator,
        &accepted_witness,
        HISTORY_ARC_PCD_CHUNK_MAX_STEPS,
    )
    .map_err(map_checkpoint_poseidon_error)?;

    let mut channel = noid_poseidon2b::channel::Poseidon2bChannel::new();
    let (claim_hash, claim_reductions) =
        prove_history_claim_hash_killshot(&claim_inputs, &mut channel);
    if !discharge_history_claim_hash_reductions_native(&claim_inputs, &claim_reductions) {
        return Err(HistoryProofError::BadStepClaimHashDischarge);
    }

    let state_hash_refs = fixed_hash_input_refs(&state_hash_inputs);
    let pcd_step_hash_refs = fixed_hash_input_refs(&pcd_step_hash_inputs);
    let accumulator_update_hash_refs = fixed_hash_input_refs(&accumulator_update_hash_inputs);
    let state_hashes =
        prove_fixed_hash_batch(history_accumulation_state_hash_params(), &state_hash_refs)?;
    let pcd_step_hashes =
        prove_fixed_hash_batch(history_pcd_step_hash_params(), &pcd_step_hash_refs)?;
    let accumulator_update_hashes = prove_fixed_hash_batch(
        history_tagged_pair_hash_params(),
        &accumulator_update_hash_refs,
    )?;

    Ok((
        next_state,
        next_accumulator,
        HistoryArcPcdChunkStepProof {
            chunk_len: items.len() as u32,
            checkpoint_poseidon,
            claim_hash,
            state_hashes,
            pcd_step_hashes,
            accumulator_update_hashes,
        },
    ))
}

pub fn verify_history_arc_pcd_chunk_step_proof_native(
    accumulator: &HistoryArcPcdAccumulator,
    previous_state: &HistoryAccumulationState,
    items: &[HistoryTransitionWitnessItem],
    proof: &HistoryArcPcdChunkStepProof,
) -> Result<(HistoryAccumulationState, HistoryArcPcdAccumulator), HistoryProofError> {
    if proof.chunk_len as usize != items.len() {
        return Err(HistoryProofError::BadStepCount);
    }
    let (
        next_state,
        next_accumulator,
        claim_inputs,
        state_hash_inputs,
        pcd_step_hash_inputs,
        accumulator_update_hash_inputs,
    ) = build_history_arc_pcd_chunk_step_inputs(accumulator, previous_state, items)?;

    verify_checkpoint_poseidon_for_history_items(
        &previous_state.accumulator,
        &next_state.accumulator,
        items,
        &proof.checkpoint_poseidon,
    )?;

    let mut channel = noid_poseidon2b::channel::Poseidon2bChannel::new();
    let claim_reductions =
        verify_history_claim_hash_killshot(&proof.claim_hash, &claim_inputs, &mut channel)
            .ok_or(HistoryProofError::BadStepClaimHashProof)?;
    if !discharge_history_claim_hash_reductions_native(&claim_inputs, &claim_reductions) {
        return Err(HistoryProofError::BadStepClaimHashDischarge);
    }

    let state_hash_refs = fixed_hash_input_refs(&state_hash_inputs);
    let pcd_step_hash_refs = fixed_hash_input_refs(&pcd_step_hash_inputs);
    let accumulator_update_hash_refs = fixed_hash_input_refs(&accumulator_update_hash_inputs);
    verify_and_discharge_fixed_hash_batch(
        history_accumulation_state_hash_params(),
        &proof.state_hashes,
        &state_hash_refs,
    )?;
    verify_and_discharge_fixed_hash_batch(
        history_pcd_step_hash_params(),
        &proof.pcd_step_hashes,
        &pcd_step_hash_refs,
    )?;
    verify_and_discharge_fixed_hash_batch(
        history_tagged_pair_hash_params(),
        &proof.accumulator_update_hashes,
        &accumulator_update_hash_refs,
    )?;

    Ok((next_state, next_accumulator))
}

pub fn history_arc_pcd_chunk_step_verifier_traces(
    accumulator: &HistoryArcPcdAccumulator,
    previous_state: &HistoryAccumulationState,
    items: &[HistoryTransitionWitnessItem],
    proof: &HistoryArcPcdChunkStepProof,
) -> Result<Vec<Vec<FiatShamirTraceOp>>, HistoryProofError> {
    if proof.chunk_len as usize != items.len() {
        return Err(HistoryProofError::BadStepCount);
    }
    let (
        next_state,
        _next_accumulator,
        claim_inputs,
        state_hash_inputs,
        pcd_step_hash_inputs,
        accumulator_update_hash_inputs,
    ) = build_history_arc_pcd_chunk_step_inputs(accumulator, previous_state, items)?;

    let accepted_witness = verify_checkpoint_poseidon_for_history_items(
        &previous_state.accumulator,
        &next_state.accumulator,
        items,
        &proof.checkpoint_poseidon,
    )?;
    let mut traces = checkpoint_poseidon_verifier_traces(
        &previous_state.accumulator,
        &next_state.accumulator,
        &accepted_witness,
        &proof.checkpoint_poseidon,
    )?;
    traces.reserve(4);

    let mut channel = HistoryTracingPoseidon2bChannel::new();
    let claim_reductions =
        verify_history_claim_hash_killshot(&proof.claim_hash, &claim_inputs, &mut channel)
            .ok_or(HistoryProofError::BadStepClaimHashProof)?;
    if !discharge_history_claim_hash_reductions_native(&claim_inputs, &claim_reductions) {
        return Err(HistoryProofError::BadStepClaimHashDischarge);
    }
    traces.push(channel.into_transcript());

    let state_hash_refs = fixed_hash_input_refs(&state_hash_inputs);
    traces.push(verify_and_discharge_fixed_hash_batch_with_trace(
        history_accumulation_state_hash_params(),
        &proof.state_hashes,
        &state_hash_refs,
    )?);

    let pcd_step_hash_refs = fixed_hash_input_refs(&pcd_step_hash_inputs);
    traces.push(verify_and_discharge_fixed_hash_batch_with_trace(
        history_pcd_step_hash_params(),
        &proof.pcd_step_hashes,
        &pcd_step_hash_refs,
    )?);

    let accumulator_update_hash_refs = fixed_hash_input_refs(&accumulator_update_hash_inputs);
    traces.push(verify_and_discharge_fixed_hash_batch_with_trace(
        history_tagged_pair_hash_params(),
        &proof.accumulator_update_hashes,
        &accumulator_update_hash_refs,
    )?);

    Ok(traces)
}

pub fn prove_history_arc_pcd_chunk_step_verifier_transcript_batch_native(
    accumulator: &HistoryArcPcdAccumulator,
    previous_state: &HistoryAccumulationState,
    items: &[HistoryTransitionWitnessItem],
    proof: &HistoryArcPcdChunkStepProof,
) -> Result<
    (
        FiatShamirTranscriptBatchProofKillShot,
        FiatShamirTranscriptReductions,
    ),
    HistoryProofError,
> {
    let traces =
        history_arc_pcd_chunk_step_verifier_traces(accumulator, previous_state, items, proof)?;
    let mut channel = noid_poseidon2b::channel::Poseidon2bChannel::new();
    prove_fiat_shamir_transcript_batch_killshot(&traces, &mut channel)
        .map_err(map_fs_transcript_error)
}

pub fn history_arc_pcd_one_step_component_digest(
    proof: &HistoryArcPcdOneStepProof,
) -> Result<Digest, HistoryProofError> {
    Ok(canonical_digest(HISTOSD1, |sponge| {
        absorb_history_arc_pcd_one_step_proof(sponge, proof);
    }))
}

pub fn history_arc_pcd_chunk_step_component_digest(
    proof: &HistoryArcPcdChunkStepProof,
) -> Result<Digest, HistoryProofError> {
    Ok(canonical_digest(HISTCSD1, |sponge| {
        absorb_history_arc_pcd_chunk_step_proof(sponge, proof);
    }))
}

pub fn history_arc_pcd_recursive_base_digest(
    start_state: &HistoryAccumulationState,
    start_accumulator: &HistoryArcPcdAccumulator,
) -> Result<Digest, HistoryProofError> {
    validate_accumulation_state_shape(start_state)?;
    let start_state_digest = history_accumulation_state_digest(start_state);
    if start_accumulator.version != HISTORY_PROOF_VERSION
        || start_accumulator.step_count != start_state.step_count
        || start_accumulator.start_state_digest != start_state_digest
        || start_accumulator.current_state_digest != start_state_digest
        || start_accumulator.pcd_root != [0u8; 32]
        || start_accumulator.step_relation_digest != history_arc_pcd_step_relation_digest()
    {
        return Err(HistoryProofError::BadPcdStepState);
    }

    let mut sponge = Poseidon2bSponge::with_iv(capacity_iv(TAG_HISTPRF));
    sponge.absorb(Block128::from(HISTRCB1));
    sponge.absorb(Block128::from(HISTORY_PROOF_VERSION as u128));
    absorb_digest(&mut sponge, &start_state_digest);
    absorb_digest(
        &mut sponge,
        &history_arc_pcd_accumulator_digest(start_accumulator),
    );
    Ok(sponge.finalize())
}

pub fn build_history_arc_pcd_recursive_step_statement(
    previous_proof_digest: Digest,
    previous_accumulator: &HistoryArcPcdAccumulator,
    previous_state: &HistoryAccumulationState,
    one_step: &HistoryArcPcdOneStepProof,
) -> Result<
    (
        HistoryArcPcdRecursiveStepStatement,
        HistoryAccumulationState,
        HistoryArcPcdAccumulator,
        Digest,
    ),
    HistoryProofError,
> {
    let reductions = verify_history_step_native(&one_step.step)?;
    discharge_history_step_native(&one_step.step, &reductions)?;
    let pcd_step =
        build_history_pcd_step_statement_native(previous_state, &one_step.step, &reductions)?;
    let next_state = pcd_step.next_state.clone();
    let next_accumulator =
        advance_history_arc_pcd_accumulator_native(previous_accumulator, &pcd_step)?;
    verify_history_arc_pcd_step_proof_native(
        previous_accumulator,
        &pcd_step,
        &next_accumulator,
        &one_step.arc_step,
    )?;

    let (statement, next_proof_digest) = build_history_arc_pcd_recursive_step_statement_from_parts(
        previous_proof_digest,
        previous_accumulator,
        &pcd_step,
        one_step,
        &next_accumulator,
    )?;
    Ok((statement, next_state, next_accumulator, next_proof_digest))
}

fn build_history_arc_pcd_recursive_step_statement_from_parts(
    previous_proof_digest: Digest,
    previous_accumulator: &HistoryArcPcdAccumulator,
    pcd_step: &HistoryPcdStepStatement,
    one_step: &HistoryArcPcdOneStepProof,
    next_accumulator: &HistoryArcPcdAccumulator,
) -> Result<(HistoryArcPcdRecursiveStepStatement, Digest), HistoryProofError> {
    let statement = HistoryArcPcdRecursiveStepStatement {
        version: HISTORY_PROOF_VERSION,
        step_count: next_accumulator.step_count,
        previous_proof_digest,
        previous_accumulator_digest: history_arc_pcd_accumulator_digest(previous_accumulator),
        pcd_step_digest: history_pcd_step_statement_digest(pcd_step),
        one_step_proof_digest: history_arc_pcd_one_step_component_digest(one_step)?,
        next_accumulator_digest: history_arc_pcd_accumulator_digest(next_accumulator),
    };
    let statement_digest = history_arc_pcd_recursive_step_statement_digest(&statement);
    let next_proof_digest = tagged_pair_digest(HISTRCN1, &previous_proof_digest, &statement_digest);
    Ok((statement, next_proof_digest))
}

pub fn prove_history_arc_pcd_recursive_chain_head_native(
    start_anchor: HeaderChainAnchor,
    end_anchor: HeaderChainAnchor,
    start_accumulator: ChainAccumulator,
    witness: &HistoryProofWitness,
) -> Result<
    (
        HistoryAccumulationState,
        HistoryArcPcdAccumulator,
        HistoryArcPcdRecursiveChainHead,
    ),
    HistoryProofError,
> {
    if witness.items.is_empty() {
        return Err(HistoryProofError::BadStepCount);
    }
    if start_accumulator.height != start_anchor.height
        || start_accumulator.state_root != start_anchor.state_root
    {
        return Err(HistoryProofError::StartAccumulatorMismatch);
    }

    let start_state =
        HistoryAccumulationState::from_anchor(&start_anchor, start_accumulator.clone())?;
    let mut state = start_state.clone();
    let mut arc_accumulator = HistoryArcPcdAccumulator::from_start_state(&start_state)?;
    let base_proof_digest = history_arc_pcd_recursive_base_digest(&state, &arc_accumulator)?;
    let mut previous_proof_digest = base_proof_digest;
    let mut head = None;

    for item in &witness.items {
        let (next_state, next_accumulator, next_head) =
            prove_history_arc_pcd_recursive_chain_head_step_native(
                base_proof_digest,
                previous_proof_digest,
                &arc_accumulator,
                &state,
                item,
            )?;
        previous_proof_digest = next_head.final_proof_digest;
        head = Some(next_head);
        arc_accumulator = next_accumulator;
        state = next_state;
    }

    if state.height != end_anchor.height || state.accumulator.state_root != end_anchor.state_root {
        return Err(HistoryProofError::EndAccumulatorMismatch);
    }
    if state.projection_root != end_anchor.projection_root {
        return Err(HistoryProofError::BadHeaderProjectionRoot);
    }
    if state.block_id != end_anchor.block_id {
        return Err(HistoryProofError::BadEndBlockId);
    }

    Ok((
        state,
        arc_accumulator,
        head.expect("non-empty witness produced a recursive chain head"),
    ))
}

pub fn prove_history_arc_pcd_recursive_chain_head_step_native(
    base_proof_digest: Digest,
    previous_proof_digest: Digest,
    previous_accumulator: &HistoryArcPcdAccumulator,
    previous_state: &HistoryAccumulationState,
    item: &HistoryTransitionWitnessItem,
) -> Result<
    (
        HistoryAccumulationState,
        HistoryArcPcdAccumulator,
        HistoryArcPcdRecursiveChainHead,
    ),
    HistoryProofError,
> {
    validate_accumulation_state_shape(previous_state)?;
    if previous_accumulator.step_count != previous_state.step_count {
        return Err(HistoryProofError::BadStepCount);
    }

    let (step, reductions) = prove_history_step_native(
        &previous_state.accumulator,
        previous_state.block_id,
        previous_state.projection_root,
        item,
    )?;
    let pcd_step = build_history_pcd_step_statement_native(previous_state, &step, &reductions)?;
    let (next_accumulator, arc_step) =
        prove_history_arc_pcd_step_native(previous_accumulator, &pcd_step)?;
    let one_step = HistoryArcPcdOneStepProof { step, arc_step };
    let next_state = pcd_step.next_state.clone();
    let (statement, expected_next_digest) =
        build_history_arc_pcd_recursive_step_statement_from_parts(
            previous_proof_digest,
            previous_accumulator,
            &pcd_step,
            &one_step,
            &next_accumulator,
        )?;
    let (next_proof_digest, final_step_proof) = prove_history_arc_pcd_recursive_step_native(
        &statement,
        previous_accumulator,
        &next_accumulator,
    )?;
    if next_proof_digest != expected_next_digest {
        return Err(HistoryProofError::BadDeciderProof);
    }

    Ok((
        next_state,
        next_accumulator.clone(),
        HistoryArcPcdRecursiveChainHead {
            version: HISTORY_PROOF_VERSION,
            step_count: next_accumulator.step_count,
            base_proof_digest,
            final_proof_digest: next_proof_digest,
            previous_accumulator: previous_accumulator.clone(),
            final_step_statement: statement,
            final_step_proof,
        },
    ))
}

pub fn prove_history_arc_pcd_recursive_step_native(
    statement: &HistoryArcPcdRecursiveStepStatement,
    previous_accumulator: &HistoryArcPcdAccumulator,
    next_accumulator: &HistoryArcPcdAccumulator,
) -> Result<(Digest, HistoryArcPcdRecursiveStepProof), HistoryProofError> {
    verify_history_arc_pcd_recursive_step_statement_shape(
        statement,
        previous_accumulator,
        next_accumulator,
    )?;
    let statement_digest = history_arc_pcd_recursive_step_statement_digest(statement);
    let next_proof_digest = tagged_pair_digest(
        HISTRCN1,
        &statement.previous_proof_digest,
        &statement_digest,
    );
    let statement_hash_fields = history_arc_pcd_recursive_step_statement_hash_fields(statement);
    let previous_accumulator_hash_fields =
        history_arc_pcd_accumulator_hash_fields(previous_accumulator);
    let next_accumulator_hash_fields = history_arc_pcd_accumulator_hash_fields(next_accumulator);
    let recursive_hashes = prove_fixed_hash_batch(
        history_arc_pcd_recursive_step_hash_params(),
        &[
            (statement_hash_fields.as_slice(), &statement_digest),
            (
                previous_accumulator_hash_fields.as_slice(),
                &statement.previous_accumulator_digest,
            ),
            (
                next_accumulator_hash_fields.as_slice(),
                &statement.next_accumulator_digest,
            ),
        ],
    )?;
    let next_proof_digest_hash = prove_fixed_hash(
        history_tagged_pair_hash_params(),
        &history_tagged_pair_hash_fields(
            HISTRCN1,
            &statement.previous_proof_digest,
            &statement_digest,
        ),
        &next_proof_digest,
    )?;
    Ok((
        next_proof_digest,
        HistoryArcPcdRecursiveStepProof {
            recursive_hashes,
            next_proof_digest_hash,
        },
    ))
}

pub fn verify_history_arc_pcd_recursive_step_proof_native(
    statement: &HistoryArcPcdRecursiveStepStatement,
    previous_accumulator: &HistoryArcPcdAccumulator,
    next_accumulator: &HistoryArcPcdAccumulator,
    proof: &HistoryArcPcdRecursiveStepProof,
) -> Result<Digest, HistoryProofError> {
    verify_history_arc_pcd_recursive_step_statement_shape(
        statement,
        previous_accumulator,
        next_accumulator,
    )?;
    let statement_digest = history_arc_pcd_recursive_step_statement_digest(statement);
    let next_proof_digest = tagged_pair_digest(
        HISTRCN1,
        &statement.previous_proof_digest,
        &statement_digest,
    );
    let statement_hash_fields = history_arc_pcd_recursive_step_statement_hash_fields(statement);
    let previous_accumulator_hash_fields =
        history_arc_pcd_accumulator_hash_fields(previous_accumulator);
    let next_accumulator_hash_fields = history_arc_pcd_accumulator_hash_fields(next_accumulator);
    verify_and_discharge_fixed_hash_batch(
        history_arc_pcd_recursive_step_hash_params(),
        &proof.recursive_hashes,
        &[
            (statement_hash_fields.as_slice(), &statement_digest),
            (
                previous_accumulator_hash_fields.as_slice(),
                &statement.previous_accumulator_digest,
            ),
            (
                next_accumulator_hash_fields.as_slice(),
                &statement.next_accumulator_digest,
            ),
        ],
    )?;
    verify_and_discharge_fixed_hash(
        history_tagged_pair_hash_params(),
        &proof.next_proof_digest_hash,
        &history_tagged_pair_hash_fields(
            HISTRCN1,
            &statement.previous_proof_digest,
            &statement_digest,
        ),
        &next_proof_digest,
    )?;
    Ok(next_proof_digest)
}

pub fn verify_history_arc_pcd_recursive_chain_head_shape_native(
    start_state: &HistoryAccumulationState,
    final_accumulator: &HistoryArcPcdAccumulator,
    head: &HistoryArcPcdRecursiveChainHead,
) -> Result<Digest, HistoryProofError> {
    if head.version != HISTORY_PROOF_VERSION || head.step_count != final_accumulator.step_count {
        return Err(HistoryProofError::BadPcdStepState);
    }
    let start_accumulator = HistoryArcPcdAccumulator::from_start_state(start_state)?;
    let base_proof_digest = history_arc_pcd_recursive_base_digest(start_state, &start_accumulator)?;
    if head.base_proof_digest != base_proof_digest {
        return Err(HistoryProofError::BadDeciderProof);
    }
    if head.final_step_statement.step_count != head.step_count
        || head.final_step_statement.next_accumulator_digest
            != history_arc_pcd_accumulator_digest(final_accumulator)
    {
        return Err(HistoryProofError::BadPcdStepState);
    }
    if head.step_count == start_accumulator.step_count {
        return Err(HistoryProofError::BadStepCount);
    }
    if head.step_count == start_accumulator.step_count + 1
        && (head.final_step_statement.previous_proof_digest != base_proof_digest
            || head.previous_accumulator != start_accumulator)
    {
        return Err(HistoryProofError::BadPcdStepState);
    }

    let final_proof_digest = verify_history_arc_pcd_recursive_step_proof_native(
        &head.final_step_statement,
        &head.previous_accumulator,
        final_accumulator,
        &head.final_step_proof,
    )?;
    if final_proof_digest != head.final_proof_digest {
        return Err(HistoryProofError::BadDeciderProof);
    }
    Ok(final_proof_digest)
}

pub fn verify_history_arc_pcd_recursive_step_statement_shape(
    statement: &HistoryArcPcdRecursiveStepStatement,
    previous_accumulator: &HistoryArcPcdAccumulator,
    next_accumulator: &HistoryArcPcdAccumulator,
) -> Result<(), HistoryProofError> {
    if statement.version != HISTORY_PROOF_VERSION {
        return Err(HistoryProofError::UnsupportedVersion {
            version: statement.version,
        });
    }
    if next_accumulator.step_count
        != previous_accumulator
            .step_count
            .checked_add(1)
            .ok_or(HistoryProofError::BadStepCount)?
        || statement.step_count != next_accumulator.step_count
        || statement.previous_accumulator_digest
            != history_arc_pcd_accumulator_digest(previous_accumulator)
        || statement.next_accumulator_digest != history_arc_pcd_accumulator_digest(next_accumulator)
    {
        return Err(HistoryProofError::BadPcdStepState);
    }
    Ok(())
}

pub fn build_history_arc_pcd_recursive_chunk_step_statement(
    previous_proof_digest: Digest,
    previous_accumulator: &HistoryArcPcdAccumulator,
    previous_state: &HistoryAccumulationState,
    items: &[HistoryTransitionWitnessItem],
    chunk_step: &HistoryArcPcdChunkStepProof,
) -> Result<
    (
        HistoryArcPcdRecursiveChunkStepStatement,
        HistoryAccumulationState,
        HistoryArcPcdAccumulator,
        Digest,
    ),
    HistoryProofError,
> {
    let (next_state, next_accumulator) = verify_history_arc_pcd_chunk_step_proof_native(
        previous_accumulator,
        previous_state,
        items,
        chunk_step,
    )?;
    let (statement, next_proof_digest) =
        build_history_arc_pcd_recursive_chunk_step_statement_from_parts(
            previous_proof_digest,
            previous_accumulator,
            chunk_step,
            &next_accumulator,
        )?;
    Ok((statement, next_state, next_accumulator, next_proof_digest))
}

fn build_history_arc_pcd_recursive_chunk_step_statement_from_parts(
    previous_proof_digest: Digest,
    previous_accumulator: &HistoryArcPcdAccumulator,
    chunk_step: &HistoryArcPcdChunkStepProof,
    next_accumulator: &HistoryArcPcdAccumulator,
) -> Result<(HistoryArcPcdRecursiveChunkStepStatement, Digest), HistoryProofError> {
    let statement = HistoryArcPcdRecursiveChunkStepStatement {
        version: HISTORY_PROOF_VERSION,
        chunk_len: chunk_step.chunk_len,
        previous_step_count: previous_accumulator.step_count,
        step_count: next_accumulator.step_count,
        previous_proof_digest,
        previous_accumulator_digest: history_arc_pcd_accumulator_digest(previous_accumulator),
        chunk_step_proof_digest: history_arc_pcd_chunk_step_component_digest(chunk_step)?,
        next_accumulator_digest: history_arc_pcd_accumulator_digest(next_accumulator),
    };
    let statement_digest = history_arc_pcd_recursive_chunk_step_statement_digest(&statement);
    let next_proof_digest = tagged_pair_digest(HISTRKN1, &previous_proof_digest, &statement_digest);
    Ok((statement, next_proof_digest))
}

pub fn prove_history_arc_pcd_recursive_chunk_chain_head_native(
    start_anchor: HeaderChainAnchor,
    end_anchor: HeaderChainAnchor,
    start_accumulator: ChainAccumulator,
    witness: &HistoryProofWitness,
) -> Result<
    (
        HistoryAccumulationState,
        HistoryArcPcdAccumulator,
        HistoryArcPcdRecursiveChunkChainHead,
    ),
    HistoryProofError,
> {
    if witness.items.is_empty() {
        return Err(HistoryProofError::BadStepCount);
    }
    if start_accumulator.height != start_anchor.height
        || start_accumulator.state_root != start_anchor.state_root
    {
        return Err(HistoryProofError::StartAccumulatorMismatch);
    }

    let start_state =
        HistoryAccumulationState::from_anchor(&start_anchor, start_accumulator.clone())?;
    let mut state = start_state.clone();
    let mut arc_accumulator = HistoryArcPcdAccumulator::from_start_state(&start_state)?;
    let base_proof_digest = history_arc_pcd_recursive_base_digest(&state, &arc_accumulator)?;
    let mut previous_proof_digest = base_proof_digest;
    let mut previous_chunk_count = 0u64;
    let mut head = None;

    for items in witness.items.chunks(HISTORY_ARC_PCD_CHUNK_MAX_STEPS) {
        let (next_state, next_accumulator, next_head) =
            prove_history_arc_pcd_recursive_chunk_chain_head_step_native(
                base_proof_digest,
                previous_proof_digest,
                previous_chunk_count,
                &arc_accumulator,
                &state,
                items,
            )?;
        previous_proof_digest = next_head.final_proof_digest;
        previous_chunk_count = next_head.chunk_count;
        head = Some(next_head);
        arc_accumulator = next_accumulator;
        state = next_state;
    }

    if state.height != end_anchor.height || state.accumulator.state_root != end_anchor.state_root {
        return Err(HistoryProofError::EndAccumulatorMismatch);
    }
    if state.projection_root != end_anchor.projection_root {
        return Err(HistoryProofError::BadHeaderProjectionRoot);
    }
    if state.block_id != end_anchor.block_id {
        return Err(HistoryProofError::BadEndBlockId);
    }

    Ok((
        state,
        arc_accumulator,
        head.expect("non-empty witness produced a recursive chunk chain head"),
    ))
}

pub fn prove_history_arc_pcd_recursive_chunk_chain_head_step_native(
    base_proof_digest: Digest,
    previous_proof_digest: Digest,
    previous_chunk_count: u64,
    previous_accumulator: &HistoryArcPcdAccumulator,
    previous_state: &HistoryAccumulationState,
    items: &[HistoryTransitionWitnessItem],
) -> Result<
    (
        HistoryAccumulationState,
        HistoryArcPcdAccumulator,
        HistoryArcPcdRecursiveChunkChainHead,
    ),
    HistoryProofError,
> {
    validate_accumulation_state_shape(previous_state)?;
    if previous_accumulator.step_count != previous_state.step_count {
        return Err(HistoryProofError::BadStepCount);
    }
    let (next_state, next_accumulator, chunk_step) =
        prove_history_arc_pcd_chunk_step_native(previous_accumulator, previous_state, items)?;
    let (statement, expected_next_digest) =
        build_history_arc_pcd_recursive_chunk_step_statement_from_parts(
            previous_proof_digest,
            previous_accumulator,
            &chunk_step,
            &next_accumulator,
        )?;
    let (next_proof_digest, final_chunk_proof) = prove_history_arc_pcd_recursive_chunk_step_native(
        &statement,
        previous_accumulator,
        &next_accumulator,
    )?;
    if next_proof_digest != expected_next_digest {
        return Err(HistoryProofError::BadDeciderProof);
    }
    let (final_chunk_verifier_transcript, _) =
        prove_history_arc_pcd_recursive_chunk_step_verifier_transcript_batch_native(
            &statement,
            previous_accumulator,
            &next_accumulator,
            &final_chunk_proof,
        )?;
    let chunk_count = previous_chunk_count
        .checked_add(1)
        .ok_or(HistoryProofError::BadStepCount)?;

    Ok((
        next_state,
        next_accumulator.clone(),
        HistoryArcPcdRecursiveChunkChainHead {
            version: HISTORY_PROOF_VERSION,
            step_count: next_accumulator.step_count,
            chunk_count,
            base_proof_digest,
            final_proof_digest: next_proof_digest,
            previous_accumulator: previous_accumulator.clone(),
            final_chunk_statement: statement,
            final_chunk_proof,
            final_chunk_verifier_transcript,
        },
    ))
}

pub fn prove_history_arc_pcd_recursive_chunk_step_native(
    statement: &HistoryArcPcdRecursiveChunkStepStatement,
    previous_accumulator: &HistoryArcPcdAccumulator,
    next_accumulator: &HistoryArcPcdAccumulator,
) -> Result<(Digest, HistoryArcPcdRecursiveChunkStepProof), HistoryProofError> {
    verify_history_arc_pcd_recursive_chunk_step_statement_shape(
        statement,
        previous_accumulator,
        next_accumulator,
    )?;
    let statement_digest = history_arc_pcd_recursive_chunk_step_statement_digest(statement);
    let next_proof_digest = tagged_pair_digest(
        HISTRKN1,
        &statement.previous_proof_digest,
        &statement_digest,
    );
    let statement_hash_fields =
        history_arc_pcd_recursive_chunk_step_statement_hash_fields(statement);
    let previous_accumulator_hash_fields =
        history_arc_pcd_accumulator_hash_fields(previous_accumulator);
    let next_accumulator_hash_fields = history_arc_pcd_accumulator_hash_fields(next_accumulator);
    let recursive_hashes = prove_fixed_hash_batch(
        history_arc_pcd_recursive_chunk_step_hash_params(),
        &[
            (statement_hash_fields.as_slice(), &statement_digest),
            (
                previous_accumulator_hash_fields.as_slice(),
                &statement.previous_accumulator_digest,
            ),
            (
                next_accumulator_hash_fields.as_slice(),
                &statement.next_accumulator_digest,
            ),
        ],
    )?;
    let next_proof_digest_hash = prove_fixed_hash(
        history_tagged_pair_hash_params(),
        &history_tagged_pair_hash_fields(
            HISTRKN1,
            &statement.previous_proof_digest,
            &statement_digest,
        ),
        &next_proof_digest,
    )?;
    Ok((
        next_proof_digest,
        HistoryArcPcdRecursiveChunkStepProof {
            recursive_hashes,
            next_proof_digest_hash,
        },
    ))
}

pub fn verify_history_arc_pcd_recursive_chunk_step_proof_native(
    statement: &HistoryArcPcdRecursiveChunkStepStatement,
    previous_accumulator: &HistoryArcPcdAccumulator,
    next_accumulator: &HistoryArcPcdAccumulator,
    proof: &HistoryArcPcdRecursiveChunkStepProof,
) -> Result<Digest, HistoryProofError> {
    verify_history_arc_pcd_recursive_chunk_step_statement_shape(
        statement,
        previous_accumulator,
        next_accumulator,
    )?;
    let statement_digest = history_arc_pcd_recursive_chunk_step_statement_digest(statement);
    let next_proof_digest = tagged_pair_digest(
        HISTRKN1,
        &statement.previous_proof_digest,
        &statement_digest,
    );
    let statement_hash_fields =
        history_arc_pcd_recursive_chunk_step_statement_hash_fields(statement);
    let previous_accumulator_hash_fields =
        history_arc_pcd_accumulator_hash_fields(previous_accumulator);
    let next_accumulator_hash_fields = history_arc_pcd_accumulator_hash_fields(next_accumulator);
    verify_and_discharge_fixed_hash_batch(
        history_arc_pcd_recursive_chunk_step_hash_params(),
        &proof.recursive_hashes,
        &[
            (statement_hash_fields.as_slice(), &statement_digest),
            (
                previous_accumulator_hash_fields.as_slice(),
                &statement.previous_accumulator_digest,
            ),
            (
                next_accumulator_hash_fields.as_slice(),
                &statement.next_accumulator_digest,
            ),
        ],
    )?;
    verify_and_discharge_fixed_hash(
        history_tagged_pair_hash_params(),
        &proof.next_proof_digest_hash,
        &history_tagged_pair_hash_fields(
            HISTRKN1,
            &statement.previous_proof_digest,
            &statement_digest,
        ),
        &next_proof_digest,
    )?;
    Ok(next_proof_digest)
}

pub fn history_arc_pcd_recursive_chunk_step_verifier_traces(
    statement: &HistoryArcPcdRecursiveChunkStepStatement,
    previous_accumulator: &HistoryArcPcdAccumulator,
    next_accumulator: &HistoryArcPcdAccumulator,
    proof: &HistoryArcPcdRecursiveChunkStepProof,
) -> Result<Vec<Vec<FiatShamirTraceOp>>, HistoryProofError> {
    verify_history_arc_pcd_recursive_chunk_step_statement_shape(
        statement,
        previous_accumulator,
        next_accumulator,
    )?;
    let statement_digest = history_arc_pcd_recursive_chunk_step_statement_digest(statement);
    let next_proof_digest = tagged_pair_digest(
        HISTRKN1,
        &statement.previous_proof_digest,
        &statement_digest,
    );
    let statement_hash_fields =
        history_arc_pcd_recursive_chunk_step_statement_hash_fields(statement);
    let previous_accumulator_hash_fields =
        history_arc_pcd_accumulator_hash_fields(previous_accumulator);
    let next_accumulator_hash_fields = history_arc_pcd_accumulator_hash_fields(next_accumulator);

    let mut traces = Vec::with_capacity(2);
    traces.push(verify_and_discharge_fixed_hash_batch_with_trace(
        history_arc_pcd_recursive_chunk_step_hash_params(),
        &proof.recursive_hashes,
        &[
            (statement_hash_fields.as_slice(), &statement_digest),
            (
                previous_accumulator_hash_fields.as_slice(),
                &statement.previous_accumulator_digest,
            ),
            (
                next_accumulator_hash_fields.as_slice(),
                &statement.next_accumulator_digest,
            ),
        ],
    )?);
    traces.push(verify_and_discharge_fixed_hash_batch_with_trace(
        history_tagged_pair_hash_params(),
        &proof.next_proof_digest_hash,
        &[(
            history_tagged_pair_hash_fields(
                HISTRKN1,
                &statement.previous_proof_digest,
                &statement_digest,
            )
            .as_slice(),
            &next_proof_digest,
        )],
    )?);
    Ok(traces)
}

pub fn prove_history_arc_pcd_recursive_chunk_step_verifier_transcript_batch_native(
    statement: &HistoryArcPcdRecursiveChunkStepStatement,
    previous_accumulator: &HistoryArcPcdAccumulator,
    next_accumulator: &HistoryArcPcdAccumulator,
    proof: &HistoryArcPcdRecursiveChunkStepProof,
) -> Result<
    (
        FiatShamirTranscriptBatchProofKillShot,
        FiatShamirTranscriptReductions,
    ),
    HistoryProofError,
> {
    let traces = history_arc_pcd_recursive_chunk_step_verifier_traces(
        statement,
        previous_accumulator,
        next_accumulator,
        proof,
    )?;
    let mut channel = noid_poseidon2b::channel::Poseidon2bChannel::new();
    prove_fiat_shamir_transcript_batch_killshot(&traces, &mut channel)
        .map_err(map_fs_transcript_error)
}

pub fn verify_history_arc_pcd_recursive_chunk_step_verifier_transcript_batch_native(
    statement: &HistoryArcPcdRecursiveChunkStepStatement,
    previous_accumulator: &HistoryArcPcdAccumulator,
    next_accumulator: &HistoryArcPcdAccumulator,
    proof: &HistoryArcPcdRecursiveChunkStepProof,
    transcript_proof: &FiatShamirTranscriptBatchProofKillShot,
) -> Result<(), HistoryProofError> {
    let traces = history_arc_pcd_recursive_chunk_step_verifier_traces(
        statement,
        previous_accumulator,
        next_accumulator,
        proof,
    )?;
    let mut channel = noid_poseidon2b::channel::Poseidon2bChannel::new();
    let reductions =
        verify_fiat_shamir_transcript_batch_killshot(&traces, transcript_proof, &mut channel)
            .map_err(map_fs_transcript_error)?;
    if discharge_fiat_shamir_transcript_batch_reductions_native(&traces, &reductions) {
        Ok(())
    } else {
        Err(HistoryProofError::BadDeciderHashDischarge)
    }
}

pub fn verify_history_arc_pcd_recursive_chunk_chain_head_shape_native(
    start_state: &HistoryAccumulationState,
    final_accumulator: &HistoryArcPcdAccumulator,
    head: &HistoryArcPcdRecursiveChunkChainHead,
) -> Result<Digest, HistoryProofError> {
    if head.version != HISTORY_PROOF_VERSION || head.step_count != final_accumulator.step_count {
        return Err(HistoryProofError::BadPcdStepState);
    }
    if head.chunk_count == 0 {
        return Err(HistoryProofError::BadStepCount);
    }
    let start_accumulator = HistoryArcPcdAccumulator::from_start_state(start_state)?;
    let base_proof_digest = history_arc_pcd_recursive_base_digest(start_state, &start_accumulator)?;
    if head.base_proof_digest != base_proof_digest {
        return Err(HistoryProofError::BadDeciderProof);
    }
    let covered_steps = head
        .step_count
        .checked_sub(start_accumulator.step_count)
        .ok_or(HistoryProofError::BadStepCount)?;
    if covered_steps == 0
        || covered_steps < head.chunk_count
        || covered_steps
            > head
                .chunk_count
                .checked_mul(HISTORY_ARC_PCD_CHUNK_MAX_STEPS as u64)
                .ok_or(HistoryProofError::BadStepCount)?
    {
        return Err(HistoryProofError::BadStepCount);
    }
    if head.final_chunk_statement.step_count != head.step_count
        || head.final_chunk_statement.next_accumulator_digest
            != history_arc_pcd_accumulator_digest(final_accumulator)
    {
        return Err(HistoryProofError::BadPcdStepState);
    }
    if head.chunk_count == 1
        && (head.final_chunk_statement.previous_proof_digest != base_proof_digest
            || head.previous_accumulator != start_accumulator)
    {
        return Err(HistoryProofError::BadPcdStepState);
    }

    let final_proof_digest = verify_history_arc_pcd_recursive_chunk_step_proof_native(
        &head.final_chunk_statement,
        &head.previous_accumulator,
        final_accumulator,
        &head.final_chunk_proof,
    )?;
    verify_history_arc_pcd_recursive_chunk_step_verifier_transcript_batch_native(
        &head.final_chunk_statement,
        &head.previous_accumulator,
        final_accumulator,
        &head.final_chunk_proof,
        &head.final_chunk_verifier_transcript,
    )?;
    if final_proof_digest != head.final_proof_digest {
        return Err(HistoryProofError::BadDeciderProof);
    }
    Ok(final_proof_digest)
}

pub fn verify_history_arc_pcd_recursive_chunk_step_statement_shape(
    statement: &HistoryArcPcdRecursiveChunkStepStatement,
    previous_accumulator: &HistoryArcPcdAccumulator,
    next_accumulator: &HistoryArcPcdAccumulator,
) -> Result<(), HistoryProofError> {
    if statement.version != HISTORY_PROOF_VERSION {
        return Err(HistoryProofError::UnsupportedVersion {
            version: statement.version,
        });
    }
    if statement.chunk_len == 0 || statement.chunk_len as usize > HISTORY_ARC_PCD_CHUNK_MAX_STEPS {
        return Err(HistoryProofError::BadStepCount);
    }
    let expected_step_count = previous_accumulator
        .step_count
        .checked_add(statement.chunk_len as u64)
        .ok_or(HistoryProofError::BadStepCount)?;
    if statement.previous_step_count != previous_accumulator.step_count
        || next_accumulator.step_count != expected_step_count
        || statement.step_count != next_accumulator.step_count
        || statement.previous_accumulator_digest
            != history_arc_pcd_accumulator_digest(previous_accumulator)
        || statement.next_accumulator_digest != history_arc_pcd_accumulator_digest(next_accumulator)
    {
        return Err(HistoryProofError::BadPcdStepState);
    }
    Ok(())
}

fn advance_history_arc_pcd_accumulator_verified(
    accumulator: &HistoryArcPcdAccumulator,
    statement: &HistoryPcdStepStatement,
    check_previous_state_digest: bool,
) -> Result<HistoryArcPcdAccumulator, HistoryProofError> {
    if accumulator.version != HISTORY_PROOF_VERSION {
        return Err(HistoryProofError::UnsupportedVersion {
            version: accumulator.version,
        });
    }
    if accumulator.step_relation_digest != history_arc_pcd_step_relation_digest() {
        return Err(HistoryProofError::BadDeciderProof);
    }
    if accumulator.step_count != statement.previous_state.step_count {
        return Err(HistoryProofError::BadPcdStepState);
    }
    if check_previous_state_digest
        && accumulator.current_state_digest
            != history_accumulation_state_digest(&statement.previous_state)
    {
        return Err(HistoryProofError::BadPcdStepState);
    }

    let step_digest = history_pcd_step_statement_digest(statement);
    let current_state_digest = history_accumulation_state_digest(&statement.next_state);
    let pcd_root = tagged_pair_digest(HISTARA1, &accumulator.pcd_root, &step_digest);
    let transcript_digest =
        tagged_pair_digest(HISTART1, &accumulator.transcript_digest, &step_digest);
    Ok(HistoryArcPcdAccumulator {
        version: HISTORY_PROOF_VERSION,
        step_count: accumulator
            .step_count
            .checked_add(1)
            .ok_or(HistoryProofError::BadStepCount)?,
        start_state_digest: accumulator.start_state_digest,
        current_state_digest,
        pcd_root,
        step_relation_digest: accumulator.step_relation_digest,
        transcript_digest,
    })
}

pub fn advance_history_accumulation_native(
    state: &HistoryAccumulationState,
    item: &HistoryTransitionWitnessItem,
) -> Result<HistoryAccumulationState, HistoryProofError> {
    if state.version != HISTORY_PROOF_VERSION {
        return Err(HistoryProofError::UnsupportedVersion {
            version: state.version,
        });
    }
    let step = build_history_step_statement(
        &state.accumulator,
        state.block_id,
        state.projection_root,
        item,
    )?;
    Ok(HistoryAccumulationState {
        version: HISTORY_PROOF_VERSION,
        height: step.next_accumulator.height,
        block_id: step.next_block_id,
        projection_root: step.next_projection_root,
        accumulator: step.next_accumulator,
        folded_witness_root: compress_with_tag(
            TAG_HISTPRF,
            &state.folded_witness_root,
            &step.folded_item_digest,
        ),
        step_count: state.step_count.saturating_add(1),
    })
}

fn next_state_from_step(
    previous_state: &HistoryAccumulationState,
    step: &HistoryStepStatement,
) -> Result<HistoryAccumulationState, HistoryProofError> {
    validate_accumulation_state_shape(previous_state)?;
    if step.version != HISTORY_PROOF_VERSION {
        return Err(HistoryProofError::BadStepVersion {
            version: step.version,
        });
    }
    let next_height = previous_state
        .height
        .checked_add(1)
        .ok_or(HistoryProofError::BadStepCount)?;
    let next_step_count = previous_state
        .step_count
        .checked_add(1)
        .ok_or(HistoryProofError::BadStepCount)?;
    if step.previous_accumulator != previous_state.accumulator
        || step.previous_block_id != previous_state.block_id
        || step.previous_projection_root != previous_state.projection_root
        || step.next_accumulator.height != next_height
    {
        return Err(HistoryProofError::BadPcdStepState);
    }
    let next_state = HistoryAccumulationState {
        version: HISTORY_PROOF_VERSION,
        height: step.next_accumulator.height,
        block_id: step.next_block_id,
        projection_root: step.next_projection_root,
        accumulator: step.next_accumulator.clone(),
        folded_witness_root: compress_with_tag(
            TAG_HISTPRF,
            &previous_state.folded_witness_root,
            &step.folded_item_digest,
        ),
        step_count: next_step_count,
    };
    validate_accumulation_state_shape(&next_state)?;
    Ok(next_state)
}

fn validate_accumulation_state_shape(
    state: &HistoryAccumulationState,
) -> Result<(), HistoryProofError> {
    if state.version != HISTORY_PROOF_VERSION {
        return Err(HistoryProofError::UnsupportedVersion {
            version: state.version,
        });
    }
    if state.height != state.accumulator.height {
        return Err(HistoryProofError::BadPcdStepState);
    }
    Ok(())
}

pub fn prove_history_native(
    start_anchor: HeaderChainAnchor,
    end_anchor: HeaderChainAnchor,
    start_accumulator: ChainAccumulator,
    witness: &HistoryProofWitness,
) -> Result<HistoryProof, HistoryProofError> {
    if start_accumulator.height != start_anchor.height
        || start_accumulator.state_root != start_anchor.state_root
    {
        return Err(HistoryProofError::StartAccumulatorMismatch);
    }

    let start_state =
        HistoryAccumulationState::from_anchor(&start_anchor, start_accumulator.clone())?;
    let mut state = start_state.clone();
    let mut arc_accumulator = HistoryArcPcdAccumulator::from_start_state(&start_state)?;

    for item in &witness.items {
        let step = build_history_step_statement(
            &state.accumulator,
            state.block_id,
            state.projection_root,
            item,
        )?;
        let pcd_step = build_history_pcd_step_statement_from_step(&state, &step)?;
        arc_accumulator =
            advance_history_arc_pcd_accumulator_verified(&arc_accumulator, &pcd_step, false)?;
        state = pcd_step.next_state;
    }

    if state.height != end_anchor.height || state.accumulator.state_root != end_anchor.state_root {
        return Err(HistoryProofError::EndAccumulatorMismatch);
    }
    if state.projection_root != end_anchor.projection_root {
        return Err(HistoryProofError::BadHeaderProjectionRoot);
    }
    if state.height != start_anchor.height && state.block_id != end_anchor.block_id {
        return Err(HistoryProofError::BadEndBlockId);
    }
    if state.height == start_anchor.height && start_anchor != end_anchor {
        return Err(HistoryProofError::EndAnchorMismatch);
    }

    let mut proof = HistoryProof {
        version: HISTORY_PROOF_VERSION,
        backend: HistoryProofBackend::NativeFoldV1,
        start_anchor,
        end_anchor,
        start_accumulator,
        end_accumulator: state.accumulator.clone(),
        folded_witness_root: state.folded_witness_root,
        step_count: state.step_count,
        decider: HistoryDeciderProof::zero(),
        proof_digest: [0u8; 32],
    };
    let statement = history_decider_statement(&proof);
    proof.decider = HistoryDeciderProof::native_fold_v1(&statement, &arc_accumulator)?;
    proof.proof_digest = history_proof_digest(&proof);
    Ok(proof)
}

pub fn prove_history_arc_pcd_one_step(
    start_anchor: HeaderChainAnchor,
    end_anchor: HeaderChainAnchor,
    start_accumulator: ChainAccumulator,
    witness: &HistoryProofWitness,
) -> Result<HistoryProof, HistoryProofError> {
    if witness.items.len() != 1 {
        return Err(HistoryProofError::BackendVerifierMissing);
    }
    if start_accumulator.height != start_anchor.height
        || start_accumulator.state_root != start_anchor.state_root
    {
        return Err(HistoryProofError::StartAccumulatorMismatch);
    }

    let start_state =
        HistoryAccumulationState::from_anchor(&start_anchor, start_accumulator.clone())?;
    let item = &witness.items[0];
    let (step_proof, reductions) = prove_history_step_native(
        &start_state.accumulator,
        start_state.block_id,
        start_state.projection_root,
        item,
    )?;
    let pcd_step = build_history_pcd_step_statement_native(&start_state, &step_proof, &reductions)?;
    let start_arc = HistoryArcPcdAccumulator::from_start_state(&start_state)?;
    let (arc_accumulator, arc_step) = prove_history_arc_pcd_step_native(&start_arc, &pcd_step)?;
    let state = pcd_step.next_state.clone();

    if state.height != end_anchor.height || state.accumulator.state_root != end_anchor.state_root {
        return Err(HistoryProofError::EndAccumulatorMismatch);
    }
    if state.projection_root != end_anchor.projection_root {
        return Err(HistoryProofError::BadHeaderProjectionRoot);
    }
    if state.block_id != end_anchor.block_id {
        return Err(HistoryProofError::BadEndBlockId);
    }

    let one_step = HistoryArcPcdOneStepProof {
        step: step_proof,
        arc_step,
    };
    let mut proof = HistoryProof {
        version: HISTORY_PROOF_VERSION,
        backend: HistoryProofBackend::ArcPcdV1,
        start_anchor,
        end_anchor,
        start_accumulator,
        end_accumulator: state.accumulator.clone(),
        folded_witness_root: state.folded_witness_root,
        step_count: state.step_count,
        decider: HistoryDeciderProof::zero(),
        proof_digest: [0u8; 32],
    };
    let statement = history_decider_statement(&proof);
    proof.decider =
        HistoryDeciderProof::arc_pcd_one_step_v1(&statement, &arc_accumulator, one_step)?;
    proof.proof_digest = history_proof_digest(&proof);
    Ok(proof)
}

pub fn verify_history_proof_native(
    proof: &HistoryProof,
    local_start_anchor: &HeaderChainAnchor,
    local_end_anchor: &HeaderChainAnchor,
) -> Result<(), HistoryProofError> {
    if proof.version != HISTORY_PROOF_VERSION {
        return Err(HistoryProofError::UnsupportedVersion {
            version: proof.version,
        });
    }
    if &proof.start_anchor != local_start_anchor {
        return Err(HistoryProofError::StartAnchorMismatch);
    }
    if &proof.end_anchor != local_end_anchor {
        return Err(HistoryProofError::EndAnchorMismatch);
    }
    if proof.start_accumulator.height != proof.start_anchor.height
        || proof.start_accumulator.state_root != proof.start_anchor.state_root
    {
        return Err(HistoryProofError::StartAccumulatorMismatch);
    }
    if proof.end_accumulator.height != proof.end_anchor.height
        || proof.end_accumulator.state_root != proof.end_anchor.state_root
    {
        return Err(HistoryProofError::EndAccumulatorMismatch);
    }
    if proof.end_anchor.height < proof.start_anchor.height
        || proof.step_count != proof.end_anchor.height - proof.start_anchor.height
    {
        return Err(HistoryProofError::BadStepCount);
    }
    verify_history_decider_shape(proof)?;
    if history_proof_digest(proof) != proof.proof_digest {
        return Err(HistoryProofError::BadProofDigest);
    }
    Ok(())
}

pub fn verify_history_proof_untrusted(
    proof: &HistoryProof,
    local_start_anchor: &HeaderChainAnchor,
    local_end_anchor: &HeaderChainAnchor,
) -> Result<(), HistoryProofError> {
    verify_history_proof_native(proof, local_start_anchor, local_end_anchor)?;
    match proof.backend {
        HistoryProofBackend::NativeFoldV1 => Err(HistoryProofError::BackendNotTrustless),
        HistoryProofBackend::ArcPcdV1
            if proof.step_count == 1
                && proof.decider.one_step_proof.is_some()
                && proof.decider.recursive_head.is_none()
                && proof.decider.recursive_chunk_head.is_none() =>
        {
            Ok(())
        }
        HistoryProofBackend::ArcPcdV1 => Err(HistoryProofError::BackendVerifierMissing),
    }?;
    Ok(())
}

pub fn history_decider_statement(proof: &HistoryProof) -> HistoryDeciderStatement {
    HistoryDeciderStatement {
        version: proof.version,
        backend: proof.backend,
        step_count: proof.step_count,
        start_anchor_digest: history_anchor_digest(&proof.start_anchor),
        end_anchor_digest: history_anchor_digest(&proof.end_anchor),
        start_accumulator_digest: history_accumulator_digest(&proof.start_accumulator),
        end_accumulator_digest: history_accumulator_digest(&proof.end_accumulator),
        folded_witness_root: proof.folded_witness_root,
    }
}

pub fn history_decider_statement_digest(statement: &HistoryDeciderStatement) -> Digest {
    let mut sponge = Poseidon2bSponge::with_iv(capacity_iv(TAG_HISTPRF));
    sponge.absorb(Block128::from(0x4849_5354_4453_5331u128)); // "HISTDSS1"
    sponge.absorb(Block128::from(statement.version as u128));
    sponge.absorb(Block128::from(statement.backend.id() as u128));
    sponge.absorb(Block128::from(statement.step_count as u128));
    absorb_digest(&mut sponge, &statement.start_anchor_digest);
    absorb_digest(&mut sponge, &statement.end_anchor_digest);
    absorb_digest(&mut sponge, &statement.start_accumulator_digest);
    absorb_digest(&mut sponge, &statement.end_accumulator_digest);
    absorb_digest(&mut sponge, &statement.folded_witness_root);
    sponge.finalize()
}

fn verify_history_decider_shape(proof: &HistoryProof) -> Result<(), HistoryProofError> {
    let statement = history_decider_statement(proof);
    if proof.decider.statement_digest != history_decider_statement_digest(&statement) {
        return Err(HistoryProofError::BadDeciderStatement);
    }
    let start_state = history_start_state_from_proof(proof)?;
    let end_state = history_end_state_from_proof(proof)?;
    match proof.backend {
        HistoryProofBackend::NativeFoldV1 => {
            verify_history_arc_pcd_boundary(
                &proof.decider.pcd_accumulator,
                &start_state,
                &end_state,
            )?;
            verify_native_fold_decider_hashes(&statement, &proof.decider)?;
        }
        HistoryProofBackend::ArcPcdV1 => {
            verify_history_arc_pcd_boundary(
                &proof.decider.pcd_accumulator,
                &start_state,
                &end_state,
            )?;
            if proof.decider.one_step_proof.is_some() {
                verify_arc_pcd_one_step_decider(
                    &statement,
                    &proof.decider,
                    &start_state,
                    &end_state,
                )?;
            } else if proof.decider.recursive_head.is_some() {
                verify_arc_pcd_recursive_head_decider(
                    &statement,
                    &proof.decider,
                    &start_state,
                    &end_state,
                )?;
            } else if proof.decider.recursive_chunk_head.is_some() {
                verify_arc_pcd_recursive_chunk_head_decider(
                    &statement,
                    &proof.decider,
                    &start_state,
                    &end_state,
                )?;
            } else {
                return Err(HistoryProofError::BadDeciderProof);
            }
        }
    }
    Ok(())
}

fn verify_native_fold_decider_hashes(
    statement: &HistoryDeciderStatement,
    decider: &HistoryDeciderProof,
) -> Result<(), HistoryProofError> {
    if decider.one_step_proof_digest != history_arc_pcd_one_step_proof_digest(&None)?
        || decider.one_step_proof.is_some()
        || decider.recursive_head_digest != history_arc_pcd_recursive_head_digest(&None)?
        || decider.recursive_head.is_some()
        || decider.recursive_chunk_head_digest
            != history_arc_pcd_recursive_chunk_head_digest(&None)?
        || decider.recursive_chunk_head.is_some()
    {
        return Err(HistoryProofError::BadDeciderProof);
    }
    verify_decider_hashes(statement, decider)
}

fn verify_decider_hashes(
    statement: &HistoryDeciderStatement,
    decider: &HistoryDeciderProof,
) -> Result<(), HistoryProofError> {
    let commitments = verify_decider_commitments_native(statement, decider)?;
    let pcd_accumulator = &decider.pcd_accumulator;
    if history_decider_hash_proofs_digest(&decider.hash_proofs)? != decider.hash_proofs_digest {
        return Err(HistoryProofError::BadDeciderHashProof);
    }
    let Some(hash_proofs) = &decider.hash_proofs else {
        return Err(HistoryProofError::BadDeciderHashProof);
    };

    verify_and_discharge_fixed_hash(
        history_arc_pcd_accumulator_hash_params(),
        &hash_proofs.arc_accumulator_hash,
        &history_arc_pcd_accumulator_hash_fields(pcd_accumulator),
        &commitments.pcd_accumulator_digest,
    )?;
    let accumulator_commitment_hash_fields = history_tagged_pair_hash_fields(
        HISTACC1,
        &commitments.pcd_accumulator_digest,
        &statement.end_accumulator_digest,
    );
    let step_relation_commitment_hash_fields = history_tagged_pair_hash_fields(
        HISTSTP1,
        &pcd_accumulator.step_relation_digest,
        &commitments.statement_digest,
    );
    let pcs_commitment_hash_fields = history_tagged_pair_hash_fields(
        HISTPCS1,
        &pcd_accumulator.pcd_root,
        &pcd_accumulator.transcript_digest,
    );
    let opening_digest_hash_fields = history_tagged_pair_hash_fields(
        HISTOPN1,
        &decider.accumulator_commitment,
        &decider.pcs_commitment,
    );
    let transcript_digest_hash_fields = history_tagged_pair_hash_fields(
        HISTDST1,
        &commitments.statement_digest,
        &decider.opening_digest,
    );
    verify_and_discharge_fixed_hash_batch(
        history_tagged_pair_hash_params(),
        &hash_proofs.tagged_pair_hashes,
        &[
            (
                accumulator_commitment_hash_fields.as_slice(),
                &decider.accumulator_commitment,
            ),
            (
                step_relation_commitment_hash_fields.as_slice(),
                &decider.step_relation_commitment,
            ),
            (
                pcs_commitment_hash_fields.as_slice(),
                &decider.pcs_commitment,
            ),
            (
                opening_digest_hash_fields.as_slice(),
                &decider.opening_digest,
            ),
            (
                transcript_digest_hash_fields.as_slice(),
                &decider.transcript_digest,
            ),
        ],
    )?;
    Ok(())
}

fn verify_decider_commitments_native(
    statement: &HistoryDeciderStatement,
    decider: &HistoryDeciderProof,
) -> Result<HistoryDeciderCommitments, HistoryProofError> {
    if decider.reserved != [[0u8; 32]; 1] {
        return Err(HistoryProofError::BadDeciderProof);
    }
    let commitments = history_decider_commitments_v1(statement, &decider.pcd_accumulator)?;
    if decider.statement_digest != commitments.statement_digest {
        return Err(HistoryProofError::BadDeciderStatement);
    }

    if decider.accumulator_commitment != commitments.accumulator_commitment
        || decider.step_relation_commitment != commitments.step_relation_commitment
        || decider.pcs_commitment != commitments.pcs_commitment
        || decider.opening_digest != commitments.opening_digest
        || decider.transcript_digest != commitments.transcript_digest
    {
        return Err(HistoryProofError::BadDeciderProof);
    }

    Ok(commitments)
}

fn verify_arc_pcd_one_step_decider(
    statement: &HistoryDeciderStatement,
    decider: &HistoryDeciderProof,
    start_state: &HistoryAccumulationState,
    end_state: &HistoryAccumulationState,
) -> Result<(), HistoryProofError> {
    if statement.step_count != 1 {
        return Err(HistoryProofError::BackendVerifierMissing);
    }
    verify_decider_commitments_native(statement, decider)?;
    if decider.recursive_head.is_some()
        || history_arc_pcd_recursive_head_digest(&None)? != decider.recursive_head_digest
        || decider.recursive_chunk_head.is_some()
        || history_arc_pcd_recursive_chunk_head_digest(&None)?
            != decider.recursive_chunk_head_digest
    {
        return Err(HistoryProofError::BadDeciderProof);
    }
    let empty_hash_proofs: Option<HistoryDeciderHashProofs> = None;
    if decider.hash_proofs.is_some()
        || history_decider_hash_proofs_digest(&empty_hash_proofs)? != decider.hash_proofs_digest
    {
        return Err(HistoryProofError::BadDeciderHashProof);
    }
    if history_arc_pcd_one_step_proof_digest(&decider.one_step_proof)?
        != decider.one_step_proof_digest
    {
        return Err(HistoryProofError::BadDeciderProof);
    }
    let Some(one_step) = &decider.one_step_proof else {
        return Err(HistoryProofError::BadDeciderProof);
    };

    let reductions = verify_history_step_native(&one_step.step)?;
    discharge_history_step_native(&one_step.step, &reductions)?;
    let pcd_step =
        build_history_pcd_step_statement_native(start_state, &one_step.step, &reductions)?;
    if &pcd_step.next_state != end_state {
        return Err(HistoryProofError::BadPcdStepState);
    }
    let start_arc = HistoryArcPcdAccumulator::from_start_state(start_state)?;
    verify_history_arc_pcd_step_proof_native(
        &start_arc,
        &pcd_step,
        &decider.pcd_accumulator,
        &one_step.arc_step,
    )?;
    Ok(())
}

fn verify_arc_pcd_recursive_head_decider(
    statement: &HistoryDeciderStatement,
    decider: &HistoryDeciderProof,
    start_state: &HistoryAccumulationState,
    end_state: &HistoryAccumulationState,
) -> Result<(), HistoryProofError> {
    if statement.step_count == 0 {
        return Err(HistoryProofError::BadStepCount);
    }
    verify_decider_commitments_native(statement, decider)?;
    let empty_hash_proofs: Option<HistoryDeciderHashProofs> = None;
    let empty_one_step: Option<HistoryArcPcdOneStepProof> = None;
    if decider.hash_proofs.is_some()
        || history_decider_hash_proofs_digest(&empty_hash_proofs)? != decider.hash_proofs_digest
        || decider.one_step_proof.is_some()
        || history_arc_pcd_one_step_proof_digest(&empty_one_step)? != decider.one_step_proof_digest
        || decider.recursive_chunk_head.is_some()
        || history_arc_pcd_recursive_chunk_head_digest(&None)?
            != decider.recursive_chunk_head_digest
    {
        return Err(HistoryProofError::BadDeciderProof);
    }
    if history_arc_pcd_recursive_head_digest(&decider.recursive_head)?
        != decider.recursive_head_digest
    {
        return Err(HistoryProofError::BadDeciderProof);
    }
    let Some(head) = &decider.recursive_head else {
        return Err(HistoryProofError::BadDeciderProof);
    };
    if head.step_count != statement.step_count || end_state.step_count != statement.step_count {
        return Err(HistoryProofError::BadStepCount);
    }
    verify_history_arc_pcd_recursive_chain_head_shape_native(
        start_state,
        &decider.pcd_accumulator,
        head,
    )?;
    Ok(())
}

fn verify_arc_pcd_recursive_chunk_head_decider(
    statement: &HistoryDeciderStatement,
    decider: &HistoryDeciderProof,
    start_state: &HistoryAccumulationState,
    end_state: &HistoryAccumulationState,
) -> Result<(), HistoryProofError> {
    if statement.step_count == 0 {
        return Err(HistoryProofError::BadStepCount);
    }
    verify_decider_commitments_native(statement, decider)?;
    let empty_hash_proofs: Option<HistoryDeciderHashProofs> = None;
    let empty_one_step: Option<HistoryArcPcdOneStepProof> = None;
    if decider.hash_proofs.is_some()
        || history_decider_hash_proofs_digest(&empty_hash_proofs)? != decider.hash_proofs_digest
        || decider.one_step_proof.is_some()
        || history_arc_pcd_one_step_proof_digest(&empty_one_step)? != decider.one_step_proof_digest
        || decider.recursive_head.is_some()
        || history_arc_pcd_recursive_head_digest(&None)? != decider.recursive_head_digest
    {
        return Err(HistoryProofError::BadDeciderProof);
    }
    if history_arc_pcd_recursive_chunk_head_digest(&decider.recursive_chunk_head)?
        != decider.recursive_chunk_head_digest
    {
        return Err(HistoryProofError::BadDeciderProof);
    }
    let Some(head) = &decider.recursive_chunk_head else {
        return Err(HistoryProofError::BadDeciderProof);
    };
    if head.step_count != statement.step_count || end_state.step_count != statement.step_count {
        return Err(HistoryProofError::BadStepCount);
    }
    verify_history_arc_pcd_recursive_chunk_chain_head_shape_native(
        start_state,
        &decider.pcd_accumulator,
        head,
    )?;
    Ok(())
}

pub fn history_proof_digest(proof: &HistoryProof) -> Digest {
    let mut sponge = Poseidon2bSponge::with_iv(capacity_iv(TAG_HISTPRF));
    sponge.absorb(Block128::from(proof.version as u128));
    sponge.absorb(Block128::from(proof.backend.id() as u128));
    absorb_anchor(&mut sponge, &proof.start_anchor);
    absorb_anchor(&mut sponge, &proof.end_anchor);
    absorb_accumulator(&mut sponge, &proof.start_accumulator);
    absorb_accumulator(&mut sponge, &proof.end_accumulator);
    absorb_digest(&mut sponge, &proof.folded_witness_root);
    sponge.absorb(Block128::from(proof.step_count as u128));
    absorb_decider_proof(&mut sponge, &proof.decider);
    sponge.finalize()
}

fn history_anchor_digest(anchor: &HeaderChainAnchor) -> Digest {
    let mut sponge = Poseidon2bSponge::with_iv(capacity_iv(TAG_HISTPRF));
    sponge.absorb(Block128::from(0x4849_5354_414E_4331u128)); // "HISTANC1"
    absorb_anchor(&mut sponge, anchor);
    sponge.finalize()
}

fn history_start_state_from_proof(
    proof: &HistoryProof,
) -> Result<HistoryAccumulationState, HistoryProofError> {
    HistoryAccumulationState::from_anchor(&proof.start_anchor, proof.start_accumulator.clone())
}

fn history_end_state_from_proof(
    proof: &HistoryProof,
) -> Result<HistoryAccumulationState, HistoryProofError> {
    let state = HistoryAccumulationState {
        version: HISTORY_PROOF_VERSION,
        height: proof.end_anchor.height,
        block_id: proof.end_anchor.block_id,
        projection_root: proof.end_anchor.projection_root,
        accumulator: proof.end_accumulator.clone(),
        folded_witness_root: proof.folded_witness_root,
        step_count: proof.step_count,
    };
    validate_accumulation_state_shape(&state)?;
    Ok(state)
}

fn verify_history_arc_pcd_boundary(
    accumulator: &HistoryArcPcdAccumulator,
    start_state: &HistoryAccumulationState,
    end_state: &HistoryAccumulationState,
) -> Result<(), HistoryProofError> {
    if accumulator.version != HISTORY_PROOF_VERSION {
        return Err(HistoryProofError::UnsupportedVersion {
            version: accumulator.version,
        });
    }
    if accumulator.step_relation_digest != history_arc_pcd_step_relation_digest()
        || accumulator.start_state_digest != history_accumulation_state_digest(start_state)
        || accumulator.current_state_digest != history_accumulation_state_digest(end_state)
        || accumulator.step_count != end_state.step_count.saturating_sub(start_state.step_count)
    {
        return Err(HistoryProofError::BadDeciderProof);
    }
    Ok(())
}

fn history_accumulator_digest(accumulator: &ChainAccumulator) -> Digest {
    let mut sponge = Poseidon2bSponge::with_iv(capacity_iv(TAG_HISTPRF));
    sponge.absorb(Block128::from(0x4849_5354_4143_4431u128)); // "HISTACD1"
    absorb_accumulator(&mut sponge, accumulator);
    sponge.finalize()
}

pub fn history_chain_accumulator_fields(
    accumulator: &ChainAccumulator,
) -> [Block128; HISTORY_CHAIN_ACCUMULATOR_FIELDS] {
    let mut fields = [Block128::ZERO; HISTORY_CHAIN_ACCUMULATOR_FIELDS];
    let mut idx = 0;
    write_accumulator_fields(&mut fields, &mut idx, accumulator);
    debug_assert_eq!(idx, HISTORY_CHAIN_ACCUMULATOR_FIELDS);
    fields
}

pub fn history_accumulation_state_fields(
    state: &HistoryAccumulationState,
) -> [Block128; HISTORY_ACCUMULATION_STATE_FIELDS] {
    let mut fields = [Block128::ZERO; HISTORY_ACCUMULATION_STATE_FIELDS];
    let mut idx = 0;
    write_accumulation_state_fields(&mut fields, &mut idx, state);
    debug_assert_eq!(idx, HISTORY_ACCUMULATION_STATE_FIELDS);
    fields
}

pub fn history_accumulation_state_hash_fields(
    state: &HistoryAccumulationState,
) -> [Block128; HISTORY_ACCUMULATION_STATE_HASH_FIELDS] {
    history_accumulation_state_hash_fields_from_fields(&history_accumulation_state_fields(state))
}

pub fn history_accumulation_state_hash_fields_from_fields(
    body: &[Block128; HISTORY_ACCUMULATION_STATE_FIELDS],
) -> [Block128; HISTORY_ACCUMULATION_STATE_HASH_FIELDS] {
    let mut fields = [Block128::ZERO; HISTORY_ACCUMULATION_STATE_HASH_FIELDS];
    fields[0] = Block128::from(HISTORY_ACCUMULATION_STATE_HASH_MARKER);
    fields[1] = Block128::from(HISTORY_ACCUMULATION_STATE_FIELDS as u128);
    fields[2..].copy_from_slice(body);
    fields
}

pub fn history_step_statement_fields(
    statement: &HistoryStepStatement,
) -> [Block128; HISTORY_STEP_STATEMENT_FIELDS] {
    let mut fields = [Block128::ZERO; HISTORY_STEP_STATEMENT_FIELDS];
    let mut idx = 0;
    write_step_statement_fields(&mut fields, &mut idx, statement);
    debug_assert_eq!(idx, HISTORY_STEP_STATEMENT_FIELDS);
    fields
}

pub fn history_pcd_step_statement_fields(
    statement: &HistoryPcdStepStatement,
) -> [Block128; HISTORY_PCD_STEP_STATEMENT_FIELDS] {
    let mut fields = [Block128::ZERO; HISTORY_PCD_STEP_STATEMENT_FIELDS];
    let mut idx = 0;
    write_field(
        &mut fields,
        &mut idx,
        Block128::from(statement.version as u128),
    );
    write_accumulation_state_fields(&mut fields, &mut idx, &statement.previous_state);
    write_step_statement_fields(&mut fields, &mut idx, &statement.step_statement);
    write_accumulation_state_fields(&mut fields, &mut idx, &statement.next_state);
    debug_assert_eq!(idx, HISTORY_PCD_STEP_STATEMENT_FIELDS);
    fields
}

pub fn history_pcd_step_statement_hash_fields(
    statement: &HistoryPcdStepStatement,
) -> [Block128; HISTORY_PCD_STEP_HASH_FIELDS] {
    history_pcd_step_statement_hash_fields_from_fields(&history_pcd_step_statement_fields(
        statement,
    ))
}

pub fn history_pcd_step_statement_hash_fields_from_fields(
    body: &[Block128; HISTORY_PCD_STEP_STATEMENT_FIELDS],
) -> [Block128; HISTORY_PCD_STEP_HASH_FIELDS] {
    let mut fields = [Block128::ZERO; HISTORY_PCD_STEP_HASH_FIELDS];
    fields[0] = Block128::from(HISTORY_PCD_STEP_HASH_MARKER);
    fields[1] = Block128::from(HISTORY_PCD_STEP_STATEMENT_FIELDS as u128);
    fields[2..].copy_from_slice(body);
    fields
}

pub fn history_arc_pcd_accumulator_fields(
    accumulator: &HistoryArcPcdAccumulator,
) -> [Block128; HISTORY_ARC_PCD_ACCUMULATOR_FIELDS] {
    let mut fields = [Block128::ZERO; HISTORY_ARC_PCD_ACCUMULATOR_FIELDS];
    let mut idx = 0;
    write_field(
        &mut fields,
        &mut idx,
        Block128::from(accumulator.version as u128),
    );
    write_field(
        &mut fields,
        &mut idx,
        Block128::from(accumulator.step_count as u128),
    );
    write_digest_fields(&mut fields, &mut idx, &accumulator.start_state_digest);
    write_digest_fields(&mut fields, &mut idx, &accumulator.current_state_digest);
    write_digest_fields(&mut fields, &mut idx, &accumulator.pcd_root);
    write_digest_fields(&mut fields, &mut idx, &accumulator.step_relation_digest);
    write_digest_fields(&mut fields, &mut idx, &accumulator.transcript_digest);
    debug_assert_eq!(idx, HISTORY_ARC_PCD_ACCUMULATOR_FIELDS);
    fields
}

pub fn history_arc_pcd_accumulator_hash_fields(
    accumulator: &HistoryArcPcdAccumulator,
) -> [Block128; HISTORY_ARC_PCD_ACCUMULATOR_HASH_FIELDS] {
    history_arc_pcd_accumulator_hash_fields_from_fields(&history_arc_pcd_accumulator_fields(
        accumulator,
    ))
}

pub fn history_arc_pcd_accumulator_hash_fields_from_fields(
    body: &[Block128; HISTORY_ARC_PCD_ACCUMULATOR_FIELDS],
) -> [Block128; HISTORY_ARC_PCD_ACCUMULATOR_HASH_FIELDS] {
    let mut fields = [Block128::ZERO; HISTORY_ARC_PCD_ACCUMULATOR_HASH_FIELDS];
    fields[0] = Block128::from(HISTORY_ARC_PCD_ACCUMULATOR_HASH_MARKER);
    fields[1] = Block128::from(HISTORY_ARC_PCD_ACCUMULATOR_FIELDS as u128);
    fields[2..].copy_from_slice(body);
    fields
}

pub fn history_arc_pcd_recursive_step_statement_fields(
    statement: &HistoryArcPcdRecursiveStepStatement,
) -> [Block128; HISTORY_ARC_PCD_RECURSIVE_STEP_FIELDS] {
    let mut fields = [Block128::ZERO; HISTORY_ARC_PCD_RECURSIVE_STEP_FIELDS];
    let mut idx = 0;
    write_field(
        &mut fields,
        &mut idx,
        Block128::from(statement.version as u128),
    );
    write_field(
        &mut fields,
        &mut idx,
        Block128::from(statement.step_count as u128),
    );
    write_digest_fields(&mut fields, &mut idx, &statement.previous_proof_digest);
    write_digest_fields(
        &mut fields,
        &mut idx,
        &statement.previous_accumulator_digest,
    );
    write_digest_fields(&mut fields, &mut idx, &statement.pcd_step_digest);
    write_digest_fields(&mut fields, &mut idx, &statement.one_step_proof_digest);
    write_digest_fields(&mut fields, &mut idx, &statement.next_accumulator_digest);
    debug_assert_eq!(idx, HISTORY_ARC_PCD_RECURSIVE_STEP_FIELDS);
    fields
}

pub fn history_arc_pcd_recursive_step_statement_hash_fields(
    statement: &HistoryArcPcdRecursiveStepStatement,
) -> [Block128; HISTORY_ARC_PCD_RECURSIVE_STEP_HASH_FIELDS] {
    history_arc_pcd_recursive_step_statement_hash_fields_from_fields(
        &history_arc_pcd_recursive_step_statement_fields(statement),
    )
}

pub fn history_arc_pcd_recursive_step_statement_hash_fields_from_fields(
    body: &[Block128; HISTORY_ARC_PCD_RECURSIVE_STEP_FIELDS],
) -> [Block128; HISTORY_ARC_PCD_RECURSIVE_STEP_HASH_FIELDS] {
    let mut fields = [Block128::ZERO; HISTORY_ARC_PCD_RECURSIVE_STEP_HASH_FIELDS];
    fields[0] = Block128::from(HISTORY_ARC_PCD_RECURSIVE_STEP_HASH_MARKER);
    fields[1] = Block128::from(HISTORY_ARC_PCD_RECURSIVE_STEP_FIELDS as u128);
    fields[2..].copy_from_slice(body);
    fields
}

pub fn history_arc_pcd_recursive_chunk_step_statement_fields(
    statement: &HistoryArcPcdRecursiveChunkStepStatement,
) -> [Block128; HISTORY_ARC_PCD_RECURSIVE_CHUNK_STEP_FIELDS] {
    let mut fields = [Block128::ZERO; HISTORY_ARC_PCD_RECURSIVE_CHUNK_STEP_FIELDS];
    let mut idx = 0;
    write_field(
        &mut fields,
        &mut idx,
        Block128::from(statement.version as u128),
    );
    write_field(
        &mut fields,
        &mut idx,
        Block128::from(statement.chunk_len as u128),
    );
    write_field(
        &mut fields,
        &mut idx,
        Block128::from(statement.previous_step_count as u128),
    );
    write_field(
        &mut fields,
        &mut idx,
        Block128::from(statement.step_count as u128),
    );
    write_digest_fields(&mut fields, &mut idx, &statement.previous_proof_digest);
    write_digest_fields(
        &mut fields,
        &mut idx,
        &statement.previous_accumulator_digest,
    );
    write_digest_fields(&mut fields, &mut idx, &statement.chunk_step_proof_digest);
    write_digest_fields(&mut fields, &mut idx, &statement.next_accumulator_digest);
    debug_assert_eq!(idx, HISTORY_ARC_PCD_RECURSIVE_CHUNK_STEP_FIELDS);
    fields
}

pub fn history_arc_pcd_recursive_chunk_step_statement_hash_fields(
    statement: &HistoryArcPcdRecursiveChunkStepStatement,
) -> [Block128; HISTORY_ARC_PCD_RECURSIVE_CHUNK_STEP_HASH_FIELDS] {
    history_arc_pcd_recursive_chunk_step_statement_hash_fields_from_fields(
        &history_arc_pcd_recursive_chunk_step_statement_fields(statement),
    )
}

pub fn history_arc_pcd_recursive_chunk_step_statement_hash_fields_from_fields(
    body: &[Block128; HISTORY_ARC_PCD_RECURSIVE_CHUNK_STEP_FIELDS],
) -> [Block128; HISTORY_ARC_PCD_RECURSIVE_CHUNK_STEP_HASH_FIELDS] {
    let mut fields = [Block128::ZERO; HISTORY_ARC_PCD_RECURSIVE_CHUNK_STEP_HASH_FIELDS];
    fields[0] = Block128::from(HISTORY_ARC_PCD_RECURSIVE_CHUNK_STEP_HASH_MARKER);
    fields[1] = Block128::from(HISTORY_ARC_PCD_RECURSIVE_CHUNK_STEP_FIELDS as u128);
    fields[2..].copy_from_slice(body);
    fields
}

fn write_accumulation_state_fields(
    fields: &mut [Block128],
    idx: &mut usize,
    state: &HistoryAccumulationState,
) {
    write_field(fields, idx, Block128::from(state.version as u128));
    write_field(fields, idx, Block128::from(state.height as u128));
    write_digest_fields(fields, idx, &state.block_id);
    write_digest_fields(fields, idx, &state.projection_root);
    write_accumulator_fields(fields, idx, &state.accumulator);
    write_digest_fields(fields, idx, &state.folded_witness_root);
    write_field(fields, idx, Block128::from(state.step_count as u128));
}

fn write_step_statement_fields(
    fields: &mut [Block128],
    idx: &mut usize,
    statement: &HistoryStepStatement,
) {
    write_field(fields, idx, Block128::from(statement.version as u128));
    write_digest_fields(fields, idx, &statement.previous_block_id);
    write_digest_fields(fields, idx, &statement.next_block_id);
    write_digest_fields(fields, idx, &statement.previous_projection_root);
    write_digest_fields(fields, idx, &statement.next_projection_root);
    write_accumulator_fields(fields, idx, &statement.previous_accumulator);
    write_accumulator_fields(fields, idx, &statement.next_accumulator);
    write_digest_fields(fields, idx, &statement.header_projection_digest);
    write_digest_fields(fields, idx, &statement.claim_digest);
    write_digest_fields(fields, idx, &statement.folded_item_digest);
}

fn write_accumulator_fields(
    fields: &mut [Block128],
    idx: &mut usize,
    accumulator: &ChainAccumulator,
) {
    write_field(fields, idx, Block128::from(accumulator.height as u128));
    write_digest_fields(fields, idx, &accumulator.state_root);
    write_digest_fields(fields, idx, &accumulator.chain_hash);
}

fn write_digest_fields(fields: &mut [Block128], idx: &mut usize, digest: &Digest) {
    let [lo, hi] = digest_to_fields(digest);
    write_field(fields, idx, lo);
    write_field(fields, idx, hi);
}

fn write_field(fields: &mut [Block128], idx: &mut usize, value: Block128) {
    fields[*idx] = value;
    *idx += 1;
}

fn tagged_pair_digest(tag: u128, left: &Digest, right: &Digest) -> Digest {
    history_tagged_pair_digest_from_hash_fields(&history_tagged_pair_hash_fields(tag, left, right))
}

pub fn history_tagged_pair_hash_fields(
    tag: u128,
    left: &Digest,
    right: &Digest,
) -> [Block128; HISTORY_TAGGED_PAIR_HASH_FIELDS] {
    let mut fields = [Block128::ZERO; HISTORY_TAGGED_PAIR_HASH_FIELDS];
    fields[0] = Block128::from(tag);
    fields[1] = Block128::from(4u128);
    let [left_lo, left_hi] = digest_to_fields(left);
    let [right_lo, right_hi] = digest_to_fields(right);
    fields[2] = left_lo;
    fields[3] = left_hi;
    fields[4] = right_lo;
    fields[5] = right_hi;
    fields
}

pub fn history_tagged_pair_digest_from_hash_fields(
    fields: &[Block128; HISTORY_TAGGED_PAIR_HASH_FIELDS],
) -> Digest {
    digest_fixed_no_pad_from_fields(fields)
}

fn absorb_decider_proof(sponge: &mut Poseidon2bSponge, proof: &HistoryDeciderProof) {
    absorb_digest(sponge, &proof.statement_digest);
    absorb_arc_pcd_accumulator(sponge, &proof.pcd_accumulator);
    absorb_digest(sponge, &proof.accumulator_commitment);
    absorb_digest(sponge, &proof.step_relation_commitment);
    absorb_digest(sponge, &proof.pcs_commitment);
    absorb_digest(sponge, &proof.opening_digest);
    absorb_digest(sponge, &proof.transcript_digest);
    absorb_digest(sponge, &proof.hash_proofs_digest);
    absorb_digest(sponge, &proof.one_step_proof_digest);
    absorb_digest(sponge, &proof.recursive_head_digest);
    absorb_digest(sponge, &proof.recursive_chunk_head_digest);
    for digest in &proof.reserved {
        absorb_digest(sponge, digest);
    }
}

fn absorb_arc_pcd_accumulator(
    sponge: &mut Poseidon2bSponge,
    accumulator: &HistoryArcPcdAccumulator,
) {
    sponge.absorb(Block128::from(accumulator.version as u128));
    sponge.absorb(Block128::from(accumulator.step_count as u128));
    absorb_digest(sponge, &accumulator.start_state_digest);
    absorb_digest(sponge, &accumulator.current_state_digest);
    absorb_digest(sponge, &accumulator.pcd_root);
    absorb_digest(sponge, &accumulator.step_relation_digest);
    absorb_digest(sponge, &accumulator.transcript_digest);
}

fn history_transition_witness_item_digest(
    item: &HistoryTransitionWitnessItem,
    projection: &Digest,
) -> Digest {
    let mut sponge = Poseidon2bSponge::with_iv(capacity_iv(TAG_HISTPRF));
    sponge.absorb(Block128::from(0x4849_5354_4954_4d31u128)); // "HISTITM1"
    sponge.absorb(Block128::from(item.header.height as u128));
    absorb_digest(&mut sponge, &item.block_id);
    absorb_digest(&mut sponge, projection);
    absorb_digest(&mut sponge, &item.parent_state_root);
    absorb_digest(&mut sponge, &item.child_state_root);
    sponge.absorb_pair(item.chain_claim[0], item.chain_claim[1]);
    absorb_digest(&mut sponge, &item.claim_digest);
    sponge.finalize()
}

pub fn history_claim_digest_from_fields(fields: &[Block128; HISTORY_CLAIM_FIELDS]) -> Digest {
    let mut sponge = Poseidon2bSponge::with_iv(capacity_iv(TAG_HISTCLM));
    for pair in fields.chunks_exact(2) {
        sponge.absorb_pair(pair[0], pair[1]);
    }
    sponge.finalize_no_pad()
}

pub fn history_chain_claim_from_digest(digest: &Digest) -> [Block128; 2] {
    digest_to_fields(digest)
}

fn digest_fixed_no_pad_from_fields(fields: &[Block128]) -> Digest {
    debug_assert_eq!(fields.len() % 2, 0);
    let mut sponge = Poseidon2bSponge::with_iv(capacity_iv(TAG_HISTPRF));
    for pair in fields.chunks_exact(2) {
        sponge.absorb_pair(pair[0], pair[1]);
    }
    sponge.finalize_no_pad()
}

fn fixed_hash_input(fields: &[Block128], expected_digest: &Digest) -> FixedFieldHashInputs {
    FixedFieldHashInputs {
        fields: fields.to_vec(),
        expected_digest: digest_to_fields(expected_digest),
    }
}

struct HistoryTracingPoseidon2bChannel {
    inner: noid_poseidon2b::channel::Poseidon2bChannel,
    transcript: Vec<FiatShamirTraceOp>,
}

impl HistoryTracingPoseidon2bChannel {
    fn new() -> Self {
        Self {
            inner: noid_poseidon2b::channel::Poseidon2bChannel::new(),
            transcript: Vec::new(),
        }
    }

    fn into_transcript(self) -> Vec<FiatShamirTraceOp> {
        self.transcript
    }
}

impl FiatShamir<Block128> for HistoryTracingPoseidon2bChannel {
    fn absorb(&mut self, elem: Block128) {
        self.transcript.push(FiatShamirTraceOp::Absorb(elem));
        self.inner.absorb(elem);
    }

    fn squeeze(&mut self) -> Block128 {
        let challenge = self.inner.squeeze();
        self.transcript.push(FiatShamirTraceOp::Squeeze(challenge));
        challenge
    }
}

fn map_fs_transcript_error(error: FiatShamirTranscriptError) -> HistoryProofError {
    match error {
        FiatShamirTranscriptError::EmptyTrace
        | FiatShamirTranscriptError::TooManyTraces
        | FiatShamirTranscriptError::TraceTooLong
        | FiatShamirTranscriptError::TooManyPermutations
        | FiatShamirTranscriptError::InvalidSqueeze
        | FiatShamirTranscriptError::NoPermutation
        | FiatShamirTranscriptError::ProofShape
        | FiatShamirTranscriptError::ProofRejected => HistoryProofError::BadDeciderProof,
    }
}

fn prove_fixed_hash(
    params: FixedFieldHashParams,
    fields: &[Block128],
    expected_digest: &Digest,
) -> Result<FixedFieldHashProofKillShot, HistoryProofError> {
    prove_fixed_hash_batch(params, &[(fields, expected_digest)])
}

fn prove_fixed_hash_batch(
    params: FixedFieldHashParams,
    inputs: &[(&[Block128], &Digest)],
) -> Result<FixedFieldHashProofKillShot, HistoryProofError> {
    let inputs: Vec<_> = inputs
        .iter()
        .map(|(fields, expected_digest)| fixed_hash_input(fields, expected_digest))
        .collect();
    let mut channel = noid_poseidon2b::channel::Poseidon2bChannel::new();
    let (proof, reductions) = prove_fixed_field_hash_killshot(params, &inputs, &mut channel);
    if discharge_fixed_field_hash_reductions_native(params, &inputs, &reductions) {
        Ok(proof)
    } else {
        Err(HistoryProofError::BadDeciderHashDischarge)
    }
}

fn verify_and_discharge_fixed_hash_batch_with_trace(
    params: FixedFieldHashParams,
    proof: &FixedFieldHashProofKillShot,
    inputs: &[(&[Block128], &Digest)],
) -> Result<Vec<FiatShamirTraceOp>, HistoryProofError> {
    for (fields, expected_digest) in inputs {
        if digest_fixed_no_pad_from_fields(fields) != **expected_digest {
            return Err(HistoryProofError::BadDeciderHashProof);
        }
    }
    let inputs: Vec<_> = inputs
        .iter()
        .map(|(fields, expected_digest)| fixed_hash_input(fields, expected_digest))
        .collect();
    let mut channel = HistoryTracingPoseidon2bChannel::new();
    let reductions = verify_fixed_field_hash_killshot(params, proof, &inputs, &mut channel)
        .ok_or(HistoryProofError::BadDeciderHashProof)?;
    if discharge_fixed_field_hash_reductions_native(params, &inputs, &reductions) {
        Ok(channel.into_transcript())
    } else {
        Err(HistoryProofError::BadDeciderHashDischarge)
    }
}

fn verify_and_discharge_fixed_hash(
    params: FixedFieldHashParams,
    proof: &FixedFieldHashProofKillShot,
    fields: &[Block128],
    expected_digest: &Digest,
) -> Result<(), HistoryProofError> {
    verify_and_discharge_fixed_hash_batch(params, proof, &[(fields, expected_digest)])
}

fn verify_and_discharge_fixed_hash_batch(
    params: FixedFieldHashParams,
    proof: &FixedFieldHashProofKillShot,
    inputs: &[(&[Block128], &Digest)],
) -> Result<(), HistoryProofError> {
    for (fields, expected_digest) in inputs {
        if digest_fixed_no_pad_from_fields(fields) != **expected_digest {
            return Err(HistoryProofError::BadDeciderHashProof);
        }
    }
    let inputs: Vec<_> = inputs
        .iter()
        .map(|(fields, expected_digest)| fixed_hash_input(fields, expected_digest))
        .collect();
    let mut channel = noid_poseidon2b::channel::Poseidon2bChannel::new();
    let reductions = verify_fixed_field_hash_killshot(params, proof, &inputs, &mut channel)
        .ok_or(HistoryProofError::BadDeciderHashProof)?;
    if discharge_fixed_field_hash_reductions_native(params, &inputs, &reductions) {
        Ok(())
    } else {
        Err(HistoryProofError::BadDeciderHashDischarge)
    }
}

fn canonical_digest(tag: u128, absorb: impl FnOnce(&mut Poseidon2bSponge)) -> Digest {
    let mut sponge = Poseidon2bSponge::with_iv(capacity_iv(TAG_HISTPRF));
    sponge.absorb(Block128::from(tag));
    sponge.absorb(Block128::from(HISTORY_PROOF_VERSION as u128));
    absorb(&mut sponge);
    sponge.finalize()
}

fn absorb_len(sponge: &mut Poseidon2bSponge, len: usize) {
    sponge.absorb(Block128::from(len as u128));
}

fn absorb_round_polynomial(sponge: &mut Poseidon2bSponge, poly: &RoundPolynomial<Block128>) {
    sponge.absorb(Block128::from(HISTRPY1));
    absorb_len(sponge, poly.coeffs.len());
    for coeff in &poly.coeffs {
        sponge.absorb(*coeff);
    }
}

fn absorb_round_polynomials(sponge: &mut Poseidon2bSponge, polys: &[RoundPolynomial<Block128>]) {
    absorb_len(sponge, polys.len());
    for poly in polys {
        absorb_round_polynomial(sponge, poly);
    }
}

fn absorb_batch_eval_round(sponge: &mut Poseidon2bSponge, round: &BatchEvalRound) {
    for eval in round.evals {
        sponge.absorb(eval);
    }
}

fn absorb_batch_eval_rounds(sponge: &mut Poseidon2bSponge, rounds: &[BatchEvalRound]) {
    sponge.absorb(Block128::from(HISTBEV1));
    absorb_len(sponge, rounds.len());
    for round in rounds {
        absorb_batch_eval_round(sponge, round);
    }
}

fn absorb_linear_eval_proof(sponge: &mut Poseidon2bSponge, proof: &LinearEvalProof) {
    sponge.absorb(Block128::from(HISTLEV1));
    absorb_batch_eval_rounds(sponge, &proof.rounds);
    sponge.absorb(proof.b_final);
}

fn absorb_multi_batch_eval_proof(sponge: &mut Poseidon2bSponge, proof: &MultiBatchEvalProof) {
    sponge.absorb(Block128::from(HISTMBV1));
    absorb_batch_eval_rounds(sponge, &proof.rounds);
    absorb_len(sponge, proof.b_finals.len());
    for final_value in &proof.b_finals {
        sponge.absorb(*final_value);
    }
}

fn absorb_block_spine_unified_proof(sponge: &mut Poseidon2bSponge, proof: &BlockSpineUnifiedProof) {
    sponge.absorb(Block128::from(HISTBKU1));
    absorb_round_polynomials(sponge, &proof.round_polys);
    sponge.absorb(proof.s_in_dec_at_r);
    sponge.absorb(proof.s_out_dec_at_r);
    sponge.absorb(proof.state_dec_at_r);
    sponge.absorb(proof.state_at_r);
    for value in proof.s_out_lane_dec_at_r {
        sponge.absorb(value);
    }
    for value in proof.state_lane_dec_at_r {
        sponge.absorb(value);
    }
}

fn absorb_block_spine_shift_proof(sponge: &mut Poseidon2bSponge, proof: &BlockSpineShiftProof) {
    sponge.absorb(Block128::from(HISTBKS1));
    absorb_round_polynomials(sponge, &proof.round_polys);
    sponge.absorb(proof.s_in_at_r2);
    sponge.absorb(proof.s_out_at_r2);
    sponge.absorb(proof.state_at_r2);
}

fn absorb_block_spine_killshot_proof(
    sponge: &mut Poseidon2bSponge,
    proof: &BlockSpineKillShotProof,
) {
    sponge.absorb(Block128::from(HISTBKK1));
    absorb_block_spine_unified_proof(sponge, &proof.main);
    absorb_block_spine_shift_proof(sponge, &proof.shift);
}

fn absorb_fixed_field_hash_proof(
    sponge: &mut Poseidon2bSponge,
    proof: &FixedFieldHashProofKillShot,
) {
    sponge.absorb(Block128::from(HISTFXH1));
    absorb_len(sponge, proof.n_claims);
    absorb_len(sponge, proof.n_fields);
    absorb_len(sponge, proof.num_vars);
    absorb_len(sponge, proof.live_slots);
    absorb_block_spine_killshot_proof(sponge, &proof.kill_shot);
    absorb_linear_eval_proof(sponge, &proof.chain);
    absorb_multi_batch_eval_proof(sponge, &proof.batch);
}

fn absorb_fiat_shamir_transcript_batch_proof(
    sponge: &mut Poseidon2bSponge,
    proof: &FiatShamirTranscriptBatchProofKillShot,
) {
    sponge.absorb(Block128::from(HISTFST1));
    absorb_len(sponge, proof.n_traces);
    absorb_len(sponge, proof.n_ops);
    absorb_len(sponge, proof.n_permutations);
    absorb_len(sponge, proof.num_vars);
    absorb_len(sponge, proof.live_slots);
    absorb_block_spine_killshot_proof(sponge, &proof.kill_shot);
    absorb_linear_eval_proof(sponge, &proof.chain);
    absorb_multi_batch_eval_proof(sponge, &proof.batch);
}

fn absorb_history_claim_hash_proof(
    sponge: &mut Poseidon2bSponge,
    proof: &HistoryClaimHashProofKillShot,
) {
    sponge.absorb(Block128::from(HISTHCH1));
    absorb_len(sponge, proof.n_claims);
    absorb_len(sponge, proof.num_vars);
    absorb_len(sponge, proof.live_slots);
    absorb_block_spine_killshot_proof(sponge, &proof.kill_shot);
    absorb_linear_eval_proof(sponge, &proof.chain);
    absorb_multi_batch_eval_proof(sponge, &proof.batch);
}

fn absorb_history_decider_hash_proofs(
    sponge: &mut Poseidon2bSponge,
    proof: &HistoryDeciderHashProofs,
) {
    sponge.absorb(Block128::from(HISTDHP1));
    absorb_fixed_field_hash_proof(sponge, &proof.arc_accumulator_hash);
    absorb_fixed_field_hash_proof(sponge, &proof.tagged_pair_hashes);
}

fn absorb_history_step_proof(sponge: &mut Poseidon2bSponge, proof: &HistoryStepProof) {
    sponge.absorb(Block128::from(HISTHSP1));
    for field in history_step_statement_fields(&proof.statement) {
        sponge.absorb(field);
    }
    for field in proof.claim_fields {
        sponge.absorb(field);
    }
    absorb_history_claim_hash_proof(sponge, &proof.claim_hash);
}

fn absorb_history_arc_pcd_step_proof(
    sponge: &mut Poseidon2bSponge,
    proof: &HistoryArcPcdStepProof,
) {
    sponge.absorb(Block128::from(HISTASP1));
    absorb_fixed_field_hash_proof(sponge, &proof.state_hashes);
    absorb_fixed_field_hash_proof(sponge, &proof.pcd_step_hash);
    absorb_fixed_field_hash_proof(sponge, &proof.accumulator_update_hashes);
}

fn absorb_history_arc_pcd_one_step_proof(
    sponge: &mut Poseidon2bSponge,
    proof: &HistoryArcPcdOneStepProof,
) {
    sponge.absorb(Block128::from(HISTOSD1));
    absorb_history_step_proof(sponge, &proof.step);
    absorb_history_arc_pcd_step_proof(sponge, &proof.arc_step);
}

fn absorb_history_arc_pcd_chunk_step_proof(
    sponge: &mut Poseidon2bSponge,
    proof: &HistoryArcPcdChunkStepProof,
) {
    sponge.absorb(Block128::from(HISTCSD1));
    sponge.absorb(Block128::from(proof.chunk_len as u128));
    absorb_history_claim_hash_proof(sponge, &proof.claim_hash);
    absorb_fixed_field_hash_proof(sponge, &proof.state_hashes);
    absorb_fixed_field_hash_proof(sponge, &proof.pcd_step_hashes);
    absorb_fixed_field_hash_proof(sponge, &proof.accumulator_update_hashes);
}

fn absorb_history_arc_pcd_recursive_step_proof(
    sponge: &mut Poseidon2bSponge,
    proof: &HistoryArcPcdRecursiveStepProof,
) {
    sponge.absorb(Block128::from(HISTHRP1));
    absorb_fixed_field_hash_proof(sponge, &proof.recursive_hashes);
    absorb_fixed_field_hash_proof(sponge, &proof.next_proof_digest_hash);
}

fn absorb_history_arc_pcd_recursive_chunk_step_proof(
    sponge: &mut Poseidon2bSponge,
    proof: &HistoryArcPcdRecursiveChunkStepProof,
) {
    sponge.absorb(Block128::from(HISTHCP1));
    absorb_fixed_field_hash_proof(sponge, &proof.recursive_hashes);
    absorb_fixed_field_hash_proof(sponge, &proof.next_proof_digest_hash);
}

fn absorb_history_arc_pcd_recursive_head(
    sponge: &mut Poseidon2bSponge,
    head: &HistoryArcPcdRecursiveChainHead,
) {
    sponge.absorb(Block128::from(HISTHRH1));
    sponge.absorb(Block128::from(head.version as u128));
    sponge.absorb(Block128::from(head.step_count as u128));
    absorb_digest(sponge, &head.base_proof_digest);
    absorb_digest(sponge, &head.final_proof_digest);
    absorb_arc_pcd_accumulator(sponge, &head.previous_accumulator);
    for field in history_arc_pcd_recursive_step_statement_fields(&head.final_step_statement) {
        sponge.absorb(field);
    }
    absorb_history_arc_pcd_recursive_step_proof(sponge, &head.final_step_proof);
}

fn absorb_history_arc_pcd_recursive_chunk_head(
    sponge: &mut Poseidon2bSponge,
    head: &HistoryArcPcdRecursiveChunkChainHead,
) {
    sponge.absorb(Block128::from(HISTHCK1));
    sponge.absorb(Block128::from(head.version as u128));
    sponge.absorb(Block128::from(head.step_count as u128));
    sponge.absorb(Block128::from(head.chunk_count as u128));
    absorb_digest(sponge, &head.base_proof_digest);
    absorb_digest(sponge, &head.final_proof_digest);
    absorb_arc_pcd_accumulator(sponge, &head.previous_accumulator);
    for field in history_arc_pcd_recursive_chunk_step_statement_fields(&head.final_chunk_statement)
    {
        sponge.absorb(field);
    }
    absorb_history_arc_pcd_recursive_chunk_step_proof(sponge, &head.final_chunk_proof);
    absorb_fiat_shamir_transcript_batch_proof(sponge, &head.final_chunk_verifier_transcript);
}

fn history_decider_hash_proofs_digest(
    hash_proofs: &Option<HistoryDeciderHashProofs>,
) -> Result<Digest, HistoryProofError> {
    Ok(canonical_digest(HISTDHP1, |sponge| match hash_proofs {
        Some(proof) => {
            sponge.absorb(Block128::from(HISTSOM1));
            absorb_history_decider_hash_proofs(sponge, proof);
        }
        None => sponge.absorb(Block128::from(HISTNUL1)),
    }))
}

fn history_arc_pcd_one_step_proof_digest(
    proof: &Option<HistoryArcPcdOneStepProof>,
) -> Result<Digest, HistoryProofError> {
    Ok(canonical_digest(HISTOSD1, |sponge| match proof {
        Some(proof) => {
            sponge.absorb(Block128::from(HISTSOM1));
            absorb_history_arc_pcd_one_step_proof(sponge, proof);
        }
        None => sponge.absorb(Block128::from(HISTNUL1)),
    }))
}

fn history_arc_pcd_recursive_head_digest(
    proof: &Option<HistoryArcPcdRecursiveChainHead>,
) -> Result<Digest, HistoryProofError> {
    Ok(canonical_digest(HISTHRH1, |sponge| match proof {
        Some(head) => {
            sponge.absorb(Block128::from(HISTSOM1));
            absorb_history_arc_pcd_recursive_head(sponge, head);
        }
        None => sponge.absorb(Block128::from(HISTNUL1)),
    }))
}

fn history_arc_pcd_recursive_chunk_head_digest(
    proof: &Option<HistoryArcPcdRecursiveChunkChainHead>,
) -> Result<Digest, HistoryProofError> {
    Ok(canonical_digest(HISTHCK1, |sponge| match proof {
        Some(head) => {
            sponge.absorb(Block128::from(HISTSOM1));
            absorb_history_arc_pcd_recursive_chunk_head(sponge, head);
        }
        None => sponge.absorb(Block128::from(HISTNUL1)),
    }))
}

fn history_claim_hash_input(
    fields: &[Block128; HISTORY_CLAIM_FIELDS],
    claim_digest: &Digest,
) -> HistoryClaimHashInputs {
    HistoryClaimHashInputs {
        fields: *fields,
        expected_claim: digest_to_fields(claim_digest),
    }
}

fn verify_step_claim_fields(
    statement: &HistoryStepStatement,
    fields: &[Block128; HISTORY_CLAIM_FIELDS],
) -> Result<(), HistoryProofError> {
    if fields[0].to_u128() != HISTORY_PROOF_VERSION as u128 {
        return Err(HistoryProofError::BadStepClaimFields);
    }
    let claim_height = fields[1].to_u128();
    if claim_height > u64::MAX as u128 || claim_height as u64 != statement.next_accumulator.height {
        return Err(HistoryProofError::BadStepClaimFields);
    }
    if claim_digest_field_pair(fields[2], fields[3]) != statement.next_block_id
        || claim_digest_field_pair(fields[4], fields[5]) != statement.previous_block_id
        || claim_digest_field_pair(fields[6], fields[7])
            != statement.previous_accumulator.state_root
        || claim_digest_field_pair(fields[8], fields[9]) != statement.next_accumulator.state_root
    {
        return Err(HistoryProofError::BadStepClaimFields);
    }
    Ok(())
}

fn claim_digest_field_pair(lo: Block128, hi: Block128) -> Digest {
    let mut out = [0u8; 32];
    out[..16].copy_from_slice(&lo.to_u128().to_le_bytes());
    out[16..].copy_from_slice(&hi.to_u128().to_le_bytes());
    out
}

fn extend_projection_root_from_digest(
    previous_root: &Digest,
    projection: &Digest,
    height: u64,
) -> Digest {
    let mut sponge = Poseidon2bSponge::with_iv(capacity_iv(TAG_HDRANCH));
    absorb_digest(&mut sponge, previous_root);
    absorb_digest(&mut sponge, projection);
    sponge.absorb(Block128::from(height as u128));
    sponge.finalize()
}

fn absorb_accumulator(sponge: &mut Poseidon2bSponge, accumulator: &ChainAccumulator) {
    sponge.absorb(Block128::from(accumulator.height as u128));
    absorb_digest(sponge, &accumulator.state_root);
    absorb_digest(sponge, &accumulator.chain_hash);
}

fn absorb_anchor(sponge: &mut Poseidon2bSponge, anchor: &HeaderChainAnchor) {
    sponge.absorb(Block128::from(anchor.height as u128));
    absorb_digest(sponge, &anchor.block_id);
    absorb_digest(sponge, &anchor.state_root);
    absorb_digest(sponge, &anchor.tx_root);
    absorb_address(sponge, &anchor.miner_address);
    sponge.absorb(Block128::from(anchor.log_slots as u128));
    sponge.absorb(Block128::from(anchor.active_slot_count as u128));
    sponge.absorb(Block128::from(anchor.alloc_counter as u128));
    absorb_digest(sponge, &anchor.cumulative_chainwork);
    absorb_digest(sponge, &anchor.projection_root);
}

fn absorb_digest(sponge: &mut Poseidon2bSponge, digest: &Digest) {
    let [lo, hi] = digest_to_fields(digest);
    sponge.absorb_pair(lo, hi);
}

fn digest_to_fields(digest: &Digest) -> [Block128; 2] {
    [
        Block128::from(u128::from_le_bytes(digest[..16].try_into().unwrap())),
        Block128::from(u128::from_le_bytes(digest[16..].try_into().unwrap())),
    ]
}

fn absorb_address(sponge: &mut Poseidon2bSponge, address: &Address) {
    absorb_digest(sponge, address.as_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use noid_chain::hash_block_header;
    use noid_chain::header_anchor::compute_header_chain_anchor;
    use noid_poseidon2b::primitives::Address;

    fn digest(seed: u8) -> Digest {
        [seed; 32]
    }

    fn header(height: u64, prev: Digest, state_seed: u8) -> BlockHeader {
        BlockHeader {
            prev_block_hash: prev,
            state_root: digest(state_seed),
            tx_root: digest(state_seed ^ 0x55),
            timestamp: 1_767_225_600 + height,
            height,
            miner_address: Address([0x44; 32]),
            nonce: height as u128,
            difficulty_target: digest(0x7f),
            log_slots: 16,
            active_slot_count: height,
            alloc_counter: height * 2,
        }
    }

    fn claim(
        height: u64,
        block_id: Digest,
        parent_block_id: Digest,
        parent_state_root: Digest,
        child_state_root: Digest,
    ) -> ([Block128; HISTORY_CLAIM_FIELDS], Digest, [Block128; 2]) {
        let mut fields = std::array::from_fn(|i| {
            Block128::from((height as u128).wrapping_mul(0x9E37_79B9_7F4A_7C15) + i as u128)
        });
        fields[0] = Block128::from(HISTORY_PROOF_VERSION as u128);
        fields[1] = Block128::from(height as u128);
        write_digest_fields(&mut fields, 2, &block_id);
        write_digest_fields(&mut fields, 4, &parent_block_id);
        write_digest_fields(&mut fields, 6, &parent_state_root);
        write_digest_fields(&mut fields, 8, &child_state_root);
        let digest = history_claim_digest_from_fields(&fields);
        let chain_claim = digest_to_fields(&digest);
        (fields, digest, chain_claim)
    }

    fn write_digest_fields(
        fields: &mut [Block128; HISTORY_CLAIM_FIELDS],
        offset: usize,
        digest: &Digest,
    ) {
        let [lo, hi] = digest_to_fields(digest);
        fields[offset] = lo;
        fields[offset + 1] = hi;
    }

    fn start_state() -> (BlockHeader, HeaderChainAnchor, ChainAccumulator) {
        let h0 = header(0, [0u8; 32], 1);
        let anchor =
            compute_header_chain_anchor(std::iter::once(&h0), digest(0xaa)).expect("anchor");
        let accumulator = ChainAccumulator {
            height: anchor.height,
            state_root: anchor.state_root,
            chain_hash: digest(0x11),
        };
        (h0, anchor, accumulator)
    }

    fn witness(n: usize) -> (HeaderChainAnchor, ChainAccumulator, HistoryProofWitness) {
        let (mut parent, _start_anchor, start_accumulator) = start_state();
        let mut headers = vec![parent.clone()];
        let mut items = Vec::with_capacity(n);

        for i in 0..n {
            let height = parent.height + 1;
            let child_state_seed = (0x20 + i as u8).max(2);
            let parent_block_id = hash_block_header(&parent);
            let mut child = header(height, parent_block_id, child_state_seed);
            let block_id = hash_block_header(&child);
            child.prev_block_hash = parent_block_id;
            let (claim_fields, claim_digest, chain_claim) = claim(
                height,
                block_id,
                parent_block_id,
                parent.state_root,
                child.state_root,
            );
            items.push(HistoryTransitionWitnessItem {
                header: child.clone(),
                block_id,
                parent_state_root: parent.state_root,
                child_state_root: child.state_root,
                claim_fields,
                chain_claim,
                claim_digest,
            });
            parent = child.clone();
            headers.push(child);
        }

        let end_anchor =
            compute_header_chain_anchor(headers.iter(), digest(0xaa)).expect("end anchor");
        (end_anchor, start_accumulator, HistoryProofWitness { items })
    }

    fn prove_n(n: usize) -> HistoryProof {
        let (_, start_anchor, _) = start_state();
        let (end_anchor, start_accumulator, witness) = witness(n);
        prove_history_native(start_anchor, end_anchor, start_accumulator, &witness)
            .expect("history proof")
    }

    #[test]
    fn history_proof_serialized_size_is_constant_for_different_lengths() {
        let p1 = prove_n(1);
        let p18 = prove_n(18);

        assert_eq!(p1.byte_len(), p18.byte_len());
        assert!(p1.byte_len() < 64 * 1024);
        assert!(p1.decider.pcd_accumulator.byte_len() < 256);
        assert!(p1.decider.hash_proofs.is_some());
        assert!(p1.decider.hash_proofs.as_ref().unwrap().byte_len() < 32 * 1024);
    }

    fn accumulation_state_n(n: usize) -> (HeaderChainAnchor, HistoryAccumulationState) {
        let (_, start_anchor, _) = start_state();
        let (end_anchor, start_accumulator, witness) = witness(n);
        let mut state =
            HistoryAccumulationState::from_anchor(&start_anchor, start_accumulator).unwrap();
        for item in &witness.items {
            state = advance_history_accumulation_native(&state, item).unwrap();
        }
        (end_anchor, state)
    }

    #[test]
    fn history_accumulation_state_size_is_constant_for_different_lengths() {
        let (_, s1) = accumulation_state_n(1);
        let (_, s18) = accumulation_state_n(18);

        assert_eq!(s1.byte_len(), s18.byte_len());
        assert!(s1.byte_len() < 256);
    }

    #[test]
    fn history_accumulation_state_matches_native_proof_envelope() {
        let (_, start_anchor, _) = start_state();
        let (end_anchor, start_accumulator, witness) = witness(18);
        let proof = prove_history_native(
            start_anchor.clone(),
            end_anchor.clone(),
            start_accumulator.clone(),
            &witness,
        )
        .expect("proof");
        let mut state =
            HistoryAccumulationState::from_anchor(&start_anchor, start_accumulator).unwrap();
        for item in &witness.items {
            state = advance_history_accumulation_native(&state, item).unwrap();
        }

        assert_eq!(state.height, end_anchor.height);
        assert_eq!(state.block_id, end_anchor.block_id);
        assert_eq!(state.projection_root, end_anchor.projection_root);
        assert_eq!(state.accumulator, proof.end_accumulator);
        assert_eq!(state.folded_witness_root, proof.folded_witness_root);
    }

    #[test]
    fn history_step_statement_size_is_constant_and_updates_roots() {
        let (_, start_anchor, start_accumulator) = start_state();
        let (end_anchor, _, witness) = witness(2);

        let step1 = build_history_step_statement(
            &start_accumulator,
            start_anchor.block_id,
            start_anchor.projection_root,
            &witness.items[0],
        )
        .expect("step 1");
        let step2 = build_history_step_statement(
            &step1.next_accumulator,
            step1.next_block_id,
            step1.next_projection_root,
            &witness.items[1],
        )
        .expect("step 2");

        assert_eq!(step1.byte_len(), step2.byte_len());
        assert_eq!(step2.next_projection_root, end_anchor.projection_root);
        assert_eq!(step2.next_accumulator.height, end_anchor.height);
        assert_eq!(step2.next_accumulator.state_root, end_anchor.state_root);
    }

    #[test]
    fn history_decider_statement_and_proof_sizes_are_constant() {
        let p1 = prove_n(1);
        let p18 = prove_n(18);
        let s1 = history_decider_statement(&p1);
        let s18 = history_decider_statement(&p18);

        assert_eq!(s1.byte_len(), s18.byte_len());
        assert_eq!(p1.decider.byte_len(), p18.decider.byte_len());
        assert_eq!(
            p1.decider.statement_digest,
            history_decider_statement_digest(&s1)
        );
    }

    #[test]
    fn history_step_proof_roundtrip_and_discharge() {
        let (_, start_anchor, start_accumulator) = start_state();
        let (_, _, witness) = witness(1);
        let (proof, reductions) = prove_history_step_native(
            &start_accumulator,
            start_anchor.block_id,
            start_anchor.projection_root,
            &witness.items[0],
        )
        .expect("step proof");

        let verified = verify_history_step_native(&proof).expect("verify step");
        assert_eq!(verified, reductions);
        discharge_history_step_native(&proof, &verified).expect("discharge step");
        assert!(proof.byte_len() < 8 * 1024);
    }

    #[test]
    fn history_pcd_step_statement_roundtrip_and_size_constant() {
        let (_, start_anchor, start_accumulator) = start_state();
        let (end_anchor, _, witness) = witness(2);
        let mut state =
            HistoryAccumulationState::from_anchor(&start_anchor, start_accumulator).unwrap();
        let mut expected_len = None;
        let mut previous_digest = None;

        for item in &witness.items {
            let (proof, reductions) = prove_history_step_native(
                &state.accumulator,
                state.block_id,
                state.projection_root,
                item,
            )
            .expect("step proof");
            let pcd = build_history_pcd_step_statement_native(&state, &proof, &reductions)
                .expect("PCD step statement");
            verify_history_pcd_step_statement_shape(&pcd).expect("PCD step shape");
            if let Some(expected_len) = expected_len {
                assert_eq!(pcd.byte_len(), expected_len);
            } else {
                expected_len = Some(pcd.byte_len());
            }
            let digest = history_pcd_step_statement_digest(&pcd);
            if let Some(previous_digest) = previous_digest {
                assert_ne!(digest, previous_digest);
            }
            previous_digest = Some(digest);
            state = pcd.next_state;
        }

        assert_eq!(state.height, end_anchor.height);
        assert_eq!(state.block_id, end_anchor.block_id);
        assert_eq!(state.projection_root, end_anchor.projection_root);
        assert_eq!(state.accumulator.state_root, end_anchor.state_root);
    }

    #[test]
    fn history_pcd_and_arc_field_projection_bind_digests() {
        let (_, start_anchor, start_accumulator) = start_state();
        let (_, _, witness) = witness(1);
        let state =
            HistoryAccumulationState::from_anchor(&start_anchor, start_accumulator).unwrap();
        let state_fields = history_accumulation_state_fields(&state);
        assert_eq!(state_fields.len(), HISTORY_ACCUMULATION_STATE_FIELDS);
        let state_hash_fields = history_accumulation_state_hash_fields(&state);
        assert_eq!(
            state_hash_fields.len(),
            HISTORY_ACCUMULATION_STATE_HASH_FIELDS
        );
        assert_eq!(
            state_hash_fields[0],
            Block128::from(HISTORY_ACCUMULATION_STATE_HASH_MARKER)
        );
        assert_eq!(
            state_hash_fields[1],
            Block128::from(HISTORY_ACCUMULATION_STATE_FIELDS as u128)
        );
        assert_eq!(
            history_accumulation_state_digest(&state),
            history_accumulation_state_digest_from_fields(&state_fields)
        );
        assert_eq!(
            history_accumulation_state_digest(&state),
            history_accumulation_state_digest_from_hash_fields(&state_hash_fields)
        );
        let mut bad_state_hash_fields = state_hash_fields;
        bad_state_hash_fields[1] += Block128::ONE;
        assert_ne!(
            history_accumulation_state_digest_from_hash_fields(&bad_state_hash_fields),
            history_accumulation_state_digest(&state)
        );

        let (proof, reductions) = prove_history_step_native(
            &state.accumulator,
            state.block_id,
            state.projection_root,
            &witness.items[0],
        )
        .expect("step proof");
        let pcd = build_history_pcd_step_statement_native(&state, &proof, &reductions).unwrap();
        let fields = history_pcd_step_statement_fields(&pcd);
        assert_eq!(fields.len(), HISTORY_PCD_STEP_STATEMENT_FIELDS);
        let hash_fields = history_pcd_step_statement_hash_fields(&pcd);
        assert_eq!(hash_fields.len(), HISTORY_PCD_STEP_HASH_FIELDS);
        assert_eq!(hash_fields[0], Block128::from(HISTORY_PCD_STEP_HASH_MARKER));
        assert_eq!(
            hash_fields[1],
            Block128::from(HISTORY_PCD_STEP_STATEMENT_FIELDS as u128)
        );
        assert_eq!(
            history_pcd_step_statement_digest(&pcd),
            history_pcd_step_statement_digest_from_fields(&fields)
        );
        assert_eq!(
            history_pcd_step_statement_digest(&pcd),
            history_pcd_step_statement_digest_from_hash_fields(&hash_fields)
        );
        let mut bad_fields = fields;
        bad_fields[13] += Block128::ONE;
        assert_ne!(
            history_pcd_step_statement_digest_from_fields(&bad_fields),
            history_pcd_step_statement_digest(&pcd)
        );
        let mut bad_hash_fields = hash_fields;
        bad_hash_fields[1] += Block128::ONE;
        assert_ne!(
            history_pcd_step_statement_digest_from_hash_fields(&bad_hash_fields),
            history_pcd_step_statement_digest(&pcd)
        );

        let arc0 = HistoryArcPcdAccumulator::from_start_state(&state).unwrap();
        let arc1 = advance_history_arc_pcd_accumulator_native(&arc0, &pcd).unwrap();
        let arc_fields = history_arc_pcd_accumulator_fields(&arc1);
        assert_eq!(arc_fields.len(), HISTORY_ARC_PCD_ACCUMULATOR_FIELDS);
        let arc_hash_fields = history_arc_pcd_accumulator_hash_fields(&arc1);
        assert_eq!(
            arc_hash_fields.len(),
            HISTORY_ARC_PCD_ACCUMULATOR_HASH_FIELDS
        );
        assert_eq!(
            arc_hash_fields[0],
            Block128::from(HISTORY_ARC_PCD_ACCUMULATOR_HASH_MARKER)
        );
        assert_eq!(
            arc_hash_fields[1],
            Block128::from(HISTORY_ARC_PCD_ACCUMULATOR_FIELDS as u128)
        );
        assert_eq!(
            history_arc_pcd_accumulator_digest(&arc1),
            history_arc_pcd_accumulator_digest_from_fields(&arc_fields)
        );
        assert_eq!(
            history_arc_pcd_accumulator_digest(&arc1),
            history_arc_pcd_accumulator_digest_from_hash_fields(&arc_hash_fields)
        );
        let mut bad_arc_fields = arc_fields;
        bad_arc_fields[3] += Block128::ONE;
        assert_ne!(
            history_arc_pcd_accumulator_digest_from_fields(&bad_arc_fields),
            history_arc_pcd_accumulator_digest(&arc1)
        );
        let mut bad_arc_hash_fields = arc_hash_fields;
        bad_arc_hash_fields[0] += Block128::ONE;
        assert_ne!(
            history_arc_pcd_accumulator_digest_from_hash_fields(&bad_arc_hash_fields),
            history_arc_pcd_accumulator_digest(&arc1)
        );

        let pair_fields = history_tagged_pair_hash_fields(
            0x4849_5354_5043_5331u128,
            &arc1.pcd_root,
            &arc1.transcript_digest,
        );
        assert_eq!(pair_fields.len(), HISTORY_TAGGED_PAIR_HASH_FIELDS);
        assert_eq!(pair_fields[0], Block128::from(0x4849_5354_5043_5331u128));
        assert_eq!(pair_fields[1], Block128::from(4u128));
        assert_eq!(
            history_tagged_pair_digest_from_hash_fields(&pair_fields),
            tagged_pair_digest(
                0x4849_5354_5043_5331u128,
                &arc1.pcd_root,
                &arc1.transcript_digest
            )
        );
        let mut bad_pair_fields = pair_fields;
        bad_pair_fields[1] += Block128::ONE;
        assert_ne!(
            history_tagged_pair_digest_from_hash_fields(&bad_pair_fields),
            history_tagged_pair_digest_from_hash_fields(&pair_fields)
        );
    }

    #[test]
    fn history_pcd_step_statement_rejects_state_tamper() {
        let (_, start_anchor, start_accumulator) = start_state();
        let (_, _, witness) = witness(1);
        let state =
            HistoryAccumulationState::from_anchor(&start_anchor, start_accumulator).unwrap();
        let (proof, reductions) = prove_history_step_native(
            &state.accumulator,
            state.block_id,
            state.projection_root,
            &witness.items[0],
        )
        .expect("step proof");
        let mut pcd = build_history_pcd_step_statement_native(&state, &proof, &reductions).unwrap();
        pcd.next_state.step_count += 1;

        assert_eq!(
            verify_history_pcd_step_statement_shape(&pcd),
            Err(HistoryProofError::BadPcdStepState)
        );
    }

    #[test]
    fn history_arc_pcd_accumulator_advances_over_pcd_steps() {
        let (_, start_anchor, start_accumulator) = start_state();
        let (end_anchor, _, witness) = witness(2);
        let mut state =
            HistoryAccumulationState::from_anchor(&start_anchor, start_accumulator).unwrap();
        let mut arc = HistoryArcPcdAccumulator::from_start_state(&state).unwrap();
        let arc_len = arc.byte_len();

        for item in &witness.items {
            let (proof, reductions) = prove_history_step_native(
                &state.accumulator,
                state.block_id,
                state.projection_root,
                item,
            )
            .expect("step proof");
            let pcd = build_history_pcd_step_statement_native(&state, &proof, &reductions)
                .expect("PCD step statement");
            arc = advance_history_arc_pcd_accumulator_native(&arc, &pcd)
                .expect("advance ARC/PCD accumulator");
            state = pcd.next_state;
            assert_eq!(arc.byte_len(), arc_len);
            assert_eq!(
                arc.current_state_digest,
                history_accumulation_state_digest(&state)
            );
            assert_eq!(arc.step_count, state.step_count);
        }

        assert_eq!(state.block_id, end_anchor.block_id);
        assert_eq!(
            arc.current_state_digest,
            history_accumulation_state_digest(&state)
        );
        assert_ne!(arc.pcd_root, [0u8; 32]);
    }

    #[test]
    fn history_arc_pcd_step_proof_roundtrip_and_size_constant() {
        let (_, start_anchor, start_accumulator) = start_state();
        let (end_anchor, _, witness) = witness(2);
        let mut state =
            HistoryAccumulationState::from_anchor(&start_anchor, start_accumulator).unwrap();
        let mut arc = HistoryArcPcdAccumulator::from_start_state(&state).unwrap();
        let mut expected_len = None;

        for item in &witness.items {
            let (step_proof, step_reductions) = prove_history_step_native(
                &state.accumulator,
                state.block_id,
                state.projection_root,
                item,
            )
            .expect("step proof");
            let pcd_step =
                build_history_pcd_step_statement_native(&state, &step_proof, &step_reductions)
                    .expect("PCD step statement");
            let native_next = advance_history_arc_pcd_accumulator_native(&arc, &pcd_step)
                .expect("native ARC/PCD step");
            let (proved_next, arc_step_proof) =
                prove_history_arc_pcd_step_native(&arc, &pcd_step).expect("ARC/PCD step proof");

            assert_eq!(proved_next, native_next);
            verify_history_arc_pcd_step_proof_native(
                &arc,
                &pcd_step,
                &proved_next,
                &arc_step_proof,
            )
            .expect("verify ARC/PCD step proof");
            if let Some(expected_len) = expected_len {
                assert_eq!(arc_step_proof.byte_len(), expected_len);
            } else {
                expected_len = Some(arc_step_proof.byte_len());
            }
            assert_eq!(arc_step_proof.state_hashes.n_claims, 2);
            assert_eq!(arc_step_proof.pcd_step_hash.n_claims, 1);
            assert_eq!(arc_step_proof.accumulator_update_hashes.n_claims, 2);
            assert!(arc_step_proof.byte_len() < 14 * 1024);

            arc = proved_next;
            state = pcd_step.next_state;
        }

        assert_eq!(state.block_id, end_anchor.block_id);
        assert_eq!(arc.step_count, 2);
    }

    #[test]
    fn history_arc_pcd_step_proof_rejects_tamper() {
        let (_, start_anchor, start_accumulator) = start_state();
        let (_, _, witness) = witness(1);
        let state =
            HistoryAccumulationState::from_anchor(&start_anchor, start_accumulator).unwrap();
        let arc = HistoryArcPcdAccumulator::from_start_state(&state).unwrap();
        let (step_proof, step_reductions) = prove_history_step_native(
            &state.accumulator,
            state.block_id,
            state.projection_root,
            &witness.items[0],
        )
        .expect("step proof");
        let pcd_step =
            build_history_pcd_step_statement_native(&state, &step_proof, &step_reductions)
                .expect("PCD step statement");
        let (mut next_arc, mut arc_step_proof) =
            prove_history_arc_pcd_step_native(&arc, &pcd_step).expect("ARC/PCD step proof");

        next_arc.pcd_root[0] ^= 1;
        assert_eq!(
            verify_history_arc_pcd_step_proof_native(&arc, &pcd_step, &next_arc, &arc_step_proof),
            Err(HistoryProofError::BadPcdStepState)
        );

        let (next_arc, _) =
            prove_history_arc_pcd_step_native(&arc, &pcd_step).expect("ARC/PCD step proof");
        arc_step_proof.accumulator_update_hashes.n_fields += 2;
        assert_eq!(
            verify_history_arc_pcd_step_proof_native(&arc, &pcd_step, &next_arc, &arc_step_proof),
            Err(HistoryProofError::BadDeciderHashProof)
        );
    }

    #[test]
    fn history_arc_pcd_chunk_step_proof_roundtrip_and_size_constant() {
        let (_, start_anchor, start_accumulator) = start_state();
        let (_, _, witness) = witness(HISTORY_ARC_PCD_CHUNK_MAX_STEPS);
        let start_state =
            HistoryAccumulationState::from_anchor(&start_anchor, start_accumulator).unwrap();
        let start_arc = HistoryArcPcdAccumulator::from_start_state(&start_state).unwrap();
        let mut expected_len = None;

        for live in [1usize, 3, HISTORY_ARC_PCD_CHUNK_MAX_STEPS] {
            let items = &witness.items[..live];
            let (next_state, next_arc, chunk_proof) =
                prove_history_arc_pcd_chunk_step_native(&start_arc, &start_state, items)
                    .expect("chunk proof");
            let (verified_state, verified_arc) = verify_history_arc_pcd_chunk_step_proof_native(
                &start_arc,
                &start_state,
                items,
                &chunk_proof,
            )
            .expect("verify chunk proof");

            assert_eq!(verified_state, next_state);
            assert_eq!(verified_arc, next_arc);
            assert_eq!(chunk_proof.chunk_len, live as u32);
            assert_eq!(
                chunk_proof.claim_hash.n_claims,
                HISTORY_ARC_PCD_CHUNK_MAX_STEPS
            );
            assert_eq!(
                chunk_proof.state_hashes.n_claims,
                HISTORY_ARC_PCD_CHUNK_MAX_STEPS * 2
            );
            assert_eq!(
                chunk_proof.pcd_step_hashes.n_claims,
                HISTORY_ARC_PCD_CHUNK_MAX_STEPS
            );
            assert_eq!(
                chunk_proof.accumulator_update_hashes.n_claims,
                HISTORY_ARC_PCD_CHUNK_MAX_STEPS * 2
            );
            if let Some(expected_len) = expected_len {
                assert_eq!(chunk_proof.byte_len(), expected_len);
            } else {
                expected_len = Some(chunk_proof.byte_len());
            }
            assert!(chunk_proof.byte_len() < 64 * 1024);
        }
    }

    #[test]
    fn history_arc_pcd_chunk_step_proof_rejects_tamper_and_bad_len() {
        let (_, start_anchor, start_accumulator) = start_state();
        let (_, _, witness) = witness(HISTORY_ARC_PCD_CHUNK_MAX_STEPS + 1);
        let start_state =
            HistoryAccumulationState::from_anchor(&start_anchor, start_accumulator).unwrap();
        let start_arc = HistoryArcPcdAccumulator::from_start_state(&start_state).unwrap();

        assert_eq!(
            prove_history_arc_pcd_chunk_step_native(&start_arc, &start_state, &[]),
            Err(HistoryProofError::BadStepCount)
        );
        assert_eq!(
            prove_history_arc_pcd_chunk_step_native(
                &start_arc,
                &start_state,
                &witness.items[..HISTORY_ARC_PCD_CHUNK_MAX_STEPS + 1],
            ),
            Err(HistoryProofError::BadStepCount)
        );

        let items = &witness.items[..3];
        let (_, _, mut chunk_proof) =
            prove_history_arc_pcd_chunk_step_native(&start_arc, &start_state, items)
                .expect("chunk proof");
        chunk_proof.state_hashes.n_fields += 2;
        assert_eq!(
            verify_history_arc_pcd_chunk_step_proof_native(
                &start_arc,
                &start_state,
                items,
                &chunk_proof,
            ),
            Err(HistoryProofError::BadDeciderHashProof)
        );

        let (_, _, mut chunk_proof) =
            prove_history_arc_pcd_chunk_step_native(&start_arc, &start_state, items)
                .expect("chunk proof");
        chunk_proof.chunk_len += 1;
        assert_eq!(
            verify_history_arc_pcd_chunk_step_proof_native(
                &start_arc,
                &start_state,
                items,
                &chunk_proof,
            ),
            Err(HistoryProofError::BadStepCount)
        );
    }

    #[test]
    fn history_arc_pcd_payload_digests_bind_canonical_nested_fields() {
        let (_, start_anchor, start_accumulator) = start_state();
        let (_, _, witness) = witness(3);
        let start_state =
            HistoryAccumulationState::from_anchor(&start_anchor, start_accumulator).unwrap();
        let start_arc = HistoryArcPcdAccumulator::from_start_state(&start_state).unwrap();

        let (step_proof, step_reductions) = prove_history_step_native(
            &start_state.accumulator,
            start_state.block_id,
            start_state.projection_root,
            &witness.items[0],
        )
        .expect("step proof");
        let pcd_step =
            build_history_pcd_step_statement_native(&start_state, &step_proof, &step_reductions)
                .expect("PCD step");
        let (_, arc_step) =
            prove_history_arc_pcd_step_native(&start_arc, &pcd_step).expect("ARC step");
        let one_step = HistoryArcPcdOneStepProof {
            step: step_proof,
            arc_step,
        };
        let one_step_digest =
            history_arc_pcd_one_step_component_digest(&one_step).expect("one-step digest");
        assert_eq!(
            one_step_digest,
            history_arc_pcd_one_step_component_digest(&one_step).expect("stable digest")
        );

        let mut bad_one_step = one_step.clone();
        bad_one_step.step.claim_fields[10] += Block128::ONE;
        assert_ne!(
            one_step_digest,
            history_arc_pcd_one_step_component_digest(&bad_one_step)
                .expect("tampered one-step digest")
        );
        assert_ne!(
            history_arc_pcd_one_step_proof_digest(&Some(one_step)).expect("some digest"),
            history_arc_pcd_one_step_proof_digest(&None).expect("none digest")
        );

        let (_, _, chunk_proof) =
            prove_history_arc_pcd_chunk_step_native(&start_arc, &start_state, &witness.items[..3])
                .expect("chunk proof");
        let chunk_digest =
            history_arc_pcd_chunk_step_component_digest(&chunk_proof).expect("chunk digest");

        let mut bad_chunk = chunk_proof.clone();
        bad_chunk.claim_hash.n_claims += 1;
        assert_ne!(
            chunk_digest,
            history_arc_pcd_chunk_step_component_digest(&bad_chunk).expect("tampered chunk digest")
        );

        let mut bad_chunk = chunk_proof.clone();
        bad_chunk.chunk_len += 1;
        assert_ne!(
            chunk_digest,
            history_arc_pcd_chunk_step_component_digest(&bad_chunk)
                .expect("tampered chunk len digest")
        );

        let base_digest =
            history_arc_pcd_recursive_base_digest(&start_state, &start_arc).expect("base digest");
        let (_, _, head) = prove_history_arc_pcd_recursive_chunk_chain_head_step_native(
            base_digest,
            base_digest,
            0,
            &start_arc,
            &start_state,
            &witness.items[..3],
        )
        .expect("recursive chunk head");
        let head_digest =
            history_arc_pcd_recursive_chunk_head_digest(&Some(head.clone())).expect("head digest");
        assert_ne!(
            head_digest,
            history_arc_pcd_recursive_chunk_head_digest(&None).expect("none head digest")
        );

        let mut bad_head = head.clone();
        bad_head.final_chunk_proof.next_proof_digest_hash.n_claims += 1;
        assert_ne!(
            head_digest,
            history_arc_pcd_recursive_chunk_head_digest(&Some(bad_head))
                .expect("tampered head proof digest")
        );

        let mut bad_head = head;
        bad_head.final_chunk_statement.chunk_step_proof_digest[0] ^= 1;
        assert_ne!(
            head_digest,
            history_arc_pcd_recursive_chunk_head_digest(&Some(bad_head))
                .expect("tampered head statement digest")
        );
    }

    #[test]
    fn history_arc_pcd_chunk_step_verifier_transcript_batch_roundtrip_and_size_constant() {
        let (_, start_anchor, start_accumulator) = start_state();
        let (_, _, witness) = witness(HISTORY_ARC_PCD_CHUNK_MAX_STEPS);
        let start_state =
            HistoryAccumulationState::from_anchor(&start_anchor, start_accumulator).unwrap();
        let start_arc = HistoryArcPcdAccumulator::from_start_state(&start_state).unwrap();
        let mut expected_len = None;
        let mut expected_ops = None;

        for live in [1usize, HISTORY_ARC_PCD_CHUNK_MAX_STEPS] {
            let items = &witness.items[..live];
            let (_, _, chunk_proof) =
                prove_history_arc_pcd_chunk_step_native(&start_arc, &start_state, items)
                    .expect("chunk proof");
            let traces = history_arc_pcd_chunk_step_verifier_traces(
                &start_arc,
                &start_state,
                items,
                &chunk_proof,
            )
            .expect("chunk verifier traces");
            assert_eq!(traces.len(), 6);

            let (transcript_proof, reductions) =
                prove_history_arc_pcd_chunk_step_verifier_transcript_batch_native(
                    &start_arc,
                    &start_state,
                    items,
                    &chunk_proof,
                )
                .expect("chunk verifier transcript proof");
            let mut channel = noid_poseidon2b::channel::Poseidon2bChannel::new();
            let verified = crate::fs_transcript::verify_fiat_shamir_transcript_batch_killshot(
                &traces,
                &transcript_proof,
                &mut channel,
            )
            .expect("verify chunk verifier transcript proof");
            assert_eq!(verified, reductions);
            assert!(
                crate::fs_transcript::discharge_fiat_shamir_transcript_batch_reductions_native(
                    &traces, &verified
                )
            );
            assert_eq!(transcript_proof.n_traces, 6);

            if let Some(expected_len) = expected_len {
                assert_eq!(transcript_proof.byte_len(), expected_len);
            } else {
                expected_len = Some(transcript_proof.byte_len());
            }
            if let Some(expected_ops) = expected_ops {
                assert_eq!(transcript_proof.n_ops, expected_ops);
            } else {
                expected_ops = Some(transcript_proof.n_ops);
            }
        }

        let items = &witness.items[..HISTORY_ARC_PCD_CHUNK_MAX_STEPS];
        let (_, _, chunk_proof) =
            prove_history_arc_pcd_chunk_step_native(&start_arc, &start_state, items)
                .expect("chunk proof");
        let mut traces = history_arc_pcd_chunk_step_verifier_traces(
            &start_arc,
            &start_state,
            items,
            &chunk_proof,
        )
        .expect("chunk verifier traces");
        let (transcript_proof, _) =
            prove_history_arc_pcd_chunk_step_verifier_transcript_batch_native(
                &start_arc,
                &start_state,
                items,
                &chunk_proof,
            )
            .expect("chunk verifier transcript proof");
        for trace in &mut traces {
            if let Some(FiatShamirTraceOp::Squeeze(value)) = trace
                .iter_mut()
                .find(|op| matches!(op, FiatShamirTraceOp::Squeeze(_)))
            {
                *value += Block128::ONE;
                break;
            }
        }
        let mut channel = noid_poseidon2b::channel::Poseidon2bChannel::new();
        assert!(
            crate::fs_transcript::verify_fiat_shamir_transcript_batch_killshot(
                &traces,
                &transcript_proof,
                &mut channel,
            )
            .is_err()
        );
    }

    #[test]
    fn history_arc_pcd_recursive_chunk_step_verifier_transcript_batch_roundtrip() {
        let (_, start_anchor, start_accumulator) = start_state();
        let (_, _, witness) = witness(3);
        let start_state =
            HistoryAccumulationState::from_anchor(&start_anchor, start_accumulator).unwrap();
        let start_arc = HistoryArcPcdAccumulator::from_start_state(&start_state).unwrap();
        let base_digest =
            history_arc_pcd_recursive_base_digest(&start_state, &start_arc).expect("base digest");
        let (_, next_arc, head) = prove_history_arc_pcd_recursive_chunk_chain_head_step_native(
            base_digest,
            base_digest,
            0,
            &start_arc,
            &start_state,
            &witness.items[..3],
        )
        .expect("recursive chunk head");
        let traces = history_arc_pcd_recursive_chunk_step_verifier_traces(
            &head.final_chunk_statement,
            &head.previous_accumulator,
            &next_arc,
            &head.final_chunk_proof,
        )
        .expect("recursive chunk verifier traces");
        assert_eq!(traces.len(), 2);
        let (transcript_proof, reductions) =
            prove_history_arc_pcd_recursive_chunk_step_verifier_transcript_batch_native(
                &head.final_chunk_statement,
                &head.previous_accumulator,
                &next_arc,
                &head.final_chunk_proof,
            )
            .expect("recursive chunk verifier transcript proof");
        assert_eq!(transcript_proof, head.final_chunk_verifier_transcript);
        verify_history_arc_pcd_recursive_chunk_step_verifier_transcript_batch_native(
            &head.final_chunk_statement,
            &head.previous_accumulator,
            &next_arc,
            &head.final_chunk_proof,
            &head.final_chunk_verifier_transcript,
        )
        .expect("verify stored recursive chunk verifier transcript proof");
        let mut channel = noid_poseidon2b::channel::Poseidon2bChannel::new();
        let verified = crate::fs_transcript::verify_fiat_shamir_transcript_batch_killshot(
            &traces,
            &transcript_proof,
            &mut channel,
        )
        .expect("verify recursive chunk verifier transcript proof");
        assert_eq!(verified, reductions);
        assert!(
            crate::fs_transcript::discharge_fiat_shamir_transcript_batch_reductions_native(
                &traces, &verified
            )
        );
        assert_eq!(transcript_proof.n_traces, 2);
        assert!(transcript_proof.byte_len() > 0);
    }

    #[test]
    fn history_arc_pcd_recursive_chunk_chain_head_roundtrip_and_size_constant() {
        let (_, start_anchor, start_accumulator) = start_state();
        let (end_anchor, _, witness) = witness(HISTORY_ARC_PCD_CHUNK_MAX_STEPS * 2 + 3);
        let start_state =
            HistoryAccumulationState::from_anchor(&start_anchor, start_accumulator.clone())
                .unwrap();
        let mut state = start_state.clone();
        let mut arc = HistoryArcPcdAccumulator::from_start_state(&start_state).unwrap();
        let base_digest = history_arc_pcd_recursive_base_digest(&state, &arc).unwrap();
        let mut previous_proof_digest = base_digest;
        let mut previous_chunk_count = 0u64;
        let mut expected_head_len = None;
        let mut final_head = None;

        for (idx, items) in witness
            .items
            .chunks(HISTORY_ARC_PCD_CHUNK_MAX_STEPS)
            .enumerate()
        {
            let (next_state, next_arc, head) =
                prove_history_arc_pcd_recursive_chunk_chain_head_step_native(
                    base_digest,
                    previous_proof_digest,
                    previous_chunk_count,
                    &arc,
                    &state,
                    items,
                )
                .expect("recursive chunk head step");
            let verified_digest = verify_history_arc_pcd_recursive_chunk_chain_head_shape_native(
                &start_state,
                &next_arc,
                &head,
            )
            .expect("verify recursive chunk head shape");

            assert_eq!(verified_digest, head.final_proof_digest);
            assert_eq!(head.chunk_count, idx as u64 + 1);
            assert_eq!(head.final_chunk_statement.chunk_len, items.len() as u32);
            assert_eq!(head.final_chunk_proof.recursive_hashes.n_claims, 3);
            if let Some(expected_len) = expected_head_len {
                assert_eq!(head.byte_len(), expected_len);
            } else {
                expected_head_len = Some(head.byte_len());
            }

            previous_proof_digest = head.final_proof_digest;
            previous_chunk_count = head.chunk_count;
            state = next_state;
            arc = next_arc;
            final_head = Some(head);
        }

        let (full_state, full_arc, full_head) =
            prove_history_arc_pcd_recursive_chunk_chain_head_native(
                start_anchor.clone(),
                end_anchor.clone(),
                start_accumulator,
                &witness,
            )
            .expect("full recursive chunk chain head");
        assert_eq!(state, full_state);
        assert_eq!(arc, full_arc);
        assert_eq!(full_head, final_head.expect("final chunk head"));
        assert_eq!(full_state.height, end_anchor.height);
        assert_eq!(full_state.block_id, end_anchor.block_id);
        assert_eq!(full_state.projection_root, end_anchor.projection_root);
        assert!(full_head.byte_len() < 18 * 1024);
    }

    #[test]
    fn history_arc_pcd_recursive_chunk_chain_head_rejects_tamper() {
        let (_, start_anchor, start_accumulator) = start_state();
        let (_, _, witness) = witness(HISTORY_ARC_PCD_CHUNK_MAX_STEPS);
        let start_state =
            HistoryAccumulationState::from_anchor(&start_anchor, start_accumulator).unwrap();
        let start_arc = HistoryArcPcdAccumulator::from_start_state(&start_state).unwrap();
        let base_digest = history_arc_pcd_recursive_base_digest(&start_state, &start_arc).unwrap();
        let (_, next_arc, head) = prove_history_arc_pcd_recursive_chunk_chain_head_step_native(
            base_digest,
            base_digest,
            0,
            &start_arc,
            &start_state,
            &witness.items,
        )
        .expect("recursive chunk head");

        let mut bad_head = head.clone();
        bad_head.final_chunk_proof.recursive_hashes.n_fields += 2;
        assert_eq!(
            verify_history_arc_pcd_recursive_chunk_chain_head_shape_native(
                &start_state,
                &next_arc,
                &bad_head,
            ),
            Err(HistoryProofError::BadDeciderHashProof)
        );

        let mut bad_head = head.clone();
        bad_head.final_chunk_verifier_transcript.n_ops += 1;
        assert_eq!(
            verify_history_arc_pcd_recursive_chunk_chain_head_shape_native(
                &start_state,
                &next_arc,
                &bad_head,
            ),
            Err(HistoryProofError::BadDeciderProof)
        );

        let mut bad_head = head.clone();
        bad_head.final_chunk_statement.chunk_len = 0;
        assert_eq!(
            verify_history_arc_pcd_recursive_chunk_chain_head_shape_native(
                &start_state,
                &next_arc,
                &bad_head,
            ),
            Err(HistoryProofError::BadStepCount)
        );

        let mut bad_head = head;
        bad_head.final_proof_digest[0] ^= 1;
        assert_eq!(
            verify_history_arc_pcd_recursive_chunk_chain_head_shape_native(
                &start_state,
                &next_arc,
                &bad_head,
            ),
            Err(HistoryProofError::BadDeciderProof)
        );
    }

    #[test]
    fn history_proof_decider_uses_step_by_step_arc_accumulator() {
        let (_, start_anchor, start_accumulator) = start_state();
        let (end_anchor, _, witness) = witness(3);
        let proof = prove_history_native(
            start_anchor.clone(),
            end_anchor.clone(),
            start_accumulator.clone(),
            &witness,
        )
        .expect("history proof");
        let mut state =
            HistoryAccumulationState::from_anchor(&start_anchor, start_accumulator).unwrap();
        let mut arc = HistoryArcPcdAccumulator::from_start_state(&state).unwrap();

        for item in &witness.items {
            let step = build_history_step_statement(
                &state.accumulator,
                state.block_id,
                state.projection_root,
                item,
            )
            .expect("step statement");
            let pcd_step = build_history_pcd_step_statement_from_step(&state, &step)
                .expect("PCD step statement");
            arc = advance_history_arc_pcd_accumulator_native(&arc, &pcd_step)
                .expect("advance ARC/PCD accumulator");
            state = pcd_step.next_state;
        }

        assert_eq!(proof.decider.pcd_accumulator, arc);
        assert_eq!(state.block_id, end_anchor.block_id);
        assert_ne!(proof.decider.pcd_accumulator.pcd_root, [0u8; 32]);

        let shorter = prove_n(2);
        assert_ne!(
            proof.decider.pcd_accumulator.pcd_root,
            shorter.decider.pcd_accumulator.pcd_root
        );
    }

    #[test]
    fn history_arc_pcd_accumulator_rejects_wrong_previous_state() {
        let (_, start_anchor, start_accumulator) = start_state();
        let (_, _, witness) = witness(1);
        let state =
            HistoryAccumulationState::from_anchor(&start_anchor, start_accumulator).unwrap();
        let arc = HistoryArcPcdAccumulator::from_start_state(&state).unwrap();
        let (proof, reductions) = prove_history_step_native(
            &state.accumulator,
            state.block_id,
            state.projection_root,
            &witness.items[0],
        )
        .expect("step proof");
        let mut pcd = build_history_pcd_step_statement_native(&state, &proof, &reductions).unwrap();
        pcd.previous_state.block_id[0] ^= 1;

        assert_eq!(
            advance_history_arc_pcd_accumulator_native(&arc, &pcd),
            Err(HistoryProofError::BadPcdStepState)
        );
    }

    #[test]
    fn history_step_proof_rejects_claim_field_tamper() {
        let (_, start_anchor, start_accumulator) = start_state();
        let (_, _, witness) = witness(1);
        let (mut proof, _) = prove_history_step_native(
            &start_accumulator,
            start_anchor.block_id,
            start_anchor.projection_root,
            &witness.items[0],
        )
        .expect("step proof");
        proof.claim_fields[0] += Block128::from(1u128);

        assert_eq!(
            verify_history_step_native(&proof),
            Err(HistoryProofError::BadStepClaimDigest)
        );
    }

    #[test]
    fn verifier_accepts_matching_local_header_anchors() {
        let (_, start_anchor, _) = start_state();
        let (end_anchor, start_accumulator, witness) = witness(18);
        let proof = prove_history_native(
            start_anchor.clone(),
            end_anchor.clone(),
            start_accumulator,
            &witness,
        )
        .expect("history proof");

        verify_history_proof_native(&proof, &start_anchor, &end_anchor).expect("verify");
    }

    #[test]
    fn untrusted_verifier_rejects_native_fold_backend() {
        let (_, start_anchor, _) = start_state();
        let (end_anchor, start_accumulator, witness) = witness(18);
        let proof = prove_history_native(
            start_anchor.clone(),
            end_anchor.clone(),
            start_accumulator,
            &witness,
        )
        .expect("history proof");

        assert_eq!(
            verify_history_proof_untrusted(&proof, &start_anchor, &end_anchor),
            Err(HistoryProofError::BackendNotTrustless)
        );
    }

    #[test]
    fn untrusted_verifier_accepts_arc_pcd_one_step_backend() {
        let (_, start_anchor, _) = start_state();
        let (end_anchor, start_accumulator, witness) = witness(1);
        let proof = prove_history_arc_pcd_one_step(
            start_anchor.clone(),
            end_anchor.clone(),
            start_accumulator,
            &witness,
        )
        .expect("one-step ARC/PCD proof");

        assert_eq!(proof.backend, HistoryProofBackend::ArcPcdV1);
        assert_eq!(proof.step_count, 1);
        assert!(proof.byte_len() < 40 * 1024);
        assert!(proof.decider.hash_proofs.is_none());
        assert_eq!(
            proof.decider.hash_proofs_digest,
            history_decider_hash_proofs_digest(&None).unwrap()
        );
        assert!(proof.decider.one_step_proof.is_some());
        verify_history_proof_native(&proof, &start_anchor, &end_anchor).expect("native verify");
        verify_history_proof_untrusted(&proof, &start_anchor, &end_anchor)
            .expect("untrusted one-step verify");
    }

    #[test]
    fn untrusted_verifier_rejects_arc_pcd_one_step_tamper() {
        let (_, start_anchor, _) = start_state();
        let (end_anchor, start_accumulator, witness) = witness(1);
        let mut proof = prove_history_arc_pcd_one_step(
            start_anchor.clone(),
            end_anchor.clone(),
            start_accumulator,
            &witness,
        )
        .expect("one-step ARC/PCD proof");
        proof
            .decider
            .one_step_proof
            .as_mut()
            .expect("one-step proof")
            .arc_step
            .accumulator_update_hashes
            .n_fields += 2;
        proof.decider.one_step_proof_digest =
            history_arc_pcd_one_step_proof_digest(&proof.decider.one_step_proof).unwrap();
        proof.proof_digest = history_proof_digest(&proof);

        assert_eq!(
            verify_history_proof_untrusted(&proof, &start_anchor, &end_anchor),
            Err(HistoryProofError::BadDeciderHashProof)
        );
    }

    #[test]
    fn untrusted_verifier_rejects_arc_pcd_one_step_decider_commitment_tamper() {
        let (_, start_anchor, _) = start_state();
        let (end_anchor, start_accumulator, witness) = witness(1);
        let mut proof = prove_history_arc_pcd_one_step(
            start_anchor.clone(),
            end_anchor.clone(),
            start_accumulator,
            &witness,
        )
        .expect("one-step ARC/PCD proof");
        proof.decider.pcs_commitment[0] ^= 1;
        proof.proof_digest = history_proof_digest(&proof);

        assert_eq!(
            verify_history_proof_untrusted(&proof, &start_anchor, &end_anchor),
            Err(HistoryProofError::BadDeciderProof)
        );
    }

    #[test]
    fn untrusted_verifier_rejects_arc_pcd_one_step_extra_hash_proofs() {
        let (_, start_anchor, _) = start_state();
        let (end_anchor, start_accumulator, witness) = witness(1);
        let native = prove_history_native(
            start_anchor.clone(),
            end_anchor.clone(),
            start_accumulator.clone(),
            &witness,
        )
        .expect("native proof");
        let mut proof = prove_history_arc_pcd_one_step(
            start_anchor.clone(),
            end_anchor.clone(),
            start_accumulator,
            &witness,
        )
        .expect("one-step ARC/PCD proof");
        proof.decider.hash_proofs = native.decider.hash_proofs;
        proof.decider.hash_proofs_digest =
            history_decider_hash_proofs_digest(&proof.decider.hash_proofs).unwrap();
        proof.proof_digest = history_proof_digest(&proof);

        assert_eq!(
            verify_history_proof_untrusted(&proof, &start_anchor, &end_anchor),
            Err(HistoryProofError::BadDeciderHashProof)
        );
    }

    #[test]
    fn arc_pcd_one_step_prover_rejects_multi_step_witness() {
        let (_, start_anchor, _) = start_state();
        let (end_anchor, start_accumulator, witness) = witness(2);

        assert_eq!(
            prove_history_arc_pcd_one_step(start_anchor, end_anchor, start_accumulator, &witness),
            Err(HistoryProofError::BackendVerifierMissing)
        );
    }

    #[test]
    fn arc_pcd_recursive_step_proof_roundtrip_and_size_constant() {
        let (_, start_anchor, _) = start_state();
        let (end_anchor, start_accumulator, witness) = witness(3);
        let first_end_anchor = {
            let mut headers = Vec::with_capacity(2);
            headers.push(header(0, [0u8; 32], 1));
            headers.push(witness.items[0].header.clone());
            compute_header_chain_anchor(headers.iter(), digest(0xaa)).unwrap()
        };
        let first_witness = HistoryProofWitness {
            items: vec![witness.items[0].clone()],
        };
        let first_proof = prove_history_arc_pcd_one_step(
            start_anchor.clone(),
            first_end_anchor,
            start_accumulator.clone(),
            &first_witness,
        )
        .expect("first one-step proof");
        let mut previous_proof_digest = history_proof_digest(&first_proof);
        let mut previous_accumulator = first_proof.decider.pcd_accumulator.clone();
        let mut previous_state = HistoryAccumulationState {
            version: HISTORY_PROOF_VERSION,
            height: first_proof.end_anchor.height,
            block_id: first_proof.end_anchor.block_id,
            projection_root: first_proof.end_anchor.projection_root,
            accumulator: first_proof.end_accumulator.clone(),
            folded_witness_root: first_proof.folded_witness_root,
            step_count: first_proof.step_count,
        };
        let mut proof_len = None;
        let mut statement_len = None;

        for item in witness.items.iter().skip(1) {
            let (step, reductions) = prove_history_step_native(
                &previous_state.accumulator,
                previous_state.block_id,
                previous_state.projection_root,
                item,
            )
            .expect("step proof");
            let pcd_step =
                build_history_pcd_step_statement_native(&previous_state, &step, &reductions)
                    .expect("PCD step");
            let (_next_accumulator, arc_step) =
                prove_history_arc_pcd_step_native(&previous_accumulator, &pcd_step)
                    .expect("ARC step");
            let one_step = HistoryArcPcdOneStepProof { step, arc_step };
            let (statement, next_state, next_accumulator, expected_next_digest) =
                build_history_arc_pcd_recursive_step_statement(
                    previous_proof_digest,
                    &previous_accumulator,
                    &previous_state,
                    &one_step,
                )
                .expect("recursive step statement");
            let (next_digest, recursive_proof) = prove_history_arc_pcd_recursive_step_native(
                &statement,
                &previous_accumulator,
                &next_accumulator,
            )
            .expect("recursive step proof");

            assert_eq!(next_digest, expected_next_digest);
            assert_eq!(
                verify_history_arc_pcd_recursive_step_proof_native(
                    &statement,
                    &previous_accumulator,
                    &next_accumulator,
                    &recursive_proof,
                )
                .expect("verify recursive step proof"),
                next_digest
            );
            if let Some(proof_len) = proof_len {
                assert_eq!(recursive_proof.byte_len(), proof_len);
            } else {
                proof_len = Some(recursive_proof.byte_len());
            }
            if let Some(statement_len) = statement_len {
                assert_eq!(statement.byte_len(), statement_len);
            } else {
                statement_len = Some(statement.byte_len());
            }
            assert_eq!(recursive_proof.recursive_hashes.n_claims, 3);
            assert_eq!(recursive_proof.next_proof_digest_hash.n_claims, 1);
            assert!(recursive_proof.byte_len() < 12 * 1024);

            previous_proof_digest = next_digest;
            previous_accumulator = next_accumulator;
            previous_state = next_state;
        }

        assert_eq!(previous_state.block_id, end_anchor.block_id);
        assert_eq!(previous_accumulator.step_count, 3);
    }

    #[test]
    fn arc_pcd_recursive_step_proof_rejects_tamper() {
        let (_, start_anchor, _) = start_state();
        let (first_end_anchor, start_accumulator, first_witness) = witness(1);
        let first_proof = prove_history_arc_pcd_one_step(
            start_anchor.clone(),
            first_end_anchor,
            start_accumulator,
            &first_witness,
        )
        .expect("first one-step proof");
        let previous_proof_digest = history_proof_digest(&first_proof);
        let previous_accumulator = first_proof.decider.pcd_accumulator.clone();
        let previous_state = HistoryAccumulationState {
            version: HISTORY_PROOF_VERSION,
            height: first_proof.end_anchor.height,
            block_id: first_proof.end_anchor.block_id,
            projection_root: first_proof.end_anchor.projection_root,
            accumulator: first_proof.end_accumulator.clone(),
            folded_witness_root: first_proof.folded_witness_root,
            step_count: first_proof.step_count,
        };
        let (_, _, second_witness) = witness(2);
        let item = &second_witness.items[1];
        let (step, reductions) = prove_history_step_native(
            &previous_state.accumulator,
            previous_state.block_id,
            previous_state.projection_root,
            item,
        )
        .expect("step proof");
        let pcd_step =
            build_history_pcd_step_statement_native(&previous_state, &step, &reductions).unwrap();
        let (_, arc_step) =
            prove_history_arc_pcd_step_native(&previous_accumulator, &pcd_step).unwrap();
        let one_step = HistoryArcPcdOneStepProof { step, arc_step };
        let (statement, _, next_accumulator, _) = build_history_arc_pcd_recursive_step_statement(
            previous_proof_digest,
            &previous_accumulator,
            &previous_state,
            &one_step,
        )
        .unwrap();
        let (_, mut recursive_proof) = prove_history_arc_pcd_recursive_step_native(
            &statement,
            &previous_accumulator,
            &next_accumulator,
        )
        .unwrap();
        recursive_proof.recursive_hashes.n_fields += 2;

        assert_eq!(
            verify_history_arc_pcd_recursive_step_proof_native(
                &statement,
                &previous_accumulator,
                &next_accumulator,
                &recursive_proof,
            ),
            Err(HistoryProofError::BadDeciderHashProof)
        );
    }

    #[test]
    fn arc_pcd_recursive_chain_head_roundtrip_and_size_constant() {
        let (_, start_anchor, _) = start_state();
        let mut head_len = None;

        for n in [1usize, 3, 18] {
            let (end_anchor, start_accumulator, witness) = witness(n);
            let start_state =
                HistoryAccumulationState::from_anchor(&start_anchor, start_accumulator.clone())
                    .expect("start state");
            let (state, final_accumulator, head) =
                prove_history_arc_pcd_recursive_chain_head_native(
                    start_anchor.clone(),
                    end_anchor.clone(),
                    start_accumulator,
                    &witness,
                )
                .expect("recursive chain head");

            assert_eq!(state.height, end_anchor.height);
            assert_eq!(state.block_id, end_anchor.block_id);
            assert_eq!(final_accumulator.step_count, n as u64);
            assert_eq!(head.step_count, n as u64);
            assert_eq!(
                verify_history_arc_pcd_recursive_chain_head_shape_native(
                    &start_state,
                    &final_accumulator,
                    &head,
                )
                .expect("verify chain-head shape"),
                head.final_proof_digest
            );
            if let Some(expected) = head_len {
                assert_eq!(head.byte_len(), expected);
            } else {
                head_len = Some(head.byte_len());
            }
            assert!(head.byte_len() < 20 * 1024);
        }
    }

    #[test]
    fn arc_pcd_recursive_chain_head_rejects_tamper() {
        let (_, start_anchor, _) = start_state();
        let (end_anchor, start_accumulator, witness) = witness(3);
        let start_state =
            HistoryAccumulationState::from_anchor(&start_anchor, start_accumulator.clone())
                .expect("start state");
        let (_, final_accumulator, mut head) = prove_history_arc_pcd_recursive_chain_head_native(
            start_anchor.clone(),
            end_anchor,
            start_accumulator,
            &witness,
        )
        .expect("recursive chain head");
        head.final_step_proof.next_proof_digest_hash.n_fields += 2;

        assert_eq!(
            verify_history_arc_pcd_recursive_chain_head_shape_native(
                &start_state,
                &final_accumulator,
                &head,
            ),
            Err(HistoryProofError::BadDeciderHashProof)
        );
    }

    #[test]
    fn untrusted_verifier_rejects_arc_pcd_with_native_fold_payload() {
        let (_, start_anchor, _) = start_state();
        let (end_anchor, start_accumulator, witness) = witness(18);
        let mut proof = prove_history_native(
            start_anchor.clone(),
            end_anchor.clone(),
            start_accumulator,
            &witness,
        )
        .expect("history proof");
        proof.backend = HistoryProofBackend::ArcPcdV1;
        let statement = history_decider_statement(&proof);
        proof.decider.statement_digest = history_decider_statement_digest(&statement);
        proof.proof_digest = history_proof_digest(&proof);

        assert_eq!(
            verify_history_proof_native(&proof, &start_anchor, &end_anchor),
            Err(HistoryProofError::BadDeciderProof)
        );
        assert_eq!(
            verify_history_proof_untrusted(&proof, &start_anchor, &end_anchor),
            Err(HistoryProofError::BadDeciderProof)
        );
    }

    #[test]
    fn verifier_rejects_anchor_mismatch_and_digest_tamper() {
        let (_, start_anchor, _) = start_state();
        let (end_anchor, start_accumulator, witness) = witness(18);
        let mut proof = prove_history_native(
            start_anchor.clone(),
            end_anchor.clone(),
            start_accumulator.clone(),
            &witness,
        )
        .expect("history proof");
        let mut bad_end = end_anchor.clone();
        bad_end.state_root[0] ^= 1;
        assert_eq!(
            verify_history_proof_native(&proof, &start_anchor, &bad_end),
            Err(HistoryProofError::EndAnchorMismatch)
        );

        proof.folded_witness_root[0] ^= 1;
        assert_eq!(
            verify_history_proof_native(&proof, &start_anchor, &end_anchor),
            Err(HistoryProofError::BadDeciderStatement)
        );

        let mut proof = prove_history_native(
            start_anchor.clone(),
            end_anchor.clone(),
            start_accumulator,
            &witness,
        )
        .expect("history proof");
        proof.proof_digest[0] ^= 1;
        assert_eq!(
            verify_history_proof_native(&proof, &start_anchor, &end_anchor),
            Err(HistoryProofError::BadProofDigest)
        );
    }

    #[test]
    fn verifier_rejects_decider_tamper() {
        let (_, start_anchor, _) = start_state();
        let (end_anchor, start_accumulator, witness) = witness(18);
        let mut proof = prove_history_native(
            start_anchor.clone(),
            end_anchor.clone(),
            start_accumulator,
            &witness,
        )
        .expect("history proof");
        proof.decider.pcs_commitment[0] ^= 1;

        assert_eq!(
            verify_history_proof_native(&proof, &start_anchor, &end_anchor),
            Err(HistoryProofError::BadDeciderProof)
        );
    }

    #[test]
    fn verifier_rejects_decider_hash_proof_tamper() {
        let (_, start_anchor, _) = start_state();
        let (end_anchor, start_accumulator, witness) = witness(18);
        let mut proof = prove_history_native(
            start_anchor.clone(),
            end_anchor.clone(),
            start_accumulator,
            &witness,
        )
        .expect("history proof");
        proof
            .decider
            .hash_proofs
            .as_mut()
            .expect("hash proofs")
            .tagged_pair_hashes
            .n_fields += 2;
        proof.decider.hash_proofs_digest =
            history_decider_hash_proofs_digest(&proof.decider.hash_proofs).unwrap();
        proof.proof_digest = history_proof_digest(&proof);

        assert_eq!(
            verify_history_proof_native(&proof, &start_anchor, &end_anchor),
            Err(HistoryProofError::BadDeciderHashProof)
        );
    }

    #[test]
    fn prover_rejects_bad_witness_parent_state() {
        let (_, start_anchor, _) = start_state();
        let (end_anchor, start_accumulator, mut witness) = witness(2);
        witness.items[1].parent_state_root[0] ^= 1;
        assert_eq!(
            prove_history_native(start_anchor, end_anchor, start_accumulator, &witness),
            Err(HistoryProofError::BadWitnessParentState { height: 2 })
        );
    }

    #[test]
    fn prover_rejects_bad_witness_claim_digest() {
        let (_, start_anchor, _) = start_state();
        let (end_anchor, start_accumulator, mut witness) = witness(2);
        witness.items[1].claim_fields[0] += Block128::from(1u128);
        assert_eq!(
            prove_history_native(start_anchor, end_anchor, start_accumulator, &witness),
            Err(HistoryProofError::BadWitnessClaimDigest { height: 2 })
        );
    }
}
