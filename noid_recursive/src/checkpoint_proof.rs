// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Final public O(1) checkpoint proof envelope.
//!
//! This module fixes the network-facing proof shape and wires the full
//! checkpoint data path through explicit scaffold backends where the optimized
//! recursive verifier is still under construction. The public verifier checks
//! the final envelope, boundary anchors, accumulator digests, and recursive head
//! shape; the roadmap closes the scaffold subrelations in place.

use noid_chain::header_anchor::HeaderChainAnchor;
use noid_core::{Block128, TowerField};
use noid_gkr::{
    discharge_fixed_field_hash_reductions_native, prove_fixed_field_hash_killshot,
    verify_fixed_field_hash_killshot, FixedFieldHashInputs, FixedFieldHashParams,
    FixedFieldHashProofKillShot,
};
use noid_poseidon2b::channel::Poseidon2bChannel;
use noid_poseidon2b::native::domain::{capacity_iv, TAG_HISTPRF};
use noid_poseidon2b::native::Poseidon2bSponge;
use noid_poseidon2b::primitives::{Address, Digest};
use rayon::prelude::*;

use crate::accepted_batch::{
    accepted_claim_batch_digest_v1, prove_accepted_claim_batch_digest_v1,
    verify_accepted_claim_batch_digest_hash_fields_v1, verify_accepted_claim_batch_digest_v1,
    AcceptedClaimBatchDigestError, AcceptedClaimBatchDigestProofV1, AcceptedClaimBatchOutput,
    AcceptedClaimBatchWitness,
};
use crate::accumulator::ChainAccumulator;
use crate::block_certificate::{
    accepted_block_certificate_batch_statement_digest_v1,
    accepted_block_certificate_batch_statement_v1, accepted_block_certificate_receipt_v1,
    accepted_block_certificate_statement_digest_v1, accepted_block_certificate_validity_handle_v1,
    prove_accepted_block_certificate_batch_digest_proof_v1,
    prove_accepted_block_certificate_proof_v1_hash_only,
    verify_accepted_block_certificate_batch_digest_proof_v1,
    verify_accepted_block_certificate_proof_v1_checkpoint,
    verify_accepted_block_certificate_receipt_projection_v1,
    AcceptedBlockCertificateBatchDigestProofV1, AcceptedBlockCertificateBatchError,
    AcceptedBlockCertificateBatchStatementV1, AcceptedBlockCertificateProofError,
    AcceptedBlockCertificateProofV1, AcceptedBlockCertificateReceiptError,
    AcceptedBlockCertificateReceiptV1, AcceptedBlockCertificateStatementV1,
    AcceptedBlockCertificateValidityHandleError, AcceptedBlockCertificateValidityHandleV1,
};
use crate::block_certificate_backend::{
    verify_accepted_block_batch_components_v1, AcceptedBlockBatchComponentErrorV1,
    AcceptedBlockBatchComponentInputsV1, AcceptedBlockBatchComponentProofV1,
};
use crate::checkpoint_ivc_backend::{
    prove_history_checkpoint_ivc_chunk_receipt_handle_core_v1,
    verify_history_checkpoint_ivc_chunk_core_v1, HistoryCheckpointIvcChunkCoreError,
    HistoryCheckpointIvcChunkCoreProofV1,
};
use crate::pow_header::RecursiveConsensusState;

pub const HISTORY_CHECKPOINT_PROOF_VERSION: u32 = 1;
pub const HISTORY_CHECKPOINT_ENGINE_STREAMING_TOWER_IVC_V1: u32 = 1;
pub const HISTORY_CHECKPOINT_BATCH_TARGET_BLOCKS: u32 = 16;
pub const HISTORY_CHECKPOINT_RETAINED_WINDOW_BLOCKS: u32 = 18;
pub const HISTORY_CHECKPOINT_STEP_STATEMENT_HASH_FIELDS: usize = 12;

const HCP_ANC1: u128 = 0x4843_505F_414E_4331; // "HCP_ANC1"
const HCP_ACC1: u128 = 0x4843_505F_4143_4331; // "HCP_ACC1"
const HCP_CON1: u128 = 0x4843_505F_434F_4E31; // "HCP_CON1"
const HCP_BND1: u128 = 0x4843_505F_424E_4431; // "HCP_BND1"
const HCP_SUM1: u128 = 0x4843_505F_5355_4D31; // "HCP_SUM1"
const HCP_HEAD1: u128 = 0x4843_505F_4845_4131; // "HCP_HEA1"
const HCP_BASE1: u128 = 0x4843_505F_4241_5331; // "HCP_BAS1"
const HCP_FOLD1: u128 = 0x4843_505F_464F_4C31; // "HCP_FOL1"
const HCP_REL1: u128 = 0x4843_505F_5245_4C31; // "HCP_REL1"
const HCP_STMT1: u128 = 0x4843_505F_5354_4D31; // "HCP_STM1"

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HistoryCheckpointHeadV1 {
    pub version: u32,
    pub engine_id: u32,
    pub checkpoint_height: u64,
    pub batch_count: u64,
    pub anchor_digest: Digest,
    pub accumulator_digest: Digest,
    pub consensus_digest: Digest,
    pub recursive_digest: Digest,
}

impl HistoryCheckpointHeadV1 {
    pub fn byte_len(&self) -> usize {
        bincode::serialized_size(self)
            .expect("serialized HistoryCheckpointHeadV1 length fits usize") as usize
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HistoryCheckpointBatchSummaryV1 {
    pub version: u32,
    pub batch_len: u32,
    pub start_anchor: HeaderChainAnchor,
    pub end_anchor: HeaderChainAnchor,
    pub start_accumulator: ChainAccumulator,
    pub end_accumulator: ChainAccumulator,
    pub start_consensus: RecursiveConsensusState,
    pub end_consensus: RecursiveConsensusState,
    pub accepted_claim_batch_digest: Digest,
}

impl HistoryCheckpointBatchSummaryV1 {
    pub fn byte_len(&self) -> usize {
        bincode::serialized_size(self)
            .expect("serialized HistoryCheckpointBatchSummaryV1 length fits usize") as usize
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HistoryCheckpointStepStatementV1 {
    pub version: u32,
    pub previous_head: HistoryCheckpointHeadV1,
    pub batch_summary: HistoryCheckpointBatchSummaryV1,
    pub next_head: HistoryCheckpointHeadV1,
}

impl HistoryCheckpointStepStatementV1 {
    pub fn byte_len(&self) -> usize {
        bincode::serialized_size(self)
            .expect("serialized HistoryCheckpointStepStatementV1 length fits usize")
            as usize
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HistoryCheckpointStepProofV1 {
    pub version: u32,
    pub step_statement_digest: Digest,
    pub certificate_batch_statement_digest: Digest,
    pub backend_proof: Vec<u8>,
}

impl HistoryCheckpointStepProofV1 {
    pub fn byte_len(&self) -> usize {
        bincode::serialized_size(self)
            .expect("serialized HistoryCheckpointStepProofV1 length fits usize") as usize
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HistoryCheckpointStepDigestProofV1 {
    pub version: u32,
    pub step_statement_digest_hash: FixedFieldHashProofKillShot,
}

impl HistoryCheckpointStepDigestProofV1 {
    pub fn byte_len(&self) -> usize {
        bincode::serialized_size(self)
            .expect("serialized HistoryCheckpointStepDigestProofV1 length fits usize")
            as usize
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HistoryCheckpointStepBackendProofV1 {
    pub version: u32,
    pub step_statement_digest_proof: HistoryCheckpointStepDigestProofV1,
    pub certificate_batch_digest_proof: AcceptedBlockCertificateBatchDigestProofV1,
    pub certificate_statements: Vec<AcceptedBlockCertificateStatementV1>,
    pub certificate_validity_proofs: Vec<AcceptedBlockCertificateProofV1>,
    pub accepted_claim_batch_digest_proof: Option<AcceptedClaimBatchDigestProofV1>,
    pub checkpoint_ivc_chunk_core_proof: Option<HistoryCheckpointIvcChunkCoreProofV1>,
}

impl HistoryCheckpointStepBackendProofV1 {
    pub fn byte_len(&self) -> usize {
        bincode::serialized_size(self)
            .expect("serialized HistoryCheckpointStepBackendProofV1 length fits usize")
            as usize
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HistoryCheckpointRecursivePayloadV1 {
    pub version: u32,
    pub engine_id: u32,
    pub head: HistoryCheckpointHeadV1,
    pub backend_proof: Vec<u8>,
}

impl HistoryCheckpointRecursivePayloadV1 {
    pub fn byte_len(&self) -> usize {
        bincode::serialized_size(self)
            .expect("serialized HistoryCheckpointRecursivePayloadV1 length fits usize")
            as usize
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HistoryCheckpointProofV1 {
    pub version: u32,
    pub engine_id: u32,
    pub checkpoint_height: u64,
    pub start_anchor: HeaderChainAnchor,
    pub end_anchor: HeaderChainAnchor,
    pub start_accumulator: ChainAccumulator,
    pub end_accumulator: ChainAccumulator,
    pub recursive_proof: Vec<u8>,
}

impl HistoryCheckpointProofV1 {
    pub fn byte_len(&self) -> usize {
        bincode::serialized_size(self)
            .expect("serialized HistoryCheckpointProofV1 length fits usize") as usize
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HistoryCheckpointProofError {
    UnsupportedVersion { actual: u32 },
    UnsupportedEngine { actual: u32 },
    EmptyRecursiveProof,
    EmptyBackendProof,
    DecodeRecursivePayload,
    BadBatchLength { actual: u32 },
    CheckpointHeightMismatch,
    BatchHeightMismatch,
    StartAnchorMismatch,
    EndAnchorMismatch,
    StartAccumulatorMismatch,
    EndAccumulatorMismatch,
    StartConsensusMismatch,
    EndConsensusMismatch,
    BatchStartMismatch,
    StepHeadMismatch,
    RecursiveHeadMismatch,
}

impl std::fmt::Display for HistoryCheckpointProofError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedVersion { actual } => {
                write!(f, "unsupported history checkpoint proof version {actual}")
            }
            Self::UnsupportedEngine { actual } => {
                write!(f, "unsupported history checkpoint proof engine {actual}")
            }
            Self::EmptyRecursiveProof => write!(f, "empty recursive checkpoint proof"),
            Self::EmptyBackendProof => write!(f, "empty recursive checkpoint backend proof"),
            Self::DecodeRecursivePayload => write!(f, "bad recursive checkpoint payload"),
            Self::BadBatchLength { actual } => {
                write!(f, "bad history checkpoint batch length {actual}")
            }
            Self::CheckpointHeightMismatch => write!(f, "checkpoint height mismatch"),
            Self::BatchHeightMismatch => write!(f, "checkpoint batch height mismatch"),
            Self::StartAnchorMismatch => write!(f, "start anchor mismatch"),
            Self::EndAnchorMismatch => write!(f, "end anchor mismatch"),
            Self::StartAccumulatorMismatch => write!(f, "start accumulator mismatch"),
            Self::EndAccumulatorMismatch => write!(f, "end accumulator mismatch"),
            Self::StartConsensusMismatch => write!(f, "start consensus mismatch"),
            Self::EndConsensusMismatch => write!(f, "end consensus mismatch"),
            Self::BatchStartMismatch => write!(f, "checkpoint batch start mismatch"),
            Self::StepHeadMismatch => write!(f, "checkpoint step head mismatch"),
            Self::RecursiveHeadMismatch => write!(f, "recursive checkpoint head mismatch"),
        }
    }
}

impl std::error::Error for HistoryCheckpointProofError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HistoryCheckpointStepProofError {
    UnsupportedVersion {
        actual: u32,
    },
    BadCheckpointStep(HistoryCheckpointProofError),
    StepStatementDigestMismatch,
    CertificateBatchDigestMismatch,
    CertificateBatchLengthMismatch {
        step: u32,
        certificates: u32,
    },
    CertificateBatchAcceptedClaimDigestMismatch,
    EmptyBackendProof,
    DecodeBackendProof,
    BadStepStatementDigestProof,
    BadStepStatementDigestDischarge,
    BadCertificateBatchStatement(AcceptedBlockCertificateBatchError),
    BadCertificateBatchDigestProof(AcceptedBlockCertificateProofError),
    BadCertificateValidityHandleProof(AcceptedBlockCertificateProofError),
    BadCertificateValidityHandle(AcceptedBlockCertificateValidityHandleError),
    CertificateStatementLengthMismatch {
        certificates: usize,
        statements: usize,
    },
    CertificateStatementDigestMismatch {
        index: usize,
    },
    CertificateValidityProofLengthMismatch {
        certificates: usize,
        proofs: usize,
        receipts: usize,
    },
    CertificateValidityProofStatementMismatch {
        index: usize,
    },
    CertificateValidityProofHandleMismatch {
        index: usize,
    },
    CertificateReceiptProjection {
        index: usize,
        source: AcceptedBlockCertificateReceiptError,
    },
    AcceptedClaimBatchLengthMismatch {
        step: u32,
        claims: usize,
    },
    AcceptedClaimBatchOutputMismatch,
    AcceptedClaimBatchDigestMismatch,
    MissingAcceptedClaimBatchDigestProof,
    BadAcceptedClaimBatchDigestProof(AcceptedClaimBatchDigestError),
    CertificateBatchComponentMismatch,
    BadAcceptedBlockBatchComponents(AcceptedBlockBatchComponentErrorV1),
    BadCheckpointIvcChunkCore(HistoryCheckpointIvcChunkCoreError),
}

impl std::fmt::Display for HistoryCheckpointStepProofError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedVersion { actual } => {
                write!(f, "unsupported history checkpoint step proof version {actual}")
            }
            Self::BadCheckpointStep(source) => {
                write!(f, "bad checkpoint step statement: {source}")
            }
            Self::StepStatementDigestMismatch => {
                write!(f, "checkpoint step statement digest mismatch")
            }
            Self::CertificateBatchDigestMismatch => {
                write!(f, "checkpoint certificate batch statement digest mismatch")
            }
            Self::CertificateBatchLengthMismatch { step, certificates } => write!(
                f,
                "checkpoint certificate batch length mismatch: step {step}, certificates {certificates}"
            ),
            Self::CertificateBatchAcceptedClaimDigestMismatch => write!(
                f,
                "checkpoint certificate batch accepted-claim digest mismatch"
            ),
            Self::EmptyBackendProof => write!(f, "empty checkpoint step backend proof"),
            Self::DecodeBackendProof => write!(f, "bad checkpoint step backend proof"),
            Self::BadStepStatementDigestProof => {
                write!(f, "bad checkpoint step statement digest proof")
            }
            Self::BadStepStatementDigestDischarge => {
                write!(f, "checkpoint step statement digest proof failed native discharge")
            }
            Self::BadCertificateBatchStatement(source) => {
                write!(f, "bad checkpoint certificate batch statement: {source}")
            }
            Self::BadCertificateBatchDigestProof(source) => {
                write!(f, "bad checkpoint certificate batch digest proof: {source}")
            }
            Self::BadCertificateValidityHandleProof(source) => {
                write!(
                    f,
                    "bad checkpoint certificate validity handle proof: {source}"
                )
            }
            Self::BadCertificateValidityHandle(source) => {
                write!(f, "bad checkpoint certificate validity handle: {source}")
            }
            Self::CertificateStatementLengthMismatch {
                certificates,
                statements,
            } => write!(
                f,
                "checkpoint certificate statement length mismatch: certificates={certificates}, statements={statements}"
            ),
            Self::CertificateStatementDigestMismatch { index } => write!(
                f,
                "checkpoint certificate statement digest mismatch at {index}"
            ),
            Self::CertificateValidityProofLengthMismatch {
                certificates,
                proofs,
                receipts,
            } => write!(
                f,
                "checkpoint certificate validity proof length mismatch: certificates={certificates}, proofs={proofs}, receipts={receipts}"
            ),
            Self::CertificateValidityProofStatementMismatch { index } => write!(
                f,
                "checkpoint certificate validity proof statement mismatch at {index}"
            ),
            Self::CertificateValidityProofHandleMismatch { index } => write!(
                f,
                "checkpoint certificate validity proof handle mismatch at {index}"
            ),
            Self::CertificateReceiptProjection { index, source } => write!(
                f,
                "checkpoint certificate receipt projection mismatch at {index}: {source}"
            ),
            Self::AcceptedClaimBatchLengthMismatch { step, claims } => write!(
                f,
                "checkpoint accepted-claim batch length mismatch: step {step}, claims {claims}"
            ),
            Self::AcceptedClaimBatchOutputMismatch => {
                write!(f, "checkpoint accepted-claim batch output mismatch")
            }
            Self::AcceptedClaimBatchDigestMismatch => {
                write!(f, "checkpoint accepted-claim batch digest mismatch")
            }
            Self::MissingAcceptedClaimBatchDigestProof => {
                write!(f, "missing checkpoint accepted-claim batch digest proof")
            }
            Self::BadAcceptedClaimBatchDigestProof(source) => {
                write!(f, "bad checkpoint accepted-claim batch digest proof: {source}")
            }
            Self::CertificateBatchComponentMismatch => {
                write!(f, "checkpoint certificate batch does not match accepted-block components")
            }
            Self::BadAcceptedBlockBatchComponents(source) => {
                write!(f, "bad checkpoint accepted-block batch components: {source:?}")
            }
            Self::BadCheckpointIvcChunkCore(source) => {
                write!(f, "bad checkpoint IVC chunk-core proof: {source}")
            }
        }
    }
}

impl std::error::Error for HistoryCheckpointStepProofError {}

pub fn history_checkpoint_head_from_boundary_v1(
    anchor: &HeaderChainAnchor,
    accumulator: &ChainAccumulator,
    consensus: &RecursiveConsensusState,
) -> Result<HistoryCheckpointHeadV1, HistoryCheckpointProofError> {
    validate_boundary(anchor, accumulator, consensus, true)?;
    let boundary_digest = history_checkpoint_boundary_digest(anchor, accumulator, consensus);
    Ok(HistoryCheckpointHeadV1 {
        version: HISTORY_CHECKPOINT_PROOF_VERSION,
        engine_id: HISTORY_CHECKPOINT_ENGINE_STREAMING_TOWER_IVC_V1,
        checkpoint_height: anchor.height,
        batch_count: 0,
        anchor_digest: history_checkpoint_anchor_digest(anchor),
        accumulator_digest: history_checkpoint_accumulator_digest(accumulator),
        consensus_digest: history_checkpoint_consensus_digest(consensus),
        recursive_digest: history_checkpoint_base_recursive_digest(&boundary_digest),
    })
}

pub fn advance_history_checkpoint_head_v1_native(
    previous_head: &HistoryCheckpointHeadV1,
    batch_summary: &HistoryCheckpointBatchSummaryV1,
) -> Result<HistoryCheckpointHeadV1, HistoryCheckpointProofError> {
    validate_head_shape(previous_head)?;
    validate_batch_summary_shape(batch_summary)?;

    let start_anchor_digest = history_checkpoint_anchor_digest(&batch_summary.start_anchor);
    let start_accumulator_digest =
        history_checkpoint_accumulator_digest(&batch_summary.start_accumulator);
    let start_consensus_digest =
        history_checkpoint_consensus_digest(&batch_summary.start_consensus);
    if previous_head.checkpoint_height != batch_summary.start_anchor.height
        || previous_head.anchor_digest != start_anchor_digest
        || previous_head.accumulator_digest != start_accumulator_digest
        || previous_head.consensus_digest != start_consensus_digest
    {
        return Err(HistoryCheckpointProofError::BatchStartMismatch);
    }

    let previous_head_digest = history_checkpoint_head_digest(previous_head);
    let batch_summary_digest = history_checkpoint_batch_summary_digest(batch_summary);
    Ok(HistoryCheckpointHeadV1 {
        version: HISTORY_CHECKPOINT_PROOF_VERSION,
        engine_id: HISTORY_CHECKPOINT_ENGINE_STREAMING_TOWER_IVC_V1,
        checkpoint_height: batch_summary.end_anchor.height,
        batch_count: previous_head.batch_count.saturating_add(1),
        anchor_digest: history_checkpoint_anchor_digest(&batch_summary.end_anchor),
        accumulator_digest: history_checkpoint_accumulator_digest(&batch_summary.end_accumulator),
        consensus_digest: history_checkpoint_consensus_digest(&batch_summary.end_consensus),
        recursive_digest: history_checkpoint_fold_recursive_digest(
            &previous_head.recursive_digest,
            &previous_head_digest,
            &batch_summary_digest,
        ),
    })
}

pub fn verify_history_checkpoint_step_statement_v1_native(
    statement: &HistoryCheckpointStepStatementV1,
) -> Result<(), HistoryCheckpointProofError> {
    if statement.version != HISTORY_CHECKPOINT_PROOF_VERSION {
        return Err(HistoryCheckpointProofError::UnsupportedVersion {
            actual: statement.version,
        });
    }
    let expected = advance_history_checkpoint_head_v1_native(
        &statement.previous_head,
        &statement.batch_summary,
    )?;
    if statement.next_head != expected {
        return Err(HistoryCheckpointProofError::StepHeadMismatch);
    }
    Ok(())
}

pub fn verify_history_checkpoint_step_proof_v1_checkpoint(
    statement: &HistoryCheckpointStepStatementV1,
    certificate_batch_statement: &AcceptedBlockCertificateBatchStatementV1,
    proof: &HistoryCheckpointStepProofV1,
) -> Result<(), HistoryCheckpointStepProofError> {
    let backend = verify_history_checkpoint_step_public_digest_components_v1(
        statement,
        certificate_batch_statement,
        proof,
    )?;

    verify_history_checkpoint_step_final_backend_gate_v1(certificate_batch_statement, &backend)
}

fn verify_history_checkpoint_step_final_backend_gate_v1(
    certificate_batch_statement: &AcceptedBlockCertificateBatchStatementV1,
    backend: &HistoryCheckpointStepBackendProofV1,
) -> Result<(), HistoryCheckpointStepProofError> {
    verify_checkpoint_step_certificate_validity_backend_v1(certificate_batch_statement, backend)
}

pub fn verify_history_checkpoint_step_proof_v1_private_components_native(
    statement: &HistoryCheckpointStepStatementV1,
    certificate_batch_statement: &AcceptedBlockCertificateBatchStatementV1,
    accepted_claim_witness: &AcceptedClaimBatchWitness,
    accepted_claim_output: &AcceptedClaimBatchOutput,
    proof: &HistoryCheckpointStepProofV1,
) -> Result<(), HistoryCheckpointStepProofError> {
    let backend = verify_history_checkpoint_step_public_digest_components_v1(
        statement,
        certificate_batch_statement,
        proof,
    )?;
    validate_checkpoint_step_accepted_claim_batch_binding(
        statement,
        accepted_claim_witness,
        accepted_claim_output,
    )?;
    let accepted_claim_batch_digest_proof = backend
        .accepted_claim_batch_digest_proof
        .as_ref()
        .ok_or(HistoryCheckpointStepProofError::MissingAcceptedClaimBatchDigestProof)?;
    verify_accepted_claim_batch_digest_v1(
        accepted_claim_witness,
        accepted_claim_output,
        accepted_claim_batch_digest_proof,
    )
    .map_err(HistoryCheckpointStepProofError::BadAcceptedClaimBatchDigestProof)
}

pub fn verify_history_checkpoint_step_proof_v1_private_block_components_native(
    statement: &HistoryCheckpointStepStatementV1,
    certificate_batch_statement: &AcceptedBlockCertificateBatchStatementV1,
    accepted_block_component_inputs: &AcceptedBlockBatchComponentInputsV1,
    accepted_block_component_proof: &AcceptedBlockBatchComponentProofV1,
    proof: &HistoryCheckpointStepProofV1,
) -> Result<AcceptedClaimBatchOutput, HistoryCheckpointStepProofError> {
    let backend = verify_history_checkpoint_step_public_digest_components_v1(
        statement,
        certificate_batch_statement,
        proof,
    )?;
    let accepted_claim_output = verify_accepted_block_batch_components_v1(
        &statement.batch_summary.start_consensus,
        &statement.batch_summary.start_accumulator,
        &statement.batch_summary.end_accumulator,
        accepted_block_component_inputs,
        accepted_block_component_proof,
    )
    .map_err(HistoryCheckpointStepProofError::BadAcceptedBlockBatchComponents)?;
    validate_checkpoint_step_accepted_block_components_binding(
        statement,
        certificate_batch_statement,
        accepted_block_component_inputs,
        &accepted_claim_output,
    )?;

    let accepted_claim_batch_digest_proof = backend
        .accepted_claim_batch_digest_proof
        .as_ref()
        .ok_or(HistoryCheckpointStepProofError::MissingAcceptedClaimBatchDigestProof)?;
    verify_accepted_claim_batch_digest_v1(
        &accepted_block_component_inputs.accepted_claim_witness,
        &accepted_claim_output,
        accepted_claim_batch_digest_proof,
    )
    .map_err(HistoryCheckpointStepProofError::BadAcceptedClaimBatchDigestProof)?;

    Ok(accepted_claim_output)
}

fn verify_history_checkpoint_step_public_digest_components_v1(
    statement: &HistoryCheckpointStepStatementV1,
    certificate_batch_statement: &AcceptedBlockCertificateBatchStatementV1,
    proof: &HistoryCheckpointStepProofV1,
) -> Result<HistoryCheckpointStepBackendProofV1, HistoryCheckpointStepProofError> {
    if proof.version != HISTORY_CHECKPOINT_PROOF_VERSION {
        return Err(HistoryCheckpointStepProofError::UnsupportedVersion {
            actual: proof.version,
        });
    }
    verify_history_checkpoint_step_statement_v1_native(statement)
        .map_err(HistoryCheckpointStepProofError::BadCheckpointStep)?;

    let expected_step_digest = history_checkpoint_step_statement_digest(statement);
    if proof.step_statement_digest != expected_step_digest {
        return Err(HistoryCheckpointStepProofError::StepStatementDigestMismatch);
    }

    let expected_certificate_digest =
        accepted_block_certificate_batch_statement_digest_v1(certificate_batch_statement);
    if proof.certificate_batch_statement_digest != expected_certificate_digest {
        return Err(HistoryCheckpointStepProofError::CertificateBatchDigestMismatch);
    }
    validate_checkpoint_step_certificate_batch_binding(statement, certificate_batch_statement)?;
    if proof.backend_proof.is_empty() {
        return Err(HistoryCheckpointStepProofError::EmptyBackendProof);
    }
    let backend: HistoryCheckpointStepBackendProofV1 =
        bincode::deserialize(&proof.backend_proof)
            .map_err(|_| HistoryCheckpointStepProofError::DecodeBackendProof)?;
    if backend.version != HISTORY_CHECKPOINT_PROOF_VERSION {
        return Err(HistoryCheckpointStepProofError::UnsupportedVersion {
            actual: backend.version,
        });
    }
    verify_accepted_block_certificate_batch_digest_proof_v1(
        certificate_batch_statement,
        &backend.certificate_batch_digest_proof,
    )
    .map_err(HistoryCheckpointStepProofError::BadCertificateBatchDigestProof)?;
    verify_history_checkpoint_step_digest_proof_v1(
        statement,
        &backend.step_statement_digest_proof,
    )?;
    if let Some(checkpoint_ivc_chunk_core_proof) = &backend.checkpoint_ivc_chunk_core_proof {
        verify_history_checkpoint_ivc_chunk_core_v1(
            statement,
            certificate_batch_statement,
            checkpoint_ivc_chunk_core_proof,
        )
        .map_err(HistoryCheckpointStepProofError::BadCheckpointIvcChunkCore)?;
        let accepted_claim_batch_digest_proof = backend
            .accepted_claim_batch_digest_proof
            .as_ref()
            .ok_or(HistoryCheckpointStepProofError::MissingAcceptedClaimBatchDigestProof)?;
        verify_accepted_claim_batch_digest_hash_fields_v1(
            &checkpoint_ivc_chunk_core_proof.accepted_claim_digest_hash_fields,
            statement.batch_summary.accepted_claim_batch_digest,
            accepted_claim_batch_digest_proof,
        )
        .map_err(HistoryCheckpointStepProofError::BadAcceptedClaimBatchDigestProof)?;
    }
    validate_checkpoint_step_certificate_validity_sidecars_v1(
        certificate_batch_statement,
        &backend,
        backend.checkpoint_ivc_chunk_core_proof.as_ref(),
    )?;

    Ok(backend)
}

fn validate_checkpoint_step_certificate_validity_sidecars_v1(
    certificate_batch_statement: &AcceptedBlockCertificateBatchStatementV1,
    backend: &HistoryCheckpointStepBackendProofV1,
    checkpoint_ivc_chunk_core_proof: Option<&HistoryCheckpointIvcChunkCoreProofV1>,
) -> Result<(), HistoryCheckpointStepProofError> {
    let certificate_len = certificate_batch_statement.batch_len as usize;
    let statement_len = backend.certificate_statements.len();
    let proof_len = backend.certificate_validity_proofs.len();

    if statement_len == 0 && proof_len == 0 {
        return Ok(());
    }
    if statement_len != certificate_len {
        return Err(
            HistoryCheckpointStepProofError::CertificateStatementLengthMismatch {
                certificates: certificate_len,
                statements: statement_len,
            },
        );
    }
    if proof_len != certificate_len {
        return Err(
            HistoryCheckpointStepProofError::CertificateValidityProofLengthMismatch {
                certificates: certificate_len,
                proofs: proof_len,
                receipts: checkpoint_ivc_chunk_core_proof
                    .map(|proof| proof.certificate_receipts.len())
                    .unwrap_or(0),
            },
        );
    }

    if let Some(chunk_core) = checkpoint_ivc_chunk_core_proof {
        if chunk_core.certificate_receipts.len() != certificate_len {
            return Err(
                HistoryCheckpointStepProofError::CertificateValidityProofLengthMismatch {
                    certificates: certificate_len,
                    proofs: proof_len,
                    receipts: chunk_core.certificate_receipts.len(),
                },
            );
        }
    }

    for index in 0..certificate_len {
        let statement = &backend.certificate_statements[index];
        let statement_digest = accepted_block_certificate_statement_digest_v1(statement);
        if statement_digest != certificate_batch_statement.certificate_statement_digests[index] {
            return Err(
                HistoryCheckpointStepProofError::CertificateStatementDigestMismatch { index },
            );
        }

        let proof = &backend.certificate_validity_proofs[index];
        if proof.statement_digest != statement_digest {
            return Err(
                HistoryCheckpointStepProofError::CertificateValidityProofStatementMismatch {
                    index,
                },
            );
        }

        if let Some(chunk_core) = checkpoint_ivc_chunk_core_proof {
            let handle = accepted_block_certificate_validity_handle_v1(proof)
                .map_err(HistoryCheckpointStepProofError::BadCertificateValidityHandle)?;
            if handle != chunk_core.certificate_validity_handles[index] {
                return Err(
                    HistoryCheckpointStepProofError::CertificateValidityProofHandleMismatch {
                        index,
                    },
                );
            }
            verify_accepted_block_certificate_receipt_projection_v1(
                statement,
                &chunk_core.certificate_receipts[index],
            )
            .map_err(|source| {
                HistoryCheckpointStepProofError::CertificateReceiptProjection { index, source }
            })?;
        }
    }

    Ok(())
}

fn verify_checkpoint_step_certificate_validity_backend_v1(
    certificate_batch_statement: &AcceptedBlockCertificateBatchStatementV1,
    backend: &HistoryCheckpointStepBackendProofV1,
) -> Result<(), HistoryCheckpointStepProofError> {
    let certificate_len = certificate_batch_statement.batch_len as usize;
    if backend.certificate_statements.is_empty() || backend.certificate_validity_proofs.is_empty() {
        return Ok(());
    }
    if backend.certificate_statements.len() != certificate_len {
        return Err(
            HistoryCheckpointStepProofError::CertificateStatementLengthMismatch {
                certificates: certificate_len,
                statements: backend.certificate_statements.len(),
            },
        );
    }
    if backend.certificate_validity_proofs.len() != certificate_len {
        return Err(
            HistoryCheckpointStepProofError::CertificateValidityProofLengthMismatch {
                certificates: certificate_len,
                proofs: backend.certificate_validity_proofs.len(),
                receipts: backend
                    .checkpoint_ivc_chunk_core_proof
                    .as_ref()
                    .map(|proof| proof.certificate_receipts.len())
                    .unwrap_or(0),
            },
        );
    }

    for (statement, proof) in backend
        .certificate_statements
        .iter()
        .zip(backend.certificate_validity_proofs.iter())
    {
        match verify_accepted_block_certificate_proof_v1_checkpoint(statement, proof) {
            Ok(()) => {}
            Err(source) => {
                return Err(
                    HistoryCheckpointStepProofError::BadCertificateValidityHandleProof(source),
                );
            }
        }
    }

    Ok(())
}

pub fn prove_history_checkpoint_step_proof_v1_batch_digest_only(
    statement: &HistoryCheckpointStepStatementV1,
    certificate_batch_statement: &AcceptedBlockCertificateBatchStatementV1,
) -> Result<HistoryCheckpointStepProofV1, HistoryCheckpointStepProofError> {
    verify_history_checkpoint_step_statement_v1_native(statement)
        .map_err(HistoryCheckpointStepProofError::BadCheckpointStep)?;
    validate_checkpoint_step_certificate_batch_binding(statement, certificate_batch_statement)?;
    let (step_statement_digest_proof, certificate_batch_digest_proof) = rayon::join(
        || prove_history_checkpoint_step_digest_proof_v1(statement),
        || {
            prove_accepted_block_certificate_batch_digest_proof_v1(certificate_batch_statement)
                .map_err(HistoryCheckpointStepProofError::BadCertificateBatchDigestProof)
        },
    );
    let backend = HistoryCheckpointStepBackendProofV1 {
        version: HISTORY_CHECKPOINT_PROOF_VERSION,
        step_statement_digest_proof: step_statement_digest_proof?,
        certificate_batch_digest_proof: certificate_batch_digest_proof?,
        certificate_statements: Vec::new(),
        certificate_validity_proofs: Vec::new(),
        accepted_claim_batch_digest_proof: None,
        checkpoint_ivc_chunk_core_proof: None,
    };
    Ok(HistoryCheckpointStepProofV1 {
        version: HISTORY_CHECKPOINT_PROOF_VERSION,
        step_statement_digest: history_checkpoint_step_statement_digest(statement),
        certificate_batch_statement_digest: accepted_block_certificate_batch_statement_digest_v1(
            certificate_batch_statement,
        ),
        backend_proof: bincode::serialize(&backend)
            .expect("HistoryCheckpointStepBackendProofV1 serializes"),
    })
}

pub fn prove_history_checkpoint_step_proof_v1_with_digest_components(
    statement: &HistoryCheckpointStepStatementV1,
    certificate_batch_statement: &AcceptedBlockCertificateBatchStatementV1,
    accepted_claim_witness: &AcceptedClaimBatchWitness,
    accepted_claim_output: &AcceptedClaimBatchOutput,
) -> Result<HistoryCheckpointStepProofV1, HistoryCheckpointStepProofError> {
    verify_history_checkpoint_step_statement_v1_native(statement)
        .map_err(HistoryCheckpointStepProofError::BadCheckpointStep)?;
    validate_checkpoint_step_certificate_batch_binding(statement, certificate_batch_statement)?;
    validate_checkpoint_step_accepted_claim_batch_binding(
        statement,
        accepted_claim_witness,
        accepted_claim_output,
    )?;

    let ((step_statement_digest_proof, certificate_batch_digest_proof), accepted_claim_proof) =
        rayon::join(
            || {
                rayon::join(
                    || prove_history_checkpoint_step_digest_proof_v1(statement),
                    || {
                        prove_accepted_block_certificate_batch_digest_proof_v1(
                            certificate_batch_statement,
                        )
                        .map_err(HistoryCheckpointStepProofError::BadCertificateBatchDigestProof)
                    },
                )
            },
            || {
                prove_accepted_claim_batch_digest_v1(accepted_claim_witness, accepted_claim_output)
                    .map_err(HistoryCheckpointStepProofError::BadAcceptedClaimBatchDigestProof)
            },
        );
    let backend = HistoryCheckpointStepBackendProofV1 {
        version: HISTORY_CHECKPOINT_PROOF_VERSION,
        step_statement_digest_proof: step_statement_digest_proof?,
        certificate_batch_digest_proof: certificate_batch_digest_proof?,
        certificate_statements: Vec::new(),
        certificate_validity_proofs: Vec::new(),
        accepted_claim_batch_digest_proof: Some(accepted_claim_proof?),
        checkpoint_ivc_chunk_core_proof: None,
    };
    Ok(HistoryCheckpointStepProofV1 {
        version: HISTORY_CHECKPOINT_PROOF_VERSION,
        step_statement_digest: history_checkpoint_step_statement_digest(statement),
        certificate_batch_statement_digest: accepted_block_certificate_batch_statement_digest_v1(
            certificate_batch_statement,
        ),
        backend_proof: bincode::serialize(&backend)
            .expect("HistoryCheckpointStepBackendProofV1 serializes"),
    })
}

pub fn prove_history_checkpoint_step_proof_v1_with_ivc_chunk_core_components(
    statement: &HistoryCheckpointStepStatementV1,
    certificate_batch_statement: &AcceptedBlockCertificateBatchStatementV1,
    certificate_statements: &[AcceptedBlockCertificateStatementV1],
    accepted_claim_witness: &AcceptedClaimBatchWitness,
    accepted_claim_output: &AcceptedClaimBatchOutput,
) -> Result<HistoryCheckpointStepProofV1, HistoryCheckpointStepProofError> {
    let certificate_receipts = certificate_statements
        .iter()
        .map(accepted_block_certificate_receipt_v1)
        .collect::<Vec<_>>();
    let certificate_validity_proofs =
        certificate_validity_proofs_from_statements(certificate_statements)?;
    prove_history_checkpoint_step_proof_v1_with_ivc_chunk_certificate_proof_components(
        statement,
        certificate_batch_statement,
        certificate_statements,
        &certificate_validity_proofs,
        &certificate_receipts,
        accepted_claim_witness,
        accepted_claim_output,
    )
}

pub fn prove_history_checkpoint_step_proof_v1_with_ivc_chunk_certificate_proof_components(
    statement: &HistoryCheckpointStepStatementV1,
    certificate_batch_statement: &AcceptedBlockCertificateBatchStatementV1,
    certificate_statements: &[AcceptedBlockCertificateStatementV1],
    certificate_validity_proofs: &[AcceptedBlockCertificateProofV1],
    certificate_receipts: &[AcceptedBlockCertificateReceiptV1],
    accepted_claim_witness: &AcceptedClaimBatchWitness,
    accepted_claim_output: &AcceptedClaimBatchOutput,
) -> Result<HistoryCheckpointStepProofV1, HistoryCheckpointStepProofError> {
    let certificate_validity_handles = certificate_validity_handles_from_proofs(
        certificate_batch_statement,
        certificate_validity_proofs,
        certificate_receipts,
    )?;
    prove_history_checkpoint_step_proof_v1_with_ivc_chunk_receipt_handle_components_inner(
        statement,
        certificate_batch_statement,
        certificate_statements,
        certificate_validity_proofs,
        &certificate_validity_handles,
        certificate_receipts,
        accepted_claim_witness,
        accepted_claim_output,
    )
}

pub fn prove_history_checkpoint_step_proof_v1_with_ivc_chunk_receipt_handle_components(
    statement: &HistoryCheckpointStepStatementV1,
    certificate_batch_statement: &AcceptedBlockCertificateBatchStatementV1,
    certificate_validity_handles: &[AcceptedBlockCertificateValidityHandleV1],
    certificate_receipts: &[AcceptedBlockCertificateReceiptV1],
    accepted_claim_witness: &AcceptedClaimBatchWitness,
    accepted_claim_output: &AcceptedClaimBatchOutput,
) -> Result<HistoryCheckpointStepProofV1, HistoryCheckpointStepProofError> {
    prove_history_checkpoint_step_proof_v1_with_ivc_chunk_receipt_handle_components_inner(
        statement,
        certificate_batch_statement,
        &[],
        &[],
        certificate_validity_handles,
        certificate_receipts,
        accepted_claim_witness,
        accepted_claim_output,
    )
}

#[allow(clippy::too_many_arguments)]
fn prove_history_checkpoint_step_proof_v1_with_ivc_chunk_receipt_handle_components_inner(
    statement: &HistoryCheckpointStepStatementV1,
    certificate_batch_statement: &AcceptedBlockCertificateBatchStatementV1,
    certificate_statements: &[AcceptedBlockCertificateStatementV1],
    certificate_validity_proofs: &[AcceptedBlockCertificateProofV1],
    certificate_validity_handles: &[AcceptedBlockCertificateValidityHandleV1],
    certificate_receipts: &[AcceptedBlockCertificateReceiptV1],
    accepted_claim_witness: &AcceptedClaimBatchWitness,
    accepted_claim_output: &AcceptedClaimBatchOutput,
) -> Result<HistoryCheckpointStepProofV1, HistoryCheckpointStepProofError> {
    verify_history_checkpoint_step_statement_v1_native(statement)
        .map_err(HistoryCheckpointStepProofError::BadCheckpointStep)?;
    validate_checkpoint_step_certificate_batch_binding(statement, certificate_batch_statement)?;
    validate_checkpoint_step_accepted_claim_batch_binding(
        statement,
        accepted_claim_witness,
        accepted_claim_output,
    )?;

    let prove_digest_components = || {
        rayon::join(
            || {
                rayon::join(
                    || prove_history_checkpoint_step_digest_proof_v1(statement),
                    || {
                        prove_accepted_block_certificate_batch_digest_proof_v1(
                            certificate_batch_statement,
                        )
                        .map_err(HistoryCheckpointStepProofError::BadCertificateBatchDigestProof)
                    },
                )
            },
            || {
                prove_accepted_claim_batch_digest_v1(accepted_claim_witness, accepted_claim_output)
                    .map_err(HistoryCheckpointStepProofError::BadAcceptedClaimBatchDigestProof)
            },
        )
    };
    let prove_chunk_core = || {
        if statement.batch_summary.batch_len == HISTORY_CHECKPOINT_BATCH_TARGET_BLOCKS {
            prove_history_checkpoint_ivc_chunk_receipt_handle_core_v1(
                statement,
                certificate_batch_statement,
                certificate_validity_handles,
                certificate_receipts,
                accepted_claim_witness,
                accepted_claim_output,
            )
            .map_err(HistoryCheckpointStepProofError::BadCheckpointIvcChunkCore)
            .map(Some)
        } else {
            Ok(None)
        }
    };
    let (
        ((step_statement_digest_proof, certificate_batch_digest_proof), accepted_claim_proof),
        checkpoint_ivc_chunk_core_proof,
    ) = rayon::join(prove_digest_components, prove_chunk_core);

    let backend = HistoryCheckpointStepBackendProofV1 {
        version: HISTORY_CHECKPOINT_PROOF_VERSION,
        step_statement_digest_proof: step_statement_digest_proof?,
        certificate_batch_digest_proof: certificate_batch_digest_proof?,
        certificate_statements: certificate_statements.to_vec(),
        certificate_validity_proofs: certificate_validity_proofs.to_vec(),
        accepted_claim_batch_digest_proof: Some(accepted_claim_proof?),
        checkpoint_ivc_chunk_core_proof: checkpoint_ivc_chunk_core_proof?,
    };
    Ok(HistoryCheckpointStepProofV1 {
        version: HISTORY_CHECKPOINT_PROOF_VERSION,
        step_statement_digest: history_checkpoint_step_statement_digest(statement),
        certificate_batch_statement_digest: accepted_block_certificate_batch_statement_digest_v1(
            certificate_batch_statement,
        ),
        backend_proof: bincode::serialize(&backend)
            .expect("HistoryCheckpointStepBackendProofV1 serializes"),
    })
}

fn certificate_validity_proofs_from_statements(
    certificate_statements: &[AcceptedBlockCertificateStatementV1],
) -> Result<Vec<AcceptedBlockCertificateProofV1>, HistoryCheckpointStepProofError> {
    certificate_statements
        .par_iter()
        .map(|statement| {
            prove_accepted_block_certificate_proof_v1_hash_only(statement)
                .map_err(HistoryCheckpointStepProofError::BadCertificateValidityHandleProof)
        })
        .collect()
}

pub fn prove_history_checkpoint_step_proof_v1_from_certificate_statements(
    statement: &HistoryCheckpointStepStatementV1,
    certificate_statements: &[AcceptedBlockCertificateStatementV1],
    accepted_claim_witness: &AcceptedClaimBatchWitness,
    accepted_claim_output: &AcceptedClaimBatchOutput,
) -> Result<
    (
        HistoryCheckpointStepProofV1,
        AcceptedBlockCertificateBatchStatementV1,
    ),
    HistoryCheckpointStepProofError,
> {
    let accepted_claim_batch_digest = validate_checkpoint_step_accepted_claim_batch_binding(
        statement,
        accepted_claim_witness,
        accepted_claim_output,
    )?;
    let certificate_batch_statement = accepted_block_certificate_batch_statement_v1(
        certificate_statements,
        &accepted_claim_witness.accepted_block_claims,
        accepted_claim_batch_digest,
    )
    .map_err(HistoryCheckpointStepProofError::BadCertificateBatchStatement)?;
    let proof = prove_history_checkpoint_step_proof_v1_with_ivc_chunk_core_components(
        statement,
        &certificate_batch_statement,
        certificate_statements,
        accepted_claim_witness,
        accepted_claim_output,
    )?;
    Ok((proof, certificate_batch_statement))
}

pub fn prove_history_checkpoint_step_proof_v1_from_block_components(
    statement: &HistoryCheckpointStepStatementV1,
    accepted_block_component_inputs: &AcceptedBlockBatchComponentInputsV1,
    accepted_block_component_proof: &AcceptedBlockBatchComponentProofV1,
) -> Result<
    (
        HistoryCheckpointStepProofV1,
        AcceptedBlockCertificateBatchStatementV1,
        AcceptedClaimBatchOutput,
    ),
    HistoryCheckpointStepProofError,
> {
    let certificate_receipts = accepted_block_component_inputs
        .accepted_block_certificate_statements
        .iter()
        .map(accepted_block_certificate_receipt_v1)
        .collect::<Vec<_>>();
    let certificate_validity_proofs = certificate_validity_proofs_from_statements(
        &accepted_block_component_inputs.accepted_block_certificate_statements,
    )?;
    prove_history_checkpoint_step_proof_v1_from_block_components_with_certificate_proofs_v1(
        statement,
        accepted_block_component_inputs,
        accepted_block_component_proof,
        &certificate_validity_proofs,
        &certificate_receipts,
    )
}

pub fn prove_history_checkpoint_step_proof_v1_from_block_components_with_certificate_proofs_v1(
    statement: &HistoryCheckpointStepStatementV1,
    accepted_block_component_inputs: &AcceptedBlockBatchComponentInputsV1,
    accepted_block_component_proof: &AcceptedBlockBatchComponentProofV1,
    certificate_validity_proofs: &[AcceptedBlockCertificateProofV1],
    certificate_receipts: &[AcceptedBlockCertificateReceiptV1],
) -> Result<
    (
        HistoryCheckpointStepProofV1,
        AcceptedBlockCertificateBatchStatementV1,
        AcceptedClaimBatchOutput,
    ),
    HistoryCheckpointStepProofError,
> {
    let accepted_claim_output = verify_accepted_block_batch_components_v1(
        &statement.batch_summary.start_consensus,
        &statement.batch_summary.start_accumulator,
        &statement.batch_summary.end_accumulator,
        accepted_block_component_inputs,
        accepted_block_component_proof,
    )
    .map_err(HistoryCheckpointStepProofError::BadAcceptedBlockBatchComponents)?;
    let accepted_claim_batch_digest = validate_checkpoint_step_accepted_claim_batch_binding(
        statement,
        &accepted_block_component_inputs.accepted_claim_witness,
        &accepted_claim_output,
    )?;
    let certificate_batch_statement = accepted_block_certificate_batch_statement_v1(
        &accepted_block_component_inputs.accepted_block_certificate_statements,
        &accepted_block_component_inputs
            .accepted_claim_witness
            .accepted_block_claims,
        accepted_claim_batch_digest,
    )
    .map_err(HistoryCheckpointStepProofError::BadCertificateBatchStatement)?;
    let proof = prove_history_checkpoint_step_proof_v1_with_ivc_chunk_certificate_proof_components(
        statement,
        &certificate_batch_statement,
        &accepted_block_component_inputs.accepted_block_certificate_statements,
        certificate_validity_proofs,
        certificate_receipts,
        &accepted_block_component_inputs.accepted_claim_witness,
        &accepted_claim_output,
    )?;
    Ok((proof, certificate_batch_statement, accepted_claim_output))
}

pub fn prove_history_checkpoint_step_proof_v1_from_block_components_with_certificate_receipt_handles_v1(
    statement: &HistoryCheckpointStepStatementV1,
    accepted_block_component_inputs: &AcceptedBlockBatchComponentInputsV1,
    accepted_block_component_proof: &AcceptedBlockBatchComponentProofV1,
    certificate_validity_handles: &[AcceptedBlockCertificateValidityHandleV1],
    certificate_receipts: &[AcceptedBlockCertificateReceiptV1],
) -> Result<
    (
        HistoryCheckpointStepProofV1,
        AcceptedBlockCertificateBatchStatementV1,
        AcceptedClaimBatchOutput,
    ),
    HistoryCheckpointStepProofError,
> {
    let accepted_claim_output = verify_accepted_block_batch_components_v1(
        &statement.batch_summary.start_consensus,
        &statement.batch_summary.start_accumulator,
        &statement.batch_summary.end_accumulator,
        accepted_block_component_inputs,
        accepted_block_component_proof,
    )
    .map_err(HistoryCheckpointStepProofError::BadAcceptedBlockBatchComponents)?;
    let accepted_claim_batch_digest = validate_checkpoint_step_accepted_claim_batch_binding(
        statement,
        &accepted_block_component_inputs.accepted_claim_witness,
        &accepted_claim_output,
    )?;
    let certificate_batch_statement = accepted_block_certificate_batch_statement_v1(
        &accepted_block_component_inputs.accepted_block_certificate_statements,
        &accepted_block_component_inputs
            .accepted_claim_witness
            .accepted_block_claims,
        accepted_claim_batch_digest,
    )
    .map_err(HistoryCheckpointStepProofError::BadCertificateBatchStatement)?;
    let proof = prove_history_checkpoint_step_proof_v1_with_ivc_chunk_receipt_handle_components(
        statement,
        &certificate_batch_statement,
        certificate_validity_handles,
        certificate_receipts,
        &accepted_block_component_inputs.accepted_claim_witness,
        &accepted_claim_output,
    )?;
    Ok((proof, certificate_batch_statement, accepted_claim_output))
}

fn certificate_validity_handles_from_proofs(
    certificate_batch_statement: &AcceptedBlockCertificateBatchStatementV1,
    certificate_validity_proofs: &[AcceptedBlockCertificateProofV1],
    certificate_receipts: &[AcceptedBlockCertificateReceiptV1],
) -> Result<Vec<AcceptedBlockCertificateValidityHandleV1>, HistoryCheckpointStepProofError> {
    let certificate_len = certificate_batch_statement.batch_len as usize;
    if certificate_validity_proofs.len() != certificate_len
        || certificate_receipts.len() != certificate_len
    {
        return Err(
            HistoryCheckpointStepProofError::CertificateValidityProofLengthMismatch {
                certificates: certificate_len,
                proofs: certificate_validity_proofs.len(),
                receipts: certificate_receipts.len(),
            },
        );
    }
    certificate_validity_proofs
        .iter()
        .enumerate()
        .map(|(index, proof)| {
            if proof.statement_digest
                != certificate_batch_statement.certificate_statement_digests[index]
            {
                return Err(
                    HistoryCheckpointStepProofError::CertificateValidityProofStatementMismatch {
                        index,
                    },
                );
            }
            accepted_block_certificate_validity_handle_v1(proof)
                .map_err(HistoryCheckpointStepProofError::BadCertificateValidityHandle)
        })
        .collect()
}

pub fn prove_history_checkpoint_step_digest_proof_v1(
    statement: &HistoryCheckpointStepStatementV1,
) -> Result<HistoryCheckpointStepDigestProofV1, HistoryCheckpointStepProofError> {
    let fields = history_checkpoint_step_statement_hash_fields(statement);
    let expected_digest = history_checkpoint_step_statement_digest(statement);
    let input = fixed_hash_input(&fields, &expected_digest);
    let params = history_checkpoint_step_statement_hash_params();
    let mut channel = Poseidon2bChannel::new();
    let inputs = [input];
    let (step_statement_digest_hash, reductions) =
        prove_fixed_field_hash_killshot(params, &inputs, &mut channel);
    if !discharge_fixed_field_hash_reductions_native(params, &inputs, &reductions) {
        return Err(HistoryCheckpointStepProofError::BadStepStatementDigestDischarge);
    }
    Ok(HistoryCheckpointStepDigestProofV1 {
        version: HISTORY_CHECKPOINT_PROOF_VERSION,
        step_statement_digest_hash,
    })
}

pub fn verify_history_checkpoint_step_digest_proof_v1(
    statement: &HistoryCheckpointStepStatementV1,
    proof: &HistoryCheckpointStepDigestProofV1,
) -> Result<(), HistoryCheckpointStepProofError> {
    if proof.version != HISTORY_CHECKPOINT_PROOF_VERSION {
        return Err(HistoryCheckpointStepProofError::UnsupportedVersion {
            actual: proof.version,
        });
    }
    let fields = history_checkpoint_step_statement_hash_fields(statement);
    let expected_digest = history_checkpoint_step_statement_digest(statement);
    let input = fixed_hash_input(&fields, &expected_digest);
    let params = history_checkpoint_step_statement_hash_params();
    let mut channel = Poseidon2bChannel::new();
    let inputs = [input];
    let reductions = verify_fixed_field_hash_killshot(
        params,
        &proof.step_statement_digest_hash,
        &inputs,
        &mut channel,
    )
    .ok_or(HistoryCheckpointStepProofError::BadStepStatementDigestProof)?;
    if discharge_fixed_field_hash_reductions_native(params, &inputs, &reductions) {
        Ok(())
    } else {
        Err(HistoryCheckpointStepProofError::BadStepStatementDigestDischarge)
    }
}

pub fn encode_history_checkpoint_recursive_payload_v1(
    payload: &HistoryCheckpointRecursivePayloadV1,
) -> Vec<u8> {
    bincode::serialize(payload).expect("HistoryCheckpointRecursivePayloadV1 serializes")
}

fn validate_checkpoint_step_certificate_batch_binding(
    statement: &HistoryCheckpointStepStatementV1,
    certificate_batch_statement: &AcceptedBlockCertificateBatchStatementV1,
) -> Result<(), HistoryCheckpointStepProofError> {
    if certificate_batch_statement.batch_len != statement.batch_summary.batch_len {
        return Err(
            HistoryCheckpointStepProofError::CertificateBatchLengthMismatch {
                step: statement.batch_summary.batch_len,
                certificates: certificate_batch_statement.batch_len,
            },
        );
    }
    if certificate_batch_statement.accepted_claim_batch_digest
        != statement.batch_summary.accepted_claim_batch_digest
    {
        return Err(HistoryCheckpointStepProofError::CertificateBatchAcceptedClaimDigestMismatch);
    }
    Ok(())
}

fn validate_checkpoint_step_accepted_claim_batch_binding(
    statement: &HistoryCheckpointStepStatementV1,
    accepted_claim_witness: &AcceptedClaimBatchWitness,
    accepted_claim_output: &AcceptedClaimBatchOutput,
) -> Result<Digest, HistoryCheckpointStepProofError> {
    let claim_len = accepted_claim_witness.headers.len();
    if claim_len > u32::MAX as usize || claim_len as u32 != statement.batch_summary.batch_len {
        return Err(
            HistoryCheckpointStepProofError::AcceptedClaimBatchLengthMismatch {
                step: statement.batch_summary.batch_len,
                claims: claim_len,
            },
        );
    }
    if accepted_claim_output.consensus_state != statement.batch_summary.end_consensus
        || accepted_claim_output.accumulator != statement.batch_summary.end_accumulator
    {
        return Err(HistoryCheckpointStepProofError::AcceptedClaimBatchOutputMismatch);
    }
    let digest = accepted_claim_batch_digest_v1(accepted_claim_witness, accepted_claim_output)
        .map_err(HistoryCheckpointStepProofError::BadAcceptedClaimBatchDigestProof)?;
    if digest != statement.batch_summary.accepted_claim_batch_digest {
        return Err(HistoryCheckpointStepProofError::AcceptedClaimBatchDigestMismatch);
    }
    Ok(digest)
}

fn validate_checkpoint_step_accepted_block_components_binding(
    statement: &HistoryCheckpointStepStatementV1,
    certificate_batch_statement: &AcceptedBlockCertificateBatchStatementV1,
    accepted_block_component_inputs: &AcceptedBlockBatchComponentInputsV1,
    accepted_claim_output: &AcceptedClaimBatchOutput,
) -> Result<Digest, HistoryCheckpointStepProofError> {
    let accepted_claim_batch_digest = validate_checkpoint_step_accepted_claim_batch_binding(
        statement,
        &accepted_block_component_inputs.accepted_claim_witness,
        accepted_claim_output,
    )?;
    let expected_certificate_batch_statement = accepted_block_certificate_batch_statement_v1(
        &accepted_block_component_inputs.accepted_block_certificate_statements,
        &accepted_block_component_inputs
            .accepted_claim_witness
            .accepted_block_claims,
        accepted_claim_batch_digest,
    )
    .map_err(HistoryCheckpointStepProofError::BadCertificateBatchStatement)?;
    if &expected_certificate_batch_statement != certificate_batch_statement {
        return Err(HistoryCheckpointStepProofError::CertificateBatchComponentMismatch);
    }
    Ok(accepted_claim_batch_digest)
}

pub fn history_checkpoint_anchor_digest(anchor: &HeaderChainAnchor) -> Digest {
    let mut sponge = checkpoint_sponge(HCP_ANC1);
    absorb_anchor(&mut sponge, anchor);
    sponge.finalize()
}

pub fn history_checkpoint_accumulator_digest(accumulator: &ChainAccumulator) -> Digest {
    let mut sponge = checkpoint_sponge(HCP_ACC1);
    absorb_accumulator(&mut sponge, accumulator);
    sponge.finalize()
}

pub fn history_checkpoint_consensus_digest(consensus: &RecursiveConsensusState) -> Digest {
    let mut sponge = checkpoint_sponge(HCP_CON1);
    absorb_consensus(&mut sponge, consensus);
    sponge.finalize()
}

pub fn history_checkpoint_batch_summary_digest(
    summary: &HistoryCheckpointBatchSummaryV1,
) -> Digest {
    let mut sponge = checkpoint_sponge(HCP_SUM1);
    sponge.absorb(Block128::from(summary.version as u128));
    sponge.absorb(Block128::from(summary.batch_len as u128));
    sponge.absorb(Block128::from(
        HISTORY_CHECKPOINT_BATCH_TARGET_BLOCKS as u128,
    ));
    sponge.absorb(Block128::from(
        HISTORY_CHECKPOINT_RETAINED_WINDOW_BLOCKS as u128,
    ));
    absorb_digest(
        &mut sponge,
        &history_checkpoint_anchor_digest(&summary.start_anchor),
    );
    absorb_digest(
        &mut sponge,
        &history_checkpoint_anchor_digest(&summary.end_anchor),
    );
    absorb_digest(
        &mut sponge,
        &history_checkpoint_accumulator_digest(&summary.start_accumulator),
    );
    absorb_digest(
        &mut sponge,
        &history_checkpoint_accumulator_digest(&summary.end_accumulator),
    );
    absorb_digest(
        &mut sponge,
        &history_checkpoint_consensus_digest(&summary.start_consensus),
    );
    absorb_digest(
        &mut sponge,
        &history_checkpoint_consensus_digest(&summary.end_consensus),
    );
    absorb_digest(&mut sponge, &summary.accepted_claim_batch_digest);
    sponge.finalize()
}

pub fn history_checkpoint_head_digest(head: &HistoryCheckpointHeadV1) -> Digest {
    let mut sponge = checkpoint_sponge(HCP_HEAD1);
    sponge.absorb(Block128::from(head.version as u128));
    sponge.absorb(Block128::from(head.engine_id as u128));
    sponge.absorb(Block128::from(head.checkpoint_height as u128));
    sponge.absorb(Block128::from(head.batch_count as u128));
    absorb_digest(&mut sponge, &head.anchor_digest);
    absorb_digest(&mut sponge, &head.accumulator_digest);
    absorb_digest(&mut sponge, &head.consensus_digest);
    absorb_digest(&mut sponge, &head.recursive_digest);
    sponge.finalize()
}

pub fn history_checkpoint_step_relation_digest() -> Digest {
    let mut sponge = checkpoint_sponge(HCP_REL1);
    sponge.absorb(Block128::from(
        HISTORY_CHECKPOINT_BATCH_TARGET_BLOCKS as u128,
    ));
    sponge.absorb(Block128::from(
        HISTORY_CHECKPOINT_RETAINED_WINDOW_BLOCKS as u128,
    ));
    sponge.finalize()
}

pub fn history_checkpoint_step_statement_digest(
    statement: &HistoryCheckpointStepStatementV1,
) -> Digest {
    digest_fixed_no_pad_from_fields(&history_checkpoint_step_statement_hash_fields(statement))
}

pub fn history_checkpoint_step_statement_hash_fields(
    statement: &HistoryCheckpointStepStatementV1,
) -> [Block128; HISTORY_CHECKPOINT_STEP_STATEMENT_HASH_FIELDS] {
    let mut fields = [Block128::ZERO; HISTORY_CHECKPOINT_STEP_STATEMENT_HASH_FIELDS];
    let mut index = 0usize;
    fields[index] = Block128::from(HCP_STMT1);
    index += 1;
    fields[index] = Block128::from(10u128);
    index += 1;
    fields[index] = Block128::from(HISTORY_CHECKPOINT_PROOF_VERSION as u128);
    index += 1;
    fields[index] = Block128::from(statement.version as u128);
    index += 1;
    push_digest_hash_fields(
        &mut fields,
        &mut index,
        &history_checkpoint_step_relation_digest(),
    );
    push_digest_hash_fields(
        &mut fields,
        &mut index,
        &history_checkpoint_head_digest(&statement.previous_head),
    );
    push_digest_hash_fields(
        &mut fields,
        &mut index,
        &history_checkpoint_batch_summary_digest(&statement.batch_summary),
    );
    push_digest_hash_fields(
        &mut fields,
        &mut index,
        &history_checkpoint_head_digest(&statement.next_head),
    );
    debug_assert_eq!(index, HISTORY_CHECKPOINT_STEP_STATEMENT_HASH_FIELDS);
    fields
}

pub fn history_checkpoint_step_statement_hash_params() -> FixedFieldHashParams {
    FixedFieldHashParams::with_default_relation_tag(
        TAG_HISTPRF,
        HISTORY_CHECKPOINT_STEP_STATEMENT_HASH_FIELDS,
    )
    .expect("history checkpoint step statement hash schedule is valid")
}

pub fn verify_history_checkpoint_proof_v1_checkpoint(
    proof: &HistoryCheckpointProofV1,
    local_start_anchor: &HeaderChainAnchor,
    local_end_anchor: &HeaderChainAnchor,
) -> Result<(), HistoryCheckpointProofError> {
    if proof.version != HISTORY_CHECKPOINT_PROOF_VERSION {
        return Err(HistoryCheckpointProofError::UnsupportedVersion {
            actual: proof.version,
        });
    }
    if proof.engine_id != HISTORY_CHECKPOINT_ENGINE_STREAMING_TOWER_IVC_V1 {
        return Err(HistoryCheckpointProofError::UnsupportedEngine {
            actual: proof.engine_id,
        });
    }
    if proof.recursive_proof.is_empty() {
        return Err(HistoryCheckpointProofError::EmptyRecursiveProof);
    }
    if proof.checkpoint_height != proof.end_anchor.height {
        return Err(HistoryCheckpointProofError::CheckpointHeightMismatch);
    }
    if &proof.start_anchor != local_start_anchor {
        return Err(HistoryCheckpointProofError::StartAnchorMismatch);
    }
    if &proof.end_anchor != local_end_anchor {
        return Err(HistoryCheckpointProofError::EndAnchorMismatch);
    }
    if proof.start_accumulator.height != proof.start_anchor.height
        || proof.start_accumulator.state_root != proof.start_anchor.state_root
    {
        return Err(HistoryCheckpointProofError::StartAccumulatorMismatch);
    }
    if proof.end_accumulator.height != proof.end_anchor.height
        || proof.end_accumulator.state_root != proof.end_anchor.state_root
    {
        return Err(HistoryCheckpointProofError::EndAccumulatorMismatch);
    }
    let payload: HistoryCheckpointRecursivePayloadV1 = bincode::deserialize(&proof.recursive_proof)
        .map_err(|_| HistoryCheckpointProofError::DecodeRecursivePayload)?;
    if payload.version != HISTORY_CHECKPOINT_PROOF_VERSION {
        return Err(HistoryCheckpointProofError::UnsupportedVersion {
            actual: payload.version,
        });
    }
    if payload.engine_id != HISTORY_CHECKPOINT_ENGINE_STREAMING_TOWER_IVC_V1 {
        return Err(HistoryCheckpointProofError::UnsupportedEngine {
            actual: payload.engine_id,
        });
    }
    validate_head_shape(&payload.head)?;
    if payload.backend_proof.is_empty() {
        return Err(HistoryCheckpointProofError::EmptyBackendProof);
    }
    if payload.head.checkpoint_height != proof.checkpoint_height
        || payload.head.anchor_digest != history_checkpoint_anchor_digest(&proof.end_anchor)
        || payload.head.accumulator_digest
            != history_checkpoint_accumulator_digest(&proof.end_accumulator)
    {
        return Err(HistoryCheckpointProofError::RecursiveHeadMismatch);
    }

    Ok(())
}

fn validate_head_shape(head: &HistoryCheckpointHeadV1) -> Result<(), HistoryCheckpointProofError> {
    if head.version != HISTORY_CHECKPOINT_PROOF_VERSION {
        return Err(HistoryCheckpointProofError::UnsupportedVersion {
            actual: head.version,
        });
    }
    if head.engine_id != HISTORY_CHECKPOINT_ENGINE_STREAMING_TOWER_IVC_V1 {
        return Err(HistoryCheckpointProofError::UnsupportedEngine {
            actual: head.engine_id,
        });
    }
    Ok(())
}

fn validate_batch_summary_shape(
    summary: &HistoryCheckpointBatchSummaryV1,
) -> Result<(), HistoryCheckpointProofError> {
    if summary.version != HISTORY_CHECKPOINT_PROOF_VERSION {
        return Err(HistoryCheckpointProofError::UnsupportedVersion {
            actual: summary.version,
        });
    }
    if summary.batch_len == 0 || summary.batch_len > HISTORY_CHECKPOINT_BATCH_TARGET_BLOCKS {
        return Err(HistoryCheckpointProofError::BadBatchLength {
            actual: summary.batch_len,
        });
    }
    let expected_end_height = summary
        .start_anchor
        .height
        .checked_add(summary.batch_len as u64)
        .ok_or(HistoryCheckpointProofError::BatchHeightMismatch)?;
    if summary.end_anchor.height != expected_end_height {
        return Err(HistoryCheckpointProofError::BatchHeightMismatch);
    }
    validate_boundary(
        &summary.start_anchor,
        &summary.start_accumulator,
        &summary.start_consensus,
        true,
    )?;
    validate_boundary(
        &summary.end_anchor,
        &summary.end_accumulator,
        &summary.end_consensus,
        false,
    )?;
    Ok(())
}

fn validate_boundary(
    anchor: &HeaderChainAnchor,
    accumulator: &ChainAccumulator,
    consensus: &RecursiveConsensusState,
    start: bool,
) -> Result<(), HistoryCheckpointProofError> {
    if accumulator.height != anchor.height || accumulator.state_root != anchor.state_root {
        return if start {
            Err(HistoryCheckpointProofError::StartAccumulatorMismatch)
        } else {
            Err(HistoryCheckpointProofError::EndAccumulatorMismatch)
        };
    }
    if consensus.height != anchor.height
        || consensus.block_id != anchor.block_id
        || consensus.state_root != anchor.state_root
        || consensus.cumulative_chainwork != anchor.cumulative_chainwork
        || consensus.log_slots != anchor.log_slots
        || consensus.active_slot_count != anchor.active_slot_count
        || consensus.alloc_counter != anchor.alloc_counter
    {
        return if start {
            Err(HistoryCheckpointProofError::StartConsensusMismatch)
        } else {
            Err(HistoryCheckpointProofError::EndConsensusMismatch)
        };
    }
    Ok(())
}

fn history_checkpoint_boundary_digest(
    anchor: &HeaderChainAnchor,
    accumulator: &ChainAccumulator,
    consensus: &RecursiveConsensusState,
) -> Digest {
    let mut sponge = checkpoint_sponge(HCP_BND1);
    absorb_digest(&mut sponge, &history_checkpoint_anchor_digest(anchor));
    absorb_digest(
        &mut sponge,
        &history_checkpoint_accumulator_digest(accumulator),
    );
    absorb_digest(&mut sponge, &history_checkpoint_consensus_digest(consensus));
    sponge.finalize()
}

fn history_checkpoint_base_recursive_digest(boundary_digest: &Digest) -> Digest {
    let mut sponge = checkpoint_sponge(HCP_BASE1);
    absorb_digest(&mut sponge, boundary_digest);
    sponge.finalize()
}

fn history_checkpoint_fold_recursive_digest(
    previous_recursive_digest: &Digest,
    previous_head_digest: &Digest,
    batch_summary_digest: &Digest,
) -> Digest {
    let mut sponge = checkpoint_sponge(HCP_FOLD1);
    absorb_digest(&mut sponge, previous_recursive_digest);
    absorb_digest(&mut sponge, previous_head_digest);
    absorb_digest(&mut sponge, batch_summary_digest);
    sponge.finalize()
}

fn checkpoint_sponge(marker: u128) -> Poseidon2bSponge {
    let mut sponge = Poseidon2bSponge::with_iv(capacity_iv(TAG_HISTPRF));
    sponge.absorb(Block128::from(marker));
    sponge.absorb(Block128::from(HISTORY_CHECKPOINT_PROOF_VERSION as u128));
    sponge
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

fn absorb_accumulator(sponge: &mut Poseidon2bSponge, accumulator: &ChainAccumulator) {
    sponge.absorb(Block128::from(accumulator.height as u128));
    absorb_digest(sponge, &accumulator.state_root);
    absorb_digest(sponge, &accumulator.chain_hash);
}

fn absorb_consensus(sponge: &mut Poseidon2bSponge, consensus: &RecursiveConsensusState) {
    sponge.absorb(Block128::from(consensus.height as u128));
    absorb_digest(sponge, &consensus.block_id);
    absorb_digest(sponge, &consensus.state_root);
    absorb_digest(sponge, &consensus.cumulative_chainwork);
    sponge.absorb(Block128::from(consensus.log_slots as u128));
    sponge.absorb(Block128::from(consensus.active_slot_count as u128));
    sponge.absorb(Block128::from(consensus.alloc_counter as u128));
    sponge.absorb(Block128::from(consensus.asert_anchor_height as u128));
    sponge.absorb(Block128::from(consensus.asert_anchor_timestamp as u128));
    absorb_digest(sponge, &consensus.asert_anchor_target);
    sponge.absorb(Block128::from(consensus.mtp_len as u128));
    for timestamp in consensus.mtp_timestamps {
        sponge.absorb(Block128::from(timestamp as u128));
    }
    sponge.absorb(Block128::from(consensus.expansion_len as u128));
    for active_count in consensus.expansion_counts {
        sponge.absorb(Block128::from(active_count as u128));
    }
}

fn absorb_digest(sponge: &mut Poseidon2bSponge, digest: &Digest) {
    let [lo, hi] = digest_to_fields(digest);
    sponge.absorb_pair(lo, hi);
}

fn push_digest_hash_fields<const N: usize>(
    fields: &mut [Block128; N],
    index: &mut usize,
    digest: &Digest,
) {
    let [lo, hi] = digest_to_fields(digest);
    fields[*index] = lo;
    *index += 1;
    fields[*index] = hi;
    *index += 1;
}

fn digest_to_fields(digest: &Digest) -> [Block128; 2] {
    [
        Block128::from(u128::from_le_bytes(digest[..16].try_into().unwrap())),
        Block128::from(u128::from_le_bytes(digest[16..].try_into().unwrap())),
    ]
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

fn absorb_address(sponge: &mut Poseidon2bSponge, address: &Address) {
    absorb_digest(sponge, address.as_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pow_header::{HeaderWitness, EXPANSION_WINDOW_LEN};
    use noid_chain::consensus::difficulty::{add_work, block_work};
    use noid_chain::consensus::params::{BLOCK_TIME, MAX_TARGET, MEDIAN_TIME_BLOCKS};
    use noid_chain::header_anchor::HeaderChainAnchor;
    use noid_chain::BlockHeader;
    use noid_poseidon2b::primitives::Address;

    fn anchor(height: u64, state_root: [u8; 32], block_id: [u8; 32]) -> HeaderChainAnchor {
        HeaderChainAnchor {
            height,
            block_id,
            state_root,
            tx_root: [0x33; 32],
            miner_address: Address([0x55; 32]),
            log_slots: 8,
            active_slot_count: height,
            alloc_counter: height,
            projection_root: [height as u8; 32],
            cumulative_chainwork: [height as u8; 32],
        }
    }

    fn accumulator(height: u64, state_root: [u8; 32]) -> ChainAccumulator {
        ChainAccumulator {
            height,
            state_root,
            chain_hash: [0x44; 32],
        }
    }

    fn consensus(anchor: &HeaderChainAnchor) -> RecursiveConsensusState {
        let mut mtp_timestamps = [0u64; MEDIAN_TIME_BLOCKS];
        mtp_timestamps[0] = 1_767_225_600 + anchor.height;
        let mut expansion_counts = [0u64; EXPANSION_WINDOW_LEN];
        expansion_counts[0] = anchor.active_slot_count;
        RecursiveConsensusState {
            height: anchor.height,
            block_id: anchor.block_id,
            state_root: anchor.state_root,
            cumulative_chainwork: anchor.cumulative_chainwork,
            log_slots: anchor.log_slots,
            active_slot_count: anchor.active_slot_count,
            alloc_counter: anchor.alloc_counter,
            asert_anchor_height: 0,
            asert_anchor_timestamp: 1_767_225_600,
            asert_anchor_target: [0x7f; 32],
            mtp_timestamps,
            mtp_len: 1,
            expansion_counts,
            expansion_len: 1,
        }
    }

    fn proof() -> HistoryCheckpointProofV1 {
        let start_anchor = anchor(0, [0x11; 32], [0x01; 32]);
        let end_anchor = anchor(16, [0x22; 32], [0x02; 32]);
        let end_accumulator = accumulator(end_anchor.height, end_anchor.state_root);
        let end_consensus = consensus(&end_anchor);
        let head =
            history_checkpoint_head_from_boundary_v1(&end_anchor, &end_accumulator, &end_consensus)
                .expect("end boundary builds checkpoint head");
        let payload = HistoryCheckpointRecursivePayloadV1 {
            version: HISTORY_CHECKPOINT_PROOF_VERSION,
            engine_id: HISTORY_CHECKPOINT_ENGINE_STREAMING_TOWER_IVC_V1,
            head,
            backend_proof: vec![0xA5; 32],
        };
        HistoryCheckpointProofV1 {
            version: HISTORY_CHECKPOINT_PROOF_VERSION,
            engine_id: HISTORY_CHECKPOINT_ENGINE_STREAMING_TOWER_IVC_V1,
            checkpoint_height: end_anchor.height,
            start_accumulator: accumulator(start_anchor.height, start_anchor.state_root),
            end_accumulator,
            start_anchor,
            end_anchor,
            recursive_proof: encode_history_checkpoint_recursive_payload_v1(&payload),
        }
    }

    fn batch_summary() -> HistoryCheckpointBatchSummaryV1 {
        let proof = proof();
        HistoryCheckpointBatchSummaryV1 {
            version: HISTORY_CHECKPOINT_PROOF_VERSION,
            batch_len: HISTORY_CHECKPOINT_BATCH_TARGET_BLOCKS,
            start_consensus: consensus(&proof.start_anchor),
            end_consensus: consensus(&proof.end_anchor),
            start_accumulator: proof.start_accumulator,
            end_accumulator: proof.end_accumulator,
            start_anchor: proof.start_anchor,
            end_anchor: proof.end_anchor,
            accepted_claim_batch_digest: [0x88; 32],
        }
    }

    fn step_statement_pair() -> (
        HistoryCheckpointStepStatementV1,
        AcceptedBlockCertificateBatchStatementV1,
    ) {
        let summary = batch_summary();
        let previous = history_checkpoint_head_from_boundary_v1(
            &summary.start_anchor,
            &summary.start_accumulator,
            &summary.start_consensus,
        )
        .expect("start boundary builds a checkpoint head");
        let next = advance_history_checkpoint_head_v1_native(&previous, &summary)
            .expect("checkpoint batch advances");
        let statement = HistoryCheckpointStepStatementV1 {
            version: HISTORY_CHECKPOINT_PROOF_VERSION,
            previous_head: previous,
            batch_summary: summary.clone(),
            next_head: next,
        };
        let mut certificate_statement_digests =
            [[0u8; 32]; HISTORY_CHECKPOINT_BATCH_TARGET_BLOCKS as usize];
        for (index, digest) in certificate_statement_digests.iter_mut().enumerate() {
            digest[0] = index as u8;
            digest[1] = 0xC7;
        }
        let certificate_batch = AcceptedBlockCertificateBatchStatementV1 {
            version: HISTORY_CHECKPOINT_PROOF_VERSION,
            batch_len: summary.batch_len,
            accepted_claim_batch_digest: summary.accepted_claim_batch_digest,
            certificate_statement_digests,
        };
        (statement, certificate_batch)
    }

    fn step_statement_pair_with_accepted_claim_batch() -> (
        HistoryCheckpointStepStatementV1,
        AcceptedClaimBatchWitness,
        AcceptedClaimBatchOutput,
        Vec<AcceptedBlockCertificateStatementV1>,
    ) {
        let start_header = BlockHeader {
            prev_block_hash: [0u8; 32],
            state_root: [0x11; 32],
            tx_root: [0x10; 32],
            timestamp: 1_767_225_600,
            height: 0,
            miner_address: Address([0x55; 32]),
            nonce: 0,
            difficulty_target: MAX_TARGET,
            log_slots: 8,
            active_slot_count: 0,
            alloc_counter: 0,
        };
        let mut consensus = RecursiveConsensusState::from_header(
            &start_header,
            block_work(&start_header.difficulty_target),
            0,
            start_header.timestamp,
            start_header.difficulty_target,
            &[start_header.timestamp],
            &[start_header.active_slot_count],
        );
        let start_consensus = consensus.clone();
        let start_accumulator = ChainAccumulator {
            height: start_header.height,
            state_root: start_header.state_root,
            chain_hash: [0u8; 32],
        };
        let start_anchor = HeaderChainAnchor {
            height: start_consensus.height,
            block_id: start_consensus.block_id,
            state_root: start_consensus.state_root,
            tx_root: start_header.tx_root,
            miner_address: start_header.miner_address,
            log_slots: start_consensus.log_slots,
            active_slot_count: start_consensus.active_slot_count,
            alloc_counter: start_consensus.alloc_counter,
            projection_root: [0x70; 32],
            cumulative_chainwork: start_consensus.cumulative_chainwork,
        };

        let chunk_len = HISTORY_CHECKPOINT_BATCH_TARGET_BLOCKS as usize;
        let mut accumulator = start_accumulator.clone();
        let mut previous_block_id = start_consensus.block_id;
        let mut headers = Vec::with_capacity(chunk_len);
        let mut claims = Vec::with_capacity(chunk_len);
        let mut certificate_statements = Vec::with_capacity(chunk_len);
        for index in 0..chunk_len {
            let height = accumulator.height + 1;
            let header = BlockHeader {
                prev_block_hash: previous_block_id,
                state_root: [(index as u8).wrapping_add(2); 32],
                tx_root: [(index as u8).wrapping_add(0x20); 32],
                timestamp: 1_767_225_600 + height * BLOCK_TIME,
                height,
                miner_address: Address([0x55; 32]),
                nonce: height as u128,
                difficulty_target: MAX_TARGET,
                log_slots: 8,
                active_slot_count: height,
                alloc_counter: height,
            };
            let header_witness = HeaderWitness::from_header(&header);
            let accepted_block_claim_digest = [(index as u8).wrapping_add(0x80); 32];
            let claim = digest_to_fields(&accepted_block_claim_digest);
            let certificate = AcceptedBlockCertificateStatementV1 {
                version: 1,
                accept_block_predicate_version: 1,
                height,
                block_id: header_witness.block_id,
                parent_block_id: previous_block_id,
                parent_state_root: accumulator.state_root,
                child_state_root: header.state_root,
                tx_root: header.tx_root,
                block_body_digest: [0xA1; 32],
                block_proof_digest: [0xA2; 32],
                auth_sidecar_digest: [0xA3; 32],
                accepted_block_claim_digest,
                accepted_state_transition_claim_digest: [0xA4; 32],
                exact_transition_digest: [0xA5; 32],
                tx_count: 1,
                user_tx_count: 0,
                live_input_count: 0,
                live_output_count: 1,
                state_frontier_node_count: 0,
                touched_slot_count: 1,
                action_count: 1,
                block_body_len: 80,
                block_proof_len: 0,
                auth_sidecar_len: 0,
            };
            consensus.height = height;
            consensus.block_id = header_witness.block_id;
            consensus.state_root = header.state_root;
            consensus.cumulative_chainwork = add_work(
                &consensus.cumulative_chainwork,
                &block_work(&header.difficulty_target),
            );
            consensus.log_slots = header.log_slots;
            consensus.active_slot_count = header.active_slot_count;
            consensus.alloc_counter = header.alloc_counter;

            accumulator =
                accumulator.extend(header.state_root, header_witness.block_id, height, claim);
            previous_block_id = header_witness.block_id;
            headers.push(header_witness);
            claims.push(claim);
            certificate_statements.push(certificate);
        }

        let accepted_claim_witness = AcceptedClaimBatchWitness {
            headers,
            accepted_block_claims: claims,
        };
        let accepted_claim_output = AcceptedClaimBatchOutput {
            consensus_state: consensus.clone(),
            accumulator: accumulator.clone(),
        };
        let accepted_claim_batch_digest =
            accepted_claim_batch_digest_v1(&accepted_claim_witness, &accepted_claim_output)
                .expect("accepted-claim digest builds");
        let end_header = accepted_claim_witness
            .headers
            .last()
            .expect("chunk fixture has last header")
            .header
            .clone();
        let end_anchor = HeaderChainAnchor {
            height: consensus.height,
            block_id: consensus.block_id,
            state_root: consensus.state_root,
            tx_root: end_header.tx_root,
            miner_address: end_header.miner_address,
            log_slots: consensus.log_slots,
            active_slot_count: consensus.active_slot_count,
            alloc_counter: consensus.alloc_counter,
            projection_root: [0x71; 32],
            cumulative_chainwork: consensus.cumulative_chainwork,
        };
        let summary = HistoryCheckpointBatchSummaryV1 {
            version: HISTORY_CHECKPOINT_PROOF_VERSION,
            batch_len: HISTORY_CHECKPOINT_BATCH_TARGET_BLOCKS,
            start_anchor,
            end_anchor,
            start_accumulator,
            end_accumulator: accepted_claim_output.accumulator.clone(),
            start_consensus,
            end_consensus: accepted_claim_output.consensus_state.clone(),
            accepted_claim_batch_digest,
        };
        let previous = history_checkpoint_head_from_boundary_v1(
            &summary.start_anchor,
            &summary.start_accumulator,
            &summary.start_consensus,
        )
        .expect("start boundary builds a checkpoint head");
        let next = advance_history_checkpoint_head_v1_native(&previous, &summary)
            .expect("checkpoint batch advances");
        let statement = HistoryCheckpointStepStatementV1 {
            version: HISTORY_CHECKPOINT_PROOF_VERSION,
            previous_head: previous,
            batch_summary: summary.clone(),
            next_head: next,
        };
        (
            statement,
            accepted_claim_witness,
            accepted_claim_output,
            certificate_statements,
        )
    }

    fn step_proof(
        statement: &HistoryCheckpointStepStatementV1,
        certificate_batch: &AcceptedBlockCertificateBatchStatementV1,
    ) -> HistoryCheckpointStepProofV1 {
        prove_history_checkpoint_step_proof_v1_batch_digest_only(statement, certificate_batch)
            .expect("checkpoint step proof builds")
    }

    fn unchecked_step_proof(
        statement: &HistoryCheckpointStepStatementV1,
        certificate_batch: &AcceptedBlockCertificateBatchStatementV1,
    ) -> HistoryCheckpointStepProofV1 {
        HistoryCheckpointStepProofV1 {
            version: HISTORY_CHECKPOINT_PROOF_VERSION,
            step_statement_digest: history_checkpoint_step_statement_digest(statement),
            certificate_batch_statement_digest:
                accepted_block_certificate_batch_statement_digest_v1(certificate_batch),
            backend_proof: vec![0x42],
        }
    }

    #[test]
    fn checkpoint_proof_v1_roundtrips_and_has_nonzero_size() {
        let proof = proof();
        let encoded = bincode::serialize(&proof).expect("serialize proof");
        let decoded: HistoryCheckpointProofV1 =
            bincode::deserialize(&encoded).expect("deserialize proof");
        assert_eq!(decoded, proof);
        assert_eq!(proof.byte_len(), encoded.len());
    }

    #[test]
    fn checkpoint_proof_v1_placeholder_payload_path_verifies() {
        let proof = proof();
        verify_history_checkpoint_proof_v1_checkpoint(
            &proof,
            &proof.start_anchor,
            &proof.end_anchor,
        )
        .expect("checkpoint proof placeholder payload path verifies");
    }

    #[test]
    fn checkpoint_proof_v1_rejects_shape_mismatches_before_backend() {
        let proof = proof();

        let mut bad = proof.clone();
        bad.version += 1;
        assert!(matches!(
            verify_history_checkpoint_proof_v1_checkpoint(
                &bad,
                &proof.start_anchor,
                &proof.end_anchor
            ),
            Err(HistoryCheckpointProofError::UnsupportedVersion { .. })
        ));

        let mut bad = proof.clone();
        bad.engine_id += 1;
        assert!(matches!(
            verify_history_checkpoint_proof_v1_checkpoint(
                &bad,
                &proof.start_anchor,
                &proof.end_anchor
            ),
            Err(HistoryCheckpointProofError::UnsupportedEngine { .. })
        ));

        let mut bad = proof.clone();
        bad.recursive_proof.clear();
        assert_eq!(
            verify_history_checkpoint_proof_v1_checkpoint(
                &bad,
                &proof.start_anchor,
                &proof.end_anchor
            ),
            Err(HistoryCheckpointProofError::EmptyRecursiveProof)
        );

        let mut bad = proof.clone();
        bad.recursive_proof = vec![0x99; 7];
        assert_eq!(
            verify_history_checkpoint_proof_v1_checkpoint(
                &bad,
                &proof.start_anchor,
                &proof.end_anchor
            ),
            Err(HistoryCheckpointProofError::DecodeRecursivePayload)
        );

        let mut bad = proof.clone();
        bad.checkpoint_height += 1;
        assert_eq!(
            verify_history_checkpoint_proof_v1_checkpoint(
                &bad,
                &proof.start_anchor,
                &proof.end_anchor
            ),
            Err(HistoryCheckpointProofError::CheckpointHeightMismatch)
        );

        let mut bad = proof.clone();
        bad.end_accumulator.state_root = [0x33; 32];
        assert_eq!(
            verify_history_checkpoint_proof_v1_checkpoint(
                &bad,
                &proof.start_anchor,
                &proof.end_anchor
            ),
            Err(HistoryCheckpointProofError::EndAccumulatorMismatch)
        );

        let mut payload: HistoryCheckpointRecursivePayloadV1 =
            bincode::deserialize(&proof.recursive_proof).expect("payload decodes");
        payload.backend_proof.clear();
        let mut bad = proof.clone();
        bad.recursive_proof = encode_history_checkpoint_recursive_payload_v1(&payload);
        assert_eq!(
            verify_history_checkpoint_proof_v1_checkpoint(
                &bad,
                &proof.start_anchor,
                &proof.end_anchor
            ),
            Err(HistoryCheckpointProofError::EmptyBackendProof)
        );

        let mut payload: HistoryCheckpointRecursivePayloadV1 =
            bincode::deserialize(&proof.recursive_proof).expect("payload decodes");
        payload.head.anchor_digest = [0x77; 32];
        let mut bad = proof.clone();
        bad.recursive_proof = encode_history_checkpoint_recursive_payload_v1(&payload);
        assert_eq!(
            verify_history_checkpoint_proof_v1_checkpoint(
                &bad,
                &proof.start_anchor,
                &proof.end_anchor
            ),
            Err(HistoryCheckpointProofError::RecursiveHeadMismatch)
        );
    }

    #[test]
    fn checkpoint_head_and_batch_step_are_deterministic() {
        let summary = batch_summary();
        let previous = history_checkpoint_head_from_boundary_v1(
            &summary.start_anchor,
            &summary.start_accumulator,
            &summary.start_consensus,
        )
        .expect("start boundary builds a checkpoint head");
        let next = advance_history_checkpoint_head_v1_native(&previous, &summary)
            .expect("checkpoint batch advances");
        assert_eq!(next.checkpoint_height, summary.end_anchor.height);
        assert_eq!(next.batch_count, 1);
        assert_eq!(
            next.anchor_digest,
            history_checkpoint_anchor_digest(&summary.end_anchor)
        );
        assert_eq!(
            next.accumulator_digest,
            history_checkpoint_accumulator_digest(&summary.end_accumulator)
        );
        assert_eq!(
            next.consensus_digest,
            history_checkpoint_consensus_digest(&summary.end_consensus)
        );

        let statement = HistoryCheckpointStepStatementV1 {
            version: HISTORY_CHECKPOINT_PROOF_VERSION,
            previous_head: previous.clone(),
            batch_summary: summary.clone(),
            next_head: next.clone(),
        };
        verify_history_checkpoint_step_statement_v1_native(&statement)
            .expect("valid native checkpoint step statement");
        assert_eq!(
            statement.byte_len(),
            bincode::serialize(&statement)
                .expect("serialize statement")
                .len()
        );
        assert_ne!(
            history_checkpoint_head_digest(&previous),
            history_checkpoint_head_digest(&next)
        );
        assert_ne!(
            history_checkpoint_step_relation_digest(),
            history_checkpoint_step_statement_digest(&statement)
        );
        assert_eq!(
            history_checkpoint_step_statement_hash_fields(&statement).len(),
            HISTORY_CHECKPOINT_STEP_STATEMENT_HASH_FIELDS
        );
        let digest_proof =
            prove_history_checkpoint_step_digest_proof_v1(&statement).expect("digest proof builds");
        verify_history_checkpoint_step_digest_proof_v1(&statement, &digest_proof)
            .expect("digest proof verifies");

        let mut tampered = statement;
        tampered.next_head.recursive_digest = [0x66; 32];
        assert_eq!(
            verify_history_checkpoint_step_digest_proof_v1(&tampered, &digest_proof),
            Err(HistoryCheckpointStepProofError::BadStepStatementDigestProof)
        );
    }

    #[test]
    fn checkpoint_step_proof_placeholder_path_binds_certificate_batch() {
        let (statement, certificate_batch) = step_statement_pair();
        let proof = step_proof(&statement, &certificate_batch);
        verify_history_checkpoint_step_proof_v1_checkpoint(&statement, &certificate_batch, &proof)
            .expect("checkpoint step checkpoint scaffold path verifies");

        let mut bad = proof.clone();
        bad.step_statement_digest = [0xAA; 32];
        assert_eq!(
            verify_history_checkpoint_step_proof_v1_checkpoint(
                &statement,
                &certificate_batch,
                &bad
            ),
            Err(HistoryCheckpointStepProofError::StepStatementDigestMismatch)
        );

        let mut bad = proof.clone();
        bad.certificate_batch_statement_digest = [0xBB; 32];
        assert_eq!(
            verify_history_checkpoint_step_proof_v1_checkpoint(
                &statement,
                &certificate_batch,
                &bad
            ),
            Err(HistoryCheckpointStepProofError::CertificateBatchDigestMismatch)
        );

        let mut bad_certificate_batch = certificate_batch.clone();
        bad_certificate_batch.batch_len -= 1;
        let bad_proof = unchecked_step_proof(&statement, &bad_certificate_batch);
        assert_eq!(
            verify_history_checkpoint_step_proof_v1_checkpoint(
                &statement,
                &bad_certificate_batch,
                &bad_proof
            ),
            Err(
                HistoryCheckpointStepProofError::CertificateBatchLengthMismatch {
                    step: statement.batch_summary.batch_len,
                    certificates: bad_certificate_batch.batch_len,
                }
            )
        );

        let mut bad_certificate_batch = certificate_batch.clone();
        bad_certificate_batch.accepted_claim_batch_digest = [0xCC; 32];
        let bad_proof = unchecked_step_proof(&statement, &bad_certificate_batch);
        assert_eq!(
            verify_history_checkpoint_step_proof_v1_checkpoint(
                &statement,
                &bad_certificate_batch,
                &bad_proof
            ),
            Err(HistoryCheckpointStepProofError::CertificateBatchAcceptedClaimDigestMismatch)
        );

        let mut bad = proof.clone();
        bad.backend_proof.clear();
        assert_eq!(
            verify_history_checkpoint_step_proof_v1_checkpoint(
                &statement,
                &certificate_batch,
                &bad
            ),
            Err(HistoryCheckpointStepProofError::EmptyBackendProof)
        );

        let mut bad = proof;
        bad.backend_proof = vec![0x42];
        assert_eq!(
            verify_history_checkpoint_step_proof_v1_checkpoint(
                &statement,
                &certificate_batch,
                &bad
            ),
            Err(HistoryCheckpointStepProofError::DecodeBackendProof)
        );
    }

    #[test]
    fn checkpoint_step_component_backend_carries_accepted_claim_digest_proof() {
        let (statement, accepted_claim_witness, accepted_claim_output, certificate_statements) =
            step_statement_pair_with_accepted_claim_batch();
        let (proof, certificate_batch) =
            prove_history_checkpoint_step_proof_v1_from_certificate_statements(
                &statement,
                &certificate_statements,
                &accepted_claim_witness,
                &accepted_claim_output,
            )
            .expect("checkpoint step component proof builds");
        let mut bad_certificate_statements = certificate_statements.clone();
        bad_certificate_statements[0].accepted_block_claim_digest = [0x11; 32];
        assert!(matches!(
            prove_history_checkpoint_step_proof_v1_from_certificate_statements(
                &statement,
                &bad_certificate_statements,
                &accepted_claim_witness,
                &accepted_claim_output,
            ),
            Err(HistoryCheckpointStepProofError::BadCertificateBatchStatement(_))
        ));
        let direct_proof = prove_history_checkpoint_step_proof_v1_with_digest_components(
            &statement,
            &certificate_batch,
            &accepted_claim_witness,
            &accepted_claim_output,
        )
        .expect("direct checkpoint step component proof builds");
        let backend: HistoryCheckpointStepBackendProofV1 =
            bincode::deserialize(&proof.backend_proof).expect("checkpoint backend decodes");
        assert_eq!(backend.certificate_statements, certificate_statements);
        assert_eq!(
            backend.certificate_validity_proofs.len(),
            certificate_statements.len()
        );
        assert!(backend.checkpoint_ivc_chunk_core_proof.is_some());
        verify_history_checkpoint_step_proof_v1_private_components_native(
            &statement,
            &certificate_batch,
            &accepted_claim_witness,
            &accepted_claim_output,
            &proof,
        )
        .expect("private digest components verify");
        verify_history_checkpoint_step_proof_v1_checkpoint(&statement, &certificate_batch, &proof)
            .expect("checkpoint component backend verifies through checkpoint scaffold path");
        assert_eq!(
            direct_proof.certificate_batch_statement_digest,
            proof.certificate_batch_statement_digest
        );
        let mut bad_backend = backend.clone();
        let mut tampered_certificate_backend: crate::block_certificate::AcceptedBlockCertificateBackendProofV1 =
            bincode::deserialize(&bad_backend.certificate_validity_proofs[0].backend_proof)
                .expect("certificate backend decodes");
        tampered_certificate_backend.statement_digest_hash.n_claims += 1;
        bad_backend.certificate_validity_proofs[0].backend_proof =
            bincode::serialize(&tampered_certificate_backend)
                .expect("tampered certificate backend serializes");
        let mut bad = proof.clone();
        bad.backend_proof =
            bincode::serialize(&bad_backend).expect("tampered checkpoint backend serializes");
        assert_eq!(
            verify_history_checkpoint_step_proof_v1_checkpoint(
                &statement,
                &certificate_batch,
                &bad
            ),
            Err(
                HistoryCheckpointStepProofError::CertificateValidityProofHandleMismatch {
                    index: 0
                }
            )
        );

        let digest_only = step_proof(&statement, &certificate_batch);
        assert_eq!(
            verify_history_checkpoint_step_proof_v1_private_components_native(
                &statement,
                &certificate_batch,
                &accepted_claim_witness,
                &accepted_claim_output,
                &digest_only,
            ),
            Err(HistoryCheckpointStepProofError::MissingAcceptedClaimBatchDigestProof)
        );

        let mut tampered_output = accepted_claim_output;
        tampered_output.accumulator.chain_hash = [0x5A; 32];
        assert_eq!(
            verify_history_checkpoint_step_proof_v1_private_components_native(
                &statement,
                &certificate_batch,
                &accepted_claim_witness,
                &tampered_output,
                &proof,
            ),
            Err(HistoryCheckpointStepProofError::AcceptedClaimBatchOutputMismatch)
        );
    }

    #[test]
    fn checkpoint_step_rejects_bad_shape_before_backend() {
        let summary = batch_summary();
        let previous = history_checkpoint_head_from_boundary_v1(
            &summary.start_anchor,
            &summary.start_accumulator,
            &summary.start_consensus,
        )
        .expect("start boundary builds a checkpoint head");

        let mut bad_summary = summary.clone();
        bad_summary.batch_len = 0;
        assert_eq!(
            advance_history_checkpoint_head_v1_native(&previous, &bad_summary),
            Err(HistoryCheckpointProofError::BadBatchLength { actual: 0 })
        );

        let mut bad_summary = summary.clone();
        bad_summary.batch_len = HISTORY_CHECKPOINT_BATCH_TARGET_BLOCKS + 1;
        assert_eq!(
            advance_history_checkpoint_head_v1_native(&previous, &bad_summary),
            Err(HistoryCheckpointProofError::BadBatchLength {
                actual: HISTORY_CHECKPOINT_BATCH_TARGET_BLOCKS + 1,
            })
        );

        let mut bad_summary = summary.clone();
        bad_summary.end_accumulator.state_root = [0x99; 32];
        assert_eq!(
            advance_history_checkpoint_head_v1_native(&previous, &bad_summary),
            Err(HistoryCheckpointProofError::EndAccumulatorMismatch)
        );

        let wrong_previous = history_checkpoint_head_from_boundary_v1(
            &summary.end_anchor,
            &summary.end_accumulator,
            &summary.end_consensus,
        )
        .expect("end boundary builds a checkpoint head");
        assert_eq!(
            advance_history_checkpoint_head_v1_native(&wrong_previous, &summary),
            Err(HistoryCheckpointProofError::BatchStartMismatch)
        );

        let next = advance_history_checkpoint_head_v1_native(&previous, &summary)
            .expect("checkpoint batch advances");
        let mut bad_statement = HistoryCheckpointStepStatementV1 {
            version: HISTORY_CHECKPOINT_PROOF_VERSION,
            previous_head: previous,
            batch_summary: summary,
            next_head: next,
        };
        bad_statement.next_head.recursive_digest = [0x77; 32];
        assert_eq!(
            verify_history_checkpoint_step_statement_v1_native(&bad_statement),
            Err(HistoryCheckpointProofError::StepHeadMismatch)
        );
    }
}
