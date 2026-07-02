// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Final public O(1) checkpoint proof envelope.
//!
//! This module fixes the network-facing proof shape and wires the checkpoint
//! data path through a recursive head proof and a strict checkpoint step
//! backend. Header consensus remains native and outside this aggregation layer.

use noid_chain::header_anchor::HeaderChainAnchor;
use noid_core::{Block128, TowerField};
use noid_gkr::{
    discharge_fixed_field_hash_reductions_native, prove_fixed_field_hash_killshot,
    verify_fixed_field_hash_killshot, FixedFieldHashInputs, FixedFieldHashParams,
    FixedFieldHashProofKillShot,
};
use noid_poseidon2b::channel::Poseidon2bChannel;
use noid_poseidon2b::native::domain::{capacity_iv, TAG_HISTPRF};
use noid_poseidon2b::native::poseidon2b_hash_byte_slices;
use noid_poseidon2b::native::Poseidon2bSponge;
use noid_poseidon2b::primitives::{Address, Digest};
use rayon::prelude::*;

use crate::accepted_batch::{
    accepted_claim_batch_digest, prove_accepted_claim_batch_digest,
    verify_accepted_claim_batch_digest, verify_accepted_claim_batch_digest_hash_fields,
    AcceptedClaimBatchDigestError, AcceptedClaimBatchDigestProof, AcceptedClaimBatchOutput,
    AcceptedClaimBatchWitness,
};
use crate::accumulator::ChainAccumulator;
use crate::block_certificate::{
    accepted_block_certificate_batch_statement, accepted_block_certificate_batch_statement_digest,
    accepted_block_certificate_receipt, accepted_block_certificate_statement_digest,
    accepted_block_certificate_validity_handle,
    prove_accepted_block_certificate_batch_digest_proof,
    verify_accepted_block_certificate_batch_digest_proof,
    verify_accepted_block_certificate_proof_checkpoint,
    verify_accepted_block_certificate_receipt_projection, AcceptedBlockCertificateBatchDigestProof,
    AcceptedBlockCertificateBatchError, AcceptedBlockCertificateBatchStatement,
    AcceptedBlockCertificateProof, AcceptedBlockCertificateProofError,
    AcceptedBlockCertificateReceipt, AcceptedBlockCertificateReceiptError,
    AcceptedBlockCertificateStatement, AcceptedBlockCertificateValidityHandle,
    AcceptedBlockCertificateValidityHandleError,
};

use crate::block_certificate_ivc::prove_accepted_block_certificate_proof_ivc_receipt;
use crate::checkpoint_ivc_backend::{
    prove_history_checkpoint_ivc_chunk_receipt_handle_core,
    verify_history_checkpoint_ivc_chunk_core, HistoryCheckpointIvcChunkCoreError,
    HistoryCheckpointIvcChunkCoreProof,
};
use crate::pow_header::RecursiveConsensusState;

pub const HISTORY_CHECKPOINT_ENGINE_STREAMING_TOWER_IVC: u32 = 1;
pub const HISTORY_CHECKPOINT_BATCH_TARGET_BLOCKS: u32 = 16;
pub const HISTORY_CHECKPOINT_RETAINED_WINDOW_BLOCKS: u32 = 18;
pub const HISTORY_CHECKPOINT_STEP_STATEMENT_HASH_FIELDS: usize = 10;

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
const HCP_PUBLIC_PROOF_DOMAIN: &[u8] = b"NOID:HCP:PUBLIC_PROOF";

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HistoryCheckpointHead {
    pub engine_id: u32,
    pub checkpoint_height: u64,
    pub batch_count: u64,
    pub anchor_digest: Digest,
    pub accumulator_digest: Digest,
    pub consensus_digest: Digest,
    pub recursive_digest: Digest,
}

impl HistoryCheckpointHead {
    pub fn byte_len(&self) -> usize {
        bincode::serialized_size(self).expect("serialized HistoryCheckpointHead length fits usize")
            as usize
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HistoryCheckpointBatchSummary {
    pub batch_len: u32,
    pub start_anchor: HeaderChainAnchor,
    pub end_anchor: HeaderChainAnchor,
    pub start_accumulator: ChainAccumulator,
    pub end_accumulator: ChainAccumulator,
    pub start_consensus: RecursiveConsensusState,
    pub end_consensus: RecursiveConsensusState,
    pub accepted_claim_batch_digest: Digest,
}

impl HistoryCheckpointBatchSummary {
    pub fn byte_len(&self) -> usize {
        bincode::serialized_size(self)
            .expect("serialized HistoryCheckpointBatchSummary length fits usize") as usize
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HistoryCheckpointStepStatement {
    pub previous_head: HistoryCheckpointHead,
    pub batch_summary: HistoryCheckpointBatchSummary,
    pub next_head: HistoryCheckpointHead,
}

impl HistoryCheckpointStepStatement {
    pub fn byte_len(&self) -> usize {
        bincode::serialized_size(self)
            .expect("serialized HistoryCheckpointStepStatement length fits usize") as usize
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HistoryCheckpointStepProof {
    pub step_statement_digest: Digest,
    pub certificate_batch_statement_digest: Digest,
    pub backend_proof: Vec<u8>,
}

impl HistoryCheckpointStepProof {
    pub fn byte_len(&self) -> usize {
        bincode::serialized_size(self)
            .expect("serialized HistoryCheckpointStepProof length fits usize") as usize
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HistoryCheckpointStepDigestProof {
    pub step_statement_digest_hash: FixedFieldHashProofKillShot,
}

impl HistoryCheckpointStepDigestProof {
    pub fn byte_len(&self) -> usize {
        bincode::serialized_size(self)
            .expect("serialized HistoryCheckpointStepDigestProof length fits usize")
            as usize
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HistoryCheckpointStepBackendProof {
    pub step_statement_digest_proof: HistoryCheckpointStepDigestProof,
    pub certificate_batch_digest_proof: AcceptedBlockCertificateBatchDigestProof,
    pub certificate_statements: Vec<AcceptedBlockCertificateStatement>,
    pub certificate_validity_proofs: Vec<AcceptedBlockCertificateProof>,
    pub accepted_claim_batch_digest_proof: Option<AcceptedClaimBatchDigestProof>,
    pub checkpoint_ivc_chunk_core_proof: Option<HistoryCheckpointIvcChunkCoreProof>,
}

impl HistoryCheckpointStepBackendProof {
    pub fn byte_len(&self) -> usize {
        bincode::serialized_size(self)
            .expect("serialized HistoryCheckpointStepBackendProof length fits usize")
            as usize
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HistoryCheckpointRecursivePayload {
    pub engine_id: u32,
    pub head: HistoryCheckpointHead,
    pub backend_proof: Vec<u8>,
}

impl HistoryCheckpointRecursivePayload {
    pub fn byte_len(&self) -> usize {
        bincode::serialized_size(self)
            .expect("serialized HistoryCheckpointRecursivePayload length fits usize")
            as usize
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HistoryCheckpointRecursiveHeadProof {
    pub engine_id: u32,
    pub head: HistoryCheckpointHead,
    pub previous_head: Option<HistoryCheckpointHead>,
    pub previous_proof_digest: Option<Digest>,
    pub step_statement: HistoryCheckpointStepStatement,
    pub certificate_batch_statement: AcceptedBlockCertificateBatchStatement,
    pub step_proof: HistoryCheckpointStepProof,
}

impl HistoryCheckpointRecursiveHeadProof {
    pub fn byte_len(&self) -> usize {
        bincode::serialized_size(self)
            .expect("serialized HistoryCheckpointRecursiveHeadProof length fits usize")
            as usize
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StoredHistoryCheckpointHeadRecord {
    pub height: u64,
    pub head: HistoryCheckpointHead,
    pub proof_digest: Digest,
    pub proof_bytes: Vec<u8>,
    pub previous_height: Option<u64>,
    pub package_end_height: u64,
}

impl StoredHistoryCheckpointHeadRecord {
    pub fn byte_len(&self) -> usize {
        bincode::serialized_size(self)
            .expect("serialized StoredHistoryCheckpointHeadRecord length fits usize")
            as usize
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HistoryCheckpointProof {
    pub engine_id: u32,
    pub checkpoint_height: u64,
    pub start_anchor: HeaderChainAnchor,
    pub end_anchor: HeaderChainAnchor,
    pub start_accumulator: ChainAccumulator,
    pub end_accumulator: ChainAccumulator,
    pub recursive_proof: Vec<u8>,
}

impl HistoryCheckpointProof {
    pub fn byte_len(&self) -> usize {
        bincode::serialized_size(self).expect("serialized HistoryCheckpointProof length fits usize")
            as usize
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HistoryCheckpointProofError {
    UnsupportedEngine { actual: u32 },
    EmptyRecursiveProof,
    EmptyBackendProof,
    DecodeRecursivePayload,
    DecodeRecursiveHeadProof,
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
    RecursivePreviousHeadMismatch,
    RecursivePreviousProofDigestMismatch,
    BadCheckpointStepProof(Box<HistoryCheckpointStepProofError>),
}

impl std::fmt::Display for HistoryCheckpointProofError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedEngine { actual } => {
                write!(f, "unsupported history checkpoint proof engine {actual}")
            }
            Self::EmptyRecursiveProof => write!(f, "empty recursive checkpoint proof"),
            Self::EmptyBackendProof => write!(f, "empty recursive checkpoint backend proof"),
            Self::DecodeRecursivePayload => write!(f, "bad recursive checkpoint payload"),
            Self::DecodeRecursiveHeadProof => {
                write!(f, "bad recursive checkpoint head proof")
            }
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
            Self::RecursivePreviousHeadMismatch => {
                write!(f, "recursive checkpoint previous head mismatch")
            }
            Self::RecursivePreviousProofDigestMismatch => {
                write!(f, "recursive checkpoint previous proof digest mismatch")
            }
            Self::BadCheckpointStepProof(source) => {
                write!(f, "bad recursive checkpoint step proof: {source}")
            }
        }
    }
}

impl std::error::Error for HistoryCheckpointProofError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::BadCheckpointStepProof(source) => Some(source.as_ref()),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HistoryCheckpointStepProofError {
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
    MissingCheckpointIvcChunkCoreProof,
    BadAcceptedClaimBatchDigestProof(AcceptedClaimBatchDigestError),
    BadCheckpointIvcChunkCore(HistoryCheckpointIvcChunkCoreError),
}

impl std::fmt::Display for HistoryCheckpointStepProofError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
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
            Self::MissingCheckpointIvcChunkCoreProof => {
                write!(f, "missing checkpoint IVC chunk core proof")
            }
            Self::BadAcceptedClaimBatchDigestProof(source) => {
                write!(f, "bad checkpoint accepted-claim batch digest proof: {source}")
            }
            Self::BadCheckpointIvcChunkCore(source) => {
                write!(f, "bad checkpoint IVC chunk-core proof: {source}")
            }
        }
    }
}

impl std::error::Error for HistoryCheckpointStepProofError {}

pub fn history_checkpoint_head_from_boundary(
    anchor: &HeaderChainAnchor,
    accumulator: &ChainAccumulator,
    consensus: &RecursiveConsensusState,
) -> Result<HistoryCheckpointHead, HistoryCheckpointProofError> {
    validate_boundary(anchor, accumulator, consensus, true)?;
    let boundary_digest = history_checkpoint_boundary_digest(anchor, accumulator, consensus);
    Ok(HistoryCheckpointHead {
        engine_id: HISTORY_CHECKPOINT_ENGINE_STREAMING_TOWER_IVC,
        checkpoint_height: anchor.height,
        batch_count: 0,
        anchor_digest: history_checkpoint_anchor_digest(anchor),
        accumulator_digest: history_checkpoint_accumulator_digest(accumulator),
        consensus_digest: history_checkpoint_consensus_digest(consensus),
        recursive_digest: history_checkpoint_base_recursive_digest(&boundary_digest),
    })
}

pub fn advance_history_checkpoint_head_native(
    previous_head: &HistoryCheckpointHead,
    batch_summary: &HistoryCheckpointBatchSummary,
) -> Result<HistoryCheckpointHead, HistoryCheckpointProofError> {
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
    Ok(HistoryCheckpointHead {
        engine_id: HISTORY_CHECKPOINT_ENGINE_STREAMING_TOWER_IVC,
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

pub fn verify_history_checkpoint_step_statement_native(
    statement: &HistoryCheckpointStepStatement,
) -> Result<(), HistoryCheckpointProofError> {
    let expected =
        advance_history_checkpoint_head_native(&statement.previous_head, &statement.batch_summary)?;
    if statement.next_head != expected {
        return Err(HistoryCheckpointProofError::StepHeadMismatch);
    }
    Ok(())
}

pub fn verify_history_checkpoint_step_proof_checkpoint(
    statement: &HistoryCheckpointStepStatement,
    certificate_batch_statement: &AcceptedBlockCertificateBatchStatement,
    proof: &HistoryCheckpointStepProof,
) -> Result<(), HistoryCheckpointStepProofError> {
    let backend = verify_history_checkpoint_step_public_digest_components(
        statement,
        certificate_batch_statement,
        proof,
    )?;

    verify_history_checkpoint_step_final_backend_gate(certificate_batch_statement, &backend)
}

fn verify_history_checkpoint_step_final_backend_gate(
    certificate_batch_statement: &AcceptedBlockCertificateBatchStatement,
    backend: &HistoryCheckpointStepBackendProof,
) -> Result<(), HistoryCheckpointStepProofError> {
    verify_checkpoint_step_certificate_validity_backend(certificate_batch_statement, backend)
}

pub fn verify_history_checkpoint_step_proof_private_components_native(
    statement: &HistoryCheckpointStepStatement,
    certificate_batch_statement: &AcceptedBlockCertificateBatchStatement,
    accepted_claim_witness: &AcceptedClaimBatchWitness,
    accepted_claim_output: &AcceptedClaimBatchOutput,
    proof: &HistoryCheckpointStepProof,
) -> Result<(), HistoryCheckpointStepProofError> {
    let backend = verify_history_checkpoint_step_public_digest_components(
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
    verify_accepted_claim_batch_digest(
        accepted_claim_witness,
        accepted_claim_output,
        accepted_claim_batch_digest_proof,
    )
    .map_err(HistoryCheckpointStepProofError::BadAcceptedClaimBatchDigestProof)
}

fn verify_history_checkpoint_step_public_digest_components(
    statement: &HistoryCheckpointStepStatement,
    certificate_batch_statement: &AcceptedBlockCertificateBatchStatement,
    proof: &HistoryCheckpointStepProof,
) -> Result<HistoryCheckpointStepBackendProof, HistoryCheckpointStepProofError> {
    verify_history_checkpoint_step_statement_native(statement)
        .map_err(HistoryCheckpointStepProofError::BadCheckpointStep)?;

    let expected_step_digest = history_checkpoint_step_statement_digest(statement);
    if proof.step_statement_digest != expected_step_digest {
        return Err(HistoryCheckpointStepProofError::StepStatementDigestMismatch);
    }

    let expected_certificate_digest =
        accepted_block_certificate_batch_statement_digest(certificate_batch_statement);
    if proof.certificate_batch_statement_digest != expected_certificate_digest {
        return Err(HistoryCheckpointStepProofError::CertificateBatchDigestMismatch);
    }
    validate_checkpoint_step_certificate_batch_binding(statement, certificate_batch_statement)?;
    if proof.backend_proof.is_empty() {
        return Err(HistoryCheckpointStepProofError::EmptyBackendProof);
    }
    let backend: HistoryCheckpointStepBackendProof = bincode::deserialize(&proof.backend_proof)
        .map_err(|_| HistoryCheckpointStepProofError::DecodeBackendProof)?;
    verify_accepted_block_certificate_batch_digest_proof(
        certificate_batch_statement,
        &backend.certificate_batch_digest_proof,
    )
    .map_err(HistoryCheckpointStepProofError::BadCertificateBatchDigestProof)?;
    verify_history_checkpoint_step_digest_proof(statement, &backend.step_statement_digest_proof)?;
    if let Some(checkpoint_ivc_chunk_core_proof) = &backend.checkpoint_ivc_chunk_core_proof {
        verify_history_checkpoint_ivc_chunk_core(
            statement,
            certificate_batch_statement,
            checkpoint_ivc_chunk_core_proof,
        )
        .map_err(HistoryCheckpointStepProofError::BadCheckpointIvcChunkCore)?;
        let accepted_claim_batch_digest_proof = backend
            .accepted_claim_batch_digest_proof
            .as_ref()
            .ok_or(HistoryCheckpointStepProofError::MissingAcceptedClaimBatchDigestProof)?;
        verify_accepted_claim_batch_digest_hash_fields(
            &checkpoint_ivc_chunk_core_proof.accepted_claim_digest_hash_fields,
            statement.batch_summary.accepted_claim_batch_digest,
            accepted_claim_batch_digest_proof,
        )
        .map_err(HistoryCheckpointStepProofError::BadAcceptedClaimBatchDigestProof)?;
    }
    validate_checkpoint_step_certificate_validity_sidecars(
        certificate_batch_statement,
        &backend,
        backend.checkpoint_ivc_chunk_core_proof.as_ref(),
    )?;

    Ok(backend)
}

fn validate_checkpoint_step_certificate_validity_sidecars(
    certificate_batch_statement: &AcceptedBlockCertificateBatchStatement,
    backend: &HistoryCheckpointStepBackendProof,
    checkpoint_ivc_chunk_core_proof: Option<&HistoryCheckpointIvcChunkCoreProof>,
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
        let statement_digest = accepted_block_certificate_statement_digest(statement);
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
            let handle = accepted_block_certificate_validity_handle(proof)
                .map_err(HistoryCheckpointStepProofError::BadCertificateValidityHandle)?;
            if handle != chunk_core.certificate_validity_handles[index] {
                return Err(
                    HistoryCheckpointStepProofError::CertificateValidityProofHandleMismatch {
                        index,
                    },
                );
            }
            verify_accepted_block_certificate_receipt_projection(
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

fn verify_checkpoint_step_certificate_validity_backend(
    certificate_batch_statement: &AcceptedBlockCertificateBatchStatement,
    backend: &HistoryCheckpointStepBackendProof,
) -> Result<(), HistoryCheckpointStepProofError> {
    let certificate_len = certificate_batch_statement.batch_len as usize;
    let checkpoint_ivc_chunk_core_proof = backend
        .checkpoint_ivc_chunk_core_proof
        .as_ref()
        .ok_or(HistoryCheckpointStepProofError::MissingCheckpointIvcChunkCoreProof)?;
    backend
        .accepted_claim_batch_digest_proof
        .as_ref()
        .ok_or(HistoryCheckpointStepProofError::MissingAcceptedClaimBatchDigestProof)?;
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
    if checkpoint_ivc_chunk_core_proof.certificate_receipts.len() != certificate_len {
        return Err(
            HistoryCheckpointStepProofError::CertificateValidityProofLengthMismatch {
                certificates: certificate_len,
                proofs: backend.certificate_validity_proofs.len(),
                receipts: checkpoint_ivc_chunk_core_proof.certificate_receipts.len(),
            },
        );
    }

    for (index, (statement, proof)) in backend
        .certificate_statements
        .iter()
        .zip(backend.certificate_validity_proofs.iter())
        .enumerate()
    {
        match verify_accepted_block_certificate_proof_checkpoint(statement, proof) {
            Ok(()) => {}
            Err(source) => {
                return Err(
                    HistoryCheckpointStepProofError::BadCertificateValidityHandleProof(source),
                );
            }
        }
        verify_accepted_block_certificate_receipt_projection(
            statement,
            &checkpoint_ivc_chunk_core_proof.certificate_receipts[index],
        )
        .map_err(|source| {
            HistoryCheckpointStepProofError::CertificateReceiptProjection { index, source }
        })?;
        let handle = accepted_block_certificate_validity_handle(proof)
            .map_err(HistoryCheckpointStepProofError::BadCertificateValidityHandle)?;
        if handle != checkpoint_ivc_chunk_core_proof.certificate_validity_handles[index] {
            return Err(
                HistoryCheckpointStepProofError::CertificateValidityProofHandleMismatch { index },
            );
        }
    }

    Ok(())
}

#[cfg(test)]
fn prove_history_checkpoint_step_digest_boundary_for_tests(
    statement: &HistoryCheckpointStepStatement,
    certificate_batch_statement: &AcceptedBlockCertificateBatchStatement,
) -> Result<HistoryCheckpointStepProof, HistoryCheckpointStepProofError> {
    verify_history_checkpoint_step_statement_native(statement)
        .map_err(HistoryCheckpointStepProofError::BadCheckpointStep)?;
    validate_checkpoint_step_certificate_batch_binding(statement, certificate_batch_statement)?;
    let (step_statement_digest_proof, certificate_batch_digest_proof) = rayon::join(
        || prove_history_checkpoint_step_digest_proof(statement),
        || {
            prove_accepted_block_certificate_batch_digest_proof(certificate_batch_statement)
                .map_err(HistoryCheckpointStepProofError::BadCertificateBatchDigestProof)
        },
    );
    let backend = HistoryCheckpointStepBackendProof {
        step_statement_digest_proof: step_statement_digest_proof?,
        certificate_batch_digest_proof: certificate_batch_digest_proof?,
        certificate_statements: Vec::new(),
        certificate_validity_proofs: Vec::new(),
        accepted_claim_batch_digest_proof: None,
        checkpoint_ivc_chunk_core_proof: None,
    };
    Ok(HistoryCheckpointStepProof {
        step_statement_digest: history_checkpoint_step_statement_digest(statement),
        certificate_batch_statement_digest: accepted_block_certificate_batch_statement_digest(
            certificate_batch_statement,
        ),
        backend_proof: bincode::serialize(&backend)
            .expect("HistoryCheckpointStepBackendProof serializes"),
    })
}

pub fn prove_history_checkpoint_step_proof_with_digest_components(
    statement: &HistoryCheckpointStepStatement,
    certificate_batch_statement: &AcceptedBlockCertificateBatchStatement,
    accepted_claim_witness: &AcceptedClaimBatchWitness,
    accepted_claim_output: &AcceptedClaimBatchOutput,
) -> Result<HistoryCheckpointStepProof, HistoryCheckpointStepProofError> {
    verify_history_checkpoint_step_statement_native(statement)
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
                    || prove_history_checkpoint_step_digest_proof(statement),
                    || {
                        prove_accepted_block_certificate_batch_digest_proof(
                            certificate_batch_statement,
                        )
                        .map_err(HistoryCheckpointStepProofError::BadCertificateBatchDigestProof)
                    },
                )
            },
            || {
                prove_accepted_claim_batch_digest(accepted_claim_witness, accepted_claim_output)
                    .map_err(HistoryCheckpointStepProofError::BadAcceptedClaimBatchDigestProof)
            },
        );
    let backend = HistoryCheckpointStepBackendProof {
        step_statement_digest_proof: step_statement_digest_proof?,
        certificate_batch_digest_proof: certificate_batch_digest_proof?,
        certificate_statements: Vec::new(),
        certificate_validity_proofs: Vec::new(),
        accepted_claim_batch_digest_proof: Some(accepted_claim_proof?),
        checkpoint_ivc_chunk_core_proof: None,
    };
    Ok(HistoryCheckpointStepProof {
        step_statement_digest: history_checkpoint_step_statement_digest(statement),
        certificate_batch_statement_digest: accepted_block_certificate_batch_statement_digest(
            certificate_batch_statement,
        ),
        backend_proof: bincode::serialize(&backend)
            .expect("HistoryCheckpointStepBackendProof serializes"),
    })
}

pub fn prove_history_checkpoint_step_proof_with_ivc_chunk_core_components(
    statement: &HistoryCheckpointStepStatement,
    certificate_batch_statement: &AcceptedBlockCertificateBatchStatement,
    certificate_statements: &[AcceptedBlockCertificateStatement],
    accepted_claim_witness: &AcceptedClaimBatchWitness,
    accepted_claim_output: &AcceptedClaimBatchOutput,
) -> Result<HistoryCheckpointStepProof, HistoryCheckpointStepProofError> {
    let certificate_receipts = certificate_statements
        .iter()
        .map(accepted_block_certificate_receipt)
        .collect::<Vec<_>>();
    let certificate_validity_proofs =
        certificate_validity_proofs_from_statements(certificate_statements)?;
    prove_history_checkpoint_step_proof_with_ivc_chunk_certificate_proof_components(
        statement,
        certificate_batch_statement,
        certificate_statements,
        &certificate_validity_proofs,
        &certificate_receipts,
        accepted_claim_witness,
        accepted_claim_output,
    )
}

pub fn prove_history_checkpoint_step_proof_with_ivc_chunk_certificate_proof_components(
    statement: &HistoryCheckpointStepStatement,
    certificate_batch_statement: &AcceptedBlockCertificateBatchStatement,
    certificate_statements: &[AcceptedBlockCertificateStatement],
    certificate_validity_proofs: &[AcceptedBlockCertificateProof],
    certificate_receipts: &[AcceptedBlockCertificateReceipt],
    accepted_claim_witness: &AcceptedClaimBatchWitness,
    accepted_claim_output: &AcceptedClaimBatchOutput,
) -> Result<HistoryCheckpointStepProof, HistoryCheckpointStepProofError> {
    let certificate_validity_handles = certificate_validity_handles_from_proofs(
        certificate_batch_statement,
        certificate_validity_proofs,
        certificate_receipts,
    )?;
    prove_history_checkpoint_step_proof_with_ivc_chunk_receipt_handle_components_inner(
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

pub fn prove_history_checkpoint_step_proof_with_ivc_chunk_receipt_handle_components(
    statement: &HistoryCheckpointStepStatement,
    certificate_batch_statement: &AcceptedBlockCertificateBatchStatement,
    certificate_validity_handles: &[AcceptedBlockCertificateValidityHandle],
    certificate_receipts: &[AcceptedBlockCertificateReceipt],
    accepted_claim_witness: &AcceptedClaimBatchWitness,
    accepted_claim_output: &AcceptedClaimBatchOutput,
) -> Result<HistoryCheckpointStepProof, HistoryCheckpointStepProofError> {
    prove_history_checkpoint_step_proof_with_ivc_chunk_receipt_handle_components_inner(
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
fn prove_history_checkpoint_step_proof_with_ivc_chunk_receipt_handle_components_inner(
    statement: &HistoryCheckpointStepStatement,
    certificate_batch_statement: &AcceptedBlockCertificateBatchStatement,
    certificate_statements: &[AcceptedBlockCertificateStatement],
    certificate_validity_proofs: &[AcceptedBlockCertificateProof],
    certificate_validity_handles: &[AcceptedBlockCertificateValidityHandle],
    certificate_receipts: &[AcceptedBlockCertificateReceipt],
    accepted_claim_witness: &AcceptedClaimBatchWitness,
    accepted_claim_output: &AcceptedClaimBatchOutput,
) -> Result<HistoryCheckpointStepProof, HistoryCheckpointStepProofError> {
    verify_history_checkpoint_step_statement_native(statement)
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
                    || prove_history_checkpoint_step_digest_proof(statement),
                    || {
                        prove_accepted_block_certificate_batch_digest_proof(
                            certificate_batch_statement,
                        )
                        .map_err(HistoryCheckpointStepProofError::BadCertificateBatchDigestProof)
                    },
                )
            },
            || {
                prove_accepted_claim_batch_digest(accepted_claim_witness, accepted_claim_output)
                    .map_err(HistoryCheckpointStepProofError::BadAcceptedClaimBatchDigestProof)
            },
        )
    };
    let prove_chunk_core = || {
        prove_history_checkpoint_ivc_chunk_receipt_handle_core(
            statement,
            certificate_batch_statement,
            certificate_validity_handles,
            certificate_receipts,
            accepted_claim_witness,
            accepted_claim_output,
        )
        .map_err(HistoryCheckpointStepProofError::BadCheckpointIvcChunkCore)
    };
    let (
        ((step_statement_digest_proof, certificate_batch_digest_proof), accepted_claim_proof),
        checkpoint_ivc_chunk_core_proof,
    ) = rayon::join(prove_digest_components, prove_chunk_core);

    let backend = HistoryCheckpointStepBackendProof {
        step_statement_digest_proof: step_statement_digest_proof?,
        certificate_batch_digest_proof: certificate_batch_digest_proof?,
        certificate_statements: certificate_statements.to_vec(),
        certificate_validity_proofs: certificate_validity_proofs.to_vec(),
        accepted_claim_batch_digest_proof: Some(accepted_claim_proof?),
        checkpoint_ivc_chunk_core_proof: Some(checkpoint_ivc_chunk_core_proof?),
    };
    Ok(HistoryCheckpointStepProof {
        step_statement_digest: history_checkpoint_step_statement_digest(statement),
        certificate_batch_statement_digest: accepted_block_certificate_batch_statement_digest(
            certificate_batch_statement,
        ),
        backend_proof: bincode::serialize(&backend)
            .expect("HistoryCheckpointStepBackendProof serializes"),
    })
}

fn certificate_validity_proofs_from_statements(
    certificate_statements: &[AcceptedBlockCertificateStatement],
) -> Result<Vec<AcceptedBlockCertificateProof>, HistoryCheckpointStepProofError> {
    certificate_statements
        .par_iter()
        .map(|statement| {
            prove_accepted_block_certificate_proof_ivc_receipt(statement)
                .map_err(HistoryCheckpointStepProofError::BadCertificateValidityHandleProof)
        })
        .collect()
}

pub fn prove_history_checkpoint_step_proof_from_certificate_statements(
    statement: &HistoryCheckpointStepStatement,
    certificate_statements: &[AcceptedBlockCertificateStatement],
    accepted_claim_witness: &AcceptedClaimBatchWitness,
    accepted_claim_output: &AcceptedClaimBatchOutput,
) -> Result<
    (
        HistoryCheckpointStepProof,
        AcceptedBlockCertificateBatchStatement,
    ),
    HistoryCheckpointStepProofError,
> {
    let accepted_claim_batch_digest = validate_checkpoint_step_accepted_claim_batch_binding(
        statement,
        accepted_claim_witness,
        accepted_claim_output,
    )?;
    let certificate_batch_statement = accepted_block_certificate_batch_statement(
        certificate_statements,
        &accepted_claim_witness.accepted_block_claims,
        accepted_claim_batch_digest,
    )
    .map_err(HistoryCheckpointStepProofError::BadCertificateBatchStatement)?;
    let proof = prove_history_checkpoint_step_proof_with_ivc_chunk_core_components(
        statement,
        &certificate_batch_statement,
        certificate_statements,
        accepted_claim_witness,
        accepted_claim_output,
    )?;
    Ok((proof, certificate_batch_statement))
}

fn certificate_validity_handles_from_proofs(
    certificate_batch_statement: &AcceptedBlockCertificateBatchStatement,
    certificate_validity_proofs: &[AcceptedBlockCertificateProof],
    certificate_receipts: &[AcceptedBlockCertificateReceipt],
) -> Result<Vec<AcceptedBlockCertificateValidityHandle>, HistoryCheckpointStepProofError> {
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
            accepted_block_certificate_validity_handle(proof)
                .map_err(HistoryCheckpointStepProofError::BadCertificateValidityHandle)
        })
        .collect()
}

pub fn prove_history_checkpoint_step_digest_proof(
    statement: &HistoryCheckpointStepStatement,
) -> Result<HistoryCheckpointStepDigestProof, HistoryCheckpointStepProofError> {
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
    Ok(HistoryCheckpointStepDigestProof {
        step_statement_digest_hash,
    })
}

pub fn verify_history_checkpoint_step_digest_proof(
    statement: &HistoryCheckpointStepStatement,
    proof: &HistoryCheckpointStepDigestProof,
) -> Result<(), HistoryCheckpointStepProofError> {
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

pub fn encode_history_checkpoint_recursive_payload(
    payload: &HistoryCheckpointRecursivePayload,
) -> Vec<u8> {
    bincode::serialize(payload).expect("HistoryCheckpointRecursivePayload serializes")
}

pub fn history_checkpoint_public_proof_bytes_digest(bytes: &[u8]) -> Digest {
    poseidon2b_hash_byte_slices(HCP_PUBLIC_PROOF_DOMAIN, &[bytes])
}

pub fn decode_history_checkpoint_recursive_head_proof(
    proof: &HistoryCheckpointProof,
) -> Result<HistoryCheckpointRecursiveHeadProof, HistoryCheckpointProofError> {
    let payload: HistoryCheckpointRecursivePayload =
        bincode::deserialize(&proof.recursive_proof)
            .map_err(|_| HistoryCheckpointProofError::DecodeRecursivePayload)?;
    decode_history_checkpoint_recursive_head_proof_from_payload(&payload)
}

fn decode_history_checkpoint_recursive_head_proof_from_payload(
    payload: &HistoryCheckpointRecursivePayload,
) -> Result<HistoryCheckpointRecursiveHeadProof, HistoryCheckpointProofError> {
    if payload.backend_proof.is_empty() {
        return Err(HistoryCheckpointProofError::EmptyBackendProof);
    }
    bincode::deserialize(&payload.backend_proof)
        .map_err(|_| HistoryCheckpointProofError::DecodeRecursiveHeadProof)
}

pub fn prove_history_checkpoint_recursive_head_record(
    previous: Option<&StoredHistoryCheckpointHeadRecord>,
    base_anchor: &HeaderChainAnchor,
    base_accumulator: &ChainAccumulator,
    step_statement: &HistoryCheckpointStepStatement,
    certificate_batch_statement: &AcceptedBlockCertificateBatchStatement,
    step_proof: &HistoryCheckpointStepProof,
) -> Result<StoredHistoryCheckpointHeadRecord, HistoryCheckpointProofError> {
    let recursive_head_proof = HistoryCheckpointRecursiveHeadProof {
        engine_id: HISTORY_CHECKPOINT_ENGINE_STREAMING_TOWER_IVC,
        head: step_statement.next_head.clone(),
        previous_head: previous.map(|record| record.head.clone()),
        previous_proof_digest: previous.map(|record| record.proof_digest),
        step_statement: step_statement.clone(),
        certificate_batch_statement: certificate_batch_statement.clone(),
        step_proof: step_proof.clone(),
    };

    let payload = HistoryCheckpointRecursivePayload {
        engine_id: HISTORY_CHECKPOINT_ENGINE_STREAMING_TOWER_IVC,
        head: recursive_head_proof.head.clone(),
        backend_proof: bincode::serialize(&recursive_head_proof)
            .expect("HistoryCheckpointRecursiveHeadProof serializes"),
    };
    let proof = HistoryCheckpointProof {
        engine_id: HISTORY_CHECKPOINT_ENGINE_STREAMING_TOWER_IVC,
        checkpoint_height: step_statement.batch_summary.end_anchor.height,
        start_anchor: base_anchor.clone(),
        end_anchor: step_statement.batch_summary.end_anchor.clone(),
        start_accumulator: base_accumulator.clone(),
        end_accumulator: step_statement.batch_summary.end_accumulator.clone(),
        recursive_proof: encode_history_checkpoint_recursive_payload(&payload),
    };
    verify_history_checkpoint_proof_checkpoint(
        &proof,
        base_anchor,
        &step_statement.batch_summary.end_anchor,
    )?;

    let proof_bytes =
        bincode::serialize(&proof).expect("HistoryCheckpointProof serialization must succeed");
    let proof_digest = history_checkpoint_public_proof_bytes_digest(&proof_bytes);
    let record = StoredHistoryCheckpointHeadRecord {
        height: step_statement.next_head.checkpoint_height,
        head: step_statement.next_head.clone(),
        proof_digest,
        proof_bytes,
        previous_height: previous.map(|record| record.height),
        package_end_height: step_statement.batch_summary.end_anchor.height,
    };
    verify_history_checkpoint_head_record_transition(previous, &record)?;
    Ok(record)
}

pub fn verify_history_checkpoint_head_record(
    record: &StoredHistoryCheckpointHeadRecord,
) -> Result<(), HistoryCheckpointProofError> {
    let proof: HistoryCheckpointProof = bincode::deserialize(&record.proof_bytes)
        .map_err(|_| HistoryCheckpointProofError::DecodeRecursivePayload)?;
    let verified = verify_history_checkpoint_proof_checkpoint_inner(
        &proof,
        &proof.start_anchor,
        &proof.end_anchor,
    )?;
    let recursive = verified.recursive;
    if record.proof_digest != history_checkpoint_public_proof_bytes_digest(&record.proof_bytes) {
        return Err(HistoryCheckpointProofError::RecursivePreviousProofDigestMismatch);
    }
    if record.height != proof.checkpoint_height
        || record.height != recursive.head.checkpoint_height
        || record.head != recursive.head
        || record.package_end_height != recursive.step_statement.batch_summary.end_anchor.height
    {
        return Err(HistoryCheckpointProofError::RecursiveHeadMismatch);
    }
    match (&recursive.previous_head, record.previous_height) {
        (None, None) => {}
        (Some(previous_head), Some(previous_height))
            if previous_head.checkpoint_height == previous_height => {}
        _ => return Err(HistoryCheckpointProofError::RecursivePreviousHeadMismatch),
    }
    Ok(())
}

pub fn verify_history_checkpoint_head_record_transition(
    previous: Option<&StoredHistoryCheckpointHeadRecord>,
    record: &StoredHistoryCheckpointHeadRecord,
) -> Result<(), HistoryCheckpointProofError> {
    verify_history_checkpoint_head_record(record)?;
    let proof: HistoryCheckpointProof = bincode::deserialize(&record.proof_bytes)
        .map_err(|_| HistoryCheckpointProofError::DecodeRecursivePayload)?;
    let recursive = decode_history_checkpoint_recursive_head_proof(&proof)?;
    match previous {
        Some(previous) => {
            verify_history_checkpoint_head_record(previous)?;
            if record.previous_height != Some(previous.height)
                || recursive.previous_head.as_ref() != Some(&previous.head)
                || recursive.previous_proof_digest != Some(previous.proof_digest)
                || recursive.step_statement.previous_head != previous.head
            {
                return Err(HistoryCheckpointProofError::RecursivePreviousHeadMismatch);
            }
            let previous_proof: HistoryCheckpointProof =
                bincode::deserialize(&previous.proof_bytes)
                    .map_err(|_| HistoryCheckpointProofError::DecodeRecursivePayload)?;
            if proof.start_anchor != previous_proof.start_anchor
                || proof.start_accumulator != previous_proof.start_accumulator
            {
                return Err(HistoryCheckpointProofError::StartAnchorMismatch);
            }
        }
        None => {
            if record.previous_height.is_some()
                || recursive.previous_head.is_some()
                || recursive.previous_proof_digest.is_some()
            {
                return Err(HistoryCheckpointProofError::RecursivePreviousHeadMismatch);
            }
        }
    }
    Ok(())
}

pub fn public_history_checkpoint_proof_from_head_record(
    record: &StoredHistoryCheckpointHeadRecord,
) -> Result<HistoryCheckpointProof, HistoryCheckpointProofError> {
    verify_history_checkpoint_head_record(record)?;
    bincode::deserialize(&record.proof_bytes)
        .map_err(|_| HistoryCheckpointProofError::DecodeRecursivePayload)
}

fn validate_checkpoint_step_certificate_batch_binding(
    statement: &HistoryCheckpointStepStatement,
    certificate_batch_statement: &AcceptedBlockCertificateBatchStatement,
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
    statement: &HistoryCheckpointStepStatement,
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
    let digest = accepted_claim_batch_digest(accepted_claim_witness, accepted_claim_output)
        .map_err(HistoryCheckpointStepProofError::BadAcceptedClaimBatchDigestProof)?;
    if digest != statement.batch_summary.accepted_claim_batch_digest {
        return Err(HistoryCheckpointStepProofError::AcceptedClaimBatchDigestMismatch);
    }
    Ok(digest)
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

pub fn history_checkpoint_batch_summary_digest(summary: &HistoryCheckpointBatchSummary) -> Digest {
    let mut sponge = checkpoint_sponge(HCP_SUM1);
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

pub fn history_checkpoint_head_digest(head: &HistoryCheckpointHead) -> Digest {
    let mut sponge = checkpoint_sponge(HCP_HEAD1);
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
    statement: &HistoryCheckpointStepStatement,
) -> Digest {
    digest_fixed_no_pad_from_fields(&history_checkpoint_step_statement_hash_fields(statement))
}

pub fn history_checkpoint_step_statement_hash_fields(
    statement: &HistoryCheckpointStepStatement,
) -> [Block128; HISTORY_CHECKPOINT_STEP_STATEMENT_HASH_FIELDS] {
    let mut fields = [Block128::ZERO; HISTORY_CHECKPOINT_STEP_STATEMENT_HASH_FIELDS];
    let mut index = 0usize;
    fields[index] = Block128::from(HCP_STMT1);
    index += 1;
    fields[index] = Block128::from(8u128);
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

pub fn verify_history_checkpoint_proof_checkpoint(
    proof: &HistoryCheckpointProof,
    local_start_anchor: &HeaderChainAnchor,
    local_end_anchor: &HeaderChainAnchor,
) -> Result<(), HistoryCheckpointProofError> {
    verify_history_checkpoint_proof_checkpoint_inner(proof, local_start_anchor, local_end_anchor)
        .map(|_| ())
}

struct VerifiedHistoryCheckpointProof {
    recursive: HistoryCheckpointRecursiveHeadProof,
}

fn verify_history_checkpoint_proof_checkpoint_inner(
    proof: &HistoryCheckpointProof,
    local_start_anchor: &HeaderChainAnchor,
    local_end_anchor: &HeaderChainAnchor,
) -> Result<VerifiedHistoryCheckpointProof, HistoryCheckpointProofError> {
    if proof.engine_id != HISTORY_CHECKPOINT_ENGINE_STREAMING_TOWER_IVC {
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
    let payload: HistoryCheckpointRecursivePayload =
        bincode::deserialize(&proof.recursive_proof)
            .map_err(|_| HistoryCheckpointProofError::DecodeRecursivePayload)?;
    if payload.engine_id != HISTORY_CHECKPOINT_ENGINE_STREAMING_TOWER_IVC {
        return Err(HistoryCheckpointProofError::UnsupportedEngine {
            actual: payload.engine_id,
        });
    }
    validate_head_shape(&payload.head)?;
    let recursive_head_proof =
        decode_history_checkpoint_recursive_head_proof_from_payload(&payload)?;
    verify_history_checkpoint_recursive_head_proof(proof, &payload, &recursive_head_proof)?;
    if payload.head.checkpoint_height != proof.checkpoint_height
        || payload.head.anchor_digest != history_checkpoint_anchor_digest(&proof.end_anchor)
        || payload.head.accumulator_digest
            != history_checkpoint_accumulator_digest(&proof.end_accumulator)
    {
        return Err(HistoryCheckpointProofError::RecursiveHeadMismatch);
    }

    Ok(VerifiedHistoryCheckpointProof {
        recursive: recursive_head_proof,
    })
}

fn verify_history_checkpoint_recursive_head_proof(
    proof: &HistoryCheckpointProof,
    payload: &HistoryCheckpointRecursivePayload,
    recursive: &HistoryCheckpointRecursiveHeadProof,
) -> Result<(), HistoryCheckpointProofError> {
    if recursive.engine_id != HISTORY_CHECKPOINT_ENGINE_STREAMING_TOWER_IVC {
        return Err(HistoryCheckpointProofError::UnsupportedEngine {
            actual: recursive.engine_id,
        });
    }
    validate_head_shape(&recursive.head)?;
    if recursive.head != payload.head || recursive.head != recursive.step_statement.next_head {
        return Err(HistoryCheckpointProofError::RecursiveHeadMismatch);
    }

    verify_history_checkpoint_step_proof_checkpoint(
        &recursive.step_statement,
        &recursive.certificate_batch_statement,
        &recursive.step_proof,
    )
    .map_err(|source| HistoryCheckpointProofError::BadCheckpointStepProof(Box::new(source)))?;

    match (&recursive.previous_head, recursive.previous_proof_digest) {
        (None, None) => {
            let expected_base = history_checkpoint_head_from_boundary(
                &proof.start_anchor,
                &proof.start_accumulator,
                &recursive.step_statement.batch_summary.start_consensus,
            )?;
            if recursive.step_statement.previous_head != expected_base
                || recursive.step_statement.batch_summary.start_anchor != proof.start_anchor
                || recursive.step_statement.batch_summary.start_accumulator
                    != proof.start_accumulator
            {
                return Err(HistoryCheckpointProofError::RecursivePreviousHeadMismatch);
            }
        }
        (Some(previous_head), Some(_previous_proof_digest)) => {
            if *previous_head != recursive.step_statement.previous_head
                || previous_head.checkpoint_height
                    != recursive.step_statement.batch_summary.start_anchor.height
                || previous_head.anchor_digest
                    != history_checkpoint_anchor_digest(
                        &recursive.step_statement.batch_summary.start_anchor,
                    )
                || previous_head.accumulator_digest
                    != history_checkpoint_accumulator_digest(
                        &recursive.step_statement.batch_summary.start_accumulator,
                    )
                || previous_head.consensus_digest
                    != history_checkpoint_consensus_digest(
                        &recursive.step_statement.batch_summary.start_consensus,
                    )
            {
                return Err(HistoryCheckpointProofError::RecursivePreviousHeadMismatch);
            }
        }
        _ => return Err(HistoryCheckpointProofError::RecursivePreviousProofDigestMismatch),
    }

    if recursive.step_statement.batch_summary.end_anchor != proof.end_anchor
        || recursive.step_statement.batch_summary.end_accumulator != proof.end_accumulator
        || recursive.head.checkpoint_height != proof.checkpoint_height
    {
        return Err(HistoryCheckpointProofError::RecursiveHeadMismatch);
    }
    Ok(())
}

fn validate_head_shape(head: &HistoryCheckpointHead) -> Result<(), HistoryCheckpointProofError> {
    if head.engine_id != HISTORY_CHECKPOINT_ENGINE_STREAMING_TOWER_IVC {
        return Err(HistoryCheckpointProofError::UnsupportedEngine {
            actual: head.engine_id,
        });
    }
    Ok(())
}

fn validate_batch_summary_shape(
    summary: &HistoryCheckpointBatchSummary,
) -> Result<(), HistoryCheckpointProofError> {
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

    fn head_record() -> StoredHistoryCheckpointHeadRecord {
        let (statement, accepted_claim_witness, accepted_claim_output, certificate_statements) =
            step_statement_pair_with_accepted_claim_batch();
        let (step_proof, certificate_batch) =
            prove_history_checkpoint_step_proof_from_certificate_statements(
                &statement,
                &certificate_statements,
                &accepted_claim_witness,
                &accepted_claim_output,
            )
            .expect("strict checkpoint step proof builds");
        prove_history_checkpoint_recursive_head_record(
            None,
            &statement.batch_summary.start_anchor,
            &statement.batch_summary.start_accumulator,
            &statement,
            &certificate_batch,
            &step_proof,
        )
        .expect("recursive checkpoint head record builds")
    }

    fn proof() -> HistoryCheckpointProof {
        let record = head_record();
        bincode::deserialize(&record.proof_bytes).expect("record proof bytes decode")
    }

    fn rewrite_record_recursive_head_proof(
        mut record: StoredHistoryCheckpointHeadRecord,
        mutate: impl FnOnce(&mut HistoryCheckpointRecursiveHeadProof),
    ) -> StoredHistoryCheckpointHeadRecord {
        let mut proof: HistoryCheckpointProof =
            bincode::deserialize(&record.proof_bytes).expect("proof decodes");
        let mut payload: HistoryCheckpointRecursivePayload =
            bincode::deserialize(&proof.recursive_proof).expect("payload decodes");
        let mut recursive: HistoryCheckpointRecursiveHeadProof =
            bincode::deserialize(&payload.backend_proof).expect("recursive head proof decodes");
        mutate(&mut recursive);
        payload.head = recursive.head.clone();
        payload.backend_proof =
            bincode::serialize(&recursive).expect("recursive head proof serializes");
        proof.recursive_proof = encode_history_checkpoint_recursive_payload(&payload);
        record.proof_bytes = bincode::serialize(&proof).expect("proof serializes");
        record.proof_digest = history_checkpoint_public_proof_bytes_digest(&record.proof_bytes);
        record
    }

    fn batch_summary() -> HistoryCheckpointBatchSummary {
        let proof = proof();
        HistoryCheckpointBatchSummary {
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
        HistoryCheckpointStepStatement,
        AcceptedBlockCertificateBatchStatement,
    ) {
        let summary = batch_summary();
        let previous = history_checkpoint_head_from_boundary(
            &summary.start_anchor,
            &summary.start_accumulator,
            &summary.start_consensus,
        )
        .expect("start boundary builds a checkpoint head");
        let next = advance_history_checkpoint_head_native(&previous, &summary)
            .expect("checkpoint batch advances");
        let statement = HistoryCheckpointStepStatement {
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
        let certificate_batch = AcceptedBlockCertificateBatchStatement {
            batch_len: summary.batch_len,
            accepted_claim_batch_digest: summary.accepted_claim_batch_digest,
            certificate_statement_digests,
        };
        (statement, certificate_batch)
    }

    fn step_statement_pair_with_accepted_claim_batch() -> (
        HistoryCheckpointStepStatement,
        AcceptedClaimBatchWitness,
        AcceptedClaimBatchOutput,
        Vec<AcceptedBlockCertificateStatement>,
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
            let certificate = AcceptedBlockCertificateStatement {
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
            accepted_claim_batch_digest(&accepted_claim_witness, &accepted_claim_output)
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
        let summary = HistoryCheckpointBatchSummary {
            batch_len: HISTORY_CHECKPOINT_BATCH_TARGET_BLOCKS,
            start_anchor,
            end_anchor,
            start_accumulator,
            end_accumulator: accepted_claim_output.accumulator.clone(),
            start_consensus,
            end_consensus: accepted_claim_output.consensus_state.clone(),
            accepted_claim_batch_digest,
        };
        let previous = history_checkpoint_head_from_boundary(
            &summary.start_anchor,
            &summary.start_accumulator,
            &summary.start_consensus,
        )
        .expect("start boundary builds a checkpoint head");
        let next = advance_history_checkpoint_head_native(&previous, &summary)
            .expect("checkpoint batch advances");
        let statement = HistoryCheckpointStepStatement {
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
        statement: &HistoryCheckpointStepStatement,
        certificate_batch: &AcceptedBlockCertificateBatchStatement,
    ) -> HistoryCheckpointStepProof {
        prove_history_checkpoint_step_digest_boundary_for_tests(statement, certificate_batch)
            .expect("checkpoint step proof builds")
    }

    fn unchecked_step_proof(
        statement: &HistoryCheckpointStepStatement,
        certificate_batch: &AcceptedBlockCertificateBatchStatement,
    ) -> HistoryCheckpointStepProof {
        HistoryCheckpointStepProof {
            step_statement_digest: history_checkpoint_step_statement_digest(statement),
            certificate_batch_statement_digest: accepted_block_certificate_batch_statement_digest(
                certificate_batch,
            ),
            backend_proof: vec![0x42],
        }
    }

    #[test]
    fn checkpoint_proof_roundtrips_and_has_nonzero_size() {
        let proof = proof();
        let encoded = bincode::serialize(&proof).expect("serialize proof");
        let decoded: HistoryCheckpointProof =
            bincode::deserialize(&encoded).expect("deserialize proof");
        assert_eq!(decoded, proof);
        assert_eq!(proof.byte_len(), encoded.len());
    }

    #[test]
    fn checkpoint_proof_recursive_head_payload_path_verifies() {
        let proof = proof();
        verify_history_checkpoint_proof_checkpoint(&proof, &proof.start_anchor, &proof.end_anchor)
            .expect("checkpoint proof recursive head payload path verifies");
    }

    #[test]
    fn recursive_head_record_base_case_verifies() {
        let record = head_record();
        verify_history_checkpoint_head_record(&record).expect("head record verifies");
        verify_history_checkpoint_head_record_transition(None, &record)
            .expect("base head record transition verifies");
    }

    #[test]
    fn recursive_head_record_rejects_public_proof_digest_mismatch() {
        let mut record = head_record();
        record.proof_digest[0] ^= 1;
        assert_eq!(
            verify_history_checkpoint_head_record(&record),
            Err(HistoryCheckpointProofError::RecursivePreviousProofDigestMismatch)
        );
    }

    #[test]
    fn recursive_head_record_rejects_wrong_previous_head() {
        let mut record = rewrite_record_recursive_head_proof(head_record(), |recursive| {
            let mut previous = recursive.step_statement.previous_head.clone();
            previous.recursive_digest = [0x33; 32];
            recursive.previous_head = Some(previous);
            recursive.previous_proof_digest = Some([0x44; 32]);
        });
        record.previous_height = Some(0);
        assert_eq!(
            verify_history_checkpoint_head_record(&record),
            Err(HistoryCheckpointProofError::RecursivePreviousHeadMismatch)
        );
    }

    #[test]
    fn recursive_head_record_rejects_wrong_previous_proof_digest_shape() {
        let record = rewrite_record_recursive_head_proof(head_record(), |recursive| {
            recursive.previous_proof_digest = Some([0x44; 32]);
        });
        assert_eq!(
            verify_history_checkpoint_head_record(&record),
            Err(HistoryCheckpointProofError::RecursivePreviousProofDigestMismatch)
        );
    }

    #[test]
    fn checkpoint_proof_rejects_shape_mismatches_before_backend() {
        let proof = proof();

        let mut bad = proof.clone();
        bad.engine_id += 1;
        assert!(matches!(
            verify_history_checkpoint_proof_checkpoint(
                &bad,
                &proof.start_anchor,
                &proof.end_anchor
            ),
            Err(HistoryCheckpointProofError::UnsupportedEngine { .. })
        ));

        let mut bad = proof.clone();
        bad.recursive_proof.clear();
        assert_eq!(
            verify_history_checkpoint_proof_checkpoint(
                &bad,
                &proof.start_anchor,
                &proof.end_anchor
            ),
            Err(HistoryCheckpointProofError::EmptyRecursiveProof)
        );

        let mut bad = proof.clone();
        bad.recursive_proof = vec![0x99; 7];
        assert_eq!(
            verify_history_checkpoint_proof_checkpoint(
                &bad,
                &proof.start_anchor,
                &proof.end_anchor
            ),
            Err(HistoryCheckpointProofError::DecodeRecursivePayload)
        );

        let mut bad = proof.clone();
        bad.checkpoint_height += 1;
        assert_eq!(
            verify_history_checkpoint_proof_checkpoint(
                &bad,
                &proof.start_anchor,
                &proof.end_anchor
            ),
            Err(HistoryCheckpointProofError::CheckpointHeightMismatch)
        );

        let mut bad = proof.clone();
        bad.end_accumulator.state_root = [0x33; 32];
        assert_eq!(
            verify_history_checkpoint_proof_checkpoint(
                &bad,
                &proof.start_anchor,
                &proof.end_anchor
            ),
            Err(HistoryCheckpointProofError::EndAccumulatorMismatch)
        );

        let mut payload: HistoryCheckpointRecursivePayload =
            bincode::deserialize(&proof.recursive_proof).expect("payload decodes");
        payload.backend_proof.clear();
        let mut bad = proof.clone();
        bad.recursive_proof = encode_history_checkpoint_recursive_payload(&payload);
        assert_eq!(
            verify_history_checkpoint_proof_checkpoint(
                &bad,
                &proof.start_anchor,
                &proof.end_anchor
            ),
            Err(HistoryCheckpointProofError::EmptyBackendProof)
        );

        let mut payload: HistoryCheckpointRecursivePayload =
            bincode::deserialize(&proof.recursive_proof).expect("payload decodes");
        payload.head.anchor_digest = [0x77; 32];
        let mut bad = proof.clone();
        bad.recursive_proof = encode_history_checkpoint_recursive_payload(&payload);
        assert_eq!(
            verify_history_checkpoint_proof_checkpoint(
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
        let previous = history_checkpoint_head_from_boundary(
            &summary.start_anchor,
            &summary.start_accumulator,
            &summary.start_consensus,
        )
        .expect("start boundary builds a checkpoint head");
        let next = advance_history_checkpoint_head_native(&previous, &summary)
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

        let statement = HistoryCheckpointStepStatement {
            previous_head: previous.clone(),
            batch_summary: summary.clone(),
            next_head: next.clone(),
        };
        verify_history_checkpoint_step_statement_native(&statement)
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
            prove_history_checkpoint_step_digest_proof(&statement).expect("digest proof builds");
        verify_history_checkpoint_step_digest_proof(&statement, &digest_proof)
            .expect("digest proof verifies");

        let mut tampered = statement;
        tampered.next_head.recursive_digest = [0x66; 32];
        assert_eq!(
            verify_history_checkpoint_step_digest_proof(&tampered, &digest_proof),
            Err(HistoryCheckpointStepProofError::BadStepStatementDigestProof)
        );
    }

    #[test]
    fn checkpoint_step_digest_boundary_path_is_not_public_checkpoint() {
        let (statement, certificate_batch) = step_statement_pair();
        let proof = step_proof(&statement, &certificate_batch);
        assert_eq!(
            verify_history_checkpoint_step_proof_checkpoint(&statement, &certificate_batch, &proof),
            Err(HistoryCheckpointStepProofError::MissingCheckpointIvcChunkCoreProof)
        );

        let mut bad = proof.clone();
        bad.step_statement_digest = [0xAA; 32];
        assert_eq!(
            verify_history_checkpoint_step_proof_checkpoint(&statement, &certificate_batch, &bad),
            Err(HistoryCheckpointStepProofError::StepStatementDigestMismatch)
        );

        let mut bad = proof.clone();
        bad.certificate_batch_statement_digest = [0xBB; 32];
        assert_eq!(
            verify_history_checkpoint_step_proof_checkpoint(&statement, &certificate_batch, &bad),
            Err(HistoryCheckpointStepProofError::CertificateBatchDigestMismatch)
        );

        let mut bad_certificate_batch = certificate_batch.clone();
        bad_certificate_batch.batch_len -= 1;
        let bad_proof = unchecked_step_proof(&statement, &bad_certificate_batch);
        assert_eq!(
            verify_history_checkpoint_step_proof_checkpoint(
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
            verify_history_checkpoint_step_proof_checkpoint(
                &statement,
                &bad_certificate_batch,
                &bad_proof
            ),
            Err(HistoryCheckpointStepProofError::CertificateBatchAcceptedClaimDigestMismatch)
        );

        let mut bad = proof.clone();
        bad.backend_proof.clear();
        assert_eq!(
            verify_history_checkpoint_step_proof_checkpoint(&statement, &certificate_batch, &bad),
            Err(HistoryCheckpointStepProofError::EmptyBackendProof)
        );

        let mut bad = proof;
        bad.backend_proof = vec![0x42];
        assert_eq!(
            verify_history_checkpoint_step_proof_checkpoint(&statement, &certificate_batch, &bad),
            Err(HistoryCheckpointStepProofError::DecodeBackendProof)
        );
    }

    #[test]
    fn checkpoint_step_component_backend_carries_accepted_claim_digest_proof() {
        let (statement, accepted_claim_witness, accepted_claim_output, certificate_statements) =
            step_statement_pair_with_accepted_claim_batch();
        let (proof, certificate_batch) =
            prove_history_checkpoint_step_proof_from_certificate_statements(
                &statement,
                &certificate_statements,
                &accepted_claim_witness,
                &accepted_claim_output,
            )
            .expect("checkpoint step component proof builds");
        let mut bad_certificate_statements = certificate_statements.clone();
        bad_certificate_statements[0].accepted_block_claim_digest = [0x11; 32];
        assert!(matches!(
            prove_history_checkpoint_step_proof_from_certificate_statements(
                &statement,
                &bad_certificate_statements,
                &accepted_claim_witness,
                &accepted_claim_output,
            ),
            Err(HistoryCheckpointStepProofError::BadCertificateBatchStatement(_))
        ));
        let direct_proof = prove_history_checkpoint_step_proof_with_digest_components(
            &statement,
            &certificate_batch,
            &accepted_claim_witness,
            &accepted_claim_output,
        )
        .expect("direct checkpoint step component proof builds");
        let backend: HistoryCheckpointStepBackendProof =
            bincode::deserialize(&proof.backend_proof).expect("checkpoint backend decodes");
        assert_eq!(backend.certificate_statements, certificate_statements);
        assert_eq!(
            backend.certificate_validity_proofs.len(),
            certificate_statements.len()
        );
        assert!(backend.checkpoint_ivc_chunk_core_proof.is_some());
        verify_history_checkpoint_step_proof_private_components_native(
            &statement,
            &certificate_batch,
            &accepted_claim_witness,
            &accepted_claim_output,
            &proof,
        )
        .expect("private digest components verify");
        verify_history_checkpoint_step_proof_checkpoint(&statement, &certificate_batch, &proof)
            .expect("checkpoint component backend verifies through checkpoint path");
        assert_eq!(
            direct_proof.certificate_batch_statement_digest,
            proof.certificate_batch_statement_digest
        );
        let mut bad_backend = backend.clone();
        bad_backend.certificate_validity_proofs[0].statement_digest[0] ^= 1;
        let mut bad = proof.clone();
        bad.backend_proof =
            bincode::serialize(&bad_backend).expect("tampered checkpoint backend serializes");
        let tampered_result =
            verify_history_checkpoint_step_proof_checkpoint(&statement, &certificate_batch, &bad);
        assert!(matches!(
            tampered_result,
            Err(
                HistoryCheckpointStepProofError::CertificateValidityProofStatementMismatch {
                    index: 0
                } | HistoryCheckpointStepProofError::CertificateValidityProofHandleMismatch {
                    index: 0
                } | HistoryCheckpointStepProofError::BadCertificateValidityHandle(_)
                    | HistoryCheckpointStepProofError::BadCertificateValidityHandleProof(_)
            )
        ));

        let digest_boundary = step_proof(&statement, &certificate_batch);
        assert_eq!(
            verify_history_checkpoint_step_proof_private_components_native(
                &statement,
                &certificate_batch,
                &accepted_claim_witness,
                &accepted_claim_output,
                &digest_boundary,
            ),
            Err(HistoryCheckpointStepProofError::MissingAcceptedClaimBatchDigestProof)
        );

        let mut tampered_output = accepted_claim_output;
        tampered_output.accumulator.chain_hash = [0x5A; 32];
        assert_eq!(
            verify_history_checkpoint_step_proof_private_components_native(
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
        let previous = history_checkpoint_head_from_boundary(
            &summary.start_anchor,
            &summary.start_accumulator,
            &summary.start_consensus,
        )
        .expect("start boundary builds a checkpoint head");

        let mut bad_summary = summary.clone();
        bad_summary.batch_len = 0;
        assert_eq!(
            advance_history_checkpoint_head_native(&previous, &bad_summary),
            Err(HistoryCheckpointProofError::BadBatchLength { actual: 0 })
        );

        let mut bad_summary = summary.clone();
        bad_summary.batch_len = HISTORY_CHECKPOINT_BATCH_TARGET_BLOCKS + 1;
        assert_eq!(
            advance_history_checkpoint_head_native(&previous, &bad_summary),
            Err(HistoryCheckpointProofError::BadBatchLength {
                actual: HISTORY_CHECKPOINT_BATCH_TARGET_BLOCKS + 1,
            })
        );

        let mut bad_summary = summary.clone();
        bad_summary.end_accumulator.state_root = [0x99; 32];
        assert_eq!(
            advance_history_checkpoint_head_native(&previous, &bad_summary),
            Err(HistoryCheckpointProofError::EndAccumulatorMismatch)
        );

        let wrong_previous = history_checkpoint_head_from_boundary(
            &summary.end_anchor,
            &summary.end_accumulator,
            &summary.end_consensus,
        )
        .expect("end boundary builds a checkpoint head");
        assert_eq!(
            advance_history_checkpoint_head_native(&wrong_previous, &summary),
            Err(HistoryCheckpointProofError::BatchStartMismatch)
        );

        let next = advance_history_checkpoint_head_native(&previous, &summary)
            .expect("checkpoint batch advances");
        let mut bad_statement = HistoryCheckpointStepStatement {
            previous_head: previous,
            batch_summary: summary,
            next_head: next,
        };
        bad_statement.next_head.recursive_digest = [0x77; 32];
        assert_eq!(
            verify_history_checkpoint_step_statement_native(&bad_statement),
            Err(HistoryCheckpointProofError::StepHeadMismatch)
        );
    }
}
