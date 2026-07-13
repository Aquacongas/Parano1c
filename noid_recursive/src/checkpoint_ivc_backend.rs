// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Poseidon-backed IVC proof-core backend for checkpoint chunks.
//!
//! This is the production-side landing zone for the extracted proof-core work.
//! It intentionally depends on `noid-ivc-prover`, not on a separate history lab
//! crate.
//!
//! Current scope: a fixed 16-slot chunk-core relation with public receipt
//! projection pins. It proves the checkpoint boundary is connected to
//! accepted-claim/header/receipt linkage witnesses. It is not yet the final
//! public checkpoint verifier: the remaining layer must prove accepted-block
//! certificate validity and previous recursive head validity inside the IVC
//! backend. It must not replay transaction-shaped retained component lists
//! inside history aggregation.

use noid_chain::BlockHeader;
use noid_core::Block128;
use noid_ivc_prover::challenger::{Challenger, FsChallenger};
use noid_ivc_prover::pcs::{ligerito::LigeritoProfile, pack_witness, PcsParams};
use noid_ivc_prover::proof_io::R1csProofBundle;
use noid_ivc_prover::r1cs::{BlockR1cs, SparseBinaryMatrix};
use noid_poseidon2b::native::poseidon2b_hash_byte_slices;
use noid_poseidon2b::primitives::{Address, Digest};

use crate::accepted_batch::{
    accepted_claim_batch_digest, accepted_claim_batch_digest_from_hash_fields,
    accepted_claim_batch_digest_hash_fields, AcceptedClaimBatchDigestError,
    AcceptedClaimBatchOutput, AcceptedClaimBatchWitness,
    ACCEPTED_CLAIM_BATCH_DIGEST_ACCUMULATOR_FIELDS, ACCEPTED_CLAIM_BATCH_DIGEST_CLAIM_FIELDS,
    ACCEPTED_CLAIM_BATCH_DIGEST_CONSENSUS_FIELDS, ACCEPTED_CLAIM_BATCH_DIGEST_HASH_FIELDS,
    ACCEPTED_CLAIM_BATCH_DIGEST_HEADER_WITNESS_FIELDS, ACCEPTED_CLAIM_BATCH_DIGEST_SLOT_FIELDS,
};
use crate::accumulator::{ChainAccumulator, ChainAccumulatorAdvanceError};
use crate::block_certificate::{
    accepted_block_certificate_batch_statement, accepted_block_certificate_receipt,
    accepted_block_certificate_receipt_chain_claim, accepted_block_receipt_projection_handle,
    verify_accepted_block_certificate_receipt_projection,
    verify_accepted_block_receipt_projection_handle, AcceptedBlockCertificateBatchError,
    AcceptedBlockCertificateBatchStatement, AcceptedBlockCertificateProofError,
    AcceptedBlockCertificateReceipt, AcceptedBlockCertificateReceiptError,
    AcceptedBlockCertificateStatement, AcceptedBlockReceiptProjectionHandle,
    AcceptedBlockReceiptProjectionHandleError,
};
use crate::block_certificate_ivc::prove_accepted_block_certificate_receipt_projection_proof;
use crate::checkpoint_proof::{
    verify_history_checkpoint_step_statement_native, HistoryCheckpointProofError,
    HistoryCheckpointStepStatement, HISTORY_CHECKPOINT_BATCH_TARGET_BLOCKS,
};
use crate::pow_header::HeaderWitness;

pub const HISTORY_CHECKPOINT_IVC_CHUNK_CORE_RELATION: u32 = 1;
/// DoS cap on the serialized chunk-core proof. Sized for the FieldR1cs
/// proof format with per-query independent Merkle paths (each FRI query
/// carries its own full-depth paths; ~118 KB at the chunk shape), plus
/// headroom.
pub const HISTORY_CHECKPOINT_IVC_CHUNK_CORE_WIRE_BYTES: usize = 160 * 1024;

const TRANSCRIPT_DOMAIN: &[u8] = b"noid-recursive-checkpoint-ivc-chunk-core";
const STATEMENT_DIGEST_DOMAIN: &[u8] = b"NOID/REC/CHK-IVC-STMT";
const CHUNK_CAPACITY: usize = HISTORY_CHECKPOINT_BATCH_TARGET_BLOCKS as usize;
const CHUNK_M: usize = 16;
const CHUNK_K_LOG: usize = 16;
const CHUNK_BITS: usize = 1usize << CHUNK_K_LOG;
const SLOT_BITS: usize = CHUNK_BITS / CHUNK_CAPACITY;
pub const HISTORY_CHECKPOINT_IVC_PCS_LOG_INV_RATE: usize = 4;
pub const HISTORY_CHECKPOINT_IVC_PCS_LOG_BATCH_SIZE: usize = 5;

const CONST_ONE: usize = 0;
const PREV_HEIGHT: usize = 1;
const CERT_HEIGHT: usize = PREV_HEIGHT + 64;
const HEADER_HEIGHT: usize = CERT_HEIGHT + 64;
const NEXT_HEIGHT: usize = HEADER_HEIGHT + 64;
const HEIGHT_CARRY: usize = NEXT_HEIGHT + 64;
const PREV_STATE: usize = HEIGHT_CARRY + 64;
const CERT_PARENT_STATE: usize = PREV_STATE + 256;
const CERT_CHILD_STATE: usize = CERT_PARENT_STATE + 256;
const HEADER_STATE: usize = CERT_CHILD_STATE + 256;
const NEXT_STATE: usize = HEADER_STATE + 256;
const PREV_BLOCK: usize = NEXT_STATE + 256;
const HEADER_PREV_BLOCK: usize = PREV_BLOCK + 256;
const CERT_PARENT_BLOCK: usize = HEADER_PREV_BLOCK + 256;
const HEADER_BLOCK: usize = CERT_PARENT_BLOCK + 256;
const CERT_BLOCK: usize = HEADER_BLOCK + 256;
const CLAIM_WITNESS: usize = CERT_BLOCK + 256;
const CERT_CLAIM_DIGEST: usize = CLAIM_WITNESS + 256;
const CERT_STATEMENT_DIGEST: usize = CERT_CLAIM_DIGEST + 256;
const SLOT_USEFUL_BITS: usize = CERT_STATEMENT_DIGEST + 256;

const _: () = assert!(SLOT_USEFUL_BITS <= SLOT_BITS);

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HistoryCheckpointIvcChunkCoreProof {
    pub relation: u32,
    pub chunk_len: u32,
    pub certificate_receipt_projection_handles: Vec<AcceptedBlockReceiptProjectionHandle>,
    pub certificate_receipts: Vec<AcceptedBlockCertificateReceipt>,
    pub accepted_claim_digest_hash_fields: Vec<Block128>,
    pub core_proof_len: u32,
    pub core_proof: Vec<u8>,
}

impl HistoryCheckpointIvcChunkCoreProof {
    pub fn byte_len(&self) -> usize {
        bincode::serialized_size(self)
            .expect("serialized HistoryCheckpointIvcChunkCoreProof length fits usize")
            as usize
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HistoryCheckpointIvcChunkCoreError {
    UnsupportedRelation {
        actual: u32,
    },
    BadChunkLength {
        actual: usize,
    },
    BadStepStatement(HistoryCheckpointProofError),
    BadCertificateBatch(AcceptedBlockCertificateBatchError),
    BadCertificateReceipt {
        index: usize,
        source: AcceptedBlockCertificateReceiptError,
    },
    BadCertificateReceiptProjectionHandle {
        index: usize,
        source: AcceptedBlockReceiptProjectionHandleError,
    },
    BadCertificateReceiptProjectionProof {
        index: usize,
        source: AcceptedBlockCertificateProofError,
    },
    BadAcceptedClaimBatchDigest(AcceptedClaimBatchDigestError),
    AcceptedClaimBatchDigestMismatch,
    AcceptedClaimOutputMismatch,
    ComponentShapeMismatch,
    CertificateStatementMismatch {
        index: usize,
    },
    AccumulatorAdvance {
        index: usize,
        source: ChainAccumulatorAdvanceError,
    },
    CoreUnsatisfied {
        row: usize,
    },
    EmptyCoreProof,
    CoreProofTooLarge {
        actual: usize,
        max: usize,
    },
    BadCoreProofPadding,
    BadCoreProofParameters {
        actual_m: usize,
        actual_log_inv_rate: usize,
        actual_log_batch_size: usize,
        actual_profile: LigeritoProfile,
    },
    DecodeCoreProof,
    CoreVerify,
}

impl std::fmt::Display for HistoryCheckpointIvcChunkCoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedRelation { actual } => {
                write!(f, "unsupported checkpoint IVC chunk relation {actual}")
            }
            Self::BadChunkLength { actual } => {
                write!(f, "bad checkpoint IVC chunk length {actual}")
            }
            Self::BadStepStatement(source) => {
                write!(f, "bad checkpoint IVC step statement: {source}")
            }
            Self::BadCertificateBatch(source) => {
                write!(f, "bad checkpoint IVC certificate batch: {source}")
            }
            Self::BadCertificateReceipt { index, source } => {
                write!(
                    f,
                    "bad checkpoint IVC certificate receipt at {index}: {source}"
                )
            }
            Self::BadCertificateReceiptProjectionHandle { index, source } => {
                write!(
                    f,
                    "bad checkpoint IVC certificate receipt projection handle at {index}: {source}"
                )
            }
            Self::BadCertificateReceiptProjectionProof { index, source } => {
                write!(
                    f,
                    "bad checkpoint IVC certificate receipt projection handle proof at {index}: {source}"
                )
            }
            Self::BadAcceptedClaimBatchDigest(source) => {
                write!(f, "bad checkpoint IVC accepted-claim digest: {source}")
            }
            Self::AcceptedClaimBatchDigestMismatch => {
                write!(f, "checkpoint IVC accepted-claim digest mismatch")
            }
            Self::AcceptedClaimOutputMismatch => {
                write!(f, "checkpoint IVC accepted-claim output mismatch")
            }
            Self::ComponentShapeMismatch => write!(f, "checkpoint IVC component shape mismatch"),
            Self::CertificateStatementMismatch { index } => {
                write!(f, "checkpoint IVC certificate mismatch at {index}")
            }
            Self::AccumulatorAdvance { index, source } => {
                write!(
                    f,
                    "checkpoint IVC accumulator advance failed at {index}: {source:?}"
                )
            }
            Self::CoreUnsatisfied { row } => {
                write!(f, "checkpoint IVC core witness does not satisfy row {row}")
            }
            Self::EmptyCoreProof => write!(f, "empty checkpoint IVC core proof"),
            Self::CoreProofTooLarge { actual, max } => {
                write!(f, "checkpoint IVC core proof too large: {actual} > {max}")
            }
            Self::BadCoreProofPadding => write!(f, "bad checkpoint IVC core proof padding"),
            Self::BadCoreProofParameters {
                actual_m,
                actual_log_inv_rate,
                actual_log_batch_size,
                actual_profile,
            } => write!(
                f,
                "bad checkpoint IVC core PCS parameters: m={actual_m}, log_inv_rate={actual_log_inv_rate}, log_batch_size={actual_log_batch_size}, profile={actual_profile:?}"
            ),
            Self::DecodeCoreProof => write!(f, "could not decode checkpoint IVC core proof"),
            Self::CoreVerify => write!(f, "checkpoint IVC core proof rejected"),
        }
    }
}

impl std::error::Error for HistoryCheckpointIvcChunkCoreError {}

pub fn prove_history_checkpoint_ivc_chunk_core(
    statement: &HistoryCheckpointStepStatement,
    certificate_batch_statement: &AcceptedBlockCertificateBatchStatement,
    certificate_statements: &[AcceptedBlockCertificateStatement],
    accepted_claim_witness: &AcceptedClaimBatchWitness,
    accepted_claim_output: &AcceptedClaimBatchOutput,
) -> Result<HistoryCheckpointIvcChunkCoreProof, HistoryCheckpointIvcChunkCoreError> {
    let (receipts, handles) =
        receipts_and_handles_from_certificate_statements(certificate_statements)?;
    let accepted_claim_batch_digest =
        accepted_claim_batch_digest(accepted_claim_witness, accepted_claim_output)
            .map_err(HistoryCheckpointIvcChunkCoreError::BadAcceptedClaimBatchDigest)?;
    let expected_batch_statement = accepted_block_certificate_batch_statement(
        certificate_statements,
        &accepted_claim_witness.accepted_block_claims,
        accepted_claim_batch_digest,
    )
    .map_err(HistoryCheckpointIvcChunkCoreError::BadCertificateBatch)?;
    if &expected_batch_statement != certificate_batch_statement {
        return Err(HistoryCheckpointIvcChunkCoreError::ComponentShapeMismatch);
    }
    prove_history_checkpoint_ivc_chunk_receipt_handle_core(
        statement,
        certificate_batch_statement,
        &handles,
        &receipts,
        accepted_claim_witness,
        accepted_claim_output,
    )
}

pub fn prove_history_checkpoint_ivc_chunk_receipt_handle_core(
    statement: &HistoryCheckpointStepStatement,
    certificate_batch_statement: &AcceptedBlockCertificateBatchStatement,
    certificate_receipt_projection_handles: &[AcceptedBlockReceiptProjectionHandle],
    certificate_receipts: &[AcceptedBlockCertificateReceipt],
    accepted_claim_witness: &AcceptedClaimBatchWitness,
    accepted_claim_output: &AcceptedClaimBatchOutput,
) -> Result<HistoryCheckpointIvcChunkCoreProof, HistoryCheckpointIvcChunkCoreError> {
    let trace = checkpoint_ivc_trace_enabled();
    let mut trace_mark = std::time::Instant::now();
    let accepted_claim_digest_hash_fields =
        accepted_claim_batch_digest_hash_fields(accepted_claim_witness, accepted_claim_output)
            .map_err(HistoryCheckpointIvcChunkCoreError::BadAcceptedClaimBatchDigest)?;
    validate_private_chunk_inputs(
        statement,
        certificate_batch_statement,
        certificate_receipt_projection_handles,
        certificate_receipts,
        accepted_claim_witness,
        accepted_claim_output,
    )?;
    checkpoint_ivc_trace_step(trace, &mut trace_mark, "validate_private");

    let r1cs = build_chunk_core_r1cs(
        statement,
        certificate_batch_statement,
        certificate_receipt_projection_handles,
        certificate_receipts,
    );
    checkpoint_ivc_trace_step(trace, &mut trace_mark, "build_r1cs");
    r1cs.csc_lincheck_circuit();
    checkpoint_ivc_trace_step(trace, &mut trace_mark, "build_csc");
    let witness = chunk_core_witness(
        &statement.batch_summary.start_accumulator,
        certificate_receipts,
        accepted_claim_witness,
    )?;
    checkpoint_ivc_trace_step(trace, &mut trace_mark, "build_witness");
    let assert_r1cs = checkpoint_ivc_assert_r1cs_enabled();
    if assert_r1cs {
        if !r1cs.satisfies(&witness) {
            return Err(HistoryCheckpointIvcChunkCoreError::CoreUnsatisfied {
                row: first_unsatisfied_row(&r1cs, &witness).unwrap_or(usize::MAX),
            });
        }
    }
    checkpoint_ivc_trace_step(trace, &mut trace_mark, "satisfies_bool/assert");
    let z_packed = pack_witness(&witness, r1cs.m);
    checkpoint_ivc_trace_step(trace, &mut trace_mark, "pack_witness");
    if assert_r1cs {
        if !r1cs.satisfies_packed(&z_packed) {
            return Err(HistoryCheckpointIvcChunkCoreError::CoreUnsatisfied {
                row: first_unsatisfied_row(&r1cs, &witness).unwrap_or(usize::MAX),
            });
        }
    }
    checkpoint_ivc_trace_step(trace, &mut trace_mark, "satisfies_packed/assert");

    let _ = noid_ivc_prover::init_perf_thread_pool();
    let pcs_params = chunk_pcs_params();
    let mut challenger = public_challenger(
        statement,
        certificate_batch_statement,
        certificate_receipt_projection_handles,
        certificate_receipts,
    );
    let (proof, commitment, _) =
        noid_ivc_prover::prover::prove(&r1cs, &z_packed, &pcs_params, &mut challenger);
    checkpoint_ivc_trace_step(trace, &mut trace_mark, "prove_r1cs");
    let core_proof = R1csProofBundle { commitment, proof }.to_bytes();
    checkpoint_ivc_trace_step(trace, &mut trace_mark, "serialize_proof");
    let core_proof_len = core_proof.len();
    if core_proof_len > HISTORY_CHECKPOINT_IVC_CHUNK_CORE_WIRE_BYTES {
        return Err(HistoryCheckpointIvcChunkCoreError::CoreProofTooLarge {
            actual: core_proof_len,
            max: HISTORY_CHECKPOINT_IVC_CHUNK_CORE_WIRE_BYTES,
        });
    }
    let mut core_proof_wire = core_proof;
    core_proof_wire.resize(HISTORY_CHECKPOINT_IVC_CHUNK_CORE_WIRE_BYTES, 0);

    Ok(HistoryCheckpointIvcChunkCoreProof {
        relation: HISTORY_CHECKPOINT_IVC_CHUNK_CORE_RELATION,
        chunk_len: statement.batch_summary.batch_len,
        certificate_receipt_projection_handles: certificate_receipt_projection_handles.to_vec(),
        certificate_receipts: certificate_receipts.to_vec(),
        accepted_claim_digest_hash_fields: accepted_claim_digest_hash_fields.to_vec(),
        core_proof_len: core_proof_len.try_into().map_err(|_| {
            HistoryCheckpointIvcChunkCoreError::CoreProofTooLarge {
                actual: core_proof_len,
                max: HISTORY_CHECKPOINT_IVC_CHUNK_CORE_WIRE_BYTES,
            }
        })?,
        core_proof: core_proof_wire,
    })
}

pub fn verify_history_checkpoint_ivc_chunk_core(
    statement: &HistoryCheckpointStepStatement,
    certificate_batch_statement: &AcceptedBlockCertificateBatchStatement,
    proof: &HistoryCheckpointIvcChunkCoreProof,
) -> Result<(), HistoryCheckpointIvcChunkCoreError> {
    let trace = checkpoint_ivc_trace_enabled();
    let mut trace_mark = std::time::Instant::now();
    validate_public_chunk_inputs(statement, certificate_batch_statement)?;
    checkpoint_ivc_trace_step(trace, &mut trace_mark, "verify_public_inputs");
    if proof.relation != HISTORY_CHECKPOINT_IVC_CHUNK_CORE_RELATION {
        return Err(HistoryCheckpointIvcChunkCoreError::UnsupportedRelation {
            actual: proof.relation,
        });
    }
    if proof.chunk_len != statement.batch_summary.batch_len {
        return Err(HistoryCheckpointIvcChunkCoreError::BadChunkLength {
            actual: proof.chunk_len as usize,
        });
    }
    validate_public_certificate_receipt_projection_handles(
        certificate_batch_statement,
        &proof.certificate_receipt_projection_handles,
    )?;
    validate_public_chunk_receipts(certificate_batch_statement, &proof.certificate_receipts)?;
    validate_public_accepted_claim_digest_fields(
        statement,
        &proof.certificate_receipts,
        &proof.accepted_claim_digest_hash_fields,
    )?;
    let core_proof_len = proof.core_proof_len as usize;
    if core_proof_len == 0 {
        return Err(HistoryCheckpointIvcChunkCoreError::EmptyCoreProof);
    }
    if core_proof_len > HISTORY_CHECKPOINT_IVC_CHUNK_CORE_WIRE_BYTES {
        return Err(HistoryCheckpointIvcChunkCoreError::CoreProofTooLarge {
            actual: core_proof_len,
            max: HISTORY_CHECKPOINT_IVC_CHUNK_CORE_WIRE_BYTES,
        });
    }
    if core_proof_len > proof.core_proof.len()
        || proof.core_proof.len() != HISTORY_CHECKPOINT_IVC_CHUNK_CORE_WIRE_BYTES
    {
        return Err(HistoryCheckpointIvcChunkCoreError::CoreProofTooLarge {
            actual: proof.core_proof.len(),
            max: HISTORY_CHECKPOINT_IVC_CHUNK_CORE_WIRE_BYTES,
        });
    }
    if proof.core_proof[core_proof_len..]
        .iter()
        .any(|&byte| byte != 0)
    {
        return Err(HistoryCheckpointIvcChunkCoreError::BadCoreProofPadding);
    }
    let bundle = R1csProofBundle::from_bytes(&proof.core_proof[..core_proof_len])
        .map_err(|_| HistoryCheckpointIvcChunkCoreError::DecodeCoreProof)?;
    validate_core_pcs_params(&bundle.commitment.params)?;
    checkpoint_ivc_trace_step(trace, &mut trace_mark, "decode_proof");
    let r1cs = build_chunk_core_r1cs(
        statement,
        certificate_batch_statement,
        &proof.certificate_receipt_projection_handles,
        &proof.certificate_receipts,
    );
    checkpoint_ivc_trace_step(trace, &mut trace_mark, "build_r1cs");
    let mut challenger = public_challenger(
        statement,
        certificate_batch_statement,
        &proof.certificate_receipt_projection_handles,
        &proof.certificate_receipts,
    );
    noid_ivc_prover::verifier::verify(
        &r1cs,
        &bundle.commitment,
        &bundle.proof,
        r1cs.csc_lincheck_circuit(),
        &mut challenger,
    )
    .map_err(|_| HistoryCheckpointIvcChunkCoreError::CoreVerify)?;
    checkpoint_ivc_trace_step(trace, &mut trace_mark, "verify_r1cs");
    Ok(())
}

fn validate_public_chunk_inputs(
    statement: &HistoryCheckpointStepStatement,
    certificate_batch_statement: &AcceptedBlockCertificateBatchStatement,
) -> Result<usize, HistoryCheckpointIvcChunkCoreError> {
    verify_history_checkpoint_step_statement_native(statement)
        .map_err(HistoryCheckpointIvcChunkCoreError::BadStepStatement)?;
    let chunk_len = statement.batch_summary.batch_len as usize;
    if chunk_len == 0 || chunk_len > CHUNK_CAPACITY {
        return Err(HistoryCheckpointIvcChunkCoreError::BadChunkLength { actual: chunk_len });
    }
    if certificate_batch_statement.batch_len as usize != chunk_len {
        return Err(HistoryCheckpointIvcChunkCoreError::BadChunkLength {
            actual: certificate_batch_statement.batch_len as usize,
        });
    }
    if certificate_batch_statement.accepted_claim_batch_digest
        != statement.batch_summary.accepted_claim_batch_digest
    {
        return Err(HistoryCheckpointIvcChunkCoreError::AcceptedClaimBatchDigestMismatch);
    }
    Ok(chunk_len)
}

fn validate_private_chunk_inputs(
    statement: &HistoryCheckpointStepStatement,
    certificate_batch_statement: &AcceptedBlockCertificateBatchStatement,
    certificate_receipt_projection_handles: &[AcceptedBlockReceiptProjectionHandle],
    certificate_receipts: &[AcceptedBlockCertificateReceipt],
    accepted_claim_witness: &AcceptedClaimBatchWitness,
    accepted_claim_output: &AcceptedClaimBatchOutput,
) -> Result<(), HistoryCheckpointIvcChunkCoreError> {
    let chunk_len = validate_public_chunk_inputs(statement, certificate_batch_statement)?;
    validate_public_certificate_receipt_projection_handles(
        certificate_batch_statement,
        certificate_receipt_projection_handles,
    )?;
    if certificate_receipts.len() != chunk_len {
        return Err(HistoryCheckpointIvcChunkCoreError::BadChunkLength {
            actual: certificate_receipts.len(),
        });
    }
    if accepted_claim_witness.headers.len() != chunk_len
        || accepted_claim_witness.accepted_block_claims.len() != chunk_len
    {
        return Err(HistoryCheckpointIvcChunkCoreError::BadChunkLength {
            actual: accepted_claim_witness.headers.len(),
        });
    }

    let accepted_claim_batch_digest =
        accepted_claim_batch_digest(accepted_claim_witness, accepted_claim_output)
            .map_err(HistoryCheckpointIvcChunkCoreError::BadAcceptedClaimBatchDigest)?;
    if accepted_claim_batch_digest != statement.batch_summary.accepted_claim_batch_digest {
        return Err(HistoryCheckpointIvcChunkCoreError::AcceptedClaimBatchDigestMismatch);
    }
    if accepted_claim_output.consensus_state != statement.batch_summary.end_consensus
        || accepted_claim_output.accumulator != statement.batch_summary.end_accumulator
    {
        return Err(HistoryCheckpointIvcChunkCoreError::AcceptedClaimOutputMismatch);
    }

    let mut accumulator = statement.batch_summary.start_accumulator.clone();
    let mut previous_block_id = accumulator.tip_block_id;
    for (index, (receipt, header_witness)) in certificate_receipts
        .iter()
        .zip(accepted_claim_witness.headers.iter())
        .enumerate()
    {
        if receipt.statement_digest
            != certificate_batch_statement.certificate_statement_digests[index]
            || receipt.height != header_witness.header.height
            || receipt.block_id != header_witness.block_id
            || receipt.parent_block_id != previous_block_id
            || receipt.parent_block_id != header_witness.header.prev_block_hash
            || receipt.parent_state_root != accumulator.state_root
            || receipt.child_state_root != header_witness.header.state_root
            || receipt.tx_root != header_witness.header.tx_root
            || accepted_block_certificate_receipt_chain_claim(receipt)
                != accepted_claim_witness.accepted_block_claims[index]
        {
            return Err(HistoryCheckpointIvcChunkCoreError::CertificateStatementMismatch { index });
        }
        accumulator = accumulator
            .advance(&header_witness.header)
            .map_err(
                |source| HistoryCheckpointIvcChunkCoreError::AccumulatorAdvance { index, source },
            )?;
        previous_block_id = header_witness.block_id;
    }
    if accumulator != accepted_claim_output.accumulator {
        return Err(HistoryCheckpointIvcChunkCoreError::AcceptedClaimOutputMismatch);
    }
    Ok(())
}

fn validate_public_certificate_receipt_projection_handles(
    certificate_batch_statement: &AcceptedBlockCertificateBatchStatement,
    certificate_receipt_projection_handles: &[AcceptedBlockReceiptProjectionHandle],
) -> Result<(), HistoryCheckpointIvcChunkCoreError> {
    let chunk_len = certificate_batch_statement.batch_len as usize;
    if certificate_receipt_projection_handles.len() != chunk_len {
        return Err(HistoryCheckpointIvcChunkCoreError::BadChunkLength {
            actual: certificate_receipt_projection_handles.len(),
        });
    }
    for (index, handle) in certificate_receipt_projection_handles.iter().enumerate() {
        verify_accepted_block_receipt_projection_handle(
            &certificate_batch_statement.certificate_statement_digests[index],
            handle,
        )
        .map_err(|source| {
            HistoryCheckpointIvcChunkCoreError::BadCertificateReceiptProjectionHandle {
                index,
                source,
            }
        })?;
    }
    Ok(())
}

fn validate_public_chunk_receipts(
    certificate_batch_statement: &AcceptedBlockCertificateBatchStatement,
    certificate_receipts: &[AcceptedBlockCertificateReceipt],
) -> Result<(), HistoryCheckpointIvcChunkCoreError> {
    let chunk_len = certificate_batch_statement.batch_len as usize;
    if certificate_receipts.len() != chunk_len {
        return Err(HistoryCheckpointIvcChunkCoreError::BadChunkLength {
            actual: certificate_receipts.len(),
        });
    }
    for (index, receipt) in certificate_receipts.iter().enumerate() {
        if receipt.statement_digest
            != certificate_batch_statement.certificate_statement_digests[index]
        {
            return Err(HistoryCheckpointIvcChunkCoreError::CertificateStatementMismatch { index });
        }
    }
    Ok(())
}

fn validate_public_accepted_claim_digest_fields(
    statement: &HistoryCheckpointStepStatement,
    certificate_receipts: &[AcceptedBlockCertificateReceipt],
    fields: &[Block128],
) -> Result<(), HistoryCheckpointIvcChunkCoreError> {
    if fields.len() != ACCEPTED_CLAIM_BATCH_DIGEST_HASH_FIELDS {
        return Err(
            HistoryCheckpointIvcChunkCoreError::BadAcceptedClaimBatchDigest(
                AcceptedClaimBatchDigestError::DigestFieldCountMismatch {
                    actual: fields.len(),
                },
            ),
        );
    }
    if accepted_claim_batch_digest_from_hash_fields(fields)
        .map_err(HistoryCheckpointIvcChunkCoreError::BadAcceptedClaimBatchDigest)?
        != statement.batch_summary.accepted_claim_batch_digest
    {
        return Err(HistoryCheckpointIvcChunkCoreError::AcceptedClaimBatchDigestMismatch);
    }
    if fields[2] != Block128::from(statement.batch_summary.batch_len as u128)
        || fields[3] != Block128::from(HISTORY_CHECKPOINT_BATCH_TARGET_BLOCKS as u128)
    {
        return Err(HistoryCheckpointIvcChunkCoreError::ComponentShapeMismatch);
    }

    let consensus = &statement.batch_summary.end_consensus;
    let consensus_offset = 4usize;
    if fields[consensus_offset] != Block128::from(consensus.height as u128)
        || fields[consensus_offset + 1..consensus_offset + 3] != digest_fields(&consensus.block_id)
        || fields[consensus_offset + 3..consensus_offset + 5]
            != digest_fields(&consensus.state_root)
    {
        return Err(HistoryCheckpointIvcChunkCoreError::AcceptedClaimOutputMismatch);
    }

    let accumulator = &statement.batch_summary.end_accumulator;
    let accumulator_offset = 4 + ACCEPTED_CLAIM_BATCH_DIGEST_CONSENSUS_FIELDS;
    if fields
        [accumulator_offset..accumulator_offset + ACCEPTED_CLAIM_BATCH_DIGEST_ACCUMULATOR_FIELDS]
        != accumulator.to_lanes()
    {
        return Err(HistoryCheckpointIvcChunkCoreError::AcceptedClaimOutputMismatch);
    }

    let slots_offset = accumulator_offset + ACCEPTED_CLAIM_BATCH_DIGEST_ACCUMULATOR_FIELDS;
    validate_public_direct_accumulator_transition(
        statement,
        certificate_receipts,
        fields,
        slots_offset,
    )?;
    for (index, receipt) in certificate_receipts.iter().enumerate() {
        let slot_offset = slots_offset + index * ACCEPTED_CLAIM_BATCH_DIGEST_SLOT_FIELDS;
        let block_id_offset = slot_offset + ACCEPTED_CLAIM_BATCH_DIGEST_HEADER_WITNESS_FIELDS - 4;
        let claim_offset = slot_offset + ACCEPTED_CLAIM_BATCH_DIGEST_HEADER_WITNESS_FIELDS;
        if fields[block_id_offset..block_id_offset + 2] != digest_fields(&receipt.block_id)
            || fields[claim_offset..claim_offset + ACCEPTED_CLAIM_BATCH_DIGEST_CLAIM_FIELDS]
                != digest_fields(&receipt.accepted_block_claim_digest)
        {
            return Err(HistoryCheckpointIvcChunkCoreError::CertificateStatementMismatch { index });
        }
    }
    Ok(())
}

/// Public-verifier twin of the final direct accumulator relation.
///
/// The fixed accepted-claim digest preimage already carries every canonical
/// header field. Reconstructing and verifying those headers here binds all ten
/// accumulator lanes, including log/counters/epoch, instead of trusting the
/// prover-side native replay. The batch is capped at sixteen, so this remains
/// constant verifier work independent of chain length.
fn validate_public_direct_accumulator_transition(
    statement: &HistoryCheckpointStepStatement,
    certificate_receipts: &[AcceptedBlockCertificateReceipt],
    fields: &[Block128],
    slots_offset: usize,
) -> Result<(), HistoryCheckpointIvcChunkCoreError> {
    let mut accumulator = statement.batch_summary.start_accumulator.clone();
    for (index, receipt) in certificate_receipts.iter().enumerate() {
        let slot = slots_offset + index * ACCEPTED_CLAIM_BATCH_DIGEST_SLOT_FIELDS;
        let pow_fields: [Block128; noid_chain::consensus::pow::POW_HEADER_FIELD_COUNT] = fields
            [slot..slot + noid_chain::consensus::pow::POW_HEADER_FIELD_COUNT]
            .try_into()
            .expect("accepted-claim header schedule has a fixed width");
        let digests = slot + noid_chain::consensus::pow::POW_HEADER_FIELD_COUNT;
        let pow_digest = digest_from_field_pair(&fields[digests..digests + 2]);
        let block_id = digest_from_field_pair(&fields[digests + 2..digests + 4]);
        let target = digest_from_field_pair(&fields[digests + 4..digests + 6]);
        let header = block_header_from_pow_fields(&pow_fields)
            .ok_or(HistoryCheckpointIvcChunkCoreError::CertificateStatementMismatch { index })?;
        let witness = HeaderWitness {
            header,
            pow_fields,
            pow_digest,
            block_id,
            target,
        };
        witness.verify().map_err(|_| {
            HistoryCheckpointIvcChunkCoreError::CertificateStatementMismatch { index }
        })?;
        if receipt.height != witness.header.height
            || receipt.block_id != witness.block_id
            || receipt.parent_block_id != witness.header.prev_block_hash
            || receipt.parent_block_id != accumulator.tip_block_id
            || receipt.parent_state_root != accumulator.state_root
            || receipt.child_state_root != witness.header.state_root
            || receipt.tx_root != witness.header.tx_root
        {
            return Err(HistoryCheckpointIvcChunkCoreError::CertificateStatementMismatch { index });
        }
        accumulator = accumulator.advance(&witness.header).map_err(|source| {
            HistoryCheckpointIvcChunkCoreError::AccumulatorAdvance { index, source }
        })?;
    }
    if accumulator != statement.batch_summary.end_accumulator {
        return Err(HistoryCheckpointIvcChunkCoreError::AcceptedClaimOutputMismatch);
    }
    Ok(())
}

fn block_header_from_pow_fields(
    fields: &[Block128; noid_chain::consensus::pow::POW_HEADER_FIELD_COUNT],
) -> Option<BlockHeader> {
    // The reserved pad lane must be zero: a nonzero pad would admit two field
    // schedules for one semantic header.
    if fields[17].to_u128() != 0 {
        return None;
    }
    Some(BlockHeader {
        prev_block_hash: digest_from_field_pair(&fields[0..2]),
        state_root: digest_from_field_pair(&fields[2..4]),
        tx_root: digest_from_field_pair(&fields[4..6]),
        timestamp: u64::try_from(fields[6].to_u128()).ok()?,
        height: u64::try_from(fields[7].to_u128()).ok()?,
        miner_address: Address(digest_from_field_pair(&fields[8..10])),
        nonce: fields[10].to_u128(),
        difficulty_target: digest_from_field_pair(&fields[11..13]),
        log_slots: u32::try_from(fields[13].to_u128()).ok()?,
        active_slot_count: u64::try_from(fields[14].to_u128()).ok()?,
        alloc_counter: u64::try_from(fields[15].to_u128()).ok()?,
        attested_coverage: u64::try_from(fields[16].to_u128()).ok()?,
    })
}

fn digest_from_field_pair(fields: &[Block128]) -> Digest {
    debug_assert_eq!(fields.len(), 2);
    let mut digest = [0u8; 32];
    digest[..16].copy_from_slice(&fields[0].to_u128().to_le_bytes());
    digest[16..].copy_from_slice(&fields[1].to_u128().to_le_bytes());
    digest
}

fn build_chunk_core_r1cs(
    statement: &HistoryCheckpointStepStatement,
    certificate_batch_statement: &AcceptedBlockCertificateBatchStatement,
    certificate_receipt_projection_handles: &[AcceptedBlockReceiptProjectionHandle],
    certificate_receipts: &[AcceptedBlockCertificateReceipt],
) -> BlockR1cs {
    let k = 1usize << CHUNK_K_LOG;
    let mut a_rows = vec![Vec::<usize>::new(); k];
    let mut b_rows = vec![Vec::<usize>::new(); k];
    let c_rows = (0..k).map(|i| vec![i]).collect::<Vec<_>>();

    set_equals_one_at(&mut a_rows, &mut b_rows, CONST_ONE, CONST_ONE);
    let chunk_len = statement.batch_summary.batch_len as usize;
    for index in 0..chunk_len {
        constrain_slot(&mut a_rows, &mut b_rows, slot_base(index));
        pin_digest(
            &mut a_rows,
            &mut b_rows,
            slot_base(index) + CERT_STATEMENT_DIGEST,
            &certificate_batch_statement.certificate_statement_digests[index],
        );
        if let Some(receipt) = certificate_receipts.get(index) {
            pin_u64(
                &mut a_rows,
                &mut b_rows,
                slot_base(index) + CERT_HEIGHT,
                receipt.height,
            );
            pin_digest(
                &mut a_rows,
                &mut b_rows,
                slot_base(index) + CERT_PARENT_STATE,
                &receipt.parent_state_root,
            );
            pin_digest(
                &mut a_rows,
                &mut b_rows,
                slot_base(index) + CERT_CHILD_STATE,
                &receipt.child_state_root,
            );
            pin_digest(
                &mut a_rows,
                &mut b_rows,
                slot_base(index) + CERT_PARENT_BLOCK,
                &receipt.parent_block_id,
            );
            pin_digest(
                &mut a_rows,
                &mut b_rows,
                slot_base(index) + CERT_BLOCK,
                &receipt.block_id,
            );
            pin_digest(
                &mut a_rows,
                &mut b_rows,
                slot_base(index) + CERT_CLAIM_DIGEST,
                &receipt.accepted_block_claim_digest,
            );
        }
    }
    pin_u64(
        &mut a_rows,
        &mut b_rows,
        slot_base(0) + PREV_HEIGHT,
        statement.batch_summary.start_accumulator.height,
    );
    pin_digest(
        &mut a_rows,
        &mut b_rows,
        slot_base(0) + PREV_STATE,
        &statement.batch_summary.start_accumulator.state_root,
    );
    pin_digest(
        &mut a_rows,
        &mut b_rows,
        slot_base(0) + PREV_BLOCK,
        &statement.batch_summary.start_accumulator.tip_block_id,
    );
    let last = slot_base(chunk_len - 1);
    pin_u64(
        &mut a_rows,
        &mut b_rows,
        last + NEXT_HEIGHT,
        statement.batch_summary.end_accumulator.height,
    );
    pin_digest(
        &mut a_rows,
        &mut b_rows,
        last + NEXT_STATE,
        &statement.batch_summary.end_accumulator.state_root,
    );
    pin_digest(
        &mut a_rows,
        &mut b_rows,
        last + HEADER_BLOCK,
        &statement.batch_summary.end_accumulator.tip_block_id,
    );

    let digest_cache = std::sync::OnceLock::new();
    digest_cache
        .set(chunk_core_r1cs_statement_digest(
            statement,
            certificate_batch_statement,
            certificate_receipt_projection_handles,
            certificate_receipts,
        ))
        .expect("fresh R1CS digest cache accepts compact statement digest");

    BlockR1cs {
        m: CHUNK_M,
        k_log: CHUNK_K_LOG,
        k_skip: 6,
        useful_bits: CHUNK_BITS,
        a_0: SparseBinaryMatrix {
            num_rows: k,
            num_cols: k,
            rows: a_rows,
        },
        b_0: SparseBinaryMatrix {
            num_rows: k,
            num_cols: k,
            rows: b_rows,
        },
        c_0: SparseBinaryMatrix {
            num_rows: k,
            num_cols: k,
            rows: c_rows,
        },
        const_pin: Some(CONST_ONE),
        digest_cache,
        csc_cache: std::sync::OnceLock::new(),
    }
}

fn chunk_core_r1cs_statement_digest(
    statement: &HistoryCheckpointStepStatement,
    certificate_batch_statement: &AcceptedBlockCertificateBatchStatement,
    certificate_receipt_projection_handles: &[AcceptedBlockReceiptProjectionHandle],
    certificate_receipts: &[AcceptedBlockCertificateReceipt],
) -> Digest {
    let constants = [
        HISTORY_CHECKPOINT_IVC_CHUNK_CORE_RELATION as u64,
        CHUNK_CAPACITY as u64,
        CHUNK_M as u64,
        CHUNK_K_LOG as u64,
        6u64,
        SLOT_BITS as u64,
        SLOT_USEFUL_BITS as u64,
    ];
    let mut constants_bytes = Vec::with_capacity(constants.len() * 8);
    for value in constants {
        constants_bytes.extend_from_slice(&value.to_le_bytes());
    }
    let statement_bytes =
        bincode::serialize(statement).expect("HistoryCheckpointStepStatement serializes");
    let certificate_bytes = bincode::serialize(certificate_batch_statement)
        .expect("AcceptedBlockCertificateBatchStatement serializes");
    let handle_bytes = bincode::serialize(certificate_receipt_projection_handles)
        .expect("certificate receipt projection handles serialize");
    let receipt_bytes =
        bincode::serialize(certificate_receipts).expect("certificate receipts serialize");
    poseidon2b_hash_byte_slices(
        STATEMENT_DIGEST_DOMAIN,
        &[
            &constants_bytes,
            &statement_bytes,
            &certificate_bytes,
            &handle_bytes,
            &receipt_bytes,
        ],
    )
}

fn constrain_slot(a_rows: &mut [Vec<usize>], b_rows: &mut [Vec<usize>], base: usize) {
    free_range(a_rows, b_rows, base + PREV_HEIGHT, 64);
    free_range(a_rows, b_rows, base + PREV_STATE, 256);
    free_range(a_rows, b_rows, base + PREV_BLOCK, 256);
    free_range(a_rows, b_rows, base + CERT_CHILD_STATE, 256);
    free_range(a_rows, b_rows, base + HEADER_BLOCK, 256);
    free_range(a_rows, b_rows, base + CLAIM_WITNESS, 256);
    free_range(a_rows, b_rows, base + CERT_STATEMENT_DIGEST, 256);
    free_range(a_rows, b_rows, base + CERT_CLAIM_DIGEST, 256);

    constrain_increment_u64(
        a_rows,
        b_rows,
        base + PREV_HEIGHT,
        base + NEXT_HEIGHT,
        base + HEIGHT_CARRY,
    );
    constrain_equal_range(a_rows, b_rows, base + NEXT_HEIGHT, base + CERT_HEIGHT, 64);
    constrain_equal_range(a_rows, b_rows, base + NEXT_HEIGHT, base + HEADER_HEIGHT, 64);
    constrain_equal_range(
        a_rows,
        b_rows,
        base + PREV_STATE,
        base + CERT_PARENT_STATE,
        256,
    );
    constrain_equal_range(
        a_rows,
        b_rows,
        base + CERT_CHILD_STATE,
        base + HEADER_STATE,
        256,
    );
    constrain_equal_range(
        a_rows,
        b_rows,
        base + CERT_CHILD_STATE,
        base + NEXT_STATE,
        256,
    );
    constrain_equal_range(
        a_rows,
        b_rows,
        base + PREV_BLOCK,
        base + HEADER_PREV_BLOCK,
        256,
    );
    constrain_equal_range(
        a_rows,
        b_rows,
        base + PREV_BLOCK,
        base + CERT_PARENT_BLOCK,
        256,
    );
    constrain_equal_range(a_rows, b_rows, base + HEADER_BLOCK, base + CERT_BLOCK, 256);
    constrain_equal_range(
        a_rows,
        b_rows,
        base + CLAIM_WITNESS,
        base + CERT_CLAIM_DIGEST,
        256,
    );
}

fn chunk_core_witness(
    start_accumulator: &ChainAccumulator,
    certificate_receipts: &[AcceptedBlockCertificateReceipt],
    accepted_claim_witness: &AcceptedClaimBatchWitness,
) -> Result<Vec<bool>, HistoryCheckpointIvcChunkCoreError> {
    let mut witness = vec![false; 1usize << CHUNK_M];
    witness[CONST_ONE] = true;

    let mut accumulator = start_accumulator.clone();
    let mut previous_block_id = certificate_receipts[0].parent_block_id;
    for index in 0..certificate_receipts.len() {
        let base = slot_base(index);
        let receipt = &certificate_receipts[index];
        let header_witness = &accepted_claim_witness.headers[index];
        let claim = accepted_claim_witness.accepted_block_claims[index];
        let next_accumulator = accumulator
            .advance(&header_witness.header)
            .map_err(
                |source| HistoryCheckpointIvcChunkCoreError::AccumulatorAdvance { index, source },
            )?;

        write_u64_bits(&mut witness, base + PREV_HEIGHT, accumulator.height);
        write_u64_bits(&mut witness, base + CERT_HEIGHT, receipt.height);
        write_u64_bits(
            &mut witness,
            base + HEADER_HEIGHT,
            header_witness.header.height,
        );
        write_u64_bits(&mut witness, base + NEXT_HEIGHT, next_accumulator.height);
        write_increment_carries(&mut witness, base + HEIGHT_CARRY, accumulator.height);
        write_digest_bits(&mut witness, base + PREV_STATE, &accumulator.state_root);
        write_digest_bits(
            &mut witness,
            base + CERT_PARENT_STATE,
            &receipt.parent_state_root,
        );
        write_digest_bits(
            &mut witness,
            base + CERT_CHILD_STATE,
            &receipt.child_state_root,
        );
        write_digest_bits(
            &mut witness,
            base + HEADER_STATE,
            &header_witness.header.state_root,
        );
        write_digest_bits(
            &mut witness,
            base + NEXT_STATE,
            &next_accumulator.state_root,
        );
        write_digest_bits(&mut witness, base + PREV_BLOCK, &previous_block_id);
        write_digest_bits(
            &mut witness,
            base + HEADER_PREV_BLOCK,
            &header_witness.header.prev_block_hash,
        );
        write_digest_bits(
            &mut witness,
            base + CERT_PARENT_BLOCK,
            &receipt.parent_block_id,
        );
        write_digest_bits(&mut witness, base + HEADER_BLOCK, &header_witness.block_id);
        write_digest_bits(&mut witness, base + CERT_BLOCK, &receipt.block_id);
        write_block128_pair_bits(&mut witness, base + CLAIM_WITNESS, claim);
        write_digest_bits(
            &mut witness,
            base + CERT_CLAIM_DIGEST,
            &receipt.accepted_block_claim_digest,
        );
        write_digest_bits(
            &mut witness,
            base + CERT_STATEMENT_DIGEST,
            &receipt.statement_digest,
        );

        accumulator = next_accumulator;
        previous_block_id = header_witness.block_id;
    }
    Ok(witness)
}

fn receipts_and_handles_from_certificate_statements(
    certificate_statements: &[AcceptedBlockCertificateStatement],
) -> Result<
    (
        Vec<AcceptedBlockCertificateReceipt>,
        Vec<AcceptedBlockReceiptProjectionHandle>,
    ),
    HistoryCheckpointIvcChunkCoreError,
> {
    certificate_statements
        .iter()
        .enumerate()
        .map(|(index, statement)| {
            let receipt = accepted_block_certificate_receipt(statement);
            verify_accepted_block_certificate_receipt_projection(statement, &receipt).map_err(
                |source| HistoryCheckpointIvcChunkCoreError::BadCertificateReceipt {
                    index,
                    source,
                },
            )?;
            let proof = prove_accepted_block_certificate_receipt_projection_proof(statement)
                .map_err(|source| {
                    HistoryCheckpointIvcChunkCoreError::BadCertificateReceiptProjectionProof {
                        index,
                        source,
                    }
                })?;
            let handle = accepted_block_receipt_projection_handle(&proof).map_err(|source| {
                HistoryCheckpointIvcChunkCoreError::BadCertificateReceiptProjectionHandle {
                    index,
                    source,
                }
            })?;
            Ok((receipt, handle))
        })
        .collect::<Result<Vec<_>, _>>()
        .map(|pairs| pairs.into_iter().unzip())
}

fn public_challenger(
    statement: &HistoryCheckpointStepStatement,
    certificate_batch_statement: &AcceptedBlockCertificateBatchStatement,
    certificate_receipt_projection_handles: &[AcceptedBlockReceiptProjectionHandle],
    certificate_receipts: &[AcceptedBlockCertificateReceipt],
) -> FsChallenger {
    let mut challenger = FsChallenger::new(TRANSCRIPT_DOMAIN);
    challenger.observe_label(b"checkpoint-ivc-public");
    let statement_bytes =
        bincode::serialize(statement).expect("HistoryCheckpointStepStatement serializes");
    let certificate_bytes = bincode::serialize(certificate_batch_statement)
        .expect("AcceptedBlockCertificateBatchStatement serializes");
    let handle_bytes = bincode::serialize(certificate_receipt_projection_handles)
        .expect("certificate receipt projection handles serialize");
    let receipt_bytes =
        bincode::serialize(certificate_receipts).expect("certificate receipts serialize");
    challenger.observe_bytes(&statement_bytes);
    challenger.observe_bytes(&certificate_bytes);
    challenger.observe_bytes(&handle_bytes);
    challenger.observe_bytes(&receipt_bytes);
    challenger
}

fn checkpoint_ivc_trace_enabled() -> bool {
    std::env::var_os("CHECKPOINT_IVC_TRACE").is_some()
}

fn checkpoint_ivc_assert_r1cs_enabled() -> bool {
    cfg!(debug_assertions) || std::env::var_os("CHECKPOINT_IVC_ASSERT_R1CS").is_some()
}

fn checkpoint_ivc_trace_step(trace: bool, mark: &mut std::time::Instant, label: &str) {
    if trace {
        eprintln!(
            "  [checkpoint_ivc] {label:<24} {:>8.2} ms",
            mark.elapsed().as_secs_f64() * 1000.0
        );
        *mark = std::time::Instant::now();
    }
}

fn chunk_pcs_params() -> PcsParams {
    PcsParams {
        m: CHUNK_M,
        log_inv_rate: HISTORY_CHECKPOINT_IVC_PCS_LOG_INV_RATE,
        log_batch_size: HISTORY_CHECKPOINT_IVC_PCS_LOG_BATCH_SIZE,
        profile: LigeritoProfile::Fast,
    }
}

fn validate_core_pcs_params(params: &PcsParams) -> Result<(), HistoryCheckpointIvcChunkCoreError> {
    if params.m == CHUNK_M
        && params.log_inv_rate == HISTORY_CHECKPOINT_IVC_PCS_LOG_INV_RATE
        && params.log_batch_size == HISTORY_CHECKPOINT_IVC_PCS_LOG_BATCH_SIZE
        && params.profile == LigeritoProfile::Fast
    {
        Ok(())
    } else {
        Err(HistoryCheckpointIvcChunkCoreError::BadCoreProofParameters {
            actual_m: params.m,
            actual_log_inv_rate: params.log_inv_rate,
            actual_log_batch_size: params.log_batch_size,
            actual_profile: params.profile,
        })
    }
}

fn first_unsatisfied_row(r1cs: &BlockR1cs, witness: &[bool]) -> Option<usize> {
    let a = r1cs.apply_a(witness);
    let b = r1cs.apply_b(witness);
    let c = r1cs.apply_c(witness);
    a.iter()
        .zip(b.iter())
        .zip(c.iter())
        .position(|((a_bit, b_bit), c_bit)| (*a_bit & *b_bit) != *c_bit)
}

fn slot_base(index: usize) -> usize {
    debug_assert!(index < CHUNK_CAPACITY);
    index * SLOT_BITS
}

fn set_equals_one_at(
    a_rows: &mut [Vec<usize>],
    b_rows: &mut [Vec<usize>],
    const_one: usize,
    row: usize,
) {
    a_rows[row] = vec![const_one];
    b_rows[row] = vec![const_one];
}

fn set_equals_public_bit_at(
    a_rows: &mut [Vec<usize>],
    b_rows: &mut [Vec<usize>],
    row: usize,
    bit: bool,
) {
    if bit {
        set_equals_one_at(a_rows, b_rows, CONST_ONE, row);
    } else {
        a_rows[row].clear();
        b_rows[row] = vec![CONST_ONE];
    }
}

fn set_equals_wire_at(
    a_rows: &mut [Vec<usize>],
    b_rows: &mut [Vec<usize>],
    row: usize,
    wire: usize,
) {
    a_rows[row] = vec![wire];
    b_rows[row] = vec![CONST_ONE];
}

fn free_range(a_rows: &mut [Vec<usize>], b_rows: &mut [Vec<usize>], offset: usize, len: usize) {
    for bit in 0..len {
        set_equals_wire_at(a_rows, b_rows, offset + bit, offset + bit);
    }
}

fn constrain_equal_range(
    a_rows: &mut [Vec<usize>],
    b_rows: &mut [Vec<usize>],
    left: usize,
    right: usize,
    len: usize,
) {
    for bit in 0..len {
        set_equals_wire_at(a_rows, b_rows, right + bit, left + bit);
    }
}

fn constrain_increment_u64(
    a_rows: &mut [Vec<usize>],
    b_rows: &mut [Vec<usize>],
    input: usize,
    output: usize,
    carry: usize,
) {
    a_rows[output] = vec![input, CONST_ONE];
    b_rows[output] = vec![CONST_ONE];
    set_equals_wire_at(a_rows, b_rows, carry, input);

    for bit in 1..64 {
        let carry_prev = carry + bit - 1;
        let carry_cur = carry + bit;
        a_rows[output + bit] = vec![input + bit, carry_prev];
        b_rows[output + bit] = vec![CONST_ONE];
        a_rows[carry_cur] = vec![input + bit];
        b_rows[carry_cur] = vec![carry_prev];
    }
}

fn pin_u64(a_rows: &mut [Vec<usize>], b_rows: &mut [Vec<usize>], offset: usize, value: u64) {
    for bit in 0..64 {
        set_equals_public_bit_at(a_rows, b_rows, offset + bit, (value >> bit) & 1 == 1);
    }
}

fn pin_digest(
    a_rows: &mut [Vec<usize>],
    b_rows: &mut [Vec<usize>],
    offset: usize,
    digest: &Digest,
) {
    let bits = digest_bits_le(digest);
    for (bit, value) in bits.iter().copied().enumerate() {
        set_equals_public_bit_at(a_rows, b_rows, offset + bit, value);
    }
}

fn digest_bits_le(digest: &Digest) -> [bool; 256] {
    let mut out = [false; 256];
    for (byte_index, byte) in digest.iter().enumerate() {
        for bit in 0..8 {
            out[byte_index * 8 + bit] = (byte >> bit) & 1 == 1;
        }
    }
    out
}

fn digest_fields(digest: &Digest) -> [Block128; 2] {
    [
        Block128::from(u128::from_le_bytes(digest[..16].try_into().unwrap())),
        Block128::from(u128::from_le_bytes(digest[16..].try_into().unwrap())),
    ]
}

fn block128_bits_le(value: Block128) -> [bool; 128] {
    let raw = value.to_u128();
    let mut out = [false; 128];
    for (bit, out_bit) in out.iter_mut().enumerate() {
        *out_bit = (raw >> bit) & 1 == 1;
    }
    out
}

fn write_digest_bits(witness: &mut [bool], offset: usize, digest: &Digest) {
    witness[offset..offset + 256].copy_from_slice(&digest_bits_le(digest));
}

fn write_block128_pair_bits(witness: &mut [bool], offset: usize, pair: [Block128; 2]) {
    witness[offset..offset + 128].copy_from_slice(&block128_bits_le(pair[0]));
    witness[offset + 128..offset + 256].copy_from_slice(&block128_bits_le(pair[1]));
}

fn write_u64_bits(witness: &mut [bool], offset: usize, value: u64) {
    for bit in 0..64 {
        witness[offset + bit] = (value >> bit) & 1 == 1;
    }
}

fn write_increment_carries(witness: &mut [bool], offset: usize, value: u64) {
    let mut carry = true;
    for bit in 0..64 {
        let input_bit = (value >> bit) & 1 == 1;
        carry &= input_bit;
        witness[offset + bit] = carry;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use noid_chain::consensus::difficulty::{add_work, block_work};
    use noid_chain::consensus::params::{BLOCK_TIME, MAX_TARGET};
    use noid_chain::consensus::{genesis_header, GENESIS_TIMESTAMP};
    use noid_chain::header_anchor::HeaderChainAnchor;
    use noid_poseidon2b::primitives::Address;

    use crate::checkpoint_proof::{
        advance_history_checkpoint_head_native, history_checkpoint_head_from_boundary,
        HistoryCheckpointBatchSummary, HISTORY_CHECKPOINT_ENGINE_STREAMING_TOWER_IVC,
    };
    use crate::pow_header::{HeaderWitness, RecursiveConsensusState};

    #[test]
    fn checkpoint_ivc_chunk_core_roundtrips_and_binds_public_boundary() {
        let fixture = chunk_fixture();
        let proof = prove_history_checkpoint_ivc_chunk_core(
            &fixture.statement,
            &fixture.certificate_batch_statement,
            &fixture.certificate_statements,
            &fixture.accepted_claim_witness,
            &fixture.accepted_claim_output,
        )
        .expect("prove chunk core");
        verify_history_checkpoint_ivc_chunk_core(
            &fixture.statement,
            &fixture.certificate_batch_statement,
            &proof,
        )
        .expect("verify chunk core");

        let mut tampered = fixture.statement.clone();
        tampered.batch_summary.end_accumulator.state_root[0] ^= 1;
        assert!(matches!(
            verify_history_checkpoint_ivc_chunk_core(
                &tampered,
                &fixture.certificate_batch_statement,
                &proof,
            ),
            Err(HistoryCheckpointIvcChunkCoreError::BadStepStatement(_))
                | Err(HistoryCheckpointIvcChunkCoreError::CoreVerify)
        ));

        let mut bad_receipt_digest = proof.clone();
        bad_receipt_digest.certificate_receipts[0].statement_digest[0] ^= 1;
        assert!(matches!(
            verify_history_checkpoint_ivc_chunk_core(
                &fixture.statement,
                &fixture.certificate_batch_statement,
                &bad_receipt_digest,
            ),
            Err(HistoryCheckpointIvcChunkCoreError::CertificateStatementMismatch { index: 0 })
        ));

        let mut bad_handle_digest = proof.clone();
        bad_handle_digest.certificate_receipt_projection_handles[0].statement_digest[0] ^= 1;
        assert!(matches!(
            verify_history_checkpoint_ivc_chunk_core(
                &fixture.statement,
                &fixture.certificate_batch_statement,
                &bad_handle_digest,
            ),
            Err(
                HistoryCheckpointIvcChunkCoreError::BadCertificateReceiptProjectionHandle {
                    index: 0,
                    ..
                }
            )
        ));

        let mut bad_handle_proof_digest = proof.clone();
        bad_handle_proof_digest.certificate_receipt_projection_handles[0].proof_digest = [0u8; 32];
        assert!(matches!(
            verify_history_checkpoint_ivc_chunk_core(
                &fixture.statement,
                &fixture.certificate_batch_statement,
                &bad_handle_proof_digest,
            ),
            Err(
                HistoryCheckpointIvcChunkCoreError::BadCertificateReceiptProjectionHandle {
                    index: 0,
                    ..
                }
            )
        ));

        let mut bad_receipt_projection = proof.clone();
        bad_receipt_projection.certificate_receipts[0].child_state_root[0] ^= 1;
        assert!(matches!(
            verify_history_checkpoint_ivc_chunk_core(
                &fixture.statement,
                &fixture.certificate_batch_statement,
                &bad_receipt_projection,
            ),
            Err(HistoryCheckpointIvcChunkCoreError::CertificateStatementMismatch { index: 0 })
        ));

        let mut bad_digest_fields = proof;
        bad_digest_fields.accepted_claim_digest_hash_fields[3] += Block128::from(1u128);
        assert!(matches!(
            verify_history_checkpoint_ivc_chunk_core(
                &fixture.statement,
                &fixture.certificate_batch_statement,
                &bad_digest_fields,
            ),
            Err(
                HistoryCheckpointIvcChunkCoreError::BadAcceptedClaimBatchDigest(
                    AcceptedClaimBatchDigestError::NonCanonicalHeader
                )
            )
        ));

        let mut bad_pcs_params = prove_history_checkpoint_ivc_chunk_core(
            &fixture.statement,
            &fixture.certificate_batch_statement,
            &fixture.certificate_statements,
            &fixture.accepted_claim_witness,
            &fixture.accepted_claim_output,
        )
        .expect("prove chunk core");
        let mut bundle = R1csProofBundle::from_bytes(
            &bad_pcs_params.core_proof[..bad_pcs_params.core_proof_len as usize],
        )
        .expect("decode core bundle");
        bundle.commitment.params.log_inv_rate = 1;
        let encoded = bundle.to_bytes();
        bad_pcs_params.core_proof_len = encoded.len() as u32;
        bad_pcs_params.core_proof = encoded;
        bad_pcs_params
            .core_proof
            .resize(HISTORY_CHECKPOINT_IVC_CHUNK_CORE_WIRE_BYTES, 0);
        assert!(matches!(
            verify_history_checkpoint_ivc_chunk_core(
                &fixture.statement,
                &fixture.certificate_batch_statement,
                &bad_pcs_params,
            ),
            Err(HistoryCheckpointIvcChunkCoreError::BadCoreProofParameters { .. })
        ));
    }

    #[test]
    fn checkpoint_ivc_chunk_core_accepts_short_chunk() {
        let fixture = chunk_fixture_with_len(1);
        let proof = prove_history_checkpoint_ivc_chunk_core(
            &fixture.statement,
            &fixture.certificate_batch_statement,
            &fixture.certificate_statements,
            &fixture.accepted_claim_witness,
            &fixture.accepted_claim_output,
        )
        .expect("prove short chunk core");
        assert_eq!(proof.chunk_len, 1);
        assert_eq!(proof.certificate_receipts.len(), 1);
        assert_eq!(proof.certificate_receipt_projection_handles.len(), 1);
        verify_history_checkpoint_ivc_chunk_core(
            &fixture.statement,
            &fixture.certificate_batch_statement,
            &proof,
        )
        .expect("verify short chunk core");
    }

    #[test]
    fn public_direct_accumulator_validator_binds_all_ten_end_lanes() {
        let fixture = chunk_fixture_with_len(1);
        let fields = accepted_claim_batch_digest_hash_fields(
            &fixture.accepted_claim_witness,
            &fixture.accepted_claim_output,
        )
        .expect("canonical accepted-claim fields");
        let receipts = fixture
            .certificate_statements
            .iter()
            .map(accepted_block_certificate_receipt)
            .collect::<Vec<_>>();
        let slots_offset = 4
            + ACCEPTED_CLAIM_BATCH_DIGEST_CONSENSUS_FIELDS
            + ACCEPTED_CLAIM_BATCH_DIGEST_ACCUMULATOR_FIELDS;
        validate_public_direct_accumulator_transition(
            &fixture.statement,
            &receipts,
            &fields,
            slots_offset,
        )
        .expect("honest direct accumulator transition");

        for lane in 0..crate::accumulator::CHAIN_ACCUMULATOR_LANES {
            let mut bad = fixture.statement.clone();
            let mut lanes = bad.batch_summary.end_accumulator.to_lanes();
            lanes[lane] += Block128::from(1u128);
            bad.batch_summary.end_accumulator = ChainAccumulator::from_lanes(lanes).unwrap();
            assert!(
                matches!(
                    validate_public_direct_accumulator_transition(
                        &bad,
                        &receipts,
                        &fields,
                        slots_offset,
                    ),
                    Err(HistoryCheckpointIvcChunkCoreError::AcceptedClaimOutputMismatch)
                ),
                "end accumulator lane {lane} was not transition-bound"
            );
        }
    }

    struct ChunkFixture {
        statement: HistoryCheckpointStepStatement,
        certificate_batch_statement: AcceptedBlockCertificateBatchStatement,
        certificate_statements: Vec<AcceptedBlockCertificateStatement>,
        accepted_claim_witness: AcceptedClaimBatchWitness,
        accepted_claim_output: AcceptedClaimBatchOutput,
    }

    fn chunk_fixture() -> ChunkFixture {
        chunk_fixture_with_len(CHUNK_CAPACITY)
    }

    fn chunk_fixture_with_len(chunk_len: usize) -> ChunkFixture {
        assert!((1..=CHUNK_CAPACITY).contains(&chunk_len));
        let start_header = genesis_header();
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
        let start_accumulator = crate::accumulator::genesis_accumulator();
        let start_anchor = noid_chain::header_anchor::compute_header_chain_anchor(
            std::iter::once(&start_header),
            start_consensus.cumulative_chainwork,
        )
        .expect("canonical genesis anchor");

        let mut accumulator = start_accumulator.clone();
        let mut previous_block_id = start_consensus.block_id;
        let mut headers = Vec::with_capacity(chunk_len);
        let mut claims = Vec::with_capacity(chunk_len);
        let mut certificate_statements = Vec::with_capacity(chunk_len);
        for index in 0..chunk_len {
            let height = accumulator.height + 1;
            let state_seed = (index as u8).wrapping_add(2);
            let header = test_header(previous_block_id, [state_seed; 32], height);
            let header_witness = HeaderWitness::from_header(&header);
            let accepted_block_claim_digest = digest_with_seed(0x80 | index as u8);
            let claim = digest_to_fields(accepted_block_claim_digest);
            let certificate = AcceptedBlockCertificateStatement {
                height,
                block_id: header_witness.block_id,
                parent_block_id: previous_block_id,
                parent_state_root: accumulator.state_root,
                child_state_root: header.state_root,
                tx_root: header.tx_root,
                block_body_digest: digest_with_seed(0x20 | index as u8),
                block_proof_digest: digest_with_seed(0x30 | index as u8),
                auth_sidecar_digest: digest_with_seed(0x40 | index as u8),
                accepted_block_claim_digest,
                accepted_state_transition_claim_digest: digest_with_seed(0x50 | index as u8),
                exact_transition_digest: digest_with_seed(0x60 | index as u8),
                tx_count: index as u32,
                user_tx_count: index as u32,
                live_input_count: 0,
                live_output_count: 0,
                state_frontier_node_count: 0,
                touched_slot_count: 0,
                action_count: 0,
                block_body_len: 0,
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

            accumulator = accumulator
                .advance(&header)
                .expect("fixture header advances accumulator");
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
                .expect("accepted claim digest");
        let certificate_batch_statement = accepted_block_certificate_batch_statement(
            &certificate_statements,
            &accepted_claim_witness.accepted_block_claims,
            accepted_claim_batch_digest,
        )
        .expect("certificate batch");
        let end_anchor = anchor_from_consensus(
            &accepted_claim_output.consensus_state,
            accepted_claim_witness
                .headers
                .last()
                .expect("chunk has last header")
                .header
                .tx_root,
        );
        let previous_head = history_checkpoint_head_from_boundary(
            &start_anchor,
            &start_accumulator,
            &start_consensus,
        )
        .expect("previous head");
        let batch_summary = HistoryCheckpointBatchSummary {
            batch_len: chunk_len as u32,
            start_anchor,
            end_anchor,
            start_accumulator,
            end_accumulator: accepted_claim_output.accumulator.clone(),
            start_consensus,
            end_consensus: accepted_claim_output.consensus_state.clone(),
            accepted_claim_batch_digest,
        };
        let next_head = advance_history_checkpoint_head_native(&previous_head, &batch_summary)
            .expect("next head");
        let statement = HistoryCheckpointStepStatement {
            previous_head,
            batch_summary,
            next_head,
        };
        assert_eq!(
            statement.next_head.engine_id,
            HISTORY_CHECKPOINT_ENGINE_STREAMING_TOWER_IVC
        );

        ChunkFixture {
            statement,
            certificate_batch_statement,
            certificate_statements,
            accepted_claim_witness,
            accepted_claim_output,
        }
    }

    fn test_header(
        prev_block_hash: Digest,
        state_root: Digest,
        height: u64,
    ) -> noid_chain::BlockHeader {
        noid_chain::BlockHeader {
            attested_coverage: 0,
            prev_block_hash,
            state_root,
            tx_root: digest_with_seed(0x10 | (height as u8)),
            timestamp: GENESIS_TIMESTAMP + height * BLOCK_TIME,
            height,
            miner_address: Address([0x44; 32]),
            nonce: height as u128,
            difficulty_target: MAX_TARGET,
            log_slots: 24,
            active_slot_count: height,
            alloc_counter: height,
        }
    }

    fn anchor_from_consensus(
        consensus: &RecursiveConsensusState,
        tx_root: Digest,
    ) -> HeaderChainAnchor {
        HeaderChainAnchor {
            height: consensus.height,
            block_id: consensus.block_id,
            state_root: consensus.state_root,
            tx_root,
            miner_address: Address([0x44; 32]),
            log_slots: consensus.log_slots,
            active_slot_count: consensus.active_slot_count,
            alloc_counter: consensus.alloc_counter,
            cumulative_chainwork: consensus.cumulative_chainwork,
        }
    }

    fn digest_to_fields(hash: Digest) -> [Block128; 2] {
        [
            Block128::from(u128::from_le_bytes(hash[..16].try_into().unwrap())),
            Block128::from(u128::from_le_bytes(hash[16..].try_into().unwrap())),
        ]
    }

    fn digest_with_seed(seed: u8) -> Digest {
        [seed; 32]
    }
}
