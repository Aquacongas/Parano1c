// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Poseidon-backed IVC proof-core backend for checkpoint chunks.
//!
//! This is the production-side landing zone for the extracted proof-core work.
//! It intentionally depends on `noid-ivc-prover`, not on a separate history lab
//! crate.
//!
//! Current scope: a fixed 16-slot chunk-core relation that proves the public
//! checkpoint boundary is connected to private accepted-claim/header/certificate
//! linkage witnesses. It is not yet the final public accepted-block verifier:
//! the next layer must encode the full `verify_accepted_block_batch_components_v1`
//! component verifier privately.

use noid_core::Block128;
use noid_ivc_prover::challenger::{Challenger, FsChallenger};
use noid_ivc_prover::pcs::{ligerito::LigeritoProfile, pack_witness, PcsParams};
use noid_ivc_prover::proof_io::R1csProofBundle;
use noid_ivc_prover::r1cs::{BlockR1cs, SparseBinaryMatrix};
use noid_poseidon2b::native::poseidon2b_hash_byte_slices;
use noid_poseidon2b::primitives::Digest;

use crate::accepted_batch::{
    accepted_claim_batch_digest_v1, AcceptedClaimBatchDigestError, AcceptedClaimBatchOutput,
    AcceptedClaimBatchWitness,
};
use crate::accumulator::ChainAccumulator;
use crate::block_certificate::{
    accepted_block_certificate_batch_statement_v1, accepted_block_certificate_chain_claim_v1,
    accepted_block_certificate_statement_digest_v1, AcceptedBlockCertificateBatchError,
    AcceptedBlockCertificateBatchStatementV1, AcceptedBlockCertificateStatementV1,
};
use crate::checkpoint_proof::{
    verify_history_checkpoint_step_statement_v1_native, HistoryCheckpointProofError,
    HistoryCheckpointStepStatementV1, HISTORY_CHECKPOINT_BATCH_TARGET_BLOCKS,
    HISTORY_CHECKPOINT_PROOF_VERSION,
};

pub const HISTORY_CHECKPOINT_IVC_CHUNK_CORE_RELATION_V1: u32 = 1;

const TRANSCRIPT_DOMAIN: &[u8] = b"noid-recursive-checkpoint-ivc-chunk-core-v1";
const STATEMENT_DIGEST_DOMAIN: &[u8] = b"NOID/REC/CHK-IVC-STMT/v1";
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
pub struct HistoryCheckpointIvcChunkCoreProofV1 {
    pub version: u32,
    pub relation: u32,
    pub chunk_len: u32,
    pub core_proof: Vec<u8>,
}

impl HistoryCheckpointIvcChunkCoreProofV1 {
    pub fn byte_len(&self) -> usize {
        bincode::serialized_size(self)
            .expect("serialized HistoryCheckpointIvcChunkCoreProofV1 length fits usize")
            as usize
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HistoryCheckpointIvcChunkCoreError {
    UnsupportedVersion { actual: u32 },
    UnsupportedRelation { actual: u32 },
    BadChunkLength { actual: usize },
    BadStepStatement(HistoryCheckpointProofError),
    BadCertificateBatch(AcceptedBlockCertificateBatchError),
    BadAcceptedClaimBatchDigest(AcceptedClaimBatchDigestError),
    AcceptedClaimBatchDigestMismatch,
    AcceptedClaimOutputMismatch,
    ComponentShapeMismatch,
    CertificateStatementMismatch { index: usize },
    CoreUnsatisfied { row: usize },
    EmptyCoreProof,
    DecodeCoreProof,
    CoreVerify,
}

impl std::fmt::Display for HistoryCheckpointIvcChunkCoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedVersion { actual } => {
                write!(f, "unsupported checkpoint IVC chunk proof version {actual}")
            }
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
            Self::CoreUnsatisfied { row } => {
                write!(f, "checkpoint IVC core witness does not satisfy row {row}")
            }
            Self::EmptyCoreProof => write!(f, "empty checkpoint IVC core proof"),
            Self::DecodeCoreProof => write!(f, "could not decode checkpoint IVC core proof"),
            Self::CoreVerify => write!(f, "checkpoint IVC core proof rejected"),
        }
    }
}

impl std::error::Error for HistoryCheckpointIvcChunkCoreError {}

pub fn prove_history_checkpoint_ivc_chunk_core_v1(
    statement: &HistoryCheckpointStepStatementV1,
    certificate_batch_statement: &AcceptedBlockCertificateBatchStatementV1,
    certificate_statements: &[AcceptedBlockCertificateStatementV1],
    accepted_claim_witness: &AcceptedClaimBatchWitness,
    accepted_claim_output: &AcceptedClaimBatchOutput,
) -> Result<HistoryCheckpointIvcChunkCoreProofV1, HistoryCheckpointIvcChunkCoreError> {
    let trace = checkpoint_ivc_trace_enabled();
    let mut trace_mark = std::time::Instant::now();
    validate_private_chunk_inputs(
        statement,
        certificate_batch_statement,
        certificate_statements,
        accepted_claim_witness,
        accepted_claim_output,
    )?;
    checkpoint_ivc_trace_step(trace, &mut trace_mark, "validate_private");

    let r1cs = build_chunk_core_r1cs(statement, certificate_batch_statement);
    checkpoint_ivc_trace_step(trace, &mut trace_mark, "build_r1cs");
    r1cs.csc_lincheck_circuit();
    checkpoint_ivc_trace_step(trace, &mut trace_mark, "build_csc");
    let witness = chunk_core_witness(
        &statement.batch_summary.start_accumulator,
        certificate_statements,
        accepted_claim_witness,
    );
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
    let mut challenger = public_challenger(statement, certificate_batch_statement);
    let (proof, commitment, _) =
        noid_ivc_prover::prover::prove(&r1cs, &z_packed, &pcs_params, &mut challenger);
    checkpoint_ivc_trace_step(trace, &mut trace_mark, "prove_r1cs");
    let core_proof = R1csProofBundle { commitment, proof }.to_bytes();
    checkpoint_ivc_trace_step(trace, &mut trace_mark, "serialize_proof");

    Ok(HistoryCheckpointIvcChunkCoreProofV1 {
        version: HISTORY_CHECKPOINT_PROOF_VERSION,
        relation: HISTORY_CHECKPOINT_IVC_CHUNK_CORE_RELATION_V1,
        chunk_len: CHUNK_CAPACITY as u32,
        core_proof,
    })
}

pub fn verify_history_checkpoint_ivc_chunk_core_v1(
    statement: &HistoryCheckpointStepStatementV1,
    certificate_batch_statement: &AcceptedBlockCertificateBatchStatementV1,
    proof: &HistoryCheckpointIvcChunkCoreProofV1,
) -> Result<(), HistoryCheckpointIvcChunkCoreError> {
    let trace = checkpoint_ivc_trace_enabled();
    let mut trace_mark = std::time::Instant::now();
    validate_public_chunk_inputs(statement, certificate_batch_statement)?;
    checkpoint_ivc_trace_step(trace, &mut trace_mark, "verify_public_inputs");
    if proof.version != HISTORY_CHECKPOINT_PROOF_VERSION {
        return Err(HistoryCheckpointIvcChunkCoreError::UnsupportedVersion {
            actual: proof.version,
        });
    }
    if proof.relation != HISTORY_CHECKPOINT_IVC_CHUNK_CORE_RELATION_V1 {
        return Err(HistoryCheckpointIvcChunkCoreError::UnsupportedRelation {
            actual: proof.relation,
        });
    }
    if proof.chunk_len as usize != CHUNK_CAPACITY {
        return Err(HistoryCheckpointIvcChunkCoreError::BadChunkLength {
            actual: proof.chunk_len as usize,
        });
    }
    if proof.core_proof.is_empty() {
        return Err(HistoryCheckpointIvcChunkCoreError::EmptyCoreProof);
    }
    let bundle = R1csProofBundle::from_bytes(&proof.core_proof)
        .map_err(|_| HistoryCheckpointIvcChunkCoreError::DecodeCoreProof)?;
    checkpoint_ivc_trace_step(trace, &mut trace_mark, "decode_proof");
    let r1cs = build_chunk_core_r1cs(statement, certificate_batch_statement);
    checkpoint_ivc_trace_step(trace, &mut trace_mark, "build_r1cs");
    let mut challenger = public_challenger(statement, certificate_batch_statement);
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
    statement: &HistoryCheckpointStepStatementV1,
    certificate_batch_statement: &AcceptedBlockCertificateBatchStatementV1,
) -> Result<(), HistoryCheckpointIvcChunkCoreError> {
    verify_history_checkpoint_step_statement_v1_native(statement)
        .map_err(HistoryCheckpointIvcChunkCoreError::BadStepStatement)?;
    if statement.batch_summary.batch_len as usize != CHUNK_CAPACITY {
        return Err(HistoryCheckpointIvcChunkCoreError::BadChunkLength {
            actual: statement.batch_summary.batch_len as usize,
        });
    }
    if certificate_batch_statement.batch_len as usize != CHUNK_CAPACITY {
        return Err(HistoryCheckpointIvcChunkCoreError::BadChunkLength {
            actual: certificate_batch_statement.batch_len as usize,
        });
    }
    if certificate_batch_statement.accepted_claim_batch_digest
        != statement.batch_summary.accepted_claim_batch_digest
    {
        return Err(HistoryCheckpointIvcChunkCoreError::AcceptedClaimBatchDigestMismatch);
    }
    Ok(())
}

fn validate_private_chunk_inputs(
    statement: &HistoryCheckpointStepStatementV1,
    certificate_batch_statement: &AcceptedBlockCertificateBatchStatementV1,
    certificate_statements: &[AcceptedBlockCertificateStatementV1],
    accepted_claim_witness: &AcceptedClaimBatchWitness,
    accepted_claim_output: &AcceptedClaimBatchOutput,
) -> Result<(), HistoryCheckpointIvcChunkCoreError> {
    validate_public_chunk_inputs(statement, certificate_batch_statement)?;
    if certificate_statements.len() != CHUNK_CAPACITY {
        return Err(HistoryCheckpointIvcChunkCoreError::BadChunkLength {
            actual: certificate_statements.len(),
        });
    }
    if accepted_claim_witness.headers.len() != CHUNK_CAPACITY
        || accepted_claim_witness.accepted_block_claims.len() != CHUNK_CAPACITY
    {
        return Err(HistoryCheckpointIvcChunkCoreError::BadChunkLength {
            actual: accepted_claim_witness.headers.len(),
        });
    }

    let accepted_claim_batch_digest =
        accepted_claim_batch_digest_v1(accepted_claim_witness, accepted_claim_output)
            .map_err(HistoryCheckpointIvcChunkCoreError::BadAcceptedClaimBatchDigest)?;
    if accepted_claim_batch_digest != statement.batch_summary.accepted_claim_batch_digest {
        return Err(HistoryCheckpointIvcChunkCoreError::AcceptedClaimBatchDigestMismatch);
    }
    if accepted_claim_output.consensus_state != statement.batch_summary.end_consensus
        || accepted_claim_output.accumulator != statement.batch_summary.end_accumulator
    {
        return Err(HistoryCheckpointIvcChunkCoreError::AcceptedClaimOutputMismatch);
    }

    let expected_batch_statement = accepted_block_certificate_batch_statement_v1(
        certificate_statements,
        &accepted_claim_witness.accepted_block_claims,
        accepted_claim_batch_digest,
    )
    .map_err(HistoryCheckpointIvcChunkCoreError::BadCertificateBatch)?;
    if &expected_batch_statement != certificate_batch_statement {
        return Err(HistoryCheckpointIvcChunkCoreError::ComponentShapeMismatch);
    }

    let mut accumulator = statement.batch_summary.start_accumulator.clone();
    let mut previous_block_id = statement.batch_summary.start_consensus.block_id;
    for (index, (certificate, header_witness)) in certificate_statements
        .iter()
        .zip(accepted_claim_witness.headers.iter())
        .enumerate()
    {
        if certificate.height != header_witness.header.height
            || certificate.block_id != header_witness.block_id
            || certificate.parent_block_id != previous_block_id
            || certificate.parent_block_id != header_witness.header.prev_block_hash
            || certificate.parent_state_root != accumulator.state_root
            || certificate.child_state_root != header_witness.header.state_root
            || accepted_block_certificate_chain_claim_v1(certificate)
                != accepted_claim_witness.accepted_block_claims[index]
        {
            return Err(HistoryCheckpointIvcChunkCoreError::CertificateStatementMismatch { index });
        }
        accumulator = accumulator.extend(
            header_witness.header.state_root,
            header_witness.block_id,
            header_witness.header.height,
            accepted_claim_witness.accepted_block_claims[index],
        );
        previous_block_id = header_witness.block_id;
    }
    if accumulator != accepted_claim_output.accumulator {
        return Err(HistoryCheckpointIvcChunkCoreError::AcceptedClaimOutputMismatch);
    }
    Ok(())
}

fn build_chunk_core_r1cs(
    statement: &HistoryCheckpointStepStatementV1,
    certificate_batch_statement: &AcceptedBlockCertificateBatchStatementV1,
) -> BlockR1cs {
    let k = 1usize << CHUNK_K_LOG;
    let mut a_rows = vec![Vec::<usize>::new(); k];
    let mut b_rows = vec![Vec::<usize>::new(); k];
    let c_rows = (0..k).map(|i| vec![i]).collect::<Vec<_>>();

    set_equals_one_at(&mut a_rows, &mut b_rows, CONST_ONE, CONST_ONE);
    for index in 0..CHUNK_CAPACITY {
        constrain_slot(&mut a_rows, &mut b_rows, slot_base(index));
        pin_digest(
            &mut a_rows,
            &mut b_rows,
            slot_base(index) + CERT_STATEMENT_DIGEST,
            &certificate_batch_statement.certificate_statement_digests[index],
        );
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
        &statement.batch_summary.start_consensus.block_id,
    );
    let last = slot_base(CHUNK_CAPACITY - 1);
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
        &statement.batch_summary.end_consensus.block_id,
    );

    let digest_cache = std::sync::OnceLock::new();
    digest_cache
        .set(chunk_core_r1cs_statement_digest(
            statement,
            certificate_batch_statement,
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
    statement: &HistoryCheckpointStepStatementV1,
    certificate_batch_statement: &AcceptedBlockCertificateBatchStatementV1,
) -> Digest {
    let constants = [
        HISTORY_CHECKPOINT_IVC_CHUNK_CORE_RELATION_V1 as u64,
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
        bincode::serialize(statement).expect("HistoryCheckpointStepStatementV1 serializes");
    let certificate_bytes = bincode::serialize(certificate_batch_statement)
        .expect("AcceptedBlockCertificateBatchStatementV1 serializes");
    poseidon2b_hash_byte_slices(
        STATEMENT_DIGEST_DOMAIN,
        &[&constants_bytes, &statement_bytes, &certificate_bytes],
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
    certificate_statements: &[AcceptedBlockCertificateStatementV1],
    accepted_claim_witness: &AcceptedClaimBatchWitness,
) -> Vec<bool> {
    let mut witness = vec![false; 1usize << CHUNK_M];
    witness[CONST_ONE] = true;

    let mut accumulator = start_accumulator.clone();
    let mut previous_block_id = certificate_statements[0].parent_block_id;
    for index in 0..CHUNK_CAPACITY {
        let base = slot_base(index);
        let certificate = &certificate_statements[index];
        let header_witness = &accepted_claim_witness.headers[index];
        let claim = accepted_claim_witness.accepted_block_claims[index];
        let next_accumulator = accumulator.extend(
            header_witness.header.state_root,
            header_witness.block_id,
            header_witness.header.height,
            claim,
        );

        write_u64_bits(&mut witness, base + PREV_HEIGHT, accumulator.height);
        write_u64_bits(&mut witness, base + CERT_HEIGHT, certificate.height);
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
            &certificate.parent_state_root,
        );
        write_digest_bits(
            &mut witness,
            base + CERT_CHILD_STATE,
            &certificate.child_state_root,
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
            &certificate.parent_block_id,
        );
        write_digest_bits(&mut witness, base + HEADER_BLOCK, &header_witness.block_id);
        write_digest_bits(&mut witness, base + CERT_BLOCK, &certificate.block_id);
        write_block128_pair_bits(&mut witness, base + CLAIM_WITNESS, claim);
        write_digest_bits(
            &mut witness,
            base + CERT_CLAIM_DIGEST,
            &certificate.accepted_block_claim_digest,
        );
        write_digest_bits(
            &mut witness,
            base + CERT_STATEMENT_DIGEST,
            &accepted_block_certificate_statement_digest_v1(certificate),
        );

        accumulator = next_accumulator;
        previous_block_id = header_witness.block_id;
    }
    witness
}

fn public_challenger(
    statement: &HistoryCheckpointStepStatementV1,
    certificate_batch_statement: &AcceptedBlockCertificateBatchStatementV1,
) -> FsChallenger {
    let mut challenger = FsChallenger::new(TRANSCRIPT_DOMAIN);
    challenger.observe_label(b"checkpoint-ivc-public-v1");
    let statement_bytes =
        bincode::serialize(statement).expect("HistoryCheckpointStepStatementV1 serializes");
    let certificate_bytes = bincode::serialize(certificate_batch_statement)
        .expect("AcceptedBlockCertificateBatchStatementV1 serializes");
    challenger.observe_bytes(&statement_bytes);
    challenger.observe_bytes(&certificate_bytes);
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
    use noid_chain::header_anchor::HeaderChainAnchor;
    use noid_poseidon2b::primitives::Address;

    use crate::checkpoint_proof::{
        advance_history_checkpoint_head_v1_native, history_checkpoint_head_from_boundary_v1,
        HistoryCheckpointBatchSummaryV1, HISTORY_CHECKPOINT_ENGINE_STREAMING_TOWER_IVC_V1,
    };
    use crate::pow_header::{HeaderWitness, RecursiveConsensusState};

    #[test]
    fn checkpoint_ivc_chunk_core_roundtrips_and_binds_public_boundary() {
        let fixture = chunk_fixture();
        let proof = prove_history_checkpoint_ivc_chunk_core_v1(
            &fixture.statement,
            &fixture.certificate_batch_statement,
            &fixture.certificate_statements,
            &fixture.accepted_claim_witness,
            &fixture.accepted_claim_output,
        )
        .expect("prove chunk core");
        verify_history_checkpoint_ivc_chunk_core_v1(
            &fixture.statement,
            &fixture.certificate_batch_statement,
            &proof,
        )
        .expect("verify chunk core");

        let mut tampered = fixture.statement.clone();
        tampered.batch_summary.end_accumulator.state_root[0] ^= 1;
        assert!(matches!(
            verify_history_checkpoint_ivc_chunk_core_v1(
                &tampered,
                &fixture.certificate_batch_statement,
                &proof,
            ),
            Err(HistoryCheckpointIvcChunkCoreError::BadStepStatement(_))
                | Err(HistoryCheckpointIvcChunkCoreError::CoreVerify)
        ));
    }

    struct ChunkFixture {
        statement: HistoryCheckpointStepStatementV1,
        certificate_batch_statement: AcceptedBlockCertificateBatchStatementV1,
        certificate_statements: Vec<AcceptedBlockCertificateStatementV1>,
        accepted_claim_witness: AcceptedClaimBatchWitness,
        accepted_claim_output: AcceptedClaimBatchOutput,
    }

    fn chunk_fixture() -> ChunkFixture {
        let start_header = test_header([0u8; 32], [1u8; 32], 0);
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
        let start_anchor = anchor_from_consensus(&start_consensus, start_header.tx_root);

        let mut accumulator = start_accumulator.clone();
        let mut previous_block_id = start_consensus.block_id;
        let mut headers = Vec::with_capacity(CHUNK_CAPACITY);
        let mut claims = Vec::with_capacity(CHUNK_CAPACITY);
        let mut certificate_statements = Vec::with_capacity(CHUNK_CAPACITY);
        for index in 0..CHUNK_CAPACITY {
            let height = accumulator.height + 1;
            let state_seed = (index as u8).wrapping_add(2);
            let header = test_header(previous_block_id, [state_seed; 32], height);
            let header_witness = HeaderWitness::from_header(&header);
            let accepted_block_claim_digest = digest_with_seed(0x80 | index as u8);
            let claim = digest_to_fields(accepted_block_claim_digest);
            let certificate = AcceptedBlockCertificateStatementV1 {
                version: crate::block_certificate::ACCEPTED_BLOCK_CERTIFICATE_STATEMENT_VERSION,
                accept_block_predicate_version: 1,
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
                .expect("accepted claim digest");
        let certificate_batch_statement = accepted_block_certificate_batch_statement_v1(
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
        let previous_head = history_checkpoint_head_from_boundary_v1(
            &start_anchor,
            &start_accumulator,
            &start_consensus,
        )
        .expect("previous head");
        let batch_summary = HistoryCheckpointBatchSummaryV1 {
            version: HISTORY_CHECKPOINT_PROOF_VERSION,
            batch_len: CHUNK_CAPACITY as u32,
            start_anchor,
            end_anchor,
            start_accumulator,
            end_accumulator: accepted_claim_output.accumulator.clone(),
            start_consensus,
            end_consensus: accepted_claim_output.consensus_state.clone(),
            accepted_claim_batch_digest,
        };
        let next_head = advance_history_checkpoint_head_v1_native(&previous_head, &batch_summary)
            .expect("next head");
        let statement = HistoryCheckpointStepStatementV1 {
            version: HISTORY_CHECKPOINT_PROOF_VERSION,
            previous_head,
            batch_summary,
            next_head,
        };
        assert_eq!(
            statement.next_head.engine_id,
            HISTORY_CHECKPOINT_ENGINE_STREAMING_TOWER_IVC_V1
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
            prev_block_hash,
            state_root,
            tx_root: digest_with_seed(0x10 | (height as u8)),
            timestamp: 1_767_225_600 + height * BLOCK_TIME,
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
            projection_root: digest_with_seed((consensus.height as u8).wrapping_add(0x70)),
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
