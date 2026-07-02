// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! IVC-backed accepted-block certificate sub-relations.
//!
//! This module uses the shared `noid_ivc_core`/`noid_ivc_prover` R1CS backend.
//! It is intentionally scoped to fixed certificate data. Transaction bodies,
//! authorization witnesses, tx-root paths, and exact-state slot paths stay in
//! the block/certificate issuance layer.

use noid_core::Block128;
use noid_ivc_prover::challenger::{Challenger, FsChallenger};
use noid_ivc_prover::circuit::BinaryR1csBuilder;
use noid_ivc_prover::pcs::{pack_witness, PcsParams};
use noid_ivc_prover::proof_io::R1csProofBundle;
use noid_ivc_prover::r1cs::BlockR1cs;
use noid_poseidon2b::native::poseidon2b_hash_byte_slices;
use noid_poseidon2b::primitives::Digest;

use crate::block_certificate::{
    accepted_block_certificate_receipt, accepted_block_certificate_statement_digest,
    verify_accepted_block_certificate_receipt_projection, AcceptedBlockCertificateProofError,
    AcceptedBlockCertificateReceipt, AcceptedBlockCertificateReceiptError,
    AcceptedBlockCertificateStatement,
};

pub const ACCEPTED_BLOCK_CERTIFICATE_IVC_RECEIPT_RELATION: u32 = 1;
pub const ACCEPTED_BLOCK_CERTIFICATE_IVC_RECEIPT_M: usize = 14;
pub const ACCEPTED_BLOCK_CERTIFICATE_IVC_RECEIPT_K_LOG: usize = 13;
pub const ACCEPTED_BLOCK_CERTIFICATE_IVC_RECEIPT_LOG_INV_RATE: usize = 4;
pub const ACCEPTED_BLOCK_CERTIFICATE_IVC_RECEIPT_LOG_BATCH_SIZE: usize = 2;

const TRANSCRIPT_DOMAIN: &[u8] = b"noid-accepted-block-certificate-ivc-receipt-v1";
const STATEMENT_DIGEST_DOMAIN: &[u8] = b"NOID/ABC/IVC-RECEIPT/v1";

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AcceptedBlockCertificateIvcReceiptBackendProof {
    pub relation: u32,
    pub receipt: AcceptedBlockCertificateReceipt,
    pub core_proof: Vec<u8>,
}

impl AcceptedBlockCertificateIvcReceiptBackendProof {
    pub fn byte_len(&self) -> usize {
        bincode::serialized_size(self)
            .expect("serialized AcceptedBlockCertificateIvcReceiptBackendProof length fits usize")
            as usize
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcceptedBlockCertificateIvcReceiptError {
    UnsupportedRelation {
        actual: u32,
    },
    BadReceiptProjection(AcceptedBlockCertificateReceiptError),
    CircuitTooSmall,
    CoreUnsatisfied,
    EmptyCoreProof,
    DecodeCoreProof,
    BadCoreParameters {
        actual_m: usize,
        actual_log_inv_rate: usize,
        actual_log_batch_size: usize,
    },
    CoreVerify,
}

impl std::fmt::Display for AcceptedBlockCertificateIvcReceiptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedRelation { actual } => {
                write!(f, "unsupported certificate IVC receipt relation {actual}")
            }
            Self::BadReceiptProjection(source) => {
                write!(f, "bad certificate receipt projection: {source}")
            }
            Self::CircuitTooSmall => write!(f, "certificate IVC receipt circuit is too small"),
            Self::CoreUnsatisfied => write!(f, "certificate IVC receipt core is unsatisfied"),
            Self::EmptyCoreProof => write!(f, "empty certificate IVC receipt core proof"),
            Self::DecodeCoreProof => write!(f, "could not decode certificate IVC receipt proof"),
            Self::BadCoreParameters {
                actual_m,
                actual_log_inv_rate,
                actual_log_batch_size,
            } => write!(
                f,
                "bad certificate IVC receipt PCS parameters: m={actual_m}, log_inv_rate={actual_log_inv_rate}, log_batch_size={actual_log_batch_size}"
            ),
            Self::CoreVerify => write!(f, "certificate IVC receipt core proof rejected"),
        }
    }
}

impl std::error::Error for AcceptedBlockCertificateIvcReceiptError {}

pub fn prove_accepted_block_certificate_ivc_receipt_backend(
    statement: &AcceptedBlockCertificateStatement,
) -> Result<AcceptedBlockCertificateIvcReceiptBackendProof, AcceptedBlockCertificateIvcReceiptError>
{
    let receipt = accepted_block_certificate_receipt(statement);
    prove_accepted_block_certificate_ivc_receipt_backend_with_receipt(statement, &receipt)
}

pub fn prove_accepted_block_certificate_ivc_receipt_backend_with_receipt(
    statement: &AcceptedBlockCertificateStatement,
    receipt: &AcceptedBlockCertificateReceipt,
) -> Result<AcceptedBlockCertificateIvcReceiptBackendProof, AcceptedBlockCertificateIvcReceiptError>
{
    verify_accepted_block_certificate_receipt_projection(statement, receipt)
        .map_err(AcceptedBlockCertificateIvcReceiptError::BadReceiptProjection)?;
    let (r1cs, witness) = build_receipt_projection_r1cs(statement, receipt)?;
    if !r1cs.satisfies(&witness) {
        return Err(AcceptedBlockCertificateIvcReceiptError::CoreUnsatisfied);
    }
    let z_packed = pack_witness(&witness, r1cs.m);
    if !r1cs.satisfies_packed(&z_packed) {
        return Err(AcceptedBlockCertificateIvcReceiptError::CoreUnsatisfied);
    }
    let _ = noid_ivc_prover::init_perf_thread_pool();
    let pcs_params = receipt_pcs_params();
    let mut challenger = receipt_challenger(statement, receipt);
    let (proof, commitment, _) =
        noid_ivc_prover::prover::prove(&r1cs, &z_packed, &pcs_params, &mut challenger);
    Ok(AcceptedBlockCertificateIvcReceiptBackendProof {
        relation: ACCEPTED_BLOCK_CERTIFICATE_IVC_RECEIPT_RELATION,
        receipt: receipt.clone(),
        core_proof: R1csProofBundle { commitment, proof }.to_bytes(),
    })
}

pub fn verify_accepted_block_certificate_ivc_receipt_backend(
    statement: &AcceptedBlockCertificateStatement,
    proof: &AcceptedBlockCertificateIvcReceiptBackendProof,
) -> Result<(), AcceptedBlockCertificateIvcReceiptError> {
    if proof.relation != ACCEPTED_BLOCK_CERTIFICATE_IVC_RECEIPT_RELATION {
        return Err(
            AcceptedBlockCertificateIvcReceiptError::UnsupportedRelation {
                actual: proof.relation,
            },
        );
    }
    if proof.core_proof.is_empty() {
        return Err(AcceptedBlockCertificateIvcReceiptError::EmptyCoreProof);
    }
    verify_accepted_block_certificate_receipt_projection(statement, &proof.receipt)
        .map_err(AcceptedBlockCertificateIvcReceiptError::BadReceiptProjection)?;

    let (r1cs, _) = build_receipt_projection_r1cs(statement, &proof.receipt)?;
    let bundle = R1csProofBundle::from_bytes(&proof.core_proof)
        .map_err(|_| AcceptedBlockCertificateIvcReceiptError::DecodeCoreProof)?;
    validate_receipt_pcs_params(&bundle.commitment.params)?;
    let mut challenger = receipt_challenger(statement, &proof.receipt);
    noid_ivc_prover::verifier::verify(
        &r1cs,
        &bundle.commitment,
        &bundle.proof,
        r1cs.csc_lincheck_circuit(),
        &mut challenger,
    )
    .map(|_| ())
    .map_err(|_| AcceptedBlockCertificateIvcReceiptError::CoreVerify)
}

pub fn prove_accepted_block_certificate_proof_ivc_receipt(
    statement: &AcceptedBlockCertificateStatement,
) -> Result<
    crate::block_certificate::AcceptedBlockCertificateProof,
    AcceptedBlockCertificateProofError,
> {
    let backend = prove_accepted_block_certificate_ivc_receipt_backend(statement)
        .map_err(|_| AcceptedBlockCertificateProofError::BadIvcReceiptBackend)?;
    Ok(crate::block_certificate::AcceptedBlockCertificateProof {
        statement_digest: accepted_block_certificate_statement_digest(statement),
        backend_proof: bincode::serialize(&backend)
            .expect("AcceptedBlockCertificateIvcReceiptBackendProof serializes"),
    })
}

pub fn decode_and_verify_accepted_block_certificate_ivc_receipt_backend(
    statement: &AcceptedBlockCertificateStatement,
    bytes: &[u8],
) -> Result<(), AcceptedBlockCertificateIvcReceiptError> {
    let backend: AcceptedBlockCertificateIvcReceiptBackendProof = bincode::deserialize(bytes)
        .map_err(|_| AcceptedBlockCertificateIvcReceiptError::DecodeCoreProof)?;
    verify_accepted_block_certificate_ivc_receipt_backend(statement, &backend)
}

pub fn accepted_block_certificate_ivc_receipt_relation_digest() -> Digest {
    let constants = [
        ACCEPTED_BLOCK_CERTIFICATE_IVC_RECEIPT_RELATION as u64,
        ACCEPTED_BLOCK_CERTIFICATE_IVC_RECEIPT_M as u64,
        ACCEPTED_BLOCK_CERTIFICATE_IVC_RECEIPT_K_LOG as u64,
        ACCEPTED_BLOCK_CERTIFICATE_IVC_RECEIPT_LOG_INV_RATE as u64,
        ACCEPTED_BLOCK_CERTIFICATE_IVC_RECEIPT_LOG_BATCH_SIZE as u64,
    ];
    let mut bytes = Vec::with_capacity(constants.len() * 8);
    for value in constants {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    poseidon2b_hash_byte_slices(STATEMENT_DIGEST_DOMAIN, &[&bytes])
}

fn build_receipt_projection_r1cs(
    statement: &AcceptedBlockCertificateStatement,
    receipt: &AcceptedBlockCertificateReceipt,
) -> Result<(BlockR1cs, Vec<bool>), AcceptedBlockCertificateIvcReceiptError> {
    let mut builder = BinaryR1csBuilder::new(ACCEPTED_BLOCK_CERTIFICATE_IVC_RECEIPT_K_LOG);
    let pairs = receipt_projection_pairs(statement, receipt);
    for (left, right) in pairs {
        let left_bits = builder
            .alloc_public_block128(left)
            .map_err(|_| AcceptedBlockCertificateIvcReceiptError::CircuitTooSmall)?;
        let right_bits = builder
            .alloc_public_block128(right)
            .map_err(|_| AcceptedBlockCertificateIvcReceiptError::CircuitTooSmall)?;
        for bit in 0..128 {
            builder
                .assert_bit_eq(left_bits[bit], right_bits[bit])
                .map_err(|_| AcceptedBlockCertificateIvcReceiptError::CircuitTooSmall)?;
        }
    }
    Ok(builder.build_with_m(ACCEPTED_BLOCK_CERTIFICATE_IVC_RECEIPT_M))
}

fn receipt_projection_pairs(
    statement: &AcceptedBlockCertificateStatement,
    receipt: &AcceptedBlockCertificateReceipt,
) -> Vec<(Block128, Block128)> {
    let statement_digest = accepted_block_certificate_statement_digest(statement);
    let mut pairs = Vec::with_capacity(13);
    push_digest_pair(&mut pairs, &statement_digest, &receipt.statement_digest);
    pairs.push((
        Block128::from(statement.height as u128),
        Block128::from(receipt.height as u128),
    ));
    push_digest_pair(&mut pairs, &statement.block_id, &receipt.block_id);
    push_digest_pair(
        &mut pairs,
        &statement.parent_block_id,
        &receipt.parent_block_id,
    );
    push_digest_pair(
        &mut pairs,
        &statement.parent_state_root,
        &receipt.parent_state_root,
    );
    push_digest_pair(
        &mut pairs,
        &statement.child_state_root,
        &receipt.child_state_root,
    );
    push_digest_pair(
        &mut pairs,
        &statement.accepted_block_claim_digest,
        &receipt.accepted_block_claim_digest,
    );
    pairs
}

fn push_digest_pair(pairs: &mut Vec<(Block128, Block128)>, left: &Digest, right: &Digest) {
    let left = digest_to_fields(left);
    let right = digest_to_fields(right);
    pairs.push((left[0], right[0]));
    pairs.push((left[1], right[1]));
}

fn digest_to_fields(digest: &Digest) -> [Block128; 2] {
    [
        Block128::from(u128::from_le_bytes(digest[..16].try_into().unwrap())),
        Block128::from(u128::from_le_bytes(digest[16..].try_into().unwrap())),
    ]
}

fn receipt_pcs_params() -> PcsParams {
    PcsParams {
        m: ACCEPTED_BLOCK_CERTIFICATE_IVC_RECEIPT_M,
        log_inv_rate: ACCEPTED_BLOCK_CERTIFICATE_IVC_RECEIPT_LOG_INV_RATE,
        log_batch_size: ACCEPTED_BLOCK_CERTIFICATE_IVC_RECEIPT_LOG_BATCH_SIZE,
        profile: Default::default(),
    }
}

fn validate_receipt_pcs_params(
    params: &PcsParams,
) -> Result<(), AcceptedBlockCertificateIvcReceiptError> {
    if params.m != ACCEPTED_BLOCK_CERTIFICATE_IVC_RECEIPT_M
        || params.log_inv_rate != ACCEPTED_BLOCK_CERTIFICATE_IVC_RECEIPT_LOG_INV_RATE
        || params.log_batch_size != ACCEPTED_BLOCK_CERTIFICATE_IVC_RECEIPT_LOG_BATCH_SIZE
    {
        return Err(AcceptedBlockCertificateIvcReceiptError::BadCoreParameters {
            actual_m: params.m,
            actual_log_inv_rate: params.log_inv_rate,
            actual_log_batch_size: params.log_batch_size,
        });
    }
    Ok(())
}

fn receipt_challenger(
    statement: &AcceptedBlockCertificateStatement,
    receipt: &AcceptedBlockCertificateReceipt,
) -> FsChallenger {
    let mut challenger = FsChallenger::new(TRANSCRIPT_DOMAIN);
    challenger.observe_bytes(&accepted_block_certificate_ivc_receipt_relation_digest());
    challenger.observe_bytes(&accepted_block_certificate_statement_digest(statement));
    challenger.observe_bytes(
        &bincode::serialize(receipt).expect("AcceptedBlockCertificateReceipt serializes"),
    );
    challenger
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(byte: u8) -> Digest {
        [byte; 32]
    }

    fn statement() -> AcceptedBlockCertificateStatement {
        AcceptedBlockCertificateStatement {
            height: 7,
            block_id: digest(1),
            parent_block_id: digest(2),
            parent_state_root: digest(3),
            child_state_root: digest(4),
            tx_root: digest(5),
            block_body_digest: digest(6),
            block_proof_digest: digest(7),
            auth_sidecar_digest: digest(8),
            accepted_block_claim_digest: digest(9),
            accepted_state_transition_claim_digest: digest(10),
            exact_transition_digest: digest(11),
            tx_count: 2,
            user_tx_count: 1,
            live_input_count: 1,
            live_output_count: 2,
            state_frontier_node_count: 3,
            touched_slot_count: 1,
            action_count: 3,
            block_body_len: 144,
            block_proof_len: 256,
            auth_sidecar_len: 512,
        }
    }

    #[test]
    fn receipt_ivc_backend_roundtrips_and_rejects_tamper() {
        let statement = statement();
        let backend = prove_accepted_block_certificate_ivc_receipt_backend(&statement)
            .expect("receipt IVC backend proves");
        assert_eq!(
            backend.relation,
            ACCEPTED_BLOCK_CERTIFICATE_IVC_RECEIPT_RELATION
        );
        assert!(!backend.core_proof.is_empty());
        verify_accepted_block_certificate_ivc_receipt_backend(&statement, &backend)
            .expect("receipt IVC backend verifies");

        let mut bad = backend.clone();
        bad.receipt.child_state_root = digest(0x55);
        assert!(matches!(
            verify_accepted_block_certificate_ivc_receipt_backend(&statement, &bad),
            Err(AcceptedBlockCertificateIvcReceiptError::BadReceiptProjection(_))
        ));

        let mut bad = backend;
        let last = bad.core_proof.len() - 1;
        bad.core_proof[last] ^= 1;
        assert!(matches!(
            verify_accepted_block_certificate_ivc_receipt_backend(&statement, &bad),
            Err(AcceptedBlockCertificateIvcReceiptError::DecodeCoreProof
                | AcceptedBlockCertificateIvcReceiptError::CoreVerify)
        ));
    }

    #[test]
    fn top_level_certificate_proof_accepts_ivc_receipt_backend() {
        let statement = statement();
        let proof = prove_accepted_block_certificate_proof_ivc_receipt(&statement)
            .expect("top-level IVC receipt proof builds");
        crate::block_certificate::verify_accepted_block_certificate_proof_checkpoint(
            &statement, &proof,
        )
        .expect("top-level IVC receipt proof verifies");
        let handle = crate::block_certificate::accepted_block_certificate_validity_handle(&proof)
            .expect("IVC receipt proof handle builds");
        assert_eq!(
            handle.statement_digest,
            accepted_block_certificate_statement_digest(&statement)
        );
    }
}
