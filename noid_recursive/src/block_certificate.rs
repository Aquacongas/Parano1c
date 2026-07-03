// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Data-only accepted-block certificate statement for recursive history proofs.
//!
//! This module is intentionally independent of `noid_block`: the final
//! recursive verifier lives here and must not depend on block-validation code.
//! `noid_block` builds these statements after full `AcceptBlock` validation.

use crate::checkpoint_proof::HISTORY_CHECKPOINT_BATCH_TARGET_BLOCKS;
use noid_core::{Block128, TowerField};
use noid_gkr::{
    discharge_fixed_field_hash_reductions_native, prove_fixed_field_hash_killshot,
    verify_fixed_field_hash_killshot, FixedFieldHashInputs, FixedFieldHashParams,
    FixedFieldHashProofKillShot,
};
use noid_poseidon2b::channel::Poseidon2bChannel;
use noid_poseidon2b::native::{
    capacity_iv, poseidon2b_hash_byte_slices, Poseidon2bSponge, TAG_HISTPRF,
};
use noid_poseidon2b::primitives::Digest;

pub const ACCEPTED_BLOCK_CERTIFICATE_STATEMENT_FIELDS: usize = 33;
pub const ACCEPTED_BLOCK_CERTIFICATE_STATEMENT_HASH_FIELDS: usize =
    ACCEPTED_BLOCK_CERTIFICATE_STATEMENT_FIELDS + 3;
pub const ACCEPTED_BLOCK_CERTIFICATE_BATCH_STATEMENT_HASH_FIELDS: usize = 38;

const ABC_STMT1: u128 = 0x4142_435F_5354_4D31; // "ABC_STM1"
const ABC_BATCH1: u128 = 0x4142_435F_4241_5431; // "ABC_BAT1"
const ABC_BODY1: &[u8] = b"NOID:ABC:BLOCK_BODY";
const ABC_PROOF1: &[u8] = b"NOID:ABC:BLOCK_PROOF";
const ABC_PROOF_META1: &[u8] = b"NOID:ABC:BLOCK_PROOF_META";
const ABC_AUTH1: &[u8] = b"NOID:ABC:AUTH_SIDECAR";
const ABC_CERTPROOF1: &[u8] = b"NOID:ABC:CERT_PROOF";
const ABC_ACCEPT1: &[u8] = b"NOID:ABC:ACCEPTANCE_RECEIPT";

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AcceptedBlockCertificateStatement {
    pub height: u64,
    pub block_id: Digest,
    pub parent_block_id: Digest,
    pub parent_state_root: Digest,
    pub child_state_root: Digest,
    pub tx_root: Digest,
    pub block_body_digest: Digest,
    pub block_proof_digest: Digest,
    pub auth_sidecar_digest: Digest,
    pub accepted_block_claim_digest: Digest,
    pub accepted_state_transition_claim_digest: Digest,
    pub exact_transition_digest: Digest,
    pub tx_count: u32,
    pub user_tx_count: u32,
    pub live_input_count: u32,
    pub live_output_count: u32,
    pub state_frontier_node_count: u32,
    pub touched_slot_count: u32,
    pub action_count: u32,
    pub block_body_len: u64,
    pub block_proof_len: u64,
    pub auth_sidecar_len: u64,
}

impl AcceptedBlockCertificateStatement {
    pub fn byte_len(&self) -> usize {
        bincode::serialized_size(self)
            .expect("serialized AcceptedBlockCertificateStatement length fits usize")
            as usize
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BlockProofAcceptanceReceipt {
    pub height: u64,
    pub block_id: Digest,
    pub parent_block_id: Digest,
    pub parent_state_root: Digest,
    pub child_state_root: Digest,
    pub tx_root: Digest,
    pub parent_log_slots: u32,
    pub child_log_slots: u32,
    pub parent_active_slot_count: u64,
    pub child_active_slot_count: u64,
    pub parent_alloc_counter: u64,
    pub child_alloc_counter: u64,
    pub block_body_digest: Digest,
    pub block_proof_digest: Digest,
    pub block_proof_meta_digest: Digest,
    pub auth_sidecar_digest: Digest,
    pub accepted_block_claim_digest: Digest,
    pub accepted_state_transition_claim_digest: Digest,
    pub exact_transition_digest: Digest,
    pub tx_count: u32,
    pub user_tx_count: u32,
    pub live_input_count: u32,
    pub live_output_count: u32,
    pub state_frontier_node_count: u32,
    pub touched_slot_count: u32,
    pub action_count: u32,
    pub block_body_len: u64,
    pub block_proof_len: u64,
    pub auth_sidecar_len: u64,
}

impl BlockProofAcceptanceReceipt {
    pub fn byte_len(&self) -> usize {
        bincode::serialized_size(self)
            .expect("serialized BlockProofAcceptanceReceipt length fits usize") as usize
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AcceptedBlockCertificateProof {
    pub statement_digest: Digest,
    pub backend_proof: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AcceptedBlockReceiptProjectionHandle {
    pub statement_digest: Digest,
    pub proof_digest: Digest,
}

impl AcceptedBlockReceiptProjectionHandle {
    pub fn byte_len(&self) -> usize {
        bincode::serialized_size(self)
            .expect("serialized AcceptedBlockReceiptProjectionHandle length fits usize")
            as usize
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AcceptedBlockCertificateReceipt {
    pub statement_digest: Digest,
    pub height: u64,
    pub block_id: Digest,
    pub parent_block_id: Digest,
    pub parent_state_root: Digest,
    pub child_state_root: Digest,
    pub tx_root: Digest,
    pub accepted_block_claim_digest: Digest,
}

impl AcceptedBlockCertificateReceipt {
    pub fn byte_len(&self) -> usize {
        bincode::serialized_size(self)
            .expect("serialized AcceptedBlockCertificateReceipt length fits usize") as usize
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AcceptedBlockCertificateBatchDigestProof {
    pub batch_statement_digest_hash: FixedFieldHashProofKillShot,
}

impl AcceptedBlockCertificateBatchDigestProof {
    pub fn byte_len(&self) -> usize {
        bincode::serialized_size(self)
            .expect("serialized AcceptedBlockCertificateBatchDigestProof length fits usize")
            as usize
    }
}

impl AcceptedBlockCertificateProof {
    pub fn byte_len(&self) -> usize {
        bincode::serialized_size(self)
            .expect("serialized AcceptedBlockCertificateProof length fits usize") as usize
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AcceptedBlockCertificateBatchStatement {
    pub batch_len: u32,
    pub accepted_claim_batch_digest: Digest,
    pub certificate_statement_digests: [Digest; HISTORY_CHECKPOINT_BATCH_TARGET_BLOCKS as usize],
}

impl AcceptedBlockCertificateBatchStatement {
    pub fn byte_len(&self) -> usize {
        bincode::serialized_size(self)
            .expect("serialized AcceptedBlockCertificateBatchStatement length fits usize")
            as usize
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcceptedBlockCertificateProofError {
    StatementDigestMismatch,
    EmptyBackendProof,
    DecodeBackendProof,
    BadBatchStatementDigestProof,
    BadBatchStatementDigestDischarge,
    BadReceiptProjectionProof,
}

impl std::fmt::Display for AcceptedBlockCertificateProofError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StatementDigestMismatch => {
                write!(f, "accepted-block certificate statement digest mismatch")
            }
            Self::EmptyBackendProof => write!(f, "empty accepted-block certificate backend proof"),
            Self::DecodeBackendProof => write!(f, "bad accepted-block certificate backend proof"),
            Self::BadBatchStatementDigestProof => {
                write!(
                    f,
                    "bad accepted-block certificate batch statement digest proof"
                )
            }
            Self::BadBatchStatementDigestDischarge => write!(
                f,
                "accepted-block certificate batch statement digest proof failed native discharge"
            ),
            Self::BadReceiptProjectionProof => {
                write!(
                    f,
                    "accepted-block certificate receipt projection proof rejected"
                )
            }
        }
    }
}

impl std::error::Error for AcceptedBlockCertificateProofError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcceptedBlockCertificateReceiptError {
    StatementDigestMismatch,
    ProjectionMismatch,
}

impl std::fmt::Display for AcceptedBlockCertificateReceiptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StatementDigestMismatch => {
                write!(f, "accepted-block certificate receipt digest mismatch")
            }
            Self::ProjectionMismatch => {
                write!(f, "accepted-block certificate receipt projection mismatch")
            }
        }
    }
}

impl std::error::Error for AcceptedBlockCertificateReceiptError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcceptedBlockReceiptProjectionHandleError {
    StatementDigestMismatch,
    EmptyBackendProof,
    DecodeBackendProof,
    EmptyProofDigest,
}

impl std::fmt::Display for AcceptedBlockReceiptProjectionHandleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StatementDigestMismatch => {
                write!(
                    f,
                    "accepted-block certificate receipt projection handle statement digest mismatch"
                )
            }
            Self::EmptyBackendProof => {
                write!(f, "empty accepted-block certificate validity backend proof")
            }
            Self::DecodeBackendProof => {
                write!(f, "bad accepted-block certificate validity backend proof")
            }
            Self::EmptyProofDigest => {
                write!(
                    f,
                    "empty accepted-block certificate receipt projection proof digest"
                )
            }
        }
    }
}

impl std::error::Error for AcceptedBlockReceiptProjectionHandleError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcceptedBlockCertificateBatchError {
    EmptyBatch,
    TooManyStatements { actual: usize },
    ClaimCountMismatch { statements: usize, claims: usize },
    ClaimProjectionMismatch { index: usize },
}

impl std::fmt::Display for AcceptedBlockCertificateBatchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyBatch => write!(f, "empty accepted-block certificate batch"),
            Self::TooManyStatements { actual } => {
                write!(f, "too many accepted-block certificate statements: {actual}")
            }
            Self::ClaimCountMismatch { statements, claims } => write!(
                f,
                "accepted-block certificate statement/claim count mismatch: {statements} statements, {claims} claims"
            ),
            Self::ClaimProjectionMismatch { index } => {
                write!(f, "accepted-block certificate claim projection mismatch at {index}")
            }
        }
    }
}

impl std::error::Error for AcceptedBlockCertificateBatchError {}

pub fn accepted_block_certificate_statement_fields(
    statement: &AcceptedBlockCertificateStatement,
) -> [Block128; ACCEPTED_BLOCK_CERTIFICATE_STATEMENT_FIELDS] {
    let mut fields = [Block128::ZERO; ACCEPTED_BLOCK_CERTIFICATE_STATEMENT_FIELDS];
    let mut index = 0usize;

    push_field(
        &mut fields,
        &mut index,
        Block128::from(statement.height as u128),
    );
    push_digest_fields(&mut fields, &mut index, &statement.block_id);
    push_digest_fields(&mut fields, &mut index, &statement.parent_block_id);
    push_digest_fields(&mut fields, &mut index, &statement.parent_state_root);
    push_digest_fields(&mut fields, &mut index, &statement.child_state_root);
    push_digest_fields(&mut fields, &mut index, &statement.tx_root);
    push_digest_fields(&mut fields, &mut index, &statement.block_body_digest);
    push_digest_fields(&mut fields, &mut index, &statement.block_proof_digest);
    push_digest_fields(&mut fields, &mut index, &statement.auth_sidecar_digest);
    push_digest_fields(
        &mut fields,
        &mut index,
        &statement.accepted_block_claim_digest,
    );
    push_digest_fields(
        &mut fields,
        &mut index,
        &statement.accepted_state_transition_claim_digest,
    );
    push_digest_fields(&mut fields, &mut index, &statement.exact_transition_digest);
    push_field(
        &mut fields,
        &mut index,
        Block128::from(statement.tx_count as u128),
    );
    push_field(
        &mut fields,
        &mut index,
        Block128::from(statement.user_tx_count as u128),
    );
    push_field(
        &mut fields,
        &mut index,
        Block128::from(statement.live_input_count as u128),
    );
    push_field(
        &mut fields,
        &mut index,
        Block128::from(statement.live_output_count as u128),
    );
    push_field(
        &mut fields,
        &mut index,
        Block128::from(statement.state_frontier_node_count as u128),
    );
    push_field(
        &mut fields,
        &mut index,
        Block128::from(statement.touched_slot_count as u128),
    );
    push_field(
        &mut fields,
        &mut index,
        Block128::from(statement.action_count as u128),
    );
    push_field(
        &mut fields,
        &mut index,
        Block128::from(statement.block_body_len as u128),
    );
    push_field(
        &mut fields,
        &mut index,
        Block128::from(statement.block_proof_len as u128),
    );
    push_field(
        &mut fields,
        &mut index,
        Block128::from(statement.auth_sidecar_len as u128),
    );
    debug_assert_eq!(index, ACCEPTED_BLOCK_CERTIFICATE_STATEMENT_FIELDS);
    fields
}

pub fn accepted_block_certificate_statement_digest(
    statement: &AcceptedBlockCertificateStatement,
) -> Digest {
    digest_fixed_no_pad_from_fields(&accepted_block_certificate_statement_hash_fields(statement))
}

pub fn accepted_block_certificate_statement_from_acceptance_receipt(
    receipt: &BlockProofAcceptanceReceipt,
) -> AcceptedBlockCertificateStatement {
    AcceptedBlockCertificateStatement {
        height: receipt.height,
        block_id: receipt.block_id,
        parent_block_id: receipt.parent_block_id,
        parent_state_root: receipt.parent_state_root,
        child_state_root: receipt.child_state_root,
        tx_root: receipt.tx_root,
        block_body_digest: receipt.block_body_digest,
        block_proof_digest: receipt.block_proof_digest,
        auth_sidecar_digest: receipt.auth_sidecar_digest,
        accepted_block_claim_digest: receipt.accepted_block_claim_digest,
        accepted_state_transition_claim_digest: receipt.accepted_state_transition_claim_digest,
        exact_transition_digest: receipt.exact_transition_digest,
        tx_count: receipt.tx_count,
        user_tx_count: receipt.user_tx_count,
        live_input_count: receipt.live_input_count,
        live_output_count: receipt.live_output_count,
        state_frontier_node_count: receipt.state_frontier_node_count,
        touched_slot_count: receipt.touched_slot_count,
        action_count: receipt.action_count,
        block_body_len: receipt.block_body_len,
        block_proof_len: receipt.block_proof_len,
        auth_sidecar_len: receipt.auth_sidecar_len,
    }
}

pub fn block_proof_acceptance_receipt_digest(receipt: &BlockProofAcceptanceReceipt) -> Digest {
    let bytes = bincode::serialize(receipt).expect("BlockProofAcceptanceReceipt serializes");
    poseidon2b_hash_byte_slices(ABC_ACCEPT1, &[&bytes])
}

pub fn accepted_block_certificate_statement_hash_fields(
    statement: &AcceptedBlockCertificateStatement,
) -> [Block128; ACCEPTED_BLOCK_CERTIFICATE_STATEMENT_HASH_FIELDS] {
    let statement_fields = accepted_block_certificate_statement_fields(statement);
    let mut fields = [Block128::ZERO; ACCEPTED_BLOCK_CERTIFICATE_STATEMENT_HASH_FIELDS];
    fields[0] = Block128::from(ABC_STMT1);
    fields[1] = Block128::from((ACCEPTED_BLOCK_CERTIFICATE_STATEMENT_FIELDS + 1) as u128);
    fields[2..2 + ACCEPTED_BLOCK_CERTIFICATE_STATEMENT_FIELDS].copy_from_slice(&statement_fields);
    fields
}

pub fn accepted_block_certificate_statement_hash_params() -> FixedFieldHashParams {
    FixedFieldHashParams::with_default_relation_tag(
        TAG_HISTPRF,
        ACCEPTED_BLOCK_CERTIFICATE_STATEMENT_HASH_FIELDS,
    )
    .expect("accepted-block certificate statement hash schedule is valid")
}

pub fn accepted_block_certificate_chain_claim(
    statement: &AcceptedBlockCertificateStatement,
) -> [Block128; 2] {
    digest_to_fields(&statement.accepted_block_claim_digest)
}

pub fn accepted_block_certificate_receipt(
    statement: &AcceptedBlockCertificateStatement,
) -> AcceptedBlockCertificateReceipt {
    AcceptedBlockCertificateReceipt {
        statement_digest: accepted_block_certificate_statement_digest(statement),
        height: statement.height,
        block_id: statement.block_id,
        parent_block_id: statement.parent_block_id,
        parent_state_root: statement.parent_state_root,
        child_state_root: statement.child_state_root,
        tx_root: statement.tx_root,
        accepted_block_claim_digest: statement.accepted_block_claim_digest,
    }
}

pub fn accepted_block_certificate_receipt_chain_claim(
    receipt: &AcceptedBlockCertificateReceipt,
) -> [Block128; 2] {
    digest_to_fields(&receipt.accepted_block_claim_digest)
}

pub fn verify_accepted_block_certificate_receipt_projection(
    statement: &AcceptedBlockCertificateStatement,
    receipt: &AcceptedBlockCertificateReceipt,
) -> Result<(), AcceptedBlockCertificateReceiptError> {
    if receipt.statement_digest != accepted_block_certificate_statement_digest(statement) {
        return Err(AcceptedBlockCertificateReceiptError::StatementDigestMismatch);
    }
    let expected = accepted_block_certificate_receipt(statement);
    if &expected == receipt {
        Ok(())
    } else {
        Err(AcceptedBlockCertificateReceiptError::ProjectionMismatch)
    }
}

pub fn accepted_block_certificate_proof_digest(proof: &AcceptedBlockCertificateProof) -> Digest {
    poseidon2b_hash_byte_slices(
        ABC_CERTPROOF1,
        &[&proof.statement_digest, proof.backend_proof.as_slice()],
    )
}

pub fn accepted_block_receipt_projection_handle(
    proof: &AcceptedBlockCertificateProof,
) -> Result<AcceptedBlockReceiptProjectionHandle, AcceptedBlockReceiptProjectionHandleError> {
    if proof.backend_proof.is_empty() {
        return Err(AcceptedBlockReceiptProjectionHandleError::EmptyBackendProof);
    }
    let _backend: crate::block_certificate_ivc::AcceptedBlockReceiptProjectionProof =
        bincode::deserialize(&proof.backend_proof)
            .map_err(|_| AcceptedBlockReceiptProjectionHandleError::DecodeBackendProof)?;

    let proof_digest = accepted_block_certificate_proof_digest(proof);
    if proof_digest == [0u8; 32] {
        return Err(AcceptedBlockReceiptProjectionHandleError::EmptyProofDigest);
    }
    Ok(AcceptedBlockReceiptProjectionHandle {
        statement_digest: proof.statement_digest,
        proof_digest,
    })
}

pub fn verify_accepted_block_receipt_projection_handle(
    expected_statement_digest: &Digest,
    handle: &AcceptedBlockReceiptProjectionHandle,
) -> Result<(), AcceptedBlockReceiptProjectionHandleError> {
    if &handle.statement_digest != expected_statement_digest {
        return Err(AcceptedBlockReceiptProjectionHandleError::StatementDigestMismatch);
    }
    if handle.proof_digest == [0u8; 32] {
        return Err(AcceptedBlockReceiptProjectionHandleError::EmptyProofDigest);
    }
    Ok(())
}

pub fn accepted_block_certificate_block_body_digest(bytes: &[u8]) -> Digest {
    certificate_bytes_digest(ABC_BODY1, bytes)
}

pub fn accepted_block_certificate_block_proof_digest(bytes: &[u8]) -> Digest {
    certificate_bytes_digest(ABC_PROOF1, bytes)
}

pub fn accepted_block_certificate_block_proof_meta_digest(bytes: &[u8]) -> Digest {
    certificate_bytes_digest(ABC_PROOF_META1, bytes)
}

pub fn accepted_block_certificate_auth_sidecar_digest(bytes: &[u8]) -> Digest {
    certificate_bytes_digest(ABC_AUTH1, bytes)
}

pub fn accepted_block_certificate_batch_statement(
    statements: &[AcceptedBlockCertificateStatement],
    accepted_block_claims: &[[Block128; 2]],
    accepted_claim_batch_digest: Digest,
) -> Result<AcceptedBlockCertificateBatchStatement, AcceptedBlockCertificateBatchError> {
    if statements.is_empty() {
        return Err(AcceptedBlockCertificateBatchError::EmptyBatch);
    }
    if statements.len() > HISTORY_CHECKPOINT_BATCH_TARGET_BLOCKS as usize {
        return Err(AcceptedBlockCertificateBatchError::TooManyStatements {
            actual: statements.len(),
        });
    }
    if statements.len() != accepted_block_claims.len() {
        return Err(AcceptedBlockCertificateBatchError::ClaimCountMismatch {
            statements: statements.len(),
            claims: accepted_block_claims.len(),
        });
    }

    let mut certificate_statement_digests =
        [[0u8; 32]; HISTORY_CHECKPOINT_BATCH_TARGET_BLOCKS as usize];
    for (index, (statement, claim)) in statements
        .iter()
        .zip(accepted_block_claims.iter().copied())
        .enumerate()
    {
        if accepted_block_certificate_chain_claim(statement) != claim {
            return Err(AcceptedBlockCertificateBatchError::ClaimProjectionMismatch { index });
        }
        certificate_statement_digests[index] =
            accepted_block_certificate_statement_digest(statement);
    }

    Ok(AcceptedBlockCertificateBatchStatement {
        batch_len: statements
            .len()
            .try_into()
            .expect("checkpoint batch target fits u32"),
        accepted_claim_batch_digest,
        certificate_statement_digests,
    })
}

pub fn accepted_block_certificate_batch_statement_digest(
    statement: &AcceptedBlockCertificateBatchStatement,
) -> Digest {
    digest_fixed_no_pad_from_fields(&accepted_block_certificate_batch_statement_hash_fields(
        statement,
    ))
}

pub fn accepted_block_certificate_batch_statement_hash_fields(
    statement: &AcceptedBlockCertificateBatchStatement,
) -> [Block128; ACCEPTED_BLOCK_CERTIFICATE_BATCH_STATEMENT_HASH_FIELDS] {
    let mut fields = [Block128::ZERO; ACCEPTED_BLOCK_CERTIFICATE_BATCH_STATEMENT_HASH_FIELDS];
    let mut index = 0usize;
    fields[index] = Block128::from(ABC_BATCH1);
    index += 1;
    fields[index] = Block128::from(36u128);
    index += 1;
    fields[index] = Block128::from(statement.batch_len as u128);
    index += 1;
    fields[index] = Block128::from(HISTORY_CHECKPOINT_BATCH_TARGET_BLOCKS as u128);
    index += 1;
    push_digest_hash_fields(
        &mut fields,
        &mut index,
        &statement.accepted_claim_batch_digest,
    );
    for digest in &statement.certificate_statement_digests {
        push_digest_hash_fields(&mut fields, &mut index, digest);
    }
    debug_assert_eq!(
        index,
        ACCEPTED_BLOCK_CERTIFICATE_BATCH_STATEMENT_HASH_FIELDS
    );
    fields
}

pub fn accepted_block_certificate_batch_statement_hash_params() -> FixedFieldHashParams {
    FixedFieldHashParams::with_default_relation_tag(
        TAG_HISTPRF,
        ACCEPTED_BLOCK_CERTIFICATE_BATCH_STATEMENT_HASH_FIELDS,
    )
    .expect("accepted-block certificate batch statement hash schedule is valid")
}

pub fn prove_accepted_block_certificate_batch_digest_proof(
    statement: &AcceptedBlockCertificateBatchStatement,
) -> Result<AcceptedBlockCertificateBatchDigestProof, AcceptedBlockCertificateProofError> {
    let fields = accepted_block_certificate_batch_statement_hash_fields(statement);
    let expected_digest = accepted_block_certificate_batch_statement_digest(statement);
    let input = fixed_hash_input(&fields, &expected_digest);
    let params = accepted_block_certificate_batch_statement_hash_params();
    let mut channel = Poseidon2bChannel::new();
    let inputs = [input];
    let (batch_statement_digest_hash, reductions) =
        prove_fixed_field_hash_killshot(params, &inputs, &mut channel);
    if !discharge_fixed_field_hash_reductions_native(params, &inputs, &reductions) {
        return Err(AcceptedBlockCertificateProofError::BadBatchStatementDigestDischarge);
    }
    Ok(AcceptedBlockCertificateBatchDigestProof {
        batch_statement_digest_hash,
    })
}

pub fn verify_accepted_block_certificate_batch_digest_proof(
    statement: &AcceptedBlockCertificateBatchStatement,
    proof: &AcceptedBlockCertificateBatchDigestProof,
) -> Result<(), AcceptedBlockCertificateProofError> {
    let fields = accepted_block_certificate_batch_statement_hash_fields(statement);
    let expected_digest = accepted_block_certificate_batch_statement_digest(statement);
    let input = fixed_hash_input(&fields, &expected_digest);
    let params = accepted_block_certificate_batch_statement_hash_params();
    let mut channel = Poseidon2bChannel::new();
    let inputs = [input];
    let reductions = verify_fixed_field_hash_killshot(
        params,
        &proof.batch_statement_digest_hash,
        &inputs,
        &mut channel,
    )
    .ok_or(AcceptedBlockCertificateProofError::BadBatchStatementDigestProof)?;
    if discharge_fixed_field_hash_reductions_native(params, &inputs, &reductions) {
        Ok(())
    } else {
        Err(AcceptedBlockCertificateProofError::BadBatchStatementDigestDischarge)
    }
}

pub fn verify_accepted_block_certificate_proof_checkpoint(
    statement: &AcceptedBlockCertificateStatement,
    proof: &AcceptedBlockCertificateProof,
) -> Result<(), AcceptedBlockCertificateProofError> {
    let expected_digest = accepted_block_certificate_statement_digest(statement);
    if proof.statement_digest != expected_digest {
        return Err(AcceptedBlockCertificateProofError::StatementDigestMismatch);
    }
    if proof.backend_proof.is_empty() {
        return Err(AcceptedBlockCertificateProofError::EmptyBackendProof);
    }
    let backend: crate::block_certificate_ivc::AcceptedBlockReceiptProjectionProof =
        bincode::deserialize(&proof.backend_proof)
            .map_err(|_| AcceptedBlockCertificateProofError::DecodeBackendProof)?;
    crate::block_certificate_ivc::verify_accepted_block_receipt_projection(statement, &backend)
        .map_err(|_| AcceptedBlockCertificateProofError::BadReceiptProjectionProof)
}

fn certificate_bytes_digest(domain: &[u8], bytes: &[u8]) -> Digest {
    poseidon2b_hash_byte_slices(domain, &[bytes])
}

fn push_field(
    fields: &mut [Block128; ACCEPTED_BLOCK_CERTIFICATE_STATEMENT_FIELDS],
    index: &mut usize,
    value: Block128,
) {
    debug_assert!(*index < ACCEPTED_BLOCK_CERTIFICATE_STATEMENT_FIELDS);
    fields[*index] = value;
    *index += 1;
}

fn push_digest_fields(
    fields: &mut [Block128; ACCEPTED_BLOCK_CERTIFICATE_STATEMENT_FIELDS],
    index: &mut usize,
    digest: &Digest,
) {
    let [lo, hi] = digest_to_fields(digest);
    push_field(fields, index, lo);
    push_field(fields, index, hi);
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

#[cfg(test)]
mod tests {
    use super::*;

    fn statement() -> AcceptedBlockCertificateStatement {
        AcceptedBlockCertificateStatement {
            height: 7,
            block_id: [0x01; 32],
            parent_block_id: [0x02; 32],
            parent_state_root: [0x03; 32],
            child_state_root: [0x04; 32],
            tx_root: [0x05; 32],
            block_body_digest: accepted_block_certificate_block_body_digest(b"body"),
            block_proof_digest: accepted_block_certificate_block_proof_digest(b"proof"),
            auth_sidecar_digest: accepted_block_certificate_auth_sidecar_digest(b"auth"),
            accepted_block_claim_digest: [0x06; 32],
            accepted_state_transition_claim_digest: [0x07; 32],
            exact_transition_digest: [0x08; 32],
            tx_count: 2,
            user_tx_count: 1,
            live_input_count: 3,
            live_output_count: 4,
            state_frontier_node_count: 5,
            touched_slot_count: 6,
            action_count: 7,
            block_body_len: 8,
            block_proof_len: 9,
            auth_sidecar_len: 10,
        }
    }

    #[test]
    fn accepted_block_certificate_statement_has_fixed_fields_and_digest() {
        let stmt = statement();
        assert_eq!(
            accepted_block_certificate_statement_fields(&stmt).len(),
            ACCEPTED_BLOCK_CERTIFICATE_STATEMENT_FIELDS
        );
        assert_eq!(
            accepted_block_certificate_statement_hash_fields(&stmt).len(),
            ACCEPTED_BLOCK_CERTIFICATE_STATEMENT_HASH_FIELDS
        );
        assert_ne!(
            accepted_block_certificate_statement_digest(&stmt),
            [0u8; 32]
        );

        let mut tampered = stmt.clone();
        tampered.child_state_root = [0xAA; 32];
        assert_ne!(
            accepted_block_certificate_statement_digest(&stmt),
            accepted_block_certificate_statement_digest(&tampered)
        );
    }

    #[test]
    fn accepted_block_certificate_chain_claim_projects_folded_claim_digest() {
        let stmt = statement();
        let projected = accepted_block_certificate_chain_claim(&stmt);
        let expected = digest_to_fields(&stmt.accepted_block_claim_digest);
        assert_eq!(projected, expected);
    }

    #[test]
    fn accepted_block_certificate_receipt_projects_fixed_history_fields() {
        let stmt = statement();
        let receipt = accepted_block_certificate_receipt(&stmt);
        assert_eq!(
            receipt.statement_digest,
            accepted_block_certificate_statement_digest(&stmt)
        );
        assert_eq!(receipt.height, stmt.height);
        assert_eq!(receipt.block_id, stmt.block_id);
        assert_eq!(receipt.parent_block_id, stmt.parent_block_id);
        assert_eq!(receipt.parent_state_root, stmt.parent_state_root);
        assert_eq!(receipt.child_state_root, stmt.child_state_root);
        assert_eq!(receipt.tx_root, stmt.tx_root);
        assert_eq!(
            accepted_block_certificate_receipt_chain_claim(&receipt),
            accepted_block_certificate_chain_claim(&stmt)
        );
        verify_accepted_block_certificate_receipt_projection(&stmt, &receipt)
            .expect("receipt projection verifies");

        let mut bad = receipt.clone();
        bad.child_state_root[0] ^= 1;
        assert_eq!(
            verify_accepted_block_certificate_receipt_projection(&stmt, &bad),
            Err(AcceptedBlockCertificateReceiptError::ProjectionMismatch)
        );

        let mut bad = receipt;
        bad.statement_digest[0] ^= 1;
        assert_eq!(
            verify_accepted_block_certificate_receipt_projection(&stmt, &bad),
            Err(AcceptedBlockCertificateReceiptError::StatementDigestMismatch)
        );
    }

    #[test]
    fn accepted_block_receipt_projection_handle_binds_statement_and_proof() {
        let stmt = statement();
        let proof = crate::block_certificate_ivc::prove_accepted_block_certificate_receipt_projection_proof(
                    &stmt,
                )
                .expect("receipt-projection proof builds");
        let handle = accepted_block_receipt_projection_handle(&proof)
            .expect("receipt projection handle builds");
        assert_eq!(
            handle.statement_digest,
            accepted_block_certificate_statement_digest(&stmt)
        );
        assert_eq!(
            handle.proof_digest,
            accepted_block_certificate_proof_digest(&proof)
        );
        assert_ne!(handle.proof_digest, [0u8; 32]);
        verify_accepted_block_receipt_projection_handle(
            &accepted_block_certificate_statement_digest(&stmt),
            &handle,
        )
        .expect("receipt projection handle verifies");

        let wrong_statement_digest = [0x99; 32];
        assert_eq!(
            verify_accepted_block_receipt_projection_handle(&wrong_statement_digest, &handle),
            Err(AcceptedBlockReceiptProjectionHandleError::StatementDigestMismatch)
        );

        let mut bad = proof.clone();
        bad.backend_proof.clear();
        assert_eq!(
            accepted_block_receipt_projection_handle(&bad),
            Err(AcceptedBlockReceiptProjectionHandleError::EmptyBackendProof)
        );

        let mut bad = proof.clone();
        bad.backend_proof = vec![0x42];
        assert_eq!(
            accepted_block_receipt_projection_handle(&bad),
            Err(AcceptedBlockReceiptProjectionHandleError::DecodeBackendProof)
        );

        let mut bad_handle = handle;
        bad_handle.proof_digest = [0u8; 32];
        assert_eq!(
            verify_accepted_block_receipt_projection_handle(
                &accepted_block_certificate_statement_digest(&stmt),
                &bad_handle,
            ),
            Err(AcceptedBlockReceiptProjectionHandleError::EmptyProofDigest)
        );
    }

    #[test]
    fn accepted_block_certificate_byte_domains_are_separated() {
        let body = accepted_block_certificate_block_body_digest(b"same");
        let proof = accepted_block_certificate_block_proof_digest(b"same");
        let auth = accepted_block_certificate_auth_sidecar_digest(b"same");
        assert_ne!(body, proof);
        assert_ne!(body, auth);
        assert_ne!(proof, auth);
    }

    #[test]
    fn accepted_block_certificate_proof_uses_receipt_projection_backend() {
        let stmt = statement();
        let good =
                crate::block_certificate_ivc::prove_accepted_block_certificate_receipt_projection_proof(&stmt)
                    .expect("receipt-projection proof builds");
        verify_accepted_block_certificate_proof_checkpoint(&stmt, &good)
            .expect("receipt-projection backend verifies through checkpoint path");

        let mut bad = good.clone();
        bad.statement_digest = [0x99; 32];
        assert_eq!(
            verify_accepted_block_certificate_proof_checkpoint(&stmt, &bad),
            Err(AcceptedBlockCertificateProofError::StatementDigestMismatch)
        );

        let mut bad = good.clone();
        let mut backend: crate::block_certificate_ivc::AcceptedBlockReceiptProjectionProof =
            bincode::deserialize(&bad.backend_proof).expect("receipt-projection backend decodes");
        backend.relation = 99;
        bad.backend_proof = bincode::serialize(&backend).expect("tampered backend serializes");
        assert_eq!(
            verify_accepted_block_certificate_proof_checkpoint(&stmt, &bad),
            Err(AcceptedBlockCertificateProofError::BadReceiptProjectionProof)
        );

        let mut bad = good.clone();
        bad.backend_proof.clear();
        assert_eq!(
            verify_accepted_block_certificate_proof_checkpoint(&stmt, &bad),
            Err(AcceptedBlockCertificateProofError::EmptyBackendProof)
        );

        let mut bad = good;
        bad.backend_proof = vec![0x42];
        assert_eq!(
            verify_accepted_block_certificate_proof_checkpoint(&stmt, &bad),
            Err(AcceptedBlockCertificateProofError::DecodeBackendProof)
        );
    }

    #[test]
    fn accepted_block_certificate_batch_statement_binds_claim_projection_and_padding() {
        let stmt = statement();
        let claim = accepted_block_certificate_chain_claim(&stmt);
        let batch =
            accepted_block_certificate_batch_statement(&[stmt.clone()], &[claim], [0x55; 32])
                .expect("batch statement builds");
        assert_eq!(
            accepted_block_certificate_batch_statement_hash_fields(&batch).len(),
            ACCEPTED_BLOCK_CERTIFICATE_BATCH_STATEMENT_HASH_FIELDS
        );
        assert_eq!(batch.batch_len, 1);
        assert_eq!(
            batch.certificate_statement_digests[0],
            accepted_block_certificate_statement_digest(&stmt)
        );
        assert_eq!(batch.certificate_statement_digests[1], [0u8; 32]);
        assert_ne!(
            accepted_block_certificate_batch_statement_digest(&batch),
            [0u8; 32]
        );
        let batch_digest_proof = prove_accepted_block_certificate_batch_digest_proof(&batch)
            .expect("batch digest proof builds");
        verify_accepted_block_certificate_batch_digest_proof(&batch, &batch_digest_proof)
            .expect("batch digest proof verifies");

        let mut tampered_batch = batch.clone();
        tampered_batch.certificate_statement_digests[0] = [0x99; 32];
        assert_eq!(
            verify_accepted_block_certificate_batch_digest_proof(
                &tampered_batch,
                &batch_digest_proof
            ),
            Err(AcceptedBlockCertificateProofError::BadBatchStatementDigestProof)
        );

        let bad_claim = [Block128::ONE, claim[1]];
        assert_eq!(
            accepted_block_certificate_batch_statement(&[stmt], &[bad_claim], [0x55; 32]),
            Err(AcceptedBlockCertificateBatchError::ClaimProjectionMismatch { index: 0 })
        );
    }
}
