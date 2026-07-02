// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Builder for accepted-block certificate statements.
//!
//! The data-only statement lives in `noid_recursive` so the final recursive
//! verifier does not depend on this block-validation crate. This module only
//! constructs that statement after full `AcceptBlock` validation has produced
//! trusted proof-facing artifacts.

use noid_chain::block::Block;
use noid_chain::block_header::BlockHeader;
use noid_chain::consensus::validation::AnchorInfo;
use noid_chain::hash_block_header;

pub use noid_recursive::{
    accepted_block_certificate_auth_sidecar_digest_v1,
    accepted_block_certificate_batch_statement_digest_v1,
    accepted_block_certificate_batch_statement_v1, accepted_block_certificate_block_body_digest_v1,
    accepted_block_certificate_block_proof_digest_v1, accepted_block_certificate_chain_claim_v1,
    accepted_block_certificate_receipt_v1, accepted_block_certificate_statement_digest_v1,
    accepted_block_certificate_statement_fields_v1, accepted_block_certificate_validity_handle_v1,
    prove_accepted_block_certificate_proof_v1_hash_only,
    verify_accepted_block_certificate_receipt_projection_v1, AcceptedBlockCertificateBatchError,
    AcceptedBlockCertificateBatchStatementV1, AcceptedBlockCertificateProofError,
    AcceptedBlockCertificateProofV1, AcceptedBlockCertificateReceiptError,
    AcceptedBlockCertificateReceiptV1, AcceptedBlockCertificateStatementV1,
    AcceptedBlockCertificateValidityHandleError, AcceptedBlockCertificateValidityHandleV1,
    ACCEPTED_BLOCK_CERTIFICATE_STATEMENT_FIELDS, ACCEPTED_BLOCK_CERTIFICATE_STATEMENT_VERSION,
};

use crate::{
    accepted_block_claim_hash_from_transcript, accepted_block_claim_transcript,
    accepted_state_transition_claim_digest, AcceptedBlockValidationArtifacts,
    AcceptedStateTransitionClaim, BlockAuthSidecar, BlockProof, VerifyBlockError,
    ACCEPT_BLOCK_PREDICATE_VERSION,
};

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AcceptedBlockCertificateRecord {
    pub height: u64,
    pub statement: AcceptedBlockCertificateStatementV1,
    pub proof: AcceptedBlockCertificateProofV1,
    pub receipt: AcceptedBlockCertificateReceiptV1,
    pub validity_handle: AcceptedBlockCertificateValidityHandleV1,
}

#[derive(Debug)]
pub enum AcceptedBlockCertificateRecordError {
    Proof(AcceptedBlockCertificateProofError),
    Receipt(AcceptedBlockCertificateReceiptError),
    ValidityHandle(AcceptedBlockCertificateValidityHandleError),
}

impl std::fmt::Display for AcceptedBlockCertificateRecordError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Proof(source) => write!(f, "accepted-block certificate proof: {source}"),
            Self::Receipt(source) => write!(f, "accepted-block certificate receipt: {source}"),
            Self::ValidityHandle(source) => {
                write!(f, "accepted-block certificate validity handle: {source}")
            }
        }
    }
}

impl std::error::Error for AcceptedBlockCertificateRecordError {}

pub fn accepted_block_certificate_record_hash_only_scaffold(
    statement: AcceptedBlockCertificateStatementV1,
) -> Result<AcceptedBlockCertificateRecord, AcceptedBlockCertificateRecordError> {
    let receipt = accepted_block_certificate_receipt_v1(&statement);
    verify_accepted_block_certificate_receipt_projection_v1(&statement, &receipt)
        .map_err(AcceptedBlockCertificateRecordError::Receipt)?;
    let proof = prove_accepted_block_certificate_proof_v1_hash_only(&statement)
        .map_err(AcceptedBlockCertificateRecordError::Proof)?;
    let validity_handle = accepted_block_certificate_validity_handle_v1(&proof)
        .map_err(AcceptedBlockCertificateRecordError::ValidityHandle)?;
    Ok(AcceptedBlockCertificateRecord {
        height: statement.height,
        statement,
        proof,
        receipt,
        validity_handle,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn accepted_block_certificate_statement_v1(
    block: &Block,
    parent: &BlockHeader,
    prev_timestamps: &[u64],
    prev_active_counts: &[u64],
    anchor: &AnchorInfo,
    block_proof_bytes: &[u8],
    block_auth_sidecar_bytes: &[u8],
    artifacts: &AcceptedBlockValidationArtifacts,
) -> Result<AcceptedBlockCertificateStatementV1, VerifyBlockError> {
    let user_tx_count = block
        .transactions
        .iter()
        .filter(|tx| !tx.body.is_coinbase)
        .count();
    let (proof, sidecar) = if user_tx_count == 0 {
        if !block_proof_bytes.is_empty() {
            return Err(VerifyBlockError::ShapeMismatch);
        }
        if !block_auth_sidecar_bytes.is_empty() {
            return Err(VerifyBlockError::AuthSidecarShapeMismatch);
        }
        (None, BlockAuthSidecar::default())
    } else {
        let proof = bincode::deserialize::<BlockProof>(block_proof_bytes)
            .map_err(|_| VerifyBlockError::ShapeMismatch)?;
        let sidecar = bincode::deserialize::<BlockAuthSidecar>(block_auth_sidecar_bytes)
            .map_err(|_| VerifyBlockError::AuthSidecarShapeMismatch)?;
        (Some(proof), sidecar)
    };

    let transcript = accepted_block_claim_transcript(
        block,
        parent,
        prev_timestamps,
        prev_active_counts,
        anchor,
        proof.as_ref(),
        &sidecar,
    )?;
    let accepted_block_claim_digest = accepted_block_claim_hash_from_transcript(&transcript);
    let transition_claim =
        AcceptedStateTransitionClaim::from_accepted_block(block, parent, artifacts)?;
    let block_body = block.to_bytes();

    Ok(AcceptedBlockCertificateStatementV1 {
        version: ACCEPTED_BLOCK_CERTIFICATE_STATEMENT_VERSION,
        accept_block_predicate_version: ACCEPT_BLOCK_PREDICATE_VERSION,
        height: block.header.height,
        block_id: hash_block_header(&block.header),
        parent_block_id: hash_block_header(parent),
        parent_state_root: parent.state_root,
        child_state_root: block.header.state_root,
        tx_root: block.header.tx_root,
        block_body_digest: accepted_block_certificate_block_body_digest_v1(&block_body),
        block_proof_digest: accepted_block_certificate_block_proof_digest_v1(block_proof_bytes),
        auth_sidecar_digest: accepted_block_certificate_auth_sidecar_digest_v1(
            block_auth_sidecar_bytes,
        ),
        accepted_block_claim_digest,
        accepted_state_transition_claim_digest: accepted_state_transition_claim_digest(
            &transition_claim,
        ),
        exact_transition_digest: transition_claim.exact_transition_digest,
        tx_count: transcript.resources.tx_count,
        user_tx_count: transcript.resources.user_tx_count,
        live_input_count: transcript.resources.live_input_count,
        live_output_count: transcript.resources.output_count,
        state_frontier_node_count: transcript.resources.state_frontier_node_count,
        touched_slot_count: transition_claim.touched_slot_count,
        action_count: transition_claim.action_count,
        block_body_len: transcript.resources.block_body_len,
        block_proof_len: transcript.resources.block_proof_len,
        auth_sidecar_len: transcript.resources.auth_sidecar_len,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn verify_accepted_block_certificate_statement_v1_native(
    expected: &AcceptedBlockCertificateStatementV1,
    block: &Block,
    parent: &BlockHeader,
    prev_timestamps: &[u64],
    prev_active_counts: &[u64],
    anchor: &AnchorInfo,
    block_proof_bytes: &[u8],
    block_auth_sidecar_bytes: &[u8],
    artifacts: &AcceptedBlockValidationArtifacts,
) -> Result<(), VerifyBlockError> {
    let actual = accepted_block_certificate_statement_v1(
        block,
        parent,
        prev_timestamps,
        prev_active_counts,
        anchor,
        block_proof_bytes,
        block_auth_sidecar_bytes,
        artifacts,
    )?;
    if &actual != expected {
        return Err(VerifyBlockError::HistoryClaimMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn statement() -> AcceptedBlockCertificateStatementV1 {
        AcceptedBlockCertificateStatementV1 {
            version: ACCEPTED_BLOCK_CERTIFICATE_STATEMENT_VERSION,
            accept_block_predicate_version: ACCEPT_BLOCK_PREDICATE_VERSION,
            height: 7,
            block_id: [1u8; 32],
            parent_block_id: [2u8; 32],
            parent_state_root: [3u8; 32],
            child_state_root: [4u8; 32],
            tx_root: [5u8; 32],
            block_body_digest: [6u8; 32],
            block_proof_digest: [7u8; 32],
            auth_sidecar_digest: [8u8; 32],
            accepted_block_claim_digest: [9u8; 32],
            accepted_state_transition_claim_digest: [10u8; 32],
            exact_transition_digest: [11u8; 32],
            tx_count: 1,
            user_tx_count: 0,
            live_input_count: 0,
            live_output_count: 1,
            state_frontier_node_count: 0,
            touched_slot_count: 1,
            action_count: 1,
            block_body_len: 128,
            block_proof_len: 0,
            auth_sidecar_len: 0,
        }
    }

    #[test]
    fn certificate_record_hash_only_scaffold_binds_statement_receipt_and_handle() {
        let statement = statement();
        let record = accepted_block_certificate_record_hash_only_scaffold(statement.clone())
            .expect("record builds");
        let digest = accepted_block_certificate_statement_digest_v1(&statement);

        assert_eq!(record.height, statement.height);
        assert_eq!(record.statement, statement);
        assert_eq!(record.proof.statement_digest, digest);
        assert_eq!(record.receipt.statement_digest, digest);
        assert_eq!(record.validity_handle.statement_digest, digest);
        assert_eq!(
            record.validity_handle,
            accepted_block_certificate_validity_handle_v1(&record.proof).expect("handle")
        );
        verify_accepted_block_certificate_receipt_projection_v1(&record.statement, &record.receipt)
            .expect("receipt projection");

        let encoded = bincode::serialize(&record).expect("serialize record");
        let decoded: AcceptedBlockCertificateRecord =
            bincode::deserialize(&encoded).expect("decode record");
        assert_eq!(decoded, record);
    }
}
