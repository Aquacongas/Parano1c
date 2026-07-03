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
    accepted_block_certificate_auth_sidecar_digest, accepted_block_certificate_batch_statement,
    accepted_block_certificate_batch_statement_digest,
    accepted_block_certificate_block_body_digest, accepted_block_certificate_block_proof_digest,
    accepted_block_certificate_block_proof_meta_digest, accepted_block_certificate_chain_claim,
    accepted_block_certificate_receipt, accepted_block_certificate_statement_digest,
    accepted_block_certificate_statement_fields,
    accepted_block_certificate_statement_from_acceptance_receipt,
    accepted_block_receipt_projection_handle, block_proof_acceptance_receipt_digest,
    prove_accepted_block_certificate_receipt_projection_proof,
    verify_accepted_block_certificate_receipt_projection, AcceptedBlockCertificateBatchError,
    AcceptedBlockCertificateBatchStatement, AcceptedBlockCertificateProof,
    AcceptedBlockCertificateProofError, AcceptedBlockCertificateReceipt,
    AcceptedBlockCertificateReceiptError, AcceptedBlockCertificateStatement,
    AcceptedBlockReceiptProjectionHandle, AcceptedBlockReceiptProjectionHandleError,
    BlockProofAcceptanceReceipt, ACCEPTED_BLOCK_CERTIFICATE_STATEMENT_FIELDS,
};

use crate::{
    accepted_block_claim_hash_from_transcript, accepted_block_claim_transcript,
    accepted_state_transition_claim_digest, AcceptedBlockValidationArtifacts,
    AcceptedStateTransitionClaim, BlockAuthSidecar, BlockProof, VerifyBlockError,
};

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AcceptedBlockCertificateRecord {
    pub height: u64,
    pub acceptance_receipt: BlockProofAcceptanceReceipt,
    pub statement: AcceptedBlockCertificateStatement,
    pub proof: AcceptedBlockCertificateProof,
    pub receipt: AcceptedBlockCertificateReceipt,
    pub receipt_projection_handle: AcceptedBlockReceiptProjectionHandle,
}

#[derive(Debug)]
pub enum AcceptedBlockCertificateRecordError {
    Proof(AcceptedBlockCertificateProofError),
    Receipt(AcceptedBlockCertificateReceiptError),
    ReceiptProjectionHandle(AcceptedBlockReceiptProjectionHandleError),
}

impl std::fmt::Display for AcceptedBlockCertificateRecordError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Proof(source) => write!(f, "accepted-block certificate proof: {source}"),
            Self::Receipt(source) => write!(f, "accepted-block certificate receipt: {source}"),
            Self::ReceiptProjectionHandle(source) => write!(
                f,
                "accepted-block certificate receipt projection handle: {source}"
            ),
        }
    }
}

impl std::error::Error for AcceptedBlockCertificateRecordError {}

pub fn accepted_block_certificate_record(
    acceptance_receipt: BlockProofAcceptanceReceipt,
) -> Result<AcceptedBlockCertificateRecord, AcceptedBlockCertificateRecordError> {
    let statement =
        accepted_block_certificate_statement_from_acceptance_receipt(&acceptance_receipt);
    let receipt = accepted_block_certificate_receipt(&statement);
    verify_accepted_block_certificate_receipt_projection(&statement, &receipt)
        .map_err(AcceptedBlockCertificateRecordError::Receipt)?;
    let proof = prove_accepted_block_certificate_receipt_projection_proof(&statement)
        .map_err(AcceptedBlockCertificateRecordError::Proof)?;
    let receipt_projection_handle = accepted_block_receipt_projection_handle(&proof)
        .map_err(AcceptedBlockCertificateRecordError::ReceiptProjectionHandle)?;
    Ok(AcceptedBlockCertificateRecord {
        height: acceptance_receipt.height,
        acceptance_receipt,
        statement,
        proof,
        receipt,
        receipt_projection_handle,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn block_proof_acceptance_receipt(
    block: &Block,
    parent: &BlockHeader,
    prev_timestamps: &[u64],
    prev_active_counts: &[u64],
    anchor: &AnchorInfo,
    block_proof_bytes: &[u8],
    block_auth_sidecar_bytes: &[u8],
    artifacts: &AcceptedBlockValidationArtifacts,
) -> Result<BlockProofAcceptanceReceipt, VerifyBlockError> {
    let user_tx_count = block
        .transactions
        .iter()
        .filter(|tx| !tx.body.is_coinbase)
        .count();
    let (proof, sidecar, block_proof_meta_digest) = if user_tx_count == 0 {
        if !block_proof_bytes.is_empty() {
            return Err(VerifyBlockError::ShapeMismatch);
        }
        if !block_auth_sidecar_bytes.is_empty() {
            return Err(VerifyBlockError::AuthSidecarShapeMismatch);
        }
        (
            None,
            BlockAuthSidecar::default(),
            accepted_block_certificate_block_proof_meta_digest(&[]),
        )
    } else {
        let proof = bincode::deserialize::<BlockProof>(block_proof_bytes)
            .map_err(|_| VerifyBlockError::ShapeMismatch)?;
        let sidecar = bincode::deserialize::<BlockAuthSidecar>(block_auth_sidecar_bytes)
            .map_err(|_| VerifyBlockError::AuthSidecarShapeMismatch)?;
        if proof.meta.prev_block_state_root != parent.state_root {
            return Err(VerifyBlockError::PrevStateRootMismatch);
        }
        if proof.meta.new_state_root != block.header.state_root {
            return Err(VerifyBlockError::NewStateRootMismatch);
        }
        if proof.meta.n_tx as usize != user_tx_count {
            return Err(VerifyBlockError::ShapeMismatch);
        }
        let meta_bytes =
            bincode::serialize(&proof.meta).map_err(|_| VerifyBlockError::ShapeMismatch)?;
        let block_proof_meta_digest =
            accepted_block_certificate_block_proof_meta_digest(&meta_bytes);
        (Some(proof), sidecar, block_proof_meta_digest)
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

    Ok(BlockProofAcceptanceReceipt {
        height: block.header.height,
        block_id: hash_block_header(&block.header),
        parent_block_id: hash_block_header(parent),
        parent_state_root: parent.state_root,
        child_state_root: block.header.state_root,
        tx_root: block.header.tx_root,
        parent_log_slots: transition_claim.parent_log_slots,
        child_log_slots: transition_claim.child_log_slots,
        parent_active_slot_count: transition_claim.parent_active_slot_count,
        child_active_slot_count: transition_claim.child_active_slot_count,
        parent_alloc_counter: transition_claim.parent_alloc_counter,
        child_alloc_counter: transition_claim.child_alloc_counter,
        block_body_digest: accepted_block_certificate_block_body_digest(&block_body),
        block_proof_digest: accepted_block_certificate_block_proof_digest(block_proof_bytes),
        block_proof_meta_digest,
        auth_sidecar_digest: accepted_block_certificate_auth_sidecar_digest(
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
pub fn accepted_block_certificate_statement(
    block: &Block,
    parent: &BlockHeader,
    prev_timestamps: &[u64],
    prev_active_counts: &[u64],
    anchor: &AnchorInfo,
    block_proof_bytes: &[u8],
    block_auth_sidecar_bytes: &[u8],
    artifacts: &AcceptedBlockValidationArtifacts,
) -> Result<AcceptedBlockCertificateStatement, VerifyBlockError> {
    let acceptance_receipt = block_proof_acceptance_receipt(
        block,
        parent,
        prev_timestamps,
        prev_active_counts,
        anchor,
        block_proof_bytes,
        block_auth_sidecar_bytes,
        artifacts,
    )?;
    Ok(accepted_block_certificate_statement_from_acceptance_receipt(&acceptance_receipt))
}

#[allow(clippy::too_many_arguments)]
pub fn verify_accepted_block_certificate_statement_native(
    expected: &AcceptedBlockCertificateStatement,
    block: &Block,
    parent: &BlockHeader,
    prev_timestamps: &[u64],
    prev_active_counts: &[u64],
    anchor: &AnchorInfo,
    block_proof_bytes: &[u8],
    block_auth_sidecar_bytes: &[u8],
    artifacts: &AcceptedBlockValidationArtifacts,
) -> Result<(), VerifyBlockError> {
    let actual = accepted_block_certificate_statement(
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

    fn acceptance_receipt() -> BlockProofAcceptanceReceipt {
        BlockProofAcceptanceReceipt {
            height: 7,
            block_id: [1u8; 32],
            parent_block_id: [2u8; 32],
            parent_state_root: [3u8; 32],
            child_state_root: [4u8; 32],
            tx_root: [5u8; 32],
            parent_log_slots: 4,
            child_log_slots: 4,
            parent_active_slot_count: 41,
            child_active_slot_count: 42,
            parent_alloc_counter: 99,
            child_alloc_counter: 100,
            block_body_digest: [6u8; 32],
            block_proof_digest: [7u8; 32],
            block_proof_meta_digest: [12u8; 32],
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
    fn certificate_record_binds_acceptance_receipt_statement_receipt_and_handle() {
        let acceptance_receipt = acceptance_receipt();
        let statement =
            accepted_block_certificate_statement_from_acceptance_receipt(&acceptance_receipt);
        let record =
            accepted_block_certificate_record(acceptance_receipt.clone()).expect("record builds");
        let digest = accepted_block_certificate_statement_digest(&statement);

        assert_eq!(record.height, acceptance_receipt.height);
        assert_eq!(record.acceptance_receipt, acceptance_receipt);
        assert_eq!(record.statement, statement);
        assert_eq!(record.proof.statement_digest, digest);
        assert_eq!(record.receipt.statement_digest, digest);
        assert_eq!(record.receipt_projection_handle.statement_digest, digest);
        assert_eq!(
            record.receipt_projection_handle,
            accepted_block_receipt_projection_handle(&record.proof).expect("handle")
        );
        verify_accepted_block_certificate_receipt_projection(&record.statement, &record.receipt)
            .expect("receipt projection");
        assert_ne!(
            block_proof_acceptance_receipt_digest(&record.acceptance_receipt),
            [0u8; 32]
        );

        let encoded = bincode::serialize(&record).expect("serialize record");
        let decoded: AcceptedBlockCertificateRecord =
            bincode::deserialize(&encoded).expect("decode record");
        assert_eq!(decoded, record);
    }
}
