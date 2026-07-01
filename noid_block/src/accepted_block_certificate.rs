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
    accepted_block_certificate_statement_digest_v1, accepted_block_certificate_statement_fields_v1,
    AcceptedBlockCertificateBatchError, AcceptedBlockCertificateBatchStatementV1,
    AcceptedBlockCertificateStatementV1, ACCEPTED_BLOCK_CERTIFICATE_STATEMENT_FIELDS,
    ACCEPTED_BLOCK_CERTIFICATE_STATEMENT_VERSION,
};

use crate::{
    accepted_block_claim_hash_from_transcript, accepted_block_claim_transcript,
    accepted_state_transition_claim_digest, AcceptedBlockValidationArtifacts,
    AcceptedStateTransitionClaim, BlockAuthSidecar, BlockProof, VerifyBlockError,
    ACCEPT_BLOCK_PREDICATE_VERSION,
};

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
