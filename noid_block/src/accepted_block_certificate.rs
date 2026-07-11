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
    accepted_state_transition_claim_digest, AcceptedBlockClaimTranscript,
    AcceptedBlockValidationArtifacts, AcceptedStateTransitionClaim, BlockAuthSidecar, BlockProof,
    VerifyBlockError,
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

/// Data derived once from a successful native `AcceptBlock` result and then
/// split between the local history-claim store and the asynchronous
/// certificate-record prover.
///
/// `history_claim_fields` intentionally remains a `Vec`: the persisted format
/// predates this bundle and serializes a vector, including its length prefix.
/// This type is an in-process ownership boundary, not a new wire schema.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptedBlockPostValidationBundle {
    pub history_claim_fields: Vec<noid_core::Block128>,
    pub acceptance_receipt: BlockProofAcceptanceReceipt,
}

struct AcceptedBlockReceiptDerivedValues {
    transcript: AcceptedBlockClaimTranscript,
    transition_claim: AcceptedStateTransitionClaim,
    block_proof_meta_digest: [u8; 32],
}

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
fn derive_accepted_block_receipt_values(
    block: &Block,
    parent: &BlockHeader,
    prev_timestamps: &[u64],
    prev_active_counts: &[u64],
    anchor: &AnchorInfo,
    block_proof_bytes: &[u8],
    block_auth_sidecar_bytes: &[u8],
    artifacts: &AcceptedBlockValidationArtifacts,
) -> Result<AcceptedBlockReceiptDerivedValues, VerifyBlockError> {
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
    let transition_claim =
        AcceptedStateTransitionClaim::from_accepted_block(block, parent, artifacts)?;

    Ok(AcceptedBlockReceiptDerivedValues {
        transcript,
        transition_claim,
        block_proof_meta_digest,
    })
}

fn block_proof_acceptance_receipt_from_derived(
    block: &Block,
    parent: &BlockHeader,
    block_proof_bytes: &[u8],
    block_auth_sidecar_bytes: &[u8],
    derived: &AcceptedBlockReceiptDerivedValues,
) -> BlockProofAcceptanceReceipt {
    let transcript = &derived.transcript;
    let transition_claim = &derived.transition_claim;
    let accepted_block_claim_digest = accepted_block_claim_hash_from_transcript(transcript);
    let block_body = block.to_bytes();

    BlockProofAcceptanceReceipt {
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
        block_proof_meta_digest: derived.block_proof_meta_digest,
        auth_sidecar_digest: accepted_block_certificate_auth_sidecar_digest(
            block_auth_sidecar_bytes,
        ),
        accepted_block_claim_digest,
        accepted_state_transition_claim_digest: accepted_state_transition_claim_digest(
            transition_claim,
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
    }
}

/// Build both post-validation records from one transition claim and one
/// accepted-block transcript.
///
/// The supplied artifacts must be the output of the successful `AcceptBlock`
/// invocation for this exact block. The same fail-closed boundary checks as
/// [`block_proof_acceptance_receipt`] run before either record is returned.
#[allow(clippy::too_many_arguments)]
pub fn accepted_block_post_validation_bundle(
    block: &Block,
    parent: &BlockHeader,
    prev_timestamps: &[u64],
    prev_active_counts: &[u64],
    anchor: &AnchorInfo,
    block_proof_bytes: &[u8],
    block_auth_sidecar_bytes: &[u8],
    artifacts: &AcceptedBlockValidationArtifacts,
) -> Result<AcceptedBlockPostValidationBundle, VerifyBlockError> {
    let derived = derive_accepted_block_receipt_values(
        block,
        parent,
        prev_timestamps,
        prev_active_counts,
        anchor,
        block_proof_bytes,
        block_auth_sidecar_bytes,
        artifacts,
    )?;
    let history_claim_fields = derived.transition_claim.fields().to_vec();
    let acceptance_receipt = block_proof_acceptance_receipt_from_derived(
        block,
        parent,
        block_proof_bytes,
        block_auth_sidecar_bytes,
        &derived,
    );
    Ok(AcceptedBlockPostValidationBundle {
        history_claim_fields,
        acceptance_receipt,
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
    let derived = derive_accepted_block_receipt_values(
        block,
        parent,
        prev_timestamps,
        prev_active_counts,
        anchor,
        block_proof_bytes,
        block_auth_sidecar_bytes,
        artifacts,
    )?;
    Ok(block_proof_acceptance_receipt_from_derived(
        block,
        parent,
        block_proof_bytes,
        block_auth_sidecar_bytes,
        &derived,
    ))
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
    use noid_chain::{build_exact_action_surface, compute_tx_root, ChainState, SlotValue};
    use noid_poseidon2b::primitives::Address;
    use noid_tx::{
        output_bitmap_bit, Transaction, TxBody, TxInput, TxOutput, TX_INPUTS, TX_OUTPUTS,
    };

    struct PostValidationFixture {
        block: Block,
        parent: BlockHeader,
        prev_timestamps: Vec<u64>,
        prev_active_counts: Vec<u64>,
        anchor: AnchorInfo,
        block_proof_bytes: Vec<u8>,
        auth_sidecar_bytes: Vec<u8>,
        artifacts: AcceptedBlockValidationArtifacts,
    }

    fn post_validation_fixture(with_user: bool) -> PostValidationFixture {
        let user_body = noid_gkr::ghost_tx::ghost_tx_body();
        let mut state = if with_user {
            ChainState::from_sparse_utxos(
                6,
                &[(
                    0,
                    SlotValue::with_owner_fields(1, 0, user_body.input_owner.as_fields()),
                )],
                0,
            )
            .expect("user pre-state")
        } else {
            ChainState::with_log_slots(6)
        };
        let miner = Address([0x41; 32]);
        let parent = BlockHeader {
            prev_block_hash: [0x10; 32],
            state_root: state.cached_state_root(),
            tx_root: [0x11; 32],
            timestamp: 1_767_225_600,
            height: 4,
            miner_address: Address([0x40; 32]),
            nonce: 7,
            difficulty_target: [0xff; 32],
            log_slots: 6,
            active_slot_count: if with_user { 1 } else { 0 },
            alloc_counter: 0,
        };
        let mut coinbase_outputs = [TxOutput::dummy(); TX_OUTPUTS];
        coinbase_outputs[0] = TxOutput {
            slot_index: 2,
            amount: 50,
            owner: miner,
        };
        let coinbase = Transaction::new(TxBody {
            epoch_anchor: hash_block_header(&parent),
            fee: 0,
            input_owner: Address([0; 32]),
            inputs: [TxInput::dummy(); TX_INPUTS],
            outputs: coinbase_outputs,
            validity_bitmap: output_bitmap_bit(0),
            is_coinbase: true,
        });
        let mut transactions = vec![coinbase];
        if with_user {
            transactions.push(Transaction::new(user_body));
        }
        let bodies = transactions
            .iter()
            .map(|tx| tx.body.clone())
            .collect::<Vec<_>>();
        let commitments = bodies
            .iter()
            .map(TxBody::claims_commitment)
            .collect::<Vec<_>>();
        let surface =
            build_exact_action_surface(&state.state, &bodies, &commitments, state.alloc_counter)
                .expect("exact action surface");
        let slot_updates = surface
            .touched_indices
            .iter()
            .copied()
            .zip(surface.new_slots.iter().copied())
            .collect::<Vec<_>>();
        let child_state_root = state
            .exact_utxo_root_after_slot_updates(6, &slot_updates)
            .expect("child state root");
        let block = Block {
            header: BlockHeader {
                prev_block_hash: hash_block_header(&parent),
                state_root: child_state_root,
                tx_root: compute_tx_root(&transactions),
                timestamp: parent.timestamp + 60,
                height: parent.height + 1,
                miner_address: miner,
                nonce: 9,
                difficulty_target: parent.difficulty_target,
                log_slots: 6,
                active_slot_count: parent
                    .active_slot_count
                    .checked_sub(u64::from(surface.spends))
                    .unwrap()
                    + u64::from(surface.mints),
                alloc_counter: parent.alloc_counter + u64::from(surface.mints),
            },
            transactions,
        };
        let exact_state_inputs = crate::ExactStateTransitionInputs {
            parent_state_root: parent.state_root,
            parent_log_slots: parent.log_slots,
            child_state_root,
            child_log_slots: block.header.log_slots,
            parent_active_slot_count: parent.active_slot_count,
            parent_alloc_counter: parent.alloc_counter,
        };
        let cache = state.exact_sparse_cache().expect("parent sparse cache");
        let state_transition =
            crate::build_exact_state_transition_proof(&cache, &surface).expect("state proof");
        let verified_transition =
            crate::verify_exact_state_transition(&exact_state_inputs, &surface, &state_transition)
                .expect("verified transition");
        let artifacts = AcceptedBlockValidationArtifacts {
            authorization: crate::VerifiedAuthorizationBatch {
                user_tx_count: if with_user { 1 } else { 0 },
                live_input_count_total: if with_user { 1 } else { 0 },
            },
            exact_state_inputs,
            exact_action_surface: surface,
            verified_transition,
            verified_exact_state_roots: None,
        };
        let (block_proof_bytes, auth_sidecar_bytes) = if with_user {
            let proof = BlockProof::minimal(
                parent.state_root,
                block.header.state_root,
                1,
                state_transition,
            );
            let sidecar = BlockAuthSidecar {
                tx_auth: vec![noid_gkr::ghost_tx::ghost_authorization().0.clone()],
            };
            (
                bincode::serialize(&proof).expect("serialize block proof"),
                bincode::serialize(&sidecar).expect("serialize auth sidecar"),
            )
        } else {
            (Vec::new(), Vec::new())
        };
        PostValidationFixture {
            block,
            parent,
            prev_timestamps: vec![1_767_225_540, 1_767_225_600],
            prev_active_counts: vec![parent.active_slot_count],
            anchor: AnchorInfo {
                anchor_height: 0,
                anchor_timestamp: 1_767_225_000,
                anchor_target: [0xff; 32],
            },
            block_proof_bytes,
            auth_sidecar_bytes,
            artifacts,
        }
    }

    fn assert_post_validation_bundle_parity(fixture: &PostValidationFixture) {
        let legacy_claim = AcceptedStateTransitionClaim::from_accepted_block(
            &fixture.block,
            &fixture.parent,
            &fixture.artifacts,
        )
        .expect("legacy history claim");
        let legacy_receipt = block_proof_acceptance_receipt(
            &fixture.block,
            &fixture.parent,
            &fixture.prev_timestamps,
            &fixture.prev_active_counts,
            &fixture.anchor,
            &fixture.block_proof_bytes,
            &fixture.auth_sidecar_bytes,
            &fixture.artifacts,
        )
        .expect("legacy acceptance receipt");
        let bundle = accepted_block_post_validation_bundle(
            &fixture.block,
            &fixture.parent,
            &fixture.prev_timestamps,
            &fixture.prev_active_counts,
            &fixture.anchor,
            &fixture.block_proof_bytes,
            &fixture.auth_sidecar_bytes,
            &fixture.artifacts,
        )
        .expect("post-validation bundle");

        assert_eq!(bundle.history_claim_fields, legacy_claim.fields().to_vec());
        assert_eq!(bundle.acceptance_receipt, legacy_receipt);
        assert_eq!(
            bincode::serialize(&bundle.history_claim_fields).unwrap(),
            bincode::serialize(&legacy_claim.fields().to_vec()).unwrap(),
            "persisted history-claim vector format must not change",
        );
    }

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

    #[test]
    fn post_validation_bundle_matches_legacy_user_records() {
        assert_post_validation_bundle_parity(&post_validation_fixture(true));
    }

    #[test]
    fn post_validation_bundle_matches_legacy_coinbase_records() {
        assert_post_validation_bundle_parity(&post_validation_fixture(false));
    }

    #[test]
    fn post_validation_bundle_preserves_boundary_mismatch_rejections() {
        let fixture = post_validation_fixture(true);

        let mut wrong_block = fixture.block.clone();
        wrong_block.header.tx_root[0] ^= 1;
        assert!(matches!(
            accepted_block_post_validation_bundle(
                &wrong_block,
                &fixture.parent,
                &fixture.prev_timestamps,
                &fixture.prev_active_counts,
                &fixture.anchor,
                &fixture.block_proof_bytes,
                &fixture.auth_sidecar_bytes,
                &fixture.artifacts,
            ),
            Err(VerifyBlockError::HistoryClaimMismatch)
        ));

        let mut wrong_artifacts = fixture.artifacts.clone();
        wrong_artifacts.exact_state_inputs.parent_alloc_counter ^= 1;
        assert!(matches!(
            accepted_block_post_validation_bundle(
                &fixture.block,
                &fixture.parent,
                &fixture.prev_timestamps,
                &fixture.prev_active_counts,
                &fixture.anchor,
                &fixture.block_proof_bytes,
                &fixture.auth_sidecar_bytes,
                &wrong_artifacts,
            ),
            Err(VerifyBlockError::HistoryClaimMismatch)
        ));

        let mut wrong_parent = fixture.parent;
        wrong_parent.state_root[0] ^= 1;
        assert!(matches!(
            accepted_block_post_validation_bundle(
                &fixture.block,
                &wrong_parent,
                &fixture.prev_timestamps,
                &fixture.prev_active_counts,
                &fixture.anchor,
                &fixture.block_proof_bytes,
                &fixture.auth_sidecar_bytes,
                &fixture.artifacts,
            ),
            Err(VerifyBlockError::PrevStateRootMismatch)
                | Err(VerifyBlockError::HistoryClaimMismatch)
        ));
    }
}
