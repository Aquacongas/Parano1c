// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Minimal production block proof kernel.
//!
//! Current block validity is:
//! - exact public transaction predicates reconstructed from `TxBody`;
//! - one owner-batched authorization proof per non-coinbase transaction;
//! - exact authenticated UTXO/ReuseGuard state transition.

pub mod accepted_block_batch;
pub mod accepted_block_certificate;
pub mod block_chain_context;
pub mod exact_state_killshot;
pub mod exact_state_transition;
pub mod history_claim;
pub mod validate;

pub use accepted_block_batch::{
    accepted_block_certificate_batch_statement_from_full_accepted_output_v1,
    accepted_claim_batch_digest_v1, history_checkpoint_batch_summary_from_full_accepted_output_v1,
    prove_full_accepted_block_batch_checkpoint_package_from_boundary_v1,
    prove_full_accepted_block_batch_checkpoint_package_v1,
    prove_history_checkpoint_step_proof_from_full_accepted_components_v1,
    prove_history_checkpoint_step_proof_from_verified_full_accepted_output_v1,
    prove_retained_full_accepted_block_batch_proof,
    public_history_checkpoint_proof_from_package_v1,
    verify_full_accepted_block_batch_checkpoint_package_v1,
    verify_full_accepted_block_batch_native,
    verify_history_checkpoint_step_proof_with_full_accepted_components_v1,
    verify_history_checkpoint_step_proof_with_verified_full_accepted_output_v1,
    verify_retained_full_accepted_block_batch_checkpoint_step_v1,
    verify_retained_full_accepted_block_batch_proof, FullAcceptedBlockBatchCheckpointPackageV1,
    FullAcceptedBlockBatchError, FullAcceptedBlockBatchItem, FullAcceptedBlockBatchOutput,
    FullAcceptedBlockBatchProofComponents, FullAcceptedBlockBatchWitness,
    RetainedFullAcceptedBlockBatchProof,
};
pub use accepted_block_certificate::{
    accepted_block_certificate_batch_statement_digest_v1,
    accepted_block_certificate_batch_statement_v1, accepted_block_certificate_chain_claim_v1,
    accepted_block_certificate_record_hash_only_scaffold,
    accepted_block_certificate_statement_digest_v1, accepted_block_certificate_statement_v1,
    verify_accepted_block_certificate_statement_v1_native, AcceptedBlockCertificateBatchError,
    AcceptedBlockCertificateBatchStatementV1, AcceptedBlockCertificateRecord,
    AcceptedBlockCertificateRecordError, AcceptedBlockCertificateStatementV1,
    ACCEPTED_BLOCK_CERTIFICATE_STATEMENT_VERSION,
};
pub use block_chain_context::{BlockChainContext, ReplayWitnessError};
pub use exact_state_killshot::{
    derive_exact_state_killshot_inputs, prove_exact_state_killshot, verify_exact_state_killshot,
    ExactStateKillShotError, ExactStateKillShotInputs, ExactStateKillShotProof,
};
pub use exact_state_transition::{
    build_exact_state_transition_proof, derive_exact_composite_state_root_inputs,
    derive_exact_guard_bucket_hash_inputs, derive_exact_guard_merkle_batch_inputs,
    derive_exact_slot_leaf_batch_inputs, derive_exact_state_merkle_batch_inputs,
    verify_exact_state_transition, ExactCompositeStateRootBatchInputs,
    ExactGuardBucketHashBatchInputs, ExactGuardMerkleBatchInputs, ExactSlotLeafBatchInputs,
    ExactStateMerkleBatchInputs, ExactStateTransitionError, ExactStateTransitionInputs,
    ExactStateTransitionProof, GuardBucketUpdateProof, VerifiedStateTransition,
};
pub use history_claim::{
    accepted_state_transition_chain_claim, accepted_state_transition_claim_digest,
    accepted_state_transition_claim_fields, AcceptedStateTransitionClaim,
    ACCEPTED_STATE_TRANSITION_CLAIM_FIELDS, ACCEPTED_STATE_TRANSITION_CLAIM_VERSION,
};
pub use validate::{
    accept_block, accept_block_timeless, accept_block_timeless_with_artifacts,
    accept_block_with_artifacts, derive_no_user_tx_validation_artifacts,
    validate_block_auth_sidecar_shape, validate_block_authorizations, validate_block_full,
    validate_block_full_timeless, validate_block_full_timeless_with_artifacts,
    AcceptedBlockRawValidationOutput, AcceptedBlockValidationArtifacts,
    AcceptedBlockValidationOutput, AuthorizationProof, AuthorizationVerifier,
    CanonicalAuthorizationStatement, FullValidationError, OwnerAuthAuthorizationVerifier,
    VerifiedAuthorization, VerifiedAuthorizationBatch, ACCEPT_BLOCK_PREDICATE_VERSION,
};

use crate::exact_state_transition::ExactStateTransitionProof as BlockExactStateTransitionProof;
use noid_chain::consensus::params::{EXPANSION_WINDOW, MEDIAN_TIME_BLOCKS};
use noid_chain::consensus::validation::AnchorInfo;
use noid_chain::{hash_block_header, Block, BlockHeader};
use noid_core::{Block128, TowerField};
use noid_gkr::OwnerAuthProofKillShot;
use noid_poseidon2b::native::compression::Poseidon2bSponge;
use noid_poseidon2b::native::domain::{capacity_iv, TAG_ACCBLK};
use noid_poseidon2b::primitives::Address;

// ---------------------------------------------------------------------------
// Public metadata
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BlockPublicMeta {
    pub prev_block_state_root: [u8; 32],
    /// New state root (= block header's `state_root`).
    pub new_state_root: [u8; 32],
    /// Number of non-coinbase transactions covered by this proof.
    pub n_tx: u32,
}

// ---------------------------------------------------------------------------
// BlockProof
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BlockProof {
    pub meta: BlockPublicMeta,
    /// Exact authenticated UTXO/ReuseGuard state transition proof.
    pub state_transition: BlockExactStateTransitionProof,
}

impl BlockProof {
    pub fn minimal(
        prev_block_state_root: [u8; 32],
        new_state_root: [u8; 32],
        n_tx: u32,
        state_transition: BlockExactStateTransitionProof,
    ) -> Self {
        Self {
            meta: BlockPublicMeta {
                prev_block_state_root,
                new_state_root,
                n_tx,
            },
            state_transition,
        }
    }

    pub fn byte_len(&self) -> usize {
        self.state_transition.byte_len()
    }
}

// ---------------------------------------------------------------------------
// Public AuthGKR sidecar
// ---------------------------------------------------------------------------

/// Public per-transaction AuthGKR capsule carried outside canonical `BlockProof`.
///
/// The sidecar contains only public proof artifacts. It must never contain
/// raw wallet secrets. It is a detached validation witness: validators check it
/// against canonical authorization statements derived from the block body and
/// authenticated state context, not against semantic block identity.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct BlockAuthSidecar {
    /// One auth proof per non-coinbase transaction in canonical block order.
    pub tx_auth: Vec<OwnerAuthProofKillShot>,
}

impl BlockAuthSidecar {
    pub fn byte_len(&self) -> usize {
        bincode::serialized_size(self).map_or(0, |len| len as usize)
    }
}

// ---------------------------------------------------------------------------
// Canonical accepted-block claim
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AcceptedBlockHeaderClaim {
    pub block_id: [u8; 32],
    pub prev_block_hash: [u8; 32],
    pub state_root: [u8; 32],
    pub tx_root: [u8; 32],
    pub timestamp: u64,
    pub height: u64,
    pub miner_address: Address,
    pub nonce: u128,
    pub difficulty_target: [u8; 32],
    pub log_slots: u32,
    pub active_slot_count: u64,
    pub alloc_counter: u64,
}

impl AcceptedBlockHeaderClaim {
    fn from_header(header: &BlockHeader) -> Self {
        Self {
            block_id: hash_block_header(header),
            prev_block_hash: header.prev_block_hash,
            state_root: header.state_root,
            tx_root: header.tx_root,
            timestamp: header.timestamp,
            height: header.height,
            miner_address: header.miner_address,
            nonce: header.nonce,
            difficulty_target: header.difficulty_target,
            log_slots: header.log_slots,
            active_slot_count: header.active_slot_count,
            alloc_counter: header.alloc_counter,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AcceptedBlockContextClaim {
    pub parent: AcceptedBlockHeaderClaim,
    pub prev_timestamps: Vec<u64>,
    pub prev_active_counts: Vec<u64>,
    pub asert_anchor_height: u64,
    pub asert_anchor_timestamp: u64,
    pub asert_anchor_target: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AcceptedBlockResourceClaim {
    pub block_body_len: u64,
    pub block_proof_len: u64,
    pub auth_sidecar_len: u64,
    pub tx_count: u32,
    pub user_tx_count: u32,
    pub live_input_count: u32,
    pub output_count: u32,
    pub state_frontier_node_count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AcceptedBlockClaimTranscript {
    pub predicate_version: u32,
    pub block: AcceptedBlockHeaderClaim,
    pub context: AcceptedBlockContextClaim,
    pub resources: AcceptedBlockResourceClaim,
}

#[allow(clippy::too_many_arguments)]
pub fn accepted_block_claim_transcript(
    block: &Block,
    parent: &BlockHeader,
    prev_timestamps: &[u64],
    prev_active_counts: &[u64],
    anchor: &AnchorInfo,
    proof: Option<&BlockProof>,
    auth_sidecar: &BlockAuthSidecar,
) -> Result<AcceptedBlockClaimTranscript, VerifyBlockError> {
    let (user_txs, live_inputs, outputs, state_frontier_nodes) =
        crate::validate::block_resource_counts(block);
    if user_txs == 0 {
        if proof.is_some() || !auth_sidecar.tx_auth.is_empty() {
            return Err(VerifyBlockError::AuthSidecarShapeMismatch);
        }
    } else if proof.is_none() {
        return Err(VerifyBlockError::ShapeMismatch);
    }
    validate::validate_block_auth_sidecar_shape(block, auth_sidecar)?;

    let proof_len = match proof {
        Some(proof) => bincode::serialized_size(proof)
            .map_err(|_| VerifyBlockError::ShapeMismatch)?
            .min(u64::MAX),
        None => 0,
    };
    let auth_sidecar_len = if user_txs == 0 {
        0
    } else {
        bincode::serialized_size(auth_sidecar)
            .map_err(|_| VerifyBlockError::AuthSidecarShapeMismatch)?
            .min(u64::MAX)
    };
    let block_body_len = block.to_bytes().len() as u64;

    Ok(AcceptedBlockClaimTranscript {
        predicate_version: validate::ACCEPT_BLOCK_PREDICATE_VERSION,
        block: AcceptedBlockHeaderClaim::from_header(&block.header),
        context: AcceptedBlockContextClaim {
            parent: AcceptedBlockHeaderClaim::from_header(parent),
            prev_timestamps: prev_timestamps.to_vec(),
            prev_active_counts: prev_active_counts.to_vec(),
            asert_anchor_height: anchor.anchor_height,
            asert_anchor_timestamp: anchor.anchor_timestamp,
            asert_anchor_target: anchor.anchor_target,
        },
        resources: AcceptedBlockResourceClaim {
            block_body_len,
            block_proof_len: proof_len,
            auth_sidecar_len,
            tx_count: block.transactions.len() as u32,
            user_tx_count: user_txs as u32,
            live_input_count: live_inputs as u32,
            output_count: outputs as u32,
            state_frontier_node_count: state_frontier_nodes as u32,
        },
    })
}

fn digest_to_fields(digest: &[u8; 32]) -> [Block128; 2] {
    [
        Block128::from(u128::from_le_bytes(digest[..16].try_into().unwrap())),
        Block128::from(u128::from_le_bytes(digest[16..].try_into().unwrap())),
    ]
}

fn push_digest_fields(fields: &mut Vec<Block128>, digest: &[u8; 32]) {
    let [lo, hi] = digest_to_fields(digest);
    fields.push(lo);
    fields.push(hi);
}

fn push_header_claim_fields(fields: &mut Vec<Block128>, claim: &AcceptedBlockHeaderClaim) {
    push_digest_fields(fields, &claim.block_id);
    push_digest_fields(fields, &claim.prev_block_hash);
    push_digest_fields(fields, &claim.state_root);
    push_digest_fields(fields, &claim.tx_root);
    fields.push(Block128::from(claim.timestamp as u128));
    fields.push(Block128::from(claim.height as u128));
    let [miner_hi, miner_lo] = claim.miner_address.as_fields();
    fields.push(miner_hi);
    fields.push(miner_lo);
    fields.push(Block128::from(claim.nonce));
    push_digest_fields(fields, &claim.difficulty_target);
    fields.push(Block128::from(claim.log_slots as u128));
    fields.push(Block128::from(claim.active_slot_count as u128));
    fields.push(Block128::from(claim.alloc_counter as u128));
}

fn push_u64_window_fields(fields: &mut Vec<Block128>, values: &[u64], max_len: usize) {
    let keep = values.len().min(max_len);
    let start = values.len().saturating_sub(keep);
    fields.push(Block128::from(keep as u128));
    for &value in &values[start..] {
        fields.push(Block128::from(value as u128));
    }
    for _ in keep..max_len {
        fields.push(Block128::ZERO);
    }
}

pub const ACCEPTED_BLOCK_CLAIM_FIELDS: usize = 80;

pub fn accepted_block_claim_fields_from_transcript(
    transcript: &AcceptedBlockClaimTranscript,
) -> [Block128; ACCEPTED_BLOCK_CLAIM_FIELDS] {
    let mut fields = Vec::with_capacity(ACCEPTED_BLOCK_CLAIM_FIELDS);
    fields.push(Block128::from(transcript.predicate_version as u128));
    push_header_claim_fields(&mut fields, &transcript.block);
    push_header_claim_fields(&mut fields, &transcript.context.parent);
    push_u64_window_fields(
        &mut fields,
        &transcript.context.prev_timestamps,
        MEDIAN_TIME_BLOCKS,
    );
    push_u64_window_fields(
        &mut fields,
        &transcript.context.prev_active_counts,
        EXPANSION_WINDOW as usize,
    );
    fields.push(Block128::from(
        transcript.context.asert_anchor_height as u128,
    ));
    fields.push(Block128::from(
        transcript.context.asert_anchor_timestamp as u128,
    ));
    push_digest_fields(&mut fields, &transcript.context.asert_anchor_target);
    fields.push(Block128::from(transcript.resources.block_body_len as u128));
    fields.push(Block128::from(transcript.resources.block_proof_len as u128));
    fields.push(Block128::from(
        transcript.resources.auth_sidecar_len as u128,
    ));
    fields.push(Block128::from(transcript.resources.tx_count as u128));
    fields.push(Block128::from(transcript.resources.user_tx_count as u128));
    fields.push(Block128::from(
        transcript.resources.live_input_count as u128,
    ));
    fields.push(Block128::from(transcript.resources.output_count as u128));
    fields.push(Block128::from(
        transcript.resources.state_frontier_node_count as u128,
    ));
    fields
        .try_into()
        .expect("accepted-block claim schedule has fixed 80-field length")
}

pub fn accepted_block_claim_hash_from_transcript(
    transcript: &AcceptedBlockClaimTranscript,
) -> [u8; 32] {
    let fields = accepted_block_claim_fields_from_transcript(transcript);
    let mut sponge = Poseidon2bSponge::with_iv(capacity_iv(TAG_ACCBLK));
    for pair in fields.chunks_exact(2) {
        sponge.absorb_pair(pair[0], pair[1]);
    }
    sponge.finalize_no_pad()
}

pub fn accepted_block_claim_from_transcript(
    transcript: &AcceptedBlockClaimTranscript,
) -> [Block128; 2] {
    let hash = accepted_block_claim_hash_from_transcript(transcript);
    digest_to_fields(&hash)
}

#[allow(clippy::too_many_arguments)]
pub fn accepted_block_claim_hash(
    block: &Block,
    parent: &BlockHeader,
    prev_timestamps: &[u64],
    prev_active_counts: &[u64],
    anchor: &AnchorInfo,
    proof: Option<&BlockProof>,
    auth_sidecar: &BlockAuthSidecar,
) -> Result<[u8; 32], VerifyBlockError> {
    let transcript = accepted_block_claim_transcript(
        block,
        parent,
        prev_timestamps,
        prev_active_counts,
        anchor,
        proof,
        auth_sidecar,
    )?;
    Ok(accepted_block_claim_hash_from_transcript(&transcript))
}

#[allow(clippy::too_many_arguments)]
pub fn accepted_block_claim(
    block: &Block,
    parent: &BlockHeader,
    prev_timestamps: &[u64],
    prev_active_counts: &[u64],
    anchor: &AnchorInfo,
    proof: Option<&BlockProof>,
    auth_sidecar: &BlockAuthSidecar,
) -> Result<[Block128; 2], VerifyBlockError> {
    let transcript = accepted_block_claim_transcript(
        block,
        parent,
        prev_timestamps,
        prev_active_counts,
        anchor,
        proof,
        auth_sidecar,
    )?;
    Ok(accepted_block_claim_from_transcript(&transcript))
}

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum VerifyBlockError {
    ShapeMismatch,
    /// `BlockProof.meta.prev_block_state_root` must equal the parent header's
    /// state root. Otherwise the proof is for a different chain state.
    PrevStateRootMismatch,
    /// `BlockProof.meta.new_state_root` must equal the candidate block header's
    /// state root. Otherwise the proved transition is not the accepted header.
    NewStateRootMismatch,
    /// Canonical public transaction predicates reconstructed from `TxBody` failed.
    TxPublicInputsMismatch {
        tx_index: usize,
    },
    /// Exact public transaction predicate failed before authorization/state checks.
    TxPublicLogic {
        tx_index: usize,
        error: noid_tx::PublicLogicError,
    },
    AuthKillShot(usize),
    AuthSpineBridge(usize),
    /// Exact action-surface reconstruction found an input whose tx-body
    /// `(slot,value,owner)` claim does not match the sequential pre-state view.
    ExactStateSurfaceInputMismatch {
        tx_index: usize,
        input_index: usize,
    },
    /// Exact action-surface reconstruction found an output slot that is
    /// not empty in the sequential pre-state view for that transaction.
    ExactStateSurfaceOutputOccupied {
        tx_index: usize,
        output_index: usize,
    },
    /// Two valid inputs in one transaction target the same slot.
    ExactStateSurfaceDuplicateInputSlot {
        tx_index: usize,
    },
    /// Two valid outputs in one transaction target the same slot.
    ExactStateSurfaceDuplicateOutputSlot {
        tx_index: usize,
    },
    /// One transaction tries to spend and mint the same slot.
    ExactStateSurfaceInputOutputSlotOverlap {
        tx_index: usize,
    },
    /// The tx-body claims commitment does not match the reconstructed exact surface.
    ExactStateSurfaceClaimsCommitmentMismatch {
        tx_index: usize,
    },
    /// A tx input/output slot is outside the current state vector.
    ExactStateSurfaceSlotOutOfRange {
        tx_index: usize,
    },
    /// Public AuthGKR sidecar length, ordering, or tx-shape tags are invalid.
    AuthSidecarShapeMismatch,
    /// Block proof/sidecar/body plus admission verification work exceed the
    /// configured DoS resource-weight limit.
    BlockResourceWeightExceeded,
    /// Exact authenticated state transition proof failed.
    ExactStateTransition(ExactStateTransitionError),
    /// Accepted state-transition claim cannot be derived from the accepted block.
    HistoryClaimMismatch,
}

#[cfg(test)]
mod tests {
    use super::*;
    use noid_chain::block::{compute_tx_root, Block};
    use noid_chain::block_header::BlockHeader;
    use noid_chain::consensus::AnchorInfo;
    use noid_poseidon2b::primitives::{Address, SpendSecret};
    use noid_tx::{hash_tx_body_for_shape, Transaction, TxBody, TxInput, TxOutput, TxShape};

    fn header(height: u64, parent: Option<&BlockHeader>, txs: &[Transaction]) -> BlockHeader {
        let prev_block_hash = parent
            .map(noid_chain::hash_block_header)
            .unwrap_or([0u8; 32]);
        BlockHeader {
            prev_block_hash,
            state_root: [height as u8; 32],
            tx_root: compute_tx_root(txs),
            timestamp: 1_767_225_600 + height * 15,
            height,
            miner_address: Address([0x44; 32]),
            nonce: height as u128,
            difficulty_target: [0xFF; 32],
            log_slots: 24,
            active_slot_count: height,
            alloc_counter: height,
        }
    }

    fn anchor(parent: &BlockHeader) -> AnchorInfo {
        AnchorInfo {
            anchor_height: parent.height,
            anchor_timestamp: parent.timestamp,
            anchor_target: parent.difficulty_target,
        }
    }

    fn minimal_proof(parent: &BlockHeader, block: &Block, n_tx: u32) -> BlockProof {
        BlockProof::minimal(
            parent.state_root,
            block.header.state_root,
            n_tx,
            ExactStateTransitionProof {
                slot_siblings: Vec::new(),
                guard_update: None,
            },
        )
    }

    fn user_tx() -> Transaction {
        let body = TxBody {
            shape: TxShape::Standard4x8,
            epoch_anchor: [0u8; 32],
            fee: 0,
            inputs: vec![TxInput {
                slot_index: 1,
                value: 100,
                owner: Address([0x11; 32]),
                spend_secret: SpendSecret([0x22; 32]),
                valid: true,
            }],
            outputs: vec![TxOutput {
                slot_index: 2,
                value: 90,
                owner: Address([0x33; 32]),
                valid: true,
            }],
            is_coinbase: false,
        };
        let tx_body_hash = hash_tx_body_for_shape(
            body.shape,
            &body.epoch_anchor,
            body.fee,
            &body.inputs,
            &body.outputs,
            body.is_coinbase,
        );
        Transaction { body, tx_body_hash }
    }

    #[test]
    fn accepted_block_claim_binds_context_and_rejects_wrong_witness_shape() {
        let parent = header(0, None, &[]);
        let block = Block {
            header: header(1, Some(&parent), &[]),
            transactions: vec![],
        };
        let empty_sidecar = BlockAuthSidecar::default();
        let a = accepted_block_claim_hash(
            &block,
            &parent,
            &[parent.timestamp],
            &[parent.active_slot_count],
            &anchor(&parent),
            None,
            &empty_sidecar,
        )
        .unwrap();
        let b = accepted_block_claim_hash(
            &block,
            &parent,
            &[parent.timestamp + 1],
            &[parent.active_slot_count],
            &anchor(&parent),
            None,
            &empty_sidecar,
        )
        .unwrap();
        assert_ne!(a, b, "MTP context must bind the accepted-block claim");

        let proof = minimal_proof(&parent, &block, 0);
        assert!(
            accepted_block_claim_hash(
                &block,
                &parent,
                &[parent.timestamp],
                &[parent.active_slot_count],
                &anchor(&parent),
                Some(&proof),
                &empty_sidecar,
            )
            .is_err(),
            "coinbase-only block without detached proof must reject carried proof metadata"
        );
    }

    #[test]
    fn accepted_block_claim_rejects_user_tx_without_block_proof() {
        let tx = user_tx();
        let parent = header(0, None, &[]);
        let block = Block {
            header: header(1, Some(&parent), std::slice::from_ref(&tx)),
            transactions: vec![tx],
        };
        let err = accepted_block_claim_hash(
            &block,
            &parent,
            &[parent.timestamp],
            &[parent.active_slot_count],
            &anchor(&parent),
            None,
            &BlockAuthSidecar::default(),
        )
        .unwrap_err();
        assert!(matches!(err, VerifyBlockError::ShapeMismatch));
    }
}
