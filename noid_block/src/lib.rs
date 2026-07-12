// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Minimal production block proof kernel.
//!
//! Current block validity is:
//! - exact public transaction predicates reconstructed from `TxBody`;
//! - one single-owner authorization proof per non-coinbase transaction;
//! - exact authenticated UTXO state transition.

pub mod accepted_block_batch;
pub mod accepted_block_certificate;
pub mod exact_state_killshot;
pub mod exact_state_transition;
pub mod history_claim;
pub mod validate;

pub use accepted_block_batch::{
    accepted_block_certificate_batch_statement_from_full_accepted_output,
    accepted_claim_batch_digest, history_checkpoint_batch_summary_from_full_accepted_output,
    prove_accepted_block_certificate_batch_checkpoint_package,
    prove_history_checkpoint_step_proof_from_verified_full_accepted_output,
    prove_retained_block_certificate_batch_checkpoint_package,
    prove_retained_block_certificate_batch_checkpoint_package_from_boundary,
    prove_retained_full_accepted_block_batch_proof, public_history_checkpoint_proof_from_package,
    reconstruct_selected_recursive_block_artifacts,
    reconstruct_selected_recursive_block_artifacts_from_single_witness,
    verify_accepted_block_certificate_batch_checkpoint_package,
    verify_full_accepted_block_batch_native,
    verify_history_checkpoint_step_proof_with_verified_full_accepted_output,
    verify_retained_full_accepted_block_batch_proof,
    AcceptedBlockCertificateBatchCheckpointPackage, AcceptedBlockCertificateBatchItem,
    AcceptedBlockCertificateBatchWitness, FullAcceptedBlockBatchError, FullAcceptedBlockBatchItem,
    FullAcceptedBlockBatchOutput, FullAcceptedBlockBatchProofComponents,
    FullAcceptedBlockBatchWitness, RetainedFullAcceptedBlockBatchProof,
    SelectedRecursiveBlockArtifacts,
};
pub use accepted_block_certificate::{
    accepted_block_certificate_batch_statement, accepted_block_certificate_batch_statement_digest,
    accepted_block_certificate_chain_claim, accepted_block_certificate_record,
    accepted_block_certificate_statement, accepted_block_certificate_statement_digest,
    accepted_block_post_validation_bundle, block_proof_acceptance_receipt,
    block_proof_acceptance_receipt_digest, verify_accepted_block_certificate_statement_native,
    AcceptedBlockCertificateBatchError, AcceptedBlockCertificateBatchStatement,
    AcceptedBlockCertificateRecord, AcceptedBlockCertificateRecordError,
    AcceptedBlockCertificateStatement, AcceptedBlockPostValidationBundle,
    BlockProofAcceptanceReceipt,
};

pub use exact_state_killshot::{
    derive_exact_state_killshot_inputs, derive_exact_state_structural_killshot_inputs,
    prove_exact_state_killshot, prove_exact_state_structural_killshot, verify_exact_state_killshot,
    verify_exact_state_structural_killshot, ExactStateKillShotError, ExactStateKillShotInputs,
    ExactStateKillShotProof, ExactStateStructuralFrontierInputs,
    EXACT_STATE_STRUCTURAL_HASH_CHUNK_SIZE, TRANSITIONAL_INLINE_EXACT_STATE_MAX_PATHS,
};
pub use exact_state_transition::{
    build_exact_state_transition_proof, build_exact_state_transition_proof_from_siblings,
    derive_exact_slot_leaf_batch_inputs, derive_exact_state_merkle_batch_inputs,
    derive_exact_state_structural_hash_batch_inputs, exact_state_structural_hash_chunk_plan,
    exact_state_structural_hash_ghost_input, exact_state_structural_hash_params,
    verify_exact_state_transition, ExactSlotLeafBatchInputs, ExactStateMerkleBatchInputs,
    ExactStateStructuralHashBatchInputs, ExactStateStructuralHashChunkPlan,
    ExactStateTransitionError, ExactStateTransitionInputs, ExactStateTransitionProof,
    VerifiedStateTransition,
};
pub use history_claim::{
    accepted_state_transition_chain_claim, accepted_state_transition_claim_digest,
    accepted_state_transition_claim_fields, AcceptedStateTransitionClaim,
    ACCEPTED_STATE_TRANSITION_CLAIM_FIELDS,
};
pub use validate::{
    accept_block, accept_block_timeless, accept_block_timeless_with_artifacts,
    accept_block_timeless_with_artifacts_with_auth_verifier, accept_block_with_artifacts,
    accept_block_with_artifacts_with_auth_verifier, validate_block_auth_sidecar_shape,
    validate_block_authorizations, validate_block_full, validate_block_full_timeless,
    validate_block_full_timeless_with_artifacts, AcceptedBlockRawValidationOutput,
    AcceptedBlockValidationArtifacts, AcceptedBlockValidationOutput, AuthorizationProof,
    AuthorizationVerifier, BlockTxEpochContext, CanonicalAuthorizationStatement,
    FullValidationError, OwnerAuthAuthorizationVerifier, PreverifiedAuthorizationVerifier,
    VerifiedAuthorization, VerifiedAuthorizationBatch,
};

use crate::exact_state_transition::ExactStateTransitionProof as BlockExactStateTransitionProof;
use noid_chain::consensus::params::{EXPANSION_WINDOW, MEDIAN_TIME_BLOCKS};
use noid_chain::consensus::validation::AnchorInfo;
use noid_chain::{hash_block_header, Block, BlockHeader};
use noid_core::{Block128, TowerField};
use noid_gkr::zk_authorization::ZkAuthorizationProof;
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
    /// Exact authenticated UTXO state transition proof.
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
#[derive(Debug, Clone, Default)]
pub struct BlockAuthSidecar {
    /// One auth proof per non-coinbase transaction in canonical block order.
    pub tx_auth: Vec<ZkAuthorizationProof>,
}

const BLOCK_AUTH_SIDECAR_MAGIC: [u8; 8] = *b"NOIDAZK1";
const BLOCK_AUTH_SIDECAR_HEADER_BYTES: usize = BLOCK_AUTH_SIDECAR_MAGIC.len() + 2;
const BLOCK_AUTH_SIDECAR_PROOF_LEN_BYTES: usize = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockAuthSidecarCodecError {
    TooLarge {
        actual: usize,
        max: usize,
    },
    InvalidMagic,
    ProofCount {
        actual: usize,
        max: usize,
    },
    Truncated,
    ProofLength {
        index: usize,
        actual: usize,
        max: usize,
    },
    ProofEncode {
        index: usize,
    },
    ProofDecode {
        index: usize,
    },
    TrailingBytes {
        remaining: usize,
    },
    LengthOverflow,
}

impl std::fmt::Display for BlockAuthSidecarCodecError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for BlockAuthSidecarCodecError {}

impl BlockAuthSidecar {
    /// Encode the versioned production sidecar. Each selected proof first
    /// passes its own allocation-bounded canonical codec.
    pub fn to_bytes(&self) -> Result<Vec<u8>, BlockAuthSidecarCodecError> {
        use noid_chain::consensus::params::BLOCK_MAX_USER_TXS;
        use noid_chain::consensus::wire_limits::MAX_BLOCK_AUTH_SIDECAR_BYTES;
        use noid_gkr::ZK_AUTHORIZATION_MAX_WIRE_BYTES;

        if self.tx_auth.len() > BLOCK_MAX_USER_TXS {
            return Err(BlockAuthSidecarCodecError::ProofCount {
                actual: self.tx_auth.len(),
                max: BLOCK_MAX_USER_TXS,
            });
        }
        let capacity = self
            .tx_auth
            .len()
            .checked_mul(BLOCK_AUTH_SIDECAR_PROOF_LEN_BYTES + ZK_AUTHORIZATION_MAX_WIRE_BYTES)
            .and_then(|proofs| BLOCK_AUTH_SIDECAR_HEADER_BYTES.checked_add(proofs))
            .ok_or(BlockAuthSidecarCodecError::LengthOverflow)?;
        if capacity > MAX_BLOCK_AUTH_SIDECAR_BYTES {
            return Err(BlockAuthSidecarCodecError::TooLarge {
                actual: capacity,
                max: MAX_BLOCK_AUTH_SIDECAR_BYTES,
            });
        }

        let mut bytes = Vec::with_capacity(capacity);
        bytes.extend_from_slice(&BLOCK_AUTH_SIDECAR_MAGIC);
        bytes.extend_from_slice(&(self.tx_auth.len() as u16).to_le_bytes());
        for (index, proof) in self.tx_auth.iter().enumerate() {
            let proof = proof
                .to_bytes()
                .map_err(|_| BlockAuthSidecarCodecError::ProofEncode { index })?;
            let proof_len = u32::try_from(proof.len())
                .map_err(|_| BlockAuthSidecarCodecError::LengthOverflow)?;
            bytes.extend_from_slice(&proof_len.to_le_bytes());
            bytes.extend_from_slice(&proof);
        }
        debug_assert_eq!(bytes.len(), self.byte_len());
        Ok(bytes)
    }

    /// Decode the versioned production sidecar without trusting any
    /// attacker-controlled allocation length. Count and every proof length
    /// are checked before allocating or invoking the selected proof decoder.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, BlockAuthSidecarCodecError> {
        use noid_chain::consensus::params::BLOCK_MAX_USER_TXS;
        use noid_chain::consensus::wire_limits::MAX_BLOCK_AUTH_SIDECAR_BYTES;
        use noid_gkr::ZK_AUTHORIZATION_MAX_WIRE_BYTES;

        if bytes.len() > MAX_BLOCK_AUTH_SIDECAR_BYTES {
            return Err(BlockAuthSidecarCodecError::TooLarge {
                actual: bytes.len(),
                max: MAX_BLOCK_AUTH_SIDECAR_BYTES,
            });
        }
        if bytes.len() < BLOCK_AUTH_SIDECAR_HEADER_BYTES {
            return Err(BlockAuthSidecarCodecError::Truncated);
        }
        if bytes[..BLOCK_AUTH_SIDECAR_MAGIC.len()] != BLOCK_AUTH_SIDECAR_MAGIC {
            return Err(BlockAuthSidecarCodecError::InvalidMagic);
        }
        let mut offset = BLOCK_AUTH_SIDECAR_MAGIC.len();
        let count = u16::from_le_bytes(
            bytes[offset..offset + 2]
                .try_into()
                .expect("two sidecar count bytes"),
        ) as usize;
        offset += 2;
        if count > BLOCK_MAX_USER_TXS {
            return Err(BlockAuthSidecarCodecError::ProofCount {
                actual: count,
                max: BLOCK_MAX_USER_TXS,
            });
        }
        let minimum = offset
            .checked_add(
                count
                    .checked_mul(BLOCK_AUTH_SIDECAR_PROOF_LEN_BYTES)
                    .ok_or(BlockAuthSidecarCodecError::LengthOverflow)?,
            )
            .ok_or(BlockAuthSidecarCodecError::LengthOverflow)?;
        if minimum > bytes.len() {
            return Err(BlockAuthSidecarCodecError::Truncated);
        }

        let mut tx_auth = Vec::with_capacity(count);
        for index in 0..count {
            let length_end = offset
                .checked_add(BLOCK_AUTH_SIDECAR_PROOF_LEN_BYTES)
                .ok_or(BlockAuthSidecarCodecError::LengthOverflow)?;
            if length_end > bytes.len() {
                return Err(BlockAuthSidecarCodecError::Truncated);
            }
            let proof_len = u32::from_le_bytes(
                bytes[offset..length_end]
                    .try_into()
                    .expect("four sidecar proof-length bytes"),
            ) as usize;
            offset = length_end;
            if proof_len > ZK_AUTHORIZATION_MAX_WIRE_BYTES {
                return Err(BlockAuthSidecarCodecError::ProofLength {
                    index,
                    actual: proof_len,
                    max: ZK_AUTHORIZATION_MAX_WIRE_BYTES,
                });
            }
            let proof_end = offset
                .checked_add(proof_len)
                .ok_or(BlockAuthSidecarCodecError::LengthOverflow)?;
            if proof_end > bytes.len() {
                return Err(BlockAuthSidecarCodecError::Truncated);
            }
            let proof = ZkAuthorizationProof::from_bytes(&bytes[offset..proof_end])
                .map_err(|_| BlockAuthSidecarCodecError::ProofDecode { index })?;
            tx_auth.push(proof);
            offset = proof_end;
        }
        if offset != bytes.len() {
            return Err(BlockAuthSidecarCodecError::TrailingBytes {
                remaining: bytes.len() - offset,
            });
        }
        Ok(Self { tx_auth })
    }

    pub fn byte_len(&self) -> usize {
        BLOCK_AUTH_SIDECAR_HEADER_BYTES
            + self
                .tx_auth
                .iter()
                .map(|proof| BLOCK_AUTH_SIDECAR_PROOF_LEN_BYTES + proof.serialized_byte_len())
                .sum::<usize>()
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
    /// Missing digest nodes in the canonical structural multiproof frontier.
    pub state_frontier_node_count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AcceptedBlockClaimTranscript {
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
    let block_body_len = block
        .canonical_wire_len()
        .map_err(|_| VerifyBlockError::BlockResourceWeightExceeded)?
        as u64;
    let (user_txs, live_inputs, outputs, state_frontier_nodes) =
        crate::validate::block_resource_counts(block)
            .map_err(|_| VerifyBlockError::BlockResourceWeightExceeded)?;
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
        u64::try_from(auth_sidecar.byte_len())
            .map_err(|_| VerifyBlockError::AuthSidecarShapeMismatch)?
    };
    Ok(AcceptedBlockClaimTranscript {
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
    fields.push(Block128::ZERO);
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
    AuthorizationProofRejected(usize),
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
    ExactStateSurfaceBlockSlotConflict {
        tx_index: usize,
        op_index: usize,
    },
    /// The tx-body claims commitment does not match the reconstructed exact surface.
    ExactStateSurfaceClaimsCommitmentMismatch {
        tx_index: usize,
    },
    /// A tx input/output slot is outside the current state vector.
    ExactStateSurfaceSlotOutOfRange {
        tx_index: usize,
    },
    /// Assigning the next live output incarnation would overflow the
    /// consensus allocation counter.
    ExactStateSurfaceAllocationCounterOverflow {
        tx_index: usize,
        output_index: usize,
    },
    /// The compact action counters cannot represent the reconstructed block.
    ExactStateSurfaceActionCountOverflow,
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
    use noid_poseidon2b::primitives::Address;
    use noid_tx::{
        output_bitmap_bit, Transaction, TxBody, TxInput, TxOutput, TX_INPUTS, TX_OUTPUTS,
    };

    #[test]
    fn selected_authorization_sidecar_codec_is_bounded_and_rejects_legacy() {
        let proof = noid_gkr::ghost_tx::prove_selected_ghost_authorization()
            .expect("fresh selected ghost proof");
        let sidecar = BlockAuthSidecar {
            tx_auth: vec![proof],
        };
        let bytes = sidecar.to_bytes().expect("encode selected sidecar");
        assert_eq!(bytes.len(), sidecar.byte_len());
        let decoded = BlockAuthSidecar::from_bytes(&bytes).expect("decode selected sidecar");
        assert_eq!(decoded.tx_auth.len(), 1);
        assert_eq!(
            decoded.tx_auth[0].to_bytes().unwrap(),
            sidecar.tx_auth[0].to_bytes().unwrap()
        );

        let mut bad_magic = bytes.clone();
        bad_magic[0] ^= 1;
        assert!(matches!(
            BlockAuthSidecar::from_bytes(&bad_magic),
            Err(BlockAuthSidecarCodecError::InvalidMagic)
        ));

        let mut too_many = bytes.clone();
        too_many[BLOCK_AUTH_SIDECAR_MAGIC.len()..BLOCK_AUTH_SIDECAR_HEADER_BYTES]
            .copy_from_slice(&256u16.to_le_bytes());
        assert!(matches!(
            BlockAuthSidecar::from_bytes(&too_many),
            Err(BlockAuthSidecarCodecError::ProofCount { .. })
        ));

        let mut oversized_proof = bytes.clone();
        oversized_proof[BLOCK_AUTH_SIDECAR_HEADER_BYTES
            ..BLOCK_AUTH_SIDECAR_HEADER_BYTES + BLOCK_AUTH_SIDECAR_PROOF_LEN_BYTES]
            .copy_from_slice(
                &((noid_gkr::ZK_AUTHORIZATION_MAX_WIRE_BYTES + 1) as u32).to_le_bytes(),
            );
        assert!(matches!(
            BlockAuthSidecar::from_bytes(&oversized_proof),
            Err(BlockAuthSidecarCodecError::ProofLength { index: 0, .. })
        ));

        let mut trailing = bytes;
        trailing.push(0);
        assert!(matches!(
            BlockAuthSidecar::from_bytes(&trailing),
            Err(BlockAuthSidecarCodecError::TrailingBytes { remaining: 1 })
        ));

        // A legacy bincode payload has no fixed selected-sidecar marker.  The
        // hard-cut decoder rejects it before attempting any proof decode; it
        // never dispatches by a legacy shape or version.
        let legacy_unframed_payload = bincode::serialize(&vec![0u64; 64])
            .expect("encode representative unframed legacy payload");
        assert!(matches!(
            BlockAuthSidecar::from_bytes(&legacy_unframed_payload),
            Err(BlockAuthSidecarCodecError::InvalidMagic)
                | Err(BlockAuthSidecarCodecError::Truncated)
        ));
    }

    fn header(height: u64, txs: &[Transaction]) -> BlockHeader {
        BlockHeader {
            prev_block_hash: [height as u8; 32],
            state_root: [0x22; 32],
            tx_root: compute_tx_root(txs),
            timestamp: 1_767_225_600 + height,
            height,
            miner_address: Address([0x33; 32]),
            nonce: height as u128,
            difficulty_target: [0xff; 32],
            log_slots: 24,
            active_slot_count: 1,
            alloc_counter: 1,
        }
    }

    fn coinbase(epoch_anchor: [u8; 32]) -> Transaction {
        let mut outputs = [TxOutput::dummy(); TX_OUTPUTS];
        outputs[0] = TxOutput {
            slot_index: 9,
            amount: 50,
            owner: Address([0x44; 32]),
        };
        Transaction::new(TxBody {
            epoch_anchor,
            fee: 0,
            input_owner: Address([0; 32]),
            inputs: [TxInput::dummy(); TX_INPUTS],
            outputs,
            validity_bitmap: output_bitmap_bit(0),
            is_coinbase: true,
        })
    }

    fn user_tx(epoch_anchor: [u8; 32]) -> Transaction {
        let owner = Address([0x55; 32]);
        let mut inputs = [TxInput::dummy(); TX_INPUTS];
        inputs[0] = TxInput {
            slot_index: 3,
            amount: 100,
            creation_id: 7,
        };
        let mut outputs = [TxOutput::dummy(); TX_OUTPUTS];
        outputs[0] = TxOutput {
            slot_index: 4,
            amount: 100,
            owner,
        };
        Transaction::new(TxBody {
            epoch_anchor,
            fee: 0,
            input_owner: owner,
            inputs,
            outputs,
            validity_bitmap: 1 | output_bitmap_bit(0),
            is_coinbase: false,
        })
    }

    fn anchor() -> AnchorInfo {
        AnchorInfo {
            anchor_height: 0,
            anchor_timestamp: 1_767_225_600,
            anchor_target: [0xff; 32],
        }
    }

    #[test]
    fn coinbase_claim_uses_final_fixed_tx_shape_counts() {
        let parent = header(0, &[]);
        let transactions = vec![coinbase(hash_block_header(&parent))];
        let block = Block {
            header: header(1, &transactions),
            transactions,
        };
        let transcript = accepted_block_claim_transcript(
            &block,
            &parent,
            &[parent.timestamp],
            &[parent.active_slot_count],
            &anchor(),
            None,
            &BlockAuthSidecar::default(),
        )
        .unwrap();

        assert_eq!(transcript.resources.tx_count, 1);
        assert_eq!(transcript.resources.user_tx_count, 0);
        assert_eq!(transcript.resources.live_input_count, 0);
        assert_eq!(transcript.resources.output_count, 1);
        assert_eq!(transcript.resources.state_frontier_node_count, 24);
        assert_eq!(
            accepted_block_claim_fields_from_transcript(&transcript).len(),
            ACCEPTED_BLOCK_CLAIM_FIELDS
        );
        assert_eq!(
            accepted_block_claim_from_transcript(&transcript),
            digest_to_fields(&accepted_block_claim_hash_from_transcript(&transcript))
        );
    }

    #[test]
    fn accepted_claim_binds_context_and_universal_tx_root() {
        let parent = header(0, &[]);
        let transactions = vec![coinbase(hash_block_header(&parent)), user_tx([0x77; 32])];
        let block = Block {
            header: header(1, &transactions),
            transactions,
        };

        let error = accepted_block_claim_transcript(
            &block,
            &parent,
            &[10, 11],
            &[1, 2],
            &anchor(),
            None,
            &BlockAuthSidecar::default(),
        )
        .unwrap_err();
        assert!(matches!(error, VerifyBlockError::ShapeMismatch));

        let coinbase_transactions = vec![coinbase(hash_block_header(&parent))];
        let coinbase_block = Block {
            header: header(1, &coinbase_transactions),
            transactions: coinbase_transactions,
        };
        let first = accepted_block_claim_transcript(
            &coinbase_block,
            &parent,
            &[10, 11],
            &[1, 2],
            &anchor(),
            None,
            &BlockAuthSidecar::default(),
        )
        .unwrap();
        let second = accepted_block_claim_transcript(
            &coinbase_block,
            &parent,
            &[10, 12],
            &[1, 2],
            &anchor(),
            None,
            &BlockAuthSidecar::default(),
        )
        .unwrap();
        assert_ne!(
            accepted_block_claim_hash_from_transcript(&first),
            accepted_block_claim_hash_from_transcript(&second)
        );
        assert_eq!(
            coinbase_block.header.tx_root,
            compute_tx_root(&coinbase_block.transactions)
        );
    }

    #[test]
    fn claim_transcript_rejects_oversized_in_memory_block_without_encoding() {
        let parent = header(0, &[]);
        let transactions =
            vec![coinbase(hash_block_header(&parent)); noid_chain::BLOCK_MAX_TXS + 1];
        // Do not derive a tx root: the semantic candidate is deliberately
        // beyond the universal tree and must fail on the O(1) length cap.
        let oversized = Block {
            header: header(1, &[]),
            transactions,
        };
        assert!(matches!(
            accepted_block_claim_transcript(
                &oversized,
                &parent,
                &[parent.timestamp],
                &[parent.active_slot_count],
                &anchor(),
                None,
                &BlockAuthSidecar::default(),
            ),
            Err(VerifyBlockError::BlockResourceWeightExceeded)
        ));
    }
}
