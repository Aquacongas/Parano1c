// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Minimal production block proof kernel.
//!
//! Current block validity is:
//! - exact public transaction predicates reconstructed from `TxBody`;
//! - one owner-batched authorization proof per non-coinbase transaction;
//! - exact authenticated UTXO/ReuseGuard state transition.

pub mod block_chain_context;
pub mod exact_state_transition;
pub mod validate;

pub use block_chain_context::{extract_replay_witness, BlockChainContext, ReplayWitnessError};
pub use exact_state_transition::{
    build_exact_state_transition_proof, verify_exact_state_transition, ExactStateTransitionError,
    ExactStateTransitionInputs, ExactStateTransitionProof, GuardBucketUpdateProof,
    VerifiedStateTransition,
};
pub use validate::{
    validate_block_auth_sidecar_root, validate_block_authorizations, validate_block_from_network,
    validate_block_full, validate_block_proof_transcript_hash, AuthorizationProof,
    AuthorizationVerifier, CanonicalAuthorizationStatement, FullValidationError,
    OwnerAuthAuthorizationVerifier, VerifiedAuthorization,
};

use crate::exact_state_transition::ExactStateTransitionProof as BlockExactStateTransitionProof;
use noid_core::Block128;
use noid_gkr::OwnerAuthProofKillShot;
use noid_poseidon2b::native::compression::Poseidon2bSponge;
use std::io::{self, Write};

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
    /// Reserved zero in the current minimal proof format.
    pub n_air_per_tx: u32,
    /// Reserved zero in the current minimal proof format.
    pub n_auth_slices_per_tx: u32,
    /// Reserved zero in the current minimal proof format.
    pub log_rows: u32,
    /// Reserved zero in the current minimal proof format.
    pub n_block_spine_slices: u32,
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
                n_air_per_tx: 0,
                n_auth_slices_per_tx: 0,
                log_rows: 0,
                n_block_spine_slices: 0,
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
/// raw wallet secrets. The block header binds the canonical sidecar bytes
/// through `witness_root`.
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

pub const BLOCK_AUTH_SIDECAR_ROOT_DOMAIN: &[u8] = b"NOID_BLOCK_AUTH_SIDECAR_ROOT_V1";

#[derive(serde::Serialize)]
struct BlockAuthSidecarRootEntry<'a> {
    block_tx_index: u32,
    shape: noid_tx::TxShape,
    tx_body_hash: noid_poseidon2b::primitives::TxBodyHash,
    auth_proof: &'a OwnerAuthProofKillShot,
}

#[derive(serde::Serialize)]
struct BlockAuthSidecarRootTranscript<'a> {
    domain: &'static [u8],
    entries: Vec<BlockAuthSidecarRootEntry<'a>>,
}

pub fn block_auth_sidecar_root(
    block: &noid_chain::block::Block,
    sidecar: &BlockAuthSidecar,
) -> Result<[u8; 32], VerifyBlockError> {
    let user_txs: Vec<(usize, &noid_tx::Transaction)> = block
        .transactions
        .iter()
        .enumerate()
        .filter(|(_, tx)| !tx.body.is_coinbase)
        .collect();
    if user_txs.len() != sidecar.tx_auth.len() {
        return Err(VerifyBlockError::AuthSidecarShapeMismatch);
    }

    let mut entries = Vec::with_capacity(user_txs.len());
    for ((block_tx_index, tx), auth_proof) in user_txs.into_iter().zip(sidecar.tx_auth.iter()) {
        entries.push(BlockAuthSidecarRootEntry {
            block_tx_index: block_tx_index as u32,
            shape: tx.body.shape,
            tx_body_hash: tx.tx_body_hash,
            auth_proof,
        });
    }

    let transcript = BlockAuthSidecarRootTranscript {
        domain: BLOCK_AUTH_SIDECAR_ROOT_DOMAIN,
        entries,
    };
    let mut writer = ProofTranscriptHashWriter::new();
    bincode::serialize_into(&mut writer, &transcript)
        .map_err(|_| VerifyBlockError::AuthSidecarShapeMismatch)?;
    Ok(writer.finalize())
}

// ---------------------------------------------------------------------------
// Canonical recursive block claim
// ---------------------------------------------------------------------------

pub const BLOCK_RECURSIVE_CLAIM_DOMAIN: &[u8] = b"NOID_BLOCK_RECURSIVE_CLAIM_V1";

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BlockRecursiveClaimTranscript {
    pub domain: Vec<u8>,
    pub meta: BlockPublicMeta,
    pub state_transition: BlockExactStateTransitionProof,
}

#[derive(serde::Serialize)]
struct BlockRecursiveClaimTranscriptRef<'a> {
    domain: &'static [u8],
    meta: &'a BlockPublicMeta,
    state_transition: &'a BlockExactStateTransitionProof,
}

pub fn block_recursive_claim_transcript(proof: &BlockProof) -> BlockRecursiveClaimTranscript {
    BlockRecursiveClaimTranscript {
        domain: BLOCK_RECURSIVE_CLAIM_DOMAIN.to_vec(),
        meta: proof.meta.clone(),
        state_transition: proof.state_transition.clone(),
    }
}

fn block_recursive_claim_transcript_ref(
    proof: &BlockProof,
) -> BlockRecursiveClaimTranscriptRef<'_> {
    BlockRecursiveClaimTranscriptRef {
        domain: BLOCK_RECURSIVE_CLAIM_DOMAIN,
        meta: &proof.meta,
        state_transition: &proof.state_transition,
    }
}

pub fn block_recursive_claim_bytes(proof: &BlockProof) -> Vec<u8> {
    bincode::serialize(&block_recursive_claim_transcript_ref(proof))
        .expect("BlockRecursiveClaimTranscript serialization must be infallible")
}

const PROOF_TRANSCRIPT_HASH_WRITE_BUFFER: usize = 64 * 1024;

struct ProofTranscriptHashWriter {
    sponge: Poseidon2bSponge,
    buffer: Vec<u8>,
}

impl ProofTranscriptHashWriter {
    fn new() -> Self {
        Self {
            sponge: Poseidon2bSponge::with_iv(noid_poseidon2b::native::domain::capacity_iv(
                noid_poseidon2b::native::domain::TAG_FSCHALNG,
            )),
            buffer: Vec::with_capacity(PROOF_TRANSCRIPT_HASH_WRITE_BUFFER),
        }
    }

    fn flush_buffer(&mut self) {
        if !self.buffer.is_empty() {
            self.sponge.update(&self.buffer);
            self.buffer.clear();
        }
    }

    fn finalize(mut self) -> [u8; 32] {
        self.flush_buffer();
        self.sponge.finalize()
    }
}

impl Write for ProofTranscriptHashWriter {
    fn write(&mut self, mut buf: &[u8]) -> io::Result<usize> {
        let written = buf.len();
        while !buf.is_empty() {
            if self.buffer.is_empty() && buf.len() >= PROOF_TRANSCRIPT_HASH_WRITE_BUFFER {
                self.sponge.update(buf);
                break;
            }
            let free = PROOF_TRANSCRIPT_HASH_WRITE_BUFFER - self.buffer.len();
            let take = free.min(buf.len());
            self.buffer.extend_from_slice(&buf[..take]);
            buf = &buf[take..];
            if self.buffer.len() == PROOF_TRANSCRIPT_HASH_WRITE_BUFFER {
                self.flush_buffer();
            }
        }
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.flush_buffer();
        Ok(())
    }
}

pub fn block_recursive_claim_hash(proof: &BlockProof) -> [u8; 32] {
    let mut writer = ProofTranscriptHashWriter::new();
    bincode::serialize_into(&mut writer, &block_recursive_claim_transcript_ref(proof))
        .expect("BlockRecursiveClaimTranscript serialization must be infallible");
    writer.finalize()
}

pub fn block_recursive_claim_field(proof: &BlockProof) -> Block128 {
    let hash = block_recursive_claim_hash(proof);
    let mut lo = [0u8; 16];
    lo.copy_from_slice(&hash[..16]);
    Block128::from(u128::from_le_bytes(lo))
}

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum VerifyBlockError {
    ShapeMismatch,
    ProofTranscriptHashMismatch,
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
    /// Public AuthGKR sidecar does not match the block/header witness commitment.
    AuthSidecarRootMismatch,
    /// Public AuthGKR sidecar length, ordering, or tx-shape tags are invalid.
    AuthSidecarShapeMismatch,
    /// Exact authenticated state transition proof failed.
    ExactStateTransition(ExactStateTransitionError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn borrowed_recursive_claim_serialization_matches_owned_transcript() {
        let proof = BlockProof {
            meta: BlockPublicMeta {
                prev_block_state_root: [0x11; 32],
                new_state_root: [0x22; 32],
                n_tx: 0,
                n_air_per_tx: 0,
                n_auth_slices_per_tx: 0,
                log_rows: 0,
                n_block_spine_slices: 0,
            },
            state_transition: ExactStateTransitionProof {
                slot_siblings: Vec::new(),
                guard_update: None,
            },
        };

        let owned = bincode::serialize(&block_recursive_claim_transcript(&proof)).unwrap();
        let borrowed = bincode::serialize(&block_recursive_claim_transcript_ref(&proof)).unwrap();
        assert_eq!(borrowed, owned);
        assert_eq!(
            block_recursive_claim_hash(&proof),
            noid_chain::block::proof_transcript_hash(&owned)
        );
    }

    #[test]
    fn sidecar_root_streaming_hash_matches_reference_byte_hash() {
        let transcript = BlockAuthSidecarRootTranscript {
            domain: BLOCK_AUTH_SIDECAR_ROOT_DOMAIN,
            entries: Vec::new(),
        };
        let bytes = bincode::serialize(&transcript).unwrap();
        let mut writer = ProofTranscriptHashWriter::new();
        bincode::serialize_into(&mut writer, &transcript).unwrap();
        assert_eq!(
            writer.finalize(),
            noid_chain::block::proof_transcript_hash(&bytes)
        );
    }
}
