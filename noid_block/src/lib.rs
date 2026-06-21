// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Block Folding (Deferred-Opening).
//!
//! # Protocol summary
//!
//! 1. One interleaved Merkle cap covering all N*n_per_tx columns.
//! 2. N per-tx Spine/Auth Kill-Shot proofs.
//! 3. N per-tx *algebraic* STARK transcripts (no FRI per tx).
//! 4. One block-level multipoint sumcheck reducing N per-tx terminal
//!    claims to a single `(r_block, h_block)`.
//! 5. One single FRI-Binius mixed opening at r_block.

#![allow(clippy::too_many_arguments)]

pub mod block_chain_context;
pub mod channel;
mod state_delta_claims;
pub mod validate;
pub mod witness_builder;

pub use block_chain_context::{extract_replay_witness, BlockChainContext};
pub use validate::{
    build_auth_public_list, build_spine_inputs_list, build_state_binding_airs, build_tx_airs,
    validate_block_auth_sidecar_root, validate_block_bucket_tx_indices,
    validate_block_from_network, validate_block_full, validate_block_proof_transcript_hash,
    validate_standard_bucket_tx_indices, verify_sweep_bucket_from_block, FullValidationError,
};
pub use witness_builder::{
    build_block_witnesses, build_empty_state_bindings, build_state_bindings_from_binding,
    build_tx_witness, OwnedStandardTxWitness, OwnedStateBindingWitness, OwnedSweepTxWitness,
    OwnedTxWitness,
};

use crate::channel::{
    block_multipoint_channel, compute_tx_transcript_digest, hash_to_fields, merkle_reduce,
    per_tx_algebraic_channel,
};
use noid_air::airs::block_state_binding::BlockStateBindingAir;
use noid_air::{Air, FixedColumns};
use noid_chain::fri_state::{
    cap_to_seg_root_with_depth, merkle_root_from_leaf, open_segment_at_point,
};
use noid_chain::segmented_state::SegmentColumns;
use noid_core::mle::{eq::eq_ind_partial_eval, split::split_mle_into_slices};
use noid_core::transcript::FiatShamir;
use noid_core::{AdditiveNTT, Block128, TowerField};
use noid_fri_binius::{
    interleaved_commit, prove_mixed_opening, verify_mixed_opening, InterleavedCommitment,
    InterleavedProverState, MixedOpeningProof, COMPACT_NUM_QUERIES,
};
use noid_gkr::{
    auth_gkr_channel, prove_block_spine_killshot, prove_sweep_block_spine_killshot,
    reconstruct_slot_states, sweep_auth_gkr_channel, verify_auth_killshot,
    verify_block_spine_killshot, verify_sweep_auth_killshot, verify_sweep_block_spine_killshot,
    AuthCircuit, AuthProofKillShot, AuthPublicInputs, BlockSpineProof, SpineCircuit, SpineInputs,
    SweepAuthCircuit, SweepAuthProofKillShot, SweepAuthPublicInputs, SweepBlockSpineMle,
    SweepBlockSpineProof, SweepSpineInputs,
};
use noid_poseidon2b::channel::Poseidon2bChannel;
use noid_poseidon2b::native::compression::Poseidon2bSponge;

use noid_stark::interleaved::{
    prove_air_interleaved_algebraic, verify_air_interleaved_algebraic_terminal,
    AlgebraicStarkProof, AlgebraicTerminalData, InterleavedStarkProof,
};
use noid_stark::{SliceClaim, VerifyError};
use noid_tx::PublicInputs;
use rayon::prelude::*;
use std::io::{self, Write};
use std::time::{Duration, Instant};

/// Log2 of the FRI slice size for the block-level interleaved commitment.
/// All per-tx columns (AIR + auth slices) and spine slices are padded
/// to `2^BASE_LOG` elements so `log_len = padded_log_len(SPINE_LOG_ROWS)`
/// matches this value.  Must satisfy:
///   BASE_LOG == SPINE_LOG_ROWS (both 11 → log_len 11 → 4× smaller sumcheck).
/// Public so wallet code can slice auth MLEs to the same granularity.
pub const BLOCK_BASE_LOG: usize = 11;
const BASE_LOG: usize = BLOCK_BASE_LOG;
/// Domain separator absorbed between the Merkle transcript-root and the
/// block column-opening phase of the block multipoint channel. Keeps the
/// multipoint-sumcheck phase distinct from the per-tx phases.
const BLOCK_MULTIPOINT_TAG: u128 = 0xFFFB_0000_0000_0000;
/// Domain separator for the column-axis terminal compression that follows the
/// block multipoint sumcheck before the final single-column FRI opening.
const BLOCK_COLUMN_TERMINAL_TAG: u128 = 0xFFFA_0000_0000_0000;

// ---------------------------------------------------------------------------
// Segment MLE opening (FRI + Merkle path)
// ---------------------------------------------------------------------------

/// FRI opening proof for one segment's three-column MLE + Merkle path binding.
///
/// **FRI opening**: `opening` proves `MLE([values, owners_hi, owners_lo], eval_point) = lane_values`
/// via compact interleaved FRI (same scheme as `SegmentedFriState`).
///
/// **Merkle path**: `merkle_siblings` proves `seg_root → state_root` via O(depth)
/// native Poseidon2b Merkle path verification.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SegmentMleOpening {
    pub seg_id: u16,
    /// MLE eval point (= `BlockStateBindingAir.eval_point` for this segment).
    pub eval_point: Vec<Block128>,
    /// Proved MLE evaluations `[values, owners_hi, owners_lo]` at `eval_point`.
    pub lane_values: [Block128; 3],
    /// Compact FRI interleaved commitment to the 3 segment columns.
    pub commitment: InterleavedCommitment,
    /// Mixed opening proof for the 3 columns at `eval_point`.
    pub opening: MixedOpeningProof,
    /// `seg_root = cap_to_seg_root_with_depth(commitment.cap, eff_log)` —
    /// matches what `SegmentedFriState` stores as the Merkle leaf.
    pub seg_root: [u8; 32],
    /// Poseidon2b Merkle siblings `seg_root → state_root` (bottom-up).
    /// Empty when `num_segments == 1` (single-segment / test mode).
    pub merkle_siblings: Vec<[u8; 32]>,
}

impl SegmentMleOpening {
    pub fn byte_len(&self) -> usize {
        let commit = self.commitment.cap.hashes.len() * 32;
        let opening = self.opening.byte_len();
        let eval = self.eval_point.len() * 16;
        let vals = 3 * 16;
        let seg = 32;
        let sibs = self.merkle_siblings.len() * 32;
        commit + opening + eval + vals + seg + sibs
    }
}

// ---------------------------------------------------------------------------
// Public metadata
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BlockPublicMeta {
    pub prev_block_state_root: [u8; 32],
    /// New state root (= block header's `state_root`). Used in `verify_block`
    /// to check post-state Merkle paths.
    pub new_state_root: [u8; 32],
    pub n_tx: u32,
    pub n_air_per_tx: u32,
    pub n_auth_slices_per_tx: u32,
    pub log_rows: u32,
    /// Number of block-level spine state slices committed to FRI.
    pub n_block_spine_slices: u32,
    /// Number of NativeDelta dirty-segment openings (one per touched segment; 0 = no state binding).
    pub n_state_bindings: u32,
    /// Legacy state-binding AIR column count. Production NativeDelta proofs set this to 0.
    pub state_binding_n_cols: u32,
    /// Legacy state-binding AIR log-rows. Production NativeDelta proofs set this to 0.
    pub state_binding_log_rows: u32,
}

// ---------------------------------------------------------------------------
// Shape bucket proofs
// ---------------------------------------------------------------------------

/// Public metadata for one homogeneous transaction-shape bucket inside a block.
///
/// This is the target metadata shape for mixed-shape block proofs. The Phase
/// N2/N3 migration moves the current flat standard fields into
/// `StandardBucketProof` and adds a sibling `SweepBucketProof`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ShapeBucketMeta {
    /// Transaction shape proven by this bucket.
    pub shape: noid_tx::TxShape,
    /// Indices into `Block.transactions`, in canonical block transaction order.
    /// Coinbase transactions must not appear here.
    pub tx_indices: Vec<u32>,
    /// Number of AIR columns per transaction for this shape.
    pub n_air_per_tx: u32,
    /// Number of shape-specific boundary slice columns per transaction.
    pub n_boundary_slices_per_tx: u32,
    /// Unpadded trace log rows for the shape-specific AIR.
    pub log_rows: u32,
    /// Number of block-spine state slices committed for this bucket.
    pub n_block_spine_slices: u32,
}

impl ShapeBucketMeta {
    #[inline]
    pub fn n_tx(&self) -> usize {
        self.tx_indices.len()
    }

    #[inline]
    pub fn n_cols_per_tx(&self) -> usize {
        self.n_air_per_tx as usize + self.n_boundary_slices_per_tx as usize
    }
}

/// Standard4x8 bucket proof target shape.
///
/// For the current standard-only implementation this bucket owns the existing
/// folded commitment/opening transcript. State-binding AIR transcripts and
/// segment openings remain common block-level fields on `BlockProof`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StandardBucketProof {
    pub meta: ShapeBucketMeta,
    /// Public inputs for bucket transactions, index-aligned with `meta.tx_indices`.
    pub tx_pis: Vec<PublicInputs>,
    /// Interleaved commitment for this bucket's tx/spine columns.
    pub commitment: InterleavedCommitment,
    /// Unified standard block-spine Kill-Shot proof for bucket txs.
    pub block_spine_proof: BlockSpineProof,
    /// Algebraic STARK transcripts — no FRI, one per bucket tx.
    pub tx_algebraic: Vec<AlgebraicStarkProof>,
    /// Bucket column openings at per-tx, block-spine, and bucket terminal points.
    pub block_col_openings: Vec<Block128>,
    /// Bucket-level degree-2 multipoint sumcheck rounds.
    pub block_multipoint_rounds: Vec<Vec<Block128>>,
    /// Fiat-Shamir challenges produced by the bucket multipoint transcript.
    pub block_multipoint_challenges: Vec<Block128>,
    /// Column-axis terminal-compression sumcheck rounds. This reduces the
    /// bucket terminal linear form to one opening of the flattened row×column MLE.
    pub block_column_sumcheck_rounds: Vec<Vec<Block128>>,
    /// Single-column FRI-Binius mixed opening for the flattened bucket commitment.
    pub mixed_opening: MixedOpeningProof,
    /// Initial claim for the bucket multipoint sumcheck.
    pub block_initial_claim: Block128,
}

impl StandardBucketProof {
    pub fn byte_len(&self) -> usize {
        let cap = self.commitment.cap.hashes.len() * 32;
        let alg: usize = self.tx_algebraic.iter().map(|a| a.byte_len()).sum();
        let spine = self.block_spine_proof.byte_len();
        let col_open = self.block_col_openings.len() * 16;
        let mp: usize = self
            .block_multipoint_rounds
            .iter()
            .map(|r| r.len() * 16)
            .sum();
        let challenges = self.block_multipoint_challenges.len() * 16;
        let column_sc: usize = self
            .block_column_sumcheck_rounds
            .iter()
            .map(|r| r.len() * 16)
            .sum();
        let mixed = self.mixed_opening.byte_len();
        cap + alg + spine + col_open + mp + challenges + column_sc + mixed
    }
}

/// Sweep25x2 bucket proof target shape.
///
/// The sweep block bucket mirrors the Standard4x8 split: per-tx algebraic
/// `SweepTxLogicAir` proofs and per-tx SweepAuth proofs are aggregated with one
/// block-level SweepBlockSpine proof, one bucket multipoint sumcheck, and one
/// mixed opening. Common state binding remains at `BlockProof` level.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SweepBucketProof {
    pub meta: ShapeBucketMeta,
    /// Public inputs for bucket transactions, index-aligned with `meta.tx_indices`.
    pub tx_pis: Vec<PublicInputs>,
    /// Unified block-level SweepBlockSpine Kill-Shot proof for bucket txs.
    pub block_spine_proof: SweepBlockSpineProof,
    /// Interleaved commitment for sweep AIR columns + sweep block spine slices.
    pub commitment: InterleavedCommitment,
    /// Algebraic STARK transcripts — no per-tx FRI, one per sweep tx.
    pub tx_algebraic: Vec<AlgebraicStarkProof>,
    /// Bucket column openings at per-tx terminal points.
    pub block_col_openings: Vec<Block128>,
    /// Bucket-level degree-2 multipoint sumcheck rounds.
    pub block_multipoint_rounds: Vec<Vec<Block128>>,
    /// Fiat-Shamir challenges produced by the sweep bucket multipoint transcript.
    pub block_multipoint_challenges: Vec<Block128>,
    /// Column-axis terminal-compression sumcheck rounds. This reduces the
    /// bucket terminal linear form to one opening of the flattened row×column MLE.
    pub block_column_sumcheck_rounds: Vec<Vec<Block128>>,
    /// Single-column FRI-Binius mixed opening for the flattened sweep bucket commitment.
    pub mixed_opening: MixedOpeningProof,
    /// Initial claim for the sweep bucket multipoint sumcheck.
    pub block_initial_claim: Block128,
}

impl SweepBucketProof {
    pub fn byte_len(&self) -> usize {
        bincode::serialize(self).map_or(0, |bytes| bytes.len())
    }
}

// ---------------------------------------------------------------------------
// BlockProof
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BlockProof {
    pub meta: BlockPublicMeta,
    /// Standard transaction-shape bucket. Present for standard-only blocks and
    /// for mixed blocks that contain at least one `Standard4x8` transaction.
    pub standard_bucket: Option<StandardBucketProof>,
    /// Sweep transaction-shape bucket. Present when the proof carries
    /// `Sweep25x2` wallet logic proofs bound to concrete block tx indices.
    pub sweep_bucket: Option<SweepBucketProof>,
    /// Legacy state-binding algebraic transcripts. Production NativeDelta proofs
    /// keep this empty; non-empty values are rejected by current verifiers.
    pub state_binding_algebraics: Vec<AlgebraicStarkProof>,
    /// Legacy standalone state-binding STARKs. Production NativeDelta proofs keep
    /// this empty; state transition soundness is checked by native delta identity
    /// plus pre/post segment MLE openings.
    pub state_binding_starks: Vec<InterleavedStarkProof>,
    /// FRI+Merkle opening proofs for pre-state segment MLEs (FRI + Merkle path).
    /// One per dirty segment. Binds native delta `pre_lane(r)` to `prev_state_root`.
    pub pre_state_openings: Vec<SegmentMleOpening>,
    /// FRI+Merkle opening proofs for post-state segment MLEs (FRI + Merkle path).
    /// One per dirty segment. Binds native delta `post_lane(r)` to `new_state_root`.
    pub post_state_openings: Vec<SegmentMleOpening>,
}

impl BlockProof {
    pub fn byte_len(&self) -> usize {
        let standard = self
            .standard_bucket
            .as_ref()
            .map_or(0, StandardBucketProof::byte_len);
        let sweep = self
            .sweep_bucket
            .as_ref()
            .map_or(0, SweepBucketProof::byte_len);
        let sb_alg: usize = self
            .state_binding_algebraics
            .iter()
            .map(|a| a.byte_len())
            .sum();
        let sb_stark: usize = self.state_binding_starks.iter().map(|p| p.byte_len()).sum();
        let pre: usize = self.pre_state_openings.iter().map(|o| o.byte_len()).sum();
        let post: usize = self.post_state_openings.iter().map(|o| o.byte_len()).sum();
        standard + sweep + sb_alg + sb_stark + pre + post
    }

    pub fn standard_bucket(&self) -> Result<&StandardBucketProof, VerifyBlockError> {
        self.standard_bucket
            .as_ref()
            .ok_or(VerifyBlockError::ShapeMismatch)
    }

    pub fn sweep_bucket(&self) -> Result<&SweepBucketProof, VerifyBlockError> {
        self.sweep_bucket
            .as_ref()
            .ok_or(VerifyBlockError::ShapeMismatch)
    }
}

// ---------------------------------------------------------------------------
// Public AuthGKR sidecar
// ---------------------------------------------------------------------------

/// Public per-transaction AuthGKR capsule carried outside canonical `BlockProof`.
///
/// The sidecar contains only public proof artifacts. It must never contain
/// `AuthInputs`, raw Auth MLE slices, or wallet secrets. The block header binds
/// the canonical sidecar bytes through `witness_root`; full nodes verify these
/// capsules before replaying per-tx algebraic transcripts.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum BlockTxAuthProof {
    Standard4x8(AuthProofKillShot),
    Sweep25x2(SweepAuthProofKillShot),
}

impl BlockTxAuthProof {
    pub fn byte_len(&self) -> usize {
        match self {
            Self::Standard4x8(p) => p.byte_len(),
            Self::Sweep25x2(p) => p.byte_len(),
        }
    }
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct BlockAuthSidecar {
    /// One auth proof per non-coinbase transaction in canonical block order.
    pub tx_auth: Vec<BlockTxAuthProof>,
}

impl BlockAuthSidecar {
    pub fn byte_len(&self) -> usize {
        bincode::serialize(self).map_or(0, |bytes| bytes.len())
    }
}

pub const BLOCK_AUTH_SIDECAR_ROOT_DOMAIN: &[u8] = b"NOID_BLOCK_AUTH_SIDECAR_ROOT_V1";

#[derive(serde::Serialize)]
struct BlockAuthSidecarRootEntry<'a> {
    block_tx_index: u32,
    shape: noid_tx::TxShape,
    tx_body_hash: noid_poseidon2b::primitives::TxBodyHash,
    auth_proof: &'a BlockTxAuthProof,
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
        match (tx.body.shape, auth_proof) {
            (noid_tx::TxShape::Standard4x8, BlockTxAuthProof::Standard4x8(_)) => {}
            (noid_tx::TxShape::Sweep25x2, BlockTxAuthProof::Sweep25x2(_)) => {}
            _ => return Err(VerifyBlockError::AuthSidecarShapeMismatch),
        }
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
    let bytes =
        bincode::serialize(&transcript).map_err(|_| VerifyBlockError::AuthSidecarShapeMismatch)?;
    Ok(noid_chain::block::proof_transcript_hash(&bytes))
}

pub fn split_auth_sidecar_for_buckets(
    block: &noid_chain::block::Block,
    proof: &BlockProof,
    sidecar: &BlockAuthSidecar,
) -> Result<(Vec<AuthProofKillShot>, Vec<SweepAuthProofKillShot>), VerifyBlockError> {
    // This validates block-order length/shape first, so the positional mapping below
    // cannot silently pair a proof with a different transaction shape.
    let _ = block_auth_sidecar_root(block, sidecar)?;

    let user_entries: Vec<(u32, &BlockTxAuthProof)> = block
        .transactions
        .iter()
        .enumerate()
        .filter(|(_, tx)| !tx.body.is_coinbase)
        .zip(sidecar.tx_auth.iter())
        .map(|((idx, _), proof)| (idx as u32, proof))
        .collect();

    let mut standard = Vec::new();
    if let Some(bucket) = proof.standard_bucket.as_ref() {
        standard.reserve(bucket.meta.tx_indices.len());
        for &block_idx in &bucket.meta.tx_indices {
            let Some((_, BlockTxAuthProof::Standard4x8(p))) =
                user_entries.iter().find(|(idx, _)| *idx == block_idx)
            else {
                return Err(VerifyBlockError::AuthSidecarShapeMismatch);
            };
            standard.push(p.clone());
        }
    }

    let mut sweep = Vec::new();
    if let Some(bucket) = proof.sweep_bucket.as_ref() {
        sweep.reserve(bucket.meta.tx_indices.len());
        for &block_idx in &bucket.meta.tx_indices {
            let Some((_, BlockTxAuthProof::Sweep25x2(p))) =
                user_entries.iter().find(|(idx, _)| *idx == block_idx)
            else {
                return Err(VerifyBlockError::AuthSidecarShapeMismatch);
            };
            sweep.push(p.clone());
        }
    }

    Ok((standard, sweep))
}

// ---------------------------------------------------------------------------
// Canonical recursive block claim (Phase N7)
// ---------------------------------------------------------------------------

pub const BLOCK_RECURSIVE_CLAIM_DOMAIN: &[u8] = b"NOID_BLOCK_RECURSIVE_CLAIM_V1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum StateBindingProofMode {
    Empty,
    /// Current production state transition mode: verifier reconstructs the
    /// canonical state-delta claim surface natively, verifies the delta-MLE
    /// identity at a root-derived random point, and binds pre/post lane
    /// openings to the endpoint state roots via compact segment MLE openings.
    NativeDelta,
    /// Legacy wide `BlockStateBindingAir` algebraic transcripts aggregated into
    /// a standard bucket commitment. Kept as an enum variant so old proof-shape
    /// failures are explicit, but production no longer emits this mode.
    Algebraic,
    /// Legacy standalone full STARKs for state binding. Production no longer
    /// emits this mode.
    Standalone,
    MixedInvalid,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BucketCoverageSummary {
    pub total_non_coinbase_tx: u32,
    pub standard_tx_indices: Vec<u32>,
    pub sweep_tx_indices: Vec<u32>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BlockRecursiveClaimTranscript {
    pub domain: Vec<u8>,
    pub meta: BlockPublicMeta,
    pub state_binding_mode: StateBindingProofMode,
    pub coverage: BucketCoverageSummary,
    pub standard_bucket: Option<StandardBucketProof>,
    pub sweep_bucket: Option<SweepBucketProof>,
    pub state_binding_algebraics: Vec<AlgebraicStarkProof>,
    pub state_binding_starks: Vec<InterleavedStarkProof>,
    pub pre_state_openings: Vec<SegmentMleOpening>,
    pub post_state_openings: Vec<SegmentMleOpening>,
}

#[derive(serde::Serialize)]
struct BucketCoverageSummaryRef<'a> {
    total_non_coinbase_tx: u32,
    standard_tx_indices: &'a [u32],
    sweep_tx_indices: &'a [u32],
}

#[derive(serde::Serialize)]
struct BlockRecursiveClaimTranscriptRef<'a> {
    domain: &'static [u8],
    meta: &'a BlockPublicMeta,
    state_binding_mode: StateBindingProofMode,
    coverage: BucketCoverageSummaryRef<'a>,
    standard_bucket: Option<&'a StandardBucketProof>,
    sweep_bucket: Option<&'a SweepBucketProof>,
    state_binding_algebraics: &'a [AlgebraicStarkProof],
    state_binding_starks: &'a [InterleavedStarkProof],
    pre_state_openings: &'a [SegmentMleOpening],
    post_state_openings: &'a [SegmentMleOpening],
}

pub fn state_binding_proof_mode(proof: &BlockProof) -> StateBindingProofMode {
    match (
        proof.state_binding_algebraics.is_empty(),
        proof.state_binding_starks.is_empty(),
        proof.meta.n_state_bindings,
    ) {
        (true, true, 0) => StateBindingProofMode::Empty,
        (true, true, _) => StateBindingProofMode::NativeDelta,
        (false, true, _) => StateBindingProofMode::Algebraic,
        (true, false, _) => StateBindingProofMode::Standalone,
        (false, false, _) => StateBindingProofMode::MixedInvalid,
    }
}

pub fn bucket_coverage_summary(proof: &BlockProof) -> BucketCoverageSummary {
    BucketCoverageSummary {
        total_non_coinbase_tx: proof.meta.n_tx,
        standard_tx_indices: proof
            .standard_bucket
            .as_ref()
            .map_or_else(Vec::new, |bucket| bucket.meta.tx_indices.clone()),
        sweep_tx_indices: proof
            .sweep_bucket
            .as_ref()
            .map_or_else(Vec::new, |bucket| bucket.meta.tx_indices.clone()),
    }
}

fn bucket_coverage_summary_ref(proof: &BlockProof) -> BucketCoverageSummaryRef<'_> {
    BucketCoverageSummaryRef {
        total_non_coinbase_tx: proof.meta.n_tx,
        standard_tx_indices: proof
            .standard_bucket
            .as_ref()
            .map_or(&[], |bucket| bucket.meta.tx_indices.as_slice()),
        sweep_tx_indices: proof
            .sweep_bucket
            .as_ref()
            .map_or(&[], |bucket| bucket.meta.tx_indices.as_slice()),
    }
}

pub fn block_recursive_claim_transcript(proof: &BlockProof) -> BlockRecursiveClaimTranscript {
    BlockRecursiveClaimTranscript {
        domain: BLOCK_RECURSIVE_CLAIM_DOMAIN.to_vec(),
        meta: proof.meta.clone(),
        state_binding_mode: state_binding_proof_mode(proof),
        coverage: bucket_coverage_summary(proof),
        standard_bucket: proof.standard_bucket.clone(),
        sweep_bucket: proof.sweep_bucket.clone(),
        state_binding_algebraics: proof.state_binding_algebraics.clone(),
        state_binding_starks: proof.state_binding_starks.clone(),
        pre_state_openings: proof.pre_state_openings.clone(),
        post_state_openings: proof.post_state_openings.clone(),
    }
}

fn block_recursive_claim_transcript_ref(
    proof: &BlockProof,
) -> BlockRecursiveClaimTranscriptRef<'_> {
    BlockRecursiveClaimTranscriptRef {
        domain: BLOCK_RECURSIVE_CLAIM_DOMAIN,
        meta: &proof.meta,
        state_binding_mode: state_binding_proof_mode(proof),
        coverage: bucket_coverage_summary_ref(proof),
        standard_bucket: proof.standard_bucket.as_ref(),
        sweep_bucket: proof.sweep_bucket.as_ref(),
        state_binding_algebraics: &proof.state_binding_algebraics,
        state_binding_starks: &proof.state_binding_starks,
        pre_state_openings: &proof.pre_state_openings,
        post_state_openings: &proof.post_state_openings,
    }
}

pub fn block_recursive_claim_bytes(proof: &BlockProof) -> Vec<u8> {
    bincode::serialize(&block_recursive_claim_transcript_ref(proof))
        .expect("BlockRecursiveClaimTranscript serialization must be infallible")
}

struct ProofTranscriptHashWriter {
    sponge: Poseidon2bSponge,
}

impl ProofTranscriptHashWriter {
    fn new() -> Self {
        Self {
            sponge: Poseidon2bSponge::with_iv(noid_poseidon2b::native::domain::capacity_iv(
                noid_poseidon2b::native::domain::TAG_FSCHALNG,
            )),
        }
    }

    fn finalize(self) -> [u8; 32] {
        self.sponge.finalize()
    }
}

impl Write for ProofTranscriptHashWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.sponge.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
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

#[cfg(test)]
mod recursive_claim_tests {
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
                n_state_bindings: 0,
                state_binding_n_cols: 0,
                state_binding_log_rows: 0,
            },
            standard_bucket: None,
            sweep_bucket: None,
            state_binding_algebraics: Vec::new(),
            state_binding_starks: Vec::new(),
            pre_state_openings: Vec::new(),
            post_state_openings: Vec::new(),
        };

        let owned = bincode::serialize(&block_recursive_claim_transcript(&proof)).unwrap();
        let borrowed = bincode::serialize(&block_recursive_claim_transcript_ref(&proof)).unwrap();
        assert_eq!(borrowed, owned);
        assert_eq!(
            block_recursive_claim_hash(&proof),
            noid_chain::block::proof_transcript_hash(&owned)
        );
    }
}

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum ProveBlockError {
    EmptyBlock,
    /// Bucket transaction indices are not strictly increasing block indices.
    InvalidTxIndices,
    /// The wallet's auth proof for tx at index `k` failed verification.
    /// This can happen if the proof was generated with wrong public inputs
    /// or if the proof bytes are corrupted.
    AuthProofInvalid(usize),
}

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
    /// Bucket-local public inputs are not the canonical public inputs derived
    /// from the block transaction body.
    TxPublicInputsMismatch {
        tx_index: usize,
    },
    BlockSpineKillShot,
    BlockSpineSliceReconstruction,
    AuthKillShot(usize),
    AuthSpineBridge(usize),
    AuthSliceReconstruction(usize),
    SweepLogic(usize),
    AlgebraicStark(usize, VerifyError),
    /// The algebraic STARK transcript replayed, but its multipoint terminal
    /// claim does not match the bucket column openings at the transcript's
    /// terminal point. This binds per-tx algebraic sumchecks to the block PCS
    /// aggregation without adding proof bytes.
    AlgebraicTerminal(usize),
    BlockMultipoint,
    FriFailed(String),
    /// FRI/Merkle opening for a segment MLE failed.
    StateMleOpeningFailed(usize),
    /// Verifier-side state-claim reconstruction found an input whose tx-body
    /// `(slot,value,owner)` claim does not match the sequential pre-state view.
    StateBindingInputMismatch {
        tx_index: usize,
        input_index: usize,
    },
    /// Verifier-side state-claim reconstruction found an output slot that is
    /// not empty in the sequential pre-state view for that transaction.
    StateBindingOutputOccupied {
        tx_index: usize,
        output_index: usize,
    },
    /// Two valid inputs in one transaction target the same slot.
    StateBindingDuplicateInputSlot {
        tx_index: usize,
    },
    /// Two valid outputs in one transaction target the same slot.
    StateBindingDuplicateOutputSlot {
        tx_index: usize,
    },
    /// One transaction tries to spend and mint the same slot.
    StateBindingInputOutputSlotOverlap {
        tx_index: usize,
    },
    /// The tx-body claims commitment does not match the bucket public input.
    StateBindingClaimsCommitmentMismatch {
        tx_index: usize,
    },
    /// A tx input/output slot is outside the current state vector.
    StateBindingSlotOutOfRange {
        tx_index: usize,
    },
    /// Public AuthGKR sidecar does not match the block/header witness commitment.
    AuthSidecarRootMismatch,
    /// Public AuthGKR sidecar length, ordering, or tx-shape tags are invalid.
    AuthSidecarShapeMismatch,
    /// The proof opening order must match verifier-reconstructed dirty segment
    /// order. `pre` and `post` openings must also refer to the same segment.
    StateBindingSegmentMismatch {
        state_binding_index: usize,
        expected_seg_id: u16,
        pre_seg_id: u16,
        post_seg_id: u16,
    },
    /// A transaction's PublicInputs.log_slots does not match BlockHeader.log_slots.
    /// The STARK proof is bound to the wrong chain configuration.
    LogSlotsInconsistent {
        tx_index: usize,
        pi_log_slots: u32,
        header_log_slots: u32,
    },
}

// ---------------------------------------------------------------------------
// Per-tx witness bundle
// ---------------------------------------------------------------------------

pub struct TxBlockWitness<'a> {
    /// Index into `Block.transactions`. Coinbase transactions must not be
    /// represented by `TxBlockWitness`.
    pub block_tx_index: u32,
    pub air: &'a dyn Air,
    pub trace: &'a noid_air::Trace,
    pub pi: &'a PublicInputs,
    pub spine_inputs: &'a SpineInputs,
    /// Public-only auth boundary (no spend_secret). The block prover
    /// never sees private keys.
    pub auth_public: &'a AuthPublicInputs,
    /// Pre-built self-contained auth proof capsule from the wallet. The block
    /// prover verifies it to derive transcript reductions, and the public capsule
    /// is carried in `BlockAuthSidecar` rather than canonical `BlockProof`.
    pub auth_proof: &'a AuthProofKillShot,
}

pub fn build_block_auth_sidecar(
    standard_witnesses: &[TxBlockWitness<'_>],
    sweep_witnesses: &[crate::witness_builder::OwnedSweepTxWitness],
) -> Result<BlockAuthSidecar, ProveBlockError> {
    let mut entries: Vec<(u32, BlockTxAuthProof)> =
        Vec::with_capacity(standard_witnesses.len() + sweep_witnesses.len());
    for w in standard_witnesses {
        entries.push((
            w.block_tx_index,
            BlockTxAuthProof::Standard4x8(w.auth_proof.clone()),
        ));
    }
    for w in sweep_witnesses {
        entries.push((
            w.block_tx_index,
            BlockTxAuthProof::Sweep25x2(w.auth_proof.clone()),
        ));
    }
    entries.sort_by_key(|(idx, _)| *idx);
    if !entries.windows(2).all(|w| w[0].0 < w[1].0) {
        return Err(ProveBlockError::InvalidTxIndices);
    }
    Ok(BlockAuthSidecar {
        tx_auth: entries.into_iter().map(|(_, proof)| proof).collect(),
    })
}

// ---------------------------------------------------------------------------
// Block-level state binding witness bundle
// ---------------------------------------------------------------------------

/// Optional state binding witness for prove_block.
/// When present, the BlockStateBindingAir columns are committed alongside
/// per-tx columns and proven via the shared block channel.
pub struct StateBindingBlockWitness<'a> {
    pub air: &'a BlockStateBindingAir,
    pub columns: &'a [Vec<Block128>],
    /// Segment ID for this binding. Used for FRI opening channel seeding.
    pub seg_id: u16,
    /// Pre-state segment columns for FRI opening. `None` = bench mode.
    pub pre_cols: Option<&'a SegmentColumns>,
    /// Claims used to derive post-state columns on demand.
    pub claims: &'a [noid_air::airs::block_state_binding::BlockStateBindingClaim],
    /// Merkle siblings for pre-state seg_root → prev_state_root.
    pub pre_siblings: &'a [[u8; 32]],
    /// Merkle siblings for post-state seg_root → new_state_root.
    pub post_siblings: &'a [[u8; 32]],
    /// Merkle tree depth. 0 = single-segment.
    pub tree_depth: usize,
    /// Block's new state root for post-state Merkle check.
    pub new_state_root: [u8; 32],
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn absorb_cap_into_p2b(ch: &mut Poseidon2bChannel, cap: &noid_fri_binius::MerkleCap) {
    for hash in &cap.hashes {
        let [h0, h1] = hash_to_fields(hash);
        ch.absorb(h0);
        ch.absorb(h1);
    }
}

fn reduction_to_transcript(point: &[Block128], value: Block128) -> Vec<Block128> {
    let mut out = Vec::with_capacity(point.len() + 1);
    out.extend_from_slice(point);
    out.push(value);
    out
}

/// Derive post-state columns from pre-state by applying spend/mint claims.
/// Clone is O(2^eff_log) — callers should drop the result immediately.
fn apply_claims_to_cols(
    pre: &SegmentColumns,
    claims: &[noid_air::airs::block_state_binding::BlockStateBindingClaim],
) -> SegmentColumns {
    let mut post = pre.clone();
    for c in claims {
        let i = c.slot_index as usize;
        debug_assert!(i < post.values.len());
        if c.is_spend {
            post.values[i] = Block128::ZERO;
            post.owners_hi[i] = Block128::ZERO;
            post.owners_lo[i] = Block128::ZERO;
        } else if c.is_mint {
            post.values[i] = c.value;
            post.owners_hi[i] = c.owner_hi;
            post.owners_lo[i] = c.owner_lo;
        }
    }
    post
}

#[derive(Debug)]
struct ProveBlockPhaseTiming {
    name: &'static str,
    elapsed: Duration,
}

#[derive(Debug)]
struct ProveBlockProfilerInner {
    started: Instant,
    last: Instant,
    phases: Vec<ProveBlockPhaseTiming>,
}

#[derive(Debug)]
struct ProveBlockProfiler {
    inner: Option<ProveBlockProfilerInner>,
}

impl ProveBlockProfiler {
    fn new() -> Self {
        let enabled = std::env::var("NOID_PROVE_BLOCK_PROFILE")
            .map(|v| {
                matches!(
                    v.trim().to_ascii_lowercase().as_str(),
                    "1" | "true" | "yes" | "on"
                )
            })
            .unwrap_or(false);

        if enabled {
            let now = Instant::now();
            Self {
                inner: Some(ProveBlockProfilerInner {
                    started: now,
                    last: now,
                    phases: Vec::with_capacity(16),
                }),
            }
        } else {
            Self { inner: None }
        }
    }

    fn phase(&mut self, name: &'static str) {
        if let Some(inner) = &mut self.inner {
            let now = Instant::now();
            inner.phases.push(ProveBlockPhaseTiming {
                name,
                elapsed: now.duration_since(inner.last),
            });
            inner.last = now;
        }
    }

    fn finish(
        self,
        n_tx: usize,
        n_state_bindings: usize,
        n_air_cols: usize,
        n_auth_slices: usize,
        n_block_spine_slices: usize,
        log_len: usize,
    ) {
        let Some(inner) = self.inner else {
            return;
        };

        let total = inner.started.elapsed();
        let summary = inner
            .phases
            .iter()
            .map(|p| format!("{}={:.3}ms", p.name, duration_ms(p.elapsed)))
            .collect::<Vec<_>>()
            .join(", ");

        for phase in &inner.phases {
            let elapsed_ms = duration_ms(phase.elapsed);
            tracing::info!(
                target: "noid_block::prove_block_profile",
                n_tx,
                n_state_bindings,
                phase = phase.name,
                elapsed_ms,
                "prove_block phase"
            );
            eprintln!(
                "prove_block_profile phase n_tx={} n_state_bindings={} phase={} elapsed_ms={:.3}",
                n_tx, n_state_bindings, phase.name, elapsed_ms
            );
        }

        let total_ms = duration_ms(total);
        tracing::info!(
            target: "noid_block::prove_block_profile",
            n_tx,
            n_state_bindings,
            n_air_cols,
            n_auth_slices,
            n_block_spine_slices,
            log_len,
            total_ms,
            phases = %summary,
            "prove_block phase profile"
        );
        eprintln!(
            "prove_block_profile summary n_tx={} n_state_bindings={} n_air_cols={} n_auth_slices={} n_block_spine_slices={} log_len={} total_ms={:.3} phases={}",
            n_tx,
            n_state_bindings,
            n_air_cols,
            n_auth_slices,
            n_block_spine_slices,
            log_len,
            total_ms,
            summary
        );
    }
}

fn duration_ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1_000.0
}

// ---------------------------------------------------------------------------
// Sweep bucket assembly
// ---------------------------------------------------------------------------

/// Assemble the public Sweep25x2 bucket from wallet-produced sweep witnesses.
///
/// This does not re-prove sweep logic: each `OwnedSweepTxWitness` already carries
/// the wallet-produced `SweepLogicProof`. The block bucket binds those proofs to
/// concrete block transaction indices plus canonical public inputs, and proves a
/// real aggregation transcript over sweep balance AIR columns and sweep block-spine
/// slices. AuthGKR is carried by self-contained per-tx capsules. Verification is performed by
/// `validate::verify_sweep_bucket_from_block`.
pub fn assemble_sweep_bucket_proof(
    prev_block_state_root: [u8; 32],
    witnesses: &[crate::witness_builder::OwnedSweepTxWitness],
) -> Result<Option<SweepBucketProof>, ProveBlockError> {
    if witnesses.is_empty() {
        return Ok(None);
    }

    let n_tx = witnesses.len();
    let tx_indices: Vec<u32> = witnesses.iter().map(|w| w.block_tx_index).collect();
    if !tx_indices.windows(2).all(|w| w[0] < w[1]) {
        return Err(ProveBlockError::InvalidTxIndices);
    }

    let n_air_per_tx = witnesses[0].air.n_columns();
    let public_flags = public_column_flags(&witnesses[0].air, n_air_per_tx)
        .ok_or(ProveBlockError::InvalidTxIndices)?;
    let committed_air_indices = committed_air_indices_from_public_flags(&public_flags);
    let n_auth_slices = 0usize;
    let n_per_tx = committed_air_indices.len();
    let log_rows = witnesses[0].trace.log_rows;
    let log_len = noid_stark::padded_log_len(log_rows);
    if log_len != BASE_LOG {
        return Err(ProveBlockError::InvalidTxIndices);
    }
    for w in witnesses {
        if w.air.n_columns() != n_air_per_tx
            || public_column_flags(&w.air, n_air_per_tx).as_ref() != Some(&public_flags)
            || w.trace.log_rows != log_rows
            || w.pi.shape_id != noid_tx::TxShape::Sweep25x2.id()
        {
            return Err(ProveBlockError::InvalidTxIndices);
        }
    }

    let spine_inputs: Vec<SweepSpineInputs> =
        witnesses.iter().map(|w| w.spine_inputs.clone()).collect();
    let sweep_block_spine_mle = SweepBlockSpineMle::build(&spine_inputs);
    let sweep_block_spine_num_vars = sweep_block_spine_mle.inner.num_vars;
    let block_spine_slices = split_mle_into_slices(
        &sweep_block_spine_mle.inner.state,
        sweep_block_spine_num_vars,
        BASE_LOG,
    );
    let n_block_spine_slices = block_spine_slices.len();
    let spine_padded_slices: Vec<Vec<Block128>> = block_spine_slices
        .iter()
        .map(|s| noid_stark::pad_column(s, log_len))
        .collect();

    struct SweepTxColumns {
        air_columns: Vec<Vec<Block128>>,
    }

    let mut per_tx_columns: Vec<SweepTxColumns> = Vec::with_capacity(n_tx);
    let mut flat_refs: Vec<&[Block128]> =
        Vec::with_capacity(n_tx * n_per_tx + n_block_spine_slices);
    for w in witnesses {
        let mut air_columns: Vec<Vec<Block128>> = Vec::with_capacity(n_air_per_tx);
        for col in &w.trace.columns {
            air_columns.push(noid_stark::pad_column(col, log_len));
        }
        per_tx_columns.push(SweepTxColumns { air_columns });
    }
    for cols in &per_tx_columns {
        for &col_idx in &committed_air_indices {
            flat_refs.push(cols.air_columns[col_idx].as_slice());
        }
    }
    for slice in &spine_padded_slices {
        flat_refs.push(slice.as_slice());
    }

    let total_cols = flat_refs.len();
    let log_cols = log2_padded_len(total_cols);
    let col_pad = 1usize << log_cols;
    let flat_bucket_column = build_flattened_bucket_column(&flat_refs, log_len, col_pad);
    let flat_commit_cols: [&[Block128]; 1] = [flat_bucket_column.as_slice()];
    let ntt = AdditiveNTT::<Block128>::new(log_len + log_cols + noid_fri::code::LOG_RATE);
    let hasher = Poseidon2bSponge::new();
    let (commitment, prover_state) = interleaved_commit(&flat_commit_cols, &ntt, &hasher);
    let cap = &commitment.cap;

    let tx_body_hashes: Vec<[Block128; 2]> = witnesses
        .iter()
        .map(|w| w.pi.tx_body_hash.as_fields())
        .collect();
    let mut spine_channel = Poseidon2bChannel::new();
    absorb_cap_into_p2b(&mut spine_channel, cap);
    let (block_spine_proof, block_spine_reductions) = prove_sweep_block_spine_killshot(
        n_tx,
        &sweep_block_spine_mle,
        &tx_body_hashes,
        &mut spine_channel,
    );
    let spine_r = &block_spine_reductions.state.point;
    let spine_r_low_base = &spine_r[..BASE_LOG];
    let spine_r_low: Vec<Block128> = {
        let mut v = spine_r_low_base.to_vec();
        v.resize(log_len, Block128::ZERO);
        v
    };
    let spine_slice_vals: Vec<Block128> = block_spine_slices
        .iter()
        .map(|s| noid_core::mle::evaluate::evaluate_slice(s, spine_r_low_base))
        .collect();
    let recon_spine =
        noid_core::mle::split::reconstruct_from_slices(&spine_slice_vals, &spine_r[BASE_LOG..]);
    if recon_spine != block_spine_reductions.state.value {
        return Err(ProveBlockError::InvalidTxIndices);
    }
    let spine_extras = reduction_to_transcript(spine_r, block_spine_reductions.state.value);

    let auth_circuit = SweepAuthCircuit::build();
    struct TxAlgResult {
        alg: AlgebraicStarkProof,
        r_pp: Vec<Block128>,
        final_claim: Block128,
        lambdas: Vec<Block128>,
    }

    let tx_alg_results_raw: Vec<Option<TxAlgResult>> = (0..n_tx)
        .into_par_iter()
        .map(|k| {
            let w = &witnesses[k];
            let mut auth_ch = sweep_auth_gkr_channel();
            let auth_reductions = verify_sweep_auth_killshot(
                &w.auth_proof,
                &auth_circuit,
                &w.auth_public,
                &mut auth_ch,
            )?;

            let claimed = w.pi.tx_body_hash.as_fields();
            if w.auth_public.tx_body_hash != claimed {
                return None;
            }
            let n_live = w.pi.n_live_inputs as usize;
            for i in 0..n_live {
                let owner = [
                    w.spine_inputs.input_leaves[i][2],
                    w.spine_inputs.input_leaves[i][3],
                ];
                if w.auth_public.expected_address[i] != owner {
                    return None;
                }
            }

            let r_auth = &auth_reductions.state.point;
            let auth_tr = reduction_to_transcript(r_auth, auth_reductions.state.value);
            let mut extras = Vec::with_capacity(spine_extras.len() + auth_tr.len());
            extras.extend_from_slice(&spine_extras);
            extras.extend_from_slice(&auth_tr);
            let slice_claims: Vec<SliceClaim> = Vec::new();
            let mut col_refs: Vec<&[Block128]> = Vec::with_capacity(n_per_tx);
            for col in &per_tx_columns[k].air_columns {
                col_refs.push(col.as_slice());
            }
            let mut ch = per_tx_algebraic_channel(&prev_block_state_root, cap, k as u32);
            let (alg, r_pp, final_claim, lambdas) = prove_air_interleaved_algebraic(
                &w.air,
                &col_refs,
                &w.pi,
                &extras,
                &slice_claims,
                log_len,
                &mut ch,
            );
            Some(TxAlgResult {
                alg,
                r_pp,
                final_claim,
                lambdas,
            })
        })
        .collect();

    let tx_alg_results: Vec<TxAlgResult> = tx_alg_results_raw
        .into_iter()
        .enumerate()
        .map(|(k, r)| r.ok_or(ProveBlockError::AuthProofInvalid(k)))
        .collect::<Result<Vec<_>, _>>()?;

    let mut tx_algebraic = Vec::with_capacity(n_tx);
    let mut tx_r_pp = Vec::with_capacity(n_tx);
    let mut tx_claims = Vec::with_capacity(n_tx);
    let mut tx_lambdas = Vec::with_capacity(n_tx);
    for r in tx_alg_results {
        tx_algebraic.push(r.alg);
        tx_r_pp.push(r.r_pp);
        tx_claims.push(r.final_claim);
        tx_lambdas.push(r.lambdas);
    }

    let tx_digests: Vec<[u8; 32]> = (0..n_tx)
        .into_par_iter()
        .map(|k| {
            compute_tx_transcript_digest(
                k as u32,
                &tx_r_pp[k],
                &tx_algebraic[k].base_openings,
                &tx_lambdas[k],
                tx_claims[k],
            )
        })
        .collect();
    let transcript_root = merkle_reduce(&tx_digests);

    let mut block_channel = block_multipoint_channel(&prev_block_state_root, cap);
    let [tr0, tr1] = hash_to_fields(&transcript_root);
    block_channel.observe_field_elem(tr0);
    block_channel.observe_field_elem(tr1);

    debug_assert_eq!(total_cols, n_tx * n_per_tx + n_block_spine_slices);
    let mut block_col_openings: Vec<Block128> = Vec::with_capacity(total_cols);
    thread_local! {
        static SWEEP_FLAT_SCRATCH: std::cell::RefCell<Vec<u128>> =
            std::cell::RefCell::new(Vec::new());
        static SWEEP_POINT_SCRATCH: std::cell::RefCell<Vec<u128>> =
            std::cell::RefCell::new(Vec::new());
    }
    SWEEP_FLAT_SCRATCH.with(|fs| {
        SWEEP_POINT_SCRATCH.with(|ps| {
            let mut flat = fs.borrow_mut();
            let mut point = ps.borrow_mut();
            for k in 0..n_tx {
                for &col_idx in &committed_air_indices {
                    let col = &per_tx_columns[k].air_columns[col_idx];
                    block_col_openings.push(noid_core::mle::evaluate::evaluate_flat_with_scratch(
                        col,
                        &tx_r_pp[k],
                        &mut flat,
                        &mut point,
                    ));
                }
            }
            for sp in &spine_padded_slices {
                block_col_openings.push(noid_core::mle::evaluate::evaluate_flat_with_scratch(
                    sp,
                    &spine_r_low,
                    &mut flat,
                    &mut point,
                ));
            }
        })
    });

    block_channel.observe_field_elem(Block128::from(BLOCK_MULTIPOINT_TAG));
    block_channel.observe_field_elems(&block_col_openings);
    let mu = block_channel.get_random_point();
    let beta_block = block_channel.get_random_point();

    let n_participants = n_tx + 1;
    let spine_participant_idx = n_tx;
    let mu_powers: Vec<Block128> = {
        let mut v = Vec::with_capacity(n_participants);
        let mut cur = Block128::ONE;
        for _ in 0..n_participants {
            v.push(cur);
            cur *= mu;
        }
        v
    };
    let max_cols = n_per_tx.max(n_block_spine_slices);
    let beta_powers: Vec<Block128> = {
        let mut v = Vec::with_capacity(max_cols);
        let mut cur = Block128::ONE;
        for _ in 0..max_cols {
            v.push(cur);
            cur *= beta_block;
        }
        v
    };

    let block_target: Block128 = {
        let mut target = Block128::ZERO;
        for k in 0..n_tx {
            let inner = (0..n_per_tx)
                .map(|i| beta_powers[i] * block_col_openings[k * n_per_tx + i])
                .fold(Block128::ZERO, |a, b| a + b);
            target += mu_powers[k] * inner;
        }
        let spine_offset = n_tx * n_per_tx;
        let inner_spine = (0..n_block_spine_slices)
            .map(|i| beta_powers[i] * block_col_openings[spine_offset + i])
            .fold(Block128::ZERO, |a, b| a + b);
        target += mu_powers[spine_participant_idx] * inner_spine;
        target
    };

    let all_r_pp: Vec<&[Block128]> = {
        let mut v: Vec<&[Block128]> = tx_r_pp.iter().map(|r| r.as_slice()).collect();
        v.push(&spine_r_low);
        v
    };
    let pairs_a: Vec<Vec<Block128>> = (0..n_participants)
        .into_par_iter()
        .map(|k| {
            let eq_k = eq_ind_partial_eval(all_r_pp[k]);
            eq_k.into_iter().map(|v| v * mu_powers[k]).collect()
        })
        .collect();

    use noid_core::hardware::{clmul_gcm, tower_to_flat_u128};
    let beta_powers_flat: Vec<u128> = beta_powers
        .iter()
        .map(|v| tower_to_flat_u128(v.0))
        .collect();
    let hyper_len = 1usize << log_len;
    let pairs_b_flat: Vec<Vec<u128>> = (0..n_participants)
        .into_par_iter()
        .map(|k| {
            let mut b_k = vec![0u128; hyper_len];
            if k < n_tx {
                for (i, &col_idx) in committed_air_indices.iter().enumerate() {
                    let col = per_tx_columns[k].air_columns[col_idx].as_slice();
                    let lam = beta_powers_flat[i];
                    b_k.iter_mut().zip(col.iter()).for_each(|(acc, &v)| {
                        *acc ^= clmul_gcm(lam, tower_to_flat_u128(v.0));
                    });
                }
            } else {
                for (i, col) in spine_padded_slices.iter().enumerate() {
                    let lam = beta_powers_flat[i];
                    b_k.iter_mut().zip(col.iter()).for_each(|(acc, &v)| {
                        *acc ^= clmul_gcm(lam, tower_to_flat_u128(v.0));
                    });
                }
            }
            b_k
        })
        .collect();

    let (block_multipoint_rounds, block_mp_challenges) =
        noid_stark::multipoint_batch::prove_multipoint_sumcheck_flat_b(
            pairs_a,
            pairs_b_flat,
            block_target,
            &mut block_channel,
        );
    let r_block: Vec<Block128> = block_mp_challenges.iter().rev().cloned().collect();
    let block_final_claim =
        sumcheck_terminal_claim(&block_multipoint_rounds, &block_mp_challenges, block_target);
    let participant_points: Vec<&[Block128]> = {
        let mut v: Vec<&[Block128]> = tx_r_pp.iter().map(|r| r.as_slice()).collect();
        v.push(&spine_r_low);
        v
    };
    let participant_widths: Vec<usize> = {
        let mut v = vec![n_per_tx; n_tx];
        v.push(n_block_spine_slices);
        v
    };
    let coeffs = bucket_terminal_coefficients(
        &participant_points,
        &participant_widths,
        &mu_powers,
        &beta_powers,
        &r_block,
        col_pad,
    );
    let (block_column_sumcheck_rounds, mixed_opening) = prove_bucket_linear_terminal_opening(
        &flat_refs,
        &prover_state,
        &r_block,
        &coeffs,
        block_final_claim,
        &ntt,
        &mut block_channel,
        &hasher,
    );

    Ok(Some(SweepBucketProof {
        meta: ShapeBucketMeta {
            shape: noid_tx::TxShape::Sweep25x2,
            tx_indices,
            n_air_per_tx: n_air_per_tx as u32,
            n_boundary_slices_per_tx: n_auth_slices as u32,
            log_rows: log_rows as u32,
            n_block_spine_slices: n_block_spine_slices as u32,
        },
        tx_pis: witnesses.iter().map(|w| w.pi.clone()).collect(),
        block_spine_proof,
        commitment,
        tx_algebraic,
        block_col_openings,
        block_multipoint_rounds,
        block_multipoint_challenges: block_mp_challenges,
        block_column_sumcheck_rounds,
        mixed_opening,
        block_initial_claim: block_target,
    }))
}

fn prove_state_mle_openings_only(
    state_bindings: &[StateBindingBlockWitness<'_>],
) -> (Vec<SegmentMleOpening>, Vec<SegmentMleOpening>) {
    let results: Vec<(Option<SegmentMleOpening>, Option<SegmentMleOpening>)> = state_bindings
        .par_iter()
        .map(|sb| {
            let Some(pre_cols) = sb.pre_cols else {
                return (None, None);
            };
            let seg_id = sb.seg_id;
            let eff_log = sb.air.eval_point.len();

            let (pre_opening, post_opening) = rayon::join(
                || {
                    let (pre_commit, pre_vals, pre_proof, pre_seg_root) = open_segment_at_point(
                        eff_log,
                        &pre_cols.values,
                        &pre_cols.owners_hi,
                        &pre_cols.owners_lo,
                        &sb.air.eval_point,
                    );
                    SegmentMleOpening {
                        seg_id,
                        eval_point: sb.air.eval_point.clone(),
                        lane_values: pre_vals,
                        commitment: pre_commit,
                        opening: pre_proof,
                        seg_root: pre_seg_root,
                        merkle_siblings: sb.pre_siblings.to_vec(),
                    }
                },
                || {
                    let post_cols = apply_claims_to_cols(pre_cols, sb.claims);
                    let (post_commit, post_vals, post_proof, post_seg_root) = open_segment_at_point(
                        eff_log,
                        &post_cols.values,
                        &post_cols.owners_hi,
                        &post_cols.owners_lo,
                        &sb.air.eval_point,
                    );
                    SegmentMleOpening {
                        seg_id,
                        eval_point: sb.air.eval_point.clone(),
                        lane_values: post_vals,
                        commitment: post_commit,
                        opening: post_proof,
                        seg_root: post_seg_root,
                        merkle_siblings: sb.post_siblings.to_vec(),
                    }
                },
            );
            (Some(pre_opening), Some(post_opening))
        })
        .collect();

    let mut pre_state_openings: Vec<SegmentMleOpening> = Vec::with_capacity(results.len());
    let mut post_state_openings: Vec<SegmentMleOpening> = Vec::with_capacity(results.len());
    for (pre, post) in results {
        if let Some(pre) = pre {
            pre_state_openings.push(pre);
        }
        if let Some(post) = post {
            post_state_openings.push(post);
        }
    }

    (pre_state_openings, post_state_openings)
}

/// Prove block-level state transition openings for sweep-only compatibility path.
///
/// Production no longer emits standalone `BlockStateBindingAir` STARKs. The state
/// transition proof is the native state-delta identity checked by the verifier,
/// plus pre/post segment MLE openings bound to `prev_state_root` and
/// `new_state_root`. The empty first return value keeps older call sites source-
/// compatible while making the proof surface explicitly `NativeDelta`.
pub fn prove_state_bindings_standalone(
    state_bindings: &[StateBindingBlockWitness<'_>],
) -> (
    Vec<InterleavedStarkProof>,
    Vec<SegmentMleOpening>,
    Vec<SegmentMleOpening>,
) {
    let (pre_state_openings, post_state_openings) = prove_state_mle_openings_only(state_bindings);
    (Vec::new(), pre_state_openings, post_state_openings)
}

pub fn verify_state_bindings_standalone(
    proof: &BlockProof,
    state_binding_airs: &[&BlockStateBindingAir],
) -> Result<(), VerifyBlockError> {
    let n_state_bindings = proof.meta.n_state_bindings as usize;
    if !proof.state_binding_starks.is_empty()
        || !proof.state_binding_algebraics.is_empty()
        || proof.meta.state_binding_n_cols != 0
        || proof.meta.state_binding_log_rows != 0
        || state_binding_airs.len() != n_state_bindings
    {
        return Err(VerifyBlockError::ShapeMismatch);
    }

    verify_state_mle_openings(proof, state_binding_airs)
}

fn verify_state_mle_openings(
    proof: &BlockProof,
    state_binding_airs: &[&BlockStateBindingAir],
) -> Result<(), VerifyBlockError> {
    let meta = &proof.meta;
    let n_state_bindings = meta.n_state_bindings as usize;
    if proof.pre_state_openings.len() != n_state_bindings
        || proof.post_state_openings.len() != n_state_bindings
    {
        return Err(VerifyBlockError::ShapeMismatch);
    }
    if n_state_bindings == 0 {
        return Ok(());
    }

    let frib_hasher = Poseidon2bSponge::new();
    for sb_idx in 0..n_state_bindings {
        let sb_air = state_binding_airs[sb_idx];
        let pre = &proof.pre_state_openings[sb_idx];
        let post = &proof.post_state_openings[sb_idx];

        if pre.seg_id != post.seg_id {
            tracing::warn!(
                sb_idx,
                pre_seg_id = pre.seg_id,
                post_seg_id = post.seg_id,
                "StateMle: pre/post segment mismatch"
            );
            return Err(VerifyBlockError::StateMleOpeningFailed(sb_idx));
        }
        if pre.eval_point != sb_air.eval_point || post.eval_point != sb_air.eval_point {
            tracing::warn!(sb_idx, "StateMle: eval_point mismatch");
            return Err(VerifyBlockError::StateMleOpeningFailed(sb_idx));
        }
        let eff_log = pre.eval_point.len();

        let verify_one = |op: &SegmentMleOpening,
                          expected_lane: &[Block128; 3]|
         -> Result<(), VerifyBlockError> {
            let commit_log = eff_log.max(noid_fri_binius::MERKLE_CAP_DEPTH);
            let ntt = AdditiveNTT::<Block128>::new(commit_log + noid_fri::code::LOG_RATE);
            let padded_pt = {
                let mut p = op.eval_point.clone();
                p.resize(commit_log, Block128::ZERO);
                p
            };
            let mut ch = noid_fri::channel::Channel::new();
            noid_fri_binius::absorb_cap(&mut ch, &op.commitment.cap);
            let col_evals = verify_mixed_opening(
                &op.commitment,
                &padded_pt,
                &[],
                &op.opening,
                &ntt,
                &mut ch,
                &frib_hasher,
                COMPACT_NUM_QUERIES,
            )
            .map_err(|e| {
                tracing::warn!(sb_idx, err=?e, "StateMle: FRI verify failed");
                VerifyBlockError::StateMleOpeningFailed(sb_idx)
            })?;

            if col_evals.len() < 3
                || [col_evals[0], col_evals[1], col_evals[2]] != op.lane_values
                || &op.lane_values != expected_lane
            {
                tracing::warn!(sb_idx, "StateMle: lane_values mismatch");
                return Err(VerifyBlockError::StateMleOpeningFailed(sb_idx));
            }
            let derived = cap_to_seg_root_with_depth(&op.commitment.cap, eff_log);
            if derived != op.seg_root {
                tracing::warn!(sb_idx, "StateMle: seg_root mismatch");
                return Err(VerifyBlockError::StateMleOpeningFailed(sb_idx));
            }
            Ok(())
        };

        verify_one(pre, &sb_air.prev_lane_openings)?;
        verify_one(post, &sb_air.new_lane_openings)?;

        let check_merkle = |op: &SegmentMleOpening,
                            expected_root: &[u8; 32]|
         -> Result<(), VerifyBlockError> {
            if op.merkle_siblings.is_empty() {
                if op.seg_root != *expected_root {
                    return Err(VerifyBlockError::StateMleOpeningFailed(sb_idx));
                }
            } else {
                let computed = merkle_root_from_leaf(&op.seg_root, op.seg_id, &op.merkle_siblings);
                if computed != *expected_root {
                    return Err(VerifyBlockError::StateMleOpeningFailed(sb_idx));
                }
            }
            Ok(())
        };
        check_merkle(pre, &meta.prev_block_state_root)?;
        check_merkle(post, &meta.new_state_root)?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// prove_block
// ---------------------------------------------------------------------------

/// `new_block_state_root` = block header's `state_root`; used in `BlockPublicMeta`
/// for post-state Merkle path verification. Pass `[0u8;32]` when there
/// are no state bindings (bench / coinbase-only mode).
pub fn prove_block(
    prev_block_state_root: [u8; 32],
    new_block_state_root: [u8; 32],
    witnesses: &[TxBlockWitness<'_>],
    state_bindings: &[StateBindingBlockWitness<'_>],
) -> Result<BlockProof, ProveBlockError> {
    prove_block_with_total_tx_count(
        prev_block_state_root,
        new_block_state_root,
        witnesses,
        state_bindings,
        witnesses.len() as u32,
    )
}

pub fn prove_block_with_total_tx_count(
    prev_block_state_root: [u8; 32],
    new_block_state_root: [u8; 32],
    witnesses: &[TxBlockWitness<'_>],
    state_bindings: &[StateBindingBlockWitness<'_>],
    total_non_coinbase_tx: u32,
) -> Result<BlockProof, ProveBlockError> {
    let n_tx = witnesses.len();
    assert!(
        n_tx >= 1,
        "standard bucket must have at least one transaction"
    );
    if total_non_coinbase_tx < n_tx as u32 {
        return Err(ProveBlockError::InvalidTxIndices);
    }

    let mut profiler = ProveBlockProfiler::new();

    let spine_circuit = SpineCircuit::build();
    let auth_circuit = AuthCircuit::build();

    let n_air_cols = witnesses[0].air.n_columns();
    let public_flags = public_column_flags(witnesses[0].air, n_air_cols)
        .ok_or(ProveBlockError::InvalidTxIndices)?;
    let committed_air_indices = committed_air_indices_from_public_flags(&public_flags);
    // Auth KillShot is now self-contained; raw AuthGKR MLE slices are not
    // committed in the block bucket.
    let n_auth_slices: usize = 0;
    let n_per_tx = committed_air_indices.len();
    let log_rows = witnesses[0].trace.log_rows;
    let log_len = noid_stark::padded_log_len(log_rows);
    for w in witnesses {
        if w.air.n_columns() != n_air_cols
            || public_column_flags(w.air, n_air_cols).as_ref() != Some(&public_flags)
            || w.trace.log_rows != log_rows
            || w.pi.shape_id != noid_tx::TxShape::Standard4x8.id()
        {
            return Err(ProveBlockError::InvalidTxIndices);
        }
    }
    profiler.phase("setup");

    // -------------------------------------------------------------------------
    // Build per-tx column pools + block spine MLE.
    // -------------------------------------------------------------------------
    // Per-tx: AIR columns (padded) only.
    // Block-level: unified spine state MLE split into slices.

    // Build fixed columns once from the first witness AIR (all txs share the
    // same AIR shape).  Fixed columns (selectors / masks) are padded once and
    // reused across all N transactions via zero-copy refs, avoiding N-1 extra
    // copies of ~65 MB of selector data per block.
    let shared_fixed = FixedColumns::from_air(witnesses[0].air, witnesses[0].trace, log_len);

    struct TxPrep {
        /// Non-fixed AIR witness columns in ascending original column-index order.
        witness_cols: Vec<Vec<Block128>>,
    }

    // Parallel prep loop.
    // Each tx's spine-state reconstruction and witness column padding are
    // fully independent; parallelize across txs with rayon.
    struct TxPrepBundle {
        slot_state_ins: Vec<[Block128; 4]>,
        prep: TxPrep,
    }
    let bundles: Vec<TxPrepBundle> = (0..n_tx)
        .into_par_iter()
        .map(|k| {
            let w = &witnesses[k];
            let spine_states = reconstruct_slot_states(&spine_circuit, w.spine_inputs);
            let slot_state_ins: Vec<[Block128; 4]> = spine_states.iter().map(|(s, _)| *s).collect();
            let witness_cols: Vec<Vec<Block128>> = w
                .trace
                .columns
                .iter()
                .enumerate()
                .filter(|(i, _)| !shared_fixed.is_fixed(*i))
                .map(|(_, col)| noid_stark::pad_column(col, log_len))
                .collect();
            TxPrepBundle {
                slot_state_ins,
                prep: TxPrep { witness_cols },
            }
        })
        .collect();

    // 59 = N_SPINE_SLOTS = max slot-state entries per tx in the BlockSpineMle layout.
    let mut all_slot_state_ins: Vec<[Block128; 4]> = Vec::with_capacity(n_tx * 59);
    let mut preps: Vec<TxPrep> = Vec::with_capacity(n_tx);
    for bundle in bundles {
        all_slot_state_ins.extend_from_slice(&bundle.slot_state_ins);
        preps.push(bundle.prep);
    }

    // Build unified block spine MLE and split state column into FRI slices.
    let block_spine_mle = noid_gkr::BlockSpineMle::build(n_tx, &all_slot_state_ins);
    let block_spine_num_vars = block_spine_mle.num_vars;
    let block_spine_slices =
        split_mle_into_slices(&block_spine_mle.state, block_spine_num_vars, BASE_LOG);
    let n_block_spine_slices = block_spine_slices.len();
    profiler.phase("tx_prep_and_block_spine_mle");

    // -------------------------------------------------------------------------
    // Single block-wide interleaved commit.
    // Layout: [per-tx columns | block spine slices].
    //
    // State transition is no longer committed as wide `BlockStateBindingAir`
    // columns. It is verified natively from canonical deltas plus pre/post
    // segment MLE openings below.
    // -------------------------------------------------------------------------
    let n_state_bindings = state_bindings.len();

    // Pad block spine slices to log_len (they may be shorter if num_vars < BASE_LOG).
    let spine_padded_slices: Vec<Vec<Block128>> = block_spine_slices
        .iter()
        .map(|s| noid_stark::pad_column(s, log_len))
        .collect();

    // Build the flat column-ref list, then commit it as one flattened row×column MLE.
    // Layout: flat[row + (col << log_len)].  This keeps the existing source-bound
    // mixed opening path, but with n_cols=1; the bucket terminal linear form is
    // discharged by a small column-axis sumcheck below.
    let mut flat_refs: Vec<&[Block128]> =
        Vec::with_capacity(n_tx * n_per_tx + n_block_spine_slices);
    for p in &preps {
        let air_refs = shared_fixed.build_full_col_refs(n_air_cols, &p.witness_cols);
        for &col_idx in &committed_air_indices {
            flat_refs.push(air_refs[col_idx]);
        }
    }
    for s in &spine_padded_slices {
        flat_refs.push(s.as_slice());
    }
    let total_cols = flat_refs.len();
    let log_cols = log2_padded_len(total_cols);
    let col_pad = 1usize << log_cols;
    let flat_bucket_column = build_flattened_bucket_column(&flat_refs, log_len, col_pad);
    let flat_commit_cols: [&[Block128]; 1] = [flat_bucket_column.as_slice()];
    profiler.phase("block_commit_flat_refs");

    let ntt = AdditiveNTT::<Block128>::new(log_len + log_cols + noid_fri::code::LOG_RATE);
    let hasher = Poseidon2bSponge::new();
    let (commitment, prover_state) = interleaved_commit(&flat_commit_cols, &ntt, &hasher);
    let cap = &commitment.cap;
    profiler.phase("interleaved_commit");

    // -------------------------------------------------------------------------
    // GKR Kill-Shots.
    //   (a) Unified block spine Kill-Shot (all txs in one shot).
    //   (b) Per-tx auth Kill-Shots (wallet pre-built, replayed for reductions).
    // -------------------------------------------------------------------------
    let tx_body_hashes: Vec<[Block128; 2]> = witnesses
        .iter()
        .map(|w| w.pi.tx_body_hash.as_fields())
        .collect();
    let auth_public_refs: Vec<&AuthPublicInputs> =
        witnesses.iter().map(|w| w.auth_public).collect();
    let auth_proof_refs: Vec<&AuthProofKillShot> = witnesses.iter().map(|w| w.auth_proof).collect();

    // (a) Unified block spine.
    let mut spine_channel = Poseidon2bChannel::new();
    absorb_cap_into_p2b(&mut spine_channel, cap);
    let (block_spine_proof, block_spine_reductions) =
        prove_block_spine_killshot(n_tx, &block_spine_mle, &tx_body_hashes, &mut spine_channel);

    // Spine reduction -> slice bridge.
    // spine_r_low is the BASE_LOG-dimensional opening point for the spine slices.
    // For the multipoint sumcheck, all participants must share the same hypercube
    // dimension (log_len). When log_len > BASE_LOG, extend with zeros — the
    // zero-padded slices evaluate identically at (r_low, 0..0) as at r_low.
    let spine_r = &block_spine_reductions.state.point;
    let spine_r_low_base = &spine_r[..BASE_LOG];
    let spine_r_low: Vec<Block128> = {
        let mut v = spine_r_low_base.to_vec();
        v.resize(log_len, Block128::ZERO);
        v
    };
    let spine_extras = reduction_to_transcript(spine_r, block_spine_reductions.state.value);
    profiler.phase("block_spine_gkr");

    // (b) Per-tx auth Kill-Shots (parallel).
    struct AuthResult {
        extras_transcript: Vec<Block128>,
    }

    // Verify wallet auth proofs; collect per-tx results or surface the first failure.
    let auth_results_raw: Vec<Option<AuthResult>> = (0..n_tx)
        .into_par_iter()
        .map(|k| {
            let mut ch = auth_gkr_channel();
            let auth_reductions = verify_auth_killshot(
                auth_proof_refs[k],
                &auth_circuit,
                auth_public_refs[k],
                &mut ch,
            )?; // returns None on failure

            let r_auth = auth_reductions.state.point.clone();
            let auth_tr = reduction_to_transcript(&r_auth, auth_reductions.state.value);
            let mut extras = Vec::with_capacity(spine_extras.len() + auth_tr.len());
            extras.extend_from_slice(&spine_extras);
            extras.extend_from_slice(&auth_tr);

            Some(AuthResult {
                extras_transcript: extras,
            })
        })
        .collect();

    // Surface the first auth failure as a ProveBlockError.
    let auth_results: Vec<AuthResult> = auth_results_raw
        .into_iter()
        .enumerate()
        .map(|(k, r)| r.ok_or(ProveBlockError::AuthProofInvalid(k)))
        .collect::<Result<Vec<_>, _>>()?;
    profiler.phase("auth_verify_and_slice_openings");

    // -------------------------------------------------------------------------
    // Parallel per-tx algebraic STARK proofs.
    //
    // Each tx uses an independent Fiat-Shamir channel seeded from:
    //   DOMAIN_TAG_TX_ALGEBRAIC || PROTOCOL_VERSION || state_root || cap || tx_index
    // This is safe because the cap already commits ALL columns (committed before
    // any challenge is drawn). The block-level binding happens via
    // the Merkle reduction of all per-tx transcripts.
    // -------------------------------------------------------------------------
    struct TxAlgResult {
        alg: AlgebraicStarkProof,
        r_pp: Vec<Block128>,
        final_claim: Block128,
        lambdas: Vec<Block128>,
    }

    let tx_alg_results: Vec<TxAlgResult> = (0..n_tx)
        .into_par_iter()
        .map(|k| {
            let w = &witnesses[k];
            let prep = &preps[k];
            let auth_res = &auth_results[k];

            let slice_claims: Vec<SliceClaim> = Vec::new();

            // Per-tx independent Fiat-Shamir channel, domain-separated by tx index.
            let mut ch = per_tx_algebraic_channel(&prev_block_state_root, cap, k as u32);

            // Build full ordered column refs (fixed zero-copy + witness).
            let all_col_refs = shared_fixed.build_full_col_refs(n_air_cols, &prep.witness_cols);

            let (alg, r_pp, final_claim, lambdas) = prove_air_interleaved_algebraic(
                w.air,
                &all_col_refs,
                w.pi,
                &auth_res.extras_transcript,
                &slice_claims,
                log_len,
                &mut ch,
            );
            TxAlgResult {
                alg,
                r_pp,
                final_claim,
                lambdas,
            }
        })
        .collect();

    let mut tx_algebraic: Vec<AlgebraicStarkProof> = Vec::with_capacity(n_tx);
    let mut tx_r_pp: Vec<Vec<Block128>> = Vec::with_capacity(n_tx);
    let mut tx_claims: Vec<Block128> = Vec::with_capacity(n_tx);
    let mut tx_lambdas: Vec<Vec<Block128>> = Vec::with_capacity(n_tx);
    for r in tx_alg_results {
        tx_algebraic.push(r.alg);
        tx_r_pp.push(r.r_pp);
        tx_claims.push(r.final_claim);
        tx_lambdas.push(r.lambdas);
    }
    profiler.phase("tx_algebraic_starks");

    // -------------------------------------------------------------------------
    // Per-segment FRI MLE openings + Merkle path.
    //
    // For each dirty segment, open the 3 pre-state and 3 post-state columns at
    // the root-derived state-delta point. The verifier checks the delta identity
    // natively from canonical claims, then checks these openings against
    // prev/new state roots.
    // -------------------------------------------------------------------------
    let sb_algebraics: Vec<AlgebraicStarkProof> = Vec::new();
    let (pre_state_openings, post_state_openings) = prove_state_mle_openings_only(state_bindings);
    profiler.phase("state_mle_openings");

    // -------------------------------------------------------------------------
    // Segmented Transcript Absorption.
    //
    // Each per-tx algebraic STARK produced an independent Fiat-Shamir transcript.
    // We summarise all transcripts into a single 32-byte Merkle root that the
    // block channel absorbs, providing soundness-equivalent binding to the
    // sequential approach while enabling parallel proving.
    // -------------------------------------------------------------------------
    let tx_digests: Vec<[u8; 32]> = (0..n_tx)
        .into_par_iter()
        .map(|k| {
            compute_tx_transcript_digest(
                k as u32,
                &tx_r_pp[k],
                &tx_algebraic[k].base_openings,
                &tx_lambdas[k],
                tx_claims[k],
            )
        })
        .collect();
    let transcript_root = merkle_reduce(&tx_digests);
    profiler.phase("tx_transcript_merkle_root");

    // -------------------------------------------------------------------------
    // Block multipoint channel — fresh, domain-separated from per-tx channels.
    // -------------------------------------------------------------------------
    let mut block_channel = block_multipoint_channel(&prev_block_state_root, cap);
    let [tr0, tr1] = hash_to_fields(&transcript_root);
    block_channel.observe_field_elem(tr0);
    block_channel.observe_field_elem(tr1);
    profiler.phase("block_channel_setup");

    // -------------------------------------------------------------------------
    // Block-level multipoint sumcheck (CRYPTO.md §6).
    //
    // Participants:
    //   0..n_tx: per-tx AIR columns, each with n_per_tx columns.
    //
    // Block spine reductions are discharged natively from public spine inputs;
    // state-delta openings are verified outside this bucket commitment.
    // -------------------------------------------------------------------------
    let n_participants = n_tx + 1; // +1 for spine
    let spine_participant_idx = n_tx;

    // M2: Parallel per-tx column openings with thread-local scratch.
    // Eliminates ~n_tx * n_per_tx * 128 KB = ~1 GB of allocations for 100 txs.
    debug_assert_eq!(total_cols, n_tx * n_per_tx + n_block_spine_slices);

    // M2 + flat-basis: evaluate_flat_with_scratch uses clmul_gcm (~4 ns/mul)
    // instead of tower-basis Karatsuba (~30 ns/mul) — 7-8x faster per column.
    thread_local! {
        static FLAT_SCRATCH: std::cell::RefCell<Vec<u128>> =
            std::cell::RefCell::new(Vec::new());
        static PT_SCRATCH: std::cell::RefCell<Vec<u128>> =
            std::cell::RefCell::new(Vec::new());
    }

    let tx_openings: Vec<Vec<Block128>> = (0..n_tx)
        .into_par_iter()
        .map(|k| {
            let r_pp_k = &tx_r_pp[k];
            let air_refs = shared_fixed.build_full_col_refs(n_air_cols, &preps[k].witness_cols);
            let mut cols_k = Vec::with_capacity(n_per_tx);
            FLAT_SCRATCH.with(|fs| {
                PT_SCRATCH.with(|ps| {
                    let mut flat = fs.borrow_mut();
                    let mut pt = ps.borrow_mut();
                    for &col_idx in &committed_air_indices {
                        let col = air_refs[col_idx];
                        cols_k.push(noid_core::mle::evaluate::evaluate_flat_with_scratch(
                            col, r_pp_k, &mut flat, &mut pt,
                        ));
                    }
                })
            });
            cols_k
        })
        .collect();

    let mut block_col_openings: Vec<Block128> = Vec::with_capacity(total_cols);
    for openings_k in tx_openings {
        block_col_openings.extend_from_slice(&openings_k);
    }
    // Block spine slice openings at spine_r_low.
    FLAT_SCRATCH.with(|fs| {
        PT_SCRATCH.with(|ps| {
            let mut flat = fs.borrow_mut();
            let mut pt = ps.borrow_mut();
            for sp in &spine_padded_slices {
                block_col_openings.push(noid_core::mle::evaluate::evaluate_flat_with_scratch(
                    sp,
                    &spine_r_low,
                    &mut flat,
                    &mut pt,
                ));
            }
        })
    });
    profiler.phase("column_openings");

    block_channel.observe_field_elem(Block128::from(BLOCK_MULTIPOINT_TAG));
    block_channel.observe_field_elems(&block_col_openings);
    let mu = block_channel.get_random_point();
    let beta_block = block_channel.get_random_point();

    let mu_powers: Vec<Block128> = {
        let mut v = Vec::with_capacity(n_participants);
        let mut cur = Block128::ONE;
        for _ in 0..n_participants {
            v.push(cur);
            cur *= mu;
        }
        v
    };

    let max_cols = n_per_tx.max(n_block_spine_slices);
    let beta_powers: Vec<Block128> = {
        let mut v = Vec::with_capacity(max_cols);
        let mut cur = Block128::ONE;
        for _ in 0..max_cols {
            v.push(cur);
            cur *= beta_block;
        }
        v
    };

    // Block sumcheck target = sum over all participants.
    let block_target: Block128 = {
        let mut target = Block128::ZERO;
        for k in 0..n_tx {
            let inner: Block128 = (0..n_per_tx)
                .map(|i| beta_powers[i] * block_col_openings[k * n_per_tx + i])
                .fold(Block128::ZERO, |a, b| a + b);
            target += mu_powers[k] * inner;
        }
        // Block spine participant.
        let spine_offset = n_tx * n_per_tx;
        let inner_spine: Block128 = (0..n_block_spine_slices)
            .map(|i| beta_powers[i] * block_col_openings[spine_offset + i])
            .fold(Block128::ZERO, |a, b| a + b);
        target += mu_powers[spine_participant_idx] * inner_spine;

        target
    };
    profiler.phase("sumcheck_challenge_and_target");

    // Collect all r_pp points for all bucket participants.
    let all_r_pp: Vec<&[Block128]> = {
        let mut v: Vec<&[Block128]> = tx_r_pp.iter().map(|r| r.as_slice()).collect();
        v.push(&spine_r_low); // block spine
        v
    };

    // A-side: A_k[j] = mu^k * eq_ind(r''_k)[j].
    let pairs_a: Vec<Vec<Block128>> = (0..n_participants)
        .into_par_iter()
        .map(|k| {
            let eq_k = eq_ind_partial_eval(all_r_pp[k]);
            eq_k.into_iter().map(|v| v * mu_powers[k]).collect()
        })
        .collect();

    // B-side: B_k[j] = sum_i beta^i * cols_k[i][j].
    let hyper_len = 1usize << log_len;

    // Build B-side directly in flat/GCM basis for the multipoint fast path.
    // This materializes the same B_k polynomials as the tower-basis path, but
    // avoids immediately flattening them again inside the sumcheck prover.
    use noid_core::hardware::{clmul_gcm, tower_to_flat_u128};
    let beta_powers_flat: Vec<u128> = beta_powers
        .iter()
        .map(|v| tower_to_flat_u128(v.0))
        .collect();
    let pairs_b_flat: Vec<Vec<u128>> = (0..n_participants)
        .into_par_iter()
        .map(|k| {
            if k < n_tx {
                let air_refs = shared_fixed.build_full_col_refs(n_air_cols, &preps[k].witness_cols);
                let mut b_k = vec![0u128; hyper_len];
                for (i, &col_idx) in committed_air_indices.iter().enumerate() {
                    let lam_flat = beta_powers_flat[i];
                    let col = air_refs[col_idx];
                    b_k.iter_mut().zip(col.iter()).for_each(|(acc, &v)| {
                        *acc ^= clmul_gcm(lam_flat, tower_to_flat_u128(v.0));
                    });
                }
                b_k
            } else {
                debug_assert_eq!(k, spine_participant_idx);
                let mut b_k = vec![0u128; hyper_len];
                for i in 0..n_block_spine_slices {
                    let lam_flat = beta_powers_flat[i];
                    let col = spine_padded_slices[i].as_slice();
                    b_k.iter_mut().zip(col.iter()).for_each(|(acc, &v)| {
                        *acc ^= clmul_gcm(lam_flat, tower_to_flat_u128(v.0));
                    });
                }
                b_k
            }
        })
        .collect();
    profiler.phase("sumcheck_pair_materialization");

    let (block_mp_rounds, block_mp_challenges) =
        noid_stark::multipoint_batch::prove_multipoint_sumcheck_flat_b(
            pairs_a,
            pairs_b_flat,
            block_target,
            &mut block_channel,
        );
    let r_block: Vec<Block128> = block_mp_challenges.iter().rev().cloned().collect();
    debug_assert_eq!(r_block.len(), log_len);
    profiler.phase("multipoint_sumcheck");

    // -------------------------------------------------------------------------
    // Column-terminal compression + one single-column FRI-Binius opening.
    // -------------------------------------------------------------------------
    let block_final_claim =
        sumcheck_terminal_claim(&block_mp_rounds, &block_mp_challenges, block_target);
    let participant_points: Vec<&[Block128]> = {
        let mut v: Vec<&[Block128]> = tx_r_pp.iter().map(|r| r.as_slice()).collect();
        v.push(&spine_r_low);
        v
    };
    let participant_widths: Vec<usize> = {
        let mut v = vec![n_per_tx; n_tx];
        v.push(n_block_spine_slices);
        v
    };
    let coeffs = bucket_terminal_coefficients(
        &participant_points,
        &participant_widths,
        &mu_powers,
        &beta_powers,
        &r_block,
        col_pad,
    );
    let (block_column_sumcheck_rounds, mixed_opening) = prove_bucket_linear_terminal_opening(
        &flat_refs,
        &prover_state,
        &r_block,
        &coeffs,
        block_final_claim,
        &ntt,
        &mut block_channel,
        &hasher,
    );
    profiler.phase("mixed_opening");

    let tx_pis: Vec<PublicInputs> = witnesses.iter().map(|w| w.pi.clone()).collect();
    profiler.phase("proof_output_clones");
    profiler.finish(
        n_tx,
        n_state_bindings,
        n_air_cols,
        n_auth_slices,
        n_block_spine_slices,
        log_len,
    );

    let meta = BlockPublicMeta {
        prev_block_state_root,
        new_state_root: new_block_state_root,
        n_tx: total_non_coinbase_tx,
        n_air_per_tx: n_air_cols as u32,
        n_auth_slices_per_tx: n_auth_slices as u32,
        log_rows: witnesses[0].trace.log_rows as u32,
        n_block_spine_slices: n_block_spine_slices as u32,
        n_state_bindings: n_state_bindings as u32,
        state_binding_n_cols: 0,
        state_binding_log_rows: 0,
    };

    let tx_indices: Vec<u32> = witnesses.iter().map(|w| w.block_tx_index).collect();
    if !tx_indices.windows(2).all(|w| w[0] < w[1]) {
        return Err(ProveBlockError::InvalidTxIndices);
    }
    let standard_bucket = StandardBucketProof {
        meta: ShapeBucketMeta {
            shape: noid_tx::TxShape::Standard4x8,
            tx_indices,
            n_air_per_tx: n_air_cols as u32,
            n_boundary_slices_per_tx: n_auth_slices as u32,
            log_rows: witnesses[0].trace.log_rows as u32,
            n_block_spine_slices: n_block_spine_slices as u32,
        },
        tx_pis,
        commitment,
        block_spine_proof,
        tx_algebraic,
        block_col_openings,
        block_multipoint_rounds: block_mp_rounds,
        block_multipoint_challenges: block_mp_challenges,
        block_column_sumcheck_rounds,
        mixed_opening,
        block_initial_claim: block_target,
    };

    Ok(BlockProof {
        meta,
        standard_bucket: Some(standard_bucket),
        sweep_bucket: None,
        state_binding_algebraics: sb_algebraics,
        state_binding_starks: vec![],
        pre_state_openings,
        post_state_openings,
    })
}

fn public_column_flags(air: &dyn Air, n_air_cols: usize) -> Option<Vec<bool>> {
    let mut flags = vec![false; n_air_cols];
    let expected_rows = 1usize.checked_shl(air.log_rows() as u32)?;
    for pc in air.public_columns() {
        if pc.col >= n_air_cols || pc.values.len() != expected_rows || flags[pc.col] {
            return None;
        }
        flags[pc.col] = true;
    }
    Some(flags)
}

fn committed_air_indices_from_public_flags(flags: &[bool]) -> Vec<usize> {
    flags
        .iter()
        .enumerate()
        .filter_map(|(idx, is_public)| (!*is_public).then_some(idx))
        .collect()
}

fn log2_padded_len(len: usize) -> usize {
    assert!(len > 0, "cannot pad an empty bucket column axis");
    len.next_power_of_two().trailing_zeros() as usize
}

fn build_flattened_bucket_column(
    cols: &[&[Block128]],
    log_len: usize,
    col_pad: usize,
) -> Vec<Block128> {
    let hyper_len = 1usize << log_len;
    assert!(col_pad.is_power_of_two());
    assert!(cols.len() <= col_pad);
    let mut flat = vec![Block128::ZERO; hyper_len * col_pad];
    flat.par_chunks_mut(hyper_len)
        .enumerate()
        .for_each(|(col_idx, chunk)| {
            if let Some(col) = cols.get(col_idx) {
                assert_eq!(col.len(), hyper_len);
                chunk.copy_from_slice(col);
            }
        });
    flat
}

fn eval_bucket_columns_at_row(
    cols: &[&[Block128]],
    r_block: &[Block128],
    col_pad: usize,
) -> Vec<Block128> {
    let mut values: Vec<Block128> = cols
        .par_iter()
        .map(|col| {
            let mut flat = Vec::new();
            let mut point = Vec::new();
            noid_core::mle::evaluate::evaluate_flat_with_scratch(
                col, r_block, &mut flat, &mut point,
            )
        })
        .collect();
    values.resize(col_pad, Block128::ZERO);
    values
}

fn bucket_terminal_coefficients(
    participant_points: &[&[Block128]],
    participant_widths: &[usize],
    mu_powers: &[Block128],
    beta_powers: &[Block128],
    r_block: &[Block128],
    col_pad: usize,
) -> Vec<Block128> {
    assert_eq!(participant_points.len(), participant_widths.len());
    assert_eq!(participant_points.len(), mu_powers.len());
    let total_cols: usize = participant_widths.iter().sum();
    assert!(total_cols <= col_pad);
    let mut coeffs = vec![Block128::ZERO; col_pad];
    let mut offset = 0usize;
    for (k, (&point, &width)) in participant_points
        .iter()
        .zip(participant_widths.iter())
        .enumerate()
    {
        let eq = noid_core::mle::eq::eq_ind(point, r_block);
        let scale = mu_powers[k] * eq;
        for i in 0..width {
            coeffs[offset + i] = scale * beta_powers[i];
        }
        offset += width;
    }
    coeffs
}

fn sumcheck_terminal_claim(
    rounds: &[Vec<Block128>],
    challenges: &[Block128],
    target: Block128,
) -> Block128 {
    match (rounds.last(), challenges.last()) {
        (Some(last_round), Some(&last_challenge)) => {
            noid_stark::lagrange_eval_at_pub(last_round, last_challenge)
        }
        _ => target,
    }
}

#[allow(clippy::too_many_arguments)]
fn prove_bucket_linear_terminal_opening(
    original_cols: &[&[Block128]],
    flat_state: &InterleavedProverState<'_>,
    r_block: &[Block128],
    coeffs: &[Block128],
    block_final_claim: Block128,
    ntt: &AdditiveNTT<Block128>,
    channel: &mut noid_fri::Channel,
    hasher: &Poseidon2bSponge,
) -> (Vec<Vec<Block128>>, MixedOpeningProof) {
    let col_pad = coeffs.len();
    let values_at_r_block = eval_bucket_columns_at_row(original_cols, r_block, col_pad);
    channel.observe_field_elem(Block128::from(BLOCK_COLUMN_TERMINAL_TAG));
    let (rounds, challenges) = noid_stark::multipoint_batch::prove_multipoint_sumcheck(
        vec![coeffs.to_vec()],
        vec![values_at_r_block.as_slice()],
        block_final_claim,
        channel,
    );
    let r_col: Vec<Block128> = challenges.iter().rev().cloned().collect();
    let mut flat_point = Vec::with_capacity(r_block.len() + r_col.len());
    flat_point.extend_from_slice(r_block);
    flat_point.extend_from_slice(&r_col);
    let mixed_opening = prove_mixed_opening(
        flat_state,
        &flat_point,
        &[],
        ntt,
        channel,
        hasher,
        COMPACT_NUM_QUERIES,
    );
    (rounds, mixed_opening)
}

#[allow(clippy::too_many_arguments)]
fn verify_bucket_linear_terminal_opening(
    commitment: &InterleavedCommitment,
    r_block: &[Block128],
    coeffs: &[Block128],
    block_final_claim: Block128,
    rounds: &[Vec<Block128>],
    mixed_opening: &MixedOpeningProof,
    ntt: &AdditiveNTT<Block128>,
    channel: &mut noid_fri::Channel,
    hasher: &Poseidon2bSponge,
) -> Result<(), VerifyBlockError> {
    if commitment.n_cols != 1
        || commitment.log_rows != r_block.len() + log2_padded_len(coeffs.len())
    {
        return Err(VerifyBlockError::ShapeMismatch);
    }
    channel.observe_field_elem(Block128::from(BLOCK_COLUMN_TERMINAL_TAG));
    let (challenges, column_final_claim) =
        noid_stark::multipoint_batch::verify_multipoint_sumcheck(
            rounds,
            block_final_claim,
            channel,
        )
        .map_err(|_| VerifyBlockError::BlockMultipoint)?;
    let r_col: Vec<Block128> = challenges.iter().rev().cloned().collect();
    let mut coeff_scratch = Vec::new();
    let mut point_scratch = Vec::new();
    let coeff_at_r_col = noid_core::mle::evaluate::evaluate_flat_with_scratch(
        coeffs,
        &r_col,
        &mut coeff_scratch,
        &mut point_scratch,
    );
    let mut flat_point = Vec::with_capacity(r_block.len() + r_col.len());
    flat_point.extend_from_slice(r_block);
    flat_point.extend_from_slice(&r_col);
    let opened = verify_mixed_opening(
        commitment,
        &flat_point,
        &[],
        mixed_opening,
        ntt,
        channel,
        hasher,
        COMPACT_NUM_QUERIES,
    )
    .map_err(VerifyBlockError::FriFailed)?;
    if opened.len() != 1 || coeff_at_r_col * opened[0] != column_final_claim {
        return Err(VerifyBlockError::BlockMultipoint);
    }
    Ok(())
}

fn public_opening_map(
    air: &dyn Air,
    point: &[Block128],
    log_len: usize,
    n_air_cols: usize,
) -> Result<Vec<Option<Block128>>, VerifyBlockError> {
    if point.len() != log_len {
        return Err(VerifyBlockError::ShapeMismatch);
    }
    let expected_rows = 1usize << air.log_rows();
    let mut openings = vec![None; n_air_cols];
    let mut hi_factor: Vec<Block128> = vec![Block128::ONE; log_len + 1];
    for k in (0..log_len).rev() {
        hi_factor[k] = hi_factor[k + 1] * (Block128::ONE + point[k]);
    }
    let mut eq_tensors: Vec<Option<Vec<Block128>>> = (0..=log_len).map(|_| None).collect();

    for pc in air.public_columns() {
        if pc.col >= n_air_cols || pc.values.len() != expected_rows || openings[pc.col].is_some() {
            return Err(VerifyBlockError::ShapeMismatch);
        }
        let k = pc.log_rows();
        if k > log_len {
            return Err(VerifyBlockError::ShapeMismatch);
        }
        let values = pc.values.as_slice();
        let lo = if values.is_empty() {
            Block128::ZERO
        } else if values.iter().all(|v| *v == values[0]) {
            values[0]
        } else {
            let tensor = eq_tensors[k]
                .get_or_insert_with(|| noid_core::mle::eq::eq_ind_partial_eval(&point[..k]));
            let mut hi = values.len();
            while hi > 0 && values[hi - 1] == Block128::ZERO {
                hi -= 1;
            }
            let mut acc = Block128::ZERO;
            for i in 0..hi {
                acc += tensor[i] * values[i];
            }
            acc
        };
        openings[pc.col] = Some(hi_factor[k] * lo);
    }
    Ok(openings)
}

fn verify_algebraic_terminal_against_bucket_openings(
    tx_index: usize,
    n_air_cols: usize,
    committed_air_indices: &[usize],
    committed_openings_at_r_pp: &[Block128],
    air: &dyn Air,
    log_len: usize,
    alg: &AlgebraicStarkProof,
    terminal: &AlgebraicTerminalData,
) -> Result<(), VerifyBlockError> {
    let s_count = terminal.shifted_indices.len();
    if committed_openings_at_r_pp.len() != committed_air_indices.len()
        || alg.shift_partials.len() != s_count
        || terminal.r_point.len() != terminal.r_pp.len()
        || terminal.lambdas.len() < n_air_cols + s_count
        || terminal.gammas.len() != s_count
    {
        return Err(VerifyBlockError::ShapeMismatch);
    }

    let public_openings = public_opening_map(air, &terminal.r_pp, log_len, n_air_cols)?;
    let mut committed_pos_by_col = vec![None::<usize>; n_air_cols];
    for (pos, &col_id) in committed_air_indices.iter().enumerate() {
        if col_id >= n_air_cols
            || public_openings[col_id].is_some()
            || committed_pos_by_col[col_id].is_some()
        {
            return Err(VerifyBlockError::ShapeMismatch);
        }
        committed_pos_by_col[col_id] = Some(pos);
    }

    let column_opening = |col_id: usize| -> Result<Block128, VerifyBlockError> {
        if col_id >= n_air_cols {
            return Err(VerifyBlockError::ShapeMismatch);
        }
        if let Some(value) = public_openings[col_id] {
            return Ok(value);
        }
        let pos = committed_pos_by_col[col_id].ok_or(VerifyBlockError::ShapeMismatch)?;
        Ok(committed_openings_at_r_pp[pos])
    };

    let eq_base = noid_core::mle::eq::eq_ind(&terminal.r_point, &terminal.r_pp);
    let mut expected = Block128::ZERO;
    for i in 0..n_air_cols {
        expected += terminal.lambdas[i] * eq_base * column_opening(i)?;
    }

    if s_count > 0 {
        let axes =
            noid_stark::ladder_batch::LadderWeightAxes::new(&terminal.r_point, &terminal.r_pp);
        for (slot, &col_id) in terminal.shifted_indices.iter().enumerate() {
            let w_s = noid_stark::ladder_batch::weight_at_axes(terminal.gammas[slot], &axes);
            expected += terminal.lambdas[n_air_cols + slot] * w_s * column_opening(col_id)?;
        }
    }

    if expected != terminal.final_claim {
        return Err(VerifyBlockError::AlgebraicTerminal(tx_index));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Sweep bucket aggregation verifier
// ---------------------------------------------------------------------------

pub fn verify_sweep_bucket_aggregation(
    prev_block_state_root: &[u8; 32],
    airs: &[&dyn Air],
    bucket: &SweepBucketProof,
    auth_public: &[SweepAuthPublicInputs],
    auth_proofs: &[SweepAuthProofKillShot],
    spine_inputs: &[SweepSpineInputs],
) -> Result<(), VerifyBlockError> {
    let n_tx = bucket.meta.n_tx();
    let n_air_cols = bucket.meta.n_air_per_tx as usize;
    if n_tx == 0 || airs.len() != n_tx {
        return Err(VerifyBlockError::ShapeMismatch);
    }
    let public_flags =
        public_column_flags(airs[0], n_air_cols).ok_or(VerifyBlockError::ShapeMismatch)?;
    let committed_air_indices = committed_air_indices_from_public_flags(&public_flags);
    let n_auth_slices = bucket.meta.n_boundary_slices_per_tx as usize;
    let n_per_tx = committed_air_indices.len();
    let n_block_spine_slices = bucket.meta.n_block_spine_slices as usize;
    let log_len = noid_stark::padded_log_len(bucket.meta.log_rows as usize);
    let total_cols = n_tx * n_per_tx + n_block_spine_slices;
    let log_cols = log2_padded_len(total_cols);
    let col_pad = 1usize << log_cols;
    let flat_log_len = log_len + log_cols;

    if bucket.meta.shape != noid_tx::TxShape::Sweep25x2
        || airs.len() != n_tx
        || bucket.tx_pis.len() != n_tx
        || auth_public.len() != n_tx
        || auth_proofs.len() != n_tx
        || spine_inputs.len() != n_tx
        || bucket.tx_algebraic.len() != n_tx
        || bucket.block_col_openings.len() != total_cols
        || bucket.commitment.n_cols != 1
        || bucket.commitment.log_rows != flat_log_len
        || n_auth_slices != 0
        || n_block_spine_slices == 0
        || log_len != BASE_LOG
    {
        return Err(VerifyBlockError::ShapeMismatch);
    }

    let auth_circuit = SweepAuthCircuit::build();
    let cap = &bucket.commitment.cap;
    let tx_body_hashes: Vec<[Block128; 2]> = bucket
        .tx_pis
        .iter()
        .map(|pi| pi.tx_body_hash.as_fields())
        .collect();
    let block_spine_reductions = {
        let mut ch = Poseidon2bChannel::new();
        absorb_cap_into_p2b(&mut ch, cap);
        verify_sweep_block_spine_killshot(&bucket.block_spine_proof, n_tx, &tx_body_hashes, &mut ch)
            .ok_or(VerifyBlockError::BlockSpineKillShot)?
    };
    let spine_r = &block_spine_reductions.state.point;
    let spine_r_low: Vec<Block128> = {
        let mut v = spine_r[..BASE_LOG].to_vec();
        v.resize(log_len, Block128::ZERO);
        v
    };
    let spine_r_high = &spine_r[BASE_LOG..];
    let spine_offset = n_tx * n_per_tx;
    let spine_slice_vals: Vec<Block128> = (0..n_block_spine_slices)
        .map(|i| bucket.block_col_openings[spine_offset + i])
        .collect();
    let recon_spine =
        noid_core::mle::split::reconstruct_from_slices(&spine_slice_vals, spine_r_high);
    if recon_spine != block_spine_reductions.state.value {
        return Err(VerifyBlockError::BlockSpineSliceReconstruction);
    }
    let spine_extras = reduction_to_transcript(spine_r, block_spine_reductions.state.value);

    struct TxVerifyResult {
        terminal: AlgebraicTerminalData,
    }

    let tx_verify_results: Vec<Result<TxVerifyResult, VerifyBlockError>> = (0..n_tx)
        .into_par_iter()
        .map(|k| {
            let pi = &bucket.tx_pis[k];
            let alg = &bucket.tx_algebraic[k];
            let auth_public = &auth_public[k];
            let spine_inputs = &spine_inputs[k];
            let auth_proof = &auth_proofs[k];

            if airs[k].n_columns() != n_air_cols
                || public_column_flags(airs[k], n_air_cols).as_ref() != Some(&public_flags)
            {
                return Err(VerifyBlockError::ShapeMismatch);
            }

            let mut auth_ch = sweep_auth_gkr_channel();
            let auth_reductions =
                verify_sweep_auth_killshot(auth_proof, &auth_circuit, auth_public, &mut auth_ch)
                    .ok_or(VerifyBlockError::AuthKillShot(k))?;

            let claimed = pi.tx_body_hash.as_fields();
            if auth_public.tx_body_hash != claimed {
                return Err(VerifyBlockError::AuthSpineBridge(k));
            }
            let n_live = pi.n_live_inputs as usize;
            for i in 0..n_live {
                let owner = [
                    spine_inputs.input_leaves[i][2],
                    spine_inputs.input_leaves[i][3],
                ];
                if auth_public.expected_address[i] != owner {
                    return Err(VerifyBlockError::AuthSpineBridge(k));
                }
            }

            let r_auth = &auth_reductions.state.point;
            if !alg.slice_claimed_values.is_empty() {
                return Err(VerifyBlockError::ShapeMismatch);
            }

            let auth_tr = reduction_to_transcript(r_auth, auth_reductions.state.value);
            let mut extras = Vec::with_capacity(spine_extras.len() + auth_tr.len());
            extras.extend_from_slice(&spine_extras);
            extras.extend_from_slice(&auth_tr);
            let slice_claims: Vec<SliceClaim> = Vec::new();
            let mut ch = per_tx_algebraic_channel(prev_block_state_root, cap, k as u32);
            let terminal = verify_air_interleaved_algebraic_terminal(
                airs[k],
                pi,
                alg,
                &extras,
                &slice_claims,
                &mut ch,
            )
            .map_err(|e| VerifyBlockError::AlgebraicStark(k, e))?;

            Ok(TxVerifyResult { terminal })
        })
        .collect();

    let mut tx_terminals = Vec::with_capacity(n_tx);
    for result in tx_verify_results {
        tx_terminals.push(result?.terminal);
    }
    for k in 0..n_tx {
        let offset = k * n_per_tx;
        verify_algebraic_terminal_against_bucket_openings(
            k,
            n_air_cols,
            &committed_air_indices,
            &bucket.block_col_openings[offset..offset + n_per_tx],
            airs[k],
            log_len,
            &bucket.tx_algebraic[k],
            &tx_terminals[k],
        )?;
    }

    let tx_digests: Vec<[u8; 32]> = (0..n_tx)
        .into_par_iter()
        .map(|k| {
            compute_tx_transcript_digest(
                k as u32,
                &tx_terminals[k].r_pp,
                &bucket.tx_algebraic[k].base_openings,
                &tx_terminals[k].lambdas,
                tx_terminals[k].final_claim,
            )
        })
        .collect();
    let transcript_root = merkle_reduce(&tx_digests);

    let mut block_channel = block_multipoint_channel(prev_block_state_root, cap);
    let [tr0, tr1] = hash_to_fields(&transcript_root);
    block_channel.observe_field_elem(tr0);
    block_channel.observe_field_elem(tr1);
    block_channel.observe_field_elem(Block128::from(BLOCK_MULTIPOINT_TAG));
    block_channel.observe_field_elems(&bucket.block_col_openings);
    let mu = block_channel.get_random_point();
    let beta_block = block_channel.get_random_point();

    let n_participants = n_tx + 1;
    let spine_participant_idx = n_tx;
    let mu_powers: Vec<Block128> = {
        let mut v = Vec::with_capacity(n_participants);
        let mut cur = Block128::ONE;
        for _ in 0..n_participants {
            v.push(cur);
            cur *= mu;
        }
        v
    };
    let max_cols = n_per_tx.max(n_block_spine_slices);
    let beta_powers: Vec<Block128> = {
        let mut v = Vec::with_capacity(max_cols);
        let mut cur = Block128::ONE;
        for _ in 0..max_cols {
            v.push(cur);
            cur *= beta_block;
        }
        v
    };

    let block_target: Block128 = {
        let mut target = Block128::ZERO;
        for k in 0..n_tx {
            let inner = (0..n_per_tx)
                .map(|i| beta_powers[i] * bucket.block_col_openings[k * n_per_tx + i])
                .fold(Block128::ZERO, |a, b| a + b);
            target += mu_powers[k] * inner;
        }
        let inner_spine = (0..n_block_spine_slices)
            .map(|i| beta_powers[i] * bucket.block_col_openings[spine_offset + i])
            .fold(Block128::ZERO, |a, b| a + b);
        target += mu_powers[spine_participant_idx] * inner_spine;
        target
    };
    if bucket.block_initial_claim != block_target {
        return Err(VerifyBlockError::BlockMultipoint);
    }

    let (block_sc_challenges, block_final_claim) =
        noid_stark::multipoint_batch::verify_multipoint_sumcheck(
            &bucket.block_multipoint_rounds,
            block_target,
            &mut block_channel,
        )
        .map_err(|_| VerifyBlockError::BlockMultipoint)?;
    if bucket.block_multipoint_challenges != block_sc_challenges {
        return Err(VerifyBlockError::BlockMultipoint);
    }
    let r_block: Vec<Block128> = block_sc_challenges.iter().rev().cloned().collect();
    if r_block.len() != log_len {
        return Err(VerifyBlockError::ShapeMismatch);
    }

    let participant_points: Vec<&[Block128]> = {
        let mut v: Vec<&[Block128]> = tx_terminals.iter().map(|t| t.r_pp.as_slice()).collect();
        v.push(&spine_r_low);
        v
    };
    let participant_widths: Vec<usize> = {
        let mut v = vec![n_per_tx; n_tx];
        v.push(n_block_spine_slices);
        v
    };
    let coeffs = bucket_terminal_coefficients(
        &participant_points,
        &participant_widths,
        &mu_powers,
        &beta_powers,
        &r_block,
        col_pad,
    );
    let ntt = AdditiveNTT::<Block128>::new(flat_log_len + noid_fri::code::LOG_RATE);
    let hasher = Poseidon2bSponge::new();
    verify_bucket_linear_terminal_opening(
        &bucket.commitment,
        &r_block,
        &coeffs,
        block_final_claim,
        &bucket.block_column_sumcheck_rounds,
        &bucket.mixed_opening,
        &ntt,
        &mut block_channel,
        &hasher,
    )?;

    Ok(())
}

// ---------------------------------------------------------------------------
// verify_block
// ---------------------------------------------------------------------------

/// Verify a `BlockProof`.
pub fn verify_block(
    airs: &[&dyn Air],
    proof: &BlockProof,
    spine_inputs_list: &[SpineInputs],
    auth_public_list: &[AuthPublicInputs],
    auth_proofs: &[AuthProofKillShot],
    state_binding_airs: &[&BlockStateBindingAir],
) -> Result<(), VerifyBlockError> {
    let meta = &proof.meta;
    let bucket = proof.standard_bucket()?;
    let n_tx = bucket.meta.n_tx();
    let n_air_cols = bucket.meta.n_air_per_tx as usize;
    if n_tx == 0 || airs.len() != n_tx {
        return Err(VerifyBlockError::ShapeMismatch);
    }
    let public_flags =
        public_column_flags(airs[0], n_air_cols).ok_or(VerifyBlockError::ShapeMismatch)?;
    let committed_air_indices = committed_air_indices_from_public_flags(&public_flags);
    let n_auth_slices = bucket.meta.n_boundary_slices_per_tx as usize;
    let n_per_tx = committed_air_indices.len() + n_auth_slices;
    let n_block_spine_slices = bucket.meta.n_block_spine_slices as usize;
    let n_state_bindings = meta.n_state_bindings as usize;
    let log_len = noid_stark::padded_log_len(bucket.meta.log_rows as usize);
    let n_participants = n_tx + 1;
    let spine_participant_idx = n_tx;
    let total_committed_cols = n_tx * n_per_tx + n_block_spine_slices;
    let log_cols = log2_padded_len(total_committed_cols);
    let col_pad = 1usize << log_cols;
    let flat_log_len = log_len + log_cols;

    if airs.len() != n_tx {
        return Err(VerifyBlockError::ShapeMismatch);
    }
    if airs[0].n_columns() != n_air_cols {
        return Err(VerifyBlockError::ShapeMismatch);
    }
    if !bucket.meta.tx_indices.windows(2).all(|w| w[0] < w[1]) {
        return Err(VerifyBlockError::ShapeMismatch);
    }
    if bucket.meta.shape != noid_tx::TxShape::Standard4x8
        || bucket.meta.n_tx() != n_tx
        || bucket.meta.n_air_per_tx as usize != n_air_cols
        || bucket.meta.n_boundary_slices_per_tx as usize != n_auth_slices
        || n_auth_slices != 0
        || bucket.meta.log_rows != meta.log_rows
        || bucket.meta.n_block_spine_slices as usize != n_block_spine_slices
        || bucket.tx_pis.len() != n_tx
        || auth_proofs.len() != n_tx
        || bucket.tx_algebraic.len() != n_tx
        || !proof.state_binding_algebraics.is_empty()
        || !proof.state_binding_starks.is_empty()
        || meta.state_binding_n_cols != 0
        || meta.state_binding_log_rows != 0
        || bucket.block_col_openings.len() != total_committed_cols
        || spine_inputs_list.len() != n_tx
        || auth_public_list.len() != n_tx
    {
        return Err(VerifyBlockError::ShapeMismatch);
    }
    if bucket.commitment.n_cols != 1 || bucket.commitment.log_rows != flat_log_len {
        return Err(VerifyBlockError::ShapeMismatch);
    }
    if state_binding_airs.len() != n_state_bindings {
        tracing::warn!(
            sb_airs_len = state_binding_airs.len(),
            n_state_bindings,
            "verify_block: state_binding count mismatch"
        );
        return Err(VerifyBlockError::ShapeMismatch);
    }

    let auth_circuit = AuthCircuit::build();
    let cap = &bucket.commitment.cap;

    // -------------------------------------------------------------------------
    // Unified block spine Kill-Shot + per-tx parallel verification.
    // -------------------------------------------------------------------------

    // (a) Unified block spine Kill-Shot — self-seeded, independent of per-tx channels.
    let tx_body_hashes: Vec<[Block128; 2]> = bucket
        .tx_pis
        .iter()
        .map(|pi| pi.tx_body_hash.as_fields())
        .collect();

    let block_spine_reductions = {
        let mut ch = Poseidon2bChannel::new();
        absorb_cap_into_p2b(&mut ch, cap);
        verify_block_spine_killshot(&bucket.block_spine_proof, n_tx, &tx_body_hashes, &mut ch)
            .ok_or(VerifyBlockError::BlockSpineKillShot)?
    };

    let spine_r = &block_spine_reductions.state.point;
    let spine_r_low: Vec<Block128> = {
        let mut v = spine_r[..BASE_LOG].to_vec();
        v.resize(log_len, Block128::ZERO);
        v
    };
    let spine_r_high = &spine_r[BASE_LOG..];
    let spine_offset = n_tx * n_per_tx;
    let spine_slice_vals: Vec<Block128> = (0..n_block_spine_slices)
        .map(|i| bucket.block_col_openings[spine_offset + i])
        .collect();
    let recon_spine =
        noid_core::mle::split::reconstruct_from_slices(&spine_slice_vals, spine_r_high);
    if recon_spine != block_spine_reductions.state.value {
        return Err(VerifyBlockError::BlockSpineSliceReconstruction);
    }
    let spine_extras = reduction_to_transcript(spine_r, block_spine_reductions.state.value);

    // (b) Parallel per-tx auth Kill-Shots + algebraic STARK.
    //
    // Each tx uses an independent per_tx_algebraic_channel, mirroring the prover.
    // Results are collected in order; any error short-circuits the whole block.
    struct TxVerifyResult {
        terminal: AlgebraicTerminalData,
    }

    let tx_verify_results: Vec<Result<TxVerifyResult, VerifyBlockError>> = (0..n_tx)
        .into_par_iter()
        .map(|k| {
            let pi = &bucket.tx_pis[k];
            let alg = &bucket.tx_algebraic[k];
            let spine_inputs = &spine_inputs_list[k];
            let auth_public = &auth_public_list[k];
            let claimed = pi.tx_body_hash.as_fields();

            if airs[k].n_columns() != n_air_cols
                || public_column_flags(airs[k], n_air_cols).as_ref() != Some(&public_flags)
            {
                return Err(VerifyBlockError::ShapeMismatch);
            }

            // Auth Kill-Shot (self-seeded, parallel-safe).
            let auth_reductions = {
                let mut ch = auth_gkr_channel();
                verify_auth_killshot(&auth_proofs[k], &auth_circuit, auth_public, &mut ch)
                    .ok_or(VerifyBlockError::AuthKillShot(k))?
            };

            if auth_public.tx_body_hash != claimed {
                return Err(VerifyBlockError::AuthSpineBridge(k));
            }
            let n_live = pi.n_live_inputs as usize;
            for i in 0..n_live {
                let owner_hi = spine_inputs.input_leaves[i][2];
                let owner_lo = spine_inputs.input_leaves[i][3];
                if auth_public.expected_address[i] != [owner_hi, owner_lo] {
                    return Err(VerifyBlockError::AuthSpineBridge(k));
                }
            }

            let r_auth = &auth_reductions.state.point;
            if !alg.slice_claimed_values.is_empty() {
                return Err(VerifyBlockError::ShapeMismatch);
            }

            let auth_tr = reduction_to_transcript(r_auth, auth_reductions.state.value);
            let mut extras = Vec::with_capacity(spine_extras.len() + auth_tr.len());
            extras.extend_from_slice(&spine_extras);
            extras.extend_from_slice(&auth_tr);

            let slice_claims: Vec<SliceClaim> = Vec::new();

            // Per-tx channel mirrors the prover's per_tx_algebraic_channel.
            let mut ch = per_tx_algebraic_channel(&meta.prev_block_state_root, cap, k as u32);

            let terminal = verify_air_interleaved_algebraic_terminal(
                airs[k],
                pi,
                alg,
                &extras,
                &slice_claims,
                &mut ch,
            )
            .map_err(|e| VerifyBlockError::AlgebraicStark(k, e))?;

            Ok(TxVerifyResult { terminal })
        })
        .collect();

    let mut tx_terminals = Vec::with_capacity(n_tx);
    for result in tx_verify_results {
        tx_terminals.push(result?.terminal);
    }
    for k in 0..n_tx {
        let offset = k * n_per_tx;
        verify_algebraic_terminal_against_bucket_openings(
            k,
            n_air_cols,
            &committed_air_indices,
            &bucket.block_col_openings[offset..offset + n_per_tx],
            airs[k],
            log_len,
            &bucket.tx_algebraic[k],
            &tx_terminals[k],
        )?;
    }

    // -------------------------------------------------------------------------
    // Native state-delta transition check + segment MLE openings.
    //
    // `build_state_binding_airs` reconstructs canonical claims from the block and
    // checks `post_lane(r) = pre_lane(r) + Σ eq(r, slot_i)·delta_i` at the
    // endpoint-root-derived `r`. The opening verifier below binds those lane
    // values to `prev_state_root` and `new_state_root`.
    // -------------------------------------------------------------------------
    verify_state_mle_openings(proof, state_binding_airs)?;

    // -------------------------------------------------------------------------
    // Reconstruct Merkle root of per-tx transcript digests.
    // The block channel absorbs this root instead of N sequential transcripts.
    // -------------------------------------------------------------------------
    let tx_digests: Vec<[u8; 32]> = (0..n_tx)
        .into_par_iter()
        .map(|k| {
            compute_tx_transcript_digest(
                k as u32,
                &tx_terminals[k].r_pp,
                &bucket.tx_algebraic[k].base_openings,
                &tx_terminals[k].lambdas,
                tx_terminals[k].final_claim,
            )
        })
        .collect();
    let transcript_root = merkle_reduce(&tx_digests);

    // Block multipoint channel — mirrors the prover's block_multipoint_channel.
    let mut block_channel = block_multipoint_channel(&meta.prev_block_state_root, cap);
    let [tr0, tr1] = hash_to_fields(&transcript_root);
    block_channel.observe_field_elem(tr0);
    block_channel.observe_field_elem(tr1);

    // -------------------------------------------------------------------------
    // Block-level multipoint sumcheck.
    // -------------------------------------------------------------------------

    block_channel.observe_field_elem(Block128::from(BLOCK_MULTIPOINT_TAG));
    block_channel.observe_field_elems(&bucket.block_col_openings);
    let mu = block_channel.get_random_point();
    let beta_block = block_channel.get_random_point();

    let mu_powers: Vec<Block128> = {
        let mut v = Vec::with_capacity(n_participants);
        let mut cur = Block128::ONE;
        for _ in 0..n_participants {
            v.push(cur);
            cur *= mu;
        }
        v
    };

    let max_cols = n_per_tx.max(n_block_spine_slices);
    let beta_powers: Vec<Block128> = {
        let mut v = Vec::with_capacity(max_cols);
        let mut cur = Block128::ONE;
        for _ in 0..max_cols {
            v.push(cur);
            cur *= beta_block;
        }
        v
    };

    let block_target: Block128 = {
        let mut target = Block128::ZERO;
        for k in 0..n_tx {
            let inner: Block128 = (0..n_per_tx)
                .map(|i| beta_powers[i] * bucket.block_col_openings[k * n_per_tx + i])
                .fold(Block128::ZERO, |a, b| a + b);
            target += mu_powers[k] * inner;
        }
        let inner_spine: Block128 = (0..n_block_spine_slices)
            .map(|i| beta_powers[i] * bucket.block_col_openings[spine_offset + i])
            .fold(Block128::ZERO, |a, b| a + b);
        target += mu_powers[spine_participant_idx] * inner_spine;
        target
    };

    let (block_sc_challenges, block_final_claim) =
        noid_stark::multipoint_batch::verify_multipoint_sumcheck(
            &bucket.block_multipoint_rounds,
            block_target,
            &mut block_channel,
        )
        .map_err(|_| VerifyBlockError::BlockMultipoint)?;
    if bucket.block_multipoint_challenges != block_sc_challenges {
        return Err(VerifyBlockError::BlockMultipoint);
    }

    let r_block: Vec<Block128> = block_sc_challenges.iter().rev().cloned().collect();
    if r_block.len() != log_len {
        return Err(VerifyBlockError::ShapeMismatch);
    }

    // -------------------------------------------------------------------------
    // Column-terminal compression + single-column FRI-Binius opening verify.
    // -------------------------------------------------------------------------
    let participant_points: Vec<&[Block128]> = {
        let mut v: Vec<&[Block128]> = tx_terminals.iter().map(|t| t.r_pp.as_slice()).collect();
        v.push(&spine_r_low);
        v
    };
    let participant_widths: Vec<usize> = {
        let mut v = vec![n_per_tx; n_tx];
        v.push(n_block_spine_slices);
        v
    };
    let coeffs = bucket_terminal_coefficients(
        &participant_points,
        &participant_widths,
        &mu_powers,
        &beta_powers,
        &r_block,
        col_pad,
    );
    let ntt = AdditiveNTT::<Block128>::new(flat_log_len + noid_fri::code::LOG_RATE);
    let hasher = Poseidon2bSponge::new();
    verify_bucket_linear_terminal_opening(
        &bucket.commitment,
        &r_block,
        &coeffs,
        block_final_claim,
        &bucket.block_column_sumcheck_rounds,
        &bucket.mixed_opening,
        &ntt,
        &mut block_channel,
        &hasher,
    )?;

    Ok(())
}
