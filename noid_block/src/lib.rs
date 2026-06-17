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
pub mod validate;
pub mod witness_builder;

pub use block_chain_context::{extract_replay_witness, BlockChainContext};
pub use validate::{
    build_auth_public_list, build_spine_inputs_list, build_state_binding_airs, build_tx_airs,
    validate_block_bucket_tx_indices, validate_block_from_network, validate_block_full,
    validate_block_proof_transcript_hash, validate_standard_bucket_tx_indices,
    verify_sweep_bucket_from_block, FullValidationError,
};
pub use witness_builder::{
    build_block_witnesses, build_empty_state_bindings, build_state_bindings_from_binding,
    build_tx_witness, OwnedStandardTxWitness, OwnedStateBindingWitness, OwnedSweepTxWitness,
    OwnedTxWitness,
};

use crate::channel::{
    block_multipoint_channel, compute_tx_transcript_digest, hash_to_fields, merkle_reduce,
    per_tx_algebraic_channel, state_binding_channel,
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
    MixedOpeningProof, COMPACT_NUM_QUERIES,
};
use noid_gkr::{
    auth_gkr_channel, prove_block_spine_killshot, reconstruct_slot_states, sweep_auth_gkr_channel,
    verify_auth_killshot, verify_block_spine_killshot, verify_sweep_auth_killshot, AuthCircuit,
    AuthProofKillShot, AuthPublicInputs, BlockSpineProof, SpineCircuit, SpineInputs,
    SweepAuthCircuit, SweepAuthPublicInputs, SweepSpineInputs,
};
use noid_poseidon2b::channel::Poseidon2bChannel;
use noid_poseidon2b::native::compression::Poseidon2bSponge;
use noid_poseidon2b::primitives::TxBodyHash;
use noid_stark::interleaved::{
    prove_air_interleaved, prove_air_interleaved_algebraic, verify_air_interleaved,
    verify_air_interleaved_algebraic, verify_air_interleaved_algebraic_with_log_len,
    AlgebraicStarkProof, InterleavedStarkProof,
};
use noid_stark::prove_logic_sweep::{
    SweepLogicProof, N_SWEEP_AUTH_SLICES, SWEEP_BOUNDARY_BASE_LOG,
};
use noid_stark::{SliceClaim, VerifyError};
use noid_tx::PublicInputs;
use rayon::prelude::*;
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
    /// Number of state binding AIR instances (one per touched segment; 0 = no state binding).
    pub n_state_bindings: u32,
    /// Number of columns per state binding AIR instance (0 if none).
    pub state_binding_n_cols: u32,
    /// Log-rows of each state binding AIR instance.
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
    /// Standard AuthGKR Kill-Shot proofs, one per bucket tx.
    pub tx_auth_proofs: Vec<AuthProofKillShot>,
    /// Algebraic STARK transcripts — no FRI, one per bucket tx.
    pub tx_algebraic: Vec<AlgebraicStarkProof>,
    /// Bucket column openings at per-tx, block-spine, and bucket terminal points.
    pub block_col_openings: Vec<Block128>,
    /// Bucket-level degree-2 multipoint sumcheck rounds.
    pub block_multipoint_rounds: Vec<Vec<Block128>>,
    /// Fiat-Shamir challenges produced by the bucket multipoint transcript.
    pub block_multipoint_challenges: Vec<Block128>,
    /// Single FRI-Binius mixed opening for the bucket commitment.
    pub mixed_opening: MixedOpeningProof,
    /// Initial claim for the bucket multipoint sumcheck.
    pub block_initial_claim: Block128,
}

impl StandardBucketProof {
    pub fn byte_len(&self) -> usize {
        let cap = self.commitment.cap.hashes.len() * 32;
        let alg: usize = self.tx_algebraic.iter().map(|a| a.byte_len()).sum();
        let spine = self.block_spine_proof.byte_len();
        let auth: usize = self.tx_auth_proofs.iter().map(|a| a.byte_len()).sum();
        let col_open = self.block_col_openings.len() * 16;
        let mp: usize = self
            .block_multipoint_rounds
            .iter()
            .map(|r| r.len() * 16)
            .sum();
        let challenges = self.block_multipoint_challenges.len() * 16;
        let mixed = self.mixed_opening.byte_len();
        cap + alg + spine + auth + col_open + mp + challenges + mixed
    }
}

/// Sweep25x2 bucket proof target shape.
///
/// Sweep wallet logic proofs are already full shape-specific proofs. The sweep
/// block bucket binds those proofs to concrete block transaction indices and
/// public inputs, then aggregates sweep balance AIR columns plus wallet-provided
/// AuthGKR `state` slices through a bucket commitment, multipoint sumcheck, and
/// mixed opening. Common state binding remains at `BlockProof` level.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SweepBucketProof {
    pub meta: ShapeBucketMeta,
    /// Public inputs for bucket transactions, index-aligned with `meta.tx_indices`.
    pub tx_pis: Vec<PublicInputs>,
    /// Public-only sweep auth boundaries, one per bucket tx.
    pub auth_public: Vec<SweepAuthPublicInputs>,
    /// Sweep AuthGKR `state` slices, one slice-list per bucket tx.
    pub auth_slices: Vec<Vec<Vec<Block128>>>,
    /// Public sweep tx-body spine inputs, one per bucket tx.
    pub spine_inputs: Vec<SweepSpineInputs>,
    /// Wallet-produced sweep logic proofs, one per bucket tx.
    pub logic_proofs: Vec<SweepLogicProof>,
    /// Interleaved commitment for sweep balance AIR columns + sweep auth slices.
    pub commitment: InterleavedCommitment,
    /// Algebraic STARK transcripts — no per-tx FRI, one per sweep tx.
    pub tx_algebraic: Vec<AlgebraicStarkProof>,
    /// Bucket column openings at per-tx terminal points.
    pub block_col_openings: Vec<Block128>,
    /// Bucket-level degree-2 multipoint sumcheck rounds.
    pub block_multipoint_rounds: Vec<Vec<Block128>>,
    /// Fiat-Shamir challenges produced by the sweep bucket multipoint transcript.
    pub block_multipoint_challenges: Vec<Block128>,
    /// Single FRI-Binius mixed opening for the sweep bucket commitment.
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
    /// Algebraic STARK transcripts for state binding AIRs (one per touched segment)
    /// when state binding columns are aggregated into the standard bucket commitment.
    pub state_binding_algebraics: Vec<AlgebraicStarkProof>,
    /// Standalone full STARK proofs for state binding AIRs. Used for sweep-only
    /// blocks where there is no standard bucket commitment to carry these columns.
    pub state_binding_starks: Vec<InterleavedStarkProof>,
    /// FRI+Merkle opening proofs for pre-state segment MLEs (FRI + Merkle path).
    /// One per dirty segment. Proves `BlockStateBindingAir.prev_lane_openings` are real.
    pub pre_state_openings: Vec<SegmentMleOpening>,
    /// FRI+Merkle opening proofs for post-state segment MLEs (FRI + Merkle path).
    /// One per dirty segment. Proves `BlockStateBindingAir.new_lane_openings` are real.
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
// Canonical recursive block claim (Phase N7)
// ---------------------------------------------------------------------------

pub const BLOCK_RECURSIVE_CLAIM_DOMAIN: &[u8] = b"NOID_BLOCK_RECURSIVE_CLAIM_V1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum StateBindingProofMode {
    Empty,
    Algebraic,
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

pub fn state_binding_proof_mode(proof: &BlockProof) -> StateBindingProofMode {
    match (
        proof.state_binding_algebraics.is_empty(),
        proof.state_binding_starks.is_empty(),
    ) {
        (true, true) => StateBindingProofMode::Empty,
        (false, true) => StateBindingProofMode::Algebraic,
        (true, false) => StateBindingProofMode::Standalone,
        (false, false) => StateBindingProofMode::MixedInvalid,
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

pub fn block_recursive_claim_bytes(proof: &BlockProof) -> Vec<u8> {
    bincode::serialize(&block_recursive_claim_transcript(proof))
        .expect("BlockRecursiveClaimTranscript serialization must be infallible")
}

pub fn block_recursive_claim_hash(proof: &BlockProof) -> [u8; 32] {
    noid_chain::block::proof_transcript_hash(&block_recursive_claim_bytes(proof))
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
    BlockSpineKillShot,
    BlockSpineSliceReconstruction,
    AuthKillShot(usize),
    AuthSpineBridge(usize),
    AuthSliceReconstruction(usize),
    SweepLogic(usize),
    AlgebraicStark(usize, VerifyError),
    BlockMultipoint,
    FriFailed(String),
    /// FRI/Merkle opening for a segment MLE failed.
    StateMleOpeningFailed(usize),
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
    /// Pre-built auth proof from the wallet. The block prover includes
    /// this as-is without re-proving.
    pub auth_proof: &'a AuthProofKillShot,
    /// Pre-built auth MLE slices from the wallet (`2^(N_AUTH_UNIFIED_VARS - BASE_LOG)`
    /// slices, each of length `2^BASE_LOG`). With BASE_LOG=11 this is 8 slices
    /// of 2048 elements.  Needed for the interleaved commitment.
    pub auth_slices: &'a [Vec<Block128>],
}

// ---------------------------------------------------------------------------
// Block-level state binding witness bundle
// ---------------------------------------------------------------------------

/// Optional state binding witness for prove_block.
/// When present, the BlockStateBindingAir columns are committed alongside
/// per-tx columns and proven via the shared block channel.
pub struct StateBindingBlockWitness<'a> {
    pub air: &'a BlockStateBindingAir,
    pub columns: Vec<Vec<Block128>>,
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

fn build_auth_slice_claims(
    n_air_cols: usize,
    auth_r_low: &[Block128],
    auth_vals: &[Block128],
) -> Vec<SliceClaim> {
    let mut claims = Vec::with_capacity(2);
    for (i, &val) in auth_vals.iter().enumerate() {
        claims.push(SliceClaim {
            col_index: n_air_cols + i,
            eval_point: auth_r_low.to_vec(),
            value: val,
        });
    }
    claims
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
/// real aggregation transcript over sweep balance AIR columns and sweep AuthGKR
/// `state` slices. Verification is performed by
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
    let n_auth_slices = witnesses[0].auth_slices.len();
    let n_per_tx = n_air_per_tx + n_auth_slices;
    let log_rows = witnesses[0].trace.log_rows;
    let log_len = noid_stark::padded_log_len(log_rows);
    if log_len != BASE_LOG {
        return Err(ProveBlockError::InvalidTxIndices);
    }
    for w in witnesses {
        if w.air.n_columns() != n_air_per_tx
            || w.auth_slices.len() != N_SWEEP_AUTH_SLICES
            || w.auth_slices.len() != n_auth_slices
            || !w
                .auth_slices
                .iter()
                .all(|slice| slice.len() == (1usize << SWEEP_BOUNDARY_BASE_LOG))
            || w.trace.log_rows != log_rows
            || w.pi.shape_id != noid_tx::TxShape::Sweep25x2.id()
        {
            return Err(ProveBlockError::InvalidTxIndices);
        }
    }

    let mut per_tx_columns: Vec<Vec<Vec<Block128>>> = Vec::with_capacity(n_tx);
    let mut flat_refs: Vec<&[Block128]> = Vec::with_capacity(n_tx * n_per_tx);
    for w in witnesses {
        let mut cols: Vec<Vec<Block128>> = Vec::with_capacity(n_per_tx);
        for col in &w.trace.columns {
            cols.push(noid_stark::pad_column(col, log_len));
        }
        for s in &w.auth_slices {
            cols.push(s.clone());
        }
        per_tx_columns.push(cols);
    }
    for cols in &per_tx_columns {
        for col in cols {
            flat_refs.push(col.as_slice());
        }
    }

    let ntt = AdditiveNTT::<Block128>::new(log_len + noid_fri::code::LOG_RATE);
    let hasher = Poseidon2bSponge::new();
    let (commitment, prover_state) = interleaved_commit(&flat_refs, &ntt, &hasher);
    let cap = &commitment.cap;

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
                &w.logic_proof.auth,
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
            let auth_r_low = &r_auth[..BASE_LOG];
            let auth_r_high = &r_auth[BASE_LOG..];
            let auth_slice_vals: Vec<Block128> = w
                .auth_slices
                .iter()
                .map(|s| noid_core::mle::evaluate::evaluate_slice(s, auth_r_low))
                .collect();
            let recon_auth =
                noid_core::mle::split::reconstruct_from_slices(&auth_slice_vals, auth_r_high);
            if recon_auth != auth_reductions.state.value {
                return None;
            }

            let auth_tr = reduction_to_transcript(r_auth, auth_reductions.state.value);
            let slice_claims = build_auth_slice_claims(n_air_per_tx, auth_r_low, &auth_slice_vals);
            let col_refs: Vec<&[Block128]> =
                per_tx_columns[k].iter().map(|c| c.as_slice()).collect();
            let mut ch = per_tx_algebraic_channel(&prev_block_state_root, cap, k as u32);
            let (alg, r_pp, final_claim, lambdas) = prove_air_interleaved_algebraic(
                &w.air,
                &col_refs,
                &w.pi,
                &auth_tr,
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

    let mut block_col_openings: Vec<Block128> = Vec::with_capacity(n_tx * n_per_tx);
    for k in 0..n_tx {
        for col in &per_tx_columns[k] {
            block_col_openings.push(noid_core::mle::evaluate::evaluate_flat(col, &tx_r_pp[k]));
        }
    }

    block_channel.observe_field_elem(Block128::from(BLOCK_MULTIPOINT_TAG));
    block_channel.observe_field_elems(&block_col_openings);
    let mu = block_channel.get_random_point();
    let beta_block = block_channel.get_random_point();

    let mu_powers: Vec<Block128> = {
        let mut v = Vec::with_capacity(n_tx);
        let mut cur = Block128::ONE;
        for _ in 0..n_tx {
            v.push(cur);
            cur *= mu;
        }
        v
    };
    let beta_powers: Vec<Block128> = {
        let mut v = Vec::with_capacity(n_per_tx);
        let mut cur = Block128::ONE;
        for _ in 0..n_per_tx {
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
        target
    };

    let pairs_a: Vec<Vec<Block128>> = (0..n_tx)
        .into_par_iter()
        .map(|k| {
            let eq_k = eq_ind_partial_eval(&tx_r_pp[k]);
            eq_k.into_iter().map(|v| v * mu_powers[k]).collect()
        })
        .collect();

    use noid_core::hardware::{clmul_gcm, tower_to_flat_u128};
    let beta_powers_flat: Vec<u128> = beta_powers
        .iter()
        .map(|v| tower_to_flat_u128(v.0))
        .collect();
    let hyper_len = 1usize << log_len;
    let pairs_b_flat: Vec<Vec<u128>> = (0..n_tx)
        .into_par_iter()
        .map(|k| {
            let mut b_k = vec![0u128; hyper_len];
            for (i, col) in per_tx_columns[k].iter().enumerate() {
                let lam = beta_powers_flat[i];
                b_k.iter_mut().zip(col.iter()).for_each(|(acc, &v)| {
                    *acc ^= clmul_gcm(lam, tower_to_flat_u128(v.0));
                });
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
    let mixed_opening = prove_mixed_opening(
        &prover_state,
        &r_block,
        &[],
        &ntt,
        &mut block_channel,
        &hasher,
        COMPACT_NUM_QUERIES,
    );

    Ok(Some(SweepBucketProof {
        meta: ShapeBucketMeta {
            shape: noid_tx::TxShape::Sweep25x2,
            tx_indices,
            n_air_per_tx: n_air_per_tx as u32,
            n_boundary_slices_per_tx: n_auth_slices as u32,
            log_rows: log_rows as u32,
            n_block_spine_slices: 0,
        },
        tx_pis: witnesses.iter().map(|w| w.pi.clone()).collect(),
        auth_public: witnesses.iter().map(|w| w.auth_public).collect(),
        auth_slices: witnesses.iter().map(|w| w.auth_slices.clone()).collect(),
        spine_inputs: witnesses.iter().map(|w| w.spine_inputs.clone()).collect(),
        logic_proofs: witnesses.iter().map(|w| w.logic_proof.clone()).collect(),
        commitment,
        tx_algebraic,
        block_col_openings,
        block_multipoint_rounds,
        block_multipoint_challenges: block_mp_challenges,
        mixed_opening,
        block_initial_claim: block_target,
    }))
}

fn empty_state_binding_public_inputs() -> PublicInputs {
    PublicInputs {
        epoch_anchor: [0u8; 32],
        tx_body_hash: TxBodyHash([0u8; 32]),
        shape_id: noid_tx::TxShape::Standard4x8.id(),
        fee: 0,
        n_live_inputs: 0,
        n_live_outputs: 0,
        coinbase_credit: 0,
        log_slots: 0,
        claims_commitment: [0u8; 32],
        is_activation: [false; 8],
        is_deactivation: [false; 4],
    }
}

/// Prove block-level state binding as standalone full STARKs.
///
/// This path is used when a block has no standard bucket commitment (for
/// example sweep-only blocks). It preserves the SC-3 security property by
/// proving each `BlockStateBindingAir` directly with its own FRI commitment.
pub fn prove_state_bindings_standalone(
    state_bindings: &[StateBindingBlockWitness<'_>],
) -> (
    Vec<InterleavedStarkProof>,
    Vec<SegmentMleOpening>,
    Vec<SegmentMleOpening>,
) {
    let empty_pi = empty_state_binding_public_inputs();
    let mut starks = Vec::with_capacity(state_bindings.len());
    let mut pre_state_openings: Vec<SegmentMleOpening> = Vec::with_capacity(state_bindings.len());
    let mut post_state_openings: Vec<SegmentMleOpening> = Vec::with_capacity(state_bindings.len());

    for sb in state_bindings {
        let log_len = noid_stark::padded_log_len(sb.air.log_rows());
        let columns = sb.air.extend_for_proving(sb.columns.clone(), log_len);
        starks.push(prove_air_interleaved(
            sb.air,
            &columns,
            &empty_pi,
            &[],
            &[],
            log_len,
            None,
            COMPACT_NUM_QUERIES,
        ));

        if let Some(pre_cols) = sb.pre_cols {
            let seg_id = sb.seg_id;
            let eff_log = sb.air.eval_point.len();
            let (pre_commit, pre_vals, pre_proof, pre_seg_root) = open_segment_at_point(
                eff_log,
                &pre_cols.values,
                &pre_cols.owners_hi,
                &pre_cols.owners_lo,
                &sb.air.eval_point,
            );
            pre_state_openings.push(SegmentMleOpening {
                seg_id,
                eval_point: sb.air.eval_point.clone(),
                lane_values: pre_vals,
                commitment: pre_commit,
                opening: pre_proof,
                seg_root: pre_seg_root,
                merkle_siblings: sb.pre_siblings.to_vec(),
            });

            let post_cols = apply_claims_to_cols(pre_cols, sb.claims);
            let (post_commit, post_vals, post_proof, post_seg_root) = open_segment_at_point(
                eff_log,
                &post_cols.values,
                &post_cols.owners_hi,
                &post_cols.owners_lo,
                &sb.air.eval_point,
            );
            post_state_openings.push(SegmentMleOpening {
                seg_id,
                eval_point: sb.air.eval_point.clone(),
                lane_values: post_vals,
                commitment: post_commit,
                opening: post_proof,
                seg_root: post_seg_root,
                merkle_siblings: sb.post_siblings.to_vec(),
            });
        }
    }

    (starks, pre_state_openings, post_state_openings)
}

pub fn verify_state_bindings_standalone(
    proof: &BlockProof,
    state_binding_airs: &[&BlockStateBindingAir],
) -> Result<(), VerifyBlockError> {
    let n_state_bindings = proof.meta.n_state_bindings as usize;
    if proof.state_binding_starks.len() != n_state_bindings
        || !proof.state_binding_algebraics.is_empty()
        || state_binding_airs.len() != n_state_bindings
    {
        return Err(VerifyBlockError::ShapeMismatch);
    }

    let empty_pi = empty_state_binding_public_inputs();
    for (sb_idx, sb_air) in state_binding_airs.iter().enumerate() {
        verify_air_interleaved(
            *sb_air,
            &empty_pi,
            &proof.state_binding_starks[sb_idx],
            &[],
            &[],
            COMPACT_NUM_QUERIES,
        )
        .map_err(|e| VerifyBlockError::AlgebraicStark(sb_idx, e))?;
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
    // Number of auth slices per tx: inferred from the first witness so the
    // block prover stays robust if BASE_LOG changes in wallet proving.
    // Expected today: 2^(N_AUTH_UNIFIED_VARS - BASE_LOG) = 2^(14-11) = 8.
    let n_auth_slices: usize = witnesses[0].auth_slices.len();
    let n_per_tx = n_air_cols + n_auth_slices;
    let log_len = noid_stark::padded_log_len(witnesses[0].trace.log_rows);
    profiler.phase("setup");

    // -------------------------------------------------------------------------
    // Build per-tx column pools + block spine MLE.
    // -------------------------------------------------------------------------
    // Per-tx: AIR columns (padded) + N_AUTH_SLICES auth slices.
    // Block-level: unified spine state MLE split into slices.

    // Build fixed columns once from the first witness AIR (all txs share the
    // same AIR shape).  Fixed columns (selectors / masks) are padded once and
    // reused across all N transactions via zero-copy refs, avoiding N-1 extra
    // copies of ~65 MB of selector data per block.
    let shared_fixed = FixedColumns::from_air(witnesses[0].air, witnesses[0].trace, log_len);

    struct TxPrep<'a> {
        /// Non-fixed AIR witness columns in ascending original column-index order.
        witness_cols: Vec<Vec<Block128>>,
        /// Per-tx auth slices borrowed from the wallet bundle; no block-time clone.
        auth_slices: &'a [Vec<Block128>],
    }

    // Parallel prep loop.
    // Each tx's spine-state reconstruction and witness column padding are
    // fully independent; parallelize across txs with rayon.
    struct TxPrepBundle<'a> {
        slot_state_ins: Vec<[Block128; 4]>,
        prep: TxPrep<'a>,
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
                prep: TxPrep {
                    witness_cols,
                    auth_slices: w.auth_slices,
                },
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
    // Layout: [per-tx columns | block spine slices | state binding columns…].
    // Multiple state binding AIRs (one per dirty segment) are flattened.
    // -------------------------------------------------------------------------
    let n_state_bindings = state_bindings.len();
    let sb_n_cols_per_seg = state_bindings.first().map_or(0, |sb| sb.air.n_columns());
    let sb_log_rows = state_bindings.first().map_or(0, |sb| sb.air.log_rows());
    let sb_n_cols_total = sb_n_cols_per_seg * n_state_bindings;

    // Extend all state binding columns to log_len using constraint-aware padding.
    // Standard zero-padding violates the eq-ladder base constraint at external rows;
    // `extend_for_proving` pads eq_ladder columns with 1 instead of 0 so that
    // `eq_0 + r_0 + b_0 + 1 = 1 + 0 + 0 + 1 = 0` (char-2) holds everywhere.
    let sb_padded_columns: Vec<Vec<Block128>> = state_bindings
        .iter()
        .flat_map(|sb| sb.air.extend_for_proving(sb.columns.clone(), log_len))
        .collect();
    // Pad block spine slices to log_len (they may be shorter if num_vars < BASE_LOG).
    let spine_padded_slices: Vec<Vec<Block128>> = block_spine_slices
        .iter()
        .map(|s| noid_stark::pad_column(s, log_len))
        .collect();

    // Build the flat column-ref list for the interleaved commitment.
    // For each tx: fixed columns (zero-copy from shared_fixed) then witness then auth slices.
    let mut flat_refs: Vec<&[Block128]> =
        Vec::with_capacity(n_tx * n_per_tx + n_block_spine_slices + sb_n_cols_total);
    for p in &preps {
        let air_refs = shared_fixed.build_full_col_refs(n_air_cols, &p.witness_cols);
        flat_refs.extend_from_slice(&air_refs);
        for s in p.auth_slices {
            flat_refs.push(s.as_slice());
        }
    }
    for s in &spine_padded_slices {
        flat_refs.push(s.as_slice());
    }
    for c in &sb_padded_columns {
        flat_refs.push(c.as_slice());
    }
    profiler.phase("state_binding_padding_and_flat_refs");

    let ntt = AdditiveNTT::<Block128>::new(log_len + noid_fri::code::LOG_RATE);
    let hasher = Poseidon2bSponge::new();
    let (commitment, prover_state) = interleaved_commit(&flat_refs, &ntt, &hasher);
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
        auth_r_low: Vec<Block128>,
        auth_slice_vals: Vec<Block128>,
        extras_transcript: Vec<Block128>,
    }

    // Verify wallet auth proofs; collect per-tx results or surface the first failure.
    let auth_results_raw: Vec<Option<AuthResult>> = (0..n_tx)
        .into_par_iter()
        .map(|k| {
            let prep = &preps[k];
            let mut ch = auth_gkr_channel();
            let auth_reductions = verify_auth_killshot(
                auth_proof_refs[k],
                &auth_circuit,
                auth_public_refs[k],
                &mut ch,
            )?; // returns None on failure

            let r_auth = auth_reductions.state.point.clone();
            let auth_r_low = r_auth[..BASE_LOG].to_vec();

            let auth_slice_vals: Vec<Block128> = prep
                .auth_slices
                .iter()
                .map(|s| noid_core::mle::evaluate::evaluate_slice(s, &auth_r_low))
                .collect();

            let auth_tr = reduction_to_transcript(&r_auth, auth_reductions.state.value);
            let mut extras = Vec::with_capacity(spine_extras.len() + auth_tr.len());
            extras.extend_from_slice(&spine_extras);
            extras.extend_from_slice(&auth_tr);

            Some(AuthResult {
                auth_r_low,
                auth_slice_vals,
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

            let slice_claims = build_auth_slice_claims(
                n_air_cols,
                &auth_res.auth_r_low,
                &auth_res.auth_slice_vals,
            );

            // Per-tx independent Fiat-Shamir channel, domain-separated by tx index.
            let mut ch = per_tx_algebraic_channel(&prev_block_state_root, cap, k as u32);

            // Build full ordered column refs (fixed zero-copy + witness).
            let mut all_col_refs = shared_fixed.build_full_col_refs(n_air_cols, &prep.witness_cols);
            for s in prep.auth_slices {
                all_col_refs.push(s.as_slice());
            }

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
    // BlockStateBindingAir algebraic STARKs — one per segment AIR.
    // Each gets a dedicated channel seeded with (prev_state_root, cap,
    // n_tx + sb_idx) — combined index avoids overlap with per-tx channels.
    // -------------------------------------------------------------------------
    let empty_pi = PublicInputs {
        epoch_anchor: [0u8; 32],
        tx_body_hash: TxBodyHash([0u8; 32]),
        shape_id: noid_tx::TxShape::Standard4x8.id(),
        fee: 0,
        n_live_inputs: 0,
        n_live_outputs: 0,
        coinbase_credit: 0,
        log_slots: 0,
        claims_commitment: [0u8; 32],
        is_activation: [false; 8],
        is_deactivation: [false; 4],
    };

    // One algebraic proof + r_pp per state-binding AIR.
    struct SbResult {
        alg: AlgebraicStarkProof,
        r_pp: Vec<Block128>,
    }
    let sb_results: Vec<SbResult> = state_bindings
        .iter()
        .enumerate()
        .map(|(sb_idx, sb)| {
            // Channel seed: n_tx + sb_idx distinguishes each segment's channel.
            let mut sb_ch = state_binding_channel(
                &prev_block_state_root,
                cap,
                total_non_coinbase_tx + sb_idx as u32,
            );
            let col_offset = sb_idx * sb_n_cols_per_seg;
            let sb_col_refs: Vec<&[Block128]> = sb_padded_columns
                [col_offset..col_offset + sb_n_cols_per_seg]
                .iter()
                .map(|c| c.as_slice())
                .collect();
            let (alg, r_pp_sb, _, _) = prove_air_interleaved_algebraic(
                sb.air,
                &sb_col_refs,
                &empty_pi,
                &[],
                &[],
                log_len,
                &mut sb_ch,
            );
            SbResult { alg, r_pp: r_pp_sb }
        })
        .collect();

    let sb_algebraics: Vec<AlgebraicStarkProof> =
        sb_results.iter().map(|r| r.alg.clone()).collect();
    let sb_r_pp_list: Vec<Vec<Block128>> = sb_results.into_iter().map(|r| r.r_pp).collect();
    profiler.phase("state_binding_algebraic_starks");

    // -------------------------------------------------------------------------
    // Per-segment FRI MLE openings + Merkle path.
    //
    // For each dirty segment, open the 3 pre-state and 3 post-state columns at
    // eval_point using compact interleaved FRI (same scheme as SegmentedFriState).
    // The resulting seg_root matches the Merkle tree leaf exactly.
    // post_cols is derived from pre_cols + claims and dropped immediately after.
    // -------------------------------------------------------------------------
    let mut pre_state_openings: Vec<SegmentMleOpening> = Vec::with_capacity(n_state_bindings);
    let mut post_state_openings: Vec<SegmentMleOpening> = Vec::with_capacity(n_state_bindings);
    for sb in state_bindings {
        if let Some(pre_cols) = sb.pre_cols {
            let seg_id = sb.seg_id;
            let eff_log = sb.air.eval_point.len();

            // Pre-state: zero-copy (borrows pre_cols).
            let (pre_commit, pre_vals, pre_proof, pre_seg_root) = open_segment_at_point(
                eff_log,
                &pre_cols.values,
                &pre_cols.owners_hi,
                &pre_cols.owners_lo,
                &sb.air.eval_point,
            );
            pre_state_openings.push(SegmentMleOpening {
                seg_id,
                eval_point: sb.air.eval_point.clone(),
                lane_values: pre_vals,
                commitment: pre_commit,
                opening: pre_proof,
                seg_root: pre_seg_root,
                merkle_siblings: sb.pre_siblings.to_vec(),
            });

            // Post-state: derive columns, open, then drop immediately.
            let post_cols = apply_claims_to_cols(pre_cols, sb.claims);
            let (post_commit, post_vals, post_proof, post_seg_root) = open_segment_at_point(
                eff_log,
                &post_cols.values,
                &post_cols.owners_hi,
                &post_cols.owners_lo,
                &sb.air.eval_point,
            );
            // post_cols dropped here — frees memory immediately.
            post_state_openings.push(SegmentMleOpening {
                seg_id,
                eval_point: sb.air.eval_point.clone(),
                lane_values: post_vals,
                commitment: post_commit,
                opening: post_proof,
                seg_root: post_seg_root,
                merkle_siblings: sb.post_siblings.to_vec(),
            });
        }
    }
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
    //   0..n_tx: per-tx (AIR + auth slices), each with n_per_tx columns
    //   n_tx: block spine slices participant (opened at spine_r_low)
    //   n_tx+1: state binding (if present)
    // -------------------------------------------------------------------------
    // One participant per state binding AIR (segment), plus spine and per-tx.
    let n_participants = n_tx + 1 + n_state_bindings; // +1 for spine
    let spine_participant_idx = n_tx;
    // State binding participants are at indices n_tx+1 .. n_tx+1+n_state_bindings.
    let sb_participant_base = n_tx + 1;

    // M2: Parallel per-tx column openings with thread-local scratch.
    // Eliminates ~n_tx * n_per_tx * 128 KB = ~1 GB of allocations for 100 txs.
    let total_cols = n_tx * n_per_tx + n_block_spine_slices + sb_n_cols_total;

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
                    for col in &air_refs {
                        cols_k.push(noid_core::mle::evaluate::evaluate_flat_with_scratch(
                            col, r_pp_k, &mut flat, &mut pt,
                        ));
                    }
                    for auth_s in preps[k].auth_slices {
                        cols_k.push(noid_core::mle::evaluate::evaluate_flat_with_scratch(
                            auth_s, r_pp_k, &mut flat, &mut pt,
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
            // State binding columns: one block per AIR instance.
            for sb_idx in 0..n_state_bindings {
                let col_offset = sb_idx * sb_n_cols_per_seg;
                let r_pp = &sb_r_pp_list[sb_idx];
                for i in 0..sb_n_cols_per_seg {
                    block_col_openings.push(noid_core::mle::evaluate::evaluate_flat_with_scratch(
                        &sb_padded_columns[col_offset + i],
                        r_pp,
                        &mut flat,
                        &mut pt,
                    ));
                }
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

    let max_cols = n_per_tx.max(n_block_spine_slices).max(sb_n_cols_per_seg);
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
        // State binding participants (one per dirty segment).
        if sb_n_cols_per_seg > 0 {
            let sb_base_offset = spine_offset + n_block_spine_slices;
            for sb_idx in 0..n_state_bindings {
                let col_offset = sb_base_offset + sb_idx * sb_n_cols_per_seg;
                let inner: Block128 = (0..sb_n_cols_per_seg)
                    .map(|i| beta_powers[i] * block_col_openings[col_offset + i])
                    .fold(Block128::ZERO, |a, b| a + b);
                target += mu_powers[sb_participant_base + sb_idx] * inner;
            }
        }
        target
    };
    profiler.phase("sumcheck_challenge_and_target");

    // Collect all r_pp points for all participants.
    let all_r_pp: Vec<&[Block128]> = {
        let mut v: Vec<&[Block128]> = tx_r_pp.iter().map(|r| r.as_slice()).collect();
        v.push(&spine_r_low); // block spine
        for r in &sb_r_pp_list {
            v.push(r.as_slice()); // one per state binding AIR
        }
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
                for i in 0..n_air_cols {
                    let lam_flat = beta_powers_flat[i];
                    let col = air_refs[i];
                    b_k.iter_mut().zip(col.iter()).for_each(|(acc, &v)| {
                        *acc ^= clmul_gcm(lam_flat, tower_to_flat_u128(v.0));
                    });
                }
                for (off, s) in preps[k].auth_slices.iter().enumerate() {
                    let lam_flat = beta_powers_flat[n_air_cols + off];
                    b_k.iter_mut().zip(s.iter()).for_each(|(acc, &v)| {
                        *acc ^= clmul_gcm(lam_flat, tower_to_flat_u128(v.0));
                    });
                }
                b_k
            } else if k == spine_participant_idx {
                let mut b_k = vec![0u128; hyper_len];
                for i in 0..n_block_spine_slices {
                    let lam_flat = beta_powers_flat[i];
                    let col = spine_padded_slices[i].as_slice();
                    b_k.iter_mut().zip(col.iter()).for_each(|(acc, &v)| {
                        *acc ^= clmul_gcm(lam_flat, tower_to_flat_u128(v.0));
                    });
                }
                b_k
            } else {
                // State binding participant k → segment index sb_idx.
                let sb_idx = k - sb_participant_base;
                let col_offset = sb_idx * sb_n_cols_per_seg;
                let mut b_k = vec![0u128; hyper_len];
                for i in 0..sb_n_cols_per_seg {
                    let lam_flat = beta_powers_flat[i];
                    let col = sb_padded_columns[col_offset + i].as_slice();
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
    // Single FRI-Binius mixed opening at r_block.
    // -------------------------------------------------------------------------
    let mixed_opening = prove_mixed_opening(
        &prover_state,
        &r_block,
        &[],
        &ntt,
        &mut block_channel,
        &hasher,
        COMPACT_NUM_QUERIES,
    );
    profiler.phase("mixed_opening");

    let tx_pis: Vec<PublicInputs> = witnesses.iter().map(|w| w.pi.clone()).collect();
    let tx_auth_proofs: Vec<AuthProofKillShot> =
        witnesses.iter().map(|w| w.auth_proof.clone()).collect();
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
        state_binding_n_cols: sb_n_cols_per_seg as u32,
        state_binding_log_rows: sb_log_rows as u32,
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
        tx_auth_proofs,
        tx_algebraic,
        block_col_openings,
        block_multipoint_rounds: block_mp_rounds,
        block_multipoint_challenges: block_mp_challenges,
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

// ---------------------------------------------------------------------------
// Sweep bucket aggregation verifier
// ---------------------------------------------------------------------------

pub fn verify_sweep_bucket_aggregation(
    prev_block_state_root: &[u8; 32],
    airs: &[&dyn Air],
    bucket: &SweepBucketProof,
) -> Result<(), VerifyBlockError> {
    let n_tx = bucket.meta.n_tx();
    let n_air_cols = bucket.meta.n_air_per_tx as usize;
    let n_auth_slices = bucket.meta.n_boundary_slices_per_tx as usize;
    let n_per_tx = n_air_cols + n_auth_slices;
    let log_len = noid_stark::padded_log_len(bucket.meta.log_rows as usize);
    let total_cols = n_tx * n_per_tx;

    if bucket.meta.shape != noid_tx::TxShape::Sweep25x2
        || airs.len() != n_tx
        || bucket.tx_pis.len() != n_tx
        || bucket.auth_public.len() != n_tx
        || bucket.auth_slices.len() != n_tx
        || bucket.spine_inputs.len() != n_tx
        || bucket.logic_proofs.len() != n_tx
        || bucket.tx_algebraic.len() != n_tx
        || bucket.block_col_openings.len() != total_cols
        || bucket.commitment.n_cols != total_cols
        || n_auth_slices != N_SWEEP_AUTH_SLICES
        || log_len != BASE_LOG
    {
        return Err(VerifyBlockError::ShapeMismatch);
    }

    let auth_circuit = SweepAuthCircuit::build();
    let cap = &bucket.commitment.cap;

    struct TxVerifyResult {
        r_pp: Vec<Block128>,
        final_claim: Block128,
        lambdas: Vec<Block128>,
    }

    let tx_verify_results: Vec<Result<TxVerifyResult, VerifyBlockError>> = (0..n_tx)
        .into_par_iter()
        .map(|k| {
            let pi = &bucket.tx_pis[k];
            let alg = &bucket.tx_algebraic[k];
            let auth_public = &bucket.auth_public[k];
            let spine_inputs = &bucket.spine_inputs[k];
            let logic_proof = &bucket.logic_proofs[k];
            let auth_slices = &bucket.auth_slices[k];

            if airs[k].n_columns() != n_air_cols
                || auth_slices.len() != n_auth_slices
                || !auth_slices
                    .iter()
                    .all(|slice| slice.len() == (1usize << SWEEP_BOUNDARY_BASE_LOG))
            {
                return Err(VerifyBlockError::ShapeMismatch);
            }

            let mut auth_ch = sweep_auth_gkr_channel();
            let auth_reductions = verify_sweep_auth_killshot(
                &logic_proof.auth,
                &auth_circuit,
                auth_public,
                &mut auth_ch,
            )
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
            let auth_r_low = &r_auth[..BASE_LOG];
            let auth_r_high = &r_auth[BASE_LOG..];
            if alg.slice_claimed_values.len() != n_auth_slices {
                return Err(VerifyBlockError::ShapeMismatch);
            }
            let auth_slice_vals = &alg.slice_claimed_values[..n_auth_slices];
            let actual_auth_slice_vals: Vec<Block128> = auth_slices
                .iter()
                .map(|s| noid_core::mle::evaluate::evaluate_slice(s, auth_r_low))
                .collect();
            if actual_auth_slice_vals != auth_slice_vals {
                return Err(VerifyBlockError::AuthSliceReconstruction(k));
            }
            let recon_auth =
                noid_core::mle::split::reconstruct_from_slices(auth_slice_vals, auth_r_high);
            if recon_auth != auth_reductions.state.value {
                return Err(VerifyBlockError::AuthSliceReconstruction(k));
            }

            let auth_tr = reduction_to_transcript(r_auth, auth_reductions.state.value);
            let slice_claims = build_auth_slice_claims(n_air_cols, auth_r_low, auth_slice_vals);
            let mut ch = per_tx_algebraic_channel(prev_block_state_root, cap, k as u32);
            let (r_pp, final_claim, lambdas) = verify_air_interleaved_algebraic(
                airs[k],
                pi,
                alg,
                &auth_tr,
                &slice_claims,
                &mut ch,
            )
            .map_err(|e| VerifyBlockError::AlgebraicStark(k, e))?;

            Ok(TxVerifyResult {
                r_pp,
                final_claim,
                lambdas,
            })
        })
        .collect();

    let mut tx_r_pp = Vec::with_capacity(n_tx);
    let mut tx_final_claims = Vec::with_capacity(n_tx);
    let mut tx_lambdas = Vec::with_capacity(n_tx);
    for result in tx_verify_results {
        let r = result?;
        tx_r_pp.push(r.r_pp);
        tx_final_claims.push(r.final_claim);
        tx_lambdas.push(r.lambdas);
    }

    let tx_digests: Vec<[u8; 32]> = (0..n_tx)
        .into_par_iter()
        .map(|k| {
            compute_tx_transcript_digest(
                k as u32,
                &tx_r_pp[k],
                &bucket.tx_algebraic[k].base_openings,
                &tx_lambdas[k],
                tx_final_claims[k],
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

    let mu_powers: Vec<Block128> = {
        let mut v = Vec::with_capacity(n_tx);
        let mut cur = Block128::ONE;
        for _ in 0..n_tx {
            v.push(cur);
            cur *= mu;
        }
        v
    };
    let beta_powers: Vec<Block128> = {
        let mut v = Vec::with_capacity(n_per_tx);
        let mut cur = Block128::ONE;
        for _ in 0..n_per_tx {
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

    let ntt = AdditiveNTT::<Block128>::new(log_len + noid_fri::code::LOG_RATE);
    let hasher = Poseidon2bSponge::new();
    verify_mixed_opening(
        &bucket.commitment,
        &r_block,
        &[],
        &bucket.mixed_opening,
        &ntt,
        &mut block_channel,
        &hasher,
        COMPACT_NUM_QUERIES,
    )
    .map_err(VerifyBlockError::FriFailed)?;

    let m = &bucket.mixed_opening.all_openings;
    if m.len() < total_cols {
        return Err(VerifyBlockError::ShapeMismatch);
    }
    let mut expected = Block128::ZERO;
    for k in 0..n_tx {
        let eq_k = noid_core::mle::eq::eq_ind(&tx_r_pp[k], &r_block);
        let mut inner = Block128::ZERO;
        for i in 0..n_per_tx {
            inner += beta_powers[i] * m[k * n_per_tx + i];
        }
        expected += mu_powers[k] * eq_k * inner;
    }
    if expected != block_final_claim {
        return Err(VerifyBlockError::BlockMultipoint);
    }

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
    state_binding_airs: &[&BlockStateBindingAir],
) -> Result<(), VerifyBlockError> {
    let meta = &proof.meta;
    let bucket = proof.standard_bucket()?;
    let n_tx = bucket.meta.n_tx();
    let n_air_cols = bucket.meta.n_air_per_tx as usize;
    let n_auth_slices = bucket.meta.n_boundary_slices_per_tx as usize;
    let n_per_tx = n_air_cols + n_auth_slices;
    let n_block_spine_slices = bucket.meta.n_block_spine_slices as usize;
    let n_state_bindings = meta.n_state_bindings as usize;
    let sb_n_cols_per_seg = meta.state_binding_n_cols as usize;
    let sb_n_cols_total = sb_n_cols_per_seg * n_state_bindings;
    let log_len = noid_stark::padded_log_len(bucket.meta.log_rows as usize);
    let has_state_binding = n_state_bindings > 0;
    let n_participants = n_tx + 1 + n_state_bindings;
    let spine_participant_idx = n_tx;
    let sb_participant_base = n_tx + 1;
    let total_committed_cols = n_tx * n_per_tx + n_block_spine_slices + sb_n_cols_total;

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
        || bucket.meta.log_rows != meta.log_rows
        || bucket.meta.n_block_spine_slices as usize != n_block_spine_slices
        || bucket.tx_pis.len() != n_tx
        || bucket.tx_auth_proofs.len() != n_tx
        || bucket.tx_algebraic.len() != n_tx
        || proof.state_binding_algebraics.len() != n_state_bindings
        || !proof.state_binding_starks.is_empty()
        || bucket.block_col_openings.len() != total_committed_cols
        || spine_inputs_list.len() != n_tx
        || auth_public_list.len() != n_tx
    {
        return Err(VerifyBlockError::ShapeMismatch);
    }
    if bucket.commitment.n_cols != total_committed_cols {
        return Err(VerifyBlockError::ShapeMismatch);
    }
    if has_state_binding && state_binding_airs.len() != n_state_bindings {
        tracing::warn!(
            sb_airs_len = state_binding_airs.len(),
            n_state_bindings,
            "verify_block: state_binding count mismatch"
        );
        return Err(VerifyBlockError::ShapeMismatch);
    }
    if has_state_binding {
        for (i, sb_air) in state_binding_airs.iter().enumerate() {
            if sb_air.n_columns() != sb_n_cols_per_seg {
                tracing::warn!(
                    sb_idx = i,
                    air_n_cols = sb_air.n_columns(),
                    proof_n_cols = sb_n_cols_per_seg,
                    "verify_block: state_binding n_cols mismatch"
                );
                return Err(VerifyBlockError::ShapeMismatch);
            }
        }
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
        r_pp: Vec<Block128>,
        final_claim: Block128,
        lambdas: Vec<Block128>,
    }

    let tx_verify_results: Vec<Result<TxVerifyResult, VerifyBlockError>> = (0..n_tx)
        .into_par_iter()
        .map(|k| {
            let pi = &bucket.tx_pis[k];
            let alg = &bucket.tx_algebraic[k];
            let spine_inputs = &spine_inputs_list[k];
            let auth_public = &auth_public_list[k];
            let claimed = pi.tx_body_hash.as_fields();

            // Auth Kill-Shot (self-seeded, parallel-safe).
            let auth_reductions = {
                let mut ch = auth_gkr_channel();
                verify_auth_killshot(
                    &bucket.tx_auth_proofs[k],
                    &auth_circuit,
                    auth_public,
                    &mut ch,
                )
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
            let auth_r_low = &r_auth[..BASE_LOG];
            let auth_r_high = &r_auth[BASE_LOG..];
            if alg.slice_claimed_values.len() != n_auth_slices {
                return Err(VerifyBlockError::ShapeMismatch);
            }
            let auth_slice_vals = &alg.slice_claimed_values[..n_auth_slices];

            let recon_auth =
                noid_core::mle::split::reconstruct_from_slices(auth_slice_vals, auth_r_high);
            if recon_auth != auth_reductions.state.value {
                return Err(VerifyBlockError::AuthSliceReconstruction(k));
            }

            let auth_tr = reduction_to_transcript(r_auth, auth_reductions.state.value);
            let mut extras = Vec::with_capacity(spine_extras.len() + auth_tr.len());
            extras.extend_from_slice(&spine_extras);
            extras.extend_from_slice(&auth_tr);

            let slice_claims = build_auth_slice_claims(n_air_cols, auth_r_low, auth_slice_vals);

            // Per-tx channel mirrors the prover's per_tx_algebraic_channel.
            let mut ch = per_tx_algebraic_channel(&meta.prev_block_state_root, cap, k as u32);

            let (r_pp_k, final_claim_k, lambdas_k) =
                verify_air_interleaved_algebraic(airs[k], pi, alg, &extras, &slice_claims, &mut ch)
                    .map_err(|e| VerifyBlockError::AlgebraicStark(k, e))?;

            Ok(TxVerifyResult {
                r_pp: r_pp_k,
                final_claim: final_claim_k,
                lambdas: lambdas_k,
            })
        })
        .collect();

    let mut tx_r_pp: Vec<Vec<Block128>> = Vec::with_capacity(n_tx);
    let mut tx_final_claims: Vec<Block128> = Vec::with_capacity(n_tx);
    let mut tx_lambdas: Vec<Vec<Block128>> = Vec::with_capacity(n_tx);
    for result in tx_verify_results {
        let r = result?;
        tx_r_pp.push(r.r_pp);
        tx_final_claims.push(r.final_claim);
        tx_lambdas.push(r.lambdas);
    }

    // -------------------------------------------------------------------------
    // State binding algebraic STARKs — one per segment AIR.
    // -------------------------------------------------------------------------
    let empty_pi_sb = PublicInputs {
        epoch_anchor: [0u8; 32],
        tx_body_hash: TxBodyHash([0u8; 32]),
        shape_id: noid_tx::TxShape::Standard4x8.id(),
        fee: 0,
        n_live_inputs: 0,
        n_live_outputs: 0,
        coinbase_credit: 0,
        log_slots: 0,
        claims_commitment: [0u8; 32],
        is_activation: [false; 8],
        is_deactivation: [false; 4],
    };
    let mut sb_r_pp_list: Vec<Vec<Block128>> = Vec::with_capacity(n_state_bindings);
    for sb_idx in 0..n_state_bindings {
        let sb_air = state_binding_airs[sb_idx];
        let sb_alg_log_rows = proof.state_binding_algebraics[sb_idx].log_rows;
        tracing::debug!(
            sb_idx,
            air_log_rows = sb_air.log_rows(),
            proof_log_rows = sb_alg_log_rows,
            air_n_cols = sb_air.n_columns(),
            proof_n_cols = sb_n_cols_per_seg,
            "verify_block: checking state_binding_air shape"
        );
        let sb_alg = &proof.state_binding_algebraics[sb_idx];
        let state_binding_channel_index = meta.n_tx as usize + sb_idx;
        let mut sb_ch = state_binding_channel(
            &meta.prev_block_state_root,
            cap,
            state_binding_channel_index as u32,
        );
        // State-binding columns are padded to the global block log_len (same as TX AIR)
        // even though the state-binding AIR itself has fewer rows (log_rows < global log_rows).
        // Pass log_len explicitly so the verifier uses the correct zero-check round count.
        let (r_pp_sb, _, _) = verify_air_interleaved_algebraic_with_log_len(
            sb_air,
            &empty_pi_sb,
            sb_alg,
            &[],
            &[],
            Some(log_len),
            &mut sb_ch,
        )
        .map_err(|e| VerifyBlockError::AlgebraicStark(n_tx + sb_idx, e))?;
        sb_r_pp_list.push(r_pp_sb);
    }

    // -------------------------------------------------------------------------
    // Verify segment MLE openings (FRI + Merkle path).
    //
    // For each dirty segment:
    //   FRI: verify compact FRI opening proves lane_values == MLE(cols, eval_point)
    //           and seg_root == cap_to_seg_root_with_depth(cap, eff_log).
    //   Merkle: verify path seg_root → prev/new_state_root natively.
    //
    // Full chain: AIR constraints → lane_values → FRI cols → seg_root → state_root.
    // -------------------------------------------------------------------------
    if proof.pre_state_openings.len() != n_state_bindings
        || proof.post_state_openings.len() != n_state_bindings
    {
        return Err(VerifyBlockError::ShapeMismatch);
    }
    if has_state_binding {
        let frib_hasher = Poseidon2bSponge::new();
        for sb_idx in 0..n_state_bindings {
            let sb_air = state_binding_airs[sb_idx];
            let pre = &proof.pre_state_openings[sb_idx];
            let post = &proof.post_state_openings[sb_idx];

            // eval_points must match the AIR.
            if pre.eval_point != sb_air.eval_point || post.eval_point != sb_air.eval_point {
                tracing::warn!(sb_idx, "StateMle: eval_point mismatch");
                return Err(VerifyBlockError::StateMleOpeningFailed(sb_idx));
            }
            let eff_log = pre.eval_point.len();

            // Helper: verify one opening and check its cap-derived seg_root.
            let verify_one = |op: &SegmentMleOpening,
                              expected_lane: &[Block128; 3]|
             -> Result<(), VerifyBlockError> {
                // Verify compact FRI opening.
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

                // Proved values must match lane_values AND AIR's expected values.
                if col_evals.len() < 3
                    || [col_evals[0], col_evals[1], col_evals[2]] != op.lane_values
                    || &op.lane_values != expected_lane
                {
                    tracing::warn!(
                        sb_idx,
                        col_ok = (col_evals.len() >= 3
                            && [col_evals[0], col_evals[1], col_evals[2]] == op.lane_values),
                        lane_ok = (&op.lane_values == expected_lane),
                        "StateMle: lane_values mismatch"
                    );
                    return Err(VerifyBlockError::StateMleOpeningFailed(sb_idx));
                }
                // seg_root = cap_to_seg_root_with_depth(cap, eff_log).
                let derived = cap_to_seg_root_with_depth(&op.commitment.cap, eff_log);
                if derived != op.seg_root {
                    tracing::warn!(sb_idx, "StateMle: seg_root mismatch");
                    return Err(VerifyBlockError::StateMleOpeningFailed(sb_idx));
                }
                Ok(())
            };

            verify_one(pre, &sb_air.prev_lane_openings)?;
            verify_one(post, &sb_air.new_lane_openings)?;

            // Merkle path seg_root → state_root (O(depth) native).
            let check_merkle = |op: &SegmentMleOpening,
                                expected_root: &[u8; 32]|
             -> Result<(), VerifyBlockError> {
                if op.merkle_siblings.is_empty() {
                    if op.seg_root != *expected_root {
                        return Err(VerifyBlockError::StateMleOpeningFailed(sb_idx));
                    }
                } else {
                    let computed =
                        merkle_root_from_leaf(&op.seg_root, op.seg_id, &op.merkle_siblings);
                    if computed != *expected_root {
                        return Err(VerifyBlockError::StateMleOpeningFailed(sb_idx));
                    }
                }
                Ok(())
            };
            check_merkle(pre, &meta.prev_block_state_root).map_err(|e| {
                tracing::warn!(sb_idx, "StateMle: pre Merkle failed");
                e
            })?;
            check_merkle(post, &meta.new_state_root).map_err(|e| {
                tracing::warn!(sb_idx, "StateMle: post Merkle failed");
                e
            })?;
        }
    }

    // -------------------------------------------------------------------------
    // Reconstruct Merkle root of per-tx transcript digests.
    // The block channel absorbs this root instead of N sequential transcripts.
    // -------------------------------------------------------------------------
    let tx_digests: Vec<[u8; 32]> = (0..n_tx)
        .into_par_iter()
        .map(|k| {
            compute_tx_transcript_digest(
                k as u32,
                &tx_r_pp[k],
                &bucket.tx_algebraic[k].base_openings,
                &tx_lambdas[k],
                tx_final_claims[k],
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

    let max_cols = n_per_tx.max(n_block_spine_slices).max(sb_n_cols_per_seg);
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
        if has_state_binding {
            let sb_base_off = spine_offset + n_block_spine_slices;
            for sb_idx in 0..n_state_bindings {
                let col_off = sb_base_off + sb_idx * sb_n_cols_per_seg;
                let inner: Block128 = (0..sb_n_cols_per_seg)
                    .map(|i| beta_powers[i] * bucket.block_col_openings[col_off + i])
                    .fold(Block128::ZERO, |a, b| a + b);
                target += mu_powers[sb_participant_base + sb_idx] * inner;
            }
        }
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
    // FRI-Binius mixed opening verify.
    // -------------------------------------------------------------------------
    let ntt = AdditiveNTT::<Block128>::new(log_len + noid_fri::code::LOG_RATE);
    let hasher = Poseidon2bSponge::new();

    verify_mixed_opening(
        &bucket.commitment,
        &r_block,
        &[],
        &bucket.mixed_opening,
        &ntt,
        &mut block_channel,
        &hasher,
        COMPACT_NUM_QUERIES,
    )
    .map_err(VerifyBlockError::FriFailed)?;

    // -------------------------------------------------------------------------
    // Block sumcheck terminal identity.
    // -------------------------------------------------------------------------
    let m = &bucket.mixed_opening.all_openings;
    if m.len() < total_committed_cols {
        return Err(VerifyBlockError::ShapeMismatch);
    }
    let mut expected = Block128::ZERO;
    for k in 0..n_tx {
        let eq_k = noid_core::mle::eq::eq_ind(&tx_r_pp[k], &r_block);
        let mut inner = Block128::ZERO;
        for i in 0..n_per_tx {
            inner += beta_powers[i] * m[k * n_per_tx + i];
        }
        expected += mu_powers[k] * eq_k * inner;
    }
    // Block spine participant
    let eq_spine = noid_core::mle::eq::eq_ind(&spine_r_low, &r_block);
    let mut inner_spine = Block128::ZERO;
    for i in 0..n_block_spine_slices {
        inner_spine += beta_powers[i] * m[spine_offset + i];
    }
    expected += mu_powers[spine_participant_idx] * eq_spine * inner_spine;
    // State binding participants (one per segment).
    if has_state_binding {
        let sb_base_off = spine_offset + n_block_spine_slices;
        for sb_idx in 0..n_state_bindings {
            let eq_sb = noid_core::mle::eq::eq_ind(&sb_r_pp_list[sb_idx], &r_block);
            let col_off = sb_base_off + sb_idx * sb_n_cols_per_seg;
            let mut inner = Block128::ZERO;
            for i in 0..sb_n_cols_per_seg {
                inner += beta_powers[i] * m[col_off + i];
            }
            expected += mu_powers[sb_participant_base + sb_idx] * eq_sb * inner;
        }
    }
    if expected != block_final_claim {
        return Err(VerifyBlockError::BlockMultipoint);
    }

    Ok(())
}
