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
    validate_block_from_network, validate_block_full, FullValidationError,
};
pub use witness_builder::{
    build_block_witnesses, build_empty_state_bindings, build_state_bindings_from_binding,
    build_tx_witness, OwnedStateBindingWitness, OwnedTxWitness,
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
    auth_gkr_channel, prove_block_spine_killshot, reconstruct_slot_states, verify_auth_killshot,
    verify_block_spine_killshot, AuthCircuit, AuthProofKillShot, AuthPublicInputs, BlockSpineProof,
    SpineCircuit, SpineInputs,
};
use noid_poseidon2b::channel::Poseidon2bChannel;
use noid_poseidon2b::native::compression::Poseidon2bSponge;
use noid_poseidon2b::primitives::TxBodyHash;
use noid_stark::interleaved::{
    prove_air_interleaved_algebraic, verify_air_interleaved_algebraic,
    verify_air_interleaved_algebraic_with_log_len, AlgebraicStarkProof,
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
// BlockProof
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BlockProof {
    pub meta: BlockPublicMeta,
    /// Single interleaved commitment covering all columns (per-tx + block spine + state binding).
    pub commitment: InterleavedCommitment,
    /// Public inputs for every transaction in order.
    pub tx_pis: Vec<PublicInputs>,
    /// Unified block spine Kill-Shot proof (covers all txs in one shot).
    pub block_spine_proof: BlockSpineProof,
    /// AuthGKR Kill-Shot proofs (one per tx).
    pub tx_auth_proofs: Vec<AuthProofKillShot>,
    /// Algebraic STARK transcripts — no FRI, one per tx.
    pub tx_algebraic: Vec<AlgebraicStarkProof>,
    /// Algebraic STARK transcripts for state binding AIRs (one per touched segment).
    /// Empty when there is no state binding.
    pub state_binding_algebraics: Vec<AlgebraicStarkProof>,
    /// Per-tx column openings at the per-tx terminal points r''_k.
    /// Flat layout: `block_col_openings[k*n_per_tx .. (k+1)*n_per_tx]`.
    /// Block spine slices follow, then state binding.
    pub block_col_openings: Vec<Block128>,
    /// Block-level degree-2 multipoint sumcheck rounds (log_rows of them).
    pub block_multipoint_rounds: Vec<Vec<Block128>>,
    /// Single FRI-Binius mixed opening at r_block.
    pub mixed_opening: MixedOpeningProof,
    /// Initial claim for the block-level multipoint sumcheck.
    /// = block_target = Σ_k μ^k × Σ_i β^i × col_openings_k[i].
    /// Block-level multipoint sumcheck initial value
    /// = Σ_k μ^k × Σ_i β^i × col_openings_k[i]. Stored so the recursive
    /// verifier can reproduce the sumcheck target without re-running prove_block.
    pub block_initial_claim: Block128,
    /// FRI+Merkle opening proofs for pre-state segment MLEs (FRI + Merkle path).
    /// One per dirty segment. Proves `BlockStateBindingAir.prev_lane_openings` are real.
    pub pre_state_openings: Vec<SegmentMleOpening>,
    /// FRI+Merkle opening proofs for post-state segment MLEs (FRI + Merkle path).
    /// One per dirty segment. Proves `BlockStateBindingAir.new_lane_openings` are real.
    pub post_state_openings: Vec<SegmentMleOpening>,
}

impl BlockProof {
    pub fn byte_len(&self) -> usize {
        let cap = self.commitment.cap.hashes.len() * 32;
        let alg: usize = self.tx_algebraic.iter().map(|a| a.byte_len()).sum();
        let sb_alg: usize = self
            .state_binding_algebraics
            .iter()
            .map(|a| a.byte_len())
            .sum();
        let spine = self.block_spine_proof.byte_len();
        let auth: usize = self.tx_auth_proofs.iter().map(|a| a.byte_len()).sum();
        let col_open = self.block_col_openings.len() * 16;
        let mp: usize = self
            .block_multipoint_rounds
            .iter()
            .map(|r| r.len() * 16)
            .sum();
        let mixed = self.mixed_opening.byte_len();
        let pre: usize = self.pre_state_openings.iter().map(|o| o.byte_len()).sum();
        let post: usize = self.post_state_openings.iter().map(|o| o.byte_len()).sum();
        cap + alg + sb_alg + spine + auth + col_open + mp + mixed + pre + post
    }
}

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum ProveBlockError {
    EmptyBlock,
    /// The wallet's auth proof for tx at index `k` failed verification.
    /// This can happen if the proof was generated with wrong public inputs
    /// or if the proof bytes are corrupted.
    AuthProofInvalid(usize),
}

#[derive(Debug)]
pub enum VerifyBlockError {
    ShapeMismatch,
    BlockSpineKillShot,
    BlockSpineSliceReconstruction,
    AuthKillShot(usize),
    AuthSpineBridge(usize),
    AuthSliceReconstruction(usize),
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
    let n_tx = witnesses.len();
    assert!(n_tx >= 1, "block must have at least one transaction");

    let mut profiler = ProveBlockProfiler::new();

    let spine_circuit = SpineCircuit::build();
    let auth_circuit = AuthCircuit::build();

    let n_air_cols = witnesses[0].air.n_columns();
    // Number of auth slices per tx: inferred from the first witness so the
    // block prover is forward-compatible with any BASE_LOG the wallet uses.
    // Expected: 2^(N_AUTH_UNIFIED_VARS - BASE_LOG) = 2^(14-11) = 8.
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
            let mut sb_ch =
                state_binding_channel(&prev_block_state_root, cap, (n_tx + sb_idx) as u32);
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

    // Column-outer accumulation: process one column at a time so both
    // b_k (128 KB) and the current column (128 KB) stay in L2 cache.
    // This avoids the L3/DRAM cache-miss storm of the row-outer layout.
    let pairs_b_owned: Vec<Vec<Block128>> = (0..n_participants)
        .into_par_iter()
        .map(|k| {
            if k < n_tx {
                let air_refs = shared_fixed.build_full_col_refs(n_air_cols, &preps[k].witness_cols);
                let mut b_k = vec![Block128::ZERO; hyper_len];
                for i in 0..n_air_cols {
                    let lam = beta_powers[i];
                    let col = air_refs[i];
                    b_k.iter_mut()
                        .zip(col.iter())
                        .for_each(|(acc, &v)| *acc += lam * v);
                }
                for (off, s) in preps[k].auth_slices.iter().enumerate() {
                    let lam = beta_powers[n_air_cols + off];
                    b_k.iter_mut()
                        .zip(s.iter())
                        .for_each(|(acc, &v)| *acc += lam * v);
                }
                b_k
            } else if k == spine_participant_idx {
                let mut b_k = vec![Block128::ZERO; hyper_len];
                for i in 0..n_block_spine_slices {
                    let lam = beta_powers[i];
                    let col = spine_padded_slices[i].as_slice();
                    b_k.iter_mut()
                        .zip(col.iter())
                        .for_each(|(acc, &v)| *acc += lam * v);
                }
                b_k
            } else {
                // State binding participant k → segment index sb_idx.
                let sb_idx = k - sb_participant_base;
                let col_offset = sb_idx * sb_n_cols_per_seg;
                let mut b_k = vec![Block128::ZERO; hyper_len];
                for i in 0..sb_n_cols_per_seg {
                    let lam = beta_powers[i];
                    let col = sb_padded_columns[col_offset + i].as_slice();
                    b_k.iter_mut()
                        .zip(col.iter())
                        .for_each(|(acc, &v)| *acc += lam * v);
                }
                b_k
            }
        })
        .collect();
    let pairs_b: Vec<&[Block128]> = pairs_b_owned.iter().map(|v| v.as_slice()).collect();
    profiler.phase("sumcheck_pair_materialization");

    let (block_mp_rounds, block_mp_challenges) =
        noid_stark::multipoint_batch::prove_multipoint_sumcheck(
            pairs_a,
            pairs_b,
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

    Ok(BlockProof {
        meta: BlockPublicMeta {
            prev_block_state_root,
            new_state_root: new_block_state_root,
            n_tx: n_tx as u32,
            n_air_per_tx: n_air_cols as u32,
            n_auth_slices_per_tx: n_auth_slices as u32,
            log_rows: witnesses[0].trace.log_rows as u32,
            n_block_spine_slices: n_block_spine_slices as u32,
            n_state_bindings: n_state_bindings as u32,
            state_binding_n_cols: sb_n_cols_per_seg as u32,
            state_binding_log_rows: sb_log_rows as u32,
        },
        commitment,
        tx_pis,
        block_spine_proof,
        tx_auth_proofs,
        tx_algebraic,
        state_binding_algebraics: sb_algebraics,
        block_col_openings,
        block_multipoint_rounds: block_mp_rounds,
        mixed_opening,
        block_initial_claim: block_target,
        pre_state_openings,
        post_state_openings,
    })
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
    let n_tx = meta.n_tx as usize;
    let n_air_cols = meta.n_air_per_tx as usize;
    let n_auth_slices = meta.n_auth_slices_per_tx as usize;
    let n_per_tx = n_air_cols + n_auth_slices;
    let n_block_spine_slices = meta.n_block_spine_slices as usize;
    let n_state_bindings = meta.n_state_bindings as usize;
    let sb_n_cols_per_seg = meta.state_binding_n_cols as usize;
    let sb_n_cols_total = sb_n_cols_per_seg * n_state_bindings;
    let log_len = noid_stark::padded_log_len(meta.log_rows as usize);
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
    if proof.tx_pis.len() != n_tx
        || proof.tx_auth_proofs.len() != n_tx
        || proof.tx_algebraic.len() != n_tx
        || proof.state_binding_algebraics.len() != n_state_bindings
        || proof.block_col_openings.len() != total_committed_cols
        || spine_inputs_list.len() != n_tx
        || auth_public_list.len() != n_tx
    {
        return Err(VerifyBlockError::ShapeMismatch);
    }
    if proof.commitment.n_cols != total_committed_cols {
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
    let cap = &proof.commitment.cap;

    // -------------------------------------------------------------------------
    // Unified block spine Kill-Shot + per-tx parallel verification.
    // -------------------------------------------------------------------------

    // (a) Unified block spine Kill-Shot — self-seeded, independent of per-tx channels.
    let tx_body_hashes: Vec<[Block128; 2]> = proof
        .tx_pis
        .iter()
        .map(|pi| pi.tx_body_hash.as_fields())
        .collect();

    let block_spine_reductions = {
        let mut ch = Poseidon2bChannel::new();
        absorb_cap_into_p2b(&mut ch, cap);
        verify_block_spine_killshot(&proof.block_spine_proof, n_tx, &tx_body_hashes, &mut ch)
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
        .map(|i| proof.block_col_openings[spine_offset + i])
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
            let pi = &proof.tx_pis[k];
            let alg = &proof.tx_algebraic[k];
            let spine_inputs = &spine_inputs_list[k];
            let auth_public = &auth_public_list[k];
            let claimed = pi.tx_body_hash.as_fields();

            // Auth Kill-Shot (self-seeded, parallel-safe).
            let auth_reductions = {
                let mut ch = auth_gkr_channel();
                verify_auth_killshot(
                    &proof.tx_auth_proofs[k],
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
        let mut sb_ch =
            state_binding_channel(&meta.prev_block_state_root, cap, (n_tx + sb_idx) as u32);
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
                &proof.tx_algebraic[k].base_openings,
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
    block_channel.observe_field_elems(&proof.block_col_openings);
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
                .map(|i| beta_powers[i] * proof.block_col_openings[k * n_per_tx + i])
                .fold(Block128::ZERO, |a, b| a + b);
            target += mu_powers[k] * inner;
        }
        let inner_spine: Block128 = (0..n_block_spine_slices)
            .map(|i| beta_powers[i] * proof.block_col_openings[spine_offset + i])
            .fold(Block128::ZERO, |a, b| a + b);
        target += mu_powers[spine_participant_idx] * inner_spine;
        if has_state_binding {
            let sb_base_off = spine_offset + n_block_spine_slices;
            for sb_idx in 0..n_state_bindings {
                let col_off = sb_base_off + sb_idx * sb_n_cols_per_seg;
                let inner: Block128 = (0..sb_n_cols_per_seg)
                    .map(|i| beta_powers[i] * proof.block_col_openings[col_off + i])
                    .fold(Block128::ZERO, |a, b| a + b);
                target += mu_powers[sb_participant_base + sb_idx] * inner;
            }
        }
        target
    };

    let (block_sc_challenges, block_final_claim) =
        noid_stark::multipoint_batch::verify_multipoint_sumcheck(
            &proof.block_multipoint_rounds,
            block_target,
            &mut block_channel,
        )
        .map_err(|_| VerifyBlockError::BlockMultipoint)?;

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
        &proof.commitment,
        &r_block,
        &[],
        &proof.mixed_opening,
        &ntt,
        &mut block_channel,
        &hasher,
        COMPACT_NUM_QUERIES,
    )
    .map_err(VerifyBlockError::FriFailed)?;

    // -------------------------------------------------------------------------
    // Block sumcheck terminal identity.
    // -------------------------------------------------------------------------
    let m = &proof.mixed_opening.all_openings;
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
