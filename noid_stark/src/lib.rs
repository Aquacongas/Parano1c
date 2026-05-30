// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

#![allow(
    clippy::needless_range_loop,
    clippy::doc_lazy_continuation,
    clippy::too_many_arguments,
    clippy::manual_memcpy
)]

//! STARK wrapper for the Paranoid transaction AIRs.
//!
//! Given an [`Air`] + [`Trace`] and a [`PublicInputs`] tuple (CRYPTO.md
//! §7), this crate produces a non-interactive STARK proof that the
//! trace satisfies every AIR constraint on the boolean hypercube.
//!
//! # Pipeline
//!
//! 1. FRI-commit every trace column at `log_len = max(TAU+1, log_rows)`
//!    (zero-padded; see [`padded_log_len`]).
//! 2. Absorb `PublicInputs` and every column root into one parent
//!    Fiat–Shamir channel.
//! 3. Draw a zero-check point `z ∈ F^{log_len}` and per-constraint
//!    batching scalars `β_j`. Run **one** zero-check sumcheck on
//!    `H(x) = eq(z, x) · Σ_j β_j · C_j(col_0(x), …)`.
//! 4. Open every column at the sumcheck's own final challenge point
//!    `r`. The verifier's terminal check is
//!    `eq(z, r) · Σ_j β_j · C_j(openings(r)) == sumcheck_final_claim`.
//!
//! This is the standard zero-check protocol: soundness is driven by
//! Schwartz–Zippel on the sumcheck itself, not by a spurious
//! point-evaluation of a non-linear constraint against column MLEs.
//! Per-variable degree of `H` is `1 + max_j deg(C_j)`, so round
//! polynomials carry that many evaluations.

pub mod ladder_batch;
pub mod multipoint_batch;
pub mod vshift;

pub mod interleaved;
pub mod prove_logic;

use crate::vshift::{cyclic_rotate_left, reconstruct_shifted_opening};
use noid_air::{Air, Constraint, EvalFrame, FlatEvalFrame, Trace};
use noid_core::{AdditiveNTT, Block128, TowerField};
use noid_fri::batch::{
    prove_batched, prove_batched_mixed, verify_batched, verify_batched_mixed, BatchedEvalProof,
    MixedBatchedEvalProof,
};
use noid_fri::channel::TAU;
use noid_fri::prover::{commit_fast, FriCommitment};
use noid_fri::Channel;
use noid_poseidon2b::native::compression::Poseidon2bSponge;
use noid_tx::PublicInputs;
use std::collections::HashMap;
use std::sync::{OnceLock, RwLock};

// ---------------------------------------------------------------------------
// Proof
// ---------------------------------------------------------------------------

/// Round polynomial stored as its `D+1` evaluations at
/// `X = 0, 1, 2, …, D` where `D` is the per-variable degree of the
/// batched zero-check polynomial.
pub type RoundPoly = Vec<Block128>;

/// A STARK proof (Stage 3b-0.6, "Ladder Merge"). One FRI commitment
/// per column, the zero-check sumcheck transcript, per-column base
/// openings `e_i = MLE_i(r_point)`, the VSHIFT ladder partials for
/// every shifted column, and finally the §12c' multipoint-batch
/// sumcheck + a **single** batched FRI opening at the shared terminal
/// point `r''`. The §12c' sumcheck inlines every ladder claim (each
/// as a `Σ_k γ_s^k · eq(P_{s,k}, x) · MLE_{col_s}(x)` term) directly
/// into the multipoint `H(x)`, so the per-slot product sumchecks of
/// legacy §12a are gone — one sumcheck closes base + ladder together.
#[derive(Debug, Clone)]
pub struct StarkProof {
    pub log_rows: usize,
    pub column_commitments: Vec<FriCommitment>,
    /// Per-column base openings `e_i = MLE_i(r_point)` at the
    /// zero-check's own challenge point. Absorbed into the parent
    /// transcript before the §12c' multipoint-batch β is squeezed; no
    /// FRI is attached at `r_point` — soundness comes from the single
    /// multipoint FRI at `r''`.
    pub base_openings: Vec<Block128>,
    /// Batched zero-check sumcheck: one `RoundPoly` per variable
    /// (`log_len` total), each a length-`(D+1)` vector of field
    /// evaluations.
    pub zero_check_rounds: Vec<RoundPoly>,
    /// VSHIFT ladders for each rotated column in
    /// `air.shifted_column_indices()` order. The k-th entry is a length
    /// `log_len + 1` vector of MLE evaluations of the base column at the
    /// ladder points (see [`crate::vshift`]). Used by the verifier both
    /// to reconstruct `C'(r)` in closed form for the zero-check
    /// composition check and as the γ_s target-claim pre-image for the
    /// §12c' multipoint sumcheck.
    pub shift_partials: Vec<Vec<Block128>>,
    /// CRYPTO.md §12c' multipoint-batch sumcheck transcript. `log_len`
    /// degree-2 round polynomials (3 field elements each) that reduce
    /// the combined base + ladder multi-point claim to a single common
    /// point `r''`.
    pub multipoint_rounds: Vec<RoundPoly>,
    /// Batched FRI opening of all base columns at the multipoint
    /// challenge `r''`. This single FRI opening closes every base
    /// claim at `r_point` and every ladder claim (inlined in §12c'
    /// as weighted eq-sums over `ladder_points(r_point)`).
    pub multipoint_batch: BatchedEvalProof,
    /// γ₃b mixed-length multipoint close. `None` for the default
    /// path — in that case `multipoint_batch` is authoritative and
    /// the proof is byte-identical to the pre-γ₃b layout. `Some` when
    /// at least one [`ExtraColumn`] participated in the close; the
    /// base columns still close at `r''` inside the mixed proof, and
    /// extras close at their own `log_len`s in the same batched
    /// opening. When `Some`, `multipoint_batch` is an *unused stub*
    /// preserved only so the struct shape doesn't change across
    /// paths (built via `BatchedEvalProof { column_openings: vec![],
    /// batch_proof: stub }` with an empty column list).
    pub multipoint_batch_mixed: Option<MixedBatchedEvalProof>,
    /// Stage 0 MLE Splitting: claimed values of boundary-slice columns
    /// at their respective GKR reduction points (r_B_low). The verifier
    /// uses these with `reconstruct_from_slices` to recover the original
    /// MLE evaluation. Empty when the legacy mixed path is used.
    pub slice_claimed_values: Vec<Block128>,
}

// ---------------------------------------------------------------------------
// Opening-point size + padding
// ---------------------------------------------------------------------------

pub fn padded_log_len(log_rows: usize) -> usize {
    (TAU + 1).max(log_rows)
}

pub fn pad_column(column: &[Block128], target_log: usize) -> Vec<Block128> {
    let target = 1usize << target_log;
    if column.len() == target {
        return column.to_vec();
    }
    assert!(target > column.len());
    let mut out = Vec::with_capacity(target);
    out.extend_from_slice(column);
    out.resize(target, Block128::ZERO);
    out
}

// ---------------------------------------------------------------------------
// Public-input absorbing
// ---------------------------------------------------------------------------

fn absorb_digest_as_pair(channel: &mut Channel, digest: &[u8; 32]) {
    let hi = u128::from_le_bytes(digest[..16].try_into().unwrap());
    let lo = u128::from_le_bytes(digest[16..].try_into().unwrap());
    channel.observe_field_elem(Block128::from(hi));
    channel.observe_field_elem(Block128::from(lo));
}

pub fn absorb_public_inputs(channel: &mut Channel, pi: &PublicInputs) {
    absorb_digest_as_pair(channel, &pi.epoch_anchor);
    absorb_digest_as_pair(channel, &pi.claims_commitment);
    absorb_digest_as_pair(channel, &pi.tx_body_hash.0);
    channel.observe_field_elem(Block128::from(pi.fee));
    // A1a — live-count public inputs. Pack both u8 counts into a
    // single field element so the wire-level struct ordering
    // (n_live_inputs before n_live_outputs) round-trips through the
    // transcript unambiguously. Soundness binding: any disagreement
    // between prover and verifier on `n_live_*` forks the channel and
    // every post-absorb challenge drifts — the FRI query set and
    // zero-check betas in particular.
    let live_packed: u128 = (pi.n_live_inputs as u128) | ((pi.n_live_outputs as u128) << 8);
    channel.observe_field_elem(Block128::from(live_packed));
    // Stage E.6 — absorb coinbase_credit alongside the live counts and
    // log_slots alongside the roots. A disagreement on either forks
    // the channel, preventing a prover from quietly reusing a
    // different circuit sizing or mint credit than the one the
    // verifier (and block header) sees.
    channel.observe_field_elem(Block128::from(pi.coinbase_credit as u128));
    channel.observe_field_elem(Block128::from(pi.log_slots as u128));
    // Stage E.4 — activation / deactivation booleans. Packed into one
    // field element each (MAX_OUTPUTS, MAX_INPUTS ≤ 8 bits, well under
    // 128). Any disagreement between prover and verifier on these
    // surfaces forks the Fiat-Shamir channel, so the chain/block
    // aggregator can trust the verified `PublicInputs` to carry the
    // same booleans the AIR pinned as `SKEL_IS_ACTIVATION_COL` and
    // `SKEL_IS_DEACTIVATION_COL`.
    let mut act_packed: u128 = 0;
    for (j, b) in pi.is_activation.iter().enumerate() {
        if *b {
            act_packed |= 1u128 << j;
        }
    }
    let mut deact_packed: u128 = 0;
    for (i, b) in pi.is_deactivation.iter().enumerate() {
        if *b {
            deact_packed |= 1u128 << i;
        }
    }
    channel.observe_field_elem(Block128::from(act_packed));
    channel.observe_field_elem(Block128::from(deact_packed));
}

// ---------------------------------------------------------------------------
// Zero-check sumcheck
// ---------------------------------------------------------------------------

/// Maximum per-variable degree of `eq · Σ β_j · C_j` given the AIR.
/// Each constraint `C_j` contributes its own per-variable degree; the
/// multilinear `eq(z, ·)` contributes +1. Round polynomials therefore
/// carry `max_c + 2` evaluations — enough to pin down a degree-`(max_c
/// + 1)` univariate exactly.
pub fn round_poly_degree(air: &(impl Air + ?Sized)) -> usize {
    let max_c = air
        .constraints()
        .iter()
        .map(|c| c.degree())
        .max()
        .unwrap_or(1);
    max_c + 1
}

/// Lagrange interpolation of `p` at `target`, where `p[i]` is the
/// evaluation of a degree-`(p.len()-1)` polynomial at the integer point
/// `i`, with integers embedded as `Block128::from(i as u8)`.
#[doc(hidden)]
pub fn lagrange_eval_at_pub(p: &[Block128], target: Block128) -> Block128 {
    lagrange_eval_at(p, target)
}

pub fn lagrange_eval_at(p: &[Block128], target: Block128) -> Block128 {
    let d_plus_one = p.len();
    let mut acc = Block128::ZERO;
    for (k, pk) in p.iter().enumerate() {
        let xk = Block128::from(k as u8);
        let mut num = Block128::ONE;
        let mut den = Block128::ONE;
        for m in 0..d_plus_one {
            if m == k {
                continue;
            }
            let xm = Block128::from(m as u8);
            num *= target + xm;
            den *= xk + xm;
        }
        acc += *pk * num * den.invert();
    }
    acc
}

/// Cached precomputed Lagrange basis denominators for degree `d_plus_one`.
///
/// For a fixed set of nodes `x_k = k` (k = 0..d_plus_one), the denominator
/// `Π_{m≠k}(x_k + x_m)` depends only on `d_plus_one` and `k`, never on the
/// target point. This cache computes them once per unique `d_plus_one` and
/// reuses across all verifier rounds, eliminating `d_plus_one` field inversions
/// per sumcheck round.
static LAGRANGE_DENOM_CACHE: OnceLock<RwLock<HashMap<usize, Vec<Block128>>>> = OnceLock::new();

fn lagrange_denoms(d_plus_one: usize) -> Vec<Block128> {
    let cache = LAGRANGE_DENOM_CACHE.get_or_init(|| RwLock::new(HashMap::new()));

    {
        let r = cache.read().unwrap();
        if let Some(v) = r.get(&d_plus_one) {
            return v.clone();
        }
    }

    let denoms: Vec<Block128> = (0..d_plus_one)
        .map(|k| {
            let xk = Block128::from(k as u8);
            let mut den = Block128::ONE;
            for m in 0..d_plus_one {
                if m != k {
                    let xm = Block128::from(m as u8);
                    den *= xk + xm;
                }
            }
            den.invert()
        })
        .collect();

    cache.write().unwrap().insert(d_plus_one, denoms.clone());
    denoms
}

/// Lagrange interpolation using precomputed denominators from [`lagrange_denoms`].
/// Equivalent to [`lagrange_eval_at`] but avoids per-call field inversions.
pub fn lagrange_eval_at_cached(p: &[Block128], target: Block128) -> Block128 {
    let d_plus_one = p.len();
    let inv_denoms = lagrange_denoms(d_plus_one);
    let mut acc = Block128::ZERO;
    for (k, pk) in p.iter().enumerate() {
        let mut num = Block128::ONE;
        for m in 0..d_plus_one {
            if m != k {
                let xm = Block128::from(m as u8);
                num *= target + xm;
            }
        }
        acc += *pk * num * inv_denoms[k];
    }
    acc
}

/// Upgrade-1.2 — Structure-of-Arrays view of the constraint list, built
/// once per zero-check invocation and reused across every round × sample
/// point. It collapses three sources of per-row overhead from the hot
/// accumulation loop:
///
/// 1. `Box<dyn Constraint>::columns()` / `::shifted_columns()` virtual
///    calls — now resolved once into flat `Vec<u32>` tables.
/// 2. `shifted_slot[idx].expect(...)` per-row branches — pre-baked into
///    absolute indices `n_base + slot` at compile time.
/// 3. Separate `betas[k] * C_k` multiply per row — still needed, but the
///    compile step lays `beta_k` into its own densely-packed `Vec`.
///
/// The `evaluate` call itself still goes through the trait object; the
/// remaining virtual-dispatch cost is closed in Wave-2 (generated fused
/// evaluator). `Constraint` implementations are untouched — every
/// existing AIR keeps compiling.
struct CompiledGates<'a> {
    constraints: &'a [Box<dyn Constraint>],
    /// For constraint `k`, `col_index_starts[k]..col_index_starts[k+1]`
    /// slices `col_indices` to yield its local-row column indices.
    col_indices: Vec<u32>,
    col_index_starts: Vec<u32>,
    /// For constraint `k`, `next_index_starts[k]..next_index_starts[k+1]`
    /// slices `next_indices` to yield its shifted-row column indices,
    /// already rewritten to absolute positions `n_base + slot`.
    next_indices: Vec<u32>,
    next_index_starts: Vec<u32>,
    /// Maximum arity of `columns()` / `shifted_columns()` across all
    /// constraints — sizes the per-thread scratch buffers so `push` can
    /// never reallocate.
    max_local_arity: usize,
    max_next_arity: usize,
    /// Flat-basis image of `betas`, pre-converted once at
    /// `CompiledGates::new` time; the zero-check hot path reads it
    /// instead of invoking `tower_to_flat_u128` per row.
    betas_flat: Vec<u128>,
}

impl<'a> CompiledGates<'a> {
    fn new(
        constraints: &'a [Box<dyn Constraint>],
        shifted_slot: &[Option<usize>],
        n_base: usize,
        betas: &[Block128],
    ) -> Self {
        let n = constraints.len();
        let mut col_indices: Vec<u32> = Vec::new();
        let mut col_index_starts: Vec<u32> = Vec::with_capacity(n + 1);
        let mut next_indices: Vec<u32> = Vec::new();
        let mut next_index_starts: Vec<u32> = Vec::with_capacity(n + 1);
        let mut max_local_arity = 0usize;
        let mut max_next_arity = 0usize;
        col_index_starts.push(0);
        next_index_starts.push(0);
        for c in constraints {
            let locals = c.columns();
            max_local_arity = max_local_arity.max(locals.len());
            for &idx in locals {
                col_indices.push(idx as u32);
            }
            col_index_starts.push(col_indices.len() as u32);
            let nexts = c.shifted_columns();
            max_next_arity = max_next_arity.max(nexts.len());
            for &idx in nexts {
                let slot = shifted_slot[idx].expect("shifted column must have a registered slot");
                next_indices.push((n_base + slot) as u32);
            }
            next_index_starts.push(next_indices.len() as u32);
        }
        let betas_flat: Vec<u128> = betas
            .iter()
            .map(|b| noid_core::hardware::tower_to_flat_u128(b.0))
            .collect();
        Self {
            constraints,
            col_indices,
            col_index_starts,
            next_indices,
            next_index_starts,
            max_local_arity,
            max_next_arity,
            betas_flat,
        }
    }
}

// ---------------------------------------------------------------------------
// [2.C] Flat-basis zero-check inner loops
// ---------------------------------------------------------------------------

/// Fold the highest variable of a multilinear table in flat basis.
/// Multiplication is the only basis-sensitive op in `a + r·(a+b)`; it
/// is replaced here with `clmul_gcm` (flat-basis mul).
fn fold_highest_flat(table: &mut Vec<u128>, r_flat: u128) {
    use noid_core::hardware::clmul_gcm;
    let half = table.len() / 2;
    for j in 0..half {
        let lo = table[j];
        let hi = table[j + half];
        table[j] = lo ^ clmul_gcm(r_flat, hi ^ lo);
    }
    table.truncate(half);
}

/// Evaluate the per-row composition `eq · Σ β_k · C_k` in flat basis,
/// fusing partial-evaluation of `eq` and every column with the constraint
/// accumulation. Computes `partial[j] = table[j] ⊕ s_flat·(table[j+half]⊕table[j])`
/// on-the-fly per hypercube position `j`, eliminating the `Vec<Cow>`
/// allocations that the legacy two-step pipeline incurred for every
/// sample point ≥ 2.
fn accumulate_sum_flat_fused(
    cur_eq: &[u128],
    cur_cols: &[Vec<u128>],
    compiled: &CompiledGates<'_>,
    s_idx: usize,
    s_flat: u128,
) -> u128 {
    use noid_core::hardware::clmul_gcm;
    use rayon::prelude::*;
    let half = cur_eq.len() / 2;
    let n_constraints = compiled.constraints.len();
    let local_cap = compiled.max_local_arity;
    let next_cap = compiled.max_next_arity;
    let n_cols = cur_cols.len();

    // Inline partial-eval helper — avoids function call overhead in the hot loop.
    #[inline(always)]
    fn pe(table: &[u128], j: usize, half: usize, s_idx: usize, s_flat: u128) -> u128 {
        if s_idx == 0 {
            table[j]
        } else if s_idx == 1 {
            table[j + half]
        } else {
            table[j] ^ clmul_gcm(s_flat, table[j + half] ^ table[j])
        }
    }

    (0..half)
        .into_par_iter()
        .map_init(
            || {
                (
                    Vec::<u128>::with_capacity(local_cap),
                    Vec::<u128>::with_capacity(next_cap),
                    vec![0u128; n_cols],
                )
            },
            |(local_scratch, next_scratch, col_partials), j| {
                let eq_val = pe(cur_eq, j, half, s_idx, s_flat);

                for (col_idx, col) in cur_cols.iter().enumerate() {
                    col_partials[col_idx] = pe(col, j, half, s_idx, s_flat);
                }

                let mut composition: u128 = 0;
                for k in 0..n_constraints {
                    let lo_s = compiled.col_index_starts[k] as usize;
                    let lo_e = compiled.col_index_starts[k + 1] as usize;
                    local_scratch.clear();
                    for &idx in &compiled.col_indices[lo_s..lo_e] {
                        local_scratch.push(col_partials[idx as usize]);
                    }
                    let ne_s = compiled.next_index_starts[k] as usize;
                    let ne_e = compiled.next_index_starts[k + 1] as usize;
                    next_scratch.clear();
                    for &idx in &compiled.next_indices[ne_s..ne_e] {
                        next_scratch.push(col_partials[idx as usize]);
                    }
                    let frame = FlatEvalFrame {
                        local: local_scratch.as_slice(),
                        next: next_scratch.as_slice(),
                    };
                    let ck = compiled.constraints[k].evaluate_flat(frame);
                    composition ^= clmul_gcm(compiled.betas_flat[k], ck);
                }
                clmul_gcm(eq_val, composition)
            },
        )
        .reduce(|| 0u128, |a, b| a ^ b)
}

/// Prover for the batched zero-check sumcheck. Holds the folded
/// column tables + eq table in flat basis (GCM polynomial basis)
/// across every round; converts to/from tower only at four
/// boundaries:
///   * inputs: every column of `cols` → flat once at entry;
///   * `eq_ind_partial_eval(z)` result → flat once at entry;
///   * each round's `evals` (n_points field elements) → tower before
///     `channel.observe_field_elems` so transcript bytes stay in the
///     observable tower basis;
///   * each round's challenge `r` → flat before `fold_highest_flat`.
/// Every other op (fold, partial_eval, accumulate_sum) is flat and
/// hits `clmul_gcm` / `square_flat_u128` hardware paths directly.
///
/// Returns `(round_polys, challenges)` in tower basis — transcript
/// bytes are identical to a naive tower-basis prover run on the same
/// inputs.
pub fn prove_zero_check(
    cols: &[&[Block128]],
    constraints: &[Box<dyn Constraint>],
    betas: &[Block128],
    z: &[Block128],
    channel: &mut Channel,
    degree: usize,
    shifted_slot: &[Option<usize>],
    n_base: usize,
) -> (Vec<RoundPoly>, Vec<Block128>) {
    use noid_core::hardware::{flat_to_tower_u128, tower_to_flat_u128};
    let n = z.len();
    let n_points = degree + 1;

    let compiled = CompiledGates::new(constraints, shifted_slot, n_base, betas);

    // Convert the initial folded tables to flat basis once; they stay
    // in flat for the full sumcheck.
    let mut cur_cols: Vec<Vec<u128>> = cols
        .iter()
        .map(|c| c.iter().map(|v| tower_to_flat_u128(v.0)).collect())
        .collect();
    let eq_tower = noid_core::mle::eq::eq_ind_partial_eval(z);
    let mut cur_eq: Vec<u128> = eq_tower.iter().map(|v| tower_to_flat_u128(v.0)).collect();

    // Pre-convert the small fixed set of sample-point scalars
    // `{2, 3, ..., degree}` to flat once. Points `0` and `1` are
    // GF(2) elements, their `u128` bit patterns are basis-invariant.
    let s_flat_table: Vec<u128> = (0..n_points)
        .map(|s_idx| {
            if s_idx <= 1 {
                s_idx as u128
            } else {
                tower_to_flat_u128(Block128::from(s_idx as u8).0)
            }
        })
        .collect();

    let mut round_polys: Vec<RoundPoly> = Vec::with_capacity(n);
    let mut challenges: Vec<Block128> = Vec::with_capacity(n);

    for _ in 0..n {
        // accumulate_sum_flat_fused already parallelises over `half` positions
        // (up to 2^(log_len-1) tasks) via rayon, fully saturating available
        // cores.  Running the outer n_points iterations (degree+1, typically
        // 2-5) serially eliminates nested-pool overhead and synchronisation
        // barriers while preserving full inner parallelism.
    
        let evals: Vec<Block128> = (0..n_points)
            .map(|s_idx| {
                let s_flat = s_flat_table[s_idx];
                let acc_flat =
                    accumulate_sum_flat_fused(&cur_eq, &cur_cols, &compiled, s_idx, s_flat);
                Block128::from(flat_to_tower_u128(acc_flat))
            })
            .collect();

        channel.observe_field_elems(&evals);
        let r = channel.get_random_point();
        let r_flat = tower_to_flat_u128(r.0);

    
        {
            use rayon::prelude::*;
            cur_cols
                .par_iter_mut()
                .for_each(|c| fold_highest_flat(c, r_flat));
        }
        fold_highest_flat(&mut cur_eq, r_flat);

        round_polys.push(evals);
        challenges.push(r);
    }

    (round_polys, challenges)
}

// ---------------------------------------------------------------------------
// Prover
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum ProveError {
    TraceRejectedByAir,
}

pub fn prove_air<A: Air>(
    air: &A,
    trace: &Trace,
    pi: &PublicInputs,
) -> Result<StarkProof, ProveError> {
    if !air.check(trace) {
        return Err(ProveError::TraceRejectedByAir);
    }
    Ok(prove_air_unchecked(air, trace, pi))
}

/// Wall-clock breakdown of [`prove_air_timed`] for a single proof.
///
/// Post-3b-0.4 bucket layout:
/// * `commit` — column commitments.
/// * `transcript_sumcheck` — parent transcript + zero-check sumcheck.
/// * `ladder_sumcheck` — per-slot ladder product sumchecks (§12a).
/// * `multipoint_fri` — §12c multipoint-batch sumcheck plus the single
///   batched FRI opening at `r''`. This bucket replaces the old
///   `base_fri` and `ladder_fri` buckets combined.
#[derive(Debug, Clone, Copy, Default)]
pub struct ProveTimings {
    pub commit: std::time::Duration,
    pub transcript_sumcheck: std::time::Duration,
    pub ladder_sumcheck: std::time::Duration,
    pub multipoint_fri: std::time::Duration,
    /// Under-bucket breakdown of `multipoint_fri`. The three fields sum
    /// (up to measurement noise) to `multipoint_fri`.
    pub mp_setup_pairs: std::time::Duration,
    pub mp_sumcheck: std::time::Duration,
    pub mp_fri: std::time::Duration,
}

impl ProveTimings {
    pub fn total(&self) -> std::time::Duration {
        self.commit + self.transcript_sumcheck + self.ladder_sumcheck + self.multipoint_fri
    }
}

/// Mirror of [`prove_air`] instrumented with per-bucket prover timers.
/// All commitments / openings are identical to `prove_air`; this variant
/// exists strictly to feed Stage 3b-0.4 decision benchmarks.
pub fn prove_air_timed<A: Air>(
    air: &A,
    trace: &Trace,
    pi: &PublicInputs,
) -> Result<(StarkProof, ProveTimings), ProveError> {
    if !air.check(trace) {
        return Err(ProveError::TraceRejectedByAir);
    }
    Ok(prove_air_unchecked_timed(air, trace, pi))
}

#[doc(hidden)]
pub fn prove_air_unchecked_timed<A: Air>(
    air: &A,
    trace: &Trace,
    pi: &PublicInputs,
) -> (StarkProof, ProveTimings) {
    use std::time::Instant;
    let mut t = ProveTimings::default();

    let log_rows = trace.log_rows;
    let log_len = padded_log_len(log_rows);
    let ntt = AdditiveNTT::<Block128>::new(log_len + noid_fri::code::LOG_RATE);
    let hasher = Poseidon2bSponge::new();

    let t0 = Instant::now();
    let (commitments, padded_columns): (Vec<FriCommitment>, Vec<Vec<Block128>>) = {
        use rayon::prelude::*;
        trace
            .columns
            .par_iter()
            .map(|col| {
                let padded = pad_column(col, log_len);
                // SAFETY-INVARIANT: commit_fast uses Blake3 instead of Poseidon2b.
                // This is sound because the round-0 Merkle tree is NEVER opened by
                // FRI queries — only its 32-byte root is absorbed into the Fiat-Shamir
                // channel. Soundness rests on Blake3 collision-resistance over the
                // full RS-encoded codeword (RATE · 2^log_len · 16 bytes).
                // See noid_fri::prover::commit_fast for full rationale.
                let commitment = commit_fast(&padded, &ntt);
                (commitment, padded)
            })
            .unzip()
    };
    t.commit = t0.elapsed();

    let t1 = Instant::now();
    let mut channel = Channel::new();
    absorb_public_inputs(&mut channel, pi);
    for c in &commitments {
        channel.observe_fri_commitment(c);
    }
    let z = channel.get_random_points(log_len);
    let n_constraints = air.constraints().len();
    let betas: Vec<Block128> = (0..n_constraints)
        .map(|_| channel.get_random_point())
        .collect();

    let shifted_indices: Vec<usize> = air.shifted_column_indices();
    assert!(
        shifted_indices.is_empty() || log_rows == padded_log_len(log_rows),
        "VSHIFT requires log_rows >= TAU+1; got log_rows={} padded={}",
        log_rows,
        padded_log_len(log_rows)
    );
    let n_base = padded_columns.len();
    let mut shifted_slot: Vec<Option<usize>> = vec![None; n_base];
    for (slot, &col_id) in shifted_indices.iter().enumerate() {
        shifted_slot[col_id] = Some(slot);
    }
    let rotated_columns: Vec<Vec<Block128>> = shifted_indices
        .iter()
        .map(|&col_id| cyclic_rotate_left(&padded_columns[col_id]))
        .collect();
    let mut sumcheck_cols: Vec<&[Block128]> = Vec::with_capacity(n_base + rotated_columns.len());
    for col in &padded_columns {
        sumcheck_cols.push(col.as_slice());
    }
    for col in &rotated_columns {
        sumcheck_cols.push(col.as_slice());
    }

    let degree = round_poly_degree(air);
    let (zero_check_rounds, r) = prove_zero_check(
        &sumcheck_cols,
        air.constraints(),
        &betas,
        &z,
        &mut channel,
        degree,
        &shifted_slot,
        n_base,
    );
    t.transcript_sumcheck = t1.elapsed();

    let r_point: Vec<Block128> = r.iter().rev().cloned().collect();

    let t2 = Instant::now();
    let (base_openings, shift_partials) =
        prove_base_and_ladder_partials(&padded_columns, &shifted_indices, &r_point, &mut channel);
    t.ladder_sumcheck = t2.elapsed();

    let t3 = Instant::now();
    let mut mp_sub = MpSubTimings::default();
    let (multipoint_rounds, multipoint_batch) = prove_multipoint_close_inner(
        &padded_columns,
        &base_openings,
        &r_point,
        &shifted_indices,
        &shift_partials,
        log_len,
        &ntt,
        &mut channel,
        &hasher,
        Some(&mut mp_sub),
    );
    t.multipoint_fri = t3.elapsed();
    t.mp_setup_pairs = mp_sub.setup_pairs;
    t.mp_sumcheck = mp_sub.sumcheck;
    t.mp_fri = mp_sub.fri;

    (
        StarkProof {
            log_rows,
            column_commitments: commitments,
            base_openings,
            zero_check_rounds,
            shift_partials,
            multipoint_rounds,
            multipoint_batch,
            multipoint_batch_mixed: None,
            slice_claimed_values: Vec::new(),
        },
        t,
    )
}

/// Stage 3b-0.6 prover — compute base per-column openings at
/// `r_point` and the VSHIFT ladder partials for every shifted column.
/// Absorbs both into the parent channel in a deterministic order so
/// the verifier replay is bit-for-bit. Unlike the legacy §12a, this
/// routine does **not** run a per-slot product sumcheck: ladder claims
/// are inlined directly into the §12c' multipoint sumcheck that
/// follows.
pub(crate) fn prove_base_and_ladder_partials(
    padded_columns: &[Vec<Block128>],
    shifted_indices: &[usize],
    r_point: &[Block128],
    channel: &mut Channel,
) -> (Vec<Block128>, Vec<Vec<Block128>>) {
    use rayon::prelude::*;

    // Base openings e_i = MLE_i(r_point). Parallel across columns.
    let base_openings: Vec<Block128> = padded_columns
        .par_iter()
        .map(|col| mle_eval(col, r_point))
        .collect();
    channel.observe_field_elems(&base_openings);

    // Ladder partials per slot — nested-fold path, O(2^n) per slot
    // versus O((n+1)·2^n) for independent `mle_eval` per ladder point.
    // See `vshift::ladder_partials`.
    let partials_per_slot: Vec<Vec<Block128>> = shifted_indices
        .par_iter()
        .map(|&col_id| crate::vshift::ladder_partials(&padded_columns[col_id], r_point))
        .collect();

    // Absorb each slot's partials with a distinct domain tag so no
    // cross-slot re-use can masquerade as a different slot's trail.
    for (slot, partials) in partials_per_slot.iter().enumerate() {
        channel.observe_field_elem(crate::ladder_batch::sub_channel_tag(slot));
        channel.observe_field_elems(partials);
    }

    (base_openings, partials_per_slot)
}

/// Stage 3b-0.6 §12c' prover — multipoint-to-single-point reduction
/// with inlined ladder terms.
///
/// For each base column we contribute a pair
///   `A_i(x) = λ_i · eq(r_point, x)`, `B_i(x) = MLE_i(x)`.
/// For each shifted slot `s` (with ladder partials `v_{s,0..n}` and an
/// independently-squeezed `γ_s`) we contribute a pair
///   `A_s(x) = η_s · W_s(x)`,     `B_s(x) = MLE_{col_s}(x)`
/// where `W_s(x) = Σ_k γ_s^k · eq(P_{s,k}, x)`. Target:
///   `T = Σ_i λ_i · e_i + Σ_s η_s · (Σ_k γ_s^k · v_{s,k})`.
///
/// The terminal claim is closed by a single batched FRI opening of
/// all base columns at `r''`. Verifier reconstructs `W_s(r'')` in
/// closed form — it's just a small weighted sum of `eq(P_{s,k}, r'')`.
#[derive(Debug, Clone, Copy, Default)]
struct MpSubTimings {
    setup_pairs: std::time::Duration,
    sumcheck: std::time::Duration,
    fri: std::time::Duration,
}

#[allow(clippy::too_many_arguments)]
fn prove_multipoint_close(
    padded_columns: &[Vec<Block128>],
    base_openings: &[Block128],
    r_point: &[Block128],
    shifted_indices: &[usize],
    shift_partials: &[Vec<Block128>],
    log_len: usize,
    ntt: &AdditiveNTT<Block128>,
    channel: &mut Channel,
    hasher: &Poseidon2bSponge,
) -> (Vec<RoundPoly>, BatchedEvalProof) {
    prove_multipoint_close_inner(
        padded_columns,
        base_openings,
        r_point,
        shifted_indices,
        shift_partials,
        log_len,
        ntt,
        channel,
        hasher,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
fn prove_multipoint_close_inner(
    padded_columns: &[Vec<Block128>],
    base_openings: &[Block128],
    r_point: &[Block128],
    shifted_indices: &[usize],
    shift_partials: &[Vec<Block128>],
    log_len: usize,
    ntt: &AdditiveNTT<Block128>,
    channel: &mut Channel,
    hasher: &Poseidon2bSponge,
    mut sub: Option<&mut MpSubTimings>,
) -> (Vec<RoundPoly>, BatchedEvalProof) {
    use noid_core::mle::eq::eq_ind_partial_eval;
    use rayon::prelude::*;
    use std::time::Instant;

    let t_setup = Instant::now();
    let n = padded_columns.len();
    let s_count = shifted_indices.len();

    // Squeeze a dedicated γ_s per slot (independent of β). The slot
    // tags were already observed in `prove_base_and_ladder_partials`
    // together with the partials, so the verifier's replay matches.
    let gammas: Vec<Block128> = (0..s_count).map(|_| channel.get_random_point()).collect();

    // Squeeze β after absorbing domain tag. Horner weights λ_i = β^i,
    // η_s = β^{n+s}.
    channel.observe_field_elem(Block128::from(crate::multipoint_batch::MULTIPOINT_TAG));
    let beta = channel.get_random_point();
    let mut lambdas: Vec<Block128> = Vec::with_capacity(n + s_count);
    let mut cur = Block128::ONE;
    for _ in 0..(n + s_count) {
        lambdas.push(cur);
        cur *= beta;
    }

    // Target:
    //   base part:   Σ_i λ_i · e_i
    //   ladder part: Σ_s η_s · (Σ_k γ_s^k · v_{s,k})
    let mut target = Block128::ZERO;
    for i in 0..n {
        target += lambdas[i] * base_openings[i];
    }
    for (slot, partials) in shift_partials.iter().enumerate() {
        let eta = lambdas[n + slot];
        let t_s = crate::ladder_batch::target_claim(gammas[slot], partials);
        target += eta * t_s;
    }

    // γ-independent trails for the ladder points shared by every slot
    // (they all anchor to the same `r_point`).
    let weight_trails = if s_count > 0 {
        Some(crate::ladder_batch::WeightTrails::new(r_point))
    } else {
        None
    };

    // Build `(A_k, B_k)` pairs. Every base pair shares the same A-side
    // factor `eq(r_point, ·)`, so by bilinearity of the sumcheck's
    // degree-2 product reduction
    //   Σ_i (λ_i · eq_base(x)) · c_i(x)
    //     ≡ eq_base(x) · (Σ_i λ_i · c_i(x))
    // across every X ∈ {0, 1, 2} and every fold step. Collapsing the
    // `n` base pairs into one fused pair `(eq_base, c_combined)` is
    // transcript-byte-identical: the reduce-Σ over round oracles is
    // identical (same bilinear form, same λ_i weights), and the
    // terminal identity still reconstructs per-column via the
    // verifier's `Σ_i λ_i · eq_base(r'') · m_i`. The committed FRI
    // batch still opens every `padded_columns[i]` at `r''`; this
    // collapse only lives inside the sumcheck pair list.
    //
    // Savings (per-tx fixture, n = 575, log_len = 13): ~600 pair-folds
    // per round × 13 rounds + n-way allocation of `A_k` tables
    // collapses to one. Ladder pairs are unchanged — they each carry
    // a distinct `W_s(·)` on the A-side.
    let eq_base = eq_ind_partial_eval(r_point);
    let hyper_len = 1usize << log_len;

    // Fold Σ_i λ_i · c_i into one combined B table. Column-major order
    // for cache locality: each column is read sequentially, the output
    // buffer is written sequentially. Parallelised via fold/reduce — one
    // partial buffer per rayon task, then summed.
    let combined_base_b: Vec<Block128> = (0..n)
        .into_par_iter()
        .fold(
            || vec![Block128::ZERO; hyper_len],
            |mut acc, i| {
                let lambda = lambdas[i];
                let col = &padded_columns[i];
                for j in 0..hyper_len {
                    acc[j] += lambda * col[j];
                }
                acc
            },
        )
        .reduce(
            || vec![Block128::ZERO; hyper_len],
            |mut a, b| {
                for j in 0..hyper_len {
                    a[j] += b[j];
                }
                a
            },
        );

    let ladder_pairs_a: Vec<Vec<Block128>> = (0..s_count)
        .into_par_iter()
        .map(|slot| {
            let trails = weight_trails
                .as_ref()
                .expect("trails present when s_count > 0");
            let mut w = crate::ladder_batch::build_weight_table_from_trails(gammas[slot], trails);
            let eta = lambdas[n + slot];
            for v in w.iter_mut() {
                *v *= eta;
            }
            w
        })
        .collect();
    let ladder_pairs_b: Vec<&[Block128]> = (0..s_count)
        .map(|slot| padded_columns[shifted_indices[slot]].as_slice())
        .collect();

    let mut pairs_a: Vec<Vec<Block128>> = Vec::with_capacity(1 + s_count);
    pairs_a.push(eq_base);
    pairs_a.extend(ladder_pairs_a);
    let mut pairs_b: Vec<&[Block128]> = Vec::with_capacity(1 + s_count);
    pairs_b.push(combined_base_b.as_slice());
    pairs_b.extend(ladder_pairs_b);
    let setup_elapsed = t_setup.elapsed();

    let t_sc = Instant::now();
    let (rounds, challenges) =
        crate::multipoint_batch::prove_multipoint_sumcheck(pairs_a, pairs_b, target, channel);
    let r_pp: Vec<Block128> = challenges.iter().rev().cloned().collect();
    debug_assert_eq!(r_pp.len(), log_len);
    let sc_elapsed = t_sc.elapsed();

    let t_fri = Instant::now();
    let col_refs: Vec<&[Block128]> = padded_columns.iter().map(|v| v.as_slice()).collect();
    let batch = prove_batched(&col_refs, &r_pp, ntt, channel, hasher);
    let fri_elapsed = t_fri.elapsed();

    if let Some(s) = sub.as_deref_mut() {
        s.setup_pairs = setup_elapsed;
        s.sumcheck = sc_elapsed;
        s.fri = fri_elapsed;
    }
    let _ = &mut sub;

    (rounds, batch)
}

// ---------------------------------------------------------------------------
// γ₃b scaffolding — mixed-length extra columns
// ---------------------------------------------------------------------------
//
// `ExtraColumn` packages a single externally-committed MLE that must
// participate in the STARK's multipoint close. The canonical consumer
// is the GKR spine's boundary MLE `B` at `log_len = 15`, opened at
// `r_B` to value `v_B`. Extras may live on a different hypercube than
// the trace columns — the mixed-length close (γ₃b) handles that via
// [`crate::multipoint_batch::prove_multipoint_sumcheck_mixed`] +
// [`noid_fri::batch::prove_batched_mixed`].
//
// **Invariants** enforced here and pinned by tests:
//
// * **A. Empty-extras ≡ default.** With `extras == &[]`, the new
//   wrappers produce a byte-identical `StarkProof` to the legacy
//   `prove_air_unchecked_with_extra`. This is tested by
//   `invariant_a_empty_extras_byte_identical` and guards every later
//   change to the mixed close.
// * **B. Single-group mixed ≡ uniform semantics.** When every extra
//   has the same `log_len` as the base trace, the mixed close
//   accepts a proof byte-identical to the default close. Pinned in
//   the follow-up that lands the real mixed path.
// * **C. Extras order is canonical.** Extras are sorted inside the
//   wrapper by `(log_len, commitment root bytes, eval_point bytes)`
//   before transcript absorption / multipoint close, so the caller's
//   argument order never leaks into the transcript.
#[derive(Debug, Clone)]
pub struct ExtraColumn {
    pub evals: Vec<Block128>,
    pub commitment: FriCommitment,
    pub eval_point: Vec<Block128>,
    pub value: Block128,
}

// ---------------------------------------------------------------------------
// Stage 0: MLE Splitting — SliceClaim for uniform FRI path
// ---------------------------------------------------------------------------

/// A claim that a boundary-slice column (appended after the AIR columns)
/// evaluates to `value` at `eval_point`. The multipoint sumcheck proves
/// this alongside the base and ladder claims.
#[derive(Debug, Clone)]
pub struct SliceClaim {
    /// Column index in the extended trace (>= n_air_cols).
    pub col_index: usize,
    /// The evaluation point (length = log_len = BASE_LOG = 13).
    pub eval_point: Vec<Block128>,
    /// The claimed evaluation value of the slice MLE at eval_point.
    pub value: Block128,
}

/// Canonical extras ordering: ascending `log_len`, then by commitment
/// root bytes, then by the serialized eval_point. Pure function of
/// extras contents — no transcript state.
fn canonicalize_extras(extras: &[ExtraColumn]) -> Vec<ExtraColumn> {
    let mut sorted: Vec<ExtraColumn> = extras.to_vec();
    sorted.sort_by(|a, b| {
        let la = a.commitment.log_len;
        let lb = b.commitment.log_len;
        la.cmp(&lb)
            .then_with(|| {
                a.commitment
                    .vector_commitment
                    .root
                    .cmp(&b.commitment.vector_commitment.root)
            })
            .then_with(|| {
                let sa: Vec<u128> = a.eval_point.iter().map(|v| v.0).collect();
                let sb: Vec<u128> = b.eval_point.iter().map(|v| v.0).collect();
                sa.cmp(&sb)
            })
    });
    sorted
}

/// Prover variant that skips the native AIR self-check. Exposed for
/// soundness testing: a malicious prover must be caught by the
/// cryptographic layer (zero-check + FRI), not by the defense-in-depth
/// native pre-check.
#[doc(hidden)]
pub fn prove_air_unchecked<A: Air>(air: &A, trace: &Trace, pi: &PublicInputs) -> StarkProof {
    prove_air_unchecked_with_extra(air, trace, pi, &[])
}

/// γ₃b opt-in wrapper around [`prove_air_unchecked_with_extra`] that
/// threads additional externally-committed MLEs through the
/// multipoint close. When `extras` is empty this is a direct
/// delegation to `prove_air_unchecked_with_extra(extra_transcript)`
/// and the output is byte-identical to the default path.
///
/// The non-empty branch (actual mixed-length close) is gated behind a
/// follow-up that lands the wiring; attempting to use it now panics
/// with a clear message. The scaffolding exists so callers (notably
/// `noid_stark::spine`) can commit to the API shape before the
/// wiring is in place.
#[doc(hidden)]
pub fn prove_air_unchecked_with_extra_columns<A: Air + ?Sized>(
    air: &A,
    trace: &Trace,
    pi: &PublicInputs,
    extra_transcript: &[Block128],
    extras: &[ExtraColumn],
) -> StarkProof {
    if extras.is_empty() {
        // Invariant A: empty extras must reduce to the legacy path
        // byte-for-byte. No canonicalization, no transcript change.
        return prove_air_unchecked_with_extra(air, trace, pi, extra_transcript);
    }
    let extras = canonicalize_extras(extras);
    prove_air_unchecked_with_extras_inner(air, trace, pi, extra_transcript, &extras)
}

/// Verifier mirror of [`prove_air_unchecked_with_extra_columns`].
/// Empty `extras` delegates byte-identically to
/// [`verify_air_with_extra`]. See that function's docstring for
/// `extra_transcript` semantics.
pub fn verify_air_with_extra_columns<A: Air + ?Sized>(
    air: &A,
    pi: &PublicInputs,
    proof: &StarkProof,
    extra_transcript: &[Block128],
    extras: &[ExtraColumn],
) -> Result<(), VerifyError> {
    if extras.is_empty() {
        return verify_air_with_extra(air, pi, proof, extra_transcript);
    }
    let extras = canonicalize_extras(extras);
    verify_air_with_extras_inner(air, pi, proof, extra_transcript, &extras)
}

/// Domain tag separating the mixed-close extras commitment absorption
/// from any other use of `observe_field_elem` on the parent channel.
/// Binds the extras' commitment roots to the parent transcript at a
/// position distinct from `extra_transcript`, so the two channels
/// cannot be confused.
const EXTRAS_ABSORB_TAG: u64 = 0xFFFA_4337_0000_0001;

// ---------------------------------------------------------------------------
// γ₃b mixed-length prove/verify
// ---------------------------------------------------------------------------
//
// Shape of the mixed close (when `extras` is non-empty and already
// canonicalized):
//
// Transcript (after zero-check + base_openings + ladder partials are
// absorbed exactly as in the default path):
//   • EXTRAS_ABSORB_TAG
//   • For each extra in canonical order:
//       - absorb the extra's FriCommitment
//       - absorb `eval_point` elements
//       - absorb `value`
//   • Squeeze γ_s per slot (same as default).
//   • MULTIPOINT_TAG + squeeze β (same as default).
//     Horner weights extend past base+ladder to cover extras at
//     indices `[n + s_count .. n + s_count + n_extras)` so every
//     weight is `β^i` for a distinct `i` — the soundness bound
//     (n + s_count + n_extras − 1)/|F| stays at ~2^{-128}.
//   • Run `prove_multipoint_sumcheck_mixed` across base pairs
//     (log_len), ladder pairs (log_len), and extra pairs
//     (each extra's `log_len`). Challenges are length `n_max`
//     where `n_max = max(log_len, extras_log_lens…)`. For γ₃b
//     wiring B lives at log_len=15 and base at 13, so n_max=15.
//   • `r''_base = last log_len` challenges (reversed); `r''_extra_k`
//     = last `extra_k.log_len` challenges (reversed).
//   • Single `prove_batched_mixed` closes every base column and
//     every extra at its own hypercube.
#[allow(clippy::too_many_arguments)]
fn prove_air_unchecked_with_extras_inner<A: Air + ?Sized>(
    air: &A,
    trace: &Trace,
    pi: &PublicInputs,
    extra_transcript: &[Block128],
    extras: &[ExtraColumn],
) -> StarkProof {
    debug_assert!(
        !extras.is_empty(),
        "mixed inner called with empty extras — caller must delegate"
    );

    let log_rows = trace.log_rows;
    let log_len = padded_log_len(log_rows);
    let ntt = AdditiveNTT::<Block128>::new(log_len + noid_fri::code::LOG_RATE);
    let hasher = Poseidon2bSponge::new();

    let (commitments, padded_columns): (Vec<FriCommitment>, Vec<Vec<Block128>>) = {
        use rayon::prelude::*;
        trace
            .columns
            .par_iter()
            .map(|col| {
                let padded = pad_column(col, log_len);
                // SAFETY-INVARIANT: commit_fast uses Blake3 instead of Poseidon2b.
                // The round-0 tree is never opened; only its root is absorbed into
                // the Fiat-Shamir channel. See noid_fri::prover::commit_fast.
                let commitment = commit_fast(&padded, &ntt);
                (commitment, padded)
            })
            .unzip()
    };

    let mut channel = Channel::new();
    absorb_public_inputs(&mut channel, pi);
    for c in &commitments {
        channel.observe_fri_commitment(c);
    }
    if !extra_transcript.is_empty() {
        channel.observe_field_elems(extra_transcript);
    }

    let z = channel.get_random_points(log_len);
    let n_constraints = air.constraints().len();
    let betas: Vec<Block128> = (0..n_constraints)
        .map(|_| channel.get_random_point())
        .collect();

    let shifted_indices: Vec<usize> = air.shifted_column_indices();
    assert!(
        shifted_indices.is_empty() || log_rows == padded_log_len(log_rows),
        "VSHIFT requires log_rows >= TAU+1; got log_rows={} padded={}",
        log_rows,
        padded_log_len(log_rows)
    );
    let n_base = padded_columns.len();
    let mut shifted_slot: Vec<Option<usize>> = vec![None; n_base];
    for (slot, &col_id) in shifted_indices.iter().enumerate() {
        shifted_slot[col_id] = Some(slot);
    }
    let rotated_columns: Vec<Vec<Block128>> = shifted_indices
        .iter()
        .map(|&col_id| cyclic_rotate_left(&padded_columns[col_id]))
        .collect();
    let mut sumcheck_cols: Vec<&[Block128]> = Vec::with_capacity(n_base + rotated_columns.len());
    for col in &padded_columns {
        sumcheck_cols.push(col.as_slice());
    }
    for col in &rotated_columns {
        sumcheck_cols.push(col.as_slice());
    }

    let degree = round_poly_degree(air);
    let (zero_check_rounds, r) = prove_zero_check(
        &sumcheck_cols,
        air.constraints(),
        &betas,
        &z,
        &mut channel,
        degree,
        &shifted_slot,
        n_base,
    );

    let r_point: Vec<Block128> = r.iter().rev().cloned().collect();

    let (base_openings, shift_partials) =
        prove_base_and_ladder_partials(&padded_columns, &shifted_indices, &r_point, &mut channel);

    // --- γ₃b: absorb extras into the parent channel ---
    //
    // Tag + per-extra (commitment, eval_point, value). Canonical
    // ordering was fixed by `canonicalize_extras`; the verifier
    // replays in the same order.
    channel.observe_field_elem(Block128::from(EXTRAS_ABSORB_TAG as u128));
    for e in extras {
        channel.observe_fri_commitment(&e.commitment);
        channel.observe_field_elems(&e.eval_point);
        channel.observe_field_elem(e.value);
    }

    // --- Mixed multipoint close ---
    let (multipoint_rounds, mixed_proof) = prove_multipoint_close_mixed(
        &padded_columns,
        &base_openings,
        &r_point,
        &shifted_indices,
        &shift_partials,
        extras,
        log_len,
        &mut channel,
        &hasher,
    );

    // Stub BatchedEvalProof so the `multipoint_batch` field stays
    // populated with something structural. The verifier never reads
    // it when `multipoint_batch_mixed` is `Some`.
    let stub = stub_batched_eval_proof();

    StarkProof {
        log_rows,
        column_commitments: commitments,
        base_openings,
        zero_check_rounds,
        shift_partials,
        multipoint_rounds,
        multipoint_batch: stub,
        multipoint_batch_mixed: Some(mixed_proof),
        slice_claimed_values: Vec::new(),
    }
}

fn stub_batched_eval_proof() -> BatchedEvalProof {
    use noid_fri::prover::{EvalProof, Univariate};
    BatchedEvalProof {
        column_openings: Vec::new(),
        batch_proof: EvalProof {
            upper_partial_evals: Vec::new(),
            sum_check_oracles: Vec::<Univariate>::new(),
            fri_oracles: Vec::new(),
            fri_queried_symbols: Vec::new(),
            fri_merkle_paths: Vec::new(),
            final_codeword: Vec::new(),
        },
    }
}

/// γ₃b mixed-length multipoint close. Mirrors
/// `prove_multipoint_close_inner` but:
///
/// * Horner weights run over `n + s_count + n_extras` indices.
/// * Uses `prove_multipoint_sumcheck_mixed` over pairs of differing
///   hypercube sizes (base+ladder all share `log_len`; each extra
///   carries its own `log_len`).
/// * Closes with `prove_batched_mixed`, which groups columns by
///   hypercube size and runs one FRI per group under a shared α.
#[allow(clippy::too_many_arguments)]
fn prove_multipoint_close_mixed(
    padded_columns: &[Vec<Block128>],
    base_openings: &[Block128],
    r_point: &[Block128],
    shifted_indices: &[usize],
    shift_partials: &[Vec<Block128>],
    extras: &[ExtraColumn],
    log_len: usize,
    channel: &mut Channel,
    hasher: &Poseidon2bSponge,
) -> (Vec<RoundPoly>, MixedBatchedEvalProof) {
    use noid_core::mle::eq::eq_ind_partial_eval;
    use rayon::prelude::*;

    let n = padded_columns.len();
    let s_count = shifted_indices.len();
    let n_extras = extras.len();

    let gammas: Vec<Block128> = (0..s_count).map(|_| channel.get_random_point()).collect();

    channel.observe_field_elem(Block128::from(crate::multipoint_batch::MULTIPOINT_TAG));
    let beta = channel.get_random_point();
    let total_weights = n + s_count + n_extras;
    let mut lambdas: Vec<Block128> = Vec::with_capacity(total_weights);
    {
        let mut cur = Block128::ONE;
        for _ in 0..total_weights {
            lambdas.push(cur);
            cur *= beta;
        }
    }

    // Target = base + inlined-ladder + extras.
    let mut target = Block128::ZERO;
    for i in 0..n {
        target += lambdas[i] * base_openings[i];
    }
    for (slot, partials) in shift_partials.iter().enumerate() {
        let t_s = crate::ladder_batch::target_claim(gammas[slot], partials);
        target += lambdas[n + slot] * t_s;
    }
    for (i, e) in extras.iter().enumerate() {
        target += lambdas[n + s_count + i] * e.value;
    }

    // Build mixed pairs. Base pairs share `eq_base` on the A-side, so
    // we collapse them into a single fused pair
    // `(eq_base, Σ_i λ_i · padded_columns[i])` — identical round-oracle
    // accumulator by bilinearity of the sumcheck's degree-2 product,
    // byte-identical transcript. See `prove_multipoint_close_inner` for
    // the full soundness argument; the mixed/extras path picks up the
    // same savings on the base slab.
    let eq_base = eq_ind_partial_eval(r_point);
    let hyper_len = 1usize << log_len;
    let combined_base_b: Vec<Block128> = (0..n)
        .into_par_iter()
        .fold(
            || vec![Block128::ZERO; hyper_len],
            |mut acc, i| {
                let lambda = lambdas[i];
                let col = &padded_columns[i];
                for j in 0..hyper_len {
                    acc[j] += lambda * col[j];
                }
                acc
            },
        )
        .reduce(
            || vec![Block128::ZERO; hyper_len],
            |mut a, b| {
                for j in 0..hyper_len {
                    a[j] += b[j];
                }
                a
            },
        );

    let weight_trails = if s_count > 0 {
        Some(crate::ladder_batch::WeightTrails::new(r_point))
    } else {
        None
    };
    let ladder_pairs_a: Vec<Vec<Block128>> = (0..s_count)
        .into_par_iter()
        .map(|slot| {
            let trails = weight_trails
                .as_ref()
                .expect("trails present when s_count > 0");
            let mut w = crate::ladder_batch::build_weight_table_from_trails(gammas[slot], trails);
            let eta = lambdas[n + slot];
            for v in w.iter_mut() {
                *v *= eta;
            }
            w
        })
        .collect();
    let ladder_pairs_b: Vec<&[Block128]> = (0..s_count)
        .map(|slot| padded_columns[shifted_indices[slot]].as_slice())
        .collect();

    let extras_pairs_a: Vec<Vec<Block128>> = (0..n_extras)
        .into_par_iter()
        .map(|i| {
            let lam = lambdas[n + s_count + i];
            let eq_e = eq_ind_partial_eval(&extras[i].eval_point);
            eq_e.into_iter().map(|v| v * lam).collect()
        })
        .collect();
    let extras_pairs_b: Vec<&[Block128]> =
        (0..n_extras).map(|i| extras[i].evals.as_slice()).collect();

    let mut pairs_a: Vec<Vec<Block128>> = Vec::with_capacity(1 + s_count + n_extras);
    pairs_a.push(eq_base);
    pairs_a.extend(ladder_pairs_a);
    pairs_a.extend(extras_pairs_a);
    let mut pairs_b: Vec<&[Block128]> = Vec::with_capacity(1 + s_count + n_extras);
    pairs_b.push(combined_base_b.as_slice());
    pairs_b.extend(ladder_pairs_b);
    pairs_b.extend(extras_pairs_b);

    // n_vars ordering must match pairs ordering: one fused base pair
    // at log_len, then s_count ladder pairs at log_len, then extras at
    // their individual sizes.
    let mut n_vars: Vec<usize> = Vec::with_capacity(1 + s_count + n_extras);
    n_vars.push(log_len);
    for _ in 0..s_count {
        n_vars.push(log_len);
    }
    for e in extras {
        n_vars.push(e.commitment.log_len);
    }

    let (rounds, challenges) = crate::multipoint_batch::prove_multipoint_sumcheck_mixed(
        pairs_a, pairs_b, &n_vars, target, channel,
    );
    let n_max = n_vars.iter().copied().max().unwrap();
    debug_assert_eq!(challenges.len(), n_max);

    // Low-var suffix of reversed challenges, per hypercube size.
    // Convention: the uniform path defined `r_point_out = reversed(challenges)`;
    // MLE(r_point_out) closes the column. For mixed, each pair of
    // n_k vars has its low rounds at `round_idx ∈ [m_k, n_max)`
    // where `m_k = n_max - n_k`; the low-var challenges in fold
    // order are `challenges[m_k..]`, reversed for MLE input.
    let reversed_full: Vec<Block128> = challenges.iter().rev().cloned().collect();
    // For base cols (n_vars = log_len): opening point is
    // `reversed_full[..log_len]` — the first log_len entries of the
    // fully-reversed challenge vector. This is the same derivation
    // as `mixed_high_scalar(challenges, m)` — the low-var suffix of
    // the forward challenges is the high-var prefix of the reversed
    // challenges.
    //
    // When n_max == log_len (every extra also at log_len), this
    // collapses to the uniform path's r'' == reversed(challenges).
    let r_pp_base: Vec<Block128> = reversed_full[..log_len].to_vec();

    // Assemble the flat column list for the mixed FRI close, in a
    // fixed order: base columns first, then extras in canonical
    // order. The verifier builds the same list from
    // `proof.column_commitments` + the canonicalized extras.
    let mut cols_for_fri: Vec<&[Block128]> = padded_columns.iter().map(|v| v.as_slice()).collect();
    let mut col_log_lens: Vec<usize> = vec![log_len; n];
    for e in extras {
        cols_for_fri.push(e.evals.as_slice());
        col_log_lens.push(e.commitment.log_len);
    }

    // Opening-point map per log_len. Every column at `log_len`
    // opens at `r_pp_base` (length log_len). Every extra with a
    // different log_len ℓ opens at `reversed_full[..ℓ]`. This is
    // exactly what the mixed sumcheck's identity requires.
    let mut eval_points: std::collections::BTreeMap<usize, Vec<Block128>> = Default::default();
    eval_points.insert(log_len, r_pp_base);
    for e in extras {
        let ll = e.commitment.log_len;
        eval_points
            .entry(ll)
            .or_insert_with(|| reversed_full[..ll].to_vec());
    }

    // One AdditiveNTT plan per distinct log_len.
    let mut ntts: std::collections::BTreeMap<usize, AdditiveNTT<Block128>> = Default::default();
    for &ll in eval_points.keys() {
        ntts.entry(ll)
            .or_insert_with(|| AdditiveNTT::<Block128>::new(ll + noid_fri::code::LOG_RATE));
    }

    let proof = prove_batched_mixed(
        &cols_for_fri,
        &col_log_lens,
        &eval_points,
        &ntts,
        channel,
        hasher,
    );

    (rounds, proof)
}

fn verify_air_with_extras_inner<A: Air + ?Sized>(
    air: &A,
    pi: &PublicInputs,
    proof: &StarkProof,
    extra_transcript: &[Block128],
    extras: &[ExtraColumn],
) -> Result<(), VerifyError> {
    if proof.log_rows != air.log_rows() {
        return Err(VerifyError::ShapeMismatch);
    }
    if proof.column_commitments.len() != air.n_columns()
        || proof.base_openings.len() != air.n_columns()
    {
        return Err(VerifyError::ShapeMismatch);
    }
    // Mixed path: multipoint_batch is a stub; the authoritative
    // opening is in multipoint_batch_mixed.
    let mixed = proof
        .multipoint_batch_mixed
        .as_ref()
        .ok_or(VerifyError::ShapeMismatch)?;
    if mixed.column_openings.len() != air.n_columns() + extras.len() {
        return Err(VerifyError::ShapeMismatch);
    }

    let log_len = padded_log_len(proof.log_rows);
    if proof.zero_check_rounds.len() != log_len {
        return Err(VerifyError::ShapeMismatch);
    }
    let degree = round_poly_degree(air);
    let n_points = degree + 1;
    for rp in &proof.zero_check_rounds {
        if rp.len() != n_points {
            return Err(VerifyError::ShapeMismatch);
        }
    }

    let hasher = Poseidon2bSponge::new();

    let mut channel = Channel::new();
    absorb_public_inputs(&mut channel, pi);
    for c in &proof.column_commitments {
        channel.observe_fri_commitment(c);
    }
    if !extra_transcript.is_empty() {
        channel.observe_field_elems(extra_transcript);
    }

    let z = channel.get_random_points(log_len);
    let n_constraints = air.constraints().len();
    let betas: Vec<Block128> = (0..n_constraints)
        .map(|_| channel.get_random_point())
        .collect();

    let mut claim = Block128::ZERO;
    let mut challenges: Vec<Block128> = Vec::with_capacity(log_len);
    for rp in &proof.zero_check_rounds {
        let sum01 = rp[0] + rp[1];
        if sum01 != claim {
            return Err(VerifyError::ZeroCheckFailed);
        }
        channel.observe_field_elems(rp);
        let r_i = channel.get_random_point();
        claim = lagrange_eval_at_cached(rp, r_i);
        challenges.push(r_i);
    }

    let r_point: Vec<Block128> = challenges.iter().rev().cloned().collect();
    let eq_zr = noid_core::mle::eq::eq_ind(&z, &r_point);

    let shifted_indices: Vec<usize> = air.shifted_column_indices();
    if proof.shift_partials.len() != shifted_indices.len() {
        return Err(VerifyError::ShapeMismatch);
    }
    let expected_ladder_len = log_len + 1;
    for partials in &proof.shift_partials {
        if partials.len() != expected_ladder_len {
            return Err(VerifyError::ShapeMismatch);
        }
    }
    if proof.multipoint_rounds.len()
        != std::cmp::max(
            log_len,
            extras
                .iter()
                .map(|e| e.commitment.log_len)
                .max()
                .unwrap_or(0),
        )
    {
        return Err(VerifyError::ShapeMismatch);
    }
    for rp in &proof.multipoint_rounds {
        if rp.len() != crate::multipoint_batch::MULTIPOINT_ROUND_POINTS {
            return Err(VerifyError::ShapeMismatch);
        }
    }
    let mut shifted_slot: Vec<Option<usize>> = vec![None; air.n_columns()];
    for (slot, &col_id) in shifted_indices.iter().enumerate() {
        shifted_slot[col_id] = Some(slot);
    }

    let shifted_openings: Vec<Block128> = proof
        .shift_partials
        .iter()
        .map(|partials| reconstruct_shifted_opening(&r_point, partials))
        .collect();

    check_public_columns(air, &proof.base_openings, &r_point, log_len)?;

    let column_openings = &proof.base_openings;
    let mut composition = Block128::ZERO;
    let mut local_scratch: Vec<Block128> = Vec::new();
    let mut next_scratch: Vec<Block128> = Vec::new();
    for (k, c) in air.constraints().iter().enumerate() {
        local_scratch.clear();
        for &j in c.columns() {
            local_scratch.push(column_openings[j]);
        }
        next_scratch.clear();
        for &j in c.shifted_columns() {
            let slot = shifted_slot[j].ok_or(VerifyError::ShapeMismatch)?;
            next_scratch.push(shifted_openings[slot]);
        }
        let frame = EvalFrame {
            local: &local_scratch,
            next: &next_scratch,
        };
        composition += betas[k] * c.evaluate(frame);
    }
    if eq_zr * composition != claim {
        return Err(VerifyError::ConstraintViolated);
    }

    // Replay ladder-partial absorptions (same as default).
    channel.observe_field_elems(&proof.base_openings);
    for (slot, partials) in proof.shift_partials.iter().enumerate() {
        channel.observe_field_elem(crate::ladder_batch::sub_channel_tag(slot));
        channel.observe_field_elems(partials);
    }

    // γ₃b: extras absorbed on the parent channel before γ_s / β.
    channel.observe_field_elem(Block128::from(EXTRAS_ABSORB_TAG as u128));
    for e in extras {
        channel.observe_fri_commitment(&e.commitment);
        channel.observe_field_elems(&e.eval_point);
        channel.observe_field_elem(e.value);
    }

    let s_count = shifted_indices.len();
    let n_extras = extras.len();
    let gammas: Vec<Block128> = (0..s_count).map(|_| channel.get_random_point()).collect();

    channel.observe_field_elem(Block128::from(crate::multipoint_batch::MULTIPOINT_TAG));
    let beta = channel.get_random_point();
    let n = proof.base_openings.len();
    let total_weights = n + s_count + n_extras;
    let mut lambdas: Vec<Block128> = Vec::with_capacity(total_weights);
    {
        let mut cur = Block128::ONE;
        for _ in 0..total_weights {
            lambdas.push(cur);
            cur *= beta;
        }
    }

    let mut target = Block128::ZERO;
    for i in 0..n {
        target += lambdas[i] * proof.base_openings[i];
    }
    for (slot, partials) in proof.shift_partials.iter().enumerate() {
        let t_s = crate::ladder_batch::target_claim(gammas[slot], partials);
        target += lambdas[n + slot] * t_s;
    }
    for (i, e) in extras.iter().enumerate() {
        target += lambdas[n + s_count + i] * e.value;
    }

    let (sc_challenges, final_claim) = crate::multipoint_batch::verify_multipoint_sumcheck_mixed(
        &proof.multipoint_rounds,
        target,
        &mut channel,
    )?;
    let reversed_full: Vec<Block128> = sc_challenges.iter().rev().cloned().collect();
    let n_max = sc_challenges.len();
    if n_max
        != std::cmp::max(
            log_len,
            extras
                .iter()
                .map(|e| e.commitment.log_len)
                .max()
                .unwrap_or(0),
        )
    {
        return Err(VerifyError::ShapeMismatch);
    }
    let r_pp_base: Vec<Block128> = reversed_full[..log_len].to_vec();

    // Reconstruct the mixed terminal. Flat column order is base then
    // extras (canonical); openings come from
    // `mixed.column_openings`. Each pair contributes
    //   lambda_k · (A_k at its low-var suffix) · m_k
    // where `A_k` was a scaled eq, plus the high-scalar prefix
    // accumulated into `s_k^final`. Using `mixed_high_scalar` on the
    // forward challenges' high prefix collapses both into a clean
    // reconstruction (the mixed sumcheck identity).
    let m_base = &mixed.column_openings[..n];
    let m_extras = &mixed.column_openings[n..];
    let eq_base = noid_core::mle::eq::eq_ind(&r_point, &r_pp_base);

    // Per-pair high-round scalar. Base + ladder share `m_base_rounds
    // = n_max - log_len`; each extra has its own. When n_max == log_len
    // (extras at the base hypercube size), m_base_rounds = 0 and
    // s_base_scalar = 1 — which reduces this reconstruction to the
    // legacy uniform formula.
    let m_base_rounds = n_max - log_len;
    let s_base_scalar = crate::multipoint_batch::mixed_high_scalar(&sc_challenges, m_base_rounds);

    let mut expected = Block128::ZERO;
    for k in 0..n {
        expected += lambdas[k] * s_base_scalar * eq_base * m_base[k];
    }
    if s_count > 0 {
        let axes = crate::ladder_batch::LadderWeightAxes::new(&r_point, &r_pp_base);
        for (slot, &col_id) in shifted_indices.iter().enumerate() {
            let w_s = crate::ladder_batch::weight_at_axes(gammas[slot], &axes);
            expected += lambdas[n + slot] * s_base_scalar * w_s * m_base[col_id];
        }
    }
    for (i, e) in extras.iter().enumerate() {
        let ll = e.commitment.log_len;
        let m_k = n_max - ll;
        let s_k = crate::multipoint_batch::mixed_high_scalar(&sc_challenges, m_k);
        let r_low: &[Block128] = &reversed_full[..ll];
        let eq_e = noid_core::mle::eq::eq_ind(&e.eval_point, r_low);
        expected += lambdas[n + s_count + i] * s_k * eq_e * m_extras[i];
    }
    if expected != final_claim {
        return Err(VerifyError::ConstraintViolated);
    }

    // Flat column list for mixed FRI verify: base (log_len) then
    // extras in canonical order, each at its own log_len.
    let mut flat_commits: Vec<FriCommitment> = proof.column_commitments.clone();
    for e in extras {
        flat_commits.push(e.commitment.clone());
    }
    let mut col_log_lens: Vec<usize> = vec![log_len; n];
    for e in extras {
        col_log_lens.push(e.commitment.log_len);
    }

    let mut eval_points: std::collections::BTreeMap<usize, Vec<Block128>> = Default::default();
    eval_points.insert(log_len, r_pp_base);
    for e in extras {
        let ll = e.commitment.log_len;
        eval_points
            .entry(ll)
            .or_insert_with(|| reversed_full[..ll].to_vec());
    }
    let mut ntts: std::collections::BTreeMap<usize, AdditiveNTT<Block128>> = Default::default();
    for &ll in eval_points.keys() {
        ntts.entry(ll)
            .or_insert_with(|| AdditiveNTT::<Block128>::new(ll + noid_fri::code::LOG_RATE));
    }

    verify_batched_mixed(
        &flat_commits,
        &col_log_lens,
        &eval_points,
        &ntts,
        mixed,
        &mut channel,
        &hasher,
    )
    .map_err(VerifyError::FriFailed)?;

    Ok(())
}

/// Like [`prove_air_unchecked`], but absorbs `extra_transcript` into
/// the parent Fiat-Shamir channel **between** the column-root
/// absorption and the zero-check point draw. The default path absorbs
/// an empty slice and is identical to `prove_air_unchecked`; the
/// GKR-spine path threads a digest of the GKR `SpineProof` through
/// this hook so any spine tamper forks every later STARK challenge.
#[doc(hidden)]
pub fn prove_air_unchecked_with_extra<A: Air + ?Sized>(
    air: &A,
    trace: &Trace,
    pi: &PublicInputs,
    extra_transcript: &[Block128],
) -> StarkProof {
    let log_rows = trace.log_rows;
    let log_len = padded_log_len(log_rows);
    let ntt = AdditiveNTT::<Block128>::new(log_len + noid_fri::code::LOG_RATE);
    let hasher = Poseidon2bSponge::new();

    // --- Commit columns (parallel across columns) ---
    let (commitments, padded_columns): (Vec<FriCommitment>, Vec<Vec<Block128>>) = {
        use rayon::prelude::*;
        trace
            .columns
            .par_iter()
            .map(|col| {
                let padded = pad_column(col, log_len);
                // SAFETY-INVARIANT: commit_fast uses Blake3 instead of Poseidon2b.
                // The round-0 tree is never opened; only its root is absorbed into
                // the Fiat-Shamir channel. See noid_fri::prover::commit_fast.
                let commitment = commit_fast(&padded, &ntt);
                (commitment, padded)
            })
            .unzip()
    };

    // --- Parent transcript: PI + column roots + optional extras ---
    let mut channel = Channel::new();
    absorb_public_inputs(&mut channel, pi);
    for c in &commitments {
        channel.observe_fri_commitment(c);
    }
    if !extra_transcript.is_empty() {
        channel.observe_field_elems(extra_transcript);
    }

    // --- Zero-check point `z` and constraint-batching scalars `β_j` ---
    let z = channel.get_random_points(log_len);
    let n_constraints = air.constraints().len();
    let betas: Vec<Block128> = (0..n_constraints)
        .map(|_| channel.get_random_point())
        .collect();

    // --- Materialise rotated virtual columns for shifted-column reads ---
    //
    // For every `col_id` in `air.shifted_column_indices()` we build a
    // padded cyclically-rotated copy and append it to the sumcheck's
    // column list. Crucially, rotation is done over the full padded
    // length `2^log_len`, matching the hypercube the MLE commits to —
    // NOT the `2^log_rows` unpadded trace. The rotated columns are
    // ephemeral to the sumcheck and are NOT FRI-committed on their own;
    // their soundness comes from the ladder partials below.
    let shifted_indices: Vec<usize> = air.shifted_column_indices();
    // VSHIFT assumes rotation over the committed MLE's own hypercube —
    // i.e. rotation at padded-length `2^log_len`. When `log_len >
    // log_rows` the witness lives on a prefix of that hypercube and the
    // cyclic-next of the last witness row is a padding row, not row 0
    // of the witness. Every current AIR that opts into rotation
    // (shipped sub-AIRs: `POSEIDON_PERM_LOG_ROWS = 8`,
    // `TXBODY_MERKLE_LOG_ROWS = 13`, `FRI_STATE_COMBINER_LOG_ROWS = 9`;
    // the stitched Stage 7 `[L]` composite lands at its own derived
    // `log_rows`, measured — not hardcoded) satisfies
    // `log_rows >= TAU+1`, so the padded case is not part of the
    // protocol contract.
    assert!(
        shifted_indices.is_empty() || log_rows == padded_log_len(log_rows),
        "VSHIFT requires log_rows >= TAU+1; got log_rows={} padded={}",
        log_rows,
        padded_log_len(log_rows)
    );
    let n_base = padded_columns.len();
    let mut shifted_slot: Vec<Option<usize>> = vec![None; n_base];
    for (slot, &col_id) in shifted_indices.iter().enumerate() {
        shifted_slot[col_id] = Some(slot);
    }
    let rotated_columns: Vec<Vec<Block128>> = shifted_indices
        .iter()
        .map(|&col_id| cyclic_rotate_left(&padded_columns[col_id]))
        .collect();
    let mut sumcheck_cols: Vec<&[Block128]> = Vec::with_capacity(n_base + rotated_columns.len());
    for col in &padded_columns {
        sumcheck_cols.push(col.as_slice());
    }
    for col in &rotated_columns {
        sumcheck_cols.push(col.as_slice());
    }

    // --- Batched zero-check sumcheck ---
    let degree = round_poly_degree(air);
    let (zero_check_rounds, r) = prove_zero_check(
        &sumcheck_cols,
        air.constraints(),
        &betas,
        &z,
        &mut channel,
        degree,
        &shifted_slot,
        n_base,
    );

    // --- Column openings at the sumcheck's final challenge point ---
    // Sumcheck folds the highest variable first, so `challenges[k]`
    // binds `x_{n-1-k}`. Reverse for MLE-eval / FRI-eval consumption.
    let r_point: Vec<Block128> = r.iter().rev().cloned().collect();

    // Base openings + VSHIFT ladder partials (absorbed on channel).
    let (base_openings, shift_partials) =
        prove_base_and_ladder_partials(&padded_columns, &shifted_indices, &r_point, &mut channel);

    // §12c' multipoint consolidation — one batched FRI closes both the
    // base claims at `r_point` and every ladder claim (inlined as a
    // γ_s-weighted eq-sum over `ladder_points(r_point)`).
    let (multipoint_rounds, multipoint_batch) = prove_multipoint_close(
        &padded_columns,
        &base_openings,
        &r_point,
        &shifted_indices,
        &shift_partials,
        log_len,
        &ntt,
        &mut channel,
        &hasher,
    );

    StarkProof {
        log_rows,
        column_commitments: commitments,
        base_openings,
        zero_check_rounds,
        shift_partials,
        multipoint_rounds,
        multipoint_batch,
        multipoint_batch_mixed: None,
        slice_claimed_values: Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// Verifier
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum VerifyError {
    ShapeMismatch,
    FriFailed(String),
    ZeroCheckFailed,
    ConstraintViolated,
}

pub fn verify_air<A: Air>(
    air: &A,
    pi: &PublicInputs,
    proof: &StarkProof,
) -> Result<(), VerifyError> {
    verify_air_with_extra(air, pi, proof, &[])
}

/// Mirror of [`prove_air_unchecked_with_extra`]: the verifier absorbs
/// `extra_transcript` at the same transcript position. Empty-slice
/// input matches the default [`verify_air`] path byte-for-byte.
pub fn verify_air_with_extra<A: Air + ?Sized>(
    air: &A,
    pi: &PublicInputs,
    proof: &StarkProof,
    extra_transcript: &[Block128],
) -> Result<(), VerifyError> {
    if proof.log_rows != air.log_rows() {
        return Err(VerifyError::ShapeMismatch);
    }
    if proof.column_commitments.len() != air.n_columns()
        || proof.base_openings.len() != air.n_columns()
        || proof.multipoint_batch.column_openings.len() != air.n_columns()
    {
        return Err(VerifyError::ShapeMismatch);
    }

    let log_len = padded_log_len(proof.log_rows);
    if proof.zero_check_rounds.len() != log_len {
        return Err(VerifyError::ShapeMismatch);
    }
    let degree = round_poly_degree(air);
    let n_points = degree + 1;
    for rp in &proof.zero_check_rounds {
        if rp.len() != n_points {
            return Err(VerifyError::ShapeMismatch);
        }
    }

    let ntt = AdditiveNTT::<Block128>::new(log_len + noid_fri::code::LOG_RATE);
    let hasher = Poseidon2bSponge::new();

    // --- Replay parent transcript ---
    let mut channel = Channel::new();
    absorb_public_inputs(&mut channel, pi);
    for c in &proof.column_commitments {
        channel.observe_fri_commitment(c);
    }
    if !extra_transcript.is_empty() {
        channel.observe_field_elems(extra_transcript);
    }
    let z = channel.get_random_points(log_len);
    let n_constraints = air.constraints().len();
    let betas: Vec<Block128> = (0..n_constraints)
        .map(|_| channel.get_random_point())
        .collect();

    // --- Replay zero-check sumcheck ---
    let mut claim = Block128::ZERO;
    let mut challenges: Vec<Block128> = Vec::with_capacity(log_len);
    for rp in &proof.zero_check_rounds {
        // p(0) + p(1) == claim
        let sum01 = rp[0] + rp[1];
        if sum01 != claim {
            return Err(VerifyError::ZeroCheckFailed);
        }
        channel.observe_field_elems(rp);
        let r_i = channel.get_random_point();
        claim = lagrange_eval_at_cached(rp, r_i);
        challenges.push(r_i);
    }

    // --- Final-claim check against the column openings ---
    // Sumcheck binds x_{n-1} first, so the opening point used for
    // column MLEs is the reversed challenge vector.
    let r_point: Vec<Block128> = challenges.iter().rev().cloned().collect();
    let eq_zr = noid_core::mle::eq::eq_ind(&z, &r_point);

    // Rebuild the shifted-column slot map from the AIR and validate
    // ladder shape before we trust it in reconstruction.
    let shifted_indices: Vec<usize> = air.shifted_column_indices();
    if proof.shift_partials.len() != shifted_indices.len() {
        return Err(VerifyError::ShapeMismatch);
    }
    let expected_ladder_len = log_len + 1;
    for partials in &proof.shift_partials {
        if partials.len() != expected_ladder_len {
            return Err(VerifyError::ShapeMismatch);
        }
    }
    if proof.multipoint_rounds.len() != log_len {
        return Err(VerifyError::ShapeMismatch);
    }
    for rp in &proof.multipoint_rounds {
        if rp.len() != crate::multipoint_batch::MULTIPOINT_ROUND_POINTS {
            return Err(VerifyError::ShapeMismatch);
        }
    }
    let mut shifted_slot: Vec<Option<usize>> = vec![None; air.n_columns()];
    for (slot, &col_id) in shifted_indices.iter().enumerate() {
        shifted_slot[col_id] = Some(slot);
    }

    // Closed-form reconstruction of `C'(r)` per shifted column, in the
    // same slot order as `shifted_indices`.
    let shifted_openings: Vec<Block128> = proof
        .shift_partials
        .iter()
        .map(|partials| reconstruct_shifted_opening(&r_point, partials))
        .collect();

    // Stage 3d-0.2: bind every `PublicColumn` to its committed base
    // opening via MLE re-evaluation at `r_point`.
    check_public_columns(air, &proof.base_openings, &r_point, log_len)?;

    let column_openings = &proof.base_openings;
    let mut composition = Block128::ZERO;
    let mut local_scratch: Vec<Block128> = Vec::new();
    let mut next_scratch: Vec<Block128> = Vec::new();
    for (k, c) in air.constraints().iter().enumerate() {
        local_scratch.clear();
        for &j in c.columns() {
            local_scratch.push(column_openings[j]);
        }
        next_scratch.clear();
        for &j in c.shifted_columns() {
            let slot = shifted_slot[j].ok_or(VerifyError::ShapeMismatch)?;
            next_scratch.push(shifted_openings[slot]);
        }
        let frame = EvalFrame {
            local: &local_scratch,
            next: &next_scratch,
        };
        composition += betas[k] * c.evaluate(frame);
    }
    if eq_zr * composition != claim {
        return Err(VerifyError::ConstraintViolated);
    }

    // --- Replay §12c' multipoint close (ladder terms inlined) ---
    verify_multipoint_close(
        proof,
        &r_point,
        &shifted_indices,
        log_len,
        &ntt,
        &mut channel,
        &hasher,
    )
}

/// Verifier-side replay of the §12c' multipoint consolidation.
/// Absorbs base openings + per-slot ladder partials on the parent
/// channel (matching the prover's order), re-derives every `γ_s` and
/// the multipoint `β`, runs the degree-2 sumcheck replay, and finishes
/// with a single `verify_batched` at `r''` that closes every base and
/// ladder claim in one FRI opening.
fn verify_multipoint_close(
    proof: &StarkProof,
    r_point: &[Block128],
    shifted_indices: &[usize],
    log_len: usize,
    ntt: &AdditiveNTT<Block128>,
    channel: &mut Channel,
    hasher: &Poseidon2bSponge,
) -> Result<(), VerifyError> {
    channel.observe_field_elems(&proof.base_openings);

    // Absorb every slot's partials with the slot tag — prover did the
    // same in `prove_base_and_ladder_partials`.
    for (slot, partials) in proof.shift_partials.iter().enumerate() {
        channel.observe_field_elem(crate::ladder_batch::sub_channel_tag(slot));
        channel.observe_field_elems(partials);
    }

    let s_count = shifted_indices.len();
    let gammas: Vec<Block128> = (0..s_count).map(|_| channel.get_random_point()).collect();

    // §12c': absorb tag, squeeze β, compute Horner weights.
    channel.observe_field_elem(Block128::from(crate::multipoint_batch::MULTIPOINT_TAG));
    let beta = channel.get_random_point();
    let n = proof.base_openings.len();
    let mut lambdas: Vec<Block128> = Vec::with_capacity(n + s_count);
    {
        let mut cur = Block128::ONE;
        for _ in 0..(n + s_count) {
            lambdas.push(cur);
            cur *= beta;
        }
    }

    // Target: base + inlined ladder contributions.
    let mut target = Block128::ZERO;
    for i in 0..n {
        target += lambdas[i] * proof.base_openings[i];
    }
    for (slot, partials) in proof.shift_partials.iter().enumerate() {
        let t_s = crate::ladder_batch::target_claim(gammas[slot], partials);
        target += lambdas[n + slot] * t_s;
    }

    let (challenges, final_claim) = crate::multipoint_batch::verify_multipoint_sumcheck(
        &proof.multipoint_rounds,
        target,
        channel,
    )?;
    let r_pp: Vec<Block128> = challenges.iter().rev().cloned().collect();
    if r_pp.len() != log_len {
        return Err(VerifyError::ShapeMismatch);
    }

    // Reconstruct terminal claim from multipoint_batch.column_openings
    // m_i at r''. Base claims share eq(r_point, r''); ladder claims use
    // W_s(r'') = Σ_k γ_s^k · eq(P_{s,k}, r'').
    let m = &proof.multipoint_batch.column_openings;
    let eq_base = noid_core::mle::eq::eq_ind(r_point, &r_pp);
    let mut expected = Block128::ZERO;
    for k in 0..n {
        expected += lambdas[k] * eq_base * m[k];
    }
    if s_count > 0 {
        let axes = crate::ladder_batch::LadderWeightAxes::new(r_point, &r_pp);
        for (slot, &col_id) in shifted_indices.iter().enumerate() {
            let w_s = crate::ladder_batch::weight_at_axes(gammas[slot], &axes);
            expected += lambdas[n + slot] * w_s * m[col_id];
        }
    }
    if expected != final_claim {
        return Err(VerifyError::ConstraintViolated);
    }

    verify_batched(
        &proof.column_commitments,
        &r_pp,
        &proof.multipoint_batch,
        ntt,
        channel,
        hasher,
    )
    .map_err(VerifyError::FriFailed)?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Instrumented verifier (for bench-time bucketed timing)
// ---------------------------------------------------------------------------

/// Wall-clock breakdown of `verify_air_timed` for a single proof.
///
/// Post-3b-0.4 bucket layout:
/// * `transcript_sumcheck` — parent transcript + zero-check replay.
/// * `composition` — zero-check terminal equation.
/// * `ladder_sumcheck` — per-slot §12a ladder sumcheck replays.
/// * `multipoint_fri` — §12c multipoint sumcheck replay + single batched
///   FRI verify at `r''`. Replaces the old `base_fri` + `ladder_fri`.
#[derive(Debug, Clone, Copy, Default)]
pub struct VerifyTimings {
    pub transcript_sumcheck: std::time::Duration,
    pub composition: std::time::Duration,
    pub ladder_sumcheck: std::time::Duration,
    pub multipoint_fri: std::time::Duration,
}

impl VerifyTimings {
    pub fn total(&self) -> std::time::Duration {
        self.transcript_sumcheck + self.composition + self.ladder_sumcheck + self.multipoint_fri
    }
}

/// Mirror of [`verify_air`] instrumented with per-bucket timers. All
/// algebraic / FRI checks are identical to `verify_air` — this variant
/// is strictly a benchmark aid.
pub fn verify_air_timed<A: Air>(
    air: &A,
    pi: &PublicInputs,
    proof: &StarkProof,
) -> (Result<(), VerifyError>, VerifyTimings) {
    use std::time::Instant;
    let mut t = VerifyTimings::default();

    let t0 = Instant::now();
    if proof.log_rows != air.log_rows() {
        return (Err(VerifyError::ShapeMismatch), t);
    }
    if proof.column_commitments.len() != air.n_columns()
        || proof.base_openings.len() != air.n_columns()
        || proof.multipoint_batch.column_openings.len() != air.n_columns()
    {
        return (Err(VerifyError::ShapeMismatch), t);
    }
    let log_len = padded_log_len(proof.log_rows);
    if proof.zero_check_rounds.len() != log_len {
        return (Err(VerifyError::ShapeMismatch), t);
    }
    let degree = round_poly_degree(air);
    let n_points = degree + 1;
    for rp in &proof.zero_check_rounds {
        if rp.len() != n_points {
            return (Err(VerifyError::ShapeMismatch), t);
        }
    }
    let ntt = AdditiveNTT::<Block128>::new(log_len + noid_fri::code::LOG_RATE);
    let hasher = Poseidon2bSponge::new();
    let mut channel = Channel::new();
    absorb_public_inputs(&mut channel, pi);
    for c in &proof.column_commitments {
        channel.observe_fri_commitment(c);
    }
    let z = channel.get_random_points(log_len);
    let n_constraints = air.constraints().len();
    let betas: Vec<Block128> = (0..n_constraints)
        .map(|_| channel.get_random_point())
        .collect();
    let mut claim = Block128::ZERO;
    let mut challenges: Vec<Block128> = Vec::with_capacity(log_len);
    for rp in &proof.zero_check_rounds {
        let sum01 = rp[0] + rp[1];
        if sum01 != claim {
            t.transcript_sumcheck += t0.elapsed();
            return (Err(VerifyError::ZeroCheckFailed), t);
        }
        channel.observe_field_elems(rp);
        let r_i = channel.get_random_point();
        claim = lagrange_eval_at_cached(rp, r_i);
        challenges.push(r_i);
    }
    t.transcript_sumcheck = t0.elapsed();

    let t1 = Instant::now();
    let r_point: Vec<Block128> = challenges.iter().rev().cloned().collect();
    let eq_zr = noid_core::mle::eq::eq_ind(&z, &r_point);
    let shifted_indices: Vec<usize> = air.shifted_column_indices();
    if proof.shift_partials.len() != shifted_indices.len() {
        return (Err(VerifyError::ShapeMismatch), t);
    }
    let expected_ladder_len = log_len + 1;
    for partials in &proof.shift_partials {
        if partials.len() != expected_ladder_len {
            return (Err(VerifyError::ShapeMismatch), t);
        }
    }
    if proof.multipoint_rounds.len() != log_len {
        return (Err(VerifyError::ShapeMismatch), t);
    }
    for rp in &proof.multipoint_rounds {
        if rp.len() != crate::multipoint_batch::MULTIPOINT_ROUND_POINTS {
            return (Err(VerifyError::ShapeMismatch), t);
        }
    }
    let mut shifted_slot: Vec<Option<usize>> = vec![None; air.n_columns()];
    for (slot, &col_id) in shifted_indices.iter().enumerate() {
        shifted_slot[col_id] = Some(slot);
    }
    let shifted_openings: Vec<Block128> = proof
        .shift_partials
        .iter()
        .map(|partials| reconstruct_shifted_opening(&r_point, partials))
        .collect();
    // Stage 3d-0.2: bind declared public columns to their base openings.
    if let Err(e) = check_public_columns(air, &proof.base_openings, &r_point, log_len) {
        t.composition = t1.elapsed();
        return (Err(e), t);
    }

    let column_openings = &proof.base_openings;
    let mut composition = Block128::ZERO;
    let mut local_scratch: Vec<Block128> = Vec::new();
    let mut next_scratch: Vec<Block128> = Vec::new();
    for (k, c) in air.constraints().iter().enumerate() {
        local_scratch.clear();
        for &j in c.columns() {
            local_scratch.push(column_openings[j]);
        }
        next_scratch.clear();
        for &j in c.shifted_columns() {
            let slot = match shifted_slot[j] {
                Some(s) => s,
                None => {
                    t.composition += t1.elapsed();
                    return (Err(VerifyError::ShapeMismatch), t);
                }
            };
            next_scratch.push(shifted_openings[slot]);
        }
        let frame = EvalFrame {
            local: &local_scratch,
            next: &next_scratch,
        };
        composition += betas[k] * c.evaluate(frame);
    }
    if eq_zr * composition != claim {
        t.composition = t1.elapsed();
        return (Err(VerifyError::ConstraintViolated), t);
    }
    t.composition = t1.elapsed();

    // --- Ladder absorption (§12c' pre-step) ---
    let t2 = Instant::now();
    channel.observe_field_elems(&proof.base_openings);
    for (slot, partials) in proof.shift_partials.iter().enumerate() {
        channel.observe_field_elem(crate::ladder_batch::sub_channel_tag(slot));
        channel.observe_field_elems(partials);
    }
    let s_count = shifted_indices.len();
    let gammas: Vec<Block128> = (0..s_count).map(|_| channel.get_random_point()).collect();
    t.ladder_sumcheck = t2.elapsed();

    // --- §12c' multipoint sumcheck replay + batched FRI at r'' ---
    let t3 = Instant::now();
    channel.observe_field_elem(Block128::from(crate::multipoint_batch::MULTIPOINT_TAG));
    let beta = channel.get_random_point();
    let n = proof.base_openings.len();
    let mut lambdas: Vec<Block128> = Vec::with_capacity(n + s_count);
    {
        let mut cur = Block128::ONE;
        for _ in 0..(n + s_count) {
            lambdas.push(cur);
            cur *= beta;
        }
    }
    let mut mp_target = Block128::ZERO;
    for i in 0..n {
        mp_target += lambdas[i] * proof.base_openings[i];
    }
    for (slot, partials) in proof.shift_partials.iter().enumerate() {
        let t_s = crate::ladder_batch::target_claim(gammas[slot], partials);
        mp_target += lambdas[n + slot] * t_s;
    }
    let (mp_challenges, mp_final) = match crate::multipoint_batch::verify_multipoint_sumcheck(
        &proof.multipoint_rounds,
        mp_target,
        &mut channel,
    ) {
        Ok(v) => v,
        Err(e) => {
            t.multipoint_fri = t3.elapsed();
            return (Err(e), t);
        }
    };
    let r_pp: Vec<Block128> = mp_challenges.iter().rev().cloned().collect();
    let m = &proof.multipoint_batch.column_openings;
    let eq_base = noid_core::mle::eq::eq_ind(&r_point, &r_pp);
    let mut expected = Block128::ZERO;
    for k in 0..n {
        expected += lambdas[k] * eq_base * m[k];
    }
    if s_count > 0 {
        let axes = crate::ladder_batch::LadderWeightAxes::new(&r_point, &r_pp);
        for (slot, &col_id) in shifted_indices.iter().enumerate() {
            let w_s = crate::ladder_batch::weight_at_axes(gammas[slot], &axes);
            expected += lambdas[n + slot] * w_s * m[col_id];
        }
    }
    if expected != mp_final {
        t.multipoint_fri = t3.elapsed();
        return (Err(VerifyError::ConstraintViolated), t);
    }
    if let Err(e) = verify_batched(
        &proof.column_commitments,
        &r_pp,
        &proof.multipoint_batch,
        &ntt,
        &mut channel,
        &hasher,
    ) {
        t.multipoint_fri = t3.elapsed();
        return (Err(VerifyError::FriFailed(e)), t);
    }
    t.multipoint_fri = t3.elapsed();

    (Ok(()), t)
}

// ---------------------------------------------------------------------------
// MLE eval helper
// ---------------------------------------------------------------------------

pub fn mle_eval(evals: &[Block128], point: &[Block128]) -> Block128 {
    let mut buf = evals.to_vec();
    for &r in point.iter().rev() {
        let half = buf.len() / 2;
        for i in 0..half {
            buf[i] = buf[i] + r * (buf[i + half] + buf[i]);
        }
        buf.truncate(half);
    }
    buf[0]
}

// ---------------------------------------------------------------------------
// Stage 3d-0.2: PublicColumn verifier-side binding
// ---------------------------------------------------------------------------

/// Enforce every `PublicColumn` declaration on the given proof.
/// For each pinned column, re-compute the MLE of the programme (zero-
/// padded from the AIR's native `log_rows` up to the proof's `log_len`)
/// at the sumcheck terminal `r_point`, and compare against
/// `base_openings[col]`. The base opening is itself bound to the
/// committed column by the §12c' multipoint FRI, so any programme
/// deviation surfaces here with overwhelming probability.
pub(crate) fn check_public_columns<A: Air + ?Sized>(
    air: &A,
    base_openings: &[Block128],
    r_point: &[Block128],
    log_len: usize,
) -> Result<(), VerifyError> {
    // Naive per-column `mle_eval` is O(2^log_len) with a fresh allocation
    // for every `PublicColumn`; on the composite AIR (log_len=13,
    // ~500 pinned cols) that dominated verify time (~161 ms).
    //
    // Two structural observations let us avoid all of that work:
    //
    //   (1) Programme MLEs are evaluated at the *same* terminal point
    //       `r_point` for every public column, so we only need one
    //       equality tensor per distinct `pc.log_rows` (i.e. per distinct
    //       programme hypercube size), shared across all pins at that
    //       size.
    //
    //   (2) Zero-padding a length-`2^k` programme up to `2^log_len` only
    //       contributes the scalar factor `∏_{i=k..log_len} (1 + r_i)`
    //       — the high variables fold through a zero half in every step
    //       and leave the low-variable MLE unchanged. So we evaluate the
    //       programme at its *native* log_rows and multiply by this
    //       precomputed factor, instead of allocating a padded buffer.
    assert_eq!(r_point.len(), log_len);
    let expected_rows = 1usize << air.log_rows();
    let publics = air.public_columns();
    if publics.is_empty() {
        return Ok(());
    }
    // Cumulative high-var factors: hi_factor[k] = ∏_{i=k..log_len} (1 + r_i).
    // hi_factor[log_len] == 1 (empty product); every public column with
    // log_rows = k uses hi_factor[k].
    let mut hi_factor: Vec<Block128> = vec![Block128::ONE; log_len + 1];
    for k in (0..log_len).rev() {
        hi_factor[k] = hi_factor[k + 1] * (Block128::ONE + r_point[k]);
    }
    // One equality tensor per distinct log_rows; lazily built on first use.
    let mut eq_tensors: Vec<Option<Vec<Block128>>> = (0..=log_len).map(|_| None).collect();
    for pc in publics {
        if pc.col >= air.n_columns() || pc.values.len() != expected_rows {
            return Err(VerifyError::ShapeMismatch);
        }
        let k = pc.log_rows();
        if k > log_len {
            return Err(VerifyError::ShapeMismatch);
        }
        let tensor = eq_tensors[k]
            .get_or_insert_with(|| noid_core::mle::eq::eq_ind_partial_eval(&r_point[..k]));
        // Programme MLEs are overwhelmingly sparse in their native
        // hypercube: `bit_adder_operand_programme(64, …)` pins 64 real
        // bits followed by 8128 zeros; `emit_*_public_columns` similarly
        // leaves long zero tails. Locate the last nonzero index once and
        // truncate the dot product there — dominates the comp runtime of
        // the composite AIR where ~500 pins share a 2^13 hypercube.
        let vs = pc.values.as_slice();
        let mut hi = vs.len();
        while hi > 0 && vs[hi - 1] == Block128::ZERO {
            hi -= 1;
        }
        let mut lo = Block128::ZERO;
        for i in 0..hi {
            lo += tensor[i] * vs[i];
        }
        let expected = hi_factor[k] * lo;
        if base_openings[pc.col] != expected {
            return Err(VerifyError::ConstraintViolated);
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use noid_air::composition::tx_logic::{witness_from_body, TxLogicAir};
    use noid_air::{
        Air, BoolGate, CompositeAir, Constraint, LinearCombinationAir, Trace, WeightedLinearGate,
    };
    use noid_poseidon2b::primitives::TxBodyHash;
    use noid_tx::{TxInput, TxOutput};

    fn mk_pi() -> PublicInputs {
        PublicInputs {
            epoch_anchor: [0x11; 32],
            claims_commitment: [0u8; 32],
            tx_body_hash: TxBodyHash([0x44; 32]),
            fee: 7,
            n_live_inputs: 0,
            n_live_outputs: 0,
            coinbase_credit: 0,
            log_slots: 24,
            is_activation: [false; noid_tx::MAX_OUTPUTS],
            is_deactivation: [false; noid_tx::MAX_INPUTS],
        }
    }

    fn mk_body() -> noid_tx::TxBody {
        noid_tx::TxBody {
            epoch_anchor: [0u8; 32],
            fee: 0,
            inputs: vec![
                TxInput::dummy(),
                TxInput::dummy(),
                TxInput::dummy(),
                TxInput::dummy(),
            ],
            outputs: vec![
                TxOutput::dummy(),
                TxOutput::dummy(),
                TxOutput::dummy(),
                TxOutput::dummy(),
                TxOutput::dummy(),
                TxOutput::dummy(),
                TxOutput::dummy(),
                TxOutput::dummy(),
            ],
            is_coinbase: false,
        }
    }

    /// Build a minimal honest TxLogicAir + trace for use as a STARK engine fixture.
    /// All inputs/outputs are dummy (value=0), so balance holds trivially.
    fn mk_logic_air_and_trace() -> (TxLogicAir, noid_air::Trace) {
        let body = mk_body();
        let witness = witness_from_body(&body);
        let air = TxLogicAir::new(witness.boundary_pins);
        let trace = air.build_trace(&witness);
        (air, trace)
    }

    // -------- Degree-3 constraint: col0 · col1 · col2 == 0 --------

    struct Deg3ProductGate {
        cols: [usize; 3],
    }
    impl Constraint for Deg3ProductGate {
        fn degree(&self) -> usize {
            3
        }
        fn columns(&self) -> &[usize] {
            &self.cols
        }
        fn evaluate(&self, frame: EvalFrame) -> Block128 {
            frame.local[0] * frame.local[1] * frame.local[2]
        }
    }

    // -------- Degree-4 constraint: (col0)^2 · (col1)^2 == 0 --------

    struct Deg4SquareGate {
        cols: [usize; 2],
    }
    impl Constraint for Deg4SquareGate {
        fn degree(&self) -> usize {
            4
        }
        fn columns(&self) -> &[usize] {
            &self.cols
        }
        fn evaluate(&self, frame: EvalFrame) -> Block128 {
            let a = frame.local[0] * frame.local[0];
            let b = frame.local[1] * frame.local[1];
            a * b
        }
    }

    // -------- Helpers --------

    fn zero_col(log_rows: usize) -> Vec<Block128> {
        vec![Block128::ZERO; 1 << log_rows]
    }
    fn bool_col(log_rows: usize, seed: u64) -> Vec<Block128> {
        (0..(1usize << log_rows))
            .map(|i| {
                let bit = ((seed.wrapping_mul(2654435761).wrapping_add(i as u64)) >> 7) & 1;
                if bit == 0 {
                    Block128::ZERO
                } else {
                    Block128::ONE
                }
            })
            .collect()
    }

    // =====================================================================
    // Honest-prover tests, one per degree class
    // =====================================================================

    #[test]
    fn honest_linear_degree_1() {
        let air = LinearCombinationAir::new(3, 4);
        let n = 1 << 4;
        let col0: Vec<Block128> = (0..n).map(|i| Block128::from(i as u128 * 7 + 1)).collect();
        let col1: Vec<Block128> = (0..n).map(|i| Block128::from(i as u128 * 11 + 3)).collect();
        let col2: Vec<Block128> = col0.iter().zip(col1.iter()).map(|(a, b)| *a + *b).collect();
        let trace = Trace::new(vec![col0, col1, col2]);
        let pi = mk_pi();
        let proof = prove_air(&air, &trace, &pi).expect("prove");
        verify_air(&air, &pi, &proof).expect("verify");
    }

    #[test]
    fn honest_bool_degree_2() {
        // A real non-degenerate boolean witness for BoolGate (degree 2).
        let (air, trace) = mk_logic_air_and_trace();
        let pi = mk_pi();
        let proof = prove_air(&air, &trace, &pi).expect("prove");
        verify_air(&air, &pi, &proof).expect("verify");
    }

    #[test]
    fn honest_bool_all_random_degree_2() {
        // A random boolean witness — not all-zero — must verify.
        let log_rows = 4;
        let constraints: Vec<Box<dyn Constraint>> = vec![Box::new(BoolGate::new(0))];
        let air = CompositeAir::from_parts(log_rows, 1, constraints);
        let col = bool_col(log_rows, 0xdead_beef);
        let trace = Trace::new(vec![col]);
        let pi = mk_pi();
        let proof = prove_air(&air, &trace, &pi).expect("prove");
        verify_air(&air, &pi, &proof).expect("verify");
    }

    #[test]
    fn honest_cubic_degree_3() {
        // col0 · col1 · col2 == 0 when at least one column is all-zero on
        // the hypercube. Use col2 = 0 as the "indicator" column.
        let log_rows = 4;
        let constraints: Vec<Box<dyn Constraint>> =
            vec![Box::new(Deg3ProductGate { cols: [0, 1, 2] })];
        let air = CompositeAir::from_parts(log_rows, 3, constraints);
        let n = 1 << log_rows;
        let col0: Vec<Block128> = (0..n).map(|i| Block128::from(i as u128 * 13 + 5)).collect();
        let col1: Vec<Block128> = (0..n).map(|i| Block128::from(i as u128 * 17 + 9)).collect();
        let col2 = zero_col(log_rows);
        let trace = Trace::new(vec![col0, col1, col2]);
        let pi = mk_pi();
        let proof = prove_air(&air, &trace, &pi).expect("prove");
        verify_air(&air, &pi, &proof).expect("verify");
    }

    #[test]
    fn honest_quartic_degree_4() {
        // (col0)^2 · (col1)^2 == 0 when col0 is all-zero on the hypercube.
        let log_rows = 4;
        let constraints: Vec<Box<dyn Constraint>> = vec![Box::new(Deg4SquareGate { cols: [0, 1] })];
        let air = CompositeAir::from_parts(log_rows, 2, constraints);
        let col0 = zero_col(log_rows);
        let n = 1 << log_rows;
        let col1: Vec<Block128> = (0..n).map(|i| Block128::from(i as u128 * 23 + 1)).collect();
        let trace = Trace::new(vec![col0, col1]);
        let pi = mk_pi();
        let proof = prove_air(&air, &trace, &pi).expect("prove");
        verify_air(&air, &pi, &proof).expect("verify");
    }

    #[test]
    fn honest_mixed_degrees_composite() {
        // Composite AIR mixing degree-1 (XOR), degree-2 (Bool),
        // degree-3 (triple product with a zero column) in one proof.
        // Round-poly degree = max(1,2,3) + 1 = 4.
        let log_rows = 4;
        let constraints: Vec<Box<dyn Constraint>> = vec![
            Box::new(BoolGate::new(0)),
            Box::new(WeightedLinearGate::new_xor(vec![1, 2])),
            Box::new(Deg3ProductGate { cols: [3, 1, 2] }),
        ];
        // col0 boolean, col1 = col2 (satisfies XOR), col3 = 0 (satisfies triple product).
        let col0 = bool_col(log_rows, 0x1234);
        let n = 1 << log_rows;
        let col1: Vec<Block128> = (0..n).map(|i| Block128::from(i as u128 * 5 + 2)).collect();
        let col2 = col1.clone();
        let col3 = zero_col(log_rows);
        let air = CompositeAir::from_parts(log_rows, 4, constraints);
        let trace = Trace::new(vec![col0, col1, col2, col3]);
        let pi = mk_pi();
        let proof = prove_air(&air, &trace, &pi).expect("prove");
        verify_air(&air, &pi, &proof).expect("verify");
    }

    // =====================================================================
    // Cryptographic soundness: malicious-prover tests
    // =====================================================================

    #[test]
    fn malicious_non_bool_witness_rejected() {
        // The prover tries to prove BoolGate on a non-boolean witness,
        // bypassing the native pre-check. The zero-check sumcheck
        // MUST reject it — this is the exact bug that was broken before.
        let (air, mut trace) = mk_logic_air_and_trace();
        trace.columns[0][2] = Block128::from(3u128); // not 0 or 1
        let pi = mk_pi();
        let proof = prove_air_unchecked(&air, &trace, &pi);
        assert!(
            verify_air(&air, &pi, &proof).is_err(),
            "verifier must reject a non-boolean witness for BoolGate"
        );
    }

    /// γ₃b invariant A. When `extras == &[]`, the new
    /// `prove_air_unchecked_with_extra_columns` wrapper must produce a
    /// proof structurally identical to the legacy
    /// `prove_air_unchecked_with_extra` path — transcript draws,
    /// commitments, round polynomials, openings, and FRI paths all
    /// byte-identical. This test is the guardrail for every later
    /// change to the mixed-length close: if the wrapper ever diverges
    /// from the default path on empty extras, this test fails first.
    #[test]
    fn invariant_a_empty_extras_byte_identical() {
        let (air, trace) = mk_logic_air_and_trace();
        let pi = mk_pi();
        let proof_legacy = prove_air_unchecked_with_extra(&air, &trace, &pi, &[]);
        let proof_wrapped = prove_air_unchecked_with_extra_columns(&air, &trace, &pi, &[], &[]);
        assert_eq!(
            format!("{:?}", proof_legacy),
            format!("{:?}", proof_wrapped),
            "empty-extras wrapper must reduce to legacy path byte-for-byte"
        );
        // Also pin the verify side: the legacy verifier and the
        // wrapper verifier must both accept the wrapped-path proof.
        verify_air(&air, &pi, &proof_wrapped).expect("default verify must accept");
        verify_air_with_extra_columns(&air, &pi, &proof_wrapped, &[], &[])
            .expect("wrapper verify must accept on empty extras");
    }

    /// γ₃b invariant C. Canonicalization is a pure function of its
    /// input; caller order must never matter.
    /// γ₃b invariant B. When every extra shares the base's
    /// `log_len`, the mixed-length close must accept: the mixed
    /// sumcheck collapses to `n_max = log_len` (no high rounds),
    /// `s_base_scalar = s_extra_scalar = 1`, and the reconstruction
    /// formula degenerates to the uniform one. This test commits to
    /// an external MLE at the same `log_len` as the base trace, runs
    /// the mixed path honestly, and verifies.
    #[test]
    fn invariant_b_single_log_len_mixed_roundtrip() {
        use noid_fri::hasher::Blake3Hasher;
        use noid_fri::prover::commit as fri_commit;

        let (air, trace) = mk_logic_air_and_trace();
        let pi = mk_pi();
        let log_rows = trace.log_rows;
        let log_len = padded_log_len(log_rows);

        // Build a deterministic MLE at the base log_len and commit.
        let extra_evals: Vec<Block128> = (0..1u128 << log_len)
            .map(|i| Block128::from(i.wrapping_mul(0x9E3779B97F4A7C15)))
            .collect();
        let ntt = AdditiveNTT::<Block128>::new(log_len + noid_fri::code::LOG_RATE);
        let hasher = Blake3Hasher::new();
        let (commitment, _tree, _code) = fri_commit(&extra_evals, &ntt, &hasher);

        // Pick an arbitrary eval_point and compute the true value so
        // the extras claim is honest.
        let eval_point: Vec<Block128> = (0..log_len)
            .map(|i| Block128::from(0xC0FFEE01u128 + i as u128))
            .collect();
        let value = noid_core::mle::evaluate::evaluate_slice(&extra_evals, &eval_point);

        let extras = vec![ExtraColumn {
            evals: extra_evals,
            commitment,
            eval_point,
            value,
        }];

        let proof = prove_air_unchecked_with_extra_columns(&air, &trace, &pi, &[], &extras);
        assert!(
            proof.multipoint_batch_mixed.is_some(),
            "non-empty extras must land in the mixed path"
        );
        verify_air_with_extra_columns(&air, &pi, &proof, &[], &extras)
            .expect("invariant B: uniform-log_len mixed close must verify");
    }

    #[test]
    fn invariant_c_extras_canonicalization_is_order_insensitive() {
        // Build two fake extras with deterministic distinct
        // commitment roots and eval points, then shuffle.
        fn mk_extra(seed: u8, log_len: usize) -> ExtraColumn {
            let evals = vec![Block128::from(seed as u128); 1 << log_len];
            let mut root = [0u8; 32];
            for (i, b) in root.iter_mut().enumerate() {
                *b = seed.wrapping_add(i as u8);
            }
            let commitment = FriCommitment {
                vector_commitment: noid_fri::merkle::VectorCommitment {
                    root,
                    depth: log_len + 1,
                },
                packing_factor: 1,
                log_len,
            };
            let eval_point: Vec<Block128> = (0..log_len)
                .map(|i| Block128::from((seed as u128) + i as u128))
                .collect();
            ExtraColumn {
                evals,
                commitment,
                eval_point,
                value: Block128::from(seed as u128),
            }
        }
        let e1 = mk_extra(1, 4);
        let e2 = mk_extra(2, 4);
        let e3 = mk_extra(3, 5);
        let a = canonicalize_extras(&[e1.clone(), e2.clone(), e3.clone()]);
        let b = canonicalize_extras(&[e3.clone(), e1.clone(), e2.clone()]);
        let c = canonicalize_extras(&[e2.clone(), e3.clone(), e1.clone()]);
        assert_eq!(format!("{:?}", a), format!("{:?}", b));
        assert_eq!(format!("{:?}", a), format!("{:?}", c));
        // And the canonical order is ascending log_len (so e3 last
        // among these; e1/e2 ordered by root bytes ⇒ e1 then e2).
        assert_eq!(a[0].commitment.vector_commitment.root[0], 1);
        assert_eq!(a[1].commitment.vector_commitment.root[0], 2);
        assert_eq!(a[2].commitment.log_len, 5);
    }

    #[test]
    fn malicious_non_bool_random_rejected() {
        // Same idea, but the whole column is random (non-boolean).
        let log_rows = 4;
        let constraints: Vec<Box<dyn Constraint>> = vec![Box::new(BoolGate::new(0))];
        let air = CompositeAir::from_parts(log_rows, 1, constraints);
        let n = 1 << log_rows;
        let bad_col: Vec<Block128> = (0..n).map(|i| Block128::from(i as u128 * 7 + 3)).collect();
        let trace = Trace::new(vec![bad_col]);
        let pi = mk_pi();
        let proof = prove_air_unchecked(&air, &trace, &pi);
        assert!(verify_air(&air, &pi, &proof).is_err());
    }

    #[test]
    fn malicious_linear_imbalance_rejected() {
        // WeightedLinearGate (XOR variant): Σ col_i != 0 somewhere on the hypercube.
        let air = LinearCombinationAir::new(2, 4);
        let n = 1 << 4;
        let col0: Vec<Block128> = (0..n).map(|i| Block128::from(i as u128 + 1)).collect();
        // col1 is NOT col0, so col0 + col1 != 0 almost everywhere.
        let col1: Vec<Block128> = (0..n).map(|i| Block128::from(i as u128 * 2 + 5)).collect();
        let trace = Trace::new(vec![col0, col1]);
        let pi = mk_pi();
        let proof = prove_air_unchecked(&air, &trace, &pi);
        assert!(verify_air(&air, &pi, &proof).is_err());
    }

    #[test]
    fn malicious_cubic_violation_rejected() {
        // Degree-3 constraint violated on the hypercube.
        let log_rows = 4;
        let constraints: Vec<Box<dyn Constraint>> =
            vec![Box::new(Deg3ProductGate { cols: [0, 1, 2] })];
        let air = CompositeAir::from_parts(log_rows, 3, constraints);
        let n = 1 << log_rows;
        let col0: Vec<Block128> = (0..n).map(|i| Block128::from(i as u128 + 1)).collect();
        let col1: Vec<Block128> = (0..n).map(|i| Block128::from(i as u128 + 2)).collect();
        let col2: Vec<Block128> = (0..n).map(|i| Block128::from(i as u128 + 3)).collect();
        let trace = Trace::new(vec![col0, col1, col2]);
        let pi = mk_pi();
        let proof = prove_air_unchecked(&air, &trace, &pi);
        assert!(verify_air(&air, &pi, &proof).is_err());
    }

    #[test]
    fn malicious_quartic_violation_rejected() {
        let log_rows = 4;
        let constraints: Vec<Box<dyn Constraint>> = vec![Box::new(Deg4SquareGate { cols: [0, 1] })];
        let air = CompositeAir::from_parts(log_rows, 2, constraints);
        let n = 1 << log_rows;
        let col0: Vec<Block128> = (0..n).map(|i| Block128::from(i as u128 + 1)).collect();
        let col1: Vec<Block128> = (0..n).map(|i| Block128::from(i as u128 + 2)).collect();
        let trace = Trace::new(vec![col0, col1]);
        let pi = mk_pi();
        let proof = prove_air_unchecked(&air, &trace, &pi);
        assert!(verify_air(&air, &pi, &proof).is_err());
    }

    #[test]
    fn malicious_one_row_violation_rejected() {
        // Even a *single* row violation must be caught — this is the
        // whole point of zero-check (it commits to every row via eq).
        let log_rows = 4;
        let constraints: Vec<Box<dyn Constraint>> = vec![Box::new(BoolGate::new(0))];
        let air = CompositeAir::from_parts(log_rows, 1, constraints);
        let mut col = vec![Block128::ZERO; 1 << log_rows];
        col[5] = Block128::from(2u128); // one bad row among zeros
        let trace = Trace::new(vec![col]);
        let pi = mk_pi();
        let proof = prove_air_unchecked(&air, &trace, &pi);
        assert!(verify_air(&air, &pi, &proof).is_err());
    }

    // =====================================================================
    // Tamper / shape tests
    // =====================================================================

    #[test]
    fn tampered_opening_rejected() {
        let (air, trace) = mk_logic_air_and_trace();
        let pi = mk_pi();
        let mut proof = prove_air(&air, &trace, &pi).expect("prove");
        proof.base_openings[0] += Block128::ONE;
        assert!(verify_air(&air, &pi, &proof).is_err());
    }

    #[test]
    fn tampered_round_poly_rejected() {
        let (air, trace) = mk_logic_air_and_trace();
        let pi = mk_pi();
        let mut proof = prove_air(&air, &trace, &pi).expect("prove");
        proof.zero_check_rounds[0][0] += Block128::ONE;
        assert!(verify_air(&air, &pi, &proof).is_err());
    }

    #[test]
    fn wrong_pi_rejected() {
        let (air, trace) = mk_logic_air_and_trace();
        let pi = mk_pi();
        let proof = prove_air(&air, &trace, &pi).expect("prove");
        let mut bad = pi;
        bad.fee = pi.fee + 1;
        assert!(verify_air(&air, &bad, &proof).is_err());
    }

    #[test]
    fn bad_trace_rejected_in_native_check() {
        let (air, mut trace) = mk_logic_air_and_trace();
        trace.columns[0][0] = Block128::from(5u128);
        assert!(prove_air(&air, &trace, &mk_pi()).is_err());
    }

    #[test]
    fn round_poly_shape_matches_air_degree() {
        // Sanity: round polys in the proof must have length
        // `max_constraint_degree + 2`, independent of AIR.
        for (air_deg, air) in [
            (1usize, {
                let c: Vec<Box<dyn Constraint>> =
                    vec![Box::new(WeightedLinearGate::new_xor(vec![0, 1]))];
                CompositeAir::from_parts(4, 2, c)
            }),
            (2usize, {
                let c: Vec<Box<dyn Constraint>> = vec![Box::new(BoolGate::new(0))];
                CompositeAir::from_parts(4, 1, c)
            }),
            (3usize, {
                let c: Vec<Box<dyn Constraint>> =
                    vec![Box::new(Deg3ProductGate { cols: [0, 1, 2] })];
                CompositeAir::from_parts(4, 3, c)
            }),
            (4usize, {
                let c: Vec<Box<dyn Constraint>> = vec![Box::new(Deg4SquareGate { cols: [0, 1] })];
                CompositeAir::from_parts(4, 2, c)
            }),
        ] {
            let n_cols = air.n_columns();
            let cols: Vec<Vec<Block128>> = (0..n_cols).map(|_| zero_col(4)).collect();
            let trace = Trace::new(cols);
            let pi = mk_pi();
            let proof = prove_air(&air, &trace, &pi).expect("prove");
            let expected_len = air_deg + 2;
            for rp in &proof.zero_check_rounds {
                assert_eq!(
                    rp.len(),
                    expected_len,
                    "round poly must carry deg+2 evaluations for air_deg={air_deg}"
                );
            }
            verify_air(&air, &pi, &proof).expect("verify");
        }
    }

    // =====================================================================
    // Unit tests for internal helpers (Lagrange / degree)
    // =====================================================================

    #[test]
    fn lagrange_eval_interpolates_known_polynomial() {
        // Build p(X) = 3 + 5X + 7X^2 + 11X^3 (coeffs in Block128).
        let a = [
            Block128::from(3u8),
            Block128::from(5u8),
            Block128::from(7u8),
            Block128::from(11u8),
        ];
        let pt = |x: Block128| a[0] + x * (a[1] + x * (a[2] + x * a[3]));
        let evals: Vec<Block128> = (0..4).map(|i| pt(Block128::from(i as u8))).collect();
        for target_i in 0..8u8 {
            let target = Block128::from(target_i);
            assert_eq!(lagrange_eval_at(&evals, target), pt(target));
        }
        // At a random-looking field point too.
        let target = Block128::from(0xabcdef0123456789u128);
        assert_eq!(lagrange_eval_at(&evals, target), pt(target));
    }

    #[test]
    fn lagrange_eval_degree_1_and_5() {
        // Degree 1.
        let p1 = |x: Block128| Block128::from(2u8) + x * Block128::from(3u8);
        let e1: Vec<Block128> = (0..2).map(|i| p1(Block128::from(i as u8))).collect();
        assert_eq!(
            lagrange_eval_at(&e1, Block128::from(7u8)),
            p1(Block128::from(7u8))
        );
        // Degree 5.
        let a = [
            Block128::from(1u8),
            Block128::from(2u8),
            Block128::from(3u8),
            Block128::from(5u8),
            Block128::from(8u8),
            Block128::from(13u8),
        ];
        let p5 = |x: Block128| a[0] + x * (a[1] + x * (a[2] + x * (a[3] + x * (a[4] + x * a[5]))));
        let e5: Vec<Block128> = (0..6).map(|i| p5(Block128::from(i as u8))).collect();
        for target_i in 0..12u8 {
            let t = Block128::from(target_i);
            assert_eq!(lagrange_eval_at(&e5, t), p5(t));
        }
    }

    #[test]
    fn lagrange_eval_cached_matches_reference() {
        // Verify that lagrange_eval_at_cached produces identical results to
        // the reference lagrange_eval_at for all degrees d in 2..=8 and a
        // range of target points, confirming the OnceLock denominator cache
        // is correct.
        let a8 = [
            Block128::from(3u8),
            Block128::from(5u8),
            Block128::from(7u8),
            Block128::from(11u8),
            Block128::from(13u8),
            Block128::from(17u8),
            Block128::from(19u8),
            Block128::from(23u8),
        ];
        for d_plus_one in 2usize..=8 {
            let evals: Vec<Block128> = a8[..d_plus_one].to_vec();
            let targets: Vec<Block128> = (0..16u8)
                .map(Block128::from)
                .chain([
                    Block128::from(0xabcdef01_23456789u128),
                    Block128::from(0xdeadbeef_cafebabeu128),
                ])
                .collect();
            for target in targets {
                assert_eq!(
                    lagrange_eval_at(&evals, target),
                    lagrange_eval_at_cached(&evals, target),
                    "mismatch at d_plus_one={d_plus_one} target={target:?}"
                );
            }
        }
    }

    #[test]
    fn lagrange_eval_cached_is_idempotent_across_calls() {
        // Second call with same d_plus_one must hit the cache and return same result.
        let evals: Vec<Block128> = (0..4).map(|i| Block128::from(i as u8 + 1)).collect();
        let target = Block128::from(99u8);
        let r1 = lagrange_eval_at_cached(&evals, target);
        let r2 = lagrange_eval_at_cached(&evals, target);
        assert_eq!(r1, r2);
    }

    #[test]
    fn round_poly_degree_matches_max_constraint() {
        let c1: Vec<Box<dyn Constraint>> = vec![Box::new(WeightedLinearGate::new_xor(vec![0, 1]))];
        let air1 = CompositeAir::from_parts(4, 2, c1);
        assert_eq!(round_poly_degree(&air1), 2); // 1 + 1

        let c2: Vec<Box<dyn Constraint>> = vec![Box::new(BoolGate::new(0))];
        let air2 = CompositeAir::from_parts(4, 1, c2);
        assert_eq!(round_poly_degree(&air2), 3); // 2 + 1

        let c3: Vec<Box<dyn Constraint>> = vec![
            Box::new(BoolGate::new(0)),
            Box::new(Deg3ProductGate { cols: [0, 1, 2] }),
            Box::new(Deg4SquareGate { cols: [0, 1] }),
        ];
        let air3 = CompositeAir::from_parts(4, 3, c3);
        assert_eq!(round_poly_degree(&air3), 5); // max(2,3,4) + 1
    }

    #[test]
    fn no_degree_skipping_anywhere() {
        // Defensive: make sure the verifier never silently accepts a
        // degree > 1 constraint just because it "doesn't run sumcheck on
        // it". If a quadratic gate is present, the proof must carry
        // round polys of length >= 4, and the verifier must enforce
        // that. We assert the shape requirement here too.
        let c: Vec<Box<dyn Constraint>> = vec![Box::new(BoolGate::new(0))];
        let air = CompositeAir::from_parts(4, 1, c);
        let trace = Trace::new(vec![zero_col(4)]);
        let pi = mk_pi();
        let mut proof = prove_air(&air, &trace, &pi).expect("prove");
        // Shape-check: round polys must carry deg+2 = 4 evals.
        assert!(proof.zero_check_rounds.iter().all(|r| r.len() == 4));
        // Shrink a round poly — verifier must complain about shape, not
        // silently ignore the higher-degree term.
        proof.zero_check_rounds[0].pop();
        assert!(matches!(
            verify_air(&air, &pi, &proof),
            Err(VerifyError::ShapeMismatch)
        ));
    }

    // =====================================================================
    // VSHIFT (cross-row rotation) — Stage 3b-0.2b integration tests
    // =====================================================================

    /// `local[0] + next[0] == 0` — forces the column to be constant
    /// along the cyclic hypercube. Degree-1 in the base column and the
    /// (virtual) rotated column; exercises the full VSHIFT ladder plumbing.
    struct NextEqualsLocalGate {
        cols: [usize; 1],
    }
    impl Constraint for NextEqualsLocalGate {
        fn degree(&self) -> usize {
            1
        }
        fn columns(&self) -> &[usize] {
            &self.cols
        }
        fn shifted_columns(&self) -> &[usize] {
            &self.cols
        }
        fn evaluate(&self, frame: EvalFrame) -> Block128 {
            frame.local[0] + frame.next[0]
        }
    }

    #[test]
    fn vshift_honest_constant_column_accepts() {
        // VSHIFT requires log_rows >= TAU+1 so cyclic rotation on the
        // committed MLE coincides with cyclic rotation on the witness.
        let log_rows = 8;
        let constraints: Vec<Box<dyn Constraint>> =
            vec![Box::new(NextEqualsLocalGate { cols: [0] })];
        let air = CompositeAir::from_parts(log_rows, 1, constraints);
        // Constant column satisfies `local + next == 0` on every row.
        let col = vec![Block128::from(0xA5u128); 1 << log_rows];
        let trace = Trace::new(vec![col]);
        let pi = mk_pi();
        let proof = prove_air(&air, &trace, &pi).expect("prove");
        assert_eq!(proof.shift_partials.len(), 1);
        assert_eq!(proof.shift_partials[0].len(), padded_log_len(log_rows) + 1);
        verify_air(&air, &pi, &proof).expect("verify");
    }

    #[test]
    fn vshift_malicious_nonconstant_column_rejected() {
        // A non-constant column breaks `local + next == 0` on every
        // non-wrap row. VSHIFT-extended sumcheck must reject.
        let log_rows = 8;
        let constraints: Vec<Box<dyn Constraint>> =
            vec![Box::new(NextEqualsLocalGate { cols: [0] })];
        let air = CompositeAir::from_parts(log_rows, 1, constraints);
        let n = 1 << log_rows;
        let col: Vec<Block128> = (0..n).map(|i| Block128::from(i as u128 + 1)).collect();
        let trace = Trace::new(vec![col]);
        let pi = mk_pi();
        let proof = prove_air_unchecked(&air, &trace, &pi);
        assert!(verify_air(&air, &pi, &proof).is_err());
    }

    #[test]
    fn vshift_tampered_ladder_partial_rejected() {
        // A malicious prover flips one ladder partial. The reconstructed
        // `C'(r)` is then inconsistent with the committed column — the
        // extra FRI opening of the base column at that ladder point
        // must fail.
        let log_rows = 8;
        let constraints: Vec<Box<dyn Constraint>> =
            vec![Box::new(NextEqualsLocalGate { cols: [0] })];
        let air = CompositeAir::from_parts(log_rows, 1, constraints);
        let col = vec![Block128::from(0x42u128); 1 << log_rows];
        let trace = Trace::new(vec![col]);
        let pi = mk_pi();
        let mut proof = prove_air(&air, &trace, &pi).expect("prove");
        // Tamper with one ladder scalar.
        proof.shift_partials[0][2] += Block128::ONE;
        assert!(verify_air(&air, &pi, &proof).is_err());
    }

    #[test]
    fn vshift_tampered_multipoint_round_rejected() {
        // Stage 3b-0.6: flipping a byte inside the §12c' multipoint
        // sumcheck transcript must diverge the channel → final FRI fails.
        let log_rows = 8;
        let constraints: Vec<Box<dyn Constraint>> =
            vec![Box::new(NextEqualsLocalGate { cols: [0] })];
        let air = CompositeAir::from_parts(log_rows, 1, constraints);
        let col = vec![Block128::from(0x42u128); 1 << log_rows];
        let trace = Trace::new(vec![col]);
        let pi = mk_pi();
        let mut proof = prove_air(&air, &trace, &pi).expect("prove");
        proof.multipoint_rounds[1][2] += Block128::ONE;
        assert!(verify_air(&air, &pi, &proof).is_err());
    }

    #[test]
    fn vshift_shape_mismatch_rejected() {
        // Stripping a ladder partial must be caught by the shape check.
        let log_rows = 8;
        let constraints: Vec<Box<dyn Constraint>> =
            vec![Box::new(NextEqualsLocalGate { cols: [0] })];
        let air = CompositeAir::from_parts(log_rows, 1, constraints);
        let col = vec![Block128::from(0x01u128); 1 << log_rows];
        let trace = Trace::new(vec![col]);
        let pi = mk_pi();
        let mut proof = prove_air(&air, &trace, &pi).expect("prove");
        proof.shift_partials[0].pop();
        assert!(matches!(
            verify_air(&air, &pi, &proof),
            Err(VerifyError::ShapeMismatch)
        ));
    }

    #[test]
    fn vshift_multi_column_batching() {
        // Two independent shifted columns — exercises slot indexing.
        let log_rows = 8;
        let constraints: Vec<Box<dyn Constraint>> = vec![
            Box::new(NextEqualsLocalGate { cols: [0] }),
            Box::new(NextEqualsLocalGate { cols: [1] }),
        ];
        let air = CompositeAir::from_parts(log_rows, 2, constraints);
        assert_eq!(air.shifted_column_indices(), vec![0, 1]);
        let col0 = vec![Block128::from(0x11u128); 1 << log_rows];
        let col1 = vec![Block128::from(0x22u128); 1 << log_rows];
        let trace = Trace::new(vec![col0, col1]);
        let pi = mk_pi();
        let proof = prove_air(&air, &trace, &pi).expect("prove");
        assert_eq!(proof.shift_partials.len(), 2);
        verify_air(&air, &pi, &proof).expect("verify");
    }

    // =====================================================================
    // CarryRippleAir — Stage 3b-0.3 integration tests
    // =====================================================================

    use noid_air::{
        CarryRippleAir, CARRY_RIPPLE_COL_CARRY, CARRY_RIPPLE_COL_IS_RESET, CARRY_RIPPLE_COL_SUM,
    };

    fn splitmix(seed: &mut u64) -> u64 {
        *seed = seed.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = *seed;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    }

    fn random_adders(n: usize, mut seed: u64) -> Vec<(u64, u64)> {
        (0..n)
            .map(|_| {
                let a = splitmix(&mut seed);
                let b = splitmix(&mut seed);
                (a, b)
            })
            .collect()
    }

    #[test]
    fn carry_ripple_honest_addition_accepts() {
        for log_rows in [8usize, 10, 12] {
            let air = CarryRippleAir::new(log_rows);
            let adders = random_adders(air.n_instances(), 0xA5A5_0000 ^ log_rows as u64);
            let trace = air.build_trace(&adders);
            assert!(air.check(&trace), "native check at log_rows={log_rows}");
            let pi = mk_pi();
            let proof = prove_air(&air, &trace, &pi).expect("prove");
            verify_air(&air, &pi, &proof).expect("verify");
        }
    }

    #[test]
    fn carry_ripple_sum_bit_flip_rejected() {
        let log_rows = 8;
        let air = CarryRippleAir::new(log_rows);
        let adders = random_adders(air.n_instances(), 0xC0FFEE);
        let mut trace = air.build_trace(&adders);
        trace.columns[CARRY_RIPPLE_COL_SUM][5] += Block128::ONE;
        let pi = mk_pi();
        let proof = prove_air_unchecked(&air, &trace, &pi);
        assert!(verify_air(&air, &pi, &proof).is_err());
    }

    #[test]
    fn carry_ripple_carry_bit_flip_rejected() {
        let log_rows = 8;
        let air = CarryRippleAir::new(log_rows);
        let adders = random_adders(air.n_instances(), 0xDEAD_BEEF);
        let mut trace = air.build_trace(&adders);
        // Flip a carry bit somewhere mid-instance (not on a reset row).
        trace.columns[CARRY_RIPPLE_COL_CARRY][10] += Block128::ONE;
        let pi = mk_pi();
        let proof = prove_air_unchecked(&air, &trace, &pi);
        assert!(verify_air(&air, &pi, &proof).is_err());
    }

    #[test]
    fn carry_ripple_fake_init_carry_rejected() {
        let log_rows = 8;
        let air = CarryRippleAir::new(log_rows);
        let adders = random_adders(air.n_instances(), 0x1234_5678);
        let mut trace = air.build_trace(&adders);
        // Row 0 is a reset row: forcing carry[0] = 1 must violate
        // `is_reset · carry == 0`. We also fix up the row-0 local
        // relations so only the init gate is unhappy: set carry[0]=1,
        // recompute sum[0] to keep xor_sum satisfied.
        trace.columns[CARRY_RIPPLE_COL_CARRY][0] = Block128::ONE;
        trace.columns[CARRY_RIPPLE_COL_SUM][0] += Block128::ONE;
        let pi = mk_pi();
        let proof = prove_air_unchecked(&air, &trace, &pi);
        assert!(verify_air(&air, &pi, &proof).is_err());
    }

    #[test]
    fn carry_ripple_wraparound_suppressed() {
        // Honest proof where every instance's carry-out at bit `w-1` is
        // nonzero (forcing an overflow). The cyclic wrap from the last
        // row back to row 0 would — absent the `(1 + is_reset_next)`
        // selector — demand `carry[0] == carry_out(last_inst)`. The
        // selector suppresses it; verifier must accept.
        let log_rows = 8;
        let air = CarryRippleAir::new(log_rows);
        // u64::MAX + 1 overflows: carry-out = 1 each instance.
        let adders: Vec<(u64, u64)> = (0..air.n_instances()).map(|_| (u64::MAX, 1u64)).collect();
        let trace = air.build_trace(&adders);
        // Sanity: the last instance's carry on the last row must be 1
        // (propagated all the way), so the wrap from row N-1 -> row 0
        // would fire carry_next without suppression.
        let last_row = (1usize << log_rows) - 1;
        // With operands (0xFFFF…, 1), bit i of `a` is 1 for all i,
        // bit 0 of `b` is 1. Ripple: carry_in[0]=0, sum[0]=0, carry[1]=1,
        // and carry[k]=1 for all k>=1. So last_row carry = 1.
        assert_eq!(
            trace.columns[CARRY_RIPPLE_COL_CARRY][last_row],
            Block128::ONE
        );
        assert_eq!(trace.columns[CARRY_RIPPLE_COL_IS_RESET][0], Block128::ONE);
        assert!(air.check(&trace));
        let pi = mk_pi();
        let proof = prove_air(&air, &trace, &pi).expect("prove");
        verify_air(&air, &pi, &proof).expect("verify");
    }

    #[test]
    fn carry_ripple_ladder_tampering_rejected() {
        let log_rows = 8;
        let air = CarryRippleAir::new(log_rows);
        let adders = random_adders(air.n_instances(), 0xBADC_0FFE);
        let trace = air.build_trace(&adders);
        let pi = mk_pi();
        let mut proof = prove_air(&air, &trace, &pi).expect("prove");
        // Slot 0 holds the ladder for the carry column (col 3 — lowest
        // index in `shifted_column_indices`). Flipping one partial
        // breaks the FRI opening at the corresponding ladder point.
        proof.shift_partials[0][3] += Block128::ONE;
        assert!(verify_air(&air, &pi, &proof).is_err());
    }

    // =====================================================================
    // RangeGateAir — Stage 3b-2 integration tests
    // =====================================================================

    use noid_air::{
        RangeGateAir, RANGE_GATE_COL_ACC, RANGE_GATE_COL_BIT, RANGE_GATE_COL_IS_RESET,
        RANGE_GATE_COL_WEIGHT, RANGE_GATE_WORD_BITS,
    };

    fn random_u64s(n: usize, mut seed: u64) -> Vec<u64> {
        (0..n).map(|_| splitmix(&mut seed)).collect()
    }

    #[test]
    fn range_gate_honest_values_accepted() {
        for log_rows in [8usize, 10, 12] {
            let air = RangeGateAir::new(log_rows);
            let values = random_u64s(
                air.n_instances(),
                0x4A06_0000u64.wrapping_add(log_rows as u64),
            );
            let trace = air.build_trace(&values);
            assert!(air.check(&trace), "native check at log_rows={log_rows}");
            let pi = mk_pi();
            let proof = prove_air(&air, &trace, &pi).expect("prove");
            verify_air(&air, &pi, &proof).expect("verify");
        }
    }

    #[test]
    fn range_gate_bit_flip_rejected() {
        let log_rows = 8;
        let air = RangeGateAir::new(log_rows);
        let values = random_u64s(air.n_instances(), 0x00C0_FFEE_BEEF);
        let mut trace = air.build_trace(&values);
        // Flip one bit without fixing up the accumulator column —
        // acc_recurrence must fire on the transition into the next row.
        trace.columns[RANGE_GATE_COL_BIT][5] += Block128::ONE;
        let pi = mk_pi();
        let proof = prove_air_unchecked(&air, &trace, &pi);
        assert!(verify_air(&air, &pi, &proof).is_err());
    }

    #[test]
    fn range_gate_non_bit_rejected() {
        let log_rows = 8;
        let air = RangeGateAir::new(log_rows);
        let values = random_u64s(air.n_instances(), 0xDEAD_F00D);
        let mut trace = air.build_trace(&values);
        // Non-bit value in the `bit` column — caught by BoolGate.
        trace.columns[RANGE_GATE_COL_BIT][3] = Block128::from(5u128);
        let pi = mk_pi();
        let proof = prove_air_unchecked(&air, &trace, &pi);
        assert!(verify_air(&air, &pi, &proof).is_err());
    }

    #[test]
    fn range_gate_acc_tampering_rejected() {
        let log_rows = 8;
        let air = RangeGateAir::new(log_rows);
        let values = random_u64s(air.n_instances(), 0x1234_5678);
        let mut trace = air.build_trace(&values);
        trace.columns[RANGE_GATE_COL_ACC][7] += Block128::from(0xA5u128);
        let pi = mk_pi();
        let proof = prove_air_unchecked(&air, &trace, &pi);
        assert!(verify_air(&air, &pi, &proof).is_err());
    }

    #[test]
    fn range_gate_weight_tampering_rejected() {
        let log_rows = 8;
        let air = RangeGateAir::new(log_rows);
        let values = random_u64s(air.n_instances(), 0xFEED_FACE);
        let mut trace = air.build_trace(&values);
        // Mutate weight at a non-reset row; weight_recurrence fires on
        // the transition that produced it.
        trace.columns[RANGE_GATE_COL_WEIGHT][9] += Block128::ONE;
        let pi = mk_pi();
        let proof = prove_air_unchecked(&air, &trace, &pi);
        assert!(verify_air(&air, &pi, &proof).is_err());
    }

    #[test]
    fn range_gate_missing_reset_rejected() {
        let log_rows = 8;
        let air = RangeGateAir::new(log_rows);
        let values = random_u64s(air.n_instances(), 0xBABE_CAFE);
        let mut trace = air.build_trace(&values);
        // Clear the reset marker at the start of instance 1 — weight
        // reinitialisation no longer fires, so weight_recurrence breaks.
        trace.columns[RANGE_GATE_COL_IS_RESET][RANGE_GATE_WORD_BITS] = Block128::ZERO;
        let pi = mk_pi();
        let proof = prove_air_unchecked(&air, &trace, &pi);
        assert!(verify_air(&air, &pi, &proof).is_err());
    }

    #[test]
    fn range_gate_accumulator_matches_referential_recurrence() {
        // Sanity check on the trace builder. NOTE: `Block128` is GF(2^128)
        // in tower basis, so the `weight_{i+1} = weight_i · 2` ladder
        // produces tower-field powers, not integer `1 << i`. `acc` at the
        // final row of an instance is therefore `Σ bit_i · tower_pow(2, i)`
        // — a faithful linear encoding of the bit vector, not the integer
        // embedding of `x`. Integer-embedding is deferred to §3b-4 via a
        // `ConstColumnGate` pinning `weight[i] = Block128::from(1u128 << i)`.
        let log_rows = 8;
        let air = RangeGateAir::new(log_rows);
        let values = random_u64s(air.n_instances(), 0x7777_7777);
        let trace = air.build_trace(&values);
        let two = Block128::from(2u128);
        for (inst, &x) in values.iter().enumerate() {
            let mut expected = Block128::ZERO;
            let mut weight = Block128::ONE;
            for i in 0..RANGE_GATE_WORD_BITS {
                if (x >> i) & 1 == 1 {
                    expected += weight;
                }
                weight *= two;
            }
            let last = inst * RANGE_GATE_WORD_BITS + RANGE_GATE_WORD_BITS - 1;
            assert_eq!(
                trace.columns[RANGE_GATE_COL_ACC][last], expected,
                "acc mismatch at instance {inst}"
            );
        }
    }

    // =====================================================================
    // BitAdderAir — Stage 3b-3a integration tests
    // =====================================================================

    use noid_air::{
        BitAdderAir, BIT_ADDER_COL_A, BIT_ADDER_COL_CARRY, BIT_ADDER_COL_IS_INPUT,
        BIT_ADDER_COL_SUM,
    };

    fn random_bit_adder_pairs(n: usize, width: usize, mut seed: u64) -> Vec<(u128, u128)> {
        let mask: u128 = if width == 128 {
            u128::MAX
        } else {
            (1u128 << width) - 1
        };
        (0..n)
            .map(|_| {
                let a_lo = splitmix(&mut seed) as u128;
                let a_hi = splitmix(&mut seed) as u128;
                let b_lo = splitmix(&mut seed) as u128;
                let b_hi = splitmix(&mut seed) as u128;
                let a = ((a_hi << 64) | a_lo) & mask;
                let b = ((b_hi << 64) | b_lo) & mask;
                (a, b)
            })
            .collect()
    }

    #[test]
    fn bit_adder_stark_honest_widths_accepted() {
        // log_rows=8 gives 2 instances of a 128-row word; exercises each
        // targeted width for balance-tree use.
        for &width in &[64usize, 65, 66, 67] {
            let air = BitAdderAir::new(width, 8);
            let pairs =
                random_bit_adder_pairs(air.n_instances(), width, 0xBADA_55E5 ^ width as u64);
            let trace = air.build_trace(&pairs);
            assert!(air.check(&trace), "native check at width={width}");
            let pi = mk_pi();
            let proof = prove_air(&air, &trace, &pi).expect("prove");
            verify_air(&air, &pi, &proof).expect("verify");
        }
    }

    #[test]
    fn bit_adder_stark_sum_bit_flip_rejected() {
        let air = BitAdderAir::new(65, 8);
        let pairs = random_bit_adder_pairs(air.n_instances(), 65, 0xC0FF_EE01);
        let mut trace = air.build_trace(&pairs);
        trace.columns[BIT_ADDER_COL_SUM][5] += Block128::ONE;
        let pi = mk_pi();
        let proof = prove_air_unchecked(&air, &trace, &pi);
        assert!(verify_air(&air, &pi, &proof).is_err());
    }

    #[test]
    fn bit_adder_stark_final_carry_flip_rejected() {
        let air = BitAdderAir::new(67, 8);
        let pairs = random_bit_adder_pairs(air.n_instances(), 67, 0xC0FF_EE02);
        let mut trace = air.build_trace(&pairs);
        // Final carry-out of instance 0 lives at row `width` = 67.
        trace.columns[BIT_ADDER_COL_CARRY][67] += Block128::ONE;
        let pi = mk_pi();
        let proof = prove_air_unchecked(&air, &trace, &pi);
        assert!(verify_air(&air, &pi, &proof).is_err());
    }

    #[test]
    fn bit_adder_stark_mid_chain_carry_flip_rejected() {
        let air = BitAdderAir::new(66, 8);
        let pairs = random_bit_adder_pairs(air.n_instances(), 66, 0xC0FF_EE03);
        let mut trace = air.build_trace(&pairs);
        trace.columns[BIT_ADDER_COL_CARRY][10] += Block128::ONE;
        let pi = mk_pi();
        let proof = prove_air_unchecked(&air, &trace, &pi);
        assert!(verify_air(&air, &pi, &proof).is_err());
    }

    #[test]
    fn bit_adder_stark_pad_tamper_rejected() {
        let air = BitAdderAir::new(64, 8);
        let pairs = random_bit_adder_pairs(air.n_instances(), 64, 0xC0FF_EE04);
        let mut trace = air.build_trace(&pairs);
        // Write `a = 1` into a padding row (past the active region).
        trace.columns[BIT_ADDER_COL_A][70] = Block128::ONE;
        let pi = mk_pi();
        let proof = prove_air_unchecked(&air, &trace, &pi);
        assert!(verify_air(&air, &pi, &proof).is_err());
    }

    #[test]
    fn bit_adder_stark_is_input_tamper_rejected() {
        let air = BitAdderAir::new(64, 8);
        let pairs = random_bit_adder_pairs(air.n_instances(), 64, 0xC0FF_EE05);
        let mut trace = air.build_trace(&pairs);
        // Turn off the is_input selector on an active row — the FA-sum
        // gate folds to 0, but this row must keep `sum = a + b + c`,
        // which still holds in the honest trace. The catch comes
        // through the carry-next rule: turning `is_input` off at row 0
        // silences the carry recurrence, but at row 1 `is_reset · carry
        // = 0` still forces carry[1] = 0 via the carry-transition from
        // row 0. So we need a row whose suppression leaves an
        // inconsistent downstream carry. Easiest: flip a sum bit in
        // concert — FA rule at that row is silenced, but BoolGate /
        // carry-next at the neighboring rows still fire. To guarantee
        // rejection we instead plant a non-bit value in a cell the
        // BoolGate pins. That is equivalent to the generic "is_input
        // fiddle" guarantee and is cleaner.
        trace.columns[BIT_ADDER_COL_IS_INPUT][3] = Block128::from(2u128);
        let pi = mk_pi();
        let proof = prove_air_unchecked(&air, &trace, &pi);
        assert!(verify_air(&air, &pi, &proof).is_err());
    }

    #[test]
    fn bit_adder_stark_ladder_tampering_rejected() {
        let air = BitAdderAir::new(65, 8);
        let pairs = random_bit_adder_pairs(air.n_instances(), 65, 0xC0FF_EE06);
        let trace = air.build_trace(&pairs);
        let pi = mk_pi();
        let mut proof = prove_air(&air, &trace, &pi).expect("prove");
        // Flip one ladder partial — FRI opening at the corresponding
        // ladder point must break.
        proof.shift_partials[0][3] += Block128::ONE;
        assert!(verify_air(&air, &pi, &proof).is_err());
    }

    // =====================================================================
    // BalanceGateAir — Stage 3b-3 integration tests
    // =====================================================================

    use noid_air::BalanceGateAir;

    /// Produce a balanced (inputs, outputs, fee) with `Σ in = Σ out + fee`.
    /// Mirrors the helper in `balance_gate::tests` but lives here so we
    /// can drive the STARK end-to-end on honest data.
    fn balanced_tuple(seed: u64) -> ([u64; 4], [u64; 8], u64) {
        let mut s = seed.wrapping_mul(0x9E3779B97F4A7C15).wrapping_add(1);
        let mut next = || -> u64 {
            s = s
                .wrapping_mul(0x5851F42D4C957F2D)
                .wrapping_add(0x14057B7EF767814F);
            s >> 32
        };
        let inputs = [
            next() & 0x0FFF_FFFF_FFFF_FFFF,
            next() & 0x0FFF_FFFF_FFFF_FFFF,
            next() & 0x0FFF_FFFF_FFFF_FFFF,
            next() & 0x0FFF_FFFF_FFFF_FFFF,
        ];
        let fee = next() & 0xFFFF;
        let total: u128 = inputs.iter().map(|&x| x as u128).sum::<u128>() - fee as u128;
        let mut remaining = total;
        let mut outs = [0u64; 8];
        for i in 0..7 {
            let take_mask = next() as u128;
            let take = take_mask % (remaining / (8 - i) as u128 + 1);
            outs[i] = take as u64;
            remaining -= take;
        }
        outs[7] = remaining as u64;
        (inputs, outs, fee)
    }

    #[test]
    fn balance_gate_stark_honest_tx_accepted() {
        // log_rows ∈ {8, 10} covers the STARK floor (two 128-row
        // instances per block) and one step up. We skip 12+ here since
        // the AIR has 66 columns, and the commit bucket grows linearly
        // with `n_cols · n_rows`.
        for log_rows in [8usize, 10] {
            let air = BalanceGateAir::new(log_rows);
            let (ins, outs, fee) = balanced_tuple(0xB0A1_0000 ^ log_rows as u64);
            let trace = air.build_trace(ins, outs, fee);
            assert!(air.check(&trace), "native check at log_rows={log_rows}");
            let pi = mk_pi();
            let proof = prove_air(&air, &trace, &pi).expect("prove");
            verify_air(&air, &pi, &proof).expect("verify");
        }
    }

    #[test]
    fn balance_gate_stark_unbalanced_rejected() {
        // Flip one low bit of the fee operand (lives on block B21's `b`
        // slot) on row 0. The AIR's native check already rejects this,
        // but we go through `prove_air_unchecked` to also exercise the
        // full STARK verifier path.
        use noid_air::{BIT_ADDER_COL_B, BIT_ADDER_N_COLS};
        let log_rows = 8usize;
        let air = BalanceGateAir::new(log_rows);
        let (ins, outs, fee) = balanced_tuple(0x000C_0FFE_EBA1);
        let mut trace = air.build_trace(ins, outs, fee);
        // BLK_B21 is the last block (ordinal 10). Column layout: block
        // base = 10 * BIT_ADDER_N_COLS, `b` slot = base + BIT_ADDER_COL_B.
        let b21_b = 10 * BIT_ADDER_N_COLS + BIT_ADDER_COL_B;
        trace.columns[b21_b][0] += Block128::ONE;
        let pi = mk_pi();
        let proof = prove_air_unchecked(&air, &trace, &pi);
        assert!(verify_air(&air, &pi, &proof).is_err());
    }

    #[test]
    fn balance_gate_stark_bridge_tamper_rejected() {
        // Corrupt the A2.a operand cell without updating A0.sum — the
        // A0 → A2 bridge (BalanceBridgeBitsGate) must reject.
        use noid_air::{BIT_ADDER_COL_A, BIT_ADDER_N_COLS};
        let log_rows = 8usize;
        let air = BalanceGateAir::new(log_rows);
        let (ins, outs, fee) = balanced_tuple(0x000C_0FFE_EBA2);
        let mut trace = air.build_trace(ins, outs, fee);
        // BLK_A2 is ordinal 2.
        let a2_a = 2 * BIT_ADDER_N_COLS + BIT_ADDER_COL_A;
        trace.columns[a2_a][3] += Block128::ONE;
        let pi = mk_pi();
        let proof = prove_air_unchecked(&air, &trace, &pi);
        assert!(verify_air(&air, &pi, &proof).is_err());
    }

    #[test]
    fn balance_gate_stark_b_chain_overflow_rejected() {
        // Construct a tx whose B chain hits `Σ outputs + fee = 2^66`
        // while the A chain stays at `2^65`. The asymmetric-width tail
        // comparison (BalanceZeroAtTransitionGate on B20 / B21) must
        // reject via the STARK path, not just the native check.
        let log_rows = 8usize;
        let air = BalanceGateAir::new(log_rows);
        let ins = [1u64 << 63, 1u64 << 63, 1u64 << 63, 1u64 << 63];
        let outs = [1u64 << 63; 8];
        let fee = 0u64;
        let trace = air.build_trace(ins, outs, fee);
        // Note: `build_trace` itself doesn't enforce balance — it just
        // lays out the block operands. The constraint system rejects
        // this trace even though it's well-formed per-block.
        let pi = mk_pi();
        let proof = prove_air_unchecked(&air, &trace, &pi);
        assert!(verify_air(&air, &pi, &proof).is_err());
    }

    #[test]
    fn balance_gate_stark_ladder_tampering_rejected() {
        // BalanceGateAir exposes one shifted column per block's carry
        // (11 shifted columns total — one per bit_adder block). Flipping
        // any ladder partial must break the FRI opening at the
        // corresponding ladder point.
        let log_rows = 8usize;
        let air = BalanceGateAir::new(log_rows);
        let (ins, outs, fee) = balanced_tuple(0x000C_0FFE_EBA3);
        let trace = air.build_trace(ins, outs, fee);
        let pi = mk_pi();
        let mut proof = prove_air(&air, &trace, &pi).expect("prove");
        proof.shift_partials[0][3] += Block128::ONE;
        assert!(verify_air(&air, &pi, &proof).is_err());
    }
}
// ---------------------------------------------------------------------------
// Stage 3c-1.5 — PoseidonPermAir STARK integration tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod poseidon_perm_stark_tests {
    use super::*;
    use noid_air::{
        build_perm_trace, emit_perm_all, Air, CompositeAir, Trace, POSEIDON_COL_IS_FULL,
        POSEIDON_COL_IS_ROUND, POSEIDON_COL_RC, POSEIDON_COL_S, POSEIDON_COL_SIN,
        POSEIDON_COL_SOUT, POSEIDON_COL_X2, POSEIDON_PERM_LOG_ROWS, POSEIDON_PERM_N_COLS,
    };
    use noid_core::Block128;
    use noid_poseidon2b::native::permutation::{F_ROUNDS, N_ROUNDS};
    use noid_poseidon2b::primitives::TxBodyHash;

    fn mk_pi() -> PublicInputs {
        PublicInputs {
            epoch_anchor: [0x11; 32],
            claims_commitment: [0u8; 32],
            tx_body_hash: TxBodyHash([0x44; 32]),
            fee: 7,
            n_live_inputs: 0,
            n_live_outputs: 0,
            coinbase_credit: 0,
            log_slots: 24,
            is_activation: [false; noid_tx::MAX_OUTPUTS],
            is_deactivation: [false; noid_tx::MAX_INPUTS],
        }
    }

    fn mk_input(seed: u128) -> [Block128; 4] {
        let s = seed.wrapping_mul(0x9E3779B97F4A7C15);
        [
            Block128::from(s ^ 0xA5A5_A5A5_A5A5_A5A5),
            Block128::from(s.wrapping_add(1) ^ 0x5A5A_5A5A_5A5A_5A5A),
            Block128::from(s.wrapping_add(2) ^ 0xFFFF_0000_FFFF_0000),
            Block128::from(s.wrapping_add(3) ^ 0x0F0F_F0F0_0F0F_F0F0),
        ]
    }

    fn mk_air() -> CompositeAir {
        CompositeAir::from_parts(
            POSEIDON_PERM_LOG_ROWS,
            POSEIDON_PERM_N_COLS,
            emit_perm_all(),
        )
    }

    #[test]
    fn poseidon_perm_stark_honest_prove_verify() {
        let air = mk_air();
        let cols = build_perm_trace(mk_input(0xDECAF));
        let trace = Trace::new(cols);
        assert!(air.check(&trace));
        let pi = mk_pi();
        let proof = prove_air(&air, &trace, &pi).expect("prove");
        verify_air(&air, &pi, &proof).expect("verify");
    }

    #[test]
    fn poseidon_perm_stark_sout_tamper_rejected() {
        let air = mk_air();
        let mut cols = build_perm_trace(mk_input(0xABCD));
        cols[POSEIDON_COL_SOUT + 2][1] += Block128::ONE;
        let trace = Trace::new(cols);
        let pi = mk_pi();
        let proof = prove_air_unchecked(&air, &trace, &pi);
        assert!(verify_air(&air, &pi, &proof).is_err());
    }

    #[test]
    fn poseidon_perm_stark_rc_tamper_rejected() {
        let air = mk_air();
        let mut cols = build_perm_trace(mk_input(0xBEEF));
        cols[POSEIDON_COL_RC][0] += Block128::ONE;
        let trace = Trace::new(cols);
        let pi = mk_pi();
        let proof = prove_air_unchecked(&air, &trace, &pi);
        assert!(verify_air(&air, &pi, &proof).is_err());
    }

    #[test]
    fn poseidon_perm_stark_partial_row_sin_kill_rejected() {
        let air = mk_air();
        let mut cols = build_perm_trace(mk_input(0xC0FFEE));
        let partial_row = F_ROUNDS / 2 + 3;
        cols[POSEIDON_COL_SIN + 2][partial_row] = Block128::ONE;
        let trace = Trace::new(cols);
        let pi = mk_pi();
        let proof = prove_air_unchecked(&air, &trace, &pi);
        assert!(verify_air(&air, &pi, &proof).is_err());
    }

    #[test]
    fn poseidon_perm_stark_is_full_non_bool_rejected() {
        let air = mk_air();
        let mut cols = build_perm_trace(mk_input(0xFACE));
        cols[POSEIDON_COL_IS_FULL][N_ROUNDS + 2] = Block128::from(0xABCDu128);
        let trace = Trace::new(cols);
        let pi = mk_pi();
        let proof = prove_air_unchecked(&air, &trace, &pi);
        assert!(verify_air(&air, &pi, &proof).is_err());
    }

    #[test]
    fn poseidon_perm_stark_is_round_non_bool_rejected() {
        let air = mk_air();
        let mut cols = build_perm_trace(mk_input(0xBAAD));
        cols[POSEIDON_COL_IS_ROUND][5] = Block128::from(2u128);
        let trace = Trace::new(cols);
        let pi = mk_pi();
        let proof = prove_air_unchecked(&air, &trace, &pi);
        assert!(verify_air(&air, &pi, &proof).is_err());
    }

    #[test]
    fn poseidon_perm_stark_x2_tamper_rejected() {
        let air = mk_air();
        let mut cols = build_perm_trace(mk_input(0x1234));
        cols[POSEIDON_COL_X2][2] += Block128::ONE;
        let trace = Trace::new(cols);
        let pi = mk_pi();
        let proof = prove_air_unchecked(&air, &trace, &pi);
        assert!(verify_air(&air, &pi, &proof).is_err());
    }

    #[test]
    fn poseidon_perm_stark_s_next_tamper_rejected() {
        // MDS blend reads `s_next[lane]` via VSHIFT — tampering the
        // next-row state on a full round must break the proof.
        let air = mk_air();
        let mut cols = build_perm_trace(mk_input(0x5EED));
        cols[POSEIDON_COL_S + 1][1] += Block128::ONE;
        let trace = Trace::new(cols);
        let pi = mk_pi();
        let proof = prove_air_unchecked(&air, &trace, &pi);
        assert!(verify_air(&air, &pi, &proof).is_err());
    }
}

// ---------------------------------------------------------------------------
// Stage 3d-0.2 — PublicColumn verifier-side binding tests.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tx_body_merkle_stark_tests {
    use super::*;
    use noid_core::Block128;

    fn mk_pi() -> PublicInputs {
        PublicInputs {
            epoch_anchor: [0x11; 32],
            claims_commitment: [0u8; 32],
            tx_body_hash: noid_poseidon2b::primitives::TxBodyHash([0x44; 32]),
            fee: 7,
            n_live_inputs: 0,
            n_live_outputs: 0,
            coinbase_credit: 0,
            log_slots: 24,
            is_activation: [false; noid_tx::MAX_OUTPUTS],
            is_deactivation: [false; noid_tx::MAX_INPUTS],
        }
    }

    // =====================================================================
    // Stage 3d-0.2 — PublicColumn verifier-side binding
    // =====================================================================

    use noid_air::{BoolGate, Constraint, PublicColumn};
    use noid_core::TowerField;

    fn pubcol_bool_col(log_rows: usize, seed: u64) -> Vec<Block128> {
        (0..(1usize << log_rows))
            .map(|i| {
                let bit = ((seed.wrapping_mul(2654435761).wrapping_add(i as u64)) >> 7) & 1;
                if bit == 0 {
                    Block128::ZERO
                } else {
                    Block128::ONE
                }
            })
            .collect()
    }

    /// Minimal AIR with one ordinary witness column and one declared
    /// public (programme) column. Used purely to exercise the
    /// verifier-side `check_public_columns` path without pulling in
    /// a Poseidon-sized AIR.
    struct PubColTestAir {
        log_rows: usize,
        n_cols: usize,
        constraints: Vec<Box<dyn Constraint>>,
        publics: Vec<PublicColumn>,
    }

    impl Air for PubColTestAir {
        fn n_columns(&self) -> usize {
            self.n_cols
        }
        fn log_rows(&self) -> usize {
            self.log_rows
        }
        fn constraints(&self) -> &[Box<dyn Constraint>] {
            &self.constraints
        }
        fn public_columns(&self) -> &[PublicColumn] {
            &self.publics
        }
    }

    fn mk_programme(log_rows: usize) -> Vec<Block128> {
        (0..(1usize << log_rows))
            .map(|i| Block128::from(0x1000_0000_0000u128 ^ i as u128))
            .collect()
    }

    #[test]
    fn public_column_honest_accepts() {
        // Witness col 0 is a boolean; col 1 is the pinned programme.
        let log_rows = 4;
        let programme = mk_programme(log_rows);
        let air = PubColTestAir {
            log_rows,
            n_cols: 2,
            constraints: vec![Box::new(BoolGate::new(0))],
            publics: vec![PublicColumn::new(1, programme.clone())],
        };
        let col0 = pubcol_bool_col(log_rows, 0xcafe);
        let trace = Trace::new(vec![col0, programme]);
        let pi = mk_pi();
        let proof = prove_air(&air, &trace, &pi).expect("prove");
        verify_air(&air, &pi, &proof).expect("verify");
    }

    #[test]
    fn public_column_tampered_cell_rejected() {
        // Malicious prover swaps one cell of the "programme" column.
        // `prove_air_unchecked` bypasses the native check so we actually
        // reach the verifier; the 3d-0.2 MLE re-eval must reject.
        let log_rows = 4;
        let programme = mk_programme(log_rows);
        let air = PubColTestAir {
            log_rows,
            n_cols: 2,
            constraints: vec![Box::new(BoolGate::new(0))],
            publics: vec![PublicColumn::new(1, programme.clone())],
        };
        let col0 = pubcol_bool_col(log_rows, 0xfade);
        let mut bad_programme = programme;
        bad_programme[7] += Block128::ONE;
        let trace = Trace::new(vec![col0, bad_programme]);
        let pi = mk_pi();
        let proof = prove_air_unchecked(&air, &trace, &pi);
        assert!(verify_air(&air, &pi, &proof).is_err());
    }

    #[test]
    fn public_column_wrong_programme_declaration_rejected() {
        // Prover honestly carries programme `A` in the trace but the
        // (shared) AIR declares a different programme `B`. The verifier
        // must reject since `base_openings[col]` matches A's MLE at r,
        // not B's.
        let log_rows = 4;
        let prog_a = mk_programme(log_rows);
        let prog_b: Vec<Block128> = (0..(1usize << log_rows))
            .map(|i| Block128::from(0xBEEF_0000_u128 ^ i as u128))
            .collect();
        let air = PubColTestAir {
            log_rows,
            n_cols: 2,
            constraints: vec![Box::new(BoolGate::new(0))],
            publics: vec![PublicColumn::new(1, prog_b)], // declared: B
        };
        let col0 = pubcol_bool_col(log_rows, 0xdeaf);
        let trace = Trace::new(vec![col0, prog_a]); // witness: A
        let pi = mk_pi();
        // Native check rejects (AIR expects B, witness has A), so use
        // the unchecked path to reach the cryptographic verifier.
        let proof = prove_air_unchecked(&air, &trace, &pi);
        assert!(verify_air(&air, &pi, &proof).is_err());
    }

    #[test]
    fn public_column_shape_checks() {
        // AIR declares a public column with the wrong row count: the
        // verifier must reject with ShapeMismatch before any MLE work.
        let log_rows = 4;
        let bad_programme: Vec<Block128> = vec![Block128::ZERO; 2]; // 2 rows, not 16
        let air = PubColTestAir {
            log_rows,
            n_cols: 2,
            constraints: vec![Box::new(BoolGate::new(0))],
            publics: vec![PublicColumn::new(1, bad_programme)],
        };
        let col0 = pubcol_bool_col(log_rows, 0x5eed);
        let col1 = vec![Block128::ZERO; 1 << log_rows];
        let trace = Trace::new(vec![col0, col1]);
        let pi = mk_pi();
        let proof = prove_air_unchecked(&air, &trace, &pi);
        assert!(matches!(
            verify_air(&air, &pi, &proof),
            Err(VerifyError::ShapeMismatch)
        ));
    }

    #[test]
    fn poseidon_perm_with_publics_end_to_end() {
        // Full STARK round-trip: Poseidon perm AIR with `rc` / `is_full`
        // / `is_round` declared as public columns. Honest trace must
        // verify; a single-cell RC tamper must be rejected by the
        // 3d-0.2 MLE re-eval at the sumcheck terminal point `r`.
        use noid_air::{
            build_perm_trace, emit_perm_all, emit_perm_public_columns, CompositeAir,
            POSEIDON_COL_RC, POSEIDON_PERM_LOG_ROWS, POSEIDON_PERM_N_COLS,
        };

        let input = [
            Block128::from(0xA5A5_u128),
            Block128::from(0x5A5A_u128),
            Block128::from(0xDEAD_u128),
            Block128::from(0xBEEF_u128),
        ];
        let air = CompositeAir::from_parts_with_publics(
            POSEIDON_PERM_LOG_ROWS,
            POSEIDON_PERM_N_COLS,
            emit_perm_all(),
            emit_perm_public_columns(),
        );

        // Honest: programme matches, verifier accepts.
        {
            let cols = build_perm_trace(input);
            let trace = Trace::new(cols);
            let pi = mk_pi();
            let proof = prove_air(&air, &trace, &pi).expect("prove");
            verify_air(&air, &pi, &proof).expect("verify");
        }

        // Malicious A: tamper rc[1][3] on a live full-round row. The
        // verifier must reject — in this case the RC-binding gate is
        // also tripped, but so is the 3d-0.2 public-column check.
        {
            let mut cols = build_perm_trace(input);
            cols[POSEIDON_COL_RC + 1][3] += Block128::ONE;
            let trace = Trace::new(cols);
            let pi = mk_pi();
            let proof = prove_air_unchecked(&air, &trace, &pi);
            assert!(verify_air(&air, &pi, &proof).is_err());
        }

        // Malicious B: tamper rc[2] on a *padding* row (r >= N_ROUNDS).
        // There, is_full = is_round = 0 so both the lane-0 and lane-1..3
        // RC-binding selectors are suppressed — the constraint system
        // cannot see the tamper. Only the 3d-0.2 public-column MLE re-
        // evaluation closes this gap. If we remove `check_public_columns`
        // from the verifier, this test fails.
        {
            use noid_air::POSEIDON_PERM_N_ROWS;
            use noid_poseidon2b::native::permutation::N_ROUNDS;
            let mut cols = build_perm_trace(input);
            const { assert!(N_ROUNDS + 3 < POSEIDON_PERM_N_ROWS) };
            cols[POSEIDON_COL_RC + 2][N_ROUNDS + 3] = Block128::from(0x1234_5678u128);
            let trace = Trace::new(cols);
            let pi = mk_pi();
            let proof = prove_air_unchecked(&air, &trace, &pi);
            assert!(verify_air(&air, &pi, &proof).is_err());
        }
    }

    #[test]
    fn public_column_multi_column_enforced() {
        // Two pinned programme columns; tamper the second, verifier
        // must still reject.
        let log_rows = 4;
        let prog_a = mk_programme(log_rows);
        let prog_b: Vec<Block128> = (0..(1usize << log_rows))
            .map(|i| Block128::from(0x0BAD_F00Du128 ^ i as u128))
            .collect();
        let air = PubColTestAir {
            log_rows,
            n_cols: 3,
            constraints: vec![Box::new(BoolGate::new(0))],
            publics: vec![
                PublicColumn::new(1, prog_a.clone()),
                PublicColumn::new(2, prog_b.clone()),
            ],
        };
        let col0 = pubcol_bool_col(log_rows, 0xabba);
        // Honest trace passes.
        {
            let trace = Trace::new(vec![col0.clone(), prog_a.clone(), prog_b.clone()]);
            let pi = mk_pi();
            let proof = prove_air(&air, &trace, &pi).expect("prove");
            verify_air(&air, &pi, &proof).expect("verify");
        }
        // Tamper prog_b, use unchecked prover, verifier rejects.
        {
            let mut bad_b = prog_b;
            bad_b[0] += Block128::ONE;
            let trace = Trace::new(vec![col0, prog_a, bad_b]);
            let pi = mk_pi();
            let proof = prove_air_unchecked(&air, &trace, &pi);
            assert!(verify_air(&air, &pi, &proof).is_err());
        }
    }

    // =====================================================================
    // Stage 3d-0.5 — RowSelectorGate primitive (STARK-level)
    // =====================================================================

    #[test]
    fn row_selector_honest_accept_and_tamper_reject() {
        // End-to-end STARK check of a "pin target_col[row] == constant"
        // row-selector tie: honest trace verifies; tampering the pinned
        // cell produces a rejecting verifier. Exercises the same code
        // path that §3d-0.6..0.10 boundary ties will exercise per tie.
        use noid_air::{emit_public_cell, BoolGate, CompositeAir, Constraint};

        let log_rows = 4;
        let n = 1usize << log_rows;
        let target_row = 5;
        let constant = Block128::from(0xFEED_FACEu128);

        // Cols: [0] indicator programme (pinned), [1] target (witness),
        //       [2] ordinary bool witness so we always have a non-empty
        //       constraint system on every row.
        let (pc, gate) = emit_public_cell(0, target_row, n, 1, constant);
        let constraints: Vec<Box<dyn Constraint>> = vec![gate, Box::new(BoolGate::new(2))];
        let air = CompositeAir::from_parts_with_publics(log_rows, 3, constraints, vec![pc]);

        let indicator = {
            let mut v = vec![Block128::ZERO; n];
            v[target_row] = Block128::ONE;
            v
        };
        let bool_col: Vec<Block128> = (0..n)
            .map(|i| {
                if i & 1 == 0 {
                    Block128::ZERO
                } else {
                    Block128::ONE
                }
            })
            .collect();

        // Honest: target row carries `constant`, other rows free.
        {
            let mut target = vec![Block128::ZERO; n];
            target[target_row] = constant;
            target[0] = Block128::from(0xDEADu128);
            target[n - 1] = Block128::from(0xBEEFu128);
            let trace = Trace::new(vec![indicator.clone(), target, bool_col.clone()]);
            let pi = mk_pi();
            let proof = prove_air(&air, &trace, &pi).expect("prove");
            verify_air(&air, &pi, &proof).expect("verify");
        }

        // Tamper the pinned cell: verifier rejects.
        {
            let mut target = vec![Block128::ZERO; n];
            target[target_row] = constant + Block128::ONE;
            let trace = Trace::new(vec![indicator.clone(), target, bool_col.clone()]);
            let pi = mk_pi();
            let proof = prove_air_unchecked(&air, &trace, &pi);
            assert!(verify_air(&air, &pi, &proof).is_err());
        }

        // Tamper the indicator column to fire on the wrong row — the
        // programme MLE re-eval rejects even before the selector fires.
        {
            let mut bad_indicator = vec![Block128::ZERO; n];
            bad_indicator[target_row + 1] = Block128::ONE;
            let mut target = vec![Block128::ZERO; n];
            target[target_row] = constant;
            let trace = Trace::new(vec![bad_indicator, target, bool_col]);
            let pi = mk_pi();
            let proof = prove_air_unchecked(&air, &trace, &pi);
            assert!(verify_air(&air, &pi, &proof).is_err());
        }
    }

    #[test]
    fn column_eq_at_row_honest_accept_and_tamper_reject() {
        // §3d-0.6b / §3d-0.9 cross-column, same-row equality primitive.
        // `emit_column_eq_at_row` pins `col_a@row == col_b@row` via a
        // shared row-indicator programme. Honest traces verify; tampers
        // that break the equality on the pinned row, or shift the
        // indicator off-schedule, both reject at the verifier.
        use noid_air::{emit_column_eq_at_row, BoolGate, CompositeAir, Constraint};

        let log_rows = 4;
        let n = 1usize << log_rows;
        let target_row = 9;

        // Cols: [0] indicator, [1] col_a, [2] col_b, [3] filler bool.
        let (pc, gate) = emit_column_eq_at_row(0, target_row, n, 1, 2);
        let constraints: Vec<Box<dyn Constraint>> = vec![gate, Box::new(BoolGate::new(3))];
        let air = CompositeAir::from_parts_with_publics(log_rows, 4, constraints, vec![pc]);

        let indicator = {
            let mut v = vec![Block128::ZERO; n];
            v[target_row] = Block128::ONE;
            v
        };
        let bool_col: Vec<Block128> = (0..n)
            .map(|i| {
                if i & 1 == 0 {
                    Block128::ZERO
                } else {
                    Block128::ONE
                }
            })
            .collect();

        // Honest: col_a and col_b agree on `target_row`, disagree freely
        // elsewhere (selector suppresses non-target rows).
        {
            let mut col_a = vec![Block128::ZERO; n];
            let mut col_b = vec![Block128::ZERO; n];
            col_a[0] = Block128::from(0x1111u128);
            col_b[0] = Block128::from(0x9999u128);
            col_a[target_row] = Block128::from(0xCAFE_F00Du128);
            col_b[target_row] = Block128::from(0xCAFE_F00Du128);
            let trace = Trace::new(vec![indicator.clone(), col_a, col_b, bool_col.clone()]);
            let pi = mk_pi();
            let proof = prove_air(&air, &trace, &pi).expect("prove");
            verify_air(&air, &pi, &proof).expect("verify");
        }

        // Tamper — two cells disagree on the pinned row.
        {
            let mut col_a = vec![Block128::ZERO; n];
            let mut col_b = vec![Block128::ZERO; n];
            col_a[target_row] = Block128::from(0xCAFE_F00Du128);
            col_b[target_row] = Block128::from(0xCAFE_F00Du128) + Block128::ONE;
            let trace = Trace::new(vec![indicator.clone(), col_a, col_b, bool_col.clone()]);
            let pi = mk_pi();
            let proof = prove_air_unchecked(&air, &trace, &pi);
            assert!(verify_air(&air, &pi, &proof).is_err());
        }

        // Tamper the indicator — programme MLE re-eval rejects.
        {
            let mut bad_indicator = vec![Block128::ZERO; n];
            bad_indicator[target_row - 1] = Block128::ONE;
            let col_a = vec![Block128::ZERO; n];
            let col_b = vec![Block128::ZERO; n];
            let trace = Trace::new(vec![bad_indicator, col_a, col_b, bool_col]);
            let pi = mk_pi();
            let proof = prove_air_unchecked(&air, &trace, &pi);
            assert!(verify_air(&air, &pi, &proof).is_err());
        }
    }

    #[test]
    fn column_eq_at_next_row_honest_accept_and_tamper_reject() {
        // §3d-0.5.2 off-by-one cross-row equality primitive. Pins
        // `col_a@row == col_b@row+1` through the base `Air`'s cyclic
        // rotation. End-to-end STARK round-trip confirms the zero-check
        // composition handles a gate with `next`-slot reads combined
        // with a `PublicColumn` indicator.
        use noid_air::{emit_column_eq_at_next_row, BoolGate, CompositeAir, Constraint};

        // log_rows must clear the VSHIFT floor (TAU+1) because this gate
        // opts into rotation via `shifted_columns`.
        let log_rows = padded_log_len(0);
        let n = 1usize << log_rows;
        let target_row = 5;

        // Cols: [0] indicator, [1] col_a (read local), [2] col_b (read next),
        // [3] filler bool.
        let (pc, gate) = emit_column_eq_at_next_row(0, target_row, n, 1, 2);
        let constraints: Vec<Box<dyn Constraint>> = vec![gate, Box::new(BoolGate::new(3))];
        let air = CompositeAir::from_parts_with_publics(log_rows, 4, constraints, vec![pc]);

        let indicator = {
            let mut v = vec![Block128::ZERO; n];
            v[target_row] = Block128::ONE;
            v
        };
        let bool_col: Vec<Block128> = (0..n)
            .map(|i| {
                if i & 1 == 0 {
                    Block128::ZERO
                } else {
                    Block128::ONE
                }
            })
            .collect();

        // Honest: col_a[target_row] == col_b[target_row + 1].
        {
            let shared = Block128::from(0x1234_5678u128);
            let mut col_a = vec![Block128::ZERO; n];
            let mut col_b = vec![Block128::ZERO; n];
            col_a[target_row] = shared;
            col_b[target_row + 1] = shared;
            // Other cells free.
            col_a[0] = Block128::from(0xAAu128);
            col_b[0] = Block128::from(0xBBu128);
            let trace = Trace::new(vec![indicator.clone(), col_a, col_b, bool_col.clone()]);
            let pi = mk_pi();
            let proof = prove_air(&air, &trace, &pi).expect("prove");
            verify_air(&air, &pi, &proof).expect("verify");
        }

        // Tamper — col_b on the adjacent row disagrees.
        {
            let shared = Block128::from(0x1234_5678u128);
            let mut col_a = vec![Block128::ZERO; n];
            let mut col_b = vec![Block128::ZERO; n];
            col_a[target_row] = shared;
            col_b[target_row + 1] = shared + Block128::ONE;
            let trace = Trace::new(vec![indicator.clone(), col_a, col_b, bool_col.clone()]);
            let pi = mk_pi();
            let proof = prove_air_unchecked(&air, &trace, &pi);
            assert!(verify_air(&air, &pi, &proof).is_err());
        }

        // Tamper the indicator — programme MLE re-eval rejects.
        {
            let mut bad_indicator = vec![Block128::ZERO; n];
            bad_indicator[target_row + 2] = Block128::ONE;
            let col_a = vec![Block128::ZERO; n];
            let col_b = vec![Block128::ZERO; n];
            let trace = Trace::new(vec![bad_indicator, col_a, col_b, bool_col]);
            let pi = mk_pi();
            let proof = prove_air_unchecked(&air, &trace, &pi);
            assert!(verify_air(&air, &pi, &proof).is_err());
        }
    }
}
