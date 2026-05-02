// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

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

use noid_air::{Air, Constraint, EvalFrame, Trace};
use crate::vshift::{cyclic_rotate_left, ladder_points, reconstruct_shifted_opening};
use noid_core::{AdditiveNTT, Block128, TowerField};
use noid_fri::batch::{prove_batched, verify_batched, BatchedEvalProof};
use noid_fri::channel::TAU;
use noid_fri::prover::{commit, FriCommitment};
use noid_fri::Channel;
use noid_poseidon2b::native::compression::Poseidon2bSponge;
use noid_tx::PublicInputs;

// ---------------------------------------------------------------------------
// Proof
// ---------------------------------------------------------------------------

/// Round polynomial stored as its `D+1` evaluations at
/// `X = 0, 1, 2, …, D` where `D` is the per-variable degree of the
/// batched zero-check polynomial.
pub type RoundPoly = Vec<Block128>;

/// A STARK proof. One FRI commitment per column, the zero-check
/// sumcheck transcript, per-column base openings `e_i = MLE_i(r_point)`,
/// VSHIFT ladder partials + per-slot product sumcheck transcripts
/// (§12a), and finally the §12c multipoint-batch sumcheck plus a
/// **single** batched FRI opening at the shared terminal point `r''`
/// that closes every base- and ladder-claim together.
#[derive(Debug, Clone)]
pub struct StarkProof {
    pub log_rows: usize,
    pub column_commitments: Vec<FriCommitment>,
    /// Per-column base openings `e_i = MLE_i(r_point)` at the
    /// zero-check's own challenge point. Absorbed into the parent
    /// transcript before the §12c multipoint-batch β is squeezed; no
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
    /// ladder points (see [`crate::vshift`]). Used by the verifier to
    /// reconstruct `C'(r)` in closed form and as the target-claim
    /// pre-image of the ladder-batch sumcheck (CRYPTO.md §12a).
    pub shift_partials: Vec<Vec<Block128>>,
    /// Per shifted column: the degree-2 product sumcheck transcript
    /// (`log_len` rounds, three field elements per round) that reduces
    /// the `n+1` ladder partials to a single opening claim
    /// `C(r'_slot)` (CRYPTO.md §12a). Outer index matches `shift_partials`.
    pub ladder_batch_rounds: Vec<Vec<RoundPoly>>,
    /// Per shifted column: the terminal ladder-sumcheck claim `C(r'_s)`.
    /// This value is **not** closed by its own FRI opening; it enters
    /// the §12c multipoint-batch sumcheck together with the base
    /// claims, and a single batched FRI at the multipoint challenge
    /// `r''` closes them all.
    pub ladder_batch_openings: Vec<Block128>,
    /// CRYPTO.md §12c multipoint-batch sumcheck transcript. `log_len`
    /// degree-2 round polynomials (3 field elements each) that reduce
    /// the combined base+ladder multi-point claim to a single common
    /// point `r''`.
    pub multipoint_rounds: Vec<RoundPoly>,
    /// Batched FRI opening of all base columns at the multipoint
    /// challenge `r''`. Replaces the per-slot ladder FRI openings from
    /// 3b-0.3 and the separate base opening at `r_point` from 3b-0.4a
    /// combined — this single FRI now closes both.
    pub multipoint_batch: BatchedEvalProof,
}

// ---------------------------------------------------------------------------
// Opening-point size + padding
// ---------------------------------------------------------------------------

pub fn padded_log_len(log_rows: usize) -> usize {
    (TAU + 1).max(log_rows)
}

fn pad_column(column: &[Block128], target_log: usize) -> Vec<Block128> {
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

fn absorb_public_inputs(channel: &mut Channel, pi: &PublicInputs) {
    absorb_digest_as_pair(channel, &pi.prev_state_root);
    absorb_digest_as_pair(channel, &pi.new_state_root);
    absorb_digest_as_pair(channel, &pi.tx_body_hash.0);
    channel.observe_field_elem(Block128::from(pi.fee));
}

// ---------------------------------------------------------------------------
// Zero-check sumcheck
// ---------------------------------------------------------------------------

/// Maximum per-variable degree of `eq · Σ β_j · C_j` given the AIR.
/// Each constraint `C_j` contributes its own per-variable degree; the
/// multilinear `eq(z, ·)` contributes +1. Round polynomials therefore
/// carry `max_c + 2` evaluations — enough to pin down a degree-`(max_c
/// + 1)` univariate exactly.
fn round_poly_degree(air: &dyn Air) -> usize {
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

fn lagrange_eval_at(p: &[Block128], target: Block128) -> Block128 {
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

/// Fold the highest variable of a multilinear table at an arbitrary
/// field point `r`, in place.
fn fold_highest<F: TowerField>(table: &mut Vec<F>, r: F) {
    let half = table.len() / 2;
    for j in 0..half {
        let lo = table[j];
        let hi = table[j + half];
        table[j] = lo + r * (hi + lo);
    }
    table.truncate(half);
}

/// Partial evaluation of a multilinear table at a field point `s` on
/// its highest variable — returns a new table of length `half`.
///
/// The general formula is `table[j] + s · (table[j+half] + table[j])`.
/// When `s = 0` it collapses to `table[j]` (lower half); when `s = 1`
/// (i.e. `Block128::ONE`) it collapses to `table[j+half]` (upper
/// half). Those two cases are hit by every sumcheck round (the round
/// polynomial is sampled at integer points `0, 1, 2, …, degree`, so
/// `s ∈ {0, 1}` always fire) and avoiding the `s · (…)` multiplication
/// removes most of the per-round Block128 arithmetic on packable
/// columns. This is a local algebraic identity: outputs are
/// bit-identical to the general branch, so soundness is unaffected.
#[inline]
fn partial_eval_highest(table: &[Block128], s: Block128) -> Vec<Block128> {
    let half = table.len() / 2;
    if s == Block128::ZERO {
        return table[..half].to_vec();
    }
    if s == Block128::ONE {
        return table[half..].to_vec();
    }
    (0..half)
        .map(|j| table[j] + s * (table[j + half] + table[j]))
        .collect()
}

/// Evaluate the per-row composition `eq · Σ β_j · C_j` given partial
/// tables at some value `s` of the current round variable, accumulated
/// over the remaining `half` hypercube positions.
///
/// The layout of `col_tables_at_s` is `[base cols..., rotated cols...]`
/// where the rotated-column block is ordered by `shifted_slot`
/// (`shifted_slot[col_id] = Some(slot)` for rotated columns). When a
/// constraint reads `shifted_columns()[k] = col_id`, we feed it the
/// rotated copy at index `n_base + shifted_slot[col_id].unwrap()`.
fn accumulate_sum(
    eq_at_s: &[Block128],
    col_tables_at_s: &[Vec<Block128>],
    constraints: &[Box<dyn Constraint>],
    betas: &[Block128],
    shifted_slot: &[Option<usize>],
    n_base: usize,
) -> Block128 {
    let half = eq_at_s.len();
    let mut local_scratch: Vec<Block128> = Vec::new();
    let mut next_scratch: Vec<Block128> = Vec::new();
    let mut acc = Block128::ZERO;
    for j in 0..half {
        let mut composition = Block128::ZERO;
        for (k, c) in constraints.iter().enumerate() {
            local_scratch.clear();
            for &idx in c.columns() {
                local_scratch.push(col_tables_at_s[idx][j]);
            }
            next_scratch.clear();
            for &idx in c.shifted_columns() {
                let slot = shifted_slot[idx]
                    .expect("shifted column must have a registered slot");
                next_scratch.push(col_tables_at_s[n_base + slot][j]);
            }
            let frame = EvalFrame {
                local: &local_scratch,
                next: &next_scratch,
            };
            composition += betas[k] * c.evaluate(frame);
        }
        acc += eq_at_s[j] * composition;
    }
    acc
}

/// Prover for the batched zero-check sumcheck. Returns the list of
/// round polynomials (one per variable, each of length `degree + 1`)
/// and the vector of challenge points `r = (r_0, …, r_{n-1})`.
fn prove_zero_check(
    cols: &[Vec<Block128>],
    constraints: &[Box<dyn Constraint>],
    betas: &[Block128],
    z: &[Block128],
    channel: &mut Channel,
    degree: usize,
    shifted_slot: &[Option<usize>],
    n_base: usize,
) -> (Vec<RoundPoly>, Vec<Block128>) {
    let n = z.len();
    let n_points = degree + 1;

    // Folded tables, one per column plus one for eq(z, ·).
    let mut cur_cols: Vec<Vec<Block128>> = cols.to_vec();
    let mut cur_eq = noid_core::mle::eq::eq_ind_partial_eval(z);

    let mut round_polys: Vec<RoundPoly> = Vec::with_capacity(n);
    let mut challenges: Vec<Block128> = Vec::with_capacity(n);

    for _ in 0..n {
        // Build round polynomial evaluations at 0, 1, 2, …, degree.
        // The `n_points` sample points are independent; at each `s`
        // we do one `partial_eval_highest` per column + one for eq,
        // then an `accumulate_sum` over the remaining hypercube.
        // Evaluate them in parallel across sample points.
        let evals: Vec<Block128> = {
            use rayon::prelude::*;
            (0..n_points)
                .into_par_iter()
                .map(|s_idx| {
                    let s = Block128::from(s_idx as u8);
                    let eq_at_s = partial_eval_highest(&cur_eq, s);
                    let cols_at_s: Vec<Vec<Block128>> = cur_cols
                        .iter()
                        .map(|c| partial_eval_highest(c, s))
                        .collect();
                    accumulate_sum(
                        &eq_at_s,
                        &cols_at_s,
                        constraints,
                        betas,
                        shifted_slot,
                        n_base,
                    )
                })
                .collect()
        };

        channel.observe_field_elems(&evals);
        let r = channel.get_random_point();

        // Folding each column's highest variable at `r` is also
        // independent per column; parallelise across columns.
        {
            use rayon::prelude::*;
            cur_cols.par_iter_mut().for_each(|c| fold_highest(c, r));
        }
        fold_highest(&mut cur_eq, r);

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
                let (commitment, _tree, _code) = commit(&padded, &ntt, &hasher);
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
    let mut sumcheck_cols: Vec<Vec<Block128>> =
        Vec::with_capacity(n_base + rotated_columns.len());
    sumcheck_cols.extend_from_slice(&padded_columns);
    sumcheck_cols.extend(rotated_columns.into_iter());

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
    let (
        base_openings,
        shift_partials,
        ladder_batch_rounds,
        ladder_batch_openings,
        ladder_challenges,
    ) = prove_base_and_ladder_claims(
        &padded_columns,
        &shifted_indices,
        &r_point,
        log_len,
        &mut channel,
    );
    t.ladder_sumcheck = t2.elapsed();

    let t3 = Instant::now();
    let (multipoint_rounds, multipoint_batch) = prove_multipoint_close(
        &padded_columns,
        &base_openings,
        &r_point,
        &shifted_indices,
        &ladder_batch_openings,
        &ladder_challenges,
        log_len,
        &ntt,
        &mut channel,
        &hasher,
    );
    t.multipoint_fri = t3.elapsed();

    (
        StarkProof {
            log_rows,
            column_commitments: commitments,
            base_openings,
            zero_check_rounds,
            shift_partials,
            ladder_batch_rounds,
            ladder_batch_openings,
            multipoint_rounds,
            multipoint_batch,
        },
        t,
    )
}

/// Stage 3b-0.4 prover — compute base per-column openings at
/// `r_point`, the VSHIFT ladder partials, and run per-slot product
/// sumchecks that collapse each ladder into a single claim
/// `C(r'_s)`. All sumchecks run on the parent `channel`; the base
/// openings and partials are absorbed in a deterministic order before
/// each γ / round polynomial squeeze so the verifier can replay
/// bit-for-bit.
///
/// Returns, in slot order:
/// - base openings `e_i` (one per column);
/// - ladder partials `v_k` (length `log_len + 1` per slot);
/// - per-slot product-sumcheck round polynomials;
/// - per-slot terminal openings `C(r'_s)`;
/// - per-slot terminal challenge vectors (highest-var-first).
fn prove_base_and_ladder_claims(
    padded_columns: &[Vec<Block128>],
    shifted_indices: &[usize],
    r_point: &[Block128],
    log_len: usize,
    channel: &mut Channel,
) -> (
    Vec<Block128>,
    Vec<Vec<Block128>>,
    Vec<Vec<RoundPoly>>,
    Vec<Block128>,
    Vec<Vec<Block128>>,
) {
    use rayon::prelude::*;

    // Base openings e_i = MLE_i(r_point). Parallel across columns.
    let base_openings: Vec<Block128> = padded_columns
        .par_iter()
        .map(|col| mle_eval(col, r_point))
        .collect();
    channel.observe_field_elems(&base_openings);

    let ladder = ladder_points(r_point);

    // Ladder partials per slot — parallel.
    let partials_per_slot: Vec<Vec<Block128>> = shifted_indices
        .par_iter()
        .map(|&col_id| {
            let col = &padded_columns[col_id];
            ladder.par_iter().map(|p| mle_eval(col, p)).collect()
        })
        .collect();

    let mut ladder_batch_rounds: Vec<Vec<RoundPoly>> =
        Vec::with_capacity(shifted_indices.len());
    let mut ladder_batch_openings: Vec<Block128> = Vec::with_capacity(shifted_indices.len());
    let mut ladder_challenges: Vec<Vec<Block128>> = Vec::with_capacity(shifted_indices.len());

    for (slot, &col_id) in shifted_indices.iter().enumerate() {
        let partials = &partials_per_slot[slot];
        channel.observe_field_elem(crate::ladder_batch::sub_channel_tag(slot));
        channel.observe_field_elems(partials);
        let gamma = channel.get_random_point();
        let target = crate::ladder_batch::target_claim(gamma, partials);
        let w = crate::ladder_batch::build_weight_table(gamma, r_point, log_len);
        let col = padded_columns[col_id].clone();
        let (rounds, challenges) =
            crate::ladder_batch::prove_product_sumcheck(col, w, target, channel);
        let r_prime: Vec<Block128> = challenges.iter().rev().cloned().collect();
        let opening = mle_eval(&padded_columns[col_id], &r_prime);
        // Absorb terminal opening so the §12c β below cannot be
        // re-used against a different terminal claim.
        channel.observe_field_elem(opening);
        ladder_batch_rounds.push(rounds);
        ladder_batch_openings.push(opening);
        ladder_challenges.push(challenges);
    }

    (
        base_openings,
        partials_per_slot,
        ladder_batch_rounds,
        ladder_batch_openings,
        ladder_challenges,
    )
}

/// Stage 3b-0.4 §12c prover — multipoint-to-single-point reduction.
///
/// Collects every `(point, column_id, scalar)` claim (one per base
/// column at `r_point`, one per ladder slot at `r'_s`), squeezes β,
/// builds the degree-2 product sumcheck on
/// `H(x) = Σ_k λ_k · eq(point_k, x) · MLE_{col_k}(x)`, and closes the
/// terminal claim via a single batched FRI opening of all base
/// columns at the sumcheck's final challenge `r''`.
#[allow(clippy::too_many_arguments)]
fn prove_multipoint_close(
    padded_columns: &[Vec<Block128>],
    base_openings: &[Block128],
    r_point: &[Block128],
    shifted_indices: &[usize],
    ladder_batch_openings: &[Block128],
    ladder_challenges: &[Vec<Block128>],
    log_len: usize,
    ntt: &AdditiveNTT<Block128>,
    channel: &mut Channel,
    hasher: &Poseidon2bSponge,
) -> (Vec<RoundPoly>, BatchedEvalProof) {
    use noid_core::mle::eq::eq_ind_partial_eval;
    use rayon::prelude::*;

    let n = padded_columns.len();
    let s_count = shifted_indices.len();

    // Squeeze β after absorbing domain tag. Horner weights λ_k = β^k.
    channel.observe_field_elem(Block128::from(crate::multipoint_batch::MULTIPOINT_TAG));
    let beta = channel.get_random_point();
    let mut lambdas: Vec<Block128> = Vec::with_capacity(n + s_count);
    let mut cur = Block128::ONE;
    for _ in 0..(n + s_count) {
        lambdas.push(cur);
        cur = cur * beta;
    }

    // Claims:
    //   base k ∈ [0, n):    point = r_point,       col_id = k
    //   ladder k ∈ [n, n+s): point = r'_slot (rev), col_id = shifted_indices[slot]
    let mut points: Vec<Vec<Block128>> = Vec::with_capacity(n + s_count);
    let mut col_ids: Vec<usize> = Vec::with_capacity(n + s_count);
    let mut openings: Vec<Block128> = Vec::with_capacity(n + s_count);
    for i in 0..n {
        points.push(r_point.to_vec());
        col_ids.push(i);
        openings.push(base_openings[i]);
    }
    for (slot, &col_id) in shifted_indices.iter().enumerate() {
        let r_prime: Vec<Block128> = ladder_challenges[slot].iter().rev().cloned().collect();
        points.push(r_prime);
        col_ids.push(col_id);
        openings.push(ladder_batch_openings[slot]);
    }

    // Target T = Σ λ_k · opening_k.
    let mut target = Block128::ZERO;
    for (l, o) in lambdas.iter().zip(openings.iter()) {
        target += *l * *o;
    }

    // Build (A_k, B_k) pairs: A_k = λ_k · eq(point_k, ·), B_k = MLE_{col_id_k}.
    // eq-tables scale cheaply; we fold λ_k into A_k so B_k stays the raw column.
    let pairs: Vec<(Vec<Block128>, Vec<Block128>)> = (0..(n + s_count))
        .into_par_iter()
        .map(|k| {
            let mut eq_table = eq_ind_partial_eval(&points[k]);
            let lam = lambdas[k];
            for v in eq_table.iter_mut() {
                *v = *v * lam;
            }
            (eq_table, padded_columns[col_ids[k]].clone())
        })
        .collect();

    let (rounds, challenges) =
        crate::multipoint_batch::prove_multipoint_sumcheck(pairs, target, channel);
    let r_pp: Vec<Block128> = challenges.iter().rev().cloned().collect();
    debug_assert_eq!(r_pp.len(), log_len);

    let col_refs: Vec<&[Block128]> = padded_columns.iter().map(|v| v.as_slice()).collect();
    let batch = prove_batched(&col_refs, &r_pp, ntt, channel, hasher);

    (rounds, batch)
}

/// Prover variant that skips the native AIR self-check. Exposed for
/// soundness testing: a malicious prover must be caught by the
/// cryptographic layer (zero-check + FRI), not by the defense-in-depth
/// native pre-check.
#[doc(hidden)]
pub fn prove_air_unchecked<A: Air>(air: &A, trace: &Trace, pi: &PublicInputs) -> StarkProof {
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
                let (commitment, _tree, _code) = commit(&padded, &ntt, &hasher);
                (commitment, padded)
            })
            .unzip()
    };

    // --- Parent transcript: PI + column roots ---
    let mut channel = Channel::new();
    absorb_public_inputs(&mut channel, pi);
    for c in &commitments {
        channel.observe_fri_commitment(c);
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
    // (`log_rows = TX_VALIDITY_LOG_ROWS = 4` will be lifted to
    // `log_rows = 16` in Stage 3b+) will satisfy `log_rows >= TAU+1`,
    // so the padded case is not part of the protocol contract.
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
    let mut sumcheck_cols: Vec<Vec<Block128>> =
        Vec::with_capacity(n_base + rotated_columns.len());
    sumcheck_cols.extend_from_slice(&padded_columns);
    sumcheck_cols.extend(rotated_columns.into_iter());

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

    // Base openings + VSHIFT ladder sumchecks (§12a).
    let (
        base_openings,
        shift_partials,
        ladder_batch_rounds,
        ladder_batch_openings,
        ladder_challenges,
    ) = prove_base_and_ladder_claims(
        &padded_columns,
        &shifted_indices,
        &r_point,
        log_len,
        &mut channel,
    );

    // §12c multipoint consolidation — one batched FRI closes both the
    // base claims at `r_point` and every ladder claim at `r'_slot`.
    let (multipoint_rounds, multipoint_batch) = prove_multipoint_close(
        &padded_columns,
        &base_openings,
        &r_point,
        &shifted_indices,
        &ladder_batch_openings,
        &ladder_challenges,
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
        ladder_batch_rounds,
        ladder_batch_openings,
        multipoint_rounds,
        multipoint_batch,
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
        claim = lagrange_eval_at(rp, r_i);
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
    if proof.shift_partials.len() != shifted_indices.len()
        || proof.ladder_batch_rounds.len() != shifted_indices.len()
        || proof.ladder_batch_openings.len() != shifted_indices.len()
    {
        return Err(VerifyError::ShapeMismatch);
    }
    let expected_ladder_len = log_len + 1;
    for partials in &proof.shift_partials {
        if partials.len() != expected_ladder_len {
            return Err(VerifyError::ShapeMismatch);
        }
    }
    for rounds in &proof.ladder_batch_rounds {
        if rounds.len() != log_len {
            return Err(VerifyError::ShapeMismatch);
        }
        for rp in rounds {
            if rp.len() != crate::ladder_batch::PRODUCT_ROUND_POINTS {
                return Err(VerifyError::ShapeMismatch);
            }
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

    // --- Replay §12a ladder sumchecks + §12c multipoint close ---
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

/// Verifier-side replay of the §12a ladder sumchecks and the §12c
/// multipoint consolidation. Absorbs per-slot partials on the parent
/// `channel`, re-derives γ_s and the multipoint β, runs the degree-2
/// sumcheck replay, and finishes with a single `verify_batched` at
/// `r''` that closes every base and ladder claim in one FRI opening.
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

    let ladder = ladder_points(r_point);
    let mut ladder_r_primes: Vec<Vec<Block128>> = Vec::with_capacity(shifted_indices.len());
    for (slot, _col_id) in shifted_indices.iter().enumerate() {
        let partials = &proof.shift_partials[slot];
        channel.observe_field_elem(crate::ladder_batch::sub_channel_tag(slot));
        channel.observe_field_elems(partials);
        let gamma = channel.get_random_point();
        let target = crate::ladder_batch::target_claim(gamma, partials);
        let (challenges, final_claim) = crate::ladder_batch::verify_product_sumcheck(
            &proof.ladder_batch_rounds[slot],
            target,
            channel,
        )?;
        let r_prime: Vec<Block128> = challenges.iter().rev().cloned().collect();
        let c_r = proof.ladder_batch_openings[slot];
        let w_r = crate::ladder_batch::weight_at(gamma, &ladder, &r_prime);
        if c_r * w_r != final_claim {
            return Err(VerifyError::ConstraintViolated);
        }
        channel.observe_field_elem(c_r);
        ladder_r_primes.push(r_prime);
    }

    // §12c: absorb tag, squeeze β, compute λ_k.
    channel.observe_field_elem(Block128::from(crate::multipoint_batch::MULTIPOINT_TAG));
    let beta = channel.get_random_point();
    let n = proof.base_openings.len();
    let s_count = shifted_indices.len();
    let mut lambdas: Vec<Block128> = Vec::with_capacity(n + s_count);
    let mut cur = Block128::ONE;
    for _ in 0..(n + s_count) {
        lambdas.push(cur);
        cur = cur * beta;
    }
    let mut target = Block128::ZERO;
    for (k, &lam) in lambdas.iter().enumerate() {
        let op = if k < n {
            proof.base_openings[k]
        } else {
            proof.ladder_batch_openings[k - n]
        };
        target += lam * op;
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
    // m_i at r''. All base claims share the same point `r_point`, so
    // `eq(r_point, r'')` is computed once.
    let m = &proof.multipoint_batch.column_openings;
    let eq_base = noid_core::mle::eq::eq_ind(r_point, &r_pp);
    let mut expected = Block128::ZERO;
    for k in 0..n {
        expected += lambdas[k] * eq_base * m[k];
    }
    for (slot, &col_id) in shifted_indices.iter().enumerate() {
        let eq_l = noid_core::mle::eq::eq_ind(&ladder_r_primes[slot], &r_pp);
        expected += lambdas[n + slot] * eq_l * m[col_id];
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
        claim = lagrange_eval_at(rp, r_i);
        challenges.push(r_i);
    }
    t.transcript_sumcheck = t0.elapsed();

    let t1 = Instant::now();
    let r_point: Vec<Block128> = challenges.iter().rev().cloned().collect();
    let eq_zr = noid_core::mle::eq::eq_ind(&z, &r_point);
    let shifted_indices: Vec<usize> = air.shifted_column_indices();
    if proof.shift_partials.len() != shifted_indices.len()
        || proof.ladder_batch_rounds.len() != shifted_indices.len()
        || proof.ladder_batch_openings.len() != shifted_indices.len()
    {
        return (Err(VerifyError::ShapeMismatch), t);
    }
    let expected_ladder_len = log_len + 1;
    for partials in &proof.shift_partials {
        if partials.len() != expected_ladder_len {
            return (Err(VerifyError::ShapeMismatch), t);
        }
    }
    for rounds in &proof.ladder_batch_rounds {
        if rounds.len() != log_len {
            return (Err(VerifyError::ShapeMismatch), t);
        }
        for rp in rounds {
            if rp.len() != crate::ladder_batch::PRODUCT_ROUND_POINTS {
                return (Err(VerifyError::ShapeMismatch), t);
            }
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

    // --- §12a ladder sumcheck replays (serial, on parent channel) ---
    let t2 = Instant::now();
    channel.observe_field_elems(&proof.base_openings);
    let ladder = ladder_points(&r_point);
    let mut ladder_r_primes: Vec<Vec<Block128>> = Vec::with_capacity(shifted_indices.len());
    for slot in 0..shifted_indices.len() {
        let partials = &proof.shift_partials[slot];
        channel.observe_field_elem(crate::ladder_batch::sub_channel_tag(slot));
        channel.observe_field_elems(partials);
        let gamma = channel.get_random_point();
        let target = crate::ladder_batch::target_claim(gamma, partials);
        let (ch_s, final_claim) = match crate::ladder_batch::verify_product_sumcheck(
            &proof.ladder_batch_rounds[slot],
            target,
            &mut channel,
        ) {
            Ok(v) => v,
            Err(e) => {
                t.ladder_sumcheck = t2.elapsed();
                return (Err(e), t);
            }
        };
        let r_prime: Vec<Block128> = ch_s.iter().rev().cloned().collect();
        let c_r = proof.ladder_batch_openings[slot];
        let w_r = crate::ladder_batch::weight_at(gamma, &ladder, &r_prime);
        if c_r * w_r != final_claim {
            t.ladder_sumcheck = t2.elapsed();
            return (Err(VerifyError::ConstraintViolated), t);
        }
        channel.observe_field_elem(c_r);
        ladder_r_primes.push(r_prime);
    }
    t.ladder_sumcheck = t2.elapsed();

    // --- §12c multipoint sumcheck replay + batched FRI at r'' ---
    let t3 = Instant::now();
    channel.observe_field_elem(Block128::from(crate::multipoint_batch::MULTIPOINT_TAG));
    let beta = channel.get_random_point();
    let n = proof.base_openings.len();
    let s_count = shifted_indices.len();
    let mut lambdas: Vec<Block128> = Vec::with_capacity(n + s_count);
    {
        let mut cur = Block128::ONE;
        for _ in 0..(n + s_count) {
            lambdas.push(cur);
            cur = cur * beta;
        }
    }
    let mut mp_target = Block128::ZERO;
    for (k, &lam) in lambdas.iter().enumerate() {
        let op = if k < n {
            proof.base_openings[k]
        } else {
            proof.ladder_batch_openings[k - n]
        };
        mp_target += lam * op;
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
    for (slot, &col_id) in shifted_indices.iter().enumerate() {
        let eq_l = noid_core::mle::eq::eq_ind(&ladder_r_primes[slot], &r_pp);
        expected += lambdas[n + slot] * eq_l * m[col_id];
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

fn mle_eval(evals: &[Block128], point: &[Block128]) -> Block128 {
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
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use noid_air::{
        Air, BoolGate, CompositeAir, Constraint, LinearCombinationAir, Trace, TxValidityAir,
        WeightedLinearGate,
    };
    use noid_poseidon2b::primitives::TxBodyHash;
    use noid_tx::{TxInput, TxOutput};

    fn mk_pi() -> PublicInputs {
        PublicInputs {
            prev_state_root: [0x11; 32],
            new_state_root: [0x22; 32],
            tx_body_hash: TxBodyHash([0x44; 32]),
            fee: 7,
        }
    }

    fn mk_body() -> noid_tx::TxBody {
        let mut input = TxInput::dummy();
        input.valid = true;
        let mut output = TxOutput::dummy();
        output.valid = true;
        noid_tx::TxBody {
            prev_state_root: [0u8; 32],
            new_state_root: [0u8; 32],
            fee: 0,
            inputs: vec![input, TxInput::dummy()],
            outputs: vec![output, TxOutput::dummy()],
        }
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
                if bit == 0 { Block128::ZERO } else { Block128::ONE }
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
        let air = TxValidityAir::new();
        let trace = TxValidityAir::build_trace(&mk_body());
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
        let constraints: Vec<Box<dyn Constraint>> = vec![Box::new(Deg3ProductGate {
            cols: [0, 1, 2],
        })];
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
        let constraints: Vec<Box<dyn Constraint>> =
            vec![Box::new(Deg4SquareGate { cols: [0, 1] })];
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
        let air = TxValidityAir::new();
        let mut trace = TxValidityAir::build_trace(&mk_body());
        trace.columns[0][2] = Block128::from(3u128); // not 0 or 1
        let pi = mk_pi();
        let proof = prove_air_unchecked(&air, &trace, &pi);
        assert!(
            verify_air(&air, &pi, &proof).is_err(),
            "verifier must reject a non-boolean witness for BoolGate"
        );
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
        let constraints: Vec<Box<dyn Constraint>> = vec![Box::new(Deg3ProductGate {
            cols: [0, 1, 2],
        })];
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
        let constraints: Vec<Box<dyn Constraint>> =
            vec![Box::new(Deg4SquareGate { cols: [0, 1] })];
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
        let air = TxValidityAir::new();
        let trace = TxValidityAir::build_trace(&mk_body());
        let pi = mk_pi();
        let mut proof = prove_air(&air, &trace, &pi).expect("prove");
        proof.base_openings[0] += Block128::ONE;
        assert!(verify_air(&air, &pi, &proof).is_err());
    }

    #[test]
    fn tampered_round_poly_rejected() {
        let air = TxValidityAir::new();
        let trace = TxValidityAir::build_trace(&mk_body());
        let pi = mk_pi();
        let mut proof = prove_air(&air, &trace, &pi).expect("prove");
        proof.zero_check_rounds[0][0] += Block128::ONE;
        assert!(verify_air(&air, &pi, &proof).is_err());
    }

    #[test]
    fn wrong_pi_rejected() {
        let air = TxValidityAir::new();
        let trace = TxValidityAir::build_trace(&mk_body());
        let pi = mk_pi();
        let proof = prove_air(&air, &trace, &pi).expect("prove");
        let mut bad = pi;
        bad.fee = pi.fee + 1;
        assert!(verify_air(&air, &bad, &proof).is_err());
    }

    #[test]
    fn bad_trace_rejected_in_native_check() {
        let air = TxValidityAir::new();
        let mut trace: Trace = TxValidityAir::build_trace(&mk_body());
        trace.columns[0][0] = Block128::from(5u128);
        assert!(prove_air(&air, &trace, &mk_pi()).is_err());
    }

    #[test]
    fn round_poly_shape_matches_air_degree() {
        // Sanity: round polys in the proof must have length
        // `max_constraint_degree + 2`, independent of AIR.
        for (air_deg, air) in [
            (1usize, {
                let c: Vec<Box<dyn Constraint>> = vec![Box::new(WeightedLinearGate::new_xor(vec![0, 1]))];
                CompositeAir::from_parts(4, 2, c)
            }),
            (2usize, {
                let c: Vec<Box<dyn Constraint>> = vec![Box::new(BoolGate::new(0))];
                CompositeAir::from_parts(4, 1, c)
            }),
            (3usize, {
                let c: Vec<Box<dyn Constraint>> = vec![Box::new(Deg3ProductGate {
                    cols: [0, 1, 2],
                })];
                CompositeAir::from_parts(4, 3, c)
            }),
            (4usize, {
                let c: Vec<Box<dyn Constraint>> =
                    vec![Box::new(Deg4SquareGate { cols: [0, 1] })];
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
        let pt = |x: Block128| {
            a[0] + x * (a[1] + x * (a[2] + x * a[3]))
        };
        let evals: Vec<Block128> = (0..4)
            .map(|i| pt(Block128::from(i as u8)))
            .collect();
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
        let p5 = |x: Block128| {
            a[0] + x * (a[1] + x * (a[2] + x * (a[3] + x * (a[4] + x * a[5]))))
        };
        let e5: Vec<Block128> = (0..6).map(|i| p5(Block128::from(i as u8))).collect();
        for target_i in 0..12u8 {
            let t = Block128::from(target_i);
            assert_eq!(lagrange_eval_at(&e5, t), p5(t));
        }
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
    fn vshift_tampered_batch_round_rejected() {
        // Stage 3b-0.4: flipping a byte inside the ladder-batch
        // product-sumcheck transcript must make the new sub-channel
        // diverge → the final FRI check fails.
        let log_rows = 8;
        let constraints: Vec<Box<dyn Constraint>> =
            vec![Box::new(NextEqualsLocalGate { cols: [0] })];
        let air = CompositeAir::from_parts(log_rows, 1, constraints);
        let col = vec![Block128::from(0x42u128); 1 << log_rows];
        let trace = Trace::new(vec![col]);
        let pi = mk_pi();
        let mut proof = prove_air(&air, &trace, &pi).expect("prove");
        proof.ladder_batch_rounds[0][1][2] += Block128::ONE;
        assert!(verify_air(&air, &pi, &proof).is_err());
    }

    #[test]
    fn vshift_tampered_batch_opening_rejected() {
        // Flipping the terminal `C(r')` opening must fail the FRI /
        // algebraic check on the ladder sub-channel.
        let log_rows = 8;
        let constraints: Vec<Box<dyn Constraint>> =
            vec![Box::new(NextEqualsLocalGate { cols: [0] })];
        let air = CompositeAir::from_parts(log_rows, 1, constraints);
        let col = vec![Block128::from(0x99u128); 1 << log_rows];
        let trace = Trace::new(vec![col]);
        let pi = mk_pi();
        let mut proof = prove_air(&air, &trace, &pi).expect("prove");
        proof.ladder_batch_openings[0] += Block128::ONE;
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
        let adders: Vec<(u64, u64)> = (0..air.n_instances())
            .map(|_| (u64::MAX, 1u64))
            .collect();
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
        assert_eq!(
            trace.columns[CARRY_RIPPLE_COL_IS_RESET][0],
            Block128::ONE
        );
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
}
