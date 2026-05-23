// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Batched sumcheck opening for the FRI-Binius interleaved commitment.
//!
//! Opens all committed columns at a common evaluation point via:
//! 1. Prover sends per-column evaluations e_k = col_k(z)
//! 2. Verifier draws gamma (Horner RLC scalar)
//! 3. Single degree-2 sumcheck: V = sum_x [B(x) * eq(x, z)]
//!    where B(x) = sum_k gamma^k * col_k(x)
//! 4. FRI proof on batched polynomial B at the sumcheck's final point r

use noid_core::mle::eq::eq_ind_partial_eval;
use noid_core::mle::evaluate::evaluate_slice;
use noid_core::{AdditiveNTT, Block128, TowerField};
use noid_fri::hasher::CryptographicHasher;
use noid_fri::prover::{prove as fri_prove, EvalProof};
use noid_fri::Channel;
use rayon::prelude::*;

use crate::interleaved_commit::InterleavedProverState;

/// Domain-separation tag for the batched opening sub-protocol.
pub const BATCHED_OPEN_TAG: u64 = 0xFFFC_0000_0000_0000;

/// Proof of opening all columns at a common point.
#[derive(Clone, Debug)]
pub struct BatchedOpeningProof {
    /// Per-column MLE evaluations at the opening point.
    pub column_openings: Vec<Block128>,
    /// Sumcheck round polynomials (degree-2, 3 evals per round).
    pub sumcheck_rounds: Vec<[Block128; 3]>,
    /// FRI proof of the batched polynomial B at the sumcheck final point.
    pub fri_proof: EvalProof,
}

/// Compute Horner weights: [1, gamma, gamma^2, ..., gamma^{n-1}].
fn horner_weights(gamma: Block128, n: usize) -> Vec<Block128> {
    let mut weights = Vec::with_capacity(n);
    let mut w = Block128::ONE;
    for _ in 0..n {
        weights.push(w);
        w *= gamma;
    }
    weights
}

/// Open all columns at `eval_point` via batched sumcheck + FRI.
///
/// The prover computes e_k = col_k(eval_point) for each column,
/// draws a gamma challenge, then proves sum_x B(x)*eq(x,z) = V
/// via a degree-2 sumcheck (B and eq are both multilinear).
pub fn prove_batched_opening(
    state: &InterleavedProverState<'_>,
    eval_point: &[Block128],
    ntt: &AdditiveNTT<Block128>,
    channel: &mut Channel,
    hasher: &dyn CryptographicHasher,
) -> BatchedOpeningProof {
    let n_cols = state.n_cols;
    let log_n = state.log_rows;
    let n = 1 << log_n;
    assert_eq!(eval_point.len(), log_n);

    // Step 1: Compute per-column openings e_k = col_k(eval_point)
    let column_openings: Vec<Block128> = state
        .raw_cols
        .par_iter()
        .map(|col| evaluate_slice(col, eval_point))
        .collect();

    // Step 2: Absorb openings, draw gamma
    channel.observe_field_elem(Block128::from(BATCHED_OPEN_TAG));
    channel.observe_field_elems(&column_openings);
    let gamma = channel.get_random_point();
    let weights = horner_weights(gamma, n_cols);

    // Step 3: Compute batched claim V = sum_k gamma^k * e_k
    let batched_claim: Block128 = weights
        .iter()
        .zip(column_openings.iter())
        .map(|(&w, &e)| w * e)
        .fold(Block128::ZERO, |acc, x| acc + x);

    // Step 4: Run degree-2 sumcheck on H(x) = B(x) * eq(x, eval_point)
    // where B(x) = sum_k gamma^k * col_k(x)
    //
    // We maintain folded column states and eq table simultaneously.
    let mut col_folds: Vec<Vec<Block128>> = state.raw_cols.iter().map(|s| s.to_vec()).collect();
    let mut eq_table = eq_ind_partial_eval(eval_point);

    let mut rounds = Vec::with_capacity(log_n);
    let mut claim = batched_claim;

    for _round in 0..log_n {
        let half = col_folds[0].len() / 2;

        // Compute round polynomial p(X) at X=0, X=1, X=2
        // p(alpha) = sum_j B(alpha, j) * eq(alpha, j)
        // where B(alpha, j) = sum_k gamma^k * col_k(alpha, j)
        let (p0, p1, p2) = compute_round_poly_batched(&col_folds, &eq_table, &weights, half);

        debug_assert_eq!(p0 + p1, claim, "Sumcheck invariant violated");

        let round_poly = [p0, p1, p2];
        rounds.push(round_poly);

        // Absorb round polynomial, draw challenge
        channel.observe_field_elems(&round_poly);
        let r = channel.get_random_point();

        // Fold columns and eq table at challenge r
        for col in col_folds.iter_mut() {
            fold_inplace(col, r);
        }
        fold_inplace(&mut eq_table, r);

        // Update claim: p(r) via Lagrange interpolation of [p(0), p(1), p(2)]
        claim = lagrange_eval_3pt(p0, p1, p2, r);
    }

    // After sumcheck: each col_fold[k] has length 1 and equals col_k(r)
    // eq_table has length 1 and equals eq(r, eval_point)
    // claim == B(r) * eq(r, eval_point)
    let b_at_r: Block128 = weights
        .iter()
        .zip(col_folds.iter())
        .map(|(&w, col)| w * col[0])
        .fold(Block128::ZERO, |acc, x| acc + x);
    let eq_at_r = eq_table[0];
    debug_assert_eq!(claim, b_at_r * eq_at_r);

    // Step 5: FRI proof on batched polynomial B at point r (the sumcheck's challenge)
    // Build B's evaluations: B[i] = sum_k gamma^k * col_k[i]
    let b_evals: Vec<Block128> = (0..n)
        .into_par_iter()
        .map(|i| {
            let mut acc = Block128::ZERO;
            for (k, col) in state.raw_cols.iter().enumerate() {
                acc += weights[k] * col[i];
            }
            acc
        })
        .collect();

    // FRI proof on B at eval_point. The channel state continues from after
    // the sumcheck rounds, binding the FRI proof to the sumcheck transcript.
    let fri_proof = fri_prove(&b_evals, eval_point, ntt, channel, hasher);

    BatchedOpeningProof {
        column_openings,
        sumcheck_rounds: rounds,
        fri_proof,
    }
}

/// Compute round polynomial evaluations at 0, 1, 2 for the batched sumcheck.
fn compute_round_poly_batched(
    col_folds: &[Vec<Block128>],
    eq_table: &[Block128],
    weights: &[Block128],
    half: usize,
) -> (Block128, Block128, Block128) {
    let n_cols = col_folds.len();
    let mut p0 = Block128::ZERO;
    let mut p1 = Block128::ZERO;
    let mut p2 = Block128::ZERO;

    for j in 0..half {
        // eq values at x_i=0 and x_i=1
        let eq_lo = eq_table[j];
        let eq_hi = eq_table[j + half];
        // eq at x_i=2: linear interpolation eq(2) = eq_lo + 2*(eq_hi - eq_lo)
        //            = eq_lo + 2*eq_hi + 2*eq_lo (char 2: subtraction = addition)
        //            ... actually in GF(2^128), 2 means Block128::from(2)
        let two = Block128::from(2u128);
        let eq_at_2 = eq_lo + two * (eq_hi + eq_lo);

        // B values at x_i=0 and x_i=1
        let mut b_lo = Block128::ZERO;
        let mut b_hi = Block128::ZERO;
        for k in 0..n_cols {
            b_lo += weights[k] * col_folds[k][j];
            b_hi += weights[k] * col_folds[k][j + half];
        }
        // B at x_i=2: B(2) = B_lo + 2*(B_hi - B_lo) = B_lo + 2*(B_hi + B_lo) (char 2)
        let b_at_2 = b_lo + two * (b_hi + b_lo);

        p0 += b_lo * eq_lo;
        p1 += b_hi * eq_hi;
        p2 += b_at_2 * eq_at_2;
    }

    (p0, p1, p2)
}

/// Fold a vector in half at challenge r: v[j] = v[j] + r * (v[j+half] + v[j])
fn fold_inplace(v: &mut Vec<Block128>, r: Block128) {
    let half = v.len() / 2;
    for j in 0..half {
        let delta = v[j + half] + v[j];
        v[j] += r * delta;
    }
    v.truncate(half);
}

/// Evaluate degree-2 polynomial from 3 points (0, p0), (1, p1), (2, p2) at x.
/// Uses Lagrange interpolation in GF(2^128).
fn lagrange_eval_3pt(p0: Block128, p1: Block128, p2: Block128, x: Block128) -> Block128 {
    // L_0(x) = (x-1)(x-2) / (0-1)(0-2) = (x+1)(x+2) / (1*2) [char 2: -a = a]
    // L_1(x) = (x-0)(x-2) / (1-0)(1-2) = x(x+2) / (1*1) = x(x+2) [char 2: 1-2 = 1+2 = 3... wait]
    //
    // In GF(2^128): 1+1=0, 2+2=0, and arithmetic is char 2.
    // Let a=0, b=1, c=2 (as field elements Block128::from(0/1/2))
    //
    // Standard formula:
    // c0 = p0
    // c2 = (p0 + p2 + alpha*(p0 + p1)) / (alpha^2 + alpha)
    //    where alpha = 2
    // c1 = p0 + p1 + c2
    // result = c0 + c1*x + c2*x^2
    let alpha = Block128::from(2u128);
    let alpha_sq = alpha * alpha;
    let denom = alpha_sq + alpha; // alpha^2 + alpha
    let denom_inv = denom.invert();
    let c0 = p0;
    let c2 = (p0 + p2 + alpha * (p0 + p1)) * denom_inv;
    let c1 = p0 + p1 + c2;
    c0 + c1 * x + c2 * x * x
}

impl BatchedOpeningProof {
    pub fn byte_len(&self) -> usize {
        let openings = self.column_openings.len() * 16;
        let rounds = self.sumcheck_rounds.len() * 3 * 16;
        let fri = self.fri_proof.byte_len();
        openings + rounds + fri
    }
}
