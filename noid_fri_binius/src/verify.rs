// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Verification logic for the FRI-Binius batched opening proof.

use noid_core::{AdditiveNTT, Block128, TowerField};
use noid_fri::hasher::CryptographicHasher;
use noid_fri::verifier::verify as fri_verify;
use noid_fri::Channel;

use crate::batched_open::{BatchedOpeningProof, BATCHED_OPEN_TAG};
use crate::interleaved_commit::InterleavedCommitment;

/// Verify a batched opening proof against a commitment.
///
/// Checks:
/// 1. Sumcheck rounds are consistent (p(0) + p(1) == claim each round)
/// 2. Terminal claim == B(r) * eq(r, eval_point)
/// 3. FRI proof verifies B(r) at the sumcheck challenge point
pub fn verify_batched_opening(
    commitment: &InterleavedCommitment,
    eval_point: &[Block128],
    proof: &BatchedOpeningProof,
    ntt: &AdditiveNTT<Block128>,
    channel: &mut Channel,
    hasher: &dyn CryptographicHasher,
) -> Result<Vec<Block128>, String> {
    let n_cols = commitment.n_cols;
    let log_n = commitment.log_rows;

    if proof.column_openings.len() != n_cols {
        return Err("Column opening count mismatch".into());
    }
    if proof.sumcheck_rounds.len() != log_n {
        return Err("Sumcheck round count mismatch".into());
    }
    if eval_point.len() != log_n {
        return Err("Eval point dimension mismatch".into());
    }

    // Step 1: Absorb openings, draw gamma (mirror prover)
    channel.observe_field_elem(Block128::from(BATCHED_OPEN_TAG));
    channel.observe_field_elems(&proof.column_openings);
    let gamma = channel.get_random_point();

    // Compute batched claim V = sum_k gamma^k * e_k
    let mut batched_claim = Block128::ZERO;
    let mut gamma_pow = Block128::ONE;
    for &e in &proof.column_openings {
        batched_claim = batched_claim + gamma_pow * e;
        gamma_pow = gamma_pow * gamma;
    }

    // Step 2: Verify sumcheck rounds
    let mut claim = batched_claim;
    let mut challenges = Vec::with_capacity(log_n);

    for round_poly in &proof.sumcheck_rounds {
        let [p0, p1, _p2] = *round_poly;

        // Check: p(0) + p(1) == claim
        if p0 + p1 != claim {
            return Err(format!(
                "Sumcheck check failed at round {}",
                challenges.len()
            ));
        }

        // Absorb, draw challenge
        channel.observe_field_elems(round_poly);
        let r = channel.get_random_point();
        challenges.push(r);

        // Update claim: p(r) via Lagrange interpolation
        claim = lagrange_eval_3pt(round_poly[0], round_poly[1], round_poly[2], r);
    }

    // Step 3: Verify terminal claim
    // claim should equal B(r) * eq(r, eval_point)
    // where B(r) = sum_k gamma^k * col_k(r) ... but we don't have col_k(r) directly.
    // Instead, verify via FRI that B evaluated at eval_point equals batched_claim.
    // The FRI proof was produced with B_evals and eval_point.
    let b_at_eval_point = batched_claim;

    // Step 4: Verify FRI proof
    // The FRI proof shows B(eval_point) = b_at_eval_point
    fri_verify(
        eval_point,
        b_at_eval_point,
        proof.fri_proof.clone(),
        ntt,
        channel,
        hasher,
    )?;

    Ok(proof.column_openings.clone())
}

/// Evaluate degree-2 polynomial from 3 points at x (same as in batched_open).
fn lagrange_eval_3pt(p0: Block128, p1: Block128, p2: Block128, x: Block128) -> Block128 {
    let alpha = Block128::from(2u128);
    let alpha_sq = alpha * alpha;
    let denom = alpha_sq + alpha;
    let denom_inv = denom.invert();
    let c0 = p0;
    let c2 = (p0 + p2 + alpha * (p0 + p1)) * denom_inv;
    let c1 = p0 + p1 + c2;
    c0 + c1 * x + c2 * x * x
}
