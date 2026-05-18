// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Mixed-point opening for the FRI-Binius interleaved PCS.
//!
//! After the outer multipoint sumcheck reduces all claims (base, ladder,
//! slice) to a single common point `r_pp`, this module proves that the
//! claimed column evaluations at `r_pp` are consistent with the committed
//! interleaved polynomial.
//!
//! Protocol:
//! 1. Prover sends per-column evaluations at `primary_point` (= r_pp)
//!    plus secondary claim values (for transcript binding)
//! 2. Verifier draws gamma (Horner RLC scalar)
//! 3. Compact FRI proves: C(primary_point) = sum_k gamma^k * col_k(primary_point)
//!    where C(x) = sum_k gamma^k * col_k(x) is multilinear
//!
//! Uses the compact FRI (TAU=8, 32 queries, batched Merkle paths) for ~28KB
//! opening proofs instead of ~70KB from the standard FRI.

use noid_core::mle::evaluate::evaluate_slice;
use noid_core::{AdditiveNTT, Block128, TowerField};
use noid_fri::hasher::CryptographicHasher;
use noid_fri::Channel;
use rayon::prelude::*;

use crate::compact_fri::{compact_fri_prove, compact_fri_verify, CompactEvalProof};
use crate::interleaved_commit::InterleavedProverState;

/// Domain-separation tag for mixed opening sub-protocol.
pub const MIXED_OPEN_TAG: u64 = 0xFFF8_0000_0000_0000;

/// A claim that column at `col_index` evaluates to `value` at `eval_point`.
#[derive(Clone, Debug)]
pub struct EvalClaim {
    pub col_index: usize,
    pub eval_point: Vec<Block128>,
    pub value: Block128,
}

/// Proof of mixed-point opening.
#[derive(Clone, Debug)]
pub struct MixedOpeningProof {
    /// Per-column evaluations at primary_point (first n_cols entries),
    /// followed by secondary claim values.
    pub all_openings: Vec<Block128>,
    /// Compact FRI proof of the gamma-batched polynomial at primary_point.
    pub fri_proof: CompactEvalProof,
}

/// Prove a mixed-point opening.
///
/// `primary_point`: the common opening point (r_pp from multipoint sumcheck)
/// `secondary_claims`: additional claims at different points (absorbed for
///   transcript binding but proven via the outer multipoint sumcheck)
pub fn prove_mixed_opening(
    state: &InterleavedProverState,
    primary_point: &[Block128],
    secondary_claims: &[EvalClaim],
    ntt: &AdditiveNTT<Block128>,
    channel: &mut Channel,
    hasher: &dyn CryptographicHasher,
) -> MixedOpeningProof {
    let n_cols = state.n_cols;
    let log_n = state.log_rows;
    let n = 1 << log_n;
    assert_eq!(primary_point.len(), log_n);

    // Step 1: Compute primary openings (all columns at primary_point)
    let primary_openings: Vec<Block128> = state
        .raw_cols
        .par_iter()
        .map(|col| evaluate_slice(col, primary_point))
        .collect();

    // Step 2: Verify secondary claims are consistent
    for claim in secondary_claims {
        assert!(claim.col_index < n_cols);
        assert_eq!(claim.eval_point.len(), log_n);
    }

    // Build flat list: primary openings then secondary claim values
    let mut all_openings = primary_openings.clone();
    for claim in secondary_claims {
        all_openings.push(claim.value);
    }

    // Step 3: Absorb all openings, draw gamma
    channel.observe_field_elem(Block128::from(MIXED_OPEN_TAG));
    channel.observe_field_elems(&all_openings);
    let gamma = channel.get_random_point();

    // Horner weights for primary columns only (FRI batching)
    let weights = compute_horner_weights(gamma, n_cols);

    // Step 4: Build batched polynomial C(x) = sum_k gamma^k * col_k(x)
    let c_evals: Vec<Block128> = (0..n)
        .into_par_iter()
        .map(|i| {
            let mut acc = Block128::ZERO;
            for (k, col) in state.raw_cols.iter().enumerate() {
                acc += weights[k] * col[i];
            }
            acc
        })
        .collect();

    // Step 5: Prove C(primary_point) via compact FRI (TAU=8, 32 queries, batched paths)
    let fri_proof = compact_fri_prove(&c_evals, primary_point, ntt, channel, hasher);

    MixedOpeningProof {
        all_openings,
        fri_proof,
    }
}

/// Verify a mixed opening proof.
pub fn verify_mixed_opening(
    commitment: &crate::interleaved_commit::InterleavedCommitment,
    primary_point: &[Block128],
    secondary_claims: &[EvalClaim],
    proof: &MixedOpeningProof,
    ntt: &AdditiveNTT<Block128>,
    channel: &mut Channel,
    hasher: &dyn CryptographicHasher,
) -> Result<Vec<Block128>, String> {
    let n_cols = commitment.n_cols;
    let log_n = commitment.log_rows;
    let total_claims = n_cols + secondary_claims.len();

    if proof.all_openings.len() != total_claims {
        return Err("Opening count mismatch".into());
    }
    if primary_point.len() != log_n {
        return Err("Eval point dimension mismatch".into());
    }

    // Step 1: Absorb openings, draw gamma (mirror prover)
    channel.observe_field_elem(Block128::from(MIXED_OPEN_TAG));
    channel.observe_field_elems(&proof.all_openings);
    let gamma = channel.get_random_point();

    // Step 2: Compute batched claim for primary columns
    let weights = compute_horner_weights(gamma, n_cols);
    let batched_claim: Block128 = weights
        .iter()
        .zip(proof.all_openings[..n_cols].iter())
        .map(|(&w, &e)| w * e)
        .fold(Block128::ZERO, |acc, x| acc + x);

    // Step 3: Verify compact FRI proof: C(primary_point) == batched_claim
    compact_fri_verify(
        primary_point,
        batched_claim,
        &proof.fri_proof,
        ntt,
        channel,
        hasher,
    )?;

    // Return primary openings (first n_cols entries)
    Ok(proof.all_openings[..n_cols].to_vec())
}

fn compute_horner_weights(gamma: Block128, n: usize) -> Vec<Block128> {
    let mut weights = Vec::with_capacity(n);
    let mut w = Block128::ONE;
    for _ in 0..n {
        weights.push(w);
        w *= gamma;
    }
    weights
}

impl MixedOpeningProof {
    pub fn byte_len(&self) -> usize {
        let openings = self.all_openings.len() * 16;
        let fri = self.fri_proof.byte_len();
        openings + fri
    }
}
