// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

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
//! Uses the compact FRI (TAU=8, 64 queries, batched Merkle paths) for ~26KB
//! opening proofs instead of ~70KB from the standard FRI.

use noid_core::mle::evaluate::evaluate_flat_with_scratch;
use noid_core::{AdditiveNTT, Block128, TowerField};
use noid_fri::hasher::CryptographicHasher;
use noid_fri::Channel;
use rayon::prelude::*;
use std::time::{Duration, Instant};

use crate::compact_fri::{compact_fri_prove, compact_fri_verify, CompactEvalProof};
use crate::interleaved_commit::InterleavedProverState;

/// Domain-separation tag for mixed opening sub-protocol.
pub const MIXED_OPEN_TAG: u64 = 0xFFF8_0000_0000_0000;

#[derive(Debug)]
struct MixedOpenPhaseTiming {
    name: &'static str,
    elapsed: Duration,
}

#[derive(Debug)]
struct MixedOpenProfiler {
    enabled: bool,
    started: Instant,
    last: Instant,
    phases: Vec<MixedOpenPhaseTiming>,
}

impl MixedOpenProfiler {
    fn new() -> Self {
        let now = Instant::now();
        Self {
            enabled: prove_profile_enabled(),
            started: now,
            last: now,
            phases: Vec::with_capacity(8),
        }
    }

    fn phase(&mut self, name: &'static str) {
        if !self.enabled {
            return;
        }
        let now = Instant::now();
        self.phases.push(MixedOpenPhaseTiming {
            name,
            elapsed: now.duration_since(self.last),
        });
        self.last = now;
    }

    fn finish(self, n_cols: usize, log_n: usize, n_secondary_claims: usize, num_queries: usize) {
        if !self.enabled {
            return;
        }
        let total = self.started.elapsed();
        let summary = self
            .phases
            .iter()
            .map(|p| format!("{}={:.3}ms", p.name, duration_ms(p.elapsed)))
            .collect::<Vec<_>>()
            .join(", ");
        eprintln!(
            "prove_block_profile mixed_opening summary n_cols={} log_n={} n_secondary_claims={} num_queries={} total_ms={:.3} phases={}",
            n_cols,
            log_n,
            n_secondary_claims,
            num_queries,
            duration_ms(total),
            summary
        );
    }
}

fn prove_profile_enabled() -> bool {
    std::env::var("NOID_PROVE_BLOCK_PROFILE")
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

fn duration_ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1_000.0
}

/// A claim that column at `col_index` evaluates to `value` at `eval_point`.
#[derive(Clone, Debug)]
pub struct EvalClaim {
    pub col_index: usize,
    pub eval_point: Vec<Block128>,
    pub value: Block128,
}

/// Proof of mixed-point opening.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
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
/// `num_queries`: FRI query count (use `COMPACT_NUM_QUERIES` for full security)
pub fn prove_mixed_opening(
    state: &InterleavedProverState<'_>,
    primary_point: &[Block128],
    secondary_claims: &[EvalClaim],
    ntt: &AdditiveNTT<Block128>,
    channel: &mut Channel,
    hasher: &dyn CryptographicHasher,
    num_queries: usize,
) -> MixedOpeningProof {
    let mut profiler = MixedOpenProfiler::new();
    let n_cols = state.n_cols;
    let log_n = state.log_rows;
    let n = 1 << log_n;
    assert_eq!(primary_point.len(), log_n);

    // Compute primary openings (all columns at primary_point). Use the same
    // flat/GCM evaluator as block multipoint openings: it preserves the field
    // value but avoids tower-basis multiplication in the hot fold loop.
    thread_local! {
        static FLAT_SCRATCH: std::cell::RefCell<Vec<u128>> = std::cell::RefCell::new(Vec::new());
        static POINT_FLAT_SCRATCH: std::cell::RefCell<Vec<u128>> = std::cell::RefCell::new(Vec::new());
    }

    let primary_openings: Vec<Block128> = state
        .raw_cols
        .par_iter()
        .map(|col| {
            FLAT_SCRATCH.with(|flat| {
                POINT_FLAT_SCRATCH.with(|point_flat| {
                    evaluate_flat_with_scratch(
                        col,
                        primary_point,
                        &mut flat.borrow_mut(),
                        &mut point_flat.borrow_mut(),
                    )
                })
            })
        })
        .collect();
    profiler.phase("primary_openings");

    // Verify secondary claims are consistent
    for claim in secondary_claims {
        assert!(claim.col_index < n_cols);
        assert_eq!(claim.eval_point.len(), log_n);
    }
    profiler.phase("secondary_claim_validation");

    // Build flat list: primary openings then secondary claim values.
    let mut all_openings = primary_openings;
    all_openings.reserve(secondary_claims.len());
    all_openings.extend(secondary_claims.iter().map(|claim| claim.value));
    profiler.phase("all_openings_assembly");

    // Absorb all openings, draw gamma.
    channel.observe_field_elem(Block128::from(MIXED_OPEN_TAG));
    channel.observe_field_elems(&all_openings);
    profiler.phase("transcript_absorb_openings");
    let gamma = channel.get_random_point();
    profiler.phase("transcript_draw_gamma");

    // Horner weights for primary columns only (FRI batching), stored in the
    // flat/GCM basis so the batched polynomial can use carry-less multiply.
    let weights_flat = compute_horner_weights_flat(gamma, n_cols);
    profiler.phase("gamma_weights");

    // Build batched polynomial C(x) = sum_k gamma^k * col_k(x).
    // Column-parallel accumulation keeps each source column and the small
    // accumulator vector hot in cache. Accumulation is performed in the flat
    // basis and converted back once for compact FRI.
    use noid_core::hardware::{clmul_gcm, flat_to_tower_u128, tower_to_flat_u128};
    let c_evals_flat: Vec<u128> = state
        .raw_cols
        .par_iter()
        .zip(weights_flat.par_iter())
        .fold(
            || vec![0u128; n],
            |mut acc, (col, &weight)| {
                acc.iter_mut().zip(col.iter()).for_each(|(acc_i, &v)| {
                    *acc_i ^= clmul_gcm(weight, tower_to_flat_u128(v.0));
                });
                acc
            },
        )
        .reduce(
            || vec![0u128; n],
            |mut a, b| {
                a.iter_mut()
                    .zip(b.iter())
                    .for_each(|(a_i, &b_i)| *a_i ^= b_i);
                a
            },
        );
    let c_evals: Vec<Block128> = c_evals_flat
        .into_iter()
        .map(|v| Block128::from(flat_to_tower_u128(v)))
        .collect();
    profiler.phase("batched_polynomial");

    // Prove C(primary_point) via compact FRI
    let fri_proof = compact_fri_prove(&c_evals, primary_point, ntt, channel, hasher, num_queries);
    profiler.phase("compact_fri_prove");

    let proof = MixedOpeningProof {
        all_openings,
        fri_proof,
    };
    profiler.phase("proof_assembly");
    profiler.finish(n_cols, log_n, secondary_claims.len(), num_queries);
    proof
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
    num_queries: usize,
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

    // Absorb openings, draw gamma (mirror prover)
    channel.observe_field_elem(Block128::from(MIXED_OPEN_TAG));
    channel.observe_field_elems(&proof.all_openings);
    let gamma = channel.get_random_point();

    // Compute batched claim for primary columns in flat/GCM basis.
    let batched_claim = compute_batched_claim_flat(gamma, &proof.all_openings[..n_cols]);

    // Verify compact FRI proof: C(primary_point) == batched_claim
    compact_fri_verify(
        primary_point,
        batched_claim,
        &proof.fri_proof,
        ntt,
        channel,
        hasher,
        num_queries,
    )?;

    // Return primary openings (first n_cols entries)
    Ok(proof.all_openings[..n_cols].to_vec())
}

fn compute_horner_weights_flat(gamma: Block128, n: usize) -> Vec<u128> {
    use noid_core::hardware::{clmul_gcm, tower_to_flat_u128};
    let gamma_flat = tower_to_flat_u128(gamma.0);
    let mut weights = Vec::with_capacity(n);
    let mut w = tower_to_flat_u128(Block128::ONE.0);
    for _ in 0..n {
        weights.push(w);
        w = clmul_gcm(w, gamma_flat);
    }
    weights
}

fn compute_batched_claim_flat(gamma: Block128, openings: &[Block128]) -> Block128 {
    use noid_core::hardware::{clmul_gcm, flat_to_tower_u128, tower_to_flat_u128};
    let gamma_flat = tower_to_flat_u128(gamma.0);
    let mut weight = tower_to_flat_u128(Block128::ONE.0);
    let mut acc = 0u128;
    for opening in openings {
        acc ^= clmul_gcm(weight, tower_to_flat_u128(opening.0));
        weight = clmul_gcm(weight, gamma_flat);
    }
    Block128::from(flat_to_tower_u128(acc))
}

impl MixedOpeningProof {
    pub fn byte_len(&self) -> usize {
        let openings = self.all_openings.len() * 16;
        let fri = self.fri_proof.byte_len();
        openings + fri
    }
}
