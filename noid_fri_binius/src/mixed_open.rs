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

use noid_core::mle::eq::eq_ind_partial_eval;
use noid_core::mle::evaluate::evaluate_flat_with_scratch;
use noid_core::{AdditiveNTT, Block128, TowerField};
use noid_fri::code::{Code, LOG_RATE, RATE};
use noid_fri::hasher::CryptographicHasher;
use noid_fri::merkle::{compute_leaf_hashes, MerkleTree, VectorCommitment};
use noid_fri::Channel;
use rayon::prelude::*;
use std::time::{Duration, Instant};

use crate::compact_fri::{
    compact_fri_prove_with_query_hook, compact_fri_verify_with_query_hook, gen_compact_queries,
    CompactEvalProof, CompactFriQueryContext,
};
use crate::interleaved_commit::{
    build_short_batched_merkle_proof, short_hash_to_output, source_leaf_hash,
    source_leaf_positions, source_root_short_from_cap, source_tree_depth,
    verify_short_batched_merkle_proof, InterleavedProverState, ShortBatchedMerkleProof, ShortHash,
    ShortMerkleTree,
};

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

/// Source binding proof for the compact FRI round-0 oracle.
///
/// The proof binds the small tensor-batched table `H` to the encoded source
/// columns with high-variable TensorFold path checks.  The verifier then
/// computes `g = H * eq_right`, encodes `Code(g)`, and requires its root to be
/// the compact FRI round-0 root.  This closes the B2/G gap without a standalone
/// prover-chosen FRI oracle.
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct SourceBindingProof {
    /// Tensor-batched low table H.  Length is `2^(log_rows - tau)`; in the
    /// current production shapes this is 8 for block/Auth and 256 for state
    /// segments, so direct reveal is cheaper and simpler than a second low PCS.
    pub h_evals: Vec<Block128>,
    /// Merkle roots for intermediate high TensorFold layers after source round
    /// 0 and before the final revealed H layer. Length is `tau - 1`.
    pub folded_roots: Vec<ShortHash>,
    /// For each source-binding query, serialized as column-major high pairs:
    /// `[col0_s0, col0_s1, col1_s0, col1_s1, ...]`.
    pub source_symbols: Vec<Block128>,
    /// Batched Merkle proof against the encoded interleaved source root.
    pub source_merkle_batch: ShortBatchedMerkleProof,
    /// Per intermediate high-folded layer queried high pairs.
    pub folded_queried_symbols: Vec<Vec<(Block128, Block128)>>,
    /// Batched Merkle proofs for `folded_roots`.
    pub folded_merkle_batch: Vec<ShortBatchedMerkleProof>,
}

/// Proof of mixed-point opening.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct MixedOpeningProof {
    /// Per-column evaluations at primary_point (first n_cols entries),
    /// followed by secondary claim values.
    pub all_openings: Vec<Block128>,
    /// Compact FRI proof of the gamma-batched polynomial at primary_point.
    /// Kept for current recursive/replay compatibility; source binding is
    /// enforced by `source_proof` below.
    pub fri_proof: CompactEvalProof,
    /// Source binding proof tying the batched opening oracle to the committed
    /// interleaved columns.
    pub source_proof: SourceBindingProof,
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
    let c_evals: Vec<Block128> = if n_cols == 1 {
        state.raw_cols[0].to_vec()
    } else {
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
        c_evals_flat
            .into_iter()
            .map(|v| Block128::from(flat_to_tower_u128(v)))
            .collect()
    };
    profiler.phase("batched_polynomial");

    // Prove C(primary_point) via compact FRI.  The source-binding hook absorbs
    // the H/table commitments before compact FRI draws query indices, so the
    // FRI round-0 oracle cannot be chosen independently of the committed source.
    let (fri_proof, _fri_query_info, source_proof) = compact_fri_prove_with_query_hook(
        &c_evals,
        primary_point,
        ntt,
        channel,
        hasher,
        num_queries,
        |ctx, channel| {
            prove_source_binding(
                state,
                &c_evals,
                primary_point,
                ctx,
                ntt,
                channel,
                hasher,
                num_queries,
            )
        },
    );
    let _ = gamma; // gamma is bound in the source verifier through source symbols.
    profiler.phase("compact_fri_and_source_binding_prove");

    let proof = MixedOpeningProof {
        all_openings,
        fri_proof,
        source_proof,
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
    for (i, claim) in secondary_claims.iter().enumerate() {
        if claim.col_index >= n_cols {
            return Err(format!(
                "Secondary claim column out of range: col_index={} n_cols={}",
                claim.col_index, n_cols
            ));
        }
        if claim.eval_point.len() != log_n {
            return Err(format!(
                "Secondary claim eval point dimension mismatch at index {i}: expected {log_n}, got {}",
                claim.eval_point.len()
            ));
        }
        let opening = proof.all_openings[n_cols + i];
        if opening != claim.value {
            return Err(format!(
                "Secondary claim value mismatch at index {i}: opening {:?} != claim {:?}",
                opening, claim.value
            ));
        }
    }

    // Absorb openings, draw gamma (mirror prover)
    channel.observe_field_elem(Block128::from(MIXED_OPEN_TAG));
    channel.observe_field_elems(&proof.all_openings);
    let gamma = channel.get_random_point();

    // Compute batched claim for primary columns in flat/GCM basis.
    let batched_claim = compute_batched_claim_flat(gamma, &proof.all_openings[..n_cols]);

    // Verify compact FRI proof and, before its query indices are drawn, bind
    // the round-0 oracle to the committed encoded source columns.
    compact_fri_verify_with_query_hook(
        primary_point,
        batched_claim,
        &proof.fri_proof,
        ntt,
        channel,
        hasher,
        num_queries,
        |ctx, channel| {
            verify_source_binding(
                commitment,
                gamma,
                primary_point,
                &proof.source_proof,
                ctx,
                ntt,
                channel,
                hasher,
                num_queries,
            )
        },
    )?;

    // Return primary openings (first n_cols entries)
    Ok(proof.all_openings[..n_cols].to_vec())
}

const MIXED_SOURCE_BINDING_TAG: u128 = 0x5B1D_0000_0000_0001u128;

struct HighFoldLayer {
    log_rows: usize,
    code: Option<Code>,
    tree: ShortMerkleTree,
}

#[allow(clippy::too_many_arguments)]
fn prove_source_binding(
    state: &InterleavedProverState<'_>,
    c_evals: &[Block128],
    primary_point: &[Block128],
    ctx: &CompactFriQueryContext,
    ntt: &AdditiveNTT<Block128>,
    channel: &mut Channel,
    hasher: &dyn CryptographicHasher,
    num_queries: usize,
) -> SourceBindingProof {
    let log_n = state.log_rows;
    let n_cols = state.n_cols;
    assert_eq!(primary_point.len(), log_n);
    assert_eq!(ctx.tau + ctx.n_rounds, log_n);
    assert_eq!(state.encoded_cols.len(), n_cols);
    assert_eq!(c_evals.len(), 1usize << log_n);

    let profile = prove_profile_enabled() && log_n >= 20;
    let profile_started = Instant::now();
    let mut profile_last = profile_started;
    let mut profile_phase = |name: &'static str| {
        if profile {
            let now = Instant::now();
            eprintln!(
                "prove_block_profile source_binding phase log_n={} n_cols={} phase={} elapsed_ms={:.3}",
                log_n,
                n_cols,
                name,
                duration_ms(now.duration_since(profile_last))
            );
            profile_last = now;
        }
    };

    let (h_evals, folded_layers) = if n_cols == 1 {
        build_high_tensor_layers_from_source_code(
            c_evals,
            &state.encoded_cols[0],
            &ctx.tensor_batching_point,
            ctx.tau,
            hasher,
        )
    } else {
        build_high_tensor_layers(c_evals, &ctx.tensor_batching_point, ctx.tau, ntt, hasher)
    };
    profile_phase("build_high_tensor_layers");
    #[cfg(debug_assertions)]
    assert_source_h_matches_compact(primary_point, ctx, &h_evals, ntt, hasher)
        .expect("prover constructed inconsistent source H");
    #[cfg(not(debug_assertions))]
    assert_source_h_claim_matches_compact(primary_point, ctx, &h_evals)
        .expect("prover constructed inconsistent source H");

    let folded_roots: Vec<ShortHash> = folded_layers
        .iter()
        .map(|layer| layer.tree.get_root())
        .collect();
    profile_phase("folded_roots");

    observe_source_binding_commitments(channel, &folded_roots, &h_evals, log_n, ctx.tau);
    let query_indices = gen_compact_queries(channel, log_n + LOG_RATE, num_queries);
    let n_queries = query_indices.len();
    profile_phase("observe_and_queries");

    let source_pair_indices: Vec<usize> = query_indices
        .iter()
        .map(|&qi| high_pair_leaf_index(qi, log_n))
        .collect();
    let mut source_symbols = Vec::with_capacity(n_queries * n_cols * 2);
    for &leaf_idx in &source_pair_indices {
        let (pos0, pos1) = source_leaf_positions(log_n, leaf_idx);
        for col in &state.encoded_cols {
            source_symbols.push(col[pos0]);
            source_symbols.push(col[pos1]);
        }
    }
    profile_phase("source_symbols");
    let source_merkle_batch = build_short_batched_merkle_proof(
        &state.source_tree,
        &source_pair_indices,
        source_tree_depth(log_n),
    );
    profile_phase("source_merkle_batch");

    let mut folded_queried_symbols = Vec::with_capacity(folded_layers.len());
    let mut folded_merkle_batch = Vec::with_capacity(folded_layers.len());
    let mut current_indices: Vec<usize> = source_pair_indices.clone();
    for layer in &folded_layers {
        let pair_indices: Vec<usize> = current_indices
            .iter()
            .map(|&idx| high_pair_leaf_index(idx, layer.log_rows))
            .collect();
        let mut symbols = Vec::with_capacity(n_queries);
        for &pair_idx in &pair_indices {
            let (pos0, pos1) = high_pair_positions(layer.log_rows, pair_idx);
            symbols.push((layer.code.idx(pos0), layer.code.idx(pos1)));
        }
        let batch = build_short_batched_merkle_proof(
            &layer.tree,
            &pair_indices,
            high_pair_tree_depth(layer.log_rows),
        );
        folded_queried_symbols.push(symbols);
        folded_merkle_batch.push(batch);
        current_indices = pair_indices;
    }
    profile_phase("folded_queries_and_batches");
    if profile {
        eprintln!(
            "prove_block_profile source_binding summary log_n={} n_cols={} total_ms={:.3}",
            log_n,
            n_cols,
            duration_ms(profile_started.elapsed())
        );
    }

    SourceBindingProof {
        h_evals,
        folded_roots,
        source_symbols,
        source_merkle_batch,
        folded_queried_symbols,
        folded_merkle_batch,
    }
}

#[allow(clippy::too_many_arguments)]
fn verify_source_binding(
    commitment: &crate::interleaved_commit::InterleavedCommitment,
    gamma: Block128,
    primary_point: &[Block128],
    proof: &SourceBindingProof,
    ctx: &CompactFriQueryContext,
    ntt: &AdditiveNTT<Block128>,
    channel: &mut Channel,
    hasher: &dyn CryptographicHasher,
    num_queries: usize,
) -> Result<(), String> {
    let log_n = commitment.log_rows;
    let n_cols = commitment.n_cols;
    if primary_point.len() != log_n {
        return Err("source binding point dimension mismatch".into());
    }
    if ctx.tau + ctx.n_rounds != log_n {
        return Err("source binding compact context dimension mismatch".into());
    }
    if proof.h_evals.len() != (1usize << ctx.n_rounds) {
        return Err(format!(
            "source binding H length mismatch: expected {}, got {}",
            1usize << ctx.n_rounds,
            proof.h_evals.len()
        ));
    }
    let expected_layers = ctx.tau.saturating_sub(1);
    if proof.folded_roots.len() != expected_layers
        || proof.folded_queried_symbols.len() != expected_layers
        || proof.folded_merkle_batch.len() != expected_layers
    {
        return Err("source binding high-fold round count mismatch".into());
    }

    assert_source_h_matches_compact(primary_point, ctx, &proof.h_evals, ntt, hasher)?;
    observe_source_binding_commitments(
        channel,
        &proof.folded_roots,
        &proof.h_evals,
        log_n,
        ctx.tau,
    );
    let query_indices = gen_compact_queries(channel, log_n + LOG_RATE, num_queries);
    let n_queries = query_indices.len();
    if proof.source_symbols.len() != n_queries * n_cols * 2 {
        return Err(format!(
            "source binding source symbol length mismatch: expected {}, got {}",
            n_queries * n_cols * 2,
            proof.source_symbols.len()
        ));
    }

    let source_root = source_root_short_from_cap(&commitment.cap)
        .ok_or_else(|| "missing short source root in interleaved commitment".to_string())?;
    let source_pair_indices: Vec<usize> = query_indices
        .iter()
        .map(|&qi| high_pair_leaf_index(qi, log_n))
        .collect();
    let mut source_leaf_hashes = Vec::with_capacity(n_queries);
    for query_idx in 0..n_queries {
        let start = query_idx * n_cols * 2;
        let end = start + n_cols * 2;
        source_leaf_hashes.push(source_leaf_hash(
            log_n,
            n_cols,
            source_pair_indices[query_idx],
            &proof.source_symbols[start..end],
        ));
    }
    verify_short_batched_merkle_proof(
        &source_root,
        &proof.source_merkle_batch,
        source_tree_depth(log_n),
        &source_pair_indices,
        &source_leaf_hashes,
    )?;

    let weights_flat = compute_horner_weights_flat(gamma, n_cols);
    let mut folded_symbols = Vec::with_capacity(n_queries);
    for query_idx in 0..n_queries {
        let start = query_idx * n_cols * 2;
        let source_pair = reduce_source_pair_flat(
            &proof.source_symbols[start..start + n_cols * 2],
            &weights_flat,
        );
        folded_symbols.push(tensor_high_fold_pair(
            ctx.tensor_batching_point[ctx.tau - 1],
            log_n,
            source_pair_indices[query_idx],
            source_pair.0,
            source_pair.1,
        ));
    }

    let mut current_indices = source_pair_indices;
    for (layer_idx, symbols) in proof.folded_queried_symbols.iter().enumerate() {
        let layer_log = log_n - 1 - layer_idx;
        if symbols.len() != n_queries {
            return Err(format!(
                "source binding symbol count mismatch at high layer {layer_idx}: expected {n_queries}, got {}",
                symbols.len()
            ));
        }
        let pair_indices: Vec<usize> = current_indices
            .iter()
            .map(|&idx| high_pair_leaf_index(idx, layer_log))
            .collect();
        let leaf_hashes: Vec<ShortHash> = symbols
            .iter()
            .zip(pair_indices.iter())
            .map(|(&(s0, s1), &pair_idx)| high_pair_leaf_hash(layer_log, pair_idx, s0, s1))
            .collect();
        verify_short_batched_merkle_proof(
            &proof.folded_roots[layer_idx],
            &proof.folded_merkle_batch[layer_idx],
            high_pair_tree_depth(layer_log),
            &pair_indices,
            &leaf_hashes,
        )?;

        let r = ctx.tensor_batching_point[ctx.tau - 2 - layer_idx];
        let mut next_folded = Vec::with_capacity(n_queries);
        for query_idx in 0..n_queries {
            let (s0, s1) = symbols[query_idx];
            let expected = if high_pair_parity(current_indices[query_idx], layer_log) == 1 {
                s1
            } else {
                s0
            };
            if folded_symbols[query_idx] != expected {
                return Err(format!(
                    "source binding high-fold path inconsistency at query {query_idx} layer {layer_idx}"
                ));
            }
            next_folded.push(tensor_high_fold_pair(
                r,
                layer_log,
                pair_indices[query_idx],
                s0,
                s1,
            ));
        }
        folded_symbols = next_folded;
        current_indices = pair_indices;
    }

    let h_code = Code::new_parallel(&proof.h_evals, ntt);
    for (query_idx, folded) in folded_symbols.iter().enumerate() {
        let expected = h_code.idx(current_indices[query_idx]);
        if *folded != expected {
            return Err(format!(
                "source binding H-code mismatch at query {query_idx}: got {folded:?} expected {expected:?}"
            ));
        }
    }

    Ok(())
}

fn observe_source_binding_commitments(
    channel: &mut Channel,
    folded_roots: &[ShortHash],
    h_evals: &[Block128],
    log_n: usize,
    tau: usize,
) {
    channel.observe_field_elem(Block128::from(MIXED_SOURCE_BINDING_TAG));
    channel.observe_field_elems(h_evals);
    for (i, &root) in folded_roots.iter().enumerate() {
        let layer_log = log_n - 1 - i;
        debug_assert!(i + 1 < tau);
        channel.observe_vector_commitment(&VectorCommitment {
            root: short_hash_to_output(root),
            depth: high_pair_tree_depth(layer_log),
        });
    }
}

fn build_high_tensor_layers(
    c_evals: &[Block128],
    beta: &[Block128],
    tau: usize,
    ntt: &AdditiveNTT<Block128>,
    hasher: &dyn CryptographicHasher,
) -> (Vec<Block128>, Vec<HighFoldLayer>) {
    let log_n = c_evals.len().trailing_zeros() as usize;
    let mut current = c_evals.to_vec();
    let mut layers = Vec::with_capacity(tau.saturating_sub(1));
    for round in 0..tau {
        let r = beta[tau - 1 - round];
        fold_highest_mle_eq_in_place(&mut current, r);
        let layer_log = log_n - 1 - round;
        if round + 1 < tau {
            let code = Code::new_parallel(&current, ntt);
            let tree = build_high_pair_tree(&code, layer_log, hasher);
            layers.push(HighFoldLayer {
                log_rows: layer_log,
                code,
                tree,
            });
        }
    }
    (current, layers)
}

fn build_high_tensor_layers_from_source_code(
    c_evals: &[Block128],
    source_code: &[Block128],
    beta: &[Block128],
    tau: usize,
    hasher: &dyn CryptographicHasher,
) -> (Vec<Block128>, Vec<HighFoldLayer>) {
    let log_n = c_evals.len().trailing_zeros() as usize;
    assert_eq!(c_evals.len(), 1usize << log_n);
    assert_eq!(source_code.len(), RATE * (1usize << log_n));

    let profile = prove_profile_enabled() && log_n >= 20;
    let mut mle_fold_total = Duration::ZERO;
    let mut direct_code_total = Duration::ZERO;
    let mut tree_total = Duration::ZERO;

    let mut current = c_evals.to_vec();
    let mut layers: Vec<HighFoldLayer> = Vec::with_capacity(tau.saturating_sub(1));
    for round in 0..tau {
        let r = beta[tau - 1 - round];
        let fold_t0 = Instant::now();
        fold_highest_mle_eq_in_place(&mut current, r);
        mle_fold_total += fold_t0.elapsed();
        if round + 1 >= tau {
            continue;
        }

        let before_layer_log = log_n - round;
        let layer_log = before_layer_log - 1;
        let input_code: &[Block128] = if round == 0 {
            source_code
        } else {
            &layers[round - 1].code.encoding
        };
        let out_len = RATE * (1usize << layer_log);
        let code_t0 = Instant::now();
        let encoding: Vec<Block128> = (0..out_len)
            .into_par_iter()
            .map(|leaf_idx| {
                let (pos0, pos1) = high_pair_positions(before_layer_log, leaf_idx);
                tensor_high_fold_pair(
                    r,
                    before_layer_log,
                    leaf_idx,
                    input_code[pos0],
                    input_code[pos1],
                )
            })
            .collect();
        direct_code_total += code_t0.elapsed();
        let code = Code { encoding };
        let tree_t0 = Instant::now();
        let tree = build_high_pair_tree(&code, layer_log, hasher);
        tree_total += tree_t0.elapsed();
        layers.push(HighFoldLayer {
            log_rows: layer_log,
            code,
            tree,
        });
    }
    if profile {
        eprintln!(
            "prove_block_profile source_binding_direct_layers log_n={} tau={} mle_fold_ms={:.3} direct_code_ms={:.3} tree_ms={:.3}",
            log_n,
            tau,
            duration_ms(mle_fold_total),
            duration_ms(direct_code_total),
            duration_ms(tree_total)
        );
    }
    (current, layers)
}

#[cfg(test)]
fn fold_highest_mle_eq(evals: &[Block128], r: Block128) -> Vec<Block128> {
    let mut out = evals.to_vec();
    fold_highest_mle_eq_in_place(&mut out, r);
    out
}

fn fold_highest_mle_eq_in_place(evals: &mut Vec<Block128>, r: Block128) {
    let half = evals.len() / 2;
    if half >= 1024 {
        let (lo, hi) = evals.split_at_mut(half);
        lo.par_iter_mut().zip(hi.par_iter()).for_each(|(l, &h)| {
            *l = *l + r * (*l + h);
        });
    } else {
        for i in 0..half {
            evals[i] = evals[i] + r * (evals[i] + evals[i + half]);
        }
    }
    evals.truncate(half);
}

fn assert_source_h_claim_matches_compact(
    primary_point: &[Block128],
    ctx: &CompactFriQueryContext,
    h_evals: &[Block128],
) -> Result<(), String> {
    let right = &primary_point[..ctx.n_rounds];
    let h_at_right = mle_evaluate_small(h_evals, right);
    if h_at_right != ctx.initial_sumcheck_claim {
        return Err("source binding H(right) does not match compact tensor claim".into());
    }
    Ok(())
}

fn assert_source_h_matches_compact(
    primary_point: &[Block128],
    ctx: &CompactFriQueryContext,
    h_evals: &[Block128],
    ntt: &AdditiveNTT<Block128>,
    hasher: &dyn CryptographicHasher,
) -> Result<(), String> {
    assert_source_h_claim_matches_compact(primary_point, ctx, h_evals)?;
    let right = &primary_point[..ctx.n_rounds];
    let eq_right = eq_ind_partial_eval(right);
    let g_evals: Vec<Block128> = h_evals
        .iter()
        .zip(eq_right.iter())
        .map(|(&h, &e)| h * e)
        .collect();
    let g_code = Code::new_parallel(&g_evals, ntt);
    if ctx.n_rounds == 0 {
        if g_code.encoding != ctx.final_codeword {
            return Err("source binding Code(H) final codeword mismatch".into());
        }
        return Ok(());
    }

    let leaf_hashes = compute_leaf_hashes(&g_code.encoding, hasher);
    let tree = MerkleTree::new_parallel(leaf_hashes, hasher);
    if ctx.fri_roots.first().copied() != Some(tree.get_root()) {
        return Err(
            "source binding Code(H*eq_right) root does not match compact FRI round-0 root".into(),
        );
    }
    Ok(())
}

fn mle_evaluate_small(evals: &[Block128], point: &[Block128]) -> Block128 {
    if point.is_empty() {
        return evals[0];
    }
    let mut buf = evals.to_vec();
    for &r in point.iter().rev() {
        let half = buf.len() / 2;
        for i in 0..half {
            buf[i] = buf[i] + r * (buf[i] + buf[i + half]);
        }
        buf.truncate(half);
    }
    buf[0]
}

fn high_pair_tree_depth(layer_log: usize) -> usize {
    layer_log + LOG_RATE - 1
}

fn high_pair_leaf_index(code_index: usize, layer_log: usize) -> usize {
    debug_assert!(layer_log > 0);
    let local_mask = (1usize << layer_log) - 1;
    let local = code_index & local_mask;
    let coset = code_index >> layer_log;
    let low = local & ((1usize << (layer_log - 1)) - 1);
    (coset << (layer_log - 1)) | low
}

fn high_pair_parity(code_index: usize, layer_log: usize) -> usize {
    let local = code_index & ((1usize << layer_log) - 1);
    (local >> (layer_log - 1)) & 1
}

fn high_pair_positions(layer_log: usize, leaf_index: usize) -> (usize, usize) {
    debug_assert!(layer_log > 0);
    let half = 1usize << (layer_log - 1);
    let local = leaf_index & (half - 1);
    let coset = leaf_index >> (layer_log - 1);
    let base = coset * (1usize << layer_log) + local;
    (base, base + half)
}

fn tensor_high_fold_pair(
    r: Block128,
    layer_log: usize,
    leaf_index: usize,
    s0: Block128,
    s1: Block128,
) -> Block128 {
    let coset = leaf_index >> (layer_log - 1);
    let basis_idx = coset + layer_log - 1;
    let basis = Block128::from(1u128 << basis_idx);
    s1 + (basis + Block128::ONE + r) * s0
}

fn high_pair_leaf_hash(
    layer_log: usize,
    leaf_index: usize,
    s0: Block128,
    s1: Block128,
) -> ShortHash {
    let mut h = blake3::Hasher::new();
    h.update(b"PARANOID/MIXED-SOURCE-HIGH-FOLD-LEAF/128/v1");
    h.update(&(layer_log as u64).to_le_bytes());
    h.update(&(leaf_index as u64).to_le_bytes());
    h.update(&s0.0.to_le_bytes());
    h.update(&s1.0.to_le_bytes());
    let digest = h.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest.as_bytes()[..16]);
    out
}

fn build_high_pair_tree(
    code: &Code,
    layer_log: usize,
    _hasher: &dyn CryptographicHasher,
) -> ShortMerkleTree {
    let leaf_count = RATE * (1usize << (layer_log - 1));
    let leaf_hashes: Vec<ShortHash> = (0..leaf_count)
        .into_par_iter()
        .map(|leaf_idx| {
            let (pos0, pos1) = high_pair_positions(layer_log, leaf_idx);
            high_pair_leaf_hash(layer_log, leaf_idx, code.idx(pos0), code.idx(pos1))
        })
        .collect();
    ShortMerkleTree::new(leaf_hashes)
}

fn reduce_source_pair_flat(symbols: &[Block128], weights_flat: &[u128]) -> (Block128, Block128) {
    use noid_core::hardware::{clmul_gcm, flat_to_tower_u128, tower_to_flat_u128};
    assert_eq!(symbols.len(), weights_flat.len() * 2);
    let mut s0 = 0u128;
    let mut s1 = 0u128;
    for (col_idx, &weight) in weights_flat.iter().enumerate() {
        s0 ^= clmul_gcm(weight, tower_to_flat_u128(symbols[2 * col_idx].0));
        s1 ^= clmul_gcm(weight, tower_to_flat_u128(symbols[2 * col_idx + 1].0));
    }
    (
        Block128::from(flat_to_tower_u128(s0)),
        Block128::from(flat_to_tower_u128(s1)),
    )
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

impl SourceBindingProof {
    pub fn byte_len(&self) -> usize {
        let h = self.h_evals.len() * 16;
        let roots = self.folded_roots.len() * 16;
        let source_symbols = self.source_symbols.len() * 16;
        let source_batch = self.source_merkle_batch.siblings.len() * 16;
        let folded_symbols: usize = self
            .folded_queried_symbols
            .iter()
            .map(|v| v.len() * 2 * 16)
            .sum();
        let folded_batches: usize = self
            .folded_merkle_batch
            .iter()
            .map(|b| b.siblings.len() * 16)
            .sum();
        let total = h + roots + source_symbols + source_batch + folded_symbols + folded_batches;
        if std::env::var("NOID_SOURCE_BINDING_PROFILE").is_ok() {
            eprintln!(
                "source_binding bytes h={} roots={} source_symbols={} source_batch={} folded_symbols={} folded_batches={} total={}",
                h,
                roots,
                source_symbols,
                source_batch,
                folded_symbols,
                folded_batches,
                total
            );
        }
        total
    }
}

impl MixedOpeningProof {
    pub fn byte_len(&self) -> usize {
        let openings = self.all_openings.len() * 16;
        let fri = self.fri_proof.byte_len();
        let source = self.source_proof.byte_len();
        openings + fri + source
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::interleaved_commit::{absorb_cap, interleaved_commit, InterleavedCommitment};
    use noid_fri::hasher::Blake3Hasher;

    const TEST_LOG_ROWS: usize = 8;
    const TEST_NUM_QUERIES: usize = 2;

    fn test_columns() -> Vec<Vec<Block128>> {
        test_columns_with_log(TEST_LOG_ROWS)
    }

    fn test_columns_with_log(log_rows: usize) -> Vec<Vec<Block128>> {
        let n = 1usize << log_rows;
        vec![
            (0..n)
                .map(|i| Block128::from((i as u128).wrapping_mul(3) ^ 0x1234))
                .collect(),
            (0..n)
                .map(|i| Block128::from((i as u128).wrapping_mul(5) ^ 0xABCD))
                .collect(),
            (0..n)
                .map(|i| Block128::from((i as u128).wrapping_mul(7) ^ 0xCAFE))
                .collect(),
        ]
    }

    fn valid_fixture() -> (
        InterleavedCommitment,
        Vec<Block128>,
        Vec<EvalClaim>,
        MixedOpeningProof,
        AdditiveNTT<Block128>,
        Blake3Hasher,
    ) {
        valid_fixture_with_log(TEST_LOG_ROWS, TEST_NUM_QUERIES)
    }

    fn valid_fixture_with_log(
        log_rows: usize,
        num_queries: usize,
    ) -> (
        InterleavedCommitment,
        Vec<Block128>,
        Vec<EvalClaim>,
        MixedOpeningProof,
        AdditiveNTT<Block128>,
        Blake3Hasher,
    ) {
        let cols = test_columns_with_log(log_rows);
        let col_refs: Vec<&[Block128]> = cols.iter().map(Vec::as_slice).collect();
        let ntt = AdditiveNTT::<Block128>::new(log_rows + noid_fri::code::LOG_RATE);
        let hasher = Blake3Hasher::new();
        let (commitment, state) = interleaved_commit(&col_refs, &ntt, &hasher);
        let primary_point: Vec<Block128> = (0..log_rows)
            .map(|i| Block128::from(0x1000u128 + i as u128))
            .collect();
        let secondary_claims = vec![EvalClaim {
            col_index: 1,
            eval_point: (0..log_rows)
                .map(|i| Block128::from(0x2000u128 + i as u128))
                .collect(),
            value: Block128::from(0xDEAD_BEEFu128),
        }];

        let mut prover_channel = Channel::new();
        absorb_cap(&mut prover_channel, &commitment.cap);
        let proof = prove_mixed_opening(
            &state,
            &primary_point,
            &secondary_claims,
            &ntt,
            &mut prover_channel,
            &hasher,
            num_queries,
        );

        (
            commitment,
            primary_point,
            secondary_claims,
            proof,
            ntt,
            hasher,
        )
    }

    fn verify_with_claims(
        commitment: &InterleavedCommitment,
        primary_point: &[Block128],
        claims: &[EvalClaim],
        proof: &MixedOpeningProof,
        ntt: &AdditiveNTT<Block128>,
        hasher: &Blake3Hasher,
    ) -> Result<Vec<Block128>, String> {
        verify_with_claims_num_queries(
            commitment,
            primary_point,
            claims,
            proof,
            ntt,
            hasher,
            TEST_NUM_QUERIES,
        )
    }

    fn verify_with_claims_num_queries(
        commitment: &InterleavedCommitment,
        primary_point: &[Block128],
        claims: &[EvalClaim],
        proof: &MixedOpeningProof,
        ntt: &AdditiveNTT<Block128>,
        hasher: &Blake3Hasher,
        num_queries: usize,
    ) -> Result<Vec<Block128>, String> {
        let mut channel = Channel::new();
        absorb_cap(&mut channel, &commitment.cap);
        verify_mixed_opening(
            commitment,
            primary_point,
            claims,
            proof,
            ntt,
            &mut channel,
            hasher,
            num_queries,
        )
    }

    #[test]
    fn source_pair_reduction_matches_batched_code_symbols() {
        let cols = test_columns();
        let col_refs: Vec<&[Block128]> = cols.iter().map(Vec::as_slice).collect();
        let ntt = AdditiveNTT::<Block128>::new(TEST_LOG_ROWS + noid_fri::code::LOG_RATE);
        let hasher = Blake3Hasher::new();
        let (_commitment, state) = interleaved_commit(&col_refs, &ntt, &hasher);
        let gamma = Block128::from(0xBAD5_EEDu128);
        let weights_flat = compute_horner_weights_flat(gamma, state.n_cols);
        let n = 1usize << state.log_rows;

        let c_evals: Vec<Block128> = (0..n)
            .map(|row| {
                compute_batched_claim_flat(
                    gamma,
                    &cols.iter().map(|col| col[row]).collect::<Vec<_>>(),
                )
            })
            .collect();
        let c_code = Code::new_parallel(&c_evals, &ntt);

        for leaf_idx in 0..source_leaf_count_for_test(state.log_rows) {
            let (pos0, pos1) = source_leaf_positions(state.log_rows, leaf_idx);
            let mut symbols = Vec::with_capacity(state.n_cols * 2);
            for col in &state.encoded_cols {
                symbols.push(col[pos0]);
                symbols.push(col[pos1]);
            }
            let reduced = reduce_source_pair_flat(&symbols, &weights_flat);
            assert_eq!(reduced.0, c_code.idx(pos0), "pos0 mismatch leaf {leaf_idx}");
            assert_eq!(reduced.1, c_code.idx(pos1), "pos1 mismatch leaf {leaf_idx}");
        }
    }

    #[test]
    fn high_tensor_fold_matches_code_new_parallel() {
        let ntt = AdditiveNTT::<Block128>::new(TEST_LOG_ROWS + noid_fri::code::LOG_RATE);
        let mut current: Vec<Block128> = (0..(1usize << TEST_LOG_ROWS))
            .map(|i| Block128::from((i as u128).wrapping_mul(0x1_0001) ^ 0xA11CE))
            .collect();
        let beta: Vec<Block128> = (0..TEST_LOG_ROWS)
            .map(|i| Block128::from(0x7000u128 + i as u128))
            .collect();

        for round in 0..TEST_LOG_ROWS {
            let layer_log = TEST_LOG_ROWS - round;
            let r = beta[TEST_LOG_ROWS - 1 - round];
            let code_before = Code::new_parallel(&current, &ntt);
            let folded = fold_highest_mle_eq(&current, r);
            let code_after = Code::new_parallel(&folded, &ntt);
            for leaf_idx in 0..(RATE * (1usize << (layer_log - 1))) {
                let (pos0, pos1) = high_pair_positions(layer_log, leaf_idx);
                let got = tensor_high_fold_pair(
                    r,
                    layer_log,
                    leaf_idx,
                    code_before.idx(pos0),
                    code_before.idx(pos1),
                );
                assert_eq!(
                    got,
                    code_after.idx(leaf_idx),
                    "high TensorFold mismatch round {round} layer_log {layer_log} leaf {leaf_idx}"
                );
            }
            current = folded;
        }
    }

    #[test]
    fn source_code_high_tensor_layers_match_ntt_rebuild_path() {
        let log_rows = crate::compact_fri::COMPACT_TAU + 2;
        let tau = crate::compact_fri::COMPACT_TAU;
        let ntt = AdditiveNTT::<Block128>::new(log_rows + noid_fri::code::LOG_RATE);
        let hasher = Blake3Hasher::new();
        let c_evals: Vec<Block128> = (0..(1usize << log_rows))
            .map(|i| Block128::from((i as u128).wrapping_mul(0x10_0001) ^ 0xD1A6))
            .collect();
        let beta: Vec<Block128> = (0..tau)
            .map(|i| Block128::from(0x9100u128 + i as u128))
            .collect();
        let source_code = Code::new_parallel(&c_evals, &ntt);

        let (h_ref, layers_ref) = build_high_tensor_layers(&c_evals, &beta, tau, &ntt, &hasher);
        let (h_direct, layers_direct) = build_high_tensor_layers_from_source_code(
            &c_evals,
            &source_code.encoding,
            &beta,
            tau,
            &hasher,
        );

        assert_eq!(h_ref, h_direct);
        assert_eq!(layers_ref.len(), layers_direct.len());
        for (idx, (a, b)) in layers_ref.iter().zip(layers_direct.iter()).enumerate() {
            assert_eq!(a.log_rows, b.log_rows, "layer {idx} log_rows mismatch");
            assert_eq!(
                a.code.encoding, b.code.encoding,
                "layer {idx} code mismatch"
            );
            assert_eq!(
                a.tree.get_root(),
                b.tree.get_root(),
                "layer {idx} root mismatch"
            );
        }
    }

    fn source_leaf_count_for_test(log_rows: usize) -> usize {
        RATE * (1usize << (log_rows - 1))
    }

    #[test]
    fn valid_secondary_claim_hygiene_passes() {
        let (commitment, primary_point, claims, proof, ntt, hasher) = valid_fixture();
        verify_with_claims(&commitment, &primary_point, &claims, &proof, &ntt, &hasher)
            .expect("valid mixed opening must verify");
    }

    #[test]
    fn valid_round0_source_binding_path_passes() {
        let log_rows = crate::compact_fri::COMPACT_TAU + 2;
        let num_queries = 3;
        let (commitment, primary_point, claims, proof, ntt, hasher) =
            valid_fixture_with_log(log_rows, num_queries);
        verify_with_claims_num_queries(
            &commitment,
            &primary_point,
            &claims,
            &proof,
            &ntt,
            &hasher,
            num_queries,
        )
        .expect("valid mixed opening with compact FRI round-0 source binding must verify");
    }

    #[test]
    fn tampered_round0_fri_root_rejects_source_binding() {
        let log_rows = crate::compact_fri::COMPACT_TAU + 2;
        let num_queries = 3;
        let (commitment, primary_point, claims, mut proof, ntt, hasher) =
            valid_fixture_with_log(log_rows, num_queries);
        proof.fri_proof.fri_roots[0][0] ^= 1;
        let err = verify_with_claims_num_queries(
            &commitment,
            &primary_point,
            &claims,
            &proof,
            &ntt,
            &hasher,
            num_queries,
        )
        .expect_err("tampered compact FRI round-0 root must reject");
        assert!(
            err.contains(
                "source binding Code(H*eq_right) root does not match compact FRI round-0 root"
            ) || err.contains("FRI root mismatch")
                || err.contains("sumcheck failed"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn tampered_source_h_rejects_round0_binding() {
        let log_rows = crate::compact_fri::COMPACT_TAU + 2;
        let num_queries = 3;
        let (commitment, primary_point, claims, mut proof, ntt, hasher) =
            valid_fixture_with_log(log_rows, num_queries);
        proof.source_proof.h_evals[0] += Block128::ONE;
        let err = verify_with_claims_num_queries(
            &commitment,
            &primary_point,
            &claims,
            &proof,
            &ntt,
            &hasher,
            num_queries,
        )
        .expect_err("tampered source H table must reject");
        assert!(
            err.contains("source binding") || err.contains("FRI"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn secondary_claim_value_mismatch_rejects_before_fri() {
        let (commitment, primary_point, mut claims, proof, ntt, hasher) = valid_fixture();
        claims[0].value += Block128::ONE;
        let err = verify_with_claims(&commitment, &primary_point, &claims, &proof, &ntt, &hasher)
            .expect_err("mismatched secondary claim value must reject");
        assert!(
            err.contains("Secondary claim value mismatch"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn secondary_claim_column_out_of_range_rejects_before_fri() {
        let (commitment, primary_point, mut claims, proof, ntt, hasher) = valid_fixture();
        claims[0].col_index = commitment.n_cols;
        let err = verify_with_claims(&commitment, &primary_point, &claims, &proof, &ntt, &hasher)
            .expect_err("out-of-range secondary claim column must reject");
        assert!(
            err.contains("Secondary claim column out of range"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn secondary_claim_eval_point_dimension_mismatch_rejects_before_fri() {
        let (commitment, primary_point, mut claims, proof, ntt, hasher) = valid_fixture();
        claims[0].eval_point.pop();
        let err = verify_with_claims(&commitment, &primary_point, &claims, &proof, &ntt, &hasher)
            .expect_err("secondary claim dimension mismatch must reject");
        assert!(
            err.contains("Secondary claim eval point dimension mismatch"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn commit_to_a_open_from_a_prime_must_reject_after_s1_fix() {
        let log_rows = crate::compact_fri::COMPACT_TAU + 2;
        let num_queries = 3;
        let cols_a = test_columns_with_log(log_rows);
        let mut cols_b = cols_a.clone();
        for (col_idx, col) in cols_b.iter_mut().enumerate() {
            for (row_idx, value) in col.iter_mut().enumerate() {
                *value += Block128::from(
                    0xA5A5_0000_0000_0000u128 ^ ((col_idx as u128) << 16) ^ row_idx as u128,
                );
            }
        }

        let refs_a: Vec<&[Block128]> = cols_a.iter().map(Vec::as_slice).collect();
        let refs_b: Vec<&[Block128]> = cols_b.iter().map(Vec::as_slice).collect();
        let ntt = AdditiveNTT::<Block128>::new(log_rows + noid_fri::code::LOG_RATE);
        let hasher = Blake3Hasher::new();
        let (commitment_a, _state_a) = interleaved_commit(&refs_a, &ntt, &hasher);
        let (commitment_b, state_b) = interleaved_commit(&refs_b, &ntt, &hasher);
        assert_ne!(
            commitment_a.cap, commitment_b.cap,
            "test must use two distinct committed column sets"
        );

        let primary_point: Vec<Block128> = (0..log_rows)
            .map(|i| Block128::from(0x3000u128 + i as u128))
            .collect();
        let secondary_claims = Vec::new();

        // Malicious shape: the Fiat-Shamir prefix uses commitment A, while the
        // prover-side columns used to build all_openings and C(x) come from A'.
        // A source-bound PCS must reject this mixed state.
        let mut prover_channel = Channel::new();
        absorb_cap(&mut prover_channel, &commitment_a.cap);
        let proof_from_b = prove_mixed_opening(
            &state_b,
            &primary_point,
            &secondary_claims,
            &ntt,
            &mut prover_channel,
            &hasher,
            num_queries,
        );

        let result = verify_with_claims_num_queries(
            &commitment_a,
            &primary_point,
            &secondary_claims,
            &proof_from_b,
            &ntt,
            &hasher,
            num_queries,
        );
        assert!(
            result.is_err(),
            "S1 gap: verifier accepted an opening proof built from A' against commitment(A)"
        );
    }
}
