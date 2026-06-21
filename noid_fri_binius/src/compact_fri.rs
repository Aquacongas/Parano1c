// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

#![allow(clippy::needless_range_loop)]

//! Compact FRI prover/verifier optimized for the interleaved PCS.
//!
//! Key differences from the generic `noid_fri::prover`:
//! - TAU=8 (256 upper partials) instead of 7 (128) -> 5 FRI rounds instead of 6
//! - 64 queries with batched Merkle proof compression (proven 128-bit soundness)
//! - Batch Merkle paths deduplicate shared ancestors across queries (~40% savings)
//!
//! Proof size target: ~38KB (down from 70KB in the generic FRI)
//! - upper_partial_evals: 256 * 16 = 4 KB
//! - sum_check_oracles: 5 * 2 * 16 = 160 bytes
//! - fri_oracles (roots): 5 * 32 = 160 bytes
//! - queried symbols: 64 * 2 * 16 * 5 = 10.2 KB
//! - Merkle paths (batched): ~22 KB (vs 55 KB independent paths)
//! - final_codeword: 4 * 16 = 64 bytes

use noid_core::mle::eq::eq_ind_partial_eval;
use noid_core::{AdditiveNTT, Block128, TowerField};
use noid_fri::code::{fold, Code, LOG_RATE};
use noid_fri::hasher::{CryptographicHasher, HashOutput};
use noid_fri::merkle::{compute_leaf_hashes, MerkleTree, VectorCommitment};
use noid_fri::Channel;
use rayon::prelude::*;
use std::time::{Duration, Instant};

/// Compact FRI TAU: number of high variables handled by tensor decomposition.
/// TAU=8 means 2^8=256 upper partial evaluations and log_len-8 FRI rounds.
pub const COMPACT_TAU: usize = 8;

/// Number of FRI queries for full security. 64 queries with rate-4 code gives:
/// - Proven soundness: 64 * log2(4) = 128 bits
/// Uses batched Merkle proofs to compress shared ancestors,
/// yielding ~40% path savings vs independent per-query paths.
#[cfg(not(debug_assertions))]
pub const COMPACT_NUM_QUERIES: usize = 64;
#[cfg(debug_assertions)]
pub const COMPACT_NUM_QUERIES: usize = 8;

fn compact_profile_enabled() -> bool {
    std::env::var("NOID_PROVE_BLOCK_PROFILE")
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

fn compact_duration_ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1_000.0
}

// ---------------------------------------------------------------------------
// Proof structures
// ---------------------------------------------------------------------------

/// Compact FRI evaluation proof with batched Merkle paths.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct CompactEvalProof {
    /// Partial evaluations over the top COMPACT_TAU variables.
    pub upper_partial_evals: Vec<Block128>,
    /// Per-round degree-1 sumcheck oracles (2 coefficients each).
    pub sum_check_oracles: Vec<[Block128; 2]>,
    /// Per-round FRI oracle commitments (Merkle roots).
    pub fri_roots: Vec<HashOutput>,
    /// Per-round queried symbol pairs (s0, s1) for each query.
    pub fri_queried_symbols: Vec<Vec<(Block128, Block128)>>,
    /// Per-round compressed Merkle authentication: sorted unique nodes.
    /// Format: for each round, the set of all sibling hashes needed to
    /// reconstruct all query paths, stored in canonical DFS order.
    pub fri_merkle_batch: Vec<BatchedMerkleProof>,
    /// Final codeword after all folding rounds (RATE=4 symbols).
    pub final_codeword: Vec<Block128>,
}

/// Compressed Merkle proof for multiple query positions in one tree.
///
/// Instead of storing full independent paths (which repeat shared ancestors),
/// stores only the unique sibling nodes needed. The verifier reconstructs
/// all paths from this compact representation.
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct BatchedMerkleProof {
    /// Sibling hashes needed for reconstruction, in layer-by-layer order.
    /// For each layer (bottom to top), only siblings that are NOT already
    /// computable from transcript-derived query paths are included.
    pub siblings: Vec<HashOutput>,
}

impl CompactEvalProof {
    pub fn byte_len(&self) -> usize {
        let upper = self.upper_partial_evals.len() * 16;
        let sc = self.sum_check_oracles.len() * 2 * 16;
        let roots = self.fri_roots.len() * 32;
        let symbols: usize = self
            .fri_queried_symbols
            .iter()
            .map(|v| v.len() * 2 * 16)
            .sum();
        let paths: usize = self
            .fri_merkle_batch
            .iter()
            .map(|b| b.siblings.len() * 32)
            .sum();
        let final_cw = self.final_codeword.len() * 16;
        upper + sc + roots + symbols + paths + final_cw
    }
}

/// Compact-FRI transcript state at the point where all oracle roots/final
/// codeword have been absorbed, but query indices have not yet been drawn.
#[derive(Clone, Debug)]
pub(crate) struct CompactFriQueryContext {
    pub tau: usize,
    pub n_rounds: usize,
    pub tensor_batching_point: Vec<Block128>,
    pub initial_sumcheck_claim: Block128,
    /// Prover-only tensor-batched low table H. Verifier contexts leave this empty
    /// and use the serialized source-binding H instead.
    pub source_h_evals: Vec<Block128>,
    pub fri_roots: Vec<HashOutput>,
    pub final_codeword: Vec<Block128>,
}

/// Query information produced after optional extra roots are absorbed.
#[allow(dead_code)]
#[derive(Clone, Debug)]
pub(crate) struct CompactFriQueryInfo {
    pub tau: usize,
    pub n_rounds: usize,
    pub tensor_batching_point: Vec<Block128>,
    pub initial_sumcheck_claim: Block128,
    pub query_indices: Vec<usize>,
}

// ---------------------------------------------------------------------------
// Prover
// ---------------------------------------------------------------------------

/// Produce a compact FRI evaluation proof.
///
/// Same protocol as `noid_fri::prover::prove` but with COMPACT_TAU and
/// batched Merkle compression. `num_queries` controls the query count
/// (use `COMPACT_NUM_QUERIES` for full security).
pub fn compact_fri_prove(
    evals: &[Block128],
    eval_point: &[Block128],
    ntt: &AdditiveNTT<Block128>,
    channel: &mut Channel,
    hasher: &dyn CryptographicHasher,
    num_queries: usize,
) -> CompactEvalProof {
    let (proof, _, ()) = compact_fri_prove_with_query_hook(
        evals,
        eval_point,
        ntt,
        channel,
        hasher,
        num_queries,
        |_, _| (),
    );
    proof
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn compact_fri_prove_with_query_hook<E, F>(
    evals: &[Block128],
    eval_point: &[Block128],
    ntt: &AdditiveNTT<Block128>,
    channel: &mut Channel,
    hasher: &dyn CryptographicHasher,
    num_queries: usize,
    before_queries: F,
) -> (CompactEvalProof, CompactFriQueryInfo, E)
where
    F: FnOnce(&CompactFriQueryContext, &mut Channel) -> E,
{
    let profile = compact_profile_enabled() && eval_point.len() >= 20;
    let profile_started = Instant::now();
    let mut profile_last = profile_started;
    let mut profile_phase = |name: &'static str| {
        if profile {
            let now = Instant::now();
            eprintln!(
                "prove_block_profile compact_fri phase log_n={} phase={} elapsed_ms={:.3}",
                eval_point.len(),
                name,
                compact_duration_ms(now.duration_since(profile_last))
            );
            profile_last = now;
        }
    };

    channel.observe_field_elems(eval_point);

    let tau = COMPACT_TAU.min(eval_point.len());
    let n = eval_point.len();
    let (right, left) = eval_point.split_at(n - tau);

    // Upper partial evaluations.
    let n_rows = 1 << tau;
    let row_len = evals.len() / n_rows;
    let upper_partial_evals: Vec<Block128> = (0..n_rows)
        .into_par_iter()
        .map(|row| {
            let row_evals = &evals[row * row_len..(row + 1) * row_len];
            mle_evaluate(row_evals, right)
        })
        .collect();
    profile_phase("upper_partial_evals");

    let left_eq = eq_ind_partial_eval(left);
    let eval: Block128 = upper_partial_evals
        .iter()
        .zip(left_eq.iter())
        .map(|(&v, &e)| v * e)
        .fold(Block128::ZERO, |a, b| a + b);
    channel.observe_field_elem(eval);
    profile_phase("eval_claim");

    // Tensor batching.
    let tensor_batching_point = channel.get_random_points(tau);
    let batching_eq = eq_ind_partial_eval(&tensor_batching_point);

    let batched_evals: Vec<Block128> = if row_len >= 1024 {
        (0..row_len)
            .into_par_iter()
            .map(|j| {
                let mut acc = Block128::ZERO;
                for (row_idx, &coeff) in batching_eq.iter().enumerate() {
                    acc += coeff * evals[row_idx * row_len + j];
                }
                acc
            })
            .collect()
    } else {
        let mut out = vec![Block128::ZERO; row_len];
        for (row_idx, &coeff) in batching_eq.iter().enumerate() {
            for (j, val) in evals[row_idx * row_len..(row_idx + 1) * row_len]
                .iter()
                .enumerate()
            {
                out[j] += coeff * *val;
            }
        }
        out
    };
    profile_phase("tensor_batching");

    // FRI commit phase with sumcheck.
    let n_rounds = right.len();
    let eq_right = eq_ind_partial_eval(right);

    let sumcheck_evals: Vec<Block128> = if batched_evals.len() >= 1024 {
        batched_evals
            .par_iter()
            .zip(eq_right.par_iter())
            .map(|(&g, &e)| g * e)
            .collect()
    } else {
        batched_evals
            .iter()
            .zip(eq_right.iter())
            .map(|(&g, &e)| g * e)
            .collect()
    };
    profile_phase("sumcheck_evals");

    let sum_check_claim: Block128 = upper_partial_evals
        .iter()
        .zip(batching_eq.iter())
        .map(|(&u, &b)| u * b)
        .fold(Block128::ZERO, |a, x| a + x);

    let mut current_evals = sumcheck_evals;
    let mut sum_check_oracles: Vec<[Block128; 2]> = Vec::with_capacity(n_rounds);
    let mut fri_roots: Vec<HashOutput> = Vec::with_capacity(n_rounds);
    let mut fri_trees: Vec<MerkleTree> = Vec::with_capacity(n_rounds);
    let mut fri_codes: Vec<Code> = Vec::with_capacity(n_rounds);
    let mut current_code = Code::new_parallel(&current_evals, ntt);
    profile_phase("initial_code");
    let mut claim = sum_check_claim;
    let mut round_sumcheck_total = Duration::ZERO;
    let mut round_merkle_total = Duration::ZERO;
    let mut round_transcript_total = Duration::ZERO;
    let mut round_fold_total = Duration::ZERO;

    for round in 0..n_rounds {
        let round_t0 = Instant::now();
        let half = current_evals.len() / 2;
        let p0 = current_evals[..half]
            .iter()
            .fold(Block128::ZERO, |acc, &v| acc + v);
        let p1 = claim + p0;
        let c0 = p0;
        let c1 = p0 + p1;
        sum_check_oracles.push([c0, c1]);
        round_sumcheck_total += round_t0.elapsed();

        let merkle_t0 = Instant::now();
        let leaf_hashes = compute_leaf_hashes(&current_code.encoding, hasher);
        let tree = MerkleTree::new_parallel(leaf_hashes, hasher);
        let root = tree.get_root();
        let code_depth = current_code.encoding.len().trailing_zeros() as usize - 1;
        fri_roots.push(root);
        fri_trees.push(tree);
        round_merkle_total += merkle_t0.elapsed();

        // Transcript: oracle coeffs + root + squeeze challenge
        let transcript_t0 = Instant::now();
        channel.observe_field_elem(c0);
        channel.observe_field_elem(c1);
        let vc = VectorCommitment {
            root,
            depth: code_depth,
        };
        channel.observe_vector_commitment(&vc);
        let r = channel.get_random_point();
        round_transcript_total += transcript_t0.elapsed();

        let fold_t0 = Instant::now();
        claim = c0 + c1 * r;
        let next_code = current_code.fold_code(r, round, ntt);
        fri_codes.push(current_code);
        fold_evals_in_place(&mut current_evals, r);
        current_code = next_code;
        round_fold_total += fold_t0.elapsed();
    }

    if profile {
        eprintln!(
            "prove_block_profile compact_fri rounds log_n={} n_rounds={} sumcheck_ms={:.3} merkle_ms={:.3} transcript_ms={:.3} fold_ms={:.3}",
            eval_point.len(),
            n_rounds,
            compact_duration_ms(round_sumcheck_total),
            compact_duration_ms(round_merkle_total),
            compact_duration_ms(round_transcript_total),
            compact_duration_ms(round_fold_total)
        );
    }
    profile_phase("fri_commit_rounds");

    let final_codeword = current_code.encoding.clone();
    channel.observe_field_elems(&final_codeword);
    profile_phase("final_codeword");

    let context = CompactFriQueryContext {
        tau,
        n_rounds,
        tensor_batching_point: tensor_batching_point.clone(),
        initial_sumcheck_claim: sum_check_claim,
        source_h_evals: batched_evals,
        fri_roots: fri_roots.clone(),
        final_codeword: final_codeword.clone(),
    };
    let extra = before_queries(&context, channel);
    profile_phase("before_queries_hook");

    // Query phase with batched Merkle compression.
    let log_domain = n_rounds + LOG_RATE;
    let query_indices = gen_compact_queries(channel, log_domain, num_queries);
    profile_phase("query_indices");

    let mut fri_queried_symbols: Vec<Vec<(Block128, Block128)>> = Vec::with_capacity(n_rounds);
    let mut fri_merkle_batch: Vec<BatchedMerkleProof> = Vec::with_capacity(n_rounds);
    let mut query_symbols_total = Duration::ZERO;
    let mut query_batch_total = Duration::ZERO;

    for round in 0..n_rounds {
        let code = &fri_codes[round];
        let tree = &fri_trees[round];
        let depth = tree.num_layers() - 1;

        let mut symbols = Vec::with_capacity(query_indices.len());
        let mut pair_indices = Vec::with_capacity(query_indices.len());

        let query_symbols_t0 = Instant::now();
        for &qi in &query_indices {
            let scaled = qi >> round;
            let pair_idx = scaled >> 1;
            let s0 = code.idx(pair_idx * 2);
            let s1 = code.idx(pair_idx * 2 + 1);
            symbols.push((s0, s1));
            pair_indices.push(pair_idx);
        }
        query_symbols_total += query_symbols_t0.elapsed();

        let query_batch_t0 = Instant::now();
        let batch_proof = build_batched_merkle_proof(tree, &pair_indices, depth);
        query_batch_total += query_batch_t0.elapsed();
        fri_queried_symbols.push(symbols);
        fri_merkle_batch.push(batch_proof);
    }
    if profile {
        eprintln!(
            "prove_block_profile compact_fri query log_n={} n_rounds={} symbols_ms={:.3} batch_ms={:.3}",
            eval_point.len(),
            n_rounds,
            compact_duration_ms(query_symbols_total),
            compact_duration_ms(query_batch_total)
        );
    }
    profile_phase("query_phase");

    if profile {
        eprintln!(
            "prove_block_profile compact_fri summary log_n={} total_ms={:.3}",
            eval_point.len(),
            compact_duration_ms(profile_started.elapsed())
        );
    }

    let query_info = CompactFriQueryInfo {
        tau,
        n_rounds,
        tensor_batching_point,
        initial_sumcheck_claim: sum_check_claim,
        query_indices,
    };

    (
        CompactEvalProof {
            upper_partial_evals,
            sum_check_oracles,
            fri_roots,
            fri_queried_symbols,
            fri_merkle_batch,
            final_codeword,
        },
        query_info,
        extra,
    )
}

// ---------------------------------------------------------------------------
// Verifier
// ---------------------------------------------------------------------------

/// Verify a compact FRI evaluation proof.
pub fn compact_fri_verify(
    eval_point: &[Block128],
    eval: Block128,
    proof: &CompactEvalProof,
    ntt: &AdditiveNTT<Block128>,
    channel: &mut Channel,
    hasher: &dyn CryptographicHasher,
    num_queries: usize,
) -> Result<(), String> {
    compact_fri_verify_with_query_hook(
        eval_point,
        eval,
        proof,
        ntt,
        channel,
        hasher,
        num_queries,
        |_, _| Ok(()),
    )
    .map(|_| ())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn compact_fri_verify_with_query_hook<E, F>(
    eval_point: &[Block128],
    eval: Block128,
    proof: &CompactEvalProof,
    ntt: &AdditiveNTT<Block128>,
    channel: &mut Channel,
    hasher: &dyn CryptographicHasher,
    num_queries: usize,
    before_queries: F,
) -> Result<(CompactFriQueryInfo, E), String>
where
    F: FnOnce(&CompactFriQueryContext, &mut Channel) -> Result<E, String>,
{
    channel.observe_field_elems(eval_point);

    let tau = COMPACT_TAU.min(eval_point.len());
    let n = eval_point.len();
    let (right, left) = eval_point.split_at(n - tau);

    let expected_upper = 1usize << tau;
    if proof.upper_partial_evals.len() != expected_upper {
        return Err(format!(
            "upper_partial_evals length mismatch: expected {}, got {}",
            expected_upper,
            proof.upper_partial_evals.len()
        ));
    }

    // Verify eval = sum eq(left, i) * upper_partial_evals[i]
    let left_eq = eq_ind_partial_eval(left);
    let mut derived_eval = Block128::ZERO;
    for (&lhs, &rhs) in left_eq.iter().zip(proof.upper_partial_evals.iter()) {
        derived_eval += lhs * rhs;
    }
    if derived_eval != eval {
        return Err("derived eval does not match claimed eval".into());
    }
    channel.observe_field_elem(eval);

    // Tensor batching
    let tensor_batching_point = channel.get_random_points(tau);
    let batching_eq = eq_ind_partial_eval(&tensor_batching_point);
    let mut claim: Block128 = proof
        .upper_partial_evals
        .iter()
        .zip(batching_eq.iter())
        .map(|(&u, &b)| u * b)
        .fold(Block128::ZERO, |a, x| a + x);
    let initial_sumcheck_claim = claim;

    // Verify sumcheck rounds
    let n_rounds = right.len();
    if proof.sum_check_oracles.len() != n_rounds
        || proof.fri_roots.len() != n_rounds
        || proof.fri_queried_symbols.len() != n_rounds
        || proof.fri_merkle_batch.len() != n_rounds
    {
        return Err("round count mismatch".into());
    }

    let mut random_point = Vec::with_capacity(n_rounds);
    for round in 0..n_rounds {
        let [c0, c1] = proof.sum_check_oracles[round];
        // p(0) + p(1) = c0 + (c0 + c1) = c1 (char 2). Must equal claim.
        if c1 != claim {
            return Err(format!("sumcheck failed at round {round}"));
        }

        channel.observe_field_elem(c0);
        channel.observe_field_elem(c1);
        let depth = compute_round_depth(n_rounds, round);
        let vc = VectorCommitment {
            root: proof.fri_roots[round],
            depth,
        };
        channel.observe_vector_commitment(&vc);
        let r = channel.get_random_point();
        random_point.push(r);
        claim = c0 + c1 * r;
    }

    // Absorb final codeword
    if proof.final_codeword.is_empty() {
        return Err("empty final codeword".into());
    }
    channel.observe_field_elems(&proof.final_codeword);

    let context = CompactFriQueryContext {
        tau,
        n_rounds,
        tensor_batching_point: tensor_batching_point.clone(),
        initial_sumcheck_claim,
        source_h_evals: Vec::new(),
        fri_roots: proof.fri_roots.clone(),
        final_codeword: proof.final_codeword.clone(),
    };
    let extra = before_queries(&context, channel)?;

    // Generate query indices (must match prover)
    let log_domain = n_rounds + LOG_RATE;
    let query_indices = gen_compact_queries(channel, log_domain, num_queries);
    let n_queries = query_indices.len();

    // Verify each round
    let mut folded_symbols: Vec<Option<Block128>> = vec![None; n_queries];

    for round in 0..n_rounds {
        let symbols = &proof.fri_queried_symbols[round];
        let batch = &proof.fri_merkle_batch[round];

        if symbols.len() != n_queries {
            return Err(format!("symbol count mismatch at round {round}"));
        }

        // Fold-consistency check
        for i in 0..n_queries {
            if round > 0 {
                let qi = query_indices[i];
                let scaled = qi >> round;
                let parity = scaled & 1;
                let (s0, s1) = symbols[i];
                let expected = if parity == 1 { s1 } else { s0 };
                if folded_symbols[i] != Some(expected) {
                    return Err(format!("symbol inconsistency at query {i} round {round}"));
                }
            }
        }

        // Verify batched Merkle proof
        let pair_indices: Vec<usize> = query_indices.iter().map(|&qi| (qi >> round) >> 1).collect();

        let leaf_hashes: Vec<HashOutput> = symbols
            .iter()
            .map(|&(s0, s1)| hasher.hash_pair(&s0, &s1))
            .collect();

        verify_batched_merkle_proof(
            &proof.fri_roots[round],
            batch,
            compute_round_depth(n_rounds, round),
            &pair_indices,
            &leaf_hashes,
            hasher,
        )?;

        // Compute folds
        let new_folded: Vec<Option<Block128>> = query_indices
            .iter()
            .zip(symbols.iter())
            .map(|(&qi, &(s0, s1))| {
                let scaled = qi >> round;
                let pair_idx = scaled >> 1;
                Some(fold(random_point[round], round, pair_idx, s0, s1, ntt))
            })
            .collect();
        folded_symbols = new_folded;
    }

    // Final codeword check
    let final_len = proof.final_codeword.len();
    for (i, sym) in folded_symbols.iter().enumerate() {
        if let Some(s) = sym {
            let qi = query_indices[i];
            let final_idx = qi >> n_rounds;
            let expected = proof.final_codeword[final_idx % final_len];
            if *s != expected {
                return Err(format!("final codeword mismatch at query {i}"));
            }
        }
    }

    let query_info = CompactFriQueryInfo {
        tau,
        n_rounds,
        tensor_batching_point,
        initial_sumcheck_claim,
        query_indices,
    };

    Ok((query_info, extra))
}

// ---------------------------------------------------------------------------
// Batched Merkle proof construction and verification
// ---------------------------------------------------------------------------

/// Build a compressed Merkle proof for multiple leaf indices.
///
/// Instead of storing N independent paths (each with `depth` siblings),
/// identifies which sibling nodes are NOT derivable from other query leaves
/// and stores only those. Nodes that appear as query leaves or as
/// computable parents of query leaves are omitted.
pub(crate) fn build_batched_merkle_proof(
    tree: &MerkleTree,
    leaf_indices: &[usize],
    depth: usize,
) -> BatchedMerkleProof {
    // Collect all node indices that we can derive from the queries themselves.
    // A node at (layer, idx) is "known" if:
    //   - It's a query leaf, OR
    //   - Both its children are known (computable via hashing)
    //
    // We only need to include siblings that are NOT known.

    let mut siblings = Vec::new();
    let mut known_at_layer: Vec<std::collections::HashSet<usize>> =
        vec![std::collections::HashSet::new(); depth + 1];

    // Layer 0 (leaves) — mark all query positions as known
    for &idx in leaf_indices {
        known_at_layer[0].insert(idx);
    }

    // Bottom-up: determine which siblings we need
    for d in 0..depth {
        let mut parents_needed: std::collections::BTreeSet<usize> =
            std::collections::BTreeSet::new();
        for &idx in &known_at_layer[d] {
            parents_needed.insert(idx >> 1);
        }

        for &parent in &parents_needed {
            let left_child = parent * 2;
            let right_child = parent * 2 + 1;
            let left_known = known_at_layer[d].contains(&left_child);
            let right_known = known_at_layer[d].contains(&right_child);

            if left_known && right_known {
                // Both children known — parent is computable
                known_at_layer[d + 1].insert(parent);
            } else if left_known {
                // Need right sibling
                let sibling_hash = tree.get_node_at_depth(depth - d, right_child);
                siblings.push(sibling_hash);
                known_at_layer[d + 1].insert(parent);
            } else if right_known {
                // Need left sibling
                let sibling_hash = tree.get_node_at_depth(depth - d, left_child);
                siblings.push(sibling_hash);
                known_at_layer[d + 1].insert(parent);
            }
        }
    }

    BatchedMerkleProof { siblings }
}

/// Verify a batched Merkle proof against a known root.
pub(crate) fn verify_batched_merkle_proof(
    root: &HashOutput,
    batch: &BatchedMerkleProof,
    depth: usize,
    leaf_indices: &[usize],
    leaf_hashes: &[HashOutput],
    hasher: &dyn CryptographicHasher,
) -> Result<(), String> {
    if leaf_indices.len() != leaf_hashes.len() {
        return Err("leaf index/hash count mismatch".into());
    }

    // Reconstruct bottom-up, consuming siblings as needed.
    let mut known: std::collections::HashMap<(usize, usize), HashOutput> =
        std::collections::HashMap::new();

    // Layer 0: insert leaf hashes (check consistency for duplicates)
    for (i, &idx) in leaf_indices.iter().enumerate() {
        if let Some(&existing) = known.get(&(0, idx)) {
            if existing != leaf_hashes[i] {
                return Err(format!("inconsistent leaf hashes for index {idx}"));
            }
        } else {
            known.insert((0, idx), leaf_hashes[i]);
        }
    }

    let mut sib_cursor = 0usize;

    for d in 0..depth {
        let mut parents_needed: std::collections::BTreeSet<usize> =
            std::collections::BTreeSet::new();
        for (&(layer, idx), _) in known.iter() {
            if layer == d {
                parents_needed.insert(idx >> 1);
            }
        }

        for &parent in &parents_needed {
            let left_child = parent * 2;
            let right_child = parent * 2 + 1;
            let left = known.get(&(d, left_child)).copied();
            let right = known.get(&(d, right_child)).copied();

            let parent_hash = match (left, right) {
                (Some(l), Some(r)) => hasher.compress(&l, &r),
                (Some(l), None) => {
                    if sib_cursor >= batch.siblings.len() {
                        return Err(format!("insufficient siblings at layer {d}"));
                    }
                    let r = batch.siblings[sib_cursor];
                    sib_cursor += 1;
                    hasher.compress(&l, &r)
                }
                (None, Some(r)) => {
                    if sib_cursor >= batch.siblings.len() {
                        return Err(format!("insufficient siblings at layer {d}"));
                    }
                    let l = batch.siblings[sib_cursor];
                    sib_cursor += 1;
                    hasher.compress(&l, &r)
                }
                (None, None) => {
                    return Err(format!("orphan parent at layer {d} idx {parent}"));
                }
            };
            known.insert((d + 1, parent), parent_hash);
        }
    }

    // The root should be at (depth, 0)
    let computed_root = known
        .get(&(depth, 0))
        .ok_or_else(|| "failed to compute root".to_string())?;
    if computed_root != root {
        return Err("batched Merkle root mismatch".into());
    }

    if sib_cursor != batch.siblings.len() {
        return Err(format!(
            "unused siblings: consumed {sib_cursor}, total {}",
            batch.siblings.len()
        ));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Generate compact query indices.
pub(crate) fn gen_compact_queries(
    channel: &mut Channel,
    log_max_len: usize,
    num_queries: usize,
) -> Vec<usize> {
    let domain_size = 1usize << log_max_len;
    if domain_size == 0 {
        return vec![];
    }
    let n_queries = num_queries.min(domain_size);
    let bit_mask = (domain_size - 1) as u128;
    let random_elems = channel.get_random_points(n_queries);
    random_elems
        .iter()
        .map(|elem| (elem.0 & bit_mask) as usize)
        .collect()
}

/// Compute the tree depth for a given round.
fn compute_round_depth(n_rounds: usize, round: usize) -> usize {
    // Round 0: domain = 2^(n_rounds + LOG_RATE), tree over pairs = 2^(n_rounds + LOG_RATE - 1)
    // depth = n_rounds + LOG_RATE - 1 - round
    n_rounds + LOG_RATE - 1 - round
}

/// Evaluate a multilinear extension at a point.
fn mle_evaluate(evals: &[Block128], point: &[Block128]) -> Block128 {
    if point.is_empty() {
        return if evals.is_empty() {
            Block128::ZERO
        } else {
            evals[0]
        };
    }
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

/// Fold an evaluation vector in half at challenge r.
fn fold_evals_in_place(evals: &mut Vec<Block128>, r: Block128) {
    let half = evals.len() / 2;
    let (lo, hi) = evals.split_at_mut(half);
    if half >= 1024 {
        lo.par_iter_mut().zip(hi.par_iter()).for_each(|(l, &h)| {
            *l += r * h;
        });
    } else {
        for i in 0..half {
            lo[i] += r * hi[i];
        }
    }
    evals.truncate(half);
}
