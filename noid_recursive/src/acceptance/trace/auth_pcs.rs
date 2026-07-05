// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! The wallet-PCS opening in the trace.
//!
//! Trace twin of `noid_gkr::auth_pcs::verify_auth_mle_opening` — the final
//! check of `verify_owner_auth_killshot`, consumed here as a
//! [`PendingAuthPcsObligation`]:
//!
//! ```text
//! verify_auth_mle_opening
//! ├─ absorb_cap                      → absorb_cap_trace
//! └─ verify_mixed_opening            → verify_mixed_opening_trace
//!    ├─ γ batching (Horner)          → powers of the squeezed γ expression
//!    └─ compact_fri_verify_with_query_hook → compact_fri_verify_trace
//!       ├─ hook: verify_source_binding → verify_source_binding_trace
//!       └─ query rounds (batched Merkle + folds)
//! ```
//!
//! Every function is a line-by-line transliteration of its native reference
//! (`noid_fri_binius/src/{mixed_open,compact_fri,interleaved_commit}.rs`) —
//! same absorb/squeeze order on the [`FriChannelTrace`], same checks; native
//! `Err` branches that depend on values are pins, branches that depend on
//! proof/statement SHAPE are build asserts (module docs of `trace`).
//!
//! **Structure vs witness:** `num_vars`, `tau`, round counts, tree depths,
//! Merkle-cap widths and the QUERY INDICES are trace structure. Query
//! indices are challenge-derived; each squeezed query challenge is pinned to
//! its structural index bits plus witness top bits
//! ([`gen_compact_queries_trace`]) — the R1CS matrix depends on the proof
//! instance exactly as it does for Merkle directions elsewhere. The
//! shape-freeze pass (witness selectors + protocol-constant matrices)
//! covers both.
//!
//! **Scope:** the wallet shapes (`AUTH_PCS_BASE_LOG ≤ num_vars < 20`,
//! `n_cols = 1`) always take the folded-layer source-binding path; the
//! direct-source-expansion branch (`log_n ≥ 20` diagnostics) is outside the
//! frozen wallet shape and asserted unreachable here.

use noid_core::{AdditiveNTT, Block128};
use noid_fri::code::LOG_RATE;
use noid_fri_binius::compact_fri::{compute_round_depth, CompactEvalProof, COMPACT_TAU};
use noid_fri_binius::interleaved_commit::{
    source_cap_depth, source_tree_depth, SOURCE_LEAF_DOMAIN,
};
use noid_fri_binius::mixed_open::{
    high_pair_leaf_index, high_pair_parity, high_pair_tree_depth, use_direct_source_expansion,
    MixedOpeningProof, SourceBindingProof, HIGH_PAIR_DOMAIN, MIXED_OPEN_TAG,
    MIXED_SOURCE_BINDING_TAG,
};
use noid_fri_binius::MERKLE_CAP_DEPTH;
use noid_gkr::auth_pcs::{AuthMleOpeningProof, AUTH_PCS_BASE_LOG};

use super::fri_pcs::{
    alloc_digest, code_new_trace, compress_digest_trace, fold_trace, gen_compact_queries_trace,
    hash_pair_trace, merkle_root_trace, mle_evaluate_small_trace, pin_digest_eq,
    verify_batched_merkle_proof_to_cap_trace, verify_batched_merkle_proof_trace, DigestExpr,
    FriChannelTrace,
};
use super::owner_auth::PendingAuthPcsObligation;
use super::{
    alloc_blocks, eq_ind_partial_eval_trace, flat_const, mul, pin_eq, FieldR1csBuilder, LinExpr,
    F128,
};

// ---------------------------------------------------------------------------
// Proof wires
// ---------------------------------------------------------------------------

/// Trace twin of `compact_fri::BatchedMerkleProof` (sibling digests).
pub struct BatchedMerkleProofTrace {
    pub siblings: Vec<DigestExpr>,
}

impl BatchedMerkleProofTrace {
    fn alloc(b: &mut FieldR1csBuilder, siblings: &[[u8; 32]]) -> Self {
        Self {
            siblings: siblings.iter().map(|s| alloc_digest(b, s)).collect(),
        }
    }
}

/// Trace twin of `CompactEvalProof`. Fixed shape: `tau = min(8, log_n)`
/// upper evals, `n_rounds = log_n − tau` rounds, per-round query symbols.
pub struct CompactEvalProofTrace {
    pub upper_partial_evals: Vec<LinExpr>,
    pub sum_check_oracles: Vec<[LinExpr; 2]>,
    pub fri_roots: Vec<DigestExpr>,
    pub fri_queried_symbols: Vec<Vec<(LinExpr, LinExpr)>>,
    pub fri_merkle_batch: Vec<BatchedMerkleProofTrace>,
    pub final_codeword: Vec<LinExpr>,
}

impl CompactEvalProofTrace {
    pub fn alloc(
        b: &mut FieldR1csBuilder,
        native: &CompactEvalProof,
        log_n: usize,
        num_queries: usize,
    ) -> Self {
        let tau = COMPACT_TAU.min(log_n);
        let n_rounds = log_n - tau;
        assert_eq!(native.upper_partial_evals.len(), 1usize << tau);
        assert_eq!(native.sum_check_oracles.len(), n_rounds);
        assert_eq!(native.fri_roots.len(), n_rounds);
        assert_eq!(native.fri_queried_symbols.len(), n_rounds);
        assert_eq!(native.fri_merkle_batch.len(), n_rounds);
        let fri_n_queries = num_queries.min(1usize << (n_rounds + LOG_RATE));
        for symbols in &native.fri_queried_symbols {
            assert_eq!(symbols.len(), fri_n_queries);
        }
        assert!(!native.final_codeword.is_empty());
        Self {
            upper_partial_evals: alloc_blocks(b, &native.upper_partial_evals),
            sum_check_oracles: native
                .sum_check_oracles
                .iter()
                .map(|[c0, c1]| {
                    let cs = alloc_blocks(b, &[*c0, *c1]);
                    [cs[0].clone(), cs[1].clone()]
                })
                .collect(),
            fri_roots: native.fri_roots.iter().map(|r| alloc_digest(b, r)).collect(),
            fri_queried_symbols: native
                .fri_queried_symbols
                .iter()
                .map(|round| {
                    round
                        .iter()
                        .map(|&(s0, s1)| {
                            let ss = alloc_blocks(b, &[s0, s1]);
                            (ss[0].clone(), ss[1].clone())
                        })
                        .collect()
                })
                .collect(),
            fri_merkle_batch: native
                .fri_merkle_batch
                .iter()
                .map(|batch| BatchedMerkleProofTrace::alloc(b, &batch.siblings))
                .collect(),
            final_codeword: alloc_blocks(b, &native.final_codeword),
        }
    }
}

/// Trace twin of `SourceBindingProof` (wallet shapes: folded-layer path).
pub struct SourceBindingProofTrace {
    pub h_evals: Vec<LinExpr>,
    pub folded_roots: Vec<DigestExpr>,
    pub source_symbols: Vec<LinExpr>,
    pub source_merkle_batch: BatchedMerkleProofTrace,
    pub folded_queried_symbols: Vec<Vec<(LinExpr, LinExpr)>>,
    pub folded_merkle_batch: Vec<BatchedMerkleProofTrace>,
}

impl SourceBindingProofTrace {
    pub fn alloc(
        b: &mut FieldR1csBuilder,
        native: &SourceBindingProof,
        log_n: usize,
        n_cols: usize,
        num_queries: usize,
    ) -> Self {
        let tau = COMPACT_TAU.min(log_n);
        let n_rounds = log_n - tau;
        assert_eq!(native.h_evals.len(), 1usize << n_rounds);
        let expected_layers = tau.saturating_sub(1);
        assert!(
            !use_direct_source_expansion(n_cols, tau, log_n),
            "direct source expansion is outside the wallet-PCS trace shape"
        );
        assert_eq!(native.folded_roots.len(), expected_layers);
        assert_eq!(native.folded_queried_symbols.len(), expected_layers);
        assert_eq!(native.folded_merkle_batch.len(), expected_layers);
        let n_queries = num_queries.min(1usize << (log_n + LOG_RATE));
        assert_eq!(native.source_symbols.len(), n_queries * n_cols * 2);
        for symbols in &native.folded_queried_symbols {
            assert_eq!(symbols.len(), n_queries);
        }
        Self {
            h_evals: alloc_blocks(b, &native.h_evals),
            folded_roots: native
                .folded_roots
                .iter()
                .map(|r| alloc_digest(b, r))
                .collect(),
            source_symbols: alloc_blocks(b, &native.source_symbols),
            source_merkle_batch: BatchedMerkleProofTrace::alloc(
                b,
                &native.source_merkle_batch.siblings,
            ),
            folded_queried_symbols: native
                .folded_queried_symbols
                .iter()
                .map(|round| {
                    round
                        .iter()
                        .map(|&(s0, s1)| {
                            let ss = alloc_blocks(b, &[s0, s1]);
                            (ss[0].clone(), ss[1].clone())
                        })
                        .collect()
                })
                .collect(),
            folded_merkle_batch: native
                .folded_merkle_batch
                .iter()
                .map(|batch| BatchedMerkleProofTrace::alloc(b, &batch.siblings))
                .collect(),
        }
    }
}

/// Trace twin of `MixedOpeningProof`.
pub struct MixedOpeningProofTrace {
    pub all_openings: Vec<LinExpr>,
    pub fri_proof: CompactEvalProofTrace,
    pub source_proof: SourceBindingProofTrace,
}

impl MixedOpeningProofTrace {
    pub fn alloc(
        b: &mut FieldR1csBuilder,
        native: &MixedOpeningProof,
        log_n: usize,
        n_cols: usize,
        n_secondary: usize,
        num_queries: usize,
    ) -> Self {
        assert_eq!(native.all_openings.len(), n_cols + n_secondary);
        Self {
            all_openings: alloc_blocks(b, &native.all_openings),
            fri_proof: CompactEvalProofTrace::alloc(b, &native.fri_proof, log_n, num_queries),
            source_proof: SourceBindingProofTrace::alloc(
                b,
                &native.source_proof,
                log_n,
                n_cols,
                num_queries,
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// Compact FRI verifier
// ---------------------------------------------------------------------------

/// Trace twin of `CompactFriQueryContext` (verifier side — `source_h_evals`
/// stays with the serialized source proof).
pub struct CompactFriQueryContextTrace {
    pub tau: usize,
    pub n_rounds: usize,
    pub tensor_batching_point: Vec<LinExpr>,
    pub initial_sumcheck_claim: LinExpr,
    pub fri_roots: Vec<DigestExpr>,
    pub final_codeword: Vec<LinExpr>,
}

/// `basis + ONE + r` factor of `tensor_high_fold_pair` — the basis constant
/// `2^(coset + layer_log − 1)` XOR 1, with one multiplication by `s0`.
fn tensor_high_fold_pair_trace(
    b: &mut FieldR1csBuilder,
    r: &LinExpr,
    layer_log: usize,
    leaf_index: usize,
    s0: &LinExpr,
    s1: &LinExpr,
) -> LinExpr {
    let coset = leaf_index >> (layer_log - 1);
    let basis_idx = coset + layer_log - 1;
    let factor = r.add_const(flat_const((1u128 << basis_idx) ^ 1));
    s1.add(&mul(b, s0, &factor))
}

/// Trace twin of `compact_fri_verify_with_query_hook`.
#[allow(clippy::too_many_arguments)]
pub fn compact_fri_verify_trace<F>(
    b: &mut FieldR1csBuilder,
    ch: &mut FriChannelTrace,
    eval_point: &[LinExpr],
    eval: &LinExpr,
    proof: &CompactEvalProofTrace,
    ntt: &AdditiveNTT<Block128>,
    num_queries: usize,
    before_queries: F,
) where
    F: FnOnce(&mut FieldR1csBuilder, &mut FriChannelTrace, &CompactFriQueryContextTrace),
{
    ch.observe_field_elems(b, eval_point);

    let tau = COMPACT_TAU.min(eval_point.len());
    let n = eval_point.len();
    let (right, left) = eval_point.split_at(n - tau);

    assert_eq!(proof.upper_partial_evals.len(), 1usize << tau);

    // Verify eval = Σ eq(left, i) · upper_partial_evals[i].
    let left_eq = eq_ind_partial_eval_trace(b, left);
    let mut derived_eval = LinExpr::zero();
    for (lhs, rhs) in left_eq.iter().zip(proof.upper_partial_evals.iter()) {
        derived_eval = derived_eval.add(&mul(b, lhs, rhs));
    }
    pin_eq(b, &derived_eval, eval);
    ch.observe_field_elem(b, eval);

    // Tensor batching.
    let tensor_batching_point = ch.squeeze_n(b, tau);
    let batching_eq = eq_ind_partial_eval_trace(b, &tensor_batching_point);
    let mut claim = LinExpr::zero();
    for (u, be) in proof.upper_partial_evals.iter().zip(batching_eq.iter()) {
        claim = claim.add(&mul(b, u, be));
    }
    let initial_sumcheck_claim = claim.clone();

    // Sumcheck rounds.
    let n_rounds = right.len();
    assert_eq!(proof.sum_check_oracles.len(), n_rounds);
    assert_eq!(proof.fri_roots.len(), n_rounds);
    assert_eq!(proof.fri_queried_symbols.len(), n_rounds);
    assert_eq!(proof.fri_merkle_batch.len(), n_rounds);

    let mut random_point = Vec::with_capacity(n_rounds);
    for round in 0..n_rounds {
        let [c0, c1] = &proof.sum_check_oracles[round];
        // p(0) + p(1) = c1 in char 2 — must equal the running claim.
        pin_eq(b, c1, &claim);

        ch.observe_field_elem(b, c0);
        ch.observe_field_elem(b, c1);
        let depth = compute_round_depth(n_rounds, round);
        ch.observe_vector_commitment(b, &proof.fri_roots[round], depth);
        let r = ch.squeeze(b);
        claim = c0.add(&mul(b, c1, &r));
        random_point.push(r);
    }

    // Absorb final codeword.
    assert!(!proof.final_codeword.is_empty());
    ch.observe_field_elems(b, &proof.final_codeword);

    let context = CompactFriQueryContextTrace {
        tau,
        n_rounds,
        tensor_batching_point,
        initial_sumcheck_claim,
        fri_roots: proof.fri_roots.clone(),
        final_codeword: proof.final_codeword.clone(),
    };
    before_queries(b, ch, &context);

    // Query phase (indices become trace structure, pinned to the squeezed
    // challenges inside gen_compact_queries_trace).
    let log_domain = n_rounds + LOG_RATE;
    let query_indices = gen_compact_queries_trace(b, ch, log_domain, num_queries);
    let n_queries = query_indices.len();

    let mut folded_symbols: Vec<Option<LinExpr>> = vec![None; n_queries];
    for round in 0..n_rounds {
        let symbols = &proof.fri_queried_symbols[round];
        assert_eq!(symbols.len(), n_queries);

        // Fold-consistency check against the previous round.
        for i in 0..n_queries {
            if round > 0 {
                let scaled = query_indices[i] >> round;
                let parity = scaled & 1;
                let (s0, s1) = &symbols[i];
                let expected = if parity == 1 { s1 } else { s0 };
                pin_eq(b, folded_symbols[i].as_ref().unwrap(), expected);
            }
        }

        let pair_indices: Vec<usize> = query_indices
            .iter()
            .map(|&qi| (qi >> round) >> 1)
            .collect();
        let leaf_hashes: Vec<DigestExpr> = symbols
            .iter()
            .map(|(s0, s1)| hash_pair_trace(b, s0, s1))
            .collect();
        verify_batched_merkle_proof_trace(
            b,
            &proof.fri_roots[round],
            &proof.fri_merkle_batch[round].siblings,
            compute_round_depth(n_rounds, round),
            &pair_indices,
            &leaf_hashes,
        );

        for i in 0..n_queries {
            let pair_idx = (query_indices[i] >> round) >> 1;
            let (s0, s1) = &symbols[i];
            folded_symbols[i] = Some(fold_trace(
                b,
                &random_point[round],
                round,
                pair_idx,
                s0,
                s1,
                ntt,
            ));
        }
    }

    // Final codeword check.
    let final_len = proof.final_codeword.len();
    for (i, sym) in folded_symbols.iter().enumerate() {
        if let Some(s) = sym {
            let final_idx = query_indices[i] >> n_rounds;
            pin_eq(b, s, &proof.final_codeword[final_idx % final_len]);
        }
    }
}

// ---------------------------------------------------------------------------
// Source binding
// ---------------------------------------------------------------------------

/// Trace twin of `assert_source_h_matches_compact` (full verifier variant):
/// pins `H(right)` to the compact tensor claim and the `Code(H · eq_right)`
/// Merkle root to the compact FRI round-0 root.
fn assert_source_h_matches_compact_trace(
    b: &mut FieldR1csBuilder,
    primary_point: &[LinExpr],
    ctx: &CompactFriQueryContextTrace,
    h_evals: &[LinExpr],
) {
    let right = &primary_point[..ctx.n_rounds];
    let h_at_right = mle_evaluate_small_trace(b, h_evals, right);
    pin_eq(b, &h_at_right, &ctx.initial_sumcheck_claim);

    let eq_right = eq_ind_partial_eval_trace(b, right);
    let g_evals: Vec<LinExpr> = h_evals
        .iter()
        .zip(eq_right.iter())
        .map(|(h, e)| mul(b, h, e))
        .collect();
    let g_code = code_new_trace(&g_evals);
    if ctx.n_rounds == 0 {
        assert_eq!(g_code.len(), ctx.final_codeword.len());
        for (g, f) in g_code.iter().zip(ctx.final_codeword.iter()) {
            pin_eq(b, g, f);
        }
        return;
    }

    let leaf_hashes: Vec<DigestExpr> = g_code
        .chunks_exact(2)
        .map(|pair| hash_pair_trace(b, &pair[0], &pair[1]))
        .collect();
    let root = merkle_root_trace(b, leaf_hashes);
    pin_digest_eq(b, &root, &ctx.fri_roots[0]);
}

/// Trace twin of `observe_source_binding_commitments`.
fn observe_source_binding_commitments_trace(
    b: &mut FieldR1csBuilder,
    ch: &mut FriChannelTrace,
    folded_roots: &[DigestExpr],
    h_evals: &[LinExpr],
    log_n: usize,
    tau: usize,
) {
    ch.observe_const_tower(b, MIXED_SOURCE_BINDING_TAG);
    ch.observe_field_elems(b, h_evals);
    for (i, root) in folded_roots.iter().enumerate() {
        let layer_log = log_n - 1 - i;
        debug_assert!(i + 1 < tau);
        ch.observe_vector_commitment(b, root, high_pair_tree_depth(layer_log));
    }
}

/// Trace twin of `source_leaf_hash` (arithmetic backend): domain/meta
/// prefixes fold to constants; every column pair costs one `hash_pair` and
/// one `compress`.
fn source_leaf_hash_trace(
    b: &mut FieldR1csBuilder,
    log_rows: usize,
    n_cols: usize,
    leaf_index: usize,
    symbols: &[LinExpr],
) -> DigestExpr {
    assert_eq!(symbols.len(), n_cols * 2);
    let mut acc = hash_pair_trace(
        b,
        &LinExpr::constant(flat_const(SOURCE_LEAF_DOMAIN)),
        &LinExpr::constant(flat_const(log_rows as u128)),
    );
    let meta = hash_pair_trace(
        b,
        &LinExpr::constant(flat_const(n_cols as u128)),
        &LinExpr::constant(flat_const(leaf_index as u128)),
    );
    acc = compress_digest_trace(b, &acc, &meta);
    for pair in symbols.chunks_exact(2) {
        let pair_hash = hash_pair_trace(b, &pair[0], &pair[1]);
        acc = compress_digest_trace(b, &acc, &pair_hash);
    }
    acc
}

/// Trace twin of `high_pair_leaf_hash`.
fn high_pair_leaf_hash_trace(
    b: &mut FieldR1csBuilder,
    layer_log: usize,
    leaf_index: usize,
    s0: &LinExpr,
    s1: &LinExpr,
) -> DigestExpr {
    let mut acc = hash_pair_trace(
        b,
        &LinExpr::constant(flat_const(HIGH_PAIR_DOMAIN)),
        &LinExpr::constant(flat_const(layer_log as u128)),
    );
    let meta = hash_pair_trace(b, &LinExpr::constant(flat_const(leaf_index as u128)), s0);
    let pair = hash_pair_trace(b, s0, s1);
    acc = compress_digest_trace(b, &acc, &meta);
    compress_digest_trace(b, &acc, &pair)
}

/// Trace twin of `verify_source_binding` (folded-layer path — the wallet
/// shape; see the module docs for the direct-expansion exclusion).
#[allow(clippy::too_many_arguments)]
fn verify_source_binding_trace(
    b: &mut FieldR1csBuilder,
    ch: &mut FriChannelTrace,
    cap_lanes: &[DigestExpr],
    log_n: usize,
    n_cols: usize,
    gamma: &LinExpr,
    primary_point: &[LinExpr],
    proof: &SourceBindingProofTrace,
    ctx: &CompactFriQueryContextTrace,
    num_queries: usize,
) {
    assert_eq!(primary_point.len(), log_n);
    assert_eq!(ctx.tau + ctx.n_rounds, log_n);
    assert_eq!(proof.h_evals.len(), 1usize << ctx.n_rounds);
    let expected_layers = ctx.tau.saturating_sub(1);
    assert_eq!(proof.folded_roots.len(), expected_layers);

    assert_source_h_matches_compact_trace(b, primary_point, ctx, &proof.h_evals);
    observe_source_binding_commitments_trace(
        b,
        ch,
        &proof.folded_roots,
        &proof.h_evals,
        log_n,
        ctx.tau,
    );
    let query_indices = gen_compact_queries_trace(b, ch, log_n + LOG_RATE, num_queries);
    let n_queries = query_indices.len();

    // Source cap = the tail of the commitment cap (mirror of
    // `source_cap_from_commitment_cap`).
    let cap_depth = source_cap_depth(log_n);
    let start = 1usize << MERKLE_CAP_DEPTH;
    assert_eq!(
        cap_lanes.len(),
        start + (1usize << cap_depth),
        "missing source cap in interleaved commitment"
    );
    let source_cap = &cap_lanes[start..];

    let source_pair_indices: Vec<usize> = query_indices
        .iter()
        .map(|&qi| high_pair_leaf_index(qi, log_n))
        .collect();
    assert_eq!(
        proof.source_symbols.len(),
        source_pair_indices.len() * n_cols * 2
    );
    let mut source_leaf_hashes = Vec::with_capacity(source_pair_indices.len());
    for (leaf_pos, &leaf_idx) in source_pair_indices.iter().enumerate() {
        let start_sym = leaf_pos * n_cols * 2;
        let end_sym = start_sym + n_cols * 2;
        source_leaf_hashes.push(source_leaf_hash_trace(
            b,
            log_n,
            n_cols,
            leaf_idx,
            &proof.source_symbols[start_sym..end_sym],
        ));
    }
    verify_batched_merkle_proof_to_cap_trace(
        b,
        source_cap,
        cap_depth,
        &proof.source_merkle_batch.siblings,
        source_tree_depth(log_n),
        &source_pair_indices,
        &source_leaf_hashes,
    );

    let h_code = code_new_trace(&proof.h_evals);

    // Horner weights for the primary columns (powers of γ).
    let mut weights: Vec<LinExpr> = Vec::with_capacity(n_cols);
    let mut w = LinExpr::constant(F128::ONE);
    for _ in 0..n_cols {
        weights.push(w.clone());
        w = if w.is_const() {
            gamma.scale(w.eval(b.values()))
        } else {
            mul(b, &w, gamma)
        };
    }

    let mut folded_symbols = Vec::with_capacity(n_queries);
    for (query_idx, &leaf_idx) in source_pair_indices.iter().take(n_queries).enumerate() {
        let start_sym = query_idx * n_cols * 2;
        // reduce_source_pair_flat: Σ_k w_k · (s_{2k}, s_{2k+1}).
        let mut s0 = LinExpr::zero();
        let mut s1 = LinExpr::zero();
        for (col_idx, weight) in weights.iter().enumerate() {
            let sym0 = &proof.source_symbols[start_sym + 2 * col_idx];
            let sym1 = &proof.source_symbols[start_sym + 2 * col_idx + 1];
            if weight.is_const() {
                let c = weight.eval(b.values());
                s0 = s0.add(&sym0.scale(c));
                s1 = s1.add(&sym1.scale(c));
            } else {
                s0 = s0.add(&mul(b, weight, sym0));
                s1 = s1.add(&mul(b, weight, sym1));
            }
        }
        folded_symbols.push(tensor_high_fold_pair_trace(
            b,
            &ctx.tensor_batching_point[ctx.tau - 1],
            log_n,
            leaf_idx,
            &s0,
            &s1,
        ));
    }

    let mut current_indices = source_pair_indices;
    for (layer_idx, symbols) in proof.folded_queried_symbols.iter().enumerate() {
        let layer_log = log_n - 1 - layer_idx;
        assert_eq!(symbols.len(), n_queries);
        let pair_indices: Vec<usize> = current_indices
            .iter()
            .map(|&idx| high_pair_leaf_index(idx, layer_log))
            .collect();
        let leaf_hashes: Vec<DigestExpr> = symbols
            .iter()
            .zip(pair_indices.iter())
            .map(|((s0, s1), &pair_idx)| {
                high_pair_leaf_hash_trace(b, layer_log, pair_idx, s0, s1)
            })
            .collect();
        verify_batched_merkle_proof_to_cap_trace(
            b,
            std::slice::from_ref(&proof.folded_roots[layer_idx]),
            0,
            &proof.folded_merkle_batch[layer_idx].siblings,
            high_pair_tree_depth(layer_log),
            &pair_indices,
            &leaf_hashes,
        );

        let r = &ctx.tensor_batching_point[ctx.tau - 2 - layer_idx];
        let mut next_folded = Vec::with_capacity(n_queries);
        for query_idx in 0..n_queries {
            let (s0, s1) = &symbols[query_idx];
            let expected = if high_pair_parity(current_indices[query_idx], layer_log) == 1 {
                s1
            } else {
                s0
            };
            pin_eq(b, &folded_symbols[query_idx], expected);
            next_folded.push(tensor_high_fold_pair_trace(
                b,
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

    for (query_idx, folded) in folded_symbols.iter().enumerate() {
        pin_eq(b, folded, &h_code[current_indices[query_idx]]);
    }
}

// ---------------------------------------------------------------------------
// Mixed opening + auth capsule glue
// ---------------------------------------------------------------------------

/// Trace twin of `verify_mixed_opening` (the auth path has no secondary
/// claims). Returns the primary opening expressions.
#[allow(clippy::too_many_arguments)]
pub fn verify_mixed_opening_trace(
    b: &mut FieldR1csBuilder,
    ch: &mut FriChannelTrace,
    cap_lanes: &[DigestExpr],
    log_n: usize,
    n_cols: usize,
    primary_point: &[LinExpr],
    proof: &MixedOpeningProofTrace,
    ntt: &AdditiveNTT<Block128>,
    num_queries: usize,
) -> Vec<LinExpr> {
    assert!(n_cols <= noid_fri_binius::mixed_open::MAX_MIXED_OPEN_VECTOR_COLS);
    assert_eq!(proof.all_openings.len(), n_cols);
    assert_eq!(primary_point.len(), log_n);

    // Absorb openings, draw gamma (mirror prover).
    ch.observe_const_tower(b, MIXED_OPEN_TAG as u128);
    ch.observe_field_elems(b, &proof.all_openings);
    let gamma = ch.squeeze(b);

    // Batched claim for the primary columns (`compute_batched_claim_flat`:
    // Horner powers of gamma).
    let mut batched_claim = LinExpr::zero();
    let mut weight = LinExpr::constant(F128::ONE);
    for opening in proof.all_openings.iter().take(n_cols) {
        if weight.is_const() {
            batched_claim = batched_claim.add(&opening.scale(weight.eval(b.values())));
        } else {
            batched_claim = batched_claim.add(&mul(b, &weight, opening));
        }
        weight = if weight.is_const() {
            gamma.scale(weight.eval(b.values()))
        } else {
            mul(b, &weight, &gamma)
        };
    }

    compact_fri_verify_trace(
        b,
        ch,
        primary_point,
        &batched_claim,
        &proof.fri_proof,
        ntt,
        num_queries,
        |b, ch, ctx| {
            verify_source_binding_trace(
                b,
                ch,
                cap_lanes,
                log_n,
                n_cols,
                &gamma,
                primary_point,
                &proof.source_proof,
                ctx,
                num_queries,
            );
        },
    );

    proof.all_openings[..n_cols].to_vec()
}

/// Trace twin of `absorb_cap`: every cap hash enters as its two u128-LE
/// lanes (the same [`DigestExpr`] wires the owner-auth slot absorbed into
/// the killshot channel — cross-slot binding by shared wires).
pub fn absorb_cap_trace(
    b: &mut FieldR1csBuilder,
    ch: &mut FriChannelTrace,
    cap_lanes: &[DigestExpr],
) {
    for hash in cap_lanes {
        ch.observe_field_elem(b, &hash[0]);
        ch.observe_field_elem(b, &hash[1]);
    }
}

/// Discharge one [`PendingAuthPcsObligation`] — the trace twin of
/// `noid_gkr::auth_pcs::verify_auth_mle_opening` over the reduced claim the
/// owner-auth slot produced — the replay-completeness closure for
/// `proof.pcs`.
pub fn discharge_auth_pcs_obligation(
    b: &mut FieldR1csBuilder,
    obligation: &PendingAuthPcsObligation,
    native: &AuthMleOpeningProof,
) {
    let num_vars = obligation.num_vars;
    // Native value checks that are shape here (the commitment fields were
    // asserted at owner-auth proof alloc; the reduction point length is the
    // layout's num_vars by construction).
    assert!(num_vars >= AUTH_PCS_BASE_LOG);
    assert_eq!(obligation.reduction.point.len(), num_vars);
    assert_eq!(native.commitment.log_rows, num_vars);
    assert_eq!(native.commitment.n_cols, 1);
    assert_eq!(obligation.commitment_cap_lanes.len(), native.commitment.cap.hashes.len());

    let num_queries = noid_fri_binius::COMPACT_NUM_QUERIES;
    let ntt = AdditiveNTT::<Block128>::new(num_vars + LOG_RATE);
    let mut channel = FriChannelTrace::new();
    absorb_cap_trace(b, &mut channel, &obligation.commitment_cap_lanes);

    let opening = MixedOpeningProofTrace::alloc(b, &native.opening, num_vars, 1, 0, num_queries);
    let openings = verify_mixed_opening_trace(
        b,
        &mut channel,
        &obligation.commitment_cap_lanes,
        num_vars,
        1,
        &obligation.reduction.point,
        &opening,
        &ntt,
        num_queries,
    );
    assert_eq!(openings.len(), 1);
    pin_eq(b, &openings[0], &obligation.reduction.value);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::super::owner_auth::build_owner_auth_slot;
    use super::super::test_support::assert_expr_is;
    use super::*;
    use noid_core::TowerField;
    use noid_gkr::owner_auth::{
        compute_owner_auth_boundary, owner_auth_gkr_channel, prove_owner_auth_killshot,
        verify_owner_auth_killshot_with_claims, OwnerAuthInputs, OwnerAuthLayout,
        OwnerAuthPublicInputs,
    };
    use noid_gkr::OwnerAuthProofKillShot;

    fn fixture(owner_count: usize, seed: u128) -> (OwnerAuthInputs, OwnerAuthPublicInputs) {
        let layout = OwnerAuthLayout::for_owner_count(owner_count).unwrap();
        let circuit = noid_gkr::owner_auth::OwnerAuthCircuit::build(layout);
        let spend_secret: Vec<[Block128; 2]> = (0..owner_count)
            .map(|i| {
                [
                    Block128::from(seed + 1000 + i as u128),
                    Block128::from(seed + 2000 + i as u128),
                ]
            })
            .collect();
        let tx_body_hash = [Block128::from(seed + 7), Block128::from(seed + 8)];
        let expected_address =
            compute_owner_auth_boundary(&circuit, spend_secret.clone(), tx_body_hash);
        let live_input_positions: Vec<usize> = (0..owner_count).collect();
        let live_slot_indices: Vec<u32> = (0..owner_count as u32).map(|i| 100 + i).collect();
        let input_to_group: Vec<usize> = (0..owner_count).collect();
        let public = OwnerAuthPublicInputs::new(
            layout,
            tx_body_hash,
            live_input_positions,
            live_slot_indices,
            input_to_group,
            expected_address,
            owner_count.max(4),
        )
        .unwrap();
        let inputs = OwnerAuthInputs::from_parts(&public, spend_secret);
        (inputs, public)
    }

    fn prove(inputs: &OwnerAuthInputs) -> OwnerAuthProofKillShot {
        let circuit = noid_gkr::owner_auth::OwnerAuthCircuit::build(inputs.layout);
        let mut ch = owner_auth_gkr_channel();
        let (proof, _) = prove_owner_auth_killshot(&circuit, inputs, &mut ch);
        proof
    }

    /// Full native killshot verify — INCLUDES `verify_auth_mle_opening`.
    fn native_accepts(proof: &OwnerAuthProofKillShot, public: &OwnerAuthPublicInputs) -> bool {
        let circuit = noid_gkr::owner_auth::OwnerAuthCircuit::build(public.layout);
        let mut ch = owner_auth_gkr_channel();
        verify_owner_auth_killshot_with_claims(proof, &circuit, public, &mut ch).is_some()
    }

    /// Full trace: owner-auth slot + PCS discharge. A build panic (a mutant
    /// off the structural schedule — sibling counts, dedup shape) is a
    /// rejection, exactly where native errors out.
    fn trace_accepts(proof: &OwnerAuthProofKillShot, public: &OwnerAuthPublicInputs) -> bool {
        let proof = proof.clone();
        let public = public.clone();
        let result = std::panic::catch_unwind(move || {
            let mut b = FieldR1csBuilder::new();
            let (_, obligation) = build_owner_auth_slot(&mut b, &proof, &public);
            discharge_auth_pcs_obligation(&mut b, &obligation, &proof.pcs);
            let (r1cs, z) = b.build();
            r1cs.satisfies(&z)
        });
        result.unwrap_or(false)
    }

    /// Enumerate every mutable value slot of the wallet-PCS opening proof:
    /// field elements as `Block128 += ONE`, digests as a low-bit flip.
    fn visit_pcs_slots(
        p: &mut AuthMleOpeningProof,
        f: &mut impl FnMut(SlotMut<'_>),
    ) {
        for h in &mut p.commitment.cap.hashes {
            f(SlotMut::Digest(h));
        }
        for v in &mut p.opening.all_openings {
            f(SlotMut::Field(v));
        }
        let fri = &mut p.opening.fri_proof;
        for v in &mut fri.upper_partial_evals {
            f(SlotMut::Field(v));
        }
        for [c0, c1] in &mut fri.sum_check_oracles {
            f(SlotMut::Field(c0));
            f(SlotMut::Field(c1));
        }
        for r in &mut fri.fri_roots {
            f(SlotMut::Digest(r));
        }
        for round in &mut fri.fri_queried_symbols {
            for (s0, s1) in round {
                f(SlotMut::Field(s0));
                f(SlotMut::Field(s1));
            }
        }
        for batch in &mut fri.fri_merkle_batch {
            for s in &mut batch.siblings {
                f(SlotMut::Digest(s));
            }
        }
        for v in &mut fri.final_codeword {
            f(SlotMut::Field(v));
        }
        let src = &mut p.opening.source_proof;
        for v in &mut src.h_evals {
            f(SlotMut::Field(v));
        }
        for r in &mut src.folded_roots {
            f(SlotMut::Digest(r));
        }
        for v in &mut src.source_symbols {
            f(SlotMut::Field(v));
        }
        for s in &mut src.source_merkle_batch.siblings {
            f(SlotMut::Digest(s));
        }
        for round in &mut src.folded_queried_symbols {
            for (s0, s1) in round {
                f(SlotMut::Field(s0));
                f(SlotMut::Field(s1));
            }
        }
        for batch in &mut src.folded_merkle_batch {
            for s in &mut batch.siblings {
                f(SlotMut::Digest(s));
            }
        }
    }

    enum SlotMut<'a> {
        Field(&'a mut Block128),
        Digest(&'a mut [u8; 32]),
    }

    fn mutate_slot(s: SlotMut<'_>) {
        match s {
            SlotMut::Field(v) => *v += Block128::ONE,
            SlotMut::Digest(d) => d[0] ^= 1,
        }
    }

    /// Positive: the honest wallet opening discharges — the full slot
    /// (owner-auth GKR + PCS) is satisfiable, and the native reduced claim
    /// matches the obligation the discharge consumed.
    #[test]
    fn auth_pcs_discharge_positive() {
        for owner_count in [1usize, 3] {
            let (inputs, public) = fixture(owner_count, 90 + owner_count as u128);
            let proof = prove(&inputs);
            assert!(native_accepts(&proof, &public));

            let circuit = noid_gkr::owner_auth::OwnerAuthCircuit::build(public.layout);
            let mut ch = owner_auth_gkr_channel();
            let claims =
                verify_owner_auth_killshot_with_claims(&proof, &circuit, &public, &mut ch)
                    .expect("native accepts");

            let mut b = FieldR1csBuilder::new();
            let (_, obligation) = build_owner_auth_slot(&mut b, &proof, &public);
            let before = b.num_wires();
            discharge_auth_pcs_obligation(&mut b, &obligation, &proof.pcs);
            let rows = b.num_wires() - before;
            assert_expr_is(&b, &obligation.reduction.value, claims.state.value, "value");
            let (r1cs, z) = b.build();
            assert!(
                r1cs.satisfies(&z),
                "honest auth-PCS discharge unsat ({owner_count} owners)"
            );
            eprintln!(
                "auth_pcs discharge rows: {rows} (owners={owner_count}, num_vars={})",
                public.layout.num_vars
            );
        }
    }

    /// Replay-completeness mutator over `proof.pcs`: every value slot of the opening proof
    /// (cap digests, openings, FRI oracles/roots/symbols/siblings, final
    /// codeword, source-binding tables/roots/symbols/siblings). 0 survivors
    /// required.
    #[test]
    fn auth_pcs_proof_mutator_kills_all() {
        let (inputs, public) = fixture(1, 300);
        let proof = prove(&inputs);
        assert!(native_accepts(&proof, &public));
        assert!(trace_accepts(&proof, &public));

        let mut n_slots = 0usize;
        {
            let mut c = proof.pcs.clone();
            visit_pcs_slots(&mut c, &mut |_| n_slots += 1);
        }
        let stride: usize = std::env::var("NOID_TRACE_MUTATE_STRIDE")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(41);
        let mut survivors = Vec::new();
        for target in (0..n_slots).step_by(stride) {
            let mut bad = proof.clone();
            let mut i = 0usize;
            visit_pcs_slots(&mut bad.pcs, &mut |slot| {
                if i == target {
                    mutate_slot(slot);
                }
                i += 1;
            });
            assert!(
                !native_accepts(&bad, &public),
                "native accepted pcs mutant {target}"
            );
            if trace_accepts(&bad, &public) {
                survivors.push(target);
            }
        }
        assert!(
            survivors.is_empty(),
            "surviving auth-PCS mutants: {survivors:?} of {n_slots} slots"
        );
    }

    /// Statement-side: a mutated reduced claim value (the wire the GKR batch
    /// closure feeds the discharge) must be unsatisfiable.
    #[test]
    fn auth_pcs_rejects_wrong_reduction_value() {
        let (inputs, public) = fixture(1, 310);
        let proof = prove(&inputs);
        let accepted = std::panic::catch_unwind(|| {
            let mut b = FieldR1csBuilder::new();
            let (_, obligation) = build_owner_auth_slot(&mut b, &proof, &public);
            let skewed = PendingAuthPcsObligation {
                commitment_cap_lanes: obligation.commitment_cap_lanes.clone(),
                num_vars: obligation.num_vars,
                reduction: super::super::BatchEvalReductionTrace {
                    point: obligation.reduction.point.clone(),
                    value: obligation
                        .reduction
                        .value
                        .add_const(flat_const(1u128)),
                },
            };
            discharge_auth_pcs_obligation(&mut b, &skewed, &proof.pcs);
            let (r1cs, z) = b.build();
            r1cs.satisfies(&z)
        })
        .unwrap_or(false);
        assert!(!accepted, "skewed reduction value must not discharge");
    }

    /// Randomized native⇔trace equivalence: honest and single-slot-mutated
    /// proofs across layouts must agree between the native killshot verifier
    /// (with PCS) and the full trace (slot + discharge).
    #[test]
    fn auth_pcs_native_trace_equivalence() {
        let cases: usize = std::env::var("NOID_TRACE_CROSS_CASES")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(24);
        let mut seed = 0x0F5A_11CEu128;
        let mut next = |m: u128| {
            seed = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(1);
            (seed >> 16) % m
        };
        let (inputs, public) = fixture(2, 500);
        let proof = prove(&inputs);
        let mut n_slots = 0usize;
        {
            let mut c = proof.pcs.clone();
            visit_pcs_slots(&mut c, &mut |_| n_slots += 1);
        }
        for case in 0..cases {
            let case_proof = if case % 2 == 0 {
                proof.clone()
            } else {
                let target = next(n_slots as u128) as usize;
                let mut bad = proof.clone();
                let mut i = 0usize;
                visit_pcs_slots(&mut bad.pcs, &mut |slot| {
                    if i == target {
                        mutate_slot(slot);
                    }
                    i += 1;
                });
                bad
            };
            let native = native_accepts(&case_proof, &public);
            let trace = trace_accepts(&case_proof, &public);
            assert_eq!(native, trace, "divergence at case {case}");
        }
    }
}
