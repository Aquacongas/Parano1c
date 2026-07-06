// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! [G] item 5b — the COMPLETE wallet-capsule mixed-opening AUTHENTICATION
//! discharged IN-TRACE via region families in ONE builder, as a reusable src
//! function ([`discharge_auth_pcs_obligation_via_region`]).
//!
//! This is the region twin of the inline
//! [`super::auth_pcs::discharge_auth_pcs_obligation`]: given the same
//! [`PendingAuthPcsObligation`] the owner-auth slot produced and the native
//! [`AuthMleOpeningProof`], it replays `verify_mixed_opening` over region
//! columns (source_tree + source-leaf + high-pair leaf families + the three
//! Merkle-authentication legs 3i / SB6 / SB8 + the SB7->SB9 fold chain + the
//! FRI fold-join), pinning every reduction terminal inline and collecting every
//! committed-column opening claim as a [`RegionPcsClaim`]. Unlike the inline fn
//! (which self-closes in R1CS), the region discharge produces committed-column
//! opening claims that the CALLER threads through the link's public IO — this fn
//! RETURNS them and does NOT build the public IO / prove.
//!
//! ## Structure — TWO union walks in ONE builder (memory)
//! A single deep-chain walk is ~1M rows; discharging every leg's leaf-walk AND
//! Merkle-walk as SEPARATE walks OOMs (region prover memory note). The
//! memory-safe assembly uses exactly TWO union walks, both in the SAME builder:
//!   - **walk A (leaf-union)**: source_tree (SB1.2) + SB6 source-leaf + SB8
//!     high-pair leaf families under ONE carry-selection + ONE walk + ONE
//!     unioned substitution; it opens each leaf tile's digest to a wire.
//!   - **walk B (merkle-union)**: the 3i FRI pair-leaf PLUS the three Merkle
//!     legs (3i / SB6-to-cap / SB8), a heterogeneous union under ONE
//!     carry-selection + ONE walk + ONE unioned substitution.
//! Walk A's per-tile leaf-digest wires feed walk B's SB6 / SB8 Merkle
//! `entry_wires`; walk B's pair-leaf digest wires feed the 3i Merkle entries —
//! all SHARED builder wires, never a public constant.
//!
//! ## Authentication-root TRANSCRIPT binding (the step-2c soundness addition)
//! The one obligation the proven gate deferred: each Merkle-auth root must be
//! bound to the Fiat-Shamir-OBSERVED root wire, not a fresh alloc, so a prover
//! cannot draw honest queries from the observed root yet authenticate fabricated
//! answers against a root chosen AFTER the query positions are known. Here every
//! Merkle leg's per-path root claim VALUE is the observed digest wire that
//! seeded the query draws:
//!   - 3i FRI leg (round r): the `fri_roots_w[r]` digest wire, observed via
//!     `observe_vector_commitment` inside the FRI sumcheck BEFORE the FRI query
//!     draw (all paths of a round share it).
//!   - SB8 leg (layer i): the `folded_roots_w[i]` digest wire, absorbed in the
//!     SB2 loop BEFORE the source query draw.
//!   - SB6 leg (to-cap): the SOURCE-CAP lane of the ABSORBED
//!     `commitment_cap_lanes` — `commitment_cap_lanes[(1<<MERKLE_CAP_DEPTH) +
//!     (leaf >> walk_depth)]`, absorbed by `absorb_cap` at the transcript start.
//! Because the recomputed root (in the Merkle family's C column at the root
//! slot) is opened == this observed wire, the walk-authenticated root IS the
//! transcript-seeded root — the auth is FS-bound.
//!
//! ## Scope (matches the proven gate `region_source_binding_full_e2e`)
//! The 3i FRI leg + FRI fold-join authenticate round 0 (n_rounds == 1 at the
//! wallet nv range validated by the unit gate). `RegionDischargeParams` exposes
//! the two documented memory reductions — `nq` (queries discharged; the channel
//! is still driven with the full `COMPACT_NUM_QUERIES`) and `sb8_auth_layers`
//! (deepest high-fold layers authenticated) — so the link can pass the full
//! values; the leaf fold chain in walk A still spans ALL `tau-1` layers to close
//! SB9 regardless.

use noid_core::hardware::flat_to_tower_u128;
use noid_core::{AdditiveNTT, Block128, TowerField};
use noid_fri::code::{Code, LOG_RATE};
use noid_fri::merkle::VectorCommitment;
use noid_fri::Channel;
use noid_fri_binius::compact_fri::{
    compute_round_depth, expand_batched_merkle_proof, expand_batched_merkle_proof_to_cap,
    gen_compact_queries, BatchedMerkleProof,
};
use noid_fri_binius::interleaved_commit::{
    source_cap_depth, source_cap_from_commitment_cap, source_leaf_hash, source_tree_depth,
    CommitmentHashBackend,
};
use noid_fri_binius::mixed_open::{
    high_pair_leaf_hash_for_trace, high_pair_leaf_index, high_pair_parity, high_pair_tree_depth,
    MIXED_OPEN_TAG, MIXED_SOURCE_BINDING_TAG,
};
use noid_fri_binius::{COMPACT_NUM_QUERIES, COMPACT_TAU, MERKLE_CAP_DEPTH};
use noid_gkr::auth_pcs::AuthMleOpeningProof;
use noid_poseidon2b::hasher::CryptographicHasher;
use noid_poseidon2b::native::permutation::STATE_SIZE;
use noid_poseidon2b::Poseidon2bSponge;

use noid_ivc_core::challenger::{Challenger, FsLaneChallenger};
use noid_ivc_core::deep_chain::leaf_hash::{
    build_high_pair_leaf_columns, build_pair_leaf_columns, build_source_leaf_columns,
    high_pair_leaf_chain, pair_leaf_refs, pair_leaf_substitution_terms, source_leaf_fixed_patterns,
    source_leaf_substitution_terms, PairLeafRefs, SourceLeafChain, SourceLeafRefs,
};
use noid_ivc_core::deep_chain::relations::{
    claimed_refs, prove_column_relation, prove_shift_discharge, verify_column_relation,
    verify_shift_discharge, window_discharge_point, ColRef, ColumnRelationProof, FixedPattern,
    RelationColumns, RelationTerm, ShiftDischargeProof,
};
use noid_ivc_core::deep_chain::schedule::{
    build_merkle_path_columns, carry_selection_terms, flat_of_tower_u128, merkle_booleanity_terms,
    merkle_fixed_patterns, merkle_substitution_terms, MerkleFamilyRefs, MerklePathColumns,
    MerklePathFamily, MerklePathWitness,
};
use noid_ivc_core::deep_chain::source_tree::{
    build_source_code_columns, build_source_tree_columns, compress_iv_flat,
    source_tree_exposure_terms, source_tree_fixed_patterns, source_tree_substitution_terms,
    SourceTree, SourceTreeRefs,
};
use noid_ivc_core::deep_chain::{
    prove_deep_chain_walk, verify_deep_chain_walk, DeepChainWalkProof, LaneClaimGroup,
};
use noid_ivc_core::field::F128;
use noid_ivc_core::field_circuit::{FieldR1csBuilder, FsChannelTrace, LinExpr};
use noid_ivc_core::public_io::WitnessSlice;

use super::auth_pcs::absorb_cap_trace;
use super::deep_chain::{
    verify_column_relation_trace, verify_deep_chain_walk_trace, verify_shift_discharge_trace,
    ColumnRelationProofTrace, DeepChainWalkProofTrace, LaneClaimGroupTrace, RelationTermTrace,
    ShiftDischargeProofTrace,
};
use super::fri_pcs::{
    alloc_digest, code_new_trace, fold_trace, gen_compact_queries_trace, mle_evaluate_small_trace,
    FriChannelTrace,
};
use super::owner_auth::PendingAuthPcsObligation;
use super::{alloc_blocks, eq_ind_partial_eval_trace, flat_of, mul, pin_eq};

// FS domains for the two region walks (self-contained sub-protocols; the
// soundness of the discharge lives in the committed-column opening claims the
// caller threads through the outer PCS, not in these transcripts).
const DOMAIN: &[u8] = b"source-binding-full-leaf-union";
const DOMAIN_B: &[u8] = b"source-binding-full-merkle-union";

// Meta committed column order (all length P):
//   CODE0=0, CODE1=1, KID0=2, KID1=3, IN0=4, IN1=5, C0=6..C3=9.
const CODE0: usize = 0;
const KID0: usize = 2;
const IN0: usize = 4;
const C0: usize = 6;
const N_COMMITTED: usize = 10;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// One discharged committed-column opening claim, carrying both the trace-wire
/// (point, value) and the concrete native (point, value) the caller folds into
/// the link's public IO envelope. `slice` is the committed [`WitnessSlice`]
/// allocated in the builder for this claim's column.
pub struct RegionPcsClaim {
    pub slice: WitnessSlice,
    /// Trace-wire point coordinates.
    pub point: Vec<LinExpr>,
    /// Trace-wire opened value.
    pub value: LinExpr,
    /// Native point (for the caller's IO envelope).
    pub native_point: Vec<F128>,
    /// Native opened value (for the caller's IO envelope).
    pub native_value: F128,
}

/// The two documented memory reductions of the region discharge, exposed so the
/// unit gate can keep them small while the link passes the full values.
#[derive(Clone, Copy, Debug)]
pub struct RegionDischargeParams {
    /// Number of distinct queries AUTHENTICATED per leg (a subset of
    /// `COMPACT_NUM_QUERIES`; the channel is still driven with the full count,
    /// so the transcript is faithful). The flatness — that this cost is
    /// query-count independent — is proven separately.
    pub nq: usize,
    /// Number of DEEPEST SB8 high-fold layers authenticated. The leaf fold chain
    /// in walk A always spans ALL `tau-1` layers to close SB9 regardless.
    pub sb8_auth_layers: usize,
}

/// Discharge one [`PendingAuthPcsObligation`] — the region twin of the inline
/// [`super::auth_pcs::discharge_auth_pcs_obligation`]. Replays the wallet-capsule
/// mixed opening IN-TRACE over region families in the SAME builder, TRANSCRIPT-
/// BINDS each Merkle-auth root to its FS-observed root wire, closes the discharge
/// contract (`all_openings[0] == reduction.value`), and RETURNS every committed-
/// column opening claim for the caller to thread through the link's public IO.
pub fn discharge_auth_pcs_obligation_via_region(
    b: &mut FieldR1csBuilder,
    obligation: &PendingAuthPcsObligation,
    native: &AuthMleOpeningProof,
    params: RegionDischargeParams,
) -> Vec<RegionPcsClaim> {
    let num_vars = obligation.num_vars;
    let proof = native;
    // Shape checks (same contract as the inline discharge).
    assert_eq!(proof.commitment.log_rows, num_vars);
    assert_eq!(proof.commitment.n_cols, 1);
    assert_eq!(obligation.reduction.point.len(), num_vars);
    assert_eq!(
        obligation.commitment_cap_lanes.len(),
        proof.commitment.cap.hashes.len()
    );

    // Recover the NATIVE reduction point (tower) from the obligation wires — the
    // wallet-PCS was opened at exactly this point, so the source binding below
    // reproduces the proof's roots (asserted). The wires carry φ(point); φ⁻¹ is
    // flat->tower.
    let point: Vec<Block128> = obligation
        .reduction
        .point
        .iter()
        .map(|e| {
            let f = e.eval(b.values());
            let flat = (f.lo as u128) | ((f.hi as u128) << 64);
            Block128::from(flat_to_tower_u128(flat))
        })
        .collect();

    let nq = params.nq;
    let log_n = proof.commitment.log_rows;
    let tau = COMPACT_TAU.min(log_n);
    let n_rounds = log_n - tau;
    let ntt = AdditiveNTT::<Block128>::new(num_vars + LOG_RATE);

    let opening = &proof.opening;
    let fri = &opening.fri_proof;
    let src = &opening.source_proof;
    let right_tower = &point[..n_rounds];

    // Source tree (SB1.2): Code(H·eq_right) → φ into the flat basis.
    let eq_r = eq_tensor_tower(right_tower);
    let g: Vec<Block128> = src.h_evals.iter().zip(eq_r.iter()).map(|(&h, &e)| h * e).collect();
    let g_code = Code::new_parallel(&g, &ntt);
    let g_code_flat: Vec<F128> = g_code.encoding.iter().map(|&bb| phi(bb)).collect();
    let tree = SourceTree { leaf_log: n_rounds + 1 };
    assert_eq!(tree.code_len(), g_code_flat.len());
    let st_wlog = tree.slots_log();
    let st_slots = tree.n_slots();
    let st_cols = build_source_tree_columns(&tree, &g_code_flat, st_wlog);
    let st_code_cols = build_source_code_columns(&tree, &g_code_flat, st_wlog);
    let fri_root0 = lanes_flat(&fri.fri_roots[0]);
    assert_eq!(st_cols.root, fri_root0, "region tree root != φ(fri_roots[0])");

    // -------------------------------------------------------------------
    // Family layout in ONE meta domain (all clean-start; source_tree at 0).
    // -------------------------------------------------------------------
    let leaf_chain = SourceLeafChain { n_cols: 1 };
    let hp_chain = high_pair_leaf_chain();
    let leaf_stride = leaf_chain.stride();
    let leaf_stride_log = leaf_stride.trailing_zeros() as usize;
    assert_eq!(leaf_stride, hp_chain.stride());

    let n_layers = tau.saturating_sub(1);
    let n_leaf_families = 1 + n_layers;
    let leaf_family_slots = nq * leaf_stride;

    let total = st_slots + n_leaf_families * leaf_family_slots;
    let w_log = total.next_power_of_two().trailing_zeros() as usize;
    let p = 1usize << w_log;
    let leaf_base = |f: usize| st_slots + f * leaf_family_slots;

    // -------------------------------------------------------------------
    // Drive the REAL FRICHANL channel from the obligation's absorbed cap +
    // reduction point (no fresh alloc — these wires bind to the killshot).
    // -------------------------------------------------------------------
    let all_openings = alloc_blocks(b, &opening.all_openings);
    let upper = alloc_blocks(b, &fri.upper_partial_evals);
    let h_evals_w = alloc_blocks(b, &src.h_evals);
    let fri_roots_w: Vec<[LinExpr; 2]> = fri.fri_roots.iter().map(|r| alloc_digest(b, r)).collect();
    let fri_root0_w = fri_roots_w[0].clone();
    let folded_roots_w: Vec<[LinExpr; 2]> =
        src.folded_roots.iter().map(|r| alloc_digest(b, r)).collect();

    let point_w = &obligation.reduction.point;

    let mut ch = FriChannelTrace::new();
    absorb_cap_trace(b, &mut ch, &obligation.commitment_cap_lanes);
    ch.observe_const_tower(b, MIXED_OPEN_TAG as u128);
    ch.observe_field_elems(b, &all_openings);
    let _gamma = ch.squeeze(b);
    let batched_claim = all_openings[0].clone();

    ch.observe_field_elems(b, point_w); // 3a
    let (right_w, left_w) = point_w.split_at(n_rounds);
    let left_eq = eq_ind_partial_eval_trace(b, left_w); // 3c
    let mut derived = LinExpr::zero();
    for (l, u) in left_eq.iter().zip(upper.iter()) {
        derived = derived.add(&mul(b, l, u));
    }
    pin_eq(b, &derived, &batched_claim);
    ch.observe_field_elem(b, &batched_claim);

    let beta = ch.squeeze_n(b, tau); // 3d
    let batching_eq = eq_ind_partial_eval_trace(b, &beta);
    let mut claim = LinExpr::zero();
    for (u, be) in upper.iter().zip(batching_eq.iter()) {
        claim = claim.add(&mul(b, u, be));
    }
    let initial_claim = claim.clone();

    // SB1.1: H(right) == initial sumcheck claim.
    let h_at_right = mle_evaluate_small_trace(b, &h_evals_w, right_w);
    pin_eq(b, &h_at_right, &initial_claim);

    // 3e sumcheck rounds. Collect the challenges — the channel<->algebra join
    // (random_point -> fold_trace) for the 3i FRI leg.
    let mut random_point: Vec<LinExpr> = Vec::with_capacity(n_rounds);
    for round in 0..n_rounds {
        let c0 = alloc_blocks(b, std::slice::from_ref(&fri.sum_check_oracles[round][0]))[0].clone();
        let c1 = alloc_blocks(b, std::slice::from_ref(&fri.sum_check_oracles[round][1]))[0].clone();
        pin_eq(b, &c1, &claim);
        ch.observe_field_elem(b, &c0);
        ch.observe_field_elem(b, &c1);
        let depth = compute_round_depth(n_rounds, round);
        ch.observe_vector_commitment(b, &fri_roots_w[round], depth);
        let r = ch.squeeze(b);
        claim = c0.add(&mul(b, &c1, &r));
        random_point.push(r);
    }
    // 3f final codeword.
    let final_cw = alloc_blocks(b, &fri.final_codeword);
    ch.observe_field_elems(b, &final_cw);

    // SB2 source-binding absorbs.
    ch.observe_const_tower(b, MIXED_SOURCE_BINDING_TAG);
    ch.observe_field_elems(b, &h_evals_w);
    for (i, root_w) in folded_roots_w.iter().enumerate() {
        ch.observe_vector_commitment(b, root_w, high_pair_tree_depth(log_n - 1 - i));
    }
    // SB3 source query draw; 3h FRI query draw.
    let query_indices = gen_compact_queries_trace(b, &mut ch, log_n + LOG_RATE, COMPACT_NUM_QUERIES);
    assert!(query_indices.len() >= nq, "need at least nq source queries");
    let fri_queries = gen_compact_queries_trace(b, &mut ch, n_rounds + LOG_RATE, COMPACT_NUM_QUERIES);
    assert!(fri_queries.len() >= nq, "need at least nq FRI queries");
    // Cross-check the in-trace draws against the REAL noid_fri::Channel.
    let (native_source_queries, native_fri_queries) =
        derive_queries(proof, &point, COMPACT_NUM_QUERIES);
    assert_eq!(query_indices, native_source_queries, "in-trace source queries match native");
    assert_eq!(fri_queries, native_fri_queries, "in-trace FRI queries match native");

    // SB1.2: g_code = Code(H·eq_right) computed in-trace.
    let eq_right_w = eq_ind_partial_eval_trace(b, right_w);
    let mut g_evals_w = Vec::with_capacity(h_evals_w.len());
    for (h, e) in h_evals_w.iter().zip(eq_right_w.iter()) {
        g_evals_w.push(mul(b, h, e));
    }
    let g_code_w = code_new_trace(&g_evals_w);
    assert_eq!(g_code_w.len(), g_code_flat.len());

    // h_code = Code(h_evals) for the SB9 closure.
    let h_code = Code::new_parallel(&src.h_evals, &ntt);
    let h_code_w = code_new_trace(&h_evals_w);
    assert_eq!(h_code_w.len(), h_code.encoding.len());

    // -------------------------------------------------------------------
    // Build the meta committed columns from the real source binding.
    // -------------------------------------------------------------------
    let mut cols: Vec<Vec<F128>> = (0..N_COMMITTED).map(|_| vec![F128::ZERO; p]).collect();
    let mut s0: [Vec<F128>; STATE_SIZE] = std::array::from_fn(|_| vec![F128::ZERO; p]);
    let mut s_out: [Vec<F128>; STATE_SIZE] = std::array::from_fn(|_| vec![F128::ZERO; p]);
    let (ghost_s0, ghost_out) =
        noid_ivc_core::deep_chain::source_tree::run_perm([F128::ZERO; STATE_SIZE]);
    for slot in 0..p {
        for j in 0..STATE_SIZE {
            s0[j][slot] = ghost_s0[j];
            s_out[j][slot] = ghost_out[j];
            cols[C0 + j][slot] = ghost_out[j];
        }
    }

    // Source_tree at [0, st_slots).
    for j in 0..2 {
        cols[CODE0 + j][0..st_slots].copy_from_slice(&st_code_cols[j]);
        cols[KID0 + j][0..st_slots].copy_from_slice(&st_cols.kid[j]);
    }
    for j in 0..STATE_SIZE {
        cols[C0 + j][0..st_slots].copy_from_slice(&st_cols.c[j]);
        s0[j][0..st_slots].copy_from_slice(&st_cols.s0[j]);
        s_out[j][0..st_slots].copy_from_slice(&st_cols.s_out[j]);
    }

    // Source query -> source pair indices; source symbols.
    let source_pair_indices: Vec<usize> =
        query_indices.iter().map(|&qi| high_pair_leaf_index(qi, log_n)).collect();

    // SB6 source-leaf family (family 0): nq tiles.
    let sb6_base = leaf_base(0);
    let mut sb6_syms: Vec<[F128; 2]> = Vec::with_capacity(nq);
    let mut sb6_digest_vals: Vec<[F128; 2]> = Vec::with_capacity(nq);
    for q in 0..nq {
        let leaf_idx = source_pair_indices[q];
        let s0v = src.source_symbols[q * 2];
        let s1v = src.source_symbols[q * 2 + 1];
        let syms = [phi(s0v), phi(s1v)];
        sb6_syms.push(syms);
        let tile = build_source_leaf_columns(&leaf_chain, log_n, leaf_idx, &syms, leaf_stride_log);
        sb6_digest_vals.push(tile.digest);
        let off = sb6_base + q * leaf_stride;
        for j in 0..2 {
            cols[IN0 + j][off..off + leaf_stride].copy_from_slice(&tile.in_[j]);
        }
        for j in 0..STATE_SIZE {
            cols[C0 + j][off..off + leaf_stride].copy_from_slice(&tile.c[j]);
            s0[j][off..off + leaf_stride].copy_from_slice(&tile.s0[j]);
            s_out[j][off..off + leaf_stride].copy_from_slice(&tile.s_out[j]);
        }
    }

    // SB8 high-pair families: fold-chain index/symbol bookkeeping.
    let current: Vec<usize> = source_pair_indices[..nq].to_vec();
    struct LayerData {
        layer_log: usize,
        pair_indices: Vec<usize>,
        syms: Vec<(Block128, Block128)>,
    }
    let mut layers: Vec<LayerData> = Vec::with_capacity(n_layers);
    {
        let mut cur = current.clone();
        for layer in 0..n_layers {
            let layer_log = log_n - 1 - layer;
            let symbols = &src.folded_queried_symbols[layer];
            let pair_indices: Vec<usize> =
                cur.iter().map(|&idx| high_pair_leaf_index(idx, layer_log)).collect();
            let syms: Vec<(Block128, Block128)> = (0..nq).map(|q| symbols[q]).collect();
            layers.push(LayerData { layer_log, pair_indices: pair_indices.clone(), syms });
            cur = pair_indices;
        }
    }

    let mut sb8_digest_vals: Vec<Vec<[F128; 2]>> = Vec::with_capacity(n_layers);
    for (layer, ld) in layers.iter().enumerate() {
        let base = leaf_base(layer + 1);
        let mut layer_digests: Vec<[F128; 2]> = Vec::with_capacity(nq);
        for q in 0..nq {
            let (s0v, s1v) = ld.syms[q];
            let tile = build_high_pair_leaf_columns(
                ld.layer_log,
                ld.pair_indices[q],
                phi(s0v),
                phi(s1v),
                leaf_stride_log,
            );
            layer_digests.push(tile.digest);
            let off = base + q * leaf_stride;
            for j in 0..2 {
                cols[IN0 + j][off..off + leaf_stride].copy_from_slice(&tile.in_[j]);
            }
            for j in 0..STATE_SIZE {
                cols[C0 + j][off..off + leaf_stride].copy_from_slice(&tile.c[j]);
                s0[j][off..off + leaf_stride].copy_from_slice(&tile.s0[j]);
                s_out[j][off..off + leaf_stride].copy_from_slice(&tile.s_out[j]);
            }
        }
        sb8_digest_vals.push(layer_digests);
    }

    // -------------------------------------------------------------------
    // Fixed patterns (localized) + refs.
    // -------------------------------------------------------------------
    let iv = compress_iv_flat();
    let mut fixed: Vec<FixedPattern> = Vec::new();
    for pat in source_tree_fixed_patterns(&tree, iv) {
        fixed.push(localize(&pat.table, 0, w_log));
    }
    for f in 0..n_leaf_families {
        let base = leaf_base(f);
        for pat in source_leaf_fixed_patterns(&leaf_chain, iv) {
            fixed.push(localize_tiled(&pat.table, base, nq, w_log));
        }
    }

    let st_refs = SourceTreeRefs {
        code: [CODE0, CODE0 + 1],
        kid: [KID0, KID0 + 1],
        c: std::array::from_fn(|i| C0 + i),
        even_int: 0,
        odd_int: 1,
        leafodd: 2,
        iv: [3, 4],
    };
    let leaf_refs: Vec<SourceLeafRefs> = (0..n_leaf_families)
        .map(|f| SourceLeafRefs {
            in_: [IN0, IN0 + 1],
            c: std::array::from_fn(|i| C0 + i),
            hp: 5 + f * 5,
            even: 5 + f * 5 + 1,
            odd: 5 + f * 5 + 2,
            iv: [5 + f * 5 + 3, 5 + f * 5 + 4],
        })
        .collect();

    // -------------------------------------------------------------------
    // Native union DAG (exposure over source_tree's own 16-view).
    // -------------------------------------------------------------------
    let half = 1usize << (st_wlog - 1);
    let kid_lo0: Vec<F128> = st_cols.kid[0][..half].to_vec();
    let kid_lo1: Vec<F128> = st_cols.kid[1][..half].to_vec();
    let committed: Vec<&[F128]> = cols.iter().map(|c| c.as_slice()).collect();
    let native_u = {
        let expo_committed: Vec<&[F128]> = vec![&kid_lo0, &kid_lo1, &st_cols.c[0], &st_cols.c[1]];
        run_union_native(
            &committed, &s0, &s_out, &fixed, &st_refs, &leaf_refs, w_log, &expo_committed, st_wlog,
            [KID0, KID0 + 1], [C0, C0 + 1],
        )
    };

    // -------------------------------------------------------------------
    // Allocate the walk-A committed slices, then discharge.
    // -------------------------------------------------------------------
    let mut slices: Vec<WitnessSlice> =
        cols.iter().map(|c| alloc_column_slice(b, c, w_log).0).collect();

    let mut claims = discharge_union(b, &fixed, &st_refs, &leaf_refs, w_log, st_wlog, &native_u);

    // -------------------------------------------------------------------
    // Grand pins: SB1.2 CODE + root; SB7->SB9 fold chain.
    // -------------------------------------------------------------------
    let l = tree.leaf_count();
    for i in 0..l {
        let slot = 2 * (l + i) + 1;
        let (pt_lin, pt_nat) = slot_point(slot, w_log);
        for lane in 0..2 {
            claims.push(Claim {
                slice: CODE0 + lane,
                point: pt_lin.clone(),
                value: g_code_w[2 * i + lane].clone(),
                native_point: pt_nat.clone(),
                native_value: g_code_flat[2 * i + lane],
            });
        }
    }
    let (rp_lin, rp_nat) = slot_point(3, w_log);
    for lane in 0..2 {
        claims.push(Claim {
            slice: C0 + lane,
            point: rp_lin.clone(),
            value: fri_root0_w[lane].clone(),
            native_point: rp_nat.clone(),
            native_value: fri_root0[lane],
        });
    }

    // SB7 + SB8 fold chain, source symbols pinned to SB6 IN columns.
    let mut folded_w: Vec<LinExpr> = Vec::with_capacity(nq);
    for q in 0..nq {
        let s0w = LinExpr::from_wire(b.alloc_f128(sb6_syms[q][0]));
        let s1w = LinExpr::from_wire(b.alloc_f128(sb6_syms[q][1]));
        let off = sb6_base + q * leaf_stride + 4;
        let (pt_lin, pt_nat) = slot_point(off, w_log);
        claims.push(Claim {
            slice: IN0,
            point: pt_lin.clone(),
            value: s0w.clone(),
            native_point: pt_nat.clone(),
            native_value: sb6_syms[q][0],
        });
        claims.push(Claim {
            slice: IN0 + 1,
            point: pt_lin,
            value: s1w.clone(),
            native_point: pt_nat,
            native_value: sb6_syms[q][1],
        });
        let folded =
            tensor_high_fold_pair_trace(b, &beta[tau - 1], log_n, source_pair_indices[q], &s0w, &s1w);
        folded_w.push(folded);
    }

    let mut cur_idx = current.clone();
    for (layer, ld) in layers.iter().enumerate() {
        let base = leaf_base(layer + 1);
        let r = &beta[tau - 2 - layer];
        let mut next_w: Vec<LinExpr> = Vec::with_capacity(nq);
        for q in 0..nq {
            let (s0v, s1v) = ld.syms[q];
            let s0f = phi(s0v);
            let s1f = phi(s1v);
            let s0w = LinExpr::from_wire(b.alloc_f128(s0f));
            let s1w = LinExpr::from_wire(b.alloc_f128(s1f));
            let off = base + q * leaf_stride + 4;
            let (pt_lin, pt_nat) = slot_point(off, w_log);
            claims.push(Claim {
                slice: IN0,
                point: pt_lin.clone(),
                value: s0w.clone(),
                native_point: pt_nat.clone(),
                native_value: s0f,
            });
            claims.push(Claim {
                slice: IN0 + 1,
                point: pt_lin,
                value: s1w.clone(),
                native_point: pt_nat,
                native_value: s1f,
            });
            let parity = high_pair_parity(cur_idx[q], ld.layer_log);
            let expected = if parity == 1 { &s1w } else { &s0w };
            pin_eq(b, &folded_w[q], expected);
            let folded = tensor_high_fold_pair_trace(b, r, ld.layer_log, ld.pair_indices[q], &s0w, &s1w);
            next_w.push(folded);
        }
        folded_w = next_w;
        cur_idx = ld.pair_indices.clone();
    }

    // SB9: the closed fold == h_code[current[q]].
    for q in 0..nq {
        let idx = cur_idx[q];
        assert!(idx < h_code_w.len(), "SB9 index in range");
        pin_eq(b, &folded_w[q], &h_code_w[idx]);
    }
    let _ = &h_code;
    let _ = current.as_slice();

    // ===================================================================
    // WALK A leaf-digest wires -> SB6 / SB8 Merkle entries (shared wires).
    // ===================================================================
    let digest_slot = leaf_chain.digest_slot();
    let mut sb6_digest_wires: Vec<[LinExpr; 2]> = Vec::with_capacity(nq);
    for q in 0..nq {
        let slot = sb6_base + q * leaf_stride + digest_slot;
        let (pt_lin, pt_nat) = slot_point(slot, w_log);
        let mut wires = [LinExpr::zero(), LinExpr::zero()];
        for lane in 0..2 {
            let v = LinExpr::from_wire(b.alloc_f128(sb6_digest_vals[q][lane]));
            claims.push(Claim {
                slice: C0 + lane,
                point: pt_lin.clone(),
                value: v.clone(),
                native_point: pt_nat.clone(),
                native_value: sb6_digest_vals[q][lane],
            });
            wires[lane] = v;
        }
        sb6_digest_wires.push(wires);
    }
    // The deepest SB8 fold layers (smallest trees) are authenticated.
    assert!(
        params.sb8_auth_layers <= n_layers,
        "sb8_auth_layers exceeds available fold layers"
    );
    let sb8_auth_layers: Vec<usize> =
        (0..params.sb8_auth_layers).map(|k| n_layers - 1 - k).collect();
    let mut sb8_digest_wires: Vec<Vec<[LinExpr; 2]>> = Vec::new();
    for &layer in &sb8_auth_layers {
        let base = leaf_base(layer + 1);
        let mut lw = Vec::with_capacity(nq);
        for q in 0..nq {
            let slot = base + q * leaf_stride + digest_slot;
            let (pt_lin, pt_nat) = slot_point(slot, w_log);
            let mut wires = [LinExpr::zero(), LinExpr::zero()];
            for lane in 0..2 {
                let v = LinExpr::from_wire(b.alloc_f128(sb8_digest_vals[layer][q][lane]));
                claims.push(Claim {
                    slice: C0 + lane,
                    point: pt_lin.clone(),
                    value: v.clone(),
                    native_point: pt_nat.clone(),
                    native_value: sb8_digest_vals[layer][q][lane],
                });
                wires[lane] = v;
            }
            lw.push(wires);
        }
        sb8_digest_wires.push(lw);
    }

    // ===================================================================
    // WALK B — the merkle-union: 3i / SB6-to-cap / SB8 legs. Root claim VALUES
    // are the FS-OBSERVED root wires (transcript-bound).
    // ===================================================================
    let hasher = Poseidon2bSponge::new();
    let iv_b = compress_iv_flat();
    let round = 0usize;

    let fri_pair_indices: Vec<usize> =
        fri_queries[..nq].iter().map(|&qi| (qi >> round) >> 1).collect();
    let fri_pairs: Vec<(F128, F128)> = (0..nq)
        .map(|q| {
            let (s0v, s1v) = fri.fri_queried_symbols[round][q];
            (phi(s0v), phi(s1v))
        })
        .collect();
    let pair_wlog = nq.trailing_zeros() as usize;
    let (pair_cols, pair_digests) = build_pair_leaf_columns(&fri_pairs, pair_wlog);

    let sb6_walk_depth = source_tree_depth(log_n) - source_cap_depth(log_n);
    let mut leg_depths: Vec<usize> = vec![compute_round_depth(n_rounds, round), sb6_walk_depth];
    for &layer in &sb8_auth_layers {
        leg_depths.push(high_pair_tree_depth(log_n - 1 - layer));
    }
    let n_legs = leg_depths.len();

    let mut meta_bases = Vec::with_capacity(n_legs);
    let mut acc = nq;
    for &d in &leg_depths {
        meta_bases.push(acc);
        acc += nq * (2 * d).next_power_of_two();
    }
    let w_log_b = acc.next_power_of_two().trailing_zeros() as usize;
    let pb = 1usize << w_log_b;
    let n_committed_b = 6 + 5 * n_legs;
    let region_pair = 0usize;
    let pair_refs = pair_leaf_refs(0);

    let mut cb: Vec<Vec<F128>> = (0..n_committed_b).map(|_| vec![F128::ZERO; pb]).collect();
    let mut s0b: [Vec<F128>; STATE_SIZE] = std::array::from_fn(|_| vec![F128::ZERO; pb]);
    let mut soutb: [Vec<F128>; STATE_SIZE] = std::array::from_fn(|_| vec![F128::ZERO; pb]);
    let (ghb0, ghbo) = noid_ivc_core::deep_chain::source_tree::run_perm([F128::ZERO; STATE_SIZE]);
    for slot in 0..pb {
        for j in 0..STATE_SIZE {
            s0b[j][slot] = ghb0[j];
            soutb[j][slot] = ghbo[j];
            cb[2 + j][slot] = ghbo[j];
        }
    }
    for j in 0..2 {
        cb[j][0..nq].copy_from_slice(&pair_cols.in_[j][0..nq]);
    }
    for j in 0..STATE_SIZE {
        cb[2 + j][0..nq].copy_from_slice(&pair_cols.c[j][0..nq]);
        s0b[j][0..nq].copy_from_slice(&pair_cols.s0[j][0..nq]);
        soutb[j][0..nq].copy_from_slice(&pair_cols.s_out[j][0..nq]);
    }

    let mut legs: Vec<MerkleLeg> = Vec::new();
    let mut all_expands_ok = true;

    // Leg 0: 3i FRI-round openings (single per-round root == fri_roots_w[round]).
    {
        let f = 0usize;
        let depth = leg_depths[f];
        let meta_base = meta_bases[f];
        let col_base = 6 + 5 * f;
        let fixed_base = 1 + 9 * f;
        let region = fixed_base + 8;
        let stride = (2 * depth).next_power_of_two();
        let n_slots = nq * stride;
        let fam_wlog = n_slots.trailing_zeros() as usize;
        let all_pi: Vec<usize> = fri_queries.iter().map(|&qi| (qi >> round) >> 1).collect();
        let all_leaves: Vec<[u8; 32]> = fri.fri_queried_symbols[round]
            .iter()
            .map(|(s0v, s1v)| hasher.hash_pair(s0v, s1v))
            .collect();
        let batch = BatchedMerkleProof { siblings: fri.fri_merkle_batch[round].siblings.clone() };
        let paths = expand_batched_merkle_proof(&batch, depth, &all_pi, &all_leaves, &hasher)
            .expect("3i FRI octopus expand");
        all_expands_ok &= !paths.is_empty();
        let root_flat = lanes_flat(&fri.fri_roots[round]);
        let mut witnesses = Vec::with_capacity(nq);
        let mut entry_vals = Vec::with_capacity(nq);
        let mut committed_roots = Vec::with_capacity(nq);
        for q in 0..nq {
            let path = paths
                .iter()
                .find(|p| p.leaf_index == fri_pair_indices[q])
                .expect("3i FRI path");
            let leaf_flat = lanes_flat(&path.leaf_hash);
            assert_eq!(pair_digests[q], leaf_flat, "3i pair-leaf digest != φ(native leaf)");
            witnesses.push(MerklePathWitness {
                entry: leaf_flat,
                siblings: path.siblings.iter().map(lanes_flat).collect(),
                directions: path.directions.clone(),
            });
            entry_vals.push(leaf_flat);
            committed_roots.push(root_flat);
        }
        let family = MerklePathFamily { depth, n_paths: nq };
        let mcols = build_merkle_path_columns(&family, iv_b, &witnesses, fam_wlog);
        place_merkle(&mut cb, &mut s0b, &mut soutb, &mcols, col_base, meta_base, n_slots);
        // TRANSCRIPT-BINDING: root == the FS-observed round root wire.
        let root_wires: Vec<[LinExpr; 2]> = (0..nq).map(|_| fri_roots_w[round].clone()).collect();
        legs.push(MerkleLeg {
            family,
            refs: union_merkle_refs(col_base, fixed_base),
            region,
            meta_base,
            cols: mcols,
            entry_vals,
            committed_roots,
            entry_wires: Vec::new(),
            pair_entry_map: Some((0..nq).collect()),
            root_wires,
        });
    }

    // Leg 1: SB6 source-tree opening (authenticated to the committed CAP; the
    // root == the FS-observed source-cap lane of the ABSORBED commitment cap).
    {
        let f = 1usize;
        let depth = leg_depths[f];
        let meta_base = meta_bases[f];
        let col_base = 6 + 5 * f;
        let fixed_base = 1 + 9 * f;
        let region = fixed_base + 8;
        let stride = (2 * depth).next_power_of_two();
        let n_slots = nq * stride;
        let fam_wlog = n_slots.trailing_zeros() as usize;
        let cap_flat: Vec<[F128; 2]> = source_cap_from_commitment_cap(&proof.commitment.cap, log_n)
            .expect("source cap")
            .iter()
            .map(lanes_flat)
            .collect();
        let all_leaves: Vec<[u8; 32]> = source_pair_indices
            .iter()
            .enumerate()
            .map(|(q, &li)| {
                let syms = [src.source_symbols[q * 2], src.source_symbols[q * 2 + 1]];
                source_leaf_hash(CommitmentHashBackend::Arithmetic, log_n, 1, li, &syms, &hasher)
            })
            .collect();
        let batch = BatchedMerkleProof { siblings: src.source_merkle_batch.siblings.clone() };
        let paths = expand_batched_merkle_proof_to_cap(
            &batch,
            source_tree_depth(log_n),
            source_cap_depth(log_n),
            &source_pair_indices,
            &all_leaves,
            &hasher,
        )
        .expect("SB6 source octopus expand");
        all_expands_ok &= !paths.is_empty();
        let cap_start = 1usize << MERKLE_CAP_DEPTH;
        let mut witnesses = Vec::with_capacity(nq);
        let mut entry_vals = Vec::with_capacity(nq);
        let mut committed_roots = Vec::with_capacity(nq);
        let mut root_wires = Vec::with_capacity(nq);
        for q in 0..nq {
            let li = source_pair_indices[q];
            let path = paths.iter().find(|p| p.leaf_index == li).expect("SB6 source path");
            assert_eq!(path.siblings.len(), sb6_walk_depth, "SB6 path is walk-depth long");
            let leaf_flat = lanes_flat(&path.leaf_hash);
            assert_eq!(sb6_digest_vals[q], leaf_flat, "SB6 leaf digest != φ(native leaf)");
            witnesses.push(MerklePathWitness {
                entry: leaf_flat,
                siblings: path.siblings.iter().map(lanes_flat).collect(),
                directions: path.directions.clone(),
            });
            entry_vals.push(leaf_flat);
            let cap_idx = li >> sb6_walk_depth;
            committed_roots.push(cap_flat[cap_idx]);
            // TRANSCRIPT-BINDING: root == the FS-observed source-cap lane wire.
            root_wires.push(obligation.commitment_cap_lanes[cap_start + cap_idx].clone());
        }
        let family = MerklePathFamily { depth, n_paths: nq };
        let mcols = build_merkle_path_columns(&family, iv_b, &witnesses, fam_wlog);
        place_merkle(&mut cb, &mut s0b, &mut soutb, &mcols, col_base, meta_base, n_slots);
        legs.push(MerkleLeg {
            family,
            refs: union_merkle_refs(col_base, fixed_base),
            region,
            meta_base,
            cols: mcols,
            entry_vals,
            committed_roots,
            entry_wires: sb6_digest_wires.clone(),
            pair_entry_map: None,
            root_wires,
        });
    }

    // Legs 2..: SB8 high-fold layer openings (root == the FS-observed
    // folded_roots_w[layer] wire, absorbed before the source query draw).
    for (k, &layer) in sb8_auth_layers.iter().enumerate() {
        let f = 2 + k;
        let depth = leg_depths[f];
        let meta_base = meta_bases[f];
        let col_base = 6 + 5 * f;
        let fixed_base = 1 + 9 * f;
        let region = fixed_base + 8;
        let stride = (2 * depth).next_power_of_two();
        let n_slots = nq * stride;
        let fam_wlog = n_slots.trailing_zeros() as usize;
        let layer_log = log_n - 1 - layer;
        let li_all: Vec<usize> = {
            let mut cur = source_pair_indices.clone();
            for ll in 0..layer {
                let lll = log_n - 1 - ll;
                cur = cur.iter().map(|&idx| high_pair_leaf_index(idx, lll)).collect();
            }
            cur.iter().map(|&idx| high_pair_leaf_index(idx, layer_log)).collect()
        };
        let layer_symbols = &src.folded_queried_symbols[layer];
        let all_leaves: Vec<[u8; 32]> = li_all
            .iter()
            .enumerate()
            .map(|(q, &li)| {
                let (s0v, s1v) = layer_symbols[q];
                high_pair_leaf_hash_for_trace(layer_log, li, s0v, s1v, &hasher)
            })
            .collect();
        let batch = BatchedMerkleProof { siblings: src.folded_merkle_batch[layer].siblings.clone() };
        let paths = expand_batched_merkle_proof(&batch, depth, &li_all, &all_leaves, &hasher)
            .expect("SB8 high-fold octopus expand");
        all_expands_ok &= !paths.is_empty();
        let root_flat = lanes_flat(&src.folded_roots[layer]);
        let chosen: Vec<usize> = layers[layer].pair_indices[..nq].to_vec();
        let mut witnesses = Vec::with_capacity(nq);
        let mut entry_vals = Vec::with_capacity(nq);
        let mut committed_roots = Vec::with_capacity(nq);
        for q in 0..nq {
            let li = chosen[q];
            let path = paths.iter().find(|p| p.leaf_index == li).expect("SB8 path");
            let leaf_flat = lanes_flat(&path.leaf_hash);
            assert_eq!(sb8_digest_vals[layer][q], leaf_flat, "SB8 leaf digest != φ(native leaf)");
            witnesses.push(MerklePathWitness {
                entry: leaf_flat,
                siblings: path.siblings.iter().map(lanes_flat).collect(),
                directions: path.directions.clone(),
            });
            entry_vals.push(leaf_flat);
            committed_roots.push(root_flat);
        }
        let family = MerklePathFamily { depth, n_paths: nq };
        let mcols = build_merkle_path_columns(&family, iv_b, &witnesses, fam_wlog);
        place_merkle(&mut cb, &mut s0b, &mut soutb, &mcols, col_base, meta_base, n_slots);
        // TRANSCRIPT-BINDING: root == the FS-observed folded-layer root wire.
        let root_wires: Vec<[LinExpr; 2]> = (0..nq).map(|_| folded_roots_w[layer].clone()).collect();
        legs.push(MerkleLeg {
            family,
            refs: union_merkle_refs(col_base, fixed_base),
            region,
            meta_base,
            cols: mcols,
            entry_vals,
            committed_roots,
            entry_wires: sb8_digest_wires[k].clone(),
            pair_entry_map: None,
            root_wires,
        });
    }

    // Fixed patterns: region_pair (0) + per leg [8 merkle patterns, region].
    let mut fixed_b: Vec<FixedPattern> = Vec::new();
    {
        let mut t = vec![F128::ZERO; pb];
        for s in 0..nq {
            t[s] = F128::ONE;
        }
        fixed_b.push(FixedPattern::new(w_log_b, t));
    }
    for leg in &legs {
        let n_slots = leg.family.n_slots();
        for pat in merkle_fixed_patterns(&leg.family, iv_b) {
            fixed_b.push(localize_tiled(&pat.table, leg.meta_base, leg.family.n_paths, w_log_b));
        }
        let mut t = vec![F128::ZERO; pb];
        for s in leg.meta_base..leg.meta_base + n_slots {
            t[s] = F128::ONE;
        }
        fixed_b.push(FixedPattern::new(w_log_b, t));
    }

    let committed_b: Vec<&[F128]> = cb.iter().map(|c| c.as_slice()).collect();
    let native_b = run_merkle_union_native(
        &committed_b, &s0b, &soutb, &fixed_b, &pair_refs, region_pair, &legs, w_log_b, DOMAIN_B,
    );
    let n_slices_a = slices.len();
    let slices_b: Vec<WitnessSlice> =
        cb.iter().map(|c| alloc_column_slice(b, c, w_log_b).0).collect();
    let (mut claims_b, _pair_digest_wires) = discharge_merkle_union(
        b, &fixed_b, &pair_refs, region_pair, &legs, w_log_b, &native_b, &pair_digests, DOMAIN_B,
    );

    // FRI fold-join: the queried symbols == the pair-leaf IN columns, folded to
    // the final codeword (round 0: no previous-round fold consistency).
    let final_len = fri.final_codeword.len();
    for q in 0..nq {
        let (s0v, s1v) = fri.fri_queried_symbols[round][q];
        let s0w = LinExpr::from_wire(b.alloc_f128(phi(s0v)));
        let s1w = LinExpr::from_wire(b.alloc_f128(phi(s1v)));
        let (pt_lin, pt_nat) = slot_point(q, w_log_b);
        claims_b.push(Claim {
            slice: pair_refs.in_[0],
            point: pt_lin.clone(),
            value: s0w.clone(),
            native_point: pt_nat.clone(),
            native_value: phi(s0v),
        });
        claims_b.push(Claim {
            slice: pair_refs.in_[1],
            point: pt_lin,
            value: s1w.clone(),
            native_point: pt_nat,
            native_value: phi(s1v),
        });
        let folded =
            fold_trace(b, &random_point[round], round, fri_pair_indices[q], &s0w, &s1w, &ntt);
        let final_idx = (fri_queries[q] >> n_rounds) % final_len;
        pin_eq(b, &folded, &final_cw[final_idx]);
    }

    // Merge walk B into the global slice/claim tables.
    for c in claims_b.iter_mut() {
        c.slice += n_slices_a;
    }
    slices.extend(slices_b);
    claims.extend(claims_b);
    assert!(all_expands_ok, "all real-sibling octopus expands returned non-empty paths");

    // Close the discharge contract: the batched primary opening == the value the
    // owner-auth killshot reduced to (inline discharge line 813-814).
    pin_eq(b, &all_openings[0], &obligation.reduction.value);

    // Resolve each claim's column index into its committed WitnessSlice.
    claims
        .into_iter()
        .map(|c| RegionPcsClaim {
            slice: slices[c.slice],
            point: c.point,
            value: c.value,
            native_point: c.native_point,
            native_value: c.native_value,
        })
        .collect()
}

// ===========================================================================
// Basis + small helpers (private; shadow the proven gate).
// ===========================================================================

fn phi(bl: Block128) -> F128 {
    flat_of_tower_u128(bl.0)
}

fn lanes_flat(d: &[u8; 32]) -> [F128; 2] {
    [
        phi(Block128::from(u128::from_le_bytes(d[..16].try_into().unwrap()))),
        phi(Block128::from(u128::from_le_bytes(d[16..].try_into().unwrap()))),
    ]
}

fn eq_tensor_tower(point: &[Block128]) -> Vec<Block128> {
    let mut t = vec![Block128::ONE; 1usize << point.len()];
    for (i, slot) in t.iter_mut().enumerate() {
        let mut e = Block128::ONE;
        for (ll, &pp) in point.iter().enumerate() {
            e = e * if (i >> ll) & 1 == 1 { pp } else { Block128::ONE + pp };
        }
        *slot = e;
    }
    t
}

fn alloc_column_slice(
    b: &mut FieldR1csBuilder,
    col: &[F128],
    log2_len: usize,
) -> (WitnessSlice, Vec<LinExpr>) {
    let block = 1usize << log2_len;
    while b.num_wires() % block != 0 {
        b.alloc_f128(F128::ZERO);
    }
    let index = b.num_wires() / block;
    let wires: Vec<LinExpr> = col.iter().map(|&v| LinExpr::from_wire(b.alloc_f128(v))).collect();
    for _ in col.len()..block {
        b.alloc_f128(F128::ZERO);
    }
    (WitnessSlice { log2_len, index }, wires)
}

/// The boolean point selecting slot `s` in `w_log` coordinates.
fn slot_point(s: usize, w_log: usize) -> (Vec<LinExpr>, Vec<F128>) {
    let lin = (0..w_log)
        .map(|bb| LinExpr::constant(if (s >> bb) & 1 == 1 { F128::ONE } else { F128::ZERO }))
        .collect();
    let nat = (0..w_log).map(|bb| if (s >> bb) & 1 == 1 { F128::ONE } else { F128::ZERO }).collect();
    (lin, nat)
}

/// Rebuild a per-family stride-period pattern as a META-period table by
/// repeating its stride table `n_tiles` times starting at `base`, zero
/// elsewhere; `low_log = meta_p_log` localizes it to `[base, base + n·stride)`.
fn localize_tiled(stride_table: &[F128], base: usize, n_tiles: usize, meta_p_log: usize) -> FixedPattern {
    let p = 1usize << meta_p_log;
    let stride = stride_table.len();
    let mut t = vec![F128::ZERO; p];
    for tile in 0..n_tiles {
        let off = base + tile * stride;
        t[off..off + stride].copy_from_slice(stride_table);
    }
    FixedPattern::new(meta_p_log, t)
}

/// Localize a full-range (non-tiled) table into a META-period table at `base`.
fn localize(table: &[F128], base: usize, meta_p_log: usize) -> FixedPattern {
    localize_tiled(table, base, 1, meta_p_log)
}

fn flat_mds_entry(e: usize, j: usize) -> F128 {
    noid_ivc_core::deep_chain::flat_mds(true)[e][j]
}

/// `basis + ONE + r` factor of `tensor_high_fold_pair`, char-2 (local twin of
/// the private `auth_pcs::tensor_high_fold_pair_trace`).
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
    let factor = r.add_const(flat_of(Block128::from((1u128 << basis_idx) ^ 1)));
    s1.add(&mul(b, s0, &factor))
}

/// Trace α-power MDS weights `m[j] = Σ_e α^{e+1}·flat(MDS[e][j])`.
fn mds_alpha_weights(b: &mut FieldR1csBuilder, alpha: &LinExpr) -> (Vec<LinExpr>, Vec<LinExpr>) {
    let mut ap = Vec::with_capacity(STATE_SIZE);
    let mut acc = LinExpr::constant(F128::ONE);
    for _ in 0..STATE_SIZE {
        acc = mul(b, &acc, alpha);
        ap.push(acc.clone());
    }
    let m = (0..STATE_SIZE)
        .map(|j| {
            let mut a = LinExpr::zero();
            for e in 0..STATE_SIZE {
                a = a.add(&ap[e].scale(flat_mds_entry(e, j)));
            }
            a
        })
        .collect();
    (m, ap)
}

// ---------------------------------------------------------------------------
// Internal claim record (global column index; resolved to a WitnessSlice at the
// end into a RegionPcsClaim).
// ---------------------------------------------------------------------------
struct Claim {
    slice: usize,
    point: Vec<LinExpr>,
    value: LinExpr,
    native_point: Vec<F128>,
    native_value: F128,
}

// ===========================================================================
// WALK A — the leaf-union native/trace DAG.
// ===========================================================================
struct UnionNative {
    sel_proof: ColumnRelationProof,
    walk_proof: DeepChainWalkProof,
    sub_proof: ColumnRelationProof,
    shifts: Vec<(usize, usize, ShiftDischargeProof)>,
    expo_proof: ColumnRelationProof,
    pending: Vec<(usize, Vec<F128>, F128)>,
    expo_pending: Vec<(usize, Vec<F128>, F128)>,
}

fn union_native_terms(
    st_refs: &SourceTreeRefs,
    leaf_refs: &[SourceLeafRefs],
    alpha: F128,
) -> Vec<RelationTerm> {
    let mut terms = source_tree_substitution_terms(st_refs, alpha);
    for lr in leaf_refs {
        terms.extend(source_leaf_substitution_terms(lr, alpha));
    }
    terms
}

#[allow(clippy::too_many_arguments)]
fn run_union_native(
    committed: &[&[F128]],
    s0: &[Vec<F128>; STATE_SIZE],
    s_out: &[Vec<F128>; STATE_SIZE],
    fixed: &[FixedPattern],
    st_refs: &SourceTreeRefs,
    leaf_refs: &[SourceLeafRefs],
    w_log: usize,
    expo_committed: &[&[F128]],
    expo_wlog: usize,
    expo_kid_meta: [usize; 2],
    expo_c_meta: [usize; 2],
) -> UnionNative {
    let internal: Vec<&[F128]> = s_out.iter().map(|c| c.as_slice()).collect();
    let mut ch_p = FsLaneChallenger::new(DOMAIN);
    let mut ch_v = FsLaneChallenger::new(DOMAIN);
    let mut pending: Vec<(usize, Vec<F128>, F128)> = Vec::new();

    let beta = ch_p.sample_f128();
    assert_eq!(beta, ch_v.sample_f128());
    let sel_terms = carry_selection_terms(&st_refs.c, beta);
    let rho = ch_p.sample_f128_vec(w_log);
    let _ = ch_v.sample_f128_vec(w_log);
    let (sel_proof, _, _) = prove_column_relation(
        F128::ZERO,
        &rho,
        &sel_terms,
        &RelationColumns { committed, internal: &internal, fixed },
        &mut ch_p,
    );
    let sel_point =
        verify_column_relation(w_log, F128::ZERO, &rho, &sel_terms, fixed, &sel_proof, &mut ch_v)
            .expect("native selection");
    let mut gv = [F128::ZERO; STATE_SIZE];
    for (r, v) in claimed_refs(&sel_terms).iter().zip(sel_proof.final_values.iter()) {
        match r {
            ColRef::Committed(c) => pending.push((*c, sel_point.clone(), *v)),
            ColRef::Internal(j) => gv[*j] = *v,
            _ => unreachable!(),
        }
    }

    let groups = vec![LaneClaimGroup { point: sel_point, values: gv }];
    let (walk_proof, _) = prove_deep_chain_walk(s0, &groups, &mut ch_p);
    let terminal = verify_deep_chain_walk(w_log, &groups, &walk_proof, &mut ch_v).expect("native walk");

    let alpha = ch_p.sample_f128();
    assert_eq!(alpha, ch_v.sample_f128());
    let sub_terms = union_native_terms(st_refs, leaf_refs, alpha);
    let mut target = F128::ZERO;
    let mut p = F128::ONE;
    for e in 0..STATE_SIZE {
        p = p * alpha;
        target += p * terminal.values[e];
    }
    let (sub_proof, _, _) = prove_column_relation(
        target,
        &terminal.point,
        &sub_terms,
        &RelationColumns { committed, internal: &[], fixed },
        &mut ch_p,
    );
    let sub_point =
        verify_column_relation(w_log, target, &terminal.point, &sub_terms, fixed, &sub_proof, &mut ch_v)
            .expect("native substitution");
    let mut shifts = Vec::new();
    for (r, v) in claimed_refs(&sub_terms).iter().zip(sub_proof.final_values.iter()) {
        match r {
            ColRef::Committed(c) => pending.push((*c, sub_point.clone(), *v)),
            ColRef::CommittedShift(c) => {
                let (pr, _) = prove_shift_discharge(committed[*c], &sub_point, *v, &mut ch_p);
                let pt = verify_shift_discharge(w_log, &sub_point, *v, &pr, &mut ch_v).expect("shift");
                pending.push((*c, pt, pr.final_value));
                shifts.push((0usize, *c, pr));
            }
            ColRef::CommittedShift2(c) => {
                let (pr, _) = noid_ivc_core::deep_chain::relations::prove_shift_discharge_pow2(
                    committed[*c],
                    &sub_point,
                    *v,
                    1,
                    &mut ch_p,
                );
                let pt = noid_ivc_core::deep_chain::relations::verify_shift_discharge_pow2(
                    w_log, &sub_point, *v, 1, &pr, &mut ch_v,
                )
                .expect("shift2");
                pending.push((*c, pt, pr.final_value));
                shifts.push((1usize, *c, pr));
            }
            _ => unreachable!(),
        }
    }

    let gamma = ch_p.sample_f128();
    assert_eq!(gamma, ch_v.sample_f128());
    let expo_terms = source_tree_exposure_terms([0, 1], [2, 3], gamma);
    let rho_e = ch_p.sample_f128_vec(expo_wlog - 1);
    let _ = ch_v.sample_f128_vec(expo_wlog - 1);
    let (expo_proof, _, _) = prove_column_relation(
        F128::ZERO,
        &rho_e,
        &expo_terms,
        &RelationColumns { committed: expo_committed, internal: &[], fixed: &[] },
        &mut ch_p,
    );
    let expo_point =
        verify_column_relation(expo_wlog - 1, F128::ZERO, &rho_e, &expo_terms, &[], &expo_proof, &mut ch_v)
            .expect("native exposure");
    let mut expo_pending: Vec<(usize, Vec<F128>, F128)> = Vec::new();
    for (r, v) in claimed_refs(&expo_terms).iter().zip(expo_proof.final_values.iter()) {
        match r {
            ColRef::Committed(ll) => {
                let mut pt = expo_point.clone();
                pt.push(F128::ZERO);
                expo_pending.push((expo_kid_meta[*ll], pt, *v));
            }
            ColRef::Window { col, stride_log, offset } => {
                let pt = window_discharge_point(*offset, *stride_log, &expo_point);
                expo_pending.push((expo_c_meta[*col - 2], pt, *v));
            }
            _ => unreachable!(),
        }
    }

    assert_eq!(ch_p.sample_f128(), ch_v.sample_f128(), "native lockstep");
    UnionNative { sel_proof, walk_proof, sub_proof, shifts, expo_proof, pending, expo_pending }
}

/// Trace twin of `union_native_terms` with α-power MDS coefficients.
fn union_trace_terms(
    m: &[LinExpr],
    st_refs: &SourceTreeRefs,
    leaf_refs: &[SourceLeafRefs],
) -> Vec<RelationTermTrace> {
    let mut terms = Vec::new();
    for i in 0..2 {
        let kid = ColRef::Committed(st_refs.kid[i]);
        let c_sh = ColRef::CommittedShift(st_refs.c[i]);
        let code = ColRef::Committed(st_refs.code[i]);
        for factors in [
            vec![ColRef::Fixed(st_refs.even_int), kid],
            vec![ColRef::Fixed(st_refs.odd_int), kid],
            vec![ColRef::Fixed(st_refs.odd_int), c_sh],
            vec![ColRef::Fixed(st_refs.leafodd), code],
        ] {
            terms.push(RelationTermTrace { coeff: m[i].clone(), factors });
        }
    }
    for j in 2..STATE_SIZE {
        terms.push(RelationTermTrace { coeff: m[j].clone(), factors: vec![ColRef::Fixed(st_refs.iv[j - 2])] });
        terms.push(RelationTermTrace {
            coeff: m[j].clone(),
            factors: vec![ColRef::Fixed(st_refs.odd_int), ColRef::CommittedShift(st_refs.c[j])],
        });
    }
    for lr in leaf_refs {
        for i in 0..2 {
            let in_col = ColRef::Committed(lr.in_[i]);
            let c_sh = ColRef::CommittedShift(lr.c[i]);
            let c_sh2 = ColRef::CommittedShift2(lr.c[i]);
            for factors in [
                vec![ColRef::Fixed(lr.hp), in_col],
                vec![ColRef::Fixed(lr.even), c_sh2],
                vec![ColRef::Fixed(lr.odd), c_sh],
                vec![ColRef::Fixed(lr.odd), c_sh2],
            ] {
                terms.push(RelationTermTrace { coeff: m[i].clone(), factors });
            }
        }
        for j in 2..STATE_SIZE {
            terms.push(RelationTermTrace { coeff: m[j].clone(), factors: vec![ColRef::Fixed(lr.iv[j - 2])] });
            terms.push(RelationTermTrace {
                coeff: m[j].clone(),
                factors: vec![ColRef::Fixed(lr.odd), ColRef::CommittedShift(lr.c[j])],
            });
        }
    }
    terms
}

fn union_ref_terms(st_refs: &SourceTreeRefs, leaf_refs: &[SourceLeafRefs]) -> Vec<RelationTerm> {
    union_native_terms(st_refs, leaf_refs, F128::ONE)
}

#[allow(clippy::too_many_arguments)]
fn discharge_union(
    b: &mut FieldR1csBuilder,
    fixed: &[FixedPattern],
    st_refs: &SourceTreeRefs,
    leaf_refs: &[SourceLeafRefs],
    w_log: usize,
    expo_wlog: usize,
    native: &UnionNative,
) -> Vec<Claim> {
    let mut ch = FsChannelTrace::new(b, DOMAIN);
    let mut out: Vec<Claim> = Vec::new();
    let np = &native.pending;
    let mut cur = 0usize;
    let zero = LinExpr::zero();

    let beta = ch.sample_f128(b);
    let mut bp = LinExpr::constant(F128::ONE);
    let mut sel_terms: Vec<RelationTermTrace> = Vec::new();
    for j in 0..STATE_SIZE {
        bp = mul(b, &bp, &beta);
        sel_terms.push(RelationTermTrace { coeff: bp.clone(), factors: vec![ColRef::Committed(st_refs.c[j])] });
        sel_terms.push(RelationTermTrace { coeff: bp.clone(), factors: vec![ColRef::Internal(j)] });
    }
    let rho = ch.sample_f128_vec(b, w_log);
    let sel_e = ColumnRelationProofTrace::alloc(b, &native.sel_proof, w_log, 2 * STATE_SIZE);
    let sel_point = verify_column_relation_trace(b, &mut ch, w_log, &zero, &rho, &sel_terms, fixed, &sel_e);
    let sel_claimed = claimed_refs(&carry_selection_terms(&st_refs.c, F128::ONE));
    let mut gv: [LinExpr; STATE_SIZE] = std::array::from_fn(|_| LinExpr::zero());
    for (r, v) in sel_claimed.iter().zip(sel_e.final_values.iter()) {
        match r {
            ColRef::Committed(_) => {
                let (col, npt, nval) = &np[cur];
                cur += 1;
                out.push(Claim { slice: *col, point: sel_point.clone(), value: v.clone(), native_point: npt.clone(), native_value: *nval });
            }
            ColRef::Internal(j) => gv[*j] = v.clone(),
            _ => unreachable!(),
        }
    }

    let groups_e = vec![LaneClaimGroupTrace { point: sel_point, values: gv }];
    let walk_e = DeepChainWalkProofTrace::alloc(b, &native.walk_proof, w_log);
    let terminal = verify_deep_chain_walk_trace(b, &mut ch, w_log, &groups_e, &walk_e);

    let alpha = ch.sample_f128(b);
    let (m, ap) = mds_alpha_weights(b, &alpha);
    let sub_terms = union_trace_terms(&m, st_refs, leaf_refs);
    let ref_terms = union_ref_terms(st_refs, leaf_refs);
    let mut target = LinExpr::zero();
    for e in 0..STATE_SIZE {
        target = target.add(&mul(b, &ap[e], &terminal.values[e]));
    }
    let sub_e = ColumnRelationProofTrace::alloc(b, &native.sub_proof, w_log, claimed_refs(&ref_terms).len());
    let sub_point = verify_column_relation_trace(b, &mut ch, w_log, &target, &terminal.point, &sub_terms, fixed, &sub_e);
    let mut shift_cursor = 0usize;
    for (r, v) in claimed_refs(&ref_terms).iter().zip(sub_e.final_values.iter()) {
        match r {
            ColRef::Committed(_) => {
                let (col, npt, nval) = &np[cur];
                cur += 1;
                out.push(Claim { slice: *col, point: sub_point.clone(), value: v.clone(), native_point: npt.clone(), native_value: *nval });
            }
            ColRef::CommittedShift(_) | ColRef::CommittedShift2(_) => {
                let (shift_log, _col, ns) = &native.shifts[shift_cursor];
                shift_cursor += 1;
                let se = ShiftDischargeProofTrace::alloc(b, ns, w_log);
                let pt = verify_shift_discharge_trace(b, &mut ch, w_log, &sub_point, v, *shift_log, &se);
                let (col, npt, nval) = &np[cur];
                cur += 1;
                out.push(Claim { slice: *col, point: pt, value: se.final_value.clone(), native_point: npt.clone(), native_value: *nval });
            }
            _ => unreachable!(),
        }
    }
    assert_eq!(shift_cursor, native.shifts.len(), "all shifts consumed");
    assert_eq!(cur, np.len(), "union pending lockstep");

    let expo_ref = source_tree_exposure_terms([0, 1], [2, 3], F128::ZERO);
    let gamma = ch.sample_f128(b);
    let mut gp = LinExpr::constant(F128::ONE);
    let mut expo_terms: Vec<RelationTermTrace> = Vec::new();
    for i in 0..2 {
        gp = mul(b, &gp, &gamma);
        expo_terms.push(RelationTermTrace { coeff: gp.clone(), factors: vec![ColRef::Committed(i)] });
        expo_terms.push(RelationTermTrace { coeff: gp.clone(), factors: vec![ColRef::Window { col: 2 + i, stride_log: 1, offset: 1 }] });
    }
    let rho_e = ch.sample_f128_vec(b, expo_wlog - 1);
    let expo_e = ColumnRelationProofTrace::alloc(b, &native.expo_proof, expo_wlog - 1, claimed_refs(&expo_ref).len());
    let expo_point = verify_column_relation_trace(b, &mut ch, expo_wlog - 1, &zero, &rho_e, &expo_terms, &[], &expo_e);
    let pad = w_log - expo_wlog;
    let mut ec = 0usize;
    for (r, v) in claimed_refs(&expo_ref).iter().zip(expo_e.final_values.iter()) {
        let (col, npt, nval) = &native.expo_pending[ec];
        ec += 1;
        match r {
            ColRef::Committed(_) => {
                let mut pt = expo_point.clone();
                pt.push(LinExpr::constant(F128::ZERO));
                for _ in 0..pad {
                    pt.push(LinExpr::constant(F128::ZERO));
                }
                let mut nat = npt.clone();
                nat.extend(std::iter::repeat(F128::ZERO).take(pad));
                out.push(Claim { slice: *col, point: pt, value: v.clone(), native_point: nat, native_value: *nval });
            }
            ColRef::Window { offset, stride_log, .. } => {
                let mut pt: Vec<LinExpr> = (0..*stride_log)
                    .map(|jb| LinExpr::constant(if (offset >> jb) & 1 == 1 { F128::ONE } else { F128::ZERO }))
                    .collect();
                pt.extend(expo_point.clone());
                for _ in 0..pad {
                    pt.push(LinExpr::constant(F128::ZERO));
                }
                let mut nat = npt.clone();
                nat.extend(std::iter::repeat(F128::ZERO).take(pad));
                out.push(Claim { slice: *col, point: pt, value: v.clone(), native_point: nat, native_value: *nval });
            }
            _ => unreachable!(),
        }
    }
    assert_eq!(ec, native.expo_pending.len(), "exposure pending lockstep");
    out
}

// ===========================================================================
// WALK B — the merkle-union.
// ===========================================================================
fn union_merkle_refs(col_base: usize, fixed_base: usize) -> MerkleFamilyRefs {
    MerkleFamilyRefs {
        e: [col_base, col_base + 1],
        sib: [col_base + 2, col_base + 3],
        d: col_base + 4,
        c: std::array::from_fn(|i| 2 + i),
        even: fixed_base,
        evenns: fixed_base + 1,
        evenstart: fixed_base + 2,
        odd: fixed_base + 3,
        oddns: fixed_base + 4,
        oddstart: fixed_base + 5,
        iv: [fixed_base + 6, fixed_base + 7],
    }
}

/// One Merkle-authentication leg placed in the shared walk-B meta domain.
struct MerkleLeg {
    family: MerklePathFamily,
    refs: MerkleFamilyRefs,
    region: usize,
    meta_base: usize,
    cols: MerklePathColumns,
    entry_vals: Vec<[F128; 2]>,
    committed_roots: Vec<[F128; 2]>,
    entry_wires: Vec<[LinExpr; 2]>,
    pair_entry_map: Option<Vec<usize>>,
    /// TRANSCRIPT-BINDING: the FS-observed root wire per path (== the wire
    /// absorbed into the channel BEFORE the query draw). The root claim's VALUE
    /// is this wire, so the walk-recomputed root is opened == the transcript
    /// root — a prover cannot authenticate against a root chosen after the query
    /// positions are known.
    root_wires: Vec<[LinExpr; 2]>,
}

fn union_bool_terms(legs: &[MerkleLeg]) -> Vec<RelationTerm> {
    let mut t = Vec::new();
    for leg in legs {
        t.extend(merkle_booleanity_terms(&leg.refs));
    }
    t
}

fn union_sub_terms_native(
    pair_refs: &PairLeafRefs,
    region_pair: usize,
    legs: &[MerkleLeg],
    alpha: F128,
) -> Vec<RelationTerm> {
    let mut terms = pair_leaf_substitution_terms(pair_refs, alpha);
    for t in terms.iter_mut() {
        t.factors.insert(0, ColRef::Fixed(region_pair));
    }
    for leg in legs {
        let mut m = merkle_substitution_terms(&leg.refs, alpha);
        for t in m.iter_mut() {
            if !t.factors.iter().any(|f| matches!(f, ColRef::Fixed(_))) {
                t.factors.insert(0, ColRef::Fixed(leg.region));
            }
        }
        terms.extend(m);
    }
    terms
}

fn union_bool_terms_trace(legs: &[MerkleLeg]) -> Vec<RelationTermTrace> {
    union_bool_terms(legs)
        .iter()
        .map(|t| RelationTermTrace { coeff: LinExpr::constant(t.coeff), factors: t.factors.clone() })
        .collect()
}

fn union_sub_terms_trace(
    b: &mut FieldR1csBuilder,
    pair_refs: &PairLeafRefs,
    region_pair: usize,
    legs: &[MerkleLeg],
    alpha: &LinExpr,
) -> (Vec<RelationTermTrace>, Vec<LinExpr>) {
    let (m, ap) = mds_alpha_weights(b, alpha);
    let mut terms: Vec<RelationTermTrace> = Vec::new();

    for i in 0..2 {
        terms.push(RelationTermTrace {
            coeff: m[i].clone(),
            factors: vec![ColRef::Fixed(region_pair), ColRef::Committed(pair_refs.in_[i])],
        });
    }

    for leg in legs {
        let refs = &leg.refs;
        let region = ColRef::Fixed(leg.region);
        for i in 0..2 {
            let c_sh = ColRef::CommittedShift(refs.c[i]);
            let c_sh2 = ColRef::CommittedShift2(refs.c[i]);
            let sib = ColRef::Committed(refs.sib[i]);
            let sib_sh = ColRef::CommittedShift(refs.sib[i]);
            let e_col = ColRef::Committed(refs.e[i]);
            let e_sh = ColRef::CommittedShift(refs.e[i]);
            let d_col = ColRef::Committed(refs.d);
            let d_sh = ColRef::CommittedShift(refs.d);
            for factors in [
                vec![region, c_sh],
                vec![ColRef::Fixed(refs.evenstart), c_sh],
                vec![ColRef::Fixed(refs.evenns), d_col, c_sh],
                vec![ColRef::Fixed(refs.even), d_col, sib],
                vec![ColRef::Fixed(refs.evenstart), e_col],
                vec![ColRef::Fixed(refs.evenstart), d_col, e_col],
                vec![ColRef::Fixed(refs.odd), sib_sh],
                vec![ColRef::Fixed(refs.odd), d_sh, sib_sh],
                vec![ColRef::Fixed(refs.oddns), d_sh, c_sh2],
                vec![ColRef::Fixed(refs.oddstart), d_sh, e_sh],
            ] {
                terms.push(RelationTermTrace { coeff: m[i].clone(), factors });
            }
        }
        for j in 2..STATE_SIZE {
            let c_sh = ColRef::CommittedShift(refs.c[j]);
            terms.push(RelationTermTrace { coeff: m[j].clone(), factors: vec![region, c_sh] });
            terms.push(RelationTermTrace {
                coeff: m[j].clone(),
                factors: vec![ColRef::Fixed(refs.even), c_sh],
            });
            terms.push(RelationTermTrace {
                coeff: m[j].clone(),
                factors: vec![ColRef::Fixed(refs.iv[j - 2])],
            });
        }
    }
    (terms, ap)
}

struct MerkleUnionNative {
    bool_proof: ColumnRelationProof,
    sel_proof: ColumnRelationProof,
    walk_proof: DeepChainWalkProof,
    sub_proof: ColumnRelationProof,
    shifts: Vec<(usize, usize, ShiftDischargeProof)>,
    pending: Vec<(usize, Vec<F128>, F128)>,
}

fn place_merkle(
    cb: &mut [Vec<F128>],
    s0b: &mut [Vec<F128>; STATE_SIZE],
    soutb: &mut [Vec<F128>; STATE_SIZE],
    cols: &MerklePathColumns,
    col_base: usize,
    meta_base: usize,
    n_slots: usize,
) {
    let rng = meta_base..meta_base + n_slots;
    for j in 0..2 {
        cb[col_base + j][rng.clone()].copy_from_slice(&cols.e[j][0..n_slots]);
        cb[col_base + 2 + j][rng.clone()].copy_from_slice(&cols.sib[j][0..n_slots]);
    }
    cb[col_base + 4][rng.clone()].copy_from_slice(&cols.d[0..n_slots]);
    for j in 0..STATE_SIZE {
        cb[2 + j][rng.clone()].copy_from_slice(&cols.c[j][0..n_slots]);
        s0b[j][rng.clone()].copy_from_slice(&cols.s0[j][0..n_slots]);
        soutb[j][rng.clone()].copy_from_slice(&cols.s_out[j][0..n_slots]);
    }
}

#[allow(clippy::too_many_arguments)]
fn run_merkle_union_native(
    committed: &[&[F128]],
    s0: &[Vec<F128>; STATE_SIZE],
    s_out: &[Vec<F128>; STATE_SIZE],
    fixed: &[FixedPattern],
    pair_refs: &PairLeafRefs,
    region_pair: usize,
    legs: &[MerkleLeg],
    w_log: usize,
    domain: &[u8],
) -> MerkleUnionNative {
    let internal: Vec<&[F128]> = s_out.iter().map(|c| c.as_slice()).collect();
    let mut ch_p = FsLaneChallenger::new(domain);
    let mut ch_v = FsLaneChallenger::new(domain);
    let mut pending: Vec<(usize, Vec<F128>, F128)> = Vec::new();

    let bool_terms = union_bool_terms(legs);
    let rho_b = ch_p.sample_f128_vec(w_log);
    let _ = ch_v.sample_f128_vec(w_log);
    let (bool_proof, _, _) = prove_column_relation(
        F128::ZERO,
        &rho_b,
        &bool_terms,
        &RelationColumns { committed, internal: &[], fixed },
        &mut ch_p,
    );
    let bool_point =
        verify_column_relation(w_log, F128::ZERO, &rho_b, &bool_terms, fixed, &bool_proof, &mut ch_v)
            .expect("native merkle-union booleanity");
    for (r, v) in claimed_refs(&bool_terms).iter().zip(bool_proof.final_values.iter()) {
        match r {
            ColRef::Committed(c) => pending.push((*c, bool_point.clone(), *v)),
            _ => unreachable!(),
        }
    }

    let beta = ch_p.sample_f128();
    assert_eq!(beta, ch_v.sample_f128());
    let sel_terms = carry_selection_terms(&pair_refs.c, beta);
    let rho = ch_p.sample_f128_vec(w_log);
    let _ = ch_v.sample_f128_vec(w_log);
    let (sel_proof, _, _) = prove_column_relation(
        F128::ZERO,
        &rho,
        &sel_terms,
        &RelationColumns { committed, internal: &internal, fixed },
        &mut ch_p,
    );
    let sel_point =
        verify_column_relation(w_log, F128::ZERO, &rho, &sel_terms, fixed, &sel_proof, &mut ch_v)
            .expect("native merkle-union selection");
    let mut gv = [F128::ZERO; STATE_SIZE];
    for (r, v) in claimed_refs(&sel_terms).iter().zip(sel_proof.final_values.iter()) {
        match r {
            ColRef::Committed(c) => pending.push((*c, sel_point.clone(), *v)),
            ColRef::Internal(j) => gv[*j] = *v,
            _ => unreachable!(),
        }
    }

    let groups = vec![LaneClaimGroup { point: sel_point, values: gv }];
    let (walk_proof, _) = prove_deep_chain_walk(s0, &groups, &mut ch_p);
    let terminal =
        verify_deep_chain_walk(w_log, &groups, &walk_proof, &mut ch_v).expect("native merkle walk");

    let alpha = ch_p.sample_f128();
    assert_eq!(alpha, ch_v.sample_f128());
    let sub_terms = union_sub_terms_native(pair_refs, region_pair, legs, alpha);
    let mut target = F128::ZERO;
    let mut p = F128::ONE;
    for e in 0..STATE_SIZE {
        p = p * alpha;
        target += p * terminal.values[e];
    }
    let (sub_proof, _, _) = prove_column_relation(
        target,
        &terminal.point,
        &sub_terms,
        &RelationColumns { committed, internal: &[], fixed },
        &mut ch_p,
    );
    let sub_point = verify_column_relation(
        w_log,
        target,
        &terminal.point,
        &sub_terms,
        fixed,
        &sub_proof,
        &mut ch_v,
    )
    .expect("native merkle-union substitution");
    let mut shifts = Vec::new();
    for (r, v) in claimed_refs(&sub_terms).iter().zip(sub_proof.final_values.iter()) {
        match r {
            ColRef::Committed(c) => pending.push((*c, sub_point.clone(), *v)),
            ColRef::CommittedShift(c) => {
                let (pr, _) = prove_shift_discharge(committed[*c], &sub_point, *v, &mut ch_p);
                let pt = verify_shift_discharge(w_log, &sub_point, *v, &pr, &mut ch_v).expect("shift");
                pending.push((*c, pt, pr.final_value));
                shifts.push((0usize, *c, pr));
            }
            ColRef::CommittedShift2(c) => {
                let (pr, _) = noid_ivc_core::deep_chain::relations::prove_shift_discharge_pow2(
                    committed[*c],
                    &sub_point,
                    *v,
                    1,
                    &mut ch_p,
                );
                let pt = noid_ivc_core::deep_chain::relations::verify_shift_discharge_pow2(
                    w_log, &sub_point, *v, 1, &pr, &mut ch_v,
                )
                .expect("shift2");
                pending.push((*c, pt, pr.final_value));
                shifts.push((1usize, *c, pr));
            }
            _ => unreachable!(),
        }
    }
    assert_eq!(ch_p.sample_f128(), ch_v.sample_f128(), "native merkle-union lockstep");
    MerkleUnionNative { bool_proof, sel_proof, walk_proof, sub_proof, shifts, pending }
}

#[allow(clippy::too_many_arguments)]
fn discharge_merkle_union(
    b: &mut FieldR1csBuilder,
    fixed: &[FixedPattern],
    pair_refs: &PairLeafRefs,
    region_pair: usize,
    legs: &[MerkleLeg],
    w_log: usize,
    native: &MerkleUnionNative,
    pair_digest_vals: &[[F128; 2]],
    domain: &[u8],
) -> (Vec<Claim>, Vec<[LinExpr; 2]>) {
    let mut ch = FsChannelTrace::new(b, domain);
    let mut out: Vec<Claim> = Vec::new();
    let np = &native.pending;
    let mut cur = 0usize;
    let zero = LinExpr::zero();

    let bool_ref = union_bool_terms(legs);
    let n_bool = claimed_refs(&bool_ref).len();
    let rho_b = ch.sample_f128_vec(b, w_log);
    let bool_e = ColumnRelationProofTrace::alloc(b, &native.bool_proof, w_log, n_bool);
    let bool_terms_e = union_bool_terms_trace(legs);
    let bool_point =
        verify_column_relation_trace(b, &mut ch, w_log, &zero, &rho_b, &bool_terms_e, fixed, &bool_e);
    for (r, v) in claimed_refs(&bool_ref).iter().zip(bool_e.final_values.iter()) {
        match r {
            ColRef::Committed(_) => {
                let (col, npt, nval) = &np[cur];
                cur += 1;
                out.push(Claim {
                    slice: *col,
                    point: bool_point.clone(),
                    value: v.clone(),
                    native_point: npt.clone(),
                    native_value: *nval,
                });
            }
            _ => unreachable!(),
        }
    }

    let beta = ch.sample_f128(b);
    let mut bp = LinExpr::constant(F128::ONE);
    let mut sel_terms: Vec<RelationTermTrace> = Vec::new();
    for j in 0..STATE_SIZE {
        bp = mul(b, &bp, &beta);
        sel_terms.push(RelationTermTrace {
            coeff: bp.clone(),
            factors: vec![ColRef::Committed(pair_refs.c[j])],
        });
        sel_terms.push(RelationTermTrace { coeff: bp.clone(), factors: vec![ColRef::Internal(j)] });
    }
    let rho = ch.sample_f128_vec(b, w_log);
    let sel_e = ColumnRelationProofTrace::alloc(b, &native.sel_proof, w_log, 2 * STATE_SIZE);
    let sel_point =
        verify_column_relation_trace(b, &mut ch, w_log, &zero, &rho, &sel_terms, fixed, &sel_e);
    let sel_claimed = claimed_refs(&carry_selection_terms(&pair_refs.c, F128::ONE));
    let mut gv: [LinExpr; STATE_SIZE] = std::array::from_fn(|_| LinExpr::zero());
    for (r, v) in sel_claimed.iter().zip(sel_e.final_values.iter()) {
        match r {
            ColRef::Committed(_) => {
                let (col, npt, nval) = &np[cur];
                cur += 1;
                out.push(Claim {
                    slice: *col,
                    point: sel_point.clone(),
                    value: v.clone(),
                    native_point: npt.clone(),
                    native_value: *nval,
                });
            }
            ColRef::Internal(j) => gv[*j] = v.clone(),
            _ => unreachable!(),
        }
    }

    let groups_e = vec![LaneClaimGroupTrace { point: sel_point, values: gv }];
    let walk_e = DeepChainWalkProofTrace::alloc(b, &native.walk_proof, w_log);
    let terminal = verify_deep_chain_walk_trace(b, &mut ch, w_log, &groups_e, &walk_e);

    let alpha = ch.sample_f128(b);
    let (sub_terms, ap) = union_sub_terms_trace(b, pair_refs, region_pair, legs, &alpha);
    let ref_terms = union_sub_terms_native(pair_refs, region_pair, legs, F128::ONE);
    let mut target = LinExpr::zero();
    for e in 0..STATE_SIZE {
        target = target.add(&mul(b, &ap[e], &terminal.values[e]));
    }
    let sub_e =
        ColumnRelationProofTrace::alloc(b, &native.sub_proof, w_log, claimed_refs(&ref_terms).len());
    let sub_point = verify_column_relation_trace(
        b,
        &mut ch,
        w_log,
        &target,
        &terminal.point,
        &sub_terms,
        fixed,
        &sub_e,
    );
    let mut shift_cursor = 0usize;
    for (r, v) in claimed_refs(&ref_terms).iter().zip(sub_e.final_values.iter()) {
        match r {
            ColRef::Committed(_) => {
                let (col, npt, nval) = &np[cur];
                cur += 1;
                out.push(Claim {
                    slice: *col,
                    point: sub_point.clone(),
                    value: v.clone(),
                    native_point: npt.clone(),
                    native_value: *nval,
                });
            }
            ColRef::CommittedShift(_) | ColRef::CommittedShift2(_) => {
                let (shift_log, _col, ns) = &native.shifts[shift_cursor];
                shift_cursor += 1;
                let se = ShiftDischargeProofTrace::alloc(b, ns, w_log);
                let pt = verify_shift_discharge_trace(b, &mut ch, w_log, &sub_point, v, *shift_log, &se);
                let (col, npt, nval) = &np[cur];
                cur += 1;
                out.push(Claim {
                    slice: *col,
                    point: pt,
                    value: se.final_value.clone(),
                    native_point: npt.clone(),
                    native_value: *nval,
                });
            }
            _ => unreachable!(),
        }
    }
    assert_eq!(shift_cursor, native.shifts.len(), "merkle-union shifts consumed");
    assert_eq!(cur, np.len(), "merkle-union pending lockstep");

    // Pair-leaf per-tile digest claims (feed the 3i Merkle entries).
    let mut pair_digest_wires = Vec::with_capacity(pair_digest_vals.len());
    for (t, dig) in pair_digest_vals.iter().enumerate() {
        let (pt_lin, pt_nat) = slot_point(t, w_log);
        let mut wires: [LinExpr; 2] = [LinExpr::zero(), LinExpr::zero()];
        for lane in 0..2 {
            let value = LinExpr::from_wire(b.alloc_f128(dig[lane]));
            out.push(Claim {
                slice: pair_refs.c[lane],
                point: pt_lin.clone(),
                value: value.clone(),
                native_point: pt_nat.clone(),
                native_value: dig[lane],
            });
            wires[lane] = value;
        }
        pair_digest_wires.push(wires);
    }

    // Per-leg entry (E == shared leaf digest wire) and root (C0/C1 == the
    // FS-OBSERVED root wire — transcript-bound, not a fresh alloc) pins.
    for leg in legs {
        let stride = leg.family.stride();
        let root_slot_local = 2 * (leg.family.depth - 1) + 1;
        for path in 0..leg.family.n_paths {
            let entry_wire: [LinExpr; 2] = match &leg.pair_entry_map {
                Some(map) => pair_digest_wires[map[path]].clone(),
                None => leg.entry_wires[path].clone(),
            };
            let entry_slot = leg.meta_base + path * stride;
            let (epl, epn) = slot_point(entry_slot, w_log);
            for lane in 0..2 {
                out.push(Claim {
                    slice: leg.refs.e[lane],
                    point: epl.clone(),
                    value: entry_wire[lane].clone(),
                    native_point: epn.clone(),
                    native_value: leg.entry_vals[path][lane],
                });
            }
            let root_slot = leg.meta_base + path * stride + root_slot_local;
            let (rpl, rpn) = slot_point(root_slot, w_log);
            for lane in 0..2 {
                // Sanity: the family's recomputed root equals the committed one.
                assert_eq!(leg.cols.roots[path][lane], leg.committed_roots[path][lane]);
                // TRANSCRIPT-BINDING: the root claim VALUE is the FS-observed
                // root wire (`leg.root_wires`), NOT a fresh alloc of the root
                // value. The recomputed root column at `root_slot` is thus opened
                // == the transcript-seeded root.
                let rv = leg.root_wires[path][lane].clone();
                out.push(Claim {
                    slice: leg.refs.c[lane],
                    point: rpl.clone(),
                    value: rv,
                    native_point: rpn.clone(),
                    native_value: leg.committed_roots[path][lane],
                });
            }
        }
    }

    (out, pair_digest_wires)
}

/// Drive the REAL noid_fri::Channel through the whole `verify_mixed_opening`
/// transcript to the two `gen_compact_queries` draws (native cross-check).
fn derive_queries(
    proof: &AuthMleOpeningProof,
    primary_point: &[Block128],
    num_queries: usize,
) -> (Vec<usize>, Vec<usize>) {
    let commitment = &proof.commitment;
    let opening = &proof.opening;
    let log_n = commitment.log_rows;
    let tau = COMPACT_TAU.min(log_n);
    let fri = &opening.fri_proof;
    let src = &opening.source_proof;
    let (right, _left) = primary_point.split_at(log_n - tau);
    let n_rounds = right.len();

    let mut channel = Channel::new();
    noid_fri_binius::absorb_cap(&mut channel, &commitment.cap);
    channel.observe_field_elem(Block128::from(MIXED_OPEN_TAG));
    channel.observe_field_elems(&opening.all_openings);
    let _gamma = channel.get_random_point();
    let batched_claim = opening.all_openings[0];
    channel.observe_field_elems(primary_point);
    channel.observe_field_elem(batched_claim);
    let _beta = channel.get_random_points(tau);
    for round in 0..n_rounds {
        let [c0, c1] = fri.sum_check_oracles[round];
        channel.observe_field_elem(c0);
        channel.observe_field_elem(c1);
        let depth = compute_round_depth(n_rounds, round);
        channel.observe_vector_commitment(&VectorCommitment { root: fri.fri_roots[round], depth });
        let _r = channel.get_random_point();
    }
    channel.observe_field_elems(&fri.final_codeword);
    channel.observe_field_elem(Block128::from(MIXED_SOURCE_BINDING_TAG));
    channel.observe_field_elems(&src.h_evals);
    for (i, root) in src.folded_roots.iter().enumerate() {
        let layer_log = log_n - 1 - i;
        channel.observe_vector_commitment(&VectorCommitment {
            root: *root,
            depth: high_pair_tree_depth(layer_log),
        });
    }
    let source_queries = gen_compact_queries(&mut channel, log_n + LOG_RATE, num_queries);
    let fri_queries = gen_compact_queries(&mut channel, n_rounds + LOG_RATE, num_queries);
    (source_queries, fri_queries)
}
