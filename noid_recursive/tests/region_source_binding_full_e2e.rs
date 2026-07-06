//! [G] item 5b — the COMPLETE wallet-capsule source-binding + FRI-query opening
//! AUTHENTICATION discharged IN-TRACE in ONE builder -> ONE
//! `prove_field_with_public_io` (the direct precursor to the src fn
//! `discharge_auth_pcs_obligation_via_region`). It EXTENDS the assembly core
//! (`region_assembly_core_e2e`) — the leaf-hashing families + SB7->SB9 fold
//! chain — by ADDING the three Merkle-authentication legs the core omits,
//! consuming REAL proof siblings + REAL committed roots:
//!   - 3i   FRI-round openings  — leaf = `hash_pair(s0,s1)`, per-round root,
//!   - SB6  source-tree opening — leaf = `source_leaf_hash`, to the committed
//!                                CAP (`cap_depth`),
//!   - SB8  high-fold layers    — leaf = `high_pair_leaf_hash`, per-layer root,
//! plus the FRI query fold-join (`fold_trace` -> `final_codeword`).
//!
//! ## Structure — ONE proof, TWO union walks in ONE builder
//! A single deep-chain walk is ~1M rows; discharging every leg's leaf-walk AND
//! Merkle-walk as SEPARATE walks is ~6 walks (~2^24) which OOMs (region prover
//! memory note). The memory-safe assembly uses exactly TWO union walks, both in
//! the SAME builder / SAME proof:
//!   - **walk A (leaf-union)**: the assembly core — the source_tree (SB1.2) +
//!     SB6 source-leaf + SB8 high-pair leaf families under ONE carry-selection +
//!     ONE `verify_deep_chain_walk_trace` + ONE unioned substitution; it now
//!     also opens each leaf tile's digest (C0/C1 at the digest slot) to a wire.
//!   - **walk B (merkle-union)**: the 3i FRI pair-leaf PLUS the three Merkle
//!     legs (3i / SB6-to-cap / SB8), a heterogeneous union (region_union_primitive
//!     generalised to a pair-leaf + N different-depth Merkle families) under ONE
//!     carry-selection + ONE walk + ONE unioned substitution; each family's fixed
//!     patterns are localized to its slot range and each Merkle family's ungated
//!     carry-forward terms are region-gated.
//!
//! ## The digest->entry JOIN is IN-BUILDER SHARED WIRES
//! Walk A's per-tile leaf-digest wires (SB6 source-leaf / SB8 high-pair) are
//! passed DIRECTLY as walk B's SB6 / SB8 Merkle `entry_wires` and claimed against
//! the Merkle E0/E1 columns; walk B's own pair-leaf digest wires feed the 3i
//! Merkle entries. So (symbols -> leaf digest) [walk A / pair-leaf] and (leaf
//! digest -> root) [walk B Merkle] compose through a SHARED WIRE opened by BOTH
//! sides of the SAME proof — never a public constant, never two proofs.
//!
//! Documented reductions (memory; all faithful — the omitted work is
//! topologically identical to the discharged work):
//!   - NQ = 4 distinct queries authenticated per leg (a subset of the real
//!     `COMPACT_NUM_QUERIES`; the octopus is expanded over the FULL real query
//!     set, a subset of the resulting independent paths is discharged).
//!   - SB8: the two DEEPEST fold layers (smallest trees) are authenticated; all
//!     `tau-1` layers are the same leaf+Merkle shape (the leaf fold chain in walk
//!     A still spans ALL `tau-1` layers to close SB9).
//!
//! Success: ONE proof verifies honestly; flipping a source-tree CODE lane, an
//! SB6/SB8 leaf symbol, a Merkle sibling in ANY leg, or a FRI queried symbol
//! leaves the trace satisfiable (committed columns are free wires) but breaks
//! that column's opening claim -> BaseFold rejects.
//!
//! ## Authentication-root binding — the ONE deferred obligation (step 2c)
//! Here each Merkle-auth root (3i `fri_roots[0]`, the SB6 source cap node, an
//! SB8 `folded_roots[layer]`) is a fresh wire whose value enters the FIXED
//! public `io_values` (identical across the honest run and all negatives), so
//! the authenticated root is a verifier-provided public input — sound for this
//! gate (a prover has zero freedom over it; sibling flips are caught). It is
//! DELIBERATELY NOT `pin_eq`'d to the Fiat-Shamir-observed root wires
//! (`fri_roots_w` / `folded_roots_w` / the absorbed cap lanes) that seed the
//! query draws. When `discharge_auth_pcs_obligation_via_region` promotes this to
//! the link, the proof roots move from verifier-fixed IO into region witness
//! (bound only by the outer PCS); at that point the src fn MUST reuse the single
//! observed root wire (or add `pin_eq(observed, auth)`) for EACH of the 3i /
//! SB6-cap / SB8 legs, else a prover could draw honest queries from the observed
//! root yet authenticate fabricated answers against an independently chosen root
//! picked after the query positions are known. Verified via a 5-lens adversarial
//! review (2026-07-06): this is the sole surfaced item and it is a step-2c
//! composition obligation, not a defect in this gate.

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
use noid_fri_binius::{COMPACT_NUM_QUERIES, COMPACT_TAU};
use noid_gkr::auth_pcs::{commit_auth_mle_column, open_auth_mle_committed, AuthMleOpeningProof};
use noid_gkr::batch_eval::BatchEvalReduction;
use noid_poseidon2b::hasher::CryptographicHasher;
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
use noid_ivc_core::pcs::{self, PcsParams};
use noid_ivc_core::public_io::{IoClaimSpec, PublicIoSpec, WitnessSlice};
use noid_poseidon2b::native::permutation::STATE_SIZE;

use noid_recursive::acceptance::trace::auth_pcs::absorb_cap_trace;
use noid_recursive::acceptance::trace::deep_chain::{
    verify_column_relation_trace, verify_deep_chain_walk_trace, verify_shift_discharge_trace,
    ColumnRelationProofTrace, DeepChainWalkProofTrace, LaneClaimGroupTrace, RelationTermTrace,
    ShiftDischargeProofTrace,
};
use noid_recursive::acceptance::trace::fri_pcs::{
    alloc_digest, code_new_trace, fold_trace, gen_compact_queries_trace, mle_evaluate_small_trace,
    FriChannelTrace,
};
use noid_recursive::acceptance::trace::{
    alloc_blocks, eq_ind_partial_eval_trace, flat_of, mul, pin_eq,
};

// ---------------------------------------------------------------------------
// Tunable: the number of source queries actually DISCHARGED. Kept small for
// memory safety (the flatness — that this cost is query-count independent — is
// already proven in `region_tiled_opening_slot_e2e`); the REAL channel is still
// driven with COMPACT_NUM_QUERIES for transcript faithfulness. Scaling this to
// COMPACT_NUM_QUERIES is mechanical.
const NQ: usize = 4;

const DOMAIN: &[u8] = b"source-binding-full-leaf-union";
const DOMAIN_B: &[u8] = b"source-binding-full-merkle-union";
const OUTER: &[u8] = b"region-source-binding-full-e2e";

// Meta committed column order (all length P):
//   CODE0=0, CODE1=1, KID0=2, KID1=3, IN0=4, IN1=5, C0=6..C3=9.
const CODE0: usize = 0;
const KID0: usize = 2;
const IN0: usize = 4;
const C0: usize = 6;
const N_COMMITTED: usize = 10;

struct Rng(u64);
impl Rng {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    }
    fn f128_block(&mut self) -> Block128 {
        Block128::from(((self.next_u64() as u128) << 64) | self.next_u64() as u128)
    }
}

fn phi(b: Block128) -> F128 {
    flat_of_tower_u128(b.0)
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
        for (l, &p) in point.iter().enumerate() {
            e = e * if (i >> l) & 1 == 1 { p } else { Block128::ONE + p };
        }
        *slot = e;
    }
    t
}

fn capsule_fixture(
    num_vars: usize,
    seed: u64,
) -> (Vec<Block128>, BatchEvalReduction, AuthMleOpeningProof) {
    use noid_core::mle::evaluate::evaluate_slice;
    let mut rng = Rng(seed);
    let column: Vec<Block128> = (0..(1usize << num_vars)).map(|_| rng.f128_block()).collect();
    let point: Vec<Block128> = (0..num_vars).map(|_| rng.f128_block()).collect();
    let value = evaluate_slice(&column, &point);
    let reduction = BatchEvalReduction { point: point.clone(), value };
    let mut committed = commit_auth_mle_column(&column, num_vars);
    let proof = open_auth_mle_committed(&mut committed, num_vars, &reduction);
    (point, reduction, proof)
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

// ---------------------------------------------------------------------------
// One discharged opening claim (global slice, derived point/value wires, and
// the concrete native (point, value) for the IO vector).
// ---------------------------------------------------------------------------
struct Claim {
    slice: usize,
    point: Vec<LinExpr>,
    value: LinExpr,
    native_point: Vec<F128>,
    native_value: F128,
}

// ---------------------------------------------------------------------------
// Native union DAG: ONE carry-selection + ONE walk + ONE union substitution +
// per-shift discharges + the source_tree exposure (a separate sumcheck). Runs
// prover+verifier channels in lockstep, recording every emitted PCS claim as
// (meta_col, point, value) in the exact order the trace twin reproduces.
// ---------------------------------------------------------------------------
struct UnionNative {
    sel_proof: ColumnRelationProof,
    walk_proof: DeepChainWalkProof,
    sub_proof: ColumnRelationProof,
    shifts: Vec<(usize, usize, ShiftDischargeProof)>, // (shift_log, meta_col, proof)
    expo_proof: ColumnRelationProof,
    /// (meta_col, native point, native value) per emitted claim, in order.
    pending: Vec<(usize, Vec<F128>, F128)>,
    /// exposure claims are recorded separately (their points are extended to
    /// the meta domain by the caller).
    expo_pending: Vec<(usize, Vec<F128>, F128)>,
}

#[allow(clippy::too_many_arguments)]
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
    // exposure inputs (source_tree's own 16-view columns) + meta cols they map to.
    expo_committed: &[&[F128]],
    expo_wlog: usize,
    expo_kid_meta: [usize; 2],
    expo_c_meta: [usize; 2],
) -> UnionNative {
    let internal: Vec<&[F128]> = s_out.iter().map(|c| c.as_slice()).collect();
    let mut ch_p = FsLaneChallenger::new(DOMAIN);
    let mut ch_v = FsLaneChallenger::new(DOMAIN);
    let mut pending: Vec<(usize, Vec<F128>, F128)> = Vec::new();

    // ONE carry-selection over the SHARED carries.
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

    // ONE deep-chain walk over the shared meta s0.
    let groups = vec![LaneClaimGroup { point: sel_point, values: gv }];
    let (walk_proof, _) = prove_deep_chain_walk(s0, &groups, &mut ch_p);
    let terminal = verify_deep_chain_walk(w_log, &groups, &walk_proof, &mut ch_v).expect("native walk");

    // ONE union substitution (source_tree ++ every leaf family).
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
                let (pr, _) =
                    noid_ivc_core::deep_chain::relations::prove_shift_discharge_pow2(committed[*c], &sub_point, *v, 1, &mut ch_p);
                let pt = noid_ivc_core::deep_chain::relations::verify_shift_discharge_pow2(w_log, &sub_point, *v, 1, &pr, &mut ch_v)
                    .expect("shift2");
                pending.push((*c, pt, pr.final_value));
                shifts.push((1usize, *c, pr));
            }
            _ => unreachable!(),
        }
    }

    // Source_tree exposure (separate sumcheck over the half domain).
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
            ColRef::Committed(l) => {
                // KID: open the full KID slice at [expo_point, 0] (low-half select),
                // then extended to the meta domain with zeros by the caller.
                let mut pt = expo_point.clone();
                pt.push(F128::ZERO);
                expo_pending.push((expo_kid_meta[*l], pt, *v));
            }
            ColRef::Window { col, stride_log, offset } => {
                let pt = window_discharge_point(*offset, *stride_log, &expo_point);
                // col local {2,3} -> meta C0/C1.
                expo_pending.push((expo_c_meta[*col - 2], pt, *v));
            }
            _ => unreachable!(),
        }
    }

    assert_eq!(ch_p.sample_f128(), ch_v.sample_f128(), "native lockstep");
    UnionNative { sel_proof, walk_proof, sub_proof, shifts, expo_proof, pending, expo_pending }
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

/// Trace twin of `union_native_terms` (source_tree wiring ++ each leaf family's
/// wiring) with α-power MDS coefficients. Line-by-line shadow of
/// `source_tree_substitution_terms` / `source_leaf_substitution_terms`.
fn union_trace_terms(
    m: &[LinExpr],
    st_refs: &SourceTreeRefs,
    leaf_refs: &[SourceLeafRefs],
) -> Vec<RelationTermTrace> {
    let mut terms = Vec::new();
    // Source_tree.
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
    // Every leaf family (source-leaf / high-pair; identical topology).
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

/// One shared reference for the claimed-ref shape of the union substitution
/// (α = 1 keeps the ref structure identical; values are irrelevant).
fn union_ref_terms(st_refs: &SourceTreeRefs, leaf_refs: &[SourceLeafRefs]) -> Vec<RelationTerm> {
    union_native_terms(st_refs, leaf_refs, F128::ONE)
}

// ---------------------------------------------------------------------------
// Trace union discharge (mirrors run_union_native), collecting Claims that
// carry both the trace point/value and the native point/value.
// ---------------------------------------------------------------------------
#[allow(clippy::too_many_arguments)]
fn discharge_union(
    b: &mut FieldR1csBuilder,
    _slices: &[WitnessSlice],
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

    // Carry-selection.
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

    // Walk.
    let groups_e = vec![LaneClaimGroupTrace { point: sel_point, values: gv }];
    let walk_e = DeepChainWalkProofTrace::alloc(b, &native.walk_proof, w_log);
    let terminal = verify_deep_chain_walk_trace(b, &mut ch, w_log, &groups_e, &walk_e);

    // Union substitution.
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

    // Source_tree exposure (separate sumcheck; points extended to meta domain).
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
    let pad = w_log - expo_wlog; // extend the exposure points to the meta domain
    let mut ec = 0usize;
    for (r, v) in claimed_refs(&expo_ref).iter().zip(expo_e.final_values.iter()) {
        let (col, npt, nval) = &native.expo_pending[ec];
        ec += 1;
        match r {
            ColRef::Committed(_) => {
                // KID full slice at [expo_point, 0]; extend with meta-high zeros.
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
                // Window(C,1,1): plain C opening at [offset bits, expo_point]; extend.
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
// WALK B — the merkle-union: ONE carry-selection + ONE deep-chain walk + ONE
// unioned substitution over a SINGLE meta domain covering the 3i FRI pair-leaf
// family PLUS the three Merkle-authentication legs (3i / SB6 / SB8), each a
// DIFFERENT depth. This is the region_union_primitive pattern generalised from
// (one leaf + one Merkle) to (one pair-leaf + N Merkle families): every family's
// fixed patterns are localized to its own slot range, and every Merkle family's
// UNGATED carry-forward terms (plus the pair-leaf's ungated input terms) are
// gated by a per-family region selector so they vanish over the other families.
// The pair-leaf digests (produced here) feed the 3i Merkle entries; the SB6 /
// SB8 Merkle entries are fed the leaf digests produced by walk A — all as
// shared builder wires (never a public constant).
// ===========================================================================

/// Custom Merkle-family refs for the walk-B union: E/SIB/D at the leg's own
/// columns, but C0..C3 aliasing the SHARED meta columns 2..5 (like
/// `region_union_primitive`'s `refs_b`, NOT `merkle_family_refs` which would
/// point C after each family's own columns).
fn union_merkle_refs(col_base: usize, fixed_base: usize) -> MerkleFamilyRefs {
    MerkleFamilyRefs {
        e: [col_base, col_base + 1],
        sib: [col_base + 2, col_base + 3],
        d: col_base + 4,
        c: std::array::from_fn(|i| 2 + i), // shared C0..C3 = meta cols 2..5
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
    /// Fixed-pattern index of this leg's region selector (1 on its slots).
    region: usize,
    /// Slot base of this leg in the meta domain.
    meta_base: usize,
    cols: MerklePathColumns,
    /// Native entry (== φ(leaf hash)) per path, in path order.
    entry_vals: Vec<[F128; 2]>,
    /// Committed root / cap node per path, in path order.
    committed_roots: Vec<[F128; 2]>,
    /// The shared digest wire feeding each path's entry (from a leaf family in
    /// walk A). Empty when the entries come from walk B's own pair-leaf digests.
    entry_wires: Vec<[LinExpr; 2]>,
    /// When `Some(map)`, this leg's entry per path is walk B's pair-leaf digest
    /// wire `pair_digest_wires[map[path]]` (the 3i FRI leg); else `entry_wires`.
    pair_entry_map: Option<Vec<usize>>,
}

/// Union booleanity term list: every Merkle leg's direction-bit booleanity,
/// each localized by its own `even` pattern (inert over the other legs).
fn union_bool_terms(legs: &[MerkleLeg]) -> Vec<RelationTerm> {
    let mut t = Vec::new();
    for leg in legs {
        t.extend(merkle_booleanity_terms(&leg.refs));
    }
    t
}

/// Union substitution term list (native, concrete α): the pair-leaf's two input
/// terms (region_pair-gated) followed by each Merkle leg's wiring terms (every
/// ungated carry-forward term region-gated so it vanishes over the other legs).
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

/// Trace twin of [`union_bool_terms`] (constant coefficients).
fn union_bool_terms_trace(legs: &[MerkleLeg]) -> Vec<RelationTermTrace> {
    union_bool_terms(legs)
        .iter()
        .map(|t| RelationTermTrace { coeff: LinExpr::constant(t.coeff), factors: t.factors.clone() })
        .collect()
}

/// Trace twin of [`union_sub_terms_native`] with α-power MDS coefficients
/// `m[j] = Σ_e α^{e+1}·flat(MDS[e][j])` as LinExpr. Line-by-line shadow of
/// `pair_leaf_substitution_terms` / `merkle_substitution_terms`. Returns the
/// terms and the α-power wires (the substitution target reuses them).
fn union_sub_terms_trace(
    b: &mut FieldR1csBuilder,
    pair_refs: &PairLeafRefs,
    region_pair: usize,
    legs: &[MerkleLeg],
    alpha: &LinExpr,
) -> (Vec<RelationTermTrace>, Vec<LinExpr>) {
    let (m, ap) = mds_alpha_weights(b, alpha);
    let mut terms: Vec<RelationTermTrace> = Vec::new();

    // Pair-leaf: m[0]·IN0 + m[1]·IN1, both region_pair-gated.
    for i in 0..2 {
        terms.push(RelationTermTrace {
            coeff: m[i].clone(),
            factors: vec![ColRef::Fixed(region_pair), ColRef::Committed(pair_refs.in_[i])],
        });
    }

    // Every Merkle leg's wiring (shadow of merkle_substitution_terms), ungated
    // carry-forward terms region-gated.
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
    /// (meta_col, native point, native value) per emitted claim, in order:
    /// booleanity D refs, selection committed refs, substitution committed/shift
    /// refs.
    pending: Vec<(usize, Vec<F128>, F128)>,
}

/// Copy one Merkle family's active columns into the shared walk-B meta domain:
/// E/SIB/D at `[col_base, col_base+5)` and C / s0 / s_out at the SHARED C
/// (meta cols 2..5), all over `[meta_base, meta_base + n_slots)`.
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

/// Run the whole merkle-union DAG natively (prover + verifier channels in
/// lockstep): union booleanity → shared carry-selection → ONE walk → union
/// substitution → per-shift discharges.
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

    // Union booleanity of every leg's direction bits (one zerocheck).
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

    // ONE carry-selection over the SHARED carries (C == s_out).
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

    // ONE deep-chain walk over the shared meta s0.
    let groups = vec![LaneClaimGroup { point: sel_point, values: gv }];
    let (walk_proof, _) = prove_deep_chain_walk(s0, &groups, &mut ch_p);
    let terminal =
        verify_deep_chain_walk(w_log, &groups, &walk_proof, &mut ch_v).expect("native merkle walk");

    // ONE union substitution (pair-leaf ++ every Merkle leg).
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

/// Trace discharge mirroring [`run_merkle_union_native`], then the per-leg
/// entry (E == shared leaf digest wire) and root (C0/C1 == committed root) pins.
/// The `pair_digest_wires` / `pair_digest_vals` (C0/C1 at each pair slot) are
/// emitted first and returned so the 3i leg's `entry_wires` reference them.
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

    // Union booleanity.
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

    // Carry-selection over the shared carries.
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

    // Walk.
    let groups_e = vec![LaneClaimGroupTrace { point: sel_point, values: gv }];
    let walk_e = DeepChainWalkProofTrace::alloc(b, &native.walk_proof, w_log);
    let terminal = verify_deep_chain_walk_trace(b, &mut ch, w_log, &groups_e, &walk_e);

    // Union substitution.
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

    // Pair-leaf per-tile digest claims (C0/C1 at pair slot t) — returned so the
    // 3i Merkle leg's entries reference these shared wires.
    let mut pair_digest_wires = Vec::with_capacity(pair_digest_vals.len());
    for (t, dig) in pair_digest_vals.iter().enumerate() {
        let (pt_lin, pt_nat) = slot_point(t, w_log);
        let mut wires: [LinExpr; 2] = [LinExpr::zero(), LinExpr::zero()];
        for lane in 0..2 {
            let value = LinExpr::from_wire(b.alloc_f128(dig[lane]));
            out.push(Claim {
                slice: pair_refs.c[lane], // C0, C1
                point: pt_lin.clone(),
                value: value.clone(),
                native_point: pt_nat.clone(),
                native_value: dig[lane],
            });
            wires[lane] = value;
        }
        pair_digest_wires.push(wires);
    }

    // Per-leg entry (E == shared leaf digest wire) and root (C0/C1 == committed
    // root/cap node) pins.
    for leg in legs {
        let stride = leg.family.stride();
        let root_slot_local = 2 * (leg.family.depth - 1) + 1;
        for path in 0..leg.family.n_paths {
            // The entry wire is either walk B's own pair-leaf digest (3i) or the
            // walk-A leaf digest passed in (SB6 / SB8) — never a public constant.
            let entry_wire: [LinExpr; 2] = match &leg.pair_entry_map {
                Some(map) => pair_digest_wires[map[path]].clone(),
                None => leg.entry_wires[path].clone(),
            };
            let entry_slot = leg.meta_base + path * stride;
            let (epl, epn) = slot_point(entry_slot, w_log);
            for lane in 0..2 {
                out.push(Claim {
                    slice: leg.refs.e[lane], // E0, E1
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
                let rv = LinExpr::from_wire(b.alloc_f128(leg.committed_roots[path][lane]));
                out.push(Claim {
                    slice: leg.refs.c[lane], // C0, C1
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
/// transcript to the two `gen_compact_queries` draws, returning
/// (source_query_indices, fri_query_indices) — the same draws the in-trace
/// FriChannelTrace produces (asserted in the test).
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

#[test]
fn region_source_binding_full_end_to_end() {
    // -------------------------------------------------------------------
    // The real capsule opening (wallet shape n_cols = 1).
    // -------------------------------------------------------------------
    let num_vars = 9usize;
    let (point, _red, proof) = capsule_fixture(num_vars, 0xA55E_C0DE);
    let log_n = proof.commitment.log_rows;
    assert_eq!(log_n, num_vars);
    assert_eq!(proof.commitment.n_cols, 1);
    let tau = COMPACT_TAU.min(log_n); // 8
    let n_rounds = log_n - tau; // 1
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
    let leaf_stride = leaf_chain.stride(); // 8
    let leaf_stride_log = leaf_stride.trailing_zeros() as usize;
    assert_eq!(leaf_stride, hp_chain.stride());

    // One SB6 source-leaf family + `n_layers` high-pair families.
    let n_layers = tau.saturating_sub(1); // 7 fold layers
    let n_leaf_families = 1 + n_layers;
    let leaf_family_slots = NQ * leaf_stride;

    // Bases: source_tree [0, st_slots); leaf family f at st_slots + f*leaf_family_slots.
    let total = st_slots + n_leaf_families * leaf_family_slots;
    let w_log = total.next_power_of_two().trailing_zeros() as usize;
    let p = 1usize << w_log;
    let leaf_base = |f: usize| st_slots + f * leaf_family_slots;

    // -------------------------------------------------------------------
    // Drive the REAL FRICHANL channel ONCE (a native + trace pair).
    // -------------------------------------------------------------------
    let mut b = FieldR1csBuilder::new();

    // Proof wires (φ-flat).
    let cap_lanes: Vec<[LinExpr; 2]> =
        proof.commitment.cap.hashes.iter().map(|h| alloc_digest(&mut b, h)).collect();
    let all_openings = alloc_blocks(&mut b, &opening.all_openings);
    let upper = alloc_blocks(&mut b, &fri.upper_partial_evals);
    let h_evals_w = alloc_blocks(&mut b, &src.h_evals);
    let point_w = alloc_blocks(&mut b, &point);
    let fri_roots_w: Vec<[LinExpr; 2]> =
        fri.fri_roots.iter().map(|r| alloc_digest(&mut b, r)).collect();
    let fri_root0_w = fri_roots_w[0].clone();
    let folded_roots_w: Vec<[LinExpr; 2]> =
        src.folded_roots.iter().map(|r| alloc_digest(&mut b, r)).collect();

    let mut ch = FriChannelTrace::new();
    absorb_cap_trace(&mut b, &mut ch, &cap_lanes);
    ch.observe_const_tower(&mut b, MIXED_OPEN_TAG as u128);
    ch.observe_field_elems(&mut b, &all_openings);
    let _gamma = ch.squeeze(&mut b);
    let batched_claim = all_openings[0].clone();

    ch.observe_field_elems(&mut b, &point_w); // 3a
    let (right_w, left_w) = point_w.split_at(n_rounds);
    let left_eq = eq_ind_partial_eval_trace(&mut b, left_w); // 3c
    let mut derived = LinExpr::zero();
    for (l, u) in left_eq.iter().zip(upper.iter()) {
        derived = derived.add(&mul(&mut b, l, u));
    }
    pin_eq(&mut b, &derived, &batched_claim);
    ch.observe_field_elem(&mut b, &batched_claim);

    let beta = ch.squeeze_n(&mut b, tau); // 3d
    let batching_eq = eq_ind_partial_eval_trace(&mut b, &beta);
    let mut claim = LinExpr::zero();
    for (u, be) in upper.iter().zip(batching_eq.iter()) {
        claim = claim.add(&mul(&mut b, u, be));
    }
    let initial_claim = claim.clone();

    // SB1.1: H(right) == initial sumcheck claim.
    let h_at_right = mle_evaluate_small_trace(&mut b, &h_evals_w, right_w);
    pin_eq(&mut b, &h_at_right, &initial_claim);

    // 3e sumcheck rounds. Collect the sumcheck challenges — the second
    // channel<->algebra join (random_point -> fold_trace) for the 3i FRI leg.
    let mut random_point: Vec<LinExpr> = Vec::with_capacity(n_rounds);
    for round in 0..n_rounds {
        let c0 = alloc_blocks(&mut b, std::slice::from_ref(&fri.sum_check_oracles[round][0]))[0].clone();
        let c1 = alloc_blocks(&mut b, std::slice::from_ref(&fri.sum_check_oracles[round][1]))[0].clone();
        pin_eq(&mut b, &c1, &claim);
        ch.observe_field_elem(&mut b, &c0);
        ch.observe_field_elem(&mut b, &c1);
        let depth = noid_fri_binius::compact_fri::compute_round_depth(n_rounds, round);
        ch.observe_vector_commitment(&mut b, &fri_roots_w[round], depth);
        let r = ch.squeeze(&mut b);
        claim = c0.add(&mul(&mut b, &c1, &r));
        random_point.push(r);
    }
    // 3f final codeword.
    let final_cw = alloc_blocks(&mut b, &fri.final_codeword);
    ch.observe_field_elems(&mut b, &final_cw);

    // SB2 source-binding absorbs.
    ch.observe_const_tower(&mut b, MIXED_SOURCE_BINDING_TAG);
    ch.observe_field_elems(&mut b, &h_evals_w);
    for (i, root_w) in folded_roots_w.iter().enumerate() {
        ch.observe_vector_commitment(&mut b, root_w, high_pair_tree_depth(log_n - 1 - i));
    }
    // SB3 source query draw (drives the channel; indices select the tiles).
    let query_indices =
        gen_compact_queries_trace(&mut b, &mut ch, log_n + LOG_RATE, COMPACT_NUM_QUERIES);
    assert!(query_indices.len() >= NQ, "need at least NQ source queries");
    // 3h FRI query draw (walk B's 3i leg selects these tiles + folds them).
    let fri_queries =
        gen_compact_queries_trace(&mut b, &mut ch, n_rounds + LOG_RATE, COMPACT_NUM_QUERIES);
    assert!(fri_queries.len() >= NQ, "need at least NQ FRI queries");
    // Cross-check the in-trace draws against the REAL noid_fri::Channel.
    let (native_source_queries, native_fri_queries) =
        derive_queries(&proof, &point, COMPACT_NUM_QUERIES);
    assert_eq!(query_indices, native_source_queries, "in-trace source queries match native");
    assert_eq!(fri_queries, native_fri_queries, "in-trace FRI queries match native");

    // SB1.2: g_code = Code(H·eq_right) computed in-trace.
    let eq_right_w = eq_ind_partial_eval_trace(&mut b, right_w);
    let mut g_evals_w = Vec::with_capacity(h_evals_w.len());
    for (h, e) in h_evals_w.iter().zip(eq_right_w.iter()) {
        g_evals_w.push(mul(&mut b, h, e));
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
    // ghost-fill the shared perm columns.
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

    // SB6 source-leaf family (family 0): NQ tiles.
    let sb6_base = leaf_base(0);
    let mut sb6_syms: Vec<[F128; 2]> = Vec::with_capacity(NQ);
    // Per-tile leaf digest (== φ(native source_leaf_hash)) — feeds the SB6
    // Merkle entries in walk B.
    let mut sb6_digest_vals: Vec<[F128; 2]> = Vec::with_capacity(NQ);
    for q in 0..NQ {
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

    // SB8 high-pair families: fold-chain index/symbol bookkeeping. Layer `L`
    // occupies leaf family `L + 1`.
    // Precompute the per-query fold index chain and each layer's tile symbols.
    let current: Vec<usize> = source_pair_indices[..NQ].to_vec();
    // Per-layer tile data (leaf_index, s0, s1) and the layer's pair indices.
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
            let syms: Vec<(Block128, Block128)> = (0..NQ).map(|q| symbols[q]).collect();
            layers.push(LayerData { layer_log, pair_indices: pair_indices.clone(), syms });
            cur = pair_indices;
        }
    }

    // Place each high-pair family's tiles into the meta columns. Capture each
    // layer's per-tile digests (== φ(native high_pair_leaf_hash)) — feed the SB8
    // Merkle entries in walk B.
    let mut sb8_digest_vals: Vec<Vec<[F128; 2]>> = Vec::with_capacity(n_layers);
    for (layer, ld) in layers.iter().enumerate() {
        let base = leaf_base(layer + 1);
        let mut layer_digests: Vec<[F128; 2]> = Vec::with_capacity(NQ);
        for q in 0..NQ {
            let (s0v, s1v) = ld.syms[q];
            let tile = build_high_pair_leaf_columns(ld.layer_log, ld.pair_indices[q], phi(s0v), phi(s1v), leaf_stride_log);
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
    // source_tree: 5 patterns localized to [0, st_slots).
    for pat in source_tree_fixed_patterns(&tree, iv) {
        fixed.push(localize(&pat.table, 0, w_log));
    }
    // each leaf family: 5 patterns, tiled NQ times at its base.
    for f in 0..n_leaf_families {
        let base = leaf_base(f);
        for pat in source_leaf_fixed_patterns(&leaf_chain, iv) {
            fixed.push(localize_tiled(&pat.table, base, NQ, w_log));
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
    // Run the native union DAG (exposure over source_tree's own 16-view).
    // -------------------------------------------------------------------
    let half = 1usize << (st_wlog - 1);
    let kid_lo0: Vec<F128> = st_cols.kid[0][..half].to_vec();
    let kid_lo1: Vec<F128> = st_cols.kid[1][..half].to_vec();
    let committed: Vec<&[F128]> = cols.iter().map(|c| c.as_slice()).collect();
    let native = {
        let expo_committed: Vec<&[F128]> = vec![&kid_lo0, &kid_lo1, &st_cols.c[0], &st_cols.c[1]];
        run_union_native(
            &committed, &s0, &s_out, &fixed, &st_refs, &leaf_refs, w_log,
            &expo_committed, st_wlog, [KID0, KID0 + 1], [C0, C0 + 1],
        )
    };

    // -------------------------------------------------------------------
    // Allocate the committed slices in the SAME builder, then discharge.
    // -------------------------------------------------------------------
    let mut slices: Vec<WitnessSlice> = cols.iter().map(|c| alloc_column_slice(&mut b, c, w_log).0).collect();

    let mut claims = discharge_union(&mut b, &slices, &fixed, &st_refs, &leaf_refs, w_log, st_wlog, &native);

    // -------------------------------------------------------------------
    // Grand pins.
    // -------------------------------------------------------------------
    // SB1.2: committed CODE columns bound to the in-trace codeword at each leaf
    // odd slot; root pin C0/C1 at heap slot 3 == fri_roots[0].
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

    // SB7 + SB8 fold chain, symbols pinned to leaf-family IN columns.
    // Source symbol wires (SB6) pinned to SB6 IN0/IN1 at each tile's pair slot 4.
    let mut folded_w: Vec<LinExpr> = Vec::with_capacity(NQ);
    for q in 0..NQ {
        let s0w = LinExpr::from_wire(b.alloc_f128(sb6_syms[q][0]));
        let s1w = LinExpr::from_wire(b.alloc_f128(sb6_syms[q][1]));
        let off = sb6_base + q * leaf_stride + 4; // hash-pair slot for the queried pair
        let (pt_lin, pt_nat) = slot_point(off, w_log);
        claims.push(Claim { slice: IN0, point: pt_lin.clone(), value: s0w.clone(), native_point: pt_nat.clone(), native_value: sb6_syms[q][0] });
        claims.push(Claim { slice: IN0 + 1, point: pt_lin, value: s1w.clone(), native_point: pt_nat, native_value: sb6_syms[q][1] });
        // SB7 fold with β[τ-1].
        let folded = tensor_high_fold_pair_trace(&mut b, &beta[tau - 1], log_n, source_pair_indices[q], &s0w, &s1w);
        folded_w.push(folded);
    }

    // SB8 layers: parity pin + fold with β[τ-2-layer]; symbols pinned to hp IN.
    let mut cur_idx = current.clone();
    for (layer, ld) in layers.iter().enumerate() {
        let base = leaf_base(layer + 1);
        let r = &beta[tau - 2 - layer];
        let mut next_w: Vec<LinExpr> = Vec::with_capacity(NQ);
        for q in 0..NQ {
            let (s0v, s1v) = ld.syms[q];
            let s0f = phi(s0v);
            let s1f = phi(s1v);
            let s0w = LinExpr::from_wire(b.alloc_f128(s0f));
            let s1w = LinExpr::from_wire(b.alloc_f128(s1f));
            let off = base + q * leaf_stride + 4; // the pair hash-pair slot
            let (pt_lin, pt_nat) = slot_point(off, w_log);
            claims.push(Claim { slice: IN0, point: pt_lin.clone(), value: s0w.clone(), native_point: pt_nat.clone(), native_value: s0f });
            claims.push(Claim { slice: IN0 + 1, point: pt_lin, value: s1w.clone(), native_point: pt_nat, native_value: s1f });
            // Parity pin: the incoming fold value == the parity-selected symbol.
            let parity = high_pair_parity(cur_idx[q], ld.layer_log);
            let expected = if parity == 1 { &s1w } else { &s0w };
            pin_eq(&mut b, &folded_w[q], expected);
            // Fold forward.
            let folded = tensor_high_fold_pair_trace(&mut b, r, ld.layer_log, ld.pair_indices[q], &s0w, &s1w);
            next_w.push(folded);
        }
        folded_w = next_w;
        cur_idx = ld.pair_indices.clone();
    }

    // SB9: the closed fold == h_code[current[q]].
    for q in 0..NQ {
        let idx = cur_idx[q];
        assert!(idx < h_code_w.len(), "SB9 index in range");
        pin_eq(&mut b, &folded_w[q], &h_code_w[idx]);
    }
    let _ = &h_code;
    let _ = current.as_slice();

    // ===================================================================
    // WALK A leaf-digest wires -> the SB6 / SB8 Merkle entries. Open walk A's
    // C0/C1 at each tile's digest slot to a fresh wire; that wire IS the
    // corresponding Merkle family's entry (an in-builder digest->entry join,
    // never a public constant).
    // ===================================================================
    let digest_slot = leaf_chain.digest_slot();
    let mut sb6_digest_wires: Vec<[LinExpr; 2]> = Vec::with_capacity(NQ);
    for q in 0..NQ {
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
    // SB8: the two DEEPEST fold layers (smallest trees) are authenticated — a
    // documented memory reduction; all `tau-1` layers are the same leaf+Merkle
    // shape, so a subset gates the mechanism.
    let sb8_auth_layers: Vec<usize> = vec![n_layers - 1, n_layers - 2];
    let mut sb8_digest_wires: Vec<Vec<[LinExpr; 2]>> = Vec::new();
    for &layer in &sb8_auth_layers {
        let base = leaf_base(layer + 1);
        let mut lw = Vec::with_capacity(NQ);
        for q in 0..NQ {
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
    // WALK B — the merkle-union: the 3i FRI, SB6 (to-cap), and SB8 (per-layer)
    // Merkle-authentication legs, all discharged by ONE carry-selection + ONE
    // deep-chain walk + ONE unioned substitution over a SINGLE meta domain
    // (pair-leaf [0, NQ), then each Merkle leg contiguous). Consumes REAL proof
    // siblings + REAL committed roots.
    // ===================================================================
    let hasher = Poseidon2bSponge::new();
    let iv_b = compress_iv_flat();
    let round = 0usize;

    // 3i pair-leaf: bare hash_pair of the queried symbols; leaf = (qi>>round)>>1.
    let fri_pair_indices: Vec<usize> =
        fri_queries[..NQ].iter().map(|&qi| (qi >> round) >> 1).collect();
    let fri_pairs: Vec<(F128, F128)> = (0..NQ)
        .map(|q| {
            let (s0v, s1v) = fri.fri_queried_symbols[round][q];
            (phi(s0v), phi(s1v))
        })
        .collect();
    let pair_wlog = NQ.trailing_zeros() as usize;
    let (pair_cols, pair_digests) = build_pair_leaf_columns(&fri_pairs, pair_wlog);

    // Leg depths in union order: 3i, SB6 (to-cap walk depth), SB8 auth layers.
    let sb6_walk_depth = source_tree_depth(log_n) - source_cap_depth(log_n);
    let mut leg_depths: Vec<usize> = vec![compute_round_depth(n_rounds, round), sb6_walk_depth];
    for &layer in &sb8_auth_layers {
        leg_depths.push(high_pair_tree_depth(log_n - 1 - layer));
    }
    let n_legs = leg_depths.len();

    // Meta layout: pair-leaf [0, NQ), then each Merkle leg contiguous.
    let mut meta_bases = Vec::with_capacity(n_legs);
    let mut acc = NQ;
    for &d in &leg_depths {
        meta_bases.push(acc);
        acc += NQ * (2 * d).next_power_of_two();
    }
    let w_log_b = acc.next_power_of_two().trailing_zeros() as usize;
    let pb = 1usize << w_log_b;
    let n_committed_b = 6 + 5 * n_legs;
    let region_pair = 0usize;
    let pair_refs = pair_leaf_refs(0); // IN0/IN1 = cols 0,1; C0..C3 = cols 2..5

    // Meta columns (ghost-filled), then overlay pair-leaf + each Merkle leg.
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
        cb[j][0..NQ].copy_from_slice(&pair_cols.in_[j][0..NQ]);
    }
    for j in 0..STATE_SIZE {
        cb[2 + j][0..NQ].copy_from_slice(&pair_cols.c[j][0..NQ]);
        s0b[j][0..NQ].copy_from_slice(&pair_cols.s0[j][0..NQ]);
        soutb[j][0..NQ].copy_from_slice(&pair_cols.s_out[j][0..NQ]);
    }

    let mut legs: Vec<MerkleLeg> = Vec::new();
    let mut all_expands_ok = true;

    // Leg 0: 3i FRI-round openings (single per-round root).
    {
        let f = 0usize;
        let depth = leg_depths[f];
        let meta_base = meta_bases[f];
        let col_base = 6 + 5 * f;
        let fixed_base = 1 + 9 * f;
        let region = fixed_base + 8;
        let stride = (2 * depth).next_power_of_two();
        let n_slots = NQ * stride;
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
        let mut witnesses = Vec::with_capacity(NQ);
        let mut entry_vals = Vec::with_capacity(NQ);
        let mut committed_roots = Vec::with_capacity(NQ);
        for q in 0..NQ {
            let p =
                paths.iter().find(|p| p.leaf_index == fri_pair_indices[q]).expect("3i FRI path");
            let leaf_flat = lanes_flat(&p.leaf_hash);
            assert_eq!(pair_digests[q], leaf_flat, "3i pair-leaf digest != φ(native leaf)");
            witnesses.push(MerklePathWitness {
                entry: leaf_flat,
                siblings: p.siblings.iter().map(lanes_flat).collect(),
                directions: p.directions.clone(),
            });
            entry_vals.push(leaf_flat);
            committed_roots.push(root_flat);
        }
        let family = MerklePathFamily { depth, n_paths: NQ };
        let cols = build_merkle_path_columns(&family, iv_b, &witnesses, fam_wlog);
        place_merkle(&mut cb, &mut s0b, &mut soutb, &cols, col_base, meta_base, n_slots);
        legs.push(MerkleLeg {
            family,
            refs: union_merkle_refs(col_base, fixed_base),
            region,
            meta_base,
            cols,
            entry_vals,
            committed_roots,
            entry_wires: Vec::new(),
            pair_entry_map: Some((0..NQ).collect()), // path q <- pair tile q
        });
    }

    // Leg 1: SB6 source-tree opening (authenticated to the committed CAP).
    {
        let f = 1usize;
        let depth = leg_depths[f];
        let meta_base = meta_bases[f];
        let col_base = 6 + 5 * f;
        let fixed_base = 1 + 9 * f;
        let region = fixed_base + 8;
        let stride = (2 * depth).next_power_of_two();
        let n_slots = NQ * stride;
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
        let mut witnesses = Vec::with_capacity(NQ);
        let mut entry_vals = Vec::with_capacity(NQ);
        let mut committed_roots = Vec::with_capacity(NQ);
        for q in 0..NQ {
            let li = source_pair_indices[q];
            let p = paths.iter().find(|p| p.leaf_index == li).expect("SB6 source path");
            assert_eq!(p.siblings.len(), sb6_walk_depth, "SB6 path is walk-depth long");
            let leaf_flat = lanes_flat(&p.leaf_hash);
            assert_eq!(sb6_digest_vals[q], leaf_flat, "SB6 leaf digest != φ(native leaf)");
            witnesses.push(MerklePathWitness {
                entry: leaf_flat,
                siblings: p.siblings.iter().map(lanes_flat).collect(),
                directions: p.directions.clone(),
            });
            entry_vals.push(leaf_flat);
            committed_roots.push(cap_flat[li >> sb6_walk_depth]);
        }
        let family = MerklePathFamily { depth, n_paths: NQ };
        let cols = build_merkle_path_columns(&family, iv_b, &witnesses, fam_wlog);
        place_merkle(&mut cb, &mut s0b, &mut soutb, &cols, col_base, meta_base, n_slots);
        legs.push(MerkleLeg {
            family,
            refs: union_merkle_refs(col_base, fixed_base),
            region,
            meta_base,
            cols,
            entry_vals,
            committed_roots,
            entry_wires: sb6_digest_wires.clone(),
            pair_entry_map: None,
        });
    }

    // Legs 2..: SB8 high-fold layer openings (single per-layer root).
    for (k, &layer) in sb8_auth_layers.iter().enumerate() {
        let f = 2 + k;
        let depth = leg_depths[f];
        let meta_base = meta_bases[f];
        let col_base = 6 + 5 * f;
        let fixed_base = 1 + 9 * f;
        let region = fixed_base + 8;
        let stride = (2 * depth).next_power_of_two();
        let n_slots = NQ * stride;
        let fam_wlog = n_slots.trailing_zeros() as usize;
        let layer_log = log_n - 1 - layer;
        // Leaf indices of ALL source queries at this fold layer (the octopus was
        // built for them).
        let li_all: Vec<usize> = {
            let mut cur = source_pair_indices.clone();
            for l in 0..layer {
                let ll = log_n - 1 - l;
                cur = cur.iter().map(|&idx| high_pair_leaf_index(idx, ll)).collect();
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
        let chosen: Vec<usize> = layers[layer].pair_indices[..NQ].to_vec();
        let mut witnesses = Vec::with_capacity(NQ);
        let mut entry_vals = Vec::with_capacity(NQ);
        let mut committed_roots = Vec::with_capacity(NQ);
        for q in 0..NQ {
            let li = chosen[q];
            let p = paths.iter().find(|p| p.leaf_index == li).expect("SB8 path");
            let leaf_flat = lanes_flat(&p.leaf_hash);
            assert_eq!(sb8_digest_vals[layer][q], leaf_flat, "SB8 leaf digest != φ(native leaf)");
            witnesses.push(MerklePathWitness {
                entry: leaf_flat,
                siblings: p.siblings.iter().map(lanes_flat).collect(),
                directions: p.directions.clone(),
            });
            entry_vals.push(leaf_flat);
            committed_roots.push(root_flat);
        }
        let family = MerklePathFamily { depth, n_paths: NQ };
        let cols = build_merkle_path_columns(&family, iv_b, &witnesses, fam_wlog);
        place_merkle(&mut cb, &mut s0b, &mut soutb, &cols, col_base, meta_base, n_slots);
        legs.push(MerkleLeg {
            family,
            refs: union_merkle_refs(col_base, fixed_base),
            region,
            meta_base,
            cols,
            entry_vals,
            committed_roots,
            entry_wires: sb8_digest_wires[k].clone(),
            pair_entry_map: None,
        });
    }

    // Fixed patterns: region_pair (0) + per leg [8 merkle patterns, region].
    let mut fixed_b: Vec<FixedPattern> = Vec::new();
    {
        let mut t = vec![F128::ZERO; pb];
        for s in 0..NQ {
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

    // Run the native merkle-union DAG, allocate the walk-B slices, discharge.
    let committed_b: Vec<&[F128]> = cb.iter().map(|c| c.as_slice()).collect();
    let native_b = run_merkle_union_native(
        &committed_b, &s0b, &soutb, &fixed_b, &pair_refs, region_pair, &legs, w_log_b, DOMAIN_B,
    );
    let n_slices_a = slices.len();
    let slices_b: Vec<WitnessSlice> =
        cb.iter().map(|c| alloc_column_slice(&mut b, c, w_log_b).0).collect();
    let (mut claims_b, _pair_digest_wires) = discharge_merkle_union(
        &mut b, &fixed_b, &pair_refs, region_pair, &legs, w_log_b, &native_b, &pair_digests, DOMAIN_B,
    );

    // FRI fold-join: the queried symbols == the pair-leaf IN columns, folded to
    // the final codeword (round 0: no previous-round fold consistency).
    let final_len = fri.final_codeword.len();
    for q in 0..NQ {
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
            fold_trace(&mut b, &random_point[round], round, fri_pair_indices[q], &s0w, &s1w, &ntt);
        let final_idx = (fri_queries[q] >> n_rounds) % final_len;
        pin_eq(&mut b, &folded, &final_cw[final_idx]);
    }

    // Merge walk B: append its slices and re-index its claims into the global
    // slice table, then fold them into the single public-IO discharge.
    for c in claims_b.iter_mut() {
        c.slice += n_slices_a;
    }
    slices.extend(slices_b);
    claims.extend(claims_b);
    assert!(all_expands_ok, "all real-sibling octopus expands returned non-empty paths");

    // -------------------------------------------------------------------
    // ONE public-IO discharge over all claims.
    // -------------------------------------------------------------------
    let max_arity = claims.iter().map(|c| c.point.len()).max().unwrap();
    let lanes_per = max_arity + 1;
    let io_len = claims.len() * lanes_per;
    let io_log = io_len.next_power_of_two().trailing_zeros() as usize;
    let mut io_values = Vec::with_capacity(io_len);
    for c in &claims {
        for k in 0..max_arity {
            io_values.push(if k < c.native_point.len() { c.native_point[k] } else { F128::ZERO });
        }
        io_values.push(c.native_value);
    }
    let (io_slice, io_wires) = alloc_column_slice(&mut b, &io_values, io_log);
    for (ci, c) in claims.iter().enumerate() {
        let g = ci * lanes_per;
        for (k, pt) in c.point.iter().enumerate() {
            pin_eq(&mut b, pt, &io_wires[g + k]);
        }
        pin_eq(&mut b, &c.value, &io_wires[g + max_arity]);
    }
    let spec = PublicIoSpec {
        io_slice,
        io_len,
        claims: claims
            .iter()
            .enumerate()
            .map(|(ci, c)| IoClaimSpec {
                slice: slices[c.slice],
                point: ci * lanes_per..ci * lanes_per + c.point.len(),
                value: ci * lanes_per + max_arity,
            })
            .collect(),
    };

    // Memory guard: with TWO union walks this must stay under 2^22 wires.
    let n_wires = b.num_wires();
    eprintln!(
        "[src-full] wires before build = {n_wires}, walkA(P={p}, w_log={w_log}), \
         walkB(P={pb}, w_log={w_log_b}, legs={n_legs}), claims = {}",
        claims.len()
    );
    assert!(n_wires < (1usize << 22), "wire guard {n_wires}");

    let (r1cs, z) = b.build();
    assert!(r1cs.satisfies(&z), "honest source-binding-full trace unsatisfiable");
    let params = PcsParams {
        m: r1cs.m + pcs::LOG_PACKING,
        log_inv_rate: 2,
        log_batch_size: 2,
        profile: Default::default(),
    };
    let mut chp = FsLaneChallenger::new(OUTER);
    let (pf, commitment, _) =
        noid_ivc_prover::field_prover::prove_field_with_public_io(&r1cs, &z, &params, &spec, &io_values, &mut chp);
    let mut chv = FsLaneChallenger::new(OUTER);
    noid_ivc_core::verifier::verify_field_with_public_io(&r1cs, &commitment, &pf, &spec, &io_values, &mut chv)
        .expect("source-binding-full composition verifies");
    eprintln!(
        "[src-full] ONE proof: rows = {} (m = {}), num_vars = {}, NQ = {}, claims = {}, \
         walks = 2 (leaf-union: {n_leaf_families} families / {n_layers} SB8 layers; \
         merkle-union: {n_legs} legs = 3i + SB6-to-cap + {} SB8 layers)",
        z.len(), r1cs.m, num_vars, NQ, claims.len(), sb8_auth_layers.len()
    );

    // -------------------------------------------------------------------
    // Negatives: flip a committed lane -> the trace stays satisfiable (free
    // wires) but that column's opening claim breaks -> BaseFold rejects.
    // -------------------------------------------------------------------
    let flip = |slice_idx: usize, off: usize| {
        let mut bad = z.clone();
        bad[slices[slice_idx].start() + off] += F128::ONE;
        assert!(r1cs.satisfies(&bad), "columns are free wires");
        let mut chp = FsLaneChallenger::new(OUTER);
        let (bp, bc, _) =
            noid_ivc_prover::field_prover::prove_field_with_public_io(&r1cs, &bad, &params, &spec, &io_values, &mut chp);
        let mut chv = FsLaneChallenger::new(OUTER);
        noid_ivc_core::verifier::verify_field_with_public_io(&r1cs, &bc, &bp, &spec, &io_values, &mut chv).is_err()
    };
    // (a) source_tree CODE lane (a leaf codeword symbol).
    let first_code_leaf = 2 * l + 1;
    assert!(flip(CODE0, first_code_leaf), "flipped source-tree CODE lane accepted");
    // (b) SB6 source-leaf symbol (walk A IN0 at tile 0's queried-pair slot 4).
    assert!(flip(IN0, sb6_base + 4), "flipped source-leaf symbol accepted");
    // (c) high-pair symbol (walk A IN1 at hp layer 0 tile 0's pair slot 4).
    let hp0_base = leaf_base(1);
    assert!(flip(IN0 + 1, hp0_base + 4), "flipped high-pair symbol accepted");
    // (d) a Merkle SIBLING lane in each of 3i / SB6 / SB8 (walk B SIB0 at each
    //     leg's node-0 even slot -> the path misses its committed root/cap).
    for f in 0..n_legs {
        let sib0_slice = n_slices_a + 6 + 5 * f + 2; // E0,E1,SIB0,...
        assert!(flip(sib0_slice, meta_bases[f]), "flipped Merkle sibling accepted (leg {f})");
    }
    // (e) a FRI queried symbol (walk B pair-leaf IN0 at pair tile 0) -> breaks
    //     both the 3i leaf hashing and the fold-join.
    assert!(flip(n_slices_a + pair_refs.in_[0], 0), "flipped FRI queried symbol accepted");
}
