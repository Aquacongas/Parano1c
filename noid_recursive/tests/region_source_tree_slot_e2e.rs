//! [G] item 5b step 3 (SB1.2) — the source-binding `Code(H)` tree rebuild
//! discharged IN-TRACE through the outer PCS. The compact-FRI source binding
//! recomputes the round-0 codeword tree and checks its root against
//! `fri_roots[0]`; replaying every internal `compress` inline is part of the
//! ~1.7M-rows/tx cost the region layer folds away. Here the whole tree DAG —
//! carry-selection, the deep-chain walk over every node permutation, the
//! substitution tying the walk input to the heap wiring (child digests read
//! plainly from `KID`), the exposure proving `KID` against `C` through the
//! half-domain `Window`, and the root pin — is replayed by the in-trace
//! verifier twins, every terminal claim (and the Window re-indexed opening)
//! discharged through ONE `prove/verify_field_with_public_io`.
//!
//! This is the last structurally-new region family made in-trace (the others
//! are leaf/path chains). A flipped committed lane (KID, C, CODE) leaves the
//! trace satisfiable but breaks its opening claim -> BaseFold rejects.

use noid_ivc_core::challenger::{Challenger, FsLaneChallenger};
use noid_ivc_core::deep_chain::relations::{
    claimed_refs, prove_column_relation, prove_shift_discharge, verify_column_relation,
    verify_shift_discharge, window_discharge_point, ColRef, ColumnRelationProof, RelationColumns,
    ShiftDischargeProof,
};
use noid_ivc_core::deep_chain::schedule::carry_selection_terms;
use noid_ivc_core::deep_chain::source_tree::{
    build_source_code_columns, build_source_tree_columns, compress_iv_flat,
    source_tree_exposure_terms, source_tree_fixed_patterns, source_tree_refs,
    source_tree_substitution_terms, SourceTree, SourceTreeColumns, SourceTreeRefs,
};
use noid_ivc_core::deep_chain::{
    prove_deep_chain_walk, verify_deep_chain_walk, DeepChainWalkProof, LaneClaimGroup,
};
use noid_ivc_core::field::F128;
use noid_ivc_core::field_circuit::{FieldR1csBuilder, FsChannelTrace, LinExpr};
use noid_ivc_core::pcs::{self, PcsParams};
use noid_ivc_core::public_io::{IoClaimSpec, PublicIoSpec, WitnessSlice};
use noid_poseidon2b::native::permutation::STATE_SIZE;
use noid_recursive::acceptance::trace::deep_chain::{
    verify_column_relation_trace, verify_deep_chain_walk_trace, verify_shift_discharge_trace,
    ColumnRelationProofTrace, DeepChainWalkProofTrace, LaneClaimGroupTrace, RelationTermTrace,
    ShiftDischargeProofTrace,
};
use noid_recursive::acceptance::trace::{alloc_blocks, mul, pin_eq};

// SB1.2 grand-slice extra imports (the real FRICHANL channel + capsule).
use noid_core::{AdditiveNTT, Block128, TowerField};
use noid_fri::code::{Code, LOG_RATE};
use noid_fri_binius::mixed_open::MIXED_OPEN_TAG;
use noid_fri_binius::COMPACT_TAU;
use noid_gkr::auth_pcs::{commit_auth_mle_column, open_auth_mle_committed, AuthMleOpeningProof};
use noid_gkr::batch_eval::BatchEvalReduction;
use noid_recursive::acceptance::trace::auth_pcs::absorb_cap_trace;
use noid_recursive::acceptance::trace::eq_ind_partial_eval_trace;
use noid_recursive::acceptance::trace::fri_pcs::{
    alloc_digest, code_new_trace, mle_evaluate_small_trace, FriChannelTrace,
};

struct Rng(u64);
impl Rng {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    }
    fn f128(&mut self) -> F128 {
        F128 { lo: self.next_u64(), hi: self.next_u64() }
    }
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

struct Claim {
    slice: usize,
    point: Vec<LinExpr>,
    value: LinExpr,
    native_point: Vec<F128>,
    native_value: F128,
}

fn slot_point(s: usize, w_log: usize) -> (Vec<LinExpr>, Vec<F128>) {
    let lin: Vec<LinExpr> = (0..w_log)
        .map(|bb| LinExpr::constant(if (s >> bb) & 1 == 1 { F128::ONE } else { F128::ZERO }))
        .collect();
    let nat: Vec<F128> =
        (0..w_log).map(|bb| if (s >> bb) & 1 == 1 { F128::ONE } else { F128::ZERO }).collect();
    (lin, nat)
}

// ---------------------------------------------------------------------------
// Native driver: run the whole source-tree DAG, recording each PCS claim's
// (global slice, point, value) in lockstep with the trace.
// ---------------------------------------------------------------------------

struct StNative {
    sel_proof: ColumnRelationProof,
    walk_proof: DeepChainWalkProof,
    sub_proof: ColumnRelationProof,
    shifts: Vec<(usize, ShiftDischargeProof)>, // (global slice, proof) for CommittedShift
    expo_proof: ColumnRelationProof,
    // (global slice, native point, native value) per emitted claim, in order.
    pending: Vec<(usize, Vec<F128>, F128)>,
}

#[allow(clippy::too_many_arguments)]
fn run_source_tree_native(
    tree: &SourceTree,
    cols: &SourceTreeColumns,
    code_cols: &[Vec<F128>; 2],
    w_log: usize,
    base: usize,
    domain: &[u8],
) -> StNative {
    let iv = compress_iv_flat();
    let fixed = source_tree_fixed_patterns(tree, iv);
    let refs = source_tree_refs(0, 0);
    let half = 1usize << (w_log - 1);

    // committed order matches source_tree_refs: CODE0,CODE1, KID0,KID1, C0..3.
    let committed: Vec<&[F128]> = vec![
        &code_cols[0], &code_cols[1], &cols.kid[0], &cols.kid[1], &cols.c[0], &cols.c[1], &cols.c[2],
        &cols.c[3],
    ];
    let internal: Vec<&[F128]> = cols.s_out.iter().map(|c| c.as_slice()).collect();
    let mut ch_p = FsLaneChallenger::new(domain);
    let mut ch_v = FsLaneChallenger::new(domain);
    let mut pending: Vec<(usize, Vec<F128>, F128)> = Vec::new();

    // ---- carry selection.
    let beta = ch_p.sample_f128();
    assert_eq!(beta, ch_v.sample_f128());
    let sel_terms = carry_selection_terms(&refs.c, beta);
    let rho = ch_p.sample_f128_vec(w_log);
    let _ = ch_v.sample_f128_vec(w_log);
    let (sel_proof, _, _) = prove_column_relation(
        F128::ZERO,
        &rho,
        &sel_terms,
        &RelationColumns { committed: &committed, internal: &internal, fixed: &fixed },
        &mut ch_p,
    );
    let sel_point =
        verify_column_relation(w_log, F128::ZERO, &rho, &sel_terms, &fixed, &sel_proof, &mut ch_v).unwrap();
    let mut gv = [F128::ZERO; STATE_SIZE];
    for (r, v) in claimed_refs(&sel_terms).iter().zip(sel_proof.final_values.iter()) {
        match r {
            ColRef::Committed(c) => pending.push((base + *c, sel_point.clone(), *v)),
            ColRef::Internal(j) => gv[*j] = *v,
            _ => unreachable!(),
        }
    }

    // ---- walk.
    let groups = vec![LaneClaimGroup { point: sel_point, values: gv }];
    let (walk_proof, _) = prove_deep_chain_walk(&cols.s0, &groups, &mut ch_p);
    let terminal = verify_deep_chain_walk(w_log, &groups, &walk_proof, &mut ch_v).unwrap();

    // ---- substitution (with shift discharges).
    let alpha = ch_p.sample_f128();
    assert_eq!(alpha, ch_v.sample_f128());
    let sub_terms = source_tree_substitution_terms(&refs, alpha);
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
        &RelationColumns { committed: &committed, internal: &[], fixed: &fixed },
        &mut ch_p,
    );
    let sub_point =
        verify_column_relation(w_log, target, &terminal.point, &sub_terms, &fixed, &sub_proof, &mut ch_v).unwrap();
    let mut shifts = Vec::new();
    for (r, v) in claimed_refs(&sub_terms).iter().zip(sub_proof.final_values.iter()) {
        match r {
            ColRef::Committed(c) => pending.push((base + *c, sub_point.clone(), *v)),
            ColRef::CommittedShift(c) => {
                let (pr, _) = prove_shift_discharge(committed[*c], &sub_point, *v, &mut ch_p);
                let pt = verify_shift_discharge(w_log, &sub_point, *v, &pr, &mut ch_v).unwrap();
                pending.push((base + *c, pt, pr.final_value));
                shifts.push((base + *c, pr));
            }
            _ => unreachable!(),
        }
    }

    // ---- exposure: KID_i(w) = C_i(2w+1) over the half domain (w_log - 1).
    let kid_lo0 = &cols.kid[0][..half];
    let kid_lo1 = &cols.kid[1][..half];
    let expo_committed: Vec<&[F128]> = vec![kid_lo0, kid_lo1, &cols.c[0], &cols.c[1]];
    let gamma = ch_p.sample_f128();
    assert_eq!(gamma, ch_v.sample_f128());
    let expo_terms = source_tree_exposure_terms([0, 1], [2, 3], gamma);
    let rho_e = ch_p.sample_f128_vec(w_log - 1);
    let _ = ch_v.sample_f128_vec(w_log - 1);
    let (expo_proof, _, _) = prove_column_relation(
        F128::ZERO,
        &rho_e,
        &expo_terms,
        &RelationColumns { committed: &expo_committed, internal: &[], fixed: &[] },
        &mut ch_p,
    );
    let expo_point =
        verify_column_relation(w_log - 1, F128::ZERO, &rho_e, &expo_terms, &[], &expo_proof, &mut ch_v)
            .unwrap();
    // Zero high bit selects the low half; Window discharges at the re-indexed
    // point. Exposure-local index l maps to global slice base+2+l (KID0,KID1,
    // C0,C1).
    for (r, v) in claimed_refs(&expo_terms).iter().zip(expo_proof.final_values.iter()) {
        match r {
            ColRef::Committed(l) => {
                let mut pt = expo_point.clone();
                pt.push(F128::ZERO);
                pending.push((base + 2 + *l, pt, *v));
            }
            ColRef::Window { col, stride_log, offset } => {
                let pt = window_discharge_point(*offset, *stride_log, &expo_point);
                pending.push((base + 2 + *col, pt, *v));
            }
            _ => unreachable!(),
        }
    }

    assert_eq!(ch_p.sample_f128(), ch_v.sample_f128(), "lockstep");
    StNative { sel_proof, walk_proof, sub_proof, shifts, expo_proof, pending }
}

// ---------------------------------------------------------------------------
// In-trace α-batched substitution terms (source_tree wiring).
// ---------------------------------------------------------------------------

fn st_sub_terms_trace(
    b: &mut FieldR1csBuilder,
    refs: &SourceTreeRefs,
    alpha: &LinExpr,
) -> (Vec<RelationTermTrace>, Vec<LinExpr>) {
    // m_j = Σ_e α^{e+1}·flat(MDS_FULL[e][j]); reuse mds_weights_pub semantics by
    // building the α-power vector and dotting with the flat MDS columns via the
    // native helper applied to a symbolic α (done through per-power scaling).
    let mut ap = Vec::with_capacity(STATE_SIZE);
    let mut acc = LinExpr::constant(F128::ONE);
    for _ in 0..STATE_SIZE {
        acc = mul(b, &acc, alpha);
        ap.push(acc.clone());
    }
    // mds[e][j] = flat(MDS_FULL[e][j]); mds_weights_pub(x)[j] = Σ_e x^{e+1}·mds[e][j].
    // Recover the per-(e,j) flat entries by evaluating mds_weights_pub at the
    // e-th unit power is awkward; instead read the flat MDS columns directly.
    let m: Vec<LinExpr> = (0..STATE_SIZE)
        .map(|j| {
            let mut a = LinExpr::zero();
            for e in 0..STATE_SIZE {
                a = a.add(&ap[e].scale(flat_mds_entry(e, j)));
            }
            a
        })
        .collect();
    let mut terms = Vec::new();
    for i in 0..2 {
        let kid = ColRef::Committed(refs.kid[i]);
        let c_sh = ColRef::CommittedShift(refs.c[i]);
        let code = ColRef::Committed(refs.code[i]);
        for factors in [
            vec![ColRef::Fixed(refs.even_int), kid],
            vec![ColRef::Fixed(refs.odd_int), kid],
            vec![ColRef::Fixed(refs.odd_int), c_sh],
            vec![ColRef::Fixed(refs.leafodd), code],
        ] {
            terms.push(RelationTermTrace { coeff: m[i].clone(), factors });
        }
    }
    for j in 2..STATE_SIZE {
        terms.push(RelationTermTrace { coeff: m[j].clone(), factors: vec![ColRef::Fixed(refs.iv[j - 2])] });
        terms.push(RelationTermTrace {
            coeff: m[j].clone(),
            factors: vec![ColRef::Fixed(refs.odd_int), ColRef::CommittedShift(refs.c[j])],
        });
    }
    (terms, ap)
}

/// One flat MDS matrix entry `flat(MDS_FULL[e][j])`, the same table
/// `mds_weights_pub` dots against the α-power vector (`mds_weights_pub(x)[j] =
/// Σ_e x^{e+1}·flat(MDS_FULL[e][j])`). `flat_mds(true)` exposes it directly.
fn flat_mds_entry(e: usize, j: usize) -> F128 {
    noid_ivc_core::deep_chain::flat_mds(true)[e][j]
}

// ---------------------------------------------------------------------------
// Trace discharge.
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn discharge_source_tree(
    b: &mut FieldR1csBuilder,
    tree: &SourceTree,
    cols: &SourceTreeColumns,
    w_log: usize,
    domain: &[u8],
    native: &StNative,
) -> Vec<Claim> {
    let iv = compress_iv_flat();
    let fixed = source_tree_fixed_patterns(tree, iv);
    let refs = source_tree_refs(0, 0);
    let mut ch = FsChannelTrace::new(b, domain);
    let mut out: Vec<Claim> = Vec::new();
    let np = &native.pending;
    let mut np_cursor = 0usize;
    let zero = LinExpr::zero();

    // ---- carry selection.
    let beta = ch.sample_f128(b);
    let mut bp = LinExpr::constant(F128::ONE);
    let mut sel_e_terms = Vec::new();
    for j in 0..STATE_SIZE {
        bp = mul(b, &bp, &beta);
        sel_e_terms.push(RelationTermTrace { coeff: bp.clone(), factors: vec![ColRef::Committed(refs.c[j])] });
        sel_e_terms.push(RelationTermTrace { coeff: bp.clone(), factors: vec![ColRef::Internal(j)] });
    }
    let rho = ch.sample_f128_vec(b, w_log);
    let sel_e = ColumnRelationProofTrace::alloc(b, &native.sel_proof, w_log, 2 * STATE_SIZE);
    let sel_point = verify_column_relation_trace(b, &mut ch, w_log, &zero, &rho, &sel_e_terms, &fixed, &sel_e);
    let sel_claimed = claimed_refs(&carry_selection_terms(&refs.c, F128::ONE));
    let mut gv: [LinExpr; STATE_SIZE] = std::array::from_fn(|_| LinExpr::zero());
    for (r, v) in sel_claimed.iter().zip(sel_e.final_values.iter()) {
        match r {
            ColRef::Committed(_) => {
                let (slice, npt, nval) = &np[np_cursor];
                np_cursor += 1;
                out.push(Claim {
                    slice: *slice,
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

    // ---- walk.
    let groups_e = vec![LaneClaimGroupTrace { point: sel_point, values: gv }];
    let walk_e = DeepChainWalkProofTrace::alloc(b, &native.walk_proof, w_log);
    let terminal = verify_deep_chain_walk_trace(b, &mut ch, w_log, &groups_e, &walk_e);

    // ---- substitution (with shifts).
    let alpha = ch.sample_f128(b);
    let sub_native = source_tree_substitution_terms(&refs, F128::ONE);
    let (sub_e_terms, ap) = st_sub_terms_trace(b, &refs, &alpha);
    let mut target = LinExpr::zero();
    for e in 0..STATE_SIZE {
        target = target.add(&mul(b, &ap[e], &terminal.values[e]));
    }
    let sub_e = ColumnRelationProofTrace::alloc(b, &native.sub_proof, w_log, claimed_refs(&sub_native).len());
    let sub_point = verify_column_relation_trace(b, &mut ch, w_log, &target, &terminal.point, &sub_e_terms, &fixed, &sub_e);
    let mut shift_cursor = 0usize;
    for (r, v) in claimed_refs(&sub_native).iter().zip(sub_e.final_values.iter()) {
        match r {
            ColRef::Committed(_) => {
                let (slice, npt, nval) = &np[np_cursor];
                np_cursor += 1;
                out.push(Claim {
                    slice: *slice,
                    point: sub_point.clone(),
                    value: v.clone(),
                    native_point: npt.clone(),
                    native_value: *nval,
                });
            }
            ColRef::CommittedShift(_) => {
                let (slice, ns) = &native.shifts[shift_cursor];
                shift_cursor += 1;
                let se = ShiftDischargeProofTrace::alloc(b, ns, w_log);
                let pt = verify_shift_discharge_trace(b, &mut ch, w_log, &sub_point, v, 0, &se);
                let (_, npt, nval) = &np[np_cursor];
                np_cursor += 1;
                out.push(Claim {
                    slice: *slice,
                    point: pt,
                    value: se.final_value.clone(),
                    native_point: npt.clone(),
                    native_value: *nval,
                });
            }
            _ => unreachable!(),
        }
    }

    // ---- exposure over the half domain (w_log - 1).
    let expo_native = source_tree_exposure_terms([0, 1], [2, 3], F128::ZERO);
    let gamma = ch.sample_f128(b);
    let mut gp = LinExpr::constant(F128::ONE);
    let mut expo_e_terms = Vec::new();
    for i in 0..2 {
        gp = mul(b, &gp, &gamma);
        expo_e_terms.push(RelationTermTrace { coeff: gp.clone(), factors: vec![ColRef::Committed(i)] });
        expo_e_terms.push(RelationTermTrace {
            coeff: gp.clone(),
            factors: vec![ColRef::Window { col: 2 + i, stride_log: 1, offset: 1 }],
        });
    }
    let rho_e = ch.sample_f128_vec(b, w_log - 1);
    let expo_e = ColumnRelationProofTrace::alloc(b, &native.expo_proof, w_log - 1, claimed_refs(&expo_native).len());
    let expo_point = verify_column_relation_trace(b, &mut ch, w_log - 1, &zero, &rho_e, &expo_e_terms, &[], &expo_e);
    for (r, v) in claimed_refs(&expo_native).iter().zip(expo_e.final_values.iter()) {
        match r {
            ColRef::Committed(_) => {
                // Open the FULL KID slice at [expo_point, 0] (low half select).
                let mut pt = expo_point.clone();
                pt.push(LinExpr::constant(F128::ZERO));
                let (slice, npt, nval) = &np[np_cursor];
                np_cursor += 1;
                out.push(Claim {
                    slice: *slice,
                    point: pt,
                    value: v.clone(),
                    native_point: npt.clone(),
                    native_value: *nval,
                });
            }
            ColRef::Window { offset, stride_log, .. } => {
                // Window(C,1,1): plain C opening at [offset bits, expo_point].
                let mut pt: Vec<LinExpr> = (0..*stride_log)
                    .map(|jb| LinExpr::constant(if (offset >> jb) & 1 == 1 { F128::ONE } else { F128::ZERO }))
                    .collect();
                pt.extend(expo_point.clone());
                let (slice, npt, nval) = &np[np_cursor];
                np_cursor += 1;
                out.push(Claim {
                    slice: *slice,
                    point: pt,
                    value: v.clone(),
                    native_point: npt.clone(),
                    native_value: *nval,
                });
            }
            _ => unreachable!(),
        }
    }
    assert_eq!(np_cursor, np.len(), "source-tree pending lockstep");
    let _ = tree;
    let _ = cols;
    out
}

/// SB1.2 in-trace: the whole source-tree DAG discharged through one public-IO.
/// Honest verifies; flipping a KID / C / CODE lane breaks its opening claim.
#[test]
fn region_source_tree_slot_end_to_end() {
    let mut rng = Rng(0x5B12_C0DE);
    let leaf_log = 3usize;
    let tree = SourceTree { leaf_log };
    let w_log = tree.slots_log();
    let code: Vec<F128> = (0..tree.code_len()).map(|_| rng.f128()).collect();
    let cols = build_source_tree_columns(&tree, &code, w_log);
    let code_cols = build_source_code_columns(&tree, &code, w_log);

    let mut b = FieldR1csBuilder::new();
    // committed slice order = source_tree_refs: CODE0,CODE1, KID0,KID1, C0..3.
    let mut slices = Vec::new();
    for col in [
        &code_cols[0], &code_cols[1], &cols.kid[0], &cols.kid[1], &cols.c[0], &cols.c[1], &cols.c[2],
        &cols.c[3],
    ] {
        slices.push(alloc_column_slice(&mut b, col, w_log).0);
    }
    let base = 0usize;

    let native = run_source_tree_native(&tree, &cols, &code_cols, w_log, base, b"source-tree-slot");
    let mut claims = discharge_source_tree(&mut b, &tree, &cols, w_log, b"source-tree-slot", &native);

    // Root pin: C0/C1 at slot 3 (heap node 1 odd) == the recomputed root.
    let (rp_lin, rp_nat) = slot_point(3, w_log);
    for lane in 0..2 {
        let rv = LinExpr::from_wire(b.alloc_f128(cols.root[lane]));
        claims.push(Claim {
            slice: base + 4 + lane, // C0, C1
            point: rp_lin.clone(),
            value: rv,
            native_point: rp_nat.clone(),
            native_value: cols.root[lane],
        });
    }

    // ---- ONE public-IO discharge over all claims.
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
        for (k, p) in c.point.iter().enumerate() {
            pin_eq(&mut b, p, &io_wires[g + k]);
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

    let (r1cs, z) = b.build();
    assert!(r1cs.satisfies(&z), "honest source-tree trace unsatisfiable");
    let params = PcsParams {
        m: r1cs.m + pcs::LOG_PACKING,
        log_inv_rate: 2,
        log_batch_size: 2,
        profile: Default::default(),
    };
    let mut chp = FsLaneChallenger::new(b"region-source-tree");
    let (proof, commitment, _) = noid_ivc_prover::field_prover::prove_field_with_public_io(
        &r1cs, &z, &params, &spec, &io_values, &mut chp,
    );
    let mut chv = FsLaneChallenger::new(b"region-source-tree");
    noid_ivc_core::verifier::verify_field_with_public_io(&r1cs, &commitment, &proof, &spec, &io_values, &mut chv)
        .expect("source-tree composition verifies");
    eprintln!(
        "[region-source-tree] rows = {} (m = {}), leaf_log = {}, claims = {}",
        z.len(),
        r1cs.m,
        leaf_log,
        spec.claims.len()
    );

    let flip = |slice_idx: usize, off: usize| {
        let mut bad = z.clone();
        bad[slices[slice_idx].start() + off] += F128::ONE;
        assert!(r1cs.satisfies(&bad), "columns are free wires");
        let mut chp = FsLaneChallenger::new(b"region-source-tree");
        let (bp, bc, _) = noid_ivc_prover::field_prover::prove_field_with_public_io(
            &r1cs, &bad, &params, &spec, &io_values, &mut chp,
        );
        let mut chv = FsLaneChallenger::new(b"region-source-tree");
        noid_ivc_core::verifier::verify_field_with_public_io(&r1cs, &bc, &bp, &spec, &io_values, &mut chv).is_err()
    };
    // Corrupt a KID lane (child digest) -> exposure/substitution claim breaks.
    assert!(flip(2, 3), "flipped KID lane accepted");
    // Corrupt a C lane (node output) -> walk/exposure/root claim breaks.
    assert!(flip(4, 5), "flipped C lane accepted");
    // Corrupt a CODE lane (leaf symbol) -> substitution claim breaks.
    let leaf_slot = 2 * tree.leaf_count() + 1;
    assert!(flip(0, leaf_slot), "flipped CODE lane accepted");
}

// ===========================================================================
// SB1.2 grand slice: the source-binding root check composed in-trace with the
// REAL FRICHANL channel. Drives FriChannelTrace through step 3d to derive the
// initial sumcheck claim, pins H(right) == that claim (SB1.1), computes the
// codeword g_code = Code(H·eq_right) in-trace via code_new_trace, binds it to
// the source_tree family's committed CODE columns, and pins the family root to
// fri_roots[0] -- replacing the inline merkle_root_trace with the region tree.
// This is the first grand-assembly leg: the FRICHANL channel joined to a region
// family in ONE trace, discharged through public-IO.
// ===========================================================================

fn phi(b: Block128) -> F128 {
    noid_ivc_core::deep_chain::schedule::flat_of_tower_u128(b.0)
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

impl Rng {
    fn f128_block(&mut self) -> Block128 {
        Block128::from(((self.next_u64() as u128) << 64) | self.next_u64() as u128)
    }
}

/// SB1.1 + SB1.2 composed in-trace with the real channel; honest verifies, and
/// tampering H, the codeword, or the tree columns breaks a claim.
#[test]
fn region_sb12_source_binding_grand() {
    let num_vars = 9usize; // tau = 8, n_rounds = 1 -> a tiny source tree
    let (point, _reduction, proof) = capsule_fixture(num_vars, 0x5B12_9A1E);
    let log_n = proof.commitment.log_rows;
    assert_eq!(log_n, num_vars);
    let n_cols = proof.commitment.n_cols;
    assert_eq!(n_cols, 1);
    let tau = COMPACT_TAU.min(log_n);
    let n_rounds = log_n - tau;
    let ntt = AdditiveNTT::<Block128>::new(num_vars + LOG_RATE);

    let opening = &proof.opening;
    let fri = &opening.fri_proof;
    let src = &opening.source_proof;
    let right_tower = &point[..n_rounds];
    let left = &point[n_rounds..];

    // ---- Native codeword + source tree (φ into the flat basis).
    let eq_r = eq_tensor_tower(right_tower);
    let g: Vec<Block128> = src.h_evals.iter().zip(eq_r.iter()).map(|(&h, &e)| h * e).collect();
    let g_code = Code::new_parallel(&g, &ntt);
    let g_code_flat: Vec<F128> = g_code.encoding.iter().map(|&b| phi(b)).collect();
    let tree = SourceTree { leaf_log: n_rounds + 1 };
    assert_eq!(tree.code_len(), g_code_flat.len(), "codeword length matches tree");
    let w_log = tree.slots_log();
    let cols = build_source_tree_columns(&tree, &g_code_flat, w_log);
    let code_cols = build_source_code_columns(&tree, &g_code_flat, w_log);
    // The region tree root IS the real FRI round-0 root (the binding SB1.2 pins).
    let fri_root0 = lanes_flat(&fri.fri_roots[0]);
    assert_eq!(cols.root, fri_root0, "region tree root != φ(fri_roots[0])");

    // ---- Trace.
    let mut b = FieldR1csBuilder::new();

    // Family committed slices (base 0): CODE0,CODE1, KID0,KID1, C0..3.
    let mut slices = Vec::new();
    for col in [
        &code_cols[0], &code_cols[1], &cols.kid[0], &cols.kid[1], &cols.c[0], &cols.c[1], &cols.c[2],
        &cols.c[3],
    ] {
        slices.push(alloc_column_slice(&mut b, col, w_log).0);
    }
    let base = 0usize;

    // Proof wires + the FRICHANL channel through step 3d.
    let cap_lanes: Vec<[LinExpr; 2]> =
        proof.commitment.cap.hashes.iter().map(|h| alloc_digest(&mut b, h)).collect();
    let all_openings = alloc_blocks(&mut b, &opening.all_openings);
    let upper = alloc_blocks(&mut b, &fri.upper_partial_evals);
    let h_evals_w = alloc_blocks(&mut b, &src.h_evals);
    let point_w = alloc_blocks(&mut b, &point);
    let fri_root0_w = alloc_digest(&mut b, &fri.fri_roots[0]);

    let mut ch = FriChannelTrace::new();
    absorb_cap_trace(&mut b, &mut ch, &cap_lanes);
    ch.observe_const_tower(&mut b, MIXED_OPEN_TAG as u128);
    ch.observe_field_elems(&mut b, &all_openings);
    let _gamma = ch.squeeze(&mut b);
    let batched_claim = all_openings[0].clone(); // n_cols = 1

    ch.observe_field_elems(&mut b, &point_w); // 3a
    let (right_w, left_w) = point_w.split_at(n_rounds);
    assert_eq!(left_w.len(), left.len());
    // 3c: eval consistency Σ eq(left,i)·upper == batched_claim.
    let left_eq = eq_ind_partial_eval_trace(&mut b, left_w);
    let mut derived = LinExpr::zero();
    for (l, u) in left_eq.iter().zip(upper.iter()) {
        derived = derived.add(&mul(&mut b, l, u));
    }
    pin_eq(&mut b, &derived, &batched_claim);
    ch.observe_field_elem(&mut b, &batched_claim);
    // 3d: tensor batching β, initial sumcheck claim.
    let beta = ch.squeeze_n(&mut b, tau);
    let batching_eq = eq_ind_partial_eval_trace(&mut b, &beta);
    let mut initial_claim = LinExpr::zero();
    for (u, be) in upper.iter().zip(batching_eq.iter()) {
        initial_claim = initial_claim.add(&mul(&mut b, u, be));
    }

    // SB1.1: H(right) == initial sumcheck claim.
    let h_at_right = mle_evaluate_small_trace(&mut b, &h_evals_w, right_w);
    pin_eq(&mut b, &h_at_right, &initial_claim);

    // SB1.2: g_code = Code(H·eq_right), computed in-trace.
    let eq_right_w = eq_ind_partial_eval_trace(&mut b, right_w);
    let mut g_evals_w = Vec::with_capacity(h_evals_w.len());
    for (h, e) in h_evals_w.iter().zip(eq_right_w.iter()) {
        g_evals_w.push(mul(&mut b, h, e));
    }
    let g_code_w = code_new_trace(&g_evals_w);
    assert_eq!(g_code_w.len(), g_code_flat.len());

    // ---- Discharge the source tree family; collect its DAG claims.
    let native = run_source_tree_native(&tree, &cols, &code_cols, w_log, base, b"sb12-source-tree");
    let mut claims = discharge_source_tree(&mut b, &tree, &cols, w_log, b"sb12-source-tree", &native);

    // Join: the committed CODE columns at each leaf odd slot equal the in-trace
    // codeword derived from H (binds the tree leaves to H, not arbitrary code).
    let l = tree.leaf_count();
    for i in 0..l {
        let slot = 2 * (l + i) + 1;
        let (pt_lin, pt_nat) = slot_point(slot, w_log);
        for lane in 0..2 {
            claims.push(Claim {
                slice: base + lane, // CODE0 / CODE1
                point: pt_lin.clone(),
                value: g_code_w[2 * i + lane].clone(),
                native_point: pt_nat.clone(),
                native_value: g_code_flat[2 * i + lane],
            });
        }
    }
    // Root pin: C0/C1 at slot 3 (heap node 1 odd) == fri_roots[0].
    let (rp_lin, rp_nat) = slot_point(3, w_log);
    for lane in 0..2 {
        claims.push(Claim {
            slice: base + 4 + lane, // C0 / C1
            point: rp_lin.clone(),
            value: fri_root0_w[lane].clone(),
            native_point: rp_nat.clone(),
            native_value: fri_root0[lane],
        });
    }

    // ---- ONE public-IO discharge over all claims.
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
        for (k, p) in c.point.iter().enumerate() {
            pin_eq(&mut b, p, &io_wires[g + k]);
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

    let (r1cs, z) = b.build();
    assert!(r1cs.satisfies(&z), "honest SB1.2 grand trace unsatisfiable");
    let params = PcsParams {
        m: r1cs.m + pcs::LOG_PACKING,
        log_inv_rate: 2,
        log_batch_size: 2,
        profile: Default::default(),
    };
    let mut chp = FsLaneChallenger::new(b"region-sb12-grand");
    let (pf, commitment, _) = noid_ivc_prover::field_prover::prove_field_with_public_io(
        &r1cs, &z, &params, &spec, &io_values, &mut chp,
    );
    let mut chv = FsLaneChallenger::new(b"region-sb12-grand");
    noid_ivc_core::verifier::verify_field_with_public_io(&r1cs, &commitment, &pf, &spec, &io_values, &mut chv)
        .expect("SB1.2 grand composition verifies");
    eprintln!(
        "[region-sb12-grand] rows = {} (m = {}), num_vars = {}, n_rounds = {}, claims = {}",
        z.len(),
        r1cs.m,
        num_vars,
        n_rounds,
        spec.claims.len()
    );

    // Negative: flip a committed CODE lane -> the tree root diverges from
    // fri_roots[0] AND the H-join claim breaks -> BaseFold rejects.
    let flip = |slice_idx: usize, off: usize| {
        let mut bad = z.clone();
        bad[slices[slice_idx].start() + off] += F128::ONE;
        assert!(r1cs.satisfies(&bad), "columns are free wires");
        let mut chp = FsLaneChallenger::new(b"region-sb12-grand");
        let (bp, bc, _) = noid_ivc_prover::field_prover::prove_field_with_public_io(
            &r1cs, &bad, &params, &spec, &io_values, &mut chp,
        );
        let mut chv = FsLaneChallenger::new(b"region-sb12-grand");
        noid_ivc_core::verifier::verify_field_with_public_io(&r1cs, &bc, &bp, &spec, &io_values, &mut chv).is_err()
    };
    let first_leaf = 2 * l + 1;
    assert!(flip(0, first_leaf), "flipped CODE leaf accepted");
    assert!(flip(4, 5), "flipped C node accepted");
}
