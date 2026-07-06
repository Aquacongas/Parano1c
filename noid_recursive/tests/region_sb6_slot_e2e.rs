//! [G] item 5b step 3 — SB6 composed IN-TRACE: source-leaf family + Merkle path
//! family in ONE trace, the leaf digest WIRED into the path entry, all
//! discharged through ONE outer PCS via public-IO.
//!
//! This is the decisive multi-family composition — the structural core of
//! `discharge_auth_pcs_obligation_via_region`. Two real wallet-PCS families
//! live as separate witness slices in the SAME FieldR1csBuilder; both claim
//! DAGs are replayed by the in-trace twins; the source-leaf digest (C0/C1 at
//! its digest slot) and the Merkle entry (E0/E1 at the path's entry slot) are
//! pinned to the SAME io lanes, so a single opening value binds them — the
//! inter-family wire SB6 needs (leaf → path entry). Every terminal claim and
//! the recomputed cap node discharge through one `prove/verify_field_with_
//! public_io`. A flipped committed lane in EITHER family breaks its opening
//! claim → BaseFold rejects.

use noid_ivc_core::challenger::{Challenger, FsLaneChallenger};
use noid_ivc_core::deep_chain::flat_mds;
use noid_ivc_core::deep_chain::leaf_hash::{
    build_source_leaf_columns, source_leaf_fixed_patterns, source_leaf_refs,
    source_leaf_substitution_terms, SourceLeafChain, SourceLeafColumns, SourceLeafRefs,
};
use noid_ivc_core::deep_chain::relations::{
    claimed_refs, prove_column_relation, prove_shift_discharge, prove_shift_discharge_pow2,
    verify_column_relation, verify_shift_discharge, verify_shift_discharge_pow2, ColRef,
    ColumnRelationProof, RelationColumns, ShiftDischargeProof,
};
use noid_ivc_core::deep_chain::schedule::{
    build_merkle_path_columns, carry_selection_terms, flat_of_tower_u128, merkle_family_refs,
    merkle_fixed_patterns, merkle_substitution_terms, MerkleFamilyRefs, MerklePathColumns,
    MerklePathFamily, MerklePathWitness,
};
use noid_ivc_core::deep_chain::{
    prove_deep_chain_walk, verify_deep_chain_walk, DeepChainWalkProof, LaneClaimGroup,
};
use noid_ivc_core::field::F128;
use noid_ivc_core::field_circuit::{FieldR1csBuilder, FsChannelTrace, LinExpr};
use noid_ivc_core::pcs::{self, PcsParams};
use noid_ivc_core::public_io::{IoClaimSpec, PublicIoSpec, WitnessSlice};
use noid_poseidon2b::native::domain::{capacity_iv, TAG_COMPRESS};
use noid_poseidon2b::native::permutation::STATE_SIZE;
use noid_recursive::acceptance::trace::deep_chain::{
    verify_column_relation_trace, verify_deep_chain_walk_trace, verify_shift_discharge_trace,
    ColumnRelationProofTrace, DeepChainWalkProofTrace, LaneClaimGroupTrace, RelationTermTrace,
    ShiftDischargeProofTrace,
};
use noid_recursive::acceptance::trace::{mul, pin_eq};

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

fn iv_flat() -> [F128; 2] {
    let iv = capacity_iv(TAG_COMPRESS);
    [flat_of_tower_u128(iv[0].0), flat_of_tower_u128(iv[1].0)]
}

fn alloc_column_slice(b: &mut FieldR1csBuilder, col: &[F128], log2_len: usize) -> (WitnessSlice, Vec<LinExpr>) {
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

/// A discharged claim: the global slice it opens, the derived point wires, the
/// claimed value wire, plus the concrete native (point, value) for the IO.
struct Claim {
    slice: usize,
    point: Vec<LinExpr>,
    value: LinExpr,
    native_point: Vec<F128>,
    native_value: F128,
}

// ---------------------------------------------------------------------------
// Source-leaf family (family A): produces the leaf digest.
// ---------------------------------------------------------------------------

struct SlNative {
    sel_proof: ColumnRelationProof,
    walk_proof: DeepChainWalkProof,
    sub_proof: ColumnRelationProof,
    shifts: Vec<(usize, usize, ShiftDischargeProof)>,
    pending: Vec<(usize, Vec<F128>, F128)>, // (col-local, point, value)
}

fn run_source_leaf_native(chain: &SourceLeafChain, cols: &SourceLeafColumns, w_log: usize, domain: &[u8]) -> SlNative {
    let fixed = source_leaf_fixed_patterns(chain, iv_flat());
    let refs = source_leaf_refs(0, 0);
    let committed: Vec<&[F128]> = vec![&cols.in_[0], &cols.in_[1], &cols.c[0], &cols.c[1], &cols.c[2], &cols.c[3]];
    let internal: Vec<&[F128]> = cols.s_out.iter().map(|c| c.as_slice()).collect();
    let mut ch_p = FsLaneChallenger::new(domain);
    let mut ch_v = FsLaneChallenger::new(domain);
    let mut pending = Vec::new();

    let beta = ch_p.sample_f128();
    assert_eq!(beta, ch_v.sample_f128());
    let sel_terms = carry_selection_terms(&refs.c, beta);
    let rho = ch_p.sample_f128_vec(w_log);
    let _ = ch_v.sample_f128_vec(w_log);
    let (sel_proof, _, _) = prove_column_relation(F128::ZERO, &rho, &sel_terms, &RelationColumns { committed: &committed, internal: &internal, fixed: &fixed }, &mut ch_p);
    let sel_point = verify_column_relation(w_log, F128::ZERO, &rho, &sel_terms, &fixed, &sel_proof, &mut ch_v).unwrap();
    let mut gv = [F128::ZERO; STATE_SIZE];
    for (r, v) in claimed_refs(&sel_terms).iter().zip(sel_proof.final_values.iter()) {
        match r {
            ColRef::Committed(c) => pending.push((*c, sel_point.clone(), *v)),
            ColRef::Internal(j) => gv[*j] = *v,
            _ => unreachable!(),
        }
    }
    let groups = vec![LaneClaimGroup { point: sel_point, values: gv }];
    let (walk_proof, _) = prove_deep_chain_walk(&cols.s0, &groups, &mut ch_p);
    let terminal = verify_deep_chain_walk(w_log, &groups, &walk_proof, &mut ch_v).unwrap();

    let alpha = ch_p.sample_f128();
    assert_eq!(alpha, ch_v.sample_f128());
    let sub_terms = source_leaf_substitution_terms(&refs, alpha);
    let mut target = F128::ZERO;
    let mut p = F128::ONE;
    for e in 0..STATE_SIZE { p = p * alpha; target += p * terminal.values[e]; }
    let (sub_proof, _, _) = prove_column_relation(target, &terminal.point, &sub_terms, &RelationColumns { committed: &committed, internal: &[], fixed: &fixed }, &mut ch_p);
    let sub_point = verify_column_relation(w_log, target, &terminal.point, &sub_terms, &fixed, &sub_proof, &mut ch_v).unwrap();

    let mut shifts = Vec::new();
    for (r, v) in claimed_refs(&sub_terms).iter().zip(sub_proof.final_values.iter()) {
        match r {
            ColRef::Committed(c) => pending.push((*c, sub_point.clone(), *v)),
            ColRef::CommittedShift(c) => {
                let (pr, _) = prove_shift_discharge(committed[*c], &sub_point, *v, &mut ch_p);
                let pt = verify_shift_discharge(w_log, &sub_point, *v, &pr, &mut ch_v).unwrap();
                pending.push((*c, pt, pr.final_value)); shifts.push((0, *c, pr));
            }
            ColRef::CommittedShift2(c) => {
                let (pr, _) = prove_shift_discharge_pow2(committed[*c], &sub_point, *v, 1, &mut ch_p);
                let pt = verify_shift_discharge_pow2(w_log, &sub_point, *v, 1, &pr, &mut ch_v).unwrap();
                pending.push((*c, pt, pr.final_value)); shifts.push((1, *c, pr));
            }
            _ => unreachable!(),
        }
    }
    assert_eq!(ch_p.sample_f128(), ch_v.sample_f128());
    SlNative { sel_proof, walk_proof, sub_proof, shifts, pending }
}

fn sl_sub_terms_trace(b: &mut FieldR1csBuilder, refs: &SourceLeafRefs, alpha: &LinExpr) -> (Vec<RelationTermTrace>, Vec<LinExpr>) {
    let mds = flat_mds(true);
    let mut ap = Vec::with_capacity(STATE_SIZE);
    let mut acc = LinExpr::constant(F128::ONE);
    for _ in 0..STATE_SIZE { acc = mul(b, &acc, alpha); ap.push(acc.clone()); }
    let m: Vec<LinExpr> = (0..STATE_SIZE).map(|j| { let mut a = LinExpr::zero(); for e in 0..STATE_SIZE { a = a.add(&ap[e].scale(mds[e][j])); } a }).collect();
    let mut terms = Vec::new();
    for i in 0..2 {
        let in_col = ColRef::Committed(refs.in_[i]);
        let c_sh = ColRef::CommittedShift(refs.c[i]);
        let c_sh2 = ColRef::CommittedShift2(refs.c[i]);
        for factors in [vec![ColRef::Fixed(refs.hp), in_col], vec![ColRef::Fixed(refs.even), c_sh2], vec![ColRef::Fixed(refs.odd), c_sh], vec![ColRef::Fixed(refs.odd), c_sh2]] {
            terms.push(RelationTermTrace { coeff: m[i].clone(), factors });
        }
    }
    for j in 2..STATE_SIZE {
        terms.push(RelationTermTrace { coeff: m[j].clone(), factors: vec![ColRef::Fixed(refs.iv[j - 2])] });
        terms.push(RelationTermTrace { coeff: m[j].clone(), factors: vec![ColRef::Fixed(refs.odd), ColRef::CommittedShift(refs.c[j])] });
    }
    (terms, ap)
}

/// Discharge the source-leaf family in-trace; returns the pending claims (with
/// global slice indices) plus the two digest wires (C0/C1 at the digest slot).
#[allow(clippy::too_many_arguments)]
fn discharge_source_leaf(
    b: &mut FieldR1csBuilder,
    chain: &SourceLeafChain,
    cols: &SourceLeafColumns,
    w_log: usize,
    domain: &[u8],
    native: &SlNative,
    slices: &[WitnessSlice],
    base: usize,
) -> (Vec<Claim>, [LinExpr; 2], [F128; 2]) {
    let fixed = source_leaf_fixed_patterns(chain, iv_flat());
    let refs = source_leaf_refs(0, 0);
    let mut ch = FsChannelTrace::new(b, domain);
    let mut out: Vec<Claim> = Vec::new();
    // (col-local, native (point, value)) run in lockstep with the trace claims.
    let np = &native.pending;
    let mut np_cursor = 0usize;
    let zero = LinExpr::zero();

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
            ColRef::Committed(c) => {
                let (_, npt, nval) = &np[np_cursor]; np_cursor += 1;
                out.push(Claim { slice: base + *c, point: sel_point.clone(), value: v.clone(), native_point: npt.clone(), native_value: *nval });
            }
            ColRef::Internal(j) => gv[*j] = v.clone(),
            _ => unreachable!(),
        }
    }
    let groups_e = vec![LaneClaimGroupTrace { point: sel_point, values: gv }];
    let walk_e = DeepChainWalkProofTrace::alloc(b, &native.walk_proof, w_log);
    let terminal = verify_deep_chain_walk_trace(b, &mut ch, w_log, &groups_e, &walk_e);

    let alpha = ch.sample_f128(b);
    let sub_native = source_leaf_substitution_terms(&refs, F128::ONE);
    let (sub_e_terms, ap) = sl_sub_terms_trace(b, &refs, &alpha);
    let mut target = LinExpr::zero();
    for e in 0..STATE_SIZE { target = target.add(&mul(b, &ap[e], &terminal.values[e])); }
    let sub_e = ColumnRelationProofTrace::alloc(b, &native.sub_proof, w_log, claimed_refs(&sub_native).len());
    let sub_point = verify_column_relation_trace(b, &mut ch, w_log, &target, &terminal.point, &sub_e_terms, &fixed, &sub_e);
    let mut shift_cursor = 0usize;
    for (r, v) in claimed_refs(&sub_native).iter().zip(sub_e.final_values.iter()) {
        match r {
            ColRef::Committed(c) => {
                let (_, npt, nval) = &np[np_cursor]; np_cursor += 1;
                out.push(Claim { slice: base + *c, point: sub_point.clone(), value: v.clone(), native_point: npt.clone(), native_value: *nval });
            }
            ColRef::CommittedShift(_) | ColRef::CommittedShift2(_) => {
                let (sl, col, ns) = &native.shifts[shift_cursor]; shift_cursor += 1;
                let se = ShiftDischargeProofTrace::alloc(b, ns, w_log);
                let pt = verify_shift_discharge_trace(b, &mut ch, w_log, &sub_point, v, *sl, &se);
                let (_, npt, nval) = &np[np_cursor]; np_cursor += 1;
                out.push(Claim { slice: base + *col, point: pt, value: se.final_value.clone(), native_point: npt.clone(), native_value: *nval });
            }
            _ => unreachable!(),
        }
    }
    assert_eq!(np_cursor, np.len(), "source-leaf pending lockstep");

    // The leaf digest wires (C0/C1 at the digest slot) — returned for wiring.
    let d = chain.digest_slot();
    let dpt_lin: Vec<LinExpr> = (0..w_log).map(|bb| LinExpr::constant(if (d >> bb) & 1 == 1 { F128::ONE } else { F128::ZERO })).collect();
    let dpt: Vec<F128> = (0..w_log).map(|bb| if (d >> bb) & 1 == 1 { F128::ONE } else { F128::ZERO }).collect();
    let mut digest_wires: [LinExpr; 2] = [LinExpr::zero(), LinExpr::zero()];
    for lane in 0..2 {
        let value = LinExpr::from_wire(b.alloc_f128(cols.digest[lane]));
        out.push(Claim { slice: base + 2 + lane, point: dpt_lin.clone(), value: value.clone(), native_point: dpt.clone(), native_value: cols.digest[lane] });
        digest_wires[lane] = value;
    }
    let _ = slices;
    (out, digest_wires, cols.digest)
}

// ---------------------------------------------------------------------------
// Merkle path family (family B): entry == the source-leaf digest.
// ---------------------------------------------------------------------------

struct MkNative {
    bool_proof: ColumnRelationProof,
    sel_proof: ColumnRelationProof,
    walk_proof: DeepChainWalkProof,
    sub_proof: ColumnRelationProof,
    shifts: Vec<(usize, usize, ShiftDischargeProof)>,
    pending: Vec<(usize, Vec<F128>, F128)>,
}

fn run_merkle_native(family: &MerklePathFamily, cols: &MerklePathColumns, w_log: usize, domain: &[u8]) -> MkNative {
    use noid_ivc_core::deep_chain::schedule::merkle_booleanity_terms;
    let fixed = merkle_fixed_patterns(family, iv_flat());
    let refs = merkle_family_refs(0, 0);
    let committed: Vec<&[F128]> = vec![&cols.e[0], &cols.e[1], &cols.sib[0], &cols.sib[1], &cols.d, &cols.c[0], &cols.c[1], &cols.c[2], &cols.c[3]];
    let internal: Vec<&[F128]> = cols.s_out.iter().map(|c| c.as_slice()).collect();
    let mut ch_p = FsLaneChallenger::new(domain);
    let mut ch_v = FsLaneChallenger::new(domain);
    let mut pending = Vec::new();

    let bool_terms = merkle_booleanity_terms(&refs);
    let rho_b = ch_p.sample_f128_vec(w_log);
    let _ = ch_v.sample_f128_vec(w_log);
    let (bool_proof, _, _) = prove_column_relation(F128::ZERO, &rho_b, &bool_terms, &RelationColumns { committed: &committed, internal: &[], fixed: &fixed }, &mut ch_p);
    let bp = verify_column_relation(w_log, F128::ZERO, &rho_b, &bool_terms, &fixed, &bool_proof, &mut ch_v).unwrap();
    pending.push((refs.d, bp, bool_proof.final_values[0]));

    let beta = ch_p.sample_f128();
    assert_eq!(beta, ch_v.sample_f128());
    let sel_terms = carry_selection_terms(&refs.c, beta);
    let rho = ch_p.sample_f128_vec(w_log);
    let _ = ch_v.sample_f128_vec(w_log);
    let (sel_proof, _, _) = prove_column_relation(F128::ZERO, &rho, &sel_terms, &RelationColumns { committed: &committed, internal: &internal, fixed: &fixed }, &mut ch_p);
    let sel_point = verify_column_relation(w_log, F128::ZERO, &rho, &sel_terms, &fixed, &sel_proof, &mut ch_v).unwrap();
    let mut gv = [F128::ZERO; STATE_SIZE];
    for (r, v) in claimed_refs(&sel_terms).iter().zip(sel_proof.final_values.iter()) {
        match r { ColRef::Committed(c) => pending.push((*c, sel_point.clone(), *v)), ColRef::Internal(j) => gv[*j] = *v, _ => unreachable!() }
    }
    let groups = vec![LaneClaimGroup { point: sel_point, values: gv }];
    let (walk_proof, _) = prove_deep_chain_walk(&cols.s0, &groups, &mut ch_p);
    let terminal = verify_deep_chain_walk(w_log, &groups, &walk_proof, &mut ch_v).unwrap();

    let alpha = ch_p.sample_f128();
    assert_eq!(alpha, ch_v.sample_f128());
    let sub_terms = merkle_substitution_terms(&refs, alpha);
    let mut target = F128::ZERO;
    let mut p = F128::ONE;
    for e in 0..STATE_SIZE { p = p * alpha; target += p * terminal.values[e]; }
    let (sub_proof, _, _) = prove_column_relation(target, &terminal.point, &sub_terms, &RelationColumns { committed: &committed, internal: &[], fixed: &fixed }, &mut ch_p);
    let sub_point = verify_column_relation(w_log, target, &terminal.point, &sub_terms, &fixed, &sub_proof, &mut ch_v).unwrap();
    let mut shifts = Vec::new();
    for (r, v) in claimed_refs(&sub_terms).iter().zip(sub_proof.final_values.iter()) {
        match r {
            ColRef::Committed(c) => pending.push((*c, sub_point.clone(), *v)),
            ColRef::CommittedShift(c) => { let (pr, _) = prove_shift_discharge(committed[*c], &sub_point, *v, &mut ch_p); let pt = verify_shift_discharge(w_log, &sub_point, *v, &pr, &mut ch_v).unwrap(); pending.push((*c, pt, pr.final_value)); shifts.push((0, *c, pr)); }
            ColRef::CommittedShift2(c) => { let (pr, _) = prove_shift_discharge_pow2(committed[*c], &sub_point, *v, 1, &mut ch_p); let pt = verify_shift_discharge_pow2(w_log, &sub_point, *v, 1, &pr, &mut ch_v).unwrap(); pending.push((*c, pt, pr.final_value)); shifts.push((1, *c, pr)); }
            _ => unreachable!(),
        }
    }
    assert_eq!(ch_p.sample_f128(), ch_v.sample_f128());
    MkNative { bool_proof, sel_proof, walk_proof, sub_proof, shifts, pending }
}

fn mk_sub_terms_trace(b: &mut FieldR1csBuilder, refs: &MerkleFamilyRefs, alpha: &LinExpr) -> (Vec<RelationTermTrace>, Vec<LinExpr>) {
    let mds = flat_mds(true);
    let mut ap = Vec::with_capacity(STATE_SIZE);
    let mut acc = LinExpr::constant(F128::ONE);
    for _ in 0..STATE_SIZE { acc = mul(b, &acc, alpha); ap.push(acc.clone()); }
    let m: Vec<LinExpr> = (0..STATE_SIZE).map(|j| { let mut a = LinExpr::zero(); for e in 0..STATE_SIZE { a = a.add(&ap[e].scale(mds[e][j])); } a }).collect();
    let mut terms = Vec::new();
    for i in 0..2 {
        let c_sh = ColRef::CommittedShift(refs.c[i]); let c_sh2 = ColRef::CommittedShift2(refs.c[i]);
        let sib = ColRef::Committed(refs.sib[i]); let sib_sh = ColRef::CommittedShift(refs.sib[i]);
        let e_col = ColRef::Committed(refs.e[i]); let e_sh = ColRef::CommittedShift(refs.e[i]);
        let d_col = ColRef::Committed(refs.d); let d_sh = ColRef::CommittedShift(refs.d);
        for factors in [vec![c_sh], vec![ColRef::Fixed(refs.evenstart), c_sh], vec![ColRef::Fixed(refs.evenns), d_col, c_sh], vec![ColRef::Fixed(refs.even), d_col, sib], vec![ColRef::Fixed(refs.evenstart), e_col], vec![ColRef::Fixed(refs.evenstart), d_col, e_col], vec![ColRef::Fixed(refs.odd), sib_sh], vec![ColRef::Fixed(refs.odd), d_sh, sib_sh], vec![ColRef::Fixed(refs.oddns), d_sh, c_sh2], vec![ColRef::Fixed(refs.oddstart), d_sh, e_sh]] {
            terms.push(RelationTermTrace { coeff: m[i].clone(), factors });
        }
    }
    for j in 2..STATE_SIZE {
        let c_sh = ColRef::CommittedShift(refs.c[j]);
        terms.push(RelationTermTrace { coeff: m[j].clone(), factors: vec![c_sh] });
        terms.push(RelationTermTrace { coeff: m[j].clone(), factors: vec![ColRef::Fixed(refs.even), c_sh] });
        terms.push(RelationTermTrace { coeff: m[j].clone(), factors: vec![ColRef::Fixed(refs.iv[j - 2])] });
    }
    (terms, ap)
}

#[allow(clippy::too_many_arguments)]
fn discharge_merkle(
    b: &mut FieldR1csBuilder,
    family: &MerklePathFamily,
    _cols: &MerklePathColumns,
    w_log: usize,
    domain: &[u8],
    native: &MkNative,
    base: usize,
    entry_slot0_point: &[LinExpr],
    entry_slot0_native: &[F128],
    entry_wires: &[LinExpr; 2],
    entry_values: &[F128; 2],
) -> Vec<Claim> {
    use noid_ivc_core::deep_chain::schedule::merkle_booleanity_terms;
    let fixed = merkle_fixed_patterns(family, iv_flat());
    let refs = merkle_family_refs(0, 0);
    let mut ch = FsChannelTrace::new(b, domain);
    let mut out: Vec<Claim> = Vec::new();
    let np = &native.pending;
    let mut np_cursor = 0usize;
    let zero = LinExpr::zero();

    let bool_terms = merkle_booleanity_terms(&refs);
    let rho_b = ch.sample_f128_vec(b, w_log);
    let bool_e = ColumnRelationProofTrace::alloc(b, &native.bool_proof, w_log, 1);
    let const_bool: Vec<RelationTermTrace> = bool_terms.iter().map(|t| RelationTermTrace { coeff: LinExpr::constant(t.coeff), factors: t.factors.clone() }).collect();
    let bpt = verify_column_relation_trace(b, &mut ch, w_log, &zero, &rho_b, &const_bool, &fixed, &bool_e);
    let (_, npt, nval) = &np[np_cursor]; np_cursor += 1;
    out.push(Claim { slice: base + refs.d, point: bpt, value: bool_e.final_values[0].clone(), native_point: npt.clone(), native_value: *nval });

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
            ColRef::Committed(c) => { let (_, npt, nval) = &np[np_cursor]; np_cursor += 1; out.push(Claim { slice: base + *c, point: sel_point.clone(), value: v.clone(), native_point: npt.clone(), native_value: *nval }); }
            ColRef::Internal(j) => gv[*j] = v.clone(),
            _ => unreachable!(),
        }
    }
    let groups_e = vec![LaneClaimGroupTrace { point: sel_point, values: gv }];
    let walk_e = DeepChainWalkProofTrace::alloc(b, &native.walk_proof, w_log);
    let terminal = verify_deep_chain_walk_trace(b, &mut ch, w_log, &groups_e, &walk_e);

    let alpha = ch.sample_f128(b);
    let sub_native = merkle_substitution_terms(&refs, F128::ONE);
    let (sub_e_terms, ap) = mk_sub_terms_trace(b, &refs, &alpha);
    let mut target = LinExpr::zero();
    for e in 0..STATE_SIZE { target = target.add(&mul(b, &ap[e], &terminal.values[e])); }
    let sub_e = ColumnRelationProofTrace::alloc(b, &native.sub_proof, w_log, claimed_refs(&sub_native).len());
    let sub_point = verify_column_relation_trace(b, &mut ch, w_log, &target, &terminal.point, &sub_e_terms, &fixed, &sub_e);
    let mut shift_cursor = 0usize;
    for (r, v) in claimed_refs(&sub_native).iter().zip(sub_e.final_values.iter()) {
        match r {
            ColRef::Committed(c) => { let (_, npt, nval) = &np[np_cursor]; np_cursor += 1; out.push(Claim { slice: base + *c, point: sub_point.clone(), value: v.clone(), native_point: npt.clone(), native_value: *nval }); }
            ColRef::CommittedShift(_) | ColRef::CommittedShift2(_) => {
                let (sl, col, ns) = &native.shifts[shift_cursor]; shift_cursor += 1;
                let se = ShiftDischargeProofTrace::alloc(b, ns, w_log);
                let pt = verify_shift_discharge_trace(b, &mut ch, w_log, &sub_point, v, *sl, &se);
                let (_, npt, nval) = &np[np_cursor]; np_cursor += 1;
                out.push(Claim { slice: base + *col, point: pt, value: se.final_value.clone(), native_point: npt.clone(), native_value: *nval });
            }
            _ => unreachable!(),
        }
    }
    assert_eq!(np_cursor, np.len(), "merkle pending lockstep");

    // The inter-family wire: E0/E1 at the entry slot == the source-leaf digest.
    for lane in 0..2 {
        out.push(Claim {
            slice: base + lane, // E0, E1
            point: entry_slot0_point.to_vec(),
            value: entry_wires[lane].clone(),
            native_point: entry_slot0_native.to_vec(),
            native_value: entry_values[lane],
        });
    }
    out
}

/// SB6 composed in-trace: source-leaf digest wired into the Merkle path entry,
/// both discharged through ONE outer PCS. Honest verifies; flipping a lane in
/// either family breaks its opening claim.
#[test]
fn region_sb6_slot_end_to_end() {
    let mut rng = Rng(0x5B6_C0DE);

    // Family A: source-leaf → digest.
    let n_cols = 3usize;
    let chain = SourceLeafChain { n_cols };
    let a_wlog = chain.stride().trailing_zeros() as usize;
    let symbols: Vec<F128> = (0..n_cols * 2).map(|_| rng.f128()).collect();
    let a_cols = build_source_leaf_columns(&chain, 6, 5, &symbols, a_wlog);
    let a_native = run_source_leaf_native(&chain, &a_cols, a_wlog, b"sb6-source-leaf");

    // Family B: Merkle path with entry == the source-leaf digest.
    let depth = 3usize;
    let family = MerklePathFamily { depth, n_paths: 1 };
    let b_wlog = family.n_slots().next_power_of_two().trailing_zeros() as usize;
    let path = MerklePathWitness {
        entry: a_cols.digest,
        siblings: (0..depth).map(|_| [rng.f128(), rng.f128()]).collect(),
        directions: (0..depth).map(|_| rng.next_u64() & 1 == 1).collect(),
    };
    let b_cols = build_merkle_path_columns(&family, iv_flat(), std::slice::from_ref(&path), b_wlog);
    let b_native = run_merkle_native(&family, &b_cols, b_wlog, b"sb6-merkle");

    // ---- Trace: both families as slices in ONE builder.
    let mut b = FieldR1csBuilder::new();
    let mut slices = Vec::new();
    for col in [&a_cols.in_[0], &a_cols.in_[1], &a_cols.c[0], &a_cols.c[1], &a_cols.c[2], &a_cols.c[3]] {
        slices.push(alloc_column_slice(&mut b, col, a_wlog).0);
    }
    let a_base = 0usize;
    for col in [&b_cols.e[0], &b_cols.e[1], &b_cols.sib[0], &b_cols.sib[1], &b_cols.d, &b_cols.c[0], &b_cols.c[1], &b_cols.c[2], &b_cols.c[3]] {
        slices.push(alloc_column_slice(&mut b, col, b_wlog).0);
    }
    let b_base = 6usize;

    let (mut claims, digest_wires, digest_vals) =
        discharge_source_leaf(&mut b, &chain, &a_cols, a_wlog, b"sb6-source-leaf", &a_native, &slices, a_base);

    // The Merkle entry (E0/E1 at slot 0) point.
    let entry_pt_lin: Vec<LinExpr> = vec![LinExpr::zero(); b_wlog]; // slot 0 = all-zero boolean point
    let entry_pt: Vec<F128> = vec![F128::ZERO; b_wlog];
    let mk_claims = discharge_merkle(
        &mut b, &family, &b_cols, b_wlog, b"sb6-merkle", &b_native, b_base,
        &entry_pt_lin, &entry_pt, &digest_wires, &digest_vals,
    );
    claims.extend(mk_claims);

    // ---- ONE public-IO discharge over all claims. Every claim's point-arity
    // must match its slice's log2_len; source-leaf (a_wlog) and merkle (b_wlog)
    // may differ, so pad the IO per claim to the max arity.
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
        claims: claims.iter().enumerate().map(|(ci, c)| IoClaimSpec {
            slice: slices[c.slice],
            point: ci * lanes_per..ci * lanes_per + c.point.len(),
            value: ci * lanes_per + max_arity,
        }).collect(),
    };

    let (r1cs, z) = b.build();
    assert!(r1cs.satisfies(&z), "honest SB6 trace unsatisfiable");
    let params = PcsParams { m: r1cs.m + pcs::LOG_PACKING, log_inv_rate: 2, log_batch_size: 2, profile: Default::default() };
    let mut chp = FsLaneChallenger::new(b"region-sb6-slot");
    let (proof, commitment, _) = noid_ivc_prover::field_prover::prove_field_with_public_io(&r1cs, &z, &params, &spec, &io_values, &mut chp);
    let mut chv = FsLaneChallenger::new(b"region-sb6-slot");
    noid_ivc_core::verifier::verify_field_with_public_io(&r1cs, &commitment, &proof, &spec, &io_values, &mut chv)
        .expect("SB6 composition verifies");
    eprintln!("[region-sb6-slot] rows = {} (m = {}), families = 2, claims = {}", z.len(), r1cs.m, spec.claims.len());

    // Negative: flip the source-leaf digest column (family A C0) -> its digest
    // opening claim breaks (and the wire to the Merkle entry no longer holds).
    let flip = |slice_idx: usize, off: usize| {
        let mut bad = z.clone();
        bad[slices[slice_idx].start() + off] += F128::ONE;
        assert!(r1cs.satisfies(&bad), "columns are free wires");
        let mut chp = FsLaneChallenger::new(b"region-sb6-slot");
        let (bp, bc, _) = noid_ivc_prover::field_prover::prove_field_with_public_io(&r1cs, &bad, &params, &spec, &io_values, &mut chp);
        let mut chv = FsLaneChallenger::new(b"region-sb6-slot");
        noid_ivc_core::verifier::verify_field_with_public_io(&r1cs, &bc, &bp, &spec, &io_values, &mut chv).is_err()
    };
    assert!(flip(2, chain.digest_slot()), "flipped source-leaf digest accepted");
    assert!(flip(6 + 5, 3), "flipped merkle C0 lane accepted"); // family B C0
}
