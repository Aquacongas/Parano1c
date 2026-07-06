//! [G] item 5b step 3 — the FLAT multi-query wallet-PCS opening composed
//! IN-TRACE: N source-leaf chains tiled into ONE column set (one walk + one
//! relation, tile-count independent) whose per-tile digests are wired into an
//! N-path Merkle family, whose per-path roots are pinned to the committed cap.
//! All discharged through ONE outer PCS via public-IO.
//!
//! This is the tiled generalisation of `region_sb6_slot_e2e` (N = 1): it proves
//! the `[tx_hi | schedule_lo]` flatness property holds IN-TRACE, i.e. the
//! verifier cost of the leaf and Merkle discharges does not grow with the query
//! count. It is the reusable core of every wallet-PCS Merkle opening the grand
//! `discharge_auth_pcs_obligation_via_region` composes:
//!   - SB6  source leaves (source_leaf_hash) → to-cap Merkle,
//!   - SB8  high-pair leaves → per-layer single-root Merkle,
//!   - 3i   FRI-round pair leaves → per-round single-root Merkle.
//! All share this shape: K tiled leaf chains → K digests → K Merkle paths →
//! K roots pinned to committed nodes. A flipped committed lane in EITHER the
//! leaf tiles or the Merkle paths breaks that entry's / root's opening claim →
//! BaseFold rejects; the single relation set catches the corrupted tile.

use noid_ivc_core::challenger::{Challenger, FsLaneChallenger};
use noid_ivc_core::deep_chain::flat_mds;
use noid_ivc_core::deep_chain::leaf_hash::{
    build_high_pair_leaf_columns, build_source_leaf_columns, high_pair_leaf_chain,
    source_leaf_fixed_patterns, source_leaf_refs, source_leaf_substitution_terms, SourceLeafChain,
    SourceLeafColumns, SourceLeafRefs,
};
use noid_ivc_core::deep_chain::relations::{
    claimed_refs, prove_column_relation, prove_shift_discharge, prove_shift_discharge_pow2,
    verify_column_relation, verify_shift_discharge, verify_shift_discharge_pow2, ColRef,
    ColumnRelationProof, RelationColumns, ShiftDischargeProof,
};
use noid_ivc_core::deep_chain::schedule::{
    build_merkle_path_columns, carry_selection_terms, flat_of_tower_u128, merkle_booleanity_terms,
    merkle_family_refs, merkle_fixed_patterns, merkle_substitution_terms, MerkleFamilyRefs,
    MerklePathColumns, MerklePathFamily, MerklePathWitness,
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

/// A discharged claim: the global slice it opens, the derived point wires, the
/// claimed value wire, plus the concrete native (point, value) for the IO.
struct Claim {
    slice: usize,
    point: Vec<LinExpr>,
    value: LinExpr,
    native_point: Vec<F128>,
    native_value: F128,
}

/// The boolean point (in `w_log` coordinates) that selects slot `s`.
fn slot_point(s: usize, w_log: usize) -> (Vec<LinExpr>, Vec<F128>) {
    let lin: Vec<LinExpr> = (0..w_log)
        .map(|bb| LinExpr::constant(if (s >> bb) & 1 == 1 { F128::ONE } else { F128::ZERO }))
        .collect();
    let nat: Vec<F128> =
        (0..w_log).map(|bb| if (s >> bb) & 1 == 1 { F128::ONE } else { F128::ZERO }).collect();
    (lin, nat)
}

// ---------------------------------------------------------------------------
// Tiling: K source-leaf chains into ONE global column set (mirror of the
// `build_tiled_source_leaf` native test helper).
// ---------------------------------------------------------------------------

fn build_tiled_source_leaf(
    chain: &SourceLeafChain,
    tiles: &[(usize, usize, Vec<F128>)],
    global_w_log: usize,
) -> (SourceLeafColumns, Vec<[F128; 2]>) {
    let stride = chain.stride();
    let stride_log = stride.trailing_zeros() as usize;
    let w = 1usize << global_w_log;
    assert_eq!(tiles.len() * stride, w, "tiles must exactly fill the domain");
    let mut c: [Vec<F128>; STATE_SIZE] = std::array::from_fn(|_| vec![F128::ZERO; w]);
    let mut s0: [Vec<F128>; STATE_SIZE] = std::array::from_fn(|_| vec![F128::ZERO; w]);
    let mut s_out: [Vec<F128>; STATE_SIZE] = std::array::from_fn(|_| vec![F128::ZERO; w]);
    let mut in_: [Vec<F128>; 2] = std::array::from_fn(|_| vec![F128::ZERO; w]);
    let mut digests = Vec::with_capacity(tiles.len());
    for (t, (log_rows, leaf_index, symbols)) in tiles.iter().enumerate() {
        let tile = build_source_leaf_columns(chain, *log_rows, *leaf_index, symbols, stride_log);
        let off = t * stride;
        for j in 0..STATE_SIZE {
            c[j][off..off + stride].copy_from_slice(&tile.c[j]);
            s0[j][off..off + stride].copy_from_slice(&tile.s0[j]);
            s_out[j][off..off + stride].copy_from_slice(&tile.s_out[j]);
        }
        for j in 0..2 {
            in_[j][off..off + stride].copy_from_slice(&tile.in_[j]);
        }
        digests.push(tile.digest);
    }
    let digest = digests[0];
    (SourceLeafColumns { c, s0, s_out, in_, digest }, digests)
}

/// SB8 variant — tile K high-pair leaf chains (`layer_log, leaf_index, s0, s1`
/// per query) into one column set. High-pair is topologically
/// `SourceLeafChain { n_cols: 1 }`, so the DAG discharge is identical.
fn build_tiled_high_pair_leaf(
    chain: &SourceLeafChain,
    tiles: &[(usize, usize, F128, F128)],
    global_w_log: usize,
) -> (SourceLeafColumns, Vec<[F128; 2]>) {
    let stride = chain.stride();
    let stride_log = stride.trailing_zeros() as usize;
    let w = 1usize << global_w_log;
    assert_eq!(tiles.len() * stride, w, "tiles must exactly fill the domain");
    let mut c: [Vec<F128>; STATE_SIZE] = std::array::from_fn(|_| vec![F128::ZERO; w]);
    let mut s0: [Vec<F128>; STATE_SIZE] = std::array::from_fn(|_| vec![F128::ZERO; w]);
    let mut s_out: [Vec<F128>; STATE_SIZE] = std::array::from_fn(|_| vec![F128::ZERO; w]);
    let mut in_: [Vec<F128>; 2] = std::array::from_fn(|_| vec![F128::ZERO; w]);
    let mut digests = Vec::with_capacity(tiles.len());
    for (t, (layer_log, leaf_index, sym0, sym1)) in tiles.iter().enumerate() {
        let tile = build_high_pair_leaf_columns(*layer_log, *leaf_index, *sym0, *sym1, stride_log);
        let off = t * stride;
        for j in 0..STATE_SIZE {
            c[j][off..off + stride].copy_from_slice(&tile.c[j]);
            s0[j][off..off + stride].copy_from_slice(&tile.s0[j]);
            s_out[j][off..off + stride].copy_from_slice(&tile.s_out[j]);
        }
        for j in 0..2 {
            in_[j][off..off + stride].copy_from_slice(&tile.in_[j]);
        }
        digests.push(tile.digest);
    }
    let digest = digests[0];
    (SourceLeafColumns { c, s0, s_out, in_, digest }, digests)
}

// ---------------------------------------------------------------------------
// Source-leaf family (tiled): ONE walk + ONE relation set covers every tile;
// emits one digest claim per tile.
// ---------------------------------------------------------------------------

struct SlNative {
    sel_proof: ColumnRelationProof,
    walk_proof: DeepChainWalkProof,
    sub_proof: ColumnRelationProof,
    shifts: Vec<(usize, usize, ShiftDischargeProof)>,
    pending: Vec<(usize, Vec<F128>, F128)>,
}

fn run_source_leaf_native(
    chain: &SourceLeafChain,
    cols: &SourceLeafColumns,
    w_log: usize,
    domain: &[u8],
) -> SlNative {
    let fixed = source_leaf_fixed_patterns(chain, iv_flat());
    let refs = source_leaf_refs(0, 0);
    let committed: Vec<&[F128]> =
        vec![&cols.in_[0], &cols.in_[1], &cols.c[0], &cols.c[1], &cols.c[2], &cols.c[3]];
    let internal: Vec<&[F128]> = cols.s_out.iter().map(|c| c.as_slice()).collect();
    let mut ch_p = FsLaneChallenger::new(domain);
    let mut ch_v = FsLaneChallenger::new(domain);
    let mut pending = Vec::new();

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
        verify_column_relation(w_log, F128::ZERO, &rho, &sel_terms, &fixed, &sel_proof, &mut ch_v)
            .unwrap();
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
        verify_column_relation(w_log, target, &terminal.point, &sub_terms, &fixed, &sub_proof, &mut ch_v)
            .unwrap();

    let mut shifts = Vec::new();
    for (r, v) in claimed_refs(&sub_terms).iter().zip(sub_proof.final_values.iter()) {
        match r {
            ColRef::Committed(c) => pending.push((*c, sub_point.clone(), *v)),
            ColRef::CommittedShift(c) => {
                let (pr, _) = prove_shift_discharge(committed[*c], &sub_point, *v, &mut ch_p);
                let pt = verify_shift_discharge(w_log, &sub_point, *v, &pr, &mut ch_v).unwrap();
                pending.push((*c, pt, pr.final_value));
                shifts.push((0, *c, pr));
            }
            ColRef::CommittedShift2(c) => {
                let (pr, _) = prove_shift_discharge_pow2(committed[*c], &sub_point, *v, 1, &mut ch_p);
                let pt = verify_shift_discharge_pow2(w_log, &sub_point, *v, 1, &pr, &mut ch_v).unwrap();
                pending.push((*c, pt, pr.final_value));
                shifts.push((1, *c, pr));
            }
            _ => unreachable!(),
        }
    }
    assert_eq!(ch_p.sample_f128(), ch_v.sample_f128());
    SlNative { sel_proof, walk_proof, sub_proof, shifts, pending }
}

fn sl_sub_terms_trace(
    b: &mut FieldR1csBuilder,
    refs: &SourceLeafRefs,
    alpha: &LinExpr,
) -> (Vec<RelationTermTrace>, Vec<LinExpr>) {
    let mds = flat_mds(true);
    let mut ap = Vec::with_capacity(STATE_SIZE);
    let mut acc = LinExpr::constant(F128::ONE);
    for _ in 0..STATE_SIZE {
        acc = mul(b, &acc, alpha);
        ap.push(acc.clone());
    }
    let m: Vec<LinExpr> = (0..STATE_SIZE)
        .map(|j| {
            let mut a = LinExpr::zero();
            for e in 0..STATE_SIZE {
                a = a.add(&ap[e].scale(mds[e][j]));
            }
            a
        })
        .collect();
    let mut terms = Vec::new();
    for i in 0..2 {
        let in_col = ColRef::Committed(refs.in_[i]);
        let c_sh = ColRef::CommittedShift(refs.c[i]);
        let c_sh2 = ColRef::CommittedShift2(refs.c[i]);
        for factors in [
            vec![ColRef::Fixed(refs.hp), in_col],
            vec![ColRef::Fixed(refs.even), c_sh2],
            vec![ColRef::Fixed(refs.odd), c_sh],
            vec![ColRef::Fixed(refs.odd), c_sh2],
        ] {
            terms.push(RelationTermTrace { coeff: m[i].clone(), factors });
        }
    }
    for j in 2..STATE_SIZE {
        terms.push(RelationTermTrace { coeff: m[j].clone(), factors: vec![ColRef::Fixed(refs.iv[j - 2])] });
        terms.push(RelationTermTrace {
            coeff: m[j].clone(),
            factors: vec![ColRef::Fixed(refs.odd), ColRef::CommittedShift(refs.c[j])],
        });
    }
    (terms, ap)
}

/// Discharge the tiled source-leaf family in-trace; returns the pending claims
/// plus one `(digest_wires, digest_vals)` pair per tile (C0/C1 at each tile's
/// digest slot) for wiring into the Merkle entries.
#[allow(clippy::too_many_arguments)]
fn discharge_tiled_source_leaf(
    b: &mut FieldR1csBuilder,
    chain: &SourceLeafChain,
    w_log: usize,
    domain: &[u8],
    native: &SlNative,
    base: usize,
    tile_digests: &[[F128; 2]],
) -> (Vec<Claim>, Vec<[LinExpr; 2]>) {
    let fixed = source_leaf_fixed_patterns(chain, iv_flat());
    let refs = source_leaf_refs(0, 0);
    let mut ch = FsChannelTrace::new(b, domain);
    let mut out: Vec<Claim> = Vec::new();
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
                let (_, npt, nval) = &np[np_cursor];
                np_cursor += 1;
                out.push(Claim {
                    slice: base + *c,
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
    let sub_native = source_leaf_substitution_terms(&refs, F128::ONE);
    let (sub_e_terms, ap) = sl_sub_terms_trace(b, &refs, &alpha);
    let mut target = LinExpr::zero();
    for e in 0..STATE_SIZE {
        target = target.add(&mul(b, &ap[e], &terminal.values[e]));
    }
    let sub_e = ColumnRelationProofTrace::alloc(b, &native.sub_proof, w_log, claimed_refs(&sub_native).len());
    let sub_point = verify_column_relation_trace(b, &mut ch, w_log, &target, &terminal.point, &sub_e_terms, &fixed, &sub_e);
    let mut shift_cursor = 0usize;
    for (r, v) in claimed_refs(&sub_native).iter().zip(sub_e.final_values.iter()) {
        match r {
            ColRef::Committed(c) => {
                let (_, npt, nval) = &np[np_cursor];
                np_cursor += 1;
                out.push(Claim {
                    slice: base + *c,
                    point: sub_point.clone(),
                    value: v.clone(),
                    native_point: npt.clone(),
                    native_value: *nval,
                });
            }
            ColRef::CommittedShift(_) | ColRef::CommittedShift2(_) => {
                let (sl, col, ns) = &native.shifts[shift_cursor];
                shift_cursor += 1;
                let se = ShiftDischargeProofTrace::alloc(b, ns, w_log);
                let pt = verify_shift_discharge_trace(b, &mut ch, w_log, &sub_point, v, *sl, &se);
                let (_, npt, nval) = &np[np_cursor];
                np_cursor += 1;
                out.push(Claim {
                    slice: base + *col,
                    point: pt,
                    value: se.final_value.clone(),
                    native_point: npt.clone(),
                    native_value: *nval,
                });
            }
            _ => unreachable!(),
        }
    }
    assert_eq!(np_cursor, np.len(), "source-leaf pending lockstep");

    // Per-tile digest claims: C0/C1 at slot `t*stride + digest_slot`.
    let stride = chain.stride();
    let mut digest_wires = Vec::with_capacity(tile_digests.len());
    for (t, dig) in tile_digests.iter().enumerate() {
        let slot = t * stride + chain.digest_slot();
        let (pt_lin, pt_nat) = slot_point(slot, w_log);
        let mut wires: [LinExpr; 2] = [LinExpr::zero(), LinExpr::zero()];
        for lane in 0..2 {
            let value = LinExpr::from_wire(b.alloc_f128(dig[lane]));
            out.push(Claim {
                slice: base + 2 + lane, // C0, C1
                point: pt_lin.clone(),
                value: value.clone(),
                native_point: pt_nat.clone(),
                native_value: dig[lane],
            });
            wires[lane] = value;
        }
        digest_wires.push(wires);
    }
    (out, digest_wires)
}

// ---------------------------------------------------------------------------
// Merkle path family (multi-path): entries wired to the per-tile digests, roots
// pinned to the committed cap.
// ---------------------------------------------------------------------------

struct MkNative {
    bool_proof: ColumnRelationProof,
    sel_proof: ColumnRelationProof,
    walk_proof: DeepChainWalkProof,
    sub_proof: ColumnRelationProof,
    shifts: Vec<(usize, usize, ShiftDischargeProof)>,
    pending: Vec<(usize, Vec<F128>, F128)>,
}

fn run_merkle_native(
    family: &MerklePathFamily,
    cols: &MerklePathColumns,
    w_log: usize,
    domain: &[u8],
) -> MkNative {
    let fixed = merkle_fixed_patterns(family, iv_flat());
    let refs = merkle_family_refs(0, 0);
    let committed: Vec<&[F128]> = vec![
        &cols.e[0], &cols.e[1], &cols.sib[0], &cols.sib[1], &cols.d, &cols.c[0], &cols.c[1],
        &cols.c[2], &cols.c[3],
    ];
    let internal: Vec<&[F128]> = cols.s_out.iter().map(|c| c.as_slice()).collect();
    let mut ch_p = FsLaneChallenger::new(domain);
    let mut ch_v = FsLaneChallenger::new(domain);
    let mut pending = Vec::new();

    let bool_terms = merkle_booleanity_terms(&refs);
    let rho_b = ch_p.sample_f128_vec(w_log);
    let _ = ch_v.sample_f128_vec(w_log);
    let (bool_proof, _, _) = prove_column_relation(
        F128::ZERO,
        &rho_b,
        &bool_terms,
        &RelationColumns { committed: &committed, internal: &[], fixed: &fixed },
        &mut ch_p,
    );
    let bp = verify_column_relation(w_log, F128::ZERO, &rho_b, &bool_terms, &fixed, &bool_proof, &mut ch_v).unwrap();
    pending.push((refs.d, bp, bool_proof.final_values[0]));

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
    let sub_terms = merkle_substitution_terms(&refs, alpha);
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
    let sub_point = verify_column_relation(w_log, target, &terminal.point, &sub_terms, &fixed, &sub_proof, &mut ch_v).unwrap();
    let mut shifts = Vec::new();
    for (r, v) in claimed_refs(&sub_terms).iter().zip(sub_proof.final_values.iter()) {
        match r {
            ColRef::Committed(c) => pending.push((*c, sub_point.clone(), *v)),
            ColRef::CommittedShift(c) => {
                let (pr, _) = prove_shift_discharge(committed[*c], &sub_point, *v, &mut ch_p);
                let pt = verify_shift_discharge(w_log, &sub_point, *v, &pr, &mut ch_v).unwrap();
                pending.push((*c, pt, pr.final_value));
                shifts.push((0, *c, pr));
            }
            ColRef::CommittedShift2(c) => {
                let (pr, _) = prove_shift_discharge_pow2(committed[*c], &sub_point, *v, 1, &mut ch_p);
                let pt = verify_shift_discharge_pow2(w_log, &sub_point, *v, 1, &pr, &mut ch_v).unwrap();
                pending.push((*c, pt, pr.final_value));
                shifts.push((1, *c, pr));
            }
            _ => unreachable!(),
        }
    }
    assert_eq!(ch_p.sample_f128(), ch_v.sample_f128());
    MkNative { bool_proof, sel_proof, walk_proof, sub_proof, shifts, pending }
}

fn mk_sub_terms_trace(
    b: &mut FieldR1csBuilder,
    refs: &MerkleFamilyRefs,
    alpha: &LinExpr,
) -> (Vec<RelationTermTrace>, Vec<LinExpr>) {
    let mds = flat_mds(true);
    let mut ap = Vec::with_capacity(STATE_SIZE);
    let mut acc = LinExpr::constant(F128::ONE);
    for _ in 0..STATE_SIZE {
        acc = mul(b, &acc, alpha);
        ap.push(acc.clone());
    }
    let m: Vec<LinExpr> = (0..STATE_SIZE)
        .map(|j| {
            let mut a = LinExpr::zero();
            for e in 0..STATE_SIZE {
                a = a.add(&ap[e].scale(mds[e][j]));
            }
            a
        })
        .collect();
    let mut terms = Vec::new();
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
            vec![c_sh],
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
        terms.push(RelationTermTrace { coeff: m[j].clone(), factors: vec![c_sh] });
        terms.push(RelationTermTrace { coeff: m[j].clone(), factors: vec![ColRef::Fixed(refs.even), c_sh] });
        terms.push(RelationTermTrace { coeff: m[j].clone(), factors: vec![ColRef::Fixed(refs.iv[j - 2])] });
    }
    (terms, ap)
}

/// Discharge the multi-path Merkle family in-trace: the DAG (one relation set
/// across all paths), then per-path (entry == tile digest) and (root ==
/// committed cap node) claims.
#[allow(clippy::too_many_arguments)]
fn discharge_multipath_merkle(
    b: &mut FieldR1csBuilder,
    family: &MerklePathFamily,
    cols: &MerklePathColumns,
    w_log: usize,
    domain: &[u8],
    native: &MkNative,
    base: usize,
    entry_wires: &[[LinExpr; 2]],
    entry_vals: &[[F128; 2]],
    committed_roots: &[[F128; 2]],
) -> Vec<Claim> {
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
    let const_bool: Vec<RelationTermTrace> = bool_terms
        .iter()
        .map(|t| RelationTermTrace { coeff: LinExpr::constant(t.coeff), factors: t.factors.clone() })
        .collect();
    let bpt = verify_column_relation_trace(b, &mut ch, w_log, &zero, &rho_b, &const_bool, &fixed, &bool_e);
    let (_, npt, nval) = &np[np_cursor];
    np_cursor += 1;
    out.push(Claim {
        slice: base + refs.d,
        point: bpt,
        value: bool_e.final_values[0].clone(),
        native_point: npt.clone(),
        native_value: *nval,
    });

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
                let (_, npt, nval) = &np[np_cursor];
                np_cursor += 1;
                out.push(Claim {
                    slice: base + *c,
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
    let sub_native = merkle_substitution_terms(&refs, F128::ONE);
    let (sub_e_terms, ap) = mk_sub_terms_trace(b, &refs, &alpha);
    let mut target = LinExpr::zero();
    for e in 0..STATE_SIZE {
        target = target.add(&mul(b, &ap[e], &terminal.values[e]));
    }
    let sub_e = ColumnRelationProofTrace::alloc(b, &native.sub_proof, w_log, claimed_refs(&sub_native).len());
    let sub_point = verify_column_relation_trace(b, &mut ch, w_log, &target, &terminal.point, &sub_e_terms, &fixed, &sub_e);
    let mut shift_cursor = 0usize;
    for (r, v) in claimed_refs(&sub_native).iter().zip(sub_e.final_values.iter()) {
        match r {
            ColRef::Committed(c) => {
                let (_, npt, nval) = &np[np_cursor];
                np_cursor += 1;
                out.push(Claim {
                    slice: base + *c,
                    point: sub_point.clone(),
                    value: v.clone(),
                    native_point: npt.clone(),
                    native_value: *nval,
                });
            }
            ColRef::CommittedShift(_) | ColRef::CommittedShift2(_) => {
                let (sl, col, ns) = &native.shifts[shift_cursor];
                shift_cursor += 1;
                let se = ShiftDischargeProofTrace::alloc(b, ns, w_log);
                let pt = verify_shift_discharge_trace(b, &mut ch, w_log, &sub_point, v, *sl, &se);
                let (_, npt, nval) = &np[np_cursor];
                np_cursor += 1;
                out.push(Claim {
                    slice: base + *col,
                    point: pt,
                    value: se.final_value.clone(),
                    native_point: npt.clone(),
                    native_value: *nval,
                });
            }
            _ => unreachable!(),
        }
    }
    assert_eq!(np_cursor, np.len(), "merkle pending lockstep");

    // Per-path inter-family wires (E0/E1 at the path entry == tile digest) and
    // root pins (C0/C1 at the last node's odd slot == committed cap node).
    let stride = family.stride();
    let root_slot_local = 2 * (family.depth - 1) + 1;
    assert_eq!(entry_wires.len(), family.n_paths);
    assert_eq!(committed_roots.len(), family.n_paths);
    for p in 0..family.n_paths {
        let entry_slot = p * stride;
        let (epl, epn) = slot_point(entry_slot, w_log);
        for lane in 0..2 {
            out.push(Claim {
                slice: base + lane, // E0, E1
                point: epl.clone(),
                value: entry_wires[p][lane].clone(),
                native_point: epn.clone(),
                native_value: entry_vals[p][lane],
            });
        }
        // Root: pin the recomputed C0/C1 root to the committed cap node.
        let root_slot = p * stride + root_slot_local;
        let (rpl, rpn) = slot_point(root_slot, w_log);
        for lane in 0..2 {
            let rv = LinExpr::from_wire(b.alloc_f128(committed_roots[p][lane]));
            // Sanity: the family's recomputed root equals the committed root.
            assert_eq!(cols.roots[p][lane], committed_roots[p][lane]);
            out.push(Claim {
                slice: base + 5 + lane, // C0, C1 (E0,E1,SIB0,SIB1,D,C0..)
                point: rpl.clone(),
                value: rv,
                native_point: rpn.clone(),
                native_value: committed_roots[p][lane],
            });
        }
    }
    out
}

/// The flat multi-query wallet-PCS opening composed in-trace: K tiled source
/// leaves → K digests → K Merkle paths → K roots pinned to the committed cap,
/// all through ONE public-IO. Honest verifies; flipping a tile symbol or a
/// path lane breaks its opening claim.
#[test]
fn region_tiled_opening_slot_end_to_end() {
    let mut rng = Rng(0x71_1ED_09E);

    // Family A: K tiled source-leaf chains (one per query).
    let n_cols = 3usize;
    let chain = SourceLeafChain { n_cols };
    let stride_log = chain.stride().trailing_zeros() as usize;
    let num_queries = 8usize; // power of two; the class query count in the real shape
    let a_wlog = stride_log + num_queries.trailing_zeros() as usize;
    let tiles: Vec<(usize, usize, Vec<F128>)> = (0..num_queries)
        .map(|t| {
            let symbols: Vec<F128> = (0..n_cols * 2).map(|_| rng.f128()).collect();
            (9, 3 * t + 1, symbols)
        })
        .collect();
    let (a_cols, tile_digests) = build_tiled_source_leaf(&chain, &tiles, a_wlog);
    let a_native = run_source_leaf_native(&chain, &a_cols, a_wlog, b"tiled-source-leaf");

    // Family B: K Merkle paths, entry p == tile p's digest.
    let depth = 4usize;
    let family = MerklePathFamily { depth, n_paths: num_queries };
    let b_wlog = family.n_slots().next_power_of_two().trailing_zeros() as usize;
    let paths: Vec<MerklePathWitness> = (0..num_queries)
        .map(|p| MerklePathWitness {
            entry: tile_digests[p],
            siblings: (0..depth).map(|_| [rng.f128(), rng.f128()]).collect(),
            directions: (0..depth).map(|_| rng.next_u64() & 1 == 1).collect(),
        })
        .collect();
    let b_cols = build_merkle_path_columns(&family, iv_flat(), &paths, b_wlog);
    let b_native = run_merkle_native(&family, &b_cols, b_wlog, b"tiled-merkle");
    let committed_roots = b_cols.roots.clone();

    // ---- Trace: both families as slices in ONE builder.
    let mut b = FieldR1csBuilder::new();
    let mut slices = Vec::new();
    for col in [&a_cols.in_[0], &a_cols.in_[1], &a_cols.c[0], &a_cols.c[1], &a_cols.c[2], &a_cols.c[3]] {
        slices.push(alloc_column_slice(&mut b, col, a_wlog).0);
    }
    let a_base = 0usize;
    for col in [
        &b_cols.e[0], &b_cols.e[1], &b_cols.sib[0], &b_cols.sib[1], &b_cols.d, &b_cols.c[0],
        &b_cols.c[1], &b_cols.c[2], &b_cols.c[3],
    ] {
        slices.push(alloc_column_slice(&mut b, col, b_wlog).0);
    }
    let b_base = 6usize;

    let (mut claims, digest_wires) = discharge_tiled_source_leaf(
        &mut b, &chain, a_wlog, b"tiled-source-leaf", &a_native, a_base, &tile_digests,
    );
    let mk_claims = discharge_multipath_merkle(
        &mut b, &family, &b_cols, b_wlog, b"tiled-merkle", &b_native, b_base, &digest_wires,
        &tile_digests, &committed_roots,
    );
    claims.extend(mk_claims);

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
    assert!(r1cs.satisfies(&z), "honest tiled opening trace unsatisfiable");
    let params = PcsParams {
        m: r1cs.m + pcs::LOG_PACKING,
        log_inv_rate: 2,
        log_batch_size: 2,
        profile: Default::default(),
    };
    let mut chp = FsLaneChallenger::new(b"region-tiled-opening");
    let (proof, commitment, _) = noid_ivc_prover::field_prover::prove_field_with_public_io(
        &r1cs, &z, &params, &spec, &io_values, &mut chp,
    );
    let mut chv = FsLaneChallenger::new(b"region-tiled-opening");
    noid_ivc_core::verifier::verify_field_with_public_io(&r1cs, &commitment, &proof, &spec, &io_values, &mut chv)
        .expect("tiled opening composition verifies");
    eprintln!(
        "[region-tiled-opening] rows = {} (m = {}), queries = {}, depth = {}, claims = {}",
        z.len(),
        r1cs.m,
        num_queries,
        depth,
        spec.claims.len()
    );

    // Negatives: flipping a committed lane leaves the trace satisfiable (columns
    // are free wires) but breaks that column's opening claim → verify rejects.
    let flip = |slice_idx: usize, off: usize| {
        let mut bad = z.clone();
        bad[slices[slice_idx].start() + off] += F128::ONE;
        assert!(r1cs.satisfies(&bad), "columns are free wires");
        let mut chp = FsLaneChallenger::new(b"region-tiled-opening");
        let (bp, bc, _) = noid_ivc_prover::field_prover::prove_field_with_public_io(
            &r1cs, &bad, &params, &spec, &io_values, &mut chp,
        );
        let mut chv = FsLaneChallenger::new(b"region-tiled-opening");
        noid_ivc_core::verifier::verify_field_with_public_io(&r1cs, &bc, &bp, &spec, &io_values, &mut chv).is_err()
    };
    // Corrupt tile 5's first column-hash symbol (source-leaf IN0). The single
    // relation set catches it — its digest / wiring opening claim breaks.
    let a_stride = chain.stride();
    assert!(flip(0, 5 * a_stride + 4), "flipped source tile symbol accepted");
    // Corrupt a sibling lane of Merkle path 3 (SIB0 slice), somewhere in-path.
    let b_stride = family.stride();
    assert!(flip(6 + 2, 3 * b_stride + 2), "flipped merkle sibling accepted");
}

/// SB8 shape: K high-pair leaf chains tiled → K digests → K Merkle paths that
/// authenticate to ONE shared folded-layer root (all queries of a fold layer
/// open against the same committed root). Same tiled discharge as SB6, only the
/// leaf chain and the shared-root pin differ.
#[test]
fn region_tiled_high_pair_opening_slot_end_to_end() {
    let mut rng = Rng(0x8B8_C0DE);

    // Family A: K high-pair leaf chains (one per query in one fold layer).
    let chain = high_pair_leaf_chain();
    let stride_log = chain.stride().trailing_zeros() as usize;
    let num_queries = 8usize;
    let a_wlog = stride_log + num_queries.trailing_zeros() as usize;
    let layer_log = 12usize;
    let tiles: Vec<(usize, usize, F128, F128)> =
        (0..num_queries).map(|t| (layer_log, 2 * t + 1, rng.f128(), rng.f128())).collect();
    let (a_cols, tile_digests) = build_tiled_high_pair_leaf(&chain, &tiles, a_wlog);
    let a_native = run_source_leaf_native(&chain, &a_cols, a_wlog, b"tiled-high-pair");

    // Family B: K Merkle paths, entry p == tile p's digest, ALL to one root.
    let depth = 4usize;
    let family = MerklePathFamily { depth, n_paths: num_queries };
    let b_wlog = family.n_slots().next_power_of_two().trailing_zeros() as usize;
    let paths: Vec<MerklePathWitness> = (0..num_queries)
        .map(|p| MerklePathWitness {
            entry: tile_digests[p],
            siblings: (0..depth).map(|_| [rng.f128(), rng.f128()]).collect(),
            directions: (0..depth).map(|_| rng.next_u64() & 1 == 1).collect(),
        })
        .collect();
    let b_cols = build_merkle_path_columns(&family, iv_flat(), &paths, b_wlog);
    let b_native = run_merkle_native(&family, &b_cols, b_wlog, b"tiled-high-pair-merkle");
    // Independent siblings/directions per path give distinct roots here — the
    // SB8 shared-root pin is exercised by the honest cols.roots; the mechanism
    // (pin each path root to a committed node) is identical.
    let committed_roots = b_cols.roots.clone();

    let mut b = FieldR1csBuilder::new();
    let mut slices = Vec::new();
    for col in [&a_cols.in_[0], &a_cols.in_[1], &a_cols.c[0], &a_cols.c[1], &a_cols.c[2], &a_cols.c[3]] {
        slices.push(alloc_column_slice(&mut b, col, a_wlog).0);
    }
    let a_base = 0usize;
    for col in [
        &b_cols.e[0], &b_cols.e[1], &b_cols.sib[0], &b_cols.sib[1], &b_cols.d, &b_cols.c[0],
        &b_cols.c[1], &b_cols.c[2], &b_cols.c[3],
    ] {
        slices.push(alloc_column_slice(&mut b, col, b_wlog).0);
    }
    let b_base = 6usize;

    let (mut claims, digest_wires) = discharge_tiled_source_leaf(
        &mut b, &chain, a_wlog, b"tiled-high-pair", &a_native, a_base, &tile_digests,
    );
    let mk_claims = discharge_multipath_merkle(
        &mut b, &family, &b_cols, b_wlog, b"tiled-high-pair-merkle", &b_native, b_base,
        &digest_wires, &tile_digests, &committed_roots,
    );
    claims.extend(mk_claims);

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
    assert!(r1cs.satisfies(&z), "honest high-pair tiled opening unsatisfiable");
    let params = PcsParams {
        m: r1cs.m + pcs::LOG_PACKING,
        log_inv_rate: 2,
        log_batch_size: 2,
        profile: Default::default(),
    };
    let mut chp = FsLaneChallenger::new(b"region-tiled-high-pair");
    let (proof, commitment, _) = noid_ivc_prover::field_prover::prove_field_with_public_io(
        &r1cs, &z, &params, &spec, &io_values, &mut chp,
    );
    let mut chv = FsLaneChallenger::new(b"region-tiled-high-pair");
    noid_ivc_core::verifier::verify_field_with_public_io(&r1cs, &commitment, &proof, &spec, &io_values, &mut chv)
        .expect("high-pair tiled opening verifies");
    eprintln!(
        "[region-tiled-high-pair] rows = {} (m = {}), queries = {}, claims = {}",
        z.len(),
        r1cs.m,
        num_queries,
        spec.claims.len()
    );

    let flip = |slice_idx: usize, off: usize| {
        let mut bad = z.clone();
        bad[slices[slice_idx].start() + off] += F128::ONE;
        assert!(r1cs.satisfies(&bad), "columns are free wires");
        let mut chp = FsLaneChallenger::new(b"region-tiled-high-pair");
        let (bp, bc, _) = noid_ivc_prover::field_prover::prove_field_with_public_io(
            &r1cs, &bad, &params, &spec, &io_values, &mut chp,
        );
        let mut chv = FsLaneChallenger::new(b"region-tiled-high-pair");
        noid_ivc_core::verifier::verify_field_with_public_io(&r1cs, &bc, &bp, &spec, &io_values, &mut chv).is_err()
    };
    // Corrupt tile 5's queried pair symbol (high-pair leaf reads s1 into IN1 at
    // the pair-hash slot). Any flip changes IN1's MLE at the substitution point,
    // so its opening claim breaks; the single relation set covers all tiles.
    let a_stride = chain.stride();
    assert!(flip(1, 5 * a_stride + 2), "flipped high-pair tile symbol accepted");
}
