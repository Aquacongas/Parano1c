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
    build_high_pair_leaf_columns, build_pair_leaf_columns, build_source_leaf_columns,
    high_pair_leaf_chain, pair_leaf_refs, pair_leaf_substitution_terms, source_leaf_fixed_patterns,
    source_leaf_refs, source_leaf_substitution_terms, PairLeafRefs, SourceLeafChain,
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

// FRI-round grand-leg (3i) extra imports: the real FRICHANL channel + fold.
use noid_core::{AdditiveNTT, Block128};
use noid_fri::code::LOG_RATE;
use noid_fri_binius::compact_fri::{
    compute_round_depth, expand_batched_merkle_proof, BatchedMerkleProof,
};
use noid_fri_binius::mixed_open::{high_pair_tree_depth, MIXED_OPEN_TAG, MIXED_SOURCE_BINDING_TAG};
use noid_fri_binius::{COMPACT_NUM_QUERIES, COMPACT_TAU};
use noid_gkr::auth_pcs::{commit_auth_mle_column, open_auth_mle_committed, AuthMleOpeningProof};
use noid_gkr::batch_eval::BatchEvalReduction;
use noid_poseidon2b::hasher::CryptographicHasher;
use noid_poseidon2b::Poseidon2bSponge;
use noid_recursive::acceptance::trace::alloc_blocks;
use noid_recursive::acceptance::trace::auth_pcs::{absorb_cap_trace, MixedOpeningProofTrace};
use noid_recursive::acceptance::trace::eq_ind_partial_eval_trace;
use noid_recursive::acceptance::trace::fri_pcs::{
    fold_trace, gen_compact_queries_trace, FriChannelTrace,
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

// ---------------------------------------------------------------------------
// FRI-round bare hash-pair family (3i): one slot per query, no fixed patterns,
// no shifts.
// ---------------------------------------------------------------------------

struct PairNative {
    sel_proof: ColumnRelationProof,
    walk_proof: DeepChainWalkProof,
    sub_proof: ColumnRelationProof,
    pending: Vec<(usize, Vec<F128>, F128)>,
}

fn run_pair_leaf_native(cols: &SourceLeafColumns, w_log: usize, domain: &[u8]) -> PairNative {
    let refs = pair_leaf_refs(0);
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
        &RelationColumns { committed: &committed, internal: &internal, fixed: &[] },
        &mut ch_p,
    );
    let sel_point =
        verify_column_relation(w_log, F128::ZERO, &rho, &sel_terms, &[], &sel_proof, &mut ch_v).unwrap();
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
    let sub_terms = pair_leaf_substitution_terms(&refs, alpha);
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
        &RelationColumns { committed: &committed, internal: &[], fixed: &[] },
        &mut ch_p,
    );
    let sub_point =
        verify_column_relation(w_log, target, &terminal.point, &sub_terms, &[], &sub_proof, &mut ch_v).unwrap();
    for (r, v) in claimed_refs(&sub_terms).iter().zip(sub_proof.final_values.iter()) {
        match r {
            ColRef::Committed(c) => pending.push((*c, sub_point.clone(), *v)),
            _ => unreachable!(),
        }
    }
    assert_eq!(ch_p.sample_f128(), ch_v.sample_f128());
    PairNative { sel_proof, walk_proof, sub_proof, pending }
}

fn pair_sub_terms_trace(
    b: &mut FieldR1csBuilder,
    refs: &PairLeafRefs,
    alpha: &LinExpr,
) -> Vec<RelationTermTrace> {
    let mds = flat_mds(true);
    let mut ap = Vec::with_capacity(STATE_SIZE);
    let mut acc = LinExpr::constant(F128::ONE);
    for _ in 0..STATE_SIZE {
        acc = mul(b, &acc, alpha);
        ap.push(acc.clone());
    }
    let m: Vec<LinExpr> = (0..2)
        .map(|j| {
            let mut a = LinExpr::zero();
            for e in 0..STATE_SIZE {
                a = a.add(&ap[e].scale(mds[e][j]));
            }
            a
        })
        .collect();
    vec![
        RelationTermTrace { coeff: m[0].clone(), factors: vec![ColRef::Committed(refs.in_[0])] },
        RelationTermTrace { coeff: m[1].clone(), factors: vec![ColRef::Committed(refs.in_[1])] },
    ]
}

fn discharge_pair_leaf(
    b: &mut FieldR1csBuilder,
    w_log: usize,
    domain: &[u8],
    native: &PairNative,
    base: usize,
    tile_digests: &[[F128; 2]],
) -> (Vec<Claim>, Vec<[LinExpr; 2]>) {
    let refs = pair_leaf_refs(0);
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
    let sel_point = verify_column_relation_trace(b, &mut ch, w_log, &zero, &rho, &sel_e_terms, &[], &sel_e);
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
    let sub_native = pair_leaf_substitution_terms(&refs, F128::ONE);
    let sub_e_terms = pair_sub_terms_trace(b, &refs, &alpha);
    // target = Σ_e ap[e]·terminal[e] (ap = α powers, recomputed here).
    let mut ap = Vec::with_capacity(STATE_SIZE);
    let mut acc = LinExpr::constant(F128::ONE);
    for _ in 0..STATE_SIZE {
        acc = mul(b, &acc, &alpha);
        ap.push(acc.clone());
    }
    let mut target = LinExpr::zero();
    for e in 0..STATE_SIZE {
        target = target.add(&mul(b, &ap[e], &terminal.values[e]));
    }
    let sub_e = ColumnRelationProofTrace::alloc(b, &native.sub_proof, w_log, claimed_refs(&sub_native).len());
    let sub_point = verify_column_relation_trace(b, &mut ch, w_log, &target, &terminal.point, &sub_e_terms, &[], &sub_e);
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
            _ => unreachable!(),
        }
    }
    assert_eq!(np_cursor, np.len(), "pair-leaf pending lockstep");

    // Per-tile digest claims: C0/C1 at slot t (stride 1).
    let mut digest_wires = Vec::with_capacity(tile_digests.len());
    for (t, dig) in tile_digests.iter().enumerate() {
        let (pt_lin, pt_nat) = slot_point(t, w_log);
        let mut wires: [LinExpr; 2] = [LinExpr::zero(), LinExpr::zero()];
        for lane in 0..2 {
            let value = LinExpr::from_wire(b.alloc_f128(dig[lane]));
            out.push(Claim {
                slice: base + 2 + lane,
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

/// 3i shape: K FRI-round pair leaves (bare hash_pair) tiled at stride 1 → K
/// digests → K Merkle paths → per-round root pins. Same tiled discharge as
/// SB6/SB8, the simplest leaf.
#[test]
fn region_tiled_fri_round_opening_slot_end_to_end() {
    let mut rng = Rng(0x3F1_C0DE);

    let num_queries = 8usize;
    let a_wlog = num_queries.trailing_zeros() as usize; // stride 1
    let pairs: Vec<(F128, F128)> = (0..num_queries).map(|_| (rng.f128(), rng.f128())).collect();
    let (a_cols, tile_digests) = build_pair_leaf_columns(&pairs, a_wlog);
    let a_native = run_pair_leaf_native(&a_cols, a_wlog, b"tiled-fri-pair");

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
    let b_native = run_merkle_native(&family, &b_cols, b_wlog, b"tiled-fri-merkle");
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

    let (mut claims, digest_wires) =
        discharge_pair_leaf(&mut b, a_wlog, b"tiled-fri-pair", &a_native, a_base, &tile_digests);
    let mk_claims = discharge_multipath_merkle(
        &mut b, &family, &b_cols, b_wlog, b"tiled-fri-merkle", &b_native, b_base, &digest_wires,
        &tile_digests, &committed_roots,
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
    assert!(r1cs.satisfies(&z), "honest FRI-round tiled opening unsatisfiable");
    let params = PcsParams {
        m: r1cs.m + pcs::LOG_PACKING,
        log_inv_rate: 2,
        log_batch_size: 2,
        profile: Default::default(),
    };
    let mut chp = FsLaneChallenger::new(b"region-tiled-fri");
    let (proof, commitment, _) = noid_ivc_prover::field_prover::prove_field_with_public_io(
        &r1cs, &z, &params, &spec, &io_values, &mut chp,
    );
    let mut chv = FsLaneChallenger::new(b"region-tiled-fri");
    noid_ivc_core::verifier::verify_field_with_public_io(&r1cs, &commitment, &proof, &spec, &io_values, &mut chv)
        .expect("FRI-round tiled opening verifies");
    eprintln!(
        "[region-tiled-fri] rows = {} (m = {}), queries = {}, claims = {}",
        z.len(),
        r1cs.m,
        num_queries,
        spec.claims.len()
    );

    let flip = |slice_idx: usize, off: usize| {
        let mut bad = z.clone();
        bad[slices[slice_idx].start() + off] += F128::ONE;
        assert!(r1cs.satisfies(&bad), "columns are free wires");
        let mut chp = FsLaneChallenger::new(b"region-tiled-fri");
        let (bp, bc, _) = noid_ivc_prover::field_prover::prove_field_with_public_io(
            &r1cs, &bad, &params, &spec, &io_values, &mut chp,
        );
        let mut chv = FsLaneChallenger::new(b"region-tiled-fri");
        noid_ivc_core::verifier::verify_field_with_public_io(&r1cs, &bc, &bp, &spec, &io_values, &mut chv).is_err()
    };
    // Corrupt query 5's first symbol (IN0 at slot 5).
    assert!(flip(0, 5), "flipped FRI queried symbol accepted");
    // Corrupt a sibling of Merkle path 2.
    let b_stride = family.stride();
    assert!(flip(6 + 2, 2 * b_stride + 2), "flipped FRI merkle sibling accepted");
}

// ===========================================================================
// FRI-round grand leg (3i): the compact-FRI query phase composed with the REAL
// FRICHANL channel. Drives FriChannelTrace through the full sumcheck + source
// binding absorbs to the FRI query draw (3h), then discharges round 0 via the
// pair-leaf + Merkle families, folding the queried symbols with fold_trace off
// the sumcheck's own random challenge (the second channel<->algebra join:
// random_point -> fold, query indices -> family selection). The symbols the
// fold consumes are pinned to the pair-leaf family's committed IN columns.
// ===========================================================================

fn phi(b: Block128) -> F128 {
    flat_of_tower_u128(b.0)
}
fn lanes_flat(d: &[u8; 32]) -> [F128; 2] {
    [
        phi(Block128::from(u128::from_le_bytes(d[..16].try_into().unwrap()))),
        phi(Block128::from(u128::from_le_bytes(d[16..].try_into().unwrap()))),
    ]
}
impl Rng {
    fn f128_block(&mut self) -> Block128 {
        Block128::from(((self.next_u64() as u128) << 64) | self.next_u64() as u128)
    }
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

#[test]
fn region_fri_round_grand() {
    let num_vars = 9usize; // tau = 8, n_rounds = 1 -> a single FRI round
    let (point, _red, proof) = capsule_fixture(num_vars, 0x3F1_9A1E);
    let log_n = proof.commitment.log_rows;
    let tau = COMPACT_TAU.min(log_n);
    let n_rounds = log_n - tau;
    let ntt = AdditiveNTT::<Block128>::new(num_vars + LOG_RATE);
    let hasher = Poseidon2bSponge::new();
    let opening = &proof.opening;

    let mut b = FieldR1csBuilder::new();
    // All proof wires (phi-flat).
    let op = MixedOpeningProofTrace::alloc(&mut b, opening, log_n, 1, 0, COMPACT_NUM_QUERIES);
    let point_w = alloc_blocks(&mut b, &point);
    let cap_lanes: Vec<[LinExpr; 2]> =
        proof.commitment.cap.hashes.iter().map(|h| alloc_digest_local(&mut b, h)).collect();

    // ---- Drive FriChannelTrace through 3h (the FRI query draw).
    let mut ch = FriChannelTrace::new();
    absorb_cap_trace(&mut b, &mut ch, &cap_lanes);
    ch.observe_const_tower(&mut b, MIXED_OPEN_TAG as u128);
    ch.observe_field_elems(&mut b, &op.all_openings);
    let _gamma = ch.squeeze(&mut b);
    let batched_claim = op.all_openings[0].clone();

    ch.observe_field_elems(&mut b, &point_w); // 3a
    let (_right_w, left_w) = point_w.split_at(n_rounds);
    let left_eq = eq_ind_partial_eval_trace(&mut b, left_w);
    let mut derived = LinExpr::zero();
    for (l, u) in left_eq.iter().zip(op.fri_proof.upper_partial_evals.iter()) {
        derived = derived.add(&mul(&mut b, l, u));
    }
    pin_eq(&mut b, &derived, &batched_claim); // 3c
    ch.observe_field_elem(&mut b, &batched_claim);
    let beta = ch.squeeze_n(&mut b, tau); // 3d
    let batching_eq = eq_ind_partial_eval_trace(&mut b, &beta);
    let mut claim = LinExpr::zero();
    for (u, be) in op.fri_proof.upper_partial_evals.iter().zip(batching_eq.iter()) {
        claim = claim.add(&mul(&mut b, u, be));
    }
    // 3e sumcheck rounds.
    let mut random_point = Vec::with_capacity(n_rounds);
    for round in 0..n_rounds {
        let [c0, c1] = &op.fri_proof.sum_check_oracles[round];
        pin_eq(&mut b, c1, &claim);
        ch.observe_field_elem(&mut b, c0);
        ch.observe_field_elem(&mut b, c1);
        let depth = compute_round_depth(n_rounds, round);
        ch.observe_vector_commitment(&mut b, &op.fri_proof.fri_roots[round], depth);
        let r = ch.squeeze(&mut b);
        claim = c0.add(&mul(&mut b, c1, &r));
        random_point.push(r);
    }
    ch.observe_field_elems(&mut b, &op.fri_proof.final_codeword); // 3f
    // SB2 source-binding absorbs.
    ch.observe_const_tower(&mut b, MIXED_SOURCE_BINDING_TAG);
    ch.observe_field_elems(&mut b, &op.source_proof.h_evals);
    for (i, root) in op.source_proof.folded_roots.iter().enumerate() {
        ch.observe_vector_commitment(&mut b, root, high_pair_tree_depth(log_n - 1 - i));
    }
    // SB3 source query draw (positions unused by the FRI leg; drives the channel).
    let _sq = gen_compact_queries_trace(&mut b, &mut ch, log_n + LOG_RATE, COMPACT_NUM_QUERIES);
    // 3h FRI query draw.
    let fri_queries = gen_compact_queries_trace(&mut b, &mut ch, n_rounds + LOG_RATE, COMPACT_NUM_QUERIES);
    let nq = fri_queries.len();

    // ---- Round 0 discharge via the pair-leaf + Merkle families.
    let round = 0usize;
    let symbols_w = &op.fri_proof.fri_queried_symbols[round];
    assert_eq!(symbols_w.len(), nq);
    let native_syms = &opening.fri_proof.fri_queried_symbols[round];
    let pairs: Vec<(F128, F128)> =
        symbols_w.iter().map(|(s0, s1)| (s0.eval(b.values()), s1.eval(b.values()))).collect();
    let a_wlog = nq.next_power_of_two().trailing_zeros() as usize;
    let (a_cols, tile_digests) = build_pair_leaf_columns(&pairs, a_wlog);
    let a_native = run_pair_leaf_native(&a_cols, a_wlog, b"fri-grand-pair");

    // Native Merkle path expansion for round 0.
    let pair_indices: Vec<usize> = fri_queries.iter().map(|&qi| (qi >> round) >> 1).collect();
    let native_leaves: Vec<[u8; 32]> =
        native_syms.iter().map(|(s0, s1)| hasher.hash_pair(s0, s1)).collect();
    let batch = BatchedMerkleProof { siblings: opening.fri_proof.fri_merkle_batch[round].siblings.clone() };
    let depth = compute_round_depth(n_rounds, round);
    let paths = expand_batched_merkle_proof(&batch, depth, &pair_indices, &native_leaves, &hasher)
        .expect("fri round path expansion");
    let family = MerklePathFamily { depth, n_paths: paths.len() };
    let b_wlog = family.n_slots().next_power_of_two().trailing_zeros() as usize;

    // Pair-leaf family slices (base 0), then Merkle slices (base 6).
    let mut slices = Vec::new();
    for col in [&a_cols.in_[0], &a_cols.in_[1], &a_cols.c[0], &a_cols.c[1], &a_cols.c[2], &a_cols.c[3]] {
        slices.push(alloc_column_slice(&mut b, col, a_wlog).0);
    }
    let a_base = 0usize;

    // Merkle witnesses: entry p == the pair-leaf digest at that leaf index.
    let mut idx_of = std::collections::HashMap::new();
    for (q, &li) in pair_indices.iter().enumerate() {
        idx_of.entry(li).or_insert(q);
    }
    let mut witnesses = Vec::with_capacity(paths.len());
    let mut entry_q = Vec::with_capacity(paths.len());
    for p in &paths {
        let q = idx_of[&p.leaf_index];
        assert_eq!(tile_digests[q], lanes_flat(&p.leaf_hash), "pair-leaf digest != phi(native leaf)");
        witnesses.push(MerklePathWitness {
            entry: tile_digests[q],
            siblings: p.siblings.iter().map(lanes_flat).collect(),
            directions: p.directions.clone(),
        });
        entry_q.push(q);
    }
    let b_cols = build_merkle_path_columns(&family, iv_flat(), &witnesses, b_wlog);
    let b_native = run_merkle_native(&family, &b_cols, b_wlog, b"fri-grand-merkle");
    let committed_roots: Vec<[F128; 2]> = (0..paths.len()).map(|_| lanes_flat(&opening.fri_proof.fri_roots[round])).collect();
    for col in [
        &b_cols.e[0], &b_cols.e[1], &b_cols.sib[0], &b_cols.sib[1], &b_cols.d, &b_cols.c[0],
        &b_cols.c[1], &b_cols.c[2], &b_cols.c[3],
    ] {
        slices.push(alloc_column_slice(&mut b, col, b_wlog).0);
    }
    let b_base = 6usize;

    // Discharge both families.
    let (mut claims, digest_wires) =
        discharge_pair_leaf(&mut b, a_wlog, b"fri-grand-pair", &a_native, a_base, &tile_digests);
    // Merkle entry wires per path (== the pair-leaf digest wire of that query).
    let entry_wires: Vec<[LinExpr; 2]> = entry_q.iter().map(|&q| digest_wires[q].clone()).collect();
    let entry_vals: Vec<[F128; 2]> = entry_q.iter().map(|&q| tile_digests[q]).collect();
    let mk_claims = discharge_multipath_merkle(
        &mut b, &family, &b_cols, b_wlog, b"fri-grand-merkle", &b_native, b_base, &entry_wires,
        &entry_vals, &committed_roots,
    );
    claims.extend(mk_claims);

    // ---- The fold join: symbols the fold consumes == the pair-leaf IN columns.
    for q in 0..nq {
        let (pt_lin, pt_nat) = slot_point(q, a_wlog);
        let sym_wires = [symbols_w[q].0.clone(), symbols_w[q].1.clone()];
        let sym_vals = [pairs[q].0, pairs[q].1];
        for lane in 0..2 {
            claims.push(Claim {
                slice: a_base + lane, // IN0 / IN1
                point: pt_lin.clone(),
                value: sym_wires[lane].clone(),
                native_point: pt_nat.clone(),
                native_value: sym_vals[lane],
            });
        }
    }

    // ---- Fold each query with fold_trace(random_point[0]) and pin to the final
    // codeword (round 0: no fold-consistency against a previous round).
    let final_len = op.fri_proof.final_codeword.len();
    for q in 0..nq {
        let pair_idx = (fri_queries[q] >> round) >> 1;
        let folded = fold_trace(&mut b, &random_point[round], round, pair_idx, &symbols_w[q].0, &symbols_w[q].1, &ntt);
        let final_idx = (fri_queries[q] >> n_rounds) % final_len;
        pin_eq(&mut b, &folded, &op.fri_proof.final_codeword[final_idx]);
    }

    // ---- ONE public-IO discharge.
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
    assert!(r1cs.satisfies(&z), "honest FRI-round grand trace unsatisfiable");
    let params = PcsParams {
        m: r1cs.m + pcs::LOG_PACKING,
        log_inv_rate: 2,
        log_batch_size: 2,
        profile: Default::default(),
    };
    let mut chp = FsLaneChallenger::new(b"region-fri-grand");
    let (pf, commitment, _) = noid_ivc_prover::field_prover::prove_field_with_public_io(
        &r1cs, &z, &params, &spec, &io_values, &mut chp,
    );
    let mut chv = FsLaneChallenger::new(b"region-fri-grand");
    noid_ivc_core::verifier::verify_field_with_public_io(&r1cs, &commitment, &pf, &spec, &io_values, &mut chv)
        .expect("FRI-round grand composition verifies");
    eprintln!(
        "[region-fri-grand] rows = {} (m = {}), num_vars = {}, queries = {}, claims = {}",
        z.len(),
        r1cs.m,
        num_vars,
        nq,
        spec.claims.len()
    );

    // Negative: flip a pair-leaf IN symbol -> the fold uses it AND the leaf
    // hashes it, so the join / Merkle authentication breaks.
    let flip = |slice_idx: usize, off: usize| {
        let mut bad = z.clone();
        bad[slices[slice_idx].start() + off] += F128::ONE;
        assert!(r1cs.satisfies(&bad), "columns are free wires");
        let mut chp = FsLaneChallenger::new(b"region-fri-grand");
        let (bp, bc, _) = noid_ivc_prover::field_prover::prove_field_with_public_io(
            &r1cs, &bad, &params, &spec, &io_values, &mut chp,
        );
        let mut chv = FsLaneChallenger::new(b"region-fri-grand");
        noid_ivc_core::verifier::verify_field_with_public_io(&r1cs, &bc, &bp, &spec, &io_values, &mut chv).is_err()
    };
    assert!(flip(0, 0), "flipped pair-leaf IN0 accepted");
    assert!(flip(6 + 5, 3), "flipped merkle C0 accepted");
}

// helper: alloc a digest (2 flat lanes) from a HashOutput.
fn alloc_digest_local(b: &mut FieldR1csBuilder, d: &[u8; 32]) -> [LinExpr; 2] {
    let lo = flat_of_tower_u128(u128::from_le_bytes(d[..16].try_into().unwrap()));
    let hi = flat_of_tower_u128(u128::from_le_bytes(d[16..].try_into().unwrap()));
    [LinExpr::from_wire(b.alloc_f128(lo)), LinExpr::from_wire(b.alloc_f128(hi))]
}
