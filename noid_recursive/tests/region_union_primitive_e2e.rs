//! [G] — the HETEROGENEOUS UNION PRIMITIVE: two DIFFERENT deep-chain families
//! discharged by ONE global walk + ONE carry-selection + a UNIONED substitution
//! over a SINGLE slot domain, all through the real outer PCS via public-IO.
//!
//! This is the memory-efficient replacement for one-walk-per-family (a naive
//! per-family assembly OOMs: N families = N independent 66-layer walks). Here
//! the two families share ONE slot domain of period `P`; family A (a
//! source-leaf chain) occupies `[0, stride_A)` and family B (a Merkle path)
//! occupies `[stride_A, stride_A + stride_B)`. The SHARED columns are `C0..C3`
//! (the perm OUTPUTS of both families, `= s_out`) and the walk input `s0`;
//! per-family input columns are nonzero only inside their own slots.
//!
//! THE KEY FIX (localized fixed patterns): the per-family `*_fixed_patterns`
//! use PER-FAMILY stride periods, so their pure-constant / carry terms would
//! fire inside the OTHER family's slots. Instead every pattern is rebuilt as a
//! table of length `P` (the META period) with the family's values in the
//! family's slots and ZERO everywhere else, and `low_log = log2(P)`. So each
//! family's patterns are localized to its slot range; the unioned substitution
//! terms then constrain only their own slots. The Merkle family's UNGATED
//! carry-forward terms (`raw = C(w−1)` with no fixed factor) are additionally
//! gated by a `region_B` selector pattern (1 on B's slots, 0 elsewhere) so
//! they, too, vanish over family A. The per-slot substitution identity
//! `Σ_terms(w) = Σ_e α^{e+1}·s0[e](w)` then holds across the whole domain: at
//! an A slot only A's terms are live, at a B slot only B's.
//!
//! ONE carry-selection (`C_j + S_out,j`, β-batched) and ONE deep-chain walk
//! (family-agnostic — it verifies every slot's permutation regardless of
//! family) cover BOTH families; the walk terminal seeds ONE union substitution.
//! Family B additionally carries a cheap booleanity relation on its direction
//! bits — an extra single sumcheck, NOT an extra walk. Every terminal claim
//! plus the per-family digest/root pins discharge through ONE
//! `prove/verify_field_with_public_io` opening; a flipped A input symbol or a
//! flipped B sibling leaves the trace satisfiable but breaks that column's
//! opening claim, so the PCS layer rejects.

use noid_ivc_core::challenger::{Challenger, FsLaneChallenger};
use noid_ivc_core::deep_chain::flat_mds;
use noid_ivc_core::deep_chain::leaf_hash::{
    build_source_leaf_columns, source_leaf_fixed_patterns, source_leaf_substitution_terms,
    SourceLeafChain, SourceLeafRefs,
};
use noid_ivc_core::deep_chain::relations::{
    claimed_refs, prove_column_relation, prove_shift_discharge, prove_shift_discharge_pow2,
    verify_column_relation, verify_shift_discharge, verify_shift_discharge_pow2, ColRef,
    ColumnRelationProof, FixedPattern, RelationColumns, RelationTerm, ShiftDischargeProof,
};
use noid_ivc_core::deep_chain::schedule::{
    build_merkle_path_columns, carry_selection_terms, merkle_booleanity_terms,
    merkle_fixed_patterns, merkle_substitution_terms, MerkleFamilyRefs, MerklePathFamily,
    MerklePathWitness,
};
use noid_ivc_core::deep_chain::source_tree::compress_iv_flat;
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
use noid_recursive::acceptance::trace::{mul, pin_eq};

const DOMAIN: &[u8] = b"union-primitive-dag";
const OUTER_DOMAIN: &[u8] = b"region-union-primitive-e2e";

// ---- Meta layout constants (one source-leaf tile + one Merkle tile). --------
// Family A: source-leaf, n_cols = 1  -> slots = 4 + 3 = 7, stride = 8.
// Family B: Merkle path, depth = 3, n_paths = 1 -> stride = n_slots = 8.
// META period P = stride_A + stride_B = 16 (already a power of two), w_log = 4.
//
// Committed column order (indices):
//   A.IN0=0, A.IN1=1, B.E0=2, B.E1=3, B.SIB0=4, B.SIB1=5, B.D=6, C0=7..C3=10.
const A_IN0: usize = 0;
const A_IN1: usize = 1;
const B_E0: usize = 2;
const B_E1: usize = 3;
const B_SIB0: usize = 4;
const B_SIB1: usize = 5;
const B_D: usize = 6;
const C0: usize = 7;
// C1=8, C2=9, C3=10.
const N_COMMITTED: usize = 11;

// Fixed-pattern indices (all rebuilt at low_log = w_log = log2(P)):
//   A: HP=0, EVEN=1, ODD=2, IV0=3, IV1=4.
//   B: EVEN=5, EVENNS=6, EVENSTART=7, ODD=8, ODDNS=9, ODDSTART=10, IV0=11, IV1=12.
//   region_B selector = 13.
const FA_BASE: usize = 0;
const FB_BASE: usize = 5;
const REGION_B: usize = 13;

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
        F128 {
            lo: self.next_u64(),
            hi: self.next_u64(),
        }
    }
}

/// Custom refs pointing A's / B's columns at the meta committed set (both
/// families' carries alias the SHARED `C0..C3`).
fn refs_a() -> SourceLeafRefs {
    SourceLeafRefs {
        in_: [A_IN0, A_IN1],
        c: std::array::from_fn(|i| C0 + i),
        hp: FA_BASE,
        even: FA_BASE + 1,
        odd: FA_BASE + 2,
        iv: [FA_BASE + 3, FA_BASE + 4],
    }
}
fn refs_b() -> MerkleFamilyRefs {
    MerkleFamilyRefs {
        e: [B_E0, B_E1],
        sib: [B_SIB0, B_SIB1],
        d: B_D,
        c: std::array::from_fn(|i| C0 + i),
        even: FB_BASE,
        evenns: FB_BASE + 1,
        evenstart: FB_BASE + 2,
        odd: FB_BASE + 3,
        oddns: FB_BASE + 4,
        oddstart: FB_BASE + 5,
        iv: [FB_BASE + 6, FB_BASE + 7],
    }
}

/// Rebuild a per-family stride-period pattern as a META-period table (length
/// `P = 2^p_log`) with the family's values placed at `[base, base + period)`
/// and ZERO everywhere else. `low_log = p_log`, so the pattern is localized to
/// the family's slot range and vanishes inside the other family's slots.
fn localize(table: &[F128], base: usize, p_log: usize) -> FixedPattern {
    let p = 1usize << p_log;
    let mut t = vec![F128::ZERO; p];
    t[base..base + table.len()].copy_from_slice(table);
    FixedPattern::new(p_log, t)
}

/// The 14 META fixed patterns (A localized to [0,stride_A), B localized to
/// [stride_A, stride_A+stride_B), plus the region_B selector).
fn meta_fixed(
    chain_a: &SourceLeafChain,
    family_b: &MerklePathFamily,
    stride_a: usize,
    p_log: usize,
) -> Vec<FixedPattern> {
    let iv = compress_iv_flat();
    let mut out = Vec::with_capacity(14);
    for pat in source_leaf_fixed_patterns(chain_a, iv) {
        out.push(localize(&pat.table, 0, p_log));
    }
    for pat in merkle_fixed_patterns(family_b, iv) {
        out.push(localize(&pat.table, stride_a, p_log));
    }
    // region_B: 1 on every B slot, 0 elsewhere.
    let mut region = vec![F128::ZERO; 1usize << p_log];
    for slot in stride_a..stride_a + family_b.n_slots() {
        region[slot] = F128::ONE;
    }
    out.push(FixedPattern::new(p_log, region));
    out
}

/// The UNION substitution term list (native, concrete α): A's source-leaf
/// wiring terms ++ B's Merkle wiring terms, with each of B's UNGATED
/// carry-forward terms wrapped by the region_B selector so they vanish over
/// family A. Both families' coefficients use the SAME MDS α-weights (one α).
fn union_terms_native(
    refs_a: &SourceLeafRefs,
    refs_b: &MerkleFamilyRefs,
    alpha: F128,
) -> Vec<RelationTerm> {
    let mut terms = source_leaf_substitution_terms(refs_a, alpha);
    let mut b = merkle_substitution_terms(refs_b, alpha);
    for t in b.iter_mut() {
        if !t.factors.iter().any(|f| matches!(f, ColRef::Fixed(_))) {
            t.factors.insert(0, ColRef::Fixed(REGION_B));
        }
    }
    terms.extend(b);
    terms
}

struct NativePending {
    point: Vec<F128>,
    value: F128,
}

struct NativeArtifacts {
    bool_proof: ColumnRelationProof,
    sel_proof: ColumnRelationProof,
    walk_proof: DeepChainWalkProof,
    sub_proof: ColumnRelationProof,
    /// (shift_log, column, proof) per shifted substitution ref, claimed order.
    shifts: Vec<(usize, usize, ShiftDischargeProof)>,
    pending: Vec<NativePending>,
}

/// Run the whole union DAG natively (prover + verifier channels in lockstep),
/// returning every proof and the verifier-derived pending claims in the exact
/// order the trace twin reproduces them (booleanity, selection, substitution).
#[allow(clippy::too_many_arguments)]
fn run_union_native(
    committed: &[&[F128]],
    s0: &[Vec<F128>; STATE_SIZE],
    s_out: &[Vec<F128>; STATE_SIZE],
    fixed: &[FixedPattern],
    refs_a: &SourceLeafRefs,
    refs_b: &MerkleFamilyRefs,
    w_log: usize,
) -> NativeArtifacts {
    let internal: Vec<&[F128]> = s_out.iter().map(|c| c.as_slice()).collect();
    let mut ch_p = FsLaneChallenger::new(DOMAIN);
    let mut ch_v = FsLaneChallenger::new(DOMAIN);
    let mut pending: Vec<NativePending> = Vec::new();

    // Booleanity of family B's direction bits (Fixed(B.even)-gated, so it is
    // inert over family A's slots).
    let bool_terms = merkle_booleanity_terms(refs_b);
    let rho_b = ch_p.sample_f128_vec(w_log);
    let _ = ch_v.sample_f128_vec(w_log);
    let (bool_proof, _, _) = prove_column_relation(
        F128::ZERO,
        &rho_b,
        &bool_terms,
        &RelationColumns {
            committed,
            internal: &[],
            fixed,
        },
        &mut ch_p,
    );
    let bool_point = verify_column_relation(
        w_log,
        F128::ZERO,
        &rho_b,
        &bool_terms,
        fixed,
        &bool_proof,
        &mut ch_v,
    )
    .expect("native booleanity");
    pending.push(NativePending {
        point: bool_point,
        value: bool_proof.final_values[0],
    });

    // ONE carry-selection over the SHARED carries → the ONE walk start group.
    let beta = ch_p.sample_f128();
    assert_eq!(beta, ch_v.sample_f128());
    let sel_terms = carry_selection_terms(&refs_a.c, beta);
    let rho = ch_p.sample_f128_vec(w_log);
    let _ = ch_v.sample_f128_vec(w_log);
    let (sel_proof, _, _) = prove_column_relation(
        F128::ZERO,
        &rho,
        &sel_terms,
        &RelationColumns {
            committed,
            internal: &internal,
            fixed,
        },
        &mut ch_p,
    );
    let sel_point = verify_column_relation(
        w_log,
        F128::ZERO,
        &rho,
        &sel_terms,
        fixed,
        &sel_proof,
        &mut ch_v,
    )
    .expect("native selection");
    let mut group_values = [F128::ZERO; STATE_SIZE];
    for (r, v) in claimed_refs(&sel_terms)
        .iter()
        .zip(sel_proof.final_values.iter())
    {
        match r {
            ColRef::Committed(_) => pending.push(NativePending {
                point: sel_point.clone(),
                value: *v,
            }),
            ColRef::Internal(j) => group_values[*j] = *v,
            _ => unreachable!(),
        }
    }

    // ONE deep-chain walk over the shared meta s0 (family-agnostic).
    let groups = vec![LaneClaimGroup {
        point: sel_point.clone(),
        values: group_values,
    }];
    let (walk_proof, _) = prove_deep_chain_walk(s0, &groups, &mut ch_p);
    let terminal =
        verify_deep_chain_walk(w_log, &groups, &walk_proof, &mut ch_v).expect("native walk");

    // ONE union substitution (A ++ B, region_B-gated ungated B terms).
    let alpha = ch_p.sample_f128();
    assert_eq!(alpha, ch_v.sample_f128());
    let sub_terms = union_terms_native(refs_a, refs_b, alpha);
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
        &RelationColumns {
            committed,
            internal: &[],
            fixed,
        },
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
    .expect("native substitution");

    let mut shifts = Vec::new();
    for (r, v) in claimed_refs(&sub_terms)
        .iter()
        .zip(sub_proof.final_values.iter())
    {
        match r {
            ColRef::Committed(_) => pending.push(NativePending {
                point: sub_point.clone(),
                value: *v,
            }),
            ColRef::CommittedShift(c) => {
                let (pr, _) = prove_shift_discharge(committed[*c], &sub_point, *v, &mut ch_p);
                let pt =
                    verify_shift_discharge(w_log, &sub_point, *v, &pr, &mut ch_v).expect("shift");
                pending.push(NativePending {
                    point: pt,
                    value: pr.final_value,
                });
                shifts.push((0usize, *c, pr));
            }
            ColRef::CommittedShift2(c) => {
                let (pr, _) =
                    prove_shift_discharge_pow2(committed[*c], &sub_point, *v, 1, &mut ch_p);
                let pt = verify_shift_discharge_pow2(w_log, &sub_point, *v, 1, &pr, &mut ch_v)
                    .expect("shift2");
                pending.push(NativePending {
                    point: pt,
                    value: pr.final_value,
                });
                shifts.push((1usize, *c, pr));
            }
            _ => unreachable!(),
        }
    }
    assert_eq!(ch_p.sample_f128(), ch_v.sample_f128(), "native lockstep");

    NativeArtifacts {
        bool_proof,
        sel_proof,
        walk_proof,
        sub_proof,
        shifts,
        pending,
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
    let wires: Vec<LinExpr> = col
        .iter()
        .map(|&v| LinExpr::from_wire(b.alloc_f128(v)))
        .collect();
    for _ in col.len()..block {
        b.alloc_f128(F128::ZERO);
    }
    (WitnessSlice { log2_len, index }, wires)
}

fn const_terms(terms: &[RelationTerm]) -> Vec<RelationTermTrace> {
    terms
        .iter()
        .map(|t| RelationTermTrace {
            coeff: LinExpr::constant(t.coeff),
            factors: t.factors.clone(),
        })
        .collect()
}

/// Trace twin of [`union_terms_native`]: A's source-leaf terms then B's Merkle
/// terms (with region_B-gated ungated carry terms), all coefficients being the
/// α-power MDS weights `m[j] = Σ_e α^{e+1}·flat(MDS_FULL[e][j])` as LinExpr.
/// Line-by-line shadow of `source_leaf_substitution_terms` /
/// `merkle_substitution_terms`. Returns the terms and the α-power wires (so the
/// substitution target reuses them).
fn union_terms_trace(
    b: &mut FieldR1csBuilder,
    refs_a: &SourceLeafRefs,
    refs_b: &MerkleFamilyRefs,
    alpha: &LinExpr,
) -> (Vec<RelationTermTrace>, Vec<LinExpr>) {
    let mds = flat_mds(true);
    let mut alpha_pows = Vec::with_capacity(STATE_SIZE);
    let mut acc = LinExpr::constant(F128::ONE);
    for _ in 0..STATE_SIZE {
        acc = mul(b, &acc, alpha);
        alpha_pows.push(acc.clone());
    }
    let m: Vec<LinExpr> = (0..STATE_SIZE)
        .map(|j| {
            let mut a = LinExpr::zero();
            for e in 0..STATE_SIZE {
                a = a.add(&alpha_pows[e].scale(mds[e][j]));
            }
            a
        })
        .collect();

    let mut terms = Vec::new();

    // Family A (source-leaf) wiring.
    for i in 0..2 {
        let in_col = ColRef::Committed(refs_a.in_[i]);
        let c_sh = ColRef::CommittedShift(refs_a.c[i]);
        let c_sh2 = ColRef::CommittedShift2(refs_a.c[i]);
        for factors in [
            vec![ColRef::Fixed(refs_a.hp), in_col],
            vec![ColRef::Fixed(refs_a.even), c_sh2],
            vec![ColRef::Fixed(refs_a.odd), c_sh],
            vec![ColRef::Fixed(refs_a.odd), c_sh2],
        ] {
            terms.push(RelationTermTrace {
                coeff: m[i].clone(),
                factors,
            });
        }
    }
    for j in 2..STATE_SIZE {
        terms.push(RelationTermTrace {
            coeff: m[j].clone(),
            factors: vec![ColRef::Fixed(refs_a.iv[j - 2])],
        });
        terms.push(RelationTermTrace {
            coeff: m[j].clone(),
            factors: vec![
                ColRef::Fixed(refs_a.odd),
                ColRef::CommittedShift(refs_a.c[j]),
            ],
        });
    }

    // Family B (Merkle) wiring; ungated carry-forward terms gated by region_B.
    let region_b = ColRef::Fixed(REGION_B);
    for i in 0..2 {
        let c_sh = ColRef::CommittedShift(refs_b.c[i]);
        let c_sh2 = ColRef::CommittedShift2(refs_b.c[i]);
        let sib = ColRef::Committed(refs_b.sib[i]);
        let sib_sh = ColRef::CommittedShift(refs_b.sib[i]);
        let e_col = ColRef::Committed(refs_b.e[i]);
        let e_sh = ColRef::CommittedShift(refs_b.e[i]);
        let d_col = ColRef::Committed(refs_b.d);
        let d_sh = ColRef::CommittedShift(refs_b.d);
        for factors in [
            vec![region_b, c_sh],
            vec![ColRef::Fixed(refs_b.evenstart), c_sh],
            vec![ColRef::Fixed(refs_b.evenns), d_col, c_sh],
            vec![ColRef::Fixed(refs_b.even), d_col, sib],
            vec![ColRef::Fixed(refs_b.evenstart), e_col],
            vec![ColRef::Fixed(refs_b.evenstart), d_col, e_col],
            vec![ColRef::Fixed(refs_b.odd), sib_sh],
            vec![ColRef::Fixed(refs_b.odd), d_sh, sib_sh],
            vec![ColRef::Fixed(refs_b.oddns), d_sh, c_sh2],
            vec![ColRef::Fixed(refs_b.oddstart), d_sh, e_sh],
        ] {
            terms.push(RelationTermTrace {
                coeff: m[i].clone(),
                factors,
            });
        }
    }
    for j in 2..STATE_SIZE {
        let c_sh = ColRef::CommittedShift(refs_b.c[j]);
        terms.push(RelationTermTrace {
            coeff: m[j].clone(),
            factors: vec![region_b, c_sh],
        });
        terms.push(RelationTermTrace {
            coeff: m[j].clone(),
            factors: vec![ColRef::Fixed(refs_b.even), c_sh],
        });
        terms.push(RelationTermTrace {
            coeff: m[j].clone(),
            factors: vec![ColRef::Fixed(refs_b.iv[j - 2])],
        });
    }

    (terms, alpha_pows)
}

struct PendingClaimTrace {
    col: usize,
    point: Vec<LinExpr>,
    value: LinExpr,
}

#[test]
fn region_union_primitive_end_to_end() {
    // ---- Build the two family tiles and the meta columns. -------------------
    let chain_a = SourceLeafChain { n_cols: 1 };
    let stride_a = chain_a.stride(); // 8
    let stride_a_log = stride_a.trailing_zeros() as usize; // 3
    let family_b = MerklePathFamily {
        depth: 3,
        n_paths: 1,
    };
    let stride_b = family_b.stride(); // 8
    let stride_b_log = family_b.stride_log(); // 3

    let p = stride_a + stride_b; // 16
    let w_log = p.trailing_zeros() as usize; // 4
    assert!(p.is_power_of_two(), "meta period must be a power of two");

    let iv = compress_iv_flat();
    let mut rng = Rng(0x0170_C0DE);

    // Family A: source-leaf, distinct symbols.
    let (log_rows_a, leaf_index_a) = (6usize, 5usize);
    let symbols_a: Vec<F128> = (0..chain_a.n_cols * 2).map(|_| rng.f128()).collect();
    let tile_a =
        build_source_leaf_columns(&chain_a, log_rows_a, leaf_index_a, &symbols_a, stride_a_log);

    // Family B: Merkle path, distinct entry/siblings/directions.
    let path_b = MerklePathWitness {
        entry: [rng.f128(), rng.f128()],
        siblings: (0..family_b.depth)
            .map(|_| [rng.f128(), rng.f128()])
            .collect(),
        directions: (0..family_b.depth)
            .map(|_| rng.next_u64() & 1 == 1)
            .collect(),
    };
    let tile_b =
        build_merkle_path_columns(&family_b, iv, std::slice::from_ref(&path_b), stride_b_log);

    // Meta committed columns (length P): per-family inputs localized, C shared.
    let mut committed_cols: Vec<Vec<F128>> =
        (0..N_COMMITTED).map(|_| vec![F128::ZERO; p]).collect();
    committed_cols[A_IN0][0..stride_a].copy_from_slice(&tile_a.in_[0]);
    committed_cols[A_IN1][0..stride_a].copy_from_slice(&tile_a.in_[1]);
    committed_cols[B_E0][stride_a..p].copy_from_slice(&tile_b.e[0]);
    committed_cols[B_E1][stride_a..p].copy_from_slice(&tile_b.e[1]);
    committed_cols[B_SIB0][stride_a..p].copy_from_slice(&tile_b.sib[0]);
    committed_cols[B_SIB1][stride_a..p].copy_from_slice(&tile_b.sib[1]);
    committed_cols[B_D][stride_a..p].copy_from_slice(&tile_b.d);
    for j in 0..STATE_SIZE {
        committed_cols[C0 + j][0..stride_a].copy_from_slice(&tile_a.c[j]);
        committed_cols[C0 + j][stride_a..p].copy_from_slice(&tile_b.c[j]);
    }

    // Shared walk input / output columns (both families store their perms).
    let mut s0: [Vec<F128>; STATE_SIZE] = std::array::from_fn(|_| vec![F128::ZERO; p]);
    let mut s_out: [Vec<F128>; STATE_SIZE] = std::array::from_fn(|_| vec![F128::ZERO; p]);
    for j in 0..STATE_SIZE {
        s0[j][0..stride_a].copy_from_slice(&tile_a.s0[j]);
        s0[j][stride_a..p].copy_from_slice(&tile_b.s0[j]);
        s_out[j][0..stride_a].copy_from_slice(&tile_a.s_out[j]);
        s_out[j][stride_a..p].copy_from_slice(&tile_b.s_out[j]);
    }

    let fixed = meta_fixed(&chain_a, &family_b, stride_a, w_log);
    let refs_a = refs_a();
    let refs_b = refs_b();

    let committed: Vec<&[F128]> = committed_cols.iter().map(|c| c.as_slice()).collect();
    let native = run_union_native(&committed, &s0, &s_out, &fixed, &refs_a, &refs_b, w_log);

    // ---- Trace circuit: committed columns as slices, then the DAG twins. ----
    let mut b = FieldR1csBuilder::new();
    let mut slices = Vec::new();
    for col in committed_cols.iter() {
        slices.push(alloc_column_slice(&mut b, col, w_log));
    }

    let mut ch = FsChannelTrace::new(&mut b, DOMAIN);
    let mut pending: Vec<PendingClaimTrace> = Vec::new();
    let zero = LinExpr::zero();

    // Booleanity of family B's direction bits (one cheap sumcheck, NOT a walk).
    let bool_terms = merkle_booleanity_terms(&refs_b);
    let rho_b = ch.sample_f128_vec(&mut b, w_log);
    let bool_e = ColumnRelationProofTrace::alloc(&mut b, &native.bool_proof, w_log, 1);
    let bool_point = verify_column_relation_trace(
        &mut b,
        &mut ch,
        w_log,
        &zero,
        &rho_b,
        &const_terms(&bool_terms),
        &fixed,
        &bool_e,
    );
    pending.push(PendingClaimTrace {
        col: refs_b.d,
        point: bool_point,
        value: bool_e.final_values[0].clone(),
    });

    // ONE carry-selection → the ONE walk start group (β-power coefficients).
    let beta = ch.sample_f128(&mut b);
    let mut beta_pow = LinExpr::constant(F128::ONE);
    let mut sel_terms_e: Vec<RelationTermTrace> = Vec::new();
    for j in 0..STATE_SIZE {
        beta_pow = mul(&mut b, &beta_pow, &beta);
        sel_terms_e.push(RelationTermTrace {
            coeff: beta_pow.clone(),
            factors: vec![ColRef::Committed(refs_a.c[j])],
        });
        sel_terms_e.push(RelationTermTrace {
            coeff: beta_pow.clone(),
            factors: vec![ColRef::Internal(j)],
        });
    }
    let rho = ch.sample_f128_vec(&mut b, w_log);
    let sel_e = ColumnRelationProofTrace::alloc(&mut b, &native.sel_proof, w_log, 2 * STATE_SIZE);
    let sel_point = verify_column_relation_trace(
        &mut b,
        &mut ch,
        w_log,
        &zero,
        &rho,
        &sel_terms_e,
        &fixed,
        &sel_e,
    );
    let sel_claimed = claimed_refs(&carry_selection_terms(&refs_a.c, F128::ONE));
    let mut group_values: [LinExpr; STATE_SIZE] = std::array::from_fn(|_| LinExpr::zero());
    for (r, v) in sel_claimed.iter().zip(sel_e.final_values.iter()) {
        match r {
            ColRef::Committed(c) => pending.push(PendingClaimTrace {
                col: *c,
                point: sel_point.clone(),
                value: v.clone(),
            }),
            ColRef::Internal(j) => group_values[*j] = v.clone(),
            _ => unreachable!(),
        }
    }

    // ONE deep-chain walk over the shared meta s0.
    let groups_e = vec![LaneClaimGroupTrace {
        point: sel_point.clone(),
        values: group_values,
    }];
    let walk_e = DeepChainWalkProofTrace::alloc(&mut b, &native.walk_proof, w_log);
    let terminal = verify_deep_chain_walk_trace(&mut b, &mut ch, w_log, &groups_e, &walk_e);

    // ONE union substitution (A ++ B, region_B-gated).
    let alpha = ch.sample_f128(&mut b);
    let sub_terms_native = union_terms_native(&refs_a, &refs_b, F128::ONE); // claimed-ref shape
    let (sub_terms_e, alpha_pows) = union_terms_trace(&mut b, &refs_a, &refs_b, &alpha);
    let mut target = LinExpr::zero();
    for e in 0..STATE_SIZE {
        target = target.add(&mul(&mut b, &alpha_pows[e], &terminal.values[e]));
    }
    let n_sub_claims = claimed_refs(&sub_terms_native).len();
    let sub_e = ColumnRelationProofTrace::alloc(&mut b, &native.sub_proof, w_log, n_sub_claims);
    let sub_point = verify_column_relation_trace(
        &mut b,
        &mut ch,
        w_log,
        &target,
        &terminal.point,
        &sub_terms_e,
        &fixed,
        &sub_e,
    );

    let sub_claimed = claimed_refs(&sub_terms_native);
    let mut shift_cursor = 0usize;
    for (r, v) in sub_claimed.iter().zip(sub_e.final_values.iter()) {
        match r {
            ColRef::Committed(c) => pending.push(PendingClaimTrace {
                col: *c,
                point: sub_point.clone(),
                value: v.clone(),
            }),
            ColRef::CommittedShift(_) | ColRef::CommittedShift2(_) => {
                let (shift_log, col, native_shift) = &native.shifts[shift_cursor];
                shift_cursor += 1;
                let shift_e = ShiftDischargeProofTrace::alloc(&mut b, native_shift, w_log);
                let pt = verify_shift_discharge_trace(
                    &mut b, &mut ch, w_log, &sub_point, v, *shift_log, &shift_e,
                );
                pending.push(PendingClaimTrace {
                    col: *col,
                    point: pt,
                    value: shift_e.final_value.clone(),
                });
            }
            _ => unreachable!(),
        }
    }
    assert_eq!(
        shift_cursor,
        native.shifts.len(),
        "all shift proofs consumed"
    );

    // ---- Per-family digest / root pins (extra opening claims). --------------
    // Family A leaf digest = C0/C1 at A's digest slot; family B root = C0/C1 at
    // B's last odd node slot.
    let a_digest_slot = chain_a.digest_slot();
    let b_root_slot = stride_a + (2 * family_b.depth - 1);
    let const_point = |slot: usize| -> Vec<LinExpr> {
        (0..w_log)
            .map(|bb| {
                LinExpr::constant(if (slot >> bb) & 1 == 1 {
                    F128::ONE
                } else {
                    F128::ZERO
                })
            })
            .collect()
    };
    // Trace pins: allocate the pinned value as a wire, tie it to the shared C.
    for (slot, dig) in [
        (a_digest_slot, tile_a.digest),
        (b_root_slot, tile_b.roots[0]),
    ] {
        for lane in 0..2 {
            let value = LinExpr::from_wire(b.alloc_f128(dig[lane]));
            pending.push(PendingClaimTrace {
                col: C0 + lane,
                point: const_point(slot),
                value,
            });
        }
    }
    // Native pins mirror them (constant point, the honest digest value).
    let mut native_pending = native.pending;
    for (slot, dig) in [
        (a_digest_slot, tile_a.digest),
        (b_root_slot, tile_b.roots[0]),
    ] {
        for lane in 0..2 {
            let pt: Vec<F128> = (0..w_log)
                .map(|bb| {
                    if (slot >> bb) & 1 == 1 {
                        F128::ONE
                    } else {
                        F128::ZERO
                    }
                })
                .collect();
            native_pending.push(NativePending {
                point: pt,
                value: dig[lane],
            });
        }
    }

    // ---- IO slice + public-IO discharge. ------------------------------------
    assert_eq!(pending.len(), native_pending.len(), "claim count lockstep");
    let lanes_per_claim = w_log + 1;
    let io_len = pending.len() * lanes_per_claim;
    let io_log = io_len.next_power_of_two().trailing_zeros() as usize;
    let mut io_values = Vec::with_capacity(io_len);
    for nc in &native_pending {
        assert_eq!(nc.point.len(), w_log, "native point arity");
        io_values.extend_from_slice(&nc.point);
        io_values.push(nc.value);
    }
    let (io_slice, io_wires) = alloc_column_slice(&mut b, &io_values, io_log);
    for (ci, claim) in pending.iter().enumerate() {
        let base = ci * lanes_per_claim;
        for (k, pt) in claim.point.iter().enumerate() {
            pin_eq(&mut b, pt, &io_wires[base + k]);
        }
        pin_eq(&mut b, &claim.value, &io_wires[base + w_log]);
    }
    let spec = PublicIoSpec {
        io_slice,
        io_len,
        claims: pending
            .iter()
            .enumerate()
            .map(|(ci, claim)| IoClaimSpec {
                slice: slices[claim.col].0,
                point: ci * lanes_per_claim..ci * lanes_per_claim + w_log,
                value: ci * lanes_per_claim + w_log,
            })
            .collect(),
    };

    // ---- The real proof (memory guard: the gate is two tiny families). ------
    let n_wires = b.num_wires();
    eprintln!("[region-union] wires before build = {n_wires}");
    assert!(n_wires < (1usize << 20), "wire guard {n_wires}");
    let (r1cs, z) = b.build();
    assert!(r1cs.satisfies(&z), "honest union trace unsatisfiable");
    let params = PcsParams {
        m: r1cs.m + pcs::LOG_PACKING,
        log_inv_rate: 2,
        log_batch_size: 2,
        profile: Default::default(),
    };
    let mut ch_p = FsLaneChallenger::new(OUTER_DOMAIN);
    let (proof, commitment, _) = noid_ivc_prover::field_prover::prove_field_with_public_io(
        &r1cs, &z, &params, &spec, &io_values, &mut ch_p,
    );
    let mut ch_v = FsLaneChallenger::new(OUTER_DOMAIN);
    noid_ivc_core::verifier::verify_field_with_public_io(
        &r1cs,
        &commitment,
        &proof,
        &spec,
        &io_values,
        &mut ch_v,
    )
    .expect("the region union-primitive slot proof verifies");

    eprintln!(
        "[region-union] rows = {} (m = {}), wires = {}, opening claims = {}, sub claims = {}",
        z.len(),
        r1cs.m,
        z.len(),
        spec.claims.len(),
        n_sub_claims,
    );

    // ---- Negative 1: flip an A input symbol. --------------------------------
    // A.IN0 slot 4 is the source-leaf column-hash input; the substitution has a
    // direct opening claim on A.IN0. The trace stays satisfiable (committed
    // columns are free wires) but that opening claim is now false → PCS rejects.
    {
        let mut bad_z = z.clone();
        let a_in0 = slices[A_IN0].0;
        bad_z[a_in0.start() + 4] += F128::ONE;
        assert!(r1cs.satisfies(&bad_z), "columns are free wires");
        let mut ch_p = FsLaneChallenger::new(OUTER_DOMAIN);
        let (bad_proof, bad_commitment, _) =
            noid_ivc_prover::field_prover::prove_field_with_public_io(
                &r1cs, &bad_z, &params, &spec, &io_values, &mut ch_p,
            );
        let mut ch_v = FsLaneChallenger::new(OUTER_DOMAIN);
        assert!(
            noid_ivc_core::verifier::verify_field_with_public_io(
                &r1cs,
                &bad_commitment,
                &bad_proof,
                &spec,
                &io_values,
                &mut ch_v,
            )
            .is_err(),
            "a flipped A input symbol must break its opening claim"
        );
    }

    // ---- Negative 2: flip a B sibling. --------------------------------------
    // B.SIB0's first live cell is at meta slot stride_a (B node 0 even slot).
    // The Merkle substitution has a direct opening claim on B.SIB0 → PCS rejects.
    {
        let mut bad_z = z.clone();
        let b_sib0 = slices[B_SIB0].0;
        bad_z[b_sib0.start() + stride_a] += F128::ONE;
        assert!(r1cs.satisfies(&bad_z), "columns are free wires");
        let mut ch_p = FsLaneChallenger::new(OUTER_DOMAIN);
        let (bad_proof, bad_commitment, _) =
            noid_ivc_prover::field_prover::prove_field_with_public_io(
                &r1cs, &bad_z, &params, &spec, &io_values, &mut ch_p,
            );
        let mut ch_v = FsLaneChallenger::new(OUTER_DOMAIN);
        assert!(
            noid_ivc_core::verifier::verify_field_with_public_io(
                &r1cs,
                &bad_commitment,
                &bad_proof,
                &spec,
                &io_values,
                &mut ch_v,
            )
            .is_err(),
            "a flipped B sibling must break its opening claim"
        );
    }
}
