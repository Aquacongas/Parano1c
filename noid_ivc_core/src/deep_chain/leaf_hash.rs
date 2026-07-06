//! Flat-basis replays of the wallet-capsule query-leaf hash schedules.
//!
//! Each FRI/source query opens a LEAF whose hash is a fixed chain of
//! `hash_pair`/`compress` over the queried symbols plus class-constant
//! metadata (domain tag, `log_rows`, `n_cols`, leaf index). The region layer
//! proves these chains with a deep-chain family (the item-3 clone of
//! `MerklePathFamily`); this module is the native flat-basis replay the
//! family and its gate are built against — the same single-basis convention
//! as [`super::source_tree`] (φ only at the symbol/digest boundary, every
//! interior lane a plain flat wire).

use crate::deep_chain::source_tree::{compress_iv_flat, flat_compress, flat_hash_pair, run_perm};
use crate::deep_chain::schedule::flat_of_tower_u128;
use crate::field::F128;
use noid_poseidon2b::native::permutation::STATE_SIZE;

/// Domain tag for encoded-source leaf hashes — the flat image of
/// `noid_fri_binius::interleaved_commit::SOURCE_LEAF_DOMAIN`. Kept in sync
/// with the native constant; a mismatch only yields honest-rejected proofs.
pub const SOURCE_LEAF_DOMAIN: u128 = 0xF21B_1D50_0000_0001u128;

/// Flat lane of a tower `u128` bit pattern (class-constant metadata and
/// queried symbols cross the region boundary through this linear map).
#[inline]
pub fn flat_lane(v: u128) -> F128 {
    flat_of_tower_u128(v)
}

/// Flat-basis replay of `source_leaf_hash(log_rows, n_cols, leaf_index,
/// symbols)`:
///
/// ```text
///   acc  = hash_pair(DOMAIN, log_rows)
///   meta = hash_pair(n_cols, leaf_index)
///   acc  = compress(acc, meta)
///   for k in 0..n_cols:  acc = compress(acc, hash_pair(sym[2k], sym[2k+1]))
/// ```
///
/// `symbols` are the `2·n_cols` queried codeword lanes already in the flat
/// basis. `log_rows`, `n_cols`, `leaf_index` are class/query metadata (their
/// flat images are formed here). Matches the native tower `source_leaf_hash`
/// under φ. Returns the leaf digest's two flat lanes.
pub fn flat_source_leaf_hash(
    log_rows: usize,
    n_cols: usize,
    leaf_index: usize,
    symbols: &[F128],
) -> [F128; 2] {
    assert_eq!(symbols.len(), n_cols * 2, "source leaf symbol count");
    let iv = compress_iv_flat();

    let acc = flat_hash_pair(flat_lane(SOURCE_LEAF_DOMAIN), flat_lane(log_rows as u128));
    let meta = flat_hash_pair(flat_lane(n_cols as u128), flat_lane(leaf_index as u128));
    let mut acc = flat_compress(iv, acc, meta);
    for k in 0..n_cols {
        let ph = flat_hash_pair(symbols[2 * k], symbols[2 * k + 1]);
        acc = flat_compress(iv, acc, ph);
    }
    acc
}

/// One source-leaf chain family instance. `n_cols` queried column pairs; the
/// per-leaf schedule occupies `4 + 3·n_cols` permutation slots (2 initial
/// `hash_pair`s + 1 two-slot `compress`, then per column a `hash_pair` + a
/// two-slot `compress`).
#[derive(Clone, Copy, Debug)]
pub struct SourceLeafChain {
    pub n_cols: usize,
}

impl SourceLeafChain {
    pub fn slots(&self) -> usize {
        4 + 3 * self.n_cols
    }
    pub fn stride(&self) -> usize {
        self.slots().next_power_of_two()
    }
    /// The slot holding the final accumulator (the leaf digest, `C0/C1`).
    pub fn digest_slot(&self) -> usize {
        3 + 3 * self.n_cols
    }
}

/// Flat-basis region columns of one source-leaf chain: every schedule slot's
/// permutation. `c[j][slot]` is the output state; the leaf digest is
/// `C0/C1` at [`SourceLeafChain::digest_slot`].
///
/// Slot roles (uniform distance-2 carry, matching the tree's `compress`
/// convention): `0` = `hash_pair(DOMAIN, log_rows)`, `1` =
/// `hash_pair(n_cols, leaf_index)`, `2/3` = the first `compress` (even
/// absorbs `acc0 = C(w−2)` on a fresh IV, odd feeds the even output forward
/// and absorbs `meta = C(w−2)`); then per column `k`: slot `4+3k` =
/// `hash_pair(sym[2k], sym[2k+1])`, `5+3k`/`6+3k` = the `compress` (even
/// absorbs the running `acc = C(w−2)`, odd absorbs `ph_k = C(w−2)`). Both
/// the acc-into-even and the hash-into-odd reads are exactly two slots back.
pub struct SourceLeafColumns {
    pub c: [Vec<F128>; STATE_SIZE],
    pub s0: [Vec<F128>; STATE_SIZE],
    pub s_out: [Vec<F128>; STATE_SIZE],
    /// The two `hash_pair` input lanes at each hash-pair slot (0 elsewhere) —
    /// the committed `IN0/IN1` columns the substitution reads.
    pub in_: [Vec<F128>; 2],
    pub digest: [F128; 2],
}

/// Replay one source-leaf chain in the flat basis and fill the region
/// columns. `symbols` are the `2·n_cols` queried flat lanes. The recomputed
/// digest matches [`flat_source_leaf_hash`] (hence native `source_leaf_hash`
/// under φ).
pub fn build_source_leaf_columns(
    chain: &SourceLeafChain,
    log_rows: usize,
    leaf_index: usize,
    symbols: &[F128],
    w_log: usize,
) -> SourceLeafColumns {
    let w = 1usize << w_log;
    assert!(w >= chain.slots(), "slot domain below the chain");
    assert_eq!(symbols.len(), chain.n_cols * 2, "source leaf symbol count");
    let iv = compress_iv_flat();

    let mut c: [Vec<F128>; STATE_SIZE] = std::array::from_fn(|_| vec![F128::ZERO; w]);
    let mut s0: [Vec<F128>; STATE_SIZE] = std::array::from_fn(|_| vec![F128::ZERO; w]);
    let mut s_out: [Vec<F128>; STATE_SIZE] = std::array::from_fn(|_| vec![F128::ZERO; w]);

    // Copy-only store: the permutation is run by the caller, so the ghost
    // fill runs `perm([0;4])` ONCE (not per slot) and active slots are permed
    // exactly once each (single-pass, matching `source_tree`).
    let mut store = |slot: usize,
                     s0v: [F128; STATE_SIZE],
                     outv: [F128; STATE_SIZE],
                     c: &mut [Vec<F128>; STATE_SIZE]| {
        for j in 0..STATE_SIZE {
            s0[j][slot] = s0v[j];
            s_out[j][slot] = outv[j];
            c[j][slot] = outv[j];
        }
    };

    // Ghost default so the walk stays consistent on unused slots (raw = 0):
    // one perm, broadcast to every slot; active slots overwritten below.
    let (ghost_s0, ghost_out) = run_perm([F128::ZERO; STATE_SIZE]);
    for slot in 0..w {
        store(slot, ghost_s0, ghost_out, &mut c);
    }

    // Initial block.
    let (a, b) = run_perm([
        flat_lane(SOURCE_LEAF_DOMAIN),
        flat_lane(log_rows as u128),
        F128::ZERO,
        F128::ZERO,
    ]);
    store(0, a, b, &mut c);
    let (a, b) = run_perm([
        flat_lane(chain.n_cols as u128),
        flat_lane(leaf_index as u128),
        F128::ZERO,
        F128::ZERO,
    ]);
    store(1, a, b, &mut c);
    // compress(acc0 = C(0), meta = C(1)).
    let acc0 = [c[0][0], c[1][0]];
    let (a, b) = run_perm([acc0[0], acc0[1], iv[0], iv[1]]);
    store(2, a, b, &mut c);
    let even_out: [F128; STATE_SIZE] = std::array::from_fn(|j| c[j][2]);
    let meta = [c[0][1], c[1][1]];
    let (a, b) = run_perm([
        even_out[0] + meta[0],
        even_out[1] + meta[1],
        even_out[2],
        even_out[3],
    ]);
    store(3, a, b, &mut c);

    // Per-column steps.
    for k in 0..chain.n_cols {
        let hp = 4 + 3 * k;
        let ev = 5 + 3 * k;
        let od = 6 + 3 * k;
        let (a, b) = run_perm([symbols[2 * k], symbols[2 * k + 1], F128::ZERO, F128::ZERO]);
        store(hp, a, b, &mut c);
        let acc = [c[0][ev - 2], c[1][ev - 2]]; // running acc, two slots back
        let (a, b) = run_perm([acc[0], acc[1], iv[0], iv[1]]);
        store(ev, a, b, &mut c);
        let even_out: [F128; STATE_SIZE] = std::array::from_fn(|j| c[j][ev]);
        let ph = [c[0][od - 2], c[1][od - 2]]; // ph_k = the hash_pair output, two slots back
        let (a, b) = run_perm([
            even_out[0] + ph[0],
            even_out[1] + ph[1],
            even_out[2],
            even_out[3],
        ]);
        store(od, a, b, &mut c);
    }

    // The committed hash_pair input columns (0 outside hash-pair slots).
    let mut in_: [Vec<F128>; 2] = std::array::from_fn(|_| vec![F128::ZERO; w]);
    in_[0][0] = flat_lane(SOURCE_LEAF_DOMAIN);
    in_[1][0] = flat_lane(log_rows as u128);
    in_[0][1] = flat_lane(chain.n_cols as u128);
    in_[1][1] = flat_lane(leaf_index as u128);
    for k in 0..chain.n_cols {
        let hp = 4 + 3 * k;
        in_[0][hp] = symbols[2 * k];
        in_[1][hp] = symbols[2 * k + 1];
    }

    let d = chain.digest_slot();
    let digest = [c[0][d], c[1][d]];
    SourceLeafColumns {
        c,
        s0,
        s_out,
        in_,
        digest,
    }
}

// ---------------------------------------------------------------------------
// Region wiring: refs, fixed patterns, substitution terms
// ---------------------------------------------------------------------------

use crate::deep_chain::relations::{ColRef, FixedPattern, RelationTerm};
use crate::deep_chain::source_tree::mds_weights_pub;

/// Column/pattern indices of one source-leaf chain. Committed column order
/// `IN0, IN1, C0..C3`; pattern order `HP, EVEN, ODD, IV0, IV1`.
#[derive(Clone, Copy, Debug)]
pub struct SourceLeafRefs {
    pub in_: [usize; 2],
    pub c: [usize; STATE_SIZE],
    pub hp: usize,
    pub even: usize,
    pub odd: usize,
    pub iv: [usize; 2],
}

pub fn source_leaf_refs(col_base: usize, fixed_base: usize) -> SourceLeafRefs {
    SourceLeafRefs {
        in_: [col_base, col_base + 1],
        c: std::array::from_fn(|i| col_base + 2 + i),
        hp: fixed_base,
        even: fixed_base + 1,
        odd: fixed_base + 2,
        iv: [fixed_base + 3, fixed_base + 4],
    }
}

/// Role of a slot in the per-leaf schedule.
fn slot_role(chain: &SourceLeafChain, slot: usize) -> u8 {
    // 0 = hash_pair, 1 = compress even, 2 = compress odd, 3 = ghost.
    if slot < 2 {
        0
    } else if slot == 2 {
        1
    } else if slot == 3 {
        2
    } else if slot < chain.slots() {
        match (slot - 4) % 3 {
            0 => 0,
            1 => 1,
            _ => 2,
        }
    } else {
        3
    }
}

/// The schedule selector/constant patterns over one `stride` period. `HP`,
/// `EVEN`, `ODD` mark the slot roles; `IV0/IV1` carry the compress capacity
/// IV at even slots. One period tiles per leaf, so the verifier's pattern
/// cost is leaf-count independent.
pub fn source_leaf_fixed_patterns(chain: &SourceLeafChain, iv_flat: [F128; 2]) -> Vec<FixedPattern> {
    let period = chain.stride();
    let low_log = period.trailing_zeros() as usize;
    let mut hp = vec![F128::ZERO; period];
    let mut even = vec![F128::ZERO; period];
    let mut odd = vec![F128::ZERO; period];
    let mut iv0 = vec![F128::ZERO; period];
    let mut iv1 = vec![F128::ZERO; period];
    for slot in 0..period {
        match slot_role(chain, slot) {
            0 => hp[slot] = F128::ONE,
            1 => {
                even[slot] = F128::ONE;
                iv0[slot] = iv_flat[0];
                iv1[slot] = iv_flat[1];
            }
            2 => odd[slot] = F128::ONE,
            _ => {}
        }
    }
    vec![
        FixedPattern::new(low_log, hp),
        FixedPattern::new(low_log, even),
        FixedPattern::new(low_log, odd),
        FixedPattern::new(low_log, iv0),
        FixedPattern::new(low_log, iv1),
    ]
}

/// Wiring substitution `Σ_j m_j·raw_j(w)` for the α-batched walk terminal.
/// The carry is uniformly two slots back (see [`build_source_leaf_columns`]):
///
/// ```text
///   raw_0 = HP·IN0 + EVEN·C0(w−2) + ODD·[C0(w−1) + C0(w−2)]
///   raw_1 = HP·IN1 + EVEN·C1(w−2) + ODD·[C1(w−1) + C1(w−2)]
///   raw_2 = IV0_pat + ODD·C2(w−1)
///   raw_3 = IV1_pat + ODD·C3(w−1)
/// ```
///
/// (`hash_pair` absorbs `IN0/IN1` on zero capacity; the compress even slot
/// absorbs the running acc `C(w−2)` on a fresh IV; the odd slot feeds the
/// even output `C(w−1)` forward and absorbs `C(w−2)` — the meta / column
/// hash.)
pub fn source_leaf_substitution_terms(refs: &SourceLeafRefs, alpha: F128) -> Vec<RelationTerm> {
    let m = mds_weights_pub(alpha);
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
            terms.push(RelationTerm {
                coeff: m[i],
                factors,
            });
        }
    }
    for j in 2..STATE_SIZE {
        terms.push(RelationTerm {
            coeff: m[j],
            factors: vec![ColRef::Fixed(refs.iv[j - 2])],
        });
        terms.push(RelationTerm {
            coeff: m[j],
            factors: vec![ColRef::Fixed(refs.odd), ColRef::CommittedShift(refs.c[j])],
        });
    }
    terms
}

// ---------------------------------------------------------------------------
// The high-fold pair leaf chain
// ---------------------------------------------------------------------------
//
// The mixed-open FRI layers open a `high_pair` leaf over the two coset-paired
// codeword symbols `s0, s1` (see `noid_fri_binius::mixed_open`). Its hash
// chain is topologically a `SourceLeafChain { n_cols: 1 }` — the same 7-slot
// schedule with the identical distance-2 carry, fixed patterns and wiring
// substitution — so the region family reuses `source_leaf_*` for geometry.
// Only the inputs differ:
//
// ```text
//   acc  = hash_pair(HIGH_PAIR_DOMAIN, layer_log)   // slot 0
//   meta = hash_pair(leaf_index, s0)                // slot 1  (s0 is a symbol!)
//   acc  = compress(acc, meta)                      // slots 2/3
//   pair = hash_pair(s0, s1)                         // slot 4
//   acc  = compress(acc, pair)                       // slots 5/6  (digest)
// ```
//
// Unlike the source leaf (whose slot-1 meta is pure metadata), the high-pair
// meta absorbs the queried symbol `s0`, and `s0` recurs as `IN0` at slot 4 —
// the assembly wires the same symbol wire into both lanes.

/// Domain tag for high-fold pair leaf hashes — the flat image of
/// `noid_fri_binius::mixed_open::HIGH_PAIR_DOMAIN`. Kept in sync with the
/// native constant; a mismatch only yields honest-rejected proofs.
pub const HIGH_PAIR_LEAF_DOMAIN: u128 = 0xF21B_1D50_0000_0002u128;

/// The slot geometry of a high-pair leaf chain — `SourceLeafChain { n_cols:
/// 1 }` (7 slots, digest at slot 6). Its fixed patterns / refs / substitution
/// are the source-leaf ones at `n_cols = 1`.
pub fn high_pair_leaf_chain() -> SourceLeafChain {
    SourceLeafChain { n_cols: 1 }
}

/// Flat-basis replay of `high_pair_leaf_hash(layer_log, leaf_index, s0, s1)`.
/// `s0, s1` are the two coset-paired queried codeword lanes already in the
/// flat basis; `layer_log`, `leaf_index` are class/query metadata. Matches the
/// native tower `high_pair_leaf_hash` under φ. Returns the leaf digest lanes.
pub fn flat_high_pair_leaf_hash(
    layer_log: usize,
    leaf_index: usize,
    s0: F128,
    s1: F128,
) -> [F128; 2] {
    let iv = compress_iv_flat();
    let acc = flat_hash_pair(flat_lane(HIGH_PAIR_LEAF_DOMAIN), flat_lane(layer_log as u128));
    let meta = flat_hash_pair(flat_lane(leaf_index as u128), s0);
    let acc = flat_compress(iv, acc, meta);
    let pair = flat_hash_pair(s0, s1);
    flat_compress(iv, acc, pair)
}

/// Flat-basis region columns of one high-pair leaf chain (same
/// [`SourceLeafColumns`] shape as the source leaf: every slot's permutation,
/// the committed `IN0/IN1` hash-pair inputs, the digest lanes). The recomputed
/// digest matches [`flat_high_pair_leaf_hash`] (native under φ).
pub fn build_high_pair_leaf_columns(
    layer_log: usize,
    leaf_index: usize,
    s0: F128,
    s1: F128,
    w_log: usize,
) -> SourceLeafColumns {
    let chain = high_pair_leaf_chain();
    let w = 1usize << w_log;
    assert!(w >= chain.slots(), "slot domain below the chain");
    let iv = compress_iv_flat();

    let mut c: [Vec<F128>; STATE_SIZE] = std::array::from_fn(|_| vec![F128::ZERO; w]);
    let mut s0c: [Vec<F128>; STATE_SIZE] = std::array::from_fn(|_| vec![F128::ZERO; w]);
    let mut s_out: [Vec<F128>; STATE_SIZE] = std::array::from_fn(|_| vec![F128::ZERO; w]);

    // Copy-only store (see build_source_leaf_columns): single-pass, the ghost
    // perm runs once and active slots are permed exactly once each.
    let mut store = |slot: usize,
                     s0v: [F128; STATE_SIZE],
                     outv: [F128; STATE_SIZE],
                     c: &mut [Vec<F128>; STATE_SIZE]| {
        for j in 0..STATE_SIZE {
            s0c[j][slot] = s0v[j];
            s_out[j][slot] = outv[j];
            c[j][slot] = outv[j];
        }
    };

    // Ghost default (raw = 0): one perm, broadcast; active slots overwritten.
    let (ghost_s0, ghost_out) = run_perm([F128::ZERO; STATE_SIZE]);
    for slot in 0..w {
        store(slot, ghost_s0, ghost_out, &mut c);
    }

    // acc = hash_pair(HIGH_PAIR_DOMAIN, layer_log).
    let (a, b) = run_perm([
        flat_lane(HIGH_PAIR_LEAF_DOMAIN),
        flat_lane(layer_log as u128),
        F128::ZERO,
        F128::ZERO,
    ]);
    store(0, a, b, &mut c);
    // meta = hash_pair(leaf_index, s0).
    let (a, b) = run_perm([flat_lane(leaf_index as u128), s0, F128::ZERO, F128::ZERO]);
    store(1, a, b, &mut c);
    // compress(acc0 = C(0), meta = C(1)).
    let acc0 = [c[0][0], c[1][0]];
    let (a, b) = run_perm([acc0[0], acc0[1], iv[0], iv[1]]);
    store(2, a, b, &mut c);
    let even_out: [F128; STATE_SIZE] = std::array::from_fn(|j| c[j][2]);
    let meta = [c[0][1], c[1][1]];
    let (a, b) = run_perm([
        even_out[0] + meta[0],
        even_out[1] + meta[1],
        even_out[2],
        even_out[3],
    ]);
    store(3, a, b, &mut c);
    // pair = hash_pair(s0, s1).
    let (a, b) = run_perm([s0, s1, F128::ZERO, F128::ZERO]);
    store(4, a, b, &mut c);
    // compress(acc = C(3), pair = C(4)).
    let acc = [c[0][3], c[1][3]];
    let (a, b) = run_perm([acc[0], acc[1], iv[0], iv[1]]);
    store(5, a, b, &mut c);
    let even_out: [F128; STATE_SIZE] = std::array::from_fn(|j| c[j][5]);
    let pair = [c[0][4], c[1][4]];
    let (a, b) = run_perm([
        even_out[0] + pair[0],
        even_out[1] + pair[1],
        even_out[2],
        even_out[3],
    ]);
    store(6, a, b, &mut c);

    // The committed hash_pair input columns (0 outside hash-pair slots).
    let mut in_: [Vec<F128>; 2] = std::array::from_fn(|_| vec![F128::ZERO; w]);
    in_[0][0] = flat_lane(HIGH_PAIR_LEAF_DOMAIN);
    in_[1][0] = flat_lane(layer_log as u128);
    in_[0][1] = flat_lane(leaf_index as u128);
    in_[1][1] = s0;
    in_[0][4] = s0;
    in_[1][4] = s1;

    let d = chain.digest_slot();
    let digest = [c[0][d], c[1][d]];
    SourceLeafColumns {
        c,
        s0: s0c,
        s_out,
        in_,
        digest,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::challenger::{Challenger, FsLaneChallenger};
    use crate::deep_chain::relations::{
        claimed_refs, prove_column_relation, prove_shift_discharge, prove_shift_discharge_pow2,
        verify_column_relation, verify_shift_discharge, verify_shift_discharge_pow2, ColRef,
        RelationColumns,
    };
    use crate::deep_chain::schedule::carry_selection_terms;
    use crate::deep_chain::source_tree::compress_iv_flat;
    use crate::deep_chain::{prove_deep_chain_walk, verify_deep_chain_walk, LaneClaimGroup};
    use crate::lincheck::build_eq_table;

    fn mle(col: &[F128], point: &[F128]) -> F128 {
        let eq = build_eq_table(point);
        let mut acc = F128::ZERO;
        for (v, e) in col.iter().zip(eq.iter()) {
            acc += *v * *e;
        }
        acc
    }

    /// Run the full region DAG for one or more tiled leaf chains of the given
    /// geometry over the supplied (global) column data (source-leaf and
    /// high-pair share this — their wiring, patterns and substitution are
    /// identical, only the column contents differ). ONE carry-selection, ONE
    /// walk and ONE substitution cover every tile; `pins` gives each tile's
    /// `(global digest slot, honest digest)` — pass the honest digest so a
    /// corrupted `c` column is caught by the pin. The fixed patterns are
    /// periodic with period = one tile's stride, so the verifier cost is
    /// tile-count independent (the `[tx_hi | schedule_lo]` flatness property).
    fn run_leaf_dag(
        chain: &SourceLeafChain,
        in0: &[F128],
        in1: &[F128],
        c: &[Vec<F128>; STATE_SIZE],
        s0: &[Vec<F128>; STATE_SIZE],
        s_out: &[Vec<F128>; STATE_SIZE],
        pins: &[(usize, [F128; 2])],
        w_log: usize,
    ) -> Result<(), String> {
        let iv = compress_iv_flat();
        let fixed = source_leaf_fixed_patterns(chain, iv);
        let refs = source_leaf_refs(0, 0);

        let committed: Vec<&[F128]> = vec![in0, in1, &c[0], &c[1], &c[2], &c[3]];
        let internal: Vec<&[F128]> = s_out.iter().map(|c| c.as_slice()).collect();
        let mut ch_p = FsLaneChallenger::new(b"leaf-dag");
        let mut ch_v = FsLaneChallenger::new(b"leaf-dag");
        let mut pending: Vec<(usize, Vec<F128>, F128)> = Vec::new();

        // carry selection → walk group.
        let beta = ch_p.sample_f128();
        assert_eq!(beta, ch_v.sample_f128());
        let sel_terms = carry_selection_terms(&refs.c, beta);
        let rho: Vec<F128> = ch_p.sample_f128_vec(w_log);
        let _ = ch_v.sample_f128_vec(w_log);
        let (sp, _, _) = prove_column_relation(
            F128::ZERO,
            &rho,
            &sel_terms,
            &RelationColumns { committed: &committed, internal: &internal, fixed: &fixed },
            &mut ch_p,
        );
        let sel_point =
            verify_column_relation(w_log, F128::ZERO, &rho, &sel_terms, &fixed, &sp, &mut ch_v)
                .map_err(|e| format!("selection: {e}"))?;
        let mut group_values = [F128::ZERO; STATE_SIZE];
        for (r, v) in claimed_refs(&sel_terms).iter().zip(sp.final_values.iter()) {
            match r {
                ColRef::Committed(cc) => pending.push((*cc, sel_point.clone(), *v)),
                ColRef::Internal(j) => group_values[*j] = *v,
                _ => unreachable!(),
            }
        }

        // walk.
        let groups = vec![LaneClaimGroup { point: sel_point.clone(), values: group_values }];
        let (wp, _) = prove_deep_chain_walk(s0, &groups, &mut ch_p);
        let terminal = verify_deep_chain_walk(w_log, &groups, &wp, &mut ch_v)
            .map_err(|e| format!("walk: {e}"))?;

        // substitution.
        let alpha = ch_p.sample_f128();
        assert_eq!(alpha, ch_v.sample_f128());
        let sub_terms = source_leaf_substitution_terms(&refs, alpha);
        let mut target = F128::ZERO;
        let mut p = F128::ONE;
        for e in 0..STATE_SIZE {
            p = p * alpha;
            target += p * terminal.values[e];
        }
        let (subp, _, _) = prove_column_relation(
            target,
            &terminal.point,
            &sub_terms,
            &RelationColumns { committed: &committed, internal: &[], fixed: &fixed },
            &mut ch_p,
        );
        let sub_point =
            verify_column_relation(w_log, target, &terminal.point, &sub_terms, &fixed, &subp, &mut ch_v)
                .map_err(|e| format!("substitution: {e}"))?;
        for (r, v) in claimed_refs(&sub_terms).iter().zip(subp.final_values.iter()) {
            match r {
                ColRef::Committed(cc) => pending.push((*cc, sub_point.clone(), *v)),
                ColRef::CommittedShift(cc) => {
                    let (pr, _) = prove_shift_discharge(committed[*cc], &sub_point, *v, &mut ch_p);
                    let pt = verify_shift_discharge(w_log, &sub_point, *v, &pr, &mut ch_v)
                        .map_err(|e| format!("shift: {e}"))?;
                    pending.push((*cc, pt, pr.final_value));
                }
                ColRef::CommittedShift2(cc) => {
                    let (pr, _) =
                        prove_shift_discharge_pow2(committed[*cc], &sub_point, *v, 1, &mut ch_p);
                    let pt = verify_shift_discharge_pow2(w_log, &sub_point, *v, 1, &pr, &mut ch_v)
                        .map_err(|e| format!("shift2: {e}"))?;
                    pending.push((*cc, pt, pr.final_value));
                }
                _ => unreachable!(),
            }
        }

        assert_eq!(ch_p.sample_f128(), ch_v.sample_f128(), "lockstep");

        for (cc, pt, v) in &pending {
            if mle(committed[*cc], pt) != *v {
                return Err(format!("claim on column {cc} is false"));
            }
        }
        // Per-tile digest pins.
        for (slot, dig) in pins {
            let digest_point: Vec<F128> = (0..w_log)
                .map(|bb| if (slot >> bb) & 1 == 1 { F128::ONE } else { F128::ZERO })
                .collect();
            if mle(&c[0], &digest_point) != dig[0] || mle(&c[1], &digest_point) != dig[1] {
                return Err(format!("digest pin mismatch at slot {slot}"));
            }
        }
        Ok(())
    }

    /// Tile `tiles` independent source-leaf chains into one global column set
    /// at `[tx_hi | schedule_lo]` stride (tile t at slots `[t·stride,
    /// (t+1)·stride)`). The per-tile distance-2 carry stays within its tile
    /// (slots 0/1 are hash-pairs that read no carry; the compresses read at
    /// most two slots back, within the tile), so the tiles compose into one
    /// walk with no cross-tile coupling. `tiles.len()` must be a power of two
    /// and exactly fill the domain. Returns the global columns and each
    /// tile's digest.
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

    /// The `[tx_hi | schedule_lo]` tiling: K source-leaf chains (distinct
    /// shapes/symbols) tiled into ONE column set, discharged by ONE
    /// carry-selection + ONE walk + ONE substitution with the per-tile fixed
    /// patterns (period = one tile's stride). Every tile's digest is pinned;
    /// honest run verifies, and corrupting one tile's symbol is caught — the
    /// single relation set covers all tiles, and its verifier cost does not
    /// grow with tile count (the flatness property [G] is built on).
    #[test]
    fn tiled_source_leaf_one_walk_one_relation() {
        let n_cols = 3usize;
        let chain = SourceLeafChain { n_cols };
        let stride_log = chain.stride().trailing_zeros() as usize;
        let num_tiles = 4usize; // power of two
        let global_w_log = stride_log + num_tiles.trailing_zeros() as usize;
        let stride = chain.stride();

        let mut seed = 0x71_1E_u64;
        let mut next = || {
            seed = seed.wrapping_add(0x9E3779B97F4A7C15);
            let mut z = seed;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
            z ^= z >> 31;
            F128 { lo: z, hi: z.rotate_left(23) }
        };
        // Distinct (log_rows, leaf_index, symbols) per tile — the schedule is
        // the same, only the witness contents differ across txs.
        let tiles: Vec<(usize, usize, Vec<F128>)> = (0..num_tiles)
            .map(|t| {
                let symbols: Vec<F128> = (0..n_cols * 2).map(|_| next()).collect();
                (4 + t, 3 * t + 1, symbols)
            })
            .collect();
        let (cols, digests) = build_tiled_source_leaf(&chain, &tiles, global_w_log);

        let pins: Vec<(usize, [F128; 2])> = digests
            .iter()
            .enumerate()
            .map(|(t, &d)| (t * stride + chain.digest_slot(), d))
            .collect();

        run_leaf_dag(&chain, &cols.in_[0], &cols.in_[1], &cols.c, &cols.s0, &cols.s_out, &pins, global_w_log)
            .expect("tiled source-leaf DAG verifies with one walk + one relation set");

        // Corrupt tile 2's first column-hash symbol: exactly that tile's
        // wiring claim (and digest) breaks; the single relation set catches it.
        {
            let mut bad = cols.in_[0].clone();
            bad[2 * stride + 4] += F128::ONE;
            assert!(
                run_leaf_dag(&chain, &bad, &cols.in_[1], &cols.c, &cols.s0, &cols.s_out, &pins, global_w_log)
                    .is_err(),
                "corrupted tile symbol accepted"
            );
        }
    }

    /// The chain column replay's recomputed digest (from the distance-2
    /// carry slot layout) equals the direct `flat_source_leaf_hash` (hence
    /// native `source_leaf_hash` under φ) across shapes, and `c == s_out`
    /// (the digest columns are the walk outputs). This validates the slot
    /// layout the region DAG will wire.
    #[test]
    fn source_leaf_columns_digest_matches() {
        let mut seed = 0x5EEDu64;
        let mut next = || {
            seed = seed.wrapping_add(0x9E3779B97F4A7C15);
            let mut z = seed;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
            z ^= z >> 31;
            F128 {
                lo: z,
                hi: z.rotate_left(17),
            }
        };
        for (n_cols, log_rows, leaf_index) in [(1usize, 4usize, 0usize), (3, 6, 5), (4, 8, 37)] {
            let chain = SourceLeafChain { n_cols };
            let w_log = chain.stride().trailing_zeros() as usize;
            let symbols: Vec<F128> = (0..n_cols * 2).map(|_| next()).collect();
            let cols = build_source_leaf_columns(&chain, log_rows, leaf_index, &symbols, w_log);

            let direct = flat_source_leaf_hash(log_rows, n_cols, leaf_index, &symbols);
            assert_eq!(cols.digest, direct, "chain digest != flat_source_leaf_hash");
            for slot in 0..(1usize << w_log) {
                for j in 0..STATE_SIZE {
                    assert_eq!(cols.c[j][slot], cols.s_out[j][slot]);
                }
            }
        }
    }

    /// The full region DAG for one source-leaf chain: carry-selection seeds
    /// the walk from the committed digests, the walk verifies every slot's
    /// permutation, the substitution ties the walk input to the distance-2
    /// chain wiring (hash-pair inputs read plainly, acc and column-hash read
    /// two slots back, feed-forward one slot back), and the digest pins to
    /// C0/C1 at the final slot. Honest run discharges every claim true; a
    /// corrupted input / output lane is caught.
    #[test]
    fn source_leaf_region_dag_roundtrip_and_negatives() {
        let n_cols = 3usize;
        let chain = SourceLeafChain { n_cols };
        let w_log = chain.stride().trailing_zeros() as usize;
        let (log_rows, leaf_index) = (6usize, 5usize);

        let mut seed = 0xA5A5u64;
        let mut next = || {
            seed = seed.wrapping_add(0x9E3779B97F4A7C15);
            let mut z = seed;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
            z ^= z >> 31;
            F128 { lo: z, hi: z.rotate_left(29) }
        };
        let symbols: Vec<F128> = (0..n_cols * 2).map(|_| next()).collect();
        let cols = build_source_leaf_columns(&chain, log_rows, leaf_index, &symbols, w_log);

        run_leaf_dag(&chain, &cols.in_[0], &cols.in_[1], &cols.c, &cols.s0, &cols.s_out, &[(chain.digest_slot(), cols.digest)], w_log)
            .expect("honest source leaf DAG verifies");

        // A corrupted symbol input breaks a claim.
        {
            let mut bad = cols.in_[0].clone();
            bad[4] += F128::ONE; // first column hash_pair input
            assert!(
                run_leaf_dag(&chain, &bad, &cols.in_[1], &cols.c, &cols.s0, &cols.s_out, &[(chain.digest_slot(), cols.digest)], w_log)
                    .is_err(),
                "corrupted IN accepted"
            );
        }
        // A corrupted output digest lane breaks the walk/digest.
        {
            let mut bad = cols.c.clone();
            bad[0][chain.digest_slot()] += F128::ONE;
            assert!(
                run_leaf_dag(&chain, &cols.in_[0], &cols.in_[1], &bad, &cols.s0, &cols.s_out, &[(chain.digest_slot(), cols.digest)], w_log)
                    .is_err(),
                "corrupted C accepted"
            );
        }
    }

    /// The high-pair leaf column replay's recomputed digest equals the direct
    /// [`flat_high_pair_leaf_hash`] (hence native `high_pair_leaf_hash` under
    /// φ) across shapes, and `c == s_out`.
    #[test]
    fn high_pair_leaf_columns_digest_matches() {
        let mut seed = 0xB19Eu64;
        let mut next = || {
            seed = seed.wrapping_add(0x9E3779B97F4A7C15);
            let mut z = seed;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
            z ^= z >> 31;
            F128 { lo: z, hi: z.rotate_left(19) }
        };
        let chain = high_pair_leaf_chain();
        let w_log = chain.stride().trailing_zeros() as usize;
        for (layer_log, leaf_index) in [(4usize, 0usize), (6, 5), (8, 37)] {
            let (s0, s1) = (next(), next());
            let cols = build_high_pair_leaf_columns(layer_log, leaf_index, s0, s1, w_log);
            let direct = flat_high_pair_leaf_hash(layer_log, leaf_index, s0, s1);
            assert_eq!(cols.digest, direct, "chain digest != flat_high_pair_leaf_hash");
            for slot in 0..(1usize << w_log) {
                for j in 0..STATE_SIZE {
                    assert_eq!(cols.c[j][slot], cols.s_out[j][slot]);
                }
            }
        }
    }

    /// The high-pair leaf region DAG reuses the source-leaf wiring (identical
    /// 7-slot schedule / distance-2 carry) over the high-pair columns: honest
    /// run discharges every claim, a corrupted symbol lane (which recurs in
    /// both the meta and the pair hash-pair) and a corrupted digest are caught.
    #[test]
    fn high_pair_leaf_region_dag_roundtrip_and_negatives() {
        let chain = high_pair_leaf_chain();
        let w_log = chain.stride().trailing_zeros() as usize;
        let (layer_log, leaf_index) = (6usize, 5usize);
        let (s0, s1) = (
            F128 { lo: 0x1234_5678, hi: 0x9ABC_DEF0 },
            F128 { lo: 0x0FED_CBA9, hi: 0x8765_4321 },
        );
        let cols = build_high_pair_leaf_columns(layer_log, leaf_index, s0, s1, w_log);

        run_leaf_dag(&chain, &cols.in_[0], &cols.in_[1], &cols.c, &cols.s0, &cols.s_out, &[(chain.digest_slot(), cols.digest)], w_log)
            .expect("honest high-pair leaf DAG verifies");

        // The symbol s0 sits at slot 1 (meta, IN1) and slot 4 (pair, IN0):
        // corrupting either input lane must break a claim.
        {
            let mut bad = cols.in_[1].clone();
            bad[1] += F128::ONE; // s0 in the meta hash_pair
            assert!(
                run_leaf_dag(&chain, &cols.in_[0], &bad, &cols.c, &cols.s0, &cols.s_out, &[(chain.digest_slot(), cols.digest)], w_log)
                    .is_err(),
                "corrupted meta symbol accepted"
            );
        }
        {
            let mut bad = cols.in_[1].clone();
            bad[4] += F128::ONE; // s1 in the pair hash_pair
            assert!(
                run_leaf_dag(&chain, &cols.in_[0], &bad, &cols.c, &cols.s0, &cols.s_out, &[(chain.digest_slot(), cols.digest)], w_log)
                    .is_err(),
                "corrupted pair symbol accepted"
            );
        }
        {
            let mut bad = cols.c.clone();
            bad[1][chain.digest_slot()] += F128::ONE;
            assert!(
                run_leaf_dag(&chain, &cols.in_[0], &cols.in_[1], &bad, &cols.s0, &cols.s_out, &[(chain.digest_slot(), cols.digest)], w_log)
                    .is_err(),
                "corrupted digest accepted"
            );
        }
    }
}
