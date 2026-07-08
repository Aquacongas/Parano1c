//! Flat-basis replay of the tx-body SPINE — the canonical Standard4x8
//! transaction-body hash — as two deep-chain region families.
//!
//! The native spine (59 Poseidon2b permutations per transaction: 4 input
//! leaves × 3, 8 output leaves × 2, 15 binary `compress` nodes × 2, one
//! wrap) decomposes into:
//!
//! - the **leaf/wrap TILE** (32 slots): the 12 leaf sub-sponges laid out
//!   contiguously plus the wrap permutation, one absorb block per slot
//!   through committed `IN0/IN1` lanes, a distance-1 `CHAIN` carry at
//!   every non-head slot and a per-slot IV pattern carrying the head
//!   capacity IVs (`TAG_LEAF` at input heads, `TAG_OUTLEAF` at output
//!   heads, `TAG_TXBODY` at the wrap). This is exactly the slot-leaf
//!   sponge shape ([`super::leaf_hash::sponge_leaf_substitution_terms`])
//!   with a richer pattern table, so the union reuses those terms.
//! - the **TREE** (64 slots): the 16-leaf binary compress tree in the
//!   [`super::source_tree`] heap layout (node `h` at slots `2h`/`2h+1`,
//!   `KID_i[w] = C_i(2w+1)`), with the LEAF level external: leaf slots
//!   are ghost permutations, the 16 leaf digests enter through the KID
//!   column (bound upstream by cell pins to the tile digests and the
//!   statement lanes), and the KID↔C exposure is GATED to internal
//!   children (`w ∈ [2, L)`). The substitution is the source-tree one
//!   with an all-zero `LEAFODD` pattern (no leaf permutations).
//!
//! Tree leaf order (the canonical tx-body layout): `L0 = epoch_anchor`,
//! `L1 = fee_leaf`, `L2..L5 = input-leaf digests`, `L6..L13 = output-leaf
//! digests`, `L14 = is_coinbase_leaf`, `L15 = pad_leaf`.
//!
//! # Basis
//!
//! Same single-basis convention as the other families: the tower
//! permutation equals `flat→tower ∘ permute_flat ∘ tower→flat` and φ is
//! F2-linear, so the whole spine runs in the flat basis with φ applied
//! only at the statement boundary. The absorbed data is public tx-body
//! statement (slots / values / owner address lanes); no wallet secret
//! ever enters these columns.

use crate::deep_chain::relations::{ColRef, FixedPattern, RelationTerm};
use crate::deep_chain::schedule::flat_of_tower_u128;
use crate::deep_chain::source_tree::{run_perm, SourceTree};
use crate::field::F128;
use noid_poseidon2b::native::domain::{
    capacity_iv_flat, TAG_COMPRESS, TAG_LEAF, TAG_OUTLEAF, TAG_TXBODY,
};
use noid_poseidon2b::native::permutation::STATE_SIZE;

/// Leaf/wrap tile geometry: 4 input chains × 3 slots + 8 output chains ×
/// 2 slots + 1 wrap + 3 ghost slots = one 32-slot tile per transaction.
pub const SPINE_N_INPUT_LEAVES: usize = 4;
pub const SPINE_N_OUTPUT_LEAVES: usize = 8;
pub const SPINE_TILE_SLOTS: usize = 32;
/// In-tile base of output chain `o` (input chain `c` is at `3c`).
pub const SPINE_TILE_OUTPUT_BASE: usize = 3 * SPINE_N_INPUT_LEAVES;
/// In-tile slot of the wrap permutation.
pub const SPINE_TILE_WRAP_SLOT: usize =
    SPINE_TILE_OUTPUT_BASE + 2 * SPINE_N_OUTPUT_LEAVES;
/// Slots `[0, SPINE_TILE_ACTIVE)` run real permutations; the rest are ghost.
pub const SPINE_TILE_ACTIVE: usize = SPINE_TILE_WRAP_SLOT + 1;

/// The 16-leaf compress tree in the source-tree heap layout.
pub const SPINE_TREE_LEAVES: usize = 16;
pub fn spine_tree() -> SourceTree {
    SourceTree { leaf_log: 4 }
}
/// Tree slots per transaction (`4·L = 64`).
pub const SPINE_TREE_SLOTS: usize = 4 * SPINE_TREE_LEAVES;
/// KID positions `[SPINE_TREE_LEAVES, 2·SPINE_TREE_LEAVES)` carry the 16
/// external leaf digests; `[2, SPINE_TREE_LEAVES)` are the window-exposed
/// internal children.
pub const SPINE_TREE_KID_LEAF_BASE: usize = SPINE_TREE_LEAVES;

/// In-tile digest slot of input chain `c` (its third permutation).
#[inline]
pub const fn spine_input_digest_slot(c: usize) -> usize {
    3 * c + 2
}

/// In-tile digest slot of output chain `o` (its second permutation).
#[inline]
pub const fn spine_output_digest_slot(o: usize) -> usize {
    SPINE_TILE_OUTPUT_BASE + 2 * o + 1
}

fn iv_flat(tag: noid_poseidon2b::native::domain::DomainTag) -> [F128; 2] {
    let iv = capacity_iv_flat(tag);
    [
        F128 { lo: iv[0] as u64, hi: (iv[0] >> 64) as u64 },
        F128 { lo: iv[1] as u64, hi: (iv[1] >> 64) as u64 },
    ]
}

pub fn leaf_iv_flat() -> [F128; 2] {
    iv_flat(TAG_LEAF)
}
pub fn outleaf_iv_flat() -> [F128; 2] {
    iv_flat(TAG_OUTLEAF)
}
pub fn txbody_iv_flat() -> [F128; 2] {
    iv_flat(TAG_TXBODY)
}
pub fn spine_compress_iv_flat() -> [F128; 2] {
    iv_flat(TAG_COMPRESS)
}

/// The input-leaf padding flush block (`[0x80, 0x01 << 120]` tower), flat —
/// the third absorb of every input chain, a protocol constant.
pub fn spine_pad_absorb_flat() -> [F128; 2] {
    [
        flat_of_tower_u128(0x80u128),
        flat_of_tower_u128(0x01u128 << 120),
    ]
}

/// One transaction's spine statement in the flat basis: the exact
/// `SpineInputs` lanes under φ.
#[derive(Clone, Debug)]
pub struct SpineInstanceFlat {
    pub epoch_anchor: [F128; 2],
    pub fee_leaf: [F128; 2],
    pub input_leaves: [[F128; 4]; SPINE_N_INPUT_LEAVES],
    pub output_leaves: [[F128; 4]; SPINE_N_OUTPUT_LEAVES],
    pub is_coinbase_leaf: [F128; 2],
    pub pad_leaf: [F128; 2],
}

impl SpineInstanceFlat {
    /// The all-zero instance — the canonical GHOST spine that pads a
    /// chunk to its per-block capacity (a fully valid hash of the zero
    /// body; nothing downstream reads its digests).
    pub fn ghost() -> Self {
        Self {
            epoch_anchor: [F128::ZERO; 2],
            fee_leaf: [F128::ZERO; 2],
            input_leaves: [[F128::ZERO; 4]; SPINE_N_INPUT_LEAVES],
            output_leaves: [[F128::ZERO; 4]; SPINE_N_OUTPUT_LEAVES],
            is_coinbase_leaf: [F128::ZERO; 2],
            pad_leaf: [F128::ZERO; 2],
        }
    }
}

/// The filled region columns of ONE spine instance: the 32-slot tile and
/// the 64-slot tree, plus every joined value the assembly pins.
pub struct SpineInstanceColumns {
    // Tile (SPINE_TILE_SLOTS slots).
    pub tile_c: [Vec<F128>; STATE_SIZE],
    pub tile_s0: [Vec<F128>; STATE_SIZE],
    pub tile_s_out: [Vec<F128>; STATE_SIZE],
    pub tile_in: [Vec<F128>; 2],
    // Tree (SPINE_TREE_SLOTS slots).
    pub tree_c: [Vec<F128>; STATE_SIZE],
    pub tree_s0: [Vec<F128>; STATE_SIZE],
    pub tree_s_out: [Vec<F128>; STATE_SIZE],
    /// `kid[w]`, `w ∈ [0, 2L)`: internal children = `C(2w+1)`, leaf
    /// children = the external digests, `kid[0] = kid[1] = 0`.
    pub tree_kid: [Vec<F128>; 2],
    /// Input/output chain digests in tile order (4 inputs then 8 outputs).
    pub chain_digests: Vec<[F128; 2]>,
    /// The recomputed tree root (`C0/C1` at tree slot 3).
    pub root: [F128; 2],
    /// The wrap digest — `tx_body_hash` under φ.
    pub tx_hash: [F128; 2],
}

/// Replay one spine instance in the flat basis. Mirrors the GKR oracle's
/// `build_state_in` role-for-role: input chains `[p0,p1,IV_LEAF]` →
/// `+[p2,p3]` → `+PAD`; output chains `[p0,p1,IV_OUTLEAF]` → `+[p2,p3]`;
/// compress nodes `[left, IV_COMPRESS]` → `+right`; wrap
/// `[root, IV_TXBODY]`. Ghost slots run `perm([0;4])`.
pub fn build_spine_instance_columns(inst: &SpineInstanceFlat) -> SpineInstanceColumns {
    let iv_leaf = leaf_iv_flat();
    let iv_out = outleaf_iv_flat();
    let iv_wrap = txbody_iv_flat();
    let iv_comp = spine_compress_iv_flat();
    let pad = spine_pad_absorb_flat();

    // ---------------- Tile ----------------
    let mut tile_c: [Vec<F128>; STATE_SIZE] =
        std::array::from_fn(|_| vec![F128::ZERO; SPINE_TILE_SLOTS]);
    let mut tile_s0: [Vec<F128>; STATE_SIZE] =
        std::array::from_fn(|_| vec![F128::ZERO; SPINE_TILE_SLOTS]);
    let mut tile_s_out: [Vec<F128>; STATE_SIZE] =
        std::array::from_fn(|_| vec![F128::ZERO; SPINE_TILE_SLOTS]);
    let mut tile_in: [Vec<F128>; 2] =
        std::array::from_fn(|_| vec![F128::ZERO; SPINE_TILE_SLOTS]);

    let mut store_tile = |slot: usize,
                          s0v: [F128; STATE_SIZE],
                          outv: [F128; STATE_SIZE],
                          c: &mut [Vec<F128>; STATE_SIZE]| {
        for j in 0..STATE_SIZE {
            tile_s0[j][slot] = s0v[j];
            tile_s_out[j][slot] = outv[j];
            c[j][slot] = outv[j];
        }
    };

    // Ghost default (slots past SPINE_TILE_ACTIVE).
    let (ghost_s0, ghost_out) = run_perm([F128::ZERO; STATE_SIZE]);
    for slot in 0..SPINE_TILE_SLOTS {
        store_tile(slot, ghost_s0, ghost_out, &mut tile_c);
    }

    let mut chain_digests: Vec<[F128; 2]> =
        Vec::with_capacity(SPINE_N_INPUT_LEAVES + SPINE_N_OUTPUT_LEAVES);

    // Input chains: head [p0, p1, IV_LEAF]; +[p2, p3]; +PAD flush.
    for (ci, p) in inst.input_leaves.iter().enumerate() {
        let base = 3 * ci;
        let (a, o) = run_perm([p[0], p[1], iv_leaf[0], iv_leaf[1]]);
        store_tile(base, a, o, &mut tile_c);
        tile_in[0][base] = p[0];
        tile_in[1][base] = p[1];
        let prev: [F128; STATE_SIZE] = std::array::from_fn(|j| tile_c[j][base]);
        let (a, o) = run_perm([prev[0] + p[2], prev[1] + p[3], prev[2], prev[3]]);
        store_tile(base + 1, a, o, &mut tile_c);
        tile_in[0][base + 1] = p[2];
        tile_in[1][base + 1] = p[3];
        let prev: [F128; STATE_SIZE] = std::array::from_fn(|j| tile_c[j][base + 1]);
        let (a, o) = run_perm([prev[0] + pad[0], prev[1] + pad[1], prev[2], prev[3]]);
        store_tile(base + 2, a, o, &mut tile_c);
        tile_in[0][base + 2] = pad[0];
        tile_in[1][base + 2] = pad[1];
        chain_digests.push([tile_c[0][base + 2], tile_c[1][base + 2]]);
    }

    // Output chains: head [p0, p1, IV_OUTLEAF]; +[p2, p3].
    for (oi, p) in inst.output_leaves.iter().enumerate() {
        let base = SPINE_TILE_OUTPUT_BASE + 2 * oi;
        let (a, o) = run_perm([p[0], p[1], iv_out[0], iv_out[1]]);
        store_tile(base, a, o, &mut tile_c);
        tile_in[0][base] = p[0];
        tile_in[1][base] = p[1];
        let prev: [F128; STATE_SIZE] = std::array::from_fn(|j| tile_c[j][base]);
        let (a, o) = run_perm([prev[0] + p[2], prev[1] + p[3], prev[2], prev[3]]);
        store_tile(base + 1, a, o, &mut tile_c);
        tile_in[0][base + 1] = p[2];
        tile_in[1][base + 1] = p[3];
        chain_digests.push([tile_c[0][base + 1], tile_c[1][base + 1]]);
    }

    // ---------------- Tree ----------------
    let l = SPINE_TREE_LEAVES;
    let mut leaf_digests: Vec<[F128; 2]> = vec![[F128::ZERO; 2]; l];
    leaf_digests[0] = inst.epoch_anchor;
    leaf_digests[1] = inst.fee_leaf;
    for ci in 0..SPINE_N_INPUT_LEAVES {
        leaf_digests[2 + ci] = chain_digests[ci];
    }
    for oi in 0..SPINE_N_OUTPUT_LEAVES {
        leaf_digests[2 + SPINE_N_INPUT_LEAVES + oi] =
            chain_digests[SPINE_N_INPUT_LEAVES + oi];
    }
    leaf_digests[14] = inst.is_coinbase_leaf;
    leaf_digests[15] = inst.pad_leaf;

    let mut tree_c: [Vec<F128>; STATE_SIZE] =
        std::array::from_fn(|_| vec![F128::ZERO; SPINE_TREE_SLOTS]);
    let mut tree_s0: [Vec<F128>; STATE_SIZE] =
        std::array::from_fn(|_| vec![F128::ZERO; SPINE_TREE_SLOTS]);
    let mut tree_s_out: [Vec<F128>; STATE_SIZE] =
        std::array::from_fn(|_| vec![F128::ZERO; SPINE_TREE_SLOTS]);
    let mut store_tree = |slot: usize,
                          s0v: [F128; STATE_SIZE],
                          outv: [F128; STATE_SIZE],
                          c: &mut [Vec<F128>; STATE_SIZE]| {
        for j in 0..STATE_SIZE {
            tree_s0[j][slot] = s0v[j];
            tree_s_out[j][slot] = outv[j];
            c[j][slot] = outv[j];
        }
    };
    // Ghost default: node 0 and every leaf slot stay `perm([0;4])`.
    for slot in 0..SPINE_TREE_SLOTS {
        store_tree(slot, ghost_s0, ghost_out, &mut tree_c);
    }

    // Child digest of heap node `g`: external for leaves, C(2g+1) for
    // internal nodes (children are filled before parents below).
    let mut node_digest: Vec<[F128; 2]> = vec![[F128::ZERO; 2]; 2 * l];
    for (i, d) in leaf_digests.iter().enumerate() {
        node_digest[l + i] = *d;
    }
    for h in (1..l).rev() {
        let left = node_digest[2 * h];
        let right = node_digest[2 * h + 1];
        let (a, o) = run_perm([left[0], left[1], iv_comp[0], iv_comp[1]]);
        store_tree(2 * h, a, o, &mut tree_c);
        let even_out: [F128; STATE_SIZE] = std::array::from_fn(|j| tree_c[j][2 * h]);
        let (a, o) = run_perm([
            even_out[0] + right[0],
            even_out[1] + right[1],
            even_out[2],
            even_out[3],
        ]);
        store_tree(2 * h + 1, a, o, &mut tree_c);
        node_digest[h] = [tree_c[0][2 * h + 1], tree_c[1][2 * h + 1]];
    }

    // KID: the absorbed child at slot w is node w (heap layout); leaf
    // children carry the EXTERNAL digests, nodes 0/1 are never read.
    let mut tree_kid: [Vec<F128>; 2] =
        std::array::from_fn(|_| vec![F128::ZERO; SPINE_TREE_SLOTS]);
    for w in 2..2 * l {
        for lane in 0..2 {
            tree_kid[lane][w] = node_digest[w][lane];
        }
    }

    let root = node_digest[1];

    // ---------------- Wrap (tile slot SPINE_TILE_WRAP_SLOT) ----------------
    let (a, o) = run_perm([root[0], root[1], iv_wrap[0], iv_wrap[1]]);
    store_tile(SPINE_TILE_WRAP_SLOT, a, o, &mut tile_c);
    tile_in[0][SPINE_TILE_WRAP_SLOT] = root[0];
    tile_in[1][SPINE_TILE_WRAP_SLOT] = root[1];
    let tx_hash = [tile_c[0][SPINE_TILE_WRAP_SLOT], tile_c[1][SPINE_TILE_WRAP_SLOT]];

    SpineInstanceColumns {
        tile_c,
        tile_s0,
        tile_s_out,
        tile_in,
        tree_c,
        tree_s0,
        tree_s_out,
        tree_kid,
        chain_digests,
        root,
        tx_hash,
    }
}

// ---------------------------------------------------------------------------
// Region wiring: fixed patterns and the gated exposure
// ---------------------------------------------------------------------------

/// The tile schedule patterns over one [`SPINE_TILE_SLOTS`] period, in the
/// order `[REGION, CHAIN, IV0, IV1]`:
/// - `REGION` — 1 at every perm-active slot `[0, SPINE_TILE_ACTIVE)`; gates
///   the plain `IN` reads in the union (the sponge-shape substitution).
/// - `CHAIN` — 1 at every non-head active chain slot (the distance-1 carry).
/// - `IV0/IV1` — the head capacity IV lanes: `TAG_LEAF` at input heads,
///   `TAG_OUTLEAF` at output heads, `TAG_TXBODY` at the wrap; 0 elsewhere.
pub fn spine_tile_fixed_patterns() -> Vec<FixedPattern> {
    let low_log = SPINE_TILE_SLOTS.trailing_zeros() as usize;
    let iv_leaf = leaf_iv_flat();
    let iv_out = outleaf_iv_flat();
    let iv_wrap = txbody_iv_flat();
    let mut region = vec![F128::ZERO; SPINE_TILE_SLOTS];
    let mut chain = vec![F128::ZERO; SPINE_TILE_SLOTS];
    let mut iv0 = vec![F128::ZERO; SPINE_TILE_SLOTS];
    let mut iv1 = vec![F128::ZERO; SPINE_TILE_SLOTS];
    for slot in 0..SPINE_TILE_ACTIVE {
        region[slot] = F128::ONE;
    }
    for c in 0..SPINE_N_INPUT_LEAVES {
        iv0[3 * c] = iv_leaf[0];
        iv1[3 * c] = iv_leaf[1];
        chain[3 * c + 1] = F128::ONE;
        chain[3 * c + 2] = F128::ONE;
    }
    for o in 0..SPINE_N_OUTPUT_LEAVES {
        let base = SPINE_TILE_OUTPUT_BASE + 2 * o;
        iv0[base] = iv_out[0];
        iv1[base] = iv_out[1];
        chain[base + 1] = F128::ONE;
    }
    iv0[SPINE_TILE_WRAP_SLOT] = iv_wrap[0];
    iv1[SPINE_TILE_WRAP_SLOT] = iv_wrap[1];
    vec![
        FixedPattern::new(low_log, region),
        FixedPattern::new(low_log, chain),
        FixedPattern::new(low_log, iv0),
        FixedPattern::new(low_log, iv1),
    ]
}

/// The tree patterns over one [`SPINE_TREE_SLOTS`] period, in the
/// source-tree order `[EVEN_INT, ODD_INT, LEAFODD, IV0, IV1]` — the
/// source-tree patterns with `LEAFODD` ZEROED (the spine tree's leaf level
/// is external, its slots ghost), so
/// [`super::source_tree::source_tree_substitution_terms`] applies verbatim
/// (its `LEAFODD·CODE` terms vanish identically).
pub fn spine_tree_fixed_patterns() -> Vec<FixedPattern> {
    let tree = spine_tree();
    let mut pats = crate::deep_chain::source_tree::source_tree_fixed_patterns(
        &tree,
        spine_compress_iv_flat(),
    );
    let low_log = pats[2].low_log;
    pats[2] = FixedPattern::new(low_log, vec![F128::ZERO; 1 << low_log]);
    pats
}

/// The INTERNAL-CHILD gate over one KID period ([`SPINE_TREE_LEAVES`]·2
/// slots): 1 at `w ∈ [2, L)` (window-exposed internal children), 0 at the
/// leaf-child positions (cell-pinned externally) and at nodes 0/1.
pub fn spine_tree_internal_child_pattern() -> FixedPattern {
    let period = 2 * SPINE_TREE_LEAVES;
    let low_log = period.trailing_zeros() as usize;
    let mut t = vec![F128::ZERO; period];
    for w in 2..SPINE_TREE_LEAVES {
        t[w] = F128::ONE;
    }
    FixedPattern::new(low_log, t)
}

/// Gated exposure terms `0 = Σ_w eq·GATE(w)·Σ_i γ^{i+1}·[KID_i^{lo}(w) +
/// C_i(2w+1)]` — the source-tree exposure restricted to internal children.
/// `kid_lo`/`c` index the relation's committed columns, `gate` its fixed
/// patterns.
pub fn spine_tree_exposure_terms(
    kid_lo: [usize; 2],
    c: [usize; 2],
    gate: usize,
    gamma: F128,
) -> Vec<RelationTerm> {
    let mut terms = Vec::new();
    let mut p = F128::ONE;
    for i in 0..2 {
        p = p * gamma;
        terms.push(RelationTerm {
            coeff: p,
            factors: vec![ColRef::Fixed(gate), ColRef::Committed(kid_lo[i])],
        });
        terms.push(RelationTerm {
            coeff: p,
            factors: vec![
                ColRef::Fixed(gate),
                ColRef::Window { col: c[i], stride_log: 1, offset: 1 },
            ],
        });
    }
    terms
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deep_chain::leaf_hash::sponge_leaf_substitution_terms;
    use crate::deep_chain::relations::{
        claimed_refs, prove_column_relation, prove_shift_discharge, verify_column_relation,
        verify_shift_discharge, window_discharge_point, RelationColumns,
    };
    use crate::deep_chain::schedule::carry_selection_terms;
    use crate::deep_chain::source_tree::{source_tree_refs, source_tree_substitution_terms};
    use crate::deep_chain::{prove_deep_chain_walk, verify_deep_chain_walk, LaneClaimGroup};
    use crate::lincheck::build_eq_table;
    use noid_core::{Block128, TowerField};
    use noid_poseidon2b::native::domain::capacity_iv;
    use noid_poseidon2b::native::permutation::Poseidon2bPermutation;

    struct Rng(u64);
    impl Rng {
        fn next_u64(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E3779B97F4A7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
            z ^ (z >> 31)
        }
        fn block(&mut self) -> Block128 {
            Block128::from(((self.next_u64() as u128) << 64) | self.next_u64() as u128)
        }
    }

    fn phi(b: Block128) -> F128 {
        let f = noid_core::hardware::tower_to_flat_u128(b.0);
        F128 { lo: f as u64, hi: (f >> 64) as u64 }
    }

    fn mle(col: &[F128], point: &[F128]) -> F128 {
        let eq = build_eq_table(point);
        let mut acc = F128::ZERO;
        for (v, e) in col.iter().zip(eq.iter()) {
            acc += *v * *e;
        }
        acc
    }

    /// Independent TOWER-basis reference of the whole spine — a
    /// transliteration of the GKR oracle's `build_state_in` schedule run
    /// with the native permutation (head `[a0, a1, iv]`, non-head
    /// `prev XOR [a0, a1]`), heap-free (recursive tree).
    struct TowerSpine {
        epoch_anchor: [Block128; 2],
        fee_leaf: [Block128; 2],
        input_leaves: [[Block128; 4]; 4],
        output_leaves: [[Block128; 4]; 8],
        is_coinbase_leaf: [Block128; 2],
        pad_leaf: [Block128; 2],
    }

    fn perm(state: [Block128; 4]) -> [Block128; 4] {
        let mut s = state;
        Poseidon2bPermutation.permute_mut(&mut s);
        s
    }

    fn tower_reference(sp: &TowerSpine) -> ([Block128; 2], Vec<[Block128; 2]>, [Block128; 2]) {
        let [lf_hi, lf_lo] = capacity_iv(TAG_LEAF);
        let [ol_hi, ol_lo] = capacity_iv(TAG_OUTLEAF);
        let [cp_hi, cp_lo] = capacity_iv(TAG_COMPRESS);
        let [tb_hi, tb_lo] = capacity_iv(TAG_TXBODY);
        let pad = [Block128::from(0x80u128), Block128::from(0x01u128 << 120)];

        let mut digests: Vec<[Block128; 2]> = Vec::new();
        let mut leaves: Vec<[Block128; 2]> = vec![[Block128::ZERO; 2]; 16];
        leaves[0] = sp.epoch_anchor;
        leaves[1] = sp.fee_leaf;
        for (i, p) in sp.input_leaves.iter().enumerate() {
            let s = perm([p[0], p[1], lf_hi, lf_lo]);
            let s = perm([s[0] + p[2], s[1] + p[3], s[2], s[3]]);
            let s = perm([s[0] + pad[0], s[1] + pad[1], s[2], s[3]]);
            leaves[2 + i] = [s[0], s[1]];
            digests.push([s[0], s[1]]);
        }
        for (i, p) in sp.output_leaves.iter().enumerate() {
            let s = perm([p[0], p[1], ol_hi, ol_lo]);
            let s = perm([s[0] + p[2], s[1] + p[3], s[2], s[3]]);
            leaves[6 + i] = [s[0], s[1]];
            digests.push([s[0], s[1]]);
        }
        leaves[14] = sp.is_coinbase_leaf;
        leaves[15] = sp.pad_leaf;

        let mut nodes: Vec<[Block128; 2]> = vec![[Block128::ZERO; 2]; 32];
        nodes[16..32].copy_from_slice(&leaves);
        for h in (1..16usize).rev() {
            let l = nodes[2 * h];
            let r = nodes[2 * h + 1];
            let s = perm([l[0], l[1], cp_hi, cp_lo]);
            let s = perm([s[0] + r[0], s[1] + r[1], s[2], s[3]]);
            nodes[h] = [s[0], s[1]];
        }
        let root = nodes[1];
        let s = perm([root[0], root[1], tb_hi, tb_lo]);
        ([s[0], s[1]], digests, root)
    }

    fn random_instance(rng: &mut Rng) -> (TowerSpine, SpineInstanceFlat) {
        let pair = |rng: &mut Rng| -> [Block128; 2] { [rng.block(), rng.block()] };
        let quad = |rng: &mut Rng| -> [Block128; 4] {
            [rng.block(), rng.block(), rng.block(), rng.block()]
        };
        let tower = TowerSpine {
            epoch_anchor: pair(rng),
            fee_leaf: pair(rng),
            input_leaves: std::array::from_fn(|_| quad(rng)),
            output_leaves: std::array::from_fn(|_| quad(rng)),
            is_coinbase_leaf: pair(rng),
            pad_leaf: [Block128::ZERO; 2],
        };
        let flat = SpineInstanceFlat {
            epoch_anchor: std::array::from_fn(|i| phi(tower.epoch_anchor[i])),
            fee_leaf: std::array::from_fn(|i| phi(tower.fee_leaf[i])),
            input_leaves: std::array::from_fn(|c| {
                std::array::from_fn(|i| phi(tower.input_leaves[c][i]))
            }),
            output_leaves: std::array::from_fn(|o| {
                std::array::from_fn(|i| phi(tower.output_leaves[o][i]))
            }),
            is_coinbase_leaf: std::array::from_fn(|i| phi(tower.is_coinbase_leaf[i])),
            pad_leaf: [F128::ZERO; 2],
        };
        (tower, flat)
    }

    /// The atomic correctness fact: the flat-basis instance replay equals
    /// the native tower spine (chain digests, root, tx_body_hash) under φ.
    #[test]
    fn spine_instance_matches_tower_reference() {
        let mut rng = Rng(0x59147E);
        for _ in 0..4 {
            let (tower, flat) = random_instance(&mut rng);
            let (want_hash, want_digests, want_root) = tower_reference(&tower);
            let cols = build_spine_instance_columns(&flat);
            for (t, d) in want_digests.iter().enumerate() {
                assert_eq!(cols.chain_digests[t][0], phi(d[0]), "chain {t} lane 0");
                assert_eq!(cols.chain_digests[t][1], phi(d[1]), "chain {t} lane 1");
            }
            assert_eq!(cols.root[0], phi(want_root[0]), "root lane 0");
            assert_eq!(cols.root[1], phi(want_root[1]), "root lane 1");
            assert_eq!(cols.tx_hash[0], phi(want_hash[0]), "tx hash lane 0");
            assert_eq!(cols.tx_hash[1], phi(want_hash[1]), "tx hash lane 1");
        }
    }

    /// The full region DAG for one spine instance union (tile + tree in one
    /// domain): carry-selection seeds the walk, ONE walk verifies every
    /// permutation, ONE substitution ties the walk input to both families'
    /// wiring (tile = region-gated sponge shape; tree = source-tree shape
    /// with zero LEAFODD), the GATED exposure proves the internal KID
    /// children, and the external joins (chain digests ↔ KID leaf cells,
    /// root ↔ wrap IN) hold as cell equalities. Honest run discharges every
    /// claim; corrupted digests / absorbs / KID cells are caught.
    #[test]
    fn spine_region_dag_roundtrip_and_negatives() {
        use crate::challenger::{Challenger, FsLaneChallenger};

        // Domain: [tree (64) | tile (32) | ghost pad (32)] = 128 slots.
        let tree_base = 0usize;
        let tile_base = SPINE_TREE_SLOTS;
        let w_log = 7usize;
        let p = 1usize << w_log;

        let mut rng = Rng(0xDA6);
        let (_, flat) = random_instance(&mut rng);
        let cols = build_spine_instance_columns(&flat);

        // Shared columns: KID0/1, IN0/1, C0..C3 (source-tree CODE unused —
        // an all-zero column reused as the zero-valued CODE reference).
        let zero_col = vec![F128::ZERO; p];
        let mut kid: [Vec<F128>; 2] = std::array::from_fn(|_| vec![F128::ZERO; p]);
        let mut in_: [Vec<F128>; 2] = std::array::from_fn(|_| vec![F128::ZERO; p]);
        let mut c: [Vec<F128>; STATE_SIZE] = std::array::from_fn(|_| vec![F128::ZERO; p]);
        let mut s0: [Vec<F128>; STATE_SIZE] = std::array::from_fn(|_| vec![F128::ZERO; p]);
        let mut s_out: [Vec<F128>; STATE_SIZE] = std::array::from_fn(|_| vec![F128::ZERO; p]);
        let (g0, go) = run_perm([F128::ZERO; STATE_SIZE]);
        for slot in 0..p {
            for j in 0..STATE_SIZE {
                s0[j][slot] = g0[j];
                s_out[j][slot] = go[j];
                c[j][slot] = go[j];
            }
        }
        for j in 0..STATE_SIZE {
            c[j][tree_base..tree_base + SPINE_TREE_SLOTS].copy_from_slice(&cols.tree_c[j]);
            s0[j][tree_base..tree_base + SPINE_TREE_SLOTS].copy_from_slice(&cols.tree_s0[j]);
            s_out[j][tree_base..tree_base + SPINE_TREE_SLOTS]
                .copy_from_slice(&cols.tree_s_out[j]);
            c[j][tile_base..tile_base + SPINE_TILE_SLOTS].copy_from_slice(&cols.tile_c[j]);
            s0[j][tile_base..tile_base + SPINE_TILE_SLOTS].copy_from_slice(&cols.tile_s0[j]);
            s_out[j][tile_base..tile_base + SPINE_TILE_SLOTS]
                .copy_from_slice(&cols.tile_s_out[j]);
        }
        for lane in 0..2 {
            kid[lane][tree_base..tree_base + SPINE_TREE_SLOTS]
                .copy_from_slice(&cols.tree_kid[lane]);
            in_[lane][tile_base..tile_base + SPINE_TILE_SLOTS]
                .copy_from_slice(&cols.tile_in[lane]);
        }

        // Fixed patterns over the whole domain (low_log = w_log): the tree
        // patterns at [0, 64) and the tile patterns at [64, 96).
        let localize = |table: &[F128], offset: usize| -> FixedPattern {
            let mut t = vec![F128::ZERO; p];
            t[offset..offset + table.len()].copy_from_slice(table);
            FixedPattern::new(w_log, t)
        };
        let mut fixed: Vec<FixedPattern> = Vec::new();
        for pat in spine_tree_fixed_patterns() {
            fixed.push(localize(&pat.table, tree_base));
        }
        for pat in spine_tile_fixed_patterns() {
            fixed.push(localize(&pat.table, tile_base));
        }
        // Committed order: CODE0=0(zero), CODE1=1(zero), KID0=2, KID1=3,
        // IN0=4, IN1=5, C0=6..C3=9 (the union's meta layout).
        let tree_refs = crate::deep_chain::source_tree::SourceTreeRefs {
            code: [0, 1],
            kid: [2, 3],
            c: std::array::from_fn(|i| 6 + i),
            even_int: 0,
            odd_int: 1,
            leafodd: 2,
            iv: [3, 4],
        };
        let tile_refs = crate::deep_chain::leaf_hash::SpongeLeafRefs {
            in_: [4, 5],
            c: std::array::from_fn(|i| 6 + i),
            odd: 6, // CHAIN
            iv: [7, 8],
        };
        let tile_region = 5;

        let run = |kid0: &[F128],
                   kid1: &[F128],
                   in0: &[F128],
                   in1: &[F128],
                   c: &[Vec<F128>; STATE_SIZE]|
         -> Result<(), String> {
            let committed: Vec<&[F128]> = vec![
                &zero_col, &zero_col, kid0, kid1, in0, in1, &c[0], &c[1], &c[2], &c[3],
            ];
            let internal: Vec<&[F128]> = s_out.iter().map(|x| x.as_slice()).collect();
            let mut ch_p = FsLaneChallenger::new(b"spine-dag");
            let mut ch_v = FsLaneChallenger::new(b"spine-dag");
            let mut pending: Vec<(usize, Vec<F128>, F128)> = Vec::new();

            // Carry selection → walk group.
            let beta = ch_p.sample_f128();
            assert_eq!(beta, ch_v.sample_f128());
            let sel_terms = carry_selection_terms(&tree_refs.c, beta);
            let rho = ch_p.sample_f128_vec(w_log);
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
            let mut gv = [F128::ZERO; STATE_SIZE];
            for (r, v) in claimed_refs(&sel_terms).iter().zip(sp.final_values.iter()) {
                match r {
                    ColRef::Committed(cc) => pending.push((*cc, sel_point.clone(), *v)),
                    ColRef::Internal(j) => gv[*j] = *v,
                    _ => unreachable!(),
                }
            }
            let groups = vec![LaneClaimGroup { point: sel_point, values: gv }];
            let (wp, _) = prove_deep_chain_walk(&s0, &groups, &mut ch_p);
            let terminal = verify_deep_chain_walk(w_log, &groups, &wp, &mut ch_v)
                .map_err(|e| format!("walk: {e}"))?;

            // Union substitution: tree terms (LEAFODD zero) + gated tile terms.
            let alpha = ch_p.sample_f128();
            assert_eq!(alpha, ch_v.sample_f128());
            let mut sub_terms = source_tree_substitution_terms(&tree_refs, alpha);
            let mut tile_terms = sponge_leaf_substitution_terms(&tile_refs, alpha);
            for t in tile_terms.iter_mut() {
                if !t.factors.iter().any(|f| matches!(f, ColRef::Fixed(_))) {
                    t.factors.insert(0, ColRef::Fixed(tile_region));
                }
            }
            sub_terms.extend(tile_terms);
            let mut target = F128::ZERO;
            let mut pw = F128::ONE;
            for e in 0..STATE_SIZE {
                pw = pw * alpha;
                target += pw * terminal.values[e];
            }
            let (subp, _, _) = prove_column_relation(
                target,
                &terminal.point,
                &sub_terms,
                &RelationColumns { committed: &committed, internal: &[], fixed: &fixed },
                &mut ch_p,
            );
            let sub_point = verify_column_relation(
                w_log,
                target,
                &terminal.point,
                &sub_terms,
                &fixed,
                &subp,
                &mut ch_v,
            )
            .map_err(|e| format!("substitution: {e}"))?;
            for (r, v) in claimed_refs(&sub_terms).iter().zip(subp.final_values.iter()) {
                match r {
                    ColRef::Committed(cc) => pending.push((*cc, sub_point.clone(), *v)),
                    ColRef::CommittedShift(cc) => {
                        let (pr, _) =
                            prove_shift_discharge(committed[*cc], &sub_point, *v, &mut ch_p);
                        let pt = verify_shift_discharge(w_log, &sub_point, *v, &pr, &mut ch_v)
                            .map_err(|e| format!("shift: {e}"))?;
                        pending.push((*cc, pt, pr.final_value));
                    }
                    _ => unreachable!("spine union references committed/shift only"),
                }
            }

            // Gated exposure over the KID half-domain (tree at offset 0, so
            // the half-domain [0, 64) covers KID's [0, 32) live range; the
            // gate zeroes everything else including the tile's half-image).
            let gate = {
                let pat = spine_tree_internal_child_pattern();
                let mut t = vec![F128::ZERO; p / 2];
                t[..pat.table.len()].copy_from_slice(&pat.table);
                FixedPattern::new(w_log - 1, t)
            };
            let kid_lo0 = &kid0[..p / 2];
            let kid_lo1 = &kid1[..p / 2];
            let expo_committed: Vec<&[F128]> = vec![kid_lo0, kid_lo1, &c[0], &c[1]];
            let gamma = ch_p.sample_f128();
            assert_eq!(gamma, ch_v.sample_f128());
            let expo_terms = spine_tree_exposure_terms([0, 1], [2, 3], 0, gamma);
            let rho_e = ch_p.sample_f128_vec(w_log - 1);
            let _ = ch_v.sample_f128_vec(w_log - 1);
            let expo_fixed = vec![gate];
            let (ep, _, _) = prove_column_relation(
                F128::ZERO,
                &rho_e,
                &expo_terms,
                &RelationColumns { committed: &expo_committed, internal: &[], fixed: &expo_fixed },
                &mut ch_p,
            );
            let expo_point = verify_column_relation(
                w_log - 1,
                F128::ZERO,
                &rho_e,
                &expo_terms,
                &expo_fixed,
                &ep,
                &mut ch_v,
            )
            .map_err(|e| format!("exposure: {e}"))?;
            for (r, v) in claimed_refs(&expo_terms).iter().zip(ep.final_values.iter()) {
                match r {
                    ColRef::Committed(0) => {
                        if mle(kid_lo0, &expo_point) != *v {
                            return Err("kid0 low claim false".into());
                        }
                    }
                    ColRef::Committed(1) => {
                        if mle(kid_lo1, &expo_point) != *v {
                            return Err("kid1 low claim false".into());
                        }
                    }
                    ColRef::Window { col, stride_log, offset } => {
                        let pt = window_discharge_point(*offset, *stride_log, &expo_point);
                        let idx = if *col == 2 { 0 } else { 1 };
                        if mle(&c[idx], &pt) != *v {
                            return Err(format!("window C{idx} claim false"));
                        }
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

            // External joins as cell equalities (the assembly's cell pins):
            // chain digests ↔ KID leaf cells; wrap IN ↔ root; wrap C ↔ hash.
            for t in 0..12 {
                let dslot = tile_base
                    + if t < 4 {
                        spine_input_digest_slot(t)
                    } else {
                        spine_output_digest_slot(t - 4)
                    };
                let leaf_idx = 2 + t;
                for lane in 0..2 {
                    let kid_col: &[F128] = if lane == 0 { kid0 } else { kid1 };
                    if kid_col[tree_base + SPINE_TREE_KID_LEAF_BASE + leaf_idx]
                        != c[lane][dslot]
                    {
                        return Err(format!("chain {t} digest != KID leaf cell"));
                    }
                }
            }
            for lane in 0..2 {
                let in_col: &[F128] = if lane == 0 { in0 } else { in1 };
                if in_col[tile_base + SPINE_TILE_WRAP_SLOT] != c[lane][tree_base + 3] {
                    return Err("wrap IN != tree root".into());
                }
            }
            Ok(())
        };

        run(&kid[0], &kid[1], &in_[0], &in_[1], &c).expect("honest spine DAG verifies");

        // A corrupted internal KID cell breaks the gated exposure.
        {
            let mut bad = kid[0].clone();
            bad[tree_base + 5] += F128::ONE;
            assert!(
                run(&bad, &kid[1], &in_[0], &in_[1], &c).is_err(),
                "corrupted internal KID accepted"
            );
        }
        // A corrupted LEAF KID cell breaks the substitution (the parent
        // absorbs it) — the walk output no longer matches.
        {
            let mut bad = kid[0].clone();
            bad[tree_base + SPINE_TREE_KID_LEAF_BASE + 3] += F128::ONE;
            assert!(
                run(&bad, &kid[1], &in_[0], &in_[1], &c).is_err(),
                "corrupted leaf KID accepted"
            );
        }
        // A corrupted absorb lane breaks the tile substitution.
        {
            let mut bad = in_[0].clone();
            bad[tile_base + 1] += F128::ONE;
            assert!(
                run(&kid[0], &kid[1], &bad, &in_[1], &c).is_err(),
                "corrupted absorb accepted"
            );
        }
        // A corrupted permutation output (C lane) breaks the walk/selection.
        {
            let mut bad = c.clone();
            bad[0][tile_base + SPINE_TILE_WRAP_SLOT] += F128::ONE;
            assert!(
                run(&kid[0], &kid[1], &in_[0], &in_[1], &bad).is_err(),
                "corrupted wrap digest accepted"
            );
        }
    }
}
