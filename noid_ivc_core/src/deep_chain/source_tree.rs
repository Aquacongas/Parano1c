//! Source-binding Merkle tree rebuild for the wallet-capsule PCS, in the
//! deep-chain region.
//!
//! The compact-FRI source binding recomputes the round-0 codeword tree and
//! checks its root against `fri_roots[0]`: `2^d` leaf hashes over the
//! `Code(H·eq_right)` symbols, then `d` levels of two-permutation `compress`
//! up to the root. Replaying every `compress` inline is the ~1.7M-rows/tx
//! cost the region layer exists to fold away; here the internal tree is a
//! fan-in-2 chain of `compress` nodes whose per-node permutations are
//! verified data-parallel by the deep-chain walk, and whose node-to-child
//! wiring is a single [`ColRef::Window`] read.
//!
//! # Basis
//!
//! The wallet capsule hashes in the TOWER basis (`Poseidon2bPermutation`),
//! but the walk anchors on `permute_flat_u128` and the region columns carry
//! flat lanes. Because `permute_mut = flat→tower ∘ permute_flat ∘
//! tower→flat` and the basis change φ is F2-linear (so `φ(a+b) = φ(a)+φ(b)`
//! and XOR feed-forwards commute with it), the WHOLE tree runs in the flat
//! basis with φ applied only at the two boundaries — the leaf code symbols
//! coming in and the root constant `fri_roots[0]` going out. This is the
//! same single-basis convention the proof-core PCS trees adopted; here it
//! keeps every digest lane a plain flat wire.
//!
//! # Slot layout (heap order, two permutations per node)
//!
//! Node `h` (1-indexed binary heap: root `h = 1`, children `2h`/`2h+1`)
//! occupies the slot pair `(2h, 2h+1)` — an EVEN slot (the first `compress`
//! permutation on `[left, IV]`) and an ODD slot (the second, feeding the
//! even output forward and absorbing `right`). The node's output digest
//! lands on lanes `C0/C1` of its ODD slot `2h+1`. A parent at slot `w` then
//! reads a child's digest with the SAME window on both of its slots:
//!
//! ```text
//!   Window(C_i, stride_log = 1, offset = 1)(w) = C_i(2w + 1)
//!     w = 2h   (parent even) → C_i(4h+1) = digest of child 2h  (left)
//!     w = 2h+1 (parent odd)  → C_i(4h+3) = digest of child 2h+1 (right)
//! ```
//!
//! because `2h`'s output slot is `2·(2h)+1 = 4h+1` and `2h+1`'s is `4h+3` —
//! one window ref supplies both children, no direction bit.
//!
//! For the INTERNAL tree built here the leaf digests are given (committed at
//! the leaf nodes' odd slots `2h+1`, `h ∈ [L, 2L)`), and the internal nodes
//! `h ∈ [1, L)` are the permutation-active slots. Leaf slots and the ghost
//! node 0 carry state forward.

use crate::deep_chain::schedule::flat_of_tower_u128;
use crate::deep_chain::{apply_round, initial_mds};
use crate::field::F128;
use noid_poseidon2b::native::domain::{capacity_iv_flat, TAG_COMPRESS};
use noid_poseidon2b::native::permutation::{N_ROUNDS, STATE_SIZE};

/// The flat-basis `compress` capacity IV (`TAG_COMPRESS`), as F128 lanes.
pub fn compress_iv_flat() -> [F128; 2] {
    let iv = capacity_iv_flat(TAG_COMPRESS);
    [
        F128 {
            lo: iv[0] as u64,
            hi: (iv[0] >> 64) as u64,
        },
        F128 {
            lo: iv[1] as u64,
            hi: (iv[1] >> 64) as u64,
        },
    ]
}

/// One Poseidon2b permutation in the flat basis, expressed as the walk
/// models it: `initial_mds` then the `N_ROUNDS` round schedule. Equal to
/// `permute_flat_u128` on the lane bit patterns (`F128{lo,hi}` IS the flat
/// u128), which is the structural anchor of the deep-chain walk.
pub fn permute_flat_state(raw: [F128; STATE_SIZE]) -> [F128; STATE_SIZE] {
    let mut state = initial_mds(raw);
    for q in 0..N_ROUNDS {
        state = apply_round(q, state);
    }
    state
}

/// Flat-basis two-permutation `compress(a, b)` with capacity IV `iv`:
///
/// ```text
///   s = permute([a0, a1, iv0, iv1]); s0 += b0; s1 += b1; s = permute(s)
///   digest = (s0, s1)
/// ```
///
/// Mirrors `noid_poseidon2b::native::compress` lane-for-lane under φ.
pub fn flat_compress(iv: [F128; 2], a: [F128; 2], b: [F128; 2]) -> [F128; 2] {
    let mut s = permute_flat_state([a[0], a[1], iv[0], iv[1]]);
    s[0] += b[0];
    s[1] += b[1];
    let s = permute_flat_state(s);
    [s[0], s[1]]
}

/// Flat lane of a tower `u128` bit pattern (leaf code symbols and the root
/// constant cross the region boundary through this linear map).
pub fn flat_lane(v: u128) -> F128 {
    flat_of_tower_u128(v)
}

/// One source-binding tree instance: `2^leaf_log` leaves over a length
/// `2^(leaf_log+1)` codeword. The heap slot domain is `2^(leaf_log+2)` (two
/// permutation slots per heap node), so the region needs `w_log ≥
/// leaf_log + 2`.
#[derive(Clone, Copy, Debug)]
pub struct SourceTree {
    pub leaf_log: usize,
}

impl SourceTree {
    pub fn leaf_count(&self) -> usize {
        1usize << self.leaf_log
    }
    pub fn code_len(&self) -> usize {
        1usize << (self.leaf_log + 1)
    }
    /// Heap node count (index 0 unused; root = 1; leaves `[L, 2L)`).
    pub fn heap_len(&self) -> usize {
        1usize << (self.leaf_log + 1)
    }
    pub fn n_slots(&self) -> usize {
        1usize << (self.leaf_log + 2)
    }
    pub fn slots_log(&self) -> usize {
        self.leaf_log + 2
    }
}

/// The flat-basis region columns of one source tree: every heap node's two
/// permutation slots. `c[j][slot]` is the permutation output state (the node
/// digest lives on lanes `C0/C1` of its ODD slot); `s0` is the walk's
/// post-`initial_mds` input; `s_out == c`.
///
/// Node roles by slot (`h = slot / 2`, `local = slot & 1`):
/// - leaf odd slot (`h ∈ [L, 2L)`, `local == 1`): `hash_pair(code[2i],
///   code[2i+1])`, one permutation on `[code0, code1, 0, 0]`, `i = h − L`;
/// - internal even slot (`h ∈ [1, L)`, `local == 0`): first `compress`
///   permutation on `[left, left, IV, IV]`, `left = C(2h+1)` via the window;
/// - internal odd slot (`h ∈ [1, L)`, `local == 1`): second `compress`
///   permutation on `[even_out + right, even_out_cap]`, `right = C(2h+1)`;
/// - leaf even slots and node 0: ghost permutations carrying state forward.
pub struct SourceTreeColumns {
    pub c: [Vec<F128>; STATE_SIZE],
    pub s0: [Vec<F128>; STATE_SIZE],
    pub s_out: [Vec<F128>; STATE_SIZE],
    /// The recomputed root digest: `C0/C1` at heap node 1's odd slot (3).
    pub root: [F128; 2],
}

/// Run one permutation from its raw pre-MDS input, returning the walk's
/// `s0` (post-`initial_mds`) and the output state (`s_out == c`).
fn run_perm(raw: [F128; STATE_SIZE]) -> ([F128; STATE_SIZE], [F128; STATE_SIZE]) {
    let s0 = initial_mds(raw);
    let mut state = s0;
    for q in 0..N_ROUNDS {
        state = apply_round(q, state);
    }
    (s0, state)
}

/// The two code lanes a leaf reads at its odd slot (`CODE0/CODE1` committed
/// columns): `CODE0[2h+1] = code[2i]`, `CODE1[2h+1] = code[2i+1]`.
pub fn build_source_code_columns(tree: &SourceTree, code: &[F128], w_log: usize) -> [Vec<F128>; 2] {
    let w = 1usize << w_log;
    assert!(w_log >= tree.slots_log(), "slot domain below the tree");
    assert_eq!(code.len(), tree.code_len(), "code length");
    let l = tree.leaf_count();
    let mut code0 = vec![F128::ZERO; w];
    let mut code1 = vec![F128::ZERO; w];
    for i in 0..l {
        let h = l + i;
        let odd = 2 * h + 1;
        code0[odd] = code[2 * i];
        code1[odd] = code[2 * i + 1];
    }
    [code0, code1]
}

/// Replay the whole tree in the flat basis and fill the region columns.
///
/// Children are filled before parents (leaves first, then heap indices
/// descending), so a parent's window read of `C(2h+1)` is already the child
/// digest. The recomputed `root` matches the native capsule tree root under
/// φ (`compute_leaf_hashes` + `MerkleTree::new_parallel`).
pub fn build_source_tree_columns(
    tree: &SourceTree,
    code: &[F128],
    w_log: usize,
) -> SourceTreeColumns {
    let w = 1usize << w_log;
    assert!(w_log >= tree.slots_log(), "slot domain below the tree");
    assert_eq!(code.len(), tree.code_len(), "code length");
    let l = tree.leaf_count();
    let iv = compress_iv_flat();

    let mut c: [Vec<F128>; STATE_SIZE] = std::array::from_fn(|_| vec![F128::ZERO; w]);
    let mut s0: [Vec<F128>; STATE_SIZE] = std::array::from_fn(|_| vec![F128::ZERO; w]);
    let mut s_out: [Vec<F128>; STATE_SIZE] = std::array::from_fn(|_| vec![F128::ZERO; w]);

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

    // Leaves: hash_pair(code0, code1) at the odd slot; even slot ghost.
    for i in 0..l {
        let h = l + i;
        let raw = [code[2 * i], code[2 * i + 1], F128::ZERO, F128::ZERO];
        let (s0v, outv) = run_perm(raw);
        store(2 * h + 1, s0v, outv, &mut c);
    }

    // Internal nodes, heap indices descending (children already filled).
    for h in (1..l).rev() {
        let left = [c[0][2 * (2 * h) + 1], c[1][2 * (2 * h) + 1]];
        let right = [c[0][2 * (2 * h + 1) + 1], c[1][2 * (2 * h + 1) + 1]];
        // Even slot: first compress permutation on [left, IV].
        let even_raw = [left[0], left[1], iv[0], iv[1]];
        let (even_s0, even_out) = run_perm(even_raw);
        store(2 * h, even_s0, even_out, &mut c);
        // Odd slot: second permutation, even output fed forward, right absorbed.
        let odd_raw = [
            even_out[0] + right[0],
            even_out[1] + right[1],
            even_out[2],
            even_out[3],
        ];
        let (odd_s0, odd_out) = run_perm(odd_raw);
        store(2 * h + 1, odd_s0, odd_out, &mut c);
    }

    let root = [c[0][3], c[1][3]];
    SourceTreeColumns {
        c,
        s0,
        s_out,
        root,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use noid_core::{Block128, CanonicalSerialize, TowerField};

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

    fn digest_bytes(a0: Block128, a1: Block128) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[..16].copy_from_slice(&a0.to_bytes());
        out[16..].copy_from_slice(&a1.to_bytes());
        out
    }

    fn tower_flat(b: Block128) -> F128 {
        let f = noid_core::hardware::tower_to_flat_u128(b.0);
        F128 {
            lo: f as u64,
            hi: (f >> 64) as u64,
        }
    }

    fn ref_leaf(a: Block128, b: Block128) -> [Block128; 2] {
        use noid_poseidon2b::native::permutation::Poseidon2bPermutation;
        let mut st = [a, b, Block128::ZERO, Block128::ZERO];
        Poseidon2bPermutation.permute_mut(&mut st);
        [st[0], st[1]]
    }

    fn ref_compress(l: [Block128; 2], r: [Block128; 2]) -> [Block128; 2] {
        let out = noid_poseidon2b::native::compress(
            &digest_bytes(l[0], l[1]),
            &digest_bytes(r[0], r[1]),
        );
        [
            Block128::from(u128::from_le_bytes(out[..16].try_into().unwrap())),
            Block128::from(u128::from_le_bytes(out[16..].try_into().unwrap())),
        ]
    }

    /// Independent native tower reference for the whole capsule tree: leaves
    /// = `hash_pair(code[2i], code[2i+1])`, then heap-order `compress` to the
    /// root — exactly `compute_leaf_hashes` + `MerkleTree::new_parallel`.
    fn reference_root(code: &[Block128]) -> [Block128; 2] {
        let l = code.len() / 2;
        let mut dig = vec![[Block128::ZERO; 2]; 2 * l];
        for i in 0..l {
            dig[l + i] = ref_leaf(code[2 * i], code[2 * i + 1]);
        }
        for h in (1..l).rev() {
            dig[h] = ref_compress(dig[2 * h], dig[2 * h + 1]);
        }
        dig[1]
    }

    /// The flat-basis heap replay reproduces the native capsule tree root
    /// (leaf `hash_pair` + internal `compress`, heap-order) under φ, at
    /// several leaf counts and with slack `w_log`.
    #[test]
    fn source_tree_root_matches_native_capsule_tree() {
        for (leaf_log, seed, slack) in [(1usize, 0xA11u64, 0), (3, 0xB22, 0), (3, 0xC33, 1)] {
            let tree = SourceTree { leaf_log };
            let mut rng = Rng(seed);
            let code_tower: Vec<Block128> = (0..tree.code_len()).map(|_| rng.block()).collect();
            let code_flat: Vec<F128> = code_tower.iter().map(|b| tower_flat(*b)).collect();
            let w_log = tree.slots_log() + slack;

            let cols = build_source_tree_columns(&tree, &code_flat, w_log);
            let want = reference_root(&code_tower);
            assert_eq!(cols.root[0], tower_flat(want[0]), "root lane 0 (leaf_log={leaf_log})");
            assert_eq!(cols.root[1], tower_flat(want[1]), "root lane 1 (leaf_log={leaf_log})");
        }
    }

    /// The atomic correctness fact: the flat-basis `flat_compress` equals the
    /// native tower-basis `compress` lane-for-lane after φ. Everything the
    /// tree family builds rests on this.
    #[test]
    fn flat_compress_matches_native_tower_compress() {
        let mut rng = Rng(0xC0FFEE);
        let iv = compress_iv_flat();
        for _ in 0..16 {
            let a0 = rng.block();
            let a1 = rng.block();
            let b0 = rng.block();
            let b1 = rng.block();

            let native = noid_poseidon2b::native::compress(
                &digest_bytes(a0, a1),
                &digest_bytes(b0, b1),
            );
            let n0 = Block128::from(u128::from_le_bytes(native[..16].try_into().unwrap()));
            let n1 = Block128::from(u128::from_le_bytes(native[16..].try_into().unwrap()));

            let got = flat_compress(
                iv,
                [tower_flat(a0), tower_flat(a1)],
                [tower_flat(b0), tower_flat(b1)],
            );
            assert_eq!(got[0], tower_flat(n0), "compress lane 0 diverges under phi");
            assert_eq!(got[1], tower_flat(n1), "compress lane 1 diverges under phi");
        }
    }
}
