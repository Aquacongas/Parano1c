//! [G] item 5b — composition gates: the wallet-capsule per-query Merkle
//! openings reproduced end-to-end by the region families.
//!
//! `verify_mixed_opening` authenticates queried symbols against committed
//! roots in three hashing-heavy places, together the dominant ~1.7M-rows/tx
//! inline work:
//!   - step 3i  — the per-round FRI openings (leaf = `hash_pair(s0, s1)`),
//!   - step SB6 — the source-tree opening (leaf = `source_leaf_hash`),
//!   - step SB8 — the high-fold layer openings (leaf = `high_pair_leaf_hash`).
//!
//! Each is the same shape-fixed composition of three already-gated pieces:
//!   - the region leaf digest (item 3 `flat_source_leaf_hash` /
//!     `flat_high_pair_leaf_hash`, or the plain `flat_hash_pair`),
//!   - item 2 `expand_batched_merkle_proof` (octopus → independent paths),
//!   - `MerklePathFamily` (per-query path replay → recomputed root).
//! The region leaf digest is asserted == φ(native leaf), fed as the path
//! entry with the expanded siblings/directions; every distinct query's path
//! folds to the SAME native committed root under φ. The path shape
//! `(query_count, depth)` is a class constant, so ONE family covers every
//! query of every tx of a class — this is what replaces the proof-dependent
//! octopus schedule.

use noid_core::Block128;
use noid_fri::merkle::MerkleTree;
use noid_fri_binius::compact_fri::{
    build_batched_merkle_proof, expand_batched_merkle_proof, IndependentMerklePath,
};
use noid_fri_binius::interleaved_commit::{source_leaf_hash, CommitmentHashBackend};
use noid_fri_binius::mixed_open::high_pair_leaf_hash_for_trace;
use noid_ivc_core::deep_chain::leaf_hash::{flat_high_pair_leaf_hash, flat_source_leaf_hash};
use noid_ivc_core::deep_chain::schedule::{
    build_merkle_path_columns, flat_of_tower_u128, MerklePathFamily, MerklePathWitness,
};
use noid_ivc_core::deep_chain::source_tree::flat_hash_pair;
use noid_ivc_core::field::F128;
use noid_poseidon2b::hasher::CryptographicHasher;
use noid_poseidon2b::native::domain::{capacity_iv, TAG_COMPRESS};
use noid_poseidon2b::Poseidon2bSponge;

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

/// Flat lanes of a 32-byte tower digest (φ split into two Block128 lanes).
fn lanes(d: &[u8; 32]) -> [F128; 2] {
    [
        flat_of_tower_u128(u128::from_le_bytes(d[..16].try_into().unwrap())),
        flat_of_tower_u128(u128::from_le_bytes(d[16..].try_into().unwrap())),
    ]
}

fn flat(b: Block128) -> F128 {
    flat_of_tower_u128(b.0)
}

/// The shared composition check: given native leaves and the per-leaf region
/// digests (indexed by tree position), expand a batched octopus proof for
/// `queries` and assert every independent path folds through
/// `MerklePathFamily` to φ(the native committed root); the region digest of
/// each queried leaf must equal φ(native leaf); a tampered sibling makes its
/// path miss the root.
fn check_region_opening(leaves: &[[u8; 32]], region_entries: &[[F128; 2]], depth: usize, queries: &[usize]) {
    let hasher = Poseidon2bSponge::new();
    let tree = MerkleTree::new_parallel(leaves.to_vec(), &hasher);
    let root_flat = lanes(&tree.get_root());
    let query_leaves: Vec<[u8; 32]> = queries.iter().map(|&i| leaves[i]).collect();
    let batch = build_batched_merkle_proof(&tree, queries, depth);
    let paths = expand_batched_merkle_proof(&batch, depth, queries, &query_leaves, &hasher)
        .expect("octopus expands to independent paths");

    let iv_tower = capacity_iv(TAG_COMPRESS);
    let iv_flat = [
        flat_of_tower_u128(iv_tower[0].0),
        flat_of_tower_u128(iv_tower[1].0),
    ];
    let family = MerklePathFamily {
        depth,
        n_paths: paths.len(),
    };
    let w_log = family.n_slots().next_power_of_two().trailing_zeros() as usize;

    let to_witness = |p: &IndependentMerklePath| -> MerklePathWitness {
        assert_eq!(
            region_entries[p.leaf_index],
            lanes(&p.leaf_hash),
            "region leaf digest != φ(native leaf) at index {}",
            p.leaf_index
        );
        MerklePathWitness {
            entry: region_entries[p.leaf_index],
            siblings: p.siblings.iter().map(lanes).collect(),
            directions: p.directions.clone(),
        }
    };

    let witnesses: Vec<MerklePathWitness> = paths.iter().map(to_witness).collect();
    let cols = build_merkle_path_columns(&family, iv_flat, &witnesses, w_log);
    assert_eq!(cols.roots.len(), paths.len());
    for (p, r) in paths.iter().zip(cols.roots.iter()) {
        assert_eq!(
            *r, root_flat,
            "region-reconstructed root for leaf {} != φ(native tree root)",
            p.leaf_index
        );
    }

    // Negative: corrupt one sibling lane — that path must miss the root.
    let mut bad = witnesses.clone();
    bad[0].siblings[0][0] += F128::ONE;
    let cols = build_merkle_path_columns(&family, iv_flat, &bad, w_log);
    assert_ne!(
        cols.roots[0], root_flat,
        "a corrupted sibling still reached the committed root"
    );
}

const QUERIES: &[usize] = &[3, 3, 10, 21, 0, 31];

/// SB6 — the source-tree opening. Region source-leaf digests reconstruct the
/// native committed source-tree root under φ.
#[test]
fn source_tree_opening_via_region_families() {
    let hasher = Poseidon2bSponge::new();
    let depth = 5usize;
    let n = 1usize << depth;
    let (log_rows, n_cols) = (9usize, 1usize); // wallet shape: n_cols = 1

    let mut rng = Rng(0x50E_AF01);
    let symbols: Vec<Vec<Block128>> = (0..n)
        .map(|_| (0..n_cols * 2).map(|_| rng.block()).collect())
        .collect();
    let leaves: Vec<[u8; 32]> = (0..n)
        .map(|i| {
            source_leaf_hash(CommitmentHashBackend::Arithmetic, log_rows, n_cols, i, &symbols[i], &hasher)
        })
        .collect();
    let region_entries: Vec<[F128; 2]> = (0..n)
        .map(|i| {
            let sym_flat: Vec<F128> = symbols[i].iter().map(|&b| flat(b)).collect();
            flat_source_leaf_hash(log_rows, n_cols, i, &sym_flat)
        })
        .collect();
    check_region_opening(&leaves, &region_entries, depth, QUERIES);
}

/// Step 3i — the per-round FRI openings. The leaf is a plain
/// `hash_pair(s0, s1)`; the region uses `flat_hash_pair`.
#[test]
fn fri_round_opening_via_region_families() {
    let hasher = Poseidon2bSponge::new();
    let depth = 6usize;
    let n = 1usize << depth;

    let mut rng = Rng(0xF21_C0DE);
    let pairs: Vec<(Block128, Block128)> = (0..n).map(|_| (rng.block(), rng.block())).collect();
    let leaves: Vec<[u8; 32]> = pairs.iter().map(|(s0, s1)| hasher.hash_pair(s0, s1)).collect();
    let region_entries: Vec<[F128; 2]> = pairs
        .iter()
        .map(|(s0, s1)| flat_hash_pair(flat(*s0), flat(*s1)))
        .collect();
    check_region_opening(&leaves, &region_entries, depth, QUERIES);
}

/// SB8 — the high-fold layer openings. The leaf is `high_pair_leaf_hash`; the
/// region uses `flat_high_pair_leaf_hash` (item 3).
#[test]
fn high_pair_layer_opening_via_region_families() {
    let hasher = Poseidon2bSponge::new();
    let depth = 5usize;
    let n = 1usize << depth;
    let layer_log = 8usize;

    let mut rng = Rng(0x819A_F0);
    let pairs: Vec<(Block128, Block128)> = (0..n).map(|_| (rng.block(), rng.block())).collect();
    let leaves: Vec<[u8; 32]> = (0..n)
        .map(|i| high_pair_leaf_hash_for_trace(layer_log, i, pairs[i].0, pairs[i].1, &hasher))
        .collect();
    let region_entries: Vec<[F128; 2]> = (0..n)
        .map(|i| flat_high_pair_leaf_hash(layer_log, i, flat(pairs[i].0), flat(pairs[i].1)))
        .collect();
    check_region_opening(&leaves, &region_entries, depth, QUERIES);
}
