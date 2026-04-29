// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Merkle tree with `CryptographicHasher`-based commitment.

use crate::hasher::{CryptographicHasher, HashOutput};

use rayon::prelude::*;

/// Minimum number of leaves to justify parallel Merkle build.
const MERKLE_PARALLEL_THRESHOLD: usize = 256;

/// Minimum number of hashes to justify batch hashing.
const BATCH_HASH_THRESHOLD: usize = 64;

/// Merkle tree backed by contiguous layers (index 0 = root, last = leaves).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MerkleTree {
    pub data: Vec<Vec<HashOutput>>,
}

/// Commitment that stores the Merkle root and tree depth.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VectorCommitment {
    pub root: HashOutput,
    pub depth: usize,
}

impl VectorCommitment {
    pub fn root(&self) -> HashOutput {
        self.root
    }
    pub fn depth(&self) -> usize {
        self.depth
    }
}

impl MerkleTree {
    /// Build a Merkle tree from a power-of-two set of leaf hashes.
    pub fn new(leaf_hashes: Vec<HashOutput>, hasher: &dyn CryptographicHasher) -> Self {
        assert!(
            leaf_hashes.len().is_power_of_two(),
            "Leaf hashes must be a power of two"
        );

        let tree_depth = leaf_hashes.len().trailing_zeros() as usize;
        let mut layers: Vec<Vec<HashOutput>> = Vec::with_capacity(tree_depth + 1);
        layers.push(leaf_hashes);

        for _ in 0..tree_depth {
            let prev = layers.last().unwrap();
            let next = build_parent_layer(prev, hasher);
            layers.push(next);
        }

        layers.reverse();
        MerkleTree { data: layers }
    }

    /// Build a Merkle tree with parallel, allocation-free layer hashing.
    ///
    /// All 2N-1 nodes are allocated once in a single buffer; each level is
    /// then filled in place by parallel batched hashing over adjacent pairs.
    /// Previously every layer was a fresh Vec allocation + copy.
    pub fn new_parallel(leaf_hashes: Vec<HashOutput>, hasher: &dyn CryptographicHasher) -> Self {
        let n = leaf_hashes.len();
        assert!(n.is_power_of_two(), "Leaf hashes must be a power of two");

        let tree_depth = n.trailing_zeros() as usize;
        let total = 2 * n - 1;

        let mut buf: Vec<HashOutput> = Vec::with_capacity(total);
        buf.extend_from_slice(&leaf_hashes);
        buf.resize(total, [0u8; 32]);

        let mut level_start = 0usize;
        let mut level_len = n;
        while level_len > 1 {
            let next_start = level_start + level_len;
            let next_len = level_len / 2;

            let (src_part, dst_part) = buf.split_at_mut(next_start);
            let src = &src_part[level_start..level_start + level_len];
            let dst = &mut dst_part[..next_len];

            if next_len >= MERKLE_PARALLEL_THRESHOLD / 2 {
                hash_layer_par_into(src, dst);
            } else if next_len >= BATCH_HASH_THRESHOLD {
                noid_poseidon2b::batch::compress_batch_interleaved_into(src, dst);
            } else {
                for (pair, out) in src.chunks_exact(2).zip(dst.iter_mut()) {
                    *out = hasher.compress(&pair[0], &pair[1]);
                }
            }

            level_start = next_start;
            level_len = next_len;
        }

        // Re-slice the flat buffer into per-depth layers (top-down).
        let mut layers: Vec<Vec<HashOutput>> = Vec::with_capacity(tree_depth + 1);
        let mut top_down: Vec<Vec<HashOutput>> = Vec::with_capacity(tree_depth + 1);
        let mut start = 0usize;
        let mut len = n;
        loop {
            top_down.push(buf[start..start + len].to_vec());
            if len == 1 {
                break;
            }
            start += len;
            len /= 2;
        }
        for lvl in top_down.into_iter().rev() {
            layers.push(lvl);
        }

        MerkleTree { data: layers }
    }

    pub fn get_root(&self) -> HashOutput {
        self.data[0][0]
    }

    pub fn get_merkle_path(&self, leaf_index: usize) -> Vec<HashOutput> {
        let leaf_depth = self.data.len() - 1;
        assert!(leaf_index < self.data[leaf_depth].len(), "Leaf index out of bounds");

        let mut index = leaf_index;
        let mut path = Vec::with_capacity(leaf_depth);

        for depth in (1..=leaf_depth).rev() {
            let sibling = index ^ 1;
            path.push(self.data[depth][sibling]);
            index >>= 1;
        }

        path
    }
}

/// Recompute the Merkle root from a leaf hash and its path.
pub fn verify_merkle_path(
    commitment: &VectorCommitment,
    leaf_hash: HashOutput,
    leaf_index: usize,
    merkle_path: &[HashOutput],
    hasher: &dyn CryptographicHasher,
) -> bool {
    if merkle_path.len() != commitment.depth {
        return false;
    }

    let mut hash = leaf_hash;
    for (d, sibling) in merkle_path.iter().enumerate() {
        let is_left_child = ((leaf_index >> d) & 1) == 0;
        hash = if is_left_child {
            hasher.compress(&hash, sibling)
        } else {
            hasher.compress(sibling, &hash)
        };
    }

    hash == commitment.root
}

fn build_parent_layer(child_layer: &[HashOutput], hasher: &dyn CryptographicHasher) -> Vec<HashOutput> {
    assert_eq!(
        child_layer.len() & 1,
        0,
        "Child layer must contain an even number of nodes"
    );
    let n = child_layer.len() / 2;
    let mut out = vec![[0u8; 32]; n];
    if n >= BATCH_HASH_THRESHOLD {
        noid_poseidon2b::batch::compress_batch_interleaved_into(child_layer, &mut out);
    } else {
        for (pair, slot) in child_layer.chunks_exact(2).zip(out.iter_mut()) {
            *slot = hasher.compress(&pair[0], &pair[1]);
        }
    }
    out
}

/// Parallel batched layer hashing writing directly into `dst`.
///
/// `src` is a slice of 2N children; `dst` is the N-entry parent layer.
fn hash_layer_par_into(src: &[HashOutput], dst: &mut [HashOutput]) {
    assert_eq!(src.len(), dst.len() * 2);
    let threads = rayon::current_num_threads().max(1);
    let mut chunk_pairs = ((src.len() / threads).max(BATCH_HASH_THRESHOLD * 2)) & !1;
    if chunk_pairs == 0 {
        chunk_pairs = 2;
    }
    let chunk_dst = chunk_pairs / 2;

    src.par_chunks(chunk_pairs)
        .zip(dst.par_chunks_mut(chunk_dst))
        .for_each(|(src_chunk, dst_chunk)| {
            noid_poseidon2b::batch::compress_batch_interleaved_into(src_chunk, dst_chunk);
        });
}

/// Hash a slice of Block128 element pairs into leaf hashes using `hash_pair`.
///
/// Uses rayon-parallel batched hashing on large inputs; batched-but-serial
/// for medium; scalar for small. No de-interleaving allocation — the batch
/// kernel reads the interleaved slice directly.
pub fn compute_leaf_hashes(
    vals: &[noid_core::Block128],
    hasher: &dyn CryptographicHasher,
) -> Vec<HashOutput> {
    assert_eq!(
        vals.len() & 1,
        0,
        "Leaf construction requires an even number of elements"
    );
    let n = vals.len() / 2;
    let mut out = vec![[0u8; 32]; n];

    if n >= MERKLE_PARALLEL_THRESHOLD / 2 {
        let threads = rayon::current_num_threads().max(1);
        // pair-count chunks must be a multiple of PACKED_LANES and at least
        // BATCH_HASH_THRESHOLD to amortise the batched kernel.
        let mut chunk_pairs = ((n / threads).max(BATCH_HASH_THRESHOLD)) & !(
            (noid_core::packed::PACKED_LANES.max(1)) - 1
        );
        if chunk_pairs == 0 {
            chunk_pairs = BATCH_HASH_THRESHOLD;
        }
        let chunk_vals = chunk_pairs * 2;

        vals.par_chunks(chunk_vals)
            .zip(out.par_chunks_mut(chunk_pairs))
            .for_each(|(vals_chunk, out_chunk)| {
                noid_poseidon2b::batch::hash_pair_batch_interleaved_into(vals_chunk, out_chunk);
            });
    } else if n >= BATCH_HASH_THRESHOLD {
        noid_poseidon2b::batch::hash_pair_batch_interleaved_into(vals, &mut out);
    } else {
        for (pair, slot) in vals.chunks_exact(2).zip(out.iter_mut()) {
            *slot = hasher.hash_pair(&pair[0], &pair[1]);
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    use noid_poseidon2b::Poseidon2bSponge;

    #[test]
    fn test_merkle_tree_basic() {
        let hasher = Poseidon2bSponge::new();
        let leaves: Vec<HashOutput> = (0..8)
            .map(|i| {
                let mut buf = [0u8; 32];
                buf[0] = i as u8;
                buf
            })
            .collect();

        let tree = MerkleTree::new(leaves.clone(), &hasher);
        let commitment = VectorCommitment {
            root: tree.get_root(),
            depth: 3,
        };

        for (i, &leaf) in leaves.iter().enumerate() {
            let path = tree.get_merkle_path(i);
            assert!(verify_merkle_path(&commitment, leaf, i, &path, &hasher));
        }
    }
}

