// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Interleaved column commitment for FRI-Binius PCS.
//!
//! All columns are bound into a single compact cap (2^5 = 32 hashes)
//! via parallel Blake3 segment hashing. No per-column NTT or full
//! Merkle tree is built — the FRI opening proof handles its own
//! commitment of the batched polynomial separately.

use noid_core::{AdditiveNTT, Block128};
use noid_fri::code::{Code, LOG_RATE, RATE};
use noid_fri::hasher::{CryptographicHasher, HashOutput};
use rayon::prelude::*;

use crate::MERKLE_CAP_DEPTH;

/// Top levels of the commitment kept as a compact binding.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MerkleCap {
    pub hashes: Vec<HashOutput>,
}

/// Public commitment to all interleaved columns (sent to verifier).
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct InterleavedCommitment {
    pub cap: MerkleCap,
    pub log_rows: usize,
    pub n_cols: usize,
}

/// Prover-side state retained after commitment (not sent to verifier).
pub struct InterleavedProverState<'a> {
    pub raw_cols: Vec<&'a [Block128]>,
    pub log_rows: usize,
    pub n_cols: usize,
    /// RS-encoded source columns used by source-bound mixed openings.
    /// Layout: `encoded_cols[col][code_index]`.
    pub encoded_cols: Vec<Vec<Block128>>,
    /// 256-bit Blake3 Merkle commitment over encoded interleaved high-pair
    /// leaves. Each leaf contains the two code symbols needed for the first
    /// source TensorFold over the highest message variable, for every committed
    /// column. Large trees are retained in chunked form to avoid keeping a full
    /// 1GB source tree resident for `log_rows=24` block bucket openings.
    pub source_tree: SourceMerkleTree,
}

pub type SourceHash = [u8; 32];

const SOURCE_HASH_BYTES: usize = 32;
const SOURCE_MERKLE_CHUNK_LOG: usize = 8;
const SOURCE_MERKLE_CHUNK_LEAVES: usize = 1 << SOURCE_MERKLE_CHUNK_LOG;
const SOURCE_MERKLE_FULL_TREE_MAX_DEPTH: usize = 18;

#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct SourceBatchedMerkleProof {
    pub siblings: Vec<SourceHash>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceHashMerkleTree {
    nodes: Vec<SourceHash>,
    layer_offsets: Vec<usize>,
    layer_lens: Vec<usize>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SourceMerkleTree {
    Full(SourceHashMerkleTree),
    Chunked {
        full_depth: usize,
        chunk_log: usize,
        upper_tree: SourceHashMerkleTree,
    },
}

impl SourceMerkleTree {
    pub(crate) fn new(encoded_cols: &[Vec<Block128>], log_rows: usize, n_cols: usize) -> Self {
        let full_depth = source_tree_depth(log_rows);
        if full_depth <= SOURCE_MERKLE_FULL_TREE_MAX_DEPTH {
            return Self::Full(SourceHashMerkleTree::new(build_source_leaf_hashes(
                encoded_cols,
                log_rows,
                n_cols,
            )));
        }

        let chunk_log = SOURCE_MERKLE_CHUNK_LOG.min(full_depth);
        let upper_depth = full_depth - chunk_log;
        let chunk_count = 1usize << upper_depth;
        let chunk_roots: Vec<SourceHash> = (0..chunk_count)
            .into_par_iter()
            .with_min_len(16)
            .map(|chunk_idx| {
                build_source_chunk_root(encoded_cols, log_rows, n_cols, chunk_log, chunk_idx)
            })
            .collect();
        Self::Chunked {
            full_depth,
            chunk_log,
            upper_tree: SourceHashMerkleTree::new(chunk_roots),
        }
    }

    pub(crate) fn get_root(&self) -> SourceHash {
        match self {
            Self::Full(tree) => tree.get_root(),
            Self::Chunked { upper_tree, .. } => upper_tree.get_root(),
        }
    }

    pub(crate) fn build_batched_merkle_proof(
        &self,
        encoded_cols: &[Vec<Block128>],
        log_rows: usize,
        n_cols: usize,
        leaf_indices: &[usize],
    ) -> SourceBatchedMerkleProof {
        match self {
            Self::Full(tree) => {
                build_source_batched_merkle_proof(tree, leaf_indices, source_tree_depth(log_rows))
            }
            Self::Chunked {
                full_depth,
                chunk_log,
                upper_tree,
            } => {
                debug_assert_eq!(*full_depth, source_tree_depth(log_rows));
                let upper_depth = full_depth - chunk_log;
                let mut chunk_cache: std::collections::HashMap<usize, SourceHashMerkleTree> =
                    std::collections::HashMap::new();
                build_source_batched_merkle_proof_with_getter(
                    *full_depth,
                    leaf_indices,
                    |node_depth, node_index| {
                        if node_depth <= upper_depth {
                            return upper_tree.get_node_at_depth(node_depth, node_index);
                        }

                        let local_depth = node_depth - upper_depth;
                        let local_width = 1usize << local_depth;
                        let chunk_idx = node_index >> local_depth;
                        let local_index = node_index & (local_width - 1);
                        let chunk_tree = chunk_cache.entry(chunk_idx).or_insert_with(|| {
                            build_source_chunk_tree(
                                encoded_cols,
                                log_rows,
                                n_cols,
                                *chunk_log,
                                chunk_idx,
                            )
                        });
                        chunk_tree.get_node_at_depth(local_depth, local_index)
                    },
                )
            }
        }
    }
}

impl SourceHashMerkleTree {
    pub(crate) fn new(leaf_hashes: Vec<SourceHash>) -> Self {
        let n = leaf_hashes.len();
        assert!(
            n.is_power_of_two(),
            "source Merkle leaves must be a power of two"
        );
        let tree_depth = n.trailing_zeros() as usize;
        let total = 2 * n - 1;
        let mut nodes = leaf_hashes;
        nodes.reserve_exact(total - n);
        nodes.resize(total, [0u8; SOURCE_HASH_BYTES]);

        let mut level_start = 0usize;
        let mut level_len = n;
        while level_len > 1 {
            let next_start = level_start + level_len;
            let next_len = level_len / 2;
            let (prefix, suffix) = nodes.split_at_mut(next_start);
            let current = &prefix[level_start..level_start + level_len];
            let next = &mut suffix[..next_len];
            if next_len >= 1024 {
                next.par_iter_mut().enumerate().for_each(|(i, out)| {
                    *out = source_compress(&current[2 * i], &current[2 * i + 1]);
                });
            } else {
                for i in 0..next_len {
                    next[i] = source_compress(&current[2 * i], &current[2 * i + 1]);
                }
            }
            level_start = next_start;
            level_len = next_len;
        }

        let mut layer_offsets = Vec::with_capacity(tree_depth + 1);
        let mut layer_lens = Vec::with_capacity(tree_depth + 1);
        let mut bottom_up_offsets = Vec::with_capacity(tree_depth + 1);
        let mut bottom_up_lens = Vec::with_capacity(tree_depth + 1);
        let mut off = 0usize;
        let mut len = n;
        loop {
            bottom_up_offsets.push(off);
            bottom_up_lens.push(len);
            if len == 1 {
                break;
            }
            off += len;
            len /= 2;
        }
        for i in (0..bottom_up_offsets.len()).rev() {
            layer_offsets.push(bottom_up_offsets[i]);
            layer_lens.push(bottom_up_lens[i]);
        }

        Self {
            nodes,
            layer_offsets,
            layer_lens,
        }
    }

    pub(crate) fn get_root(&self) -> SourceHash {
        self.nodes[self.layer_offsets[0]]
    }

    pub(crate) fn get_node_at_depth(&self, depth: usize, index: usize) -> SourceHash {
        assert!(depth < self.layer_offsets.len());
        assert!(index < self.layer_lens[depth]);
        self.nodes[self.layer_offsets[depth] + index]
    }
}

pub(crate) fn source_hash_to_output(h: SourceHash) -> HashOutput {
    h
}

pub(crate) fn source_hash_from_output(h: &HashOutput) -> Option<SourceHash> {
    Some(*h)
}

fn source_hash(hasher: blake3::Hasher) -> SourceHash {
    *hasher.finalize().as_bytes()
}

pub(crate) fn source_compress(left: &SourceHash, right: &SourceHash) -> SourceHash {
    let mut h = blake3::Hasher::new();
    h.update(b"PARANOID/SOURCE-BINDING-MERKLE-256/v2");
    h.update(left);
    h.update(right);
    source_hash(h)
}

pub(crate) fn build_source_batched_merkle_proof(
    tree: &SourceHashMerkleTree,
    leaf_indices: &[usize],
    depth: usize,
) -> SourceBatchedMerkleProof {
    build_source_batched_merkle_proof_with_getter(depth, leaf_indices, |node_depth, node_index| {
        tree.get_node_at_depth(node_depth, node_index)
    })
}

fn build_source_batched_merkle_proof_with_getter<F>(
    depth: usize,
    leaf_indices: &[usize],
    mut get_node_at_depth: F,
) -> SourceBatchedMerkleProof
where
    F: FnMut(usize, usize) -> SourceHash,
{
    let mut siblings = Vec::new();
    let mut known_at_layer: Vec<std::collections::HashSet<usize>> =
        vec![std::collections::HashSet::new(); depth + 1];
    for &idx in leaf_indices {
        known_at_layer[0].insert(idx);
    }
    for d in 0..depth {
        let mut parents_needed = std::collections::BTreeSet::new();
        for &idx in &known_at_layer[d] {
            parents_needed.insert(idx >> 1);
        }
        for &parent in &parents_needed {
            let left_child = parent * 2;
            let right_child = parent * 2 + 1;
            let left_known = known_at_layer[d].contains(&left_child);
            let right_known = known_at_layer[d].contains(&right_child);
            if left_known && right_known {
                known_at_layer[d + 1].insert(parent);
            } else if left_known {
                siblings.push(get_node_at_depth(depth - d, right_child));
                known_at_layer[d + 1].insert(parent);
            } else if right_known {
                siblings.push(get_node_at_depth(depth - d, left_child));
                known_at_layer[d + 1].insert(parent);
            }
        }
    }
    SourceBatchedMerkleProof { siblings }
}

pub(crate) fn verify_source_batched_merkle_proof(
    root: &SourceHash,
    batch: &SourceBatchedMerkleProof,
    depth: usize,
    leaf_indices: &[usize],
    leaf_hashes: &[SourceHash],
) -> Result<(), String> {
    if leaf_indices.len() != leaf_hashes.len() {
        return Err("source leaf index/hash count mismatch".into());
    }
    let mut known: std::collections::HashMap<(usize, usize), SourceHash> =
        std::collections::HashMap::new();
    for (i, &idx) in leaf_indices.iter().enumerate() {
        if let Some(&existing) = known.get(&(0, idx)) {
            if existing != leaf_hashes[i] {
                return Err(format!("inconsistent source leaf hashes for index {idx}"));
            }
        } else {
            known.insert((0, idx), leaf_hashes[i]);
        }
    }

    let mut sib_cursor = 0usize;
    for d in 0..depth {
        let mut parents_needed = std::collections::BTreeSet::new();
        for (&(layer, idx), _) in known.iter() {
            if layer == d {
                parents_needed.insert(idx >> 1);
            }
        }
        for &parent in &parents_needed {
            let left_child = parent * 2;
            let right_child = parent * 2 + 1;
            let left = known.get(&(d, left_child)).copied();
            let right = known.get(&(d, right_child)).copied();
            let parent_hash = match (left, right) {
                (Some(l), Some(r)) => source_compress(&l, &r),
                (Some(l), None) => {
                    if sib_cursor >= batch.siblings.len() {
                        return Err(format!("insufficient source siblings at layer {d}"));
                    }
                    let r = batch.siblings[sib_cursor];
                    sib_cursor += 1;
                    source_compress(&l, &r)
                }
                (None, Some(r)) => {
                    if sib_cursor >= batch.siblings.len() {
                        return Err(format!("insufficient source siblings at layer {d}"));
                    }
                    let l = batch.siblings[sib_cursor];
                    sib_cursor += 1;
                    source_compress(&l, &r)
                }
                (None, None) => return Err(format!("source orphan parent at layer {d}")),
            };
            known.insert((d + 1, parent), parent_hash);
        }
    }
    let computed_root = known
        .get(&(depth, 0))
        .ok_or_else(|| "failed to compute source root".to_string())?;
    if computed_root != root {
        return Err("source batched Merkle root mismatch".into());
    }
    if sib_cursor != batch.siblings.len() {
        return Err(format!(
            "unused source siblings: consumed {sib_cursor}, total {}",
            batch.siblings.len()
        ));
    }
    Ok(())
}

/// Commit all columns into a compact cap + prover state.
///
/// Uses parallel Blake3 hashing over column data segments. Each of the
/// 2^CAP_DEPTH segments covers `n / 2^CAP_DEPTH` rows and all columns.
/// This provides collision-resistant binding without NTT or full tree.
pub fn interleaved_commit<'a>(
    cols: &[&'a [Block128]],
    _ntt: &AdditiveNTT<Block128>,
    _hasher: &dyn CryptographicHasher,
) -> (InterleavedCommitment, InterleavedProverState<'a>) {
    assert!(!cols.is_empty());
    let n = cols[0].len();
    assert!(n.is_power_of_two());
    let log_rows = n.trailing_zeros() as usize;
    let n_cols = cols.len();

    for col in cols.iter() {
        assert_eq!(col.len(), n, "All columns must have the same length");
    }

    let cap_size = 1usize << MERKLE_CAP_DEPTH;
    let rows_per_segment = n / cap_size;

    let cap_hashes: Vec<HashOutput> = (0..cap_size)
        .into_par_iter()
        .map(|seg| {
            let start = seg * rows_per_segment;
            let end = start + rows_per_segment;
            let mut hasher = blake3::Hasher::new();
            hasher.update(b"PARANOID/INTERLEAVED-CAP/v1");
            hasher.update(&(seg as u64).to_le_bytes());
            hasher.update(&(n_cols as u64).to_le_bytes());
            hasher.update(&(log_rows as u64).to_le_bytes());
            for row in start..end {
                for col in cols.iter() {
                    let bytes = col[row].0.to_le_bytes();
                    hasher.update(&bytes);
                }
            }
            *hasher.finalize().as_bytes()
        })
        .collect();

    let encoded_cols: Vec<Vec<Block128>> = cols
        .par_iter()
        .map(|col| Code::new_parallel(col, _ntt).encoding)
        .collect();
    let source_tree = SourceMerkleTree::new(&encoded_cols, log_rows, n_cols);
    let source_root = source_hash_to_output(source_tree.get_root());

    let mut cap_hashes = cap_hashes;
    cap_hashes.push(source_root);
    let cap = MerkleCap { hashes: cap_hashes };

    let commitment = InterleavedCommitment {
        cap,
        log_rows,
        n_cols,
    };

    let state = InterleavedProverState {
        raw_cols: cols.to_vec(),
        log_rows,
        n_cols,
        encoded_cols,
        source_tree,
    };

    (commitment, state)
}

pub(crate) fn source_leaf_count(log_rows: usize) -> usize {
    1usize << (log_rows + LOG_RATE - 1)
}

pub(crate) fn source_tree_depth(log_rows: usize) -> usize {
    log_rows + LOG_RATE - 1
}

pub(crate) fn source_root_from_cap(cap: &MerkleCap) -> Option<SourceHash> {
    cap.hashes.last().and_then(source_hash_from_output)
}

pub(crate) fn source_leaf_hash(
    log_rows: usize,
    n_cols: usize,
    leaf_index: usize,
    symbols: &[Block128],
) -> SourceHash {
    assert_eq!(symbols.len(), n_cols * 2);
    let mut h = blake3::Hasher::new();
    h.update(b"PARANOID/INTERLEAVED-SOURCE-HIGH-PAIR-LEAF/256/v2");
    h.update(&(log_rows as u64).to_le_bytes());
    h.update(&(n_cols as u64).to_le_bytes());
    h.update(&(leaf_index as u64).to_le_bytes());
    for symbol in symbols {
        h.update(&symbol.0.to_le_bytes());
    }
    source_hash(h)
}

pub(crate) fn source_leaf_positions(log_rows: usize, leaf_index: usize) -> (usize, usize) {
    assert!(log_rows > 0);
    let half = 1usize << (log_rows - 1);
    let local_mask = half - 1;
    let local = leaf_index & local_mask;
    let coset = leaf_index >> (log_rows - 1);
    let base = coset * (1usize << log_rows) + local;
    (base, base + half)
}

fn build_source_leaf_hashes(
    encoded_cols: &[Vec<Block128>],
    log_rows: usize,
    n_cols: usize,
) -> Vec<SourceHash> {
    assert_source_encoded_shape(encoded_cols, log_rows, n_cols);
    let leaf_count = source_leaf_count(log_rows);
    (0..leaf_count)
        .into_par_iter()
        .map(|leaf_index| {
            source_leaf_hash_from_encoded_cols_at(encoded_cols, log_rows, n_cols, leaf_index)
        })
        .collect()
}

fn build_source_chunk_root(
    encoded_cols: &[Vec<Block128>],
    log_rows: usize,
    n_cols: usize,
    chunk_log: usize,
    chunk_idx: usize,
) -> SourceHash {
    assert_source_encoded_shape(encoded_cols, log_rows, n_cols);
    let chunk_leaf_count = 1usize << chunk_log;
    let first_leaf = chunk_idx * chunk_leaf_count;
    if chunk_log == SOURCE_MERKLE_CHUNK_LOG {
        let mut layer = [[0u8; SOURCE_HASH_BYTES]; SOURCE_MERKLE_CHUNK_LEAVES];
        for local in 0..chunk_leaf_count {
            layer[local] = source_leaf_hash_from_encoded_cols_at(
                encoded_cols,
                log_rows,
                n_cols,
                first_leaf + local,
            );
        }
        let mut len = chunk_leaf_count;
        while len > 1 {
            for i in 0..(len / 2) {
                layer[i] = source_compress(&layer[2 * i], &layer[2 * i + 1]);
            }
            len /= 2;
        }
        return layer[0];
    }

    let mut layer: Vec<SourceHash> = (0..chunk_leaf_count)
        .map(|local| {
            source_leaf_hash_from_encoded_cols_at(
                encoded_cols,
                log_rows,
                n_cols,
                first_leaf + local,
            )
        })
        .collect();
    let mut len = chunk_leaf_count;
    while len > 1 {
        for i in 0..(len / 2) {
            layer[i] = source_compress(&layer[2 * i], &layer[2 * i + 1]);
        }
        len /= 2;
    }
    layer[0]
}

fn build_source_chunk_tree(
    encoded_cols: &[Vec<Block128>],
    log_rows: usize,
    n_cols: usize,
    chunk_log: usize,
    chunk_idx: usize,
) -> SourceHashMerkleTree {
    assert_source_encoded_shape(encoded_cols, log_rows, n_cols);
    let chunk_leaf_count = 1usize << chunk_log;
    let first_leaf = chunk_idx * chunk_leaf_count;
    let leaf_hashes: Vec<SourceHash> = (0..chunk_leaf_count)
        .map(|local| {
            source_leaf_hash_from_encoded_cols_at(
                encoded_cols,
                log_rows,
                n_cols,
                first_leaf + local,
            )
        })
        .collect();
    SourceHashMerkleTree::new(leaf_hashes)
}

fn source_leaf_hash_from_encoded_cols_at(
    encoded_cols: &[Vec<Block128>],
    log_rows: usize,
    n_cols: usize,
    leaf_index: usize,
) -> SourceHash {
    let (pos0, pos1) = source_leaf_positions(log_rows, leaf_index);
    source_leaf_hash_from_encoded_cols(log_rows, n_cols, leaf_index, encoded_cols, pos0, pos1)
}

fn assert_source_encoded_shape(encoded_cols: &[Vec<Block128>], log_rows: usize, n_cols: usize) {
    assert_eq!(encoded_cols.len(), n_cols);
    let code_len = (1usize << log_rows) * RATE;
    for col in encoded_cols {
        assert_eq!(col.len(), code_len);
    }
}

fn source_leaf_hash_from_encoded_cols(
    log_rows: usize,
    n_cols: usize,
    leaf_index: usize,
    encoded_cols: &[Vec<Block128>],
    pos0: usize,
    pos1: usize,
) -> SourceHash {
    let mut h = blake3::Hasher::new();
    h.update(b"PARANOID/INTERLEAVED-SOURCE-HIGH-PAIR-LEAF/256/v2");
    h.update(&(log_rows as u64).to_le_bytes());
    h.update(&(n_cols as u64).to_le_bytes());
    h.update(&(leaf_index as u64).to_le_bytes());
    for col in encoded_cols {
        h.update(&col[pos0].0.to_le_bytes());
        h.update(&col[pos1].0.to_le_bytes());
    }
    source_hash(h)
}

/// Absorb the cap into a Fiat-Shamir channel.
pub fn absorb_cap(channel: &mut noid_fri::Channel, cap: &MerkleCap) {
    for hash in &cap.hashes {
        let hi = u128::from_le_bytes(hash[..16].try_into().unwrap());
        let lo = u128::from_le_bytes(hash[16..].try_into().unwrap());
        channel.observe_field_elem(Block128::from(hi));
        channel.observe_field_elem(Block128::from(lo));
    }
}

impl InterleavedCommitment {
    pub fn tree_depth(&self) -> usize {
        self.log_rows
    }
}
