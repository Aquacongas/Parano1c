// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Interleaved column commitment for FRI-Binius PCS.
//!
//! All columns are bound into a single compact cap (2^5 = 32 hashes). The
//! cap and source-binding Merkle nodes use the caller's field-friendly hasher.

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

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum CommitmentHashBackend {
    Arithmetic = 1,
}

impl CommitmentHashBackend {
    pub fn as_u128(self) -> u128 {
        match self {
            Self::Arithmetic => 1,
        }
    }
}

/// Public commitment to all interleaved columns (sent to verifier).
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct InterleavedCommitment {
    pub cap: MerkleCap,
    pub log_rows: usize,
    pub n_cols: usize,
    pub hash_backend: CommitmentHashBackend,
}

/// Prover-side state retained after commitment (not sent to verifier).
pub struct InterleavedProverState<'a> {
    pub raw_cols: Vec<&'a [Block128]>,
    pub log_rows: usize,
    pub n_cols: usize,
    /// RS-encoded source columns used by source-bound mixed openings.
    /// Layout: `encoded_cols[col][code_index]`.
    pub encoded_cols: Vec<Vec<Block128>>,
    /// Merkle commitment over encoded interleaved high-pair leaves. Each leaf
    /// contains the two code symbols needed for the first source TensorFold over
    /// the highest message variable, for every committed column. Large trees are
    /// retained in chunked form to avoid keeping a full 1GB source tree resident
    /// for `log_rows=24` diagnostic bucket openings.
    pub source_tree: SourceMerkleTree,
    pub hash_backend: CommitmentHashBackend,
}

pub type SourceHash = [u8; 32];

const SOURCE_HASH_BYTES: usize = 32;
const SOURCE_MERKLE_CHUNK_LOG: usize = 8;
const SOURCE_MERKLE_CHUNK_LEAVES: usize = 1 << SOURCE_MERKLE_CHUNK_LOG;
const SOURCE_MERKLE_FULL_TREE_MAX_DEPTH: usize = 18;
const SOURCE_CAP_DEPTH: usize = MERKLE_CAP_DEPTH;

#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct SourceBatchedMerkleProof {
    pub siblings: Vec<SourceHash>,
}

/// One canonical missing-sibling position in a batched path to a Merkle cap.
/// `depth_from_root == depth` denotes the leaf layer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SourceMerkleSiblingPosition {
    pub depth_from_root: usize,
    pub index: usize,
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
    pub(crate) fn new(
        encoded_cols: &[Vec<Block128>],
        log_rows: usize,
        n_cols: usize,
        backend: CommitmentHashBackend,
        hasher: &dyn CryptographicHasher,
    ) -> Self {
        let full_depth = source_tree_depth(log_rows);
        if full_depth <= SOURCE_MERKLE_FULL_TREE_MAX_DEPTH {
            return Self::Full(SourceHashMerkleTree::new(
                build_source_leaf_hashes(encoded_cols, log_rows, n_cols, backend, hasher),
                backend,
                hasher,
            ));
        }

        let chunk_log = SOURCE_MERKLE_CHUNK_LOG.min(full_depth);
        let upper_depth = full_depth - chunk_log;
        let chunk_count = 1usize << upper_depth;
        let chunk_roots: Vec<SourceHash> = (0..chunk_count)
            .into_par_iter()
            .with_min_len(16)
            .map(|chunk_idx| {
                build_source_chunk_root(
                    encoded_cols,
                    log_rows,
                    n_cols,
                    chunk_log,
                    chunk_idx,
                    backend,
                    hasher,
                )
            })
            .collect();
        Self::Chunked {
            full_depth,
            chunk_log,
            upper_tree: SourceHashMerkleTree::new(chunk_roots, backend, hasher),
        }
    }

    pub(crate) fn build_batched_merkle_proof_to_cap(
        &self,
        encoded_cols: &[Vec<Block128>],
        log_rows: usize,
        n_cols: usize,
        leaf_indices: &[usize],
        cap_depth: usize,
        backend: CommitmentHashBackend,
        hasher: &dyn CryptographicHasher,
    ) -> SourceBatchedMerkleProof {
        match self {
            Self::Full(tree) => build_source_batched_merkle_proof_to_cap(
                tree,
                leaf_indices,
                source_tree_depth(log_rows),
                cap_depth,
                backend,
                hasher,
            ),
            Self::Chunked {
                full_depth,
                chunk_log,
                upper_tree,
            } => {
                debug_assert_eq!(*full_depth, source_tree_depth(log_rows));
                let upper_depth = full_depth - chunk_log;
                assert!(
                    cap_depth <= upper_depth,
                    "source cap must stay inside chunked upper tree"
                );
                let mut chunk_cache: std::collections::HashMap<usize, SourceHashMerkleTree> =
                    std::collections::HashMap::new();
                build_source_batched_merkle_proof_with_getter_to_cap(
                    *full_depth,
                    cap_depth,
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
                                backend,
                                hasher,
                            )
                        });
                        chunk_tree.get_node_at_depth(local_depth, local_index)
                    },
                )
            }
        }
    }

    pub(crate) fn get_cap(&self, cap_depth: usize) -> Vec<SourceHash> {
        match self {
            Self::Full(tree) => tree.get_layer_at_depth(cap_depth),
            Self::Chunked {
                full_depth,
                chunk_log,
                upper_tree,
            } => {
                let upper_depth = full_depth - chunk_log;
                assert!(
                    cap_depth <= upper_depth,
                    "source cap must stay inside chunked upper tree"
                );
                upper_tree.get_layer_at_depth(cap_depth)
            }
        }
    }
}

impl SourceHashMerkleTree {
    pub(crate) fn new(
        leaf_hashes: Vec<SourceHash>,
        backend: CommitmentHashBackend,
        hasher: &dyn CryptographicHasher,
    ) -> Self {
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
                    *out = source_compress(backend, &current[2 * i], &current[2 * i + 1], hasher);
                });
            } else {
                for i in 0..next_len {
                    next[i] =
                        source_compress(backend, &current[2 * i], &current[2 * i + 1], hasher);
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

    #[cfg(test)]
    pub(crate) fn get_root(&self) -> SourceHash {
        self.nodes[self.layer_offsets[0]]
    }

    pub(crate) fn get_node_at_depth(&self, depth: usize, index: usize) -> SourceHash {
        assert!(depth < self.layer_offsets.len());
        assert!(index < self.layer_lens[depth]);
        self.nodes[self.layer_offsets[depth] + index]
    }

    pub(crate) fn get_layer_at_depth(&self, depth: usize) -> Vec<SourceHash> {
        assert!(depth < self.layer_offsets.len());
        let offset = self.layer_offsets[depth];
        let len = self.layer_lens[depth];
        self.nodes[offset..offset + len].to_vec()
    }
}

pub(crate) fn source_hash_to_output(h: SourceHash) -> HashOutput {
    h
}

pub(crate) fn source_compress(
    _backend: CommitmentHashBackend,
    left: &SourceHash,
    right: &SourceHash,
    hasher: &dyn CryptographicHasher,
) -> SourceHash {
    hasher.compress(left, right)
}

/// Canonical sibling schedule shared by native builders, recursive geometry,
/// and security-model differentials.
pub fn canonical_source_batched_merkle_sibling_positions(
    depth: usize,
    cap_depth: usize,
    leaf_indices: &[usize],
) -> Result<Vec<SourceMerkleSiblingPosition>, String> {
    if cap_depth > depth {
        return Err("source cap depth exceeds tree depth".into());
    }
    let leaf_bound = 1usize
        .checked_shl(depth as u32)
        .ok_or_else(|| "source tree depth exceeds usize".to_string())?;
    if let Some(&index) = leaf_indices.iter().find(|&&index| index >= leaf_bound) {
        return Err(format!("source leaf index {index} out of range"));
    }

    let mut positions = Vec::new();
    let mut known = sorted_unique_usize(leaf_indices);
    for d in 0..(depth - cap_depth) {
        let parents = sorted_unique_parents(&known);
        let mut next = Vec::with_capacity(parents.len());
        for &parent in &parents {
            let left_child = parent * 2;
            let right_child = parent * 2 + 1;
            let left_known = known.binary_search(&left_child).is_ok();
            let right_known = known.binary_search(&right_child).is_ok();
            if left_known && right_known {
            } else if left_known {
                positions.push(SourceMerkleSiblingPosition {
                    depth_from_root: depth - d,
                    index: right_child,
                });
            } else if right_known {
                positions.push(SourceMerkleSiblingPosition {
                    depth_from_root: depth - d,
                    index: left_child,
                });
            }
            if left_known || right_known {
                next.push(parent);
            }
        }
        known = next;
    }
    Ok(positions)
}

fn build_source_batched_merkle_proof_with_getter_to_cap<F>(
    depth: usize,
    cap_depth: usize,
    leaf_indices: &[usize],
    mut get_node_at_depth: F,
) -> SourceBatchedMerkleProof
where
    F: FnMut(usize, usize) -> SourceHash,
{
    let positions =
        canonical_source_batched_merkle_sibling_positions(depth, cap_depth, leaf_indices)
            .expect("internal source Merkle opening shape");
    let siblings = positions
        .into_iter()
        .map(|position| get_node_at_depth(position.depth_from_root, position.index))
        .collect();
    SourceBatchedMerkleProof { siblings }
}

pub(crate) fn build_source_batched_merkle_proof_to_cap(
    tree: &SourceHashMerkleTree,
    leaf_indices: &[usize],
    depth: usize,
    cap_depth: usize,
    backend: CommitmentHashBackend,
    hasher: &dyn CryptographicHasher,
) -> SourceBatchedMerkleProof {
    let _ = (backend, hasher);
    build_source_batched_merkle_proof_with_getter_to_cap(
        depth,
        cap_depth,
        leaf_indices,
        |node_depth, node_index| tree.get_node_at_depth(node_depth, node_index),
    )
}

pub(crate) fn verify_source_batched_merkle_proof_to_cap(
    cap_nodes: &[SourceHash],
    cap_depth: usize,
    batch: &SourceBatchedMerkleProof,
    depth: usize,
    leaf_indices: &[usize],
    leaf_hashes: &[SourceHash],
    backend: CommitmentHashBackend,
    hasher: &dyn CryptographicHasher,
) -> Result<(), String> {
    if cap_depth > depth {
        return Err("source cap depth exceeds tree depth".into());
    }
    if cap_nodes.len() != (1usize << cap_depth) {
        return Err("source cap width mismatch".into());
    }
    if leaf_indices.len() != leaf_hashes.len() {
        return Err("source leaf index/hash count mismatch".into());
    }
    let (mut known_indices, mut known_hashes) =
        sorted_unique_source_leaf_hashes(leaf_indices, leaf_hashes)
            .map_err(|idx| format!("inconsistent source leaf hashes for index {idx}"))?;

    let mut sib_cursor = 0usize;
    for d in 0..(depth - cap_depth) {
        let mut next_indices = Vec::new();
        let mut next_hashes = Vec::new();
        let mut cursor = 0usize;
        while cursor < known_indices.len() {
            let parent = known_indices[cursor] >> 1;
            let left_child = parent * 2;
            let right_child = left_child + 1;
            let mut left = None;
            let mut right = None;
            while cursor < known_indices.len() && (known_indices[cursor] >> 1) == parent {
                let idx = known_indices[cursor];
                if idx == left_child {
                    left = Some(known_hashes[cursor]);
                } else if idx == right_child {
                    right = Some(known_hashes[cursor]);
                } else {
                    return Err(format!("source bad child index {idx} at layer {d}"));
                }
                cursor += 1;
            }
            let parent_hash = match (left, right) {
                (Some(l), Some(r)) => source_compress(backend, &l, &r, hasher),
                (Some(l), None) => {
                    if sib_cursor >= batch.siblings.len() {
                        return Err(format!("insufficient source siblings at layer {d}"));
                    }
                    let r = batch.siblings[sib_cursor];
                    sib_cursor += 1;
                    source_compress(backend, &l, &r, hasher)
                }
                (None, Some(r)) => {
                    if sib_cursor >= batch.siblings.len() {
                        return Err(format!("insufficient source siblings at layer {d}"));
                    }
                    let l = batch.siblings[sib_cursor];
                    sib_cursor += 1;
                    source_compress(backend, &l, &r, hasher)
                }
                (None, None) => return Err(format!("source orphan parent at layer {d}")),
            };
            next_indices.push(parent);
            next_hashes.push(parent_hash);
        }
        known_indices = next_indices;
        known_hashes = next_hashes;
    }
    for (idx, hash) in known_indices.iter().zip(known_hashes.iter()) {
        if *idx >= cap_nodes.len() {
            return Err("source cap node index out of range".into());
        }
        if hash != &cap_nodes[*idx] {
            return Err("source batched Merkle cap mismatch".into());
        }
    }
    if sib_cursor != batch.siblings.len() {
        return Err(format!(
            "unused source siblings: consumed {sib_cursor}, total {}",
            batch.siblings.len()
        ));
    }
    Ok(())
}

fn sorted_unique_usize(values: &[usize]) -> Vec<usize> {
    let mut out = values.to_vec();
    out.sort_unstable();
    out.dedup();
    out
}

fn sorted_unique_parents(values: &[usize]) -> Vec<usize> {
    let mut out = Vec::with_capacity(values.len());
    let mut last = None;
    for &value in values {
        let parent = value >> 1;
        if last != Some(parent) {
            out.push(parent);
            last = Some(parent);
        }
    }
    out
}

fn sorted_unique_source_leaf_hashes(
    leaf_indices: &[usize],
    leaf_hashes: &[SourceHash],
) -> Result<(Vec<usize>, Vec<SourceHash>), usize> {
    let mut pairs: Vec<(usize, SourceHash)> = leaf_indices
        .iter()
        .copied()
        .zip(leaf_hashes.iter().copied())
        .collect();
    pairs.sort_unstable_by_key(|(idx, _)| *idx);

    let mut indices = Vec::with_capacity(pairs.len());
    let mut hashes = Vec::with_capacity(pairs.len());
    for (idx, hash) in pairs {
        if indices.last().copied() == Some(idx) {
            if hashes.last().copied() != Some(hash) {
                return Err(idx);
            }
        } else {
            indices.push(idx);
            hashes.push(hash);
        }
    }
    Ok((indices, hashes))
}

/// Commit all columns into a compact cap + prover state using the arithmetic
/// hash backend.
pub fn interleaved_commit<'a>(
    cols: &[&'a [Block128]],
    ntt: &AdditiveNTT<Block128>,
    hasher: &dyn CryptographicHasher,
) -> (InterleavedCommitment, InterleavedProverState<'a>) {
    interleaved_commit_with_backend(cols, ntt, hasher, CommitmentHashBackend::Arithmetic)
}

/// Commit all columns into a compact cap + prover state using the supplied
/// arithmetic-friendly hasher for cap and source-binding Merkle nodes.
pub fn interleaved_commit_arithmetic<'a>(
    cols: &[&'a [Block128]],
    ntt: &AdditiveNTT<Block128>,
    hasher: &dyn CryptographicHasher,
) -> (InterleavedCommitment, InterleavedProverState<'a>) {
    interleaved_commit_with_backend(cols, ntt, hasher, CommitmentHashBackend::Arithmetic)
}

fn interleaved_commit_with_backend<'a>(
    cols: &[&'a [Block128]],
    ntt: &AdditiveNTT<Block128>,
    hasher: &dyn CryptographicHasher,
    backend: CommitmentHashBackend,
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
            interleaved_cap_segment_hash(
                backend,
                cols,
                seg,
                rows_per_segment,
                n_cols,
                log_rows,
                hasher,
            )
        })
        .collect();

    let encoded_cols: Vec<Vec<Block128>> = cols
        .par_iter()
        .map(|col| Code::new_parallel(col, ntt).encoding)
        .collect();
    let source_tree = SourceMerkleTree::new(&encoded_cols, log_rows, n_cols, backend, hasher);
    let source_cap = source_tree.get_cap(source_cap_depth(log_rows));

    let mut cap_hashes = cap_hashes;
    cap_hashes.extend(source_cap.into_iter().map(source_hash_to_output));
    let cap = MerkleCap { hashes: cap_hashes };

    let commitment = InterleavedCommitment {
        cap,
        log_rows,
        n_cols,
        hash_backend: backend,
    };

    let state = InterleavedProverState {
        raw_cols: cols.to_vec(),
        log_rows,
        n_cols,
        encoded_cols,
        source_tree,
        hash_backend: backend,
    };

    (commitment, state)
}

fn interleaved_cap_segment_hash(
    _backend: CommitmentHashBackend,
    cols: &[&[Block128]],
    seg: usize,
    rows_per_segment: usize,
    n_cols: usize,
    log_rows: usize,
    hasher: &dyn CryptographicHasher,
) -> HashOutput {
    let start = seg * rows_per_segment;
    let end = start + rows_per_segment;
    const CAP_DOMAIN: u128 = 0xF21B_1DCA_0000_0001u128;
    let mut acc = hasher.hash_pair(
        &Block128::from(CAP_DOMAIN),
        &Block128::from(log_rows as u128),
    );
    let meta = hasher.hash_pair(
        &Block128::from(seg as u128),
        &Block128::from(n_cols as u128),
    );
    acc = hasher.compress(&acc, &meta);
    for row in start..end {
        for col in cols.iter() {
            let elem = hasher.hash_field(&col[row]);
            acc = hasher.compress(&acc, &elem);
        }
    }
    acc
}

pub(crate) fn source_leaf_count(log_rows: usize) -> usize {
    1usize << (log_rows + LOG_RATE - 1)
}

pub fn source_tree_depth(log_rows: usize) -> usize {
    log_rows + LOG_RATE - 1
}

pub fn source_cap_depth(log_rows: usize) -> usize {
    SOURCE_CAP_DEPTH.min(source_tree_depth(log_rows))
}

pub fn source_cap_from_commitment_cap(cap: &MerkleCap, log_rows: usize) -> Option<&[SourceHash]> {
    let cap_depth = source_cap_depth(log_rows);
    let source_cap_count = 1usize << cap_depth;
    let start = 1usize << MERKLE_CAP_DEPTH;
    let end = start.checked_add(source_cap_count)?;
    if cap.hashes.len() != end {
        return None;
    }
    Some(&cap.hashes[start..end])
}

pub fn source_leaf_hash(
    _backend: CommitmentHashBackend,
    log_rows: usize,
    n_cols: usize,
    leaf_index: usize,
    symbols: &[Block128],
    hasher: &dyn CryptographicHasher,
) -> SourceHash {
    assert_eq!(symbols.len(), n_cols * 2);
    source_leaf_hash_arithmetic(log_rows, n_cols, leaf_index, symbols, hasher)
}

/// Domain tag for encoded-source leaf hashes.
///
/// Public so the in-circuit trace twin can replay this definition;
/// change both together.
pub const SOURCE_LEAF_DOMAIN: u128 = 0xF21B_1D50_0000_0001u128;

fn source_leaf_hash_arithmetic(
    log_rows: usize,
    n_cols: usize,
    leaf_index: usize,
    symbols: &[Block128],
    hasher: &dyn CryptographicHasher,
) -> SourceHash {
    let mut acc = hasher.hash_pair(
        &Block128::from(SOURCE_LEAF_DOMAIN),
        &Block128::from(log_rows as u128),
    );
    let meta = hasher.hash_pair(
        &Block128::from(n_cols as u128),
        &Block128::from(leaf_index as u128),
    );
    acc = hasher.compress(&acc, &meta);
    let mut pair_hashes = vec![[0u8; 32]; symbols.len() / 2];
    hasher.batch_hash_pair(symbols, &mut pair_hashes);
    for pair_hash in pair_hashes {
        acc = hasher.compress(&acc, &pair_hash);
    }
    acc
}

pub fn source_leaf_positions(log_rows: usize, leaf_index: usize) -> (usize, usize) {
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
    backend: CommitmentHashBackend,
    hasher: &dyn CryptographicHasher,
) -> Vec<SourceHash> {
    assert_source_encoded_shape(encoded_cols, log_rows, n_cols);
    let leaf_count = source_leaf_count(log_rows);
    (0..leaf_count)
        .into_par_iter()
        .map(|leaf_index| {
            source_leaf_hash_from_encoded_cols_at(
                encoded_cols,
                log_rows,
                n_cols,
                leaf_index,
                backend,
                hasher,
            )
        })
        .collect()
}

fn build_source_chunk_root(
    encoded_cols: &[Vec<Block128>],
    log_rows: usize,
    n_cols: usize,
    chunk_log: usize,
    chunk_idx: usize,
    backend: CommitmentHashBackend,
    hasher: &dyn CryptographicHasher,
) -> SourceHash {
    assert_source_encoded_shape(encoded_cols, log_rows, n_cols);
    let chunk_leaf_count = 1usize << chunk_log;
    let first_leaf = chunk_idx * chunk_leaf_count;
    if chunk_log == SOURCE_MERKLE_CHUNK_LOG {
        let mut layer = [[0u8; SOURCE_HASH_BYTES]; SOURCE_MERKLE_CHUNK_LEAVES];
        for (local, leaf) in layer.iter_mut().take(chunk_leaf_count).enumerate() {
            *leaf = source_leaf_hash_from_encoded_cols_at(
                encoded_cols,
                log_rows,
                n_cols,
                first_leaf + local,
                backend,
                hasher,
            );
        }
        let mut len = chunk_leaf_count;
        while len > 1 {
            for i in 0..(len / 2) {
                layer[i] = source_compress(backend, &layer[2 * i], &layer[2 * i + 1], hasher);
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
                backend,
                hasher,
            )
        })
        .collect();
    let mut len = chunk_leaf_count;
    while len > 1 {
        for i in 0..(len / 2) {
            layer[i] = source_compress(backend, &layer[2 * i], &layer[2 * i + 1], hasher);
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
    backend: CommitmentHashBackend,
    hasher: &dyn CryptographicHasher,
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
                backend,
                hasher,
            )
        })
        .collect();
    SourceHashMerkleTree::new(leaf_hashes, backend, hasher)
}

fn source_leaf_hash_from_encoded_cols_at(
    encoded_cols: &[Vec<Block128>],
    log_rows: usize,
    n_cols: usize,
    leaf_index: usize,
    backend: CommitmentHashBackend,
    hasher: &dyn CryptographicHasher,
) -> SourceHash {
    let (pos0, pos1) = source_leaf_positions(log_rows, leaf_index);
    source_leaf_hash_from_encoded_cols(
        log_rows,
        n_cols,
        leaf_index,
        encoded_cols,
        pos0,
        pos1,
        backend,
        hasher,
    )
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
    backend: CommitmentHashBackend,
    hasher: &dyn CryptographicHasher,
) -> SourceHash {
    let _ = backend;
    let mut symbols = Vec::with_capacity(n_cols * 2);
    for col in encoded_cols {
        symbols.push(col[pos0]);
        symbols.push(col[pos1]);
    }
    source_leaf_hash_arithmetic(log_rows, n_cols, leaf_index, &symbols, hasher)
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
