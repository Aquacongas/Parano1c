// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Canonical exact sparse Merkle multiproofs.
//!
//! The proof contains only missing frontier hashes. Indices, directions and
//! topology are verifier-derived from the canonical touched set.

use std::collections::{BTreeMap, BTreeSet};

use crate::exact_state_hash::{state_node_hash, zero_slot_roots, StateHash};

/// Canonical Merkle multiproof with implicit topology.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CanonicalMerkleMultiProof {
    pub siblings: Vec<StateHash>,
}

/// One directed full path derived from a canonical multiproof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpandedMerklePath {
    pub index: u32,
    pub leaf: StateHash,
    pub siblings: Vec<StateHash>,
    /// `false`: current node is left child. `true`: current node is right child.
    pub directions: Vec<bool>,
}

/// Sparse non-default node cache for exact-state proofs.
#[derive(Debug, Clone)]
pub struct SparseMerkleCache {
    depth: u32,
    zero_roots: Vec<StateHash>,
    nodes: BTreeMap<(u32, u64), StateHash>,
}

/// Errors returned by sparse Merkle proof helpers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SparseMerkleError {
    InvalidDepth {
        depth: u32,
    },
    EmptyIndices,
    LeafCountMismatch {
        indices: usize,
        leaves: usize,
    },
    UnsortedIndices,
    DuplicateIndex {
        index: u32,
    },
    IndexOutOfRange {
        index: u32,
        depth: u32,
    },
    ProofLengthMismatch {
        expected: usize,
        actual: usize,
    },
    CacheDepthMismatch {
        cache_depth: u32,
        requested_depth: u32,
    },
}

impl core::fmt::Display for SparseMerkleError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidDepth { depth } => write!(f, "invalid sparse Merkle depth {depth}"),
            Self::EmptyIndices => write!(f, "sparse Merkle proof requires at least one index"),
            Self::LeafCountMismatch { indices, leaves } => {
                write!(
                    f,
                    "leaf count {leaves} does not match index count {indices}"
                )
            }
            Self::UnsortedIndices => write!(f, "indices must be strictly sorted"),
            Self::DuplicateIndex { index } => write!(f, "duplicate index {index}"),
            Self::IndexOutOfRange { index, depth } => {
                write!(f, "index {index} is out of range for depth {depth}")
            }
            Self::ProofLengthMismatch { expected, actual } => {
                write!(f, "proof has {actual} siblings, expected {expected}")
            }
            Self::CacheDepthMismatch {
                cache_depth,
                requested_depth,
            } => write!(
                f,
                "cache depth {cache_depth} does not match requested depth {requested_depth}"
            ),
        }
    }
}

impl std::error::Error for SparseMerkleError {}

impl SparseMerkleCache {
    /// Create an empty exact sparse Merkle cache at `depth`.
    pub fn new(depth: u32) -> Result<Self, SparseMerkleError> {
        validate_depth(depth)?;
        Ok(Self {
            depth,
            zero_roots: zero_slot_roots(depth as usize),
            nodes: BTreeMap::new(),
        })
    }

    /// Create a cache and apply leaf updates.
    pub fn from_leaves(depth: u32, leaves: &[(u32, StateHash)]) -> Result<Self, SparseMerkleError> {
        let mut cache = Self::new(depth)?;
        for &(index, leaf) in leaves {
            cache.set_leaf(index, leaf)?;
        }
        Ok(cache)
    }

    #[inline]
    pub fn depth(&self) -> u32 {
        self.depth
    }

    /// Return the exact Merkle root represented by this cache.
    pub fn root(&self) -> StateHash {
        self.node_hash(self.depth, 0)
    }

    /// Read one cached node or the canonical zero node for its level.
    pub fn node_hash(&self, level: u32, index: u64) -> StateHash {
        self.nodes
            .get(&(level, index))
            .copied()
            .unwrap_or_else(|| self.zero_roots[level as usize])
    }

    /// Set one leaf and update only its ancestor path.
    pub fn set_leaf(&mut self, index: u32, leaf: StateHash) -> Result<(), SparseMerkleError> {
        validate_index(index, self.depth)?;
        let mut idx = index as u64;
        let mut hash = leaf;
        self.set_node(0, idx, hash);
        for level in 0..self.depth {
            let sibling_idx = idx ^ 1;
            let base = idx & !1;
            let (left, right) = if idx == base {
                (hash, self.node_hash(level, sibling_idx))
            } else {
                (self.node_hash(level, sibling_idx), hash)
            };
            hash = state_node_hash(left, right);
            idx = base / 2;
            self.set_node(level + 1, idx, hash);
        }
        Ok(())
    }

    fn set_node(&mut self, level: u32, index: u64, hash: StateHash) {
        if hash == self.zero_roots[level as usize] {
            self.nodes.remove(&(level, index));
        } else {
            self.nodes.insert((level, index), hash);
        }
    }
}

/// Return the exact number of sibling hashes needed for sorted `indices`.
pub fn expected_sibling_count(indices: &[u32], depth: u32) -> Result<usize, SparseMerkleError> {
    let mut known = validate_indices(indices, depth)?;
    let mut count = 0usize;
    for _level in 0..depth {
        let mut next = BTreeSet::new();
        let mut processed = BTreeSet::new();
        for &pos in &known {
            let base = pos & !1;
            if !processed.insert(base) {
                continue;
            }
            let left_known = known.contains(&base);
            let right_known = known.contains(&(base + 1));
            if left_known ^ right_known {
                count = count.saturating_add(1);
            }
            next.insert(base / 2);
        }
        known = next;
    }
    Ok(count)
}

/// Reconstruct the Merkle root for sorted `indices` and index-aligned `leaves`.
pub fn reconstruct_root(
    indices: &[u32],
    leaves: &[StateHash],
    siblings: &[StateHash],
    depth: u32,
) -> Result<StateHash, SparseMerkleError> {
    if indices.len() != leaves.len() {
        return Err(SparseMerkleError::LeafCountMismatch {
            indices: indices.len(),
            leaves: leaves.len(),
        });
    }
    let expected = expected_sibling_count(indices, depth)?;
    if siblings.len() != expected {
        return Err(SparseMerkleError::ProofLengthMismatch {
            expected,
            actual: siblings.len(),
        });
    }

    let mut known: BTreeMap<u64, StateHash> = indices
        .iter()
        .copied()
        .zip(leaves.iter().copied())
        .map(|(index, leaf)| (index as u64, leaf))
        .collect();
    let mut cursor = 0usize;

    for _level in 0..depth {
        let mut next = BTreeMap::new();
        let mut processed = BTreeSet::new();
        for &pos in known.keys() {
            let base = pos & !1;
            if !processed.insert(base) {
                continue;
            }
            let left = known.get(&base).copied();
            let right = known.get(&(base + 1)).copied();
            let parent = match (left, right) {
                (Some(left), Some(right)) => state_node_hash(left, right),
                (Some(left), None) => {
                    let right = siblings[cursor];
                    cursor += 1;
                    state_node_hash(left, right)
                }
                (None, Some(right)) => {
                    let left = siblings[cursor];
                    cursor += 1;
                    state_node_hash(left, right)
                }
                (None, None) => unreachable!("processed parent must have one known child"),
            };
            next.insert(base / 2, parent);
        }
        known = next;
    }

    debug_assert_eq!(cursor, siblings.len());
    match known.into_iter().next() {
        Some((0, root)) => Ok(root),
        _ => Err(SparseMerkleError::InvalidDepth { depth }),
    }
}

/// Expand a canonical implicit multiproof into one directed full path per leaf.
///
/// This is a deterministic verifier-side projection of the same proof consumed
/// by [`reconstruct_root`]. Sibling hashes may come either from the explicit
/// proof vector or from another known touched subtree.
pub fn expand_multiproof_paths(
    indices: &[u32],
    leaves: &[StateHash],
    siblings: &[StateHash],
    depth: u32,
) -> Result<Vec<ExpandedMerklePath>, SparseMerkleError> {
    if indices.len() != leaves.len() {
        return Err(SparseMerkleError::LeafCountMismatch {
            indices: indices.len(),
            leaves: leaves.len(),
        });
    }
    let expected = expected_sibling_count(indices, depth)?;
    if siblings.len() != expected {
        return Err(SparseMerkleError::ProofLengthMismatch {
            expected,
            actual: siblings.len(),
        });
    }

    #[derive(Clone)]
    struct Node {
        hash: StateHash,
        leaves: Vec<usize>,
    }

    let path_depth = depth as usize;
    let mut out: Vec<ExpandedMerklePath> = indices
        .iter()
        .copied()
        .zip(leaves.iter().copied())
        .map(|(index, leaf)| ExpandedMerklePath {
            index,
            leaf,
            siblings: vec![[0u8; 32]; path_depth],
            directions: vec![false; path_depth],
        })
        .collect();
    let mut known: BTreeMap<u64, Node> = indices
        .iter()
        .copied()
        .zip(leaves.iter().copied())
        .enumerate()
        .map(|(leaf_pos, (index, leaf))| {
            (
                index as u64,
                Node {
                    hash: leaf,
                    leaves: vec![leaf_pos],
                },
            )
        })
        .collect();
    let mut cursor = 0usize;

    for level in 0..depth {
        let mut next = BTreeMap::new();
        let mut processed = BTreeSet::new();
        for &pos in known.keys() {
            let base = pos & !1;
            if !processed.insert(base) {
                continue;
            }
            let left = known.get(&base).cloned();
            let right = known.get(&(base + 1)).cloned();
            let (left, right) = match (left, right) {
                (Some(left), Some(right)) => (left, right),
                (Some(left), None) => {
                    let right = Node {
                        hash: siblings[cursor],
                        leaves: Vec::new(),
                    };
                    cursor += 1;
                    (left, right)
                }
                (None, Some(right)) => {
                    let left = Node {
                        hash: siblings[cursor],
                        leaves: Vec::new(),
                    };
                    cursor += 1;
                    (left, right)
                }
                (None, None) => unreachable!("processed parent must have one known child"),
            };

            for &leaf_pos in &left.leaves {
                out[leaf_pos].siblings[level as usize] = right.hash;
                out[leaf_pos].directions[level as usize] = false;
            }
            for &leaf_pos in &right.leaves {
                out[leaf_pos].siblings[level as usize] = left.hash;
                out[leaf_pos].directions[level as usize] = true;
            }

            let mut parent_leaves = left.leaves;
            parent_leaves.extend(right.leaves);
            next.insert(
                base / 2,
                Node {
                    hash: state_node_hash(left.hash, right.hash),
                    leaves: parent_leaves,
                },
            );
        }
        known = next;
    }

    debug_assert_eq!(cursor, siblings.len());
    Ok(out)
}

/// Build a canonical multiproof from a sparse cache.
pub fn build_multiproof(
    cache: &SparseMerkleCache,
    indices: &[u32],
    depth: u32,
) -> Result<CanonicalMerkleMultiProof, SparseMerkleError> {
    if cache.depth != depth {
        return Err(SparseMerkleError::CacheDepthMismatch {
            cache_depth: cache.depth,
            requested_depth: depth,
        });
    }
    let mut known = validate_indices(indices, depth)?;
    let mut siblings = Vec::with_capacity(expected_sibling_count(indices, depth)?);
    for level in 0..depth {
        let mut next = BTreeSet::new();
        let mut processed = BTreeSet::new();
        for &pos in &known {
            let base = pos & !1;
            if !processed.insert(base) {
                continue;
            }
            let left_known = known.contains(&base);
            let right_known = known.contains(&(base + 1));
            match (left_known, right_known) {
                (true, true) => {}
                (true, false) => siblings.push(cache.node_hash(level, base + 1)),
                (false, true) => siblings.push(cache.node_hash(level, base)),
                (false, false) => unreachable!("processed parent must have one known child"),
            }
            next.insert(base / 2);
        }
        known = next;
    }
    Ok(CanonicalMerkleMultiProof { siblings })
}

fn validate_depth(depth: u32) -> Result<(), SparseMerkleError> {
    if depth > 32 {
        return Err(SparseMerkleError::InvalidDepth { depth });
    }
    Ok(())
}

fn validate_index(index: u32, depth: u32) -> Result<(), SparseMerkleError> {
    validate_depth(depth)?;
    let limit = 1u64 << depth;
    if (index as u64) >= limit {
        return Err(SparseMerkleError::IndexOutOfRange { index, depth });
    }
    Ok(())
}

fn validate_indices(indices: &[u32], depth: u32) -> Result<BTreeSet<u64>, SparseMerkleError> {
    validate_depth(depth)?;
    if indices.is_empty() {
        return Err(SparseMerkleError::EmptyIndices);
    }
    let mut prev = None;
    let mut out = BTreeSet::new();
    for &index in indices {
        validate_index(index, depth)?;
        if let Some(prev) = prev {
            if index < prev {
                return Err(SparseMerkleError::UnsortedIndices);
            }
            if index == prev {
                return Err(SparseMerkleError::DuplicateIndex { index });
            }
        }
        prev = Some(index);
        out.insert(index as u64);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exact_state_hash::{slot_leaf_hash, zero_slot_roots};
    use crate::fri_state::SlotValue;
    use noid_core::Block128;

    fn leaf(seed: u128) -> StateHash {
        slot_leaf_hash(SlotValue {
            value: Block128::from(seed as u64),
            owner_hi: Block128::from(seed.wrapping_mul(17)),
            owner_lo: Block128::from(seed.wrapping_mul(29)),
        })
    }

    fn naive_root(depth: u32, leaves: &[(u32, StateHash)]) -> StateHash {
        let zero = zero_slot_roots(depth as usize)[0];
        let mut level = vec![zero; 1usize << depth];
        for &(idx, leaf) in leaves {
            level[idx as usize] = leaf;
        }
        for _ in 0..depth {
            level = level
                .chunks_exact(2)
                .map(|pair| state_node_hash(pair[0], pair[1]))
                .collect();
        }
        level[0]
    }

    #[test]
    fn cache_root_matches_naive_full_tree() {
        let leaves = [(0, leaf(1)), (3, leaf(2)), (11, leaf(3)), (15, leaf(4))];
        let cache = SparseMerkleCache::from_leaves(4, &leaves).unwrap();
        assert_eq!(cache.root(), naive_root(4, &leaves));
    }

    #[test]
    fn multiproof_roundtrips_old_and_new_roots_with_shared_siblings() {
        let old_leaves = [(0, leaf(1)), (3, leaf(2)), (11, leaf(3)), (15, leaf(4))];
        let cache = SparseMerkleCache::from_leaves(4, &old_leaves).unwrap();
        let indices = [0, 11, 15];
        let old_touched = [leaf(1), leaf(3), leaf(4)];
        let proof = build_multiproof(&cache, &indices, 4).unwrap();

        let old_root = reconstruct_root(&indices, &old_touched, &proof.siblings, 4).unwrap();
        assert_eq!(old_root, cache.root());

        let new_touched = [leaf(21), leaf(23), leaf(24)];
        let mut new_all = old_leaves;
        new_all[0] = (0, new_touched[0]);
        new_all[2] = (11, new_touched[1]);
        new_all[3] = (15, new_touched[2]);
        let new_root = reconstruct_root(&indices, &new_touched, &proof.siblings, 4).unwrap();
        assert_eq!(new_root, naive_root(4, &new_all));
    }

    #[test]
    fn sibling_count_deduplicates_neighboring_leaves() {
        assert_eq!(expected_sibling_count(&[0], 4).unwrap(), 4);
        assert_eq!(expected_sibling_count(&[0, 1], 4).unwrap(), 3);
        assert_eq!(expected_sibling_count(&[0, 1, 2, 3], 4).unwrap(), 2);
        assert_eq!(
            expected_sibling_count(&(0u32..16).collect::<Vec<_>>(), 4).unwrap(),
            0
        );
    }

    #[test]
    fn rejects_missing_extra_reordered_and_duplicate_topology() {
        let cache = SparseMerkleCache::from_leaves(4, &[(2, leaf(1)), (9, leaf(2))]).unwrap();
        let indices = [2, 9];
        let leaves = [leaf(1), leaf(2)];
        let proof = build_multiproof(&cache, &indices, 4).unwrap();
        assert!(matches!(
            reconstruct_root(
                &indices,
                &leaves,
                &proof.siblings[..proof.siblings.len() - 1],
                4
            ),
            Err(SparseMerkleError::ProofLengthMismatch { .. })
        ));
        let mut extra = proof.siblings.clone();
        extra.push([7u8; 32]);
        assert!(matches!(
            reconstruct_root(&indices, &leaves, &extra, 4),
            Err(SparseMerkleError::ProofLengthMismatch { .. })
        ));
        assert_eq!(
            expected_sibling_count(&[9, 2], 4),
            Err(SparseMerkleError::UnsortedIndices)
        );
        assert_eq!(
            expected_sibling_count(&[2, 2], 4),
            Err(SparseMerkleError::DuplicateIndex { index: 2 })
        );
    }

    #[test]
    fn bit_flip_or_wrong_leaf_changes_root() {
        let cache = SparseMerkleCache::from_leaves(4, &[(2, leaf(1)), (9, leaf(2))]).unwrap();
        let indices = [2, 9];
        let leaves = [leaf(1), leaf(2)];
        let proof = build_multiproof(&cache, &indices, 4).unwrap();
        let root = reconstruct_root(&indices, &leaves, &proof.siblings, 4).unwrap();
        assert_eq!(root, cache.root());

        let mut bad_siblings = proof.siblings.clone();
        bad_siblings[0][0] ^= 1;
        assert_ne!(
            reconstruct_root(&indices, &leaves, &bad_siblings, 4).unwrap(),
            root
        );

        let bad_leaves = [leaf(1), leaf(99)];
        assert_ne!(
            reconstruct_root(&indices, &bad_leaves, &proof.siblings, 4).unwrap(),
            root
        );
    }

    #[test]
    fn leaf_cannot_move_to_another_index_with_same_frontier() {
        let cache = SparseMerkleCache::from_leaves(4, &[(2, leaf(1))]).unwrap();
        let proof = build_multiproof(&cache, &[2], 4).unwrap();
        let root_at_two = reconstruct_root(&[2], &[leaf(1)], &proof.siblings, 4).unwrap();
        assert_eq!(root_at_two, cache.root());
        let root_at_three = reconstruct_root(&[3], &[leaf(1)], &proof.siblings, 4).unwrap();
        assert_ne!(root_at_three, cache.root());
    }

    #[test]
    fn expanded_paths_match_multiproof_root_with_directions() {
        let leaves = [(2, leaf(1)), (5, leaf(2)), (14, leaf(3))];
        let cache = SparseMerkleCache::from_leaves(4, &leaves).unwrap();
        let indices = [2, 5, 14];
        let touched = [leaf(1), leaf(2), leaf(3)];
        let proof = build_multiproof(&cache, &indices, 4).unwrap();
        let paths = expand_multiproof_paths(&indices, &touched, &proof.siblings, 4).unwrap();
        assert_eq!(paths.len(), 3);

        for path in paths {
            let mut current = path.leaf;
            for level in 0..4 {
                current = if path.directions[level] {
                    state_node_hash(path.siblings[level], current)
                } else {
                    state_node_hash(current, path.siblings[level])
                };
            }
            assert_eq!(current, cache.root(), "index {}", path.index);
        }
    }
}
