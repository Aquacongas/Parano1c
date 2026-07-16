// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Shape-only direct Merkle-forest prototype for the selected ZK capsule.
//!
//! Native capsule proofs already carry canonical batched (octopus) Merkle
//! siblings.  The current Wallet-B region expands those siblings into 64
//! independent eight-node paths.  This module retains the native bottom-up
//! forest instead: duplicate leaves are canonicalized once and shared parents
//! are compressed once.
//!
//! This is deliberately not wired into the production Wallet-B sidecar.  The
//! value builder below exactly mirrors native sorting, sibling consumption,
//! left/right order and cap binding, while the fixed A128 certificate reserves
//! one key plus `LEFT[2], RIGHT[2], C[4]` per hash row.  A future sidecar must
//! additionally prove the key/routing permutation, active-prefix/padding rule,
//! sibling-stream permutation and cap endpoints.  Native data-dependent
//! sorting is never presented here as a frozen-matrix relation.

use noid_fri::hasher::CryptographicHasher;
use noid_fri_binius::capsule::CapsuleNodeHasher;
use noid_fri_binius::interleaved_commit::{
    canonical_source_batched_merkle_sibling_positions, SourceBatchedMerkleProof, SourceHash,
    SourceMerkleSiblingPosition,
};
use noid_fri_binius::zk_capsule_pcs::{
    ZK_CAPSULE_PCS_MID_CAP_DEPTH, ZK_CAPSULE_PCS_MID_TREE_DEPTH, ZK_CAPSULE_PCS_QUERY_COUNT,
    ZK_CAPSULE_PCS_SOURCE_CAP_DEPTH, ZK_CAPSULE_PCS_SOURCE_TREE_DEPTH,
};
use noid_ivc_core::deep_chain::capsule_leaf::raw_flat_lane;
use noid_ivc_core::deep_chain::source_tree::run_perm;
use noid_ivc_core::public_io::WitnessSlice;
use noid_poseidon2b::native::domain::{capacity_iv_flat, TAG_CAPSNODE};
use noid_poseidon2b::native::permutation::STATE_SIZE;

use crate::circuit_support::{pin_eq, poseidon2b_permute, FieldR1csBuilder, LinExpr, F128};

pub const A128_FOREST_CAPSULES: usize = 128;
pub const CAPSULE_FOREST_LEVELS: usize = 8;
pub const CAPSULE_FOREST_COMMITTED_COLUMNS: usize = 1 + 2 + 2 + STATE_SIZE;

/// Maximum parent rows per capsule at every source level, leaf-to-cap.
pub const CAPSULE_SOURCE_FOREST_ROWS_PER_LEVEL: [usize; CAPSULE_FOREST_LEVELS] =
    [64, 64, 64, 64, 64, 64, 64, 32];
/// Maximum parent rows per capsule at every mid level, leaf-to-cap.
pub const CAPSULE_MID_FOREST_ROWS_PER_LEVEL: [usize; CAPSULE_FOREST_LEVELS] =
    [64, 64, 64, 32, 16, 8, 4, 2];

pub const CAPSULE_SOURCE_FOREST_ROWS: usize = 7 * 64 + 32;
pub const CAPSULE_MID_FOREST_ROWS: usize = 3 * 64 + 32 + 16 + 8 + 4 + 2;
pub const CAPSULE_FOREST_ROWS: usize = CAPSULE_SOURCE_FOREST_ROWS + CAPSULE_MID_FOREST_ROWS;

pub const A128_SOURCE_FOREST_NODE_SLOTS: usize = A128_FOREST_CAPSULES * CAPSULE_SOURCE_FOREST_ROWS;
pub const A128_MID_FOREST_NODE_SLOTS: usize = A128_FOREST_CAPSULES * CAPSULE_MID_FOREST_ROWS;
pub const A128_FOREST_NODE_SLOTS: usize =
    A128_SOURCE_FOREST_NODE_SLOTS + A128_MID_FOREST_NODE_SLOTS;
pub const A128_FOREST_COMMITTED_CELLS: usize =
    A128_FOREST_NODE_SLOTS * CAPSULE_FOREST_COMMITTED_COLUMNS;
pub const A128_FOREST_COMMITTED_CELLS_PER_CAPSULE: usize =
    A128_FOREST_COMMITTED_CELLS / A128_FOREST_CAPSULES;

/// A monolithic six-path-equivalent domain rounds 93,952 active hash slots
/// back to `2^17`, exactly erasing the forest saving.
pub const A128_FOREST_MONOLITHIC_W_LOG: usize = 17;
pub const A128_FOREST_MONOLITHIC_COMMITTED_CELLS: usize =
    CAPSULE_FOREST_COMMITTED_COLUMNS * (1 << A128_FOREST_MONOLITHIC_W_LOG);

/// One native capsule compression plus four pins to its committed `C` cells.
pub const CAPSULE_FOREST_NODE_TRACE_ROWS: usize =
    noid_ivc_core::field_circuit::POSEIDON2B_PERMUTE_CONSTRAINTS + STATE_SIZE;

const _: () = assert!(ZK_CAPSULE_PCS_QUERY_COUNT == 64);
const _: () = assert!(ZK_CAPSULE_PCS_SOURCE_TREE_DEPTH - ZK_CAPSULE_PCS_SOURCE_CAP_DEPTH == 8);
const _: () = assert!(ZK_CAPSULE_PCS_MID_TREE_DEPTH - ZK_CAPSULE_PCS_MID_CAP_DEPTH == 8);
const _: () = assert!(CAPSULE_FOREST_COMMITTED_COLUMNS == 9);
const _: () = assert!(CAPSULE_SOURCE_FOREST_ROWS == 480);
const _: () = assert!(CAPSULE_MID_FOREST_ROWS == 254);
const _: () = assert!(CAPSULE_FOREST_ROWS == 734);
const _: () = assert!(A128_SOURCE_FOREST_NODE_SLOTS == 61_440);
const _: () = assert!(A128_MID_FOREST_NODE_SLOTS == 32_512);
const _: () = assert!(A128_FOREST_NODE_SLOTS == 93_952);
const _: () = assert!(A128_FOREST_COMMITTED_CELLS == 845_568);
const _: () = assert!(A128_FOREST_COMMITTED_CELLS_PER_CAPSULE == 6_606);
const _: () = assert!(A128_FOREST_MONOLITHIC_COMMITTED_CELLS == 1_179_648);
const _: () = assert!(CAPSULE_FOREST_NODE_TRACE_ROWS == 364);

/// Fixed committed column order at every forest level.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(usize)]
pub enum CapsuleMerkleForestColumn {
    /// Parent index plus one; zero is reserved for canonical inactive padding.
    Key = 0,
    Left0 = 1,
    Left1 = 2,
    Right0 = 3,
    Right1 = 4,
    C0 = 5,
    C1 = 6,
    C2 = 7,
    C3 = 8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapsuleMerkleForestFamily {
    Source,
    Mid,
}

impl CapsuleMerkleForestFamily {
    const fn rows_per_level(self) -> [usize; CAPSULE_FOREST_LEVELS] {
        match self {
            Self::Source => CAPSULE_SOURCE_FOREST_ROWS_PER_LEVEL,
            Self::Mid => CAPSULE_MID_FOREST_ROWS_PER_LEVEL,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ForestLevelId {
    family: CapsuleMerkleForestFamily,
    level: usize,
}

/// Physical order is descending by dyadic width.  This is what makes all 144
/// column slices contiguous with no hidden gap between source and mid.
const FOREST_LEVEL_ALLOCATION_ORDER: [ForestLevelId; 2 * CAPSULE_FOREST_LEVELS] = [
    ForestLevelId {
        family: CapsuleMerkleForestFamily::Source,
        level: 0,
    },
    ForestLevelId {
        family: CapsuleMerkleForestFamily::Source,
        level: 1,
    },
    ForestLevelId {
        family: CapsuleMerkleForestFamily::Source,
        level: 2,
    },
    ForestLevelId {
        family: CapsuleMerkleForestFamily::Source,
        level: 3,
    },
    ForestLevelId {
        family: CapsuleMerkleForestFamily::Source,
        level: 4,
    },
    ForestLevelId {
        family: CapsuleMerkleForestFamily::Source,
        level: 5,
    },
    ForestLevelId {
        family: CapsuleMerkleForestFamily::Source,
        level: 6,
    },
    ForestLevelId {
        family: CapsuleMerkleForestFamily::Mid,
        level: 0,
    },
    ForestLevelId {
        family: CapsuleMerkleForestFamily::Mid,
        level: 1,
    },
    ForestLevelId {
        family: CapsuleMerkleForestFamily::Mid,
        level: 2,
    },
    ForestLevelId {
        family: CapsuleMerkleForestFamily::Source,
        level: 7,
    },
    ForestLevelId {
        family: CapsuleMerkleForestFamily::Mid,
        level: 3,
    },
    ForestLevelId {
        family: CapsuleMerkleForestFamily::Mid,
        level: 4,
    },
    ForestLevelId {
        family: CapsuleMerkleForestFamily::Mid,
        level: 5,
    },
    ForestLevelId {
        family: CapsuleMerkleForestFamily::Mid,
        level: 6,
    },
    ForestLevelId {
        family: CapsuleMerkleForestFamily::Mid,
        level: 7,
    },
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapsuleMerkleForestLayoutProposal {
    LevelSeparated { start_wire: usize },
    Monolithic { start_wire: usize, w_log: usize },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CapsuleMerkleForestError {
    MisalignedStart {
        start_wire: usize,
        alignment: usize,
    },
    AllocationOverflow,
    MonolithicAllocationRejected {
        start_wire: usize,
        w_log: usize,
    },
    CapDepth {
        depth: usize,
        cap_depth: usize,
    },
    CapWidth {
        expected: usize,
        actual: usize,
    },
    LeafCount {
        indices: usize,
        hashes: usize,
    },
    QueryCount {
        expected: usize,
        actual: usize,
    },
    LeafIndexOutOfRange {
        index: usize,
        depth: usize,
    },
    InconsistentRepeatedLeaf {
        index: usize,
    },
    CanonicalSchedule(String),
    CanonicalScheduleMismatch {
        expected: SourceMerkleSiblingPosition,
        actual: SourceMerkleSiblingPosition,
    },
    InsufficientSiblings {
        layer: usize,
    },
    UnusedSiblings {
        consumed: usize,
        total: usize,
    },
    OrphanParent {
        layer: usize,
        parent: usize,
    },
    CapIndexOutOfRange {
        index: usize,
    },
    CapMismatch {
        index: usize,
    },
    CapsuleCount {
        expected: usize,
        actual: usize,
    },
    ForestGeometry {
        family: CapsuleMerkleForestFamily,
    },
    LevelCapacity {
        family: CapsuleMerkleForestFamily,
        level: usize,
        capacity: usize,
        actual: usize,
    },
    ColumnShape {
        family: CapsuleMerkleForestFamily,
        level: usize,
        column: usize,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CapsuleMerkleForestLevelLayout {
    pub family: CapsuleMerkleForestFamily,
    pub level: usize,
    pub slots_per_capsule: usize,
    pub w_log: usize,
    pub slices: [WitnessSlice; CAPSULE_FOREST_COMMITTED_COLUMNS],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct A128CapsuleMerkleForestLayout {
    source: [CapsuleMerkleForestLevelLayout; CAPSULE_FOREST_LEVELS],
    mid: [CapsuleMerkleForestLevelLayout; CAPSULE_FOREST_LEVELS],
    start_wire: usize,
    end_wire: usize,
}

impl A128CapsuleMerkleForestLayout {
    pub fn certify(
        proposal: CapsuleMerkleForestLayoutProposal,
    ) -> Result<Self, CapsuleMerkleForestError> {
        let start_wire = match proposal {
            CapsuleMerkleForestLayoutProposal::LevelSeparated { start_wire } => start_wire,
            CapsuleMerkleForestLayoutProposal::Monolithic { start_wire, w_log } => {
                return Err(CapsuleMerkleForestError::MonolithicAllocationRejected {
                    start_wire,
                    w_log,
                });
            }
        };
        let largest_level_len = A128_FOREST_CAPSULES * 64;
        if start_wire % largest_level_len != 0 {
            return Err(CapsuleMerkleForestError::MisalignedStart {
                start_wire,
                alignment: largest_level_len,
            });
        }
        let mut source = [None; CAPSULE_FOREST_LEVELS];
        let mut mid = [None; CAPSULE_FOREST_LEVELS];
        let mut cursor = start_wire;
        for id in FOREST_LEVEL_ALLOCATION_ORDER {
            let slots_per_capsule = id.family.rows_per_level()[id.level];
            let len = A128_FOREST_CAPSULES * slots_per_capsule;
            debug_assert!(len.is_power_of_two());
            let w_log = len.trailing_zeros() as usize;
            debug_assert_eq!(cursor % len, 0);
            let slices = std::array::from_fn(|column| WitnessSlice {
                log2_len: w_log,
                index: (cursor >> w_log) + column,
            });
            let layout = CapsuleMerkleForestLevelLayout {
                family: id.family,
                level: id.level,
                slots_per_capsule,
                w_log,
                slices,
            };
            match id.family {
                CapsuleMerkleForestFamily::Source => source[id.level] = Some(layout),
                CapsuleMerkleForestFamily::Mid => mid[id.level] = Some(layout),
            }
            cursor = cursor
                .checked_add(CAPSULE_FOREST_COMMITTED_COLUMNS * len)
                .ok_or(CapsuleMerkleForestError::AllocationOverflow)?;
        }
        let end_wire = start_wire
            .checked_add(A128_FOREST_COMMITTED_CELLS)
            .ok_or(CapsuleMerkleForestError::AllocationOverflow)?;
        debug_assert_eq!(cursor, end_wire);
        Ok(Self {
            source: source.map(|level| level.expect("all source levels allocated")),
            mid: mid.map(|level| level.expect("all mid levels allocated")),
            start_wire,
            end_wire,
        })
    }

    pub fn source(&self) -> &[CapsuleMerkleForestLevelLayout; CAPSULE_FOREST_LEVELS] {
        &self.source
    }

    pub fn mid(&self) -> &[CapsuleMerkleForestLevelLayout; CAPSULE_FOREST_LEVELS] {
        &self.mid
    }

    pub const fn start_wire(&self) -> usize {
        self.start_wire
    }

    pub const fn end_wire(&self) -> usize {
        self.end_wire
    }

    pub const fn committed_cells(&self) -> usize {
        self.end_wire - self.start_wire
    }

    fn level(
        &self,
        family: CapsuleMerkleForestFamily,
        level: usize,
    ) -> &CapsuleMerkleForestLevelLayout {
        match family {
            CapsuleMerkleForestFamily::Source => &self.source[level],
            CapsuleMerkleForestFamily::Mid => &self.mid[level],
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapsuleMerkleSiblingSide {
    Left,
    Right,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalCapsuleMerkleForestNode {
    pub parent_index: usize,
    pub left: SourceHash,
    pub right: SourceHash,
    pub s0: [F128; STATE_SIZE],
    pub c: [F128; STATE_SIZE],
    pub digest: SourceHash,
    pub consumed_sibling: Option<(SourceMerkleSiblingPosition, CapsuleMerkleSiblingSide)>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalCapsuleMerkleForest {
    depth: usize,
    cap_depth: usize,
    levels: Vec<Vec<CanonicalCapsuleMerkleForestNode>>,
    final_indices: Vec<usize>,
    final_hashes: Vec<SourceHash>,
    siblings_consumed: usize,
}

impl CanonicalCapsuleMerkleForest {
    pub const fn depth(&self) -> usize {
        self.depth
    }

    pub const fn cap_depth(&self) -> usize {
        self.cap_depth
    }

    pub fn levels(&self) -> &[Vec<CanonicalCapsuleMerkleForestNode>] {
        &self.levels
    }

    pub fn final_indices(&self) -> &[usize] {
        &self.final_indices
    }

    pub fn final_hashes(&self) -> &[SourceHash] {
        &self.final_hashes
    }

    pub const fn siblings_consumed(&self) -> usize {
        self.siblings_consumed
    }

    pub fn consumed_sibling_positions(&self) -> Vec<SourceMerkleSiblingPosition> {
        self.levels
            .iter()
            .flatten()
            .filter_map(|node| node.consumed_sibling.map(|(position, _)| position))
            .collect()
    }
}

pub struct CapsuleMerkleForestOpening<'a> {
    pub cap_nodes: &'a [SourceHash],
    pub batch: &'a SourceBatchedMerkleProof,
    pub leaf_indices: &'a [usize],
    pub leaf_hashes: &'a [SourceHash],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapsuleSourceMidMerkleForests {
    pub source: CanonicalCapsuleMerkleForest,
    pub mid: CanonicalCapsuleMerkleForest,
}

fn hash_lanes(hash: &SourceHash) -> [F128; 2] {
    [
        raw_flat_lane(u128::from_le_bytes(hash[..16].try_into().unwrap())),
        raw_flat_lane(u128::from_le_bytes(hash[16..].try_into().unwrap())),
    ]
}

fn flat_bits(value: F128) -> u128 {
    (u128::from(value.hi) << 64) | u128::from(value.lo)
}

fn lanes_hash(lanes: [F128; 2]) -> SourceHash {
    let mut hash = [0u8; 32];
    hash[..16].copy_from_slice(&flat_bits(lanes[0]).to_le_bytes());
    hash[16..].copy_from_slice(&flat_bits(lanes[1]).to_le_bytes());
    hash
}

fn capsule_node_witness(
    left: &SourceHash,
    right: &SourceHash,
) -> ([F128; STATE_SIZE], [F128; STATE_SIZE], SourceHash) {
    let left_lanes = hash_lanes(left);
    let right_lanes = hash_lanes(right);
    let iv = capacity_iv_flat(TAG_CAPSNODE).map(raw_flat_lane);
    let raw = [
        left_lanes[0],
        left_lanes[1],
        right_lanes[0] + iv[0],
        right_lanes[1] + iv[1],
    ];
    let (s0, c) = run_perm(raw);
    let digest = lanes_hash([c[0] + left_lanes[0], c[1] + left_lanes[1]]);
    debug_assert_eq!(digest, CapsuleNodeHasher.compress(left, right));
    (s0, c, digest)
}

fn sorted_unique_leaf_hashes(
    leaf_indices: &[usize],
    leaf_hashes: &[SourceHash],
) -> Result<(Vec<usize>, Vec<SourceHash>), CapsuleMerkleForestError> {
    let mut pairs = leaf_indices
        .iter()
        .copied()
        .zip(leaf_hashes.iter().copied())
        .collect::<Vec<_>>();
    pairs.sort_unstable_by_key(|(index, _)| *index);
    let mut indices = Vec::with_capacity(pairs.len());
    let mut hashes = Vec::with_capacity(pairs.len());
    for (index, hash) in pairs {
        if indices.last().copied() == Some(index) {
            if hashes.last().copied() != Some(hash) {
                return Err(CapsuleMerkleForestError::InconsistentRepeatedLeaf { index });
            }
        } else {
            indices.push(index);
            hashes.push(hash);
        }
    }
    Ok((indices, hashes))
}

/// Direct line-for-line value reconstruction of the native source verifier.
/// The public native sibling-position helper supplies the exact canonical
/// schedule; each missing child must match its next position before a sibling
/// value is consumed.
pub fn build_canonical_capsule_merkle_forest(
    cap_nodes: &[SourceHash],
    cap_depth: usize,
    batch: &SourceBatchedMerkleProof,
    depth: usize,
    leaf_indices: &[usize],
    leaf_hashes: &[SourceHash],
) -> Result<CanonicalCapsuleMerkleForest, CapsuleMerkleForestError> {
    if cap_depth > depth {
        return Err(CapsuleMerkleForestError::CapDepth { depth, cap_depth });
    }
    let expected_cap = 1usize
        .checked_shl(cap_depth as u32)
        .ok_or(CapsuleMerkleForestError::AllocationOverflow)?;
    if cap_nodes.len() != expected_cap {
        return Err(CapsuleMerkleForestError::CapWidth {
            expected: expected_cap,
            actual: cap_nodes.len(),
        });
    }
    if leaf_indices.len() != leaf_hashes.len() {
        return Err(CapsuleMerkleForestError::LeafCount {
            indices: leaf_indices.len(),
            hashes: leaf_hashes.len(),
        });
    }
    let leaf_bound = 1usize
        .checked_shl(depth as u32)
        .ok_or(CapsuleMerkleForestError::AllocationOverflow)?;
    if let Some(&index) = leaf_indices.iter().find(|&&index| index >= leaf_bound) {
        return Err(CapsuleMerkleForestError::LeafIndexOutOfRange { index, depth });
    }
    let schedule =
        canonical_source_batched_merkle_sibling_positions(depth, cap_depth, leaf_indices)
            .map_err(CapsuleMerkleForestError::CanonicalSchedule)?;
    let (mut known_indices, mut known_hashes) =
        sorted_unique_leaf_hashes(leaf_indices, leaf_hashes)?;

    let mut levels = Vec::with_capacity(depth - cap_depth);
    let mut sibling_cursor = 0usize;
    for layer in 0..(depth - cap_depth) {
        let mut nodes = Vec::with_capacity(known_indices.len());
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
                let index = known_indices[cursor];
                if index == left_child {
                    left = Some(known_hashes[cursor]);
                } else if index == right_child {
                    right = Some(known_hashes[cursor]);
                } else {
                    return Err(CapsuleMerkleForestError::OrphanParent { layer, parent });
                }
                cursor += 1;
            }

            let mut consumed_sibling = None;
            let (left, right) = match (left, right) {
                (Some(left), Some(right)) => (left, right),
                (Some(left), None) => {
                    let actual = SourceMerkleSiblingPosition {
                        depth_from_root: depth - layer,
                        index: right_child,
                    };
                    let expected = schedule
                        .get(sibling_cursor)
                        .copied()
                        .ok_or(CapsuleMerkleForestError::InsufficientSiblings { layer })?;
                    if expected != actual {
                        return Err(CapsuleMerkleForestError::CanonicalScheduleMismatch {
                            expected,
                            actual,
                        });
                    }
                    let right = batch
                        .siblings
                        .get(sibling_cursor)
                        .copied()
                        .ok_or(CapsuleMerkleForestError::InsufficientSiblings { layer })?;
                    sibling_cursor += 1;
                    consumed_sibling = Some((actual, CapsuleMerkleSiblingSide::Right));
                    (left, right)
                }
                (None, Some(right)) => {
                    let actual = SourceMerkleSiblingPosition {
                        depth_from_root: depth - layer,
                        index: left_child,
                    };
                    let expected = schedule
                        .get(sibling_cursor)
                        .copied()
                        .ok_or(CapsuleMerkleForestError::InsufficientSiblings { layer })?;
                    if expected != actual {
                        return Err(CapsuleMerkleForestError::CanonicalScheduleMismatch {
                            expected,
                            actual,
                        });
                    }
                    let left = batch
                        .siblings
                        .get(sibling_cursor)
                        .copied()
                        .ok_or(CapsuleMerkleForestError::InsufficientSiblings { layer })?;
                    sibling_cursor += 1;
                    consumed_sibling = Some((actual, CapsuleMerkleSiblingSide::Left));
                    (left, right)
                }
                (None, None) => {
                    return Err(CapsuleMerkleForestError::OrphanParent { layer, parent });
                }
            };
            let (s0, c, digest) = capsule_node_witness(&left, &right);
            nodes.push(CanonicalCapsuleMerkleForestNode {
                parent_index: parent,
                left,
                right,
                s0,
                c,
                digest,
                consumed_sibling,
            });
            next_indices.push(parent);
            next_hashes.push(digest);
        }
        levels.push(nodes);
        known_indices = next_indices;
        known_hashes = next_hashes;
    }

    for (&index, hash) in known_indices.iter().zip(&known_hashes) {
        let cap = cap_nodes
            .get(index)
            .ok_or(CapsuleMerkleForestError::CapIndexOutOfRange { index })?;
        if hash != cap {
            return Err(CapsuleMerkleForestError::CapMismatch { index });
        }
    }
    if sibling_cursor != batch.siblings.len() {
        return Err(CapsuleMerkleForestError::UnusedSiblings {
            consumed: sibling_cursor,
            total: batch.siblings.len(),
        });
    }
    if sibling_cursor != schedule.len() {
        return Err(CapsuleMerkleForestError::UnusedSiblings {
            consumed: sibling_cursor,
            total: schedule.len(),
        });
    }
    Ok(CanonicalCapsuleMerkleForest {
        depth,
        cap_depth,
        levels,
        final_indices: known_indices,
        final_hashes: known_hashes,
        siblings_consumed: sibling_cursor,
    })
}

pub fn build_capsule_source_mid_merkle_forests(
    source: CapsuleMerkleForestOpening<'_>,
    mid: CapsuleMerkleForestOpening<'_>,
) -> Result<CapsuleSourceMidMerkleForests, CapsuleMerkleForestError> {
    for opening in [&source, &mid] {
        if opening.leaf_indices.len() != ZK_CAPSULE_PCS_QUERY_COUNT {
            return Err(CapsuleMerkleForestError::QueryCount {
                expected: ZK_CAPSULE_PCS_QUERY_COUNT,
                actual: opening.leaf_indices.len(),
            });
        }
    }
    let source = build_canonical_capsule_merkle_forest(
        source.cap_nodes,
        ZK_CAPSULE_PCS_SOURCE_CAP_DEPTH,
        source.batch,
        ZK_CAPSULE_PCS_SOURCE_TREE_DEPTH,
        source.leaf_indices,
        source.leaf_hashes,
    )?;
    let mid = build_canonical_capsule_merkle_forest(
        mid.cap_nodes,
        ZK_CAPSULE_PCS_MID_CAP_DEPTH,
        mid.batch,
        ZK_CAPSULE_PCS_MID_TREE_DEPTH,
        mid.leaf_indices,
        mid.leaf_hashes,
    )?;
    Ok(CapsuleSourceMidMerkleForests { source, mid })
}

#[derive(Clone, Debug)]
pub struct CapsuleMerkleForestLevelColumns {
    committed: [Vec<F128>; CAPSULE_FOREST_COMMITTED_COLUMNS],
    s0: [Vec<F128>; STATE_SIZE],
    s_out: [Vec<F128>; STATE_SIZE],
}

impl CapsuleMerkleForestLevelColumns {
    fn zeroed(len: usize) -> Self {
        Self {
            committed: std::array::from_fn(|_| vec![F128::ZERO; len]),
            s0: std::array::from_fn(|_| vec![F128::ZERO; len]),
            s_out: std::array::from_fn(|_| vec![F128::ZERO; len]),
        }
    }

    pub fn committed(&self) -> &[Vec<F128>; CAPSULE_FOREST_COMMITTED_COLUMNS] {
        &self.committed
    }

    pub fn s0(&self) -> &[Vec<F128>; STATE_SIZE] {
        &self.s0
    }

    pub fn s_out(&self) -> &[Vec<F128>; STATE_SIZE] {
        &self.s_out
    }
}

#[derive(Clone, Debug)]
pub struct A128CapsuleMerkleForestColumns {
    source: [CapsuleMerkleForestLevelColumns; CAPSULE_FOREST_LEVELS],
    mid: [CapsuleMerkleForestLevelColumns; CAPSULE_FOREST_LEVELS],
}

impl A128CapsuleMerkleForestColumns {
    pub fn source(&self) -> &[CapsuleMerkleForestLevelColumns; CAPSULE_FOREST_LEVELS] {
        &self.source
    }

    pub fn mid(&self) -> &[CapsuleMerkleForestLevelColumns; CAPSULE_FOREST_LEVELS] {
        &self.mid
    }

    fn level(
        &self,
        family: CapsuleMerkleForestFamily,
        level: usize,
    ) -> &CapsuleMerkleForestLevelColumns {
        match family {
            CapsuleMerkleForestFamily::Source => &self.source[level],
            CapsuleMerkleForestFamily::Mid => &self.mid[level],
        }
    }
}

fn store_forest_node(
    columns: &mut CapsuleMerkleForestLevelColumns,
    slot: usize,
    node: &CanonicalCapsuleMerkleForestNode,
) {
    let left = hash_lanes(&node.left);
    let right = hash_lanes(&node.right);
    columns.committed[CapsuleMerkleForestColumn::Key as usize][slot] =
        raw_flat_lane((node.parent_index + 1) as u128);
    columns.committed[CapsuleMerkleForestColumn::Left0 as usize][slot] = left[0];
    columns.committed[CapsuleMerkleForestColumn::Left1 as usize][slot] = left[1];
    columns.committed[CapsuleMerkleForestColumn::Right0 as usize][slot] = right[0];
    columns.committed[CapsuleMerkleForestColumn::Right1 as usize][slot] = right[1];
    for lane in 0..STATE_SIZE {
        columns.committed[CapsuleMerkleForestColumn::C0 as usize + lane][slot] = node.c[lane];
        columns.s0[lane][slot] = node.s0[lane];
        columns.s_out[lane][slot] = node.c[lane];
    }
}

/// Pack 128 independently rooted source/mid forests into the certified level
/// domains.  Zero-key rows are canonical inactive padding.  This function is
/// the explicit value-level handoff that can replace current independent
/// Wallet-B columns once a routing sidecar exists.
pub fn pack_a128_capsule_merkle_forest_columns(
    capsules: &[CapsuleSourceMidMerkleForests],
) -> Result<A128CapsuleMerkleForestColumns, CapsuleMerkleForestError> {
    if capsules.len() != A128_FOREST_CAPSULES {
        return Err(CapsuleMerkleForestError::CapsuleCount {
            expected: A128_FOREST_CAPSULES,
            actual: capsules.len(),
        });
    }
    let mut source = std::array::from_fn(|level| {
        CapsuleMerkleForestLevelColumns::zeroed(
            A128_FOREST_CAPSULES * CAPSULE_SOURCE_FOREST_ROWS_PER_LEVEL[level],
        )
    });
    let mut mid = std::array::from_fn(|level| {
        CapsuleMerkleForestLevelColumns::zeroed(
            A128_FOREST_CAPSULES * CAPSULE_MID_FOREST_ROWS_PER_LEVEL[level],
        )
    });
    for (capsule, forests) in capsules.iter().enumerate() {
        for (family, forest, capacities, columns) in [
            (
                CapsuleMerkleForestFamily::Source,
                &forests.source,
                CAPSULE_SOURCE_FOREST_ROWS_PER_LEVEL,
                &mut source,
            ),
            (
                CapsuleMerkleForestFamily::Mid,
                &forests.mid,
                CAPSULE_MID_FOREST_ROWS_PER_LEVEL,
                &mut mid,
            ),
        ] {
            let expected_geometry = match family {
                CapsuleMerkleForestFamily::Source => (
                    ZK_CAPSULE_PCS_SOURCE_TREE_DEPTH,
                    ZK_CAPSULE_PCS_SOURCE_CAP_DEPTH,
                ),
                CapsuleMerkleForestFamily::Mid => {
                    (ZK_CAPSULE_PCS_MID_TREE_DEPTH, ZK_CAPSULE_PCS_MID_CAP_DEPTH)
                }
            };
            if (forest.depth, forest.cap_depth) != expected_geometry
                || forest.levels.len() != CAPSULE_FOREST_LEVELS
            {
                return Err(CapsuleMerkleForestError::ForestGeometry { family });
            }
            for level in 0..CAPSULE_FOREST_LEVELS {
                if forest.levels[level].len() > capacities[level] {
                    return Err(CapsuleMerkleForestError::LevelCapacity {
                        family,
                        level,
                        capacity: capacities[level],
                        actual: forest.levels[level].len(),
                    });
                }
                let base = capsule * capacities[level];
                for (row, node) in forest.levels[level].iter().enumerate() {
                    store_forest_node(&mut columns[level], base + row, node);
                }
            }
        }
    }
    Ok(A128CapsuleMerkleForestColumns { source, mid })
}

pub fn allocate_a128_capsule_merkle_forest_columns(
    b: &mut FieldR1csBuilder,
    columns: &A128CapsuleMerkleForestColumns,
) -> Result<(A128CapsuleMerkleForestLayout, usize), CapsuleMerkleForestError> {
    let largest_level_len = A128_FOREST_CAPSULES * 64;
    let before_alignment = b.num_wires();
    while b.num_wires() % largest_level_len != 0 {
        b.alloc_f128(F128::ZERO);
    }
    let start_wire = b.num_wires();
    let alignment_rows = start_wire - before_alignment;
    let layout = A128CapsuleMerkleForestLayout::certify(
        CapsuleMerkleForestLayoutProposal::LevelSeparated { start_wire },
    )?;
    for id in FOREST_LEVEL_ALLOCATION_ORDER {
        let level_layout = layout.level(id.family, id.level);
        let level_columns = columns.level(id.family, id.level);
        let expected_len = 1usize << level_layout.w_log;
        for column in 0..CAPSULE_FOREST_COMMITTED_COLUMNS {
            if level_columns.committed[column].len() != expected_len {
                return Err(CapsuleMerkleForestError::ColumnShape {
                    family: id.family,
                    level: id.level,
                    column,
                });
            }
            let slice = level_layout.slices[column];
            assert_eq!(slice.start(), b.num_wires(), "forest level slice cursor");
            for &value in &level_columns.committed[column] {
                b.alloc_f128(value);
            }
        }
    }
    assert_eq!(b.num_wires(), layout.end_wire());
    Ok((layout, alignment_rows))
}

/// One-node constraint differential.  Routing/key constraints intentionally
/// remain outside this primitive and are the production integration seam.
pub fn verify_capsule_merkle_forest_node_trace(
    b: &mut FieldR1csBuilder,
    left: &[LinExpr; 2],
    right: &[LinExpr; 2],
    committed_c: &[LinExpr; STATE_SIZE],
) -> [LinExpr; 2] {
    let trace_start = b.num_wires();
    let iv = capacity_iv_flat(TAG_CAPSNODE).map(raw_flat_lane);
    let raw = [
        left[0].clone(),
        left[1].clone(),
        right[0].add_const(iv[0]),
        right[1].add_const(iv[1]),
    ];
    let computed = poseidon2b_permute(b, raw);
    for lane in 0..STATE_SIZE {
        pin_eq(b, &computed[lane], &committed_c[lane]);
    }
    debug_assert_eq!(b.num_wires() - trace_start, CAPSULE_FOREST_NODE_TRACE_ROWS);
    [committed_c[0].add(&left[0]), committed_c[1].add(&left[1])]
}

#[cfg(test)]
mod tests {
    use noid_fri_binius::compact_fri::{expand_batched_merkle_proof_to_cap, BatchedMerkleProof};
    use noid_fri_binius::interleaved_commit::SourceBatchedMerkleProof;

    use super::*;

    #[derive(Clone)]
    struct ForestFixture {
        depth: usize,
        cap_depth: usize,
        cap_nodes: Vec<SourceHash>,
        batch: SourceBatchedMerkleProof,
        indices: Vec<usize>,
        hashes: Vec<SourceHash>,
    }

    fn leaf_hash(index: usize, salt: u8) -> SourceHash {
        let mut hash = std::array::from_fn(|byte| {
            salt.wrapping_add((index as u8).wrapping_mul(17))
                .wrapping_add((byte as u8).wrapping_mul(29))
        });
        hash[..8].copy_from_slice(&(index as u64).to_le_bytes());
        hash[8] = salt;
        hash
    }

    fn forest_fixture(depth: usize, cap_depth: usize, indices: Vec<usize>) -> ForestFixture {
        let leaves = (0..1usize << depth)
            .map(|index| leaf_hash(index, depth as u8))
            .collect::<Vec<_>>();
        let mut bottom_up = vec![leaves];
        while bottom_up.last().unwrap().len() > 1 {
            let current = bottom_up.last().unwrap();
            let next = current
                .chunks_exact(2)
                .map(|pair| CapsuleNodeHasher.compress(&pair[0], &pair[1]))
                .collect::<Vec<_>>();
            bottom_up.push(next);
        }
        let at_depth =
            |depth_from_root: usize, index: usize| bottom_up[depth - depth_from_root][index];
        let cap_nodes = bottom_up[depth - cap_depth].clone();
        let positions =
            canonical_source_batched_merkle_sibling_positions(depth, cap_depth, &indices).unwrap();
        let siblings = positions
            .iter()
            .map(|position| at_depth(position.depth_from_root, position.index))
            .collect();
        let hashes = indices.iter().map(|&index| bottom_up[0][index]).collect();
        ForestFixture {
            depth,
            cap_depth,
            cap_nodes,
            batch: SourceBatchedMerkleProof { siblings },
            indices,
            hashes,
        }
    }

    fn direct_accepts(fixture: &ForestFixture) -> bool {
        build_canonical_capsule_merkle_forest(
            &fixture.cap_nodes,
            fixture.cap_depth,
            &fixture.batch,
            fixture.depth,
            &fixture.indices,
            &fixture.hashes,
        )
        .is_ok()
    }

    fn native_accepts(fixture: &ForestFixture) -> bool {
        // The production native verifier is crate-private. Its public
        // independent-path expansion mirrors the same canonical sibling
        // consumption and cap endpoint, so it is the external differential
        // oracle available to this isolated crate.
        expanded_accepts(fixture)
    }

    /// Existing independent-path expansion is the current recursive handoff
    /// and independently mirrors the native batched verifier's consumption.
    fn expanded_accepts(fixture: &ForestFixture) -> bool {
        if fixture.cap_depth > fixture.depth
            || fixture.cap_nodes.len() != 1usize << fixture.cap_depth
        {
            return false;
        }
        let batch = BatchedMerkleProof {
            siblings: fixture.batch.siblings.clone(),
        };
        let Ok(paths) = expand_batched_merkle_proof_to_cap(
            &batch,
            fixture.depth,
            fixture.cap_depth,
            &fixture.indices,
            &fixture.hashes,
            &CapsuleNodeHasher,
        ) else {
            return false;
        };
        for path in paths {
            let mut node = path.leaf_hash;
            for (&sibling, &right) in path.siblings.iter().zip(&path.directions) {
                node = if right {
                    CapsuleNodeHasher.compress(&sibling, &node)
                } else {
                    CapsuleNodeHasher.compress(&node, &sibling)
                };
            }
            let cap_index = path.leaf_index >> (fixture.depth - fixture.cap_depth);
            if fixture.cap_nodes.get(cap_index) != Some(&node) {
                return false;
            }
        }
        true
    }

    fn source_worst_indices() -> Vec<usize> {
        (0..32)
            .flat_map(|cap| {
                let base = cap << 8;
                [base, base + 128]
            })
            .collect()
    }

    fn mid_worst_indices() -> Vec<usize> {
        (0..64).map(|index| index << 3).collect()
    }

    #[test]
    fn a128_level_certificate_is_exact_gap_free_and_rejects_monolith() {
        let layout = A128CapsuleMerkleForestLayout::certify(
            CapsuleMerkleForestLayoutProposal::LevelSeparated { start_wire: 0 },
        )
        .unwrap();
        assert_eq!(layout.committed_cells(), 845_568);
        assert_eq!(layout.end_wire(), A128_FOREST_COMMITTED_CELLS);
        assert_eq!(
            layout.source().map(|level| level.w_log),
            [13, 13, 13, 13, 13, 13, 13, 12]
        );
        assert_eq!(
            layout.mid().map(|level| level.w_log),
            [13, 13, 13, 12, 11, 10, 9, 8]
        );
        let mut cursor = 0;
        for id in FOREST_LEVEL_ALLOCATION_ORDER {
            let level = layout.level(id.family, id.level);
            for slice in level.slices {
                assert_eq!(slice.start(), cursor);
                cursor += slice.len();
            }
        }
        assert_eq!(cursor, A128_FOREST_COMMITTED_CELLS);
        assert_eq!(
            A128CapsuleMerkleForestLayout::certify(CapsuleMerkleForestLayoutProposal::Monolithic {
                start_wire: 0,
                w_log: A128_FOREST_MONOLITHIC_W_LOG,
            }),
            Err(CapsuleMerkleForestError::MonolithicAllocationRejected {
                start_wire: 0,
                w_log: 17,
            })
        );
        assert_eq!(
            A128_FOREST_MONOLITHIC_COMMITTED_CELLS - A128_FOREST_COMMITTED_CELLS,
            334_080
        );
    }

    #[test]
    fn exact_source_and_mid_forests_match_native_schedule_and_path_expansion() {
        let source = forest_fixture(13, 5, source_worst_indices());
        let mid = forest_fixture(9, 1, mid_worst_indices());
        assert!(native_accepts(&source));
        assert!(native_accepts(&mid));
        assert!(expanded_accepts(&source));
        assert!(expanded_accepts(&mid));
        let forests = build_capsule_source_mid_merkle_forests(
            CapsuleMerkleForestOpening {
                cap_nodes: &source.cap_nodes,
                batch: &source.batch,
                leaf_indices: &source.indices,
                leaf_hashes: &source.hashes,
            },
            CapsuleMerkleForestOpening {
                cap_nodes: &mid.cap_nodes,
                batch: &mid.batch,
                leaf_indices: &mid.indices,
                leaf_hashes: &mid.hashes,
            },
        )
        .unwrap();
        assert_eq!(
            forests
                .source
                .levels
                .iter()
                .map(Vec::len)
                .collect::<Vec<_>>(),
            CAPSULE_SOURCE_FOREST_ROWS_PER_LEVEL.to_vec()
        );
        assert_eq!(
            forests.mid.levels.iter().map(Vec::len).collect::<Vec<_>>(),
            CAPSULE_MID_FOREST_ROWS_PER_LEVEL.to_vec()
        );
        assert_eq!(
            forests.source.consumed_sibling_positions(),
            canonical_source_batched_merkle_sibling_positions(13, 5, &source.indices).unwrap()
        );
        assert_eq!(
            forests.mid.consumed_sibling_positions(),
            canonical_source_batched_merkle_sibling_positions(9, 1, &mid.indices).unwrap()
        );
    }

    #[test]
    fn exact_worst_forests_pack_into_all_a128_level_cells() {
        let source = forest_fixture(13, 5, source_worst_indices());
        let mid = forest_fixture(9, 1, mid_worst_indices());
        let forests = build_capsule_source_mid_merkle_forests(
            CapsuleMerkleForestOpening {
                cap_nodes: &source.cap_nodes,
                batch: &source.batch,
                leaf_indices: &source.indices,
                leaf_hashes: &source.hashes,
            },
            CapsuleMerkleForestOpening {
                cap_nodes: &mid.cap_nodes,
                batch: &mid.batch,
                leaf_indices: &mid.indices,
                leaf_hashes: &mid.hashes,
            },
        )
        .unwrap();
        let capsules = vec![forests; A128_FOREST_CAPSULES];
        let columns = pack_a128_capsule_merkle_forest_columns(&capsules).unwrap();
        let committed_cells = columns
            .source()
            .iter()
            .chain(columns.mid())
            .flat_map(|level| level.committed())
            .map(Vec::len)
            .sum::<usize>();
        assert_eq!(committed_cells, A128_FOREST_COMMITTED_CELLS);
        for levels in [columns.source(), columns.mid()] {
            for level in levels {
                assert!(level.committed()[CapsuleMerkleForestColumn::Key as usize]
                    .iter()
                    .all(|&key| key != F128::ZERO));
            }
        }
    }

    #[test]
    fn malformed_sibling_stream_and_cap_match_existing_native_expansion_rejection() {
        let valid = forest_fixture(13, 5, source_worst_indices());
        assert!(direct_accepts(&valid));
        assert!(native_accepts(&valid));
        assert!(expanded_accepts(&valid));

        let mut cases = Vec::new();
        let mut missing = valid.clone();
        missing.batch.siblings.pop();
        cases.push(missing);
        let mut trailing = valid.clone();
        trailing.batch.siblings.push(leaf_hash(99, 7));
        cases.push(trailing);
        let mut reordered = valid.clone();
        reordered.batch.siblings.swap(0, 1);
        cases.push(reordered);
        let mut wrong_cap = valid.clone();
        wrong_cap.cap_nodes[0][0] ^= 1;
        cases.push(wrong_cap);

        for malformed in cases {
            assert!(!direct_accepts(&malformed));
            assert!(!native_accepts(&malformed));
            assert!(!expanded_accepts(&malformed));
        }
    }

    #[test]
    fn repeated_indices_require_one_identical_leaf_hash() {
        let indices = vec![37; ZK_CAPSULE_PCS_QUERY_COUNT];
        let valid = forest_fixture(13, 5, indices);
        let forest = build_canonical_capsule_merkle_forest(
            &valid.cap_nodes,
            valid.cap_depth,
            &valid.batch,
            valid.depth,
            &valid.indices,
            &valid.hashes,
        )
        .unwrap();
        assert_eq!(
            forest.levels.iter().map(Vec::len).collect::<Vec<_>>(),
            vec![1; 8]
        );
        assert_eq!(forest.siblings_consumed(), 8);
        assert!(native_accepts(&valid));
        assert!(expanded_accepts(&valid));

        let mut inconsistent = valid.clone();
        inconsistent.hashes[1][0] ^= 1;
        assert_eq!(
            build_canonical_capsule_merkle_forest(
                &inconsistent.cap_nodes,
                inconsistent.cap_depth,
                &inconsistent.batch,
                inconsistent.depth,
                &inconsistent.indices,
                &inconsistent.hashes,
            ),
            Err(CapsuleMerkleForestError::InconsistentRepeatedLeaf { index: 37 })
        );
        assert!(!native_accepts(&inconsistent));
        assert!(!expanded_accepts(&inconsistent));
    }

    #[test]
    fn one_node_trace_matches_native_capsule_compression() {
        let left = leaf_hash(11, 3);
        let right = leaf_hash(29, 5);
        let (_, c, native) = capsule_node_witness(&left, &right);
        assert_eq!(native, CapsuleNodeHasher.compress(&left, &right));
        let left_values = hash_lanes(&left);
        let right_values = hash_lanes(&right);
        let mut b = FieldR1csBuilder::new();
        let left_w = left_values.map(|value| LinExpr::from_wire(b.alloc_f128(value)));
        let right_w = right_values.map(|value| LinExpr::from_wire(b.alloc_f128(value)));
        let c_w = c.map(|value| LinExpr::from_wire(b.alloc_f128(value)));
        let before = b.num_wires();
        let digest = verify_capsule_merkle_forest_node_trace(&mut b, &left_w, &right_w, &c_w);
        assert_eq!(b.num_wires() - before, CAPSULE_FOREST_NODE_TRACE_ROWS);
        assert_eq!(lanes_hash(digest.map(|lane| lane.eval(b.values()))), native);
        let (r1cs, witness) = b.build();
        assert!(r1cs.satisfies(&witness));
    }
}
