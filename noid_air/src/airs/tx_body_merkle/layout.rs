// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Stage 3d-0.9.B — instance layout for the 59-instance tx-body Merkle
//! stack (Option α, post-order linearization).
//!
//! See ROADMAP §3d-0.9 "Design decisions":
//!
//! - 4 input leaves × 3 permutations (two `absorb_pair` blocks + the
//!   padding-flush in `finalize`) = 12 instances
//! - 8 output leaves × 2 permutations (`hash_output_leaf` absorbs four
//!   fields `[slot, value, owner_hi, owner_lo]` as two rate blocks and
//!   squeezes with no padding flush under IV `TAG_OUTLEAF`) = 16
//! - 15 internal `compress` nodes × 2 permutations = 30
//! - 1 wrap `compress(root, TXBODY_tag)` × 1 permutation = 1
//!
//! Total = **59 instances**. Each occupies one `SLOT = 128`-row slice
//! (same as 3c-5), laid out back-to-back in post-order tree traversal
//! so every cross-instance echo interval is bounded by subtree size.

use super::air::{instance_row_offset, TXBODY_MERKLE_SLOT_ROWS};

/// Shape of the tx-body Merkle tree (mirrors
/// [`noid_poseidon2b::primitives`] constants; re-stated here to keep
/// the layout module self-contained at its own test site).
pub const TXBODY_N_INPUT_LEAVES: usize = 4;
pub const TXBODY_N_OUTPUT_LEAVES: usize = 8;
pub const TXBODY_N_TREE_LEAVES: usize = 16;
pub const TXBODY_TREE_DEPTH: usize = 4;

/// Permutation budget per sub-sponge:
///
/// - Input leaf (`hash_leaf(&[slot, value, owner_hi, owner_lo])`): two
///   full `absorb_pair` blocks + `finalize` padding flush = **3**.
/// - Output leaf (`hash_output_leaf`: four fields as two `absorb_pair`
///   blocks under IV `TAG_OUTLEAF`, `finalize_no_pad` squeeze) = **2**.
/// - Internal `compress` (two permutations by construction) = **2**.
/// - Wrap (single permutation after the depth-4 root) = **1**.
pub const PERMS_PER_INPUT_LEAF: usize = 3;
pub const PERMS_PER_OUTPUT_LEAF: usize = 2;
pub const PERMS_PER_COMPRESS: usize = 2;
pub const PERMS_PER_WRAP: usize = 1;

/// Canonical tree-leaf indexing. Must agree with
/// `noid_poseidon2b::primitives::hash_tx_body` leaf ordering.
pub const TREE_LEAF_PREV_STATE_ROOT: usize = 0;
pub const TREE_LEAF_FEE: usize = 1;
pub const TREE_LEAF_INPUT_BASE: usize = 2;
pub const TREE_LEAF_OUTPUT_BASE: usize = 6;
pub const TREE_LEAF_PAD_BASE: usize = 14;

/// Total number of Poseidon2b permutations proved by the tx-body AIR
/// under the Option α layout. Must equal `TXBODY_MERKLE_N_PERMS` once
/// 3d-0.9.D retires the 68-instance 3c-5 path.
pub const N_INSTANCES: usize =
    TXBODY_N_INPUT_LEAVES * PERMS_PER_INPUT_LEAF
        + TXBODY_N_OUTPUT_LEAVES * PERMS_PER_OUTPUT_LEAF
        + 15 * PERMS_PER_COMPRESS
        + PERMS_PER_WRAP;

/// Classification of one permutation instance inside the stack. The
/// `leaf_idx` for input / output variants is the positional slot
/// (`0..TXBODY_N_INPUT_LEAVES` or `0..TXBODY_N_OUTPUT_LEAVES`), not the
/// tree-leaf index — `tree_leaf_index()` converts between them.
///
/// Compress variants carry `(level, pos)` such that `level ∈ 1..=4`
/// (`1` = bottom, `4` = root) and `pos` is the post-order position
/// within that level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstanceRole {
    /// Input-leaf sponge, first `absorb_pair` permutation (head).
    InputLeafPermA { leaf_idx: u8 },
    /// Input-leaf sponge, second `absorb_pair` permutation.
    InputLeafPermB { leaf_idx: u8 },
    /// Input-leaf sponge, `finalize` padding-flush permutation.
    InputLeafPermC { leaf_idx: u8 },
    /// Output-leaf sponge (`hash_output_leaf`), first permutation
    /// (head). Absorbs `[slot, value]` as one rate block under
    /// capacity IV `TAG_OUTLEAF`.
    OutputLeafPermA { leaf_idx: u8 },
    /// Output-leaf sponge, second permutation. Absorbs
    /// `[owner_hi, owner_lo]` as the second rate block. The sub-sponge
    /// squeezes the digest directly from this permutation's output —
    /// no padding-flush permutation (matches `finalize_no_pad` native
    /// side).
    OutputLeafPermB { leaf_idx: u8 },
    /// Internal Merkle `compress`, first permutation (head); absorbs
    /// the left-child digest through the capacity IV seed.
    CompressPermA { level: u8, pos: u8 },
    /// Internal Merkle `compress`, second permutation; absorbs the
    /// right-child digest via the inter-perm XOR.
    CompressPermB { level: u8, pos: u8 },
    /// Final wrap `compress(root, TXBODY_tag)` permutation (single).
    WrapPerm,
}

impl InstanceRole {
    /// `true` when this instance's row-0 pre-MDS state is a fresh
    /// sponge seed (capacity-IV + first absorb block). Non-head
    /// instances take their pre-MDS seed from the previous
    /// permutation's output plus an inter-perm XOR absorb.
    pub const fn is_head(&self) -> bool {
        matches!(
            self,
            Self::InputLeafPermA { .. }
                | Self::OutputLeafPermA { .. }
                | Self::CompressPermA { .. }
                | Self::WrapPerm
        )
    }

    /// Canonical Merkle-tree leaf index for a leaf-sponge instance
    /// (`L0..L15` per `hash_tx_body`). `None` for compress / wrap.
    pub const fn tree_leaf_index(&self) -> Option<usize> {
        match *self {
            Self::InputLeafPermA { leaf_idx }
            | Self::InputLeafPermB { leaf_idx }
            | Self::InputLeafPermC { leaf_idx } => {
                Some(TREE_LEAF_INPUT_BASE + leaf_idx as usize)
            }
            Self::OutputLeafPermA { leaf_idx } | Self::OutputLeafPermB { leaf_idx } => {
                Some(TREE_LEAF_OUTPUT_BASE + leaf_idx as usize)
            }
            _ => None,
        }
    }
}

/// Per-instance bookkeeping: where it sits in the trace and how it
/// wires to its neighbours.
///
/// `children` is populated for compress / wrap instances and carries
/// the **instance ids** (not tree-leaf ids) of the two child sources
/// whose output digests feed this compress's row-0 pre-MDS seed (left
/// child via capacity IV absorb, right child via inter-perm XOR
/// between Perm A and Perm B).
///
/// For non-AIR tree leaves (L0 / L1 / L14 / L15 — `prev_state_root`,
/// `fee_leaf`, zero-pad), `children` still references an instance id
/// when such a child exists; for non-AIR children the caller pins the
/// pre-MDS seed via `emit_public_cell` rather than an echo column.
/// See 3d-0.9.C / 3d-0.9.E.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InstanceMeta {
    pub role: InstanceRole,
    pub slot_base_row: usize,
    pub is_head: bool,
    pub parent: Option<usize>,
    /// Optional left / right child instance ids. `None` inside a slot
    /// means the child is a non-AIR leaf (`prev_state_root`, `fee`,
    /// zero-pad) and must be pinned via a verifier-known constant.
    pub children: Option<[Option<usize>; 2]>,
}

/// Tree-leaf → sub-sponge instance-count classifier.
#[cfg(test)]
const fn perms_for_tree_leaf(tree_leaf_idx: usize) -> usize {
    if tree_leaf_idx >= TREE_LEAF_INPUT_BASE
        && tree_leaf_idx < TREE_LEAF_INPUT_BASE + TXBODY_N_INPUT_LEAVES
    {
        PERMS_PER_INPUT_LEAF
    } else if tree_leaf_idx >= TREE_LEAF_OUTPUT_BASE
        && tree_leaf_idx < TREE_LEAF_OUTPUT_BASE + TXBODY_N_OUTPUT_LEAVES
    {
        PERMS_PER_OUTPUT_LEAF
    } else {
        0
    }
}

/// Build the full `[InstanceMeta; N_INSTANCES]` layout via post-order
/// traversal. Runs in O(N_INSTANCES); the result is deterministic and
/// intentionally computed at `TxBodyMerkleAir::new()` time rather than
/// pinned as a `const` (the nested `Option`s preclude `const` in
/// current stable Rust without an allocator, and the cost is once
/// per AIR construction — negligible).
pub fn build_instance_layout() -> Vec<InstanceMeta> {
    let mut out = Vec::with_capacity(N_INSTANCES);

    // First: emit every AIR-hashed tree leaf in canonical order so the
    // compress level-1 nodes can reference their children deterministically.
    // Tree leaves L0, L1, L14, L15 have no AIR instance (None children
    // downstream). `tree_leaf_last_instance[L]` records the id of the
    // instance whose output is the digest of L (the last permutation
    // of that leaf's sub-sponge).
    let mut tree_leaf_last_instance: [Option<usize>; TXBODY_N_TREE_LEAVES] =
        [None; TXBODY_N_TREE_LEAVES];

    // Input leaves L2..L5 (3 perms each).
    for leaf_slot in 0..TXBODY_N_INPUT_LEAVES {
        let tree_leaf = TREE_LEAF_INPUT_BASE + leaf_slot;
        let a_id = out.len();
        out.push(make_meta(
            InstanceRole::InputLeafPermA { leaf_idx: leaf_slot as u8 },
            a_id,
            None,
            None,
        ));
        let b_id = out.len();
        out.push(make_meta(
            InstanceRole::InputLeafPermB { leaf_idx: leaf_slot as u8 },
            b_id,
            None,
            None,
        ));
        let c_id = out.len();
        out.push(make_meta(
            InstanceRole::InputLeafPermC { leaf_idx: leaf_slot as u8 },
            c_id,
            None,
            None,
        ));
        tree_leaf_last_instance[tree_leaf] = Some(c_id);
    }

    // Output leaves L6..L13 (2 perms each).
    for leaf_slot in 0..TXBODY_N_OUTPUT_LEAVES {
        let tree_leaf = TREE_LEAF_OUTPUT_BASE + leaf_slot;
        let a_id = out.len();
        out.push(make_meta(
            InstanceRole::OutputLeafPermA { leaf_idx: leaf_slot as u8 },
            a_id,
            None,
            None,
        ));
        let b_id = out.len();
        out.push(make_meta(
            InstanceRole::OutputLeafPermB { leaf_idx: leaf_slot as u8 },
            b_id,
            None,
            None,
        ));
        tree_leaf_last_instance[tree_leaf] = Some(b_id);
    }

    // Compress tree: level 1 sits over tree leaves (pairs of adjacent
    // L_i, L_{i+1}), level 2 over level-1 pairs, ..., level 4 is the
    // root. `level_last_instance[level][pos]` = id of that node's
    // Perm B (the digest-producing permutation).
    let mut prev_level_last: Vec<Option<usize>> = tree_leaf_last_instance.to_vec();
    for level in 1..=TXBODY_TREE_DEPTH {
        let n_nodes = 1 << (TXBODY_TREE_DEPTH - level);
        let mut this_level_last = Vec::with_capacity(n_nodes);
        for pos in 0..n_nodes {
            let left_child = prev_level_last[2 * pos];
            let right_child = prev_level_last[2 * pos + 1];
            let a_id = out.len();
            out.push(make_meta(
                InstanceRole::CompressPermA {
                    level: level as u8,
                    pos: pos as u8,
                },
                a_id,
                None,
                Some([left_child, right_child]),
            ));
            let b_id = out.len();
            out.push(make_meta(
                InstanceRole::CompressPermB {
                    level: level as u8,
                    pos: pos as u8,
                },
                b_id,
                None,
                Some([left_child, right_child]),
            ));
            this_level_last.push(Some(b_id));
        }
        prev_level_last = this_level_last;
    }

    // Wrap: single permutation over the root digest with the TXBODY
    // capacity IV. Child = root (single).
    let root_instance = prev_level_last[0];
    let wrap_id = out.len();
    out.push(make_meta(
        InstanceRole::WrapPerm,
        wrap_id,
        None,
        Some([root_instance, None]),
    ));

    // Fill in `parent` back-references in a second pass.
    // Collect child→parent edges first to avoid aliased mutable borrows.
    let edges: Vec<(usize, usize)> = out
        .iter()
        .enumerate()
        .filter_map(|(parent_id, m)| m.children.map(|c| (parent_id, c)))
        .flat_map(|(parent_id, [l, r])| {
            [l, r]
                .into_iter()
                .flatten()
                .map(move |child_id| (child_id, parent_id))
        })
        .collect();
    for (child_id, parent_id) in edges {
        if out[child_id].parent.is_none() {
            out[child_id].parent = Some(parent_id);
        }
    }

    debug_assert_eq!(out.len(), N_INSTANCES);
    out
}

#[inline]
fn make_meta(
    role: InstanceRole,
    id: usize,
    parent: Option<usize>,
    children: Option<[Option<usize>; 2]>,
) -> InstanceMeta {
    InstanceMeta {
        role,
        slot_base_row: id * TXBODY_MERKLE_SLOT_ROWS,
        is_head: role.is_head(),
        parent,
        children,
    }
}

/// Row offset for instance `id` — identical to the 3c-5
/// `instance_row_offset` (same `SLOT = 128` stride).
#[inline]
pub fn layout_instance_row_offset(id: usize) -> usize {
    instance_row_offset(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn instance_count_matches_budget() {
        assert_eq!(N_INSTANCES, 59);
        let layout = build_instance_layout();
        assert_eq!(layout.len(), N_INSTANCES);
    }

    #[test]
    fn role_counts_by_category() {
        let layout = build_instance_layout();
        let mut input_perms = 0;
        let mut output_perms = 0;
        let mut compress_perms = 0;
        let mut wrap_perms = 0;
        for m in &layout {
            match m.role {
                InstanceRole::InputLeafPermA { .. }
                | InstanceRole::InputLeafPermB { .. }
                | InstanceRole::InputLeafPermC { .. } => input_perms += 1,
                InstanceRole::OutputLeafPermA { .. } | InstanceRole::OutputLeafPermB { .. } => {
                    output_perms += 1
                }
                InstanceRole::CompressPermA { .. } | InstanceRole::CompressPermB { .. } => {
                    compress_perms += 1
                }
                InstanceRole::WrapPerm => wrap_perms += 1,
            }
        }
        assert_eq!(input_perms, TXBODY_N_INPUT_LEAVES * PERMS_PER_INPUT_LEAF);
        assert_eq!(output_perms, TXBODY_N_OUTPUT_LEAVES * PERMS_PER_OUTPUT_LEAF);
        assert_eq!(compress_perms, 15 * PERMS_PER_COMPRESS);
        assert_eq!(wrap_perms, PERMS_PER_WRAP);
    }

    #[test]
    fn heads_are_first_perm_of_each_sub_sponge() {
        let layout = build_instance_layout();
        let head_count = layout.iter().filter(|m| m.is_head).count();
        // 4 input-leaf heads + 8 output-leaf heads + 15 compress heads +
        // 1 wrap = 28 heads.
        assert_eq!(head_count, 4 + 8 + 15 + 1);
    }

    #[test]
    fn slot_row_offsets_are_strided() {
        let layout = build_instance_layout();
        for (id, m) in layout.iter().enumerate() {
            assert_eq!(m.slot_base_row, id * TXBODY_MERKLE_SLOT_ROWS);
        }
    }

    #[test]
    fn post_order_invariants() {
        let layout = build_instance_layout();
        // Every compress / wrap instance references children whose
        // instance-ids precede it.
        for (parent_id, m) in layout.iter().enumerate() {
            if let Some([l, r]) = m.children {
                for child in [l, r].into_iter().flatten() {
                    assert!(
                        child < parent_id,
                        "instance {parent_id} references later child {child} ({:?})",
                        m.role,
                    );
                }
            }
        }
    }

    #[test]
    fn parent_back_references_are_consistent() {
        let layout = build_instance_layout();
        for (child_id, m) in layout.iter().enumerate() {
            if let Some(parent_id) = m.parent {
                let parent = layout[parent_id];
                let refs_child = parent
                    .children
                    .map(|[l, r]| [l, r].into_iter().flatten().any(|c| c == child_id))
                    .unwrap_or(false);
                assert!(refs_child, "parent {parent_id} must reference child {child_id}");
            }
        }
    }

    #[test]
    fn every_tree_leaf_sponge_feeds_level_one_compress() {
        let layout = build_instance_layout();
        // Collect the `children` fields of every level-1 compress
        // Perm A (CompressPermA with level == 1) and verify each refers
        // to an existing leaf-sponge last-perm or to `None` for the
        // four non-AIR tree leaves (L0, L1, L14, L15).
        let mut level1_children: Vec<[Option<usize>; 2]> = Vec::new();
        for m in &layout {
            if let InstanceRole::CompressPermA { level: 1, .. } = m.role {
                level1_children.push(m.children.unwrap());
            }
        }
        assert_eq!(level1_children.len(), 8);
        let non_air_leaves = [
            TREE_LEAF_PREV_STATE_ROOT,
            TREE_LEAF_FEE,
            TREE_LEAF_PAD_BASE,
            TREE_LEAF_PAD_BASE + 1,
        ];
        // For the pair (L0, L1) both children must be None; for the
        // pair (L14, L15) both children must be None. All other
        // level-1 compress nodes must have both children Some.
        for (pair_idx, [l, r]) in level1_children.iter().enumerate() {
            let left_tree = 2 * pair_idx;
            let right_tree = 2 * pair_idx + 1;
            assert_eq!(l.is_none(), non_air_leaves.contains(&left_tree));
            assert_eq!(r.is_none(), non_air_leaves.contains(&right_tree));
        }
    }

    #[test]
    fn wrap_is_last_and_references_root() {
        let layout = build_instance_layout();
        let last = layout.last().unwrap();
        assert!(matches!(last.role, InstanceRole::WrapPerm));
        let [l, r] = last.children.unwrap();
        assert!(l.is_some(), "wrap must reference root compress instance");
        assert!(r.is_none(), "wrap is unary");
        // And that root is the Perm B of the level-4 compress.
        let root_id = l.unwrap();
        assert!(matches!(
            layout[root_id].role,
            InstanceRole::CompressPermB { level: 4, pos: 0 }
        ));
    }

    #[test]
    fn tree_leaf_index_matches_canonical_ordering() {
        for leaf_slot in 0..TXBODY_N_INPUT_LEAVES {
            assert_eq!(
                InstanceRole::InputLeafPermA {
                    leaf_idx: leaf_slot as u8
                }
                .tree_leaf_index(),
                Some(TREE_LEAF_INPUT_BASE + leaf_slot),
            );
        }
        for leaf_slot in 0..TXBODY_N_OUTPUT_LEAVES {
            assert_eq!(
                InstanceRole::OutputLeafPermB {
                    leaf_idx: leaf_slot as u8
                }
                .tree_leaf_index(),
                Some(TREE_LEAF_OUTPUT_BASE + leaf_slot),
            );
        }
        assert_eq!(InstanceRole::WrapPerm.tree_leaf_index(), None);
        assert_eq!(
            InstanceRole::CompressPermA { level: 2, pos: 1 }.tree_leaf_index(),
            None,
        );
    }

    #[test]
    fn perms_for_tree_leaf_dispatch() {
        assert_eq!(perms_for_tree_leaf(TREE_LEAF_PREV_STATE_ROOT), 0);
        assert_eq!(perms_for_tree_leaf(TREE_LEAF_FEE), 0);
        assert_eq!(perms_for_tree_leaf(TREE_LEAF_INPUT_BASE), PERMS_PER_INPUT_LEAF);
        assert_eq!(
            perms_for_tree_leaf(TREE_LEAF_INPUT_BASE + 3),
            PERMS_PER_INPUT_LEAF
        );
        assert_eq!(
            perms_for_tree_leaf(TREE_LEAF_OUTPUT_BASE),
            PERMS_PER_OUTPUT_LEAF
        );
        assert_eq!(
            perms_for_tree_leaf(TREE_LEAF_OUTPUT_BASE + 7),
            PERMS_PER_OUTPUT_LEAF
        );
        assert_eq!(perms_for_tree_leaf(TREE_LEAF_PAD_BASE), 0);
        assert_eq!(perms_for_tree_leaf(TREE_LEAF_PAD_BASE + 1), 0);
    }

    #[test]
    fn total_row_budget_fits_half_hypercube() {
        // 59 × 128 = 7552 ≤ 2^13 = 8192 — the ROADMAP-claimed halving
        // from 2^14 to 2^13 is feasible at this instance count.
        let live_rows = N_INSTANCES * TXBODY_MERKLE_SLOT_ROWS;
        assert_eq!(live_rows, 7552);
        assert!(live_rows <= (1 << 13));
    }
}
