// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Canonical 59-slot tx-body Poseidon2b topology used by GKR.
//!
//! This module keeps the production GKR crate's tx-body proof layout aligned
//! with the canonical tx-body hash:
//! 4 input leaves × 3 permutations, 8 output leaves × 2 permutations,
//! 15 binary compress nodes × 2 permutations, and 1 final wrap permutation.

pub const TXBODY_N_INPUT_LEAVES: usize = 4;
pub const TXBODY_N_OUTPUT_LEAVES: usize = 8;
pub const TXBODY_N_TREE_LEAVES: usize = 16;
pub const TXBODY_TREE_DEPTH: usize = 4;

pub const PERMS_PER_INPUT_LEAF: usize = 3;
pub const PERMS_PER_OUTPUT_LEAF: usize = 2;
pub const PERMS_PER_COMPRESS: usize = 2;
pub const PERMS_PER_WRAP: usize = 1;

pub const TREE_LEAF_PREV_STATE_ROOT: usize = 0;
pub const TREE_LEAF_FEE: usize = 1;
pub const TREE_LEAF_INPUT_BASE: usize = 2;
pub const TREE_LEAF_OUTPUT_BASE: usize = 6;
pub const TREE_LEAF_PAD_BASE: usize = 14;

pub const N_INSTANCES: usize = TXBODY_N_INPUT_LEAVES * PERMS_PER_INPUT_LEAF
    + TXBODY_N_OUTPUT_LEAVES * PERMS_PER_OUTPUT_LEAF
    + 15 * PERMS_PER_COMPRESS
    + PERMS_PER_WRAP;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstanceRole {
    InputLeafPermA { leaf_idx: u8 },
    InputLeafPermB { leaf_idx: u8 },
    InputLeafPermC { leaf_idx: u8 },
    OutputLeafPermA { leaf_idx: u8 },
    OutputLeafPermB { leaf_idx: u8 },
    CompressPermA { level: u8, pos: u8 },
    CompressPermB { level: u8, pos: u8 },
    WrapPerm,
}

impl InstanceRole {
    pub const fn is_head(&self) -> bool {
        matches!(
            self,
            Self::InputLeafPermA { .. }
                | Self::OutputLeafPermA { .. }
                | Self::CompressPermA { .. }
                | Self::WrapPerm
        )
    }

    pub const fn tree_leaf_index(&self) -> Option<usize> {
        match *self {
            Self::InputLeafPermA { leaf_idx }
            | Self::InputLeafPermB { leaf_idx }
            | Self::InputLeafPermC { leaf_idx } => Some(TREE_LEAF_INPUT_BASE + leaf_idx as usize),
            Self::OutputLeafPermA { leaf_idx } | Self::OutputLeafPermB { leaf_idx } => {
                Some(TREE_LEAF_OUTPUT_BASE + leaf_idx as usize)
            }
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InstanceMeta {
    pub role: InstanceRole,
    pub is_head: bool,
    pub parent: Option<usize>,
    pub children: Option<[Option<usize>; 2]>,
}

pub fn build_instance_layout() -> Vec<InstanceMeta> {
    let mut out = Vec::with_capacity(N_INSTANCES);
    let mut tree_leaf_last_instance: [Option<usize>; TXBODY_N_TREE_LEAVES] =
        [None; TXBODY_N_TREE_LEAVES];

    for leaf_slot in 0..TXBODY_N_INPUT_LEAVES {
        let tree_leaf = TREE_LEAF_INPUT_BASE + leaf_slot;
        out.push(make_meta(InstanceRole::InputLeafPermA {
            leaf_idx: leaf_slot as u8,
        }));
        out.push(make_meta(InstanceRole::InputLeafPermB {
            leaf_idx: leaf_slot as u8,
        }));
        let c_id = out.len();
        out.push(make_meta(InstanceRole::InputLeafPermC {
            leaf_idx: leaf_slot as u8,
        }));
        tree_leaf_last_instance[tree_leaf] = Some(c_id);
    }

    for leaf_slot in 0..TXBODY_N_OUTPUT_LEAVES {
        let tree_leaf = TREE_LEAF_OUTPUT_BASE + leaf_slot;
        out.push(make_meta(InstanceRole::OutputLeafPermA {
            leaf_idx: leaf_slot as u8,
        }));
        let b_id = out.len();
        out.push(make_meta(InstanceRole::OutputLeafPermB {
            leaf_idx: leaf_slot as u8,
        }));
        tree_leaf_last_instance[tree_leaf] = Some(b_id);
    }

    let mut prev_level_last: Vec<Option<usize>> = tree_leaf_last_instance.to_vec();
    for level in 1..=TXBODY_TREE_DEPTH {
        let n_nodes = 1 << (TXBODY_TREE_DEPTH - level);
        let mut this_level_last = Vec::with_capacity(n_nodes);
        for pos in 0..n_nodes {
            let children = [prev_level_last[2 * pos], prev_level_last[2 * pos + 1]];
            out.push(make_meta_with_children(
                InstanceRole::CompressPermA {
                    level: level as u8,
                    pos: pos as u8,
                },
                children,
            ));
            let b_id = out.len();
            out.push(make_meta_with_children(
                InstanceRole::CompressPermB {
                    level: level as u8,
                    pos: pos as u8,
                },
                children,
            ));
            this_level_last.push(Some(b_id));
        }
        prev_level_last = this_level_last;
    }

    let root_instance = prev_level_last[0];
    out.push(make_meta_with_children(
        InstanceRole::WrapPerm,
        [root_instance, None],
    ));

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
fn make_meta(role: InstanceRole) -> InstanceMeta {
    InstanceMeta {
        role,
        is_head: role.is_head(),
        parent: None,
        children: None,
    }
}

#[inline]
fn make_meta_with_children(role: InstanceRole, children: [Option<usize>; 2]) -> InstanceMeta {
    InstanceMeta {
        role,
        is_head: role.is_head(),
        parent: None,
        children: Some(children),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn instance_count_matches_budget() {
        assert_eq!(N_INSTANCES, 59);
        assert_eq!(build_instance_layout().len(), N_INSTANCES);
    }

    #[test]
    fn role_counts_by_category() {
        let layout = build_instance_layout();
        let mut input_perms = 0;
        let mut output_perms = 0;
        let mut compress_perms = 0;
        let mut wrap_perms = 0;
        for meta in &layout {
            match meta.role {
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
    fn post_order_invariants() {
        let layout = build_instance_layout();
        for (parent_id, meta) in layout.iter().enumerate() {
            if let Some([l, r]) = meta.children {
                for child in [l, r].into_iter().flatten() {
                    assert!(child < parent_id);
                }
            }
        }
    }

    #[test]
    fn wrap_is_last_and_references_root() {
        let layout = build_instance_layout();
        let last = layout.last().unwrap();
        assert!(matches!(last.role, InstanceRole::WrapPerm));
        let [left, right] = last.children.unwrap();
        assert!(left.is_some());
        assert!(right.is_none());
        assert!(matches!(
            layout[left.unwrap()].role,
            InstanceRole::CompressPermB { level: 4, pos: 0 }
        ));
    }
}
