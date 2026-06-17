// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Typed topology description of the `Sweep25x2` tx-body Merkle Poseidon2b
//! spine.
//!
//! Layout mirrors `noid_poseidon2b::primitives::hash_tx_body_sweep25x2`:
//!
//! ```text
//! L0          epoch_anchor
//! L1          fee_leaf
//! L2          shape_leaf(Sweep25x2)
//! L3..L27     input leaves[0..25]
//! L28..L29    output leaves[0..2]
//! L30         is_coinbase_leaf
//! L31         reserved/pad
//! ```
//!
//! Proved permutation slots:
//!
//! - 25 input leaves × 3 perms = 75
//! - 2 output leaves × 2 perms = 4
//! - 31 internal compress nodes × 2 perms = 62
//! - 1 tx-body wrap perm = 1
//!
//! Total = 142 slots.

use noid_core::Block128;
use noid_poseidon2b::native::domain::{
    capacity_iv, TAG_COMPRESS, TAG_LEAF, TAG_OUTLEAF, TAG_TXBODY,
};

pub const SWEEP_SPINE_INPUT_LEAVES: usize = 25;
pub const SWEEP_SPINE_OUTPUT_LEAVES: usize = 2;
pub const SWEEP_SPINE_TREE_LEAVES: usize = 32;
pub const SWEEP_SPINE_TREE_DEPTH: usize = 5;

pub const SWEEP_TREE_LEAF_EPOCH_ANCHOR: usize = 0;
pub const SWEEP_TREE_LEAF_FEE: usize = 1;
pub const SWEEP_TREE_LEAF_SHAPE: usize = 2;
pub const SWEEP_TREE_LEAF_INPUT_BASE: usize = 3;
pub const SWEEP_TREE_LEAF_OUTPUT_BASE: usize = 28;
pub const SWEEP_TREE_LEAF_IS_COINBASE: usize = 30;
pub const SWEEP_TREE_LEAF_PAD: usize = 31;

pub const SWEEP_PERMS_PER_INPUT_LEAF: usize = 3;
pub const SWEEP_PERMS_PER_OUTPUT_LEAF: usize = 2;
pub const SWEEP_PERMS_PER_COMPRESS: usize = 2;
pub const SWEEP_PERMS_PER_WRAP: usize = 1;

pub const N_SWEEP_SPINE_SLOTS: usize = SWEEP_SPINE_INPUT_LEAVES * SWEEP_PERMS_PER_INPUT_LEAF
    + SWEEP_SPINE_OUTPUT_LEAVES * SWEEP_PERMS_PER_OUTPUT_LEAF
    + (SWEEP_SPINE_TREE_LEAVES - 1) * SWEEP_PERMS_PER_COMPRESS
    + SWEEP_PERMS_PER_WRAP;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SweepSpineSlotRole {
    InputLeafPermA { leaf_idx: u8 },
    InputLeafPermB { leaf_idx: u8 },
    InputLeafPermC { leaf_idx: u8 },
    OutputLeafPermA { leaf_idx: u8 },
    OutputLeafPermB { leaf_idx: u8 },
    CompressPermA { level: u8, pos: u8 },
    CompressPermB { level: u8, pos: u8 },
    WrapPerm,
}

impl SweepSpineSlotRole {
    pub const fn is_head(&self) -> bool {
        matches!(
            self,
            Self::InputLeafPermA { .. }
                | Self::OutputLeafPermA { .. }
                | Self::CompressPermA { .. }
                | Self::WrapPerm
        )
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SweepSlotDescriptor {
    pub id: usize,
    pub role: SweepSpineSlotRole,
    pub capacity_iv: [Block128; 2],
    pub is_head: bool,
    pub prev_output_src: Option<usize>,
    pub left_child: Option<usize>,
    pub right_child: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SweepSpineInputs {
    pub epoch_anchor: [Block128; 2],
    pub fee_leaf: [Block128; 2],
    pub shape_leaf: [Block128; 2],
    pub input_leaves: [[Block128; 4]; SWEEP_SPINE_INPUT_LEAVES],
    pub output_leaves: [[Block128; 4]; SWEEP_SPINE_OUTPUT_LEAVES],
    pub is_coinbase_leaf: [Block128; 2],
    pub pad_leaf: [Block128; 2],
}

#[derive(Debug, Clone)]
pub struct SweepSpineCircuit {
    pub slots: Vec<SweepSlotDescriptor>,
}

impl SweepSpineCircuit {
    pub fn build() -> Self {
        let iv_leaf = capacity_iv(TAG_LEAF);
        let iv_outleaf = capacity_iv(TAG_OUTLEAF);
        let iv_compress = capacity_iv(TAG_COMPRESS);
        let iv_txbody = capacity_iv(TAG_TXBODY);

        let mut slots = Vec::with_capacity(N_SWEEP_SPINE_SLOTS);
        let mut leaf_last: [Option<usize>; SWEEP_SPINE_TREE_LEAVES] =
            [None; SWEEP_SPINE_TREE_LEAVES];

        for leaf_idx in 0..SWEEP_SPINE_INPUT_LEAVES {
            let a = push_slot(
                &mut slots,
                SweepSpineSlotRole::InputLeafPermA {
                    leaf_idx: leaf_idx as u8,
                },
                iv_leaf,
                None,
                None,
            );
            let b = push_slot(
                &mut slots,
                SweepSpineSlotRole::InputLeafPermB {
                    leaf_idx: leaf_idx as u8,
                },
                iv_leaf,
                None,
                None,
            );
            let c = push_slot(
                &mut slots,
                SweepSpineSlotRole::InputLeafPermC {
                    leaf_idx: leaf_idx as u8,
                },
                iv_leaf,
                None,
                None,
            );
            debug_assert_eq!(b, a + 1);
            debug_assert_eq!(c, b + 1);
            leaf_last[SWEEP_TREE_LEAF_INPUT_BASE + leaf_idx] = Some(c);
        }

        for leaf_idx in 0..SWEEP_SPINE_OUTPUT_LEAVES {
            let a = push_slot(
                &mut slots,
                SweepSpineSlotRole::OutputLeafPermA {
                    leaf_idx: leaf_idx as u8,
                },
                iv_outleaf,
                None,
                None,
            );
            let b = push_slot(
                &mut slots,
                SweepSpineSlotRole::OutputLeafPermB {
                    leaf_idx: leaf_idx as u8,
                },
                iv_outleaf,
                None,
                None,
            );
            debug_assert_eq!(b, a + 1);
            leaf_last[SWEEP_TREE_LEAF_OUTPUT_BASE + leaf_idx] = Some(b);
        }

        let mut current = leaf_last.to_vec();
        for level in 1..=SWEEP_SPINE_TREE_DEPTH {
            let parent_count = SWEEP_SPINE_TREE_LEAVES >> level;
            let mut next = vec![None; parent_count];
            for pos in 0..parent_count {
                let left = current[2 * pos];
                let right = current[2 * pos + 1];
                let a = push_slot(
                    &mut slots,
                    SweepSpineSlotRole::CompressPermA {
                        level: level as u8,
                        pos: pos as u8,
                    },
                    iv_compress,
                    left,
                    right,
                );
                let b = push_slot(
                    &mut slots,
                    SweepSpineSlotRole::CompressPermB {
                        level: level as u8,
                        pos: pos as u8,
                    },
                    iv_compress,
                    left,
                    right,
                );
                debug_assert_eq!(b, a + 1);
                next[pos] = Some(b);
            }
            current = next;
        }
        debug_assert_eq!(current.len(), 1);
        let root = current[0].expect("sweep spine root must be a proved compress slot");

        push_slot(
            &mut slots,
            SweepSpineSlotRole::WrapPerm,
            iv_txbody,
            Some(root),
            None,
        );

        debug_assert_eq!(slots.len(), N_SWEEP_SPINE_SLOTS);
        Self { slots }
    }

    #[inline]
    pub fn wrap_id(&self) -> usize {
        self.slots.len() - 1
    }
}

fn push_slot(
    slots: &mut Vec<SweepSlotDescriptor>,
    role: SweepSpineSlotRole,
    capacity_iv: [Block128; 2],
    left_child: Option<usize>,
    right_child: Option<usize>,
) -> usize {
    let id = slots.len();
    let is_head = role.is_head();
    slots.push(SweepSlotDescriptor {
        id,
        role,
        capacity_iv,
        is_head,
        prev_output_src: if is_head { None } else { Some(id - 1) },
        left_child,
        right_child,
    });
    id
}

#[inline]
pub const fn sweep_input_tree_leaf(leaf_slot: usize) -> usize {
    SWEEP_TREE_LEAF_INPUT_BASE + leaf_slot
}

#[inline]
pub const fn sweep_output_tree_leaf(leaf_slot: usize) -> usize {
    SWEEP_TREE_LEAF_OUTPUT_BASE + leaf_slot
}

#[cfg(test)]
mod tests {
    use super::*;
    use noid_poseidon2b::native::domain::TAG_TXBODY;

    #[test]
    fn build_has_expected_slot_count_and_wrap() {
        let c = SweepSpineCircuit::build();
        assert_eq!(N_SWEEP_SPINE_SLOTS, 142);
        assert_eq!(c.slots.len(), N_SWEEP_SPINE_SLOTS);
        assert_eq!(c.wrap_id(), N_SWEEP_SPINE_SLOTS - 1);
        assert!(matches!(
            c.slots.last().unwrap().role,
            SweepSpineSlotRole::WrapPerm
        ));
    }

    #[test]
    fn heads_are_ivs_non_heads_chain_prev() {
        let c = SweepSpineCircuit::build();
        for s in &c.slots {
            if s.is_head {
                assert!(s.prev_output_src.is_none());
            } else {
                assert_eq!(s.prev_output_src, Some(s.id - 1));
            }
        }
    }

    #[test]
    fn wrap_iv_is_txbody() {
        let c = SweepSpineCircuit::build();
        let wrap = c.slots.last().unwrap();
        assert_eq!(wrap.capacity_iv, capacity_iv(TAG_TXBODY));
    }
}
