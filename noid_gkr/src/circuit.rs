// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Typed topology description of the 59-slot tx-body Merkle Poseidon2b
//! spine. Sourced from the existing layout module in
//! `noid_air::airs::tx_body_merkle::layout` — this crate never
//! duplicates the layout, it reads it.
//!
//! The topology is static: 4 input leaves (3 perms each) + 8 output
//! leaves (2 each) + 15 compress nodes (2 each) + 1 wrap = 59 slots,
//! post-order. Each slot produces one digest (the pre-squeeze state
//! lanes 0..1 of its last permutation). Non-head slots take their
//! pre-MDS seed as `prev_output XOR absorb_block`; head slots take it
//! as `[absorb_block, capacity_iv]` for the slot's role.

use noid_air::airs::tx_body_merkle::layout::{
    build_instance_layout, InstanceMeta, InstanceRole, N_INSTANCES, TREE_LEAF_INPUT_BASE,
    TREE_LEAF_OUTPUT_BASE, TXBODY_N_INPUT_LEAVES, TXBODY_N_OUTPUT_LEAVES,
};
use noid_core::Block128;
use noid_poseidon2b::native::domain::{
    capacity_iv, TAG_COMPRESS, TAG_LEAF, TAG_OUTLEAF, TAG_TXBODY,
};

/// One Poseidon2b permutation slot, annotated with everything the GKR
/// prover needs to drive its inputs from either the previous slot's
/// output or from an external boundary source (leaf payload / IV).
#[derive(Debug, Clone, Copy)]
pub struct SlotDescriptor {
    /// Instance id in `0..N_INSTANCES` (matches the AIR layout).
    pub id: usize,
    /// Original `InstanceRole` from the AIR layout.
    pub role: InstanceRole,
    /// Capacity IV used at the head of the sub-sponge this slot lives
    /// in. Every slot under the same sub-sponge shares one IV; we
    /// carry it on every descriptor for local availability.
    pub capacity_iv: [Block128; 2],
    /// `true` if this slot is the head of its sub-sponge (uses the IV
    /// directly) and `false` if it chains from the previous slot's
    /// output via an inter-perm XOR absorb.
    pub is_head: bool,
    /// For non-head slots: the instance id whose output feeds this
    /// slot's state[0..1] before the absorb XOR.
    pub prev_output_src: Option<usize>,
    /// For compress heads (Perm A), the left child's instance id —
    /// whose output becomes this slot's rate block. `None` if the
    /// left child is a non-AIR leaf pinned by a verifier constant.
    pub left_child: Option<usize>,
    /// For compress Perm B: the right child's instance id, whose
    /// digest is XOR'd into state[0..1] of the Perm-B pre-MDS seed.
    pub right_child: Option<usize>,
}

/// Per-transaction witness inputs the GKR boundary must carry. These
/// are the values the STARK either already binds via public cells
/// (leaf payloads, fee, epoch_anchor, is_coinbase) or derives from
/// deterministic structure (capacity IVs).
#[derive(Debug, Clone)]
pub struct SpineInputs {
    /// `epoch_anchor` as two field lanes (tree leaf L0). Replaces the
    /// former `prev_state_root` — provides fork-binding without state
    /// coupling.
    pub epoch_anchor: [Block128; 2],
    /// `fee_leaf(fee)` as two field lanes (tree leaf L1).
    pub fee_leaf: [Block128; 2],
    /// Four input-leaf payloads, each `[slot, value, owner_hi,
    /// owner_lo]` (tree leaves L2..L5).
    pub input_leaves: [[Block128; 4]; TXBODY_N_INPUT_LEAVES],
    /// Eight output-leaf payloads, each `[slot, value, owner_hi,
    /// owner_lo]` (tree leaves L6..L13).
    pub output_leaves: [[Block128; 4]; TXBODY_N_OUTPUT_LEAVES],
    /// `is_coinbase_leaf` as two lanes (tree leaf L14).
    pub is_coinbase_leaf: [Block128; 2],
    /// Pad leaf (tree leaf L15), always `[0, 0]` in current shape.
    pub pad_leaf: [Block128; 2],
}

/// Static topology of the 59-slot spine. Cheap to construct (one pass
/// over the layout), typically built once per process and reused.
#[derive(Debug, Clone)]
pub struct SpineCircuit {
    pub slots: Vec<SlotDescriptor>,
    pub layout: Vec<InstanceMeta>,
}

impl SpineCircuit {
    /// Build the full topology from the canonical AIR layout.
    pub fn build() -> Self {
        let layout = build_instance_layout();
        debug_assert_eq!(layout.len(), N_INSTANCES);

        let iv_leaf = capacity_iv(TAG_LEAF);
        let iv_outleaf = capacity_iv(TAG_OUTLEAF);
        let iv_compress = capacity_iv(TAG_COMPRESS);
        let iv_txbody = capacity_iv(TAG_TXBODY);

        let slots = layout
            .iter()
            .enumerate()
            .map(|(id, meta)| {
                let iv = match meta.role {
                    InstanceRole::InputLeafPermA { .. }
                    | InstanceRole::InputLeafPermB { .. }
                    | InstanceRole::InputLeafPermC { .. } => iv_leaf,
                    InstanceRole::OutputLeafPermA { .. } | InstanceRole::OutputLeafPermB { .. } => {
                        iv_outleaf
                    }
                    InstanceRole::CompressPermA { .. } | InstanceRole::CompressPermB { .. } => {
                        iv_compress
                    }
                    InstanceRole::WrapPerm => iv_txbody,
                };

                let prev_output_src = if meta.is_head { None } else { Some(id - 1) };
                let (left_child, right_child) = match meta.children {
                    Some([l, r]) => (l, r),
                    None => (None, None),
                };

                SlotDescriptor {
                    id,
                    role: meta.role,
                    capacity_iv: iv,
                    is_head: meta.is_head,
                    prev_output_src,
                    left_child,
                    right_child,
                }
            })
            .collect();

        Self { slots, layout }
    }

    /// Index of the final wrap slot, whose output is `tx_body_hash`.
    #[inline]
    pub fn wrap_id(&self) -> usize {
        self.slots.len() - 1
    }
}

/// Canonical tree-leaf index helper (public for callers that need to
/// map leaf_slot → tree_leaf without going through the layout).
#[inline]
pub const fn input_tree_leaf(leaf_slot: usize) -> usize {
    TREE_LEAF_INPUT_BASE + leaf_slot
}

#[inline]
pub const fn output_tree_leaf(leaf_slot: usize) -> usize {
    TREE_LEAF_OUTPUT_BASE + leaf_slot
}

#[cfg(test)]
mod tests {
    use super::*;
    use noid_air::airs::tx_body_merkle::layout::N_INSTANCES;

    #[test]
    fn build_has_59_slots_with_one_wrap() {
        let c = SpineCircuit::build();
        assert_eq!(c.slots.len(), N_INSTANCES);
        assert_eq!(c.wrap_id(), N_INSTANCES - 1);
        assert!(matches!(
            c.slots.last().unwrap().role,
            InstanceRole::WrapPerm
        ));
    }

    #[test]
    fn heads_are_ivs_non_heads_chain_prev() {
        let c = SpineCircuit::build();
        for s in &c.slots {
            if s.is_head {
                assert!(s.prev_output_src.is_none(), "head must not chain from prev");
            } else {
                assert_eq!(s.prev_output_src, Some(s.id - 1));
            }
        }
    }

    #[test]
    fn wrap_iv_is_txbody() {
        let c = SpineCircuit::build();
        let wrap = c.slots.last().unwrap();
        assert_eq!(wrap.capacity_iv, capacity_iv(TAG_TXBODY));
    }
}
