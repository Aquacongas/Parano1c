// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! P128 exact-state topology census over retained production primitives.
//!
//! The production exact-state design is kept intact: a sibling-only native
//! frontier derives fixed local/upper paired updates, sorted actions bind the
//! old/new leaves, and segment compaction closes both header roots. Research
//! only copies the small private assembly glue so it can measure the P128
//! geometry without widening a production API.

use noid_recursive::acceptance::trace::action_compaction::CompactedActionTrace;
use noid_recursive::acceptance::trace::exact_state::{
    bind_actions_to_exact_state_leaves, select_upper_paired_roots, ExactStateSlotWires,
    PairedRootCellPair, StateDepthTrace,
};
use noid_recursive::acceptance::trace::region_source_binding::PairedExactStateCells;
use noid_recursive::acceptance::trace::segment_compaction::{
    bind_segment_upper_chain, compact_segment_updates,
};

use crate::circuit_support::{pin_eq, FieldR1csBuilder, LinExpr};

pub const P128_TOUCHED_CAPACITY: usize = crate::action_relation::ACTION_LIVE_CAPACITY;
pub const P128_SEGMENT_CAPACITY: usize = 256;
pub const PAIRED_UPDATE_ROWS: usize = 64;
pub const P128_PAIRED_ACTIVE_ROWS: usize =
    (P128_TOUCHED_CAPACITY + P128_SEGMENT_CAPACITY) * PAIRED_UPDATE_ROWS;
pub const P128_PAIRED_DOMAIN_ROWS: usize = P128_PAIRED_ACTIVE_ROWS.next_power_of_two();
pub const P128_PAIRED_COMMITTED_COLUMNS: usize = 9;
pub const P128_PAIRED_COMMITTED_CELLS: usize =
    P128_PAIRED_DOMAIN_ROWS * P128_PAIRED_COMMITTED_COLUMNS;

const _: () = assert!(P128_TOUCHED_CAPACITY == 1_277);
const _: () = assert!(P128_SEGMENT_CAPACITY == 256);
const _: () = assert!(P128_PAIRED_ACTIVE_ROWS == 98_112);
const _: () = assert!(P128_PAIRED_DOMAIN_ROWS == 131_072);
const _: () = assert!(P128_PAIRED_COMMITTED_CELLS == 1_179_648);

fn pin_pair(builder: &mut FieldR1csBuilder, left: &[LinExpr; 2], right: &[LinExpr; 2]) {
    pin_eq(builder, &left[0], &right[0]);
    pin_eq(builder, &left[1], &right[1]);
}

/// Close the retained exact-state connection layer for P128.
///
/// Paired cells are authenticated-interface aliases: this function counts the
/// direct leaf/action/segment/root glue, while the 9-column paired carrier is
/// reported separately by [`P128_PAIRED_COMMITTED_CELLS`].
pub fn bind_p128_exact_state_connection(
    builder: &mut FieldR1csBuilder,
    actions: &CompactedActionTrace,
    exact_state: &ExactStateSlotWires,
    paired: &PairedExactStateCells,
    child_depth: &StateDepthTrace,
) -> usize {
    let before = builder.num_wires();
    let touched_capacity = actions.rows.len();
    assert_eq!(touched_capacity, P128_TOUCHED_CAPACITY);
    assert_eq!(exact_state.slot_leaves.len(), 2 * touched_capacity);
    assert_eq!(paired.local.len(), touched_capacity);
    assert_eq!(paired.upper.len(), P128_SEGMENT_CAPACITY);

    let (old_leaves, new_leaves) = exact_state.slot_leaves.split_at(touched_capacity);
    bind_actions_to_exact_state_leaves(builder, &actions.rows, old_leaves, new_leaves);

    let mut local_before = Vec::with_capacity(touched_capacity);
    let mut local_after = Vec::with_capacity(touched_capacity);
    for index in 0..touched_capacity {
        let cells = &paired.local[index];
        pin_pair(builder, &old_leaves[index].expected_leaf, &cells.old_entry);
        pin_pair(builder, &new_leaves[index].expected_leaf, &cells.new_entry);
        for level in 0..16 {
            pin_eq(
                builder,
                &cells.directions[level],
                &LinExpr::from_wire(actions.slot_bits[index][level]),
            );
        }
        local_before.push(cells.old_root.clone());
        local_after.push(cells.new_root.clone());
    }

    let segments = compact_segment_updates(
        builder,
        &actions.rows,
        &actions.slot_bits,
        &actions.adjacent_msb_one_hot,
        &actions.adjacent_both_live,
        &local_before,
        &local_after,
        paired.upper.len(),
    );

    let mut upper_old_entries = Vec::with_capacity(paired.upper.len());
    let mut upper_new_entries = Vec::with_capacity(paired.upper.len());
    let mut upper_before = Vec::with_capacity(paired.upper.len());
    let mut upper_after = Vec::with_capacity(paired.upper.len());
    for (index, cells) in paired.upper.iter().enumerate() {
        for level in 0..16 {
            pin_eq(
                builder,
                &cells.directions[level],
                &LinExpr::from_wire(segments.segment_id_bits[index][level]),
            );
        }
        let roots_by_depth: [PairedRootCellPair; 16] = std::array::from_fn(|level| {
            [
                cells.old_roots[level].clone(),
                cells.new_roots[level].clone(),
            ]
        });
        let selected = select_upper_paired_roots(builder, child_depth, &roots_by_depth);
        upper_old_entries.push(cells.old_entry.clone());
        upper_new_entries.push(cells.new_entry.clone());
        upper_before.push(selected[0].clone());
        upper_after.push(selected[1].clone());
    }

    bind_segment_upper_chain(
        builder,
        &segments,
        &upper_old_entries,
        &upper_new_entries,
        &upper_before,
        &upper_after,
        &exact_state.roots.old_root,
        &exact_state.roots.new_root,
    );
    let rows = builder.num_wires() - before;
    // Keep a final explicit pin in this module's vocabulary so accidental
    // replacement of the production glue by a no-op cannot pass a census.
    debug_assert!(rows > 0);
    rows
}

#[cfg(test)]
mod tests {
    use super::*;
    use noid_chain::exact_state_hash::{slot_leaf_hash, StateHash};
    use noid_chain::sparse_merkle::{
        derive_structural_frontier_plan, evaluate_structural_frontier,
    };
    use noid_chain::SlotValue;
    use noid_core::{hardware::flat_to_tower_u128, Block128};
    use noid_gkr::state_leaf_killshot::SlotLeafInputs;
    use noid_ivc_core::field_r1cs::FieldR1cs;
    use noid_poseidon2b::native::{capacity_iv, DomainTag};
    use noid_recursive::acceptance::history_step::ExactStateStructuralFrontierInputs;
    use noid_recursive::acceptance::trace::action_surface::ActionRowTrace;
    use noid_recursive::acceptance::trace::exact_state::{
        bind_exact_state_header_roots_dynamic, build_exact_state_structural_region_slot,
        ExactStatePairedRegionData,
    };
    use noid_recursive::acceptance::trace::paired_merkle_update::{
        build_paired_merkle_update_columns, PairedMerkleUpdateWitness,
    };
    use noid_recursive::acceptance::trace::region_source_binding::{
        PairedLocalExactStateCells, PairedUpperExactStateCells,
    };

    use crate::action_relation::{bind_p128_action_relation, ACTION_CANDIDATES};
    use crate::circuit_support::{alloc_block, flat_of, F128};

    const TAG_EXSTNOD: DomainTag = DomainTag::new(b"EXSTNOD_");

    fn fields_to_hash(fields: [Block128; 2]) -> StateHash {
        let mut digest = [0u8; 32];
        digest[..16].copy_from_slice(&fields[0].0.to_le_bytes());
        digest[16..].copy_from_slice(&fields[1].0.to_le_bytes());
        digest
    }

    fn hash_to_fields(digest: StateHash) -> [Block128; 2] {
        let mut low = [0u8; 16];
        let mut high = [0u8; 16];
        low.copy_from_slice(&digest[..16]);
        high.copy_from_slice(&digest[16..]);
        [
            Block128::from(u128::from_le_bytes(low)),
            Block128::from(u128::from_le_bytes(high)),
        ]
    }

    fn leaf(slot: SlotValue) -> SlotLeafInputs {
        SlotLeafInputs {
            packed_value: slot.value,
            owner_hi: slot.owner_hi,
            owner_lo: slot.owner_lo,
            expected_leaf: hash_to_fields(slot_leaf_hash(slot)),
        }
    }

    fn tower(builder: &FieldR1csBuilder, expression: &LinExpr) -> Block128 {
        let flat = expression.eval(builder.values());
        Block128::from(flat_to_tower_u128(
            (flat.lo as u128) | ((flat.hi as u128) << 64),
        ))
    }

    fn synthetic_candidates(builder: &mut FieldR1csBuilder) -> CompactedActionTrace {
        let mut candidates = Vec::with_capacity(ACTION_CANDIDATES);
        for candidate in 0..ACTION_CANDIDATES {
            let live = alloc_block(builder, Block128::from((candidate == 0) as u128));
            // Candidate zero is coinbase. The remaining rows are page-local
            // Tx8x2 actions, so their output/mint slots are 8 and 9 after
            // removing the coinbase offset. Keeping the offset in the modulo
            // silently changed the structural relation for sparse fixtures.
            let page_action = candidate.saturating_sub(1) % noid_tx::TX_ACTIONS;
            let mint_position = candidate == 0 || page_action >= noid_tx::TX_INPUTS;
            candidates.push(ActionRowTrace {
                live: live.clone(),
                slot_index: alloc_block(
                    builder,
                    Block128::from(if candidate == 0 { 7u128 } else { 0 }),
                ),
                value: alloc_block(
                    builder,
                    Block128::from(if candidate == 0 { 50_000_000u128 } else { 0 }),
                ),
                owner: [
                    alloc_block(
                        builder,
                        Block128::from(if candidate == 0 { 0x1234u128 } else { 0 }),
                    ),
                    alloc_block(
                        builder,
                        Block128::from(if candidate == 0 { 0x5678u128 } else { 0 }),
                    ),
                ],
                is_mint: if mint_position { live } else { LinExpr::zero() },
            });
        }
        let parent = alloc_block(builder, Block128::from(100u128));
        let child = alloc_block(builder, Block128::from(101u128));
        let height = alloc_block(builder, Block128::from(9u128));
        bind_p128_action_relation(builder, &mut candidates, &parent, &child, &height)
    }

    fn frontier_from_actions(
        builder: &FieldR1csBuilder,
        actions: &CompactedActionTrace,
        depth: u32,
    ) -> ExactStateStructuralFrontierInputs {
        let mut indices = Vec::new();
        let mut old_slot_leaves = Vec::new();
        let mut new_slot_leaves = Vec::new();
        for action in &actions.rows {
            if action.live.eval(builder.values()) != F128::ONE {
                continue;
            }
            let index = tower(builder, &action.slot_index).0 as u32;
            let value = tower(builder, &action.value);
            let owner = [
                tower(builder, &action.owner[0]),
                tower(builder, &action.owner[1]),
            ];
            let mint = action.is_mint.eval(builder.values()) == F128::ONE;
            indices.push(index);
            old_slot_leaves.push(leaf(if mint {
                SlotValue::EMPTY
            } else {
                SlotValue {
                    value,
                    owner_hi: owner[0],
                    owner_lo: owner[1],
                }
            }));
            new_slot_leaves.push(leaf(if mint {
                SlotValue {
                    value,
                    owner_hi: owner[0],
                    owner_lo: owner[1],
                }
            } else {
                SlotValue::EMPTY
            }));
        }
        let plan = derive_structural_frontier_plan(&indices, depth).unwrap();
        let live_sibling_digests = (0..plan.frontier_positions().len())
            .map(|ordinal| {
                slot_leaf_hash(SlotValue {
                    value: Block128::from(10_000 + ordinal as u128),
                    owner_hi: Block128::from(20_000 + ordinal as u128),
                    owner_lo: Block128::from(30_000 + ordinal as u128),
                })
            })
            .collect::<Vec<_>>();
        let old_hashes = old_slot_leaves
            .iter()
            .map(|input| fields_to_hash(input.expected_leaf))
            .collect::<Vec<_>>();
        let new_hashes = new_slot_leaves
            .iter()
            .map(|input| fields_to_hash(input.expected_leaf))
            .collect::<Vec<_>>();
        let old_evaluation =
            evaluate_structural_frontier(&plan, &old_hashes, &live_sibling_digests).unwrap();
        let new_evaluation =
            evaluate_structural_frontier(&plan, &new_hashes, &live_sibling_digests).unwrap();
        ExactStateStructuralFrontierInputs {
            touched_indices: indices,
            active_depth: depth,
            old_slot_leaves,
            new_slot_leaves,
            live_sibling_digests,
            old_combine_digests: old_evaluation.combines,
            new_combine_digests: new_evaluation.combines,
            old_root: old_evaluation.root,
            new_root: new_evaluation.root,
        }
    }

    fn alloc_flat(builder: &mut FieldR1csBuilder, value: F128) -> LinExpr {
        LinExpr::from_wire(builder.alloc_f128(value))
    }

    fn paired_cells(
        builder: &mut FieldR1csBuilder,
        paired: &ExactStatePairedRegionData,
    ) -> PairedExactStateCells {
        let packed = paired.packed_updates();
        let iv = capacity_iv(TAG_EXSTNOD);
        let columns = build_paired_merkle_update_columns(
            &packed.updates,
            [flat_of(iv[0]), flat_of(iv[1])],
            packed.w_log,
        );
        let pair = |builder: &mut FieldR1csBuilder, values: [F128; 2]| {
            values.map(|value| alloc_flat(builder, value))
        };
        let directions = |builder: &mut FieldR1csBuilder, update: &PairedMerkleUpdateWitness| {
            update.directions.map(|direction| {
                alloc_flat(builder, if direction { F128::ONE } else { F128::ZERO })
            })
        };

        let local = (0..paired.touched_capacity)
            .map(|ordinal| {
                let update = &packed.updates[ordinal];
                let (old_root, new_root) = columns.update_roots_at_depth(ordinal, 16);
                PairedLocalExactStateCells {
                    old_entry: pair(builder, update.old_entry),
                    new_entry: pair(builder, update.new_entry),
                    old_root: pair(builder, old_root),
                    new_root: pair(builder, new_root),
                    directions: directions(builder, update),
                }
            })
            .collect::<Vec<_>>();
        let upper = (0..paired.segment_capacity)
            .map(|segment| {
                let ordinal = paired.touched_capacity + segment;
                let update = &packed.updates[ordinal];
                let roots: [([F128; 2], [F128; 2]); 16] =
                    std::array::from_fn(|depth| columns.update_roots_at_depth(ordinal, depth + 1));
                PairedUpperExactStateCells {
                    old_entry: pair(builder, update.old_entry),
                    new_entry: pair(builder, update.new_entry),
                    old_roots: std::array::from_fn(|depth| pair(builder, roots[depth].0)),
                    new_roots: std::array::from_fn(|depth| pair(builder, roots[depth].1)),
                    directions: directions(builder, update),
                }
            })
            .collect::<Vec<_>>();
        PairedExactStateCells { local, upper }
    }

    struct BuiltCase {
        matrix: FieldR1cs,
        witness: Vec<F128>,
        structural_rows: usize,
        connection_rows: usize,
        interface_alias_rows: usize,
    }

    fn build_case() -> BuiltCase {
        let mut builder = FieldR1csBuilder::new();
        let actions = synthetic_candidates(&mut builder);
        let frontier = frontier_from_actions(&builder, &actions, 24);
        let parent_root =
            hash_to_fields(frontier.old_root).map(|value| alloc_block(&mut builder, value));
        let child_root =
            hash_to_fields(frontier.new_root).map(|value| alloc_block(&mut builder, value));
        let parent_log = alloc_block(&mut builder, Block128::from(24u128));
        let child_log = alloc_block(&mut builder, Block128::from(24u128));

        let before = builder.num_wires();
        let (exact_state, region) = build_exact_state_structural_region_slot(
            &mut builder,
            &frontier,
            P128_TOUCHED_CAPACITY,
            P128_SEGMENT_CAPACITY,
        )
        .unwrap();
        let depth = bind_exact_state_header_roots_dynamic(
            &mut builder,
            &exact_state.roots,
            &parent_root,
            &parent_log,
            &child_root,
            &child_log,
        );
        let structural_rows = builder.num_wires() - before;

        let before = builder.num_wires();
        let paired = paired_cells(&mut builder, &region.paired);
        let interface_alias_rows = builder.num_wires() - before;
        let connection_rows = bind_p128_exact_state_connection(
            &mut builder,
            &actions,
            &exact_state,
            &paired,
            &depth.child,
        );
        let (matrix, witness) = builder.build();
        BuiltCase {
            matrix,
            witness,
            structural_rows,
            connection_rows,
            interface_alias_rows,
        }
    }

    #[test]
    fn p128_exact_state_relation_satisfies_and_reports_census() {
        let case = build_case();
        assert!(case.matrix.satisfies(&case.witness));
        println!(
            "P128 exact-state structural={} connection={} exposed_aliases={} paired_cells={}",
            case.structural_rows,
            case.connection_rows,
            case.interface_alias_rows,
            P128_PAIRED_COMMITTED_CELLS,
        );
        assert!(case.structural_rows > 0);
        assert!(case.connection_rows > 0);
        assert_eq!(P128_PAIRED_COMMITTED_CELLS, 1_179_648);
    }
}
