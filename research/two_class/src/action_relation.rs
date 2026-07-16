// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Exact P128 action-routing seam over the retained production Beneš gadget.

use noid_recursive::acceptance::trace::action_compaction::{
    bind_mint_packed_values_body_order, compact_action_rows, CompactedActionTrace,
};
use noid_recursive::acceptance::trace::action_surface::ActionRowTrace;
use noid_recursive::acceptance::trace::{FieldR1csBuilder, LinExpr};

pub const ACTION_CANDIDATES: usize = 1 + crate::geometry::PAGE_CAPACITY * noid_tx::TX_ACTIONS;
pub const ACTION_LIVE_CAPACITY: usize =
    1 + crate::geometry::INPUT_CAPACITY + crate::geometry::OUTPUT_CAPACITY;
pub const ACTION_SORT_CAPACITY: usize = ACTION_CANDIDATES.next_power_of_two();

/// Measured allocator + Beneš + live-prefix + strict-uniqueness delta after
/// the source actions and the three counter/header aliases already exist.
pub const ACTION_RELATION_ROWS: usize = 337_769;

const _: () = assert!(ACTION_CANDIDATES == 1_281);
const _: () = assert!(ACTION_LIVE_CAPACITY == 1_277);
const _: () = assert!(ACTION_SORT_CAPACITY == 2_048);

pub fn bind_p128_action_relation(
    builder: &mut FieldR1csBuilder,
    candidates: &mut [ActionRowTrace],
    parent_alloc_counter: &LinExpr,
    child_alloc_counter: &LinExpr,
    block_height: &LinExpr,
) -> CompactedActionTrace {
    assert_eq!(candidates.len(), ACTION_CANDIDATES);
    let before = builder.num_wires();
    bind_mint_packed_values_body_order(
        builder,
        candidates,
        parent_alloc_counter,
        child_alloc_counter,
        block_height,
    );
    let compacted = compact_action_rows(builder, candidates, ACTION_LIVE_CAPACITY);
    assert_eq!(compacted.source_rows, ACTION_CANDIDATES);
    assert_eq!(compacted.sort_rows, ACTION_SORT_CAPACITY);
    assert_eq!(
        builder.num_wires() - before,
        ACTION_RELATION_ROWS,
        "P128 action relation row drift"
    );
    compacted
}

#[cfg(test)]
mod tests {
    use super::*;
    use noid_core::Block128;
    use noid_recursive::acceptance::trace::{alloc_block, F128};

    fn selected(builder: &mut FieldR1csBuilder, live: bool, value: u128) -> LinExpr {
        alloc_block(builder, Block128::from(if live { value } else { 0 }))
    }

    fn row(
        builder: &mut FieldR1csBuilder,
        ordinal: usize,
        live: bool,
        mint: bool,
    ) -> ActionRowTrace {
        let live_wire = selected(builder, live, 1);
        ActionRowTrace {
            live: live_wire.clone(),
            slot_index: selected(builder, live, ordinal as u128 + 1),
            value: selected(builder, live, ordinal as u128 + 10_000),
            owner: [
                selected(builder, live, ordinal as u128 + 20_000),
                selected(builder, live, ordinal as u128 + 30_000),
            ],
            is_mint: if mint { live_wire } else { LinExpr::zero() },
        }
    }

    #[test]
    fn saturated_p128_action_relation_has_exact_rows_and_satisfies() {
        let mut builder = FieldR1csBuilder::new();
        let mut candidates = Vec::with_capacity(ACTION_CANDIDATES);
        candidates.push(row(&mut builder, 0, true, true));
        let mut input_index = 0usize;
        let mut ordinal = 1usize;
        for _page in 0..crate::geometry::PAGE_CAPACITY {
            for _slot in 0..noid_tx::TX_INPUTS {
                let live = input_index < crate::geometry::INPUT_CAPACITY;
                candidates.push(row(&mut builder, ordinal, live, false));
                input_index += 1;
                ordinal += 1;
            }
            for _slot in 0..noid_tx::TX_OUTPUTS {
                candidates.push(row(&mut builder, ordinal, true, true));
                ordinal += 1;
            }
        }
        assert_eq!(candidates.len(), ACTION_CANDIDATES);
        assert_eq!(
            candidates
                .iter()
                .filter(|row| row.live.eval(builder.values()) == F128::ONE)
                .count(),
            ACTION_LIVE_CAPACITY,
        );

        let parent = alloc_block(&mut builder, Block128::from(100u128));
        let child = alloc_block(
            &mut builder,
            Block128::from(100u128 + 1 + crate::geometry::OUTPUT_CAPACITY as u128),
        );
        let height = alloc_block(&mut builder, Block128::from(7u128));
        let before = builder.num_wires();
        let compacted =
            bind_p128_action_relation(&mut builder, &mut candidates, &parent, &child, &height);
        assert_eq!(builder.num_wires() - before, ACTION_RELATION_ROWS);
        assert_eq!(compacted.rows.len(), ACTION_LIVE_CAPACITY);

        let (matrix, witness) = builder.build();
        assert!(matrix.satisfies(&witness));

        // Capacity-dead output selectors remain allocated expressions in the
        // real fixed matrix.  They must not be replaced by constants merely
        // because their current witness value is zero.
        let mut sparse_builder = FieldR1csBuilder::new_witness_only();
        let mut sparse = Vec::with_capacity(ACTION_CANDIDATES);
        sparse.push(row(&mut sparse_builder, 0, true, true));
        let mut ordinal = 1usize;
        for page in 0..crate::geometry::PAGE_CAPACITY {
            for slot in 0..noid_tx::TX_INPUTS {
                sparse.push(row(
                    &mut sparse_builder,
                    ordinal,
                    page == 0 && slot == 0,
                    false,
                ));
                ordinal += 1;
            }
            for slot in 0..noid_tx::TX_OUTPUTS {
                sparse.push(row(
                    &mut sparse_builder,
                    ordinal,
                    page == 0 && slot == 0,
                    true,
                ));
                ordinal += 1;
            }
        }
        let sparse_parent = alloc_block(&mut sparse_builder, Block128::from(100u128));
        let sparse_child = alloc_block(&mut sparse_builder, Block128::from(102u128));
        let sparse_height = alloc_block(&mut sparse_builder, Block128::from(7u128));
        let sparse_before = sparse_builder.num_wires();
        let _ = bind_p128_action_relation(
            &mut sparse_builder,
            &mut sparse,
            &sparse_parent,
            &sparse_child,
            &sparse_height,
        );
        assert_eq!(
            sparse_builder.num_wires() - sparse_before,
            ACTION_RELATION_ROWS
        );
        let (sparse_rows, sparse_witness) = sparse_builder.build_witness_only();
        assert_eq!(sparse_rows, matrix.useful_rows);
        assert!(matrix.satisfies(&sparse_witness));
    }
}
