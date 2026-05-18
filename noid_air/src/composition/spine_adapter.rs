// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Spine-embedding adapter — layout and typed-cell accessors.
//!
//! Defines where a
//! [`crate::airs::tx_body_spine::TxBodySpineComposite`] block sits
//! inside the outer tx-validity composite and exposes typed
//! `(col, row)` accessors for the cells used as bridge dsts:
//!
//! - **T2a dst** (auth-tag tie, per input `i ∈ 0..MAX_INPUTS`):
//!   [`SpineEmbeddingLayout::auth_tag_hi_outer_cell`] /
//!   [`SpineEmbeddingLayout::auth_tag_lo_outer_cell`] — points at
//!   `TxValidityCol::AuthTagHi/Lo` (composite-internal cols 8/9, row
//!   `i`) inside the embedded spine.
//!
//! - **Output leaf absorb row** (per output `j ∈ 0..MAX_OUTPUTS`):
//!   [`SpineEmbeddingLayout::output_leaf_a_outer_cell`] — points at
//!   the `OutputLeafPermA` rate-absorb payload row inside the spine's
//!   `TxBodyMerkle` block, on the canonical payload column shared
//!   across all leaf-rate slots. This cell is pinned directly by
//!   `TxBodyMerkleAir`'s `o1_payload_programme` public column.
//!
//! - **T2b dst** (tx-body-hash tie, per input):
//!   [`SpineEmbeddingLayout::wrap_output_outer_cell`] — points at the
//!   wrap-perm output row `(s[0..1] @ wrap_slot_base_row + N_ROUNDS)`
//!   inside the spine's `TxBodyMerkle` block. This is the canonical
//!   single origin of `tx_body_hash` per the audit § 1 / § 6.2
//!   invariants.
//!
//! All accessors derive their values from `build_instance_layout()`
//! and the spine's public column-offset constants — they cannot drift
//! out of sync silently.

use crate::airs::tx_body_merkle::{
    build_instance_layout, leaf_rate_payload_col, InstanceRole, N_ROUNDS, TXBODY_MERKLE_LAYOUT,
};
use crate::airs::tx_body_spine::{
    spine_n_cols, txv_live_mask_col, SPINE_LOG_ROWS, TXV_COL_OFFSET, TX_BODY_MERKLE_COL_OFFSET,
};
use crate::airs::tx_validity::TxValidityCol;
use crate::composition::registry::Cell;
use noid_tx::{MAX_INPUTS, MAX_OUTPUTS};

/// Layout descriptor for an embedded
/// [`crate::airs::tx_body_spine::TxBodySpineComposite`] block inside a
/// larger outer composite trace.
///
/// Construction does not allocate or run any AIR work — it only
/// captures the outer column offset at which the spine block starts
/// and exposes typed accessors. Validation ensures the spine block
/// fits inside the caller-claimed outer column count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpineEmbeddingLayout {
    /// Outer column at which the spine block begins. Inside the
    /// block, columns follow the spine's native layout:
    ///
    /// ```text
    ///   block_base + TXV_COL_OFFSET ..
    ///                  block_base + TX_VALIDITY_3B4_PINNED_N_COLS
    ///       — TxValidity sub-AIR (cols 0..70-ish)
    ///   block_base + TX_BODY_MERKLE_COL_OFFSET ..
    ///                  block_base + TX_BODY_MERKLE_COL_OFFSET + merkle_n
    ///       — TxBodyMerkle sub-AIR
    ///   block_base + txv_live_mask_col()
    ///       — TxvLiveMask programme column
    /// ```
    block_base: usize,
}

/// Errors from layout construction. Kept narrow — the only failure
/// mode is "claimed outer column count cannot fit the spine block at
/// the requested base".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpineLayoutError {
    /// `block_base + spine_n_cols() > outer_n_cols`.
    OuterTooNarrow {
        block_base: usize,
        spine_width: usize,
        outer_n_cols: usize,
    },
    /// `outer_log_rows < SPINE_LOG_ROWS` — outer trace cannot host the
    /// 2^13-row spine. PR B must lift `outer_log_rows` ≥ 13.
    OuterTooShort {
        outer_log_rows: usize,
        required: usize,
    },
}

impl SpineEmbeddingLayout {
    /// Construct a layout placing the spine block at `block_base`
    /// inside an outer composite of `outer_n_cols` columns and
    /// `outer_log_rows` log-rows. Validates fit; returns
    /// [`SpineLayoutError`] on overflow.
    pub fn new(
        block_base: usize,
        outer_n_cols: usize,
        outer_log_rows: usize,
    ) -> Result<Self, SpineLayoutError> {
        let spine_width = spine_n_cols();
        if block_base + spine_width > outer_n_cols {
            return Err(SpineLayoutError::OuterTooNarrow {
                block_base,
                spine_width,
                outer_n_cols,
            });
        }
        if outer_log_rows < SPINE_LOG_ROWS {
            return Err(SpineLayoutError::OuterTooShort {
                outer_log_rows,
                required: SPINE_LOG_ROWS,
            });
        }
        Ok(Self { block_base })
    }

    /// Outer column at which the spine block starts.
    pub fn block_base(&self) -> usize {
        self.block_base
    }

    /// Spine block width (composite-internal column count).
    pub fn spine_width(&self) -> usize {
        spine_n_cols()
    }

    /// Outer column one past the end of the spine block. PR B's
    /// caller appends further blocks starting here.
    pub fn block_end(&self) -> usize {
        self.block_base + self.spine_width()
    }

    /// Required outer log-rows. Spine demands `≥ SPINE_LOG_ROWS = 13`.
    pub fn required_outer_log_rows(&self) -> usize {
        SPINE_LOG_ROWS
    }

    /// Outer column at which the embedded `TxValidityAir` block begins
    /// (= `block_base`, since `TXV_COL_OFFSET = 0`). Exposed for
    /// readability at call sites that operate on the TxValidity
    /// sub-block.
    pub fn txv_block_outer_offset(&self) -> usize {
        self.block_base + TXV_COL_OFFSET
    }

    /// Outer column at which the embedded `TxBodyMerkle` block begins.
    pub fn merkle_block_outer_offset(&self) -> usize {
        self.block_base + TX_BODY_MERKLE_COL_OFFSET
    }

    /// Outer column of the `TxvLiveMask` programme.
    pub fn txv_live_mask_outer_col(&self) -> usize {
        self.block_base + txv_live_mask_col()
    }

    // -----------------------------------------------------------------
    // T2a dst — auth-tag (input i)
    // -----------------------------------------------------------------

    /// Outer cell carrying `TxValidityCol::AuthTagHi[row = input]`.
    /// Used as the **T2a high-lane bridge dst** in PR B, replacing the
    /// 5.5-era `pinned_row_programme(auth_tag_hi)` `PublicColumn`.
    pub fn auth_tag_hi_outer_cell(&self, input: usize) -> Cell {
        assert!(
            input < MAX_INPUTS,
            "input {input} out of range [0, {MAX_INPUTS})"
        );
        Cell::new(
            self.txv_block_outer_offset() + TxValidityCol::AuthTagHi.index(),
            input,
        )
    }

    /// Outer cell carrying `TxValidityCol::AuthTagLo[row = input]`.
    pub fn auth_tag_lo_outer_cell(&self, input: usize) -> Cell {
        assert!(
            input < MAX_INPUTS,
            "input {input} out of range [0, {MAX_INPUTS})"
        );
        Cell::new(
            self.txv_block_outer_offset() + TxValidityCol::AuthTagLo.index(),
            input,
        )
    }

    // -----------------------------------------------------------------
    // Output leaf absorb row — output leaf payload (output j)
    // -----------------------------------------------------------------

    /// Outer cell carrying the `OutputLeafPermA` lane-`lane` payload
    /// for output `j`. Row is the PermA `slot_base_row` derived from
    /// `build_instance_layout()`; column is the canonical leaf-rate
    /// payload column for `lane` (E.4.c-1: column does not depend on
    /// slot). This cell is pinned directly by
    /// `TxBodyMerkleAir`'s `o1_payload_programme` public column,
    /// closing the output-leaf-absorb binding.
    pub fn output_leaf_a_outer_cell(&self, output: usize, lane: usize) -> Cell {
        assert!(
            output < MAX_OUTPUTS,
            "output {output} out of range [0, {MAX_OUTPUTS})"
        );
        assert!(lane < 2, "lane {lane} must be 0 or 1");
        let row = output_leaf_perm_a_row(output);
        let col = self.merkle_block_outer_offset() + leaf_rate_payload_col(0, lane);
        Cell::new(col, row)
    }

    // -----------------------------------------------------------------
    // T2b dst — tx_body_hash via Merkle wrap-output (lane)
    // -----------------------------------------------------------------

    /// Outer cell carrying `tx_body_hash[lane]` at the wrap-perm
    /// output row inside the embedded `TxBodyMerkle` block. This is
    /// the **single canonical origin** of `tx_body_hash` per the
    /// audit § 1 / § 6.2 invariants and the
    /// `stage_5_7_invariant_tx_body_hash_single_origin` regression
    /// test.
    ///
    /// PR C will use this as the **T2b bridge dst**, replacing the
    /// 5.5-era `pre_s_b_dst` cells whose programmes carried
    /// `tx_body_hash` directly. After PR C, only the wrap-output cell
    /// itself carries `tx_body_hash`; bridges link consumers to it
    /// via cross-row equality.
    pub fn wrap_output_outer_cell(&self, lane: usize) -> Cell {
        assert!(lane < 2, "lane {lane} must be 0 or 1");
        let row = merkle_wrap_output_row();
        let col = self.merkle_block_outer_offset() + TXBODY_MERKLE_LAYOUT.s + lane;
        Cell::new(col, row)
    }
}

// ---------------------------------------------------------------------
// Layout-derived row helpers
// ---------------------------------------------------------------------

/// Canonical row inside the Merkle block at which output `j`'s
/// `OutputLeafPermA` permutation absorbs `[value, owner_hi]`. Derived
/// from `build_instance_layout()`; bijection guaranteed by the
/// pre-5.7 hardening.
fn output_leaf_perm_a_row(output: usize) -> usize {
    let layout = build_instance_layout();
    for meta in layout.iter() {
        if let InstanceRole::OutputLeafPermA { leaf_idx } = meta.role {
            if leaf_idx as usize == output {
                return meta.slot_base_row;
            }
        }
    }
    panic!("output {output}: no OutputLeafPermA in layout — Merkle layout drifted");
}

/// Canonical row inside the Merkle block at which the wrap-perm
/// output `(s[0..1])` lives. This is the single ground-truth row
/// for `tx_body_hash`.
fn merkle_wrap_output_row() -> usize {
    let layout = build_instance_layout();
    for meta in layout.iter() {
        if matches!(meta.role, InstanceRole::WrapPerm) {
            return meta.slot_base_row + N_ROUNDS;
        }
    }
    panic!("no WrapPerm in layout — Merkle layout drifted");
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::airs::tx_body_spine::merkle_band_width;
    use crate::airs::tx_body_spine::{SPINE_LOG_ROWS, TXV_COL_OFFSET, TX_BODY_MERKLE_COL_OFFSET};
    use crate::airs::tx_validity::TX_VALIDITY_3B4_PINNED_N_COLS;

    fn mk(base: usize) -> SpineEmbeddingLayout {
        SpineEmbeddingLayout::new(base, base + spine_n_cols(), SPINE_LOG_ROWS)
            .expect("layout fits exactly")
    }

    #[test]
    fn new_rejects_outer_too_narrow() {
        let err = SpineEmbeddingLayout::new(0, spine_n_cols() - 1, SPINE_LOG_ROWS).unwrap_err();
        assert!(matches!(err, SpineLayoutError::OuterTooNarrow { .. }));
    }

    #[test]
    fn new_rejects_outer_too_short() {
        let err = SpineEmbeddingLayout::new(0, spine_n_cols(), SPINE_LOG_ROWS - 1).unwrap_err();
        assert!(matches!(err, SpineLayoutError::OuterTooShort { .. }));
    }

    #[test]
    fn new_accepts_exact_fit() {
        let layout = mk(0);
        assert_eq!(layout.block_base(), 0);
        assert_eq!(layout.block_end(), spine_n_cols());
        assert_eq!(layout.required_outer_log_rows(), SPINE_LOG_ROWS);
    }

    #[test]
    fn block_extents_track_base() {
        let layout = mk(42);
        assert_eq!(layout.block_base(), 42);
        assert_eq!(layout.block_end(), 42 + spine_n_cols());
        assert_eq!(layout.txv_block_outer_offset(), 42 + TXV_COL_OFFSET);
        assert_eq!(
            layout.merkle_block_outer_offset(),
            42 + TX_BODY_MERKLE_COL_OFFSET
        );
        assert_eq!(layout.txv_live_mask_outer_col(), 42 + txv_live_mask_col());
    }

    #[test]
    fn auth_tag_outer_cells_track_block_base_and_input() {
        let layout = mk(100);
        for input in 0..MAX_INPUTS {
            let hi = layout.auth_tag_hi_outer_cell(input);
            let lo = layout.auth_tag_lo_outer_cell(input);
            assert_eq!(hi.col, 100 + TxValidityCol::AuthTagHi.index());
            assert_eq!(lo.col, 100 + TxValidityCol::AuthTagLo.index());
            assert_eq!(hi.row, input);
            assert_eq!(lo.row, input);
            // hi/lo cols are adjacent (8 / 9 by audit § 2 invariant).
            assert_eq!(lo.col, hi.col + 1);
        }
    }

    #[test]
    #[should_panic(expected = "out of range")]
    fn auth_tag_hi_panics_on_oob_input() {
        let layout = mk(0);
        let _ = layout.auth_tag_hi_outer_cell(MAX_INPUTS);
    }

    #[test]
    fn output_leaf_a_outer_cells_share_payload_column_per_lane() {
        let layout = mk(7);
        // Column for both lanes is shared across all outputs (E.4.c-1
        // collapse). Rows must be pairwise distinct (bijection
        // guarded by `TxBodyMerkleCols::from_layout`).
        let lane0_col = layout.output_leaf_a_outer_cell(0, 0).col;
        let lane1_col = layout.output_leaf_a_outer_cell(0, 1).col;
        assert_eq!(lane1_col, lane0_col + 1);
        let mut seen_rows = std::collections::HashSet::new();
        for output in 0..MAX_OUTPUTS {
            let cell0 = layout.output_leaf_a_outer_cell(output, 0);
            let cell1 = layout.output_leaf_a_outer_cell(output, 1);
            assert_eq!(cell0.col, lane0_col);
            assert_eq!(cell1.col, lane1_col);
            assert_eq!(cell0.row, cell1.row);
            assert!(
                seen_rows.insert(cell0.row),
                "output rows must be a bijection — collision at output {output}"
            );
        }
    }

    #[test]
    #[should_panic(expected = "out of range")]
    fn output_leaf_a_panics_on_oob_output() {
        let layout = mk(0);
        let _ = layout.output_leaf_a_outer_cell(MAX_OUTPUTS, 0);
    }

    #[test]
    #[should_panic(expected = "must be 0 or 1")]
    fn output_leaf_a_panics_on_oob_lane() {
        let layout = mk(0);
        let _ = layout.output_leaf_a_outer_cell(0, 2);
    }

    #[test]
    fn wrap_output_outer_cell_lanes_adjacent() {
        let layout = mk(11);
        let hi = layout.wrap_output_outer_cell(0);
        let lo = layout.wrap_output_outer_cell(1);
        assert_eq!(lo.col, hi.col + 1);
        assert_eq!(hi.row, lo.row);
        // Wrap-output lives strictly past the leaf-payload rows for
        // every output, so it cannot collide with an output-leaf
        // absorb row.
        for output in 0..MAX_OUTPUTS {
            let leaf_row = layout.output_leaf_a_outer_cell(output, 0).row;
            assert_ne!(
                hi.row, leaf_row,
                "wrap-output row collides with output {output} leaf-A row"
            );
        }
    }

    #[test]
    fn layout_is_stable_across_calls() {
        let a = mk(13);
        let b = mk(13);
        assert_eq!(a, b);
        for input in 0..MAX_INPUTS {
            assert_eq!(
                a.auth_tag_hi_outer_cell(input),
                b.auth_tag_hi_outer_cell(input)
            );
            assert_eq!(
                a.auth_tag_lo_outer_cell(input),
                b.auth_tag_lo_outer_cell(input)
            );
        }
        for output in 0..MAX_OUTPUTS {
            for lane in 0..2 {
                assert_eq!(
                    a.output_leaf_a_outer_cell(output, lane),
                    b.output_leaf_a_outer_cell(output, lane)
                );
            }
        }
        for lane in 0..2 {
            assert_eq!(
                a.wrap_output_outer_cell(lane),
                b.wrap_output_outer_cell(lane)
            );
        }
    }

    #[test]
    fn spine_width_matches_block_extents() {
        // The spine width is exactly the published per-block extent
        // sum — TxValidity (cols 0..TX_VALIDITY_3B4_PINNED_N_COLS),
        // TxBodyMerkle (cols starting at TX_VALIDITY_3B4_PINNED_N_COLS),
        // plus a single TxvLiveMask column past the Merkle block.
        let merkle_n = merkle_band_width();
        assert_eq!(spine_n_cols(), TX_VALIDITY_3B4_PINNED_N_COLS + merkle_n + 1);
    }
}
