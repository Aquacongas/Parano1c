// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Stage 5.6 — `HLeafBlock`: a single `HLeafAir` instance embedded into
//! an outer composite trace via [`RowWindowWrapper`], plus one bridge
//! family:
//!
//! - **T3** — output squeeze → output-leaf-payload cell, per lane.
//!   Source: `HLeafAir.s_C[lane]@HLEAF_OUTPUT_ROW` for
//!   `lane ∈ {hi, lo}`. Destination: caller-supplied outer cell
//!   (typically a per-output `(col, row)` pair carrying the declared
//!   leaf hash for output `j`). One bridge per lane, dst is unique per
//!   output.
//!
//! Stage 5.7 re-points the destinations at `TxBodyMerkleAir`'s E.4.c
//! rate-absorb payload columns inside `TxBodySpineComposite` — the
//! bridge contract is unchanged.
//!
//! # Column budget (per block)
//!
//! | span                                          | role                         |
//! |-----------------------------------------------|------------------------------|
//! | `col_offset .. col_offset + HLEAF_N_COLS`     | HLeaf sub-AIR trace columns  |
//! | `window_indicator_col`                        | RowWindowWrapper indicator   |
//! | `t3_hi` 4 cols                                | T3 hi-lane bridge            |
//! | `t3_lo` 4 cols                                | T3 lo-lane bridge            |
//!
//! The sub-AIR is embedded under [`WrapPolicy::MaskOff`] because
//! `HLeafAir::requires_true_cyclic_wrap()` is `false`.

use crate::airs::hleaf::{
    build_hleaf_trace, HLeafAir, HLEAF_LAYOUT_C, HLEAF_LOG_ROWS, HLEAF_N_COLS, HLEAF_N_ROWS,
    HLEAF_OUTPUT_ROW,
};
use crate::composition::row_window::{
    InnerAirView, RowWindowParams, RowWindowWiring, RowWindowWrapper, WrapPolicy,
};
use crate::composition::t1_owner_tie::{
    emit_t1_lane, write_t1_lane_bridge, LaneBridgeBudget, LaneBridgeTie,
};
use crate::gates::const_column::PublicColumn;
use crate::{Air, Constraint};
use noid_core::Block128;

/// Column-budget descriptor for one embedded HLeaf block.
#[derive(Debug, Clone, Copy)]
pub struct HLeafBlockColumns {
    /// Start column of the HLeaf sub-AIR.
    pub col_offset: usize,
    /// Outer column reserved for the RowWindowWrapper's window indicator.
    pub window_indicator_col: usize,
    /// T3 hi-lane bridge budget (HLeaf squeeze hi → leaf_hi dst).
    pub t3_hi_budget: LaneBridgeBudget,
    /// T3 lo-lane bridge budget (HLeaf squeeze lo → leaf_lo dst).
    pub t3_lo_budget: LaneBridgeBudget,
}

/// Destination cells for T3. Per-output cells carrying the declared
/// leaf hash `(leaf_hi, leaf_lo)` for output `j`.
#[derive(Debug, Clone, Copy)]
pub struct HLeafBlockTargets {
    pub leaf_hi_dst_col: usize,
    pub leaf_hi_dst_row: usize,
    pub leaf_lo_dst_col: usize,
    pub leaf_lo_dst_row: usize,
}

/// Parameters for a single [`emit_hleaf_block`] call.
#[derive(Debug, Clone, Copy)]
pub struct HLeafBlockParams {
    pub cols: HLeafBlockColumns,
    pub row_window_start: usize,
    pub outer_n_cols: usize,
    pub outer_log_rows: usize,
    /// Public output fields `[slot, value, owner_hi, owner_lo]` —
    /// pinned via the HLeaf A-seed pin and B-carry absorb at AIR
    /// construction time.
    pub fields: [Block128; 4],
    pub targets: HLeafBlockTargets,
}

/// Output of [`emit_hleaf_block`].
pub struct HLeafBlockWiring {
    pub constraints: Vec<Box<dyn Constraint>>,
    pub public_columns: Vec<PublicColumn>,
    /// Absolute `(col, row)` of the squeezed leaf hi lane.
    pub squeezed_leaf_hi_cell: (usize, usize),
    pub squeezed_leaf_lo_cell: (usize, usize),
}

/// Emit the full wiring for one embedded HLeaf block: sub-AIR via
/// RowWindowWrapper + two lane bridges (T3 hi/lo).
pub fn emit_hleaf_block(p: HLeafBlockParams) -> HLeafBlockWiring {
    let outer_n_rows = 1usize << p.outer_log_rows;
    assert!(
        p.row_window_start + HLEAF_N_ROWS <= outer_n_rows,
        "emit_hleaf_block: window [{}, {}) exceeds outer rows {}",
        p.row_window_start,
        p.row_window_start + HLEAF_N_ROWS,
        outer_n_rows,
    );

    // 1) Wrap the sub-AIR. `new_no_output_pin` keeps the squeezed leaf
    //    cells as free witness — T3 ties them at composite level.
    let air = HLeafAir::new_no_output_pin(p.fields);
    let requires_cyclic = air.requires_true_cyclic_wrap();
    let (inner_n_cols, constraints_inner, publics_inner) = air.into_parts();
    assert_eq!(inner_n_cols, HLEAF_N_COLS);
    let inner_view = InnerAirView {
        inner_n_cols: HLEAF_N_COLS,
        inner_log_rows: HLEAF_LOG_ROWS,
        constraints: constraints_inner,
        public_columns: publics_inner,
        requires_true_cyclic_wrap: requires_cyclic,
    };
    let window_params = RowWindowParams {
        col_offset: p.cols.col_offset,
        outer_n_cols: p.outer_n_cols,
        outer_log_rows: p.outer_log_rows,
        row_window_start: p.row_window_start,
        row_window_end: p.row_window_start + HLEAF_N_ROWS,
        window_indicator_col: p.cols.window_indicator_col,
        policy: WrapPolicy::MaskOff,
        terminator_pin_cols: Vec::new(),
    };
    let RowWindowWiring {
        mut constraints,
        mut public_columns,
    } = RowWindowWrapper::wrap(inner_view, window_params);

    // 2) Outer-trace absolute cells.
    let squeezed_hi_col = p.cols.col_offset + HLEAF_LAYOUT_C.s;
    let squeezed_lo_col = p.cols.col_offset + HLEAF_LAYOUT_C.s + 1;
    let squeezed_row = p.row_window_start + HLEAF_OUTPUT_ROW;

    // 3) T3 hi-lane bridge.
    let t3_hi_tie = LaneBridgeTie {
        src_col: squeezed_hi_col,
        src_row: squeezed_row,
        dst_col: p.targets.leaf_hi_dst_col,
        dst_row: p.targets.leaf_hi_dst_row,
    };
    let wiring = emit_t1_lane(t3_hi_tie, p.cols.t3_hi_budget, outer_n_rows);
    public_columns.extend(wiring.public_columns);
    constraints.extend(wiring.constraints);

    // 4) T3 lo-lane bridge.
    let t3_lo_tie = LaneBridgeTie {
        src_col: squeezed_lo_col,
        src_row: squeezed_row,
        dst_col: p.targets.leaf_lo_dst_col,
        dst_row: p.targets.leaf_lo_dst_row,
    };
    let wiring = emit_t1_lane(t3_lo_tie, p.cols.t3_lo_budget, outer_n_rows);
    public_columns.extend(wiring.public_columns);
    constraints.extend(wiring.constraints);

    HLeafBlockWiring {
        constraints,
        public_columns,
        squeezed_leaf_hi_cell: (squeezed_hi_col, squeezed_row),
        squeezed_leaf_lo_cell: (squeezed_lo_col, squeezed_row),
    }
}

/// Result of [`write_hleaf_block_trace`].
pub struct HLeafBlockTraceCells {
    pub leaf: [Block128; 2],
}

/// Populate the outer trace with an honest HLeaf block plus matching
/// T3 bridge columns. Expects the caller to pre-allocate `cols`
/// ZERO-initialised to the full outer column × row count.
pub fn write_hleaf_block_trace(
    cols: &mut [Vec<Block128>],
    p: HLeafBlockParams,
) -> HLeafBlockTraceCells {
    let outer_n_rows = 1usize << p.outer_log_rows;

    // 1) HLeaf sub-trace into the column window.
    let inner_cols = build_hleaf_trace(p.fields);
    assert_eq!(inner_cols.len(), HLEAF_N_COLS);
    for (i, src) in inner_cols.into_iter().enumerate() {
        assert_eq!(src.len(), HLEAF_N_ROWS);
        let dst = &mut cols[p.cols.col_offset + i];
        for (r, v) in src.into_iter().enumerate() {
            dst[p.row_window_start + r] = v;
        }
    }

    // 2) Extract squeezed leaf cells.
    let squeezed_hi_col = p.cols.col_offset + HLEAF_LAYOUT_C.s;
    let squeezed_lo_col = p.cols.col_offset + HLEAF_LAYOUT_C.s + 1;
    let squeezed_row = p.row_window_start + HLEAF_OUTPUT_ROW;
    let leaf_hi = cols[squeezed_hi_col][squeezed_row];
    let leaf_lo = cols[squeezed_lo_col][squeezed_row];

    // 3) Plant destination cells.
    cols[p.targets.leaf_hi_dst_col][p.targets.leaf_hi_dst_row] = leaf_hi;
    cols[p.targets.leaf_lo_dst_col][p.targets.leaf_lo_dst_row] = leaf_lo;

    // 4) Bridge column witness values.
    let t3_hi_tie = LaneBridgeTie {
        src_col: squeezed_hi_col,
        src_row: squeezed_row,
        dst_col: p.targets.leaf_hi_dst_col,
        dst_row: p.targets.leaf_hi_dst_row,
    };
    write_t1_lane_bridge(cols, t3_hi_tie, p.cols.t3_hi_budget, outer_n_rows, leaf_hi);

    let t3_lo_tie = LaneBridgeTie {
        src_col: squeezed_lo_col,
        src_row: squeezed_row,
        dst_col: p.targets.leaf_lo_dst_col,
        dst_row: p.targets.leaf_lo_dst_row,
    };
    write_t1_lane_bridge(cols, t3_lo_tie, p.cols.t3_lo_budget, outer_n_rows, leaf_lo);

    HLeafBlockTraceCells {
        leaf: [leaf_hi, leaf_lo],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::airs::hleaf::{extract_hleaf_output, HLEAF_LAYOUT_A};
    use crate::{Air, CompositeAir, Trace};
    use noid_core::TowerField;

    const OUTER_LOG_ROWS: usize = HLEAF_LOG_ROWS + 1; // 512 rows.
    const OUTER_N_ROWS: usize = 1 << OUTER_LOG_ROWS;
    const ROW_WINDOW_START: usize = 0;

    // Column layout for the scaffold:
    //   0 .. HLEAF_N_COLS                       HLeaf sub-AIR
    //   HLEAF_N_COLS                              window indicator
    //   HLEAF_N_COLS + 1..+4                      T3 hi (bridge + 3 ind)
    //   HLEAF_N_COLS + 5..+8                      T3 lo
    //   HLEAF_N_COLS + 9                          leaf_hi dst column
    //   HLEAF_N_COLS + 10                         leaf_lo dst column
    const WINDOW_INDICATOR_COL: usize = HLEAF_N_COLS;
    const T3_HI_BRIDGE: usize = HLEAF_N_COLS + 1;
    const T3_HI_SRC: usize = HLEAF_N_COLS + 2;
    const T3_HI_DST: usize = HLEAF_N_COLS + 3;
    const T3_HI_TRANS: usize = HLEAF_N_COLS + 4;
    const T3_LO_BRIDGE: usize = HLEAF_N_COLS + 5;
    const T3_LO_SRC: usize = HLEAF_N_COLS + 6;
    const T3_LO_DST: usize = HLEAF_N_COLS + 7;
    const T3_LO_TRANS: usize = HLEAF_N_COLS + 8;
    const LEAF_HI_DST_COL: usize = HLEAF_N_COLS + 9;
    const LEAF_LO_DST_COL: usize = HLEAF_N_COLS + 10;
    const OUTER_N_COLS: usize = HLEAF_N_COLS + 11;

    const LEAF_HI_DST_ROW: usize = HLEAF_N_ROWS + 3;
    const LEAF_LO_DST_ROW: usize = HLEAF_N_ROWS + 5;

    fn mk_fields4(seed: u128) -> [Block128; 4] {
        let s = seed.wrapping_mul(0x9E3779B97F4A7C15);
        [
            Block128::from(s ^ 0x1111_1111_1111_1111),
            Block128::from(s.wrapping_add(1) ^ 0x2222_2222_2222_2222),
            Block128::from(s.wrapping_add(2) ^ 0x3333_3333_3333_3333),
            Block128::from(s.wrapping_add(3) ^ 0x4444_4444_4444_4444),
        ]
    }

    fn params(fields: [Block128; 4]) -> HLeafBlockParams {
        HLeafBlockParams {
            cols: HLeafBlockColumns {
                col_offset: 0,
                window_indicator_col: WINDOW_INDICATOR_COL,
                t3_hi_budget: LaneBridgeBudget {
                    bridge_col: T3_HI_BRIDGE,
                    src_indicator_col: T3_HI_SRC,
                    dst_indicator_col: T3_HI_DST,
                    transition_indicator_col: T3_HI_TRANS,
                },
                t3_lo_budget: LaneBridgeBudget {
                    bridge_col: T3_LO_BRIDGE,
                    src_indicator_col: T3_LO_SRC,
                    dst_indicator_col: T3_LO_DST,
                    transition_indicator_col: T3_LO_TRANS,
                },
            },
            row_window_start: ROW_WINDOW_START,
            outer_n_cols: OUTER_N_COLS,
            outer_log_rows: OUTER_LOG_ROWS,
            fields,
            targets: HLeafBlockTargets {
                leaf_hi_dst_col: LEAF_HI_DST_COL,
                leaf_hi_dst_row: LEAF_HI_DST_ROW,
                leaf_lo_dst_col: LEAF_LO_DST_COL,
                leaf_lo_dst_row: LEAF_LO_DST_ROW,
            },
        }
    }

    fn build(fields: [Block128; 4]) -> (CompositeAir, Vec<Vec<Block128>>, HLeafBlockParams) {
        let p = params(fields);
        let w = emit_hleaf_block(p);
        let air = CompositeAir::from_parts_with_publics(
            OUTER_LOG_ROWS,
            OUTER_N_COLS,
            w.constraints,
            w.public_columns,
        );
        let mut cols: Vec<Vec<Block128>> = (0..OUTER_N_COLS)
            .map(|_| vec![Block128::ZERO; OUTER_N_ROWS])
            .collect();
        let _ = write_hleaf_block_trace(&mut cols, p);
        for pc in air.public_columns() {
            cols[pc.col] = pc.values.clone();
        }
        (air, cols, p)
    }

    #[test]
    fn honest_accepts() {
        let (air, cols, _) = build(mk_fields4(0x1234));
        assert!(air.check(&Trace::new(cols)));
    }

    #[test]
    fn squeeze_matches_native() {
        let fields = mk_fields4(0xCAFE);
        let (_air, cols, _p) = build(fields);
        let native = extract_hleaf_output(&build_hleaf_trace(fields));
        assert_eq!(
            cols[HLEAF_LAYOUT_C.s][ROW_WINDOW_START + HLEAF_OUTPUT_ROW],
            native[0]
        );
        assert_eq!(
            cols[HLEAF_LAYOUT_C.s + 1][ROW_WINDOW_START + HLEAF_OUTPUT_ROW],
            native[1]
        );
    }

    #[test]
    fn hleaf_interior_tamper_rejects() {
        let (air, mut cols, _) = build(mk_fields4(0x5678));
        cols[HLEAF_LAYOUT_A.sout + 2][ROW_WINDOW_START + 1] =
            cols[HLEAF_LAYOUT_A.sout + 2][ROW_WINDOW_START + 1] + Block128::ONE;
        assert!(!air.check(&Trace::new(cols)));
    }

    #[test]
    fn t3_hi_dst_tamper_rejects() {
        let (air, mut cols, _) = build(mk_fields4(0xABCD));
        cols[LEAF_HI_DST_COL][LEAF_HI_DST_ROW] =
            cols[LEAF_HI_DST_COL][LEAF_HI_DST_ROW] + Block128::ONE;
        assert!(!air.check(&Trace::new(cols)));
    }

    #[test]
    fn t3_lo_dst_tamper_rejects() {
        let (air, mut cols, _) = build(mk_fields4(0xBEEF));
        cols[LEAF_LO_DST_COL][LEAF_LO_DST_ROW] =
            cols[LEAF_LO_DST_COL][LEAF_LO_DST_ROW] + Block128::ONE;
        assert!(!air.check(&Trace::new(cols)));
    }

    #[test]
    fn t3_hi_bridge_interior_tamper_rejects() {
        let (air, mut cols, _) = build(mk_fields4(0x5555));
        let squeezed_row = ROW_WINDOW_START + HLEAF_OUTPUT_ROW;
        let mid = (squeezed_row + LEAF_HI_DST_ROW) / 2;
        cols[T3_HI_BRIDGE][mid] = cols[T3_HI_BRIDGE][mid] + Block128::ONE;
        assert!(!air.check(&Trace::new(cols)));
    }

    #[test]
    fn t3_lo_bridge_interior_tamper_rejects() {
        let (air, mut cols, _) = build(mk_fields4(0x7777));
        let squeezed_row = ROW_WINDOW_START + HLEAF_OUTPUT_ROW;
        let mid = (squeezed_row + LEAF_LO_DST_ROW) / 2;
        cols[T3_LO_BRIDGE][mid] = cols[T3_LO_BRIDGE][mid] + Block128::ONE;
        assert!(!air.check(&Trace::new(cols)));
    }

    #[test]
    fn outside_window_hleaf_edit_accepted() {
        // MaskOff silences HLeaf constraints outside the window.
        let (air, mut cols, _) = build(mk_fields4(0x9999));
        let far_row = ROW_WINDOW_START + HLEAF_N_ROWS + 5;
        cols[HLEAF_LAYOUT_A.sout + 2][far_row] = Block128::from(0xDEAD_u128);
        assert!(air.check(&Trace::new(cols)));
    }
}
