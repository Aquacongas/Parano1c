// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Stage 5.4 — `HAddrBlock`: a single `HAddrAir` instance embedded into
//! an outer composite trace via [`RowWindowWrapper`], plus a T1 bridge
//! pair tying the squeezed `(addr_hi, addr_lo)` to a pair of owner-lane
//! destination cells elsewhere in the outer trace.
//!
//! This is the reusable unit from which the full Stage 5.4 composite
//! (`HAddrAir × N_INPUTS` all tied to `FriStateOpenAir`'s owner columns)
//! is assembled. Isolating a single instance here lets us lock down the
//! embedding shape and tamper-matrix semantics without entangling the
//! larger composite column-budget work.
//!
//! # Column budget (per block)
//!
//! Given the caller-supplied `col_offset` and `row_window_start`:
//!
//! | span                                                | role                                        |
//! |-----------------------------------------------------|---------------------------------------------|
//! | `col_offset .. col_offset + HADDR_N_COLS`           | HAddr sub-AIR trace columns                 |
//! | `window_indicator_col`                              | RowWindowWrapper multi-hot indicator        |
//! | `t1_hi.bridge_col` + 3 indicator cols               | hi-lane bridge (4 cols)                     |
//! | `t1_lo.bridge_col` + 3 indicator cols               | lo-lane bridge (4 cols)                     |
//!
//! The sub-AIR is embedded under [`WrapPolicy::MaskOff`] because
//! `HAddrAir::requires_true_cyclic_wrap()` is `false`.

use crate::airs::haddr::{
    build_haddr_trace, HAddrAir, HADDR_LAYOUT_B, HADDR_LOG_ROWS, HADDR_N_COLS, HADDR_N_ROWS,
    HADDR_OUTPUT_ROW,
};
use crate::composition::row_window::{
    InnerAirView, RowWindowParams, RowWindowWiring, RowWindowWrapper, WrapPolicy,
};
use crate::composition::t1_owner_tie::{
    emit_t1_lane, write_t1_lane_bridge, T1LaneColumnBudget, T1LaneTie,
};
use crate::gates::const_column::PublicColumn;
use crate::{Air, Constraint};
use noid_core::Block128;

/// Column-budget descriptor for one embedded HAddr block.
#[derive(Debug, Clone, Copy)]
pub struct HAddrBlockColumns {
    /// Start column of the HAddr sub-AIR.
    pub col_offset: usize,
    /// Outer column reserved for the RowWindowWrapper's window indicator.
    pub window_indicator_col: usize,
    /// T1 hi-lane bridge budget (4 outer cols). `src` is the HAddr
    /// squeeze; `dst` is caller-chosen.
    pub t1_hi_budget: T1LaneColumnBudget,
    /// T1 lo-lane bridge budget (4 outer cols).
    pub t1_lo_budget: T1LaneColumnBudget,
}

/// T1 destination cells — the outer-trace owner lanes the squeezed
/// address ties to. Caller decides which sub-AIR / row these live on.
#[derive(Debug, Clone, Copy)]
pub struct HAddrBlockT1Targets {
    pub owner_hi_dst_col: usize,
    pub owner_hi_dst_row: usize,
    pub owner_lo_dst_col: usize,
    pub owner_lo_dst_row: usize,
}

/// Parameters for a single [`emit_haddr_block`] call.
#[derive(Debug, Clone, Copy)]
pub struct HAddrBlockParams {
    pub cols: HAddrBlockColumns,
    pub row_window_start: usize,
    pub outer_n_cols: usize,
    pub outer_log_rows: usize,
    pub t1_targets: HAddrBlockT1Targets,
}

/// Output of [`emit_haddr_block`].
pub struct HAddrBlockWiring {
    pub constraints: Vec<Box<dyn Constraint>>,
    pub public_columns: Vec<PublicColumn>,
    /// Absolute `(col, row)` of the squeezed address hi lane.
    pub squeezed_hi_cell: (usize, usize),
    /// Absolute `(col, row)` of the squeezed address lo lane.
    pub squeezed_lo_cell: (usize, usize),
}

/// Emit the full wiring for one embedded HAddr block: sub-AIR via
/// RowWindowWrapper + two T1 lane bridges.
pub fn emit_haddr_block(p: HAddrBlockParams) -> HAddrBlockWiring {
    let outer_n_rows = 1usize << p.outer_log_rows;
    assert!(
        p.row_window_start + HADDR_N_ROWS <= outer_n_rows,
        "emit_haddr_block: window [{}, {}) exceeds outer rows {}",
        p.row_window_start,
        p.row_window_start + HADDR_N_ROWS,
        outer_n_rows,
    );

    // 1) Wrap the sub-AIR.
    let air = HAddrAir::new_no_output_pin();
    let requires_cyclic = air.requires_true_cyclic_wrap();
    let (inner_n_cols, constraints_inner, publics_inner) = air.into_parts();
    assert_eq!(inner_n_cols, HADDR_N_COLS);
    let inner_view = InnerAirView {
        inner_n_cols: HADDR_N_COLS,
        inner_log_rows: HADDR_LOG_ROWS,
        constraints: constraints_inner,
        public_columns: publics_inner,
        requires_true_cyclic_wrap: requires_cyclic,
    };
    let window_params = RowWindowParams {
        col_offset: p.cols.col_offset,
        outer_n_cols: p.outer_n_cols,
        outer_log_rows: p.outer_log_rows,
        row_window_start: p.row_window_start,
        row_window_end: p.row_window_start + HADDR_N_ROWS,
        window_indicator_col: p.cols.window_indicator_col,
        policy: WrapPolicy::MaskOff,
        terminator_pin_cols: Vec::new(),
    };
    let RowWindowWiring {
        mut constraints,
        mut public_columns,
    } = RowWindowWrapper::wrap(inner_view, window_params);

    // 2) Outer-trace absolute cells of the squeezed hi / lo.
    let squeezed_hi_col = p.cols.col_offset + HADDR_LAYOUT_B.s;
    let squeezed_lo_col = p.cols.col_offset + HADDR_LAYOUT_B.s + 1;
    let squeezed_row = p.row_window_start + HADDR_OUTPUT_ROW;

    // 3) T1 hi-lane bridge: squeezed_hi → owner_hi_dst.
    let hi_tie = T1LaneTie {
        src_col: squeezed_hi_col,
        src_row: squeezed_row,
        dst_col: p.t1_targets.owner_hi_dst_col,
        dst_row: p.t1_targets.owner_hi_dst_row,
    };
    let hi_wiring = emit_t1_lane(hi_tie, p.cols.t1_hi_budget, outer_n_rows);
    public_columns.extend(hi_wiring.public_columns);
    constraints.extend(hi_wiring.constraints);

    // 4) T1 lo-lane bridge: squeezed_lo → owner_lo_dst.
    let lo_tie = T1LaneTie {
        src_col: squeezed_lo_col,
        src_row: squeezed_row,
        dst_col: p.t1_targets.owner_lo_dst_col,
        dst_row: p.t1_targets.owner_lo_dst_row,
    };
    let lo_wiring = emit_t1_lane(lo_tie, p.cols.t1_lo_budget, outer_n_rows);
    public_columns.extend(lo_wiring.public_columns);
    constraints.extend(lo_wiring.constraints);

    HAddrBlockWiring {
        constraints,
        public_columns,
        squeezed_hi_cell: (squeezed_hi_col, squeezed_row),
        squeezed_lo_cell: (squeezed_lo_col, squeezed_row),
    }
}

/// Populate the outer trace with an honest HAddr block plus matching
/// T1 bridge columns. Expects the caller to pre-allocate `cols` with
/// the full outer column count × outer row count (ZERO-initialised).
///
/// After this call the HAddr sub-AIR's block occupies
/// `cols[col_offset..col_offset + HADDR_N_COLS]` on rows
/// `[row_window_start, row_window_start + HADDR_N_ROWS)`. The squeezed
/// address lands at `(squeezed_hi_cell, squeezed_lo_cell)` and the
/// matching dst cells are written, so both bridge ends agree.
pub fn write_haddr_block_trace(
    cols: &mut [Vec<Block128>],
    p: HAddrBlockParams,
    secret: [Block128; 2],
) -> ([Block128; 2], (usize, usize), (usize, usize)) {
    let outer_n_rows = 1usize << p.outer_log_rows;

    // 1) HAddr sub-trace into the column window.
    let inner_cols = build_haddr_trace(secret);
    assert_eq!(inner_cols.len(), HADDR_N_COLS);
    for (i, src) in inner_cols.into_iter().enumerate() {
        assert_eq!(src.len(), HADDR_N_ROWS);
        let dst = &mut cols[p.cols.col_offset + i];
        for (r, v) in src.into_iter().enumerate() {
            dst[p.row_window_start + r] = v;
        }
    }

    // 2) Extract squeezed lanes from the column block we just wrote.
    let squeezed_hi_col = p.cols.col_offset + HADDR_LAYOUT_B.s;
    let squeezed_lo_col = p.cols.col_offset + HADDR_LAYOUT_B.s + 1;
    let squeezed_row = p.row_window_start + HADDR_OUTPUT_ROW;
    let addr_hi = cols[squeezed_hi_col][squeezed_row];
    let addr_lo = cols[squeezed_lo_col][squeezed_row];

    // 3) Plant matching destination cells.
    cols[p.t1_targets.owner_hi_dst_col][p.t1_targets.owner_hi_dst_row] = addr_hi;
    cols[p.t1_targets.owner_lo_dst_col][p.t1_targets.owner_lo_dst_row] = addr_lo;

    // 4) Bridge column values for both lanes.
    let hi_tie = T1LaneTie {
        src_col: squeezed_hi_col,
        src_row: squeezed_row,
        dst_col: p.t1_targets.owner_hi_dst_col,
        dst_row: p.t1_targets.owner_hi_dst_row,
    };
    write_t1_lane_bridge(cols, hi_tie, p.cols.t1_hi_budget, outer_n_rows, addr_hi);
    let lo_tie = T1LaneTie {
        src_col: squeezed_lo_col,
        src_row: squeezed_row,
        dst_col: p.t1_targets.owner_lo_dst_col,
        dst_row: p.t1_targets.owner_lo_dst_row,
    };
    write_t1_lane_bridge(cols, lo_tie, p.cols.t1_lo_budget, outer_n_rows, addr_lo);

    (
        [addr_hi, addr_lo],
        (squeezed_hi_col, squeezed_row),
        (squeezed_lo_col, squeezed_row),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Air, CompositeAir, Trace};
    use noid_core::TowerField;

    const OUTER_LOG_ROWS: usize = HADDR_LOG_ROWS + 1; // 512 rows, window fits twice-over.
    const OUTER_N_ROWS: usize = 1 << OUTER_LOG_ROWS;
    const ROW_WINDOW_START: usize = 0;

    /// Outer column plan used by the tests:
    ///   0 .. HADDR_N_COLS                       HAddr sub-AIR
    ///   HADDR_N_COLS                              window indicator
    ///   HADDR_N_COLS + 1                          hi bridge
    ///   HADDR_N_COLS + 2 .. +5                    hi indicators (src, dst, transition)
    ///   HADDR_N_COLS + 5                          lo bridge
    ///   HADDR_N_COLS + 6 .. +9                    lo indicators
    ///   HADDR_N_COLS + 9                          hi dst column
    ///   HADDR_N_COLS + 10                         lo dst column
    const WINDOW_INDICATOR_COL: usize = HADDR_N_COLS;
    const HI_BRIDGE_COL: usize = HADDR_N_COLS + 1;
    const HI_SRC_IND_COL: usize = HADDR_N_COLS + 2;
    const HI_DST_IND_COL: usize = HADDR_N_COLS + 3;
    const HI_TRANS_IND_COL: usize = HADDR_N_COLS + 4;
    const LO_BRIDGE_COL: usize = HADDR_N_COLS + 5;
    const LO_SRC_IND_COL: usize = HADDR_N_COLS + 6;
    const LO_DST_IND_COL: usize = HADDR_N_COLS + 7;
    const LO_TRANS_IND_COL: usize = HADDR_N_COLS + 8;
    const HI_DST_COL: usize = HADDR_N_COLS + 9;
    const LO_DST_COL: usize = HADDR_N_COLS + 10;
    const OUTER_N_COLS: usize = HADDR_N_COLS + 11;

    const HI_DST_ROW: usize = HADDR_N_ROWS + 3;
    const LO_DST_ROW: usize = HADDR_N_ROWS + 5;

    fn params() -> HAddrBlockParams {
        HAddrBlockParams {
            cols: HAddrBlockColumns {
                col_offset: 0,
                window_indicator_col: WINDOW_INDICATOR_COL,
                t1_hi_budget: T1LaneColumnBudget {
                    bridge_col: HI_BRIDGE_COL,
                    src_indicator_col: HI_SRC_IND_COL,
                    dst_indicator_col: HI_DST_IND_COL,
                    transition_indicator_col: HI_TRANS_IND_COL,
                },
                t1_lo_budget: T1LaneColumnBudget {
                    bridge_col: LO_BRIDGE_COL,
                    src_indicator_col: LO_SRC_IND_COL,
                    dst_indicator_col: LO_DST_IND_COL,
                    transition_indicator_col: LO_TRANS_IND_COL,
                },
            },
            row_window_start: ROW_WINDOW_START,
            outer_n_cols: OUTER_N_COLS,
            outer_log_rows: OUTER_LOG_ROWS,
            t1_targets: HAddrBlockT1Targets {
                owner_hi_dst_col: HI_DST_COL,
                owner_hi_dst_row: HI_DST_ROW,
                owner_lo_dst_col: LO_DST_COL,
                owner_lo_dst_row: LO_DST_ROW,
            },
        }
    }

    fn mk_secret(seed: u128) -> [Block128; 2] {
        let s = seed.wrapping_mul(0x9E3779B97F4A7C15);
        [
            Block128::from(s ^ 0xA5A5_A5A5_A5A5_A5A5),
            Block128::from(s.wrapping_add(1) ^ 0x5A5A_5A5A_5A5A_5A5A),
        ]
    }

    fn build(secret: [Block128; 2]) -> (CompositeAir, Vec<Vec<Block128>>) {
        let p = params();
        let w = emit_haddr_block(p);
        let air = CompositeAir::from_parts_with_publics(
            OUTER_LOG_ROWS,
            OUTER_N_COLS,
            w.constraints,
            w.public_columns,
        );
        let mut cols: Vec<Vec<Block128>> = (0..OUTER_N_COLS)
            .map(|_| vec![Block128::ZERO; OUTER_N_ROWS])
            .collect();
        let _ = write_haddr_block_trace(&mut cols, p, secret);
        // Overwrite every public column with its declared programme so
        // `Air::check`'s exact-match test passes. Equivalent to the
        // skeleton's build_trace final pass.
        for pc in air.public_columns() {
            cols[pc.col] = pc.values.clone();
        }
        (air, cols)
    }

    #[test]
    fn honest_accepts() {
        let (air, cols) = build(mk_secret(0x1234));
        assert!(air.check(&Trace::new(cols)));
    }

    #[test]
    fn haddr_interior_tamper_rejects() {
        let (air, mut cols) = build(mk_secret(0x5678));
        // Flip an interior perm-A sout cell.
        use crate::airs::haddr::HADDR_LAYOUT_A;
        cols[HADDR_LAYOUT_A.sout + 2][ROW_WINDOW_START + 1] =
            cols[HADDR_LAYOUT_A.sout + 2][ROW_WINDOW_START + 1] + Block128::ONE;
        assert!(!air.check(&Trace::new(cols)));
    }

    #[test]
    fn t1_hi_dst_tamper_rejects() {
        let (air, mut cols) = build(mk_secret(0xABCD));
        cols[HI_DST_COL][HI_DST_ROW] = cols[HI_DST_COL][HI_DST_ROW] + Block128::ONE;
        assert!(!air.check(&Trace::new(cols)));
    }

    #[test]
    fn t1_lo_dst_tamper_rejects() {
        let (air, mut cols) = build(mk_secret(0xBEEF));
        cols[LO_DST_COL][LO_DST_ROW] = cols[LO_DST_COL][LO_DST_ROW] + Block128::ONE;
        assert!(!air.check(&Trace::new(cols)));
    }

    #[test]
    fn t1_hi_bridge_interior_tamper_rejects() {
        let (air, mut cols) = build(mk_secret(0xCAFE));
        // Bridge interval = [min(src, dst), max(src, dst)]. Pick a row
        // inside it.
        let squeezed_row = ROW_WINDOW_START + HADDR_OUTPUT_ROW;
        let mid = (squeezed_row + HI_DST_ROW) / 2;
        cols[HI_BRIDGE_COL][mid] = cols[HI_BRIDGE_COL][mid] + Block128::ONE;
        assert!(!air.check(&Trace::new(cols)));
    }

    #[test]
    fn outside_window_haddr_edit_accepted() {
        // MaskOff silences HAddr constraints on outer rows outside the
        // window. Editing an HAddr sub-AIR column at row
        // row_window_start + HADDR_N_ROWS + k must NOT reject.
        let (air, mut cols) = build(mk_secret(0x9999));
        use crate::airs::haddr::HADDR_LAYOUT_A;
        let far_row = ROW_WINDOW_START + HADDR_N_ROWS + 7;
        cols[HADDR_LAYOUT_A.sout + 2][far_row] = Block128::from(0xDEAD_u128);
        assert!(air.check(&Trace::new(cols)));
    }

    #[test]
    fn matches_native_address_derivation() {
        use noid_poseidon2b::primitives::{derive_address, SpendSecret};
        use noid_core::CanonicalSerialize;

        let secret_fields = mk_secret(0x7777_7777);
        let (_air, cols) = build(secret_fields);
        let (hi_col, row) = (HADDR_LAYOUT_B.s, ROW_WINDOW_START + HADDR_OUTPUT_ROW);
        let addr_hi = cols[hi_col][row];
        let addr_lo = cols[hi_col + 1][row];

        let hi_bytes = secret_fields[0].to_bytes();
        let lo_bytes = secret_fields[1].to_bytes();
        let mut secret_bytes = [0u8; 32];
        secret_bytes[..16].copy_from_slice(&hi_bytes[..16]);
        secret_bytes[16..].copy_from_slice(&lo_bytes[..16]);
        let native = derive_address(&SpendSecret(secret_bytes));

        let addr_hi_bytes = addr_hi.to_bytes();
        let addr_lo_bytes = addr_lo.to_bytes();
        let mut out_bytes = [0u8; 32];
        out_bytes[..16].copy_from_slice(&addr_hi_bytes[..16]);
        out_bytes[16..].copy_from_slice(&addr_lo_bytes[..16]);
        assert_eq!(out_bytes, native.0);

        // And the dst cells mirror the same hi/lo.
        assert_eq!(cols[HI_DST_COL][HI_DST_ROW], addr_hi);
        assert_eq!(cols[LO_DST_COL][LO_DST_ROW], addr_lo);
    }
}
