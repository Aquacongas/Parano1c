// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Stage 5.5 — `HAuthBlock`: a single `HAuthAir` instance embedded into
//! an outer composite trace via [`RowWindowWrapper`], plus two bridge
//! families:
//!
//! - **T2a** — output squeeze → TxValidity `AuthTag` cell, per lane.
//!   Source: `HAuthAir.s_C[lane]@OUTPUT_ROW`. Destination: caller-
//!   supplied outer cell (typically `TxValidityCol::AuthTagHi/Lo` at
//!   row `i`). One bridge per lane, dst is unique per input.
//!
//! - **T2b** — second-absorb pre-MDS seed → shared tx-body-hash cell,
//!   per lane. Source: `HAuthAir.pre_s_B[lane]@N_ROUNDS`. Destination:
//!   caller-supplied outer cell shared across **every** HAuth block
//!   (the tx-body-hash is the same public input for all inputs). One
//!   bridge per lane per input.
//!
//! This is the reusable unit from which the Stage 5.5 composite
//! (`HAuthAir × N_INPUTS` all tied through T2a to distinct AuthTag rows
//! and through T2b to a shared pair of tx-body-hash cells) is
//! assembled.
//!
//! # Column budget (per block)
//!
//! | span                                          | role                         |
//! |-----------------------------------------------|------------------------------|
//! | `col_offset .. col_offset + HAUTH_N_COLS`     | HAuth sub-AIR trace columns  |
//! | `window_indicator_col`                        | RowWindowWrapper indicator   |
//! | `t2a_hi` 4 cols                               | T2a hi-lane bridge           |
//! | `t2a_lo` 4 cols                               | T2a lo-lane bridge           |
//! | `t2b_hi` 4 cols                               | T2b hi-lane bridge           |
//! | `t2b_lo` 4 cols                               | T2b lo-lane bridge           |
//!
//! The sub-AIR is embedded under [`WrapPolicy::MaskOff`] because
//! `HAuthAir::requires_true_cyclic_wrap()` is `false`.

use crate::airs::hauth::{
    build_hauth_trace, HAuthAir, HAUTH_LAYOUT_C, HAUTH_LOG_ROWS, HAUTH_N_COLS,
    HAUTH_N_ROWS, HAUTH_OUTPUT_ROW, HAUTH_PRE_S_B_BASE,
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
use noid_poseidon2b::native::permutation::N_ROUNDS;

/// Per-lane pre-MDS B seed row (where T2b picks up its source cell).
/// `HAuthAir` uses `HAUTH_B_SEED_ROW = N_ROUNDS + 1` as the post-MDS
/// state row; the pre-MDS witness row is the row below it, `N_ROUNDS`.
const HAUTH_PRE_S_B_ROW: usize = N_ROUNDS;

/// Column-budget descriptor for one embedded HAuth block.
#[derive(Debug, Clone, Copy)]
pub struct HAuthBlockColumns {
    /// Start column of the HAuth sub-AIR.
    pub col_offset: usize,
    /// Outer column reserved for the RowWindowWrapper's window indicator.
    pub window_indicator_col: usize,
    /// T2a hi-lane bridge budget (HAuth squeeze hi → AuthTagHi dst).
    pub t2a_hi_budget: LaneBridgeBudget,
    /// T2a lo-lane bridge budget (HAuth squeeze lo → AuthTagLo dst).
    pub t2a_lo_budget: LaneBridgeBudget,
    /// T2b hi-lane bridge budget (HAuth pre_s_B[0]@N_ROUNDS → tx_body_hash_hi dst).
    pub t2b_hi_budget: LaneBridgeBudget,
    /// T2b lo-lane bridge budget (HAuth pre_s_B[1]@N_ROUNDS → tx_body_hash_lo dst).
    pub t2b_lo_budget: LaneBridgeBudget,
}

/// Destination cells for T2a + T2b. T2a destinations are per-input
/// (usually `AuthTagHi/Lo[input]`); T2b destinations are the shared
/// pair carrying `tx_body_hash_hi/lo` (identical across every HAuth
/// block in the composite).
#[derive(Debug, Clone, Copy)]
pub struct HAuthBlockTargets {
    pub auth_tag_hi_dst_col: usize,
    pub auth_tag_hi_dst_row: usize,
    pub auth_tag_lo_dst_col: usize,
    pub auth_tag_lo_dst_row: usize,
    pub tx_body_hi_dst_col: usize,
    pub tx_body_hi_dst_row: usize,
    pub tx_body_lo_dst_col: usize,
    pub tx_body_lo_dst_row: usize,
}

/// Parameters for a single [`emit_hauth_block`] call.
#[derive(Debug, Clone, Copy)]
pub struct HAuthBlockParams {
    pub cols: HAuthBlockColumns,
    pub row_window_start: usize,
    pub outer_n_cols: usize,
    pub outer_log_rows: usize,
    /// Public tx-body-hash `(hi, lo)` — pins the absorb XOR inside
    /// HAuthAir and seeds the T2b destination cells on `build_trace`.
    /// Identical across every HAuth block in the composite.
    pub tx_body_hash: [Block128; 2],
    pub targets: HAuthBlockTargets,
}

/// Output of [`emit_hauth_block`].
pub struct HAuthBlockWiring {
    pub constraints: Vec<Box<dyn Constraint>>,
    pub public_columns: Vec<PublicColumn>,
    /// Absolute `(col, row)` of the squeezed auth-tag hi lane.
    pub squeezed_tag_hi_cell: (usize, usize),
    pub squeezed_tag_lo_cell: (usize, usize),
    /// Absolute `(col, row)` of the pre-MDS B-seed cell, per lane.
    /// Stage 5.7 replaces T2b with a direct tie from these cells into
    /// the Merkle wrap output columns.
    pub pre_s_b_hi_cell: (usize, usize),
    pub pre_s_b_lo_cell: (usize, usize),
}

/// Emit the full wiring for one embedded HAuth block: sub-AIR via
/// RowWindowWrapper + four lane bridges (T2a hi/lo + T2b hi/lo).
pub fn emit_hauth_block(p: HAuthBlockParams) -> HAuthBlockWiring {
    let outer_n_rows = 1usize << p.outer_log_rows;
    assert!(
        p.row_window_start + HAUTH_N_ROWS <= outer_n_rows,
        "emit_hauth_block: window [{}, {}) exceeds outer rows {}",
        p.row_window_start,
        p.row_window_start + HAUTH_N_ROWS,
        outer_n_rows,
    );

    // 1) Wrap the sub-AIR. `new_no_output_pin` takes tx_body so the
    //    absorb XOR at row N_ROUNDS pins pre_s_B to
    //    A.s + [tx_body_hi, tx_body_lo, 0, 0] — which is what T2b
    //    then bridges to the composite-level tx_body_hash cells.
    let air = HAuthAir::new_no_output_pin(p.tx_body_hash);
    let requires_cyclic = air.requires_true_cyclic_wrap();
    let (inner_n_cols, constraints_inner, publics_inner) = air.into_parts();
    assert_eq!(inner_n_cols, HAUTH_N_COLS);
    let inner_view = InnerAirView {
        inner_n_cols: HAUTH_N_COLS,
        inner_log_rows: HAUTH_LOG_ROWS,
        constraints: constraints_inner,
        public_columns: publics_inner,
        requires_true_cyclic_wrap: requires_cyclic,
    };
    let window_params = RowWindowParams {
        col_offset: p.cols.col_offset,
        outer_n_cols: p.outer_n_cols,
        outer_log_rows: p.outer_log_rows,
        row_window_start: p.row_window_start,
        row_window_end: p.row_window_start + HAUTH_N_ROWS,
        window_indicator_col: p.cols.window_indicator_col,
        policy: WrapPolicy::MaskOff,
        terminator_pin_cols: Vec::new(),
    };
    let RowWindowWiring {
        mut constraints,
        mut public_columns,
    } = RowWindowWrapper::wrap(inner_view, window_params);

    // 2) Outer-trace absolute cells.
    let squeezed_hi_col = p.cols.col_offset + HAUTH_LAYOUT_C.s;
    let squeezed_lo_col = p.cols.col_offset + HAUTH_LAYOUT_C.s + 1;
    let squeezed_row = p.row_window_start + HAUTH_OUTPUT_ROW;

    let pre_s_b_hi_col = p.cols.col_offset + HAUTH_PRE_S_B_BASE;
    let pre_s_b_lo_col = p.cols.col_offset + HAUTH_PRE_S_B_BASE + 1;
    let pre_s_b_row = p.row_window_start + HAUTH_PRE_S_B_ROW;

    // 3) T2a hi-lane bridge.
    let t2a_hi_tie = LaneBridgeTie {
        src_col: squeezed_hi_col,
        src_row: squeezed_row,
        dst_col: p.targets.auth_tag_hi_dst_col,
        dst_row: p.targets.auth_tag_hi_dst_row,
    };
    let wiring = emit_t1_lane(t2a_hi_tie, p.cols.t2a_hi_budget, outer_n_rows);
    public_columns.extend(wiring.public_columns);
    constraints.extend(wiring.constraints);

    // 4) T2a lo-lane bridge.
    let t2a_lo_tie = LaneBridgeTie {
        src_col: squeezed_lo_col,
        src_row: squeezed_row,
        dst_col: p.targets.auth_tag_lo_dst_col,
        dst_row: p.targets.auth_tag_lo_dst_row,
    };
    let wiring = emit_t1_lane(t2a_lo_tie, p.cols.t2a_lo_budget, outer_n_rows);
    public_columns.extend(wiring.public_columns);
    constraints.extend(wiring.constraints);

    // 5) T2b hi-lane bridge.
    let t2b_hi_tie = LaneBridgeTie {
        src_col: pre_s_b_hi_col,
        src_row: pre_s_b_row,
        dst_col: p.targets.tx_body_hi_dst_col,
        dst_row: p.targets.tx_body_hi_dst_row,
    };
    let wiring = emit_t1_lane(t2b_hi_tie, p.cols.t2b_hi_budget, outer_n_rows);
    public_columns.extend(wiring.public_columns);
    constraints.extend(wiring.constraints);

    // 6) T2b lo-lane bridge.
    let t2b_lo_tie = LaneBridgeTie {
        src_col: pre_s_b_lo_col,
        src_row: pre_s_b_row,
        dst_col: p.targets.tx_body_lo_dst_col,
        dst_row: p.targets.tx_body_lo_dst_row,
    };
    let wiring = emit_t1_lane(t2b_lo_tie, p.cols.t2b_lo_budget, outer_n_rows);
    public_columns.extend(wiring.public_columns);
    constraints.extend(wiring.constraints);

    HAuthBlockWiring {
        constraints,
        public_columns,
        squeezed_tag_hi_cell: (squeezed_hi_col, squeezed_row),
        squeezed_tag_lo_cell: (squeezed_lo_col, squeezed_row),
        pre_s_b_hi_cell: (pre_s_b_hi_col, pre_s_b_row),
        pre_s_b_lo_cell: (pre_s_b_lo_col, pre_s_b_row),
    }
}

/// Result of [`write_hauth_block_trace`].
pub struct HAuthBlockTraceCells {
    pub tag: [Block128; 2],
    pub pre_s_b: [Block128; 2],
}

/// Populate the outer trace with an honest HAuth block plus matching
/// T2a/T2b bridge columns. Expects the caller to pre-allocate `cols`
/// ZERO-initialised to the full outer column × row count. Writes:
///
/// - HAuth sub-AIR columns on rows `[row_window_start, +HAUTH_N_ROWS)`.
/// - Mirrored destination cells for all four bridges (so src == dst
///   on the honest trace).
/// - Bridge column witness values for all four lanes.
///
/// Returns the squeezed auth tag and pre-MDS B-seed values (caller may
/// compare them against native reference).
pub fn write_hauth_block_trace(
    cols: &mut [Vec<Block128>],
    p: HAuthBlockParams,
    secret: [Block128; 2],
) -> HAuthBlockTraceCells {
    let outer_n_rows = 1usize << p.outer_log_rows;

    // 1) HAuth sub-trace into the column window.
    let inner_cols = build_hauth_trace(secret, p.tx_body_hash);
    assert_eq!(inner_cols.len(), HAUTH_N_COLS);
    for (i, src) in inner_cols.into_iter().enumerate() {
        assert_eq!(src.len(), HAUTH_N_ROWS);
        let dst = &mut cols[p.cols.col_offset + i];
        for (r, v) in src.into_iter().enumerate() {
            dst[p.row_window_start + r] = v;
        }
    }

    // 2) Extract squeezed + pre-MDS B cells.
    let squeezed_hi_col = p.cols.col_offset + HAUTH_LAYOUT_C.s;
    let squeezed_lo_col = p.cols.col_offset + HAUTH_LAYOUT_C.s + 1;
    let squeezed_row = p.row_window_start + HAUTH_OUTPUT_ROW;
    let tag_hi = cols[squeezed_hi_col][squeezed_row];
    let tag_lo = cols[squeezed_lo_col][squeezed_row];

    let pre_s_b_hi_col = p.cols.col_offset + HAUTH_PRE_S_B_BASE;
    let pre_s_b_lo_col = p.cols.col_offset + HAUTH_PRE_S_B_BASE + 1;
    let pre_s_b_row = p.row_window_start + HAUTH_PRE_S_B_ROW;
    let pre_hi = cols[pre_s_b_hi_col][pre_s_b_row];
    let pre_lo = cols[pre_s_b_lo_col][pre_s_b_row];

    // 3) Plant destination cells. T2a dsts are per-input; T2b dsts are
    //    shared across blocks and may have been planted by an earlier
    //    block — the write here is idempotent (honest traces agree on
    //    the shared tx_body_hash).
    cols[p.targets.auth_tag_hi_dst_col][p.targets.auth_tag_hi_dst_row] = tag_hi;
    cols[p.targets.auth_tag_lo_dst_col][p.targets.auth_tag_lo_dst_row] = tag_lo;
    cols[p.targets.tx_body_hi_dst_col][p.targets.tx_body_hi_dst_row] = pre_hi;
    cols[p.targets.tx_body_lo_dst_col][p.targets.tx_body_lo_dst_row] = pre_lo;

    // 4) Bridge column witness values.
    let t2a_hi_tie = LaneBridgeTie {
        src_col: squeezed_hi_col,
        src_row: squeezed_row,
        dst_col: p.targets.auth_tag_hi_dst_col,
        dst_row: p.targets.auth_tag_hi_dst_row,
    };
    write_t1_lane_bridge(cols, t2a_hi_tie, p.cols.t2a_hi_budget, outer_n_rows, tag_hi);

    let t2a_lo_tie = LaneBridgeTie {
        src_col: squeezed_lo_col,
        src_row: squeezed_row,
        dst_col: p.targets.auth_tag_lo_dst_col,
        dst_row: p.targets.auth_tag_lo_dst_row,
    };
    write_t1_lane_bridge(cols, t2a_lo_tie, p.cols.t2a_lo_budget, outer_n_rows, tag_lo);

    let t2b_hi_tie = LaneBridgeTie {
        src_col: pre_s_b_hi_col,
        src_row: pre_s_b_row,
        dst_col: p.targets.tx_body_hi_dst_col,
        dst_row: p.targets.tx_body_hi_dst_row,
    };
    write_t1_lane_bridge(cols, t2b_hi_tie, p.cols.t2b_hi_budget, outer_n_rows, pre_hi);

    let t2b_lo_tie = LaneBridgeTie {
        src_col: pre_s_b_lo_col,
        src_row: pre_s_b_row,
        dst_col: p.targets.tx_body_lo_dst_col,
        dst_row: p.targets.tx_body_lo_dst_row,
    };
    write_t1_lane_bridge(cols, t2b_lo_tie, p.cols.t2b_lo_budget, outer_n_rows, pre_lo);

    HAuthBlockTraceCells {
        tag: [tag_hi, tag_lo],
        pre_s_b: [pre_hi, pre_lo],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::airs::hauth::{extract_hauth_output, HAUTH_LAYOUT_A};
    use crate::{Air, CompositeAir, Trace};
    use noid_core::TowerField;

    const OUTER_LOG_ROWS: usize = HAUTH_LOG_ROWS + 1; // 512 rows.
    const OUTER_N_ROWS: usize = 1 << OUTER_LOG_ROWS;
    const ROW_WINDOW_START: usize = 0;

    // Column layout for the scaffold:
    //   0 .. HAUTH_N_COLS                       HAuth sub-AIR
    //   HAUTH_N_COLS                              window indicator
    //   HAUTH_N_COLS + 1..+4                      T2a hi (bridge + 3 ind)
    //   HAUTH_N_COLS + 5..+8                      T2a lo
    //   HAUTH_N_COLS + 9..+12                     T2b hi
    //   HAUTH_N_COLS + 13..+16                    T2b lo
    //   HAUTH_N_COLS + 17                         auth_tag_hi dst column
    //   HAUTH_N_COLS + 18                         auth_tag_lo dst column
    //   HAUTH_N_COLS + 19                         tx_body_hi dst column
    //   HAUTH_N_COLS + 20                         tx_body_lo dst column
    const WINDOW_INDICATOR_COL: usize = HAUTH_N_COLS;
    const T2A_HI_BRIDGE: usize = HAUTH_N_COLS + 1;
    const T2A_HI_SRC: usize = HAUTH_N_COLS + 2;
    const T2A_HI_DST: usize = HAUTH_N_COLS + 3;
    const T2A_HI_TRANS: usize = HAUTH_N_COLS + 4;
    const T2A_LO_BRIDGE: usize = HAUTH_N_COLS + 5;
    const T2A_LO_SRC: usize = HAUTH_N_COLS + 6;
    const T2A_LO_DST: usize = HAUTH_N_COLS + 7;
    const T2A_LO_TRANS: usize = HAUTH_N_COLS + 8;
    const T2B_HI_BRIDGE: usize = HAUTH_N_COLS + 9;
    const T2B_HI_SRC: usize = HAUTH_N_COLS + 10;
    const T2B_HI_DST: usize = HAUTH_N_COLS + 11;
    const T2B_HI_TRANS: usize = HAUTH_N_COLS + 12;
    const T2B_LO_BRIDGE: usize = HAUTH_N_COLS + 13;
    const T2B_LO_SRC: usize = HAUTH_N_COLS + 14;
    const T2B_LO_DST: usize = HAUTH_N_COLS + 15;
    const T2B_LO_TRANS: usize = HAUTH_N_COLS + 16;
    const AUTH_TAG_HI_DST_COL: usize = HAUTH_N_COLS + 17;
    const AUTH_TAG_LO_DST_COL: usize = HAUTH_N_COLS + 18;
    const TX_BODY_HI_DST_COL: usize = HAUTH_N_COLS + 19;
    const TX_BODY_LO_DST_COL: usize = HAUTH_N_COLS + 20;
    const OUTER_N_COLS: usize = HAUTH_N_COLS + 21;

    const AUTH_TAG_HI_DST_ROW: usize = HAUTH_N_ROWS + 3;
    const AUTH_TAG_LO_DST_ROW: usize = HAUTH_N_ROWS + 5;
    const TX_BODY_HI_DST_ROW: usize = HAUTH_N_ROWS + 7;
    const TX_BODY_LO_DST_ROW: usize = HAUTH_N_ROWS + 9;

    fn mk_fields(seed: u128) -> [Block128; 2] {
        let s = seed.wrapping_mul(0x9E3779B97F4A7C15);
        [
            Block128::from(s ^ 0xA5A5_A5A5_A5A5_A5A5),
            Block128::from(s.wrapping_add(1) ^ 0x5A5A_5A5A_5A5A_5A5A),
        ]
    }

    fn params(tx_body: [Block128; 2]) -> HAuthBlockParams {
        HAuthBlockParams {
            cols: HAuthBlockColumns {
                col_offset: 0,
                window_indicator_col: WINDOW_INDICATOR_COL,
                t2a_hi_budget: LaneBridgeBudget {
                    bridge_col: T2A_HI_BRIDGE,
                    src_indicator_col: T2A_HI_SRC,
                    dst_indicator_col: T2A_HI_DST,
                    transition_indicator_col: T2A_HI_TRANS,
                },
                t2a_lo_budget: LaneBridgeBudget {
                    bridge_col: T2A_LO_BRIDGE,
                    src_indicator_col: T2A_LO_SRC,
                    dst_indicator_col: T2A_LO_DST,
                    transition_indicator_col: T2A_LO_TRANS,
                },
                t2b_hi_budget: LaneBridgeBudget {
                    bridge_col: T2B_HI_BRIDGE,
                    src_indicator_col: T2B_HI_SRC,
                    dst_indicator_col: T2B_HI_DST,
                    transition_indicator_col: T2B_HI_TRANS,
                },
                t2b_lo_budget: LaneBridgeBudget {
                    bridge_col: T2B_LO_BRIDGE,
                    src_indicator_col: T2B_LO_SRC,
                    dst_indicator_col: T2B_LO_DST,
                    transition_indicator_col: T2B_LO_TRANS,
                },
            },
            row_window_start: ROW_WINDOW_START,
            outer_n_cols: OUTER_N_COLS,
            outer_log_rows: OUTER_LOG_ROWS,
            tx_body_hash: tx_body,
            targets: HAuthBlockTargets {
                auth_tag_hi_dst_col: AUTH_TAG_HI_DST_COL,
                auth_tag_hi_dst_row: AUTH_TAG_HI_DST_ROW,
                auth_tag_lo_dst_col: AUTH_TAG_LO_DST_COL,
                auth_tag_lo_dst_row: AUTH_TAG_LO_DST_ROW,
                tx_body_hi_dst_col: TX_BODY_HI_DST_COL,
                tx_body_hi_dst_row: TX_BODY_HI_DST_ROW,
                tx_body_lo_dst_col: TX_BODY_LO_DST_COL,
                tx_body_lo_dst_row: TX_BODY_LO_DST_ROW,
            },
        }
    }

    fn build(
        secret: [Block128; 2],
        tx_body: [Block128; 2],
    ) -> (CompositeAir, Vec<Vec<Block128>>, HAuthBlockParams) {
        let p = params(tx_body);
        let w = emit_hauth_block(p);
        let air = CompositeAir::from_parts_with_publics(
            OUTER_LOG_ROWS,
            OUTER_N_COLS,
            w.constraints,
            w.public_columns,
        );
        let mut cols: Vec<Vec<Block128>> = (0..OUTER_N_COLS)
            .map(|_| vec![Block128::ZERO; OUTER_N_ROWS])
            .collect();
        let _ = write_hauth_block_trace(&mut cols, p, secret);
        // Overwrite every public column with its declared programme.
        for pc in air.public_columns() {
            cols[pc.col] = pc.values.clone();
        }
        (air, cols, p)
    }

    #[test]
    fn honest_accepts() {
        let (air, cols, _) = build(mk_fields(0x1234), mk_fields(0xAAAA));
        assert!(air.check(&Trace::new(cols)));
    }

    #[test]
    fn squeeze_matches_native() {
        let secret = mk_fields(0xCAFE);
        let tx_body = mk_fields(0xBABE);
        let (_air, cols, _p) = build(secret, tx_body);
        let native = extract_hauth_output(&build_hauth_trace(secret, tx_body));
        assert_eq!(
            cols[HAUTH_LAYOUT_C.s][ROW_WINDOW_START + HAUTH_OUTPUT_ROW],
            native[0]
        );
        assert_eq!(
            cols[HAUTH_LAYOUT_C.s + 1][ROW_WINDOW_START + HAUTH_OUTPUT_ROW],
            native[1]
        );
    }

    #[test]
    fn hauth_interior_tamper_rejects() {
        let (air, mut cols, _) = build(mk_fields(0x5678), mk_fields(0x9999));
        // Flip an interior perm-A sout cell — should reject via the
        // sub-AIR constraints (inside the window, MaskOff leaves them
        // active).
        cols[HAUTH_LAYOUT_A.sout + 2][ROW_WINDOW_START + 1] =
            cols[HAUTH_LAYOUT_A.sout + 2][ROW_WINDOW_START + 1] + Block128::ONE;
        assert!(!air.check(&Trace::new(cols)));
    }

    #[test]
    fn t2a_hi_dst_tamper_rejects() {
        let (air, mut cols, _) = build(mk_fields(0xABCD), mk_fields(0xDCBA));
        cols[AUTH_TAG_HI_DST_COL][AUTH_TAG_HI_DST_ROW] =
            cols[AUTH_TAG_HI_DST_COL][AUTH_TAG_HI_DST_ROW] + Block128::ONE;
        assert!(!air.check(&Trace::new(cols)));
    }

    #[test]
    fn t2a_lo_dst_tamper_rejects() {
        let (air, mut cols, _) = build(mk_fields(0xBEEF), mk_fields(0xFEEB));
        cols[AUTH_TAG_LO_DST_COL][AUTH_TAG_LO_DST_ROW] =
            cols[AUTH_TAG_LO_DST_COL][AUTH_TAG_LO_DST_ROW] + Block128::ONE;
        assert!(!air.check(&Trace::new(cols)));
    }

    #[test]
    fn t2b_hi_dst_tamper_rejects() {
        let (air, mut cols, _) = build(mk_fields(0x1111), mk_fields(0x2222));
        cols[TX_BODY_HI_DST_COL][TX_BODY_HI_DST_ROW] =
            cols[TX_BODY_HI_DST_COL][TX_BODY_HI_DST_ROW] + Block128::ONE;
        assert!(!air.check(&Trace::new(cols)));
    }

    #[test]
    fn t2b_lo_dst_tamper_rejects() {
        let (air, mut cols, _) = build(mk_fields(0x3333), mk_fields(0x4444));
        cols[TX_BODY_LO_DST_COL][TX_BODY_LO_DST_ROW] =
            cols[TX_BODY_LO_DST_COL][TX_BODY_LO_DST_ROW] + Block128::ONE;
        assert!(!air.check(&Trace::new(cols)));
    }

    #[test]
    fn t2a_hi_bridge_interior_tamper_rejects() {
        let (air, mut cols, _) = build(mk_fields(0x5555), mk_fields(0x6666));
        let squeezed_row = ROW_WINDOW_START + HAUTH_OUTPUT_ROW;
        let mid = (squeezed_row + AUTH_TAG_HI_DST_ROW) / 2;
        cols[T2A_HI_BRIDGE][mid] = cols[T2A_HI_BRIDGE][mid] + Block128::ONE;
        assert!(!air.check(&Trace::new(cols)));
    }

    #[test]
    fn t2b_hi_bridge_interior_tamper_rejects() {
        let (air, mut cols, _) = build(mk_fields(0x7777), mk_fields(0x8888));
        let pre_row = ROW_WINDOW_START + HAUTH_PRE_S_B_ROW;
        let mid = (pre_row + TX_BODY_HI_DST_ROW) / 2;
        cols[T2B_HI_BRIDGE][mid] = cols[T2B_HI_BRIDGE][mid] + Block128::ONE;
        assert!(!air.check(&Trace::new(cols)));
    }

    #[test]
    fn outside_window_hauth_edit_accepted() {
        // MaskOff silences HAuth constraints outside the window.
        let (air, mut cols, _) = build(mk_fields(0x9999), mk_fields(0xAAAA));
        let far_row = ROW_WINDOW_START + HAUTH_N_ROWS + 5;
        cols[HAUTH_LAYOUT_A.sout + 2][far_row] = Block128::from(0xDEAD_u128);
        assert!(air.check(&Trace::new(cols)));
    }
}
