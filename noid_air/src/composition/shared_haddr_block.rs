// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! OP-1.γ — `SharedHAddrBlock`: single embedded [`HAddrMultiAir`] +
//! `N_INPUTS` T1 owner-lane bridge pairs. Drop-in replacement for
//! calling [`emit_haddr_block`] once per input.
//!
//! # Column budget
//!
//! | span                                                      | role                                |
//! |-----------------------------------------------------------|-------------------------------------|
//! | `col_offset .. col_offset + haddr_multi_n_cols(n_inputs)` | HAddrMultiAir sub-AIR trace columns |
//! | `window_indicator_col`                                    | RowWindowWrapper window indicator   |
//! | per input `i`: 8 outer cols                               | T1 hi + lo bridge pair              |
//!
//! Total bridge overhead: `1 + 8·n_inputs` outer columns (vs. the
//! legacy per-block layout of `1 + 8 + HADDR_N_COLS = HADDR_N_COLS + 9`
//! per input — at 4 inputs that is `4·80 = 320` cols for the blocks
//! alone before we count the multi-AIR's 80 cols).
//!
//! Savings for 4 inputs, expressed in outer columns:
//!
//! | layout                                               | cols |
//! |------------------------------------------------------|------|
//! | 4 × `emit_haddr_block` (legacy)                      | 4 · (71 + 9) = 320 |
//! | 1 × `emit_shared_haddr_block` with n_inputs = 4      | 80 + 1 + 32 = 113  |
//!
//! # Soundness
//!
//! `HAddrMultiAir` (OP-1.α) emits per-input boundary pins each gated
//! by a single-hot `ind_row_*[i]` public column. Output squeeze is not
//! pinned inside the AIR — this module adds N T1 bridges per output
//! squeeze cell, one pair per input, tying to caller-supplied owner
//! destinations. Per-input soundness therefore mirrors the legacy
//! single-block path exactly: the squeeze cell's value is the same
//! bit-for-bit (see `single_instance_output_matches_legacy_haddr` test
//! in `haddr_multi.rs`), the bridge primitive is identical, and the
//! per-input indicator bands are disjoint.

use crate::airs::haddr_multi::{
    build_haddr_multi_trace, emit_haddr_multi_no_output_pin, haddr_multi_min_log_rows,
    haddr_multi_n_cols, haddr_multi_row_output, HAddrMultiAir, HADDR_MULTI_LAYOUT_B,
};
use crate::composition::row_window::{
    InnerAirView, RowWindowParams, RowWindowWiring, RowWindowWrapper, WrapPolicy,
};
use crate::composition::t1_owner_tie::{
    emit_t1_lane, write_t1_lane_bridge, T1LaneColumnBudget, T1LaneTie,
};
use crate::gates::const_column::PublicColumn;
use crate::Constraint;
use noid_core::Block128;

/// Per-input T1 bridge column budget (hi + lo).
#[derive(Debug, Clone, Copy)]
pub struct SharedHAddrInputBudget {
    pub t1_hi_budget: T1LaneColumnBudget,
    pub t1_lo_budget: T1LaneColumnBudget,
}

/// Per-input T1 destination cells — the outer-trace owner lanes
/// the squeezed address ties to.
#[derive(Debug, Clone, Copy)]
pub struct SharedHAddrInputTargets {
    pub owner_hi_dst_col: usize,
    pub owner_hi_dst_row: usize,
    pub owner_lo_dst_col: usize,
    pub owner_lo_dst_row: usize,
}

/// Parameters for a single `emit_shared_haddr_block` call.
#[derive(Debug, Clone)]
pub struct SharedHAddrBlockParams {
    /// `n_inputs` independent `derive_address` sponges packed in one
    /// column slab. Must equal `inputs.len()`.
    pub n_inputs: usize,
    /// Start column of the `HAddrMultiAir` slab inside the outer trace.
    pub col_offset: usize,
    /// Outer column reserved for the RowWindowWrapper's window indicator.
    pub window_indicator_col: usize,
    /// Starting outer row of the window. The window spans
    /// `2^haddr_multi_min_log_rows(n_inputs)` rows.
    pub row_window_start: usize,
    pub outer_n_cols: usize,
    pub outer_log_rows: usize,
    /// Per-input T1 bridge budgets. `inputs[i]` holds the bridge + 3
    /// indicator column allocations for input `i`'s hi and lo lanes.
    pub inputs: Vec<(SharedHAddrInputBudget, SharedHAddrInputTargets)>,
}

/// Output of [`emit_shared_haddr_block`].
pub struct SharedHAddrBlockWiring {
    pub constraints: Vec<Box<dyn Constraint>>,
    pub public_columns: Vec<PublicColumn>,
    /// `squeezed_cells[i] = ((hi_col, row), (lo_col, row))` for input `i`.
    pub squeezed_cells: Vec<((usize, usize), (usize, usize))>,
}

/// Emit the full wiring for a shared HAddr block: one `HAddrMultiAir`
/// embedded via `RowWindowWrapper` + `n_inputs` T1 lane-pair bridges.
pub fn emit_shared_haddr_block(p: SharedHAddrBlockParams) -> SharedHAddrBlockWiring {
    assert_eq!(
        p.inputs.len(),
        p.n_inputs,
        "emit_shared_haddr_block: inputs.len() {} != n_inputs {}",
        p.inputs.len(),
        p.n_inputs,
    );
    let outer_n_rows = 1usize << p.outer_log_rows;
    let inner_log_rows = haddr_multi_min_log_rows(p.n_inputs);
    let inner_n_rows = 1usize << inner_log_rows;
    assert!(
        p.row_window_start + inner_n_rows <= outer_n_rows,
        "emit_shared_haddr_block: window [{}, {}) exceeds outer rows {}",
        p.row_window_start,
        p.row_window_start + inner_n_rows,
        outer_n_rows,
    );

    // 1) Wrap the multi-AIR.
    let air = HAddrMultiAir::new(p.n_inputs, inner_log_rows);
    let inner_n_cols = haddr_multi_n_cols(p.n_inputs);
    let (reported_n_cols, constraints_inner, publics_inner) = air.into_parts();
    assert_eq!(reported_n_cols, inner_n_cols);

    let inner_view = InnerAirView {
        inner_n_cols,
        inner_log_rows,
        constraints: constraints_inner,
        public_columns: publics_inner,
        // HAddrMultiAir has no cross-instance cyclic read: disjoint
        // row bands + row-local perm interior + indicator-gated
        // boundary pins. Safe under MaskOff.
        requires_true_cyclic_wrap: false,
    };
    let window_params = RowWindowParams {
        col_offset: p.col_offset,
        outer_n_cols: p.outer_n_cols,
        outer_log_rows: p.outer_log_rows,
        row_window_start: p.row_window_start,
        row_window_end: p.row_window_start + inner_n_rows,
        window_indicator_col: p.window_indicator_col,
        policy: WrapPolicy::MaskOff,
        terminator_pin_cols: Vec::new(),
    };
    let RowWindowWiring {
        mut constraints,
        mut public_columns,
    } = RowWindowWrapper::wrap(inner_view, window_params);

    // 2) Per-input T1 bridges.
    let mut squeezed_cells = Vec::with_capacity(p.n_inputs);
    for (i, (budget, target)) in p.inputs.iter().enumerate() {
        let squeezed_hi_col = p.col_offset + HADDR_MULTI_LAYOUT_B.s;
        let squeezed_lo_col = p.col_offset + HADDR_MULTI_LAYOUT_B.s + 1;
        let squeezed_row = p.row_window_start + haddr_multi_row_output(i);

        let hi_tie = T1LaneTie {
            src_col: squeezed_hi_col,
            src_row: squeezed_row,
            dst_col: target.owner_hi_dst_col,
            dst_row: target.owner_hi_dst_row,
        };
        let hi_wiring = emit_t1_lane(hi_tie, budget.t1_hi_budget, outer_n_rows);
        public_columns.extend(hi_wiring.public_columns);
        constraints.extend(hi_wiring.constraints);

        let lo_tie = T1LaneTie {
            src_col: squeezed_lo_col,
            src_row: squeezed_row,
            dst_col: target.owner_lo_dst_col,
            dst_row: target.owner_lo_dst_row,
        };
        let lo_wiring = emit_t1_lane(lo_tie, budget.t1_lo_budget, outer_n_rows);
        public_columns.extend(lo_wiring.public_columns);
        constraints.extend(lo_wiring.constraints);

        squeezed_cells.push((
            (squeezed_hi_col, squeezed_row),
            (squeezed_lo_col, squeezed_row),
        ));
    }

    // Silence unused warnings for helpers imported for completeness.
    let _ = emit_haddr_multi_no_output_pin;

    SharedHAddrBlockWiring {
        constraints,
        public_columns,
        squeezed_cells,
    }
}

/// Populate the outer trace with an honest shared HAddr block plus the
/// matching T1 bridge columns for every input.
pub fn write_shared_haddr_block_trace(
    cols: &mut [Vec<Block128>],
    p: &SharedHAddrBlockParams,
    secrets: &[[Block128; 2]],
) -> Vec<[Block128; 2]> {
    assert_eq!(secrets.len(), p.n_inputs);
    let outer_n_rows = 1usize << p.outer_log_rows;
    let inner_log_rows = haddr_multi_min_log_rows(p.n_inputs);
    let inner_n_rows = 1usize << inner_log_rows;
    let inner_n_cols = haddr_multi_n_cols(p.n_inputs);

    // 1) Multi-AIR sub-trace into the column window.
    let inner_cols = build_haddr_multi_trace(secrets, inner_log_rows);
    assert_eq!(inner_cols.len(), inner_n_cols);
    for (i, src) in inner_cols.into_iter().enumerate() {
        assert_eq!(src.len(), inner_n_rows);
        let dst = &mut cols[p.col_offset + i];
        for (r, v) in src.into_iter().enumerate() {
            dst[p.row_window_start + r] = v;
        }
    }

    // 2) Per-input T1 bridges — extract squeeze, plant dst, write bridge.
    let mut addrs = Vec::with_capacity(p.n_inputs);
    for (i, (budget, target)) in p.inputs.iter().enumerate() {
        let squeezed_hi_col = p.col_offset + HADDR_MULTI_LAYOUT_B.s;
        let squeezed_lo_col = p.col_offset + HADDR_MULTI_LAYOUT_B.s + 1;
        let squeezed_row = p.row_window_start + haddr_multi_row_output(i);
        let addr_hi = cols[squeezed_hi_col][squeezed_row];
        let addr_lo = cols[squeezed_lo_col][squeezed_row];

        cols[target.owner_hi_dst_col][target.owner_hi_dst_row] = addr_hi;
        cols[target.owner_lo_dst_col][target.owner_lo_dst_row] = addr_lo;

        write_t1_lane_bridge(
            cols,
            T1LaneTie {
                src_col: squeezed_hi_col,
                src_row: squeezed_row,
                dst_col: target.owner_hi_dst_col,
                dst_row: target.owner_hi_dst_row,
            },
            budget.t1_hi_budget,
            outer_n_rows,
            addr_hi,
        );
        write_t1_lane_bridge(
            cols,
            T1LaneTie {
                src_col: squeezed_lo_col,
                src_row: squeezed_row,
                dst_col: target.owner_lo_dst_col,
                dst_row: target.owner_lo_dst_row,
            },
            budget.t1_lo_budget,
            outer_n_rows,
            addr_lo,
        );

        addrs.push([addr_hi, addr_lo]);
    }

    addrs
}

/// Outer-column overhead introduced by a shared HAddr block, **not**
/// counting the multi-AIR's sub-trace columns: `1` window indicator
/// plus `8 · n_inputs` T1 bridge/indicator columns.
pub const fn shared_haddr_outer_overhead_cols(n_inputs: usize) -> usize {
    1 + 8 * n_inputs
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::airs::haddr::{build_haddr_trace, extract_haddr_output};
    use crate::{Air, CompositeAir, Trace};
    use noid_core::TowerField;

    fn mk_secret(seed: u128) -> [Block128; 2] {
        let s = seed.wrapping_mul(0x9E3779B97F4A7C15);
        [
            Block128::from(s ^ 0xA5A5_A5A5_A5A5_A5A5),
            Block128::from(s.wrapping_add(1) ^ 0x5A5A_5A5A_5A5A_5A5A),
        ]
    }

    /// Build a per-input bridge column layout starting at `base`.
    /// Each input consumes 8 cols (4 hi + 4 lo) plus 2 dst cols.
    fn per_input_budget(base: usize) -> (SharedHAddrInputBudget, usize) {
        (
            SharedHAddrInputBudget {
                t1_hi_budget: T1LaneColumnBudget {
                    bridge_col: base,
                    src_indicator_col: base + 1,
                    dst_indicator_col: base + 2,
                    transition_indicator_col: base + 3,
                },
                t1_lo_budget: T1LaneColumnBudget {
                    bridge_col: base + 4,
                    src_indicator_col: base + 5,
                    dst_indicator_col: base + 6,
                    transition_indicator_col: base + 7,
                },
            },
            base + 8,
        )
    }

    fn build(n_inputs: usize, secrets: Vec<[Block128; 2]>) -> (CompositeAir, Vec<Vec<Block128>>) {
        let inner_n_cols = haddr_multi_n_cols(n_inputs);
        let inner_log_rows = haddr_multi_min_log_rows(n_inputs);
        let outer_log_rows = inner_log_rows + 1;
        let outer_n_rows = 1usize << outer_log_rows;

        // Column layout:
        //   0 .. inner_n_cols                       multi-AIR slab
        //   inner_n_cols                            window indicator
        //   inner_n_cols + 1 ..                     per-input T1 budgets
        //                                           (8 cols each)
        //   then per-input dst cols (2 each)
        let window_indicator_col = inner_n_cols;
        let mut cursor = inner_n_cols + 1;
        let mut inputs = Vec::with_capacity(n_inputs);
        for _ in 0..n_inputs {
            let (budget, next) = per_input_budget(cursor);
            cursor = next;
            // Reserve dst columns after all budgets, but we can
            // allocate them inline per input for simplicity.
            let hi_dst = cursor;
            let lo_dst = cursor + 1;
            cursor += 2;
            inputs.push((
                budget,
                SharedHAddrInputTargets {
                    owner_hi_dst_col: hi_dst,
                    owner_hi_dst_row: (1 << inner_log_rows) + 3,
                    owner_lo_dst_col: lo_dst,
                    owner_lo_dst_row: (1 << inner_log_rows) + 5,
                },
            ));
        }
        let outer_n_cols = cursor;

        let p = SharedHAddrBlockParams {
            n_inputs,
            col_offset: 0,
            window_indicator_col,
            row_window_start: 0,
            outer_n_cols,
            outer_log_rows,
            inputs,
        };

        let wiring = emit_shared_haddr_block(p.clone());
        let air = CompositeAir::from_parts_with_publics(
            outer_log_rows,
            outer_n_cols,
            wiring.constraints,
            wiring.public_columns,
        );

        let mut cols: Vec<Vec<Block128>> = (0..outer_n_cols)
            .map(|_| vec![Block128::ZERO; outer_n_rows])
            .collect();
        let _ = write_shared_haddr_block_trace(&mut cols, &p, &secrets);

        // Overwrite every public column with its declared programme so
        // `Air::check`'s exact-match test passes.
        for pc in air.public_columns() {
            cols[pc.col] = pc.values.clone();
        }

        (air, cols)
    }

    #[test]
    fn honest_one_input_accepts() {
        let (air, cols) = build(1, vec![mk_secret(0x1234)]);
        assert!(air.check(&Trace::new(cols)));
    }

    #[test]
    fn honest_four_inputs_accept() {
        let secrets = (0..4).map(|i| mk_secret(0x1000 + i)).collect::<Vec<_>>();
        let (air, cols) = build(4, secrets);
        assert!(air.check(&Trace::new(cols)));
    }

    #[test]
    fn addr_matches_native_per_input() {
        let secrets = (0..4).map(|i| mk_secret(0xABCD + i)).collect::<Vec<_>>();
        let (_air, cols) = build(4, secrets.clone());
        for (i, s) in secrets.iter().enumerate() {
            let row = haddr_multi_row_output(i);
            let hi = cols[HADDR_MULTI_LAYOUT_B.s][row];
            let lo = cols[HADDR_MULTI_LAYOUT_B.s + 1][row];

            let legacy = build_haddr_trace(*s);
            let [expected_hi, expected_lo] = extract_haddr_output(&legacy);
            assert_eq!(hi, expected_hi, "input {i} hi mismatch");
            assert_eq!(lo, expected_lo, "input {i} lo mismatch");
        }
    }

    #[test]
    fn per_input_dst_tamper_rejects() {
        let secrets = (0..2).map(|i| mk_secret(0xBEEF + i)).collect::<Vec<_>>();
        let (air, mut cols) = build(2, secrets);
        // Tamper input 1's hi dst cell.
        // dst cols per layout: base + 1 (window) + 8 (input 0 bridges)
        //                      + 2 (input 0 dsts) + 8 (input 1 bridges) + 0
        let inner_n_cols = haddr_multi_n_cols(2);
        let hi_dst_input1 = inner_n_cols + 1 + 8 + 2 + 8;
        let hi_dst_row_input1 = (1 << haddr_multi_min_log_rows(2)) + 3;
        cols[hi_dst_input1][hi_dst_row_input1] =
            cols[hi_dst_input1][hi_dst_row_input1] + Block128::ONE;
        assert!(!air.check(&Trace::new(cols)));
    }

    #[test]
    fn cross_input_squeeze_tamper_rejects() {
        // Corrupt input 0's squeezed output cell — its T1 bridge rejects.
        let secrets = (0..2).map(|i| mk_secret(0x7777 + i)).collect::<Vec<_>>();
        let (air, mut cols) = build(2, secrets);
        let row = haddr_multi_row_output(0);
        cols[HADDR_MULTI_LAYOUT_B.s][row] =
            cols[HADDR_MULTI_LAYOUT_B.s][row] + Block128::ONE;
        assert!(!air.check(&Trace::new(cols)));
    }

    #[test]
    fn overhead_formula_matches() {
        assert_eq!(shared_haddr_outer_overhead_cols(0), 1);
        assert_eq!(shared_haddr_outer_overhead_cols(4), 1 + 32);
    }
}
