// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Stage 5.2 — [`RowWindowWrapper`]: embed a sub-AIR's constraints
//! and public columns into a larger outer trace at
//! `(col_offset, row_window)`.
//!
//! The wrapper does four things:
//!
//! 1. **Column remap.** Every inner constraint's column indices are
//!    shifted by `col_offset` via an inline `ShiftedColumnsConstraint`
//!    adapter that relies on the project-wide "gates read
//!    `frame.local[i]` by ordinal" invariant.
//! 2. **Row silencing** (`WrapPolicy::MaskOff`). Each shifted
//!    constraint is wrapped in a [`SelectorGate`] driven by a
//!    multi-hot window indicator `PublicColumn` that is `ONE` on
//!    `[row_window_start, row_window_end)` and `ZERO` elsewhere.
//! 3. **Public-column lift.** Each inner `PublicColumn`'s column
//!    index is shifted by `col_offset`; its `values` vector is
//!    re-padded from `2^inner_log_rows` to `2^outer_log_rows` with
//!    `ZERO` outside the window. Caller guarantees the inner's
//!    public-column programmes already hold zero on inner rows
//!    outside the relevant live range (every shipped AIR does).
//! 4. **Terminator pins** (`WrapPolicy::TerminatorPin`). For sub-AIRs
//!    whose cyclic `next(last_inner_row) = first_inner_row` read is
//!    load-bearing (`Air::requires_true_cyclic_wrap() == true`), the
//!    wrapper additionally emits one [`emit_cross_row_eq`] bridge per
//!    shifted column, pinning
//!    `trace[col][row_window_end] == trace[col][row_window_start]`.
//!    (The last inner row's shifted read lands on outer row
//!    `row_window_end`, so that's the cell the bridge's dst pin ties
//!    back to `row_window_start`.)
//!    This restores the logical cyclic tie that the window break
//!    would otherwise drop. MaskOff is rejected at wrap time for
//!    such sub-AIRs.

use crate::composition::bridge::{emit_cross_row_eq, BridgeHold, BridgeParams};
use crate::gates::const_column::PublicColumn;
use crate::gates::row_selector::multi_row_indicator_programme;
use crate::gates::selector::SelectorGate;
use crate::{Constraint, EvalFrame, FlatEvalFrame};
use noid_core::{Block128, TowerField};

/// Wrap policy controlling how the inner AIR's cyclic-wrap semantics
/// are reconciled with being embedded on a sub-interval of the outer
/// trace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WrapPolicy {
    /// Silence every inner constraint on outer rows outside
    /// `[row_window_start, row_window_end)`. Safe when the inner AIR
    /// either uses no `shifted_columns` or gates cross-instance wraps
    /// behind its own `is_reset` / indicator selectors (i.e.
    /// `Air::requires_true_cyclic_wrap() == false`).
    MaskOff,
    /// `MaskOff` plus one [`emit_cross_row_eq`] boundary pin per
    /// shifted column, tying
    /// `trace[col][row_window_end] == trace[col][row_window_start]`.
    /// Required for sub-AIRs whose cyclic wrap is load-bearing.
    TerminatorPin,
}

/// Immutable view of a sub-AIR's wiring, ready to be wrapped.
///
/// Caller destructures the sub-AIR into these four fields. The
/// wrapper consumes them and produces an embedded wiring bundle.
pub struct InnerAirView {
    pub inner_n_cols: usize,
    pub inner_log_rows: usize,
    pub constraints: Vec<Box<dyn Constraint>>,
    pub public_columns: Vec<PublicColumn>,
    /// Set to `true` iff the sub-AIR reports
    /// `Air::requires_true_cyclic_wrap() == true`. The wrapper
    /// asserts policy compatibility against this flag.
    pub requires_true_cyclic_wrap: bool,
}

/// Parameters for a single [`RowWindowWrapper::wrap`] call.
#[derive(Debug, Clone)]
pub struct RowWindowParams {
    /// Column offset at which the sub-AIR starts in the outer trace.
    pub col_offset: usize,
    /// Outer trace column count. Used for bounds assertions and
    /// bridge-column allocation.
    pub outer_n_cols: usize,
    /// Outer `log_rows`. `2^outer_log_rows` must be `>= row_window_end`.
    pub outer_log_rows: usize,
    /// Row interval the sub-AIR occupies, half-open:
    /// `[row_window_start, row_window_end)`. The window width must
    /// equal `2^inner_log_rows` (the wrapper does not support
    /// sub-instance embedding — a sub-AIR is placed whole).
    pub row_window_start: usize,
    pub row_window_end: usize,
    /// Outer column reserved for the window's multi-hot indicator.
    /// Allocated by the composite; unique per embedded placement.
    pub window_indicator_col: usize,
    pub policy: WrapPolicy,
    /// Bridge / indicator columns used by [`WrapPolicy::TerminatorPin`].
    /// Ignored under [`WrapPolicy::MaskOff`]. Length must equal
    /// `3 * inner_shifted_cols.len() + inner_shifted_cols.len()` —
    /// i.e. four outer columns (bridge + 3 indicators) per shifted
    /// inner column. Allocation is the caller's responsibility.
    pub terminator_pin_cols: Vec<TerminatorPinCols>,
}

/// Column allocations for a single [`WrapPolicy::TerminatorPin`]
/// boundary pin: four outer columns per shifted inner column.
#[derive(Debug, Clone, Copy)]
pub struct TerminatorPinCols {
    /// Inner-relative column index (shifted-reads column). The
    /// wrapper applies `col_offset` internally.
    pub inner_col: usize,
    pub bridge_col: usize,
    pub src_indicator_col: usize,
    pub dst_indicator_col: usize,
    pub transition_indicator_col: usize,
}

/// Output of [`RowWindowWrapper::wrap`]: wrapped constraints plus the
/// window indicator and any terminator-pin public columns. Caller
/// appends to the outer composite's lists.
pub struct RowWindowWiring {
    pub constraints: Vec<Box<dyn Constraint>>,
    pub public_columns: Vec<PublicColumn>,
}

// ---------------------------------------------------------------------------
// Column-offset adapter (internal; not re-exported)
// ---------------------------------------------------------------------------

struct ShiftedColumnsConstraint {
    inner: Box<dyn Constraint>,
    shifted_cols: Vec<usize>,
    shifted_next: Vec<usize>,
}

impl ShiftedColumnsConstraint {
    fn new(inner: Box<dyn Constraint>, offset: usize, inner_n_cols: usize) -> Self {
        for &c in inner.columns() {
            assert!(
                c < inner_n_cols,
                "RowWindowWrapper: inner local column {c} out of inner range [0, {inner_n_cols})"
            );
        }
        for &c in inner.shifted_columns() {
            assert!(
                c < inner_n_cols,
                "RowWindowWrapper: inner shifted column {c} out of inner range [0, {inner_n_cols})"
            );
        }
        let shifted_cols = inner.columns().iter().map(|&c| c + offset).collect();
        let shifted_next = inner
            .shifted_columns()
            .iter()
            .map(|&c| c + offset)
            .collect();
        Self {
            inner,
            shifted_cols,
            shifted_next,
        }
    }
}

impl Constraint for ShiftedColumnsConstraint {
    fn degree(&self) -> usize {
        self.inner.degree()
    }
    fn columns(&self) -> &[usize] {
        &self.shifted_cols
    }
    fn shifted_columns(&self) -> &[usize] {
        &self.shifted_next
    }
    fn evaluate(&self, frame: EvalFrame) -> Block128 {
        self.inner.evaluate(frame)
    }
    fn evaluate_flat(&self, frame: FlatEvalFrame) -> u128 {
        self.inner.evaluate_flat(frame)
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

pub struct RowWindowWrapper;

impl RowWindowWrapper {
    /// Embed `inner` at `(col_offset, row_window)` in an outer trace
    /// of shape `(outer_n_cols, 2^outer_log_rows)`. Returns the
    /// wrapped constraint list and all public columns the caller
    /// must append to the outer composite.
    pub fn wrap(mut inner: InnerAirView, params: RowWindowParams) -> RowWindowWiring {
        let outer_n_rows = 1usize << params.outer_log_rows;
        let inner_n_rows = 1usize << inner.inner_log_rows;

        // ---- Parameter validation ------------------------------------------
        assert!(
            params.row_window_end > params.row_window_start,
            "RowWindowWrapper: row window must be non-empty"
        );
        assert!(
            params.row_window_end <= outer_n_rows,
            "RowWindowWrapper: row_window_end {} exceeds outer_n_rows {}",
            params.row_window_end,
            outer_n_rows,
        );
        assert_eq!(
            params.row_window_end - params.row_window_start,
            inner_n_rows,
            "RowWindowWrapper: window width {} must equal inner n_rows {}",
            params.row_window_end - params.row_window_start,
            inner_n_rows,
        );
        assert!(
            params.col_offset + inner.inner_n_cols <= params.outer_n_cols,
            "RowWindowWrapper: col_offset + inner_n_cols ({} + {}) exceeds outer_n_cols {}",
            params.col_offset,
            inner.inner_n_cols,
            params.outer_n_cols,
        );
        assert!(
            params.window_indicator_col < params.outer_n_cols,
            "RowWindowWrapper: window_indicator_col {} >= outer_n_cols {}",
            params.window_indicator_col,
            params.outer_n_cols,
        );
        // Indicator must not alias any shifted inner column.
        assert!(
            params.window_indicator_col < params.col_offset
                || params.window_indicator_col >= params.col_offset + inner.inner_n_cols,
            "RowWindowWrapper: window_indicator_col {} collides with inner column band [{}, {})",
            params.window_indicator_col,
            params.col_offset,
            params.col_offset + inner.inner_n_cols,
        );

        // ---- Policy / wrap compatibility -----------------------------------
        match params.policy {
            WrapPolicy::MaskOff => {
                assert!(
                    !inner.requires_true_cyclic_wrap,
                    "RowWindowWrapper: sub-AIR requires load-bearing cyclic wrap; MaskOff policy illegal (use TerminatorPin)"
                );
            }
            WrapPolicy::TerminatorPin => {
                // TerminatorPin needs row_window_end to be a valid outer
                // row (the bridge dst row), i.e. strictly inside the
                // trace.
                assert!(
                    params.row_window_end < outer_n_rows,
                    "RowWindowWrapper: TerminatorPin requires row_window_end {} < outer_n_rows {} (dst pin lands on row_window_end)",
                    params.row_window_end,
                    outer_n_rows,
                );
                // TerminatorPin pins every inner-shifted column on the
                // window boundary. Collect the sorted, deduplicated
                // union first.
                let mut shifted_cols: Vec<usize> = Vec::new();
                for c in &inner.constraints {
                    for &j in c.shifted_columns() {
                        if !shifted_cols.contains(&j) {
                            shifted_cols.push(j);
                        }
                    }
                }
                shifted_cols.sort_unstable();
                assert_eq!(
                    params.terminator_pin_cols.len(),
                    shifted_cols.len(),
                    "RowWindowWrapper: TerminatorPin requires one column-allocation per shifted inner column ({} shifted, {} allocations)",
                    shifted_cols.len(),
                    params.terminator_pin_cols.len(),
                );
                // Every allocated inner_col must actually appear in the
                // shifted union.
                for pin in &params.terminator_pin_cols {
                    assert!(
                        shifted_cols.contains(&pin.inner_col),
                        "RowWindowWrapper: TerminatorPin inner_col {} not in shifted column union",
                        pin.inner_col,
                    );
                }
            }
        }

        // ---- Build the window indicator ------------------------------------
        let window_rows: Vec<usize> = (params.row_window_start..params.row_window_end).collect();
        let window_programme = multi_row_indicator_programme(&window_rows, outer_n_rows);
        let window_pc = PublicColumn::new(params.window_indicator_col, window_programme);

        // ---- Wrap every inner constraint: shift cols, then gate by window --
        let mut wrapped_constraints: Vec<Box<dyn Constraint>> =
            Vec::with_capacity(inner.constraints.len());
        for c in inner.constraints.drain(..) {
            let shifted: Box<dyn Constraint> = Box::new(ShiftedColumnsConstraint::new(
                c,
                params.col_offset,
                inner.inner_n_cols,
            ));
            let gated: Box<dyn Constraint> =
                Box::new(SelectorGate::new(params.window_indicator_col, shifted));
            wrapped_constraints.push(gated);
        }

        // ---- Lift inner public columns --------------------------------------
        let mut public_columns: Vec<PublicColumn> = Vec::with_capacity(
            inner.public_columns.len()
                + 1
                + if matches!(params.policy, WrapPolicy::TerminatorPin) {
                    3 * params.terminator_pin_cols.len()
                } else {
                    0
                },
        );
        for pc in inner.public_columns.drain(..) {
            assert!(
                pc.col < inner.inner_n_cols,
                "RowWindowWrapper: inner public column {} escapes inner range [0, {})",
                pc.col,
                inner.inner_n_cols,
            );
            assert_eq!(
                pc.values.len(),
                inner_n_rows,
                "RowWindowWrapper: inner public column {} has length {} (expected inner_n_rows = {})",
                pc.col,
                pc.values.len(),
                inner_n_rows,
            );
            let mut lifted = vec![Block128::ZERO; outer_n_rows];
            for (i, v) in pc.values.into_iter().enumerate() {
                lifted[params.row_window_start + i] = v;
            }
            public_columns.push(PublicColumn::new(pc.col + params.col_offset, lifted));
        }
        public_columns.push(window_pc);

        // ---- Terminator pins ------------------------------------------------
        if matches!(params.policy, WrapPolicy::TerminatorPin) {
            for pin in &params.terminator_pin_cols {
                let outer_col = params.col_offset + pin.inner_col;
                let bw = emit_cross_row_eq(BridgeParams {
                    bridge_col: pin.bridge_col,
                    src_col: outer_col,
                    src_row: params.row_window_start,
                    dst_col: outer_col,
                    dst_row: params.row_window_end,
                    total_rows: outer_n_rows,
                    hold: BridgeHold::Interval,
                    src_indicator_col: pin.src_indicator_col,
                    dst_indicator_col: pin.dst_indicator_col,
                    transition_indicator_col: pin.transition_indicator_col,
                });
                public_columns.extend(bw.public_columns);
                wrapped_constraints.extend(bw.constraints);
            }
        }

        // ---- Final range checks ---------------------------------------------
        for c in &wrapped_constraints {
            for &j in c.columns() {
                assert!(
                    j < params.outer_n_cols,
                    "RowWindowWrapper: wrapped constraint reads outer col {j} >= outer_n_cols {}",
                    params.outer_n_cols
                );
            }
            for &j in c.shifted_columns() {
                assert!(
                    j < params.outer_n_cols,
                    "RowWindowWrapper: wrapped constraint shifted col {j} >= outer_n_cols {}",
                    params.outer_n_cols
                );
            }
        }
        for pc in &public_columns {
            assert!(
                pc.col < params.outer_n_cols,
                "RowWindowWrapper: public column {} >= outer_n_cols {}",
                pc.col,
                params.outer_n_cols,
            );
            assert_eq!(
                pc.values.len(),
                outer_n_rows,
                "RowWindowWrapper: public column {} values length {} != outer_n_rows {}",
                pc.col,
                pc.values.len(),
                outer_n_rows,
            );
        }

        RowWindowWiring {
            constraints: wrapped_constraints,
            public_columns,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gates::linear::{WeightedLinearGate, WeightedLinearGateShifted};
    use crate::{Air, CompositeAir, Trace};

    /// Build a trivial inner "AIR": a single `col_a + col_b == 0` gate
    /// over a 4-row inner shape, no public columns. Useful for
    /// isolating wrapper behavior from real AIR complexity.
    fn make_inner_xor() -> InnerAirView {
        let gate: Box<dyn Constraint> = Box::new(WeightedLinearGate::new_xor(vec![0, 1]));
        InnerAirView {
            inner_n_cols: 2,
            inner_log_rows: 2,
            constraints: vec![gate],
            public_columns: vec![],
            requires_true_cyclic_wrap: false,
        }
    }

    /// Build the embedded outer AIR and trace from a scaffold.
    /// Outer shape: 8 columns × 16 rows.
    ///   col 0–1 : inner payload (col_offset = 0)
    ///   col 2   : window indicator
    ///   col 3   : bridge (unused under MaskOff)
    ///   col 4   : src indicator  (unused under MaskOff)
    ///   col 5   : dst indicator  (unused under MaskOff)
    ///   col 6   : transition indicator (unused under MaskOff)
    ///   col 7   : free row payload outside the window
    fn scaffold_mask_off(row_start: usize, row_end: usize) -> (CompositeAir, Vec<Vec<Block128>>) {
        let inner = make_inner_xor();
        let params = RowWindowParams {
            col_offset: 0,
            outer_n_cols: 8,
            outer_log_rows: 4,
            row_window_start: row_start,
            row_window_end: row_end,
            window_indicator_col: 2,
            policy: WrapPolicy::MaskOff,
            terminator_pin_cols: vec![],
        };
        let w = RowWindowWrapper::wrap(inner, params);
        let air = CompositeAir::from_parts_with_publics(4, 8, w.constraints, w.public_columns);
        let cols = vec![vec![Block128::ZERO; 16]; 8];
        (air, cols)
    }

    #[test]
    fn mask_off_all_zero_trace_accepts() {
        let (air, mut cols) = scaffold_mask_off(4, 8);
        // Window indicator (col 2) must match the programme the wrapper emitted.
        for r in 4..8 {
            cols[2][r] = Block128::ONE;
        }
        let trace = Trace::new(cols);
        assert!(air.check(&trace));
    }

    #[test]
    fn mask_off_enforces_inside_window() {
        let (air, mut cols) = scaffold_mask_off(4, 8);
        for r in 4..8 {
            cols[2][r] = Block128::ONE;
        }
        // Break the XOR at row 5: col_a = 1, col_b = 0.
        cols[0][5] = Block128::ONE;
        let trace = Trace::new(cols);
        assert!(!air.check(&trace));
    }

    #[test]
    fn mask_off_silent_outside_window() {
        let (air, mut cols) = scaffold_mask_off(4, 8);
        for r in 4..8 {
            cols[2][r] = Block128::ONE;
        }
        // XOR violation at row 1 (outside window): gate is silenced.
        cols[0][1] = Block128::ONE;
        let trace = Trace::new(cols);
        assert!(air.check(&trace));
    }

    #[test]
    fn mask_off_rejects_tampered_window_indicator() {
        let (air, mut cols) = scaffold_mask_off(4, 8);
        // Programme says indicator hot on [4,8); tamper puts a stray
        // hot bit at row 0.
        cols[2][0] = Block128::ONE;
        for r in 4..8 {
            cols[2][r] = Block128::ONE;
        }
        let trace = Trace::new(cols);
        assert!(!air.check(&trace));
    }

    #[test]
    fn mask_off_public_column_lifted_and_padded() {
        // Inner declares a public column on its col 0, hot only on
        // inner row 2 (mimics a boundary-tie indicator inside the
        // sub-AIR).
        let mut inner = make_inner_xor();
        let mut values = vec![Block128::ZERO; 4];
        values[2] = Block128::ONE;
        inner.public_columns = vec![PublicColumn::new(0, values)];
        // Re-emit the XOR gate reading col 1 only (col 0 is now
        // occupied by the public-column constraint's data column — but
        // since we already declared the constraint list above, swap to
        // a gate that doesn't touch col 0).
        inner.constraints = vec![Box::new(WeightedLinearGate::new(
            vec![(1, Block128::ONE)],
            Block128::ZERO,
        ))];

        let params = RowWindowParams {
            col_offset: 3,
            outer_n_cols: 8,
            outer_log_rows: 4,
            row_window_start: 8,
            row_window_end: 12,
            window_indicator_col: 0,
            policy: WrapPolicy::MaskOff,
            terminator_pin_cols: vec![],
        };
        let w = RowWindowWrapper::wrap(inner, params);
        // Public column for inner col 0 should land at outer col 3,
        // values[row] = ONE iff row == 8 + 2 == 10.
        let lifted = w
            .public_columns
            .iter()
            .find(|pc| pc.col == 3)
            .expect("lifted public column missing");
        for (row, &v) in lifted.values.iter().enumerate() {
            let want = if row == 10 {
                Block128::ONE
            } else {
                Block128::ZERO
            };
            assert_eq!(v, want, "row {row}");
        }
    }

    // -----------------------------------------------------------------------
    // Terminator-pin scenario: inner AIR whose last-row wrap is load-bearing.
    // The fake inner asserts `col0[r] == col0[r+1]` on every row (constant-
    // column constraint). Under MaskOff, the constraint at the last inner
    // row reads col0[outer_row_window_end] which is free witness outside
    // the window — the constraint vanishes incorrectly. TerminatorPin adds
    // a bridge pinning col0[row_window_end] == col0[row_window_start].
    // -----------------------------------------------------------------------

    fn make_inner_constant_col() -> InnerAirView {
        // col0[r] + col0[r+1] == 0 on every row.
        let gate: Box<dyn Constraint> = Box::new(WeightedLinearGateShifted::new_xor_next(0, 0));
        InnerAirView {
            inner_n_cols: 1,
            inner_log_rows: 2,
            constraints: vec![gate],
            public_columns: vec![],
            requires_true_cyclic_wrap: true,
        }
    }

    #[test]
    #[should_panic(expected = "load-bearing cyclic wrap")]
    fn mask_off_rejects_inner_requiring_cyclic_wrap() {
        let inner = make_inner_constant_col();
        let params = RowWindowParams {
            col_offset: 0,
            outer_n_cols: 8,
            outer_log_rows: 4,
            row_window_start: 4,
            row_window_end: 8,
            window_indicator_col: 1,
            policy: WrapPolicy::MaskOff,
            terminator_pin_cols: vec![],
        };
        let _ = RowWindowWrapper::wrap(inner, params);
    }

    #[test]
    fn terminator_pin_restores_cyclic_tie() {
        // Inner is "col0 constant across all inner rows". Embed at
        // rows [4, 8) with TerminatorPin.
        let inner = make_inner_constant_col();
        let params = RowWindowParams {
            col_offset: 0,
            outer_n_cols: 8,
            outer_log_rows: 4,
            row_window_start: 4,
            row_window_end: 8,
            window_indicator_col: 1,
            policy: WrapPolicy::TerminatorPin,
            terminator_pin_cols: vec![TerminatorPinCols {
                inner_col: 0,
                bridge_col: 2,
                src_indicator_col: 3,
                dst_indicator_col: 4,
                transition_indicator_col: 5,
            }],
        };
        let w = RowWindowWrapper::wrap(inner, params);
        let air = CompositeAir::from_parts_with_publics(4, 8, w.constraints, w.public_columns);

        // Honest trace: col 0 constant = 0xAA on rows 4..8, bridge
        // interval covers [row_start, row_end-1] = [4, 7]. Wait — src
        // = row_start (4), dst = row_end - 1 (7). BridgeHold::Interval
        // is [4, 7]. We need col 0 at row 4 and row 7 to be equal, via
        // the bridge.
        let v = Block128::from(0xAAu128);
        let mut cols: Vec<Vec<Block128>> = (0..8).map(|_| vec![Block128::ZERO; 16]).collect();
        // col 0 must equal v on [row_window_start, row_window_end]
        // (inclusive) so the inner constraint at last-inner-row reading
        // col[row_window_end] also holds.
        for r in 4..=8 {
            cols[0][r] = v;
        }
        // Window indicator [4, 8).
        for r in 4..8 {
            cols[1][r] = Block128::ONE;
        }
        // Bridge column: hot across [row_window_start, row_window_end].
        for r in 4..=8 {
            cols[2][r] = v;
        }
        // Bridge src/dst/transition indicators.
        cols[3][4] = Block128::ONE; // src at row_window_start
        cols[4][8] = Block128::ONE; // dst at row_window_end
        for r in 4..8 {
            cols[5][r] = Block128::ONE;
        }
        let trace = Trace::new(cols);
        assert!(air.check(&trace));
    }

    #[test]
    fn terminator_pin_rejects_broken_boundary() {
        let inner = make_inner_constant_col();
        let params = RowWindowParams {
            col_offset: 0,
            outer_n_cols: 8,
            outer_log_rows: 4,
            row_window_start: 4,
            row_window_end: 8,
            window_indicator_col: 1,
            policy: WrapPolicy::TerminatorPin,
            terminator_pin_cols: vec![TerminatorPinCols {
                inner_col: 0,
                bridge_col: 2,
                src_indicator_col: 3,
                dst_indicator_col: 4,
                transition_indicator_col: 5,
            }],
        };
        let w = RowWindowWrapper::wrap(inner, params);
        let air = CompositeAir::from_parts_with_publics(4, 8, w.constraints, w.public_columns);

        // Break: col0[row_window_end] != col0[row_window_start]. The
        // bridge's dst pin catches the boundary mismatch.
        let v = Block128::from(0xAAu128);
        let v2 = Block128::from(0xBBu128);
        let mut cols: Vec<Vec<Block128>> = (0..8).map(|_| vec![Block128::ZERO; 16]).collect();
        for r in 4..8 {
            cols[0][r] = v;
        }
        cols[0][8] = v2; // broken boundary
        for r in 4..8 {
            cols[1][r] = Block128::ONE;
        }
        for r in 4..=8 {
            cols[2][r] = v;
        }
        cols[3][4] = Block128::ONE;
        cols[4][8] = Block128::ONE;
        for r in 4..8 {
            cols[5][r] = Block128::ONE;
        }
        let trace = Trace::new(cols);
        assert!(!air.check(&trace));
    }

    // -----------------------------------------------------------------------
    // Adversarial attack suite (Stage 4.95 §7 deliverable):
    // malicious rebasing / overlapping windows / selector leakage /
    // masked constraint bypass / shifted-column escape.
    // -----------------------------------------------------------------------

    /// Attack 1 — **malicious rebasing**: prover swaps window indicator
    /// to fire on a different row range than declared. `PublicColumn`
    /// check rejects.
    #[test]
    fn attack_malicious_rebasing_rejected() {
        let (air, mut cols) = scaffold_mask_off(4, 8);
        // Declared window: rows 4..8. Prover writes 8..12 instead —
        // shifts where the inner gate fires. PublicColumn rejects
        // because the programme does not match.
        for r in 8..12 {
            cols[2][r] = Block128::ONE;
        }
        let trace = Trace::new(cols);
        assert!(!air.check(&trace));
    }

    /// Attack 2 — **selector leakage**: prover writes the window
    /// indicator *also* hot on one extra row outside the declared
    /// range, hoping to "silence" extra rows under some future
    /// constraint. Indicator programme rejects.
    #[test]
    fn attack_selector_leakage_rejected() {
        let (air, mut cols) = scaffold_mask_off(4, 8);
        for r in 4..8 {
            cols[2][r] = Block128::ONE;
        }
        cols[2][12] = Block128::ONE; // unauthorized hot bit
        let trace = Trace::new(cols);
        assert!(!air.check(&trace));
    }

    /// Attack 3 — **masked constraint bypass**: prover disables the
    /// indicator entirely (all zero), hoping the inner gate vanishes
    /// everywhere. Indicator programme rejects the tampered column.
    #[test]
    fn attack_masked_constraint_bypass_rejected() {
        let (air, mut cols) = scaffold_mask_off(4, 8);
        // Indicator all zero — no hot bit at all.
        for r in 0..16 {
            cols[2][r] = Block128::ZERO;
        }
        let trace = Trace::new(cols);
        assert!(!air.check(&trace));
    }

    /// Attack 4 — **shifted-column escape**: under `TerminatorPin`,
    /// prover sets the boundary cells correctly but tampers an interior
    /// bridge cell, hoping the transition gate misses it. Transition
    /// gate fires on every interior row → reject.
    #[test]
    fn attack_shifted_column_escape_rejected() {
        let inner = make_inner_constant_col();
        let params = RowWindowParams {
            col_offset: 0,
            outer_n_cols: 8,
            outer_log_rows: 4,
            row_window_start: 4,
            row_window_end: 8,
            window_indicator_col: 1,
            policy: WrapPolicy::TerminatorPin,
            terminator_pin_cols: vec![TerminatorPinCols {
                inner_col: 0,
                bridge_col: 2,
                src_indicator_col: 3,
                dst_indicator_col: 4,
                transition_indicator_col: 5,
            }],
        };
        let w = RowWindowWrapper::wrap(inner, params);
        let air = CompositeAir::from_parts_with_publics(4, 8, w.constraints, w.public_columns);

        let v = Block128::from(0xAAu128);
        let mut cols: Vec<Vec<Block128>> = (0..8).map(|_| vec![Block128::ZERO; 16]).collect();
        for r in 4..=8 {
            cols[0][r] = v;
        }
        for r in 4..8 {
            cols[1][r] = Block128::ONE;
        }
        // Bridge: correct at boundary, corrupted in interior.
        cols[2][4] = v;
        cols[2][5] = v + Block128::ONE; // interior tamper
        cols[2][6] = v;
        cols[2][7] = v;
        cols[2][8] = v;
        cols[3][4] = Block128::ONE;
        cols[4][8] = Block128::ONE;
        for r in 4..8 {
            cols[5][r] = Block128::ONE;
        }
        let trace = Trace::new(cols);
        assert!(!air.check(&trace));
    }

    // -----------------------------------------------------------------------
    // Bounds / argument validation panics
    // -----------------------------------------------------------------------

    #[test]
    #[should_panic(expected = "window width")]
    fn window_width_mismatch_rejected() {
        let inner = make_inner_xor();
        let params = RowWindowParams {
            col_offset: 0,
            outer_n_cols: 8,
            outer_log_rows: 4,
            row_window_start: 0,
            row_window_end: 8, // width 8, inner n_rows = 4
            window_indicator_col: 2,
            policy: WrapPolicy::MaskOff,
            terminator_pin_cols: vec![],
        };
        let _ = RowWindowWrapper::wrap(inner, params);
    }

    #[test]
    #[should_panic(expected = "exceeds outer_n_rows")]
    fn row_window_overflow_rejected() {
        let inner = make_inner_xor();
        let params = RowWindowParams {
            col_offset: 0,
            outer_n_cols: 8,
            outer_log_rows: 4,
            row_window_start: 16,
            row_window_end: 20,
            window_indicator_col: 2,
            policy: WrapPolicy::MaskOff,
            terminator_pin_cols: vec![],
        };
        let _ = RowWindowWrapper::wrap(inner, params);
    }

    #[test]
    #[should_panic(expected = "exceeds outer_n_cols")]
    fn col_offset_overflow_rejected() {
        let inner = make_inner_xor();
        let params = RowWindowParams {
            col_offset: 10,
            outer_n_cols: 8,
            outer_log_rows: 4,
            row_window_start: 0,
            row_window_end: 4,
            window_indicator_col: 1,
            policy: WrapPolicy::MaskOff,
            terminator_pin_cols: vec![],
        };
        let _ = RowWindowWrapper::wrap(inner, params);
    }

    #[test]
    #[should_panic(expected = "collides with inner column band")]
    fn window_indicator_aliases_inner_rejected() {
        let inner = make_inner_xor();
        let params = RowWindowParams {
            col_offset: 0,
            outer_n_cols: 8,
            outer_log_rows: 4,
            row_window_start: 0,
            row_window_end: 4,
            // col 0 is inside the inner column band [0, 2).
            window_indicator_col: 0,
            policy: WrapPolicy::MaskOff,
            terminator_pin_cols: vec![],
        };
        let _ = RowWindowWrapper::wrap(inner, params);
    }

    #[test]
    #[should_panic(expected = "requires one column-allocation")]
    fn terminator_pin_mismatched_alloc_rejected() {
        let inner = make_inner_constant_col();
        let params = RowWindowParams {
            col_offset: 0,
            outer_n_cols: 8,
            outer_log_rows: 4,
            row_window_start: 4,
            row_window_end: 8,
            window_indicator_col: 1,
            policy: WrapPolicy::TerminatorPin,
            terminator_pin_cols: vec![], // empty, but inner has one shifted column
        };
        let _ = RowWindowWrapper::wrap(inner, params);
    }
}
