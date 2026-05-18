// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

#![allow(clippy::needless_range_loop)]

//! Stage 5.1 — cross-row equality bridge primitive.
//!
//! `emit_cross_row_eq` pins `trace[src_col][src_row] ==
//! trace[dst_col][dst_row]` on a single outer trace, even when the two
//! rows are far apart. Implementation uses a witness "bridge" column
//! held constant across an interval spanning the two rows:
//!
//! ```text
//!   bridge[src_row]       == src_col[src_row]   -- src pin
//!   bridge[dst_row]       == dst_col[dst_row]   -- dst pin
//!   bridge[r]             == bridge[r+1]  for r in transition range
//! ```
//!
//! Three cheap single-row / multi-row selector gates, one committed
//! bridge column, no new STARK-layer machinery. Reuses existing
//! primitives ([`WeightedLinearGate`], [`WeightedLinearGateShifted`],
//! [`SelectorGate`], [`PublicColumn`]).
//!
//! Hold policies:
//!
//! - [`BridgeHold::Interval`]: transition fires on
//!   `[min(src_row, dst_row), max(src_row, dst_row))`. Default for
//!   close src/dst — smaller activation surface, no interaction with
//!   unrelated rows.
//! - [`BridgeHold::FullTrace`]: transition fires on every row (including
//!   the cyclic wrap). Default when the interval would cover most of
//!   the trace anyway — slightly simpler programme, no free rows for
//!   the bridge column.
//!
//! Coloring (sharing a single bridge column across disjoint ties) is
//! *not* handled by this primitive; the caller allocates
//! `bridge_col` and the three indicator column ids and may reuse them
//! across ties where programmes coincide.

use crate::gates::const_column::PublicColumn;
use crate::gates::linear::{WeightedLinearGate, WeightedLinearGateShifted};
use crate::gates::row_selector::{multi_row_indicator_programme, row_indicator_programme};
use crate::gates::selector::SelectorGate;
use crate::Constraint;
use noid_core::Block128;

/// Policy selecting the row range across which the bridge column is
/// held constant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BridgeHold {
    /// Hold only across `[min(src_row, dst_row), max(src_row, dst_row)]`.
    /// Transition fires on rows `min..max`. Outside this interval the
    /// bridge column is unconstrained witness.
    Interval,
    /// Hold across the full cyclic trace. Transition fires on every
    /// row, so `bridge[last] == bridge[0]` is also enforced. Bridge
    /// carries a single constant throughout.
    FullTrace,
}

/// Caller-allocated columns for a single cross-row equality bridge.
#[derive(Debug, Clone, Copy)]
pub struct BridgeParams {
    /// Witness column that carries the held value.
    pub bridge_col: usize,
    /// Source cell: `(col, row)` providing the value.
    pub src_col: usize,
    pub src_row: usize,
    /// Destination cell: `(col, row)` that must match the source.
    pub dst_col: usize,
    pub dst_row: usize,
    /// Trace height (power of two).
    pub total_rows: usize,
    /// Hold policy.
    pub hold: BridgeHold,
    /// `PublicColumn` column id for the src-pin single-row indicator.
    pub src_indicator_col: usize,
    /// `PublicColumn` column id for the dst-pin single-row indicator.
    pub dst_indicator_col: usize,
    /// `PublicColumn` column id for the transition multi-row indicator.
    pub transition_indicator_col: usize,
}

/// Output bundle from [`emit_cross_row_eq`]. Caller appends these to
/// its AIR's public-column / constraint lists.
pub struct BridgeWiring {
    pub public_columns: Vec<PublicColumn>,
    pub constraints: Vec<Box<dyn Constraint>>,
}

fn assert_params(p: &BridgeParams) {
    assert!(
        p.total_rows.is_power_of_two() && p.total_rows > 1,
        "emit_cross_row_eq: total_rows must be a power of two > 1"
    );
    assert!(
        p.src_row < p.total_rows,
        "emit_cross_row_eq: src_row out of range"
    );
    assert!(
        p.dst_row < p.total_rows,
        "emit_cross_row_eq: dst_row out of range"
    );
    assert_ne!(
        p.src_row, p.dst_row,
        "emit_cross_row_eq: src_row and dst_row must differ (use emit_column_eq_at_row for same-row ties)"
    );

    // Bridge / src / dst / indicator columns must all be distinct.
    let cols = [
        ("bridge", p.bridge_col),
        ("src", p.src_col),
        ("dst", p.dst_col),
        ("src_indicator", p.src_indicator_col),
        ("dst_indicator", p.dst_indicator_col),
        ("transition_indicator", p.transition_indicator_col),
    ];
    for i in 0..cols.len() {
        for j in (i + 1)..cols.len() {
            // src_col == dst_col is *permitted* (same-column, different-row
            // tie is a valid use — "this column is constant across rows
            // r and s"). All other pairs must differ.
            let same_col_pair = (cols[i].0 == "src" && cols[j].0 == "dst")
                || (cols[i].0 == "dst" && cols[j].0 == "src");
            if same_col_pair {
                continue;
            }
            assert_ne!(
                cols[i].1, cols[j].1,
                "emit_cross_row_eq: columns {} and {} must differ (both = {})",
                cols[i].0, cols[j].0, cols[i].1
            );
        }
    }
}

/// Emit the full bridge wiring (indicators + src-pin + dst-pin +
/// transition). The caller must still write the witness values into
/// the bridge column (use [`write_bridge_column`]).
pub fn emit_cross_row_eq(p: BridgeParams) -> BridgeWiring {
    assert_params(&p);

    let (lo, hi) = if p.src_row < p.dst_row {
        (p.src_row, p.dst_row)
    } else {
        (p.dst_row, p.src_row)
    };

    // ----- Indicator programmes ------------------------------------------------
    let src_programme = row_indicator_programme(p.src_row, p.total_rows);
    let dst_programme = row_indicator_programme(p.dst_row, p.total_rows);
    let transition_rows: Vec<usize> = match p.hold {
        BridgeHold::Interval => (lo..hi).collect(),
        BridgeHold::FullTrace => (0..p.total_rows).collect(),
    };
    let transition_programme = multi_row_indicator_programme(&transition_rows, p.total_rows);

    let public_columns = vec![
        PublicColumn::new(p.src_indicator_col, src_programme),
        PublicColumn::new(p.dst_indicator_col, dst_programme),
        PublicColumn::new(p.transition_indicator_col, transition_programme),
    ];

    // ----- Gates ---------------------------------------------------------------
    // Src pin: bridge[src_row] + src_col[src_row] == 0 (XOR).
    let src_inner: Box<dyn Constraint> =
        Box::new(WeightedLinearGate::new_xor(vec![p.bridge_col, p.src_col]));
    let src_gate: Box<dyn Constraint> = Box::new(SelectorGate::new(p.src_indicator_col, src_inner));

    // Dst pin: bridge[dst_row] + dst_col[dst_row] == 0 (XOR).
    let dst_inner: Box<dyn Constraint> =
        Box::new(WeightedLinearGate::new_xor(vec![p.bridge_col, p.dst_col]));
    let dst_gate: Box<dyn Constraint> = Box::new(SelectorGate::new(p.dst_indicator_col, dst_inner));

    // Transition: bridge[r] + bridge[r+1] == 0 on every row where
    // transition indicator is hot. `new_xor_next(col, col)` aliases
    // the two sides onto the same column — legitimate per
    // `WeightedLinearGateShifted` construction rules.
    let transition_inner: Box<dyn Constraint> = Box::new(WeightedLinearGateShifted::new_xor_next(
        p.bridge_col,
        p.bridge_col,
    ));
    let transition_gate: Box<dyn Constraint> = Box::new(SelectorGate::new(
        p.transition_indicator_col,
        transition_inner,
    ));

    BridgeWiring {
        public_columns,
        constraints: vec![src_gate, dst_gate, transition_gate],
    }
}

/// Write the bridge column's witness values for a single tie. `value`
/// is the shared src/dst cell value; the bridge column must carry it
/// on every row of the transition range.
///
/// Out-of-interval rows of an `Interval` bridge are left at
/// whatever the caller pre-initialised them to (typically `ZERO`).
pub fn write_bridge_column(cols: &mut [Vec<Block128>], p: &BridgeParams, value: Block128) {
    let (lo, hi) = if p.src_row < p.dst_row {
        (p.src_row, p.dst_row)
    } else {
        (p.dst_row, p.src_row)
    };
    let col = &mut cols[p.bridge_col];
    match p.hold {
        BridgeHold::Interval => {
            for r in lo..=hi {
                col[r] = value;
            }
        }
        BridgeHold::FullTrace => {
            for r in 0..p.total_rows {
                col[r] = value;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Air, CompositeAir, Trace};
    use noid_core::TowerField;

    /// Build a small trace with a bridge wiring and verify the check
    /// accepts / rejects as expected. Layout:
    ///   col 0 — src column
    ///   col 1 — dst column
    ///   col 2 — bridge
    ///   col 3 — src_indicator
    ///   col 4 — dst_indicator
    ///   col 5 — transition_indicator
    fn scaffold(
        hold: BridgeHold,
        src_row: usize,
        dst_row: usize,
        total_rows: usize,
    ) -> (BridgeParams, CompositeAir) {
        let p = BridgeParams {
            bridge_col: 2,
            src_col: 0,
            src_row,
            dst_col: 1,
            dst_row,
            total_rows,
            hold,
            src_indicator_col: 3,
            dst_indicator_col: 4,
            transition_indicator_col: 5,
        };
        let w = emit_cross_row_eq(p);
        let log_rows = total_rows.trailing_zeros() as usize;
        let air =
            CompositeAir::from_parts_with_publics(log_rows, 6, w.constraints, w.public_columns);
        (p, air)
    }

    fn make_trace(
        p: &BridgeParams,
        hold: BridgeHold,
        src_val: Block128,
        dst_val: Block128,
    ) -> Trace {
        let n = p.total_rows;
        let mut cols: Vec<Vec<Block128>> = (0..6).map(|_| vec![Block128::ZERO; n]).collect();
        cols[p.src_col][p.src_row] = src_val;
        cols[p.dst_col][p.dst_row] = dst_val;
        // Bridge witness: assume honest prover (value == src_val == dst_val).
        write_bridge_column(&mut cols, p, src_val);
        // Indicator programmes (matching the emitted PublicColumns).
        cols[p.src_indicator_col][p.src_row] = Block128::ONE;
        cols[p.dst_indicator_col][p.dst_row] = Block128::ONE;
        let (lo, hi) = if p.src_row < p.dst_row {
            (p.src_row, p.dst_row)
        } else {
            (p.dst_row, p.src_row)
        };
        match hold {
            BridgeHold::Interval => {
                for r in lo..hi {
                    cols[p.transition_indicator_col][r] = Block128::ONE;
                }
            }
            BridgeHold::FullTrace => {
                for r in 0..n {
                    cols[p.transition_indicator_col][r] = Block128::ONE;
                }
            }
        }
        Trace::new(cols)
    }

    #[test]
    fn honest_interval_accepts() {
        let (p, air) = scaffold(BridgeHold::Interval, 1, 6, 16);
        let v = Block128::from(0xDEAD_BEEFu128);
        let trace = make_trace(&p, BridgeHold::Interval, v, v);
        assert!(air.check(&trace));
    }

    #[test]
    fn honest_full_trace_accepts() {
        let (p, air) = scaffold(BridgeHold::FullTrace, 1, 14, 16);
        let v = Block128::from(0xC0FFEEu128);
        let trace = make_trace(&p, BridgeHold::FullTrace, v, v);
        assert!(air.check(&trace));
    }

    #[test]
    fn mismatched_dst_rejected() {
        let (p, air) = scaffold(BridgeHold::Interval, 1, 6, 16);
        let v = Block128::from(0x1111u128);
        let v2 = Block128::from(0x2222u128);
        let trace = make_trace(&p, BridgeHold::Interval, v, v2);
        assert!(!air.check(&trace));
    }

    #[test]
    fn tampered_bridge_cell_in_interval_rejected() {
        let (p, air) = scaffold(BridgeHold::Interval, 1, 6, 16);
        let v = Block128::from(0xAAu128);
        let n = p.total_rows;
        let mut cols: Vec<Vec<Block128>> = (0..6).map(|_| vec![Block128::ZERO; n]).collect();
        cols[p.src_col][p.src_row] = v;
        cols[p.dst_col][p.dst_row] = v;
        write_bridge_column(&mut cols, &p, v);
        // Flip one interior bridge cell — transition gate catches it.
        cols[p.bridge_col][3] = v + Block128::ONE;
        cols[p.src_indicator_col][p.src_row] = Block128::ONE;
        cols[p.dst_indicator_col][p.dst_row] = Block128::ONE;
        for r in p.src_row..p.dst_row {
            cols[p.transition_indicator_col][r] = Block128::ONE;
        }
        let trace = Trace::new(cols);
        assert!(!air.check(&trace));
    }

    #[test]
    fn interval_leaves_outside_rows_free() {
        // Bridge is unconstrained outside the interval; a garbage value
        // at row 0 or row (total_rows - 1) does not reject.
        let (p, air) = scaffold(BridgeHold::Interval, 4, 10, 16);
        let v = Block128::from(0x42u128);
        let n = p.total_rows;
        let mut cols: Vec<Vec<Block128>> = (0..6).map(|_| vec![Block128::ZERO; n]).collect();
        cols[p.src_col][p.src_row] = v;
        cols[p.dst_col][p.dst_row] = v;
        write_bridge_column(&mut cols, &p, v);
        cols[p.bridge_col][0] = Block128::from(0xBADu128);
        cols[p.bridge_col][15] = Block128::from(0xBAD2u128);
        cols[p.src_indicator_col][p.src_row] = Block128::ONE;
        cols[p.dst_indicator_col][p.dst_row] = Block128::ONE;
        for r in p.src_row..p.dst_row {
            cols[p.transition_indicator_col][r] = Block128::ONE;
        }
        let trace = Trace::new(cols);
        assert!(air.check(&trace));
    }

    #[test]
    fn full_trace_catches_far_tamper() {
        // FullTrace constrains every row including the cyclic wrap, so
        // a tamper anywhere is caught.
        let (p, air) = scaffold(BridgeHold::FullTrace, 3, 9, 16);
        let v = Block128::from(0x77u128);
        let mut cols: Vec<Vec<Block128>> =
            (0..6).map(|_| vec![Block128::ZERO; p.total_rows]).collect();
        cols[p.src_col][p.src_row] = v;
        cols[p.dst_col][p.dst_row] = v;
        write_bridge_column(&mut cols, &p, v);
        // Tamper a row far outside the src..dst interval.
        cols[p.bridge_col][14] = v + Block128::ONE;
        cols[p.src_indicator_col][p.src_row] = Block128::ONE;
        cols[p.dst_indicator_col][p.dst_row] = Block128::ONE;
        for r in 0..p.total_rows {
            cols[p.transition_indicator_col][r] = Block128::ONE;
        }
        let trace = Trace::new(cols);
        assert!(!air.check(&trace));
    }

    #[test]
    fn src_row_greater_than_dst_row_interval_ok() {
        // Hold interval = [min, max] regardless of argument order.
        let (p, air) = scaffold(BridgeHold::Interval, 12, 3, 16);
        let v = Block128::from(0x55u128);
        let trace = make_trace(&p, BridgeHold::Interval, v, v);
        assert!(air.check(&trace));
    }

    #[test]
    fn same_column_different_rows_allowed() {
        // src_col == dst_col — valid tie ("column is constant across
        // rows r and s"). Layout shifts src/dst onto column 0, bridge
        // elsewhere.
        let p = BridgeParams {
            bridge_col: 1,
            src_col: 0,
            src_row: 2,
            dst_col: 0,
            dst_row: 7,
            total_rows: 16,
            hold: BridgeHold::Interval,
            src_indicator_col: 2,
            dst_indicator_col: 3,
            transition_indicator_col: 4,
        };
        let w = emit_cross_row_eq(p);
        let air = CompositeAir::from_parts_with_publics(4, 5, w.constraints, w.public_columns);
        let v = Block128::from(0x88u128);
        let mut cols: Vec<Vec<Block128>> = (0..5).map(|_| vec![Block128::ZERO; 16]).collect();
        cols[0][2] = v;
        cols[0][7] = v;
        write_bridge_column(&mut cols, &p, v);
        cols[2][2] = Block128::ONE;
        cols[3][7] = Block128::ONE;
        for r in 2..7 {
            cols[4][r] = Block128::ONE;
        }
        let trace = Trace::new(cols);
        assert!(air.check(&trace));

        // And rejects when col 0 disagrees at row 7.
        let mut cols_bad: Vec<Vec<Block128>> = (0..5).map(|_| vec![Block128::ZERO; 16]).collect();
        cols_bad[0][2] = v;
        cols_bad[0][7] = v + Block128::ONE;
        write_bridge_column(&mut cols_bad, &p, v);
        cols_bad[2][2] = Block128::ONE;
        cols_bad[3][7] = Block128::ONE;
        for r in 2..7 {
            cols_bad[4][r] = Block128::ONE;
        }
        assert!(!air.check(&Trace::new(cols_bad)));
    }

    // ---- Tamper matrix ------------------------------------------------------
    //
    // For every declared cell of the wiring (src value, dst value, each
    // bridge row inside the active interval, each indicator row), a
    // single flip must be caught by *some* gate. Exhaustive over all
    // interior cells of a small trace.

    #[test]
    fn tamper_matrix_interval() {
        let (p, air) = scaffold(BridgeHold::Interval, 2, 9, 16);
        let v = Block128::from(0xABCDu128);

        // Build one honest trace column vector; each tamper clones it,
        // flips one cell, checks reject.
        let mut honest: Vec<Vec<Block128>> = (0..6).map(|_| vec![Block128::ZERO; 16]).collect();
        honest[p.src_col][p.src_row] = v;
        honest[p.dst_col][p.dst_row] = v;
        write_bridge_column(&mut honest, &p, v);
        honest[p.src_indicator_col][p.src_row] = Block128::ONE;
        honest[p.dst_indicator_col][p.dst_row] = Block128::ONE;
        for r in p.src_row..p.dst_row {
            honest[p.transition_indicator_col][r] = Block128::ONE;
        }
        assert!(air.check(&Trace::new(honest.clone())));

        let flip = Block128::ONE;

        // Flip src cell.
        {
            let mut t = honest.clone();
            t[p.src_col][p.src_row] += flip;
            assert!(!air.check(&Trace::new(t)), "src cell tamper undetected");
        }
        // Flip dst cell.
        {
            let mut t = honest.clone();
            t[p.dst_col][p.dst_row] += flip;
            assert!(!air.check(&Trace::new(t)), "dst cell tamper undetected");
        }
        // Flip each bridge cell inside [src_row, dst_row].
        for r in p.src_row..=p.dst_row {
            let mut t = honest.clone();
            t[p.bridge_col][r] += flip;
            assert!(
                !air.check(&Trace::new(t)),
                "bridge cell tamper at row {r} undetected"
            );
        }
        // Flip each indicator cell (both directions: turning on a silent
        // row, turning off the hot row).
        for r in 0..p.total_rows {
            let mut t = honest.clone();
            t[p.src_indicator_col][r] += flip;
            assert!(
                !air.check(&Trace::new(t)),
                "src indicator row {r} tamper undetected"
            );
        }
        for r in 0..p.total_rows {
            let mut t = honest.clone();
            t[p.dst_indicator_col][r] += flip;
            assert!(
                !air.check(&Trace::new(t)),
                "dst indicator row {r} tamper undetected"
            );
        }
        for r in 0..p.total_rows {
            let mut t = honest.clone();
            t[p.transition_indicator_col][r] += flip;
            assert!(
                !air.check(&Trace::new(t)),
                "transition indicator row {r} tamper undetected"
            );
        }
    }

    #[test]
    #[should_panic(expected = "src_row and dst_row must differ")]
    fn rejects_same_row() {
        let _ = emit_cross_row_eq(BridgeParams {
            bridge_col: 2,
            src_col: 0,
            src_row: 3,
            dst_col: 1,
            dst_row: 3,
            total_rows: 16,
            hold: BridgeHold::Interval,
            src_indicator_col: 3,
            dst_indicator_col: 4,
            transition_indicator_col: 5,
        });
    }

    #[test]
    #[should_panic(expected = "must differ")]
    fn rejects_bridge_aliases_indicator() {
        let _ = emit_cross_row_eq(BridgeParams {
            bridge_col: 3,
            src_col: 0,
            src_row: 1,
            dst_col: 1,
            dst_row: 6,
            total_rows: 16,
            hold: BridgeHold::Interval,
            src_indicator_col: 3,
            dst_indicator_col: 4,
            transition_indicator_col: 5,
        });
    }

    #[test]
    #[should_panic(expected = "power of two")]
    fn rejects_non_power_of_two_rows() {
        let _ = emit_cross_row_eq(BridgeParams {
            bridge_col: 2,
            src_col: 0,
            src_row: 1,
            dst_col: 1,
            dst_row: 3,
            total_rows: 7,
            hold: BridgeHold::Interval,
            src_indicator_col: 3,
            dst_indicator_col: 4,
            transition_indicator_col: 5,
        });
    }

    #[test]
    #[should_panic(expected = "out of range")]
    fn rejects_row_out_of_range() {
        let _ = emit_cross_row_eq(BridgeParams {
            bridge_col: 2,
            src_col: 0,
            src_row: 16,
            dst_col: 1,
            dst_row: 3,
            total_rows: 16,
            hold: BridgeHold::Interval,
            src_indicator_col: 3,
            dst_indicator_col: 4,
            transition_indicator_col: 5,
        });
    }
}
