// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Stage 5.4 — T1 owner-lane tie primitive.
//!
//! T1 pins, per tx input `i`:
//!
//! ```text
//!   HAddrAir<i>.s_B[0]@OUTPUT_ROW  ==  FriStateOpenAir.owner_hi[lane = i]
//!   HAddrAir<i>.s_B[1]@OUTPUT_ROW  ==  FriStateOpenAir.owner_lo[lane = i]
//! ```
//!
//! Each input needs two cross-row equality bridges — one per owner
//! lane. This module exposes a typed façade over [`emit_cross_row_eq`]
//! that packages the four caller-allocated outer columns per bridge
//! (bridge + src/dst/transition indicators) into a single
//! [`T1LaneColumnBudget`]. The caller wires two budgets per input
//! (hi, lo) and appends the returned [`BridgeWiring`] to its composite.
//!
//! The helper is intentionally independent of the outer composite's
//! column / row layout: it reads the src and dst `(col, row)` pairs
//! directly and delegates the soundness argument to the bridge
//! primitive. That keeps it reusable across the Stage 5.4 and 5.7
//! embeddings without coupling either to the other.

use crate::composition::bridge::{
    emit_cross_row_eq, write_bridge_column, BridgeHold, BridgeParams, BridgeWiring,
};
use crate::gates::const_column::PublicColumn;
use crate::Constraint;
use noid_core::Block128;

/// Four outer columns the caller allocates for a single T1 lane bridge.
#[derive(Debug, Clone, Copy)]
pub struct T1LaneColumnBudget {
    pub bridge_col: usize,
    pub src_indicator_col: usize,
    pub dst_indicator_col: usize,
    pub transition_indicator_col: usize,
}

/// One T1 lane tie: source cell (HAddr squeeze) and destination cell
/// (FriStateOpen owner lane).
#[derive(Debug, Clone, Copy)]
pub struct T1LaneTie {
    pub src_col: usize,
    pub src_row: usize,
    pub dst_col: usize,
    pub dst_row: usize,
}

/// Emit the bridge wiring for a single owner lane.
pub fn emit_t1_lane(
    tie: T1LaneTie,
    budget: T1LaneColumnBudget,
    outer_n_rows: usize,
) -> BridgeWiring {
    emit_cross_row_eq(BridgeParams {
        bridge_col: budget.bridge_col,
        src_col: tie.src_col,
        src_row: tie.src_row,
        dst_col: tie.dst_col,
        dst_row: tie.dst_row,
        total_rows: outer_n_rows,
        hold: BridgeHold::Interval,
        src_indicator_col: budget.src_indicator_col,
        dst_indicator_col: budget.dst_indicator_col,
        transition_indicator_col: budget.transition_indicator_col,
    })
}

/// Populate the bridge column of a single T1 lane tie on the outer
/// trace. `value` is the shared src/dst cell value (either the honest
/// HAddr squeeze or equivalently the FriStateOpen owner lane).
pub fn write_t1_lane_bridge(
    cols: &mut [Vec<Block128>],
    tie: T1LaneTie,
    budget: T1LaneColumnBudget,
    outer_n_rows: usize,
    value: Block128,
) {
    let params = BridgeParams {
        bridge_col: budget.bridge_col,
        src_col: tie.src_col,
        src_row: tie.src_row,
        dst_col: tie.dst_col,
        dst_row: tie.dst_row,
        total_rows: outer_n_rows,
        hold: BridgeHold::Interval,
        src_indicator_col: budget.src_indicator_col,
        dst_indicator_col: budget.dst_indicator_col,
        transition_indicator_col: budget.transition_indicator_col,
    };
    write_bridge_column(cols, &params, value);
}

/// Two lane budgets + two lane ties for one input's full T1 binding
/// (hi + lo).
#[derive(Debug, Clone, Copy)]
pub struct T1InputWiring {
    pub hi: (T1LaneTie, T1LaneColumnBudget),
    pub lo: (T1LaneTie, T1LaneColumnBudget),
}

// -- Stage 5.5 aliases --------------------------------------------------
// The T1 primitive is generic cell-to-cell equality. Stage 5.5's T2a
// (auth-tag) and T2b (tx-body-hash) ties reuse it unchanged. These
// aliases exist purely to make 5.5 call sites self-documenting.

/// Stage 5.5 alias — same shape as [`T1LaneColumnBudget`]. Used for
/// both T2a (HAuth squeeze → TxValidity auth-tag cell) and T2b (HAuth
/// pre-MDS B seed → shared tx-body-hash cell).
pub type LaneBridgeBudget = T1LaneColumnBudget;

/// Stage 5.5 alias — same shape as [`T1LaneTie`]. A single `(src, dst)`
/// cell pair the bridge enforces equality on.
pub type LaneBridgeTie = T1LaneTie;

/// Emit the full T1 wiring for one input: both lane bridges, public
/// indicator columns concatenated, constraints concatenated.
pub fn emit_t1_input(
    input: T1InputWiring,
    outer_n_rows: usize,
) -> (Vec<PublicColumn>, Vec<Box<dyn Constraint>>) {
    let hi = emit_t1_lane(input.hi.0, input.hi.1, outer_n_rows);
    let lo = emit_t1_lane(input.lo.0, input.lo.1, outer_n_rows);
    let mut public_columns = hi.public_columns;
    public_columns.extend(lo.public_columns);
    let mut constraints = hi.constraints;
    constraints.extend(lo.constraints);
    (public_columns, constraints)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Air, CompositeAir, Trace};
    use noid_core::TowerField;

    /// Scaffold: 10-column outer trace, 16 rows. Emulates an HAddr
    /// squeeze cell at (col 0, row 5) and a FriStateOpen owner lane
    /// at (col 1, row 11). The four remaining bridge/indicator cols
    /// per lane sit at 2..6 (hi) and 6..10 (lo). We exercise the `hi`
    /// lane only in this mini-scaffold; the `lo` lane is covered by
    /// the paired `emit_t1_input` test below.
    const OUTER_LOG_ROWS: usize = 4;
    const OUTER_N_ROWS: usize = 1 << OUTER_LOG_ROWS;

    fn lane_scaffold_hi() -> (T1LaneTie, T1LaneColumnBudget, CompositeAir) {
        let tie = T1LaneTie {
            src_col: 0,
            src_row: 5,
            dst_col: 1,
            dst_row: 11,
        };
        let budget = T1LaneColumnBudget {
            bridge_col: 2,
            src_indicator_col: 3,
            dst_indicator_col: 4,
            transition_indicator_col: 5,
        };
        let w = emit_t1_lane(tie, budget, OUTER_N_ROWS);
        let air = CompositeAir::from_parts_with_publics(
            OUTER_LOG_ROWS,
            10,
            w.constraints,
            w.public_columns,
        );
        (tie, budget, air)
    }

    fn honest_hi_trace(
        tie: T1LaneTie,
        budget: T1LaneColumnBudget,
        v: Block128,
    ) -> Vec<Vec<Block128>> {
        let mut cols: Vec<Vec<Block128>> =
            (0..10).map(|_| vec![Block128::ZERO; OUTER_N_ROWS]).collect();
        cols[tie.src_col][tie.src_row] = v;
        cols[tie.dst_col][tie.dst_row] = v;
        write_t1_lane_bridge(&mut cols, tie, budget, OUTER_N_ROWS, v);
        cols[budget.src_indicator_col][tie.src_row] = Block128::ONE;
        cols[budget.dst_indicator_col][tie.dst_row] = Block128::ONE;
        let (lo, hi) = if tie.src_row < tie.dst_row {
            (tie.src_row, tie.dst_row)
        } else {
            (tie.dst_row, tie.src_row)
        };
        for r in lo..hi {
            cols[budget.transition_indicator_col][r] = Block128::ONE;
        }
        cols
    }

    #[test]
    fn t1_lane_honest_accepts() {
        let (tie, budget, air) = lane_scaffold_hi();
        let v = Block128::from(0xA5A5_0000_DEAD_BEEF_u128);
        let cols = honest_hi_trace(tie, budget, v);
        assert!(air.check(&Trace::new(cols)));
    }

    #[test]
    fn t1_lane_src_tamper_rejects() {
        let (tie, budget, air) = lane_scaffold_hi();
        let v = Block128::from(0x1234_5678_u128);
        let mut cols = honest_hi_trace(tie, budget, v);
        cols[tie.src_col][tie.src_row] =
            cols[tie.src_col][tie.src_row] + Block128::ONE;
        assert!(!air.check(&Trace::new(cols)));
    }

    #[test]
    fn t1_lane_dst_tamper_rejects() {
        let (tie, budget, air) = lane_scaffold_hi();
        let v = Block128::from(0xCAFE_F00D_u128);
        let mut cols = honest_hi_trace(tie, budget, v);
        cols[tie.dst_col][tie.dst_row] =
            cols[tie.dst_col][tie.dst_row] + Block128::ONE;
        assert!(!air.check(&Trace::new(cols)));
    }

    #[test]
    fn t1_lane_interior_bridge_tamper_rejects() {
        let (tie, budget, air) = lane_scaffold_hi();
        let v = Block128::from(0x5555_u128);
        let mut cols = honest_hi_trace(tie, budget, v);
        cols[budget.bridge_col][7] =
            cols[budget.bridge_col][7] + Block128::ONE;
        assert!(!air.check(&Trace::new(cols)));
    }

    #[test]
    fn t1_lane_outside_interval_free() {
        // Bridge column outside [src_row, dst_row] is unconstrained.
        let (tie, budget, air) = lane_scaffold_hi();
        let v = Block128::from(0x42_u128);
        let mut cols = honest_hi_trace(tie, budget, v);
        // Row 0 is below the interval [5, 11]; row 15 is above it.
        cols[budget.bridge_col][0] = Block128::from(0xDEAD_u128);
        cols[budget.bridge_col][15] = Block128::from(0xBEEF_u128);
        assert!(air.check(&Trace::new(cols)));
    }

    /// Scaffold for the paired (hi, lo) wiring: two independent lanes
    /// share the same src/dst column pair but different rows (hi at
    /// row 5/11, lo at row 5/11 on lane-distinct cols).
    fn input_scaffold() -> (T1InputWiring, CompositeAir) {
        let wiring = T1InputWiring {
            hi: (
                T1LaneTie {
                    src_col: 0,
                    src_row: 5,
                    dst_col: 2,
                    dst_row: 11,
                },
                T1LaneColumnBudget {
                    bridge_col: 4,
                    src_indicator_col: 5,
                    dst_indicator_col: 6,
                    transition_indicator_col: 7,
                },
            ),
            lo: (
                T1LaneTie {
                    src_col: 1,
                    src_row: 5,
                    dst_col: 3,
                    dst_row: 11,
                },
                T1LaneColumnBudget {
                    bridge_col: 8,
                    src_indicator_col: 9,
                    dst_indicator_col: 10,
                    transition_indicator_col: 11,
                },
            ),
        };
        let (publics, constraints) = emit_t1_input(wiring, OUTER_N_ROWS);
        let air = CompositeAir::from_parts_with_publics(
            OUTER_LOG_ROWS,
            12,
            constraints,
            publics,
        );
        (wiring, air)
    }

    fn honest_input_trace(wiring: T1InputWiring, vhi: Block128, vlo: Block128) -> Vec<Vec<Block128>> {
        let mut cols: Vec<Vec<Block128>> =
            (0..12).map(|_| vec![Block128::ZERO; OUTER_N_ROWS]).collect();

        // hi lane
        let (tie, budget) = wiring.hi;
        cols[tie.src_col][tie.src_row] = vhi;
        cols[tie.dst_col][tie.dst_row] = vhi;
        write_t1_lane_bridge(&mut cols, tie, budget, OUTER_N_ROWS, vhi);
        cols[budget.src_indicator_col][tie.src_row] = Block128::ONE;
        cols[budget.dst_indicator_col][tie.dst_row] = Block128::ONE;
        for r in tie.src_row..tie.dst_row {
            cols[budget.transition_indicator_col][r] = Block128::ONE;
        }

        // lo lane
        let (tie, budget) = wiring.lo;
        cols[tie.src_col][tie.src_row] = vlo;
        cols[tie.dst_col][tie.dst_row] = vlo;
        write_t1_lane_bridge(&mut cols, tie, budget, OUTER_N_ROWS, vlo);
        cols[budget.src_indicator_col][tie.src_row] = Block128::ONE;
        cols[budget.dst_indicator_col][tie.dst_row] = Block128::ONE;
        for r in tie.src_row..tie.dst_row {
            cols[budget.transition_indicator_col][r] = Block128::ONE;
        }

        cols
    }

    #[test]
    fn t1_input_honest_accepts() {
        let (wiring, air) = input_scaffold();
        let cols = honest_input_trace(
            wiring,
            Block128::from(0x1111_u128),
            Block128::from(0x2222_u128),
        );
        assert!(air.check(&Trace::new(cols)));
    }

    #[test]
    fn t1_input_hi_tamper_rejects() {
        // Tamper the hi-lane dst while lo lane stays honest — the hi
        // bridge still rejects.
        let (wiring, air) = input_scaffold();
        let mut cols = honest_input_trace(
            wiring,
            Block128::from(0x3333_u128),
            Block128::from(0x4444_u128),
        );
        let (tie_hi, _) = wiring.hi;
        cols[tie_hi.dst_col][tie_hi.dst_row] =
            cols[tie_hi.dst_col][tie_hi.dst_row] + Block128::ONE;
        assert!(!air.check(&Trace::new(cols)));
    }

    #[test]
    fn t1_input_lo_tamper_rejects() {
        let (wiring, air) = input_scaffold();
        let mut cols = honest_input_trace(
            wiring,
            Block128::from(0x5555_u128),
            Block128::from(0x6666_u128),
        );
        let (tie_lo, _) = wiring.lo;
        cols[tie_lo.dst_col][tie_lo.dst_row] =
            cols[tie_lo.dst_col][tie_lo.dst_row] + Block128::ONE;
        assert!(!air.check(&Trace::new(cols)));
    }

    #[test]
    fn t1_input_independent_lanes() {
        // Ensure hi and lo lanes use disjoint bridge / indicator cols.
        let w = T1InputWiring {
            hi: (
                T1LaneTie {
                    src_col: 0,
                    src_row: 5,
                    dst_col: 2,
                    dst_row: 11,
                },
                T1LaneColumnBudget {
                    bridge_col: 4,
                    src_indicator_col: 5,
                    dst_indicator_col: 6,
                    transition_indicator_col: 7,
                },
            ),
            lo: (
                T1LaneTie {
                    src_col: 1,
                    src_row: 5,
                    dst_col: 3,
                    dst_row: 11,
                },
                T1LaneColumnBudget {
                    bridge_col: 8,
                    src_indicator_col: 9,
                    dst_indicator_col: 10,
                    transition_indicator_col: 11,
                },
            ),
        };
        let hi_cols = [
            w.hi.1.bridge_col,
            w.hi.1.src_indicator_col,
            w.hi.1.dst_indicator_col,
            w.hi.1.transition_indicator_col,
        ];
        let lo_cols = [
            w.lo.1.bridge_col,
            w.lo.1.src_indicator_col,
            w.lo.1.dst_indicator_col,
            w.lo.1.transition_indicator_col,
        ];
        for h in hi_cols {
            for l in lo_cols {
                assert_ne!(h, l, "hi / lo lane col alias: {h} == {l}");
            }
        }
    }
}
