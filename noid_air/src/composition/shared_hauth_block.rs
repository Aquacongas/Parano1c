// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! OP-1.γ / OP-1.δ.3 — `SharedHAuthBlock`: single embedded
//! [`HAuthMultiAir`] + `n_inputs` T2a lane bridges (hi + lo) +
//! **one** shared T2b lane bridge pair.
//!
//! # Column budget
//!
//! | span                                                       | role |
//! |------------------------------------------------------------|------|
//! | `col_offset .. col_offset + hauth_multi_n_cols(n_inputs)`  | HAuthMultiAir slab |
//! | `window_indicator_col`                                     | window indicator |
//! | per input `i`: 8 outer cols                                | T2a hi + T2a lo bridges |
//! | 8 outer cols (shared)                                      | T2b hi + T2b lo bridges |
//!
//! T2a destinations remain per-input (squeezed tag differs per
//! secret). T2b, however, binds the shared
//! `tx_body_col[0..2]@row 0` witness columns inside the AIR to the
//! single canonical `tx_body_hash` origin cell pair. The AIR's
//! `tx_body_col` is enforced constant across rows by a shifted-XOR
//! gate, so binding it at row 0 fixes the value the B-carry reads at
//! every input's `row_N_ROUNDS`.
//!
//! # Soundness
//!
//! [`HAuthMultiAir`] pins each input's row-0 / row-N_ROUNDS /
//! row-2N+1 boundary ties with single-hot per-input indicators. The
//! `tx_body_col[0..2]` columns are pinned constant across rows; the
//! single T2b bridge on row 0 ties them to the external
//! `tx_body_hash` origin. The B-carry at row-N_ROUNDS reads from
//! `tx_body_col` instead of a hard-coded AIR constant, which lets the
//! caller point T2b at a dst (e.g. `TxBodyMerkleAir`'s wrap-output)
//! whose value is determined only at trace-construction time.

use crate::airs::hauth_multi::{
    build_hauth_multi_trace, hauth_multi_min_log_rows, hauth_multi_n_cols,
    hauth_multi_row_output, HAuthMultiAir, HAUTH_MULTI_LAYOUT_C,
    HAUTH_MULTI_TX_BODY_BASE,
};
use crate::composition::row_window::{
    InnerAirView, RowWindowParams, RowWindowWiring, RowWindowWrapper, WrapPolicy,
};
use crate::composition::t1_owner_tie::{
    emit_t1_lane, write_t1_lane_bridge, LaneBridgeBudget, LaneBridgeTie,
};
use crate::gates::const_column::PublicColumn;
use crate::Constraint;
use noid_core::Block128;

/// Per-input bridge column budget: two T2a lane bridges
/// (T2a hi + T2a lo), 4 cols each = 8 cols total.
#[derive(Debug, Clone, Copy)]
pub struct SharedHAuthInputBudget {
    pub t2a_hi_budget: LaneBridgeBudget,
    pub t2a_lo_budget: LaneBridgeBudget,
}

/// Per-input T2a destination cells. `auth_tag_*` carry the squeezed
/// tag into `TxValidityCol::AuthTag{Hi,Lo}[i]`.
#[derive(Debug, Clone, Copy)]
pub struct SharedHAuthInputTargets {
    pub auth_tag_hi_dst_col: usize,
    pub auth_tag_hi_dst_row: usize,
    pub auth_tag_lo_dst_col: usize,
    pub auth_tag_lo_dst_row: usize,
}

/// Shared T2b lane-bridge budget + destination for the
/// `tx_body_col[0..2]@row 0` binding. Both hi/lo lanes bridge to the
/// same external origin cell pair (consecutive columns, same row).
#[derive(Debug, Clone, Copy)]
pub struct SharedHAuthTxBodyBinding {
    pub hi_budget: LaneBridgeBudget,
    pub lo_budget: LaneBridgeBudget,
    pub hi_dst_col: usize,
    pub hi_dst_row: usize,
    pub lo_dst_col: usize,
    pub lo_dst_row: usize,
}

/// Parameters for a single [`emit_shared_hauth_block`] call.
#[derive(Debug, Clone)]
pub struct SharedHAuthBlockParams {
    pub n_inputs: usize,
    pub col_offset: usize,
    pub window_indicator_col: usize,
    pub row_window_start: usize,
    pub outer_n_cols: usize,
    pub outer_log_rows: usize,
    pub tx_body_hash: [Block128; 2],
    pub inputs: Vec<(SharedHAuthInputBudget, SharedHAuthInputTargets)>,
    pub tx_body_binding: SharedHAuthTxBodyBinding,
}

/// Output of [`emit_shared_hauth_block`].
pub struct SharedHAuthBlockWiring {
    pub constraints: Vec<Box<dyn Constraint>>,
    pub public_columns: Vec<PublicColumn>,
    /// For each input `i`: squeezed-tag hi/lo src cells.
    pub per_input_cells: Vec<InputCells>,
    /// Shared `tx_body_col@row 0` hi/lo src cells.
    pub tx_body_cells: TxBodyCells,
}

#[derive(Debug, Clone, Copy)]
pub struct InputCells {
    pub tag_hi_cell: (usize, usize),
    pub tag_lo_cell: (usize, usize),
}

#[derive(Debug, Clone, Copy)]
pub struct TxBodyCells {
    pub hi_cell: (usize, usize),
    pub lo_cell: (usize, usize),
}

/// Emit the full wiring for a shared HAuth block.
pub fn emit_shared_hauth_block(p: SharedHAuthBlockParams) -> SharedHAuthBlockWiring {
    assert_eq!(p.inputs.len(), p.n_inputs);
    let outer_n_rows = 1usize << p.outer_log_rows;
    let inner_log_rows = hauth_multi_min_log_rows(p.n_inputs);
    let inner_n_rows = 1usize << inner_log_rows;
    assert!(
        p.row_window_start + inner_n_rows <= outer_n_rows,
        "emit_shared_hauth_block: window [{}, {}) exceeds outer rows {}",
        p.row_window_start,
        p.row_window_start + inner_n_rows,
        outer_n_rows,
    );

    // 1) Wrap the multi-AIR.
    let air = HAuthMultiAir::new(p.n_inputs, inner_log_rows);
    let inner_n_cols = hauth_multi_n_cols(p.n_inputs);
    let (reported_n_cols, constraints_inner, publics_inner) = air.into_parts();
    assert_eq!(reported_n_cols, inner_n_cols);

    let inner_view = InnerAirView {
        inner_n_cols,
        inner_log_rows,
        constraints: constraints_inner,
        public_columns: publics_inner,
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

    // 2) Per-input T2a bridges.
    let mut per_input_cells = Vec::with_capacity(p.n_inputs);
    for (i, (budget, target)) in p.inputs.iter().enumerate() {
        let squeezed_hi_col = p.col_offset + HAUTH_MULTI_LAYOUT_C.s;
        let squeezed_lo_col = p.col_offset + HAUTH_MULTI_LAYOUT_C.s + 1;
        let squeezed_row = p.row_window_start + hauth_multi_row_output(i);

        // T2a hi.
        let t2a_hi_tie = LaneBridgeTie {
            src_col: squeezed_hi_col,
            src_row: squeezed_row,
            dst_col: target.auth_tag_hi_dst_col,
            dst_row: target.auth_tag_hi_dst_row,
        };
        let w = emit_t1_lane(t2a_hi_tie, budget.t2a_hi_budget, outer_n_rows);
        public_columns.extend(w.public_columns);
        constraints.extend(w.constraints);

        // T2a lo.
        let t2a_lo_tie = LaneBridgeTie {
            src_col: squeezed_lo_col,
            src_row: squeezed_row,
            dst_col: target.auth_tag_lo_dst_col,
            dst_row: target.auth_tag_lo_dst_row,
        };
        let w = emit_t1_lane(t2a_lo_tie, budget.t2a_lo_budget, outer_n_rows);
        public_columns.extend(w.public_columns);
        constraints.extend(w.constraints);

        per_input_cells.push(InputCells {
            tag_hi_cell: (squeezed_hi_col, squeezed_row),
            tag_lo_cell: (squeezed_lo_col, squeezed_row),
        });
    }

    // 3) Single shared T2b bridge tying tx_body_col[0..2]@row 0 to the
    //    external canonical tx_body_hash origin.
    let tx_body_hi_col = p.col_offset + HAUTH_MULTI_TX_BODY_BASE;
    let tx_body_lo_col = p.col_offset + HAUTH_MULTI_TX_BODY_BASE + 1;
    let tx_body_row = p.row_window_start;

    let t2b_hi_tie = LaneBridgeTie {
        src_col: tx_body_hi_col,
        src_row: tx_body_row,
        dst_col: p.tx_body_binding.hi_dst_col,
        dst_row: p.tx_body_binding.hi_dst_row,
    };
    let w = emit_t1_lane(t2b_hi_tie, p.tx_body_binding.hi_budget, outer_n_rows);
    public_columns.extend(w.public_columns);
    constraints.extend(w.constraints);

    let t2b_lo_tie = LaneBridgeTie {
        src_col: tx_body_lo_col,
        src_row: tx_body_row,
        dst_col: p.tx_body_binding.lo_dst_col,
        dst_row: p.tx_body_binding.lo_dst_row,
    };
    let w = emit_t1_lane(t2b_lo_tie, p.tx_body_binding.lo_budget, outer_n_rows);
    public_columns.extend(w.public_columns);
    constraints.extend(w.constraints);

    SharedHAuthBlockWiring {
        constraints,
        public_columns,
        per_input_cells,
        tx_body_cells: TxBodyCells {
            hi_cell: (tx_body_hi_col, tx_body_row),
            lo_cell: (tx_body_lo_col, tx_body_row),
        },
    }
}

/// Per-input squeeze values extracted from the honest trace.
#[derive(Debug, Clone, Copy)]
pub struct SharedHAuthInputCells {
    pub tag: [Block128; 2],
}

/// Populate the outer trace with an honest shared HAuth block + all
/// bridge columns.
pub fn write_shared_hauth_block_trace(
    cols: &mut [Vec<Block128>],
    p: &SharedHAuthBlockParams,
    secrets: &[[Block128; 2]],
) -> Vec<SharedHAuthInputCells> {
    assert_eq!(secrets.len(), p.n_inputs);
    let outer_n_rows = 1usize << p.outer_log_rows;
    let inner_log_rows = hauth_multi_min_log_rows(p.n_inputs);
    let inner_n_rows = 1usize << inner_log_rows;
    let inner_n_cols = hauth_multi_n_cols(p.n_inputs);

    // 1) Multi-AIR sub-trace.
    let inner_cols = build_hauth_multi_trace(secrets, p.tx_body_hash, inner_log_rows);
    assert_eq!(inner_cols.len(), inner_n_cols);
    for (i, src) in inner_cols.into_iter().enumerate() {
        assert_eq!(src.len(), inner_n_rows);
        let dst = &mut cols[p.col_offset + i];
        for (r, v) in src.into_iter().enumerate() {
            dst[p.row_window_start + r] = v;
        }
    }

    // `tx_body_col[0..2]` is constrained constant across rows by a
    // cyclic shifted-XOR gate inside the AIR. Under `MaskOff` the gate
    // is silenced outside the window, but the cyclic `next` read at
    // the window's last row crosses into the outer trace. Plant the
    // shared `tx_body_hash` across **every** outer row of the two
    // tx-body columns so the wrapped gate stays satisfied at the
    // boundary.
    let tx_body_hi_outer = p.col_offset + HAUTH_MULTI_TX_BODY_BASE;
    let tx_body_lo_outer = p.col_offset + HAUTH_MULTI_TX_BODY_BASE + 1;
    for row in 0..outer_n_rows {
        cols[tx_body_hi_outer][row] = p.tx_body_hash[0];
        cols[tx_body_lo_outer][row] = p.tx_body_hash[1];
    }

    // 2) Per-input extract + T2a bridge write.
    let mut result = Vec::with_capacity(p.n_inputs);
    for (i, (budget, target)) in p.inputs.iter().enumerate() {
        let squeezed_hi_col = p.col_offset + HAUTH_MULTI_LAYOUT_C.s;
        let squeezed_lo_col = p.col_offset + HAUTH_MULTI_LAYOUT_C.s + 1;
        let squeezed_row = p.row_window_start + hauth_multi_row_output(i);
        let tag_hi = cols[squeezed_hi_col][squeezed_row];
        let tag_lo = cols[squeezed_lo_col][squeezed_row];

        // Plant per-input destinations.
        cols[target.auth_tag_hi_dst_col][target.auth_tag_hi_dst_row] = tag_hi;
        cols[target.auth_tag_lo_dst_col][target.auth_tag_lo_dst_row] = tag_lo;

        write_t1_lane_bridge(
            cols,
            LaneBridgeTie {
                src_col: squeezed_hi_col,
                src_row: squeezed_row,
                dst_col: target.auth_tag_hi_dst_col,
                dst_row: target.auth_tag_hi_dst_row,
            },
            budget.t2a_hi_budget,
            outer_n_rows,
            tag_hi,
        );
        write_t1_lane_bridge(
            cols,
            LaneBridgeTie {
                src_col: squeezed_lo_col,
                src_row: squeezed_row,
                dst_col: target.auth_tag_lo_dst_col,
                dst_row: target.auth_tag_lo_dst_row,
            },
            budget.t2a_lo_budget,
            outer_n_rows,
            tag_lo,
        );

        result.push(SharedHAuthInputCells {
            tag: [tag_hi, tag_lo],
        });
    }

    // 3) Shared T2b bridge: plant tx_body hi/lo at destinations and
    //    write the two bridge columns.
    let tx_body_hi_col = p.col_offset + HAUTH_MULTI_TX_BODY_BASE;
    let tx_body_lo_col = p.col_offset + HAUTH_MULTI_TX_BODY_BASE + 1;
    let tx_body_row = p.row_window_start;
    let txb_hi = cols[tx_body_hi_col][tx_body_row];
    let txb_lo = cols[tx_body_lo_col][tx_body_row];
    cols[p.tx_body_binding.hi_dst_col][p.tx_body_binding.hi_dst_row] = txb_hi;
    cols[p.tx_body_binding.lo_dst_col][p.tx_body_binding.lo_dst_row] = txb_lo;
    write_t1_lane_bridge(
        cols,
        LaneBridgeTie {
            src_col: tx_body_hi_col,
            src_row: tx_body_row,
            dst_col: p.tx_body_binding.hi_dst_col,
            dst_row: p.tx_body_binding.hi_dst_row,
        },
        p.tx_body_binding.hi_budget,
        outer_n_rows,
        txb_hi,
    );
    write_t1_lane_bridge(
        cols,
        LaneBridgeTie {
            src_col: tx_body_lo_col,
            src_row: tx_body_row,
            dst_col: p.tx_body_binding.lo_dst_col,
            dst_row: p.tx_body_binding.lo_dst_row,
        },
        p.tx_body_binding.lo_budget,
        outer_n_rows,
        txb_lo,
    );

    result
}

/// Outer-column overhead, not counting the multi-AIR sub-trace:
/// `1` window indicator + `8 · n_inputs` per-input T2a bridge cols +
/// `8` shared T2b bridge cols.
pub const fn shared_hauth_outer_overhead_cols(n_inputs: usize) -> usize {
    1 + 8 * n_inputs + 8
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::airs::hauth::{build_hauth_trace, extract_hauth_output};
    use crate::{Air, CompositeAir, Trace};
    use noid_core::TowerField;

    fn mk_fields(seed: u128) -> [Block128; 2] {
        let s = seed.wrapping_mul(0x9E3779B97F4A7C15);
        [
            Block128::from(s ^ 0xA5A5_A5A5_A5A5_A5A5),
            Block128::from(s.wrapping_add(1) ^ 0x5A5A_5A5A_5A5A_5A5A),
        ]
    }

    fn per_input_budget(base: usize) -> (SharedHAuthInputBudget, usize) {
        let b = SharedHAuthInputBudget {
            t2a_hi_budget: LaneBridgeBudget {
                bridge_col: base,
                src_indicator_col: base + 1,
                dst_indicator_col: base + 2,
                transition_indicator_col: base + 3,
            },
            t2a_lo_budget: LaneBridgeBudget {
                bridge_col: base + 4,
                src_indicator_col: base + 5,
                dst_indicator_col: base + 6,
                transition_indicator_col: base + 7,
            },
        };
        (b, base + 8)
    }

    fn build(
        n_inputs: usize,
        secrets: Vec<[Block128; 2]>,
        tx_body: [Block128; 2],
    ) -> (CompositeAir, Vec<Vec<Block128>>) {
        let inner_n_cols = hauth_multi_n_cols(n_inputs);
        let inner_log_rows = hauth_multi_min_log_rows(n_inputs);
        let outer_log_rows = inner_log_rows + 1;
        let outer_n_rows = 1usize << outer_log_rows;

        // Layout:
        //   0 .. inner_n_cols           multi-AIR slab
        //   inner_n_cols                window indicator
        //   inner_n_cols + 1 ..         per-input: 8 T2a bridge cols +
        //                               2 T2a dst cols each
        //   ...                         shared T2b: 8 bridge cols + 2 dst cols
        let window_indicator_col = inner_n_cols;
        let mut cursor = inner_n_cols + 1;
        let mut inputs = Vec::with_capacity(n_inputs);
        for _ in 0..n_inputs {
            let (budget, next) = per_input_budget(cursor);
            cursor = next;
            let tag_hi = cursor;
            let tag_lo = cursor + 1;
            cursor += 2;
            inputs.push((
                budget,
                SharedHAuthInputTargets {
                    auth_tag_hi_dst_col: tag_hi,
                    auth_tag_hi_dst_row: (1 << inner_log_rows) + 3,
                    auth_tag_lo_dst_col: tag_lo,
                    auth_tag_lo_dst_row: (1 << inner_log_rows) + 5,
                },
            ));
        }

        // Shared T2b bridge + dst cols.
        let t2b_base = cursor;
        let t2b_hi_budget = LaneBridgeBudget {
            bridge_col: t2b_base,
            src_indicator_col: t2b_base + 1,
            dst_indicator_col: t2b_base + 2,
            transition_indicator_col: t2b_base + 3,
        };
        let t2b_lo_budget = LaneBridgeBudget {
            bridge_col: t2b_base + 4,
            src_indicator_col: t2b_base + 5,
            dst_indicator_col: t2b_base + 6,
            transition_indicator_col: t2b_base + 7,
        };
        cursor += 8;
        let txb_hi_dst_col = cursor;
        let txb_lo_dst_col = cursor + 1;
        cursor += 2;

        let tx_body_binding = SharedHAuthTxBodyBinding {
            hi_budget: t2b_hi_budget,
            lo_budget: t2b_lo_budget,
            hi_dst_col: txb_hi_dst_col,
            hi_dst_row: (1 << inner_log_rows) + 11,
            lo_dst_col: txb_lo_dst_col,
            lo_dst_row: (1 << inner_log_rows) + 13,
        };
        let outer_n_cols = cursor;

        let p = SharedHAuthBlockParams {
            n_inputs,
            col_offset: 0,
            window_indicator_col,
            row_window_start: 0,
            outer_n_cols,
            outer_log_rows,
            tx_body_hash: tx_body,
            inputs,
            tx_body_binding,
        };

        let wiring = emit_shared_hauth_block(p.clone());
        let air = CompositeAir::from_parts_with_publics(
            outer_log_rows,
            outer_n_cols,
            wiring.constraints,
            wiring.public_columns,
        );

        let mut cols: Vec<Vec<Block128>> = (0..outer_n_cols)
            .map(|_| vec![Block128::ZERO; outer_n_rows])
            .collect();
        let _ = write_shared_hauth_block_trace(&mut cols, &p, &secrets);

        for pc in air.public_columns() {
            cols[pc.col] = pc.values.clone();
        }

        (air, cols)
    }

    #[test]
    fn honest_one_input_accepts() {
        let tx_body = mk_fields(0xAA);
        let secrets = vec![mk_fields(0x11)];
        let (air, cols) = build(1, secrets, tx_body);
        assert!(air.check(&Trace::new(cols)));
    }

    #[test]
    fn honest_four_inputs_accept() {
        let tx_body = mk_fields(0xBEEF);
        let secrets = (0..4).map(|i| mk_fields(0x1000 + i)).collect::<Vec<_>>();
        let (air, cols) = build(4, secrets, tx_body);
        assert!(air.check(&Trace::new(cols)));
    }

    #[test]
    fn tag_matches_native_per_input() {
        let tx_body = mk_fields(0xCAFE);
        let secrets = (0..4).map(|i| mk_fields(0xABCD + i)).collect::<Vec<_>>();
        let (_air, cols) = build(4, secrets.clone(), tx_body);
        for (i, s) in secrets.iter().enumerate() {
            let row = hauth_multi_row_output(i);
            let hi = cols[HAUTH_MULTI_LAYOUT_C.s][row];
            let lo = cols[HAUTH_MULTI_LAYOUT_C.s + 1][row];

            let legacy = build_hauth_trace(*s, tx_body);
            let [exp_hi, exp_lo] = extract_hauth_output(&legacy);
            assert_eq!(hi, exp_hi, "input {i} tag_hi mismatch");
            assert_eq!(lo, exp_lo, "input {i} tag_lo mismatch");
        }
    }

    #[test]
    fn tag_dst_tamper_rejects() {
        let tx_body = mk_fields(0xFEED);
        let secrets = (0..2).map(|i| mk_fields(0x7000 + i)).collect::<Vec<_>>();
        let (air, mut cols) = build(2, secrets, tx_body);
        // Tag dst for input 0 lives at col `inner_n_cols + 1 + 8` (after
        // input 0's 8 T2a bridge cols), row `(1<<inner_log_rows) + 3`.
        let inner_n_cols = hauth_multi_n_cols(2);
        let tag_hi_input0 = inner_n_cols + 1 + 8;
        let tag_hi_row_input0 = (1 << hauth_multi_min_log_rows(2)) + 3;
        cols[tag_hi_input0][tag_hi_row_input0] =
            cols[tag_hi_input0][tag_hi_row_input0] + Block128::ONE;
        assert!(!air.check(&Trace::new(cols)));
    }

    #[test]
    fn tx_body_dst_tamper_rejects() {
        let tx_body = mk_fields(0x1A1A);
        let secrets = (0..2).map(|i| mk_fields(0x2B2B + i)).collect::<Vec<_>>();
        let (air, mut cols) = build(2, secrets, tx_body);
        // Shared T2b dst hi col lives at:
        //   inner + 1 (window) + n_inputs·10 (T2a bridges+dsts) + 8 (T2b bridge cols).
        let inner_n_cols = hauth_multi_n_cols(2);
        let n_inputs = 2;
        let txb_hi_col = inner_n_cols + 1 + n_inputs * 10 + 8;
        let txb_hi_row = (1 << hauth_multi_min_log_rows(2)) + 11;
        cols[txb_hi_col][txb_hi_row] = cols[txb_hi_col][txb_hi_row] + Block128::ONE;
        assert!(!air.check(&Trace::new(cols)));
    }

    #[test]
    fn cross_input_squeeze_tamper_rejects() {
        let tx_body = mk_fields(0x9A);
        let secrets = (0..2).map(|i| mk_fields(0x8B + i)).collect::<Vec<_>>();
        let (air, mut cols) = build(2, secrets, tx_body);
        let row = hauth_multi_row_output(1);
        cols[HAUTH_MULTI_LAYOUT_C.s][row] =
            cols[HAUTH_MULTI_LAYOUT_C.s][row] + Block128::ONE;
        assert!(!air.check(&Trace::new(cols)));
    }

    #[test]
    fn overhead_formula_matches() {
        assert_eq!(shared_hauth_outer_overhead_cols(0), 1 + 8);
        assert_eq!(shared_hauth_outer_overhead_cols(4), 1 + 32 + 8);
    }
}
