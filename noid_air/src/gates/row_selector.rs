// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! `RowSelectorGate`: Stage 3d-0.5 primitive for boundary ties.
//!
//! Every "pin a witness cell to a public constant on one specific row"
//! debt carried from §3b-4 / §3c-2 / §3c-3 / §3c-4 / §3c-5 needs a
//! constraint that activates on exactly one row of the trace. The
//! existing `PublicColumn` / `ConstColumnGate` pin entire columns;
//! `SelectorGate` gates an inner constraint by a witness column. Combined
//! — a `PublicColumn` that is `1` at `row` and `0` everywhere else,
//! multiplied into an inner constraint via `SelectorGate` — they express
//! a single-row constraint without adding any new STARK-layer machinery.
//!
//! This module only ships the glue:
//!
//! - [`row_indicator_programme`] — builds the `2^log_rows` value vector
//!   of an indicator column.
//! - [`emit_row_selector`] — takes `(indicator_col, row, total_rows,
//!   inner)` and returns the pair `(PublicColumn, SelectorGate)` that
//!   the caller appends to its AIR's declarations + constraints.
//! - [`emit_public_cell`] — specialisation of [`emit_row_selector`] for
//!   the "pin one witness cell to a constant" case (`target_col@row ==
//!   constant`).
//! - [`emit_column_eq_at_row`] — specialisation for "pin two witness
//!   cells of the same trace to be equal at a single row"
//!   (`col_a@row == col_b@row`). This is the cross-column / single-row
//!   variant that §3d-0.9's `TxBodyMerkleAir` inter-instance wiring and
//!   §3d-0.6b's absorb XOR ties need — the constant form of
//!   [`emit_public_cell`] can't express it because neither cell is a
//!   public constant.
//!
//! Soundness. The indicator column is a `PublicColumn`, so the native
//! `Air::check` rejects any trace whose indicator column deviates from
//! the declared programme, and the verifier's `check_public_columns`
//! re-evaluates the indicator MLE at the zero-check terminal `r_point`
//! and asserts equality with the base opening. The inner constraint is
//! multiplied by that indicator; on all non-target rows the product is
//! zero by construction, and on the target row the selector is `1` so
//! `inner.evaluate` must vanish. Extending to arbitrary sparse row sets
//! only requires replacing the `programme[row] = ONE` line with a
//! multi-hot programme — every downstream §3d-0.6..0.10 boundary tie is
//! single-row, so that variant is deferred until something actually
//! needs it.

use crate::gates::const_column::PublicColumn;
use crate::gates::linear::{WeightedLinearGate, WeightedLinearGateShifted};
use crate::gates::selector::SelectorGate;
use crate::Constraint;
use noid_core::{Block128, TowerField};

/// Build the `2^log_rows` programme vector that is `ONE` at `row` and
/// `ZERO` elsewhere. `total_rows` must be a power of two; `row` must be
/// strictly less than `total_rows`.
pub fn row_indicator_programme(row: usize, total_rows: usize) -> Vec<Block128> {
    assert!(
        total_rows.is_power_of_two() && total_rows > 0,
        "row_indicator_programme: total_rows must be a non-zero power of two"
    );
    assert!(
        row < total_rows,
        "row_indicator_programme: row {row} out of range for total_rows {total_rows}"
    );
    let mut v = vec![Block128::ZERO; total_rows];
    v[row] = Block128::ONE;
    v
}

/// Multi-hot variant of [`row_indicator_programme`]: `ONE` on every row
/// in `rows`, `ZERO` elsewhere. `total_rows` must be a non-zero power
/// of two; every element of `rows` must be strictly less than
/// `total_rows`. Duplicates in `rows` are tolerated (writing `ONE`
/// twice is idempotent).
///
/// §3d-0.5.1 primitive. Used by any boundary tie that needs to fire on
/// a fixed public subset of rows — most immediately the
/// `InputValid` / `OutputValid` row-domain masks on `TxValidityAir`
/// and any "padding region MUST be zero" wiring.
pub fn multi_row_indicator_programme(rows: &[usize], total_rows: usize) -> Vec<Block128> {
    assert!(
        total_rows.is_power_of_two() && total_rows > 0,
        "multi_row_indicator_programme: total_rows must be a non-zero power of two"
    );
    let mut v = vec![Block128::ZERO; total_rows];
    for &r in rows {
        assert!(
            r < total_rows,
            "multi_row_indicator_programme: row {r} out of range for total_rows {total_rows}"
        );
        v[r] = Block128::ONE;
    }
    v
}

/// Materialise a row-selector bundle: the indicator `PublicColumn` plus
/// the `SelectorGate` that gates `inner` by it. The caller appends the
/// indicator to their AIR's `public_columns` and the selector gate to
/// their `constraints`. `indicator_col` must be a column index reserved
/// by the caller for this indicator (typically a dedicated column per
/// distinct target row, shareable across ties that all fire on the same
/// row).
pub fn emit_row_selector(
    indicator_col: usize,
    row: usize,
    total_rows: usize,
    inner: Box<dyn Constraint>,
) -> (PublicColumn, Box<dyn Constraint>) {
    let programme = row_indicator_programme(row, total_rows);
    let pc = PublicColumn::new(indicator_col, programme);
    let sel: Box<dyn Constraint> = Box::new(SelectorGate::new(indicator_col, inner));
    (pc, sel)
}

/// Pin `trace[target_col][row] == constant` via an indicator column.
/// Equivalent to `emit_row_selector(indicator_col, row, total_rows,
/// WeightedLinearGate { target_col + constant == 0 })` — in char-2 the
/// constraint residue `target_col + constant` vanishes iff the cell
/// matches.
pub fn emit_public_cell(
    indicator_col: usize,
    row: usize,
    total_rows: usize,
    target_col: usize,
    constant: Block128,
) -> (PublicColumn, Box<dyn Constraint>) {
    assert_ne!(
        indicator_col, target_col,
        "emit_public_cell: indicator and target columns must differ"
    );
    let inner = WeightedLinearGate::new(vec![(target_col, Block128::ONE)], constant);
    emit_row_selector(indicator_col, row, total_rows, Box::new(inner))
}

/// Pin `trace[col_a][row] == trace[col_b][row]` via an indicator column.
/// Equivalent to `emit_row_selector(indicator_col, row, total_rows,
/// WeightedLinearGate { col_a + col_b == 0 })`. In characteristic 2 the
/// XOR residue `col_a + col_b` vanishes iff the two cells agree.
///
/// The two-column witness form (vs. the one-column `emit_public_cell`)
/// is what `ColumnEqAtRowGate` in the roadmap refers to — needed for
/// cross-instance carries where neither side is a verifier-known
/// constant. Cross-row comparison (`col_a@row_x == col_b@row_y` with
/// `row_x != row_y`) is out of scope here because it requires a
/// `shifted_columns` path through the base AIR abstraction; every
/// §3d-0.6b / §3d-0.9 use-site so far only needs the same-row form.
/// Multi-row analogue of [`emit_row_selector`]: `inner` fires on every
/// row in `rows`, silent elsewhere. Caller appends the returned
/// `PublicColumn` to its `public_columns` and the constraint to its
/// `constraints`. `indicator_col` must differ from every column read
/// by `inner` (the `SelectorGate` wrapper enforces this implicitly by
/// reserving `indicator_col` as its local-0 slot).
pub fn emit_multi_row_selector(
    indicator_col: usize,
    rows: &[usize],
    total_rows: usize,
    inner: Box<dyn Constraint>,
) -> (PublicColumn, Box<dyn Constraint>) {
    let programme = multi_row_indicator_programme(rows, total_rows);
    let pc = PublicColumn::new(indicator_col, programme);
    let sel: Box<dyn Constraint> = Box::new(SelectorGate::new(indicator_col, inner));
    (pc, sel)
}

/// Pin `trace[target_col][r] == 0` for every `r ∈ rows` via a shared
/// multi-hot indicator column. Specialisation of
/// [`emit_multi_row_selector`] for the "target column MUST be zero on
/// this row subset" pattern — the constraint residue `target_col`
/// vanishes iff the cell is zero (in characteristic 2). Shared
/// indicator amortises the MLE re-eval cost across every row in
/// `rows`.
pub fn emit_rows_must_be_zero(
    indicator_col: usize,
    rows: &[usize],
    total_rows: usize,
    target_col: usize,
) -> (PublicColumn, Box<dyn Constraint>) {
    assert_ne!(
        indicator_col, target_col,
        "emit_rows_must_be_zero: indicator and target columns must differ"
    );
    let inner = WeightedLinearGate::new(vec![(target_col, Block128::ONE)], Block128::ZERO);
    emit_multi_row_selector(indicator_col, rows, total_rows, Box::new(inner))
}

pub fn emit_column_eq_at_row(
    indicator_col: usize,
    row: usize,
    total_rows: usize,
    col_a: usize,
    col_b: usize,
) -> (PublicColumn, Box<dyn Constraint>) {
    assert_ne!(
        col_a, col_b,
        "emit_column_eq_at_row: left/right columns must differ"
    );
    assert_ne!(
        indicator_col, col_a,
        "emit_column_eq_at_row: indicator must differ from col_a"
    );
    assert_ne!(
        indicator_col, col_b,
        "emit_column_eq_at_row: indicator must differ from col_b"
    );
    let inner = WeightedLinearGate::new_xor(vec![col_a, col_b]);
    emit_row_selector(indicator_col, row, total_rows, Box::new(inner))
}

/// Pin `trace[col_a][row] == trace[col_b][(row+1) mod total_rows]` via
/// an indicator column. Off-by-one cross-row analogue of
/// [`emit_column_eq_at_row`], built on [`WeightedLinearGateShifted`] so
/// `col_b` is read through the base `Air`'s cyclic `+1` rotation.
///
/// §3d-0.5.2 primitive. First caller is 3d-0.6b tie (3): the
/// inter-permutation carry `A.s[lane]@row_N_ROUNDS ==
/// B.s[lane]@row_0` reduces to this shape when the trace places the
/// two rows adjacent to each other.
pub fn emit_column_eq_at_next_row(
    indicator_col: usize,
    row: usize,
    total_rows: usize,
    col_a: usize,
    col_b_at_next: usize,
) -> (PublicColumn, Box<dyn Constraint>) {
    assert_ne!(
        indicator_col, col_a,
        "emit_column_eq_at_next_row: indicator must differ from col_a"
    );
    assert_ne!(
        indicator_col, col_b_at_next,
        "emit_column_eq_at_next_row: indicator must differ from col_b_at_next"
    );
    // col_a and col_b_at_next may alias: that pins `col@row == col@row+1`,
    // a legitimate "row is constant across the boundary" query.
    let inner = WeightedLinearGateShifted::new_xor_next(col_a, col_b_at_next);
    emit_row_selector(indicator_col, row, total_rows, Box::new(inner))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Air, CompositeAir, Trace};

    /// Single cell pinned on row 2 of a 4-row trace. Honest witness has
    /// `target_col[2] == constant`; indicator column is `[0, 0, 1, 0]`.
    #[test]
    fn public_cell_accepts_matching() {
        let constant = Block128::from(0xDEAD_BEEFu128);
        let (pc, gate) = emit_public_cell(0, 2, 4, 1, constant);
        let air = CompositeAir::from_parts_with_publics(2, 2, vec![gate], vec![pc]);
        let indicator = vec![
            Block128::ZERO,
            Block128::ZERO,
            Block128::ONE,
            Block128::ZERO,
        ];
        let mut target = vec![Block128::ZERO; 4];
        target[2] = constant;
        let trace = Trace::new(vec![indicator, target]);
        assert!(air.check(&trace));
    }

    #[test]
    fn public_cell_rejects_wrong_cell_on_target_row() {
        let constant = Block128::from(0xDEAD_BEEFu128);
        let (pc, gate) = emit_public_cell(0, 2, 4, 1, constant);
        let air = CompositeAir::from_parts_with_publics(2, 2, vec![gate], vec![pc]);
        let indicator = vec![
            Block128::ZERO,
            Block128::ZERO,
            Block128::ONE,
            Block128::ZERO,
        ];
        let mut target = vec![Block128::ZERO; 4];
        target[2] = constant + Block128::ONE;
        let trace = Trace::new(vec![indicator, target]);
        assert!(!air.check(&trace));
    }

    /// Single-row selector ignores cells on non-target rows: if the
    /// caller wants "must equal constant on row 2 and be anything
    /// elsewhere", the gate is silent on rows 0, 1, 3. Verified here —
    /// the other-row cells are noise and the trace still accepts.
    #[test]
    fn public_cell_silent_on_non_target_rows() {
        let constant = Block128::from(0xDEAD_BEEFu128);
        let (pc, gate) = emit_public_cell(0, 2, 4, 1, constant);
        let air = CompositeAir::from_parts_with_publics(2, 2, vec![gate], vec![pc]);
        let indicator = vec![
            Block128::ZERO,
            Block128::ZERO,
            Block128::ONE,
            Block128::ZERO,
        ];
        let mut target = vec![Block128::ZERO; 4];
        target[0] = Block128::from(0x1234u128);
        target[1] = Block128::from(0x5678u128);
        target[2] = constant;
        target[3] = Block128::from(0x9ABCu128);
        let trace = Trace::new(vec![indicator, target]);
        assert!(air.check(&trace));
    }

    /// A prover that writes `1` on a non-target row of the indicator
    /// column is rejected by the `PublicColumn` declaration itself.
    #[test]
    fn tampered_indicator_column_rejected() {
        let constant = Block128::from(0xDEAD_BEEFu128);
        let (pc, gate) = emit_public_cell(0, 2, 4, 1, constant);
        let air = CompositeAir::from_parts_with_publics(2, 2, vec![gate], vec![pc]);
        // Move the `1` to row 0 — programme says row 2.
        let indicator = vec![
            Block128::ONE,
            Block128::ZERO,
            Block128::ZERO,
            Block128::ZERO,
        ];
        let mut target = vec![Block128::ZERO; 4];
        target[2] = constant;
        let trace = Trace::new(vec![indicator, target]);
        assert!(!air.check(&trace));
    }

    /// Two row-selector gates on the same row share one indicator column
    /// (common pattern: `state[2]@0 == IV_hi` + `state[3]@0 == IV_lo`
    /// both use the row-0 indicator).
    #[test]
    fn two_cells_share_one_indicator() {
        let k1 = Block128::from(0x1111_1111u128);
        let k2 = Block128::from(0x2222_2222u128);
        // Indicator at col 0, targets at col 1 and col 2; same target row.
        let programme = row_indicator_programme(3, 4);
        let pc = PublicColumn::new(0, programme);
        let inner1 = WeightedLinearGate::new(vec![(1, Block128::ONE)], k1);
        let inner2 = WeightedLinearGate::new(vec![(2, Block128::ONE)], k2);
        let sel1: Box<dyn Constraint> = Box::new(SelectorGate::new(0, Box::new(inner1)));
        let sel2: Box<dyn Constraint> = Box::new(SelectorGate::new(0, Box::new(inner2)));
        let air = CompositeAir::from_parts_with_publics(2, 3, vec![sel1, sel2], vec![pc]);
        let indicator = vec![
            Block128::ZERO,
            Block128::ZERO,
            Block128::ZERO,
            Block128::ONE,
        ];
        let mut c1 = vec![Block128::ZERO; 4];
        c1[3] = k1;
        let mut c2 = vec![Block128::ZERO; 4];
        c2[3] = k2;
        let trace = Trace::new(vec![indicator, c1.clone(), c2.clone()]);
        assert!(air.check(&trace));
        // Tamper c2[3] — second gate rejects.
        let mut c2_bad = c2.clone();
        c2_bad[3] = k2 + Block128::ONE;
        let trace_bad = Trace::new(vec![
            vec![
                Block128::ZERO,
                Block128::ZERO,
                Block128::ZERO,
                Block128::ONE,
            ],
            c1,
            c2_bad,
        ]);
        assert!(!air.check(&trace_bad));
    }

    #[test]
    #[should_panic(expected = "row")]
    fn indicator_row_out_of_range_rejected() {
        let _ = row_indicator_programme(4, 4);
    }

    #[test]
    #[should_panic(expected = "power of two")]
    fn indicator_total_rows_not_power_of_two_rejected() {
        let _ = row_indicator_programme(0, 3);
    }

    #[test]
    #[should_panic(expected = "indicator and target columns must differ")]
    fn public_cell_rejects_alias() {
        let _ = emit_public_cell(0, 0, 4, 0, Block128::ZERO);
    }

    // -------------------------------------------------------------------
    // emit_column_eq_at_row
    // -------------------------------------------------------------------

    #[test]
    fn column_eq_accepts_matching_cells() {
        // Indicator on col 0, equate col 1 vs col 2 at row 2.
        let (pc, gate) = emit_column_eq_at_row(0, 2, 4, 1, 2);
        let air = CompositeAir::from_parts_with_publics(2, 3, vec![gate], vec![pc]);
        let indicator = vec![
            Block128::ZERO,
            Block128::ZERO,
            Block128::ONE,
            Block128::ZERO,
        ];
        let shared = Block128::from(0xDEAD_u128);
        let col_a = vec![
            Block128::ZERO,
            Block128::from(1u128),
            shared,
            Block128::ZERO,
        ];
        let col_b = vec![
            Block128::from(99u128),
            Block128::from(42u128),
            shared,
            Block128::ZERO,
        ];
        let trace = Trace::new(vec![indicator, col_a, col_b]);
        assert!(air.check(&trace));
    }

    #[test]
    fn column_eq_rejects_mismatch_on_target_row() {
        let (pc, gate) = emit_column_eq_at_row(0, 2, 4, 1, 2);
        let air = CompositeAir::from_parts_with_publics(2, 3, vec![gate], vec![pc]);
        let indicator = vec![
            Block128::ZERO,
            Block128::ZERO,
            Block128::ONE,
            Block128::ZERO,
        ];
        let col_a = vec![Block128::ZERO; 4];
        let mut col_b = vec![Block128::ZERO; 4];
        col_b[2] = Block128::ONE;
        let trace = Trace::new(vec![indicator, col_a, col_b]);
        assert!(!air.check(&trace));
    }

    #[test]
    fn column_eq_silent_on_non_target_rows() {
        // Rows 0, 1, 3 can freely disagree; only row 2 is pinned.
        let (pc, gate) = emit_column_eq_at_row(0, 2, 4, 1, 2);
        let air = CompositeAir::from_parts_with_publics(2, 3, vec![gate], vec![pc]);
        let indicator = vec![
            Block128::ZERO,
            Block128::ZERO,
            Block128::ONE,
            Block128::ZERO,
        ];
        let col_a = vec![
            Block128::from(0xAAu128),
            Block128::from(0xBBu128),
            Block128::from(0xCAFEu128),
            Block128::from(0xDDu128),
        ];
        let col_b = vec![
            Block128::from(0x11u128),
            Block128::from(0x22u128),
            Block128::from(0xCAFEu128),
            Block128::from(0x44u128),
        ];
        let trace = Trace::new(vec![indicator, col_a, col_b]);
        assert!(air.check(&trace));
    }

    #[test]
    fn column_eq_rejects_tampered_indicator() {
        let (pc, gate) = emit_column_eq_at_row(0, 2, 4, 1, 2);
        let air = CompositeAir::from_parts_with_publics(2, 3, vec![gate], vec![pc]);
        // Indicator fires on row 0 instead — programme rejects.
        let indicator = vec![
            Block128::ONE,
            Block128::ZERO,
            Block128::ZERO,
            Block128::ZERO,
        ];
        let col_a = vec![Block128::ZERO; 4];
        let col_b = vec![Block128::ZERO; 4];
        let trace = Trace::new(vec![indicator, col_a, col_b]);
        assert!(!air.check(&trace));
    }

    #[test]
    #[should_panic(expected = "left/right columns must differ")]
    fn column_eq_rejects_same_column() {
        let _ = emit_column_eq_at_row(0, 0, 4, 1, 1);
    }

    #[test]
    #[should_panic(expected = "indicator must differ from col_a")]
    fn column_eq_rejects_indicator_alias_a() {
        let _ = emit_column_eq_at_row(1, 0, 4, 1, 2);
    }

    #[test]
    #[should_panic(expected = "indicator must differ from col_b")]
    fn column_eq_rejects_indicator_alias_b() {
        let _ = emit_column_eq_at_row(2, 0, 4, 1, 2);
    }

    // -------------------------------------------------------------------
    // emit_rows_must_be_zero (3d-0.5.1)
    // -------------------------------------------------------------------

    #[test]
    fn multi_row_programme_hot_bits() {
        let p = multi_row_indicator_programme(&[1, 3], 8);
        for (row, &v) in p.iter().enumerate() {
            let want = if row == 1 || row == 3 {
                Block128::ONE
            } else {
                Block128::ZERO
            };
            assert_eq!(v, want, "row {row}");
        }
    }

    #[test]
    fn multi_row_programme_tolerates_duplicates() {
        let p = multi_row_indicator_programme(&[2, 2, 2], 4);
        assert_eq!(
            p,
            vec![
                Block128::ZERO,
                Block128::ZERO,
                Block128::ONE,
                Block128::ZERO
            ]
        );
    }

    #[test]
    #[should_panic(expected = "row")]
    fn multi_row_programme_row_out_of_range() {
        let _ = multi_row_indicator_programme(&[0, 5], 4);
    }

    #[test]
    #[should_panic(expected = "power of two")]
    fn multi_row_programme_bad_total_rows() {
        let _ = multi_row_indicator_programme(&[0], 3);
    }

    #[test]
    fn rows_must_be_zero_accepts_honest() {
        // Indicator at col 0, target at col 1, forbidden rows {1, 3}.
        let (pc, gate) = emit_rows_must_be_zero(0, &[1, 3], 4, 1);
        let air = CompositeAir::from_parts_with_publics(2, 2, vec![gate], vec![pc]);
        let indicator = vec![Block128::ZERO, Block128::ONE, Block128::ZERO, Block128::ONE];
        // Free-form on allowed rows (0, 2); zero on forbidden rows (1, 3).
        let target = vec![
            Block128::from(0xAAu128),
            Block128::ZERO,
            Block128::from(0xBBu128),
            Block128::ZERO,
        ];
        let trace = Trace::new(vec![indicator, target]);
        assert!(air.check(&trace));
    }

    #[test]
    fn rows_must_be_zero_rejects_nonzero_on_forbidden_row() {
        let (pc, gate) = emit_rows_must_be_zero(0, &[1, 3], 4, 1);
        let air = CompositeAir::from_parts_with_publics(2, 2, vec![gate], vec![pc]);
        let indicator = vec![Block128::ZERO, Block128::ONE, Block128::ZERO, Block128::ONE];
        // Row 3 is forbidden but target is nonzero.
        let target = vec![
            Block128::ZERO,
            Block128::ZERO,
            Block128::ZERO,
            Block128::ONE,
        ];
        let trace = Trace::new(vec![indicator, target]);
        assert!(!air.check(&trace));
    }

    #[test]
    fn rows_must_be_zero_silent_on_allowed_rows() {
        let (pc, gate) = emit_rows_must_be_zero(0, &[1, 3], 4, 1);
        let air = CompositeAir::from_parts_with_publics(2, 2, vec![gate], vec![pc]);
        let indicator = vec![Block128::ZERO, Block128::ONE, Block128::ZERO, Block128::ONE];
        let target = vec![
            Block128::from(0xFFu128),
            Block128::ZERO,
            Block128::from(0xEEu128),
            Block128::ZERO,
        ];
        let trace = Trace::new(vec![indicator, target]);
        assert!(air.check(&trace));
    }

    #[test]
    fn rows_must_be_zero_rejects_tampered_indicator() {
        let (pc, gate) = emit_rows_must_be_zero(0, &[1, 3], 4, 1);
        let air = CompositeAir::from_parts_with_publics(2, 2, vec![gate], vec![pc]);
        // Indicator tampered to also fire on row 0.
        let indicator = vec![Block128::ONE, Block128::ONE, Block128::ZERO, Block128::ONE];
        let target = vec![Block128::ZERO; 4];
        let trace = Trace::new(vec![indicator, target]);
        assert!(!air.check(&trace));
    }

    #[test]
    #[should_panic(expected = "indicator and target columns must differ")]
    fn rows_must_be_zero_rejects_alias() {
        let _ = emit_rows_must_be_zero(0, &[1], 4, 0);
    }

    // -------------------------------------------------------------------
    // emit_column_eq_at_next_row (3d-0.5.2)
    // -------------------------------------------------------------------

    #[test]
    fn column_eq_next_accepts_adjacent_match() {
        // Indicator on col 0, pin col1@row2 == col2@row3.
        let (pc, gate) = emit_column_eq_at_next_row(0, 2, 4, 1, 2);
        let air = CompositeAir::from_parts_with_publics(2, 3, vec![gate], vec![pc]);
        let indicator = vec![
            Block128::ZERO,
            Block128::ZERO,
            Block128::ONE,
            Block128::ZERO,
        ];
        let shared = Block128::from(0xC0FFEEu128);
        // col1[2] == shared; col2[3] == shared. Rows 0, 1, 3 of col1 and
        // rows 0, 1, 2 of col2 are free.
        let col1 = vec![
            Block128::from(1u128),
            Block128::from(2u128),
            shared,
            Block128::from(3u128),
        ];
        let col2 = vec![
            Block128::from(9u128),
            Block128::from(8u128),
            Block128::from(7u128),
            shared,
        ];
        let trace = Trace::new(vec![indicator, col1, col2]);
        assert!(air.check(&trace));
    }

    #[test]
    fn column_eq_next_rejects_mismatch() {
        let (pc, gate) = emit_column_eq_at_next_row(0, 2, 4, 1, 2);
        let air = CompositeAir::from_parts_with_publics(2, 3, vec![gate], vec![pc]);
        let indicator = vec![
            Block128::ZERO,
            Block128::ZERO,
            Block128::ONE,
            Block128::ZERO,
        ];
        let col1 = vec![
            Block128::ZERO,
            Block128::ZERO,
            Block128::ONE,
            Block128::ZERO,
        ];
        let col2 = vec![Block128::ZERO; 4]; // col2[3] = 0, but col1[2] = 1.
        let trace = Trace::new(vec![indicator, col1, col2]);
        assert!(!air.check(&trace));
    }

    #[test]
    fn column_eq_next_wraps_cyclically() {
        // row = 3 pins col1[3] == col2[0] (cyclic rotation).
        let (pc, gate) = emit_column_eq_at_next_row(0, 3, 4, 1, 2);
        let air = CompositeAir::from_parts_with_publics(2, 3, vec![gate], vec![pc]);
        let indicator = vec![
            Block128::ZERO,
            Block128::ZERO,
            Block128::ZERO,
            Block128::ONE,
        ];
        let shared = Block128::from(0xAAu128);
        let col1 = vec![Block128::ZERO, Block128::ZERO, Block128::ZERO, shared];
        let col2 = vec![shared, Block128::ZERO, Block128::ZERO, Block128::ZERO];
        let trace = Trace::new(vec![indicator, col1, col2]);
        assert!(air.check(&trace));
    }

    #[test]
    fn column_eq_next_silent_on_other_rows() {
        let (pc, gate) = emit_column_eq_at_next_row(0, 2, 4, 1, 2);
        let air = CompositeAir::from_parts_with_publics(2, 3, vec![gate], vec![pc]);
        let indicator = vec![
            Block128::ZERO,
            Block128::ZERO,
            Block128::ONE,
            Block128::ZERO,
        ];
        // col1[2] == col2[3]; any other (row, row+1) pair may disagree.
        let shared = Block128::from(7u128);
        let col1 = vec![
            Block128::from(111u128),
            Block128::from(222u128),
            shared,
            Block128::from(333u128),
        ];
        let col2 = vec![
            Block128::from(555u128),
            Block128::from(666u128),
            Block128::from(777u128),
            shared,
        ];
        let trace = Trace::new(vec![indicator, col1, col2]);
        assert!(air.check(&trace));
    }

    #[test]
    fn column_eq_next_rejects_tampered_indicator() {
        let (pc, gate) = emit_column_eq_at_next_row(0, 2, 4, 1, 2);
        let air = CompositeAir::from_parts_with_publics(2, 3, vec![gate], vec![pc]);
        let indicator = vec![
            Block128::ONE,
            Block128::ZERO,
            Block128::ZERO,
            Block128::ZERO,
        ];
        let col1 = vec![Block128::ZERO; 4];
        let col2 = vec![Block128::ZERO; 4];
        let trace = Trace::new(vec![indicator, col1, col2]);
        assert!(!air.check(&trace));
    }

    #[test]
    #[should_panic(expected = "indicator must differ from col_a")]
    fn column_eq_next_rejects_indicator_alias_a() {
        let _ = emit_column_eq_at_next_row(1, 0, 4, 1, 2);
    }

    #[test]
    #[should_panic(expected = "indicator must differ from col_b_at_next")]
    fn column_eq_next_rejects_indicator_alias_b() {
        let _ = emit_column_eq_at_next_row(2, 0, 4, 1, 2);
    }
}
