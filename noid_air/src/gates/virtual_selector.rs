// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Virtual row selectors.
//!
//! A virtual selector is a verifier-known multilinear polynomial that is
//! evaluated from the row index / sumcheck point instead of being committed as
//! a trace column.  This keeps the same algebraic degree as a committed
//! boolean selector column, but removes the selector from the commitment,
//! base openings, public-column checks, and multipoint close.

use crate::{Constraint, EvalFrame, FlatEvalFrame};
use noid_core::hardware::clmul_gcm;
use noid_core::{Block128, TowerField};

/// Evaluate the zero-padded MLE of a single-hot row selector at `point`.
///
/// The native selector table has length `2^log_rows` and is `1` exactly at
/// `row`.  When the STARK commits the AIR over a larger `log_len`, the old
/// committed-column path zero-padded the selector.  The MLE of that padded
/// table is:
///
/// `eq(row_bits, point[..log_rows]) * Π_{i=log_rows}^{log_len-1} (1 + point[i])`.
#[inline]
fn row_selector_value(row: usize, point: &[Block128], log_rows: usize) -> Block128 {
    debug_assert!(log_rows <= point.len());
    let mut acc = Block128::ONE;
    for i in 0..log_rows {
        let coord = point[i];
        let factor = if ((row >> i) & 1) == 1 {
            coord
        } else {
            Block128::ONE + coord
        };
        if factor == Block128::ZERO {
            return Block128::ZERO;
        }
        acc *= factor;
    }
    for &coord in &point[log_rows..] {
        acc *= Block128::ONE + coord;
    }
    acc
}

#[inline]
fn high_zero_factor(point: &[Block128], log_rows: usize) -> Block128 {
    let mut acc = Block128::ONE;
    for &coord in &point[log_rows..] {
        let factor = Block128::ONE + coord;
        if factor == Block128::ZERO {
            return Block128::ZERO;
        }
        acc *= factor;
    }
    acc
}

#[inline]
fn high_zero_factor_flat(point_flat: &[u128], log_rows: usize) -> u128 {
    let mut acc = 1u128;
    for &coord in &point_flat[log_rows..] {
        let factor = coord ^ 1u128;
        if factor == 0 {
            return 0;
        }
        acc = clmul_gcm(acc, factor);
    }
    acc
}

/// Native-domain MLE for a prefix selector: `1` on rows `0..end_exclusive`.
fn prefix_selector_native(end_exclusive: usize, point: &[Block128], vars: usize) -> Block128 {
    if end_exclusive == 0 {
        return Block128::ZERO;
    }
    if vars == 0 {
        return Block128::ONE;
    }
    let full = 1usize << vars;
    if end_exclusive >= full {
        return Block128::ONE;
    }
    let half = 1usize << (vars - 1);
    let high = point[vars - 1];
    if end_exclusive <= half {
        (Block128::ONE + high) * prefix_selector_native(end_exclusive, point, vars - 1)
    } else {
        (Block128::ONE + high)
            + high * prefix_selector_native(end_exclusive - half, point, vars - 1)
    }
}

fn prefix_selector_native_flat(end_exclusive: usize, point_flat: &[u128], vars: usize) -> u128 {
    if end_exclusive == 0 {
        return 0;
    }
    if vars == 0 {
        return 1;
    }
    let full = 1usize << vars;
    if end_exclusive >= full {
        return 1;
    }
    let half = 1usize << (vars - 1);
    let high = point_flat[vars - 1];
    if end_exclusive <= half {
        clmul_gcm(
            high ^ 1u128,
            prefix_selector_native_flat(end_exclusive, point_flat, vars - 1),
        )
    } else {
        (high ^ 1u128)
            ^ clmul_gcm(
                high,
                prefix_selector_native_flat(end_exclusive - half, point_flat, vars - 1),
            )
    }
}

/// Evaluate the zero-padded MLE of a prefix row selector at `point`.
fn prefix_selector_value(end_exclusive: usize, point: &[Block128], log_rows: usize) -> Block128 {
    debug_assert!(log_rows <= point.len());
    let native = prefix_selector_native(end_exclusive, point, log_rows);
    if native == Block128::ZERO {
        return Block128::ZERO;
    }
    native * high_zero_factor(point, log_rows)
}

fn prefix_selector_value_flat(end_exclusive: usize, point_flat: &[u128], log_rows: usize) -> u128 {
    debug_assert!(log_rows <= point_flat.len());
    let native = prefix_selector_native_flat(end_exclusive, point_flat, log_rows);
    if native == 0 {
        return 0;
    }
    clmul_gcm(native, high_zero_factor_flat(point_flat, log_rows))
}

/// Flat/GCM-basis variant of [`row_selector_value`].
#[inline]
fn row_selector_value_flat(row: usize, point_flat: &[u128], log_rows: usize) -> u128 {
    debug_assert!(log_rows <= point_flat.len());
    let mut acc = 1u128;
    for i in 0..log_rows {
        let coord = point_flat[i];
        let factor = if ((row >> i) & 1) == 1 {
            coord
        } else {
            coord ^ 1u128
        };
        if factor == 0 {
            return 0;
        }
        acc = clmul_gcm(acc, factor);
    }
    let hi = high_zero_factor_flat(point_flat, log_rows);
    if hi == 0 {
        return 0;
    }
    clmul_gcm(acc, hi)
}

/// `row_selector(row) · inner == 0`, where `row_selector` is not a committed
/// trace column.
///
/// Degree is `1 + inner.degree()`, matching the old committed-selector gate:
/// the row selector is a multilinear verifier-known polynomial in the AIR row
/// variables.  It is deterministic from `(row, log_rows, log_len)` and never
/// prover-chosen.
pub struct VirtualRowSelectorGate {
    row: usize,
    inner: Box<dyn Constraint>,
    cols: Vec<usize>,
    shifted: Vec<usize>,
}

/// `prefix_selector(0..end_exclusive) · inner == 0`, with the selector
/// evaluated virtually instead of committed as a multi-hot trace column.
pub struct VirtualPrefixSelectorGate {
    end_exclusive: usize,
    inner: Box<dyn Constraint>,
    cols: Vec<usize>,
    shifted: Vec<usize>,
}

impl VirtualRowSelectorGate {
    pub fn new(row: usize, inner: Box<dyn Constraint>) -> Self {
        let cols = inner.columns().to_vec();
        let shifted = inner.shifted_columns().to_vec();
        Self {
            row,
            inner,
            cols,
            shifted,
        }
    }

    pub fn row(&self) -> usize {
        self.row
    }
}

impl VirtualPrefixSelectorGate {
    pub fn new(end_exclusive: usize, inner: Box<dyn Constraint>) -> Self {
        let cols = inner.columns().to_vec();
        let shifted = inner.shifted_columns().to_vec();
        Self {
            end_exclusive,
            inner,
            cols,
            shifted,
        }
    }

    pub fn end_exclusive(&self) -> usize {
        self.end_exclusive
    }
}

impl Constraint for VirtualRowSelectorGate {
    fn degree(&self) -> usize {
        1 + self.inner.degree()
    }

    fn columns(&self) -> &[usize] {
        &self.cols
    }

    fn shifted_columns(&self) -> &[usize] {
        &self.shifted
    }

    fn needs_eval_point(&self) -> bool {
        true
    }

    fn evaluate(&self, _frame: EvalFrame) -> Block128 {
        panic!("VirtualRowSelectorGate requires row/point-aware evaluation")
    }

    fn evaluate_flat(&self, _frame: FlatEvalFrame) -> u128 {
        panic!("VirtualRowSelectorGate requires row/point-aware flat evaluation")
    }

    fn evaluate_row(&self, frame: EvalFrame, row: usize, _log_rows: usize) -> Block128 {
        if row == self.row {
            self.inner.evaluate(frame)
        } else {
            Block128::ZERO
        }
    }

    fn evaluate_at_point(&self, frame: EvalFrame, point: &[Block128], log_rows: usize) -> Block128 {
        let selector = row_selector_value(self.row, point, log_rows);
        if selector == Block128::ZERO {
            return Block128::ZERO;
        }
        selector * self.inner.evaluate(frame)
    }

    fn evaluate_flat_at_point(
        &self,
        frame: FlatEvalFrame,
        point_flat: &[u128],
        log_rows: usize,
    ) -> u128 {
        let selector = row_selector_value_flat(self.row, point_flat, log_rows);
        if selector == 0 {
            return 0;
        }
        let inner = self.inner.evaluate_flat(frame);
        clmul_gcm(selector, inner)
    }
}

impl Constraint for VirtualPrefixSelectorGate {
    fn degree(&self) -> usize {
        1 + self.inner.degree()
    }

    fn columns(&self) -> &[usize] {
        &self.cols
    }

    fn shifted_columns(&self) -> &[usize] {
        &self.shifted
    }

    fn needs_eval_point(&self) -> bool {
        true
    }

    fn evaluate(&self, _frame: EvalFrame) -> Block128 {
        panic!("VirtualPrefixSelectorGate requires row/point-aware evaluation")
    }

    fn evaluate_flat(&self, _frame: FlatEvalFrame) -> u128 {
        panic!("VirtualPrefixSelectorGate requires row/point-aware flat evaluation")
    }

    fn evaluate_row(&self, frame: EvalFrame, row: usize, _log_rows: usize) -> Block128 {
        if row < self.end_exclusive {
            self.inner.evaluate(frame)
        } else {
            Block128::ZERO
        }
    }

    fn evaluate_at_point(&self, frame: EvalFrame, point: &[Block128], log_rows: usize) -> Block128 {
        let selector = prefix_selector_value(self.end_exclusive, point, log_rows);
        if selector == Block128::ZERO {
            return Block128::ZERO;
        }
        selector * self.inner.evaluate(frame)
    }

    fn evaluate_flat_at_point(
        &self,
        frame: FlatEvalFrame,
        point_flat: &[u128],
        log_rows: usize,
    ) -> u128 {
        let selector = prefix_selector_value_flat(self.end_exclusive, point_flat, log_rows);
        if selector == 0 {
            return 0;
        }
        let inner = self.inner.evaluate_flat(frame);
        clmul_gcm(selector, inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gates::{multi_row_indicator_programme, WeightedLinearGate};
    use noid_core::hardware::tower_to_flat_u128;
    use noid_core::mle::evaluate::evaluate_flat;

    #[test]
    fn virtual_row_selector_matches_single_hot_mle() {
        let log_rows = 4;
        let row = 9usize;
        let point: Vec<Block128> = (0..log_rows)
            .map(|i| Block128::from(0x100u128 + i as u128 * 17))
            .collect();
        let mut programme = vec![Block128::ZERO; 1 << log_rows];
        programme[row] = Block128::ONE;
        assert_eq!(
            row_selector_value(row, &point, log_rows),
            evaluate_flat(&programme, &point)
        );
    }

    #[test]
    fn virtual_row_selector_matches_zero_padded_single_hot_mle() {
        let log_rows = 3;
        let log_len = 5;
        let row = 6usize;
        let point: Vec<Block128> = (0..log_len)
            .map(|i| Block128::from(0x55u128 + i as u128 * 0x33))
            .collect();
        let mut programme = vec![Block128::ZERO; 1 << log_len];
        programme[row] = Block128::ONE;
        assert_eq!(
            row_selector_value(row, &point, log_rows),
            evaluate_flat(&programme, &point)
        );
    }

    #[test]
    fn virtual_row_selector_flat_matches_tower() {
        let log_rows = 3;
        let log_len = 4;
        let row = 5usize;
        let point: Vec<Block128> = (0..log_len)
            .map(|i| Block128::from(0xAAu128 + i as u128 * 7))
            .collect();
        let point_flat: Vec<u128> = point.iter().map(|v| tower_to_flat_u128(v.0)).collect();
        let tower = row_selector_value(row, &point, log_rows);
        let flat = row_selector_value_flat(row, &point_flat, log_rows);
        assert_eq!(flat, tower_to_flat_u128(tower.0));
    }

    #[test]
    fn virtual_row_gate_fires_only_on_native_target_row() {
        let inner: Box<dyn Constraint> = Box::new(WeightedLinearGate::new_xor(vec![0, 1]));
        let gate = VirtualRowSelectorGate::new(2, inner);
        let bad = EvalFrame {
            local: &[Block128::ONE, Block128::ZERO],
            next: &[],
        };
        assert_eq!(gate.evaluate_row(bad, 0, 2), Block128::ZERO);
        assert_ne!(gate.evaluate_row(bad, 2, 2), Block128::ZERO);
    }

    #[test]
    fn virtual_prefix_selector_matches_multi_hot_mle() {
        let log_rows = 4;
        let end = 11usize;
        let point: Vec<Block128> = (0..log_rows)
            .map(|i| Block128::from(0x701u128 + i as u128 * 19))
            .collect();
        let rows: Vec<usize> = (0..end).collect();
        let programme = multi_row_indicator_programme(&rows, 1 << log_rows);
        assert_eq!(
            prefix_selector_value(end, &point, log_rows),
            evaluate_flat(&programme, &point)
        );
    }

    #[test]
    fn virtual_prefix_selector_matches_zero_padded_multi_hot_mle() {
        let log_rows = 3;
        let log_len = 5;
        let end = 5usize;
        let point: Vec<Block128> = (0..log_len)
            .map(|i| Block128::from(0x901u128 + i as u128 * 23))
            .collect();
        let rows: Vec<usize> = (0..end).collect();
        let native = multi_row_indicator_programme(&rows, 1 << log_rows);
        let mut padded = vec![Block128::ZERO; 1 << log_len];
        padded[..native.len()].copy_from_slice(&native);
        assert_eq!(
            prefix_selector_value(end, &point, log_rows),
            evaluate_flat(&padded, &point)
        );
    }

    #[test]
    fn virtual_prefix_selector_flat_matches_tower() {
        let log_rows = 4;
        let log_len = 6;
        let end = 9usize;
        let point: Vec<Block128> = (0..log_len)
            .map(|i| Block128::from(0xA01u128 + i as u128 * 29))
            .collect();
        let point_flat: Vec<u128> = point.iter().map(|v| tower_to_flat_u128(v.0)).collect();
        let tower = prefix_selector_value(end, &point, log_rows);
        let flat = prefix_selector_value_flat(end, &point_flat, log_rows);
        assert_eq!(flat, tower_to_flat_u128(tower.0));
    }

    #[test]
    fn virtual_prefix_gate_fires_on_native_prefix_only() {
        let inner: Box<dyn Constraint> = Box::new(WeightedLinearGate::new_xor(vec![0, 1]));
        let gate = VirtualPrefixSelectorGate::new(3, inner);
        let bad = EvalFrame {
            local: &[Block128::ONE, Block128::ZERO],
            next: &[],
        };
        assert_ne!(gate.evaluate_row(bad, 0, 3), Block128::ZERO);
        assert_ne!(gate.evaluate_row(bad, 2, 3), Block128::ZERO);
        assert_eq!(gate.evaluate_row(bad, 3, 3), Block128::ZERO);
    }
}
