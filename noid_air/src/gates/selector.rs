// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! `SelectorGate`: wraps any constraint in a boolean selector column so
//! the underlying gate is suppressed at boundary / padding rows without
//! baking the selector into every constituent term by hand.

use crate::{Constraint, EvalFrame};
use noid_core::Block128;

/// `selector · inner == 0`. Degree is `1 + inner.degree()`. Rotation
/// reads forward from `inner.shifted_columns()`; the selector column is
/// local-only.
pub struct SelectorGate {
    selector_col: usize,
    inner: Box<dyn Constraint>,
    cols: Vec<usize>,
    shifted: Vec<usize>,
    /// For each `inner.columns()[k]`, its index inside `self.cols`.
    inner_local_remap: Vec<usize>,
}

impl SelectorGate {
    pub fn new(selector_col: usize, inner: Box<dyn Constraint>) -> Self {
        let inner_cols: Vec<usize> = inner.columns().to_vec();
        let mut cols = vec![selector_col];
        for &c in &inner_cols {
            if !cols.contains(&c) {
                cols.push(c);
            }
        }
        let inner_local_remap: Vec<usize> = inner_cols
            .iter()
            .map(|c| cols.iter().position(|x| x == c).unwrap())
            .collect();
        let shifted = inner.shifted_columns().to_vec();
        Self {
            selector_col,
            inner,
            cols,
            shifted,
            inner_local_remap,
        }
    }

    pub fn selector_col(&self) -> usize {
        self.selector_col
    }
}

impl Constraint for SelectorGate {
    fn degree(&self) -> usize {
        1 + self.inner.degree()
    }
    fn columns(&self) -> &[usize] {
        &self.cols
    }
    fn shifted_columns(&self) -> &[usize] {
        &self.shifted
    }
    fn evaluate(&self, frame: EvalFrame) -> Block128 {
        let selector = frame.local[0];
        if self.inner_local_remap.is_empty() {
            return selector * self.inner.evaluate(EvalFrame {
                local: &[],
                next: frame.next,
            });
        }
        let inner_local: Vec<Block128> = self
            .inner_local_remap
            .iter()
            .map(|&i| frame.local[i])
            .collect();
        let inner_frame = EvalFrame {
            local: &inner_local,
            next: frame.next,
        };
        selector * self.inner.evaluate(inner_frame)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gates::{BoolGate, WeightedLinearGate};
    use crate::{Air, CompositeAir, Trace};
    use noid_core::TowerField;

    #[test]
    fn selector_gate_suppresses_on_zero_selector() {
        let inner: Box<dyn Constraint> =
            Box::new(WeightedLinearGate::new_xor(vec![1, 2]));
        let sel = SelectorGate::new(0, inner);
        let air = CompositeAir::from_parts(2, 3, vec![Box::new(sel)]);
        let n = 1 << 2;
        let col0 = vec![Block128::ZERO; n];
        let col1: Vec<Block128> = (0..n).map(|i| Block128::from(i as u128 + 1)).collect();
        let col2 = vec![Block128::from(42u128); n];
        let trace = Trace::new(vec![col0, col1, col2]);
        assert!(air.check(&trace));
    }

    #[test]
    fn selector_gate_fires_on_one_selector() {
        let inner: Box<dyn Constraint> =
            Box::new(WeightedLinearGate::new_xor(vec![1, 2]));
        let sel = SelectorGate::new(0, inner);
        let air = CompositeAir::from_parts(2, 3, vec![Box::new(sel)]);
        let n = 1 << 2;
        let col0 = vec![Block128::ONE; n];
        let col1: Vec<Block128> = (0..n).map(|i| Block128::from(i as u128 + 1)).collect();
        let col2 = vec![Block128::from(42u128); n];
        let trace = Trace::new(vec![col0, col1, col2]);
        assert!(!air.check(&trace));
    }

    #[test]
    fn selector_gate_degree_includes_selector() {
        let inner: Box<dyn Constraint> = Box::new(BoolGate::new(1));
        let sel = SelectorGate::new(0, inner);
        assert_eq!(<SelectorGate as Constraint>::degree(&sel), 3);
    }
}
