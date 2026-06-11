// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! `SelectorGate`: wraps any constraint in a boolean selector column so
//! the underlying gate is suppressed at boundary / padding rows without
//! baking the selector into every constituent term by hand.

use crate::{Constraint, EvalFrame, FlatEvalFrame};
use noid_core::hardware::clmul_gcm;
use noid_core::{Block128, TowerField};

/// `selector · inner == 0` (or `(1 + selector) · inner == 0` when
/// constructed via [`SelectorGate::new_negated`]). Degree is
/// `1 + inner.degree()`. Rotation reads forward from
/// `inner.shifted_columns()`; the selector column is local-only.
pub struct SelectorGate {
    selector_col: usize,
    /// When `true`, evaluates as `(1 + selector) · inner`; i.e. fires
    /// on `selector == 0`, suppressed on `selector == 1`. Used when a
    /// row-constant marker (e.g. tx-level `is_coinbase`) must silence
    /// a sub-circuit wholesale.
    negated: bool,
    inner: Box<dyn Constraint>,
    cols: Vec<usize>,
    shifted: Vec<usize>,
    /// For each `inner.columns()[k]`, its index inside `self.cols`.
    inner_local_remap: Vec<usize>,
}

impl SelectorGate {
    pub fn new(selector_col: usize, inner: Box<dyn Constraint>) -> Self {
        Self::build(selector_col, inner, false)
    }

    /// `(1 + selector) · inner == 0` — fires when `selector = 0`,
    /// suppressed when `selector = 1`. The GF(2) complement pattern.
    pub fn new_negated(selector_col: usize, inner: Box<dyn Constraint>) -> Self {
        Self::build(selector_col, inner, true)
    }

    fn build(selector_col: usize, inner: Box<dyn Constraint>, negated: bool) -> Self {
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
            negated,
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
        let raw = frame.local[0];
        let selector = if self.negated {
            Block128::ONE + raw
        } else {
            raw
        };
        if self.inner_local_remap.is_empty() {
            return selector
                * self.inner.evaluate(EvalFrame {
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
    /// [2.C.4] Flat-basis evaluator. Selector columns are GF(2)-valued
    /// (`BoolGate`-constrained upstream), so `F(selector) = selector` and
    /// the tower `selector * inner` becomes `clmul_gcm(selector,
    /// inner.evaluate_flat(...))`. The index-remap mirrors the tower path.
    ///
    /// [2.C.4b] Uses a fixed-size STACK array for index remapping when
    /// arity ≤ 16. Eliminates the `Vec<u128>` heap allocation that was
    /// previously called ~25 million times per wallet proof (158 constraints
    /// × 4096 positions × 13 rounds × 3 samples), saving ~250 ms.
    fn evaluate_flat(&self, frame: FlatEvalFrame) -> u128 {
        // Selector columns are GF(2)-valued; the `(1 + sel)` complement
        // over char-2 is just `sel ^ 1`.
        let raw = frame.local[0];
        let selector = if self.negated { raw ^ 1u128 } else { raw };
        let remap = &self.inner_local_remap;
        let inner_val = match remap.len() {
            // Common case: no remapping (inner has no local columns).
            0 => self.inner.evaluate_flat(FlatEvalFrame {
                local: &[],
                next: frame.next,
            }),
            // Fast path: stack-allocated buffer avoids heap allocation.
            // TxLogicAir inner gates have at most ~4 local columns;
            // the bound of 16 covers all realistic gate arities.
            n if n <= 16 => {
                let mut buf = [0u128; 16];
                for (dst, &src) in buf[..n].iter_mut().zip(remap.iter()) {
                    *dst = frame.local[src];
                }
                self.inner.evaluate_flat(FlatEvalFrame {
                    local: &buf[..n],
                    next: frame.next,
                })
            }
            // Fallback for unusually wide inner gates.
            _ => {
                let inner_local: Vec<u128> = remap.iter().map(|&i| frame.local[i]).collect();
                self.inner.evaluate_flat(FlatEvalFrame {
                    local: &inner_local,
                    next: frame.next,
                })
            }
        };
        clmul_gcm(selector, inner_val)
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
        let inner: Box<dyn Constraint> = Box::new(WeightedLinearGate::new_xor(vec![1, 2]));
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
        let inner: Box<dyn Constraint> = Box::new(WeightedLinearGate::new_xor(vec![1, 2]));
        let sel = SelectorGate::new(0, inner);
        let air = CompositeAir::from_parts(2, 3, vec![Box::new(sel)]);
        let n = 1 << 2;
        let col0 = vec![Block128::ONE; n];
        let col1: Vec<Block128> = (0..n).map(|i| Block128::from(i as u128 + 1)).collect();
        let col2 = vec![Block128::from(42u128); n];
        let trace = Trace::new(vec![col0, col1, col2]);
        assert!(!air.check(&trace));
    }

    /// [2.C.4] Native `evaluate_flat` must equal
    /// `tower_to_flat_u128(evaluate(...))` on every honest input.
    #[test]
    fn selector_flat_matches_tower() {
        use noid_core::hardware::tower_to_flat_u128;
        let inner: Box<dyn Constraint> = Box::new(WeightedLinearGate::new_xor(vec![1, 2]));
        let sel = SelectorGate::new(0, inner);
        for (s_raw, a_raw, b_raw) in [
            (0u128, 0u128, 0u128),
            (1, 0xdeadbeef, 0xcafef00d),
            (0, 0xffff_ffff_ffff_ffff, 1),
            (1, 0x1234_5678_90ab_cdef, 0xfedc_ba98_7654_3210),
        ] {
            let s = Block128::from(s_raw);
            let a = Block128::from(a_raw);
            let b = Block128::from(b_raw);
            let tower_out = <SelectorGate as Constraint>::evaluate(
                &sel,
                EvalFrame {
                    local: &[s, a, b],
                    next: &[],
                },
            );
            let flat_out = <SelectorGate as Constraint>::evaluate_flat(
                &sel,
                FlatEvalFrame {
                    local: &[
                        tower_to_flat_u128(s.0),
                        tower_to_flat_u128(a.0),
                        tower_to_flat_u128(b.0),
                    ],
                    next: &[],
                },
            );
            assert_eq!(flat_out, tower_to_flat_u128(tower_out.0));
        }
    }

    /// `new_negated` — inner fires when selector = 0, is suppressed
    /// when selector = 1. Dual of `selector_gate_suppresses_on_zero_selector`.
    #[test]
    fn selector_gate_negated_suppresses_on_one_selector() {
        let inner: Box<dyn Constraint> = Box::new(WeightedLinearGate::new_xor(vec![1, 2]));
        let sel = SelectorGate::new_negated(0, inner);
        let air = CompositeAir::from_parts(2, 3, vec![Box::new(sel)]);
        let n = 1 << 2;
        let col0 = vec![Block128::ONE; n];
        let col1: Vec<Block128> = (0..n).map(|i| Block128::from(i as u128 + 1)).collect();
        let col2 = vec![Block128::from(42u128); n];
        let trace = Trace::new(vec![col0, col1, col2]);
        assert!(air.check(&trace));
    }

    /// `new_negated` — inner fires when selector = 0: violating rows
    /// must reject.
    #[test]
    fn selector_gate_negated_fires_on_zero_selector() {
        let inner: Box<dyn Constraint> = Box::new(WeightedLinearGate::new_xor(vec![1, 2]));
        let sel = SelectorGate::new_negated(0, inner);
        let air = CompositeAir::from_parts(2, 3, vec![Box::new(sel)]);
        let n = 1 << 2;
        let col0 = vec![Block128::ZERO; n];
        let col1: Vec<Block128> = (0..n).map(|i| Block128::from(i as u128 + 1)).collect();
        let col2 = vec![Block128::from(42u128); n];
        let trace = Trace::new(vec![col0, col1, col2]);
        assert!(!air.check(&trace));
    }

    /// Flat-vs-tower equivalence for the negated variant: selector = 0
    /// (fire) and selector = 1 (suppress), each against honest and
    /// adversarial inner payloads.
    #[test]
    fn selector_negated_flat_matches_tower() {
        use noid_core::hardware::tower_to_flat_u128;
        let inner: Box<dyn Constraint> = Box::new(WeightedLinearGate::new_xor(vec![1, 2]));
        let sel = SelectorGate::new_negated(0, inner);
        for (s_raw, a_raw, b_raw) in [
            (0u128, 0u128, 0u128),
            (0, 0xdeadbeef, 0xcafef00d),
            (1, 0xffff_ffff_ffff_ffff, 1),
            (1, 0x1234_5678_90ab_cdef, 0xfedc_ba98_7654_3210),
        ] {
            let s = Block128::from(s_raw);
            let a = Block128::from(a_raw);
            let b = Block128::from(b_raw);
            let tower_out = <SelectorGate as Constraint>::evaluate(
                &sel,
                EvalFrame {
                    local: &[s, a, b],
                    next: &[],
                },
            );
            let flat_out = <SelectorGate as Constraint>::evaluate_flat(
                &sel,
                FlatEvalFrame {
                    local: &[
                        tower_to_flat_u128(s.0),
                        tower_to_flat_u128(a.0),
                        tower_to_flat_u128(b.0),
                    ],
                    next: &[],
                },
            );
            assert_eq!(flat_out, tower_to_flat_u128(tower_out.0));
        }
    }

    #[test]
    fn selector_gate_degree_includes_selector() {
        let inner: Box<dyn Constraint> = Box::new(BoolGate::new(1));
        let sel = SelectorGate::new(0, inner);
        assert_eq!(<SelectorGate as Constraint>::degree(&sel), 3);
    }
}
