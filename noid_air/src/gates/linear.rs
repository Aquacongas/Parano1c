// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! `WeightedLinearGate`: `Σ wᵢ · colᵢ + c == 0` — degree-1 linear gate
//! over GF(2^128). XOR-linear sum (all weights `ONE`, no constant) is
//! the special case exposed through [`WeightedLinearGate::new_xor`] and
//! used by balance / bit-XOR gates.

use crate::{Constraint, EvalFrame};
use noid_core::{Block128, TowerField};

/// `Σ_i weight_i · col_i + constant == 0`.
pub struct WeightedLinearGate {
    terms: Vec<(usize, Block128)>,
    constant: Block128,
    cols: Vec<usize>,
}

impl WeightedLinearGate {
    /// `Σ weight_i · col_i + constant == 0`. Column indices in `terms`
    /// must be unique.
    pub fn new(terms: Vec<(usize, Block128)>, constant: Block128) -> Self {
        assert!(!terms.is_empty(), "linear gate needs at least one column");
        let cols: Vec<usize> = terms.iter().map(|&(c, _)| c).collect();
        for i in 0..cols.len() {
            for j in (i + 1)..cols.len() {
                assert_ne!(
                    cols[i], cols[j],
                    "WeightedLinearGate: duplicate column index {}",
                    cols[i]
                );
            }
        }
        Self { terms, constant, cols }
    }

    /// `Σ col_i == 0` — the XOR-linear special case used by balance
    /// and bit-XOR gates.
    pub fn new_xor(cols: Vec<usize>) -> Self {
        let terms = cols.into_iter().map(|c| (c, Block128::ONE)).collect();
        Self::new(terms, Block128::ZERO)
    }
}

impl Constraint for WeightedLinearGate {
    fn degree(&self) -> usize {
        1
    }
    fn columns(&self) -> &[usize] {
        &self.cols
    }
    fn evaluate(&self, frame: EvalFrame) -> Block128 {
        let mut acc = self.constant;
        for (i, &(_, w)) in self.terms.iter().enumerate() {
            acc = acc + w * frame.local[i];
        }
        acc
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Air, CompositeAir, Trace};

    #[test]
    fn weighted_linear_gate_native_check_with_constant() {
        // 3 · col0 + 5 · col1 + 7 == 0.
        let w0 = Block128::from(3u128);
        let w1 = Block128::from(5u128);
        let k = Block128::from(7u128);
        let gate = WeightedLinearGate::new(vec![(0, w0), (1, w1)], k);
        let air = CompositeAir::from_parts(2, 2, vec![Box::new(gate)]);
        let inv_w1 = w1.invert();
        let n = 1 << 2;
        let col0: Vec<Block128> = (0..n).map(|i| Block128::from(i as u128 * 9 + 2)).collect();
        let col1: Vec<Block128> = col0.iter().map(|c| (w0 * *c + k) * inv_w1).collect();
        let trace = Trace::new(vec![col0, col1]);
        assert!(air.check(&trace));
    }

    #[test]
    fn weighted_linear_gate_rejects_wrong_constant() {
        let w0 = Block128::from(3u128);
        let w1 = Block128::from(5u128);
        let gate =
            WeightedLinearGate::new(vec![(0, w0), (1, w1)], Block128::from(7u128));
        let air = CompositeAir::from_parts(2, 2, vec![Box::new(gate)]);
        let col0: Vec<Block128> = (0..4).map(|i| Block128::from(i as u128)).collect();
        let inv_w1 = w1.invert();
        let col1: Vec<Block128> = col0.iter().map(|c| w0 * *c * inv_w1).collect();
        let trace = Trace::new(vec![col0, col1]);
        assert!(!air.check(&trace));
    }

    #[test]
    #[should_panic(expected = "duplicate column index")]
    fn weighted_linear_gate_rejects_duplicate_columns() {
        let _ = WeightedLinearGate::new(
            vec![(0, Block128::ONE), (0, Block128::from(2u128))],
            Block128::ZERO,
        );
    }
}
