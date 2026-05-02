// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! `LinearCombinationAir` — fixed-shape AIR enforcing `Σ_i col_i(x) == 0`
//! on the boolean hypercube. Used as the XOR-linear / balance test rig
//! for the sumcheck+FRI stack; higher-level gates build on it.

use crate::gates::WeightedLinearGate;
use crate::{Air, Constraint};

/// Fixed shape: `n_cols` columns, each of length `2^log_rows`. The
/// single constraint is `Σ_i col_i(x) == 0` for every hypercube point
/// `x`. This is the XOR-linear / balance gate — in GF(2^128), addition
/// is XOR, so forcing a sum to zero forces the columns to XOR to zero
/// row-by-row.
pub struct LinearCombinationAir {
    n_cols: usize,
    log_rows: usize,
    constraints: Vec<Box<dyn Constraint>>,
}

impl LinearCombinationAir {
    pub fn new(n_cols: usize, log_rows: usize) -> Self {
        let cols: Vec<usize> = (0..n_cols).collect();
        let constraints: Vec<Box<dyn Constraint>> =
            vec![Box::new(WeightedLinearGate::new_xor(cols))];
        Self {
            n_cols,
            log_rows,
            constraints,
        }
    }
}

impl Air for LinearCombinationAir {
    fn n_columns(&self) -> usize {
        self.n_cols
    }
    fn log_rows(&self) -> usize {
        self.log_rows
    }
    fn constraints(&self) -> &[Box<dyn Constraint>] {
        &self.constraints
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Trace;
    use noid_core::Block128;

    #[test]
    fn linear_gate_native_check() {
        let log_rows = 3;
        let air = LinearCombinationAir::new(3, log_rows);
        let n = 1 << log_rows;
        let col0: Vec<Block128> = (0..n).map(|i| Block128::from(i as u128 * 7 + 1)).collect();
        let col1: Vec<Block128> = (0..n).map(|i| Block128::from(i as u128 * 11 + 3)).collect();
        let col2: Vec<Block128> = col0
            .iter()
            .zip(col1.iter())
            .map(|(a, b)| *a + *b)
            .collect();
        let trace = Trace::new(vec![col0, col1, col2]);
        assert!(air.check(&trace));
    }

    #[test]
    fn linear_gate_rejects_imbalance() {
        let air = LinearCombinationAir::new(2, 2);
        let trace = Trace::new(vec![
            vec![Block128::from(1u128); 4],
            vec![Block128::from(2u128); 4],
        ]);
        assert!(!air.check(&trace));
    }
}
