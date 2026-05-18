// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! `PublicColumn`: an AIR-level declaration that trace column `col`
//! must match a fixed, verifier-known sequence `values[0..2^log_rows]`.
//!
//! This is the Stage 3d-0.1 primitive that closes every "trusted-input"
//! debt carried from §3c-1 (`rc` / `is_full` / `is_round`) and the
//! §3c-2/3/4 sponge boundaries (IV, absorb XOR, inter-perm carry, output
//! squeeze) — any cell that must equal a programme-defined constant
//! rather than a witness-free variable.
//!
//! The native `Air::check` path enforces `trace[col][row] == values[row]`
//! row-by-row. The STARK-layer integration (programme-MLE evaluation
//! at the sumcheck terminal `r`, no FRI commitment required) lands as
//! Stage 3d-0.2. Until then, `PublicColumn` is native-check only and
//! is not referenced by any STARK-composed AIR.
//!
//! Design note. `PublicColumn` is deliberately *not* a `Constraint`:
//! row-local constraints are evaluated at an arbitrary field point `r`
//! during the zero-check sumcheck where "row index" has no meaning, and
//! threading a row-index back into the sumcheck creates an infinite
//! regress (the row-index column itself would need pinning). An
//! AIR-level declaration sidesteps the regress: the verifier evaluates
//! the public MLE at `r` directly, no witness-level constraint needed.

use noid_core::Block128;

/// Pin a trace column to a fixed, publicly-known value sequence.
#[derive(Debug, Clone)]
pub struct PublicColumn {
    pub col: usize,
    pub values: Vec<Block128>,
}

impl PublicColumn {
    /// `values.len()` must equal `1 << log_rows` of the enclosing AIR.
    /// The constructor rejects empty or non-power-of-two sequences.
    pub fn new(col: usize, values: Vec<Block128>) -> Self {
        assert!(
            !values.is_empty() && values.len().is_power_of_two(),
            "PublicColumn: values.len() must be a non-zero power of two"
        );
        Self { col, values }
    }

    pub fn log_rows(&self) -> usize {
        self.values.len().trailing_zeros() as usize
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Air, BoolGate, Constraint, Trace};

    /// Test-only AIR: one ordinary `BoolGate` constraint plus one or
    /// more `PublicColumn` declarations. Exists to exercise the native
    /// check path end-to-end without pulling in a full §3c AIR.
    struct TestAir {
        log_rows: usize,
        n_cols: usize,
        constraints: Vec<Box<dyn Constraint>>,
        publics: Vec<PublicColumn>,
    }

    impl Air for TestAir {
        fn n_columns(&self) -> usize {
            self.n_cols
        }
        fn log_rows(&self) -> usize {
            self.log_rows
        }
        fn constraints(&self) -> &[Box<dyn Constraint>] {
            &self.constraints
        }
        fn public_columns(&self) -> &[PublicColumn] {
            &self.publics
        }
    }

    fn round_constants_like() -> Vec<Block128> {
        // Four "programme" values — stand-in for a round-constant row.
        (0..4)
            .map(|i| Block128::from(0xDEAD_BEEF_0000_0000u128 ^ (i as u128)))
            .collect()
    }

    #[test]
    fn public_column_round_trip() {
        let vs: Vec<Block128> = (0..4).map(|i| Block128::from(i as u128)).collect();
        let p = PublicColumn::new(3, vs.clone());
        assert_eq!(p.col, 3);
        assert_eq!(p.log_rows(), 2);
        assert_eq!(p.values, vs);
    }

    #[test]
    #[should_panic(expected = "non-zero power of two")]
    fn public_column_rejects_non_power_of_two() {
        let _ = PublicColumn::new(0, vec![Block128::from(1u128); 3]);
    }

    #[test]
    #[should_panic(expected = "non-zero power of two")]
    fn public_column_rejects_empty() {
        let _ = PublicColumn::new(0, Vec::<Block128>::new());
    }

    #[test]
    fn air_check_accepts_matching_public_column() {
        // Two cols: col 0 is a witness bool, col 1 is the "programme".
        use noid_core::TowerField;
        let programme = round_constants_like();
        let air = TestAir {
            log_rows: 2,
            n_cols: 2,
            constraints: vec![Box::new(BoolGate::new(0))],
            publics: vec![PublicColumn::new(1, programme.clone())],
        };
        let col0 = vec![Block128::ZERO, Block128::ONE, Block128::ZERO, Block128::ONE];
        let trace = Trace::new(vec![col0, programme]);
        assert!(air.check(&trace));
    }

    #[test]
    fn air_check_rejects_tampered_public_column() {
        use noid_core::TowerField;
        let programme = round_constants_like();
        let air = TestAir {
            log_rows: 2,
            n_cols: 2,
            constraints: vec![Box::new(BoolGate::new(0))],
            publics: vec![PublicColumn::new(1, programme.clone())],
        };
        let col0 = vec![Block128::ZERO, Block128::ONE, Block128::ZERO, Block128::ONE];
        let mut bad = programme.clone();
        bad[2] += Block128::ONE;
        let trace = Trace::new(vec![col0, bad]);
        assert!(!air.check(&trace));
    }

    #[test]
    fn air_check_rejects_wrong_length_public_column() {
        // Declared column values length mismatches trace n_rows: the
        // check must reject rather than index-out-of-bounds.
        use noid_core::TowerField;
        let short: Vec<Block128> = (0..2).map(|_| Block128::ZERO).collect();
        // 4-row trace, but programme is only 2 rows.
        let air = TestAir {
            log_rows: 2,
            n_cols: 2,
            constraints: vec![Box::new(BoolGate::new(0))],
            publics: vec![PublicColumn::new(1, short)],
        };
        let col0 = vec![Block128::ZERO; 4];
        let col1 = vec![Block128::ZERO; 4];
        let trace = Trace::new(vec![col0, col1]);
        assert!(!air.check(&trace));
    }

    #[test]
    fn air_check_rejects_out_of_range_public_column() {
        use noid_core::TowerField;
        let programme = vec![Block128::ZERO; 4];
        let air = TestAir {
            log_rows: 2,
            n_cols: 2,
            constraints: vec![Box::new(BoolGate::new(0))],
            publics: vec![PublicColumn::new(7, programme)], // col 7 > n_cols
        };
        let col0 = vec![Block128::ZERO; 4];
        let col1 = vec![Block128::ZERO; 4];
        let trace = Trace::new(vec![col0, col1]);
        assert!(!air.check(&trace));
    }

    #[test]
    fn multiple_public_columns_all_enforced() {
        use noid_core::TowerField;
        let prog_a = round_constants_like();
        let prog_b: Vec<Block128> = (0..4)
            .map(|i| Block128::from(0xABCDu128 ^ i as u128))
            .collect();
        let air = TestAir {
            log_rows: 2,
            n_cols: 3,
            constraints: vec![Box::new(BoolGate::new(0))],
            publics: vec![
                PublicColumn::new(1, prog_a.clone()),
                PublicColumn::new(2, prog_b.clone()),
            ],
        };
        let col0 = vec![Block128::ZERO, Block128::ONE, Block128::ZERO, Block128::ONE];
        // Honest: both programme columns match.
        let trace = Trace::new(vec![col0.clone(), prog_a.clone(), prog_b.clone()]);
        assert!(air.check(&trace));

        // Tamper the second programme column — check must reject.
        let mut bad_b = prog_b;
        bad_b[0] += Block128::ONE;
        let bad_trace = Trace::new(vec![col0, prog_a, bad_b]);
        assert!(!air.check(&bad_trace));
    }
}
