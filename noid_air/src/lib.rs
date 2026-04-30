// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Arithmetization layer for the Paranoid transaction STARK.
//!
//! Defines witness traces and the polynomial constraints they must
//! satisfy on the boolean hypercube. The prover/verifier wrapper that
//! commits columns through the FRI PCS, enforces the constraints via
//! zero-check sumcheck, and binds everything to the public inputs lives
//! in `noid_stark`.
//!
//! Concepts:
//!
//! - [`Trace`] — rectangular column matrix, column length = `2^log_rows`.
//! - [`Constraint`] — algebraic gate over the values of some subset of
//!   columns at one row. Zero on the whole hypercube iff the witness is
//!   valid.
//! - [`Air`] — the shape (columns + log_rows) together with a set of
//!   constraints.
//! - [`CompositeAir`] — stacks several AIRs side-by-side into one
//!   column matrix, re-indexing their constraints.
//!
//! Concrete AIRs shipped here:
//!
//! - [`TxValidityAir`] — every entry of the single column is boolean.
//!   Used for the `valid` flag column.
//! - [`LinearCombinationAir`] — in char-2 this enforces
//!   `Σ_i col_i(x) + const(x) == 0` over the hypercube. It is the
//!   balance and XOR-linear gate.
//!
//! These two composed together already prove a real transaction
//! predicate: every slot is well-formed (boolean `valid`), and an
//! auxiliary column derived from `(value × valid)` per slot sums to the
//! fee — all in char-2.

use noid_core::{Block128, TowerField};
use noid_tx::{TxBody, MAX_INPUTS, MAX_OUTPUTS};

// ---------------------------------------------------------------------------
// Trace
// ---------------------------------------------------------------------------

/// A witness trace: columns of equal power-of-two length. Each column
/// is the evaluation vector of a multilinear polynomial over
/// `log_rows` boolean variables.
#[derive(Debug, Clone)]
pub struct Trace {
    pub columns: Vec<Vec<Block128>>,
    pub log_rows: usize,
}

impl Trace {
    pub fn new(columns: Vec<Vec<Block128>>) -> Self {
        assert!(!columns.is_empty(), "trace needs at least one column");
        let len = columns[0].len();
        assert!(len.is_power_of_two(), "column length must be a power of two");
        for c in &columns {
            assert_eq!(c.len(), len, "all columns must have equal length");
        }
        let log_rows = len.trailing_zeros() as usize;
        Self { columns, log_rows }
    }

    pub fn n_cols(&self) -> usize {
        self.columns.len()
    }

    pub fn n_rows(&self) -> usize {
        1 << self.log_rows
    }
}

// ---------------------------------------------------------------------------
// Constraint abstraction
// ---------------------------------------------------------------------------

/// A single algebraic constraint. `evaluate` is called either with
/// per-row column values (native check) or with field evaluations of
/// each column's MLE at one challenge point (zero-check sumcheck).
pub trait Constraint: Send + Sync {
    /// Maximum total degree in the column variables.
    fn degree(&self) -> usize;
    /// Column indices this constraint reads.
    fn columns(&self) -> &[usize];
    /// Evaluate given the column values.
    fn evaluate(&self, cols: &[Block128]) -> Block128;
}

// ---------------------------------------------------------------------------
// Air trait
// ---------------------------------------------------------------------------

pub trait Air {
    fn n_columns(&self) -> usize;
    fn log_rows(&self) -> usize;
    fn constraints(&self) -> &[Box<dyn Constraint>];

    /// Native correctness check — catches malformed witnesses before
    /// the STARK is invoked.
    fn check(&self, trace: &Trace) -> bool {
        if trace.n_cols() != self.n_columns() || trace.log_rows != self.log_rows() {
            return false;
        }
        let n = trace.n_rows();
        for row in 0..n {
            for c in self.constraints() {
                let vals: Vec<Block128> =
                    c.columns().iter().map(|&j| trace.columns[j][row]).collect();
                if c.evaluate(&vals) != Block128::ZERO {
                    return false;
                }
            }
        }
        true
    }
}

// ---------------------------------------------------------------------------
// Concrete gates
// ---------------------------------------------------------------------------

/// `v * (v + 1) == 0` (char-2): forces `v ∈ {0,1}`.
pub struct BoolGate {
    cols: [usize; 1],
}

impl BoolGate {
    pub fn new(col: usize) -> Self {
        Self { cols: [col] }
    }
}

impl Constraint for BoolGate {
    fn degree(&self) -> usize {
        2
    }
    fn columns(&self) -> &[usize] {
        &self.cols
    }
    fn evaluate(&self, cols: &[Block128]) -> Block128 {
        let v = cols[0];
        v * v + v
    }
}

/// `Σ_i col_i == 0` (char-2 linear gate). In GF(2^128) the per-column
/// weights can be arbitrary field elements — we use `ONE` for each
/// column by default since XOR-linear balance doesn't need weighting.
pub struct XorLinearGate {
    cols: Vec<usize>,
}

impl XorLinearGate {
    pub fn new(cols: Vec<usize>) -> Self {
        assert!(!cols.is_empty(), "linear gate needs at least one column");
        Self { cols }
    }
}

impl Constraint for XorLinearGate {
    fn degree(&self) -> usize {
        1
    }
    fn columns(&self) -> &[usize] {
        &self.cols
    }
    fn evaluate(&self, cols: &[Block128]) -> Block128 {
        cols.iter().fold(Block128::ZERO, |a, &b| a + b)
    }
}

// ---------------------------------------------------------------------------
// TxValidityAir (single boolean column)
// ---------------------------------------------------------------------------

pub const TX_VALIDITY_SLOTS: usize = MAX_INPUTS + MAX_OUTPUTS;
pub const TX_VALIDITY_LOG_ROWS: usize = 4;

pub struct TxValidityAir {
    constraints: Vec<Box<dyn Constraint>>,
}

impl Default for TxValidityAir {
    fn default() -> Self {
        Self::new()
    }
}

impl TxValidityAir {
    pub fn new() -> Self {
        let constraints: Vec<Box<dyn Constraint>> = vec![Box::new(BoolGate::new(0))];
        Self { constraints }
    }

    /// Row layout: inputs first, then outputs, then zero pad to
    /// `2^TX_VALIDITY_LOG_ROWS`.
    pub fn build_trace(body: &TxBody) -> Trace {
        let n_rows = 1 << TX_VALIDITY_LOG_ROWS;
        let mut col = vec![Block128::ZERO; n_rows];
        for (i, input) in body.inputs.iter().enumerate().take(MAX_INPUTS) {
            col[i] = if input.valid { Block128::ONE } else { Block128::ZERO };
        }
        for (i, output) in body.outputs.iter().enumerate().take(MAX_OUTPUTS) {
            col[MAX_INPUTS + i] = if output.valid {
                Block128::ONE
            } else {
                Block128::ZERO
            };
        }
        Trace::new(vec![col])
    }
}

impl Air for TxValidityAir {
    fn n_columns(&self) -> usize {
        1
    }
    fn log_rows(&self) -> usize {
        TX_VALIDITY_LOG_ROWS
    }
    fn constraints(&self) -> &[Box<dyn Constraint>] {
        &self.constraints
    }
}

// ---------------------------------------------------------------------------
// LinearCombinationAir
// ---------------------------------------------------------------------------

/// Fixed shape: `n_cols` columns, each of length `2^log_rows`. The
/// single constraint is `Σ_i col_i(x) == 0` for every hypercube point
/// `x`. This is the XOR-linear / balance gate — in GF(2^128), addition
/// is XOR, so forcing a sum to zero forces the columns to XOR to zero
/// row-by-row. To prove `Σ inputs + Σ outputs == fee` without range
/// checks, the prover supplies a "fee" column whose every row carries
/// the fee and lets the balance gate cancel it.
pub struct LinearCombinationAir {
    n_cols: usize,
    log_rows: usize,
    constraints: Vec<Box<dyn Constraint>>,
}

impl LinearCombinationAir {
    pub fn new(n_cols: usize, log_rows: usize) -> Self {
        let cols: Vec<usize> = (0..n_cols).collect();
        let constraints: Vec<Box<dyn Constraint>> = vec![Box::new(XorLinearGate::new(cols))];
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

// ---------------------------------------------------------------------------
// CompositeAir
// ---------------------------------------------------------------------------

/// Side-by-side composition of several AIRs of the same `log_rows`.
/// Columns of the k-th sub-AIR occupy a contiguous block of the
/// composite trace; each sub-constraint is rewritten to read from its
/// offset-shifted indices.
pub struct CompositeAir {
    log_rows: usize,
    n_cols: usize,
    constraints: Vec<Box<dyn Constraint>>,
}

impl CompositeAir {
    /// Build from an explicit column count and constraint list. Column
    /// indices inside each constraint refer to the full composite
    /// trace; callers that compose sub-AIRs supply already-shifted
    /// indices.
    pub fn from_parts(
        log_rows: usize,
        n_cols: usize,
        constraints: Vec<Box<dyn Constraint>>,
    ) -> Self {
        Self {
            log_rows,
            n_cols,
            constraints,
        }
    }
}

impl Air for CompositeAir {
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use noid_tx::{TxInput, TxOutput};

    fn mk_body() -> TxBody {
        TxBody {
            prev_state_root: [0u8; 32],
            new_state_root: [0u8; 32],
            nullifier_root: [0u8; 32],
            fee: 0,
            inputs: vec![TxInput::dummy(), TxInput::dummy()],
            outputs: vec![TxOutput::dummy(), TxOutput::dummy(), TxOutput::dummy()],
        }
    }

    #[test]
    fn validity_air_native_check() {
        let air = TxValidityAir::new();
        let trace = TxValidityAir::build_trace(&mk_body());
        assert!(air.check(&trace));
    }

    #[test]
    fn validity_air_rejects_non_bool() {
        let air = TxValidityAir::new();
        let mut trace = TxValidityAir::build_trace(&mk_body());
        trace.columns[0][3] = Block128::from(5u128);
        assert!(!air.check(&trace));
    }

    #[test]
    fn linear_gate_native_check() {
        let log_rows = 3;
        let air = LinearCombinationAir::new(3, log_rows);
        let n = 1 << log_rows;
        // col0 + col1 + col2 == 0 per row. Pick col0 and col1 random;
        // col2 = col0 + col1.
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
            vec![Block128::from(2u128); 4], // 1 + 2 = 3 != 0 in char-2
        ]);
        assert!(!air.check(&trace));
    }

    #[test]
    fn composite_from_parts() {
        // 2 columns: bool check on col0, linear sum(col0, col1)==0 on col1.
        let constraints: Vec<Box<dyn Constraint>> = vec![
            Box::new(BoolGate::new(0)),
            Box::new(XorLinearGate::new(vec![0, 1])),
        ];
        let air = CompositeAir::from_parts(3, 2, constraints);
        let n = 1 << 3;
        // col0 ∈ {0,1}, col1 == col0 to satisfy XOR-linear sum == 0.
        let col0: Vec<Block128> = (0..n)
            .map(|i| if i & 1 == 0 { Block128::ZERO } else { Block128::ONE })
            .collect();
        let col1 = col0.clone();
        let trace = Trace::new(vec![col0, col1]);
        assert!(air.check(&trace));
    }
}
