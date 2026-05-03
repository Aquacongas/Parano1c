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
//! Module layout:
//!
//! - [`gates`] — reusable Stage 3b-1 primitives (`BoolGate`,
//!   `WeightedLinearGate`, `SelectorGate`).
//! - [`airs`] — concrete AIRs (`TxValidityAir`, `CarryRippleAir`,
//!   `LinearCombinationAir`).

use noid_core::{Block128, TowerField};

pub mod airs;
pub mod gates;

pub use airs::{
    build_balance_columns, emit_balance_constraints, emit_block_constraints, AccInitGate,
    AccNextGate, BalanceBridgeBitsGate, BalanceBridgeCarryGate, BalanceFinalCarryGate,
    BalanceFinalSumGate, BalanceGateAir, BalanceZeroAtTransitionGate, BitAdderAir,
    BitAdderCarryInitGate, BitAdderCarryNextGate, BitAdderLayout, CarryInitGate, CarryNextGate,
    apply_mds_row, build_perm_trace, build_sbox_x7_columns, emit_mds_row_constraints,
    emit_perm_all, emit_perm_all_at, emit_perm_mds_blend, emit_perm_mds_blend_at,
    emit_perm_partial_sbox_kill, emit_perm_partial_sbox_kill_at, emit_perm_rc_binding,
    emit_perm_rc_binding_at, emit_perm_sbox_chain, emit_perm_sbox_chain_at,
    emit_sbox_x7_constraints, extract_perm_output, is_full_round, write_perm_trace_at,
    CarryRippleAir, FaSumGate, PartialSboxKillGate, PermLayout, PermMdsBlendGate,
    LinearCombinationAir, MdsKind, MdsLayout, MdsRowGate, PadZeroGate, PoseidonPermColumns,
    DEFAULT_PERM_LAYOUT,
    build_haddr_trace, emit_haddr_constraints, extract_haddr_output, HAddrAir, HADDR_LAYOUT_A,
    HADDR_LAYOUT_B, HADDR_LOG_ROWS, HADDR_N_COLS, HADDR_N_ROWS, HADDR_PAD_0, HADDR_PAD_1,
    HADDR_PERM_A_BASE, HADDR_PERM_B_BASE,
    build_hauth_trace, emit_hauth_constraints, extract_hauth_output, HAuthAir, HAUTH_LAYOUT_A,
    HAUTH_LAYOUT_B, HAUTH_LAYOUT_C, HAUTH_LOG_ROWS, HAUTH_N_COLS, HAUTH_N_ROWS, HAUTH_PERM_A_BASE,
    HAUTH_PERM_B_BASE, HAUTH_PERM_C_BASE,
    build_hleaf_trace, emit_hleaf_constraints, extract_hleaf_output, HLeafAir, HLEAF_LAYOUT_A,
    HLEAF_LAYOUT_B, HLEAF_LAYOUT_C, HLEAF_LOG_ROWS, HLEAF_N_COLS, HLEAF_N_ROWS, HLEAF_PERM_A_BASE,
    HLEAF_PERM_B_BASE, HLEAF_PERM_C_BASE,
    RangeGateAir, SboxX7Layout, TxValidityAir,
    TxValidityCol, WeightInitGate, WeightNextGate, BALANCE_MIN_LOG_ROWS, BALANCE_N_BLOCKS,
    BALANCE_N_COLS, BIT_ADDER_COL_A, BIT_ADDER_COL_B, BIT_ADDER_COL_CARRY, BIT_ADDER_COL_IS_INPUT,
    BIT_ADDER_COL_IS_RESET, BIT_ADDER_COL_SUM, BIT_ADDER_LOG_WORD_BITS, BIT_ADDER_MAX_WIDTH,
    BIT_ADDER_N_COLS, BIT_ADDER_WORD_BITS, CARRY_RIPPLE_COL_A, CARRY_RIPPLE_COL_B,
    CARRY_RIPPLE_COL_CARRY, CARRY_RIPPLE_COL_IS_RESET, CARRY_RIPPLE_COL_SUM,
    CARRY_RIPPLE_LOG_WORD_BITS, CARRY_RIPPLE_N_COLS, CARRY_RIPPLE_WORD_BITS, RANGE_GATE_COL_ACC,
    RANGE_GATE_COL_BIT, RANGE_GATE_COL_IS_RESET, RANGE_GATE_COL_WEIGHT, RANGE_GATE_LOG_WORD_BITS,
    POSEIDON_COL_IS_FULL, POSEIDON_COL_IS_ROUND, POSEIDON_COL_RC, POSEIDON_COL_S,
    POSEIDON_COL_SIN, POSEIDON_COL_SOUT, POSEIDON_COL_X2, POSEIDON_COL_X3, POSEIDON_COL_X4, POSEIDON_N_ACTIVE_ROWS, POSEIDON_PERM_LOG_ROWS,
    POSEIDON_PERM_N_COLS, POSEIDON_PERM_N_ROWS, RANGE_GATE_N_COLS, RANGE_GATE_WORD_BITS,
    SBOX_X7_N_COLS, TX_VALIDITY_3B4_LOG_ROWS, TX_VALIDITY_3B4_N_COLS,
    TX_VALIDITY_BALANCE_COL_OFFSET, TX_VALIDITY_LOG_ROWS, TX_VALIDITY_N_COLS, TX_VALIDITY_ROWS,
    TX_VALIDITY_SLOTS,
};
pub use gates::{BoolGate, MulGate, SelectorGate, SquareGate, WeightedLinearGate};

// ---------------------------------------------------------------------------
// Column domain (Binius small-field tag)
// ---------------------------------------------------------------------------

/// The logical small-field a column lives in. Used by the DA / commitment
/// layer to decide whether to ship the column on the bit-packed, byte-packed,
/// or raw Block128 path. Evaluation / constraint checking always lifts to
/// `Block128` — the domain tag is purely a serialisation / commitment hint,
/// so it is soundness-neutral — it tells DA how to ship the column, not how
/// AIR / STARK evaluate constraints.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColumnDomain {
    /// Every cell is `0` or `1`. Can be bit-packed 128x on DA.
    Bit,
    /// Every cell fits in the low byte. Can be byte-packed 16x on DA.
    Byte,
    /// Cell is a full GF(2^128) element; no packing.
    Block128,
}

// ---------------------------------------------------------------------------
// Trace
// ---------------------------------------------------------------------------

/// A witness trace: columns of equal power-of-two length. Each column
/// is the evaluation vector of a multilinear polynomial over
/// `log_rows` boolean variables. Each column carries a [`ColumnDomain`]
/// tag describing its logical small-field; by default all columns are
/// tagged `Block128` so legacy callers stay unchanged.
#[derive(Debug, Clone)]
pub struct Trace {
    pub columns: Vec<Vec<Block128>>,
    pub domains: Vec<ColumnDomain>,
    pub log_rows: usize,
}

impl Trace {
    pub fn new(columns: Vec<Vec<Block128>>) -> Self {
        let domains = vec![ColumnDomain::Block128; columns.len()];
        Self::new_with_domains(columns, domains)
    }

    pub fn new_with_domains(
        columns: Vec<Vec<Block128>>,
        domains: Vec<ColumnDomain>,
    ) -> Self {
        assert!(!columns.is_empty(), "trace needs at least one column");
        assert_eq!(
            columns.len(),
            domains.len(),
            "one domain tag required per column"
        );
        let len = columns[0].len();
        assert!(len.is_power_of_two(), "column length must be a power of two");
        for c in &columns {
            assert_eq!(c.len(), len, "all columns must have equal length");
        }
        let log_rows = len.trailing_zeros() as usize;
        for (col, dom) in columns.iter().zip(domains.iter()) {
            match dom {
                ColumnDomain::Bit => {
                    for v in col {
                        debug_assert!(
                            *v == Block128::ZERO || *v == Block128::ONE,
                            "Bit-tagged column contains non-bit cell"
                        );
                    }
                }
                ColumnDomain::Byte => {
                    for v in col {
                        debug_assert!(
                            v.to_u128() <= 0xff,
                            "Byte-tagged column contains cell > 0xff"
                        );
                    }
                }
                ColumnDomain::Block128 => {}
            }
        }
        Self {
            columns,
            domains,
            log_rows,
        }
    }

    pub fn n_cols(&self) -> usize {
        self.columns.len()
    }

    pub fn n_rows(&self) -> usize {
        1 << self.log_rows
    }

    pub fn domain(&self, col: usize) -> ColumnDomain {
        self.domains[col]
    }
}

// ---------------------------------------------------------------------------
// Constraint abstraction
// ---------------------------------------------------------------------------

/// Per-row evaluation frame presented to a [`Constraint`]. `local`
/// carries the column values at the current row (indexed by
/// [`Constraint::columns`]); `next` carries the values at the
/// cyclically-next row (indexed by [`Constraint::shifted_columns`]).
#[derive(Debug, Clone, Copy)]
pub struct EvalFrame<'a> {
    pub local: &'a [Block128],
    pub next: &'a [Block128],
}

/// A single algebraic constraint. `evaluate` is called either with
/// per-row column values (native check) or with field evaluations of
/// each column's MLE at one challenge point (zero-check sumcheck).
pub trait Constraint: Send + Sync {
    /// Maximum total degree in the column variables.
    fn degree(&self) -> usize;
    /// Column indices this constraint reads at the current row.
    fn columns(&self) -> &[usize];
    /// Column indices this constraint additionally reads at the
    /// cyclically-next row. Default is empty; gates that don't need
    /// rotation ignore `EvalFrame::next`.
    fn shifted_columns(&self) -> &[usize] {
        &[]
    }
    /// Evaluate the constraint on the given frame.
    fn evaluate(&self, frame: EvalFrame) -> Block128;
}

// ---------------------------------------------------------------------------
// Air trait
// ---------------------------------------------------------------------------

pub trait Air {
    fn n_columns(&self) -> usize;
    fn log_rows(&self) -> usize;
    fn constraints(&self) -> &[Box<dyn Constraint>];

    /// Sorted, de-duplicated union of `Constraint::shifted_columns()`
    /// across all constraints. This is the set of columns the STARK
    /// layer must materialise cyclically-rotated tables for, and for
    /// which VSHIFT ladder openings are required. Default-computed;
    /// override only for concrete AIRs that want to pin the layout.
    fn shifted_column_indices(&self) -> Vec<usize> {
        let mut out: Vec<usize> = Vec::new();
        for c in self.constraints() {
            for &j in c.shifted_columns() {
                if !out.contains(&j) {
                    out.push(j);
                }
            }
        }
        out.sort_unstable();
        out
    }

    /// Native correctness check — catches malformed witnesses before
    /// the STARK is invoked. Rotation is cyclic: `next(last) = first`.
    fn check(&self, trace: &Trace) -> bool {
        if trace.n_cols() != self.n_columns() || trace.log_rows != self.log_rows() {
            return false;
        }
        let n = trace.n_rows();
        for row in 0..n {
            let next_row = if row + 1 == n { 0 } else { row + 1 };
            for c in self.constraints() {
                let local: Vec<Block128> =
                    c.columns().iter().map(|&j| trace.columns[j][row]).collect();
                let next: Vec<Block128> = c
                    .shifted_columns()
                    .iter()
                    .map(|&j| trace.columns[j][next_row])
                    .collect();
                let frame = EvalFrame { local: &local, next: &next };
                if c.evaluate(frame) != Block128::ZERO {
                    return false;
                }
            }
        }
        true
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
// Cross-module composition tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn composite_from_parts() {
        // 2 columns: bool check on col0, linear sum(col0, col1)==0 on col1.
        let constraints: Vec<Box<dyn Constraint>> = vec![
            Box::new(BoolGate::new(0)),
            Box::new(WeightedLinearGate::new_xor(vec![0, 1])),
        ];
        let air = CompositeAir::from_parts(3, 2, constraints);
        let n = 1 << 3;
        let col0: Vec<Block128> = (0..n)
            .map(|i| if i & 1 == 0 { Block128::ZERO } else { Block128::ONE })
            .collect();
        let col1 = col0.clone();
        let trace = Trace::new(vec![col0, col1]);
        assert!(air.check(&trace));
    }
}
