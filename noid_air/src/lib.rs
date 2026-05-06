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

use noid_core::hardware::{flat_to_tower_u128, tower_to_flat_u128};
use noid_core::{Block128, TowerField};

pub mod airs;
pub mod gates;

pub use airs::{
    apply_mds_row, bit_adder_is_input_programme, bit_adder_is_reset_programme,
    bit_adder_operand_programme, build_balance_columns, build_haddr_trace, build_hauth_trace,
    build_hleaf_trace, build_instance_layout, build_perm_trace, build_sbox_x7_columns,
    build_tx_body_merkle_trace, build_tx_body_merkle_trace_with_boundary_pins,
    build_tx_body_merkle_typed_trace, emit_balance_constraints,
    emit_balance_selector_public_columns, emit_balance_value_public_columns,
    emit_block_constraints, emit_haddr, emit_hauth, emit_hleaf, emit_mds_row_constraints,
    emit_perm_all, emit_perm_all_at, emit_perm_mds_blend, emit_perm_mds_blend_at,
    emit_perm_partial_sbox_kill, emit_perm_partial_sbox_kill_at, emit_perm_public_columns,
    emit_perm_public_columns_at, emit_perm_public_columns_row_major_at, emit_perm_rc_binding,
    emit_perm_rc_binding_at, emit_perm_sbox_chain, emit_perm_sbox_chain_at,
    emit_sbox_x7_constraints, emit_tx_body_merkle_constraints,
    emit_tx_body_merkle_constraints_with_boundary_pins, emit_tx_body_merkle_public_columns,
    emit_tx_body_merkle_public_columns_with_boundary_pins, extract_haddr_output,
    extract_hauth_output, extract_hleaf_output, extract_instance_output, extract_perm_output,
    instance_row_offset, is_full_round, leaf_rate_absorb_instance_ids, leaf_rate_payload_col,
    perm_is_full_values, perm_is_full_values_row_major, perm_is_round_values,
    perm_is_round_values_row_major, perm_rc_values, perm_rc_values_row_major,
    tx_body_merkle_column_domains, write_perm_trace_at, write_perm_trace_at_offset, AccInitGate,
    AccNextGate, BalanceBridgeBitsGate, BalanceBridgeCarryGate, BalanceFinalCarryGate,
    BalanceFinalSumGate, BalanceGateAir, BalanceZeroAtTransitionGate, BitAdderAir,
    BitAdderCarryInitGate, BitAdderCarryNextGate, BitAdderLayout, CarryInitGate, CarryNextGate,
    CarryRippleAir, FaSumGate, HAddrAir, HAuthAir, HLeafAir, LinearCombinationAir, MdsKind,
    MdsLayout, MdsRowGate, PadZeroGate, PartialSboxKillGate, PermLayout, PermMdsBlendGate,
    PoseidonPermColumns, RangeGateAir, SboxX7Layout, TxBodyMerkleAir, TxBodyMerkleBoundaryPins,
    TxBodySpineComposite, TxValidityAir, TxValidityCol, WeightInitGate, WeightNextGate,
    BALANCE_MIN_LOG_ROWS, BALANCE_N_BLOCKS, BALANCE_N_COLS, BIT_ADDER_COL_A, BIT_ADDER_COL_B,
    BIT_ADDER_COL_CARRY, BIT_ADDER_COL_IS_INPUT, BIT_ADDER_COL_IS_RESET, BIT_ADDER_COL_SUM,
    BIT_ADDER_LOG_WORD_BITS, BIT_ADDER_MAX_WIDTH, BIT_ADDER_N_COLS, BIT_ADDER_WORD_BITS,
    CARRY_RIPPLE_COL_A, CARRY_RIPPLE_COL_B, CARRY_RIPPLE_COL_CARRY, CARRY_RIPPLE_COL_IS_RESET,
    CARRY_RIPPLE_COL_SUM, CARRY_RIPPLE_LOG_WORD_BITS, CARRY_RIPPLE_N_COLS, CARRY_RIPPLE_WORD_BITS,
    DEFAULT_PERM_LAYOUT, HADDR_B_SEED_ROW, HADDR_IND_ROW_0, HADDR_IND_ROW_N_ROUNDS,
    HADDR_IND_ROW_OUTPUT, HADDR_LAYOUT_A, HADDR_LAYOUT_B, HADDR_LOG_ROWS, HADDR_N_COLS,
    HADDR_N_ROWS, HADDR_OUTPUT_ROW, HADDR_PAD_0, HADDR_PAD_1, HADDR_PERM_A_BASE, HADDR_PERM_B_BASE,
    HADDR_PRE_S_A_BASE, HADDR_PRE_S_B_BASE, HAUTH_B_SEED_ROW, HAUTH_C_SEED_ROW, HAUTH_IND_ROW_0,
    HAUTH_IND_ROW_2N_PLUS_1, HAUTH_IND_ROW_N_ROUNDS, HAUTH_IND_ROW_OUTPUT, HAUTH_LAYOUT_A,
    HAUTH_LAYOUT_B, HAUTH_LAYOUT_C, HAUTH_LOG_ROWS, HAUTH_N_COLS, HAUTH_N_ROWS, HAUTH_OUTPUT_ROW,
    HAUTH_PERM_A_BASE, HAUTH_PERM_B_BASE, HAUTH_PERM_C_BASE, HAUTH_PRE_S_A_BASE,
    HAUTH_PRE_S_B_BASE, HAUTH_PRE_S_C_BASE, HLEAF_B_SEED_ROW, HLEAF_C_SEED_ROW, HLEAF_IND_ROW_0,
    HLEAF_IND_ROW_2N_PLUS_1, HLEAF_IND_ROW_N_ROUNDS, HLEAF_IND_ROW_OUTPUT, HLEAF_LAYOUT_A,
    HLEAF_LAYOUT_B, HLEAF_LAYOUT_C, HLEAF_LOG_ROWS, HLEAF_N_COLS, HLEAF_N_ROWS, HLEAF_OUTPUT_ROW,
    HLEAF_PERM_A_BASE, HLEAF_PERM_B_BASE, HLEAF_PERM_C_BASE, HLEAF_PRE_S_A_BASE,
    HLEAF_PRE_S_B_BASE, HLEAF_PRE_S_C_BASE, N_LEAF_RATE_PAYLOAD_COLS, POSEIDON_COL_IS_FULL,
    POSEIDON_COL_IS_ROUND, POSEIDON_COL_RC, POSEIDON_COL_S, POSEIDON_COL_SIN, POSEIDON_COL_SOUT,
    POSEIDON_COL_X2, POSEIDON_COL_X3, POSEIDON_COL_X4, POSEIDON_N_ACTIVE_ROWS,
    POSEIDON_PERM_LOG_ROWS, POSEIDON_PERM_N_COLS, POSEIDON_PERM_N_ROWS, RANGE_GATE_COL_ACC,
    RANGE_GATE_COL_BIT, RANGE_GATE_COL_IS_RESET, RANGE_GATE_COL_WEIGHT, RANGE_GATE_LOG_WORD_BITS,
    RANGE_GATE_N_COLS, RANGE_GATE_WORD_BITS, SBOX_X7_N_COLS, SPINE_LOG_ROWS, TXBODY_MERKLE_LAYOUT,
    TXBODY_MERKLE_LOG_ROWS, TXBODY_MERKLE_N_COLS, TXBODY_MERKLE_N_COLS_WITH_BOUNDARY_PINS,
    TXBODY_MERKLE_N_PERMS, TXBODY_MERKLE_N_ROWS, TXBODY_MERKLE_PRE_S_BASE,
    TXBODY_MERKLE_SLOT_LOG_ROWS, TXBODY_MERKLE_SLOT_ROWS, TXV_COL_OFFSET, TXV_LIVE_ROWS,
    TX_BODY_MERKLE_COL_OFFSET, TX_VALIDITY_3B4_LOG_ROWS, TX_VALIDITY_3B4_N_COLS,
    TX_VALIDITY_3B4_PINNED_N_COLS, TX_VALIDITY_BALANCE_COL_OFFSET,
    TX_VALIDITY_INPUT_VALID_MASK_COL, TX_VALIDITY_LOG_ROWS, TX_VALIDITY_N_COLS,
    TX_VALIDITY_OUTPUT_VALID_MASK_COL, TX_VALIDITY_ROWS, TX_VALIDITY_SLOTS,
};
pub use gates::{
    emit_column_eq_at_next_row, emit_column_eq_at_row, emit_multi_row_selector, emit_public_cell,
    emit_row_selector, emit_rows_must_be_zero, multi_row_indicator_programme,
    row_indicator_programme, BoolGate, MulGate, PublicColumn, SelectorGate, SquareGate,
    WeightedLinearGate, WeightedLinearGateShifted,
};

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

    pub fn new_with_domains(columns: Vec<Vec<Block128>>, domains: Vec<ColumnDomain>) -> Self {
        assert!(!columns.is_empty(), "trace needs at least one column");
        assert_eq!(
            columns.len(),
            domains.len(),
            "one domain tag required per column"
        );
        let len = columns[0].len();
        assert!(
            len.is_power_of_two(),
            "column length must be a power of two"
        );
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

/// Flat-basis (GCM polynomial basis) evaluation frame — same
/// semantics as [`EvalFrame`] but the field elements are carried in
/// the `tower_to_flat_u128`-image basis. Used by
/// [`Constraint::evaluate_flat`] to avoid per-mul basis conversion in
/// the STARK zero-check hot path. XOR (additive group operation) is
/// basis-agnostic; multiplication in flat basis is a single
/// `clmul_gcm` call versus tower-basis Karatsuba.
///
/// **Invariant**: every element in `local` / `next` equals
/// `tower_to_flat_u128(v.0)` for the corresponding tower-basis
/// `Block128 v` that a tower-path caller would have supplied in
/// [`EvalFrame`]. Callers MUST NOT mix bases.
#[derive(Debug, Clone, Copy)]
pub struct FlatEvalFrame<'a> {
    pub local: &'a [u128],
    pub next: &'a [u128],
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

    /// [2.C.1] Flat-basis evaluator — default implementation converts
    /// the flat inputs back to tower, delegates to [`evaluate`], and
    /// converts the result back to flat. Bit-identical to the
    /// tower-basis path by construction (every operation factors
    /// through the same `evaluate` routine).
    ///
    /// Concrete gates can override this with a direct flat-basis
    /// implementation; overrides MUST satisfy: for every legal
    /// `EvalFrame f`, `evaluate_flat(frame_flat(f))` equals
    /// `tower_to_flat_u128(self.evaluate(f).0)`. This equivalence is
    /// what enables the STARK zero-check to swap bases without
    /// changing transcript bytes or the accept/reject set.
    ///
    /// Default-implementation: O(arity) basis conversions per
    /// `evaluate_flat` call — same cost as a no-op switch. Hot AIRs
    /// are expected to override once the STARK layer starts calling
    /// this path (landing in [2.C.2+]).
    fn evaluate_flat(&self, frame: FlatEvalFrame) -> u128 {
        let local_tower: Vec<Block128> = frame
            .local
            .iter()
            .map(|&v| Block128::from(flat_to_tower_u128(v)))
            .collect();
        let next_tower: Vec<Block128> = frame
            .next
            .iter()
            .map(|&v| Block128::from(flat_to_tower_u128(v)))
            .collect();
        let out = self.evaluate(EvalFrame {
            local: &local_tower,
            next: &next_tower,
        });
        tower_to_flat_u128(out.0)
    }
}

// ---------------------------------------------------------------------------
// Air trait
// ---------------------------------------------------------------------------

pub trait Air {
    fn n_columns(&self) -> usize;
    fn log_rows(&self) -> usize;
    fn constraints(&self) -> &[Box<dyn Constraint>];

    /// Trace columns pinned to a publicly-known, verifier-side value
    /// sequence (Stage 3d-0.1). Default empty: AIRs without pinned
    /// columns keep legacy behaviour. Each declared column must be in
    /// `0..n_columns()` and carry `2^log_rows()` values; duplicates are
    /// rejected by `Air::check`. STARK-layer verification of public
    /// columns lands in Stage 3d-0.2.
    fn public_columns(&self) -> &[PublicColumn] {
        &[]
    }

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
    ///
    /// # Safety-critical
    ///
    /// This pre-check is part of the node safety contour and MUST
    /// remain always-on in every release build from genesis onward.
    /// The fast path below is an identity-preserving rewrite of the
    /// reference implementation in [`check_legacy`]: for every `Trace`,
    /// both paths return the same `bool`. Regression is guarded by
    /// [`check_equivalence_for_tests`] plus per-AIR tamper tests.
    ///
    /// The rewrite avoids two hotspot costs from the reference path:
    ///   * per-row `Vec::<Block128>` heap allocations for
    ///     `c.columns()` and `c.shifted_columns()` projections,
    ///   * single-threaded execution on 2^log_rows rows × n_constraints.
    /// The *semantics* of the check are untouched.
    fn check(&self, trace: &Trace) -> bool {
        use rayon::prelude::*;

        if trace.n_cols() != self.n_columns() || trace.log_rows != self.log_rows() {
            return false;
        }
        let n = trace.n_rows();

        // Public-column pin-check — same linear scan, same order as the
        // reference implementation.
        for pc in self.public_columns() {
            if pc.col >= self.n_columns() || pc.values.len() != n {
                return false;
            }
            let col = &trace.columns[pc.col];
            for row in 0..n {
                if col[row] != pc.values[row] {
                    return false;
                }
            }
        }

        let constraints = self.constraints();
        if constraints.is_empty() || n == 0 {
            return true;
        }

        // SoA projection of the constraint index plan, built once per
        // `check` call. Mirrors the reference inner loop: for every
        // constraint we resolve `columns()` and `shifted_columns()` into
        // flat `u32` index arrays plus offsets. Doing this per-call
        // (rather than caching across calls) keeps `Air::check` free of
        // internal state and therefore safe to call on any `Trace`.
        let mut local_offsets: Vec<u32> = Vec::with_capacity(constraints.len() + 1);
        let mut next_offsets: Vec<u32> = Vec::with_capacity(constraints.len() + 1);
        let mut local_idx: Vec<u32> = Vec::new();
        let mut next_idx: Vec<u32> = Vec::new();
        let mut max_local = 0usize;
        let mut max_next = 0usize;
        local_offsets.push(0);
        next_offsets.push(0);
        // The top-of-function `trace.n_cols() == self.n_columns()`
        // equality plus the AIR's own invariant that its constraints
        // reference indices in `0..n_columns()` together imply every
        // `j` here is in-range for `trace.columns`. No added checks —
        // the reference path also panics on malformed AIRs.
        for c in constraints {
            let cols = c.columns();
            let shifted = c.shifted_columns();
            max_local = max_local.max(cols.len());
            max_next = max_next.max(shifted.len());
            for &j in cols {
                local_idx.push(j as u32);
            }
            for &j in shifted {
                next_idx.push(j as u32);
            }
            local_offsets.push(local_idx.len() as u32);
            next_offsets.push(next_idx.len() as u32);
        }

        // Parallel row sweep with `find_any`: equivalent to the
        // reference short-circuit `return false` on the first failing
        // constraint, just distributed across threads. Each worker
        // re-uses two scratch `Vec`s via `map_init`, matching the exact
        // slices the reference code passes to `c.evaluate`.
        let cols_ref: &[Vec<Block128>] = &trace.columns;
        let local_offsets_ref = &local_offsets;
        let next_offsets_ref = &next_offsets;
        let local_idx_ref = &local_idx;
        let next_idx_ref = &next_idx;

        let bad_row = (0..n).into_par_iter().map_init(
            || {
                (
                    Vec::<Block128>::with_capacity(max_local),
                    Vec::<Block128>::with_capacity(max_next),
                )
            },
            |(local_buf, next_buf), row| {
                let next_row = if row + 1 == n { 0 } else { row + 1 };
                for (ci, c) in constraints.iter().enumerate() {
                    let l_start = local_offsets_ref[ci] as usize;
                    let l_end = local_offsets_ref[ci + 1] as usize;
                    let n_start = next_offsets_ref[ci] as usize;
                    let n_end = next_offsets_ref[ci + 1] as usize;

                    local_buf.clear();
                    for &j in &local_idx_ref[l_start..l_end] {
                        local_buf.push(cols_ref[j as usize][row]);
                    }
                    next_buf.clear();
                    for &j in &next_idx_ref[n_start..n_end] {
                        next_buf.push(cols_ref[j as usize][next_row]);
                    }

                    let frame = EvalFrame {
                        local: local_buf,
                        next: next_buf,
                    };
                    if c.evaluate(frame) != Block128::ZERO {
                        return true;
                    }
                }
                false
            },
        );

        !bad_row.any(|failed| failed)
    }
}

/// Reference implementation of [`Air::check`]. Kept for equivalence
/// testing — the optimized `Air::check` must agree with this on every
/// input, both honest and malformed. **Never** call this from prod: it
/// exists solely as the oracle for regression guards.
#[doc(hidden)]
pub fn check_legacy<A: Air + ?Sized>(air: &A, trace: &Trace) -> bool {
    if trace.n_cols() != air.n_columns() || trace.log_rows != air.log_rows() {
        return false;
    }
    let n = trace.n_rows();
    for pc in air.public_columns() {
        if pc.col >= air.n_columns() || pc.values.len() != n {
            return false;
        }
        for row in 0..n {
            if trace.columns[pc.col][row] != pc.values[row] {
                return false;
            }
        }
    }
    for row in 0..n {
        let next_row = if row + 1 == n { 0 } else { row + 1 };
        for c in air.constraints() {
            let local: Vec<Block128> = c.columns().iter().map(|&j| trace.columns[j][row]).collect();
            let next: Vec<Block128> = c
                .shifted_columns()
                .iter()
                .map(|&j| trace.columns[j][next_row])
                .collect();
            let frame = EvalFrame {
                local: &local,
                next: &next,
            };
            if c.evaluate(frame) != Block128::ZERO {
                return false;
            }
        }
    }
    true
}

/// Asserts [`Air::check`] and [`check_legacy`] agree on `trace`. Used
/// by regression tests across concrete AIRs.
#[doc(hidden)]
pub fn check_equivalence_for_tests<A: Air + ?Sized>(air: &A, trace: &Trace) -> bool {
    air.check(trace) == check_legacy(air, trace)
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
    public_columns: Vec<PublicColumn>,
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
            public_columns: Vec::new(),
        }
    }

    /// Like [`from_parts`] but also declares a set of AIR-pinned public
    /// (programme) columns. Each declaration is native-checked by
    /// [`Air::check`] and bound at the STARK verifier via
    /// `check_public_columns` in `noid_stark`.
    pub fn from_parts_with_publics(
        log_rows: usize,
        n_cols: usize,
        constraints: Vec<Box<dyn Constraint>>,
        public_columns: Vec<PublicColumn>,
    ) -> Self {
        Self {
            log_rows,
            n_cols,
            constraints,
            public_columns,
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
    fn public_columns(&self) -> &[PublicColumn] {
        &self.public_columns
    }
}

// ---------------------------------------------------------------------------
// Cross-module composition tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn build_bool_xor_air(log_rows: usize) -> CompositeAir {
        let constraints: Vec<Box<dyn Constraint>> = vec![
            Box::new(BoolGate::new(0)),
            Box::new(WeightedLinearGate::new_xor(vec![0, 1])),
        ];
        CompositeAir::from_parts(log_rows, 2, constraints)
    }

    #[test]
    fn composite_from_parts() {
        let air = build_bool_xor_air(3);
        let n = 1 << 3;
        let col0: Vec<Block128> = (0..n)
            .map(|i| {
                if i & 1 == 0 {
                    Block128::ZERO
                } else {
                    Block128::ONE
                }
            })
            .collect();
        let col1 = col0.clone();
        let trace = Trace::new(vec![col0, col1]);
        assert!(air.check(&trace));
        assert!(check_equivalence_for_tests(&air, &trace));
    }

    /// Accept / reject equivalence between the optimized `Air::check`
    /// and the reference `check_legacy`, across a grid of:
    ///   * honest traces,
    ///   * every single-cell tamper (row × col flips),
    ///   * malformed shapes (wrong log_rows, wrong n_cols).
    /// Regression guard for [2.A].
    #[test]
    fn check_matches_legacy_on_honest_and_tampered() {
        for &log_rows in &[1usize, 2, 3, 6] {
            let n = 1usize << log_rows;
            let air = build_bool_xor_air(log_rows);

            // Honest: col0 = bit pattern, col1 = col0 (XOR == 0).
            let col0_honest: Vec<Block128> = (0..n)
                .map(|i| {
                    if i & 1 == 0 {
                        Block128::ZERO
                    } else {
                        Block128::ONE
                    }
                })
                .collect();
            let col1_honest = col0_honest.clone();
            let trace = Trace::new(vec![col0_honest.clone(), col1_honest.clone()]);
            assert_eq!(air.check(&trace), check_legacy(&air, &trace));
            assert!(air.check(&trace));

            // Tamper every single cell — flip bit, assert legacy and
            // fast-path agree (both should reject for any flip that
            // breaks bool-ness on col0 or XOR on col1).
            for col in 0..2 {
                for row in 0..n {
                    let mut c0 = col0_honest.clone();
                    let mut c1 = col1_honest.clone();
                    {
                        let cell = if col == 0 { &mut c0[row] } else { &mut c1[row] };
                        *cell = *cell + Block128::ONE;
                    }
                    let tampered = Trace::new(vec![c0, c1]);
                    assert_eq!(
                        air.check(&tampered),
                        check_legacy(&air, &tampered),
                        "divergence at log_rows={log_rows} col={col} row={row}"
                    );
                }
            }

            // Additional tamper: replace a cell with a non-bit element
            // on col0 (breaks BoolGate but not XOR if col1 mirrors it).
            for row in 0..n {
                let mut c0 = col0_honest.clone();
                let mut c1 = col1_honest.clone();
                let garbage = Block128::from(0x1234_5678_9abc_def0_u128);
                c0[row] = garbage;
                c1[row] = garbage;
                let tampered = Trace::new(vec![c0, c1]);
                assert_eq!(
                    air.check(&tampered),
                    check_legacy(&air, &tampered),
                    "divergence on garbage tamper log_rows={log_rows} row={row}"
                );
            }
        }
    }

    /// [2.C.1] The default `evaluate_flat` must, by construction,
    /// agree with `evaluate` after basis conversion. Guard against
    /// accidental override drift by exercising every concrete gate we
    /// hit in the bool-XOR composite.
    #[test]
    fn default_evaluate_flat_matches_tower() {
        let air = build_bool_xor_air(2);
        // Seed a mixed frame: non-bit values, non-zero XOR pattern.
        let local_tower = [
            Block128::from(0xdeadbeefcafef00d_u128),
            Block128::from(0x1234567890abcdef_u128),
        ];
        let next_tower = [Block128::ZERO, Block128::ONE];
        let local_flat: Vec<u128> = local_tower
            .iter()
            .map(|v| tower_to_flat_u128(v.0))
            .collect();
        let next_flat: Vec<u128> = next_tower.iter().map(|v| tower_to_flat_u128(v.0)).collect();
        for c in air.constraints() {
            // Slice to this constraint's arity — BoolGate reads 1 col,
            // WeightedLinearGate XOR reads 2 cols; local_tower has ≥2.
            let local_arity = c.columns().len();
            let next_arity = c.shifted_columns().len();
            let tf = EvalFrame {
                local: &local_tower[..local_arity],
                next: &next_tower[..next_arity],
            };
            let ff = FlatEvalFrame {
                local: &local_flat[..local_arity],
                next: &next_flat[..next_arity],
            };
            let tower_out = c.evaluate(tf);
            let flat_out = c.evaluate_flat(ff);
            assert_eq!(
                flat_out,
                tower_to_flat_u128(tower_out.0),
                "default evaluate_flat disagreed with tower path on {:?}",
                c.columns()
            );
        }
    }

    #[test]
    fn check_matches_legacy_on_shape_mismatch() {
        let air = build_bool_xor_air(3);
        let n = 1 << 3;
        let zeros: Vec<Block128> = vec![Block128::ZERO; n];

        // Wrong column count.
        let wrong_cols = Trace::new(vec![zeros.clone()]);
        assert_eq!(air.check(&wrong_cols), check_legacy(&air, &wrong_cols));
        assert!(!air.check(&wrong_cols));

        // Wrong log_rows (4 instead of 3).
        let wrong_rows0: Vec<Block128> = vec![Block128::ZERO; 1 << 4];
        let wrong_rows1 = wrong_rows0.clone();
        let wrong_rows = Trace::new(vec![wrong_rows0, wrong_rows1]);
        assert_eq!(air.check(&wrong_rows), check_legacy(&air, &wrong_rows));
        assert!(!air.check(&wrong_rows));
    }
}
