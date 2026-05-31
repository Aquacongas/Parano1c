// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

#![allow(clippy::needless_range_loop, clippy::doc_lazy_continuation)]

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
pub mod composition;
pub mod gates;

pub use airs::{
    apply_mds_row, bit_adder_is_input_programme, bit_adder_is_reset_programme,
    bit_adder_operand_programme, build_balance_columns, build_instance_layout, build_perm_trace,
    build_sbox_x7_columns, build_tx_body_merkle_trace,
    build_tx_body_merkle_trace_with_boundary_pins, build_tx_body_merkle_typed_trace,
    emit_balance_constraints, emit_balance_selector_public_columns,
    emit_balance_value_public_columns, emit_block_constraints, emit_mds_row_constraints,
    emit_perm_all, emit_perm_all_at, emit_perm_mds_blend, emit_perm_mds_blend_at,
    emit_perm_partial_sbox_kill, emit_perm_partial_sbox_kill_at, emit_perm_public_columns,
    emit_perm_public_columns_at, emit_perm_public_columns_row_major_at, emit_perm_rc_binding,
    emit_perm_rc_binding_at, emit_perm_sbox_chain, emit_perm_sbox_chain_at,
    emit_sbox_x7_constraints, emit_tx_body_merkle_constraints,
    emit_tx_body_merkle_constraints_with_boundary_pins, emit_tx_body_merkle_public_columns,
    emit_tx_body_merkle_public_columns_with_boundary_pins, extract_instance_output,
    extract_perm_output, instance_row_offset, is_full_round, leaf_rate_absorb_instance_ids,
    leaf_rate_payload_col, perm_is_full_values, perm_is_full_values_row_major,
    perm_is_round_values, perm_is_round_values_row_major, perm_rc_values, perm_rc_values_row_major,
    tx_body_merkle_column_domains, write_perm_trace_at, write_perm_trace_at_offset, AccInitGate,
    AccNextGate, BalanceBridgeBitsGate, BalanceBridgeCarryGate, BalanceFinalCarryGate,
    BalanceFinalSumGate, BalanceGateAir, BalanceZeroAtTransitionGate, BitAdderAir,
    BitAdderCarryInitGate, BitAdderCarryNextGate, BitAdderLayout, CarryInitGate, CarryNextGate,
    CarryRippleAir, FaSumGate, LinearCombinationAir, MdsKind, MdsLayout, MdsRowGate, PadZeroGate,
    PartialSboxKillGate, PermLayout, PermMdsBlendGate, PoseidonPermColumns, RangeGateAir,
    SboxX7Layout, TxBodyMerkleAir, TxBodyMerkleBoundaryPins, TxBodySpineComposite, WeightInitGate,
    WeightNextGate, BALANCE_MIN_LOG_ROWS, BALANCE_N_BLOCKS, BALANCE_N_COLS, BIT_ADDER_COL_A,
    BIT_ADDER_COL_B, BIT_ADDER_COL_CARRY, BIT_ADDER_COL_IS_INPUT, BIT_ADDER_COL_IS_RESET,
    BIT_ADDER_COL_SUM, BIT_ADDER_LOG_WORD_BITS, BIT_ADDER_MAX_WIDTH, BIT_ADDER_N_COLS,
    BIT_ADDER_WORD_BITS, CARRY_RIPPLE_COL_A, CARRY_RIPPLE_COL_B, CARRY_RIPPLE_COL_CARRY,
    CARRY_RIPPLE_COL_IS_RESET, CARRY_RIPPLE_COL_SUM, CARRY_RIPPLE_LOG_WORD_BITS,
    CARRY_RIPPLE_N_COLS, CARRY_RIPPLE_WORD_BITS, DEFAULT_PERM_LAYOUT, N_LEAF_RATE_PAYLOAD_COLS,
    POSEIDON_COL_IS_FULL, POSEIDON_COL_IS_ROUND, POSEIDON_COL_RC, POSEIDON_COL_S, POSEIDON_COL_SIN,
    POSEIDON_COL_SOUT, POSEIDON_COL_X2, POSEIDON_COL_X3, POSEIDON_COL_X4, POSEIDON_N_ACTIVE_ROWS,
    POSEIDON_PERM_LOG_ROWS, POSEIDON_PERM_N_COLS, POSEIDON_PERM_N_ROWS, RANGE_GATE_COL_ACC,
    RANGE_GATE_COL_BIT, RANGE_GATE_COL_IS_RESET, RANGE_GATE_COL_WEIGHT, RANGE_GATE_LOG_WORD_BITS,
    RANGE_GATE_N_COLS, RANGE_GATE_WORD_BITS, SBOX_X7_N_COLS, SPINE_LOG_ROWS, TXBODY_MERKLE_LAYOUT,
    TXBODY_MERKLE_LOG_ROWS, TXBODY_MERKLE_N_COLS, TXBODY_MERKLE_N_COLS_WITH_BOUNDARY_PINS,
    TXBODY_MERKLE_N_PERMS, TXBODY_MERKLE_N_ROWS, TXBODY_MERKLE_PRE_S_BASE,
    TXBODY_MERKLE_SLOT_LOG_ROWS, TXBODY_MERKLE_SLOT_ROWS, TXV_COL_OFFSET, TXV_LIVE_ROWS,
    TX_BODY_MERKLE_COL_OFFSET,
};
pub use airs::{
    BlockStateBindingAir, BlockStateBindingClaim, BlockStateBindingLayout,
    BlockStateBindingWitness, BLOCK_STATE_BINDING_LOG_ROWS, BLOCK_STATE_BINDING_LOG_SLOTS,
    BLOCK_STATE_BINDING_MAX_SLOTS, BLOCK_STATE_BINDING_N_ROWS,
};
pub use gates::{
    emit_column_eq_at_next_row, emit_column_eq_at_row, emit_multi_row_selector, emit_public_cell,
    emit_row_selector, emit_rows_must_be_zero, multi_row_indicator_programme,
    row_indicator_programme, BoolGate, EqLadderStepGate, MulGate, PublicColumn, SelectorGate,
    SquareGate, WeightedLinearGate, WeightedLinearGateShifted,
};

use std::borrow::Cow;

// ---------------------------------------------------------------------------
// Column padding utilities
// ---------------------------------------------------------------------------

/// Pad a column to the target log length, returning a borrowed slice if
/// the column is already the correct size (zero-copy), or an owned vector
/// with zero-padding otherwise.
///
/// This is used to avoid unnecessary allocations when extracting fixed
/// columns that may already be at the target size.
pub fn pad_column_cow(column: &[Block128], target_log: usize) -> Cow<'_, [Block128]> {
    let target_len = 1 << target_log;
    if column.len() == target_len {
        Cow::Borrowed(column)
    } else {
        let mut padded = Vec::with_capacity(target_len);
        padded.extend_from_slice(column);
        padded.resize(target_len, Block128::ZERO);
        Cow::Owned(padded)
    }
}

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
// Fixed Columns (shared across transactions)
// ---------------------------------------------------------------------------

/// Fixed columns that are identical across all transactions in a block.
/// Built once per AIR and shared to eliminate per-tx duplication.
///
/// Stores columns in both tower basis (constraint evaluation) and flat
/// basis (zero-check hot path) to avoid repeated conversions.
///
/// Column lookups are O(1) via `col_pos`, a dense position map indexed
/// by the original column index. This replaces the former O(n_fixed)
/// linear scan in `tower_column` / `flat_column` / `is_fixed`.
#[derive(Clone)]
pub struct FixedColumns {
    /// Tower-basis columns, one per entry in `col_indices`, in the same order.
    pub tower: Vec<Vec<Block128>>,
    /// Flat-basis columns (tower_to_flat_u128 applied), same order.
    pub flat: Vec<Vec<u128>>,
    /// Original Trace column indices of the fixed columns.
    pub col_indices: Vec<usize>,
    /// Padded log length.
    pub log_len: usize,
    /// O(1) position map: `col_pos[original_col_idx]` = `Some(pos)` where
    /// `pos` is the index into `tower` / `flat`, or `None` for non-fixed columns.
    /// Length equals `air.n_columns()` at construction time.
    col_pos: Vec<Option<usize>>,
}

impl FixedColumns {
    /// Build `FixedColumns` from an AIR and its trace, padded to `target_log`.
    ///
    /// Fixed columns (identified by `air.fixed_columns()`) are padded,
    /// converted to flat basis, and stored with an O(1) position map.
    /// Padding and flat conversion run in parallel via rayon when there are
    /// multiple fixed columns.
    pub fn from_air<A: Air + ?Sized>(air: &A, trace: &Trace, target_log: usize) -> Self {
        use rayon::prelude::*;
        let indices = air.fixed_columns();
        let n_air_cols = air.n_columns();
        let target_len = 1usize << target_log;

        // Pad and convert in parallel — each fixed column is independent.
        let (tower, flat): (Vec<Vec<Block128>>, Vec<Vec<u128>>) = indices
            .par_iter()
            .map(|&idx| {
                let col = &trace.columns[idx];
                // Pad by extending (clone + resize); no intermediate Cow needed.
                let mut tower_col = col.clone();
                if tower_col.len() < target_len {
                    tower_col.resize(target_len, Block128::ZERO);
                }
                debug_assert_eq!(tower_col.len(), target_len);
                let flat_col: Vec<u128> = tower_col
                    .iter()
                    .map(|v| noid_core::hardware::tower_to_flat_u128(v.0))
                    .collect();
                (tower_col, flat_col)
            })
            .unzip();

        // Build O(1) dense position map.
        let mut col_pos = vec![None::<usize>; n_air_cols];
        for (pos, &idx) in indices.iter().enumerate() {
            if idx < n_air_cols {
                col_pos[idx] = Some(pos);
            }
        }

        Self {
            tower,
            flat,
            col_indices: indices,
            log_len: target_log,
            col_pos,
        }
    }

    /// Tower-basis column for original Trace index `idx`.  O(1).
    ///
    /// # Panics
    /// Panics if `idx` is not a fixed column (not in `air.fixed_columns()`).
    #[inline]
    pub fn tower_column(&self, idx: usize) -> &[Block128] {
        let pos = self.col_pos[idx].expect("idx must be a fixed column");
        &self.tower[pos]
    }

    /// Flat-basis column for original Trace index `idx`.  O(1).
    ///
    /// # Panics
    /// Panics if `idx` is not a fixed column.
    #[inline]
    pub fn flat_column(&self, idx: usize) -> &[u128] {
        let pos = self.col_pos[idx].expect("idx must be a fixed column");
        &self.flat[pos]
    }

    /// Returns `true` iff `idx` is a fixed column.  O(1).
    #[inline]
    pub fn is_fixed(&self, idx: usize) -> bool {
        idx < self.col_pos.len() && self.col_pos[idx].is_some()
    }

    /// Reconstruct a full ordered column reference slice from fixed and witness data.
    ///
    /// `n_cols_total` must equal `air.n_columns()`.  `witness` must contain
    /// exactly the non-fixed columns in ascending original column-index order
    /// (i.e., the result of filtering out fixed column indices from the trace).
    ///
    /// The returned `Vec` holds `n_cols_total` `&[Block128]` pointers — fixed
    /// columns point into `self.tower`, witness columns point into `witness`.
    /// No data is copied.
    pub fn build_full_col_refs<'a>(
        &'a self,
        n_cols_total: usize,
        witness: &'a [Vec<Block128>],
    ) -> Vec<&'a [Block128]> {
        let mut result = Vec::with_capacity(n_cols_total);
        let mut w_idx = 0usize;
        for col_idx in 0..n_cols_total {
            if self.is_fixed(col_idx) {
                result.push(self.tower_column(col_idx));
            } else {
                result.push(witness[w_idx].as_slice());
                w_idx += 1;
            }
        }
        result
    }
}

// ---------------------------------------------------------------------------
// Split Trace View (borrowed view for evaluators)
// ---------------------------------------------------------------------------

/// Borrowed view of a split trace for constraint evaluators.
///
/// Provides access to both fixed columns (shared via Arc) and witness
/// columns (per-tx, mutable) without ownership transfer.
#[derive(Clone, Copy)]
pub struct SplitTraceView<'a> {
    /// Fixed columns (shared across all txs)
    pub fixed: &'a FixedColumns,
    /// Witness columns (per-tx, tower basis)
    pub witness: &'a [Vec<Block128>],
    /// Witness columns (per-tx, flat basis, pre-converted)
    pub witness_flat: &'a [Vec<u128>],
    /// Log rows for this trace
    pub log_rows: usize,
}

impl<'a> SplitTraceView<'a> {
    /// Get tower-basis column by original Trace index.
    ///
    /// Returns fixed column if `idx` is fixed, otherwise returns witness column.
    /// Witness column index is computed by subtracting the number of fixed
    /// columns before `idx`.
    pub fn column(&self, idx: usize) -> &[Block128] {
        if self.fixed.is_fixed(idx) {
            self.fixed.tower_column(idx)
        } else {
            // Compute witness column index
            let witness_idx = self.witness_index(idx);
            &self.witness[witness_idx]
        }
    }

    /// Get flat-basis column by original Trace index.
    ///
    /// Returns fixed column if `idx` is fixed, otherwise returns witness column.
    pub fn column_flat(&self, idx: usize) -> &[u128] {
        if self.fixed.is_fixed(idx) {
            self.fixed.flat_column(idx)
        } else {
            let witness_idx = self.witness_index(idx);
            &self.witness_flat[witness_idx]
        }
    }

    /// Compute witness column index from original Trace index.
    ///
    /// Witness columns are numbered sequentially, skipping fixed columns.
    fn witness_index(&self, idx: usize) -> usize {
        // Count how many fixed columns come before idx
        let fixed_before = self.fixed.col_indices.iter().filter(|&&i| i < idx).count();
        idx - fixed_before
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
    /// Default-implementation uses **thread-local scratch buffers** to
    /// eliminate the two `Vec<Block128>` allocations that the naive
    /// version would do per call. The zero-check sumcheck invokes this
    /// for 158 constraints × 4096 positions × 39 rounds per tx —
    /// thread-local reuse cuts ~200 M allocations/tx to zero.
    /// Rayon workers execute constraint closures sequentially (one at a
    /// time per thread), so the RefCell borrow never conflicts.
    fn evaluate_flat(&self, frame: FlatEvalFrame) -> u128 {
        thread_local! {
            static LOCAL_TMP: std::cell::RefCell<Vec<Block128>> =
                std::cell::RefCell::new(Vec::new());
            static NEXT_TMP: std::cell::RefCell<Vec<Block128>> =
                std::cell::RefCell::new(Vec::new());
        }
        LOCAL_TMP.with(|local_ref| {
            NEXT_TMP.with(|next_ref| {
                let mut local_tmp = local_ref.borrow_mut();
                let mut next_tmp = next_ref.borrow_mut();
                local_tmp.clear();
                local_tmp.extend(
                    frame
                        .local
                        .iter()
                        .map(|&v| Block128::from(flat_to_tower_u128(v))),
                );
                next_tmp.clear();
                next_tmp.extend(
                    frame
                        .next
                        .iter()
                        .map(|&v| Block128::from(flat_to_tower_u128(v))),
                );
                let out = self.evaluate(EvalFrame {
                    local: &local_tmp,
                    next: &next_tmp,
                });
                tower_to_flat_u128(out.0)
            })
        })
    }
}

// ---------------------------------------------------------------------------
// Air trait
// ---------------------------------------------------------------------------

pub trait Air: Send + Sync {
    fn n_columns(&self) -> usize;
    fn log_rows(&self) -> usize;
    fn constraints(&self) -> &[Box<dyn Constraint>];

    /// Whether the AIR has a constraint whose cyclic `next(last_row) =
    /// first_row` wrap is load-bearing (a carry/accumulator chain that
    /// must close at row 0, not a dead padding row). Default `false`:
    /// every shipped AIR either uses no `shifted_columns` at all, or
    /// gates cross-instance wraps behind an `is_reset` selector. New
    /// AIRs whose last-row wrap is semantically required must override
    /// this to `true`. The Stage 5 `RowWindowWrapper` asserts policy
    /// compatibility against this flag: an AIR with
    /// `REQUIRES_TRUE_CYCLIC_WRAP = true` cannot be embedded under the
    /// default `MaskOff` policy and forces the caller to wire a
    /// `TerminatorPin` instead.
    fn requires_true_cyclic_wrap(&self) -> bool {
        false
    }

    /// Trace columns pinned to a publicly-known, verifier-side value
    /// sequence (Stage 3d-0.1). Default empty: AIRs without pinned
    /// columns keep legacy behaviour. Each declared column must be in
    /// `0..n_columns()` and carry `2^log_rows()` values; duplicates are
    /// rejected by `Air::check`. STARK-layer verification of public
    /// columns lands in Stage 3d-0.2.
    fn public_columns(&self) -> &[PublicColumn] {
        &[]
    }

    /// Domain of each trace column for the Tower Sumcheck optimisation.
    ///
    /// Returns `ColumnDomain::Block128` for all columns by default (conservative;
    /// no boolean fast-path). AIRs that have GF(2)-valued columns should override
    /// this to return `ColumnDomain::Bit` for those columns, enabling the
    /// Tower Sumcheck boolean fast-path which replaces `clmul_gcm` with a bitwise
    /// AND instruction for the partial-evaluation of boolean columns.
    ///
    /// The returned slice length MUST equal `n_columns()`. Implementations that
    /// override this method should assert this in their AIR constructor.
    fn column_domains(&self) -> Vec<ColumnDomain> {
        vec![ColumnDomain::Block128; self.n_columns()]
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

    /// Indices of columns that are fixed (identical across all valid traces
    /// for this AIR). Fixed columns are shared across all transactions via Arc
    /// to eliminate per-tx duplication. Default: empty (all columns are witness).
    /// Override per-AIR to identify selectors, masks, and other fixed structure.
    fn fixed_columns(&self) -> Vec<usize> {
        vec![]
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

    /// Consume the composite and return its `(log_rows, n_cols,
    /// constraints, public_columns)`. Used by Stage 5.7 PR B.3 to
    /// embed an already-built composite (e.g. `TxValidityCompositeLeaf`)
    /// inside a larger outer composite without re-instantiating the
    /// underlying sub-AIRs.
    pub fn into_parts(self) -> (usize, usize, Vec<Box<dyn Constraint>>, Vec<PublicColumn>) {
        (
            self.log_rows,
            self.n_cols,
            self.constraints,
            self.public_columns,
        )
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
                        *cell += Block128::ONE;
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
