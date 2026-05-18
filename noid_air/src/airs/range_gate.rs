// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! `RangeGateAir` — Stage 3b-2 u64 range check via bit-decomposition.
//!
//! One range-check instance occupies `WORD_BITS = 64` consecutive rows;
//! `2^(log_rows - LOG_WORD_BITS)` instances are stacked per trace. Each
//! instance proves `x ∈ [0, 2^64)` by exhibiting the bit decomposition
//! of `x` in the `bit` column and reconstructing `x` in the `acc` column
//! via the recurrence
//!
//! ```text
//! acc[0]   = bit[0] · weight[0]            (with weight[0] = 1)
//! acc[i+1] = acc[i] + bit[i+1] · weight[i+1]   for i = 0..w-2
//! weight[i+1] = weight[i] · 2              (GF(2^128) multiplication)
//! ```
//!
//! The `(1 + is_reset_next)` selector zeros the recurrence at the row
//! preceding an instance reset so the accumulator does not have to
//! chain between instances.
//!
//! TOWER-BASIS NOTE. `Block128` is GF(2^128) in tower basis, so the
//! `weight_{i+1} = weight_i · 2` ladder produces tower-field powers of
//! two, NOT integer `1 << i`. Consequently `acc` at the last row of an
//! instance equals `Σ bit_i · tower_pow(2, i)` — a faithful linear
//! encoding of the bit vector, but NOT the integer embedding of `x`.
//! For range-checking alone this is sufficient (the bool constraints
//! pin every `bit_i ∈ {0, 1}` and the recurrence is injective). For
//! §3b-3 BalanceGate the integer-sum relation is built directly on the
//! bit columns without relying on `acc`, and integer-embedding of `acc`
//! is deferred to §3b-4 where a `ConstColumnGate` can pin `weight[i] =
//! Block128::from(1u128 << i)` explicitly.

use crate::gates::BoolGate;
use crate::{Air, ColumnDomain, Constraint, EvalFrame, FlatEvalFrame, Trace};
use noid_core::hardware::{clmul_gcm, tower_to_flat_u128};
use noid_core::{Block128, TowerField};

fn two_flat() -> u128 {
    use std::sync::OnceLock;
    static VAL: OnceLock<u128> = OnceLock::new();
    *VAL.get_or_init(|| tower_to_flat_u128(Block128::from(2u128).0))
}

/// Bit-width of one range-check instance (u64).
pub const RANGE_GATE_WORD_BITS: usize = 64;
pub const RANGE_GATE_LOG_WORD_BITS: usize = 6;

pub const RANGE_GATE_N_COLS: usize = 4;
pub const RANGE_GATE_COL_BIT: usize = 0;
pub const RANGE_GATE_COL_ACC: usize = 1;
pub const RANGE_GATE_COL_IS_RESET: usize = 2;
pub const RANGE_GATE_COL_WEIGHT: usize = 3;

/// `is_reset · (acc + bit · weight) == 0` — at each reset row (bit 0 of
/// an instance) the accumulator must equal `bit · weight` = `bit · 1` =
/// `bit`. Degree 3.
pub struct AccInitGate {
    cols: [usize; 4],
}

impl Default for AccInitGate {
    fn default() -> Self {
        Self::new()
    }
}

impl AccInitGate {
    pub fn new() -> Self {
        Self {
            cols: [
                RANGE_GATE_COL_IS_RESET,
                RANGE_GATE_COL_ACC,
                RANGE_GATE_COL_BIT,
                RANGE_GATE_COL_WEIGHT,
            ],
        }
    }
}

impl Constraint for AccInitGate {
    fn degree(&self) -> usize {
        3
    }
    fn columns(&self) -> &[usize] {
        &self.cols
    }
    fn evaluate(&self, frame: EvalFrame) -> Block128 {
        let is_reset = frame.local[0];
        let acc = frame.local[1];
        let bit = frame.local[2];
        let weight = frame.local[3];
        is_reset * (acc + bit * weight)
    }
    fn evaluate_flat(&self, frame: FlatEvalFrame) -> u128 {
        let is_reset = frame.local[0];
        let acc = frame.local[1];
        let bit = frame.local[2];
        let weight = frame.local[3];
        clmul_gcm(is_reset, acc ^ clmul_gcm(bit, weight))
    }
}

/// `(1 + is_reset_next) · (next(acc) + acc + next(bit) · next(weight)) == 0`.
///
/// Enforces the accumulator recurrence on every non-reset transition.
/// The `(1 + is_reset_next)` factor zeros the constraint when the next
/// row is a reset (including the cyclic wrap from the last row back to
/// row 0), so accumulators do not have to chain across instances. Degree 3.
pub struct AccNextGate {
    local: [usize; 1],
    shifted: [usize; 4],
}

impl Default for AccNextGate {
    fn default() -> Self {
        Self::new()
    }
}

impl AccNextGate {
    pub fn new() -> Self {
        Self {
            local: [RANGE_GATE_COL_ACC],
            shifted: [
                RANGE_GATE_COL_IS_RESET,
                RANGE_GATE_COL_ACC,
                RANGE_GATE_COL_BIT,
                RANGE_GATE_COL_WEIGHT,
            ],
        }
    }
}

impl Constraint for AccNextGate {
    fn degree(&self) -> usize {
        3
    }
    fn columns(&self) -> &[usize] {
        &self.local
    }
    fn shifted_columns(&self) -> &[usize] {
        &self.shifted
    }
    fn evaluate(&self, frame: EvalFrame) -> Block128 {
        let acc = frame.local[0];
        let is_reset_next = frame.next[0];
        let acc_next = frame.next[1];
        let bit_next = frame.next[2];
        let weight_next = frame.next[3];
        (Block128::ONE + is_reset_next) * (acc_next + acc + bit_next * weight_next)
    }
    fn evaluate_flat(&self, frame: FlatEvalFrame) -> u128 {
        let acc = frame.local[0];
        let is_reset_next = frame.next[0];
        let acc_next = frame.next[1];
        let bit_next = frame.next[2];
        let weight_next = frame.next[3];
        let inner = acc_next ^ acc ^ clmul_gcm(bit_next, weight_next);
        clmul_gcm(1 ^ is_reset_next, inner)
    }
}

/// `is_reset · (weight + 1) == 0` — at every reset row, `weight == 1`.
/// Degree 2.
pub struct WeightInitGate {
    cols: [usize; 2],
}

impl Default for WeightInitGate {
    fn default() -> Self {
        Self::new()
    }
}

impl WeightInitGate {
    pub fn new() -> Self {
        Self {
            cols: [RANGE_GATE_COL_IS_RESET, RANGE_GATE_COL_WEIGHT],
        }
    }
}

impl Constraint for WeightInitGate {
    fn degree(&self) -> usize {
        2
    }
    fn columns(&self) -> &[usize] {
        &self.cols
    }
    fn evaluate(&self, frame: EvalFrame) -> Block128 {
        let is_reset = frame.local[0];
        let weight = frame.local[1];
        is_reset * (weight + Block128::ONE)
    }
    fn evaluate_flat(&self, frame: FlatEvalFrame) -> u128 {
        let is_reset = frame.local[0];
        let weight = frame.local[1];
        clmul_gcm(is_reset, weight ^ 1)
    }
}

/// `(1 + is_reset_next) · (next(weight) + weight · TWO) == 0`.
///
/// Doubles `weight` on every non-reset transition; in GF(2^128) this
/// is multiplication by the element `Block128::from(2) = x`, i.e.
/// monomial shift. Degree 2.
pub struct WeightNextGate {
    local: [usize; 1],
    shifted: [usize; 2],
}

impl Default for WeightNextGate {
    fn default() -> Self {
        Self::new()
    }
}

impl WeightNextGate {
    pub fn new() -> Self {
        Self {
            local: [RANGE_GATE_COL_WEIGHT],
            shifted: [RANGE_GATE_COL_IS_RESET, RANGE_GATE_COL_WEIGHT],
        }
    }
}

impl Constraint for WeightNextGate {
    fn degree(&self) -> usize {
        2
    }
    fn columns(&self) -> &[usize] {
        &self.local
    }
    fn shifted_columns(&self) -> &[usize] {
        &self.shifted
    }
    fn evaluate(&self, frame: EvalFrame) -> Block128 {
        let weight = frame.local[0];
        let is_reset_next = frame.next[0];
        let weight_next = frame.next[1];
        let two = Block128::from(2u128);
        (Block128::ONE + is_reset_next) * (weight_next + weight * two)
    }
    fn evaluate_flat(&self, frame: FlatEvalFrame) -> u128 {
        let weight = frame.local[0];
        let is_reset_next = frame.next[0];
        let weight_next = frame.next[1];
        clmul_gcm(
            1 ^ is_reset_next,
            weight_next ^ clmul_gcm(weight, two_flat()),
        )
    }
}

/// u64 range-check AIR. `2^(log_rows - LOG_WORD_BITS)` independent
/// instances laid out along the hypercube, one per 64 rows.
pub struct RangeGateAir {
    log_rows: usize,
    constraints: Vec<Box<dyn Constraint>>,
}

impl RangeGateAir {
    pub fn new(log_rows: usize) -> Self {
        assert!(
            log_rows >= RANGE_GATE_LOG_WORD_BITS,
            "RangeGateAir needs at least one 64-bit instance (log_rows >= {})",
            RANGE_GATE_LOG_WORD_BITS
        );
        let constraints: Vec<Box<dyn Constraint>> = vec![
            Box::new(BoolGate::new(RANGE_GATE_COL_BIT)),
            Box::new(BoolGate::new(RANGE_GATE_COL_IS_RESET)),
            Box::new(AccInitGate::new()),
            Box::new(AccNextGate::new()),
            Box::new(WeightInitGate::new()),
            Box::new(WeightNextGate::new()),
        ];
        Self {
            log_rows,
            constraints,
        }
    }

    pub fn n_instances(&self) -> usize {
        1usize << (self.log_rows - RANGE_GATE_LOG_WORD_BITS)
    }

    /// Build a parallel trace from `n_instances` u64 values. Each value
    /// is decomposed into `WORD_BITS` bits laid out LSB-first in
    /// consecutive rows.
    pub fn build_trace(&self, values: &[u64]) -> Trace {
        let n = self.n_instances();
        assert_eq!(
            values.len(),
            n,
            "expected {} values, got {}",
            n,
            values.len()
        );
        let n_rows = 1usize << self.log_rows;
        let w = RANGE_GATE_WORD_BITS;

        let mut bit_col = vec![Block128::ZERO; n_rows];
        let mut acc_col = vec![Block128::ZERO; n_rows];
        let mut is_reset_col = vec![Block128::ZERO; n_rows];
        let mut weight_col = vec![Block128::ZERO; n_rows];

        let two = Block128::from(2u128);

        for (inst, &x) in values.iter().enumerate() {
            let base = inst * w;
            let mut weight = Block128::ONE;
            let mut acc = Block128::ZERO;
            for bit_pos in 0..w {
                let row = base + bit_pos;
                let b = ((x >> bit_pos) & 1) as u128;
                let b_block = Block128::from(b);
                bit_col[row] = b_block;
                weight_col[row] = weight;
                if bit_pos == 0 {
                    is_reset_col[row] = Block128::ONE;
                    acc = b_block * weight;
                } else {
                    acc = acc + b_block * weight;
                }
                acc_col[row] = acc;
                weight = weight * two;
            }
        }

        let cols = vec![bit_col, acc_col, is_reset_col, weight_col];
        let domains = vec![
            ColumnDomain::Bit,
            ColumnDomain::Block128,
            ColumnDomain::Bit,
            ColumnDomain::Block128,
        ];
        Trace::new_with_domains(cols, domains)
    }
}

impl Air for RangeGateAir {
    fn n_columns(&self) -> usize {
        RANGE_GATE_N_COLS
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

    const TEST_LOG_ROWS: usize = 8; // 4 instances of 64 bits

    fn mk_air() -> RangeGateAir {
        RangeGateAir::new(TEST_LOG_ROWS)
    }

    fn mk_values() -> Vec<u64> {
        vec![0u64, 1u64, 0xdead_beef_cafe_babeu64, u64::MAX]
    }

    #[test]
    fn range_gate_native_check_accepts_valid() {
        let air = mk_air();
        let trace = air.build_trace(&mk_values());
        assert!(air.check(&trace));
    }

    #[test]
    fn range_gate_rejects_non_bool_bit() {
        let air = mk_air();
        let mut trace = air.build_trace(&mk_values());
        // Write a non-bit field element into a `bit` cell.
        trace.columns[RANGE_GATE_COL_BIT][3] = Block128::from(5u128);
        assert!(!air.check(&trace));
    }

    #[test]
    fn range_gate_rejects_tampered_acc() {
        let air = mk_air();
        let mut trace = air.build_trace(&mk_values());
        // Mutate one accumulator cell mid-instance — acc_recurrence must
        // catch it on the previous-row transition into this cell.
        let original = trace.columns[RANGE_GATE_COL_ACC][5];
        trace.columns[RANGE_GATE_COL_ACC][5] = original + Block128::from(0xA5A5u128);
        assert!(!air.check(&trace));
    }

    #[test]
    fn range_gate_rejects_tampered_weight() {
        let air = mk_air();
        let mut trace = air.build_trace(&mk_values());
        let original = trace.columns[RANGE_GATE_COL_WEIGHT][7];
        trace.columns[RANGE_GATE_COL_WEIGHT][7] = original + Block128::ONE;
        assert!(!air.check(&trace));
    }

    #[test]
    fn range_gate_rejects_missing_reset_marker() {
        let air = mk_air();
        let mut trace = air.build_trace(&mk_values());
        // Clear the reset bit at the start of instance 1; weight-init
        // would no longer be enforced there and weight_recurrence would
        // fire on the transition into row 64.
        trace.columns[RANGE_GATE_COL_IS_RESET][RANGE_GATE_WORD_BITS] = Block128::ZERO;
        assert!(!air.check(&trace));
    }

    #[test]
    fn range_gate_rejects_spurious_reset_marker() {
        let air = mk_air();
        let mut trace = air.build_trace(&mk_values());
        // Plant a fake reset marker mid-instance 2 (value 0xdead…bebe);
        // acc at that row is non-zero, so `acc_init` (`is_reset · (acc +
        // bit·weight) == 0`) no longer holds. `weight_init` on the same
        // row also breaks because weight at row 2*64+10 is no longer 1.
        let spurious_row = 2 * RANGE_GATE_WORD_BITS + 10;
        trace.columns[RANGE_GATE_COL_IS_RESET][spurious_row] = Block128::ONE;
        assert!(!air.check(&trace));
    }

    #[test]
    fn range_gate_accumulator_matches_referential_recurrence() {
        // Sanity check on the trace construction, not the constraint
        // system. NOTE: `Block128` is GF(2^128) in *tower basis*, so
        // `Block128::from(2)^i != Block128::from(1u128 << i)`; `acc` is
        // therefore NOT the integer embedding of the decoded value — it
        // is `Σ bit_i · tower_pow(2, i)`. Making `acc` an honest
        // integer-embedding requires a fixed weight column driven by a
        // `ConstColumnGate` and is deferred to §3b-4 composition (see
        // ROADMAP). Here we just replay the field recurrence and confirm
        // the builder agrees with itself.
        let air = mk_air();
        let values = mk_values();
        let trace = air.build_trace(&values);
        let two = Block128::from(2u128);
        for (inst, &x) in values.iter().enumerate() {
            let mut expected = Block128::ZERO;
            let mut weight = Block128::ONE;
            for i in 0..RANGE_GATE_WORD_BITS {
                if (x >> i) & 1 == 1 {
                    expected = expected + weight;
                }
                weight = weight * two;
            }
            let last = inst * RANGE_GATE_WORD_BITS + RANGE_GATE_WORD_BITS - 1;
            assert_eq!(trace.columns[RANGE_GATE_COL_ACC][last], expected);
        }
    }
}
