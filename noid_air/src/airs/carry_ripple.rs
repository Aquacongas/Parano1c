// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! `CarryRippleAir` — 64-bit
//! ripple-carry adder laid out along the hypercube, one instance per
//! `WORD_BITS` rows.

use crate::gates::{BoolGate, WeightedLinearGate};
use crate::{Air, ColumnDomain, Constraint, EvalFrame, FlatEvalFrame, Trace};
use noid_core::hardware::clmul_gcm;
use noid_core::{Block128, TowerField};

/// Word width of one 64-bit ripple-carry adder instance laid out along
/// the hypercube. Each adder instance occupies `WORD_BITS` consecutive
/// rows; `2^(log_rows - LOG_WORD_BITS)` instances are stacked per trace.
pub const CARRY_RIPPLE_WORD_BITS: usize = 64;
pub const CARRY_RIPPLE_LOG_WORD_BITS: usize = 6;
pub const CARRY_RIPPLE_N_COLS: usize = 5;
pub const CARRY_RIPPLE_COL_A: usize = 0;
pub const CARRY_RIPPLE_COL_B: usize = 1;
pub const CARRY_RIPPLE_COL_SUM: usize = 2;
pub const CARRY_RIPPLE_COL_CARRY: usize = 3;
pub const CARRY_RIPPLE_COL_IS_RESET: usize = 4;

/// `(1 + is_reset_next) · (next(carry) + a·b + a·carry + b·carry) == 0`.
///
/// The `(1 + is_reset_next)` factor zeros the constraint at the row
/// preceding an instance reset (in particular at the cyclic wrap-around
/// from the last bit of the last instance to row 0) so that the
/// carry-out of one adder does not have to match the carry-in of the
/// next. Degree 3 in the column variables.
pub struct CarryNextGate {
    local: [usize; 3],
    shifted: [usize; 2],
}

impl Default for CarryNextGate {
    fn default() -> Self {
        Self::new()
    }
}

impl CarryNextGate {
    pub fn new() -> Self {
        Self {
            local: [
                CARRY_RIPPLE_COL_A,
                CARRY_RIPPLE_COL_B,
                CARRY_RIPPLE_COL_CARRY,
            ],
            shifted: [CARRY_RIPPLE_COL_CARRY, CARRY_RIPPLE_COL_IS_RESET],
        }
    }
}

impl Constraint for CarryNextGate {
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
        let a = frame.local[0];
        let b = frame.local[1];
        let carry = frame.local[2];
        let next_carry = frame.next[0];
        let is_reset_next = frame.next[1];
        (Block128::ONE + is_reset_next) * (next_carry + a * b + a * carry + b * carry)
    }
    fn evaluate_flat(&self, frame: FlatEvalFrame) -> u128 {
        let a = frame.local[0];
        let b = frame.local[1];
        let carry = frame.local[2];
        let next_carry = frame.next[0];
        let is_reset_next = frame.next[1];
        let inner = next_carry ^ clmul_gcm(a, b) ^ clmul_gcm(a, carry) ^ clmul_gcm(b, carry);
        clmul_gcm(1 ^ is_reset_next, inner)
    }
}

/// `is_reset · carry == 0` — at every reset row the carry-in must be zero.
pub struct CarryInitGate {
    cols: [usize; 2],
}

impl Default for CarryInitGate {
    fn default() -> Self {
        Self::new()
    }
}

impl CarryInitGate {
    pub fn new() -> Self {
        Self {
            cols: [CARRY_RIPPLE_COL_IS_RESET, CARRY_RIPPLE_COL_CARRY],
        }
    }
}

impl Constraint for CarryInitGate {
    fn degree(&self) -> usize {
        2
    }
    fn columns(&self) -> &[usize] {
        &self.cols
    }
    fn evaluate(&self, frame: EvalFrame) -> Block128 {
        frame.local[0] * frame.local[1]
    }
    fn evaluate_flat(&self, frame: FlatEvalFrame) -> u128 {
        clmul_gcm(frame.local[0], frame.local[1])
    }
}

/// 64-bit ripple-carry adder AIR. One or more adder instances are laid
/// out consecutively along the hypercube, each occupying `WORD_BITS`
/// rows. `log_rows` must satisfy `log_rows >= LOG_WORD_BITS` (at least
/// one instance); the VSHIFT invariant `log_rows >=
/// TAU + 1 = 8` is enforced by the STARK layer.
pub struct CarryRippleAir {
    log_rows: usize,
    constraints: Vec<Box<dyn Constraint>>,
}

impl CarryRippleAir {
    pub fn new(log_rows: usize) -> Self {
        assert!(
            log_rows >= CARRY_RIPPLE_LOG_WORD_BITS,
            "CarryRippleAir needs at least one 64-bit instance (log_rows >= {})",
            CARRY_RIPPLE_LOG_WORD_BITS
        );
        let constraints: Vec<Box<dyn Constraint>> = vec![
            Box::new(BoolGate::new(CARRY_RIPPLE_COL_A)),
            Box::new(BoolGate::new(CARRY_RIPPLE_COL_B)),
            Box::new(BoolGate::new(CARRY_RIPPLE_COL_CARRY)),
            Box::new(WeightedLinearGate::new_xor(vec![
                CARRY_RIPPLE_COL_SUM,
                CARRY_RIPPLE_COL_A,
                CARRY_RIPPLE_COL_B,
                CARRY_RIPPLE_COL_CARRY,
            ])),
            Box::new(CarryNextGate::new()),
            Box::new(CarryInitGate::new()),
        ];
        Self {
            log_rows,
            constraints,
        }
    }

    pub fn n_instances(&self) -> usize {
        1usize << (self.log_rows - CARRY_RIPPLE_LOG_WORD_BITS)
    }

    /// Build a parallel trace from `n_instances` `(a, b)` operand pairs.
    /// Expects `adders.len() == 2^(log_rows - 6)`.
    pub fn build_trace(&self, adders: &[(u64, u64)]) -> Trace {
        let n = self.n_instances();
        assert_eq!(
            adders.len(),
            n,
            "expected {} adders, got {}",
            n,
            adders.len()
        );
        let n_rows = 1usize << self.log_rows;
        let w = CARRY_RIPPLE_WORD_BITS;
        let mut a_col = vec![Block128::ZERO; n_rows];
        let mut b_col = vec![Block128::ZERO; n_rows];
        let mut sum_col = vec![Block128::ZERO; n_rows];
        let mut carry_col = vec![Block128::ZERO; n_rows];
        let mut is_reset_col = vec![Block128::ZERO; n_rows];

        for (inst, &(a_word, b_word)) in adders.iter().enumerate() {
            let base = inst * w;
            let mut c: u64 = 0;
            for bit in 0..w {
                let row = base + bit;
                let a_bit = (a_word >> bit) & 1;
                let b_bit = (b_word >> bit) & 1;
                let s_bit = a_bit ^ b_bit ^ c;
                let next_c = (a_bit & b_bit) ^ (a_bit & c) ^ (b_bit & c);
                a_col[row] = Block128::from(a_bit as u128);
                b_col[row] = Block128::from(b_bit as u128);
                sum_col[row] = Block128::from(s_bit as u128);
                carry_col[row] = Block128::from(c as u128);
                if bit == 0 {
                    is_reset_col[row] = Block128::ONE;
                }
                c = next_c;
            }
        }

        let cols = vec![a_col, b_col, sum_col, carry_col, is_reset_col];
        let domains = vec![ColumnDomain::Bit; CARRY_RIPPLE_N_COLS];
        Trace::new_with_domains(cols, domains)
    }
}

impl Air for CarryRippleAir {
    fn n_columns(&self) -> usize {
        CARRY_RIPPLE_N_COLS
    }
    fn log_rows(&self) -> usize {
        self.log_rows
    }
    fn constraints(&self) -> &[Box<dyn Constraint>] {
        &self.constraints
    }
    fn column_domains(&self) -> Vec<ColumnDomain> {
        vec![ColumnDomain::Bit; CARRY_RIPPLE_N_COLS]
    }
}
