// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! `MulGate` / `SquareGate`: degree-2 algebraic gates asserting
//! `out == a · b` (resp. `out == a · a`) over GF(2^128).
//!
//! Promoted from ad-hoc forms inside §3a/§3b AIRs to first-class gates
//! in preparation for §3c Poseidon arithmetization: every round of the
//! Poseidon2b permutation is a fixed chain of squarings and products
//! over `Block128`, so the S-box sub-circuit is expressed as repeated
//! applications of these two primitives.
//!
//! In char-2 the constraint `out + a·b == 0` is the same as
//! `out − a·b == 0`; we write the char-2 form because `+` and `−`
//! coincide on `Block128` and `Block128::ZERO` is additive identity.

use crate::{Constraint, EvalFrame};
use noid_core::Block128;

/// `out == a · b` (local-only, degree 2).
pub struct MulGate {
    cols: [usize; 3],
}

impl MulGate {
    /// New `MulGate` asserting `col[out] == col[a] · col[b]` on every row.
    pub fn new(out: usize, a: usize, b: usize) -> Self {
        assert!(out != a && out != b && a != b, "MulGate: columns must be distinct");
        Self { cols: [out, a, b] }
    }
}

impl Constraint for MulGate {
    fn degree(&self) -> usize {
        2
    }
    fn columns(&self) -> &[usize] {
        &self.cols
    }
    fn evaluate(&self, frame: EvalFrame) -> Block128 {
        let out = frame.local[0];
        let a = frame.local[1];
        let b = frame.local[2];
        out + a * b
    }
}

/// `out == a · a` (local-only, degree 2). Over GF(2^128) squaring is a
/// linear Frobenius map, but the constraint engine treats it as a
/// generic degree-2 identity; the linearity is exploited by the
/// backend's specialised squaring kernel, not by the AIR.
pub struct SquareGate {
    cols: [usize; 2],
}

impl SquareGate {
    pub fn new(out: usize, a: usize) -> Self {
        assert_ne!(out, a, "SquareGate: out and a must be distinct columns");
        Self { cols: [out, a] }
    }
}

impl Constraint for SquareGate {
    fn degree(&self) -> usize {
        2
    }
    fn columns(&self) -> &[usize] {
        &self.cols
    }
    fn evaluate(&self, frame: EvalFrame) -> Block128 {
        let out = frame.local[0];
        let a = frame.local[1];
        out + a * a
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Air, CompositeAir, Trace};
    use noid_core::TowerField;

    fn mk_cols(n_rows: usize, seed: u128) -> Vec<Block128> {
        (0..n_rows)
            .map(|i| Block128::from(seed.wrapping_mul(0x9E3779B97F4A7C15).wrapping_add(i as u128)))
            .collect()
    }

    #[test]
    fn mul_gate_accepts_correct_product() {
        let a = mk_cols(8, 0xABCD);
        let b = mk_cols(8, 0x1234);
        let out: Vec<Block128> = a.iter().zip(b.iter()).map(|(x, y)| *x * *y).collect();
        let air = CompositeAir::from_parts(3, 3, vec![Box::new(MulGate::new(0, 1, 2))]);
        let trace = Trace::new(vec![out, a, b]);
        assert!(air.check(&trace));
    }

    #[test]
    fn mul_gate_rejects_wrong_product() {
        let a = mk_cols(8, 0xABCD);
        let b = mk_cols(8, 0x1234);
        let mut out: Vec<Block128> = a.iter().zip(b.iter()).map(|(x, y)| *x * *y).collect();
        out[3] = out[3] + Block128::ONE;
        let air = CompositeAir::from_parts(3, 3, vec![Box::new(MulGate::new(0, 1, 2))]);
        let trace = Trace::new(vec![out, a, b]);
        assert!(!air.check(&trace));
    }

    #[test]
    #[should_panic(expected = "distinct")]
    fn mul_gate_rejects_duplicate_columns() {
        let _ = MulGate::new(0, 0, 1);
    }

    #[test]
    fn square_gate_accepts_correct_square() {
        let a = mk_cols(8, 0xBEEF);
        let out: Vec<Block128> = a.iter().map(|x| *x * *x).collect();
        let air = CompositeAir::from_parts(3, 2, vec![Box::new(SquareGate::new(0, 1))]);
        let trace = Trace::new(vec![out, a]);
        assert!(air.check(&trace));
    }

    #[test]
    fn square_gate_rejects_wrong_square() {
        let a = mk_cols(8, 0xBEEF);
        let mut out: Vec<Block128> = a.iter().map(|x| *x * *x).collect();
        out[1] = out[1] + Block128::ONE;
        let air = CompositeAir::from_parts(3, 2, vec![Box::new(SquareGate::new(0, 1))]);
        let trace = Trace::new(vec![out, a]);
        assert!(!air.check(&trace));
    }

    #[test]
    #[should_panic(expected = "distinct")]
    fn square_gate_rejects_duplicate_columns() {
        let _ = SquareGate::new(0, 0);
    }
}
