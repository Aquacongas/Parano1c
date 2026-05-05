// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! `BoolGate`: `v · (v + 1) == 0` in char-2, forcing `v ∈ {0, 1}`.

use crate::{Constraint, EvalFrame, FlatEvalFrame};
use noid_core::hardware::square_flat_u128;
use noid_core::Block128;

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
    fn evaluate(&self, frame: EvalFrame) -> Block128 {
        let v = frame.local[0];
        v * v + v
    }
    /// [2.C.3] Native flat-basis evaluator. `v · v` over GF(2^128) is
    /// the Frobenius squaring; flat basis has a dedicated
    /// `square_flat_u128` kernel that skips the full multiply. XOR
    /// is basis-agnostic. Equivalence with the tower-basis
    /// `evaluate`: `F(v*v + v) = F(v*v) + F(v) = square_flat(F(v)) ^
    /// F(v)` since `F(a+b) = F(a) + F(b)` (linear) and `F(a*a) =
    /// square_flat(F(a))` by construction of the flat square kernel.
    fn evaluate_flat(&self, frame: FlatEvalFrame) -> u128 {
        let v = frame.local[0];
        square_flat_u128(v) ^ v
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Air, CompositeAir, Trace};
    use noid_core::TowerField;

    /// [2.C.3] Native `evaluate_flat` must equal
    /// `tower_to_flat_u128(evaluate(...))` on every honest input.
    /// This is the only property that lets the STARK zero-check swap
    /// between tower and flat without changing transcript bytes.
    #[test]
    fn bool_flat_matches_tower() {
        use noid_core::hardware::tower_to_flat_u128;
        let gate = BoolGate::new(0);
        for v_raw in [
            0u128,
            1,
            2,
            0xdeadbeef,
            0xffff_ffff_ffff_ffff_u128,
            0xdead_beef_cafe_f00d_1234_5678_90ab_cdef_u128,
        ] {
            let v = Block128::from(v_raw);
            let tower_out = gate.evaluate(EvalFrame {
                local: &[v],
                next: &[],
            });
            let v_flat = tower_to_flat_u128(v.0);
            let flat_out = gate.evaluate_flat(FlatEvalFrame {
                local: &[v_flat],
                next: &[],
            });
            assert_eq!(
                flat_out,
                tower_to_flat_u128(tower_out.0),
                "BoolGate flat disagrees on v={v_raw:#x}"
            );
        }
    }

    #[test]
    fn bool_gate_rejects_non_bit() {
        let air = CompositeAir::from_parts(2, 1, vec![Box::new(BoolGate::new(0))]);
        let mut col = vec![Block128::ZERO; 4];
        col[2] = Block128::from(5u128);
        let trace = Trace::new(vec![col]);
        assert!(!air.check(&trace));
    }
}
