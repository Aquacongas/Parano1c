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

use crate::{Constraint, EvalFrame, FlatEvalFrame};
use noid_core::hardware::{clmul_gcm, square_flat_u128};
use noid_core::Block128;

/// `out == a · b` (local-only, degree 2).
pub struct MulGate {
    cols: [usize; 3],
}

impl MulGate {
    /// New `MulGate` asserting `col[out] == col[a] · col[b]` on every row.
    pub fn new(out: usize, a: usize, b: usize) -> Self {
        assert!(
            out != a && out != b && a != b,
            "MulGate: columns must be distinct"
        );
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
    /// [2.C.3] Flat-basis evaluator: XOR + single CLMUL. Equivalent
    /// to the tower path by isomorphism of the multiplicative group
    /// under `F = tower_to_flat_u128`:
    ///   `F(out + a*b) = F(out) ^ F(a)*F(b) = out_flat ^ clmul_gcm(a_flat, b_flat)`.
    fn evaluate_flat(&self, frame: FlatEvalFrame) -> u128 {
        let out = frame.local[0];
        let a = frame.local[1];
        let b = frame.local[2];
        out ^ clmul_gcm(a, b)
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
    /// [2.C.3] Flat-basis squaring via the dedicated
    /// `square_flat_u128` kernel (single Frobenius linear map, no
    /// CLMUL needed). Equivalent to tower path as for `BoolGate`.
    fn evaluate_flat(&self, frame: FlatEvalFrame) -> u128 {
        let out = frame.local[0];
        let a = frame.local[1];
        out ^ square_flat_u128(a)
    }
}

/// `out == a · b · c` (local-only, degree 3).
///
/// Motivation. Several AIR stages stack two `MulGate`s through an
/// intermediate committed column to express a triple product —
/// e.g. `FriStateOpenAir`'s β.2.a pipeline
///   `gp_lane = γ^i · (eq(r, slot_bits) · opened_pre_lane)`
/// which α + β.2.a split via a committed `col_mle_prod_*`
/// intermediate. Fusing to one degree-3 gate drops the intermediate
/// column (one fewer FRI commitment per lane) at the cost of one
/// more degree level, which the quotient machinery already
/// absorbs (e.g. MDS-blend constraints are degree-3).
pub struct TripleProductGate {
    cols: [usize; 4],
}

impl TripleProductGate {
    /// New `TripleProductGate` asserting `col[out] == col[a] · col[b]
    /// · col[c]` on every row. All four column indices must be
    /// pairwise distinct.
    pub fn new(out: usize, a: usize, b: usize, c: usize) -> Self {
        let all = [out, a, b, c];
        for i in 0..all.len() {
            for j in (i + 1)..all.len() {
                assert_ne!(
                    all[i], all[j],
                    "TripleProductGate: columns must be pairwise distinct"
                );
            }
        }
        Self { cols: all }
    }
}

impl Constraint for TripleProductGate {
    fn degree(&self) -> usize {
        3
    }
    fn columns(&self) -> &[usize] {
        &self.cols
    }
    fn evaluate(&self, frame: EvalFrame) -> Block128 {
        let out = frame.local[0];
        let a = frame.local[1];
        let b = frame.local[2];
        let c = frame.local[3];
        out + a * b * c
    }
    /// Flat-basis evaluator: two chained CLMULs + XOR. Equivalent
    /// to the tower path by the same `F(a·b) = clmul_gcm(F(a), F(b))`
    /// isomorphism used in `MulGate::evaluate_flat`.
    fn evaluate_flat(&self, frame: FlatEvalFrame) -> u128 {
        let out = frame.local[0];
        let a = frame.local[1];
        let b = frame.local[2];
        let c = frame.local[3];
        out ^ clmul_gcm(clmul_gcm(a, b), c)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Air, CompositeAir, Trace};
    use noid_core::TowerField;

    fn mk_cols(n_rows: usize, seed: u128) -> Vec<Block128> {
        (0..n_rows)
            .map(|i| {
                Block128::from(
                    seed.wrapping_mul(0x9E3779B97F4A7C15)
                        .wrapping_add(i as u128),
                )
            })
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

    /// [2.C.3] Flat-vs-tower equivalence for MulGate across a
    /// parameter sweep including 0, 1, and random-looking values.
    #[test]
    fn mul_flat_matches_tower() {
        use noid_core::hardware::tower_to_flat_u128;
        let gate = MulGate::new(0, 1, 2);
        let raws: [u128; 6] = [
            0,
            1,
            0xdead_beef,
            0xcafe_f00d_1234_5678_u128,
            0xffff_ffff_ffff_ffff_0000_0000_0000_0001_u128,
            0x1234_5678_9abc_def0_fedc_ba98_7654_3210_u128,
        ];
        for &o in &raws {
            for &a in &raws {
                for &b in &raws {
                    let out = Block128::from(o);
                    let ab = Block128::from(a);
                    let bb = Block128::from(b);
                    let tower_out = gate.evaluate(EvalFrame {
                        local: &[out, ab, bb],
                        next: &[],
                    });
                    let flat_local = [
                        tower_to_flat_u128(out.0),
                        tower_to_flat_u128(ab.0),
                        tower_to_flat_u128(bb.0),
                    ];
                    let flat_out = gate.evaluate_flat(FlatEvalFrame {
                        local: &flat_local,
                        next: &[],
                    });
                    assert_eq!(
                        flat_out,
                        tower_to_flat_u128(tower_out.0),
                        "MulGate flat diverged at o={o:#x} a={a:#x} b={b:#x}"
                    );
                }
            }
        }
    }

    #[test]
    fn square_flat_matches_tower() {
        use noid_core::hardware::tower_to_flat_u128;
        let gate = SquareGate::new(0, 1);
        for raw_o in [0u128, 1, 0xdead, 0xffff_ffff_ffff_ffff_u128] {
            for raw_a in [0u128, 1, 7, 0x1234_5678_9abc_def0_u128] {
                let out = Block128::from(raw_o);
                let a = Block128::from(raw_a);
                let tower_out = gate.evaluate(EvalFrame {
                    local: &[out, a],
                    next: &[],
                });
                let flat_local = [tower_to_flat_u128(out.0), tower_to_flat_u128(a.0)];
                let flat_out = gate.evaluate_flat(FlatEvalFrame {
                    local: &flat_local,
                    next: &[],
                });
                assert_eq!(
                    flat_out,
                    tower_to_flat_u128(tower_out.0),
                    "SquareGate flat diverged at o={raw_o:#x} a={raw_a:#x}"
                );
            }
        }
    }
}
