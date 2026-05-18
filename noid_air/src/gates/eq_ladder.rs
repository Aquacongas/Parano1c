// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! `EqLadderStepGate` — fused degree-2 recurrence gate for the
//! char-2 MLE equality-indicator ladder.
//!
//! In GF(2^128) the 1-variable `eq` indicator is
//!   `eq_one_var(r, b) = 1 + r + b`
//! (XOR form, because in char-2 `x + (1 - x) = 1`). The full
//! multilinear equality indicator at `bits ∈ {0, 1}^k` against a
//! transcript-derived point `r ∈ F^k` factors as a ladder:
//!   `eq_0 = eq_one_var(r_0, b_0)`,
//!   `eq_k = eq_{k-1} · eq_one_var(r_k, b_k)`.
//!
//! This gate asserts one step of that ladder row-locally:
//!   `out + prev · (ONE + r + b) == 0`.
//!
//! Why a fused gate, not `MulGate + WeightedLinearGate`? The
//! non-fused layout needs one intermediate column per step
//! (`lin_k = 1 + r_k + b_k`), doubling the committed-column count
//! across the ladder. `EqLadderStepGate` eliminates the
//! intermediate: `L` ladder steps → `L` committed eq-columns,
//! zero intermediates. Same degree bound (2), fewer FRI columns,
//! strictly smaller proof.

use crate::{Constraint, EvalFrame, FlatEvalFrame};
use noid_core::hardware::clmul_gcm;
use noid_core::{Block128, TowerField};

/// `out + prev · (ONE + r + b) == 0` (degree 2).
///
/// Columns (in order): `out`, `prev`, `r`, `b`. All four must be
/// distinct — `prev` aliasing `out` would force `prev == 0`, which
/// is never what the ladder wants.
pub struct EqLadderStepGate {
    cols: [usize; 4],
}

impl EqLadderStepGate {
    pub fn new(out: usize, prev: usize, r: usize, b: usize) -> Self {
        let cols = [out, prev, r, b];
        for i in 0..cols.len() {
            for j in (i + 1)..cols.len() {
                assert_ne!(
                    cols[i], cols[j],
                    "EqLadderStepGate: columns must be pairwise distinct"
                );
            }
        }
        Self { cols }
    }
}

impl Constraint for EqLadderStepGate {
    fn degree(&self) -> usize {
        2
    }
    fn columns(&self) -> &[usize] {
        &self.cols
    }
    fn evaluate(&self, frame: EvalFrame) -> Block128 {
        let out = frame.local[0];
        let prev = frame.local[1];
        let r = frame.local[2];
        let b = frame.local[3];
        out + prev * (Block128::ONE + r + b)
    }
    /// Flat-basis evaluator. XOR-linear in the `(ONE + r + b)`
    /// factor, one CLMUL for the product. Matches the tower path
    /// by the same field-isomorphism argument as `MulGate`.
    fn evaluate_flat(&self, frame: FlatEvalFrame) -> u128 {
        let out = frame.local[0];
        let prev = frame.local[1];
        let r = frame.local[2];
        let b = frame.local[3];
        // ONE in flat basis is `tower_to_flat_u128(1) == 1`
        // (field isomorphism fixes the multiplicative identity).
        let factor = 1u128 ^ r ^ b;
        out ^ clmul_gcm(prev, factor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Air, CompositeAir, Trace};
    use noid_core::hardware::tower_to_flat_u128;

    fn mk_rows(n: usize, seed: u128) -> Vec<Block128> {
        (0..n)
            .map(|i| {
                Block128::from(
                    seed.wrapping_mul(0x9E3779B97F4A7C15)
                        .wrapping_add(i as u128),
                )
            })
            .collect()
    }

    #[test]
    fn eq_ladder_step_accepts_honest() {
        let n = 1 << 3;
        let prev = mk_rows(n, 0xABCD);
        let r = mk_rows(n, 0x1234);
        // b is a bit column (0 / 1).
        let b: Vec<Block128> = (0..n)
            .map(|i| {
                if i & 1 == 0 {
                    Block128::ZERO
                } else {
                    Block128::ONE
                }
            })
            .collect();
        let out: Vec<Block128> = (0..n)
            .map(|i| prev[i] * (Block128::ONE + r[i] + b[i]))
            .collect();
        let air = CompositeAir::from_parts(3, 4, vec![Box::new(EqLadderStepGate::new(0, 1, 2, 3))]);
        let trace = Trace::new(vec![out, prev, r, b]);
        assert!(air.check(&trace));
    }

    #[test]
    fn eq_ladder_step_rejects_tampered_out() {
        let n = 1 << 3;
        let prev = mk_rows(n, 0xABCD);
        let r = mk_rows(n, 0x1234);
        let b: Vec<Block128> = (0..n)
            .map(|i| {
                if i & 1 == 0 {
                    Block128::ZERO
                } else {
                    Block128::ONE
                }
            })
            .collect();
        let mut out: Vec<Block128> = (0..n)
            .map(|i| prev[i] * (Block128::ONE + r[i] + b[i]))
            .collect();
        out[2] = out[2] + Block128::ONE;
        let air = CompositeAir::from_parts(3, 4, vec![Box::new(EqLadderStepGate::new(0, 1, 2, 3))]);
        let trace = Trace::new(vec![out, prev, r, b]);
        assert!(!air.check(&trace));
    }

    #[test]
    fn eq_ladder_step_rejects_tampered_r() {
        let n = 1 << 3;
        let prev = mk_rows(n, 0xABCD);
        let mut r = mk_rows(n, 0x1234);
        let b: Vec<Block128> = (0..n)
            .map(|i| {
                if i & 1 == 0 {
                    Block128::ZERO
                } else {
                    Block128::ONE
                }
            })
            .collect();
        let out: Vec<Block128> = (0..n)
            .map(|i| prev[i] * (Block128::ONE + r[i] + b[i]))
            .collect();
        r[1] = r[1] + Block128::ONE;
        let air = CompositeAir::from_parts(3, 4, vec![Box::new(EqLadderStepGate::new(0, 1, 2, 3))]);
        let trace = Trace::new(vec![out, prev, r, b]);
        assert!(!air.check(&trace));
    }

    #[test]
    fn eq_ladder_step_rejects_tampered_b() {
        let n = 1 << 3;
        let prev = mk_rows(n, 0xABCD);
        let r = mk_rows(n, 0x1234);
        let b: Vec<Block128> = (0..n)
            .map(|i| {
                if i & 1 == 0 {
                    Block128::ZERO
                } else {
                    Block128::ONE
                }
            })
            .collect();
        let out: Vec<Block128> = (0..n)
            .map(|i| prev[i] * (Block128::ONE + r[i] + b[i]))
            .collect();
        let mut b_bad = b.clone();
        b_bad[0] = b_bad[0] + Block128::ONE;
        let air = CompositeAir::from_parts(3, 4, vec![Box::new(EqLadderStepGate::new(0, 1, 2, 3))]);
        let trace = Trace::new(vec![out, prev, r, b_bad]);
        assert!(!air.check(&trace));
    }

    #[test]
    #[should_panic(expected = "distinct")]
    fn eq_ladder_step_rejects_duplicate_columns() {
        let _ = EqLadderStepGate::new(0, 0, 1, 2);
    }

    /// Flat-vs-tower equivalence sweep — same shape as `MulGate`.
    #[test]
    fn eq_ladder_step_flat_matches_tower() {
        let gate = EqLadderStepGate::new(0, 1, 2, 3);
        let raws: [u128; 5] = [
            0,
            1,
            0xdead_beef,
            0xcafe_f00d_1234_5678_u128,
            0xffff_ffff_ffff_ffff_0000_0000_0000_0001_u128,
        ];
        // b is a bit, but the identity is polynomial — flat must
        // agree at every u128 anyway.
        for &o in &raws {
            for &p in &raws {
                for &r in &raws {
                    for &b in &raws {
                        let out_b = Block128::from(o);
                        let prev_b = Block128::from(p);
                        let r_b = Block128::from(r);
                        let b_b = Block128::from(b);
                        let tower_out = gate.evaluate(EvalFrame {
                            local: &[out_b, prev_b, r_b, b_b],
                            next: &[],
                        });
                        let flat_local = [
                            tower_to_flat_u128(out_b.0),
                            tower_to_flat_u128(prev_b.0),
                            tower_to_flat_u128(r_b.0),
                            tower_to_flat_u128(b_b.0),
                        ];
                        let flat_out = gate.evaluate_flat(FlatEvalFrame {
                            local: &flat_local,
                            next: &[],
                        });
                        assert_eq!(
                            flat_out,
                            tower_to_flat_u128(tower_out.0),
                            "EqLadderStep flat diverged at o={o:#x} p={p:#x} r={r:#x} b={b:#x}"
                        );
                    }
                }
            }
        }
    }
}
