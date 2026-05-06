// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! `WeightedLinearGate`: `Σ wᵢ · colᵢ + c == 0` — degree-1 linear gate
//! over GF(2^128). XOR-linear sum (all weights `ONE`, no constant) is
//! the special case exposed through [`WeightedLinearGate::new_xor`] and
//! used by balance / bit-XOR gates.

use crate::{Constraint, EvalFrame, FlatEvalFrame};
use noid_core::hardware::{clmul_gcm, tower_to_flat_u128};
use noid_core::{Block128, TowerField};

/// `Σ_i weight_i · col_i + constant == 0`.
pub struct WeightedLinearGate {
    terms: Vec<(usize, Block128)>,
    constant: Block128,
    cols: Vec<usize>,
    /// [2.C.3] Flat-basis image of `terms[i].1`, pre-converted once at
    /// construction so the hot `evaluate_flat` path needs only XOR +
    /// `clmul_gcm`. Same length / order as `terms`.
    weights_flat: Vec<u128>,
    /// [2.C.3] Flat-basis image of `constant`.
    constant_flat: u128,
}

impl WeightedLinearGate {
    /// `Σ weight_i · col_i + constant == 0`. Column indices in `terms`
    /// must be unique.
    pub fn new(terms: Vec<(usize, Block128)>, constant: Block128) -> Self {
        assert!(!terms.is_empty(), "linear gate needs at least one column");
        let cols: Vec<usize> = terms.iter().map(|&(c, _)| c).collect();
        for i in 0..cols.len() {
            for j in (i + 1)..cols.len() {
                assert_ne!(
                    cols[i], cols[j],
                    "WeightedLinearGate: duplicate column index {}",
                    cols[i]
                );
            }
        }
        let weights_flat: Vec<u128> = terms.iter().map(|(_, w)| tower_to_flat_u128(w.0)).collect();
        let constant_flat = tower_to_flat_u128(constant.0);
        Self {
            terms,
            constant,
            cols,
            weights_flat,
            constant_flat,
        }
    }

    /// `Σ col_i == 0` — the XOR-linear special case used by balance
    /// and bit-XOR gates.
    pub fn new_xor(cols: Vec<usize>) -> Self {
        let terms = cols.into_iter().map(|c| (c, Block128::ONE)).collect();
        Self::new(terms, Block128::ZERO)
    }
}

impl Constraint for WeightedLinearGate {
    fn degree(&self) -> usize {
        1
    }
    fn columns(&self) -> &[usize] {
        &self.cols
    }
    fn evaluate(&self, frame: EvalFrame) -> Block128 {
        let mut acc = self.constant;
        for (i, &(_, w)) in self.terms.iter().enumerate() {
            acc = acc + w * frame.local[i];
        }
        acc
    }
    /// [2.C.3] Flat-basis evaluator. Weights are cached in flat basis
    /// at construction time so each term costs one `clmul_gcm` + XOR.
    /// Equivalent to `evaluate` by field-isomorphism argument: `F` is
    /// linear in `+` and multiplicative on `·`, so
    ///   `F(Σ w_i · v_i + c) = Σ F(w_i)·F(v_i) + F(c)`.
    fn evaluate_flat(&self, frame: FlatEvalFrame) -> u128 {
        let mut acc = self.constant_flat;
        for (i, &wf) in self.weights_flat.iter().enumerate() {
            acc ^= clmul_gcm(wf, frame.local[i]);
        }
        acc
    }
}

/// Linear gate with mixed local-row and next-row column reads:
/// `Σ_i w_local_i · local[i] + Σ_j w_next_j · next[j] + constant == 0`.
/// Degree-1; rotation reads are cyclic (`next(last) == first`), matching
/// the base `Air::check` contract. Column indices in `local_terms` must
/// be pairwise distinct; same for `next_terms`. A column may appear on
/// both sides (local + next read of the same column is legitimate).
///
/// §3d-0.5.2 primitive. Used by [`crate::gates::emit_column_eq_at_next_row`]
/// to express cross-row equality ties — the inter-permutation carry in
/// 3d-0.6b tie (3) is the first caller.
pub struct WeightedLinearGateShifted {
    local_terms: Vec<(usize, Block128)>,
    next_terms: Vec<(usize, Block128)>,
    constant: Block128,
    cols: Vec<usize>,
    shifted: Vec<usize>,
    /// [2.C.3] Flat-basis caches for the hot `evaluate_flat` path.
    local_weights_flat: Vec<u128>,
    next_weights_flat: Vec<u128>,
    constant_flat: u128,
}

impl WeightedLinearGateShifted {
    pub fn new(
        local_terms: Vec<(usize, Block128)>,
        next_terms: Vec<(usize, Block128)>,
        constant: Block128,
    ) -> Self {
        assert!(
            !local_terms.is_empty() || !next_terms.is_empty(),
            "shifted linear gate needs at least one term"
        );
        let cols: Vec<usize> = local_terms.iter().map(|&(c, _)| c).collect();
        for i in 0..cols.len() {
            for j in (i + 1)..cols.len() {
                assert_ne!(
                    cols[i], cols[j],
                    "WeightedLinearGateShifted: duplicate local column {}",
                    cols[i]
                );
            }
        }
        let shifted: Vec<usize> = next_terms.iter().map(|&(c, _)| c).collect();
        for i in 0..shifted.len() {
            for j in (i + 1)..shifted.len() {
                assert_ne!(
                    shifted[i], shifted[j],
                    "WeightedLinearGateShifted: duplicate next column {}",
                    shifted[i]
                );
            }
        }
        let local_weights_flat: Vec<u128> = local_terms
            .iter()
            .map(|(_, w)| tower_to_flat_u128(w.0))
            .collect();
        let next_weights_flat: Vec<u128> = next_terms
            .iter()
            .map(|(_, w)| tower_to_flat_u128(w.0))
            .collect();
        let constant_flat = tower_to_flat_u128(constant.0);
        Self {
            local_terms,
            next_terms,
            constant,
            cols,
            shifted,
            local_weights_flat,
            next_weights_flat,
            constant_flat,
        }
    }

    /// Pins `col_a@row == col_b@row+1` in char-2 (XOR). Equivalent to
    /// `Self::new(vec![(col_a, ONE)], vec![(col_b, ONE)], ZERO)`.
    pub fn new_xor_next(col_a: usize, col_b_next: usize) -> Self {
        Self::new(
            vec![(col_a, Block128::ONE)],
            vec![(col_b_next, Block128::ONE)],
            Block128::ZERO,
        )
    }
}

impl Constraint for WeightedLinearGateShifted {
    fn degree(&self) -> usize {
        1
    }
    fn columns(&self) -> &[usize] {
        &self.cols
    }
    fn shifted_columns(&self) -> &[usize] {
        &self.shifted
    }
    fn evaluate(&self, frame: EvalFrame) -> Block128 {
        let mut acc = self.constant;
        for (i, &(_, w)) in self.local_terms.iter().enumerate() {
            acc = acc + w * frame.local[i];
        }
        for (i, &(_, w)) in self.next_terms.iter().enumerate() {
            acc = acc + w * frame.next[i];
        }
        acc
    }
    /// [2.C.3] Flat-basis evaluator; mirrors the tower path with
    /// cached flat weights for both the local and next terms.
    fn evaluate_flat(&self, frame: FlatEvalFrame) -> u128 {
        let mut acc = self.constant_flat;
        for (i, &wf) in self.local_weights_flat.iter().enumerate() {
            acc ^= clmul_gcm(wf, frame.local[i]);
        }
        for (i, &wf) in self.next_weights_flat.iter().enumerate() {
            acc ^= clmul_gcm(wf, frame.next[i]);
        }
        acc
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Air, CompositeAir, Trace};

    #[test]
    fn weighted_linear_gate_native_check_with_constant() {
        // 3 · col0 + 5 · col1 + 7 == 0.
        let w0 = Block128::from(3u128);
        let w1 = Block128::from(5u128);
        let k = Block128::from(7u128);
        let gate = WeightedLinearGate::new(vec![(0, w0), (1, w1)], k);
        let air = CompositeAir::from_parts(2, 2, vec![Box::new(gate)]);
        let inv_w1 = w1.invert();
        let n = 1 << 2;
        let col0: Vec<Block128> = (0..n).map(|i| Block128::from(i as u128 * 9 + 2)).collect();
        let col1: Vec<Block128> = col0.iter().map(|c| (w0 * *c + k) * inv_w1).collect();
        let trace = Trace::new(vec![col0, col1]);
        assert!(air.check(&trace));
    }

    #[test]
    fn weighted_linear_gate_rejects_wrong_constant() {
        let w0 = Block128::from(3u128);
        let w1 = Block128::from(5u128);
        let gate = WeightedLinearGate::new(vec![(0, w0), (1, w1)], Block128::from(7u128));
        let air = CompositeAir::from_parts(2, 2, vec![Box::new(gate)]);
        let col0: Vec<Block128> = (0..4).map(|i| Block128::from(i as u128)).collect();
        let inv_w1 = w1.invert();
        let col1: Vec<Block128> = col0.iter().map(|c| w0 * *c * inv_w1).collect();
        let trace = Trace::new(vec![col0, col1]);
        assert!(!air.check(&trace));
    }

    #[test]
    #[should_panic(expected = "duplicate column index")]
    fn weighted_linear_gate_rejects_duplicate_columns() {
        let _ = WeightedLinearGate::new(
            vec![(0, Block128::ONE), (0, Block128::from(2u128))],
            Block128::ZERO,
        );
    }

    // -----------------------------------------------------------------
    // WeightedLinearGateShifted
    // -----------------------------------------------------------------

    #[test]
    fn shifted_gate_xor_next_accepts_off_by_one_equal() {
        // col0@row == col1@row+1 for every row; cyclic rotation.
        let gate = WeightedLinearGateShifted::new_xor_next(0, 1);
        let air = CompositeAir::from_parts(2, 2, vec![Box::new(gate)]);
        let n = 1usize << 2;
        // col0 = [a, b, c, d]; col1 = [b, c, d, a]  (next of col1 must equal col0 here means
        // col1[row+1] == col0[row], i.e. col1 is a left-rotation of col0).
        let a = Block128::from(11u128);
        let b = Block128::from(22u128);
        let c = Block128::from(33u128);
        let d = Block128::from(44u128);
        let col0 = vec![a, b, c, d];
        let col1 = vec![d, a, b, c];
        let trace = Trace::new(vec![col0, col1]);
        assert!(air.check(&trace));
        let _ = n;
    }

    #[test]
    fn shifted_gate_xor_next_rejects_mismatch() {
        let gate = WeightedLinearGateShifted::new_xor_next(0, 1);
        let air = CompositeAir::from_parts(2, 2, vec![Box::new(gate)]);
        let col0 = vec![
            Block128::ZERO,
            Block128::ZERO,
            Block128::ZERO,
            Block128::ZERO,
        ];
        let col1 = vec![
            Block128::ZERO,
            Block128::ZERO,
            Block128::ONE,
            Block128::ZERO,
        ];
        // col0[1] = 0 but col1[2] = 1 → mismatch.
        let trace = Trace::new(vec![col0, col1]);
        assert!(!air.check(&trace));
    }

    #[test]
    #[should_panic(expected = "duplicate next column")]
    fn shifted_gate_rejects_duplicate_next_column() {
        let _ = WeightedLinearGateShifted::new(
            vec![],
            vec![(0, Block128::ONE), (0, Block128::from(2u128))],
            Block128::ZERO,
        );
    }

    #[test]
    #[should_panic(expected = "at least one term")]
    fn shifted_gate_rejects_empty() {
        let _ = WeightedLinearGateShifted::new(vec![], vec![], Block128::ZERO);
    }

    /// [2.C.3] Native `evaluate_flat` must agree with the tower path
    /// after basis mapping, for both gates. Sweep over random-looking
    /// weights / values covering zero, one, and full-width inputs.
    #[test]
    fn weighted_linear_flat_matches_tower() {
        use noid_core::hardware::tower_to_flat_u128;
        let w0 = Block128::from(0xdead_beef_u128);
        let w1 = Block128::from(0xffff_ffff_ffff_ffff_0000_0000_0000_0001_u128);
        let k = Block128::from(0x1234_5678_9abc_def0_u128);
        let gate = WeightedLinearGate::new(vec![(0, w0), (1, w1)], k);
        for raw_a in [0u128, 1, 7, 0xcafe, 0xffff_ffff_ffff_ffff_u128] {
            for raw_b in [0u128, 1, 2, 0xbeef_u128, 0x8000_0000_0000_0000_u128] {
                let a = Block128::from(raw_a);
                let b = Block128::from(raw_b);
                let tower_out = gate.evaluate(EvalFrame {
                    local: &[a, b],
                    next: &[],
                });
                let flat_local = [tower_to_flat_u128(a.0), tower_to_flat_u128(b.0)];
                let flat_out = gate.evaluate_flat(FlatEvalFrame {
                    local: &flat_local,
                    next: &[],
                });
                assert_eq!(
                    flat_out,
                    tower_to_flat_u128(tower_out.0),
                    "WeightedLinearGate flat diverged at a={raw_a:#x} b={raw_b:#x}"
                );
            }
        }
    }

    #[test]
    fn weighted_linear_shifted_flat_matches_tower() {
        use noid_core::hardware::tower_to_flat_u128;
        let gate = WeightedLinearGateShifted::new(
            vec![(0, Block128::from(0xabcd_u128))],
            vec![(1, Block128::from(0xef01_u128))],
            Block128::from(0x5a5a_u128),
        );
        for raw_local in [0u128, 1, 0xdead_cafe_u128, 0xffff_0000_ffff_0000_u128] {
            for raw_next in [0u128, 1, 0xbeef_u128, 0x8000_0000_0000_0000_u128] {
                let l = Block128::from(raw_local);
                let n = Block128::from(raw_next);
                let tower_out = gate.evaluate(EvalFrame {
                    local: &[l],
                    next: &[n],
                });
                let flat_out = gate.evaluate_flat(FlatEvalFrame {
                    local: &[tower_to_flat_u128(l.0)],
                    next: &[tower_to_flat_u128(n.0)],
                });
                assert_eq!(
                    flat_out,
                    tower_to_flat_u128(tower_out.0),
                    "WeightedLinearGateShifted flat diverged at local={raw_local:#x} next={raw_next:#x}"
                );
            }
        }
    }
}
