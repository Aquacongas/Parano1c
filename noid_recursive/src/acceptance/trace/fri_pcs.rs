// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Shared PCS trace primitives used by the region wallet-PCS discharge:
//!
//! - [`compact_queries_from_squeezes_with_bits`] — the query-index rule on
//!   PRE-SQUEEZED challenge wires (the region path reads them from walk-C
//!   carry cells). Each challenge decomposes into all 128 tower bits
//!   (booleanity-pinned, φ-weighted sum pinned to the wire), and the low
//!   `log_max_len` bits are the transcript-bound query position — witness
//!   bits driving muxes/affine forms, never native constants (class
//!   fixity).
//! - [`forward_ntt_trace`] — the additive-NTT butterfly network with
//!   constant basis twiddles: F128-linear, pure `LinExpr` algebra
//!   (0 constraints). The capsule-rate encode twin is built on it.
//! - [`mle_evaluate_small_trace`] — the highest-variable MLE fold loop
//!   (`2^n − 1` multiplications) for small tables.

use noid_core::hardware::flat_to_tower_u128;
use noid_core::Block128;

use super::{flat_const, mul, pin_zero, FieldR1csBuilder, LinExpr};

/// The native TOWER value of a trace expression (fixture/bookkeeping only —
/// never a constraint).
pub fn expr_tower_value(b: &FieldR1csBuilder, e: &LinExpr) -> Block128 {
    let f = e.eval(b.values());
    let flat = (f.lo as u128) | ((f.hi as u128) << 64);
    Block128(flat_to_tower_u128(flat))
}

/// The query-index rule driven from PRE-SQUEEZED challenge wires.
/// `squeezes.len()` must be the already-clamped query count (exactly the
/// channel schedule's `Squeeze(query_count)` op — every squeeze becomes one
/// query). Position derivation is byte-identical to the native
/// `e.0 & ((1 << log_max_len) − 1)` rule.
pub fn compact_queries_from_squeezes_with_bits(
    b: &mut FieldR1csBuilder,
    squeezes: &[LinExpr],
    log_max_len: usize,
) -> (Vec<usize>, Vec<Vec<LinExpr>>) {
    assert!(log_max_len < usize::BITS as usize);
    let mut indices = Vec::with_capacity(squeezes.len());
    let mut all_bits = Vec::with_capacity(squeezes.len());
    for e in squeezes {
        let (idx, bits) = decompose_query_squeeze(b, e, log_max_len);
        indices.push(idx);
        all_bits.push(bits);
    }
    (indices, all_bits)
}

/// Decompose one squeezed challenge wire `e` into its query index (low
/// `log_max_len` bits of the tower value) and the low `log_max_len` position
/// bits as witness wires (LSB first). Decomposes ALL 128 bits into booleans
/// (not just the high bits past the mask): baking the low position bits as
/// `add_const` constants would put the query position into the pinning row's
/// constant term and drift the matrix across blocks. `pin_zero(sum + e)` binds
/// the decomposition to the squeeze; booleanity pins each bit.
fn decompose_query_squeeze(
    b: &mut FieldR1csBuilder,
    e: &LinExpr,
    log_max_len: usize,
) -> (usize, Vec<LinExpr>) {
    let bit_mask = ((1u128 << log_max_len) - 1) as u128;
    let tower = expr_tower_value(b, e).0;
    let idx = (tower & bit_mask) as usize;
    let mut sum = LinExpr::zero();
    let mut bits = Vec::with_capacity(log_max_len);
    for i in 0..128 {
        let bit = LinExpr::from_wire(b.alloc_bool((tower >> i) & 1 == 1));
        sum = sum.add(&bit.scale(flat_const(1u128 << i)));
        if i < log_max_len {
            bits.push(bit);
        }
    }
    pin_zero(b, &sum.add(e));
    (idx, bits)
}

/// Trace twin of `noid_core::ntt::forward_ntt` over expressions. The
/// butterflies are affine with constant basis twiddles — 0 constraints.
pub fn forward_ntt_trace(coeffs: &[LinExpr], basis: &[Block128]) -> Vec<LinExpr> {
    let n = coeffs.len();
    assert!(n.is_power_of_two());
    assert_eq!(basis.len(), n.trailing_zeros() as usize);
    let mut evals = coeffs.to_vec();
    let mut len = 1usize;
    for &bb in basis.iter() {
        let b_flat = flat_const(bb.0);
        for start in (0..n).step_by(2 * len) {
            for i in start..start + len {
                let u = evals[i].clone();
                let v = evals[i + len].clone();
                let sum = u.add(&v);
                evals[i] = sum.clone();
                evals[i + len] = sum.scale(b_flat).add(&v);
            }
        }
        len *= 2;
    }
    evals
}

/// Trace twin of the highest-variable MLE fold loop for small tables
/// (`2^n − 1` multiplications).
pub fn mle_evaluate_small_trace(
    b: &mut FieldR1csBuilder,
    evals: &[LinExpr],
    point: &[LinExpr],
) -> LinExpr {
    if point.is_empty() {
        return evals[0].clone();
    }
    let mut buf = evals.to_vec();
    for r in point.iter().rev() {
        let half = buf.len() / 2;
        for i in 0..half {
            let diff = buf[i].add(&buf[i + half]);
            buf[i] = buf[i].add(&mul(b, r, &diff));
        }
        buf.truncate(half);
    }
    buf[0].clone()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::super::test_support::assert_expr_is;
    use super::super::alloc_blocks;
    use super::*;
    use noid_core::AdditiveNTT;

    struct Rng(u128);
    impl Rng {
        fn next_u128(&mut self) -> u128 {
            self.0 = self
                .0
                .wrapping_mul(0x9E37_79B9_7F4A_7C15)
                .wrapping_add(0xB5AD_4ECE_DA1C_E2A9);
            self.0
        }
        fn next_block(&mut self) -> Block128 {
            Block128::from(self.next_u128())
        }
    }

    /// The pre-squeezed query decomposition reproduces the native
    /// `e.0 & mask` index rule, its 128-bit recomposition pins to the wire,
    /// and the returned low bits equal the index's binary digits.
    #[test]
    fn queries_from_squeezes_match_native_mask_rule() {
        let mut rng = Rng(0x9E37);
        let log_max_len = 14usize;
        let squeezed: Vec<Block128> = (0..8).map(|_| rng.next_block()).collect();
        let mut b = FieldR1csBuilder::new();
        let wires = alloc_blocks(&mut b, &squeezed);
        let (indices, bits) = compact_queries_from_squeezes_with_bits(&mut b, &wires, log_max_len);
        for (q, e) in squeezed.iter().enumerate() {
            let native = (e.0 & ((1u128 << log_max_len) - 1)) as usize;
            assert_eq!(indices[q], native, "query {q} index");
            for (i, bit) in bits[q].iter().enumerate() {
                let v = bit.eval(b.values());
                let expect = (native >> i) & 1 == 1;
                assert_eq!(v != noid_ivc_core::field::F128::ZERO, expect, "query {q} bit {i}");
            }
        }
        let (r1cs, z) = b.build();
        assert!(r1cs.satisfies(&z), "honest decomposition satisfies");
    }

    /// The NTT twin reproduces `AdditiveNTT::forward_transform` for a
    /// shifted-basis window (the capsule-encode window form).
    #[test]
    fn forward_ntt_trace_matches_native_window() {
        let log_n = 4usize;
        let mut rng = Rng(7);
        let msg: Vec<Block128> = (0..1usize << log_n).map(|_| rng.next_block()).collect();
        let ntt = AdditiveNTT::<Block128>::new(log_n + 5);
        for round in [0u32, 3, 17] {
            let mut native = msg.clone();
            ntt.forward_transform(&mut native, round, 0);
            let mut b = FieldR1csBuilder::new();
            let msg_e = alloc_blocks(&mut b, &msg);
            let basis: Vec<Block128> = (round as usize..round as usize + log_n)
                .map(|i| Block128::from(1u128 << i))
                .collect();
            let enc = forward_ntt_trace(&msg_e, &basis);
            for (e, nv) in enc.iter().zip(native.iter()) {
                assert_expr_is(&b, e, *nv, "window symbol");
            }
        }
    }

    #[test]
    fn mle_evaluate_small_trace_matches_native() {
        let mut rng = Rng(31);
        for n in [0usize, 1, 3, 5] {
            let evals: Vec<Block128> = (0..1usize << n).map(|_| rng.next_block()).collect();
            let point: Vec<Block128> = (0..n).map(|_| rng.next_block()).collect();
            let mut buf = evals.clone();
            for &r in point.iter().rev() {
                let half = buf.len() / 2;
                for i in 0..half {
                    buf[i] = buf[i] + r * (buf[i] + buf[i + half]);
                }
                buf.truncate(half);
            }
            let native = buf[0];

            let mut b = FieldR1csBuilder::new();
            let evals_e = alloc_blocks(&mut b, &evals);
            let point_e = alloc_blocks(&mut b, &point);
            let got = mle_evaluate_small_trace(&mut b, &evals_e, &point_e);
            assert_expr_is(&b, &got, native, "mle_evaluate_small");
            let (r1cs, z) = b.build();
            assert!(r1cs.satisfies(&z));
        }
    }
}
