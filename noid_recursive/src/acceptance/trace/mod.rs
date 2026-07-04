// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Killshot verifiers as arithmetic F128 traces — the verifier-replay and
//! discharge slots of the recursive acceptance proof.
//!
//! Every `*_trace` function in this tree is a **line-by-line transliteration**
//! of its native `verify_*` / `discharge_*_native` reference (hard rule):
//! same absorb/squeeze order on the raw killshot channel
//! ([`RawChannelTrace`] — the in-circuit mirror of
//! `noid_poseidon2b::channel::Poseidon2bChannel`), same checks, no
//! reorderings. Any edit to a native verifier MUST change its trace twin (and
//! `tier1_shape_stats.rs`) in the same commit.
//!
//! ## How native control flow maps into the trace
//!
//! - **Shape checks** (`proof.rounds.len() != n`, degree bounds, claim
//!   counts): the trace has a FIXED shape (fixed-shape invariant) — a proof of the
//!   wrong shape is unrepresentable; the `alloc` constructors assert. Value
//!   mutations inside an honest shape are what the auto-mutator exercises.
//! - **Value checks** (`return None` on a mismatched field equation): a
//!   [`pin_zero`] row — the trace becomes unsatisfiable exactly where native
//!   rejects (replay-completeness invariant).
//! - **Basis**: circuit wires carry flat (GCM) images of tower values
//!   (`φ = tower_to_flat_u128`); XOR commutes with φ and every tower mul is
//!   an F128 mul of the flat images, so replayed verifier algebra is
//!   value-for-value the native algebra. Public tower constants enter via
//!   [`flat_of`] / `flat_const`.
//! - **Association of products**: where a native helper evaluates a public
//!   polynomial by a different-but-equal strategy (eq tensors instead of
//!   per-index products), the trace may share partial products — field
//!   algebra is associative, the VALUE is bit-identical and the FS schedule
//!   is untouched. The FS schedule itself is never restructured.

pub mod accepted_claim_hash;
pub mod auth_pcs;
pub mod batch_eval;
pub mod fri_pcs;
pub mod block_spine;
pub mod accepted_claim_batch;
pub mod checkpoint_poseidon;
pub mod exact_state;
pub mod merkle_path;
pub mod owner_auth;
pub mod self_verify;
pub mod tx_body_spine;

use std::collections::HashMap;

use noid_core::Block128;

pub use noid_ivc_core::field_circuit::{
    flat_const, poseidon2b_permute, FieldR1csBuilder, LinExpr, RawChannelTrace, Wire,
};
pub use noid_ivc_core::field::F128;

/// φ-map a tower value into the circuit (flat) basis.
#[inline]
pub fn flat_of(v: Block128) -> F128 {
    flat_const(v.0)
}

/// Allocate a witness wire carrying the flat image of a tower value.
#[inline]
pub fn alloc_block(b: &mut FieldR1csBuilder, v: Block128) -> LinExpr {
    LinExpr::from_wire(b.alloc_f128(flat_of(v)))
}

/// Allocate a witness wire per element.
pub fn alloc_blocks(b: &mut FieldR1csBuilder, vs: &[Block128]) -> Vec<LinExpr> {
    vs.iter().map(|&v| alloc_block(b, v)).collect()
}

/// Constant (public, build-time) tower value as an expression.
#[inline]
pub fn const_block(v: Block128) -> LinExpr {
    LinExpr::constant(flat_of(v))
}

/// Assert `expr == 0` (1 wire). The trace twin of a native
/// `if lhs != rhs { return None; }` check, called with `lhs + rhs`
/// (subtraction == addition in char 2).
#[inline]
pub fn pin_zero(b: &mut FieldR1csBuilder, expr: &LinExpr) {
    b.pin_f128(expr, F128::ZERO);
}

/// Assert two expressions are equal.
#[inline]
pub fn pin_eq(b: &mut FieldR1csBuilder, lhs: &LinExpr, rhs: &LinExpr) {
    pin_zero(b, &lhs.add(rhs));
}

/// One multiplication, returned as an expression.
#[inline]
pub fn mul(b: &mut FieldR1csBuilder, x: &LinExpr, y: &LinExpr) -> LinExpr {
    LinExpr::from_wire(b.mul(x, y))
}

/// Trace twin of `noid_core::mle::eq::eq_ind` for two expression points:
/// `Π (1 + x_i + y_i)` (the char-2 form of `x·y + (1−x)(1−y)`).
pub fn eq_ind_trace(b: &mut FieldR1csBuilder, x: &[LinExpr], y: &[LinExpr]) -> LinExpr {
    b.eq_eval_trace(x, y)
}

/// Trace twin of `noid_core::mle::eq::eq_ind_partial_eval`: the tensor
/// `(1−r_0, r_0) ⊗ … ⊗ (1−r_{n−1}, r_{n−1})` of length `2^n`, bit `i` of the
/// index ↔ `point[i]`. Costs `2^n − 1` multiplications.
pub fn eq_ind_partial_eval_trace(
    b: &mut FieldR1csBuilder,
    point: &[LinExpr],
) -> Vec<LinExpr> {
    let mut result = vec![LinExpr::constant(F128::ONE)];
    for r_i in point {
        let len = result.len();
        for j in 0..len {
            let prod = mul(b, &result[j], r_i);
            result[j] = result[j].add(&prod); // val − val·r == val + val·r
            result.push(prod);
        }
    }
    result
}

/// Trace twin of `noid_core::mle::evaluate::evaluate_slice` for an
/// expression table at an expression point: `Σ_x tab[x] · eq(x, r)` via the
/// eq tensor (same value as the native highest-var fold).
pub fn evaluate_slice_trace(
    b: &mut FieldR1csBuilder,
    tab: &[LinExpr],
    point: &[LinExpr],
) -> LinExpr {
    assert_eq!(tab.len(), 1usize << point.len());
    let eq = eq_ind_partial_eval_trace(b, point);
    let mut acc = LinExpr::zero();
    for (t, e) in tab.iter().zip(eq.iter()) {
        acc = acc.add(&mul(b, t, e));
    }
    acc
}

/// Memoized `eq(boolean-index, r)` products over one challenge point `r` —
/// the trace twin of `batch_eval::eq_at_boolean_index`. Native multiplies the
/// per-bit factors `r_b` / `1 + r_b` left to right; the cache shares prefix
/// products across indices (associativity — same value), which is what makes
/// large public linear relations (spine chain claims, Merkle path chains)
/// affordable in-trace.
pub struct BooleanPointEqCache {
    r: Vec<LinExpr>,
    /// (depth, index & ((1<<depth)−1)) → product of the first `depth` factors.
    memo: HashMap<(usize, usize), LinExpr>,
}

impl BooleanPointEqCache {
    pub fn new(r: &[LinExpr]) -> Self {
        Self {
            r: r.to_vec(),
            memo: HashMap::new(),
        }
    }

    fn factor(&self, bit: usize, set: bool) -> LinExpr {
        if set {
            self.r[bit].clone()
        } else {
            self.r[bit].add_const(F128::ONE)
        }
    }

    /// `eq` at the boolean point whose bit `b` is `(index >> b) & 1`, over
    /// all `n = r.len()` variables.
    pub fn eq_at_index(&mut self, b: &mut FieldR1csBuilder, index: usize) -> LinExpr {
        let n = self.r.len();
        assert!(n >= 1);
        assert!(index < (1usize << n));
        self.prefix(b, index, n)
    }

    fn prefix(&mut self, b: &mut FieldR1csBuilder, index: usize, depth: usize) -> LinExpr {
        let key = (depth, index & ((1usize << depth) - 1));
        if let Some(e) = self.memo.get(&key) {
            return e.clone();
        }
        let expr = if depth == 1 {
            self.factor(0, index & 1 == 1)
        } else {
            let below = self.prefix(b, index, depth - 1);
            let f = self.factor(depth - 1, (index >> (depth - 1)) & 1 == 1);
            mul(b, &below, &f)
        };
        self.memo.insert(key, expr.clone());
        expr
    }
}

/// Enforce that `expr` (the flat image `φ(v)` of a tower value `v`) carries
/// a value whose TOWER bit pattern fits in `n_bits` integer bits. Because φ
/// is F2-linear, `φ(v) = Σ_i bit_i(v) · φ(2^i)` — so allocating the tower
/// bits as booleans and pinning the φ-mapped power sum against the wire
/// forces every tower bit above `n_bits − 1` to zero. Used to make native
/// implicit type bounds (u64 amounts, u32 slots) explicit in-trace.
/// Returns the bit wires (LSB-first, tower bit order).
pub fn range_check_bits(b: &mut FieldR1csBuilder, expr: &LinExpr, n_bits: usize) -> Vec<Wire> {
    use noid_core::hardware::flat_to_tower_u128;
    assert!(n_bits <= 128);
    let flat = expr.eval(b.values());
    let tower = flat_to_tower_u128((flat.lo as u128) | ((flat.hi as u128) << 64));
    let bits: Vec<Wire> = (0..n_bits)
        .map(|i| b.alloc_bool((tower >> i) & 1 == 1))
        .collect();
    let mut sum = LinExpr::zero();
    for (i, bit) in bits.iter().enumerate() {
        sum = sum.add(&LinExpr::from_wire(*bit).scale(flat_const(1u128 << i)));
    }
    pin_zero(b, &sum.add(expr));
    bits
}

/// Enforce strict unsigned `a < b` over two already range-checked bit
/// decompositions (LSB-first, same width): MSB-first borrow fold, then pin
/// the less-than accumulator to 1. ~3 multiplications per bit.
pub fn pin_lt_strict(b: &mut FieldR1csBuilder, a_bits: &[Wire], b_bits: &[Wire]) {
    assert_eq!(a_bits.len(), b_bits.len());
    assert!(!a_bits.is_empty());
    let mut acc_lt = LinExpr::zero();
    let mut acc_eq = LinExpr::constant(F128::ONE);
    for (a, bb) in a_bits.iter().rev().zip(b_bits.iter().rev()) {
        let a_e = LinExpr::from_wire(*a);
        let b_e = LinExpr::from_wire(*bb);
        // (¬a_i)·b_i — this bit decides if all higher bits are equal.
        let not_a_and_b = mul(b, &a_e.add_const(F128::ONE), &b_e);
        acc_lt = acc_lt.add(&mul(b, &acc_eq, &not_a_and_b));
        // eq_i = 1 + a_i + b_i (char-2 bit equality).
        acc_eq = mul(b, &acc_eq, &a_e.add(&b_e).add_const(F128::ONE));
    }
    pin_zero(b, &acc_lt.add_const(F128::ONE));
}

/// A univariate round polynomial in coefficient form, allocated from a native
/// `RoundPolynomial<Block128>` (`noid_core::sumcheck`). The coefficient count
/// is part of the trace shape: native's `degree() > BOUND → reject` becomes
/// an alloc-time assertion (an off-shape proof is unrepresentable).
pub struct RoundPolyTrace {
    pub coeffs: Vec<LinExpr>,
}

impl RoundPolyTrace {
    pub fn alloc(
        b: &mut FieldR1csBuilder,
        native: &noid_core::sumcheck::prove::RoundPolynomial<Block128>,
        expected_coeffs: usize,
    ) -> Self {
        assert_eq!(
            native.coeffs.len(),
            expected_coeffs,
            "round polynomial off the frozen trace shape"
        );
        Self {
            coeffs: alloc_blocks(b, &native.coeffs),
        }
    }

    /// `p(0) + p(1)` — in char 2 this is `Σ_{i≥1} coeffs[i]`, linear (free).
    pub fn sum_at_0_plus_1(&self) -> LinExpr {
        let mut acc = LinExpr::zero();
        for c in self.coeffs.iter().skip(1) {
            acc = acc.add(c);
        }
        acc
    }

    /// Horner evaluation at an expression point — the trace twin of
    /// `RoundPolynomial::evaluate` (`degree` multiplications).
    pub fn evaluate(&self, b: &mut FieldR1csBuilder, x: &LinExpr) -> LinExpr {
        b.horner_eval(&self.coeffs, x)
    }

    /// Absorb the coefficients in native order (`for &c in &poly.coeffs`).
    pub fn absorb_coeffs(&self, b: &mut FieldR1csBuilder, ch: &mut RawChannelTrace) {
        for c in &self.coeffs {
            ch.absorb(b, c);
        }
    }
}

/// Reduced claim `(point, value)` as expressions — the trace twin of
/// `noid_gkr::batch_eval::BatchEvalReduction`.
#[derive(Clone)]
pub struct BatchEvalReductionTrace {
    pub point: Vec<LinExpr>,
    pub value: LinExpr,
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;

    /// Evaluate an expression against a builder's current witness and map
    /// back to the tower basis for comparison with native values.
    pub fn tower_value(b: &FieldR1csBuilder, e: &LinExpr) -> Block128 {
        use noid_core::hardware::flat_to_tower_u128;
        let f = e.eval(b.values());
        let flat = (f.lo as u128) | ((f.hi as u128) << 64);
        Block128(flat_to_tower_u128(flat))
    }

    pub fn assert_expr_is(b: &FieldR1csBuilder, e: &LinExpr, native: Block128, what: &str) {
        assert_eq!(tower_value(b, e), native, "{what} diverged from native");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use noid_core::mle::eq::{eq_ind, eq_ind_partial_eval};
    use noid_core::TowerField;

    fn rand_blocks(seed: u64, n: usize) -> Vec<Block128> {
        let mut s = seed as u128;
        (0..n)
            .map(|_| {
                s = s
                    .wrapping_mul(0x9E37_79B9_7F4A_7C15)
                    .wrapping_add(0xDEAD_BEEF);
                Block128::from(s)
            })
            .collect()
    }

    #[test]
    fn eq_partial_eval_trace_matches_native() {
        for n in [1usize, 3, 6] {
            let point = rand_blocks(7 + n as u64, n);
            let mut b = FieldR1csBuilder::new();
            let exprs = alloc_blocks(&mut b, &point);
            let tensor = eq_ind_partial_eval_trace(&mut b, &exprs);
            let native = eq_ind_partial_eval::<Block128>(&point);
            assert_eq!(tensor.len(), native.len());
            for (e, nv) in tensor.iter().zip(native.iter()) {
                test_support::assert_expr_is(&b, e, *nv, "eq tensor entry");
            }
            let (r1cs, z) = b.build();
            assert!(r1cs.satisfies(&z));
        }
    }

    #[test]
    fn boolean_point_eq_cache_matches_native() {
        let n = 9usize;
        let r = rand_blocks(99, n);
        let mut b = FieldR1csBuilder::new();
        let r_exprs = alloc_blocks(&mut b, &r);
        let mut cache = BooleanPointEqCache::new(&r_exprs);
        for index in [0usize, 1, 2, 5, 63, 200, 511, 300, 5, 200] {
            let e = cache.eq_at_index(&mut b, index);
            let point: Vec<Block128> = (0..n)
                .map(|bit| {
                    if (index >> bit) & 1 == 1 {
                        Block128::ONE
                    } else {
                        Block128::ZERO
                    }
                })
                .collect();
            let native = eq_ind(&point, &r);
            test_support::assert_expr_is(&b, &e, native, "boolean eq");
        }
        let (r1cs, z) = b.build();
        assert!(r1cs.satisfies(&z));
    }

    #[test]
    fn evaluate_slice_trace_matches_native() {
        let n = 5usize;
        let tab = rand_blocks(3, 1 << n);
        let point = rand_blocks(4, n);
        let mut b = FieldR1csBuilder::new();
        let tab_e = alloc_blocks(&mut b, &tab);
        let point_e = alloc_blocks(&mut b, &point);
        let got = evaluate_slice_trace(&mut b, &tab_e, &point_e);
        let native = noid_core::mle::evaluate::evaluate_slice(&tab, &point);
        test_support::assert_expr_is(&b, &got, native, "evaluate_slice");
        let (r1cs, z) = b.build();
        assert!(r1cs.satisfies(&z));
    }
}
