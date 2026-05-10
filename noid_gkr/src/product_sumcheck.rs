// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Stage G1b.α — product sumcheck primitive.
//!
//! Reduces a claim `v = Σ_x eq(r, x) · A(x) · B(x)` over the boolean
//! hypercube `{0,1}^n` to two smaller claims `a = A(r')` and
//! `b = B(r')` at a fresh point `r'` of the same length. `r'` is the
//! vector of per-round Fiat-Shamir challenges, so the verifier
//! recomputes it from the transcript.
//!
//! Protocol shape (standard Thaler / Libra product sumcheck):
//!
//! ```text
//! round i:   prover emits p_i(X) = deg-3 univariate as 4 evaluations
//!              (e0, e1, e2, e3) at X = 0, 1, 2, 3 (field elements).
//!            transcript absorbs the four coefficients.
//!            challenge r_i = channel.squeeze()
//!            update running claim to p_i(r_i)
//!            fold eq, A, B tables by r_i (highest-variable-first)
//!
//! after n rounds:
//!            prover sends (a, b) = (A(r'), B(r')).
//!            verifier accepts iff final_claim == eq(r, r') · a · b
//! ```
//!
//! `r'` is returned in **variable order** (`r'[k]` is the final
//! binding of variable `k`). Because we fold highest-var-first, the
//! variable-order point is the push-order challenge vector reversed.
//!
//! The transcript is whatever `FiatShamir<Block128>` implementer the
//! caller supplies; the inner STARK uses `Poseidon2bChannel`.

use noid_core::mle::eq::{eq_ind, eq_ind_partial_eval};
use noid_core::transcript::FiatShamir;
use noid_core::{Block128, TowerField};

/// Round polynomial stored as its evaluations at `X = 0, 1, 2, 3`.
///
/// Sumcheck telescope check uses `evals[0] + evals[1] == running_claim`.
/// Lagrange evaluation at a challenge `r` uses the explicit
/// interpolant below.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoundEvals {
    pub evals: [Block128; 4],
}

impl RoundEvals {
    #[inline]
    pub fn sum_at_0_plus_1(&self) -> Block128 {
        self.evals[0] + self.evals[1]
    }

    /// Lagrange-interpolate at `r` from evaluations at `{0,1,2,3}`.
    pub fn evaluate(&self, r: Block128) -> Block128 {
        lagrange_at_0_1_2_3(&self.evals, r)
    }
}

/// Lagrange evaluation: given `e_k = p(k)` for `k ∈ {0,1,2,3}`,
/// return `p(r)`. Uses the standard Lagrange basis in GF(2^128).
#[inline]
pub fn lagrange_at_0_1_2_3(evals: &[Block128; 4], r: Block128) -> Block128 {
    let f0 = Block128::from(0u128);
    let f1 = Block128::from(1u128);
    let f2 = Block128::from(2u128);
    let f3 = Block128::from(3u128);

    // L_k(r) = Π_{j≠k} (r + x_j) / (x_k + x_j) — char-2 subtraction == addition.
    let denom = |k: usize| -> Block128 {
        let xk = Block128::from(k as u128);
        let mut d = Block128::ONE;
        for j in 0..4 {
            if j == k {
                continue;
            }
            d *= xk + Block128::from(j as u128);
        }
        d
    };
    let numer = |k: usize| -> Block128 {
        let mut p = Block128::ONE;
        for j in 0..4 {
            if j == k {
                continue;
            }
            p *= r + Block128::from(j as u128);
        }
        p
    };

    let _ = (f0, f1, f2, f3); // silence unused; used implicitly
    let mut acc = Block128::ZERO;
    for k in 0..4 {
        acc += evals[k] * numer(k) * denom(k).invert();
    }
    acc
}

/// Full product-sumcheck proof: the per-round evaluations plus the
/// final reduced pair `(a, b)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductProof {
    pub rounds: Vec<RoundEvals>,
    pub a_final: Block128,
    pub b_final: Block128,
}

impl ProductProof {
    /// Raw field-element accounting of this proof's wire size.
    /// `rounds.len() * 4` block-128s for the round polys plus the two
    /// finals. Matches the accounting convention in
    /// `bench_prover::estimate_stark_proof_bytes` (no serialisation
    /// framing, just 16 bytes per `Block128`).
    pub fn byte_len(&self) -> usize {
        self.rounds.len() * 4 * 16 + 2 * 16
    }
}

/// Honest prover.
///
/// `a`, `b`: MLE tables of length `2^n`, `n = r.len()`.
/// `r`: claim point.
/// `v`: claimed value `Σ_x eq(r, x) · A(x) · B(x)`.
/// `channel`: Fiat-Shamir channel seeded and synchronized by caller.
///
/// Returns the proof and the challenge vector `r'` in the same order
/// as the sumcheck rounds (round 0 opens the highest-indexed
/// variable — matching `noid_core::mle::fold::fold_highest_var_inplace`).
pub fn prove_product<T: FiatShamir<Block128>>(
    a: &[Block128],
    b: &[Block128],
    r: &[Block128],
    v: Block128,
    channel: &mut T,
) -> (ProductProof, Vec<Block128>) {
    let n = r.len();
    assert_eq!(a.len(), 1 << n);
    assert_eq!(b.len(), 1 << n);

    // Sanity (debug only): claim matches witness.
    debug_assert_eq!(compute_product_claim(a, b, r), v, "claim mismatches witness");

    let mut eq_tbl = eq_ind_partial_eval(r);
    let mut a_tbl = a.to_vec();
    let mut b_tbl = b.to_vec();

    let mut rounds = Vec::with_capacity(n);
    let mut challenges = Vec::with_capacity(n);

    let mut claim = v;
    let _ = claim;
    for _round in 0..n {
        let half = a_tbl.len() / 2;

        // Compute p(0), p(1), p(2), p(3) where
        // p(X) = Σ_x ((1-X)eq_lo[x] + X*eq_hi[x])
        //          * ((1-X)A_lo[x] + X*A_hi[x])
        //          * ((1-X)B_lo[x] + X*B_hi[x])
        // over the remaining `half` index positions. In char 2:
        //   t(k) = t_lo + k * (t_lo + t_hi) for each of eq, A, B.
        let evals = eval_round_at_0_1_2_3(&eq_tbl, &a_tbl, &b_tbl, half);
        let re = RoundEvals { evals };

        // Telescope check on prover side (debug): e0 + e1 == claim.
        debug_assert_eq!(re.sum_at_0_plus_1(), claim);

        // Absorb the 4 evals into transcript, squeeze challenge.
        for e in &re.evals {
            channel.absorb(*e);
        }
        let r_i = channel.squeeze();

        // Advance claim and fold all three tables.
        claim = re.evaluate(r_i);
        fold_inplace(&mut eq_tbl, r_i);
        fold_inplace(&mut a_tbl, r_i);
        fold_inplace(&mut b_tbl, r_i);

        rounds.push(re);
        challenges.push(r_i);
    }

    debug_assert_eq!(a_tbl.len(), 1);
    debug_assert_eq!(b_tbl.len(), 1);
    debug_assert_eq!(eq_tbl.len(), 1);
    debug_assert_eq!(claim, eq_tbl[0] * a_tbl[0] * b_tbl[0]);

    // Challenges were pushed in highest-var-first order; the caller
    // expects `r'` in variable order (same indexing as `r`).
    challenges.reverse();

    let proof = ProductProof {
        rounds,
        a_final: a_tbl[0],
        b_final: b_tbl[0],
    };
    (proof, challenges)
}

/// Verifier.
///
/// Returns `Some(r')` — the challenge vector — on success, `None` on
/// any failure. On success the caller may rely on:
///
/// - `proof.a_final == A(r')`
/// - `proof.b_final == B(r')`
///
/// where `r'` is the returned challenge vector, **provided** the
/// caller separately verifies the two final claims against
/// committed-to MLEs (or recursively against deeper sumchecks).
pub fn verify_product<T: FiatShamir<Block128>>(
    proof: &ProductProof,
    r: &[Block128],
    v: Block128,
    channel: &mut T,
) -> Option<Vec<Block128>> {
    let n = r.len();
    if proof.rounds.len() != n {
        return None;
    }

    let mut claim = v;
    let mut challenges = Vec::with_capacity(n);

    for re in &proof.rounds {
        if re.sum_at_0_plus_1() != claim {
            return None;
        }
        for e in &re.evals {
            channel.absorb(*e);
        }
        let r_i = channel.squeeze();
        claim = re.evaluate(r_i);
        challenges.push(r_i);
    }

    // Challenges were pushed in highest-var-first order; put them
    // into variable order (matching `r`) for the eq check and return.
    challenges.reverse();

    // Final identity: claim == eq(r, r') * a * b.
    let eq_rr = eq_ind(r, &challenges);
    let rhs = eq_rr * proof.a_final * proof.b_final;
    if claim != rhs {
        return None;
    }

    Some(challenges)
}

/// Compute `Σ_x eq(r, x) · A(x) · B(x)` — the honest claim from a
/// witness. Used by tests and by the prover's debug_assert.
pub fn compute_product_claim(a: &[Block128], b: &[Block128], r: &[Block128]) -> Block128 {
    let eq = eq_ind_partial_eval(r);
    debug_assert_eq!(eq.len(), a.len());
    debug_assert_eq!(eq.len(), b.len());
    let mut acc = Block128::ZERO;
    for i in 0..a.len() {
        acc += eq[i] * a[i] * b[i];
    }
    acc
}

/// Build the four eval points `(p(0), p(1), p(2), p(3))` for one
/// round of the product sumcheck. `half = current_len / 2`.
///
/// Per-entry: `t(k) = t_lo + k * (t_lo + t_hi)` (char 2).
fn eval_round_at_0_1_2_3(
    eq: &[Block128],
    a: &[Block128],
    b: &[Block128],
    half: usize,
) -> [Block128; 4] {
    let f0 = Block128::from(0u128);
    let f1 = Block128::from(1u128);
    let f2 = Block128::from(2u128);
    let f3 = Block128::from(3u128);

    let mut e0 = Block128::ZERO;
    let mut e1 = Block128::ZERO;
    let mut e2 = Block128::ZERO;
    let mut e3 = Block128::ZERO;

    for j in 0..half {
        let eq_lo = eq[j];
        let eq_hi = eq[j + half];
        let a_lo = a[j];
        let a_hi = a[j + half];
        let b_lo = b[j];
        let b_hi = b[j + half];

        // Differences
        let d_eq = eq_lo + eq_hi;
        let d_a = a_lo + a_hi;
        let d_b = b_lo + b_hi;

        // p(0) = eq_lo * a_lo * b_lo
        e0 += eq_lo * a_lo * b_lo;

        // p(1) = eq_hi * a_hi * b_hi
        e1 += eq_hi * a_hi * b_hi;

        // Helper to evaluate one entry at X = k.
        let eval_at = |k: Block128| -> Block128 {
            let eq_k = eq_lo + k * d_eq;
            let a_k = a_lo + k * d_a;
            let b_k = b_lo + k * d_b;
            eq_k * a_k * b_k
        };

        e2 += eval_at(f2);
        e3 += eval_at(f3);

        // keep f0/f1 referenced for clarity on what indexing means
        let _ = (f0, f1);
    }

    [e0, e1, e2, e3]
}

/// Fold the highest-indexed variable in-place by challenge `r`.
/// Matches `fold_highest_var_inplace` in `noid_core::mle::fold` but
/// kept local to avoid pulling the whole fold module surface in.
fn fold_inplace(v: &mut Vec<Block128>, r: Block128) {
    let half = v.len() / 2;
    for j in 0..half {
        let lo = v[j];
        let hi = v[j + half];
        v[j] = lo + r * (lo + hi);
    }
    v.truncate(half);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lagrange_roundtrip_through_0_1_2_3() {
        // Fix a known deg-3 polynomial p(X) = 7 + 3X + 2X^2 + X^3 and
        // verify Lagrange reconstruction at several points.
        let c0 = Block128::from(7u128);
        let c1 = Block128::from(3u128);
        let c2 = Block128::from(2u128);
        let c3 = Block128::from(1u128);
        let eval = |x: Block128| -> Block128 { c0 + c1 * x + c2 * x * x + c3 * x * x * x };

        let evals = [
            eval(Block128::from(0u128)),
            eval(Block128::from(1u128)),
            eval(Block128::from(2u128)),
            eval(Block128::from(3u128)),
        ];

        for r_i in [5u128, 17, 0x1234, u128::MAX] {
            let r = Block128::from(r_i);
            let got = lagrange_at_0_1_2_3(&evals, r);
            let want = eval(r);
            assert_eq!(got, want, "lagrange mismatch at r={r_i}");
        }
    }
}
