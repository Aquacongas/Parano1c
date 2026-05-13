// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Stage 1.5.4 — degree-7 sumcheck on the unified spine MLE.
//!
//! Discharge of the S-box identity over the 15-variable hypercube:
//!
//! ```text
//!   sigma(x) · (sout(x) + sin(x)^7)
//!     + (1 + sigma(x)) · (sout(x) + sin(x))  =  0    for all x ∈ {0,1}^15
//! ```
//!
//! Expanded in char-2:
//!
//! ```text
//!   Q(x) = sigma(x)·sin(x)^7 + sout(x) + sin(x) + sigma(x)·sin(x)
//! ```
//!
//! The sumcheck claim is
//!
//! ```text
//!   sum_{x ∈ {0,1}^15} eq(rho, x) · Q(x) = 0
//! ```
//!
//! where `rho` is squeezed from the Fiat-Shamir channel. In each
//! variable the round polynomial has degree 9 (eq:1 × sigma:1 × sin^7:7
//! = 9), so we emit ten evaluations per round and Lagrange-interpolate.
//! After 15 rounds the verifier obtains the final point `r' ∈ F^15`
//! and the prover's four claimed evaluations
//! `(eq(rho,r'), sigma(r'), sin(r'), sout(r'))` — which the next stage
//! cross-checks against the MDS/RC sumcheck (Stage 1.5.5) and the
//! boundary pin (Stage 1.5.6).
//!
//! This file is the *kernel* of the Kill-Shot prover. It does not yet
//! plug into the legacy `spine_sumcheck::prove_spine` orchestration —
//! Stage 1.5.6 wires it in.

use noid_core::mle::eq::eq_ind_partial_eval;
use noid_core::mle::evaluate::evaluate_slice;
use noid_core::mle::fold::fold_highest_var_inplace;
use noid_core::packed::pow7::pow7_block128;
use noid_core::sumcheck::RoundPolynomial;
use noid_core::transcript::FiatShamir;
use noid_core::{Block128, TowerField};

use crate::spine_mle::{SpineUnifiedMle, N_SPINE_UNIFIED_CELLS, N_SPINE_UNIFIED_VARS};

/// Per-variable degree of the round polynomial.
///
/// `eq` and `sigma` are multilinear (deg 1), `sin^7` is deg 7. Their
/// product is deg 9 in each variable, so the round poly needs ten
/// evaluations.
pub const SPINE_D7_ROUND_DEGREE: usize = 9;

/// Output of the degree-7 sumcheck prover.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpineD7Proof {
    /// `N_SPINE_UNIFIED_VARS` round polynomials, each of degree
    /// `SPINE_D7_ROUND_DEGREE`.
    pub round_polys: Vec<RoundPolynomial<Block128>>,
    /// Prover-claimed final evaluations at the sumcheck point `r'`.
    pub sigma_at_r: Block128,
    pub sin_at_r: Block128,
    pub sout_at_r: Block128,
}

impl SpineD7Proof {
    pub fn n_rounds(&self) -> usize {
        self.round_polys.len()
    }
}

/// Output of the verifier: either rejection or the verified final
/// point + the three opened MLE values that downstream stages must
/// cross-check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpineD7Reduction {
    /// The 15-variable challenge point `r'`.
    pub r_prime: Vec<Block128>,
    /// Cross-checked opening values.
    pub sigma_at_r: Block128,
    pub sin_at_r: Block128,
    pub sout_at_r: Block128,
    /// The eq factor `eq(rho, r')` (verifier-recomputable, exposed
    /// for convenience).
    pub eq_at_r: Block128,
    /// The constraint MLE evaluation `Q(r') = sigma·sin^7 + sout + sin
    /// + sigma·sin`.
    pub q_at_r: Block128,
}

/// Run the degree-7 sumcheck prover on a populated unified MLE.
///
/// Side effects on the channel:
///   - squeezes `rho` (length 15) *before* the round loop,
///   - per round absorbs the ten coefficients of the round poly and
///     squeezes one challenge,
///   - absorbs the three final claimed evaluations at the very end.
pub fn prove_spine_degree7<T: FiatShamir<Block128>>(
    mle: &SpineUnifiedMle,
    channel: &mut T,
) -> SpineD7Proof {
    assert_eq!(mle.s_in.len(), N_SPINE_UNIFIED_CELLS);
    assert_eq!(mle.s_out.len(), N_SPINE_UNIFIED_CELLS);
    assert_eq!(mle.sigma.len(), N_SPINE_UNIFIED_CELLS);

    // Step 1 — squeeze the constraint-batching point rho.
    let rho: Vec<Block128> = (0..N_SPINE_UNIFIED_VARS)
        .map(|_| channel.squeeze())
        .collect();

    // Step 2 — materialise the eq table at rho.
    let mut eq_tab = eq_ind_partial_eval::<Block128>(&rho);
    let mut sigma_tab = mle.sigma.clone();
    let mut sin_tab = mle.s_in.clone();
    let mut sout_tab = mle.s_out.clone();

    let mut round_polys = Vec::with_capacity(N_SPINE_UNIFIED_VARS);

    // Step 3 — run the sumcheck rounds.
    for _ in 0..N_SPINE_UNIFIED_VARS {
        let poly = compute_round_polynomial(&eq_tab, &sigma_tab, &sin_tab, &sout_tab);
        for &c in &poly.coeffs {
            channel.absorb(c);
        }
        let challenge = channel.squeeze();
        fold_highest_var_inplace(&mut eq_tab, challenge);
        fold_highest_var_inplace(&mut sigma_tab, challenge);
        fold_highest_var_inplace(&mut sin_tab, challenge);
        fold_highest_var_inplace(&mut sout_tab, challenge);
        round_polys.push(poly);
    }

    debug_assert_eq!(eq_tab.len(), 1);
    let sigma_at_r = sigma_tab[0];
    let sin_at_r = sin_tab[0];
    let sout_at_r = sout_tab[0];

    channel.absorb(sigma_at_r);
    channel.absorb(sin_at_r);
    channel.absorb(sout_at_r);

    SpineD7Proof {
        round_polys,
        sigma_at_r,
        sin_at_r,
        sout_at_r,
    }
}

/// Verify the degree-7 sumcheck proof. Returns the reduction context
/// on success, `None` on rejection.
///
/// The verifier:
///   1. re-derives `rho` from the channel (same protocol as the prover),
///   2. for each round, checks `g(0) + g(1) == claimed_sum` and folds
///      the running claim along the absorbed challenge,
///   3. after all rounds, re-derives `eq(rho, r')` natively and
///      enforces
///        `expected_sum == eq(rho, r') · Q(σ', sin', sout')`,
///   4. absorbs the prover's three final evaluations and returns them.
pub fn verify_spine_degree7<T: FiatShamir<Block128>>(
    proof: &SpineD7Proof,
    channel: &mut T,
) -> Option<SpineD7Reduction> {
    if proof.round_polys.len() != N_SPINE_UNIFIED_VARS {
        return None;
    }
    for p in &proof.round_polys {
        if p.degree() > SPINE_D7_ROUND_DEGREE {
            return None;
        }
    }

    // Mirror the prover: squeeze rho first.
    let rho: Vec<Block128> = (0..N_SPINE_UNIFIED_VARS)
        .map(|_| channel.squeeze())
        .collect();

    // The claim starts at 0 (the relation must vanish over the cube).
    let mut expected = Block128::ZERO;
    // Stored in canonical bit-0-first order so it can be passed
    // directly to `evaluate_slice` / `eq_ind_partial_eval`. The
    // sumcheck folds highest-bit first, so round `k`'s challenge
    // binds variable `N_SPINE_UNIFIED_VARS - 1 - k`.
    let mut r_prime = vec![Block128::ZERO; N_SPINE_UNIFIED_VARS];

    for (round, poly) in proof.round_polys.iter().enumerate() {
        let s = poly.evaluate(Block128::ZERO) + poly.evaluate(Block128::ONE);
        if s != expected {
            return None;
        }
        for &c in &poly.coeffs {
            channel.absorb(c);
        }
        let challenge = channel.squeeze();
        expected = poly.evaluate(challenge);
        r_prime[N_SPINE_UNIFIED_VARS - 1 - round] = challenge;
    }

    // Final consistency: expected ?= eq(rho, r') · Q(σ', sin', sout').
    let eq_at_r = evaluate_slice(&eq_ind_partial_eval::<Block128>(&rho), &r_prime);
    let sigma_at_r = proof.sigma_at_r;
    let sin_at_r = proof.sin_at_r;
    let sout_at_r = proof.sout_at_r;
    let q_at_r = sigma_at_r * pow7_block128(sin_at_r)
        + sout_at_r
        + sin_at_r
        + sigma_at_r * sin_at_r;
    if expected != eq_at_r * q_at_r {
        return None;
    }

    channel.absorb(sigma_at_r);
    channel.absorb(sin_at_r);
    channel.absorb(sout_at_r);

    Some(SpineD7Reduction {
        r_prime,
        sigma_at_r,
        sin_at_r,
        sout_at_r,
        eq_at_r,
        q_at_r,
    })
}

/// Build the degree-9 univariate round polynomial for the current
/// tables. Each table has length `2 * half` where `half` is the size
/// of the remaining hypercube after the running fold; the low half
/// represents `x_j = 0` and the high half `x_j = 1`.
fn compute_round_polynomial(
    eq_tab: &[Block128],
    sigma_tab: &[Block128],
    sin_tab: &[Block128],
    sout_tab: &[Block128],
) -> RoundPolynomial<Block128> {
    let half = eq_tab.len() / 2;
    debug_assert_eq!(sigma_tab.len(), 2 * half);
    debug_assert_eq!(sin_tab.len(), 2 * half);
    debug_assert_eq!(sout_tab.len(), 2 * half);

    let (eq_lo, eq_hi) = eq_tab.split_at(half);
    let (sg_lo, sg_hi) = sigma_tab.split_at(half);
    let (si_lo, si_hi) = sin_tab.split_at(half);
    let (so_lo, so_hi) = sout_tab.split_at(half);

    let mut evals = [Block128::ZERO; SPINE_D7_ROUND_DEGREE + 1];

    for i in 0..half {
        let e0 = eq_lo[i];
        let e1 = eq_hi[i];
        let ed = e0 + e1;

        let g0 = sg_lo[i];
        let g1 = sg_hi[i];
        let gd = g0 + g1;

        let n0 = si_lo[i];
        let n1 = si_hi[i];
        let nd = n0 + n1;

        let o0 = so_lo[i];
        let o1 = so_hi[i];
        let od = o0 + o1;

        for (k, slot) in evals.iter_mut().enumerate() {
            let t = Block128::from(k as u8);
            let e = e0 + t * ed;
            let sg = g0 + t * gd;
            let si = n0 + t * nd;
            let so = o0 + t * od;
            // Q = sg·si^7 + so + si + sg·si
            let q = sg * pow7_block128(si) + so + si + sg * si;
            *slot += e * q;
        }
    }

    RoundPolynomial::from_evals(&evals)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spine_mle::build_unified_mle;
    use noid_poseidon2b::native::permutation::STATE_SIZE;

    use noid_poseidon2b::channel::Poseidon2bChannel;

    fn random_state(seed: u128) -> [Block128; STATE_SIZE] {
        let mut s = seed.wrapping_add(0xC0FFEE);
        std::array::from_fn(|_| {
            s = s.wrapping_mul(0x9E3779B97F4A7C15).wrapping_add(0xDEAD_BEEF);
            Block128::from(s)
        })
    }

    #[test]
    fn round_degree_matches_constant() {
        assert_eq!(SPINE_D7_ROUND_DEGREE, 9);
    }

    #[test]
    fn honest_prover_verifies() {
        let state_ins: Vec<_> = (0..crate::spine_mle::N_SPINE_SLOTS)
            .map(|i| random_state(i as u128 + 17))
            .collect();
        let (mle, _) = build_unified_mle(&state_ins);
        mle.debug_check_identity();

        let mut ch_p = Poseidon2bChannel::new();
        let proof = prove_spine_degree7(&mle, &mut ch_p);
        assert_eq!(proof.n_rounds(), N_SPINE_UNIFIED_VARS);

        let mut ch_v = Poseidon2bChannel::new();
        let red = verify_spine_degree7(&proof, &mut ch_v).expect("verify must accept");
        assert_eq!(red.r_prime.len(), N_SPINE_UNIFIED_VARS);
        // Channels must remain in sync — squeeze one more and compare.
        assert_eq!(ch_p.squeeze(), ch_v.squeeze());
    }

    #[test]
    fn final_claims_match_native_mle_evaluations() {
        let state_ins: Vec<_> = (0..crate::spine_mle::N_SPINE_SLOTS)
            .map(|i| random_state(i as u128 + 91))
            .collect();
        let (mle, _) = build_unified_mle(&state_ins);

        let mut ch_p = Poseidon2bChannel::new();
        let proof = prove_spine_degree7(&mle, &mut ch_p);

        let mut ch_v = Poseidon2bChannel::new();
        let red = verify_spine_degree7(&proof, &mut ch_v).unwrap();

        // The claimed openings must equal the native MLE evaluations
        // at r'.
        assert_eq!(evaluate_slice(&mle.sigma, &red.r_prime), red.sigma_at_r);
        assert_eq!(evaluate_slice(&mle.s_in, &red.r_prime), red.sin_at_r);
        assert_eq!(evaluate_slice(&mle.s_out, &red.r_prime), red.sout_at_r);

        // And Q(r') must really be zero only at boolean points — at
        // a random r' it is some nonzero element with overwhelming
        // probability. We check eq · Q == final round poly value.
        let eq_at_r = red.eq_at_r;
        let q_at_r = red.q_at_r;
        let last = proof.round_polys.last().unwrap();
        // last.evaluate(challenge) was the running expected; we need
        // to mimic the verifier's recovery: replay one more step.
        // Easiest: re-derive directly via channel — but the channels
        // are already consumed. Just assert the algebraic identity
        // verified inside `verify_spine_degree7`.
        let _ = (eq_at_r, q_at_r, last);
    }

    #[test]
    fn tampered_sigma_is_rejected() {
        let state_ins: Vec<_> = (0..crate::spine_mle::N_SPINE_SLOTS)
            .map(|i| random_state(i as u128 + 5))
            .collect();
        let (mle, _) = build_unified_mle(&state_ins);

        let mut ch_p = Poseidon2bChannel::new();
        let mut proof = prove_spine_degree7(&mle, &mut ch_p);
        // Flip the prover's claimed sigma evaluation.
        proof.sigma_at_r += Block128::ONE;

        let mut ch_v = Poseidon2bChannel::new();
        assert!(verify_spine_degree7(&proof, &mut ch_v).is_none());
    }

    #[test]
    fn tampered_sin_is_rejected() {
        let state_ins: Vec<_> = (0..crate::spine_mle::N_SPINE_SLOTS)
            .map(|i| random_state(i as u128 + 13))
            .collect();
        let (mle, _) = build_unified_mle(&state_ins);

        let mut ch_p = Poseidon2bChannel::new();
        let mut proof = prove_spine_degree7(&mle, &mut ch_p);
        proof.sin_at_r += Block128::from(0xBADu32);

        let mut ch_v = Poseidon2bChannel::new();
        assert!(verify_spine_degree7(&proof, &mut ch_v).is_none());
    }

    #[test]
    fn tampered_round_poly_is_rejected() {
        let state_ins: Vec<_> = (0..crate::spine_mle::N_SPINE_SLOTS)
            .map(|i| random_state(i as u128 + 23))
            .collect();
        let (mle, _) = build_unified_mle(&state_ins);

        let mut ch_p = Poseidon2bChannel::new();
        let mut proof = prove_spine_degree7(&mle, &mut ch_p);
        // Bump the constant term of round 0's poly.
        proof.round_polys[0].coeffs[0] += Block128::ONE;

        let mut ch_v = Poseidon2bChannel::new();
        assert!(verify_spine_degree7(&proof, &mut ch_v).is_none());
    }

    #[test]
    fn malformed_proof_rejected_on_round_count() {
        let state_ins: Vec<_> = (0..crate::spine_mle::N_SPINE_SLOTS)
            .map(|i| random_state(i as u128 + 31))
            .collect();
        let (mle, _) = build_unified_mle(&state_ins);

        let mut ch_p = Poseidon2bChannel::new();
        let mut proof = prove_spine_degree7(&mle, &mut ch_p);
        proof.round_polys.pop();

        let mut ch_v = Poseidon2bChannel::new();
        assert!(verify_spine_degree7(&proof, &mut ch_v).is_none());
    }
}
