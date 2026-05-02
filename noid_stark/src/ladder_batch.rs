// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Stage 3b-0.4 Candidate A — batched ladder-FRI opening via a
//! degree-2 multilinear product sumcheck.
//!
//! See CRYPTO.md §12a for the protocol and soundness argument. In
//! short: given the committed base column `C: {0,1}^n → F` and the
//! ladder partials `v_k = C(P_k)` for `k = 0, …, n`, the prover
//! proves
//!
//! ```text
//!   Σ_{x ∈ {0,1}^n}  C(x) · W(x)  =  Σ_{k=0}^{n} γ^k · v_k   (= T)
//! ```
//!
//! where `W(x) = Σ_k γ^k · eq(P_k, x)` and `γ` is Fiat–Shamir from
//! the ladder-batch sub-channel. The sumcheck collapses into a
//! single claim `C(r') · W(r')` at a random `r' ∈ F^n`; one FRI
//! opening of `C` at `r'` closes the statement. The ladder partials
//! `v_k` are kept in the proof because the verifier still needs them
//! to reconstruct `C'(r)` via `crate::vshift::reconstruct_shifted_opening`.

use noid_core::{Block128, TowerField};

use crate::RoundPoly;

/// Number of evaluations per round polynomial for the degree-2
/// product sumcheck (evaluations at `X = 0, 1, 2`).
pub const PRODUCT_ROUND_POINTS: usize = 3;

/// Compute the ladder-batch target
/// `T = Σ_{k=0}^{n} γ^k · v_k`.
pub fn target_claim(gamma: Block128, partials: &[Block128]) -> Block128 {
    let mut acc = Block128::ZERO;
    let mut gk = Block128::ONE;
    for &v in partials {
        acc += gk * v;
        gk *= gamma;
    }
    acc
}

/// Evaluate `W(r') = Σ_k γ^k · eq(P_k, r')` in closed form. `points`
/// must be `ladder_points(r)` (same LSB-first convention as `r'`).
pub fn weight_at(gamma: Block128, points: &[Vec<Block128>], r_prime: &[Block128]) -> Block128 {
    let mut acc = Block128::ZERO;
    let mut gk = Block128::ONE;
    for pk in points {
        acc += gk * noid_core::mle::eq::eq_ind(pk, r_prime);
        gk *= gamma;
    }
    acc
}

/// Build the weight table `W(x)` for all `x ∈ {0,1}^n` as a length
/// `2^n` vector in the crate's LSB-first flat-index convention
/// (matches `padded_columns`). `points` must be in ladder order
/// `[P_0, …, P_n]` and every point must have length `n`.
pub fn build_weight_table(gamma: Block128, points: &[Vec<Block128>], n: usize) -> Vec<Block128> {
    let len = 1usize << n;
    let mut w = vec![Block128::ZERO; len];
    let mut gk = Block128::ONE;
    for pk in points {
        debug_assert_eq!(pk.len(), n);
        let eq_table = noid_core::mle::eq::eq_ind_partial_eval(pk);
        debug_assert_eq!(eq_table.len(), len);
        for i in 0..len {
            w[i] += gk * eq_table[i];
        }
        gk *= gamma;
    }
    w
}

/// Run the degree-2 product sumcheck in-place. Given initial tables
/// `c` and `w` of length `2^n`, returns the `n` round polynomials and
/// the final challenge vector `challenges`. The first challenge binds
/// the highest variable (upper half), matching the zero-check
/// convention in `crate::prove_zero_check`.
///
/// After this routine returns, the caller forms
/// `r_prime = challenges.iter().rev().collect()` to use as the MLE
/// opening point of `C` (LSB-first).
pub fn prove_product_sumcheck(
    mut c: Vec<Block128>,
    mut w: Vec<Block128>,
    target: Block128,
    channel: &mut noid_fri::Channel,
) -> (Vec<RoundPoly>, Vec<Block128>) {
    let n = c.len().trailing_zeros() as usize;
    debug_assert_eq!(c.len(), w.len());
    debug_assert_eq!(c.len(), 1usize << n);

    let mut rounds: Vec<RoundPoly> = Vec::with_capacity(n);
    let mut challenges: Vec<Block128> = Vec::with_capacity(n);
    let mut claim = target;

    for _ in 0..n {
        // Degree-2 round polynomial
        //   p(s) = Σ_{j < half} ((c[j] + s*(c[j+half]+c[j]))
        //                      · (w[j] + s*(w[j+half]+w[j])))
        // sent as evaluations at s ∈ {0, 1, 2}. We exploit s=0 and
        // s=1 directly and only pay the general branch at s=2.
        let half = c.len() / 2;
        let mut p0 = Block128::ZERO;
        let mut p1 = Block128::ZERO;
        let mut p2 = Block128::ZERO;
        let two = Block128::from(2u8);
        for j in 0..half {
            let c0 = c[j];
            let c1 = c[j + half];
            let w0 = w[j];
            let w1 = w[j + half];
            p0 += c0 * w0;
            p1 += c1 * w1;
            // s = 2 = Block128::from(2u8). Char 2 so 1+s = 3, but
            // we use the generic formula for clarity.
            let cs = c0 + two * (c1 + c0);
            let ws = w0 + two * (w1 + w0);
            p2 += cs * ws;
        }

        // Sanity (debug only): p(0) + p(1) must match the running claim.
        debug_assert_eq!(p0 + p1, claim, "product sumcheck consistency failure");

        let rp = vec![p0, p1, p2];
        channel.observe_field_elems(&rp);
        let r = channel.get_random_point();

        // Fold both tables at r on the highest variable.
        let mut c_next = Vec::with_capacity(half);
        let mut w_next = Vec::with_capacity(half);
        for j in 0..half {
            c_next.push(c[j] + r * (c[j + half] + c[j]));
            w_next.push(w[j] + r * (w[j + half] + w[j]));
        }
        c = c_next;
        w = w_next;

        claim = crate::lagrange_eval_at_pub(&rp, r);
        rounds.push(rp);
        challenges.push(r);
    }

    (rounds, challenges)
}

/// Verify-side replay of the degree-2 product sumcheck. Consumes the
/// round polynomials one by one and returns the challenge vector plus
/// the terminal claim (which must equal `C(r') · W(r')`).
pub fn verify_product_sumcheck(
    rounds: &[RoundPoly],
    target: Block128,
    channel: &mut noid_fri::Channel,
) -> Result<(Vec<Block128>, Block128), crate::VerifyError> {
    let mut claim = target;
    let mut challenges: Vec<Block128> = Vec::with_capacity(rounds.len());
    for rp in rounds {
        if rp.len() != PRODUCT_ROUND_POINTS {
            return Err(crate::VerifyError::ShapeMismatch);
        }
        if rp[0] + rp[1] != claim {
            return Err(crate::VerifyError::ZeroCheckFailed);
        }
        channel.observe_field_elems(rp);
        let r = channel.get_random_point();
        claim = crate::lagrange_eval_at_pub(rp, r);
        challenges.push(r);
    }
    Ok((challenges, claim))
}

/// Domain tag used to seed the ladder-batch sub-channel for a given
/// shifted-column `slot`. CRYPTO.md §12a.4 pins the exact value
/// `0xFFFE_0000_0000_0000 | slot`; deliberately distinct from the old
/// per-ladder-point tag `0xFFFF_0000_0000_0000 | slot`.
#[inline]
pub fn sub_channel_tag(slot: usize) -> Block128 {
    Block128::from(0xFFFE_0000_0000_0000_u128 | (slot as u128))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vshift::ladder_points;
    use noid_core::Block128;

    fn mle_eval_at(col: &[Block128], r: &[Block128]) -> Block128 {
        let mut buf = col.to_vec();
        for &rk in r.iter().rev() {
            let half = buf.len() / 2;
            for i in 0..half {
                buf[i] = buf[i] + rk * (buf[i + half] + buf[i]);
            }
            buf.truncate(half);
        }
        buf[0]
    }

    fn random_vec(n: usize, seed: u128) -> Vec<Block128> {
        (0..n)
            .map(|i| {
                let x = seed
                    .wrapping_mul(0x9E3779B97F4A7C15)
                    .wrapping_add(i as u128)
                    .wrapping_mul(0xBF58476D1CE4E5B9);
                Block128::from(x | 1)
            })
            .collect()
    }

    #[test]
    fn weight_table_matches_closed_form() {
        let n = 3usize;
        let r = random_vec(n, 0x1111);
        let points = ladder_points(&r);
        let gamma = Block128::from(0xDEAD_BEEF_u128);
        let table = build_weight_table(gamma, &points, n);
        for idx in 0..(1usize << n) {
            let x: Vec<Block128> = (0..n)
                .map(|b| if (idx >> b) & 1 == 1 { Block128::ONE } else { Block128::ZERO })
                .collect();
            let mut expected = Block128::ZERO;
            let mut gk = Block128::ONE;
            for pk in &points {
                expected += gk * noid_core::mle::eq::eq_ind(pk, &x);
                gk *= gamma;
            }
            assert_eq!(table[idx], expected, "weight table mismatch at idx {}", idx);
        }
    }

    #[test]
    fn product_sumcheck_roundtrip() {
        use noid_fri::Channel;

        let n = 4usize;
        let col = random_vec(1usize << n, 0xABCD);
        let r = random_vec(n, 0xF00D);
        let points = ladder_points(&r);
        let partials: Vec<Block128> = points.iter().map(|p| mle_eval_at(&col, p)).collect();

        let mut pch = Channel::new();
        let gamma = pch.get_random_point();
        let target = target_claim(gamma, &partials);
        let w = build_weight_table(gamma, &points, n);
        let (rounds, _challenges) =
            prove_product_sumcheck(col.clone(), w.clone(), target, &mut pch);

        let mut vch = Channel::new();
        let gamma_v = vch.get_random_point();
        assert_eq!(gamma, gamma_v);
        let target_v = target_claim(gamma_v, &partials);
        let (challenges_v, final_claim) =
            verify_product_sumcheck(&rounds, target_v, &mut vch).unwrap();
        let r_prime: Vec<Block128> = challenges_v.iter().rev().cloned().collect();
        let c_r = mle_eval_at(&col, &r_prime);
        let w_r = weight_at(gamma_v, &points, &r_prime);
        assert_eq!(final_claim, c_r * w_r);
    }

    #[test]
    fn forged_partial_changes_target() {
        let n = 3usize;
        let col = random_vec(1usize << n, 0x42);
        let r = random_vec(n, 0x77);
        let points = ladder_points(&r);
        let honest: Vec<Block128> = points.iter().map(|p| mle_eval_at(&col, p)).collect();
        let mut forged = honest.clone();
        forged[1] = forged[1] + Block128::ONE;
        let gamma = Block128::from(0x123u128);
        assert_ne!(target_claim(gamma, &honest), target_claim(gamma, &forged));
    }
}
