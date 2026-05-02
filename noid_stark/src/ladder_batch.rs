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
/// (matches `padded_columns`).
///
/// Exploits the structural sparsity of `ladder_points(r)`: for `k < n`
/// the point `P_k` has eq-table supported only on indices
/// `(j << (k+1)) | (1 << k)` where `j ∈ [0, 2^{n-k-1})` and the values
/// there equal `eq_ind_partial_eval(r[k+1..])`. `P_n` contributes only
/// to index 0 (value `1`). The per-`k` supports are disjoint, so the
/// scatter is parallel-safe. Total work is `O(2^n)` muls, independent
/// of `n`, versus the old `O(n · 2^n)`.
pub fn build_weight_table(gamma: Block128, r: &[Block128], n: usize) -> Vec<Block128> {
    debug_assert_eq!(r.len(), n);
    use rayon::prelude::*;

    let len = 1usize << n;
    let mut w = vec![Block128::ZERO; len];

    // Precompute powers γ^0..γ^n once.
    let mut gammas = Vec::with_capacity(n + 1);
    {
        let mut gk = Block128::ONE;
        for _ in 0..=n {
            gammas.push(gk);
            gk *= gamma;
        }
    }

    // P_n contributes γ^n at index 0.
    w[0] = gammas[n];

    // Scatter per-k into disjoint strides. Writes from different k
    // never collide, so we can safely produce each fragment in
    // parallel and apply them sequentially.
    let fragments: Vec<(usize, usize, Vec<Block128>)> = (0..n)
        .into_par_iter()
        .map(|k| {
            let trail = noid_core::mle::eq::eq_ind_partial_eval(&r[k + 1..n]);
            let gk = gammas[k];
            let scaled: Vec<Block128> = trail.into_iter().map(|v| gk * v).collect();
            let stride = 1usize << (k + 1);
            let base = 1usize << k;
            (stride, base, scaled)
        })
        .collect();
    for (stride, base, scaled) in fragments {
        for (j, v) in scaled.into_iter().enumerate() {
            w[base + j * stride] = v;
        }
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

    use rayon::prelude::*;

    let mut rounds: Vec<RoundPoly> = Vec::with_capacity(n);
    let mut challenges: Vec<Block128> = Vec::with_capacity(n);
    let mut claim = target;
    let two = Block128::from(2u8);

    for _ in 0..n {
        let half = c.len() / 2;
        let (p0, p1, p2) = (0..half)
            .into_par_iter()
            .map(|j| {
                let c0 = c[j];
                let c1 = c[j + half];
                let w0 = w[j];
                let w1 = w[j + half];
                let cs = c0 + two * (c1 + c0);
                let ws = w0 + two * (w1 + w0);
                (c0 * w0, c1 * w1, cs * ws)
            })
            .reduce(
                || (Block128::ZERO, Block128::ZERO, Block128::ZERO),
                |a, b| (a.0 + b.0, a.1 + b.1, a.2 + b.2),
            );

        debug_assert_eq!(p0 + p1, claim, "product sumcheck consistency failure");

        let rp = vec![p0, p1, p2];
        channel.observe_field_elems(&rp);
        let r = channel.get_random_point();

        // In-place fold at the highest variable.
        let (lo_c, hi_c) = c.split_at_mut(half);
        lo_c.par_iter_mut()
            .zip(hi_c.par_iter())
            .for_each(|(lo, hi)| *lo = *lo + r * (*hi + *lo));
        c.truncate(half);
        let (lo_w, hi_w) = w.split_at_mut(half);
        lo_w.par_iter_mut()
            .zip(hi_w.par_iter())
            .for_each(|(lo, hi)| *lo = *lo + r * (*hi + *lo));
        w.truncate(half);

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
        let table = build_weight_table(gamma, &r, n);
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
        let w = build_weight_table(gamma, &r, n);
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
