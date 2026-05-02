// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Stage 3b-0.4 — multipoint-to-single-point reduction (CRYPTO.md §12c).
//!
//! After the zero-check sumcheck we hold `N` base claims
//! `e_i = MLE_i(r_point)` and, after per-slot product sumchecks
//! (§12a), `S` ladder claims `o_s = MLE_{col_id_s}(r'_s)`. Instead of
//! closing each ladder claim with its own FRI opening, this module
//! reduces *all* claims to a single common point `r''` via a
//! degree-2 multilinear product sumcheck on
//!
//! ```text
//!   H(x) = eq(r_point, x) · Σ_i β^i · MLE_i(x)
//!        + Σ_s β^{N+s} · eq(r'_s, x) · MLE_{col_id_s}(x)
//! ```
//!
//! which sums on the hypercube to
//! `T = Σ_i β^i · e_i + Σ_s β^{N+s} · o_s`. The terminal claim
//! `claim(r'') = Σ_i β^i · eq(r_point, r'') · m_i + Σ_s β^{N+s} ·
//! eq(r'_s, r'') · m_{col_id_s}` is closed by a **single** batched
//! FRI opening of all base columns at `r''`, replacing the per-slot
//! ladder FRI of 3b-0.3.

use noid_core::{Block128, TowerField};

use crate::RoundPoly;

/// Evaluations per round polynomial for the degree-2 multipoint
/// sumcheck (`X = 0, 1, 2`).
pub const MULTIPOINT_ROUND_POINTS: usize = 3;

/// Domain tag absorbed into the parent channel before squeezing the
/// multipoint batching scalar `β`. Distinct from `RLCOPEN_TAG`
/// (`0xFFFD_…`, §12b) and `LADDERFS` (`0xFFFE_…`, §12a).
pub const MULTIPOINT_TAG: u128 = 0xFFFC_0000_0000_0000;

/// Run degree-2 sumcheck on `H(x) = Σ_k A_k(x) · B_k(x)` where each
/// `(A_k, B_k)` is a pair of multilinear tables of length `2^n` in the
/// crate's LSB-first flat-index convention. Returns the `n` round
/// polynomials (each with evaluations at `X ∈ {0, 1, 2}`) and the
/// raw challenge vector (highest-var-first, matching the zero-check
/// convention). The caller forms `r'' =
/// challenges.iter().rev().collect()` for MLE opening.
pub fn prove_multipoint_sumcheck(
    mut pairs: Vec<(Vec<Block128>, Vec<Block128>)>,
    target: Block128,
    channel: &mut noid_fri::Channel,
) -> (Vec<RoundPoly>, Vec<Block128>) {
    assert!(!pairs.is_empty(), "multipoint: at least one pair required");
    let n = pairs[0].0.len().trailing_zeros() as usize;
    for (a, b) in &pairs {
        debug_assert_eq!(a.len(), 1 << n);
        debug_assert_eq!(b.len(), 1 << n);
    }

    use rayon::prelude::*;

    let mut rounds: Vec<RoundPoly> = Vec::with_capacity(n);
    let mut challenges: Vec<Block128> = Vec::with_capacity(n);
    let mut claim = target;
    let two = Block128::from(2u8);

    for _ in 0..n {
        let half = pairs[0].0.len() / 2;
        let (p0, p1, p2) = pairs
            .par_iter()
            .map(|(a, b)| {
                (0..half)
                    .into_par_iter()
                    .map(|j| {
                        let a0 = a[j];
                        let a1 = a[j + half];
                        let b0 = b[j];
                        let b1 = b[j + half];
                        let as_ = a0 + two * (a1 + a0);
                        let bs_ = b0 + two * (b1 + b0);
                        (a0 * b0, a1 * b1, as_ * bs_)
                    })
                    .reduce(
                        || (Block128::ZERO, Block128::ZERO, Block128::ZERO),
                        |a, b| (a.0 + b.0, a.1 + b.1, a.2 + b.2),
                    )
            })
            .reduce(
                || (Block128::ZERO, Block128::ZERO, Block128::ZERO),
                |a, b| (a.0 + b.0, a.1 + b.1, a.2 + b.2),
            );
        debug_assert_eq!(p0 + p1, claim, "multipoint sumcheck consistency failure");

        let rp = vec![p0, p1, p2];
        channel.observe_field_elems(&rp);
        let r = channel.get_random_point();

        pairs.par_iter_mut().for_each(|(a, b)| {
            let (lo_a, hi_a) = a.split_at_mut(half);
            lo_a.par_iter_mut()
                .zip(hi_a.par_iter())
                .for_each(|(lo, hi)| *lo = *lo + r * (*hi + *lo));
            a.truncate(half);
            let (lo_b, hi_b) = b.split_at_mut(half);
            lo_b.par_iter_mut()
                .zip(hi_b.par_iter())
                .for_each(|(lo, hi)| *lo = *lo + r * (*hi + *lo));
            b.truncate(half);
        });

        claim = crate::lagrange_eval_at_pub(&rp, r);
        rounds.push(rp);
        challenges.push(r);
    }

    (rounds, challenges)
}

/// Verify-side replay. Returns challenge vector (highest-var-first)
/// and the terminal claim the caller must match against
/// `Σ_k A_k(r'') · B_k(r'')`.
pub fn verify_multipoint_sumcheck(
    rounds: &[RoundPoly],
    target: Block128,
    channel: &mut noid_fri::Channel,
) -> Result<(Vec<Block128>, Block128), crate::VerifyError> {
    let mut claim = target;
    let mut challenges: Vec<Block128> = Vec::with_capacity(rounds.len());
    for rp in rounds {
        if rp.len() != MULTIPOINT_ROUND_POINTS {
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

#[cfg(test)]
mod tests {
    use super::*;
    use noid_core::mle::eq::{eq_ind, eq_ind_partial_eval};
    use noid_fri::Channel;

    fn rand_vec(n: usize, seed: u128) -> Vec<Block128> {
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

    fn mle_at(table: &[Block128], r: &[Block128]) -> Block128 {
        let mut buf = table.to_vec();
        for &rk in r.iter().rev() {
            let half = buf.len() / 2;
            for i in 0..half {
                buf[i] = buf[i] + rk * (buf[i + half] + buf[i]);
            }
            buf.truncate(half);
        }
        buf[0]
    }

    #[test]
    fn multipoint_roundtrip_pair_of_products() {
        let n = 4usize;
        let len = 1 << n;

        let col0 = rand_vec(len, 0xA1);
        let col1 = rand_vec(len, 0xB2);
        let r_a = rand_vec(n, 0xC3);
        let r_b = rand_vec(n, 0xD4);

        let e0 = mle_at(&col0, &r_a);
        let e1 = mle_at(&col1, &r_b);

        let eq_a = eq_ind_partial_eval(&r_a);
        let eq_b = eq_ind_partial_eval(&r_b);

        let mut pch = Channel::new();
        let beta = pch.get_random_point();
        let target = e0 + beta * e1;

        let scaled_col1: Vec<Block128> = col1.iter().map(|v| *v * beta).collect();
        let pairs = vec![(eq_a.clone(), col0.clone()), (eq_b.clone(), scaled_col1)];
        let (rounds, challenges) = prove_multipoint_sumcheck(pairs, target, &mut pch);

        let mut vch = Channel::new();
        let beta_v = vch.get_random_point();
        assert_eq!(beta, beta_v);
        let (challenges_v, final_claim) =
            verify_multipoint_sumcheck(&rounds, target, &mut vch).unwrap();
        assert_eq!(challenges, challenges_v);

        let r_pp: Vec<Block128> = challenges_v.iter().rev().cloned().collect();
        let m0 = mle_at(&col0, &r_pp);
        let m1 = mle_at(&col1, &r_pp);
        let eq_a_pp = eq_ind(&r_a, &r_pp);
        let eq_b_pp = eq_ind(&r_b, &r_pp);
        let expected = eq_a_pp * m0 + beta * eq_b_pp * m1;
        assert_eq!(final_claim, expected);
    }

    #[test]
    fn tampered_target_is_rejected() {
        let n = 3usize;
        let len = 1 << n;
        let col = rand_vec(len, 0x11);
        let r = rand_vec(n, 0x22);
        let eq_r = eq_ind_partial_eval(&r);
        let e = mle_at(&col, &r);

        let mut pch = Channel::new();
        let _ = pch.get_random_point();
        let pairs = vec![(eq_r, col)];
        let (rounds, _) = prove_multipoint_sumcheck(pairs, e, &mut pch);

        let mut vch = Channel::new();
        let _ = vch.get_random_point();
        let target_wrong = e + Block128::ONE;
        let res = verify_multipoint_sumcheck(&rounds, target_wrong, &mut vch);
        assert!(res.is_err(), "divergent target must be rejected");
    }
}
