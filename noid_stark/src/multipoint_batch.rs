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

use noid_core::Block128;

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
    pairs_a: Vec<Vec<Block128>>,
    pairs_b: Vec<&[Block128]>,
    target: Block128,
    channel: &mut noid_fri::Channel,
) -> (Vec<RoundPoly>, Vec<Block128>) {
    assert!(!pairs_a.is_empty(), "multipoint: at least one pair required");
    assert_eq!(pairs_a.len(), pairs_b.len(), "A and B pair counts must match");
    let n = pairs_a[0].len().trailing_zeros() as usize;
    for (a, b) in pairs_a.iter().zip(pairs_b.iter()) {
        debug_assert_eq!(a.len(), 1 << n);
        debug_assert_eq!(b.len(), 1 << n);
    }

    use noid_core::hardware::{clmul_gcm, flat_to_tower_u128, tower_to_flat_u128};
    use rayon::prelude::*;

    // Convert every pair table to flat basis once. All inner arithmetic
    // (round-oracle accumulation + per-round fold) runs in flat basis
    // via `clmul_gcm` — XOR is basis-agnostic. We convert back to tower
    // only for the three round-oracle evals (observed on the transcript)
    // and the final challenge scalar (which we need in tower to feed
    // back into `lagrange_eval_at_pub`; the flat copy is used for the
    // fold itself).
    //
    // `pairs_b` arrives as borrowed slices into the caller's committed
    // column pool — they are not re-clonable data, so we allocate a
    // single fresh flat buffer per B without an intermediate owned
    // tower-basis copy.
    let mut pairs_flat: Vec<(Vec<u128>, Vec<u128>)> = pairs_a
        .into_par_iter()
        .zip(pairs_b.into_par_iter())
        .map(|(a, b)| {
            let a_flat: Vec<u128> = a.into_iter().map(|v| tower_to_flat_u128(v.0)).collect();
            let b_flat: Vec<u128> = b.iter().map(|v| tower_to_flat_u128(v.0)).collect();
            (a_flat, b_flat)
        })
        .collect();

    let two_flat = tower_to_flat_u128(Block128::from(2u8).0);

    let mut rounds: Vec<RoundPoly> = Vec::with_capacity(n);
    let mut challenges: Vec<Block128> = Vec::with_capacity(n);
    let mut claim = target;

    for _ in 0..n {
        let half = pairs_flat[0].0.len() / 2;

        // Round-oracle: three XOR accumulators in flat basis. For each
        // (A, B) pair and each j:
        //   a_s = a0 ^ clmul(two_flat, a1 ^ a0)
        //   b_s = b0 ^ clmul(two_flat, b1 ^ b0)
        //   p0 ^= clmul(a0, b0)
        //   p1 ^= clmul(a1, b1)
        //   p2 ^= clmul(a_s, b_s)
        // These match the tower-basis `a_s = a0 + 2·(a1+a0)` and the
        // three point evaluations at X ∈ {0, 1, 2}. Soundness-neutral:
        // conversion is isomorphism of GF(2^128), so the aggregate
        // tower-basis sum equals `flat_to_tower(aggregate_flat)`.
        let (p0_flat, p1_flat, p2_flat) = pairs_flat
            .par_iter()
            .map(|(a, b)| {
                let mut s0: u128 = 0;
                let mut s1: u128 = 0;
                let mut s2: u128 = 0;
                for j in 0..half {
                    let a0 = a[j];
                    let a1 = a[j + half];
                    let b0 = b[j];
                    let b1 = b[j + half];
                    let a_s = a0 ^ clmul_gcm(two_flat, a1 ^ a0);
                    let b_s = b0 ^ clmul_gcm(two_flat, b1 ^ b0);
                    s0 ^= clmul_gcm(a0, b0);
                    s1 ^= clmul_gcm(a1, b1);
                    s2 ^= clmul_gcm(a_s, b_s);
                }
                (s0, s1, s2)
            })
            .reduce(
                || (0u128, 0u128, 0u128),
                |x, y| (x.0 ^ y.0, x.1 ^ y.1, x.2 ^ y.2),
            );
        let p0 = Block128::from(flat_to_tower_u128(p0_flat));
        let p1 = Block128::from(flat_to_tower_u128(p1_flat));
        let p2 = Block128::from(flat_to_tower_u128(p2_flat));
        debug_assert_eq!(p0 + p1, claim, "multipoint sumcheck consistency failure");

        let rp = vec![p0, p1, p2];
        channel.observe_field_elems(&rp);
        let r = channel.get_random_point();
        let r_flat = tower_to_flat_u128(r.0);

        // Fold in flat: lo = lo ^ clmul(r_flat, hi ^ lo).
        pairs_flat.par_iter_mut().for_each(|(a, b)| {
            let half = a.len() / 2;
            let (lo_a, hi_a) = a.split_at_mut(half);
            for i in 0..half {
                lo_a[i] ^= clmul_gcm(r_flat, hi_a[i] ^ lo_a[i]);
            }
            a.truncate(half);
            let (lo_b, hi_b) = b.split_at_mut(half);
            for i in 0..half {
                lo_b[i] ^= clmul_gcm(r_flat, hi_b[i] ^ lo_b[i]);
            }
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
    use noid_core::TowerField;
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
        let pairs_a = vec![eq_a.clone(), eq_b.clone()];
        let pairs_b: Vec<&[Block128]> = vec![col0.as_slice(), scaled_col1.as_slice()];
        let (rounds, challenges) =
            prove_multipoint_sumcheck(pairs_a, pairs_b, target, &mut pch);

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
        let pairs_a = vec![eq_r];
        let pairs_b: Vec<&[Block128]> = vec![col.as_slice()];
        let (rounds, _) = prove_multipoint_sumcheck(pairs_a, pairs_b, e, &mut pch);

        let mut vch = Channel::new();
        let _ = vch.get_random_point();
        let target_wrong = e + Block128::ONE;
        let res = verify_multipoint_sumcheck(&rounds, target_wrong, &mut vch);
        assert!(res.is_err(), "divergent target must be rejected");
    }
}
