// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

#![allow(clippy::needless_range_loop)]

//! Shared helpers for the ladder-merge protocol.
//!
//! See CRYPTO.md §12c' for the protocol and soundness argument. The
//! legacy per-slot product sumcheck (old §12a) is gone: ladder claims
//! are inlined directly into the §12c' multipoint sumcheck as
//! γ_s-weighted eq-sums over `ladder_points(r_point)`.
//!
//! What survives here:
//!   * `target_claim(γ, partials)` — computes `Σ_k γ^k · v_k`, used
//!     both prover- and verifier-side to build the §12c' target.
//!   * `weight_at(γ, points, r'')` — closed-form verifier evaluator
//!     for `W_s(r'') = Σ_k γ_s^k · eq(P_{s,k}, r'')`.
//!   * `WeightTrails` + `build_weight_table_from_trails` — hypercube
//!     materialisation of `W_s(x)` on `{0,1}^n`, used prover-side to
//!     build the ladder pairs for `prove_multipoint_sumcheck`.
//!   * `sub_channel_tag(slot)` — domain tag absorbed with each slot's
//!     partials so that cross-slot confusion is impossible.

use noid_core::{Block128, TowerField};

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
///
/// Reference implementation — O((n+1) · n) field ops via per-point
/// `eq_ind`. Prefer [`LadderWeightAxes`] + [`weight_at_axes`] when
/// evaluating `W_s(r'')` for many slots at a shared `(r, r'')`: each
/// slot drops to O(n) after a one-time O(n) precompute.
pub fn weight_at(gamma: Block128, points: &[Vec<Block128>], r_prime: &[Block128]) -> Block128 {
    let mut acc = Block128::ZERO;
    let mut gk = Block128::ONE;
    for pk in points {
        acc += gk * noid_core::mle::eq::eq_ind(pk, r_prime);
        gk *= gamma;
    }
    acc
}

/// Closed-form axes for `eq(P_k, r'')` shared by every slot of a single
/// `prove_air` / `verify_air` call. Derived from the structural
/// sparsity of `ladder_points(r)`:
///
/// ```text
///   eq(P_k, r'') = prefix[k] · r''[k] · suffix[k+1]      (k < n)
///   eq(P_n, r'') = prefix[n]
/// ```
///
/// with (char-2 tower, `1 - x = 1 + x`)
///
/// ```text
///   prefix[0] = 1,   prefix[k+1] = prefix[k] · (1 + r''[k])
///   suffix[n] = 1,   suffix[k]   = suffix[k+1] · (1 + r[k] + r''[k])
/// ```
///
/// Per-slot `weight_at_axes` is then O(n) field ops instead of O(n^2).
pub struct LadderWeightAxes {
    prefix: Vec<Block128>,
    suffix: Vec<Block128>,
    r_prime: Vec<Block128>,
    n: usize,
}

impl LadderWeightAxes {
    pub fn new(r: &[Block128], r_prime: &[Block128]) -> Self {
        let n = r.len();
        assert_eq!(r_prime.len(), n, "r and r'' must share length");
        let one = Block128::ONE;

        let mut prefix = Vec::with_capacity(n + 1);
        prefix.push(one);
        for k in 0..n {
            let last = prefix[k];
            prefix.push(last * (one + r_prime[k]));
        }

        let mut suffix = vec![Block128::ZERO; n + 1];
        suffix[n] = one;
        for k in (0..n).rev() {
            suffix[k] = suffix[k + 1] * (one + r[k] + r_prime[k]);
        }

        Self {
            prefix,
            suffix,
            r_prime: r_prime.to_vec(),
            n,
        }
    }
}

/// `W_s(r'') = Σ_{k=0}^{n-1} γ^k · prefix[k] · r''[k] · suffix[k+1]
///           + γ^n · prefix[n]`.
pub fn weight_at_axes(gamma: Block128, axes: &LadderWeightAxes) -> Block128 {
    let n = axes.n;
    let mut acc = Block128::ZERO;
    let mut gk = Block128::ONE;
    for k in 0..n {
        acc += gk * axes.prefix[k] * axes.r_prime[k] * axes.suffix[k + 1];
        gk *= gamma;
    }
    acc += gk * axes.prefix[n];
    acc
}

/// γ-independent fragments of the weight table. Computed once per
/// `r_point`, reused across every ladder slot. See
/// [`build_weight_table_from_trails`].
///
/// `trails[k]` is `eq_ind_partial_eval(r[k+1..n])` (length `2^{n-k-1}`).
/// `trails.len() == n`.
pub struct WeightTrails {
    trails: Vec<Vec<Block128>>,
    n: usize,
}

impl WeightTrails {
    pub fn new(r: &[Block128]) -> Self {
        let n = r.len();
        let trails: Vec<Vec<Block128>> = (0..n)
            .map(|k| noid_core::mle::eq::eq_ind_partial_eval(&r[k + 1..n]))
            .collect();
        Self { trails, n }
    }
}

/// Build the weight table `W(x)` for all `x ∈ {0,1}^n` using
/// precomputed γ-independent trails. Because every ladder slot in a
/// `prove_air` call shares the same `r_point`, hoisting the trails out
/// of the slot loop and only doing the `γ^k` scale here saves N_slots
/// calls to `eq_ind_partial_eval`.
///
/// Exploits the structural sparsity of `ladder_points(r)`: for `k < n`
/// the point `P_k` has eq-table supported only on indices
/// `(j << (k+1)) | (1 << k)` where `j ∈ [0, 2^{n-k-1})` and the values
/// there equal `eq_ind_partial_eval(r[k+1..])`. `P_n` contributes only
/// to index 0 (value `1`). The per-`k` supports are disjoint.
pub fn build_weight_table_from_trails(gamma: Block128, trails: &WeightTrails) -> Vec<Block128> {
    let n = trails.n;
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

    // Scatter per-k into disjoint strides.
    for k in 0..n {
        let gk = gammas[k];
        let stride = 1usize << (k + 1);
        let base = 1usize << k;
        let trail = &trails.trails[k];
        for (j, &v) in trail.iter().enumerate() {
            w[base + j * stride] = gk * v;
        }
    }
    w
}

/// Domain tag absorbed alongside a slot's ladder partials on the
/// parent channel so that two distinct slots can never be confused:
/// `0xFFFE_0000_0000_0000 | slot`. CRYPTO.md §12c'.3.
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
        let trails = WeightTrails::new(&r);
        let table = build_weight_table_from_trails(gamma, &trails);
        for idx in 0..(1usize << n) {
            let x: Vec<Block128> = (0..n)
                .map(|b| {
                    if (idx >> b) & 1 == 1 {
                        Block128::ONE
                    } else {
                        Block128::ZERO
                    }
                })
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
    fn weight_at_axes_matches_reference() {
        for n in 1..=6 {
            for trial in 0..5u128 {
                let r = random_vec(n, 0xAA00 ^ trial ^ (n as u128));
                let r_prime = random_vec(n, 0xBB00 ^ trial ^ (n as u128));
                let points = ladder_points(&r);
                let axes = LadderWeightAxes::new(&r, &r_prime);
                for slot in 0..4 {
                    let gamma = Block128::from(0x1234_0000u128 ^ (slot as u128) ^ trial);
                    let reference = weight_at(gamma, &points, &r_prime);
                    let fast = weight_at_axes(gamma, &axes);
                    assert_eq!(
                        fast, reference,
                        "axes eval mismatch n={} trial={} slot={}",
                        n, trial, slot
                    );
                }
            }
        }
    }

    #[test]
    fn forged_partial_changes_target() {
        let n = 3usize;
        let col = random_vec(1usize << n, 0x42);
        let r = random_vec(n, 0x77);
        let points = ladder_points(&r);
        let honest: Vec<Block128> = points.iter().map(|p| mle_eval_at(&col, p)).collect();
        let mut forged = honest.clone();
        forged[1] += Block128::ONE;
        let gamma = Block128::from(0x123u128);
        assert_ne!(target_claim(gamma, &honest), target_claim(gamma, &forged));
    }
}
