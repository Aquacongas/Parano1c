// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! VSHIFT gadget — cyclic row-rotation of a committed column inside the
//! zero-check sumcheck, via a closed-form multilinear identity.
//!
//! ## Convention
//!
//! The opening point `r` follows the same indexing as
//! `noid_stark::mle_eval`: with that routine's `point.iter().rev()`
//! half-split fold, the flat row index decomposes as
//! `i = r[0] + 2·r[1] + 4·r[2] + … + 2^{n-1}·r[n-1]`. That is,
//! **`r[0]` binds the LSB**, `r[n-1]` binds the MSB. Ladder points live
//! in this same convention so they can be plugged straight into
//! `mle_eval` / `fri::verify` without permutation.
//!
//! ## Identity
//!
//! Let `C'(i) = C((i+1) mod 2^n)`. Splitting by the LSB (= `r[0]` under
//! our convention) gives the recursion
//!
//! ```text
//!   C'(r[0], r[1], …, r[n-1])
//!     = (1 + r[0]) · C(1, r[1], …, r[n-1])
//!     +      r[0]  · shift_up(C)(r[1], …, r[n-1])
//! ```
//!
//! where `shift_up(C)` is the same gadget applied to `C|_{LSB=0}`, one
//! variable smaller. Unrolling all `n` levels gives the **ladder form**
//!
//! ```text
//!   C'(r) = Σ_{k=0}^{n}  w_k(r) · P_k
//! ```
//!
//! with ladder points and coefficients
//!
//! ```text
//!   P_k = C(0, …, 0, 1, r[k+1], …, r[n-1])     for k ∈ {0,…,n-1}
//!         └─ k zeros ─┘
//!   P_n = C(0, 0, …, 0)                         // full wrap
//!
//!   w_0(r) = 1 + r[0]
//!   w_k(r) = r[0]·r[1]·…·r[k-1]·(1 + r[k])     for k ∈ {1,…,n-1}
//!   w_n(r) = r[0]·r[1]·…·r[n-1]
//! ```
//!
//! Sanity (n=1): `P_0 = C(1)`, `P_1 = C(0)`,
//! `C'(r[0]) = (1+r[0])·C(1) + r[0]·C(0)`. At `r[0]=0` (char-2) we
//! evaluate `C'` at row `0`, which is `col[(0+1) mod 2] = col[1]` — and
//! the formula gives `1·C(1) + 0·C(0) = col[1]`. At `r[0]=1` the row is
//! `1`, with cyclic-next `col[0]`; formula gives `0·col[1] + 1·col[0]`.
//!
//! ## Soundness
//!
//! The `P_k` are MLE evaluations of the **committed** `C`. The verifier
//! never receives a prover-supplied `C'(r)`; it reconstructs it from
//! the ladder via the closed-form identity. Any inconsistency in the
//! ladder is caught by FRI opening verification of `C` at the ladder
//! points.

use noid_core::{Block128, TowerField};

/// The `n+1` evaluation points on the hypercube of `C` whose values form
/// the VSHIFT ladder for an opening at `r`.
///
/// Points are returned in ladder order `P_0, P_1, …, P_n`; each point
/// is a length-`n` `Block128` vector in the same convention as `r`
/// (`p[0]` binds the LSB, `p[n-1]` the MSB).
pub fn ladder_points(r: &[Block128]) -> Vec<Vec<Block128>> {
    let n = r.len();
    let mut out = Vec::with_capacity(n + 1);
    // P_k: first k coords = 0, coord k = 1, trailing coords copy r[k+1..].
    for k in 0..n {
        let mut p = vec![Block128::ZERO; n];
        p[k] = Block128::ONE;
        for i in (k + 1)..n {
            p[i] = r[i];
        }
        out.push(p);
    }
    out.push(vec![Block128::ZERO; n]);
    out
}

/// Compute all `n + 1` ladder partials `v_k = C(P_k)` in `O(2^n)` total
/// field operations (vs `O((n+1) · 2^n)` for independent per-point
/// evaluations).
///
/// Exploits the structural nesting of the ladder points. Let
/// `S_k(x_0,…,x_k) = C(x_0,…,x_k, r[k+1],…,r[n-1])` — the MLE over the
/// first `k+1` hypercube coords with every higher coord bound to `r`.
/// Then
///
/// ```text
///   v_n = C(0,…,0) = col[0]
///   v_k = S_k(0,…,0,1)    — flat index 2^k in S_k's 2^{k+1}-entry table   (k < n)
///   S_{k-1} = fold(S_k, r[k])                                              (halves)
/// ```
///
/// One descent from `k = n-1` down to `k = 0` extracts every partial
/// with total work `Σ_{k=0}^{n-1} 2^k = 2^n - 1` half-folds.
pub fn ladder_partials(col: &[Block128], r: &[Block128]) -> Vec<Block128> {
    let n = r.len();
    assert_eq!(col.len(), 1usize << n, "column length must be 2^n");

    let mut partials = vec![Block128::ZERO; n + 1];
    partials[n] = col[0];
    if n == 0 {
        return partials;
    }

    // Each fold step consumes the current MSB coord of `buf`. Start
    // with all `n` coords live (`buf.len() = 2^n`) and fold coord
    // `n-1`, then `n-2`, …, until only coords `0..=k` remain. At that
    // point the table has length `2^{k+1}` and equals `S_k(x_0,…,x_k)`;
    // read `v_k = buf[2^k]` before folding coord `k` away.
    let mut buf: Vec<Block128> = col.to_vec();
    for k in (0..n).rev() {
        let half = 1usize << k;
        // v_k sits at flat index 2^k in the current length-2·half table.
        partials[k] = buf[half];
        // Consume coord `k` (current MSB) with `r[k]`.
        let rk = r[k];
        for i in 0..half {
            buf[i] = buf[i] + rk * (buf[i + half] + buf[i]);
        }
        buf.truncate(half);
    }
    partials
}

/// Reconstruct `C'(r)` from the ladder `partials = [P_0, …, P_n]` and
/// the opening point `r`:
///
/// ```text
///   inner ← P_n
///   for k from n-1 down to 0:
///       inner ← (1 + r[k]) · P_k + r[k] · inner
///   return inner                                    // = C'(r)
/// ```
pub fn reconstruct_shifted_opening(r: &[Block128], partials: &[Block128]) -> Block128 {
    let n = r.len();
    assert_eq!(
        partials.len(),
        n + 1,
        "VSHIFT ladder must carry exactly log_len + 1 partials"
    );
    let one = Block128::ONE;
    let mut inner = partials[n];
    for k in (0..n).rev() {
        let rk = r[k];
        inner = (one + rk) * partials[k] + rk * inner;
    }
    inner
}

/// Native cyclic left-rotation of a column table by one row:
/// `out[i] = col[(i+1) mod N]`. Used by the prover to materialise `C'`
/// as a virtual column for the zero-check sumcheck.
pub fn cyclic_rotate_left(col: &[Block128]) -> Vec<Block128> {
    let n = col.len();
    assert!(n > 0, "cannot rotate empty column");
    let mut out = Vec::with_capacity(n);
    out.extend_from_slice(&col[1..]);
    out.push(col[0]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// MLE at point `r` using the crate-wide convention:
    /// `r[0]` binds the LSB, `r[n-1]` the MSB (flat row index
    /// `i = Σ r[k]·2^k`). Matches `noid_stark::mle_eval`.
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

    fn random_column(n: usize, seed: u128) -> Vec<Block128> {
        (0..(1usize << n))
            .map(|i| {
                let x = seed
                    .wrapping_mul(0x9E3779B97F4A7C15)
                    .wrapping_add(i as u128)
                    .wrapping_mul(0xBF58476D1CE4E5B9);
                Block128::from(x)
            })
            .collect()
    }

    fn random_point(n: usize, seed: u128) -> Vec<Block128> {
        (0..n)
            .map(|i| {
                let x = seed
                    .wrapping_mul(0xC6BC279692B5C323)
                    .wrapping_add((i as u128).wrapping_mul(0xD1B54A32D192ED03));
                Block128::from(x | 1)
            })
            .collect()
    }

    #[test]
    fn cyclic_rotate_matches_definition() {
        let col = vec![
            Block128::from(10u128),
            Block128::from(20u128),
            Block128::from(30u128),
            Block128::from(40u128),
        ];
        let rot = cyclic_rotate_left(&col);
        assert_eq!(rot, vec![
            Block128::from(20u128),
            Block128::from(30u128),
            Block128::from(40u128),
            Block128::from(10u128),
        ]);
    }

    /// `ladder_partials` (nested-fold, O(2^n)) agrees with the
    /// reference per-point `mle_eval_at` for every ladder point.
    #[test]
    fn ladder_partials_matches_per_point_eval() {
        for n in 1..=6 {
            for trial in 0..5u128 {
                let col = random_column(n, 0xC0DE_0000 ^ trial);
                let r = random_point(n, 0xBEEF_0000 ^ trial ^ (n as u128));
                let points = ladder_points(&r);
                let reference: Vec<Block128> =
                    points.iter().map(|p| mle_eval_at(&col, p)).collect();
                let fast = ladder_partials(&col, &r);
                assert_eq!(fast, reference, "ladder_partials mismatch at n={} trial={}", n, trial);
            }
        }
    }

    /// For every n in {1,…,5}, for random columns and random points,
    /// the ladder-reconstructed `C'(r)` must equal the MLE of the
    /// natively-rotated column at `r`.
    #[test]
    fn ladder_identity_matches_native_rotation() {
        for n in 1..=5 {
            for trial in 0..8u128 {
                let col = random_column(n, 0xA5A5_0000 ^ trial);
                let r = random_point(n, 0xF00D_0000 ^ trial ^ (n as u128));

                let rot = cyclic_rotate_left(&col);
                let expected = mle_eval_at(&rot, &r);

                let points = ladder_points(&r);
                let partials: Vec<Block128> =
                    points.iter().map(|p| mle_eval_at(&col, p)).collect();
                let got = reconstruct_shifted_opening(&r, &partials);

                assert_eq!(
                    got, expected,
                    "VSHIFT identity failed at n={} trial={}",
                    n, trial
                );
            }
        }
    }

    /// Boundary: at `r` = all-zero, `C'(r) = C'(0,…,0) = col[(0+1) mod N] = col[1]`.
    #[test]
    fn ladder_at_zero_point_picks_row_one() {
        for n in 1..=4 {
            let col = random_column(n, 0xCAFE_BABE ^ n as u128);
            let r = vec![Block128::ZERO; n];
            let partials: Vec<Block128> = ladder_points(&r)
                .iter()
                .map(|p| mle_eval_at(&col, p))
                .collect();
            assert_eq!(reconstruct_shifted_opening(&r, &partials), col[1]);
        }
    }

    /// Boundary: at `r` = all-one (char-2), little-endian all-ones
    /// corresponds to the last hypercube row, whose cyclic-next is row 0.
    /// So `C'(1,…,1) = col[0]`.
    #[test]
    fn ladder_at_one_point_wraps_to_row_zero() {
        for n in 1..=4 {
            let col = random_column(n, 0xDEAD_BEEF ^ n as u128);
            let r = vec![Block128::ONE; n];
            let partials: Vec<Block128> = ladder_points(&r)
                .iter()
                .map(|p| mle_eval_at(&col, p))
                .collect();
            assert_eq!(reconstruct_shifted_opening(&r, &partials), col[0]);
        }
    }

    /// Tampering with any single ladder value produces a different
    /// reconstructed `C'(r)` w.h.p.
    #[test]
    fn tampered_ladder_produces_different_opening() {
        let n = 4;
        let col = random_column(n, 0x1234_5678);
        let r = random_point(n, 0x9ABC_DEF0);
        let mut partials: Vec<Block128> = ladder_points(&r)
            .iter()
            .map(|p| mle_eval_at(&col, p))
            .collect();
        let honest = reconstruct_shifted_opening(&r, &partials);
        for k in 0..=n {
            let saved = partials[k];
            partials[k] = saved + Block128::from(0x42u128);
            let tampered = reconstruct_shifted_opening(&r, &partials);
            assert_ne!(honest, tampered, "tamper at ladder index {} went undetected", k);
            partials[k] = saved;
        }
    }
}
