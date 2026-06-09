// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

#![allow(clippy::unnecessary_cast)]

//! Multipoint-to-single-point reduction (CRYPTO.md §12c).
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
    pairs_a: Vec<Vec<Block128>>,
    pairs_b: Vec<&[Block128]>,
    target: Block128,
    channel: &mut noid_fri::Channel,
) -> (Vec<RoundPoly>, Vec<Block128>) {
    assert!(
        !pairs_a.is_empty(),
        "multipoint: at least one pair required"
    );
    assert_eq!(
        pairs_a.len(),
        pairs_b.len(),
        "A and B pair counts must match"
    );
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

/// Like [`prove_multipoint_sumcheck`] but accepts pre-flattened B-side
/// tables (already in flat GCM basis). Saves the O(N * hyper_len)
/// tower-to-flat conversion when the caller can build B tables directly
/// in flat basis.
pub fn prove_multipoint_sumcheck_flat_b(
    pairs_a: Vec<Vec<Block128>>,
    pairs_b_flat: Vec<Vec<u128>>,
    target: Block128,
    channel: &mut noid_fri::Channel,
) -> (Vec<RoundPoly>, Vec<Block128>) {
    assert!(!pairs_a.is_empty());
    assert_eq!(pairs_a.len(), pairs_b_flat.len());
    let n = pairs_a[0].len().trailing_zeros() as usize;
    for (a, b) in pairs_a.iter().zip(pairs_b_flat.iter()) {
        debug_assert_eq!(a.len(), 1 << n);
        debug_assert_eq!(b.len(), 1 << n);
    }

    use noid_core::hardware::{clmul_gcm, flat_to_tower_u128, tower_to_flat_u128};
    use rayon::prelude::*;

    let mut pairs_flat: Vec<(Vec<u128>, Vec<u128>)> = pairs_a
        .into_par_iter()
        .zip(pairs_b_flat.into_par_iter())
        .map(|(a, b_flat)| {
            let a_flat: Vec<u128> = a.into_iter().map(|v| tower_to_flat_u128(v.0)).collect();
            (a_flat, b_flat)
        })
        .collect();

    let two_flat = tower_to_flat_u128(Block128::from(2u8).0);

    let mut rounds: Vec<RoundPoly> = Vec::with_capacity(n);
    let mut challenges: Vec<Block128> = Vec::with_capacity(n);
    let mut claim = target;

    for _ in 0..n {
        let half = pairs_flat[0].0.len() / 2;

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

// ---------------------------------------------------------------------------
// γ₃b: mixed-length multipoint sumcheck
// ---------------------------------------------------------------------------
//
// Motivation. The uniform-length prover above assumes every pair lives on
// the same 2^N hypercube. `noid_stark::spine` needs to inject a boundary
// claim `(r_B, v_B)` on a 2^15 MLE alongside the base-trace columns on
// 2^11 (or other log_rows < 15) without padding B into a bigger
// commitment. The fix is a char-2-safe MLE lift, applied only inside the
// sumcheck — the caller's tables keep their natural size.
//
// Lift. For a pair `(A_k, B_k)` of length `2^{n_k}` with `n_k ≤ N`
// (where `N = max_k n_k`), define the lift on `N` variables
// `(y, z) = (y_0,…,y_{m-1}, z_0,…,z_{n_k-1})` with `m = N - n_k`:
//
//     A_k^*(y, z) = eq_0(y) · A_k(z) = (∏_j (1 + y_j)) · A_k(z)
//     B_k^*(y, z) =                      B_k(z)
//
// The `eq_0` factor is char-2 safe: `Σ_{b∈{0,1}} (1 + b) = 1 + 0 = 1`,
// so `Σ_y eq_0(y) = 1`. Hence `Σ_{y,z} A_k^* · B_k^* = Σ_z A_k · B_k`,
// and the lifted target equals the original `T = Σ_k Σ_z A_k · B_k`.
//
// Round structure. With highest-var-first folding (the existing
// convention — MSB is bound in round 0), pair `k`'s high vars `y_*`
// are bound in rounds `0..m_k`; its low vars `z_*` in rounds
// `m_k..N`. Two round modes per pair:
//
// - **High mode** (round `i < m_k`). The partial MLE at round `i`,
//   after binding `y_0,…,y_{i-1}` to `r_0,…,r_{i-1}`, is
//   `s_i · (1 + X) · T_k` where `s_i = ∏_{j<i} (1 + r_j)` and
//   `T_k = Σ_z A_k(z)·B_k(z)` is the pair's whole-cube sum (computed
//   once, reused every high round). Oracle evals at `X ∈ {0,1,2}`:
//   `p(0) = s_i·T_k`, `p(1) = 0`, `p(2) = s_i · 3 · T_k`. Tables are
//   **not** folded. `s_{i+1} = s_i · (1 + r_i)`.
//
// - **Low mode** (round `i ≥ m_k`). Standard degree-2 product round on
//   `(A_k(z_unbound…), B_k(z_unbound…))`, scaled by the frozen
//   `s_{m_k}` factor. Tables fold normally: `lo ^= clmul(r, hi ^ lo)`.
//
// Terminal. After `N` rounds with final challenges `(r_0,…,r_{N-1})`:
// for pair `k`, define `s_k^final = ∏_{j<m_k}(1 + r_j)` (≡ 1 when
// `m_k = 0`). The verifier's final-claim identity is
//
//     claim(r) = Σ_k s_k^final · A_k(r_low_k) · B_k(r_low_k)
//
// where `r_low_k = (r_{m_k},…,r_{N-1})` in fold order (i.e. the last
// `n_k` challenges as the sumcheck emitted them; caller reverses when
// feeding into hypercube MLE eval).
//
// Compatibility. When `n_k = N` for every pair, `m_k = 0` for all `k`,
// no pair ever enters high mode, and the oracle XOR-reduction + table
// fold is byte-identical to the uniform path — `prove_multipoint_sumcheck`
// remains a correct implementation of the zero-`m_k` case.

/// Scalar factor `∏_{j<m}(1 + r_hi[j])` where `r_hi` = first `m`
/// challenges (in fold order). Empty product ⇒ `Block128::ONE`.
/// Exposed so the outer verifier can reconstruct each mixed-length
/// pair's terminal contribution without recomputing the lift.
pub fn mixed_high_scalar(challenges: &[Block128], m: usize) -> Block128 {
    debug_assert!(m <= challenges.len());
    let mut acc = Block128::ONE;
    for r in &challenges[..m] {
        acc *= Block128::ONE + *r;
    }
    acc
}

/// Mixed-length variant of [`prove_multipoint_sumcheck`]. Each pair
/// `(pairs_a[k], pairs_b[k])` has length `2^{n_vars[k]}` with
/// `n_vars[k] ≤ N` where `N = n_vars.iter().max()`. Runs `N`
/// degree-2 rounds against the MLE lift described in the module
/// header. Returns the `N` round polynomials and the challenge
/// vector (highest-var-first, length `N`). Uniform input
/// (`n_vars[k] == N` for every `k`) produces a transcript and round
/// sequence byte-identical to the uniform prover.
pub fn prove_multipoint_sumcheck_mixed(
    pairs_a: Vec<Vec<Block128>>,
    pairs_b: Vec<&[Block128]>,
    n_vars: &[usize],
    target: Block128,
    channel: &mut noid_fri::Channel,
) -> (Vec<RoundPoly>, Vec<Block128>) {
    assert!(
        !pairs_a.is_empty(),
        "multipoint-mixed: at least one pair required"
    );
    assert_eq!(
        pairs_a.len(),
        pairs_b.len(),
        "A and B pair counts must match"
    );
    assert_eq!(
        pairs_a.len(),
        n_vars.len(),
        "n_vars length must match pair count"
    );
    let n_max = *n_vars.iter().max().expect("non-empty n_vars") as usize;
    assert!(n_max >= 1, "multipoint-mixed: need at least one variable");
    for (k, (a, b)) in pairs_a.iter().zip(pairs_b.iter()).enumerate() {
        assert_eq!(
            a.len(),
            1 << n_vars[k],
            "pair {k}: pair_a length {} != 2^{} = {}",
            a.len(),
            n_vars[k],
            1usize << n_vars[k]
        );
        assert_eq!(
            b.len(),
            1 << n_vars[k],
            "pair {k}: pair_b length {} != 2^{} = {}",
            b.len(),
            n_vars[k],
            1usize << n_vars[k]
        );
        assert!(n_vars[k] <= n_max, "pair {k}: n_vars > n_max impossible");
    }

    use noid_core::hardware::{clmul_gcm, flat_to_tower_u128, tower_to_flat_u128};
    use rayon::prelude::*;

    let n_pairs = pairs_a.len();

    // Convert every pair table to flat basis once. Keep natural sizes.
    let mut pairs_flat: Vec<(Vec<u128>, Vec<u128>)> = pairs_a
        .into_par_iter()
        .zip(pairs_b.into_par_iter())
        .map(|(a, b)| {
            let a_flat: Vec<u128> = a.into_iter().map(|v| tower_to_flat_u128(v.0)).collect();
            let b_flat: Vec<u128> = b.iter().map(|v| tower_to_flat_u128(v.0)).collect();
            (a_flat, b_flat)
        })
        .collect();

    // Per-pair count of high rounds (`m_k = n_max - n_k`).
    let m_per_pair: Vec<usize> = n_vars.iter().map(|n| n_max - *n).collect();

    // Per-pair accumulating high scalar `s_k` in flat basis. Starts
    // at `1` (flat). Updated during a pair's high rounds, then frozen.
    let one_flat = tower_to_flat_u128(Block128::ONE.0);
    let two_flat = tower_to_flat_u128(Block128::from(2u8).0);
    // `1 + 2 = 3` in GF(2), flat. XOR of flat constants.
    let three_flat = one_flat ^ two_flat;
    let mut s_flat: Vec<u128> = vec![one_flat; n_pairs];

    // Whole-cube sum `T_k = Σ_z A_k(z) B_k(z)` in flat basis, for
    // pairs that have any high rounds. Computed once up front so we
    // don't recompute per round.
    let t_flat: Vec<u128> = (0..n_pairs)
        .into_par_iter()
        .map(|k| {
            if m_per_pair[k] == 0 {
                0u128
            } else {
                let (a, b) = &pairs_flat[k];
                let mut acc: u128 = 0;
                for j in 0..a.len() {
                    acc ^= clmul_gcm(a[j], b[j]);
                }
                acc
            }
        })
        .collect();

    let mut rounds: Vec<RoundPoly> = Vec::with_capacity(n_max);
    let mut challenges: Vec<Block128> = Vec::with_capacity(n_max);
    let mut claim = target;

    for round_idx in 0..n_max {
        // Build round oracle = Σ_k pair_k's contribution.
        let (p0_flat, p1_flat, p2_flat) = (0..n_pairs)
            .into_par_iter()
            .map(|k| {
                let m_k = m_per_pair[k];
                if round_idx < m_k {
                    // High mode: p = s · (1+X) · T_k.
                    // evals: p(0) = s·T, p(1) = 0, p(2) = s·3·T.
                    let s_t = clmul_gcm(s_flat[k], t_flat[k]);
                    let p0 = s_t;
                    let p1 = 0u128;
                    let p2 = clmul_gcm(three_flat, s_t);
                    (p0, p1, p2)
                } else {
                    // Low mode: standard product round, scaled by s_k.
                    let (a, b) = &pairs_flat[k];
                    let half = a.len() / 2;
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
                    let sk = s_flat[k];
                    (clmul_gcm(sk, s0), clmul_gcm(sk, s1), clmul_gcm(sk, s2))
                }
            })
            .reduce(
                || (0u128, 0u128, 0u128),
                |x, y| (x.0 ^ y.0, x.1 ^ y.1, x.2 ^ y.2),
            );

        let p0 = Block128::from(flat_to_tower_u128(p0_flat));
        let p1 = Block128::from(flat_to_tower_u128(p1_flat));
        let p2 = Block128::from(flat_to_tower_u128(p2_flat));
        debug_assert_eq!(p0 + p1, claim, "multipoint-mixed consistency failure");

        let rp = vec![p0, p1, p2];
        channel.observe_field_elems(&rp);
        let r = channel.get_random_point();
        let r_flat = tower_to_flat_u128(r.0);

        // Fold / update per pair.
        // - pairs still in high mode: update s_k ← s_k · (1 + r).
        // - pairs entering / in low mode: fold tables by r.
        // `one_flat ^ r_flat` = (1 + r) in flat basis.
        let one_plus_r_flat = one_flat ^ r_flat;
        pairs_flat
            .par_iter_mut()
            .enumerate()
            .for_each(|(k, (a, b))| {
                let m_k = m_per_pair[k];
                if round_idx < m_k {
                    // High round: no table fold. Scalar update handled
                    // below (non-parallel, one clmul per pair).
                    let _ = (a, b);
                } else {
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
                }
            });
        for k in 0..n_pairs {
            if round_idx < m_per_pair[k] {
                s_flat[k] = clmul_gcm(s_flat[k], one_plus_r_flat);
            }
        }

        claim = crate::lagrange_eval_at_pub(&rp, r);
        rounds.push(rp);
        challenges.push(r);
    }

    (rounds, challenges)
}

/// Mixed-length counterpart of [`verify_multipoint_sumcheck`]. Replays
/// `n_max` rounds and returns `(challenges, final_claim)`. The caller
/// is responsible for reconstructing the terminal identity
/// `Σ_k s_k^final · A_k(r_low_k) · B_k(r_low_k)` using
/// [`mixed_high_scalar`] per pair.
pub fn verify_multipoint_sumcheck_mixed(
    rounds: &[RoundPoly],
    target: Block128,
    channel: &mut noid_fri::Channel,
) -> Result<(Vec<Block128>, Block128), crate::VerifyError> {
    // Replay shape is identical to the uniform verifier — the proof
    // structure (N round polys × 3 evals) is the same; per-pair size
    // information is a public protocol constant the caller carries.
    verify_multipoint_sumcheck(rounds, target, channel)
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
        let (rounds, challenges) = prove_multipoint_sumcheck(pairs_a, pairs_b, target, &mut pch);

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
    fn mixed_length_pair_roundtrip() {
        // Two pairs: one at n = 4 (short), one at n = 6 (long).
        // n_max = 6; the short pair rides through 2 high rounds, then
        // 4 low rounds.
        let n_short = 4usize;
        let n_long = 6usize;
        let col_short = rand_vec(1 << n_short, 0x501);
        let col_long = rand_vec(1 << n_long, 0x502);
        let r_short = rand_vec(n_short, 0x601);
        let r_long = rand_vec(n_long, 0x602);

        let e_short = mle_at(&col_short, &r_short);
        let e_long = mle_at(&col_long, &r_long);
        let eq_short = eq_ind_partial_eval(&r_short);
        let eq_long = eq_ind_partial_eval(&r_long);

        let mut pch = Channel::new();
        let beta = pch.get_random_point();
        let target = e_short + beta * e_long;

        let scaled_long: Vec<Block128> = col_long.iter().map(|v| *v * beta).collect();
        let pairs_a = vec![eq_short.clone(), eq_long.clone()];
        let pairs_b: Vec<&[Block128]> = vec![col_short.as_slice(), scaled_long.as_slice()];
        let n_vars = vec![n_short, n_long];
        let (rounds, challenges) =
            prove_multipoint_sumcheck_mixed(pairs_a, pairs_b, &n_vars, target, &mut pch);
        assert_eq!(rounds.len(), n_long);
        assert_eq!(challenges.len(), n_long);

        let mut vch = Channel::new();
        let beta_v = vch.get_random_point();
        assert_eq!(beta, beta_v);
        let (challenges_v, final_claim) =
            verify_multipoint_sumcheck_mixed(&rounds, target, &mut vch).unwrap();
        assert_eq!(challenges, challenges_v);

        // Reconstruct terminal claim per pair. fold-order challenges
        // are highest-var-first; for pair k, the last n_k challenges
        // are its z-challenges (also highest-var-first). Reverse per
        // pair to get MLE eval point.
        let m_short = n_long - n_short;
        let r_short_low_fold: Vec<Block128> = challenges_v[m_short..].to_vec();
        let r_short_mle: Vec<Block128> = r_short_low_fold.iter().rev().cloned().collect();
        let r_long_mle: Vec<Block128> = challenges_v.iter().rev().cloned().collect();

        let a_short = mle_at(&eq_short, &r_short_mle);
        let b_short = mle_at(&col_short, &r_short_mle);
        let a_long = mle_at(&eq_long, &r_long_mle);
        let b_long = mle_at(&scaled_long, &r_long_mle);

        let s_short = mixed_high_scalar(&challenges_v, m_short);
        let s_long = mixed_high_scalar(&challenges_v, 0);
        assert_eq!(s_long, Block128::ONE);

        let expected = s_short * a_short * b_short + s_long * a_long * b_long;
        assert_eq!(final_claim, expected, "mixed terminal must reconstruct");

        // Cross-check: A_k(r_k) · B_k(r_k) ≟ eq(r_k, r_mle_k) · MLE(col_k)(r_mle_k).
        let eq_short_check = eq_ind(&r_short, &r_short_mle);
        let m_short_check = mle_at(&col_short, &r_short_mle);
        assert_eq!(a_short * b_short, eq_short_check * m_short_check);
        let eq_long_check = eq_ind(&r_long, &r_long_mle);
        let m_long_check = mle_at(&col_long, &r_long_mle);
        assert_eq!(a_long * b_long, eq_long_check * m_long_check * beta);
    }

    #[test]
    fn mixed_uniform_matches_original() {
        // When all pairs are uniform length, the mixed prover and
        // verifier must accept the same transcript the non-mixed
        // prover produces — this pins the "high-mode never triggers"
        // degenerate case.
        let n = 4usize;
        let len = 1 << n;
        let col0 = rand_vec(len, 0xAA1);
        let col1 = rand_vec(len, 0xAA2);
        let r_a = rand_vec(n, 0xAB1);
        let r_b = rand_vec(n, 0xAB2);

        let e0 = mle_at(&col0, &r_a);
        let e1 = mle_at(&col1, &r_b);
        let eq_a = eq_ind_partial_eval(&r_a);
        let eq_b = eq_ind_partial_eval(&r_b);

        let mut pch = Channel::new();
        let beta = pch.get_random_point();
        let target = e0 + beta * e1;
        let scaled_col1: Vec<Block128> = col1.iter().map(|v| *v * beta).collect();

        // Mixed path (all same length):
        let pairs_a = vec![eq_a.clone(), eq_b.clone()];
        let pairs_b: Vec<&[Block128]> = vec![col0.as_slice(), scaled_col1.as_slice()];
        let n_vars = vec![n, n];
        let (rounds_mixed, ch_mixed) =
            prove_multipoint_sumcheck_mixed(pairs_a, pairs_b, &n_vars, target, &mut pch);

        // Uniform path on a fresh channel — must yield byte-identical
        // round polys and challenges.
        let mut pch2 = Channel::new();
        let beta2 = pch2.get_random_point();
        assert_eq!(beta, beta2);
        let scaled_col1b: Vec<Block128> = col1.iter().map(|v| *v * beta2).collect();
        let pairs_a2 = vec![eq_a.clone(), eq_b.clone()];
        let pairs_b2: Vec<&[Block128]> = vec![col0.as_slice(), scaled_col1b.as_slice()];
        let (rounds_ref, ch_ref) = prove_multipoint_sumcheck(pairs_a2, pairs_b2, target, &mut pch2);

        assert_eq!(rounds_mixed, rounds_ref);
        assert_eq!(ch_mixed, ch_ref);
    }

    #[test]
    fn mixed_tampered_target_is_rejected() {
        let n_short = 3usize;
        let n_long = 5usize;
        let col_short = rand_vec(1 << n_short, 0x701);
        let col_long = rand_vec(1 << n_long, 0x702);
        let r_short = rand_vec(n_short, 0x801);
        let r_long = rand_vec(n_long, 0x802);
        let eq_short = eq_ind_partial_eval(&r_short);
        let eq_long = eq_ind_partial_eval(&r_long);
        let e_short = mle_at(&col_short, &r_short);
        let e_long = mle_at(&col_long, &r_long);

        let mut pch = Channel::new();
        let target = e_short + e_long;
        let pairs_a = vec![eq_short, eq_long];
        let pairs_b: Vec<&[Block128]> = vec![col_short.as_slice(), col_long.as_slice()];
        let n_vars = vec![n_short, n_long];
        let (rounds, _) =
            prove_multipoint_sumcheck_mixed(pairs_a, pairs_b, &n_vars, target, &mut pch);

        let mut vch = Channel::new();
        let res = verify_multipoint_sumcheck_mixed(&rounds, target + Block128::ONE, &mut vch);
        assert!(res.is_err(), "mixed: divergent target must be rejected");
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
