// SPDX-License-Identifier: Apache-2.0
// Adapted from binius64. Copyright (C) 2026 Paranoid.

//! Sum-Check Prover for binary tower fields.
//!
//! For each of `n_vars` rounds:
//!   1. Compute the degree-2 univariate round polynomial.
//!   2. Emit coefficients to the transcript.
//!   3. Derive a challenge and fold the MLE in-place.

use super::super::mle::fold::fold_highest_var_inplace;
use crate::{Block128, TowerField};

/// A degree-2 univariate polynomial stored as [c0, c1, c2]: c0 + c1*X + c2*X^2.
#[derive(Debug, Clone, PartialEq)]
pub struct RoundPolynomial<F> {
    pub coeffs: [F; 3],
}

impl<F: TowerField> RoundPolynomial<F> {
    /// Evaluate using Horner's method: c0 + x*(c1 + x*c2).
    pub fn evaluate(&self, x: F) -> F {
        self.coeffs[0] + x * (self.coeffs[1] + x * self.coeffs[2])
    }

    /// Full Lagrange interpolation through (0, e0), (1, e1), (field(2), e2).
    ///
    /// Solving the 3x3 system in the field:
    ///   c0 = e0
    ///   c1 + c2 = e0 + e1
    ///   c2*(f2 + f4) = e2 + e0 + (e0+e1)*f2    where f2=field(2), f4=f2*f2
    pub fn from_three_evals_field(e0: F, e1: F, e2: F) -> Self {
        let f2 = F::from(2u8);
        let f4 = f2 * f2;
        let c0 = e0;
        let lhs = e0 + e1; // c1 + c2
        let rhs = e2 + e0 + lhs * f2;
        let c2 = rhs * (f2 + f4).invert();
        let c1 = lhs + c2;
        Self {
            coeffs: [c0, c1, c2],
        }
    }
}

/// Run the sumcheck prover for a single multilinear polynomial.
///
/// `evals`       — evaluations over the boolean hypercube {0,1}^n, length 2^n.
/// `claimed_sum` — alleged sum of all evaluations.
/// `transcript`  — round poly coefficients are appended here; challenges are
///                 derived as the running field-sum of all transcript elements.
///
/// Returns `(round_polys, final_eval)`.
pub fn prove_single<F: TowerField>(
    evals: &[F],
    claimed_sum: F,
    transcript: &mut Vec<F>,
) -> (Vec<RoundPolynomial<F>>, F) {
    let n = evals.len().trailing_zeros() as usize;
    assert_eq!(evals.len(), 1 << n, "evals length must be a power of 2");
    assert!(n > 0, "need at least 1 variable");

    let mut current_evals = evals.to_vec();
    let mut round_polys = Vec::with_capacity(n);
    let _claim = claimed_sum;

    for _round in 0..n {
        let half = current_evals.len() / 2;
        let f2 = F::from(2u8);

        let mut u0 = F::ZERO;
        let mut u1 = F::ZERO;
        let mut u2 = F::ZERO;
        for j in 0..half {
            let v_lo = current_evals[j];
            let v_hi = current_evals[j + half];
            u0 += v_lo;
            u1 += v_hi;
            u2 += v_lo * (F::ONE - f2) + v_hi * f2;
        }

        let round_poly = RoundPolynomial::from_three_evals_field(u0, u1, u2);
        round_polys.push(round_poly.clone());

        for &c in &round_poly.coeffs {
            transcript.push(c);
        }

        let challenge = transcript.iter().fold(F::ZERO, |acc, &x| acc + x);
        let _claim = round_poly.evaluate(challenge);
        fold_highest_var_inplace(&mut current_evals, challenge);
    }

    assert_eq!(current_evals.len(), 1);
    (round_polys, current_evals[0])
}

// ---------------------------------------------------------------------------
// Packed Block128 variant
// ---------------------------------------------------------------------------

use crate::hardware::tower_to_flat_u128;
use crate::packed::{pack_slice_mut, PackedBlock128, PACKED_LANES};
use rayon::prelude::*;

/// Minimum number of packed elements to justify Rayon overhead.
const PARALLEL_THRESHOLD_PACKED: usize = 256;

/// Packed sumcheck prover for Block128.
///
/// Identical API to `prove_single`, but uses packed XOR / scalar-mul
/// for the per-round fold when the polynomial is large enough.
pub fn prove_single_packed(
    evals: &[Block128],
    claimed_sum: Block128,
    transcript: &mut Vec<Block128>,
) -> (Vec<RoundPolynomial<Block128>>, Block128) {
    let n = evals.len().trailing_zeros() as usize;
    assert_eq!(evals.len(), 1 << n, "evals length must be a power of 2");
    assert!(n > 0, "need at least 1 variable");

    let mut current_evals = evals.to_vec();
    let mut round_polys = Vec::with_capacity(n);
    let _claim = claimed_sum;

    use crate::hardware::{clmul_gcm, flat_to_tower_u128};
    // Minimum `half` to justify rayon parallelism on the round-poly
    // accumulator. Below this the fold/reduce overhead dominates.
    const SUMCHECK_PAR_THRESHOLD: usize = 1 << 12;
    for _round in 0..n {
        let half = current_evals.len() / 2;
        let f2 = Block128::from(2u8);
        // Flat-basis constants used inside the u2 accumulator.
        let c_lo_flat = tower_to_flat_u128((Block128::ONE - f2).0);
        let c_hi_flat = tower_to_flat_u128(f2.0);

        // XOR sums and the flat-basis CLMUL share the same input, so only
        // convert each element to flat once and accumulate both sums (u0,
        // u1) and u2 (via CLMUL) in flat. Convert u0, u1, u2 back at the
        // end — three matrix applies per round instead of `half` tower muls.
        let (lo_half, hi_half) = current_evals.split_at(half);
        let (u0_flat, u1_flat, u2_flat) = if half >= SUMCHECK_PAR_THRESHOLD {
            lo_half
                .par_iter()
                .zip(hi_half.par_iter())
                .fold(
                    || (0u128, 0u128, 0u128),
                    |(a0, a1, a2), (v_lo, v_hi)| {
                        let v_lo_flat = tower_to_flat_u128(v_lo.0);
                        let v_hi_flat = tower_to_flat_u128(v_hi.0);
                        (
                            a0 ^ v_lo_flat,
                            a1 ^ v_hi_flat,
                            a2 ^ clmul_gcm(v_lo_flat, c_lo_flat) ^ clmul_gcm(v_hi_flat, c_hi_flat),
                        )
                    },
                )
                .reduce(
                    || (0u128, 0u128, 0u128),
                    |(a0, a1, a2), (b0, b1, b2)| (a0 ^ b0, a1 ^ b1, a2 ^ b2),
                )
        } else {
            let mut u0_flat: u128 = 0;
            let mut u1_flat: u128 = 0;
            let mut u2_flat: u128 = 0;
            for j in 0..half {
                let v_lo_flat = tower_to_flat_u128(lo_half[j].0);
                let v_hi_flat = tower_to_flat_u128(hi_half[j].0);
                u0_flat ^= v_lo_flat;
                u1_flat ^= v_hi_flat;
                u2_flat ^= clmul_gcm(v_lo_flat, c_lo_flat) ^ clmul_gcm(v_hi_flat, c_hi_flat);
            }
            (u0_flat, u1_flat, u2_flat)
        };
        let u0 = Block128(flat_to_tower_u128(u0_flat));
        let u1 = Block128(flat_to_tower_u128(u1_flat));
        let u2 = Block128(flat_to_tower_u128(u2_flat));

        let round_poly = RoundPolynomial::from_three_evals_field(u0, u1, u2);
        round_polys.push(round_poly.clone());

        for &c in &round_poly.coeffs {
            transcript.push(c);
        }

        let challenge = transcript.iter().fold(Block128::ZERO, |acc, &x| acc + x);
        let _claim = round_poly.evaluate(challenge);

        // Packed fold
        let can_use_packed = if PACKED_LANES == 1 {
            true
        } else {
            half.is_multiple_of(PACKED_LANES) && half >= PACKED_LANES
        };
        if can_use_packed {
            fold_highest_var_packed_inplace(&mut current_evals, challenge, half);
        } else {
            fold_highest_var_inplace(&mut current_evals, challenge);
        }
    }

    assert_eq!(current_evals.len(), 1);
    (round_polys, current_evals[0])
}

/// Fold the highest variable in-place using packed operations.
///
/// `half` is current_evals.len() / 2.  The lower `half` elements are
/// updated in packed form; the vector is then truncated.
pub fn fold_highest_var_packed_inplace(
    current_evals: &mut Vec<Block128>,
    challenge: Block128,
    half: usize,
) {
    let packed = pack_slice_mut(&mut current_evals[..2 * half]);
    let packed_half = packed.len() / 2;
    let challenge_flat = tower_to_flat_u128(challenge.0);

    // XOR is basis-agnostic, so we can convert each packed lane to flat
    // basis once per fold iteration (instead of once per CLMUL inside
    // scalar_mul) and convert back after the linear combination.
    let fold_one = |lo: &mut PackedBlock128, hi: PackedBlock128| {
        let lo_flat = lo.to_flat();
        let hi_flat = hi.to_flat();
        let diff = hi_flat.xor(lo_flat);
        let scaled = diff.flat_scalar_mul(challenge_flat);
        let new_lo_flat = lo_flat.xor(scaled);
        *lo = new_lo_flat.to_tower();
    };

    if packed_half >= PARALLEL_THRESHOLD_PACKED {
        let (lo, hi) = packed.split_at_mut(packed_half);
        lo.par_iter_mut()
            .zip(hi.par_iter())
            .for_each(|(lo_val, &hi_val)| fold_one(lo_val, hi_val));
    } else {
        for i in 0..packed_half {
            let hi = packed[i + packed_half];
            fold_one(&mut packed[i], hi);
        }
    }

    current_evals.truncate(half);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Block128;

    type F = Block128;

    #[test]
    fn test_from_three_evals_field_roundtrip() {
        let e0 = F::from(5u8);
        let e1 = F::from(9u8);
        let e2 = F::from(3u8);
        let poly = RoundPolynomial::from_three_evals_field(e0, e1, e2);
        assert_eq!(poly.evaluate(F::ZERO), e0);
        assert_eq!(poly.evaluate(F::ONE), e1);
        assert_eq!(poly.evaluate(F::from(2u8)), e2);
    }

    #[test]
    fn test_prove_single_sum_consistency() {
        let evals = vec![F::ZERO, F::ONE, F::ONE, F::ZERO];
        let claimed_sum = evals.iter().fold(F::ZERO, |a, &b| a + b);
        let mut transcript = Vec::new();
        let (round_polys, _) = prove_single(&evals, claimed_sum, &mut transcript);
        assert_eq!(round_polys.len(), 2);
        let rp0 = &round_polys[0];
        assert_eq!(rp0.evaluate(F::ZERO) + rp0.evaluate(F::ONE), claimed_sum);
    }

    #[test]
    fn test_prove_single_larger() {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let n = 4;
        let evals: Vec<F> = (0..(1 << n)).map(|_| F::from(rng.gen::<u128>())).collect();
        let claimed_sum = evals.iter().fold(F::ZERO, |a, &b| a + b);
        let mut transcript = Vec::new();
        let (round_polys, _) = prove_single(&evals, claimed_sum, &mut transcript);
        assert_eq!(round_polys.len(), n);
        assert_eq!(
            round_polys[0].evaluate(F::ZERO) + round_polys[0].evaluate(F::ONE),
            claimed_sum
        );
    }

    #[test]
    fn test_prove_single_packed_matches_scalar() {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let n = 6; // 64 elements, fits nicely in packed lanes
        let evals: Vec<F> = (0..(1 << n)).map(|_| F::from(rng.gen::<u128>())).collect();
        let claimed_sum = evals.iter().fold(F::ZERO, |a, &b| a + b);

        let mut transcript_scalar = Vec::new();
        let (scalar_polys, scalar_final) =
            prove_single(&evals, claimed_sum, &mut transcript_scalar);

        let mut transcript_packed = Vec::new();
        let (packed_polys, packed_final) =
            prove_single_packed(&evals, claimed_sum, &mut transcript_packed);

        assert_eq!(scalar_final, packed_final);
        assert_eq!(scalar_polys.len(), packed_polys.len());
        for (s, p) in scalar_polys.iter().zip(packed_polys.iter()) {
            assert_eq!(s.coeffs, p.coeffs);
        }
        assert_eq!(transcript_scalar, transcript_packed);
    }
}
