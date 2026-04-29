// SPDX-License-Identifier: Apache-2.0
// Adapted from binius64. Copyright (C) 2026 Paranoid.

//! Sum-Check Verifier for binary tower fields.

use super::prove::RoundPolynomial;
use crate::TowerField;

/// Verify a Sum-Check proof.
///
/// For each round polynomial u_i(X) checks: u_i(0) + u_i(1) == current_claim,
/// then advances claim = u_i(r_i).
///
/// Returns `Some(final_claim)` on success, `None` on any failure.
pub fn verify<F: TowerField>(
    round_polys: &[RoundPolynomial<F>],
    challenges: &[F],
    initial_claim: F,
) -> Option<F> {
    if round_polys.len() != challenges.len() {
        return None;
    }

    let mut claim = initial_claim;

    for (i, poly) in round_polys.iter().enumerate() {
        let computed_sum = poly.evaluate(F::ZERO) + poly.evaluate(F::ONE);
        if computed_sum != claim {
            return None;
        }
        claim = poly.evaluate(challenges[i]);
    }

    Some(claim)
}

#[cfg(test)]
mod tests {
    use super::super::prove::prove_single;
    use super::*;
    use crate::Block128;

    type F = Block128;

    /// Replay the prover's deterministic challenge derivation.
    fn replay_challenges(round_polys: &[RoundPolynomial<F>]) -> Vec<F> {
        let mut transcript: Vec<F> = Vec::new();
        let mut challenges = Vec::new();
        for poly in round_polys {
            for &c in &poly.coeffs {
                transcript.push(c);
            }
            let challenge = transcript.iter().fold(F::ZERO, |acc, &x| acc + x);
            challenges.push(challenge);
        }
        challenges
    }

    #[test]
    fn test_verify_accepts_valid_proof() {
        let evals = vec![F::ZERO, F::ONE, F::ONE, F::ZERO];
        let claimed_sum = evals.iter().fold(F::ZERO, |a, &b| a + b);
        let mut transcript = Vec::new();
        let (round_polys, final_eval) = prove_single(&evals, claimed_sum, &mut transcript);
        let challenges = replay_challenges(&round_polys);

        let result = verify(&round_polys, &challenges, claimed_sum);
        assert!(result.is_some(), "valid proof must be accepted");
        assert_eq!(result.unwrap(), final_eval);
    }

    #[test]
    fn test_verify_rejects_wrong_initial_claim() {
        let evals = vec![F::ZERO, F::ONE, F::ONE, F::ZERO];
        let claimed_sum = evals.iter().fold(F::ZERO, |a, &b| a + b);
        let mut transcript = Vec::new();
        let (round_polys, _) = prove_single(&evals, claimed_sum, &mut transcript);
        let challenges = replay_challenges(&round_polys);

        let result = verify(&round_polys, &challenges, F::ONE);
        assert!(result.is_none(), "wrong claim must be rejected");
    }

    #[test]
    fn test_verify_rejects_wrong_challenge_length() {
        let evals = vec![F::ZERO, F::ONE, F::ONE, F::ZERO];
        let claimed_sum = evals.iter().fold(F::ZERO, |a, &b| a + b);
        let mut transcript = Vec::new();
        let (round_polys, _) = prove_single(&evals, claimed_sum, &mut transcript);

        let result = verify(&round_polys, &[F::ONE], claimed_sum);
        assert!(result.is_none());
    }

    #[test]
    fn test_verify_larger_polynomial() {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let n = 6;
        let evals: Vec<F> = (0..(1 << n)).map(|_| F::from(rng.gen::<u128>())).collect();
        let claimed_sum = evals.iter().fold(F::ZERO, |a, &b| a + b);
        let mut transcript = Vec::new();
        let (round_polys, final_eval) = prove_single(&evals, claimed_sum, &mut transcript);
        let challenges = replay_challenges(&round_polys);

        let result = verify(&round_polys, &challenges, claimed_sum);
        assert!(result.is_some());
        assert_eq!(result.unwrap(), final_eval);
    }
}
