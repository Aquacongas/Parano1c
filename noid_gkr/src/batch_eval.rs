// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

#![allow(clippy::needless_range_loop)]

//! Stage G3.γ₂ — batch-evaluation sumcheck.
//!
//! Reduces `M` MLE-evaluation claims `(r_i, v_i)` on a **single**
//! multilinear polynomial `B` of length `2^n` to one point-value pair
//! `(r_B, v_B)` via a standard RLC + degree-2 sumcheck:
//!
//! ```text
//!   V := Σ_i α_i · v_i  with  α_i ← channel.squeeze()
//!   W(x) := Σ_i α_i · eq(r_i, x)
//!   H(x) := W(x) · B(x)
//!
//!   V == Σ_x H(x)   (by linearity of eq)
//!
//!   sumcheck H over n variables → (r_B, claim_B)
//!   verifier checks  claim_B == W(r_B) · v_B_claimed
//! ```
//!
//! Soundness: W(r_B) is recomputed by the verifier as
//! `Σ_i α_i · eq(r_i, r_B)`. `v_B = B(r_B)` is the reduced claim that
//! the caller discharges — in γ₂ by a native evaluation on the
//! concatenated boundary MLE; in γ₃ by a STARK multipoint opening on
//! the committed boundary column.
//!
//! Why a fresh primitive rather than reusing `product_sumcheck`:
//! `product_sumcheck` folds in an extra `eq(r, x)` factor (degree 3
//! per variable). Here the outer eq has been absorbed into `W`, so
//! `H = W · B` is degree 2 per variable, one less round polynomial
//! coefficient per round.

use std::sync::OnceLock;

use noid_core::mle::eq::eq_ind;
use noid_core::mle::fold::fold_highest_var_par;
use noid_core::transcript::FiatShamir;
use noid_core::{Block128, TowerField};
use rayon::prelude::*;

/// Inverse Lagrange denominators at `{0,1,2}`. Cached so per-round
/// `evaluate` is invert-free in the hot path.
fn denom_inv_3() -> &'static [Block128; 3] {
    static CACHE: OnceLock<[Block128; 3]> = OnceLock::new();
    CACHE.get_or_init(|| {
        let mut out = [Block128::ZERO; 3];
        for k in 0..3 {
            let xk = Block128::from(k as u128);
            let mut d = Block128::ONE;
            for j in 0..3 {
                if j == k {
                    continue;
                }
                d *= xk + Block128::from(j as u128);
            }
            out[k] = d.invert();
        }
        out
    })
}

const PAR_THRESHOLD: usize = 64;

/// One round of the degree-2 batch-eval sumcheck, stored as its
/// evaluations at `X = 0, 1, 2`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BatchEvalRound {
    pub evals: [Block128; 3],
}

impl BatchEvalRound {
    #[inline]
    pub fn sum_at_0_plus_1(&self) -> Block128 {
        self.evals[0] + self.evals[1]
    }

    /// Lagrange-interpolate at `r` from evaluations at `{0,1,2}`.
    pub fn evaluate(&self, r: Block128) -> Block128 {
        lagrange_at_0_1_2(&self.evals, r)
    }
}

/// Lagrange evaluation at a single point from evals at `{0,1,2}`. Uses
/// the cached denominator inverses in `denom_inv_3()` so the hot path
/// is invert-free.
#[inline]
pub fn lagrange_at_0_1_2(evals: &[Block128; 3], r: Block128) -> Block128 {
    let denom_inv = denom_inv_3();
    let r0 = r + Block128::from(0u128);
    let r1 = r + Block128::from(1u128);
    let r2 = r + Block128::from(2u128);
    let n0 = r1 * r2;
    let n1 = r0 * r2;
    let n2 = r0 * r1;
    evals[0] * n0 * denom_inv[0] + evals[1] * n1 * denom_inv[1] + evals[2] * n2 * denom_inv[2]
}

/// One `(r, v)` MLE-evaluation claim on the shared target MLE `B`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvalClaim {
    pub point: Vec<Block128>,
    pub value: Block128,
}

/// Proof object: one round poly per sumcheck variable plus the final
/// reduced `(r_B, v_B)` is derived by the verifier from the transcript
/// and the last round's final claim, so only the round polys and the
/// prover's `b_final` need to ship.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BatchEvalProof {
    pub rounds: Vec<BatchEvalRound>,
    /// `b_final = B(r_B)`. Verifier cross-checks against
    /// `final_claim / W(r_B)`; caller discharges this against the
    /// committed `B`.
    pub b_final: Block128,
}

impl BatchEvalProof {
    /// Raw field-element byte size: `rounds.len() * 3` degree-2 round
    /// evals plus `b_final`, 16 bytes each.
    pub fn byte_len(&self) -> usize {
        self.rounds.len() * 3 * 16 + 16
    }
}

/// Output of a successful verify.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchEvalReduction {
    /// `r_B` — the sumcheck's terminal point, in variable order.
    pub point: Vec<Block128>,
    /// `v_B = B(r_B)` as claimed by the prover and telescope-consistent.
    pub value: Block128,
}

#[allow(dead_code)]
fn fold_inplace(tbl: &mut Vec<Block128>, r: Block128) {
    fold_highest_var_par(tbl, r);
}

/// Flat-basis fold: folds a `Vec<u128>` table in place using `clmul_gcm` (~4 ns/mul).
/// ~7x faster than the tower-basis `fold_highest_var_par`.
fn fold_flat(tbl: &mut Vec<u128>, r_flat: u128) {
    use noid_core::hardware::clmul_gcm;
    let half = tbl.len() / 2;
    if half >= 1024 {
        let (lo, hi) = tbl.split_at_mut(half);
        lo.par_iter_mut().zip(hi.par_iter()).for_each(|(l, &h)| {
            *l ^= clmul_gcm(r_flat, *l ^ h);
        });
    } else {
        for j in 0..half {
            tbl[j] ^= clmul_gcm(r_flat, tbl[j] ^ tbl[j + half]);
        }
    }
    tbl.truncate(half);
}

/// Build `W(x)` table in flat (GCM) basis using clmul_gcm — ~7x faster
/// than the tower-basis version.
fn build_w_table_flat(claims: &[EvalClaim], alphas: &[Block128], n: usize) -> Vec<u128> {
    use noid_core::hardware::{clmul_gcm, tower_to_flat_u128};
    debug_assert_eq!(claims.len(), alphas.len());
    let len = 1usize << n;
    claims
        .par_iter()
        .zip(alphas.par_iter())
        .map(|(claim, &alpha)| {
            let alpha_flat = tower_to_flat_u128(alpha.0);
            let point_flat: Vec<u128> = claim
                .point
                .iter()
                .map(|v| tower_to_flat_u128(v.0))
                .collect();
            let mut eq: Vec<u128> = Vec::with_capacity(len);
            eq.push(alpha_flat);
            for &r_flat in &point_flat {
                let cur = eq.len();
                for j in 0..cur {
                    let prod = clmul_gcm(eq[j], r_flat);
                    eq[j] ^= prod; // subtraction = addition in char 2
                    eq.push(prod);
                }
            }
            debug_assert_eq!(eq.len(), len);
            eq
        })
        .reduce(
            || vec![0u128; len],
            |mut a, b| {
                a.iter_mut().zip(b.iter()).for_each(|(ai, bi)| *ai ^= bi);
                a
            },
        )
}

/// Build `W(x)` table in tower (Block128) basis. Used for small tables.
#[allow(dead_code)]
fn build_w_table(claims: &[EvalClaim], alphas: &[Block128], n: usize) -> Vec<Block128> {
    debug_assert_eq!(claims.len(), alphas.len());
    let len = 1usize << n;
    claims
        .par_iter()
        .zip(alphas.par_iter())
        .map(|(claim, &alpha)| {
            debug_assert_eq!(claim.point.len(), n);
            let mut eq: Vec<Block128> = Vec::with_capacity(len);
            eq.push(alpha);
            for &r_i in &claim.point {
                let cur = eq.len();
                for j in 0..cur {
                    let prod = eq[j] * r_i;
                    eq[j] -= prod;
                    eq.push(prod);
                }
            }
            debug_assert_eq!(eq.len(), len);
            eq
        })
        .reduce(
            || vec![Block128::ZERO; len],
            |mut a, b| {
                for (ai, bi) in a.iter_mut().zip(b.iter()) {
                    *ai += *bi;
                }
                a
            },
        )
}

/// Flat-basis round polynomial evaluation. Uses clmul_gcm (~4 ns/mul) vs
/// Block128 mul (~30 ns). Returns evaluations at X=0,1,2 as u128 (flat basis).
fn eval_round_flat(w: &[u128], b: &[u128], half: usize) -> [u128; 3] {
    use noid_core::hardware::clmul_gcm;
    let f2_flat = noid_core::hardware::tower_to_flat_u128(noid_core::Block128::from(2u128).0);
    let per_entry = |j: usize| -> [u128; 3] {
        let w_lo = w[j];
        let w_hi = w[j + half];
        let b_lo = b[j];
        let b_hi = b[j + half];
        let dw = w_lo ^ w_hi;
        let db = b_lo ^ b_hi;
        let w2 = w_lo ^ clmul_gcm(f2_flat, dw);
        let b2 = b_lo ^ clmul_gcm(f2_flat, db);
        [
            clmul_gcm(w_lo, b_lo),
            clmul_gcm(w_hi, b_hi),
            clmul_gcm(w2, b2),
        ]
    };
    if half >= PAR_THRESHOLD {
        (0..half).into_par_iter().map(per_entry).reduce(
            || [0u128; 3],
            |a, b| [a[0] ^ b[0], a[1] ^ b[1], a[2] ^ b[2]],
        )
    } else {
        let mut acc = [0u128; 3];
        for j in 0..half {
            let p = per_entry(j);
            acc[0] ^= p[0];
            acc[1] ^= p[1];
            acc[2] ^= p[2];
        }
        acc
    }
}

/// Evaluate `W(r) = Σ_i α_i · eq(r_i, r)` without materialising the table.
fn evaluate_w_at(claims: &[EvalClaim], alphas: &[Block128], r: &[Block128]) -> Block128 {
    debug_assert_eq!(claims.len(), alphas.len());
    let mut acc = Block128::ZERO;
    for (claim, &alpha) in claims.iter().zip(alphas.iter()) {
        debug_assert_eq!(claim.point.len(), r.len());
        acc += alpha * eq_ind(&claim.point, r);
    }
    acc
}

/// Squeeze one RLC challenge per claim.
fn squeeze_alphas<T: FiatShamir<Block128>>(channel: &mut T, m: usize) -> Vec<Block128> {
    (0..m).map(|_| channel.squeeze()).collect()
}

/// Absorb all claim points and values into the channel so `α_i` are
/// bound to the exact set of claims being batched.
fn absorb_claims<T: FiatShamir<Block128>>(channel: &mut T, claims: &[EvalClaim]) {
    for c in claims {
        for e in &c.point {
            channel.absorb(*e);
        }
        channel.absorb(c.value);
    }
}

/// Honest prover.
///
/// `b`: length-`2^n` table of the target MLE. Must be the same table
/// whose claims are being discharged.
/// `claims`: the M `(r_i, v_i)` claims.
/// `channel`: shared Fiat-Shamir channel.
///
/// Returns the proof and the `(r_B, v_B)` reduction so callers can
/// feed it into the next protocol layer.
pub fn prove_batch_eval<T: FiatShamir<Block128>>(
    b: &[Block128],
    claims: &[EvalClaim],
    channel: &mut T,
) -> (BatchEvalProof, BatchEvalReduction) {
    let n = b.len().trailing_zeros() as usize;
    assert_eq!(b.len(), 1 << n);
    assert!(!claims.is_empty());
    for c in claims {
        assert_eq!(c.point.len(), n);
    }

    absorb_claims(channel, claims);
    let alphas = squeeze_alphas(channel, claims.len());

    // Convert w and b to flat (GCM) basis for ~7x faster arithmetic.
    let mut w_flat = build_w_table_flat(claims, &alphas, n);
    let mut b_flat: Vec<u128> = {
        use noid_core::hardware::tower_to_flat_u128;
        use rayon::prelude::*;
        if b.len() >= 4096 {
            b.par_iter().map(|v| tower_to_flat_u128(v.0)).collect()
        } else {
            b.iter().map(|v| tower_to_flat_u128(v.0)).collect()
        }
    };

    // Initial claim: V = Σ α_i · v_i.
    let mut claim = Block128::ZERO;
    for (c, &a) in claims.iter().zip(alphas.iter()) {
        claim += a * c.value;
    }

    let mut rounds = Vec::with_capacity(n);
    let mut challenges = Vec::with_capacity(n);

    for _round in 0..n {
        let half = w_flat.len() / 2;
        // Evaluate round polynomial in flat basis, convert to tower for transcript.
        let evals_flat = eval_round_flat(&w_flat, &b_flat, half);
        let evals: [Block128; 3] =
            evals_flat.map(|v| Block128::from(noid_core::hardware::flat_to_tower_u128(v)));
        let re = BatchEvalRound { evals };

        debug_assert_eq!(re.sum_at_0_plus_1(), claim);

        for e in &re.evals {
            channel.absorb(*e);
        }
        let r_i = channel.squeeze();
        let r_i_flat = noid_core::hardware::tower_to_flat_u128(r_i.0);

        claim = re.evaluate(r_i);
        fold_flat(&mut w_flat, r_i_flat);
        fold_flat(&mut b_flat, r_i_flat);

        rounds.push(re);
        challenges.push(r_i);
    }

    debug_assert_eq!(w_flat.len(), 1);
    debug_assert_eq!(b_flat.len(), 1);
    let b_final = Block128::from(noid_core::hardware::flat_to_tower_u128(b_flat[0]));
    let w_final = Block128::from(noid_core::hardware::flat_to_tower_u128(w_flat[0]));
    debug_assert_eq!(claim, w_final * b_final);

    challenges.reverse();

    let proof = BatchEvalProof { rounds, b_final };
    let reduction = BatchEvalReduction {
        point: challenges.clone(),
        value: b_final,
    };
    (proof, reduction)
}

/// Honest verifier. Returns `Some(reduction)` on accept, `None` on
/// reject. The caller is responsible for discharging
/// `reduction.value == B(reduction.point)` against the commitment to
/// `B`.
pub fn verify_batch_eval<T: FiatShamir<Block128>>(
    proof: &BatchEvalProof,
    claims: &[EvalClaim],
    n: usize,
    channel: &mut T,
) -> Option<BatchEvalReduction> {
    if claims.is_empty() {
        return None;
    }
    for c in claims {
        if c.point.len() != n {
            return None;
        }
    }
    if proof.rounds.len() != n {
        return None;
    }

    absorb_claims(channel, claims);
    let alphas = squeeze_alphas(channel, claims.len());

    let mut claim = Block128::ZERO;
    for (c, &a) in claims.iter().zip(alphas.iter()) {
        claim += a * c.value;
    }

    let mut challenges = Vec::with_capacity(n);
    for re in &proof.rounds {
        if re.sum_at_0_plus_1() != claim {
            return None;
        }
        for e in &re.evals {
            channel.absorb(*e);
        }
        let r_i = channel.squeeze();
        claim = re.evaluate(r_i);
        challenges.push(r_i);
    }
    challenges.reverse();

    // Final check: claim == W(r_B) · b_final.
    let w_at = evaluate_w_at(claims, &alphas, &challenges);
    if claim != w_at * proof.b_final {
        return None;
    }

    Some(BatchEvalReduction {
        point: challenges,
        value: proof.b_final,
    })
}

#[allow(dead_code)]
fn eval_round_at_0_1_2(w: &[Block128], b: &[Block128], half: usize) -> [Block128; 3] {
    let f2 = Block128::from(2u128);
    let per_entry = |j: usize| -> [Block128; 3] {
        let w_lo = w[j];
        let w_hi = w[j + half];
        let b_lo = b[j];
        let b_hi = b[j + half];
        let d_w = w_lo + w_hi;
        let d_b = b_lo + b_hi;
        let w2 = w_lo + f2 * d_w;
        let b2 = b_lo + f2 * d_b;
        [w_lo * b_lo, w_hi * b_hi, w2 * b2]
    };
    if half >= PAR_THRESHOLD {
        (0..half).into_par_iter().map(per_entry).reduce(
            || [Block128::ZERO; 3],
            |a, b| [a[0] + b[0], a[1] + b[1], a[2] + b[2]],
        )
    } else {
        let mut acc = [Block128::ZERO; 3];
        for j in 0..half {
            let p = per_entry(j);
            acc[0] += p[0];
            acc[1] += p[1];
            acc[2] += p[2];
        }
        acc
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use noid_core::mle::evaluate::evaluate_slice;
    use noid_poseidon2b::channel::Poseidon2bChannel;
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};

    fn rand_vec(rng: &mut StdRng, n: usize) -> Vec<Block128> {
        (0..n).map(|_| Block128::from(rng.gen::<u128>())).collect()
    }

    fn fresh_channel(seed: u64) -> Poseidon2bChannel {
        let mut ch = Poseidon2bChannel::new();
        ch.absorb(Block128::from(seed as u128));
        ch
    }

    #[test]
    fn honest_roundtrip_single_claim() {
        let mut rng = StdRng::seed_from_u64(1);
        let n = 5;
        let b = rand_vec(&mut rng, 1 << n);
        let r0 = rand_vec(&mut rng, n);
        let v0 = evaluate_slice(&b, &r0);
        let claims = vec![EvalClaim {
            point: r0,
            value: v0,
        }];

        let mut cp = fresh_channel(7);
        let (proof, red_p) = prove_batch_eval(&b, &claims, &mut cp);

        let mut cv = fresh_channel(7);
        let red_v = verify_batch_eval(&proof, &claims, n, &mut cv).unwrap();
        assert_eq!(red_p, red_v);
        assert_eq!(red_v.value, evaluate_slice(&b, &red_v.point));
    }

    #[test]
    fn honest_roundtrip_many_claims() {
        let mut rng = StdRng::seed_from_u64(2);
        let n = 6;
        let b = rand_vec(&mut rng, 1 << n);
        let m = 17;
        let claims: Vec<EvalClaim> = (0..m)
            .map(|_| {
                let r = rand_vec(&mut rng, n);
                let v = evaluate_slice(&b, &r);
                EvalClaim { point: r, value: v }
            })
            .collect();

        let mut cp = fresh_channel(13);
        let (proof, red_p) = prove_batch_eval(&b, &claims, &mut cp);

        let mut cv = fresh_channel(13);
        let red_v = verify_batch_eval(&proof, &claims, n, &mut cv).unwrap();
        assert_eq!(red_p, red_v);
        assert_eq!(red_v.value, evaluate_slice(&b, &red_v.point));
    }

    #[test]
    fn forged_verifier_claim_rejected() {
        // Prover runs honestly. Verifier is handed a claim vector with
        // one tampered `value`; its initial running claim forks, so
        // round 0's telescope `e0+e1 == claim` fails immediately.
        let mut rng = StdRng::seed_from_u64(3);
        let n = 5;
        let b = rand_vec(&mut rng, 1 << n);
        let r0 = rand_vec(&mut rng, n);
        let good = evaluate_slice(&b, &r0);
        let honest_claims = vec![EvalClaim {
            point: r0.clone(),
            value: good,
        }];

        let mut cp = fresh_channel(9);
        let (proof, _) = prove_batch_eval(&b, &honest_claims, &mut cp);

        let bad_claims = vec![EvalClaim {
            point: r0,
            value: good + Block128::from(1u128),
        }];
        let mut cv = fresh_channel(9);
        assert!(verify_batch_eval(&proof, &bad_claims, n, &mut cv).is_none());
    }

    #[test]
    fn tampered_b_final_rejected() {
        let mut rng = StdRng::seed_from_u64(4);
        let n = 5;
        let b = rand_vec(&mut rng, 1 << n);
        let r0 = rand_vec(&mut rng, n);
        let v0 = evaluate_slice(&b, &r0);
        let claims = vec![EvalClaim {
            point: r0,
            value: v0,
        }];

        let mut cp = fresh_channel(17);
        let (mut proof, _) = prove_batch_eval(&b, &claims, &mut cp);
        proof.b_final += Block128::from(1u128);

        let mut cv = fresh_channel(17);
        assert!(verify_batch_eval(&proof, &claims, n, &mut cv).is_none());
    }

    #[test]
    fn determinism() {
        let mut rng = StdRng::seed_from_u64(5);
        let n = 5;
        let b = rand_vec(&mut rng, 1 << n);
        let r0 = rand_vec(&mut rng, n);
        let v0 = evaluate_slice(&b, &r0);
        let claims = vec![EvalClaim {
            point: r0,
            value: v0,
        }];

        let mut c1 = fresh_channel(21);
        let (p1, _) = prove_batch_eval(&b, &claims, &mut c1);
        let mut c2 = fresh_channel(21);
        let (p2, _) = prove_batch_eval(&b, &claims, &mut c2);
        assert_eq!(p1, p2);
    }
}
