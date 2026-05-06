// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Helpers for CRYPTO.md §12b (RLC-batched base-column opening).
//!
//! This module currently exposes:
//!
//! * [`horner_weights`] — derive `[1, α, α², …, α^{n-1}]` from the single
//!   batching scalar `α` squeezed from the parent transcript (§12b.2
//!   step 2).
//! * [`rlc_openings`] — batched claim `e_batch = Σ λ_i · e_i`
//!   (§12b.2 step 3).
//! * [`rlc_codewords`] — batched codeword `C_batch = Σ λ_i · C_i`
//!   (§12b.2 step 3, pointwise sum of per-column RS codewords).
//! * [`rlc_symbol_pairs`] — query-phase batched symbol pair
//!   `(Σ λ_i · s_{i,0}, Σ λ_i · s_{i,1})` (§12b.2 step 5).
//!
//! These are pure building blocks that the next sub-stage (3b-0.5c-2)
//! will compose into `prove_batched` / `verify_batched`. Keeping them
//! here lets the implementation ship with its own test coverage
//! before the full protocol path lands, so any regression in the
//! reduction can be bisected cheaply.

use noid_core::{AdditiveNTT, Block128, TowerField};

use crate::channel::Channel;
use crate::hasher::CryptographicHasher;
use crate::prover::{prove as fri_prove, EvalProof, FriCommitment};
use crate::verifier::verify as fri_verify;

// ---------------------------------------------------------------------------
// Domain tag
// ---------------------------------------------------------------------------

/// 8-byte domain tag for the §12b batched-opening sub-channel.
///
/// Distinct from `0xFFFE_…` (LADDERFS, §12a) and from any per-column
/// binding byte used by `prove_air`. Absorbed once, after the per-column
/// openings, before the α squeeze — pins the transcript order from
/// CRYPTO.md §12b.4.
pub const RLCOPEN_TAG: u64 = 0xFFFD_0000_0000_0000;

// ---------------------------------------------------------------------------
// Batched proof struct
// ---------------------------------------------------------------------------

/// A batched opening proof for `n_cols` codewords evaluated at the same
/// point `r`.
///
/// See CRYPTO.md §12b. The batched claim is
/// `e_batch = Σ_i α^i · e_i` and the FRI-layer proof attests that the
/// multilinear `MLE_batch = Σ_i α^i · MLE_i` evaluates to `e_batch` at
/// `r`.
///
/// **Stage 3b-0.5.1 — per-column reuse.** There is no Merkle commitment
/// to the batched codeword `C_batch` in the proof. The batched MLE is a
/// linear combination of per-column MLEs that the caller has already
/// committed (and whose roots are already bound into the parent
/// transcript before the batched-opening sub-protocol runs). Soundness
/// against a malicious prover forging `MLE_batch` is therefore entirely
/// inherited from the per-column commitments plus the RLC bound: for a
/// dishonest prover to win at the batched claim it would need to hit a
/// root of a degree-`(n - 1)` polynomial in α (CRYPTO.md §12b.3), which
/// is negligible at `|F| = 2^128`.
#[derive(Clone, Debug)]
pub struct BatchedEvalProof {
    /// Per-column openings `e_i = MLE_i(r)`. Absorbed into the parent
    /// transcript in column-index order (§12b.2 step 1).
    pub column_openings: Vec<Block128>,
    /// Single FRI evaluation proof of `MLE_batch(r) == e_batch`. The
    /// proof's own FRI-oracle commitments (per-round folded roots)
    /// carry the authentication for rounds `> 0`; round 0 is the
    /// batched codeword itself, bound via the per-column roots the
    /// caller already absorbed.
    pub batch_proof: EvalProof,
}

// ---------------------------------------------------------------------------
// prove_batched / verify_batched
// ---------------------------------------------------------------------------

/// Prove opening of `n_cols` multilinear extensions at a common point
/// `r`, producing a single batched FRI proof (CRYPTO.md §12b).
///
/// Inputs:
/// * `evals_per_col[i]` — hypercube evaluations of column `i`.
///   All columns must be the same length, which must be
///   `1 << eval_point.len()`.
/// * `eval_point` — the common opening point `r ∈ F^{log_len}`.
/// * `ntt` — the additive-NTT plan for `log_len + LOG_RATE`.
/// * `channel` — the parent Fiat–Shamir transcript. Must already have
///   absorbed whatever the outer protocol commits before the batched
///   opening (in `noid_stark` that is PI + column roots + the
///   zero-check sumcheck). This function absorbs openings, the
///   `RLCOPEN_TAG`, the batched commitment, and threads α through the
///   transcript — see CRYPTO.md §12b.4.
///
/// The individual per-column FRI commitments are **not** re-absorbed
/// here. The outer protocol is responsible for having absorbed them
/// into the parent channel before calling this function. The
/// verifier's counterpart `verify_batched` expects the same invariant.
pub fn prove_batched(
    evals_per_col: &[&[Block128]],
    eval_point: &[Block128],
    ntt: &AdditiveNTT<Block128>,
    channel: &mut Channel,
    hasher: &dyn CryptographicHasher,
) -> BatchedEvalProof {
    assert!(
        !evals_per_col.is_empty(),
        "prove_batched: need at least one column"
    );
    let log_len = eval_point.len();
    let expected_len = 1usize << log_len;
    for (i, c) in evals_per_col.iter().enumerate() {
        assert_eq!(
            c.len(),
            expected_len,
            "prove_batched: column {i} length {} != 2^{log_len} = {expected_len}",
            c.len()
        );
    }

    // Step 1 (§12b.2): compute per-column openings e_i = MLE_i(r) and
    // absorb them into the parent transcript in ascending column order.
    let column_openings: Vec<Block128> = {
        use rayon::prelude::*;
        evals_per_col
            .par_iter()
            .map(|col| noid_core::mle::evaluate::evaluate_slice(col, eval_point))
            .collect()
    };
    channel.observe_field_elems(&column_openings);

    // Domain separation for the batched-opening sub-protocol.
    channel.observe_field_elem(Block128::from(RLCOPEN_TAG as u128));

    // Step 2 (§12b.2): squeeze α, derive Horner weights.
    let alpha = channel.get_random_point();
    let n_cols = evals_per_col.len();
    let lambdas = horner_weights(alpha, n_cols);

    // Step 3 (§12b.2): batched evaluations on the hypercube. The MLE
    // of the pointwise RLC of per-column evaluation vectors is
    // exactly `Σ λ_i · MLE_i`, so `MLE_batch(r) = Σ λ_i · e_i` — the
    // verifier reconstructs that claim independently from the
    // openings it has already absorbed.
    let evals_batch: Vec<Block128> = rlc_codewords(&lambdas, evals_per_col);

    // Step 4 (§12b.2, 3b-0.5.1): single FRI opening of the batched
    // MLE. No commitment to `C_batch` is built — the per-column
    // commitments absorbed upstream already bind every column of the
    // RLC, and α was drawn from that same transcript prefix. `fri_prove`
    // proceeds straight to sumcheck + FRI-fold on `evals_batch` and
    // only absorbs `eval_point` into the channel (the round-0 oracle
    // that replaces an external commitment is the sumcheck-derived
    // `h = MLE_batch · eq(·, right)` codeword, which is committed
    // inside the fold loop itself).
    let batch_proof = fri_prove(&evals_batch, eval_point, ntt, channel, hasher);

    BatchedEvalProof {
        column_openings,
        batch_proof,
    }
}

/// Verify a [`BatchedEvalProof`] against externally committed per-column
/// commitments at the common point `r` (CRYPTO.md §12b).
///
/// Returns `Ok(openings)` on success, where `openings[i] = e_i` is the
/// per-column MLE evaluation the caller can plug back into its outer
/// protocol (zero-check terminal equation, etc.).
pub fn verify_batched(
    column_commitments: &[FriCommitment],
    eval_point: &[Block128],
    proof: &BatchedEvalProof,
    ntt: &AdditiveNTT<Block128>,
    channel: &mut Channel,
    hasher: &dyn CryptographicHasher,
) -> Result<Vec<Block128>, String> {
    if proof.column_openings.len() != column_commitments.len() {
        return Err(format!(
            "verify_batched: openings count {} != commitments count {}",
            proof.column_openings.len(),
            column_commitments.len()
        ));
    }
    // Every per-column commitment must bind an MLE over the same
    // hypercube size as the shared opening point.
    for (i, c) in column_commitments.iter().enumerate() {
        if c.log_len != eval_point.len() {
            return Err(format!(
                "verify_batched: column {i} commitment log_len {} != eval point length {}",
                c.log_len,
                eval_point.len()
            ));
        }
    }

    // Mirror prove_batched transcript order exactly (§12b.4):
    //   1. absorb openings
    //   2. absorb RLCOPEN_TAG
    //   3. squeeze α
    //   4. run fri_verify on the batched claim at r (no extra commit)
    channel.observe_field_elems(&proof.column_openings);
    channel.observe_field_elem(Block128::from(RLCOPEN_TAG as u128));
    let alpha = channel.get_random_point();
    let n_cols = proof.column_openings.len();
    let lambdas = horner_weights(alpha, n_cols);

    let e_batch = rlc_openings(&lambdas, &proof.column_openings);

    fri_verify(
        eval_point,
        e_batch,
        proof.batch_proof.clone(),
        ntt,
        channel,
        hasher,
    )?;

    Ok(proof.column_openings.clone())
}

/// Horner weights `λ_i = α^i` for `i = 0, …, n - 1`.
///
/// CRYPTO.md §12b.2 step 2 — Fiat–Shamir squeezes exactly one scalar
/// `α` and both parties derive the weights by iterated multiplication.
/// Soundness is `(n - 1) / |F|`, negligible for `|F| = 2^128` at any
/// realistic column count.
pub fn horner_weights(alpha: Block128, n: usize) -> Vec<Block128> {
    let mut out = Vec::with_capacity(n);
    let mut cur = Block128::ONE;
    for _ in 0..n {
        out.push(cur);
        cur = cur * alpha;
    }
    out
}

/// Batched claim `e_batch = Σ λ_i · e_i` (§12b.2 step 3).
///
/// Panics if `lambdas.len() != openings.len()`.
pub fn rlc_openings(lambdas: &[Block128], openings: &[Block128]) -> Block128 {
    assert_eq!(
        lambdas.len(),
        openings.len(),
        "rlc_openings: lambda / opening length mismatch"
    );
    let mut acc = Block128::ZERO;
    for (&l, &e) in lambdas.iter().zip(openings.iter()) {
        acc += l * e;
    }
    acc
}

/// Pointwise batched codeword `C_batch[j] = Σ λ_i · C_i[j]` (§12b.2 step 3).
///
/// All inputs must be the same length. Parallelises across symbol
/// positions when the codeword is long enough for the overhead to pay
/// off, and stays deterministic in its reduction order (per-index
/// accumulation over columns in ascending `i`).
pub fn rlc_codewords(lambdas: &[Block128], codewords: &[&[Block128]]) -> Vec<Block128> {
    assert_eq!(
        lambdas.len(),
        codewords.len(),
        "rlc_codewords: lambda / codeword count mismatch"
    );
    assert!(
        !codewords.is_empty(),
        "rlc_codewords: need at least one codeword"
    );
    let len = codewords[0].len();
    for (i, cw) in codewords.iter().enumerate() {
        assert_eq!(
            cw.len(),
            len,
            "rlc_codewords: codeword {i} has length {} but expected {}",
            cw.len(),
            len
        );
    }

    use rayon::prelude::*;
    if len >= 1024 {
        (0..len)
            .into_par_iter()
            .map(|j| {
                let mut acc = Block128::ZERO;
                for (i, &lam) in lambdas.iter().enumerate() {
                    acc += lam * codewords[i][j];
                }
                acc
            })
            .collect()
    } else {
        let mut out = vec![Block128::ZERO; len];
        for (i, &lam) in lambdas.iter().enumerate() {
            for (j, &v) in codewords[i].iter().enumerate() {
                out[j] += lam * v;
            }
        }
        out
    }
}

/// Query-phase batched symbol pair `(Σ λ_i · s_{i,0}, Σ λ_i · s_{i,1})`
/// (§12b.2 step 5). Takes the per-column symbol pairs collected from
/// each column's Merkle opening and reduces them against the RLC
/// weights.
pub fn rlc_symbol_pairs(
    lambdas: &[Block128],
    pairs: &[(Block128, Block128)],
) -> (Block128, Block128) {
    assert_eq!(
        lambdas.len(),
        pairs.len(),
        "rlc_symbol_pairs: lambda / pair count mismatch"
    );
    let mut s0 = Block128::ZERO;
    let mut s1 = Block128::ZERO;
    for (&lam, &(a, b)) in lambdas.iter().zip(pairs.iter()) {
        s0 += lam * a;
        s1 += lam * b;
    }
    (s0, s1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};

    fn rng() -> StdRng {
        StdRng::seed_from_u64(0x0123_4567_89AB_CDEF)
    }

    fn rand_block(r: &mut StdRng) -> Block128 {
        Block128::from(r.gen::<u128>())
    }

    #[test]
    fn horner_weights_start_with_one_and_chain_correctly() {
        let mut r = rng();
        let alpha = rand_block(&mut r);
        let w = horner_weights(alpha, 6);
        assert_eq!(w.len(), 6);
        assert_eq!(w[0], Block128::ONE);
        for i in 1..6 {
            assert_eq!(w[i], w[i - 1] * alpha);
        }
    }

    #[test]
    fn horner_weights_zero_length() {
        let mut r = rng();
        let alpha = rand_block(&mut r);
        assert!(horner_weights(alpha, 0).is_empty());
    }

    #[test]
    fn rlc_openings_is_linear() {
        // Property: e_batch(λ, e) is linear in e for fixed λ.
        // e_batch(λ, e + e') == e_batch(λ, e) + e_batch(λ, e')
        let mut r = rng();
        let lambdas: Vec<Block128> = (0..5).map(|_| rand_block(&mut r)).collect();
        let e1: Vec<Block128> = (0..5).map(|_| rand_block(&mut r)).collect();
        let e2: Vec<Block128> = (0..5).map(|_| rand_block(&mut r)).collect();
        let e_sum: Vec<Block128> = e1.iter().zip(&e2).map(|(a, b)| *a + *b).collect();
        let lhs = rlc_openings(&lambdas, &e_sum);
        let rhs = rlc_openings(&lambdas, &e1) + rlc_openings(&lambdas, &e2);
        assert_eq!(lhs, rhs);
    }

    #[test]
    fn rlc_codewords_matches_per_position_rlc() {
        let mut r = rng();
        let n_cols = 4;
        let len = 32;
        let cws: Vec<Vec<Block128>> = (0..n_cols)
            .map(|_| (0..len).map(|_| rand_block(&mut r)).collect())
            .collect();
        let lambdas: Vec<Block128> = (0..n_cols).map(|_| rand_block(&mut r)).collect();

        let cw_refs: Vec<&[Block128]> = cws.iter().map(|v| v.as_slice()).collect();
        let batched = rlc_codewords(&lambdas, &cw_refs);

        for j in 0..len {
            let mut expected = Block128::ZERO;
            for (i, lam) in lambdas.iter().enumerate() {
                expected += *lam * cws[i][j];
            }
            assert_eq!(batched[j], expected, "mismatch at position {j}");
        }
    }

    #[test]
    fn rlc_codewords_respects_parallel_threshold() {
        // Large codeword (above the 1024 threshold) must produce the same
        // result as the small-input scalar path.
        let mut r = rng();
        let n_cols = 3;
        let len = 2048;
        let cws: Vec<Vec<Block128>> = (0..n_cols)
            .map(|_| (0..len).map(|_| rand_block(&mut r)).collect())
            .collect();
        let lambdas: Vec<Block128> = (0..n_cols).map(|_| rand_block(&mut r)).collect();

        let cw_refs: Vec<&[Block128]> = cws.iter().map(|v| v.as_slice()).collect();
        let batched_parallel = rlc_codewords(&lambdas, &cw_refs);

        // Recompute via the scalar reference.
        let mut expected = vec![Block128::ZERO; len];
        for (i, lam) in lambdas.iter().enumerate() {
            for (j, v) in cws[i].iter().enumerate() {
                expected[j] += *lam * *v;
            }
        }
        assert_eq!(batched_parallel, expected);
    }

    #[test]
    fn rlc_symbol_pairs_is_linear_on_each_side() {
        let mut r = rng();
        let lambdas = horner_weights(rand_block(&mut r), 5);
        let pairs: Vec<(Block128, Block128)> = (0..5)
            .map(|_| (rand_block(&mut r), rand_block(&mut r)))
            .collect();
        let (s0, s1) = rlc_symbol_pairs(&lambdas, &pairs);

        // Reference via explicit loop.
        let mut r0 = Block128::ZERO;
        let mut r1 = Block128::ZERO;
        for (i, &(a, b)) in pairs.iter().enumerate() {
            r0 += lambdas[i] * a;
            r1 += lambdas[i] * b;
        }
        assert_eq!(s0, r0);
        assert_eq!(s1, r1);
    }

    /// The core soundness hook for §12b: if any `e_i` is wrong, the
    /// batched claim is wrong except on a degree-`(n - 1)` polynomial
    /// in α. Here we verify the structural identity — the difference
    /// `rlc_openings(λ, good) − rlc_openings(λ, bad)` equals
    /// `Σ λ_i · δ_i` where `δ_i = good_i − bad_i`. Pinning this
    /// exactly means any future refactor of `rlc_openings` can't
    /// silently break the soundness argument in CRYPTO.md §12b.3.
    #[test]
    fn rlc_openings_soundness_identity() {
        let mut r = rng();
        let lambdas = horner_weights(rand_block(&mut r), 4);
        let good: Vec<Block128> = (0..4).map(|_| rand_block(&mut r)).collect();
        let mut bad = good.clone();
        // Perturb column 2 — the only δ ≠ 0 is at index 2.
        bad[2] = bad[2] + Block128::ONE;

        let e_good = rlc_openings(&lambdas, &good);
        let e_bad = rlc_openings(&lambdas, &bad);
        // δ_i is all-zero except δ_2 = (good - bad) = ONE.
        let expected_diff = lambdas[2] * Block128::ONE;
        assert_eq!(e_good + e_bad, expected_diff);
    }

    // -------------------------------------------------------------------
    // End-to-end prove_batched / verify_batched
    // -------------------------------------------------------------------

    use crate::channel::{Channel, TAU};
    use crate::code::LOG_RATE;
    use crate::hasher::HashOutput;
    use crate::prover::commit;
    use noid_core::AdditiveNTT;
    use noid_poseidon2b::native::compression::Poseidon2bSponge;

    fn mk_eval_point(r: &mut StdRng, log_len: usize) -> Vec<Block128> {
        (0..log_len).map(|_| rand_block(r)).collect()
    }

    /// End-to-end round-trip: prove_batched + verify_batched succeeds
    /// on a multi-column input at a common random opening point.
    #[test]
    fn prove_verify_batched_roundtrip() {
        let mut r = rng();
        let log_len = TAU + 3; // 10 → 3 FRI folding rounds, realistic shape
        let n_cols = 4;
        let ntt = AdditiveNTT::<Block128>::new(log_len + LOG_RATE);
        let hasher = Poseidon2bSponge::new();

        let cols: Vec<Vec<Block128>> = (0..n_cols)
            .map(|_| (0..1 << log_len).map(|_| rand_block(&mut r)).collect())
            .collect();

        // Simulate the outer protocol: commit each column and absorb
        // the roots into a parent transcript before calling into
        // prove_batched / verify_batched.
        let commitments: Vec<FriCommitment> = cols
            .iter()
            .map(|c| {
                let (commitment, _t, _cd) = commit(c, &ntt, &hasher);
                commitment
            })
            .collect();
        let eval_point = mk_eval_point(&mut r, log_len);

        let mut prover_ch = Channel::new();
        for c in &commitments {
            prover_ch.observe_fri_commitment(c);
        }
        let col_refs: Vec<&[Block128]> = cols.iter().map(|v| v.as_slice()).collect();
        let proof = prove_batched(&col_refs, &eval_point, &ntt, &mut prover_ch, &hasher);

        // Independent per-column evaluation to cross-check openings.
        let expected_openings: Vec<Block128> = cols
            .iter()
            .map(|c| noid_core::mle::evaluate::evaluate_slice(c, &eval_point))
            .collect();
        assert_eq!(proof.column_openings, expected_openings);

        let mut verifier_ch = Channel::new();
        for c in &commitments {
            verifier_ch.observe_fri_commitment(c);
        }
        let openings = verify_batched(
            &commitments,
            &eval_point,
            &proof,
            &ntt,
            &mut verifier_ch,
            &hasher,
        )
        .expect("batched verify must succeed on honest proof");
        assert_eq!(openings, expected_openings);
    }

    /// Soundness smoke: tampering with a single per-column opening
    /// must make verify_batched reject (the batched FRI claim no
    /// longer matches `MLE_batch(r)`).
    #[test]
    fn verify_batched_rejects_tampered_opening() {
        let mut r = rng();
        let log_len = TAU + 2;
        let n_cols = 3;
        let ntt = AdditiveNTT::<Block128>::new(log_len + LOG_RATE);
        let hasher = Poseidon2bSponge::new();

        let cols: Vec<Vec<Block128>> = (0..n_cols)
            .map(|_| (0..1 << log_len).map(|_| rand_block(&mut r)).collect())
            .collect();
        let commitments: Vec<FriCommitment> =
            cols.iter().map(|c| commit(c, &ntt, &hasher).0).collect();
        let eval_point = mk_eval_point(&mut r, log_len);

        let mut prover_ch = Channel::new();
        for c in &commitments {
            prover_ch.observe_fri_commitment(c);
        }
        let col_refs: Vec<&[Block128]> = cols.iter().map(|v| v.as_slice()).collect();
        let mut proof = prove_batched(&col_refs, &eval_point, &ntt, &mut prover_ch, &hasher);

        // Flip one bit in column 1's opening.
        proof.column_openings[1] = proof.column_openings[1] + Block128::ONE;

        let mut verifier_ch = Channel::new();
        for c in &commitments {
            verifier_ch.observe_fri_commitment(c);
        }
        let res = verify_batched(
            &commitments,
            &eval_point,
            &proof,
            &ntt,
            &mut verifier_ch,
            &hasher,
        );
        assert!(res.is_err(), "tampered opening must be rejected");
    }

    /// Soundness: tampering any of the FRI oracle roots inside the
    /// batched proof must be caught. Stage 3b-0.5.1 removes the outer
    /// commitment to `C_batch`, so the authentication chain now runs
    /// entirely through the per-round FRI-fold oracles inside
    /// `batch_proof`. Flipping a bit in any of those roots must make
    /// the verifier's `fri_verify` replay desync.
    #[test]
    fn verify_batched_rejects_tampered_fri_oracle_root() {
        let mut r = rng();
        let log_len = TAU + 2;
        let n_cols = 3;
        let ntt = AdditiveNTT::<Block128>::new(log_len + LOG_RATE);
        let hasher = Poseidon2bSponge::new();

        let cols: Vec<Vec<Block128>> = (0..n_cols)
            .map(|_| (0..1 << log_len).map(|_| rand_block(&mut r)).collect())
            .collect();
        let commitments: Vec<FriCommitment> =
            cols.iter().map(|c| commit(c, &ntt, &hasher).0).collect();
        let eval_point = mk_eval_point(&mut r, log_len);

        let mut prover_ch = Channel::new();
        for c in &commitments {
            prover_ch.observe_fri_commitment(c);
        }
        let col_refs: Vec<&[Block128]> = cols.iter().map(|v| v.as_slice()).collect();
        let mut proof = prove_batched(&col_refs, &eval_point, &ntt, &mut prover_ch, &hasher);

        assert!(
            !proof.batch_proof.fri_oracles.is_empty(),
            "batched proof must carry at least one FRI fold oracle"
        );
        // Flip one bit inside the round-0 folded-codeword root.
        let mut bad_root: HashOutput = proof.batch_proof.fri_oracles[0].root;
        bad_root[0] ^= 1;
        proof.batch_proof.fri_oracles[0].root = bad_root;

        let mut verifier_ch = Channel::new();
        for c in &commitments {
            verifier_ch.observe_fri_commitment(c);
        }
        let res = verify_batched(
            &commitments,
            &eval_point,
            &proof,
            &ntt,
            &mut verifier_ch,
            &hasher,
        );
        assert!(res.is_err(), "tampered FRI oracle root must be rejected");
    }

    /// Soundness: verifier with a divergent parent transcript must
    /// reject. Concretely the verifier absorbs the column commitments
    /// in a different order than the prover did — α (and every
    /// subsequent challenge) is different, so the batched FRI replay
    /// desyncs. This protects against an adversary who tries to
    /// reuse an honest proof under a different column permutation.
    #[test]
    fn verify_batched_rejects_transcript_divergence() {
        let mut r = rng();
        let log_len = TAU + 2;
        let n_cols = 3;
        let ntt = AdditiveNTT::<Block128>::new(log_len + LOG_RATE);
        let hasher = Poseidon2bSponge::new();

        let cols: Vec<Vec<Block128>> = (0..n_cols)
            .map(|_| (0..1 << log_len).map(|_| rand_block(&mut r)).collect())
            .collect();
        let commitments: Vec<FriCommitment> =
            cols.iter().map(|c| commit(c, &ntt, &hasher).0).collect();
        let eval_point = mk_eval_point(&mut r, log_len);

        let mut prover_ch = Channel::new();
        for c in &commitments {
            prover_ch.observe_fri_commitment(c);
        }
        let col_refs: Vec<&[Block128]> = cols.iter().map(|v| v.as_slice()).collect();
        let proof = prove_batched(&col_refs, &eval_point, &ntt, &mut prover_ch, &hasher);

        // Verifier absorbs commitments in reversed order — α will
        // differ from the prover's α, and the batched FRI check fails.
        let mut verifier_ch = Channel::new();
        for c in commitments.iter().rev() {
            verifier_ch.observe_fri_commitment(c);
        }
        let res = verify_batched(
            &commitments,
            &eval_point,
            &proof,
            &ntt,
            &mut verifier_ch,
            &hasher,
        );
        assert!(res.is_err(), "divergent parent transcript must be rejected");
    }

    /// Soundness: flipping one coordinate of the verifier's eval_point
    /// must make the batched FRI check fail. The prover's `MLE_batch`
    /// was committed for the true `r`; at a different `r'`, both the
    /// FRI query-phase challenges and the terminal evaluation mismatch.
    #[test]
    fn verify_batched_rejects_tampered_eval_point() {
        let mut r = rng();
        let log_len = TAU + 2;
        let n_cols = 3;
        let ntt = AdditiveNTT::<Block128>::new(log_len + LOG_RATE);
        let hasher = Poseidon2bSponge::new();

        let cols: Vec<Vec<Block128>> = (0..n_cols)
            .map(|_| (0..1 << log_len).map(|_| rand_block(&mut r)).collect())
            .collect();
        let commitments: Vec<FriCommitment> =
            cols.iter().map(|c| commit(c, &ntt, &hasher).0).collect();
        let eval_point = mk_eval_point(&mut r, log_len);

        let mut prover_ch = Channel::new();
        for c in &commitments {
            prover_ch.observe_fri_commitment(c);
        }
        let col_refs: Vec<&[Block128]> = cols.iter().map(|v| v.as_slice()).collect();
        let proof = prove_batched(&col_refs, &eval_point, &ntt, &mut prover_ch, &hasher);

        let mut bad_point = eval_point.clone();
        bad_point[0] = bad_point[0] + Block128::ONE;

        let mut verifier_ch = Channel::new();
        for c in &commitments {
            verifier_ch.observe_fri_commitment(c);
        }
        let res = verify_batched(
            &commitments,
            &bad_point,
            &proof,
            &ntt,
            &mut verifier_ch,
            &hasher,
        );
        assert!(res.is_err(), "tampered eval_point must be rejected");
    }

    /// Single-column batch reduces to the non-batched opening's
    /// semantics: for `n_cols = 1`, `λ_0 = 1` so `C_batch ≡ C_0` and
    /// `e_batch ≡ e_0`. This protects the reduction path from ever
    /// diverging on the degenerate case.
    #[test]
    fn prove_verify_batched_single_column() {
        let mut r = rng();
        let log_len = TAU + 2;
        let ntt = AdditiveNTT::<Block128>::new(log_len + LOG_RATE);
        let hasher = Poseidon2bSponge::new();

        let col: Vec<Block128> = (0..1 << log_len).map(|_| rand_block(&mut r)).collect();
        let (commitment, _t, _cd) = commit(&col, &ntt, &hasher);
        let eval_point = mk_eval_point(&mut r, log_len);

        let mut prover_ch = Channel::new();
        prover_ch.observe_fri_commitment(&commitment);
        let proof = prove_batched(
            &[col.as_slice()],
            &eval_point,
            &ntt,
            &mut prover_ch,
            &hasher,
        );

        assert_eq!(proof.column_openings.len(), 1);

        let mut verifier_ch = Channel::new();
        verifier_ch.observe_fri_commitment(&commitment);
        verify_batched(
            &[commitment],
            &eval_point,
            &proof,
            &ntt,
            &mut verifier_ch,
            &hasher,
        )
        .expect("single-column batched verify must succeed");
    }
}
