// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Stage G1b.α tests — product sumcheck primitive.
//!
//! The primitive reduces `v = Σ_x eq(r, x) · A(x) · B(x)` to two
//! smaller claims `(a, b) = (A(r'), B(r'))`. Honest round-trip +
//! four mutation tests + transcript determinism.

use noid_core::mle::evaluate::evaluate_slice;
use noid_core::transcript::FiatShamir;
use noid_core::Block128;
use noid_gkr::product_sumcheck::{
    compute_product_claim, prove_product, verify_product, RoundEvals,
};
use noid_poseidon2b::channel::Poseidon2bChannel;
use rand::{rngs::StdRng, Rng, SeedableRng};

fn rand_vec(rng: &mut StdRng, n: usize) -> Vec<Block128> {
    (0..n).map(|_| Block128::from(rng.gen::<u128>())).collect()
}

fn rand_point(rng: &mut StdRng, n_vars: usize) -> Vec<Block128> {
    (0..n_vars)
        .map(|_| Block128::from(rng.gen::<u128>()))
        .collect()
}

fn fresh_channel(seed: u64) -> Poseidon2bChannel {
    // Same seed on both sides = same transcript.
    let mut ch = Poseidon2bChannel::new();
    ch.absorb(Block128::from(seed as u128));
    ch
}

#[test]
fn honest_roundtrip_matches_reduced_claims() {
    let mut rng = StdRng::seed_from_u64(0x1);
    let n_vars = 6;
    let a = rand_vec(&mut rng, 1 << n_vars);
    let b = rand_vec(&mut rng, 1 << n_vars);
    let r = rand_point(&mut rng, n_vars);
    let v = compute_product_claim(&a, &b, &r);

    let mut p_ch = fresh_channel(42);
    let (proof, r_prime) = prove_product(&a, &b, &r, v, &mut p_ch);

    let mut v_ch = fresh_channel(42);
    let r_prime_v = verify_product(&proof, &r, v, &mut v_ch).expect("must verify");
    assert_eq!(r_prime, r_prime_v);

    // Final reduced claims must match A(r') / B(r') literally.
    assert_eq!(proof.a_final, evaluate_slice(&a, &r_prime));
    assert_eq!(proof.b_final, evaluate_slice(&b, &r_prime));
}

#[test]
fn multiple_random_fixtures_roundtrip() {
    for seed in 0..20u64 {
        let mut rng = StdRng::seed_from_u64(seed ^ 0xABCDEF);
        let n_vars = 4 + (seed as usize % 5); // 4..=8
        let a = rand_vec(&mut rng, 1 << n_vars);
        let b = rand_vec(&mut rng, 1 << n_vars);
        let r = rand_point(&mut rng, n_vars);
        let v = compute_product_claim(&a, &b, &r);

        let mut p_ch = fresh_channel(seed);
        let (proof, _) = prove_product(&a, &b, &r, v, &mut p_ch);

        let mut v_ch = fresh_channel(seed);
        assert!(
            verify_product(&proof, &r, v, &mut v_ch).is_some(),
            "honest roundtrip must verify (seed={seed})"
        );
    }
}

#[test]
fn mutation_wrong_claim_rejects() {
    let mut rng = StdRng::seed_from_u64(0x2);
    let n_vars = 5;
    let a = rand_vec(&mut rng, 1 << n_vars);
    let b = rand_vec(&mut rng, 1 << n_vars);
    let r = rand_point(&mut rng, n_vars);
    let v = compute_product_claim(&a, &b, &r);

    let mut p_ch = fresh_channel(7);
    let (proof, _) = prove_product(&a, &b, &r, v, &mut p_ch);

    let mut v_ch = fresh_channel(7);
    let bad_v = v + Block128::from(1u128);
    assert!(
        verify_product(&proof, &r, bad_v, &mut v_ch).is_none(),
        "verifier must reject wrong claim"
    );
}

#[test]
fn mutation_flipped_round_poly_rejects() {
    let mut rng = StdRng::seed_from_u64(0x3);
    let n_vars = 5;
    let a = rand_vec(&mut rng, 1 << n_vars);
    let b = rand_vec(&mut rng, 1 << n_vars);
    let r = rand_point(&mut rng, n_vars);
    let v = compute_product_claim(&a, &b, &r);

    let mut p_ch = fresh_channel(8);
    let (mut proof, _) = prove_product(&a, &b, &r, v, &mut p_ch);

    // Mutate one coefficient in the middle round polynomial.
    let mid = proof.rounds.len() / 2;
    let mut evals = proof.rounds[mid].evals;
    evals[2] += Block128::from(1u128);
    proof.rounds[mid] = RoundEvals { evals };

    let mut v_ch = fresh_channel(8);
    assert!(
        verify_product(&proof, &r, v, &mut v_ch).is_none(),
        "verifier must reject mutated round polynomial"
    );
}

#[test]
fn mutation_wrong_final_ab_rejects() {
    let mut rng = StdRng::seed_from_u64(0x4);
    let n_vars = 5;
    let a = rand_vec(&mut rng, 1 << n_vars);
    let b = rand_vec(&mut rng, 1 << n_vars);
    let r = rand_point(&mut rng, n_vars);
    let v = compute_product_claim(&a, &b, &r);

    let mut p_ch = fresh_channel(9);
    let (mut proof, _) = prove_product(&a, &b, &r, v, &mut p_ch);

    // Flip the prover's final a.
    proof.a_final += Block128::from(1u128);

    let mut v_ch = fresh_channel(9);
    assert!(
        verify_product(&proof, &r, v, &mut v_ch).is_none(),
        "verifier must reject tampered final a"
    );
}

#[test]
fn mutation_shifted_claim_point_rejects() {
    // Prover claims at point `r`, verifier checks against shifted `r2`.
    let mut rng = StdRng::seed_from_u64(0x5);
    let n_vars = 5;
    let a = rand_vec(&mut rng, 1 << n_vars);
    let b = rand_vec(&mut rng, 1 << n_vars);
    let r = rand_point(&mut rng, n_vars);
    let v = compute_product_claim(&a, &b, &r);

    let mut p_ch = fresh_channel(10);
    let (proof, _) = prove_product(&a, &b, &r, v, &mut p_ch);

    let mut r2 = r.clone();
    r2[0] += Block128::from(1u128);

    let mut v_ch = fresh_channel(10);
    assert!(
        verify_product(&proof, &r2, v, &mut v_ch).is_none(),
        "verifier must reject shifted claim point"
    );
}

#[test]
fn transcript_determinism() {
    let mut rng = StdRng::seed_from_u64(0x6);
    let n_vars = 6;
    let a = rand_vec(&mut rng, 1 << n_vars);
    let b = rand_vec(&mut rng, 1 << n_vars);
    let r = rand_point(&mut rng, n_vars);
    let v = compute_product_claim(&a, &b, &r);

    let mut c1 = fresh_channel(100);
    let (p1, ch1) = prove_product(&a, &b, &r, v, &mut c1);
    let mut c2 = fresh_channel(100);
    let (p2, ch2) = prove_product(&a, &b, &r, v, &mut c2);

    assert_eq!(p1, p2);
    assert_eq!(ch1, ch2);
}
