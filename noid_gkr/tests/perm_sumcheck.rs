// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Stage G1b.β tests — chained permutation sumcheck.
//!
//! Honest round-trip, mutation A (output claim), mutation B (witness
//! tamper), mutation C (swapped RC), mutation D (MDS_FULL on a partial
//! round via swapped witness), transcript determinism, and a native
//! cross-check that `sout_mle(r₀)` matches `Σ_x eq(r₀,x) · sout(x)`.

use noid_core::mle::evaluate::evaluate_slice;
use noid_core::transcript::FiatShamir;
use noid_core::Block128;
use noid_gkr::layers::{evaluate_permutation, round_kind, RoundKind};
use noid_gkr::mle_layout::{PermMle, N_PERM_VARS};
use noid_gkr::perm_sumcheck::{prove_perm, verify_perm};
use noid_poseidon2b::channel::Poseidon2bChannel;
use noid_poseidon2b::native::permutation::{Poseidon2bPermutation, N_ROUNDS, STATE_SIZE};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

fn rand_state(rng: &mut StdRng) -> [Block128; STATE_SIZE] {
    [
        Block128::from(rng.gen::<u128>()),
        Block128::from(rng.gen::<u128>()),
        Block128::from(rng.gen::<u128>()),
        Block128::from(rng.gen::<u128>()),
    ]
}

fn fresh_channel(seed: u64) -> Poseidon2bChannel {
    let mut ch = Poseidon2bChannel::new();
    ch.absorb(Block128::from(seed as u128));
    ch
}

/// γ₂-lift helper: reconstruct `v0 = sout_mle(r0)` from a claimed
/// `state_in`. Mirrors what the prod spine wrapper does: the caller of
/// `verify_perm` is now responsible for supplying `v0`.
fn v0_from_state(state_in: [Block128; STATE_SIZE]) -> impl FnOnce(&[Block128]) -> Block128 {
    move |r0: &[Block128]| {
        let witness = evaluate_permutation(state_in);
        let sout_mle = PermMle::from_witness(&witness).sout;
        evaluate_slice(&sout_mle, r0)
    }
}

#[test]
fn honest_roundtrip() {
    let mut rng = StdRng::seed_from_u64(0xA1);
    for _ in 0..20 {
        let st = rand_state(&mut rng);

        let mut p_ch = fresh_channel(1);
        let (proof, _r0, _v0, _claims) = prove_perm(st, &mut p_ch);

        let mut v_ch = fresh_channel(1);
        assert!(verify_perm(&proof, &mut v_ch, v0_from_state(st)).is_some());
    }
}

#[test]
fn prover_output_claim_matches_native_sout_mle() {
    // The prover's initial claim `v0 = sout_mle(r0)` must equal the
    // value the verifier would compute from the honest witness.
    let mut rng = StdRng::seed_from_u64(0xA2);
    for _ in 0..10 {
        let st = rand_state(&mut rng);

        let mut p_ch = fresh_channel(2);
        let (_proof, _r0_prover, v0, _claims) = prove_perm(st, &mut p_ch);

        // γ₄: `absorb_boundary` was deleted — prover and verifier no
        // longer absorb `state_in` before the first squeeze. Mirror
        // the post-γ₄ transcript shape directly.
        let mut v_ch = fresh_channel(2);
        let r0: Vec<Block128> = (0..N_PERM_VARS).map(|_| v_ch.squeeze()).collect();

        let witness = evaluate_permutation(st);
        let mle = PermMle::from_witness(&witness);
        assert_eq!(v0, evaluate_slice(&mle.sout, &r0));

        // And the final state must match native (reuse of G1a invariant).
        let mut s = st;
        Poseidon2bPermutation.permute_mut(&mut s);
        assert_eq!(s, witness.final_state());
    }
}

#[test]
fn mutation_a_flipped_output_claim_rejects() {
    // Prover honestly produces a proof on `st`, but the verifier is
    // handed a state whose final output differs by one bit. The
    // verifier reconstructs a *different* witness and derives a
    // different `v0`, which the first sumcheck's telescope must reject.
    let mut rng = StdRng::seed_from_u64(0xA3);
    let st = rand_state(&mut rng);

    let mut p_ch = fresh_channel(3);
    let (proof, _, _, _) = prove_perm(st, &mut p_ch);

    let mut bad_state = st;
    bad_state[0] += Block128::from(1u128);

    let mut v_ch = fresh_channel(3);
    assert!(verify_perm(&proof, &mut v_ch, v0_from_state(bad_state)).is_none());
}

#[test]
fn mutation_b_tampered_round_polynomial_rejects() {
    // Flip one coefficient in the middle of the first sumcheck (sout =
    // x4·x3). Verifier's telescope must reject.
    let mut rng = StdRng::seed_from_u64(0xA4);
    let st = rand_state(&mut rng);

    let mut p_ch = fresh_channel(4);
    let (mut proof, _, _, _) = prove_perm(st, &mut p_ch);

    let mid = proof.sout_x4x3.rounds.len() / 2;
    let mut re = proof.sout_x4x3.rounds[mid];
    re.evals[2] += Block128::from(1u128);
    proof.sout_x4x3.rounds[mid] = re;

    let mut v_ch = fresh_channel(4);
    assert!(verify_perm(&proof, &mut v_ch, v0_from_state(st)).is_none());
}

#[test]
fn mutation_c_tampered_final_ab_rejects() {
    // Tamper the final reduced claim of the sout sumcheck. The follow-up
    // `x4 = x2 · x2` sumcheck would be initialized with the tampered
    // value, but the transcript has already diverged because the
    // mutation happens after the prover's transcript was consumed —
    // here we flip an element that the verifier does not absorb again,
    // so the transcripts stay in sync up to the faulty claim. The
    // downstream sin-expansion check against the honest state MLE
    // catches the inconsistency.
    let mut rng = StdRng::seed_from_u64(0xA5);
    let st = rand_state(&mut rng);

    let mut p_ch = fresh_channel(5);
    let (mut proof, _, _, _) = prove_perm(st, &mut p_ch);

    proof.sout_x4x3.a_final += Block128::from(1u128);

    let mut v_ch = fresh_channel(5);
    assert!(verify_perm(&proof, &mut v_ch, v0_from_state(st)).is_none());
}

#[test]
fn mutation_d_forged_sin_claim_rejects() {
    // Tampering sin(ρ) inside a sin-expansion proof forces the
    // verifier's state-MLE consistency check to fail. This is exactly
    // the attack surface that would open if a dishonest prover
    // mis-applied MDS_FULL on a partial round (the downstream sin
    // claims would disagree with the honestly-reconstructed state
    // MLE).
    let mut rng = StdRng::seed_from_u64(0xA6);
    let st = rand_state(&mut rng);

    let mut p_ch = fresh_channel(6);
    let (mut proof, _, _, _) = prove_perm(st, &mut p_ch);

    proof.sin_r3_check.a_final += Block128::from(1u128);

    let mut v_ch = fresh_channel(6);
    assert!(verify_perm(&proof, &mut v_ch, v0_from_state(st)).is_none());
}

#[test]
fn mutation_e_bad_x4_diagonal_rejects() {
    // x4 = x2 · x2 must have a_final == b_final. Force them apart.
    let mut rng = StdRng::seed_from_u64(0xA7);
    let st = rand_state(&mut rng);

    let mut p_ch = fresh_channel(7);
    let (mut proof, _, _, _) = prove_perm(st, &mut p_ch);

    proof.x4_x2x2.b_final += Block128::from(1u128);

    let mut v_ch = fresh_channel(7);
    assert!(verify_perm(&proof, &mut v_ch, v0_from_state(st)).is_none());
}

#[test]
fn transcript_determinism() {
    let mut rng = StdRng::seed_from_u64(0xA8);
    let st = rand_state(&mut rng);

    let mut c1 = fresh_channel(100);
    let (p1, r0_1, v1, c1_claims) = prove_perm(st, &mut c1);
    let mut c2 = fresh_channel(100);
    let (p2, r0_2, v2, c2_claims) = prove_perm(st, &mut c2);

    assert_eq!(p1, p2);
    assert_eq!(r0_1, r0_2);
    assert_eq!(v1, v2);
    assert_eq!(c1_claims, c2_claims);
}

#[test]
fn cross_check_native_sout_at_all_active_vertices() {
    // For every active (row, lane) hypercube vertex the sout MLE must
    // equal sbox_x7(sin), which by construction equals the round's
    // raw S-box output. This pins the native/witness binding the
    // sumcheck chain relies on.
    use noid_poseidon2b::native::permutation::sbox_x7;

    let mut rng = StdRng::seed_from_u64(0xA9);
    let st = rand_state(&mut rng);
    let witness = evaluate_permutation(st);
    let mle = PermMle::from_witness(&witness);

    for r in 0..N_ROUNDS {
        let kind = round_kind(r);
        let lanes = match kind {
            RoundKind::Full => 0..STATE_SIZE,
            RoundKind::Partial => 0..1,
        };
        for lane in lanes {
            let idx = (r << 2) | lane;
            let sin = witness.sin[r][lane];
            let sout = witness.sout[r][lane];
            assert_eq!(sout, sbox_x7(sin));
            assert_eq!(mle.sout[idx], sout);
            assert_eq!(mle.sin[idx], sin);
        }
    }
}
