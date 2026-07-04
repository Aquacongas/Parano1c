//! End-to-end FieldR1cs prove → verify tests: honest roundtrip, false
//! witnesses, and mutation of every proof/commitment component → reject.

use noid_ivc_core::challenger::{Challenger, FsLaneChallenger};
use noid_ivc_core::field::F128;
use noid_ivc_core::field_r1cs::synthetic_satisfiable;
use noid_ivc_core::pcs::{self, PcsParams};
use noid_ivc_core::proof::FieldR1csProof;
use noid_ivc_core::verifier::verify_field;
use noid_ivc_prover::field_prover::prove_field;

fn params_for(m_elems: usize) -> PcsParams {
    PcsParams {
        m: m_elems + pcs::LOG_PACKING,
        log_inv_rate: 2,
        log_batch_size: 2,
        profile: Default::default(),
    }
}

const TEST_DOMAIN: &[u8] = b"field-r1cs-e2e-v0";

#[test]
fn honest_roundtrip_multiple_shapes() {
    for &(m, k_log, seed) in &[(10usize, 7usize, 1u64), (12, 8, 2), (13, 10, 3)] {
        let (r1cs, z) = synthetic_satisfiable(m, k_log, seed);
        assert!(r1cs.satisfies(&z));
        let params = params_for(m);

        let mut ch_p = FsLaneChallenger::new(TEST_DOMAIN);
        let (proof, commitment, claim_p) = prove_field(&r1cs, &z, &params, &mut ch_p);

        let mut ch_v = FsLaneChallenger::new(TEST_DOMAIN);
        let claim_v = verify_field(&r1cs, &commitment, &proof, &mut ch_v)
            .unwrap_or_else(|e| panic!("honest proof rejected (m={m}, k_log={k_log}): {e:?}"));
        assert_eq!(claim_p, claim_v, "claim mismatch m={m}");

        // Transcript lockstep survives to the next challenge.
        assert_eq!(ch_p.sample_f128(), ch_v.sample_f128());
    }
}

#[test]
fn false_witnesses_rejected() {
    let (r1cs, z) = synthetic_satisfiable(10, 7, 42);
    let params = params_for(10);
    for seed in 0..8u64 {
        let mut bad_z = z.clone();
        let idx = (seed as usize * 131) % bad_z.len();
        bad_z[idx] += F128 {
            lo: 1 + seed,
            hi: seed.wrapping_mul(0x9E3779B97F4A7C15),
        };
        assert!(!r1cs.satisfies(&bad_z), "corruption did not break satisfiability");

        let mut ch_p = FsLaneChallenger::new(TEST_DOMAIN);
        let (proof, commitment, _) = prove_field(&r1cs, &bad_z, &params, &mut ch_p);
        let mut ch_v = FsLaneChallenger::new(TEST_DOMAIN);
        assert!(
            verify_field(&r1cs, &commitment, &proof, &mut ch_v).is_err(),
            "false witness accepted (seed={seed})"
        );
    }
}

/// Adversarial proof/commitment SHAPES must be rejected as errors, never
/// panic: the snapshot decider runs this verifier on untrusted envelopes.
#[test]
fn adversarial_shapes_rejected_not_panicking() {
    use noid_ivc_core::verifier::VerifyError;

    let (r1cs, z) = synthetic_satisfiable(10, 7, 99);
    let params = params_for(10);
    let mut ch_p = FsLaneChallenger::new(TEST_DOMAIN);
    let (proof, commitment, _) = prove_field(&r1cs, &z, &params, &mut ch_p);

    // Commitment parameters that disagree with the instance shape.
    for delta in [-1i64, 1, 7] {
        let mut bad = commitment.clone();
        bad.params.m = (bad.params.m as i64 + delta) as usize;
        let mut ch_v = FsLaneChallenger::new(TEST_DOMAIN);
        let res = verify_field(&r1cs, &bad, &proof, &mut ch_v);
        assert!(
            matches!(res, Err(VerifyError::ParamsMismatch)),
            "params.m off by {delta} must be ParamsMismatch, got {res:?}"
        );
    }
    {
        let mut bad = commitment.clone();
        bad.params.log_batch_size = bad.params.m; // log_dim would underflow
        let mut ch_v = FsLaneChallenger::new(TEST_DOMAIN);
        let res = verify_field(&r1cs, &bad, &proof, &mut ch_v);
        assert!(matches!(res, Err(VerifyError::ParamsMismatch)), "got {res:?}");
    }

    // A proof whose sumcheck depth disagrees with the commitment.
    let mut truncated = proof.clone();
    truncated.pcs_open.round_messages.pop();
    let mut ch_v = FsLaneChallenger::new(TEST_DOMAIN);
    assert!(
        verify_field(&r1cs, &commitment, &truncated, &mut ch_v).is_err(),
        "truncated PCS round messages accepted"
    );
    let mut extended = proof.clone();
    let extra = extended.pcs_open.round_messages[0].clone();
    extended.pcs_open.round_messages.push(extra);
    let mut ch_v = FsLaneChallenger::new(TEST_DOMAIN);
    assert!(
        verify_field(&r1cs, &commitment, &extended, &mut ch_v).is_err(),
        "extended PCS round messages accepted"
    );
}

/// Every structured proof element, mutated one at a time → reject. Plus
/// commitment-root and statement substitution.
#[test]
fn mutations_rejected() {
    let (r1cs, z) = synthetic_satisfiable(11, 7, 7);
    let params = params_for(11);
    let mut ch_p = FsLaneChallenger::new(TEST_DOMAIN);
    let (proof, commitment, _) = prove_field(&r1cs, &z, &params, &mut ch_p);

    // Sanity: honest accepts.
    let mut ch = FsLaneChallenger::new(TEST_DOMAIN);
    assert!(verify_field(&r1cs, &commitment, &proof, &mut ch).is_ok());

    let mut cases: Vec<(String, FieldR1csProof)> = Vec::new();

    // Zerocheck: every F128 element of every component.
    for i in 0..proof.zerocheck.round1_ab.len() {
        let mut p = proof.clone();
        p.zerocheck.round1_ab[i].lo ^= 1;
        cases.push((format!("zc.round1_ab[{i}]"), p));
    }
    for i in 0..proof.zerocheck.round1_c.len() {
        let mut p = proof.clone();
        p.zerocheck.round1_c[i].hi ^= 1;
        cases.push((format!("zc.round1_c[{i}]"), p));
    }
    for i in 0..proof.zerocheck.multilinear_rounds.len() {
        let mut p = proof.clone();
        p.zerocheck.multilinear_rounds[i].0.lo ^= 1;
        cases.push((format!("zc.mlv[{i}].0"), p));
        let mut p = proof.clone();
        p.zerocheck.multilinear_rounds[i].1.hi ^= 1;
        cases.push((format!("zc.mlv[{i}].1"), p));
    }
    for (name, f) in [
        ("zc.final_a_eval", 0usize),
        ("zc.final_b_eval", 1),
        ("zc.final_c_eval", 2),
    ] {
        let mut p = proof.clone();
        match f {
            0 => p.zerocheck.final_a_eval.lo ^= 1,
            1 => p.zerocheck.final_b_eval.lo ^= 1,
            _ => p.zerocheck.final_c_eval.lo ^= 1,
        }
        cases.push((name.to_string(), p));
    }

    // Lincheck: every round message and every z_partial slot.
    for i in 0..proof.lincheck.rounds.len() {
        let mut p = proof.clone();
        p.lincheck.rounds[i].0.lo ^= 1;
        cases.push((format!("lc.rounds[{i}].0"), p));
        let mut p = proof.clone();
        p.lincheck.rounds[i].1.hi ^= 1;
        cases.push((format!("lc.rounds[{i}].1"), p));
    }
    for i in 0..proof.lincheck.z_partial.len() {
        let mut p = proof.clone();
        p.lincheck.z_partial[i].lo ^= 1;
        cases.push((format!("lc.z_partial[{i}]"), p));
    }

    // PCS: final values, grinding nonce, round messages, FRI query shape.
    {
        let mut p = proof.clone();
        p.pcs_open.final_a += F128::ONE;
        cases.push(("pcs.final_a".to_string(), p));
        let mut p = proof.clone();
        p.pcs_open.final_b += F128::ONE;
        cases.push(("pcs.final_b".to_string(), p));
        let mut p = proof.clone();
        p.pcs_open.pow_nonce = p.pcs_open.pow_nonce.wrapping_add(1);
        cases.push(("pcs.pow_nonce".to_string(), p));
        if !proof.pcs_open.plaintext_tail.is_empty() {
            let mut p = proof.clone();
            p.pcs_open.plaintext_tail[0].lo ^= 1;
            cases.push(("pcs.plaintext_tail[0]".to_string(), p));
            let mut p = proof.clone();
            let last = p.pcs_open.plaintext_tail.len() - 1;
            p.pcs_open.plaintext_tail[last].hi ^= 1;
            cases.push(("pcs.plaintext_tail[last]".to_string(), p));
            let mut p = proof.clone();
            p.pcs_open.plaintext_tail.pop();
            cases.push(("pcs.plaintext_tail truncated".to_string(), p));
        }
        let mut p = proof.clone();
        p.pcs_open.queries.truncate(p.pcs_open.queries.len() / 2);
        cases.push(("pcs.queries truncated".to_string(), p));
        for i in 0..proof.pcs_open.round_messages.len() {
            let mut p = proof.clone();
            p.pcs_open.round_messages[i].u_0.lo ^= 1;
            cases.push((format!("pcs.round_messages[{i}].u_0"), p));
        }
    }

    for (label, bad) in cases {
        let mut ch = FsLaneChallenger::new(TEST_DOMAIN);
        assert!(
            verify_field(&r1cs, &commitment, &bad, &mut ch).is_err(),
            "mutation {label} accepted"
        );
    }

    // Commitment-root substitution.
    let mut bad_commitment = commitment.clone();
    bad_commitment.root[0] ^= 1;
    let mut ch = FsLaneChallenger::new(TEST_DOMAIN);
    assert!(
        verify_field(&r1cs, &bad_commitment, &proof, &mut ch).is_err(),
        "commitment root tamper accepted"
    );

    // Statement substitution: a different instance must not verify the same
    // proof (the statement digest is transcript-bound).
    let (other_r1cs, _) = synthetic_satisfiable(11, 7, 8);
    let mut ch = FsLaneChallenger::new(TEST_DOMAIN);
    assert!(
        verify_field(&other_r1cs, &commitment, &proof, &mut ch).is_err(),
        "statement substitution accepted"
    );
}

/// Serialized-bytes fuzz: bit-flip a sample of positions across the encoded
/// proof; any decodable mutant must be rejected.
#[test]
fn serialized_bitflips_rejected() {
    let (r1cs, z) = synthetic_satisfiable(10, 7, 99);
    let params = params_for(10);
    let mut ch_p = FsLaneChallenger::new(TEST_DOMAIN);
    let (proof, commitment, _) = prove_field(&r1cs, &z, &params, &mut ch_p);

    let bytes = bincode::serialize(&proof).expect("proof serializes");
    let step = (bytes.len() / 97).max(1);
    let mut checked = 0usize;
    for pos in (0..bytes.len()).step_by(step) {
        let mut mutated = bytes.clone();
        mutated[pos] ^= 0x40;
        let Ok(bad): Result<FieldR1csProof, _> = bincode::deserialize(&mutated) else {
            continue; // shape-destroying flip — rejected at decode
        };
        let mut ch = FsLaneChallenger::new(TEST_DOMAIN);
        assert!(
            verify_field(&r1cs, &commitment, &bad, &mut ch).is_err(),
            "byte flip at {pos} accepted"
        );
        checked += 1;
    }
    assert!(checked > 20, "too few decodable mutants exercised: {checked}");
}
