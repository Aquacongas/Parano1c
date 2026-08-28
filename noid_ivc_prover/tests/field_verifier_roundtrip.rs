//! End-to-end FieldR1cs prove → verify tests: honest roundtrip, false
//! witnesses, and mutation of every proof/commitment component → reject.

use noid_ivc_core::challenger::{Challenger, FsLaneChallenger};
use noid_ivc_core::field::F128;
use noid_ivc_core::field_r1cs::synthetic_satisfiable;
use noid_ivc_core::pcs::{self, PcsParams};
use noid_ivc_core::proof::{FieldR1csProof, FieldShape};
use noid_ivc_core::public_io::{PublicIoSpec, WitnessSlice};
use noid_ivc_core::verifier::{
    VerifyError, verify_field, verify_field_deferred_matrix_with_post_commit,
    verify_field_deferred_matrix_with_post_commit_context, verify_field_with_public_io,
    verify_field_with_public_io_and_post_commit,
    verify_field_with_public_io_and_post_commit_context,
};
use noid_ivc_prover::field_prover::{
    prove_field, prove_field_with_public_io_and_post_commit,
    prove_field_with_public_io_and_post_commit_context,
};

fn params_for(m_elems: usize) -> PcsParams {
    PcsParams {
        m: m_elems + pcs::LOG_PACKING,
        log_inv_rate: 2,
        log_batch_size: 2,
        profile: Default::default(),
    }
}

const TEST_DOMAIN: &[u8] = b"field-r1cs-e2e-v0";

#[derive(Clone)]
struct PostCommitOpening {
    point: Vec<F128>,
    value: F128,
}

fn mle_eval(values: &[F128], point: &[F128]) -> F128 {
    assert_eq!(values.len(), 1usize << point.len());
    values
        .iter()
        .zip(noid_ivc_core::lincheck::build_eq_table(point))
        .fold(F128::ZERO, |sum, (&value, weight)| sum + value * weight)
}

#[test]
fn post_commit_auxiliary_claim_roundtrip_and_causality() {
    let (r1cs, z) = synthetic_satisfiable(10, 7, 0xA11CE);
    let params = params_for(10);
    let spec = PublicIoSpec {
        io_slice: WitnessSlice {
            log2_len: 0,
            index: 0,
        },
        io_len: 1,
        claims: Vec::new(),
    };
    let io = [z[0]];

    let mut ch_p = FsLaneChallenger::new(b"field-post-commit-v0");
    let (proof, auxiliary, commitment, _) = prove_field_with_public_io_and_post_commit(
        &r1cs,
        &z,
        &params,
        &spec,
        &io,
        &mut ch_p,
        |z, _commitment, ch| {
            // This draw is causally downstream of bind_statement_field, which
            // has already absorbed the exact witness commitment root.
            ch.observe_label(b"post-commit-opening-test-v0");
            let point = ch.sample_f128_vec(r1cs.m);
            let value = mle_eval(z, &point);
            ch.observe_f128(value);
            let claim = pcs::QuirkyDirectClaim {
                z_skip: F128::ZERO,
                k_skip: 0,
                x_rest: point.clone(),
                value,
            };
            (PostCommitOpening { point, value }, vec![claim])
        },
    );

    let verify = |auxiliary: &PostCommitOpening| {
        let mut ch_v = FsLaneChallenger::new(b"field-post-commit-v0");
        verify_field_with_public_io_and_post_commit(
            &r1cs,
            &commitment,
            &proof,
            &spec,
            &io,
            auxiliary,
            &mut ch_v,
            |auxiliary, ch| {
                ch.observe_label(b"post-commit-opening-test-v0");
                let expected_point = ch.sample_f128_vec(r1cs.m);
                if auxiliary.point != expected_point {
                    return Err(VerifyError::Auxiliary);
                }
                ch.observe_f128(auxiliary.value);
                Ok(vec![pcs::QuirkyDirectClaim {
                    z_skip: F128::ZERO,
                    k_skip: 0,
                    x_rest: auxiliary.point.clone(),
                    value: auxiliary.value,
                }])
            },
        )
    };

    assert!(verify(&auxiliary).is_ok());

    // A proof produced in sidecar mode must not be accepted through the
    // legacy verifier entry point. Production still has to make the sidecar
    // mandatory in its envelope/VK; this guards the transcript-level half of
    // that downgrade barrier.
    let mut ch_without_aux = FsLaneChallenger::new(b"field-post-commit-v0");
    assert!(
        verify_field_with_public_io(&r1cs, &commitment, &proof, &spec, &io, &mut ch_without_aux,)
            .is_err(),
        "post-commit proof accepted without its mandatory auxiliary replay"
    );

    // HistoryStep recursion uses the matrix-free verifier. Its post-commit
    // prefix and appended terminal claim must be transcript-identical.
    let mut ch_deferred = FsLaneChallenger::new(b"field-post-commit-v0");
    let deferred = verify_field_deferred_matrix_with_post_commit(
        &FieldShape::of(&r1cs),
        &r1cs.statement_digest(),
        &commitment,
        &proof,
        &spec,
        &io,
        &auxiliary,
        &mut ch_deferred,
        |auxiliary, ch| {
            ch.observe_label(b"post-commit-opening-test-v0");
            let expected_point = ch.sample_f128_vec(r1cs.m);
            if auxiliary.point != expected_point {
                return Err(VerifyError::Auxiliary);
            }
            ch.observe_f128(auxiliary.value);
            Ok(vec![pcs::QuirkyDirectClaim {
                z_skip: F128::ZERO,
                k_skip: 0,
                x_rest: auxiliary.point.clone(),
                value: auxiliary.value,
            }])
        },
    );
    assert!(deferred.is_ok());

    let mut bad_point = auxiliary.clone();
    bad_point.point[0] += F128::ONE;
    assert_eq!(verify(&bad_point), Err(VerifyError::Auxiliary));

    let mut bad_value = auxiliary;
    bad_value.value += F128::ONE;
    assert!(verify(&bad_value).is_err());
}

#[test]
fn post_commit_context_binds_class_and_owns_claim_sink() {
    const CLASS_DIGEST: [u8; 32] = [0xC7; 32];
    let (r1cs, z) = synthetic_satisfiable(10, 7, 0xC07E57);
    let params = params_for(10);
    let spec = PublicIoSpec {
        io_slice: WitnessSlice {
            log2_len: 0,
            index: 0,
        },
        io_len: 1,
        claims: Vec::new(),
    };
    let io = [z[0]];

    let mut ch_p = FsLaneChallenger::new(b"field-post-commit-context-v1");
    let (proof, auxiliary, commitment, _) = prove_field_with_public_io_and_post_commit_context(
        &r1cs,
        &z,
        &params,
        &spec,
        &io,
        &CLASS_DIGEST,
        &mut ch_p,
        |context| {
            assert_eq!(context.total_vars(), r1cs.m);
            assert_eq!(context.witness(), z.as_slice());
            context.observe_label(b"context-opening-v1");
            let point = context.sample_f128_vec(r1cs.m);
            let value = mle_eval(context.witness(), &point);
            context.observe_f128(value);
            context.append_claim(pcs::QuirkyDirectClaim {
                z_skip: F128::ZERO,
                k_skip: 0,
                x_rest: point.clone(),
                value,
            });
            assert_eq!(context.claim_count(), 1);
            PostCommitOpening { point, value }
        },
    );

    let verify = |class_digest: &[u8; 32], auxiliary: &PostCommitOpening, append_claim: bool| {
        let mut ch_v = FsLaneChallenger::new(b"field-post-commit-context-v1");
        verify_field_with_public_io_and_post_commit_context(
            &r1cs,
            &commitment,
            &proof,
            &spec,
            &io,
            class_digest,
            auxiliary,
            &mut ch_v,
            |auxiliary, context| {
                assert_eq!(context.total_vars(), r1cs.m);
                assert_eq!(context.commitment().root, commitment.root);
                context.observe_label(b"context-opening-v1");
                let point = context.sample_f128_vec(r1cs.m);
                if point != auxiliary.point {
                    return Err(VerifyError::Auxiliary);
                }
                context.observe_f128(auxiliary.value);
                if append_claim {
                    context.append_claims([pcs::QuirkyDirectClaim {
                        z_skip: F128::ZERO,
                        k_skip: 0,
                        x_rest: auxiliary.point.clone(),
                        value: auxiliary.value,
                    }]);
                    assert_eq!(context.claim_count(), 1);
                }
                Ok(())
            },
        )
    };

    assert!(verify(&CLASS_DIGEST, &auxiliary, true).is_ok());

    let mut wrong_class = CLASS_DIGEST;
    wrong_class[0] ^= 1;
    assert!(
        verify(&wrong_class, &auxiliary, true).is_err(),
        "post-commit class substitution accepted"
    );
    assert!(
        verify(&CLASS_DIGEST, &auxiliary, false).is_err(),
        "callback claim omission did not alter the mandatory PCS batch"
    );

    let mut bad_auxiliary = auxiliary.clone();
    bad_auxiliary.value += F128::ONE;
    assert!(verify(&CLASS_DIGEST, &bad_auxiliary, true).is_err());

    let mut core_only = FsLaneChallenger::new(b"field-post-commit-context-v1");
    assert!(
        verify_field_with_public_io(&r1cs, &commitment, &proof, &spec, &io, &mut core_only,)
            .is_err(),
        "context proof downgraded to the core-only verifier"
    );

    let mut deferred_ch = FsLaneChallenger::new(b"field-post-commit-context-v1");
    assert!(
        verify_field_deferred_matrix_with_post_commit_context(
            &FieldShape::of(&r1cs),
            &r1cs.statement_digest(),
            &commitment,
            &proof,
            &spec,
            &io,
            &CLASS_DIGEST,
            &auxiliary,
            &mut deferred_ch,
            |auxiliary, context| {
                context.observe_label(b"context-opening-v1");
                let point = context.sample_f128_vec(r1cs.m);
                if point != auxiliary.point {
                    return Err(VerifyError::Auxiliary);
                }
                context.observe_f128(auxiliary.value);
                context.append_claim(pcs::QuirkyDirectClaim {
                    z_skip: F128::ZERO,
                    k_skip: 0,
                    x_rest: auxiliary.point.clone(),
                    value: auxiliary.value,
                });
                Ok(())
            },
        )
        .is_ok(),
        "deferred context verifier diverged from the full verifier"
    );
}

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
        assert!(
            !r1cs.satisfies(&bad_z),
            "corruption did not break satisfiability"
        );

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
        assert!(
            matches!(res, Err(VerifyError::ParamsMismatch)),
            "got {res:?}"
        );
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

        // Per-query independent Merkle paths: sibling flips at the bottom
        // and top level, truncation/extension (depth is an exact shape
        // check), leaf flips and a desynced position.
        let mut p = proof.clone();
        p.pcs_open.queries[0].initial_path[0][0] ^= 1;
        cases.push(("pcs.q0.initial_path[bottom]".to_string(), p));
        let mut p = proof.clone();
        let top = p.pcs_open.queries[0].initial_path.len() - 1;
        p.pcs_open.queries[0].initial_path[top][31] ^= 1;
        cases.push(("pcs.q0.initial_path[top]".to_string(), p));
        let mut p = proof.clone();
        p.pcs_open.queries[0].initial_path.pop();
        cases.push(("pcs.q0.initial_path truncated".to_string(), p));
        let mut p = proof.clone();
        p.pcs_open.queries[0].initial_path.push([0u8; 32]);
        cases.push(("pcs.q0.initial_path extended".to_string(), p));
        let mut p = proof.clone();
        p.pcs_open.queries[0].initial_leaf[0].lo ^= 1;
        cases.push(("pcs.q0.initial_leaf[0]".to_string(), p));
        let mut p = proof.clone();
        p.pcs_open.queries[0].position ^= 1;
        cases.push(("pcs.q0.position".to_string(), p));
        if !proof.pcs_open.queries[0].post_row_batch_path.is_empty() {
            let mut p = proof.clone();
            p.pcs_open.queries[0].post_row_batch_path[0][0] ^= 1;
            cases.push(("pcs.q0.post_rb_path[bottom]".to_string(), p));
            let mut p = proof.clone();
            p.pcs_open.queries[0].post_row_batch_leaf[0].lo ^= 1;
            cases.push(("pcs.q0.post_rb_leaf[0]".to_string(), p));
        }
        if let Some(first_epoch_path) = proof.pcs_open.queries[0].epoch_paths.first() {
            if !first_epoch_path.is_empty() {
                let mut p = proof.clone();
                p.pcs_open.queries[0].epoch_paths[0][0][0] ^= 1;
                cases.push(("pcs.q0.epoch_path[0][bottom]".to_string(), p));
            }
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
    assert!(
        checked > 20,
        "too few decodable mutants exercised: {checked}"
    );
}
