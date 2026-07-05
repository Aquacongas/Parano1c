//! THE recursion fixed point: a proof of the link class verifying a
//! proof of the same class — π₀ (genesis) → π₁ → π₂ — decided natively
//! once at the tip. This is the O(1)-history capability itself, at the
//! smallest honest class size (the [R] replay is nearly flat in the
//! verified instance's size, so the class must be big enough to host
//! its own verifier).
//!
//! The chain here is a STUB link (no block content yet): each link
//! verifies its predecessor, threads the digest/genesis rules and folds
//! the deferred matrix claim. Block slots attach to the same skeleton
//! next.

use std::time::Instant;

use noid_ivc_core::challenger::FsLaneChallenger;
use noid_ivc_core::field::F128;
use noid_ivc_core::pcs::{self, PcsParams};
use noid_ivc_core::proof::FieldShape;
use noid_ivc_core::zerocheck::K_SKIP;
use noid_ivc_prover::field_prover::prove_field_with_public_io;
use noid_recursive::acceptance::link::{
    build_link, decide_tip, genesis_witness, link_io_layout, LinkClass, LinkEnvelope, LinkInput,
};

/// The smallest class that hosts its own verifier: the deferred [R]
/// replay of a `2^22`-row proof plus the chain plumbing measured
/// 4,515,906 rows (> 2^22), so the fixed point closes at `2^23` — with
/// ~44% headroom that the block slots will use later.
const CLASS_M: usize = 23;

#[test]
fn recursion_fixed_point_two_links() {
    let shape = FieldShape {
        m: CLASS_M,
        k_log: CLASS_M,
        k_skip: K_SKIP,
        const_pin: Some(0),
    };
    let params = PcsParams {
        m: CLASS_M + pcs::LOG_PACKING,
        log_inv_rate: 2,
        log_batch_size: 5,
        profile: Default::default(),
    };
    let class = LinkClass::new(shape, params.clone());
    let layout = link_io_layout(shape.k_log);

    // ---- The genesis dummy T and its proof (exists without the class).
    let t0 = Instant::now();
    let t_witness = genesis_witness(&shape);
    let t_io = vec![F128::ZERO; class.spec.io_len];
    let mut ch = FsLaneChallenger::new(b"history-link-v0");
    let (t_proof, t_commitment, _) = prove_field_with_public_io(
        &class.genesis,
        &t_witness,
        &params,
        &class.spec,
        &t_io,
        &mut ch,
    );
    let env_t = LinkEnvelope {
        proof: t_proof,
        commitment: t_commitment,
        io: t_io,
    };
    eprintln!("[fixed-point] genesis dummy proof: {:.1?}", t0.elapsed());

    // ---- π₀: the genesis link. Building its trace CREATES the class
    // matrix (the trace never contains the class digest or matrix).
    let t0 = Instant::now();
    let built0 = build_link(
        &class,
        &LinkInput {
            prev: &env_t,
            verified_digest: class.genesis_digest,
            genesis: true,
            fold_matrix: &class.genesis,
            block: None,
        },
    );
    eprintln!(
        "[fixed-point] genesis link build: {:.1?}, rows used = {}",
        t0.elapsed(),
        built0.witness.len()
    );
    let class_r1cs = built0.r1cs;
    let t0 = Instant::now();
    let class_digest = class_r1cs.statement_digest();
    eprintln!("[fixed-point] class digest: {:.1?}", t0.elapsed());

    let t0 = Instant::now();
    let mut ch = FsLaneChallenger::new(b"history-link-v0");
    let (p0, c0, _) = prove_field_with_public_io(
        &class_r1cs,
        &built0.witness,
        &params,
        &class.spec,
        &built0.io,
        &mut ch,
    );
    eprintln!("[fixed-point] pi_0 prove: {:.1?}", t0.elapsed());
    let env0 = LinkEnvelope {
        proof: p0,
        commitment: c0,
        io: built0.io,
    };

    // ---- π₁ verifies π₀; π₂ verifies π₁. The SAME class instance must
    // come out of every build (the fixed-shape gate).
    let mut prev_env = env0;
    for step in 1..=2u32 {
        let t0 = Instant::now();
        let built = build_link(
            &class,
            &LinkInput {
                prev: &prev_env,
                verified_digest: class_digest,
                genesis: false,
                fold_matrix: &class_r1cs,
                block: None,
            },
        );
        let build_t = t0.elapsed();
        assert_eq!(
            built.r1cs.a_0.rows, class_r1cs.a_0.rows,
            "link {step}: class A matrix drifted"
        );
        assert_eq!(
            built.r1cs.b_0.rows, class_r1cs.b_0.rows,
            "link {step}: class B matrix drifted"
        );
        let t0 = Instant::now();
        let mut ch = FsLaneChallenger::new(b"history-link-v0");
        let (proof, commitment, _) = prove_field_with_public_io(
            &class_r1cs,
            &built.witness,
            &params,
            &class.spec,
            &built.io,
            &mut ch,
        );
        eprintln!(
            "[fixed-point] pi_{step} build: {build_t:.1?}, prove: {:.1?}",
            t0.elapsed()
        );
        prev_env = LinkEnvelope {
            proof,
            commitment,
            io: built.io,
        };
    }

    // ---- The decider accepts the tip.
    let t0 = Instant::now();
    decide_tip(&class, &class_r1cs, &prev_env).expect("decider accepts the two-link chain");
    eprintln!("[fixed-point] decide_tip: {:.1?}", t0.elapsed());
    eprintln!(
        "[fixed-point] RECURSION CLOSED: pi_2 verified pi_1 verified pi_0 (class m = {CLASS_M})"
    );

    // ---- Negatives at the decider (the chain's outer boundary).
    // Any tampered IO lane must be rejected — the proof binds the IO.
    for lane in [
        layout.w_d,
        layout.g,
        layout.acc_point,
        layout.acc_value,
    ] {
        let mut bad = LinkEnvelope {
            proof: prev_env.proof.clone(),
            commitment: prev_env.commitment.clone(),
            io: prev_env.io.clone(),
        };
        bad.io[lane] += F128::ONE;
        assert!(
            decide_tip(&class, &class_r1cs, &bad).is_err(),
            "tampered IO lane {lane} accepted"
        );
    }
    // A genesis link is not a valid tip.
    {
        let mut bad_io = prev_env.io.clone();
        bad_io[layout.g] = F128::ONE;
        let bad = LinkEnvelope {
            proof: prev_env.proof.clone(),
            commitment: prev_env.commitment.clone(),
            io: bad_io,
        };
        assert!(
            decide_tip(&class, &class_r1cs, &bad).is_err(),
            "genesis tip accepted"
        );
    }
    // Tampered proof bytes.
    {
        let mut bad = LinkEnvelope {
            proof: prev_env.proof.clone(),
            commitment: prev_env.commitment.clone(),
            io: prev_env.io.clone(),
        };
        if let Some(w) = bad.proof.lincheck.rounds.first_mut() {
            w.0 += F128::ONE;
        }
        assert!(
            decide_tip(&class, &class_r1cs, &bad).is_err(),
            "tampered tip proof accepted"
        );
    }
}
