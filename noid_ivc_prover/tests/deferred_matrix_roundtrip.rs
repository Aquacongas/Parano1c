//! The deferred-matrix verification pipeline on REAL proofs: the
//! matrix-free verifier must be transcript-identical to the plain one,
//! its deferred bilinear claim must be TRUE against the instance
//! matrices, and the claim-fold accumulator chain must stay true through
//! multiple links down to the decider's native matrix evaluation.

use noid_ivc_core::challenger::{Challenger, FsLaneChallenger};
use noid_ivc_core::field::F128;
use noid_ivc_core::field_r1cs::{FieldR1cs, SparseFieldMatrix};
use noid_ivc_core::matrix_claim::{
    fresh_claim_value, prove_matrix_claim_fold, stacked_matrix_mle_eval,
    verify_matrix_claim_fold, MatrixAccClaim,
};
use noid_ivc_core::pcs::{self, PcsParams};
use noid_ivc_core::proof::FieldShape;
use noid_ivc_core::public_io::PublicIoSpec;
use noid_ivc_core::verifier::{verify_field_deferred_matrix, verify_field_with_public_io};
use noid_ivc_prover::field_prover::prove_field_with_public_io;

fn params_for(m_elems: usize) -> PcsParams {
    PcsParams {
        m: m_elems + pcs::LOG_PACKING,
        log_inv_rate: 2,
        log_batch_size: 2,
        profile: Default::default(),
    }
}

/// Free-rows instance (see `public_io_roundtrip.rs`): row 0 pins the
/// constant wire, every other row is `z_i·z_0 = z_i`.
fn free_instance(m: usize, k_log: usize, seed: u64) -> (FieldR1cs, Vec<F128>) {
    let k = 1usize << k_log;
    let a_0 = SparseFieldMatrix {
        num_rows: k,
        num_cols: k,
        rows: (0..k)
            .map(|r| {
                if r == 0 {
                    vec![(0u32, F128::ONE)]
                } else {
                    vec![(r as u32, F128::ONE)]
                }
            })
            .collect(),
    };
    let b_0 = SparseFieldMatrix {
        num_rows: k,
        num_cols: k,
        rows: (0..k).map(|_| vec![(0u32, F128::ONE)]).collect(),
    };
    let r1cs = FieldR1cs {
        m,
        k_log,
        k_skip: noid_ivc_core::zerocheck::K_SKIP.min(k_log),
        useful_rows: k,
        a_0,
        b_0,
        const_pin: Some(0),
        digest_cache: std::sync::OnceLock::new(),
        csc_cache: std::sync::OnceLock::new(),
    };

    let mut state = seed;
    let mut next = move || {
        state = state.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    };
    let n = 1usize << m;
    let mut z = vec![F128::ZERO; n];
    for blk in 0..(n / k) {
        z[blk * k] = F128::ONE;
        for r in 1..k {
            z[blk * k + r] = F128 {
                lo: next(),
                hi: next(),
            };
        }
    }
    assert!(r1cs.satisfies(&z));
    (r1cs, z)
}

/// Empty-IO spec (the deferred verifier requires an envelope; the chain
/// spike gives it real lanes — here the transcript equivalence is the
/// point, so a minimal one-lane envelope suffices).
fn tiny_spec(k_log: usize) -> (PublicIoSpec, noid_ivc_core::public_io::WitnessSlice) {
    let io_slice = noid_ivc_core::public_io::WitnessSlice {
        log2_len: 1,
        index: 1,
    };
    assert!(io_slice.start() % (1 << k_log) != 0);
    (
        PublicIoSpec {
            io_slice,
            io_len: 2,
            claims: vec![],
        },
        io_slice,
    )
}

#[test]
fn deferred_matrix_pipeline_on_real_proofs() {
    let m = 11;
    let k_log = 7;
    let (r1cs, mut z) = free_instance(m, k_log, 0xDEF1);
    let (spec, io_slice) = tiny_spec(k_log);
    let io: Vec<F128> = vec![
        F128 { lo: 0xA1, hi: 0 },
        F128 { lo: 0xB2, hi: 0 },
    ];
    z[io_slice.start()] = io[0];
    z[io_slice.start() + 1] = io[1];

    let params = params_for(m);
    let mut ch_p = FsLaneChallenger::new(b"deferred-e2e");
    let (proof, commitment, _claims) =
        prove_field_with_public_io(&r1cs, &z, &params, &spec, &io, &mut ch_p);

    // Plain verification accepts.
    let mut ch_v1 = FsLaneChallenger::new(b"deferred-e2e");
    verify_field_with_public_io(&r1cs, &commitment, &proof, &spec, &io, &mut ch_v1)
        .expect("plain verify accepts");

    // Deferred-matrix verification accepts, transcript-identically.
    let shape = FieldShape::of(&r1cs);
    let digest = r1cs.statement_digest();
    let mut ch_v2 = FsLaneChallenger::new(b"deferred-e2e");
    let (_claim, fresh) = verify_field_deferred_matrix(
        &shape,
        &digest,
        &commitment,
        &proof,
        &spec,
        &io,
        &mut ch_v2,
    )
    .expect("deferred verify accepts");
    assert_eq!(
        ch_v1.sample_f128(),
        ch_v2.sample_f128(),
        "deferred verifier diverged from the plain transcript"
    );

    // THE equivalence: the deferred bilinear claim is true against the
    // instance matrices — the deferred final and the plain final agree.
    assert_eq!(
        fresh_claim_value(&r1cs, &fresh),
        fresh.value,
        "deferred lincheck claim is false against the matrices"
    );

    // Fold chain: genesis (gate 0) then two links; the accumulator stays
    // true and the decider's native evaluation accepts.
    let junk_acc = MatrixAccClaim::zero(k_log);
    let mut fold_ch_p = FsLaneChallenger::new(b"deferred-fold");
    let mut fold_ch_v = FsLaneChallenger::new(b"deferred-fold");
    let (fp0, acc0) = prove_matrix_claim_fold(&r1cs, &fresh, &junk_acc, false, &mut fold_ch_p);
    let acc0_v = verify_matrix_claim_fold(
        k_log,
        r1cs.k_skip,
        &fresh,
        &junk_acc,
        F128::ZERO,
        &fp0,
        &mut fold_ch_v,
    )
    .expect("genesis fold verifies");
    assert_eq!(acc0, acc0_v);

    // Two more links reusing the same fresh claim (any true claims fold).
    let mut acc = acc0;
    for _ in 0..2 {
        let (fp, next) = prove_matrix_claim_fold(&r1cs, &fresh, &acc, true, &mut fold_ch_p);
        let next_v = verify_matrix_claim_fold(
            k_log,
            r1cs.k_skip,
            &fresh,
            &acc,
            F128::ONE,
            &fp,
            &mut fold_ch_v,
        )
        .expect("link fold verifies");
        assert_eq!(next, next_v);
        acc = next;
    }
    assert_eq!(
        stacked_matrix_mle_eval(&r1cs, &acc),
        acc.value,
        "decider rejects the chained accumulator"
    );

    // Tampered proof bytes reach the deferred verifier too: flip one
    // lincheck round wire — rejected (transcript-threaded claim).
    let mut bad = proof.clone();
    if let Some(w) = bad.lincheck.rounds.first_mut() {
        w.0 += F128::ONE;
    }
    let mut ch = FsLaneChallenger::new(b"deferred-e2e");
    assert!(
        verify_field_deferred_matrix(&shape, &digest, &commitment, &bad, &spec, &io, &mut ch)
            .is_err(),
        "tampered lincheck round accepted by the deferred verifier"
    );

    // A wrong statement digest shifts the transcript and is rejected.
    let mut bad_digest = digest;
    bad_digest[0] ^= 1;
    let mut ch = FsLaneChallenger::new(b"deferred-e2e");
    assert!(
        verify_field_deferred_matrix(
            &shape,
            &bad_digest,
            &commitment,
            &proof,
            &spec,
            &io,
            &mut ch
        )
        .is_err(),
        "wrong statement digest accepted"
    );
}
