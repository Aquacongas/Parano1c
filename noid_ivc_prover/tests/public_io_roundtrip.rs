//! Public-IO binding end-to-end: honest roundtrip, envelope tampering,
//! forged derived claims, spec mismatches → reject.

use noid_ivc_core::challenger::{Challenger, FsLaneChallenger};
use noid_ivc_core::field::F128;
use noid_ivc_core::field_r1cs::{FieldR1cs, SparseFieldMatrix};
use noid_ivc_core::lincheck::build_eq_table;
use noid_ivc_core::pcs::{self, PcsParams};
use noid_ivc_core::public_io::{IoClaimSpec, PublicIoSpec, WitnessSlice};
use noid_ivc_core::verifier::{verify_field, verify_field_with_public_io};
use noid_ivc_prover::field_prover::prove_field_with_public_io;

const TEST_DOMAIN: &[u8] = b"public-io-e2e-v0";

fn params_for(m_elems: usize) -> PcsParams {
    PcsParams {
        m: m_elems + pcs::LOG_PACKING,
        log_inv_rate: 2,
        log_batch_size: 2,
        profile: Default::default(),
    }
}

/// An instance whose non-constant rows are all FREE (`z_i = z_i · z_0` with
/// `z_0 = 1` pinned), so tests can place arbitrary public-IO lanes and claim
/// targets anywhere in the witness.
fn free_instance(m: usize, k_log: usize, seed: u64) -> (FieldR1cs, Vec<F128>) {
    let k = 1usize << k_log;
    let a_0 = SparseFieldMatrix::from_rows(
        k,
        (0..k)
            .map(|r| {
                if r == 0 {
                    vec![(0u32, F128::ONE)]
                } else {
                    vec![(r as u32, F128::ONE)]
                }
            })
            .collect(),
    );
    let b_0 = SparseFieldMatrix::from_rows(
        k,
        (0..k).map(|_| vec![(0u32, F128::ONE)]).collect(),
    );
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

/// MLE of a zero-padded witness slice at a point.
fn slice_mle(z: &[F128], slice: &WitnessSlice, point: &[F128]) -> F128 {
    assert_eq!(point.len(), slice.log2_len);
    let eq = build_eq_table(point);
    let mut acc = F128::ZERO;
    for (t, e) in eq.iter().enumerate() {
        acc += z[slice.start() + t] * *e;
    }
    acc
}

/// The shared fixture: an IO slice carrying [p0, p1, v, tag] and one derived
/// claim `witness over TARGET at (p0, p1) == v`.
fn fixture(
    m: usize,
    k_log: usize,
    seed: u64,
) -> (FieldR1cs, Vec<F128>, PublicIoSpec, Vec<F128>) {
    let (r1cs, mut z) = free_instance(m, k_log, seed);
    let io_slice = WitnessSlice {
        log2_len: 3,
        index: 2,
    };
    let target = WitnessSlice {
        log2_len: 2,
        index: 9,
    };
    // The two regions must not overlap (io: 16..24, target: 36..40 here) and
    // must avoid the per-block const wires (multiples of 2^k_log).
    assert!(io_slice.start() % (1 << k_log) != 0 && target.start() % (1 << k_log) != 0);
    let spec = PublicIoSpec {
        io_slice,
        io_len: 4,
        claims: vec![IoClaimSpec {
            slice: target,
            point: 0..2,
            value: 2,
        }],
    };

    let p = [F128 { lo: 17, hi: 5 }, F128 { lo: 23, hi: 9 }];
    let v = slice_mle(&z, &target, &p);
    let io = vec![p[0], p[1], v, F128 { lo: 0xA11CE, hi: 0 }];
    let start = io_slice.start();
    for (t, lane) in io.iter().enumerate() {
        z[start + t] = *lane;
    }
    for t in io.len()..io_slice.len() {
        z[start + t] = F128::ZERO;
    }
    assert!(r1cs.satisfies(&z), "io lanes must stay in free rows");
    (r1cs, z, spec, io)
}

#[test]
fn honest_roundtrip_with_public_io() {
    let (r1cs, z, spec, io) = fixture(11, 7, 7);
    let params = params_for(11);

    let mut ch_p = FsLaneChallenger::new(TEST_DOMAIN);
    let (proof, commitment, claim_p) =
        prove_field_with_public_io(&r1cs, &z, &params, &spec, &io, &mut ch_p);

    let mut ch_v = FsLaneChallenger::new(TEST_DOMAIN);
    let claim_v = verify_field_with_public_io(&r1cs, &commitment, &proof, &spec, &io, &mut ch_v)
        .expect("honest public-io proof must verify");
    assert_eq!(claim_p, claim_v);
    assert_eq!(ch_p.sample_f128(), ch_v.sample_f128());
}

#[test]
fn tampered_envelope_lane_rejected() {
    let (r1cs, z, spec, io) = fixture(11, 7, 8);
    let params = params_for(11);

    let mut ch_p = FsLaneChallenger::new(TEST_DOMAIN);
    let (proof, commitment, _) =
        prove_field_with_public_io(&r1cs, &z, &params, &spec, &io, &mut ch_p);

    for lane in 0..io.len() {
        let mut bad = io.clone();
        bad[lane] += F128::ONE;
        let mut ch_v = FsLaneChallenger::new(TEST_DOMAIN);
        assert!(
            verify_field_with_public_io(&r1cs, &commitment, &proof, &spec, &bad, &mut ch_v)
                .is_err(),
            "tampered envelope lane {lane} accepted"
        );
    }
}

/// The money test: a prover whose envelope and witness are CONSISTENT but
/// whose derived claim is FALSE against the target slice must fail — the
/// batched opening catches the forged endpoint.
#[test]
fn forged_derived_claim_rejected() {
    let (r1cs, mut z, spec, mut io) = fixture(11, 7, 9);
    let params = params_for(11);

    io[2] += F128::ONE; // forge the claimed value...
    z[spec.io_slice.start() + 2] = io[2]; // ...consistently in the witness
    assert!(r1cs.satisfies(&z));

    let mut ch_p = FsLaneChallenger::new(TEST_DOMAIN);
    let (proof, commitment, _) =
        prove_field_with_public_io(&r1cs, &z, &params, &spec, &io, &mut ch_p);

    let mut ch_v = FsLaneChallenger::new(TEST_DOMAIN);
    assert!(
        verify_field_with_public_io(&r1cs, &commitment, &proof, &spec, &io, &mut ch_v).is_err(),
        "forged derived claim accepted"
    );
}

/// Witness IO tail beyond io_len must be zero — the binding claim covers the
/// whole padded slice, so smuggling a nonzero tail lane fails verification.
#[test]
fn nonzero_io_padding_rejected() {
    let (r1cs, mut z, spec, io) = fixture(11, 7, 10);
    let params = params_for(11);
    z[spec.io_slice.start() + spec.io_len] = F128::ONE;
    assert!(r1cs.satisfies(&z));

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut ch_p = FsLaneChallenger::new(TEST_DOMAIN);
        prove_field_with_public_io(&r1cs, &z, &params, &spec, &io, &mut ch_p)
    }));
    match result {
        // The honest-prover guard fails fast on the mismatch...
        Err(_) => {}
        // ...and if a prover bypassed it, the verifier must reject.
        Ok((proof, commitment, _)) => {
            let mut ch_v = FsLaneChallenger::new(TEST_DOMAIN);
            assert!(
                verify_field_with_public_io(&r1cs, &commitment, &proof, &spec, &io, &mut ch_v)
                    .is_err(),
                "nonzero io padding accepted"
            );
        }
    }
}

/// A verifier using a different spec (shifted target slice) must reject a
/// proof made for the original spec.
#[test]
fn spec_mismatch_rejected() {
    let (r1cs, z, spec, io) = fixture(11, 7, 11);
    let params = params_for(11);

    let mut ch_p = FsLaneChallenger::new(TEST_DOMAIN);
    let (proof, commitment, _) =
        prove_field_with_public_io(&r1cs, &z, &params, &spec, &io, &mut ch_p);

    let mut other = spec.clone();
    other.claims[0].slice.index += 1;
    let mut ch_v = FsLaneChallenger::new(TEST_DOMAIN);
    assert!(
        verify_field_with_public_io(&r1cs, &commitment, &proof, &other, &io, &mut ch_v).is_err(),
        "spec substitution accepted"
    );
}

/// A public-io proof is not interchangeable with a plain proof: the plain
/// verifier must reject it (transcript diverges at the envelope binding).
#[test]
fn public_io_proof_rejected_by_plain_verifier() {
    let (r1cs, z, spec, io) = fixture(11, 7, 12);
    let params = params_for(11);

    let mut ch_p = FsLaneChallenger::new(TEST_DOMAIN);
    let (proof, commitment, _) =
        prove_field_with_public_io(&r1cs, &z, &params, &spec, &io, &mut ch_p);

    let mut ch_v = FsLaneChallenger::new(TEST_DOMAIN);
    assert!(
        verify_field(&r1cs, &commitment, &proof, &mut ch_v).is_err(),
        "public-io proof accepted by the plain verifier"
    );
}
