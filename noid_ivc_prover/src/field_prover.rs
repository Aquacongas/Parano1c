//! Top-level **FieldR1cs** prover: commit → bind → field zerocheck →
//! field lincheck → batched quirky-direct PCS open. Structural mirror of
//! [`crate::prover::prove`] on the F128-element witness; the verifier is
//! `noid_ivc_core::verifier::verify_field`.

use noid_ivc_core::challenger::Challenger;
use noid_ivc_core::field::F128;
use noid_ivc_core::field_r1cs::FieldR1cs;
use noid_ivc_core::lincheck::{self, QuirkyPoint};
use noid_ivc_core::pcs::{self, Commitment, PcsParams, QuirkyDirectClaim};
use noid_ivc_core::proof::{FieldR1csProof, R1csClaim, ZClaim, bind_statement_field};
use noid_ivc_core::zerocheck;

/// Prove a FieldR1cs instance on a witness of `2^m` F128 elements.
///
/// `pcs_params.m` counts **bits** (the PCS packing convention), so it must be
/// `r1cs.m + LOG_PACKING`: the committed vector is the witness itself, one
/// F128 element per packed slot, no repacking.
///
/// Returns the proof bundle, the witness commitment, and the two z-claims
/// (`ab` from lincheck, `c` from the zerocheck's extract_c — both quirky
/// points over the element variables).
pub fn prove_field<Ch: Challenger>(
    r1cs: &FieldR1cs,
    z: &[F128],
    pcs_params: &PcsParams,
    challenger: &mut Ch,
) -> (FieldR1csProof, Commitment, R1csClaim) {
    r1cs.validate_shape();
    assert_eq!(z.len(), 1usize << r1cs.m);
    assert_eq!(
        pcs_params.m,
        r1cs.m + pcs::LOG_PACKING,
        "pcs_params.m must be r1cs.m + LOG_PACKING (bit-log of the commitment)"
    );
    assert_eq!(
        r1cs.k_skip,
        zerocheck::K_SKIP,
        "the field zerocheck is hardwired to K_SKIP"
    );

    // Phase timings, env-gated (mirrors NOIDH_ZC_TIMING's pattern).
    let timing = std::env::var_os("NOIDH_FIELD_PROVE_TIMING").is_some();
    let mut t = std::time::Instant::now();
    let lap = move |label: &str, t: &mut std::time::Instant| {
        if timing {
            eprintln!(
                "[field-prove] {label}: {:.2} ms",
                t.elapsed().as_secs_f64() * 1e3
            );
        }
        *t = std::time::Instant::now();
    };

    // ---- PCS commit to the element witness (no repacking).
    let (commitment, prover_data) = pcs::commit(z, pcs_params);
    lap("pcs commit", &mut t);

    // ---- Bind the FS transcript to the statement.
    bind_statement_field(challenger, r1cs, &commitment);

    // ---- a = A·z, b = B·z over F128; c aliases z (C = I).
    let a = r1cs.apply_a(z);
    let b = r1cs.apply_b(z);
    lap("apply A/B", &mut t);

    // ---- Field zerocheck.
    let (zc_proof, zc_claim) = zerocheck::field::prove(&a, &b, z, r1cs.m, challenger);
    drop(a);
    drop(b);
    lap("zerocheck", &mut t);

    // ---- Zerocheck output → lincheck input (same quirky layout as the
    // boolean path).
    let inner_rest_len = r1cs.k_log - r1cs.k_skip;
    let x_ab = QuirkyPoint {
        z_skip: zc_claim.z,
        x_inner_rest: zc_claim.mlv_challenges[..inner_rest_len].to_vec(),
        x_outer: zc_claim.mlv_challenges[inner_rest_len..].to_vec(),
    };

    // ---- Field lincheck against the coefficient-carrying circuit.
    let (lc_proof, lc_claim) = lincheck::prove_field(
        z,
        r1cs.m,
        r1cs.k_log,
        r1cs.k_skip,
        r1cs.useful_rows,
        r1cs.csc_lincheck_circuit(),
        &x_ab,
        challenger,
    );
    lap("lincheck", &mut t);

    // ---- The two z-claims.
    let ab = ZClaim {
        point: QuirkyPoint {
            z_skip: lc_claim.r_inner_skip,
            x_inner_rest: lc_claim.r_inner_rest.clone(),
            x_outer: x_ab.x_outer.clone(),
        },
        value: lc_claim.w,
    };
    let c = ZClaim {
        point: QuirkyPoint {
            z_skip: zc_claim.z,
            x_inner_rest: zc_claim.r_rest[..inner_rest_len].to_vec(),
            x_outer: zc_claim.r_rest[inner_rest_len..].to_vec(),
        },
        value: zc_claim.c_eval,
    };

    // ---- Batched quirky-direct PCS open over both claims.
    let x_rest_of = |zc: &ZClaim| -> Vec<F128> {
        let mut v = zc.point.x_inner_rest.clone();
        v.extend_from_slice(&zc.point.x_outer);
        v
    };
    let claims = [
        QuirkyDirectClaim {
            z_skip: ab.point.z_skip,
            k_skip: r1cs.k_skip,
            x_rest: x_rest_of(&ab),
            value: ab.value,
        },
        QuirkyDirectClaim {
            z_skip: c.point.z_skip,
            k_skip: r1cs.k_skip,
            x_rest: x_rest_of(&c),
            value: c.value,
        },
    ];
    let pcs_open = pcs::open_batch_quirky_direct(z, &prover_data, &commitment, &claims, challenger);
    lap("pcs open", &mut t);

    let proof = FieldR1csProof {
        zerocheck: zc_proof,
        lincheck: lc_proof,
        pcs_open,
    };
    (proof, commitment, R1csClaim { ab, c })
}
