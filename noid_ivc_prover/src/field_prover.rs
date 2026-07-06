//! Top-level **FieldR1cs** prover: commit → bind → field zerocheck →
//! field lincheck → batched quirky-direct PCS open. Structural mirror of
//! [`crate::prover::prove`] on the F128-element witness; the verifier is
//! `noid_ivc_core::verifier::verify_field`.

use noid_ivc_core::challenger::Challenger;
use noid_ivc_core::field::F128;
use noid_ivc_core::field_r1cs::{FieldR1cs, FieldRowCircuit};
use noid_ivc_core::lincheck::{self, QuirkyPoint};
use noid_ivc_core::pcs::{self, Commitment, PcsParams, QuirkyDirectClaim};
use noid_ivc_core::proof::{FieldR1csProof, R1csClaim, ZClaim, bind_statement_field};
use noid_ivc_core::public_io::{PublicIoSpec, assert_witness_matches_io, bind_public_io};
use noid_ivc_core::zerocheck;

/// Resident set size in MiB (Linux `/proc/self/status`) for the env-gated
/// per-phase memory column: `(current VmRSS, peak VmHWM)`. VmHWM is the
/// high-water mark since process start — monotone, so a jump between two lap
/// prints reveals an intra-phase transient (e.g. the lincheck parallel fold's
/// per-thread combs) that the lap-boundary VmRSS misses. Returns `(0, 0)` where
/// unavailable.
fn vmrss_mb() -> (u64, u64) {
    let field = |s: &str, key: &str| -> u64 {
        s.lines()
            .find(|l| l.starts_with(key))
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|kb| kb.parse::<u64>().ok())
            .map(|kb| kb / 1024)
            .unwrap_or(0)
    };
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .map(|s| (field(&s, "VmRSS:"), field(&s, "VmHWM:")))
        .unwrap_or((0, 0))
}

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
    prove_field_inner(r1cs, z, pcs_params, None, challenger)
}

/// [`prove_field`] with a public-IO envelope: right after the statement
/// binding, absorb the spec + envelope lanes, sample the binding point, and
/// append the IO claims to the batched PCS opening (see
/// `noid_ivc_core::public_io`). The witness must hold the envelope lanes in
/// the spec's IO slice (zero-padded) — asserted here.
pub fn prove_field_with_public_io<Ch: Challenger>(
    r1cs: &FieldR1cs,
    z: &[F128],
    pcs_params: &PcsParams,
    spec: &PublicIoSpec,
    io: &[F128],
    challenger: &mut Ch,
) -> (FieldR1csProof, Commitment, R1csClaim) {
    prove_field_inner(r1cs, z, pcs_params, Some((spec, io)), challenger)
}

fn prove_field_inner<Ch: Challenger>(
    r1cs: &FieldR1cs,
    z: &[F128],
    pcs_params: &PcsParams,
    public_io: Option<(&PublicIoSpec, &[F128])>,
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

    // Phase timings + resident-set size, env-gated (mirrors NOIDH_ZC_TIMING's
    // pattern). The RSS column shows where the prover's memory grows — commit
    // (codeword + Merkle tree), lincheck (constraint matrix), open — so the
    // dominant buffer is visible without an external profiler.
    let timing = std::env::var_os("NOIDH_FIELD_PROVE_TIMING").is_some();
    let mut t = std::time::Instant::now();
    let lap = move |label: &str, t: &mut std::time::Instant| {
        if timing {
            let (rss, peak) = vmrss_mb();
            eprintln!(
                "[field-prove] {label}: {:.2} ms, RSS {rss} MB (peak {peak} MB)",
                t.elapsed().as_secs_f64() * 1e3,
            );
        }
        *t = std::time::Instant::now();
    };

    if timing {
        // Constraint-matrix residency. Dictionary-encoded CSR: per nonzero a
        // u32 column index + a u32 value-table index (8 B), plus 8 B/row
        // offsets and a tiny value table (the matrix is a protocol constant
        // with a few hundred distinct coefficients). The plain-CSR `Vec<F128>`
        // was 20 B/nonzero; the original `Vec<Vec<(u32,F128)>>` 32 B/nonzero +
        // a 24 B row header. The matrix is the largest resident prover buffer
        // at block-bearing sizes.
        let a_nnz = r1cs.a_0.nnz();
        let b_nnz = r1cs.b_0.nnz();
        let nnz = a_nnz + b_nnz;
        let a_dist = r1cs.a_0.distinct_values();
        let b_dist = r1cs.b_0.distinct_values();
        let rows = 1usize << r1cs.k_log;
        let mb = |b: usize| b / (1024 * 1024);
        let dict = nnz * 8 + rows * 8 * 2 + (a_dist + b_dist) * 16;
        let csr = nnz * 20 + rows * 8 * 2;
        let vecvec = nnz * 32 + rows * 24 * 2;
        let (rss, peak) = vmrss_mb();
        eprintln!(
            "[field-prove] matrix @entry: a_nnz={a_nnz} b_nnz={b_nnz} rows={rows} \
             distinct={a_dist}+{b_dist} | dict≈{}MB (plainCSR≈{}MB, VecVec≈{}MB), \
             RSS {rss}MB (peak {peak}MB)",
            mb(dict),
            mb(csr),
            mb(vecvec),
        );
    }

    // ---- PCS commit to the element witness (no repacking).
    let (commitment, prover_data) = pcs::commit(z, pcs_params);
    lap("pcs commit", &mut t);

    // ---- Bind the FS transcript to the statement.
    bind_statement_field(challenger, r1cs, &commitment);

    // ---- Public-IO envelope binding (before any sub-protocol challenge).
    let io_claims: Vec<QuirkyDirectClaim> = match public_io {
        Some((spec, io)) => {
            assert_witness_matches_io(z, spec, io);
            bind_public_io(challenger, spec, io, r1cs.m)
        }
        None => Vec::new(),
    };

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
        // Fold lincheck off the row-major `a_0`/`b_0` the caller already owns,
        // rather than materializing (and caching) a transposed CSC copy. This
        // keeps only ONE constraint-matrix representation resident through the
        // lincheck+open peak (~halving matrix RAM). The fold is value-identical
        // to `csc_lincheck_circuit()` (same `comb_vec`), so the proof is
        // byte-identical. The CSC path stays for the verifier / trace twin.
        &FieldRowCircuit::new(&r1cs.a_0, &r1cs.b_0, r1cs.const_pin),
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
    let mut claims = vec![
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
    claims.extend(io_claims);
    let pcs_open = pcs::open_batch_quirky_direct(z, &prover_data, &commitment, &claims, challenger);
    lap("pcs open", &mut t);

    let proof = FieldR1csProof {
        zerocheck: zc_proof,
        lincheck: lc_proof,
        pcs_open,
    };
    (proof, commitment, R1csClaim { ab, c })
}
