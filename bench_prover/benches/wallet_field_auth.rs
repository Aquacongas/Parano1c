// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Wallet-side FieldR1cs authorization proving — the decision bench.
//!
//! Question under measurement: if the wallet proved its owner-authorization
//! statement directly as a FieldR1cs instance (the same proof system the
//! block proof runs on) instead of the current GKR + compact-FRI capsule,
//! what would the wallet pay (prove time on mobile-class hardware, proof
//! bytes) and what would a full block carry (bytes x 255 standard txs / 40
//! sweeps vs the wire caps)?
//!
//! The circuit here is the representative builder-shaped Poseidon2b chain
//! (~360 rows/permutation, ~20 nnz/row): a real authorization circuit is a
//! Poseidon spine over address derivation + intent binding, so its cost is
//! bracketed by chain instances of 2^12..2^16 constraints. Plug the exact
//! authorization circuit size into this table once it exists.
//!
//! Mobile proxy: a phone-class SoC is modeled as the 4-thread pool run
//! multiplied by a stated per-core slowdown factor (2-3x for recent
//! flagships, ~4x for mid-range) — printed alongside the raw numbers.
//!
//! The transcript grind: `prove_field` includes a 16-bit pre-query grind
//! sized to shrink the FRI query table for the block-proof recursion; the
//! nonce search cost is a geometric random variable (mean 2^16 trials)
//! whose sample depends on the transcript state. Prove times are therefore
//! MEDIANS over several transcript domains, and the expected grind cost is
//! estimated separately as a mean over independent probe states. A
//! wallet-profile prover would not grind (per-tx proofs are verified
//! natively and folded, never replayed query-by-query in the recursion),
//! so `prove - E[grind]` approximates the wallet-profile prove time.

use std::time::Duration;

use bench_prover::{fmt_bytes, fmt_ms, median, poseidon_chain_field_instance, time_once};
use noid_ivc_prover::challenger::{Challenger, FsLaneChallenger};
use noid_ivc_prover::field_prover::prove_field;
use noid_ivc_prover::field_r1cs::FieldR1cs;
use noid_ivc_prover::field::F128;
use noid_ivc_prover::pcs::{self, PcsParams, QUERY_GRIND_BITS};
use noid_ivc_prover::verifier::verify_field;

const DOMAINS: [&[u8]; 5] = [
    b"wallet-field-auth-bench-d0",
    b"wallet-field-auth-bench-d1",
    b"wallet-field-auth-bench-d2",
    b"wallet-field-auth-bench-d3",
    b"wallet-field-auth-bench-d4",
];
const GRIND_PROBES: usize = 8;
const MOBILE_THREADS: usize = 4;
/// Per-core slowdown of a phone-class SoC vs this desktop for this
/// hash/NTT-bound workload (stated assumption, not a measurement).
const MOBILE_PER_CORE_FACTOR_LOW: f64 = 2.0;
const MOBILE_PER_CORE_FACTOR_HIGH: f64 = 4.0;

struct Case {
    label: String,
    prove_full: Duration,
    prove_mobile: Duration,
    verify: Duration,
    proof_bytes: usize,
}

fn median_prove(r1cs: &FieldR1cs, z: &[F128], params: &PcsParams) -> Duration {
    median(
        DOMAINS
            .iter()
            .map(|d| {
                let mut ch = FsLaneChallenger::new(d);
                time_once(|| prove_field(r1cs, z, params, &mut ch)).0
            })
            .collect(),
    )
}

/// Expected grind cost: mean of the deterministic nonce search over
/// independent probe transcript states.
fn expected_grind() -> Duration {
    let total: Duration = (0..GRIND_PROBES)
        .map(|i| {
            let mut ch = FsLaneChallenger::new(b"wallet-grind-probe");
            ch.observe_bytes(&[i as u8]);
            time_once(|| ch.grind_pow(QUERY_GRIND_BITS)).0
        })
        .sum();
    total / GRIND_PROBES as u32
}

fn run_case(
    label: &str,
    r1cs: &FieldR1cs,
    z: &[F128],
    mobile_pool: &rayon::ThreadPool,
    log_inv_rate: usize,
    log_batch_size: usize,
) -> Case {
    let params = PcsParams {
        m: r1cs.m + pcs::LOG_PACKING,
        log_inv_rate,
        log_batch_size,
        profile: Default::default(),
    };
    // Shape constants (computed once per circuit shape, cacheable in the
    // wallet binary) — excluded from the prove loop.
    let _ = r1cs.statement_digest();
    let _ = r1cs.csc_lincheck_circuit();

    let prove_full = median_prove(r1cs, z, &params);
    let prove_mobile = mobile_pool.install(|| median_prove(r1cs, z, &params));

    let mut ch = FsLaneChallenger::new(DOMAINS[0]);
    let (proof, commitment, _claim) = prove_field(r1cs, z, &params, &mut ch);
    let mut ch = FsLaneChallenger::new(DOMAINS[0]);
    let (verify, out) = time_once(|| verify_field(r1cs, &commitment, &proof, &mut ch));
    out.expect("honest proof verifies");
    let proof_bytes = bincode::serialize(&proof).expect("serializes").len();

    Case {
        label: label.to_string(),
        prove_full,
        prove_mobile,
        verify,
        proof_bytes,
    }
}

fn main() {
    noid_ivc_prover::init_perf_thread_pool();
    let threads = rayon::current_num_threads();
    let mobile_pool = rayon::ThreadPoolBuilder::new()
        .num_threads(MOBILE_THREADS)
        .build()
        .expect("mobile-proxy pool");
    println!(
        "== Wallet FieldR1cs-auth bench — full pool {threads} threads, mobile proxy {MOBILE_THREADS} threads ==\n"
    );

    let grind_full = expected_grind();
    let grind_mobile = mobile_pool.install(expected_grind);
    println!(
        "E[16-bit grind] : {} full / {} @{MOBILE_THREADS}t   (embedded once in every prove below)\n",
        fmt_ms(grind_full),
        fmt_ms(grind_mobile)
    );

    let mut cases = Vec::new();

    // Chain lengths sized to land just under 2^m rows at ~360 rows/perm.
    for &chain in &[11usize, 22, 45, 90, 182] {
        let (gen_time, (r1cs, z)) = time_once(|| poseidon_chain_field_instance(chain));
        assert!(r1cs.satisfies(&z));
        let case = run_case(
            &format!("2^{} lir2 lb5", r1cs.m),
            &r1cs,
            &z,
            &mobile_pool,
            2,
            5,
        );
        println!(
            "{} ({chain} perms, witness gen {}):",
            case.label,
            fmt_ms(gen_time)
        );
        println!(
            "  prove {} full / {} @{MOBILE_THREADS}t   verify {}   proof {}",
            fmt_ms(case.prove_full),
            fmt_ms(case.prove_mobile),
            fmt_ms(case.verify),
            fmt_bytes(case.proof_bytes)
        );
        cases.push(case);
    }

    // Proof-byte frontier at the mid bracket: rate and leaf-batch variants
    // (fewer queries / smaller leaves shrink bytes at more prover NTT work).
    println!("\n== Param variants @ 2^14 (bytes vs prove time) ==");
    let (_, (r1cs14, z14)) = time_once(|| poseidon_chain_field_instance(45));
    for &(lir, lb) in &[(2usize, 2usize), (3, 2), (4, 2), (4, 5)] {
        let case = run_case(
            &format!("2^{} lir{lir} lb{lb}", r1cs14.m),
            &r1cs14,
            &z14,
            &mobile_pool,
            lir,
            lb,
        );
        println!(
            "  {}: prove {} full / {} @{MOBILE_THREADS}t   verify {}   proof {}",
            case.label,
            fmt_ms(case.prove_full),
            fmt_ms(case.prove_mobile),
            fmt_ms(case.verify),
            fmt_bytes(case.proof_bytes)
        );
        cases.push(case);
    }

    println!("\n== Mobile projections (4t median x per-core factor; sans grind in parens) ==");
    for c in &cases {
        let with = c.prove_mobile.as_secs_f64();
        let sans = c.prove_mobile.saturating_sub(grind_mobile).as_secs_f64();
        println!(
            "  {:<14}: {:>5.0} - {:>5.0} ms   (wallet profile, no grind: {:>5.0} - {:>5.0} ms)",
            c.label,
            with * MOBILE_PER_CORE_FACTOR_LOW * 1e3,
            with * MOBILE_PER_CORE_FACTOR_HIGH * 1e3,
            sans * MOBILE_PER_CORE_FACTOR_LOW * 1e3,
            sans * MOBILE_PER_CORE_FACTOR_HIGH * 1e3,
        );
    }

    println!("\n== Block wire arithmetic (per-tx proof bytes vs caps) ==");
    println!(
        "  caps: per-std-auth {} , per-sweep-auth {} , sidecar {} , proof+sidecar {}",
        fmt_bytes(noid_chain::consensus::wire_limits::MAX_STANDARD_AUTHORIZATION_BYTES),
        fmt_bytes(noid_chain::consensus::wire_limits::MAX_SWEEP_AUTHORIZATION_BYTES),
        fmt_bytes(noid_chain::consensus::wire_limits::MAX_BLOCK_AUTH_SIDECAR_BYTES),
        fmt_bytes(noid_chain::consensus::wire_limits::MAX_BLOCK_PROOF_PLUS_SIDECAR_BYTES),
    );
    for c in &cases {
        let x255 = c.proof_bytes * 255;
        let x40 = c.proof_bytes * 40;
        let std_ok = c.proof_bytes
            <= noid_chain::consensus::wire_limits::MAX_STANDARD_AUTHORIZATION_BYTES;
        let sidecar_ok =
            x255 <= noid_chain::consensus::wire_limits::MAX_BLOCK_AUTH_SIDECAR_BYTES;
        println!(
            "  {:<14}: {} /tx   x255 = {}   x40 = {}   per-tx cap {}   sidecar cap {}",
            c.label,
            fmt_bytes(c.proof_bytes),
            fmt_bytes(x255),
            fmt_bytes(x40),
            if std_ok { "OK" } else { "OVER" },
            if sidecar_ok { "OK" } else { "OVER" },
        );
    }

    println!("\n== Node-side native verify (mempool admission pays this per tx) ==");
    for c in &cases {
        println!(
            "  {:<14}: {} /tx   x255 = {:.0} ms",
            c.label,
            fmt_ms(c.verify),
            c.verify.as_secs_f64() * 255.0 * 1e3
        );
    }
}
