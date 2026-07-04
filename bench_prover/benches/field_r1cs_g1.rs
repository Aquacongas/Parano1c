// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Substrate throughput bench for the FieldR1cs prover: prove a synthetic
//! 2^19-constraint F128 trace and check the ≤ 4 s budget on reference
//! hardware; report sustained constraints/s against the per-block proving
//! budget (a 16-tx verifier-replay trace is ≈ 4M constraints and must be
//! provable well inside the 15 s block time; ≈ 0.27M/s sustained is the
//! floor, ≈ 1.0M/s the 4 s p95 target).
//!
//! Cases: 2^17 / 2^18 / 2^19 constraints (k_log = 16 — production-shaped
//! blocks), PCS log_inv_rate = 4, log_batch_size = 5.
//! `NOIDH_FIELD_PROVE_TIMING=1` adds the per-phase prover split.

use std::time::{Duration, Instant};

use bench_prover::{fmt_bytes, fmt_ms};
use noid_ivc_prover::challenger::FsLaneChallenger;
use noid_ivc_prover::field_r1cs::synthetic_satisfiable;
use noid_ivc_prover::pcs::{self, PcsParams};
use noid_ivc_prover::verifier::verify_field;
use noid_ivc_prover::field_prover::prove_field;

const DOMAIN: &[u8] = b"field-r1cs-g1-bench-v0";
const G1_BUDGET: Duration = Duration::from_secs(4);
const REPEATS: usize = 3;

fn main() {
    noid_ivc_prover::init_perf_thread_pool();
    let threads = rayon::current_num_threads();
    println!("== FieldR1cs substrate bench — rayon threads: {threads} ==\n");

    let mut g1_result: Option<(Duration, f64)> = None;

    // (m, k_log, log_inv_rate): the 2^19 gate case is swept across code
    // rates — the commit (Merkle over the codeword) is the dominant prover
    // cost, and rate trades hashing volume against FRI query count
    // (110 @ 1/16 … 148 @ 1/4), i.e. prover time against proof size and the
    // recursion slot's in-circuit query-replay budget.
    for &(m, k_log, log_inv_rate) in &[
        (17usize, 16usize, 2usize),
        (18, 16, 2),
        (19, 16, 4),
        (19, 16, 3),
        (19, 16, 2),
    ] {
        let n_constraints = 1usize << m;
        let params = PcsParams {
            m: m + pcs::LOG_PACKING,
            log_inv_rate,
            log_batch_size: 5,
            profile: Default::default(),
        };

        let t = Instant::now();
        let (r1cs, z) = synthetic_satisfiable(m, k_log, 0xC0FFEE ^ m as u64);
        let gen_time = t.elapsed();
        assert!(r1cs.satisfies(&z));

        // Prove (min of REPEATS; the min is the honest sustained-throughput
        // number — later runs benefit from warmed allocators/page cache).
        let mut best = Duration::MAX;
        let mut artifacts = None;
        for _ in 0..REPEATS {
            let mut ch = FsLaneChallenger::new(DOMAIN);
            let t = Instant::now();
            let out = prove_field(&r1cs, &z, &params, &mut ch);
            let dt = t.elapsed();
            if dt < best {
                best = dt;
            }
            artifacts = Some(out);
        }
        let (proof, commitment, _claim) = artifacts.unwrap();

        // Verify.
        let mut ch = FsLaneChallenger::new(DOMAIN);
        let t = Instant::now();
        verify_field(&r1cs, &commitment, &proof, &mut ch).expect("honest proof verifies");
        let verify_time = t.elapsed();

        let proof_bytes = bincode::serialize(&proof).expect("serializes").len();
        let rate = n_constraints as f64 / best.as_secs_f64();

        println!(
            "2^{m} constraints (k_log={k_log}, log_inv_rate={log_inv_rate}, nnz A+B/block = {}):",
            r1cs.a_0.nnz() + r1cs.b_0.nnz()
        );
        println!("  witness gen : {:>10}", fmt_ms(gen_time));
        println!("  prove (min) : {:>10}   ({:.3} M constraints/s)", fmt_ms(best), rate / 1e6);
        println!("  verify      : {:>10}", fmt_ms(verify_time));
        println!("  proof size  : {:>10}", fmt_bytes(proof_bytes));
        println!();

        if m == 19 && log_inv_rate == 2 {
            g1_result = Some((best, rate));
        }
    }

    let (t19, rate19) = g1_result.expect("2^19 case ran");
    let g1_pass = t19 <= G1_BUDGET;
    println!("== G1: prove 2^19 ≤ 4 s → {} ({}) ==", if g1_pass { "PASS" } else { "FAIL" }, fmt_ms(t19));
    println!(
        "== G1b inputs: measured {:.3} M constraints/s; required 0.27 M/s (block-time budget), 1.0 M/s (4 s p95 target) ==",
        rate19 / 1e6
    );
}
