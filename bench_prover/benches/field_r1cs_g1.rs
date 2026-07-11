// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Substrate throughput bench for the FieldR1cs prover — the G1 gate.
//!
//! The gate case is a **builder-shaped single-block instance** (a Poseidon2b
//! permutation chain from `FieldR1csBuilder`, `m = k_log`, ~20 nnz/row):
//! the same coefficient density, block structure, and wire locality as a
//! production verifier-replay trace. Synthetic multi-block instances
//! (~2.5 nnz/row) overstate sustained throughput and are kept only as a
//! labeled comparison point.
//!
//! Per-shape-class constants (the statement digest and the CSC lincheck
//! circuit) are timed separately and NOT charged to the prove loop: in
//! production both are computed once per shape class and installed on fresh
//! instances (`seed_statement_digest`), never per block. The reported prove
//! time is the warm per-block cost.
//!
//! Budget: prove 2^19 ≤ 4 s on reference hardware; a 16-tx verifier-replay
//! trace is ≈ 4M constraints and must be provable well inside the 15 s block
//! time (≈ 0.27M/s sustained floor, ≈ 1.0M/s the 4 s p95 target).
//!
//! `NOIDH_FIELD_PROVE_TIMING=1` adds the per-phase prover split;
//! `NOIDH_COMMIT_TIMING=1` splits the commit into NTT vs Merkle.

use std::time::{Duration, Instant};

use bench_prover::{fmt_bytes, fmt_ms, poseidon_chain_field_instance};
use noid_ivc_prover::challenger::FsLaneChallenger;
use noid_ivc_prover::field::F128;
use noid_ivc_prover::field_prover::prove_field;
use noid_ivc_prover::field_r1cs::{synthetic_satisfiable, FieldR1cs};
use noid_ivc_prover::pcs::{self, PcsParams};
use noid_ivc_prover::verifier::verify_field;

const DOMAIN: &[u8] = b"field-r1cs-g1-bench-v0";
const G1_BUDGET: Duration = Duration::from_secs(4);
const REPEATS: usize = 3;

struct CaseResult {
    prove: Duration,
    rate: f64,
}

fn run_case(
    label: &str,
    r1cs: &FieldR1cs,
    z: &[F128],
    gen_time: Duration,
    log_inv_rate: usize,
    log_batch_size: usize,
) -> CaseResult {
    let m = r1cs.m;
    let n_constraints = 1usize << m;
    let params = PcsParams {
        m: m + pcs::LOG_PACKING,
        log_inv_rate,
        log_batch_size,
        profile: Default::default(),
    };

    // Per-shape-class constants, timed apart from the prove loop.
    let t = Instant::now();
    let _ = r1cs.statement_digest();
    let digest_time = t.elapsed();
    let t = Instant::now();
    let _ = r1cs.csc_lincheck_circuit();
    let csc_time = t.elapsed();

    // Warm per-block prove (min of REPEATS — the honest sustained number;
    // later runs benefit from warmed allocators/page cache).
    let mut best = Duration::MAX;
    let mut artifacts = None;
    for _ in 0..REPEATS {
        let mut ch = FsLaneChallenger::new(DOMAIN);
        let t = Instant::now();
        let out = prove_field(r1cs, z, &params, &mut ch);
        let dt = t.elapsed();
        if dt < best {
            best = dt;
        }
        artifacts = Some(out);
    }
    let (proof, commitment, _claim) = artifacts.unwrap();

    let mut ch = FsLaneChallenger::new(DOMAIN);
    let t = Instant::now();
    verify_field(r1cs, &commitment, &proof, &mut ch).expect("honest proof verifies");
    let verify_time = t.elapsed();

    let proof_bytes = bincode::serialize(&proof).expect("serializes").len();
    let rate = n_constraints as f64 / best.as_secs_f64();

    println!(
        "{label}: 2^{m} constraints (k_log={}, lir={log_inv_rate}, lb={log_batch_size}, nnz A+B/block = {})",
        r1cs.k_log,
        r1cs.a_0.nnz() + r1cs.b_0.nnz()
    );
    println!("  witness gen    : {:>10}", fmt_ms(gen_time));
    println!(
        "  shape constants: {:>10} digest + {:>10} csc   (once per shape class)",
        fmt_ms(digest_time),
        fmt_ms(csc_time)
    );
    println!(
        "  prove (min)    : {:>10}   ({:.3} M constraints/s)",
        fmt_ms(best),
        rate / 1e6
    );
    println!("  verify         : {:>10}", fmt_ms(verify_time));
    println!("  proof size     : {:>10}", fmt_bytes(proof_bytes));
    println!();

    CaseResult { prove: best, rate }
}

fn main() {
    noid_ivc_prover::init_perf_thread_pool();
    let threads = rayon::current_num_threads();
    println!("== FieldR1cs substrate bench — rayon threads: {threads} ==\n");

    let mut g1_result: Option<CaseResult> = None;

    // Builder-shaped gate cases. Chain lengths sized as ceil((2^m − 5)/360):
    // 364 ≈ 2^17, 1456 ≈ 2^19. The 2^19 case is swept across code rates —
    // commit hashing is the dominant prover cost, and rate trades that
    // against FRI query count (110 @ 1/16 … 148 @ 1/4), i.e. prover time
    // against proof size and the recursion slot's query-replay budget —
    // plus a small-leaf (lb=2) variant, the recursion-side leaf diet whose
    // prover cost delta this quantifies.
    for &(chain, lir, lb) in &[
        (364usize, 2usize, 5usize),
        (1456, 2, 5),
        (1456, 3, 5),
        (1456, 4, 5),
        (1456, 2, 2),
    ] {
        let t = Instant::now();
        let (r1cs, z) = poseidon_chain_field_instance(chain);
        let gen_time = t.elapsed();
        assert!(r1cs.satisfies(&z));

        let result = run_case("builder-shaped", &r1cs, &z, gen_time, lir, lb);
        if r1cs.m == 19 && lir == 2 && lb == 5 {
            g1_result = Some(result);
        }
    }

    // Legacy synthetic multi-block shape (~2.5 nnz/row, no builder locality):
    // kept as a comparison point only — it overstates sustained throughput
    // and is NOT the gate.
    {
        let m = 19usize;
        let t = Instant::now();
        let (r1cs, z) = synthetic_satisfiable(m, 16, 0xC0FFEE ^ m as u64);
        let gen_time = t.elapsed();
        assert!(r1cs.satisfies(&z));
        run_case(
            "synthetic (comparison, not the gate)",
            &r1cs,
            &z,
            gen_time,
            2,
            5,
        );
    }

    let g1 = g1_result.expect("builder-shaped 2^19 gate case ran");
    let g1_pass = g1.prove <= G1_BUDGET;
    println!(
        "== G1: builder-shaped prove 2^19 ≤ 4 s → {} ({}) ==",
        if g1_pass { "PASS" } else { "FAIL" },
        fmt_ms(g1.prove)
    );
    println!(
        "== G1b inputs: measured {:.3} M constraints/s; required 0.27 M/s (block-time budget), 1.0 M/s (4 s p95 target) ==",
        g1.rate / 1e6
    );
}
