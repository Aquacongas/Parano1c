// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid. All rights reserved.

//! Release report: prints a single branded, screenshot-ready table with the
//! headline numbers devs usually compare across implementations.
//!
//! Run with:  cargo bench --bench release_report
//!
//! All figures are wall-clock medians over a small number of samples, measured
//! end-to-end on one machine. The trace size (log2) is the primary knob —
//! everything else is derived from it.

use std::time::{Duration, Instant};

use noid_core::ntt::forward_ntt_parallel;
use noid_core::packed::PACKED_LANES;
use noid_core::sumcheck::prove::prove_single_packed;
use noid_core::{AdditiveNTT, Block128, TowerField};

use noid_fri::channel::Channel;
use noid_fri::code::{LOG_RATE, RATE};
use noid_fri::merkle::{compute_leaf_hashes, MerkleTree};
use noid_fri::prover::{commit, prove};
use noid_fri::verifier::verify;
use noid_fri::{NUM_QUERIES, TAU};

use noid_poseidon2b::native::compression::Poseidon2bSponge;

use rand::rngs::StdRng;
use rand::Rng;
use rand::SeedableRng;

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/// Trace sizes (log2) shown in the main table.
const LOG_TRACES: &[usize] = &[14, 16, 18, 20];

/// Warmup + sample counts for each data point.
const WARMUP: usize = 1;
const SAMPLES: usize = 3;

// ---------------------------------------------------------------------------
// Timing helpers
// ---------------------------------------------------------------------------

fn median(mut v: Vec<Duration>) -> Duration {
    v.sort();
    v[v.len() / 2]
}

fn time<F: FnMut()>(mut f: F) -> Duration {
    for _ in 0..WARMUP {
        f();
    }
    let mut samples = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        let t = Instant::now();
        f();
        samples.push(t.elapsed());
    }
    median(samples)
}

fn fmt_ms(d: Duration) -> String {
    let ms = d.as_secs_f64() * 1_000.0;
    if ms >= 1_000.0 {
        format!("{:>9.2} s ", ms / 1_000.0)
    } else if ms >= 1.0 {
        format!("{:>9.2} ms", ms)
    } else {
        format!("{:>9.2} us", ms * 1_000.0)
    }
}

fn fmt_kb(bytes: usize) -> String {
    let kb = bytes as f64 / 1024.0;
    if kb >= 1024.0 {
        format!("{:>8.2} MB", kb / 1024.0)
    } else {
        format!("{:>8.2} KB", kb)
    }
}

fn fmt_count(n: usize) -> String {
    const KI: f64 = 1024.0;
    const MI: f64 = 1024.0 * 1024.0;
    let nf = n as f64;
    if nf >= MI {
        format!("{:.0}M", nf / MI)
    } else if nf >= KI {
        format!("{:.0}K", nf / KI)
    } else {
        format!("{}", n)
    }
}

// ---------------------------------------------------------------------------
// Environment detection
// ---------------------------------------------------------------------------

fn detect_arch() -> &'static str {
    if cfg!(target_arch = "x86_64") {
        "x86_64"
    } else if cfg!(target_arch = "aarch64") {
        "aarch64"
    } else {
        "unknown"
    }
}

fn detect_simd() -> &'static str {
    #[cfg(target_arch = "x86_64")]
    {
        if is_x86_feature_detected!("avx512f") {
            return "AVX-512";
        }
        if is_x86_feature_detected!("avx2") {
            return "AVX2";
        }
        if is_x86_feature_detected!("pclmulqdq") {
            return "SSE+CLMUL";
        }
        "scalar"
    }
    #[cfg(target_arch = "aarch64")]
    {
        "NEON+PMULL"
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        "scalar"
    }
}

// ---------------------------------------------------------------------------
// Proof-size estimator
// ---------------------------------------------------------------------------

/// Estimated proof size in bytes for a given log_len.
///
/// Matches the layout of `EvalProof`:
///   upper_partial_evals: 2^TAU   * 16 B
///   sum_check_oracles:  (log_len - TAU) rounds * 3 coeffs * 16 B
///   fri_oracles:        (log_len - TAU) roots  * 32 B
///   fri_queried_symbols: rounds * NUM_QUERIES * 2 * 16 B
///   fri_merkle_paths:   Σ_round NUM_QUERIES * depth_r * 32 B
///   final_codeword:     RATE * 16 B
fn estimate_proof_bytes(log_len: usize) -> usize {
    let tau = TAU.min(log_len);
    let n_rounds = log_len.saturating_sub(tau);

    let upper = (1usize << tau) * 16;
    let sum_check = n_rounds * 3 * 16;
    let fri_roots = n_rounds * 32;
    let queried = n_rounds * NUM_QUERIES * 2 * 16;

    // Merkle path depth shrinks by 1 per folding round. Depth_0 = log_len + LOG_RATE - 1.
    let mut paths = 0usize;
    for r in 0..n_rounds {
        let depth = (log_len + LOG_RATE).saturating_sub(1 + r);
        paths += NUM_QUERIES * depth * 32;
    }

    let final_cw = RATE * 16;

    upper + sum_check + fri_roots + queried + paths + final_cw
}

// ---------------------------------------------------------------------------
// Row measurements
// ---------------------------------------------------------------------------

struct Row {
    log_len: usize,
    ntt_ms: Duration,
    merkle_ms: Duration,
    commit_ms: Duration,
    prove_ms: Duration,
    verify_ms: Duration,
    sumcheck_ms: Duration,
    proof_bytes: usize,
    throughput_cells_per_s: f64,
}

fn bench_row(log_len: usize, hasher: &Poseidon2bSponge) -> Row {
    let n = 1usize << log_len;
    let mut rng = StdRng::seed_from_u64(0xBEAD_C0DE_DEAD_BEEF ^ log_len as u64);

    let evals: Vec<Block128> = (0..n).map(|_| Block128::from(rng.gen::<u128>())).collect();
    let eval_point: Vec<Block128> = (0..log_len)
        .map(|_| Block128::from(rng.gen::<u128>()))
        .collect();

    // NTT on the rate-expanded domain — exactly what `commit()` runs inside
    // `Code::new_parallel`. The input is zero-extended from `n` to `n*RATE`
    // and transformed against a basis of size `log_len + LOG_RATE`.
    let ntt = AdditiveNTT::<Block128>::new(log_len + LOG_RATE);
    let code_len = n * RATE;
    let mut expanded: Vec<Block128> = Vec::with_capacity(code_len);
    expanded.extend_from_slice(&evals);
    expanded.resize(code_len, Block128::ZERO);
    let expanded_basis: Vec<Block128> = (0..log_len + LOG_RATE)
        .map(|i| Block128::from(1u128 << i))
        .collect();
    let ntt_ms = time(|| {
        let _ = forward_ntt_parallel(&expanded, &expanded_basis);
    });

    // Merkle commit over the RS-expanded codeword: leaf hashing + tree build.
    // This is the Merkle half of `commit()` (NTT not included here).
    let leaves_raw: Vec<Block128> = (0..code_len)
        .map(|i| Block128::from((i as u128).wrapping_mul(0x9E3779B97F4A7C15)))
        .collect();
    let merkle_ms = time(|| {
        let leaf_hashes = compute_leaf_hashes(&leaves_raw, hasher);
        let _ = MerkleTree::new_parallel(leaf_hashes, hasher);
    });

    // Sumcheck on a trace-sized polynomial.
    let sumcheck_poly: Vec<Block128> = evals.clone();
    let claimed_sum = sumcheck_poly
        .iter()
        .fold(Block128::ZERO, |a, b| a + *b);
    let sumcheck_ms = time(|| {
        let mut t = Vec::new();
        prove_single_packed(&sumcheck_poly, claimed_sum, &mut t);
    });

    // Commit.
    let commit_ms = time(|| {
        let _ = commit(&evals, &ntt, hasher);
    });
    let (commitment, _tree, _code) = commit(&evals, &ntt, hasher);

    // Prove.
    let prove_ms = time(|| {
        let mut ch = Channel::new();
        let _ = prove(&commitment, &evals, &eval_point, &ntt, &mut ch, hasher);
    });
    let mut ch = Channel::new();
    let proof = prove(&commitment, &evals, &eval_point, &ntt, &mut ch, hasher);

    // Derive the claimed eval for verify().
    let claimed_eval = noid_core::mle::evaluate::evaluate_slice(&evals, &eval_point);

    // Verify.
    let verify_ms = time(|| {
        let mut ch = Channel::new();
        let _ = verify(
            &commitment,
            &eval_point,
            claimed_eval,
            proof.clone(),
            &ntt,
            &mut ch,
            hasher,
        );
    });

    let proof_bytes = estimate_proof_bytes(log_len);
    let throughput = n as f64 / prove_ms.as_secs_f64();

    Row {
        log_len,
        ntt_ms,
        merkle_ms,
        commit_ms,
        prove_ms,
        verify_ms,
        sumcheck_ms,
        proof_bytes,
        throughput_cells_per_s: throughput,
    }
}

// ---------------------------------------------------------------------------
// ASCII banner + table
// ---------------------------------------------------------------------------

const BANNER: &str = r#"
   ____   _    ____      _    _   _  ___ ___ ____
  |  _ \ / \  |  _ \    / \  | \ | |/ _ \_ _|  _ \
  | |_) / _ \ | |_) |  / _ \ |  \| | | | | || | | |
  |  __/ ___ \|  _ <  / ___ \| |\  | |_| | || |_| |
  |_| /_/   \_\_| \_\/_/   \_\_| \_|\___/___|____/

  PARANOID  --  FRI + Poseidon2b  --  Release Report
"#;

fn print_banner() {
    println!("{}", BANNER);
    println!("  Binary-tower GF(2^128) prover. All measurements are wall-clock,");
    println!("  median of {} samples, single-process multi-threaded.", SAMPLES);
    println!();
}

fn print_environment() {
    let threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);

    println!("  +------------------------- ENVIRONMENT -------------------------+");
    println!("  | {:<18} {:<42} |", "arch:", detect_arch());
    println!("  | {:<18} {:<42} |", "simd:", detect_simd());
    println!("  | {:<18} {:<42} |", "os:", std::env::consts::OS);
    println!("  | {:<18} {:<42} |", "threads (rayon):", threads);
    println!("  | {:<18} {:<42} |", "packed lanes:", PACKED_LANES.to_string());
    println!("  | {:<18} {:<42} |", "profile:", if cfg!(debug_assertions) { "debug (!)" } else { "release" });
    println!("  +---------------------------------------------------------------+");
    println!();
}

fn print_params() {
    println!("  +------------------------- PARAMETERS --------------------------+");
    println!("  | {:<28} {:<32} |", "field:", "GF(2^128) binary tower");
    println!("  | {:<28} {:<32} |", "commitment hash:", "Poseidon2b (t=8, 128-bit state)");
    println!("  | {:<28} {:<32} |", "PCS:", "FRI (DEEP-FRI style)");
    println!("  | {:<28} {:<32} |", "code rate (RATE):", format!("{} (log2 = {})", RATE, LOG_RATE));
    println!("  | {:<28} {:<32} |", "num FRI queries:", NUM_QUERIES.to_string());
    println!("  | {:<28} {:<32} |", "TAU (batched vars):", TAU.to_string());
    println!("  | {:<28} {:<32} |", "NTT:", "additive (Lin-Chung-Han)");
    println!("  +---------------------------------------------------------------+");
    println!();
}

fn print_table(rows: &[Row]) {
    println!("  +-------------------------------------------- PROVER PERFORMANCE --------------------------------------------+");
    println!(
        "  | {:>7} | {:>7} | {:>12} | {:>12} | {:>12} | {:>12} | {:>12} | {:>11} |",
        "log_n", "trace", "ntt", "merkle", "commit", "prove", "verify", "proof"
    );
    println!("  |---------+---------+--------------+--------------+--------------+--------------+--------------+-------------|");
    for r in rows {
        println!(
            "  | {:>7} | {:>7} | {:>12} | {:>12} | {:>12} | {:>12} | {:>12} | {:>11} |",
            r.log_len,
            fmt_count(1 << r.log_len),
            fmt_ms(r.ntt_ms),
            fmt_ms(r.merkle_ms),
            fmt_ms(r.commit_ms),
            fmt_ms(r.prove_ms),
            fmt_ms(r.verify_ms),
            fmt_kb(r.proof_bytes),
        );
    }
    println!("  +------------------------------------------------------------------------------------------------------------+");
    println!();

    println!("  +------------------------- THROUGHPUT --------------------------+");
    println!("  | {:>7} | {:>12} | {:>24} |", "log_n", "sumcheck", "prove throughput");
    println!("  |---------+--------------+--------------------------|");
    for r in rows {
        let cells_s = r.throughput_cells_per_s;
        let label = if cells_s >= 1e6 {
            format!("{:>10.2} Mcells/s", cells_s / 1e6)
        } else {
            format!("{:>10.2} Kcells/s", cells_s / 1e3)
        };
        println!(
            "  | {:>7} | {:>12} | {:>24} |",
            r.log_len,
            fmt_ms(r.sumcheck_ms),
            label,
        );
    }
    println!("  +---------------------------------------------------------------+");
    println!();
}

fn print_footer() {
    println!("  columns:");
    println!("    trace   = 2^log_n multilinear evaluations committed (KiB/MiB, binary)");
    println!("    ntt     = parallel additive NTT over the rate-expanded domain (size n*RATE)");
    println!("    merkle  = leaf hashing + Poseidon2b Merkle tree build over RS-encoded leaves");
    println!("    commit  = full commit() = NTT + leaf hash + Merkle tree (end-to-end)");
    println!("    prove   = end-to-end evaluation proof (commit excluded)");
    println!("    verify  = end-to-end verification on the prover's proof");
    println!("    proof   = estimated serialized proof size");
    println!();
    println!("  notes:");
    println!("    * the 'sumcheck' column is a standalone micro-benchmark on a");
    println!("      trace-sized polynomial, NOT the sumcheck embedded in `prove`,");
    println!("      which runs on a 2^(log_n - TAU) polynomial.");
    println!("    * 'ntt' + 'merkle' will not exactly equal 'commit': commit also");
    println!("      performs a zero-pad and Block128->u128 bookkeeping pass.");
    println!();
    println!("  reproduce:  cargo bench --bench release_report");
    println!();
}

// ---------------------------------------------------------------------------
// Entrypoint
// ---------------------------------------------------------------------------

fn main() {
    print_banner();
    print_environment();
    print_params();

    let hasher = Poseidon2bSponge::new();

    let mut rows = Vec::with_capacity(LOG_TRACES.len());
    for &log_len in LOG_TRACES {
        eprintln!("  measuring log_n = {} ...", log_len);
        rows.push(bench_row(log_len, &hasher));
    }
    eprintln!();

    print_table(&rows);
    print_footer();
}
