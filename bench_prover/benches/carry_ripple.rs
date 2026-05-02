// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Stage 3b-0.3 CarryRippleAir benchmark.
//!
//! Measures prover wall-clock, verifier wall-clock split into four
//! buckets (transcript+sumcheck, composition, base-column FRI,
//! ladder FRI), and estimated proof size at three trace sizes:
//!
//!   - `small`  log_rows =  8   (4 parallel 64-bit adders)
//!   - `mid`    log_rows = 12   (64 parallel 64-bit adders)
//!   - `prod`   log_rows = 16   (1024 parallel 64-bit adders)
//!
//! Bucket (3) — ladder FRI — is the Stage 3b-0.4 decision driver.
//!
//! Emits a Markdown report to `bench_prover/reports/carry_ripple.md`.

use std::fs;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use noid_air::{Air, CarryRippleAir};
use noid_fri::code::LOG_RATE;
use noid_fri::{NUM_QUERIES, TAU};
use noid_poseidon2b::primitives::TxBodyHash;
use noid_stark::{
    padded_log_len, prove_air, prove_air_timed, verify_air_timed, ProveTimings, StarkProof,
    VerifyTimings,
};
use noid_tx::PublicInputs;

const SAMPLES: usize = 3;
const WARMUP: usize = 1;

fn median(mut v: Vec<Duration>) -> Duration {
    v.sort();
    v[v.len() / 2]
}

fn time<F: FnMut()>(mut f: F) -> Duration {
    for _ in 0..WARMUP {
        f();
    }
    let mut xs = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        let t = Instant::now();
        f();
        xs.push(t.elapsed());
    }
    median(xs)
}

fn fmt_ms(d: Duration) -> String {
    let ms = d.as_secs_f64() * 1_000.0;
    if ms >= 1_000.0 {
        format!("{:.2} s", ms / 1_000.0)
    } else if ms >= 1.0 {
        format!("{:.2} ms", ms)
    } else {
        format!("{:.2} us", ms * 1_000.0)
    }
}

fn fmt_bytes(bytes: usize) -> String {
    if bytes >= 1024 * 1024 {
        format!("{:.2} MB", bytes as f64 / (1024.0 * 1024.0))
    } else if bytes >= 1024 {
        format!("{:.2} KB", bytes as f64 / 1024.0)
    } else {
        format!("{} B", bytes)
    }
}

fn mk_pi() -> PublicInputs {
    PublicInputs {
        prev_state_root: [0x11; 32],
        new_state_root: [0x22; 32],
        tx_body_hash: TxBodyHash([0x44; 32]),
        fee: 7,
    }
}

fn splitmix(seed: &mut u64) -> u64 {
    *seed = seed.wrapping_add(0x9E3779B97F4A7C15);
    let mut z = *seed;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
    z ^ (z >> 31)
}

fn random_adders(n: usize, mut seed: u64) -> Vec<(u64, u64)> {
    (0..n)
        .map(|_| {
            let a = splitmix(&mut seed);
            let b = splitmix(&mut seed);
            (a, b)
        })
        .collect()
}

/// Byte-size of a single FRI evaluation proof at `log_len` (matches
/// `release_report::estimate_proof_bytes`).
fn fri_opening_bytes(log_len: usize) -> usize {
    let tau = TAU.min(log_len);
    let n_rounds = log_len.saturating_sub(tau);
    let upper = (1usize << tau) * 16;
    let sum_check = n_rounds * 3 * 16;
    let fri_roots = n_rounds * 32;
    let queried = n_rounds * NUM_QUERIES * 2 * 16;
    let mut paths = 0usize;
    for r in 0..n_rounds {
        let depth = (log_len + LOG_RATE).saturating_sub(1 + r);
        paths += NUM_QUERIES * depth * 32;
    }
    let final_cw = noid_fri::code::RATE * 16;
    upper + sum_check + fri_roots + queried + paths + final_cw
}

fn estimate_stark_proof_bytes(
    proof: &StarkProof,
    log_len: usize,
    n_cols: usize,
    n_shifted: usize,
) -> (usize, usize, usize) {
    let per_opening = fri_opening_bytes(log_len);
    let column_roots = n_cols * 32;
    // Base openings at r_point and multipoint openings at r''.
    let base_openings = n_cols * 16;
    let multipoint_openings = n_cols * 16;
    let sumcheck = proof
        .zero_check_rounds
        .iter()
        .map(|r| r.len() * 16)
        .sum::<usize>();
    let shift_partials = n_shifted * (log_len + 1) * 16;
    // Ladder sumchecks (no per-slot FRI anymore).
    let ladder_batch_rounds = proof
        .ladder_batch_rounds
        .iter()
        .flat_map(|s| s.iter())
        .map(|r| r.len() * 16)
        .sum::<usize>();
    let ladder_openings = n_shifted * 16;
    let ladder_block = ladder_batch_rounds + ladder_openings;
    // §12c multipoint-batch sumcheck (log_len degree-2 rounds) plus
    // the single batched FRI opening at r''.
    let multipoint_rounds = proof
        .multipoint_rounds
        .iter()
        .map(|r| r.len() * 16)
        .sum::<usize>();
    let multipoint_fri = per_opening + 32 + multipoint_rounds + multipoint_openings;
    let total = column_roots
        + base_openings
        + sumcheck
        + shift_partials
        + ladder_block
        + multipoint_fri;
    (total, multipoint_fri, ladder_block)
}

struct Row {
    label: &'static str,
    log_rows: usize,
    n_instances: usize,
    prove: Duration,
    prove_buckets: ProveTimings,
    verify: VerifyTimings,
    proof_bytes: usize,
    multipoint_fri_bytes: usize,
    ladder_block_bytes: usize,
}

fn bench_config(label: &'static str, log_rows: usize) -> Row {
    let air = CarryRippleAir::new(log_rows);
    let n_instances = air.n_instances();
    let adders = random_adders(n_instances, 0xA5A5_0000 ^ log_rows as u64);
    let trace = air.build_trace(&adders);
    assert!(air.check(&trace), "native check failed at log_rows={log_rows}");
    let pi = mk_pi();

    let prove = time(|| {
        let _ = prove_air(&air, &trace, &pi).unwrap();
    });
    for _ in 0..WARMUP {
        let _ = prove_air_timed(&air, &trace, &pi).unwrap();
    }
    let mut prove_samples: Vec<ProveTimings> = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        let (_p, t) = prove_air_timed(&air, &trace, &pi).unwrap();
        prove_samples.push(t);
    }
    prove_samples.sort_by_key(|t| t.total());
    let prove_buckets = prove_samples[prove_samples.len() / 2];
    let proof = prove_air(&air, &trace, &pi).unwrap();

    let mut verify_samples: Vec<VerifyTimings> = Vec::with_capacity(SAMPLES);
    for _ in 0..WARMUP {
        let (r, _) = verify_air_timed(&air, &pi, &proof);
        r.unwrap();
    }
    for _ in 0..SAMPLES {
        let (r, t) = verify_air_timed(&air, &pi, &proof);
        r.unwrap();
        verify_samples.push(t);
    }
    verify_samples.sort_by_key(|t| t.total());
    let verify = verify_samples[verify_samples.len() / 2];

    let log_len = padded_log_len(log_rows);
    let n_cols = air.n_columns();
    let n_shifted = air.shifted_column_indices().len();
    let (proof_bytes, multipoint_fri_bytes, ladder_block_bytes) =
        estimate_stark_proof_bytes(&proof, log_len, n_cols, n_shifted);

    Row {
        label,
        log_rows,
        n_instances,
        prove,
        prove_buckets,
        verify,
        proof_bytes,
        multipoint_fri_bytes,
        ladder_block_bytes,
    }
}

fn percent(part: Duration, whole: Duration) -> f64 {
    if whole.is_zero() {
        0.0
    } else {
        100.0 * part.as_secs_f64() / whole.as_secs_f64()
    }
}

fn emit_report(rows: &[Row]) -> String {
    let mut s = String::new();
    s.push_str("# CarryRippleAir benchmark (Stage 3b-0.4)\n\n");
    s.push_str("AIR: 64-bit ripple-carry adder, 5 columns (a, b, sum, carry, is_reset), ");
    s.push_str("single rotation read on `carry` (`shifted_columns = [3]`).\n\n");
    s.push_str("Post-3b-0.4: `multipoint_fri` is the single batched FRI opening at `r''` ");
    s.push_str("that closes both the base claims at `r_point` and every ladder claim at ");
    s.push_str("`r'_s` (CRYPTO.md §12c). `ladder_block` is the per-slot §12a partials + ");
    s.push_str("product sumcheck transcript — no per-slot FRI anymore.\n\n");

    s.push_str("## Summary\n\n");
    s.push_str("| label | log_rows | adders | prove | verify (total) | proof size |\n");
    s.push_str("|-------|----------|--------|-------|-----------------|------------|\n");
    for r in rows {
        s.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} |\n",
            r.label,
            r.log_rows,
            r.n_instances,
            fmt_ms(r.prove),
            fmt_ms(r.verify.total()),
            fmt_bytes(r.proof_bytes),
        ));
    }

    s.push_str("\n## Prover time buckets\n\n");
    s.push_str(
        "| label | commit | transcript+sumcheck | ladder sumcheck | multipoint+FRI | total |\n",
    );
    s.push_str(
        "|-------|--------|---------------------|-----------------|----------------|-------|\n",
    );
    for r in rows {
        let total = r.prove_buckets.total();
        s.push_str(&format!(
            "| {} | {} ({:.1}%) | {} ({:.1}%) | {} ({:.1}%) | {} ({:.1}%) | {} |\n",
            r.label,
            fmt_ms(r.prove_buckets.commit),
            percent(r.prove_buckets.commit, total),
            fmt_ms(r.prove_buckets.transcript_sumcheck),
            percent(r.prove_buckets.transcript_sumcheck, total),
            fmt_ms(r.prove_buckets.ladder_sumcheck),
            percent(r.prove_buckets.ladder_sumcheck, total),
            fmt_ms(r.prove_buckets.multipoint_fri),
            percent(r.prove_buckets.multipoint_fri, total),
            fmt_ms(total),
        ));
    }

    s.push_str("\n## Verifier time buckets\n\n");
    s.push_str(
        "| label | transcript+sumcheck | composition | ladder sumcheck | multipoint+FRI | total |\n",
    );
    s.push_str(
        "|-------|---------------------|-------------|-----------------|----------------|-------|\n",
    );
    for r in rows {
        let total = r.verify.total();
        s.push_str(&format!(
            "| {} | {} ({:.1}%) | {} ({:.1}%) | {} ({:.1}%) | {} ({:.1}%) | {} |\n",
            r.label,
            fmt_ms(r.verify.transcript_sumcheck),
            percent(r.verify.transcript_sumcheck, total),
            fmt_ms(r.verify.composition),
            percent(r.verify.composition, total),
            fmt_ms(r.verify.ladder_sumcheck),
            percent(r.verify.ladder_sumcheck, total),
            fmt_ms(r.verify.multipoint_fri),
            percent(r.verify.multipoint_fri, total),
            fmt_ms(total),
        ));
    }

    s.push_str("\n## Proof-size buckets\n\n");
    s.push_str("| label | multipoint FRI | ladder block | multipoint share | total |\n");
    s.push_str("|-------|----------------|--------------|------------------|-------|\n");
    for r in rows {
        let share = if r.proof_bytes == 0 {
            0.0
        } else {
            100.0 * r.multipoint_fri_bytes as f64 / r.proof_bytes as f64
        };
        s.push_str(&format!(
            "| {} | {} | {} | {:.1}% | {} |\n",
            r.label,
            fmt_bytes(r.multipoint_fri_bytes),
            fmt_bytes(r.ladder_block_bytes),
            share,
            fmt_bytes(r.proof_bytes),
        ));
    }

    s
}

fn main() {
    let mut rows: Vec<Row> = Vec::new();
    rows.push(bench_config("small", 8));
    rows.push(bench_config("mid", 12));
    rows.push(bench_config("prod", 16));

    println!();
    println!("  PARANOID -- CarryRippleAir (Stage 3b-0.3)");
    println!();
    for r in &rows {
        println!(
            "  {:<5} log_rows={:>2} adders={:>4}  prove {:>10}  verify {:>10}  proof {:>10}",
            r.label,
            r.log_rows,
            r.n_instances,
            fmt_ms(r.prove),
            fmt_ms(r.verify.total()),
            fmt_bytes(r.proof_bytes),
        );
        let ptot = r.prove_buckets.total();
        println!(
            "          prove  buckets: commit {} ({:.1}%) | ts+sc {} ({:.1}%) | ladsc {} ({:.1}%) | mp+fri {} ({:.1}%)",
            fmt_ms(r.prove_buckets.commit),
            percent(r.prove_buckets.commit, ptot),
            fmt_ms(r.prove_buckets.transcript_sumcheck),
            percent(r.prove_buckets.transcript_sumcheck, ptot),
            fmt_ms(r.prove_buckets.ladder_sumcheck),
            percent(r.prove_buckets.ladder_sumcheck, ptot),
            fmt_ms(r.prove_buckets.multipoint_fri),
            percent(r.prove_buckets.multipoint_fri, ptot),
        );
        let total = r.verify.total();
        println!(
            "          verify buckets: ts+sc {} ({:.1}%) | comp {} ({:.1}%) | ladsc {} ({:.1}%) | mp+fri {} ({:.1}%)",
            fmt_ms(r.verify.transcript_sumcheck),
            percent(r.verify.transcript_sumcheck, total),
            fmt_ms(r.verify.composition),
            percent(r.verify.composition, total),
            fmt_ms(r.verify.ladder_sumcheck),
            percent(r.verify.ladder_sumcheck, total),
            fmt_ms(r.verify.multipoint_fri),
            percent(r.verify.multipoint_fri, total),
        );
    }
    println!();

    let report = emit_report(&rows);
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("reports");
    let _ = fs::create_dir_all(&path);
    path.push("carry_ripple.md");
    fs::write(&path, &report).expect("write carry_ripple.md");
    println!("  report written to {}", path.display());
    println!();
}
