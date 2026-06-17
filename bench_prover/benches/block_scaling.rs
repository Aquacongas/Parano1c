// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Block/bucket scaling benchmark for mixed transaction shapes.
//!
//!   cargo bench --bench block_scaling
//!
//! Measures:
//! - existing `Standard4x8` block prover (`prove_block` standard bucket path);
//! - `Sweep25x2` bucket aggregation (`assemble_sweep_bucket_proof`);
//! - mixed composition estimates using real standard + real sweep bucket proofs.
//!
//! Wallet proof generation is pre-built and reported separately; block timings do
//! not include wallet proving latency.

use std::time::{Duration, Instant};

use bench_prover::{
    bench_standard_block, bench_standard_block_with_total, bench_sweep_bucket, fmt_bytes, fmt_ms,
    owned_sweep_witness, prove_sweep_wallet, standard_fixture, standard_scenario, sweep_fixture,
    sweep_scenario, time_once, StandardFixture, SweepFixture,
};
use noid_block::OwnedSweepTxWitness;

fn build_standard_fixtures(n: usize, slot_base: u32) -> Vec<StandardFixture> {
    (0..n)
        .map(|i| {
            let shape = if i % 3 == 0 { (4, 8) } else { (2, 2) };
            standard_fixture(standard_scenario(
                "standard block tx",
                shape.0,
                shape.1,
                slot_base + i as u32 * 100,
                0xA1 + i as u128 * 0x100,
            ))
        })
        .collect()
}

fn build_sweep_fixtures(n: usize, slot_base: u32) -> Vec<SweepFixture> {
    (0..n)
        .map(|i| {
            let n_inputs = match i % 3 {
                0 => 5,
                1 => 10,
                _ => 25,
            };
            sweep_fixture(sweep_scenario(
                "sweep block tx",
                n_inputs,
                slot_base + i as u32 * 100,
                0xB1 + i as u128 * 0x100,
            ))
        })
        .collect()
}

fn preprove_sweep_witnesses(
    fixtures: &[SweepFixture],
    index_base: u32,
) -> (Duration, Vec<OwnedSweepTxWitness>) {
    time_once(|| {
        fixtures
            .iter()
            .enumerate()
            .map(|(i, f)| {
                let wallet = prove_sweep_wallet(f, 1);
                owned_sweep_witness(index_base + i as u32, f, wallet.proof)
            })
            .collect::<Vec<_>>()
    })
}

fn print_standard_block(n: usize, fixtures: &[StandardFixture]) {
    eprintln!("  benchmarking standard-only block N={n}...");
    let r = bench_standard_block(fixtures);
    println!("  [Standard-only block: {n} tx]");
    println!("    prove_block:             {}", fmt_ms(r.prove_time));
    println!("    verify_block:            {}", fmt_ms(r.verify_time));
    println!("    block proof:             {}", fmt_bytes(r.proof_bytes));
    println!(
        "    standard bucket:         {}",
        fmt_bytes(r.standard_bucket_bytes)
    );
    println!(
        "    unified spine:           {}",
        fmt_bytes(r.unified_spine_bytes)
    );
    println!(
        "    per-tx algebraic:        {}",
        fmt_bytes(r.per_tx_algebraic_bytes)
    );
    println!();
}

fn print_sweep_bucket(n: usize, fixtures: &[SweepFixture]) {
    eprintln!("  pre-proving sweep wallet proofs N={n}...");
    let (wallet_prep, witnesses) = preprove_sweep_witnesses(fixtures, 1);
    eprintln!("  benchmarking sweep bucket N={n}...");
    let r = bench_sweep_bucket(&witnesses);
    println!("  [Sweep-only bucket: {n} tx]");
    println!("    wallet pre-proof total:  {}", fmt_ms(wallet_prep));
    println!("    assemble bucket:         {}", fmt_ms(r.prove_time));
    println!("    verify bucket:           {}", fmt_ms(r.verify_time));
    println!("    sweep bucket proof:      {}", fmt_bytes(r.bucket_bytes));
    println!(
        "    per-tx algebraic:        {}",
        fmt_bytes(r.per_tx_algebraic_bytes)
    );
    println!();
}

fn print_mixed(n_standard: usize, n_sweep: usize) {
    eprintln!("  building mixed block fixtures {n_standard} standard + {n_sweep} sweep...");
    let standard = build_standard_fixtures(n_standard, 20_000);
    let sweep = build_sweep_fixtures(n_sweep, 40_000);
    let (sweep_wallet_prep, sweep_witnesses) =
        preprove_sweep_witnesses(&sweep, 1 + n_standard as u32);

    eprintln!("  benchmarking mixed standard bucket...");
    let std_r = bench_standard_block_with_total(&standard, (n_standard + n_sweep) as u32);
    eprintln!("  benchmarking mixed sweep bucket...");
    let sweep_r = bench_sweep_bucket(&sweep_witnesses);

    println!("  [Mixed composition: {n_standard} Standard4x8 + {n_sweep} Sweep25x2]");
    println!("    sweep wallet pre-proof:  {}", fmt_ms(sweep_wallet_prep));
    println!(
        "    prove buckets total:     {}",
        fmt_ms(std_r.prove_time + sweep_r.prove_time)
    );
    println!("      standard bucket:       {}", fmt_ms(std_r.prove_time));
    println!(
        "      sweep bucket:          {}",
        fmt_ms(sweep_r.prove_time)
    );
    println!(
        "    verify buckets total:    {}",
        fmt_ms(std_r.verify_time + sweep_r.verify_time)
    );
    println!(
        "    proof bytes total:       {}",
        fmt_bytes(std_r.standard_bucket_bytes + sweep_r.bucket_bytes)
    );
    println!(
        "      standard bucket:       {}",
        fmt_bytes(std_r.standard_bucket_bytes)
    );
    println!(
        "      sweep bucket:          {}",
        fmt_bytes(sweep_r.bucket_bytes)
    );
    println!();
}

fn main() {
    println!();
    println!("  =====================================================================");
    println!("  PARANOID Block/Bucket Scaling Benchmark");
    println!("  =====================================================================");
    println!("  Real production proof paths; wallet proofs are pre-built for block timing.");
    println!();

    let max_standard = 100;
    eprintln!("  building {max_standard} standard fixtures...");
    let t = Instant::now();
    let standard_fixtures = build_standard_fixtures(max_standard, 0);
    eprintln!(
        "  standard fixtures ready in {}",
        fmt_ms(t.elapsed()).trim()
    );

    for &n in &[10usize, 20, 100] {
        print_standard_block(n, &standard_fixtures[..n]);
    }

    for &n in &[1usize, 4, 10] {
        let fixtures = build_sweep_fixtures(n, 10_000 + n as u32 * 1_000);
        print_sweep_bucket(n, &fixtures);
    }

    print_mixed(8, 2); // 80/20-ish
    print_mixed(5, 5); // 50/50

    println!("  -------------------------------------------------------------------");
    println!("  NOTES:");
    println!("    - Standard timings use current prove_block/verify_block API.");
    println!("    - Sweep timings use assemble_sweep_bucket_proof + aggregation verifier.");
    println!("    - Mixed rows are real standard bucket + real sweep bucket composition.");
    println!("    - Wallet pre-proof time is reported separately and is not block-time work.");
    println!("  -------------------------------------------------------------------");
    println!("  Reproduce: cargo bench --bench block_scaling");
    println!();
}
