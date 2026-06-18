// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Block/bucket scaling benchmark for mixed transaction shapes.
//!
//!   cargo bench --bench block_scaling
//!
//! Measures both component bucket paths and full production block proof paths.
//! The standard bucket-only rows reproduce the old numbers; full block rows add
//! common state-binding proofs and are the cap-driving production numbers.
//!
//! Wallet proof generation is pre-built and reported separately; block timings do
//! not include wallet proving latency.

use std::time::{Duration, Instant};

use bench_prover::{
    bench_full_block_proof, bench_standard_block, bench_sweep_bucket, fmt_bytes, fmt_ms,
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
                slot_base + i as u32 * 10_000,
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
    eprintln!("  benchmarking standard-only bucket component N={n}...");
    let bucket = bench_standard_block(fixtures);
    println!("  [Standard-only bucket component: {n} tx]");
    println!("    prove bucket path:       {}", fmt_ms(bucket.prove_time));
    println!(
        "    verify bucket path:      {}",
        fmt_ms(bucket.verify_time)
    );
    println!(
        "    component proof:         {}",
        fmt_bytes(bucket.proof_bytes)
    );
    println!(
        "      standard bucket:       {}",
        fmt_bytes(bucket.standard_bucket_bytes)
    );
    println!(
        "      block spine:           {}",
        fmt_bytes(bucket.unified_spine_bytes)
    );
    println!(
        "      per-tx algebraic:      {}",
        fmt_bytes(bucket.per_tx_algebraic_bytes)
    );
    println!();

    eprintln!("  benchmarking standard-only full block proof N={n}...");
    let full = bench_full_block_proof(fixtures, &[], &[]);
    println!("  [Standard-only full block proof: {n} tx]");
    println!("    prove full block:        {}", fmt_ms(full.prove_time));
    println!("    verify full block:       {}", fmt_ms(full.verify_time));
    println!(
        "    block proof:             {}",
        fmt_bytes(full.proof_bytes)
    );
    println!(
        "      standard bucket:       {}",
        fmt_bytes(full.standard_bucket_bytes)
    );
    println!(
        "      state binding:         {}",
        fmt_bytes(full.state_binding_bytes)
    );
    println!(
        "    state-binding overhead:  prove +{}, bytes +{}",
        fmt_ms(full.prove_time.saturating_sub(bucket.prove_time)).trim(),
        fmt_bytes(full.proof_bytes.saturating_sub(bucket.proof_bytes)).trim()
    );
    println!();
}

fn print_sweep_bucket(n: usize, fixtures: &[SweepFixture]) {
    eprintln!("  pre-proving sweep wallet proofs N={n}...");
    let (wallet_prep, witnesses) = preprove_sweep_witnesses(fixtures, 1);
    eprintln!("  benchmarking sweep-only full block proof N={n}...");
    let full = bench_full_block_proof(&[], fixtures, &witnesses);
    eprintln!("  benchmarking sweep bucket detail N={n}...");
    let bucket = bench_sweep_bucket(&witnesses);
    println!("  [Sweep-only full block proof: {n} tx]");
    println!("    wallet pre-proof total:  {}", fmt_ms(wallet_prep));
    println!("    prove full block:        {}", fmt_ms(full.prove_time));
    println!("    verify full block:       {}", fmt_ms(full.verify_time));
    println!(
        "    block proof:             {}",
        fmt_bytes(full.proof_bytes)
    );
    println!(
        "      sweep bucket:          {}",
        fmt_bytes(full.sweep_bucket_bytes)
    );
    println!(
        "      state binding:         {}",
        fmt_bytes(full.state_binding_bytes)
    );
    println!(
        "    bucket aggregation only:  {}",
        fmt_ms(bucket.aggregation_verify_time)
    );
    println!(
        "      block spine:           {}",
        fmt_bytes(bucket.block_spine_bytes)
    );
    println!(
        "      tx auth proofs total:  {}",
        fmt_bytes(bucket.tx_auth_proofs_bytes)
    );
    println!(
        "      per-tx algebraic:      {}",
        fmt_bytes(bucket.per_tx_algebraic_bytes)
    );
    println!();
}

fn print_mixed(n_standard: usize, n_sweep: usize) {
    eprintln!("  building mixed block fixtures {n_standard} standard + {n_sweep} sweep...");
    let standard = build_standard_fixtures(n_standard, 20_000);
    let sweep = build_sweep_fixtures(n_sweep, 2_000_000);
    let (sweep_wallet_prep, sweep_witnesses) =
        preprove_sweep_witnesses(&sweep, 1 + n_standard as u32);

    eprintln!("  benchmarking mixed full block proof...");
    let full = bench_full_block_proof(&standard, &sweep, &sweep_witnesses);

    println!("  [Mixed full block proof: {n_standard} Standard4x8 + {n_sweep} Sweep25x2]");
    println!("    sweep wallet pre-proof:  {}", fmt_ms(sweep_wallet_prep));
    println!("    prove full block:        {}", fmt_ms(full.prove_time));
    println!("    verify full block:       {}", fmt_ms(full.verify_time));
    println!(
        "    block proof:             {}",
        fmt_bytes(full.proof_bytes)
    );
    println!(
        "      standard bucket:       {}",
        fmt_bytes(full.standard_bucket_bytes)
    );
    println!(
        "      sweep bucket:          {}",
        fmt_bytes(full.sweep_bucket_bytes)
    );
    println!(
        "      state binding:         {}",
        fmt_bytes(full.state_binding_bytes)
    );
    println!();
}

fn main() {
    println!();
    println!("  =====================================================================");
    println!("  PARANOID Block/Bucket Scaling Benchmark");
    println!("  =====================================================================");
    println!("  Bucket components plus full production block proofs.");
    println!("  Wallet proofs are pre-built for block timing.");
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
    println!("    - Bucket component rows are diagnostic breakdowns, not production validity.");
    println!(
        "    - Full block rows are the production proof-native path: buckets + state binding."
    );
    println!("    - Sweep bucket aggregation is printed only as a component breakdown.");
    println!("    - Mixed rows include both buckets plus common state-binding proofs.");
    println!("    - Wallet pre-proof time is reported separately and is not block-time work.");
    println!("  -------------------------------------------------------------------");
    println!("  Reproduce: cargo bench --bench block_scaling");
    println!();
}
