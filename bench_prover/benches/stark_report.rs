// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Paranoid proof report for current mixed-shape pipeline.
//!
//!   cargo bench --bench stark_report
//!
//! Summarizes real production proof paths for:
//! - wallet `Standard4x8` proofs;
//! - wallet `Sweep25x2` proofs;
//! - standard block bucket;
//! - sweep bucket aggregation;
//! - mixed bucket composition.

use bench_prover::{
    bench_recursive_step, bench_standard_block_with_total, bench_sweep_bucket,
    consolidation_scenario, fmt_bytes, fmt_ms, live_counts, mixed_block_proof, owned_sweep_witness,
    proof_size_standard, proof_size_sweep, prove_standard_wallet, prove_sweep_wallet,
    standard_block_proof_with_total, standard_fixture, standard_scenario, sweep_fixture,
    sweep_only_block_proof, sweep_scenario, RecursiveStepBench, StandardFixture, SweepFixture,
};
use noid_block::OwnedSweepTxWitness;

const STANDARD_SAMPLES: usize = 3;
const SWEEP_SAMPLES: usize = 2;

fn print_banner() {
    println!();
    println!("  ======================================================================");
    println!("  PARANOID — Mixed Shape STARK/GKR Report");
    println!("  ======================================================================");
    println!("  Real proof paths only: wallet proofs, bucket aggregation, block verify.");
    println!("  Standard samples: {STANDARD_SAMPLES}; Sweep samples: {SWEEP_SAMPLES}");
    println!();
}

fn print_wallet_standard(f: &StandardFixture) -> bench_prover::StandardWalletBench {
    eprintln!("  report: wallet standard {}", f.scenario.label);
    let r = prove_standard_wallet(f, STANDARD_SAMPLES);
    let (n_in, n_out) = live_counts(&f.scenario.body);
    let (total, stark, auth) = proof_size_standard(&r.proof);
    println!("  [Wallet Standard4x8] {}", f.scenario.desc);
    println!("    live IO:       {n_in} inputs / {n_out} outputs");
    println!("    prove:         {}", fmt_ms(r.prove_time));
    println!("    verify:        {}", fmt_ms(r.verify_time));
    println!("    proof:         {}", fmt_bytes(total));
    println!("      STARK:       {}", fmt_bytes(stark));
    println!("      AuthGKR:     {}", fmt_bytes(auth));
    println!();
    r
}

fn print_wallet_sweep(f: &SweepFixture) -> bench_prover::SweepWalletBench {
    eprintln!("  report: wallet sweep {}", f.scenario.label);
    let r = prove_sweep_wallet(f, SWEEP_SAMPLES);
    let (n_in, n_out) = live_counts(&f.scenario.body);
    let (total, stark, auth, spine) = proof_size_sweep(&r.proof);
    println!("  [Wallet Sweep25x2] {}", f.scenario.desc);
    println!("    live IO:       {n_in} inputs / {n_out} outputs");
    println!("    prove:         {}", fmt_ms(r.prove_time));
    println!("    verify:        {}", fmt_ms(r.verify_time));
    println!("    proof:         {}", fmt_bytes(total));
    println!("      STARK:       {}", fmt_bytes(stark));
    println!("      AuthGKR:     {}", fmt_bytes(auth));
    println!("      SpineGKR:    {}", fmt_bytes(spine));
    println!();
    r
}

fn preprove_sweep_witnesses(
    fixtures: &[SweepFixture],
    index_base: u32,
) -> Vec<OwnedSweepTxWitness> {
    fixtures
        .iter()
        .enumerate()
        .map(|(i, f)| {
            let wallet = prove_sweep_wallet(f, 1);
            owned_sweep_witness(index_base + i as u32, f, wallet.proof)
        })
        .collect()
}

fn print_recursive(label: &str, r: &RecursiveStepBench) {
    println!("  [Recursive update: {label}]");
    println!("    prove:         {}", fmt_ms(r.prove_time));
    println!("    verify:        {}", fmt_ms(r.verify_time));
    println!("    proof:         {}", fmt_bytes(r.proof_bytes));
    println!("    source proof:  {}", fmt_bytes(r.block_proof_bytes));
    if r.standard_bucket_bytes > 0 {
        println!("      standard:    {}", fmt_bytes(r.standard_bucket_bytes));
    }
    if r.sweep_bucket_bytes > 0 {
        println!("      sweep:       {}", fmt_bytes(r.sweep_bucket_bytes));
    }
    println!();
}

fn main() {
    print_banner();

    let std_small = standard_fixture(standard_scenario("std-small", 1, 2, 0, 0xA1));
    let std_max = standard_fixture(standard_scenario("std-max", 4, 8, 100, 0xB1));
    let sweep_min = sweep_fixture(sweep_scenario("sweep-min", 5, 1_000, 0xC1));
    let sweep_mid = sweep_fixture(sweep_scenario("sweep-mid", 10, 2_000, 0xD1));
    let sweep_max = sweep_fixture(sweep_scenario("sweep-max", 25, 3_000, 0xE1));
    let sweep_consolidate = sweep_fixture(consolidation_scenario("sweep-consolidate", 25, 4_000));

    println!("  ----------------------------------------------------------------------");
    println!("  Layer 1: wallet proof classes");
    println!("  ----------------------------------------------------------------------");
    let std_small_r = print_wallet_standard(&std_small);
    let std_max_r = print_wallet_standard(&std_max);
    let sweep_min_r = print_wallet_sweep(&sweep_min);
    let sweep_mid_r = print_wallet_sweep(&sweep_mid);
    let sweep_max_r = print_wallet_sweep(&sweep_max);
    let sweep_consolidate_r = print_wallet_sweep(&sweep_consolidate);

    println!("  ----------------------------------------------------------------------");
    println!("  Layer 2: bucket/block aggregation");
    println!("  ----------------------------------------------------------------------");

    let standard_block = vec![
        standard_fixture(standard_scenario("std-b0", 1, 2, 10_000, 0x10)),
        standard_fixture(standard_scenario("std-b1", 4, 8, 10_100, 0x20)),
        standard_fixture(standard_scenario("std-b2", 2, 2, 10_200, 0x30)),
        standard_fixture(standard_scenario("std-b3", 4, 8, 10_300, 0x40)),
    ];
    eprintln!("  report: standard block bucket N=4");
    let std_block_r = bench_standard_block_with_total(&standard_block, 4);
    println!("  [Standard block bucket: 4 tx]");
    println!("    prove:         {}", fmt_ms(std_block_r.prove_time));
    println!("    verify:        {}", fmt_ms(std_block_r.verify_time));
    println!("    proof:         {}", fmt_bytes(std_block_r.proof_bytes));
    println!(
        "    bucket:        {}",
        fmt_bytes(std_block_r.standard_bucket_bytes)
    );
    println!(
        "    spine:         {}",
        fmt_bytes(std_block_r.unified_spine_bytes)
    );
    println!();

    let sweep_block = vec![
        sweep_fixture(sweep_scenario("sw-b0", 5, 20_000, 0x50)),
        sweep_fixture(sweep_scenario("sw-b1", 10, 20_100, 0x60)),
        sweep_fixture(sweep_scenario("sw-b2", 25, 20_200, 0x70)),
        sweep_fixture(consolidation_scenario("sw-b3", 25, 20_300)),
    ];
    eprintln!("  report: sweep bucket N=4");
    let sweep_witnesses = preprove_sweep_witnesses(&sweep_block, 1);
    let sweep_bucket_r = bench_sweep_bucket(&sweep_witnesses);
    println!("  [Sweep bucket: 4 tx]");
    println!("    assemble:      {}", fmt_ms(sweep_bucket_r.prove_time));
    println!("    verify:        {}", fmt_ms(sweep_bucket_r.verify_time));
    println!(
        "    bucket proof:  {}",
        fmt_bytes(sweep_bucket_r.bucket_bytes)
    );
    println!(
        "    algebraic/tx:  {}",
        fmt_bytes(sweep_bucket_r.per_tx_algebraic_bytes)
    );
    println!();

    println!("  [Mixed composition: 4 standard + 4 sweep]");
    println!(
        "    prove total:   {}",
        fmt_ms(std_block_r.prove_time + sweep_bucket_r.prove_time)
    );
    println!(
        "    verify total:  {}",
        fmt_ms(std_block_r.verify_time + sweep_bucket_r.verify_time)
    );
    println!(
        "    proof total:   {}",
        fmt_bytes(std_block_r.standard_bucket_bytes + sweep_bucket_r.bucket_bytes)
    );
    println!();

    println!("  ----------------------------------------------------------------------");
    println!("  Layer 3: recursive chain update");
    println!("  ----------------------------------------------------------------------");

    eprintln!("  report: recursive update standard block");
    let (_, std_block_proof) = standard_block_proof_with_total(&standard_block, 4);
    let rec_standard = bench_recursive_step(&std_block_proof);
    print_recursive("standard-only block", &rec_standard);

    eprintln!("  report: recursive update sweep block");
    let (_, sweep_block_proof) = sweep_only_block_proof(&sweep_witnesses);
    let rec_sweep = bench_recursive_step(&sweep_block_proof);
    print_recursive("sweep-only block", &rec_sweep);

    eprintln!("  report: recursive update mixed block");
    let mixed_sweep_witnesses =
        preprove_sweep_witnesses(&sweep_block, 1 + standard_block.len() as u32);
    let (_, mixed_proof) = mixed_block_proof(&standard_block, &mixed_sweep_witnesses);
    let rec_mixed = bench_recursive_step(&mixed_proof);
    print_recursive("mixed standard+sweep block", &rec_mixed);

    println!("  ----------------------------------------------------------------------");
    println!("  Summary / fee-policy inputs");
    println!("  ----------------------------------------------------------------------");
    println!(
        "    Standard small prove:       {}",
        fmt_ms(std_small_r.prove_time)
    );
    println!(
        "    Standard max prove:         {}",
        fmt_ms(std_max_r.prove_time)
    );
    println!(
        "    Sweep 5-input prove:        {}",
        fmt_ms(sweep_min_r.prove_time)
    );
    println!(
        "    Sweep 10-input prove:       {}",
        fmt_ms(sweep_mid_r.prove_time)
    );
    println!(
        "    Sweep 25-input prove:       {}",
        fmt_ms(sweep_max_r.prove_time)
    );
    println!(
        "    Sweep consolidation prove:  {}",
        fmt_ms(sweep_consolidate_r.prove_time)
    );
    println!();
    println!(
        "    Standard block N=4 prove:   {}",
        fmt_ms(std_block_r.prove_time)
    );
    println!(
        "    Sweep bucket N=4 prove:     {}",
        fmt_ms(sweep_bucket_r.prove_time)
    );
    println!();
    println!(
        "    Recursive standard update:  {}",
        fmt_ms(rec_standard.prove_time)
    );
    println!(
        "    Recursive sweep update:     {}",
        fmt_ms(rec_sweep.prove_time)
    );
    println!(
        "    Recursive mixed update:     {}",
        fmt_ms(rec_mixed.prove_time)
    );
    println!();

    println!("  Reproduce: cargo bench --bench stark_report");
    println!();
}
