// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Wallet-side transaction proof benchmark.
//!
//!   cargo bench --bench alice_sends_bob
//!
//! Measures real wallet proof paths for:
//! - `Standard4x8` small/default sends;
//! - `Sweep25x2` 5/10/25-input sends;
//! - `Sweep25x2` consolidation-style 25->1;
//! - logical split compositions (26 and 50 inputs).

use bench_prover::{
    consolidation_scenario, fmt_bytes, fmt_ms, live_counts, proof_size_standard, proof_size_sweep,
    prove_standard_wallet, prove_sweep_wallet, standard_fixture, standard_scenario,
    standard_wallet_bundle_size, sweep_fixture, sweep_scenario, sweep_wallet_bundle_size,
    StandardFixture, StandardWalletBench, SweepFixture, SweepWalletBench,
};

const SAMPLES_STANDARD: usize = 5;
const SAMPLES_SWEEP: usize = 3;

fn print_standard(f: &StandardFixture, r: &StandardWalletBench) {
    let (n_in, n_out) = live_counts(&f.scenario.body);
    let (total, stark, auth) = proof_size_standard(&r.proof);
    println!("  --------------------------------------------------------------------");
    println!("  {}", f.scenario.label);
    println!("  {}", f.scenario.desc);
    println!("  --------------------------------------------------------------------");
    println!("    shape:          Standard4x8");
    println!("    live IO:        {n_in} inputs / {n_out} outputs");
    println!("    prove median:   {}", fmt_ms(r.prove_time));
    println!("    verify median:  {}", fmt_ms(r.verify_time));
    let bundle = standard_wallet_bundle_size(f, &r.proof);
    println!("    wallet bundle:  {}", fmt_bytes(bundle));
    println!("    authorization:  {}", fmt_bytes(total));
    println!("      STARK:        {}", fmt_bytes(stark));
    println!("      AuthGKR:      {}", fmt_bytes(auth));
    println!();
}

fn print_sweep(f: &SweepFixture, r: &SweepWalletBench) {
    let (n_in, n_out) = live_counts(&f.scenario.body);
    let (total, stark, auth, spine) = proof_size_sweep(&r.proof);
    println!("  --------------------------------------------------------------------");
    println!("  {}", f.scenario.label);
    println!("  {}", f.scenario.desc);
    println!("  --------------------------------------------------------------------");
    println!("    shape:          Sweep25x2");
    println!("    live IO:        {n_in} inputs / {n_out} outputs");
    println!("    prove median:   {}", fmt_ms(r.prove_time));
    println!("    verify median:  {}", fmt_ms(r.verify_time));
    let bundle = sweep_wallet_bundle_size(f, &r.proof);
    println!("    wallet bundle:  {}", fmt_bytes(bundle));
    println!("    authorization:  {}", fmt_bytes(total));
    println!("      STARK:        {}", fmt_bytes(stark));
    println!("      AuthGKR:      {}", fmt_bytes(auth));
    println!(
        "      Wallet spine: {} (removed; block-side only)",
        fmt_bytes(spine)
    );
    println!();
}

fn main() {
    println!();
    println!("  ====================================================================");
    println!("  PARANOID — Wallet Proof Bench: Standard4x8 vs Sweep25x2");
    println!("  ====================================================================");
    println!("  Production proof paths; no mock/native shortcuts.");
    println!("  Standard samples: {SAMPLES_STANDARD}; Sweep samples: {SAMPLES_SWEEP}");
    println!();

    let standard_1x2 = standard_fixture(standard_scenario("SCENARIO A", 1, 2, 0, 0xA1));
    let standard_4x8 = standard_fixture(standard_scenario("SCENARIO B", 4, 8, 100, 0xB1));
    let sweep_5x2 = sweep_fixture(sweep_scenario("SCENARIO C", 5, 1_000, 0xC1));
    let sweep_10x2 = sweep_fixture(sweep_scenario("SCENARIO D", 10, 2_000, 0xD1));
    let sweep_25x2 = sweep_fixture(sweep_scenario("SCENARIO E", 25, 3_000, 0xE1));
    let consolidate_25x1 = sweep_fixture(consolidation_scenario("SCENARIO F", 25, 4_000));

    eprintln!("  benchmarking standard 1x2...");
    let r_standard_1x2 = prove_standard_wallet(&standard_1x2, SAMPLES_STANDARD);
    eprintln!("  benchmarking standard 4x8...");
    let r_standard_4x8 = prove_standard_wallet(&standard_4x8, SAMPLES_STANDARD);
    eprintln!("  benchmarking sweep 5x2...");
    let r_sweep_5x2 = prove_sweep_wallet(&sweep_5x2, SAMPLES_SWEEP);
    eprintln!("  benchmarking sweep 10x2...");
    let r_sweep_10x2 = prove_sweep_wallet(&sweep_10x2, SAMPLES_SWEEP);
    eprintln!("  benchmarking sweep 25x2...");
    let r_sweep_25x2 = prove_sweep_wallet(&sweep_25x2, SAMPLES_SWEEP);
    eprintln!("  benchmarking sweep consolidation 25x1...");
    let r_consolidate_25x1 = prove_sweep_wallet(&consolidate_25x1, SAMPLES_SWEEP);

    print_standard(&standard_1x2, &r_standard_1x2);
    print_standard(&standard_4x8, &r_standard_4x8);
    print_sweep(&sweep_5x2, &r_sweep_5x2);
    print_sweep(&sweep_10x2, &r_sweep_10x2);
    print_sweep(&sweep_25x2, &r_sweep_25x2);
    print_sweep(&consolidate_25x1, &r_consolidate_25x1);

    println!("  ====================================================================");
    println!("  Logical split compositions");
    println!("  ====================================================================");
    println!("  These rows are composition summaries using the measured wallet bundles above.");
    println!();

    let (s25_total, _, _, _) = proof_size_sweep(&r_sweep_25x2.proof);
    let (std_tail_total, _, _) = proof_size_standard(&r_standard_1x2.proof);
    let s25_bundle = sweep_wallet_bundle_size(&sweep_25x2, &r_sweep_25x2.proof);
    let std_tail_bundle = standard_wallet_bundle_size(&standard_1x2, &r_standard_1x2.proof);

    let split_26_prove = r_sweep_25x2.prove_time + r_standard_1x2.prove_time;
    let split_26_verify = r_sweep_25x2.verify_time + r_standard_1x2.verify_time;
    println!("  Split 26 inputs: Sweep25x2(25) + Standard4x8 tail");
    println!("    prove total:   {}", fmt_ms(split_26_prove));
    println!("    verify total:  {}", fmt_ms(split_26_verify));
    println!(
        "    bundle total:  {}",
        fmt_bytes(s25_bundle + std_tail_bundle)
    );
    println!(
        "    auth total:    {}",
        fmt_bytes(s25_total + std_tail_total)
    );
    println!();

    println!("  Split 50 inputs: Sweep25x2(25) + Sweep25x2(25)");
    println!(
        "    prove total:   {}",
        fmt_ms(r_sweep_25x2.prove_time + r_sweep_25x2.prove_time)
    );
    println!(
        "    verify total:  {}",
        fmt_ms(r_sweep_25x2.verify_time + r_sweep_25x2.verify_time)
    );
    println!("    bundle total:  {}", fmt_bytes(s25_bundle * 2));
    println!("    auth total:    {}", fmt_bytes(s25_total * 2));
    println!();

    println!("  ====================================================================");
    println!("  Reproduce: cargo bench --bench alice_sends_bob");
    println!("  ====================================================================");
    println!();
}
