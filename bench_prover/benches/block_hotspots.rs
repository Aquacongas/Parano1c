// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Short production block proof hotspot benchmark for optimization loops.
//!
//!   cargo bench -p bench_prover --bench block_hotspots
//!
//! Defaults are intentionally small for fast loops. Use:
//!
//!   NOID_HOTSPOT_STANDARD_TX=255 NOID_HOTSPOT_SWEEP_TX=0 \
//!     cargo bench -p bench_prover --bench block_hotspots
//!
//! for the max standard block memory/profile case: 255 Standard4x8-equivalent
//! user txs plus coinbase. Use
//! `NOID_HOTSPOT_STANDARD_TX=0 NOID_HOTSPOT_SWEEP_TX=40` for the consensus
//! max full-sweep case.

use std::env;
use std::time::Duration;

use bench_prover::{
    bench_full_block_proof_minimal, fmt_bytes, fmt_ms, live_counts, minimal_tx_fixture,
    standard_scenario, sweep_scenario, time_once, BenchScenario, FullBlockProofBench,
    MinimalTxFixture,
};
use noid_chain::consensus::params::{BLOCK_MAX_FULL_SWEEP25X2_TXS, BLOCK_MAX_USER_TXS};
use noid_core::mem_profile::{current_mem_snapshot, MemSnapshot};

const MAX_STANDARD_USER_TXS: usize = BLOCK_MAX_USER_TXS;
const MAX_FULL_SWEEP_TXS: usize = BLOCK_MAX_FULL_SWEEP25X2_TXS;
const DEFAULT_STANDARD_TX: usize = 2;
const DEFAULT_SWEEP_TX: usize = 1;
const REFERENCE_STANDARD_TX: usize = MAX_STANDARD_USER_TXS;
const REFERENCE_SWEEP_TX: usize = MAX_FULL_SWEEP_TXS;
const STANDARD_SLOT_BASE: u32 = 0;
const SWEEP_SLOT_BASE: u32 = 2_000_000;
const SWEEP_SLOT_STRIDE: u32 = 100;

fn env_count(name: &str, default: usize) -> usize {
    env::var(name)
        .ok()
        .and_then(|value| value.trim().parse::<usize>().ok())
        .unwrap_or(default)
}

fn enable_phase_profile() -> bool {
    match env::var("NOID_BENCH_FULL_BLOCK_PROFILE") {
        Ok(value) => matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        Err(_) => {
            env::set_var("NOID_BENCH_FULL_BLOCK_PROFILE", "1");
            true
        }
    }
}

fn print_mem_delta(label: &str, before: Option<MemSnapshot>, after: Option<MemSnapshot>) {
    if let (Some(b), Some(a)) = (before, after) {
        println!(
            "    mem {label:<18} rss_delta={:>+8.1} MB  rss={:>8.1} MB  hwm={:>8.1} MB",
            a.delta_rss_mb(b),
            a.rss_mb(),
            a.hwm_mb()
        );
    }
}

fn build_standard_fixtures(n: usize, slot_base: u32) -> Vec<MinimalTxFixture> {
    (0..n)
        .map(|i| {
            minimal_tx_fixture(standard_scenario(
                "standard hotspot tx",
                4,
                8,
                slot_base + i as u32 * 10_000,
                0xA1 + i as u128 * 0x100,
            ))
        })
        .collect()
}

fn build_sweep_scenarios(n: usize, slot_base: u32) -> Vec<BenchScenario> {
    (0..n)
        .map(|i| {
            sweep_scenario(
                "sweep hotspot tx",
                25,
                slot_base + i as u32 * SWEEP_SLOT_STRIDE,
                0xB1 + i as u128 * 0x100,
            )
        })
        .collect()
}

fn preprove_minimal_fixtures(scenarios: &[BenchScenario]) -> (Duration, Vec<MinimalTxFixture>) {
    time_once(|| {
        scenarios
            .iter()
            .cloned()
            .map(minimal_tx_fixture)
            .collect::<Vec<_>>()
    })
}

fn aggregate_live_counts(fixtures: &[MinimalTxFixture]) -> (usize, usize) {
    fixtures.iter().fold((0, 0), |(inputs, outputs), fixture| {
        let (n_in, n_out) = live_counts(&fixture.scenario.body);
        (inputs + n_in, outputs + n_out)
    })
}

fn aggregate_live_counts_scenarios(scenarios: &[BenchScenario]) -> (usize, usize) {
    scenarios
        .iter()
        .fold((0, 0), |(inputs, outputs), scenario| {
            let (n_in, n_out) = live_counts(&scenario.body);
            (inputs + n_in, outputs + n_out)
        })
}

fn print_full_result(full: &FullBlockProofBench) {
    println!("    assemble proof:          {}", fmt_ms(full.prove_time));
    println!("    verify block:            {}", fmt_ms(full.verify_time));
    println!(
        "    block proof:             {}",
        fmt_bytes(full.proof_bytes)
    );
    println!(
        "    auth sidecar:            {}",
        fmt_bytes(full.auth_sidecar_bytes)
    );
    println!(
        "    block proof + sidecar:   {}",
        fmt_bytes(full.proof_bytes + full.auth_sidecar_bytes)
    );
    println!(
        "      state transition:      {}",
        fmt_bytes(full.state_transition_bytes)
    );
    println!(
        "      exact siblings:        {}",
        full.proof.state_transition.slot_siblings.len()
    );
}

fn print_standard_hotspot(n: usize) {
    println!("  =====================================================================");
    println!("  STANDARD-ONLY BLOCK HOTSPOT: {n} x TxShape::Standard4x8 4-in/8-out");
    println!("  =====================================================================");

    eprintln!("  building standard hotspot fixtures N={n}...");
    let start_mem = current_mem_snapshot();
    let (fixture_build, fixtures) = time_once(|| build_standard_fixtures(n, STANDARD_SLOT_BASE));
    let after_fixtures = current_mem_snapshot();
    let (live_inputs, live_outputs) = aggregate_live_counts(&fixtures);

    eprintln!("  standard minimal block proof N={n}...");
    let before = current_mem_snapshot();
    let full = bench_full_block_proof_minimal(&fixtures);
    let after = current_mem_snapshot();

    println!("    fixture build:           {}", fmt_ms(fixture_build));
    print_mem_delta("fixtures", start_mem, after_fixtures);
    println!("    live IO total:           {live_inputs} inputs / {live_outputs} outputs");
    println!("    user txs:                {}", full.proof.meta.n_tx);
    println!("    total txs:               {}", full.proof.meta.n_tx + 1);
    print_full_result(&full);
    print_mem_delta("after block", before, after);
    println!();
}

fn print_sweep_hotspot(n: usize) {
    println!("  =====================================================================");
    println!("  SWEEP-ONLY BLOCK HOTSPOT: {n} x TxShape::Sweep25x2 25-in/2-out");
    println!("  =====================================================================");

    eprintln!("  building sweep hotspot fixtures N={n}...");
    let start_mem = current_mem_snapshot();
    let (fixture_build, scenarios) = time_once(|| build_sweep_scenarios(n, SWEEP_SLOT_BASE));
    let after_fixtures = current_mem_snapshot();
    let (live_inputs, live_outputs) = aggregate_live_counts_scenarios(&scenarios);

    eprintln!("  pre-proving sweep wallet proofs N={n}...");
    let before_preproof = current_mem_snapshot();
    let (wallet_prep, fixtures) = preprove_minimal_fixtures(&scenarios);
    let after_preproof = current_mem_snapshot();

    eprintln!("  sweep minimal block proof N={n}...");
    let before = current_mem_snapshot();
    let full = bench_full_block_proof_minimal(&fixtures);
    let after = current_mem_snapshot();

    println!("    fixture build:           {}", fmt_ms(fixture_build));
    print_mem_delta("fixtures", start_mem, after_fixtures);
    println!("    wallet pre-proof total:  {}", fmt_ms(wallet_prep));
    print_mem_delta("wallet preproof", before_preproof, after_preproof);
    println!("    live IO total:           {live_inputs} inputs / {live_outputs} outputs");
    println!("    user txs:                {}", full.proof.meta.n_tx);
    println!("    total txs:               {}", full.proof.meta.n_tx + 1);
    print_full_result(&full);
    print_mem_delta("after block", before, after);
    println!();
}

fn main() {
    let phase_profile = enable_phase_profile();

    let n_standard =
        env_count("NOID_HOTSPOT_STANDARD_TX", DEFAULT_STANDARD_TX).min(MAX_STANDARD_USER_TXS);
    let n_sweep = env_count("NOID_HOTSPOT_SWEEP_TX", DEFAULT_SWEEP_TX).min(MAX_FULL_SWEEP_TXS);

    println!();
    println!("  =====================================================================");
    println!("  PARANOID Block Hotspot Benchmark");
    println!("  =====================================================================");
    println!("  Minimal production block proof path only.");
    println!(
        "  Full-block phase profile: {}",
        if phase_profile {
            "on"
        } else {
            "off (NOID_BENCH_FULL_BLOCK_PROFILE=0)"
        }
    );
    println!("  Defaults: standard tx={DEFAULT_STANDARD_TX}, sweep tx={DEFAULT_SWEEP_TX}");
    println!("  Reference: standard tx={REFERENCE_STANDARD_TX}, sweep tx={REFERENCE_SWEEP_TX}");
    println!("  Current:  standard tx={n_standard}, sweep tx={n_sweep}");
    println!("  Override: NOID_HOTSPOT_STANDARD_TX=<n> NOID_HOTSPOT_SWEEP_TX=<n> (0 skips a case)");
    println!();

    if n_standard == 0 {
        println!("  [skip] standard hotspot disabled by NOID_HOTSPOT_STANDARD_TX=0");
        println!();
    } else {
        print_standard_hotspot(n_standard);
    }
    if n_sweep == 0 {
        println!("  [skip] sweep hotspot disabled by NOID_HOTSPOT_SWEEP_TX=0");
        println!();
    } else {
        print_sweep_hotspot(n_sweep);
    }

    println!("  -------------------------------------------------------------------");
    println!("  NOTES:");
    println!("    - Historical shape-bucket aggregation is not measured by this bench.");
    println!("    - Wallet pre-proof time is separate; block prove uses prebuilt wallet proofs.");
    println!("    - bench_full_block_profile lines expose production phases.");
    println!("    - For compact summary only: NOID_BENCH_FULL_BLOCK_PROFILE=0 cargo bench -p bench_prover --bench block_hotspots");
    println!("  -------------------------------------------------------------------");
    println!("  Reproduce: cargo bench -p bench_prover --bench block_hotspots");
    println!();
}
