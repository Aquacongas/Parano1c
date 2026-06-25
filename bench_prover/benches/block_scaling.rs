// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Production block scaling benchmark for mixed transaction shapes.
//!
//!   cargo bench --bench block_scaling
//!
//! Measures the minimal production block proof path only:
//! authorization sidecar verification plus exact authenticated state transition.
//! Wallet proof generation is pre-built and reported separately; block timings do
//! not include wallet proving latency.

use std::time::{Duration, Instant};

use bench_prover::{
    bench_full_block_proof_minimal, fmt_bytes, fmt_ms, minimal_tx_fixture, standard_scenario,
    sweep_scenario, time_once, BenchScenario, MinimalTxFixture,
};
use noid_chain::consensus::params::BLOCK_MAX_TXS;

const MAX_TOTAL_BLOCK_TXS: usize = BLOCK_MAX_TXS;
const MAX_USER_TXS: usize = BLOCK_MAX_TXS - 1;

fn build_standard_fixtures(n: usize, slot_base: u32) -> Vec<MinimalTxFixture> {
    (0..n)
        .map(|i| {
            let shape = if i % 3 == 0 { (4, 8) } else { (2, 2) };
            minimal_tx_fixture(standard_scenario(
                "standard block tx",
                shape.0,
                shape.1,
                slot_base + i as u32 * 10_000,
                0xA1 + i as u128 * 0x100,
            ))
        })
        .collect()
}

fn build_sweep_scenarios(n: usize, slot_base: u32) -> Vec<BenchScenario> {
    (0..n)
        .map(|i| {
            let n_inputs = match i % 3 {
                0 => 5,
                1 => 10,
                _ => 25,
            };
            sweep_scenario(
                "sweep block tx",
                n_inputs,
                slot_base + i as u32 * 100,
                0xB1 + i as u128 * 0x100,
            )
        })
        .collect()
}

fn build_sweep_heavy_scenarios(n: usize, slot_base: u32) -> Vec<BenchScenario> {
    (0..n)
        .map(|i| {
            sweep_scenario(
                "sweep-heavy max block tx",
                25,
                slot_base + i as u32 * 100,
                0xC1 + i as u128 * 0x100,
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

fn env_bool(name: &str) -> bool {
    std::env::var(name)
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes"
            )
        })
        .unwrap_or(false)
}

fn env_usize_list(name: &str, default: &[usize]) -> Vec<usize> {
    let Ok(value) = std::env::var(name) else {
        return default.to_vec();
    };
    let parsed = value
        .split(',')
        .filter_map(|part| part.trim().parse::<usize>().ok())
        .filter(|&n| (1..=MAX_USER_TXS).contains(&n))
        .collect::<Vec<_>>();
    if parsed.is_empty() {
        default.to_vec()
    } else {
        parsed
    }
}

fn print_full_block(
    label: &str,
    sweep_wallet_prep: Option<Duration>,
    full: bench_prover::FullBlockProofBench,
) {
    println!("  [{label}]");
    if let Some(wallet_prep) = sweep_wallet_prep {
        println!("    sweep wallet pre-proof:  {}", fmt_ms(wallet_prep));
    }
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
    println!("      user txs:              {}", full.proof.meta.n_tx);
    println!("      total txs:             {}", full.proof.meta.n_tx + 1);
    println!();
}

fn print_standard_block(n: usize, fixtures: &[MinimalTxFixture]) {
    eprintln!("  benchmarking standard-only minimal block proof N={n}...");
    let full = bench_full_block_proof_minimal(fixtures);
    print_full_block(
        &format!("Standard-only minimal block proof: {n} tx"),
        None,
        full,
    );
}

fn print_sweep_block(n: usize, scenarios: &[BenchScenario]) {
    eprintln!("  pre-proving sweep wallet proofs N={n}...");
    let (wallet_prep, fixtures) = preprove_minimal_fixtures(scenarios);
    eprintln!("  benchmarking sweep-only minimal block proof N={n}...");
    let full = bench_full_block_proof_minimal(&fixtures);
    print_full_block(
        &format!("Sweep-only minimal block proof: {n} tx"),
        Some(wallet_prep),
        full,
    );
}

fn print_mixed(n_standard: usize, n_sweep: usize) {
    eprintln!("  building mixed block fixtures {n_standard} standard + {n_sweep} sweep...");
    let mut fixtures = build_standard_fixtures(n_standard, 20_000);
    let sweep = build_sweep_scenarios(n_sweep, 2_000_000);
    let (sweep_wallet_prep, mut sweep_fixtures) = preprove_minimal_fixtures(&sweep);
    fixtures.append(&mut sweep_fixtures);

    eprintln!("  benchmarking mixed minimal block proof...");
    let full = bench_full_block_proof_minimal(&fixtures);
    print_full_block(
        &format!(
            "Mixed minimal block proof: {n_standard} TxShape::Standard4x8 + {n_sweep} TxShape::Sweep25x2"
        ),
        Some(sweep_wallet_prep),
        full,
    );
}

fn main() {
    println!();
    println!("  =====================================================================");
    println!("  PARANOID Block Scaling Benchmark");
    println!("  =====================================================================");
    println!("  Minimal production block proof path only.");
    println!("  Wallet proofs are pre-built for block timing.");
    println!();

    let standard_ns = env_usize_list(
        "NOID_BLOCK_SCALING_STANDARD_NS",
        &[10usize, 20, 100, MAX_USER_TXS],
    );
    let max_standard = standard_ns.iter().copied().max().unwrap_or(MAX_USER_TXS);
    eprintln!("  building {max_standard} standard fixtures...");
    let t = Instant::now();
    let standard_fixtures = build_standard_fixtures(max_standard, 0);
    eprintln!(
        "  standard fixtures ready in {}",
        fmt_ms(t.elapsed()).trim()
    );

    if !standard_fixtures.is_empty() {
        let warmup_n = standard_ns
            .iter()
            .copied()
            .min()
            .unwrap_or(1)
            .min(standard_fixtures.len());
        eprintln!("  warming minimal block proof path N={warmup_n}...");
        let _ = bench_full_block_proof_minimal(&standard_fixtures[..warmup_n]);
    }

    for n in standard_ns {
        print_standard_block(n, &standard_fixtures[..n]);
    }

    if env_bool("NOID_BLOCK_SCALING_STANDARD_ONLY") {
        println!("  -------------------------------------------------------------------");
        println!("  NOTES:");
        println!("    - Standard-only profiling mode enabled.");
        println!("  -------------------------------------------------------------------");
        println!(
            "  Reproduce: NOID_BLOCK_SCALING_STANDARD_ONLY=1 cargo bench --bench block_scaling"
        );
        println!();
        return;
    }

    for &n in &[1usize, 4, 10] {
        let scenarios = build_sweep_scenarios(n, 10_000 + n as u32 * 1_000);
        print_sweep_block(n, &scenarios);
    }
    eprintln!("  building max sweep-heavy fixtures {MAX_USER_TXS} user txs...");
    let max_sweep_scenarios = build_sweep_heavy_scenarios(MAX_USER_TXS, 3_000_000);
    print_sweep_block(MAX_USER_TXS, &max_sweep_scenarios);

    print_mixed(8, 2);
    print_mixed(5, 5);

    println!("  -------------------------------------------------------------------");
    println!("  NOTES:");
    println!("    - Rows measure production BlockProof + BlockAuthSidecar only.");
    println!(
        "    - Max block rows use {MAX_USER_TXS} non-coinbase txs + 1 coinbase = {MAX_TOTAL_BLOCK_TXS} total txs."
    );
    println!("    - Wallet pre-proof time is reported separately and is not block-time work.");
    println!("    - Historical bucket aggregation is not measured by this bench.");
    println!("  -------------------------------------------------------------------");
    println!("  Reproduce: cargo bench --bench block_scaling");
    println!();
}
