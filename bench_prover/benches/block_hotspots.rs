// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Short block proof hotspot benchmark for optimization loops.
//!
//!   cargo bench -p bench_prover --bench block_hotspots
//!
//! Defaults are intentionally small for fast optimization loops. Use:
//!
//!   NOID_HOTSPOT_STANDARD_TX=10 NOID_HOTSPOT_SWEEP_TX=2 \
//!     cargo bench -p bench_prover --bench block_hotspots
//!
//! to reproduce the larger reference hotspot, or set either count to `0` to skip it.
//!
//! Runs up to two production block cases:
//! - one standard-only block;
//! - one sweep-only block.
//!
//! Detailed full-block phase profiling is enabled automatically for this bench.
//! Wallet proof generation is pre-built and reported separately; block timings do
//! not include wallet proving latency.

use std::env;
use std::time::Duration;

use bench_prover::{
    bench_full_block_proof, bench_standard_block, bench_sweep_bucket, fmt_bytes, fmt_ms,
    live_counts, owned_sweep_witness, prove_sweep_wallet, standard_fixture, standard_scenario,
    sweep_fixture, sweep_scenario, time_once, StandardFixture, SweepFixture,
};
use noid_block::OwnedSweepTxWitness;

const DEFAULT_STANDARD_TX: usize = 2;
const DEFAULT_SWEEP_TX: usize = 1;
const REFERENCE_STANDARD_TX: usize = 10;
const REFERENCE_SWEEP_TX: usize = 2;
const STANDARD_SLOT_BASE: u32 = 0;
const SWEEP_SLOT_BASE: u32 = 2_000_000;
const SWEEP_SLOT_STRIDE: u32 = 100_000;

fn env_count(name: &str, default: usize) -> usize {
    env::var(name)
        .ok()
        .and_then(|value| value.trim().parse::<usize>().ok())
        .unwrap_or(default)
}

fn enable_phase_profile() -> bool {
    match env::var("NOID_PROVE_BLOCK_PROFILE") {
        Ok(value) => matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        Err(_) => {
            env::set_var("NOID_PROVE_BLOCK_PROFILE", "1");
            true
        }
    }
}

fn ms(d: Duration) -> String {
    fmt_ms(d).trim().to_owned()
}

fn bytes(n: usize) -> String {
    fmt_bytes(n).trim().to_owned()
}

fn build_standard_fixtures(n: usize, slot_base: u32) -> Vec<StandardFixture> {
    (0..n)
        .map(|i| {
            standard_fixture(standard_scenario(
                "standard hotspot tx",
                4,
                8,
                slot_base + i as u32 * 10_000,
                0xA1 + i as u128 * 0x100,
            ))
        })
        .collect()
}

fn build_sweep_fixtures(n: usize, slot_base: u32) -> Vec<SweepFixture> {
    (0..n)
        .map(|i| {
            sweep_fixture(sweep_scenario(
                "sweep hotspot tx",
                25,
                slot_base + i as u32 * SWEEP_SLOT_STRIDE,
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

fn aggregate_live_counts_standard(fixtures: &[StandardFixture]) -> (usize, usize) {
    fixtures.iter().fold((0, 0), |(inputs, outputs), fixture| {
        let (n_in, n_out) = live_counts(&fixture.scenario.body);
        (inputs + n_in, outputs + n_out)
    })
}

fn aggregate_live_counts_sweep(fixtures: &[SweepFixture]) -> (usize, usize) {
    fixtures.iter().fold((0, 0), |(inputs, outputs), fixture| {
        let (n_in, n_out) = live_counts(&fixture.scenario.body);
        (inputs + n_in, outputs + n_out)
    })
}

fn print_standard_hotspot(n: usize) {
    println!("  =====================================================================");
    println!("  1/2 STANDARD-ONLY BLOCK HOTSPOT: {n} x Standard4x8 4-in/8-out");
    println!("  =====================================================================");

    eprintln!("  building standard hotspot fixtures N={n}...");
    let (fixture_build, fixtures) = time_once(|| build_standard_fixtures(n, STANDARD_SLOT_BASE));
    let (live_inputs, live_outputs) = aggregate_live_counts_standard(&fixtures);

    eprintln!("  standard bucket component N={n}...");
    let bucket = bench_standard_block(&fixtures);

    eprintln!("  standard full block proof N={n}...");
    let full = bench_full_block_proof(&fixtures, &[], &[]);

    println!("    fixture build:             {}", fmt_ms(fixture_build));
    println!("    live IO total:             {live_inputs} inputs / {live_outputs} outputs");
    println!(
        "    meta:                      n_tx={}, state_bindings={}",
        full.proof.meta.n_tx, full.proof.meta.n_state_bindings
    );
    println!(
        "                               n_air_per_tx={}, auth_slices_per_tx={}, block_spine_slices={}",
        full.proof.meta.n_air_per_tx,
        full.proof.meta.n_auth_slices_per_tx,
        full.proof.meta.n_block_spine_slices
    );
    println!();

    println!(
        "    bucket prove:              {}",
        fmt_ms(bucket.prove_time)
    );
    println!(
        "    bucket verify:             {}",
        fmt_ms(bucket.verify_time)
    );
    println!(
        "    bucket component proof:    {}",
        fmt_bytes(bucket.proof_bytes)
    );
    println!(
        "      standard bucket:         {}",
        fmt_bytes(bucket.standard_bucket_bytes)
    );
    println!(
        "      block spine:             {}",
        fmt_bytes(bucket.unified_spine_bytes)
    );
    println!(
        "      per-tx algebraic:        {}",
        fmt_bytes(bucket.per_tx_algebraic_bytes)
    );
    println!();

    println!("    full prove:                {}", fmt_ms(full.prove_time));
    println!(
        "    full verify:               {}",
        fmt_ms(full.verify_time)
    );
    println!(
        "    full block proof:          {}",
        fmt_bytes(full.proof_bytes)
    );
    println!(
        "      standard bucket:         {}",
        fmt_bytes(full.standard_bucket_bytes)
    );
    println!(
        "      state binding:           {}",
        fmt_bytes(full.state_binding_bytes)
    );
    println!(
        "    full-minus-bucket:         prove +{}, bytes +{}",
        ms(full.prove_time.saturating_sub(bucket.prove_time)),
        bytes(full.proof_bytes.saturating_sub(bucket.proof_bytes))
    );
    println!(
        "    standard-bucket delta:     bytes +{}",
        bytes(
            full.standard_bucket_bytes
                .saturating_sub(bucket.standard_bucket_bytes)
        )
    );
    println!();
}

fn print_sweep_hotspot(n: usize) {
    println!("  =====================================================================");
    println!("  2/2 SWEEP-ONLY BLOCK HOTSPOT: {n} x Sweep25x2 25-in/2-out");
    println!("  =====================================================================");

    eprintln!("  building sweep hotspot fixtures N={n}...");
    let (fixture_build, fixtures) = time_once(|| build_sweep_fixtures(n, SWEEP_SLOT_BASE));
    let (live_inputs, live_outputs) = aggregate_live_counts_sweep(&fixtures);

    eprintln!("  pre-proving sweep wallet proofs N={n}...");
    let (wallet_prep, witnesses) = preprove_sweep_witnesses(&fixtures, 1);

    eprintln!("  sweep full block proof N={n}...");
    let full = bench_full_block_proof(&[], &fixtures, &witnesses);

    eprintln!("  sweep bucket component N={n}...");
    let bucket = bench_sweep_bucket(&witnesses);

    println!("    fixture build:             {}", fmt_ms(fixture_build));
    println!("    wallet pre-proof total:    {}", fmt_ms(wallet_prep));
    println!("    live IO total:             {live_inputs} inputs / {live_outputs} outputs");
    println!(
        "    meta:                      n_tx={}, state_bindings={}",
        full.proof.meta.n_tx, full.proof.meta.n_state_bindings
    );
    println!(
        "                               n_air_per_tx={}, auth_slices_per_tx={}, block_spine_slices={}",
        full.proof.meta.n_air_per_tx,
        full.proof.meta.n_auth_slices_per_tx,
        full.proof.meta.n_block_spine_slices
    );
    println!();

    println!(
        "    sweep bucket prove:        {}",
        fmt_ms(bucket.prove_time)
    );
    println!(
        "    bucket aggregation verify: {}",
        fmt_ms(bucket.aggregation_verify_time)
    );
    println!(
        "    sweep bucket proof:        {}",
        fmt_bytes(bucket.bucket_bytes)
    );
    println!(
        "      block spine:             {}",
        fmt_bytes(bucket.block_spine_bytes)
    );
    println!(
        "      tx auth proofs total:    {}",
        fmt_bytes(bucket.tx_auth_proofs_bytes)
    );
    println!(
        "      per-tx auth proof:       {}",
        fmt_bytes(bucket.per_tx_auth_proof_bytes)
    );
    println!(
        "      per-tx algebraic:        {}",
        fmt_bytes(bucket.per_tx_algebraic_bytes)
    );
    println!();

    println!("    full prove:                {}", fmt_ms(full.prove_time));
    println!(
        "    full verify:               {}",
        fmt_ms(full.verify_time)
    );
    println!(
        "    full block proof:          {}",
        fmt_bytes(full.proof_bytes)
    );
    println!(
        "      sweep bucket:            {}",
        fmt_bytes(full.sweep_bucket_bytes)
    );
    println!(
        "      state binding:           {}",
        fmt_bytes(full.state_binding_bytes)
    );
    println!(
        "    full-minus-bucket:         prove +{}, bytes +{}",
        ms(full.prove_time.saturating_sub(bucket.prove_time)),
        bytes(full.proof_bytes.saturating_sub(bucket.bucket_bytes))
    );
    println!();
}

fn main() {
    let phase_profile = enable_phase_profile();

    let n_standard = env_count("NOID_HOTSPOT_STANDARD_TX", DEFAULT_STANDARD_TX);
    let n_sweep = env_count("NOID_HOTSPOT_SWEEP_TX", DEFAULT_SWEEP_TX);

    println!();
    println!("  =====================================================================");
    println!("  PARANOID Block Hotspot Benchmark");
    println!("  =====================================================================");
    println!("  Up to two block cases: one standard-only block and one sweep-only block.");
    println!(
        "  Full-block phase profile: {}",
        if phase_profile {
            "on"
        } else {
            "off (NOID_PROVE_BLOCK_PROFILE=0)"
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
    println!("    - This bench intentionally has no 10/20/100 matrix and no mixed cases.");
    println!("    - Reference hotspot: NOID_HOTSPOT_STANDARD_TX={REFERENCE_STANDARD_TX} NOID_HOTSPOT_SWEEP_TX={REFERENCE_SWEEP_TX} cargo bench -p bench_prover --bench block_hotspots");
    println!("    - Wallet pre-proof time is separate; block prove uses prebuilt wallet proofs.");
    println!("    - bench_full_block_profile lines expose body_clone, seed_state,");
    println!("      sweep_bucket_prove, core_proof, block_assembly, etc.");
    println!("    - For compact summary only: NOID_PROVE_BLOCK_PROFILE=0 cargo bench -p bench_prover --bench block_hotspots");
    println!("  -------------------------------------------------------------------");
    println!("  Reproduce: cargo bench -p bench_prover --bench block_hotspots");
    println!();
}
