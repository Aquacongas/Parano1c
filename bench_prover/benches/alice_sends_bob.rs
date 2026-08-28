// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Wallet authorization benchmark for the sole Tx8x2 form.

use bench_prover::{
    authorization_size, fmt_bytes, fmt_ms, live_counts, minimal_tx_fixture, prove_wallet,
    state_shrinking_scenario, tx8x2_scenario, wallet_bundle_size, MinimalTxFixture, WalletBench,
};

const DEFAULT_SAMPLES: usize = 5;

fn samples() -> usize {
    std::env::var("NOID_WALLET_BENCH_SAMPLES")
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|&value| value > 0)
        .unwrap_or(DEFAULT_SAMPLES)
}

fn print_case(fixture: &MinimalTxFixture, result: &WalletBench) {
    let (inputs, outputs) = live_counts(&fixture.scenario.body);
    println!("  {}", fixture.scenario.label);
    println!("    body:            {}", fixture.scenario.desc);
    println!("    live actions:    {inputs} inputs / {outputs} outputs");
    println!("    owner groups:    1 (fixed protocol geometry)");
    println!("    prove median:    {}", fmt_ms(result.prove_time));
    println!("    verify median:   {}", fmt_ms(result.verify_time));
    println!(
        "    proof / bundle: {} / {}",
        fmt_bytes(authorization_size(&result.proof)),
        fmt_bytes(wallet_bundle_size(&result.proof))
    );
}

fn main() {
    let _ = noid_ivc_prover::init_perf_thread_pool();
    let samples = samples();
    println!("PARANOID wallet authorization — Tx8x2, samples={samples}");
    println!("Current measurements only; no pre-Tx8x2 golden comparison.\n");

    let cases = [
        tx8x2_scenario("send-small", 1, 2, 0, 0xA1),
        tx8x2_scenario("send-medium", 4, 2, 100, 0xB1),
        tx8x2_scenario("send-max-input", 8, 2, 200, 0xC1),
        state_shrinking_scenario("state-shrink-max", 8, 300, 0xD1),
    ];

    for scenario in cases {
        let fixture = minimal_tx_fixture(scenario);
        let result = prove_wallet(&fixture, samples);
        print_case(&fixture, &result);
    }
}
