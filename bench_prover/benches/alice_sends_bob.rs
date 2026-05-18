// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Real-world bench: Alice sends to Bob.
//!
//!   cargo bench --bench alice_sends_bob
//!
//! Two scenarios, both fully real — no simulations, no estimations:
//!   A) Standard: 2 inputs, 4 outputs (typical payment)
//!   B) Max capacity: 4 inputs, 8 outputs (worst-case transaction)
//!
//! Measures wall-clock time for proving and verifying each.

use std::time::{Duration, Instant};

use noid_air::composition::tx_validity_with_spine::fixture;
use noid_air::composition::tx_validity_with_spine::TxValidityCompositeWithSpine;
use noid_air::Air;
use noid_core::{Block128, TowerField};
use noid_gkr::{compute_auth_boundary, AuthCircuit, AuthInputs, SpineInputs, N_AUTH_INPUTS};
use noid_stark::prove_tx::{prove_tx, verify_tx, TxWitness};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

struct BenchResult {
    prove_cold: Duration,
    verify_cold: Duration,
    prove_median: Duration,
    verify_median: Duration,
    prove_best: Duration,
    verify_best: Duration,
    proof_bytes: usize,
    stark_bytes: usize,
    spine_bytes: usize,
    auth_bytes: usize,
}

fn build_inputs(comp: &TxValidityCompositeWithSpine) -> (SpineInputs, AuthInputs) {
    let pins = comp.boundary_pins();
    let spine_inputs = SpineInputs {
        prev_state_root: pins.prev_state_root,
        fee_leaf: pins.fee_leaf,
        input_leaves: pins.input_leaf_absorb,
        output_leaves: pins.output_leaf_absorb,
        is_coinbase_leaf: pins.is_coinbase_leaf,
        pad_leaf: [Block128::ZERO; 2],
    };

    let pi = comp.public_inputs();
    let auth_circuit = AuthCircuit::build();
    let n_live = pi.n_live_inputs as usize;
    let all_secrets = [
        fixture::mk_secret(0xA1),
        fixture::mk_secret(0xB2),
        fixture::mk_secret(0xC3),
        fixture::mk_secret(0xD4),
    ];
    let mut spend_secret = [[Block128::ZERO; 2]; N_AUTH_INPUTS];
    for i in 0..n_live {
        spend_secret[i] = all_secrets[i];
    }
    let tx_body_hash = comp.tx_body_hash_fields();
    let (expected_address, expected_auth_tag) =
        compute_auth_boundary(&auth_circuit, spend_secret, tx_body_hash);
    let auth_inputs = AuthInputs {
        spend_secret,
        tx_body_hash,
        expected_address,
        expected_auth_tag,
    };

    (spine_inputs, auth_inputs)
}

fn run_scenario(label: &str, comp: &TxValidityCompositeWithSpine) -> BenchResult {
    let pi = comp.public_inputs();
    let trace = comp.build_trace();
    let air = comp.air();
    let (spine_inputs, auth_inputs) = build_inputs(comp);

    assert!(
        air.check(&trace),
        "FATAL: trace rejected by AIR for {}",
        label
    );

    let witness = TxWitness {
        air,
        trace: &trace,
        pi: &pi,
        spine_inputs: &spine_inputs,
        auth_inputs: &auth_inputs,
    };

    // Cold prove
    let t = Instant::now();
    let tx_proof = prove_tx(&witness).expect("prove_tx failed");
    let prove_cold = t.elapsed();

    let proof_bytes = tx_proof.estimated_byte_len();
    let spine_bytes = tx_proof.spine.byte_len();
    let auth_bytes = tx_proof.auth.byte_len();
    let stark_bytes = proof_bytes - spine_bytes - auth_bytes;

    // Cold verify
    let t = Instant::now();
    verify_tx(air, &pi, &spine_inputs, &auth_inputs, &tx_proof).expect("verify_tx failed");
    let verify_cold = t.elapsed();

    // Warm runs
    const RUNS: usize = 5;
    let mut prove_times = Vec::with_capacity(RUNS);
    let mut verify_times = Vec::with_capacity(RUNS);

    for _ in 0..RUNS {
        let t = Instant::now();
        let p = prove_tx(&witness).expect("prove_tx");
        prove_times.push(t.elapsed());

        let t = Instant::now();
        verify_tx(air, &pi, &spine_inputs, &auth_inputs, &p).expect("verify_tx");
        verify_times.push(t.elapsed());
    }

    prove_times.sort();
    verify_times.sort();

    BenchResult {
        prove_cold,
        verify_cold,
        prove_median: prove_times[RUNS / 2],
        verify_median: verify_times[RUNS / 2],
        prove_best: prove_times[0],
        verify_best: verify_times[0],
        proof_bytes,
        stark_bytes,
        spine_bytes,
        auth_bytes,
    }
}

fn print_result(label: &str, desc: &str, r: &BenchResult) {
    println!("  --------------------------------------------------------------------");
    println!("  {}", label);
    println!("  {}", desc);
    println!("  --------------------------------------------------------------------");
    println!();
    println!("                         Cold          Median        Best");
    println!(
        "    Prove:         {:>8.2} ms    {:>8.2} ms    {:>8.2} ms",
        r.prove_cold.as_secs_f64() * 1000.0,
        r.prove_median.as_secs_f64() * 1000.0,
        r.prove_best.as_secs_f64() * 1000.0,
    );
    println!(
        "    Verify:        {:>8.2} ms    {:>8.2} ms    {:>8.2} ms",
        r.verify_cold.as_secs_f64() * 1000.0,
        r.verify_median.as_secs_f64() * 1000.0,
        r.verify_best.as_secs_f64() * 1000.0,
    );
    println!();
    println!(
        "    Proof size:    {:>8.2} KB  ({} bytes)",
        r.proof_bytes as f64 / 1024.0,
        r.proof_bytes,
    );
    println!(
        "      STARK:       {:>8.2} KB  ({:.0}%)",
        r.stark_bytes as f64 / 1024.0,
        100.0 * r.stark_bytes as f64 / r.proof_bytes as f64,
    );
    println!(
        "      SpineGKR:    {:>8.2} KB  ({:.0}%)",
        r.spine_bytes as f64 / 1024.0,
        100.0 * r.spine_bytes as f64 / r.proof_bytes as f64,
    );
    println!(
        "      AuthGKR:     {:>8.2} KB  ({:.0}%)",
        r.auth_bytes as f64 / 1024.0,
        100.0 * r.auth_bytes as f64 / r.proof_bytes as f64,
    );
    println!();
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() {
    println!();
    println!("  ====================================================================");
    println!("  PARANOID — Real Transaction Bench");
    println!("  ====================================================================");
    println!("  Protocol: STARK (297 cols) + SpineGKR (59 perms) + AuthGKR (20 perms)");
    println!("  Mode:     Production (single-transcript, interleaved PCS)");
    println!("  Runs:     1 cold + 5 warm per scenario");
    println!();

    // -----------------------------------------------------------------------
    // Scenario A: Standard transaction (2 inputs, 4 outputs)
    // -----------------------------------------------------------------------
    eprintln!("  running scenario A: standard tx (2 in / 4 out)...");
    let comp_std = fixture::build_honest_realistic();
    let result_std = run_scenario("standard", &comp_std);

    // -----------------------------------------------------------------------
    // Scenario B: Max-capacity transaction (4 inputs, 8 outputs)
    // -----------------------------------------------------------------------
    eprintln!("  running scenario B: max-capacity tx (4 in / 8 out)...");
    let comp_max = fixture::build_honest_realistic_max();
    let result_max = run_scenario("max-capacity", &comp_max);

    // -----------------------------------------------------------------------
    // Print results
    // -----------------------------------------------------------------------
    print_result(
        "SCENARIO A: Standard (2 inputs, 4 outputs, fee=50)",
        "Alice spends 2 UTXOs (100+50) -> 4 recipients (40+30+20+10) + fee 50",
        &result_std,
    );

    print_result(
        "SCENARIO B: Max Capacity (4 inputs, 8 outputs, fee=575)",
        "4 UTXOs (1000+500+250+125) -> 8 recipients (400+300+200+150+100+75+50+25) + fee 575",
        &result_max,
    );

    println!("  ====================================================================");
    println!("  All proofs cryptographically verified. Zero simulations.");
    println!("  Reproduce: cargo bench --bench alice_sends_bob");
    println!("  ====================================================================");
    println!();
}
