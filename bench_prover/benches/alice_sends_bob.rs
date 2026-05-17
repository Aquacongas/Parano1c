// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Real-world bench: Alice sends to Bob.
//!
//!   cargo bench --bench alice_sends_bob
//!
//! No pre-computations, no estimations, no warm caches on first run.
//! Measures wall-clock time to:
//!   1. Build a real transaction (Alice spends 2 UTXOs -> 4 outputs + fee)
//!   2. Generate a full production proof (STARK + SpineGKR + AuthGKR)
//!   3. Verify that proof
//!
//! All numbers are REAL — the proof is cryptographically sound and verified.

use std::time::Instant;

use noid_air::composition::tx_validity_with_spine::fixture;
use noid_air::Air;
use noid_core::{Block128, TowerField};
use noid_gkr::{
    compute_auth_boundary, AuthCircuit, AuthInputs, SpineInputs, N_AUTH_INPUTS,
};
use noid_stark::prove_tx::{prove_tx, verify_tx, TxWitness};

fn main() {
    println!();
    println!("  ====================================================================");
    println!("  PARANOID — Real Transaction Bench: Alice sends to Bob");
    println!("  ====================================================================");
    println!();
    println!("  Transaction: Alice spends 2 UTXOs (100 + 50 = 150 total)");
    println!("               -> 4 outputs (40 + 30 + 20 + 10 = 100)");
    println!("               -> Fee = 50");
    println!("  Protocol:    STARK (297 cols) + SpineGKR (59 perms) + AuthGKR (20 perms)");
    println!("  Mode:        Production (single-transcript, interleaved PCS)");
    println!();

    // -----------------------------------------------------------------------
    // Phase 1: Build the real transaction and execution trace
    // -----------------------------------------------------------------------
    println!("  [1] Building transaction witness...");

    let t_build = Instant::now();

    let comp = fixture::build_honest_realistic();
    let pi = comp.public_inputs();
    let trace = comp.build_trace();
    let air = comp.air();

    let pins = comp.boundary_pins();
    let spine_inputs = SpineInputs {
        prev_state_root: pins.prev_state_root,
        fee_leaf: pins.fee_leaf,
        input_leaves: pins.input_leaf_absorb,
        output_leaves: pins.output_leaf_absorb,
        is_coinbase_leaf: pins.is_coinbase_leaf,
        pad_leaf: [Block128::ZERO; 2],
    };

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

    let build_elapsed = t_build.elapsed();

    assert!(air.check(&trace), "FATAL: trace rejected by native AIR check");

    println!(
        "      Done in {:.1} ms  (trace: {} cols x 2^{} rows)",
        build_elapsed.as_secs_f64() * 1000.0,
        trace.columns.len(),
        air.log_rows(),
    );
    println!();

    // -----------------------------------------------------------------------
    // Phase 2: PROVE — full production pipeline, cold, timed
    // -----------------------------------------------------------------------
    println!("  [2] PROVING (cold start, single-transcript orchestrator)...");

    let witness = TxWitness {
        air,
        trace: &trace,
        pi: &pi,
        spine_inputs: &spine_inputs,
        auth_inputs: &auth_inputs,
    };

    let t_prove = Instant::now();
    let tx_proof = prove_tx(&witness).expect("prove_tx failed");
    let prove_cold = t_prove.elapsed();

    let proof_bytes = tx_proof.estimated_byte_len();
    let spine_bytes = tx_proof.spine.byte_len();
    let auth_bytes = tx_proof.auth.byte_len();
    let stark_bytes = proof_bytes - spine_bytes - auth_bytes;

    println!(
        "      Prove:  {:>8.2} ms",
        prove_cold.as_secs_f64() * 1000.0,
    );
    println!(
        "      Proof:  {:>8.2} KB  (STARK {:.1} + Spine {:.1} + Auth {:.1})",
        proof_bytes as f64 / 1024.0,
        stark_bytes as f64 / 1024.0,
        spine_bytes as f64 / 1024.0,
        auth_bytes as f64 / 1024.0,
    );
    println!();

    // -----------------------------------------------------------------------
    // Phase 3: VERIFY — full production pipeline, timed
    // -----------------------------------------------------------------------
    println!("  [3] VERIFYING...");

    let t_verify = Instant::now();
    verify_tx(air, &pi, &spine_inputs, &auth_inputs, &tx_proof).expect("verify_tx failed");
    let verify_cold = t_verify.elapsed();

    println!(
        "      Verify: {:>8.2} ms  -> VALID",
        verify_cold.as_secs_f64() * 1000.0,
    );
    println!();

    // -----------------------------------------------------------------------
    // Phase 4: Repeated runs to show stable performance
    // -----------------------------------------------------------------------
    const RUNS: usize = 5;
    println!("  [4] {} additional runs (warm OnceLock caches)...", RUNS);
    println!();

    let mut prove_times = Vec::with_capacity(RUNS);
    let mut verify_times = Vec::with_capacity(RUNS);

    for i in 0..RUNS {
        let t = Instant::now();
        let p = prove_tx(&witness).expect("prove_tx");
        prove_times.push(t.elapsed());

        let t = Instant::now();
        verify_tx(air, &pi, &spine_inputs, &auth_inputs, &p).expect("verify_tx");
        verify_times.push(t.elapsed());

        println!(
            "      run {}: prove {:>8.2} ms  |  verify {:>6.2} ms",
            i + 1,
            prove_times[i].as_secs_f64() * 1000.0,
            verify_times[i].as_secs_f64() * 1000.0,
        );
    }

    prove_times.sort();
    verify_times.sort();
    let median_prove = prove_times[RUNS / 2];
    let median_verify = verify_times[RUNS / 2];
    let min_prove = prove_times[0];
    let min_verify = verify_times[0];

    println!();
    println!("  ====================================================================");
    println!("  RESULTS");
    println!("  ====================================================================");
    println!();
    println!("                         Cold          Median        Best");
    println!(
        "    Prove:         {:>8.2} ms    {:>8.2} ms    {:>8.2} ms",
        prove_cold.as_secs_f64() * 1000.0,
        median_prove.as_secs_f64() * 1000.0,
        min_prove.as_secs_f64() * 1000.0,
    );
    println!(
        "    Verify:        {:>8.2} ms    {:>8.2} ms    {:>8.2} ms",
        verify_cold.as_secs_f64() * 1000.0,
        median_verify.as_secs_f64() * 1000.0,
        min_verify.as_secs_f64() * 1000.0,
    );
    println!();
    println!(
        "    Proof size:    {:>8.2} KB  ({} bytes)",
        proof_bytes as f64 / 1024.0,
        proof_bytes,
    );
    println!(
        "      STARK:       {:>8.2} KB  ({:.0}%)",
        stark_bytes as f64 / 1024.0,
        100.0 * stark_bytes as f64 / proof_bytes as f64,
    );
    println!(
        "      SpineGKR:    {:>8.2} KB  ({:.0}%)",
        spine_bytes as f64 / 1024.0,
        100.0 * spine_bytes as f64 / proof_bytes as f64,
    );
    println!(
        "      AuthGKR:     {:>8.2} KB  ({:.0}%)",
        auth_bytes as f64 / 1024.0,
        100.0 * auth_bytes as f64 / proof_bytes as f64,
    );
    println!();
    println!("    All proofs cryptographically verified. Zero simulations.");
    println!();
}
