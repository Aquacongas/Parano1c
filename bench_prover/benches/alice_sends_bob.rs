// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

#![allow(clippy::manual_memcpy)]

//! Real-world bench: Alice sends to Bob (wallet-side LogicProof).
//!
//!   cargo bench --bench alice_sends_bob
//!
//! Two scenarios, both fully real — no simulations, no estimations:
//!   A) Standard: 2 inputs, 4 outputs (typical payment)
//!   B) Max capacity: 4 inputs, 8 outputs (worst-case transaction)
//!
//! Measures wall-clock time for proving and verifying the wallet-side
//! `LogicProof` via `prove_logic` / `verify_logic`. This is the stateless
//! proof the wallet produces — it does NOT include state-opening work
//! (that is the full-node's responsibility via `BlockStateBinding`).

use std::time::{Duration, Instant};

use noid_air::composition::tx_logic::{
    boundary_pins_from_body, witness_from_body, TxLogicAir, TX_LOGIC_N_COLS,
};
use noid_air::Air;
use noid_core::{Block128, TowerField};
use noid_gkr::{compute_auth_boundary, AuthCircuit, AuthInputs, SpineInputs, N_AUTH_INPUTS};
use noid_poseidon2b::primitives::{
    derive_address, hash_auth_tag, Address, AuthTag, SpendSecret, TxBodyHash,
};
use noid_stark::prove_logic::{prove_logic, verify_logic, LogicWitness};
use noid_tx::{
    compute_claims_commitment, PublicInputs, TxBody, TxInput, TxOutput, MAX_INPUTS, MAX_OUTPUTS,
};

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
    auth_bytes: usize,
}

fn mk_secret(seed: u128) -> [Block128; 2] {
    [
        Block128::from(seed.wrapping_mul(0x9E3779B97F4A7C15) ^ 0xA5A5_A5A5_A5A5_A5A5),
        Block128::from(seed.wrapping_mul(0xBF58476D1CE4E5B9) ^ 0x5A5A_5A5A_5A5A_5A5A),
    ]
}

fn fields_to_bytes(fields: [Block128; 2]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[..16].copy_from_slice(&fields[0].to_u128().to_le_bytes());
    out[16..].copy_from_slice(&fields[1].to_u128().to_le_bytes());
    out
}

fn native_address(secret: [Block128; 2]) -> Address {
    derive_address(&SpendSecret(fields_to_bytes(secret)))
}

fn native_auth_tag_fields(secret: [Block128; 2], tx_body_hash: [Block128; 2]) -> [Block128; 2] {
    hash_auth_tag(
        &SpendSecret(fields_to_bytes(secret)),
        &TxBodyHash(fields_to_bytes(tx_body_hash)),
    )
    .as_fields()
}

struct Scenario {
    body: TxBody,
    secrets: [[Block128; 2]; N_AUTH_INPUTS],
    n_live: usize,
}

fn build_standard_scenario() -> Scenario {
    let secrets = [
        mk_secret(0xA1),
        mk_secret(0xB2),
        mk_secret(0xC3),
        mk_secret(0xD4),
    ];
    let addrs: [Address; 4] = [
        native_address(secrets[0]),
        native_address(secrets[1]),
        native_address(secrets[2]),
        native_address(secrets[3]),
    ];

    let out_secrets = [secrets[0], secrets[1], mk_secret(0x1E), mk_secret(0x2F)];
    let out_owners: [Address; 4] = [
        native_address(out_secrets[0]),
        native_address(out_secrets[1]),
        native_address(out_secrets[2]),
        native_address(out_secrets[3]),
    ];

    let body = TxBody {
        shape: noid_tx::TxShape::Standard4x8,
        epoch_anchor: [0xAA; 32],
        fee: 50,
        inputs: vec![
            TxInput {
                slot_index: 0,
                value: 100,
                owner: addrs[0],
                spend_secret: SpendSecret(fields_to_bytes(secrets[0])),
                auth_tag: AuthTag([0u8; 32]),
                valid: true,
            },
            TxInput {
                slot_index: 3,
                value: 50,
                owner: addrs[1],
                spend_secret: SpendSecret(fields_to_bytes(secrets[1])),
                auth_tag: AuthTag([0u8; 32]),
                valid: true,
            },
            TxInput::dummy(),
            TxInput::dummy(),
        ],
        outputs: vec![
            TxOutput {
                slot_index: 1,
                value: 40,
                owner: out_owners[0],
                valid: true,
            },
            TxOutput {
                slot_index: 2,
                value: 30,
                owner: out_owners[1],
                valid: true,
            },
            TxOutput {
                slot_index: 4,
                value: 20,
                owner: out_owners[2],
                valid: true,
            },
            TxOutput {
                slot_index: 5,
                value: 10,
                owner: out_owners[3],
                valid: true,
            },
            TxOutput::dummy(),
            TxOutput::dummy(),
            TxOutput::dummy(),
            TxOutput::dummy(),
        ],
        is_coinbase: false,
    };

    Scenario {
        body,
        secrets,
        n_live: 2,
    }
}

fn build_max_scenario() -> Scenario {
    let secrets = [
        mk_secret(0xA1),
        mk_secret(0xB2),
        mk_secret(0xC3),
        mk_secret(0xD4),
    ];
    let addrs: [Address; 4] = [
        native_address(secrets[0]),
        native_address(secrets[1]),
        native_address(secrets[2]),
        native_address(secrets[3]),
    ];

    let out_secrets = [
        mk_secret(0x10),
        mk_secret(0x20),
        mk_secret(0x30),
        mk_secret(0x40),
        mk_secret(0x50),
        mk_secret(0x60),
        mk_secret(0x70),
        mk_secret(0x80),
    ];
    let out_owners: [Address; 8] = std::array::from_fn(|i| native_address(out_secrets[i]));

    let body = TxBody {
        shape: noid_tx::TxShape::Standard4x8,
        epoch_anchor: [0xBB; 32],
        fee: 575,
        inputs: vec![
            TxInput {
                slot_index: 0,
                value: 1000,
                owner: addrs[0],
                spend_secret: SpendSecret(fields_to_bytes(secrets[0])),
                auth_tag: AuthTag([0u8; 32]),
                valid: true,
            },
            TxInput {
                slot_index: 3,
                value: 500,
                owner: addrs[1],
                spend_secret: SpendSecret(fields_to_bytes(secrets[1])),
                auth_tag: AuthTag([0u8; 32]),
                valid: true,
            },
            TxInput {
                slot_index: 5,
                value: 250,
                owner: addrs[2],
                spend_secret: SpendSecret(fields_to_bytes(secrets[2])),
                auth_tag: AuthTag([0u8; 32]),
                valid: true,
            },
            TxInput {
                slot_index: 7,
                value: 125,
                owner: addrs[3],
                spend_secret: SpendSecret(fields_to_bytes(secrets[3])),
                auth_tag: AuthTag([0u8; 32]),
                valid: true,
            },
        ],
        outputs: vec![
            TxOutput {
                slot_index: 1,
                value: 400,
                owner: out_owners[0],
                valid: true,
            },
            TxOutput {
                slot_index: 2,
                value: 300,
                owner: out_owners[1],
                valid: true,
            },
            TxOutput {
                slot_index: 4,
                value: 200,
                owner: out_owners[2],
                valid: true,
            },
            TxOutput {
                slot_index: 6,
                value: 150,
                owner: out_owners[3],
                valid: true,
            },
            TxOutput {
                slot_index: 8,
                value: 100,
                owner: out_owners[4],
                valid: true,
            },
            TxOutput {
                slot_index: 9,
                value: 75,
                owner: out_owners[5],
                valid: true,
            },
            TxOutput {
                slot_index: 10,
                value: 50,
                owner: out_owners[6],
                valid: true,
            },
            TxOutput {
                slot_index: 11,
                value: 25,
                owner: out_owners[7],
                valid: true,
            },
        ],
        is_coinbase: false,
    };

    Scenario {
        body,
        secrets,
        n_live: 4,
    }
}

fn finalize_scenario(scenario: &mut Scenario) {
    let pins = boundary_pins_from_body(&scenario.body);
    let tx_body_hash = pins.tx_body_hash;

    for i in 0..scenario.n_live {
        let tag_fields = native_auth_tag_fields(scenario.secrets[i], tx_body_hash);
        scenario.body.inputs[i].auth_tag = AuthTag(fields_to_bytes(tag_fields));
    }
}

fn build_logic_inputs(
    body: &TxBody,
    secrets: &[[Block128; 2]; N_AUTH_INPUTS],
    n_live: usize,
) -> (
    TxLogicAir,
    noid_air::Trace,
    PublicInputs,
    SpineInputs,
    AuthInputs,
) {
    let pins = boundary_pins_from_body(body);
    let air = TxLogicAir::new(pins);

    let logic_witness = witness_from_body(body);
    let trace = air.build_trace(&logic_witness);

    let spine_inputs = SpineInputs {
        epoch_anchor: pins.epoch_anchor,
        fee_leaf: pins.fee_leaf,
        input_leaves: pins.input_leaf_absorb,
        output_leaves: pins.output_leaf_absorb,
        is_coinbase_leaf: pins.is_coinbase_leaf,
        pad_leaf: [Block128::ZERO; 2],
    };

    let auth_circuit = AuthCircuit::build();
    let mut spend_secret = [[Block128::ZERO; 2]; N_AUTH_INPUTS];
    for i in 0..n_live {
        spend_secret[i] = secrets[i];
    }
    let tx_body_hash = pins.tx_body_hash;
    let (expected_address, expected_auth_tag) =
        compute_auth_boundary(&auth_circuit, spend_secret, tx_body_hash);
    let auth_inputs = AuthInputs {
        spend_secret,
        tx_body_hash,
        expected_address,
        expected_auth_tag,
    };

    let n_live_inputs = body.inputs.iter().filter(|inp| inp.valid).count() as u8;
    let n_live_outputs = body.outputs.iter().filter(|out| out.valid).count() as u8;
    let claims_commitment = compute_claims_commitment(&body.inputs, &body.outputs);

    let mut is_activation = [false; MAX_OUTPUTS];
    for (j, out) in body.outputs.iter().enumerate().take(MAX_OUTPUTS) {
        is_activation[j] = out.valid;
    }
    let mut is_deactivation = [false; MAX_INPUTS];
    for (i, inp) in body.inputs.iter().enumerate().take(MAX_INPUTS) {
        is_deactivation[i] = inp.valid;
    }

    let pi = PublicInputs {
        epoch_anchor: body.epoch_anchor,
        tx_body_hash: TxBodyHash(fields_to_bytes(tx_body_hash)),
        shape_id: body.shape.id(),
        fee: body.fee,
        n_live_inputs,
        n_live_outputs,
        coinbase_credit: 0,
        log_slots: 24,
        claims_commitment,
        is_activation,
        is_deactivation,
    };

    (air, trace, pi, spine_inputs, auth_inputs)
}

fn run_scenario(label: &str, scenario: &Scenario) -> BenchResult {
    let (air, trace, pi, spine_inputs, auth_inputs) =
        build_logic_inputs(&scenario.body, &scenario.secrets, scenario.n_live);

    assert!(
        air.check(&trace),
        "FATAL: trace rejected by AIR for {}",
        label
    );

    let witness = LogicWitness {
        air: &air,
        trace: &trace,
        pi: &pi,
        auth_inputs: &auth_inputs,
    };

    // Cold prove
    let t = Instant::now();
    let logic_proof = prove_logic(&witness).expect("prove_logic failed");
    let prove_cold = t.elapsed();

    let proof_bytes = logic_proof.estimated_byte_len();
    let auth_bytes = logic_proof.auth.byte_len();
    let stark_bytes = proof_bytes - auth_bytes;

    // Cold verify
    let auth_public = auth_inputs.to_public();
    let t = Instant::now();
    verify_logic(&air, &pi, &spine_inputs, &auth_public, &logic_proof)
        .expect("verify_logic failed");
    let verify_cold = t.elapsed();

    // Warm runs
    const RUNS: usize = 5;
    let mut prove_times = Vec::with_capacity(RUNS);
    let mut verify_times = Vec::with_capacity(RUNS);

    for _ in 0..RUNS {
        let t = Instant::now();
        let p = prove_logic(&witness).expect("prove_logic");
        prove_times.push(t.elapsed());

        let t = Instant::now();
        verify_logic(&air, &pi, &spine_inputs, &auth_public, &p).expect("verify_logic");
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
    println!("  PARANOID — Wallet LogicProof Bench");
    println!("  ====================================================================");
    println!(
        "  Protocol: STARK ({} cols) + AuthGKR (20 perms) [Split GKR: SpineGKR at block]",
        TX_LOGIC_N_COLS
    );
    println!("  Mode:     Production (single-transcript, interleaved PCS)");
    println!("  Path:     Wallet-side prove_logic (stateless, no spine, no state-opening)");
    println!("  Runs:     1 cold + 5 warm per scenario");
    println!();

    // -----------------------------------------------------------------------
    // Scenario A: Standard transaction (2 inputs, 4 outputs)
    // -----------------------------------------------------------------------
    eprintln!("  running scenario A: standard tx (2 in / 4 out)...");
    let mut scenario_std = build_standard_scenario();
    finalize_scenario(&mut scenario_std);
    let result_std = run_scenario("standard", &scenario_std);

    // -----------------------------------------------------------------------
    // Scenario B: Max-capacity transaction (4 inputs, 8 outputs)
    // -----------------------------------------------------------------------
    eprintln!("  running scenario B: max-capacity tx (4 in / 8 out)...");
    let mut scenario_max = build_max_scenario();
    finalize_scenario(&mut scenario_max);
    let result_max = run_scenario("max-capacity", &scenario_max);

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
