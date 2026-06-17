// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Block scaling benchmark — measures the block prover's real workload.
//!
//!   cargo bench --bench block_scaling
//!
//! In production the pipeline is:
//!   1. Wallets produce TxIntents (trace + AuthGKR proof) offline.
//!   2. Full Node collects N intents from mempool.
//!   3. Full Node runs prove_block: commit + spine KS + per-tx algebraic
//!      STARK (no per-tx FRI) + multipoint sumcheck + single FRI opening.
//!
//! This bench times step (1) once to show wallet-side cost, then
//! measures step (3) — the real block-production bottleneck — at
//! varying block sizes.

use std::time::{Duration, Instant};

use noid_air::composition::tx_logic::{boundary_pins_from_body, witness_from_body, TxLogicAir};
use noid_air::Air;
use noid_block::{prove_block, verify_block, TxBlockWitness, BLOCK_BASE_LOG};
use noid_core::mle::split::split_mle_into_slices;
use noid_core::{Block128, TowerField};
use noid_gkr::{
    auth_gkr_channel, build_auth_unified_from_inputs, compute_auth_boundary, prove_auth_killshot,
    AuthCircuit, AuthInputs, AuthProofKillShot, AuthPublicInputs, SpineInputs, N_AUTH_INPUTS,
    N_AUTH_UNIFIED_VARS,
};
use noid_poseidon2b::primitives::{
    derive_address, hash_auth_tag, Address, AuthTag, SpendSecret, TxBodyHash,
};
use noid_tx::{
    compute_claims_commitment, PublicInputs, TxBody, TxInput, TxOutput, MAX_INPUTS, MAX_OUTPUTS,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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

fn fmt_ms(d: Duration) -> String {
    let ms = d.as_secs_f64() * 1_000.0;
    if ms >= 1_000.0 {
        format!("{:>8.2} s ", ms / 1_000.0)
    } else {
        format!("{:>8.2} ms", ms)
    }
}

fn fmt_bytes(bytes: usize) -> String {
    if bytes >= 1024 * 1024 {
        format!("{:>8.2} MB", bytes as f64 / (1024.0 * 1024.0))
    } else if bytes >= 1024 {
        format!("{:>8.2} KB", bytes as f64 / 1024.0)
    } else {
        format!("{:>8} B ", bytes)
    }
}

// ---------------------------------------------------------------------------
// Fixture (wallet-side work product)
// ---------------------------------------------------------------------------

struct TxFixture {
    air: TxLogicAir,
    trace: noid_air::Trace,
    pi: PublicInputs,
    spine_inputs: SpineInputs,
    auth_public: AuthPublicInputs,
    auth_proof: AuthProofKillShot,
    auth_slices: Vec<Vec<Block128>>,
}

fn build_tx_fixture(slot_base: u32, secrets: &[[Block128; 2]; N_AUTH_INPUTS]) -> TxFixture {
    let n_inputs = 2;
    let n_outputs = 2;
    let fee = 10u128;
    let input_values = [100u64, 50];
    let output_values = [80u64, 60];

    let addrs: Vec<Address> = (0..N_AUTH_INPUTS)
        .map(|i| native_address(secrets[i]))
        .collect();

    let mut inputs = Vec::with_capacity(MAX_INPUTS);
    for i in 0..n_inputs {
        inputs.push(TxInput {
            slot_index: slot_base + i as u32,
            value: input_values[i],
            owner: addrs[i],
            spend_secret: SpendSecret(fields_to_bytes(secrets[i])),
            auth_tag: AuthTag([0u8; 32]),
            valid: true,
        });
    }
    while inputs.len() < MAX_INPUTS {
        inputs.push(TxInput::dummy());
    }

    let out_secrets: Vec<[Block128; 2]> = (0..MAX_OUTPUTS)
        .map(|j| mk_secret(0x100 + slot_base as u128 + j as u128))
        .collect();
    let mut outputs = Vec::with_capacity(MAX_OUTPUTS);
    for j in 0..n_outputs {
        outputs.push(TxOutput {
            slot_index: slot_base + MAX_INPUTS as u32 + j as u32,
            value: output_values[j],
            owner: native_address(out_secrets[j]),
            valid: true,
        });
    }
    while outputs.len() < MAX_OUTPUTS {
        outputs.push(TxOutput::dummy());
    }

    let mut body = TxBody {
        shape: noid_tx::TxShape::Standard4x8,
        epoch_anchor: [0xAA; 32],
        fee,
        inputs,
        outputs,
        is_coinbase: false,
    };

    let pins = boundary_pins_from_body(&body);
    let tx_body_hash = pins.tx_body_hash;

    for i in 0..n_inputs {
        let tag_fields = native_auth_tag_fields(secrets[i], tx_body_hash);
        body.inputs[i].auth_tag = AuthTag(fields_to_bytes(tag_fields));
    }

    let air = TxLogicAir::new(pins);
    let logic_witness = witness_from_body(&body);
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
    for i in 0..n_inputs {
        spend_secret[i] = secrets[i];
    }
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

    let auth_public = auth_inputs.to_public();
    let mut ch = auth_gkr_channel();
    let (auth_proof, _) = prove_auth_killshot(&auth_circuit, &auth_inputs, &mut ch);
    let auth_mle = build_auth_unified_from_inputs(&auth_circuit, &auth_inputs);
    let auth_slices = split_mle_into_slices(&auth_mle.state, N_AUTH_UNIFIED_VARS, BLOCK_BASE_LOG);

    TxFixture {
        air,
        trace,
        pi,
        spine_inputs,
        auth_public,
        auth_proof,
        auth_slices,
    }
}

// ---------------------------------------------------------------------------
// Bench driver
// ---------------------------------------------------------------------------

fn bench_block(n_tx: usize, fixtures: &[TxFixture]) {
    let witnesses: Vec<TxBlockWitness<'_>> = fixtures[..n_tx]
        .iter()
        .enumerate()
        .map(|(k, f)| TxBlockWitness {
            block_tx_index: (k + 1) as u32,
            air: &f.air as &dyn Air,
            trace: &f.trace,
            pi: &f.pi,
            spine_inputs: &f.spine_inputs,
            auth_public: &f.auth_public,
            auth_proof: &f.auth_proof,
            auth_slices: &f.auth_slices,
        })
        .collect();

    let prev_state_root = [0xAA; 32];

    // Block Prove (this is ONLY block-prover work; wallet proofs are pre-built)
    let t0 = Instant::now();
    let block_proof =
        prove_block(prev_state_root, [0u8; 32], &witnesses, &[]).expect("prove_block");
    let prove_time = t0.elapsed();

    // Block Verify
    let spine_inputs_list: Vec<SpineInputs> = fixtures[..n_tx]
        .iter()
        .map(|f| f.spine_inputs.clone())
        .collect();
    let auth_public_list: Vec<AuthPublicInputs> =
        fixtures[..n_tx].iter().map(|f| f.auth_public).collect();
    let air_refs: Vec<&dyn Air> = fixtures[..n_tx]
        .iter()
        .map(|f| &f.air as &dyn Air)
        .collect();

    let t1 = Instant::now();
    verify_block(
        &air_refs,
        &block_proof,
        &spine_inputs_list,
        &auth_public_list,
        &[],
    )
    .expect("verify_block");
    let verify_time = t1.elapsed();

    let proof_bytes = block_proof.byte_len();
    let standard_bucket = block_proof
        .standard_bucket
        .as_ref()
        .expect("standard bucket");
    let spine_bytes = standard_bucket.block_spine_proof.byte_len();
    let alg_bytes_total: usize = standard_bucket
        .tx_algebraic
        .iter()
        .map(|a| a.byte_len())
        .sum();

    println!("  [{:>4}-tx Block]", n_tx);
    println!("    prove_block (full node):   {}", fmt_ms(prove_time));
    println!("    verify_block (any node):   {}", fmt_ms(verify_time));
    println!(
        "    prove per tx (amortized):  {}",
        fmt_ms(prove_time / n_tx as u32)
    );
    println!(
        "    verify per tx (amortized): {}",
        fmt_ms(verify_time / n_tx as u32)
    );
    println!("    block proof size:          {}", fmt_bytes(proof_bytes));
    println!(
        "    proof per tx:              {}",
        fmt_bytes(proof_bytes / n_tx)
    );
    println!("    unified spine:             {}", fmt_bytes(spine_bytes));
    println!(
        "    algebraic total:           {}",
        fmt_bytes(alg_bytes_total)
    );
    println!();
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() {
    println!();
    println!("  =====================================================================");
    println!("  PARANOID Block Scaling Benchmark");
    println!("  =====================================================================");
    println!();
    println!("  Block production pipeline (production topology):");
    println!("    WALLET (offline): trace + AuthGKR proof  -->  TxIntent in mempool");
    println!("    FULL NODE (block assembly): commit + spine KS + per-tx algebraic");
    println!("      STARK (no per-tx FRI) + multipoint sumcheck + single FRI opening");
    println!();
    println!("  This bench measures FULL NODE prove_block time (the block-time");
    println!("  bottleneck). Wallet-side work is shown separately below.");
    println!();

    let secrets = [
        mk_secret(0xA1),
        mk_secret(0xB2),
        mk_secret(0xC3),
        mk_secret(0xD4),
    ];

    let block_sizes = [10, 20, 100];
    let max_n = *block_sizes.iter().max().unwrap();

    // -------------------------------------------------------------------------
    // Wallet-side timing (offline, per-tx, NOT part of block production)
    // -------------------------------------------------------------------------
    eprintln!("  timing wallet-side TxIntent preparation (1 tx)...");
    let t_wallet = Instant::now();
    let _ = build_tx_fixture(9999, &secrets);
    let wallet_time = t_wallet.elapsed();

    println!("  -------------------------------------------------------------------");
    println!("  WALLET-SIDE (offline, not in block-time budget):");
    println!(
        "    TxIntent prep (trace + AuthGKR):  {}",
        fmt_ms(wallet_time)
    );
    println!("    This happens on user's device before submitting to mempool.");
    println!("    The full node never re-does this work.");
    println!("  -------------------------------------------------------------------");
    println!();

    // -------------------------------------------------------------------------
    // Build remaining fixtures (simulates mempool of pre-proven TxIntents)
    // -------------------------------------------------------------------------
    eprintln!(
        "  building {} TxIntent fixtures (simulating mempool)...",
        max_n
    );
    let t_build = Instant::now();
    let fixtures: Vec<TxFixture> = (0..max_n)
        .map(|i| build_tx_fixture(i as u32 * 20, &secrets))
        .collect();
    eprintln!(
        "  {} intents ready in {} (wallet-parallel, not block time)",
        max_n,
        fmt_ms(t_build.elapsed()).trim()
    );
    eprintln!();

    // -------------------------------------------------------------------------
    // Full Node block proving (THE block-time bottleneck)
    // -------------------------------------------------------------------------
    println!("  -------------------------------------------------------------------");
    println!("  FULL NODE prove_block (block-time budget = 15s target):");
    println!("  -------------------------------------------------------------------");
    println!("  Receives pre-proven TxIntents from mempool. Work done here:");
    println!("    1. Interleaved Merkle commit (all columns, one tree)");
    println!("    2. Unified spine GKR Kill-Shot (body-hash correctness)");
    println!("    3. Per-tx algebraic STARK (zero-check, no per-tx FRI)");
    println!("    4. Block-level multipoint sumcheck (batches all openings)");
    println!("    5. Single FRI-Binius mixed opening");
    println!("  -------------------------------------------------------------------");
    println!();

    for &n in &block_sizes {
        eprintln!("  benchmarking N={}...", n);
        bench_block(n, &fixtures);
    }

    println!("  -------------------------------------------------------------------");
    println!("  NOTES:");
    println!("    - Internal miner runs PoW search and prove_block in parallel.");
    println!("    - If prove_block fits the miner's adaptive budget, the block can include those transactions.");
    println!("    - Empty-block fallback: miner starts on coinbase-only header");
    println!("      immediately; full template replaces it once prove_block finishes.");
    println!("    - Wallet-side prep shown above is NOT additive to block time.");
    println!("  -------------------------------------------------------------------");
    println!();
    println!("  Reproduce: cargo bench --bench block_scaling");
    println!();
}
