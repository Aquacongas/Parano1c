// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

#![allow(clippy::manual_memcpy)]

//! Paranoid STARK report — **Full Two-Layer Pipeline**.
//!
//!   cargo bench --bench stark_report
//!
//!   Layer 1 (Wallet):    prove_logic / verify_logic (81-col TxLogicAir)
//!   Layer 2 (Full Node): verify_logic + prove_block (deferred-opening aggregation)
//!   Block Verifier:      verify_block (GKR + algebraic STARK + FRI)
//!
//! Shows how transactions flow from wallet to block, how they are
//! aggregated via deferred-opening, and the cost at each stage.

use std::time::{Duration, Instant};

use noid_air::composition::tx_logic::{
    boundary_pins_from_body, witness_from_body, TxLogicAir, TX_LOGIC_LOG_ROWS, TX_LOGIC_N_COLS,
};
use noid_air::Air;
use noid_block::{prove_block, verify_block, TxBlockWitness, BLOCK_BASE_LOG};
use noid_core::mle::split::split_mle_into_slices;
use noid_core::{Block128, TowerField};
use noid_fri_binius::COMPACT_NUM_QUERIES;
use noid_gkr::{
    auth_gkr_channel, build_auth_unified_from_inputs, compute_auth_boundary, prove_auth_killshot,
    AuthCircuit, AuthInputs, AuthProofKillShot, AuthPublicInputs, SpineInputs, N_AUTH_INPUTS,
    N_AUTH_UNIFIED_VARS,
};
use noid_poseidon2b::primitives::{
    derive_address, hash_auth_tag, Address, AuthTag, SpendSecret, TxBodyHash,
};
use noid_stark::prove_logic::{prove_logic, verify_logic, LogicProof, LogicWitness};
use noid_tx::{
    compute_claims_commitment, PublicInputs, TxBody, TxInput, TxOutput, MAX_INPUTS, MAX_OUTPUTS,
};

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

const WARMUP: usize = 1;
const SAMPLES: usize = 3;

// ---------------------------------------------------------------------------
// Timing helpers
// ---------------------------------------------------------------------------

fn median(mut v: Vec<Duration>) -> Duration {
    v.sort();
    v[v.len() / 2]
}

fn time<F: FnMut()>(mut f: F) -> Duration {
    for _ in 0..WARMUP {
        f();
    }
    let mut xs = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        let t = Instant::now();
        f();
        xs.push(t.elapsed());
    }
    median(xs)
}

fn time_once<F: FnOnce()>(f: F) -> Duration {
    let t = Instant::now();
    f();
    t.elapsed()
}

fn fmt_ms(d: Duration) -> String {
    let ms = d.as_secs_f64() * 1_000.0;
    if ms >= 1_000.0 {
        format!("{:>9.2} s ", ms / 1_000.0)
    } else if ms >= 1.0 {
        format!("{:>9.2} ms", ms)
    } else {
        format!("{:>9.2} us", ms * 1_000.0)
    }
}

fn fmt_bytes(bytes: usize) -> String {
    if bytes >= 1024 * 1024 {
        format!("{:>9.2} MB", bytes as f64 / (1024.0 * 1024.0))
    } else if bytes >= 1024 {
        format!("{:>9.2} KB", bytes as f64 / 1024.0)
    } else {
        format!("{:>9} B ", bytes)
    }
}

// ---------------------------------------------------------------------------
// Fixture construction
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

struct TxFixture {
    air: TxLogicAir,
    trace: noid_air::Trace,
    pi: PublicInputs,
    spine_inputs: SpineInputs,
    auth_inputs: AuthInputs,
    auth_public: AuthPublicInputs,
    auth_proof: AuthProofKillShot,
    auth_slices: Vec<Vec<Block128>>,
}

fn build_tx_fixture(
    slot_base: u32,
    input_values: &[u64],
    output_values: &[u64],
    fee: u128,
    secrets: &[[Block128; 2]; N_AUTH_INPUTS],
) -> TxFixture {
    let n_inputs = input_values.len().min(MAX_INPUTS);
    let n_outputs = output_values.len().min(MAX_OUTPUTS);
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

    // Generate wallet-side auth proof + slices (simulates wallet).
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
        auth_inputs,
        auth_public,
        auth_proof,
        auth_slices,
    }
}

// ---------------------------------------------------------------------------
// Pipeline stages
// ---------------------------------------------------------------------------

struct WalletResult {
    prove_time: Duration,
    verify_time: Duration,
    proof: LogicProof,
}

fn bench_wallet_prove(fixture: &TxFixture) -> WalletResult {
    let witness = LogicWitness {
        air: &fixture.air,
        trace: &fixture.trace,
        pi: &fixture.pi,
        auth_inputs: &fixture.auth_inputs,
    };

    let prove_time = time(|| {
        let _ = prove_logic(&witness).expect("prove_logic");
    });

    let proof = prove_logic(&witness).expect("prove_logic");

    let verify_time = time(|| {
        verify_logic(
            &fixture.air,
            &fixture.pi,
            &fixture.spine_inputs,
            &fixture.auth_public,
            &proof,
        )
        .expect("verify_logic");
    });

    WalletResult {
        prove_time,
        verify_time,
        proof,
    }
}

#[allow(dead_code)]
struct BlockResult {
    n_tx: usize,
    verify_logic_time: Duration,
    prove_block_time: Duration,
    verify_block_time: Duration,
    block_proof_bytes: usize,
    per_tx_algebraic_bytes: usize,
    unified_spine_bytes: usize,
}

fn bench_block_pipeline(fixtures: &[TxFixture], proofs: &[LogicProof]) -> BlockResult {
    let n_tx = fixtures.len();

    // Full-node verifies all wallet LogicProofs (each with its own AIR)
    let verify_logic_time = time_once(|| {
        for k in 0..n_tx {
            verify_logic(
                &fixtures[k].air,
                &fixtures[k].pi,
                &fixtures[k].spine_inputs,
                &fixtures[k].auth_public,
                &proofs[k],
            )
            .expect("verify_logic in block pipeline");
        }
    });

    // Full-node constructs TxBlockWitnesses and calls prove_block.
    // The block prover receives only public auth data + pre-built proof.
    let witnesses: Vec<TxBlockWitness<'_>> = fixtures
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

    let prev_state_root = fixtures[0].pi.epoch_anchor;

    let prove_block_time = time_once(|| {
        let _ = prove_block(prev_state_root, [0u8; 32], &witnesses, &[]).expect("prove_block");
    });

    let block_proof =
        prove_block(prev_state_root, [0u8; 32], &witnesses, &[]).expect("prove_block");
    let block_proof_bytes = block_proof.byte_len();
    let standard_bucket = block_proof
        .standard_bucket
        .as_ref()
        .expect("standard bucket");
    let per_tx_algebraic_bytes = if !standard_bucket.tx_algebraic.is_empty() {
        standard_bucket.tx_algebraic[0].byte_len()
    } else {
        0
    };
    let unified_spine_bytes = standard_bucket.block_spine_proof.byte_len();

    // Verifier verifies the block proof (only public auth data)
    let spine_inputs_list: Vec<SpineInputs> =
        fixtures.iter().map(|f| f.spine_inputs.clone()).collect();
    let auth_public_list: Vec<AuthPublicInputs> = fixtures.iter().map(|f| f.auth_public).collect();
    let air_refs: Vec<&dyn Air> = fixtures.iter().map(|f| &f.air as &dyn Air).collect();

    let verify_block_time = time_once(|| {
        verify_block(
            &air_refs,
            &block_proof,
            &spine_inputs_list,
            &auth_public_list,
            &[],
        )
        .expect("verify_block");
    });

    BlockResult {
        n_tx,
        verify_logic_time,
        prove_block_time,
        verify_block_time,
        block_proof_bytes,
        per_tx_algebraic_bytes,
        unified_spine_bytes,
    }
}

// ---------------------------------------------------------------------------
// Banner and printing
// ---------------------------------------------------------------------------

const BANNER: &str = r#"
   ____   _    ____      _    _   _  ___ ___ ____
  |  _ \ / \  |  _ \    / \  | \ | |/ _ \_ _|  _ \
  | |_) / _ \ | |_) |  / _ \ |  \| | | | | || | | |
  |  __/ ___ \|  _ <  / ___ \| |\  | |_| | || |_| |
  |_| /_/   \_\_| \_\/_/   \_\_| \_|\___/___|____/

  PARANOID  --  Two-Layer ZK Architecture: Full Pipeline Report
  Layer 1: Wallet (prove_logic, 81-col TxLogicAir, stateless)
  Layer 2: Full Node (verify_logic + prove_block, deferred-opening)
  Verifier: verify_block (GKR + algebraic STARK + single FRI)
"#;

fn print_banner() {
    println!("{}", BANNER);
    println!(
        "  Wall-clock medians, release profile. Warmup: {} / Samples: {}.",
        WARMUP, SAMPLES
    );
    println!();
}

fn print_section(title: &str) {
    println!("  ==========================================================================");
    println!("  {title}");
    println!("  ==========================================================================");
    println!();
}

fn print_subsection(title: &str) {
    println!("  --------------------------------------------------------------------------");
    println!("  {title}");
    println!("  --------------------------------------------------------------------------");
}

// ---------------------------------------------------------------------------
// Entrypoint
// ---------------------------------------------------------------------------

fn main() {
    print_banner();

    let secrets = [
        mk_secret(0xA1),
        mk_secret(0xB2),
        mk_secret(0xC3),
        mk_secret(0xD4),
    ];

    // =========================================================================
    // Build fixtures: 4 transactions for block aggregation test
    // =========================================================================
    eprintln!("  building fixtures (4 transactions)...");

    let fixture_1 = build_tx_fixture(0, &[100, 50], &[60, 40], 50, &secrets);
    let fixture_2 = build_tx_fixture(100, &[200, 100], &[150, 80, 50, 20], 0, &secrets);
    let fixture_3 = build_tx_fixture(200, &[500], &[300, 200], 0, &secrets);
    let fixture_4 = build_tx_fixture(
        300,
        &[1000, 500, 250, 125],
        &[400, 300, 200, 150, 100, 75, 50, 25],
        575,
        &secrets,
    );

    for (i, f) in [&fixture_1, &fixture_2, &fixture_3, &fixture_4]
        .iter()
        .enumerate()
    {
        assert!(
            f.air.check(&f.trace),
            "FATAL: fixture {} trace rejected by AIR",
            i
        );
    }

    // =========================================================================
    // SECTION 1: Wallet-side (Layer 1)
    // =========================================================================
    print_section("LAYER 1: WALLET — prove_logic (stateless, client-side)");

    println!("  Architecture (Split GKR):");
    println!(
        "    AIR:         TxLogicAir ({} columns, log_rows={})",
        TX_LOGIC_N_COLS, TX_LOGIC_LOG_ROWS
    );
    println!(
        "    GKR Auth:    {} inputs x 5 perms = {} Poseidon2b perms (spend auth)",
        N_AUTH_INPUTS,
        N_AUTH_INPUTS * 5
    );
    println!("    GKR Spine:   DEFERRED to block prover (59 Poseidon2b perms)");
    println!(
        "    PCS:         FRI-Binius interleaved ({} AIR cols + {} auth slices)",
        TX_LOGIC_N_COLS,
        1 << (N_AUTH_UNIFIED_VARS - BLOCK_BASE_LOG)
    );
    println!("    FRI queries: {} (wallet & block)", COMPACT_NUM_QUERIES);
    println!("    Binding:     epoch_anchor (6-block TTL, no state root needed)");
    println!();

    eprintln!("  benchmarking wallet prove_logic / verify_logic...");
    let wallet_1 = bench_wallet_prove(&fixture_1);
    let wallet_2 = bench_wallet_prove(&fixture_2);
    let wallet_3 = bench_wallet_prove(&fixture_3);
    let wallet_4 = bench_wallet_prove(&fixture_4);

    let wallets = [&wallet_1, &wallet_2, &wallet_3, &wallet_4];
    let labels = [
        "Tx 1: 2 in / 2 out, fee=50",
        "Tx 2: 2 in / 4 out, fee=0",
        "Tx 3: 1 in / 2 out, fee=0",
        "Tx 4: 4 in / 8 out, fee=575 (max capacity)",
    ];

    for (i, (w, label)) in wallets.iter().zip(labels.iter()).enumerate() {
        let proof_bytes = w.proof.estimated_byte_len();
        let auth_bytes = w.proof.auth.byte_len();
        let stark_bytes = proof_bytes - auth_bytes;

        println!("  [Tx {}] {}", i + 1, label);
        println!(
            "    prove_logic:    {}    verify_logic:    {}",
            fmt_ms(w.prove_time),
            fmt_ms(w.verify_time)
        );
        println!(
            "    proof size:     {} (STARK: {}, Auth: {})",
            fmt_bytes(proof_bytes),
            fmt_bytes(stark_bytes),
            fmt_bytes(auth_bytes),
        );
        println!();
    }

    let avg_prove: Duration =
        wallets.iter().map(|w| w.prove_time).sum::<Duration>() / wallets.len() as u32;
    let avg_verify: Duration =
        wallets.iter().map(|w| w.verify_time).sum::<Duration>() / wallets.len() as u32;
    let avg_bytes: usize = wallets
        .iter()
        .map(|w| w.proof.estimated_byte_len())
        .sum::<usize>()
        / wallets.len();

    print_subsection("Wallet Summary");
    println!(
        "    Average prove:   {}    (target < 500 ms)",
        fmt_ms(avg_prove)
    );
    println!(
        "    Average verify:  {}    (target < 100 ms)",
        fmt_ms(avg_verify)
    );
    println!(
        "    Average size:    {}    (target < 50 KB)",
        fmt_bytes(avg_bytes)
    );
    println!();

    // =========================================================================
    // SECTION 2: Full Node (Layer 2)
    // =========================================================================
    print_section("LAYER 2: FULL NODE — verify_logic + prove_block (deferred-opening)");

    println!("  Architecture:");
    println!("    Input:       N wallet LogicProofs + mempool transaction bodies");
    println!("    Pipeline:");
    println!("      1. Verify each LogicProof (verify_logic) — reject invalid txs");
    println!("      2. Build single interleaved Merkle tree over ALL columns");
    println!("      3. Unified Block SpineGKR: ONE Kill-Shot over N*59 perms");
    println!("      4. Per-tx Auth Kill-Shots + algebraic STARK (no FRI per tx)");
    println!("      5. Block-level multipoint sumcheck -> single r_block");
    println!("      6. ONE FRI-Binius mixed opening at r_block (amortized over N)");
    println!("    State binding: BlockStateBinding (slot opens, pre/post root, C_claimed bridge)");
    println!();

    // --- Block with 1 tx ---
    eprintln!("  benchmarking block pipeline (1 tx)...");
    let fixtures_1tx = vec![build_tx_fixture(0, &[100, 50], &[60, 40], 50, &secrets)];
    let proofs_1tx: Vec<LogicProof> = fixtures_1tx
        .iter()
        .map(|f| {
            let w = LogicWitness {
                air: &f.air,
                trace: &f.trace,
                pi: &f.pi,
                auth_inputs: &f.auth_inputs,
            };
            prove_logic(&w).expect("prove_logic")
        })
        .collect();
    let block_1tx = bench_block_pipeline(&fixtures_1tx, &proofs_1tx);

    // --- Block with 4 txs ---
    eprintln!("  benchmarking block pipeline (4 txs)...");
    let owned_fixtures: Vec<TxFixture> = vec![
        build_tx_fixture(0, &[100, 50], &[60, 40], 50, &secrets),
        build_tx_fixture(100, &[200, 100], &[150, 80, 50, 20], 0, &secrets),
        build_tx_fixture(200, &[500], &[300, 200], 0, &secrets),
        build_tx_fixture(
            300,
            &[1000, 500, 250, 125],
            &[400, 300, 200, 150, 100, 75, 50, 25],
            575,
            &secrets,
        ),
    ];
    let owned_proofs: Vec<LogicProof> = owned_fixtures
        .iter()
        .map(|f| {
            let w = LogicWitness {
                air: &f.air,
                trace: &f.trace,
                pi: &f.pi,
                auth_inputs: &f.auth_inputs,
            };
            prove_logic(&w).expect("prove_logic")
        })
        .collect();
    let block_4tx = bench_block_pipeline(&owned_fixtures, &owned_proofs);

    println!("  [1-tx Block]");
    println!(
        "    verify_logic (N=1):       {}",
        fmt_ms(block_1tx.verify_logic_time)
    );
    println!(
        "    prove_block (N=1):        {}",
        fmt_ms(block_1tx.prove_block_time)
    );
    println!(
        "    verify_block (N=1):       {}",
        fmt_ms(block_1tx.verify_block_time)
    );
    println!(
        "    block proof size:         {}",
        fmt_bytes(block_1tx.block_proof_bytes)
    );
    println!(
        "    unified spine (1*59):     {}",
        fmt_bytes(block_1tx.unified_spine_bytes)
    );
    println!(
        "    per-tx algebraic STARK:   {}",
        fmt_bytes(block_1tx.per_tx_algebraic_bytes)
    );
    println!();

    println!("  [4-tx Block] (Unified Block SpineGKR)");
    println!(
        "    verify_logic (N=4):       {}",
        fmt_ms(block_4tx.verify_logic_time)
    );
    println!(
        "    prove_block (N=4):        {}",
        fmt_ms(block_4tx.prove_block_time)
    );
    println!(
        "    verify_block (N=4):       {}",
        fmt_ms(block_4tx.verify_block_time)
    );
    println!(
        "    block proof size:         {}",
        fmt_bytes(block_4tx.block_proof_bytes)
    );
    println!(
        "    unified spine (4*59):     {}",
        fmt_bytes(block_4tx.unified_spine_bytes)
    );
    println!(
        "    per-tx algebraic STARK:   {}",
        fmt_bytes(block_4tx.per_tx_algebraic_bytes)
    );
    println!();

    let fri_amort_1 = block_1tx.block_proof_bytes;
    let fri_amort_4 = block_4tx.block_proof_bytes;
    let ratio = fri_amort_4 as f64 / fri_amort_1 as f64;
    // Deferred-opening amortizes the FRI over all txs (constant ~14 KB overhead).
    // Per-tx marginal cost is ~20 KB of column openings + algebraic STARK.
    // At large N, BlockProof/N converges to the per-tx marginal cost.
    println!(
        "    Block proof growth: 4 txs = {:.2}x the 1-tx size (FRI amortized; per-tx ~{} KB)",
        ratio,
        (block_4tx
            .block_proof_bytes
            .saturating_sub(block_1tx.block_proof_bytes))
            / 3
            / 1024
    );
    println!(
        "    Cost per tx (4-tx block): prove {} / verify {}",
        fmt_ms(block_4tx.prove_block_time / 4),
        fmt_ms(block_4tx.verify_block_time / 4),
    );
    println!();

    // =========================================================================
    // SECTION 3: End-to-end summary
    // =========================================================================
    print_section("END-TO-END: Transaction Lifecycle");

    println!("  Flow: User -> Wallet -> Network -> Full Node -> Block -> Verifiers");
    println!();
    println!("    1. Wallet builds TxBody (inputs, outputs, fee, epoch_anchor)");
    println!(
        "    2. Wallet calls prove_logic() -> LogicProof ({} bytes)",
        avg_bytes
    );
    println!("       Time: {} (user-facing latency)", fmt_ms(avg_prove));
    println!();
    println!("    3. Wallet broadcasts TxIntent (TxBody + LogicProof) over P2P");
    println!();
    println!("    4. Full node receives TxIntent, calls verify_logic()");
    println!("       Time: {} (mempool admission)", fmt_ms(avg_verify));
    println!("       Rejects: tampered body-hash, invalid balance, bad auth");
    println!();
    println!("    5. Miner collects N valid TxIntents into a block");
    println!("       Unified Block SpineGKR (1 proof for all N*59 perms)");
    println!(
        "       N=4 time: {} (unified spine + deferred-opening FRI)",
        fmt_ms(block_4tx.prove_block_time),
    );
    println!();
    println!("    6. Block verifier checks the block proof");
    println!(
        "       N=4 time: {} (GKR + algebraic STARK + FRI)",
        fmt_ms(block_4tx.verify_block_time)
    );
    println!();

    print_subsection("Total Latencies");
    let total_user = avg_prove;
    let total_node = avg_verify + block_4tx.prove_block_time / 4;
    let total_verifier = block_4tx.verify_block_time / 4;
    println!(
        "    User (wallet):      {}  (prove_logic)",
        fmt_ms(total_user)
    );
    println!(
        "    Full node (per tx): {}  (verify_logic + prove_block/N)",
        fmt_ms(total_node)
    );
    println!(
        "    Block verifier/tx:  {}  (verify_block/N)",
        fmt_ms(total_verifier)
    );
    println!();

    print_subsection("Proof Sizes");
    println!(
        "    LogicProof (wallet):   {}  (per-tx, carried over P2P)",
        fmt_bytes(avg_bytes)
    );
    println!(
        "    BlockProof (4 txs):    {}  (amortized FRI)",
        fmt_bytes(block_4tx.block_proof_bytes)
    );
    println!(
        "    BlockProof per tx:     {}  (= BlockProof / N)",
        fmt_bytes(block_4tx.block_proof_bytes / 4)
    );
    println!();

    print_subsection("Security Properties");
    println!("    - Fiat-Shamir binds prev_block_state_root into block channel");
    println!("    - Auth-spine bridge checks live input slots (deactivating); dummies cannot authorize spend");
    println!("    - GKR channels seeded with interleaved Merkle cap");
    println!("    - Slice reconstruction verified against GKR reduction values");
    println!("    - BlockStateBinding enforces slot pre/post conditions (full node)");
    println!();

    println!("  Reproduce: cargo bench --bench stark_report");
    println!();
}
