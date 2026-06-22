// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Focused recursive proof hotspot benchmark.
//!
//!   cargo bench -p bench_prover --bench recursive_hotspots
//!
//! Defaults are intentionally small enough for optimization loops while still
//! exercising real production block proofs. Override with:
//!
//!   NOID_RECURSIVE_STANDARD_TX=10 NOID_RECURSIVE_SWEEP_TX=1 \
//!     cargo bench -p bench_prover --bench recursive_hotspots

use std::env;
use std::time::Duration;

use bench_prover::{
    bench_full_block_proof, bench_recursive_step, fmt_bytes, fmt_ms, owned_sweep_witness,
    prove_sweep_wallet, standard_fixture, standard_scenario, sweep_fixture, sweep_scenario,
    time_once, RecursiveStepBench, StandardFixture, SweepFixture,
};
use noid_chain::consensus::genesis::genesis_header;
use noid_chain::{hash_block_header, BlockHeader};
use noid_core::mem_profile::{current_mem_snapshot, MemSnapshot};
use noid_poseidon2b::primitives::Address;
use noid_recursive::{
    null_block_replay_witness, prove_genesis_recursive, prove_recursive_step,
    verify_recursive_step, ChainAccumulator, RecursiveBlockAir, RecursiveBlockProof,
};

const DEFAULT_STANDARD_TX: usize = 1;
const DEFAULT_SWEEP_TX: usize = 1;
const REFERENCE_STANDARD_TX: usize = 10;
const REFERENCE_SWEEP_TX: usize = 1;
const BENCH_LOG_SLOTS: u32 = bench_prover::BENCH_LOG_SLOTS;
const STANDARD_SLOT_BASE: u32 = 0;
const SWEEP_SLOT_BASE: u32 = 2_000_000;
const SWEEP_SLOT_STRIDE: u32 = 100_000;

fn env_count(name: &str, default: usize) -> usize {
    env::var(name)
        .ok()
        .and_then(|value| value.trim().parse::<usize>().ok())
        .unwrap_or(default)
}

fn print_mem(label: &str, snap: Option<MemSnapshot>) {
    if let Some(s) = snap {
        println!(
            "    mem {label:<18} rss={:>8.1} MB  hwm={:>8.1} MB",
            s.rss_mb(),
            s.hwm_mb()
        );
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

fn zero_pre_acc() -> ChainAccumulator {
    ChainAccumulator {
        height: 0,
        state_root: [0u8; 32],
        chain_hash: [0u8; 32],
    }
}

fn null_step_header(
    prev_header: &BlockHeader,
    prev_acc: &ChainAccumulator,
    height: u64,
) -> BlockHeader {
    let mut state_root = prev_acc.state_root;
    state_root[..8].copy_from_slice(&height.to_le_bytes());
    BlockHeader {
        prev_block_hash: hash_block_header(prev_header),
        state_root,
        tx_root: [0u8; 32],
        timestamp: prev_header.timestamp + 1,
        height,
        miner_address: Address([0u8; 32]),
        nonce: 0,
        difficulty_target: [0xFFu8; 32],
        // Null/coinbase-only recursive replay witness marker accepted by verifier.
        proof_transcript_hash: [1u8; 32],
        witness_root: [0u8; 32],
        log_slots: BENCH_LOG_SLOTS,
        active_slot_count: 0,
        alloc_counter: 0,
    }
}

fn verify_step(
    proof: &RecursiveBlockProof,
    prev_acc: &ChainAccumulator,
    header: &BlockHeader,
) -> Duration {
    let rec_air = RecursiveBlockAir::from_prev_state_root(&prev_acc.state_root);
    let (verify_time, _) = time_once(|| {
        verify_recursive_step(proof, prev_acc, header, &rec_air)
            .expect("verify recursive benchmark step")
    });
    verify_time
}

fn print_genesis_case() -> RecursiveBlockProof {
    println!("  ---------------------------------------------------------------------");
    println!("  GENESIS RECURSIVE PROOF");
    println!("  ---------------------------------------------------------------------");
    let pre_acc = zero_pre_acc();
    let genesis = genesis_header();
    let before = current_mem_snapshot();
    print_mem("before", before);
    let (prove_time, proof) = time_once(prove_genesis_recursive);
    let verify_time = verify_step(&proof, &pre_acc, &genesis);
    let after = current_mem_snapshot();
    println!("    prove:                  {}", fmt_ms(prove_time));
    println!("    verify:                 {}", fmt_ms(verify_time));
    println!(
        "    recursive proof:        {}",
        fmt_bytes(proof.byte_len())
    );
    print_mem_delta("after", before, after);
    println!();
    proof
}

fn print_null_step_case(
    prev_header: &BlockHeader,
    prev_proof: &RecursiveBlockProof,
) -> RecursiveBlockProof {
    println!("  ---------------------------------------------------------------------");
    println!("  NULL / COINBASE-ONLY RECURSIVE STEP");
    println!("  ---------------------------------------------------------------------");
    let prev_acc = prev_proof.acc.clone();
    let header = null_step_header(prev_header, &prev_acc, prev_acc.height + 1);
    let witness = null_block_replay_witness();
    let before = current_mem_snapshot();
    print_mem("before", before);
    let (prove_time, proof) =
        time_once(|| prove_recursive_step(&witness, &header, &prev_acc, Some(prev_proof)));
    let verify_time = verify_step(&proof, &prev_acc, &header);
    let after = current_mem_snapshot();
    println!("    prove:                  {}", fmt_ms(prove_time));
    println!("    verify:                 {}", fmt_ms(verify_time));
    println!(
        "    recursive proof:        {}",
        fmt_bytes(proof.byte_len())
    );
    print_mem_delta("after", before, after);
    println!();
    proof
}

fn build_standard_fixtures(n: usize) -> Vec<StandardFixture> {
    (0..n)
        .map(|i| {
            standard_fixture(standard_scenario(
                "recursive standard tx",
                4,
                8,
                STANDARD_SLOT_BASE + i as u32 * 10_000,
                0xA1 + i as u128 * 0x100,
            ))
        })
        .collect()
}

fn build_sweep_fixtures(n: usize) -> Vec<SweepFixture> {
    (0..n)
        .map(|i| {
            sweep_fixture(sweep_scenario(
                "recursive sweep tx",
                25,
                SWEEP_SLOT_BASE + i as u32 * SWEEP_SLOT_STRIDE,
                0xB1 + i as u128 * 0x100,
            ))
        })
        .collect()
}

fn print_recursive_block_case(label: &str, r: &RecursiveStepBench) {
    println!("    recursive prove:        {}", fmt_ms(r.prove_time));
    println!("    recursive verify:       {}", fmt_ms(r.verify_time));
    println!("    recursive proof:        {}", fmt_bytes(r.proof_bytes));
    println!(
        "    source block proof:     {}",
        fmt_bytes(r.block_proof_bytes)
    );
    if r.standard_bucket_bytes > 0 {
        println!(
            "      standard bucket:      {}",
            fmt_bytes(r.standard_bucket_bytes)
        );
    }
    if r.sweep_bucket_bytes > 0 {
        println!(
            "      sweep bucket:         {}",
            fmt_bytes(r.sweep_bucket_bytes)
        );
    }
    println!("    label:                  {label}");
}

fn print_standard_block_case(n: usize) {
    if n == 0 {
        println!("  [skip] standard recursive block disabled by NOID_RECURSIVE_STANDARD_TX=0");
        println!();
        return;
    }

    println!("  ---------------------------------------------------------------------");
    println!("  REAL STANDARD BLOCK RECURSIVE STEP: {n} x Standard4x8 4-in/8-out");
    println!("  ---------------------------------------------------------------------");
    eprintln!("  recursive bench: building standard fixtures N={n}...");
    let (fixture_build, fixtures) = time_once(|| build_standard_fixtures(n));
    eprintln!("  recursive bench: proving standard full block N={n}...");
    let before_block = current_mem_snapshot();
    let block = bench_full_block_proof(&fixtures, &[], &[]);
    let after_block = current_mem_snapshot();
    eprintln!("  recursive bench: recursive update over standard full block N={n}...");
    let before_rec = current_mem_snapshot();
    let rec = bench_recursive_step(&block.proof);
    let after_rec = current_mem_snapshot();

    println!("    fixture build:          {}", fmt_ms(fixture_build));
    println!("    block prove:            {}", fmt_ms(block.prove_time));
    println!("    block verify:           {}", fmt_ms(block.verify_time));
    println!(
        "    block proof:            {}",
        fmt_bytes(block.proof_bytes)
    );
    println!(
        "    auth sidecar:           {}",
        fmt_bytes(block.auth_sidecar_bytes)
    );
    println!(
        "      standard bucket:      {}",
        fmt_bytes(block.standard_bucket_bytes)
    );
    println!(
        "      state binding:        {}",
        fmt_bytes(block.state_binding_bytes)
    );
    print_mem_delta("after block", before_block, after_block);
    print_recursive_block_case("standard full block", &rec);
    print_mem_delta("after recursive", before_rec, after_rec);
    println!();
}

fn print_sweep_block_case(n: usize) {
    if n == 0 {
        println!("  [skip] sweep recursive block disabled by NOID_RECURSIVE_SWEEP_TX=0");
        println!();
        return;
    }

    println!("  ---------------------------------------------------------------------");
    println!("  REAL SWEEP BLOCK RECURSIVE STEP: {n} x Sweep25x2 25-in/2-out");
    println!("  ---------------------------------------------------------------------");
    eprintln!("  recursive bench: building sweep fixtures N={n}...");
    let (fixture_build, fixtures) = time_once(|| build_sweep_fixtures(n));
    eprintln!("  recursive bench: pre-proving sweep wallet proofs N={n}...");
    let (wallet_prep, witnesses) = time_once(|| {
        fixtures
            .iter()
            .enumerate()
            .map(|(i, f)| {
                let wallet = prove_sweep_wallet(f, 1);
                owned_sweep_witness(1 + i as u32, f, wallet.proof)
            })
            .collect::<Vec<_>>()
    });
    eprintln!("  recursive bench: proving sweep full block N={n}...");
    let before_block = current_mem_snapshot();
    let block = bench_full_block_proof(&[], &fixtures, &witnesses);
    let after_block = current_mem_snapshot();
    eprintln!("  recursive bench: recursive update over sweep full block N={n}...");
    let before_rec = current_mem_snapshot();
    let rec = bench_recursive_step(&block.proof);
    let after_rec = current_mem_snapshot();

    println!("    fixture build:          {}", fmt_ms(fixture_build));
    println!("    wallet pre-proof:       {}", fmt_ms(wallet_prep));
    println!("    block prove:            {}", fmt_ms(block.prove_time));
    println!("    block verify:           {}", fmt_ms(block.verify_time));
    println!(
        "    block proof:            {}",
        fmt_bytes(block.proof_bytes)
    );
    println!(
        "    auth sidecar:           {}",
        fmt_bytes(block.auth_sidecar_bytes)
    );
    println!(
        "      sweep bucket:         {}",
        fmt_bytes(block.sweep_bucket_bytes)
    );
    println!(
        "      state binding:        {}",
        fmt_bytes(block.state_binding_bytes)
    );
    print_mem_delta("after block", before_block, after_block);
    print_recursive_block_case("sweep full block", &rec);
    print_mem_delta("after recursive", before_rec, after_rec);
    println!();
}

fn main() {
    let n_standard = env_count("NOID_RECURSIVE_STANDARD_TX", DEFAULT_STANDARD_TX);
    let n_sweep = env_count("NOID_RECURSIVE_SWEEP_TX", DEFAULT_SWEEP_TX);

    println!();
    println!("  =====================================================================");
    println!("  PARANOID Recursive Proof Hotspot Benchmark");
    println!("  =====================================================================");
    println!("  Focus: recursive proof prove/verify time, size, and process memory.");
    println!("  Defaults: standard tx={DEFAULT_STANDARD_TX}, sweep tx={DEFAULT_SWEEP_TX}");
    println!("  Reference: standard tx={REFERENCE_STANDARD_TX}, sweep tx={REFERENCE_SWEEP_TX}");
    println!("  Current:  standard tx={n_standard}, sweep tx={n_sweep}");
    println!(
        "  Override: NOID_RECURSIVE_STANDARD_TX=<n> NOID_RECURSIVE_SWEEP_TX=<n> (0 skips a case)"
    );
    println!();

    let genesis = genesis_header();
    let genesis_proof = print_genesis_case();
    let _null_proof = print_null_step_case(&genesis, &genesis_proof);
    print_standard_block_case(n_standard);
    print_sweep_block_case(n_sweep);

    println!("  -------------------------------------------------------------------");
    println!("  NOTES:");
    println!("    - Real block rows use production BlockProof construction first.");
    println!("    - Wallet pre-proof time is separate for sweep rows; recursive rows use the resulting block proof.");
    println!("    - Memory is Linux /proc/self/status RSS/HWM for this bench process.");
    println!("  -------------------------------------------------------------------");
    println!("  Reproduce: cargo bench -p bench_prover --bench recursive_hotspots");
    println!();
}
