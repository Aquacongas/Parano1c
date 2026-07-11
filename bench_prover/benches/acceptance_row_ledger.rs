// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Accepted-block `block_slots` row-ledger diagnostic.
//!
//! The default is a B1, content-shaped smoke fixture. Set `NOID_ROW_B255=1`
//! for the real B255 class ledger; that mode first crosses the retained m22+
//! component-prover roofline and then assembles the full region-backed tier.
//!
//! The retained component proof is generated before the assembly timer and
//! before the RSS baseline. Set `NOID_ROW_SATISFY=1` to additionally scan the
//! assembled matrices against the witness.

use std::io::Write;
use std::time::Instant;

use bench_prover::{
    accepted_b255_proved_truth_fixture, accepted_single_user_fixture, AcceptedSingleBlockFixture,
};
use noid_core::mem_profile::{current_mem_snapshot, MemSnapshot};
use noid_recursive::acceptance::block_slots::{build_block_slots_with_config, BlockSlotsConfig};
use noid_recursive::acceptance::trace::FieldR1csBuilder;

fn print_rss(label: &str, snapshot: Option<MemSnapshot>) {
    match snapshot {
        Some(snapshot) => println!("  {label:<22} {:>10.1} MiB", snapshot.rss_mb()),
        None => println!("  {label:<22} unavailable"),
    }
}

fn main() {
    let b255 = std::env::var_os("NOID_ROW_B255").is_some();
    println!("PARANOID accepted block_slots row ledger");
    println!(
        "fixture: {}",
        if b255 {
            "B255 full region-backed class gate"
        } else {
            "B1 content-shaped diagnostic (set NOID_ROW_B255=1 for the class gate)"
        }
    );
    println!("generating retained component proof outside measured assembly ...");
    std::io::stdout().flush().expect("flush benchmark heading");

    let fixture_started = Instant::now();
    let fixture = if b255 {
        accepted_b255_proved_truth_fixture(0xB255_ACCE_57ED)
    } else {
        accepted_single_user_fixture(0xACCE_57ED)
    };
    let fixture_time = fixture_started.elapsed();

    // Drop the consensus/state seed objects before taking the assembly RSS
    // baseline. Only the production component statement, retained proof and
    // accumulator boundary remain live for `block_slots`.
    let AcceptedSingleBlockFixture {
        start_accumulator,
        output,
        component_proof,
        ..
    } = fixture;
    let noid_block::FullAcceptedBlockBatchOutput {
        accepted_claim_batch,
        proof_components,
        ..
    } = output;
    let end_accumulator = accepted_claim_batch.accumulator;
    let inputs = proof_components.component_inputs;

    println!(
        "fixture/proof setup:    {:>10.3} s  (excluded)",
        fixture_time.as_secs_f64()
    );
    println!("component ledger (FieldR1cs rows):");
    std::io::stdout().flush().expect("flush fixture timing");

    // `row_ledger_mark` is intentionally env-gated in library code. This
    // diagnostic always enables it; each materialized wire is exactly one
    // FieldR1cs constraint row.
    std::env::set_var("NOID_ROW_LEDGER", "1");
    let before = current_mem_snapshot();
    let mut builder = FieldR1csBuilder::new();
    let mut config = BlockSlotsConfig::default();
    if b255 {
        config.owner_auth_region = true;
        config.exact_state_region = true;
        config.tx_root_region = true;
        config.spine_region = true;
        config.tier_user_tx_capacity = Some(255);
    }
    let assembly_started = Instant::now();
    let slots = build_block_slots_with_config(
        &mut builder,
        &start_accumulator,
        &end_accumulator,
        &inputs,
        &component_proof,
        config,
    );
    let assembly_time = assembly_started.elapsed();
    let after_assembly = current_mem_snapshot();
    let builder_rows = builder.num_wires();

    assert_eq!(
        slots.compacted_actions.source_rows,
        if b255 { 2_551 } else { 11 }
    );
    assert_eq!(
        slots.compacted_actions.rows.len(),
        if b255 { 1_531 } else { 11 }
    );

    let build_started = Instant::now();
    let (r1cs, witness) = builder.build();
    let build_time = build_started.elapsed();
    let after_build = current_mem_snapshot();

    let satisfy = std::env::var_os("NOID_ROW_SATISFY").is_some();
    let satisfy_time = satisfy.then(|| {
        let started = Instant::now();
        assert!(r1cs.satisfies(&witness));
        started.elapsed()
    });

    println!("\nassembly summary (proof setup excluded):");
    println!("  builder rows          {builder_rows:>10}");
    println!("  useful R1CS rows      {:>10}", r1cs.useful_rows);
    println!("  padded m              {:>10}", r1cs.m);
    println!(
        "  slot assembly         {:>10.3} s",
        assembly_time.as_secs_f64()
    );
    println!(
        "  matrix build          {:>10.3} s",
        build_time.as_secs_f64()
    );
    match satisfy_time {
        Some(elapsed) => println!("  satisfy scan          {:>10.3} s", elapsed.as_secs_f64()),
        None => println!("  satisfy scan             skipped (set NOID_ROW_SATISFY=1)"),
    }

    println!("\ncurrent RSS (VmRSS; VmHWM intentionally omitted):");
    print_rss("assembly baseline", before);
    print_rss("after slot assembly", after_assembly);
    print_rss("after matrix build", after_build);
    if let (Some(before), Some(after)) = (before, after_assembly) {
        println!(
            "  {:<22} {:>10.1} MiB",
            "assembly RSS delta",
            after.delta_rss_mb(before)
        );
    }
    if let (Some(before), Some(after)) = (before, after_build) {
        println!(
            "  {:<22} {:>10.1} MiB",
            "total RSS delta",
            after.delta_rss_mb(before)
        );
    }
    println!(
        "  note: VmHWM includes the excluded retained-proof setup, so this bench does not report it"
    );
}
