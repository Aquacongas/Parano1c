// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Current Tx8x2 class ledger.
//!
//! This executable emits only values measured or derived from the current
//! code. It contains no pre-cutover performance golden and freezes nothing.

use bench_prover::{
    bench_full_block_proof_minimal, fmt_bytes, fmt_ms, minimal_tx_fixture, time_once,
    tx8x2_scenario,
};
use noid_chain::consensus::params::USER_TX_CLASS_TIERS;
use noid_recursive::acceptance::shape::ShapeClass;

fn requested_tiers() -> Vec<usize> {
    let raw = std::env::var("NOID_SHAPE_TIERS").unwrap_or_else(|_| "8".into());
    let tiers: Vec<_> = raw
        .split(',')
        .filter_map(|part| part.trim().parse().ok())
        .collect();
    assert!(!tiers.is_empty());
    assert!(tiers.iter().all(|tier| USER_TX_CLASS_TIERS.contains(tier)));
    tiers
}

fn main() {
    let _ = noid_ivc_prover::init_perf_thread_pool();
    let tiers = requested_tiers();
    println!("PARANOID Tx8x2 current class ledger");
    println!("Run NOID_SHAPE_TIERS=8,32,64,255 for a full remeasurement.");
    println!("Measurements below are run-local and are not protocol constants.\n");

    for tier in tiers {
        let class = ShapeClass { tier };
        let spend_capacity = class.spend_capacity();
        let touched_capacity = class.touched_capacity();
        let (fixture_time, fixtures) = time_once(|| {
            (0..tier)
                .map(|index| {
                    minimal_tx_fixture(tx8x2_scenario(
                        "shape-ledger",
                        noid_tx::TX_INPUTS,
                        noid_tx::TX_OUTPUTS,
                        (index * 2_048) as u32,
                        0x7100_0000 + index as u128,
                    ))
                })
                .collect::<Vec<_>>()
        });
        let result = bench_full_block_proof_minimal(&fixtures);
        println!("  B{tier}");
        println!(
            "    shape_digest:      {}",
            hex::encode(class.shape_digest())
        );
        println!("    tx capacity:       {tier}");
        println!("    spend capacity:    {spend_capacity}");
        println!("    auth capacity:     {}", class.authorization_capacity());
        println!("    touched capacity:  {touched_capacity}");
        println!(
            "    tx tree:           {} leaves / depth {}",
            noid_chain::tx_tree::TX_TREE_LEAVES,
            noid_chain::tx_tree::TX_TREE_DEPTH
        );
        println!("    fixture build:     {}", fmt_ms(fixture_time));
        println!("    block prove:       {}", fmt_ms(result.prove_time));
        println!("    block verify:      {}", fmt_ms(result.verify_time));
        println!("    block proof:       {}", fmt_bytes(result.proof_bytes));
        println!(
            "    auth sidecar:      {}",
            fmt_bytes(result.auth_sidecar_bytes)
        );
        println!(
            "    state transition: {}",
            fmt_bytes(result.state_transition_bytes)
        );
    }
}
