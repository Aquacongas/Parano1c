// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Minimal production block-proof scaling over the B8/B32/B64/B255 ladder.

use bench_prover::{
    bench_full_block_proof_minimal, fmt_bytes, fmt_ms, minimal_tx_fixture, tx8x2_scenario,
    MinimalTxFixture,
};
use noid_chain::consensus::params::USER_TX_CLASS_TIERS;

fn requested_tiers() -> Vec<usize> {
    let raw = std::env::var("NOID_BLOCK_TIERS").unwrap_or_else(|_| "8".into());
    let tiers: Vec<usize> = raw
        .split(',')
        .filter_map(|part| part.trim().parse().ok())
        .collect();
    assert!(!tiers.is_empty(), "NOID_BLOCK_TIERS must contain a tier");
    for tier in &tiers {
        assert!(
            USER_TX_CLASS_TIERS.contains(tier),
            "unsupported tier B{tier}; use 8,32,64,255"
        );
    }
    tiers
}

fn fixtures(tier: usize) -> Vec<MinimalTxFixture> {
    (0..tier)
        .map(|index| {
            let slot_base = (index * 2_048) as u32;
            minimal_tx_fixture(tx8x2_scenario(
                "block-user-tx",
                8,
                2,
                slot_base,
                0xB10C_0000 + index as u128,
            ))
        })
        .collect()
}

fn main() {
    let _ = noid_ivc_prover::init_perf_thread_pool();
    let tiers = requested_tiers();
    println!("PARANOID block scaling — canonical Tx8x2 classes {tiers:?}");
    println!("Set NOID_BLOCK_TIERS=8,32,64,255 for the full ladder.");
    println!("No stale performance golden is enforced; remeasure on this harness.\n");

    for tier in tiers {
        let bodies = tier + 1; // mandatory coinbase + real user bodies
        let live_spine_slots = bodies * noid_gkr::N_SPINE_SLOTS;
        let spine_slot_domain = live_spine_slots.next_power_of_two();
        let spine_num_vars = noid_gkr::block_spine::num_vars_for(live_spine_slots);
        let expected = match tier {
            8 => (279, 512, 18),
            32 => (1_023, 1_024, 19),
            64 => (2_015, 2_048, 20),
            255 => (7_936, 8_192, 22),
            _ => unreachable!("tier filtered above"),
        };
        assert_eq!(
            (live_spine_slots, spine_slot_domain, spine_num_vars),
            expected,
            "B{tier} body-spine geometry drift"
        );
        eprintln!("building B{tier} fixed-owner fixtures...");
        let fixtures = fixtures(tier);
        eprintln!("proving B{tier} minimal block...");
        let result = bench_full_block_proof_minimal(&fixtures);
        println!("  B{tier} ({tier} user tx + coinbase)");
        println!(
            "    body spine:        {live_spine_slots} live / {spine_slot_domain} slots / m={spine_num_vars}"
        );
        println!("    prove:             {}", fmt_ms(result.prove_time));
        println!("    verify:            {}", fmt_ms(result.verify_time));
        println!("    block proof:       {}", fmt_bytes(result.proof_bytes));
        println!(
            "    auth sidecar:      {}",
            fmt_bytes(result.auth_sidecar_bytes)
        );
        println!(
            "    exact transition: {}",
            fmt_bytes(result.state_transition_bytes)
        );
    }
}
