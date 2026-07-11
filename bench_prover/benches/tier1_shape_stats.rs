// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Current Tx8x2 class ledger.
//!
//! This executable emits only values measured or derived from the current
//! code. It contains no pre-cutover performance golden and freezes nothing.

use bench_prover::{
    bench_full_block_proof_minimal, fmt_bytes, fmt_ms, legal_block_scenarios, minimal_tx_fixture,
    time_once,
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
        let bodies = tier + 1;
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
        let spend_capacity = class.spend_capacity();
        let touched_capacity = class.touched_capacity();
        let action_candidate_capacity = class.action_candidate_capacity();
        let action_sort_capacity = class.action_sort_capacity();
        let frontier_sibling_capacity = class.frontier_sibling_capacity();
        let frontier_combine_capacity = class.frontier_combine_capacity();
        let (fixture_time, fixtures) = time_once(|| {
            legal_block_scenarios("shape-ledger", tier, 0x7100_0000)
                .into_iter()
                .map(minimal_tx_fixture)
                .collect::<Vec<_>>()
        });
        let result = bench_full_block_proof_minimal(&fixtures);
        let frontier_siblings = result.proof.state_transition.slot_siblings.len();
        assert!(frontier_siblings <= frontier_sibling_capacity);
        println!("  B{tier}");
        println!(
            "    shape_digest:      {}",
            hex::encode(class.shape_digest())
        );
        println!("    tx capacity:       {tier}");
        println!("    spend capacity:    {spend_capacity}");
        println!("    auth capacity:     {}", class.authorization_capacity());
        println!("    action candidates: {action_candidate_capacity}");
        println!("    action sort rows:  {action_sort_capacity}");
        println!("    touched capacity:  {touched_capacity}");
        println!("    frontier siblings:{frontier_sibling_capacity:>9}");
        println!("    frontier combines:{frontier_combine_capacity:>9} / root");
        println!("    fixture frontier: {frontier_siblings:>9} siblings");
        println!(
            "    body spine:        {live_spine_slots} live / {spine_slot_domain} slots / m={spine_num_vars}"
        );
        println!(
            "    tx tree:           {} leaves / depth {}",
            noid_chain::tx_tree::TX_TREE_LEAVES,
            noid_chain::tx_tree::TX_TREE_DEPTH
        );
        println!("    fixture build:     {}", fmt_ms(fixture_time));
        println!("    exact-state seed:  {}", fmt_ms(result.state_seed_time));
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
