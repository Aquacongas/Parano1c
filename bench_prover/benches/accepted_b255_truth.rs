// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Complete consensus-accepted B255 truth fixture.
//!
//! Default mode performs the native production replay and derives every
//! component statement. `NOID_B255_COMPONENT_PROOF=1` additionally crosses
//! the retained m22+ component-prover roofline. Run the two modes in separate
//! fresh processes and wrap them in `/usr/bin/time -v` for authoritative HWM.

use std::time::Instant;

use bench_prover::{
    accepted_b255_proved_truth_fixture, accepted_b255_truth_fixture, fmt_bytes, fmt_ms,
};
use noid_core::mem_profile::current_mem_snapshot;

const SEED: u128 = 0xB255_ACCE_57ED;

fn print_memory() {
    match current_mem_snapshot() {
        Some(memory) => println!(
            "    process RSS/HWM:    {:>8.1} / {:>8.1} MiB",
            memory.rss_mb(),
            memory.hwm_mb()
        ),
        None => println!("    process RSS/HWM:    unavailable"),
    }
}

fn assert_geometry(
    witness: &noid_block::FullAcceptedBlockBatchWitness,
    output: &noid_block::FullAcceptedBlockBatchOutput,
) {
    let block = &witness.items[0].block;
    let resources = noid_chain::consensus::validate_block_resource_preflight(block)
        .expect("B255 truth resource preflight");
    assert_eq!(resources.user_tx_count, 255);
    assert_eq!(resources.live_input_count, 1_020);
    assert_eq!(resources.output_count, 511);
    assert_eq!(resources.action_count, 1_531);
    assert_eq!(resources.touched_slot_count, 1_531);
    assert_eq!(resources.distinct_segment_count, 256);
    assert_eq!(resources.state_frontier_node_count, 20_420);
    assert_eq!(
        output
            .proof_components
            .component_inputs
            .tx_body_inputs
            .len(),
        256
    );
    assert_eq!(
        output
            .proof_components
            .component_inputs
            .authorization_inputs
            .len(),
        255
    );
    assert_eq!(
        output.end_state.cached_state_root(),
        block.header.state_root
    );
}

fn main() {
    let _ = noid_ivc_prover::init_perf_thread_pool();
    let prove_components = std::env::var_os("NOID_B255_COMPONENT_PROOF").is_some();
    println!("PARANOID accepted B255 truth fixture");
    println!("  rayon threads:        {}", rayon::current_num_threads());

    let started = Instant::now();
    if prove_components {
        println!("  mode:                 native replay + retained component proof");
        let fixture = accepted_b255_proved_truth_fixture(SEED);
        let elapsed = started.elapsed();
        assert_geometry(&fixture.witness, &fixture.output);
        println!("    total:              {}", fmt_ms(elapsed));
        println!(
            "    retained proof:     {}",
            fmt_bytes(
                fixture
                    .component_proof
                    .byte_len(&fixture.output.proof_components.component_inputs)
            )
        );
        print_memory();
    } else {
        println!("  mode:                 native replay / statement derivation");
        println!("  opt-in prover:        NOID_B255_COMPONENT_PROOF=1");
        let fixture = accepted_b255_truth_fixture(SEED);
        let elapsed = started.elapsed();
        assert_geometry(&fixture.witness, &fixture.output);
        println!("    total:              {}", fmt_ms(elapsed));
        println!("    frontier siblings:  20,420");
        println!("    exact path carrier: 3,062 paths (transitional; structural cut pending)");
        print_memory();
    }
}
