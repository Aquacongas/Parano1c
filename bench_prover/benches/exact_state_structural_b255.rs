// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Isolated retained structural exact-state roofline on the production B255
//! truth fixture.  Native block acceptance/fixture construction is reported
//! separately and excluded from the prove/verify timers.

use std::io::Write;
use std::time::Instant;

use bench_prover::accepted_b255_truth_fixture;
use noid_core::mem_profile::current_mem_snapshot;

fn main() {
    println!("PARANOID B255 retained structural exact-state roofline");
    println!("building native accepted truth fixture (excluded) ...");
    std::io::stdout().flush().expect("flush benchmark heading");

    let fixture_started = Instant::now();
    let fixture = accepted_b255_truth_fixture(0xB255_ACCE_57ED);
    let fixture_time = fixture_started.elapsed();
    let inputs = &fixture.output.proof_components.component_inputs;
    assert_eq!(inputs.exact_state_structural_inputs.len(), 1);
    let structural = &inputs.exact_state_structural_inputs[0];
    let plan = noid_chain::sparse_merkle::derive_structural_frontier_plan(
        &structural.touched_indices,
        structural.active_depth,
    )
    .expect("truth fixture structural plan");

    println!(
        "fixture/native replay:   {:>10.3} s",
        fixture_time.as_secs_f64()
    );
    println!(
        "touched slots:           {:>10}",
        structural.touched_indices.len()
    );
    println!(
        "live siblings:          {:>10}",
        structural.live_sibling_digests.len()
    );
    println!("combines/root:          {:>10}", plan.combines().len());
    std::io::stdout().flush().expect("flush fixture summary");

    let audit_started = Instant::now();
    noid_recursive::block_certificate_backend::verify_exact_state_structural_frontier(structural)
        .expect("independent native structural audit");
    let audit_time = audit_started.elapsed();

    let before = current_mem_snapshot();
    let prove_started = Instant::now();
    let proof = noid_block::prove_exact_state_structural_killshot(structural)
        .expect("prove structural exact state");
    let prove_time = prove_started.elapsed();
    let after_prove = current_mem_snapshot();

    let verify_started = Instant::now();
    noid_block::verify_exact_state_structural_killshot(structural, &proof)
        .expect("verify structural exact state");
    let verify_time = verify_started.elapsed();
    let proof_bytes = bincode::serialized_size(&proof).expect("serialized proof size") as usize;

    println!("\nretained component:");
    println!(
        "  structural chunks      {:>10}",
        proof.structural_hashes.len()
    );
    println!(
        "  independent DAG audit  {:>10.3} s",
        audit_time.as_secs_f64()
    );
    println!(
        "  prove                  {:>10.3} s",
        prove_time.as_secs_f64()
    );
    println!(
        "  verify                 {:>10.3} s",
        verify_time.as_secs_f64()
    );
    println!(
        "  serialized proof       {:>10.2} KiB",
        proof_bytes as f64 / 1024.0
    );
    if let (Some(before), Some(after)) = (before, after_prove) {
        println!(
            "  current RSS delta       {:>10.1} MiB",
            after.delta_rss_mb(before)
        );
        println!("  current RSS after       {:>10.1} MiB", after.rss_mb());
    }
}
