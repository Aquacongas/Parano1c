// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Full production terminal-sidecar `BlockClass` proof gate for B8.
//!
//! This is deliberately an opt-in `harness = false` executable: run it as
//! `cargo bench -p bench_prover --bench block_class_b8_proof`. It constructs
//! the complete production region stack, freezes its exact six-child sidecar
//! VK, proves the resulting class instance with fixed 20-lane public IO, and
//! verifies the mandatory Field+sidecar envelope.
//!
//! The structural exact-state region is the production path. The retained
//! component fixture still carries small transitional Merkle-path proofs, so
//! this gate clears those proofs before class freeze/build and thereby ensures
//! the outer proof cannot fall back to them.
//!
//! The selected-ZK terminal-sidecar cut leaves an 814,956-row natural m20
//! relation while the published B8 ladder slot remains frozen at m22. The matrix/witness
//! suffix is genuinely empty zero padding (not identity rows), and
//! `useful_rows` records the raw relation size so the padded proof kernels can
//! skip it. Any growth beyond the frozen m22 class remains a gate failure,
//! never an implicit shape upgrade.

use std::io::Write;
use std::time::{Duration, Instant};

use bench_prover::{accepted_single_user_fixture, fmt_bytes};
use noid_core::mem_profile::{current_mem_snapshot, MemSnapshot};
use noid_ivc_prover::challenger::FsLaneChallenger;
use noid_ivc_prover::pcs::{self, PcsParams};
use noid_recursive::acceptance::block_class::{
    build_selected_zk_b8_block_proof_trace, prove_built_block, verify_block_proof, BlockClass,
    BlockProofEnvelope, BlockProofError, BuiltBlock, BLOCK_IO_LEN,
};
use noid_recursive::acceptance::link::SelectedZkB8BlockInput;

const DOMAIN: &[u8] = b"history-block-v0";
const SEED: u128 = 0xB8_B10C_C1A5_5001;
const TIER: usize = 8;
const CLASS_M: usize = 22;
const EXPECTED_USEFUL_ROWS: usize = 814_956;
const K_SKIP: usize = 6;
const LOG_INV_RATE: usize = 2;
const LOG_BATCH_SIZE: usize = 5;

#[derive(Clone, Copy)]
struct Phase {
    elapsed: Duration,
    memory: Option<MemSnapshot>,
}

fn finish_phase(started: Instant) -> Phase {
    Phase {
        elapsed: started.elapsed(),
        memory: current_mem_snapshot(),
    }
}

fn print_phase(label: &str, phase: Phase) {
    match phase.memory {
        Some(memory) => println!(
            "  {label:<18} {:>9.3} s  RSS {:>9.1} MiB  HWM {:>9.1} MiB",
            phase.elapsed.as_secs_f64(),
            memory.rss_mb(),
            memory.hwm_mb(),
        ),
        None => println!(
            "  {label:<18} {:>9.3} s  RSS unavailable",
            phase.elapsed.as_secs_f64(),
        ),
    }
}

fn main() {
    let _ = noid_ivc_prover::init_perf_thread_pool();
    println!("PARANOID B8 full BlockClass public-IO proof gate");
    println!("  production region stack; structural exact state; no legacy path proofs");
    println!("  rayon threads:       {}", rayon::current_num_threads());
    std::io::stdout().flush().expect("flush benchmark heading");

    let fixture_started = Instant::now();
    let mut fixture = accepted_single_user_fixture(SEED);
    assert_eq!(fixture.component_proof.exact_state.len(), 1);
    for exact_state in &mut fixture.component_proof.exact_state {
        exact_state.state_paths.clear();
    }
    assert!(
        fixture
            .component_proof
            .exact_state
            .iter()
            .all(|proof| proof.state_paths.is_empty()),
        "the production class gate must not carry legacy exact-state path proofs"
    );
    assert_eq!(
        noid_chain::consensus::params::user_tx_class_tier(1)
            .expect("one user transaction has a consensus class"),
        TIER,
        "the fixture must freeze the B8 class"
    );
    let fixture_phase = finish_phase(fixture_started);

    let freeze_live = fixture
        .output
        .proof_components
        .selected_authorization_proofs
        .clone();
    let build_live = fixture
        .output
        .proof_components
        .selected_authorization_proofs
        .clone();
    let freeze_ghost = noid_gkr::ghost_tx::prove_selected_ghost_authorization()
        .expect("fresh selected freeze ghost");
    let build_ghost = noid_gkr::ghost_tx::prove_selected_ghost_authorization()
        .expect("fresh selected build ghost");
    let freeze_input = SelectedZkB8BlockInput::try_new(
        &fixture.start_accumulator,
        &fixture.output.accepted_claim_batch.accumulator,
        &fixture.output.proof_components.component_inputs,
        &fixture.component_proof,
        freeze_live,
        freeze_ghost,
    )
    .expect("canonical selected B8 freeze input");
    let pcs_params = PcsParams {
        m: CLASS_M + pcs::LOG_PACKING,
        log_inv_rate: LOG_INV_RATE,
        log_batch_size: LOG_BATCH_SIZE,
        profile: Default::default(),
    };

    let freeze_started = Instant::now();
    let mut class = BlockClass::freeze_selected_zk_b8(pcs_params, freeze_input);
    let freeze_phase = finish_phase(freeze_started);
    assert_eq!(class.shape.m, CLASS_M);
    assert_eq!(class.pcs_params.m, CLASS_M + pcs::LOG_PACKING);
    assert_eq!(class.spec.io_len, BLOCK_IO_LEN);
    assert!(class.spec.claims.is_empty());

    let build_input = SelectedZkB8BlockInput::try_new(
        &fixture.start_accumulator,
        &fixture.output.accepted_claim_batch.accumulator,
        &fixture.output.proof_components.component_inputs,
        &fixture.component_proof,
        build_live,
        build_ghost,
    )
    .expect("canonical selected B8 build input");
    let build_started = Instant::now();
    let built = build_selected_zk_b8_block_proof_trace(&class, build_input);
    let build_phase = finish_phase(build_started);
    assert_block_shape(&built, &class);

    let satisfy_started = Instant::now();
    assert!(
        built.r1cs.satisfies(&built.witness),
        "full B8 BlockClass trace must satisfy its frozen matrix"
    );
    let satisfy_phase = finish_phase(satisfy_started);

    std::io::stdout().flush().expect("flush build summary");
    let prove_started = Instant::now();
    let mut prover_challenger = FsLaneChallenger::new(DOMAIN);
    let proof = prove_built_block(&class, &built, &mut prover_challenger)
        .expect("complete B8 Field+sidecar proof");
    let prove_phase = finish_phase(prove_started);
    let proof_bytes = proof.byte_len();
    let sidecar_bytes = proof.region_sidecar().byte_len();

    let verify_started = Instant::now();
    let mut verifier_challenger = FsLaneChallenger::new(DOMAIN);
    verify_block_proof(&class, &built.r1cs, &proof, &mut verifier_challenger)
        .expect("full B8 BlockClass envelope verifies with its frozen sidecar VK");
    let verify_phase = finish_phase(verify_started);

    // A core-only wire object cannot decode as the production envelope: the
    // fourth, mandatory sidecar field is absent.
    let core_only = bincode::serialize(&(proof.field_proof(), proof.commitment(), proof.io()))
        .expect("serialize core-only downgrade attempt");
    assert!(
        bincode::deserialize::<BlockProofEnvelope>(&core_only).is_err(),
        "core-only Field proof must not decode as a production block proof"
    );

    // The post-commit class digest freezes the exact IO spec as well as the
    // matrix, PCS profile, and sidecar VK.
    class.spec.io_len += 1;
    let mut mutated_class_challenger = FsLaneChallenger::new(DOMAIN);
    assert_eq!(
        verify_block_proof(&class, &built.r1cs, &proof, &mut mutated_class_challenger,)
            .unwrap_err(),
        BlockProofError::ClassIdentityMismatch
    );
    class.spec.io_len -= 1;

    println!("\nproduction proof-gate result:");
    println!("  useful rows        {:>12}", built.r1cs.useful_rows);
    println!("  class m            {:>12}", built.r1cs.m);
    println!("  PCS m              {:>12}", class.pcs_params.m);
    println!("  public IO lanes    {:>12}", class.spec.io_len);
    println!(
        "  sidecar bytes      {:>12}  ({})",
        sidecar_bytes,
        fmt_bytes(sidecar_bytes)
    );
    println!(
        "  envelope bytes     {:>12}  ({})",
        proof_bytes,
        fmt_bytes(proof_bytes)
    );
    println!("\nphase timings and process memory snapshots:");
    print_phase("fixture", fixture_phase);
    print_phase("freeze", freeze_phase);
    print_phase("build", build_phase);
    print_phase("satisfy", satisfy_phase);
    print_phase("prove", prove_phase);
    print_phase("verify", verify_phase);
}

fn assert_block_shape(built: &BuiltBlock, class: &BlockClass) {
    assert_eq!(built.r1cs.m, CLASS_M, "B8 class must remain at m22");
    assert_eq!(built.r1cs.k_log, CLASS_M);
    assert_eq!(built.r1cs.k_skip, K_SKIP);
    assert_eq!(built.r1cs.const_pin, Some(0));
    assert_eq!(built.witness.len(), 1usize << CLASS_M);
    assert_eq!(built.io.len(), class.spec.io_len);
    assert_eq!(
        built.r1cs.useful_rows, EXPECTED_USEFUL_ROWS,
        "B8 terminal relation row snapshot drift"
    );
    assert!(
        built.r1cs.useful_rows <= 1usize << CLASS_M,
        "B8 production trace outgrew m22"
    );
    assert!(
        built.r1cs.useful_rows > 1usize << (CLASS_M - 3),
        "m19 now suffices; re-audit the frozen B8 ladder slot"
    );
    assert!(
        built.r1cs.useful_rows <= 1usize << (CLASS_M - 2),
        "terminal B8 relation no longer fits its audited natural m20 geometry"
    );
}
