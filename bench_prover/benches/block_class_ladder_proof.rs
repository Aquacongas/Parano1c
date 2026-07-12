// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Full production BlockClass proof gates for the canonical ladder.
//!
//! Defaults to B64, the first class whose selected V4 children have unequal
//! native walk widths. Select a comma-separated subset with
//! `NOID_BLOCK_CLASS_TIERS=8,32,64,255`. Each class uses its smallest accepted
//! member (1/9/33/65 user transactions); the tier-capacity relation and
//! sidecar geometry are nevertheless the exact production class geometry.

use std::io::Write;
use std::time::{Duration, Instant};

use bench_prover::{
    accepted_proved_user_block_fixture, fmt_bytes, tx8x2_scenario, AcceptedSingleBlockFixture,
};
use noid_core::mem_profile::{current_mem_snapshot, MemSnapshot};
use noid_ivc_prover::challenger::FsLaneChallenger;
use noid_ivc_prover::pcs::{self, PcsParams};
use noid_recursive::acceptance::block_class::{
    build_selected_zk_block_proof_trace, prove_built_block, verify_block_proof, BlockClass,
    BuiltBlock,
};
use noid_recursive::acceptance::link::SelectedZkBlockInput;

const BLOCK_DOMAIN: &[u8] = b"history-block-v0";
const K_SKIP: usize = 6;
const LOG_INV_RATE: usize = 2;
const LOG_BATCH_SIZE: usize = 5;

#[derive(Clone, Copy)]
struct Phase {
    elapsed: Duration,
    memory: Option<MemSnapshot>,
}

fn timed<T>(f: impl FnOnce() -> T) -> (T, Phase) {
    let started = Instant::now();
    let value = f();
    (
        value,
        Phase {
            elapsed: started.elapsed(),
            memory: current_mem_snapshot(),
        },
    )
}

fn print_phase(label: &str, phase: Phase) {
    match phase.memory {
        Some(memory) => println!(
            "    {label:<12} {:>8.3} s  RSS {:>9.1} MiB  HWM {:>9.1} MiB",
            phase.elapsed.as_secs_f64(),
            memory.rss_mb(),
            memory.hwm_mb(),
        ),
        None => println!(
            "    {label:<12} {:>8.3} s  RSS unavailable",
            phase.elapsed.as_secs_f64(),
        ),
    }
}

fn requested_tiers() -> Vec<usize> {
    let raw = std::env::var("NOID_BLOCK_CLASS_TIERS").unwrap_or_else(|_| "64".into());
    let tiers = raw
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(|part| part.parse::<usize>().expect("numeric block tier"))
        .collect::<Vec<_>>();
    assert!(!tiers.is_empty(), "at least one block tier");
    assert!(tiers
        .iter()
        .all(|tier| { noid_chain::consensus::params::USER_TX_CLASS_TIERS.contains(tier) }));
    tiers
}

fn class_m(tier: usize) -> usize {
    match tier {
        8 => 22,
        32 | 64 => 23,
        255 => 24,
        _ => unreachable!("canonical tier"),
    }
}

fn expected_useful_rows(tier: usize) -> usize {
    match tier {
        8 => 814_956,
        32 => 2_476_136,
        64 => 4_015_399,
        255 => 13_058_193,
        _ => unreachable!("canonical tier"),
    }
}

fn tier_floor_user_txs(tier: usize) -> usize {
    match tier {
        8 => 1,
        32 => 9,
        64 => 33,
        255 => 65,
        _ => unreachable!("canonical tier"),
    }
}

fn fixture_for(tier: usize) -> AcceptedSingleBlockFixture {
    let count = tier_floor_user_txs(tier);
    let scenarios = (0..count)
        .map(|index| {
            tx8x2_scenario(
                "block-class-ladder-floor",
                noid_tx::TX_INPUTS,
                noid_tx::TX_OUTPUTS,
                u32::try_from(index * 2_048).expect("fixture slot base"),
                0xB10C_C1A5_0000 + ((tier as u128) << 32) + index as u128,
            )
        })
        .collect();
    let fixture = accepted_proved_user_block_fixture(scenarios);
    assert_eq!(
        noid_chain::consensus::params::user_tx_class_tier(count),
        Some(tier),
    );
    assert_eq!(
        fixture
            .output
            .proof_components
            .component_inputs
            .exact_state_structural_inputs
            .len(),
        1,
    );
    fixture
}

fn freeze_and_build<const TIER: usize>(
    fixture: &AcceptedSingleBlockFixture,
    pcs_params: PcsParams,
) -> (BlockClass, BuiltBlock, Phase, Phase) {
    let freeze_input = SelectedZkBlockInput::<TIER>::try_new(
        &fixture.start_accumulator,
        &fixture.output.accepted_claim_batch.accumulator,
        &fixture.output.proof_components.component_inputs,
        &fixture.component_proof,
        fixture
            .output
            .proof_components
            .selected_authorization_proofs
            .clone(),
        noid_gkr::ghost_tx::prove_selected_ghost_authorization()
            .expect("fresh selected freeze ghost"),
    )
    .expect("canonical selected freeze input");
    let (class, freeze_phase) = timed(|| BlockClass::freeze_selected_zk(pcs_params, freeze_input));
    let build_input = SelectedZkBlockInput::<TIER>::try_new(
        &fixture.start_accumulator,
        &fixture.output.accepted_claim_batch.accumulator,
        &fixture.output.proof_components.component_inputs,
        &fixture.component_proof,
        fixture
            .output
            .proof_components
            .selected_authorization_proofs
            .clone(),
        noid_gkr::ghost_tx::prove_selected_ghost_authorization()
            .expect("fresh selected build ghost"),
    )
    .expect("canonical selected build input");
    let (built, build_phase) = timed(|| build_selected_zk_block_proof_trace(&class, build_input));
    (class, built, freeze_phase, build_phase)
}

fn main() {
    let _ = noid_ivc_prover::init_perf_thread_pool();
    let tiers = requested_tiers();
    println!("PARANOID full BlockClass ladder proof gates {tiers:?}");
    println!("  mandatory selected V4 sidecar; sibling-frontier exact state");
    println!("  rayon threads: {}", rayon::current_num_threads());
    std::io::stdout().flush().expect("flush benchmark heading");

    for tier in tiers {
        let m = class_m(tier);
        let pcs_params = PcsParams {
            m: m + pcs::LOG_PACKING,
            log_inv_rate: LOG_INV_RATE,
            log_batch_size: LOG_BATCH_SIZE,
            profile: Default::default(),
        };

        let (fixture, fixture_phase) = timed(|| fixture_for(tier));
        let (class, built, freeze_phase, build_phase) = match tier {
            8 => freeze_and_build::<8>(&fixture, pcs_params),
            32 => freeze_and_build::<32>(&fixture, pcs_params),
            64 => freeze_and_build::<64>(&fixture, pcs_params),
            255 => freeze_and_build::<255>(&fixture, pcs_params),
            _ => unreachable!("canonical tier"),
        };
        assert_eq!(built.r1cs.m, m);
        assert_eq!(built.r1cs.k_skip, K_SKIP);
        assert_eq!(
            built.r1cs.useful_rows,
            expected_useful_rows(tier),
            "B{tier} selected production row snapshot drift"
        );
        assert!(built.r1cs.useful_rows <= 1usize << m);
        let ((), satisfy_phase) = timed(|| {
            assert!(built.r1cs.satisfies(&built.witness), "B{tier} relation");
        });
        let (envelope, prove_phase) = timed(|| {
            let mut challenger = FsLaneChallenger::new(BLOCK_DOMAIN);
            prove_built_block(&class, &built, &mut challenger)
                .unwrap_or_else(|error| panic!("B{tier} proof failed: {error}"))
        });
        let ((), verify_phase) = timed(|| {
            let mut challenger = FsLaneChallenger::new(BLOCK_DOMAIN);
            verify_block_proof(&class, &built.r1cs, &envelope, &mut challenger)
                .unwrap_or_else(|error| panic!("B{tier} verification failed: {error}"));
        });

        let vk = class.sidecar_vk();
        println!(
            "\n  B{tier} (floor {} user tx, m{m})",
            tier_floor_user_txs(tier)
        );
        println!("    useful rows {:>12}", built.r1cs.useful_rows);
        println!(
            "    walk w_logs WA/MA/WB/MB/OC/MC = {}/{}/{}/{}/{}/{}",
            vk.wallet_a().w_log(),
            vk.meta_a().w_log(),
            vk.wallet_b().w_log(),
            vk.meta_b().w_log(),
            vk.owner_c().w_log(),
            vk.main_c().w_log(),
        );
        println!(
            "    sidecar {:>12}  ({})",
            envelope.region_sidecar().byte_len(),
            fmt_bytes(envelope.region_sidecar().byte_len()),
        );
        println!(
            "    envelope{:>12}  ({})",
            envelope.byte_len(),
            fmt_bytes(envelope.byte_len()),
        );
        print_phase("fixture", fixture_phase);
        print_phase("freeze", freeze_phase);
        print_phase("build", build_phase);
        print_phase("satisfy", satisfy_phase);
        print_phase("prove", prove_phase);
        print_phase("verify", verify_phase);
    }
}
