// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Exact opt-in measurement of the selected-ZK replacement in the canonical
//! B255 Block relation.  Proof/fixture setup is deliberately outside both the
//! assembly timer and its RSS baseline.

use std::time::Instant;

use bench_prover::{
    accepted_proved_user_block_fixture, fmt_ms, tx8x2_scenario, AcceptedSingleBlockFixture,
    BenchScenario,
};
use noid_core::mem_profile::{current_mem_snapshot, MemSnapshot};
use noid_gkr::zk_auth_capsule::ZkAuthCapsuleStateTable;
use noid_gkr::zk_authorization::{
    prove_zk_authorization_from_state, ZkAuthCapsuleOwnerStatement, ZkAuthorizationProof,
};
use noid_gkr::{evaluate_permutation, owner_auth_public_from_body};
use noid_poseidon2b::{capacity_iv, derive_address, SpendSecret, TAG_ADDRFIX};
use noid_recursive::acceptance::block_class::{
    build_selected_zk_b255_measurement_full, build_selected_zk_b255_measurement_witness_only,
};
use noid_recursive::acceptance::link::SelectedZkB255MeasurementInput;
use noid_recursive::block_certificate_backend::{
    AcceptedBlockBatchComponentInputs, AcceptedBlockBatchComponentProof,
};
use noid_recursive::ChainAccumulator;
use noid_tx::{TxBody, TX_INPUTS, TX_OUTPUTS};
use rayon::prelude::*;

const DEFAULT_LIVE: usize = 65;
const B255_TIER: usize = 255;
const EXPECTED_USEFUL_ROWS: usize = 13_058_193;
const SEED: u128 = 0xB255_5E1E_C7ED;

fn scenarios(live: usize, seed: u128) -> Vec<BenchScenario> {
    assert!(
        (DEFAULT_LIVE..=B255_TIER).contains(&live),
        "selected measurement needs 65..=255 live users"
    );
    assert_eq!(
        noid_chain::consensus::params::user_tx_class_tier(live),
        Some(B255_TIER),
        "measurement fixture must select the B255 class"
    );
    (0..live)
        .map(|index| {
            tx8x2_scenario(
                "selected-zk-b255",
                TX_INPUTS,
                TX_OUTPUTS,
                (index * 2_048) as u32,
                seed + index as u128,
            )
        })
        .collect()
}

struct PreparedSelectedFixture {
    start_accumulator: ChainAccumulator,
    end_accumulator: ChainAccumulator,
    inputs: AcceptedBlockBatchComponentInputs,
    component_proof: AcceptedBlockBatchComponentProof,
    live_proofs: Vec<ZkAuthorizationProof>,
    ghost_proof: Option<ZkAuthorizationProof>,
}

impl PreparedSelectedFixture {
    fn measurement_input(
        &self,
        live_proofs: Vec<ZkAuthorizationProof>,
        ghost_proof: ZkAuthorizationProof,
    ) -> SelectedZkB255MeasurementInput<'_> {
        SelectedZkB255MeasurementInput::try_new(
            &self.start_accumulator,
            &self.end_accumulator,
            &self.inputs,
            &self.component_proof,
            live_proofs,
            ghost_proof,
        )
        .expect("canonical selected B255 measurement carrier")
    }

    fn take_proofs(&mut self) -> (Vec<ZkAuthorizationProof>, ZkAuthorizationProof) {
        (
            std::mem::take(&mut self.live_proofs),
            self.ghost_proof
                .take()
                .expect("selected ghost proof consumed once"),
        )
    }
}

fn prove_selected_authorization(body: &TxBody, secret: &SpendSecret) -> ZkAuthorizationProof {
    let public = owner_auth_public_from_body(body).expect("canonical selected owner statement");
    assert_eq!(
        public.expected_address,
        derive_address(secret).as_fields(),
        "selected proof authority does not own the canonical body"
    );
    let [secret_hi, secret_lo] = secret.as_fields();
    let [iv_hi, iv_lo] = capacity_iv(TAG_ADDRFIX);
    let permutation = evaluate_permutation([secret_hi, secret_lo, iv_hi, iv_lo]);
    assert_eq!(
        [permutation.final_state()[0], permutation.final_state()[1]],
        public.expected_address,
        "address permutation drift"
    );
    let state = ZkAuthCapsuleStateTable::from_permutation_witness(&permutation)
        .expect("selected authorization state table");
    let statement = ZkAuthCapsuleOwnerStatement {
        tx_body_hash: public.tx_body_hash,
        address: public.expected_address,
    };
    prove_zk_authorization_from_state(state.cells(), statement)
        .expect("selected authorization proof")
}

fn print_rss(label: &str, snapshot: Option<MemSnapshot>) {
    match snapshot {
        Some(snapshot) => println!("  {label:<28} {:>10.1} MiB", snapshot.rss_mb()),
        None => println!("  {label:<28} unavailable"),
    }
}

fn prepare_selected_fixture(live: usize, seed: u128) -> PreparedSelectedFixture {
    let mut scenarios = scenarios(live, seed);
    let secrets = scenarios
        .iter()
        .map(|scenario| scenario.spend_secret.clone())
        .collect::<Vec<_>>();
    let mut fixture = accepted_proved_user_block_fixture(scenarios.clone());
    for exact_state in &mut fixture.component_proof.exact_state {
        exact_state.state_paths.clear();
    }

    // The accepted fixture canonicalizes epoch/fee/output amounts.  Replace
    // the pre-canonical bodies before deriving ZK statements while retaining
    // their wallet-local spend authorities in exactly the same order.
    let canonical_users = &fixture.witness.items[0].block.transactions[1..];
    assert_eq!(canonical_users.len(), scenarios.len());
    for (scenario, transaction) in scenarios.iter_mut().zip(canonical_users) {
        scenario.body = transaction.body.clone();
    }
    let live_proofs = scenarios
        .par_iter()
        .zip(secrets.par_iter())
        .map(|(scenario, secret)| prove_selected_authorization(&scenario.body, secret))
        .collect::<Vec<_>>();
    let ghost_body = noid_gkr::ghost_tx::ghost_tx_body();
    let ghost_secret = noid_gkr::ghost_tx::ghost_spend_secret();
    let ghost_proof = prove_selected_authorization(&ghost_body, &ghost_secret);

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
    PreparedSelectedFixture {
        start_accumulator,
        end_accumulator: accepted_claim_batch.accumulator,
        inputs: proof_components.component_inputs,
        component_proof,
        live_proofs,
        ghost_proof: Some(ghost_proof),
    }
}

fn main() {
    let _ = noid_ivc_prover::init_perf_thread_pool();
    let live = std::env::var("NOID_SELECTED_ZK_LIVE")
        .ok()
        .and_then(|raw| raw.parse().ok())
        .unwrap_or(DEFAULT_LIVE);
    let witness_live = std::env::var("NOID_SELECTED_ZK_WITNESS_LIVE")
        .ok()
        .and_then(|raw| raw.parse().ok())
        .unwrap_or(live);
    println!("PARANOID selected-ZK canonical B255 Block measurement");
    println!("  live users:                 {live} (fixed B255/256 authorization geometry)");
    println!("  witness-only users:         {witness_live}");
    println!("  proof and retained-component setup is excluded from assembly timing/RSS");

    let setup_started = Instant::now();
    let mut full_fixture = prepare_selected_fixture(live, SEED);
    let mut distinct_witness_fixture = (witness_live != live)
        .then(|| prepare_selected_fixture(witness_live, SEED ^ 0xC1A5_5F1E_17A5_0000));
    let setup_time = setup_started.elapsed();
    let second_full_proofs = std::env::var_os("NOID_SELECTED_ZK_SECOND_FULL").map(|_| {
        let fixture = distinct_witness_fixture.as_ref().unwrap_or(&full_fixture);
        (
            fixture.live_proofs.clone(),
            fixture
                .ghost_proof
                .as_ref()
                .expect("second-full ghost proof exists")
                .clone(),
        )
    });

    let (witness_only_live, witness_only_ghost) = match distinct_witness_fixture.as_mut() {
        Some(fixture) => fixture.take_proofs(),
        None => (
            full_fixture.live_proofs.clone(),
            full_fixture
                .ghost_proof
                .as_ref()
                .expect("full ghost proof exists")
                .clone(),
        ),
    };
    let (live_proofs, ghost_proof) = full_fixture.take_proofs();
    let full_input = full_fixture.measurement_input(live_proofs, ghost_proof);
    let witness_input = distinct_witness_fixture
        .as_ref()
        .unwrap_or(&full_fixture)
        .measurement_input(witness_only_live, witness_only_ghost);
    let second_full_input = second_full_proofs.map(|(live_proofs, ghost_proof)| {
        distinct_witness_fixture
            .as_ref()
            .unwrap_or(&full_fixture)
            .measurement_input(live_proofs, ghost_proof)
    });

    println!("  excluded setup:              {}", fmt_ms(setup_time));
    let before = current_mem_snapshot();
    let full_started = Instant::now();
    let full = build_selected_zk_b255_measurement_full(full_input);
    let full_time = full_started.elapsed();
    let after_full = current_mem_snapshot();
    assert_eq!(full.r1cs().useful_rows, EXPECTED_USEFUL_ROWS);
    assert_eq!(full.r1cs().m, 24);
    assert_eq!(full.witness().len(), 1 << 24);
    assert_eq!(full.region_vk().version(), 4);

    let witness_only_started = Instant::now();
    let witness_only = build_selected_zk_b255_measurement_witness_only(witness_input, &full);
    let witness_only_time = witness_only_started.elapsed();
    let after_witness_only = current_mem_snapshot();
    assert_eq!(witness_only.useful_rows(), EXPECTED_USEFUL_ROWS);
    if witness_live == live {
        assert_eq!(witness_only.witness(), full.witness());
    } else {
        assert_ne!(
            witness_only.io(),
            full.io(),
            "distinct Block IO unexpectedly equal"
        );
    }
    assert_eq!(witness_only.region_vk(), full.region_vk());

    let satisfy_time = std::env::var_os("NOID_ROW_SATISFY").map(|_| {
        let started = Instant::now();
        assert!(full.r1cs().satisfies(witness_only.witness()));
        started.elapsed()
    });
    let second_full = second_full_input.map(|input| {
        let started = Instant::now();
        let replay = build_selected_zk_b255_measurement_full(input);
        let elapsed = started.elapsed();
        assert!(
            full.has_identical_relation(&replay),
            "cross-content full selected B255 relation drift"
        );
        assert_eq!(replay.region_vk(), full.region_vk());
        assert_eq!(replay.r1cs().useful_rows, EXPECTED_USEFUL_ROWS);
        (elapsed, current_mem_snapshot())
    });

    println!("\nexact selected replacement:");
    println!(
        "  useful rows:                {:>10}",
        full.r1cs().useful_rows
    );
    println!("  padded class:               m={}", full.r1cs().m);
    println!("  full matrix assembly:        {}", fmt_ms(full_time));
    println!(
        "  witness-only rebuild:        {}",
        fmt_ms(witness_only_time)
    );
    match satisfy_time {
        Some(elapsed) => println!("  frozen-matrix satisfy scan:  {}", fmt_ms(elapsed)),
        None => println!("  frozen-matrix satisfy scan:  skipped (set NOID_ROW_SATISFY=1)"),
    }
    match second_full {
        Some((elapsed, _)) => println!("  second-full exact relation:  {}", fmt_ms(elapsed)),
        None => {
            println!("  second-full exact relation:  skipped (set NOID_SELECTED_ZK_SECOND_FULL=1)")
        }
    }
    println!("\ncurrent RSS:");
    print_rss("assembly baseline", before);
    print_rss("after full matrix", after_full);
    print_rss("after witness-only", after_witness_only);
    if let Some((_, snapshot)) = second_full {
        print_rss("during second full", snapshot);
    }
}
