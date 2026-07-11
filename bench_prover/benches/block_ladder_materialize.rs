// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Canonical four-slot Block/Link ladder materialization gate.
//!
//! This deliberately stops before a full cross-tier proof chain. It freezes
//! the exact B8/B32/B64/B255 Block identities on the smallest user-bearing
//! member of each class, then freezes and cross-validates all four Link classes
//! against the complete universal bank. `NOID_LADDER_HOST_TIER` selects one of
//! those classes for the final capacity probe and defaults to B8. Standalone
//! class-floor fixtures begin at a synthetic accepted parent, so that final
//! Link witness is not a genesis-continuous proof; the separate cross-tier
//! chain supplies continuity. A one-slot ladder is not a substitute for either
//! gate.

use std::io::Write;
use std::time::Instant;

use bench_prover::{
    accepted_proved_user_block_fixture, tx8x2_scenario, AcceptedSingleBlockFixture,
};
use noid_ivc_prover::challenger::FsLaneChallenger;
use noid_ivc_prover::pcs::{self, PcsParams};
use noid_ivc_prover::proof::FieldShape;
use noid_recursive::acceptance::block_class::{
    build_block_proof_trace, prove_built_block, BlockClass,
};
use noid_recursive::acceptance::block_slots::BlockSlotsConfig;
use noid_recursive::acceptance::link::LinkBlock;
use noid_recursive::acceptance::split_link::{
    build_split_link, CanonicalSplitLinkLadder, SplitLinkInput, SplitLinkSlotMaterial,
    CANONICAL_BLOCK_CLASS_MS, CANONICAL_LINK_CLASS_M, CANONICAL_PCS_LOG_BATCH_SIZE,
    CANONICAL_PCS_LOG_INV_RATE,
};
use noid_recursive::acceptance::trace::region_source_binding::RegionDischargeParams;

const BLOCK_DOMAIN: &[u8] = b"history-block-v0";
const TIERS: [usize; 4] = noid_chain::consensus::params::USER_TX_CLASS_TIERS;
const K_SKIP: usize = 6;

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
                "canonical-ladder-floor",
                noid_tx::TX_INPUTS,
                noid_tx::TX_OUTPUTS,
                u32::try_from(index * 2_048).expect("fixture slot base"),
                0x1ADD_E000 + ((tier as u128) << 32) + index as u128,
            )
        })
        .collect();
    let mut fixture = accepted_proved_user_block_fixture(scenarios);
    assert_eq!(
        noid_chain::consensus::params::user_tx_class_tier(count),
        Some(tier),
        "floor fixture must select B{tier}",
    );
    for exact_state in &mut fixture.component_proof.exact_state {
        exact_state.state_paths.clear();
    }
    fixture
}

fn block_view<'a>(
    fixture: &'a AcceptedSingleBlockFixture,
    tier: usize,
    region_params: RegionDischargeParams,
) -> LinkBlock<'a> {
    LinkBlock {
        start_accumulator: &fixture.start_accumulator,
        end_accumulator: &fixture.output.accepted_claim_batch.accumulator,
        inputs: &fixture.output.proof_components.component_inputs,
        proof: &fixture.component_proof,
        config: BlockSlotsConfig {
            discharge_wallet_pcs: true,
            wallet_pcs_params: region_params,
            owner_auth_region: true,
            exact_state_region: true,
            tx_root_region: true,
            spine_region: true,
            tier_user_tx_capacity: Some(tier),
        },
    }
}

fn field_shape(m: usize) -> FieldShape {
    FieldShape {
        m,
        k_log: m,
        k_skip: K_SKIP,
        const_pin: Some(0),
    }
}

fn pcs_params(m: usize) -> PcsParams {
    PcsParams {
        m: m + pcs::LOG_PACKING,
        log_inv_rate: CANONICAL_PCS_LOG_INV_RATE,
        log_batch_size: CANONICAL_PCS_LOG_BATCH_SIZE,
        profile: Default::default(),
    }
}

fn main() {
    let _ = noid_ivc_prover::init_perf_thread_pool();
    let hosted_tier = std::env::var("NOID_LADDER_HOST_TIER")
        .ok()
        .map(|value| value.parse::<usize>().expect("numeric hosted tier"))
        .unwrap_or(8);
    let hosted_slot = TIERS
        .iter()
        .position(|tier| *tier == hosted_tier)
        .expect("NOID_LADDER_HOST_TIER must be 8, 32, 64, or 255");
    let region_params = RegionDischargeParams {
        nq: noid_fri_binius::capsule::CAPSULE_NUM_QUERIES,
    };
    println!("PARANOID canonical B8/B32/B64/B255 ladder materialization");
    println!("  class-floor fixtures: 1 / 9 / 33 / 65 user transactions");
    println!("  final capacity probe:  B{hosted_tier} hosted by the full four-slot Link bank");
    std::io::stdout().flush().expect("flush benchmark heading");

    let mut classes = Vec::with_capacity(TIERS.len());
    let mut block_matrices = Vec::with_capacity(TIERS.len());
    let mut block_envelopes = Vec::with_capacity(TIERS.len());
    let mut start_accumulators = Vec::with_capacity(TIERS.len());
    for (&tier, &m) in TIERS.iter().zip(&CANONICAL_BLOCK_CLASS_MS) {
        let started = Instant::now();
        let fixture = fixture_for(tier);
        let block = block_view(&fixture, tier, region_params);
        let class = BlockClass::freeze(field_shape(m), pcs_params(m), region_params, &block, tier);
        let built_block = build_block_proof_trace(&class, &block);
        assert!(
            built_block.r1cs.satisfies(&built_block.witness),
            "B{tier} class-floor Block witness"
        );
        let mut block_challenger = FsLaneChallenger::new(BLOCK_DOMAIN);
        let block_envelope = prove_built_block(&class, &built_block, &mut block_challenger)
            .unwrap_or_else(|error| panic!("B{tier} block envelope failed: {error}"));
        let digest = *class
            .class_statement_digest
            .get()
            .expect("frozen block matrix digest");
        println!(
            "  B{tier:<3} m{m}: {}  fixture+freeze+proof {:>8.3} s",
            hex::encode(digest),
            started.elapsed().as_secs_f64(),
        );
        start_accumulators.push(fixture.start_accumulator.clone());
        let mut block_matrix = built_block.r1cs;
        block_matrix.release_csc_cache();
        block_matrices.push(block_matrix);
        block_envelopes.push(block_envelope);
        classes.push(class);
        drop(fixture);
    }

    let link_shape = field_shape(CANONICAL_LINK_CLASS_M);
    let ladder = CanonicalSplitLinkLadder::from_block_classes(
        link_shape,
        pcs_params(CANONICAL_LINK_CLASS_M),
        [&classes[0], &classes[1], &classes[2], &classes[3]],
    )
    .expect("canonical four-slot descriptor");
    assert_eq!(
        ladder
            .slots()
            .iter()
            .map(|slot| slot.tier)
            .collect::<Vec<_>>(),
        TIERS,
        "canonical ladder order",
    );

    let materials: [SplitLinkSlotMaterial<'_>; CanonicalSplitLinkLadder::SLOT_COUNT] =
        std::array::from_fn(|slot| SplitLinkSlotMaterial {
            block_class: &classes[slot],
            sample_block: &block_envelopes[slot],
            block_matrix: &block_matrices[slot],
        });
    for (slot, material) in materials.iter().copied().enumerate() {
        ladder
            .validate_slot_material(slot, material)
            .unwrap_or_else(|error| panic!("preflight B{} ladder material: {error}", TIERS[slot]));
    }
    let freeze_started = Instant::now();
    let link_classes = ladder.freeze_all(materials);
    ladder
        .validate_materialized(&link_classes)
        .unwrap_or_else(|error| panic!("materialized Link ladder identity drift: {error}"));
    println!(
        "  four-class universal Link freeze+validation: {:>8.3} s",
        freeze_started.elapsed().as_secs_f64(),
    );
    let link_class_digests = link_classes
        .iter()
        .map(|class| {
            *class
                .class_statement_digest
                .get()
                .expect("frozen Link matrix digest")
        })
        .collect::<Vec<_>>();
    let link_post_commit_class_digests = link_classes
        .iter()
        .map(|class| *class.post_commit_class_digest())
        .collect::<Vec<_>>();
    println!("\nactual four-class Link registry:");
    for slot in 0..TIERS.len() {
        println!(
            "  L-B{:<3} matrix {}  post-commit {}",
            TIERS[slot],
            hex::encode(link_class_digests[slot]),
            hex::encode(link_post_commit_class_digests[slot]),
        );
    }

    let link_class = &link_classes[hosted_slot];
    assert_ne!(
        &start_accumulators[hosted_slot],
        &noid_recursive::genesis_accumulator(),
        "standalone class-floor capacity fixture must retain its synthetic accepted parent"
    );
    let built_link = build_split_link(
        link_class,
        &SplitLinkInput {
            prev: link_class.genesis_envelope(),
            prev_slot: hosted_slot,
            genesis: true,
            link_class_digests: link_class_digests.clone(),
            link_post_commit_class_digests: link_post_commit_class_digests.clone(),
            block: &block_envelopes[hosted_slot],
            fold_matrix_link: &link_class.genesis,
            fold_matrix_block: &block_matrices[hosted_slot],
        },
    );
    assert_eq!(built_link.r1cs.m, CANONICAL_LINK_CLASS_M);
    assert!(
        built_link.r1cs.useful_rows <= 1usize << CANONICAL_LINK_CLASS_M,
        "full universal Link relation exceeds m24",
    );
    let link_satisfied = built_link.r1cs.satisfies(&built_link.witness);
    assert!(
        !link_satisfied,
        "standalone class-floor fixture unexpectedly matched canonical Link genesis"
    );
    println!("\nuniversal Link capacity result:");
    println!("  useful rows       {:>12}", built_link.r1cs.useful_rows);
    println!(
        "  m24 capacity      {:>12}",
        1usize << CANONICAL_LINK_CLASS_M
    );
    println!(
        "  remaining rows    {:>12}",
        (1usize << CANONICAL_LINK_CLASS_M) - built_link.r1cs.useful_rows,
    );
    println!("  relation witness   standalone/non-continuous (capacity only)");
}
