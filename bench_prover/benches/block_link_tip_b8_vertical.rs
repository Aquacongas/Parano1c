// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Opt-in full terminal-sidecar vertical gate:
//! canonical genesis -> B8 block 1 -> split link 1 -> B8 block 2 -> split link
//! 2 -> native tip decider.
//!
//! Run deliberately, never as part of the default suite:
//! `cargo bench -p bench_prover --bench block_link_tip_b8_vertical`.

use std::io::Write;
use std::time::{Duration, Instant};

use bench_prover::{accepted_two_coinbase_chain_fixture, fmt_bytes, AcceptedSingleBlockFixture};
use noid_core::mem_profile::{current_mem_snapshot, MemSnapshot};
use noid_ivc_prover::challenger::FsLaneChallenger;
use noid_ivc_prover::pcs::{self, PcsParams};
use noid_ivc_prover::proof::FieldShape;
use noid_recursive::acceptance::block_class::{
    build_block_proof_trace, prove_built_block, verify_block_proof, BlockClass, BlockProofEnvelope,
    BuiltBlock,
};
use noid_recursive::acceptance::block_slots::BlockSlotsConfig;
use noid_recursive::acceptance::link::LinkBlock;
use noid_recursive::acceptance::split_link::{
    build_split_link, decide_block_tip_split, decide_tip_split, prove_built_split_link,
    tip_block_accumulator_split, verify_split_link_proof, CanonicalSplitLinkLadder, LadderSlotInfo,
    LinkProofEnvelope, SplitLinkInput, SplitLinkSlotMaterial,
};
use noid_recursive::acceptance::trace::region_source_binding::RegionDischargeParams;
use noid_recursive::region_sidecar::link_post_commit_class_digest;

const BLOCK_DOMAIN: &[u8] = b"history-block-v0";
const LINK_DOMAIN: &[u8] = b"history-link-v0";
const TIER: usize = 8;
const BLOCK_M: usize = 22;
const LINK_M: usize = 24;
const K_SKIP: usize = 6;
const LOG_INV_RATE: usize = 2;
const LOG_BATCH_SIZE: usize = 5;
const EXPECTED_BLOCK_USEFUL_ROWS: usize = 808_858;
const LADDER_TIERS: [usize; 4] = [8, 32, 64, 255];
const LADDER_BLOCK_MS: [usize; 4] = [22, 23, 23, 24];

#[derive(Clone, Copy)]
struct Phase {
    elapsed: Duration,
    memory: Option<MemSnapshot>,
}

#[derive(Clone, Copy)]
struct ProofPhases {
    build: Phase,
    satisfy: Phase,
    prove: Phase,
    verify: Phase,
}

#[derive(Clone, Copy)]
struct ArtifactMetrics {
    useful_rows: usize,
    class_m: usize,
    sidecar_bytes: usize,
    envelope_bytes: usize,
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
            "  {label:<24} {:>9.3} s  RSS {:>9.1} MiB  HWM {:>9.1} MiB",
            phase.elapsed.as_secs_f64(),
            memory.rss_mb(),
            memory.hwm_mb(),
        ),
        None => println!(
            "  {label:<24} {:>9.3} s  RSS unavailable",
            phase.elapsed.as_secs_f64(),
        ),
    }
}

fn print_artifact(label: &str, metrics: ArtifactMetrics) {
    println!("  {label}:");
    println!("    useful rows       {:>12}", metrics.useful_rows);
    println!("    class m           {:>12}", metrics.class_m);
    println!(
        "    sidecar bytes     {:>12}  ({})",
        metrics.sidecar_bytes,
        fmt_bytes(metrics.sidecar_bytes),
    );
    println!(
        "    envelope bytes    {:>12}  ({})",
        metrics.envelope_bytes,
        fmt_bytes(metrics.envelope_bytes),
    );
}

fn block_view<'a>(
    fixture: &'a AcceptedSingleBlockFixture,
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
            tier_user_tx_capacity: Some(TIER),
        },
    }
}

fn provisional_ladder_slot(tier: usize, m: usize) -> LadderSlotInfo {
    let b_shape = FieldShape {
        m,
        k_log: m,
        k_skip: K_SKIP,
        const_pin: Some(0),
    };
    LadderSlotInfo {
        tier,
        b_shape,
        b_digest: [tier as u8; 32],
        b_pcs_params: PcsParams {
            m: m + pcs::LOG_PACKING,
            log_inv_rate: LOG_INV_RATE,
            log_batch_size: LOG_BATCH_SIZE,
            profile: Default::default(),
        },
        b_post_commit_class_digest: [tier.wrapping_add(1) as u8; 32],
        b_sidecar_vk_digest: [tier.wrapping_add(2) as u8; 32],
    }
}

fn main() {
    let _ = noid_ivc_prover::init_perf_thread_pool();
    println!("PARANOID B8 block -> link -> tip terminal-sidecar gate");
    println!("  two canonical coinbase-only children of the real genesis boundary");
    println!("  two mandatory Block sidecars; T ghost + two mandatory Link sidecars");
    println!("  rayon threads:       {}", rayon::current_num_threads());
    std::io::stdout().flush().expect("flush benchmark heading");

    let (fixtures, fixture_phase) = timed(accepted_two_coinbase_chain_fixture);
    assert_eq!(
        fixtures[0].start_accumulator,
        noid_recursive::genesis_accumulator()
    );
    assert_eq!(
        fixtures[1].start_accumulator, fixtures[0].output.accepted_claim_batch.accumulator,
        "fixture accumulator continuity",
    );
    for (index, fixture) in fixtures.iter().enumerate() {
        assert_eq!(fixture.component_proof.exact_state.len(), 1);
        assert!(
            fixture
                .component_proof
                .exact_state
                .iter()
                .all(|proof| proof.state_paths.is_empty()),
            "block {index}: vertical gate must not carry legacy exact-state paths",
        );
        assert_eq!(
            noid_chain::consensus::params::user_tx_class_tier(0),
            Some(TIER),
        );
    }

    let region_params = RegionDischargeParams {
        nq: noid_fri_binius::capsule::CAPSULE_NUM_QUERIES,
    };
    let block_shape = FieldShape {
        m: BLOCK_M,
        k_log: BLOCK_M,
        k_skip: K_SKIP,
        const_pin: Some(0),
    };
    let block_pcs_params = PcsParams {
        m: BLOCK_M + pcs::LOG_PACKING,
        log_inv_rate: LOG_INV_RATE,
        log_batch_size: LOG_BATCH_SIZE,
        profile: Default::default(),
    };
    let block1 = block_view(&fixtures[0], region_params);
    let block2 = block_view(&fixtures[1], region_params);

    let (block_class, block_freeze_phase) =
        timed(|| BlockClass::freeze(block_shape, block_pcs_params, region_params, &block1, TIER));
    let block_digest = *block_class
        .class_statement_digest
        .get()
        .expect("frozen B8 matrix digest");

    let (block1_envelope, block_matrix, block1_metrics, block1_phases) = {
        let (built, build) = timed(|| build_block_proof_trace(&block_class, &block1));
        assert_eq!(built.r1cs.useful_rows, EXPECTED_BLOCK_USEFUL_ROWS);
        let ((), satisfy) = timed(|| {
            assert!(built.r1cs.satisfies(&built.witness), "block 1 relation");
        });
        let (envelope, prove) = timed(|| {
            let mut challenger = FsLaneChallenger::new(BLOCK_DOMAIN);
            prove_built_block(&block_class, &built, &mut challenger)
                .expect("block 1 mandatory envelope")
        });
        let ((), verify) = timed(|| {
            let mut challenger = FsLaneChallenger::new(BLOCK_DOMAIN);
            verify_block_proof(&block_class, &built.r1cs, &envelope, &mut challenger)
                .expect("block 1 envelope verification");
        });
        let metrics = ArtifactMetrics {
            useful_rows: built.r1cs.useful_rows,
            class_m: built.r1cs.m,
            sidecar_bytes: envelope.region_sidecar().byte_len(),
            envelope_bytes: envelope.byte_len(),
        };
        let BuiltBlock {
            r1cs,
            witness: _,
            io: _,
            region_preparation: _,
        } = built;
        (
            envelope,
            r1cs,
            metrics,
            ProofPhases {
                build,
                satisfy,
                prove,
                verify,
            },
        )
    };

    let (block2_envelope, block2_metrics, block2_phases) = {
        let (built, build) = timed(|| build_block_proof_trace(&block_class, &block2));
        assert_eq!(built.r1cs.statement_digest(), block_digest);
        assert_eq!(built.r1cs.a_0, block_matrix.a_0, "B8 A matrix drift");
        assert_eq!(built.r1cs.b_0, block_matrix.b_0, "B8 B matrix drift");
        let ((), satisfy) = timed(|| {
            assert!(built.r1cs.satisfies(&built.witness), "block 2 relation");
        });
        let (envelope, prove) = timed(|| {
            let mut challenger = FsLaneChallenger::new(BLOCK_DOMAIN);
            prove_built_block(&block_class, &built, &mut challenger)
                .expect("block 2 mandatory envelope")
        });
        let ((), verify) = timed(|| {
            let mut challenger = FsLaneChallenger::new(BLOCK_DOMAIN);
            verify_block_proof(&block_class, &built.r1cs, &envelope, &mut challenger)
                .expect("block 2 envelope verification");
        });
        let metrics = ArtifactMetrics {
            useful_rows: built.r1cs.useful_rows,
            class_m: built.r1cs.m,
            sidecar_bytes: envelope.region_sidecar().byte_len(),
            envelope_bytes: envelope.byte_len(),
        };
        (
            envelope,
            metrics,
            ProofPhases {
                build,
                satisfy,
                prove,
                verify,
            },
        )
    };
    assert_eq!(
        block1_metrics.envelope_bytes, block2_metrics.envelope_bytes,
        "same-class block envelope length",
    );

    let link_shape = FieldShape {
        m: LINK_M,
        k_log: LINK_M,
        k_skip: K_SKIP,
        const_pin: Some(0),
    };
    let link_pcs_params = PcsParams {
        m: LINK_M + pcs::LOG_PACKING,
        log_inv_rate: LOG_INV_RATE,
        log_batch_size: LOG_BATCH_SIZE,
        profile: Default::default(),
    };
    // This vertical hosts B8 but always lays out the complete four-slot bank.
    // The unhosted identities are explicit provisional registry constants;
    // `block_ladder_materialize` replaces them with the four actual frozen
    // BlockClass identities. Geometry and IO are already the exact universal
    // ladder here, so a one-slot capacity result cannot regress unnoticed.
    let mut ladder_slots = LADDER_TIERS
        .into_iter()
        .zip(LADDER_BLOCK_MS)
        .map(|(tier, m)| provisional_ladder_slot(tier, m))
        .collect::<Vec<_>>();
    ladder_slots[0] = LadderSlotInfo {
        tier: TIER,
        b_shape: block_shape,
        b_digest: block_digest,
        b_pcs_params: block_class.pcs_params.clone(),
        b_post_commit_class_digest: *block_class.post_commit_class_digest(),
        b_sidecar_vk_digest: block_class.sidecar_vk().transcript_digest(),
    };
    let ladder = CanonicalSplitLinkLadder::try_new(link_shape, link_pcs_params, ladder_slots)
        .expect("canonical four-slot B8 vertical descriptor");
    let material = SplitLinkSlotMaterial {
        block_class: &block_class,
        sample_block: &block1_envelope,
        block_matrix: &block_matrix,
    };
    ladder
        .validate_slot_material(0, material)
        .expect("B8 vertical slot material preflight");
    let (link_class, link_freeze_phase) = timed(|| ladder.freeze_slot(0, material));
    let link_digest = *link_class
        .class_statement_digest
        .get()
        .expect("frozen split-link matrix digest");
    let mut link_class_digests = LADDER_TIERS
        .iter()
        .map(|tier| [0x80u8.wrapping_add(*tier as u8); 32])
        .collect::<Vec<_>>();
    link_class_digests[0] = link_digest;
    let link_post_commit_digests = link_class_digests
        .iter()
        .map(|digest| {
            link_post_commit_class_digest(
                digest,
                &link_class.spec,
                &link_class.pcs_params,
                link_class.sidecar_vk(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        link_post_commit_digests[0],
        *link_class.post_commit_class_digest(),
        "hosted B8 composite identity",
    );
    let genesis_matrix = link_class
        .rebuild_genesis_matrix()
        .expect("canonical transient genesis matrix");
    let genesis_metrics = ArtifactMetrics {
        useful_rows: genesis_matrix.useful_rows,
        class_m: genesis_matrix.m,
        sidecar_bytes: link_class.genesis_envelope().region_sidecar().byte_len(),
        envelope_bytes: link_class.genesis_envelope().byte_len(),
    };
    let layout = link_class.layout();
    let genesis_header = noid_chain::consensus::genesis_header();
    let absent_matrices = [None, None, None, None];
    let block_matrices = [Some(&block_matrix), None, None, None];

    let (link1_envelope, link1_matrix, link1_metrics, link1_phases) = {
        let input = SplitLinkInput {
            prev: link_class.genesis_envelope(),
            prev_slot: 0,
            genesis: true,
            link_class_digests: link_class_digests.clone(),
            link_post_commit_class_digests: link_post_commit_digests.clone(),
            block: &block1_envelope,
            fold_matrix_link: &genesis_matrix,
            fold_matrix_block: &block_matrix,
        };
        let (built, build) = timed(|| build_split_link(&link_class, &input));
        assert_eq!(built.r1cs.statement_digest(), link_digest);
        assert_eq!(built.io[layout.g], noid_ivc_prover::field::F128::ONE);
        assert_eq!(
            built.io[layout.link_lanes[0].live],
            noid_ivc_prover::field::F128::ZERO,
            "first link has no accumulated predecessor-class claim",
        );
        assert_eq!(
            built.io[layout.b_lanes[0].live],
            noid_ivc_prover::field::F128::ONE,
        );
        for slot in 1..LADDER_TIERS.len() {
            assert_eq!(
                built.io[layout.link_lanes[slot].live],
                noid_ivc_prover::field::F128::ZERO,
                "inactive predecessor lane {slot}",
            );
            assert_eq!(
                built.io[layout.b_lanes[slot].live],
                noid_ivc_prover::field::F128::ZERO,
                "inactive hosted-block lane {slot}",
            );
        }
        let ((), satisfy) = timed(|| {
            assert!(built.r1cs.satisfies(&built.witness), "first link relation");
        });
        let (envelope, prove) = timed(|| {
            let mut challenger = FsLaneChallenger::new(LINK_DOMAIN);
            prove_built_split_link(&link_class, &built, &mut challenger)
                .expect("first link mandatory envelope")
        });
        let ((), verify) = timed(|| {
            let mut challenger = FsLaneChallenger::new(LINK_DOMAIN);
            verify_split_link_proof(&link_class, &built.r1cs, &envelope, &mut challenger)
                .expect("first link envelope verification");
        });
        decide_block_tip_split(
            &link_class,
            &built.r1cs,
            &envelope,
            &link_class_digests,
            &link_post_commit_digests,
            &absent_matrices,
            &block_matrices,
            &fixtures[0].witness.items[0].block.header,
            &genesis_header,
        )
        .expect("one-block g=1 tip must be decidable");
        let metrics = ArtifactMetrics {
            useful_rows: built.r1cs.useful_rows,
            class_m: built.r1cs.m,
            sidecar_bytes: envelope.region_sidecar().byte_len(),
            envelope_bytes: envelope.byte_len(),
        };
        let matrix = built.r1cs;
        (
            envelope,
            matrix,
            metrics,
            ProofPhases {
                build,
                satisfy,
                prove,
                verify,
            },
        )
    };

    let (link2_envelope, link2_matrix, link2_metrics, link2_phases) = {
        let input = SplitLinkInput {
            prev: &link1_envelope,
            prev_slot: 0,
            genesis: false,
            link_class_digests: link_class_digests.clone(),
            link_post_commit_class_digests: link_post_commit_digests.clone(),
            block: &block2_envelope,
            fold_matrix_link: &link1_matrix,
            fold_matrix_block: &block_matrix,
        };
        let (built, build) = timed(|| build_split_link(&link_class, &input));
        assert_eq!(built.r1cs.statement_digest(), link_digest);
        assert_eq!(built.r1cs.a_0, link1_matrix.a_0, "link A matrix drift");
        assert_eq!(built.r1cs.b_0, link1_matrix.b_0, "link B matrix drift");
        assert_eq!(built.io[layout.g], noid_ivc_prover::field::F128::ZERO);
        assert_eq!(
            built.io[layout.link_lanes[0].live],
            noid_ivc_prover::field::F128::ONE,
        );
        assert_eq!(
            built.io[layout.b_lanes[0].live],
            noid_ivc_prover::field::F128::ONE,
        );
        for slot in 1..LADDER_TIERS.len() {
            assert_eq!(
                built.io[layout.link_lanes[slot].live],
                noid_ivc_prover::field::F128::ZERO,
                "inactive predecessor lane {slot}",
            );
            assert_eq!(
                built.io[layout.b_lanes[slot].live],
                noid_ivc_prover::field::F128::ZERO,
                "inactive hosted-block lane {slot}",
            );
        }
        let ((), satisfy) = timed(|| {
            assert!(
                built.r1cs.satisfies(&built.witness),
                "successor link relation"
            );
        });
        let (envelope, prove) = timed(|| {
            let mut challenger = FsLaneChallenger::new(LINK_DOMAIN);
            prove_built_split_link(&link_class, &built, &mut challenger)
                .expect("successor link mandatory envelope")
        });
        let ((), verify) = timed(|| {
            let mut challenger = FsLaneChallenger::new(LINK_DOMAIN);
            verify_split_link_proof(&link_class, &built.r1cs, &envelope, &mut challenger)
                .expect("successor link envelope verification");
        });
        let metrics = ArtifactMetrics {
            useful_rows: built.r1cs.useful_rows,
            class_m: built.r1cs.m,
            sidecar_bytes: envelope.region_sidecar().byte_len(),
            envelope_bytes: envelope.byte_len(),
        };
        let matrix = built.r1cs;
        (
            envelope,
            matrix,
            metrics,
            ProofPhases {
                build,
                satisfy,
                prove,
                verify,
            },
        )
    };
    drop(link1_matrix);
    assert_eq!(
        link1_metrics.envelope_bytes, link2_metrics.envelope_bytes,
        "same-class link envelope length",
    );
    assert!(link2_metrics.useful_rows <= 1usize << LINK_M);
    let link_matrices = [Some(&link2_matrix), None, None, None];

    let ((), decider_phase) = timed(|| {
        decide_block_tip_split(
            &link_class,
            &link2_matrix,
            &link2_envelope,
            &link_class_digests,
            &link_post_commit_digests,
            &link_matrices,
            &block_matrices,
            &fixtures[1].witness.items[0].block.header,
            &genesis_header,
        )
        .expect("two-block B8 -> B8 tip decider");
    });
    assert_eq!(
        tip_block_accumulator_split(&link_class, &link2_envelope).expect("tip accumulator lanes"),
        fixtures[1].output.accepted_claim_batch.accumulator,
    );

    // Cheap terminal-boundary negatives: no additional proof construction.
    assert!(
        decide_tip_split(
            &link_class,
            &link2_matrix,
            &link2_envelope,
            &link_class_digests,
            &link_post_commit_digests,
            &absent_matrices,
            &block_matrices,
        )
        .is_err(),
        "live link lane accepted without its matrix",
    );
    assert!(
        decide_tip_split(
            &link_class,
            &link2_matrix,
            &link2_envelope,
            &link_class_digests,
            &link_post_commit_digests,
            &link_matrices,
            &absent_matrices,
        )
        .is_err(),
        "live block lane accepted without its matrix",
    );
    let mut wrong_link_digests = link_class_digests.clone();
    wrong_link_digests[0][0] ^= 1;
    assert!(
        decide_tip_split(
            &link_class,
            &link2_matrix,
            &link2_envelope,
            &wrong_link_digests,
            &link_post_commit_digests,
            &link_matrices,
            &block_matrices,
        )
        .is_err(),
        "wrong matrix whitelist accepted",
    );
    let mut wrong_post_commit = link_post_commit_digests.clone();
    wrong_post_commit[0][0] ^= 1;
    assert!(
        decide_tip_split(
            &link_class,
            &link2_matrix,
            &link2_envelope,
            &link_class_digests,
            &wrong_post_commit,
            &link_matrices,
            &block_matrices,
        )
        .is_err(),
        "wrong post-commit whitelist accepted",
    );
    let mut wrong_tip_header = fixtures[1].witness.items[0].block.header.clone();
    wrong_tip_header.nonce ^= 1;
    assert!(
        decide_block_tip_split(
            &link_class,
            &link2_matrix,
            &link2_envelope,
            &link_class_digests,
            &link_post_commit_digests,
            &link_matrices,
            &block_matrices,
            &wrong_tip_header,
            &genesis_header,
        )
        .is_err(),
        "wrong local tip header accepted",
    );
    let core_only = bincode::serialize(&(
        link2_envelope.field_proof(),
        link2_envelope.commitment(),
        link2_envelope.io(),
    ))
    .expect("serialize core-only link downgrade");
    assert!(
        bincode::deserialize::<LinkProofEnvelope>(&core_only).is_err(),
        "core-only Field proof decoded as a production link envelope",
    );
    let block_core_only = bincode::serialize(&(
        block1_envelope.field_proof(),
        block1_envelope.commitment(),
        block1_envelope.io(),
    ))
    .expect("serialize core-only block downgrade");
    assert!(
        bincode::deserialize::<BlockProofEnvelope>(&block_core_only).is_err(),
        "core-only Field proof decoded as a production block envelope",
    );

    println!("\nvertical artifact summary:");
    print_artifact("block 1", block1_metrics);
    print_artifact("block 2", block2_metrics);
    print_artifact("genesis T", genesis_metrics);
    print_artifact("link 1", link1_metrics);
    print_artifact("link 2", link2_metrics);
    println!("\nphase timings and process memory snapshots:");
    print_phase("fixtures", fixture_phase);
    print_phase("block class freeze", block_freeze_phase);
    print_phase("block 1 build", block1_phases.build);
    print_phase("block 1 satisfy", block1_phases.satisfy);
    print_phase("block 1 prove", block1_phases.prove);
    print_phase("block 1 verify", block1_phases.verify);
    print_phase("block 2 build", block2_phases.build);
    print_phase("block 2 satisfy", block2_phases.satisfy);
    print_phase("block 2 prove", block2_phases.prove);
    print_phase("block 2 verify", block2_phases.verify);
    print_phase("link class freeze + T", link_freeze_phase);
    print_phase("link 1 build", link1_phases.build);
    print_phase("link 1 satisfy", link1_phases.satisfy);
    print_phase("link 1 prove", link1_phases.prove);
    print_phase("link 1 verify", link1_phases.verify);
    print_phase("link 2 build", link2_phases.build);
    print_phase("link 2 satisfy", link2_phases.satisfy);
    print_phase("link 2 prove", link2_phases.prove);
    print_phase("link 2 verify", link2_phases.verify);
    print_phase("tip decider", decider_phase);
}
