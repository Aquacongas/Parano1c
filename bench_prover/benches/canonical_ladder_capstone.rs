// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Opt-in honest canonical-ladder capstone.
//!
//! The fixture starts at the real genesis boundary and crosses every production
//! proof class in one continuous chain:
//!
//! ```text
//! user txs  0 -> 1 -> 3 -> 7 -> 8 -> 17 -> 33 -> 65 -> 131 -> 255
//! Block     B8   B8   B8   B8   B8   B32   B64   B255  B255   B255
//! Link      L8   L8   L8   L8   L8   L32   L64   L255  L255   L255
//! ```
//!
//! Every Block and Link envelope is proved and verified.  The final native
//! decider receives each live class matrix, the actual four-class Link
//! whitelist, and the locally selected tip/genesis headers.
//!
//! This gate is deliberately not part of the default suite:
//! `cargo bench -p bench_prover --bench canonical_ladder_capstone`.
//! Set `NOID_CAPSTONE_TRANSITION_SUFFIX=1` to continue after the 255-user block
//! with the real suffix `B255 -> B8 -> B255 -> B32 -> B64`.
//!
//! Memory note: per-step matrices are never retained.  The gate keeps exactly
//! one representative Block matrix and one representative Link matrix per
//! production class because the final accumulated lanes need all of them.
//! Four m22/m23/m24 Block matrices, four m24 Link matrices, one shared m24
//! genesis matrix, and the active prover witness still make this an
//! intentionally high-memory capstone.  Verification-populated CSC caches are
//! explicitly discarded before a representative matrix is retained; the
//! native decider can evaluate its accumulated lanes from the canonical CSR.

use std::io::Write;
use std::time::Instant;

use bench_prover::{
    accepted_canonical_ladder_transition_chain_fixture,
    accepted_canonical_saturated_ladder_chain_fixture, fmt_bytes, AcceptedSingleBlockFixture,
};
use noid_core::mem_profile::current_mem_snapshot;
use noid_core::Block128;
use noid_ivc_prover::challenger::FsLaneChallenger;
use noid_ivc_prover::field::F128;
use noid_ivc_prover::field_r1cs::FieldR1cs;
use noid_ivc_prover::pcs::{self, PcsParams};
use noid_ivc_prover::proof::FieldShape;
use noid_recursive::acceptance::block_class::{
    build_block_proof_trace, prove_built_block, verify_block_proof, BlockClass, BlockProofEnvelope,
    BLOCK_IO_END_ACC, BLOCK_IO_START_ACC,
};
use noid_recursive::acceptance::block_slots::BlockSlotsConfig;
use noid_recursive::acceptance::link::LinkBlock;
use noid_recursive::acceptance::split_link::{
    build_split_link, decide_block_tip_split, prove_built_split_link, tip_block_accumulator_split,
    verify_split_link_proof, CanonicalSplitLinkLadder, LinkProofEnvelope, SplitLinkInput,
    SplitLinkSlotMaterial, CANONICAL_BLOCK_CLASS_MS, CANONICAL_LINK_CLASS_M,
    CANONICAL_PCS_LOG_BATCH_SIZE, CANONICAL_PCS_LOG_INV_RATE,
};
use noid_recursive::acceptance::trace::region_source_binding::RegionDischargeParams;
use noid_recursive::accumulator::{ChainAccumulator, CHAIN_ACCUMULATOR_LANES};

const BLOCK_DOMAIN: &[u8] = b"history-block-v0";
const LINK_DOMAIN: &[u8] = b"history-link-v0";
const K_SKIP: usize = 6;
const FIXTURE_SEED: u128 = 0x4341_4E4F_4E49_4341_4C4C_4144_4445_5201;
const SATURATED_USER_COUNTS: [usize; 10] = [0, 1, 3, 7, 8, 17, 33, 65, 131, 255];
const TRANSITION_USER_COUNTS: [usize; 14] = [0, 1, 3, 7, 8, 17, 33, 65, 131, 255, 8, 65, 17, 33];
const CLASS_SAMPLE_STEPS: [usize; 4] = [0, 5, 6, 7];
const B255_STEPS: [usize; 3] = [7, 8, 9];
const TIERS: [usize; 4] = noid_chain::consensus::params::USER_TX_CLASS_TIERS;

#[derive(Clone, Copy, Default)]
struct StepMetrics {
    block_rows: usize,
    block_envelope_bytes: usize,
    link_rows: usize,
    link_envelope_bytes: usize,
    block_seconds: f64,
    link_seconds: f64,
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

fn decode_accumulator(io: &[F128], offset: usize) -> ChainAccumulator {
    let lanes: [Block128; CHAIN_ACCUMULATOR_LANES] = std::array::from_fn(|lane| {
        let value = io[offset + lane];
        let flat = (value.lo as u128) | ((value.hi as u128) << 64);
        Block128::from(noid_core::hardware::flat_to_tower_u128(flat))
    });
    ChainAccumulator::from_lanes(lanes).expect("canonical accumulator IO lanes")
}

fn class_slots(user_counts: &[usize]) -> Vec<usize> {
    user_counts
        .iter()
        .map(|&user_count| {
            let tier = noid_chain::consensus::params::user_tx_class_tier(user_count)
                .expect("canonical user count selects a Block class");
            TIERS
                .iter()
                .position(|candidate| *candidate == tier)
                .expect("consensus tier belongs to the canonical ladder")
        })
        .collect()
}

fn assert_fixture_chain(
    fixtures: &[AcceptedSingleBlockFixture],
    user_counts: &[usize],
    step_slots: &[usize],
) {
    assert_eq!(fixtures.len(), user_counts.len());
    assert_eq!(fixtures.len(), step_slots.len());
    let genesis = noid_chain::consensus::genesis_header();
    for (step, fixture) in fixtures.iter().enumerate() {
        let block = &fixture.witness.items[0].block;
        let user_count = block
            .transactions
            .len()
            .checked_sub(1)
            .expect("accepted block includes coinbase");
        let slot = step_slots[step];
        assert_eq!(user_count, user_counts[step], "step {step}: user count");
        assert_eq!(
            noid_chain::consensus::params::user_tx_class_tier(user_count),
            Some(TIERS[slot]),
            "step {step}: consensus Block class",
        );
        assert_eq!(
            block.header.prev_block_hash,
            noid_chain::hash_block_header(&fixture.parent),
            "step {step}: parent hash",
        );
        assert_eq!(
            block.header.height,
            fixture.parent.height + 1,
            "step {step}: height continuity",
        );
        assert_eq!(
            fixture.start_accumulator.state_root,
            fixture.pre_state.cached_state_root(),
            "step {step}: pre-state accumulator boundary",
        );
        assert_eq!(fixture.component_proof.exact_state.len(), 1);
        assert!(
            fixture
                .component_proof
                .exact_state
                .iter()
                .all(|proof| proof.state_paths.is_empty()),
            "step {step}: retained exact-state component carried legacy paths",
        );
        if step == 0 {
            assert_eq!(fixture.parent, genesis, "first parent is real genesis");
            assert_eq!(
                fixture.start_accumulator,
                noid_recursive::genesis_accumulator(),
                "first Block starts at the recursive genesis boundary",
            );
        } else {
            let previous = &fixtures[step - 1];
            assert_eq!(
                fixture.parent, previous.witness.items[0].block.header,
                "step {step}: exact parent header continuity",
            );
            assert_eq!(
                fixture.start_accumulator, previous.output.accepted_claim_batch.accumulator,
                "step {step}: accumulator continuity",
            );
            assert_eq!(
                fixture.pre_state.cached_state_root(),
                previous.output.end_state.cached_state_root(),
                "step {step}: state continuity",
            );
        }
    }
}

fn main() {
    let _ = noid_ivc_prover::init_perf_thread_pool();
    let region_params = RegionDischargeParams {
        nq: noid_fri_binius::capsule::CAPSULE_NUM_QUERIES,
    };
    let transition_suffix = std::env::var("NOID_CAPSTONE_TRANSITION_SUFFIX")
        .ok()
        .as_deref()
        == Some("1");
    let user_counts: &[usize] = if transition_suffix {
        &TRANSITION_USER_COUNTS
    } else {
        &SATURATED_USER_COUNTS
    };
    let step_slots = class_slots(user_counts);
    if transition_suffix {
        assert_eq!(
            &step_slots[9..],
            &[3, 0, 3, 1, 2],
            "saturated tip plus representative down/skip/up suffix",
        );
    } else {
        assert_eq!(
            user_counts, &SATURATED_USER_COUNTS,
            "default saturated metric sequence must remain frozen",
        );
    }

    println!("PARANOID honest canonical Block/Link ladder capstone");
    println!("  user tx counts:      {user_counts:?}");
    println!("  class slots:         {step_slots:?}");
    println!(
        "  transition suffix:  {}",
        if transition_suffix {
            "enabled (B255 -> B8 -> B255 -> B32 -> B64)"
        } else {
            "disabled (reproducible ten-step saturated baseline)"
        }
    );
    println!("  rayon threads:       {}", rayon::current_num_threads());
    println!("  Link capacity:       m{CANONICAL_LINK_CLASS_M}");
    println!(
        "  retained matrices:  one Block + one Link representative per class (high-memory gate)"
    );
    std::io::stdout().flush().expect("flush benchmark heading");

    let fixture_started = Instant::now();
    let fixtures = if transition_suffix {
        accepted_canonical_ladder_transition_chain_fixture(FIXTURE_SEED)
            .into_iter()
            .collect::<Vec<_>>()
    } else {
        accepted_canonical_saturated_ladder_chain_fixture(FIXTURE_SEED)
            .into_iter()
            .collect::<Vec<_>>()
    };
    assert_fixture_chain(&fixtures, user_counts, &step_slots);
    println!(
        "  continuous retained fixtures: {:>8.3} s",
        fixture_started.elapsed().as_secs_f64(),
    );

    // Freeze all actual Block classes before consuming the fixtures.  Each
    // class is sampled from the same continuous chain later proved below.
    let mut block_classes = Vec::with_capacity(CanonicalSplitLinkLadder::SLOT_COUNT);
    for slot in 0..CanonicalSplitLinkLadder::SLOT_COUNT {
        let sample_step = CLASS_SAMPLE_STEPS[slot];
        assert_eq!(
            step_slots[sample_step], slot,
            "class sample step must select its canonical slot",
        );
        let sample = block_view(&fixtures[sample_step], TIERS[slot], region_params);
        block_classes.push(BlockClass::freeze(
            field_shape(CANONICAL_BLOCK_CLASS_MS[slot]),
            pcs_params(CANONICAL_BLOCK_CLASS_MS[slot]),
            region_params,
            &sample,
            TIERS[slot],
        ));
    }

    let expected_start_accumulators = fixtures
        .iter()
        .map(|fixture| fixture.start_accumulator.clone())
        .collect::<Vec<_>>();
    let expected_end_accumulators = fixtures
        .iter()
        .map(|fixture| fixture.output.accepted_claim_batch.accumulator.clone())
        .collect::<Vec<_>>();
    let local_tip = &fixtures
        .last()
        .expect("canonical capstone fixture tip")
        .witness
        .items[0]
        .block;
    if !transition_suffix {
        assert_eq!(
            local_tip.transactions.len() - 1,
            noid_chain::consensus::params::BLOCK_MAX_USER_TXS,
            "the default local capstone tip must carry all 255 production user transactions",
        );
    }
    let local_tip_header = local_tip.header.clone();

    // All Block envelopes are needed by the Link phase, but only the
    // first matrix encountered for each class survives this loop.  In
    // particular, the five B8 steps do not leave five m22 matrix copies live.
    let mut block_matrices: [Option<FieldR1cs>; CanonicalSplitLinkLadder::SLOT_COUNT] =
        std::array::from_fn(|_| None);
    let mut block_envelopes: Vec<BlockProofEnvelope> = Vec::with_capacity(user_counts.len());
    let mut block_envelope_bytes = [None; CanonicalSplitLinkLadder::SLOT_COUNT];
    let mut block_matrix_digests = vec![[0u8; 32]; user_counts.len()];
    let mut metrics = vec![StepMetrics::default(); user_counts.len()];
    for (step, fixture) in fixtures.iter().enumerate() {
        let slot = step_slots[step];
        let tier = TIERS[slot];
        let block_started = Instant::now();
        let view = block_view(fixture, tier, region_params);
        let built = build_block_proof_trace(&block_classes[slot], &view);
        assert_eq!(built.r1cs.m, CANONICAL_BLOCK_CLASS_MS[slot]);
        assert!(
            built.r1cs.useful_rows <= 1usize << CANONICAL_BLOCK_CLASS_MS[slot],
            "step {step}: B{tier} relation exceeds its frozen class",
        );
        assert!(
            built.r1cs.satisfies(&built.witness),
            "step {step}: B{tier} relation",
        );
        assert_eq!(
            decode_accumulator(&built.io, BLOCK_IO_START_ACC),
            expected_start_accumulators[step],
            "step {step}: direct Block start accumulator IO",
        );
        assert_eq!(
            decode_accumulator(&built.io, BLOCK_IO_END_ACC),
            expected_end_accumulators[step],
            "step {step}: direct Block end accumulator IO",
        );

        let mut challenger = FsLaneChallenger::new(BLOCK_DOMAIN);
        let envelope = prove_built_block(&block_classes[slot], &built, &mut challenger)
            .unwrap_or_else(|error| panic!("step {step}: B{tier} proof failed: {error}"));
        let mut challenger = FsLaneChallenger::new(BLOCK_DOMAIN);
        verify_block_proof(
            &block_classes[slot],
            &built.r1cs,
            &envelope,
            &mut challenger,
        )
        .unwrap_or_else(|error| panic!("step {step}: B{tier} verify failed: {error}"));
        assert_eq!(
            decode_accumulator(envelope.io(), BLOCK_IO_START_ACC),
            expected_start_accumulators[step],
            "step {step}: proved Block start accumulator IO",
        );
        assert_eq!(
            decode_accumulator(envelope.io(), BLOCK_IO_END_ACC),
            expected_end_accumulators[step],
            "step {step}: proved Block end accumulator IO",
        );

        let envelope_bytes = envelope.byte_len();
        if let Some(expected) = block_envelope_bytes[slot] {
            assert_eq!(
                envelope_bytes, expected,
                "step {step}: same-class B{tier} envelope length drift",
            );
        } else {
            block_envelope_bytes[slot] = Some(envelope_bytes);
        }

        let matrix_digest = built.r1cs.statement_digest();
        block_matrix_digests[step] = matrix_digest;
        let mut matrix = built.r1cs;
        // Native proof verification warms the matrix's large CSC cache.  The
        // retained registry/decider representative only needs canonical CSR;
        // do not pin one additional CSC copy for every production class.
        matrix.release_csc_cache();
        if let Some(representative) = &block_matrices[slot] {
            assert_eq!(
                representative.statement_digest(),
                matrix_digest,
                "step {step}: B{tier} matrix drift",
            );
        } else {
            block_matrices[slot] = Some(matrix);
        }
        metrics[step].block_rows = block_matrices[slot]
            .as_ref()
            .expect("Block representative")
            .useful_rows;
        metrics[step].block_envelope_bytes = envelope_bytes;
        metrics[step].block_seconds = block_started.elapsed().as_secs_f64();
        block_envelopes.push(envelope);
    }
    let first_b255_step = B255_STEPS[0];
    for &step in &B255_STEPS[1..] {
        assert_eq!(
            block_matrix_digests[step], block_matrix_digests[first_b255_step],
            "B255 matrix must be invariant across the 65/131/255 live counts",
        );
        assert_eq!(
            metrics[step].block_envelope_bytes, metrics[first_b255_step].block_envelope_bytes,
            "B255 envelope length must be invariant across the 65/131/255 live counts",
        );
    }
    // Component proofs and full states are no longer necessary.  Releasing
    // all fixtures before the m24 Link phase is important on a finite-
    // memory proving host.
    drop(fixtures);

    let block_refs: [&FieldR1cs; CanonicalSplitLinkLadder::SLOT_COUNT] =
        std::array::from_fn(|slot| {
            block_matrices[slot]
                .as_ref()
                .expect("one Block matrix representative per class")
        });
    let ladder = CanonicalSplitLinkLadder::from_block_classes(
        field_shape(CANONICAL_LINK_CLASS_M),
        pcs_params(CANONICAL_LINK_CLASS_M),
        [
            &block_classes[0],
            &block_classes[1],
            &block_classes[2],
            &block_classes[3],
        ],
    )
    .expect("actual canonical four-slot ladder descriptor");
    let materials: [SplitLinkSlotMaterial<'_>; CanonicalSplitLinkLadder::SLOT_COUNT] =
        std::array::from_fn(|slot| SplitLinkSlotMaterial {
            block_class: &block_classes[slot],
            sample_block: &block_envelopes[CLASS_SAMPLE_STEPS[slot]],
            block_matrix: block_refs[slot],
        });
    let freeze_started = Instant::now();
    let link_classes = ladder.freeze_all(materials);
    ladder
        .validate_materialized(&link_classes)
        .expect("materialized actual Link ladder identity");
    drop(block_classes);
    println!(
        "  actual four-class Link freeze: {:>8.3} s",
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
    for slot in 0..CanonicalSplitLinkLadder::SLOT_COUNT {
        println!(
            "  L-B{:<3} matrix {}  post-commit {}",
            TIERS[slot],
            hex::encode(link_class_digests[slot]),
            hex::encode(link_post_commit_class_digests[slot]),
        );
    }

    let mut link_matrices: [Option<FieldR1cs>; CanonicalSplitLinkLadder::SLOT_COUNT] =
        std::array::from_fn(|_| None);
    let mut previous_link: Option<LinkProofEnvelope> = None;
    let mut previous_slot = 0usize;
    let mut common_link_envelope_bytes = None;
    let mut seen_link_class = [false; CanonicalSplitLinkLadder::SLOT_COUNT];
    let mut link_matrix_digests = vec![[0u8; 32]; user_counts.len()];
    for step in 0..user_counts.len() {
        let slot = step_slots[step];
        let tier = TIERS[slot];
        let class = &link_classes[slot];
        let link_started = Instant::now();
        let genesis_matrix = (step == 0).then(|| {
            class
                .rebuild_genesis_matrix()
                .expect("canonical transient genesis matrix")
        });
        let (envelope, matrix, useful_rows) = {
            let genesis = step == 0;
            let prev = if genesis {
                class.genesis_envelope()
            } else {
                previous_link.as_ref().expect("previous recursive Link")
            };
            let fold_matrix_link = if genesis {
                genesis_matrix
                    .as_ref()
                    .expect("genesis matrix loaded for genesis step")
            } else {
                link_matrices[previous_slot]
                    .as_ref()
                    .expect("previous Link class matrix representative")
            };
            if !genesis {
                assert_eq!(
                    fold_matrix_link.structural_statement_digest(),
                    link_class_digests[previous_slot],
                    "step {step}: beta-selected previous Link matrix identity",
                );
                assert_eq!(
                    link_post_commit_class_digests[previous_slot],
                    *link_classes[previous_slot].post_commit_class_digest(),
                    "step {step}: beta-selected previous post-commit identity",
                );
                assert_eq!(
                    tip_block_accumulator_split(class, prev)
                        .expect("previous Link accumulator lanes"),
                    decode_accumulator(block_envelopes[step].io(), BLOCK_IO_START_ACC),
                    "step {step}: direct accumulator pass-through before recursion",
                );
            }
            let input = SplitLinkInput {
                prev,
                prev_slot: previous_slot,
                genesis,
                link_class_digests: link_class_digests.clone(),
                link_post_commit_class_digests: link_post_commit_class_digests.clone(),
                block: &block_envelopes[step],
                fold_matrix_link,
                fold_matrix_block: block_refs[slot],
            };
            let built = build_split_link(class, &input);
            assert_eq!(built.r1cs.m, CANONICAL_LINK_CLASS_M);
            assert!(
                built.r1cs.useful_rows <= 1usize << CANONICAL_LINK_CLASS_M,
                "step {step}: L-B{tier} exceeds m{CANONICAL_LINK_CLASS_M}",
            );
            assert!(
                built.r1cs.satisfies(&built.witness),
                "step {step}: recursive L-B{tier} relation",
            );

            let layout = class.layout();
            assert_eq!(
                built.io[layout.g],
                if genesis { F128::ONE } else { F128::ZERO },
                "step {step}: g must be one on the first Link only",
            );
            for lane_slot in 0..CanonicalSplitLinkLadder::SLOT_COUNT {
                let expected_link_live = if step == 0 {
                    false
                } else {
                    step_slots[..step].contains(&lane_slot)
                };
                let expected_block_live = step_slots[..=step].contains(&lane_slot);
                assert_eq!(
                    built.io[layout.link_lanes[lane_slot].live],
                    if expected_link_live {
                        F128::ONE
                    } else {
                        F128::ZERO
                    },
                    "step {step}: Link lane {lane_slot} liveness",
                );
                assert_eq!(
                    built.io[layout.b_lanes[lane_slot].live],
                    if expected_block_live {
                        F128::ONE
                    } else {
                        F128::ZERO
                    },
                    "step {step}: Block lane {lane_slot} liveness",
                );
            }

            let mut challenger = FsLaneChallenger::new(LINK_DOMAIN);
            let envelope = prove_built_split_link(class, &built, &mut challenger)
                .unwrap_or_else(|error| panic!("step {step}: L-B{tier} proof failed: {error}"));
            let mut challenger = FsLaneChallenger::new(LINK_DOMAIN);
            verify_split_link_proof(class, &built.r1cs, &envelope, &mut challenger)
                .unwrap_or_else(|error| panic!("step {step}: L-B{tier} verify failed: {error}"));
            assert_eq!(
                tip_block_accumulator_split(class, &envelope)
                    .expect("Link accumulator output lanes"),
                expected_end_accumulators[step],
                "step {step}: direct recursive accumulator boundary",
            );
            let useful_rows = built.r1cs.useful_rows;
            let mut matrix = built.r1cs;
            // As in the Block phase, retain CSR but release the verification
            // cache.  Only the final tip matrix rebuilds CSC inside the final
            // native proof verification.
            matrix.release_csc_cache();
            (envelope, matrix, useful_rows)
        };

        let envelope_bytes = envelope.byte_len();
        if let Some(expected) = common_link_envelope_bytes {
            assert_eq!(
                envelope_bytes, expected,
                "step {step}: universal Link envelope length changed at L-B{tier}",
            );
        } else {
            common_link_envelope_bytes = Some(envelope_bytes);
        }
        let matrix_digest = matrix.statement_digest();
        if let Some(representative) = &link_matrices[slot] {
            assert_eq!(
                representative.statement_digest(),
                matrix_digest,
                "step {step}: L-B{tier} matrix drift",
            );
        } else {
            link_matrices[slot] = Some(matrix);
            seen_link_class[slot] = true;
        }
        link_matrix_digests[step] = matrix_digest;
        metrics[step].link_rows = useful_rows;
        metrics[step].link_envelope_bytes = envelope_bytes;
        metrics[step].link_seconds = link_started.elapsed().as_secs_f64();
        previous_link = Some(envelope);
        previous_slot = slot;
    }
    assert!(seen_link_class.into_iter().all(|seen| seen));
    for &step in &B255_STEPS[1..] {
        assert_eq!(
            link_matrix_digests[step], link_matrix_digests[first_b255_step],
            "L-B255 matrix must be invariant across the 65/131/255 live counts",
        );
        assert_eq!(
            metrics[step].link_envelope_bytes, metrics[first_b255_step].link_envelope_bytes,
            "L-B255 envelope length must be invariant across the 65/131/255 live counts",
        );
    }

    let final_slot = *step_slots.last().expect("non-empty chain");
    let tip_class = &link_classes[final_slot];
    let tip_matrix = link_matrices[final_slot]
        .as_ref()
        .expect("tip Link class matrix");
    let tip = previous_link.as_ref().expect("recursive Link tip");
    let tip_layout = tip_class.layout();
    let link_matrix_refs: [Option<&FieldR1cs>; CanonicalSplitLinkLadder::SLOT_COUNT] =
        std::array::from_fn(|slot| {
            if tip.io()[tip_layout.link_lanes[slot].live] == F128::ONE {
                Some(
                    link_matrices[slot]
                        .as_ref()
                        .expect("every live Link lane has its class matrix"),
                )
            } else {
                None
            }
        });
    let block_matrix_refs: [Option<&FieldR1cs>; CanonicalSplitLinkLadder::SLOT_COUNT] =
        std::array::from_fn(|slot| {
            if tip.io()[tip_layout.b_lanes[slot].live] == F128::ONE {
                Some(block_refs[slot])
            } else {
                None
            }
        });
    assert_eq!(
        link_matrix_refs
            .iter()
            .map(Option::is_some)
            .collect::<Vec<_>>(),
        vec![true, true, true, true],
        "the 131 and 255 steps recursively replay the already-live L-B255 lane",
    );
    assert!(
        block_matrix_refs.iter().all(Option::is_some),
        "the capstone must exercise every live Block matrix lane",
    );

    let genesis_header = noid_chain::consensus::genesis_header();
    let decider_started = Instant::now();
    decide_block_tip_split(
        tip_class,
        tip_matrix,
        tip,
        &link_class_digests,
        &link_post_commit_class_digests,
        &link_matrix_refs,
        &block_matrix_refs,
        &local_tip_header,
        &genesis_header,
    )
    .expect("honest B8 -> B32 -> B64 -> B255 native tip decider");
    let tip_accumulator =
        tip_block_accumulator_split(tip_class, tip).expect("final accumulator lanes");
    assert_eq!(
        tip_accumulator,
        *expected_end_accumulators.last().expect("final accumulator"),
        "final Link accumulator equals the accepted Block accumulator",
    );
    assert_eq!(
        tip_accumulator.tip_block_id,
        noid_chain::hash_block_header(&local_tip_header),
        "final accumulator is anchored to the local tip header",
    );
    assert_eq!(tip_accumulator.state_root, local_tip_header.state_root);

    println!("\ncapstone proof summary:");
    println!(
        "  step  user  class     Block rows / envelope       Link rows / envelope       seconds"
    );
    for (step, metric) in metrics.iter().enumerate() {
        println!(
            "  {step:>4}  {:>4}  B{:<3}  {:>11} / {:>10}  {:>11} / {:>10}  {:>8.3} + {:>8.3}",
            user_counts[step],
            TIERS[step_slots[step]],
            metric.block_rows,
            fmt_bytes(metric.block_envelope_bytes),
            metric.link_rows,
            fmt_bytes(metric.link_envelope_bytes),
            metric.block_seconds,
            metric.link_seconds,
        );
    }
    println!(
        "  universal Link envelope length: {} ({})",
        common_link_envelope_bytes.expect("at least one Link envelope"),
        fmt_bytes(common_link_envelope_bytes.expect("at least one Link envelope")),
    );
    println!(
        "  native final decider:            {:>8.3} s",
        decider_started.elapsed().as_secs_f64(),
    );
    if let Some(memory) = current_mem_snapshot() {
        println!(
            "  process memory:                  RSS {:>9.1} MiB  HWM {:>9.1} MiB",
            memory.rss_mb(),
            memory.hwm_mb(),
        );
    }
}
