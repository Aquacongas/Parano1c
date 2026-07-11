// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Recording-free production handoff for wallet/meta A/B and main FRICHANL C.
//! All five authorities run after the enclosing witness commitment on the
//! same typestate challenger and append into its one private Field PCS sink.

use noid_chain::exact_state_hash::{slot_leaf_hash, StateHash};
use noid_chain::sparse_merkle::{derive_structural_frontier_plan, evaluate_structural_frontier};
use noid_chain::SlotValue;
use noid_core::Block128;
use noid_fri_binius::capsule::{CAPSULE_LOG_RATE, CAPSULE_TAU};
use noid_gkr::auth_pcs::{commit_auth_mle_column, open_auth_mle_committed, AuthMleOpeningProof};
use noid_gkr::batch_eval::BatchEvalReduction;
use noid_gkr::state_leaf_killshot::SlotLeafInputs;
use noid_ivc_core::challenger::{Challenger, FsLaneChallenger};
use noid_ivc_core::deep_chain::schedule::{
    build_merkle_path_columns, compile_duplex, LaneSource, MerklePathFamily, MerklePathWitness,
};
use noid_ivc_core::deep_chain::source_tree::compress_iv_flat;
use noid_ivc_core::deep_chain::spine::{
    build_spine_instance_columns, SpineInstanceFlat, SPINE_TREE_LEAVES,
};
use noid_ivc_core::field::F128;
use noid_ivc_core::field_circuit::{FieldR1csBuilder, LinExpr};
use noid_ivc_core::pcs::{self, PcsParams};
use noid_ivc_core::public_io::{PublicIoSpec, WitnessSlice};
use noid_ivc_core::verifier::{verify_field_with_public_io_and_post_commit_context, VerifyError};
use noid_ivc_prover::field_prover::prove_field_with_public_io_and_post_commit_context;
use noid_recursive::acceptance::region::capsule_pcs_channel_schedule;
use noid_recursive::acceptance::trace::exact_state::build_exact_state_structural_region_slot;
use noid_recursive::acceptance::trace::owner_auth::PendingAuthPcsObligation;
use noid_recursive::acceptance::trace::region_source_binding::{
    auth_pcs_main_c_sidecar_purpose, auth_pcs_meta_a_sidecar_purpose,
    auth_pcs_meta_b_sidecar_purpose, auth_pcs_wallet_a_sidecar_purpose,
    auth_pcs_wallet_b_sidecar_purpose, prepare_auth_pcs_obligations_via_region_with_paired_handoff,
    RegionDischargeParams, SpineInstanceRegion, SpineRegionData, TxRootPathRegion,
    TxRootRegionData,
};
use noid_recursive::acceptance::trace::{alloc_block, alloc_blocks, BatchEvalReductionTrace};
use noid_recursive::block_certificate_backend::ExactStateStructuralFrontierInputs;
use noid_recursive::region_sidecar::{
    verify_duplex_region_sidecar, verify_merkle_region_sidecar, verify_walk_a_region_sidecar,
    DuplexRegionSidecarProof, MerkleRegionSidecarProof, WalkARegionDescriptor,
    WalkARegionSidecarProof,
};

const FIELD_DOMAIN: &[u8] = b"auth-pcs-region-preparation-e2e-v1";
const CLASS_DIGEST: [u8; 32] = [0xA7; 32];

struct Rng(u64);

impl Rng {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    }

    fn block(&mut self) -> Block128 {
        Block128::from(((self.next_u64() as u128) << 64) | self.next_u64() as u128)
    }
}

fn capsule_fixture(num_vars: usize) -> (Vec<Block128>, BatchEvalReduction, AuthMleOpeningProof) {
    use noid_core::mle::evaluate::evaluate_slice;

    let mut rng = Rng(0xA55E_C0DE);
    let column = (0..1usize << num_vars)
        .map(|_| rng.block())
        .collect::<Vec<_>>();
    let point = (0..num_vars).map(|_| rng.block()).collect::<Vec<_>>();
    let reduction = BatchEvalReduction {
        value: evaluate_slice(&column, &point),
        point: point.clone(),
    };
    let mut committed = commit_auth_mle_column(&column, num_vars);
    let proof = open_auth_mle_committed(&mut committed, num_vars, &reduction);
    (point, reduction, proof)
}

fn f128(value: u128) -> F128 {
    F128 {
        lo: value as u64,
        hi: (value >> 64) as u64,
    }
}

fn digest_fields(digest: StateHash) -> [Block128; 2] {
    [
        Block128::from(u128::from_le_bytes(digest[..16].try_into().unwrap())),
        Block128::from(u128::from_le_bytes(digest[16..].try_into().unwrap())),
    ]
}

fn structural_leaf(seed: u128) -> SlotLeafInputs {
    let slot = SlotValue {
        value: Block128::from(seed),
        owner_hi: Block128::from(seed.wrapping_mul(17)),
        owner_lo: Block128::from(seed.wrapping_mul(29)),
    };
    SlotLeafInputs {
        packed_value: slot.value,
        owner_hi: slot.owner_hi,
        owner_lo: slot.owner_lo,
        expected_leaf: digest_fields(slot_leaf_hash(slot)),
    }
}

fn fields_digest(fields: [Block128; 2]) -> StateHash {
    let mut digest = [0u8; 32];
    digest[..16].copy_from_slice(&fields[0].0.to_le_bytes());
    digest[16..].copy_from_slice(&fields[1].0.to_le_bytes());
    digest
}

fn structural_frontier() -> ExactStateStructuralFrontierInputs {
    let touched_indices = vec![0];
    let active_depth = 24;
    let old_slot_leaves = vec![structural_leaf(11)];
    let new_slot_leaves = vec![structural_leaf(19)];
    let plan = derive_structural_frontier_plan(&touched_indices, active_depth).unwrap();
    let live_sibling_digests = (0..plan.frontier_positions().len())
        .map(|ordinal| {
            slot_leaf_hash(SlotValue {
                value: Block128::from(100 + ordinal as u128),
                owner_hi: Block128::from(200 + ordinal as u128),
                owner_lo: Block128::from(300 + ordinal as u128),
            })
        })
        .collect::<Vec<_>>();
    let old = evaluate_structural_frontier(
        &plan,
        &[fields_digest(old_slot_leaves[0].expected_leaf)],
        &live_sibling_digests,
    )
    .unwrap();
    let new = evaluate_structural_frontier(
        &plan,
        &[fields_digest(new_slot_leaves[0].expected_leaf)],
        &live_sibling_digests,
    )
    .unwrap();
    ExactStateStructuralFrontierInputs {
        touched_indices,
        active_depth,
        old_slot_leaves,
        new_slot_leaves,
        live_sibling_digests,
        old_combine_digests: old.combines,
        new_combine_digests: new.combines,
        old_root: old.root,
        new_root: new.root,
    }
}

fn alloc_raw_digest(builder: &mut FieldR1csBuilder, digest: &[u8; 32]) -> [LinExpr; 2] {
    [
        LinExpr::from_wire(
            builder.alloc_f128(f128(u128::from_le_bytes(digest[..16].try_into().unwrap()))),
        ),
        LinExpr::from_wire(
            builder.alloc_f128(f128(u128::from_le_bytes(digest[16..].try_into().unwrap()))),
        ),
    ]
}

fn alloc_pair(builder: &mut FieldR1csBuilder, values: [F128; 2]) -> [LinExpr; 2] {
    std::array::from_fn(|lane| LinExpr::from_wire(builder.alloc_f128(values[lane])))
}

struct FiveSidecars {
    wallet_a: WalkARegionSidecarProof,
    meta_a: WalkARegionSidecarProof,
    wallet_b: MerkleRegionSidecarProof,
    meta_b: MerkleRegionSidecarProof,
    main_c: DuplexRegionSidecarProof,
    claim_counts: [usize; 5],
    post_state: F128,
}

#[test]
fn five_auth_pcs_verticals_share_one_postcommit_context_and_outer_batch() {
    let num_vars = 9;
    let (point, reduction, native) = capsule_fixture(num_vars);
    let mut builder = FieldR1csBuilder::new();
    builder.alloc_f128(F128::ONE); // one stable public-IO cell

    let obligation = PendingAuthPcsObligation {
        commitment_cap_lanes: native
            .commitment
            .cap
            .hashes
            .iter()
            .map(|digest| alloc_raw_digest(&mut builder, digest))
            .collect(),
        num_vars,
        reduction: BatchEvalReductionTrace {
            point: alloc_blocks(&mut builder, &point),
            value: alloc_block(&mut builder, reduction.value),
        },
    };

    let (_, exact_state) =
        build_exact_state_structural_region_slot(&mut builder, &structural_frontier(), 1, 1)
            .unwrap();

    let spine_flat = SpineInstanceFlat::ghost();
    let spine_columns = build_spine_instance_columns(&spine_flat);
    let spine = SpineRegionData {
        instances: vec![SpineInstanceRegion {
            leaves_w: std::array::from_fn(|leaf| alloc_pair(&mut builder, spine_flat.leaves[leaf])),
            tx_hash_w: alloc_pair(&mut builder, spine_columns.tx_hash),
            tx_hash_flat: spine_columns.tx_hash,
            flat: spine_flat,
        }],
    };
    assert_eq!(spine.instances[0].leaves_w.len(), SPINE_TREE_LEAVES);

    let entry_flat = spine.instances[0].tx_hash_flat;
    let zero_sibling = [F128::ZERO; 2];
    let tx_root_columns = build_merkle_path_columns(
        &MerklePathFamily {
            depth: 1,
            n_paths: 1,
        },
        compress_iv_flat(),
        &[MerklePathWitness {
            entry: entry_flat,
            siblings: vec![zero_sibling],
            directions: vec![false],
        }],
        1,
    );
    let root_flat = tx_root_columns.roots[0];
    let tx_root = TxRootRegionData {
        depth: 1,
        root_w: alloc_pair(&mut builder, root_flat),
        root_flat,
        paths: vec![TxRootPathRegion {
            entry_w: spine.instances[0].tx_hash_w.clone(),
            entry_flat,
            siblings: vec![zero_sibling],
        }],
        rim_flat: Vec::new(),
    };

    let preparation = prepare_auth_pcs_obligations_via_region_with_paired_handoff(
        &mut builder,
        std::slice::from_ref(&obligation),
        std::slice::from_ref(&native),
        RegionDischargeParams { nq: 1 },
        &exact_state,
        &tx_root,
        &spine,
    );

    assert_eq!(
        preparation.wallet_a_vk.purpose(),
        &auth_pcs_wallet_a_sidecar_purpose()
    );
    assert_eq!(
        preparation.meta_a_vk.purpose(),
        &auth_pcs_meta_a_sidecar_purpose()
    );
    assert_eq!(
        preparation.wallet_b_vk.purpose(),
        &auth_pcs_wallet_b_sidecar_purpose()
    );
    assert_eq!(
        preparation.meta_b_vk.purpose(),
        &auth_pcs_meta_b_sidecar_purpose()
    );
    assert_eq!(
        preparation.main_c_vk.purpose(),
        &auth_pcs_main_c_sidecar_purpose()
    );
    assert!(matches!(
        preparation.wallet_a_vk.descriptor(),
        WalkARegionDescriptor::Wallet { .. }
    ));
    assert!(matches!(
        preparation.meta_a_vk.descriptor(),
        WalkARegionDescriptor::Meta {
            exact_state_region_log: Some(_),
            spine_cap_log: Some(_),
            ..
        }
    ));

    let all_slices = preparation
        .wallet_a_vk
        .slices()
        .iter()
        .chain(preparation.meta_a_vk.slices())
        .chain(preparation.wallet_b_vk.slices())
        .chain(preparation.meta_b_vk.slices())
        .chain(preparation.main_c_vk.slices())
        .copied()
        .collect::<Vec<_>>();
    assert_eq!(all_slices.len(), 6 + 8 + 9 + 9 + 6);
    let mut starts = all_slices
        .iter()
        .map(WitnessSlice::start)
        .collect::<Vec<_>>();
    starts.sort_unstable();
    starts.dedup();
    assert_eq!(
        starts.len(),
        all_slices.len(),
        "exact slices must not alias"
    );
    assert_eq!(
        preparation.main_c_vk.fixed().len(),
        7,
        "main C is the one-region recording-free layout (no recording region/D)"
    );
    assert_eq!(preparation.paired.local.len(), 1);
    assert_eq!(preparation.paired.upper.len(), 1);

    let wallet_a_plan = preparation.wallet_a_prover_plan().unwrap();
    let meta_a_plan = preparation.meta_a_prover_plan().unwrap();
    let wallet_b_plan = preparation.wallet_b_prover_plan().unwrap();
    let meta_b_plan = preparation.meta_b_prover_plan().unwrap();
    let main_c_plan = preparation.main_c_prover_plan().unwrap();

    let (r1cs, witness) = builder.build();
    assert!(r1cs.satisfies(&witness));

    // Exact Stage-2 negatives: one paired exact-state committed cell and one
    // main-C absorb cell are statement-pinned in the outer R1CS.
    let paired_cell = preparation.paired.local[0].directions[0].terms[0].0 as usize;
    let mut bad_paired = witness.clone();
    bad_paired[paired_cell] += F128::ONE;
    assert!(!r1cs.satisfies(&bad_paired));

    let schedule = capsule_pcs_channel_schedule(&native, num_vars, &point);
    let layout = compile_duplex(&schedule.ops);
    assert_eq!(layout.challenges.len(), CAPSULE_TAU + 1 + 1);
    let (data_slot, data_lane) = layout
        .slots
        .iter()
        .enumerate()
        .find_map(|(slot, compiled)| {
            compiled
                .lanes
                .iter()
                .position(|source| matches!(source, Some(LaneSource::Data(0))))
                .map(|lane| (slot, lane))
        })
        .unwrap();
    let main_c_cell = preparation.main_c_vk.slices()[data_lane].start() + data_slot;
    let mut bad_main_c = witness.clone();
    bad_main_c[main_c_cell] += F128::ONE;
    assert!(!r1cs.satisfies(&bad_main_c));
    assert_eq!(layout.n_data, schedule.data_flat.len());
    assert!(num_vars + CAPSULE_LOG_RATE > CAPSULE_TAU);

    let pcs_params = PcsParams {
        m: r1cs.m + pcs::LOG_PACKING,
        log_inv_rate: 2,
        log_batch_size: 2,
        profile: Default::default(),
    };
    let spec = PublicIoSpec {
        io_slice: WitnessSlice {
            log2_len: 0,
            index: 0,
        },
        io_len: 1,
        claims: Vec::new(),
    };
    let io = vec![F128::ONE];
    let mut prover_challenger = FsLaneChallenger::new(FIELD_DOMAIN);
    let (field_proof, sidecars, commitment, _) = prove_field_with_public_io_and_post_commit_context(
        &r1cs,
        &witness,
        &pcs_params,
        &spec,
        &io,
        &CLASS_DIGEST,
        &mut prover_challenger,
        |context| {
            let witness = context.witness();
            let (wallet_a, claims) = wallet_a_plan.prove(witness, context).unwrap();
            context.append_claims(claims);
            let count_wallet_a = context.claim_count();
            let (meta_a, claims) = meta_a_plan.prove(witness, context).unwrap();
            context.append_claims(claims);
            let count_meta_a = context.claim_count();
            let (wallet_b, claims) = wallet_b_plan.prove(witness, context).unwrap();
            context.append_claims(claims);
            let count_wallet_b = context.claim_count();
            let (meta_b, claims) = meta_b_plan.prove(witness, context).unwrap();
            context.append_claims(claims);
            let count_meta_b = context.claim_count();
            let (main_c, claims) = main_c_plan.prove(witness, context).unwrap();
            context.append_claims(claims);
            let count_main_c = context.claim_count();
            FiveSidecars {
                wallet_a,
                meta_a,
                wallet_b,
                meta_b,
                main_c,
                claim_counts: [
                    count_wallet_a,
                    count_meta_a,
                    count_wallet_b,
                    count_meta_b,
                    count_main_c,
                ],
                post_state: context.sample_f128(),
            }
        },
    );
    assert!(sidecars
        .claim_counts
        .windows(2)
        .all(|pair| pair[0] < pair[1]));

    let mut verifier_challenger = FsLaneChallenger::new(FIELD_DOMAIN);
    verify_field_with_public_io_and_post_commit_context(
        &r1cs,
        &commitment,
        &field_proof,
        &spec,
        &io,
        &CLASS_DIGEST,
        &sidecars,
        &mut verifier_challenger,
        |proofs, context| {
            let total_vars = context.total_vars();
            let claims = verify_walk_a_region_sidecar(
                &preparation.wallet_a_vk,
                total_vars,
                &proofs.wallet_a,
                context,
            )
            .map_err(|_| VerifyError::Auxiliary)?;
            context.append_claims(claims);
            assert_eq!(context.claim_count(), proofs.claim_counts[0]);
            let claims = verify_walk_a_region_sidecar(
                &preparation.meta_a_vk,
                total_vars,
                &proofs.meta_a,
                context,
            )
            .map_err(|_| VerifyError::Auxiliary)?;
            context.append_claims(claims);
            assert_eq!(context.claim_count(), proofs.claim_counts[1]);
            let claims = verify_merkle_region_sidecar(
                &preparation.wallet_b_vk,
                total_vars,
                &proofs.wallet_b,
                context,
            )
            .map_err(|_| VerifyError::Auxiliary)?;
            context.append_claims(claims);
            assert_eq!(context.claim_count(), proofs.claim_counts[2]);
            let claims = verify_merkle_region_sidecar(
                &preparation.meta_b_vk,
                total_vars,
                &proofs.meta_b,
                context,
            )
            .map_err(|_| VerifyError::Auxiliary)?;
            context.append_claims(claims);
            assert_eq!(context.claim_count(), proofs.claim_counts[3]);
            let claims = verify_duplex_region_sidecar(
                &preparation.main_c_vk,
                total_vars,
                &proofs.main_c,
                context,
            )
            .map_err(|_| VerifyError::Auxiliary)?;
            context.append_claims(claims);
            assert_eq!(context.claim_count(), proofs.claim_counts[4]);
            assert_eq!(context.sample_f128(), proofs.post_state);
            Ok(())
        },
    )
    .expect("five sidecars verify in the enclosing Field PCS batch");
}
