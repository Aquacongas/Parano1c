// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! One-time canonical selected-recursive artifact generator.
//!
//! Builds the pinned class registry plus all nine canonical matrix
//! artifacts (T, four PreviousLink tiers, four CurrentBlock tiers) into an
//! artifact root, with per-stage terminal progress. Class relations are
//! content-invariant, so one deterministic floor member per Block class
//! reproduces the exact canonical matrices; every export is digest-checked,
//! and when a registry artifact already exists in the root its digest must
//! match the freshly rebuilt registry (the independent-rebuild gate) —
//! wrong or drifted generation cannot be installed.
//!
//! Usage: `noid-matrix-gen <artifact-root>` (default `./selected-recursive`).

use std::io::Write as _;
use std::time::Instant;

use bench_prover::{
    accepted_proved_user_block_fixture, tx8x2_scenario, AcceptedSingleBlockFixture,
};
use noid_ivc_prover::challenger::FsLaneChallenger;
use noid_ivc_prover::field_r1cs::FieldR1cs;
use noid_ivc_prover::pcs::{self, PcsParams};
use noid_ivc_prover::proof::FieldShape;
use noid_miner::{
    LocalSelectedRecursiveClassRegistryStore, LocalSelectedRecursiveMatrixSource,
    SelectedRecursiveMatrixArtifactIdentity, SelectedRecursiveMatrixKind, SelectedRecursiveTier,
};
use noid_recursive::acceptance::block_class::{
    build_selected_zk_block_proof_trace, prove_built_block, verify_block_proof, BlockClass,
    BlockProofEnvelope, BuiltBlock,
};
use noid_recursive::acceptance::link::SelectedZkBlockInput;
use noid_recursive::acceptance::split_link::{
    build_split_link, CanonicalSplitLinkLadder, SplitLinkClass, SplitLinkInput,
    SplitLinkSlotMaterial, CANONICAL_BLOCK_CLASS_MS, CANONICAL_LINK_CLASS_M,
    CANONICAL_PCS_LOG_BATCH_SIZE, CANONICAL_PCS_LOG_INV_RATE,
};

const BLOCK_DOMAIN: &[u8] = b"history-block-v0";
const K_SKIP: usize = 6;
const TIERS: [usize; 4] = noid_chain::consensus::params::USER_TX_CLASS_TIERS;
const SELECTED_TIERS: [SelectedRecursiveTier; 4] = [
    SelectedRecursiveTier::B8,
    SelectedRecursiveTier::B32,
    SelectedRecursiveTier::B64,
    SelectedRecursiveTier::B255,
];
/// Deterministic generation seed: the canonical floor members below are
/// protocol tooling constants, not secrets. Content does not affect the
/// exported matrices (content-invariance), only reproducibility of the run.
const FIXTURE_SEED_BASE: u128 = 0xB10C_C1A5_0000;

fn stage(step: usize, total: usize, label: &str) -> Instant {
    println!("[{step}/{total}] {label}...");
    std::io::stdout().flush().expect("flush progress");
    Instant::now()
}

fn done(started: Instant) {
    println!("        done in {:.1} s", started.elapsed().as_secs_f64());
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

fn tier_floor_user_txs(tier: usize) -> usize {
    match tier {
        8 => 1,
        32 => 9,
        64 => 33,
        255 => 65,
        _ => unreachable!("canonical tier"),
    }
}

fn floor_fixture(tier: usize) -> AcceptedSingleBlockFixture {
    let count = tier_floor_user_txs(tier);
    let scenarios = (0..count)
        .map(|index| {
            tx8x2_scenario(
                "matrix-gen-floor",
                noid_tx::TX_INPUTS,
                noid_tx::TX_OUTPUTS,
                u32::try_from(index * 2_048).expect("fixture slot base"),
                FIXTURE_SEED_BASE + ((tier as u128) << 32) + index as u128,
            )
        })
        .collect();
    let fixture = accepted_proved_user_block_fixture(scenarios);
    assert_eq!(
        noid_chain::consensus::params::user_tx_class_tier(count),
        Some(tier),
        "floor member must select its own class",
    );
    fixture
}

fn selected_block_input<const TIER: usize>(
    fixture: &AcceptedSingleBlockFixture,
) -> SelectedZkBlockInput<'_, TIER> {
    SelectedZkBlockInput::try_new(
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
            .expect("fresh canonical selected ghost proof"),
    )
    .expect("canonical selected Block input")
}

fn freeze_block_class(
    fixture: &AcceptedSingleBlockFixture,
    tier: usize,
    params: PcsParams,
) -> BlockClass {
    match tier {
        8 => BlockClass::freeze_selected_zk(params, selected_block_input::<8>(fixture)),
        32 => BlockClass::freeze_selected_zk(params, selected_block_input::<32>(fixture)),
        64 => BlockClass::freeze_selected_zk(params, selected_block_input::<64>(fixture)),
        255 => BlockClass::freeze_selected_zk(params, selected_block_input::<255>(fixture)),
        _ => unreachable!("canonical tier"),
    }
}

fn build_block_trace(
    class: &BlockClass,
    fixture: &AcceptedSingleBlockFixture,
    tier: usize,
) -> BuiltBlock {
    match tier {
        8 => build_selected_zk_block_proof_trace(class, selected_block_input::<8>(fixture)),
        32 => build_selected_zk_block_proof_trace(class, selected_block_input::<32>(fixture)),
        64 => build_selected_zk_block_proof_trace(class, selected_block_input::<64>(fixture)),
        255 => build_selected_zk_block_proof_trace(class, selected_block_input::<255>(fixture)),
        _ => unreachable!("canonical tier"),
    }
}

fn export_matrix(
    store: &LocalSelectedRecursiveMatrixSource,
    kind: SelectedRecursiveMatrixKind,
    matrix: &FieldR1cs,
    expected_digest: [u8; 32],
) {
    let digest = matrix.statement_digest();
    assert_eq!(
        digest, expected_digest,
        "canonical {kind:?} matrix digest drifted from its frozen class identity",
    );
    let identity =
        SelectedRecursiveMatrixArtifactIdentity::new(kind, FieldShape::of(matrix), digest);
    store
        .export_matrix(identity, matrix)
        .expect("export canonical matrix artifact");
    println!("        {kind:?}: {}", hex::encode(digest));
}

fn main() {
    let _ = noid_ivc_prover::init_perf_thread_pool();
    let root = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "selected-recursive".into());
    let total = 6usize;
    println!("PARANOID canonical matrix generator");
    println!("  artifact root:  {root}");
    println!("  rayon threads:  {}", rayon::current_num_threads());
    println!("  one-time cost:  minutes; every later node start is instant");

    let registry_store = LocalSelectedRecursiveClassRegistryStore::new(&root);
    let matrix_store = LocalSelectedRecursiveMatrixSource::new(&root);

    // [1] Deterministic floor members, one per Block class.
    let t = stage(1, total, "building four canonical floor members");
    let fixtures: Vec<AcceptedSingleBlockFixture> =
        TIERS.iter().map(|&t| floor_fixture(t)).collect();
    done(t);

    // [2] Freeze the four Block classes.
    let t = stage(2, total, "freezing B8/B32/B64/B255 classes");
    let block_classes: Vec<BlockClass> = TIERS
        .iter()
        .zip(&fixtures)
        .map(|(&tier, fixture)| {
            freeze_block_class(
                fixture,
                tier,
                pcs_params(
                    CANONICAL_BLOCK_CLASS_MS[TIERS.iter().position(|c| *c == tier).unwrap()],
                ),
            )
        })
        .collect();
    done(t);

    // [3] Build, export, and prove one member per class.
    let t = stage(3, total, "building and exporting the four Block matrices");
    let mut block_matrices: Vec<FieldR1cs> = Vec::with_capacity(4);
    let mut block_envelopes: Vec<BlockProofEnvelope> = Vec::with_capacity(4);
    for (slot, (&tier, fixture)) in TIERS.iter().zip(&fixtures).enumerate() {
        let built = build_block_trace(&block_classes[slot], fixture, tier);
        assert!(built.r1cs.satisfies(&built.witness), "B{tier} floor member");
        // Proving validates the built matrix against the frozen class
        // identity before anything is exported.
        let mut challenger = FsLaneChallenger::new(BLOCK_DOMAIN);
        let envelope = prove_built_block(&block_classes[slot], &built, &mut challenger)
            .expect("prove canonical floor member");
        let mut verifier = FsLaneChallenger::new(BLOCK_DOMAIN);
        verify_block_proof(&block_classes[slot], &built.r1cs, &envelope, &mut verifier)
            .expect("verify canonical floor member");
        let digest = built.r1cs.statement_digest();
        export_matrix(
            &matrix_store,
            SelectedRecursiveMatrixKind::CurrentBlock(SELECTED_TIERS[slot]),
            &built.r1cs,
            digest,
        );
        block_envelopes.push(envelope);
        let mut matrix = built.r1cs;
        matrix.release_csc_cache();
        block_matrices.push(matrix);
    }
    drop(fixtures);
    done(t);

    // [4] Freeze the Link ladder (builds and proves the canonical T once).
    let t = stage(4, total, "freezing the four-slot Link ladder and T");
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
    .expect("canonical four-slot ladder descriptor");
    let materials: [SplitLinkSlotMaterial<'_>; CanonicalSplitLinkLadder::SLOT_COUNT] =
        std::array::from_fn(|slot| SplitLinkSlotMaterial {
            block_class: &block_classes[slot],
            sample_block: &block_envelopes[slot],
            block_matrix: &block_matrices[slot],
        });
    let link_classes: [SplitLinkClass; 4] = ladder.freeze_all(materials);
    done(t);

    // [5] Registry: export fresh, or verify byte-digest identity when one
    // is already installed (the independent-rebuild gate).
    let t = stage(5, total, "pinning the class registry");
    let registry_path = registry_store.artifact_path();
    let block_class_array: &[BlockClass; 4] = block_classes
        .as_slice()
        .try_into()
        .expect("four canonical Block classes");
    if registry_path.is_file() {
        let existing = std::fs::read(&registry_path).expect("read installed registry");
        let existing_digest: [u8; 32] = existing[existing.len() - 32..]
            .try_into()
            .expect("registry trailer digest");
        let fresh = noid_recursive::encode_selected_recursive_class_registry(
            block_class_array,
            &ladder,
            &link_classes,
        )
        .expect("encode rebuilt registry");
        let fresh_digest: [u8; 32] = fresh[fresh.len() - 32..]
            .try_into()
            .expect("rebuilt registry trailer digest");
        assert_eq!(
            existing_digest, fresh_digest,
            "installed registry does not match the independently rebuilt one",
        );
        println!("        installed registry digest reproduced independently");
    } else {
        registry_store
            .export(block_class_array, &ladder, &link_classes)
            .expect("export pinned class registry");
    }
    let installed = std::fs::read(&registry_path).expect("read pinned registry");
    let registry_digest = hex::encode(&installed[installed.len() - 32..]);
    println!("        registry digest: {registry_digest}");
    done(t);

    // [6] The five Link-family matrices: T plus one derivation build per slot.
    let t = stage(
        6,
        total,
        "building and exporting T and the four Link matrices",
    );
    let genesis_matrix = link_classes[0]
        .rebuild_genesis_matrix()
        .expect("rebuild canonical T matrix");
    export_matrix(
        &matrix_store,
        SelectedRecursiveMatrixKind::GenesisLink,
        &genesis_matrix,
        link_classes[0].genesis_digest,
    );
    for (slot, link_class) in link_classes.iter().enumerate() {
        let input = SplitLinkInput {
            prev: link_class.genesis_envelope(),
            prev_slot: 0,
            genesis: true,
            // Matrix-derivation build: whitelist digests are witness data
            // and do not shape the relation.
            link_class_digests: vec![[0u8; 32]; CanonicalSplitLinkLadder::SLOT_COUNT],
            link_post_commit_class_digests: vec![[0u8; 32]; CanonicalSplitLinkLadder::SLOT_COUNT],
            block: &block_envelopes[slot],
            fold_matrix_link: &genesis_matrix,
            fold_matrix_block: &block_matrices[slot],
        };
        let built = build_split_link(link_class, &input);
        let expected = *link_class
            .class_statement_digest
            .get()
            .expect("frozen Link class digest");
        export_matrix(
            &matrix_store,
            SelectedRecursiveMatrixKind::PreviousLink(SELECTED_TIERS[slot]),
            &built.r1cs,
            expected,
        );
    }
    done(t);

    println!("complete: pinned registry + 9 canonical matrices in {root}");
    println!("registry digest (release pin): {registry_digest}");
}
