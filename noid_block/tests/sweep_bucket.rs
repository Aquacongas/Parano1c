// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Sweep25x2 block-bucket binding tests.
//!
//! These tests exercise the lightweight bucket layer added before full mixed
//! block aggregation: wallet-produced sweep logic proofs are carried in a
//! `SweepBucketProof` and bound to concrete block transaction indices.

use noid_air::composition::tx_logic::{boundary_pins_from_body, witness_from_body, TxLogicAir};
use noid_air::Air;
use noid_block::{
    assemble_sweep_bucket_proof, block_recursive_claim_hash, build_state_bindings_from_binding,
    build_tx_witness, extract_replay_witness, prove_block_with_total_tx_count,
    prove_state_bindings_standalone, validate_block_bucket_tx_indices,
    validate_block_proof_transcript_hash, verify_state_bindings_standalone,
    verify_sweep_bucket_from_block, BlockProof, BlockPublicMeta, OwnedTxWitness, TxBlockWitness,
    BLOCK_BASE_LOG,
};
use noid_chain::block::Block;
use noid_chain::block_header::BlockHeader;
use noid_chain::consensus::params::GENESIS_TARGET;
use noid_chain::segmented_state::SegmentColumns;
use noid_chain::state::ChainState;
use noid_chain::state_binding::BlockStateBinding;
use noid_core::mle::split::split_mle_into_slices;
use noid_core::{Block128, TowerField};
use noid_gkr::{
    auth_gkr_channel, build_auth_unified_from_inputs, compute_auth_boundary, prove_auth_killshot,
    AuthCircuit, AuthInputs, AuthProofKillShot, AuthPublicInputs, SpineInputs, N_AUTH_INPUTS,
    N_AUTH_UNIFIED_VARS,
};
use noid_poseidon2b::primitives::{
    derive_address, hash_auth_tag, Address, AuthTag, SpendSecret, TxBodyHash,
};
use noid_recursive::{
    accumulator::genesis_accumulator, air::RecursiveBlockAir, prove::prove_recursive_step,
    verify::verify_recursive_step,
};
use noid_stark::prove_logic_sweep::{
    build_sweep_auth_slices, prove_sweep_logic, sweep_logic_witness_parts_from_body,
    SweepLogicWitness,
};
use noid_stark::{SweepWalletProofBundle, WalletProofBundle};
use noid_tx::{
    compute_claims_commitment, hash_tx_body_for_shape, PublicInputs, Transaction, TxBody, TxInput,
    TxOutput, TxShape, MAX_INPUTS, MAX_OUTPUTS,
};
use std::collections::HashMap;

const TEST_LOG_SLOTS: u32 = 24;

fn mk_secret(seed: u8) -> SpendSecret {
    let mut bytes = [0u8; 32];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = seed.wrapping_mul(19).wrapping_add(i as u8).wrapping_add(7);
    }
    SpendSecret(bytes)
}

fn mk_sweep_mint_body() -> TxBody {
    TxBody {
        shape: TxShape::Sweep25x2,
        epoch_anchor: [0x5A; 32],
        fee: 0,
        inputs: vec![],
        outputs: vec![TxOutput {
            slot_index: 7,
            value: 12_345,
            owner: Address([0xA1; 32]),
            valid: true,
        }],
        is_coinbase: false,
    }
}

fn mk_sweep_body(n_live_inputs: usize) -> TxBody {
    assert!(n_live_inputs <= TxShape::Sweep25x2.max_inputs());
    let mut inputs = Vec::with_capacity(n_live_inputs);
    for i in 0..n_live_inputs {
        let secret = mk_secret(i as u8 + 1);
        let owner = derive_address(&secret);
        inputs.push(TxInput {
            slot_index: 1_000 + i as u32,
            value: 10_000 + i as u64,
            owner,
            spend_secret: secret,
            auth_tag: AuthTag([0u8; 32]),
            valid: true,
        });
    }

    let total: u64 = inputs.iter().map(|i| i.value).sum();
    let fee = 777u64;
    let spendable = total - fee;

    let mut body = TxBody {
        shape: TxShape::Sweep25x2,
        epoch_anchor: [0x5A; 32],
        fee: fee as u128,
        inputs,
        outputs: vec![
            TxOutput {
                slot_index: 50_000,
                value: spendable / 2,
                owner: Address([0xA1; 32]),
                valid: true,
            },
            TxOutput {
                slot_index: 50_001,
                value: spendable - spendable / 2,
                owner: Address([0xA2; 32]),
                valid: true,
            },
        ],
        is_coinbase: false,
    };

    let tx_hash = hash_tx_body_for_shape(
        body.shape,
        &body.epoch_anchor,
        body.fee,
        &body.inputs,
        &body.outputs,
        body.is_coinbase,
    );
    for input in &mut body.inputs {
        input.auth_tag = hash_auth_tag(&input.spend_secret, &tx_hash);
    }

    body
}

fn public_inputs_for_body(body: &TxBody) -> PublicInputs {
    PublicInputs {
        epoch_anchor: body.epoch_anchor,
        tx_body_hash: hash_tx_body_for_shape(
            body.shape,
            &body.epoch_anchor,
            body.fee,
            &body.inputs,
            &body.outputs,
            body.is_coinbase,
        ),
        shape_id: body.shape.id(),
        fee: body.fee,
        n_live_inputs: body.inputs.iter().filter(|i| i.valid).count() as u8,
        n_live_outputs: body.outputs.iter().filter(|o| o.valid).count() as u8,
        coinbase_credit: 0,
        log_slots: TEST_LOG_SLOTS,
        claims_commitment: compute_claims_commitment(&body.inputs, &body.outputs),
        is_activation: [false; MAX_OUTPUTS],
        is_deactivation: [false; MAX_INPUTS],
    }
}

fn tx_from_body(body: TxBody) -> Transaction {
    let tx_body_hash = hash_tx_body_for_shape(
        body.shape,
        &body.epoch_anchor,
        body.fee,
        &body.inputs,
        &body.outputs,
        body.is_coinbase,
    );
    Transaction { body, tx_body_hash }
}

fn coinbase_tx() -> Transaction {
    tx_from_body(TxBody {
        shape: TxShape::Standard4x8,
        epoch_anchor: [0u8; 32],
        fee: 0,
        inputs: vec![],
        outputs: vec![TxOutput {
            slot_index: 42,
            value: 5000,
            owner: Address([0xC0; 32]),
            valid: true,
        }],
        is_coinbase: true,
    })
}

fn block_with_user_tx(user_tx: Transaction) -> Block {
    Block {
        header: BlockHeader {
            prev_block_hash: [0u8; 32],
            state_root: [0u8; 32],
            tx_root: [0u8; 32],
            timestamp: 1,
            height: 1,
            miner_address: Address([0u8; 32]),
            nonce: 0,
            difficulty_target: GENESIS_TARGET,
            proof_transcript_hash: [0u8; 32],
            witness_root: [0u8; 32],
            log_slots: TEST_LOG_SLOTS,
            active_slot_count: 0,
            alloc_counter: 0,
        },
        transactions: vec![coinbase_tx(), user_tx],
    }
}

#[allow(dead_code)]
fn block_with_standard_and_sweep_tx(standard_tx: Transaction, sweep_tx: Transaction) -> Block {
    let mut block = block_with_user_tx(standard_tx);
    block.transactions.push(sweep_tx);
    block
}

#[allow(dead_code)]
fn mk_standard_secret(seed: u128) -> [Block128; 2] {
    [
        Block128::from(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ 0xA5A5_A5A5_A5A5_A5A5),
        Block128::from(seed.wrapping_mul(0xBF58_476D_1CE4_E5B9) ^ 0x5A5A_5A5A_5A5A_5A5A),
    ]
}

#[allow(dead_code)]
fn fields_to_bytes(f: [Block128; 2]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[..16].copy_from_slice(&f[0].to_u128().to_le_bytes());
    out[16..].copy_from_slice(&f[1].to_u128().to_le_bytes());
    out
}

#[allow(dead_code)]
struct StandardFixture {
    body: TxBody,
    air: TxLogicAir,
    trace: noid_air::Trace,
    pi: PublicInputs,
    spine_inputs: SpineInputs,
    auth_public: AuthPublicInputs,
    auth_proof: AuthProofKillShot,
    auth_slices: Vec<Vec<Block128>>,
}

#[allow(dead_code)]
fn standard_fixture() -> StandardFixture {
    standard_fixture_with_params(0xA1, 0, 10, 0xAA)
}

#[allow(dead_code)]
fn standard_fixture_with_params(
    seed_base: u128,
    input_slot_base: u32,
    output_slot_base: u32,
    epoch: u8,
) -> StandardFixture {
    let secrets = [
        mk_standard_secret(seed_base),
        mk_standard_secret(seed_base.wrapping_add(0x11)),
    ];
    let addrs: Vec<_> = secrets
        .iter()
        .map(|s| derive_address(&SpendSecret(fields_to_bytes(*s))))
        .collect();

    let mut inputs = vec![
        TxInput {
            slot_index: input_slot_base,
            value: 100,
            owner: addrs[0],
            spend_secret: SpendSecret(fields_to_bytes(secrets[0])),
            auth_tag: AuthTag([0u8; 32]),
            valid: true,
        },
        TxInput {
            slot_index: input_slot_base + 1,
            value: 50,
            owner: addrs[1],
            spend_secret: SpendSecret(fields_to_bytes(secrets[1])),
            auth_tag: AuthTag([0u8; 32]),
            valid: true,
        },
    ];
    while inputs.len() < MAX_INPUTS {
        inputs.push(TxInput::dummy());
    }

    let mut outputs = vec![
        TxOutput {
            slot_index: output_slot_base,
            value: 80,
            owner: addrs[0],
            valid: true,
        },
        TxOutput {
            slot_index: output_slot_base + 1,
            value: 60,
            owner: addrs[1],
            valid: true,
        },
    ];
    while outputs.len() < MAX_OUTPUTS {
        outputs.push(TxOutput::dummy());
    }

    let mut body = TxBody {
        shape: TxShape::Standard4x8,
        epoch_anchor: [epoch; 32],
        fee: 10,
        inputs,
        outputs,
        is_coinbase: false,
    };

    let pins = boundary_pins_from_body(&body);
    for i in 0..2 {
        body.inputs[i].auth_tag = hash_auth_tag(
            &SpendSecret(fields_to_bytes(secrets[i])),
            &TxBodyHash(fields_to_bytes(pins.tx_body_hash)),
        );
    }

    let pins = boundary_pins_from_body(&body);
    let air = TxLogicAir::new(pins);
    let trace = air.build_trace(&witness_from_body(&body));
    let mut is_activation = [false; MAX_OUTPUTS];
    for (j, output) in body.outputs.iter().enumerate().take(MAX_OUTPUTS) {
        is_activation[j] = output.valid;
    }
    let mut is_deactivation = [false; MAX_INPUTS];
    for (i, input) in body.inputs.iter().enumerate().take(MAX_INPUTS) {
        is_deactivation[i] = input.valid;
    }
    let pi = PublicInputs {
        epoch_anchor: body.epoch_anchor,
        tx_body_hash: TxBodyHash(fields_to_bytes(pins.tx_body_hash)),
        shape_id: body.shape.id(),
        fee: body.fee,
        n_live_inputs: body.inputs.iter().filter(|i| i.valid).count() as u8,
        n_live_outputs: body.outputs.iter().filter(|o| o.valid).count() as u8,
        coinbase_credit: 0,
        log_slots: TEST_LOG_SLOTS,
        claims_commitment: compute_claims_commitment(&body.inputs, &body.outputs),
        is_activation,
        is_deactivation,
    };
    let spine_inputs = SpineInputs {
        epoch_anchor: pins.epoch_anchor,
        fee_leaf: pins.fee_leaf,
        input_leaves: pins.input_leaf_absorb,
        output_leaves: pins.output_leaf_absorb,
        is_coinbase_leaf: pins.is_coinbase_leaf,
        pad_leaf: [Block128::ZERO; 2],
    };

    let mut spend_secret = [[Block128::ZERO; 2]; N_AUTH_INPUTS];
    for (dst, src) in spend_secret.iter_mut().zip(secrets.iter()) {
        *dst = *src;
    }
    let circuit = AuthCircuit::build();
    let (expected_address, expected_auth_tag) =
        compute_auth_boundary(&circuit, spend_secret, pi.tx_body_hash.as_fields());
    let auth_inputs = AuthInputs {
        spend_secret,
        tx_body_hash: pi.tx_body_hash.as_fields(),
        expected_address,
        expected_auth_tag,
    };
    let mut ch = auth_gkr_channel();
    let (auth_proof, _) = prove_auth_killshot(&circuit, &auth_inputs, &mut ch);
    let auth_mle = build_auth_unified_from_inputs(&circuit, &auth_inputs);
    let auth_slices = split_mle_into_slices(&auth_mle.state, N_AUTH_UNIFIED_VARS, BLOCK_BASE_LOG);

    StandardFixture {
        body,
        air,
        trace,
        pi,
        spine_inputs,
        auth_public: auth_inputs.to_public(),
        auth_proof,
        auth_slices,
    }
}

fn prove_sweep_bundle(body: &TxBody) -> WalletProofBundle {
    let pi = public_inputs_for_body(body);
    let (air, trace, auth_inputs, spine_inputs) = sweep_logic_witness_parts_from_body(body);
    assert!(air.check(&trace));
    let witness = SweepLogicWitness {
        air: &air,
        trace: &trace,
        pi: &pi,
        auth_inputs: &auth_inputs,
        spine_inputs: &spine_inputs,
    };
    let logic_proof = prove_sweep_logic(&witness).expect("prove sweep logic");
    let auth_slices = build_sweep_auth_slices(&auth_inputs);
    WalletProofBundle::Sweep25x2(SweepWalletProofBundle {
        logic_proof,
        auth_slices,
        auth_public: auth_inputs.to_public(),
    })
}

fn empty_bucketized_proof(n_tx: u32) -> BlockProof {
    BlockProof {
        meta: BlockPublicMeta {
            prev_block_state_root: [0u8; 32],
            new_state_root: [0u8; 32],
            n_tx,
            n_air_per_tx: 0,
            n_auth_slices_per_tx: 0,
            log_rows: noid_air::airs::tx_body_spine::SPINE_LOG_ROWS as u32,
            n_block_spine_slices: 0,
            n_state_bindings: 0,
            state_binding_n_cols: 0,
            state_binding_log_rows: 0,
        },
        standard_bucket: None,
        sweep_bucket: None,
        state_binding_algebraics: vec![],
        state_binding_starks: vec![],
        pre_state_openings: vec![],
        post_state_openings: vec![],
    }
}

fn sweep_bucket_proof_for_body(body: TxBody) -> (Block, BlockProof) {
    let bundle = prove_sweep_bundle(&body);
    let block = block_with_user_tx(tx_from_body(body));
    let owned = noid_block::build_block_witnesses(&block.transactions, &[bundle], TEST_LOG_SLOTS);
    let sweep_witnesses: Vec<_> = owned
        .into_iter()
        .map(|w| match w {
            OwnedTxWitness::Sweep25x2(w) => w,
            OwnedTxWitness::Standard4x8(_) => panic!("expected sweep witness"),
        })
        .collect();
    assert_eq!(sweep_witnesses[0].block_tx_index, 1);

    let sweep_bucket = assemble_sweep_bucket_proof([0u8; 32], &sweep_witnesses)
        .expect("assemble sweep bucket")
        .expect("non-empty sweep bucket");

    let proof = BlockProof {
        meta: BlockPublicMeta {
            prev_block_state_root: [0u8; 32],
            new_state_root: [0u8; 32],
            n_tx: 1,
            n_air_per_tx: 0,
            n_auth_slices_per_tx: 0,
            log_rows: noid_air::airs::tx_body_spine::SPINE_LOG_ROWS as u32,
            n_block_spine_slices: 0,
            n_state_bindings: 0,
            state_binding_n_cols: 0,
            state_binding_log_rows: 0,
        },
        standard_bucket: None,
        sweep_bucket: Some(sweep_bucket),
        state_binding_algebraics: vec![],
        state_binding_starks: vec![],
        pre_state_openings: vec![],
        post_state_openings: vec![],
    };
    (block, proof)
}

#[allow(dead_code)]
fn block_with_user_txs(mut user_txs: Vec<Transaction>) -> Block {
    assert!(
        !user_txs.is_empty(),
        "test block needs at least one user tx"
    );
    let first = user_txs.remove(0);
    let mut block = block_with_user_tx(first);
    block.transactions.extend(user_txs);
    block
}

#[allow(dead_code)]
fn mixed_block_proof() -> (Block, BlockProof) {
    mixed_block_proof_with_counts(1, 1)
}

#[allow(dead_code)]
fn mixed_block_proof_with_counts(n_standard: usize, n_sweep: usize) -> (Block, BlockProof) {
    assert!(n_standard > 0, "mixed test needs at least one standard tx");
    assert!(n_sweep > 0, "mixed test needs at least one sweep tx");

    let standards: Vec<_> = (0..n_standard)
        .map(|i| {
            standard_fixture_with_params(
                0xA1 + (i as u128) * 0x20,
                (i as u32) * 10,
                100 + (i as u32) * 10,
                0xAAu8.wrapping_add(i as u8),
            )
        })
        .collect();
    let sweep_bodies: Vec<_> = (0..n_sweep).map(|i| mk_sweep_body(5 + i)).collect();

    let mut txs = Vec::with_capacity(n_standard + n_sweep);
    txs.extend(standards.iter().map(|s| tx_from_body(s.body.clone())));
    txs.extend(sweep_bodies.iter().cloned().map(tx_from_body));
    let block = block_with_user_txs(txs);

    let standard_witnesses: Vec<_> = standards
        .iter()
        .enumerate()
        .map(|(i, standard)| TxBlockWitness {
            block_tx_index: 1 + i as u32,
            air: &standard.air as &dyn Air,
            trace: &standard.trace,
            pi: &standard.pi,
            spine_inputs: &standard.spine_inputs,
            auth_public: &standard.auth_public,
            auth_proof: &standard.auth_proof,
            auth_slices: &standard.auth_slices,
        })
        .collect();
    let mut proof = prove_block_with_total_tx_count(
        [0u8; 32],
        [0u8; 32],
        &standard_witnesses,
        &[],
        (n_standard + n_sweep) as u32,
    )
    .expect("prove standard bucket for mixed block");

    let sweep_bundles: Vec<_> = sweep_bodies.iter().map(prove_sweep_bundle).collect();
    let sweep_witnesses: Vec<_> = sweep_bodies
        .iter()
        .zip(sweep_bundles.iter())
        .enumerate()
        .map(|(i, (body, bundle))| {
            match build_tx_witness(
                1 + n_standard as u32 + i as u32,
                body,
                bundle,
                TEST_LOG_SLOTS,
            ) {
                OwnedTxWitness::Sweep25x2(w) => w,
                OwnedTxWitness::Standard4x8(_) => panic!("expected sweep witness"),
            }
        })
        .collect();
    proof.sweep_bucket = Some(
        assemble_sweep_bucket_proof([0u8; 32], &sweep_witnesses)
            .expect("assemble sweep bucket")
            .expect("non-empty sweep bucket"),
    );

    (block, proof)
}

#[test]
fn canonical_recursive_claim_hash_is_deterministic_and_binds_meta() {
    let proof = empty_bucketized_proof(0);
    assert_eq!(
        block_recursive_claim_hash(&proof),
        block_recursive_claim_hash(&proof)
    );

    let mut tampered = proof.clone();
    tampered.meta.n_tx = 1;
    assert_ne!(
        block_recursive_claim_hash(&proof),
        block_recursive_claim_hash(&tampered)
    );
}

#[test]
fn proof_transcript_hash_mismatch_rejects() {
    let mut block = block_with_user_tx(tx_from_body(mk_sweep_mint_body()));
    let proof = empty_bucketized_proof(1);

    block.header.proof_transcript_hash = [0u8; 32];
    assert!(validate_block_proof_transcript_hash(&block, &proof).is_err());

    block.header.proof_transcript_hash = block_recursive_claim_hash(&proof);
    validate_block_proof_transcript_hash(&block, &proof).expect("matching hash accepts");
}

#[test]
#[cfg_attr(debug_assertions, ignore = "release-only sweep proof regression")]
fn sweep_bucket_assembles_and_verifies_from_owned_witness() {
    let (block, proof) = sweep_bucket_proof_for_body(mk_sweep_body(5));

    validate_block_bucket_tx_indices(&block, &proof).expect("bucket coverage");
    verify_sweep_bucket_from_block(&block, &proof).expect("sweep bucket verifies");

    let bucket = proof.sweep_bucket.as_ref().expect("sweep bucket");
    assert_eq!(bucket.meta.shape, TxShape::Sweep25x2);
    assert_eq!(bucket.meta.tx_indices, vec![1]);
    assert_eq!(bucket.tx_pis[0].shape_id, TxShape::Sweep25x2.id());
    assert_eq!(bucket.auth_slices.len(), 1);
    assert_eq!(
        bucket.meta.n_boundary_slices_per_tx as usize,
        bucket.auth_slices[0].len()
    );
    assert!(bucket.byte_len() > 0);

    let canonical_hash = block_recursive_claim_hash(&proof);
    let mut tampered = proof.clone();
    tampered.sweep_bucket.as_mut().unwrap().meta.tx_indices[0] = 2;
    assert_ne!(canonical_hash, block_recursive_claim_hash(&tampered));
}

#[test]
#[cfg_attr(debug_assertions, ignore = "release-only sweep proof regression")]
fn sweep_bucket_rejects_index_and_shape_tampering() {
    let (block, mut proof) = sweep_bucket_proof_for_body(mk_sweep_body(5));

    proof.sweep_bucket.as_mut().unwrap().meta.tx_indices[0] = 0;
    assert!(validate_block_bucket_tx_indices(&block, &proof).is_err());

    proof.sweep_bucket.as_mut().unwrap().meta.tx_indices[0] = 1;
    proof.sweep_bucket.as_mut().unwrap().tx_pis[0].shape_id = TxShape::Standard4x8.id();
    assert!(validate_block_bucket_tx_indices(&block, &proof).is_err());
}

#[test]
#[cfg_attr(debug_assertions, ignore = "release-only sweep proof regression")]
fn sweep_bucket_rejects_spine_tampering() {
    let (block, mut proof) = sweep_bucket_proof_for_body(mk_sweep_body(5));

    let bucket = proof.sweep_bucket.as_mut().unwrap();
    bucket.spine_inputs[0].output_leaves[0][0] += Block128::ONE;

    validate_block_bucket_tx_indices(&block, &proof).expect("coverage still intact");
    assert!(verify_sweep_bucket_from_block(&block, &proof).is_err());
}

#[test]
#[cfg_attr(debug_assertions, ignore = "release-only sweep proof regression")]
fn sweep_bucket_rejects_auth_slice_shape_tampering() {
    let (block, mut proof) = sweep_bucket_proof_for_body(mk_sweep_body(5));

    proof.sweep_bucket.as_mut().unwrap().auth_slices[0].pop();
    assert!(validate_block_bucket_tx_indices(&block, &proof).is_err());
}

#[test]
#[cfg_attr(debug_assertions, ignore = "release-only sweep proof regression")]
fn sweep_bucket_rejects_auth_slice_value_tampering() {
    let (block, mut proof) = sweep_bucket_proof_for_body(mk_sweep_body(5));

    for v in &mut proof.sweep_bucket.as_mut().unwrap().auth_slices[0][0] {
        *v += Block128::ONE;
    }
    validate_block_bucket_tx_indices(&block, &proof).expect("coverage still intact");
    assert!(verify_sweep_bucket_from_block(&block, &proof).is_err());
}

#[test]
#[cfg_attr(debug_assertions, ignore = "release-only sweep proof regression")]
fn sweep_bucket_rejects_aggregation_opening_tampering() {
    let (block, mut proof) = sweep_bucket_proof_for_body(mk_sweep_body(5));

    proof.sweep_bucket.as_mut().unwrap().block_col_openings[0] += Block128::ONE;
    validate_block_bucket_tx_indices(&block, &proof).expect("coverage still intact");
    assert!(verify_sweep_bucket_from_block(&block, &proof).is_err());
}

#[test]
#[cfg_attr(debug_assertions, ignore = "release-only sweep proof regression")]
fn sweep_bucket_rejects_block_initial_claim_tampering() {
    let (block, mut proof) = sweep_bucket_proof_for_body(mk_sweep_body(5));

    proof.sweep_bucket.as_mut().unwrap().block_initial_claim += Block128::ONE;
    validate_block_bucket_tx_indices(&block, &proof).expect("coverage still intact");
    assert!(verify_sweep_bucket_from_block(&block, &proof).is_err());
}

#[test]
#[cfg_attr(debug_assertions, ignore = "release-only sweep proof regression")]
fn sweep_bucket_rejects_block_multipoint_challenge_tampering() {
    let (block, mut proof) = sweep_bucket_proof_for_body(mk_sweep_body(5));

    proof
        .sweep_bucket
        .as_mut()
        .unwrap()
        .block_multipoint_challenges[0] += Block128::ONE;
    validate_block_bucket_tx_indices(&block, &proof).expect("coverage still intact");
    assert!(verify_sweep_bucket_from_block(&block, &proof).is_err());
}

#[test]
#[cfg_attr(debug_assertions, ignore = "release-only sweep proof regression")]
fn sweep_bucket_rejects_mixed_opening_tampering() {
    let (block, mut proof) = sweep_bucket_proof_for_body(mk_sweep_body(5));

    proof
        .sweep_bucket
        .as_mut()
        .unwrap()
        .mixed_opening
        .all_openings[0] += Block128::ONE;
    validate_block_bucket_tx_indices(&block, &proof).expect("coverage still intact");
    assert!(verify_sweep_bucket_from_block(&block, &proof).is_err());
}

#[test]
#[cfg_attr(debug_assertions, ignore = "release-only sweep proof regression")]
fn sweep_only_replay_witness_extracts_and_recursive_step_verifies() {
    let (mut block, proof) = sweep_bucket_proof_for_body(mk_sweep_body(5));
    block.header.proof_transcript_hash = block_recursive_claim_hash(&proof);

    let witness = extract_replay_witness(&proof).expect("sweep-only replay witness");
    let sweep_bucket = proof.sweep_bucket.as_ref().expect("sweep bucket");
    assert_eq!(
        witness.block_initial_claim,
        sweep_bucket.block_initial_claim
    );
    assert_eq!(
        witness.chain_claim,
        noid_block::block_recursive_claim_field(&proof)
    );
    assert_eq!(
        witness.block_multipoint_rounds,
        sweep_bucket.block_multipoint_rounds
    );

    let prev_acc = genesis_accumulator([0u8; 32], [0u8; 32]);
    let rec_proof = prove_recursive_step(&witness, &block.header, &prev_acc, None);
    let rec_air = RecursiveBlockAir::from_prev_state_root(&prev_acc.state_root);
    verify_recursive_step(&rec_proof, &prev_acc, &block.header, &rec_air)
        .expect("sweep-only recursive step verifies");
}

#[test]
#[cfg_attr(debug_assertions, ignore = "release-only mixed proof regression")]
fn mixed_replay_witness_extracts_secondary_lane_and_recursive_step_verifies() {
    let (mut block, proof) = mixed_block_proof();
    block.header.proof_transcript_hash = block_recursive_claim_hash(&proof);

    validate_block_bucket_tx_indices(&block, &proof).expect("mixed bucket coverage");
    verify_sweep_bucket_from_block(&block, &proof).expect("mixed sweep bucket verifies");
    validate_block_proof_transcript_hash(&block, &proof).expect("mixed header transcript hash");

    let standard_bucket = proof.standard_bucket.as_ref().expect("standard bucket");
    let sweep_bucket = proof.sweep_bucket.as_ref().expect("sweep bucket");
    let witness = extract_replay_witness(&proof).expect("mixed replay witness");

    assert_eq!(
        witness.block_initial_claim,
        standard_bucket.block_initial_claim
    );
    assert_eq!(
        witness.block_multipoint_rounds,
        standard_bucket.block_multipoint_rounds
    );
    assert_eq!(
        witness.block_multipoint_challenges,
        standard_bucket.block_multipoint_challenges
    );
    assert_eq!(
        witness.block_secondary_initial_claim,
        sweep_bucket.block_initial_claim
    );
    assert_eq!(
        witness.block_secondary_multipoint_rounds,
        sweep_bucket.block_multipoint_rounds
    );
    assert_eq!(
        witness.block_secondary_multipoint_challenges,
        sweep_bucket.block_multipoint_challenges
    );
    assert_eq!(
        witness.chain_claim,
        noid_block::block_recursive_claim_field(&proof)
    );

    let prev_acc = genesis_accumulator([0u8; 32], [0u8; 32]);
    let rec_proof = prove_recursive_step(&witness, &block.header, &prev_acc, None);
    let rec_air = RecursiveBlockAir::from_prev_state_root(&prev_acc.state_root);
    verify_recursive_step(&rec_proof, &prev_acc, &block.header, &rec_air)
        .expect("mixed recursive step verifies");
}

#[test]
#[cfg_attr(debug_assertions, ignore = "release-only mixed proof regression")]
fn mixed_many_standard_one_sweep_replay_witness_verifies() {
    let (mut block, proof) = mixed_block_proof_with_counts(2, 1);
    block.header.proof_transcript_hash = block_recursive_claim_hash(&proof);

    validate_block_bucket_tx_indices(&block, &proof).expect("mixed coverage");
    verify_sweep_bucket_from_block(&block, &proof).expect("mixed sweep bucket verifies");
    validate_block_proof_transcript_hash(&block, &proof).expect("mixed transcript hash");

    let standard_bucket = proof.standard_bucket.as_ref().expect("standard bucket");
    let sweep_bucket = proof.sweep_bucket.as_ref().expect("sweep bucket");
    assert_eq!(standard_bucket.meta.tx_indices, vec![1, 2]);
    assert_eq!(sweep_bucket.meta.tx_indices, vec![3]);

    let witness = extract_replay_witness(&proof).expect("mixed replay witness");
    assert_eq!(
        witness.block_multipoint_rounds,
        standard_bucket.block_multipoint_rounds
    );
    assert_eq!(
        witness.block_secondary_multipoint_rounds,
        sweep_bucket.block_multipoint_rounds
    );
}

#[test]
#[cfg_attr(debug_assertions, ignore = "release-only mixed proof regression")]
fn mixed_one_standard_many_sweep_replay_witness_verifies() {
    let (mut block, proof) = mixed_block_proof_with_counts(1, 2);
    block.header.proof_transcript_hash = block_recursive_claim_hash(&proof);

    validate_block_bucket_tx_indices(&block, &proof).expect("mixed coverage");
    verify_sweep_bucket_from_block(&block, &proof).expect("mixed sweep bucket verifies");
    validate_block_proof_transcript_hash(&block, &proof).expect("mixed transcript hash");

    let standard_bucket = proof.standard_bucket.as_ref().expect("standard bucket");
    let sweep_bucket = proof.sweep_bucket.as_ref().expect("sweep bucket");
    assert_eq!(standard_bucket.meta.tx_indices, vec![1]);
    assert_eq!(sweep_bucket.meta.tx_indices, vec![2, 3]);

    let witness = extract_replay_witness(&proof).expect("mixed replay witness");
    assert_eq!(
        witness.block_multipoint_rounds,
        standard_bucket.block_multipoint_rounds
    );
    assert_eq!(
        witness.block_secondary_multipoint_rounds,
        sweep_bucket.block_multipoint_rounds
    );
}

#[test]
#[cfg_attr(debug_assertions, ignore = "release-only mixed proof regression")]
fn mixed_block_rejects_duplicate_and_missing_bucket_indices() {
    let (block, proof) = mixed_block_proof();
    validate_block_bucket_tx_indices(&block, &proof).expect("honest mixed coverage");

    let mut duplicate = proof.clone();
    duplicate.sweep_bucket.as_mut().unwrap().meta.tx_indices = vec![1];
    assert!(
        validate_block_bucket_tx_indices(&block, &duplicate).is_err(),
        "duplicate standard/sweep index must reject"
    );

    let mut missing = proof;
    missing
        .sweep_bucket
        .as_mut()
        .unwrap()
        .meta
        .tx_indices
        .clear();
    missing.sweep_bucket.as_mut().unwrap().tx_pis.clear();
    missing.sweep_bucket.as_mut().unwrap().auth_public.clear();
    missing.sweep_bucket.as_mut().unwrap().auth_slices.clear();
    missing.sweep_bucket.as_mut().unwrap().spine_inputs.clear();
    missing.sweep_bucket.as_mut().unwrap().logic_proofs.clear();
    assert!(
        validate_block_bucket_tx_indices(&block, &missing).is_err(),
        "missing sweep tx index must reject"
    );
}

#[test]
#[cfg_attr(debug_assertions, ignore = "release-only mixed proof regression")]
fn mixed_block_rejects_cross_shape_bucket_indices() {
    let (block, proof) = mixed_block_proof();
    validate_block_bucket_tx_indices(&block, &proof).expect("honest mixed coverage");

    let mut sweep_in_standard = proof.clone();
    sweep_in_standard
        .standard_bucket
        .as_mut()
        .unwrap()
        .meta
        .tx_indices = vec![2];
    assert!(
        validate_block_bucket_tx_indices(&block, &sweep_in_standard).is_err(),
        "sweep tx claimed by standard bucket must reject"
    );

    let mut standard_in_sweep = proof;
    standard_in_sweep
        .sweep_bucket
        .as_mut()
        .unwrap()
        .meta
        .tx_indices = vec![1];
    assert!(
        validate_block_bucket_tx_indices(&block, &standard_in_sweep).is_err(),
        "standard tx claimed by sweep bucket must reject"
    );
}

#[test]
#[cfg_attr(debug_assertions, ignore = "release-only mixed proof regression")]
fn mixed_bucket_order_tampering_rejects() {
    let (block, mut proof) = mixed_block_proof_with_counts(2, 1);
    validate_block_bucket_tx_indices(&block, &proof).expect("honest mixed coverage");

    proof
        .standard_bucket
        .as_mut()
        .unwrap()
        .meta
        .tx_indices
        .swap(0, 1);
    assert!(
        validate_block_bucket_tx_indices(&block, &proof).is_err(),
        "non-canonical bucket tx order must reject"
    );
}

#[test]
#[cfg_attr(debug_assertions, ignore = "release-only mixed proof regression")]
fn mixed_block_rejects_swapped_sweep_bucket_after_validation() {
    let (block, mut proof) = mixed_block_proof();
    validate_block_bucket_tx_indices(&block, &proof).expect("honest mixed coverage");

    let (_other_block, other_sweep_only_proof) = sweep_bucket_proof_for_body(mk_sweep_body(6));
    let mut swapped_bucket = other_sweep_only_proof
        .sweep_bucket
        .expect("alternate sweep bucket");
    swapped_bucket.meta.tx_indices = vec![2];
    proof.sweep_bucket = Some(swapped_bucket);

    assert!(
        validate_block_bucket_tx_indices(&block, &proof).is_err(),
        "a valid sweep bucket for another tx body must not bind to the mixed block"
    );
}

#[test]
#[cfg_attr(debug_assertions, ignore = "release-only mixed proof regression")]
fn mixed_header_transcript_rejects_state_meta_tamper() {
    let (mut block, mut proof) = mixed_block_proof();
    block.header.proof_transcript_hash = block_recursive_claim_hash(&proof);
    validate_block_proof_transcript_hash(&block, &proof).expect("honest transcript hash");

    let canonical_hash = block.header.proof_transcript_hash;
    proof.meta.new_state_root[0] ^= 0x01;

    assert_ne!(canonical_hash, block_recursive_claim_hash(&proof));
    assert!(
        validate_block_proof_transcript_hash(&block, &proof).is_err(),
        "header proof_transcript_hash must bind mixed proof state metadata"
    );
}

#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "release-only state-binding proof regression"
)]
fn standalone_state_binding_proves_and_verifies_for_sweep_only_path() {
    let body = mk_sweep_mint_body();
    let commitment = compute_claims_commitment(&body.inputs, &body.outputs);

    let mut state = ChainState::with_log_slots(6);
    let prev_state_root = state.state_root();
    let mut state_for_binding = state.state.clone();
    let binding = BlockStateBinding::build(&mut state_for_binding, &[body.clone()], &[commitment])
        .expect("build binding");

    let mut pre_segs = HashMap::new();
    pre_segs.insert(0u16, SegmentColumns::new_zero(64));
    let owned = build_state_bindings_from_binding(
        &binding,
        &[body],
        None,
        &pre_segs,
        prev_state_root,
        1,
        6,
    );
    let witnesses: Vec<_> = owned.iter().map(|b| b.as_witness()).collect();
    let (starks, pre_openings, post_openings) = prove_state_bindings_standalone(&witnesses);

    let proof = BlockProof {
        meta: BlockPublicMeta {
            prev_block_state_root: prev_state_root,
            new_state_root: binding.new_state_root,
            n_tx: 1,
            n_air_per_tx: 0,
            n_auth_slices_per_tx: 0,
            log_rows: noid_air::airs::tx_body_spine::SPINE_LOG_ROWS as u32,
            n_block_spine_slices: 0,
            n_state_bindings: starks.len() as u32,
            state_binding_n_cols: witnesses[0].air.n_columns() as u32,
            state_binding_log_rows: witnesses[0].air.log_rows() as u32,
        },
        standard_bucket: None,
        sweep_bucket: None,
        state_binding_algebraics: vec![],
        state_binding_starks: starks,
        pre_state_openings: pre_openings,
        post_state_openings: post_openings,
    };
    let air_refs: Vec<_> = owned.iter().map(|b| &b.air).collect();
    verify_state_bindings_standalone(&proof, &air_refs).expect("standalone state binding verifies");
}
