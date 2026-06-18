// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

use std::collections::HashMap;

use noid_air::Air;
use noid_chain::consensus::fees::required_fee_for_tx_body;
use noid_chain::consensus::genesis::genesis_header;
use noid_chain::consensus::pow::full_block_hash;
use noid_chain::fri_state::SlotValue;
use noid_chain::nullifier::NullifierSet;
use noid_chain::state::ChainState;
use noid_core::{Block128, TowerField};
use noid_mempool::{AsyncMempool, ChainView, SubmitError};
use noid_poseidon2b::primitives::{
    derive_address, hash_auth_tag, Address, AuthTag, SpendSecret, TxBodyHash,
};
use noid_stark::prove_logic_sweep::{
    build_sweep_auth_slices, prove_sweep_logic, sweep_logic_witness_parts_from_body,
    SweepLogicWitness,
};
use noid_stark::wallet_bundle::{SweepWalletProofBundle, WalletProofBundle};
use noid_tx::{
    compute_claims_commitment, hash_tx_body_for_shape, TxBody, TxInput, TxIntent, TxOutput, TxShape,
};

fn mk_secret(seed: u8) -> SpendSecret {
    let mut bytes = [0u8; 32];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = seed.wrapping_mul(29).wrapping_add(i as u8).wrapping_add(11);
    }
    SpendSecret(bytes)
}

fn mk_sweep_body(epoch_anchor: [u8; 32], fee: u64) -> TxBody {
    let mut inputs = Vec::with_capacity(5);
    for i in 0..5u32 {
        let spend_secret = mk_secret(i as u8 + 1);
        inputs.push(TxInput {
            slot_index: 1_000 + i,
            value: 20_000 + i as u64,
            owner: derive_address(&spend_secret),
            spend_secret,
            auth_tag: AuthTag([0u8; 32]),
            valid: true,
        });
    }

    let total: u64 = inputs.iter().map(|i| i.value).sum();
    let spendable = total.checked_sub(fee).expect("fee below input total");
    let mut body = TxBody {
        shape: TxShape::Sweep25x2,
        epoch_anchor,
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

    let tx_body_hash = hash_tx_body_for_shape(
        body.shape,
        &body.epoch_anchor,
        body.fee,
        &body.inputs,
        &body.outputs,
        body.is_coinbase,
    );
    for input in &mut body.inputs {
        input.auth_tag = hash_auth_tag(&input.spend_secret, &tx_body_hash);
    }

    body
}

fn empty_chain_view() -> ChainView {
    let genesis = genesis_header();
    let mut headers = HashMap::new();
    headers.insert(0, genesis);

    let state = ChainState::new();
    ChainView::new(
        0,
        headers,
        NullifierSet::new(),
        state.active_slot_count,
        state.state,
    )
}

fn chain_view_with_inputs(body: &TxBody) -> ChainView {
    let genesis = genesis_header();
    let mut headers = HashMap::new();
    headers.insert(0, genesis);

    let mut state = ChainState::new();
    for input in body.inputs.iter().filter(|i| i.valid) {
        state
            .state
            .set_slot(
                input.slot_index,
                SlotValue {
                    value: Block128::from(input.value as u128),
                    owner_hi: input.owner.as_fields()[0],
                    owner_lo: input.owner.as_fields()[1],
                },
            )
            .expect("insert live input slot");
        state.active_slot_count += 1;
    }

    ChainView::new(
        0,
        headers,
        NullifierSet::new(),
        state.active_slot_count,
        state.state,
    )
}

fn prove_bundle(body: &TxBody) -> WalletProofBundle {
    let (air, trace, auth_inputs, _) = sweep_logic_witness_parts_from_body(body);
    assert!(air.check(&trace));

    let tx_body_hash = hash_tx_body_for_shape(
        body.shape,
        &body.epoch_anchor,
        body.fee,
        &body.inputs,
        &body.outputs,
        body.is_coinbase,
    );
    let pi = noid_tx::PublicInputs {
        epoch_anchor: body.epoch_anchor,
        tx_body_hash,
        shape_id: body.shape.id(),
        fee: body.fee,
        n_live_inputs: body.inputs.iter().filter(|i| i.valid).count() as u8,
        n_live_outputs: body.outputs.iter().filter(|o| o.valid).count() as u8,
        coinbase_credit: 0,
        log_slots: 24,
        claims_commitment: compute_claims_commitment(&body.inputs, &body.outputs),
        is_activation: [false; noid_tx::MAX_OUTPUTS],
        is_deactivation: [false; noid_tx::MAX_INPUTS],
    };

    let witness = SweepLogicWitness {
        air: &air,
        trace: &trace,
        pi: &pi,
        auth_inputs: &auth_inputs,
    };
    let logic_proof = prove_sweep_logic(&witness).expect("prove sweep logic");
    let auth_slices = build_sweep_auth_slices(&auth_inputs);

    WalletProofBundle::Sweep25x2(SweepWalletProofBundle {
        logic_proof,
        auth_slices,
        auth_public: auth_inputs.to_public(),
    })
}

fn intent_with_proof(body: TxBody, logic_proof_bytes: Vec<u8>) -> TxIntent {
    let tx_body_hash = hash_tx_body_for_shape(
        body.shape,
        &body.epoch_anchor,
        body.fee,
        &body.inputs,
        &body.outputs,
        body.is_coinbase,
    );
    TxIntent {
        tx_body: body.clone(),
        tx_body_hash,
        claims_commitment: compute_claims_commitment(&body.inputs, &body.outputs),
        claimed_slots: TxIntent::claimed_slots_from_body(&body),
        logic_proof_bytes,
    }
}

fn intent_without_proof(body: TxBody) -> TxIntent {
    TxIntent {
        tx_body: body,
        tx_body_hash: TxBodyHash([0u8; 32]),
        claims_commitment: [0u8; 32],
        claimed_slots: vec![],
        logic_proof_bytes: vec![],
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[cfg_attr(debug_assertions, ignore = "release-only sweep proof regression")]
async fn mempool_accepts_valid_sweep25x2_bundle() {
    let genesis = genesis_header();
    let epoch_anchor = full_block_hash(&genesis);
    let probe = mk_sweep_body(epoch_anchor, 0);
    let fee = required_fee_for_tx_body(&probe, 5, 24);
    let body = mk_sweep_body(epoch_anchor, fee);
    let view = chain_view_with_inputs(&body);
    let tx_body_hash = hash_tx_body_for_shape(
        body.shape,
        &body.epoch_anchor,
        body.fee,
        &body.inputs,
        &body.outputs,
        body.is_coinbase,
    );
    let bundle = prove_bundle(&body);
    let intent = TxIntent {
        tx_body: body.clone(),
        tx_body_hash,
        claims_commitment: compute_claims_commitment(&body.inputs, &body.outputs),
        claimed_slots: TxIntent::claimed_slots_from_body(&body),
        logic_proof_bytes: bundle.to_bytes(),
    };
    let intent_bytes = intent.to_bytes();

    let mempool = AsyncMempool::new(view, noid_mempool::config::MempoolConfig::default());
    let admitted = mempool
        .submit(intent, intent_bytes)
        .await
        .expect("valid Sweep25x2 intent should be admitted");
    assert_eq!(admitted, tx_body_hash);

    let selected = mempool.select_for_block(1).await;
    assert_eq!(selected.len(), 1);
    let cached = selected[0]
        .cached_algebraic_proof
        .as_ref()
        .expect("admitted sweep proof should be cached");
    let cached_bundle = WalletProofBundle::from_bytes(cached).expect("decode cached bundle");
    assert_eq!(cached_bundle.shape(), TxShape::Sweep25x2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[cfg_attr(debug_assertions, ignore = "release-only sweep proof regression")]
async fn mempool_rejects_sweep_body_tamper_against_valid_bundle() {
    let genesis = genesis_header();
    let epoch_anchor = full_block_hash(&genesis);
    let probe = mk_sweep_body(epoch_anchor, 0);
    let fee = required_fee_for_tx_body(&probe, 5, 24);
    let body = mk_sweep_body(epoch_anchor, fee);
    let view = chain_view_with_inputs(&body);
    let bundle = prove_bundle(&body);

    let mut tampered = body.clone();
    tampered.outputs[1].value = tampered.outputs[1].value.saturating_add(1);
    let tx_body_hash = hash_tx_body_for_shape(
        tampered.shape,
        &tampered.epoch_anchor,
        tampered.fee,
        &tampered.inputs,
        &tampered.outputs,
        tampered.is_coinbase,
    );
    let intent = TxIntent {
        tx_body: tampered.clone(),
        tx_body_hash,
        claims_commitment: compute_claims_commitment(&tampered.inputs, &tampered.outputs),
        claimed_slots: TxIntent::claimed_slots_from_body(&tampered),
        logic_proof_bytes: bundle.to_bytes(),
    };
    let intent_bytes = intent.to_bytes();

    let mempool = AsyncMempool::new(view, noid_mempool::MempoolConfig::default());
    let result = mempool.submit(intent, intent_bytes).await;
    assert!(matches!(result, Err(SubmitError::InvalidProof(_))));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[cfg_attr(debug_assertions, ignore = "release-only sweep proof regression")]
async fn mempool_rejects_sweep_fee_tamper_against_valid_bundle() {
    let genesis = genesis_header();
    let epoch_anchor = full_block_hash(&genesis);
    let probe = mk_sweep_body(epoch_anchor, 0);
    let fee = required_fee_for_tx_body(&probe, 5, 24);
    let body = mk_sweep_body(epoch_anchor, fee);
    let view = chain_view_with_inputs(&body);
    let bundle = prove_bundle(&body);

    let mut tampered = body.clone();
    tampered.fee = tampered.fee.saturating_add(1);
    tampered.outputs[1].value = tampered.outputs[1].value.saturating_sub(1);
    let intent = intent_with_proof(tampered, bundle.to_bytes());
    let intent_bytes = intent.to_bytes();

    let mempool = AsyncMempool::new(view, noid_mempool::MempoolConfig::default());
    let result = mempool.submit(intent, intent_bytes).await;
    assert!(matches!(result, Err(SubmitError::InvalidProof(_))));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[cfg_attr(debug_assertions, ignore = "release-only sweep proof regression")]
async fn mempool_rejects_sweep_auth_tamper() {
    let genesis = genesis_header();
    let epoch_anchor = full_block_hash(&genesis);
    let probe = mk_sweep_body(epoch_anchor, 0);
    let fee = required_fee_for_tx_body(&probe, 5, 24);
    let body = mk_sweep_body(epoch_anchor, fee);
    let view = chain_view_with_inputs(&body);
    let mut bundle = prove_bundle(&body);
    match &mut bundle {
        WalletProofBundle::Sweep25x2(sweep) => {
            sweep.auth_public.expected_auth_tag[0][0] += Block128::ONE;
        }
        WalletProofBundle::Standard4x8(_) => panic!("expected sweep bundle"),
    }
    let intent = intent_with_proof(body, bundle.to_bytes());
    let intent_bytes = intent.to_bytes();

    let mempool = AsyncMempool::new(view, noid_mempool::MempoolConfig::default());
    let result = mempool.submit(intent, intent_bytes).await;
    assert!(matches!(result, Err(SubmitError::InvalidProof(_))));
}

#[tokio::test]
async fn mempool_rejects_malformed_sweep_bundle_bytes() {
    let genesis = genesis_header();
    let epoch_anchor = full_block_hash(&genesis);
    let probe = mk_sweep_body(epoch_anchor, 0);
    let fee = required_fee_for_tx_body(&probe, 5, 24);
    let body = mk_sweep_body(epoch_anchor, fee);
    let view = chain_view_with_inputs(&body);
    let intent = intent_with_proof(body, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    let intent_bytes = intent.to_bytes();

    let mempool = AsyncMempool::new(view, noid_mempool::MempoolConfig::default());
    let result = mempool.submit(intent, intent_bytes).await;
    assert!(matches!(result, Err(SubmitError::InvalidProof(_))));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[cfg_attr(debug_assertions, ignore = "release-only sweep proof regression")]
async fn mempool_rejects_wrong_shape_bundle_for_standard_body() {
    let genesis = genesis_header();
    let epoch_anchor = full_block_hash(&genesis);
    let probe = mk_sweep_body(epoch_anchor, 0);
    let fee = required_fee_for_tx_body(&probe, 5, 24);
    let sweep_body = mk_sweep_body(epoch_anchor, fee);
    let view = chain_view_with_inputs(&sweep_body);
    let sweep_bundle = prove_bundle(&sweep_body);

    let mut standard_body = sweep_body.clone();
    standard_body.shape = TxShape::Standard4x8;
    standard_body
        .inputs
        .truncate(TxShape::Standard4x8.max_inputs());
    let intent = intent_with_proof(standard_body, sweep_bundle.to_bytes());
    let intent_bytes = intent.to_bytes();

    let mempool = AsyncMempool::new(view, noid_mempool::MempoolConfig::default());
    let result = mempool.submit(intent, intent_bytes).await;
    assert!(matches!(result, Err(SubmitError::InvalidProof(_))));
}

#[tokio::test]
async fn mempool_rejects_sweep_nullifier_collision_before_zk() {
    let genesis = genesis_header();
    let epoch_anchor = full_block_hash(&genesis);
    let probe = mk_sweep_body(epoch_anchor, 0);
    let fee = required_fee_for_tx_body(&probe, 5, 24);
    let body = mk_sweep_body(epoch_anchor, fee);
    let intent = intent_with_proof(body.clone(), vec![0x01]);

    let mut view = chain_view_with_inputs(&body);
    view.nullifiers.insert_block(&[intent.tx_body_hash]);
    let mempool = AsyncMempool::new(view, noid_mempool::MempoolConfig::default());
    let result = mempool.submit(intent, vec![]).await;
    assert!(matches!(
        result,
        Err(SubmitError::Consensus(
            noid_chain::consensus::ConsensusError::NullifierCollision
        ))
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[cfg_attr(debug_assertions, ignore = "release-only sweep proof regression")]
async fn mempool_rejects_sweep_input_conflict_with_admitted_sweep() {
    let genesis = genesis_header();
    let epoch_anchor = full_block_hash(&genesis);
    let probe = mk_sweep_body(epoch_anchor, 0);
    let fee = required_fee_for_tx_body(&probe, 5, 24);
    let body = mk_sweep_body(epoch_anchor, fee);
    let view = chain_view_with_inputs(&body);
    let bundle = prove_bundle(&body);
    let first = intent_with_proof(body.clone(), bundle.to_bytes());
    let first_bytes = first.to_bytes();

    let mempool = AsyncMempool::new(view, noid_mempool::MempoolConfig::default());
    mempool
        .submit(first, first_bytes)
        .await
        .expect("first sweep should be admitted");

    let mut conflicting = body;
    conflicting.outputs[0].slot_index = 50_010;
    conflicting.outputs[1].slot_index = 50_011;
    let second = intent_with_proof(conflicting, vec![0x01]);
    let result = mempool.submit(second, vec![]).await;
    assert!(matches!(
        result,
        Err(SubmitError::Consensus(
            noid_chain::consensus::ConsensusError::SlotConflict
        ))
    ));
}

#[tokio::test]
async fn mempool_rejects_sweep_with_more_than_25_inputs_without_panic() {
    let genesis = genesis_header();
    let epoch_anchor = full_block_hash(&genesis);
    let mut body = mk_sweep_body(epoch_anchor, 9_000);
    while body.inputs.len() <= TxShape::Sweep25x2.max_inputs() {
        body.inputs.push(body.inputs[0].clone());
    }

    let mempool = AsyncMempool::new(empty_chain_view(), noid_mempool::MempoolConfig::default());
    let intent = intent_without_proof(body);
    let result = mempool.submit(intent, vec![]).await;
    assert!(matches!(result, Err(SubmitError::MalformedIntent(_))));
}

#[tokio::test]
async fn mempool_rejects_sweep_with_more_than_2_outputs_without_panic() {
    let genesis = genesis_header();
    let epoch_anchor = full_block_hash(&genesis);
    let mut body = mk_sweep_body(epoch_anchor, 9_000);
    body.outputs.push(TxOutput {
        slot_index: 50_002,
        value: 1,
        owner: Address([0xA3; 32]),
        valid: true,
    });

    let mempool = AsyncMempool::new(empty_chain_view(), noid_mempool::MempoolConfig::default());
    let intent = intent_without_proof(body);
    let result = mempool.submit(intent, vec![]).await;
    assert!(matches!(result, Err(SubmitError::MalformedIntent(_))));
}
