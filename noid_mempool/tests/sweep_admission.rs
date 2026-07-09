// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

use std::collections::HashMap;

use noid_chain::consensus::fees::required_fee_for_tx_body;
use noid_chain::consensus::genesis::genesis_header;
use noid_chain::consensus::pow::block_id;
use noid_chain::fri_state::SlotValue;
use noid_chain::state::ChainState;
use noid_core::{Block128, TowerField};
use noid_gkr::{
    prove_wallet_authorization, verify_wallet_authorization, WalletAuthorizationBundle,
};
use noid_mempool::{AsyncMempool, ChainView, SubmitError};
use noid_poseidon2b::primitives::{derive_address, Address, SpendSecret, TxBodyHash};
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
    // One owner per tx (consensus rule): every live input shares the
    // sweeping wallet's single active address.
    let spend_secret = mk_secret(1);
    let owner = derive_address(&spend_secret);
    let mut inputs = Vec::with_capacity(5);
    for i in 0..5u32 {
        inputs.push(TxInput {
            slot_index: 1_000 + i,
            value: 20_000 + i as u64,
            owner,
            spend_secret: spend_secret.clone(),
            valid: true,
        });
    }

    let total: u64 = inputs.iter().map(|i| i.value).sum();
    let spendable = total.checked_sub(fee).expect("fee below input total");
    TxBody {
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
    }
}

fn empty_chain_view() -> ChainView {
    let genesis = genesis_header();
    let mut headers = HashMap::new();
    headers.insert(0, genesis);

    let state = ChainState::new();
    ChainView::new(0, headers, state.active_slot_count, state.state)
}

fn chain_view_with_inputs(body: &TxBody) -> ChainView {
    chain_view_with_live_slots(body, false)
}

fn chain_view_with_inputs_and_outputs(body: &TxBody) -> ChainView {
    chain_view_with_live_slots(body, true)
}

fn chain_view_with_live_slots(body: &TxBody, include_outputs: bool) -> ChainView {
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
    if include_outputs {
        for output in body.outputs.iter().filter(|o| o.valid) {
            state
                .state
                .set_slot(
                    output.slot_index,
                    SlotValue {
                        value: Block128::from(output.value as u128),
                        owner_hi: output.owner.as_fields()[0],
                        owner_lo: output.owner.as_fields()[1],
                    },
                )
                .expect("insert occupied output slot");
            state.active_slot_count += 1;
        }
    }

    ChainView::new(0, headers, state.active_slot_count, state.state)
}

fn prove_bundle(body: &TxBody) -> WalletAuthorizationBundle {
    let spend_secrets = body
        .inputs
        .iter()
        .filter(|input| input.valid)
        .map(|input| input.spend_secret.clone())
        .collect();
    prove_wallet_authorization(body, spend_secrets).expect("prove sweep authorization")
}

fn authorization_bytes(bundle: &WalletAuthorizationBundle) -> Vec<u8> {
    bundle.to_bytes().expect("serialize wallet authorization")
}

fn intent_with_proof(body: TxBody, authorization_bytes: Vec<u8>) -> TxIntent {
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
        authorization_bytes,
    }
}

fn intent_without_proof(body: TxBody) -> TxIntent {
    TxIntent {
        tx_body: body,
        tx_body_hash: TxBodyHash([0u8; 32]),
        claims_commitment: [0u8; 32],
        claimed_slots: vec![],
        authorization_bytes: vec![],
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[cfg_attr(debug_assertions, ignore = "release-only sweep proof regression")]
async fn mempool_accepts_valid_sweep25x2_bundle() {
    let genesis = genesis_header();
    let epoch_anchor = block_id(&genesis);
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
        authorization_bytes: authorization_bytes(&bundle),
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
        .cached_authorization
        .as_ref()
        .expect("admitted sweep proof should be cached");
    let cached_bundle =
        WalletAuthorizationBundle::from_bytes(cached).expect("decode cached authorization");
    verify_wallet_authorization(&body, &cached_bundle).expect("verify cached sweep authorization");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[cfg_attr(debug_assertions, ignore = "release-only sweep proof regression")]
async fn mempool_rejects_sweep_body_tamper_against_valid_bundle() {
    let genesis = genesis_header();
    let epoch_anchor = block_id(&genesis);
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
        authorization_bytes: authorization_bytes(&bundle),
    };
    let intent_bytes = intent.to_bytes();

    let mempool = AsyncMempool::new(view, noid_mempool::MempoolConfig::default());
    let result = mempool.submit(intent, intent_bytes).await;
    assert!(matches!(result, Err(SubmitError::MalformedIntent(_))));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[cfg_attr(debug_assertions, ignore = "release-only sweep proof regression")]
async fn mempool_rejects_sweep_fee_tamper_against_valid_bundle() {
    let genesis = genesis_header();
    let epoch_anchor = block_id(&genesis);
    let probe = mk_sweep_body(epoch_anchor, 0);
    let fee = required_fee_for_tx_body(&probe, 5, 24);
    let body = mk_sweep_body(epoch_anchor, fee);
    let view = chain_view_with_inputs(&body);
    let bundle = prove_bundle(&body);

    let mut tampered = body.clone();
    tampered.fee = tampered.fee.saturating_add(1);
    tampered.outputs[1].value = tampered.outputs[1].value.saturating_sub(1);
    let intent = intent_with_proof(tampered, authorization_bytes(&bundle));
    let intent_bytes = intent.to_bytes();

    let mempool = AsyncMempool::new(view, noid_mempool::MempoolConfig::default());
    let result = mempool.submit(intent, intent_bytes).await;
    assert!(matches!(result, Err(SubmitError::InvalidProof(_))));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[cfg_attr(debug_assertions, ignore = "release-only sweep proof regression")]
async fn mempool_rejects_sweep_auth_tamper() {
    let genesis = genesis_header();
    let epoch_anchor = block_id(&genesis);
    let probe = mk_sweep_body(epoch_anchor, 0);
    let fee = required_fee_for_tx_body(&probe, 5, 24);
    let body = mk_sweep_body(epoch_anchor, fee);
    let view = chain_view_with_inputs(&body);
    let mut bundle = prove_bundle(&body);
    bundle.proof.kill_shot.main.state_at_r += Block128::ONE;
    let intent = intent_with_proof(body, authorization_bytes(&bundle));
    let intent_bytes = intent.to_bytes();

    let mempool = AsyncMempool::new(view, noid_mempool::MempoolConfig::default());
    let result = mempool.submit(intent, intent_bytes).await;
    assert!(matches!(result, Err(SubmitError::InvalidProof(_))));
}

#[tokio::test]
async fn mempool_rejects_malformed_sweep_bundle_bytes() {
    let genesis = genesis_header();
    let epoch_anchor = block_id(&genesis);
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
    let epoch_anchor = block_id(&genesis);
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
    let standard_input_sum: u64 = standard_body
        .inputs
        .iter()
        .filter(|input| input.valid)
        .map(|input| input.value)
        .sum();
    standard_body.outputs[0].value = standard_input_sum - standard_body.fee as u64;
    // Dead entries must carry the canonical dummy pattern.
    standard_body.outputs[1] = TxOutput {
        slot_index: 0,
        value: 0,
        owner: Address([0u8; 32]),
        valid: false,
    };
    let intent = intent_with_proof(standard_body, authorization_bytes(&sweep_bundle));
    let intent_bytes = intent.to_bytes();

    let mempool = AsyncMempool::new(view, noid_mempool::MempoolConfig::default());
    let result = mempool.submit(intent, intent_bytes).await;
    assert!(matches!(result, Err(SubmitError::InvalidProof(_))));
}

#[tokio::test]
async fn mempool_rejects_sweep_replay_by_occupied_output_before_zk() {
    let genesis = genesis_header();
    let epoch_anchor = block_id(&genesis);
    let probe = mk_sweep_body(epoch_anchor, 0);
    let fee = required_fee_for_tx_body(&probe, 5, 24);
    let body = mk_sweep_body(epoch_anchor, fee);
    let intent = intent_with_proof(body.clone(), vec![0x01]);

    let view = chain_view_with_inputs_and_outputs(&body);
    let mempool = AsyncMempool::new(view, noid_mempool::MempoolConfig::default());
    let result = mempool.submit(intent, vec![]).await;
    assert!(matches!(
        result,
        Err(SubmitError::Consensus(
            noid_chain::consensus::ConsensusError::SlotConflict
        ))
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[cfg_attr(debug_assertions, ignore = "release-only sweep proof regression")]
async fn mempool_rejects_sweep_input_conflict_with_admitted_sweep() {
    let genesis = genesis_header();
    let epoch_anchor = block_id(&genesis);
    let probe = mk_sweep_body(epoch_anchor, 0);
    let fee = required_fee_for_tx_body(&probe, 5, 24);
    let body = mk_sweep_body(epoch_anchor, fee);
    let view = chain_view_with_inputs(&body);
    let bundle = prove_bundle(&body);
    let first = intent_with_proof(body.clone(), authorization_bytes(&bundle));
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
    let epoch_anchor = block_id(&genesis);
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
    let epoch_anchor = block_id(&genesis);
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
