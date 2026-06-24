// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

use noid_air::{
    composition::{sweep25x2_balance_witness_from_body, sweep_logic_air_and_trace_from_body},
    Air,
};
use noid_poseidon2b::primitives::{Address, SpendSecret, TxBodyHash};
use noid_stark::{prove_air, verify_air};
use noid_tx::{
    compute_claims_commitment, hash_tx_body_for_shape, PublicInputs, TxBody, TxInput, TxOutput,
    TxShape, MAX_INPUTS, MAX_OUTPUTS,
};

fn mk_input(i: usize) -> TxInput {
    TxInput {
        slot_index: i as u32,
        value: 1_000 + i as u64,
        owner: Address([i as u8; 32]),
        spend_secret: SpendSecret([0x80 ^ i as u8; 32]),
        valid: true,
    }
}

fn mk_sweep_body() -> TxBody {
    let inputs: Vec<TxInput> = (0..TxShape::Sweep25x2.max_inputs()).map(mk_input).collect();
    let total: u64 = inputs.iter().map(|i| i.value).sum();
    let fee = 901u64;
    let spendable = total - fee;

    TxBody {
        shape: TxShape::Sweep25x2,
        epoch_anchor: [0x5A; 32],
        fee: fee as u128,
        inputs,
        outputs: vec![
            TxOutput {
                slot_index: 10_000,
                value: spendable / 3,
                owner: Address([0xA1; 32]),
                valid: true,
            },
            TxOutput {
                slot_index: 10_001,
                value: spendable - spendable / 3,
                owner: Address([0xA2; 32]),
                valid: true,
            },
        ],
        is_coinbase: false,
    }
}

fn public_inputs_for_body(body: &TxBody) -> PublicInputs {
    let tx_body_hash = hash_tx_body_for_shape(
        body.shape,
        &body.epoch_anchor,
        body.fee,
        &body.inputs,
        &body.outputs,
        body.is_coinbase,
    );

    PublicInputs {
        epoch_anchor: body.epoch_anchor,
        tx_body_hash: TxBodyHash(tx_body_hash.0),
        shape_id: body.shape.id(),
        fee: body.fee,
        n_live_inputs: body.inputs.iter().filter(|i| i.valid).count() as u8,
        n_live_outputs: body.outputs.iter().filter(|o| o.valid).count() as u8,
        coinbase_credit: 0,
        log_slots: 24,
        claims_commitment: compute_claims_commitment(&body.inputs, &body.outputs),
        // PublicInputs currently stores standard-sized activation/deactivation
        // arrays. The standalone sweep balance proof does not consume them.
        is_activation: [false; MAX_OUTPUTS],
        is_deactivation: [false; MAX_INPUTS],
    }
}

#[test]
#[cfg_attr(debug_assertions, ignore = "release-only proof regression")]
fn sweep25x2_balance_air_proves_and_verifies() {
    let body = mk_sweep_body();
    let pi = public_inputs_for_body(&body);
    assert_eq!(pi.shape_id, TxShape::Sweep25x2.id());
    assert_eq!(pi.n_live_inputs, 25);
    assert_eq!(pi.n_live_outputs, 2);

    let witness = sweep25x2_balance_witness_from_body(&body);
    let (air, trace) = witness.build_air_and_trace();

    let proof = prove_air(&air, &trace, &pi).expect("prove sweep balance AIR");
    verify_air(&air, &pi, &proof).expect("verify sweep balance AIR");

    let mut wrong_shape_pi = pi;
    wrong_shape_pi.shape_id = TxShape::Standard4x8.id();
    assert!(
        verify_air(&air, &wrong_shape_pi, &proof).is_err(),
        "sweep balance proof must be transcript-bound to shape_id"
    );
}

#[test]
#[cfg_attr(debug_assertions, ignore = "release-only proof regression")]
fn sweep_tx_logic_air_proves_and_rejects_body_tamper() {
    let body = mk_sweep_body();
    let pi = public_inputs_for_body(&body);
    let (air, trace) = sweep_logic_air_and_trace_from_body(&body);
    assert!(!air.public_columns().is_empty());

    let proof = prove_air(&air, &trace, &pi).expect("prove sweep tx logic AIR");
    verify_air(&air, &pi, &proof).expect("verify sweep tx logic AIR");

    let mut tampered_body = body.clone();
    tampered_body.inputs[0].value += 1;
    tampered_body.outputs[0].value += 1;
    let tampered_pi = public_inputs_for_body(&tampered_body);
    let (tampered_air, _) = sweep_logic_air_and_trace_from_body(&tampered_body);
    assert!(
        verify_air(&tampered_air, &tampered_pi, &proof).is_err(),
        "body-derived PublicColumns must reject a proof made for a different sweep body"
    );
}
