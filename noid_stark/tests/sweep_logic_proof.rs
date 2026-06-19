// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

use noid_air::Air;
use noid_core::Block128;
use noid_core::TowerField;
use noid_fri_binius::COMPACT_NUM_QUERIES;
use noid_poseidon2b::primitives::{
    derive_address, hash_auth_tag, Address, AuthTag, SpendSecret, TxBodyHash,
};
use noid_stark::interleaved::{prove_air_interleaved, verify_air_interleaved};
use noid_stark::prove_logic_sweep::{
    prove_sweep_logic, sweep_logic_witness_parts_from_body, verify_sweep_logic, SweepLogicWitness,
    N_SWEEP_AUTH_SLICES,
};
use noid_stark::{prove_air, verify_air};
use noid_tx::{
    compute_claims_commitment, hash_tx_body_for_shape, PublicInputs, TxBody, TxInput, TxOutput,
    TxShape, MAX_INPUTS, MAX_OUTPUTS,
};

fn mk_secret(seed: u8) -> SpendSecret {
    let mut bytes = [0u8; 32];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = seed.wrapping_mul(19).wrapping_add(i as u8).wrapping_add(7);
    }
    SpendSecret(bytes)
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
        input.auth_tag = hash_auth_tag(&input.spend_secret, &TxBodyHash(tx_hash.0));
    }

    body
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
        is_activation: [false; MAX_OUTPUTS],
        is_deactivation: [false; MAX_INPUTS],
    }
}

#[test]
fn sweep_auth_slices_are_not_part_of_logic_wire_shape() {
    assert_eq!(N_SWEEP_AUTH_SLICES, 0);

    let body = mk_sweep_body(5);
    let pi = public_inputs_for_body(&body);
    let (air, trace, auth_inputs, _) = sweep_logic_witness_parts_from_body(&body);
    let witness = SweepLogicWitness {
        air: &air,
        trace: &trace,
        pi: &pi,
        auth_inputs: &auth_inputs,
    };
    let proof = prove_sweep_logic(&witness).expect("prove sweep logic");

    assert_eq!(proof.n_boundary_slices, 0);
    assert!(proof.stark.slice_claimed_values.is_empty());
    assert_eq!(proof.stark.commitment.n_cols, air.n_columns());
}

#[test]
#[cfg_attr(debug_assertions, ignore = "release-only proof regression")]
fn sweep_balance_air_proves_at_logic_log_rows() {
    let body = mk_sweep_body(5);
    let pi = public_inputs_for_body(&body);
    let (air, trace, _, _) = sweep_logic_witness_parts_from_body(&body);
    assert_eq!(air.log_rows(), 11);
    assert!(air.check(&trace));
    let proof = prove_air(&air, &trace, &pi).expect("prove sweep balance at logic log_rows");
    verify_air(&air, &pi, &proof).expect("verify sweep balance at logic log_rows");
}

#[test]
#[cfg_attr(debug_assertions, ignore = "release-only proof regression")]
fn sweep_balance_interleaved_with_long_extra_proves() {
    let body = mk_sweep_body(5);
    let pi = public_inputs_for_body(&body);
    let (air, trace, _, _) = sweep_logic_witness_parts_from_body(&body);
    let log_len = noid_stark::padded_log_len(trace.log_rows);
    let columns: Vec<Vec<Block128>> = trace
        .columns
        .iter()
        .map(|c| noid_stark::pad_column(c, log_len))
        .collect();
    let extra = vec![Block128::from(7u128); 105];
    let proof = prove_air_interleaved(
        &air,
        &columns,
        &pi,
        &extra,
        &[],
        log_len,
        None,
        COMPACT_NUM_QUERIES,
    );
    verify_air_interleaved(&air, &pi, &proof, &extra, &[], COMPACT_NUM_QUERIES)
        .expect("verify interleaved sweep balance with long extra");
}

fn prove_verify_sweep_logic(
    n_live_inputs: usize,
) -> (
    noid_air::composition::SweepTxLogicAir,
    PublicInputs,
    noid_gkr::SweepSpineInputs,
    noid_gkr::SweepAuthPublicInputs,
    noid_stark::prove_logic_sweep::SweepLogicProof,
) {
    let body = mk_sweep_body(n_live_inputs);
    let pi = public_inputs_for_body(&body);
    let (air, trace, auth_inputs, spine_inputs) = sweep_logic_witness_parts_from_body(&body);
    assert!(air.check(&trace));

    let witness = SweepLogicWitness {
        air: &air,
        trace: &trace,
        pi: &pi,
        auth_inputs: &auth_inputs,
    };
    let proof = prove_sweep_logic(&witness).expect("prove sweep logic");
    assert_eq!(proof.n_boundary_slices, 0);
    assert!(proof.stark.slice_claimed_values.is_empty());
    assert_eq!(proof.stark.commitment.n_cols, air.n_columns());

    let auth_public = auth_inputs.to_public();
    verify_sweep_logic(&air, &pi, &spine_inputs, &auth_public, &proof).expect("verify sweep logic");
    (air, pi, spine_inputs, auth_public, proof)
}

#[test]
#[cfg_attr(debug_assertions, ignore = "release-only proof regression")]
fn sweep_logic_proves_and_verifies_5_live_inputs() {
    let (air, pi, spine_inputs, auth_public, proof) = prove_verify_sweep_logic(5);

    let mut wrong_shape = pi;
    wrong_shape.shape_id = TxShape::Standard4x8.id();
    assert!(verify_sweep_logic(&air, &wrong_shape, &spine_inputs, &auth_public, &proof).is_err());

    let mut wrong_spine = spine_inputs.clone();
    wrong_spine.input_leaves[1][2] += noid_core::Block128::ONE;
    assert!(verify_sweep_logic(&air, &pi, &wrong_spine, &auth_public, &proof).is_err());

    let mut wrong_auth_public = auth_public;
    wrong_auth_public.expected_address[4][0] += noid_core::Block128::ONE;
    assert!(verify_sweep_logic(&air, &pi, &spine_inputs, &wrong_auth_public, &proof).is_err());
}

#[test]
#[cfg_attr(debug_assertions, ignore = "release-only proof regression")]
fn sweep_logic_proves_and_verifies_21_live_inputs() {
    let (_, pi, _, _, proof) = prove_verify_sweep_logic(21);
    assert_eq!(pi.n_live_inputs, 21);
    assert!(proof.estimated_byte_len() > 0);
}

#[test]
#[cfg_attr(debug_assertions, ignore = "release-only proof regression")]
fn sweep_logic_proves_and_verifies_25_live_inputs() {
    let (_, pi, _, _, proof) = prove_verify_sweep_logic(25);
    assert_eq!(pi.n_live_inputs, 25);
    assert!(proof.estimated_byte_len() > 0);
}
