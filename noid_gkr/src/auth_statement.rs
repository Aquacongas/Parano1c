// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Canonical Auth public statements derived from `TxBody`.

use noid_core::{Block128, TowerField};
use noid_poseidon2b::primitives::{fee_leaf, is_coinbase_leaf, tx_shape_leaf, Digest};
use noid_tx::{hash_tx_body_for_shape, TxBody, TxInput, TxOutput, TxShape};
use zeroize::Zeroize;

use crate::{
    compute_auth_boundary, compute_sweep_auth_boundary, AuthCircuit, AuthPublicInputs,
    SweepAuthCircuit, SweepAuthInputs, SweepAuthPublicInputs, SweepSpineInputs, N_AUTH_INPUTS,
    N_SWEEP_AUTH_INPUTS,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthStatementError {
    Coinbase,
    ShapeMismatch { expected: TxShape, actual: TxShape },
    TooManyInputs { actual: usize, max: usize },
    TooManyOutputs { actual: usize, max: usize },
}

impl std::fmt::Display for AuthStatementError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for AuthStatementError {}

fn check_body_shape(body: &TxBody, expected: TxShape) -> Result<(), AuthStatementError> {
    if body.is_coinbase {
        return Err(AuthStatementError::Coinbase);
    }
    if body.shape != expected {
        return Err(AuthStatementError::ShapeMismatch {
            expected,
            actual: body.shape,
        });
    }
    if body.inputs.len() > body.shape.max_inputs() {
        return Err(AuthStatementError::TooManyInputs {
            actual: body.inputs.len(),
            max: body.shape.max_inputs(),
        });
    }
    if body.outputs.len() > body.shape.max_outputs() {
        return Err(AuthStatementError::TooManyOutputs {
            actual: body.outputs.len(),
            max: body.shape.max_outputs(),
        });
    }
    Ok(())
}

pub fn standard_auth_public_from_body(
    body: &TxBody,
) -> Result<AuthPublicInputs, AuthStatementError> {
    check_body_shape(body, TxShape::Standard4x8)?;

    let tx_body_hash = hash_tx_body_for_shape(
        body.shape,
        &body.epoch_anchor,
        body.fee,
        &body.inputs,
        &body.outputs,
        body.is_coinbase,
    )
    .as_fields();

    let circuit = AuthCircuit::build();
    let zero_secrets = [[Block128::ZERO; 2]; N_AUTH_INPUTS];
    let (dummy_addresses, dummy_auth_tags) =
        compute_auth_boundary(&circuit, zero_secrets, tx_body_hash);

    let mut expected_address = dummy_addresses;
    let mut expected_auth_tag = dummy_auth_tags;
    for (i, input) in body.inputs.iter().take(N_AUTH_INPUTS).enumerate() {
        if input.valid {
            expected_address[i] = input.owner.as_fields();
            expected_auth_tag[i] = input.auth_tag.as_fields();
        }
    }

    Ok(AuthPublicInputs {
        tx_body_hash,
        expected_address,
        expected_auth_tag,
    })
}

pub fn sweep_auth_public_from_body(
    body: &TxBody,
) -> Result<SweepAuthPublicInputs, AuthStatementError> {
    check_body_shape(body, TxShape::Sweep25x2)?;

    let tx_body_hash = hash_tx_body_for_shape(
        body.shape,
        &body.epoch_anchor,
        body.fee,
        &body.inputs,
        &body.outputs,
        body.is_coinbase,
    )
    .as_fields();

    let circuit = SweepAuthCircuit::build();
    let zero_secrets = [[Block128::ZERO; 2]; N_SWEEP_AUTH_INPUTS];
    let (dummy_addresses, dummy_auth_tags) =
        compute_sweep_auth_boundary(&circuit, zero_secrets, tx_body_hash);

    let mut expected_address = dummy_addresses;
    let mut expected_auth_tag = dummy_auth_tags;
    for (i, input) in body.inputs.iter().take(N_SWEEP_AUTH_INPUTS).enumerate() {
        if input.valid {
            expected_address[i] = input.owner.as_fields();
            expected_auth_tag[i] = input.auth_tag.as_fields();
        }
    }

    Ok(SweepAuthPublicInputs {
        tx_body_hash,
        expected_address,
        expected_auth_tag,
    })
}

fn digest_to_fields(d: &Digest) -> [Block128; 2] {
    let mut a = [0u8; 16];
    let mut b = [0u8; 16];
    a.copy_from_slice(&d[..16]);
    b.copy_from_slice(&d[16..]);
    [
        Block128::from(u128::from_le_bytes(a)),
        Block128::from(u128::from_le_bytes(b)),
    ]
}

pub fn sweep_spine_inputs_from_body(body: &TxBody) -> Result<SweepSpineInputs, AuthStatementError> {
    check_body_shape(body, TxShape::Sweep25x2)?;

    let mut input_leaves = [[Block128::ZERO; 4]; TxShape::Sweep25x2.max_inputs()];
    for i in 0..TxShape::Sweep25x2.max_inputs() {
        let inp = body.inputs.get(i).cloned().unwrap_or_else(TxInput::dummy);
        let [owner_hi, owner_lo] = inp.owner.as_fields();
        input_leaves[i] = [
            Block128::from(inp.slot_index as u128),
            Block128::from(inp.value as u128),
            owner_hi,
            owner_lo,
        ];
    }

    let mut output_leaves = [[Block128::ZERO; 4]; TxShape::Sweep25x2.max_outputs()];
    for i in 0..TxShape::Sweep25x2.max_outputs() {
        let out = body.outputs.get(i).copied().unwrap_or_else(TxOutput::dummy);
        let [owner_hi, owner_lo] = out.owner.as_fields();
        output_leaves[i] = [
            Block128::from(out.slot_index as u128),
            Block128::from(out.value as u128),
            owner_hi,
            owner_lo,
        ];
    }

    Ok(SweepSpineInputs {
        epoch_anchor: digest_to_fields(&body.epoch_anchor),
        fee_leaf: digest_to_fields(&fee_leaf(body.fee)),
        shape_leaf: digest_to_fields(&tx_shape_leaf(TxShape::Sweep25x2.id())),
        input_leaves,
        output_leaves,
        is_coinbase_leaf: digest_to_fields(&is_coinbase_leaf(body.is_coinbase)),
        pad_leaf: [Block128::ZERO, Block128::ZERO],
    })
}

pub fn sweep_auth_inputs_from_body(body: &TxBody) -> Result<SweepAuthInputs, AuthStatementError> {
    check_body_shape(body, TxShape::Sweep25x2)?;
    let tx_body_hash = hash_tx_body_for_shape(
        body.shape,
        &body.epoch_anchor,
        body.fee,
        &body.inputs,
        &body.outputs,
        body.is_coinbase,
    )
    .as_fields();

    let mut spend_secret = [[Block128::ZERO; 2]; N_SWEEP_AUTH_INPUTS];
    for i in 0..N_SWEEP_AUTH_INPUTS {
        let inp = body.inputs.get(i).cloned().unwrap_or_else(TxInput::dummy);
        if inp.valid {
            spend_secret[i] = inp.spend_secret.as_fields();
        }
    }

    let auth_circuit = SweepAuthCircuit::build();
    let (expected_address, expected_auth_tag) =
        compute_sweep_auth_boundary(&auth_circuit, spend_secret, tx_body_hash);

    let auth_inputs = SweepAuthInputs {
        spend_secret,
        tx_body_hash,
        expected_address,
        expected_auth_tag,
    };
    spend_secret.zeroize();
    Ok(auth_inputs)
}
