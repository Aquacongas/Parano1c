// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Canonical Standard4x8 spine public statements derived from `TxBody`.

use noid_core::{Block128, TowerField};
use noid_poseidon2b::primitives::{fee_leaf, is_coinbase_leaf, Digest};
use noid_tx::{TxBody, TxInput, TxOutput, TxShape};

use crate::SpineInputs;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpineStatementError {
    ShapeMismatch { expected: TxShape, actual: TxShape },
    TooManyInputs { actual: usize, max: usize },
    TooManyOutputs { actual: usize, max: usize },
}

impl std::fmt::Display for SpineStatementError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for SpineStatementError {}

fn digest_to_fields(d: &Digest) -> [Block128; 2] {
    let mut lo = [0u8; 16];
    let mut hi = [0u8; 16];
    lo.copy_from_slice(&d[..16]);
    hi.copy_from_slice(&d[16..]);
    [
        Block128::from(u128::from_le_bytes(lo)),
        Block128::from(u128::from_le_bytes(hi)),
    ]
}

pub fn spine_inputs_from_body(body: &TxBody) -> Result<SpineInputs, SpineStatementError> {
    if body.shape != TxShape::Standard4x8 {
        return Err(SpineStatementError::ShapeMismatch {
            expected: TxShape::Standard4x8,
            actual: body.shape,
        });
    }
    if body.inputs.len() > body.shape.max_inputs() {
        return Err(SpineStatementError::TooManyInputs {
            actual: body.inputs.len(),
            max: body.shape.max_inputs(),
        });
    }
    if body.outputs.len() > body.shape.max_outputs() {
        return Err(SpineStatementError::TooManyOutputs {
            actual: body.outputs.len(),
            max: body.shape.max_outputs(),
        });
    }

    let mut input_leaves = [[Block128::ZERO; 4]; TxShape::Standard4x8.max_inputs()];
    for (i, leaf) in input_leaves.iter_mut().enumerate() {
        let inp = body.inputs.get(i).cloned().unwrap_or_else(TxInput::dummy);
        let [owner_hi, owner_lo] = inp.owner.as_fields();
        *leaf = [
            Block128::from(inp.slot_index as u128),
            Block128::from(inp.value as u128),
            owner_hi,
            owner_lo,
        ];
    }

    let mut output_leaves = [[Block128::ZERO; 4]; TxShape::Standard4x8.max_outputs()];
    for (i, leaf) in output_leaves.iter_mut().enumerate() {
        let out = body.outputs.get(i).copied().unwrap_or_else(TxOutput::dummy);
        let [owner_hi, owner_lo] = out.owner.as_fields();
        *leaf = [
            Block128::from(out.slot_index as u128),
            Block128::from(out.value as u128),
            owner_hi,
            owner_lo,
        ];
    }

    Ok(SpineInputs {
        epoch_anchor: digest_to_fields(&body.epoch_anchor),
        fee_leaf: digest_to_fields(&fee_leaf(body.fee)),
        input_leaves,
        output_leaves,
        is_coinbase_leaf: digest_to_fields(&is_coinbase_leaf(body.is_coinbase)),
        pad_leaf: [Block128::ZERO; 2],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{compute_tx_body_hash, SpineCircuit};
    use noid_core::CanonicalSerialize;
    use noid_poseidon2b::primitives::{
        derive_address, hash_input_leaf, hash_output_leaf, hash_tx_body, SpendSecret,
    };
    use noid_tx::{TxInput, TxOutput};

    fn digest_fields_to_bytes(fields: [Block128; 2]) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[..16].copy_from_slice(&fields[0].to_bytes());
        out[16..].copy_from_slice(&fields[1].to_bytes());
        out
    }

    #[test]
    fn standard_spine_statement_matches_native_tx_hash() {
        let secret = SpendSecret([3u8; 32]);
        let body = TxBody {
            shape: TxShape::Standard4x8,
            epoch_anchor: [0xA5; 32],
            fee: 7,
            inputs: vec![TxInput {
                slot_index: 11,
                value: 50,
                owner: derive_address(&secret),
                spend_secret: secret.clone(),
                valid: true,
            }],
            outputs: vec![TxOutput {
                slot_index: 20,
                value: 43,
                owner: derive_address(&SpendSecret([4u8; 32])),
                valid: true,
            }],
            is_coinbase: false,
        };

        let inputs = spine_inputs_from_body(&body).expect("standard statement");
        let got = digest_fields_to_bytes(compute_tx_body_hash(&SpineCircuit::build(), &inputs));
        let mut input_leaf_hashes = [[0u8; 32]; 4];
        for (i, leaf) in input_leaf_hashes.iter_mut().enumerate() {
            let input = body.inputs.get(i).cloned().unwrap_or_else(TxInput::dummy);
            *leaf = hash_input_leaf(input.slot_index, input.value, &input.owner);
        }
        let mut output_leaf_hashes = [[0u8; 32]; 8];
        for (i, leaf) in output_leaf_hashes.iter_mut().enumerate() {
            let output = body.outputs.get(i).copied().unwrap_or_else(TxOutput::dummy);
            *leaf = hash_output_leaf(output.slot_index, output.value, &output.owner);
        }
        let native = hash_tx_body(
            &body.epoch_anchor,
            body.fee,
            &input_leaf_hashes,
            &output_leaf_hashes,
            body.is_coinbase,
        );
        assert_eq!(got, native.0);
    }
}
