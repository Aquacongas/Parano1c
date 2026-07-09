// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Canonical sweep-spine public statements derived from `TxBody`.

use noid_core::{Block128, TowerField};
use noid_poseidon2b::primitives::{fee_leaf, is_coinbase_leaf, tx_shape_leaf, Digest};
use noid_tx::{TxBody, TxInput, TxOutput, TxShape};

use crate::SweepSpineInputs;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SweepSpineStatementError {
    Coinbase,
    ShapeMismatch { expected: TxShape, actual: TxShape },
    TooManyInputs { actual: usize, max: usize },
    TooManyOutputs { actual: usize, max: usize },
}

impl std::fmt::Display for SweepSpineStatementError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for SweepSpineStatementError {}

fn check_body_shape(body: &TxBody, expected: TxShape) -> Result<(), SweepSpineStatementError> {
    if body.is_coinbase {
        return Err(SweepSpineStatementError::Coinbase);
    }
    if body.shape != expected {
        return Err(SweepSpineStatementError::ShapeMismatch {
            expected,
            actual: body.shape,
        });
    }
    if body.inputs.len() > body.shape.max_inputs() {
        return Err(SweepSpineStatementError::TooManyInputs {
            actual: body.inputs.len(),
            max: body.shape.max_inputs(),
        });
    }
    if body.outputs.len() > body.shape.max_outputs() {
        return Err(SweepSpineStatementError::TooManyOutputs {
            actual: body.outputs.len(),
            max: body.shape.max_outputs(),
        });
    }
    Ok(())
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

pub fn sweep_spine_inputs_from_body(
    body: &TxBody,
) -> Result<SweepSpineInputs, SweepSpineStatementError> {
    check_body_shape(body, TxShape::Sweep25x2)?;

    let mut input_leaves = [[Block128::ZERO; 4]; TxShape::Sweep25x2.max_inputs()];
    for (i, leaf) in input_leaves
        .iter_mut()
        .enumerate()
        .take(TxShape::Sweep25x2.max_inputs())
    {
        let inp = body.inputs.get(i).cloned().unwrap_or_else(TxInput::dummy);
        let [owner_hi, owner_lo] = inp.owner.as_fields();
        *leaf = [
            Block128::from(inp.slot_index as u128),
            Block128::from(inp.value as u128),
            owner_hi,
            owner_lo,
        ];
    }

    let mut output_leaves = [[Block128::ZERO; 4]; TxShape::Sweep25x2.max_outputs()];
    for (i, leaf) in output_leaves
        .iter_mut()
        .enumerate()
        .take(TxShape::Sweep25x2.max_outputs())
    {
        let out = body.outputs.get(i).copied().unwrap_or_else(TxOutput::dummy);
        let [owner_hi, owner_lo] = out.owner.as_fields();
        *leaf = [
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
        // The reserved leaf carries the committed liveness bitmap — the
        // same rule as the standard spine (L31 of the sweep tree).
        pad_leaf: digest_to_fields(&noid_poseidon2b::primitives::validity_leaf(
            noid_tx::validity_bits_for_shape(body.shape, &body.inputs, &body.outputs),
        )),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuit_sweep::SweepSpineCircuit;
    use crate::oracle_sweep::evaluate_sweep_spine;
    use noid_poseidon2b::primitives::{
        derive_address, hash_input_leaf, hash_output_leaf, hash_tx_body_sweep25x2, SpendSecret,
        SWEEP_TXBODY_INPUTS, SWEEP_TXBODY_OUTPUTS,
    };

    fn fields_to_digest(fields: [Block128; 2]) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[..16].copy_from_slice(&fields[0].to_u128().to_le_bytes());
        out[16..].copy_from_slice(&fields[1].to_u128().to_le_bytes());
        out
    }

    /// The sweep statement's reserved leaf must carry the SAME validity
    /// bitmap the native body hash commits — a SPARSE nonzero live set
    /// (dead dummy holes between live entries) is exactly the case a
    /// zero-bitmap fixture cannot catch.
    #[test]
    fn sweep_spine_statement_matches_native_tx_hash_sparse_bitmap() {
        let secret = SpendSecret([9u8; 32]);
        let owner = derive_address(&secret);
        // Live inputs at positions 0, 2, 5 (one owner per tx); dummy holes
        // at 1, 3, 4; live output at 0, dead dummy at 1.
        let mut inputs = vec![TxInput::dummy(); 6];
        for &pos in &[0usize, 2, 5] {
            inputs[pos] = TxInput {
                slot_index: 100 + pos as u32,
                value: 1_000 + pos as u64,
                owner,
                spend_secret: secret.clone(),
                valid: true,
            };
        }
        let total: u64 = inputs.iter().filter(|i| i.valid).map(|i| i.value).sum();
        let body = TxBody {
            shape: TxShape::Sweep25x2,
            epoch_anchor: [0x77; 32],
            fee: 5,
            inputs,
            outputs: vec![
                TxOutput {
                    slot_index: 900,
                    value: total - 5,
                    owner,
                    valid: true,
                },
                TxOutput::dummy(),
            ],
            is_coinbase: false,
        };

        let statement = sweep_spine_inputs_from_body(&body).expect("sweep statement");
        let got =
            fields_to_digest(evaluate_sweep_spine(&SweepSpineCircuit::build(), &statement).tx_body_hash);

        let mut input_leaf_hashes = [[0u8; 32]; SWEEP_TXBODY_INPUTS];
        for (i, leaf) in input_leaf_hashes.iter_mut().enumerate() {
            let input = body.inputs.get(i).cloned().unwrap_or_else(TxInput::dummy);
            *leaf = hash_input_leaf(input.slot_index, input.value, &input.owner);
        }
        let mut output_leaf_hashes = [[0u8; 32]; SWEEP_TXBODY_OUTPUTS];
        for (i, leaf) in output_leaf_hashes.iter_mut().enumerate() {
            let output = body.outputs.get(i).copied().unwrap_or_else(TxOutput::dummy);
            *leaf = hash_output_leaf(output.slot_index, output.value, &output.owner);
        }
        let bits = noid_tx::validity_bits_for_shape(body.shape, &body.inputs, &body.outputs);
        assert_ne!(bits, 0, "the fixture must exercise a NONZERO bitmap");
        let native = hash_tx_body_sweep25x2(
            &body.epoch_anchor,
            body.fee,
            &input_leaf_hashes,
            &output_leaf_hashes,
            body.is_coinbase,
            bits,
        );
        assert_eq!(got, native.0, "sweep GKR body hash != native (bitmap leaf)");
    }
}
