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
        pad_leaf: [Block128::ZERO, Block128::ZERO],
    })
}
