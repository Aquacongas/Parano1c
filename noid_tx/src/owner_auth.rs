// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Canonical owner-batched authorization statement.
//!
//! This module is intentionally transaction-layer only: it derives the public
//! owner statement from `TxBody` and never reads `SpendSecret`.

use noid_poseidon2b::primitives::{Address, TxBodyHash};

use crate::{hash_tx_body_for_shape, TxBody, TxShape};

pub const MAX_OWNER_AUTH_GROUPS: usize = 25;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnerAuthError {
    Coinbase,
    UnsupportedShape(TxShape),
    TooManyInputs { actual: usize, max: usize },
    TooManyOutputs { actual: usize, max: usize },
    NoLiveInputs,
    TooManyOwnerGroups { actual: usize, max: usize },
}

impl std::fmt::Display for OwnerAuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for OwnerAuthError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct OwnerAuthGroup {
    pub owner: Address,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CanonicalOwnerAuth {
    pub tx_body_hash: TxBodyHash,
    /// Physical input positions in `TxBody.inputs` where `valid = true`.
    pub live_input_positions: Vec<usize>,
    /// UTXO slot indices for the live inputs, in canonical transaction order.
    pub live_slot_indices: Vec<u32>,
    /// Unique owners in first-occurrence order.
    pub groups: Vec<OwnerAuthGroup>,
    /// For each live input position, the index into `groups`.
    pub input_to_group: Vec<usize>,
    /// Transcript padding width for the per-input vectors: the shape's input
    /// capacity (`TxShape::max_inputs`). The authorization transcript absorbs
    /// each vector padded to this length with a sentinel so that the absorb
    /// schedule depends only on the shape, never on the live-input count.
    pub padded_input_len: usize,
}

impl CanonicalOwnerAuth {
    #[inline]
    pub fn owner_count(&self) -> usize {
        self.groups.len()
    }

    #[inline]
    pub fn live_input_count(&self) -> usize {
        self.live_input_positions.len()
    }
}

pub fn canonical_owner_auth(body: &TxBody) -> Result<CanonicalOwnerAuth, OwnerAuthError> {
    if body.is_coinbase {
        return Err(OwnerAuthError::Coinbase);
    }
    if !body.shape.proof_supported() {
        return Err(OwnerAuthError::UnsupportedShape(body.shape));
    }

    let max_inputs = body.shape.max_inputs();
    if body.inputs.len() > max_inputs {
        return Err(OwnerAuthError::TooManyInputs {
            actual: body.inputs.len(),
            max: max_inputs,
        });
    }
    let max_outputs = body.shape.max_outputs();
    if body.outputs.len() > max_outputs {
        return Err(OwnerAuthError::TooManyOutputs {
            actual: body.outputs.len(),
            max: max_outputs,
        });
    }

    let mut live_input_positions = Vec::new();
    let mut live_slot_indices = Vec::new();
    let mut groups: Vec<OwnerAuthGroup> = Vec::new();
    let mut first_positions: Vec<usize> = Vec::new();
    let mut input_to_group = Vec::new();

    for (input_position, input) in body.inputs.iter().enumerate() {
        if !input.valid {
            continue;
        }
        live_input_positions.push(input_position);
        live_slot_indices.push(input.slot_index);
        let group_idx = match groups.iter().position(|group| group.owner == input.owner) {
            Some(idx) => idx,
            None => {
                groups.push(OwnerAuthGroup { owner: input.owner });
                first_positions.push(input_position);
                groups.len() - 1
            }
        };
        input_to_group.push(group_idx);
    }

    if live_input_positions.is_empty() {
        return Err(OwnerAuthError::NoLiveInputs);
    }
    if groups.len() > MAX_OWNER_AUTH_GROUPS {
        return Err(OwnerAuthError::TooManyOwnerGroups {
            actual: groups.len(),
            max: MAX_OWNER_AUTH_GROUPS,
        });
    }

    let tx_body_hash = hash_tx_body_for_shape(
        body.shape,
        &body.epoch_anchor,
        body.fee,
        &body.inputs,
        &body.outputs,
        body.is_coinbase,
    );

    Ok(CanonicalOwnerAuth {
        tx_body_hash,
        live_input_positions,
        live_slot_indices,
        groups,
        input_to_group,
        padded_input_len: max_inputs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{TxInput, TxOutput};
    use noid_poseidon2b::primitives::SpendSecret;

    fn input(owner: u8, valid: bool) -> TxInput {
        TxInput {
            slot_index: owner as u32,
            value: 10,
            owner: Address([owner; 32]),
            spend_secret: SpendSecret([0xEE; 32]),
            valid,
        }
    }

    fn output(value: u64) -> TxOutput {
        TxOutput {
            slot_index: 100,
            value,
            owner: Address([0xA0; 32]),
            valid: true,
        }
    }

    fn body(shape: TxShape, inputs: Vec<TxInput>) -> TxBody {
        TxBody {
            shape,
            epoch_anchor: [0x51; 32],
            fee: 1,
            inputs,
            outputs: vec![output(9)],
            is_coinbase: false,
        }
    }

    #[test]
    fn groups_unique_owners_by_first_live_physical_position() {
        let body = body(
            TxShape::Sweep25x2,
            vec![
                input(1, false),
                input(2, true),
                input(3, true),
                input(2, true),
            ],
        );

        let stmt = canonical_owner_auth(&body).expect("canonical statement");
        assert_eq!(stmt.live_input_positions, vec![1, 2, 3]);
        assert_eq!(stmt.live_slot_indices, vec![2, 3, 2]);
        assert_eq!(stmt.groups.len(), 2);
        assert_eq!(stmt.groups[0].owner, Address([2; 32]));
        assert_eq!(stmt.groups[1].owner, Address([3; 32]));
        assert_eq!(stmt.input_to_group, vec![0, 1, 0]);
    }

    #[test]
    fn repeated_owner_maps_to_first_owner_group() {
        let body = body(
            TxShape::Sweep25x2,
            vec![input(2, true), input(3, true), input(2, true)],
        );

        let stmt = canonical_owner_auth(&body).expect("canonical statement");
        assert_eq!(stmt.groups.len(), 2);
        assert_eq!(stmt.input_to_group, vec![0, 1, 0]);
    }

    #[test]
    fn zero_input_non_coinbase_rejects() {
        let body = body(TxShape::Standard4x8, vec![input(1, false)]);
        assert_eq!(
            canonical_owner_auth(&body),
            Err(OwnerAuthError::NoLiveInputs)
        );
    }

    #[test]
    fn coinbase_rejects() {
        let mut body = body(TxShape::Standard4x8, vec![]);
        body.is_coinbase = true;
        assert_eq!(canonical_owner_auth(&body), Err(OwnerAuthError::Coinbase));
    }

    #[test]
    fn shape_capacity_rejects_before_hashing() {
        let mut body = body(
            TxShape::Standard4x8,
            (0..=TxShape::Standard4x8.max_inputs())
                .map(|i| input(i as u8, true))
                .collect(),
        );
        assert_eq!(
            canonical_owner_auth(&body),
            Err(OwnerAuthError::TooManyInputs { actual: 5, max: 4 })
        );

        body.inputs.truncate(TxShape::Standard4x8.max_inputs());
        body.outputs = vec![output(1); TxShape::Standard4x8.max_outputs() + 1];
        assert_eq!(
            canonical_owner_auth(&body),
            Err(OwnerAuthError::TooManyOutputs { actual: 9, max: 8 })
        );
    }
}
