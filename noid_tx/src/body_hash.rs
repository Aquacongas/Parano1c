// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Canonical Tx8x2 body hash on the temporary 59-permutation carrier.
//!
//! The public body is already final. Until the flattened 31-permutation spine
//! lands, its records are injectively mapped into the existing 4-input/8-output
//! carrier. This module is the single native definition of that mapping.

use noid_core::{Block128, TowerField};
use noid_poseidon2b::primitives::{
    hash_input_leaf_packed, hash_output_leaf_packed, hash_tx_body_carrier, Address, Digest,
    TxBodyHash, TXBODY_CARRIER_INPUTS, TXBODY_CARRIER_OUTPUTS,
};

use crate::{pack_amount_creation_id, TxBody, TX_INPUTS, TX_OUTPUTS};

pub const CARRIER_INPUTS: usize = TXBODY_CARRIER_INPUTS;
pub const CARRIER_OUTPUTS: usize = TXBODY_CARRIER_OUTPUTS;

/// Logical Tx8x2 records expressed as the old carrier's raw four-lane
/// payloads. This is proof plumbing, never a wire representation.
pub fn carrier_payloads(
    body: &TxBody,
) -> (
    [[Block128; 4]; CARRIER_INPUTS],
    [[Block128; 4]; CARRIER_OUTPUTS],
) {
    let mut carrier_inputs = [[Block128::ZERO; 4]; CARRIER_INPUTS];
    let mut carrier_outputs = [[Block128::ZERO; 4]; CARRIER_OUTPUTS];
    let [owner_hi, owner_lo] = body.input_owner.as_fields();

    for logical_index in 0..TX_INPUTS {
        let input = body.inputs[logical_index];
        let owner = if body.input_is_live(logical_index) {
            [owner_hi, owner_lo]
        } else {
            [Block128::ZERO; 2]
        };
        let payload = [
            Block128::from(input.slot_index as u128),
            pack_amount_creation_id(input.amount, input.creation_id),
            owner[0],
            owner[1],
        ];
        if logical_index < CARRIER_INPUTS {
            carrier_inputs[logical_index] = payload;
        } else {
            carrier_outputs[logical_index - CARRIER_INPUTS] = payload;
        }
    }

    for logical_index in 0..TX_OUTPUTS {
        let output = body.outputs[logical_index];
        let [output_owner_hi, output_owner_lo] = output.owner.as_fields();
        carrier_outputs[4 + logical_index] = [
            Block128::from(output.slot_index as u128),
            Block128::from(output.amount as u128),
            output_owner_hi,
            output_owner_lo,
        ];
    }

    // Carrier output payloads 6 and 7 remain the fixed zero payload.
    (carrier_inputs, carrier_outputs)
}

pub fn hash_tx_body(body: &TxBody) -> TxBodyHash {
    let (input_payloads, output_payloads) = carrier_payloads(body);
    let mut input_leaves: [Digest; CARRIER_INPUTS] = [[0u8; 32]; CARRIER_INPUTS];
    let mut output_leaves: [Digest; CARRIER_OUTPUTS] = [[0u8; 32]; CARRIER_OUTPUTS];

    for (index, payload) in input_payloads.iter().enumerate() {
        input_leaves[index] = hash_input_leaf_packed(
            payload[0].0 as u32,
            payload[1],
            &address_from_fields(payload[2], payload[3]),
        );
    }
    for (index, payload) in output_payloads.iter().enumerate() {
        output_leaves[index] = hash_output_leaf_packed(
            payload[0].0 as u32,
            payload[1],
            &address_from_fields(payload[2], payload[3]),
        );
    }

    hash_tx_body_carrier(
        &body.epoch_anchor,
        body.fee,
        &input_leaves,
        &output_leaves,
        body.is_coinbase,
        body.validity_bitmap,
    )
}

fn address_from_fields(hi: Block128, lo: Block128) -> Address {
    let mut bytes = [0u8; 32];
    bytes[..16].copy_from_slice(&hi.0.to_le_bytes());
    bytes[16..].copy_from_slice(&lo.0.to_le_bytes());
    Address(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{output_bitmap_bit, TxInput, TxOutput, TX_VALIDITY_MASK};

    fn body() -> TxBody {
        let mut inputs = [TxInput::dummy(); TX_INPUTS];
        inputs[0] = TxInput {
            slot_index: 11,
            amount: 50,
            creation_id: 3,
        };
        inputs[7] = TxInput {
            slot_index: 77,
            amount: 60,
            creation_id: 9,
        };
        let outputs = [
            TxOutput {
                slot_index: 101,
                amount: 70,
                owner: Address([0x31; 32]),
            },
            TxOutput {
                slot_index: 102,
                amount: 30,
                owner: Address([0x32; 32]),
            },
        ];
        TxBody {
            epoch_anchor: [0xA5; 32],
            fee: 10,
            input_owner: Address([0x21; 32]),
            inputs,
            outputs,
            validity_bitmap: (1 << 0) | (1 << 7) | output_bitmap_bit(0) | output_bitmap_bit(1),
            is_coinbase: false,
        }
    }

    #[test]
    fn carrier_mapping_uses_every_logical_edge() {
        let body = body();
        let (ins, outs) = carrier_payloads(&body);
        assert_eq!(ins[0][0], Block128::from(11u128));
        assert_eq!(outs[3][0], Block128::from(77u128));
        assert_eq!(outs[4][0], Block128::from(101u128));
        assert_eq!(outs[5][0], Block128::from(102u128));
        assert_eq!(outs[6], [Block128::ZERO; 4]);
        assert_eq!(outs[7], [Block128::ZERO; 4]);
    }

    #[test]
    fn input_seven_creation_id_high_half_is_bound() {
        let body = body();
        let h0 = hash_tx_body(&body);
        let mut changed = body;
        changed.inputs[7].creation_id ^= 1;
        assert_ne!(h0, hash_tx_body(&changed));
    }

    #[test]
    fn every_body_surface_is_hash_bound() {
        let base = body();
        let hash = hash_tx_body(&base);

        let mut variants = Vec::new();
        let mut v = base.clone();
        v.epoch_anchor[0] ^= 1;
        variants.push(v);
        let mut v = base.clone();
        v.fee ^= 1;
        variants.push(v);
        let mut v = base.clone();
        v.input_owner.0[0] ^= 1;
        variants.push(v);
        let mut v = base.clone();
        v.inputs[0].slot_index ^= 1;
        variants.push(v);
        let mut v = base.clone();
        v.inputs[7].amount ^= 1;
        variants.push(v);
        let mut v = base.clone();
        v.outputs[0].owner.0[0] ^= 1;
        variants.push(v);
        let mut v = base.clone();
        v.outputs[1].amount ^= 1;
        variants.push(v);
        let mut v = base.clone();
        v.validity_bitmap ^= 1 << 4;
        variants.push(v);
        let mut v = base;
        v.is_coinbase = true;
        variants.push(v);

        for variant in variants {
            assert_ne!(hash, hash_tx_body(&variant));
        }
        assert_eq!(TX_VALIDITY_MASK, 0x03ff);
    }

    #[test]
    fn every_fixed_record_lane_is_hash_bound() {
        let mut inputs = [TxInput::dummy(); TX_INPUTS];
        for (index, input) in inputs.iter_mut().enumerate() {
            *input = TxInput {
                slot_index: 100 + index as u32,
                amount: 10 + index as u64,
                creation_id: 1_000 + index as u64,
            };
        }
        let outputs = [
            TxOutput {
                slot_index: 200,
                amount: 50,
                owner: Address([0x41; 32]),
            },
            TxOutput {
                slot_index: 201,
                amount: 51,
                owner: Address([0x42; 32]),
            },
        ];
        let body = TxBody {
            epoch_anchor: [0x51; 32],
            fee: 7,
            input_owner: Address([0x52; 32]),
            inputs,
            outputs,
            validity_bitmap: TX_VALIDITY_MASK,
            is_coinbase: false,
        };
        assert!(body.validate_canonical().is_ok());
        let expected = hash_tx_body(&body);

        for index in 0..TX_INPUTS {
            let mut changed = body.clone();
            changed.inputs[index].slot_index ^= 1;
            assert_ne!(expected, hash_tx_body(&changed), "input {index} slot");

            let mut changed = body.clone();
            changed.inputs[index].amount ^= 1;
            assert_ne!(expected, hash_tx_body(&changed), "input {index} amount");

            let mut changed = body.clone();
            changed.inputs[index].creation_id ^= 1;
            assert_ne!(
                expected,
                hash_tx_body(&changed),
                "input {index} creation id"
            );
        }

        for index in 0..TX_OUTPUTS {
            let mut changed = body.clone();
            changed.outputs[index].slot_index ^= 1;
            assert_ne!(expected, hash_tx_body(&changed), "output {index} slot");

            let mut changed = body.clone();
            changed.outputs[index].amount ^= 1;
            assert_ne!(expected, hash_tx_body(&changed), "output {index} amount");

            let mut changed = body.clone();
            changed.outputs[index].owner.0[31] ^= 1;
            assert_ne!(expected, hash_tx_body(&changed), "output {index} owner");
        }

        for bit in 0..crate::TX_ACTIONS {
            let mut changed = body.clone();
            changed.validity_bitmap ^= 1 << bit;
            assert_ne!(expected, hash_tx_body(&changed), "bitmap bit {bit}");
        }
    }
}
