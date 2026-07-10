// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Canonical Tx8x2 statements on the temporary 59-permutation carrier.

use noid_core::Block128;
use noid_poseidon2b::primitives::{fee_leaf, is_coinbase_leaf, Digest};
use noid_tx::{body_hash::carrier_payloads, TxBody};

use crate::SpineInputs;

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

pub fn spine_inputs_from_body(body: &TxBody) -> SpineInputs {
    let (input_leaves, output_leaves) = carrier_payloads(body);
    SpineInputs {
        epoch_anchor: digest_to_fields(&body.epoch_anchor),
        fee_leaf: digest_to_fields(&fee_leaf(body.fee)),
        input_leaves,
        output_leaves,
        is_coinbase_leaf: digest_to_fields(&is_coinbase_leaf(body.is_coinbase)),
        // The reserved leaf carries the sole committed liveness bitmap.
        pad_leaf: digest_to_fields(&noid_poseidon2b::primitives::validity_leaf(
            body.validity_bitmap,
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{compute_tx_body_hash, SpineCircuit};
    use noid_core::CanonicalSerialize;
    use noid_poseidon2b::primitives::Address;
    use noid_tx::{output_bitmap_bit, TxInput, TxOutput, TX_INPUTS, TX_OUTPUTS};

    fn digest_fields_to_bytes(fields: [Block128; 2]) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[..16].copy_from_slice(&fields[0].to_bytes());
        out[16..].copy_from_slice(&fields[1].to_bytes());
        out
    }

    #[test]
    fn tx8x2_carrier_statement_matches_native_tx_hash() {
        let mut inputs = [TxInput::dummy(); TX_INPUTS];
        inputs[0] = TxInput {
            slot_index: 11,
            amount: 50,
            creation_id: 29,
        };
        inputs[7] = TxInput {
            slot_index: 77,
            amount: 20,
            creation_id: 31,
        };
        let mut outputs = [TxOutput::dummy(); TX_OUTPUTS];
        outputs[0] = TxOutput {
            slot_index: 20,
            amount: 63,
            owner: Address([4u8; 32]),
        };
        let body = TxBody {
            epoch_anchor: [0xA5; 32],
            fee: 7,
            input_owner: Address([3u8; 32]),
            inputs,
            outputs,
            validity_bitmap: (1 << 0) | (1 << 7) | output_bitmap_bit(0),
            is_coinbase: false,
        };

        let circuit = SpineCircuit::build();
        assert_eq!(
            circuit.slots.len(),
            59,
            "incarnations must not grow the spine"
        );

        let mut hashes = Vec::new();
        for creation_id in [0, 31] {
            let mut body = body.clone();
            body.inputs[7].creation_id = creation_id;
            let statement = spine_inputs_from_body(&body);
            let got = digest_fields_to_bytes(compute_tx_body_hash(&circuit, &statement));
            assert_eq!(got, body.txid().0);
            hashes.push(got);
        }
        assert_ne!(hashes[0], hashes[1], "logical input 7 must be bound");
    }
}
