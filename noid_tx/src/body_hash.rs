// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

#![allow(clippy::needless_range_loop)]

//! Canonical transaction-body hash for the transparent UTXO model.
//!
//! Adapter over `noid_poseidon2b::primitives::hash_tx_body`. The
//! primitives layer enforces a fixed 16-leaf / depth-4 layout (see
//! `TXBODY_LEAVES`); this adapter builds the per-input and per-output
//! leaves from `TxInput` / `TxOutput`, filling missing slots with
//! `TxInput::dummy` / `TxOutput::dummy`.
//!
//! Every slot is hashed unconditionally, including `valid=false`
//! slots (which absorb `(0, 0, zero_address)` fields), AND the per-entry
//! `valid` selectors are committed as a bitmap in the reserved pad leaf
//! (input bit `i`, output bit `max_inputs + j`): the same slot contents
//! with different liveness selectors are DIFFERENT transactions — the
//! balance/action semantics are bound by the hash, so no consumer can
//! reinterpret one body hash under another live set.

use noid_poseidon2b::primitives::{
    hash_input_leaf_packed, hash_output_leaf, hash_tx_body as hash_tx_body_core,
    hash_tx_body_sweep25x2 as hash_tx_body_sweep25x2_core, Digest, TxBodyHash, SWEEP_TXBODY_INPUTS,
    SWEEP_TXBODY_OUTPUTS, TXBODY_INPUTS, TXBODY_OUTPUTS,
};

use crate::types::{pack_amount_creation_id, TxInput, TxOutput, TxShape};

/// Compute the canonical transaction-body hash. `inputs.len()` and
/// `outputs.len()` must not exceed `MAX_INPUTS` / `MAX_OUTPUTS`;
/// missing slots are filled with `TxInput::dummy` / `TxOutput::dummy`
/// so the leaf tree is always depth-4. Every slot — including
/// `valid=false` ones — is hashed into its leaf.
///
/// `epoch_anchor` occupies leaf L0 (replacing the former
/// `prev_state_root`), providing fork-binding and natural TTL.
pub fn hash_tx_body(
    epoch_anchor: &Digest,
    fee: u128,
    inputs: &[TxInput],
    outputs: &[TxOutput],
    is_coinbase: bool,
) -> TxBodyHash {
    hash_tx_body_for_shape(
        TxShape::Standard4x8,
        epoch_anchor,
        fee,
        inputs,
        outputs,
        is_coinbase,
    )
}

/// The liveness bitmap committed in the body's reserved leaf: input bit
/// `i`, output bit `max_inputs + j`. Shared by the body hash, the spine
/// statement and every consumer that re-derives the committed selectors.
pub fn validity_bits_for_shape(shape: TxShape, inputs: &[TxInput], outputs: &[TxOutput]) -> u128 {
    let mut bits = 0u128;
    for (i, inp) in inputs.iter().enumerate() {
        if inp.valid {
            bits |= 1u128 << i;
        }
    }
    for (j, out) in outputs.iter().enumerate() {
        if out.valid {
            bits |= 1u128 << (shape.max_inputs() + j);
        }
    }
    bits
}

/// Compute the canonical transaction-body hash for a specific shape.
///
/// `Standard4x8` preserves the existing 16-leaf launch layout exactly.
/// `Sweep25x2` uses the reserved 32-leaf layout with an explicit shape leaf.
pub fn hash_tx_body_for_shape(
    shape: TxShape,
    epoch_anchor: &Digest,
    fee: u128,
    inputs: &[TxInput],
    outputs: &[TxOutput],
    is_coinbase: bool,
) -> TxBodyHash {
    assert!(
        inputs.len() <= shape.max_inputs(),
        "inputs exceed shape max"
    );
    assert!(
        outputs.len() <= shape.max_outputs(),
        "outputs exceed shape max"
    );

    let validity_bits = validity_bits_for_shape(shape, inputs, outputs);

    match shape {
        TxShape::Standard4x8 => {
            debug_assert_eq!(shape.max_inputs(), TXBODY_INPUTS);
            debug_assert_eq!(shape.max_outputs(), TXBODY_OUTPUTS);

            let mut input_leaves: [Digest; TXBODY_INPUTS] = [[0u8; 32]; TXBODY_INPUTS];
            for i in 0..TXBODY_INPUTS {
                let inp = inputs.get(i).cloned().unwrap_or_else(TxInput::dummy);
                input_leaves[i] = hash_input_leaf_packed(
                    inp.slot_index,
                    pack_amount_creation_id(inp.value, inp.creation_id),
                    &inp.owner,
                );
            }

            let mut output_leaves: [Digest; TXBODY_OUTPUTS] = [[0u8; 32]; TXBODY_OUTPUTS];
            for i in 0..TXBODY_OUTPUTS {
                let out = outputs.get(i).copied().unwrap_or_else(TxOutput::dummy);
                output_leaves[i] = hash_output_leaf(out.slot_index, out.value, &out.owner);
            }

            hash_tx_body_core(
                epoch_anchor,
                fee,
                &input_leaves,
                &output_leaves,
                is_coinbase,
                validity_bits,
            )
        }
        TxShape::Sweep25x2 => {
            debug_assert_eq!(shape.max_inputs(), SWEEP_TXBODY_INPUTS);
            debug_assert_eq!(shape.max_outputs(), SWEEP_TXBODY_OUTPUTS);

            let mut input_leaves: [Digest; SWEEP_TXBODY_INPUTS] = [[0u8; 32]; SWEEP_TXBODY_INPUTS];
            for i in 0..SWEEP_TXBODY_INPUTS {
                let inp = inputs.get(i).cloned().unwrap_or_else(TxInput::dummy);
                input_leaves[i] = hash_input_leaf_packed(
                    inp.slot_index,
                    pack_amount_creation_id(inp.value, inp.creation_id),
                    &inp.owner,
                );
            }

            let mut output_leaves: [Digest; SWEEP_TXBODY_OUTPUTS] =
                [[0u8; 32]; SWEEP_TXBODY_OUTPUTS];
            for i in 0..SWEEP_TXBODY_OUTPUTS {
                let out = outputs.get(i).copied().unwrap_or_else(TxOutput::dummy);
                output_leaves[i] = hash_output_leaf(out.slot_index, out.value, &out.owner);
            }

            hash_tx_body_sweep25x2_core(
                epoch_anchor,
                fee,
                &input_leaves,
                &output_leaves,
                is_coinbase,
                validity_bits,
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use noid_poseidon2b::primitives::{Address, SpendSecret};

    fn mk_input(seed: u8) -> TxInput {
        TxInput {
            slot_index: seed as u32,
            value: (seed as u64) * 11,
            creation_id: 0,
            owner: Address([seed; 32]),
            spend_secret: SpendSecret([seed ^ 0xAA; 32]),
            valid: true,
        }
    }

    fn mk_output(seed: u8) -> TxOutput {
        TxOutput {
            slot_index: (seed as u32).wrapping_mul(3),
            value: (seed as u64) * 7,
            owner: Address([seed; 32]),
            valid: true,
        }
    }

    #[test]
    fn determinism() {
        let anchor = [0xABu8; 32];
        let i = [mk_input(1)];
        let o = [mk_output(2), mk_output(3)];
        assert_eq!(
            hash_tx_body(&anchor, 5, &i, &o, false),
            hash_tx_body(&anchor, 5, &i, &o, false)
        );
    }

    #[test]
    fn output_value_flip_changes_body_hash() {
        let anchor = [0u8; 32];
        let o1 = mk_output(1);
        let mut o2 = o1;
        o2.value ^= 0xFF;
        let h1 = hash_tx_body(&anchor, 0, &[], &[o1], false);
        let h2 = hash_tx_body(&anchor, 0, &[], &[o2], false);
        assert_ne!(h1, h2);
    }

    #[test]
    fn output_slot_index_is_bound() {
        let anchor = [0u8; 32];
        let o1 = mk_output(1);
        let mut o2 = o1;
        o2.slot_index ^= 0x33;
        let h1 = hash_tx_body(&anchor, 0, &[], &[o1], false);
        let h2 = hash_tx_body(&anchor, 0, &[], &[o2], false);
        assert_ne!(h1, h2);
    }

    #[test]
    fn input_slot_index_is_bound() {
        let anchor = [0u8; 32];
        let mut i1 = mk_input(1);
        let mut i2 = i1.clone();
        i2.slot_index ^= 0x55;
        i1.valid = true;
        let h1 = hash_tx_body(&anchor, 0, &[i1], &[], false);
        let h2 = hash_tx_body(&anchor, 0, &[i2], &[], false);
        assert_ne!(h1, h2);
    }

    #[test]
    fn input_creation_id_zero_uses_low_lane_and_nonzero_is_bound() {
        let anchor = [0x31u8; 32];
        let zero_id = mk_input(3);
        let zero_id_leaf = hash_input_leaf_packed(
            zero_id.slot_index,
            pack_amount_creation_id(zero_id.value, zero_id.creation_id),
            &zero_id.owner,
        );
        assert_eq!(
            zero_id_leaf,
            hash_input_leaf_packed(
                zero_id.slot_index,
                pack_amount_creation_id(zero_id.value, 0),
                &zero_id.owner,
            )
        );

        let h0 = hash_tx_body(&anchor, 0, std::slice::from_ref(&zero_id), &[], false);
        let mut incarnated = zero_id;
        incarnated.creation_id = 9;
        let h9 = hash_tx_body(&anchor, 0, &[incarnated], &[], false);
        assert_ne!(h0, h9);
    }

    #[test]
    fn ordering_and_fee_sensitive() {
        let anchor = [0u8; 32];
        let i1 = mk_input(1);
        let i2 = mk_input(2);
        let h_a = hash_tx_body(&anchor, 10, &[i1.clone(), i2.clone()], &[], false);
        let h_b = hash_tx_body(&anchor, 10, &[i2.clone(), i1.clone()], &[], false);
        let h_c = hash_tx_body(&anchor, 11, &[i1, i2], &[], false);
        assert_ne!(h_a, h_b);
        assert_ne!(h_a, h_c);
    }

    #[test]
    fn dummy_input_equals_zero_leaf() {
        let anchor = [0u8; 32];
        let real = mk_input(1);
        let h1 = hash_tx_body(&anchor, 0, std::slice::from_ref(&real), &[], false);
        let h2 = hash_tx_body(
            &anchor,
            0,
            &[real, TxInput::dummy(), TxInput::dummy()],
            &[],
            false,
        );
        assert_eq!(h1, h2);
    }

    #[test]
    fn is_coinbase_flips_hash() {
        let anchor = [0u8; 32];
        let h0 = hash_tx_body(&anchor, 0, &[], &[], false);
        let h1 = hash_tx_body(&anchor, 0, &[], &[], true);
        assert_ne!(h0, h1);
    }

    #[test]
    fn epoch_anchor_flip_changes_body_hash() {
        let a1 = [0x11u8; 32];
        let a2 = [0x22u8; 32];
        let h1 = hash_tx_body(&a1, 0, &[], &[], false);
        let h2 = hash_tx_body(&a2, 0, &[], &[], false);
        assert_ne!(h1, h2);
    }

    #[test]
    fn sweep_hash_is_shape_separated() {
        let anchor = [0x44u8; 32];
        let inputs = vec![mk_input(1)];
        let outputs = vec![mk_output(1)];
        let standard =
            hash_tx_body_for_shape(TxShape::Standard4x8, &anchor, 7, &inputs, &outputs, false);
        let sweep =
            hash_tx_body_for_shape(TxShape::Sweep25x2, &anchor, 7, &inputs, &outputs, false);
        assert_ne!(standard, sweep);
    }

    #[test]
    fn sweep_hash_binds_last_input_and_second_output() {
        let anchor = [0x55u8; 32];
        let mut inputs: Vec<TxInput> = (0..25).map(|i| mk_input(i as u8 + 1)).collect();
        let outputs = vec![mk_output(1), mk_output(2)];
        let h1 = hash_tx_body_for_shape(TxShape::Sweep25x2, &anchor, 9, &inputs, &outputs, false);
        inputs[24].value ^= 1;
        let h2 = hash_tx_body_for_shape(TxShape::Sweep25x2, &anchor, 9, &inputs, &outputs, false);
        assert_ne!(h1, h2);

        let mut outputs2 = outputs;
        outputs2[1].owner = Address([0xEE; 32]);
        let h3 = hash_tx_body_for_shape(TxShape::Sweep25x2, &anchor, 9, &inputs, &outputs2, false);
        assert_ne!(h2, h3);
    }

    #[test]
    #[should_panic(expected = "inputs exceed shape max")]
    fn standard_hash_rejects_more_than_four_inputs() {
        let inputs = vec![TxInput::dummy(); 5];
        let _ = hash_tx_body_for_shape(TxShape::Standard4x8, &[0u8; 32], 0, &inputs, &[], false);
    }

    #[test]
    #[should_panic(expected = "outputs exceed shape max")]
    fn sweep_hash_rejects_more_than_two_outputs() {
        let outputs = vec![TxOutput::dummy(); 3];
        let _ = hash_tx_body_for_shape(TxShape::Sweep25x2, &[0u8; 32], 0, &[], &outputs, false);
    }
}
