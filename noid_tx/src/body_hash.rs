// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Canonical transaction-body hash for the transparent UTXO model.
//!
//! Adapter over `noid_poseidon2b::primitives::hash_tx_body`. The
//! primitives layer enforces a fixed 16-leaf / depth-4 layout (see
//! `TXBODY_LEAVES`); this adapter builds the per-input and per-output
//! leaves from `TxInput` / `TxOutput`, padding dummy / missing slots
//! with the zero digest.

use noid_poseidon2b::primitives::{
    hash_input_leaf, hash_output_leaf, hash_tx_body as hash_tx_body_core, Digest, TxBodyHash,
    TXBODY_INPUTS, TXBODY_OUTPUTS,
};

use crate::types::{TxInput, TxOutput, MAX_INPUTS, MAX_OUTPUTS};

/// Compute the canonical transaction-body hash. `inputs.len()` and
/// `outputs.len()` must not exceed `MAX_INPUTS` / `MAX_OUTPUTS`;
/// missing slots are zero-padded so the leaf tree is always depth-4.
pub fn hash_tx_body(
    prev_state_root: &Digest,
    fee: u128,
    inputs: &[TxInput],
    outputs: &[TxOutput],
) -> TxBodyHash {
    assert!(inputs.len() <= MAX_INPUTS, "inputs exceed MAX_INPUTS");
    assert!(outputs.len() <= MAX_OUTPUTS, "outputs exceed MAX_OUTPUTS");
    debug_assert_eq!(MAX_INPUTS, TXBODY_INPUTS);
    debug_assert_eq!(MAX_OUTPUTS, TXBODY_OUTPUTS);

    let mut input_leaves: [Digest; TXBODY_INPUTS] = [[0u8; 32]; TXBODY_INPUTS];
    for (i, inp) in inputs.iter().enumerate() {
        // Dummy slots collapse to the zero digest — same as a missing
        // slot — so the body hash cannot distinguish `valid=false` from
        // an absent slot, matching the AIR's selector treatment.
        if inp.valid {
            input_leaves[i] = hash_input_leaf(inp.slot_index, inp.value, &inp.owner);
        }
    }

    let mut output_leaves: [Digest; TXBODY_OUTPUTS] = [[0u8; 32]; TXBODY_OUTPUTS];
    for (i, out) in outputs.iter().enumerate() {
        if out.valid {
            output_leaves[i] = hash_output_leaf(out.value, &out.owner);
        }
    }

    hash_tx_body_core(prev_state_root, fee, &input_leaves, &output_leaves)
}

#[cfg(test)]
mod tests {
    use super::*;
    use noid_poseidon2b::primitives::{Address, AuthTag, SpendSecret};

    fn mk_input(seed: u8) -> TxInput {
        TxInput {
            slot_index: seed as u32,
            value: (seed as u64) * 11,
            owner: Address([seed; 32]),
            spend_secret: SpendSecret([seed ^ 0xAA; 32]),
            auth_tag: AuthTag([seed ^ 0x55; 32]),
            valid: true,
        }
    }

    fn mk_output(seed: u8) -> TxOutput {
        TxOutput {
            value: (seed as u64) * 7,
            owner: Address([seed; 32]),
            valid: true,
        }
    }

    #[test]
    fn determinism() {
        let prev = [0xABu8; 32];
        let i = [mk_input(1)];
        let o = [mk_output(2), mk_output(3)];
        assert_eq!(
            hash_tx_body(&prev, 5, &i, &o),
            hash_tx_body(&prev, 5, &i, &o)
        );
    }

    #[test]
    fn output_value_flip_changes_body_hash() {
        let prev = [0u8; 32];
        let o1 = mk_output(1);
        let mut o2 = o1;
        o2.value ^= 0xFF;
        let h1 = hash_tx_body(&prev, 0, &[], &[o1]);
        let h2 = hash_tx_body(&prev, 0, &[], &[o2]);
        assert_ne!(h1, h2);
    }

    #[test]
    fn input_slot_index_is_bound() {
        // Body hash must bind the slot index, since the AIR checks
        // state openings at that index.
        let prev = [0u8; 32];
        let mut i1 = mk_input(1);
        let mut i2 = i1;
        i2.slot_index ^= 0x55;
        i1.valid = true;
        let h1 = hash_tx_body(&prev, 0, &[i1], &[]);
        let h2 = hash_tx_body(&prev, 0, &[i2], &[]);
        assert_ne!(h1, h2);
    }

    #[test]
    fn ordering_and_fee_sensitive() {
        let prev = [0u8; 32];
        let i1 = mk_input(1);
        let i2 = mk_input(2);
        let h_a = hash_tx_body(&prev, 10, &[i1, i2], &[]);
        let h_b = hash_tx_body(&prev, 10, &[i2, i1], &[]);
        let h_c = hash_tx_body(&prev, 11, &[i1, i2], &[]);
        assert_ne!(h_a, h_b);
        assert_ne!(h_a, h_c);
    }

    #[test]
    fn dummy_input_equals_zero_leaf() {
        // A body with `valid=false` inputs must hash the same as a body
        // missing those inputs outright.
        let prev = [0u8; 32];
        let real = mk_input(1);
        let h1 = hash_tx_body(&prev, 0, &[real], &[]);
        let h2 = hash_tx_body(&prev, 0, &[real, TxInput::dummy(), TxInput::dummy()], &[]);
        assert_eq!(h1, h2);
    }
}
