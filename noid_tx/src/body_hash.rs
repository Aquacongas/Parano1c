// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Canonical transaction-body hash for the transparent UTXO model.
//!
//! Adapter over `noid_poseidon2b::primitives::hash_tx_body`. The
//! primitives layer enforces a fixed 16-leaf / depth-4 layout (see
//! `TXBODY_LEAVES`); this adapter builds the per-input and per-output
//! leaves from `TxInput` / `TxOutput`, filling missing slots with
//! `TxInput::dummy` / `TxOutput::dummy`.
//!
//! Every slot is hashed unconditionally, including `valid=false`
//! slots (which absorb `(0, 0, zero_address)` fields). `valid` is a
//! pure AIR selector, not an input to the body hash; this matches
//! the AIR's `pins.{input,output}_leaf_absorb` lowering exactly.

use noid_poseidon2b::primitives::{
    hash_input_leaf, hash_output_leaf, hash_tx_body as hash_tx_body_core, Digest, TxBodyHash,
    TXBODY_INPUTS, TXBODY_OUTPUTS,
};

use crate::types::{TxInput, TxOutput, MAX_INPUTS, MAX_OUTPUTS};

/// Compute the canonical transaction-body hash. `inputs.len()` and
/// `outputs.len()` must not exceed `MAX_INPUTS` / `MAX_OUTPUTS`;
/// missing slots are filled with `TxInput::dummy` / `TxOutput::dummy`
/// so the leaf tree is always depth-4. Every slot — including
/// `valid=false` ones — is hashed into its leaf.
pub fn hash_tx_body(
    prev_state_root: &Digest,
    fee: u128,
    inputs: &[TxInput],
    outputs: &[TxOutput],
    is_coinbase: bool,
) -> TxBodyHash {
    assert!(inputs.len() <= MAX_INPUTS, "inputs exceed MAX_INPUTS");
    assert!(outputs.len() <= MAX_OUTPUTS, "outputs exceed MAX_OUTPUTS");
    debug_assert_eq!(MAX_INPUTS, TXBODY_INPUTS);
    debug_assert_eq!(MAX_OUTPUTS, TXBODY_OUTPUTS);

    let mut input_leaves: [Digest; TXBODY_INPUTS] = [[0u8; 32]; TXBODY_INPUTS];
    for i in 0..TXBODY_INPUTS {
        let inp = inputs.get(i).copied().unwrap_or_else(TxInput::dummy);
        input_leaves[i] = hash_input_leaf(inp.slot_index, inp.value, &inp.owner);
    }

    let mut output_leaves: [Digest; TXBODY_OUTPUTS] = [[0u8; 32]; TXBODY_OUTPUTS];
    for i in 0..TXBODY_OUTPUTS {
        let out = outputs.get(i).copied().unwrap_or_else(TxOutput::dummy);
        output_leaves[i] = hash_output_leaf(out.slot_index, out.value, &out.owner);
    }

    hash_tx_body_core(
        prev_state_root,
        fee,
        &input_leaves,
        &output_leaves,
        is_coinbase,
    )
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
            slot_index: (seed as u32).wrapping_mul(3),
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
            hash_tx_body(&prev, 5, &i, &o, false),
            hash_tx_body(&prev, 5, &i, &o, false)
        );
    }

    #[test]
    fn output_value_flip_changes_body_hash() {
        let prev = [0u8; 32];
        let o1 = mk_output(1);
        let mut o2 = o1;
        o2.value ^= 0xFF;
        let h1 = hash_tx_body(&prev, 0, &[], &[o1], false);
        let h2 = hash_tx_body(&prev, 0, &[], &[o2], false);
        assert_ne!(h1, h2);
    }

    #[test]
    fn output_slot_index_is_bound() {
        // Stage E.1: body hash must bind the output slot_index so a
        // forger can't reroute the minted output to a different state
        // cell without changing tx_body_hash.
        let prev = [0u8; 32];
        let o1 = mk_output(1);
        let mut o2 = o1;
        o2.slot_index ^= 0x33;
        let h1 = hash_tx_body(&prev, 0, &[], &[o1], false);
        let h2 = hash_tx_body(&prev, 0, &[], &[o2], false);
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
        let h1 = hash_tx_body(&prev, 0, &[i1], &[], false);
        let h2 = hash_tx_body(&prev, 0, &[i2], &[], false);
        assert_ne!(h1, h2);
    }

    #[test]
    fn ordering_and_fee_sensitive() {
        let prev = [0u8; 32];
        let i1 = mk_input(1);
        let i2 = mk_input(2);
        let h_a = hash_tx_body(&prev, 10, &[i1, i2], &[], false);
        let h_b = hash_tx_body(&prev, 10, &[i2, i1], &[], false);
        let h_c = hash_tx_body(&prev, 11, &[i1, i2], &[], false);
        assert_ne!(h_a, h_b);
        assert_ne!(h_a, h_c);
    }

    #[test]
    fn dummy_input_equals_zero_leaf() {
        // A body with `valid=false` inputs must hash the same as a body
        // missing those inputs outright.
        let prev = [0u8; 32];
        let real = mk_input(1);
        let h1 = hash_tx_body(&prev, 0, &[real], &[], false);
        let h2 = hash_tx_body(
            &prev,
            0,
            &[real, TxInput::dummy(), TxInput::dummy()],
            &[],
            false,
        );
        assert_eq!(h1, h2);
    }

    #[test]
    fn is_coinbase_flips_hash() {
        // E.5.f₂ adapter-level: is_coinbase must reach the core hash.
        let prev = [0u8; 32];
        let h0 = hash_tx_body(&prev, 0, &[], &[], false);
        let h1 = hash_tx_body(&prev, 0, &[], &[], true);
        assert_ne!(h0, h1);
    }
}
