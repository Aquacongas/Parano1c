// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Native reference execution of the 125-slot `SweepAuthCircuit`.
//!
//! Mirrors [`crate::oracle::evaluate_spine`] but drives the per-input
//! HAddr/HAuth schedule instead of the tx-body Merkle spine. Each slot
//! is a single Poseidon2b permutation with an explicit `state_in`
//! derived from (a) the slot's capacity IV at head, or (b) the previous
//! slot's `state_out` plus an absorb-XOR on the rate lanes otherwise.
//!
//! The absorb schedule matches
//! [`noid_poseidon2b::primitives::derive_address`] and
//! [`noid_poseidon2b::primitives::hash_auth_tag`] byte-for-byte — this
//! file's differential tests pin that correspondence.

use noid_core::{Block128, TowerField};
use noid_poseidon2b::native::permutation::Poseidon2bPermutation;

use crate::auth_circuit_sweep::{
    SweepAuthCircuit, SweepAuthInputs, SweepAuthSlotDescriptor, SweepAuthSlotRole, AUTH_PAD_0,
    AUTH_PAD_1, N_SWEEP_AUTH_INPUTS,
};

/// Per-slot state snapshot.
#[derive(Debug, Clone, Copy)]
pub struct SweepAuthSlotState {
    pub state_in: [Block128; 4],
    pub state_out: [Block128; 4],
}

impl SweepAuthSlotState {
    /// Digest produced by this slot's permutation: state_out[0..1].
    #[inline]
    pub fn digest(&self) -> [Block128; 2] {
        [self.state_out[0], self.state_out[1]]
    }
}

/// Full auth witness: per-slot states plus the derived `(Address,
/// AuthTag)` boundary for each input.
#[derive(Debug, Clone)]
pub struct SweepAuthWitness {
    pub slots: Vec<SweepAuthSlotState>,
    pub derived_address: [[Block128; 2]; N_SWEEP_AUTH_INPUTS],
    pub derived_auth_tag: [[Block128; 2]; N_SWEEP_AUTH_INPUTS],
}

/// Native reference. Drives the 125 permutations in post-order, returns
/// the full witness plus the derived `(Address, AuthTag)` pairs.
pub fn evaluate_sweep_auth(
    circuit: &SweepAuthCircuit,
    inputs: &SweepAuthInputs,
) -> SweepAuthWitness {
    let perm = Poseidon2bPermutation;
    let mut slots: Vec<SweepAuthSlotState> = Vec::with_capacity(circuit.slots.len());

    for slot in &circuit.slots {
        let state_in = build_state_in(slot, inputs, &slots);
        let mut state_out = state_in;
        perm.permute_mut(&mut state_out);
        slots.push(SweepAuthSlotState {
            state_in,
            state_out,
        });
    }

    let mut derived_address = [[Block128::ZERO; 2]; N_SWEEP_AUTH_INPUTS];
    let mut derived_auth_tag = [[Block128::ZERO; 2]; N_SWEEP_AUTH_INPUTS];
    for i in 0..N_SWEEP_AUTH_INPUTS {
        derived_address[i] = slots[SweepAuthCircuit::haddr_output_slot(i)].digest();
        derived_auth_tag[i] = slots[SweepAuthCircuit::hauth_output_slot(i)].digest();
    }

    SweepAuthWitness {
        slots,
        derived_address,
        derived_auth_tag,
    }
}

/// Pad block pushed by a sponge `finalize()` on an empty buffer.
#[inline]
fn padding_absorb_block() -> [Block128; 2] {
    [Block128::from(AUTH_PAD_0), Block128::from(AUTH_PAD_1)]
}

fn build_state_in(
    slot: &SweepAuthSlotDescriptor,
    inputs: &SweepAuthInputs,
    prev: &[SweepAuthSlotState],
) -> [Block128; 4] {
    let [iv_hi, iv_lo] = slot.capacity_iv;

    match slot.role {
        SweepAuthSlotRole::HAddrPermA { input_idx } => {
            let [a, b] = inputs.spend_secret[input_idx as usize];
            [a, b, iv_hi, iv_lo]
        }
        SweepAuthSlotRole::HAddrPermB { .. } => {
            chain_absorb_pair(prev, slot, padding_absorb_block())
        }
        SweepAuthSlotRole::HAuthPermA { input_idx } => {
            let [a, b] = inputs.spend_secret[input_idx as usize];
            [a, b, iv_hi, iv_lo]
        }
        SweepAuthSlotRole::HAuthPermB { .. } => chain_absorb_pair(prev, slot, inputs.tx_body_hash),
        SweepAuthSlotRole::HAuthPermC { .. } => {
            chain_absorb_pair(prev, slot, padding_absorb_block())
        }
    }
}

#[inline]
fn chain_absorb_pair(
    prev: &[SweepAuthSlotState],
    slot: &SweepAuthSlotDescriptor,
    absorb: [Block128; 2],
) -> [Block128; 4] {
    let src = slot
        .prev_output_src
        .expect("non-head auth slot must carry prev_output_src");
    let s = prev[src].state_out;
    [s[0] + absorb[0], s[1] + absorb[1], s[2], s[3]]
}

/// Convenience: compute the honest `(expected_address, expected_auth_tag)`
/// boundary from `spend_secret` + `tx_body_hash` without building any
/// proof. Callers use this to populate `SweepAuthInputs` before entering the
/// transcript.
pub fn compute_sweep_auth_boundary(
    circuit: &SweepAuthCircuit,
    spend_secret: [[Block128; 2]; N_SWEEP_AUTH_INPUTS],
    tx_body_hash: [Block128; 2],
) -> (
    [[Block128; 2]; N_SWEEP_AUTH_INPUTS],
    [[Block128; 2]; N_SWEEP_AUTH_INPUTS],
) {
    use crate::auth_circuit_sweep::SweepAuthInputs;
    let probe = SweepAuthInputs {
        spend_secret,
        tx_body_hash,
        expected_address: [[Block128::ZERO; 2]; N_SWEEP_AUTH_INPUTS],
        expected_auth_tag: [[Block128::ZERO; 2]; N_SWEEP_AUTH_INPUTS],
    };
    let w = evaluate_sweep_auth(circuit, &probe);
    (w.derived_address, w.derived_auth_tag)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::needless_range_loop)]
    use super::*;
    use noid_core::CanonicalSerialize;
    use noid_poseidon2b::primitives::{derive_address, hash_auth_tag, SpendSecret, TxBodyHash};

    fn fields_to_digest(f: [Block128; 2]) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[..16].copy_from_slice(&f[0].to_bytes());
        out[16..].copy_from_slice(&f[1].to_bytes());
        out
    }

    fn digest_to_fields(d: &[u8; 32]) -> [Block128; 2] {
        let mut a = [0u8; 16];
        let mut b = [0u8; 16];
        a.copy_from_slice(&d[..16]);
        b.copy_from_slice(&d[16..]);
        [
            Block128::from(u128::from_le_bytes(a)),
            Block128::from(u128::from_le_bytes(b)),
        ]
    }

    fn mk_secret(seed: u8) -> SpendSecret {
        SpendSecret([seed; 32])
    }

    fn mk_tx_body_hash(seed: u8) -> TxBodyHash {
        TxBodyHash([seed; 32])
    }

    #[test]
    fn empty_inputs_witness_is_well_formed() {
        let circuit = SweepAuthCircuit::build();
        let inputs = SweepAuthInputs::zero();
        let w = evaluate_sweep_auth(&circuit, &inputs);
        assert_eq!(w.slots.len(), circuit.slots.len());
    }

    #[test]
    fn derived_address_matches_native() {
        let circuit = SweepAuthCircuit::build();
        let secrets: [SpendSecret; N_SWEEP_AUTH_INPUTS] =
            std::array::from_fn(|i| mk_secret(i as u8 + 1));

        let mut inputs = SweepAuthInputs::zero();
        for (i, s) in secrets.iter().enumerate() {
            inputs.spend_secret[i] = s.as_fields();
        }

        let w = evaluate_sweep_auth(&circuit, &inputs);
        for i in 0..N_SWEEP_AUTH_INPUTS {
            let native = derive_address(&secrets[i]);
            assert_eq!(
                fields_to_digest(w.derived_address[i]),
                native.into_bytes(),
                "derive_address mismatch at input {i}",
            );
        }
    }

    #[test]
    fn derived_auth_tag_matches_native() {
        let circuit = SweepAuthCircuit::build();
        let secrets: [SpendSecret; N_SWEEP_AUTH_INPUTS] =
            std::array::from_fn(|i| mk_secret((i as u8).wrapping_mul(7).wrapping_add(11)));
        let tbh = mk_tx_body_hash(0x5A);

        let mut inputs = SweepAuthInputs::zero();
        for (i, s) in secrets.iter().enumerate() {
            inputs.spend_secret[i] = s.as_fields();
        }
        inputs.tx_body_hash = digest_to_fields(&tbh.into_bytes());

        let w = evaluate_sweep_auth(&circuit, &inputs);
        for i in 0..N_SWEEP_AUTH_INPUTS {
            let native = hash_auth_tag(&secrets[i], &tbh);
            assert_eq!(
                fields_to_digest(w.derived_auth_tag[i]),
                native.into_bytes(),
                "hash_auth_tag mismatch at input {i}",
            );
        }
    }

    #[test]
    fn zero_secret_matches_native() {
        let circuit = SweepAuthCircuit::build();
        let inputs = SweepAuthInputs::zero();
        let w = evaluate_sweep_auth(&circuit, &inputs);
        let zero_secret = SpendSecret([0u8; 32]);
        let zero_tbh = TxBodyHash([0u8; 32]);
        let expected_addr = derive_address(&zero_secret);
        let expected_tag = hash_auth_tag(&zero_secret, &zero_tbh);
        for i in 0..N_SWEEP_AUTH_INPUTS {
            assert_eq!(
                fields_to_digest(w.derived_address[i]),
                expected_addr.into_bytes()
            );
            assert_eq!(
                fields_to_digest(w.derived_auth_tag[i]),
                expected_tag.into_bytes()
            );
        }
    }
}
