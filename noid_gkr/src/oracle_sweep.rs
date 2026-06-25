// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Native execution of the 142-permutation `Sweep25x2` tx-body spine.

use noid_core::{Block128, CanonicalSerialize};
use noid_poseidon2b::native::permutation::Poseidon2bPermutation;

use crate::circuit_sweep::{
    SweepSlotDescriptor, SweepSpineCircuit, SweepSpineInputs, SweepSpineSlotRole,
};

#[inline]
fn padding_absorb_block() -> [Block128; 2] {
    [Block128::from(0x80u128), Block128::from(0x01u128 << 120)]
}

#[derive(Debug, Clone, Copy)]
pub struct SweepSpineSlotState {
    pub state_in: [Block128; 4],
    pub state_out: [Block128; 4],
}

impl SweepSpineSlotState {
    #[inline]
    pub fn digest(&self) -> [Block128; 2] {
        [self.state_out[0], self.state_out[1]]
    }
}

#[derive(Debug, Clone)]
pub struct SweepSpineWitness {
    pub slots: Vec<SweepSpineSlotState>,
    pub tx_body_hash: [Block128; 2],
}

impl SweepSpineWitness {
    pub fn tx_body_hash_bytes(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[..16].copy_from_slice(&self.tx_body_hash[0].to_bytes());
        out[16..].copy_from_slice(&self.tx_body_hash[1].to_bytes());
        out
    }
}

pub fn evaluate_sweep_spine(
    circuit: &SweepSpineCircuit,
    inputs: &SweepSpineInputs,
) -> SweepSpineWitness {
    let perm = Poseidon2bPermutation;
    let mut slots = Vec::with_capacity(circuit.slots.len());

    for slot in &circuit.slots {
        let state_in = build_state_in(slot, inputs, &slots);
        let mut state_out = state_in;
        perm.permute_mut(&mut state_out);
        slots.push(SweepSpineSlotState {
            state_in,
            state_out,
        });
    }

    let tx_body_hash = slots
        .last()
        .expect("sweep spine must have wrap slot")
        .digest();
    SweepSpineWitness {
        slots,
        tx_body_hash,
    }
}

fn build_state_in(
    slot: &SweepSlotDescriptor,
    inputs: &SweepSpineInputs,
    prev: &[SweepSpineSlotState],
) -> [Block128; 4] {
    let [iv_hi, iv_lo] = slot.capacity_iv;
    match slot.role {
        SweepSpineSlotRole::InputLeafPermA { leaf_idx } => {
            let payload = inputs.input_leaves[leaf_idx as usize];
            [payload[0], payload[1], iv_hi, iv_lo]
        }
        SweepSpineSlotRole::InputLeafPermB { leaf_idx } => {
            let payload = inputs.input_leaves[leaf_idx as usize];
            chain_absorb_pair(prev, slot, [payload[2], payload[3]])
        }
        SweepSpineSlotRole::InputLeafPermC { .. } => {
            chain_absorb_pair(prev, slot, padding_absorb_block())
        }
        SweepSpineSlotRole::OutputLeafPermA { leaf_idx } => {
            let payload = inputs.output_leaves[leaf_idx as usize];
            [payload[0], payload[1], iv_hi, iv_lo]
        }
        SweepSpineSlotRole::OutputLeafPermB { leaf_idx } => {
            let payload = inputs.output_leaves[leaf_idx as usize];
            chain_absorb_pair(prev, slot, [payload[2], payload[3]])
        }
        SweepSpineSlotRole::CompressPermA { level, pos } => {
            let left = resolve_child_digest(slot.left_child, prev, inputs, level, pos, true);
            [left[0], left[1], iv_hi, iv_lo]
        }
        SweepSpineSlotRole::CompressPermB { level, pos } => {
            let right = resolve_child_digest(slot.right_child, prev, inputs, level, pos, false);
            chain_absorb_pair(prev, slot, right)
        }
        SweepSpineSlotRole::WrapPerm => {
            let root_id = slot
                .left_child
                .expect("sweep wrap must reference root slot");
            let root = prev[root_id].digest();
            [root[0], root[1], iv_hi, iv_lo]
        }
    }
}

#[inline]
fn chain_absorb_pair(
    prev: &[SweepSpineSlotState],
    slot: &SweepSlotDescriptor,
    absorb: [Block128; 2],
) -> [Block128; 4] {
    let src = slot
        .prev_output_src
        .expect("non-head sweep spine slot must carry prev_output_src");
    let s = prev[src].state_out;
    [s[0] + absorb[0], s[1] + absorb[1], s[2], s[3]]
}

fn resolve_child_digest(
    child: Option<usize>,
    prev: &[SweepSpineSlotState],
    inputs: &SweepSpineInputs,
    level: u8,
    pos: u8,
    is_left: bool,
) -> [Block128; 2] {
    if let Some(id) = child {
        return prev[id].digest();
    }

    debug_assert_eq!(level, 1, "non-AIR child outside level-1 compress");
    match (pos, is_left) {
        (0, true) => inputs.epoch_anchor,
        (0, false) => inputs.fee_leaf,
        (1, true) => inputs.shape_leaf,
        (15, true) => inputs.is_coinbase_leaf,
        (15, false) => inputs.pad_leaf,
        _ => panic!("unexpected non-AIR sweep child at compress (level={level}, pos={pos})"),
    }
}

pub fn digest_to_fields(d: &[u8; 32]) -> [Block128; 2] {
    let mut a = [0u8; 16];
    let mut b = [0u8; 16];
    a.copy_from_slice(&d[..16]);
    b.copy_from_slice(&d[16..]);
    [
        Block128::from(u128::from_le_bytes(a)),
        Block128::from(u128::from_le_bytes(b)),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use noid_core::TowerField;
    use noid_poseidon2b::primitives::{
        hash_input_leaf, hash_output_leaf, hash_tx_body_sweep25x2, Address, Digest,
        SWEEP_TXBODY_INPUTS, SWEEP_TXBODY_OUTPUTS,
    };

    fn fields_to_digest(f: [Block128; 2]) -> Digest {
        let mut out = [0u8; 32];
        out[..16].copy_from_slice(&f[0].to_bytes());
        out[16..].copy_from_slice(&f[1].to_bytes());
        out
    }

    fn fixture_inputs() -> (
        SweepSpineInputs,
        [Digest; SWEEP_TXBODY_INPUTS],
        [Digest; SWEEP_TXBODY_OUTPUTS],
    ) {
        let mut input_payloads = [[Block128::ZERO; 4]; SWEEP_TXBODY_INPUTS];
        let mut input_leaves = [[0u8; 32]; SWEEP_TXBODY_INPUTS];
        for i in 0..SWEEP_TXBODY_INPUTS {
            let owner = Address([i as u8 + 1; 32]);
            let slot = 10 + i as u32;
            let value = 1_000 + i as u64;
            let [owner_hi, owner_lo] = owner.as_fields();
            input_payloads[i] = [
                Block128::from(slot as u128),
                Block128::from(value as u128),
                owner_hi,
                owner_lo,
            ];
            input_leaves[i] = hash_input_leaf(slot, value, &owner);
        }

        let mut output_payloads = [[Block128::ZERO; 4]; SWEEP_TXBODY_OUTPUTS];
        let mut output_leaves = [[0u8; 32]; SWEEP_TXBODY_OUTPUTS];
        for i in 0..SWEEP_TXBODY_OUTPUTS {
            let owner = Address([0xA0 + i as u8; 32]);
            let slot = 100 + i as u32;
            let value = 9_000 + i as u64;
            let [owner_hi, owner_lo] = owner.as_fields();
            output_payloads[i] = [
                Block128::from(slot as u128),
                Block128::from(value as u128),
                owner_hi,
                owner_lo,
            ];
            output_leaves[i] = hash_output_leaf(slot, value, &owner);
        }

        let epoch_anchor = [0x5Au8; 32];
        let fee = 123u128;
        let is_coinbase = false;
        let inputs = SweepSpineInputs {
            epoch_anchor: digest_to_fields(&epoch_anchor),
            fee_leaf: [Block128::from(fee), Block128::ZERO],
            shape_leaf: [Block128::ONE, Block128::ZERO],
            input_leaves: input_payloads,
            output_leaves: output_payloads,
            is_coinbase_leaf: [Block128::from(is_coinbase as u128), Block128::ZERO],
            pad_leaf: [Block128::ZERO, Block128::ZERO],
        };
        (inputs, input_leaves, output_leaves)
    }

    #[test]
    fn sweep_spine_oracle_matches_native_hash() {
        let circuit = SweepSpineCircuit::build();
        let (inputs, input_leaves, output_leaves) = fixture_inputs();
        let got = evaluate_sweep_spine(&circuit, &inputs).tx_body_hash;
        let want = hash_tx_body_sweep25x2(&[0x5Au8; 32], 123, &input_leaves, &output_leaves, false);
        assert_eq!(fields_to_digest(got), want.into_bytes());
    }

    #[test]
    fn sweep_spine_oracle_binds_shape_leaf() {
        let circuit = SweepSpineCircuit::build();
        let (mut inputs, _, _) = fixture_inputs();
        let honest = evaluate_sweep_spine(&circuit, &inputs).tx_body_hash;
        inputs.shape_leaf[0] += Block128::ONE;
        let tampered = evaluate_sweep_spine(&circuit, &inputs).tx_body_hash;
        assert_ne!(honest, tampered);
    }
}
