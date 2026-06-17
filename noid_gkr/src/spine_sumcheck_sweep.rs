// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Sweep tx-body spine utility functions: state reconstruction and native
//! discharge helpers for the 142-slot `Sweep25x2` spine.

use noid_core::{Block128, TowerField};
use noid_poseidon2b::native::permutation::STATE_SIZE;

use crate::circuit_sweep::{SweepSpineCircuit, SweepSpineInputs, N_SWEEP_SPINE_SLOTS};
use crate::layers::evaluate_permutation;
use crate::mle_layout::{PermMle, N_PERM_CELLS, N_PERM_VARS};

pub const N_SWEEP_SPINE_SLOTS_PADDED: usize = 256;
pub const N_SWEEP_SLOT_VARS: usize = 8;
pub const N_SWEEP_BOUNDARY_VARS: usize = N_SWEEP_SLOT_VARS + N_PERM_VARS;
pub const N_SWEEP_BOUNDARY_CELLS: usize = 1 << N_SWEEP_BOUNDARY_VARS;

pub fn build_sweep_boundary_mle(
    slot_states: &[([Block128; STATE_SIZE], [Block128; STATE_SIZE])],
) -> Vec<Block128> {
    debug_assert_eq!(slot_states.len(), N_SWEEP_SPINE_SLOTS);
    let mut b = vec![Block128::ZERO; N_SWEEP_BOUNDARY_CELLS];
    for (s, (state_in, _)) in slot_states.iter().enumerate() {
        let witness = evaluate_permutation(*state_in);
        let state_mle = PermMle::from_witness(&witness).state;
        debug_assert_eq!(state_mle.len(), N_PERM_CELLS);
        let offset = s << N_PERM_VARS;
        b[offset..offset + N_PERM_CELLS].copy_from_slice(&state_mle);
    }
    b
}

pub fn reconstruct_sweep_spine_slot_states(
    circuit: &SweepSpineCircuit,
    inputs: &SweepSpineInputs,
) -> Vec<([Block128; STATE_SIZE], [Block128; STATE_SIZE])> {
    use crate::oracle_sweep::evaluate_sweep_spine;
    let w = evaluate_sweep_spine(circuit, inputs);
    w.slots
        .into_iter()
        .map(|s| (s.state_in, s.state_out))
        .collect()
}

pub fn discharge_sweep_boundary_native(
    circuit: &SweepSpineCircuit,
    inputs: &SweepSpineInputs,
    reduction: &crate::batch_eval::BatchEvalReduction,
) -> bool {
    let states = reconstruct_sweep_spine_slot_states(circuit, inputs);
    let boundary_mle = build_sweep_boundary_mle(&states);
    noid_core::mle::evaluate::evaluate_slice(&boundary_mle, &reduction.point) == reduction.value
}

pub fn compute_sweep_tx_body_hash(
    circuit: &SweepSpineCircuit,
    inputs: &SweepSpineInputs,
) -> [Block128; 2] {
    let states = reconstruct_sweep_spine_slot_states(circuit, inputs);
    let wrap = states
        .last()
        .expect("sweep spine must have at least one slot");
    [wrap.1[0], wrap.1[1]]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oracle_sweep::evaluate_sweep_spine;

    #[test]
    fn constants_match_sweep_slot_count() {
        assert_eq!(N_SWEEP_SPINE_SLOTS, 142);
        assert_eq!(N_SWEEP_SPINE_SLOTS_PADDED, 256);
        assert_eq!(N_SWEEP_SLOT_VARS, 8);
        assert_eq!(N_SWEEP_BOUNDARY_VARS, 17);
    }

    #[test]
    fn compute_hash_matches_oracle() {
        let circuit = SweepSpineCircuit::build();
        let inputs = SweepSpineInputs {
            epoch_anchor: [Block128::from(1u128), Block128::from(2u128)],
            fee_leaf: [Block128::from(3u128), Block128::ZERO],
            shape_leaf: [Block128::ONE, Block128::ZERO],
            input_leaves: [[Block128::from(4u128); 4]; 25],
            output_leaves: [[Block128::from(5u128); 4]; 2],
            is_coinbase_leaf: [Block128::ZERO, Block128::ZERO],
            pad_leaf: [Block128::ZERO, Block128::ZERO],
        };
        assert_eq!(
            compute_sweep_tx_body_hash(&circuit, &inputs),
            evaluate_sweep_spine(&circuit, &inputs).tx_body_hash
        );
    }
}
