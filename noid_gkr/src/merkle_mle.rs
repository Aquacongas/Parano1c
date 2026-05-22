// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

#![allow(clippy::needless_range_loop)]

//! Merkle path GKR — 14-variable unified MLE.
//!
//! Bit layout (14 bits, low → high): `elem:2 | round:7 | slot:5`.
//!
//! 32 slots (16 compressions × 2 perms), same geometry as AuthGKR.
//! `N_MERKLE_LIVE_SLOTS` depends on `active_depth` at runtime but the
//! hypercube is always 2^14 cells. Unused slots are zero-padded.

use noid_core::{Block128, TowerField};
use noid_poseidon2b::native::permutation::{N_ROUNDS, STATE_SIZE};

use crate::layers::{evaluate_permutation, PermLayerWitness};
use crate::merkle_circuit::N_MERKLE_SLOTS;

/// Maximum live slots (all 32 when active_depth = 16).
pub const N_MERKLE_MAX_LIVE_SLOTS: usize = N_MERKLE_SLOTS;

/// `log2(32) = 5` slot variables.
pub const N_MERKLE_SLOT_BITS: usize = 5;
/// `log2(128) = 7` round variables.
pub const N_MERKLE_ROUND_VARS: usize = 7;
/// `log2(4) = 2` element variables.
pub const N_MERKLE_ELEM_VARS: usize = 2;
/// Total variable count.
pub const N_MERKLE_UNIFIED_VARS: usize = N_MERKLE_SLOT_BITS + N_MERKLE_ROUND_VARS + N_MERKLE_ELEM_VARS;
/// `2^14 = 16 384` cells.
pub const N_MERKLE_UNIFIED_CELLS: usize = 1 << N_MERKLE_UNIFIED_VARS;

const _: () = assert!(N_ROUNDS == 66);
const _: () = assert!(STATE_SIZE == 4);
const _: () = assert!(N_MERKLE_MAX_LIVE_SLOTS <= (1 << N_MERKLE_SLOT_BITS));
const _: () = assert!(N_MERKLE_UNIFIED_VARS == 14);

/// The four columns of the Merkle GKR unified MLE.
#[derive(Debug, Clone)]
pub struct MerkleUnifiedMle {
    pub s_in: Vec<Block128>,
    pub s_out: Vec<Block128>,
    pub sigma: Vec<Block128>,
    pub state: Vec<Block128>,
}

impl MerkleUnifiedMle {
    pub fn zero() -> Self {
        Self {
            s_in: vec![Block128::ZERO; N_MERKLE_UNIFIED_CELLS],
            s_out: vec![Block128::ZERO; N_MERKLE_UNIFIED_CELLS],
            sigma: vec![Block128::ZERO; N_MERKLE_UNIFIED_CELLS],
            state: vec![Block128::ZERO; N_MERKLE_UNIFIED_CELLS],
        }
    }

    #[inline]
    pub fn index(slot: usize, round: usize, elem: usize) -> usize {
        debug_assert!(slot < 1 << N_MERKLE_SLOT_BITS);
        debug_assert!(round < 1 << N_MERKLE_ROUND_VARS);
        debug_assert!(elem < 1 << N_MERKLE_ELEM_VARS);
        (slot << (N_MERKLE_ROUND_VARS + N_MERKLE_ELEM_VARS)) | (round << N_MERKLE_ELEM_VARS) | elem
    }

    pub fn populate_slot(&mut self, slot: usize, witness: &PermLayerWitness) {
        assert!(slot < N_MERKLE_MAX_LIVE_SLOTS, "slot out of range");
        for r in 0..N_ROUNDS {
            let active_mask = match witness.kind[r] {
                crate::layers::RoundKind::Full => [true; STATE_SIZE],
                crate::layers::RoundKind::Partial => {
                    let mut m = [false; STATE_SIZE];
                    m[0] = true;
                    m
                }
            };
            for elem in 0..STATE_SIZE {
                let idx = Self::index(slot, r, elem);
                self.s_in[idx] = witness.sin[r][elem];
                self.s_out[idx] = witness.sout[r][elem];
                self.sigma[idx] = if active_mask[elem] {
                    Block128::ONE
                } else {
                    Block128::ZERO
                };
            }
        }
        debug_assert_eq!(witness.state.len(), N_ROUNDS + 1);
        for r in 0..=N_ROUNDS {
            for elem in 0..STATE_SIZE {
                let idx = Self::index(slot, r, elem);
                self.state[idx] = witness.state[r][elem];
            }
        }
    }
}

/// Build the Merkle unified MLE from `live_slots` `state_in` vectors.
pub fn build_merkle_unified_mle(
    slot_state_ins: &[[Block128; STATE_SIZE]],
    live_slots: usize,
) -> (MerkleUnifiedMle, Vec<PermLayerWitness>) {
    assert!(live_slots <= N_MERKLE_MAX_LIVE_SLOTS);
    assert_eq!(slot_state_ins.len(), live_slots);
    let mut mle = MerkleUnifiedMle::zero();
    let mut witnesses = Vec::with_capacity(live_slots);
    for (slot, state_in) in slot_state_ins.iter().enumerate() {
        let w = evaluate_permutation(*state_in);
        mle.populate_slot(slot, &w);
        witnesses.push(w);
    }
    (mle, witnesses)
}

#[cfg(test)]
mod tests {
    use super::*;
    use noid_poseidon2b::native::permutation::Poseidon2bPermutation;

    fn random_state(seed: u128) -> [Block128; STATE_SIZE] {
        let mut s = seed;
        std::array::from_fn(|_| {
            s = s.wrapping_mul(0x9E3779B97F4A7C15).wrapping_add(0xDEAD_BEEF);
            Block128::from(s)
        })
    }

    #[test]
    fn topology_constants() {
        assert_eq!(N_MERKLE_UNIFIED_VARS, 14);
        assert_eq!(N_MERKLE_UNIFIED_CELLS, 16_384);
    }

    #[test]
    fn index_round_trip() {
        for slot in 0..N_MERKLE_MAX_LIVE_SLOTS {
            for round in 0..N_ROUNDS {
                for elem in 0..STATE_SIZE {
                    let idx = MerkleUnifiedMle::index(slot, round, elem);
                    assert!(idx < N_MERKLE_UNIFIED_CELLS);
                    let recovered_elem = idx & 0b11;
                    let recovered_round = (idx >> 2) & 0b111_1111;
                    let recovered_slot = idx >> 9;
                    assert_eq!(recovered_elem, elem);
                    assert_eq!(recovered_round, round);
                    assert_eq!(recovered_slot, slot);
                }
            }
        }
    }

    #[test]
    fn build_mle_round_trips_permutation() {
        let live = 8;
        let state_ins: Vec<_> = (0..live).map(|i| random_state(i as u128 + 1)).collect();
        let (_, witnesses) = build_merkle_unified_mle(&state_ins, live);
        assert_eq!(witnesses.len(), live);
        let perm = Poseidon2bPermutation;
        for (slot, state_in) in state_ins.iter().enumerate() {
            let mut native = *state_in;
            perm.permute_mut(&mut native);
            assert_eq!(witnesses[slot].final_state(), native, "slot {slot}");
        }
    }

    #[test]
    fn padded_slots_are_zero() {
        let live = 4;
        let state_ins: Vec<_> = (0..live).map(|i| random_state(i as u128 + 100)).collect();
        let (mle, _) = build_merkle_unified_mle(&state_ins, live);
        for slot in live..(1 << N_MERKLE_SLOT_BITS) {
            for round in 0..(1 << N_MERKLE_ROUND_VARS) {
                for elem in 0..(1 << N_MERKLE_ELEM_VARS) {
                    let idx = MerkleUnifiedMle::index(slot, round, elem);
                    assert_eq!(mle.s_in[idx], Block128::ZERO);
                    assert_eq!(mle.s_out[idx], Block128::ZERO);
                    assert_eq!(mle.state[idx], Block128::ZERO);
                }
            }
        }
    }
}
