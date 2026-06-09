// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

#![allow(clippy::needless_range_loop)]

//! AuthGKR dedicated 14-variable unified MLE.
//!
//! Architecture
//! ------------
//!
//! AuthGKR drives `N_AUTH_LIVE_SLOTS = 20` Poseidon2b permutations
//! (4 inputs × 5 perms each: HAddrPermA, HAddrPermB, HAuthPermA,
//! HAuthPermB, HAuthPermC). The Spine Kill-Shot reused the Spine's
//! 15-variable hypercube (`2^15 = 32K` cells) verbatim — paying for
//! 44 padded slots. AuthGKR is instead placed on a smaller hypercube:
//!
//! Bit layout (14 bits, low → high): `elem:2 | round:7 | slot:5`.
//! `(slot, round, elem)` lives at index
//! `(slot << 9) | (round << 2) | elem`.
//!
//! The elem/round bit positions match Spine — only the slot field
//! narrows from 6 bits to 5. This halves the hypercube from 2^15 to
//! 2^14 cells while keeping every per-cell identity (C1, C1', C2)
//! identical.
//!
//! Topology (matches `noid_poseidon2b` natively):
//!   - Rounds 0..3 and 62..65 are full; rounds 4..61 are partial.
//!   - `state[round]` exists for `round ∈ 0..=N_ROUNDS` (67 rows).
//!   - `s_in` / `s_out` exist for `round ∈ 0..N_ROUNDS`.
//!   - Slots `N_AUTH_LIVE_SLOTS..32` are zero-padded.
//!   - Rounds `N_ROUNDS..128` are zero-padded.

use noid_core::{Block128, TowerField};
use noid_poseidon2b::native::permutation::{F_ROUNDS, N_ROUNDS, P_ROUNDS, STATE_SIZE};

use crate::layers::{evaluate_permutation, PermLayerWitness, RoundKind};

/// Number of live AuthGKR permutation slots: 4 inputs × 5 perms.
pub const N_AUTH_LIVE_SLOTS: usize = 20;

/// `log2(32) = 5` slot variables — half the bit budget of Spine.
pub const N_AUTH_SLOT_BITS: usize = 5;
/// `log2(128) = 7` round variables (covers `N_ROUNDS = 66` with padding).
pub const N_AUTH_ROUND_VARS: usize = 7;
/// `log2(4) = 2` element-within-state variables.
pub const N_AUTH_ELEM_VARS: usize = 2;
/// Total variable count of the AuthGKR unified MLE.
pub const N_AUTH_UNIFIED_VARS: usize = N_AUTH_SLOT_BITS + N_AUTH_ROUND_VARS + N_AUTH_ELEM_VARS;
/// `2^14 = 16 384` cells.
pub const N_AUTH_UNIFIED_CELLS: usize = 1 << N_AUTH_UNIFIED_VARS;

const _: () = assert!(N_ROUNDS == 66);
const _: () = assert!(STATE_SIZE == 4);
const _: () = assert!(N_AUTH_LIVE_SLOTS <= (1 << N_AUTH_SLOT_BITS));
const _: () = assert!(N_ROUNDS <= (1 << N_AUTH_ROUND_VARS));
const _: () = assert!(STATE_SIZE <= (1 << N_AUTH_ELEM_VARS));

/// The four columns of the AuthGKR unified MLE. Each is a length-`2^14`
/// vector of `Block128`. The verifier opens all of them at points
/// derived from the unified sumcheck's final challenge.
#[derive(Debug, Clone)]
pub struct AuthUnifiedMle {
    pub s_in: Vec<Block128>,
    pub s_out: Vec<Block128>,
    pub sigma: Vec<Block128>,
    /// Round-entry state. `state[(slot, 0, elem)]` is the
    /// post-initial-MDS state lane; `state[(slot, N_ROUNDS, elem)]`
    /// is the permutation output lane. Rounds `> N_ROUNDS` and
    /// padded slots are zero.
    pub state: Vec<Block128>,
}

impl AuthUnifiedMle {
    /// Empty (all-zero) MLE — useful as a starting buffer before
    /// `populate_slot`.
    pub fn zero() -> Self {
        Self {
            s_in: vec![Block128::ZERO; N_AUTH_UNIFIED_CELLS],
            s_out: vec![Block128::ZERO; N_AUTH_UNIFIED_CELLS],
            sigma: vec![Block128::ZERO; N_AUTH_UNIFIED_CELLS],
            state: vec![Block128::ZERO; N_AUTH_UNIFIED_CELLS],
        }
    }

    /// Index into the AuthGKR unified MLE for `(slot, round, elem)`.
    /// Bit positions for elem/round match Spine; only the slot field
    /// narrows from 6 to 5 bits.
    #[inline]
    pub fn index(slot: usize, round: usize, elem: usize) -> usize {
        debug_assert!(slot < 1 << N_AUTH_SLOT_BITS);
        debug_assert!(round < 1 << N_AUTH_ROUND_VARS);
        debug_assert!(elem < 1 << N_AUTH_ELEM_VARS);
        (slot << (N_AUTH_ROUND_VARS + N_AUTH_ELEM_VARS)) | (round << N_AUTH_ELEM_VARS) | elem
    }

    /// Fill in one slot's cells from an instrumented `PermLayerWitness`.
    /// `slot` must satisfy `slot < N_AUTH_LIVE_SLOTS`.
    pub fn populate_slot(&mut self, slot: usize, witness: &PermLayerWitness) {
        assert!(slot < N_AUTH_LIVE_SLOTS, "slot out of range");
        for r in 0..N_ROUNDS {
            let active_mask = match witness.kind[r] {
                RoundKind::Full => [true; STATE_SIZE],
                RoundKind::Partial => {
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

/// Compile-time sigma schedule, identical to Spine.
pub fn auth_sigma_at(round: usize, elem: usize) -> Block128 {
    if round >= N_ROUNDS || elem >= STATE_SIZE {
        return Block128::ZERO;
    }
    let is_partial = (F_ROUNDS / 2..F_ROUNDS / 2 + P_ROUNDS).contains(&round);
    if !is_partial || elem == 0 {
        Block128::ONE
    } else {
        Block128::ZERO
    }
}

/// Build the AuthGKR unified MLE from `N_AUTH_LIVE_SLOTS` `state_in`
/// vectors, one per permutation slot in post-order.
pub fn build_auth_unified_mle_v2(
    slot_state_ins: &[[Block128; STATE_SIZE]],
) -> (AuthUnifiedMle, Vec<PermLayerWitness>) {
    assert_eq!(
        slot_state_ins.len(),
        N_AUTH_LIVE_SLOTS,
        "expected exactly N_AUTH_LIVE_SLOTS slot inputs"
    );
    let mut mle = AuthUnifiedMle::zero();
    let mut witnesses = Vec::with_capacity(N_AUTH_LIVE_SLOTS);
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
    fn topology_constants_consistent() {
        assert_eq!(N_AUTH_UNIFIED_VARS, 14);
        assert_eq!(N_AUTH_UNIFIED_CELLS, 16_384);
    }

    #[test]
    fn index_round_trip() {
        for slot in 0..N_AUTH_LIVE_SLOTS {
            for round in 0..N_ROUNDS {
                for elem in 0..STATE_SIZE {
                    let idx = AuthUnifiedMle::index(slot, round, elem);
                    assert!(idx < N_AUTH_UNIFIED_CELLS);
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
    fn sigma_schedule_matches_native_round_kinds() {
        use crate::layers::round_kind;
        for round in 0..N_ROUNDS {
            let kind = round_kind(round);
            for elem in 0..STATE_SIZE {
                let expected = match kind {
                    RoundKind::Full => Block128::ONE,
                    RoundKind::Partial => {
                        if elem == 0 {
                            Block128::ONE
                        } else {
                            Block128::ZERO
                        }
                    }
                };
                assert_eq!(
                    auth_sigma_at(round, elem),
                    expected,
                    "round {round} elem {elem}"
                );
            }
        }
    }

    #[test]
    fn build_auth_unified_mle_v2_round_trips() {
        let state_ins: Vec<_> = (0..N_AUTH_LIVE_SLOTS)
            .map(|i| random_state(i as u128 + 1))
            .collect();
        let (mle, witnesses) = build_auth_unified_mle_v2(&state_ins);
        assert_eq!(witnesses.len(), N_AUTH_LIVE_SLOTS);

        let perm = Poseidon2bPermutation;
        for (slot, state_in) in state_ins.iter().enumerate() {
            let mut native = *state_in;
            perm.permute_mut(&mut native);
            assert_eq!(witnesses[slot].final_state(), native, "slot {slot}");
        }

        // Padded slots must be all-zero in every column.
        for slot in N_AUTH_LIVE_SLOTS..(1 << N_AUTH_SLOT_BITS) {
            for round in 0..(1 << N_AUTH_ROUND_VARS) {
                for elem in 0..(1 << N_AUTH_ELEM_VARS) {
                    let idx = AuthUnifiedMle::index(slot, round, elem);
                    assert_eq!(mle.s_in[idx], Block128::ZERO);
                    assert_eq!(mle.s_out[idx], Block128::ZERO);
                    assert_eq!(mle.sigma[idx], Block128::ZERO);
                    assert_eq!(mle.state[idx], Block128::ZERO);
                }
            }
        }
        // Padded rounds inside live slots must also be zero.
        for slot in 0..N_AUTH_LIVE_SLOTS {
            for round in N_ROUNDS..(1 << N_AUTH_ROUND_VARS) {
                for elem in 0..STATE_SIZE {
                    let idx = AuthUnifiedMle::index(slot, round, elem);
                    assert_eq!(mle.s_in[idx], Block128::ZERO);
                    assert_eq!(mle.s_out[idx], Block128::ZERO);
                    assert_eq!(mle.sigma[idx], Block128::ZERO);
                }
            }
        }
    }
}
