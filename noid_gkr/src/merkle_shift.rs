// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

#![allow(clippy::needless_range_loop)]

//! Merkle path GKR — shift index helpers and cached schedule tables.
//!
//! 14-variable hypercube (`elem:2 | round:7 | slot:5`). The `live_slots`
//! value varies per Merkle instance (2 × active_depth), so schedule tables are
//! parameterised rather than cached with a fixed slot count.

use noid_core::mle::eq::eq_ind_partial_eval;
use noid_core::{Block128, TowerField};
use noid_poseidon2b::native::permutation::{
    F_ROUNDS, MDS_FULL, MDS_PARTIAL, N_ROUNDS, P_ROUNDS, ROUND_CONSTANTS, STATE_SIZE,
};

use crate::merkle_mle::{
    N_MERKLE_ELEM_VARS, N_MERKLE_ROUND_VARS, N_MERKLE_SLOT_BITS, N_MERKLE_UNIFIED_CELLS,
    N_MERKLE_UNIFIED_VARS,
};

const ELEM_BITS: usize = N_MERKLE_ELEM_VARS;
const ROUND_BITS: usize = N_MERKLE_ROUND_VARS;
const SLOT_BITS: usize = N_MERKLE_SLOT_BITS;

const ROUND_SHIFT: usize = ELEM_BITS;
const SLOT_SHIFT: usize = ELEM_BITS + ROUND_BITS;

const ROUND_MASK: u16 = ((1 << ROUND_BITS) - 1) << ROUND_SHIFT;
const ELEM_MASK: u16 = (1 << ELEM_BITS) - 1;

const ROUND_LIMIT: usize = 1 << ROUND_BITS;

const _: () = assert!(ELEM_BITS + ROUND_BITS + SLOT_BITS == N_MERKLE_UNIFIED_VARS);

#[inline]
pub fn merkle_round_of(idx: u16) -> usize {
    ((idx & ROUND_MASK) >> ROUND_SHIFT) as usize
}

#[inline]
pub fn merkle_elem_of(idx: u16) -> usize {
    (idx & ELEM_MASK) as usize
}

#[inline]
pub fn merkle_slot_of(idx: u16) -> usize {
    ((idx >> SLOT_SHIFT) & ((1 << SLOT_BITS) - 1)) as usize
}

#[inline]
pub fn merkle_dec_round_index(idx: u16) -> u16 {
    let round = merkle_round_of(idx);
    let prev = (round + ROUND_LIMIT - 1) & (ROUND_LIMIT - 1);
    (idx & !ROUND_MASK) | ((prev as u16) << ROUND_SHIFT)
}

#[inline]
pub fn merkle_inc_round_index(idx: u16) -> u16 {
    let round = merkle_round_of(idx);
    let next = (round + 1) & (ROUND_LIMIT - 1);
    (idx & !ROUND_MASK) | ((next as u16) << ROUND_SHIFT)
}

#[inline]
pub fn merkle_pack_index(slot: usize, round: usize, elem: usize) -> u16 {
    debug_assert!(slot < (1 << SLOT_BITS));
    debug_assert!(round < ROUND_LIMIT);
    debug_assert!(elem < (1 << ELEM_BITS));
    ((slot << SLOT_SHIFT) | (round << ROUND_SHIFT) | elem) as u16
}

#[inline]
fn mds_coeff(round: usize, i: usize, j: usize) -> Block128 {
    let is_partial = (F_ROUNDS / 2..F_ROUNDS / 2 + P_ROUNDS).contains(&round);
    let raw = if is_partial {
        MDS_PARTIAL[i][j]
    } else {
        MDS_FULL[i][j]
    };
    Block128::from(raw)
}

#[inline]
fn merkle_sigma_at(round: usize, elem: usize) -> Block128 {
    let is_partial = (F_ROUNDS / 2..F_ROUNDS / 2 + P_ROUNDS).contains(&round);
    if is_partial && elem != 0 {
        Block128::ZERO
    } else {
        Block128::ONE
    }
}

/// Build mu table for a given live_slots count.
pub fn build_merkle_mu_table(live_slots: usize) -> Vec<Block128> {
    let mut tab = vec![Block128::ZERO; N_MERKLE_UNIFIED_CELLS];
    for slot in 0..live_slots {
        for round in 0..N_ROUNDS {
            for elem in 0..STATE_SIZE {
                let idx = merkle_pack_index(slot, round, elem);
                tab[idx as usize] = Block128::ONE;
            }
        }
    }
    tab
}

/// Build sigma table for a given live_slots count.
pub fn build_merkle_sigma_table(live_slots: usize) -> Vec<Block128> {
    let mut tab = vec![Block128::ZERO; N_MERKLE_UNIFIED_CELLS];
    for slot in 0..live_slots {
        for round in 0..N_ROUNDS {
            for elem in 0..STATE_SIZE {
                let idx = merkle_pack_index(slot, round, elem);
                tab[idx as usize] = merkle_sigma_at(round, elem);
            }
        }
    }
    tab
}

/// Build RC table for a given live_slots count.
pub fn build_merkle_rc_table(live_slots: usize) -> Vec<Block128> {
    let mut tab = vec![Block128::ZERO; N_MERKLE_UNIFIED_CELLS];
    for slot in 0..live_slots {
        for round in 0..N_ROUNDS {
            let is_partial = (F_ROUNDS / 2..F_ROUNDS / 2 + P_ROUNDS).contains(&round);
            for elem in 0..STATE_SIZE {
                if is_partial && elem != 0 {
                    continue;
                }
                let idx = merkle_pack_index(slot, round, elem);
                tab[idx as usize] = Block128::from(ROUND_CONSTANTS[elem][round]);
            }
        }
    }
    tab
}

/// Build MDS lane table for a given live_slots count.
pub fn build_merkle_mds_lane_table(live_slots: usize, lane: usize) -> Vec<Block128> {
    debug_assert!(lane < STATE_SIZE);
    let mut out = vec![Block128::ZERO; N_MERKLE_UNIFIED_CELLS];
    for y in 0..N_MERKLE_UNIFIED_CELLS {
        let yb = y as u16;
        let slot = merkle_slot_of(yb);
        if slot >= live_slots {
            continue;
        }
        let dec_round = merkle_round_of(merkle_dec_round_index(yb));
        if dec_round >= N_ROUNDS {
            continue;
        }
        let elem = merkle_elem_of(yb);
        out[y] = mds_coeff(dec_round, elem, lane);
    }
    out
}

/// `out[y] = src[dec_round_index(y)]`.
pub fn merkle_permute_by_dec(src: &[Block128]) -> Vec<Block128> {
    debug_assert_eq!(src.len(), N_MERKLE_UNIFIED_CELLS);
    let mut out = vec![Block128::ZERO; N_MERKLE_UNIFIED_CELLS];
    for y in 0..N_MERKLE_UNIFIED_CELLS {
        out[y] = src[merkle_dec_round_index(y as u16) as usize];
    }
    out
}

/// Build the unified mask `U[y] = eq(rho, dec(y)) * mu(dec(y))`.
pub fn build_merkle_u_table(rho: &[Block128], live_slots: usize) -> Vec<Block128> {
    debug_assert_eq!(rho.len(), N_MERKLE_UNIFIED_VARS);
    let eq_tab = eq_ind_partial_eval::<Block128>(rho);
    let mu_tab = build_merkle_mu_table(live_slots);
    let mut out = vec![Block128::ZERO; N_MERKLE_UNIFIED_CELLS];
    for y in 0..N_MERKLE_UNIFIED_CELLS {
        let x = merkle_dec_round_index(y as u16) as usize;
        out[y] = eq_tab[x] * mu_tab[x];
    }
    out
}

/// Build sigma-dec table.
pub fn build_merkle_sigma_dec_table(live_slots: usize) -> Vec<Block128> {
    merkle_permute_by_dec(&build_merkle_sigma_table(live_slots))
}

/// Build RC-dec table.
pub fn build_merkle_rc_dec_table(live_slots: usize) -> Vec<Block128> {
    merkle_permute_by_dec(&build_merkle_rc_table(live_slots))
}

/// Project lane: `out[y] = src[(y & ~ELEM_MASK) | lane]`.
pub fn merkle_project_lane(src: &[Block128], lane: usize) -> Vec<Block128> {
    debug_assert!(lane < STATE_SIZE);
    debug_assert_eq!(src.len(), N_MERKLE_UNIFIED_CELLS);
    let mut out = vec![Block128::ZERO; N_MERKLE_UNIFIED_CELLS];
    for y in 0..N_MERKLE_UNIFIED_CELLS {
        let row_base = (y as u16) & !ELEM_MASK;
        out[y] = src[(row_base | lane as u16) as usize];
    }
    out
}

/// Build sigma-dec lane tables (one per lane).
pub fn build_merkle_sigma_dec_lane_tables(live_slots: usize) -> [Vec<Block128>; STATE_SIZE] {
    let sigma_dec = build_merkle_sigma_dec_table(live_slots);
    std::array::from_fn(|j| merkle_project_lane(&sigma_dec, j))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dec_round_is_inverse_of_inc() {
        for idx in 0..N_MERKLE_UNIFIED_CELLS as u16 {
            assert_eq!(merkle_inc_round_index(merkle_dec_round_index(idx)), idx);
            assert_eq!(merkle_dec_round_index(merkle_inc_round_index(idx)), idx);
        }
    }

    #[test]
    fn pack_unpack_round_trip() {
        for slot in 0..32 {
            for round in 0..N_ROUNDS {
                for elem in 0..STATE_SIZE {
                    let idx = merkle_pack_index(slot, round, elem);
                    assert_eq!(merkle_slot_of(idx), slot);
                    assert_eq!(merkle_round_of(idx), round);
                    assert_eq!(merkle_elem_of(idx), elem);
                }
            }
        }
    }

    #[test]
    fn mu_table_matches_definition() {
        let live = 16;
        let tab = build_merkle_mu_table(live);
        for idx in 0..N_MERKLE_UNIFIED_CELLS {
            let want =
                if merkle_slot_of(idx as u16) < live && merkle_round_of(idx as u16) < N_ROUNDS {
                    Block128::ONE
                } else {
                    Block128::ZERO
                };
            assert_eq!(tab[idx], want, "mu mismatch at idx {idx}");
        }
    }

    #[test]
    fn permute_by_dec_is_round_shift() {
        let src: Vec<_> = (0..N_MERKLE_UNIFIED_CELLS)
            .map(|i| Block128::from(i as u128))
            .collect();
        let dst = merkle_permute_by_dec(&src);
        for y in 0..N_MERKLE_UNIFIED_CELLS {
            let x = merkle_dec_round_index(y as u16) as usize;
            assert_eq!(dst[y], src[x]);
        }
    }
}
