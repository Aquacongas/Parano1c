// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

#![allow(clippy::needless_range_loop)]

//! Round-shift index helpers and public schedule MLEs for
//! the Sweep AuthGKR 16-variable unified Kill Shot.
//!
//! Forked from `spine_shift.rs`, retargeted onto the AuthGKR hypercube
//! (`elem:2 | round:7 | slot:7` → 16 bits, `2^16 = 65 536` cells). The
//! `live_slots` axis is fixed at `N_SWEEP_AUTH_LIVE_SLOTS = 125`.
//!
//! Every public schedule that does not depend on the protocol challenge
//! (μ, σ, RC, the four MDS lane tables) is cached behind a `OnceLock` so
//! repeated AuthGKR proofs in the same process pay the build cost
//! exactly once. The U mask depends on ρ and is therefore not cached.

use std::sync::OnceLock;

use noid_core::mle::eq::eq_ind_partial_eval;
use noid_core::{Block128, TowerField};
use noid_poseidon2b::native::permutation::{
    F_ROUNDS, MDS_FULL, MDS_PARTIAL, N_ROUNDS, P_ROUNDS, ROUND_CONSTANTS, STATE_SIZE,
};

use crate::auth_mle_sweep::{
    sweep_auth_sigma_at, N_SWEEP_AUTH_ELEM_VARS, N_SWEEP_AUTH_LIVE_SLOTS, N_SWEEP_AUTH_ROUND_VARS,
    N_SWEEP_AUTH_SLOT_BITS, N_SWEEP_AUTH_UNIFIED_CELLS, N_SWEEP_AUTH_UNIFIED_VARS,
};

const ELEM_BITS: usize = N_SWEEP_AUTH_ELEM_VARS; // 2
const ROUND_BITS: usize = N_SWEEP_AUTH_ROUND_VARS; // 7
const SLOT_BITS: usize = N_SWEEP_AUTH_SLOT_BITS; // 5

const ROUND_SHIFT: usize = ELEM_BITS;
const SLOT_SHIFT: usize = ELEM_BITS + ROUND_BITS;

const ROUND_MASK: u16 = ((1 << ROUND_BITS) - 1) << ROUND_SHIFT;
const ELEM_MASK: u16 = (1 << ELEM_BITS) - 1;
const SLOT_MASK: u16 = ((1 << SLOT_BITS) - 1) << SLOT_SHIFT;

const ROUND_LIMIT: usize = 1 << ROUND_BITS; // 128
const ELEM_LIMIT: usize = 1 << ELEM_BITS; // 4

const _: () = assert!(ELEM_BITS + ROUND_BITS + SLOT_BITS == N_SWEEP_AUTH_UNIFIED_VARS);

#[inline]
pub fn sweep_auth_round_of(idx: u16) -> usize {
    ((idx & ROUND_MASK) >> ROUND_SHIFT) as usize
}

#[inline]
pub fn sweep_auth_elem_of(idx: u16) -> usize {
    (idx & ELEM_MASK) as usize
}

#[inline]
pub fn sweep_auth_slot_of(idx: u16) -> usize {
    ((idx & SLOT_MASK) >> SLOT_SHIFT) as usize
}

/// Decrement the round component of a 14-bit cell index by 1 (mod 128).
#[inline]
pub fn sweep_auth_dec_round_index(idx: u16) -> u16 {
    let round = sweep_auth_round_of(idx);
    let prev = (round + ROUND_LIMIT - 1) & (ROUND_LIMIT - 1);
    (idx & !ROUND_MASK) | ((prev as u16) << ROUND_SHIFT)
}

/// Increment the round component of a 14-bit cell index by 1 (mod 128).
#[inline]
pub fn sweep_auth_inc_round_index(idx: u16) -> u16 {
    let round = sweep_auth_round_of(idx);
    let next = (round + 1) & (ROUND_LIMIT - 1);
    (idx & !ROUND_MASK) | ((next as u16) << ROUND_SHIFT)
}

/// Pack `(slot, round, elem)` into the 14-bit cell index.
#[inline]
pub fn sweep_auth_pack_index(slot: usize, round: usize, elem: usize) -> u16 {
    debug_assert!(slot < (1 << SLOT_BITS));
    debug_assert!(round < ROUND_LIMIT);
    debug_assert!(elem < ELEM_LIMIT);
    ((slot << SLOT_SHIFT) | (round << ROUND_SHIFT) | elem) as u16
}

// ---------------------------------------------------------------------------
// MDS lookup
// ---------------------------------------------------------------------------

#[inline]
pub fn sweep_auth_mds_coeff(round: usize, i: usize, j: usize) -> Block128 {
    debug_assert!(round < N_ROUNDS);
    debug_assert!(i < STATE_SIZE);
    debug_assert!(j < STATE_SIZE);
    let is_partial = (F_ROUNDS / 2..F_ROUNDS / 2 + P_ROUNDS).contains(&round);
    let raw = if is_partial {
        MDS_PARTIAL[i][j]
    } else {
        MDS_FULL[i][j]
    };
    Block128::from(raw)
}

// ---------------------------------------------------------------------------
// Cached schedules
// ---------------------------------------------------------------------------

static MU_TABLE: OnceLock<Vec<Block128>> = OnceLock::new();
static SIGMA_TABLE: OnceLock<Vec<Block128>> = OnceLock::new();
static RC_TABLE: OnceLock<Vec<Block128>> = OnceLock::new();
static MDS_LANE_TABLES: OnceLock<[Vec<Block128>; STATE_SIZE]> = OnceLock::new();
static SIGMA_DEC_TABLE: OnceLock<Vec<Block128>> = OnceLock::new();
static RC_DEC_TABLE: OnceLock<Vec<Block128>> = OnceLock::new();
static SIGMA_DEC_LANE_TABLES: OnceLock<[Vec<Block128>; STATE_SIZE]> = OnceLock::new();

fn build_mu_table_uncached() -> Vec<Block128> {
    let mut tab = vec![Block128::ZERO; N_SWEEP_AUTH_UNIFIED_CELLS];
    for slot in 0..N_SWEEP_AUTH_LIVE_SLOTS {
        for round in 0..N_ROUNDS {
            for elem in 0..STATE_SIZE {
                let idx = sweep_auth_pack_index(slot, round, elem);
                tab[idx as usize] = Block128::ONE;
            }
        }
    }
    tab
}

fn build_sigma_table_uncached() -> Vec<Block128> {
    let mut tab = vec![Block128::ZERO; N_SWEEP_AUTH_UNIFIED_CELLS];
    for slot in 0..N_SWEEP_AUTH_LIVE_SLOTS {
        for round in 0..N_ROUNDS {
            for elem in 0..STATE_SIZE {
                let idx = sweep_auth_pack_index(slot, round, elem);
                tab[idx as usize] = sweep_auth_sigma_at(round, elem);
            }
        }
    }
    tab
}

fn build_rc_table_uncached() -> Vec<Block128> {
    let mut tab = vec![Block128::ZERO; N_SWEEP_AUTH_UNIFIED_CELLS];
    for slot in 0..N_SWEEP_AUTH_LIVE_SLOTS {
        for round in 0..N_ROUNDS {
            let is_partial = (F_ROUNDS / 2..F_ROUNDS / 2 + P_ROUNDS).contains(&round);
            for elem in 0..STATE_SIZE {
                if is_partial && elem != 0 {
                    continue;
                }
                let idx = sweep_auth_pack_index(slot, round, elem);
                tab[idx as usize] = Block128::from(ROUND_CONSTANTS[elem][round]);
            }
        }
    }
    tab
}

fn build_mds_lane_table_uncached(lane: usize) -> Vec<Block128> {
    debug_assert!(lane < STATE_SIZE);
    let mut out = vec![Block128::ZERO; N_SWEEP_AUTH_UNIFIED_CELLS];
    for y in 0..N_SWEEP_AUTH_UNIFIED_CELLS {
        let yb = y as u16;
        let slot = sweep_auth_slot_of(yb);
        if slot >= N_SWEEP_AUTH_LIVE_SLOTS {
            continue;
        }
        let dec_round = sweep_auth_round_of(sweep_auth_dec_round_index(yb));
        if dec_round >= N_ROUNDS {
            continue;
        }
        let elem = sweep_auth_elem_of(yb);
        out[y] = sweep_auth_mds_coeff(dec_round, elem, lane);
    }
    out
}

/// μ table — cached.
pub fn sweep_auth_mu_table() -> &'static [Block128] {
    MU_TABLE.get_or_init(build_mu_table_uncached)
}

/// σ table — cached.
pub fn sweep_auth_sigma_table() -> &'static [Block128] {
    SIGMA_TABLE.get_or_init(build_sigma_table_uncached)
}

/// RC table — cached.
pub fn sweep_auth_rc_table() -> &'static [Block128] {
    RC_TABLE.get_or_init(build_rc_table_uncached)
}

/// MDS lane tables (one per lane in `0..STATE_SIZE`) — cached.
pub fn sweep_auth_mds_lane_tables() -> &'static [Vec<Block128>; STATE_SIZE] {
    MDS_LANE_TABLES.get_or_init(|| std::array::from_fn(build_mds_lane_table_uncached))
}

/// Convenience wrapper to fetch a single lane table.
pub fn sweep_auth_mds_lane_table(lane: usize) -> &'static [Block128] {
    &sweep_auth_mds_lane_tables()[lane]
}

/// `permute_by_dec(sigma_table)` — cached.
pub fn sweep_auth_sigma_dec_table() -> &'static [Block128] {
    SIGMA_DEC_TABLE.get_or_init(|| sweep_auth_permute_by_dec(sweep_auth_sigma_table()))
}

/// `permute_by_dec(rc_table)` — cached.
pub fn sweep_auth_rc_dec_table() -> &'static [Block128] {
    RC_DEC_TABLE.get_or_init(|| sweep_auth_permute_by_dec(sweep_auth_rc_table()))
}

/// `project_lane(sigma_dec, j)` for each lane — cached.
pub fn sweep_auth_sigma_dec_lane_tables() -> &'static [Vec<Block128>; STATE_SIZE] {
    SIGMA_DEC_LANE_TABLES.get_or_init(|| {
        let sigma_dec = sweep_auth_permute_by_dec(sweep_auth_sigma_table());
        std::array::from_fn(|j| sweep_auth_project_lane(&sigma_dec, j))
    })
}

// ---------------------------------------------------------------------------
// Pre-flat cached tables: stored as Vec<u128> already in GCM basis.
// Eliminates ~180K tower_to_flat conversions per auth verify (16384 × 11 tables).
// ---------------------------------------------------------------------------

fn to_flat_vec(tower: &[Block128]) -> Vec<u128> {
    use noid_core::hardware::tower_to_flat_u128;
    tower.iter().map(|v| tower_to_flat_u128(v.0)).collect()
}

/// Cached pre-flat auth sigma-dec table.
pub fn sweep_auth_sigma_dec_table_flat() -> &'static Vec<u128> {
    static CACHE: OnceLock<Vec<u128>> = OnceLock::new();
    CACHE.get_or_init(|| to_flat_vec(sweep_auth_sigma_dec_table()))
}

/// Cached pre-flat auth RC-dec table.
pub fn sweep_auth_rc_dec_table_flat() -> &'static Vec<u128> {
    static CACHE: OnceLock<Vec<u128>> = OnceLock::new();
    CACHE.get_or_init(|| to_flat_vec(sweep_auth_rc_dec_table()))
}

/// Cached pre-flat auth MDS lane table for a given lane.
pub fn sweep_auth_mds_lane_tables_flat() -> &'static [Vec<u128>; STATE_SIZE] {
    static CACHE: OnceLock<[Vec<u128>; STATE_SIZE]> = OnceLock::new();
    CACHE.get_or_init(|| {
        let tower = sweep_auth_mds_lane_tables();
        std::array::from_fn(|j| to_flat_vec(&tower[j]))
    })
}

/// Cached pre-flat auth sigma-dec lane tables, one per lane.
pub fn sweep_auth_sigma_dec_lane_tables_flat() -> &'static [Vec<u128>; STATE_SIZE] {
    static CACHE: OnceLock<[Vec<u128>; STATE_SIZE]> = OnceLock::new();
    CACHE.get_or_init(|| {
        let tower = sweep_auth_sigma_dec_lane_tables();
        std::array::from_fn(|j| to_flat_vec(&tower[j]))
    })
}

// ---------------------------------------------------------------------------
// Permutation helpers
// ---------------------------------------------------------------------------

/// `out[y] = src[sweep_auth_dec_round_index(y)]`.
pub fn sweep_auth_permute_by_dec(src: &[Block128]) -> Vec<Block128> {
    debug_assert_eq!(src.len(), N_SWEEP_AUTH_UNIFIED_CELLS);
    // Sequential: rayon overhead exceeds compute for N_SWEEP_AUTH_UNIFIED_CELLS = 16384.
    let mut out = vec![Block128::ZERO; N_SWEEP_AUTH_UNIFIED_CELLS];
    for y in 0..N_SWEEP_AUTH_UNIFIED_CELLS {
        out[y] = src[sweep_auth_dec_round_index(y as u16) as usize];
    }
    out
}

/// Build the unified mask `U[y] = eq(ρ, dec(y)) · μ(dec(y))`. ρ has
/// length `N_SWEEP_AUTH_UNIFIED_VARS = 16`. Not cached — depends on ρ.
pub fn sweep_auth_build_u_table(rho: &[Block128]) -> Vec<Block128> {
    debug_assert_eq!(rho.len(), N_SWEEP_AUTH_UNIFIED_VARS);
    let eq_tab = eq_ind_partial_eval::<Block128>(rho);
    let mu_tab = sweep_auth_mu_table();
    let mut out = vec![Block128::ZERO; N_SWEEP_AUTH_UNIFIED_CELLS];
    for y in 0..N_SWEEP_AUTH_UNIFIED_CELLS {
        let x = sweep_auth_dec_round_index(y as u16) as usize;
        out[y] = eq_tab[x] * mu_tab[x];
    }
    out
}

/// Build `lane[y] = src[ (slot(y), round(y), e=lane) ]`. Independent of
/// `elem` bits of `y`.
pub fn sweep_auth_project_lane(src: &[Block128], lane: usize) -> Vec<Block128> {
    debug_assert!(lane < STATE_SIZE);
    debug_assert_eq!(src.len(), N_SWEEP_AUTH_UNIFIED_CELLS);
    let mut out = vec![Block128::ZERO; N_SWEEP_AUTH_UNIFIED_CELLS];
    for y in 0..N_SWEEP_AUTH_UNIFIED_CELLS {
        let row_base = (y as u16) & !ELEM_MASK;
        out[y] = src[(row_base | lane as u16) as usize];
    }
    out
}

// ---------------------------------------------------------------------------
// MLE evaluators — used by verifier and tests.
// ---------------------------------------------------------------------------

fn inner_product_with_eq_tensor(tab: &[Block128], point: &[Block128]) -> Block128 {
    let eq_tab = eq_ind_partial_eval::<Block128>(point);
    debug_assert_eq!(eq_tab.len(), tab.len());
    let mut acc = Block128::ZERO;
    for (a, b) in tab.iter().zip(eq_tab.iter()) {
        acc += *a * *b;
    }
    acc
}

pub fn sweep_auth_mu_evaluate(point: &[Block128]) -> Block128 {
    debug_assert_eq!(point.len(), N_SWEEP_AUTH_UNIFIED_VARS);
    inner_product_with_eq_tensor(sweep_auth_mu_table(), point)
}

pub fn sweep_auth_sigma_evaluate(point: &[Block128]) -> Block128 {
    debug_assert_eq!(point.len(), N_SWEEP_AUTH_UNIFIED_VARS);
    inner_product_with_eq_tensor(sweep_auth_sigma_table(), point)
}

pub fn sweep_auth_rc_evaluate(point: &[Block128]) -> Block128 {
    debug_assert_eq!(point.len(), N_SWEEP_AUTH_UNIFIED_VARS);
    inner_product_with_eq_tensor(sweep_auth_rc_table(), point)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn boolean_point(idx: u16) -> Vec<Block128> {
        (0..N_SWEEP_AUTH_UNIFIED_VARS)
            .map(|b| {
                if (idx >> b) & 1 == 1 {
                    Block128::ONE
                } else {
                    Block128::ZERO
                }
            })
            .collect()
    }

    #[test]
    fn dec_round_is_inverse_of_inc_round() {
        for idx in 0..N_SWEEP_AUTH_UNIFIED_CELLS {
            let idx = idx as u16;
            assert_eq!(
                sweep_auth_inc_round_index(sweep_auth_dec_round_index(idx)),
                idx
            );
            assert_eq!(
                sweep_auth_dec_round_index(sweep_auth_inc_round_index(idx)),
                idx
            );
        }
    }

    #[test]
    fn dec_round_wraps_modulo_128() {
        let idx = sweep_auth_pack_index(3, 0, 2);
        let dec = sweep_auth_dec_round_index(idx);
        assert_eq!(sweep_auth_slot_of(dec), 3);
        assert_eq!(sweep_auth_elem_of(dec), 2);
        assert_eq!(sweep_auth_round_of(dec), ROUND_LIMIT - 1);
    }

    #[test]
    fn pack_unpack_round_trip() {
        for slot in 0..N_SWEEP_AUTH_LIVE_SLOTS {
            for round in 0..N_ROUNDS {
                for elem in 0..STATE_SIZE {
                    let idx = sweep_auth_pack_index(slot, round, elem);
                    assert_eq!(sweep_auth_slot_of(idx), slot);
                    assert_eq!(sweep_auth_round_of(idx), round);
                    assert_eq!(sweep_auth_elem_of(idx), elem);
                }
            }
        }
    }

    #[test]
    fn mu_table_matches_definition() {
        let tab = sweep_auth_mu_table();
        for idx in 0..N_SWEEP_AUTH_UNIFIED_CELLS {
            let want = if sweep_auth_slot_of(idx as u16) < N_SWEEP_AUTH_LIVE_SLOTS
                && sweep_auth_round_of(idx as u16) < N_ROUNDS
            {
                Block128::ONE
            } else {
                Block128::ZERO
            };
            assert_eq!(tab[idx], want, "mu mismatch at idx {idx}");
        }
    }

    #[test]
    fn cached_tables_are_idempotent() {
        let a = sweep_auth_mu_table().as_ptr();
        let b = sweep_auth_mu_table().as_ptr();
        assert_eq!(a, b, "μ table should be cached");
        let c = sweep_auth_sigma_table().as_ptr();
        let d = sweep_auth_sigma_table().as_ptr();
        assert_eq!(c, d, "σ table should be cached");
        let e = sweep_auth_rc_table().as_ptr();
        let f = sweep_auth_rc_table().as_ptr();
        assert_eq!(e, f, "RC table should be cached");
        for lane in 0..STATE_SIZE {
            let p = sweep_auth_mds_lane_table(lane).as_ptr();
            let q = sweep_auth_mds_lane_table(lane).as_ptr();
            assert_eq!(p, q, "MDS lane {lane} should be cached");
        }
    }

    #[test]
    fn sigma_evaluate_at_boolean_points_matches_native() {
        for slot in [0usize, 5, 19] {
            for round in [0usize, 4, 5, 30, 61, 62, 65] {
                for elem in 0..STATE_SIZE {
                    let idx = sweep_auth_pack_index(slot, round, elem);
                    let pt = boolean_point(idx);
                    assert_eq!(
                        sweep_auth_sigma_evaluate(&pt),
                        sweep_auth_sigma_at(round, elem)
                    );
                }
            }
        }
    }

    #[test]
    fn rc_evaluate_at_live_boolean_points_matches_native() {
        for slot in [0usize, 1, 10, 19] {
            for round in [0usize, 1, 4, 5, 33, 61, 62, 65] {
                let is_partial = (F_ROUNDS / 2..F_ROUNDS / 2 + P_ROUNDS).contains(&round);
                for elem in 0..STATE_SIZE {
                    let idx = sweep_auth_pack_index(slot, round, elem);
                    let pt = boolean_point(idx);
                    let want = if is_partial && elem != 0 {
                        Block128::ZERO
                    } else {
                        Block128::from(ROUND_CONSTANTS[elem][round])
                    };
                    assert_eq!(
                        sweep_auth_rc_evaluate(&pt),
                        want,
                        "slot={slot} round={round} elem={elem}"
                    );
                }
            }
        }
    }

    #[test]
    fn rc_zero_outside_live_topology() {
        let idx = sweep_auth_pack_index(N_SWEEP_AUTH_LIVE_SLOTS, 7, 1);
        let pt = boolean_point(idx);
        assert_eq!(sweep_auth_rc_evaluate(&pt), Block128::ZERO);
        let idx2 = sweep_auth_pack_index(0, N_ROUNDS, 0);
        let pt2 = boolean_point(idx2);
        assert_eq!(sweep_auth_rc_evaluate(&pt2), Block128::ZERO);
    }

    #[test]
    fn permute_by_dec_is_round_shift() {
        let src: Vec<_> = (0..N_SWEEP_AUTH_UNIFIED_CELLS)
            .map(|i| Block128::from(i as u128))
            .collect();
        let dst = sweep_auth_permute_by_dec(&src);
        for y in 0..N_SWEEP_AUTH_UNIFIED_CELLS {
            let x = sweep_auth_dec_round_index(y as u16) as usize;
            assert_eq!(dst[y], src[x]);
        }
    }

    #[test]
    fn build_u_table_matches_definition() {
        let rho = boolean_point(7);
        let u = sweep_auth_build_u_table(&rho);
        let mu = sweep_auth_mu_table();
        for y in 0..N_SWEEP_AUTH_UNIFIED_CELLS {
            let x = sweep_auth_dec_round_index(y as u16) as usize;
            let want = if x == 7 { mu[x] } else { Block128::ZERO };
            assert_eq!(u[y], want);
        }
    }

    #[test]
    fn project_lane_is_elem_substitution() {
        let src: Vec<_> = (0..N_SWEEP_AUTH_UNIFIED_CELLS)
            .map(|i| Block128::from(i as u128))
            .collect();
        for lane in 0..STATE_SIZE {
            let p = sweep_auth_project_lane(&src, lane);
            for y in 0..N_SWEEP_AUTH_UNIFIED_CELLS {
                let want = src[((y as u16) & !ELEM_MASK | lane as u16) as usize];
                assert_eq!(p[y], want);
            }
        }
    }

    #[test]
    fn mds_lane_table_zero_outside_topology() {
        for lane in 0..STATE_SIZE {
            let tab = sweep_auth_mds_lane_table(lane);
            for y in (N_SWEEP_AUTH_LIVE_SLOTS << SLOT_SHIFT)..N_SWEEP_AUTH_UNIFIED_CELLS {
                if sweep_auth_slot_of(y as u16) >= N_SWEEP_AUTH_LIVE_SLOTS {
                    assert_eq!(tab[y], Block128::ZERO, "padded slot y={y}");
                }
            }
            let y = sweep_auth_pack_index(0, 1, 2) as usize;
            let dec_y = sweep_auth_dec_round_index(y as u16);
            let dec_round = sweep_auth_round_of(dec_y);
            let elem = sweep_auth_elem_of(y as u16);
            assert_eq!(tab[y], sweep_auth_mds_coeff(dec_round, elem, lane));
        }
    }
}
