// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

#![allow(clippy::needless_range_loop, clippy::doc_overindented_list_items)]

//! Round-shift index helpers and public MLE evaluators
//! for the unified Spine Kill-Shot sumcheck.
//!
//! The unified Kill-Shot sumcheck proves
//!
//! ```text
//!   Σ_y  U(y) · [ C1(dec(y)) + β · C2(y) ] = 0
//! ```
//!
//! by the change of variable `y = inc_round(x)`. The non-linearity of
//! the round-shift carry stays out of the MLEs and lives entirely in
//! these public schedules:
//!
//! * `U(y)             = eq(ρ, dec(y)) · μ(dec(y))`
//! * `μ(x) = 1` iff   `round(x) < N_ROUNDS` **and** `slot(x) < N_SWEEP_SPINE_SLOTS`
//!                    (i.e. `x` is a live witness cell). This mask is
//!                    keyed at `dec(y)` because every constraint
//!                    summed by `U(y)` is keyed there: C1/C1' are
//!                    indexed at `dec(y)`, and C2's source row
//!                    (whose MDS image is `state(y)`) is at `dec(y)`.
//! * `RC(y)`           is the public 17-var MLE of round constants
//!                    indexed at the *next* round (i.e. evaluated at
//!                    `y` directly — no shift needed inside this MLE).
//! * `σ(x)`            is the public S-box selector schedule.
//!
//! Index layout (low → high bit): `elem:2 | round:7 | slot:8`.
//! `sweep_spine_dec_round_index(y)` decrements the round bits by 1 (mod 128) using
//! plain integer arithmetic on the 17-bit index — no symbolic
//! polynomial work.
//!
//! All `*_evaluate` functions take a 17-element point in `F^17` and
//! return the evaluation of the corresponding multilinear extension.
//! They are intended for the verifier (called once per spine proof)
//! and for prover sanity tests; the prover itself does not call them
//! in the hot path.

use std::sync::OnceLock;

use noid_core::mle::eq::eq_ind_partial_eval;
use noid_core::{Block128, TowerField};
use noid_poseidon2b::native::permutation::{
    F_ROUNDS, MDS_FULL, MDS_PARTIAL, N_ROUNDS, P_ROUNDS, ROUND_CONSTANTS, STATE_SIZE,
};

use crate::circuit_sweep::N_SWEEP_SPINE_SLOTS;
use crate::spine_mle_sweep::{
    sweep_spine_sigma_at, N_SWEEP_SPINE_ELEM_VARS, N_SWEEP_SPINE_ROUND_VARS,
    N_SWEEP_SPINE_SLOT_VARS, N_SWEEP_SPINE_UNIFIED_CELLS, N_SWEEP_SPINE_UNIFIED_VARS,
};

const ELEM_BITS: usize = N_SWEEP_SPINE_ELEM_VARS; // 2
const ROUND_BITS: usize = N_SWEEP_SPINE_ROUND_VARS; // 7
const SLOT_BITS: usize = N_SWEEP_SPINE_SLOT_VARS; // 8

const ROUND_SHIFT: usize = ELEM_BITS;
const SLOT_SHIFT: usize = ELEM_BITS + ROUND_BITS;

const ROUND_MASK: u32 = ((1 << ROUND_BITS) - 1) << ROUND_SHIFT;
const ELEM_MASK: u32 = (1 << ELEM_BITS) - 1;
const SLOT_MASK: u32 = ((1 << SLOT_BITS) - 1) << SLOT_SHIFT;

const ROUND_LIMIT: usize = 1 << ROUND_BITS; // 128
const ELEM_LIMIT: usize = 1 << ELEM_BITS; // 4

// Compile-time consistency with the unified MLE.
const _: () = assert!(ELEM_BITS + ROUND_BITS + SLOT_BITS == N_SWEEP_SPINE_UNIFIED_VARS);

/// Extract the 7-bit round index from a packed 17-bit cell index.
#[inline]
pub fn sweep_spine_round_of(idx: u32) -> usize {
    ((idx & ROUND_MASK) >> ROUND_SHIFT) as usize
}

/// Extract the 2-bit element index from a packed 17-bit cell index.
#[inline]
pub fn sweep_spine_elem_of(idx: u32) -> usize {
    (idx & ELEM_MASK) as usize
}

/// Extract the 8-bit slot index from a packed 17-bit cell index.
#[inline]
pub fn sweep_spine_slot_of(idx: u32) -> usize {
    ((idx & SLOT_MASK) >> SLOT_SHIFT) as usize
}

/// Decrement the round component of a 17-bit cell index by 1 (mod 128).
/// This is the inverse of `sweep_spine_inc_round_index` and is the *only* helper
/// the prover hot path needs: it is plain integer arithmetic with no
/// symbolic / polynomial expansion.
#[inline]
pub fn sweep_spine_dec_round_index(idx: u32) -> u32 {
    let round = sweep_spine_round_of(idx);
    let prev = (round + ROUND_LIMIT - 1) & (ROUND_LIMIT - 1);
    (idx & !ROUND_MASK) | ((prev as u32) << ROUND_SHIFT)
}

/// Increment the round component of a 17-bit cell index by 1 (mod 128).
/// Provided for symmetry / tests; the hot path only ever decrements.
#[inline]
pub fn sweep_spine_inc_round_index(idx: u32) -> u32 {
    let round = sweep_spine_round_of(idx);
    let next = (round + 1) & (ROUND_LIMIT - 1);
    (idx & !ROUND_MASK) | ((next as u32) << ROUND_SHIFT)
}

// ---------------------------------------------------------------------------
// μ schedule
// ---------------------------------------------------------------------------

/// `μ_table[idx] == ONE` iff `slot(idx) < live_slots` and
/// `round(idx) < N_ROUNDS` (the "live witness cell" mask). Otherwise
/// `ZERO`. Length `2^17`. Parameterised by `live_slots` for the
/// 142-slot sweep tx-body spine topology.
pub fn build_sweep_spine_mu_table_for_live_slots(live_slots: usize) -> Vec<Block128> {
    debug_assert!(live_slots <= (1 << SLOT_BITS));
    let mut tab = vec![Block128::ZERO; N_SWEEP_SPINE_UNIFIED_CELLS];
    for slot in 0..live_slots {
        for round in 0..N_ROUNDS {
            for elem in 0..STATE_SIZE {
                let idx = sweep_spine_pack_index(slot, round, elem);
                tab[idx as usize] = Block128::ONE;
            }
        }
    }
    tab
}

/// Spine default — `live_slots = N_SWEEP_SPINE_SLOTS`.
pub fn build_sweep_spine_mu_table() -> Vec<Block128> {
    build_sweep_spine_mu_table_for_live_slots(N_SWEEP_SPINE_SLOTS)
}

/// Evaluate the multilinear extension of μ at an arbitrary point.
pub fn sweep_spine_mu_evaluate(point: &[Block128]) -> Block128 {
    debug_assert_eq!(point.len(), N_SWEEP_SPINE_UNIFIED_VARS);
    inner_product_with_eq_tensor(&build_sweep_spine_mu_table(), point)
}

// ---------------------------------------------------------------------------
// σ schedule
// ---------------------------------------------------------------------------

/// `σ_table[idx] == ONE` iff the cell goes through the x^7 S-box on the
/// active topology. Length `2^17`. Parameterised by `live_slots`.
pub fn build_sweep_spine_sigma_table_for_live_slots(live_slots: usize) -> Vec<Block128> {
    debug_assert!(live_slots <= (1 << SLOT_BITS));
    let mut tab = vec![Block128::ZERO; N_SWEEP_SPINE_UNIFIED_CELLS];
    for slot in 0..live_slots {
        for round in 0..N_ROUNDS {
            for elem in 0..STATE_SIZE {
                let idx = sweep_spine_pack_index(slot, round, elem);
                tab[idx as usize] = sweep_spine_sigma_at(round, elem);
            }
        }
    }
    tab
}

/// Spine default — `live_slots = N_SWEEP_SPINE_SLOTS`.
pub fn build_sweep_spine_sigma_table() -> Vec<Block128> {
    build_sweep_spine_sigma_table_for_live_slots(N_SWEEP_SPINE_SLOTS)
}

/// Cached spine sigma-dec table: `sweep_spine_permute_by_dec(sigma_table)` (`OnceLock`).
/// Use this in the verifier hot path instead of building + permuting every call.
pub fn sweep_spine_sigma_dec_table() -> &'static Vec<Block128> {
    static CACHE: OnceLock<Vec<Block128>> = OnceLock::new();
    CACHE.get_or_init(|| {
        sweep_spine_permute_by_dec(&build_sweep_spine_sigma_table_for_live_slots(
            N_SWEEP_SPINE_SLOTS,
        ))
    })
}

/// Cached spine RC-dec table: `sweep_spine_permute_by_dec(rc_table)` (`OnceLock`).
pub fn sweep_spine_rc_dec_table() -> &'static Vec<Block128> {
    static CACHE: OnceLock<Vec<Block128>> = OnceLock::new();
    CACHE.get_or_init(|| {
        sweep_spine_permute_by_dec(&build_sweep_spine_rc_table_for_live_slots(
            N_SWEEP_SPINE_SLOTS,
        ))
    })
}

/// Cached spine MDS lane tables (`OnceLock`), one per lane.
pub fn sweep_spine_mds_lane_tables() -> &'static [Vec<Block128>; STATE_SIZE] {
    static CACHE: OnceLock<[Vec<Block128>; STATE_SIZE]> = OnceLock::new();
    CACHE.get_or_init(|| {
        std::array::from_fn(|j| {
            build_sweep_spine_mds_lane_table_for_live_slots(j, N_SWEEP_SPINE_SLOTS)
        })
    })
}

/// Cached `sweep_spine_project_lane(spine_sigma_dec, j)` for each lane j (`OnceLock`).
pub fn sweep_spine_sigma_dec_lane_tables() -> &'static [Vec<Block128>; STATE_SIZE] {
    static CACHE: OnceLock<[Vec<Block128>; STATE_SIZE]> = OnceLock::new();
    CACHE.get_or_init(|| {
        let sigma_dec = sweep_spine_permute_by_dec(&build_sweep_spine_sigma_table_for_live_slots(
            N_SWEEP_SPINE_SLOTS,
        ));
        std::array::from_fn(|j| sweep_spine_project_lane(&sigma_dec, j))
    })
}

// ---------------------------------------------------------------------------
// Pre-flat cached tables: stored as Vec<u128> already in GCM basis.
// Eliminates ~360K tower_to_flat conversions per verify (32768 × 11 tables).
// ---------------------------------------------------------------------------

fn to_flat_vec(tower: &[Block128]) -> Vec<u128> {
    use noid_core::hardware::tower_to_flat_u128;
    tower.iter().map(|v| tower_to_flat_u128(v.0)).collect()
}

/// Cached pre-flat spine sigma-dec table.
pub fn sweep_sweep_spine_sigma_dec_table_flat() -> &'static Vec<u128> {
    static CACHE: OnceLock<Vec<u128>> = OnceLock::new();
    CACHE.get_or_init(|| to_flat_vec(sweep_spine_sigma_dec_table()))
}

/// Cached pre-flat spine RC-dec table.
pub fn sweep_sweep_spine_rc_dec_table_flat() -> &'static Vec<u128> {
    static CACHE: OnceLock<Vec<u128>> = OnceLock::new();
    CACHE.get_or_init(|| to_flat_vec(sweep_spine_rc_dec_table()))
}

/// Cached pre-flat spine MDS lane tables, one per lane.
pub fn sweep_sweep_spine_mds_lane_tables_flat() -> &'static [Vec<u128>; STATE_SIZE] {
    static CACHE: OnceLock<[Vec<u128>; STATE_SIZE]> = OnceLock::new();
    CACHE.get_or_init(|| {
        let tower = sweep_spine_mds_lane_tables();
        std::array::from_fn(|j| to_flat_vec(&tower[j]))
    })
}

/// Cached pre-flat spine sigma-dec lane tables, one per lane.
pub fn sweep_sweep_spine_sigma_dec_lane_tables_flat() -> &'static [Vec<u128>; STATE_SIZE] {
    static CACHE: OnceLock<[Vec<u128>; STATE_SIZE]> = OnceLock::new();
    CACHE.get_or_init(|| {
        let tower = sweep_spine_sigma_dec_lane_tables();
        std::array::from_fn(|j| to_flat_vec(&tower[j]))
    })
}

/// Evaluate the multilinear extension of σ at an arbitrary point.
pub fn sweep_spine_sigma_evaluate(point: &[Block128]) -> Block128 {
    debug_assert_eq!(point.len(), N_SWEEP_SPINE_UNIFIED_VARS);
    inner_product_with_eq_tensor(&build_sweep_spine_sigma_table(), point)
}

// ---------------------------------------------------------------------------
// Round-constant MLE: RC(idx) = ROUND_CONSTANTS[elem][round] for live cells.
// Indexed at *the cell where the constant is consumed*, i.e. directly
// at `y` after the change of variable.
// ---------------------------------------------------------------------------

/// RC table indexed by `(slot, round, elem)`. Pads zero outside the
/// live topology. The constant for partial rounds is stored only at
/// `elem == 0` to mirror the native permutation semantics.
/// Parameterised by `live_slots`.
pub fn build_sweep_spine_rc_table_for_live_slots(live_slots: usize) -> Vec<Block128> {
    debug_assert!(live_slots <= (1 << SLOT_BITS));
    let mut tab = vec![Block128::ZERO; N_SWEEP_SPINE_UNIFIED_CELLS];
    for slot in 0..live_slots {
        for round in 0..N_ROUNDS {
            let is_partial = (F_ROUNDS / 2..F_ROUNDS / 2 + P_ROUNDS).contains(&round);
            for elem in 0..STATE_SIZE {
                if is_partial && elem != 0 {
                    continue;
                }
                let idx = sweep_spine_pack_index(slot, round, elem);
                tab[idx as usize] = Block128::from(ROUND_CONSTANTS[elem][round]);
            }
        }
    }
    tab
}

/// Spine default — `live_slots = N_SWEEP_SPINE_SLOTS`.
pub fn build_sweep_spine_rc_table() -> Vec<Block128> {
    build_sweep_spine_rc_table_for_live_slots(N_SWEEP_SPINE_SLOTS)
}

/// Evaluate the public RC MLE at an arbitrary point.
pub fn sweep_spine_rc_evaluate(point: &[Block128]) -> Block128 {
    debug_assert_eq!(point.len(), N_SWEEP_SPINE_UNIFIED_VARS);
    inner_product_with_eq_tensor(&build_sweep_spine_rc_table(), point)
}

// ---------------------------------------------------------------------------
// MDS row coefficient lookup, used by C2.
// ---------------------------------------------------------------------------

/// Returns the MDS coefficient `M[i][j]` to use at a given round —
/// `MDS_FULL` on full rounds, `MDS_PARTIAL` on partial rounds. `round`
/// is the *source* round (i.e. `round(dec(y))` in the unified
/// sumcheck).
#[inline]
pub fn sweep_spine_mds_coeff(round: usize, i: usize, j: usize) -> Block128 {
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
// Permutation helpers (unified sumcheck Variant I).
//
// All "_dec" tables are pure permutations of their source by
// `sweep_spine_dec_round_index`. They let the unified sumcheck treat all factors
// as plain multilinear MLEs in `y`, at the cost of running a small
// shift gadget afterwards to reduce a `T_dec_ml(r')` claim back to a
// claim on `T_ml` at a permuted point.
// ---------------------------------------------------------------------------

/// Return `out[y] = src[sweep_spine_dec_round_index(y)]`. Used to align every
/// "indexed at `dec(y)`" factor of the unified constraint with the
/// natural `y`-fold direction of the sumcheck.
pub fn sweep_spine_permute_by_dec(src: &[Block128]) -> Vec<Block128> {
    debug_assert_eq!(src.len(), N_SWEEP_SPINE_UNIFIED_CELLS);
    let mut out = vec![Block128::ZERO; N_SWEEP_SPINE_UNIFIED_CELLS];
    for y in 0..N_SWEEP_SPINE_UNIFIED_CELLS {
        out[y] = src[sweep_spine_dec_round_index(y as u32) as usize];
    }
    out
}

/// Build the unified mask `U[y] = eq(ρ, dec(y)) · μ(dec(y))` for the
/// main sumcheck. `ρ` has length `N_SWEEP_SPINE_UNIFIED_VARS`. This is the
/// only `dec`-twisted public schedule the verifier rebuilds natively
/// at the start of the protocol. Parameterised by `live_slots`.
pub fn build_sweep_spine_u_table_for_live_slots(
    rho: &[Block128],
    live_slots: usize,
) -> Vec<Block128> {
    debug_assert_eq!(rho.len(), N_SWEEP_SPINE_UNIFIED_VARS);
    let eq_tab = eq_ind_partial_eval::<Block128>(rho);
    let mu_tab = build_sweep_spine_mu_table_for_live_slots(live_slots);
    let mut out = vec![Block128::ZERO; N_SWEEP_SPINE_UNIFIED_CELLS];
    for y in 0..N_SWEEP_SPINE_UNIFIED_CELLS {
        let x = sweep_spine_dec_round_index(y as u32) as usize;
        out[y] = eq_tab[x] * mu_tab[x];
    }
    out
}

/// Spine default — `live_slots = N_SWEEP_SPINE_SLOTS`.
pub fn build_sweep_spine_u_table(rho: &[Block128]) -> Vec<Block128> {
    build_sweep_spine_u_table_for_live_slots(rho, N_SWEEP_SPINE_SLOTS)
}

/// Build `lane[y] = src[ (slot(y), round(y), e=lane) ]`. Independent of
/// the `elem` bits of `y` — those are projected out and replaced by a
/// fixed lane index. Used by the C2 contribution where the four MDS
/// inputs come from the four lanes of the same `(slot, round)` row.
pub fn sweep_spine_project_lane(src: &[Block128], lane: usize) -> Vec<Block128> {
    debug_assert!(lane < STATE_SIZE);
    debug_assert_eq!(src.len(), N_SWEEP_SPINE_UNIFIED_CELLS);
    let mut out = vec![Block128::ZERO; N_SWEEP_SPINE_UNIFIED_CELLS];
    for y in 0..N_SWEEP_SPINE_UNIFIED_CELLS {
        let row_base = (y as u32) & !ELEM_MASK; // zero the elem bits
        out[y] = src[(row_base | lane as u32) as usize];
    }
    out
}

/// `M_kind_lane_table[y] = M_{kind(dec(y))}[elem(y)][lane]` — the four
/// per-lane MDS coefficient schedules used by C2. `lane` ranges over
/// `0..STATE_SIZE`. Padded cells (slot ≥ N_SWEEP_SPINE_SLOTS or
/// round(dec(y)) outside `0..N_ROUNDS`) get coefficient `ZERO` so the
/// C2 contribution there vanishes.
pub fn build_sweep_spine_mds_lane_table_for_live_slots(
    lane: usize,
    live_slots: usize,
) -> Vec<Block128> {
    debug_assert!(lane < STATE_SIZE);
    debug_assert!(live_slots <= (1 << SLOT_BITS));
    let mut out = vec![Block128::ZERO; N_SWEEP_SPINE_UNIFIED_CELLS];
    for y in 0..N_SWEEP_SPINE_UNIFIED_CELLS {
        let yb = y as u32;
        let slot = sweep_spine_slot_of(yb);
        if slot >= live_slots {
            continue;
        }
        let dec_round = sweep_spine_round_of(sweep_spine_dec_round_index(yb));
        if dec_round >= N_ROUNDS {
            continue;
        }
        let elem = sweep_spine_elem_of(yb);
        out[y] = sweep_spine_mds_coeff(dec_round, elem, lane);
    }
    out
}

/// Spine default — `live_slots = N_SWEEP_SPINE_SLOTS`.
pub fn build_sweep_spine_mds_lane_table(lane: usize) -> Vec<Block128> {
    build_sweep_spine_mds_lane_table_for_live_slots(lane, N_SWEEP_SPINE_SLOTS)
}

// ---------------------------------------------------------------------------
// Internals.
// ---------------------------------------------------------------------------

/// Pack `(slot, round, elem)` into the 17-bit cell index with the
/// canonical layout `elem:2 | round:7 | slot:8` (low → high bit).
#[inline]
pub fn sweep_spine_pack_index(slot: usize, round: usize, elem: usize) -> u32 {
    debug_assert!(slot < (1 << SLOT_BITS));
    debug_assert!(round < ROUND_LIMIT);
    debug_assert!(elem < ELEM_LIMIT);
    ((slot << SLOT_SHIFT) | (round << ROUND_SHIFT) | elem) as u32
}

/// Inner product of a length-`2^17` table with the eq-tensor of
/// `point`, evaluating the multilinear extension of `tab` at `point`.
fn inner_product_with_eq_tensor(tab: &[Block128], point: &[Block128]) -> Block128 {
    let eq_tab = eq_ind_partial_eval::<Block128>(point);
    debug_assert_eq!(eq_tab.len(), tab.len());
    let mut acc = Block128::ZERO;
    for (a, b) in tab.iter().zip(eq_tab.iter()) {
        acc += *a * *b;
    }
    acc
}

#[cfg(test)]
mod tests {
    use super::*;

    fn boolean_point(idx: u32) -> Vec<Block128> {
        (0..N_SWEEP_SPINE_UNIFIED_VARS)
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
        for idx in 0..N_SWEEP_SPINE_UNIFIED_CELLS as u32 {
            assert_eq!(
                sweep_spine_inc_round_index(sweep_spine_dec_round_index(idx)),
                idx
            );
            assert_eq!(
                sweep_spine_dec_round_index(sweep_spine_inc_round_index(idx)),
                idx
            );
        }
    }

    #[test]
    fn dec_round_wraps_modulo_128() {
        // round 0 should wrap to round 127 (= 2^7 - 1).
        let idx = sweep_spine_pack_index(3, 0, 2);
        let dec = sweep_spine_dec_round_index(idx);
        assert_eq!(sweep_spine_slot_of(dec), 3);
        assert_eq!(sweep_spine_elem_of(dec), 2);
        assert_eq!(sweep_spine_round_of(dec), ROUND_LIMIT - 1);
    }

    #[test]
    fn dec_round_decrements_in_middle() {
        let idx = sweep_spine_pack_index(7, 33, 1);
        let dec = sweep_spine_dec_round_index(idx);
        assert_eq!(sweep_spine_slot_of(dec), 7);
        assert_eq!(sweep_spine_elem_of(dec), 1);
        assert_eq!(sweep_spine_round_of(dec), 32);
    }

    #[test]
    fn pack_unpack_round_trip() {
        for slot in 0..N_SWEEP_SPINE_SLOTS {
            for round in 0..N_ROUNDS {
                for elem in 0..STATE_SIZE {
                    let idx = sweep_spine_pack_index(slot, round, elem);
                    assert_eq!(sweep_spine_slot_of(idx), slot);
                    assert_eq!(sweep_spine_round_of(idx), round);
                    assert_eq!(sweep_spine_elem_of(idx), elem);
                }
            }
        }
    }

    #[test]
    fn mu_table_matches_definition() {
        let tab = build_sweep_spine_mu_table();
        for idx in 0..N_SWEEP_SPINE_UNIFIED_CELLS {
            let want = if sweep_spine_slot_of(idx as u32) < N_SWEEP_SPINE_SLOTS
                && sweep_spine_round_of(idx as u32) < N_ROUNDS
            {
                Block128::ONE
            } else {
                Block128::ZERO
            };
            assert_eq!(tab[idx], want, "mu mismatch at idx {idx}");
        }
    }

    #[test]
    fn sweep_spine_mu_evaluate_at_boolean_points_matches_table() {
        let tab = build_sweep_spine_mu_table();
        // Spot-check a handful of indices — exhaustive 128K would be too slow.
        for &idx in &[0u32, 1, 4, 7, 64, 1023, 8192, 16383, 32767, 131071] {
            let pt = boolean_point(idx);
            assert_eq!(sweep_spine_mu_evaluate(&pt), tab[idx as usize], "idx {idx}");
        }
    }

    #[test]
    fn sweep_spine_sigma_evaluate_at_boolean_points_matches_native() {
        for slot in [0usize, 5, 58, N_SWEEP_SPINE_SLOTS - 1] {
            for round in [0usize, 4, 5, 30, 61, 62, 65] {
                for elem in 0..STATE_SIZE {
                    let idx = sweep_spine_pack_index(slot, round, elem);
                    let pt = boolean_point(idx);
                    assert_eq!(
                        sweep_spine_sigma_evaluate(&pt),
                        sweep_spine_sigma_at(round, elem)
                    );
                }
            }
        }
    }

    #[test]
    fn sweep_spine_rc_evaluate_at_live_boolean_points_matches_native() {
        for slot in [0usize, 1, 30, 58, N_SWEEP_SPINE_SLOTS - 1] {
            for round in [0usize, 1, 4, 5, 33, 61, 62, 65] {
                let is_partial = (F_ROUNDS / 2..F_ROUNDS / 2 + P_ROUNDS).contains(&round);
                for elem in 0..STATE_SIZE {
                    let idx = sweep_spine_pack_index(slot, round, elem);
                    let pt = boolean_point(idx);
                    let want = if is_partial && elem != 0 {
                        Block128::ZERO
                    } else {
                        Block128::from(ROUND_CONSTANTS[elem][round])
                    };
                    assert_eq!(
                        sweep_spine_rc_evaluate(&pt),
                        want,
                        "slot={slot} round={round} elem={elem}"
                    );
                }
            }
        }
    }

    #[test]
    fn rc_zero_outside_live_topology() {
        // Padded slots: any cell must be zero.
        let idx = sweep_spine_pack_index(N_SWEEP_SPINE_SLOTS, 7, 1);
        let pt = boolean_point(idx);
        assert_eq!(sweep_spine_rc_evaluate(&pt), Block128::ZERO);
        // Padded round inside a live slot.
        let idx2 = sweep_spine_pack_index(0, N_ROUNDS, 0);
        let pt2 = boolean_point(idx2);
        assert_eq!(sweep_spine_rc_evaluate(&pt2), Block128::ZERO);
    }

    #[test]
    fn sweep_spine_mds_coeff_switches_full_vs_partial() {
        // round 0 is full, round 5 is partial in this schedule
        // (F_ROUNDS=8 → full = 0..3 and 62..65, partial = 4..61).
        for i in 0..STATE_SIZE {
            for j in 0..STATE_SIZE {
                assert_eq!(
                    sweep_spine_mds_coeff(0, i, j),
                    Block128::from(MDS_FULL[i][j])
                );
                assert_eq!(
                    sweep_spine_mds_coeff(5, i, j),
                    Block128::from(MDS_PARTIAL[i][j])
                );
                assert_eq!(
                    sweep_spine_mds_coeff(63, i, j),
                    Block128::from(MDS_FULL[i][j])
                );
            }
        }
    }

    #[test]
    fn sweep_spine_permute_by_dec_is_round_shift() {
        let mut src = vec![Block128::ZERO; N_SWEEP_SPINE_UNIFIED_CELLS];
        for i in 0..N_SWEEP_SPINE_UNIFIED_CELLS {
            src[i] = Block128::from(i as u128);
        }
        let dst = sweep_spine_permute_by_dec(&src);
        for y in 0..N_SWEEP_SPINE_UNIFIED_CELLS {
            let x = sweep_spine_dec_round_index(y as u32) as usize;
            assert_eq!(dst[y], src[x], "y={y} x={x}");
        }
    }

    #[test]
    fn build_sweep_spine_u_table_matches_definition() {
        // ρ = boolean point at idx 7 → eq(ρ, ·) is an indicator,
        // U[y] should be 1 iff dec(y)==7 ∧ μ(7)==1.
        let rho = boolean_point(7);
        let u = build_sweep_spine_u_table(&rho);
        let mu = build_sweep_spine_mu_table();
        for y in 0..N_SWEEP_SPINE_UNIFIED_CELLS {
            let x = sweep_spine_dec_round_index(y as u32) as usize;
            let want = if x == 7 { mu[x] } else { Block128::ZERO };
            assert_eq!(u[y], want, "y={y}");
        }
    }

    #[test]
    fn sweep_spine_project_lane_is_elem_substitution() {
        let mut src = vec![Block128::ZERO; N_SWEEP_SPINE_UNIFIED_CELLS];
        for i in 0..N_SWEEP_SPINE_UNIFIED_CELLS {
            src[i] = Block128::from(i as u128);
        }
        for lane in 0..STATE_SIZE {
            let p = sweep_spine_project_lane(&src, lane);
            for y in 0..N_SWEEP_SPINE_UNIFIED_CELLS {
                let want = src[((y as u32) & !ELEM_MASK | lane as u32) as usize];
                assert_eq!(p[y], want, "lane={lane} y={y}");
            }
        }
    }

    #[test]
    fn mds_lane_table_zero_outside_topology() {
        for lane in 0..STATE_SIZE {
            let tab = build_sweep_spine_mds_lane_table(lane);
            // Padded slot.
            for y in (N_SWEEP_SPINE_SLOTS << SLOT_SHIFT)..N_SWEEP_SPINE_UNIFIED_CELLS {
                if sweep_spine_slot_of(y as u32) >= N_SWEEP_SPINE_SLOTS {
                    assert_eq!(tab[y], Block128::ZERO, "padded slot y={y}");
                }
            }
            // Live cell where dec(y) is also live: must equal the
            // native MDS coefficient.
            let y = sweep_spine_pack_index(0, 1, 2) as usize; // dec(y) is round 0, full
            let dec_y = sweep_spine_dec_round_index(y as u32);
            let dec_round = sweep_spine_round_of(dec_y);
            let elem = sweep_spine_elem_of(y as u32);
            assert_eq!(tab[y], sweep_spine_mds_coeff(dec_round, elem, lane));
        }
    }
}
