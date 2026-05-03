// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Stage 3c-5 — `TxBodyMerkleAir` (homogeneous 68-instance permutation stack).
//!
//! Per the tx-body Merkle shape locked in `primitives.rs`
//! (`TXBODY_INPUTS = 4`, `TXBODY_OUTPUTS = 8`, `TXBODY_DEPTH = 4`), one
//! honest tx produces
//!
//! ```text
//!   12 leaf hashes × 3 permutations each        = 36 perms
//!   15 internal compress() × 2 permutations     = 30 perms
//!    1 wrap compress(root, wrap_tag) × 2         =  2 perms
//!   -----------------------------------------------------
//!   total                                       = 68 perms
//! ```
//!
//! # Layout strategy
//!
//! Homogeneous stacking along rows. One Poseidon2b permutation block
//! (30 cols, same layout as 3c-1), with **68 instances laid out
//! row-major**. Each instance occupies a `SLOT = 128`-row slice of the
//! trace (nearest power-of-2 ≥ `N_ROUNDS + 1 = 67`). Total rows =
//! `68 × 128 = 8704`, padded to `2^14 = 16384`. Remaining 89 slots are
//! inert (all columns zero, every gate is selector-suppressed because
//! `is_round = 0`).
//!
//! The constraint set is **the same 29 gates as `PoseidonPermAir`**,
//! emitted once — they hold at every row, so they cover all 68
//! instances simultaneously without the per-instance column blow-up of
//! a side-by-side layout.
//!
//! This is exactly the regime the §3b-0 ladder-sumcheck batcher was
//! built to amortize. The `ts+sc` bucket now pays for 30 columns over
//! `2^14` rows (once), not `68 × 30` columns over `2^8` rows, so the
//! column-count cost of the multi-permutation proof goes linear → log
//! at the sumcheck layer.
//!
//! # Inter-instance safety
//!
//! The MDS blend gate reads `s_next[lane]` via a single shift. At the
//! last active row of instance `k` (`row_offset + N_ROUNDS`) the gate is
//! suppressed by `is_round = 0` on the output row — so the shift-into-
//! padding and the shift-into-next-instance's-row-0 are both
//! unconstrained. No data leaks between instances at the interior
//! layer.
//!
//! **Boundary ties** (which instance's output feeds which instance's
//! input, the two fixed absorb-XORs per leaf, the compress IV, the wrap
//! tag) are deferred to §3d's `ConstColumnGate` / `RowSelectorGate`
//! bundle. 3c-5 proves: "these 68 rows-chunks are each a legal
//! Poseidon2b permutation whose input sits at their first row".

use crate::airs::poseidon_perm::{
    emit_perm_all_at, write_perm_trace_at_offset, PermLayout, DEFAULT_PERM_LAYOUT,
    POSEIDON_PERM_N_COLS,
};
use crate::{Air, Constraint, Trace};
use noid_core::{Block128, TowerField};
use noid_poseidon2b::native::permutation::{N_ROUNDS, STATE_SIZE};

/// Number of permutation instances proved in one tx-body Merkle trace.
pub const TXBODY_MERKLE_N_PERMS: usize = 68;

/// Rows allotted to each permutation instance. Must be `>= N_ROUNDS +
/// 1 = 67`; rounded up to the nearest power of two for clean row
/// arithmetic.
pub const TXBODY_MERKLE_SLOT_ROWS: usize = 128;
pub const TXBODY_MERKLE_SLOT_LOG_ROWS: usize = 7;

/// Total row count, padded to the next power of two covering all 68
/// instance slots.
pub const TXBODY_MERKLE_LOG_ROWS: usize = 14;
pub const TXBODY_MERKLE_N_ROWS: usize = 1 << TXBODY_MERKLE_LOG_ROWS;

/// Column count: one permutation lane, reused row-major across all
/// 68 instances.
pub const TXBODY_MERKLE_N_COLS: usize = POSEIDON_PERM_N_COLS;

pub const TXBODY_MERKLE_LAYOUT: PermLayout = DEFAULT_PERM_LAYOUT;

/// Row offset of instance `k`'s first row.
#[inline]
pub const fn instance_row_offset(k: usize) -> usize {
    k * TXBODY_MERKLE_SLOT_ROWS
}

/// Build an honest witness trace for a batch of `N_PERMS` Poseidon2b
/// permutations, laid out row-major at `SLOT`-row stride. Each
/// `inputs[k]` seeds instance `k`'s row-0 state. Everything beyond the
/// 68 instance slots is zero padding (no active rows, all selectors
/// off).
pub fn build_tx_body_merkle_trace(
    inputs: &[[Block128; STATE_SIZE]; TXBODY_MERKLE_N_PERMS],
) -> Vec<Vec<Block128>> {
    let mut cols: Vec<Vec<Block128>> = (0..TXBODY_MERKLE_N_COLS)
        .map(|_| vec![Block128::ZERO; TXBODY_MERKLE_N_ROWS])
        .collect();

    for (k, input) in inputs.iter().enumerate() {
        let row_offset = instance_row_offset(k);
        write_perm_trace_at_offset(&mut cols, TXBODY_MERKLE_LAYOUT, *input, row_offset);
    }

    cols
}

/// Extract instance `k`'s permutation output (state at row
/// `instance_row_offset(k) + N_ROUNDS`).
pub fn extract_instance_output(
    cols: &[Vec<Block128>],
    k: usize,
) -> [Block128; STATE_SIZE] {
    let row = instance_row_offset(k) + N_ROUNDS;
    let mut out = [Block128::ZERO; STATE_SIZE];
    for lane in 0..STATE_SIZE {
        out[lane] = cols[TXBODY_MERKLE_LAYOUT.s + lane][row];
    }
    out
}

/// Emit the stacked-permutation constraint set. Identical to
/// `emit_perm_all_at(DEFAULT_PERM_LAYOUT)`: 29 gates, each holding at
/// every row of the trace (selectors gate them on or off per-row). No
/// per-instance duplication.
pub fn emit_tx_body_merkle_constraints() -> Vec<Box<dyn Constraint>> {
    emit_perm_all_at(TXBODY_MERKLE_LAYOUT)
}

pub struct TxBodyMerkleAir {
    constraints: Vec<Box<dyn Constraint>>,
}

impl TxBodyMerkleAir {
    pub fn new() -> Self {
        Self {
            constraints: emit_tx_body_merkle_constraints(),
        }
    }

    pub fn build_trace(
        &self,
        inputs: &[[Block128; STATE_SIZE]; TXBODY_MERKLE_N_PERMS],
    ) -> Trace {
        Trace::new(build_tx_body_merkle_trace(inputs))
    }
}

impl Default for TxBodyMerkleAir {
    fn default() -> Self {
        Self::new()
    }
}

impl Air for TxBodyMerkleAir {
    fn n_columns(&self) -> usize {
        TXBODY_MERKLE_N_COLS
    }
    fn log_rows(&self) -> usize {
        TXBODY_MERKLE_LOG_ROWS
    }
    fn constraints(&self) -> &[Box<dyn Constraint>] {
        &self.constraints
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use noid_poseidon2b::native::permutation::Poseidon2bPermutation;

    fn mk_input(seed: u128) -> [Block128; STATE_SIZE] {
        let s = seed.wrapping_mul(0x9E3779B97F4A7C15);
        [
            Block128::from(s ^ 0xA5A5_A5A5_A5A5_A5A5),
            Block128::from(s.wrapping_add(1) ^ 0x5A5A_5A5A_5A5A_5A5A),
            Block128::from(s.wrapping_add(2) ^ 0xFFFF_0000_FFFF_0000),
            Block128::from(s.wrapping_add(3) ^ 0x0F0F_F0F0_0F0F_F0F0),
        ]
    }

    fn mk_batch() -> [[Block128; STATE_SIZE]; TXBODY_MERKLE_N_PERMS] {
        let mut out = [[Block128::ZERO; STATE_SIZE]; TXBODY_MERKLE_N_PERMS];
        for k in 0..TXBODY_MERKLE_N_PERMS {
            out[k] = mk_input(k as u128 + 1);
        }
        out
    }

    #[test]
    fn layout_arithmetic_is_consistent() {
        assert_eq!(TXBODY_MERKLE_SLOT_ROWS, 1 << TXBODY_MERKLE_SLOT_LOG_ROWS);
        assert!(TXBODY_MERKLE_SLOT_ROWS >= N_ROUNDS + 1);
        assert!(
            TXBODY_MERKLE_N_PERMS * TXBODY_MERKLE_SLOT_ROWS <= TXBODY_MERKLE_N_ROWS,
            "68 instances must fit inside 2^14 rows",
        );
        assert_eq!(TXBODY_MERKLE_N_COLS, POSEIDON_PERM_N_COLS);
    }

    #[test]
    fn each_instance_output_matches_native_permutation() {
        let batch = mk_batch();
        let cols = build_tx_body_merkle_trace(&batch);
        for (k, input) in batch.iter().enumerate() {
            let mut native = *input;
            Poseidon2bPermutation.permute_mut(&mut native);
            let traced = extract_instance_output(&cols, k);
            assert_eq!(traced, native, "instance {k} output must match native");
        }
    }

    #[test]
    fn trace_dimensions_match_constants() {
        let cols = build_tx_body_merkle_trace(&mk_batch());
        assert_eq!(cols.len(), TXBODY_MERKLE_N_COLS);
        for c in &cols {
            assert_eq!(c.len(), TXBODY_MERKLE_N_ROWS);
        }
    }

    #[test]
    fn padding_rows_are_inert() {
        // Rows beyond the 68 instance slots must be zero in every column.
        let cols = build_tx_body_merkle_trace(&mk_batch());
        let last_used_row = instance_row_offset(TXBODY_MERKLE_N_PERMS - 1) + N_ROUNDS;
        // Within the last slot past N_ROUNDS, is_round/is_full are zero.
        for r in (last_used_row + 1)..TXBODY_MERKLE_N_ROWS {
            assert_eq!(cols[TXBODY_MERKLE_LAYOUT.is_round][r], Block128::ZERO);
            assert_eq!(cols[TXBODY_MERKLE_LAYOUT.is_full][r], Block128::ZERO);
        }
    }

    #[test]
    fn constraint_count_is_single_instance_worth() {
        // 29 = 16 (sbox chain) + 6 (rc binding incl. bool gates) + 4 (mds
        // blend) + 3 (partial sbox kill). The whole point of the
        // homogeneous stack: gate set does NOT scale with N_PERMS.
        let cs = emit_tx_body_merkle_constraints();
        assert_eq!(cs.len(), 29);
    }

    #[test]
    fn air_accepts_honest_stacked_trace() {
        let air = TxBodyMerkleAir::new();
        let trace = air.build_trace(&mk_batch());
        assert!(air.check(&trace));
    }

    #[test]
    fn air_rejects_tamper_in_instance_0() {
        let air = TxBodyMerkleAir::new();
        let mut cols = build_tx_body_merkle_trace(&mk_batch());
        let row = instance_row_offset(0) + 1;
        cols[TXBODY_MERKLE_LAYOUT.sout + 2][row] =
            cols[TXBODY_MERKLE_LAYOUT.sout + 2][row] + Block128::ONE;
        assert!(!air.check(&Trace::new(cols)));
    }

    #[test]
    fn air_rejects_tamper_in_mid_instance() {
        let air = TxBodyMerkleAir::new();
        let mut cols = build_tx_body_merkle_trace(&mk_batch());
        // Tamper an MDS output at a full-round row of instance 33.
        let row = instance_row_offset(33) + 3;
        cols[TXBODY_MERKLE_LAYOUT.s + 1][row] =
            cols[TXBODY_MERKLE_LAYOUT.s + 1][row] + Block128::ONE;
        assert!(!air.check(&Trace::new(cols)));
    }

    #[test]
    fn air_rejects_tamper_in_last_instance() {
        let air = TxBodyMerkleAir::new();
        let mut cols = build_tx_body_merkle_trace(&mk_batch());
        // Partial-round RC at instance 67.
        let row = instance_row_offset(TXBODY_MERKLE_N_PERMS - 1) + 10;
        cols[TXBODY_MERKLE_LAYOUT.rc + 0][row] =
            cols[TXBODY_MERKLE_LAYOUT.rc + 0][row] + Block128::ONE;
        assert!(!air.check(&Trace::new(cols)));
    }

    #[test]
    fn tamper_in_inter_instance_padding_is_suppressed() {
        // Between instance k's output row and instance k+1's row 0,
        // is_round = is_full = 0 — so the MDS blend and RC binding
        // gates are suppressed. We can freely tamper `s[..]` and
        // `rc[..]` on padding rows without tripping any constraint.
        //
        // Note: the S-box chain (x2=sin², sout=x4·x3, ...) is NOT
        // selector-gated — it holds at every row. So sin/x2/x3/x4/sout
        // must remain zero on padding; only `s` and `rc` are free.
        let air = TxBodyMerkleAir::new();
        let mut cols = build_tx_body_merkle_trace(&mk_batch());
        let pad_row = instance_row_offset(5) + N_ROUNDS + 10;
        assert!(pad_row < instance_row_offset(6));
        cols[TXBODY_MERKLE_LAYOUT.s + 0][pad_row] = Block128::from(0xFEEDFACE_DEADBEEF_u128);
        cols[TXBODY_MERKLE_LAYOUT.s + 2][pad_row] = Block128::from(0xABCD_1234_u128);
        cols[TXBODY_MERKLE_LAYOUT.rc + 1][pad_row] = Block128::from(0x9999_8888_u128);
        assert!(air.check(&Trace::new(cols)));
    }
}
