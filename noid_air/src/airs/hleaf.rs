// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Stage 3c-4 — `HLeafAir` (4-field `hash_leaf`, 3 permutations).
//!
//! Witnesses the native
//! `noid_poseidon2b::primitives::hash_leaf(&[f0, f1, f2, f3])` pipeline,
//! which is the per-input leaf hash used by `hash_input_leaf` in the
//! tx-body Merkle tree:
//!
//! ```text
//! state = [0, 0, capacity_iv(TAG_LEAF)]
//! state[0] ^= f0; state[1] ^= f1
//! permute                                      // perm A (absorb #1)
//! state[0] ^= f2; state[1] ^= f3
//! permute                                      // perm B (absorb #2)
//! state[0] ^= PAD_0; state[1] ^= PAD_1
//! permute                                      // perm C (padding flush)
//! output = state[0] || state[1]
//! ```
//!
//! Column layout (90 cols = 3 × [`POSEIDON_PERM_N_COLS`]): three perm
//! blocks at bases `0`, `30`, `60`, all sharing the row axis at the
//! STARK floor (`log_rows = 8`, 256 rows).
//!
//! At interior-constraint level this is identical to `HAuthAir`: only
//! the capacity IV (trusted input) differs. Boundary ties (IV, each
//! absorb XOR, two inter-permutation carries, output squeeze) are
//! deferred to §3d's `RowSelectorGate` / `ConstColumnGate` bundle.

use crate::airs::haddr::{HADDR_PAD_0, HADDR_PAD_1};
use crate::airs::poseidon_perm::{
    write_perm_trace_at, PermLayout, POSEIDON_PERM_LOG_ROWS, POSEIDON_PERM_N_COLS,
    POSEIDON_PERM_N_ROWS,
};
use crate::{Air, Constraint, Trace};
use noid_core::{Block128, TowerField};
use noid_poseidon2b::native::domain::{capacity_iv, TAG_LEAF};
use noid_poseidon2b::native::permutation::STATE_SIZE;

pub const HLEAF_PERM_A_BASE: usize = 0;
pub const HLEAF_PERM_B_BASE: usize = POSEIDON_PERM_N_COLS;
pub const HLEAF_PERM_C_BASE: usize = 2 * POSEIDON_PERM_N_COLS;
pub const HLEAF_N_COLS: usize = 3 * POSEIDON_PERM_N_COLS;
pub const HLEAF_LOG_ROWS: usize = POSEIDON_PERM_LOG_ROWS;
pub const HLEAF_N_ROWS: usize = POSEIDON_PERM_N_ROWS;

pub const HLEAF_LAYOUT_A: PermLayout = PermLayout::at(HLEAF_PERM_A_BASE);
pub const HLEAF_LAYOUT_B: PermLayout = PermLayout::at(HLEAF_PERM_B_BASE);
pub const HLEAF_LAYOUT_C: PermLayout = PermLayout::at(HLEAF_PERM_C_BASE);

/// Build an honest witness trace for `hash_leaf(&[f0, f1, f2, f3])`
/// under `TAG_LEAF`.
pub fn build_hleaf_trace(fields: [Block128; 4]) -> Vec<Vec<Block128>> {
    let mut cols: Vec<Vec<Block128>> = (0..HLEAF_N_COLS)
        .map(|_| vec![Block128::ZERO; HLEAF_N_ROWS])
        .collect();

    let [iv_hi, iv_lo] = capacity_iv(TAG_LEAF);

    // Perm A: seed with LEAF IV, XOR absorb (f0, f1) into rate.
    let perm_a_input: [Block128; STATE_SIZE] = [fields[0], fields[1], iv_hi, iv_lo];
    let state_after_a = write_perm_trace_at(&mut cols, HLEAF_LAYOUT_A, perm_a_input);

    // Perm B: XOR absorb (f2, f3) into rate; capacity flows through.
    let perm_b_input: [Block128; STATE_SIZE] = [
        state_after_a[0] + fields[2],
        state_after_a[1] + fields[3],
        state_after_a[2],
        state_after_a[3],
    ];
    let state_after_b = write_perm_trace_at(&mut cols, HLEAF_LAYOUT_B, perm_b_input);

    // Perm C: padding flush.
    let pad0 = Block128::from(HADDR_PAD_0);
    let pad1 = Block128::from(HADDR_PAD_1);
    let perm_c_input: [Block128; STATE_SIZE] = [
        state_after_b[0] + pad0,
        state_after_b[1] + pad1,
        state_after_b[2],
        state_after_b[3],
    ];
    write_perm_trace_at(&mut cols, HLEAF_LAYOUT_C, perm_c_input);

    cols
}

/// Extract the `(out[0], out[1])` state at row `N_ROUNDS` of block C.
pub fn extract_hleaf_output(cols: &[Vec<Block128>]) -> [Block128; 2] {
    let row = noid_poseidon2b::native::permutation::N_ROUNDS;
    [
        cols[HLEAF_LAYOUT_C.s][row],
        cols[HLEAF_LAYOUT_C.s + 1][row],
    ]
}

/// Emit the three interior constraint blocks.
pub fn emit_hleaf_constraints() -> Vec<Box<dyn Constraint>> {
    let mut out = Vec::with_capacity(87);
    out.extend(crate::airs::emit_perm_all_at(HLEAF_LAYOUT_A));
    out.extend(crate::airs::emit_perm_all_at(HLEAF_LAYOUT_B));
    out.extend(crate::airs::emit_perm_all_at(HLEAF_LAYOUT_C));
    out
}

pub struct HLeafAir {
    constraints: Vec<Box<dyn Constraint>>,
}

impl HLeafAir {
    pub fn new() -> Self {
        Self {
            constraints: emit_hleaf_constraints(),
        }
    }

    pub fn build_trace(&self, fields: [Block128; 4]) -> Trace {
        Trace::new(build_hleaf_trace(fields))
    }
}

impl Default for HLeafAir {
    fn default() -> Self {
        Self::new()
    }
}

impl Air for HLeafAir {
    fn n_columns(&self) -> usize {
        HLEAF_N_COLS
    }
    fn log_rows(&self) -> usize {
        HLEAF_LOG_ROWS
    }
    fn constraints(&self) -> &[Box<dyn Constraint>] {
        &self.constraints
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use noid_core::CanonicalSerialize;

    fn mk_fields4(seed: u128) -> [Block128; 4] {
        let s = seed.wrapping_mul(0x9E3779B97F4A7C15);
        [
            Block128::from(s ^ 0x1111_1111_1111_1111),
            Block128::from(s.wrapping_add(1) ^ 0x2222_2222_2222_2222),
            Block128::from(s.wrapping_add(2) ^ 0x3333_3333_3333_3333),
            Block128::from(s.wrapping_add(3) ^ 0x4444_4444_4444_4444),
        ]
    }

    #[test]
    fn hleaf_trace_matches_primitives_hash_leaf() {
        use noid_poseidon2b::primitives::hash_leaf;
        let fields = mk_fields4(0x1EAF_5EED);
        let native = hash_leaf(&fields);

        let cols = build_hleaf_trace(fields);
        let out_fields = extract_hleaf_output(&cols);
        let mut out_bytes = [0u8; 32];
        out_bytes[..16].copy_from_slice(&out_fields[0].to_bytes());
        out_bytes[16..].copy_from_slice(&out_fields[1].to_bytes());
        assert_eq!(out_bytes, native);
    }

    #[test]
    fn hleaf_matches_hash_input_leaf_vector() {
        use noid_poseidon2b::primitives::{hash_input_leaf, Address};
        let slot = 42u32;
        let value = 1_234_567u64;
        let mut owner_bytes = [0u8; 32];
        owner_bytes.iter_mut().enumerate().for_each(|(i, b)| *b = i as u8);
        let owner = Address(owner_bytes);
        let [owner_hi, owner_lo] = owner.as_fields();

        let fields = [
            Block128::from(slot as u128),
            Block128::from(value as u128),
            owner_hi,
            owner_lo,
        ];
        let cols = build_hleaf_trace(fields);
        let out_fields = extract_hleaf_output(&cols);
        let mut out_bytes = [0u8; 32];
        out_bytes[..16].copy_from_slice(&out_fields[0].to_bytes());
        out_bytes[16..].copy_from_slice(&out_fields[1].to_bytes());

        let native = hash_input_leaf(slot, value, &owner);
        assert_eq!(out_bytes, native);
    }

    #[test]
    fn hleaf_air_accepts_honest_trace() {
        let air = HLeafAir::new();
        let trace = air.build_trace(mk_fields4(0xC0FFEE));
        assert!(air.check(&trace));
    }

    #[test]
    fn hleaf_air_rejects_perm_a_sout_tamper() {
        let air = HLeafAir::new();
        let mut cols = build_hleaf_trace(mk_fields4(1));
        cols[HLEAF_LAYOUT_A.sout + 2][1] = cols[HLEAF_LAYOUT_A.sout + 2][1] + Block128::ONE;
        let trace = Trace::new(cols);
        assert!(!air.check(&trace));
    }

    #[test]
    fn hleaf_air_rejects_perm_b_mds_tamper() {
        let air = HLeafAir::new();
        let mut cols = build_hleaf_trace(mk_fields4(2));
        cols[HLEAF_LAYOUT_B.s + 1][3] = cols[HLEAF_LAYOUT_B.s + 1][3] + Block128::ONE;
        let trace = Trace::new(cols);
        assert!(!air.check(&trace));
    }

    #[test]
    fn hleaf_air_rejects_perm_c_partial_sin_kill() {
        let air = HLeafAir::new();
        let mut cols = build_hleaf_trace(mk_fields4(3));
        cols[HLEAF_LAYOUT_C.sin + 2][5] = Block128::ONE;
        let trace = Trace::new(cols);
        assert!(!air.check(&trace));
    }

    #[test]
    fn hleaf_air_rejects_perm_c_rc_tamper_on_full_row() {
        let air = HLeafAir::new();
        let mut cols = build_hleaf_trace(mk_fields4(4));
        // Row 1 is a full round (first F_ROUNDS/2 = 4 rows are full),
        // so lane 1's `is_full`-gated RC binding fires.
        cols[HLEAF_LAYOUT_C.rc + 1][1] = cols[HLEAF_LAYOUT_C.rc + 1][1] + Block128::ONE;
        let trace = Trace::new(cols);
        assert!(!air.check(&trace));
    }

    #[test]
    fn hleaf_blocks_disjoint_and_sized() {
        let layouts = [HLEAF_LAYOUT_A, HLEAF_LAYOUT_B, HLEAF_LAYOUT_C];
        for i in 0..3 {
            for j in (i + 1)..3 {
                assert_ne!(layouts[i].s, layouts[j].s);
                assert_ne!(layouts[i].rc, layouts[j].rc);
            }
        }
        assert_eq!(HLEAF_N_COLS, 3 * POSEIDON_PERM_N_COLS);
    }
}
