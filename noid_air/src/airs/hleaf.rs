// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Stage 3d-0.8 — `HLeafAir`: three-permutation sponge for
//! `hash_leaf(&[f0, f1, f2, f3])` with all boundary ties installed
//! (pre-MDS seed pin, absorb XORs, inter-permutation carries, MDS
//! seeds, output squeeze).
//!
//! All four field inputs and the expected leaf hash are public; there
//! is no privacy invariant to preserve here (unlike `HAuthAir`).
//!
//! # Trace layout (`HLEAF_N_COLS = 106`)
//!
//! | cols     | contents                                                 |
//! |----------|----------------------------------------------------------|
//! | 0..30    | Block A permutation, rows `0..=N_ROUNDS`                 |
//! | 30..60   | Block B permutation, rows `N_ROUNDS+1..=2*N_ROUNDS+1`    |
//! | 60..90   | Block C permutation, rows `2*N_ROUNDS+2..=3*N_ROUNDS+2`  |
//! | 90..94   | `pre_s_A[0..4]` — pre-MDS seed at row 0                  |
//! | 94..98   | `pre_s_B[0..4]` — pre-MDS seed at row N_ROUNDS           |
//! | 98..102  | `pre_s_C[0..4]` — pre-MDS seed at row 2*N_ROUNDS+1       |
//! | 102      | `ind_row_0`                                              |
//! | 103      | `ind_row_N_ROUNDS`                                       |
//! | 104      | `ind_row_2N_PLUS_1`                                      |
//! | 105      | `ind_row_output`                                         |

use crate::airs::haddr::{HADDR_PAD_0, HADDR_PAD_1};
use crate::airs::poseidon_perm::{
    is_full_round, write_perm_trace_at, write_perm_trace_at_offset, PermLayout,
    POSEIDON_PERM_LOG_ROWS, POSEIDON_PERM_N_COLS, POSEIDON_PERM_N_ROWS,
};
use crate::gates::row_selector::row_indicator_programme;
use crate::gates::{
    PublicColumn, SelectorGate, WeightedLinearGate, WeightedLinearGateShifted,
};
use crate::{Air, Constraint, Trace};
use noid_core::{Block128, TowerField};
use noid_poseidon2b::native::domain::{capacity_iv, TAG_LEAF};
use noid_poseidon2b::native::permutation::{MDS_FULL, N_ROUNDS, ROUND_CONSTANTS, STATE_SIZE};

// ---------------------------------------------------------------------------
// Layout constants
// ---------------------------------------------------------------------------

pub const HLEAF_PERM_A_BASE: usize = 0;
pub const HLEAF_PERM_B_BASE: usize = POSEIDON_PERM_N_COLS;
pub const HLEAF_PERM_C_BASE: usize = 2 * POSEIDON_PERM_N_COLS;
pub const HLEAF_PRE_S_A_BASE: usize = 3 * POSEIDON_PERM_N_COLS;
pub const HLEAF_PRE_S_B_BASE: usize = HLEAF_PRE_S_A_BASE + STATE_SIZE;
pub const HLEAF_PRE_S_C_BASE: usize = HLEAF_PRE_S_B_BASE + STATE_SIZE;
pub const HLEAF_IND_ROW_0: usize = HLEAF_PRE_S_C_BASE + STATE_SIZE;
pub const HLEAF_IND_ROW_N_ROUNDS: usize = HLEAF_IND_ROW_0 + 1;
pub const HLEAF_IND_ROW_2N_PLUS_1: usize = HLEAF_IND_ROW_N_ROUNDS + 1;
pub const HLEAF_IND_ROW_OUTPUT: usize = HLEAF_IND_ROW_2N_PLUS_1 + 1;
pub const HLEAF_N_COLS: usize = HLEAF_IND_ROW_OUTPUT + 1;
pub const HLEAF_LOG_ROWS: usize = POSEIDON_PERM_LOG_ROWS;
pub const HLEAF_N_ROWS: usize = POSEIDON_PERM_N_ROWS;

pub const HLEAF_LAYOUT_A: PermLayout = PermLayout::at(HLEAF_PERM_A_BASE);
pub const HLEAF_LAYOUT_B: PermLayout = PermLayout::at(HLEAF_PERM_B_BASE);
pub const HLEAF_LAYOUT_C: PermLayout = PermLayout::at(HLEAF_PERM_C_BASE);

pub const HLEAF_B_SEED_ROW: usize = N_ROUNDS + 1;
pub const HLEAF_C_SEED_ROW: usize = 2 * N_ROUNDS + 2;
pub const HLEAF_OUTPUT_ROW: usize = 3 * N_ROUNDS + 2;

// ---------------------------------------------------------------------------
// Programme helpers
// ---------------------------------------------------------------------------

fn perm_is_full_at(row_offset: usize) -> Vec<Block128> {
    let mut out = vec![Block128::ZERO; HLEAF_N_ROWS];
    for r in 0..N_ROUNDS {
        if is_full_round(r) {
            out[row_offset + r] = Block128::ONE;
        }
    }
    out
}

fn perm_is_round_at(row_offset: usize) -> Vec<Block128> {
    let mut out = vec![Block128::ZERO; HLEAF_N_ROWS];
    for r in 0..N_ROUNDS {
        out[row_offset + r] = Block128::ONE;
    }
    out
}

fn perm_rc_at(lane: usize, row_offset: usize) -> Vec<Block128> {
    let mut out = vec![Block128::ZERO; HLEAF_N_ROWS];
    for r in 0..N_ROUNDS {
        out[row_offset + r] = Block128::from(ROUND_CONSTANTS[lane][r]);
    }
    out
}

fn emit_perm_publics_offset(layout: PermLayout, row_offset: usize) -> Vec<PublicColumn> {
    let mut out = Vec::with_capacity(STATE_SIZE + 2);
    out.push(PublicColumn::new(layout.is_full, perm_is_full_at(row_offset)));
    out.push(PublicColumn::new(layout.is_round, perm_is_round_at(row_offset)));
    for lane in 0..STATE_SIZE {
        out.push(PublicColumn::new(
            layout.rc + lane,
            perm_rc_at(lane, row_offset),
        ));
    }
    out
}

fn mds_full_row_terms(lane: usize, pre_base: usize) -> Vec<(usize, Block128)> {
    (0..STATE_SIZE)
        .map(|j| (pre_base + j, Block128::from(MDS_FULL[lane][j])))
        .collect()
}

// ---------------------------------------------------------------------------
// Trace builder
// ---------------------------------------------------------------------------

/// Build an honest witness trace for `hash_leaf(&[f0, f1, f2, f3])`
/// under `TAG_LEAF`.
pub fn build_hleaf_trace(fields: [Block128; 4]) -> Vec<Vec<Block128>> {
    let mut cols: Vec<Vec<Block128>> = (0..HLEAF_N_COLS)
        .map(|_| vec![Block128::ZERO; HLEAF_N_ROWS])
        .collect();

    let [iv_hi, iv_lo] = capacity_iv(TAG_LEAF);

    // Block A: seed [f0, f1, iv_hi, iv_lo] at row 0.
    let perm_a_input: [Block128; STATE_SIZE] = [fields[0], fields[1], iv_hi, iv_lo];
    let state_after_a = write_perm_trace_at(&mut cols, HLEAF_LAYOUT_A, perm_a_input);

    // Block B: absorb (f2, f3) into rate.
    let perm_b_input: [Block128; STATE_SIZE] = [
        state_after_a[0] + fields[2],
        state_after_a[1] + fields[3],
        state_after_a[2],
        state_after_a[3],
    ];
    let state_after_b =
        write_perm_trace_at_offset(&mut cols, HLEAF_LAYOUT_B, perm_b_input, HLEAF_B_SEED_ROW);

    // Block C: padding flush.
    let pad0 = Block128::from(HADDR_PAD_0);
    let pad1 = Block128::from(HADDR_PAD_1);
    let perm_c_input: [Block128; STATE_SIZE] = [
        state_after_b[0] + pad0,
        state_after_b[1] + pad1,
        state_after_b[2],
        state_after_b[3],
    ];
    write_perm_trace_at_offset(&mut cols, HLEAF_LAYOUT_C, perm_c_input, HLEAF_C_SEED_ROW);

    // Pre-MDS witness rows.
    for lane in 0..STATE_SIZE {
        cols[HLEAF_PRE_S_A_BASE + lane][0] = perm_a_input[lane];
        cols[HLEAF_PRE_S_B_BASE + lane][N_ROUNDS] = perm_b_input[lane];
        cols[HLEAF_PRE_S_C_BASE + lane][2 * N_ROUNDS + 1] = perm_c_input[lane];
    }

    // Row indicators.
    cols[HLEAF_IND_ROW_0][0] = Block128::ONE;
    cols[HLEAF_IND_ROW_N_ROUNDS][N_ROUNDS] = Block128::ONE;
    cols[HLEAF_IND_ROW_2N_PLUS_1][2 * N_ROUNDS + 1] = Block128::ONE;
    cols[HLEAF_IND_ROW_OUTPUT][HLEAF_OUTPUT_ROW] = Block128::ONE;

    cols
}

/// Extract `(out_hi, out_lo) = s_C[0..2]@HLEAF_OUTPUT_ROW`.
pub fn extract_hleaf_output(cols: &[Vec<Block128>]) -> [Block128; 2] {
    [
        cols[HLEAF_LAYOUT_C.s][HLEAF_OUTPUT_ROW],
        cols[HLEAF_LAYOUT_C.s + 1][HLEAF_OUTPUT_ROW],
    ]
}

// ---------------------------------------------------------------------------
// Constraint / public-column emission
// ---------------------------------------------------------------------------

/// Build the full constraint list and public-column set. Both
/// `fields` and `expected_leaf` are public.
pub fn emit_hleaf(
    fields: [Block128; 4],
    expected_leaf: [Block128; 2],
) -> (Vec<Box<dyn Constraint>>, Vec<PublicColumn>) {
    let mut constraints: Vec<Box<dyn Constraint>> = Vec::new();
    let mut public_columns: Vec<PublicColumn> = Vec::new();

    // Interior: three independent permutation blocks.
    constraints.extend(crate::airs::emit_perm_all_at(HLEAF_LAYOUT_A));
    constraints.extend(crate::airs::emit_perm_all_at(HLEAF_LAYOUT_B));
    constraints.extend(crate::airs::emit_perm_all_at(HLEAF_LAYOUT_C));

    public_columns.extend(emit_perm_publics_offset(HLEAF_LAYOUT_A, 0));
    public_columns.extend(emit_perm_publics_offset(HLEAF_LAYOUT_B, HLEAF_B_SEED_ROW));
    public_columns.extend(emit_perm_publics_offset(HLEAF_LAYOUT_C, HLEAF_C_SEED_ROW));

    public_columns.push(PublicColumn::new(
        HLEAF_IND_ROW_0,
        row_indicator_programme(0, HLEAF_N_ROWS),
    ));
    public_columns.push(PublicColumn::new(
        HLEAF_IND_ROW_N_ROUNDS,
        row_indicator_programme(N_ROUNDS, HLEAF_N_ROWS),
    ));
    public_columns.push(PublicColumn::new(
        HLEAF_IND_ROW_2N_PLUS_1,
        row_indicator_programme(2 * N_ROUNDS + 1, HLEAF_N_ROWS),
    ));
    public_columns.push(PublicColumn::new(
        HLEAF_IND_ROW_OUTPUT,
        row_indicator_programme(HLEAF_OUTPUT_ROW, HLEAF_N_ROWS),
    ));

    // Tie A-seed pin: all four pre_s_A lanes at row 0 — [f0, f1, iv_hi, iv_lo].
    let [iv_hi, iv_lo] = capacity_iv(TAG_LEAF);
    let seed_a = [fields[0], fields[1], iv_hi, iv_lo];
    for (lane, expected) in seed_a.iter().enumerate() {
        let inner: Box<dyn Constraint> = Box::new(WeightedLinearGate::new(
            vec![(HLEAF_PRE_S_A_BASE + lane, Block128::ONE)],
            *expected,
        ));
        constraints.push(Box::new(SelectorGate::new(HLEAF_IND_ROW_0, inner)));
    }

    // Tie MDS-A: s_A[lane]@0 + Σ MDS_FULL[lane][j] · pre_s_A[j]@0 == 0.
    for lane in 0..STATE_SIZE {
        let mut terms = vec![(HLEAF_LAYOUT_A.s + lane, Block128::ONE)];
        terms.extend(mds_full_row_terms(lane, HLEAF_PRE_S_A_BASE));
        let inner: Box<dyn Constraint> =
            Box::new(WeightedLinearGate::new(terms, Block128::ZERO));
        constraints.push(Box::new(SelectorGate::new(HLEAF_IND_ROW_0, inner)));
    }

    // Tie B-carry at row N_ROUNDS:
    // A.s[lane] + pre_s_B[lane] + ABSORB_B_lane == 0, ABSORB_B = [f2, f3, 0, 0].
    for lane in 0..STATE_SIZE {
        let absorb = match lane {
            0 => fields[2],
            1 => fields[3],
            _ => Block128::ZERO,
        };
        let inner: Box<dyn Constraint> = Box::new(WeightedLinearGate::new(
            vec![
                (HLEAF_LAYOUT_A.s + lane, Block128::ONE),
                (HLEAF_PRE_S_B_BASE + lane, Block128::ONE),
            ],
            absorb,
        ));
        constraints.push(Box::new(SelectorGate::new(HLEAF_IND_ROW_N_ROUNDS, inner)));
    }

    // Tie MDS-B: s_B[lane]@(N_ROUNDS+1) + Σ MDS_FULL[lane][j] · pre_s_B[j]@N_ROUNDS == 0.
    for lane in 0..STATE_SIZE {
        let inner: Box<dyn Constraint> = Box::new(WeightedLinearGateShifted::new(
            mds_full_row_terms(lane, HLEAF_PRE_S_B_BASE),
            vec![(HLEAF_LAYOUT_B.s + lane, Block128::ONE)],
            Block128::ZERO,
        ));
        constraints.push(Box::new(SelectorGate::new(HLEAF_IND_ROW_N_ROUNDS, inner)));
    }

    // Tie C-carry at row 2*N_ROUNDS+1:
    // B.s[lane] + pre_s_C[lane] + PAD_lane == 0.
    for lane in 0..STATE_SIZE {
        let pad = match lane {
            0 => Block128::from(HADDR_PAD_0),
            1 => Block128::from(HADDR_PAD_1),
            _ => Block128::ZERO,
        };
        let inner: Box<dyn Constraint> = Box::new(WeightedLinearGate::new(
            vec![
                (HLEAF_LAYOUT_B.s + lane, Block128::ONE),
                (HLEAF_PRE_S_C_BASE + lane, Block128::ONE),
            ],
            pad,
        ));
        constraints.push(Box::new(SelectorGate::new(HLEAF_IND_ROW_2N_PLUS_1, inner)));
    }

    // Tie MDS-C: s_C[lane]@(2*N_ROUNDS+2) + Σ MDS_FULL[lane][j] · pre_s_C[j]@(2*N_ROUNDS+1) == 0.
    for lane in 0..STATE_SIZE {
        let inner: Box<dyn Constraint> = Box::new(WeightedLinearGateShifted::new(
            mds_full_row_terms(lane, HLEAF_PRE_S_C_BASE),
            vec![(HLEAF_LAYOUT_C.s + lane, Block128::ONE)],
            Block128::ZERO,
        ));
        constraints.push(Box::new(SelectorGate::new(HLEAF_IND_ROW_2N_PLUS_1, inner)));
    }

    // Tie output squeeze: s_C[0..2]@HLEAF_OUTPUT_ROW == expected_leaf.
    for (lane, expected) in expected_leaf.iter().enumerate() {
        let inner: Box<dyn Constraint> = Box::new(WeightedLinearGate::new(
            vec![(HLEAF_LAYOUT_C.s + lane, Block128::ONE)],
            *expected,
        ));
        constraints.push(Box::new(SelectorGate::new(HLEAF_IND_ROW_OUTPUT, inner)));
    }

    (constraints, public_columns)
}

// ---------------------------------------------------------------------------
// HLeafAir
// ---------------------------------------------------------------------------

pub struct HLeafAir {
    constraints: Vec<Box<dyn Constraint>>,
    public_columns: Vec<PublicColumn>,
}

impl HLeafAir {
    pub fn new(fields: [Block128; 4], expected_leaf: [Block128; 2]) -> Self {
        let (constraints, public_columns) = emit_hleaf(fields, expected_leaf);
        Self {
            constraints,
            public_columns,
        }
    }

    pub fn build_trace(&self, fields: [Block128; 4]) -> Trace {
        Trace::new(build_hleaf_trace(fields))
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
    fn public_columns(&self) -> &[PublicColumn] {
        &self.public_columns
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

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

    fn expected_leaf_for(fields: [Block128; 4]) -> [Block128; 2] {
        extract_hleaf_output(&build_hleaf_trace(fields))
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
        let fields = mk_fields4(0xC0FFEE);
        let air = HLeafAir::new(fields, expected_leaf_for(fields));
        let trace = air.build_trace(fields);
        assert!(air.check(&trace));
    }

    #[test]
    fn hleaf_air_rejects_perm_a_sout_tamper() {
        let fields = mk_fields4(1);
        let air = HLeafAir::new(fields, expected_leaf_for(fields));
        let mut cols = build_hleaf_trace(fields);
        cols[HLEAF_LAYOUT_A.sout + 2][1] = cols[HLEAF_LAYOUT_A.sout + 2][1] + Block128::ONE;
        assert!(!air.check(&Trace::new(cols)));
    }

    #[test]
    fn hleaf_air_rejects_perm_b_mds_tamper() {
        let fields = mk_fields4(2);
        let air = HLeafAir::new(fields, expected_leaf_for(fields));
        let mut cols = build_hleaf_trace(fields);
        cols[HLEAF_LAYOUT_B.s + 1][HLEAF_B_SEED_ROW + 3] =
            cols[HLEAF_LAYOUT_B.s + 1][HLEAF_B_SEED_ROW + 3] + Block128::ONE;
        assert!(!air.check(&Trace::new(cols)));
    }

    #[test]
    fn hleaf_air_rejects_perm_c_rc_tamper() {
        let fields = mk_fields4(4);
        let air = HLeafAir::new(fields, expected_leaf_for(fields));
        let mut cols = build_hleaf_trace(fields);
        cols[HLEAF_LAYOUT_C.rc + 1][HLEAF_C_SEED_ROW + 1] =
            cols[HLEAF_LAYOUT_C.rc + 1][HLEAF_C_SEED_ROW + 1] + Block128::ONE;
        assert!(!air.check(&Trace::new(cols)));
    }

    #[test]
    fn hleaf_air_rejects_wrong_declared_leaf() {
        let fields = mk_fields4(0x5EED_BBBB);
        let mut wrong = expected_leaf_for(fields);
        wrong[0] = wrong[0] + Block128::ONE;
        let air = HLeafAir::new(fields, wrong);
        let trace = air.build_trace(fields);
        assert!(!air.check(&trace));
    }

    #[test]
    fn hleaf_air_rejects_output_cell_tamper() {
        let fields = mk_fields4(0x5EED_CCCC);
        let air = HLeafAir::new(fields, expected_leaf_for(fields));
        let mut cols = build_hleaf_trace(fields);
        cols[HLEAF_LAYOUT_C.s][HLEAF_OUTPUT_ROW] =
            cols[HLEAF_LAYOUT_C.s][HLEAF_OUTPUT_ROW] + Block128::ONE;
        assert!(!air.check(&Trace::new(cols)));
    }

    #[test]
    fn hleaf_air_rejects_seed_iv_pin_tamper() {
        let fields = mk_fields4(0x3333);
        let air = HLeafAir::new(fields, expected_leaf_for(fields));
        let mut cols = build_hleaf_trace(fields);
        cols[HLEAF_PRE_S_A_BASE + 2][0] = cols[HLEAF_PRE_S_A_BASE + 2][0] + Block128::ONE;
        assert!(!air.check(&Trace::new(cols)));
    }

    #[test]
    fn hleaf_air_rejects_seed_field_pin_tamper() {
        let fields = mk_fields4(0x5555);
        let air = HLeafAir::new(fields, expected_leaf_for(fields));
        let mut cols = build_hleaf_trace(fields);
        cols[HLEAF_PRE_S_A_BASE][0] = cols[HLEAF_PRE_S_A_BASE][0] + Block128::ONE;
        assert!(!air.check(&Trace::new(cols)));
    }

    #[test]
    fn hleaf_air_rejects_b_carry_tamper() {
        let fields = mk_fields4(0x7777);
        let air = HLeafAir::new(fields, expected_leaf_for(fields));
        let mut cols = build_hleaf_trace(fields);
        cols[HLEAF_PRE_S_B_BASE][N_ROUNDS] =
            cols[HLEAF_PRE_S_B_BASE][N_ROUNDS] + Block128::ONE;
        assert!(!air.check(&Trace::new(cols)));
    }

    #[test]
    fn hleaf_air_rejects_c_carry_tamper() {
        let fields = mk_fields4(0x9999);
        let air = HLeafAir::new(fields, expected_leaf_for(fields));
        let mut cols = build_hleaf_trace(fields);
        cols[HLEAF_PRE_S_C_BASE + 1][2 * N_ROUNDS + 1] =
            cols[HLEAF_PRE_S_C_BASE + 1][2 * N_ROUNDS + 1] + Block128::ONE;
        assert!(!air.check(&Trace::new(cols)));
    }

    #[test]
    fn hleaf_air_rejects_mds_b_output_tamper() {
        let fields = mk_fields4(0xBBBB);
        let air = HLeafAir::new(fields, expected_leaf_for(fields));
        let mut cols = build_hleaf_trace(fields);
        cols[HLEAF_LAYOUT_B.s][HLEAF_B_SEED_ROW] =
            cols[HLEAF_LAYOUT_B.s][HLEAF_B_SEED_ROW] + Block128::ONE;
        assert!(!air.check(&Trace::new(cols)));
    }

    #[test]
    fn hleaf_air_rejects_mds_c_output_tamper() {
        let fields = mk_fields4(0xDDDD);
        let air = HLeafAir::new(fields, expected_leaf_for(fields));
        let mut cols = build_hleaf_trace(fields);
        cols[HLEAF_LAYOUT_C.s][HLEAF_C_SEED_ROW] =
            cols[HLEAF_LAYOUT_C.s][HLEAF_C_SEED_ROW] + Block128::ONE;
        assert!(!air.check(&Trace::new(cols)));
    }

    #[test]
    fn hleaf_air_rejects_wrong_declared_field() {
        // Air declared for `fields_declared`, trace built with `fields_true`:
        // A-seed pin mismatch rejects.
        let fields_true = mk_fields4(0x3434);
        let fields_declared = mk_fields4(0x5656);
        let leaf = expected_leaf_for(fields_true);
        let air = HLeafAir::new(fields_declared, leaf);
        let trace = air.build_trace(fields_true);
        assert!(!air.check(&trace));
    }

    #[test]
    fn hleaf_air_rejects_tampered_indicator_row_0() {
        let fields = mk_fields4(0x1313);
        let air = HLeafAir::new(fields, expected_leaf_for(fields));
        let mut cols = build_hleaf_trace(fields);
        cols[HLEAF_IND_ROW_0][0] = Block128::ZERO;
        cols[HLEAF_IND_ROW_0][5] = Block128::ONE;
        assert!(!air.check(&Trace::new(cols)));
    }

    #[test]
    fn hleaf_air_rejects_tampered_indicator_output() {
        let fields = mk_fields4(0x3535);
        let air = HLeafAir::new(fields, expected_leaf_for(fields));
        let mut cols = build_hleaf_trace(fields);
        cols[HLEAF_IND_ROW_OUTPUT][HLEAF_OUTPUT_ROW] = Block128::ZERO;
        cols[HLEAF_IND_ROW_OUTPUT][HLEAF_OUTPUT_ROW - 1] = Block128::ONE;
        assert!(!air.check(&Trace::new(cols)));
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
        assert_eq!(
            HLEAF_N_COLS,
            3 * POSEIDON_PERM_N_COLS + 3 * STATE_SIZE + 4
        );
        assert!(HLEAF_OUTPUT_ROW < HLEAF_N_ROWS);
    }
}
