// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Stage 3d-0.7 — `HAuthAir`: three-permutation sponge for
//! `hash_auth_tag(spend_secret, tx_body_hash)` with all boundary ties
//! installed (capacity IV, absorb XORs, inter-permutation carries, MDS
//! seeds, output squeeze).
//!
//! # Privacy invariant
//!
//! `spend_secret` is a **private witness** — only the prover (wallet)
//! sees it. `tx_body_hash` and `expected_tag` are public inputs. No
//! secret-derived value lands in a `PublicColumn` or any verifier-
//! reconstructable pin. Soundness closes through the output-squeeze
//! tie: any tampered secret produces a different `(tag_hi, tag_lo)` and
//! is caught there (Poseidon2b collision resistance).
//!
//! # Trace layout (`HAUTH_N_COLS = 106`)
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
//! | 105      | `ind_row_output`  (`1` at row 3*N_ROUNDS+2)              |

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
use noid_poseidon2b::native::domain::{capacity_iv, TAG_AUTHTAG};
use noid_poseidon2b::native::permutation::{MDS_FULL, N_ROUNDS, ROUND_CONSTANTS, STATE_SIZE};

// ---------------------------------------------------------------------------
// Layout constants
// ---------------------------------------------------------------------------

pub const HAUTH_PERM_A_BASE: usize = 0;
pub const HAUTH_PERM_B_BASE: usize = POSEIDON_PERM_N_COLS;
pub const HAUTH_PERM_C_BASE: usize = 2 * POSEIDON_PERM_N_COLS;
pub const HAUTH_PRE_S_A_BASE: usize = 3 * POSEIDON_PERM_N_COLS;
pub const HAUTH_PRE_S_B_BASE: usize = HAUTH_PRE_S_A_BASE + STATE_SIZE;
pub const HAUTH_PRE_S_C_BASE: usize = HAUTH_PRE_S_B_BASE + STATE_SIZE;
pub const HAUTH_IND_ROW_0: usize = HAUTH_PRE_S_C_BASE + STATE_SIZE;
pub const HAUTH_IND_ROW_N_ROUNDS: usize = HAUTH_IND_ROW_0 + 1;
pub const HAUTH_IND_ROW_2N_PLUS_1: usize = HAUTH_IND_ROW_N_ROUNDS + 1;
pub const HAUTH_IND_ROW_OUTPUT: usize = HAUTH_IND_ROW_2N_PLUS_1 + 1;
pub const HAUTH_N_COLS: usize = HAUTH_IND_ROW_OUTPUT + 1;
pub const HAUTH_LOG_ROWS: usize = POSEIDON_PERM_LOG_ROWS;
pub const HAUTH_N_ROWS: usize = POSEIDON_PERM_N_ROWS;

pub const HAUTH_LAYOUT_A: PermLayout = PermLayout::at(HAUTH_PERM_A_BASE);
pub const HAUTH_LAYOUT_B: PermLayout = PermLayout::at(HAUTH_PERM_B_BASE);
pub const HAUTH_LAYOUT_C: PermLayout = PermLayout::at(HAUTH_PERM_C_BASE);

pub const HAUTH_B_SEED_ROW: usize = N_ROUNDS + 1;
pub const HAUTH_C_SEED_ROW: usize = 2 * N_ROUNDS + 2;
pub const HAUTH_OUTPUT_ROW: usize = 3 * N_ROUNDS + 2;

// ---------------------------------------------------------------------------
// Programme helpers
// ---------------------------------------------------------------------------

fn perm_is_full_at(row_offset: usize) -> Vec<Block128> {
    let mut out = vec![Block128::ZERO; HAUTH_N_ROWS];
    for r in 0..N_ROUNDS {
        if is_full_round(r) {
            out[row_offset + r] = Block128::ONE;
        }
    }
    out
}

fn perm_is_round_at(row_offset: usize) -> Vec<Block128> {
    let mut out = vec![Block128::ZERO; HAUTH_N_ROWS];
    for r in 0..N_ROUNDS {
        out[row_offset + r] = Block128::ONE;
    }
    out
}

fn perm_rc_at(lane: usize, row_offset: usize) -> Vec<Block128> {
    let mut out = vec![Block128::ZERO; HAUTH_N_ROWS];
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

/// Build an honest witness trace for
/// `hash_auth_tag(spend_secret, tx_body_hash)`.
pub fn build_hauth_trace(
    secret: [Block128; 2],
    tx_body: [Block128; 2],
) -> Vec<Vec<Block128>> {
    let mut cols: Vec<Vec<Block128>> = (0..HAUTH_N_COLS)
        .map(|_| vec![Block128::ZERO; HAUTH_N_ROWS])
        .collect();

    let [iv_hi, iv_lo] = capacity_iv(TAG_AUTHTAG);

    // Block A: seed [secret_hi, secret_lo, iv_hi, iv_lo] at row 0.
    let perm_a_input: [Block128; STATE_SIZE] = [secret[0], secret[1], iv_hi, iv_lo];
    let state_after_a = write_perm_trace_at(&mut cols, HAUTH_LAYOUT_A, perm_a_input);

    // Block B: absorb tx_body into rate, perm rows N_ROUNDS+1..=2*N_ROUNDS+1.
    let perm_b_input: [Block128; STATE_SIZE] = [
        state_after_a[0] + tx_body[0],
        state_after_a[1] + tx_body[1],
        state_after_a[2],
        state_after_a[3],
    ];
    let state_after_b =
        write_perm_trace_at_offset(&mut cols, HAUTH_LAYOUT_B, perm_b_input, HAUTH_B_SEED_ROW);

    // Block C: padding flush, perm rows 2*N_ROUNDS+2..=3*N_ROUNDS+2.
    let pad0 = Block128::from(HADDR_PAD_0);
    let pad1 = Block128::from(HADDR_PAD_1);
    let perm_c_input: [Block128; STATE_SIZE] = [
        state_after_b[0] + pad0,
        state_after_b[1] + pad1,
        state_after_b[2],
        state_after_b[3],
    ];
    write_perm_trace_at_offset(&mut cols, HAUTH_LAYOUT_C, perm_c_input, HAUTH_C_SEED_ROW);

    // Pre-MDS witness rows.
    for lane in 0..STATE_SIZE {
        cols[HAUTH_PRE_S_A_BASE + lane][0] = perm_a_input[lane];
        cols[HAUTH_PRE_S_B_BASE + lane][N_ROUNDS] = perm_b_input[lane];
        cols[HAUTH_PRE_S_C_BASE + lane][2 * N_ROUNDS + 1] = perm_c_input[lane];
    }

    // Row indicators.
    cols[HAUTH_IND_ROW_0][0] = Block128::ONE;
    cols[HAUTH_IND_ROW_N_ROUNDS][N_ROUNDS] = Block128::ONE;
    cols[HAUTH_IND_ROW_2N_PLUS_1][2 * N_ROUNDS + 1] = Block128::ONE;
    cols[HAUTH_IND_ROW_OUTPUT][HAUTH_OUTPUT_ROW] = Block128::ONE;

    cols
}

/// Extract `(tag_hi, tag_lo) = s_C[0..2]@HAUTH_OUTPUT_ROW`.
pub fn extract_hauth_output(cols: &[Vec<Block128>]) -> [Block128; 2] {
    [
        cols[HAUTH_LAYOUT_C.s][HAUTH_OUTPUT_ROW],
        cols[HAUTH_LAYOUT_C.s + 1][HAUTH_OUTPUT_ROW],
    ]
}

// ---------------------------------------------------------------------------
// Constraint / public-column emission
// ---------------------------------------------------------------------------

/// Build the full constraint list and public-column set. `tx_body` and
/// `expected_tag` are public; the secret stays in the witness.
pub fn emit_hauth(
    tx_body: [Block128; 2],
    expected_tag: [Block128; 2],
) -> (Vec<Box<dyn Constraint>>, Vec<PublicColumn>) {
    let mut constraints: Vec<Box<dyn Constraint>> = Vec::new();
    let mut public_columns: Vec<PublicColumn> = Vec::new();

    // Interior: three independent permutation blocks.
    constraints.extend(crate::airs::emit_perm_all_at(HAUTH_LAYOUT_A));
    constraints.extend(crate::airs::emit_perm_all_at(HAUTH_LAYOUT_B));
    constraints.extend(crate::airs::emit_perm_all_at(HAUTH_LAYOUT_C));

    public_columns.extend(emit_perm_publics_offset(HAUTH_LAYOUT_A, 0));
    public_columns.extend(emit_perm_publics_offset(HAUTH_LAYOUT_B, HAUTH_B_SEED_ROW));
    public_columns.extend(emit_perm_publics_offset(HAUTH_LAYOUT_C, HAUTH_C_SEED_ROW));

    public_columns.push(PublicColumn::new(
        HAUTH_IND_ROW_0,
        row_indicator_programme(0, HAUTH_N_ROWS),
    ));
    public_columns.push(PublicColumn::new(
        HAUTH_IND_ROW_N_ROUNDS,
        row_indicator_programme(N_ROUNDS, HAUTH_N_ROWS),
    ));
    public_columns.push(PublicColumn::new(
        HAUTH_IND_ROW_2N_PLUS_1,
        row_indicator_programme(2 * N_ROUNDS + 1, HAUTH_N_ROWS),
    ));
    public_columns.push(PublicColumn::new(
        HAUTH_IND_ROW_OUTPUT,
        row_indicator_programme(HAUTH_OUTPUT_ROW, HAUTH_N_ROWS),
    ));

    // Tie 1 — capacity IV pin on pre_s_A[2..4] at row 0.
    let [iv_hi, iv_lo] = capacity_iv(TAG_AUTHTAG);
    for (lane, iv) in [(2usize, iv_hi), (3usize, iv_lo)] {
        let inner: Box<dyn Constraint> = Box::new(WeightedLinearGate::new(
            vec![(HAUTH_PRE_S_A_BASE + lane, Block128::ONE)],
            iv,
        ));
        constraints.push(Box::new(SelectorGate::new(HAUTH_IND_ROW_0, inner)));
    }

    // Tie MDS-A: s_A[lane]@0 + Σ MDS_FULL[lane][j] · pre_s_A[j]@0 == 0.
    for lane in 0..STATE_SIZE {
        let mut terms = vec![(HAUTH_LAYOUT_A.s + lane, Block128::ONE)];
        terms.extend(mds_full_row_terms(lane, HAUTH_PRE_S_A_BASE));
        let inner: Box<dyn Constraint> =
            Box::new(WeightedLinearGate::new(terms, Block128::ZERO));
        constraints.push(Box::new(SelectorGate::new(HAUTH_IND_ROW_0, inner)));
    }

    // Tie B-carry at row N_ROUNDS:
    // A.s[lane] + pre_s_B[lane] + ABSORB_B_lane == 0, ABSORB_B = [tx_body_hi, tx_body_lo, 0, 0].
    for lane in 0..STATE_SIZE {
        let absorb = match lane {
            0 => tx_body[0],
            1 => tx_body[1],
            _ => Block128::ZERO,
        };
        let inner: Box<dyn Constraint> = Box::new(WeightedLinearGate::new(
            vec![
                (HAUTH_LAYOUT_A.s + lane, Block128::ONE),
                (HAUTH_PRE_S_B_BASE + lane, Block128::ONE),
            ],
            absorb,
        ));
        constraints.push(Box::new(SelectorGate::new(HAUTH_IND_ROW_N_ROUNDS, inner)));
    }

    // Tie MDS-B: s_B[lane]@(N_ROUNDS+1) + Σ MDS_FULL[lane][j] · pre_s_B[j]@N_ROUNDS == 0.
    for lane in 0..STATE_SIZE {
        let inner: Box<dyn Constraint> = Box::new(WeightedLinearGateShifted::new(
            mds_full_row_terms(lane, HAUTH_PRE_S_B_BASE),
            vec![(HAUTH_LAYOUT_B.s + lane, Block128::ONE)],
            Block128::ZERO,
        ));
        constraints.push(Box::new(SelectorGate::new(HAUTH_IND_ROW_N_ROUNDS, inner)));
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
                (HAUTH_LAYOUT_B.s + lane, Block128::ONE),
                (HAUTH_PRE_S_C_BASE + lane, Block128::ONE),
            ],
            pad,
        ));
        constraints.push(Box::new(SelectorGate::new(HAUTH_IND_ROW_2N_PLUS_1, inner)));
    }

    // Tie MDS-C: s_C[lane]@(2*N_ROUNDS+2) + Σ MDS_FULL[lane][j] · pre_s_C[j]@(2*N_ROUNDS+1) == 0.
    for lane in 0..STATE_SIZE {
        let inner: Box<dyn Constraint> = Box::new(WeightedLinearGateShifted::new(
            mds_full_row_terms(lane, HAUTH_PRE_S_C_BASE),
            vec![(HAUTH_LAYOUT_C.s + lane, Block128::ONE)],
            Block128::ZERO,
        ));
        constraints.push(Box::new(SelectorGate::new(HAUTH_IND_ROW_2N_PLUS_1, inner)));
    }

    // Tie output squeeze: s_C[0..2]@HAUTH_OUTPUT_ROW == expected_tag.
    for (lane, expected) in expected_tag.iter().enumerate() {
        let inner: Box<dyn Constraint> = Box::new(WeightedLinearGate::new(
            vec![(HAUTH_LAYOUT_C.s + lane, Block128::ONE)],
            *expected,
        ));
        constraints.push(Box::new(SelectorGate::new(HAUTH_IND_ROW_OUTPUT, inner)));
    }

    (constraints, public_columns)
}

// ---------------------------------------------------------------------------
// HAuthAir
// ---------------------------------------------------------------------------

pub struct HAuthAir {
    constraints: Vec<Box<dyn Constraint>>,
    public_columns: Vec<PublicColumn>,
}

impl HAuthAir {
    pub fn new(tx_body: [Block128; 2], expected_tag: [Block128; 2]) -> Self {
        let (constraints, public_columns) = emit_hauth(tx_body, expected_tag);
        Self {
            constraints,
            public_columns,
        }
    }

    pub fn build_trace(
        &self,
        secret: [Block128; 2],
        tx_body: [Block128; 2],
    ) -> Trace {
        Trace::new(build_hauth_trace(secret, tx_body))
    }
}

impl Air for HAuthAir {
    fn n_columns(&self) -> usize {
        HAUTH_N_COLS
    }
    fn log_rows(&self) -> usize {
        HAUTH_LOG_ROWS
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

    fn mk_fields(seed: u128) -> [Block128; 2] {
        let s = seed.wrapping_mul(0x9E3779B97F4A7C15);
        [
            Block128::from(s ^ 0xA5A5_A5A5_A5A5_A5A5),
            Block128::from(s.wrapping_add(1) ^ 0x5A5A_5A5A_5A5A_5A5A),
        ]
    }

    fn expected_tag_for(secret: [Block128; 2], tx_body: [Block128; 2]) -> [Block128; 2] {
        extract_hauth_output(&build_hauth_trace(secret, tx_body))
    }

    #[test]
    fn hauth_trace_matches_primitives_hash_auth_tag() {
        use noid_poseidon2b::primitives::{hash_auth_tag, SpendSecret, TxBodyHash};
        let secret_fields = mk_fields(0xA07_5EED);
        let txbody_fields = mk_fields(0x5C0FF_B0D);

        let mut sb = [0u8; 32];
        sb[..16].copy_from_slice(&secret_fields[0].to_bytes());
        sb[16..].copy_from_slice(&secret_fields[1].to_bytes());
        let mut tb = [0u8; 32];
        tb[..16].copy_from_slice(&txbody_fields[0].to_bytes());
        tb[16..].copy_from_slice(&txbody_fields[1].to_bytes());

        let native = hash_auth_tag(&SpendSecret(sb), &TxBodyHash(tb));

        let cols = build_hauth_trace(secret_fields, txbody_fields);
        let out_fields = extract_hauth_output(&cols);
        let mut out_bytes = [0u8; 32];
        out_bytes[..16].copy_from_slice(&out_fields[0].to_bytes());
        out_bytes[16..].copy_from_slice(&out_fields[1].to_bytes());
        assert_eq!(out_bytes, native.0);
    }

    #[test]
    fn hauth_air_accepts_honest_trace() {
        let secret = mk_fields(0xCAFE);
        let tx_body = mk_fields(0xBABE);
        let air = HAuthAir::new(tx_body, expected_tag_for(secret, tx_body));
        let trace = air.build_trace(secret, tx_body);
        assert!(air.check(&trace));
    }

    #[test]
    fn hauth_air_rejects_perm_a_sout_tamper() {
        let secret = mk_fields(1);
        let tx_body = mk_fields(2);
        let air = HAuthAir::new(tx_body, expected_tag_for(secret, tx_body));
        let mut cols = build_hauth_trace(secret, tx_body);
        cols[HAUTH_LAYOUT_A.sout + 2][1] = cols[HAUTH_LAYOUT_A.sout + 2][1] + Block128::ONE;
        assert!(!air.check(&Trace::new(cols)));
    }

    #[test]
    fn hauth_air_rejects_perm_b_mds_tamper() {
        let secret = mk_fields(3);
        let tx_body = mk_fields(4);
        let air = HAuthAir::new(tx_body, expected_tag_for(secret, tx_body));
        let mut cols = build_hauth_trace(secret, tx_body);
        cols[HAUTH_LAYOUT_B.s + 1][HAUTH_B_SEED_ROW + 3] =
            cols[HAUTH_LAYOUT_B.s + 1][HAUTH_B_SEED_ROW + 3] + Block128::ONE;
        assert!(!air.check(&Trace::new(cols)));
    }

    #[test]
    fn hauth_air_rejects_perm_c_rc_tamper() {
        let secret = mk_fields(5);
        let tx_body = mk_fields(6);
        let air = HAuthAir::new(tx_body, expected_tag_for(secret, tx_body));
        let mut cols = build_hauth_trace(secret, tx_body);
        cols[HAUTH_LAYOUT_C.rc + 1][HAUTH_C_SEED_ROW + 1] =
            cols[HAUTH_LAYOUT_C.rc + 1][HAUTH_C_SEED_ROW + 1] + Block128::ONE;
        assert!(!air.check(&Trace::new(cols)));
    }

    #[test]
    fn hauth_air_rejects_wrong_declared_tag() {
        let secret = mk_fields(0xC0DE);
        let tx_body = mk_fields(0xBEEF);
        let mut wrong = expected_tag_for(secret, tx_body);
        wrong[0] = wrong[0] + Block128::ONE;
        let air = HAuthAir::new(tx_body, wrong);
        let trace = air.build_trace(secret, tx_body);
        assert!(!air.check(&trace));
    }

    #[test]
    fn hauth_air_rejects_output_cell_tamper() {
        let secret = mk_fields(0x1111);
        let tx_body = mk_fields(0x2222);
        let air = HAuthAir::new(tx_body, expected_tag_for(secret, tx_body));
        let mut cols = build_hauth_trace(secret, tx_body);
        cols[HAUTH_LAYOUT_C.s][HAUTH_OUTPUT_ROW] =
            cols[HAUTH_LAYOUT_C.s][HAUTH_OUTPUT_ROW] + Block128::ONE;
        assert!(!air.check(&Trace::new(cols)));
    }

    #[test]
    fn hauth_air_rejects_iv_pin_tamper() {
        let secret = mk_fields(0x3333);
        let tx_body = mk_fields(0x4444);
        let air = HAuthAir::new(tx_body, expected_tag_for(secret, tx_body));
        let mut cols = build_hauth_trace(secret, tx_body);
        cols[HAUTH_PRE_S_A_BASE + 2][0] = cols[HAUTH_PRE_S_A_BASE + 2][0] + Block128::ONE;
        assert!(!air.check(&Trace::new(cols)));
    }

    #[test]
    fn hauth_air_rejects_secret_pre_mds_tamper() {
        let secret = mk_fields(0x5555);
        let tx_body = mk_fields(0x6666);
        let air = HAuthAir::new(tx_body, expected_tag_for(secret, tx_body));
        let mut cols = build_hauth_trace(secret, tx_body);
        cols[HAUTH_PRE_S_A_BASE][0] = cols[HAUTH_PRE_S_A_BASE][0] + Block128::ONE;
        assert!(!air.check(&Trace::new(cols)));
    }

    #[test]
    fn hauth_air_rejects_b_carry_tamper() {
        let secret = mk_fields(0x7777);
        let tx_body = mk_fields(0x8888);
        let air = HAuthAir::new(tx_body, expected_tag_for(secret, tx_body));
        let mut cols = build_hauth_trace(secret, tx_body);
        cols[HAUTH_PRE_S_B_BASE][N_ROUNDS] =
            cols[HAUTH_PRE_S_B_BASE][N_ROUNDS] + Block128::ONE;
        assert!(!air.check(&Trace::new(cols)));
    }

    #[test]
    fn hauth_air_rejects_c_carry_tamper() {
        let secret = mk_fields(0x9999);
        let tx_body = mk_fields(0xAAAA);
        let air = HAuthAir::new(tx_body, expected_tag_for(secret, tx_body));
        let mut cols = build_hauth_trace(secret, tx_body);
        cols[HAUTH_PRE_S_C_BASE + 1][2 * N_ROUNDS + 1] =
            cols[HAUTH_PRE_S_C_BASE + 1][2 * N_ROUNDS + 1] + Block128::ONE;
        assert!(!air.check(&Trace::new(cols)));
    }

    #[test]
    fn hauth_air_rejects_mds_b_output_tamper() {
        let secret = mk_fields(0xBBBB);
        let tx_body = mk_fields(0xCCCC);
        let air = HAuthAir::new(tx_body, expected_tag_for(secret, tx_body));
        let mut cols = build_hauth_trace(secret, tx_body);
        cols[HAUTH_LAYOUT_B.s][HAUTH_B_SEED_ROW] =
            cols[HAUTH_LAYOUT_B.s][HAUTH_B_SEED_ROW] + Block128::ONE;
        assert!(!air.check(&Trace::new(cols)));
    }

    #[test]
    fn hauth_air_rejects_mds_c_output_tamper() {
        let secret = mk_fields(0xDDDD);
        let tx_body = mk_fields(0xEEEE);
        let air = HAuthAir::new(tx_body, expected_tag_for(secret, tx_body));
        let mut cols = build_hauth_trace(secret, tx_body);
        cols[HAUTH_LAYOUT_C.s][HAUTH_C_SEED_ROW] =
            cols[HAUTH_LAYOUT_C.s][HAUTH_C_SEED_ROW] + Block128::ONE;
        assert!(!air.check(&Trace::new(cols)));
    }

    #[test]
    fn hauth_air_rejects_wrong_declared_tx_body() {
        // Air declared for tx_body_declared, trace built with tx_body_true:
        // B-carry absorb constant mismatch rejects.
        let secret = mk_fields(0x1212);
        let tx_body_true = mk_fields(0x3434);
        let tx_body_declared = mk_fields(0x5656);
        let tag = expected_tag_for(secret, tx_body_true);
        let air = HAuthAir::new(tx_body_declared, tag);
        let trace = air.build_trace(secret, tx_body_true);
        assert!(!air.check(&trace));
    }

    #[test]
    fn hauth_air_rejects_tampered_indicator_row_0() {
        let secret = mk_fields(0x1313);
        let tx_body = mk_fields(0x2424);
        let air = HAuthAir::new(tx_body, expected_tag_for(secret, tx_body));
        let mut cols = build_hauth_trace(secret, tx_body);
        cols[HAUTH_IND_ROW_0][0] = Block128::ZERO;
        cols[HAUTH_IND_ROW_0][5] = Block128::ONE;
        assert!(!air.check(&Trace::new(cols)));
    }

    #[test]
    fn hauth_air_rejects_tampered_indicator_output() {
        let secret = mk_fields(0x3535);
        let tx_body = mk_fields(0x4646);
        let air = HAuthAir::new(tx_body, expected_tag_for(secret, tx_body));
        let mut cols = build_hauth_trace(secret, tx_body);
        cols[HAUTH_IND_ROW_OUTPUT][HAUTH_OUTPUT_ROW] = Block128::ZERO;
        cols[HAUTH_IND_ROW_OUTPUT][HAUTH_OUTPUT_ROW - 1] = Block128::ONE;
        assert!(!air.check(&Trace::new(cols)));
    }

    #[test]
    fn hauth_blocks_disjoint_and_sized() {
        let layouts = [HAUTH_LAYOUT_A, HAUTH_LAYOUT_B, HAUTH_LAYOUT_C];
        for i in 0..3 {
            for j in (i + 1)..3 {
                assert_ne!(layouts[i].s, layouts[j].s);
                assert_ne!(layouts[i].rc, layouts[j].rc);
            }
        }
        assert_eq!(
            HAUTH_N_COLS,
            3 * POSEIDON_PERM_N_COLS + 3 * STATE_SIZE + 4
        );
        assert!(HAUTH_OUTPUT_ROW < HAUTH_N_ROWS);
    }
}
