// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Stage 3d-0.6b — `HAddrAir`: two-permutation sponge for
//! `derive_address(secret)` with all four boundary ties installed
//! (capacity IV, absorb XOR, inter-permutation carry, output squeeze).
//!
//! # Privacy invariant
//!
//! `SpendSecret` is a **private witness** — known only to the prover
//! (the wallet). The verifier sees only the commitment to the trace
//! columns plus the public inputs (prev_state_root, new_state_root,
//! tx_body_hash, fee). No secret-derived value ever lands in a
//! `PublicColumn` or any verifier-reconstructable pin.
//!
//! # Trace layout
//!
//! `HADDR_N_COLS = 71`, `HADDR_N_ROWS = 2^POSEIDON_PERM_LOG_ROWS = 256`.
//!
//! | cols   | contents                                                  |
//! |--------|-----------------------------------------------------------|
//! | 0..30  | Block A permutation, rows `0..=N_ROUNDS`                  |
//! | 30..60 | Block B permutation, rows `N_ROUNDS+1..=2*N_ROUNDS+1`     |
//! | 60..64 | `pre_s_A[0..4]` — pre-MDS seed for block A at row 0 only  |
//! | 64..68 | `pre_s_B[0..4]` — pre-MDS seed for block B at row N_ROUNDS|
//! | 68     | `ind_row_0`       — `1` at row 0, else 0                  |
//! | 69     | `ind_row_N_ROUNDS`— `1` at row N_ROUNDS, else 0           |
//! | 70     | `ind_row_output`  — `1` at row 2*N_ROUNDS+1, else 0       |
//!
//! Row 0 of `pre_s_A` carries `[secret_hi, secret_lo, IV_hi, IV_lo]`.
//! Lanes 2 and 3 (the IV lanes) are pinned to the public domain-
//! separation constants via `emit_public_cell`; lanes 0 and 1 (the
//! secret) are pure witness — no public pin.
//!
//! Row `N_ROUNDS` of `pre_s_B` carries
//! `[A.s[0]@N_ROUNDS + PAD_0, A.s[1]@N_ROUNDS + PAD_1,
//!   A.s[2]@N_ROUNDS, A.s[3]@N_ROUNDS]` — the padding-flushed state
//! that seeds block B's permutation.
//!
//! # Boundary ties
//!
//! 1. **Capacity IV (public)** — `pre_s_A[2]@0 == IV_hi`,
//!    `pre_s_A[3]@0 == IV_lo`. Both pinned via `emit_public_cell`.
//! 2. **Absorb XOR (witness)** — no public pin. Secret lanes
//!    `pre_s_A[0..2]@0` are witness cells. Their value is constrained
//!    only through the MDS gate into `s_A[..]@0`, the block-A interior
//!    gates, the inter-permutation carry (tie 3), the MDS-B gate, the
//!    block-B interior gates, and the output squeeze (tie 4). A
//!    prover that tampers the secret produces a mismatched
//!    `(addr_hi, addr_lo)` and is caught by tie 4.
//! 3. **MDS-A (row 0)** — `s_A[lane]@0 == Σ MDS_FULL[lane][j] ·
//!    pre_s_A[j]@0` for every lane, gated by `ind_row_0`.
//! 4. **Inter-permutation carry (row N_ROUNDS)** —
//!    `A.s[lane]@N_ROUNDS + pre_s_B[lane]@N_ROUNDS + PAD_lane == 0`
//!    for every lane, gated by `ind_row_N_ROUNDS`.
//!    `PAD_lane ∈ {PAD_0, PAD_1, 0, 0}`.
//! 5. **MDS-B (row N_ROUNDS → N_ROUNDS+1)** —
//!    `s_B[lane]@(N_ROUNDS+1) == Σ MDS_FULL[lane][j] ·
//!    pre_s_B[j]@N_ROUNDS` via `WeightedLinearGateShifted`, gated by
//!    `ind_row_N_ROUNDS`.
//! 6. **Output squeeze (public)** — `s_B[0]@(2*N_ROUNDS+1) ==
//!    addr_hi`, `s_B[1]@(2*N_ROUNDS+1) == addr_lo`. Pinned via
//!    `emit_public_cell`.

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
use noid_poseidon2b::native::domain::{capacity_iv, TAG_ADDRESS};
use noid_poseidon2b::native::permutation::{
    MDS_FULL, N_ROUNDS, ROUND_CONSTANTS, STATE_SIZE,
};

// ---------------------------------------------------------------------------
// Layout constants
// ---------------------------------------------------------------------------

/// Column offset of the block-A permutation.
pub const HADDR_PERM_A_BASE: usize = 0;
/// Column offset of the block-B permutation.
pub const HADDR_PERM_B_BASE: usize = POSEIDON_PERM_N_COLS;
/// Column offset of the block-A pre-MDS seed (`pre_s_A[0..4]`).
pub const HADDR_PRE_S_A_BASE: usize = 2 * POSEIDON_PERM_N_COLS;
/// Column offset of the block-B pre-MDS seed (`pre_s_B[0..4]`).
pub const HADDR_PRE_S_B_BASE: usize = HADDR_PRE_S_A_BASE + STATE_SIZE;
/// Indicator column: `1` at row 0, `0` elsewhere.
pub const HADDR_IND_ROW_0: usize = HADDR_PRE_S_B_BASE + STATE_SIZE;
/// Indicator column: `1` at row `N_ROUNDS`, `0` elsewhere.
pub const HADDR_IND_ROW_N_ROUNDS: usize = HADDR_IND_ROW_0 + 1;
/// Indicator column: `1` at row `2*N_ROUNDS+1`, `0` elsewhere.
pub const HADDR_IND_ROW_OUTPUT: usize = HADDR_IND_ROW_N_ROUNDS + 1;
/// Total column count.
pub const HADDR_N_COLS: usize = HADDR_IND_ROW_OUTPUT + 1;
/// Trace row count.
pub const HADDR_LOG_ROWS: usize = POSEIDON_PERM_LOG_ROWS;
pub const HADDR_N_ROWS: usize = POSEIDON_PERM_N_ROWS;

/// Fixed layouts for the two permutation blocks.
pub const HADDR_LAYOUT_A: PermLayout = PermLayout::at(HADDR_PERM_A_BASE);
pub const HADDR_LAYOUT_B: PermLayout = PermLayout::at(HADDR_PERM_B_BASE);

/// Row at which block B's post-MDS state `s[lane]@row` lives
/// (block B's row-0 in local coordinates).
pub const HADDR_B_SEED_ROW: usize = N_ROUNDS + 1;
/// Row at which block B's permutation output lives.
pub const HADDR_OUTPUT_ROW: usize = 2 * N_ROUNDS + 1;

/// Padding constants from the sponge's `fill_padding` routine after a
/// single `absorb_pair(secret_hi, secret_lo)` with no further updates:
/// `0x80` at byte 0 and `0x01` at byte 31 of the 32-byte rate buffer.
pub const HADDR_PAD_0: u128 = 0x80;
pub const HADDR_PAD_1: u128 = 0x01u128 << 120;

// ---------------------------------------------------------------------------
// Programme-column helpers for the two permutation blocks
// ---------------------------------------------------------------------------

fn haddr_is_full_values(row_offset: usize) -> Vec<Block128> {
    let mut out = vec![Block128::ZERO; HADDR_N_ROWS];
    for r in 0..N_ROUNDS {
        if is_full_round(r) {
            out[row_offset + r] = Block128::ONE;
        }
    }
    out
}

fn haddr_is_round_values(row_offset: usize) -> Vec<Block128> {
    let mut out = vec![Block128::ZERO; HADDR_N_ROWS];
    for r in 0..N_ROUNDS {
        out[row_offset + r] = Block128::ONE;
    }
    out
}

fn haddr_rc_values(lane: usize, row_offset: usize) -> Vec<Block128> {
    let mut out = vec![Block128::ZERO; HADDR_N_ROWS];
    for r in 0..N_ROUNDS {
        out[row_offset + r] = Block128::from(ROUND_CONSTANTS[lane][r]);
    }
    out
}

fn emit_perm_publics_offset(layout: PermLayout, row_offset: usize) -> Vec<PublicColumn> {
    let mut out = Vec::with_capacity(STATE_SIZE + 2);
    out.push(PublicColumn::new(
        layout.is_full,
        haddr_is_full_values(row_offset),
    ));
    out.push(PublicColumn::new(
        layout.is_round,
        haddr_is_round_values(row_offset),
    ));
    for lane in 0..STATE_SIZE {
        out.push(PublicColumn::new(
            layout.rc + lane,
            haddr_rc_values(lane, row_offset),
        ));
    }
    out
}

// ---------------------------------------------------------------------------
// Trace builder
// ---------------------------------------------------------------------------

/// Build an honest witness trace for `derive_address(secret)`.
///
/// `secret = [secret_hi, secret_lo]` matches `SpendSecret::as_fields()`.
/// Returns a (`HADDR_N_COLS`) × `HADDR_N_ROWS` column matrix.
pub fn build_haddr_trace(secret: [Block128; 2]) -> Vec<Vec<Block128>> {
    let mut cols: Vec<Vec<Block128>> = (0..HADDR_N_COLS)
        .map(|_| vec![Block128::ZERO; HADDR_N_ROWS])
        .collect();

    let [iv_hi, iv_lo] = capacity_iv(TAG_ADDRESS);

    // Block A — absorb. Pre-MDS seed = [secret_hi, secret_lo, IV_hi, IV_lo].
    let perm_a_input: [Block128; STATE_SIZE] = [secret[0], secret[1], iv_hi, iv_lo];
    let state_after_a = write_perm_trace_at(&mut cols, HADDR_LAYOUT_A, perm_a_input);

    // Block B — padding flush. Pre-MDS seed at row N_ROUNDS, permutation
    // at rows N_ROUNDS+1..=2*N_ROUNDS+1.
    let pad0 = Block128::from(HADDR_PAD_0);
    let pad1 = Block128::from(HADDR_PAD_1);
    let perm_b_input: [Block128; STATE_SIZE] = [
        state_after_a[0] + pad0,
        state_after_a[1] + pad1,
        state_after_a[2],
        state_after_a[3],
    ];
    write_perm_trace_at_offset(&mut cols, HADDR_LAYOUT_B, perm_b_input, HADDR_B_SEED_ROW);

    // Pre-MDS witness rows.
    cols[HADDR_PRE_S_A_BASE + 0][0] = secret[0];
    cols[HADDR_PRE_S_A_BASE + 1][0] = secret[1];
    cols[HADDR_PRE_S_A_BASE + 2][0] = iv_hi;
    cols[HADDR_PRE_S_A_BASE + 3][0] = iv_lo;
    for lane in 0..STATE_SIZE {
        cols[HADDR_PRE_S_B_BASE + lane][N_ROUNDS] = perm_b_input[lane];
    }

    // Row indicators.
    cols[HADDR_IND_ROW_0][0] = Block128::ONE;
    cols[HADDR_IND_ROW_N_ROUNDS][N_ROUNDS] = Block128::ONE;
    cols[HADDR_IND_ROW_OUTPUT][HADDR_OUTPUT_ROW] = Block128::ONE;

    cols
}

/// Extract `(addr_hi, addr_lo) = s_B[0..2]@HADDR_OUTPUT_ROW`.
pub fn extract_haddr_output(cols: &[Vec<Block128>]) -> [Block128; 2] {
    [
        cols[HADDR_LAYOUT_B.s][HADDR_OUTPUT_ROW],
        cols[HADDR_LAYOUT_B.s + 1][HADDR_OUTPUT_ROW],
    ]
}

// ---------------------------------------------------------------------------
// Constraint / public-column emission
// ---------------------------------------------------------------------------

fn mds_full_row_terms(
    lane: usize,
    pre_s_base: usize,
) -> Vec<(usize, Block128)> {
    (0..STATE_SIZE)
        .map(|j| (pre_s_base + j, Block128::from(MDS_FULL[lane][j])))
        .collect()
}

fn pad_constant(lane: usize) -> Block128 {
    match lane {
        0 => Block128::from(HADDR_PAD_0),
        1 => Block128::from(HADDR_PAD_1),
        _ => Block128::ZERO,
    }
}

/// Build the full `HAddrAir` constraint list and public-column set.
///
/// `expected_addr = [addr_hi, addr_lo]` is the publicly-declared address
/// that the sponge must produce. Everything else — the secret, the
/// intermediate states — stays in the witness. Returns
/// `(constraints, public_columns)`.
pub fn emit_haddr(
    expected_addr: [Block128; 2],
) -> (Vec<Box<dyn Constraint>>, Vec<PublicColumn>) {
    let mut constraints: Vec<Box<dyn Constraint>> = Vec::new();
    let mut public_columns: Vec<PublicColumn> = Vec::new();

    // Interior gates: two independent permutation blocks.
    constraints.extend(crate::airs::emit_perm_all_at(HADDR_LAYOUT_A));
    constraints.extend(crate::airs::emit_perm_all_at(HADDR_LAYOUT_B));

    // Programme columns for the two permutation blocks.
    public_columns.extend(emit_perm_publics_offset(HADDR_LAYOUT_A, 0));
    public_columns.extend(emit_perm_publics_offset(HADDR_LAYOUT_B, HADDR_B_SEED_ROW));

    // Row indicator programmes (shared across multiple gates each).
    public_columns.push(PublicColumn::new(
        HADDR_IND_ROW_0,
        row_indicator_programme(0, HADDR_N_ROWS),
    ));
    public_columns.push(PublicColumn::new(
        HADDR_IND_ROW_N_ROUNDS,
        row_indicator_programme(N_ROUNDS, HADDR_N_ROWS),
    ));
    public_columns.push(PublicColumn::new(
        HADDR_IND_ROW_OUTPUT,
        row_indicator_programme(HADDR_OUTPUT_ROW, HADDR_N_ROWS),
    ));

    // Tie 1 — capacity IV pin on pre_s_A[2..4] at row 0. The indicator
    // column is already declared above; `emit_public_cell` would
    // re-declare it, so we bypass it and build the selector directly.
    let [iv_hi, iv_lo] = capacity_iv(TAG_ADDRESS);
    for (lane, iv) in [(2usize, iv_hi), (3usize, iv_lo)] {
        let inner: Box<dyn Constraint> = Box::new(WeightedLinearGate::new(
            vec![(HADDR_PRE_S_A_BASE + lane, Block128::ONE)],
            iv,
        ));
        constraints.push(Box::new(SelectorGate::new(HADDR_IND_ROW_0, inner)));
    }

    // Tie 3a — MDS-A: s_A[lane]@0 + Σ MDS_FULL[lane][j] · pre_s_A[j]@0 == 0.
    // Row-local gate gated by ind_row_0.
    for lane in 0..STATE_SIZE {
        let mut terms = vec![(HADDR_LAYOUT_A.s + lane, Block128::ONE)];
        terms.extend(mds_full_row_terms(lane, HADDR_PRE_S_A_BASE));
        let inner: Box<dyn Constraint> =
            Box::new(WeightedLinearGate::new(terms, Block128::ZERO));
        constraints.push(Box::new(SelectorGate::new(HADDR_IND_ROW_0, inner)));
    }

    // Tie 3b — inter-permutation carry at row N_ROUNDS:
    // A.s[lane]@N_ROUNDS + pre_s_B[lane]@N_ROUNDS + PAD_lane == 0.
    for lane in 0..STATE_SIZE {
        let inner: Box<dyn Constraint> = Box::new(WeightedLinearGate::new(
            vec![
                (HADDR_LAYOUT_A.s + lane, Block128::ONE),
                (HADDR_PRE_S_B_BASE + lane, Block128::ONE),
            ],
            pad_constant(lane),
        ));
        constraints.push(Box::new(SelectorGate::new(
            HADDR_IND_ROW_N_ROUNDS,
            inner,
        )));
    }

    // Tie 3c — MDS-B across rows N_ROUNDS → N_ROUNDS+1:
    // s_B[lane]@(N_ROUNDS+1) + Σ MDS_FULL[lane][j] · pre_s_B[j]@N_ROUNDS == 0.
    for lane in 0..STATE_SIZE {
        let inner: Box<dyn Constraint> = Box::new(WeightedLinearGateShifted::new(
            mds_full_row_terms(lane, HADDR_PRE_S_B_BASE),
            vec![(HADDR_LAYOUT_B.s + lane, Block128::ONE)],
            Block128::ZERO,
        ));
        constraints.push(Box::new(SelectorGate::new(
            HADDR_IND_ROW_N_ROUNDS,
            inner,
        )));
    }

    // Tie 4 — output squeeze at HADDR_OUTPUT_ROW. Pin s_B[0..2] to the
    // declared address. Indicator already declared above, so bypass
    // `emit_public_cell` and wire SelectorGate directly.
    for (lane, expected) in expected_addr.iter().enumerate() {
        let inner: Box<dyn Constraint> = Box::new(WeightedLinearGate::new(
            vec![(HADDR_LAYOUT_B.s + lane, Block128::ONE)],
            *expected,
        ));
        constraints.push(Box::new(SelectorGate::new(HADDR_IND_ROW_OUTPUT, inner)));
    }

    (constraints, public_columns)
}

// ---------------------------------------------------------------------------
// HAddrAir
// ---------------------------------------------------------------------------

/// `HAddrAir` — Poseidon2b two-permutation sponge for `derive_address`,
/// with all four boundary ties installed. The constructor receives the
/// public `expected_addr` that the sponge must produce; the private
/// `secret` is supplied to [`HAddrAir::build_trace`] and never leaves
/// the witness.
pub struct HAddrAir {
    constraints: Vec<Box<dyn Constraint>>,
    public_columns: Vec<PublicColumn>,
}

impl HAddrAir {
    pub fn new(expected_addr: [Block128; 2]) -> Self {
        let (constraints, public_columns) = emit_haddr(expected_addr);
        Self {
            constraints,
            public_columns,
        }
    }

    pub fn build_trace(&self, secret: [Block128; 2]) -> Trace {
        Trace::new(build_haddr_trace(secret))
    }
}

impl Air for HAddrAir {
    fn n_columns(&self) -> usize {
        HADDR_N_COLS
    }
    fn log_rows(&self) -> usize {
        HADDR_LOG_ROWS
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
    use noid_poseidon2b::native::compression::Poseidon2bSponge;

    fn mk_secret(seed: u128) -> [Block128; 2] {
        let s = seed.wrapping_mul(0x9E3779B97F4A7C15);
        [
            Block128::from(s ^ 0xA5A5_A5A5_A5A5_A5A5),
            Block128::from(s.wrapping_add(1) ^ 0x5A5A_5A5A_5A5A_5A5A),
        ]
    }

    fn native_derive_address(secret: [Block128; 2]) -> [u8; 32] {
        let mut s = Poseidon2bSponge::with_iv(capacity_iv(TAG_ADDRESS));
        s.absorb_pair(secret[0], secret[1]);
        s.finalize()
    }

    fn expected_addr_for(secret: [Block128; 2]) -> [Block128; 2] {
        let cols = build_haddr_trace(secret);
        extract_haddr_output(&cols)
    }

    // -----------------------------------------------------------------
    // Trace vs native reference
    // -----------------------------------------------------------------

    #[test]
    fn haddr_trace_matches_native_derive_address() {
        let secret = mk_secret(0xDECAF_CAFE_BABE);
        let cols = build_haddr_trace(secret);
        let out_fields = extract_haddr_output(&cols);
        let mut out_bytes = [0u8; 32];
        out_bytes[..16].copy_from_slice(&out_fields[0].to_bytes());
        out_bytes[16..].copy_from_slice(&out_fields[1].to_bytes());
        assert_eq!(out_bytes, native_derive_address(secret));
    }

    #[test]
    fn haddr_trace_matches_primitives_derive_address() {
        use noid_poseidon2b::primitives::{derive_address, SpendSecret};
        let secret_fields = mk_secret(0x1234_5678_9ABC);
        let mut bytes = [0u8; 32];
        bytes[..16].copy_from_slice(&secret_fields[0].to_bytes());
        bytes[16..].copy_from_slice(&secret_fields[1].to_bytes());
        let native = derive_address(&SpendSecret(bytes));
        let cols = build_haddr_trace(secret_fields);
        let out_fields = extract_haddr_output(&cols);
        let mut out_bytes = [0u8; 32];
        out_bytes[..16].copy_from_slice(&out_fields[0].to_bytes());
        out_bytes[16..].copy_from_slice(&out_fields[1].to_bytes());
        assert_eq!(out_bytes, native.0);
    }

    // -----------------------------------------------------------------
    // Honest accept
    // -----------------------------------------------------------------

    #[test]
    fn haddr_air_accepts_honest_trace() {
        let secret = mk_secret(0xBEEF);
        let air = HAddrAir::new(expected_addr_for(secret));
        let trace = air.build_trace(secret);
        assert!(air.check(&trace));
    }

    // -----------------------------------------------------------------
    // Interior-gate tamper negatives
    // -----------------------------------------------------------------

    #[test]
    fn haddr_air_rejects_perm_a_sout_tamper() {
        let secret = mk_secret(0xABCD);
        let air = HAddrAir::new(expected_addr_for(secret));
        let mut cols = build_haddr_trace(secret);
        cols[HADDR_LAYOUT_A.sout + 2][1] = cols[HADDR_LAYOUT_A.sout + 2][1] + Block128::ONE;
        assert!(!air.check(&Trace::new(cols)));
    }

    #[test]
    fn haddr_air_rejects_perm_b_rc_tamper() {
        let secret = mk_secret(0xFADE);
        let air = HAddrAir::new(expected_addr_for(secret));
        let mut cols = build_haddr_trace(secret);
        // Block B rc lives at rows N_ROUNDS+1..2*N_ROUNDS+1; pick a full-round row.
        cols[HADDR_LAYOUT_B.rc][HADDR_B_SEED_ROW + 1] =
            cols[HADDR_LAYOUT_B.rc][HADDR_B_SEED_ROW + 1] + Block128::ONE;
        assert!(!air.check(&Trace::new(cols)));
    }

    #[test]
    fn haddr_air_rejects_perm_b_partial_row_sin_kill() {
        let secret = mk_secret(0xC0FFEE);
        let air = HAddrAir::new(expected_addr_for(secret));
        let mut cols = build_haddr_trace(secret);
        // Partial-round inside block B: `sin[1]` must be zero.
        cols[HADDR_LAYOUT_B.sin + 1][HADDR_B_SEED_ROW + 5] = Block128::ONE;
        assert!(!air.check(&Trace::new(cols)));
    }

    #[test]
    fn haddr_air_rejects_padding_row_rc_tamper() {
        // Tamper `rc` on a row outside block B's active range — caught
        // only by the B programme-column declaration.
        let secret = mk_secret(0x5ADC0DE);
        let air = HAddrAir::new(expected_addr_for(secret));
        let mut cols = build_haddr_trace(secret);
        cols[HADDR_LAYOUT_B.rc + 2][HADDR_OUTPUT_ROW + 3] = Block128::from(0xDEAD_BEEFu128);
        assert!(!air.check(&Trace::new(cols)));
    }

    // -----------------------------------------------------------------
    // Boundary-tie negatives
    // -----------------------------------------------------------------

    #[test]
    fn haddr_air_rejects_wrong_declared_addr() {
        // Declared output does not match the honest sponge: the output-
        // squeeze tie rejects.
        let secret = mk_secret(0xC0DE);
        let mut wrong = expected_addr_for(secret);
        wrong[0] = wrong[0] + Block128::ONE;
        let air = HAddrAir::new(wrong);
        let trace = air.build_trace(secret);
        assert!(!air.check(&trace));
    }

    #[test]
    fn haddr_air_rejects_output_cell_tamper() {
        // Honest declared address, but s_B[0]@output_row flipped.
        let secret = mk_secret(0x1111);
        let air = HAddrAir::new(expected_addr_for(secret));
        let mut cols = build_haddr_trace(secret);
        cols[HADDR_LAYOUT_B.s][HADDR_OUTPUT_ROW] =
            cols[HADDR_LAYOUT_B.s][HADDR_OUTPUT_ROW] + Block128::ONE;
        assert!(!air.check(&Trace::new(cols)));
    }

    #[test]
    fn haddr_air_rejects_iv_pin_tamper() {
        // Flip pre_s_A[2]@0 — violates the capacity-IV pin.
        let secret = mk_secret(0x2222);
        let air = HAddrAir::new(expected_addr_for(secret));
        let mut cols = build_haddr_trace(secret);
        cols[HADDR_PRE_S_A_BASE + 2][0] = cols[HADDR_PRE_S_A_BASE + 2][0] + Block128::ONE;
        assert!(!air.check(&Trace::new(cols)));
    }

    #[test]
    fn haddr_air_rejects_secret_pre_mds_tamper() {
        // Flip pre_s_A[0]@0 without updating block A's s[0]@0 — the
        // MDS-A gate rejects.
        let secret = mk_secret(0x3333);
        let air = HAddrAir::new(expected_addr_for(secret));
        let mut cols = build_haddr_trace(secret);
        cols[HADDR_PRE_S_A_BASE][0] = cols[HADDR_PRE_S_A_BASE][0] + Block128::ONE;
        assert!(!air.check(&Trace::new(cols)));
    }

    #[test]
    fn haddr_air_rejects_inter_perm_carry_tamper() {
        // Flip pre_s_B[0]@N_ROUNDS — breaks the inter-permutation carry.
        let secret = mk_secret(0x4444);
        let air = HAddrAir::new(expected_addr_for(secret));
        let mut cols = build_haddr_trace(secret);
        cols[HADDR_PRE_S_B_BASE][N_ROUNDS] =
            cols[HADDR_PRE_S_B_BASE][N_ROUNDS] + Block128::ONE;
        assert!(!air.check(&Trace::new(cols)));
    }

    #[test]
    fn haddr_air_rejects_mds_b_output_tamper() {
        // Flip s_B[0]@(N_ROUNDS+1) — breaks the MDS-B shifted gate.
        let secret = mk_secret(0x5555);
        let air = HAddrAir::new(expected_addr_for(secret));
        let mut cols = build_haddr_trace(secret);
        cols[HADDR_LAYOUT_B.s][HADDR_B_SEED_ROW] =
            cols[HADDR_LAYOUT_B.s][HADDR_B_SEED_ROW] + Block128::ONE;
        assert!(!air.check(&Trace::new(cols)));
    }

    #[test]
    fn haddr_air_rejects_tampered_indicator_row_0() {
        // Move the row-0 indicator to another row — PublicColumn MLE
        // mismatch rejects.
        let secret = mk_secret(0x6666);
        let air = HAddrAir::new(expected_addr_for(secret));
        let mut cols = build_haddr_trace(secret);
        cols[HADDR_IND_ROW_0][0] = Block128::ZERO;
        cols[HADDR_IND_ROW_0][3] = Block128::ONE;
        assert!(!air.check(&Trace::new(cols)));
    }

    #[test]
    fn haddr_air_rejects_tampered_indicator_output() {
        let secret = mk_secret(0x7777);
        let air = HAddrAir::new(expected_addr_for(secret));
        let mut cols = build_haddr_trace(secret);
        cols[HADDR_IND_ROW_OUTPUT][HADDR_OUTPUT_ROW] = Block128::ZERO;
        cols[HADDR_IND_ROW_OUTPUT][HADDR_OUTPUT_ROW - 1] = Block128::ONE;
        assert!(!air.check(&Trace::new(cols)));
    }

    #[test]
    fn haddr_blocks_are_independent_in_column_space() {
        let a_cols = [
            HADDR_LAYOUT_A.s, HADDR_LAYOUT_A.sin, HADDR_LAYOUT_A.sout,
            HADDR_LAYOUT_A.rc, HADDR_LAYOUT_A.is_full, HADDR_LAYOUT_A.is_round,
        ];
        let b_cols = [
            HADDR_LAYOUT_B.s, HADDR_LAYOUT_B.sin, HADDR_LAYOUT_B.sout,
            HADDR_LAYOUT_B.rc, HADDR_LAYOUT_B.is_full, HADDR_LAYOUT_B.is_round,
        ];
        for a in a_cols {
            for b in b_cols {
                assert_ne!(a, b);
            }
        }
        assert_eq!(HADDR_N_COLS, 2 * POSEIDON_PERM_N_COLS + 2 * STATE_SIZE + 3);
    }
}
