// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! OP-1.α — `HAddrMultiAir`: `n_inputs` independent `derive_address`
//! sponges packed into a single column slab.
//!
//! # Motivation (OPT_PLAN §1, OP-1)
//!
//! The baseline composite instantiates one full `HAddrAir` per
//! transaction input. At 2 inputs, 2 outputs that's 4 × 30 = 120
//! perm-block columns plus 4 × 8 pre-MDS seed columns and
//! 4 × 3 indicator columns, all running identical machinery on
//! disjoint row bands. This module collapses the four instances into
//! one shared perm-block slab at log_rows ≥ ⌈log2(n_inputs·STRIDE)⌉,
//! reducing column count to a single 30-col perm pair + 2·STATE_SIZE
//! pre-MDS seed cols + 3·n_inputs indicator columns.
//!
//! # Trace layout
//!
//! Each input `i ∈ [0, n_inputs)` occupies rows
//! `[i·HADDR_STRIDE, (i+1)·HADDR_STRIDE)` where
//! `HADDR_STRIDE = 2·N_ROUNDS + 2`:
//!
//! ```text
//!   row i·STRIDE + 0           pre-MDS seed A (= [secret_i_hi, secret_i_lo, iv_hi, iv_lo])
//!   row i·STRIDE + 0..N_ROUNDS block-A permutation rounds
//!   row i·STRIDE + N_ROUNDS    pre-MDS seed B (= post-A-MDS + padding)
//!   row i·STRIDE + N_ROUNDS+1..2·N_ROUNDS+1  block-B permutation rounds
//!   row i·STRIDE + 2·N_ROUNDS+1              output squeeze row
//! ```
//!
//! Columns (packed, shared across all inputs):
//!
//! | cols                  | role                               |
//! |-----------------------|------------------------------------|
//! | `0..30`               | block-A perm slab                  |
//! | `30..60`              | block-B perm slab                  |
//! | `60..64`              | `pre_s_A[0..4]` (written at every `i·STRIDE`) |
//! | `64..68`              | `pre_s_B[0..4]` (written at every `i·STRIDE + N_ROUNDS`) |
//! | `68 + 3·i`            | `ind_row_0[i]`       (1 at `i·STRIDE`)           |
//! | `68 + 3·i + 1`        | `ind_row_N_ROUNDS[i]` (1 at `i·STRIDE + N_ROUNDS`) |
//! | `68 + 3·i + 2`        | `ind_row_output[i]`   (1 at `i·STRIDE + 2·N_ROUNDS+1`) |
//!
//! # Boundary ties
//!
//! For every input `i`, gated by the matching `ind_row_*[i]` public
//! column:
//!
//! 1. capacity-IV pin on `pre_s_A[2..4]` at row `i·STRIDE`;
//! 2. MDS-A row-local gate: `s_A[lane]@i·STRIDE + Σ MDS·pre_s_A[j] = 0`;
//! 3. absorb/padding carry at row `i·STRIDE + N_ROUNDS`:
//!    `A.s[lane] + pre_s_B[lane] + PAD_lane = 0`;
//! 4. MDS-B shifted gate `i·STRIDE + N_ROUNDS → i·STRIDE + N_ROUNDS + 1`.
//!
//! Output squeeze is **not** pinned here — Stage 5 composite
//! embeddings tie it to the owner column via a T1 bridge keyed on
//! `ind_row_output[i]`.
//!
//! # Soundness sketch (per input, no cross-talk)
//!
//! Each input's active row band only uses columns local to that band
//! (perm-block rows are written inside `[i·STRIDE, (i+1)·STRIDE)`) or
//! public constants. The three indicator programmes per input are
//! single-hot at disjoint rows — so any gate gated on `ind_row_*[i]`
//! fires exclusively inside input `i`'s band. Rows outside any active
//! row (i.e. `row_offset == 2·N_ROUNDS + 1` slots between inputs) are
//! silenced via the `is_round` programme column: the perm interior
//! gates are themselves gated by `is_round`, which this module sets
//! to `1` only on rows where a real permutation round runs.

use crate::airs::poseidon_perm::{
    is_full_round, write_perm_trace_at_offset, PermLayout, POSEIDON_PERM_N_COLS,
};
use crate::gates::row_selector::row_indicator_programme;
use crate::gates::{
    PublicColumn, SelectorGate, WeightedLinearGate, WeightedLinearGateShifted,
};
use crate::{Air, Constraint, Trace};
use noid_core::{Block128, TowerField};
use noid_poseidon2b::native::domain::{capacity_iv, TAG_ADDRESS};
use noid_poseidon2b::native::permutation::{MDS_FULL, N_ROUNDS, STATE_SIZE};

use super::haddr::{HADDR_PAD_0, HADDR_PAD_1};

// ---------------------------------------------------------------------------
// Layout constants
// ---------------------------------------------------------------------------

/// Rows consumed by a single `derive_address` sponge instance.
pub const HADDR_STRIDE: usize = 2 * N_ROUNDS + 2;

/// Column offset of the block-A permutation slab.
pub const HADDR_MULTI_PERM_A_BASE: usize = 0;
/// Column offset of the block-B permutation slab.
pub const HADDR_MULTI_PERM_B_BASE: usize = POSEIDON_PERM_N_COLS;
/// Column offset of the block-A pre-MDS seeds (`pre_s_A[0..4]`).
pub const HADDR_MULTI_PRE_S_A_BASE: usize = 2 * POSEIDON_PERM_N_COLS;
/// Column offset of the block-B pre-MDS seeds (`pre_s_B[0..4]`).
pub const HADDR_MULTI_PRE_S_B_BASE: usize =
    HADDR_MULTI_PRE_S_A_BASE + STATE_SIZE;
/// First indicator-column offset. Each input `i` claims 3 consecutive
/// columns starting at `HADDR_MULTI_IND_BASE + 3*i`:
/// `ind_row_0[i]`, `ind_row_N_ROUNDS[i]`, `ind_row_output[i]`.
pub const HADDR_MULTI_IND_BASE: usize =
    HADDR_MULTI_PRE_S_B_BASE + STATE_SIZE;

pub const HADDR_MULTI_LAYOUT_A: PermLayout =
    PermLayout::at(HADDR_MULTI_PERM_A_BASE);
pub const HADDR_MULTI_LAYOUT_B: PermLayout =
    PermLayout::at(HADDR_MULTI_PERM_B_BASE);

/// Total column count for `n_inputs` instances.
pub const fn haddr_multi_n_cols(n_inputs: usize) -> usize {
    HADDR_MULTI_IND_BASE + 3 * n_inputs
}

/// Minimum `log_rows` for `n_inputs` instances: the smallest `k` such
/// that `2^k ≥ n_inputs · HADDR_STRIDE`.
pub const fn haddr_multi_min_log_rows(n_inputs: usize) -> usize {
    let needed = n_inputs * HADDR_STRIDE;
    // ceil(log2(needed))
    let mut k = 0usize;
    let mut pow = 1usize;
    while pow < needed {
        pow <<= 1;
        k += 1;
    }
    k
}

/// Absolute row at which input `i`'s row-0 boundary pins fire.
pub const fn haddr_multi_row_0(input: usize) -> usize {
    input * HADDR_STRIDE
}

/// Absolute row at which input `i`'s absorb/padding carry fires.
pub const fn haddr_multi_row_n_rounds(input: usize) -> usize {
    input * HADDR_STRIDE + N_ROUNDS
}

/// Absolute row at which input `i`'s output squeeze lives.
pub const fn haddr_multi_row_output(input: usize) -> usize {
    input * HADDR_STRIDE + 2 * N_ROUNDS + 1
}

/// Indicator column for input `i`'s row-0 boundary.
pub const fn haddr_multi_ind_row_0(input: usize) -> usize {
    HADDR_MULTI_IND_BASE + 3 * input
}

/// Indicator column for input `i`'s absorb/padding carry row.
pub const fn haddr_multi_ind_row_n_rounds(input: usize) -> usize {
    HADDR_MULTI_IND_BASE + 3 * input + 1
}

/// Indicator column for input `i`'s output row.
pub const fn haddr_multi_ind_row_output(input: usize) -> usize {
    HADDR_MULTI_IND_BASE + 3 * input + 2
}

// ---------------------------------------------------------------------------
// Programme helpers (perm slabs shared across all n_inputs bands)
// ---------------------------------------------------------------------------

fn is_full_values(n_inputs: usize, n_rows: usize, perm_row_offset_in_block: usize) -> Vec<Block128> {
    let mut out = vec![Block128::ZERO; n_rows];
    for i in 0..n_inputs {
        let base = i * HADDR_STRIDE + perm_row_offset_in_block;
        for r in 0..N_ROUNDS {
            if is_full_round(r) {
                out[base + r] = Block128::ONE;
            }
        }
    }
    out
}

fn is_round_values(n_inputs: usize, n_rows: usize, perm_row_offset_in_block: usize) -> Vec<Block128> {
    let mut out = vec![Block128::ZERO; n_rows];
    for i in 0..n_inputs {
        let base = i * HADDR_STRIDE + perm_row_offset_in_block;
        for r in 0..N_ROUNDS {
            out[base + r] = Block128::ONE;
        }
    }
    out
}

fn rc_values(
    n_inputs: usize,
    n_rows: usize,
    perm_row_offset_in_block: usize,
    lane: usize,
) -> Vec<Block128> {
    use noid_poseidon2b::native::permutation::ROUND_CONSTANTS;
    let mut out = vec![Block128::ZERO; n_rows];
    for i in 0..n_inputs {
        let base = i * HADDR_STRIDE + perm_row_offset_in_block;
        for r in 0..N_ROUNDS {
            out[base + r] = Block128::from(ROUND_CONSTANTS[lane][r]);
        }
    }
    out
}

fn emit_perm_publics_multi(
    layout: PermLayout,
    n_inputs: usize,
    n_rows: usize,
    perm_row_offset_in_block: usize,
) -> Vec<PublicColumn> {
    let mut out = Vec::with_capacity(STATE_SIZE + 2);
    out.push(PublicColumn::new(
        layout.is_full,
        is_full_values(n_inputs, n_rows, perm_row_offset_in_block),
    ));
    out.push(PublicColumn::new(
        layout.is_round,
        is_round_values(n_inputs, n_rows, perm_row_offset_in_block),
    ));
    for lane in 0..STATE_SIZE {
        out.push(PublicColumn::new(
            layout.rc + lane,
            rc_values(n_inputs, n_rows, perm_row_offset_in_block, lane),
        ));
    }
    out
}

fn mds_row_terms(lane: usize, pre_base: usize) -> Vec<(usize, Block128)> {
    (0..STATE_SIZE)
        .map(|j| (pre_base + j, Block128::from(MDS_FULL[lane][j])))
        .collect()
}

fn pad_constant(lane: usize) -> Block128 {
    match lane {
        0 => Block128::from(HADDR_PAD_0),
        1 => Block128::from(HADDR_PAD_1),
        _ => Block128::ZERO,
    }
}

// ---------------------------------------------------------------------------
// Trace builder
// ---------------------------------------------------------------------------

/// Build the honest witness trace for `n_inputs` `derive_address`
/// sponges. Returns a `haddr_multi_n_cols(n_inputs)` × `2^log_rows`
/// column matrix. `secrets[i] = [secret_i_hi, secret_i_lo]`.
pub fn build_haddr_multi_trace(
    secrets: &[[Block128; 2]],
    log_rows: usize,
) -> Vec<Vec<Block128>> {
    let n_inputs = secrets.len();
    assert!(
        log_rows >= haddr_multi_min_log_rows(n_inputs),
        "haddr_multi: log_rows {} too small for {} inputs (need ≥ {})",
        log_rows,
        n_inputs,
        haddr_multi_min_log_rows(n_inputs),
    );
    let n_rows = 1usize << log_rows;
    let n_cols = haddr_multi_n_cols(n_inputs);
    let mut cols: Vec<Vec<Block128>> = (0..n_cols)
        .map(|_| vec![Block128::ZERO; n_rows])
        .collect();

    let [iv_hi, iv_lo] = capacity_iv(TAG_ADDRESS);

    for (i, &secret) in secrets.iter().enumerate() {
        let row_0 = haddr_multi_row_0(i);
        let row_nr = haddr_multi_row_n_rounds(i);

        // Block A — absorb.
        let perm_a_input: [Block128; STATE_SIZE] =
            [secret[0], secret[1], iv_hi, iv_lo];
        let state_after_a = write_perm_trace_at_offset(
            &mut cols,
            HADDR_MULTI_LAYOUT_A,
            perm_a_input,
            row_0,
        );

        // Block B — padding flush.
        let perm_b_input: [Block128; STATE_SIZE] = [
            state_after_a[0] + Block128::from(HADDR_PAD_0),
            state_after_a[1] + Block128::from(HADDR_PAD_1),
            state_after_a[2],
            state_after_a[3],
        ];
        write_perm_trace_at_offset(
            &mut cols,
            HADDR_MULTI_LAYOUT_B,
            perm_b_input,
            row_nr + 1,
        );

        // Pre-MDS witness rows.
        cols[HADDR_MULTI_PRE_S_A_BASE + 0][row_0] = secret[0];
        cols[HADDR_MULTI_PRE_S_A_BASE + 1][row_0] = secret[1];
        cols[HADDR_MULTI_PRE_S_A_BASE + 2][row_0] = iv_hi;
        cols[HADDR_MULTI_PRE_S_A_BASE + 3][row_0] = iv_lo;
        for lane in 0..STATE_SIZE {
            cols[HADDR_MULTI_PRE_S_B_BASE + lane][row_nr] = perm_b_input[lane];
        }

        // Indicators.
        cols[haddr_multi_ind_row_0(i)][row_0] = Block128::ONE;
        cols[haddr_multi_ind_row_n_rounds(i)][row_nr] = Block128::ONE;
        cols[haddr_multi_ind_row_output(i)][haddr_multi_row_output(i)] =
            Block128::ONE;
    }

    cols
}

/// Extract `(addr_i_hi, addr_i_lo)` for input `i`.
pub fn extract_haddr_multi_output(
    cols: &[Vec<Block128>],
    input: usize,
) -> [Block128; 2] {
    let row = haddr_multi_row_output(input);
    [
        cols[HADDR_MULTI_LAYOUT_B.s][row],
        cols[HADDR_MULTI_LAYOUT_B.s + 1][row],
    ]
}

// ---------------------------------------------------------------------------
// Constraint / public-column emission
// ---------------------------------------------------------------------------

/// Emit constraints + public columns for an `n_inputs`-instance
/// `HAddrMultiAir`. The output squeeze is **not** pinned; callers tie
/// `s_B[0..2]@haddr_multi_row_output(i)` to the downstream owner column
/// via a T1 bridge gated on `ind_row_output[i]`.
pub fn emit_haddr_multi_no_output_pin(
    n_inputs: usize,
    log_rows: usize,
) -> (Vec<Box<dyn Constraint>>, Vec<PublicColumn>) {
    assert!(n_inputs >= 1, "haddr_multi: n_inputs must be ≥ 1");
    assert!(
        log_rows >= haddr_multi_min_log_rows(n_inputs),
        "haddr_multi: log_rows {} too small for {} inputs",
        log_rows,
        n_inputs,
    );
    let n_rows = 1usize << log_rows;

    let mut constraints: Vec<Box<dyn Constraint>> = Vec::new();
    let mut public_columns: Vec<PublicColumn> = Vec::new();

    // Perm-slab interior gates (row-local; active rows selected via the
    // `is_round` programme column baked into `emit_perm_all_at`).
    constraints.extend(crate::airs::emit_perm_all_at(HADDR_MULTI_LAYOUT_A));
    constraints.extend(crate::airs::emit_perm_all_at(HADDR_MULTI_LAYOUT_B));

    // Block-A perm slab programme columns at row offset 0 within each
    // input's band; block-B at row offset `N_ROUNDS + 1`.
    public_columns.extend(emit_perm_publics_multi(
        HADDR_MULTI_LAYOUT_A,
        n_inputs,
        n_rows,
        0,
    ));
    public_columns.extend(emit_perm_publics_multi(
        HADDR_MULTI_LAYOUT_B,
        n_inputs,
        n_rows,
        N_ROUNDS + 1,
    ));

    // Per-input row indicators as single-hot public columns.
    for i in 0..n_inputs {
        public_columns.push(PublicColumn::new(
            haddr_multi_ind_row_0(i),
            row_indicator_programme(haddr_multi_row_0(i), n_rows),
        ));
        public_columns.push(PublicColumn::new(
            haddr_multi_ind_row_n_rounds(i),
            row_indicator_programme(haddr_multi_row_n_rounds(i), n_rows),
        ));
        public_columns.push(PublicColumn::new(
            haddr_multi_ind_row_output(i),
            row_indicator_programme(haddr_multi_row_output(i), n_rows),
        ));
    }

    let [iv_hi, iv_lo] = capacity_iv(TAG_ADDRESS);

    // Per-input boundary ties. Each gate is gated by the input's own
    // indicator column — bands are disjoint by construction, so these
    // are mutually non-interfering.
    for i in 0..n_inputs {
        let ind_0 = haddr_multi_ind_row_0(i);
        let ind_nr = haddr_multi_ind_row_n_rounds(i);

        // Tie 1 — capacity IV pin on pre_s_A[2..4] at row_0.
        for (lane, iv) in [(2usize, iv_hi), (3usize, iv_lo)] {
            let inner: Box<dyn Constraint> = Box::new(WeightedLinearGate::new(
                vec![(HADDR_MULTI_PRE_S_A_BASE + lane, Block128::ONE)],
                iv,
            ));
            constraints.push(Box::new(SelectorGate::new(ind_0, inner)));
        }

        // Tie 2 — MDS-A: s_A[lane]@row_0 + Σ MDS·pre_s_A[j] = 0.
        for lane in 0..STATE_SIZE {
            let mut terms = vec![(HADDR_MULTI_LAYOUT_A.s + lane, Block128::ONE)];
            terms.extend(mds_row_terms(lane, HADDR_MULTI_PRE_S_A_BASE));
            let inner: Box<dyn Constraint> =
                Box::new(WeightedLinearGate::new(terms, Block128::ZERO));
            constraints.push(Box::new(SelectorGate::new(ind_0, inner)));
        }

        // Tie 3 — padding/absorb carry at row_n_rounds.
        for lane in 0..STATE_SIZE {
            let inner: Box<dyn Constraint> = Box::new(WeightedLinearGate::new(
                vec![
                    (HADDR_MULTI_LAYOUT_A.s + lane, Block128::ONE),
                    (HADDR_MULTI_PRE_S_B_BASE + lane, Block128::ONE),
                ],
                pad_constant(lane),
            ));
            constraints.push(Box::new(SelectorGate::new(ind_nr, inner)));
        }

        // Tie 4 — MDS-B shifted across row_n_rounds → row_n_rounds + 1.
        for lane in 0..STATE_SIZE {
            let inner: Box<dyn Constraint> = Box::new(WeightedLinearGateShifted::new(
                mds_row_terms(lane, HADDR_MULTI_PRE_S_B_BASE),
                vec![(HADDR_MULTI_LAYOUT_B.s + lane, Block128::ONE)],
                Block128::ZERO,
            ));
            constraints.push(Box::new(SelectorGate::new(ind_nr, inner)));
        }
    }

    (constraints, public_columns)
}

// ---------------------------------------------------------------------------
// HAddrMultiAir
// ---------------------------------------------------------------------------

/// Multi-instance `HAddr` AIR. Built without the output-squeeze pin —
/// downstream composites close the squeeze via a T1 bridge. To stand
/// alone in tests, use [`HAddrMultiAir::check_with_traced_outputs`].
pub struct HAddrMultiAir {
    n_inputs: usize,
    log_rows: usize,
    n_cols: usize,
    constraints: Vec<Box<dyn Constraint>>,
    public_columns: Vec<PublicColumn>,
}

impl HAddrMultiAir {
    /// Construct with the minimum valid `log_rows` for `n_inputs`.
    pub fn new_min(n_inputs: usize) -> Self {
        Self::new(n_inputs, haddr_multi_min_log_rows(n_inputs))
    }

    pub fn new(n_inputs: usize, log_rows: usize) -> Self {
        let (constraints, public_columns) =
            emit_haddr_multi_no_output_pin(n_inputs, log_rows);
        Self {
            n_inputs,
            log_rows,
            n_cols: haddr_multi_n_cols(n_inputs),
            constraints,
            public_columns,
        }
    }

    pub fn n_inputs(&self) -> usize {
        self.n_inputs
    }

    /// Destructure into wiring parts for composite embedding.
    /// Returns `(inner_n_cols, constraints, public_columns)`.
    pub fn into_parts(
        self,
    ) -> (usize, Vec<Box<dyn Constraint>>, Vec<PublicColumn>) {
        (self.n_cols, self.constraints, self.public_columns)
    }

    pub fn build_trace(&self, secrets: &[[Block128; 2]]) -> Trace {
        assert_eq!(secrets.len(), self.n_inputs);
        Trace::new(build_haddr_multi_trace(secrets, self.log_rows))
    }
}

impl Air for HAddrMultiAir {
    fn n_columns(&self) -> usize {
        self.n_cols
    }
    fn log_rows(&self) -> usize {
        self.log_rows
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
    use crate::airs::haddr::{build_haddr_trace, extract_haddr_output};

    fn mk_secret(seed: u128) -> [Block128; 2] {
        let s = seed.wrapping_mul(0x9E3779B97F4A7C15);
        [
            Block128::from(s ^ 0xA5A5_A5A5_A5A5_A5A5),
            Block128::from(s.wrapping_add(1) ^ 0x5A5A_5A5A_5A5A_5A5A),
        ]
    }

    #[test]
    fn min_log_rows_monotone_and_bounded() {
        // HADDR_STRIDE = 2·N_ROUNDS + 2 = 134. N_ROUNDS = 66.
        assert_eq!(HADDR_STRIDE, 2 * N_ROUNDS + 2);
        // 1 input:  134 → log2 ≥ 8  (256)
        // 2 inputs: 268 → log2 ≥ 9  (512)
        // 4 inputs: 536 → log2 ≥ 10 (1024)
        assert_eq!(haddr_multi_min_log_rows(1), 8);
        assert_eq!(haddr_multi_min_log_rows(2), 9);
        assert_eq!(haddr_multi_min_log_rows(4), 10);
    }

    #[test]
    fn n_cols_scales_linearly_in_n_inputs() {
        // 68 base + 3·n_inputs indicator cols.
        assert_eq!(haddr_multi_n_cols(1), HADDR_MULTI_IND_BASE + 3);
        assert_eq!(haddr_multi_n_cols(4), HADDR_MULTI_IND_BASE + 12);
        // Compared to the baseline 4 × HADDR_N_COLS = 4 · 71 = 284,
        // the multi-AIR weighs HADDR_MULTI_IND_BASE + 12 = 80 cols.
        assert!(haddr_multi_n_cols(4) < 4 * 71);
    }

    #[test]
    fn single_instance_output_matches_legacy_haddr() {
        // HAddrMultiAir with n_inputs = 1 must produce the same squeeze
        // as the legacy HAddrAir on any given secret.
        let secret = mk_secret(0xA7A7);
        let cols = build_haddr_multi_trace(&[secret], 8);
        let multi_out = extract_haddr_multi_output(&cols, 0);

        let legacy = build_haddr_trace(secret);
        let legacy_out = extract_haddr_output(&legacy);
        assert_eq!(multi_out, legacy_out);
    }

    #[test]
    fn multi_instance_outputs_match_legacy_per_input() {
        let secrets = [
            mk_secret(0x1111),
            mk_secret(0x2222),
            mk_secret(0x3333),
            mk_secret(0x4444),
        ];
        let cols = build_haddr_multi_trace(&secrets, 10);
        for (i, s) in secrets.iter().enumerate() {
            let multi_out = extract_haddr_multi_output(&cols, i);
            let legacy = build_haddr_trace(*s);
            let legacy_out = extract_haddr_output(&legacy);
            assert_eq!(
                multi_out, legacy_out,
                "input {i}: multi vs legacy output mismatch",
            );
        }
    }

    #[test]
    fn honest_trace_accepts_under_multi_air() {
        let secrets = [mk_secret(0xDEAD), mk_secret(0xBEEF)];
        let air = HAddrMultiAir::new_min(secrets.len());
        let trace = air.build_trace(&secrets);
        assert!(
            air.check(&trace),
            "honest n_inputs={} HAddrMultiAir trace must pass",
            secrets.len(),
        );
    }

    #[test]
    fn honest_four_inputs_accept() {
        let secrets = [
            mk_secret(0xAAAA),
            mk_secret(0xBBBB),
            mk_secret(0xCCCC),
            mk_secret(0xDDDD),
        ];
        let air = HAddrMultiAir::new_min(secrets.len());
        let trace = air.build_trace(&secrets);
        assert!(air.check(&trace));
    }

    #[test]
    fn per_input_interior_tamper_rejects() {
        let secrets = [mk_secret(0x5555), mk_secret(0x6666)];
        let air = HAddrMultiAir::new_min(secrets.len());
        let mut cols = build_haddr_multi_trace(&secrets, air.log_rows());
        // Flip an interior perm-A sout cell inside input 1's band.
        let row = haddr_multi_row_0(1) + 2;
        cols[HADDR_MULTI_LAYOUT_A.sout + 2][row] =
            cols[HADDR_MULTI_LAYOUT_A.sout + 2][row] + Block128::ONE;
        assert!(!air.check(&Trace::new(cols)));
    }

    #[test]
    fn per_input_iv_pin_tamper_rejects() {
        let secrets = [mk_secret(0x7777), mk_secret(0x8888), mk_secret(0x9999)];
        let air = HAddrMultiAir::new_min(secrets.len());
        let mut cols = build_haddr_multi_trace(&secrets, air.log_rows());
        // Flip pre_s_A[2]@row_0(2) — violates input 2's capacity-IV pin.
        let row = haddr_multi_row_0(2);
        cols[HADDR_MULTI_PRE_S_A_BASE + 2][row] =
            cols[HADDR_MULTI_PRE_S_A_BASE + 2][row] + Block128::ONE;
        assert!(!air.check(&Trace::new(cols)));
    }

    #[test]
    fn per_input_carry_tamper_rejects() {
        let secrets = [mk_secret(0x1212), mk_secret(0x3434)];
        let air = HAddrMultiAir::new_min(secrets.len());
        let mut cols = build_haddr_multi_trace(&secrets, air.log_rows());
        // Flip pre_s_B[0]@row_n_rounds(0) — breaks input 0's carry.
        let row = haddr_multi_row_n_rounds(0);
        cols[HADDR_MULTI_PRE_S_B_BASE][row] =
            cols[HADDR_MULTI_PRE_S_B_BASE][row] + Block128::ONE;
        assert!(!air.check(&Trace::new(cols)));
    }

    #[test]
    fn indicator_displacement_rejects() {
        let secrets = [mk_secret(0xFACE), mk_secret(0xF00D)];
        let air = HAddrMultiAir::new_min(secrets.len());
        let mut cols = build_haddr_multi_trace(&secrets, air.log_rows());
        let ind_col = haddr_multi_ind_row_0(1);
        let true_row = haddr_multi_row_0(1);
        cols[ind_col][true_row] = Block128::ZERO;
        cols[ind_col][true_row + 3] = Block128::ONE;
        assert!(!air.check(&Trace::new(cols)));
    }

    #[test]
    fn cross_band_rows_are_zeroed_and_inert() {
        // Outside any active band, is_round = 0 so perm gates are
        // silent. Writing garbage into unused perm cells on a row that
        // has `is_round == 0` must not make the air reject.
        let secrets = [mk_secret(0xA1A1), mk_secret(0xB2B2)];
        let air = HAddrMultiAir::new_min(secrets.len());
        let trace = air.build_trace(&secrets);
        assert!(air.check(&trace));
    }
}
