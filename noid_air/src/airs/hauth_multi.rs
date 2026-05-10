// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! OP-1.β — `HAuthMultiAir`: `n_inputs` independent
//! `hash_auth_tag(secret_i, tx_body_hash)` sponges packed into a single
//! column slab.
//!
//! # Motivation (OPT_PLAN §1, OP-1)
//!
//! The baseline composite instantiates one full `HAuthAir` per
//! transaction input (3 perm blocks × 30 cols = 90 perm cols + 12
//! pre-MDS seed cols + 4 indicator cols = 106 cols per input). At 4
//! inputs that's 4 × 106 = 424 columns. This module collapses the four
//! instances into one shared perm-slab layout at
//! `log_rows ≥ ⌈log2(n_inputs · HAUTH_STRIDE)⌉`, reducing the column
//! count to `3 · 30 + 3 · 4 + 4 · n_inputs = 102 + 4·n_inputs`.
//!
//! # Trace layout
//!
//! Each input `i ∈ [0, n_inputs)` occupies rows
//! `[i · HAUTH_STRIDE, (i+1) · HAUTH_STRIDE)` where
//! `HAUTH_STRIDE = 3 · N_ROUNDS + 3`:
//!
//! ```text
//!   row i·STRIDE + 0                pre-MDS A seed (= [sec_i_hi, sec_i_lo, iv_hi, iv_lo])
//!   row i·STRIDE + 0..N_ROUNDS      block-A permutation rounds
//!   row i·STRIDE + N_ROUNDS         pre-MDS B seed (= A.s + [txb_hi, txb_lo, 0, 0])
//!   row i·STRIDE + N_ROUNDS+1..2N+1 block-B permutation rounds
//!   row i·STRIDE + 2N+1             pre-MDS C seed (= B.s + [pad0, pad1, 0, 0])
//!   row i·STRIDE + 2N+2..3N+2       block-C permutation rounds
//!   row i·STRIDE + 3N+2             output squeeze row
//! ```
//!
//! Columns (packed, shared across all inputs):
//!
//! | cols           | role                                      |
//! |----------------|-------------------------------------------|
//! | `0..30`        | block-A perm slab                         |
//! | `30..60`       | block-B perm slab                         |
//! | `60..90`       | block-C perm slab                         |
//! | `90..94`       | `pre_s_A[0..4]` at every `i·STRIDE`       |
//! | `94..98`       | `pre_s_B[0..4]` at every `i·STRIDE+N_ROUNDS` |
//! | `98..102`      | `pre_s_C[0..4]` at every `i·STRIDE+2N+1`  |
//! | `102..104`     | `tx_body_col[0..2]` — column-constant shared absorb |
//! | `104 + 4·i`    | `ind_row_0[i]`                            |
//! | `104 + 4·i+1`  | `ind_row_N_ROUNDS[i]`                     |
//! | `104 + 4·i+2`  | `ind_row_2N_PLUS_1[i]`                    |
//! | `104 + 4·i+3`  | `ind_row_output[i]` (at `3N+2` offset)    |
//!
//! # Soundness
//!
//! Row bands `[i·STRIDE, (i+1)·STRIDE)` are disjoint and every boundary
//! gate is gated by a single-hot per-input indicator. `tx_body_hash` is
//! no longer a compile-time AIR constant: it is a pair of witness
//! columns `tx_body_col[0..2]` constrained to be constant across all
//! rows (by a shifted-XOR `col@row + col@row+1 == 0` gate on each
//! lane). Every input's B-carry reads from `tx_body_col` at its own
//! `row_N_ROUNDS`, so the same canonical value enters every input's
//! absorb — semantically matching `for input in tx:
//! hash_auth_tag(secret_i, txb)`. Downstream composites supply a
//! single T2b bridge tying `tx_body_col[0..2] @ row 0` to the external
//! canonical `tx_body_hash` origin (e.g. `TxBodyMerkleAir`'s
//! wrap-output).

use crate::airs::haddr::{HADDR_PAD_0, HADDR_PAD_1};
use crate::airs::poseidon_perm::{
    is_full_round, write_perm_trace_at_offset, PermLayout, POSEIDON_PERM_N_COLS,
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

/// Rows consumed by a single `hash_auth_tag` sponge instance.
pub const HAUTH_STRIDE: usize = 3 * N_ROUNDS + 3;

pub const HAUTH_MULTI_PERM_A_BASE: usize = 0;
pub const HAUTH_MULTI_PERM_B_BASE: usize = POSEIDON_PERM_N_COLS;
pub const HAUTH_MULTI_PERM_C_BASE: usize = 2 * POSEIDON_PERM_N_COLS;
pub const HAUTH_MULTI_PRE_S_A_BASE: usize = 3 * POSEIDON_PERM_N_COLS;
pub const HAUTH_MULTI_PRE_S_B_BASE: usize =
    HAUTH_MULTI_PRE_S_A_BASE + STATE_SIZE;
pub const HAUTH_MULTI_PRE_S_C_BASE: usize =
    HAUTH_MULTI_PRE_S_B_BASE + STATE_SIZE;
/// Column base of the `tx_body_col[0..2]` absorb-value witness columns.
/// These hold the canonical `tx_body_hash` (hi, lo), replicated on every
/// row and enforced constant by shifted-XOR gates. Downstream composites
/// bridge these columns at row 0 to the external `tx_body_hash` origin.
pub const HAUTH_MULTI_TX_BODY_BASE: usize =
    HAUTH_MULTI_PRE_S_C_BASE + STATE_SIZE;

pub const HAUTH_MULTI_TX_BODY_COLS: usize = 2;

pub const HAUTH_MULTI_IND_BASE: usize =
    HAUTH_MULTI_TX_BODY_BASE + HAUTH_MULTI_TX_BODY_COLS;

pub const HAUTH_MULTI_LAYOUT_A: PermLayout =
    PermLayout::at(HAUTH_MULTI_PERM_A_BASE);
pub const HAUTH_MULTI_LAYOUT_B: PermLayout =
    PermLayout::at(HAUTH_MULTI_PERM_B_BASE);
pub const HAUTH_MULTI_LAYOUT_C: PermLayout =
    PermLayout::at(HAUTH_MULTI_PERM_C_BASE);

/// Block-B seed row offset within an instance band.
pub const HAUTH_B_SEED_OFF: usize = N_ROUNDS;
/// Block-C seed row offset within an instance band.
pub const HAUTH_C_SEED_OFF: usize = 2 * N_ROUNDS + 1;
/// Output row offset within an instance band.
pub const HAUTH_OUTPUT_OFF: usize = 3 * N_ROUNDS + 2;

pub const fn hauth_multi_n_cols(n_inputs: usize) -> usize {
    HAUTH_MULTI_IND_BASE + 4 * n_inputs
}

pub const fn hauth_multi_min_log_rows(n_inputs: usize) -> usize {
    let needed = n_inputs * HAUTH_STRIDE;
    let mut k = 0usize;
    let mut pow = 1usize;
    while pow < needed {
        pow <<= 1;
        k += 1;
    }
    k
}

pub const fn hauth_multi_row_0(input: usize) -> usize {
    input * HAUTH_STRIDE
}
pub const fn hauth_multi_row_n_rounds(input: usize) -> usize {
    input * HAUTH_STRIDE + N_ROUNDS
}
pub const fn hauth_multi_row_2n_plus_1(input: usize) -> usize {
    input * HAUTH_STRIDE + 2 * N_ROUNDS + 1
}
pub const fn hauth_multi_row_output(input: usize) -> usize {
    input * HAUTH_STRIDE + 3 * N_ROUNDS + 2
}

pub const fn hauth_multi_ind_row_0(input: usize) -> usize {
    HAUTH_MULTI_IND_BASE + 4 * input
}
pub const fn hauth_multi_ind_row_n_rounds(input: usize) -> usize {
    HAUTH_MULTI_IND_BASE + 4 * input + 1
}
pub const fn hauth_multi_ind_row_2n_plus_1(input: usize) -> usize {
    HAUTH_MULTI_IND_BASE + 4 * input + 2
}
pub const fn hauth_multi_ind_row_output(input: usize) -> usize {
    HAUTH_MULTI_IND_BASE + 4 * input + 3
}

// ---------------------------------------------------------------------------
// Programme helpers
// ---------------------------------------------------------------------------

fn is_full_values(
    n_inputs: usize,
    n_rows: usize,
    perm_row_offset_in_instance: usize,
) -> Vec<Block128> {
    let mut out = vec![Block128::ZERO; n_rows];
    for i in 0..n_inputs {
        let base = i * HAUTH_STRIDE + perm_row_offset_in_instance;
        for r in 0..N_ROUNDS {
            if is_full_round(r) {
                out[base + r] = Block128::ONE;
            }
        }
    }
    out
}

fn is_round_values(
    n_inputs: usize,
    n_rows: usize,
    perm_row_offset_in_instance: usize,
) -> Vec<Block128> {
    let mut out = vec![Block128::ZERO; n_rows];
    for i in 0..n_inputs {
        let base = i * HAUTH_STRIDE + perm_row_offset_in_instance;
        for r in 0..N_ROUNDS {
            out[base + r] = Block128::ONE;
        }
    }
    out
}

fn rc_values(
    n_inputs: usize,
    n_rows: usize,
    perm_row_offset_in_instance: usize,
    lane: usize,
) -> Vec<Block128> {
    let mut out = vec![Block128::ZERO; n_rows];
    for i in 0..n_inputs {
        let base = i * HAUTH_STRIDE + perm_row_offset_in_instance;
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
    perm_row_offset_in_instance: usize,
) -> Vec<PublicColumn> {
    let mut out = Vec::with_capacity(STATE_SIZE + 2);
    out.push(PublicColumn::new(
        layout.is_full,
        is_full_values(n_inputs, n_rows, perm_row_offset_in_instance),
    ));
    out.push(PublicColumn::new(
        layout.is_round,
        is_round_values(n_inputs, n_rows, perm_row_offset_in_instance),
    ));
    for lane in 0..STATE_SIZE {
        out.push(PublicColumn::new(
            layout.rc + lane,
            rc_values(n_inputs, n_rows, perm_row_offset_in_instance, lane),
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

/// Build an honest witness trace for `n_inputs` `hash_auth_tag` sponges
/// sharing the same public `tx_body_hash`. `secrets[i]` is the private
/// spend-secret for input `i`.
pub fn build_hauth_multi_trace(
    secrets: &[[Block128; 2]],
    tx_body: [Block128; 2],
    log_rows: usize,
) -> Vec<Vec<Block128>> {
    let n_inputs = secrets.len();
    assert!(
        log_rows >= hauth_multi_min_log_rows(n_inputs),
        "hauth_multi: log_rows {} too small for {} inputs (need ≥ {})",
        log_rows,
        n_inputs,
        hauth_multi_min_log_rows(n_inputs),
    );
    let n_rows = 1usize << log_rows;
    let n_cols = hauth_multi_n_cols(n_inputs);
    let mut cols: Vec<Vec<Block128>> = (0..n_cols)
        .map(|_| vec![Block128::ZERO; n_rows])
        .collect();

    let [iv_hi, iv_lo] = capacity_iv(TAG_AUTHTAG);

    // Fill the shared `tx_body_col` columns on every row of the trace
    // so the shifted-XOR constant-column gate holds everywhere.
    for row in 0..n_rows {
        cols[HAUTH_MULTI_TX_BODY_BASE][row] = tx_body[0];
        cols[HAUTH_MULTI_TX_BODY_BASE + 1][row] = tx_body[1];
    }

    for (i, &secret) in secrets.iter().enumerate() {
        let row_0 = hauth_multi_row_0(i);
        let row_nr = hauth_multi_row_n_rounds(i);
        let row_2n1 = hauth_multi_row_2n_plus_1(i);

        // Block A — absorb secret.
        let perm_a_input: [Block128; STATE_SIZE] =
            [secret[0], secret[1], iv_hi, iv_lo];
        let state_after_a = write_perm_trace_at_offset(
            &mut cols,
            HAUTH_MULTI_LAYOUT_A,
            perm_a_input,
            row_0,
        );

        // Block B — absorb tx_body.
        let perm_b_input: [Block128; STATE_SIZE] = [
            state_after_a[0] + tx_body[0],
            state_after_a[1] + tx_body[1],
            state_after_a[2],
            state_after_a[3],
        ];
        let state_after_b = write_perm_trace_at_offset(
            &mut cols,
            HAUTH_MULTI_LAYOUT_B,
            perm_b_input,
            row_nr + 1,
        );

        // Block C — padding flush.
        let perm_c_input: [Block128; STATE_SIZE] = [
            state_after_b[0] + Block128::from(HADDR_PAD_0),
            state_after_b[1] + Block128::from(HADDR_PAD_1),
            state_after_b[2],
            state_after_b[3],
        ];
        write_perm_trace_at_offset(
            &mut cols,
            HAUTH_MULTI_LAYOUT_C,
            perm_c_input,
            row_2n1 + 1,
        );

        // Pre-MDS witness rows.
        cols[HAUTH_MULTI_PRE_S_A_BASE + 0][row_0] = secret[0];
        cols[HAUTH_MULTI_PRE_S_A_BASE + 1][row_0] = secret[1];
        cols[HAUTH_MULTI_PRE_S_A_BASE + 2][row_0] = iv_hi;
        cols[HAUTH_MULTI_PRE_S_A_BASE + 3][row_0] = iv_lo;
        for lane in 0..STATE_SIZE {
            cols[HAUTH_MULTI_PRE_S_B_BASE + lane][row_nr] = perm_b_input[lane];
            cols[HAUTH_MULTI_PRE_S_C_BASE + lane][row_2n1] = perm_c_input[lane];
        }

        // Indicators.
        cols[hauth_multi_ind_row_0(i)][row_0] = Block128::ONE;
        cols[hauth_multi_ind_row_n_rounds(i)][row_nr] = Block128::ONE;
        cols[hauth_multi_ind_row_2n_plus_1(i)][row_2n1] = Block128::ONE;
        cols[hauth_multi_ind_row_output(i)][hauth_multi_row_output(i)] =
            Block128::ONE;
    }

    cols
}

/// Extract `(tag_i_hi, tag_i_lo)` for input `i`.
pub fn extract_hauth_multi_output(
    cols: &[Vec<Block128>],
    input: usize,
) -> [Block128; 2] {
    let row = hauth_multi_row_output(input);
    [
        cols[HAUTH_MULTI_LAYOUT_C.s][row],
        cols[HAUTH_MULTI_LAYOUT_C.s + 1][row],
    ]
}

// ---------------------------------------------------------------------------
// Constraint / public-column emission
// ---------------------------------------------------------------------------

/// Emit constraints + public columns for an `n_inputs`-instance
/// `HAuthMultiAir`. The output squeeze is **not** pinned; callers tie
/// `s_C[0..2]@hauth_multi_row_output(i)` to the downstream auth-tag
/// lane cell via a T2a bridge gated on `ind_row_output[i]`. The
/// `tx_body_col[0..2]` absorb-value columns are pinned constant across
/// rows but are **not** tied to any external value here — the caller
/// adds a T2b bridge from `tx_body_col[0..2]@row 0` to the canonical
/// `tx_body_hash` origin to close the binding.
pub fn emit_hauth_multi_no_output_pin(
    n_inputs: usize,
    log_rows: usize,
) -> (Vec<Box<dyn Constraint>>, Vec<PublicColumn>) {
    assert!(n_inputs >= 1, "hauth_multi: n_inputs must be ≥ 1");
    assert!(
        log_rows >= hauth_multi_min_log_rows(n_inputs),
        "hauth_multi: log_rows {} too small for {} inputs",
        log_rows,
        n_inputs,
    );
    let n_rows = 1usize << log_rows;

    let mut constraints: Vec<Box<dyn Constraint>> = Vec::new();
    let mut public_columns: Vec<PublicColumn> = Vec::new();

    // Perm-slab interior gates for all three blocks.
    constraints.extend(crate::airs::emit_perm_all_at(HAUTH_MULTI_LAYOUT_A));
    constraints.extend(crate::airs::emit_perm_all_at(HAUTH_MULTI_LAYOUT_B));
    constraints.extend(crate::airs::emit_perm_all_at(HAUTH_MULTI_LAYOUT_C));

    public_columns.extend(emit_perm_publics_multi(
        HAUTH_MULTI_LAYOUT_A,
        n_inputs,
        n_rows,
        0,
    ));
    public_columns.extend(emit_perm_publics_multi(
        HAUTH_MULTI_LAYOUT_B,
        n_inputs,
        n_rows,
        N_ROUNDS + 1,
    ));
    public_columns.extend(emit_perm_publics_multi(
        HAUTH_MULTI_LAYOUT_C,
        n_inputs,
        n_rows,
        2 * N_ROUNDS + 2,
    ));

    // Constant-column gate for `tx_body_col[0..2]`: `col@row + col@row+1 == 0`
    // for every row (cyclic) — forces the column to be a single field
    // element across the whole trace. The specific value is bound
    // externally by a T2b bridge the caller adds at row 0.
    for lane in 0..HAUTH_MULTI_TX_BODY_COLS {
        constraints.push(Box::new(WeightedLinearGateShifted::new_xor_next(
            HAUTH_MULTI_TX_BODY_BASE + lane,
            HAUTH_MULTI_TX_BODY_BASE + lane,
        )));
    }

    for i in 0..n_inputs {
        public_columns.push(PublicColumn::new(
            hauth_multi_ind_row_0(i),
            row_indicator_programme(hauth_multi_row_0(i), n_rows),
        ));
        public_columns.push(PublicColumn::new(
            hauth_multi_ind_row_n_rounds(i),
            row_indicator_programme(hauth_multi_row_n_rounds(i), n_rows),
        ));
        public_columns.push(PublicColumn::new(
            hauth_multi_ind_row_2n_plus_1(i),
            row_indicator_programme(hauth_multi_row_2n_plus_1(i), n_rows),
        ));
        public_columns.push(PublicColumn::new(
            hauth_multi_ind_row_output(i),
            row_indicator_programme(hauth_multi_row_output(i), n_rows),
        ));
    }

    let [iv_hi, iv_lo] = capacity_iv(TAG_AUTHTAG);

    for i in 0..n_inputs {
        let ind_0 = hauth_multi_ind_row_0(i);
        let ind_nr = hauth_multi_ind_row_n_rounds(i);
        let ind_2n1 = hauth_multi_ind_row_2n_plus_1(i);

        // Tie 1 — capacity IV pin on pre_s_A[2..4] at row_0.
        for (lane, iv) in [(2usize, iv_hi), (3usize, iv_lo)] {
            let inner: Box<dyn Constraint> = Box::new(WeightedLinearGate::new(
                vec![(HAUTH_MULTI_PRE_S_A_BASE + lane, Block128::ONE)],
                iv,
            ));
            constraints.push(Box::new(SelectorGate::new(ind_0, inner)));
        }

        // Tie MDS-A: s_A[lane]@row_0 + Σ MDS·pre_s_A[j] = 0.
        for lane in 0..STATE_SIZE {
            let mut terms = vec![(HAUTH_MULTI_LAYOUT_A.s + lane, Block128::ONE)];
            terms.extend(mds_row_terms(lane, HAUTH_MULTI_PRE_S_A_BASE));
            let inner: Box<dyn Constraint> =
                Box::new(WeightedLinearGate::new(terms, Block128::ZERO));
            constraints.push(Box::new(SelectorGate::new(ind_0, inner)));
        }

        // Tie B-carry at row_n_rounds: A.s[lane] + pre_s_B[lane] + ABSORB[lane] = 0.
        // For lanes 0..=1, ABSORB comes from the shared witness column
        // `tx_body_col[lane]` (read at the same row); for lanes 2..=3
        // the padding is zero.
        for lane in 0..STATE_SIZE {
            let inner: Box<dyn Constraint> = if lane < 2 {
                Box::new(WeightedLinearGate::new(
                    vec![
                        (HAUTH_MULTI_LAYOUT_A.s + lane, Block128::ONE),
                        (HAUTH_MULTI_PRE_S_B_BASE + lane, Block128::ONE),
                        (HAUTH_MULTI_TX_BODY_BASE + lane, Block128::ONE),
                    ],
                    Block128::ZERO,
                ))
            } else {
                Box::new(WeightedLinearGate::new(
                    vec![
                        (HAUTH_MULTI_LAYOUT_A.s + lane, Block128::ONE),
                        (HAUTH_MULTI_PRE_S_B_BASE + lane, Block128::ONE),
                    ],
                    Block128::ZERO,
                ))
            };
            constraints.push(Box::new(SelectorGate::new(ind_nr, inner)));
        }

        // Tie MDS-B shifted: row_n_rounds → row_n_rounds + 1.
        for lane in 0..STATE_SIZE {
            let inner: Box<dyn Constraint> = Box::new(WeightedLinearGateShifted::new(
                mds_row_terms(lane, HAUTH_MULTI_PRE_S_B_BASE),
                vec![(HAUTH_MULTI_LAYOUT_B.s + lane, Block128::ONE)],
                Block128::ZERO,
            ));
            constraints.push(Box::new(SelectorGate::new(ind_nr, inner)));
        }

        // Tie C-carry at row_2n+1: B.s[lane] + pre_s_C[lane] + PAD[lane] = 0.
        for lane in 0..STATE_SIZE {
            let inner: Box<dyn Constraint> = Box::new(WeightedLinearGate::new(
                vec![
                    (HAUTH_MULTI_LAYOUT_B.s + lane, Block128::ONE),
                    (HAUTH_MULTI_PRE_S_C_BASE + lane, Block128::ONE),
                ],
                pad_constant(lane),
            ));
            constraints.push(Box::new(SelectorGate::new(ind_2n1, inner)));
        }

        // Tie MDS-C shifted: row_2n+1 → row_2n+2.
        for lane in 0..STATE_SIZE {
            let inner: Box<dyn Constraint> = Box::new(WeightedLinearGateShifted::new(
                mds_row_terms(lane, HAUTH_MULTI_PRE_S_C_BASE),
                vec![(HAUTH_MULTI_LAYOUT_C.s + lane, Block128::ONE)],
                Block128::ZERO,
            ));
            constraints.push(Box::new(SelectorGate::new(ind_2n1, inner)));
        }
    }

    (constraints, public_columns)
}

// ---------------------------------------------------------------------------
// HAuthMultiAir
// ---------------------------------------------------------------------------

/// Multi-instance `HAuth` AIR. Built without the output-squeeze pin and
/// without a baked-in `tx_body_hash` — downstream composites close the
/// squeeze via T2a bridges onto the TxValidity auth-tag lane cells and
/// bind `tx_body_hash` via a single T2b bridge on the
/// `tx_body_col[0..2]@row 0` cells.
pub struct HAuthMultiAir {
    n_inputs: usize,
    log_rows: usize,
    n_cols: usize,
    constraints: Vec<Box<dyn Constraint>>,
    public_columns: Vec<PublicColumn>,
}

impl HAuthMultiAir {
    pub fn new_min(n_inputs: usize) -> Self {
        Self::new(n_inputs, hauth_multi_min_log_rows(n_inputs))
    }

    pub fn new(n_inputs: usize, log_rows: usize) -> Self {
        let (constraints, public_columns) =
            emit_hauth_multi_no_output_pin(n_inputs, log_rows);
        Self {
            n_inputs,
            log_rows,
            n_cols: hauth_multi_n_cols(n_inputs),
            constraints,
            public_columns,
        }
    }

    pub fn n_inputs(&self) -> usize {
        self.n_inputs
    }

    pub fn into_parts(
        self,
    ) -> (usize, Vec<Box<dyn Constraint>>, Vec<PublicColumn>) {
        (self.n_cols, self.constraints, self.public_columns)
    }

    pub fn build_trace(
        &self,
        secrets: &[[Block128; 2]],
        tx_body: [Block128; 2],
    ) -> Trace {
        assert_eq!(secrets.len(), self.n_inputs);
        Trace::new(build_hauth_multi_trace(secrets, tx_body, self.log_rows))
    }
}

impl Air for HAuthMultiAir {
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
    use crate::airs::hauth::{build_hauth_trace, extract_hauth_output};

    fn mk_fields(seed: u128) -> [Block128; 2] {
        let s = seed.wrapping_mul(0x9E3779B97F4A7C15);
        [
            Block128::from(s ^ 0xA5A5_A5A5_A5A5_A5A5),
            Block128::from(s.wrapping_add(1) ^ 0x5A5A_5A5A_5A5A_5A5A),
        ]
    }

    #[test]
    fn min_log_rows_monotone_and_bounded() {
        // HAUTH_STRIDE = 3·N_ROUNDS + 3 = 201.
        assert_eq!(HAUTH_STRIDE, 3 * N_ROUNDS + 3);
        // 1 input:  201 → log2 ≥ 8  (256)
        // 2 inputs: 402 → log2 ≥ 9  (512)
        // 4 inputs: 804 → log2 ≥ 10 (1024)
        assert_eq!(hauth_multi_min_log_rows(1), 8);
        assert_eq!(hauth_multi_min_log_rows(2), 9);
        assert_eq!(hauth_multi_min_log_rows(4), 10);
    }

    #[test]
    fn n_cols_scales_linearly_in_n_inputs() {
        // 102 base + 4·n_inputs indicator cols.
        assert_eq!(hauth_multi_n_cols(1), HAUTH_MULTI_IND_BASE + 4);
        assert_eq!(hauth_multi_n_cols(4), HAUTH_MULTI_IND_BASE + 16);
        // Baseline 4·106 = 424 cols; multi 102 + 16 = 118 cols.
        assert!(hauth_multi_n_cols(4) < 4 * 106);
    }

    #[test]
    fn single_instance_output_matches_legacy_hauth() {
        let secret = mk_fields(0xA7);
        let tx_body = mk_fields(0xB8);
        let cols = build_hauth_multi_trace(&[secret], tx_body, 8);
        let multi_out = extract_hauth_multi_output(&cols, 0);

        let legacy = build_hauth_trace(secret, tx_body);
        let legacy_out = extract_hauth_output(&legacy);
        assert_eq!(multi_out, legacy_out);
    }

    #[test]
    fn multi_instance_outputs_match_legacy_per_input() {
        let tx_body = mk_fields(0xFEED);
        let secrets = [
            mk_fields(0x1111),
            mk_fields(0x2222),
            mk_fields(0x3333),
            mk_fields(0x4444),
        ];
        let cols = build_hauth_multi_trace(&secrets, tx_body, 10);
        for (i, s) in secrets.iter().enumerate() {
            let multi_out = extract_hauth_multi_output(&cols, i);
            let legacy = build_hauth_trace(*s, tx_body);
            let legacy_out = extract_hauth_output(&legacy);
            assert_eq!(
                multi_out, legacy_out,
                "input {i}: multi vs legacy tag mismatch",
            );
        }
    }

    #[test]
    fn honest_trace_accepts_under_multi_air() {
        let tx_body = mk_fields(0xCAFE);
        let secret = mk_fields(0xBEEF);
        let air = HAuthMultiAir::new_min(1);
        let trace = air.build_trace(&[secret], tx_body);
        assert!(air.check(&trace));
    }

    #[test]
    fn honest_four_inputs_accept() {
        let tx_body = mk_fields(0xABCD);
        let secrets = [
            mk_fields(0xD0),
            mk_fields(0xD1),
            mk_fields(0xD2),
            mk_fields(0xD3),
        ];
        let air = HAuthMultiAir::new_min(4);
        let trace = air.build_trace(&secrets, tx_body);
        assert!(air.check(&trace));
    }

    #[test]
    fn per_input_interior_tamper_rejects() {
        let tx_body = mk_fields(0xAA);
        let secrets = [mk_fields(0x11), mk_fields(0x22)];
        let air = HAuthMultiAir::new_min(2);
        let mut cols = build_hauth_multi_trace(&secrets, tx_body, air.log_rows());

        // Corrupt block-B slab inside input 1's band.
        let tamper_row = hauth_multi_row_n_rounds(1) + 3;
        cols[HAUTH_MULTI_LAYOUT_B.sout + 2][tamper_row] =
            cols[HAUTH_MULTI_LAYOUT_B.sout + 2][tamper_row] + Block128::ONE;
        assert!(!air.check(&Trace::new(cols)));
    }

    #[test]
    fn per_input_iv_pin_tamper_rejects() {
        let tx_body = mk_fields(0xBB);
        let secrets = [mk_fields(0x33), mk_fields(0x44)];
        let air = HAuthMultiAir::new_min(2);
        let mut cols = build_hauth_multi_trace(&secrets, tx_body, air.log_rows());

        let r = hauth_multi_row_0(1);
        cols[HAUTH_MULTI_PRE_S_A_BASE + 2][r] =
            cols[HAUTH_MULTI_PRE_S_A_BASE + 2][r] + Block128::ONE;
        assert!(!air.check(&Trace::new(cols)));
    }

    #[test]
    fn per_input_b_carry_tamper_rejects() {
        let tx_body = mk_fields(0xCC);
        let secrets = [mk_fields(0x55), mk_fields(0x66)];
        let air = HAuthMultiAir::new_min(2);
        let mut cols = build_hauth_multi_trace(&secrets, tx_body, air.log_rows());

        let r = hauth_multi_row_n_rounds(0);
        cols[HAUTH_MULTI_PRE_S_B_BASE][r] =
            cols[HAUTH_MULTI_PRE_S_B_BASE][r] + Block128::ONE;
        assert!(!air.check(&Trace::new(cols)));
    }

    #[test]
    fn per_input_c_carry_tamper_rejects() {
        let tx_body = mk_fields(0xDD);
        let secrets = [mk_fields(0x77), mk_fields(0x88)];
        let air = HAuthMultiAir::new_min(2);
        let mut cols = build_hauth_multi_trace(&secrets, tx_body, air.log_rows());

        let r = hauth_multi_row_2n_plus_1(1);
        cols[HAUTH_MULTI_PRE_S_C_BASE + 1][r] =
            cols[HAUTH_MULTI_PRE_S_C_BASE + 1][r] + Block128::ONE;
        assert!(!air.check(&Trace::new(cols)));
    }

    #[test]
    fn indicator_displacement_rejects() {
        let tx_body = mk_fields(0xEE);
        let secrets = [mk_fields(0x99)];
        let air = HAuthMultiAir::new_min(1);
        let mut cols = build_hauth_multi_trace(&secrets, tx_body, air.log_rows());

        let orig = hauth_multi_row_0(0);
        cols[hauth_multi_ind_row_0(0)][orig] = Block128::ZERO;
        cols[hauth_multi_ind_row_0(0)][orig + 7] = Block128::ONE;
        assert!(!air.check(&Trace::new(cols)));
    }

    #[test]
    fn tx_body_col_non_constant_rejects() {
        // Break the shifted-XOR constant-column gate for tx_body_col[0].
        let tx_body = mk_fields(0x5151);
        let secret = mk_fields(0x7272);
        let air = HAuthMultiAir::new_min(1);
        let mut cols = build_hauth_multi_trace(&[secret], tx_body, air.log_rows());
        let tamper_row = cols[HAUTH_MULTI_TX_BODY_BASE].len() - 1;
        cols[HAUTH_MULTI_TX_BODY_BASE][tamper_row] =
            cols[HAUTH_MULTI_TX_BODY_BASE][tamper_row] + Block128::ONE;
        assert!(!air.check(&Trace::new(cols)));
    }

    #[test]
    fn tx_body_col_mismatched_absorb_rejects() {
        // If the trace writes the wrong tx_body into tx_body_col, all
        // per-input B-carries still use the column value — so the
        // constant-column gate stays green, but the per-input B-carry
        // disagrees with the prover-computed pre_s_B (which was derived
        // from the true tx_body).
        let txb_true = mk_fields(0xA1A1);
        let txb_fake = mk_fields(0xB2B2);
        let secret = mk_fields(0xC3C3);
        let air = HAuthMultiAir::new_min(1);
        let mut cols = build_hauth_multi_trace(&[secret], txb_true, air.log_rows());
        for row in 0..cols[HAUTH_MULTI_TX_BODY_BASE].len() {
            cols[HAUTH_MULTI_TX_BODY_BASE][row] = txb_fake[0];
            cols[HAUTH_MULTI_TX_BODY_BASE + 1][row] = txb_fake[1];
        }
        assert!(!air.check(&Trace::new(cols)));
    }
}
