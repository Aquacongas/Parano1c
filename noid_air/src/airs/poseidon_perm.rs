// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

#![allow(
    clippy::needless_range_loop,
    clippy::identity_op,
    clippy::manual_memcpy
)]

//! `PoseidonPermAir` witness layout + trace builder.
//!
//! One Poseidon2b permutation rendered as a witness trace on the
//! boolean hypercube. This module pins the column layout and supplies
//! a `build_trace(input)` helper that produces a witness bit-for-bit
//! equivalent to `noid_poseidon2b::native::permutation::permute_mut`.
//! The STARK constraint emitter is in `poseidon_constraints`; shipping the builder
//! first gives us a golden reference to validate gates against.
//!
//! # Row programme
//!
//! Native Poseidon2b applies `MDS_FULL` to the input, then 66 rounds:
//! rounds `[0, F_ROUNDS/2)` and `[F_ROUNDS/2 + P_ROUNDS, N_ROUNDS)` are
//! **full** (RC + S-box on all 4 lanes + MDS_FULL); rounds
//! `[F_ROUNDS/2, F_ROUNDS/2 + P_ROUNDS)` are **partial** (RC + S-box on
//! lane 0 only + MDS_PARTIAL). With `F_ROUNDS = 8`, `P_ROUNDS = 58`:
//!
//! | rows  | round type | `is_full` |
//! |-------|------------|-----------|
//! | 0..3  | full       | 1         |
//! | 4..61 | partial    | 0         |
//! | 62..65| full       | 1         |
//! | 66    | output     | 0         |
//! | 67..  | padding    | 0         |
//!
//! Row `r ∈ 0..66` represents the round step whose **input** state is
//! `s[0..4]` at row `r`, and whose **output** state is `s[0..4]` at row
//! `r+1` (after this round's MDS). Row 0's `s[..]` is the post-initial-
//! MDS state (i.e. `MDS_FULL(input)`). Row 66's `s[..]` is the
//! permutation output.
//!
//! # Column layout (30 columns)
//!
//! | range    | name         | semantics                              |
//! |----------|--------------|----------------------------------------|
//! | 0..4     | `s[0..4]`    | state at row start                     |
//! | 4..8     | `sin[0..4]`  | S-box input = `s[i] + RC[i][r]`        |
//! | 8..12    | `x2[0..4]`   | `sin[i]²`                              |
//! | 12..16   | `x4[0..4]`   | `x2[i]²`                               |
//! | 16..20   | `x3[0..4]`   | `x2[i] · sin[i]`                       |
//! | 20..24   | `sout[0..4]` | `x4[i] · x3[i]`                        |
//! | 24       | `is_full`    | `1` on full-round rows, `0` otherwise  |
//! | 25..29   | `rc[0..4]`   | `ROUND_CONSTANTS[i][r]` programme      |
//! | 29       | `is_round`   | `1` on rows `0..N_ROUNDS`, `0` on      |
//! |          |              | output row + padding                   |
//!
//! The `rc[..]` columns, along with `is_full` and `is_round`, carry
//! fixed programmes and are declared as `PublicColumn`s via
//! [`emit_perm_public_columns`]. The native `Air::check` path and the
//! STARK verifier both enforce that the committed trace matches these
//! programmes cell-by-cell.
//!
//! Partial-round rows zero out lanes 1..3 of `sin`, `x2`, `x4`, `x3`,
//! `sout` — the MDS_PARTIAL gate then reads `sout[0]` as the only live
//! lane plus `s[1..4]` for the other three lanes (per the native
//! implementation, which feeds un-S-boxed state into lanes 1..3 of the
//! partial-round MDS multiplication). 3c-1.4b wires the selector
//! constraints that enforce this.

use crate::airs::poseidon_sbox::{emit_sbox_x7_constraints, SboxX7Layout};
use crate::gates::{BoolGate, PublicColumn, SelectorGate, WeightedLinearGate};
use crate::{Constraint, EvalFrame, FlatEvalFrame};
use noid_core::hardware::{clmul_gcm, tower_to_flat_u128};
use noid_core::{Block128, TowerField};
use noid_poseidon2b::native::permutation::{
    sbox_x7, F_ROUNDS, MDS_FULL, MDS_PARTIAL, N_ROUNDS, P_ROUNDS, ROUND_CONSTANTS, STATE_SIZE,
};

pub const POSEIDON_PERM_N_COLS: usize = 30;
/// 256 rows. We need `log_rows >= TAU+1 = 8` for the STARK's VSHIFT
/// ladder to coincide with cyclic rotation on the committed MLE
/// (`MdsBlendGate` reads `s_next[lane]`). 67 active rows comfortably
/// fit under 256.
pub const POSEIDON_PERM_LOG_ROWS: usize = 8;
pub const POSEIDON_PERM_N_ROWS: usize = 1 << POSEIDON_PERM_LOG_ROWS;

/// Column offsets. Each of `s`, `sin`, `x2`, `x4`, `x3`, `sout` occupies
/// 4 consecutive columns (one per lane).
pub const POSEIDON_COL_S: usize = 0;
pub const POSEIDON_COL_SIN: usize = 4;
pub const POSEIDON_COL_X2: usize = 8;
pub const POSEIDON_COL_X4: usize = 12;
pub const POSEIDON_COL_X3: usize = 16;
pub const POSEIDON_COL_SOUT: usize = 20;
pub const POSEIDON_COL_IS_FULL: usize = 24;
pub const POSEIDON_COL_RC: usize = 25;
pub const POSEIDON_COL_IS_ROUND: usize = 29;

/// Number of active round rows in one permutation instance (`N_ROUNDS`
/// rounds + one output row).
pub const POSEIDON_N_ACTIVE_ROWS: usize = N_ROUNDS + 1;

/// Returns `true` iff round `r` is a full round. Matches the
/// `if !(F_ROUNDS/2..F_ROUNDS/2 + P_ROUNDS).contains(&r)` branch in
/// `Poseidon2bPermutation::permute_mut`.
#[inline]
pub fn is_full_round(r: usize) -> bool {
    !(F_ROUNDS / 2..F_ROUNDS / 2 + P_ROUNDS).contains(&r)
}

/// Column layout for one Poseidon permutation block inside a larger
/// trace. The default layout (`PermLayout::at(0)`) reproduces the
/// single-instance column constants used by the standalone AIR.
/// Host AIRs (e.g. `FriStateCombinerAir`) stack multiple perm blocks
/// side-by-side by passing different bases.
///
/// Within a block, columns are contiguous in the same order the
/// `POSEIDON_COL_*` constants describe: `s (4) | sin (4) | x2 (4) |
/// x4 (4) | x3 (4) | sout (4) | is_full (1) | rc (4) | is_round (1)`.
#[derive(Debug, Clone, Copy)]
pub struct PermLayout {
    pub s: usize,
    pub sin: usize,
    pub x2: usize,
    pub x4: usize,
    pub x3: usize,
    pub sout: usize,
    pub is_full: usize,
    pub rc: usize,
    pub is_round: usize,
}

impl PermLayout {
    /// Contiguous block starting at column `base`, matching the
    /// single-instance layout used by 3c-1.
    pub const fn at(base: usize) -> Self {
        Self {
            s: base + POSEIDON_COL_S,
            sin: base + POSEIDON_COL_SIN,
            x2: base + POSEIDON_COL_X2,
            x4: base + POSEIDON_COL_X4,
            x3: base + POSEIDON_COL_X3,
            sout: base + POSEIDON_COL_SOUT,
            is_full: base + POSEIDON_COL_IS_FULL,
            rc: base + POSEIDON_COL_RC,
            is_round: base + POSEIDON_COL_IS_ROUND,
        }
    }
}

/// Default layout: column 0 of the trace. Equivalent to
/// `PermLayout::at(0)`; restates the 3c-1 column constants.
pub const DEFAULT_PERM_LAYOUT: PermLayout = PermLayout::at(0);

/// Apply the MDS_FULL matrix natively (used to seed row 0's state).
fn mds_full(state: [Block128; STATE_SIZE]) -> [Block128; STATE_SIZE] {
    let mut out = [Block128::ZERO; STATE_SIZE];
    for i in 0..STATE_SIZE {
        let mut acc = Block128::ZERO;
        for j in 0..STATE_SIZE {
            let w = MDS_FULL[i][j];
            if w == 1 {
                acc += state[j];
            } else if w != 0 {
                acc += Block128::from(w) * state[j];
            }
        }
        out[i] = acc;
    }
    out
}

/// Apply the MDS_PARTIAL matrix natively.
fn mds_partial(state: [Block128; STATE_SIZE]) -> [Block128; STATE_SIZE] {
    let mut out = [Block128::ZERO; STATE_SIZE];
    for i in 0..STATE_SIZE {
        let mut acc = Block128::ZERO;
        for j in 0..STATE_SIZE {
            let w = MDS_PARTIAL[i][j];
            if w == 1 {
                acc += state[j];
            } else if w != 0 {
                acc += Block128::from(w) * state[j];
            }
        }
        out[i] = acc;
    }
    out
}

/// One permutation instance's witness columns.
///
/// Outer index: column (0..`POSEIDON_PERM_N_COLS`).
/// Inner index: row (0..`POSEIDON_PERM_N_ROWS`).
pub type PoseidonPermColumns = Vec<Vec<Block128>>;

/// Build a full witness trace for one Poseidon2b permutation of
/// `input`. The active rows `0..67` encode the round chain; rows
/// `67..128` are zero padding.
///
/// Row 0's `s[..]` is `MDS_FULL(input)` (so the first round's RC+S-box
/// acts on the post-initial-MDS state, matching `permute_mut`). Row
/// 66's `s[..]` is the permutation output.
pub fn build_perm_trace(input: [Block128; STATE_SIZE]) -> PoseidonPermColumns {
    let mut cols: PoseidonPermColumns = (0..POSEIDON_PERM_N_COLS)
        .map(|_| vec![Block128::ZERO; POSEIDON_PERM_N_ROWS])
        .collect();

    // Row 0 state = MDS_FULL(input). This matches the initial
    // `apply_mds_full(state)` before the round loop in permute_mut.
    let mut state = mds_full(input);
    for lane in 0..STATE_SIZE {
        cols[POSEIDON_COL_S + lane][0] = state[lane];
    }

    for r in 0..N_ROUNDS {
        let is_full = is_full_round(r);
        cols[POSEIDON_COL_IS_FULL][r] = if is_full {
            Block128::ONE
        } else {
            Block128::ZERO
        };
        cols[POSEIDON_COL_IS_ROUND][r] = Block128::ONE;
        for lane in 0..STATE_SIZE {
            cols[POSEIDON_COL_RC + lane][r] = Block128::from(ROUND_CONSTANTS[lane][r]);
        }

        if is_full {
            // sin[i] = s[i] + RC[i][r]; x-chain on all lanes.
            let mut sout = [Block128::ZERO; STATE_SIZE];
            for lane in 0..STATE_SIZE {
                let sin = state[lane] + Block128::from(ROUND_CONSTANTS[lane][r]);
                let x2 = sin * sin;
                let x4 = x2 * x2;
                let x3 = x2 * sin;
                let so = x4 * x3;
                cols[POSEIDON_COL_SIN + lane][r] = sin;
                cols[POSEIDON_COL_X2 + lane][r] = x2;
                cols[POSEIDON_COL_X4 + lane][r] = x4;
                cols[POSEIDON_COL_X3 + lane][r] = x3;
                cols[POSEIDON_COL_SOUT + lane][r] = so;
                sout[lane] = so;
                // Sanity: matches native sbox_x7.
                debug_assert_eq!(so, sbox_x7(sin));
            }
            state = mds_full(sout);
        } else {
            // Partial round: RC + S-box on lane 0 only; lanes 1..3 of
            // sin/x*/sout are pinned to zero on this row. MDS_PARTIAL
            // mixes [sbox(lane0), state[1], state[2], state[3]] in the
            // native implementation; we capture that by feeding
            // `[sout_0, state[1], state[2], state[3]]` into mds_partial.
            let sin0 = state[0] + Block128::from(ROUND_CONSTANTS[0][r]);
            let x2 = sin0 * sin0;
            let x4 = x2 * x2;
            let x3 = x2 * sin0;
            let sout0 = x4 * x3;
            cols[POSEIDON_COL_SIN + 0][r] = sin0;
            cols[POSEIDON_COL_X2 + 0][r] = x2;
            cols[POSEIDON_COL_X4 + 0][r] = x4;
            cols[POSEIDON_COL_X3 + 0][r] = x3;
            cols[POSEIDON_COL_SOUT + 0][r] = sout0;
            debug_assert_eq!(sout0, sbox_x7(sin0));

            let mut mds_in = [Block128::ZERO; STATE_SIZE];
            mds_in[0] = sout0;
            for lane in 1..STATE_SIZE {
                mds_in[lane] = state[lane];
            }
            state = mds_partial(mds_in);
        }

        // Write next state into row r+1.
        let next_row = r + 1;
        for lane in 0..STATE_SIZE {
            cols[POSEIDON_COL_S + lane][next_row] = state[lane];
        }
    }

    cols
}

/// Extract the permutation output (state at row `N_ROUNDS`).
pub fn extract_perm_output(cols: &PoseidonPermColumns) -> [Block128; STATE_SIZE] {
    let row = N_ROUNDS;
    let mut out = [Block128::ZERO; STATE_SIZE];
    for lane in 0..STATE_SIZE {
        out[lane] = cols[POSEIDON_COL_S + lane][row];
    }
    out
}

/// Write one Poseidon2b permutation of `input` into columns `cols` at
/// the given `layout`. Columns are assumed pre-allocated with
/// `POSEIDON_PERM_N_ROWS` rows. Rows written: `0..=N_ROUNDS`; rows
/// `N_ROUNDS+1..` are left untouched (caller may rely on them being
/// zero-initialised).
///
/// Returns the permutation output `state[N_ROUNDS] = s[..]` for
/// convenience (same as `extract_perm_output` would read).
pub fn write_perm_trace_at(
    cols: &mut [Vec<Block128>],
    layout: PermLayout,
    input: [Block128; STATE_SIZE],
) -> [Block128; STATE_SIZE] {
    // Row 0 state = MDS_FULL(input).
    let mut state = mds_full(input);
    for lane in 0..STATE_SIZE {
        cols[layout.s + lane][0] = state[lane];
    }

    for r in 0..N_ROUNDS {
        let is_full = is_full_round(r);
        cols[layout.is_full][r] = if is_full {
            Block128::ONE
        } else {
            Block128::ZERO
        };
        cols[layout.is_round][r] = Block128::ONE;
        for lane in 0..STATE_SIZE {
            cols[layout.rc + lane][r] = Block128::from(ROUND_CONSTANTS[lane][r]);
        }

        if is_full {
            let mut sout = [Block128::ZERO; STATE_SIZE];
            for lane in 0..STATE_SIZE {
                let sin = state[lane] + Block128::from(ROUND_CONSTANTS[lane][r]);
                let x2 = sin * sin;
                let x4 = x2 * x2;
                let x3 = x2 * sin;
                let so = x4 * x3;
                cols[layout.sin + lane][r] = sin;
                cols[layout.x2 + lane][r] = x2;
                cols[layout.x4 + lane][r] = x4;
                cols[layout.x3 + lane][r] = x3;
                cols[layout.sout + lane][r] = so;
                sout[lane] = so;
                debug_assert_eq!(so, sbox_x7(sin));
            }
            state = mds_full(sout);
        } else {
            let sin0 = state[0] + Block128::from(ROUND_CONSTANTS[0][r]);
            let x2 = sin0 * sin0;
            let x4 = x2 * x2;
            let x3 = x2 * sin0;
            let sout0 = x4 * x3;
            cols[layout.sin + 0][r] = sin0;
            cols[layout.x2 + 0][r] = x2;
            cols[layout.x4 + 0][r] = x4;
            cols[layout.x3 + 0][r] = x3;
            cols[layout.sout + 0][r] = sout0;
            debug_assert_eq!(sout0, sbox_x7(sin0));

            let mut mds_in = [Block128::ZERO; STATE_SIZE];
            mds_in[0] = sout0;
            for lane in 1..STATE_SIZE {
                mds_in[lane] = state[lane];
            }
            state = mds_partial(mds_in);
        }

        let next_row = r + 1;
        for lane in 0..STATE_SIZE {
            cols[layout.s + lane][next_row] = state[lane];
        }
    }

    state
}

/// Row-offset variant of [`write_perm_trace_at`]. Writes rows
/// `row_offset..=row_offset + N_ROUNDS` of `cols` for a single Poseidon2b
/// permutation of `input`. Used by `TxBodyMerkleAir` (3c-5) to stack N
/// homogeneous permutation instances row-major into one trace.
///
/// Caller is responsible for sizing `cols` so `row_offset + N_ROUNDS <
/// cols[_].len()` and for ensuring the rows being written are zero.
/// Leaves all other rows untouched.
pub fn write_perm_trace_at_offset(
    cols: &mut [Vec<Block128>],
    layout: PermLayout,
    input: [Block128; STATE_SIZE],
    row_offset: usize,
) -> [Block128; STATE_SIZE] {
    let mut state = mds_full(input);
    for lane in 0..STATE_SIZE {
        cols[layout.s + lane][row_offset] = state[lane];
    }

    for r in 0..N_ROUNDS {
        let row = row_offset + r;
        let is_full = is_full_round(r);
        cols[layout.is_full][row] = if is_full {
            Block128::ONE
        } else {
            Block128::ZERO
        };
        cols[layout.is_round][row] = Block128::ONE;
        for lane in 0..STATE_SIZE {
            cols[layout.rc + lane][row] = Block128::from(ROUND_CONSTANTS[lane][r]);
        }

        if is_full {
            let mut sout = [Block128::ZERO; STATE_SIZE];
            for lane in 0..STATE_SIZE {
                let sin = state[lane] + Block128::from(ROUND_CONSTANTS[lane][r]);
                let x2 = sin * sin;
                let x4 = x2 * x2;
                let x3 = x2 * sin;
                let so = x4 * x3;
                cols[layout.sin + lane][row] = sin;
                cols[layout.x2 + lane][row] = x2;
                cols[layout.x4 + lane][row] = x4;
                cols[layout.x3 + lane][row] = x3;
                cols[layout.sout + lane][row] = so;
                sout[lane] = so;
                debug_assert_eq!(so, sbox_x7(sin));
            }
            state = mds_full(sout);
        } else {
            let sin0 = state[0] + Block128::from(ROUND_CONSTANTS[0][r]);
            let x2 = sin0 * sin0;
            let x4 = x2 * x2;
            let x3 = x2 * sin0;
            let sout0 = x4 * x3;
            cols[layout.sin + 0][row] = sin0;
            cols[layout.x2 + 0][row] = x2;
            cols[layout.x4 + 0][row] = x4;
            cols[layout.x3 + 0][row] = x3;
            cols[layout.sout + 0][row] = sout0;
            debug_assert_eq!(sout0, sbox_x7(sin0));

            let mut mds_in = [Block128::ZERO; STATE_SIZE];
            mds_in[0] = sout0;
            for lane in 1..STATE_SIZE {
                mds_in[lane] = state[lane];
            }
            state = mds_partial(mds_in);
        }

        let next_row = row + 1;
        for lane in 0..STATE_SIZE {
            cols[layout.s + lane][next_row] = state[lane];
        }
    }

    state
}

/// Emit the per-lane S-box chain constraints for `PoseidonPermAir`.
///
/// Four gates per lane × 4 lanes = 16 degree-2 constraints, all local
/// (no rotations). They pin
/// `x2[i] = sin[i]²`, `x4[i] = x2[i]²`, `x3[i] = x2[i]·sin[i]`,
/// `sout[i] = x4[i]·x3[i]` on every row.
///
/// Partial rounds and padding rows hold `sin[i] = 0` for the relevant
/// lanes (by construction in `build_perm_trace`); the chain then
/// forces `x2=x4=x3=sout = 0` trivially — no extra selector needed for
/// this layer. Selector gating for lanes 1..3 during partial rounds
/// (i.e. forcing `sin[lane] = 0`) comes with the RC / selector layer
/// in 3c-1.4c and the MDS blend in 3c-1.4d.
pub fn emit_perm_sbox_chain() -> Vec<Box<dyn Constraint>> {
    emit_perm_sbox_chain_at(DEFAULT_PERM_LAYOUT)
}

/// Layout-parameterized version of [`emit_perm_sbox_chain`].
pub fn emit_perm_sbox_chain_at(layout: PermLayout) -> Vec<Box<dyn Constraint>> {
    let mut out = Vec::with_capacity(16);
    for lane in 0..STATE_SIZE {
        let sx = SboxX7Layout {
            sin: layout.sin + lane,
            x2: layout.x2 + lane,
            x4: layout.x4 + lane,
            x3: layout.x3 + lane,
            sout: layout.sout + lane,
        };
        out.extend(emit_sbox_x7_constraints(sx));
    }
    out
}

/// Emit the RC-binding layer.
///
/// - Lane 0 (live on full and partial rounds): gated by `is_round`, so
///   `is_round · (sin[0] + s[0] + rc[0]) == 0`. On the output row
///   (`r = N_ROUNDS`) `s[0]` is the permutation output and
///   `sin[0] = rc[0] = 0`, so we must suppress the XOR there.
/// - Lanes 1..3 (live only on full rounds): gated by `is_full`, i.e.
///   `is_full · (sin[i] + s[i] + rc[i]) == 0`. On partial rows
///   `is_full = 0` suppresses the XOR; the kill-selector in 3c-1.4e
///   still has to enforce `sin[i] = 0` on partial rows.
/// - Bool gates on both selectors: `is_full ∈ {0,1}`, `is_round ∈ {0,1}`.
pub fn emit_perm_rc_binding() -> Vec<Box<dyn Constraint>> {
    emit_perm_rc_binding_at(DEFAULT_PERM_LAYOUT)
}

/// Layout-parameterized version of [`emit_perm_rc_binding`].
pub fn emit_perm_rc_binding_at(layout: PermLayout) -> Vec<Box<dyn Constraint>> {
    let mut out: Vec<Box<dyn Constraint>> = Vec::with_capacity(STATE_SIZE + 2);

    let lane0_inner: Box<dyn Constraint> = Box::new(WeightedLinearGate::new_xor(vec![
        layout.sin, layout.s, layout.rc,
    ]));
    out.push(Box::new(SelectorGate::new(layout.is_round, lane0_inner)));

    for lane in 1..STATE_SIZE {
        let inner: Box<dyn Constraint> = Box::new(WeightedLinearGate::new_xor(vec![
            layout.sin + lane,
            layout.s + lane,
            layout.rc + lane,
        ]));
        out.push(Box::new(SelectorGate::new(layout.is_full, inner)));
    }

    out.push(Box::new(BoolGate::new(layout.is_full)));
    out.push(Box::new(BoolGate::new(layout.is_round)));
    out
}

/// Blended MDS transition gate for one output lane.
///
/// On active round rows, exactly one arm fires:
///
/// - Full round (`is_full = 1`):
///   `s_next[i] == Σ_j MDS_FULL[i][j] · sout[j]`.
/// - Partial round (`is_full = 0`, `is_round = 1`):
///   `s_next[i] == MDS_PARTIAL[i][0] · sout[0] +
///                 Σ_{j=1..3} MDS_PARTIAL[i][j] · s[j]`.
///   Lanes 1..3 feed un-S-boxed state (matches the native reference).
///
/// On the output row and padding (`is_round = 0`), the whole gate is
/// suppressed — next-row state is unconstrained here.
///
/// Expressed as a single polynomial via the identity
/// `is_full · (is_full + 1) = 0` for bool `is_full`:
///
/// ```text
///   is_round · [ is_full · full_residue + (is_full + 1) · partial_residue ] == 0
/// ```
///
/// Degree: 3 (selector · selector · residue). Rotation: one `s_next[i]`.
/// Locals: `sout[0..4]`, `s[1..4]`, `is_full`, `is_round` — 10 columns.
pub struct PermMdsBlendGate {
    lane: usize,
    locals: Vec<usize>,
    shifted: [usize; 1],
    /// Index inside `locals` of `sout[j]` for j=0..4.
    sout_idx: [usize; STATE_SIZE],
    /// Index inside `locals` of `s[j]` for j=1..4. (`s[0]` is not read.)
    s_idx: [usize; STATE_SIZE - 1],
    /// Index inside `locals` of `is_full`, `is_round`.
    is_full_idx: usize,
    is_round_idx: usize,
    /// [2.C.4] Flat-basis image of `MDS_FULL[lane][0..4]` and
    /// `MDS_PARTIAL[lane][0..4]`. Pre-converted once in
    /// `with_layout`; hot `evaluate_flat` reads these as CLMUL
    /// operands without per-row conversion. Matches the tower-path
    /// `w == 0` / `w == 1` short-circuits — both special values are
    /// GF(2) subfield elements and survive `tower_to_flat_u128` as
    /// themselves.
    mds_full_flat: [u128; STATE_SIZE],
    mds_partial_flat: [u128; STATE_SIZE],
}

impl PermMdsBlendGate {
    pub fn new(lane: usize) -> Self {
        Self::with_layout(lane, DEFAULT_PERM_LAYOUT)
    }

    /// Layout-parameterized constructor. The single shifted column is
    /// `s_next[lane]` within `layout`.
    pub fn with_layout(lane: usize, layout: PermLayout) -> Self {
        assert!(lane < STATE_SIZE);
        let mut locals: Vec<usize> = Vec::with_capacity(10);
        let mut sout_idx = [0usize; STATE_SIZE];
        for j in 0..STATE_SIZE {
            sout_idx[j] = locals.len();
            locals.push(layout.sout + j);
        }
        let mut s_idx = [0usize; STATE_SIZE - 1];
        for (k, j) in (1..STATE_SIZE).enumerate() {
            s_idx[k] = locals.len();
            locals.push(layout.s + j);
        }
        let is_full_idx = locals.len();
        locals.push(layout.is_full);
        let is_round_idx = locals.len();
        locals.push(layout.is_round);

        let mut mds_full_flat = [0u128; STATE_SIZE];
        let mut mds_partial_flat = [0u128; STATE_SIZE];
        for j in 0..STATE_SIZE {
            mds_full_flat[j] = match MDS_FULL[lane][j] {
                0 => 0,
                1 => 1,
                w => tower_to_flat_u128(w),
            };
            mds_partial_flat[j] = match MDS_PARTIAL[lane][j] {
                0 => 0,
                1 => 1,
                w => tower_to_flat_u128(w),
            };
        }

        Self {
            lane,
            locals,
            shifted: [layout.s + lane],
            sout_idx,
            s_idx,
            is_full_idx,
            is_round_idx,
            mds_full_flat,
            mds_partial_flat,
        }
    }

    #[inline]
    fn apply_row(
        mat: &[[u128; STATE_SIZE]; STATE_SIZE],
        lane: usize,
        vals: [Block128; STATE_SIZE],
    ) -> Block128 {
        let mut acc = Block128::ZERO;
        for j in 0..STATE_SIZE {
            let w = mat[lane][j];
            if w == 1 {
                acc += vals[j];
            } else if w != 0 {
                acc += Block128::from(w) * vals[j];
            }
        }
        acc
    }
}

impl Constraint for PermMdsBlendGate {
    fn degree(&self) -> usize {
        3
    }
    fn columns(&self) -> &[usize] {
        &self.locals
    }
    fn shifted_columns(&self) -> &[usize] {
        &self.shifted
    }
    fn evaluate(&self, frame: EvalFrame) -> Block128 {
        let s_next = frame.next[0];
        let sout: [Block128; STATE_SIZE] = [
            frame.local[self.sout_idx[0]],
            frame.local[self.sout_idx[1]],
            frame.local[self.sout_idx[2]],
            frame.local[self.sout_idx[3]],
        ];
        let is_full = frame.local[self.is_full_idx];
        let is_round = frame.local[self.is_round_idx];

        // Full arm: s_next + MDS_FULL[lane] · sout
        let full_residue = s_next + Self::apply_row(&MDS_FULL, self.lane, sout);

        // Partial arm: s_next + MDS_PARTIAL[lane] · [sout[0], s[1], s[2], s[3]]
        let partial_input: [Block128; STATE_SIZE] = [
            sout[0],
            frame.local[self.s_idx[0]],
            frame.local[self.s_idx[1]],
            frame.local[self.s_idx[2]],
        ];
        let partial_residue = s_next + Self::apply_row(&MDS_PARTIAL, self.lane, partial_input);

        let one_plus_is_full = is_full + Block128::ONE;
        is_round * (is_full * full_residue + one_plus_is_full * partial_residue)
    }

    /// [2.C.4] Flat-basis evaluator. Mirrors `evaluate` operation by
    /// operation, using `clmul_gcm` for the basis-sensitive mults and
    /// XOR for addition. Coefficients come from the pre-converted
    /// `mds_full_flat` / `mds_partial_flat` caches. Bit-identical to
    /// `tower_to_flat_u128(self.evaluate(...))` by the flat isomorphism.
    fn evaluate_flat(&self, frame: FlatEvalFrame) -> u128 {
        let s_next = frame.next[0];
        let sout: [u128; STATE_SIZE] = [
            frame.local[self.sout_idx[0]],
            frame.local[self.sout_idx[1]],
            frame.local[self.sout_idx[2]],
            frame.local[self.sout_idx[3]],
        ];
        let is_full = frame.local[self.is_full_idx];
        let is_round = frame.local[self.is_round_idx];

        // Full arm: s_next ^ Σ MDS_FULL_FLAT[lane][j] · sout[j]
        let mut full_residue = s_next;
        for j in 0..STATE_SIZE {
            let wf = self.mds_full_flat[j];
            if wf == 1 {
                full_residue ^= sout[j];
            } else if wf != 0 {
                full_residue ^= clmul_gcm(wf, sout[j]);
            }
        }

        // Partial arm operands: [sout[0], s[1], s[2], s[3]].
        let partial_inputs: [u128; STATE_SIZE] = [
            sout[0],
            frame.local[self.s_idx[0]],
            frame.local[self.s_idx[1]],
            frame.local[self.s_idx[2]],
        ];
        let mut partial_residue = s_next;
        for j in 0..STATE_SIZE {
            let wf = self.mds_partial_flat[j];
            if wf == 1 {
                partial_residue ^= partial_inputs[j];
            } else if wf != 0 {
                partial_residue ^= clmul_gcm(wf, partial_inputs[j]);
            }
        }

        // `is_full + 1` = `is_full ^ 1` (GF(2) elements are basis-invariant).
        let one_plus_is_full = is_full ^ 1;
        let inner = clmul_gcm(is_full, full_residue) ^ clmul_gcm(one_plus_is_full, partial_residue);
        clmul_gcm(is_round, inner)
    }
}

/// Emit the MDS blend layer: one `PermMdsBlendGate` per output lane.
pub fn emit_perm_mds_blend() -> Vec<Box<dyn Constraint>> {
    emit_perm_mds_blend_at(DEFAULT_PERM_LAYOUT)
}

/// Layout-parameterized version of [`emit_perm_mds_blend`].
pub fn emit_perm_mds_blend_at(layout: PermLayout) -> Vec<Box<dyn Constraint>> {
    (0..STATE_SIZE)
        .map(|lane| Box::new(PermMdsBlendGate::with_layout(lane, layout)) as Box<dyn Constraint>)
        .collect()
}

/// Emit the complete `PoseidonPermAir` constraint set: S-box chain +
/// RC binding (with is_full / is_round selectors) + MDS blend +
/// partial-round S-box kill. Lays out as
/// `16 + 6 + 4 + 3 = 29` gates.
pub fn emit_perm_all() -> Vec<Box<dyn Constraint>> {
    emit_perm_all_at(DEFAULT_PERM_LAYOUT)
}

/// Layout-parameterized version of [`emit_perm_all`]. Used by host
/// AIRs that stack multiple permutation blocks side-by-side.
pub fn emit_perm_all_at(layout: PermLayout) -> Vec<Box<dyn Constraint>> {
    let mut out = Vec::new();
    out.extend(emit_perm_sbox_chain_at(layout));
    out.extend(emit_perm_rc_binding_at(layout));
    out.extend(emit_perm_mds_blend_at(layout));
    out.extend(emit_perm_partial_sbox_kill_at(layout));
    out
}

/// Emit the partial-round S-box-kill layer: on non-full rows, pin
/// `sin[lane] = 0` for lanes 1..3. Concretely:
///
/// ```text
///   (is_full + 1) · sin[lane] == 0       for lane ∈ {1, 2, 3}
/// ```
///
/// (Char-2: `is_full + 1 = 1 - is_full`.) Forces the canonical
/// partial-round layout that `build_perm_trace` produces: S-box acts on
/// lane 0 only; lanes 1..3 of `sin`/`x2`/`x4`/`x3`/`sout` are zero.
/// Together with the S-box chain (`x2 = sin²` etc.), killing `sin`
/// cascades through the rest: `sin=0 ⇒ x2=x4=x3=sout=0`. Padding rows
/// (`is_round=0`, `is_full=0`) also fall under this kill — fine, they
/// carry zero by construction.
pub fn emit_perm_partial_sbox_kill() -> Vec<Box<dyn Constraint>> {
    emit_perm_partial_sbox_kill_at(DEFAULT_PERM_LAYOUT)
}

/// Layout-parameterized version of [`emit_perm_partial_sbox_kill`].
pub fn emit_perm_partial_sbox_kill_at(layout: PermLayout) -> Vec<Box<dyn Constraint>> {
    let mut out: Vec<Box<dyn Constraint>> = Vec::with_capacity(STATE_SIZE - 1);
    for lane in 1..STATE_SIZE {
        out.push(Box::new(PartialSboxKillGate::with_layout(lane, layout)));
    }
    out
}

/// `(is_full + 1) · sin[lane] == 0`. Degree 2, one local read + is_full.
pub struct PartialSboxKillGate {
    locals: [usize; 2],
}

impl PartialSboxKillGate {
    pub fn new(lane: usize) -> Self {
        Self::with_layout(lane, DEFAULT_PERM_LAYOUT)
    }

    /// Layout-parameterized constructor.
    pub fn with_layout(lane: usize, layout: PermLayout) -> Self {
        assert!((1..STATE_SIZE).contains(&lane));
        Self {
            locals: [layout.is_full, layout.sin + lane],
        }
    }
}

impl Constraint for PartialSboxKillGate {
    fn degree(&self) -> usize {
        2
    }
    fn columns(&self) -> &[usize] {
        &self.locals
    }
    fn evaluate(&self, frame: EvalFrame) -> Block128 {
        let is_full = frame.local[0];
        let sin = frame.local[1];
        (is_full + Block128::ONE) * sin
    }
    /// [2.C.4] Flat-basis evaluator: `is_full` is a GF(2) selector, so
    /// `(is_full + 1)` equals `is_full ^ 1` in every basis. Single
    /// `clmul_gcm` and one XOR.
    fn evaluate_flat(&self, frame: FlatEvalFrame) -> u128 {
        let is_full = frame.local[0];
        let sin = frame.local[1];
        clmul_gcm(is_full ^ 1, sin)
    }
}

// ---------------------------------------------------------------------------
// Public-column programmes for the perm selectors + RC
// ---------------------------------------------------------------------------

/// Build the `is_full` programme column as a length-`POSEIDON_PERM_N_ROWS`
/// vector: `1` on full-round rows in `0..N_ROUNDS`, `0` everywhere else
/// (partial rows, output row, padding).
pub fn perm_is_full_values() -> Vec<Block128> {
    let mut out = vec![Block128::ZERO; POSEIDON_PERM_N_ROWS];
    for r in 0..N_ROUNDS {
        if is_full_round(r) {
            out[r] = Block128::ONE;
        }
    }
    out
}

/// Build the `is_round` programme column: `1` on rows `0..N_ROUNDS`,
/// `0` on the output row and padding. Matches the selector written by
/// `build_perm_trace` / `write_perm_trace_at`.
pub fn perm_is_round_values() -> Vec<Block128> {
    let mut out = vec![Block128::ZERO; POSEIDON_PERM_N_ROWS];
    for r in 0..N_ROUNDS {
        out[r] = Block128::ONE;
    }
    out
}

/// Build `rc[lane]` programme column: `ROUND_CONSTANTS[lane][r]` for
/// `r ∈ 0..N_ROUNDS`, `0` on the output row and padding.
pub fn perm_rc_values(lane: usize) -> Vec<Block128> {
    assert!(lane < STATE_SIZE);
    let mut out = vec![Block128::ZERO; POSEIDON_PERM_N_ROWS];
    for r in 0..N_ROUNDS {
        out[r] = Block128::from(ROUND_CONSTANTS[lane][r]);
    }
    out
}

/// Declare every selector / round-constant column of a standalone
/// `PoseidonPermAir` as a [`PublicColumn`]. One declaration each for
/// `is_full`, `is_round`, and `rc[0..STATE_SIZE]` — six columns total.
/// The caller (typically a `CompositeAir::from_parts_with_publics`)
/// feeds these alongside the constraint list returned by
/// [`emit_perm_all_at`]. This closes the 3c-1 "trusted public input"
/// debt on `rc` / `is_full` / `is_round`: native `Air::check` verifies
/// the trace cells match the programme, and the STARK verifier re-
/// evaluates each programme MLE at `r_point` and asserts equality with
/// `base_openings[col]` (bound to the FRI commitment by the §12c'
/// multipoint opening).
pub fn emit_perm_public_columns_at(layout: PermLayout) -> Vec<PublicColumn> {
    let mut out = Vec::with_capacity(STATE_SIZE + 2);
    out.push(PublicColumn::new(layout.is_full, perm_is_full_values()));
    out.push(PublicColumn::new(layout.is_round, perm_is_round_values()));
    for lane in 0..STATE_SIZE {
        out.push(PublicColumn::new(layout.rc + lane, perm_rc_values(lane)));
    }
    out
}

/// Default-layout shorthand for [`emit_perm_public_columns_at`].
pub fn emit_perm_public_columns() -> Vec<PublicColumn> {
    emit_perm_public_columns_at(DEFAULT_PERM_LAYOUT)
}

// ---------------------------------------------------------------------------
// Row-major public-column programmes for stacked permutations
// ---------------------------------------------------------------------------

/// Build the `is_full` programme column for a row-major stack of
/// `n_instances` Poseidon2b permutations at `stride` rows per instance,
/// laid out over `total_rows = 1 << log_rows`. Matches
/// [`write_perm_trace_at_offset`] semantics: inside each instance slot
/// `k * stride .. k * stride + stride`, only the `N_ROUNDS` active
/// rows carry the selector; the output row and every row beyond
/// `n_instances * stride` is zero.
pub fn perm_is_full_values_row_major(
    n_instances: usize,
    stride: usize,
    total_rows: usize,
) -> Vec<Block128> {
    assert!(total_rows.is_power_of_two() && total_rows > 0);
    assert!(stride > N_ROUNDS);
    assert!(n_instances * stride <= total_rows);
    let mut out = vec![Block128::ZERO; total_rows];
    for k in 0..n_instances {
        let base = k * stride;
        for r in 0..N_ROUNDS {
            if is_full_round(r) {
                out[base + r] = Block128::ONE;
            }
        }
    }
    out
}

/// Row-major version of [`perm_is_round_values`].
pub fn perm_is_round_values_row_major(
    n_instances: usize,
    stride: usize,
    total_rows: usize,
) -> Vec<Block128> {
    assert!(total_rows.is_power_of_two() && total_rows > 0);
    assert!(stride > N_ROUNDS);
    assert!(n_instances * stride <= total_rows);
    let mut out = vec![Block128::ZERO; total_rows];
    for k in 0..n_instances {
        let base = k * stride;
        for r in 0..N_ROUNDS {
            out[base + r] = Block128::ONE;
        }
    }
    out
}

/// Row-major version of [`perm_rc_values`]: writes
/// `ROUND_CONSTANTS[lane][r]` at row `k*stride + r` for every instance
/// `k ∈ 0..n_instances` and every round `r ∈ 0..N_ROUNDS`. All other
/// rows (output, intra-slot padding, trailing trace padding) are zero.
pub fn perm_rc_values_row_major(
    lane: usize,
    n_instances: usize,
    stride: usize,
    total_rows: usize,
) -> Vec<Block128> {
    assert!(lane < STATE_SIZE);
    assert!(total_rows.is_power_of_two() && total_rows > 0);
    assert!(stride > N_ROUNDS);
    assert!(n_instances * stride <= total_rows);
    let mut out = vec![Block128::ZERO; total_rows];
    for k in 0..n_instances {
        let base = k * stride;
        for r in 0..N_ROUNDS {
            out[base + r] = Block128::from(ROUND_CONSTANTS[lane][r]);
        }
    }
    out
}

/// Declare every selector / round-constant column of a row-major
/// stacked permutation AIR (e.g. `TxBodyMerkleAir`) as a
/// [`PublicColumn`]. The `layout` identifies the columns; `n_instances`
/// and `stride` describe the row-major packing; `total_rows` is the
/// hypercube size (`1 << air.log_rows()`).
pub fn emit_perm_public_columns_row_major_at(
    layout: PermLayout,
    n_instances: usize,
    stride: usize,
    total_rows: usize,
) -> Vec<PublicColumn> {
    let mut out = Vec::with_capacity(STATE_SIZE + 2);
    out.push(PublicColumn::new(
        layout.is_full,
        perm_is_full_values_row_major(n_instances, stride, total_rows),
    ));
    out.push(PublicColumn::new(
        layout.is_round,
        perm_is_round_values_row_major(n_instances, stride, total_rows),
    ));
    for lane in 0..STATE_SIZE {
        out.push(PublicColumn::new(
            layout.rc + lane,
            perm_rc_values_row_major(lane, n_instances, stride, total_rows),
        ));
    }
    out
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

    #[test]
    fn round_schedule_matches_native_branch() {
        // First F/2 full, then P partial, then F/2 full.
        let f_half = F_ROUNDS / 2;
        for r in 0..f_half {
            assert!(is_full_round(r), "round {r} should be full");
        }
        for r in f_half..f_half + P_ROUNDS {
            assert!(!is_full_round(r), "round {r} should be partial");
        }
        for r in f_half + P_ROUNDS..N_ROUNDS {
            assert!(is_full_round(r), "round {r} should be full");
        }
    }

    #[test]
    fn perm_trace_output_matches_native_permutation() {
        for seed in 0..4 {
            let input = mk_input(seed);
            let cols = build_perm_trace(input);

            // Native reference: copy input, permute in place.
            let mut native_state = input;
            Poseidon2bPermutation.permute_mut(&mut native_state);

            let trace_out = extract_perm_output(&cols);
            assert_eq!(
                trace_out, native_state,
                "seed {seed}: trace output must match native permute_mut"
            );
        }
    }

    #[test]
    fn perm_trace_row_0_is_initial_mds() {
        let input = mk_input(0x1234);
        let cols = build_perm_trace(input);
        let expected_row0 = mds_full(input);
        for lane in 0..STATE_SIZE {
            assert_eq!(cols[POSEIDON_COL_S + lane][0], expected_row0[lane]);
        }
    }

    #[test]
    fn perm_trace_is_full_selector_matches_schedule() {
        let input = mk_input(42);
        let cols = build_perm_trace(input);
        for r in 0..N_ROUNDS {
            let expected = if is_full_round(r) {
                Block128::ONE
            } else {
                Block128::ZERO
            };
            assert_eq!(cols[POSEIDON_COL_IS_FULL][r], expected, "row {r}");
        }
        // Padding rows 67..128: is_full stays zero.
        for r in N_ROUNDS + 1..POSEIDON_PERM_N_ROWS {
            assert_eq!(cols[POSEIDON_COL_IS_FULL][r], Block128::ZERO);
        }
    }

    #[test]
    fn perm_trace_partial_rounds_zero_unused_lanes() {
        let input = mk_input(7);
        let cols = build_perm_trace(input);
        for r in F_ROUNDS / 2..F_ROUNDS / 2 + P_ROUNDS {
            for lane in 1..STATE_SIZE {
                assert_eq!(cols[POSEIDON_COL_SIN + lane][r], Block128::ZERO);
                assert_eq!(cols[POSEIDON_COL_X2 + lane][r], Block128::ZERO);
                assert_eq!(cols[POSEIDON_COL_X4 + lane][r], Block128::ZERO);
                assert_eq!(cols[POSEIDON_COL_X3 + lane][r], Block128::ZERO);
                assert_eq!(cols[POSEIDON_COL_SOUT + lane][r], Block128::ZERO);
            }
        }
    }

    #[test]
    fn perm_sbox_chain_accepts_honest_trace() {
        use crate::{Air, CompositeAir, Trace};
        let input = mk_input(0xBEEF);
        let cols = build_perm_trace(input);
        let air = CompositeAir::from_parts(
            POSEIDON_PERM_LOG_ROWS,
            POSEIDON_PERM_N_COLS,
            emit_perm_sbox_chain(),
        );
        assert!(air.check(&Trace::new(cols)));
    }

    #[test]
    fn perm_sbox_chain_rejects_sout_tamper() {
        use crate::{Air, CompositeAir, Trace};
        let input = mk_input(0xABCD);
        let mut cols = build_perm_trace(input);
        // Flip one byte of sout[2] at an arbitrary active row.
        cols[POSEIDON_COL_SOUT + 2][10] += Block128::ONE;
        let air = CompositeAir::from_parts(
            POSEIDON_PERM_LOG_ROWS,
            POSEIDON_PERM_N_COLS,
            emit_perm_sbox_chain(),
        );
        assert!(!air.check(&Trace::new(cols)));
    }

    #[test]
    fn perm_sbox_chain_rejects_x2_tamper_on_partial_row() {
        // Partial-round lane-0 values are live; tampering them must
        // also trip the chain.
        use crate::{Air, CompositeAir, Trace};
        let input = mk_input(0x5555);
        let mut cols = build_perm_trace(input);
        let partial_row = F_ROUNDS / 2 + 3;
        cols[POSEIDON_COL_X2 + 0][partial_row] += Block128::ONE;
        let air = CompositeAir::from_parts(
            POSEIDON_PERM_LOG_ROWS,
            POSEIDON_PERM_N_COLS,
            emit_perm_sbox_chain(),
        );
        assert!(!air.check(&Trace::new(cols)));
    }

    #[test]
    fn perm_sbox_chain_constraint_count_and_degree() {
        let cs = emit_perm_sbox_chain();
        assert_eq!(cs.len(), 4 * STATE_SIZE, "4 gates per lane × 4 lanes");
        for c in &cs {
            assert_eq!(c.degree(), 2);
            assert!(c.shifted_columns().is_empty(), "S-box chain is local only");
        }
    }

    #[test]
    fn perm_rc_binding_accepts_honest_trace() {
        use crate::{Air, CompositeAir, Trace};
        let input = mk_input(0xC0DE);
        let cols = build_perm_trace(input);
        let air = CompositeAir::from_parts(
            POSEIDON_PERM_LOG_ROWS,
            POSEIDON_PERM_N_COLS,
            emit_perm_rc_binding(),
        );
        assert!(air.check(&Trace::new(cols)));
    }

    #[test]
    fn perm_rc_binding_rejects_sin_tamper() {
        use crate::{Air, CompositeAir, Trace};
        let input = mk_input(0xDEAD);
        let mut cols = build_perm_trace(input);
        // Row 2 is a full round — lane-1..3 RC binding is live there.
        assert!(is_full_round(2));
        cols[POSEIDON_COL_SIN + 1][2] += Block128::ONE;
        let air = CompositeAir::from_parts(
            POSEIDON_PERM_LOG_ROWS,
            POSEIDON_PERM_N_COLS,
            emit_perm_rc_binding(),
        );
        assert!(!air.check(&Trace::new(cols)));
    }

    #[test]
    fn perm_rc_binding_rejects_rc_tamper() {
        use crate::{Air, CompositeAir, Trace};
        let input = mk_input(0xFACE);
        let mut cols = build_perm_trace(input);
        cols[POSEIDON_COL_RC + 0][0] += Block128::ONE;
        let air = CompositeAir::from_parts(
            POSEIDON_PERM_LOG_ROWS,
            POSEIDON_PERM_N_COLS,
            emit_perm_rc_binding(),
        );
        assert!(!air.check(&Trace::new(cols)));
    }

    #[test]
    fn perm_rc_binding_rejects_is_full_non_bool() {
        use crate::{Air, CompositeAir, Trace};
        let input = mk_input(0xBAAD);
        let mut cols = build_perm_trace(input);
        // Stuff a non-{0,1} value into is_full at a padding row.
        cols[POSEIDON_COL_IS_FULL][N_ROUNDS + 2] = Block128::from(0x1234_5678_u128);
        let air = CompositeAir::from_parts(
            POSEIDON_PERM_LOG_ROWS,
            POSEIDON_PERM_N_COLS,
            emit_perm_rc_binding(),
        );
        assert!(!air.check(&Trace::new(cols)));
    }

    #[test]
    fn perm_rc_binding_does_not_fire_on_partial_row_for_lane_1_to_3() {
        // Sanity: on a partial row, s[lane]!=0 and rc[lane]!=0 while
        // sin[lane]==0. The unconditional lane-0 gate is happy because
        // lane 0 is live; the gated lane-1..3 gates must be suppressed
        // by is_full=0.
        let input = mk_input(0xAAAA);
        let cols = build_perm_trace(input);
        let partial_row = F_ROUNDS / 2 + 1;
        assert!(!is_full_round(partial_row));
        for lane in 1..STATE_SIZE {
            assert_eq!(cols[POSEIDON_COL_SIN + lane][partial_row], Block128::ZERO);
            assert_ne!(cols[POSEIDON_COL_S + lane][partial_row], Block128::ZERO);
        }
    }

    #[test]
    fn perm_rc_columns_match_programme_on_active_rows() {
        let input = mk_input(0);
        let cols = build_perm_trace(input);
        for r in 0..N_ROUNDS {
            for lane in 0..STATE_SIZE {
                assert_eq!(
                    cols[POSEIDON_COL_RC + lane][r],
                    Block128::from(ROUND_CONSTANTS[lane][r]),
                    "rc[{lane}][{r}]",
                );
            }
        }
        for r in N_ROUNDS..POSEIDON_PERM_N_ROWS {
            for lane in 0..STATE_SIZE {
                assert_eq!(cols[POSEIDON_COL_RC + lane][r], Block128::ZERO);
            }
        }
    }

    #[test]
    fn perm_mds_blend_accepts_honest_trace() {
        use crate::{Air, CompositeAir, Trace};
        let input = mk_input(0x11);
        let cols = build_perm_trace(input);
        let air = CompositeAir::from_parts(
            POSEIDON_PERM_LOG_ROWS,
            POSEIDON_PERM_N_COLS,
            emit_perm_mds_blend(),
        );
        assert!(air.check(&Trace::new(cols)));
    }

    #[test]
    fn perm_mds_blend_rejects_s_next_tamper_on_full_row() {
        use crate::{Air, CompositeAir, Trace};
        let input = mk_input(0x22);
        let mut cols = build_perm_trace(input);
        // row 0 is a full round, so s_next lives at row 1.
        assert!(is_full_round(0));
        cols[POSEIDON_COL_S + 2][1] += Block128::ONE;
        let air = CompositeAir::from_parts(
            POSEIDON_PERM_LOG_ROWS,
            POSEIDON_PERM_N_COLS,
            emit_perm_mds_blend(),
        );
        assert!(!air.check(&Trace::new(cols)));
    }

    #[test]
    fn perm_mds_blend_rejects_s_next_tamper_on_partial_row() {
        use crate::{Air, CompositeAir, Trace};
        let input = mk_input(0x33);
        let mut cols = build_perm_trace(input);
        let partial_row = F_ROUNDS / 2 + 5;
        assert!(!is_full_round(partial_row));
        // s_next for this row sits at partial_row + 1.
        cols[POSEIDON_COL_S + 3][partial_row + 1] += Block128::ONE;
        let air = CompositeAir::from_parts(
            POSEIDON_PERM_LOG_ROWS,
            POSEIDON_PERM_N_COLS,
            emit_perm_mds_blend(),
        );
        assert!(!air.check(&Trace::new(cols)));
    }

    #[test]
    fn perm_mds_blend_rejects_sout_tamper_on_full_row() {
        use crate::{Air, CompositeAir, Trace};
        let input = mk_input(0x44);
        let mut cols = build_perm_trace(input);
        assert!(is_full_round(1));
        cols[POSEIDON_COL_SOUT + 1][1] += Block128::ONE;
        let air = CompositeAir::from_parts(
            POSEIDON_PERM_LOG_ROWS,
            POSEIDON_PERM_N_COLS,
            emit_perm_mds_blend(),
        );
        assert!(!air.check(&Trace::new(cols)));
    }

    #[test]
    fn perm_mds_blend_rejects_s_lane_tamper_on_partial_row() {
        use crate::{Air, CompositeAir, Trace};
        // On partial rows the blend reads s[1..3] from the CURRENT row.
        // Tampering s[2] at a partial row must trip the gate.
        let input = mk_input(0x55);
        let mut cols = build_perm_trace(input);
        let partial_row = F_ROUNDS / 2 + 2;
        assert!(!is_full_round(partial_row));
        cols[POSEIDON_COL_S + 2][partial_row] += Block128::ONE;
        let air = CompositeAir::from_parts(
            POSEIDON_PERM_LOG_ROWS,
            POSEIDON_PERM_N_COLS,
            emit_perm_mds_blend(),
        );
        assert!(!air.check(&Trace::new(cols)));
    }

    #[test]
    fn perm_mds_blend_suppressed_on_output_and_padding_rows() {
        use crate::{Air, CompositeAir, Trace};
        // Tamper s at a padding row transition — is_round=0 should
        // suppress the blend (this only checks the MDS blend gate, so
        // no other constraints complain about the edit).
        let input = mk_input(0x66);
        let mut cols = build_perm_trace(input);
        // Row N_ROUNDS is the output row; its s_next (= row N_ROUNDS+1)
        // is padding. With is_round=0 on row N_ROUNDS, the blend must
        // accept arbitrary garbage in the padding column.
        cols[POSEIDON_COL_S + 1][N_ROUNDS + 1] = Block128::from(0xFEEDFACEu128);
        let air = CompositeAir::from_parts(
            POSEIDON_PERM_LOG_ROWS,
            POSEIDON_PERM_N_COLS,
            emit_perm_mds_blend(),
        );
        assert!(air.check(&Trace::new(cols)));
    }

    #[test]
    fn perm_partial_sbox_kill_accepts_honest_trace() {
        use crate::{Air, CompositeAir, Trace};
        let input = mk_input(0x77);
        let cols = build_perm_trace(input);
        let air = CompositeAir::from_parts(
            POSEIDON_PERM_LOG_ROWS,
            POSEIDON_PERM_N_COLS,
            emit_perm_partial_sbox_kill(),
        );
        assert!(air.check(&Trace::new(cols)));
    }

    #[test]
    fn perm_partial_sbox_kill_rejects_nonzero_sin_on_partial_row() {
        use crate::{Air, CompositeAir, Trace};
        let input = mk_input(0x88);
        let mut cols = build_perm_trace(input);
        let partial_row = F_ROUNDS / 2 + 4;
        assert!(!is_full_round(partial_row));
        cols[POSEIDON_COL_SIN + 2][partial_row] = Block128::ONE;
        let air = CompositeAir::from_parts(
            POSEIDON_PERM_LOG_ROWS,
            POSEIDON_PERM_N_COLS,
            emit_perm_partial_sbox_kill(),
        );
        assert!(!air.check(&Trace::new(cols)));
    }

    #[test]
    fn perm_partial_sbox_kill_allows_nonzero_sin_on_full_row() {
        use crate::{Air, CompositeAir, Trace};
        // On full rows, is_full=1 so (is_full+1)=0 kills the constraint.
        // We edit sin[2] at a full row and the kill should accept it.
        // (RC binding would reject, but we're only checking the kill
        // layer in isolation here.)
        let input = mk_input(0x99);
        let mut cols = build_perm_trace(input);
        assert!(is_full_round(2));
        cols[POSEIDON_COL_SIN + 2][2] = Block128::from(0xABCDEFu128);
        let air = CompositeAir::from_parts(
            POSEIDON_PERM_LOG_ROWS,
            POSEIDON_PERM_N_COLS,
            emit_perm_partial_sbox_kill(),
        );
        assert!(air.check(&Trace::new(cols)));
    }

    #[test]
    fn perm_partial_sbox_kill_constraint_count_and_degree() {
        let cs = emit_perm_partial_sbox_kill();
        assert_eq!(cs.len(), STATE_SIZE - 1);
        for c in &cs {
            assert_eq!(c.degree(), 2);
            assert!(c.shifted_columns().is_empty());
        }
    }

    #[test]
    fn perm_mds_blend_constraint_count_and_degree() {
        let cs = emit_perm_mds_blend();
        assert_eq!(cs.len(), STATE_SIZE);
        for c in &cs {
            assert_eq!(c.degree(), 3);
            assert_eq!(c.shifted_columns().len(), 1);
        }
    }

    #[test]
    fn perm_all_accepts_honest_trace() {
        use crate::{Air, CompositeAir, Trace};
        for seed in 0..4u128 {
            let input = mk_input(seed);
            let cols = build_perm_trace(input);
            let air = CompositeAir::from_parts(
                POSEIDON_PERM_LOG_ROWS,
                POSEIDON_PERM_N_COLS,
                emit_perm_all(),
            );
            assert!(air.check(&Trace::new(cols)), "seed {seed}");
        }
    }

    #[test]
    fn perm_all_forgery_matrix() {
        // For every (column, row) cell that the builder populates
        // non-trivially, tampering must trip at least one gate.
        use crate::{Air, CompositeAir, Trace};
        let input = mk_input(0xABC);

        // Smoke-check a broad selection of tamper sites.
        let sites: &[(usize, usize, &str)] = &[
            (POSEIDON_COL_S + 0, 1, "state lane0 row1"),
            (POSEIDON_COL_S + 2, 3, "state lane2 row3"),
            (POSEIDON_COL_SIN + 0, 0, "sin lane0 row0 (full)"),
            (POSEIDON_COL_SIN + 1, 2, "sin lane1 row2 (full)"),
            (POSEIDON_COL_X2 + 0, F_ROUNDS / 2 + 1, "x2 lane0 partial"),
            (POSEIDON_COL_X4 + 3, 1, "x4 lane3 full"),
            (POSEIDON_COL_X3 + 2, 62, "x3 lane2 final full"),
            (
                POSEIDON_COL_SOUT + 0,
                F_ROUNDS / 2 + 7,
                "sout lane0 partial",
            ),
            (POSEIDON_COL_SOUT + 2, 63, "sout lane2 final full"),
            (POSEIDON_COL_RC + 1, 0, "rc lane1 row0"),
            (POSEIDON_COL_IS_FULL, 0, "is_full row0"),
            (POSEIDON_COL_IS_ROUND, N_ROUNDS / 2, "is_round mid"),
        ];
        let air = CompositeAir::from_parts(
            POSEIDON_PERM_LOG_ROWS,
            POSEIDON_PERM_N_COLS,
            emit_perm_all(),
        );

        for &(col, row, label) in sites {
            let mut cols = build_perm_trace(input);
            cols[col][row] += Block128::from(0xDEADBEEFu128);
            assert!(
                !air.check(&Trace::new(cols)),
                "forgery at ({col}, {row}) = {label} slipped through",
            );
        }
    }

    #[test]
    fn perm_trace_column_count_and_row_count_match_constants() {
        let input = mk_input(0);
        let cols = build_perm_trace(input);
        assert_eq!(cols.len(), POSEIDON_PERM_N_COLS);
        for c in &cols {
            assert_eq!(c.len(), POSEIDON_PERM_N_ROWS);
        }
    }

    // ---------------------------------------------------------------------
    // PublicColumn programmes for rc / is_full / is_round
    // ---------------------------------------------------------------------

    #[test]
    fn perm_public_columns_match_builder_output() {
        // The helper programmes must be bit-identical to what
        // `build_perm_trace` writes into the witness columns.
        let input = mk_input(0x1337);
        let cols = build_perm_trace(input);
        assert_eq!(perm_is_full_values(), cols[POSEIDON_COL_IS_FULL]);
        assert_eq!(perm_is_round_values(), cols[POSEIDON_COL_IS_ROUND]);
        for lane in 0..STATE_SIZE {
            assert_eq!(perm_rc_values(lane), cols[POSEIDON_COL_RC + lane]);
        }
    }

    #[test]
    fn perm_public_columns_declaration_shape() {
        let publics = emit_perm_public_columns();
        // is_full, is_round, rc[0..STATE_SIZE]
        assert_eq!(publics.len(), STATE_SIZE + 2);
        for p in &publics {
            assert_eq!(p.values.len(), POSEIDON_PERM_N_ROWS);
        }
    }

    #[test]
    fn perm_all_with_publics_accepts_honest_trace() {
        use crate::{Air, CompositeAir, Trace};
        let input = mk_input(0xF00D);
        let cols = build_perm_trace(input);
        let air = CompositeAir::from_parts_with_publics(
            POSEIDON_PERM_LOG_ROWS,
            POSEIDON_PERM_N_COLS,
            emit_perm_all(),
            emit_perm_public_columns(),
        );
        assert!(air.check(&Trace::new(cols)));
    }

    #[test]
    fn perm_public_columns_reject_rc_tamper() {
        // Tamper a single cell of the `rc` witness column. With the
        // 3d-0.3 public-column declaration, native `Air::check` rejects
        // without needing the (imperfect) RC-binding gate to catch it.
        use crate::{Air, CompositeAir, Trace};
        let input = mk_input(0xBEEF);
        let mut cols = build_perm_trace(input);
        cols[POSEIDON_COL_RC + 2][5] += Block128::ONE;
        let air = CompositeAir::from_parts_with_publics(
            POSEIDON_PERM_LOG_ROWS,
            POSEIDON_PERM_N_COLS,
            emit_perm_all(),
            emit_perm_public_columns(),
        );
        assert!(!air.check(&Trace::new(cols)));
    }

    #[test]
    fn perm_public_columns_reject_is_full_flip() {
        use crate::{Air, CompositeAir, Trace};
        let input = mk_input(0xCAFE);
        let mut cols = build_perm_trace(input);
        // Flip is_full at a full-round row — the programme says 1, we
        // write 0. Native check must reject.
        assert!(is_full_round(0));
        cols[POSEIDON_COL_IS_FULL][0] = Block128::ZERO;
        let air = CompositeAir::from_parts_with_publics(
            POSEIDON_PERM_LOG_ROWS,
            POSEIDON_PERM_N_COLS,
            emit_perm_all(),
            emit_perm_public_columns(),
        );
        assert!(!air.check(&Trace::new(cols)));
    }

    #[test]
    fn perm_public_columns_row_major_match_builder_output() {
        // Build a stacked trace with 3 instances at stride = POSEIDON_N_ACTIVE_ROWS
        // (67) rounded up to 128 rows — same shape TxBodyMerkleAir uses.
        const N_INSTANCES: usize = 3;
        const STRIDE: usize = 128;
        const LOG_ROWS: usize = 10; // 1024 >= 3*128
        const TOTAL: usize = 1 << LOG_ROWS;

        let mut cols: Vec<Vec<Block128>> = (0..POSEIDON_PERM_N_COLS)
            .map(|_| vec![Block128::ZERO; TOTAL])
            .collect();
        for k in 0..N_INSTANCES {
            let input = [
                Block128::from((k as u128 + 1) * 0x1111),
                Block128::from((k as u128 + 1) * 0x2222),
                Block128::from((k as u128 + 1) * 0x3333),
                Block128::from((k as u128 + 1) * 0x4444),
            ];
            write_perm_trace_at_offset(&mut cols, DEFAULT_PERM_LAYOUT, input, k * STRIDE);
        }

        let is_full = perm_is_full_values_row_major(N_INSTANCES, STRIDE, TOTAL);
        let is_round = perm_is_round_values_row_major(N_INSTANCES, STRIDE, TOTAL);
        assert_eq!(is_full, cols[POSEIDON_COL_IS_FULL]);
        assert_eq!(is_round, cols[POSEIDON_COL_IS_ROUND]);
        for lane in 0..STATE_SIZE {
            let rc = perm_rc_values_row_major(lane, N_INSTANCES, STRIDE, TOTAL);
            assert_eq!(rc, cols[POSEIDON_COL_RC + lane]);
        }
    }

    #[test]
    fn perm_public_columns_row_major_declaration_shape() {
        const LOG_ROWS: usize = 14;
        const TOTAL: usize = 1 << LOG_ROWS;
        let publics = emit_perm_public_columns_row_major_at(DEFAULT_PERM_LAYOUT, 68, 128, TOTAL);
        assert_eq!(publics.len(), STATE_SIZE + 2);
        for p in &publics {
            assert_eq!(p.values.len(), TOTAL);
        }
    }

    #[test]
    fn perm_public_columns_reject_is_round_extension() {
        // Attempt to pretend the output row (`r = N_ROUNDS`) is still
        // an active round by flipping is_round to 1 there. Programme
        // forbids it — reject.
        use crate::{Air, CompositeAir, Trace};
        let input = mk_input(0xDEAD);
        let mut cols = build_perm_trace(input);
        cols[POSEIDON_COL_IS_ROUND][N_ROUNDS] = Block128::ONE;
        let air = CompositeAir::from_parts_with_publics(
            POSEIDON_PERM_LOG_ROWS,
            POSEIDON_PERM_N_COLS,
            emit_perm_all(),
            emit_perm_public_columns(),
        );
        assert!(!air.check(&Trace::new(cols)));
    }
}
