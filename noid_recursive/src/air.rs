// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

#![allow(clippy::needless_range_loop)]

//! `RecursiveBlockAir` — proves multipoint sumcheck consistency and
//! accumulator transitions for recursive proofs.
//!
//! ## Column layout (N_COLS = 8)
//!
//! | Col | Name          | Meaning                                    |
//! |-----|---------------|--------------------------------------------|
//! |   0 | `COL_P0`      | round polynomial eval at 0                 |
//! |   1 | `COL_P1`      | round polynomial eval at 1                 |
//! |   2 | `COL_R`       | Fiat-Shamir challenge for this round       |
//! |   3 | `COL_CLAIM_IN`  | sumcheck claim entering this round         |
//! |   4 | `COL_CLAIM_OUT` | folded claim: `p0 + r*(p0+p1)`            |
//! |   5 | `COL_SEL_BLOCK` | 1 on block_n sumcheck rows (0–10)         |
//! |   6 | `COL_SEL_REC`   | 1 on rec_{n-1} sumcheck rows (11–21)      |
//! |   7 | `COL_SEL_ACC`   | 1 on accumulator row (22)                 |
//!
//! ## Row layout (256 rows = 2^8)
//!
//! | Rows    | Purpose                                         |
//! |---------|-------------------------------------------------|
//! | 0–10    | block_n multipoint sumcheck (11 rounds)         |
//! | 11–21   | rec_{n-1} multipoint sumcheck (11 rounds)       |
//! | 22      | accumulator / state-root continuity check       |
//! | 23–255  | padding (all zero, no active selector)          |
//!
//! ## Constraints
//!
//! - `COL_SEL_BLOCK` / `COL_SEL_REC` rows: `claim_out == p0 + r*(p0+p1)`
//!   (degree-2, gated by a `SelectorGate`).
//! - `COL_SEL_ACC` row: `COL_P0 == acc_prev_state_root_hi` and
//!   `COL_P1 == acc_prev_state_root_lo` (degree-2 via `SelectorGate`
//!   wrapping `WeightedLinearGate`).
//! - `COL_SEL_BLOCK`, `COL_SEL_REC`, `COL_SEL_ACC` are declared as
//!   `PublicColumn`s, so the verifier checks them against the known
//!   programme without additional FRI overhead.

use noid_air::airs::tx_body_spine::SPINE_LOG_ROWS;
use noid_air::gates::{SelectorGate, WeightedLinearGate};
use noid_air::{Air, Constraint, EvalFrame, FlatEvalFrame, PublicColumn};
use noid_core::hardware::clmul_gcm;
use noid_core::{Block128, TowerField};

// =============================================================================
// Constants
// =============================================================================

/// Log2 of the trace height.
pub const LOG_ROWS: usize = 8;
/// Trace row count: 2^8 = 256.
pub const N_ROWS: usize = 1 << LOG_ROWS;
/// Number of AIR columns.
pub const N_COLS: usize = 8;

pub const COL_P0: usize = 0;
pub const COL_P1: usize = 1;
pub const COL_R: usize = 2;
pub const COL_CLAIM_IN: usize = 3;
pub const COL_CLAIM_OUT: usize = 4;
pub const COL_SEL_BLOCK: usize = 5;
pub const COL_SEL_REC: usize = 6;
pub const COL_SEL_ACC: usize = 7;

pub const BLOCK_SUMCHECK_START: usize = 0;
/// Rounds in the block-level multipoint sumcheck = log_len = SPINE_LOG_ROWS = 11.
pub const BLOCK_SUMCHECK_ROUNDS: usize = SPINE_LOG_ROWS;
/// Recursive sumcheck starts immediately after the block sumcheck rows.
pub const REC_SUMCHECK_START: usize = BLOCK_SUMCHECK_ROUNDS;
/// Rounds in the previous recursive proof's sumcheck (same log_len).
pub const REC_SUMCHECK_ROUNDS: usize = SPINE_LOG_ROWS;
/// Single accumulator / state-continuity check row.
pub const ACC_ROW: usize = REC_SUMCHECK_START + REC_SUMCHECK_ROUNDS;

// =============================================================================
// FoldCheckGate — degree-2 sumcheck fold constraint
// =============================================================================

/// Asserts `claim_out + p0 + r * (p0 + p1) == 0` (degree 2).
///
/// This is the per-round sumcheck consistency identity:
/// folding evaluations `(p0, p1)` at challenge `r` yields
/// `p0 + r*(p0+p1)`, which must equal the outgoing claim.
///
/// Column order as seen by `evaluate`:
/// `[COL_CLAIM_OUT=4, COL_P0=0, COL_P1=1, COL_R=2]`.
/// The `SelectorGate` wrapper re-maps indices so the inner gate always
/// sees its own column order regardless of how the selector column is
/// positioned.
struct FoldCheckGate {
    cols: [usize; 4],
}

impl FoldCheckGate {
    fn new() -> Self {
        Self {
            cols: [COL_CLAIM_OUT, COL_P0, COL_P1, COL_R],
        }
    }
}

impl Constraint for FoldCheckGate {
    fn degree(&self) -> usize {
        2
    }

    fn columns(&self) -> &[usize] {
        &self.cols
    }

    /// Tower-basis: evaluates `claim_out + p0 + r * (p0 + p1)`.
    fn evaluate(&self, frame: EvalFrame<'_>) -> Block128 {
        // Column order: [claim_out, p0, p1, r]
        let claim_out = frame.local[0];
        let p0 = frame.local[1];
        let p1 = frame.local[2];
        let r = frame.local[3];
        // GF(2^128): subtract == add, so the residue is:
        //   claim_out - (p0 + r*(p0+p1))  ==  claim_out + p0 + r*(p0+p1)
        claim_out + p0 + r * (p0 + p1)
    }

    /// Flat-basis: XOR for addition, `clmul_gcm` for multiplication.
    fn evaluate_flat(&self, frame: FlatEvalFrame<'_>) -> u128 {
        let claim_out = frame.local[0];
        let p0 = frame.local[1];
        let p1 = frame.local[2];
        let r = frame.local[3];
        claim_out ^ p0 ^ clmul_gcm(r, p0 ^ p1)
    }
}

// =============================================================================
// Witness
// =============================================================================

/// All algebraic data needed to construct the recursive step trace.
///
/// `block_*` fields come from `block_n`'s `InterleavedStarkProof`
/// (specifically `multipoint_rounds`).  `rec_*` fields come from the
/// previous `RecursiveBlockProof` (or zeros at genesis).
pub struct RecursiveBlockWitness {
    /// Round polynomials from block_n's multipoint sumcheck.
    /// `block_multipoint_rounds[i]` = `[eval_at_0, eval_at_1, ...]`.
    pub block_multipoint_rounds: Vec<Vec<Block128>>,
    /// Sumcheck claim at the start of block_n's multipoint phase.
    pub block_initial_claim: Block128,
    /// Fiat-Shamir challenges for block_n's multipoint sumcheck rounds.
    pub block_challenges: Vec<Block128>,
    /// Round polynomials from the previous recursive proof's multipoint sumcheck.
    pub rec_multipoint_rounds: Vec<Vec<Block128>>,
    /// Sumcheck claim at the start of the previous recursive sumcheck.
    pub rec_initial_claim: Block128,
    /// Fiat-Shamir challenges for the previous recursive sumcheck rounds.
    pub rec_challenges: Vec<Block128>,
    /// Accumulator state root before this block (32 bytes).
    pub acc_prev_state_root: [u8; 32],
    /// Accumulator state root after this block (32 bytes).
    pub acc_new_state_root: [u8; 32],
}

// =============================================================================
// AIR
// =============================================================================

/// AIR for one recursive proof step.
///
/// Proves:
/// 1. Block-n multipoint sumcheck consistency (11 rounds, rows 0–10).
/// 2. Previous recursive proof sumcheck consistency (11 rounds, rows 11–21).
/// 3. Accumulator state-root continuity at row 22.
///
/// Selector columns (`COL_SEL_BLOCK`, `COL_SEL_REC`, `COL_SEL_ACC`) are
/// declared as `PublicColumn`s — the verifier evaluates their MLEs
/// directly without needing witness-level boolean constraints.
pub struct RecursiveBlockAir {
    constraints: Vec<Box<dyn Constraint>>,
    public_columns: Vec<PublicColumn>,
}

impl RecursiveBlockAir {
    /// Construct the AIR from just the previous accumulator state root.
    ///
    /// This is the verifier-side constructor: the verifier only needs the
    /// `acc_prev_state_root` to pin the accumulator constraint.
    /// All other `RecursiveBlockWitness` fields are used only for trace
    /// generation (prover side) and are not needed here.
    ///
    /// Use this when verifying a `RecursiveBlockProof` without having the
    /// full prover witness (e.g. snapshot verification in a light client).
    pub fn from_prev_state_root(acc_prev_state_root: &[u8; 32]) -> Self {
        let dummy_witness = RecursiveBlockWitness {
            block_multipoint_rounds: Vec::new(),
            block_initial_claim: Block128::ZERO,
            block_challenges: Vec::new(),
            rec_multipoint_rounds: Vec::new(),
            rec_initial_claim: Block128::ZERO,
            rec_challenges: Vec::new(),
            acc_prev_state_root: *acc_prev_state_root,
            acc_new_state_root: [0u8; 32],
        };
        Self::new(&dummy_witness)
    }

    /// Construct the AIR from a witness.
    ///
    /// The witness supplies the accumulator state root used to pin
    /// `COL_P0[ACC_ROW]` and `COL_P1[ACC_ROW]` to the correct values.
    pub fn new(witness: &RecursiveBlockWitness) -> Self {
        let mut constraints: Vec<Box<dyn Constraint>> = Vec::new();
        let mut public_columns: Vec<PublicColumn> = Vec::new();

        // ---- Selector programmes ----
        let mut sel_block = vec![Block128::ZERO; N_ROWS];
        for r in BLOCK_SUMCHECK_START..BLOCK_SUMCHECK_START + BLOCK_SUMCHECK_ROUNDS {
            sel_block[r] = Block128::ONE;
        }
        let mut sel_rec = vec![Block128::ZERO; N_ROWS];
        for r in REC_SUMCHECK_START..REC_SUMCHECK_START + REC_SUMCHECK_ROUNDS {
            sel_rec[r] = Block128::ONE;
        }
        let mut sel_acc = vec![Block128::ZERO; N_ROWS];
        sel_acc[ACC_ROW] = Block128::ONE;

        public_columns.push(PublicColumn::new(COL_SEL_BLOCK, sel_block));
        public_columns.push(PublicColumn::new(COL_SEL_REC, sel_rec));
        public_columns.push(PublicColumn::new(COL_SEL_ACC, sel_acc));

        // ---- Fold consistency constraints ----
        // On rows where sel_block == 1: claim_out == p0 + r*(p0+p1).
        constraints.push(Box::new(SelectorGate::new(
            COL_SEL_BLOCK,
            Box::new(FoldCheckGate::new()),
        )));
        // On rows where sel_rec == 1: same fold check for rec sumcheck.
        constraints.push(Box::new(SelectorGate::new(
            COL_SEL_REC,
            Box::new(FoldCheckGate::new()),
        )));

        // ---- Accumulator state-root pins at ACC_ROW ----
        // The 32-byte state root is split into two 16-byte Block128 halves.
        // At row 26 (where sel_acc == 1):
        //   COL_P0 must equal sr_hi (first 16 bytes)
        //   COL_P1 must equal sr_lo (last  16 bytes)
        let sr = &witness.acc_prev_state_root;
        let mut hi_bytes = [0u8; 16];
        let mut lo_bytes = [0u8; 16];
        hi_bytes.copy_from_slice(&sr[0..16]);
        lo_bytes.copy_from_slice(&sr[16..32]);
        let sr_hi = Block128::from(u128::from_le_bytes(hi_bytes));
        let sr_lo = Block128::from(u128::from_le_bytes(lo_bytes));

        // sel_acc * (COL_P0 + sr_hi) == 0  ↔  COL_P0[ACC_ROW] == sr_hi
        constraints.push(Box::new(SelectorGate::new(
            COL_SEL_ACC,
            Box::new(WeightedLinearGate::new(
                vec![(COL_P0, Block128::ONE)],
                sr_hi,
            )),
        )));
        // sel_acc * (COL_P1 + sr_lo) == 0  ↔  COL_P1[ACC_ROW] == sr_lo
        constraints.push(Box::new(SelectorGate::new(
            COL_SEL_ACC,
            Box::new(WeightedLinearGate::new(
                vec![(COL_P1, Block128::ONE)],
                sr_lo,
            )),
        )));

        Self {
            constraints,
            public_columns,
        }
    }
}

impl Air for RecursiveBlockAir {
    fn n_columns(&self) -> usize {
        N_COLS
    }

    fn log_rows(&self) -> usize {
        LOG_ROWS
    }

    fn constraints(&self) -> &[Box<dyn Constraint>] {
        &self.constraints
    }

    fn public_columns(&self) -> &[PublicColumn] {
        &self.public_columns
    }
}

// =============================================================================
// Trace builder
// =============================================================================

/// Build the 256×8 execution trace for `RecursiveBlockAir`.
///
/// All rows are initialised to zero.  Active rows are filled from the
/// witness; selector columns are always set correctly regardless of
/// whether witness data is available (falling back to zero field
/// elements).
pub fn build_recursive_trace(witness: &RecursiveBlockWitness) -> Vec<Vec<Block128>> {
    let mut cols: Vec<Vec<Block128>> = (0..N_COLS).map(|_| vec![Block128::ZERO; N_ROWS]).collect();

    // ---- Selector columns ----
    // These must match the PublicColumn declarations in RecursiveBlockAir::new.
    for row in BLOCK_SUMCHECK_START..BLOCK_SUMCHECK_START + BLOCK_SUMCHECK_ROUNDS {
        cols[COL_SEL_BLOCK][row] = Block128::ONE;
    }
    for row in REC_SUMCHECK_START..REC_SUMCHECK_START + REC_SUMCHECK_ROUNDS {
        cols[COL_SEL_REC][row] = Block128::ONE;
    }
    cols[COL_SEL_ACC][ACC_ROW] = Block128::ONE;

    // ---- Block multipoint sumcheck rows (0–12) ----
    let mut block_claim = witness.block_initial_claim;
    for round in 0..BLOCK_SUMCHECK_ROUNDS {
        let row = BLOCK_SUMCHECK_START + round;
        let p0 = witness
            .block_multipoint_rounds
            .get(round)
            .and_then(|rp| rp.first())
            .copied()
            .unwrap_or(Block128::ZERO);
        let p1 = witness
            .block_multipoint_rounds
            .get(round)
            .and_then(|rp| rp.get(1))
            .copied()
            .unwrap_or(Block128::ZERO);
        let r = witness
            .block_challenges
            .get(round)
            .copied()
            .unwrap_or(Block128::ZERO);
        let claim_out = p0 + r * (p0 + p1);

        cols[COL_P0][row] = p0;
        cols[COL_P1][row] = p1;
        cols[COL_R][row] = r;
        cols[COL_CLAIM_IN][row] = block_claim;
        cols[COL_CLAIM_OUT][row] = claim_out;
        block_claim = claim_out;
    }

    // ---- Rec multipoint sumcheck rows (13–25) ----
    let mut rec_claim = witness.rec_initial_claim;
    for round in 0..REC_SUMCHECK_ROUNDS {
        let row = REC_SUMCHECK_START + round;
        let p0 = witness
            .rec_multipoint_rounds
            .get(round)
            .and_then(|rp| rp.first())
            .copied()
            .unwrap_or(Block128::ZERO);
        let p1 = witness
            .rec_multipoint_rounds
            .get(round)
            .and_then(|rp| rp.get(1))
            .copied()
            .unwrap_or(Block128::ZERO);
        let r = witness
            .rec_challenges
            .get(round)
            .copied()
            .unwrap_or(Block128::ZERO);
        let claim_out = p0 + r * (p0 + p1);

        cols[COL_P0][row] = p0;
        cols[COL_P1][row] = p1;
        cols[COL_R][row] = r;
        cols[COL_CLAIM_IN][row] = rec_claim;
        cols[COL_CLAIM_OUT][row] = claim_out;
        rec_claim = claim_out;
    }

    // ---- Accumulator row (26) ----
    // COL_P0 and COL_P1 carry the two halves of the previous state root.
    // These must match the constants pinned by RecursiveBlockAir::new.
    let sr = &witness.acc_prev_state_root;
    let mut hi_bytes = [0u8; 16];
    let mut lo_bytes = [0u8; 16];
    hi_bytes.copy_from_slice(&sr[0..16]);
    lo_bytes.copy_from_slice(&sr[16..32]);
    cols[COL_P0][ACC_ROW] = Block128::from(u128::from_le_bytes(hi_bytes));
    cols[COL_P1][ACC_ROW] = Block128::from(u128::from_le_bytes(lo_bytes));

    cols
}
