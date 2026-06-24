// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

#![allow(clippy::needless_range_loop)]

//! `RecursiveBlockAir` — proves multipoint sumcheck consistency and
//! accumulator transitions for recursive proofs.
//!
//! ## Column layout (N_COLS = 10)
//!
//! | Col | Name                  | Meaning                                      |
//! |-----|-----------------------|----------------------------------------------|
//! |   0 | `COL_P0`              | round polynomial eval at 0                   |
//! |   1 | `COL_P1`              | round polynomial eval at 1                   |
//! |   2 | `COL_P2`              | round polynomial eval at 2                   |
//! |   3 | `COL_R`               | Fiat-Shamir challenge for this round         |
//! |   4 | `COL_CLAIM_IN`        | sumcheck claim entering this round           |
//! |   5 | `COL_CLAIM_OUT`       | folded claim: `Lagrange([p0,p1,p2], r)`      |
//! |   6 | `COL_SEL_BLOCK`       | 1 on primary block bucket rows (0–10)        |
//! |   7 | `COL_SEL_BLOCK_SECONDARY` | 1 on secondary bucket rows (11–21)       |
//! |   8 | `COL_SEL_REC`         | 1 on rec_{n-1} sumcheck rows (22–29)         |
//! |   9 | `COL_SEL_ACC`         | 1 on accumulator row (30)                    |
//!
//! ## Row layout (256 rows = 2^8)
//!
//! | Rows    | Purpose                                         |
//! |---------|-------------------------------------------------|
//! | 0–10    | primary block bucket multipoint sumcheck        |
//! | 11–21   | secondary block bucket multipoint sumcheck      |
//! | 22–29   | rec_{n-1} recursive-STARK multipoint sumcheck   |
//! | 30      | accumulator / state-root continuity check       |
//! | 31–255  | padding (all zero, no active selector)          |
//!
//! ## Constraints
//!
//! - Bucket/recursive sumcheck rows: `claim_in == p0 + p1` and
//!   `claim_out == Lagrange([p0,p1,p2], r)` for the degree-2 sumcheck round
//!   polynomial (degree-3 in active witness columns, then gated by `SelectorGate`).
//! - `COL_SEL_ACC` row: `COL_P0 == acc_prev_state_root_hi` and
//!   `COL_P1 == acc_prev_state_root_lo` (degree-2 via `SelectorGate`
//!   wrapping `WeightedLinearGate`).
//! - Selector columns are declared as `PublicColumn`s, so the verifier checks
//!   them against the known programme without additional FRI overhead.

use noid_air::airs::tx_body_spine::SPINE_LOG_ROWS;
use noid_air::gates::{SelectorGate, WeightedLinearGate};
use noid_air::{Air, Constraint, EvalFrame, FlatEvalFrame, PublicColumn};
use noid_core::{Block128, TowerField};

// =============================================================================
// Constants
// =============================================================================

/// Log2 of the trace height.
pub const LOG_ROWS: usize = 8;
/// Trace row count: 2^8 = 256.
pub const N_ROWS: usize = 1 << LOG_ROWS;
/// Number of AIR columns.
pub const N_COLS: usize = 10;

pub const COL_P0: usize = 0;
pub const COL_P1: usize = 1;
pub const COL_P2: usize = 2;
pub const COL_R: usize = 3;
pub const COL_CLAIM_IN: usize = 4;
pub const COL_CLAIM_OUT: usize = 5;
pub const COL_SEL_BLOCK: usize = 6;
pub const COL_SEL_BLOCK_SECONDARY: usize = 7;
pub const COL_SEL_REC: usize = 8;
pub const COL_SEL_ACC: usize = 9;

pub const BLOCK_SUMCHECK_START: usize = 0;
/// Rounds in each block-level bucket multipoint sumcheck = log_len = SPINE_LOG_ROWS = 11.
pub const BLOCK_SUMCHECK_ROUNDS: usize = SPINE_LOG_ROWS;
/// Secondary block bucket sumcheck starts immediately after the primary bucket rows.
pub const BLOCK_SECONDARY_SUMCHECK_START: usize = BLOCK_SUMCHECK_START + BLOCK_SUMCHECK_ROUNDS;
/// Recursive sumcheck starts immediately after both block bucket sumcheck lanes.
pub const REC_SUMCHECK_START: usize = BLOCK_SECONDARY_SUMCHECK_START + BLOCK_SUMCHECK_ROUNDS;
/// Rounds in the previous recursive proof's multipoint sumcheck.
///
/// Block bucket proofs replay `SPINE_LOG_ROWS` rounds, but a recursive proof is
/// itself proven over `RecursiveBlockAir::LOG_ROWS`, so its interleaved STARK
/// multipoint transcript has `padded_log_len(LOG_ROWS) == LOG_ROWS` rounds.
/// Keeping this at `SPINE_LOG_ROWS` leaves active rec-lane rows after the
/// previous proof's transcript ends, producing invalid recursive proofs that
/// late-join snapshot verification rejects with `ZeroCheckFailed`.
pub const REC_SUMCHECK_ROUNDS: usize = LOG_ROWS;
/// Single accumulator / state-continuity check row.
pub const ACC_ROW: usize = REC_SUMCHECK_START + REC_SUMCHECK_ROUNDS;

// =============================================================================
// FoldCheckGate — degree-2 sumcheck fold constraint
// =============================================================================

/// Asserts `claim_in + p0 + p1 == 0`.
///
/// This is the sumcheck round boundary identity: the incoming claim must equal
/// the round polynomial's Boolean-hypercube sum `rp(0) + rp(1)`.
struct ClaimInCheckGate {
    cols: [usize; 3],
}

impl ClaimInCheckGate {
    fn new() -> Self {
        Self {
            cols: [COL_CLAIM_IN, COL_P0, COL_P1],
        }
    }
}

impl Constraint for ClaimInCheckGate {
    fn degree(&self) -> usize {
        1
    }

    fn columns(&self) -> &[usize] {
        &self.cols
    }

    fn evaluate(&self, frame: EvalFrame<'_>) -> Block128 {
        let claim_in = frame.local[0];
        let p0 = frame.local[1];
        let p1 = frame.local[2];
        claim_in + p0 + p1
    }

    fn evaluate_flat(&self, frame: FlatEvalFrame<'_>) -> u128 {
        let claim_in = frame.local[0];
        let p0 = frame.local[1];
        let p1 = frame.local[2];
        claim_in ^ p0 ^ p1
    }
}

/// Asserts `claim_out == Lagrange([p0, p1, p2], r)`.
///
/// Bucket multipoint sumcheck rounds are degree-2 polynomials represented by
/// evaluations at X ∈ {0,1,2}. The outgoing claim is the Lagrange evaluation of
/// that degree-2 polynomial at the Fiat-Shamir challenge `r`.
///
/// Column order as seen by `evaluate`:
/// `[COL_CLAIM_OUT, COL_P0, COL_P1, COL_P2, COL_R]`.
/// The `SelectorGate` wrapper re-maps indices so the inner gate always
/// sees its own column order regardless of how the selector column is
/// positioned.
struct FoldCheckGate {
    cols: [usize; 5],
}

impl FoldCheckGate {
    fn new() -> Self {
        Self {
            cols: [COL_CLAIM_OUT, COL_P0, COL_P1, COL_P2, COL_R],
        }
    }
}

fn lagrange3(p: [Block128; 3], target: Block128) -> Block128 {
    let xs = [
        Block128::from(0u8),
        Block128::from(1u8),
        Block128::from(2u8),
    ];
    let mut acc = Block128::ZERO;
    for k in 0..3 {
        let mut num = Block128::ONE;
        let mut den = Block128::ONE;
        for m in 0..3 {
            if m == k {
                continue;
            }
            num *= target + xs[m];
            den *= xs[k] + xs[m];
        }
        acc += p[k] * num * den.invert();
    }
    acc
}

impl Constraint for FoldCheckGate {
    fn degree(&self) -> usize {
        3
    }

    fn columns(&self) -> &[usize] {
        &self.cols
    }

    /// Tower-basis: evaluates `claim_out + Lagrange([p0,p1,p2], r)`.
    fn evaluate(&self, frame: EvalFrame<'_>) -> Block128 {
        let claim_out = frame.local[0];
        let p0 = frame.local[1];
        let p1 = frame.local[2];
        let p2 = frame.local[3];
        let r = frame.local[4];
        claim_out + lagrange3([p0, p1, p2], r)
    }

    /// Flat-basis wrapper. Recursive traces are tiny, so convert through tower
    /// basis instead of duplicating the degree-2 interpolation arithmetic here.
    fn evaluate_flat(&self, frame: FlatEvalFrame<'_>) -> u128 {
        use noid_core::hardware::{flat_to_tower_u128, tower_to_flat_u128};
        let claim_out = Block128::from(flat_to_tower_u128(frame.local[0]));
        let p0 = Block128::from(flat_to_tower_u128(frame.local[1]));
        let p1 = Block128::from(flat_to_tower_u128(frame.local[2]));
        let p2 = Block128::from(flat_to_tower_u128(frame.local[3]));
        let r = Block128::from(flat_to_tower_u128(frame.local[4]));
        tower_to_flat_u128((claim_out + lagrange3([p0, p1, p2], r)).0)
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
    /// Round polynomials from block_n's secondary bucket multipoint sumcheck.
    /// All-zero for single-shape blocks.
    pub block_secondary_multipoint_rounds: Vec<Vec<Block128>>,
    /// Sumcheck claim at the start of block_n's secondary bucket multipoint phase.
    /// ZERO for single-shape blocks.
    pub block_secondary_initial_claim: Block128,
    /// Fiat-Shamir challenges for block_n's secondary bucket multipoint rounds.
    /// All-zero for single-shape blocks.
    pub block_secondary_challenges: Vec<Block128>,
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
/// 1. Primary block bucket multipoint sumcheck consistency (rows 0–10).
/// 2. Secondary block bucket multipoint sumcheck consistency (rows 11–21).
/// 3. Previous recursive proof sumcheck consistency (rows 22–32).
/// 4. Accumulator state-root continuity at row 33.
///
/// Selector columns are declared as `PublicColumn`s — the verifier evaluates
/// their MLEs directly without needing witness-level boolean constraints.
pub struct RecursiveBlockAir {
    constraints: Vec<Box<dyn Constraint>>,
    public_columns: Vec<PublicColumn>,
}

impl RecursiveBlockAir {
    /// Number of AIR constraints:
    /// 3 × ClaimInCheckGate (primary block + secondary block + rec sumcheck)
    /// + 3 × FoldCheckGate (primary block + secondary block + rec sumcheck)
    /// + 2 × WeightedLinearGate (acc hi/lo).
    ///
    /// Used by `derive_rec_multipoint_replay` to replay the FS channel correctly.
    pub const N_CONSTRAINTS: usize = 8;

    /// Construct the AIR from just the previous accumulator state root.
    ///
    /// This is the verifier-side constructor: the verifier only needs the
    /// `acc_prev_state_root` to pin the accumulator constraint.
    /// All other `RecursiveBlockWitness` fields are used only for trace
    /// generation (prover side) and are not needed here.
    ///
    /// Use this when verifying a `RecursiveBlockProof` without having the
    /// full prover witness (e.g. snapshot verification during sync).
    pub fn from_prev_state_root(acc_prev_state_root: &[u8; 32]) -> Self {
        let dummy_witness = RecursiveBlockWitness {
            block_multipoint_rounds: Vec::new(),
            block_initial_claim: Block128::ZERO,
            block_challenges: Vec::new(),
            block_secondary_multipoint_rounds: Vec::new(),
            block_secondary_initial_claim: Block128::ZERO,
            block_secondary_challenges: Vec::new(),
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
        let mut sel_block_secondary = vec![Block128::ZERO; N_ROWS];
        for r in
            BLOCK_SECONDARY_SUMCHECK_START..BLOCK_SECONDARY_SUMCHECK_START + BLOCK_SUMCHECK_ROUNDS
        {
            sel_block_secondary[r] = Block128::ONE;
        }
        let mut sel_rec = vec![Block128::ZERO; N_ROWS];
        for r in REC_SUMCHECK_START..REC_SUMCHECK_START + REC_SUMCHECK_ROUNDS {
            sel_rec[r] = Block128::ONE;
        }
        let mut sel_acc = vec![Block128::ZERO; N_ROWS];
        sel_acc[ACC_ROW] = Block128::ONE;

        public_columns.push(PublicColumn::new(COL_SEL_BLOCK, sel_block));
        public_columns.push(PublicColumn::new(
            COL_SEL_BLOCK_SECONDARY,
            sel_block_secondary,
        ));
        public_columns.push(PublicColumn::new(COL_SEL_REC, sel_rec));
        public_columns.push(PublicColumn::new(COL_SEL_ACC, sel_acc));

        // ---- Sumcheck round consistency constraints ----
        // On active rows: incoming claim equals rp(0)+rp(1), then folds to
        // claim_out at the Fiat-Shamir challenge r.
        constraints.push(Box::new(SelectorGate::new(
            COL_SEL_BLOCK,
            Box::new(ClaimInCheckGate::new()),
        )));
        constraints.push(Box::new(SelectorGate::new(
            COL_SEL_BLOCK,
            Box::new(FoldCheckGate::new()),
        )));
        constraints.push(Box::new(SelectorGate::new(
            COL_SEL_BLOCK_SECONDARY,
            Box::new(ClaimInCheckGate::new()),
        )));
        constraints.push(Box::new(SelectorGate::new(
            COL_SEL_BLOCK_SECONDARY,
            Box::new(FoldCheckGate::new()),
        )));
        constraints.push(Box::new(SelectorGate::new(
            COL_SEL_REC,
            Box::new(ClaimInCheckGate::new()),
        )));
        constraints.push(Box::new(SelectorGate::new(
            COL_SEL_REC,
            Box::new(FoldCheckGate::new()),
        )));

        // ---- Accumulator state-root pins at ACC_ROW ----
        // The 32-byte state root is split into two 16-byte Block128 halves.
        // At row 22 (where sel_acc == 1):
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

fn fill_sumcheck_lane(
    cols: &mut [Vec<Block128>],
    start_row: usize,
    rounds_len: usize,
    rounds: &[Vec<Block128>],
    initial_claim: Block128,
    challenges: &[Block128],
) {
    let mut claim = initial_claim;
    for round in 0..rounds_len {
        let row = start_row + round;
        let p0 = rounds
            .get(round)
            .and_then(|rp| rp.first())
            .copied()
            .unwrap_or(Block128::ZERO);
        let p1 = rounds
            .get(round)
            .and_then(|rp| rp.get(1))
            .copied()
            .unwrap_or(Block128::ZERO);
        let p2 = rounds
            .get(round)
            .and_then(|rp| rp.get(2))
            .copied()
            .unwrap_or(Block128::ZERO);
        let r = challenges.get(round).copied().unwrap_or(Block128::ZERO);
        let claim_out = lagrange3([p0, p1, p2], r);

        cols[COL_P0][row] = p0;
        cols[COL_P1][row] = p1;
        cols[COL_P2][row] = p2;
        cols[COL_R][row] = r;
        cols[COL_CLAIM_IN][row] = claim;
        cols[COL_CLAIM_OUT][row] = claim_out;
        claim = claim_out;
    }
}

/// Build the 256×10 execution trace for `RecursiveBlockAir`.
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
    for row in
        BLOCK_SECONDARY_SUMCHECK_START..BLOCK_SECONDARY_SUMCHECK_START + BLOCK_SUMCHECK_ROUNDS
    {
        cols[COL_SEL_BLOCK_SECONDARY][row] = Block128::ONE;
    }
    for row in REC_SUMCHECK_START..REC_SUMCHECK_START + REC_SUMCHECK_ROUNDS {
        cols[COL_SEL_REC][row] = Block128::ONE;
    }
    cols[COL_SEL_ACC][ACC_ROW] = Block128::ONE;

    fill_sumcheck_lane(
        &mut cols,
        BLOCK_SUMCHECK_START,
        BLOCK_SUMCHECK_ROUNDS,
        &witness.block_multipoint_rounds,
        witness.block_initial_claim,
        &witness.block_challenges,
    );
    fill_sumcheck_lane(
        &mut cols,
        BLOCK_SECONDARY_SUMCHECK_START,
        BLOCK_SUMCHECK_ROUNDS,
        &witness.block_secondary_multipoint_rounds,
        witness.block_secondary_initial_claim,
        &witness.block_secondary_challenges,
    );
    fill_sumcheck_lane(
        &mut cols,
        REC_SUMCHECK_START,
        REC_SUMCHECK_ROUNDS,
        &witness.rec_multipoint_rounds,
        witness.rec_initial_claim,
        &witness.rec_challenges,
    );

    // ---- Accumulator row ----
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
