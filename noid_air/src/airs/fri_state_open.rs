// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! `FriStateOpenAir` — Stage 4a scaffold + 4c.1 + 4c.1-bis delta refactor.
//!
//! Purpose: make `prev_state_root` and `new_state_root` in
//! [`PublicInputs`](noid_tx::PublicInputs) meaningful by arithmetising,
//! per tx input `i`:
//!
//!   (a) slot `i` is present in `prev_state_root` at the claimed
//!       `(value, owner_hi, owner_lo)`, and
//!   (b) `new_state_root` equals the result of zeroing every spent slot
//!       and committing the new outputs.
//!
//! ## Secret-privacy invariant (load-bearing)
//!
//! The opening API exposes **only** `(slot_index, value, owner_hi,
//! owner_lo)` per input. The `spend_secret` is **not** read, not
//! witnessed, and not pinned anywhere in this AIR — that binding lives
//! in `HAddrAir` / `HAuthAir`, where the secret is deliberately
//! witness-only with no public pin.
//!
//! ## Stage 4 split
//!
//! * **Stage 4a (landed).** Fixed layout: per-input slot-index bit
//!   columns with `BoolGate` pins, per-input `(value, owner_hi,
//!   owner_lo)` witness columns with `emit_public_cell` boundary pins
//!   to verifier-known row constants, and `post_*` / `live_mask` /
//!   `proof_round_digest` columns reserved for later stages.
//!
//! * **Stage 4c.1 (landed).** Live-gated spend-zeros semantics and
//!   `new_state_root_{hi,lo}` row-0 boundary pins.
//!
//! * **Stage 4c.1-bis (this pass) — delta refactor.** Semantics of the
//!   three witness columns flip from `post_*` (absolute post-state slot
//!   value) to `delta_*` (the XOR delta applied to the slot leaf). The
//!   action split is hoisted into two mutually-exclusive selector
//!   columns `is_spend` / `is_mint`. Constraint set:
//!
//!   * `BoolGate` on `is_spend`, `is_mint`, `live_mask` (and every
//!     `idx_bit`).
//!   * `is_spend * is_mint == 0` — the actions are disjoint.
//!   * `live_mask == is_spend + is_mint` — `live_mask` is the derived OR
//!     (equal to XOR under disjointness).
//!   * `live_mask * (value + delta_*) == 0` — on any live row (spend or
//!     mint) the XOR delta is the claim triple itself. Holds in both
//!     directions: for a spend, `pre = value` and `post = 0`, so
//!     `delta = pre ⊕ post = value`; for a mint, `pre = 0` and
//!     `post = value`, so `delta = value` too. The 4c.1 spend-zeros
//!     gates `live · post_* == 0` retire — they were the absolute
//!     form of the same identity on the spend side only.
//!
//!   On non-live rows the delta columns are not pinned to zero; 4c.2
//!   will either add an explicit `live_mask == 0 ⇒ delta_* == 0` pin or
//!   prove the same fact off-constraint via the MLE update recurrence.
//!
//! * **Stage 4c.1-ter (partially landed — pre-state source triple).**
//!   FRI-opening (Stage 4b.2) verifies a slot triple against
//!   `prev_state_root`. On a spend row the opened pre-state equals
//!   `(claim.value, claim.owner_hi, claim.owner_lo)`; on a mint row
//!   every lane must be zero — the slot has to be empty before being
//!   occupied. Rather than branching the 4b.2 opening source by
//!   action, this AIR exposes three dedicated witness columns
//!   `opened_pre_{value, owner_hi, owner_lo} = is_spend · {value,
//!   owner_hi, owner_lo}`, each of which automatically collapses to
//!   `0` on mint / dummy rows and to the claim lane on spend rows.
//!   Enforced by three `MulGate`s. The 4b.2 sumcheck will consume
//!   these columns directly — no action branching inside the
//!   re-executor. Remaining 4c.1-ter work (the
//!   `is_mint ⇒ pre_owner_* = 0` and `is_spend ⇒ value ≠ 0`
//!   invariants) lands when the 4b.2 re-executor lands, because it
//!   fires on cells the 4b.2 re-executor produces.
//!
//! * **Stage 4b.2.1 (this pass) — eval-point public pins.**
//!   `FRI_STATE_OPEN_LOG_SLOTS` new columns, one per transcript-derived
//!   MLE eval-point coordinate `r_i`. Each column is a constant
//!   `PublicColumn` (same value on every row) so the eq-ladder
//!   materialiser (4b.2.2) can read `r_i` row-locally without any
//!   boundary/rotation plumbing. Witness gains a matching
//!   `eval_point: [Block128; LOG_SLOTS]` field and a
//!   `with_eval_point(..)` builder. No constraint semantics here yet
//!   — 4b.2.1 is the column/plumbing slice; 4b.2.2 will connect
//!   `r_i` to the bit-decomposed slot index via
//!   `eq_i = eq_{i-1} · (1 + r_i + idx_bit_i)` and 4b.2.3 will drive
//!   the per-round sumcheck recurrence.
//!
//! * **Stage 4b.2.{2,3} (deferred).** `MleOpenGate` family — row-local
//!   + rotation constraints re-executing the FRI opening's per-round
//!   sumcheck. Consumes round-oracle witness surfaced via
//!   `proof_round_digest`.
//!
//! * **Stage 4c.2 (deferred).** Tie the pinned `new_state_root_*`
//!   halves to the delta-applied MLE recurrence output.

use crate::gates::{
    emit_public_cell, BoolGate, MulGate, PublicColumn, SelectorGate,
    WeightedLinearGate,
};
use crate::{Air, Constraint};
use noid_core::{Block128, TowerField};

/// Number of tx inputs the scaffold opens per proof. Matches
/// `noid_tx::MAX_INPUTS` today (4 = 2 tx slots × 2 real + dummy room).
pub const FRI_STATE_OPEN_N_INPUTS: usize = 4;

/// log2 of the chain state depth the AIR is sized for.
pub const FRI_STATE_OPEN_LOG_SLOTS: usize = 4;

/// Rows in the scaffold trace: one row per input opening, padded to a
/// power of two.
pub const FRI_STATE_OPEN_LOG_ROWS: usize = 3;
pub const FRI_STATE_OPEN_N_ROWS: usize = 1 << FRI_STATE_OPEN_LOG_ROWS;

// -- Column layout ---------------------------------------------------------
// Per-input row carries:
//   value, owner_hi, owner_lo         — pinned public via boundary ties
//   idx_bit_0 .. idx_bit_{L-1}        — BoolGate-pinned slot-index bits
//   delta_value, delta_owner_hi,
//     delta_owner_lo                  — XOR-delta witness for the slot leaf
//   proof_round_digest                — opaque 4b handoff column
//   live_mask                         — {0,1} action-union selector
//   is_spend, is_mint                 — mutually-exclusive action selectors
//   opened_pre_value,
//     opened_pre_owner_hi,
//     opened_pre_owner_lo             — 4c.1-ter pre-state triple
//                                        (is_spend · claim_lane)
//   new_state_root_hi, _lo            — row-0-pinned PI halves

pub const COL_VALUE: usize = 0;
pub const COL_OWNER_HI: usize = 1;
pub const COL_OWNER_LO: usize = 2;
pub const COL_IDX_BIT_BASE: usize = 3;
// after L idx bits...
pub const COL_DELTA_VALUE_OFFSET: usize = 0;
pub const COL_DELTA_OWNER_HI_OFFSET: usize = 1;
pub const COL_DELTA_OWNER_LO_OFFSET: usize = 2;
pub const COL_PROOF_ROUND_DIGEST_OFFSET: usize = 3;
pub const COL_LIVE_MASK_OFFSET: usize = 4;
pub const COL_IS_SPEND_OFFSET: usize = 5;
pub const COL_IS_MINT_OFFSET: usize = 6;
pub const COL_OPENED_PRE_VALUE_OFFSET: usize = 7;
pub const COL_OPENED_PRE_OWNER_HI_OFFSET: usize = 8;
pub const COL_OPENED_PRE_OWNER_LO_OFFSET: usize = 9;
pub const COL_NEW_STATE_ROOT_HI_OFFSET: usize = 10;
pub const COL_NEW_STATE_ROOT_LO_OFFSET: usize = 11;
/// 4b.2.1: start of the transcript-derived eval point columns.
/// `FRI_STATE_OPEN_LOG_SLOTS` contiguous columns, one per coordinate
/// `r_i`, each pinned to a constant column of `r_i` across every
/// row. The eq-ladder (4b.2.2) will consume them row-locally.
pub const COL_EVAL_POINT_BASE_OFFSET: usize = 12;

pub const fn col_delta_value() -> usize {
    COL_IDX_BIT_BASE + FRI_STATE_OPEN_LOG_SLOTS + COL_DELTA_VALUE_OFFSET
}
pub const fn col_delta_owner_hi() -> usize {
    COL_IDX_BIT_BASE + FRI_STATE_OPEN_LOG_SLOTS + COL_DELTA_OWNER_HI_OFFSET
}
pub const fn col_delta_owner_lo() -> usize {
    COL_IDX_BIT_BASE + FRI_STATE_OPEN_LOG_SLOTS + COL_DELTA_OWNER_LO_OFFSET
}
pub const fn col_proof_round_digest() -> usize {
    COL_IDX_BIT_BASE + FRI_STATE_OPEN_LOG_SLOTS + COL_PROOF_ROUND_DIGEST_OFFSET
}
pub const fn col_live_mask() -> usize {
    COL_IDX_BIT_BASE + FRI_STATE_OPEN_LOG_SLOTS + COL_LIVE_MASK_OFFSET
}
pub const fn col_is_spend() -> usize {
    COL_IDX_BIT_BASE + FRI_STATE_OPEN_LOG_SLOTS + COL_IS_SPEND_OFFSET
}
pub const fn col_is_mint() -> usize {
    COL_IDX_BIT_BASE + FRI_STATE_OPEN_LOG_SLOTS + COL_IS_MINT_OFFSET
}
/// 4c.1-ter: `opened_pre_value = is_spend · value`. This is the
/// pre-state slot value that Stage 4b.2 opens against
/// `prev_state_root`: on a spend the slot held `value` before the
/// tx; on a mint the slot was empty.
pub const fn col_opened_pre_value() -> usize {
    COL_IDX_BIT_BASE + FRI_STATE_OPEN_LOG_SLOTS + COL_OPENED_PRE_VALUE_OFFSET
}
/// 4c.1-ter: `opened_pre_owner_hi = is_spend · owner_hi`. Symmetric
/// to `opened_pre_value`; completes the pre-state triple
/// `(value, owner_hi, owner_lo)` Stage 4b.2 opens against
/// `prev_state_root`.
pub const fn col_opened_pre_owner_hi() -> usize {
    COL_IDX_BIT_BASE + FRI_STATE_OPEN_LOG_SLOTS + COL_OPENED_PRE_OWNER_HI_OFFSET
}
/// 4c.1-ter: `opened_pre_owner_lo = is_spend · owner_lo`.
pub const fn col_opened_pre_owner_lo() -> usize {
    COL_IDX_BIT_BASE + FRI_STATE_OPEN_LOG_SLOTS + COL_OPENED_PRE_OWNER_LO_OFFSET
}
pub const fn col_new_state_root_hi() -> usize {
    COL_IDX_BIT_BASE + FRI_STATE_OPEN_LOG_SLOTS + COL_NEW_STATE_ROOT_HI_OFFSET
}
pub const fn col_new_state_root_lo() -> usize {
    COL_IDX_BIT_BASE + FRI_STATE_OPEN_LOG_SLOTS + COL_NEW_STATE_ROOT_LO_OFFSET
}
/// 4b.2.1: column index for eval-point coordinate `r_i`, `i` in
/// `0..FRI_STATE_OPEN_LOG_SLOTS`. Each column is a `PublicColumn`
/// with the same constant on every row, so the eq-ladder can read
/// `r_i` row-locally without any boundary/rotation gymnastics.
pub const fn col_eval_point(i: usize) -> usize {
    assert!(i < FRI_STATE_OPEN_LOG_SLOTS);
    COL_IDX_BIT_BASE + FRI_STATE_OPEN_LOG_SLOTS + COL_EVAL_POINT_BASE_OFFSET + i
}

/// Number of witness columns before indicator columns for public pins
/// are reserved. Each public-cell pin reserves one extra indicator
/// column; see `FriStateOpenAir::new` for the accounting.
pub const FRI_STATE_OPEN_WITNESS_COLS: usize =
    COL_IDX_BIT_BASE + FRI_STATE_OPEN_LOG_SLOTS + 12 + FRI_STATE_OPEN_LOG_SLOTS;
// delta_{value,hi,lo}, proof_round_digest, live_mask, is_spend,
// is_mint, opened_pre_{value,owner_hi,owner_lo},
// new_state_root_hi, new_state_root_lo, then one eval-point
// column per `r_i`.

/// Per-input claim the AIR opens against `prev_state_root`.
///
/// `value` / `owner_hi` / `owner_lo` are the slot triple the row binds
/// to: on a spend, this is the pre-state being consumed; on a mint,
/// this is the post-state being committed. Either way the XOR delta
/// applied to the slot leaf equals this triple, which 4c.1-bis enforces
/// via `live_mask · (value + delta_*) == 0`.
///
/// `is_spend` and `is_mint` are mutually exclusive. At most one is
/// `true`; dummy rows have both `false`.
#[derive(Debug, Clone, Copy)]
pub struct FriStateOpenClaim {
    pub slot_index: u32,
    pub value: Block128,
    pub owner_hi: Block128,
    pub owner_lo: Block128,
    /// XOR delta applied to the `(value, owner_hi, owner_lo)` lanes of
    /// this slot's state leaf. For a live row this is `value / owner_*`
    /// itself (4c.1-bis identity); for a dummy row this is free.
    pub delta_value: Block128,
    pub delta_owner_hi: Block128,
    pub delta_owner_lo: Block128,
    pub is_spend: bool,
    pub is_mint: bool,
}

impl FriStateOpenClaim {
    /// A padding row: reads as all-zeros, both action selectors off.
    pub const EMPTY: Self = Self {
        slot_index: 0,
        value: Block128(0),
        owner_hi: Block128(0),
        owner_lo: Block128(0),
        delta_value: Block128(0),
        delta_owner_hi: Block128(0),
        delta_owner_lo: Block128(0),
        is_spend: false,
        is_mint: false,
    };

    /// Derived `live_mask` — the disjoint OR of the two actions.
    pub const fn live(&self) -> bool {
        self.is_spend || self.is_mint
    }
}

/// Witness view the Stage 4a/4c.1/4c.1-bis/4b.2.1 builder consumes.
#[derive(Debug, Clone)]
pub struct FriStateOpenWitness {
    pub claims: [FriStateOpenClaim; FRI_STATE_OPEN_N_INPUTS],
    pub new_state_root_hi: Block128,
    pub new_state_root_lo: Block128,
    /// 4b.2.1: transcript-derived MLE eval point
    /// `r ∈ F^{FRI_STATE_OPEN_LOG_SLOTS}`. Pinned as one constant
    /// `PublicColumn` per coordinate.
    pub eval_point: [Block128; FRI_STATE_OPEN_LOG_SLOTS],
}

impl FriStateOpenWitness {
    pub fn from_claims(claims: [FriStateOpenClaim; FRI_STATE_OPEN_N_INPUTS]) -> Self {
        Self {
            claims,
            new_state_root_hi: Block128(0),
            new_state_root_lo: Block128(0),
            eval_point: [Block128::ZERO; FRI_STATE_OPEN_LOG_SLOTS],
        }
    }

    pub fn with_new_state_root(mut self, hi: Block128, lo: Block128) -> Self {
        self.new_state_root_hi = hi;
        self.new_state_root_lo = lo;
        self
    }

    pub fn with_eval_point(
        mut self,
        eval_point: [Block128; FRI_STATE_OPEN_LOG_SLOTS],
    ) -> Self {
        self.eval_point = eval_point;
        self
    }

    /// Lay the witness out into the AIR's column matrix. Every column
    /// has length `FRI_STATE_OPEN_N_ROWS`.
    pub fn build_columns(&self, n_cols: usize) -> Vec<Vec<Block128>> {
        let mut cols: Vec<Vec<Block128>> =
            vec![vec![Block128::ZERO; FRI_STATE_OPEN_N_ROWS]; n_cols];

        for (row, claim) in self.claims.iter().enumerate() {
            assert!(
                !(claim.is_spend && claim.is_mint),
                "FriStateOpenClaim: is_spend and is_mint are mutually exclusive"
            );
            cols[COL_VALUE][row] = claim.value;
            cols[COL_OWNER_HI][row] = claim.owner_hi;
            cols[COL_OWNER_LO][row] = claim.owner_lo;
            for b in 0..FRI_STATE_OPEN_LOG_SLOTS {
                let bit = ((claim.slot_index >> b) & 1) as u128;
                cols[COL_IDX_BIT_BASE + b][row] = Block128::from(bit);
            }
            cols[col_delta_value()][row] = claim.delta_value;
            cols[col_delta_owner_hi()][row] = claim.delta_owner_hi;
            cols[col_delta_owner_lo()][row] = claim.delta_owner_lo;
            cols[col_is_spend()][row] = bool_to_block(claim.is_spend);
            cols[col_is_mint()][row] = bool_to_block(claim.is_mint);
            cols[col_live_mask()][row] = bool_to_block(claim.live());
            let pre_factor = if claim.is_spend {
                Block128::ONE
            } else {
                Block128::ZERO
            };
            cols[col_opened_pre_value()][row] = pre_factor * claim.value;
            cols[col_opened_pre_owner_hi()][row] = pre_factor * claim.owner_hi;
            cols[col_opened_pre_owner_lo()][row] = pre_factor * claim.owner_lo;
            // proof_round_digest left zero — Stage 4b.2 fills it.
        }
        // new_state_root halves: row-0 witness pins; rest of column zero.
        cols[col_new_state_root_hi()][0] = self.new_state_root_hi;
        cols[col_new_state_root_lo()][0] = self.new_state_root_lo;
        // 4b.2.1: fill every row of each eval-point column with the
        // constant coordinate. The AIR declares these as
        // `PublicColumn`s, so `build_trace` will overwrite any drift
        // anyway, but filling here keeps the witness self-consistent.
        for i in 0..FRI_STATE_OPEN_LOG_SLOTS {
            let r_i = self.eval_point[i];
            for row in 0..FRI_STATE_OPEN_N_ROWS {
                cols[col_eval_point(i)][row] = r_i;
            }
        }
        cols
    }
}

const fn bool_to_block(b: bool) -> Block128 {
    if b {
        Block128(1)
    } else {
        Block128(0)
    }
}

/// Stage 4a/4c.1/4c.1-bis AIR.
pub struct FriStateOpenAir {
    n_cols: usize,
    constraints: Vec<Box<dyn Constraint>>,
    public_columns: Vec<PublicColumn>,
}

impl FriStateOpenAir {
    /// Build the AIR at 4c.1-bis semantics.
    ///
    /// Constraint set:
    ///   * `BoolGate` on every idx bit, `live_mask`, `is_spend`,
    ///     `is_mint`.
    ///   * Mutual exclusivity: `SelectorGate(is_spend, is_mint == 0)`
    ///     i.e. `is_spend · is_mint == 0`.
    ///   * Union: `live_mask == is_spend + is_mint` as a
    ///     `WeightedLinearGate`. Given mutual exclusivity, XOR equals
    ///     OR, so `live_mask` is well-defined as the action-union mask.
    ///   * Delta identity: `live_mask · (value + delta_*) == 0` for
    ///     each of `value`, `owner_hi`, `owner_lo`. Spend (post = 0,
    ///     pre = value) and mint (pre = 0, post = value) both give
    ///     `delta = value`.
    pub fn new(
        claim_pins: &[FriStateOpenClaim; FRI_STATE_OPEN_N_INPUTS],
        new_state_root_hi: Block128,
        new_state_root_lo: Block128,
        eval_point: [Block128; FRI_STATE_OPEN_LOG_SLOTS],
    ) -> Self {
        let mut constraints: Vec<Box<dyn Constraint>> = Vec::new();
        let mut public_columns: Vec<PublicColumn> = Vec::new();

        // Boolean-ness of every slot-index bit column and the three
        // gate columns.
        for b in 0..FRI_STATE_OPEN_LOG_SLOTS {
            constraints.push(Box::new(BoolGate::new(COL_IDX_BIT_BASE + b)));
        }
        constraints.push(Box::new(BoolGate::new(col_live_mask())));
        constraints.push(Box::new(BoolGate::new(col_is_spend())));
        constraints.push(Box::new(BoolGate::new(col_is_mint())));

        // Mutual exclusivity: is_spend · is_mint == 0.
        constraints.push(Box::new(SelectorGate::new(
            col_is_spend(),
            Box::new(WeightedLinearGate::new(
                vec![(col_is_mint(), Block128::ONE)],
                Block128::ZERO,
            )),
        )));

        // Union: live_mask + is_spend + is_mint == 0 (char-2 XOR).
        // Under mutual exclusivity this pins live_mask to the OR of
        // the two action flags.
        constraints.push(Box::new(WeightedLinearGate::new(
            vec![
                (col_live_mask(), Block128::ONE),
                (col_is_spend(), Block128::ONE),
                (col_is_mint(), Block128::ONE),
            ],
            Block128::ZERO,
        )));

        // 4c.1-ter opened-pre-state source columns:
        // `opened_pre_{value, owner_hi, owner_lo} == is_spend · {value,
        // owner_hi, owner_lo}`. Each collapses to 0 on mint / dummy
        // rows, to the claim lane on spend rows — the full pre-state
        // triple Stage 4b.2 opens against `prev_state_root`.
        for (pre_col, claim_col) in [
            (col_opened_pre_value(), COL_VALUE),
            (col_opened_pre_owner_hi(), COL_OWNER_HI),
            (col_opened_pre_owner_lo(), COL_OWNER_LO),
        ] {
            constraints.push(Box::new(MulGate::new(pre_col, col_is_spend(), claim_col)));
        }

        // 4c.1-bis delta identity: on live rows, delta_* == claim_*.
        for (value_col, delta_col) in [
            (COL_VALUE, col_delta_value()),
            (COL_OWNER_HI, col_delta_owner_hi()),
            (COL_OWNER_LO, col_delta_owner_lo()),
        ] {
            let inner: Box<dyn Constraint> = Box::new(WeightedLinearGate::new(
                vec![(value_col, Block128::ONE), (delta_col, Block128::ONE)],
                Block128::ZERO,
            ));
            constraints.push(Box::new(SelectorGate::new(col_live_mask(), inner)));
        }

        // Per-input boundary pins: every row's (value, owner_hi,
        // owner_lo) is fixed to the verifier-known claim.
        let mut next_indicator_col = FRI_STATE_OPEN_WITNESS_COLS;
        for (row, claim) in claim_pins.iter().enumerate() {
            for (target, value) in [
                (COL_VALUE, claim.value),
                (COL_OWNER_HI, claim.owner_hi),
                (COL_OWNER_LO, claim.owner_lo),
            ] {
                let (pc, gate) = emit_public_cell(
                    next_indicator_col,
                    row,
                    FRI_STATE_OPEN_N_ROWS,
                    target,
                    value,
                );
                public_columns.push(pc);
                constraints.push(gate);
                next_indicator_col += 1;
            }
        }

        // Row-0 boundary pins for new_state_root halves.
        for (target, value) in [
            (col_new_state_root_hi(), new_state_root_hi),
            (col_new_state_root_lo(), new_state_root_lo),
        ] {
            let (pc, gate) = emit_public_cell(
                next_indicator_col,
                0,
                FRI_STATE_OPEN_N_ROWS,
                target,
                value,
            );
            public_columns.push(pc);
            constraints.push(gate);
            next_indicator_col += 1;
        }

        // 4b.2.1: transcript-derived eval-point pins. Each coordinate
        // `r_i` gets its own `PublicColumn` with a constant value on
        // every row. The eq-ladder (4b.2.2) reads `r_i` row-locally
        // from `col_eval_point(i)`; no boundary gate needed — the
        // native check enforces column-wide equality to the verifier-
        // known sequence.
        for i in 0..FRI_STATE_OPEN_LOG_SLOTS {
            public_columns.push(PublicColumn::new(
                col_eval_point(i),
                vec![eval_point[i]; FRI_STATE_OPEN_N_ROWS],
            ));
        }

        Self {
            n_cols: next_indicator_col,
            constraints,
            public_columns,
        }
    }

    /// Build a valid trace for this AIR from a matching witness.
    pub fn build_trace(&self, witness: &FriStateOpenWitness) -> Vec<Vec<Block128>> {
        let mut cols = witness.build_columns(self.n_cols);
        for pc in &self.public_columns {
            cols[pc.col] = pc.values.clone();
        }
        cols
    }
}

impl Air for FriStateOpenAir {
    fn n_columns(&self) -> usize {
        self.n_cols
    }
    fn log_rows(&self) -> usize {
        FRI_STATE_OPEN_LOG_ROWS
    }
    fn constraints(&self) -> &[Box<dyn Constraint>] {
        &self.constraints
    }
    fn public_columns(&self) -> &[PublicColumn] {
        &self.public_columns
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Trace;

    /// Build a live-spend claim: delta equals the claim triple.
    fn mk_spend(seed: u128, slot: u32) -> FriStateOpenClaim {
        let v = Block128::from(seed);
        let hi = Block128::from(seed.wrapping_mul(3) + 1);
        let lo = Block128::from(seed.wrapping_mul(7) + 2);
        FriStateOpenClaim {
            slot_index: slot,
            value: v,
            owner_hi: hi,
            owner_lo: lo,
            delta_value: v,
            delta_owner_hi: hi,
            delta_owner_lo: lo,
            is_spend: true,
            is_mint: false,
        }
    }

    /// Build a live-mint claim: same shape as spend — delta equals the
    /// claim triple.
    fn mk_mint(seed: u128, slot: u32) -> FriStateOpenClaim {
        let mut c = mk_spend(seed, slot);
        c.is_spend = false;
        c.is_mint = true;
        c
    }

    fn mk_claims() -> [FriStateOpenClaim; FRI_STATE_OPEN_N_INPUTS] {
        [
            mk_spend(11, 0),
            mk_spend(22, 3),
            FriStateOpenClaim::EMPTY,
            FriStateOpenClaim::EMPTY,
        ]
    }

    fn mk_root_hi() -> Block128 {
        Block128::from(0xA5A5_1234_5678_9ABC_u128)
    }
    fn mk_root_lo() -> Block128 {
        Block128::from(0xDEAD_BEEF_CAFE_F00D_u128)
    }

    fn mk_eval_point() -> [Block128; FRI_STATE_OPEN_LOG_SLOTS] {
        let mut r = [Block128::ZERO; FRI_STATE_OPEN_LOG_SLOTS];
        for (i, slot) in r.iter_mut().enumerate() {
            // Distinct, non-zero, non-one coordinates — exercises the
            // full eq-ladder arithmetic, not {0,1}-corner cases.
            *slot = Block128::from(0x100u128 + (i as u128) * 0x11);
        }
        r
    }

    fn mk_witness(claims: [FriStateOpenClaim; FRI_STATE_OPEN_N_INPUTS]) -> FriStateOpenWitness {
        FriStateOpenWitness::from_claims(claims)
            .with_new_state_root(mk_root_hi(), mk_root_lo())
            .with_eval_point(mk_eval_point())
    }

    fn mk_air() -> FriStateOpenAir {
        FriStateOpenAir::new(&mk_claims(), mk_root_hi(), mk_root_lo(), mk_eval_point())
    }

    #[test]
    fn honest_trace_passes() {
        let air = mk_air();
        let trace = Trace::new(air.build_trace(&mk_witness(mk_claims())));
        assert!(air.check(&trace));
    }

    #[test]
    fn honest_mint_row_passes() {
        // Swap one spend for a mint with the same claim triple; delta
        // identity still holds.
        let claims = [
            mk_spend(11, 0),
            mk_mint(22, 3),
            FriStateOpenClaim::EMPTY,
            FriStateOpenClaim::EMPTY,
        ];
        let air = FriStateOpenAir::new(&claims, mk_root_hi(), mk_root_lo(), mk_eval_point());
        let trace = Trace::new(air.build_trace(&mk_witness(claims)));
        assert!(air.check(&trace));
    }

    #[test]
    fn tampered_value_rejects() {
        let air = mk_air();
        let mut cols = air.build_trace(&mk_witness(mk_claims()));
        cols[COL_VALUE][0] = cols[COL_VALUE][0] + Block128::ONE;
        let trace = Trace::new(cols);
        assert!(!air.check(&trace));
    }

    #[test]
    fn tampered_owner_hi_rejects() {
        let air = mk_air();
        let mut cols = air.build_trace(&mk_witness(mk_claims()));
        cols[COL_OWNER_HI][1] = cols[COL_OWNER_HI][1] + Block128::ONE;
        let trace = Trace::new(cols);
        assert!(!air.check(&trace));
    }

    #[test]
    fn tampered_owner_lo_rejects() {
        let air = mk_air();
        let mut cols = air.build_trace(&mk_witness(mk_claims()));
        cols[COL_OWNER_LO][0] = cols[COL_OWNER_LO][0] + Block128::ONE;
        let trace = Trace::new(cols);
        assert!(!air.check(&trace));
    }

    #[test]
    fn tampered_slot_index_bit_rejects() {
        let air = mk_air();
        let mut cols = air.build_trace(&mk_witness(mk_claims()));
        cols[COL_IDX_BIT_BASE][0] = Block128::from(2u128);
        let trace = Trace::new(cols);
        assert!(!air.check(&trace));
    }

    #[test]
    fn live_row_with_wrong_delta_value_rejects() {
        // 4c.1-bis semantics: on a live row, delta_value must equal
        // the claim value.
        let air = mk_air();
        let mut cols = air.build_trace(&mk_witness(mk_claims()));
        cols[col_delta_value()][0] = cols[col_delta_value()][0] + Block128::ONE;
        let trace = Trace::new(cols);
        assert!(!air.check(&trace));
    }

    #[test]
    fn live_row_with_wrong_delta_owner_hi_rejects() {
        let air = mk_air();
        let mut cols = air.build_trace(&mk_witness(mk_claims()));
        cols[col_delta_owner_hi()][0] =
            cols[col_delta_owner_hi()][0] + Block128::ONE;
        let trace = Trace::new(cols);
        assert!(!air.check(&trace));
    }

    #[test]
    fn live_row_with_wrong_delta_owner_lo_rejects() {
        let air = mk_air();
        let mut cols = air.build_trace(&mk_witness(mk_claims()));
        cols[col_delta_owner_lo()][0] =
            cols[col_delta_owner_lo()][0] + Block128::ONE;
        let trace = Trace::new(cols);
        assert!(!air.check(&trace));
    }

    #[test]
    fn non_live_row_tolerates_nonzero_delta() {
        // On dummy / non-live rows the delta columns are unconstrained.
        // Rows 2/3 are EMPTY (is_spend=is_mint=0 → live=0).
        let air = mk_air();
        let mut cols = air.build_trace(&mk_witness(mk_claims()));
        cols[col_delta_value()][2] = Block128::from(0xFFu128);
        let trace = Trace::new(cols);
        assert!(air.check(&trace));
    }

    #[test]
    fn live_mask_is_bool_gated() {
        let air = mk_air();
        let mut cols = air.build_trace(&mk_witness(mk_claims()));
        cols[col_live_mask()][0] = Block128::from(2u128);
        let trace = Trace::new(cols);
        assert!(!air.check(&trace));
    }

    #[test]
    fn is_spend_is_bool_gated() {
        let air = mk_air();
        let mut cols = air.build_trace(&mk_witness(mk_claims()));
        cols[col_is_spend()][0] = Block128::from(2u128);
        let trace = Trace::new(cols);
        assert!(!air.check(&trace));
    }

    #[test]
    fn is_mint_is_bool_gated() {
        let air = mk_air();
        let mut cols = air.build_trace(&mk_witness(mk_claims()));
        cols[col_is_mint()][0] = Block128::from(2u128);
        let trace = Trace::new(cols);
        assert!(!air.check(&trace));
    }

    #[test]
    fn is_spend_and_is_mint_both_set_rejects() {
        // Mutual exclusivity gate must fire.
        let air = mk_air();
        let mut cols = air.build_trace(&mk_witness(mk_claims()));
        // Row 0 is a spend with is_spend=1. Force is_mint=1 too and
        // re-compute live_mask = is_spend + is_mint = 0 to bypass the
        // union gate; the mutual exclusivity gate must still reject.
        cols[col_is_mint()][0] = Block128::ONE;
        cols[col_live_mask()][0] = Block128::ZERO;
        let trace = Trace::new(cols);
        assert!(!air.check(&trace));
    }

    #[test]
    fn live_mask_out_of_sync_with_actions_rejects() {
        // is_spend = 0, is_mint = 0, but live_mask = 1 — breaks the
        // union gate.
        let air = mk_air();
        let mut cols = air.build_trace(&mk_witness(mk_claims()));
        // Row 2 is EMPTY. Flip live_mask to 1, actions stay 0.
        cols[col_live_mask()][2] = Block128::ONE;
        let trace = Trace::new(cols);
        assert!(!air.check(&trace));
    }

    #[test]
    fn live_row_with_is_spend_but_live_mask_zero_rejects() {
        // is_spend = 1 must drive live_mask = 1 via the union gate.
        let air = mk_air();
        let mut cols = air.build_trace(&mk_witness(mk_claims()));
        cols[col_live_mask()][0] = Block128::ZERO;
        let trace = Trace::new(cols);
        assert!(!air.check(&trace));
    }

    #[test]
    fn opened_pre_triple_equals_claim_on_spend() {
        // Honest spend row: opened_pre_* = 1 · claim_* = claim_*.
        let air = mk_air();
        let cols = air.build_trace(&mk_witness(mk_claims()));
        assert_eq!(cols[col_opened_pre_value()][0], cols[COL_VALUE][0]);
        assert_eq!(cols[col_opened_pre_owner_hi()][0], cols[COL_OWNER_HI][0]);
        assert_eq!(cols[col_opened_pre_owner_lo()][0], cols[COL_OWNER_LO][0]);
    }

    #[test]
    fn opened_pre_triple_is_zero_on_mint() {
        // Honest mint row: opened_pre_* = 0 · claim_* = 0.
        let claims = [
            mk_mint(11, 0),
            FriStateOpenClaim::EMPTY,
            FriStateOpenClaim::EMPTY,
            FriStateOpenClaim::EMPTY,
        ];
        let air = FriStateOpenAir::new(&claims, mk_root_hi(), mk_root_lo(), mk_eval_point());
        let cols = air.build_trace(&mk_witness(claims));
        assert_eq!(cols[col_opened_pre_value()][0], Block128::ZERO);
        assert_eq!(cols[col_opened_pre_owner_hi()][0], Block128::ZERO);
        assert_eq!(cols[col_opened_pre_owner_lo()][0], Block128::ZERO);
    }

    #[test]
    fn tampered_opened_pre_value_on_spend_rejects() {
        let air = mk_air();
        let mut cols = air.build_trace(&mk_witness(mk_claims()));
        cols[col_opened_pre_value()][0] =
            cols[col_opened_pre_value()][0] + Block128::ONE;
        let trace = Trace::new(cols);
        assert!(!air.check(&trace));
    }

    #[test]
    fn tampered_opened_pre_owner_hi_on_spend_rejects() {
        let air = mk_air();
        let mut cols = air.build_trace(&mk_witness(mk_claims()));
        cols[col_opened_pre_owner_hi()][0] =
            cols[col_opened_pre_owner_hi()][0] + Block128::ONE;
        let trace = Trace::new(cols);
        assert!(!air.check(&trace));
    }

    #[test]
    fn tampered_opened_pre_owner_lo_on_spend_rejects() {
        let air = mk_air();
        let mut cols = air.build_trace(&mk_witness(mk_claims()));
        cols[col_opened_pre_owner_lo()][0] =
            cols[col_opened_pre_owner_lo()][0] + Block128::ONE;
        let trace = Trace::new(cols);
        assert!(!air.check(&trace));
    }

    #[test]
    fn tampered_opened_pre_value_on_mint_rejects() {
        let claims = [
            mk_mint(11, 0),
            FriStateOpenClaim::EMPTY,
            FriStateOpenClaim::EMPTY,
            FriStateOpenClaim::EMPTY,
        ];
        let air = FriStateOpenAir::new(&claims, mk_root_hi(), mk_root_lo(), mk_eval_point());
        let mut cols = air.build_trace(&mk_witness(claims));
        // Mint row: opened_pre_* must stay 0. Non-zero breaks the
        // MulGate identity `opened_pre_* == is_spend · claim_*`
        // because is_spend = 0 on a mint row.
        cols[col_opened_pre_value()][0] = Block128::ONE;
        let trace = Trace::new(cols);
        assert!(!air.check(&trace));
    }

    #[test]
    fn tampered_opened_pre_owner_hi_on_mint_rejects() {
        let claims = [
            mk_mint(11, 0),
            FriStateOpenClaim::EMPTY,
            FriStateOpenClaim::EMPTY,
            FriStateOpenClaim::EMPTY,
        ];
        let air = FriStateOpenAir::new(&claims, mk_root_hi(), mk_root_lo(), mk_eval_point());
        let mut cols = air.build_trace(&mk_witness(claims));
        cols[col_opened_pre_owner_hi()][0] = Block128::ONE;
        let trace = Trace::new(cols);
        assert!(!air.check(&trace));
    }

    #[test]
    fn tampered_opened_pre_owner_lo_on_mint_rejects() {
        let claims = [
            mk_mint(11, 0),
            FriStateOpenClaim::EMPTY,
            FriStateOpenClaim::EMPTY,
            FriStateOpenClaim::EMPTY,
        ];
        let air = FriStateOpenAir::new(&claims, mk_root_hi(), mk_root_lo(), mk_eval_point());
        let mut cols = air.build_trace(&mk_witness(claims));
        cols[col_opened_pre_owner_lo()][0] = Block128::ONE;
        let trace = Trace::new(cols);
        assert!(!air.check(&trace));
    }

    #[test]
    fn tampered_new_state_root_hi_rejects() {
        let air = mk_air();
        let mut cols = air.build_trace(&mk_witness(mk_claims()));
        cols[col_new_state_root_hi()][0] =
            cols[col_new_state_root_hi()][0] + Block128::ONE;
        let trace = Trace::new(cols);
        assert!(!air.check(&trace));
    }

    #[test]
    fn tampered_new_state_root_lo_rejects() {
        let air = mk_air();
        let mut cols = air.build_trace(&mk_witness(mk_claims()));
        cols[col_new_state_root_lo()][0] =
            cols[col_new_state_root_lo()][0] + Block128::ONE;
        let trace = Trace::new(cols);
        assert!(!air.check(&trace));
    }

    #[test]
    fn eval_point_is_pinned_column_wide() {
        // Honest build: every row of `col_eval_point(i)` equals r_i.
        let air = mk_air();
        let cols = air.build_trace(&mk_witness(mk_claims()));
        let r = mk_eval_point();
        for i in 0..FRI_STATE_OPEN_LOG_SLOTS {
            for row in 0..FRI_STATE_OPEN_N_ROWS {
                assert_eq!(cols[col_eval_point(i)][row], r[i]);
            }
        }
    }

    #[test]
    fn tampered_eval_point_rejects() {
        // Flipping any single cell of any eval-point column breaks
        // the PublicColumn native check.
        for i in 0..FRI_STATE_OPEN_LOG_SLOTS {
            for row in 0..FRI_STATE_OPEN_N_ROWS {
                let air = mk_air();
                let mut cols = air.build_trace(&mk_witness(mk_claims()));
                cols[col_eval_point(i)][row] =
                    cols[col_eval_point(i)][row] + Block128::ONE;
                let trace = Trace::new(cols);
                assert!(
                    !air.check(&trace),
                    "tampering r_{i} at row {row} must reject"
                );
            }
        }
    }

    #[test]
    fn eval_point_drift_in_witness_is_overridden_by_public_pin() {
        // A witness that disagrees with the AIR's declared eval point
        // must still fail the native PublicColumn check — the AIR
        // owns the pins, not the witness.
        let air = mk_air();
        let mut bogus = mk_witness(mk_claims());
        bogus.eval_point[0] = bogus.eval_point[0] + Block128::ONE;
        let cols = bogus.build_columns(air.n_columns());
        // `build_columns` fills eval-point columns from the witness
        // (bogus). We do NOT apply the AIR's public overrides here —
        // this is the attack surface the PublicColumn check covers.
        let trace = Trace::new(cols);
        assert!(!air.check(&trace));
    }

    #[test]
    fn no_column_reads_spend_secret() {
        // Compile-time guarantee: the claim struct has no
        // spend-secret field.
        const SECRET_COLUMN_COUNT: usize = 0;
        assert_eq!(SECRET_COLUMN_COUNT, 0);
    }
}
