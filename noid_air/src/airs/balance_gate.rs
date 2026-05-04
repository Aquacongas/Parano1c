// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! `BalanceGateAir` — Stage 3b-3 UTXO conservation law AIR.
//!
//! Enforces `Σ inputs == Σ outputs + fee` (standard UTXO accounting) for
//! a 4-in / 8-out / 1-fee tx shape, all operands treated as `u64`. The
//! check is realised by two parallel chains of width-growing
//! `bit_adder` blocks with cross-block carry-bridge gates, terminated by
//! a bitwise-equality check between the two chain tails.
//!
//! ```text
//! Chain A (Σ inputs, 4 operands):
//!   A0: i0 + i1         (width 64 → 65-bit)
//!   A1: i2 + i3         (width 64 → 65-bit)
//!   A2: A0 + A1         (width 65 → 66-bit)
//!
//! Chain B (Σ outputs + fee, balanced binary tree + fee tail):
//!   B00..B03: o0+o1, o2+o3, o4+o5, o6+o7    (width 64 → 65-bit)
//!   B10, B11: B00+B01, B02+B03              (width 65 → 66-bit)
//!   B20:      B10+B11                       (width 66 → 67-bit)
//!   B21:      B20+fee                       (width 67 → 68-bit)
//! ```
//!
//! Each block is one instance of [`BitAdderAir`] at a dedicated column
//! offset (6 columns per block × 11 blocks = 66 columns). Bridges
//! equate `sum_k[r]` with `a_{k+1}[r]` (or `b_{k+1}[r]`) on the active
//! input rows of block `k`, and `carry_k[W_k]` with the top-bit of the
//! downstream block's operand at row `W_k`.
//!
//! Final equality between the 66-bit A tail and the 68-bit B tail uses
//! four gates:
//!
//! 1. `A2.sum ≡ B21.sum` on rows `0..64` (A2.is_input selector) — bits 0..64.
//! 2. `A2.carry[65] ≡ B21.sum[65]` (A2.is_input transition) — bit 65.
//! 3. `B21.sum[66] ≡ 0` (B20.is_input transition at row 65) — bit 66.
//! 4. `B21.carry[67] ≡ 0` (B21.is_input transition at row 66) — bit 67.
//!
//! Gates 3 and 4 catch the `Σ outputs + fee ≥ 2^66` overflow attack.
//!
//! The integer embedding holds because every bit column is pinned to
//! `{0, 1}` by a `BoolGate`, and the full-adder recurrences on the
//! constituent `bit_adder` blocks are bit-exact integer addition —
//! independently of the tower-basis interpretation of `Block128`
//! (see the caveat in `range_gate.rs`). No use of `Block128::from(2)`
//! as integer-doubling anywhere in the chain.

use crate::airs::bit_adder::{
    bit_adder_is_input_programme, bit_adder_is_reset_programme, emit_block_constraints,
    BitAdderAir, BitAdderLayout, BIT_ADDER_COL_A, BIT_ADDER_COL_B, BIT_ADDER_COL_CARRY,
    BIT_ADDER_COL_IS_INPUT, BIT_ADDER_COL_IS_RESET, BIT_ADDER_COL_SUM, BIT_ADDER_LOG_WORD_BITS,
    BIT_ADDER_N_COLS,
};
use crate::gates::PublicColumn;
use crate::{Air, ColumnDomain, Constraint, EvalFrame, Trace};
use noid_core::{Block128, TowerField};

/// Number of `bit_adder` blocks stitched together.
pub const BALANCE_N_BLOCKS: usize = 11;
pub const BALANCE_N_COLS: usize = BALANCE_N_BLOCKS * BIT_ADDER_N_COLS;

/// Minimum `log_rows` — one 128-row word per block, with STARK's
/// `log_rows >= 8` floor forcing a second zero-filled instance.
pub const BALANCE_MIN_LOG_ROWS: usize = 8;

/// Block ordinals inside the composite column matrix. Each occupies 6
/// contiguous columns starting at `ordinal * 6`.
const BLK_A0: usize = 0;
const BLK_A1: usize = 1;
const BLK_A2: usize = 2;
const BLK_B00: usize = 3;
const BLK_B01: usize = 4;
const BLK_B02: usize = 5;
const BLK_B03: usize = 6;
const BLK_B10: usize = 7;
const BLK_B11: usize = 8;
const BLK_B20: usize = 9;
const BLK_B21: usize = 10;

const BLOCK_WIDTHS: [usize; BALANCE_N_BLOCKS] = [
    64, // A0
    64, // A1
    65, // A2
    64, // B00
    64, // B01
    64, // B02
    64, // B03
    65, // B10
    65, // B11
    66, // B20
    67, // B21
];

/// `is_input_src · (dst + sum_src) == 0` — degree-2 bridge that equates
/// every active-input bit of the downstream operand column with the
/// corresponding bit of the upstream block's `sum` column.
pub struct BalanceBridgeBitsGate {
    /// `[is_input_src, dst, sum_src]`.
    cols: [usize; 3],
}

impl BalanceBridgeBitsGate {
    pub fn new(is_input_src: usize, dst: usize, sum_src: usize) -> Self {
        Self {
            cols: [is_input_src, dst, sum_src],
        }
    }
}

impl Constraint for BalanceBridgeBitsGate {
    fn degree(&self) -> usize {
        2
    }
    fn columns(&self) -> &[usize] {
        &self.cols
    }
    fn evaluate(&self, frame: EvalFrame) -> Block128 {
        let is_input_src = frame.local[0];
        let dst = frame.local[1];
        let sum_src = frame.local[2];
        is_input_src * (dst + sum_src)
    }
}

/// `is_input_src · (1 + is_input_src_next) · (dst_next + carry_src_next) == 0`.
///
/// Fires only on the last active row of the upstream block, where it
/// equates the upstream carry-out bit with the top input bit of the
/// downstream operand column at the downstream block's row `W_src`.
/// Degree 3, rotation-consuming.
pub struct BalanceBridgeCarryGate {
    /// `[is_input_src]`.
    local: [usize; 1],
    /// `[is_input_src, dst, carry_src]`.
    shifted: [usize; 3],
}

impl BalanceBridgeCarryGate {
    pub fn new(is_input_src: usize, dst: usize, carry_src: usize) -> Self {
        Self {
            local: [is_input_src],
            shifted: [is_input_src, dst, carry_src],
        }
    }
}

impl Constraint for BalanceBridgeCarryGate {
    fn degree(&self) -> usize {
        3
    }
    fn columns(&self) -> &[usize] {
        &self.local
    }
    fn shifted_columns(&self) -> &[usize] {
        &self.shifted
    }
    fn evaluate(&self, frame: EvalFrame) -> Block128 {
        let is_input_src = frame.local[0];
        let is_input_src_next = frame.next[0];
        let dst_next = frame.next[1];
        let carry_src_next = frame.next[2];
        is_input_src * (Block128::ONE + is_input_src_next) * (dst_next + carry_src_next)
    }
}

/// `is_input_{A2} · (A2.sum + B21.sum) == 0` — bitwise equality of bits
/// `0..64` across the active input rows of `A2`.
pub struct BalanceFinalSumGate {
    cols: [usize; 3],
}

impl BalanceFinalSumGate {
    pub fn new(is_input_a2: usize, a2_sum: usize, b21_sum: usize) -> Self {
        Self {
            cols: [is_input_a2, a2_sum, b21_sum],
        }
    }
}

impl Constraint for BalanceFinalSumGate {
    fn degree(&self) -> usize {
        2
    }
    fn columns(&self) -> &[usize] {
        &self.cols
    }
    fn evaluate(&self, frame: EvalFrame) -> Block128 {
        frame.local[0] * (frame.local[1] + frame.local[2])
    }
}

/// `is_input_{A2} · (1 + is_input_{A2}_next) · (A2.carry_next + B21.sum_next) == 0`
/// — equates bit 65 of the A tail (its carry-out) with bit 65 of the
/// B tail sum. Fires at the A2 is_input transition (row 64 of inst 0).
pub struct BalanceFinalCarryGate {
    local: [usize; 1],
    shifted: [usize; 3],
}

impl BalanceFinalCarryGate {
    pub fn new(is_input_a2: usize, a2_carry: usize, b21_sum: usize) -> Self {
        Self {
            local: [is_input_a2],
            shifted: [is_input_a2, a2_carry, b21_sum],
        }
    }
}

impl Constraint for BalanceFinalCarryGate {
    fn degree(&self) -> usize {
        3
    }
    fn columns(&self) -> &[usize] {
        &self.local
    }
    fn shifted_columns(&self) -> &[usize] {
        &self.shifted
    }
    fn evaluate(&self, frame: EvalFrame) -> Block128 {
        let is_input_a2 = frame.local[0];
        let is_input_a2_next = frame.next[0];
        let a2_carry_next = frame.next[1];
        let b21_sum_next = frame.next[2];
        is_input_a2
            * (Block128::ONE + is_input_a2_next)
            * (a2_carry_next + b21_sum_next)
    }
}

/// `is_input_sel · (1 + is_input_sel_next) · target_next == 0` — degree-3
/// rotation gate that pins a single target cell to zero on the row
/// immediately after a selector's `is_input` boundary. Used to pin the
/// excess top bits of the B tail (`B21.sum[66]`, `B21.carry[67]`) to
/// zero, guaranteeing the B-chain value fits in 66 bits for a balanced
/// tx. Catches the `Σ outputs + fee ≥ 2^66` overflow attack.
pub struct BalanceZeroAtTransitionGate {
    local: [usize; 1],
    shifted: [usize; 2],
}

impl BalanceZeroAtTransitionGate {
    pub fn new(is_input_sel: usize, target: usize) -> Self {
        Self {
            local: [is_input_sel],
            shifted: [is_input_sel, target],
        }
    }
}

impl Constraint for BalanceZeroAtTransitionGate {
    fn degree(&self) -> usize {
        3
    }
    fn columns(&self) -> &[usize] {
        &self.local
    }
    fn shifted_columns(&self) -> &[usize] {
        &self.shifted
    }
    fn evaluate(&self, frame: EvalFrame) -> Block128 {
        let sel = frame.local[0];
        let sel_next = frame.next[0];
        let target_next = frame.next[1];
        sel * (Block128::ONE + sel_next) * target_next
    }
}

/// One bridge spec: upstream block feeds one operand slot
/// (`a` or `b`) of the downstream block.
#[derive(Clone, Copy)]
enum OperandSlot {
    A,
    B,
}

#[derive(Clone, Copy)]
struct BridgeSpec {
    src: usize,
    dst: usize,
    slot: OperandSlot,
}

const BRIDGES: [BridgeSpec; 9] = [
    // Chain A
    BridgeSpec { src: BLK_A0, dst: BLK_A2, slot: OperandSlot::A },
    BridgeSpec { src: BLK_A1, dst: BLK_A2, slot: OperandSlot::B },
    // Chain B — level 1 → 2
    BridgeSpec { src: BLK_B00, dst: BLK_B10, slot: OperandSlot::A },
    BridgeSpec { src: BLK_B01, dst: BLK_B10, slot: OperandSlot::B },
    BridgeSpec { src: BLK_B02, dst: BLK_B11, slot: OperandSlot::A },
    BridgeSpec { src: BLK_B03, dst: BLK_B11, slot: OperandSlot::B },
    // Chain B — level 2 → 3
    BridgeSpec { src: BLK_B10, dst: BLK_B20, slot: OperandSlot::A },
    BridgeSpec { src: BLK_B11, dst: BLK_B20, slot: OperandSlot::B },
    // Chain B — fee tail
    BridgeSpec { src: BLK_B20, dst: BLK_B21, slot: OperandSlot::A },
];

fn dst_col_at(block: usize, slot: OperandSlot, base_col: usize) -> usize {
    let base = base_col + block * BIT_ADDER_N_COLS;
    match slot {
        OperandSlot::A => base + BIT_ADDER_COL_A,
        OperandSlot::B => base + BIT_ADDER_COL_B,
    }
}

fn src_sum_col_at(block: usize, base_col: usize) -> usize {
    base_col + block * BIT_ADDER_N_COLS + BIT_ADDER_COL_SUM
}
fn src_carry_col_at(block: usize, base_col: usize) -> usize {
    base_col + block * BIT_ADDER_N_COLS + BIT_ADDER_COL_CARRY
}
fn src_is_input_col_at(block: usize, base_col: usize) -> usize {
    base_col + block * BIT_ADDER_N_COLS + BIT_ADDER_COL_IS_INPUT
}

#[cfg(test)]
fn dst_col(block: usize, slot: OperandSlot) -> usize {
    dst_col_at(block, slot, 0)
}
#[cfg(test)]
fn src_sum_col(block: usize) -> usize {
    src_sum_col_at(block, 0)
}

/// Emit the full `BalanceGateAir` constraint set with every column
/// index shifted by `base_col`. `base_col == 0` recovers the
/// standalone layout. Used by Stage 3b-4 to embed this AIR as a
/// sub-circuit of `TxValidityAir` at an arbitrary column offset.
pub fn emit_balance_constraints(base_col: usize) -> Vec<Box<dyn Constraint>> {
    let mut constraints: Vec<Box<dyn Constraint>> = Vec::new();

    // Per-block bit_adder constraints at shifted layouts.
    for blk in 0..BALANCE_N_BLOCKS {
        let layout = BitAdderLayout::shifted(base_col + blk * BIT_ADDER_N_COLS);
        constraints.extend(emit_block_constraints(layout));
    }

    // Bridges.
    for b in BRIDGES.iter() {
        let dst = dst_col_at(b.dst, b.slot, base_col);
        let src_sum = src_sum_col_at(b.src, base_col);
        let src_carry = src_carry_col_at(b.src, base_col);
        let src_is_input = src_is_input_col_at(b.src, base_col);
        constraints.push(Box::new(BalanceBridgeBitsGate::new(
            src_is_input,
            dst,
            src_sum,
        )));
        constraints.push(Box::new(BalanceBridgeCarryGate::new(
            src_is_input,
            dst,
            src_carry,
        )));
    }

    // Final equality: A2 (66-bit value) vs B21 (up to 68-bit value).
    let a2_sum = src_sum_col_at(BLK_A2, base_col);
    let a2_carry = src_carry_col_at(BLK_A2, base_col);
    let a2_is_input = src_is_input_col_at(BLK_A2, base_col);
    let b20_is_input = src_is_input_col_at(BLK_B20, base_col);
    let b21_sum = src_sum_col_at(BLK_B21, base_col);
    let b21_carry = src_carry_col_at(BLK_B21, base_col);
    let b21_is_input = src_is_input_col_at(BLK_B21, base_col);

    constraints.push(Box::new(BalanceFinalSumGate::new(
        a2_is_input,
        a2_sum,
        b21_sum,
    )));
    constraints.push(Box::new(BalanceFinalCarryGate::new(
        a2_is_input,
        a2_carry,
        b21_sum,
    )));
    constraints.push(Box::new(BalanceZeroAtTransitionGate::new(
        b20_is_input,
        b21_sum,
    )));
    constraints.push(Box::new(BalanceZeroAtTransitionGate::new(
        b21_is_input,
        b21_carry,
    )));

    constraints
}

/// Build the 66-column balance sub-trace (operand bits, sums, carries,
/// selectors) and its per-column [`ColumnDomain`] tags. Pure helper so
/// a composite AIR can splice these columns at an arbitrary offset
/// without going through [`BalanceGateAir::build_trace`] (which wraps
/// everything in a standalone [`Trace`]).
///
/// Alias kept for [`TxValidityAir::build_trace_3b4`] compatibility.
pub fn build_balance_columns(
    inputs: [u64; 4],
    outputs: [u64; 8],
    fee: u64,
    log_rows: usize,
) -> (Vec<Vec<Block128>>, Vec<ColumnDomain>) {
    build_balance_trace_parts(log_rows, inputs, outputs, fee)
}

pub fn build_balance_trace_parts(
    log_rows: usize,
    inputs: [u64; 4],
    outputs: [u64; 8],
    fee: u64,
) -> (Vec<Vec<Block128>>, Vec<ColumnDomain>) {
    assert!(
        log_rows >= BALANCE_MIN_LOG_ROWS,
        "balance sub-trace needs log_rows >= {BALANCE_MIN_LOG_ROWS}"
    );
    let n_instances = 1usize << (log_rows - BIT_ADDER_LOG_WORD_BITS);

    let i: [u128; 4] = [
        inputs[0] as u128,
        inputs[1] as u128,
        inputs[2] as u128,
        inputs[3] as u128,
    ];
    let o: [u128; 8] = [
        outputs[0] as u128,
        outputs[1] as u128,
        outputs[2] as u128,
        outputs[3] as u128,
        outputs[4] as u128,
        outputs[5] as u128,
        outputs[6] as u128,
        outputs[7] as u128,
    ];
    let fee_u = fee as u128;

    let a0_v = i[0] + i[1];
    let a1_v = i[2] + i[3];
    assert!(a0_v < (1u128 << 65));
    assert!(a1_v < (1u128 << 65));

    let b00_v = o[0] + o[1];
    let b01_v = o[2] + o[3];
    let b02_v = o[4] + o[5];
    let b03_v = o[6] + o[7];
    let b10_v = b00_v + b01_v;
    let b11_v = b02_v + b03_v;
    assert!(b10_v < (1u128 << 66));
    assert!(b11_v < (1u128 << 66));
    let b20_v = b10_v + b11_v;
    assert!(b20_v < (1u128 << 67));

    fn first_pair(n: usize, a: u128, b: u128) -> Vec<(u128, u128)> {
        let mut v = vec![(0u128, 0u128); n];
        v[0] = (a, b);
        v
    }

    let per_block: [(usize, u128, u128); BALANCE_N_BLOCKS] = [
        (BLOCK_WIDTHS[BLK_A0], i[0], i[1]),
        (BLOCK_WIDTHS[BLK_A1], i[2], i[3]),
        (BLOCK_WIDTHS[BLK_A2], a0_v, a1_v),
        (BLOCK_WIDTHS[BLK_B00], o[0], o[1]),
        (BLOCK_WIDTHS[BLK_B01], o[2], o[3]),
        (BLOCK_WIDTHS[BLK_B02], o[4], o[5]),
        (BLOCK_WIDTHS[BLK_B03], o[6], o[7]),
        (BLOCK_WIDTHS[BLK_B10], b00_v, b01_v),
        (BLOCK_WIDTHS[BLK_B11], b02_v, b03_v),
        (BLOCK_WIDTHS[BLK_B20], b10_v, b11_v),
        (BLOCK_WIDTHS[BLK_B21], b20_v, fee_u),
    ];

    let mut cols: Vec<Vec<Block128>> = Vec::with_capacity(BALANCE_N_COLS);
    let mut domains: Vec<ColumnDomain> = Vec::with_capacity(BALANCE_N_COLS);
    for &(width, a, b) in per_block.iter() {
        let air = BitAdderAir::new(width, log_rows);
        let sub = air.build_trace(&first_pair(n_instances, a, b));
        cols.extend(sub.columns.into_iter());
        domains.extend(sub.domains.into_iter());
    }
    (cols, domains)
}

/// Pin every `bit_adder` block's `is_reset` / `is_input` selector
/// columns to their literal programmes (22 declarations across the
/// 11 blocks). §3d-0.10 wiring: zero new constraints — just the
/// `PublicColumn` machinery from §3d-0.2 applied to columns that
/// used to be free witnesses. `base_col` is the column offset of the
/// balance block inside the composite trace; pass `0` for the
/// standalone `BalanceGateAir`.
pub fn emit_balance_selector_public_columns(
    base_col: usize,
    log_rows: usize,
) -> Vec<PublicColumn> {
    assert!(
        log_rows >= BALANCE_MIN_LOG_ROWS,
        "balance selector publics need log_rows >= {BALANCE_MIN_LOG_ROWS}"
    );
    let mut out = Vec::with_capacity(2 * BALANCE_N_BLOCKS);
    for blk in 0..BALANCE_N_BLOCKS {
        let block_base = base_col + blk * BIT_ADDER_N_COLS;
        let width = BLOCK_WIDTHS[blk];
        out.push(PublicColumn::new(
            block_base + BIT_ADDER_COL_IS_RESET,
            bit_adder_is_reset_programme(log_rows),
        ));
        out.push(PublicColumn::new(
            block_base + BIT_ADDER_COL_IS_INPUT,
            bit_adder_is_input_programme(width, log_rows),
        ));
    }
    out
}

/// Composite AIR proving `Σ inputs = Σ outputs + fee` for a 4-in / 8-out
/// tx. See module-level docs for the chain layout.
pub struct BalanceGateAir {
    log_rows: usize,
    constraints: Vec<Box<dyn Constraint>>,
    public_columns: Vec<PublicColumn>,
}

impl BalanceGateAir {
    pub fn new(log_rows: usize) -> Self {
        assert!(
            log_rows >= BALANCE_MIN_LOG_ROWS,
            "BalanceGateAir needs log_rows >= {BALANCE_MIN_LOG_ROWS}"
        );
        Self {
            log_rows,
            constraints: emit_balance_constraints(0),
            public_columns: Vec::new(),
        }
    }

    /// §3d-0.10 — balance AIR with the 22 `bit_adder` selector
    /// programmes pinned. Constraints are unchanged; the selector
    /// columns become `PublicColumn`-bound, so a prover that tampers
    /// `is_reset` / `is_input` on any row is rejected by the native
    /// check and by the STARK verifier's `check_public_columns` MLE
    /// re-eval — closes the "selectors are witness, not pinned"
    /// bullet from §3b-4's debt list.
    pub fn new_with_selector_pins(log_rows: usize) -> Self {
        assert!(
            log_rows >= BALANCE_MIN_LOG_ROWS,
            "BalanceGateAir needs log_rows >= {BALANCE_MIN_LOG_ROWS}"
        );
        Self {
            log_rows,
            constraints: emit_balance_constraints(0),
            public_columns: emit_balance_selector_public_columns(0, log_rows),
        }
    }

    pub fn n_instances(&self) -> usize {
        1usize << (self.log_rows - BIT_ADDER_LOG_WORD_BITS)
    }

    /// Build a composite trace from primary tx values. Each block is
    /// populated via [`BitAdderAir::build_trace`]; instance 0 carries
    /// the actual tx, instances `1..n_instances` are zero-filled
    /// padding (operands `(0, 0)` trivially satisfy every constraint).
    pub fn build_trace(&self, inputs: [u64; 4], outputs: [u64; 8], fee: u64) -> Trace {
        let (cols, domains) =
            build_balance_trace_parts(self.log_rows, inputs, outputs, fee);
        Trace::new_with_domains(cols, domains)
    }
}

impl Air for BalanceGateAir {
    fn n_columns(&self) -> usize {
        BALANCE_N_COLS
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

#[cfg(test)]
mod tests {
    use super::*;

    const LOG_ROWS: usize = 8;

    fn balanced_tuple(seed: u64) -> ([u64; 4], [u64; 8], u64) {
        // Build balanced (inputs, outputs, fee) with `Σ in = Σ out + fee`:
        //   pick 4 inputs, pick fee ≤ Σ inputs, distribute `Σ in - fee`
        //   across 8 outputs via pseudo-random split.
        let mut s = seed.wrapping_mul(0x9E3779B97F4A7C15).wrapping_add(1);
        let mut next = || -> u64 {
            s = s
                .wrapping_mul(0x5851F42D4C957F2D)
                .wrapping_add(0x14057B7EF767814F);
            s >> 32
        };
        // Keep inputs well below u64::MAX to avoid accidental chain
        // overflow while splitting into outputs.
        let inputs = [
            next() & 0x0FFF_FFFF_FFFF_FFFF,
            next() & 0x0FFF_FFFF_FFFF_FFFF,
            next() & 0x0FFF_FFFF_FFFF_FFFF,
            next() & 0x0FFF_FFFF_FFFF_FFFF,
        ];
        let fee = next() & 0xFFFF;
        let total: u128 = inputs.iter().map(|&x| x as u128).sum::<u128>() - fee as u128;
        // Split `total` into 8 outputs.
        let mut remaining = total;
        let mut outs = [0u64; 8];
        for i in 0..7 {
            let take_mask = next() as u128;
            let take = take_mask % (remaining / (8 - i) as u128 + 1);
            outs[i] = take as u64;
            remaining -= take;
        }
        outs[7] = remaining as u64;
        (inputs, outs, fee)
    }

    #[test]
    fn balance_gate_accepts_balanced_tx() {
        let air = BalanceGateAir::new(LOG_ROWS);
        for seed in 0..8u64 {
            let (ins, outs, fee) = balanced_tuple(seed);
            let trace = air.build_trace(ins, outs, fee);
            assert!(
                air.check(&trace),
                "balanced tx rejected: seed={seed} ins={ins:?} outs={outs:?} fee={fee}"
            );
        }
    }

    #[test]
    fn balance_gate_rejects_unbalanced() {
        // Flip one bit in each of the 13 primary witness columns in turn
        // and check the composite AIR rejects. The tampered column maps
        // to one of: A0.a (i0), A0.b (i1), A1.a (i2), A1.b (i3),
        // B21.b (fee), B0k.a/.b (o0..o7).
        let air = BalanceGateAir::new(LOG_ROWS);
        let (ins, outs, fee) = balanced_tuple(42);
        let honest = air.build_trace(ins, outs, fee);
        assert!(air.check(&honest));

        // (block, slot, label) for each of the 13 primary operands.
        let tampers: [(usize, OperandSlot, &str); 13] = [
            (BLK_A0, OperandSlot::A, "i0"),
            (BLK_A0, OperandSlot::B, "i1"),
            (BLK_A1, OperandSlot::A, "i2"),
            (BLK_A1, OperandSlot::B, "i3"),
            (BLK_B21, OperandSlot::B, "fee"),
            (BLK_B00, OperandSlot::A, "o0"),
            (BLK_B00, OperandSlot::B, "o1"),
            (BLK_B01, OperandSlot::A, "o2"),
            (BLK_B01, OperandSlot::B, "o3"),
            (BLK_B02, OperandSlot::A, "o4"),
            (BLK_B02, OperandSlot::B, "o5"),
            (BLK_B03, OperandSlot::A, "o6"),
            (BLK_B03, OperandSlot::B, "o7"),
        ];
        for &(blk, slot, label) in tampers.iter() {
            let mut bad = honest.clone();
            let col = dst_col(blk, slot);
            // Row 0 is always an active input row of instance 0.
            bad.columns[col][0] += Block128::ONE;
            assert!(
                !air.check(&bad),
                "balance gate accepted tampered operand `{label}`"
            );
        }
    }

    #[test]
    fn balance_gate_rejects_sum_overflow() {
        // Inputs [u64::MAX] × 4 sum to 2^66 - 4 ≤ 2^66, fits in A2 (66-bit
        // result). Outputs set to zero with small fee — B21 value is tiny,
        // low bits don't match A2 — bitwise eq on rows 0..64 catches it.
        let air = BalanceGateAir::new(LOG_ROWS);
        let ins = [u64::MAX, u64::MAX, u64::MAX, u64::MAX];
        let outs = [0u64; 8];
        let fee = 4u64;
        let trace = air.build_trace(ins, outs, fee);
        assert!(!air.check(&trace));
    }

    #[test]
    fn balance_gate_rejects_b_chain_top_bit_overflow() {
        // Construct outputs whose sum makes B21.sum[66] = 1 while A2's
        // value has bit 66 = 0 (impossible, since A2 tops out at 66 bits,
        // but worth checking that gate 3 fires).
        //
        // Take outs = [2^63, 2^63, 2^63, 2^63, 2^63, 2^63, 2^63, 2^63]:
        //   Σ outs = 8 * 2^63 = 2^66.
        // Set fee = 0, ins such that Σ ins = 2^66 too → A2 = 2^66.
        // A2 (width-65 block) can hold a value up to 2^66 - 1; at exactly
        // 2^66, A2.carry[65] = 1 and A2.sum[0..64] = 0.
        // B21 = Σ outs + fee = 2^66; B21.sum[0..65] = 0, B21.sum[66] = 1,
        // B21.carry[67] = 0. A2.carry[65] = 1 vs B21.sum[65] = 0 →
        // `BalanceFinalCarryGate` catches at row 64. Additionally
        // B21.sum[66] = 1 → `BalanceZeroAtTransitionGate` on B20.is_input
        // catches at row 65. Either path rejects.
        let air = BalanceGateAir::new(LOG_ROWS);
        let ins = [1u64 << 63, 1u64 << 63, 1u64 << 63, 1u64 << 63];
        let outs = [1u64 << 63; 8];
        let fee = 0u64;
        // Σ ins = 2^65, Σ outs + fee = 2^66. Unbalanced by 2^65 → must reject.
        let trace = air.build_trace(ins, outs, fee);
        assert!(!air.check(&trace));
    }

    #[test]
    fn balance_gate_rejects_tampered_bridge() {
        // Modify A2.a at row 3 without updating A0.sum[3] — the
        // bridge A0 → A2 must reject.
        let air = BalanceGateAir::new(LOG_ROWS);
        let (ins, outs, fee) = balanced_tuple(7);
        let mut bad = air.build_trace(ins, outs, fee);
        let col_a2_a = dst_col(BLK_A2, OperandSlot::A);
        bad.columns[col_a2_a][3] += Block128::ONE;
        assert!(!air.check(&bad));
    }

    #[test]
    fn balance_gate_rejects_flipped_final_sum_bit() {
        let air = BalanceGateAir::new(LOG_ROWS);
        let (ins, outs, fee) = balanced_tuple(9);
        let honest = air.build_trace(ins, outs, fee);
        assert!(air.check(&honest));

        // Flip a bit of A2.sum at row 2.
        let mut bad_a = honest.clone();
        let col_a2_sum = src_sum_col(BLK_A2);
        bad_a.columns[col_a2_sum][2] += Block128::ONE;
        assert!(!air.check(&bad_a));

        // Flip a bit of B21.sum at row 7.
        let mut bad_b = honest.clone();
        let col_b21_sum = src_sum_col(BLK_B21);
        bad_b.columns[col_b21_sum][7] += Block128::ONE;
        assert!(!air.check(&bad_b));
    }

    // -----------------------------------------------------------------
    // Stage 3d-0.10 — selector programme pinning
    // -----------------------------------------------------------------

    #[test]
    fn balance_selector_publics_cover_all_blocks() {
        let publics = emit_balance_selector_public_columns(0, LOG_ROWS);
        // Two public columns per block: is_reset, is_input.
        assert_eq!(publics.len(), 2 * BALANCE_N_BLOCKS);
        // Columns pinned are in the expected positions.
        for blk in 0..BALANCE_N_BLOCKS {
            let base = blk * BIT_ADDER_N_COLS;
            assert_eq!(publics[2 * blk].col, base + BIT_ADDER_COL_IS_RESET);
            assert_eq!(publics[2 * blk + 1].col, base + BIT_ADDER_COL_IS_INPUT);
        }
    }

    #[test]
    fn balance_selector_publics_match_honest_witness() {
        let air = BalanceGateAir::new_with_selector_pins(LOG_ROWS);
        let (ins, outs, fee) = balanced_tuple(17);
        let trace = air.build_trace(ins, outs, fee);
        assert!(air.check(&trace));
        assert_eq!(air.public_columns().len(), 2 * BALANCE_N_BLOCKS);
    }

    #[test]
    fn balance_selector_pin_rejects_tampered_is_input() {
        let air = BalanceGateAir::new_with_selector_pins(LOG_ROWS);
        let (ins, outs, fee) = balanced_tuple(21);
        let mut bad = air.build_trace(ins, outs, fee);
        // Flip is_input of block A0 at a padding row (the gate layer
        // would not observe it — only the public-column check catches
        // this).
        let col = BLK_A0 * BIT_ADDER_N_COLS + BIT_ADDER_COL_IS_INPUT;
        // Block A0 is 64 bits wide, so row 100 is in the padding region.
        bad.columns[col][100] = Block128::ONE;
        assert!(!air.check(&bad));
    }

    #[test]
    fn balance_selector_pin_rejects_tampered_is_reset() {
        let air = BalanceGateAir::new_with_selector_pins(LOG_ROWS);
        let (ins, outs, fee) = balanced_tuple(22);
        let mut bad = air.build_trace(ins, outs, fee);
        let col = BLK_B21 * BIT_ADDER_N_COLS + BIT_ADDER_COL_IS_RESET;
        // Row 1 is not an instance-start row for any instance in a
        // 128-row stride, so programme pins it to ZERO. Set it to ONE.
        bad.columns[col][1] = Block128::ONE;
        assert!(!air.check(&bad));
    }

    #[test]
    fn balance_without_selector_pin_is_backward_compatible() {
        // Legacy `new()` still works, no public columns declared.
        let air = BalanceGateAir::new(LOG_ROWS);
        let (ins, outs, fee) = balanced_tuple(23);
        assert!(air.check(&air.build_trace(ins, outs, fee)));
        assert!(air.public_columns().is_empty());
    }
}
