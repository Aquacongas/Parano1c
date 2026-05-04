// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! `BitAdderAir` — Stage 3b-3a width-parameterised ripple-carry adder.
//!
//! Generalises `CarryRippleAir` to arbitrary input width `W ≤ 127`.
//! Each adder instance occupies `WORD_BITS = 128` consecutive rows of
//! the hypercube (a fixed power-of-two word, independent of `W`), with
//! `W` "active" input rows at positions `0..W-1` and `128 - W` padding
//! rows at positions `W..127`. The final output carry `c_W` lives on
//! row `W` of each instance.
//!
//! Column layout (6 columns, all `Bit`-domain):
//!
//! | idx | name        | active on       | semantics                          |
//! | --- | ----------- | --------------- | ---------------------------------- |
//! | 0   | `a`         | rows `0..W-1`   | input bit `a_i`                    |
//! | 1   | `b`         | rows `0..W-1`   | input bit `b_i`                    |
//! | 2   | `sum`       | rows `0..W-1`   | `s_i = a_i + b_i + c_i` (char-2)   |
//! | 3   | `carry`     | rows `0..=W`    | `c_0 = 0`; `c_{i+1} = a_i·b_i +`   |
//! |     |             |                 | `a_i·c_i + b_i·c_i`                |
//! | 4   | `is_reset`  | row 0 of inst   | resets carry-in to 0               |
//! | 5   | `is_input`  | rows `0..W-1`   | selector enabling FA on input rows |
//!
//! Semantics of rows `W..127` ("padding"): `a = b = sum = 0` (pinned via
//! degree-2 selector gates). `carry` is **not** pinned on rows `W+1..127`
//! — those cells are don't-cares and not read by any downstream gate.
//! `sum[W]` is **not** used; the final carry-out is read from
//! `carry[W]`. The stacked layout lets `N = 2^(log_rows - 7)` independent
//! adder instances share one column matrix.
//!
//! Selectors (`is_reset`, `is_input`) are witness columns, not pinned
//! to position by a separate constraint — tampering them triggers
//! violations through the dependent gates (mirrors the precedent set by
//! `CarryRippleAir` and `RangeGateAir`).

use crate::gates::BoolGate;
use crate::{Air, ColumnDomain, Constraint, EvalFrame, Trace};
use noid_core::{Block128, TowerField};

/// Word width of one adder instance (rows per instance). `W ≤ 127`
/// guarantees the final carry row `W` fits inside the word.
pub const BIT_ADDER_WORD_BITS: usize = 128;
pub const BIT_ADDER_LOG_WORD_BITS: usize = 7;
/// Maximum input width (in bits) of one adder instance.
pub const BIT_ADDER_MAX_WIDTH: usize = 127;

pub const BIT_ADDER_N_COLS: usize = 6;
pub const BIT_ADDER_COL_A: usize = 0;
pub const BIT_ADDER_COL_B: usize = 1;
pub const BIT_ADDER_COL_SUM: usize = 2;
pub const BIT_ADDER_COL_CARRY: usize = 3;
pub const BIT_ADDER_COL_IS_RESET: usize = 4;
pub const BIT_ADDER_COL_IS_INPUT: usize = 5;

/// Column layout for one `bit_adder` block. Every gate in this module
/// reads its column indices off a [`BitAdderLayout`] instance; the
/// default layout matches the `BIT_ADDER_COL_*` constants used by the
/// standalone [`BitAdderAir`], while [`BitAdderLayout::shifted`] lets
/// several blocks coexist at contiguous offsets in a composite trace.
#[derive(Debug, Clone, Copy)]
pub struct BitAdderLayout {
    pub a: usize,
    pub b: usize,
    pub sum: usize,
    pub carry: usize,
    pub is_reset: usize,
    pub is_input: usize,
}

impl BitAdderLayout {
    /// Standalone-AIR layout: columns `0..6` in declaration order.
    pub const DEFAULT: Self = Self {
        a: BIT_ADDER_COL_A,
        b: BIT_ADDER_COL_B,
        sum: BIT_ADDER_COL_SUM,
        carry: BIT_ADDER_COL_CARRY,
        is_reset: BIT_ADDER_COL_IS_RESET,
        is_input: BIT_ADDER_COL_IS_INPUT,
    };

    /// Shift every column index by `base`. Handy when tiling several
    /// blocks at contiguous offsets in a composite trace.
    pub const fn shifted(base: usize) -> Self {
        Self {
            a: BIT_ADDER_COL_A + base,
            b: BIT_ADDER_COL_B + base,
            sum: BIT_ADDER_COL_SUM + base,
            carry: BIT_ADDER_COL_CARRY + base,
            is_reset: BIT_ADDER_COL_IS_RESET + base,
            is_input: BIT_ADDER_COL_IS_INPUT + base,
        }
    }
}

impl Default for BitAdderLayout {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// `(1 + is_input) · col == 0` — pins `col` to zero on padding rows.
/// Degree 2.
pub struct PadZeroGate {
    cols: [usize; 2],
}

impl PadZeroGate {
    /// Default layout: `is_input` taken from `BIT_ADDER_COL_IS_INPUT`.
    pub fn new(col: usize) -> Self {
        Self::with_is_input(BIT_ADDER_COL_IS_INPUT, col)
    }

    /// Explicit `is_input` column — lets this gate live in a composite
    /// trace where multiple bit_adder blocks each own a distinct
    /// selector column.
    pub fn with_is_input(is_input: usize, col: usize) -> Self {
        Self {
            cols: [is_input, col],
        }
    }
}

impl Constraint for PadZeroGate {
    fn degree(&self) -> usize {
        2
    }
    fn columns(&self) -> &[usize] {
        &self.cols
    }
    fn evaluate(&self, frame: EvalFrame) -> Block128 {
        let is_input = frame.local[0];
        let v = frame.local[1];
        (Block128::ONE + is_input) * v
    }
}

/// `is_input · (sum + a + b + carry) == 0` — full-adder sum relation
/// on active input rows. Degree 2.
pub struct FaSumGate {
    cols: [usize; 5],
}

impl Default for FaSumGate {
    fn default() -> Self {
        Self::new()
    }
}

impl FaSumGate {
    /// Default layout (standalone `BitAdderAir`).
    pub fn new() -> Self {
        Self::with_layout(BitAdderLayout::DEFAULT)
    }

    /// Construct the gate for an explicit block layout; column order
    /// inside the frame is `[is_input, sum, a, b, carry]`.
    pub fn with_layout(l: BitAdderLayout) -> Self {
        Self {
            cols: [l.is_input, l.sum, l.a, l.b, l.carry],
        }
    }
}

impl Constraint for FaSumGate {
    fn degree(&self) -> usize {
        2
    }
    fn columns(&self) -> &[usize] {
        &self.cols
    }
    fn evaluate(&self, frame: EvalFrame) -> Block128 {
        let is_input = frame.local[0];
        let sum = frame.local[1];
        let a = frame.local[2];
        let b = frame.local[3];
        let carry = frame.local[4];
        is_input * (sum + a + b + carry)
    }
}

/// `is_reset · carry == 0` — carry-in is zero at every instance start.
/// Degree 2.
pub struct BitAdderCarryInitGate {
    cols: [usize; 2],
}

impl Default for BitAdderCarryInitGate {
    fn default() -> Self {
        Self::new()
    }
}

impl BitAdderCarryInitGate {
    /// Default layout (standalone `BitAdderAir`).
    pub fn new() -> Self {
        Self::with_layout(BitAdderLayout::DEFAULT)
    }

    pub fn with_layout(l: BitAdderLayout) -> Self {
        Self {
            cols: [l.is_reset, l.carry],
        }
    }
}

impl Constraint for BitAdderCarryInitGate {
    fn degree(&self) -> usize {
        2
    }
    fn columns(&self) -> &[usize] {
        &self.cols
    }
    fn evaluate(&self, frame: EvalFrame) -> Block128 {
        frame.local[0] * frame.local[1]
    }
}

/// `is_input · (1 + is_reset_next) · (next(carry) + a·b + a·c + b·c) == 0`.
///
/// Enforces the majority-function carry recurrence on every active
/// input row. The `is_input` factor restricts the rule to rows
/// `0..W-1`; the `(1 + is_reset_next)` factor suppresses the constraint
/// at the cyclic wrap into the next instance (not needed in practice,
/// since the wrap target is padding, but kept for uniformity with
/// `CarryRippleAir`). Degree 4.
pub struct BitAdderCarryNextGate {
    local: [usize; 4],
    shifted: [usize; 2],
}

impl Default for BitAdderCarryNextGate {
    fn default() -> Self {
        Self::new()
    }
}

impl BitAdderCarryNextGate {
    /// Default layout (standalone `BitAdderAir`).
    pub fn new() -> Self {
        Self::with_layout(BitAdderLayout::DEFAULT)
    }

    pub fn with_layout(l: BitAdderLayout) -> Self {
        Self {
            local: [l.is_input, l.a, l.b, l.carry],
            shifted: [l.carry, l.is_reset],
        }
    }
}

impl Constraint for BitAdderCarryNextGate {
    fn degree(&self) -> usize {
        4
    }
    fn columns(&self) -> &[usize] {
        &self.local
    }
    fn shifted_columns(&self) -> &[usize] {
        &self.shifted
    }
    fn evaluate(&self, frame: EvalFrame) -> Block128 {
        let is_input = frame.local[0];
        let a = frame.local[1];
        let b = frame.local[2];
        let carry = frame.local[3];
        let next_carry = frame.next[0];
        let is_reset_next = frame.next[1];
        is_input
            * (Block128::ONE + is_reset_next)
            * (next_carry + a * b + a * carry + b * carry)
    }
}

/// Emit the full set of constraints for one `bit_adder` block at the
/// given [`BitAdderLayout`]. Two blocks living at disjoint column
/// offsets in the same composite trace can each call this with their
/// own layout — the returned vectors can be concatenated directly.
///
/// Selector programmes for one `bit_adder` block. Both columns are
/// pure public data: `is_input` is `1` on rows `inst*128 + b` for
/// `b ∈ 0..width`, `0` elsewhere; `is_reset` is `1` only on row
/// `inst*128` of every instance. Used by §3d-0.10 to pin the block's
/// selector columns via `PublicColumn` declarations.
pub fn bit_adder_is_input_programme(width: usize, log_rows: usize) -> Vec<Block128> {
    assert!(width >= 1 && width <= BIT_ADDER_MAX_WIDTH);
    assert!(log_rows >= BIT_ADDER_LOG_WORD_BITS);
    let n_rows = 1usize << log_rows;
    let n_instances = 1usize << (log_rows - BIT_ADDER_LOG_WORD_BITS);
    let mut v = vec![Block128::ZERO; n_rows];
    for inst in 0..n_instances {
        let base = inst * BIT_ADDER_WORD_BITS;
        for b in 0..width {
            v[base + b] = Block128::ONE;
        }
    }
    v
}

pub fn bit_adder_is_reset_programme(log_rows: usize) -> Vec<Block128> {
    assert!(log_rows >= BIT_ADDER_LOG_WORD_BITS);
    let n_rows = 1usize << log_rows;
    let n_instances = 1usize << (log_rows - BIT_ADDER_LOG_WORD_BITS);
    let mut v = vec![Block128::ZERO; n_rows];
    for inst in 0..n_instances {
        v[inst * BIT_ADDER_WORD_BITS] = Block128::ONE;
    }
    v
}

/// Gate list is identical to the one baked into [`BitAdderAir::new`]:
/// one `BoolGate` per column, three `PadZeroGate`s on the bit columns,
/// and the three full-adder gates (`FaSumGate`,
/// `BitAdderCarryInitGate`, `BitAdderCarryNextGate`).
pub fn emit_block_constraints(layout: BitAdderLayout) -> Vec<Box<dyn Constraint>> {
    vec![
        Box::new(BoolGate::new(layout.a)),
        Box::new(BoolGate::new(layout.b)),
        Box::new(BoolGate::new(layout.sum)),
        Box::new(BoolGate::new(layout.carry)),
        Box::new(BoolGate::new(layout.is_reset)),
        Box::new(BoolGate::new(layout.is_input)),
        Box::new(PadZeroGate::with_is_input(layout.is_input, layout.a)),
        Box::new(PadZeroGate::with_is_input(layout.is_input, layout.b)),
        Box::new(PadZeroGate::with_is_input(layout.is_input, layout.sum)),
        Box::new(FaSumGate::with_layout(layout)),
        Box::new(BitAdderCarryInitGate::with_layout(layout)),
        Box::new(BitAdderCarryNextGate::with_layout(layout)),
    ]
}

/// Width-parameterised ripple-carry adder AIR. One or more adder
/// instances are laid out consecutively along the hypercube, each
/// occupying `WORD_BITS = 128` rows; `W ≤ 127` input bits and one
/// output carry at row `W`. The `log_rows >= TAU + 1 = 8` invariant
/// demanded by the STARK layer is automatically satisfied since
/// `LOG_WORD_BITS = 7` + at least one instance means `log_rows >= 8`
/// when `n_instances >= 2`; for a single-instance trace (`log_rows =
/// 7`) callers must keep `log_rows >= 8` themselves if they go through
/// the STARK wrapper.
pub struct BitAdderAir {
    width: usize,
    log_rows: usize,
    constraints: Vec<Box<dyn Constraint>>,
}

impl BitAdderAir {
    pub fn new(width: usize, log_rows: usize) -> Self {
        assert!(
            width >= 1 && width <= BIT_ADDER_MAX_WIDTH,
            "BitAdderAir width {} must be in 1..={}",
            width,
            BIT_ADDER_MAX_WIDTH
        );
        assert!(
            log_rows >= BIT_ADDER_LOG_WORD_BITS,
            "BitAdderAir needs at least one {}-row instance (log_rows >= {})",
            BIT_ADDER_WORD_BITS,
            BIT_ADDER_LOG_WORD_BITS
        );
        let constraints = emit_block_constraints(BitAdderLayout::DEFAULT);
        Self {
            width,
            log_rows,
            constraints,
        }
    }

    pub fn width(&self) -> usize {
        self.width
    }

    pub fn n_instances(&self) -> usize {
        1usize << (self.log_rows - BIT_ADDER_LOG_WORD_BITS)
    }

    /// Build a parallel trace from `n_instances` `(a, b)` operand pairs,
    /// interpreting each pair as `width`-bit operands (low-order bits
    /// significant). Returns a fully-zeroed padding region on rows
    /// `width..127` of each instance (`carry` row `width` carries the
    /// output carry; rows `width+1..127` are zero by construction even
    /// though the AIR does not constrain them).
    pub fn build_trace(&self, adders: &[(u128, u128)]) -> Trace {
        let n = self.n_instances();
        assert_eq!(adders.len(), n, "expected {} adders, got {}", n, adders.len());
        let n_rows = 1usize << self.log_rows;
        let w_word = BIT_ADDER_WORD_BITS;
        let w_in = self.width;
        let mask_input: u128 = if w_in == 128 {
            u128::MAX
        } else {
            (1u128 << w_in) - 1
        };

        let mut a_col = vec![Block128::ZERO; n_rows];
        let mut b_col = vec![Block128::ZERO; n_rows];
        let mut sum_col = vec![Block128::ZERO; n_rows];
        let mut carry_col = vec![Block128::ZERO; n_rows];
        let mut is_reset_col = vec![Block128::ZERO; n_rows];
        let mut is_input_col = vec![Block128::ZERO; n_rows];

        for (inst, &(a_word, b_word)) in adders.iter().enumerate() {
            assert!(
                a_word == (a_word & mask_input),
                "a operand exceeds width {} bits",
                w_in
            );
            assert!(
                b_word == (b_word & mask_input),
                "b operand exceeds width {} bits",
                w_in
            );
            let base = inst * w_word;
            let mut c: u128 = 0;
            for bit in 0..w_in {
                let row = base + bit;
                let a_bit = (a_word >> bit) & 1;
                let b_bit = (b_word >> bit) & 1;
                let s_bit = a_bit ^ b_bit ^ c;
                let next_c = (a_bit & b_bit) ^ (a_bit & c) ^ (b_bit & c);
                a_col[row] = Block128::from(a_bit);
                b_col[row] = Block128::from(b_bit);
                sum_col[row] = Block128::from(s_bit);
                carry_col[row] = Block128::from(c);
                is_input_col[row] = Block128::ONE;
                if bit == 0 {
                    is_reset_col[row] = Block128::ONE;
                }
                c = next_c;
            }
            // Final output carry on row `w_in` of the instance.
            carry_col[base + w_in] = Block128::from(c);
        }

        let cols = vec![
            a_col,
            b_col,
            sum_col,
            carry_col,
            is_reset_col,
            is_input_col,
        ];
        let domains = vec![ColumnDomain::Bit; BIT_ADDER_N_COLS];
        Trace::new_with_domains(cols, domains)
    }
}

impl Air for BitAdderAir {
    fn n_columns(&self) -> usize {
        BIT_ADDER_N_COLS
    }
    fn log_rows(&self) -> usize {
        self.log_rows
    }
    fn constraints(&self) -> &[Box<dyn Constraint>] {
        &self.constraints
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_pairs(n: usize, width: usize, seed: u64) -> Vec<(u128, u128)> {
        let mask: u128 = if width == 128 {
            u128::MAX
        } else {
            (1u128 << width) - 1
        };
        let mut s = seed;
        (0..n)
            .map(|_| {
                s = s.wrapping_add(0x9E3779B97F4A7C15);
                let a = ((s as u128) << 64) ^ (s.wrapping_mul(0xC6BC279692B5C323) as u128);
                s = s.wrapping_add(0x9E3779B97F4A7C15);
                let b = ((s as u128) << 64) ^ (s.wrapping_mul(0xC6BC279692B5C323) as u128);
                (a & mask, b & mask)
            })
            .collect()
    }

    fn read_carry_out(trace: &Trace, inst: usize, width: usize) -> u128 {
        trace.columns[BIT_ADDER_COL_CARRY][inst * BIT_ADDER_WORD_BITS + width].to_u128()
    }

    fn read_sum(trace: &Trace, inst: usize, width: usize) -> u128 {
        let base = inst * BIT_ADDER_WORD_BITS;
        let mut s = 0u128;
        for i in 0..width {
            let bit = trace.columns[BIT_ADDER_COL_SUM][base + i].to_u128() & 1;
            s |= bit << i;
        }
        s
    }

    #[test]
    fn bit_adder_honest_64() {
        let air = BitAdderAir::new(64, 8); // 2 instances
        let pairs = vec![
            (0x0123_4567_89AB_CDEFu128, 0xFEDC_BA98_7654_3210u128),
            (u128::from(u64::MAX), 1u128),
        ];
        let trace = air.build_trace(&pairs);
        assert!(air.check(&trace));
        // Sanity: the second instance (MAX + 1) must have carry-out 1
        // and sum 0.
        assert_eq!(read_carry_out(&trace, 1, 64), 1);
        assert_eq!(read_sum(&trace, 1, 64), 0);
        // First instance: plain integer add truncated to 64 bits.
        let expected_sum =
            0x0123_4567_89AB_CDEFu128.wrapping_add(0xFEDC_BA98_7654_3210u128) & ((1u128 << 64) - 1);
        assert_eq!(read_sum(&trace, 0, 64), expected_sum);
    }

    #[test]
    fn bit_adder_honest_all_widths() {
        for &width in &[64usize, 65, 66, 67] {
            let air = BitAdderAir::new(width, 8);
            let pairs = mk_pairs(air.n_instances(), width, 0xA5A5 ^ width as u64);
            let trace = air.build_trace(&pairs);
            assert!(
                air.check(&trace),
                "honest trace rejected at width={width}"
            );
            // Spot-check: sum + (carry_out << width) == a + b (mod 2^(width+1)).
            for (inst, &(a, b)) in pairs.iter().enumerate() {
                let sum = read_sum(&trace, inst, width);
                let cout = read_carry_out(&trace, inst, width);
                let modulus_bits = width + 1;
                let modulus: u128 = if modulus_bits >= 128 {
                    u128::MAX
                } else {
                    (1u128 << modulus_bits) - 1
                };
                let expected = a.wrapping_add(b) & modulus;
                let got = (sum | (cout << width)) & modulus;
                assert_eq!(got, expected, "width={width} inst={inst}");
            }
        }
    }

    #[test]
    fn bit_adder_rejects_flipped_sum_bit() {
        let air = BitAdderAir::new(65, 8);
        let pairs = mk_pairs(air.n_instances(), 65, 0xDEAD);
        let mut trace = air.build_trace(&pairs);
        trace.columns[BIT_ADDER_COL_SUM][5] += Block128::ONE;
        assert!(!air.check(&trace));
    }

    #[test]
    fn bit_adder_rejects_flipped_carry_mid_chain() {
        let air = BitAdderAir::new(66, 8);
        let pairs = mk_pairs(air.n_instances(), 66, 0xBEEF);
        let mut trace = air.build_trace(&pairs);
        // Row 10 is mid-instance-0, carry is unpinned-free in isolation
        // but FA constraint then breaks at the same row.
        trace.columns[BIT_ADDER_COL_CARRY][10] += Block128::ONE;
        assert!(!air.check(&trace));
    }

    #[test]
    fn bit_adder_rejects_flipped_final_carry() {
        let air = BitAdderAir::new(67, 8);
        let pairs = mk_pairs(air.n_instances(), 67, 0xF00D);
        let mut trace = air.build_trace(&pairs);
        // Flip the final carry-out at row 67 of instance 0.
        trace.columns[BIT_ADDER_COL_CARRY][67] += Block128::ONE;
        assert!(!air.check(&trace));
    }

    #[test]
    fn bit_adder_rejects_fake_init_carry() {
        let air = BitAdderAir::new(64, 8);
        let pairs = mk_pairs(air.n_instances(), 64, 0xCAFE);
        let mut trace = air.build_trace(&pairs);
        trace.columns[BIT_ADDER_COL_CARRY][0] = Block128::ONE;
        // Fix up sum[0] so FA at row 0 still holds — only the init gate
        // should fail.
        trace.columns[BIT_ADDER_COL_SUM][0] += Block128::ONE;
        assert!(!air.check(&trace));
    }

    #[test]
    fn bit_adder_rejects_nonzero_pad_input() {
        let air = BitAdderAir::new(64, 8);
        let pairs = mk_pairs(air.n_instances(), 64, 0x1234);
        let mut trace = air.build_trace(&pairs);
        // Set `a` on a padding row (past the active input region).
        trace.columns[BIT_ADDER_COL_A][70] = Block128::ONE;
        assert!(!air.check(&trace));
    }

    #[test]
    fn bit_adder_rejects_spurious_reset_marker() {
        let air = BitAdderAir::new(64, 8);
        let pairs = mk_pairs(air.n_instances(), 64, 0x5678);
        let mut trace = air.build_trace(&pairs);
        // Plant a fake reset marker mid-instance 0 at a row where the
        // honest carry column is 1. `is_reset · carry = 1 · 1 = 1` —
        // carry-init gate must catch it. Find such a row; if none
        // exists in this seed, fall through with a guaranteed
        // synthetic carry of 1.
        let mut caught = false;
        for row in 1..64 {
            if trace.columns[BIT_ADDER_COL_CARRY][row] == Block128::ONE {
                trace.columns[BIT_ADDER_COL_IS_RESET][row] = Block128::ONE;
                caught = true;
                break;
            }
        }
        if !caught {
            trace.columns[BIT_ADDER_COL_IS_RESET][10] = Block128::ONE;
            trace.columns[BIT_ADDER_COL_CARRY][10] = Block128::ONE;
        }
        assert!(!air.check(&trace));
    }

    #[test]
    fn bit_adder_rejects_wrong_fa_sum() {
        let air = BitAdderAir::new(66, 8);
        let pairs = mk_pairs(air.n_instances(), 66, 0xABCD);
        let mut trace = air.build_trace(&pairs);
        // Flip `a` mid-instance without compensating sum/carry — FA
        // must catch it.
        trace.columns[BIT_ADDER_COL_A][3] += Block128::ONE;
        assert!(!air.check(&trace));
    }

    /// Two honest adder blocks living side-by-side in one composite
    /// trace. Block 0 at columns `0..6` (default layout), block 1 at
    /// columns `6..12` (shifted by 6). `emit_block_constraints` must
    /// evaluate correctly at the shifted offset, and any tamper inside
    /// the second block must be caught by the second block's gates.
    #[test]
    fn bit_adder_gates_work_at_shifted_offset() {
        let width = 64usize;
        let log_rows = 8usize; // one 128-row word per block, same hypercube
        let air0 = BitAdderAir::new(width, log_rows);
        // Single-instance traces per block; ensure n_instances matches.
        let pairs0 = mk_pairs(air0.n_instances(), width, 0x1111);
        let pairs1 = mk_pairs(air0.n_instances(), width, 0x2222);
        let t0 = air0.build_trace(&pairs0);
        let t1 = air0.build_trace(&pairs1);

        // Stitch the two 6-column traces into one 12-column composite.
        let mut cols: Vec<Vec<Block128>> = t0.columns.clone();
        cols.extend(t1.columns.clone());
        let domains = vec![ColumnDomain::Bit; 12];
        let trace = Trace::new_with_domains(cols, domains);

        // Hand-built composite AIR: block 0 default layout, block 1
        // shifted by BIT_ADDER_N_COLS.
        let mut constraints = emit_block_constraints(BitAdderLayout::DEFAULT);
        constraints.extend(emit_block_constraints(BitAdderLayout::shifted(
            BIT_ADDER_N_COLS,
        )));
        let air = crate::CompositeAir::from_parts(log_rows, 12, constraints);

        assert!(air.check(&trace), "honest composite trace rejected");

        // Tamper inside the second block's sum column — only the
        // shifted FA gate can catch it.
        let mut bad = trace.clone();
        bad.columns[BIT_ADDER_N_COLS + BIT_ADDER_COL_SUM][3] += Block128::ONE;
        assert!(!air.check(&bad));

        // Tamper inside the first block's carry column — only the
        // default FA/carry gates catch it.
        let mut bad = trace.clone();
        bad.columns[BIT_ADDER_COL_CARRY][5] += Block128::ONE;
        assert!(!air.check(&bad));
    }

    /// A shifted block in isolation (no block at the default offset)
    /// must still pass `air.check` when given an honest trace that
    /// leaves columns `0..6` zero and populates `6..12`. Proves that
    /// the gate family is genuinely column-offset-agnostic and does not
    /// sneak in any hard-coded reads of the default columns.
    #[test]
    fn bit_adder_gates_isolated_at_shifted_offset() {
        let width = 65usize;
        let log_rows = 8usize;
        let air_default = BitAdderAir::new(width, log_rows);
        let pairs = mk_pairs(air_default.n_instances(), width, 0x3333);
        let shifted_trace = air_default.build_trace(&pairs);

        // Pad six zero columns in front of the 6-column honest trace.
        let n_rows = shifted_trace.n_rows();
        let mut cols: Vec<Vec<Block128>> = (0..BIT_ADDER_N_COLS)
            .map(|_| vec![Block128::ZERO; n_rows])
            .collect();
        cols.extend(shifted_trace.columns.clone());
        let domains = vec![ColumnDomain::Bit; 12];
        let trace = Trace::new_with_domains(cols, domains);

        let constraints = emit_block_constraints(BitAdderLayout::shifted(BIT_ADDER_N_COLS));
        let air = crate::CompositeAir::from_parts(log_rows, 12, constraints);
        assert!(air.check(&trace), "isolated shifted block rejected");
    }

    #[test]
    #[should_panic(expected = "width")]
    fn bit_adder_rejects_width_zero() {
        let _ = BitAdderAir::new(0, 8);
    }

    #[test]
    #[should_panic(expected = "width")]
    fn bit_adder_rejects_width_overflow() {
        let _ = BitAdderAir::new(128, 8);
    }

    #[test]
    #[should_panic(expected = "exceeds width")]
    fn bit_adder_rejects_operand_overflow() {
        let air = BitAdderAir::new(64, 7);
        // Only 1 instance for log_rows=7.
        let _ = air.build_trace(&[(1u128 << 64, 0)]);
    }
}
