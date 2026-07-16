// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Fixed-capacity `P128` scanner for native `PagedSpend` page streams.
//!
//! This relation deliberately stops at the acceptance seam: callers provide
//! the page hash and the semantic aliases already derived from the Tx8x2 body
//! spine/action surface.  The scanner proves the block-level page protocol and
//! emits canonical logical authorization aliases, but does not alter the
//! production block-slot/freezer relation.
//!
//! The physical shape is always 128 pages and 128 logical authorization slots.
//! There is deliberately no smaller checkpoint or alternate public binder.
//! Page liveness is a prefix, while START/END delimit exact-length groups.  A
//! START carries the claimed group page count; the countdown proves that END
//! occurs on exactly that page and supplies the count absorbed by `PAGEDTX_`.
//! The logical digest is the exact native sponge:
//!
//! ```text
//! permute(version, page_count, PAGEDTX_ capacity IV)
//! for page_hash in ordered_pages: absorb_pair(page_hash); permute()
//! absorb_pair(0x80, 1 << 120); permute()
//! ```
//!
//! Inputs and outputs are dense across all pages of a group, continuation
//! fees are zero, owner/epoch aliases are invariant, all counts are checked
//! u16 integers, and monetary conservation uses a tight 75-bit ripple adder.
//! The tight width is an exact checked-u128 implementation here: at most 1024
//! physical u64 inputs can occur, hence every possible physical sum is below
//! `2^74` and therefore below both `2^75` and `u128::MAX`.
//!
//! # Caller pins intentionally outside this module
//!
//! This scanner consumes semantic aliases; it does not fabricate their body
//! provenance.  Its eventual caller must pin `page_hash` to the Tx8x2 body
//! spine, pin START/END to validity-bitmap bits 10/11 in body leaf L15, bind
//! `page_live` and capacity ghosts to the block occupancy/canonical-ghost
//! relation, prove `is_coinbase == false`, connect selectors and amounts to the
//! action surface, enforce block-wide action-slot uniqueness, and insert the
//! compacted logical txids into the authenticated logical transaction root.
//! Until all of those connections land, this is an exploratory acceptance
//! component rather than a production consensus seam.

use noid_core::Block128;
use noid_poseidon2b::native::{capacity_iv, DomainTag};
use noid_tx::{TX_INPUTS, TX_OUTPUTS};

use crate::circuit_support::{
    const_block, flat_const, mul, pin_eq, pin_zero, poseidon2b_permute, range_check_bits,
    FieldR1csBuilder, LinExpr, Wire, F128,
};
use crate::paged_spend::{
    MAX_PAGEDSPEND_GROUPS, MAX_PAGEDSPEND_INPUTS, MAX_PAGEDSPEND_OUTPUTS, MAX_PAGEDSPEND_PAGES,
    PAGEDTX_VERSION,
};

const TAG_PAGEDTX: DomainTag = DomainTag::new(b"PAGEDTX_");

/// Physical PagedSpend page slots in the exploratory block relation.
pub const PAGED_SPEND_PAGE_CAPACITY: usize = MAX_PAGEDSPEND_PAGES;
/// Logical authorization slots in the sole P128/A128 scanner.
pub const PAGED_SPEND_AUTH_CAPACITY: usize = MAX_PAGEDSPEND_GROUPS;
const _: () = assert!(PAGED_SPEND_PAGE_CAPACITY * TX_OUTPUTS == MAX_PAGEDSPEND_OUTPUTS);
const _: () = assert!(PAGED_SPEND_AUTH_CAPACITY == 128);
const _: () = assert!(MAX_PAGEDSPEND_OUTPUTS <= u16::MAX as usize);
/// Reference fixture rows used to allocate 31 semantic aliases per page.
pub const PAGED_SPEND_PAGE_ALIAS_ROWS: usize = 3_968;
/// Exact scanner-only row delta for the fixed P128/A128 relation.
pub const PAGED_SPEND_A128_SCANNER_ROWS: usize = 563_777;
/// Constant-one + reference page aliases + scanner rows.
pub const PAGED_SPEND_A128_REFERENCE_USEFUL_ROWS: usize = 567_746;
/// Eleven u64 decompositions per page, each 64 boolean rows plus one pin.
pub const PAGED_SPEND_A128_REUSABLE_RANGE_ROWS: usize = 91_520;
/// Scanner delta when those same-builder ranges already exist.
pub const PAGED_SPEND_A128_REUSED_SCANNER_ROWS: usize =
    PAGED_SPEND_A128_SCANNER_ROWS - PAGED_SPEND_A128_REUSABLE_RANGE_ROWS;
/// Tower bits in every native monetary lane.
const U64_BITS: usize = 64;
/// Native page/group/block counters are canonical u16 values.
const COUNT_BITS: usize = 16;
/// `1024 * (2^64 - 1) < 2^74`; one spare bit keeps every adder checked.
const MONEY_BITS: usize = 75;

const _: () = assert!(PAGED_SPEND_A128_REUSABLE_RANGE_ROWS == 128 * 11 * 65);
const _: () = assert!(PAGED_SPEND_A128_REUSED_SCANNER_ROWS == 472_257);

/// Semantic aliases for one physical page.
///
/// The fields are intentionally expression-valued: the eventual block
/// relation can connect them directly to the already-authenticated Tx8x2
/// body/action trace without allocating a second page representation.
#[derive(Clone)]
pub struct PagedSpendPageTraceInput {
    /// Physical page occupancy.  Across the 128 slots this must be a prefix.
    pub page_live: LinExpr,
    /// START marker (validity-bitmap bit 10).
    pub start: LinExpr,
    /// END marker (validity-bitmap bit 11).
    pub end: LinExpr,
    /// Exact logical page count, nonzero only on START.
    pub declared_page_count: LinExpr,
    /// Existing Tx8x2 body hash, low/high digest lanes.
    pub page_hash: [LinExpr; 2],
    /// Shared input owner, low/high address lanes.
    pub input_owner: [LinExpr; 2],
    /// Shared anti-replay epoch anchor, low/high lanes.
    pub epoch_anchor: [LinExpr; 2],
    /// Raw page fee.  It is nonzero only on START.
    pub fee: LinExpr,
    /// Tx8x2 input bitmap aliases.
    pub input_live: [LinExpr; TX_INPUTS],
    /// Raw u64 input amounts.
    pub input_amounts: [LinExpr; TX_INPUTS],
    /// Tx8x2 output bitmap aliases.
    pub output_live: [LinExpr; TX_OUTPUTS],
    /// Raw u64 output amounts.
    pub output_amounts: [LinExpr; TX_OUTPUTS],
}

/// One u64 lane whose tower-basis decomposition is already constrained in
/// this same builder.  The value expression is retained so scanner reuse can
/// require structural identity rather than accepting caller-supplied bits.
#[derive(Clone)]
pub struct ProvenU64Range {
    pub(crate) value: LinExpr,
    pub(crate) bits: [Wire; U64_BITS],
}

/// Exact reusable u64 ranges belonging to one page's semantic aliases.
///
/// This is the research seam that production public arithmetic may eventually
/// implement.  It is local and concrete; no private production trace type is
/// imported into the laboratory.
#[derive(Clone)]
pub struct PagedSpendPageProvenRanges {
    pub(crate) fee: ProvenU64Range,
    pub(crate) inputs: [ProvenU64Range; TX_INPUTS],
    pub(crate) outputs: [ProvenU64Range; TX_OUTPUTS],
}

impl PagedSpendPageProvenRanges {
    pub fn prove(b: &mut FieldR1csBuilder, page: &PagedSpendPageTraceInput) -> Self {
        let prove = |b: &mut FieldR1csBuilder, value: &LinExpr| ProvenU64Range {
            value: value.clone(),
            bits: range_check_bits(b, value, U64_BITS)
                .try_into()
                .expect("u64 range has exactly 64 bits"),
        };
        Self {
            fee: prove(b, &page.fee),
            inputs: std::array::from_fn(|slot| prove(b, &page.input_amounts[slot])),
            outputs: std::array::from_fn(|slot| prove(b, &page.output_amounts[slot])),
        }
    }
}

/// One page-indexed logical END row.  Every payload lane is zero away from an
/// END, making this a stable seam for other block-level consumers.
#[derive(Clone)]
pub struct PagedSpendEndTrace {
    pub live: LinExpr,
    pub logical_txid: [LinExpr; 2],
    pub input_owner: [LinExpr; 2],
    pub epoch_anchor: [LinExpr; 2],
    pub fee: LinExpr,
    pub page_count: LinExpr,
    pub live_input_count: LinExpr,
    pub live_output_count: LinExpr,
    /// Checked group input sum.  Conservation proves this is also
    /// `output_sum + fee` as an unsigned integer.
    pub balanced_sum: LinExpr,
}

/// Canonical authorization statement for one logical PagedSpend group.
///
/// Native authorization binds exactly `(logical_txid, input_owner)`.  These
/// rows are the END rows stably compacted in physical order; live rows are a
/// prefix and all capacity padding is exactly zero.
#[derive(Clone)]
pub struct PagedSpendAuthAliasTrace {
    pub live: LinExpr,
    pub logical_txid: [LinExpr; 2],
    pub input_owner: [LinExpr; 2],
}

/// Outputs of the fixed `P128/A128` scanner.
pub struct PagedSpendBlockTrace<const AUTH_CAPACITY: usize> {
    /// Page-indexed END facts (128 fixed rows).
    pub end_rows: [PagedSpendEndTrace; PAGED_SPEND_PAGE_CAPACITY],
    /// Stable physical-order logical authorization aliases.
    pub logical_auth_aliases: [PagedSpendAuthAliasTrace; AUTH_CAPACITY],
    /// Checked u16 block counters.
    pub page_count: LinExpr,
    pub logical_count: LinExpr,
    pub live_input_count: LinExpr,
    pub live_output_count: LinExpr,
}

#[inline]
fn one() -> LinExpr {
    LinExpr::constant(F128::ONE)
}

#[inline]
fn pin_boolean(b: &mut FieldR1csBuilder, value: &LinExpr) {
    let relation = mul(b, value, &value.add_const(F128::ONE));
    pin_zero(b, &relation);
}

#[inline]
fn pin_gated_zero(b: &mut FieldR1csBuilder, gate: &LinExpr, value: &LinExpr) {
    let relation = mul(b, gate, value);
    pin_zero(b, &relation);
}

/// Boolean selector mux: `selector ? when_one : when_zero`.
#[inline]
fn mux(
    b: &mut FieldR1csBuilder,
    selector: &LinExpr,
    when_one: &LinExpr,
    when_zero: &LinExpr,
) -> LinExpr {
    when_zero.add(&mul(b, selector, &when_one.add(when_zero)))
}

fn reconstruct_bits(bits: &[LinExpr]) -> LinExpr {
    assert!(bits.len() <= 128);
    bits.iter()
        .enumerate()
        .fold(LinExpr::zero(), |sum, (bit, value)| {
            sum.add(&value.scale(flat_const(1u128 << bit)))
        })
}

/// `1` iff every supplied proven-boolean bit is zero.
fn bits_are_zero(b: &mut FieldR1csBuilder, bits: &[LinExpr]) -> LinExpr {
    assert!(!bits.is_empty());
    bits.iter()
        .fold(one(), |acc, bit| mul(b, &acc, &bit.add_const(F128::ONE)))
}

/// Fixed-width ripple increment by one proven-boolean selector.
fn increment_bits<const WIDTH: usize>(
    b: &mut FieldR1csBuilder,
    bits: &[LinExpr; WIDTH],
    selector: &LinExpr,
) -> [LinExpr; WIDTH] {
    let mut carry = selector.clone();
    let next = std::array::from_fn(|index| {
        let previous = bits[index].clone();
        let sum = previous.add(&carry);
        carry = mul(b, &previous, &carry);
        sum
    });
    pin_zero(b, &carry);
    next
}

/// Fixed-width checked unsigned addition.  Inputs are already proven bits;
/// the final carry pin gives native `checked_add` semantics.
fn checked_add_bits<const WIDTH: usize>(
    b: &mut FieldR1csBuilder,
    lhs: &[LinExpr; WIDTH],
    rhs: &[LinExpr; WIDTH],
) -> [LinExpr; WIDTH] {
    let mut carry = LinExpr::zero();
    let sum = std::array::from_fn(|index| {
        let lhs_bit = lhs[index].clone();
        let rhs_bit = rhs[index].clone();
        let out = lhs_bit.add(&rhs_bit).add(&carry);
        let both = mul(b, &lhs_bit, &rhs_bit);
        let carry_with_xor = mul(b, &carry, &lhs_bit.add(&rhs_bit));
        carry = both.add(&carry_with_xor);
        out
    });
    pin_zero(b, &carry);
    sum
}

fn widen_u64(bits: &[Wire]) -> [LinExpr; MONEY_BITS] {
    assert_eq!(bits.len(), U64_BITS);
    std::array::from_fn(|index| {
        if index < U64_BITS {
            LinExpr::from_wire(bits[index])
        } else {
            LinExpr::zero()
        }
    })
}

/// Strict unsigned comparison against a public u16 constant.
fn lt_constant_bits(b: &mut FieldR1csBuilder, bits: &[LinExpr; COUNT_BITS], bound: u16) -> LinExpr {
    let mut less = LinExpr::zero();
    let mut equal = one();
    for index in (0..COUNT_BITS).rev() {
        let bit = bits[index].clone();
        if (bound >> index) & 1 == 1 {
            let decision = mul(b, &equal, &bit.add_const(F128::ONE));
            less = less.add(&decision);
            equal = mul(b, &equal, &bit);
        } else {
            equal = mul(b, &equal, &bit.add_const(F128::ONE));
        }
    }
    less
}

/// Update a dense-stream gap bit with one selector.  `gap * selector = 0`
/// rejects a live slot after the first dead slot; the returned bit is
/// `gap OR !selector`.
fn dense_step(b: &mut FieldR1csBuilder, gap: &LinExpr, selector: &LinExpr) -> LinExpr {
    pin_gated_zero(b, gap, selector);
    let not_selector = selector.add_const(F128::ONE);
    gap.add(&not_selector).add(&mul(b, gap, &not_selector))
}

/// Subtract one from a u16 bit vector.  The returned borrow is one exactly
/// when the input was zero.
fn subtract_one(
    b: &mut FieldR1csBuilder,
    bits: &[LinExpr; COUNT_BITS],
) -> ([LinExpr; COUNT_BITS], LinExpr) {
    let mut borrow = one();
    let difference = std::array::from_fn(|index| {
        let bit = bits[index].clone();
        let out = bit.add(&borrow);
        borrow = mul(b, &borrow, &bit.add_const(F128::ONE));
        out
    });
    (difference, borrow)
}

fn gate_array<const N: usize>(
    b: &mut FieldR1csBuilder,
    gate: &LinExpr,
    values: &[LinExpr; N],
) -> [LinExpr; N] {
    std::array::from_fn(|index| mul(b, gate, &values[index]))
}

/// Bind the full fixed-capacity page scanner.
///
/// The relation shape never depends on page occupancy, group boundaries,
/// bitmap selectors, or amounts. Its public API always builds P128/A128.
pub fn bind_paged_spend_block(
    b: &mut FieldR1csBuilder,
    pages: &[PagedSpendPageTraceInput; PAGED_SPEND_PAGE_CAPACITY],
) -> PagedSpendBlockTrace<PAGED_SPEND_AUTH_CAPACITY> {
    bind_paged_spend_block_inner::<PAGED_SPEND_AUTH_CAPACITY>(b, pages, None)
}

/// Bind the scanner while reusing same-builder u64 decompositions.
///
/// The retained value expressions must be exactly equal to the page aliases;
/// a parallel or substituted range table is rejected before matrix assembly.
pub fn bind_paged_spend_block_reusing_ranges(
    b: &mut FieldR1csBuilder,
    pages: &[PagedSpendPageTraceInput; PAGED_SPEND_PAGE_CAPACITY],
    ranges: &[PagedSpendPageProvenRanges],
) -> PagedSpendBlockTrace<PAGED_SPEND_AUTH_CAPACITY> {
    assert_eq!(
        ranges.len(),
        PAGED_SPEND_PAGE_CAPACITY,
        "one proven range bundle per physical page"
    );
    bind_paged_spend_block_inner::<PAGED_SPEND_AUTH_CAPACITY>(b, pages, Some(ranges))
}

fn bind_paged_spend_block_inner<const AUTH_CAPACITY: usize>(
    b: &mut FieldR1csBuilder,
    pages: &[PagedSpendPageTraceInput; PAGED_SPEND_PAGE_CAPACITY],
    proven_ranges: Option<&[PagedSpendPageProvenRanges]>,
) -> PagedSpendBlockTrace<AUTH_CAPACITY> {
    assert_eq!(
        AUTH_CAPACITY, PAGED_SPEND_AUTH_CAPACITY,
        "PagedSpend scanner is fixed at P128/A128"
    );

    let zero_count: [LinExpr; COUNT_BITS] = std::array::from_fn(|_| LinExpr::zero());
    let zero_money: [LinExpr; MONEY_BITS] = std::array::from_fn(|_| LinExpr::zero());

    // Block-global state.
    let mut previous_page_live = one();
    let mut active = LinExpr::zero();
    let mut remaining_pages = zero_count.clone();
    let mut rolling_hash_state: [LinExpr; 4] = std::array::from_fn(|_| LinExpr::zero());

    let mut owner_carry: [LinExpr; 2] = std::array::from_fn(|_| LinExpr::zero());
    let mut epoch_carry: [LinExpr; 2] = std::array::from_fn(|_| LinExpr::zero());
    let mut fee_carry = LinExpr::zero();
    let mut declared_count_carry = LinExpr::zero();
    let mut input_gap_carry = LinExpr::zero();
    let mut output_gap_carry = LinExpr::zero();
    let mut group_input_count = zero_count.clone();
    let mut group_output_count = zero_count.clone();
    let mut group_input_sum = zero_money.clone();
    let mut group_output_plus_fee = zero_money.clone();

    let mut block_page_count = zero_count.clone();
    let mut block_logical_count = zero_count.clone();
    let mut block_input_count = zero_count.clone();
    let mut block_output_count = zero_count.clone();

    // A one-hot logical cursor gives stable END compaction without a sort
    // network.  Once slot A-1 is consumed the vector becomes all-zero; the
    // coverage pin below rejects any subsequent END.
    let mut auth_cursor: [LinExpr; AUTH_CAPACITY] =
        std::array::from_fn(|index| if index == 0 { one() } else { LinExpr::zero() });
    let mut auth_live: [LinExpr; AUTH_CAPACITY] = std::array::from_fn(|_| LinExpr::zero());
    let mut auth_txid: [[LinExpr; 2]; AUTH_CAPACITY] =
        std::array::from_fn(|_| std::array::from_fn(|_| LinExpr::zero()));
    let mut auth_owner: [[LinExpr; 2]; AUTH_CAPACITY] =
        std::array::from_fn(|_| std::array::from_fn(|_| LinExpr::zero()));

    let [paged_iv_0, paged_iv_1] = capacity_iv(TAG_PAGEDTX);
    let mut end_rows = Vec::with_capacity(PAGED_SPEND_PAGE_CAPACITY);

    for (page_index, page) in pages.iter().enumerate() {
        let proven = proven_ranges.map(|ranges| &ranges[page_index]);
        let page_live = page.page_live.clone();
        let start = page.start.clone();
        let end = page.end.clone();
        pin_boolean(b, &page_live);
        pin_boolean(b, &start);
        pin_boolean(b, &end);

        // Fixed physical occupancy is a prefix.  An active group may not
        // disappear into padding without an END.
        pin_gated_zero(b, &previous_page_live.add_const(F128::ONE), &page_live);
        pin_gated_zero(b, &active, &page_live.add_const(F128::ONE));
        previous_page_live = page_live.clone();

        // Every live page starts exactly when no group was active.  END may
        // coincide with START (the canonical one-page transaction).
        let expected_start = mul(b, &page_live, &active.add_const(F128::ONE));
        pin_eq(b, &start, &expected_start);
        pin_gated_zero(b, &end, &page_live.add_const(F128::ONE));
        let active_after = mul(b, &page_live, &end.add_const(F128::ONE));

        // START's u16 page count is canonical, nonzero, and at most 128.
        let declared_wires = range_check_bits(b, &page.declared_page_count, COUNT_BITS);
        let declared_bits: [LinExpr; COUNT_BITS] =
            std::array::from_fn(|index| LinExpr::from_wire(declared_wires[index]));
        pin_gated_zero(b, &start.add_const(F128::ONE), &page.declared_page_count);
        for bit in &declared_bits[8..] {
            pin_zero(b, bit);
        }
        for bit in &declared_bits[..7] {
            pin_gated_zero(b, &declared_bits[7], bit);
        }

        let countdown_before: [LinExpr; COUNT_BITS] = std::array::from_fn(|index| {
            mux(b, &start, &declared_bits[index], &remaining_pages[index])
        });
        let (countdown_after, countdown_underflow) = subtract_one(b, &countdown_before);
        pin_gated_zero(b, &page_live, &countdown_underflow);
        let countdown_is_zero = bits_are_zero(b, &countdown_after);
        let expected_end = mul(b, &page_live, &countdown_is_zero);
        pin_eq(b, &end, &expected_end);
        remaining_pages = gate_array(b, &active_after, &countdown_after);

        // Same-owner / same-epoch group aliases.  Muxing at START makes the
        // first page the canonical value; all continuations are pinned to it.
        let group_owner: [LinExpr; 2] =
            std::array::from_fn(|lane| mux(b, &start, &page.input_owner[lane], &owner_carry[lane]));
        let group_epoch: [LinExpr; 2] = std::array::from_fn(|lane| {
            mux(b, &start, &page.epoch_anchor[lane], &epoch_carry[lane])
        });
        for lane in 0..2 {
            pin_gated_zero(
                b,
                &page_live,
                &page.input_owner[lane].add(&group_owner[lane]),
            );
            pin_gated_zero(
                b,
                &page_live,
                &page.epoch_anchor[lane].add(&group_epoch[lane]),
            );
        }

        let fee_wires = match proven {
            Some(ranges) => {
                assert_eq!(ranges.fee.value, page.fee, "substituted fee range");
                ranges.fee.bits.to_vec()
            }
            None => range_check_bits(b, &page.fee, U64_BITS),
        };
        pin_gated_zero(b, &start.add_const(F128::ONE), &page.fee);
        let group_fee = mux(b, &start, &page.fee, &fee_carry);
        let group_declared_count = mux(b, &start, &page.declared_page_count, &declared_count_carry);

        // Dense selectors and exact u64 amounts.
        let mut input_gap = input_gap_carry.clone();
        let mut output_gap = output_gap_carry.clone();
        let mut input_amount_bits = Vec::with_capacity(TX_INPUTS);
        let mut output_amount_bits = Vec::with_capacity(TX_OUTPUTS);
        let mut all_action_selectors = Vec::with_capacity(TX_INPUTS + TX_OUTPUTS);

        for (slot, (selector, amount)) in
            page.input_live.iter().zip(&page.input_amounts).enumerate()
        {
            pin_boolean(b, selector);
            pin_gated_zero(b, selector, &page_live.add_const(F128::ONE));
            let amount_bits = match proven {
                Some(ranges) => {
                    assert_eq!(
                        ranges.inputs[slot].value, *amount,
                        "substituted input range"
                    );
                    ranges.inputs[slot].bits.to_vec()
                }
                None => range_check_bits(b, amount, U64_BITS),
            };
            pin_gated_zero(b, &selector.add_const(F128::ONE), amount);
            input_gap = dense_step(b, &input_gap, selector);
            all_action_selectors.push(selector.clone());
            input_amount_bits.push(amount_bits);
        }
        for (slot, (selector, amount)) in page
            .output_live
            .iter()
            .zip(&page.output_amounts)
            .enumerate()
        {
            pin_boolean(b, selector);
            pin_gated_zero(b, selector, &page_live.add_const(F128::ONE));
            let amount_bits = match proven {
                Some(ranges) => {
                    assert_eq!(
                        ranges.outputs[slot].value, *amount,
                        "substituted output range"
                    );
                    ranges.outputs[slot].bits.to_vec()
                }
                None => range_check_bits(b, amount, U64_BITS),
            };
            pin_gated_zero(b, &selector.add_const(F128::ONE), amount);
            output_gap = dense_step(b, &output_gap, selector);
            all_action_selectors.push(selector.clone());
            output_amount_bits.push(amount_bits);
        }

        // Minimal page count: the END page must carry at least one action.
        // Together with density this is exactly max(ceil(ni/8), ceil(no/2),1).
        let no_action = bits_are_zero(b, &all_action_selectors);
        pin_gated_zero(b, &end, &no_action);

        // Group and block u16 counts use the same already-proven selectors.
        block_page_count = increment_bits(b, &block_page_count, &page_live);
        block_logical_count = increment_bits(b, &block_logical_count, &end);
        for selector in &page.input_live {
            group_input_count = increment_bits(b, &group_input_count, selector);
            block_input_count = increment_bits(b, &block_input_count, selector);
        }
        for selector in &page.output_live {
            group_output_count = increment_bits(b, &group_output_count, selector);
            block_output_count = increment_bits(b, &block_output_count, selector);
        }

        // Native requires at least one group input.
        let no_group_input = bits_are_zero(b, &group_input_count);
        pin_gated_zero(b, &end, &no_group_input);

        // Checked integer balance.  Output+fee starts with START's fee and is
        // then accumulated across every page; continuation fees were pinned 0.
        let fee_bits = widen_u64(&fee_wires);
        if U64_BITS < MONEY_BITS {
            debug_assert!(fee_bits[U64_BITS..].iter().all(|bit| bit.is_const()));
        }
        group_output_plus_fee = std::array::from_fn(|index| {
            group_output_plus_fee[index].add(&mul(b, &start, &fee_bits[index]))
        });
        for amount in &input_amount_bits {
            group_input_sum = checked_add_bits(b, &group_input_sum, &widen_u64(amount));
        }
        for amount in &output_amount_bits {
            group_output_plus_fee = checked_add_bits(b, &group_output_plus_fee, &widen_u64(amount));
        }
        let input_sum_value = reconstruct_bits(&group_input_sum);
        let output_plus_fee_value = reconstruct_bits(&group_output_plus_fee);
        pin_gated_zero(b, &end, &input_sum_value.add(&output_plus_fee_value));

        // Exact `PAGEDTX_` sponge.  Header/final candidates are evaluated at
        // every physical page to keep one witness-independent matrix shape;
        // START and END select the candidates algebraically.
        let header_state = poseidon2b_permute(
            b,
            [
                const_block(Block128::from(PAGEDTX_VERSION as u128)),
                page.declared_page_count.clone(),
                const_block(paged_iv_0),
                const_block(paged_iv_1),
            ],
        );
        let absorb_base: [LinExpr; 4] = std::array::from_fn(|lane| {
            mux(b, &start, &header_state[lane], &rolling_hash_state[lane])
        });
        let absorbed_state = poseidon2b_permute(
            b,
            [
                absorb_base[0].add(&page.page_hash[0]),
                absorb_base[1].add(&page.page_hash[1]),
                absorb_base[2].clone(),
                absorb_base[3].clone(),
            ],
        );
        let finalized_state = poseidon2b_permute(
            b,
            [
                absorbed_state[0].add(&const_block(Block128::from(0x80u128))),
                absorbed_state[1].add(&const_block(Block128::from(1u128 << 120))),
                absorbed_state[2].clone(),
                absorbed_state[3].clone(),
            ],
        );
        let logical_txid = [finalized_state[0].clone(), finalized_state[1].clone()];

        let end_row = PagedSpendEndTrace {
            live: end.clone(),
            logical_txid: gate_array(b, &end, &logical_txid),
            input_owner: gate_array(b, &end, &group_owner),
            epoch_anchor: gate_array(b, &end, &group_epoch),
            fee: mul(b, &end, &group_fee),
            page_count: mul(b, &end, &group_declared_count),
            live_input_count: mul(b, &end, &reconstruct_bits(&group_input_count)),
            live_output_count: mul(b, &end, &reconstruct_bits(&group_output_count)),
            balanced_sum: mul(b, &end, &input_sum_value),
        };

        // Stable END -> logical authorization aliases.
        let selections: [LinExpr; AUTH_CAPACITY] =
            std::array::from_fn(|slot| mul(b, &end, &auth_cursor[slot]));
        let coverage = selections
            .iter()
            .fold(LinExpr::zero(), |sum, selected| sum.add(selected));
        pin_eq(b, &end, &coverage);
        for slot in 0..AUTH_CAPACITY {
            auth_live[slot] = auth_live[slot].add(&selections[slot]);
            for lane in 0..2 {
                auth_txid[slot][lane] =
                    auth_txid[slot][lane].add(&mul(b, &selections[slot], &logical_txid[lane]));
                auth_owner[slot][lane] =
                    auth_owner[slot][lane].add(&mul(b, &selections[slot], &group_owner[lane]));
            }
        }
        auth_cursor = std::array::from_fn(|slot| {
            let shifted = if slot == 0 {
                LinExpr::zero()
            } else {
                selections[slot - 1].clone()
            };
            auth_cursor[slot].add(&selections[slot]).add(&shifted)
        });

        // Carry only an unfinished group.  END and capacity padding therefore
        // reset every group-local state before the next START.
        active = active_after.clone();
        rolling_hash_state = gate_array(b, &active_after, &absorbed_state);
        owner_carry = gate_array(b, &active_after, &group_owner);
        epoch_carry = gate_array(b, &active_after, &group_epoch);
        fee_carry = mul(b, &active_after, &group_fee);
        declared_count_carry = mul(b, &active_after, &group_declared_count);
        input_gap_carry = mul(b, &active_after, &input_gap);
        output_gap_carry = mul(b, &active_after, &output_gap);
        group_input_count = gate_array(b, &active_after, &group_input_count);
        group_output_count = gate_array(b, &active_after, &group_output_count);
        group_input_sum = gate_array(b, &active_after, &group_input_sum);
        group_output_plus_fee = gate_array(b, &active_after, &group_output_plus_fee);

        end_rows.push(end_row);
    }

    // No group may cross the fixed block boundary.  The block-wide native
    // PagedSpend input cap is 1020 (strictly less than 1021).
    pin_zero(b, &active);
    let input_count_in_range =
        lt_constant_bits(b, &block_input_count, (MAX_PAGEDSPEND_INPUTS + 1) as u16);
    pin_eq(b, &input_count_in_range, &one());
    let output_count_in_range =
        lt_constant_bits(b, &block_output_count, (MAX_PAGEDSPEND_OUTPUTS + 1) as u16);
    pin_eq(b, &output_count_in_range, &one());

    let logical_auth_aliases = std::array::from_fn(|slot| PagedSpendAuthAliasTrace {
        live: auth_live[slot].clone(),
        logical_txid: auth_txid[slot].clone(),
        input_owner: auth_owner[slot].clone(),
    });

    PagedSpendBlockTrace {
        end_rows: end_rows
            .try_into()
            .unwrap_or_else(|_| unreachable!("fixed 128-page loop")),
        logical_auth_aliases,
        page_count: reconstruct_bits(&block_page_count),
        logical_count: reconstruct_bits(&block_logical_count),
        live_input_count: reconstruct_bits(&block_input_count),
        live_output_count: reconstruct_bits(&block_output_count),
    }
}

#[cfg(test)]
mod tests {
    use noid_ivc_core::field_r1cs::FieldR1cs;
    use noid_poseidon2b::primitives::Address;
    use noid_tx::{output_bitmap_bit, TxBody, TxInput, TxOutput};

    use super::*;
    use crate::circuit_support::{alloc_block, tower_value};
    use crate::paged_spend::{
        hash_paged_spend, validate_paged_spend, validate_paged_spend_stream, TxPage,
        PAGEDSPEND_END_BIT, PAGEDSPEND_START_BIT,
    };

    const INPUT_AMOUNT: u64 = 100_000;

    #[derive(Clone)]
    struct Fixture {
        pages: Vec<TxPage>,
        declared_counts: Vec<u16>,
    }

    impl Fixture {
        fn from_groups(groups: &[Vec<TxPage>]) -> Self {
            let mut pages = Vec::new();
            let mut declared_counts = Vec::new();
            for group in groups {
                validate_paged_spend(group).expect("honest fixture group");
                for (index, page) in group.iter().enumerate() {
                    pages.push(page.clone());
                    declared_counts.push(if index == 0 { group.len() as u16 } else { 0 });
                }
            }
            assert!(pages.len() <= PAGED_SPEND_PAGE_CAPACITY);
            Self {
                pages,
                declared_counts,
            }
        }
    }

    fn owner(seed: u32) -> Address {
        let mut bytes = [0u8; 32];
        bytes[..4].copy_from_slice(&seed.to_le_bytes());
        bytes[4..].fill(0x42);
        Address(bytes)
    }

    fn group(seed: u32, input_count: usize, output_count: usize, fee: u64) -> Vec<TxPage> {
        assert!(input_count > 0);
        assert!(output_count > 0);
        let page_count = 1usize
            .max(input_count.div_ceil(TX_INPUTS))
            .max(output_count.div_ceil(TX_OUTPUTS));
        let output_total = input_count as u64 * INPUT_AMOUNT - fee;
        let group_owner = owner(seed);
        let mut epoch_anchor = [0x91u8; 32];
        epoch_anchor[..4].copy_from_slice(&seed.to_le_bytes());
        let mut pages = Vec::with_capacity(page_count);

        for page_index in 0..page_count {
            let mut inputs = [TxInput::dummy(); TX_INPUTS];
            let mut outputs = [TxOutput::dummy(); TX_OUTPUTS];
            let mut bitmap = 0u16;
            for slot in 0..TX_INPUTS {
                let index = page_index * TX_INPUTS + slot;
                if index < input_count {
                    inputs[slot] = TxInput {
                        slot_index: seed * 2_000 + index as u32 + 1,
                        amount: INPUT_AMOUNT,
                        creation_id: u64::from(seed) * 2_000 + index as u64 + 50,
                    };
                    bitmap |= 1 << slot;
                }
            }
            for slot in 0..TX_OUTPUTS {
                let index = page_index * TX_OUTPUTS + slot;
                if index < output_count {
                    outputs[slot] = TxOutput {
                        slot_index: 1_000_000 + seed * 300 + index as u32,
                        amount: if index + 1 == output_count {
                            output_total - (output_count as u64 - 1)
                        } else {
                            1
                        },
                        owner: owner(seed.wrapping_add(10_000)),
                    };
                    bitmap |= output_bitmap_bit(slot);
                }
            }
            if page_index == 0 {
                bitmap |= PAGEDSPEND_START_BIT;
            }
            if page_index + 1 == page_count {
                bitmap |= PAGEDSPEND_END_BIT;
            }
            pages.push(
                TxPage::new(TxBody {
                    epoch_anchor,
                    fee: if page_index == 0 { fee } else { 0 },
                    input_owner: group_owner,
                    inputs,
                    outputs,
                    validity_bitmap: bitmap,
                    is_coinbase: false,
                })
                .expect("page fixture shape"),
            );
        }
        pages
    }

    fn bytes_as_fields(bytes: &[u8; 32]) -> [Block128; 2] {
        let low = u128::from_le_bytes(bytes[..16].try_into().unwrap());
        let high = u128::from_le_bytes(bytes[16..].try_into().unwrap());
        [Block128::from(low), Block128::from(high)]
    }

    fn alloc_pair(b: &mut FieldR1csBuilder, values: [Block128; 2]) -> [LinExpr; 2] {
        values.map(|value| alloc_block(b, value))
    }

    fn alloc_page(
        b: &mut FieldR1csBuilder,
        page: Option<&TxPage>,
        declared_page_count: u16,
    ) -> PagedSpendPageTraceInput {
        match page {
            Some(page) => PagedSpendPageTraceInput {
                page_live: alloc_block(b, Block128::from(1u128)),
                start: alloc_block(b, Block128::from(page.is_start() as u128)),
                end: alloc_block(b, Block128::from(page.is_end() as u128)),
                declared_page_count: alloc_block(b, Block128::from(declared_page_count as u128)),
                page_hash: alloc_pair(b, page.page_hash().as_fields()),
                input_owner: alloc_pair(b, page.body.input_owner.as_fields()),
                epoch_anchor: alloc_pair(b, bytes_as_fields(&page.body.epoch_anchor)),
                fee: alloc_block(b, Block128::from(page.body.fee as u128)),
                input_live: std::array::from_fn(|slot| {
                    alloc_block(b, Block128::from(page.body.input_is_live(slot) as u128))
                }),
                input_amounts: std::array::from_fn(|slot| {
                    alloc_block(b, Block128::from(page.body.inputs[slot].amount as u128))
                }),
                output_live: std::array::from_fn(|slot| {
                    alloc_block(b, Block128::from(page.body.output_is_live(slot) as u128))
                }),
                output_amounts: std::array::from_fn(|slot| {
                    alloc_block(b, Block128::from(page.body.outputs[slot].amount as u128))
                }),
            },
            None => PagedSpendPageTraceInput {
                page_live: alloc_block(b, Block128::from(0u128)),
                start: alloc_block(b, Block128::from(0u128)),
                end: alloc_block(b, Block128::from(0u128)),
                declared_page_count: alloc_block(b, Block128::from(0u128)),
                page_hash: alloc_pair(b, [Block128::from(0u128); 2]),
                input_owner: alloc_pair(b, [Block128::from(0u128); 2]),
                epoch_anchor: alloc_pair(b, [Block128::from(0u128); 2]),
                fee: alloc_block(b, Block128::from(0u128)),
                input_live: std::array::from_fn(|_| alloc_block(b, Block128::from(0u128))),
                input_amounts: std::array::from_fn(|_| alloc_block(b, Block128::from(0u128))),
                output_live: std::array::from_fn(|_| alloc_block(b, Block128::from(0u128))),
                output_amounts: std::array::from_fn(|_| alloc_block(b, Block128::from(0u128))),
            },
        }
    }

    fn bind_fixture(
        b: &mut FieldR1csBuilder,
        fixture: &Fixture,
    ) -> PagedSpendBlockTrace<PAGED_SPEND_AUTH_CAPACITY> {
        assert_eq!(fixture.pages.len(), fixture.declared_counts.len());
        let pages: [PagedSpendPageTraceInput; PAGED_SPEND_PAGE_CAPACITY] =
            std::array::from_fn(|index| {
                alloc_page(
                    b,
                    fixture.pages.get(index),
                    fixture.declared_counts.get(index).copied().unwrap_or(0),
                )
            });
        bind_paged_spend_block(b, &pages)
    }

    fn witness_only(fixture: &Fixture) -> (usize, Vec<F128>) {
        let mut b = FieldR1csBuilder::new_witness_only();
        let _ = bind_fixture(&mut b, fixture);
        b.build_witness_only()
    }

    fn assert_rejects(matrix: &FieldR1cs, fixture: &Fixture, label: &str) {
        let (rows, witness) = witness_only(fixture);
        assert_eq!(rows, matrix.useful_rows, "{label}: trace shape drifted");
        assert!(!matrix.satisfies(&witness), "accepted {label}");
    }

    fn assert_expr_u128(b: &FieldR1csBuilder, expression: &LinExpr, expected: u128, label: &str) {
        assert_eq!(
            tower_value(b, expression),
            Block128::from(expected),
            "{label}"
        );
    }

    fn row_ledger() -> (usize, usize, usize) {
        let mut b = FieldR1csBuilder::new();
        let before_inputs = b.num_wires();
        let pages: [PagedSpendPageTraceInput; PAGED_SPEND_PAGE_CAPACITY] =
            std::array::from_fn(|_| alloc_page(&mut b, None, 0));
        let input_alias_rows = b.num_wires() - before_inputs;
        let before_binder = b.num_wires();
        let _ = bind_paged_spend_block(&mut b, &pages);
        let binder_rows = b.num_wires() - before_binder;
        (input_alias_rows, binder_rows, b.num_wires())
    }

    #[test]
    fn p128_scanner_row_ledger() {
        let a128 = row_ledger();
        eprintln!("P128/A128 row ledger: {a128:?}");
        assert_eq!(
            a128,
            (
                PAGED_SPEND_PAGE_ALIAS_ROWS,
                PAGED_SPEND_A128_SCANNER_ROWS,
                PAGED_SPEND_A128_REFERENCE_USEFUL_ROWS,
            )
        );
        assert_eq!(PAGED_SPEND_PAGE_ALIAS_ROWS, PAGED_SPEND_PAGE_CAPACITY * 31);
    }

    #[test]
    fn p128_scanner_reuses_exact_same_builder_u64_ranges() {
        let mut builder = FieldR1csBuilder::new();
        let before_inputs = builder.num_wires();
        let pages: [PagedSpendPageTraceInput; PAGED_SPEND_PAGE_CAPACITY] =
            std::array::from_fn(|_| alloc_page(&mut builder, None, 0));
        let input_alias_rows = builder.num_wires() - before_inputs;

        let before_ranges = builder.num_wires();
        let ranges = (0..PAGED_SPEND_PAGE_CAPACITY)
            .map(|page| PagedSpendPageProvenRanges::prove(&mut builder, &pages[page]))
            .collect::<Vec<_>>();
        let range_rows = builder.num_wires() - before_ranges;

        let before_scanner = builder.num_wires();
        let _ = bind_paged_spend_block_reusing_ranges(&mut builder, &pages, &ranges);
        let scanner_rows = builder.num_wires() - before_scanner;

        assert_eq!(input_alias_rows, PAGED_SPEND_PAGE_ALIAS_ROWS);
        assert_eq!(range_rows, PAGED_SPEND_A128_REUSABLE_RANGE_ROWS);
        assert_eq!(scanner_rows, PAGED_SPEND_A128_REUSED_SCANNER_ROWS);
        assert_eq!(builder.num_wires(), PAGED_SPEND_A128_REFERENCE_USEFUL_ROWS);
    }

    #[test]
    fn p128_a128_honest_boundaries_and_negative_semantics() {
        // The 100-input / 13-page target and the 1020-input / 128-page
        // physical maximum share one fixed P128/A128 matrix.
        {
            let hundred_group = group(1, 100, 1, 15_700);
            let hundred = Fixture::from_groups(std::slice::from_ref(&hundred_group));
            assert_eq!(hundred.pages.len(), 13);
            validate_paged_spend_stream(&hundred.pages).expect("100/13 native fixture");

            let mut builder = FieldR1csBuilder::new();
            let trace = bind_fixture(&mut builder, &hundred);
            let expected_hash = hash_paged_spend(&hundred_group).unwrap().as_fields();
            for lane in 0..2 {
                assert_eq!(
                    tower_value(&builder, &trace.logical_auth_aliases[0].logical_txid[lane]),
                    expected_hash[lane],
                    "exact PAGEDTX_ lane {lane}",
                );
                assert_eq!(
                    tower_value(&builder, &trace.logical_auth_aliases[0].input_owner[lane]),
                    hundred_group[0].body.input_owner.as_fields()[lane],
                    "canonical owner lane {lane}",
                );
            }
            assert_expr_u128(&builder, &trace.page_count, 13, "block page count");
            assert_expr_u128(&builder, &trace.logical_count, 1, "logical count");
            assert_expr_u128(&builder, &trace.live_input_count, 100, "input count");
            assert_expr_u128(&builder, &trace.live_output_count, 1, "output count");
            assert_expr_u128(
                &builder,
                &trace.end_rows[12].page_count,
                13,
                "END page count",
            );
            assert_expr_u128(
                &builder,
                &trace.end_rows[12].balanced_sum,
                100 * INPUT_AMOUNT as u128,
                "checked balance",
            );
            assert_expr_u128(
                &builder,
                &trace.logical_auth_aliases[1].live,
                0,
                "auth padding",
            );

            let useful_rows = builder.num_wires();
            let (matrix, witness) = builder.build();
            assert_eq!(matrix.useful_rows, useful_rows);
            assert!(matrix.satisfies(&witness), "honest 100/13 P128/A128");

            let maximum_group = group(2, 1_020, 1, 5_000);
            let maximum = Fixture::from_groups(std::slice::from_ref(&maximum_group));
            assert_eq!(maximum.pages.len(), 128);
            validate_paged_spend_stream(&maximum.pages).expect("1020/128 native fixture");
            let mut maximum_builder = FieldR1csBuilder::new_witness_only();
            let maximum_trace = bind_fixture(&mut maximum_builder, &maximum);
            let maximum_hash = hash_paged_spend(&maximum_group).unwrap().as_fields();
            for (lane, expected) in maximum_hash.iter().enumerate() {
                assert_eq!(
                    tower_value(
                        &maximum_builder,
                        &maximum_trace.logical_auth_aliases[0].logical_txid[lane],
                    ),
                    *expected,
                    "128-page PAGEDTX_ lane {lane}",
                );
            }
            let (rows, maximum_witness) = maximum_builder.build_witness_only();
            assert_eq!(rows, matrix.useful_rows, "P128/A128 must be value-fixed");
            assert!(
                matrix.satisfies(&maximum_witness),
                "honest 1020/128 P128/A128"
            );

            // Boundary, continuity, density, fee, owner/epoch, balance and
            // block-cap failures are algebraic rejections of the same matrix.
            let mut bad_count = hundred.clone();
            bad_count.declared_counts[0] = 12;
            assert_rejects(&matrix, &bad_count, "wrong START page count");

            let mut zero_count = hundred.clone();
            zero_count.declared_counts[0] = 0;
            assert_rejects(&matrix, &zero_count, "zero START page count");

            let mut late_end = hundred.clone();
            late_end.declared_counts[0] = 14;
            assert_rejects(&matrix, &late_end, "late END countdown");

            let mut early_end = hundred.clone();
            early_end.pages[0].body.validity_bitmap |= PAGEDSPEND_END_BIT;
            assert_rejects(&matrix, &early_end, "early END marker");

            let mut missing_start = hundred.clone();
            missing_start.pages[0].body.validity_bitmap &= !PAGEDSPEND_START_BIT;
            assert_rejects(&matrix, &missing_start, "missing START");

            let mut continuation_fee = hundred.clone();
            continuation_fee.pages[1].body.fee = 1;
            assert_rejects(&matrix, &continuation_fee, "continuation fee");

            let mut wrong_owner = hundred.clone();
            wrong_owner.pages[1].body.input_owner = owner(999);
            assert_rejects(&matrix, &wrong_owner, "owner mismatch");

            let mut wrong_epoch = hundred.clone();
            wrong_epoch.pages[1].body.epoch_anchor[0] ^= 1;
            assert_rejects(&matrix, &wrong_epoch, "epoch mismatch");

            let mut sparse = hundred.clone();
            sparse.pages[0].body.validity_bitmap &= !(1 << 7);
            sparse.pages[0].body.inputs[7] = TxInput::dummy();
            assert_rejects(&matrix, &sparse, "cross-page sparse input");

            let mut unbalanced = hundred.clone();
            unbalanced.pages[0].body.outputs[0].amount += 1;
            assert_rejects(&matrix, &unbalanced, "u128 balance mismatch");

            let mut over_input_cap = maximum.clone();
            let last = over_input_cap.pages.last_mut().unwrap();
            last.body.inputs[4] = TxInput {
                slot_index: 999_999,
                amount: INPUT_AMOUNT,
                creation_id: 999_999,
            };
            last.body.validity_bitmap |= 1 << 4;
            over_input_cap.pages[0].body.outputs[0].amount += INPUT_AMOUNT;
            assert_rejects(&matrix, &over_input_cap, "1021st block input");

            let mut partial_final_group = hundred.clone();
            partial_final_group.pages.truncate(12);
            partial_final_group.declared_counts.truncate(12);
            assert_rejects(&matrix, &partial_final_group, "partial final group");
        }

        // Strategic class: all 128 physical pages may independently END and
        // map one-for-one into A128 authorization aliases.
        {
            let groups = (0..128)
                .map(|index| group(20_000 + index, 1, 1, 7))
                .collect::<Vec<_>>();
            let all_one_page = Fixture::from_groups(&groups);
            validate_paged_spend_stream(&all_one_page.pages).expect("128 one-page native stream");

            let mut builder = FieldR1csBuilder::new();
            let trace = bind_fixture(&mut builder, &all_one_page);
            assert_expr_u128(&builder, &trace.page_count, 128, "A128 page count");
            assert_expr_u128(&builder, &trace.logical_count, 128, "A128 logical count");
            for slot in [0usize, 63, 127] {
                assert_expr_u128(
                    &builder,
                    &trace.logical_auth_aliases[slot].live,
                    1,
                    "A128 auth live",
                );
                let expected = hash_paged_spend(&groups[slot]).unwrap().as_fields();
                for lane in 0..2 {
                    assert_eq!(
                        tower_value(
                            &builder,
                            &trace.logical_auth_aliases[slot].logical_txid[lane],
                        ),
                        expected[lane],
                        "A128 auth {slot} hash lane {lane}",
                    );
                }
            }
            let useful_rows = builder.num_wires();
            let (matrix, witness) = builder.build();
            assert!(matrix.satisfies(&witness), "honest 128 one-page P128/A128");

            let single = Fixture::from_groups(std::slice::from_ref(&groups[0]));
            let (single_rows, single_witness) = witness_only(&single);
            assert_eq!(single_rows, useful_rows, "P128/A128 content-fixed rows");
            assert!(
                matrix.satisfies(&single_witness),
                "honest one-page P128/A128"
            );
        }
    }
}
