// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Checked fee, burn, and coinbase arithmetic for logical PagedSpend groups.
//!
//! The relation consumes the fixed 128 page-indexed END rows emitted by the
//! logical scanner. A live END pays one base fee for its complete logical
//! transaction, irrespective of its physical page count. Counts and the paid
//! fee are scanner-authenticated aliases; pressure and emission reuse the
//! existing production depth selector. No alternate fee path or transaction
//! format is introduced into production by this research module.

use noid_chain::consensus::fees::{PRESSURE_EXTREME_BPS, PRESSURE_HIGH_BPS, PRESSURE_LOW_BPS};
use noid_chain::consensus::params::{
    BASE_REWARD_MICRONOID, FEE_PER_INPUT, FEE_PER_OUTPUT, MIN_FEE_BASE, STATE_GROWTH_FEE_BASE,
};
use noid_core::{hardware::flat_to_tower_u128, Block128};
use noid_recursive::acceptance::trace::exact_state::{
    StateDepthTrace, MAX_EXACT_STATE_DEPTH, MIN_EXACT_STATE_DEPTH,
};

use crate::circuit_support::{
    alloc_block, flat_const, mul, pin_eq, pin_zero, range_check_bits, FieldR1csBuilder, LinExpr,
    Wire, F128,
};
use crate::geometry::{INPUT_CAPACITY, OUTPUT_CAPACITY};
use crate::paged_spend_relation::{PagedSpendEndTrace, PAGED_SPEND_PAGE_CAPACITY};

const U64_BITS: usize = 64;
const MONEY_SUM_BITS: usize = 72;
const COUNT_BITS: usize = 16;
const MINIMUM_FEE_BITS: usize = 24;
const MAX_MINIMUM_FEE: u128 = MIN_FEE_BASE as u128
    + FEE_PER_INPUT as u128 * INPUT_CAPACITY as u128
    + FEE_PER_OUTPUT as u128 * OUTPUT_CAPACITY as u128
    + STATE_GROWTH_FEE_BASE as u128 * 8 * OUTPUT_CAPACITY as u128;
const MAX_BLOCK_COINBASE_CEILING: u128 = crate::geometry::AUTHORIZATION_CAPACITY as u128
    * u64::MAX as u128
    + BASE_REWARD_MICRONOID as u128;

const _: () = assert!(INPUT_CAPACITY < (1usize << COUNT_BITS));
const _: () = assert!(OUTPUT_CAPACITY < (1usize << COUNT_BITS));
const _: () = assert!(MAX_MINIMUM_FEE < (1u128 << MINIMUM_FEE_BITS));
const _: () = assert!(MAX_BLOCK_COINBASE_CEILING < (1u128 << MONEY_SUM_BITS));

/// Exact fixed-shape delta after END aliases, depth selectors, parent active
/// count, coinbase amount, and the coinbase u64 range already exist.
pub const P128_GROUP_FEE_ROWS: usize = 144_195;

/// Proven fee facts for one page-indexed logical END row.
pub struct LogicalGroupFeeTrace {
    pub end_live: LinExpr,
    pub live_input_count: LinExpr,
    pub live_output_count: LinExpr,
    pub paid_fee: LinExpr,
    pub minimum_fee: LinExpr,
    pub burned_fee: LinExpr,
    pub claimable_fee: LinExpr,
    pub claimable_bits: [Wire; U64_BITS],
}

/// Fixed-P128 block fee/reward result.
pub struct P128BlockFeeTrace {
    pub pressure_multiplier: LinExpr,
    pub groups: Vec<LogicalGroupFeeTrace>,
    pub claimable_fee_sum: LinExpr,
    pub block_reward: LinExpr,
    pub max_coinbase_value: LinExpr,
}

fn tower_value(builder: &FieldR1csBuilder, expression: &LinExpr) -> u128 {
    let flat = expression.eval(builder.values());
    flat_to_tower_u128((flat.lo as u128) | ((flat.hi as u128) << 64))
}

fn reconstruct_bits(bits: &[LinExpr]) -> LinExpr {
    assert!(bits.len() <= 128);
    bits.iter()
        .enumerate()
        .fold(LinExpr::zero(), |sum, (bit, value)| {
            sum.add(&value.scale(flat_const(1u128 << bit)))
        })
}

/// Checked ordinary-integer addition over already-boolean tower bits.
fn checked_add_bits(
    builder: &mut FieldR1csBuilder,
    left: &[LinExpr],
    right: &[LinExpr],
) -> Vec<LinExpr> {
    assert_eq!(left.len(), right.len());
    let mut carry = LinExpr::zero();
    let mut sum = Vec::with_capacity(left.len());
    for (a, b) in left.iter().zip(right) {
        sum.push(a.add(b).add(&carry));
        let a_b = mul(builder, a, b);
        let carry_axb = mul(builder, &carry, &a.add(b));
        carry = a_b.add(&carry_axb);
    }
    pin_zero(builder, &carry);
    sum
}

/// Final borrow of `left - right`, i.e. the unsigned predicate `left < right`.
fn less_than_bits(builder: &mut FieldR1csBuilder, left: &[LinExpr], right: &[LinExpr]) -> LinExpr {
    assert_eq!(left.len(), right.len());
    let mut borrow = LinExpr::zero();
    for (a, b) in left.iter().zip(right) {
        let not_a_b = mul(builder, &a.add_const(F128::ONE), b);
        let borrow_equal = mul(builder, &borrow, &a.add(b).add_const(F128::ONE));
        borrow = not_a_b.add(&borrow_equal);
    }
    borrow
}

fn selected_constant_bits(selectors: &[LinExpr], constants: &[u64], width: usize) -> Vec<LinExpr> {
    assert_eq!(selectors.len(), constants.len());
    (0..width)
        .map(|bit| {
            selectors
                .iter()
                .zip(constants)
                .filter(|(_, constant)| bit < u64::BITS as usize && (**constant >> bit) & 1 == 1)
                .fold(LinExpr::zero(), |sum, (selector, _)| sum.add(selector))
        })
        .collect()
}

/// Smallest active count whose floor-basis-point occupancy reaches a boundary.
fn occupancy_threshold(depth: usize, threshold_bps: u64) -> u64 {
    let capacity = 1u128 << depth;
    (capacity * u128::from(threshold_bps)).div_ceil(10_000) as u64
}

fn depth_selected_threshold_bits(depth: &StateDepthTrace, threshold_bps: u64) -> Vec<LinExpr> {
    let constants = (MIN_EXACT_STATE_DEPTH..=MAX_EXACT_STATE_DEPTH)
        .map(|candidate| occupancy_threshold(candidate, threshold_bps))
        .collect::<Vec<_>>();
    selected_constant_bits(&depth.one_hot, &constants, U64_BITS)
}

fn bind_pressure(
    builder: &mut FieldR1csBuilder,
    parent_active_count: &LinExpr,
    parent_depth: &StateDepthTrace,
) -> (LinExpr, [LinExpr; 4]) {
    let active_bits = range_check_bits(builder, parent_active_count, U64_BITS)
        .into_iter()
        .map(LinExpr::from_wire)
        .collect::<Vec<_>>();
    let low = depth_selected_threshold_bits(parent_depth, PRESSURE_LOW_BPS);
    let high = depth_selected_threshold_bits(parent_depth, PRESSURE_HIGH_BPS);
    let extreme = depth_selected_threshold_bits(parent_depth, PRESSURE_EXTREME_BPS);

    let below_low = less_than_bits(builder, &active_bits, &low);
    let below_high = less_than_bits(builder, &active_bits, &high);
    let below_extreme = less_than_bits(builder, &active_bits, &extreme);
    let regions = [
        below_low.clone(),
        below_low.add(&below_high),
        below_high.add(&below_extreme),
        below_extreme.add_const(F128::ONE),
    ];
    let derived = reconstruct_bits(&selected_constant_bits(&regions, &[1, 2, 4, 8], 4));

    let native_active = tower_value(builder, parent_active_count) as u64;
    let native_depth = tower_value(builder, &parent_depth.value) as u32;
    let native = noid_chain::consensus::fees::pressure_multiplier(native_active, native_depth);
    let pressure = alloc_block(builder, Block128::from(native as u128));
    pin_eq(builder, &pressure, &derived);
    (pressure, regions)
}

#[inline]
fn pin_boolean(builder: &mut FieldR1csBuilder, value: &LinExpr) {
    let relation = mul(builder, value, &value.add_const(F128::ONE));
    pin_zero(builder, &relation);
}

#[inline]
fn pin_gated_zero(builder: &mut FieldR1csBuilder, gate: &LinExpr, value: &LinExpr) {
    let relation = mul(builder, gate, value);
    pin_zero(builder, &relation);
}

fn constant_bits(value: usize, width: usize) -> Vec<LinExpr> {
    assert!(width <= usize::BITS as usize);
    (0..width)
        .map(|bit| {
            if (value >> bit) & 1 == 1 {
                LinExpr::constant(F128::ONE)
            } else {
                LinExpr::zero()
            }
        })
        .collect()
}

fn bits_are_zero(builder: &mut FieldR1csBuilder, bits: &[LinExpr]) -> LinExpr {
    assert!(!bits.is_empty());
    bits.iter().fold(LinExpr::constant(F128::ONE), |zero, bit| {
        mul(builder, &zero, &bit.add_const(F128::ONE))
    })
}

fn pin_less_than_public(builder: &mut FieldR1csBuilder, bits: &[LinExpr], exclusive_bound: usize) {
    let bound = constant_bits(exclusive_bound, bits.len());
    let is_below = less_than_bits(builder, bits, &bound);
    pin_eq(builder, &is_below, &LinExpr::constant(F128::ONE));
}

/// Fixed-width wrapping subtraction plus its exact final borrow.
fn wrapping_sub_bits(
    builder: &mut FieldR1csBuilder,
    left: &[LinExpr],
    right: &[LinExpr],
) -> (Vec<LinExpr>, LinExpr) {
    assert_eq!(left.len(), right.len());
    let mut borrow = LinExpr::zero();
    let mut difference = Vec::with_capacity(left.len());
    for (a, b) in left.iter().zip(right) {
        difference.push(a.add(b).add(&borrow));
        let not_a_b = mul(builder, &a.add_const(F128::ONE), b);
        let borrow_equal = mul(builder, &borrow, &a.add(b).add_const(F128::ONE));
        borrow = not_a_b.add(&borrow_equal);
    }
    (difference, borrow)
}

/// Checked multiplication of an unsigned bit vector by a public integer.
fn checked_scale_bits(
    builder: &mut FieldR1csBuilder,
    bits: &[LinExpr],
    multiplier: u64,
    width: usize,
) -> Vec<LinExpr> {
    assert!(width <= 128);
    let mut terms = Vec::new();
    for shift in 0..u64::BITS as usize {
        if (multiplier >> shift) & 1 == 0 {
            continue;
        }
        let term = (0..width)
            .map(|output_bit| {
                output_bit
                    .checked_sub(shift)
                    .and_then(|input_bit| bits.get(input_bit))
                    .cloned()
                    .unwrap_or_else(LinExpr::zero)
            })
            .collect::<Vec<_>>();
        for bit in bits.iter().skip(width.saturating_sub(shift)) {
            pin_zero(builder, bit);
        }
        terms.push(term);
    }
    let Some((first, rest)) = terms.split_first() else {
        return vec![LinExpr::zero(); width];
    };
    rest.iter().fold(first.clone(), |sum, term| {
        checked_add_bits(builder, &sum, term)
    })
}

/// Select `base * {1,2,4,8}` from the exact pressure intervals.
fn select_pressure_shift(
    builder: &mut FieldR1csBuilder,
    base: &[LinExpr],
    pressure_regions: &[LinExpr; 4],
) -> Vec<LinExpr> {
    let width = base.len();
    for (shift, region) in pressure_regions.iter().enumerate() {
        for bit in base.iter().skip(width.saturating_sub(shift)) {
            pin_gated_zero(builder, region, bit);
        }
    }
    (0..width)
        .map(|output_bit| {
            pressure_regions
                .iter()
                .enumerate()
                .filter_map(|(shift, region)| {
                    output_bit
                        .checked_sub(shift)
                        .map(|input_bit| mul(builder, region, &base[input_bit]))
                })
                .fold(LinExpr::zero(), |selected, bit| selected.add(&bit))
        })
        .collect()
}

fn bind_group_fee(
    builder: &mut FieldR1csBuilder,
    end: &PagedSpendEndTrace,
    pressure_regions: &[LinExpr; 4],
) -> LogicalGroupFeeTrace {
    let end_live = end.live.clone();
    pin_boolean(builder, &end_live);

    let input_bits = range_check_bits(builder, &end.live_input_count, COUNT_BITS)
        .into_iter()
        .map(LinExpr::from_wire)
        .collect::<Vec<_>>();
    let output_bits = range_check_bits(builder, &end.live_output_count, COUNT_BITS)
        .into_iter()
        .map(LinExpr::from_wire)
        .collect::<Vec<_>>();
    let fee_wires = range_check_bits(builder, &end.fee, U64_BITS);
    let fee_bits = fee_wires
        .iter()
        .copied()
        .map(LinExpr::from_wire)
        .collect::<Vec<_>>();

    // Recheck the scanner's logical limits at this monetary boundary.
    pin_less_than_public(builder, &input_bits, INPUT_CAPACITY + 1);
    pin_less_than_public(builder, &output_bits, OUTPUT_CAPACITY + 1);
    let dead = end_live.add_const(F128::ONE);
    pin_gated_zero(builder, &dead, &end.live_input_count);
    pin_gated_zero(builder, &dead, &end.live_output_count);
    pin_gated_zero(builder, &dead, &end.fee);
    let input_is_zero = bits_are_zero(builder, &input_bits);
    pin_gated_zero(builder, &end_live, &input_is_zero);

    let input_fee_bits = checked_scale_bits(builder, &input_bits, FEE_PER_INPUT, MINIMUM_FEE_BITS);
    let output_fee_bits =
        checked_scale_bits(builder, &output_bits, FEE_PER_OUTPUT, MINIMUM_FEE_BITS);

    let (growth_difference, output_below_input) =
        wrapping_sub_bits(builder, &output_bits, &input_bits);
    let no_borrow = output_below_input.add_const(F128::ONE);
    let growth_bits = growth_difference
        .iter()
        .map(|bit| mul(builder, &no_borrow, bit))
        .collect::<Vec<_>>();
    let low_pressure_burn = checked_scale_bits(
        builder,
        &growth_bits,
        STATE_GROWTH_FEE_BASE,
        MINIMUM_FEE_BITS,
    );
    let burn_bits = select_pressure_shift(builder, &low_pressure_burn, pressure_regions);
    let burned_derived = reconstruct_bits(&burn_bits);
    let burned_native = tower_value(builder, &burned_derived);
    let burned_fee = alloc_block(builder, Block128::from(burned_native));
    pin_eq(builder, &burned_fee, &burned_derived);

    let base_bits = (0..MINIMUM_FEE_BITS)
        .map(|bit| {
            if (MIN_FEE_BASE >> bit) & 1 == 1 {
                end_live.clone()
            } else {
                LinExpr::zero()
            }
        })
        .collect::<Vec<_>>();
    let base_and_inputs = checked_add_bits(builder, &base_bits, &input_fee_bits);
    let base_io = checked_add_bits(builder, &base_and_inputs, &output_fee_bits);
    let minimum_bits = checked_add_bits(builder, &base_io, &burn_bits);
    let minimum_derived = reconstruct_bits(&minimum_bits);
    let minimum_native = tower_value(builder, &minimum_derived);
    let minimum_fee = alloc_block(builder, Block128::from(minimum_native));
    pin_eq(builder, &minimum_fee, &minimum_derived);

    let mut minimum_wide = minimum_bits;
    minimum_wide.resize(U64_BITS, LinExpr::zero());
    let fee_below_minimum = less_than_bits(builder, &fee_bits, &minimum_wide);
    pin_zero(builder, &fee_below_minimum);

    let fee_native = tower_value(builder, &end.fee);
    let claimable_native = fee_native.checked_sub(burned_native).unwrap_or(0);
    let claimable_fee = alloc_block(builder, Block128::from(claimable_native));
    let claimable_bits: [Wire; U64_BITS] = range_check_bits(builder, &claimable_fee, U64_BITS)
        .try_into()
        .expect("claimable u64 range has exactly 64 bits");
    let claimable_expr_bits = claimable_bits
        .iter()
        .copied()
        .map(LinExpr::from_wire)
        .collect::<Vec<_>>();
    let mut burn_wide = burn_bits;
    burn_wide.resize(U64_BITS, LinExpr::zero());
    let fee_reconstruction =
        reconstruct_bits(&checked_add_bits(builder, &claimable_expr_bits, &burn_wide));
    pin_eq(builder, &fee_reconstruction, &end.fee);

    LogicalGroupFeeTrace {
        end_live,
        live_input_count: end.live_input_count.clone(),
        live_output_count: end.live_output_count.clone(),
        paid_fee: end.fee.clone(),
        minimum_fee,
        burned_fee,
        claimable_fee,
        claimable_bits,
    }
}

/// Bind fees once per logical group, aggregate miner-claimable fees, and
/// enforce the ordinary emission ceiling against the coinbase amount.
pub fn bind_p128_group_fee_arithmetic(
    builder: &mut FieldR1csBuilder,
    end_rows: &[PagedSpendEndTrace; PAGED_SPEND_PAGE_CAPACITY],
    parent_active_count: &LinExpr,
    parent_depth: &StateDepthTrace,
    child_depth: &StateDepthTrace,
    coinbase_amount: &LinExpr,
    coinbase_amount_bits: &[Wire; U64_BITS],
) -> P128BlockFeeTrace {
    let before = builder.num_wires();
    let (pressure_multiplier, pressure_regions) =
        bind_pressure(builder, parent_active_count, parent_depth);
    let groups = end_rows
        .iter()
        .map(|end| bind_group_fee(builder, end, &pressure_regions))
        .collect::<Vec<_>>();

    let mut aggregate_bits = vec![LinExpr::zero(); MONEY_SUM_BITS];
    if let Some((first, rest)) = groups.split_first() {
        for (destination, bit) in aggregate_bits.iter_mut().zip(&first.claimable_bits) {
            *destination = LinExpr::from_wire(*bit);
        }
        for group in rest {
            let mut term = group
                .claimable_bits
                .iter()
                .copied()
                .map(LinExpr::from_wire)
                .collect::<Vec<_>>();
            term.resize(MONEY_SUM_BITS, LinExpr::zero());
            aggregate_bits = checked_add_bits(builder, &aggregate_bits, &term);
        }
    }
    let aggregate_reconstruction = reconstruct_bits(&aggregate_bits);
    let aggregate_native = tower_value(builder, &aggregate_reconstruction);
    let claimable_fee_sum = alloc_block(builder, Block128::from(aggregate_native));
    pin_eq(builder, &claimable_fee_sum, &aggregate_reconstruction);

    let rewards = (MIN_EXACT_STATE_DEPTH..=MAX_EXACT_STATE_DEPTH)
        .map(|depth| noid_chain::consensus::emission::block_reward(depth as u32))
        .collect::<Vec<_>>();
    let reward_bits = selected_constant_bits(&child_depth.one_hot, &rewards, MONEY_SUM_BITS);
    let block_reward = reconstruct_bits(&reward_bits);
    let max_bits = checked_add_bits(builder, &aggregate_bits, &reward_bits);
    let max_coinbase_value = reconstruct_bits(&max_bits);

    let mut coinbase_bits = coinbase_amount_bits
        .iter()
        .copied()
        .map(LinExpr::from_wire)
        .collect::<Vec<_>>();
    pin_eq(builder, coinbase_amount, &reconstruct_bits(&coinbase_bits));
    coinbase_bits.resize(MONEY_SUM_BITS, LinExpr::zero());
    let overclaim = less_than_bits(builder, &max_bits, &coinbase_bits);
    pin_zero(builder, &overclaim);

    assert_eq!(
        builder.num_wires() - before,
        P128_GROUP_FEE_ROWS,
        "P128 logical-group fee relation row drift"
    );
    P128BlockFeeTrace {
        pressure_multiplier,
        groups,
        claimable_fee_sum,
        block_reward,
        max_coinbase_value,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use noid_ivc_core::field_r1cs::FieldR1cs;

    #[derive(Clone, Copy)]
    struct FeeSpec {
        inputs: u16,
        outputs: u16,
        fee: u64,
    }

    struct BuiltCase {
        matrix: Option<FieldR1cs>,
        witness: Vec<F128>,
        trace: P128BlockFeeTrace,
        coinbase: LinExpr,
        binder_rows: usize,
        useful_rows: usize,
    }

    fn fee_spec(inputs: u16, outputs: u16, active: u64, depth: u32, tip: u64) -> FeeSpec {
        let breakdown = noid_chain::consensus::fees::fee_breakdown(
            u64::from(inputs),
            u64::from(outputs),
            active,
            depth,
        );
        FeeSpec {
            inputs,
            outputs,
            fee: breakdown.required_total.checked_add(tip).unwrap(),
        }
    }

    fn claimable(spec: FeeSpec, active: u64, depth: u32) -> u64 {
        let breakdown = noid_chain::consensus::fees::fee_breakdown(
            u64::from(spec.inputs),
            u64::from(spec.outputs),
            active,
            depth,
        );
        spec.fee.checked_sub(breakdown.burned).unwrap()
    }

    fn maximum_coinbase(
        specs: &[FeeSpec],
        active: u64,
        parent_depth: u32,
        child_depth: u32,
    ) -> u64 {
        let claimable_sum = specs
            .iter()
            .copied()
            .map(|spec| u128::from(claimable(spec, active, parent_depth)))
            .sum::<u128>();
        let maximum =
            u128::from(noid_chain::consensus::emission::block_reward(child_depth)) + claimable_sum;
        u64::try_from(maximum).expect("test coinbase ceiling fits u64")
    }

    fn end_row(
        builder: &mut FieldR1csBuilder,
        index: usize,
        spec: Option<FeeSpec>,
    ) -> PagedSpendEndTrace {
        let spec = spec.unwrap_or(FeeSpec {
            inputs: 0,
            outputs: 0,
            fee: 0,
        });
        let live = u128::from(spec.inputs != 0);
        let selected = |value: u128| if live == 1 { value } else { 0 };
        PagedSpendEndTrace {
            live: alloc_block(builder, Block128::from(live)),
            logical_txid: std::array::from_fn(|lane| {
                alloc_block(
                    builder,
                    Block128::from(selected((2 * index + lane + 1) as u128)),
                )
            }),
            input_owner: std::array::from_fn(|lane| {
                alloc_block(
                    builder,
                    Block128::from(selected((10_000 + 2 * index + lane) as u128)),
                )
            }),
            epoch_anchor: std::array::from_fn(|lane| {
                alloc_block(
                    builder,
                    Block128::from(selected((20_000 + 2 * index + lane) as u128)),
                )
            }),
            fee: alloc_block(builder, Block128::from(spec.fee as u128)),
            page_count: alloc_block(builder, Block128::from(live)),
            live_input_count: alloc_block(builder, Block128::from(spec.inputs as u128)),
            live_output_count: alloc_block(builder, Block128::from(spec.outputs as u128)),
            balanced_sum: alloc_block(builder, Block128::from(live)),
        }
    }

    fn build_case(
        specs: &[FeeSpec],
        parent_active: u64,
        parent_depth: u32,
        child_depth: u32,
        coinbase: u64,
        record_matrix: bool,
    ) -> BuiltCase {
        assert!(specs.len() <= PAGED_SPEND_PAGE_CAPACITY);
        let mut builder = if record_matrix {
            FieldR1csBuilder::new()
        } else {
            FieldR1csBuilder::new_witness_only()
        };
        let parent_active = alloc_block(&mut builder, Block128::from(parent_active as u128));
        let parent_depth_value = alloc_block(&mut builder, Block128::from(parent_depth as u128));
        let child_depth_value = alloc_block(&mut builder, Block128::from(child_depth as u128));
        let parent_depth = StateDepthTrace::bind(&mut builder, &parent_depth_value);
        let child_depth = StateDepthTrace::bind(&mut builder, &child_depth_value);
        let end_rows =
            std::array::from_fn(|index| end_row(&mut builder, index, specs.get(index).copied()));
        let coinbase = alloc_block(&mut builder, Block128::from(coinbase as u128));
        let coinbase_bits: [Wire; U64_BITS] = range_check_bits(&mut builder, &coinbase, U64_BITS)
            .try_into()
            .expect("coinbase u64 range");
        let before = builder.num_wires();
        let trace = bind_p128_group_fee_arithmetic(
            &mut builder,
            &end_rows,
            &parent_active,
            &parent_depth,
            &child_depth,
            &coinbase,
            &coinbase_bits,
        );
        let binder_rows = builder.num_wires() - before;
        if record_matrix {
            let (matrix, witness) = builder.build();
            BuiltCase {
                useful_rows: matrix.useful_rows,
                matrix: Some(matrix),
                witness,
                trace,
                coinbase,
                binder_rows,
            }
        } else {
            let (useful_rows, witness) = builder.build_witness_only();
            BuiltCase {
                matrix: None,
                witness,
                trace,
                coinbase,
                binder_rows,
                useful_rows,
            }
        }
    }

    fn value(witness: &[F128], expression: &LinExpr) -> u128 {
        let flat = expression.eval(witness);
        flat_to_tower_u128((flat.lo as u128) | ((flat.hi as u128) << 64))
    }

    fn sole_wire(expression: &LinExpr) -> usize {
        assert_eq!(expression.terms.len(), 1);
        expression.terms[0].0 as usize
    }

    #[test]
    fn release_group_shapes_match_native_fee_semantics() {
        let active = 0;
        let depth = 24;
        let specs = [
            fee_spec(1, 1, active, depth, 7),
            fee_spec(100, 13, active, depth, 11),
            fee_spec(1_020, 128, active, depth, 13),
        ];
        let maximum = maximum_coinbase(&specs, active, depth, depth);
        let case = build_case(&specs, active, depth, depth, maximum - 1, true);
        let matrix = case.matrix.as_ref().unwrap();
        assert!(matrix.satisfies(&case.witness));
        for (index, spec) in specs.iter().copied().enumerate() {
            let native = noid_chain::consensus::fees::fee_breakdown(
                u64::from(spec.inputs),
                u64::from(spec.outputs),
                active,
                depth,
            );
            assert_eq!(
                value(&case.witness, &case.trace.groups[index].minimum_fee),
                u128::from(native.required_total)
            );
            assert_eq!(
                value(&case.witness, &case.trace.groups[index].burned_fee),
                u128::from(native.burned)
            );
            assert_eq!(
                value(&case.witness, &case.trace.groups[index].claimable_fee),
                u128::from(claimable(spec, active, depth))
            );
        }

        // The 1,020-input sweep still carries exactly one base fee.
        let sweep = noid_chain::consensus::fees::fee_breakdown(1_020, 128, active, depth);
        assert_eq!(sweep.base, MIN_FEE_BASE);
    }

    #[test]
    fn all_128_independent_groups_aggregate_exactly() {
        let active = 0;
        let depth = 24;
        let specs = vec![fee_spec(1, 1, active, depth, 3); 128];
        let maximum = maximum_coinbase(&specs, active, depth, depth);
        let case = build_case(&specs, active, depth, depth, maximum, true);
        let matrix = case.matrix.as_ref().unwrap();
        assert!(matrix.satisfies(&case.witness));
        assert_eq!(
            value(&case.witness, &case.trace.claimable_fee_sum),
            specs
                .iter()
                .copied()
                .map(|spec| u128::from(claimable(spec, active, depth)))
                .sum::<u128>()
        );
        assert_eq!(
            value(&case.witness, &case.trace.max_coinbase_value),
            u128::from(maximum)
        );
    }

    #[test]
    fn exact_pressure_boundaries_match_native_burn() {
        let depth = MIN_EXACT_STATE_DEPTH as u32;
        for (basis_points, before, at) in [
            (PRESSURE_LOW_BPS, 1u64, 2u64),
            (PRESSURE_HIGH_BPS, 2, 4),
            (PRESSURE_EXTREME_BPS, 4, 8),
        ] {
            let threshold = occupancy_threshold(depth as usize, basis_points);
            for (active, expected_pressure) in [(threshold - 1, before), (threshold, at)] {
                let spec = fee_spec(1, 2, active, depth, 0);
                let case = build_case(&[spec], active, depth, depth, 0, true);
                let matrix = case.matrix.as_ref().unwrap();
                assert!(matrix.satisfies(&case.witness));
                let native = noid_chain::consensus::fees::fee_breakdown(1, 2, active, depth);
                assert_eq!(
                    value(&case.witness, &case.trace.pressure_multiplier),
                    u128::from(expected_pressure)
                );
                assert_eq!(
                    value(&case.witness, &case.trace.groups[0].burned_fee),
                    u128::from(native.burned)
                );
            }
        }
    }

    #[test]
    fn malformed_fee_count_dead_row_and_coinbase_reject() {
        let depth = 24;
        let active = occupancy_threshold(depth as usize, PRESSURE_EXTREME_BPS);
        let honest = fee_spec(1, 256, active, depth, 17);
        let maximum = maximum_coinbase(&[honest], active, depth, depth);
        let case = build_case(&[honest], active, depth, depth, maximum, true);
        let matrix = case.matrix.as_ref().unwrap();
        assert!(matrix.satisfies(&case.witness));

        let mut wrong_burn = case.witness.clone();
        wrong_burn[sole_wire(&case.trace.groups[0].burned_fee)] += F128::ONE;
        assert!(!matrix.satisfies(&wrong_burn));

        let mut wrong_count = case.witness.clone();
        wrong_count[sole_wire(&case.trace.groups[0].live_input_count)] += F128::ONE;
        assert!(!matrix.satisfies(&wrong_count));

        let mut nonzero_dead_fee = case.witness.clone();
        nonzero_dead_fee[sole_wire(&case.trace.groups[1].paid_fee)] += F128::ONE;
        assert!(!matrix.satisfies(&nonzero_dead_fee));

        let native = noid_chain::consensus::fees::fee_breakdown(1, 256, active, depth);
        let below_minimum = FeeSpec {
            inputs: 1,
            outputs: 256,
            fee: native.required_total - 1,
        };
        let bad_fee = build_case(&[below_minimum], active, depth, depth, 0, true);
        assert!(!bad_fee.matrix.as_ref().unwrap().satisfies(&bad_fee.witness));

        let over_cap_native = noid_chain::consensus::fees::fee_breakdown(1_021, 1, active, depth);
        let over_cap = FeeSpec {
            inputs: 1_021,
            outputs: 1,
            fee: over_cap_native.required_total,
        };
        let bad_count = build_case(&[over_cap], active, depth, depth, 0, true);
        assert!(!bad_count
            .matrix
            .as_ref()
            .unwrap()
            .satisfies(&bad_count.witness));

        let overclaim = build_case(&[honest], active, depth, depth, maximum + 1, true);
        assert!(!overclaim
            .matrix
            .as_ref()
            .unwrap()
            .satisfies(&overclaim.witness));

        let mut wrong_coinbase = case.witness.clone();
        wrong_coinbase[sole_wire(&case.coinbase)] += F128::ONE;
        assert!(!matrix.satisfies(&wrong_coinbase));
    }

    #[test]
    fn fee_matrix_is_exact_and_content_invariant() {
        let sparse_active = 0;
        let sparse_depth = 24;
        let sparse_specs = [fee_spec(1, 1, sparse_active, sparse_depth, 0)];
        let sparse_max = maximum_coinbase(&sparse_specs, sparse_active, sparse_depth, sparse_depth);
        let sparse = build_case(
            &sparse_specs,
            sparse_active,
            sparse_depth,
            sparse_depth,
            sparse_max,
            true,
        );
        let matrix = sparse.matrix.as_ref().unwrap();
        assert!(matrix.satisfies(&sparse.witness));

        let dense_depth = 32;
        let dense_active = occupancy_threshold(dense_depth as usize, PRESSURE_EXTREME_BPS);
        let dense_specs = vec![fee_spec(1, 2, dense_active, dense_depth, 5); 128];
        let dense_max = maximum_coinbase(&dense_specs, dense_active, dense_depth, dense_depth);
        let dense = build_case(
            &dense_specs,
            dense_active,
            dense_depth,
            dense_depth,
            dense_max,
            false,
        );
        assert_eq!(sparse.binder_rows, P128_GROUP_FEE_ROWS);
        assert_eq!(dense.binder_rows, P128_GROUP_FEE_ROWS);
        assert_eq!(sparse.useful_rows, dense.useful_rows);
        assert!(matrix.satisfies(&dense.witness));
    }
}
