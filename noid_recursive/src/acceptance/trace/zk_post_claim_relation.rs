// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Production-disconnected trace for the owner-capsule post-claim relation.
//!
//! The AuthGKR exposes five ZK-padded operand evaluations and two Libra-mask
//! evaluations.
//! Together with the four public boundary values they are compressed, in the
//! exact native order, by one nonzero `eta`.  The resulting scalar is the bank
//! claim consumed by Phase A.  This module also evaluates the transparent
//! relation MLE at Phase A's terminal point without allocating, committing, or
//! accepting a witness-supplied 2^11-cell relation table.
//!
//! All points use canonical LOW-to-HIGH variable order.  State addresses are
//! `lane[0..2] || round[0..7] || high[0..2]`; mask addresses are
//! `power[0..4] || variable[0..4] || 0 || 0 || 1`.  The formulas below factor
//! those layouts directly.  In particular, only the active rounds `0..=65`
//! enter the shifted/current state functionals.

use noid_core::{Block128, TowerField};
use noid_gkr::zk_auth_capsule::{
    sparse_boundary_claims, AuthCapsuleBoundaryPublic, ZK_AUTH_CAPSULE_BANK_VARS,
    ZK_AUTH_CAPSULE_POST_CLAIMS, ZK_AUTH_CAPSULE_TERMINAL_BLINDING_BOOLEAN_INDEX,
    ZK_AUTH_CAPSULE_TERMINAL_BLINDING_OFFSET, ZK_AUTH_CAPSULE_TERMINAL_OPERAND_CLAIMS,
};
use noid_poseidon2b::native::domain::{capacity_iv, TAG_ADDRFIX};

use super::{eq_ind_partial_eval_trace, flat_of, mul, pin_eq, FieldR1csBuilder, LinExpr, F128};

pub const ZK_POST_CLAIM_VARS: usize = ZK_AUTH_CAPSULE_BANK_VARS;
pub const ZK_POST_CLAIM_OPERAND_CLAIMS: usize = ZK_AUTH_CAPSULE_TERMINAL_OPERAND_CLAIMS;
pub const ZK_POST_CLAIM_TOTAL_CLAIMS: usize = ZK_AUTH_CAPSULE_POST_CLAIMS;

/// One inverse witness, one product, and one equality pin for `eta != 0`.
pub const ZK_POST_CLAIM_ETA_ROWS: usize = 3;
/// Ten Horner products for the eleven ordered scalar claims.
pub const ZK_POST_CLAIM_SCALAR_RLC_ROWS: usize = 10;
/// Five factored, ZK-padded terminal operand functionals at `s`, including
/// the rank-five dummy extension and its in-circuit nonzero coefficient check.
pub const ZK_POST_CLAIM_STATE_RELATION_ROWS: usize = 95;
/// Four sparse boundary functionals at `s`.
pub const ZK_POST_CLAIM_BOUNDARY_RELATION_ROWS: usize = 18;
/// Both Libra-mask functionals, before their shared high-address selector.
pub const ZK_POST_CLAIM_MASK_RELATION_ROWS: usize = 162;
/// Exact eta fold of the eleven relation functionals; the last two share the
/// mask-address selector and therefore cost eleven rather than twelve rows.
pub const ZK_POST_CLAIM_RELATION_RLC_ROWS: usize = 11;
/// Incremental rows after all caller-owned dynamic inputs are allocated.
/// Deliberately excludes transcript replay and Phase A itself.
pub const ZK_POST_CLAIM_RELATION_TRACE_ROWS: usize = ZK_POST_CLAIM_ETA_ROWS
    + ZK_POST_CLAIM_SCALAR_RLC_ROWS
    + ZK_POST_CLAIM_STATE_RELATION_ROWS
    + ZK_POST_CLAIM_BOUNDARY_RELATION_ROWS
    + ZK_POST_CLAIM_MASK_RELATION_ROWS
    + ZK_POST_CLAIM_RELATION_RLC_ROWS;

const LANE_BITS: usize = 2;
const ROUND_BITS: usize = 7;
const ROUND_START: usize = LANE_BITS;
const HIGH_START: usize = LANE_BITS + ROUND_BITS;
const MASK_ACTIVE_VARIABLES: usize = 11;
const MASK_ACTIVE_POWERS: usize = 11;

const _: () = assert!(ZK_POST_CLAIM_VARS == 11);
const _: () = assert!(ZK_POST_CLAIM_OPERAND_CLAIMS == 5);
const _: () = assert!(ZK_POST_CLAIM_TOTAL_CLAIMS == 11);
const _: () = assert!(ZK_AUTH_CAPSULE_TERMINAL_BLINDING_BOOLEAN_INDEX == 2047);
const _: () = assert!(ZK_AUTH_CAPSULE_TERMINAL_BLINDING_OFFSET == 1280);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ZkPostClaimDynamicInput {
    InputPoint,
    AuthTerminalPoint,
    PhaseATerminalPoint,
    Eta,
    TerminalOperandClaim,
    MaskInputClaim,
    MaskFinalClaim,
    ExpectedAddress,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ZkPostClaimRelationTraceError {
    /// A transcript/claim value was embedded in the class matrix rather than
    /// entering through an allocated wire.
    DynamicInputIsConstant {
        input: ZkPostClaimDynamicInput,
        index: usize,
    },
    ZeroEta,
    ZeroTerminalBlindingWeight,
}

#[derive(Clone, Debug)]
pub struct ZkPostClaimRelationTraceInput {
    /// AuthGKR input point `rho`, canonical LOW-to-HIGH.
    pub input_point: [LinExpr; ZK_POST_CLAIM_VARS],
    /// AuthGKR terminal point `r`, canonical LOW-to-HIGH.
    pub auth_terminal_point: [LinExpr; ZK_POST_CLAIM_VARS],
    /// Phase-A terminal point `s`, canonical LOW-to-HIGH.
    pub phase_a_terminal_point: [LinExpr; ZK_POST_CLAIM_VARS],
    /// Post-claim RLC challenge, sampled after all eleven scalar claims.
    pub eta: LinExpr,
    /// `[state_inc, state_lane_0, ..., state_lane_3]`.
    pub terminal_operand_claims: [LinExpr; ZK_POST_CLAIM_OPERAND_CLAIMS],
    pub mask_mle_at_input: LinExpr,
    pub mask_final_at_terminal: LinExpr,
    /// Public output-address lanes.  Capacity-IV lanes are protocol constants.
    pub expected_address: [LinExpr; 2],
}

#[derive(Clone, Debug)]
pub struct ZkPostClaimRelationTraceOutput {
    /// The derived Phase-A bank claim `<B,t>`.
    pub bank_claim: LinExpr,
    /// Alias of `bank_claim`, named after the native relation field.
    pub expected_inner_product: LinExpr,
    /// Transparent `t(s)` at the canonical Phase-A terminal point.
    pub terminal_relation_value: LinExpr,
}

fn check_dynamic(
    expression: &LinExpr,
    input: ZkPostClaimDynamicInput,
    index: usize,
) -> Result<(), ZkPostClaimRelationTraceError> {
    if expression.is_const() {
        Err(ZkPostClaimRelationTraceError::DynamicInputIsConstant { input, index })
    } else {
        Ok(())
    }
}

fn preflight_dynamic_inputs(
    input: &ZkPostClaimRelationTraceInput,
) -> Result<(), ZkPostClaimRelationTraceError> {
    for (index, expression) in input.input_point.iter().enumerate() {
        check_dynamic(expression, ZkPostClaimDynamicInput::InputPoint, index)?;
    }
    for (index, expression) in input.auth_terminal_point.iter().enumerate() {
        check_dynamic(
            expression,
            ZkPostClaimDynamicInput::AuthTerminalPoint,
            index,
        )?;
    }
    for (index, expression) in input.phase_a_terminal_point.iter().enumerate() {
        check_dynamic(
            expression,
            ZkPostClaimDynamicInput::PhaseATerminalPoint,
            index,
        )?;
    }
    check_dynamic(&input.eta, ZkPostClaimDynamicInput::Eta, 0)?;
    for (index, expression) in input.terminal_operand_claims.iter().enumerate() {
        check_dynamic(
            expression,
            ZkPostClaimDynamicInput::TerminalOperandClaim,
            index,
        )?;
    }
    check_dynamic(
        &input.mask_mle_at_input,
        ZkPostClaimDynamicInput::MaskInputClaim,
        0,
    )?;
    check_dynamic(
        &input.mask_final_at_terminal,
        ZkPostClaimDynamicInput::MaskFinalClaim,
        0,
    )?;
    for (index, expression) in input.expected_address.iter().enumerate() {
        check_dynamic(expression, ZkPostClaimDynamicInput::ExpectedAddress, index)?;
    }
    Ok(())
}

fn product(b: &mut FieldR1csBuilder, factors: &[LinExpr]) -> LinExpr {
    assert!(!factors.is_empty());
    let mut result = factors[0].clone();
    for factor in &factors[1..] {
        result = mul(b, &result, factor);
    }
    result
}

fn rlc_horner(b: &mut FieldR1csBuilder, eta: &LinExpr, values: &[LinExpr]) -> LinExpr {
    assert!(!values.is_empty());
    let mut result = values[values.len() - 1].clone();
    for value in values[..values.len() - 1].iter().rev() {
        result = value.add(&mul(b, eta, &result));
    }
    result
}

fn constrain_eta_nonzero(b: &mut FieldR1csBuilder, eta: &LinExpr) {
    constrain_nonzero(b, eta);
}

fn constrain_nonzero(b: &mut FieldR1csBuilder, value: &LinExpr) {
    let inverse = LinExpr::from_wire(b.alloc_f128(value.eval(b.values()).inv()));
    let product = LinExpr::from_wire(b.mul(value, &inverse));
    pin_eq(b, &product, &LinExpr::constant(F128::ONE));
}

/// Extend an existing Boolean equality tensor by higher coordinates.  The
/// input tensor is ordered by natural Boolean index over its existing low
/// variables.
fn extend_boolean_tensor(
    b: &mut FieldR1csBuilder,
    mut tensor: Vec<LinExpr>,
    higher_coordinates: &[LinExpr],
) -> Vec<LinExpr> {
    for coordinate in higher_coordinates {
        let old_len = tensor.len();
        let mut high = Vec::with_capacity(old_len);
        for low in &mut tensor {
            let at_one = mul(b, low, coordinate);
            *low = low.add(&at_one);
            high.push(at_one);
        }
        tensor.extend(high);
    }
    tensor
}

struct RoundCorrelations {
    same_active: LinExpr,
    shifted_active: LinExpr,
}

/// Correlations over the seven round bits:
///
/// - `same_active = sum_{q=0}^{65} eq(q,r) eq(q,s)`;
/// - `shifted_active = sum_{q=0}^{65} eq(q,r) eq(q+1,s)`.
///
/// The addition-by-one recurrence covers `0..63`; two sparse terms cover
/// `64,65`.  No 128- or 2048-cell witness table is materialized.
fn active_round_correlations(
    b: &mut FieldR1csBuilder,
    r: &[LinExpr],
    s: &[LinExpr],
) -> RoundCorrelations {
    assert_eq!(r.len(), ROUND_BITS);
    assert_eq!(s.len(), ROUND_BITS);

    // a_i: 0 -> 1 at bit i; b_i: 1 -> 0 at bit i.
    let a: [LinExpr; ROUND_BITS] =
        std::array::from_fn(|i| mul(b, &r[i].add_const(F128::ONE), &s[i]));
    let carry: [LinExpr; ROUND_BITS] =
        std::array::from_fn(|i| mul(b, &r[i], &s[i].add_const(F128::ONE)));

    // Equality suffix over bits 1..5, shared by the same-round selector and
    // the increment recurrence.
    let eq: [LinExpr; 6] = std::array::from_fn(|i| r[i].add(&s[i]).add_const(F128::ONE));
    let mut eq_suffix: [LinExpr; 6] = std::array::from_fn(|_| LinExpr::zero());
    eq_suffix[5] = eq[5].clone();
    for i in (1..5).rev() {
        eq_suffix[i] = mul(b, &eq[i], &eq_suffix[i + 1]);
    }

    // Both points are zero at a fixed bit.  These suffixes describe the two
    // sparse high-round cases 64 and 65.
    let zero_pair: [LinExpr; 6] = std::array::from_fn(|i| {
        if i == 0 {
            LinExpr::zero()
        } else {
            mul(b, &r[i].add_const(F128::ONE), &s[i].add_const(F128::ONE))
        }
    });
    let mut zero_suffix: [LinExpr; 6] = std::array::from_fn(|_| LinExpr::zero());
    zero_suffix[5] = zero_pair[5].clone();
    for i in (1..5).rev() {
        zero_suffix[i] = mul(b, &zero_pair[i], &zero_suffix[i + 1]);
    }

    // F_n = a_0*Eq(high) + b_0*F_{n-1}(high), excluding the all-one input.
    let mut increment_low_six = a[5].clone();
    for i in (0..5).rev() {
        increment_low_six =
            mul(b, &a[i], &eq_suffix[i + 1]).add(&mul(b, &carry[i], &increment_low_six));
    }

    let high_zero = mul(b, &r[6].add_const(F128::ONE), &s[6].add_const(F128::ONE));
    let low_range = mul(b, &high_zero, &increment_low_six);

    // q=63 carries out of the low six bits into round bit six.
    let low_all_ones_carry = product(b, &carry[..6]);
    let q63 = mul(b, &low_all_ones_carry, &a[6]);

    // q=64 and q=65, with round bit six staying one.
    let q64_low = mul(b, &a[0], &zero_suffix[1]);
    let q65_low = mul(b, &carry[0], &a[1]);
    let q65_low = mul(b, &q65_low, &zero_suffix[2]);
    let high_one = mul(b, &r[6], &s[6]);
    let high_sparse = mul(b, &high_one, &q64_low.add(&q65_low));
    let shifted_active = low_range.add(&q63).add(&high_sparse);

    // Rounds 0..63: high bit zero and all lower bits equal.  Rounds 64,65:
    // high bit one, low bit arbitrary/equal, bits 1..5 fixed zero.
    let lower_equal = mul(b, &eq[0], &eq_suffix[1]);
    let low_block = mul(b, &high_zero, &lower_equal);
    let sparse_high = mul(b, &high_one, &zero_suffix[1]);
    let sparse_high = mul(b, &sparse_high, &eq[0]);
    let same_active = low_block.add(&sparse_high);

    RoundCorrelations {
        same_active,
        shifted_active,
    }
}

struct OperandRelationValues {
    terminal: [LinExpr; ZK_POST_CLAIM_OPERAND_CLAIMS],
    lane_at_s: [LinExpr; 4],
    s_high_zero: LinExpr,
}

fn terminal_operand_relation_values(
    b: &mut FieldR1csBuilder,
    r: &[LinExpr; ZK_POST_CLAIM_VARS],
    s: &[LinExpr; ZK_POST_CLAIM_VARS],
) -> OperandRelationValues {
    let lane_tensor = eq_ind_partial_eval_trace(b, &s[..LANE_BITS]);
    let lane_at_s: [LinExpr; 4] = lane_tensor.try_into().expect("two lane bits");

    let r_high_zero = mul(
        b,
        &r[HIGH_START].add_const(F128::ONE),
        &r[HIGH_START + 1].add_const(F128::ONE),
    );
    let s_high_zero = mul(
        b,
        &s[HIGH_START].add_const(F128::ONE),
        &s[HIGH_START + 1].add_const(F128::ONE),
    );
    let joint_high_zero = mul(b, &r_high_zero, &s_high_zero);

    let round =
        active_round_correlations(b, &r[ROUND_START..HIGH_START], &s[ROUND_START..HIGH_START]);

    let same_common = mul(b, &joint_high_zero, &round.same_active);
    let lane_values: [LinExpr; 4] =
        std::array::from_fn(|lane| mul(b, &same_common, &lane_at_s[lane]));

    let lane_equal = mul(
        b,
        &r[0].add(&s[0]).add_const(F128::ONE),
        &r[1].add(&s[1]).add_const(F128::ONE),
    );
    let increment = mul(b, &joint_high_zero, &lane_equal);
    let increment = mul(b, &increment, &round.shifted_active);

    // ZK dummy extension. Native operand table row 2047 is inactive and
    // reads five distinct bank cells 1280..1284. Its coefficient at AuthGKR's
    // terminal point is eq(r, 2047) = product_j r_j. The five bank-cell basis
    // weights at Phase A's point are eq(s, 1280+i), i=0..4.
    let r_blinding_weight = product(b, r);
    constrain_nonzero(b, &r_blinding_weight);

    // Cells 1280..1284 share address bits
    // [3..=10] = [0,0,0,0,0,1,0,1]. The first four use bit2=0 and the four
    // two-bit lane basis values; the fifth is low bits 100.
    let s_blinding_high_factors = [
        s[3].add_const(F128::ONE),
        s[4].add_const(F128::ONE),
        s[5].add_const(F128::ONE),
        s[6].add_const(F128::ONE),
        s[7].add_const(F128::ONE),
        s[8].clone(),
        s[9].add_const(F128::ONE),
        s[10].clone(),
    ];
    let s_blinding_high = product(b, &s_blinding_high_factors);
    let joint_blinding_high = mul(b, &r_blinding_weight, &s_blinding_high);
    let joint_bit2_zero = mul(b, &joint_blinding_high, &s[2].add_const(F128::ONE));
    let mut blinding_values: [LinExpr; ZK_POST_CLAIM_OPERAND_CLAIMS] =
        std::array::from_fn(|_| LinExpr::zero());
    for lane in 0..4 {
        blinding_values[lane] = mul(b, &joint_bit2_zero, &lane_at_s[lane]);
    }
    let joint_bit2_one = mul(b, &joint_blinding_high, &s[2]);
    blinding_values[4] = mul(b, &joint_bit2_one, &lane_at_s[0]);

    OperandRelationValues {
        terminal: [
            increment.add(&blinding_values[0]),
            lane_values[0].add(&blinding_values[1]),
            lane_values[1].add(&blinding_values[2]),
            lane_values[2].add(&blinding_values[3]),
            lane_values[3].add(&blinding_values[4]),
        ],
        lane_at_s,
        s_high_zero,
    }
}

fn boundary_relation_values(
    b: &mut FieldR1csBuilder,
    s: &[LinExpr; ZK_POST_CLAIM_VARS],
    lane_at_s: &[LinExpr; 4],
    s_high_zero: &LinExpr,
) -> [LinExpr; 4] {
    let coefficient_source = sparse_boundary_claims(AuthCapsuleBoundaryPublic::canonical([
        Block128::ZERO,
        Block128::ZERO,
    ]));

    let round_zero_factors: Vec<LinExpr> = (ROUND_START..HIGH_START)
        .map(|coordinate| s[coordinate].add_const(F128::ONE))
        .collect();
    let round_zero = product(b, &round_zero_factors);
    let row_zero = mul(b, &round_zero, s_high_zero);

    let initial_lane_eval = |claim_index: usize| {
        coefficient_source[claim_index]
            .terms
            .iter()
            .fold(LinExpr::zero(), |acc, term| {
                let lane = term.bank_index & 3;
                acc.add(&lane_at_s[lane].scale(flat_of(term.coefficient)))
            })
    };
    let initial_2 = mul(b, &row_zero, &initial_lane_eval(0));
    let initial_3 = mul(b, &row_zero, &initial_lane_eval(1));

    // Round 66 = binary 1000010 in LOW-to-HIGH round-bit order.
    let round_66_factors: Vec<LinExpr> = (0..ROUND_BITS)
        .map(|bit| {
            if bit == 1 || bit == 6 {
                s[ROUND_START + bit].clone()
            } else {
                s[ROUND_START + bit].add_const(F128::ONE)
            }
        })
        .collect();
    let round_66 = product(b, &round_66_factors);
    let row_66 = mul(b, &round_66, s_high_zero);
    let output_0 = mul(b, &row_66, &lane_at_s[0]);
    let output_1 = mul(b, &row_66, &lane_at_s[1]);

    [initial_2, initial_3, output_0, output_1]
}

struct MaskRelationValues {
    input_without_high: LinExpr,
    final_without_high: LinExpr,
    high_selector: LinExpr,
}

fn mask_relation_values(
    b: &mut FieldR1csBuilder,
    rho: &[LinExpr; ZK_POST_CLAIM_VARS],
    r: &[LinExpr; ZK_POST_CLAIM_VARS],
    s: &[LinExpr; ZK_POST_CLAIM_VARS],
    lane_at_s: &[LinExpr; 4],
) -> MaskRelationValues {
    // Mask power occupies address bits 0..3.  Reuse the already-built tensor
    // for bits 0..1 and extend it through bits 2..3.
    let power_tensor = extend_boolean_tensor(b, lane_at_s.to_vec(), &s[2..4]);
    let variable_tensor = eq_ind_partial_eval_trace(b, &s[4..8]);

    // All active mask cells have address bits 8,9,10 = 0,0,1.
    let mask_high = mul(b, &s[10], &s[9].add_const(F128::ONE));
    let high_selector = mul(b, &mask_high, &s[8].add_const(F128::ONE));

    let active_variable_weight = variable_tensor[..MASK_ACTIVE_VARIABLES]
        .iter()
        .fold(LinExpr::zero(), |acc, value| acc.add(value));
    let rho_weighted_variables = (0..MASK_ACTIVE_VARIABLES)
        .fold(LinExpr::zero(), |acc, variable| {
            acc.add(&mul(b, &variable_tensor[variable], &rho[variable]))
        });
    let positive_power_weight = power_tensor[1..MASK_ACTIVE_POWERS]
        .iter()
        .fold(LinExpr::zero(), |acc, value| acc.add(value));
    let input_without_high = mul(b, &power_tensor[0], &active_variable_weight).add(&mul(
        b,
        &positive_power_weight,
        &rho_weighted_variables,
    ));

    let mut final_without_high = LinExpr::zero();
    for variable in 0..MASK_ACTIVE_VARIABLES {
        // sum_{power=0}^{10} eq(power,s[0..4]) * r_variable^power.
        let mut polynomial = power_tensor[MASK_ACTIVE_POWERS - 1].clone();
        for power in (0..MASK_ACTIVE_POWERS - 1).rev() {
            polynomial = power_tensor[power].add(&mul(b, &r[variable], &polynomial));
        }
        final_without_high =
            final_without_high.add(&mul(b, &variable_tensor[variable], &polynomial));
    }

    MaskRelationValues {
        input_without_high,
        final_without_high,
        high_selector,
    }
}

/// Derive the post-claim bank claim and transparent `t(s)`.
///
/// The eleven scalar claims are compressed in the exact native order:
/// terminal state (five), boundary (IV2, IV3, address0, address1), and mask
/// (input, final).  `eta != 0` is an in-circuit fact, not merely a native
/// precondition.
pub fn build_zk_post_claim_relation_trace(
    b: &mut FieldR1csBuilder,
    input: &ZkPostClaimRelationTraceInput,
) -> Result<ZkPostClaimRelationTraceOutput, ZkPostClaimRelationTraceError> {
    preflight_dynamic_inputs(input)?;
    if input.eta.eval(b.values()) == F128::ZERO {
        return Err(ZkPostClaimRelationTraceError::ZeroEta);
    }
    if input
        .auth_terminal_point
        .iter()
        .fold(F128::ONE, |acc, coordinate| {
            acc * coordinate.eval(b.values())
        })
        == F128::ZERO
    {
        return Err(ZkPostClaimRelationTraceError::ZeroTerminalBlindingWeight);
    }

    let trace_start = b.num_wires();
    constrain_eta_nonzero(b, &input.eta);
    let eta_end = b.num_wires();
    debug_assert_eq!(eta_end - trace_start, ZK_POST_CLAIM_ETA_ROWS);

    let iv = capacity_iv(TAG_ADDRFIX);
    let ordered_scalars = [
        input.terminal_operand_claims[0].clone(),
        input.terminal_operand_claims[1].clone(),
        input.terminal_operand_claims[2].clone(),
        input.terminal_operand_claims[3].clone(),
        input.terminal_operand_claims[4].clone(),
        LinExpr::constant(flat_of(iv[0])),
        LinExpr::constant(flat_of(iv[1])),
        input.expected_address[0].clone(),
        input.expected_address[1].clone(),
        input.mask_mle_at_input.clone(),
        input.mask_final_at_terminal.clone(),
    ];
    let expected_inner_product = rlc_horner(b, &input.eta, &ordered_scalars);
    let scalar_end = b.num_wires();
    debug_assert_eq!(scalar_end - eta_end, ZK_POST_CLAIM_SCALAR_RLC_ROWS);

    let operands = terminal_operand_relation_values(
        b,
        &input.auth_terminal_point,
        &input.phase_a_terminal_point,
    );
    let state_end = b.num_wires();
    debug_assert_eq!(state_end - scalar_end, ZK_POST_CLAIM_STATE_RELATION_ROWS);
    let boundary = boundary_relation_values(
        b,
        &input.phase_a_terminal_point,
        &operands.lane_at_s,
        &operands.s_high_zero,
    );
    let boundary_end = b.num_wires();
    debug_assert_eq!(
        boundary_end - state_end,
        ZK_POST_CLAIM_BOUNDARY_RELATION_ROWS
    );
    let mask = mask_relation_values(
        b,
        &input.input_point,
        &input.auth_terminal_point,
        &input.phase_a_terminal_point,
        &operands.lane_at_s,
    );
    let mask_end = b.num_wires();
    debug_assert_eq!(mask_end - boundary_end, ZK_POST_CLAIM_MASK_RELATION_ROWS);

    // Fold claims 10 and 9 before applying their shared mask-bank selector,
    // then continue the exact eta-Horner order through boundary and state.
    let mut terminal_relation_value =
        mask.input_without_high
            .add(&mul(b, &input.eta, &mask.final_without_high));
    terminal_relation_value = mul(b, &mask.high_selector, &terminal_relation_value);
    let leading_relation_values = [
        operands.terminal[0].clone(),
        operands.terminal[1].clone(),
        operands.terminal[2].clone(),
        operands.terminal[3].clone(),
        operands.terminal[4].clone(),
        boundary[0].clone(),
        boundary[1].clone(),
        boundary[2].clone(),
        boundary[3].clone(),
    ];
    for value in leading_relation_values.iter().rev() {
        terminal_relation_value = value.add(&mul(b, &input.eta, &terminal_relation_value));
    }
    debug_assert_eq!(b.num_wires() - mask_end, ZK_POST_CLAIM_RELATION_RLC_ROWS);

    debug_assert_eq!(
        b.num_wires() - trace_start,
        ZK_POST_CLAIM_RELATION_TRACE_ROWS,
        "post-claim relation row ledger drifted"
    );
    Ok(ZkPostClaimRelationTraceOutput {
        bank_claim: expected_inner_product.clone(),
        expected_inner_product,
        terminal_relation_value,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acceptance::trace::{alloc_block, pin_eq, test_support::tower_value};
    use noid_core::mle::evaluate::evaluate_slice;
    use noid_core::TowerField;
    use noid_gkr::zk_auth_capsule::{
        build_post_claim_relation, AuthCapsulePostClaims, AuthCapsuleTerminalOperandClaims,
    };
    use noid_ivc_core::field_r1cs::FieldR1cs;

    const DYNAMIC_INPUT_ROWS: usize =
        3 * ZK_POST_CLAIM_VARS + 1 + ZK_POST_CLAIM_OPERAND_CLAIMS + 2 + 2;
    const FIXTURE_USEFUL_ROWS: usize = 1 + DYNAMIC_INPUT_ROWS + ZK_POST_CLAIM_RELATION_TRACE_ROWS;

    #[derive(Clone)]
    struct NativeFixture {
        rho: [Block128; ZK_POST_CLAIM_VARS],
        r: [Block128; ZK_POST_CLAIM_VARS],
        s: [Block128; ZK_POST_CLAIM_VARS],
        eta: Block128,
        terminal: [Block128; ZK_POST_CLAIM_OPERAND_CLAIMS],
        mask_input: Block128,
        mask_final: Block128,
        address: [Block128; 2],
        bank_claim: Block128,
        terminal_relation_value: Block128,
    }

    fn elem(index: usize, domain: u128, salt: u128) -> Block128 {
        Block128::from(
            domain
                .wrapping_mul(index as u128 + 1)
                .rotate_left(((index * 23 + 7) % 127) as u32)
                ^ salt.rotate_left(((index * 11 + 1) % 127) as u32)
                ^ (index as u128 + 1).wrapping_mul(0x9E37_79B9_7F4A_7C15),
        )
    }

    fn fixture(salt: u128) -> NativeFixture {
        let rho = std::array::from_fn(|i| elem(i, 0xA110, salt ^ 0x11));
        let r = std::array::from_fn(|i| elem(i, 0xB220, salt ^ 0x22));
        let s = std::array::from_fn(|i| elem(i, 0xC330, salt ^ 0x33));
        let mut eta = elem(19, 0xE7A0, salt ^ 0x44);
        if eta == Block128::ZERO {
            eta = Block128::ONE;
        }
        let terminal = std::array::from_fn(|i| elem(i, 0x57A7E, salt ^ 0x55));
        let mask_input = elem(31, 0x6A5C, salt ^ 0x66);
        let mask_final = elem(32, 0x6A5C, salt ^ 0x77);
        let address = [elem(41, 0xADD0, salt ^ 0x88), elem(42, 0xADD0, salt ^ 0x99)];
        let claims = AuthCapsulePostClaims {
            terminal_operands: AuthCapsuleTerminalOperandClaims {
                increment: terminal[0],
                lane: [terminal[1], terminal[2], terminal[3], terminal[4]],
            },
            mask_mle_at_input: mask_input,
            mask_final_at_terminal: mask_final,
        };
        let relation = build_post_claim_relation(
            &rho,
            &r,
            AuthCapsuleBoundaryPublic::canonical(address),
            claims,
            eta,
        )
        .expect("nonzero eta");
        let bank_claim = relation.expected_inner_product;
        let terminal_relation_value = evaluate_slice(&relation.weights, &s);
        NativeFixture {
            rho,
            r,
            s,
            eta,
            terminal,
            mask_input,
            mask_final,
            address,
            bank_claim,
            terminal_relation_value,
        }
    }

    fn alloc_input(
        b: &mut FieldR1csBuilder,
        native: &NativeFixture,
    ) -> ZkPostClaimRelationTraceInput {
        ZkPostClaimRelationTraceInput {
            input_point: std::array::from_fn(|i| alloc_block(b, native.rho[i])),
            auth_terminal_point: std::array::from_fn(|i| alloc_block(b, native.r[i])),
            phase_a_terminal_point: std::array::from_fn(|i| alloc_block(b, native.s[i])),
            eta: alloc_block(b, native.eta),
            terminal_operand_claims: std::array::from_fn(|i| alloc_block(b, native.terminal[i])),
            mask_mle_at_input: alloc_block(b, native.mask_input),
            mask_final_at_terminal: alloc_block(b, native.mask_final),
            expected_address: std::array::from_fn(|i| alloc_block(b, native.address[i])),
        }
    }

    struct BuiltFixture {
        r1cs: FieldR1cs,
        witness: Vec<F128>,
        trace_rows: usize,
        bank_claim: Block128,
        terminal_relation_value: Block128,
        eta_wire: usize,
        auth_terminal_wire: usize,
    }

    fn bare_wire(expression: &LinExpr) -> usize {
        assert_eq!(expression.constant, F128::ZERO);
        assert_eq!(expression.terms.len(), 1);
        assert_eq!(expression.terms[0].1, F128::ONE);
        expression.terms[0].0 as usize
    }

    fn build(native: &NativeFixture, pin_to: Option<(Block128, Block128)>) -> BuiltFixture {
        let mut b = FieldR1csBuilder::new();
        let input = alloc_input(&mut b, native);
        let eta_wire = bare_wire(&input.eta);
        let auth_terminal_wire = bare_wire(&input.auth_terminal_point[0]);
        assert_eq!(b.num_wires(), 1 + DYNAMIC_INPUT_ROWS);
        let before = b.num_wires();
        let output = build_zk_post_claim_relation_trace(&mut b, &input).expect("valid fixture");
        let trace_rows = b.num_wires() - before;
        let bank_claim = tower_value(&b, &output.bank_claim);
        let terminal_relation_value = tower_value(&b, &output.terminal_relation_value);
        if let Some((expected_bank, expected_terminal)) = pin_to {
            pin_eq(
                &mut b,
                &output.bank_claim,
                &LinExpr::constant(flat_of(expected_bank)),
            );
            pin_eq(
                &mut b,
                &output.terminal_relation_value,
                &LinExpr::constant(flat_of(expected_terminal)),
            );
        }
        let (r1cs, witness) = b.build();
        BuiltFixture {
            r1cs,
            witness,
            trace_rows,
            bank_claim,
            terminal_relation_value,
            eta_wire,
            auth_terminal_wire,
        }
    }

    #[test]
    fn post_claim_relation_trace_matches_native_dense_relation() {
        for salt in [0xA11C_E001, 0xA11C_E002, 0xA11C_E003] {
            let native = fixture(salt);
            let built = build(&native, None);
            assert!(built.r1cs.satisfies(&built.witness));
            assert_eq!(built.bank_claim, native.bank_claim);
            assert_eq!(
                built.terminal_relation_value,
                native.terminal_relation_value
            );
        }
    }

    #[test]
    fn eta_is_nonzero_natively_and_in_circuit() {
        let native = fixture(0xA11C_E010);
        let built = build(&native, None);
        assert!(built.r1cs.satisfies(&built.witness));
        let mut tampered = built.witness.clone();
        tampered[built.eta_wire] = F128::ZERO;
        assert!(!built.r1cs.satisfies(&tampered));

        let mut zero = native;
        zero.eta = Block128::ZERO;
        let mut b = FieldR1csBuilder::new();
        let input = alloc_input(&mut b, &zero);
        let before = b.num_wires();
        assert!(matches!(
            build_zk_post_claim_relation_trace(&mut b, &input),
            Err(ZkPostClaimRelationTraceError::ZeroEta)
        ));
        assert_eq!(b.num_wires(), before);
    }

    #[test]
    fn terminal_blinding_weight_is_nonzero_natively_and_in_circuit() {
        let native = fixture(0xA11C_E011);
        let built = build(&native, None);
        assert!(built.r1cs.satisfies(&built.witness));

        let mut tampered = built.witness.clone();
        tampered[built.auth_terminal_wire] = F128::ZERO;
        assert!(!built.r1cs.satisfies(&tampered));

        let mut zero = native;
        zero.r[0] = Block128::ZERO;
        let mut b = FieldR1csBuilder::new();
        let input = alloc_input(&mut b, &zero);
        let before = b.num_wires();
        assert!(matches!(
            build_zk_post_claim_relation_trace(&mut b, &input),
            Err(ZkPostClaimRelationTraceError::ZeroTerminalBlindingWeight)
        ));
        assert_eq!(b.num_wires(), before);
    }

    #[test]
    fn claim_order_point_and_boundary_tampers_miss_the_original_outputs() {
        let original = fixture(0xA11C_E020);
        let pins = (original.bank_claim, original.terminal_relation_value);
        let mut mutations = Vec::new();

        let mut order = original.clone();
        order.terminal.swap(1, 4);
        mutations.push(("terminal claim order", order));

        let mut rho = original.clone();
        rho.rho[7] += Block128::ONE;
        mutations.push(("rho", rho));

        let mut r = original.clone();
        r.r[3] += Block128::ONE;
        mutations.push(("AuthGKR terminal", r));

        let mut s = original.clone();
        s.s[9] += Block128::ONE;
        mutations.push(("Phase-A terminal", s));

        let mut address = original.clone();
        address.address[0] += Block128::ONE;
        mutations.push(("address", address));

        let mut eta = original.clone();
        eta.eta += Block128::ONE;
        if eta.eta == Block128::ZERO {
            eta.eta += Block128::from(2u128);
        }
        mutations.push(("eta", eta));

        for (name, mutation) in mutations {
            let built = build(&mutation, Some(pins));
            assert_eq!(built.trace_rows, ZK_POST_CLAIM_RELATION_TRACE_ROWS);
            assert!(
                !built.r1cs.satisfies(&built.witness),
                "accepted {name} tamper"
            );
        }
    }

    #[test]
    fn trace_has_exact_content_invariant_shape() {
        let left = build(&fixture(0xA11C_E030), None);
        let right = build(&fixture(0xA11C_E031), None);
        assert!(left.r1cs.satisfies(&left.witness));
        assert!(right.r1cs.satisfies(&right.witness));
        assert_eq!(left.trace_rows, ZK_POST_CLAIM_RELATION_TRACE_ROWS);
        assert_eq!(right.trace_rows, ZK_POST_CLAIM_RELATION_TRACE_ROWS);
        assert_eq!(left.r1cs.useful_rows, FIXTURE_USEFUL_ROWS);
        assert_eq!(right.r1cs.useful_rows, FIXTURE_USEFUL_ROWS);
        assert_eq!(left.r1cs.statement_digest(), right.r1cs.statement_digest());
    }

    #[test]
    fn dynamic_inputs_cannot_be_embedded_as_constants() {
        let native = fixture(0xA11C_E040);
        let mut b = FieldR1csBuilder::new();
        let mut input = alloc_input(&mut b, &native);
        input.phase_a_terminal_point[6] = LinExpr::constant(flat_of(native.s[6]));
        let before = b.num_wires();
        assert!(matches!(
            build_zk_post_claim_relation_trace(&mut b, &input),
            Err(ZkPostClaimRelationTraceError::DynamicInputIsConstant {
                input: ZkPostClaimDynamicInput::PhaseATerminalPoint,
                index: 6,
            })
        ));
        assert_eq!(b.num_wires(), before);
    }
}
