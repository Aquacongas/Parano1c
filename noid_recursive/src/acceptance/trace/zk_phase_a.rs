// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Production-disconnected recursive verifier trace for capsule Phase A.
//!
//! This is the fixed-shape arithmetic twin of
//! [`noid_fri_binius::zk_phase_a::verify_phase_a`], excluding transcript
//! replay. The caller supplies already-bound dynamic expressions for the two
//! relation claims, `gamma`, eleven HIGH-to-LOW challenges, the two proof
//! fields in every round, transparent `t(s)`, and the Phase-B-linked terminal
//! oracle value `v`.
//!
//! `t(s)` is an interface value, not an independently trusted witness: the
//! integrating capsule region must supply it from its transparent relation
//! evaluation/recomputation gadget. This primitive then enforces the terminal
//! equation `running = t(s) * v`.
//!
//! Gamma admissibility is sound in-circuit. Two inverse witnesses enforce
//! `gamma != 0` and `gamma + 1 != 0`; native endpoint checks are only an early
//! construction error and are not the soundness boundary.

use noid_fri_binius::zk_phase_a::{PHASE_A_SERIALIZED_FIELDS_PER_ROUND, PHASE_A_VARS};

use super::{pin_eq, FieldR1csBuilder, LinExpr, F128};

pub const ZK_PHASE_A_ROUNDS: usize = PHASE_A_VARS;
pub const ZK_PHASE_A_FIELDS_PER_ROUND: usize = PHASE_A_SERIALIZED_FIELDS_PER_ROUND;

/// Two inverse witnesses, two products, and two equality pins.
pub const ZK_PHASE_A_GAMMA_ADMISSIBILITY_ROWS: usize = 6;
/// `b + gamma * (b + sigma)`.
pub const ZK_PHASE_A_INITIAL_CLAIM_ROWS: usize = 1;
/// Horner evaluation of one quadratic round polynomial.
pub const ZK_PHASE_A_ROWS_PER_ROUND: usize = 2;
pub const ZK_PHASE_A_SUMCHECK_ROWS: usize = ZK_PHASE_A_ROUNDS * ZK_PHASE_A_ROWS_PER_ROUND;
/// One multiplication for `t(s) * v` and one terminal equality pin.
pub const ZK_PHASE_A_TERMINAL_ROWS: usize = 2;
/// Incremental rows after all caller-owned dynamic inputs have been allocated.
pub const ZK_PHASE_A_TRACE_ROWS: usize = ZK_PHASE_A_GAMMA_ADMISSIBILITY_ROWS
    + ZK_PHASE_A_INITIAL_CLAIM_ROWS
    + ZK_PHASE_A_SUMCHECK_ROWS
    + ZK_PHASE_A_TERMINAL_ROWS;

const _: () = assert!(ZK_PHASE_A_ROUNDS == 11);
const _: () = assert!(ZK_PHASE_A_FIELDS_PER_ROUND == 2);
const _: () = assert!(ZK_PHASE_A_SUMCHECK_ROWS == 22);
const _: () = assert!(ZK_PHASE_A_TRACE_ROWS == 31);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ZkPhaseATraceDynamicInput {
    BankClaim,
    CompanionClaim,
    Gamma,
    Challenge,
    RoundAtOne,
    RoundAtInfinity,
    TerminalRelationValue,
    TerminalOracleValue,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ZkPhaseATraceError {
    /// A transcript/proof value was accidentally embedded in the matrix as a
    /// build-time constant instead of entering through an allocated wire.
    DynamicInputIsConstant {
        input: ZkPhaseATraceDynamicInput,
        index: usize,
    },
    GammaZero,
    GammaOne,
}

#[derive(Clone, Debug)]
pub struct ZkPhaseATraceRound {
    /// Serialized `p(1)` field.
    pub at_one: LinExpr,
    /// Serialized quadratic coefficient `p(infinity)`.
    pub at_infinity: LinExpr,
}

#[derive(Clone, Debug)]
pub struct ZkPhaseATraceInput {
    /// `b = <B,t>`.
    pub bank_claim: LinExpr,
    /// `sigma = <C,t>`.
    pub companion_claim: LinExpr,
    pub gamma: LinExpr,
    /// Transcript challenges in exact sumcheck order `[s_10, ..., s_0]`.
    pub challenges_high_to_low: [LinExpr; ZK_PHASE_A_ROUNDS],
    pub rounds: [ZkPhaseATraceRound; ZK_PHASE_A_ROUNDS],
    /// Transparent relation evaluation `t(s)`, supplied by the caller's
    /// relation gadget at the canonical terminal point.
    pub terminal_relation_value: LinExpr,
    /// Phase-B-linked `O_gamma(s)` value `v`.
    pub terminal_oracle_value: LinExpr,
}

#[derive(Clone, Debug)]
pub struct ZkPhaseATraceOutput {
    pub initial_claim: LinExpr,
    pub running_claim: LinExpr,
    /// Canonical MLE order `[s_0, ..., s_10]`.
    pub terminal_point: [LinExpr; ZK_PHASE_A_ROUNDS],
    pub terminal_relation_value: LinExpr,
    pub terminal_oracle_value: LinExpr,
}

fn check_dynamic(
    expression: &LinExpr,
    input: ZkPhaseATraceDynamicInput,
    index: usize,
) -> Result<(), ZkPhaseATraceError> {
    if expression.is_const() {
        Err(ZkPhaseATraceError::DynamicInputIsConstant { input, index })
    } else {
        Ok(())
    }
}

fn preflight_dynamic_inputs(input: &ZkPhaseATraceInput) -> Result<(), ZkPhaseATraceError> {
    check_dynamic(&input.bank_claim, ZkPhaseATraceDynamicInput::BankClaim, 0)?;
    check_dynamic(
        &input.companion_claim,
        ZkPhaseATraceDynamicInput::CompanionClaim,
        0,
    )?;
    check_dynamic(&input.gamma, ZkPhaseATraceDynamicInput::Gamma, 0)?;
    for round in 0..ZK_PHASE_A_ROUNDS {
        check_dynamic(
            &input.challenges_high_to_low[round],
            ZkPhaseATraceDynamicInput::Challenge,
            round,
        )?;
        check_dynamic(
            &input.rounds[round].at_one,
            ZkPhaseATraceDynamicInput::RoundAtOne,
            round,
        )?;
        check_dynamic(
            &input.rounds[round].at_infinity,
            ZkPhaseATraceDynamicInput::RoundAtInfinity,
            round,
        )?;
    }
    check_dynamic(
        &input.terminal_relation_value,
        ZkPhaseATraceDynamicInput::TerminalRelationValue,
        0,
    )?;
    check_dynamic(
        &input.terminal_oracle_value,
        ZkPhaseATraceDynamicInput::TerminalOracleValue,
        0,
    )
}

/// Allocate an inverse witness and constrain `value * inverse = 1`.
fn constrain_nonzero(b: &mut FieldR1csBuilder, value: &LinExpr) {
    let inverse_value = value.eval(b.values()).inv();
    let inverse = LinExpr::from_wire(b.alloc_f128(inverse_value));
    // Use the raw builder multiplication deliberately: every admissibility
    // check owns exactly one multiplication row even for a degenerate caller
    // expression. Dynamic-input preflight separately excludes constants.
    let product = LinExpr::from_wire(b.mul(value, &inverse));
    pin_eq(b, &product, &LinExpr::constant(F128::ONE));
}

/// Verify the fixed 11-round Phase-A relation inside an F128 trace.
///
/// Transcript absorption/squeezing, construction of `t(s)`, and the Phase-B
/// opening are deliberately outside this disconnected primitive. Every input
/// that will eventually originate in the transcript or proof must be an
/// allocated expression; constants are rejected before any trace rows are
/// appended.
pub fn verify_zk_phase_a_trace(
    b: &mut FieldR1csBuilder,
    input: &ZkPhaseATraceInput,
) -> Result<ZkPhaseATraceOutput, ZkPhaseATraceError> {
    preflight_dynamic_inputs(input)?;

    let gamma_value = input.gamma.eval(b.values());
    if gamma_value == F128::ZERO {
        return Err(ZkPhaseATraceError::GammaZero);
    }
    if gamma_value == F128::ONE {
        return Err(ZkPhaseATraceError::GammaOne);
    }

    let trace_start = b.num_wires();
    constrain_nonzero(b, &input.gamma);
    let gamma_plus_one = input.gamma.add_const(F128::ONE);
    constrain_nonzero(b, &gamma_plus_one);
    debug_assert_eq!(
        b.num_wires() - trace_start,
        ZK_PHASE_A_GAMMA_ADMISSIBILITY_ROWS
    );

    // Characteristic two: (1-gamma)B + gamma*C = B + gamma*(B+C).
    let claims_delta = input.bank_claim.add(&input.companion_claim);
    let mixed_claim = LinExpr::from_wire(b.mul(&input.gamma, &claims_delta));
    let initial_claim = input.bank_claim.add(&mixed_claim);
    debug_assert_eq!(
        b.num_wires() - trace_start,
        ZK_PHASE_A_GAMMA_ADMISSIBILITY_ROWS + ZK_PHASE_A_INITIAL_CLAIM_ROWS
    );

    let mut running_claim = initial_claim.clone();
    for round in 0..ZK_PHASE_A_ROUNDS {
        let round_start = b.num_wires();
        let proof = &input.rounds[round];
        let challenge = &input.challenges_high_to_low[round];

        // From p(0)+p(1)=claim:
        //   p(0) = claim + p(1)
        // and the linear coefficient is claim + p(infinity). Evaluate
        //   p(r) = p(0) + r * ((claim+p_inf) + r*p_inf)
        // as an exact two-multiplication Horner step.
        let at_zero = running_claim.add(&proof.at_one);
        let linear = running_claim.add(&proof.at_infinity);
        let quadratic_tail = LinExpr::from_wire(b.mul(challenge, &proof.at_infinity));
        let horner_inner = linear.add(&quadratic_tail);
        let horner_tail = LinExpr::from_wire(b.mul(challenge, &horner_inner));
        running_claim = at_zero.add(&horner_tail);

        debug_assert_eq!(b.num_wires() - round_start, ZK_PHASE_A_ROWS_PER_ROUND);
    }

    // The sumcheck binds high-to-low, while every MLE interface is canonical
    // low-to-high. Reordering aliases expressions and costs no rows.
    let terminal_point = std::array::from_fn(|low_variable| {
        input.challenges_high_to_low[ZK_PHASE_A_ROUNDS - 1 - low_variable].clone()
    });

    let terminal_product =
        LinExpr::from_wire(b.mul(&input.terminal_relation_value, &input.terminal_oracle_value));
    pin_eq(b, &running_claim, &terminal_product);

    debug_assert_eq!(b.num_wires() - trace_start, ZK_PHASE_A_TRACE_ROWS);
    Ok(ZkPhaseATraceOutput {
        initial_claim,
        running_claim,
        terminal_point,
        terminal_relation_value: input.terminal_relation_value.clone(),
        terminal_oracle_value: input.terminal_oracle_value.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acceptance::trace::{alloc_block, test_support::tower_value};
    use noid_core::{Block128, TowerField};
    use noid_fri_binius::zk_phase_a::{
        prove_phase_a, verify_phase_a, ZkPhaseARelationClaims, ZkPhaseARoundProof,
        PHASE_A_ORACLE_LEN,
    };
    use noid_ivc_core::field_r1cs::FieldR1cs;

    const ZK_PHASE_A_DYNAMIC_INPUT_ROWS: usize =
        2 + 1 + ZK_PHASE_A_ROUNDS + ZK_PHASE_A_ROUNDS * ZK_PHASE_A_FIELDS_PER_ROUND + 2;
    const ZK_PHASE_A_FIXTURE_USEFUL_ROWS: usize =
        1 + ZK_PHASE_A_DYNAMIC_INPUT_ROWS + ZK_PHASE_A_TRACE_ROWS;

    #[derive(Clone)]
    struct NativeCase {
        relation_claims: ZkPhaseARelationClaims,
        gamma: Block128,
        challenges: [Block128; ZK_PHASE_A_ROUNDS],
        rounds: [ZkPhaseARoundProof; ZK_PHASE_A_ROUNDS],
        terminal_point: [Block128; ZK_PHASE_A_ROUNDS],
        terminal_relation_value: Block128,
        terminal_oracle_value: Block128,
        initial_claim: Block128,
    }

    fn elem(index: usize, domain: u128, salt: u128) -> Block128 {
        Block128::from(
            domain
                .wrapping_mul(index as u128 + 1)
                .rotate_left(((index * 17 + 3) % 127) as u32)
                ^ salt.rotate_left((index % 127) as u32)
                ^ (index as u128 + 1).wrapping_mul(0x9E37_79B9_7F4A_7C15),
        )
    }

    fn table(domain: u128, salt: u128) -> [Block128; PHASE_A_ORACLE_LEN] {
        std::array::from_fn(|index| elem(index, domain, salt))
    }

    fn native_case(salt: u128) -> NativeCase {
        let bank = table(0xB4A9, salt ^ 0x11);
        let companion = table(0xC09A, salt ^ 0x22);
        let relation = table(0x7E1A_710, salt ^ 0x33);
        let challenges = std::array::from_fn(|round| elem(round + 31, 0xC4A1_1E6E, salt ^ 0x44));
        let mut gamma = elem(19, 0x0006_A77A, salt ^ 0x55);
        if gamma == Block128::ZERO || gamma == Block128::ONE {
            gamma += Block128::from(2u128);
        }

        let output = prove_phase_a(&bank, &companion, &relation, gamma, &challenges)
            .expect("native Phase-A fixture");
        let verified = verify_phase_a(
            &output.proof,
            output.relation_claims,
            &relation,
            gamma,
            &challenges,
            output.terminal_oracle_value,
        )
        .expect("native Phase-A fixture verifies");
        NativeCase {
            relation_claims: output.relation_claims,
            gamma,
            challenges,
            rounds: output.proof.rounds,
            terminal_point: output.terminal_point,
            terminal_relation_value: verified.terminal_relation_value,
            terminal_oracle_value: output.terminal_oracle_value,
            initial_claim: output.initial_claim,
        }
    }

    struct BuiltCase {
        r1cs: FieldR1cs,
        witness: Vec<F128>,
        trace_rows: usize,
        initial_claim: Block128,
        running_claim: Block128,
        terminal_point: [Block128; ZK_PHASE_A_ROUNDS],
        gamma_wire: usize,
    }

    fn input_wire(expression: &LinExpr) -> usize {
        assert_eq!(expression.terms.len(), 1);
        assert_eq!(expression.terms[0].1, F128::ONE);
        assert_eq!(expression.constant, F128::ZERO);
        expression.terms[0].0 as usize
    }

    fn build_case(case: &NativeCase) -> Result<BuiltCase, ZkPhaseATraceError> {
        let mut b = FieldR1csBuilder::new();
        let bank_claim = alloc_block(&mut b, case.relation_claims.bank);
        let companion_claim = alloc_block(&mut b, case.relation_claims.companion);
        let gamma = alloc_block(&mut b, case.gamma);
        let gamma_wire = input_wire(&gamma);
        let challenges_high_to_low =
            std::array::from_fn(|round| alloc_block(&mut b, case.challenges[round]));
        let rounds = std::array::from_fn(|round| ZkPhaseATraceRound {
            at_one: alloc_block(&mut b, case.rounds[round].at_one),
            at_infinity: alloc_block(&mut b, case.rounds[round].at_infinity),
        });
        let terminal_relation_value = alloc_block(&mut b, case.terminal_relation_value);
        let terminal_oracle_value = alloc_block(&mut b, case.terminal_oracle_value);
        assert_eq!(
            b.num_wires(),
            1 + ZK_PHASE_A_DYNAMIC_INPUT_ROWS,
            "fixture input ledger"
        );

        let input = ZkPhaseATraceInput {
            bank_claim,
            companion_claim,
            gamma,
            challenges_high_to_low,
            rounds,
            terminal_relation_value,
            terminal_oracle_value,
        };
        let before = b.num_wires();
        let output = verify_zk_phase_a_trace(&mut b, &input)?;
        let trace_rows = b.num_wires() - before;
        let initial_claim = tower_value(&b, &output.initial_claim);
        let running_claim = tower_value(&b, &output.running_claim);
        let terminal_point =
            std::array::from_fn(|index| tower_value(&b, &output.terminal_point[index]));
        let (r1cs, witness) = b.build();
        Ok(BuiltCase {
            r1cs,
            witness,
            trace_rows,
            initial_claim,
            running_claim,
            terminal_point,
            gamma_wire,
        })
    }

    #[test]
    fn zk_phase_a_trace_matches_native_honestly() {
        let native = native_case(0xA11C_E001);
        let built = build_case(&native).expect("trace builds");
        assert!(built.r1cs.satisfies(&built.witness));
        assert_eq!(built.initial_claim, native.initial_claim);
        assert_eq!(built.terminal_point, native.terminal_point);
        assert_eq!(
            built.running_claim,
            native.terminal_relation_value * native.terminal_oracle_value
        );
    }

    #[test]
    fn zk_phase_a_trace_rejects_round_terminal_v_and_terminal_t_tampering() {
        let native = native_case(0xA11C_E002);
        let mut mutations = Vec::new();

        let mut round = native.clone();
        round.rounds[5].at_one += Block128::ONE;
        mutations.push(("round p(1)", round));

        let mut infinity = native.clone();
        infinity.rounds[8].at_infinity += Block128::ONE;
        mutations.push(("round p(infinity)", infinity));

        let mut terminal_v = native.clone();
        terminal_v.terminal_oracle_value += Block128::ONE;
        mutations.push(("terminal v", terminal_v));

        let mut terminal_t = native.clone();
        terminal_t.terminal_relation_value += Block128::ONE;
        mutations.push(("terminal t(s)", terminal_t));

        for (name, mutation) in mutations {
            let built = build_case(&mutation).expect("tampered trace still has valid shape");
            assert!(
                !built.r1cs.satisfies(&built.witness),
                "accepted {name} tamper"
            );
        }
    }

    #[test]
    fn zk_phase_a_trace_rejects_gamma_endpoints_preflight_and_in_circuit() {
        let native = native_case(0xA11C_E003);

        let mut zero = native.clone();
        zero.gamma = Block128::ZERO;
        assert!(matches!(
            build_case(&zero),
            Err(ZkPhaseATraceError::GammaZero)
        ));

        let mut one = native.clone();
        one.gamma = Block128::ONE;
        assert!(matches!(
            build_case(&one),
            Err(ZkPhaseATraceError::GammaOne)
        ));

        let built = build_case(&native).expect("honest trace");
        assert!(built.r1cs.satisfies(&built.witness));
        for endpoint in [F128::ZERO, F128::ONE] {
            let mut tampered = built.witness.clone();
            tampered[built.gamma_wire] = endpoint;
            assert!(
                !built.r1cs.satisfies(&tampered),
                "gamma endpoint escaped inverse constraints"
            );
        }
    }

    #[test]
    fn zk_phase_a_trace_uses_high_to_low_rounds_and_returns_low_to_high_point() {
        let native = native_case(0xA11C_E004);
        let built = build_case(&native).expect("honest trace");
        assert!(built.r1cs.satisfies(&built.witness));
        for low_variable in 0..ZK_PHASE_A_ROUNDS {
            assert_eq!(
                built.terminal_point[low_variable],
                native.challenges[ZK_PHASE_A_ROUNDS - 1 - low_variable]
            );
        }

        let mut wrong_order = native.clone();
        wrong_order.challenges.reverse();
        let wrong = build_case(&wrong_order).expect("wrong-order trace has fixed shape");
        assert!(
            !wrong.r1cs.satisfies(&wrong.witness),
            "LOW-to-HIGH challenges were accepted as round order"
        );
    }

    #[test]
    fn zk_phase_a_trace_has_exact_row_ledger_and_content_invariant_shape() {
        let left = build_case(&native_case(0xA11C_E005)).expect("left trace");
        let right = build_case(&native_case(0xA11C_E006)).expect("right trace");
        assert!(left.r1cs.satisfies(&left.witness));
        assert!(right.r1cs.satisfies(&right.witness));

        assert_eq!(ZK_PHASE_A_GAMMA_ADMISSIBILITY_ROWS, 6);
        assert_eq!(ZK_PHASE_A_INITIAL_CLAIM_ROWS, 1);
        assert_eq!(ZK_PHASE_A_ROWS_PER_ROUND, 2);
        assert_eq!(ZK_PHASE_A_SUMCHECK_ROWS, 22);
        assert_eq!(ZK_PHASE_A_TERMINAL_ROWS, 2);
        assert_eq!(ZK_PHASE_A_TRACE_ROWS, 31);
        assert_eq!(left.trace_rows, ZK_PHASE_A_TRACE_ROWS);
        assert_eq!(right.trace_rows, ZK_PHASE_A_TRACE_ROWS);
        assert_eq!(left.r1cs.useful_rows, ZK_PHASE_A_FIXTURE_USEFUL_ROWS);
        assert_eq!(right.r1cs.useful_rows, ZK_PHASE_A_FIXTURE_USEFUL_ROWS);
        assert_eq!(left.r1cs.statement_digest(), right.r1cs.statement_digest());
    }

    #[test]
    fn zk_phase_a_trace_refuses_constant_challenges_and_proof_fields() {
        let native = native_case(0xA11C_E007);
        let mut b = FieldR1csBuilder::new();
        let mut input = ZkPhaseATraceInput {
            bank_claim: alloc_block(&mut b, native.relation_claims.bank),
            companion_claim: alloc_block(&mut b, native.relation_claims.companion),
            gamma: alloc_block(&mut b, native.gamma),
            challenges_high_to_low: std::array::from_fn(|round| {
                if round == 3 {
                    LinExpr::constant(super::super::flat_of(native.challenges[round]))
                } else {
                    alloc_block(&mut b, native.challenges[round])
                }
            }),
            rounds: std::array::from_fn(|round| ZkPhaseATraceRound {
                at_one: alloc_block(&mut b, native.rounds[round].at_one),
                at_infinity: alloc_block(&mut b, native.rounds[round].at_infinity),
            }),
            terminal_relation_value: alloc_block(&mut b, native.terminal_relation_value),
            terminal_oracle_value: alloc_block(&mut b, native.terminal_oracle_value),
        };
        let before = b.num_wires();
        assert!(matches!(
            verify_zk_phase_a_trace(&mut b, &input),
            Err(ZkPhaseATraceError::DynamicInputIsConstant {
                input: ZkPhaseATraceDynamicInput::Challenge,
                index: 3,
            })
        ));
        assert_eq!(b.num_wires(), before, "failed preflight appended rows");

        input.challenges_high_to_low[3] = alloc_block(&mut b, native.challenges[3]);
        input.rounds[7].at_infinity =
            LinExpr::constant(super::super::flat_of(native.rounds[7].at_infinity));
        let before = b.num_wires();
        assert!(matches!(
            verify_zk_phase_a_trace(&mut b, &input),
            Err(ZkPhaseATraceError::DynamicInputIsConstant {
                input: ZkPhaseATraceDynamicInput::RoundAtInfinity,
                index: 7,
            })
        ));
        assert_eq!(b.num_wires(), before, "failed preflight appended rows");
    }
}
