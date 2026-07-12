// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Production-disconnected recursive algebra for one selected capsule
//! Phase-B query.
//!
//! The caller supplies one already transcript-bound, LSB-first source query
//! `q0..q12` and the three authenticated openings belonging to it:
//!
//! - a joint source leaf `[B0, C0, ..., B7, C7]`;
//! - the corresponding 16-cell mid leaf;
//! - the common 16-coefficient tail.
//!
//! This trace applies the selected affine-LCH folds and enforces both
//! cross-layer splices.  The same query expressions are aliased throughout:
//! `q0..q3` select the source result from the mid leaf and `q4..q12` select
//! the mid result from the encoded tail.  Query-bit booleanity, transcript
//! recomposition, Merkle authentication, and cap selection belong to their
//! surrounding regions and are deliberately not duplicated here.
//!
//! Exact incremental row ledger after caller-owned inputs:
//!
//! ```text
//! source gamma + affine fold3       22
//! 16-way mid-member selector        15
//! source -> selected-mid pin         1
//! affine mid fold4                  30
//! affine-tail selector              15
//! mid -> selected-tail pin           1
//!                                    --
//! total                              84
//! ```
//!
//! This module remains disconnected from the active acceptance region and
//! wire format.  It fixes the arithmetic unit that the capsule region can
//! instantiate once per query without making its matrix depend on query
//! values or proof contents.

use std::sync::OnceLock;

use noid_fri_binius::zk_affine_code::{ZkAffineCodeError, ZkAffineLchCode};
use noid_fri_binius::zk_capsule_algebra::{
    JOINT_SOURCE_LEAF_SYMBOLS, MID_STANDARD_FOLDS, SOURCE_QUERY_BITS, SOURCE_STANDARD_FOLDS,
    TAIL_SYMBOLS,
};

use super::zk_affine_fold::{fold_joint_source_leaf_trace, mid_standard_fold4_trace};
use super::zk_affine_tail::{
    select_affine_tail16_trace, ZK_AFFINE_TAIL_LEN, ZK_AFFINE_TAIL_QUERY_BITS,
    ZK_AFFINE_TAIL_SELECTOR_ROWS,
};
use super::{mul, pin_eq, FieldR1csBuilder, LinExpr};

pub const ZK_PHASE_B_SOURCE_FOLD_ROWS: usize = 22;
pub const ZK_PHASE_B_MID_MEMBER_SELECTOR_ROWS: usize = (1 << MID_STANDARD_FOLDS) - 1;
pub const ZK_PHASE_B_SOURCE_SPLICE_PIN_ROWS: usize = 1;
pub const ZK_PHASE_B_MID_FOLD_ROWS: usize = 30;
pub const ZK_PHASE_B_TAIL_SELECTOR_ROWS: usize = ZK_AFFINE_TAIL_SELECTOR_ROWS;
pub const ZK_PHASE_B_MID_SPLICE_PIN_ROWS: usize = 1;

/// Exact incremental row count of one complete disconnected query algebra.
pub const ZK_PHASE_B_QUERY_TRACE_ROWS: usize = ZK_PHASE_B_SOURCE_FOLD_ROWS
    + ZK_PHASE_B_MID_MEMBER_SELECTOR_ROWS
    + ZK_PHASE_B_SOURCE_SPLICE_PIN_ROWS
    + ZK_PHASE_B_MID_FOLD_ROWS
    + ZK_PHASE_B_TAIL_SELECTOR_ROWS
    + ZK_PHASE_B_MID_SPLICE_PIN_ROWS;

/// Rows charged by the active query algebra that this unit replaces.
pub const ZK_PHASE_B_PREVIOUS_ACTIVE_QUERY_ROWS: usize = 49;
/// Exact per-query increase when this complete unit replaces that algebra.
pub const ZK_PHASE_B_QUERY_ACTIVE_EQUIVALENT_DELTA_ROWS: usize =
    ZK_PHASE_B_QUERY_TRACE_ROWS - ZK_PHASE_B_PREVIOUS_ACTIVE_QUERY_ROWS;

const MID_MEMBER_QUERY_BITS: usize = MID_STANDARD_FOLDS;
const MID_LEAF_QUERY_BIT_OFFSET: usize = MID_MEMBER_QUERY_BITS;

const _: () = assert!(JOINT_SOURCE_LEAF_SYMBOLS == 16);
const _: () = assert!(SOURCE_QUERY_BITS == 13);
const _: () = assert!(SOURCE_STANDARD_FOLDS == 3);
const _: () = assert!(MID_STANDARD_FOLDS == 4);
const _: () = assert!(TAIL_SYMBOLS == 16);
const _: () = assert!(ZK_AFFINE_TAIL_LEN == TAIL_SYMBOLS);
const _: () = assert!(SOURCE_QUERY_BITS - MID_LEAF_QUERY_BIT_OFFSET == 9);
const _: () = assert!(ZK_AFFINE_TAIL_QUERY_BITS == 9);
const _: () = assert!(ZK_PHASE_B_MID_MEMBER_SELECTOR_ROWS == 15);
const _: () = assert!(ZK_PHASE_B_QUERY_TRACE_ROWS == 84);
const _: () = assert!(ZK_PHASE_B_QUERY_ACTIVE_EQUIVALENT_DELTA_ROWS == 35);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ZkPhaseBQueryDynamicInput {
    QueryBit,
    JointSourceLeaf,
    MidLeaf,
    Tail,
    Gamma,
    SourceChallenge,
    MidChallenge,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ZkPhaseBQueryTraceError {
    /// A proof/transcript value was embedded as a build-time matrix constant
    /// instead of entering through an allocated expression.
    DynamicInputIsConstant {
        input: ZkPhaseBQueryDynamicInput,
        index: usize,
    },
    AffineCode(ZkAffineCodeError),
}

impl From<ZkAffineCodeError> for ZkPhaseBQueryTraceError {
    fn from(value: ZkAffineCodeError) -> Self {
        Self::AffineCode(value)
    }
}

#[derive(Clone, Debug)]
pub struct ZkPhaseBQueryTraceInput {
    /// Transcript-bound source-leaf bits `q0..q12`, LSB first.
    pub query_bits: [LinExpr; SOURCE_QUERY_BITS],
    /// Authenticated adjacent layout `[B0, C0, ..., B7, C7]`.
    pub joint_source_leaf: [LinExpr; JOINT_SOURCE_LEAF_SYMBOLS],
    /// Authenticated contiguous mid codeword leaf.
    pub mid_leaf: [LinExpr; 1 << MID_STANDARD_FOLDS],
    /// Revealed common coefficient tail after seven LOW-to-HIGH folds.
    pub tail: [LinExpr; TAIL_SYMBOLS],
    pub gamma: LinExpr,
    /// Challenges for logical variables `0..3`, LOW-to-HIGH.
    pub source_challenges: [LinExpr; SOURCE_STANDARD_FOLDS],
    /// Challenges for logical variables `3..7`, LOW-to-HIGH.
    pub mid_challenges: [LinExpr; MID_STANDARD_FOLDS],
}

#[derive(Clone, Debug)]
pub struct ZkPhaseBQueryTraceOutput {
    /// Result of the joint source line and the first three affine folds.
    pub source_folded: LinExpr,
    /// Mid-leaf member selected by the shared `q0..q3` aliases.
    pub selected_mid_member: LinExpr,
    /// Result of the next four affine folds.
    pub mid_folded: LinExpr,
    /// Encoded-tail cell selected by the shared `q4..q12` aliases.
    pub selected_tail_cell: LinExpr,
}

fn selected_code() -> Result<&'static ZkAffineLchCode, ZkAffineCodeError> {
    static CODE: OnceLock<Result<ZkAffineLchCode, ZkAffineCodeError>> = OnceLock::new();
    match CODE.get_or_init(ZkAffineLchCode::selected) {
        Ok(code) => Ok(code),
        Err(error) => Err(*error),
    }
}

fn check_dynamic(
    expression: &LinExpr,
    input: ZkPhaseBQueryDynamicInput,
    index: usize,
) -> Result<(), ZkPhaseBQueryTraceError> {
    if expression.is_const() {
        Err(ZkPhaseBQueryTraceError::DynamicInputIsConstant { input, index })
    } else {
        Ok(())
    }
}

fn preflight_dynamic_inputs(
    input: &ZkPhaseBQueryTraceInput,
) -> Result<(), ZkPhaseBQueryTraceError> {
    for (index, expression) in input.query_bits.iter().enumerate() {
        check_dynamic(expression, ZkPhaseBQueryDynamicInput::QueryBit, index)?;
    }
    for (index, expression) in input.joint_source_leaf.iter().enumerate() {
        check_dynamic(
            expression,
            ZkPhaseBQueryDynamicInput::JointSourceLeaf,
            index,
        )?;
    }
    for (index, expression) in input.mid_leaf.iter().enumerate() {
        check_dynamic(expression, ZkPhaseBQueryDynamicInput::MidLeaf, index)?;
    }
    for (index, expression) in input.tail.iter().enumerate() {
        check_dynamic(expression, ZkPhaseBQueryDynamicInput::Tail, index)?;
    }
    check_dynamic(&input.gamma, ZkPhaseBQueryDynamicInput::Gamma, 0)?;
    for (index, expression) in input.source_challenges.iter().enumerate() {
        check_dynamic(
            expression,
            ZkPhaseBQueryDynamicInput::SourceChallenge,
            index,
        )?;
    }
    for (index, expression) in input.mid_challenges.iter().enumerate() {
        check_dynamic(expression, ZkPhaseBQueryDynamicInput::MidChallenge, index)?;
    }
    Ok(())
}

/// Evaluate a dynamic 16-cell table at four LSB-first query coordinates.
///
/// For Boolean query bits this is exactly a 16-way member mux.  Written as
/// four adjacent multilinear folds, it has the fixed `8 + 4 + 2 + 1 = 15`
/// multiplication-row shape and also remains the table's MLE off-cube.
fn select_mid_member_trace(
    b: &mut FieldR1csBuilder,
    mid_leaf: &[LinExpr; 1 << MID_STANDARD_FOLDS],
    member_bits: &[LinExpr; MID_MEMBER_QUERY_BITS],
) -> LinExpr {
    let mut current = mid_leaf.to_vec();
    for bit in member_bits {
        current = current
            .chunks_exact(2)
            .map(|pair| pair[0].add(&mul(b, bit, &pair[0].add(&pair[1]))))
            .collect();
    }
    debug_assert_eq!(current.len(), 1);
    current.pop().expect("four folds leave one selected member")
}

/// Verify the complete algebraic linkage of one selected Phase-B query.
///
/// All dynamic inputs are preflighted before any rows are appended.  The
/// selected code and every array shape are protocol constants, so an honest
/// call always appends exactly [`ZK_PHASE_B_QUERY_TRACE_ROWS`] rows.
pub fn verify_zk_phase_b_query_trace(
    b: &mut FieldR1csBuilder,
    input: &ZkPhaseBQueryTraceInput,
) -> Result<ZkPhaseBQueryTraceOutput, ZkPhaseBQueryTraceError> {
    preflight_dynamic_inputs(input)?;
    let code = selected_code()?;
    let trace_start = b.num_wires();

    let source_folded = fold_joint_source_leaf_trace(
        b,
        code,
        &input.joint_source_leaf,
        &input.gamma,
        &input.query_bits,
        &input.source_challenges,
    )?;
    debug_assert_eq!(b.num_wires() - trace_start, ZK_PHASE_B_SOURCE_FOLD_ROWS);

    let member_bits: [LinExpr; MID_MEMBER_QUERY_BITS] =
        std::array::from_fn(|bit| input.query_bits[bit].clone());
    let selected_mid_member = select_mid_member_trace(b, &input.mid_leaf, &member_bits);
    debug_assert_eq!(
        b.num_wires() - trace_start,
        ZK_PHASE_B_SOURCE_FOLD_ROWS + ZK_PHASE_B_MID_MEMBER_SELECTOR_ROWS
    );
    pin_eq(b, &source_folded, &selected_mid_member);

    let mid_folded = mid_standard_fold4_trace(
        b,
        code,
        &input.mid_leaf,
        &input.query_bits,
        &input.mid_challenges,
    )?;

    let tail_query_bits: [LinExpr; ZK_AFFINE_TAIL_QUERY_BITS] =
        std::array::from_fn(|bit| input.query_bits[MID_LEAF_QUERY_BIT_OFFSET + bit].clone());
    let selected_tail_cell = select_affine_tail16_trace(b, &input.tail, &tail_query_bits);
    pin_eq(b, &mid_folded, &selected_tail_cell);

    debug_assert_eq!(b.num_wires() - trace_start, ZK_PHASE_B_QUERY_TRACE_ROWS);
    Ok(ZkPhaseBQueryTraceOutput {
        source_folded,
        selected_mid_member,
        mid_folded,
        selected_tail_cell,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acceptance::trace::{alloc_block, flat_of, test_support::tower_value, F128};
    use noid_core::mle::fold::fold_variable_inplace;
    use noid_core::{Block128, TowerField};
    use noid_fri_binius::zk_affine_code::AFFINE_CODE_MESSAGE_LEN;
    use noid_fri_binius::zk_capsule::ZK_AUTH_CAPSULE_GEOMETRY;
    use noid_fri_binius::zk_capsule_algebra::{
        build_joint_source_leaf, build_mid_leaf, encode_tail16, fold_joint_source_leaf,
        mid_standard_fold4,
    };
    use noid_ivc_core::field_r1cs::FieldR1cs;

    const DYNAMIC_INPUT_ROWS: usize = SOURCE_QUERY_BITS
        + JOINT_SOURCE_LEAF_SYMBOLS
        + (1 << MID_STANDARD_FOLDS)
        + TAIL_SYMBOLS
        + 1
        + SOURCE_STANDARD_FOLDS
        + MID_STANDARD_FOLDS;
    const FIXTURE_USEFUL_ROWS: usize = 1 + DYNAMIC_INPUT_ROWS + ZK_PHASE_B_QUERY_TRACE_ROWS;

    #[derive(Clone)]
    struct NativeCase {
        query: usize,
        joint_source_leaf: [Block128; JOINT_SOURCE_LEAF_SYMBOLS],
        mid_leaf: [Block128; 1 << MID_STANDARD_FOLDS],
        tail: [Block128; TAIL_SYMBOLS],
        gamma: Block128,
        source_challenges: [Block128; SOURCE_STANDARD_FOLDS],
        mid_challenges: [Block128; MID_STANDARD_FOLDS],
        source_folded: Block128,
        mid_folded: Block128,
    }

    fn elem(index: usize, domain: u128, salt: u128) -> Block128 {
        Block128::from(
            domain
                .wrapping_mul(index as u128 + 1)
                .rotate_left(((13 * index + 11) % 127) as u32)
                ^ salt.rotate_left(((7 * index + 3) % 127) as u32)
                ^ (index as u128 + 5).wrapping_mul(0x9E37_79B9_7F4A_7C15),
        )
    }

    fn message(domain: u128, salt: u128) -> [Block128; AFFINE_CODE_MESSAGE_LEN] {
        std::array::from_fn(|index| elem(index, domain, salt))
    }

    fn native_case(salt: u128, query: usize) -> NativeCase {
        assert!(query < ZK_AUTH_CAPSULE_GEOMETRY.source_leaf_count);
        let code = ZkAffineLchCode::selected().expect("selected affine code");
        let bank = message(0xB4A9, salt ^ 0x11);
        let companion = message(0xC09A, salt ^ 0x22);
        let mut gamma = elem(17, 0x6A77A, salt ^ 0x33);
        if gamma == Block128::ZERO || gamma == Block128::ONE {
            gamma += Block128::from(2u128);
        }
        let source_challenges = std::array::from_fn(|round| elem(round + 31, 0x503CE, salt ^ 0x44));
        let mid_challenges = std::array::from_fn(|round| elem(round + 47, 0xA11D, salt ^ 0x55));

        let bank_code = code.encode(&bank).expect("bank encoding");
        let companion_code = code.encode(&companion).expect("companion encoding");
        let virtual_message = bank
            .iter()
            .zip(companion.iter())
            .map(|(&bank, &companion)| bank + gamma * (bank + companion))
            .collect::<Vec<_>>();

        let mut mid_code = code.encode(&virtual_message).expect("mixed encoding");
        for (round, &challenge) in source_challenges.iter().enumerate() {
            mid_code = code
                .fold_codeword_once(&mid_code, round, challenge)
                .expect("source codeword fold");
        }
        let mut tail_code = mid_code.clone();
        for (round, &challenge) in mid_challenges.iter().enumerate() {
            tail_code = code
                .fold_codeword_once(&tail_code, SOURCE_STANDARD_FOLDS + round, challenge)
                .expect("mid codeword fold");
        }

        let mut tail_coefficients = virtual_message;
        for challenge in source_challenges.iter().chain(mid_challenges.iter()) {
            fold_variable_inplace(&mut tail_coefficients, *challenge, 0);
        }
        let tail: [Block128; TAIL_SYMBOLS] = tail_coefficients
            .try_into()
            .expect("seven message folds leave sixteen coefficients");
        assert_eq!(
            encode_tail16(&code, &tail).expect("tail encoding"),
            tail_code,
            "native folded-codeword/tail identity"
        );

        let joint_source_leaf =
            build_joint_source_leaf(&bank_code, &companion_code, query).expect("joint source leaf");
        let mid_leaf_index = query >> MID_MEMBER_QUERY_BITS;
        let mid_leaf = build_mid_leaf(&mid_code, mid_leaf_index).expect("mid leaf");
        let source_folded =
            fold_joint_source_leaf(&code, &joint_source_leaf, gamma, query, &source_challenges)
                .expect("native source fold");
        let mid_folded = mid_standard_fold4(&code, &mid_leaf, mid_leaf_index, &mid_challenges)
            .expect("native mid fold");
        assert_eq!(source_folded, mid_leaf[query & 0xf]);
        assert_eq!(mid_folded, tail_code[mid_leaf_index]);

        NativeCase {
            query,
            joint_source_leaf,
            mid_leaf,
            tail,
            gamma,
            source_challenges,
            mid_challenges,
            source_folded,
            mid_folded,
        }
    }

    fn input_wire(expression: &LinExpr) -> usize {
        assert_eq!(expression.terms.len(), 1);
        assert_eq!(expression.terms[0].1, F128::ONE);
        assert_eq!(expression.constant, F128::ZERO);
        expression.terms[0].0 as usize
    }

    fn alloc_input(b: &mut FieldR1csBuilder, case: &NativeCase) -> ZkPhaseBQueryTraceInput {
        ZkPhaseBQueryTraceInput {
            query_bits: std::array::from_fn(|bit| {
                alloc_block(b, Block128::from(((case.query >> bit) & 1) as u128))
            }),
            joint_source_leaf: std::array::from_fn(|index| {
                alloc_block(b, case.joint_source_leaf[index])
            }),
            mid_leaf: std::array::from_fn(|index| alloc_block(b, case.mid_leaf[index])),
            tail: std::array::from_fn(|index| alloc_block(b, case.tail[index])),
            gamma: alloc_block(b, case.gamma),
            source_challenges: std::array::from_fn(|index| {
                alloc_block(b, case.source_challenges[index])
            }),
            mid_challenges: std::array::from_fn(|index| alloc_block(b, case.mid_challenges[index])),
        }
    }

    struct BuiltCase {
        r1cs: FieldR1cs,
        witness: Vec<F128>,
        trace_rows: usize,
        source_folded: Block128,
        selected_mid_member: Block128,
        mid_folded: Block128,
        selected_tail_cell: Block128,
        query_wires: [usize; SOURCE_QUERY_BITS],
        source_challenge_wires: [usize; SOURCE_STANDARD_FOLDS],
        mid_challenge_wires: [usize; MID_STANDARD_FOLDS],
    }

    fn build_case(case: &NativeCase) -> Result<BuiltCase, ZkPhaseBQueryTraceError> {
        let mut b = FieldR1csBuilder::new();
        let input = alloc_input(&mut b, case);
        assert_eq!(b.num_wires(), 1 + DYNAMIC_INPUT_ROWS, "input ledger");
        let query_wires = std::array::from_fn(|index| input_wire(&input.query_bits[index]));
        let source_challenge_wires =
            std::array::from_fn(|index| input_wire(&input.source_challenges[index]));
        let mid_challenge_wires =
            std::array::from_fn(|index| input_wire(&input.mid_challenges[index]));
        let before = b.num_wires();
        let output = verify_zk_phase_b_query_trace(&mut b, &input)?;
        let trace_rows = b.num_wires() - before;
        let source_folded = tower_value(&b, &output.source_folded);
        let selected_mid_member = tower_value(&b, &output.selected_mid_member);
        let mid_folded = tower_value(&b, &output.mid_folded);
        let selected_tail_cell = tower_value(&b, &output.selected_tail_cell);
        let (r1cs, witness) = b.build();
        Ok(BuiltCase {
            r1cs,
            witness,
            trace_rows,
            source_folded,
            selected_mid_member,
            mid_folded,
            selected_tail_cell,
            query_wires,
            source_challenge_wires,
            mid_challenge_wires,
        })
    }

    #[test]
    fn phase_b_query_trace_matches_real_affine_codewords_at_varied_queries() {
        for (salt, query) in [
            (0xA11C_E001, 0usize),
            (0xA11C_E002, 1usize),
            (0xA11C_E003, 0x12a5usize),
            (0xA11C_E004, ZK_AUTH_CAPSULE_GEOMETRY.source_leaf_count - 1),
        ] {
            let native = native_case(salt, query);
            let built = build_case(&native).expect("honest trace builds");
            assert!(built.r1cs.satisfies(&built.witness));
            assert_eq!(built.source_folded, native.source_folded);
            assert_eq!(built.selected_mid_member, native.source_folded);
            assert_eq!(built.mid_folded, native.mid_folded);
            assert_eq!(built.selected_tail_cell, native.mid_folded);
        }
    }

    #[test]
    fn source_mid_and_tail_splice_tampering_all_reject() {
        let honest = native_case(0xA11C_E101, 0x12a5);
        let assert_rejected = |candidate: &NativeCase, name: &str| {
            let built = build_case(candidate).expect("tamper preserves fixed shape");
            assert_eq!(built.trace_rows, ZK_PHASE_B_QUERY_TRACE_ROWS);
            assert!(!built.r1cs.satisfies(&built.witness), "accepted {name}");
        };

        let mut source = honest.clone();
        source.joint_source_leaf[3] += Block128::ONE;
        assert_rejected(&source, "joint-source splice tamper");

        let mut mid = honest.clone();
        mid.mid_leaf[(honest.query & 0xf) ^ 1] += Block128::ONE;
        assert_rejected(&mid, "mid-leaf splice tamper");

        let mut tail = honest;
        tail.tail[7] += Block128::ONE;
        assert_rejected(&tail, "tail splice tamper");
    }

    #[test]
    fn transcript_query_and_both_challenge_families_are_live_constraints() {
        let native = native_case(0xA11C_E201, 0x0d6b);
        let built = build_case(&native).expect("honest trace");
        assert!(built.r1cs.satisfies(&built.witness));

        for (name, wire) in [
            ("low member query bit", built.query_wires[1]),
            ("mid/tail query bit", built.query_wires[8]),
            ("source challenge", built.source_challenge_wires[2]),
            ("mid challenge", built.mid_challenge_wires[3]),
        ] {
            let mut tampered = built.witness.clone();
            tampered[wire] += F128::ONE;
            assert!(!built.r1cs.satisfies(&tampered), "accepted {name} tamper");
        }
    }

    #[test]
    fn phase_b_query_trace_has_exact_ledger_and_content_invariant_shape() {
        let left = build_case(&native_case(0xA11C_E301, 0x0123)).expect("left trace");
        let right = build_case(&native_case(0xA11C_E302, 0x1e7a)).expect("right trace");
        assert!(left.r1cs.satisfies(&left.witness));
        assert!(right.r1cs.satisfies(&right.witness));

        assert_eq!(ZK_PHASE_B_SOURCE_FOLD_ROWS, 22);
        assert_eq!(ZK_PHASE_B_MID_MEMBER_SELECTOR_ROWS, 15);
        assert_eq!(ZK_PHASE_B_SOURCE_SPLICE_PIN_ROWS, 1);
        assert_eq!(ZK_PHASE_B_MID_FOLD_ROWS, 30);
        assert_eq!(ZK_PHASE_B_TAIL_SELECTOR_ROWS, 15);
        assert_eq!(ZK_PHASE_B_MID_SPLICE_PIN_ROWS, 1);
        assert_eq!(ZK_PHASE_B_QUERY_TRACE_ROWS, 84);
        assert_eq!(ZK_PHASE_B_QUERY_ACTIVE_EQUIVALENT_DELTA_ROWS, 35);
        assert_eq!(left.trace_rows, ZK_PHASE_B_QUERY_TRACE_ROWS);
        assert_eq!(right.trace_rows, ZK_PHASE_B_QUERY_TRACE_ROWS);
        assert_eq!(left.r1cs.useful_rows, FIXTURE_USEFUL_ROWS);
        assert_eq!(right.r1cs.useful_rows, FIXTURE_USEFUL_ROWS);
        assert_eq!(
            left.r1cs.structural_statement_digest(),
            right.r1cs.structural_statement_digest(),
            "Phase-B query matrix depends on values or query index"
        );
    }

    #[test]
    fn dynamic_constant_preflight_is_complete_and_atomic() {
        let native = native_case(0xA11C_E401, 0x09ab);
        let mut b = FieldR1csBuilder::new();
        let mut input = alloc_input(&mut b, &native);

        input.query_bits[4] = LinExpr::constant(flat_of(Block128::ONE));
        let before = b.num_wires();
        assert!(matches!(
            verify_zk_phase_b_query_trace(&mut b, &input),
            Err(ZkPhaseBQueryTraceError::DynamicInputIsConstant {
                input: ZkPhaseBQueryDynamicInput::QueryBit,
                index: 4,
            })
        ));
        assert_eq!(b.num_wires(), before);

        input.query_bits[4] =
            alloc_block(&mut b, Block128::from(((native.query >> 4) & 1) as u128));
        input.mid_challenges[3] = LinExpr::constant(flat_of(native.mid_challenges[3]));
        let before = b.num_wires();
        assert!(matches!(
            verify_zk_phase_b_query_trace(&mut b, &input),
            Err(ZkPhaseBQueryTraceError::DynamicInputIsConstant {
                input: ZkPhaseBQueryDynamicInput::MidChallenge,
                index: 3,
            })
        ));
        assert_eq!(b.num_wires(), before, "late preflight appended rows");
    }
}
