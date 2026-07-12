// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Exact algebraic carrier for the future owner-authorization ZK capsule.
//!
//! This module is deliberately disconnected from `owner_auth`, proof wire
//! formats, Fiat--Shamir channels, and the production authorization switch.
//! It fixes the natural low-to-high indexing and checks the algebra that a
//! later protocol wrapper must commit and reduce:
//!
//! - one 2^11-cell bank,
//! - a 512-cell Poseidon state trace in the `high = 00` slice,
//! - 512 dedicated, independently fresh PCS coins,
//! - the complete 256-cell characteristic-two Libra mask buffer,
//! - 768 further independently fresh padding cells,
//! - one degree-ten MLE-check for the reindexed Poseidon transition, and
//! - five ZK-padded terminal operand evaluations, and
//! - one post-claim linear relation containing all operand, boundary, and mask
//!   evaluations.
//!
//! This file creates no transcript randomness. Every challenge is an explicit
//! caller input. A production wrapper must commit the bank before deriving the
//! main MLE-check challenges, absorb every scalar claim in the fixed order
//! below before deriving the post-claim RLC challenge, and then discharge the
//! returned linear relation through the hiding capsule PCS.

use std::sync::OnceLock;

use noid_core::sumcheck::RoundPolynomial;
use noid_core::{Block128, TowerField};
use noid_poseidon2b::native::domain::{capacity_iv, TAG_ADDRFIX};
use noid_poseidon2b::native::permutation::{
    F_ROUNDS, MDS_FULL, MDS_PARTIAL, N_ROUNDS, P_ROUNDS, ROUND_CONSTANTS, STATE_SIZE,
};

use crate::layers::PermLayerWitness;
use crate::zk_mlecheck::{
    combine_main_and_mask_round, mlecheck_endpoint_claim, ZkMleCheckError, ZkMleCheckMaskView,
    ZkMleCheckRoundProof, ZkMleCheckVerifierState, ZK_MLECHECK_MASK_DEGREE, ZK_MLECHECK_MASK_LEN,
    ZK_MLECHECK_MASK_ROW_STRIDE, ZK_MLECHECK_N_VARS,
};

pub const ZK_AUTH_CAPSULE_BANK_VARS: usize = 11;
pub const ZK_AUTH_CAPSULE_BANK_LEN: usize = 1 << ZK_AUTH_CAPSULE_BANK_VARS;

pub const ZK_AUTH_CAPSULE_STATE_VARS: usize = 9;
pub const ZK_AUTH_CAPSULE_STATE_LEN: usize = 1 << ZK_AUTH_CAPSULE_STATE_VARS;
pub const ZK_AUTH_CAPSULE_STATE_OFFSET: usize = 0;

pub const ZK_AUTH_CAPSULE_PCS_COINS_LEN: usize = 512;
pub const ZK_AUTH_CAPSULE_PCS_COINS_OFFSET: usize =
    ZK_AUTH_CAPSULE_STATE_OFFSET + ZK_AUTH_CAPSULE_STATE_LEN;

pub const ZK_AUTH_CAPSULE_LIBRA_MASK_LEN: usize = 256;
pub const ZK_AUTH_CAPSULE_LIBRA_MASK_OFFSET: usize =
    ZK_AUTH_CAPSULE_PCS_COINS_OFFSET + ZK_AUTH_CAPSULE_PCS_COINS_LEN;

pub const ZK_AUTH_CAPSULE_REMAINING_PADDING_LEN: usize = 768;
pub const ZK_AUTH_CAPSULE_REMAINING_PADDING_OFFSET: usize =
    ZK_AUTH_CAPSULE_LIBRA_MASK_OFFSET + ZK_AUTH_CAPSULE_LIBRA_MASK_LEN;

/// Five independently fresh cells reserved for the terminal operand
/// extensions. They are outside the state, PCS-coin, and Libra-mask regions.
pub const ZK_AUTH_CAPSULE_TERMINAL_BLINDING_CELLS: usize = 5;
pub const ZK_AUTH_CAPSULE_TERMINAL_BLINDING_OFFSET: usize =
    ZK_AUTH_CAPSULE_REMAINING_PADDING_OFFSET;
/// One inactive Boolean row shared by all five operand extensions.  Each
/// extension reads a different committed blinding cell at this row.
pub const ZK_AUTH_CAPSULE_TERMINAL_BLINDING_BOOLEAN_INDEX: usize = ZK_AUTH_CAPSULE_BANK_LEN - 1;

pub const ZK_AUTH_CAPSULE_ACTIVE_ROUNDS: usize = N_ROUNDS;
pub const ZK_AUTH_CAPSULE_STORED_ROUNDS: usize = 1 << 7;
pub const ZK_AUTH_CAPSULE_MAIN_DEGREE: usize = 10;
pub const ZK_AUTH_CAPSULE_TERMINAL_OPERAND_CLAIMS: usize = 5;
pub const ZK_AUTH_CAPSULE_BOUNDARY_CLAIMS: usize = 4;
pub const ZK_AUTH_CAPSULE_MASK_CLAIMS: usize = 2;
pub const ZK_AUTH_CAPSULE_POST_CLAIMS: usize = ZK_AUTH_CAPSULE_TERMINAL_OPERAND_CLAIMS
    + ZK_AUTH_CAPSULE_BOUNDARY_CLAIMS
    + ZK_AUTH_CAPSULE_MASK_CLAIMS;

const STATE_LANE_BITS: usize = 2;
const STATE_ROUND_BITS: usize = 7;
const STATE_HIGH_BITS: usize = 2;
const STATE_ROUND_SHIFT: usize = STATE_LANE_BITS;
const STATE_HIGH_SHIFT: usize = STATE_LANE_BITS + STATE_ROUND_BITS;

const _: () = assert!(ZK_AUTH_CAPSULE_BANK_VARS == ZK_MLECHECK_N_VARS);
const _: () = assert!(ZK_AUTH_CAPSULE_LIBRA_MASK_LEN == ZK_MLECHECK_MASK_LEN);
const _: () =
    assert!(ZK_AUTH_CAPSULE_BANK_VARS == noid_fri_binius::zk_affine_code::AFFINE_CODE_MESSAGE_LOG);
const _: () =
    assert!(ZK_AUTH_CAPSULE_BANK_LEN == noid_fri_binius::zk_affine_code::AFFINE_CODE_MESSAGE_LEN);
const _: () =
    assert!(ZK_AUTH_CAPSULE_STATE_LEN == noid_fri_binius::zk_affine_code::AFFINE_STATE_LEN);
const _: () = assert!(
    ZK_AUTH_CAPSULE_PCS_COINS_OFFSET == noid_fri_binius::zk_affine_code::AFFINE_PCS_COINS_START
);
const _: () =
    assert!(ZK_AUTH_CAPSULE_PCS_COINS_LEN == noid_fri_binius::zk_affine_code::AFFINE_PCS_COINS_LEN);
const _: () = assert!(
    ZK_AUTH_CAPSULE_LIBRA_MASK_OFFSET == noid_fri_binius::zk_affine_code::AFFINE_LIBRA_MASK_START
);
const _: () = assert!(
    ZK_AUTH_CAPSULE_LIBRA_MASK_LEN == noid_fri_binius::zk_affine_code::AFFINE_LIBRA_MASK_LEN
);
const _: () = assert!(
    ZK_AUTH_CAPSULE_REMAINING_PADDING_OFFSET
        == noid_fri_binius::zk_affine_code::AFFINE_FRESH_PADDING_START
);
const _: () = assert!(
    ZK_AUTH_CAPSULE_REMAINING_PADDING_LEN
        == noid_fri_binius::zk_affine_code::AFFINE_FRESH_PADDING_LEN
);
const _: () = assert!(
    ZK_AUTH_CAPSULE_REMAINING_PADDING_OFFSET + ZK_AUTH_CAPSULE_REMAINING_PADDING_LEN
        == ZK_AUTH_CAPSULE_BANK_LEN
);
const _: () = assert!(
    ZK_AUTH_CAPSULE_TERMINAL_BLINDING_OFFSET + ZK_AUTH_CAPSULE_TERMINAL_BLINDING_CELLS
        <= ZK_AUTH_CAPSULE_BANK_LEN
);
const _: () = assert!(ZK_AUTH_CAPSULE_TERMINAL_BLINDING_BOOLEAN_INDEX >= ZK_AUTH_CAPSULE_STATE_LEN);
const _: () = assert!(STATE_SIZE == 1 << STATE_LANE_BITS);
const _: () = assert!(ZK_AUTH_CAPSULE_STORED_ROUNDS == 1 << STATE_ROUND_BITS);
const _: () = assert!(ZK_AUTH_CAPSULE_STATE_VARS == STATE_LANE_BITS + STATE_ROUND_BITS);
const _: () = assert!(ZK_AUTH_CAPSULE_BANK_VARS == ZK_AUTH_CAPSULE_STATE_VARS + STATE_HIGH_BITS);
const _: () = assert!(N_ROUNDS == 66);
const _: () = assert!(F_ROUNDS + P_ROUNDS == N_ROUNDS);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZkAuthCapsuleError {
    BankLength { expected: usize, actual: usize },
    MleShape { expected: usize, actual: usize },
    StateRoundOutOfRange { round: usize },
    CurrentRoundOutOfRange { round: usize },
    StateLaneOutOfRange { lane: usize },
    TraceRowCount { expected: usize, actual: usize },
    MainRelationMismatch { round: usize, lane: usize },
    BoundaryMismatch { claim_index: usize },
    TooManyPriorChallenges { max: usize, actual: usize },
    PolynomialDegreeOverflow { max: usize, actual: usize },
    MainRoundEndpointMismatch { round: usize },
    MainTerminalMismatch,
    ZeroTerminalBlindingWeight,
    ZeroMaskBatchChallenge,
    ZeroPostClaimChallenge,
    ZkMleCheck(ZkMleCheckError),
}

impl From<ZkMleCheckError> for ZkAuthCapsuleError {
    fn from(value: ZkMleCheckError) -> Self {
        Self::ZkMleCheck(value)
    }
}

/// Borrowed, exact-size view of the complete owner-authorization bank.
///
/// Freshness and independence of the three random regions are protocol
/// preconditions. This view checks their positions and lengths; it neither
/// generates nor clones randomness.
#[derive(Clone, Copy)]
pub struct ZkAuthCapsuleBankView<'a> {
    cells: &'a [Block128],
}

impl<'a> ZkAuthCapsuleBankView<'a> {
    pub fn checked(cells: &'a [Block128]) -> Result<Self, ZkAuthCapsuleError> {
        if cells.len() != ZK_AUTH_CAPSULE_BANK_LEN {
            return Err(ZkAuthCapsuleError::BankLength {
                expected: ZK_AUTH_CAPSULE_BANK_LEN,
                actual: cells.len(),
            });
        }
        Ok(Self { cells })
    }

    pub fn cells(&self) -> &'a [Block128] {
        self.cells
    }

    pub fn state(&self) -> &'a [Block128] {
        &self.cells
            [ZK_AUTH_CAPSULE_STATE_OFFSET..ZK_AUTH_CAPSULE_STATE_OFFSET + ZK_AUTH_CAPSULE_STATE_LEN]
    }

    pub fn dedicated_pcs_coins(&self) -> &'a [Block128] {
        &self.cells[ZK_AUTH_CAPSULE_PCS_COINS_OFFSET
            ..ZK_AUTH_CAPSULE_PCS_COINS_OFFSET + ZK_AUTH_CAPSULE_PCS_COINS_LEN]
    }

    pub fn libra_mask(&self) -> &'a [Block128] {
        &self.cells[ZK_AUTH_CAPSULE_LIBRA_MASK_OFFSET
            ..ZK_AUTH_CAPSULE_LIBRA_MASK_OFFSET + ZK_AUTH_CAPSULE_LIBRA_MASK_LEN]
    }

    pub fn remaining_padding(&self) -> &'a [Block128] {
        &self.cells[ZK_AUTH_CAPSULE_REMAINING_PADDING_OFFSET..]
    }

    pub fn libra_mask_view(&self) -> Result<ZkMleCheckMaskView<'a>, ZkAuthCapsuleError> {
        Ok(ZkMleCheckMaskView::checked(self.libra_mask())?)
    }
}

/// Zeroizing owner of the 512-cell state table used by the disconnected
/// carrier. Rows `0..=66` contain the Poseidon trace; the unused rows remain
/// zero. The later bank owner is responsible for zeroizing the complete bank.
#[derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct ZkAuthCapsuleStateTable {
    cells: Box<[Block128; ZK_AUTH_CAPSULE_STATE_LEN]>,
}

impl ZkAuthCapsuleStateTable {
    pub fn from_permutation_witness(
        witness: &PermLayerWitness,
    ) -> Result<Self, ZkAuthCapsuleError> {
        if witness.state.len() != N_ROUNDS + 1 {
            return Err(ZkAuthCapsuleError::TraceRowCount {
                expected: N_ROUNDS + 1,
                actual: witness.state.len(),
            });
        }
        let mut cells = Box::new([Block128::ZERO; ZK_AUTH_CAPSULE_STATE_LEN]);
        for round in 0..=N_ROUNDS {
            for lane in 0..STATE_SIZE {
                cells[state_cell_index(round, lane)?] = witness.state[round][lane];
            }
        }
        Ok(Self { cells })
    }

    pub(crate) fn cells(&self) -> &[Block128; ZK_AUTH_CAPSULE_STATE_LEN] {
        &self.cells
    }

    /// Fixed public geometry without exposing any state cell.
    pub const fn len(&self) -> usize {
        ZK_AUTH_CAPSULE_STATE_LEN
    }

    pub const fn is_empty(&self) -> bool {
        false
    }
}

/// Natural low-to-high state address: lane bits 0..1, then round bits 2..8.
pub fn state_cell_index(round: usize, lane: usize) -> Result<usize, ZkAuthCapsuleError> {
    if round >= ZK_AUTH_CAPSULE_STORED_ROUNDS {
        return Err(ZkAuthCapsuleError::StateRoundOutOfRange { round });
    }
    if lane >= STATE_SIZE {
        return Err(ZkAuthCapsuleError::StateLaneOutOfRange { lane });
    }
    Ok((round << STATE_ROUND_SHIFT) | lane)
}

/// Address of `state[round, lane]` for an actual current Poseidon round.
pub fn current_state_cell_index(round: usize, lane: usize) -> Result<usize, ZkAuthCapsuleError> {
    if round >= ZK_AUTH_CAPSULE_ACTIVE_ROUNDS {
        return Err(ZkAuthCapsuleError::CurrentRoundOutOfRange { round });
    }
    state_cell_index(round, lane)
}

/// Nonwrapping address of `state[round + 1, lane]`.
///
/// In particular, round 65 maps to row 66. Round 127 can never wrap to row
/// zero because only actual current rounds `0..65` are accepted.
pub fn next_state_cell_index(round: usize, lane: usize) -> Result<usize, ZkAuthCapsuleError> {
    if round >= ZK_AUTH_CAPSULE_ACTIVE_ROUNDS {
        return Err(ZkAuthCapsuleError::CurrentRoundOutOfRange { round });
    }
    state_cell_index(round + 1, lane)
}

#[inline]
fn state_round_from_boolean_index(index: usize) -> usize {
    (index >> STATE_ROUND_SHIFT) & (ZK_AUTH_CAPSULE_STORED_ROUNDS - 1)
}

#[inline]
fn state_lane_from_boolean_index(index: usize) -> usize {
    index & (STATE_SIZE - 1)
}

#[inline]
fn state_high_from_boolean_index(index: usize) -> usize {
    index >> STATE_HIGH_SHIFT
}

#[inline]
fn active_state_selector_at_boolean_index(index: usize) -> bool {
    state_high_from_boolean_index(index) == 0
        && state_round_from_boolean_index(index) < ZK_AUTH_CAPSULE_ACTIVE_ROUNDS
}

/// Fold variable zero (the lowest-index variable) from an evaluation table.
pub fn fold_lowest_variable_in_place(
    values: &mut Vec<Block128>,
    challenge: Block128,
) -> Result<(), ZkAuthCapsuleError> {
    if values.len() < 2 || !values.len().is_power_of_two() {
        return Err(ZkAuthCapsuleError::MleShape {
            expected: values.len().next_power_of_two().max(2),
            actual: values.len(),
        });
    }
    let half = values.len() / 2;
    for low_index in 0..half {
        let at_zero = values[2 * low_index];
        let at_one = values[2 * low_index + 1];
        values[low_index] = at_zero + challenge * (at_one - at_zero);
    }
    values.truncate(half);
    Ok(())
}

/// Evaluate a natural-order multilinear table with variables supplied
/// low-to-high. Variable zero is folded first from adjacent pairs.
pub fn evaluate_mle_low_to_high(
    values: &[Block128],
    point: &[Block128],
) -> Result<Block128, ZkAuthCapsuleError> {
    let expected = 1usize.checked_shl(point.len() as u32).unwrap_or(usize::MAX);
    if values.len() != expected {
        return Err(ZkAuthCapsuleError::MleShape {
            expected,
            actual: values.len(),
        });
    }
    let mut folded = values.to_vec();
    for &challenge in point {
        fold_lowest_variable_in_place(&mut folded, challenge)?;
    }
    debug_assert_eq!(folded.len(), 1);
    Ok(folded[0])
}

/// Equality-tensor weights in natural low-to-high Boolean index order.
pub fn mle_weights_low_to_high(point: &[Block128]) -> Vec<Block128> {
    let mut weights = vec![Block128::ONE];
    for &coordinate in point {
        let old_len = weights.len();
        weights.resize(old_len * 2, Block128::ZERO);
        for index in 0..old_len {
            let prior = weights[index];
            weights[index] = prior * (Block128::ONE - coordinate);
            weights[old_len + index] = prior * coordinate;
        }
    }
    weights
}

#[inline]
fn is_partial_round(round: usize) -> bool {
    (F_ROUNDS / 2..F_ROUNDS / 2 + P_ROUNDS).contains(&round)
}

#[inline]
fn sigma_at(round: usize, lane: usize) -> Block128 {
    if is_partial_round(round) && lane != 0 {
        Block128::ZERO
    } else {
        Block128::ONE
    }
}

#[inline]
fn round_constant_at(round: usize, lane: usize) -> Block128 {
    if is_partial_round(round) && lane != 0 {
        Block128::ZERO
    } else {
        Block128::from(ROUND_CONSTANTS[lane][round])
    }
}

#[inline]
fn mds_at(round: usize, output_lane: usize, input_lane: usize) -> Block128 {
    if is_partial_round(round) {
        Block128::from(MDS_PARTIAL[output_lane][input_lane])
    } else {
        Block128::from(MDS_FULL[output_lane][input_lane])
    }
}

#[inline]
fn pow7(value: Block128) -> Block128 {
    let value2 = value * value;
    let value4 = value2 * value2;
    value4 * value2 * value
}

#[inline]
fn poseidon_pi(round: usize, lane: usize, state: Block128) -> Block128 {
    let sigma = sigma_at(round, lane);
    let with_rc = state + round_constant_at(round, lane);
    sigma * pow7(with_rc) + (Block128::ONE + sigma) * state
}

/// Check all 66 x 4 Boolean transition equations with nonwrapping next-row
/// addressing. Padded rounds and non-fundamental high slices are selected out.
pub fn validate_auth_main_relation(
    bank: ZkAuthCapsuleBankView<'_>,
) -> Result<(), ZkAuthCapsuleError> {
    for round in 0..ZK_AUTH_CAPSULE_ACTIVE_ROUNDS {
        for output_lane in 0..STATE_SIZE {
            let mut relation = bank.state()[next_state_cell_index(round, output_lane)?];
            for input_lane in 0..STATE_SIZE {
                let state = bank.state()[current_state_cell_index(round, input_lane)?];
                relation +=
                    mds_at(round, output_lane, input_lane) * poseidon_pi(round, input_lane, state);
            }
            if relation != Block128::ZERO {
                return Err(ZkAuthCapsuleError::MainRelationMismatch {
                    round,
                    lane: output_lane,
                });
            }
        }
    }
    Ok(())
}

#[derive(Clone)]
struct MainTables {
    active: Vec<Block128>,
    increment: Vec<Block128>,
    lane: [Vec<Block128>; STATE_SIZE],
    mds: [Vec<Block128>; STATE_SIZE],
    sigma: [Vec<Block128>; STATE_SIZE],
    rc: [Vec<Block128>; STATE_SIZE],
}

impl MainTables {
    fn build(bank: ZkAuthCapsuleBankView<'_>) -> Self {
        let mut active = vec![Block128::ZERO; ZK_AUTH_CAPSULE_BANK_LEN];
        let mut increment = vec![Block128::ZERO; ZK_AUTH_CAPSULE_BANK_LEN];
        let mut lane: [Vec<Block128>; STATE_SIZE] =
            std::array::from_fn(|_| vec![Block128::ZERO; ZK_AUTH_CAPSULE_BANK_LEN]);
        let mut mds: [Vec<Block128>; STATE_SIZE] =
            std::array::from_fn(|_| vec![Block128::ZERO; ZK_AUTH_CAPSULE_BANK_LEN]);
        let mut sigma: [Vec<Block128>; STATE_SIZE] =
            std::array::from_fn(|_| vec![Block128::ZERO; ZK_AUTH_CAPSULE_BANK_LEN]);
        let mut rc: [Vec<Block128>; STATE_SIZE] =
            std::array::from_fn(|_| vec![Block128::ZERO; ZK_AUTH_CAPSULE_BANK_LEN]);

        for index in 0..ZK_AUTH_CAPSULE_BANK_LEN {
            if !active_state_selector_at_boolean_index(index) {
                continue;
            }
            let round = state_round_from_boolean_index(index);
            let output_lane = state_lane_from_boolean_index(index);
            active[index] = Block128::ONE;
            increment[index] = bank.state()
                [next_state_cell_index(round, output_lane).expect("active index is in range")];
            for input_lane in 0..STATE_SIZE {
                lane[input_lane][index] = bank.state()[current_state_cell_index(round, input_lane)
                    .expect("active index is in range")];
                mds[input_lane][index] = mds_at(round, output_lane, input_lane);
                sigma[input_lane][index] = sigma_at(round, input_lane);
                rc[input_lane][index] = round_constant_at(round, input_lane);
            }
        }

        // ZK dummy row. The active selector is zero here, so these values do
        // not change any Boolean transition equation. At the terminal field
        // point they give the five public operand evaluations independent,
        // fresh one-time pads while keeping them bound to the same bank.
        increment[ZK_AUTH_CAPSULE_TERMINAL_BLINDING_BOOLEAN_INDEX] =
            bank.cells()[ZK_AUTH_CAPSULE_TERMINAL_BLINDING_OFFSET];
        for input_lane in 0..STATE_SIZE {
            lane[input_lane][ZK_AUTH_CAPSULE_TERMINAL_BLINDING_BOOLEAN_INDEX] =
                bank.cells()[ZK_AUTH_CAPSULE_TERMINAL_BLINDING_OFFSET + 1 + input_lane];
        }

        Self {
            active,
            increment,
            lane,
            mds,
            sigma,
            rc,
        }
    }

    fn terminal_value(
        &self,
        point: &[Block128; ZK_AUTH_CAPSULE_BANK_VARS],
    ) -> Result<Block128, ZkAuthCapsuleError> {
        let active = evaluate_mle_low_to_high(&self.active, point)?;
        let increment = evaluate_mle_low_to_high(&self.increment, point)?;
        let mut q = increment;
        for input_lane in 0..STATE_SIZE {
            let state = evaluate_mle_low_to_high(&self.lane[input_lane], point)?;
            let mds = evaluate_mle_low_to_high(&self.mds[input_lane], point)?;
            let sigma = evaluate_mle_low_to_high(&self.sigma[input_lane], point)?;
            let rc = evaluate_mle_low_to_high(&self.rc[input_lane], point)?;
            q += mds * (sigma * pow7(state + rc) + (Block128::ONE + sigma) * state);
        }
        Ok(active * q)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthCapsuleTerminalOperandClaims {
    pub increment: Block128,
    pub lane: [Block128; STATE_SIZE],
}

impl AuthCapsuleTerminalOperandClaims {
    pub fn ordered(self) -> [Block128; ZK_AUTH_CAPSULE_TERMINAL_OPERAND_CLAIMS] {
        [
            self.increment,
            self.lane[0],
            self.lane[1],
            self.lane[2],
            self.lane[3],
        ]
    }
}

/// Exact rank certificate for the five terminal one-time pads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthCapsuleTerminalBlindingRankCertificate {
    pub boolean_index: usize,
    pub common_coefficient: Block128,
    pub blinding_cell_indices: [usize; ZK_AUTH_CAPSULE_TERMINAL_BLINDING_CELLS],
    pub certified_rank: usize,
}

/// Evaluate the multilinear basis polynomial for one Boolean index.
pub fn mle_basis_weight_at_boolean_index(
    point: &[Block128; ZK_AUTH_CAPSULE_BANK_VARS],
    boolean_index: usize,
) -> Block128 {
    debug_assert!(boolean_index < ZK_AUTH_CAPSULE_BANK_LEN);
    point
        .iter()
        .enumerate()
        .fold(Block128::ONE, |coefficient, (variable, &coordinate)| {
            if (boolean_index >> variable) & 1 == 1 {
                coefficient * coordinate
            } else {
                coefficient * (Block128::ONE - coordinate)
            }
        })
}

/// Certify the diagonal `5 x 5` random submatrix in the terminal operand
/// observations. A zero basis weight is an overwhelmingly rare transcript
/// degeneracy; production proving retries from a fresh commitment and
/// verification rejects it.
pub fn certify_terminal_blinding_rank(
    point: &[Block128; ZK_AUTH_CAPSULE_BANK_VARS],
) -> Result<AuthCapsuleTerminalBlindingRankCertificate, ZkAuthCapsuleError> {
    let common_coefficient =
        mle_basis_weight_at_boolean_index(point, ZK_AUTH_CAPSULE_TERMINAL_BLINDING_BOOLEAN_INDEX);
    if common_coefficient == Block128::ZERO {
        return Err(ZkAuthCapsuleError::ZeroTerminalBlindingWeight);
    }
    Ok(AuthCapsuleTerminalBlindingRankCertificate {
        boolean_index: ZK_AUTH_CAPSULE_TERMINAL_BLINDING_BOOLEAN_INDEX,
        common_coefficient,
        blinding_cell_indices: std::array::from_fn(|claim| {
            ZK_AUTH_CAPSULE_TERMINAL_BLINDING_OFFSET + claim
        }),
        certified_rank: ZK_AUTH_CAPSULE_TERMINAL_BLINDING_CELLS,
    })
}

/// Weights for the ZK-padded
/// `[state_inc, state_lane_0, ..., state_lane_3]` operand extensions at one
/// low-to-high terminal point. Active rows carry the real transition operands;
/// one inactive row contributes five distinct fresh committed pads.
pub fn terminal_operand_functional_weights(
    point: &[Block128; ZK_AUTH_CAPSULE_BANK_VARS],
) -> [Vec<Block128>; ZK_AUTH_CAPSULE_TERMINAL_OPERAND_CLAIMS] {
    let eq = mle_weights_low_to_high(point);
    let mut weights: [Vec<Block128>; ZK_AUTH_CAPSULE_TERMINAL_OPERAND_CLAIMS] =
        std::array::from_fn(|_| vec![Block128::ZERO; ZK_AUTH_CAPSULE_BANK_LEN]);

    for (boolean_index, &coefficient) in eq.iter().enumerate() {
        if !active_state_selector_at_boolean_index(boolean_index) {
            continue;
        }
        let round = state_round_from_boolean_index(boolean_index);
        let output_lane = state_lane_from_boolean_index(boolean_index);
        let next = next_state_cell_index(round, output_lane).expect("active round is in range");
        weights[0][next] += coefficient;
        for input_lane in 0..STATE_SIZE {
            let current =
                current_state_cell_index(round, input_lane).expect("active round is in range");
            weights[1 + input_lane][current] += coefficient;
        }
    }
    let blinding_coefficient = eq[ZK_AUTH_CAPSULE_TERMINAL_BLINDING_BOOLEAN_INDEX];
    for (claim, weights_for_claim) in weights.iter_mut().enumerate() {
        weights_for_claim[ZK_AUTH_CAPSULE_TERMINAL_BLINDING_OFFSET + claim] += blinding_coefficient;
    }
    weights
}

#[inline]
fn inner_product(lhs: &[Block128], rhs: &[Block128]) -> Block128 {
    debug_assert_eq!(lhs.len(), rhs.len());
    lhs.iter()
        .zip(rhs)
        .fold(Block128::ZERO, |acc, (&a, &b)| acc + a * b)
}

pub fn compute_terminal_operand_claims(
    bank: ZkAuthCapsuleBankView<'_>,
    point: &[Block128; ZK_AUTH_CAPSULE_BANK_VARS],
) -> AuthCapsuleTerminalOperandClaims {
    let weights = terminal_operand_functional_weights(point);
    AuthCapsuleTerminalOperandClaims {
        increment: inner_product(bank.cells(), &weights[0]),
        lane: std::array::from_fn(|input_lane| {
            inner_product(bank.cells(), &weights[1 + input_lane])
        }),
    }
}

/// Evaluate the degree-ten main polynomial at its terminal point from exactly
/// the five ZK-padded operand claims that the post-claim relation later binds
/// to the bank.
pub fn evaluate_auth_main_terminal_from_claims(
    point: &[Block128; ZK_AUTH_CAPSULE_BANK_VARS],
    claims: AuthCapsuleTerminalOperandClaims,
) -> Result<Block128, ZkAuthCapsuleError> {
    let mut active = vec![Block128::ZERO; ZK_AUTH_CAPSULE_BANK_LEN];
    let mut mds: [Vec<Block128>; STATE_SIZE] =
        std::array::from_fn(|_| vec![Block128::ZERO; ZK_AUTH_CAPSULE_BANK_LEN]);
    let mut sigma: [Vec<Block128>; STATE_SIZE] =
        std::array::from_fn(|_| vec![Block128::ZERO; ZK_AUTH_CAPSULE_BANK_LEN]);
    let mut rc: [Vec<Block128>; STATE_SIZE] =
        std::array::from_fn(|_| vec![Block128::ZERO; ZK_AUTH_CAPSULE_BANK_LEN]);

    for index in 0..ZK_AUTH_CAPSULE_BANK_LEN {
        if !active_state_selector_at_boolean_index(index) {
            continue;
        }
        let round = state_round_from_boolean_index(index);
        let output_lane = state_lane_from_boolean_index(index);
        active[index] = Block128::ONE;
        for input_lane in 0..STATE_SIZE {
            mds[input_lane][index] = mds_at(round, output_lane, input_lane);
            sigma[input_lane][index] = sigma_at(round, input_lane);
            rc[input_lane][index] = round_constant_at(round, input_lane);
        }
    }

    let active_at_point = evaluate_mle_low_to_high(&active, point)?;
    let mut q = claims.increment;
    for input_lane in 0..STATE_SIZE {
        let mds_at_point = evaluate_mle_low_to_high(&mds[input_lane], point)?;
        let sigma_at_point = evaluate_mle_low_to_high(&sigma[input_lane], point)?;
        let rc_at_point = evaluate_mle_low_to_high(&rc[input_lane], point)?;
        let state = claims.lane[input_lane];
        q += mds_at_point
            * (sigma_at_point * pow7(state + rc_at_point)
                + (Block128::ONE + sigma_at_point) * state);
    }
    Ok(active_at_point * q)
}

#[derive(Clone, Copy)]
struct FixedPolynomial {
    coeffs: [Block128; ZK_AUTH_CAPSULE_MAIN_DEGREE + 1],
    degree: usize,
}

impl FixedPolynomial {
    fn zero() -> Self {
        Self {
            coeffs: [Block128::ZERO; ZK_AUTH_CAPSULE_MAIN_DEGREE + 1],
            degree: 0,
        }
    }

    fn one() -> Self {
        let mut result = Self::zero();
        result.coeffs[0] = Block128::ONE;
        result
    }

    fn affine(at_zero: Block128, at_one: Block128) -> Self {
        let mut result = Self::zero();
        result.coeffs[0] = at_zero;
        result.coeffs[1] = at_one - at_zero;
        result.degree = 1;
        result
    }

    fn add_assign(&mut self, rhs: &Self) {
        for index in 0..=rhs.degree {
            self.coeffs[index] += rhs.coeffs[index];
        }
        self.degree = self.degree.max(rhs.degree);
    }

    fn add(mut self, rhs: &Self) -> Self {
        self.add_assign(rhs);
        self
    }

    fn scale(mut self, scalar: Block128) -> Self {
        for coefficient in &mut self.coeffs[..=self.degree] {
            *coefficient *= scalar;
        }
        self
    }

    fn mul(self, rhs: Self) -> Result<Self, ZkAuthCapsuleError> {
        let degree = self.degree + rhs.degree;
        if degree > ZK_AUTH_CAPSULE_MAIN_DEGREE {
            return Err(ZkAuthCapsuleError::PolynomialDegreeOverflow {
                max: ZK_AUTH_CAPSULE_MAIN_DEGREE,
                actual: degree,
            });
        }
        let mut result = Self::zero();
        result.degree = degree;
        for left in 0..=self.degree {
            for right in 0..=rhs.degree {
                result.coeffs[left + right] += self.coeffs[left] * rhs.coeffs[right];
            }
        }
        Ok(result)
    }

    fn pow7(self) -> Result<Self, ZkAuthCapsuleError> {
        let square = self.mul(self)?;
        let fourth = square.mul(square)?;
        fourth.mul(square)?.mul(self)
    }

    fn into_round_polynomial(self) -> RoundPolynomial<Block128> {
        // The ZK MLE-check combines every main round with an exact degree-ten
        // mask round, so retain all eleven coefficient positions.
        RoundPolynomial::from_coeffs(self.coeffs.to_vec())
    }
}

#[derive(Clone)]
struct RestrictedMainTables {
    active: Vec<Block128>,
    increment: Vec<Block128>,
    lane: [Vec<Block128>; STATE_SIZE],
    mds: [Vec<Block128>; STATE_SIZE],
    sigma: [Vec<Block128>; STATE_SIZE],
    rc: [Vec<Block128>; STATE_SIZE],
}

fn restrict_high_variables(table: &[Block128], prior_challenges: &[Block128]) -> Vec<Block128> {
    let mut restricted = table.to_vec();
    for &challenge in prior_challenges {
        let half = restricted.len() / 2;
        for index in 0..half {
            let at_zero = restricted[index];
            let at_one = restricted[index + half];
            restricted[index] = at_zero + challenge * (at_one - at_zero);
        }
        restricted.truncate(half);
    }
    restricted
}

impl RestrictedMainTables {
    fn new(full: &MainTables, prior_challenges: &[Block128]) -> Self {
        Self {
            active: restrict_high_variables(&full.active, prior_challenges),
            increment: restrict_high_variables(&full.increment, prior_challenges),
            lane: std::array::from_fn(|input_lane| {
                restrict_high_variables(&full.lane[input_lane], prior_challenges)
            }),
            mds: std::array::from_fn(|input_lane| {
                restrict_high_variables(&full.mds[input_lane], prior_challenges)
            }),
            sigma: std::array::from_fn(|input_lane| {
                restrict_high_variables(&full.sigma[input_lane], prior_challenges)
            }),
            rc: std::array::from_fn(|input_lane| {
                restrict_high_variables(&full.rc[input_lane], prior_challenges)
            }),
        }
    }
}

fn endpoint_polynomial(table: &[Block128], lower_index: usize, half: usize) -> FixedPolynomial {
    FixedPolynomial::affine(table[lower_index], table[lower_index + half])
}

fn boolean_eq_weight(point: &[Block128], boolean_index: usize) -> Block128 {
    point
        .iter()
        .enumerate()
        .fold(Block128::ONE, |weight, (variable, &coordinate)| {
            if ((boolean_index >> variable) & 1) == 0 {
                weight * (Block128::ONE - coordinate)
            } else {
                weight * coordinate
            }
        })
}

fn auth_main_round_from_tables(
    full: &MainTables,
    input_point: &[Block128; ZK_AUTH_CAPSULE_BANK_VARS],
    prior_challenges: &[Block128],
) -> Result<RoundPolynomial<Block128>, ZkAuthCapsuleError> {
    if prior_challenges.len() >= ZK_AUTH_CAPSULE_BANK_VARS {
        return Err(ZkAuthCapsuleError::TooManyPriorChallenges {
            max: ZK_AUTH_CAPSULE_BANK_VARS - 1,
            actual: prior_challenges.len(),
        });
    }
    let current_var = ZK_AUTH_CAPSULE_BANK_VARS - 1 - prior_challenges.len();
    let restricted = RestrictedMainTables::new(full, prior_challenges);
    let half = 1usize << current_var;
    debug_assert_eq!(restricted.active.len(), 2 * half);

    let mut round = FixedPolynomial::zero();
    for lower_index in 0..half {
        let active = endpoint_polynomial(&restricted.active, lower_index, half);
        let mut q = endpoint_polynomial(&restricted.increment, lower_index, half);
        for input_lane in 0..STATE_SIZE {
            let state = endpoint_polynomial(&restricted.lane[input_lane], lower_index, half);
            let mds = endpoint_polynomial(&restricted.mds[input_lane], lower_index, half);
            let sigma = endpoint_polynomial(&restricted.sigma[input_lane], lower_index, half);
            let rc = endpoint_polynomial(&restricted.rc[input_lane], lower_index, half);
            let with_rc = state.add(&rc);
            let sboxed = sigma.mul(with_rc.pow7()?)?;
            let pass_through = FixedPolynomial::one().add(&sigma).mul(state)?;
            let pi = sboxed.add(&pass_through);
            q.add_assign(&mds.mul(pi)?);
        }
        let weighted = active
            .mul(q)?
            .scale(boolean_eq_weight(&input_point[..current_var], lower_index));
        round.add_assign(&weighted);
    }
    Ok(round.into_round_polynomial())
}

/// Exact degree-ten main round in high-to-low MLE-check order.
/// `prior_challenges[0]` fixes variable ten, then variable nine, and so on.
pub fn auth_main_round_polynomial(
    bank: ZkAuthCapsuleBankView<'_>,
    input_point: &[Block128; ZK_AUTH_CAPSULE_BANK_VARS],
    prior_challenges: &[Block128],
) -> Result<RoundPolynomial<Block128>, ZkAuthCapsuleError> {
    let tables = MainTables::build(bank);
    auth_main_round_from_tables(&tables, input_point, prior_challenges)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthCapsuleBoundaryClaimKind {
    InitialIvLane2,
    InitialIvLane3,
    OutputAddressLane0,
    OutputAddressLane1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthCapsuleLinearTerm {
    pub bank_index: usize,
    pub coefficient: Block128,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthCapsuleSparseBoundaryClaim {
    pub kind: AuthCapsuleBoundaryClaimKind,
    pub terms: Vec<AuthCapsuleLinearTerm>,
    pub expected: Block128,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthCapsuleBoundaryPublic {
    pub capacity_iv: [Block128; 2],
    pub expected_address: [Block128; 2],
}

impl AuthCapsuleBoundaryPublic {
    pub fn canonical(expected_address: [Block128; 2]) -> Self {
        Self {
            capacity_iv: capacity_iv(TAG_ADDRFIX),
            expected_address,
        }
    }
}

fn mds_full_inverse() -> &'static [[Block128; STATE_SIZE]; STATE_SIZE] {
    static INVERSE: OnceLock<[[Block128; STATE_SIZE]; STATE_SIZE]> = OnceLock::new();
    INVERSE.get_or_init(|| {
        let mut augmented = [[Block128::ZERO; STATE_SIZE * 2]; STATE_SIZE];
        for row in 0..STATE_SIZE {
            for column in 0..STATE_SIZE {
                augmented[row][column] = Block128::from(MDS_FULL[row][column]);
            }
            augmented[row][STATE_SIZE + row] = Block128::ONE;
        }
        for column in 0..STATE_SIZE {
            let pivot = (column..STATE_SIZE)
                .find(|&row| augmented[row][column] != Block128::ZERO)
                .expect("Poseidon MDS_FULL is invertible");
            if pivot != column {
                augmented.swap(pivot, column);
            }
            let inverse = augmented[column][column].invert();
            for entry in &mut augmented[column] {
                *entry *= inverse;
            }
            for row in 0..STATE_SIZE {
                if row == column {
                    continue;
                }
                let factor = augmented[row][column];
                let pivot_row = augmented[column];
                for (entry, &pivot_entry) in augmented[row].iter_mut().zip(&pivot_row) {
                    *entry += factor * pivot_entry;
                }
            }
        }
        std::array::from_fn(|row| std::array::from_fn(|column| augmented[row][STATE_SIZE + column]))
    })
}

pub fn sparse_boundary_claims(
    public: AuthCapsuleBoundaryPublic,
) -> [AuthCapsuleSparseBoundaryClaim; ZK_AUTH_CAPSULE_BOUNDARY_CLAIMS] {
    let inverse = mds_full_inverse();
    let initial = |pre_lane: usize, kind, expected| AuthCapsuleSparseBoundaryClaim {
        kind,
        terms: (0..STATE_SIZE)
            .map(|post_lane| AuthCapsuleLinearTerm {
                bank_index: state_cell_index(0, post_lane).expect("fixed row and lane"),
                coefficient: inverse[pre_lane][post_lane],
            })
            .collect(),
        expected,
    };
    let output = |lane: usize, kind, expected| AuthCapsuleSparseBoundaryClaim {
        kind,
        terms: vec![AuthCapsuleLinearTerm {
            bank_index: state_cell_index(N_ROUNDS, lane).expect("fixed row and lane"),
            coefficient: Block128::ONE,
        }],
        expected,
    };
    [
        initial(
            2,
            AuthCapsuleBoundaryClaimKind::InitialIvLane2,
            public.capacity_iv[0],
        ),
        initial(
            3,
            AuthCapsuleBoundaryClaimKind::InitialIvLane3,
            public.capacity_iv[1],
        ),
        output(
            0,
            AuthCapsuleBoundaryClaimKind::OutputAddressLane0,
            public.expected_address[0],
        ),
        output(
            1,
            AuthCapsuleBoundaryClaimKind::OutputAddressLane1,
            public.expected_address[1],
        ),
    ]
}

fn evaluate_sparse_claim(
    bank: ZkAuthCapsuleBankView<'_>,
    claim: &AuthCapsuleSparseBoundaryClaim,
) -> Block128 {
    claim.terms.iter().fold(Block128::ZERO, |acc, term| {
        acc + term.coefficient * bank.cells()[term.bank_index]
    })
}

pub fn validate_sparse_boundary(
    bank: ZkAuthCapsuleBankView<'_>,
    public: AuthCapsuleBoundaryPublic,
) -> Result<(), ZkAuthCapsuleError> {
    for (claim_index, claim) in sparse_boundary_claims(public).iter().enumerate() {
        if evaluate_sparse_claim(bank, claim) != claim.expected {
            return Err(ZkAuthCapsuleError::BoundaryMismatch { claim_index });
        }
    }
    Ok(())
}

/// Linear bank weights for the Libra mask's Boolean-table MLE at the input
/// point. Padded row/stride cells have coefficient zero but remain committed.
pub fn libra_mask_mle_functional_weights(
    input_point: &[Block128; ZK_AUTH_CAPSULE_BANK_VARS],
) -> Vec<Block128> {
    let mut weights = vec![Block128::ZERO; ZK_AUTH_CAPSULE_BANK_LEN];
    for (variable, &coordinate) in input_point.iter().enumerate() {
        let row = ZK_AUTH_CAPSULE_LIBRA_MASK_OFFSET + variable * ZK_MLECHECK_MASK_ROW_STRIDE;
        weights[row] += Block128::ONE;
        for power in 1..=ZK_MLECHECK_MASK_DEGREE {
            weights[row + power] += coordinate;
        }
    }
    weights
}

/// Linear bank weights for `g(r) = sum_i g_i(r_i)` at the terminal point.
pub fn libra_mask_final_functional_weights(
    terminal_point: &[Block128; ZK_AUTH_CAPSULE_BANK_VARS],
) -> Vec<Block128> {
    let mut weights = vec![Block128::ZERO; ZK_AUTH_CAPSULE_BANK_LEN];
    for (variable, &coordinate) in terminal_point.iter().enumerate() {
        let row = ZK_AUTH_CAPSULE_LIBRA_MASK_OFFSET + variable * ZK_MLECHECK_MASK_ROW_STRIDE;
        let mut power = Block128::ONE;
        for exponent in 0..=ZK_MLECHECK_MASK_DEGREE {
            weights[row + exponent] += power;
            power *= coordinate;
        }
    }
    weights
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthCapsulePostClaims {
    pub terminal_operands: AuthCapsuleTerminalOperandClaims,
    pub mask_mle_at_input: Block128,
    pub mask_final_at_terminal: Block128,
}

impl AuthCapsulePostClaims {
    /// Fixed RLC order. A protocol wrapper must absorb these five prover
    /// claims and two mask claims, together with the already-bound public
    /// boundary statement, before sampling the RLC challenge.
    pub fn ordered_with_boundary(
        self,
        boundary: AuthCapsuleBoundaryPublic,
    ) -> [Block128; ZK_AUTH_CAPSULE_POST_CLAIMS] {
        let terminal = self.terminal_operands.ordered();
        [
            terminal[0],
            terminal[1],
            terminal[2],
            terminal[3],
            terminal[4],
            boundary.capacity_iv[0],
            boundary.capacity_iv[1],
            boundary.expected_address[0],
            boundary.expected_address[1],
            self.mask_mle_at_input,
            self.mask_final_at_terminal,
        ]
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthCapsulePostClaimRelation {
    pub weights: Vec<Block128>,
    pub expected_inner_product: Block128,
}

impl AuthCapsulePostClaimRelation {
    pub fn verify(&self, bank: ZkAuthCapsuleBankView<'_>) -> bool {
        self.weights.len() == ZK_AUTH_CAPSULE_BANK_LEN
            && inner_product(bank.cells(), &self.weights) == self.expected_inner_product
    }
}

fn accumulate_dense_relation(output: &mut [Block128], source: &[Block128], coefficient: Block128) {
    debug_assert_eq!(output.len(), source.len());
    for (target, &weight) in output.iter_mut().zip(source) {
        *target += coefficient * weight;
    }
}

/// Build the one transparent post-claim relation after claim absorption.
///
/// The caller supplies the already-derived nonzero RLC challenge. This helper
/// intentionally has no transcript handle and therefore cannot sample early.
pub fn build_post_claim_relation(
    input_point: &[Block128; ZK_AUTH_CAPSULE_BANK_VARS],
    terminal_point: &[Block128; ZK_AUTH_CAPSULE_BANK_VARS],
    boundary: AuthCapsuleBoundaryPublic,
    claims: AuthCapsulePostClaims,
    post_claim_rlc_after_absorption: Block128,
) -> Result<AuthCapsulePostClaimRelation, ZkAuthCapsuleError> {
    if post_claim_rlc_after_absorption == Block128::ZERO {
        return Err(ZkAuthCapsuleError::ZeroPostClaimChallenge);
    }
    let terminal_weights = terminal_operand_functional_weights(terminal_point);
    let boundary_claims = sparse_boundary_claims(boundary);
    let mask_mle_weights = libra_mask_mle_functional_weights(input_point);
    let mask_final_weights = libra_mask_final_functional_weights(terminal_point);
    let ordered_scalars = claims.ordered_with_boundary(boundary);

    let mut weights = vec![Block128::ZERO; ZK_AUTH_CAPSULE_BANK_LEN];
    let mut expected_inner_product = Block128::ZERO;
    let mut rlc_power = Block128::ONE;
    let mut claim_index = 0;

    for relation_weights in &terminal_weights {
        accumulate_dense_relation(&mut weights, relation_weights, rlc_power);
        expected_inner_product += rlc_power * ordered_scalars[claim_index];
        rlc_power *= post_claim_rlc_after_absorption;
        claim_index += 1;
    }
    for boundary_claim in &boundary_claims {
        for term in &boundary_claim.terms {
            weights[term.bank_index] += rlc_power * term.coefficient;
        }
        expected_inner_product += rlc_power * ordered_scalars[claim_index];
        rlc_power *= post_claim_rlc_after_absorption;
        claim_index += 1;
    }
    for relation_weights in [&mask_mle_weights, &mask_final_weights] {
        accumulate_dense_relation(&mut weights, relation_weights, rlc_power);
        expected_inner_product += rlc_power * ordered_scalars[claim_index];
        rlc_power *= post_claim_rlc_after_absorption;
        claim_index += 1;
    }
    debug_assert_eq!(claim_index, ZK_AUTH_CAPSULE_POST_CLAIMS);

    Ok(AuthCapsulePostClaimRelation {
        weights,
        expected_inner_product,
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthCapsuleExplicitMleCheckCarrier {
    pub round_proofs: Vec<ZkMleCheckRoundProof>,
    pub terminal_point: [Block128; ZK_AUTH_CAPSULE_BANK_VARS],
    pub terminal_operands: AuthCapsuleTerminalOperandClaims,
    pub mask_mle_at_input: Block128,
    pub mask_final_at_terminal: Block128,
    pub main_final_at_terminal: Block128,
}

impl AuthCapsuleExplicitMleCheckCarrier {
    pub fn post_claims(&self) -> AuthCapsulePostClaims {
        AuthCapsulePostClaims {
            terminal_operands: self.terminal_operands,
            mask_mle_at_input: self.mask_mle_at_input,
            mask_final_at_terminal: self.mask_final_at_terminal,
        }
    }
}

/// Build and internally telescope the disconnected MLE-check carrier with
/// explicit caller-supplied challenges. This is an algebra/indexing gate, not
/// a proof API: it performs no commitment, transcript absorption, PCS opening,
/// serialization, recursive verification, or randomness generation.
pub fn build_explicit_mlecheck_carrier(
    bank: ZkAuthCapsuleBankView<'_>,
    input_point: [Block128; ZK_AUTH_CAPSULE_BANK_VARS],
    mask_batch_challenge: Block128,
    round_challenges_high_to_low: [Block128; ZK_AUTH_CAPSULE_BANK_VARS],
) -> Result<AuthCapsuleExplicitMleCheckCarrier, ZkAuthCapsuleError> {
    if mask_batch_challenge == Block128::ZERO {
        return Err(ZkAuthCapsuleError::ZeroMaskBatchChallenge);
    }
    validate_auth_main_relation(bank)?;
    let mask = bank.libra_mask_view()?;
    let tables = MainTables::build(bank);
    let mask_mle_at_input = mask.evaluate_mle(&input_point);
    let mut main_running_claim = Block128::ZERO;
    let mut round_proofs = Vec::with_capacity(ZK_AUTH_CAPSULE_BANK_VARS);

    for round in 0..ZK_AUTH_CAPSULE_BANK_VARS {
        let variable = ZK_AUTH_CAPSULE_BANK_VARS - 1 - round;
        let main_round = auth_main_round_from_tables(
            &tables,
            &input_point,
            &round_challenges_high_to_low[..round],
        )?;
        if mlecheck_endpoint_claim(&main_round.coeffs, input_point[variable]) != main_running_claim
        {
            return Err(ZkAuthCapsuleError::MainRoundEndpointMismatch { round });
        }
        let mask_round =
            mask.round_coefficients(&input_point, &round_challenges_high_to_low[..round])?;
        let combined = combine_main_and_mask_round(&main_round, &mask_round, mask_batch_challenge)?;
        round_proofs.push(ZkMleCheckRoundProof::truncate(&combined)?);
        main_running_claim = main_round.evaluate(round_challenges_high_to_low[round]);
    }

    let terminal_point = std::array::from_fn(|variable| {
        round_challenges_high_to_low[ZK_AUTH_CAPSULE_BANK_VARS - 1 - variable]
    });
    certify_terminal_blinding_rank(&terminal_point)?;
    let terminal_operands = compute_terminal_operand_claims(bank, &terminal_point);
    let main_final_at_terminal =
        evaluate_auth_main_terminal_from_claims(&terminal_point, terminal_operands)?;
    let direct_main_final = tables.terminal_value(&terminal_point)?;
    if main_running_claim != main_final_at_terminal || direct_main_final != main_final_at_terminal {
        return Err(ZkAuthCapsuleError::MainTerminalMismatch);
    }
    let mask_final_at_terminal = mask.evaluate_final(&terminal_point);

    let mut verifier = ZkMleCheckVerifierState::new(
        input_point,
        Block128::ZERO,
        mask_mle_at_input,
        mask_batch_challenge,
    );
    for (proof, &challenge) in round_proofs.iter().zip(round_challenges_high_to_low.iter()) {
        verifier.transition(proof, challenge)?;
    }
    verifier.finish_checked(mask_final_at_terminal, main_final_at_terminal)?;

    Ok(AuthCapsuleExplicitMleCheckCarrier {
        round_proofs,
        terminal_point,
        terminal_operands,
        mask_mle_at_input,
        mask_final_at_terminal,
        main_final_at_terminal,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layers::evaluate_permutation;

    fn elem(index: usize, domain: u128) -> Block128 {
        Block128::from(
            domain
                .wrapping_mul(index as u128 + 1)
                .rotate_left((index % 127) as u32)
                ^ (index as u128 * 0x9E37_79B9_7F4A_7C15),
        )
    }

    fn point(domain: u128) -> [Block128; ZK_AUTH_CAPSULE_BANK_VARS] {
        std::array::from_fn(|index| elem(index + 23, domain))
    }

    fn fixture() -> (Vec<Block128>, AuthCapsuleBoundaryPublic) {
        let iv = capacity_iv(TAG_ADDRFIX);
        let input = [elem(0, 0x5EC2E7), elem(1, 0x5EC2E7), iv[0], iv[1]];
        let witness = evaluate_permutation(input);
        let address = [witness.final_state()[0], witness.final_state()[1]];
        let state = ZkAuthCapsuleStateTable::from_permutation_witness(&witness).unwrap();
        let mut bank = vec![Block128::ZERO; ZK_AUTH_CAPSULE_BANK_LEN];
        bank[..ZK_AUTH_CAPSULE_STATE_LEN].copy_from_slice(state.cells());
        for (index, cell) in bank
            .iter_mut()
            .enumerate()
            .take(ZK_AUTH_CAPSULE_LIBRA_MASK_OFFSET)
            .skip(ZK_AUTH_CAPSULE_PCS_COINS_OFFSET)
        {
            *cell = elem(index, 0xC01A5);
        }
        for (index, cell) in bank
            .iter_mut()
            .enumerate()
            .take(ZK_AUTH_CAPSULE_REMAINING_PADDING_OFFSET)
            .skip(ZK_AUTH_CAPSULE_LIBRA_MASK_OFFSET)
        {
            *cell = elem(index, 0x11B2A);
        }
        for (index, cell) in bank
            .iter_mut()
            .enumerate()
            .skip(ZK_AUTH_CAPSULE_REMAINING_PADDING_OFFSET)
        {
            *cell = elem(index, 0xA771A6);
        }
        (bank, AuthCapsuleBoundaryPublic::canonical(address))
    }

    #[test]
    fn layout_and_nonwrapping_addresses_are_exact() {
        assert_eq!(ZK_AUTH_CAPSULE_STATE_OFFSET, 0);
        assert_eq!(ZK_AUTH_CAPSULE_PCS_COINS_OFFSET, 512);
        assert_eq!(ZK_AUTH_CAPSULE_LIBRA_MASK_OFFSET, 1024);
        assert_eq!(ZK_AUTH_CAPSULE_REMAINING_PADDING_OFFSET, 1280);
        assert_eq!(ZK_AUTH_CAPSULE_BANK_LEN, 2048);
        assert_eq!(state_cell_index(0, 0).unwrap(), 0);
        assert_eq!(state_cell_index(0, 3).unwrap(), 3);
        assert_eq!(state_cell_index(1, 0).unwrap(), 4);
        assert_eq!(state_cell_index(127, 3).unwrap(), 511);
        assert_eq!(next_state_cell_index(65, 3).unwrap(), 66 * 4 + 3);
        assert!(matches!(
            current_state_cell_index(66, 0),
            Err(ZkAuthCapsuleError::CurrentRoundOutOfRange { round: 66 })
        ));
        assert!(matches!(
            next_state_cell_index(127, 0),
            Err(ZkAuthCapsuleError::CurrentRoundOutOfRange { round: 127 })
        ));

        let (bank, _) = fixture();
        let view = ZkAuthCapsuleBankView::checked(&bank).unwrap();
        assert_eq!(view.state().len(), 512);
        assert_eq!(view.dedicated_pcs_coins().len(), 512);
        assert_eq!(view.libra_mask().len(), 256);
        assert_eq!(view.remaining_padding().len(), 768);
        assert!(matches!(
            ZkAuthCapsuleBankView::checked(&bank[..2047]),
            Err(ZkAuthCapsuleError::BankLength { .. })
        ));
    }

    #[test]
    fn low_to_high_folds_and_weights_match_boolean_indexing() {
        let table: Vec<Block128> = (0..8).map(|index| elem(index, 0xF01D)).collect();
        for selected in 0..8 {
            let boolean_point: [Block128; 3] = std::array::from_fn(|variable| {
                Block128::from(((selected >> variable) & 1) as u128)
            });
            assert_eq!(
                evaluate_mle_low_to_high(&table, &boolean_point).unwrap(),
                table[selected]
            );
            assert_eq!(
                inner_product(&table, &mle_weights_low_to_high(&boolean_point)),
                table[selected]
            );
        }

        let arbitrary = point(0xF01D);
        assert_eq!(
            evaluate_mle_low_to_high(&table, &arbitrary[..3]).unwrap(),
            inner_product(&table, &mle_weights_low_to_high(&arbitrary[..3]))
        );
    }

    #[test]
    fn honest_trace_matches_reindexed_relation_and_sparse_boundary() {
        let (bank, boundary) = fixture();
        let view = ZkAuthCapsuleBankView::checked(&bank).unwrap();
        validate_auth_main_relation(view).unwrap();
        validate_sparse_boundary(view, boundary).unwrap();

        let mut bad_transition = bank.clone();
        bad_transition[current_state_cell_index(17, 2).unwrap()] += Block128::ONE;
        assert!(matches!(
            validate_auth_main_relation(ZkAuthCapsuleBankView::checked(&bad_transition).unwrap()),
            Err(ZkAuthCapsuleError::MainRelationMismatch { .. })
        ));

        let wrong_boundary = AuthCapsuleBoundaryPublic {
            expected_address: [
                boundary.expected_address[0] + Block128::ONE,
                boundary.expected_address[1],
            ],
            ..boundary
        };
        assert!(matches!(
            validate_sparse_boundary(view, wrong_boundary),
            Err(ZkAuthCapsuleError::BoundaryMismatch { claim_index: 2 })
        ));
    }

    #[test]
    fn terminal_and_mask_functionals_equal_direct_evaluations() {
        let (bank, _) = fixture();
        let view = ZkAuthCapsuleBankView::checked(&bank).unwrap();
        let terminal = point(0x7E2A11);
        let claims = compute_terminal_operand_claims(view, &terminal);
        let tables = MainTables::build(view);
        assert_eq!(
            claims.increment,
            evaluate_mle_low_to_high(&tables.increment, &terminal).unwrap()
        );
        for lane in 0..STATE_SIZE {
            assert_eq!(
                claims.lane[lane],
                evaluate_mle_low_to_high(&tables.lane[lane], &terminal).unwrap()
            );
        }
        assert_eq!(
            evaluate_auth_main_terminal_from_claims(&terminal, claims).unwrap(),
            tables.terminal_value(&terminal).unwrap()
        );

        let certificate = certify_terminal_blinding_rank(&terminal).unwrap();
        assert_eq!(certificate.certified_rank, 5);
        assert_eq!(
            certificate.blinding_cell_indices,
            [1280, 1281, 1282, 1283, 1284]
        );
        let weights = terminal_operand_functional_weights(&terminal);
        for claim in 0..ZK_AUTH_CAPSULE_TERMINAL_OPERAND_CLAIMS {
            for blinder in 0..ZK_AUTH_CAPSULE_TERMINAL_BLINDING_CELLS {
                assert_eq!(
                    weights[claim][ZK_AUTH_CAPSULE_TERMINAL_BLINDING_OFFSET + blinder],
                    if claim == blinder {
                        certificate.common_coefficient
                    } else {
                        Block128::ZERO
                    }
                );
            }
        }

        let input = point(0x1A907);
        let mask = view.libra_mask_view().unwrap();
        assert_eq!(
            inner_product(view.cells(), &libra_mask_mle_functional_weights(&input)),
            mask.evaluate_mle(&input)
        );
        assert_eq!(
            inner_product(
                view.cells(),
                &libra_mask_final_functional_weights(&terminal)
            ),
            mask.evaluate_final(&terminal)
        );
    }

    #[test]
    fn explicit_degree_ten_carrier_and_post_claim_relation_roundtrip() {
        let (bank, boundary) = fixture();
        let view = ZkAuthCapsuleBankView::checked(&bank).unwrap();
        let input = point(0x1A907);
        let challenges = point(0xC4A11);
        let lambda = elem(77, 0x1A4BDA);
        let carrier = build_explicit_mlecheck_carrier(view, input, lambda, challenges).unwrap();
        assert_eq!(carrier.round_proofs.len(), ZK_AUTH_CAPSULE_BANK_VARS);

        let relation = build_post_claim_relation(
            &input,
            &carrier.terminal_point,
            boundary,
            carrier.post_claims(),
            elem(91, 0xA1C),
        )
        .unwrap();
        assert!(relation.verify(view));
        assert!(relation.weights
            [ZK_AUTH_CAPSULE_PCS_COINS_OFFSET..ZK_AUTH_CAPSULE_LIBRA_MASK_OFFSET]
            .iter()
            .all(|&weight| weight == Block128::ZERO));
        assert!(relation.weights[ZK_AUTH_CAPSULE_TERMINAL_BLINDING_OFFSET
            ..ZK_AUTH_CAPSULE_TERMINAL_BLINDING_OFFSET + ZK_AUTH_CAPSULE_TERMINAL_BLINDING_CELLS]
            .iter()
            .all(|&weight| weight != Block128::ZERO));
        assert!(relation.weights
            [ZK_AUTH_CAPSULE_TERMINAL_BLINDING_OFFSET + ZK_AUTH_CAPSULE_TERMINAL_BLINDING_CELLS..]
            .iter()
            .all(|&weight| weight == Block128::ZERO));

        let mut tampered_claims = carrier.post_claims();
        tampered_claims.terminal_operands.increment += Block128::ONE;
        let tampered_relation = build_post_claim_relation(
            &input,
            &carrier.terminal_point,
            boundary,
            tampered_claims,
            elem(91, 0xA1C),
        )
        .unwrap();
        assert!(!tampered_relation.verify(view));

        assert_eq!(
            build_explicit_mlecheck_carrier(view, input, Block128::ZERO, challenges),
            Err(ZkAuthCapsuleError::ZeroMaskBatchChallenge)
        );
        assert_eq!(
            build_post_claim_relation(
                &input,
                &carrier.terminal_point,
                boundary,
                carrier.post_claims(),
                Block128::ZERO,
            ),
            Err(ZkAuthCapsuleError::ZeroPostClaimChallenge)
        );
    }

    #[test]
    fn repeated_proof_terminal_claims_are_fully_simulatable_from_fresh_pads() {
        let (base_bank, _) = fixture();

        // Sixty-six independent transcript points are enough to recover the
        // old state-only lane tables. With five fresh pads per proof, every
        // five-scalar observation vector can instead be programmed without
        // changing a single active state cell.
        for proof_index in 0..ZK_AUTH_CAPSULE_ACTIVE_ROUNDS {
            let terminal = point(0x5A11_0000 + proof_index as u128);
            let certificate = certify_terminal_blinding_rank(&terminal).unwrap();
            let base_view = ZkAuthCapsuleBankView::checked(&base_bank).unwrap();
            let before = compute_terminal_operand_claims(base_view, &terminal).ordered();
            let desired: [Block128; ZK_AUTH_CAPSULE_TERMINAL_OPERAND_CLAIMS] =
                std::array::from_fn(|claim| elem(10_000 + proof_index * 5 + claim, 0x51A0_1A7E));

            let mut simulated_bank = base_bank.clone();
            let inverse = certificate.common_coefficient.invert();
            for claim in 0..ZK_AUTH_CAPSULE_TERMINAL_OPERAND_CLAIMS {
                simulated_bank[certificate.blinding_cell_indices[claim]] +=
                    (desired[claim] - before[claim]) * inverse;
            }

            let simulated_view = ZkAuthCapsuleBankView::checked(&simulated_bank).unwrap();
            assert_eq!(
                compute_terminal_operand_claims(simulated_view, &terminal).ordered(),
                desired
            );
            validate_auth_main_relation(simulated_view).unwrap();
            assert_eq!(
                &simulated_bank[..ZK_AUTH_CAPSULE_STATE_LEN],
                &base_bank[..ZK_AUTH_CAPSULE_STATE_LEN]
            );
        }
    }

    #[test]
    fn zero_terminal_blinding_basis_weight_is_rejected() {
        let mut degenerate = [Block128::ONE; ZK_AUTH_CAPSULE_BANK_VARS];
        degenerate[4] = Block128::ZERO;
        assert_eq!(
            certify_terminal_blinding_rank(&degenerate),
            Err(ZkAuthCapsuleError::ZeroTerminalBlindingWeight)
        );
    }
}
