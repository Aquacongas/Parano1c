// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Joint finite-field conditioning certificate for the ZK authorization bank.
//!
//! This module checks the exact independent-randomness blocks, the companion
//! change of variables, and the source-opening, terminal-operand, and
//! characteristic-two Libra rank certificates.
//!
//! The unconditional companion lemma is an executable algebraic simulator
//! step.  For
//! `gamma != 0,1`, fixing the bank `B` and changing variables from the fresh
//! companion `C` to
//!
//! ```text
//! U = (1 + gamma) B + gamma C
//! ```
//!
//! is a rank-2048 bijection.  Consequently a raw companion functional can be
//! rewritten using the same bank functional and a functional of `U`.  After
//! conditioning on `U`, it introduces no new *kind* of bank functional beyond
//! the source functionals whose rank is certified separately.  Phase A,
//! `upper`, `mid`, and `tail` are deterministic algebraic functions of `U` and
//! their already conditioned challenges.
//!
//! The protocol also publishes the pre-`gamma` scalar
//! `sigma = <C, t>`.  [`ZkAuthConditionedCompanionHyperplaneCertificate`]
//! separately certifies the exact conditioned statement: at fixed
//! `<B, t> = b`, the companion blend maps the `C`-fiber `<C, t> = sigma`
//! bijectively onto the corresponding `U`-fiber.  Its 2047- or
//! 2048-dimensional rank is a rank on the conditioned affine space, not an
//! additional public-observation rank and is therefore deliberately absent
//! from [`ZkAuthJointHidingRankCertificate::certified_joint_rank`].
//!
//! These are necessary finite-field simulator lemmas only.  They are not a
//! hiding proof for the hash commitment, do not model hash collisions, and do
//! not establish a Fiat-Shamir proof or security in the ROM/QROM.

use noid_core::{Block128, TowerField};
use noid_fri_binius::zk_affine_code::{
    AffineHighPaddingRankCertificate, AFFINE_CODE_MESSAGE_LEN, AFFINE_FRESH_PADDING_START,
    AFFINE_FUNDAMENTAL_LOG, AFFINE_LIBRA_MASK_LEN, AFFINE_LIBRA_MASK_START, AFFINE_PCS_COINS_LEN,
    AFFINE_PCS_COINS_START, AFFINE_STATE_LEN,
};

use crate::zk_auth_capsule::{
    certify_terminal_blinding_rank, AuthCapsuleTerminalBlindingRankCertificate,
    ZK_AUTH_CAPSULE_BANK_LEN, ZK_AUTH_CAPSULE_BANK_VARS, ZK_AUTH_CAPSULE_LIBRA_MASK_LEN,
    ZK_AUTH_CAPSULE_LIBRA_MASK_OFFSET, ZK_AUTH_CAPSULE_PCS_COINS_LEN,
    ZK_AUTH_CAPSULE_PCS_COINS_OFFSET, ZK_AUTH_CAPSULE_STATE_LEN,
    ZK_AUTH_CAPSULE_TERMINAL_BLINDING_BOOLEAN_INDEX, ZK_AUTH_CAPSULE_TERMINAL_BLINDING_CELLS,
    ZK_AUTH_CAPSULE_TERMINAL_BLINDING_OFFSET,
};
use crate::zk_mlecheck::{
    certify_zk_mlecheck_mask_rank, ZkMleCheckMaskRankCertificate, ZK_MLECHECK_ACTIVE_MASK_COEFFS,
    ZK_MLECHECK_MASK_OBSERVATION_RANK, ZK_MLECHECK_PUBLIC_MASK_FIELDS,
};

pub const ZK_AUTH_FRESH_BANK_SUFFIX_CELLS: usize =
    ZK_AUTH_CAPSULE_BANK_LEN - ZK_AUTH_CAPSULE_STATE_LEN;
pub const ZK_AUTH_FRESH_COMPANION_CELLS: usize = ZK_AUTH_CAPSULE_BANK_LEN;
pub const ZK_AUTH_TOTAL_FRESH_CELLS: usize =
    ZK_AUTH_FRESH_BANK_SUFFIX_CELLS + ZK_AUTH_FRESH_COMPANION_CELLS;
/// Dimension of the selected full-bank companion change of variables.
pub const ZK_AUTH_COMPANION_CHANGE_DIMENSION: usize = ZK_AUTH_CAPSULE_BANK_LEN;
/// Rank of `C -> (1 + gamma) B + gamma C` whenever `gamma != 0`.
pub const ZK_AUTH_COMPANION_CHANGE_RANK: usize = ZK_AUTH_COMPANION_CHANGE_DIMENSION;
/// Dimension of a nontrivial scalar-functional fiber in the companion bank.
pub const ZK_AUTH_COMPANION_HYPERPLANE_DIMENSION: usize = ZK_AUTH_COMPANION_CHANGE_DIMENSION - 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkAuthRandomBlock {
    pub start: usize,
    pub len: usize,
}

impl ZkAuthRandomBlock {
    pub const fn end(self) -> usize {
        self.start + self.len
    }
}

pub const ZK_AUTH_SOURCE_COIN_RANDOM_BLOCK: ZkAuthRandomBlock = ZkAuthRandomBlock {
    start: ZK_AUTH_CAPSULE_PCS_COINS_OFFSET,
    len: ZK_AUTH_CAPSULE_PCS_COINS_LEN,
};
pub const ZK_AUTH_LIBRA_RANDOM_BLOCK: ZkAuthRandomBlock = ZkAuthRandomBlock {
    start: ZK_AUTH_CAPSULE_LIBRA_MASK_OFFSET,
    len: ZK_AUTH_CAPSULE_LIBRA_MASK_LEN,
};
pub const ZK_AUTH_TERMINAL_OPERAND_PAD_RANDOM_BLOCK: ZkAuthRandomBlock = ZkAuthRandomBlock {
    start: ZK_AUTH_CAPSULE_TERMINAL_BLINDING_OFFSET,
    len: ZK_AUTH_CAPSULE_TERMINAL_BLINDING_CELLS,
};

const _: () = assert!(ZK_AUTH_CAPSULE_BANK_LEN == AFFINE_CODE_MESSAGE_LEN);
const _: () = assert!(ZK_AUTH_CAPSULE_STATE_LEN == AFFINE_STATE_LEN);
const _: () = assert!(ZK_AUTH_CAPSULE_PCS_COINS_OFFSET == AFFINE_PCS_COINS_START);
const _: () = assert!(ZK_AUTH_CAPSULE_PCS_COINS_LEN == AFFINE_PCS_COINS_LEN);
const _: () = assert!(ZK_AUTH_CAPSULE_LIBRA_MASK_OFFSET == AFFINE_LIBRA_MASK_START);
const _: () = assert!(ZK_AUTH_CAPSULE_LIBRA_MASK_LEN == AFFINE_LIBRA_MASK_LEN);
const _: () = assert!(ZK_AUTH_CAPSULE_TERMINAL_BLINDING_OFFSET == AFFINE_FRESH_PADDING_START);
const _: () = assert!(ZK_AUTH_SOURCE_COIN_RANDOM_BLOCK.start == 512);
const _: () = assert!(ZK_AUTH_SOURCE_COIN_RANDOM_BLOCK.end() == 1_024);
const _: () = assert!(ZK_AUTH_LIBRA_RANDOM_BLOCK.start == 1_024);
const _: () = assert!(ZK_AUTH_LIBRA_RANDOM_BLOCK.end() == 1_280);
const _: () = assert!(ZK_AUTH_TERMINAL_OPERAND_PAD_RANDOM_BLOCK.start == 1_280);
const _: () = assert!(ZK_AUTH_TERMINAL_OPERAND_PAD_RANDOM_BLOCK.end() == 1_285);
const _: () = assert!(ZK_AUTH_FRESH_BANK_SUFFIX_CELLS == 1_536);
const _: () = assert!(ZK_AUTH_FRESH_COMPANION_CELLS == 2_048);
const _: () = assert!(ZK_AUTH_TOTAL_FRESH_CELLS == 3_584);
const _: () = assert!(ZK_AUTH_COMPANION_CHANGE_DIMENSION == 2_048);
const _: () = assert!(ZK_AUTH_COMPANION_CHANGE_RANK == 2_048);
const _: () = assert!(ZK_AUTH_COMPANION_HYPERPLANE_DIMENSION == 2_047);

/// Exact scalar certificate for the full companion change of variables.
///
/// The forward coefficients state
/// `U = forward_bank * B + forward_companion * C`.  The inverse coefficients
/// state `C = inverse_blend * U + inverse_bank * B`.  The same equality holds
/// after applying any source linear functional `L`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkAuthCompanionChangeOfVariablesCertificate {
    pub gamma: Block128,
    pub dimension: usize,
    pub certified_rank: usize,
    pub forward_bank_coefficient: Block128,
    pub forward_companion_coefficient: Block128,
    pub inverse_blend_coefficient: Block128,
    pub inverse_bank_coefficient: Block128,
}

impl ZkAuthCompanionChangeOfVariablesCertificate {
    /// Recheck every coefficient and the exact 2048-dimensional rank claim.
    pub fn validate(&self) -> Result<(), ZkAuthHidingRankError> {
        if self.gamma == Block128::ZERO || self.gamma == Block128::ONE {
            return Err(ZkAuthHidingRankError::GammaEndpoint);
        }
        let forward_bank = Block128::ONE + self.gamma;
        let inverse_blend = self.gamma.invert();
        let inverse_bank = inverse_blend * forward_bank;
        if self.dimension != ZK_AUTH_COMPANION_CHANGE_DIMENSION
            || self.certified_rank != ZK_AUTH_COMPANION_CHANGE_RANK
            || self.forward_bank_coefficient != forward_bank
            || self.forward_companion_coefficient != self.gamma
            || self.inverse_blend_coefficient != inverse_blend
            || self.inverse_bank_coefficient != inverse_bank
            || self.forward_bank_coefficient == Block128::ZERO
            || self.forward_companion_coefficient == Block128::ZERO
            || self.forward_companion_coefficient * self.inverse_blend_coefficient != Block128::ONE
        {
            return Err(ZkAuthHidingRankError::MalformedCompanionChangeOfVariablesCertificate);
        }
        Ok(())
    }

    /// Apply `U = (1 + gamma) B + gamma C` to the complete selected bank.
    pub fn blend(
        &self,
        bank: &[Block128; ZK_AUTH_COMPANION_CHANGE_DIMENSION],
        companion: &[Block128; ZK_AUTH_COMPANION_CHANGE_DIMENSION],
    ) -> Result<[Block128; ZK_AUTH_COMPANION_CHANGE_DIMENSION], ZkAuthHidingRankError> {
        self.validate()?;
        Ok(std::array::from_fn(|index| {
            self.forward_bank_coefficient * bank[index]
                + self.forward_companion_coefficient * companion[index]
        }))
    }

    /// Invert the complete change of variables at fixed `B`.
    pub fn recover_companion(
        &self,
        bank: &[Block128; ZK_AUTH_COMPANION_CHANGE_DIMENSION],
        blend: &[Block128; ZK_AUTH_COMPANION_CHANGE_DIMENSION],
    ) -> Result<[Block128; ZK_AUTH_COMPANION_CHANGE_DIMENSION], ZkAuthHidingRankError> {
        self.validate()?;
        Ok(std::array::from_fn(|index| {
            self.inverse_blend_coefficient * blend[index]
                + self.inverse_bank_coefficient * bank[index]
        }))
    }

    /// Rewrite a raw companion observation after any linear functional `L`:
    /// `L(C) = gamma^-1 (L(U) + (1 + gamma) L(B))`.
    pub fn recover_companion_functional(
        &self,
        bank_functional: Block128,
        blend_functional: Block128,
    ) -> Result<Block128, ZkAuthHidingRankError> {
        self.validate()?;
        Ok(self.inverse_blend_coefficient * blend_functional
            + self.inverse_bank_coefficient * bank_functional)
    }
}

/// Certify the exact scalar matrix `gamma I_2048` and its inverse.
pub fn certify_zk_auth_companion_change_of_variables(
    gamma: Block128,
) -> Result<ZkAuthCompanionChangeOfVariablesCertificate, ZkAuthHidingRankError> {
    if gamma == Block128::ZERO || gamma == Block128::ONE {
        return Err(ZkAuthHidingRankError::GammaEndpoint);
    }
    let forward_bank_coefficient = Block128::ONE + gamma;
    let inverse_blend_coefficient = gamma.invert();
    let certificate = ZkAuthCompanionChangeOfVariablesCertificate {
        gamma,
        dimension: ZK_AUTH_COMPANION_CHANGE_DIMENSION,
        certified_rank: ZK_AUTH_COMPANION_CHANGE_RANK,
        forward_bank_coefficient,
        forward_companion_coefficient: gamma,
        inverse_blend_coefficient,
        inverse_bank_coefficient: inverse_blend_coefficient * forward_bank_coefficient,
    };
    certificate.validate()?;
    Ok(certificate)
}

/// Exact conditioned certificate for the public pre-`gamma`
/// `sigma = <C, t>` observation.
///
/// For a nonzero relation `t`, both the source and target are affine
/// hyperplanes of dimension 2047.  For `t = 0`, the only consistent public
/// claims are `b = sigma = 0` and both fibers are the complete
/// 2048-dimensional space.  In either case, at every fixed bank `B` with
/// `<B, t> = b`,
///
/// ```text
/// U = (1 + gamma) B + gamma C
/// <U, t> = (1 + gamma) b + gamma sigma
/// C = gamma^-1 U + gamma^-1 (1 + gamma) B
/// ```
///
/// restricts to a bijection between the two fibers.  The
/// `conditioned_change_rank` below is the rank of this restriction on the
/// fiber direction `ker(t)`; it must not be added to a public-observation
/// rank ledger.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkAuthConditionedCompanionHyperplaneCertificate {
    pub gamma: Block128,
    pub relation_len: usize,
    pub relation_rank: usize,
    pub affine_fiber_dimension: usize,
    pub conditioned_change_rank: usize,
    pub pivot_index: Option<usize>,
    pub pivot_coefficient: Block128,
    pub bank_claim: Block128,
    pub companion_claim: Block128,
    pub expected_blend_claim: Block128,
    pub forward_bank_coefficient: Block128,
    pub forward_companion_coefficient: Block128,
    pub inverse_blend_coefficient: Block128,
    pub inverse_bank_coefficient: Block128,
}

fn companion_linear_functional(
    relation: &[Block128],
    values: &[Block128; ZK_AUTH_COMPANION_CHANGE_DIMENSION],
) -> Block128 {
    relation
        .iter()
        .zip(values)
        .fold(Block128::ZERO, |sum, (&coefficient, &value)| {
            sum + coefficient * value
        })
}

impl ZkAuthConditionedCompanionHyperplaneCertificate {
    /// Recompute the relation pivot, both fiber dimensions, every scalar
    /// coefficient, and the forced target-fiber claim from the exact `t`.
    pub fn validate(&self, relation: &[Block128]) -> Result<(), ZkAuthHidingRankError> {
        if relation.len() != ZK_AUTH_COMPANION_CHANGE_DIMENSION {
            return Err(ZkAuthHidingRankError::MalformedCompanionRelationLength);
        }
        if self.gamma == Block128::ZERO || self.gamma == Block128::ONE {
            return Err(ZkAuthHidingRankError::GammaEndpoint);
        }

        let expected_pivot = relation
            .iter()
            .position(|&coefficient| coefficient != Block128::ZERO);
        let expected_relation_rank = usize::from(expected_pivot.is_some());
        let expected_fiber_dimension = ZK_AUTH_COMPANION_CHANGE_DIMENSION - expected_relation_rank;
        let expected_pivot_coefficient = expected_pivot
            .map(|index| relation[index])
            .unwrap_or(Block128::ZERO);
        if expected_relation_rank == 0
            && (self.bank_claim != Block128::ZERO || self.companion_claim != Block128::ZERO)
        {
            return Err(ZkAuthHidingRankError::ZeroRelationRequiresZeroClaims);
        }

        let forward_bank_coefficient = Block128::ONE + self.gamma;
        let inverse_blend_coefficient = self.gamma.invert();
        let inverse_bank_coefficient = inverse_blend_coefficient * forward_bank_coefficient;
        let expected_blend_claim =
            forward_bank_coefficient * self.bank_claim + self.gamma * self.companion_claim;

        if self.relation_len != ZK_AUTH_COMPANION_CHANGE_DIMENSION
            || self.relation_rank != expected_relation_rank
            || self.affine_fiber_dimension != expected_fiber_dimension
            || self.conditioned_change_rank != expected_fiber_dimension
            || self.pivot_index != expected_pivot
            || self.pivot_coefficient != expected_pivot_coefficient
            || (self.relation_rank == 1 && self.pivot_coefficient == Block128::ZERO)
            || (self.relation_rank == 0 && self.pivot_coefficient != Block128::ZERO)
            || self.forward_bank_coefficient != forward_bank_coefficient
            || self.forward_companion_coefficient != self.gamma
            || self.inverse_blend_coefficient != inverse_blend_coefficient
            || self.inverse_bank_coefficient != inverse_bank_coefficient
            || self.forward_companion_coefficient * self.inverse_blend_coefficient != Block128::ONE
            || self.expected_blend_claim != expected_blend_claim
        {
            return Err(ZkAuthHidingRankError::MalformedConditionedCompanionHyperplaneCertificate);
        }
        Ok(())
    }

    /// Apply the companion blend to a complete pair of bank vectors.
    pub fn blend(
        &self,
        relation: &[Block128],
        bank: &[Block128; ZK_AUTH_COMPANION_CHANGE_DIMENSION],
        companion: &[Block128; ZK_AUTH_COMPANION_CHANGE_DIMENSION],
    ) -> Result<[Block128; ZK_AUTH_COMPANION_CHANGE_DIMENSION], ZkAuthHidingRankError> {
        self.validate(relation)?;
        if companion_linear_functional(relation, bank) != self.bank_claim {
            return Err(ZkAuthHidingRankError::ConditionedBankClaimMismatch);
        }
        if companion_linear_functional(relation, companion) != self.companion_claim {
            return Err(ZkAuthHidingRankError::ConditionedCompanionClaimMismatch);
        }
        Ok(std::array::from_fn(|index| {
            self.forward_bank_coefficient * bank[index]
                + self.forward_companion_coefficient * companion[index]
        }))
    }

    /// Recover the complete companion vector from a point in the certified
    /// target fiber.
    pub fn recover_companion(
        &self,
        relation: &[Block128],
        bank: &[Block128; ZK_AUTH_COMPANION_CHANGE_DIMENSION],
        blend: &[Block128; ZK_AUTH_COMPANION_CHANGE_DIMENSION],
    ) -> Result<[Block128; ZK_AUTH_COMPANION_CHANGE_DIMENSION], ZkAuthHidingRankError> {
        self.validate(relation)?;
        if companion_linear_functional(relation, bank) != self.bank_claim {
            return Err(ZkAuthHidingRankError::ConditionedBankClaimMismatch);
        }
        if companion_linear_functional(relation, blend) != self.expected_blend_claim {
            return Err(ZkAuthHidingRankError::ConditionedBlendClaimMismatch);
        }
        Ok(std::array::from_fn(|index| {
            self.inverse_blend_coefficient * blend[index]
                + self.inverse_bank_coefficient * bank[index]
        }))
    }

    /// Validate all three complete vectors and return the independently
    /// recovered companion.  This checks the two input claims, the target
    /// claim, every coordinate of the forward blend, and every coordinate of
    /// the inverse recovery.
    pub fn validate_vectors(
        &self,
        relation: &[Block128],
        bank: &[Block128; ZK_AUTH_COMPANION_CHANGE_DIMENSION],
        companion: &[Block128; ZK_AUTH_COMPANION_CHANGE_DIMENSION],
        blend: &[Block128; ZK_AUTH_COMPANION_CHANGE_DIMENSION],
    ) -> Result<[Block128; ZK_AUTH_COMPANION_CHANGE_DIMENSION], ZkAuthHidingRankError> {
        self.validate(relation)?;
        if companion_linear_functional(relation, bank) != self.bank_claim {
            return Err(ZkAuthHidingRankError::ConditionedBankClaimMismatch);
        }
        if companion_linear_functional(relation, companion) != self.companion_claim {
            return Err(ZkAuthHidingRankError::ConditionedCompanionClaimMismatch);
        }
        if companion_linear_functional(relation, blend) != self.expected_blend_claim {
            return Err(ZkAuthHidingRankError::ConditionedBlendClaimMismatch);
        }
        if bank.iter().zip(companion).zip(blend).any(
            |((&bank_value, &companion_value), &blend_value)| {
                blend_value
                    != self.forward_bank_coefficient * bank_value
                        + self.forward_companion_coefficient * companion_value
            },
        ) {
            return Err(ZkAuthHidingRankError::ConditionedBlendVectorMismatch);
        }
        let recovered = self.recover_companion(relation, bank, blend)?;
        if recovered != *companion {
            return Err(ZkAuthHidingRankError::ConditionedCompanionRecoveryMismatch);
        }
        Ok(recovered)
    }
}

/// Certify the exact affine-fiber statement induced by the public
/// pre-`gamma` companion observation.
///
/// This finite-field lemma does not prove that an adaptively
/// Fiat-Shamir-derived `t` is independent of committed data, nor does it prove
/// commitment hiding, collision resistance, or a ROM/QROM transcript hybrid.
pub fn certify_zk_auth_conditioned_companion_hyperplane(
    relation: &[Block128],
    bank_claim: Block128,
    companion_claim: Block128,
    gamma: Block128,
) -> Result<ZkAuthConditionedCompanionHyperplaneCertificate, ZkAuthHidingRankError> {
    if relation.len() != ZK_AUTH_COMPANION_CHANGE_DIMENSION {
        return Err(ZkAuthHidingRankError::MalformedCompanionRelationLength);
    }
    if gamma == Block128::ZERO || gamma == Block128::ONE {
        return Err(ZkAuthHidingRankError::GammaEndpoint);
    }
    let pivot_index = relation
        .iter()
        .position(|&coefficient| coefficient != Block128::ZERO);
    if pivot_index.is_none() && (bank_claim != Block128::ZERO || companion_claim != Block128::ZERO)
    {
        return Err(ZkAuthHidingRankError::ZeroRelationRequiresZeroClaims);
    }
    let relation_rank = usize::from(pivot_index.is_some());
    let affine_fiber_dimension = ZK_AUTH_COMPANION_CHANGE_DIMENSION - relation_rank;
    let forward_bank_coefficient = Block128::ONE + gamma;
    let inverse_blend_coefficient = gamma.invert();
    let certificate = ZkAuthConditionedCompanionHyperplaneCertificate {
        gamma,
        relation_len: relation.len(),
        relation_rank,
        affine_fiber_dimension,
        conditioned_change_rank: affine_fiber_dimension,
        pivot_index,
        pivot_coefficient: pivot_index
            .map(|index| relation[index])
            .unwrap_or(Block128::ZERO),
        bank_claim,
        companion_claim,
        expected_blend_claim: forward_bank_coefficient * bank_claim + gamma * companion_claim,
        forward_bank_coefficient,
        forward_companion_coefficient: gamma,
        inverse_blend_coefficient,
        inverse_bank_coefficient: inverse_blend_coefficient * forward_bank_coefficient,
    };
    certificate.validate(relation)?;
    Ok(certificate)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ZkAuthHidingRankError {
    MalformedSourceRankCertificate,
    RandomBlockLayout,
    ZeroTerminalBlindingWeight,
    MalformedTerminalOperandPadRankCertificate,
    LambdaZero,
    MalformedLibraRankCertificate,
    GammaEndpoint,
    MalformedCompanionChangeOfVariablesCertificate,
    MalformedCompanionRelationLength,
    ZeroRelationRequiresZeroClaims,
    MalformedConditionedCompanionHyperplaneCertificate,
    ConditionedBankClaimMismatch,
    ConditionedCompanionClaimMismatch,
    ConditionedBlendClaimMismatch,
    ConditionedBlendVectorMismatch,
    ConditionedCompanionRecoveryMismatch,
}

/// Necessary algebraic rank facts after jointly conditioning on source
/// openings, five terminal-operand claims, and the 112 Libra-dependent public
/// fields.  The one rank deficit is the intended Libra terminal relation.
///
/// This ledger intentionally does not accept the transcript-specific `t`,
/// `b`, or `sigma`.  A complete verifier-side algebraic check must pair it
/// with [`certify_zk_auth_conditioned_companion_hyperplane`] using those exact
/// values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkAuthJointHidingRankCertificate {
    pub source: AffineHighPaddingRankCertificate,
    pub companion_change_of_variables: ZkAuthCompanionChangeOfVariablesCertificate,
    pub terminal_operand_pads: AuthCapsuleTerminalBlindingRankCertificate,
    pub libra: ZkMleCheckMaskRankCertificate,
    pub source_coin_block: ZkAuthRandomBlock,
    pub libra_block: ZkAuthRandomBlock,
    pub terminal_operand_pad_block: ZkAuthRandomBlock,
    pub source_rank: usize,
    /// Rank of the bijective `C -> U` change, stated separately rather than
    /// added to the public-observation rank ledger below.
    pub companion_change_rank: usize,
    pub terminal_operand_rank: usize,
    pub joint_source_terminal_rank: usize,
    pub public_conditioning_fields: usize,
    pub certified_joint_rank: usize,
    pub intended_relations: usize,
    pub fresh_bank_suffix_cells: usize,
    pub fresh_companion_cells: usize,
    pub total_fresh_cells: usize,
}

fn validate_random_block_layout() -> Result<(), ZkAuthHidingRankError> {
    let source = ZK_AUTH_SOURCE_COIN_RANDOM_BLOCK;
    let libra = ZK_AUTH_LIBRA_RANDOM_BLOCK;
    let terminal = ZK_AUTH_TERMINAL_OPERAND_PAD_RANDOM_BLOCK;
    if source
        != (ZkAuthRandomBlock {
            start: 512,
            len: 512,
        })
        || libra
            != (ZkAuthRandomBlock {
                start: 1_024,
                len: 256,
            })
        || terminal
            != (ZkAuthRandomBlock {
                start: 1_280,
                len: 5,
            })
        || source.end() != libra.start
        || libra.end() != terminal.start
        || terminal.end() > ZK_AUTH_CAPSULE_BANK_LEN
        || ZK_AUTH_FRESH_BANK_SUFFIX_CELLS != 1_536
        || ZK_AUTH_FRESH_COMPANION_CELLS != 2_048
        || ZK_AUTH_TOTAL_FRESH_CELLS != 3_584
    {
        return Err(ZkAuthHidingRankError::RandomBlockLayout);
    }
    Ok(())
}

fn validate_source_rank(
    source: &AffineHighPaddingRankCertificate,
) -> Result<(), ZkAuthHidingRankError> {
    if source.independent_coeff_start != ZK_AUTH_SOURCE_COIN_RANDOM_BLOCK.start
        || source.independent_coeff_len != ZK_AUTH_SOURCE_COIN_RANDOM_BLOCK.len
        || source.distinct_query_count > ZK_AUTH_SOURCE_COIN_RANDOM_BLOCK.len
        || source.certified_rank != source.distinct_query_count
        || source.nonzero_factor_level != AFFINE_FUNDAMENTAL_LOG
    {
        return Err(ZkAuthHidingRankError::MalformedSourceRankCertificate);
    }
    Ok(())
}

fn validate_terminal_operand_rank(
    terminal: &AuthCapsuleTerminalBlindingRankCertificate,
) -> Result<(), ZkAuthHidingRankError> {
    let expected_indices =
        std::array::from_fn(|index| ZK_AUTH_TERMINAL_OPERAND_PAD_RANDOM_BLOCK.start + index);
    if terminal.boolean_index != ZK_AUTH_CAPSULE_TERMINAL_BLINDING_BOOLEAN_INDEX
        || terminal.common_coefficient == Block128::ZERO
        || terminal.blinding_cell_indices != expected_indices
        || terminal.certified_rank != ZK_AUTH_CAPSULE_TERMINAL_BLINDING_CELLS
    {
        return Err(ZkAuthHidingRankError::MalformedTerminalOperandPadRankCertificate);
    }
    Ok(())
}

fn validate_libra_rank(libra: &ZkMleCheckMaskRankCertificate) -> Result<(), ZkAuthHidingRankError> {
    if libra.active_mask_coefficients != ZK_MLECHECK_ACTIVE_MASK_COEFFS
        || libra.public_mask_dependent_fields != ZK_MLECHECK_PUBLIC_MASK_FIELDS
        || libra.certified_rank != ZK_MLECHECK_MASK_OBSERVATION_RANK
        || libra.intended_terminal_relations != 1
        || libra.remaining_active_degrees_of_freedom
            != ZK_MLECHECK_ACTIVE_MASK_COEFFS - ZK_MLECHECK_MASK_OBSERVATION_RANK
    {
        return Err(ZkAuthHidingRankError::MalformedLibraRankCertificate);
    }
    Ok(())
}

/// Combine the selected companion, source, terminal-operand, and Libra
/// algebraic arguments.
///
/// The companion certificate proves that the full `C -> U` scalar matrix is
/// invertible and records the functional rewrite coefficients.  Its rank is
/// not added to `certified_joint_rank`: that ledger counts conditioned public
/// fields against disjoint fresh bank blocks, whereas `C -> U` is a change of
/// coordinates on the independently fresh companion.
///
/// The source certificate supplies a rank-`q` minor in bank cells
/// `512..1024`.  The terminal point supplies the nonzero diagonal
/// `eq(r,2047) I_5` in cells `1280..1285`; hence source plus terminal has rank
/// `q+5` even though source openings may also depend on those five cells.
/// Libra contributes rank 111 from the disjoint block `1024..1280`.
pub fn certify_zk_auth_joint_hiding_rank(
    source: AffineHighPaddingRankCertificate,
    terminal_point: &[Block128; ZK_AUTH_CAPSULE_BANK_VARS],
    lambda: Block128,
    gamma: Block128,
) -> Result<ZkAuthJointHidingRankCertificate, ZkAuthHidingRankError> {
    validate_random_block_layout()?;
    validate_source_rank(&source)?;
    let companion_change_of_variables = certify_zk_auth_companion_change_of_variables(gamma)?;

    let terminal_operand_pads = certify_terminal_blinding_rank(terminal_point)
        .map_err(|_| ZkAuthHidingRankError::ZeroTerminalBlindingWeight)?;
    validate_terminal_operand_rank(&terminal_operand_pads)?;
    let libra =
        certify_zk_mlecheck_mask_rank(lambda).map_err(|_| ZkAuthHidingRankError::LambdaZero)?;
    validate_libra_rank(&libra)?;

    let joint_source_terminal_rank = source.certified_rank + terminal_operand_pads.certified_rank;
    let public_conditioning_fields = source.distinct_query_count
        + terminal_operand_pads.certified_rank
        + libra.public_mask_dependent_fields;
    let certified_joint_rank = joint_source_terminal_rank + libra.certified_rank;

    Ok(ZkAuthJointHidingRankCertificate {
        source_rank: source.certified_rank,
        companion_change_rank: companion_change_of_variables.certified_rank,
        terminal_operand_rank: terminal_operand_pads.certified_rank,
        source,
        companion_change_of_variables,
        terminal_operand_pads,
        libra,
        source_coin_block: ZK_AUTH_SOURCE_COIN_RANDOM_BLOCK,
        libra_block: ZK_AUTH_LIBRA_RANDOM_BLOCK,
        terminal_operand_pad_block: ZK_AUTH_TERMINAL_OPERAND_PAD_RANDOM_BLOCK,
        joint_source_terminal_rank,
        public_conditioning_fields,
        certified_joint_rank,
        intended_relations: 1,
        fresh_bank_suffix_cells: ZK_AUTH_FRESH_BANK_SUFFIX_CELLS,
        fresh_companion_cells: ZK_AUTH_FRESH_COMPANION_CELLS,
        total_fresh_cells: ZK_AUTH_TOTAL_FRESH_CELLS,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use noid_fri_binius::zk_affine_code::ZkAffineLchCode;
    use noid_fri_binius::zk_capsule_algebra::certify_source_query_hiding_rank;

    fn terminal_point(seed: u128) -> [Block128; ZK_AUTH_CAPSULE_BANK_VARS] {
        std::array::from_fn(|index| Block128::from(seed + index as u128 + 1))
    }

    fn source_rank(leaves: &[usize]) -> AffineHighPaddingRankCertificate {
        certify_source_query_hiding_rank(&ZkAffineLchCode::selected().unwrap(), leaves).unwrap()
    }

    fn certify(
        source: AffineHighPaddingRankCertificate,
    ) -> Result<ZkAuthJointHidingRankCertificate, ZkAuthHidingRankError> {
        certify_zk_auth_joint_hiding_rank(
            source,
            &terminal_point(0xA11C_E200),
            Block128::from(2u128),
            Block128::from(3u128),
        )
    }

    fn vector(seed: u128) -> [Block128; ZK_AUTH_COMPANION_CHANGE_DIMENSION] {
        std::array::from_fn(|index| {
            let lane = index as u128 + 1;
            Block128::from(
                seed.rotate_left((index % 127) as u32)
                    ^ lane.wrapping_mul(0x9E37_79B9_7F4A_7C15_D1B5_4A32_D192_ED03),
            )
        })
    }

    fn linear_functional(
        weights: &[Block128; ZK_AUTH_COMPANION_CHANGE_DIMENSION],
        values: &[Block128; ZK_AUTH_COMPANION_CHANGE_DIMENSION],
    ) -> Block128 {
        weights
            .iter()
            .zip(values)
            .fold(Block128::ZERO, |sum, (&weight, &value)| {
                sum + weight * value
            })
    }

    fn companion_relation(
        pivot: usize,
        seed: u128,
    ) -> [Block128; ZK_AUTH_COMPANION_CHANGE_DIMENSION] {
        assert!(pivot < ZK_AUTH_COMPANION_CHANGE_DIMENSION);
        std::array::from_fn(|index| {
            if index < pivot || (index - pivot) % 37 != 0 {
                Block128::ZERO
            } else {
                Block128::from(seed.wrapping_add(index as u128 + 1))
            }
        })
    }

    #[test]
    fn max_source_rank_closes_joint_conditioning_ledger() {
        let leaves: Vec<_> = (0..64).collect();
        let certificate = certify(source_rank(&leaves)).unwrap();
        assert_eq!(certificate.source_rank, 512);
        assert_eq!(
            certificate.companion_change_rank,
            ZK_AUTH_COMPANION_CHANGE_RANK
        );
        assert_eq!(
            certificate
                .companion_change_of_variables
                .forward_bank_coefficient,
            Block128::ONE + certificate.companion_change_of_variables.gamma
        );
        assert_eq!(
            certificate
                .companion_change_of_variables
                .forward_companion_coefficient,
            certificate.companion_change_of_variables.gamma
        );
        certificate
            .companion_change_of_variables
            .validate()
            .unwrap();
        assert_eq!(certificate.terminal_operand_rank, 5);
        assert_eq!(certificate.joint_source_terminal_rank, 517);
        assert_eq!(certificate.libra.public_mask_dependent_fields, 112);
        assert_eq!(certificate.libra.certified_rank, 111);
        assert_eq!(certificate.libra.intended_terminal_relations, 1);
        assert_eq!(certificate.public_conditioning_fields, 629);
        assert_eq!(certificate.certified_joint_rank, 628);
        assert_eq!(certificate.intended_relations, 1);
        assert_eq!(
            certificate.source_coin_block,
            ZkAuthRandomBlock {
                start: 512,
                len: 512
            }
        );
        assert_eq!(
            certificate.libra_block,
            ZkAuthRandomBlock {
                start: 1_024,
                len: 256
            }
        );
        assert_eq!(
            certificate.terminal_operand_pad_block,
            ZkAuthRandomBlock {
                start: 1_280,
                len: 5
            }
        );
        assert_eq!(certificate.fresh_bank_suffix_cells, 1_536);
        assert_eq!(certificate.fresh_companion_cells, 2_048);
        assert_eq!(certificate.total_fresh_cells, 3_584);
    }

    #[test]
    fn full_companion_change_of_variables_is_bijective_for_multiple_gammas() {
        let bank = vector(0xB4A0_0001);
        let companion = vector(0xC09A_0002);
        for gamma in [
            Block128::from(2u128),
            Block128::from(3u128),
            Block128::from(0xA11C_E5E5_D00D_F00Du128),
        ] {
            let certificate = certify_zk_auth_companion_change_of_variables(gamma).unwrap();
            assert_eq!(certificate.dimension, 2_048);
            assert_eq!(certificate.certified_rank, 2_048);
            assert_eq!(
                certificate.forward_companion_coefficient * certificate.inverse_blend_coefficient,
                Block128::ONE
            );
            let blend = certificate.blend(&bank, &companion).unwrap();
            let recovered = certificate.recover_companion(&bank, &blend).unwrap();
            assert_eq!(recovered, companion, "full-vector roundtrip at {gamma:?}");
        }
    }

    #[test]
    fn arbitrary_linear_functionals_obey_the_same_companion_rewrite() {
        let bank = vector(0xB4A0_1001);
        let companion = vector(0xC09A_1002);
        for (gamma, weight_seed) in [
            (Block128::from(2u128), 0x1u128),
            (Block128::from(7u128), 0xA11C_u128),
            (Block128::from(0xDEAD_BEEF_CAFE_1234u128), 0xFACE_600Du128),
        ] {
            let certificate = certify_zk_auth_companion_change_of_variables(gamma).unwrap();
            let blend = certificate.blend(&bank, &companion).unwrap();
            let weights = vector(weight_seed);
            let bank_value = linear_functional(&weights, &bank);
            let companion_value = linear_functional(&weights, &companion);
            let blend_value = linear_functional(&weights, &blend);
            assert_eq!(
                blend_value,
                certificate.forward_bank_coefficient * bank_value
                    + certificate.forward_companion_coefficient * companion_value
            );
            assert_eq!(
                certificate
                    .recover_companion_functional(bank_value, blend_value)
                    .unwrap(),
                companion_value
            );
        }
    }

    #[test]
    fn conditioned_sigma_hyperplanes_are_bijective_for_multiple_pivots_and_gammas() {
        let bank = vector(0xB4A0_2001);
        let companion = vector(0xC09A_2002);
        for (pivot, gamma, relation_seed) in [
            (0usize, Block128::from(2u128), 0x10u128),
            (19usize, Block128::from(7u128), 0xA110u128),
            (
                ZK_AUTH_COMPANION_CHANGE_DIMENSION - 1,
                Block128::from(0xDEAD_BEEF_CAFE_1234u128),
                0xF00Du128,
            ),
        ] {
            let relation = companion_relation(pivot, relation_seed);
            let bank_claim = linear_functional(&relation, &bank);
            let companion_claim = linear_functional(&relation, &companion);
            let certificate = certify_zk_auth_conditioned_companion_hyperplane(
                &relation,
                bank_claim,
                companion_claim,
                gamma,
            )
            .unwrap();

            assert_eq!(certificate.relation_rank, 1);
            assert_eq!(certificate.pivot_index, Some(pivot));
            assert_eq!(certificate.pivot_coefficient, relation[pivot]);
            assert_ne!(certificate.pivot_coefficient, Block128::ZERO);
            assert_eq!(
                certificate.affine_fiber_dimension,
                ZK_AUTH_COMPANION_HYPERPLANE_DIMENSION
            );
            assert_eq!(
                certificate.conditioned_change_rank,
                ZK_AUTH_COMPANION_HYPERPLANE_DIMENSION
            );
            assert_eq!(
                certificate.expected_blend_claim,
                (Block128::ONE + gamma) * bank_claim + gamma * companion_claim
            );

            let blend = certificate.blend(&relation, &bank, &companion).unwrap();
            assert_eq!(
                linear_functional(&relation, &blend),
                certificate.expected_blend_claim
            );
            let recovered = certificate
                .validate_vectors(&relation, &bank, &companion, &blend)
                .unwrap();
            assert_eq!(recovered, companion);
            assert_eq!(
                certificate
                    .recover_companion(&relation, &bank, &blend)
                    .unwrap(),
                companion
            );
        }
    }

    #[test]
    fn conditioned_sigma_map_is_stable_under_bank_and_companion_fiber_moves() {
        let mut relation = [Block128::ZERO; ZK_AUTH_COMPANION_CHANGE_DIMENSION];
        relation[5] = Block128::from(11u128);
        relation[97] = Block128::from(13u128);
        relation[1_111] = Block128::from(17u128);
        let bank = vector(0xB4A0_3001);
        let companion = vector(0xC09A_3002);
        let bank_claim = linear_functional(&relation, &bank);
        let companion_claim = linear_functional(&relation, &companion);
        let certificate = certify_zk_auth_conditioned_companion_hyperplane(
            &relation,
            bank_claim,
            companion_claim,
            Block128::from(29u128),
        )
        .unwrap();
        let blend = certificate.blend(&relation, &bank, &companion).unwrap();

        // In characteristic two this two-coordinate displacement lies in
        // ker(t): t_5 (t_97 d) + t_97 (t_5 d) = 0.
        let displacement = Block128::from(0xA11C_Eu128);
        let mut moved_bank = bank;
        moved_bank[5] += relation[97] * displacement;
        moved_bank[97] += relation[5] * displacement;
        assert_eq!(linear_functional(&relation, &moved_bank), bank_claim);
        let moved_bank_blend = certificate
            .blend(&relation, &moved_bank, &companion)
            .unwrap();
        assert_ne!(moved_bank_blend, blend);
        assert_eq!(
            linear_functional(&relation, &moved_bank_blend),
            certificate.expected_blend_claim
        );
        assert_eq!(
            certificate
                .validate_vectors(&relation, &moved_bank, &companion, &moved_bank_blend,)
                .unwrap(),
            companion
        );

        // At fixed B, a move inside the C-fiber maps to a move inside the
        // U-fiber and the inverse recovers that exact point.
        let mut moved_companion = companion;
        moved_companion[5] += relation[97] * displacement;
        moved_companion[97] += relation[5] * displacement;
        assert_eq!(
            linear_functional(&relation, &moved_companion),
            companion_claim
        );
        let moved_companion_blend = certificate
            .blend(&relation, &bank, &moved_companion)
            .unwrap();
        assert_ne!(moved_companion_blend, blend);
        assert_eq!(
            linear_functional(&relation, &moved_companion_blend),
            certificate.expected_blend_claim
        );
        assert_eq!(
            certificate
                .validate_vectors(&relation, &bank, &moved_companion, &moved_companion_blend,)
                .unwrap(),
            moved_companion
        );

        // Surjectivity is checked independently of a forward-generated
        // companion: project an arbitrary U onto the certified target fiber,
        // invert it, and map the result forward again.
        let mut arbitrary_target = vector(0xAFF1_4E00);
        let target_error =
            linear_functional(&relation, &arbitrary_target) + certificate.expected_blend_claim;
        arbitrary_target[5] += target_error * relation[5].invert();
        assert_eq!(
            linear_functional(&relation, &arbitrary_target),
            certificate.expected_blend_claim
        );
        let arbitrary_preimage = certificate
            .recover_companion(&relation, &bank, &arbitrary_target)
            .unwrap();
        assert_eq!(
            linear_functional(&relation, &arbitrary_preimage),
            companion_claim
        );
        assert_eq!(
            certificate
                .blend(&relation, &bank, &arbitrary_preimage)
                .unwrap(),
            arbitrary_target
        );
    }

    #[test]
    fn zero_relation_uses_full_space_and_requires_zero_claims() {
        let relation = [Block128::ZERO; ZK_AUTH_COMPANION_CHANGE_DIMENSION];
        let bank = vector(0xB4A0_4001);
        let companion = vector(0xC09A_4002);
        let certificate = certify_zk_auth_conditioned_companion_hyperplane(
            &relation,
            Block128::ZERO,
            Block128::ZERO,
            Block128::from(31u128),
        )
        .unwrap();
        assert_eq!(certificate.relation_rank, 0);
        assert_eq!(certificate.pivot_index, None);
        assert_eq!(certificate.pivot_coefficient, Block128::ZERO);
        assert_eq!(
            certificate.affine_fiber_dimension,
            ZK_AUTH_COMPANION_CHANGE_DIMENSION
        );
        assert_eq!(
            certificate.conditioned_change_rank,
            ZK_AUTH_COMPANION_CHANGE_DIMENSION
        );
        assert_eq!(certificate.expected_blend_claim, Block128::ZERO);
        let blend = certificate.blend(&relation, &bank, &companion).unwrap();
        assert_eq!(
            certificate
                .validate_vectors(&relation, &bank, &companion, &blend)
                .unwrap(),
            companion
        );

        let fake_rank_one = ZkAuthConditionedCompanionHyperplaneCertificate {
            relation_rank: 1,
            affine_fiber_dimension: ZK_AUTH_COMPANION_HYPERPLANE_DIMENSION,
            conditioned_change_rank: ZK_AUTH_COMPANION_HYPERPLANE_DIMENSION,
            pivot_index: Some(0),
            pivot_coefficient: Block128::ONE,
            ..certificate
        };
        assert_eq!(
            fake_rank_one.validate(&relation),
            Err(ZkAuthHidingRankError::MalformedConditionedCompanionHyperplaneCertificate)
        );

        for (bank_claim, companion_claim) in [
            (Block128::ONE, Block128::ZERO),
            (Block128::ZERO, Block128::ONE),
            (Block128::ONE, Block128::ONE),
        ] {
            assert_eq!(
                certify_zk_auth_conditioned_companion_hyperplane(
                    &relation,
                    bank_claim,
                    companion_claim,
                    Block128::from(31u128),
                ),
                Err(ZkAuthHidingRankError::ZeroRelationRequiresZeroClaims)
            );
        }
    }

    #[test]
    fn conditioned_sigma_rejects_malformed_relations_endpoints_and_certificate_tampering() {
        let relation = companion_relation(11, 0x5000);
        let bank = vector(0xB4A0_5001);
        let companion = vector(0xC09A_5002);
        let bank_claim = linear_functional(&relation, &bank);
        let companion_claim = linear_functional(&relation, &companion);
        let honest = certify_zk_auth_conditioned_companion_hyperplane(
            &relation,
            bank_claim,
            companion_claim,
            Block128::from(37u128),
        )
        .unwrap();
        let blend = honest.blend(&relation, &bank, &companion).unwrap();

        assert_eq!(
            certify_zk_auth_conditioned_companion_hyperplane(
                &relation[..ZK_AUTH_COMPANION_CHANGE_DIMENSION - 1],
                bank_claim,
                companion_claim,
                Block128::from(37u128),
            ),
            Err(ZkAuthHidingRankError::MalformedCompanionRelationLength)
        );
        assert_eq!(
            honest.validate(&relation[..ZK_AUTH_COMPANION_CHANGE_DIMENSION - 1]),
            Err(ZkAuthHidingRankError::MalformedCompanionRelationLength)
        );
        for gamma in [Block128::ZERO, Block128::ONE] {
            assert_eq!(
                certify_zk_auth_conditioned_companion_hyperplane(
                    &relation,
                    bank_claim,
                    companion_claim,
                    gamma,
                ),
                Err(ZkAuthHidingRankError::GammaEndpoint)
            );
        }

        let malformed = [
            ZkAuthConditionedCompanionHyperplaneCertificate {
                gamma: honest.gamma + Block128::ONE,
                ..honest
            },
            ZkAuthConditionedCompanionHyperplaneCertificate {
                relation_len: honest.relation_len - 1,
                ..honest
            },
            ZkAuthConditionedCompanionHyperplaneCertificate {
                relation_rank: 0,
                ..honest
            },
            ZkAuthConditionedCompanionHyperplaneCertificate {
                affine_fiber_dimension: honest.affine_fiber_dimension + 1,
                ..honest
            },
            ZkAuthConditionedCompanionHyperplaneCertificate {
                conditioned_change_rank: honest.conditioned_change_rank + 1,
                ..honest
            },
            ZkAuthConditionedCompanionHyperplaneCertificate {
                pivot_index: Some(12),
                ..honest
            },
            ZkAuthConditionedCompanionHyperplaneCertificate {
                pivot_coefficient: honest.pivot_coefficient + Block128::ONE,
                ..honest
            },
            ZkAuthConditionedCompanionHyperplaneCertificate {
                expected_blend_claim: honest.expected_blend_claim + Block128::ONE,
                ..honest
            },
            ZkAuthConditionedCompanionHyperplaneCertificate {
                forward_bank_coefficient: honest.forward_bank_coefficient + Block128::ONE,
                ..honest
            },
            ZkAuthConditionedCompanionHyperplaneCertificate {
                forward_companion_coefficient: honest.forward_companion_coefficient + Block128::ONE,
                ..honest
            },
            ZkAuthConditionedCompanionHyperplaneCertificate {
                inverse_blend_coefficient: honest.inverse_blend_coefficient + Block128::ONE,
                ..honest
            },
            ZkAuthConditionedCompanionHyperplaneCertificate {
                inverse_bank_coefficient: honest.inverse_bank_coefficient + Block128::ONE,
                ..honest
            },
        ];
        for certificate in malformed {
            assert_eq!(
                certificate.validate(&relation),
                Err(ZkAuthHidingRankError::MalformedConditionedCompanionHyperplaneCertificate)
            );
        }

        // Correlated claim forgeries remain internally well-formed affine
        // statements, but the complete vectors reject them.
        let forged_bank_claim = bank_claim + Block128::ONE;
        let forged_bank = ZkAuthConditionedCompanionHyperplaneCertificate {
            bank_claim: forged_bank_claim,
            expected_blend_claim: honest.forward_bank_coefficient * forged_bank_claim
                + honest.gamma * companion_claim,
            ..honest
        };
        forged_bank.validate(&relation).unwrap();
        assert_eq!(
            forged_bank.validate_vectors(&relation, &bank, &companion, &blend),
            Err(ZkAuthHidingRankError::ConditionedBankClaimMismatch)
        );
        let forged_companion_claim = companion_claim + Block128::ONE;
        let forged_companion = ZkAuthConditionedCompanionHyperplaneCertificate {
            companion_claim: forged_companion_claim,
            expected_blend_claim: honest.forward_bank_coefficient * bank_claim
                + honest.gamma * forged_companion_claim,
            ..honest
        };
        forged_companion.validate(&relation).unwrap();
        assert_eq!(
            forged_companion.validate_vectors(&relation, &bank, &companion, &blend),
            Err(ZkAuthHidingRankError::ConditionedCompanionClaimMismatch)
        );

        let mut wrong_claim_blend = blend;
        wrong_claim_blend[11] += Block128::ONE;
        assert_eq!(
            honest.validate_vectors(&relation, &bank, &companion, &wrong_claim_blend),
            Err(ZkAuthHidingRankError::ConditionedBlendClaimMismatch)
        );
        let mut wrong_vector_blend = blend;
        let displacement = Block128::from(41u128);
        wrong_vector_blend[11] += relation[48] * displacement;
        wrong_vector_blend[48] += relation[11] * displacement;
        assert_eq!(
            linear_functional(&relation, &wrong_vector_blend),
            honest.expected_blend_claim
        );
        assert_eq!(
            honest.validate_vectors(&relation, &bank, &companion, &wrong_vector_blend),
            Err(ZkAuthHidingRankError::ConditionedBlendVectorMismatch)
        );
    }

    #[test]
    fn companion_endpoints_and_coefficient_tampering_reject() {
        for gamma in [Block128::ZERO, Block128::ONE] {
            assert_eq!(
                certify_zk_auth_companion_change_of_variables(gamma),
                Err(ZkAuthHidingRankError::GammaEndpoint)
            );
        }

        let honest = certify_zk_auth_companion_change_of_variables(Block128::from(3u128)).unwrap();
        for malformed in [
            ZkAuthCompanionChangeOfVariablesCertificate {
                certified_rank: honest.certified_rank - 1,
                ..honest
            },
            ZkAuthCompanionChangeOfVariablesCertificate {
                forward_bank_coefficient: honest.forward_bank_coefficient + Block128::ONE,
                ..honest
            },
            ZkAuthCompanionChangeOfVariablesCertificate {
                forward_companion_coefficient: honest.forward_companion_coefficient + Block128::ONE,
                ..honest
            },
            ZkAuthCompanionChangeOfVariablesCertificate {
                inverse_blend_coefficient: honest.inverse_blend_coefficient + Block128::ONE,
                ..honest
            },
            ZkAuthCompanionChangeOfVariablesCertificate {
                inverse_bank_coefficient: honest.inverse_bank_coefficient + Block128::ONE,
                ..honest
            },
        ] {
            assert_eq!(
                malformed.validate(),
                Err(ZkAuthHidingRankError::MalformedCompanionChangeOfVariablesCertificate)
            );
            assert_eq!(
                malformed.recover_companion_functional(Block128::ONE, Block128::ONE),
                Err(ZkAuthHidingRankError::MalformedCompanionChangeOfVariablesCertificate)
            );
        }
    }

    #[test]
    fn duplicate_and_small_source_queries_use_only_distinct_position_rank() {
        let repeated = certify(source_rank(&[17usize; 64])).unwrap();
        assert_eq!(repeated.source_rank, 8);
        assert_eq!(repeated.joint_source_terminal_rank, 13);
        assert_eq!(repeated.certified_joint_rank, 124);

        let small = certify(source_rank(&[3, 3, 9, 11])).unwrap();
        assert_eq!(small.source_rank, 24);
        assert_eq!(small.joint_source_terminal_rank, 29);
        assert_eq!(small.certified_joint_rank, 140);
    }

    #[test]
    fn malformed_source_and_degenerate_challenges_reject() {
        let honest = source_rank(&[0, 1, 2]);
        for malformed in [
            AffineHighPaddingRankCertificate {
                certified_rank: honest.certified_rank - 1,
                ..honest
            },
            AffineHighPaddingRankCertificate {
                independent_coeff_start: 511,
                ..honest
            },
            AffineHighPaddingRankCertificate {
                independent_coeff_len: 511,
                ..honest
            },
            AffineHighPaddingRankCertificate {
                nonzero_factor_level: AFFINE_FUNDAMENTAL_LOG - 1,
                ..honest
            },
            AffineHighPaddingRankCertificate {
                distinct_query_count: 513,
                certified_rank: 513,
                ..honest
            },
        ] {
            assert_eq!(
                certify(malformed),
                Err(ZkAuthHidingRankError::MalformedSourceRankCertificate)
            );
        }

        let mut zero_kappa = terminal_point(0xA11C_E201);
        zero_kappa[4] = Block128::ZERO;
        assert_eq!(
            certify_zk_auth_joint_hiding_rank(
                honest,
                &zero_kappa,
                Block128::from(2u128),
                Block128::from(3u128),
            ),
            Err(ZkAuthHidingRankError::ZeroTerminalBlindingWeight)
        );
        assert_eq!(
            certify_zk_auth_joint_hiding_rank(
                honest,
                &terminal_point(0xA11C_E202),
                Block128::ZERO,
                Block128::from(3u128),
            ),
            Err(ZkAuthHidingRankError::LambdaZero)
        );
        for gamma in [Block128::ZERO, Block128::ONE] {
            assert_eq!(
                certify_zk_auth_joint_hiding_rank(
                    honest,
                    &terminal_point(0xA11C_E203),
                    Block128::from(2u128),
                    gamma,
                ),
                Err(ZkAuthHidingRankError::GammaEndpoint)
            );
        }
    }

    fn matrix_rank(mut matrix: Vec<Vec<Block128>>) -> usize {
        if matrix.is_empty() {
            return 0;
        }
        let columns = matrix[0].len();
        assert!(matrix.iter().all(|row| row.len() == columns));
        let mut rank = 0;
        for column in 0..columns {
            let Some(pivot) =
                (rank..matrix.len()).find(|&row| matrix[row][column] != Block128::ZERO)
            else {
                continue;
            };
            matrix.swap(rank, pivot);
            let inverse = matrix[rank][column].invert();
            for value in &mut matrix[rank][column..] {
                *value *= inverse;
            }
            let pivot_row = matrix[rank].clone();
            for row in 0..matrix.len() {
                if row == rank {
                    continue;
                }
                let factor = matrix[row][column];
                if factor == Block128::ZERO {
                    continue;
                }
                for col in column..columns {
                    matrix[row][col] += factor * pivot_row[col];
                }
            }
            rank += 1;
            if rank == matrix.len() {
                break;
            }
        }
        rank
    }

    #[test]
    fn explicit_terminal_pad_matrices_pin_distinct_shared_and_reused_rank() {
        let kappa_a = Block128::from(5u128);
        let kappa_b = Block128::from(7u128);

        let mut distinct = vec![vec![Block128::ZERO; 5]; 5];
        for claim in 0..5 {
            distinct[claim][claim] = kappa_a;
        }
        assert_eq!(matrix_rank(distinct), 5);

        let shared = vec![vec![kappa_a]; 5];
        assert_eq!(matrix_rank(shared), 1);

        let mut reused = vec![vec![Block128::ZERO; 5]; 10];
        let mut fresh = vec![vec![Block128::ZERO; 10]; 10];
        for (proof, kappa) in [kappa_a, kappa_b].into_iter().enumerate() {
            for claim in 0..5 {
                let row = proof * 5 + claim;
                reused[row][claim] = kappa;
                fresh[row][proof * 5 + claim] = kappa;
            }
        }
        assert_eq!(matrix_rank(reused), 5);
        assert_eq!(matrix_rank(fresh), 10);
    }
}
