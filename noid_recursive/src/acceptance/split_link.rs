// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! The SPLIT self-verification link — the link half of the two-level π.
//!
//! A split link verifies TWO proofs: the previous link (same link shape,
//! possibly a different link class) and one block proof `π_block` (the
//! standalone block class of this link class's ladder slot,
//! [`super::block_class`]). The block classes live on a LADDER of shapes
//! (one capacity per shape — an [R] replay's transcript schedule is
//! structural in the verified shape and spec, so each link class hosts
//! exactly one block class); all link classes share ONE shape and ONE
//! public-IO spec, so `[R]_prev` is structurally identical everywhere and
//! only baked constants differ per class (its slot's block-class digest
//! and spec).
//!
//! Nothing of any LINK class is baked into a link matrix. The ladder's
//! link-class matrix digests and their matrix/spec/PCS/sidecar composite
//! digests ride public IO as two paired WHITELIST lane blocks. Every
//! non-genesis link inherits both unchanged and the decider pins/recomputes
//! them at the tip. `[R]_prev` selects both identities as
//! `Σ_a β_a·WL_a + g·D_T`; the raw digest binds the Field statement and the
//! composite digest binds its post-commit sidecar context. The block-class
//! identities are baked because the block class has no self-reference.
//!
//! Deferred matrix claims accumulate in PER-MATRIX LANES: one lane per
//! link class plus one lane per block class, each `2·k_log + 1` point
//! lanes, a value lane and a LIVENESS bit. A link runs exactly TWO fold
//! twins — the `[R]_prev` claim folds into the β-muxed link lane, the
//! `[R]_B` claim into its own slot's block lane — and pins every other
//! lane through unchanged. Liveness is monotone (`out = sel OR in`),
//! starts dead at the chain root (the genesis dummy T carries all-zero
//! IO) and gates each fold's incoming claim: the old genesis gating,
//! generalized per lane. A selected lane's outgoing liveness is
//! identically 1 (char-2 OR against any incoming value). The `g = 1` arm pins
//! T's commitment to the canonical full-identity ghost witness and pins its
//! IO to zero, so bootstrap cannot plant accumulator lanes.
//!
//! Chain rules: the block proof's exposed `start_acc` must equal the
//! previous link's exposed block accumulator (or the class's genesis
//! accumulator under `g = 1`), and its `end_acc` is pinned to this
//! link's own block-accumulator IO. Block-internal transition validity
//! (tip, state, depth, counters and epoch) is the block class's job.
//!
//! The decider verifies the tip natively against its published class
//! matrix, pins both whitelist blocks, and evaluates each LIVE lane's
//! accumulated claim against the published matrix — one native MLE pass per
//! USED matrix; dead lanes need no matrix at all. A first block link may be a
//! tip with `g = 1`: the flag says its predecessor is T, not that the tip is T.

use std::sync::Arc;

use noid_chain::BlockHeader;
use noid_ivc_core::challenger::{Challenger, FsLaneChallenger};
use noid_ivc_core::field::F128;
use noid_ivc_core::field_circuit::{FieldR1csBuilder, FsChannelTrace, LinExpr};
use noid_ivc_core::field_r1cs::{FieldR1cs, SparseFieldMatrix};
use noid_ivc_core::matrix_claim::{
    prove_matrix_claim_fold, stacked_matrix_mle_eval, FreshLincheckClaim, MatrixAccClaim,
    MatrixClaimEvaluator, MatrixFoldProof,
};
use noid_ivc_core::pcs::{Commitment, PcsParams};
use noid_ivc_core::proof::{pcs_params_statement_bytes, FieldR1csProof, FieldShape, R1csClaim};
use noid_ivc_core::public_io::{PublicIoSpec, WitnessSlice};
use noid_ivc_core::verifier::{
    verify_field_deferred_matrix_with_post_commit_context,
    verify_field_with_public_io_and_post_commit_context, VerifyError,
};

use super::block_class::{
    is_production_block_io_spec, BlockClass, BlockProofEnvelope, BLOCK_IO_END_ACC,
    BLOCK_IO_START_ACC,
};
use super::link::block_acc_lanes;
use super::trace::matrix_fold::{
    verify_matrix_claim_fold_trace, MatrixAccClaimTrace, MatrixFoldProofTrace,
};
use super::trace::r_pcs_region::{
    finalize_r_pcs_link_region, prepare_r_pcs_link_columns_universal,
    prepare_r_pcs_link_genesis_ghost, RPcsLinkRegionPreparation, RPcsLinkUniversalGeometry,
    RPcsProof,
};
use super::trace::self_verify::{
    alloc_flat_digest, flat_digest_lanes, lagrange_weights_window_trace,
    verify_field_trace_deferred_region_with_post_commit_context,
    verify_field_trace_deferred_region_with_post_commit_context_expr, FieldR1csProofTrace,
    FlatDigestExpr, PcsWalkObligations,
};
use super::trace::{mul, pin_eq};
use crate::accumulator::{genesis_accumulator, ChainAccumulator, ChainAccumulatorLaneError};
use crate::region_sidecar::{
    block_post_commit_class_digest, decode_block_region_sidecar_bounded,
    decode_link_region_sidecar_bounded, link_post_commit_class_digest,
    verify_block_region_sidecar_post_commit, verify_block_region_sidecar_trace_post_commit,
    verify_link_region_sidecar_post_commit, verify_link_region_sidecar_trace_post_commit,
    LinkRegionProverPlan, LinkRegionSidecarProof, LinkRegionSidecarVk, RegionSidecarError,
};
use noid_core::Block128;
use noid_ivc_prover::field_prover::prove_field_with_public_io_and_post_commit_context;

/// One ladder slot's protocol constants, as seen by EVERY link class (the
/// lane widths must be known to lay out the shared IO). The full block
/// spec is only needed by the slot's OWN link class.
#[derive(Clone, Debug)]
pub struct LadderSlotInfo {
    /// The consensus user-tx capacity this slot hosts.
    pub tier: usize,
    /// The block class shape (fixes the slot's fold-lane width).
    pub b_shape: FieldShape,
    /// The block class statement digest ([R]_B verifies against it; baked
    /// into the slot's link-class matrix).
    pub b_digest: [u8; 32],
    /// Exact block PCS geometry.  The whole ladder is frozen into one
    /// universal link-sidecar descriptor; mixed query counts are rejected.
    pub b_pcs_params: PcsParams,
    /// Composite identity of the exact block matrix/spec/PCS/sidecar class.
    pub b_post_commit_class_digest: [u8; 32],
    /// Digest of the ordered six-child block sidecar VK.  Keeping this lane
    /// separately makes a mismatched but internally valid block authority
    /// detectable before its hosted link class is materialized.
    pub b_sidecar_vk_digest: [u8; 32],
}

/// Frozen production Field dimensions for the four consensus Block classes.
pub const CANONICAL_BLOCK_CLASS_MS: [usize;
    noid_chain::consensus::params::USER_TX_CLASS_TIERS.len()] = [22, 23, 23, 24];
/// Frozen production Field dimension shared by every Link class.
pub const CANONICAL_LINK_CLASS_M: usize = 24;
/// Frozen production BaseFold inverse-rate logarithm.
pub const CANONICAL_PCS_LOG_INV_RATE: usize = 2;
/// Frozen production BaseFold row-batch logarithm.
pub const CANONICAL_PCS_LOG_BATCH_SIZE: usize = 5;

/// Validation failures for the production four-slot universal ladder.
///
/// The legacy one-slot benchmark constructs [`SplitLinkClass`] directly.  A
/// production deployment must instead enter through
/// [`CanonicalSplitLinkLadder`], which makes the complete consensus ladder a
/// typed, validated object before any per-slot link class is frozen.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CanonicalLadderError {
    SlotCount {
        expected: usize,
        actual: usize,
    },
    TierMismatch {
        slot: usize,
        expected: usize,
        actual: usize,
    },
    LinkClassSize {
        expected: usize,
        actual: usize,
    },
    LinkShape,
    LinkPcsShape,
    LinkPcsParameters,
    LinkIoDoesNotFit,
    BlockClassSize {
        slot: usize,
        expected: usize,
        actual: usize,
    },
    BlockShape {
        slot: usize,
    },
    BlockPcsShape {
        slot: usize,
    },
    BlockPcsParameters {
        slot: usize,
    },
    UnsupportedUniversalPcs,
    SlotOutOfRange {
        slot: usize,
    },
    BlockClassTier {
        slot: usize,
    },
    BlockClassIdentity {
        slot: usize,
    },
    BlockClassShape {
        slot: usize,
    },
    BlockClassDigest {
        slot: usize,
    },
    BlockClassPcs {
        slot: usize,
    },
    BlockClassPostCommit {
        slot: usize,
    },
    BlockClassSidecarVk {
        slot: usize,
    },
    BlockMatrixShape {
        slot: usize,
    },
    BlockMatrixDigest {
        slot: usize,
    },
    BlockEnvelopePcs {
        slot: usize,
    },
    BlockEnvelopeIo {
        slot: usize,
    },
    BlockEnvelopeSidecar {
        slot: usize,
    },
    BlockEnvelopeProof {
        slot: usize,
    },
    MaterializedClassCount {
        expected: usize,
        actual: usize,
    },
    MaterializedClassShape {
        slot: usize,
    },
    MaterializedClassPcs {
        slot: usize,
    },
    MaterializedClassLadder {
        slot: usize,
    },
    MaterializedClassSlot {
        slot: usize,
        actual: usize,
    },
    MaterializedClassIdentity {
        slot: usize,
    },
    MaterializedSidecarIdentity {
        slot: usize,
    },
    MaterializedGenesisIdentity {
        slot: usize,
    },
}

impl std::fmt::Display for CanonicalLadderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SlotCount { expected, actual } => {
                write!(
                    f,
                    "canonical ladder requires {expected} slots, got {actual}"
                )
            }
            Self::TierMismatch {
                slot,
                expected,
                actual,
            } => write!(
                f,
                "canonical ladder slot {slot} must be B{expected}, got B{actual}"
            ),
            Self::LinkClassSize { expected, actual } => write!(
                f,
                "canonical Link class must use m{expected}, got m{actual}"
            ),
            Self::LinkShape => write!(f, "split-link shape must be one full Field block"),
            Self::LinkPcsShape => write!(f, "link PCS descriptor does not match link shape"),
            Self::LinkPcsParameters => {
                write!(
                    f,
                    "link PCS descriptor is not the frozen production profile"
                )
            }
            Self::LinkIoDoesNotFit => {
                write!(f, "canonical split-link IO does not fit the link shape")
            }
            Self::BlockClassSize {
                slot,
                expected,
                actual,
            } => write!(
                f,
                "canonical block slot {slot} must use m{expected}, got m{actual}"
            ),
            Self::BlockShape { slot } => {
                write!(f, "block slot {slot} must be one canonical Field block")
            }
            Self::BlockPcsShape { slot } => {
                write!(f, "block PCS descriptor does not match slot {slot} shape")
            }
            Self::BlockPcsParameters { slot } => write!(
                f,
                "block slot {slot} PCS descriptor is not the frozen production profile"
            ),
            Self::UnsupportedUniversalPcs => write!(
                f,
                "link and block PCS descriptors do not share supported universal geometry"
            ),
            Self::SlotOutOfRange { slot } => write!(f, "ladder slot {slot} is out of range"),
            Self::BlockClassTier { slot } => {
                write!(f, "block class tier does not match ladder slot {slot}")
            }
            Self::BlockClassIdentity { slot } => {
                write!(f, "block class {slot} has an invalid frozen identity")
            }
            Self::BlockClassShape { slot } => {
                write!(f, "block class shape does not match ladder slot {slot}")
            }
            Self::BlockClassDigest { slot } => {
                write!(f, "block class digest does not match ladder slot {slot}")
            }
            Self::BlockClassPcs { slot } => {
                write!(f, "block class PCS does not match ladder slot {slot}")
            }
            Self::BlockClassPostCommit { slot } => write!(
                f,
                "block post-commit class identity does not match ladder slot {slot}"
            ),
            Self::BlockClassSidecarVk { slot } => {
                write!(f, "block sidecar VK does not match ladder slot {slot}")
            }
            Self::BlockMatrixShape { slot } => {
                write!(f, "block matrix shape does not match ladder slot {slot}")
            }
            Self::BlockMatrixDigest { slot } => {
                write!(f, "block matrix digest does not match ladder slot {slot}")
            }
            Self::BlockEnvelopePcs { slot } => {
                write!(f, "sample block PCS does not match ladder slot {slot}")
            }
            Self::BlockEnvelopeIo { slot } => {
                write!(f, "sample block IO does not match ladder slot {slot}")
            }
            Self::BlockEnvelopeSidecar { slot } => {
                write!(f, "sample block sidecar does not match ladder slot {slot}")
            }
            Self::BlockEnvelopeProof { slot } => {
                write!(
                    f,
                    "sample block proof does not verify for ladder slot {slot}"
                )
            }
            Self::MaterializedClassCount { expected, actual } => write!(
                f,
                "materialized ladder requires {expected} classes, got {actual}"
            ),
            Self::MaterializedClassShape { slot } => {
                write!(f, "materialized link class {slot} has a different shape")
            }
            Self::MaterializedClassPcs { slot } => {
                write!(
                    f,
                    "materialized link class {slot} has different PCS parameters"
                )
            }
            Self::MaterializedClassLadder { slot } => {
                write!(f, "materialized link class {slot} has a different ladder")
            }
            Self::MaterializedClassSlot { slot, actual } => write!(
                f,
                "materialized link class {slot} advertises ladder slot {actual}"
            ),
            Self::MaterializedClassIdentity { slot } => {
                write!(
                    f,
                    "materialized link class {slot} has an invalid frozen identity"
                )
            }
            Self::MaterializedSidecarIdentity { slot } => write!(
                f,
                "materialized link class {slot} has a different universal sidecar identity"
            ),
            Self::MaterializedGenesisIdentity { slot } => write!(
                f,
                "materialized link class {slot} has a different genesis identity"
            ),
        }
    }
}

impl std::error::Error for CanonicalLadderError {}

/// One slot's already-frozen block artifacts used to materialize its link
/// class.  All four values are consumed under one
/// [`CanonicalSplitLinkLadder`] descriptor, so shape/PCS/ladder drift between
/// link classes is rejected before the expensive freeze begins.
#[derive(Clone, Copy)]
pub struct SplitLinkSlotMaterial<'a> {
    pub block_class: &'a BlockClass,
    pub sample_block: &'a BlockProofEnvelope,
    pub block_matrix: &'a FieldR1cs,
}

/// The sole production universal-ladder descriptor.
///
/// Construction enforces the exact consensus order `B8, B32, B64, B255`,
/// each block shape's exact PCS dimension, and the common query geometry used
/// by the universal link sidecar.  Reusing this object to freeze every slot
/// guarantees that all four link classes receive byte-identical ladder data,
/// link shape, and link PCS parameters.
#[derive(Clone, Debug)]
pub struct CanonicalSplitLinkLadder {
    link_shape: FieldShape,
    link_pcs_params: PcsParams,
    slots: [LadderSlotInfo; noid_chain::consensus::params::USER_TX_CLASS_TIERS.len()],
}

fn is_canonical_pcs_profile(params: &PcsParams) -> bool {
    params.log_inv_rate == CANONICAL_PCS_LOG_INV_RATE
        && params.log_batch_size == CANONICAL_PCS_LOG_BATCH_SIZE
        && params.profile == Default::default()
}

/// Materialize an ordered fixed-size registry whose first entry constructs a
/// shared bootstrap and whose remaining entries consume it.  Keeping this
/// orchestration generic makes the one-bootstrap ownership rule testable
/// without building production-size recursive matrices.
#[cfg(test)]
fn materialize_with_shared_bootstrap<T, C, S, const N: usize>(
    materials: [T; N],
    mut freeze_first: impl FnMut(usize, T) -> (C, S),
    mut freeze_shared: impl FnMut(usize, T, &S) -> C,
) -> [C; N] {
    let mut materials = materials.into_iter().enumerate();
    let (first_slot, first_material) = materials
        .next()
        .expect("a shared-bootstrap registry has at least one slot");
    let (first, shared) = freeze_first(first_slot, first_material);

    let mut classes = Vec::with_capacity(N);
    classes.push(first);
    for (slot, material) in materials {
        classes.push(freeze_shared(slot, material, &shared));
    }
    classes
        .try_into()
        .unwrap_or_else(|_| unreachable!("fixed registry count was preallocated"))
}

impl CanonicalSplitLinkLadder {
    pub const SLOT_COUNT: usize = noid_chain::consensus::params::USER_TX_CLASS_TIERS.len();

    /// Validate an externally materialized descriptor.  `slots` is a `Vec`
    /// deliberately: decoded/configured ladders must prove their exact length,
    /// not gain it from an array type supplied by the caller.
    pub fn try_new(
        link_shape: FieldShape,
        link_pcs_params: PcsParams,
        slots: Vec<LadderSlotInfo>,
    ) -> Result<Self, CanonicalLadderError> {
        let actual = slots.len();
        let slots: [LadderSlotInfo; Self::SLOT_COUNT] =
            slots
                .try_into()
                .map_err(|_| CanonicalLadderError::SlotCount {
                    expected: Self::SLOT_COUNT,
                    actual,
                })?;

        for (slot, (&expected, info)) in noid_chain::consensus::params::USER_TX_CLASS_TIERS
            .iter()
            .zip(&slots)
            .enumerate()
        {
            if info.tier != expected {
                return Err(CanonicalLadderError::TierMismatch {
                    slot,
                    expected,
                    actual: info.tier,
                });
            }
        }
        if link_shape.m != CANONICAL_LINK_CLASS_M {
            return Err(CanonicalLadderError::LinkClassSize {
                expected: CANONICAL_LINK_CLASS_M,
                actual: link_shape.m,
            });
        }
        if link_shape.m >= usize::BITS as usize
            || link_shape.m != link_shape.k_log
            || link_shape.k_skip > link_shape.k_log
            || link_shape.k_skip != noid_ivc_core::zerocheck::K_SKIP
            || link_shape.const_pin != Some(0)
        {
            return Err(CanonicalLadderError::LinkShape);
        }
        if link_shape.m.checked_add(noid_ivc_core::pcs::LOG_PACKING) != Some(link_pcs_params.m) {
            return Err(CanonicalLadderError::LinkPcsShape);
        }
        if !is_canonical_pcs_profile(&link_pcs_params) {
            return Err(CanonicalLadderError::LinkPcsParameters);
        }
        for (slot, (info, &expected_m)) in slots.iter().zip(&CANONICAL_BLOCK_CLASS_MS).enumerate() {
            if info.b_shape.m != expected_m {
                return Err(CanonicalLadderError::BlockClassSize {
                    slot,
                    expected: expected_m,
                    actual: info.b_shape.m,
                });
            }
            if info.b_shape.m >= usize::BITS as usize
                || info.b_shape.m != info.b_shape.k_log
                || info.b_shape.k_skip > info.b_shape.k_log
                || info.b_shape.k_skip != noid_ivc_core::zerocheck::K_SKIP
                || info.b_shape.const_pin != Some(0)
            {
                return Err(CanonicalLadderError::BlockShape { slot });
            }
            if info.b_shape.m.checked_add(noid_ivc_core::pcs::LOG_PACKING)
                != Some(info.b_pcs_params.m)
            {
                return Err(CanonicalLadderError::BlockPcsShape { slot });
            }
            if !is_canonical_pcs_profile(&info.b_pcs_params) {
                return Err(CanonicalLadderError::BlockPcsParameters { slot });
            }
        }
        let spec = split_io_spec(link_shape.k_log, &slots);
        if !spec.io_slice.fits(link_shape.m) || spec.io_len > spec.io_slice.len() {
            return Err(CanonicalLadderError::LinkIoDoesNotFit);
        }

        let link_rate = link_pcs_params.log_inv_rate;
        // `default_fri_queries` is intentionally total only on the supported
        // table and panics otherwise.  Check its domain before deriving the
        // query count that the authoritative universal-geometry constructor
        // requires as input; that constructor then validates every group.
        if !(1..=5).contains(&link_rate) {
            return Err(CanonicalLadderError::UnsupportedUniversalPcs);
        }
        let n_queries = noid_ivc_core::pcs::default_fri_queries(link_rate);
        let block_params = slots
            .iter()
            .map(|slot| slot.b_pcs_params.clone())
            .collect::<Vec<_>>();
        RPcsLinkUniversalGeometry::new(&link_pcs_params, &block_params, n_queries)
            .map_err(|_| CanonicalLadderError::UnsupportedUniversalPcs)?;

        Ok(Self {
            link_shape,
            link_pcs_params,
            slots,
        })
    }

    /// Materialize the descriptor directly from the four frozen block
    /// classes.  The input order is consensus-significant and checked by
    /// [`try_new`](Self::try_new).
    pub fn from_block_classes(
        link_shape: FieldShape,
        link_pcs_params: PcsParams,
        block_classes: [&BlockClass; Self::SLOT_COUNT],
    ) -> Result<Self, CanonicalLadderError> {
        let mut slots = Vec::with_capacity(Self::SLOT_COUNT);
        for (slot, block_class) in block_classes.into_iter().enumerate() {
            let b_digest = block_class
                .validate_frozen_identity()
                .map_err(|_| CanonicalLadderError::BlockClassIdentity { slot })?;
            slots.push(LadderSlotInfo {
                tier: block_class.tier(),
                b_shape: block_class.shape,
                b_digest,
                b_pcs_params: block_class.pcs_params.clone(),
                b_post_commit_class_digest: *block_class.post_commit_class_digest(),
                b_sidecar_vk_digest: block_class.sidecar_vk().transcript_digest(),
            });
        }
        Self::try_new(link_shape, link_pcs_params, slots)
    }

    pub fn link_shape(&self) -> FieldShape {
        self.link_shape
    }

    pub fn link_pcs_params(&self) -> &PcsParams {
        &self.link_pcs_params
    }

    pub fn slots(&self) -> &[LadderSlotInfo; Self::SLOT_COUNT] {
        &self.slots
    }

    /// Recoverable metadata/shape preflight for one hosted slot.  This is
    /// separate from [`freeze_slot`](Self::freeze_slot): the actual recursive
    /// class build is assertion-driven and can still fail if the supplied
    /// proof is cryptographically invalid.
    pub fn validate_slot_material(
        &self,
        slot: usize,
        material: SplitLinkSlotMaterial<'_>,
    ) -> Result<(), CanonicalLadderError> {
        let info = self
            .slots
            .get(slot)
            .ok_or(CanonicalLadderError::SlotOutOfRange { slot })?;
        let b_digest = material
            .block_class
            .validate_frozen_identity()
            .map_err(|_| CanonicalLadderError::BlockClassIdentity { slot })?;
        if material.block_class.tier() != info.tier {
            return Err(CanonicalLadderError::BlockClassTier { slot });
        }
        if material.block_class.shape != info.b_shape {
            return Err(CanonicalLadderError::BlockClassShape { slot });
        }
        if b_digest != info.b_digest {
            return Err(CanonicalLadderError::BlockClassDigest { slot });
        }
        if !same_pcs_params(&material.block_class.pcs_params, &info.b_pcs_params) {
            return Err(CanonicalLadderError::BlockClassPcs { slot });
        }
        if material.block_class.post_commit_class_digest() != &info.b_post_commit_class_digest {
            return Err(CanonicalLadderError::BlockClassPostCommit { slot });
        }
        if material.block_class.sidecar_vk().transcript_digest() != info.b_sidecar_vk_digest {
            return Err(CanonicalLadderError::BlockClassSidecarVk { slot });
        }
        if FieldShape::of(material.block_matrix) != info.b_shape {
            return Err(CanonicalLadderError::BlockMatrixShape { slot });
        }
        if material.block_matrix.structural_statement_digest() != info.b_digest {
            return Err(CanonicalLadderError::BlockMatrixDigest { slot });
        }
        if !same_pcs_params(
            &material.sample_block.commitment().params,
            &info.b_pcs_params,
        ) {
            return Err(CanonicalLadderError::BlockEnvelopePcs { slot });
        }
        if material.sample_block.io().len() != material.block_class.spec.io_len {
            return Err(CanonicalLadderError::BlockEnvelopeIo { slot });
        }
        for offset in [BLOCK_IO_START_ACC, BLOCK_IO_END_ACC] {
            let lanes = std::array::from_fn(|lane| {
                Block128::from(flat_to_block(material.sample_block.io()[offset + lane]))
            });
            ChainAccumulator::from_lanes(lanes)
                .map_err(|_| CanonicalLadderError::BlockEnvelopeIo { slot })?;
        }
        let encoded = bincode::serialize(material.sample_block.region_sidecar())
            .map_err(|_| CanonicalLadderError::BlockEnvelopeSidecar { slot })?;
        decode_block_region_sidecar_bounded(
            material.block_class.sidecar_vk(),
            info.b_shape.m,
            &encoded,
        )
        .map_err(|_| CanonicalLadderError::BlockEnvelopeSidecar { slot })?;
        let mut challenger = FsLaneChallenger::new(b"history-block-v0");
        verify_field_deferred_matrix_with_post_commit_context(
            &info.b_shape,
            &info.b_digest,
            material.sample_block.commitment(),
            material.sample_block.field_proof(),
            &material.block_class.spec,
            material.sample_block.io(),
            &info.b_post_commit_class_digest,
            material.sample_block.region_sidecar(),
            &mut challenger,
            |sidecar, context| {
                verify_block_region_sidecar_post_commit(
                    material.block_class.sidecar_vk(),
                    sidecar,
                    context,
                )
                .map_err(|_| VerifyError::Auxiliary)
            },
        )
        .map_err(|_| CanonicalLadderError::BlockEnvelopeProof { slot })?;
        Ok(())
    }

    /// Freeze one hosted link class.  Call
    /// [`validate_slot_material`](Self::validate_slot_material) directly when
    /// a recoverable preflight result is needed.
    pub fn freeze_slot(&self, slot: usize, material: SplitLinkSlotMaterial<'_>) -> SplitLinkClass {
        self.validate_slot_material(slot, material)
            .expect("invalid canonical split-link slot material");
        self.freeze_slot_preflighted(slot, material)
    }

    fn freeze_slot_preflighted(
        &self,
        slot: usize,
        material: SplitLinkSlotMaterial<'_>,
    ) -> SplitLinkClass {
        self.freeze_slot_preflighted_with_genesis(slot, material, None)
    }

    fn freeze_slot_preflighted_with_genesis(
        &self,
        slot: usize,
        material: SplitLinkSlotMaterial<'_>,
        shared_genesis: Option<&SharedSplitLinkGenesis>,
    ) -> SplitLinkClass {
        SplitLinkClass::freeze(
            self.link_shape,
            self.link_pcs_params.clone(),
            self.slots.to_vec(),
            slot,
            material.block_class,
            material.sample_block,
            material.block_matrix,
            shared_genesis,
        )
    }

    fn freeze_slot_preflighted_with_transient_genesis(
        &self,
        slot: usize,
        material: SplitLinkSlotMaterial<'_>,
        genesis: &mut FieldR1cs,
        shared_genesis: Option<&SharedSplitLinkGenesis>,
    ) -> SplitLinkClass {
        SplitLinkClass::freeze_with_transient_genesis(
            self.link_shape,
            self.link_pcs_params.clone(),
            self.slots.to_vec(),
            slot,
            material.block_class,
            material.sample_block,
            material.block_matrix,
            genesis,
            shared_genesis,
        )
    }

    /// Freeze the complete universal ladder from ordered per-tier artifacts.
    pub fn freeze_all(
        &self,
        materials: [SplitLinkSlotMaterial<'_>; Self::SLOT_COUNT],
    ) -> [SplitLinkClass; Self::SLOT_COUNT] {
        for (slot, material) in materials.iter().copied().enumerate() {
            self.validate_slot_material(slot, material)
                .expect("invalid canonical split-link ladder material");
        }
        // Build T once for this materialization pass.  Every slot consumes the
        // same transient allocation sequentially, then the complete registry
        // drops it instead of retaining it behind an Arc.
        let mut genesis = split_genesis_instance(&self.link_shape);
        let mut materials = materials.into_iter().enumerate();
        let (first_slot, first_material) = materials
            .next()
            .expect("canonical ladder has at least one slot");
        let first = self.freeze_slot_preflighted_with_transient_genesis(
            first_slot,
            first_material,
            &mut genesis,
            None,
        );
        let shared_genesis = first.shared_genesis();
        let mut materialized = Vec::with_capacity(Self::SLOT_COUNT);
        materialized.push(first);
        for (slot, material) in materials {
            materialized.push(self.freeze_slot_preflighted_with_transient_genesis(
                slot,
                material,
                &mut genesis,
                Some(&shared_genesis),
            ));
        }
        let classes: [SplitLinkClass; Self::SLOT_COUNT] = materialized
            .try_into()
            .unwrap_or_else(|_| unreachable!("canonical ladder count was prevalidated"));
        drop(genesis);
        self.validate_materialized(&classes)
            .expect("fresh canonical split-link ladder identity drift");
        for class in &classes[1..] {
            assert!(
                classes[0].shares_genesis_artifacts_with(class),
                "freeze_all must retain one shared canonical genesis bootstrap"
            );
        }
        classes
    }

    /// Validate classes materialized elsewhere against this descriptor.  This
    /// is useful when class construction is distributed or cached.
    pub fn validate_materialized(
        &self,
        classes: &[SplitLinkClass],
    ) -> Result<(), CanonicalLadderError> {
        if classes.len() != Self::SLOT_COUNT {
            return Err(CanonicalLadderError::MaterializedClassCount {
                expected: Self::SLOT_COUNT,
                actual: classes.len(),
            });
        }
        let reference = &classes[0];
        reference
            .validate_materialized_identity()
            .map_err(|_| CanonicalLadderError::MaterializedClassIdentity { slot: 0 })?;
        let reference_sidecar_vk = reference
            .sidecar_vk
            .get()
            .ok_or(CanonicalLadderError::MaterializedClassIdentity { slot: 0 })?;
        let reference_genesis_envelope = reference
            .genesis_envelope
            .get()
            .ok_or(CanonicalLadderError::MaterializedClassIdentity { slot: 0 })?;
        let reference_genesis_bytes = bincode::serialize(reference_genesis_envelope.as_ref())
            .map_err(|_| CanonicalLadderError::MaterializedClassIdentity { slot: 0 })?;
        for (slot, class) in classes.iter().enumerate() {
            class
                .validate_materialized_identity()
                .map_err(|_| CanonicalLadderError::MaterializedClassIdentity { slot })?;
            if class.shape != self.link_shape {
                return Err(CanonicalLadderError::MaterializedClassShape { slot });
            }
            if !same_pcs_params(&class.pcs_params, &self.link_pcs_params) {
                return Err(CanonicalLadderError::MaterializedClassPcs { slot });
            }
            if !same_ladder(&class.ladder, &self.slots) {
                return Err(CanonicalLadderError::MaterializedClassLadder { slot });
            }
            if class.slot != slot {
                return Err(CanonicalLadderError::MaterializedClassSlot {
                    slot,
                    actual: class.slot,
                });
            }
            if class.sidecar_vk.get() != Some(reference_sidecar_vk) {
                return Err(CanonicalLadderError::MaterializedSidecarIdentity { slot });
            }
            let genesis_envelope = class
                .genesis_envelope
                .get()
                .ok_or(CanonicalLadderError::MaterializedClassIdentity { slot })?;
            let genesis_bytes = bincode::serialize(genesis_envelope.as_ref())
                .map_err(|_| CanonicalLadderError::MaterializedClassIdentity { slot })?;
            if class.genesis_digest != reference.genesis_digest
                || class.genesis_post_commit_class_digest.get()
                    != reference.genesis_post_commit_class_digest.get()
                || class.genesis_block_accumulator != reference.genesis_block_accumulator
                || genesis_bytes != reference_genesis_bytes
            {
                return Err(CanonicalLadderError::MaterializedGenesisIdentity { slot });
            }
        }
        Ok(())
    }
}

fn same_ladder(left: &[LadderSlotInfo], right: &[LadderSlotInfo]) -> bool {
    left.len() == right.len()
        && left.iter().zip(right).all(|(left, right)| {
            left.tier == right.tier
                && left.b_shape == right.b_shape
                && left.b_digest == right.b_digest
                && same_pcs_params(&left.b_pcs_params, &right.b_pcs_params)
                && left.b_post_commit_class_digest == right.b_post_commit_class_digest
                && left.b_sidecar_vk_digest == right.b_sidecar_vk_digest
        })
}

/// Offsets of one per-matrix accumulator lane within the link IO.
#[derive(Clone, Copy, Debug)]
pub struct SplitLaneLayout {
    /// First point coordinate (`2·k_log + 1` lanes).
    pub point: usize,
    /// The accumulated claim value.
    pub value: usize,
    /// The liveness bit (0 = lane dead/unused, 1 = carries a claim).
    pub live: usize,
}

impl SplitLaneLayout {
    fn new(offset: usize, k_log: usize) -> (Self, usize) {
        let point_len = 2 * k_log + 1;
        (
            Self {
                point: offset,
                value: offset + point_len,
                live: offset + point_len + 1,
            },
            offset + point_len + 2,
        )
    }
}

/// The split-link public-IO layout, shared by every link class of a
/// ladder: `[g | matrix whitelist (2 lanes per slot) | post-commit whitelist
/// (2 lanes per slot) | link lanes | block lanes | block_acc (ACC_LANES)]`.
#[derive(Clone, Debug)]
pub struct SplitIoLayout {
    pub g: usize,
    /// First whitelist lane (`2 · n_slots` lanes: the link-class
    /// statement digests, inherited along the chain).
    pub wl: usize,
    /// First composite post-commit class-digest whitelist lane.
    pub wl_post_commit: usize,
    /// Per-link-class accumulator lanes (all at the link k_log).
    pub link_lanes: Vec<SplitLaneLayout>,
    /// Per-block-class accumulator lanes (slot-specific k_log).
    pub b_lanes: Vec<SplitLaneLayout>,
    /// The covered block's end accumulator ([`ACC_LANES`] lanes).
    pub block_acc: usize,
    pub len: usize,
}

pub fn split_io_layout(link_k_log: usize, ladder: &[LadderSlotInfo]) -> SplitIoLayout {
    let n = ladder.len();
    let g = 0usize;
    let wl = 1usize;
    let wl_post_commit = wl + 2 * n;
    let mut off = wl_post_commit + 2 * n;
    let mut link_lanes = Vec::with_capacity(n);
    for _ in 0..n {
        let (lane, next) = SplitLaneLayout::new(off, link_k_log);
        link_lanes.push(lane);
        off = next;
    }
    let mut b_lanes = Vec::with_capacity(n);
    for slot in ladder {
        let (lane, next) = SplitLaneLayout::new(off, slot.b_shape.k_log);
        b_lanes.push(lane);
        off = next;
    }
    SplitIoLayout {
        g,
        wl,
        wl_post_commit,
        link_lanes,
        b_lanes,
        block_acc: off,
        len: off + super::link::ACC_LANES,
    }
}

/// The shared fixed statement. Link-region openings are verifier output of the
/// mandatory post-commit sidecar and never public-IO claim descriptors.
pub fn split_io_spec(link_k_log: usize, ladder: &[LadderSlotInfo]) -> PublicIoSpec {
    let layout = split_io_layout(link_k_log, ladder);
    let log2_len = layout.len.next_power_of_two().trailing_zeros() as usize;
    PublicIoSpec {
        io_slice: WitnessSlice { log2_len, index: 1 },
        io_len: layout.len,
        claims: Vec::new(),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SplitTransitionSelection {
    digest: [u8; 32],
    post_commit: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SplitTransitionError {
    PreviousSlot,
    CurrentSlot,
    PreviousIo,
    WhitelistSize,
    PostCommitWhitelistSize,
    WhitelistInheritance,
    PostCommitWhitelistInheritance,
    SelectedLinkMatrix,
    SelectedLinkPostCommit,
    CurrentBlockMatrix,
    AccumulatorWidth,
    AccumulatorContinuity,
    LinkClaimWidth,
    BlockClaimWidth,
}

/// Cheap non-genesis preflight shared by every real class transition.
///
/// The cryptographic replay below still verifies the previous envelope.  This
/// boundary additionally makes the native fold inputs unambiguous before any
/// expensive work: `prev_slot` must select the matrix actually supplied to the
/// fold, its paired post-commit identity, and the exact whitelist inherited in
/// the previous public IO.  The hosted Block matrix and direct accumulator
/// boundary are checked at the same time.
#[allow(clippy::too_many_arguments)]
fn preflight_split_transition(
    layout: &SplitIoLayout,
    prev_slot: usize,
    current_slot: usize,
    link_class_digests: &[[u8; 32]],
    link_post_commit_class_digests: &[[u8; 32]],
    prev_io: &[F128],
    fold_link_matrix_digest: [u8; 32],
    fold_link_post_commit: [u8; 32],
    fold_block_matrix_digest: [u8; 32],
    expected_block_matrix_digest: [u8; 32],
    block_start_accumulator: &[F128],
    expected_start_accumulator: &[F128],
) -> Result<SplitTransitionSelection, SplitTransitionError> {
    let n = layout.link_lanes.len();
    if prev_slot >= n {
        return Err(SplitTransitionError::PreviousSlot);
    }
    if current_slot >= n || layout.b_lanes.len() != n {
        return Err(SplitTransitionError::CurrentSlot);
    }
    if prev_io.len() != layout.len {
        return Err(SplitTransitionError::PreviousIo);
    }
    if link_class_digests.len() != n {
        return Err(SplitTransitionError::WhitelistSize);
    }
    if link_post_commit_class_digests.len() != n {
        return Err(SplitTransitionError::PostCommitWhitelistSize);
    }
    for (slot, digest) in link_class_digests.iter().enumerate() {
        let lanes = flat_digest_lanes(digest);
        if prev_io[layout.wl + 2 * slot] != lanes[0]
            || prev_io[layout.wl + 2 * slot + 1] != lanes[1]
        {
            return Err(SplitTransitionError::WhitelistInheritance);
        }
    }
    for (slot, digest) in link_post_commit_class_digests.iter().enumerate() {
        let lanes = flat_digest_lanes(digest);
        if prev_io[layout.wl_post_commit + 2 * slot] != lanes[0]
            || prev_io[layout.wl_post_commit + 2 * slot + 1] != lanes[1]
        {
            return Err(SplitTransitionError::PostCommitWhitelistInheritance);
        }
    }
    let selected = SplitTransitionSelection {
        digest: link_class_digests[prev_slot],
        post_commit: link_post_commit_class_digests[prev_slot],
    };
    if selected.digest != fold_link_matrix_digest {
        return Err(SplitTransitionError::SelectedLinkMatrix);
    }
    if selected.post_commit != fold_link_post_commit {
        return Err(SplitTransitionError::SelectedLinkPostCommit);
    }
    if fold_block_matrix_digest != expected_block_matrix_digest {
        return Err(SplitTransitionError::CurrentBlockMatrix);
    }
    if block_start_accumulator.len() != super::link::ACC_LANES
        || expected_start_accumulator.len() != super::link::ACC_LANES
    {
        return Err(SplitTransitionError::AccumulatorWidth);
    }
    if block_start_accumulator != expected_start_accumulator {
        return Err(SplitTransitionError::AccumulatorContinuity);
    }
    Ok(selected)
}

/// Construct the transition-dependent public IO.  Keeping this routing in one
/// production helper lets the exhaustive 4x4 gate cover downward and skipped
/// transitions without constructing sixteen m24 recursive proofs.
#[allow(clippy::too_many_arguments)]
fn route_split_transition_io(
    layout: &SplitIoLayout,
    genesis: bool,
    prev_slot: usize,
    current_slot: usize,
    link_class_digests: &[[u8; 32]],
    link_post_commit_class_digests: &[[u8; 32]],
    prev_io: &[F128],
    acc_link: &MatrixAccClaim,
    acc_block: &MatrixAccClaim,
    block_end_accumulator: &[F128],
) -> Result<Vec<F128>, SplitTransitionError> {
    let n = layout.link_lanes.len();
    if (!genesis && prev_slot >= n) || prev_io.len() != layout.len {
        return Err(if prev_io.len() != layout.len {
            SplitTransitionError::PreviousIo
        } else {
            SplitTransitionError::PreviousSlot
        });
    }
    if current_slot >= n || layout.b_lanes.len() != n {
        return Err(SplitTransitionError::CurrentSlot);
    }
    if link_class_digests.len() != n {
        return Err(SplitTransitionError::WhitelistSize);
    }
    if link_post_commit_class_digests.len() != n {
        return Err(SplitTransitionError::PostCommitWhitelistSize);
    }
    let link_lane = &layout.link_lanes[if genesis { 0 } else { prev_slot }];
    if acc_link.point.len() != link_lane.value - link_lane.point {
        return Err(SplitTransitionError::LinkClaimWidth);
    }
    let block_lane = &layout.b_lanes[current_slot];
    if acc_block.point.len() != block_lane.value - block_lane.point {
        return Err(SplitTransitionError::BlockClaimWidth);
    }
    if block_end_accumulator.len() != super::link::ACC_LANES {
        return Err(SplitTransitionError::AccumulatorWidth);
    }

    let mut io = vec![F128::ZERO; layout.len];
    io[layout.g] = if genesis { F128::ONE } else { F128::ZERO };
    for (slot, digest) in link_class_digests.iter().enumerate() {
        let lanes = flat_digest_lanes(digest);
        io[layout.wl + 2 * slot] = lanes[0];
        io[layout.wl + 2 * slot + 1] = lanes[1];
    }
    for (slot, digest) in link_post_commit_class_digests.iter().enumerate() {
        let lanes = flat_digest_lanes(digest);
        io[layout.wl_post_commit + 2 * slot] = lanes[0];
        io[layout.wl_post_commit + 2 * slot + 1] = lanes[1];
    }
    for (slot, lane) in layout.link_lanes.iter().enumerate() {
        if !genesis && slot == prev_slot {
            io[lane.point..lane.value].copy_from_slice(&acc_link.point);
            io[lane.value] = acc_link.value;
            io[lane.live] = F128::ONE;
        } else {
            io[lane.point..=lane.live].copy_from_slice(&prev_io[lane.point..=lane.live]);
        }
    }
    for (slot, lane) in layout.b_lanes.iter().enumerate() {
        if slot == current_slot {
            io[lane.point..lane.value].copy_from_slice(&acc_block.point);
            io[lane.value] = acc_block.value;
            io[lane.live] = F128::ONE;
        } else {
            io[lane.point..=lane.live].copy_from_slice(&prev_io[lane.point..=lane.live]);
        }
    }
    io[layout.block_acc..layout.block_acc + super::link::ACC_LANES]
        .copy_from_slice(block_end_accumulator);
    Ok(io)
}

/// Bootstrap relation used only by split links.  Every row is the tautology
/// `z_r · z_0 = z_r`, so the canonical nonzero L-A/L-B ghost columns can live
/// in T's committed witness.  Its deferred matrix claim still has a compact
/// closed form (see [`split_genesis_baked_claim_value`]); no T matrix is baked
/// into the recursive class.
fn split_genesis_instance(shape: &FieldShape) -> FieldR1cs {
    assert_eq!(shape.m, shape.k_log, "split genesis is one Field block");
    let k = 1usize << shape.k_log;
    let row_offsets = (0..=k).collect::<Vec<_>>();
    let width = u32::try_from(k).expect("split genesis width fits u32");
    let a_0 = SparseFieldMatrix::from_dict(
        k,
        (0..width).collect(),
        vec![0; k],
        vec![F128::ONE],
        row_offsets.clone(),
    );
    let b_0 = SparseFieldMatrix::from_dict(k, vec![0; k], vec![0; k], vec![F128::ONE], row_offsets);
    FieldR1cs {
        m: shape.m,
        k_log: shape.k_log,
        k_skip: shape.k_skip,
        useful_rows: k,
        a_0,
        b_0,
        const_pin: Some(0),
        digest_cache: std::sync::OnceLock::new(),
        csc_cache: std::sync::OnceLock::new(),
    }
}

fn split_genesis_baked_claim_value(
    b: &mut FieldR1csBuilder,
    fresh: &super::trace::matrix_fold::FreshLincheckClaimTrace,
) -> LinExpr {
    let ell = fresh.z_partial.len();
    assert!(ell.is_power_of_two(), "genesis z_partial window");
    let one = LinExpr::constant(F128::ONE);
    let lambda = lagrange_weights_window_trace(b, &fresh.z_skip, 0, ell, 0);
    let mut low_diagonal = LinExpr::zero();
    for row in 0..ell {
        low_diagonal = low_diagonal.add(&mul(b, &lambda[row], &fresh.z_partial[row]));
    }
    let mut high_diagonal = LinExpr::constant(F128::ONE);
    for (x, r) in fresh.x_inner_rest.iter().zip(&fresh.r_inner_rest) {
        let both = mul(b, x, r);
        let neither = mul(b, &one.add(x), &one.add(r));
        high_diagonal = mul(b, &high_diagonal, &both.add(&neither));
    }
    let mut q0 = LinExpr::constant(F128::ONE);
    for r in &fresh.r_inner_rest {
        q0 = mul(b, &q0, &one.add(r));
    }
    let a = mul(b, &fresh.alpha, &low_diagonal);
    let a = mul(b, &a, &high_diagonal);
    let b_value = mul(b, &fresh.z_partial[0], &q0);
    a.add(&b_value)
}

/// The slot-independent bootstrap retained by every class in one materialized
/// ladder.  The m24 genesis matrix is deliberately absent: it is needed only
/// while freezing a class or proving a genesis Link and must be rebuilt/loaded
/// transiently at those boundaries.
#[derive(Clone)]
struct SharedSplitLinkGenesis {
    genesis_digest: [u8; 32],
    sidecar_vk: Arc<LinkRegionSidecarVk>,
    post_commit_class_digest: [u8; 32],
    envelope: Arc<LinkProofEnvelope>,
}

/// One ladder slot's LINK class constants.
pub struct SplitLinkClass {
    /// The link shape — identical for every class of the ladder.
    pub shape: FieldShape,
    pub pcs_params: PcsParams,
    /// The shared spec (identical across the ladder's link classes).
    pub spec: PublicIoSpec,
    /// Statement digest of THIS class's matrix — filled by the first
    /// build, seeded into every later instance.
    pub class_statement_digest: std::sync::OnceLock<[u8; 32]>,
    /// Statement identity of the canonical genesis dummy T.  The T matrix is
    /// not retained by the class; one T proof serves every class of the
    /// ladder and provers load/rebuild the matrix only on demand.
    pub genesis_digest: [u8; 32],
    /// The block accumulator a genesis link's block must start from.
    genesis_block_accumulator: ChainAccumulator,
    ladder: Vec<LadderSlotInfo>,
    /// This class's ladder slot (selects the hosted block class).
    slot: usize,
    /// The slot's block-class spec ([R]_B replays it; a baked structural
    /// constant of this class).
    b_spec: PublicIoSpec,
    /// The slot's block-class PCS parameters.
    b_pcs_params: PcsParams,
    universal_geometry: RPcsLinkUniversalGeometry,
    sidecar_vk: std::sync::OnceLock<Arc<LinkRegionSidecarVk>>,
    post_commit_class_digest: std::sync::OnceLock<[u8; 32]>,
    genesis_post_commit_class_digest: std::sync::OnceLock<[u8; 32]>,
    genesis_envelope: std::sync::OnceLock<Arc<LinkProofEnvelope>>,
    b_sidecar_vk: Arc<crate::region_sidecar::BlockRegionSidecarVk>,
    b_post_commit_class_digest: [u8; 32],
}

impl SplitLinkClass {
    /// Rehydrate one selected production Link class from compact registry
    /// metadata.  Matrices and sample Block proofs are deliberately absent:
    /// the constructor rebuilds all derived geometry, installs only published
    /// identities, and validates the complete post-commit binding before the
    /// class can escape.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_selected_registry_parts(
        descriptor: &CanonicalSplitLinkLadder,
        slot: usize,
        block_class: &BlockClass,
        shape: FieldShape,
        pcs_params: PcsParams,
        spec: PublicIoSpec,
        matrix_digest: [u8; 32],
        post_commit_class_digest: [u8; 32],
        genesis_digest: [u8; 32],
        genesis_post_commit_class_digest: [u8; 32],
        sidecar_vk: Arc<LinkRegionSidecarVk>,
        genesis_envelope: Arc<LinkProofEnvelope>,
        b_spec: PublicIoSpec,
        b_pcs_params: PcsParams,
        b_sidecar_vk_digest: [u8; 32],
        b_post_commit_class_digest: [u8; 32],
    ) -> Result<Self, LinkProofError> {
        let ladder_slot = descriptor
            .slots()
            .get(slot)
            .ok_or(LinkProofError::ClassIdentityMismatch)?;
        block_class
            .validate_selected_zk_identity_for_tier(ladder_slot.tier)
            .map_err(|_| LinkProofError::ClassIdentityMismatch)?;
        let block_digest = block_class
            .class_statement_digest
            .get()
            .copied()
            .ok_or(LinkProofError::ClassIdentityMismatch)?;
        if shape != descriptor.link_shape()
            || !same_pcs_params(&pcs_params, descriptor.link_pcs_params())
            || ladder_slot.b_shape != block_class.shape
            || ladder_slot.b_digest != block_digest
            || !same_pcs_params(&ladder_slot.b_pcs_params, &block_class.pcs_params)
            || ladder_slot.b_sidecar_vk_digest != block_class.sidecar_vk().transcript_digest()
            || ladder_slot.b_post_commit_class_digest != *block_class.post_commit_class_digest()
            || !is_production_block_io_spec(&b_spec)
            || !same_pcs_params(&b_pcs_params, &block_class.pcs_params)
            || b_sidecar_vk_digest != block_class.sidecar_vk().transcript_digest()
            || b_post_commit_class_digest != *block_class.post_commit_class_digest()
        {
            return Err(LinkProofError::ClassIdentityMismatch);
        }
        let expected_spec = split_io_spec(shape.k_log, descriptor.slots());
        if spec.io_slice != expected_spec.io_slice
            || spec.io_len != expected_spec.io_len
            || !spec.claims.is_empty()
        {
            return Err(LinkProofError::ClassIdentityMismatch);
        }
        let block_params = descriptor
            .slots()
            .iter()
            .map(|slot| slot.b_pcs_params.clone())
            .collect::<Vec<_>>();
        let n_queries = noid_ivc_core::pcs::default_fri_queries(pcs_params.log_inv_rate);
        let universal_geometry =
            RPcsLinkUniversalGeometry::new(&pcs_params, &block_params, n_queries)
                .map_err(|_| LinkProofError::ClassIdentityMismatch)?;

        let class_statement_digest = std::sync::OnceLock::new();
        class_statement_digest
            .set(matrix_digest)
            .map_err(|_| LinkProofError::ClassIdentityMismatch)?;
        let sidecar_vk_lock = std::sync::OnceLock::new();
        sidecar_vk_lock
            .set(sidecar_vk)
            .map_err(|_| LinkProofError::ClassIdentityMismatch)?;
        let post_commit_lock = std::sync::OnceLock::new();
        post_commit_lock
            .set(post_commit_class_digest)
            .map_err(|_| LinkProofError::ClassIdentityMismatch)?;
        let genesis_post_commit_lock = std::sync::OnceLock::new();
        genesis_post_commit_lock
            .set(genesis_post_commit_class_digest)
            .map_err(|_| LinkProofError::ClassIdentityMismatch)?;
        let genesis_envelope_lock = std::sync::OnceLock::new();
        genesis_envelope_lock
            .set(genesis_envelope)
            .map_err(|_| LinkProofError::ClassIdentityMismatch)?;
        let class = Self {
            shape,
            pcs_params,
            spec,
            class_statement_digest,
            genesis_digest,
            genesis_block_accumulator: genesis_accumulator(),
            ladder: descriptor.slots().to_vec(),
            slot,
            b_spec,
            b_pcs_params,
            universal_geometry,
            sidecar_vk: sidecar_vk_lock,
            post_commit_class_digest: post_commit_lock,
            genesis_post_commit_class_digest: genesis_post_commit_lock,
            genesis_envelope: genesis_envelope_lock,
            b_sidecar_vk: block_class.sidecar_vk_arc(),
            b_post_commit_class_digest,
        };
        class.validate_frozen_identity()?;
        Ok(class)
    }

    pub(crate) fn registry_genesis_post_commit_digest(&self) -> Result<[u8; 32], LinkProofError> {
        self.genesis_post_commit_class_digest
            .get()
            .copied()
            .ok_or(LinkProofError::UnfrozenClass)
    }

    /// Freeze one slot against the universal link-sidecar key.  Bootstrap T
    /// already carries the same mandatory two-child sidecar as an ordinary
    /// link; its columns are the canonical zero-data/zero-path ghost.
    fn freeze(
        shape: FieldShape,
        pcs_params: PcsParams,
        ladder: Vec<LadderSlotInfo>,
        slot: usize,
        block_class: &BlockClass,
        sample_block: &BlockProofEnvelope,
        block_matrix: &FieldR1cs,
        shared_genesis: Option<&SharedSplitLinkGenesis>,
    ) -> Self {
        let mut genesis = split_genesis_instance(&shape);
        Self::freeze_with_transient_genesis(
            shape,
            pcs_params,
            ladder,
            slot,
            block_class,
            sample_block,
            block_matrix,
            &mut genesis,
            shared_genesis,
        )
    }

    /// Freeze one slot while borrowing the caller's sole transient T matrix.
    /// `freeze_all` uses this to avoid rebuilding T for each slot without
    /// transferring it into any materialized class.
    #[allow(clippy::too_many_arguments)]
    fn freeze_with_transient_genesis(
        shape: FieldShape,
        pcs_params: PcsParams,
        ladder: Vec<LadderSlotInfo>,
        slot: usize,
        block_class: &BlockClass,
        sample_block: &BlockProofEnvelope,
        block_matrix: &FieldR1cs,
        genesis: &mut FieldR1cs,
        shared_genesis: Option<&SharedSplitLinkGenesis>,
    ) -> Self {
        CanonicalSplitLinkLadder::try_new(shape, pcs_params.clone(), ladder.clone())
            .expect("internal split-link freeze requires the canonical ladder");
        let genesis_block_accumulator = genesis_accumulator();
        assert!(slot < ladder.len(), "slot out of ladder");
        assert_eq!(
            pcs_params.m,
            shape.m + noid_ivc_core::pcs::LOG_PACKING,
            "link PCS m vs Field shape"
        );
        for (index, ladder_slot) in ladder.iter().enumerate() {
            assert_eq!(
                ladder_slot.b_pcs_params.m,
                ladder_slot.b_shape.m + noid_ivc_core::pcs::LOG_PACKING,
                "block slot {index}: PCS m vs Field shape"
            );
        }
        assert_eq!(
            ladder[slot].b_shape, block_class.shape,
            "slot shape vs block class"
        );
        let b_digest = block_class
            .validate_frozen_identity()
            .expect("hosted block class must retain its frozen identity");
        assert_eq!(
            ladder[slot].b_digest, b_digest,
            "slot digest vs block class"
        );
        assert_eq!(
            pcs_params_statement_bytes(&ladder[slot].b_pcs_params),
            pcs_params_statement_bytes(&block_class.pcs_params),
            "slot PCS descriptor vs block class"
        );
        assert_eq!(
            ladder[slot].b_post_commit_class_digest,
            *block_class.post_commit_class_digest(),
            "slot post-commit identity vs block class"
        );
        assert_eq!(
            ladder[slot].b_sidecar_vk_digest,
            block_class.sidecar_vk().transcript_digest(),
            "slot sidecar VK identity vs block class"
        );
        // Class freezing needs T once to derive the hosted Link matrix.  Keep
        // it local so a materialized registry never pins an m24 FieldR1cs.
        assert_eq!(FieldShape::of(&*genesis), shape, "split-genesis shape");
        // statement_digest() also warms the transient instance's digest cache,
        // so proving T reads it instead of re-hashing serialization.
        let genesis_digest = genesis.statement_digest();
        if let Some(shared) = shared_genesis {
            assert_eq!(
                genesis_digest, shared.genesis_digest,
                "rebuilt split-genesis statement identity"
            );
        }
        let block_params = ladder
            .iter()
            .map(|slot| slot.b_pcs_params.clone())
            .collect::<Vec<_>>();
        let n_queries = noid_ivc_core::pcs::default_fri_queries(pcs_params.log_inv_rate);
        let universal_geometry =
            RPcsLinkUniversalGeometry::new(&pcs_params, &block_params, n_queries)
                .expect("link/block ladder must share one frozen query count");
        let spec = split_io_spec(shape.k_log, &ladder);
        let class = Self {
            shape,
            pcs_params: pcs_params.clone(),
            spec,
            class_statement_digest: std::sync::OnceLock::new(),
            genesis_digest,
            genesis_block_accumulator,
            ladder,
            slot,
            b_spec: block_class.spec.clone(),
            b_pcs_params: block_class.pcs_params.clone(),
            universal_geometry,
            sidecar_vk: std::sync::OnceLock::new(),
            post_commit_class_digest: std::sync::OnceLock::new(),
            genesis_post_commit_class_digest: std::sync::OnceLock::new(),
            genesis_envelope: std::sync::OnceLock::new(),
            b_sidecar_vk: block_class.sidecar_vk_arc(),
            b_post_commit_class_digest: *block_class.post_commit_class_digest(),
        };

        if let Some(shared) = shared_genesis {
            let expected_genesis_post_commit = link_post_commit_class_digest(
                &class.genesis_digest,
                &class.spec,
                &class.pcs_params,
                shared.sidecar_vk.as_ref(),
            );
            assert_eq!(
                shared.post_commit_class_digest, expected_genesis_post_commit,
                "shared split-genesis post-commit identity"
            );
            assert_eq!(
                shared.envelope.io(),
                vec![F128::ZERO; class.spec.io_len],
                "shared split-genesis public IO"
            );
            assert!(
                same_pcs_params(&shared.envelope.commitment().params, &class.pcs_params),
                "shared split-genesis PCS parameters"
            );
            class
                .sidecar_vk
                .set(Arc::clone(&shared.sidecar_vk))
                .expect("fresh shared universal link sidecar VK lock");
            class
                .genesis_post_commit_class_digest
                .set(shared.post_commit_class_digest)
                .expect("fresh shared genesis post-commit digest lock");
            class
                .genesis_envelope
                .set(Arc::clone(&shared.envelope))
                .expect("fresh shared genesis envelope lock");
        } else {
            let (t_witness, ghost_preparation) = class.build_genesis_ghost_witness();
            assert!(
                genesis.satisfies(&t_witness),
                "canonical split-genesis ghost must satisfy full-identity T"
            );
            class
                .sidecar_vk
                .set(Arc::new(ghost_preparation.vk().clone()))
                .expect("fresh universal link sidecar VK lock");
            let genesis_post_commit = link_post_commit_class_digest(
                &class.genesis_digest,
                &class.spec,
                &class.pcs_params,
                class.sidecar_vk(),
            );
            class
                .genesis_post_commit_class_digest
                .set(genesis_post_commit)
                .expect("fresh genesis post-commit digest lock");
            let t_io = vec![F128::ZERO; class.spec.io_len];
            let ghost_plan =
                LinkRegionProverPlan::new(ghost_preparation.vk(), ghost_preparation.prover_input())
                    .expect("canonical genesis ghost plan");
            let mut ch = FsLaneChallenger::new(b"history-link-v0");
            let (t_proof, t_sidecar, t_commitment, _) =
                prove_field_with_public_io_and_post_commit_context(
                    &*genesis,
                    &t_witness,
                    &pcs_params,
                    &class.spec,
                    &t_io,
                    &genesis_post_commit,
                    &mut ch,
                    |context| ghost_plan.prove_post_commit(context),
                );
            // T is immutable after this point.  Its optional CSC transpose is
            // derived verifier scratch and must not become part of the shared
            // long-lived ladder allocation.
            genesis.release_csc_cache();
            let env_t = Arc::new(LinkProofEnvelope {
                field_proof: t_proof,
                commitment: t_commitment,
                io: t_io,
                region_sidecar: t_sidecar.expect("canonical genesis ghost proof"),
            });
            class
                .genesis_envelope
                .set(env_t)
                .expect("fresh genesis envelope lock");
        }
        let built = build_split_link_inner(
            &class,
            &SplitLinkInput {
                prev: class.genesis_envelope(),
                prev_slot: 0,
                genesis: true,
                link_class_digests: vec![[0u8; 32]; class.ladder.len()],
                link_post_commit_class_digests: vec![[0u8; 32]; class.ladder.len()],
                block: sample_block,
                fold_matrix_link: &*genesis,
                fold_matrix_block: block_matrix,
            },
            true,
        );
        assert_eq!(
            built.region_preparation.vk(),
            class.sidecar_vk(),
            "genesis build must reproduce the universal link sidecar VK"
        );
        let matrix_digest = built.r1cs.statement_digest();
        class
            .class_statement_digest
            .set(matrix_digest)
            .expect("fresh link matrix digest lock");
        let post_commit = link_post_commit_class_digest(
            &matrix_digest,
            &class.spec,
            &class.pcs_params,
            class.sidecar_vk(),
        );
        class
            .post_commit_class_digest
            .set(post_commit)
            .expect("fresh link post-commit digest lock");
        class
    }

    pub fn layout(&self) -> SplitIoLayout {
        split_io_layout(self.shape.k_log, &self.ladder)
    }

    pub fn ladder(&self) -> &[LadderSlotInfo] {
        &self.ladder
    }

    pub fn slot(&self) -> usize {
        self.slot
    }

    pub fn sidecar_vk(&self) -> &LinkRegionSidecarVk {
        self.sidecar_vk
            .get()
            .expect("frozen link sidecar VK")
            .as_ref()
    }

    pub fn post_commit_class_digest(&self) -> &[u8; 32] {
        self.post_commit_class_digest
            .get()
            .expect("frozen link post-commit class")
    }

    pub fn genesis_envelope(&self) -> &LinkProofEnvelope {
        self.genesis_envelope
            .get()
            .expect("frozen genesis envelope")
            .as_ref()
    }

    /// Rebuild the canonical genesis matrix for an on-demand proving source.
    ///
    /// The returned matrix is owned by the caller and is not cached by the
    /// class.  Its structural identity is checked before it crosses the
    /// production loader boundary.
    pub fn rebuild_genesis_matrix(&self) -> Result<FieldR1cs, LinkProofError> {
        let matrix = split_genesis_instance(&self.shape);
        if matrix.statement_digest() != self.genesis_digest {
            return Err(LinkProofError::ClassIdentityMismatch);
        }
        Ok(matrix)
    }

    fn shared_genesis(&self) -> SharedSplitLinkGenesis {
        SharedSplitLinkGenesis {
            genesis_digest: self.genesis_digest,
            sidecar_vk: Arc::clone(self.sidecar_vk.get().expect("frozen link sidecar VK")),
            post_commit_class_digest: *self
                .genesis_post_commit_class_digest
                .get()
                .expect("frozen genesis post-commit identity"),
            envelope: Arc::clone(
                self.genesis_envelope
                    .get()
                    .expect("frozen genesis envelope"),
            ),
        }
    }

    fn shares_genesis_artifacts_with(&self, other: &Self) -> bool {
        self.genesis_digest == other.genesis_digest
            && self.genesis_post_commit_class_digest.get()
                == other.genesis_post_commit_class_digest.get()
            && self.genesis_block_accumulator == other.genesis_block_accumulator
            && matches!(
                (self.sidecar_vk.get(), other.sidecar_vk.get()),
                (Some(left), Some(right)) if Arc::ptr_eq(left, right)
            )
            && matches!(
                (self.genesis_envelope.get(), other.genesis_envelope.get()),
                (Some(left), Some(right)) if Arc::ptr_eq(left, right)
            )
    }

    fn build_genesis_ghost_witness(&self) -> (Vec<F128>, RPcsLinkRegionPreparation) {
        assert_eq!(
            self.shape.k_log, self.shape.m,
            "genesis ghost currently requires one full-width Field block"
        );
        let mut builder = FieldR1csBuilder::new();
        let io_start = self.spec.io_slice.start();
        while builder.num_wires() < io_start {
            builder.alloc_f128(F128::ZERO);
        }
        for _ in 0..1usize << self.spec.io_slice.log2_len {
            builder.alloc_f128(F128::ZERO);
        }
        let preparation = prepare_r_pcs_link_genesis_ghost(&mut builder, &self.universal_geometry)
            .expect("canonical genesis ghost columns");
        let target = 1usize << self.shape.m;
        assert!(
            builder.num_wires() <= target,
            "genesis ghost exceeds link shape"
        );
        let mut witness = builder.values().to_vec();
        witness.resize(target, F128::ZERO);
        witness[0] = F128::ONE;
        (witness, preparation)
    }
}

/// One split-link build's inputs.
pub struct SplitLinkInput<'a> {
    /// The previous link envelope (or the genesis dummy T's proof when
    /// `genesis = true`).
    pub prev: &'a LinkProofEnvelope,
    /// The previous link's ladder slot (drives β; ignored at genesis).
    pub prev_slot: usize,
    pub genesis: bool,
    /// The whitelist values: every ladder slot's LINK-class statement
    /// digest. Witness data (never baked); the decider pins the tip's.
    /// A throwaway matrix-derivation build passes zeros.
    pub link_class_digests: Vec<[u8; 32]>,
    /// Composite post-commit identities paired with `link_class_digests`.
    pub link_post_commit_class_digests: Vec<[u8; 32]>,
    /// The covered block's proof envelope (`π_block`, this class's slot).
    pub block: &'a BlockProofEnvelope,
    /// The matrix the PREVIOUS proof was proven over — native fold
    /// prover only (T at genesis, else the previous link class's
    /// matrix). Never enters the trace.
    pub fold_matrix_link: &'a FieldR1cs,
    /// The slot's block-class matrix — native fold prover only.
    pub fold_matrix_block: &'a FieldR1cs,
}

/// Matrix-free half of one split-link build input.
///
/// Unlike [`SplitLinkInput`], this object owns both registry vectors and holds
/// references only to the two proof envelopes. Production consumes it through
/// [`begin_split_link_native_preparation`]; neither consuming matrix phase
/// retains a borrow of the matrix it just authenticated and folded.
pub struct SplitLinkTraceInput<'a> {
    /// The previous link envelope (or the canonical T envelope at genesis).
    pub prev: &'a LinkProofEnvelope,
    /// Previous Link-class slot; ignored only when `genesis` is true.
    pub prev_slot: usize,
    pub genesis: bool,
    pub link_class_digests: Vec<[u8; 32]>,
    pub link_post_commit_class_digests: Vec<[u8; 32]>,
    /// The covered Block proof envelope for the current Link class.
    pub block: &'a BlockProofEnvelope,
}

impl<'a> SplitLinkTraceInput<'a> {
    fn from_combined(input: &SplitLinkInput<'a>) -> Self {
        Self {
            prev: input.prev,
            prev_slot: input.prev_slot,
            genesis: input.genesis,
            link_class_digests: input.link_class_digests.clone(),
            link_post_commit_class_digests: input.link_post_commit_class_digests.clone(),
            block: input.block,
        }
    }
}

/// Fail-closed native preparation error raised before recursive trace
/// allocation.  The phased API reports structural/class mixing instead of
/// reaching the assertion-only compatibility wrapper.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SplitLinkPreparationError {
    ClassIdentity,
    PreviousEnvelopeIo,
    BlockEnvelopeIo,
    RegistryShape,
    PreviousPcsParameters,
    BlockPcsParameters,
    PreviousSlot,
    GenesisPredecessor,
    TransitionBinding,
    PreviousMatrixShape,
    PreviousMatrixDigest,
    BlockMatrixShape,
    BlockMatrixDigest,
    PreviousProof,
    BlockProof,
    IoRouting,
}

impl core::fmt::Display for SplitLinkPreparationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let message = match self {
            Self::ClassIdentity => "split-link class identity is not frozen",
            Self::PreviousEnvelopeIo => "previous Link envelope IO shape mismatch",
            Self::BlockEnvelopeIo => "current Block envelope IO shape mismatch",
            Self::RegistryShape => "split-link registry shape mismatch",
            Self::PreviousPcsParameters => "previous Link PCS parameters mismatch",
            Self::BlockPcsParameters => "current Block PCS parameters mismatch",
            Self::PreviousSlot => "previous Link slot is outside the canonical ladder",
            Self::GenesisPredecessor => "genesis predecessor is not canonical T",
            Self::TransitionBinding => "split-link transition/class binding mismatch",
            Self::PreviousMatrixShape => "previous Link matrix shape mismatch",
            Self::PreviousMatrixDigest => "previous Link matrix structural digest mismatch",
            Self::BlockMatrixShape => "current Block matrix shape mismatch",
            Self::BlockMatrixDigest => "current Block matrix structural digest mismatch",
            Self::PreviousProof => "previous Link envelope verification failed",
            Self::BlockProof => "current Block envelope verification failed",
            Self::IoRouting => "split-link accumulated-claim IO routing failed",
        };
        f.write_str(message)
    }
}

impl std::error::Error for SplitLinkPreparationError {}

/// First consuming phase of production native Link preparation.
///
/// It owns the immutable proof/input binding but no matrix. Supplying the
/// previous-Link matrix consumes this state and returns a block-only phase, so
/// the previous matrix may be released before the block matrix is loaded.
#[must_use = "previous-Link matrix phase must be consumed"]
pub struct SplitLinkPreviousMatrixPhase<'a> {
    core: SplitLinkNativePreparationCore<'a>,
}

/// Second consuming phase. The previous-Link fold proof and output claim are
/// owned here; neither the previous matrix nor a way to replace its class/slot
/// remains reachable.
#[must_use = "current-Block matrix phase must be consumed"]
pub struct SplitLinkBlockMatrixPhase<'a> {
    core: SplitLinkNativePreparationCore<'a>,
    fold_proof_link: MatrixFoldProof,
    acc_link: MatrixAccClaim,
}

struct SplitLinkNativePreparationCore<'a> {
    class: &'a SplitLinkClass,
    input: SplitLinkTraceInput<'a>,
    layout: SplitIoLayout,
    expected_link_matrix_digest: [u8; 32],
    expected_link_post_commit: [u8; 32],
    expected_block_matrix_digest: [u8; 32],
    freeze: bool,
}

fn validate_split_fold_matrix_identity(
    matrix: &FieldR1cs,
    expected_shape: FieldShape,
    expected_digest: [u8; 32],
    shape_error: SplitLinkPreparationError,
    digest_error: SplitLinkPreparationError,
) -> Result<(), SplitLinkPreparationError> {
    if FieldShape::of(matrix) != expected_shape {
        return Err(shape_error);
    }
    // `statement_digest()` has a seedable cache for trusted rebuilt class
    // artifacts.  A matrix crossing this public phased boundary is untrusted,
    // so authenticate its CSR contents directly before proof replay.
    if matrix.structural_statement_digest() != expected_digest {
        return Err(digest_error);
    }
    Ok(())
}

fn prove_split_matrix_fold(
    transcript_domain: &'static [u8],
    matrix: &FieldR1cs,
    fresh: &noid_ivc_core::matrix_claim::FreshLincheckClaim,
    incoming: &MatrixAccClaim,
    gate: bool,
) -> (MatrixFoldProof, MatrixAccClaim) {
    let mut challenger = FsLaneChallenger::new(transcript_domain);
    prove_matrix_claim_fold(matrix, fresh, incoming, gate, &mut challenger)
}

/// One-shot native split-link preparation.
///
/// This owns every fold proof and routed IO value needed by trace assembly,
/// but deliberately contains no reference to either matrix used by the native
/// fold prover. A memory-governed caller can therefore release both matrices
/// before calling [`Self::assemble`].
#[must_use = "native split-link preparation must be assembled"]
pub struct PreparedSplitLink<'a> {
    class: &'a SplitLinkClass,
    input: SplitLinkTraceInput<'a>,
    fold_proof_link: MatrixFoldProof,
    fold_proof_block: MatrixFoldProof,
    io: Vec<F128>,
    freeze: bool,
}

impl<'a> PreparedSplitLink<'a> {
    /// Assemble the recursive trace without accessing either native fold
    /// matrix. Consumes the preparation so it cannot be mixed or replayed with
    /// another class/input pair.
    pub fn assemble(self) -> BuiltSplitLink {
        assemble_prepared_split_link(self)
    }
}

/// A built split link.
pub struct BuiltSplitLink {
    pub r1cs: FieldR1cs,
    pub witness: Vec<F128>,
    pub io: Vec<F128>,
    region_preparation: RPcsLinkRegionPreparation,
}

/// Mandatory production link envelope.  Core-only downgrade is impossible
/// through the typed API because the two-child sidecar is private/nonoptional.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct LinkProofEnvelope {
    field_proof: FieldR1csProof,
    commitment: Commitment,
    io: Vec<F128>,
    region_sidecar: LinkRegionSidecarProof,
}

impl LinkProofEnvelope {
    pub fn field_proof(&self) -> &FieldR1csProof {
        &self.field_proof
    }
    pub fn commitment(&self) -> &Commitment {
        &self.commitment
    }
    pub fn io(&self) -> &[F128] {
        &self.io
    }
    pub fn region_sidecar(&self) -> &LinkRegionSidecarProof {
        &self.region_sidecar
    }
    pub fn byte_len(&self) -> usize {
        bincode::serialized_size(self).expect("link proof envelope serialized length") as usize
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LinkProofError {
    UnfrozenClass,
    ClassIdentityMismatch,
    PcsParamsMismatch,
    InvalidIo,
    MatrixMismatch,
    MatrixClaimMismatch,
    AccumulatorClaimMismatch,
    SidecarVkMismatch,
    Sidecar(RegionSidecarError),
    Field(VerifyError),
}

impl std::fmt::Display for LinkProofError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnfrozenClass => write!(f, "link class is not frozen"),
            Self::ClassIdentityMismatch => write!(f, "link post-commit class identity drift"),
            Self::PcsParamsMismatch => write!(f, "link PCS parameters do not match the class"),
            Self::InvalidIo => write!(f, "link public IO does not match the class"),
            Self::MatrixMismatch => write!(f, "link matrix does not match its frozen class"),
            Self::MatrixClaimMismatch => {
                write!(
                    f,
                    "link deferred matrix claim is false for its frozen class"
                )
            }
            Self::AccumulatorClaimMismatch => {
                write!(f, "link accumulated matrix claim is false")
            }
            Self::SidecarVkMismatch => write!(f, "link sidecar VK does not match its class"),
            Self::Sidecar(error) => write!(f, "link sidecar error: {error:?}"),
            Self::Field(error) => write!(f, "link Field proof error: {error:?}"),
        }
    }
}

impl std::error::Error for LinkProofError {}

impl From<RegionSidecarError> for LinkProofError {
    fn from(value: RegionSidecarError) -> Self {
        Self::Sidecar(value)
    }
}

impl From<VerifyError> for LinkProofError {
    fn from(value: VerifyError) -> Self {
        Self::Field(value)
    }
}

impl SplitLinkClass {
    fn validate_frozen_identity(&self) -> Result<[u8; 32], LinkProofError> {
        let matrix_digest = self
            .class_statement_digest
            .get()
            .copied()
            .ok_or(LinkProofError::UnfrozenClass)?;
        CanonicalSplitLinkLadder::try_new(self.shape, self.pcs_params.clone(), self.ladder.clone())
            .map_err(|_| LinkProofError::ClassIdentityMismatch)?;
        if self.shape.m.checked_add(noid_ivc_core::pcs::LOG_PACKING) != Some(self.pcs_params.m) {
            return Err(LinkProofError::PcsParamsMismatch);
        }
        let layout = self.layout();
        if !self.spec.claims.is_empty()
            || self.spec.io_len != layout.len
            || self.spec.io_slice.index != 1
            || self.spec.io_slice.log2_len
                != layout.len.next_power_of_two().trailing_zeros() as usize
            || !self.spec.io_slice.fits(self.shape.m)
            || self.spec.io_len > self.spec.io_slice.len()
        {
            return Err(LinkProofError::ClassIdentityMismatch);
        }
        let slot = self
            .ladder
            .get(self.slot)
            .ok_or(LinkProofError::ClassIdentityMismatch)?;
        if !is_production_block_io_spec(&self.b_spec)
            || self.b_pcs_params.m != slot.b_shape.m + noid_ivc_core::pcs::LOG_PACKING
            || !same_pcs_params(&self.b_pcs_params, &slot.b_pcs_params)
            || self.b_sidecar_vk.transcript_digest() != slot.b_sidecar_vk_digest
            || self.b_post_commit_class_digest != slot.b_post_commit_class_digest
        {
            return Err(LinkProofError::ClassIdentityMismatch);
        }
        let expected_block_post_commit = block_post_commit_class_digest(
            &slot.b_digest,
            &self.b_spec,
            &self.b_pcs_params,
            &self.b_sidecar_vk,
        );
        if expected_block_post_commit != self.b_post_commit_class_digest {
            return Err(LinkProofError::ClassIdentityMismatch);
        }
        if self.genesis_block_accumulator != genesis_accumulator() {
            return Err(LinkProofError::ClassIdentityMismatch);
        }
        let sidecar_vk = self.sidecar_vk.get().ok_or(LinkProofError::UnfrozenClass)?;
        let expected =
            link_post_commit_class_digest(&matrix_digest, &self.spec, &self.pcs_params, sidecar_vk);
        if Some(&expected) != self.post_commit_class_digest.get() {
            return Err(LinkProofError::ClassIdentityMismatch);
        }
        let expected_genesis_post_commit = link_post_commit_class_digest(
            &self.genesis_digest,
            &self.spec,
            &self.pcs_params,
            sidecar_vk,
        );
        if Some(&expected_genesis_post_commit) != self.genesis_post_commit_class_digest.get() {
            return Err(LinkProofError::ClassIdentityMismatch);
        }
        let genesis_envelope = self
            .genesis_envelope
            .get()
            .ok_or(LinkProofError::UnfrozenClass)?;
        if genesis_envelope.io().len() != self.spec.io_len
            || genesis_envelope
                .io()
                .iter()
                .any(|value| *value != F128::ZERO)
            || !same_pcs_params(&genesis_envelope.commitment().params, &self.pcs_params)
        {
            return Err(LinkProofError::ClassIdentityMismatch);
        }
        Ok(matrix_digest)
    }

    fn validate_materialized_identity(&self) -> Result<(), LinkProofError> {
        self.validate_frozen_identity()?;
        let sidecar_vk = self.sidecar_vk.get().ok_or(LinkProofError::UnfrozenClass)?;
        let genesis_envelope = self
            .genesis_envelope
            .get()
            .ok_or(LinkProofError::UnfrozenClass)?;
        let encoded = bincode::serialize(genesis_envelope.region_sidecar())
            .map_err(|_| LinkProofError::ClassIdentityMismatch)?;
        decode_link_region_sidecar_bounded(sidecar_vk, self.shape.m, &encoded)
            .map_err(LinkProofError::Sidecar)?;
        let genesis_post_commit = self
            .genesis_post_commit_class_digest
            .get()
            .ok_or(LinkProofError::UnfrozenClass)?;
        let mut challenger = FsLaneChallenger::new(b"history-link-v0");
        verify_field_deferred_matrix_with_post_commit_context(
            &self.shape,
            &self.genesis_digest,
            genesis_envelope.commitment(),
            genesis_envelope.field_proof(),
            &self.spec,
            genesis_envelope.io(),
            genesis_post_commit,
            genesis_envelope.region_sidecar(),
            &mut challenger,
            |sidecar, context| {
                verify_link_region_sidecar_post_commit(sidecar_vk, sidecar, context)
                    .map_err(|_| VerifyError::Auxiliary)
            },
        )?;
        Ok(())
    }
}

/// Commit one built link and prove its mandatory L-A/L-B authority on the
/// same causally post-commit challenger.
pub fn prove_built_split_link<Ch: Challenger>(
    class: &SplitLinkClass,
    built: &BuiltSplitLink,
    challenger: &mut Ch,
) -> Result<LinkProofEnvelope, LinkProofError> {
    let matrix_digest = class.validate_frozen_identity()?;
    if built.io.len() != class.spec.io_len {
        return Err(LinkProofError::InvalidIo);
    }
    if built.r1cs.statement_digest() != matrix_digest || FieldShape::of(&built.r1cs) != class.shape
    {
        return Err(LinkProofError::MatrixMismatch);
    }
    if built.region_preparation.vk() != class.sidecar_vk() {
        return Err(LinkProofError::SidecarVkMismatch);
    }
    let plan = LinkRegionProverPlan::new(
        built.region_preparation.vk(),
        built.region_preparation.prover_input(),
    )?;
    let (field_proof, sidecar, commitment, _) = prove_field_with_public_io_and_post_commit_context(
        &built.r1cs,
        &built.witness,
        &class.pcs_params,
        &class.spec,
        &built.io,
        class.post_commit_class_digest(),
        challenger,
        |context| plan.prove_post_commit(context),
    );
    Ok(LinkProofEnvelope {
        field_proof,
        commitment,
        io: built.io.clone(),
        region_sidecar: sidecar?,
    })
}

/// Full native verification of a production link envelope. A plain Field
/// proof is intentionally not accepted by this boundary.
pub fn verify_split_link_proof<Ch: Challenger>(
    class: &SplitLinkClass,
    matrix: &FieldR1cs,
    envelope: &LinkProofEnvelope,
    challenger: &mut Ch,
) -> Result<R1csClaim, LinkProofError> {
    let matrix_digest = class.validate_frozen_identity()?;
    if !same_pcs_params(&envelope.commitment().params, &class.pcs_params) {
        return Err(LinkProofError::PcsParamsMismatch);
    }
    if envelope.io().len() != class.spec.io_len {
        return Err(LinkProofError::InvalidIo);
    }
    if matrix.statement_digest() != matrix_digest || FieldShape::of(matrix) != class.shape {
        return Err(LinkProofError::MatrixMismatch);
    }
    verify_field_with_public_io_and_post_commit_context(
        matrix,
        envelope.commitment(),
        envelope.field_proof(),
        &class.spec,
        envelope.io(),
        class.post_commit_class_digest(),
        envelope.region_sidecar(),
        challenger,
        |sidecar, context| {
            verify_link_region_sidecar_post_commit(class.sidecar_vk(), sidecar, context)
                .map_err(|_| VerifyError::Auxiliary)
        },
    )
    .map_err(LinkProofError::Field)
}

/// Verify the complete production Link envelope while deferring only the
/// lincheck final against the class matrix.
///
/// This is transcript-identical to [`verify_split_link_proof`], including the
/// mandatory post-commit sidecar.  The returned claim is not an acceptance
/// result: a caller must evaluate it against the structurally authenticated
/// class matrix before using the proof.
fn verify_split_link_proof_deferred_matrix<Ch: Challenger>(
    class: &SplitLinkClass,
    envelope: &LinkProofEnvelope,
    challenger: &mut Ch,
) -> Result<(R1csClaim, FreshLincheckClaim), LinkProofError> {
    let matrix_digest = class.validate_frozen_identity()?;
    if !same_pcs_params(&envelope.commitment().params, &class.pcs_params) {
        return Err(LinkProofError::PcsParamsMismatch);
    }
    if envelope.io().len() != class.spec.io_len {
        return Err(LinkProofError::InvalidIo);
    }
    verify_field_deferred_matrix_with_post_commit_context(
        &class.shape,
        &matrix_digest,
        envelope.commitment(),
        envelope.field_proof(),
        &class.spec,
        envelope.io(),
        class.post_commit_class_digest(),
        envelope.region_sidecar(),
        challenger,
        |sidecar, context| {
            verify_link_region_sidecar_post_commit(class.sidecar_vk(), sidecar, context)
                .map_err(|_| VerifyError::Auxiliary)
        },
    )
    .map_err(LinkProofError::Field)
}

fn same_pcs_params(left: &PcsParams, right: &PcsParams) -> bool {
    pcs_params_statement_bytes(left) == pcs_params_statement_bytes(right)
}

fn alloc_expr(b: &mut FieldR1csBuilder, v: F128) -> LinExpr {
    LinExpr::from_wire(b.alloc_f128(v))
}

/// Assemble one split link. Native pass first (both deferred verifies +
/// both folds — every IO value is known before the trace starts), then
/// the trace: IO cells, both envelopes, the two [R] replays IN REGION
/// MODE (path-free — their PCS hashing lands on the link's two walks),
/// the chain rules, the two fold twins, the lane routing pins, the walk
/// discharge and the region-tail pins.
pub fn build_split_link(class: &SplitLinkClass, input: &SplitLinkInput<'_>) -> BuiltSplitLink {
    build_split_link_inner(class, input, false)
}

/// [`build_split_link`] core. `freeze = true` only suppresses the final matrix
/// identity check while the one bootstrap matrix is being established.
fn build_split_link_inner(
    class: &SplitLinkClass,
    input: &SplitLinkInput<'_>,
    freeze: bool,
) -> BuiltSplitLink {
    prepare_split_link_native_inner(
        class,
        SplitLinkTraceInput::from_combined(input),
        input.fold_matrix_link,
        input.fold_matrix_block,
        freeze,
    )
    .assemble()
}

/// Begin production native preparation without loading either child matrix.
///
/// This performs class, registry, IO, PCS and transition preflight only. The
/// returned consuming phase accepts exactly the previous-Link matrix; after it
/// returns, that matrix can be dropped before the current Block matrix is
/// loaded.
pub fn begin_split_link_native_preparation<'a>(
    class: &'a SplitLinkClass,
    input: SplitLinkTraceInput<'a>,
) -> Result<SplitLinkPreviousMatrixPhase<'a>, SplitLinkPreparationError> {
    begin_split_link_native_preparation_inner(class, input, false)
}

fn begin_split_link_native_preparation_inner<'a>(
    class: &'a SplitLinkClass,
    input: SplitLinkTraceInput<'a>,
    freeze: bool,
) -> Result<SplitLinkPreviousMatrixPhase<'a>, SplitLinkPreparationError> {
    if !freeze {
        class
            .validate_frozen_identity()
            .map_err(|_| SplitLinkPreparationError::ClassIdentity)?;
    }
    let layout = class.layout();
    let n = class.ladder.len();
    let slot = class.slot;
    if class.spec.io_len != layout.len || layout.b_lanes.len() != n || slot >= n {
        return Err(SplitLinkPreparationError::RegistryShape);
    }
    if input.prev.io().len() != layout.len {
        return Err(SplitLinkPreparationError::PreviousEnvelopeIo);
    }
    if input.block.io().len() != class.b_spec.io_len {
        return Err(SplitLinkPreparationError::BlockEnvelopeIo);
    }
    if input.link_class_digests.len() != n || input.link_post_commit_class_digests.len() != n {
        return Err(SplitLinkPreparationError::RegistryShape);
    }
    if !same_pcs_params(&input.prev.commitment().params, &class.pcs_params) {
        return Err(SplitLinkPreparationError::PreviousPcsParameters);
    }
    if !same_pcs_params(&input.block.commitment().params, &class.b_pcs_params) {
        return Err(SplitLinkPreparationError::BlockPcsParameters);
    }
    if !input.genesis && input.prev_slot >= n {
        return Err(SplitLinkPreparationError::PreviousSlot);
    }
    if input.genesis
        && (input.prev.commitment().root != class.genesis_envelope().commitment().root
            || input.prev.io() != class.genesis_envelope().io())
    {
        return Err(SplitLinkPreparationError::GenesisPredecessor);
    }

    let expected_link_matrix_digest = if input.genesis {
        class.genesis_digest
    } else {
        input.link_class_digests[input.prev_slot]
    };
    let expected_link_post_commit = if input.genesis {
        *class
            .genesis_post_commit_class_digest
            .get()
            .ok_or(SplitLinkPreparationError::ClassIdentity)?
    } else {
        input.link_post_commit_class_digests[input.prev_slot]
    };
    let expected_block_matrix_digest = class.ladder[slot].b_digest;

    if !freeze && !input.genesis {
        for (digest, post_commit) in input
            .link_class_digests
            .iter()
            .zip(&input.link_post_commit_class_digests)
        {
            if *post_commit
                != link_post_commit_class_digest(
                    digest,
                    &class.spec,
                    &class.pcs_params,
                    class.sidecar_vk(),
                )
            {
                return Err(SplitLinkPreparationError::TransitionBinding);
            }
        }
        preflight_split_transition(
            &layout,
            input.prev_slot,
            slot,
            &input.link_class_digests,
            &input.link_post_commit_class_digests,
            input.prev.io(),
            expected_link_matrix_digest,
            expected_link_post_commit,
            expected_block_matrix_digest,
            class.ladder[slot].b_digest,
            &input.block.io()[BLOCK_IO_START_ACC..BLOCK_IO_START_ACC + super::link::ACC_LANES],
            &input.prev.io()[layout.block_acc..layout.block_acc + super::link::ACC_LANES],
        )
        .map_err(|_| SplitLinkPreparationError::TransitionBinding)?;
    }

    Ok(SplitLinkPreviousMatrixPhase {
        core: SplitLinkNativePreparationCore {
            class,
            input,
            layout,
            expected_link_matrix_digest,
            expected_link_post_commit,
            expected_block_matrix_digest,
            freeze,
        },
    })
}

impl<'a> SplitLinkPreviousMatrixPhase<'a> {
    /// Verify/fold the previous Link against one structurally authenticated
    /// matrix and consume this phase. No matrix borrow enters the returned
    /// block phase.
    pub fn prepare_previous_link(
        self,
        fold_matrix_link: &FieldR1cs,
    ) -> Result<SplitLinkBlockMatrixPhase<'a>, SplitLinkPreparationError> {
        let core = self.core;
        validate_split_fold_matrix_identity(
            fold_matrix_link,
            core.class.shape,
            core.expected_link_matrix_digest,
            SplitLinkPreparationError::PreviousMatrixShape,
            SplitLinkPreparationError::PreviousMatrixDigest,
        )?;

        let mut ch_native = FsLaneChallenger::new(b"history-link-v0");
        let (_previous_claim, fresh_link) = verify_field_deferred_matrix_with_post_commit_context(
            &core.class.shape,
            &core.expected_link_matrix_digest,
            core.input.prev.commitment(),
            core.input.prev.field_proof(),
            &core.class.spec,
            core.input.prev.io(),
            &core.expected_link_post_commit,
            core.input.prev.region_sidecar(),
            &mut ch_native,
            |sidecar, context| {
                verify_link_region_sidecar_post_commit(core.class.sidecar_vk(), sidecar, context)
                    .map_err(|_| VerifyError::Auxiliary)
            },
        )
        .map_err(|_| SplitLinkPreparationError::PreviousProof)?;

        let k_l = core.class.shape.k_log;
        let (incoming_link, in_live_link) = if core.input.genesis {
            (MatrixAccClaim::zero(k_l), F128::ZERO)
        } else {
            let lane = &core.layout.link_lanes[core.input.prev_slot];
            (
                MatrixAccClaim {
                    point: core.input.prev.io()[lane.point..lane.value].to_vec(),
                    value: core.input.prev.io()[lane.value],
                },
                core.input.prev.io()[lane.live],
            )
        };
        let gate_link = !core.input.genesis && in_live_link == F128::ONE;
        let (fold_proof_link, acc_link) = prove_split_matrix_fold(
            b"history-link-fold-v0",
            fold_matrix_link,
            &fresh_link,
            &incoming_link,
            gate_link,
        );
        Ok(SplitLinkBlockMatrixPhase {
            core,
            fold_proof_link,
            acc_link,
        })
    }
}

impl<'a> SplitLinkBlockMatrixPhase<'a> {
    /// Verify/fold the current Block against its one class matrix, route the
    /// exact accumulated claims and return matrix-free recursive assembly
    /// material.
    pub fn prepare_current_block(
        self,
        fold_matrix_block: &FieldR1cs,
    ) -> Result<PreparedSplitLink<'a>, SplitLinkPreparationError> {
        let Self {
            core,
            fold_proof_link,
            acc_link,
        } = self;
        let class = core.class;
        let slot = class.slot;
        let b_shape = class.ladder[slot].b_shape;
        validate_split_fold_matrix_identity(
            fold_matrix_block,
            b_shape,
            core.expected_block_matrix_digest,
            SplitLinkPreparationError::BlockMatrixShape,
            SplitLinkPreparationError::BlockMatrixDigest,
        )?;

        let mut ch_native = FsLaneChallenger::new(b"history-block-v0");
        let (_block_claim, fresh_block) = verify_field_deferred_matrix_with_post_commit_context(
            &b_shape,
            &core.expected_block_matrix_digest,
            core.input.block.commitment(),
            core.input.block.field_proof(),
            &class.b_spec,
            core.input.block.io(),
            &class.b_post_commit_class_digest,
            core.input.block.region_sidecar(),
            &mut ch_native,
            |sidecar, context| {
                verify_block_region_sidecar_post_commit(&class.b_sidecar_vk, sidecar, context)
                    .map_err(|_| VerifyError::Auxiliary)
            },
        )
        .map_err(|_| SplitLinkPreparationError::BlockProof)?;

        let b_lane = &core.layout.b_lanes[slot];
        let incoming_block = MatrixAccClaim {
            point: core.input.prev.io()[b_lane.point..b_lane.value].to_vec(),
            value: core.input.prev.io()[b_lane.value],
        };
        let gate_block = core.input.prev.io()[b_lane.live] == F128::ONE;
        let (fold_proof_block, acc_block) = prove_split_matrix_fold(
            b"history-block-fold-v0",
            fold_matrix_block,
            &fresh_block,
            &incoming_block,
            gate_block,
        );
        let io = route_split_transition_io(
            &core.layout,
            core.input.genesis,
            core.input.prev_slot,
            slot,
            &core.input.link_class_digests,
            &core.input.link_post_commit_class_digests,
            core.input.prev.io(),
            &acc_link,
            &acc_block,
            &core.input.block.io()[BLOCK_IO_END_ACC..BLOCK_IO_END_ACC + super::link::ACC_LANES],
        )
        .map_err(|_| SplitLinkPreparationError::IoRouting)?;

        Ok(PreparedSplitLink {
            class,
            input: core.input,
            fold_proof_link,
            fold_proof_block,
            io,
            freeze: core.freeze,
        })
    }
}

/// Compatibility wrapper that accepts both matrix borrows at once.
/// Production proof coordinators should use
/// [`begin_split_link_native_preparation`] and release the previous matrix
/// before loading the current Block matrix.
pub fn prepare_split_link_native<'a>(
    class: &'a SplitLinkClass,
    input: SplitLinkTraceInput<'a>,
    fold_matrix_link: &FieldR1cs,
    fold_matrix_block: &FieldR1cs,
) -> PreparedSplitLink<'a> {
    prepare_split_link_native_inner(class, input, fold_matrix_link, fold_matrix_block, false)
}

fn prepare_split_link_native_inner<'a>(
    class: &'a SplitLinkClass,
    input: SplitLinkTraceInput<'a>,
    fold_matrix_link: &FieldR1cs,
    fold_matrix_block: &FieldR1cs,
    freeze: bool,
) -> PreparedSplitLink<'a> {
    begin_split_link_native_preparation_inner(class, input, freeze)
        .expect("invalid split-link native preparation")
        .prepare_previous_link(fold_matrix_link)
        .expect("previous Link native phase")
        .prepare_current_block(fold_matrix_block)
        .expect("current Block native phase")
}

fn assemble_prepared_split_link(prepared: PreparedSplitLink<'_>) -> BuiltSplitLink {
    let PreparedSplitLink {
        class,
        input,
        fold_proof_link,
        fold_proof_block,
        io,
        freeze,
    } = prepared;
    let layout = class.layout();
    let n = class.ladder.len();
    let k_l = class.shape.k_log;
    let slot = class.slot;
    let b_shape = class.ladder[slot].b_shape;
    let b_lane = &layout.b_lanes[slot];

    // ---- The two inner PCS carriers. Their openings are owned by the
    // post-commit link sidecar, not copied into public IO.
    let r_pcs_proofs = [
        RPcsProof {
            native: &input.prev.field_proof().pcs_open,
            params: &class.pcs_params,
            commitment_root: flat_digest_lanes(&input.prev.commitment().root),
        },
        RPcsProof {
            native: &input.block.field_proof().pcs_open,
            params: &class.b_pcs_params,
            commitment_root: flat_digest_lanes(&input.block.commitment().root),
        },
    ];

    // ---- Trace pass.
    let mut b = FieldR1csBuilder::new();
    let mut ledger = 0usize;
    let io_start = class.spec.io_slice.start();
    while b.num_wires() < io_start {
        b.alloc_f128(F128::ZERO);
    }
    let io_cells: Vec<LinExpr> = (0..1usize << class.spec.io_slice.log2_len)
        .map(|t| {
            let v = if t < layout.len { io[t] } else { F128::ZERO };
            alloc_expr(&mut b, v)
        })
        .collect();
    let g = io_cells[layout.g].clone();

    // ---- Walk-column allocation FIRST (right after the IO cells): the
    // columns' slices — hence the class's opening-claim spec — must be
    // identical across every link class of the ladder, so nothing
    // class-specific (envelope sizes differ per slot!) may precede them.
    let r_cols = prepare_r_pcs_link_columns_universal(
        &mut b,
        &r_pcs_proofs,
        &class.universal_geometry,
        &[0, slot + 1],
    )
    .expect("universal recording-free link columns");
    crate::acceptance::row_ledger_mark(&b, &mut ledger, "split: walk columns");

    // Envelope wires: the previous link, then the block proof.
    let prev_root = alloc_flat_digest(&mut b, &input.prev.commitment().root);
    let prev_io_wires: Vec<LinExpr> = input
        .prev
        .io()
        .iter()
        .map(|&v| alloc_expr(&mut b, v))
        .collect();
    let prev_proof_e = FieldR1csProofTrace::alloc_shape_mode(
        &mut b,
        input.prev.field_proof(),
        &class.shape,
        &class.pcs_params,
        false,
    );
    let block_root = alloc_flat_digest(&mut b, &input.block.commitment().root);
    let block_io_wires: Vec<LinExpr> = input
        .block
        .io()
        .iter()
        .map(|&v| alloc_expr(&mut b, v))
        .collect();
    let block_proof_e = FieldR1csProofTrace::alloc_shape_mode(
        &mut b,
        input.block.field_proof(),
        &b_shape,
        &class.b_pcs_params,
        false,
    );
    crate::acceptance::row_ledger_mark(&b, &mut ledger, "split: IO + envelope alloc");

    // ---- β selector: one-hot over the previous link's ladder slot,
    // all-zero at genesis (Σ β = 1 + g).
    let one = LinExpr::constant(F128::ONE);
    let not_g = one.add(&g);
    let beta: Vec<LinExpr> = (0..n)
        .map(|a| {
            let v = if !input.genesis && a == input.prev_slot {
                F128::ONE
            } else {
                F128::ZERO
            };
            alloc_expr(&mut b, v)
        })
        .collect();
    // g and every β boolean; Σ β = 1 + g.
    let g_bool = mul(&mut b, &g, &not_g);
    pin_eq(&mut b, &g_bool, &LinExpr::zero());
    let mut beta_sum = LinExpr::zero();
    for ba in &beta {
        let nb = one.add(ba);
        let bb = mul(&mut b, ba, &nb);
        pin_eq(&mut b, &bb, &LinExpr::zero());
        beta_sum = beta_sum.add(ba);
    }
    pin_eq(&mut b, &beta_sum, &not_g);

    // A g=1 link verifies the one canonical bootstrap witness.  Matrix and
    // sidecar validity alone would also admit other full-identity T witnesses;
    // the root and zero IO pins make the ghost instance unique across slots.
    let canonical_t_root = flat_digest_lanes(&class.genesis_envelope().commitment().root);
    for lane in 0..2 {
        let delta = prev_root[lane].add(&LinExpr::constant(canonical_t_root[lane]));
        let gated = mul(&mut b, &g, &delta);
        pin_eq(&mut b, &gated, &LinExpr::zero());
    }
    for wire in &prev_io_wires {
        let gated = mul(&mut b, &g, wire);
        pin_eq(&mut b, &gated, &LinExpr::zero());
    }

    // ---- The verified digest: w_D = Σ β_a·WL_a + g·D_T. Subsumes the
    // genesis rule (β all-zero under g = 1 by the sum pin).
    let d_t = flat_digest_lanes(&class.genesis_digest);
    let w_d: FlatDigestExpr = [0usize, 1usize].map(|lane| {
        let mut acc = g.scale(d_t[lane]);
        for (a, ba) in beta.iter().enumerate() {
            let wl_cell = &io_cells[layout.wl + 2 * a + lane];
            acc = acc.add(&mul(&mut b, ba, wl_cell));
        }
        acc
    });
    let genesis_pc = flat_digest_lanes(
        class
            .genesis_post_commit_class_digest
            .get()
            .expect("frozen genesis post-commit identity"),
    );
    let w_post_commit: FlatDigestExpr = [0usize, 1usize].map(|lane| {
        let mut acc = g.scale(genesis_pc[lane]);
        for (a, ba) in beta.iter().enumerate() {
            let wl_cell = &io_cells[layout.wl_post_commit + 2 * a + lane];
            acc = acc.add(&mul(&mut b, ba, wl_cell));
        }
        acc
    });

    // ---- [R]_prev: the deferred replay of the previous link's proof,
    // in REGION mode — its PCS hashing lands on the link walks below.
    let mut obs_prev = PcsWalkObligations::default();
    let mut ch = FsChannelTrace::new(&mut b, b"history-link-v0");
    let (_pce, fresh_link_e) = verify_field_trace_deferred_region_with_post_commit_context_expr(
        &mut b,
        &mut ch,
        &class.shape,
        &class.pcs_params,
        &w_d,
        &prev_root,
        &prev_proof_e,
        &class.spec,
        &prev_io_wires,
        &w_post_commit,
        Some(&mut obs_prev),
        |builder, context| {
            verify_link_region_sidecar_trace_post_commit(
                builder,
                context,
                class.sidecar_vk(),
                input.prev.region_sidecar(),
            )
            .expect("previous link sidecar trace shape")
        },
    );
    crate::acceptance::row_ledger_mark(&b, &mut ledger, "split: [R]_prev replay");

    // ---- [R]_B: the deferred replay of the block proof, against the
    // BAKED block-class digest.
    let d_b = flat_digest_lanes(&class.ladder[slot].b_digest);
    let w_b: FlatDigestExpr = [LinExpr::constant(d_b[0]), LinExpr::constant(d_b[1])];
    let mut obs_block = PcsWalkObligations::default();
    let mut chb = FsChannelTrace::new(&mut b, b"history-block-v0");
    let (_bce, fresh_block_e) = verify_field_trace_deferred_region_with_post_commit_context(
        &mut b,
        &mut chb,
        &b_shape,
        &class.b_pcs_params,
        &w_b,
        &block_root,
        &block_proof_e,
        &class.b_spec,
        &block_io_wires,
        &class.b_post_commit_class_digest,
        Some(&mut obs_block),
        |builder, context| {
            verify_block_region_sidecar_trace_post_commit(
                builder,
                context,
                &class.b_sidecar_vk,
                input.block.region_sidecar(),
            )
            .expect("block sidecar trace shape")
        },
    );
    crate::acceptance::row_ledger_mark(&b, &mut ledger, "split: [R]_B replay");

    // ---- Genesis arm: the fresh [R]_prev claim equals T's baked
    // bilinear value under g = 1.
    let baked = split_genesis_baked_claim_value(&mut b, &fresh_link_e);
    let diff = fresh_link_e.value.add(&baked);
    let gated = mul(&mut b, &g, &diff);
    pin_eq(&mut b, &gated, &LinExpr::zero());

    // ---- Whitelist inheritance (gated off only at genesis).
    for j in 0..4 * n {
        let diff = io_cells[layout.wl + j].add(&prev_io_wires[layout.wl + j]);
        let gated = mul(&mut b, &not_g, &diff);
        pin_eq(&mut b, &gated, &LinExpr::zero());
    }

    // ---- Link-lane fold twin: incoming = β-mux over the previous link
    // lanes; the fold's incoming gate = the muxed liveness (β is already
    // zero at genesis, so no extra not_g factor is needed).
    let mux_lane = |b: &mut FieldR1csBuilder, pick: &dyn Fn(&SplitLaneLayout) -> usize| {
        let mut acc = LinExpr::zero();
        for (a, ba) in beta.iter().enumerate() {
            let src = prev_io_wires[pick(&layout.link_lanes[a])].clone();
            acc = acc.add(&mul(b, ba, &src));
        }
        acc
    };
    let incoming_link_e = MatrixAccClaimTrace {
        point: (0..2 * k_l + 1)
            .map(|j| mux_lane(&mut b, &|lane: &SplitLaneLayout| lane.point + j))
            .collect(),
        value: mux_lane(&mut b, &|lane: &SplitLaneLayout| lane.value),
    };
    let gate_link_e = mux_lane(&mut b, &|lane: &SplitLaneLayout| lane.live);
    let fold_proof_link_e = MatrixFoldProofTrace::alloc(&mut b, &fold_proof_link, k_l);
    let mut chf = FsChannelTrace::new(&mut b, b"history-link-fold-v0");
    let acc_link_e = verify_matrix_claim_fold_trace(
        &mut b,
        &mut chf,
        k_l,
        class.shape.k_skip,
        &fresh_link_e,
        &incoming_link_e,
        &gate_link_e,
        &fold_proof_link_e,
    );

    // Link-lane routing: lane a carries the fold output when β_a = 1,
    // otherwise passes the previous lane through; liveness is the
    // monotone OR of selection and inheritance.
    for (a, lane) in layout.link_lanes.iter().enumerate() {
        let ba = &beta[a];
        for j in 0..=2 * k_l + 1 {
            let (own, prev_v, fold_v) = if j <= 2 * k_l {
                (
                    &io_cells[lane.point + j],
                    &prev_io_wires[lane.point + j],
                    &acc_link_e.point[j],
                )
            } else {
                (
                    &io_cells[lane.value],
                    &prev_io_wires[lane.value],
                    &acc_link_e.value,
                )
            };
            let delta = fold_v.add(prev_v);
            let picked = mul(&mut b, ba, &delta);
            pin_eq(&mut b, own, &prev_v.add(&picked));
        }
        let prev_live = &prev_io_wires[lane.live];
        let overlap = mul(&mut b, ba, prev_live);
        pin_eq(
            &mut b,
            &io_cells[lane.live],
            &ba.add(prev_live).add(&overlap),
        );
    }

    // ---- Block-lane fold twin (own slot; no β, no genesis gating — a
    // genesis link folds its block 0 claim; the incoming gate rides the
    // previous liveness alone, dead against T's zero IO).
    let incoming_block_e = MatrixAccClaimTrace {
        point: (b_lane.point..b_lane.value)
            .map(|j| prev_io_wires[j].clone())
            .collect(),
        value: prev_io_wires[b_lane.value].clone(),
    };
    let gate_block_e = prev_io_wires[b_lane.live].clone();
    let fold_proof_block_e = MatrixFoldProofTrace::alloc(&mut b, &fold_proof_block, b_shape.k_log);
    let mut chf2 = FsChannelTrace::new(&mut b, b"history-block-fold-v0");
    let acc_block_e = verify_matrix_claim_fold_trace(
        &mut b,
        &mut chf2,
        b_shape.k_log,
        b_shape.k_skip,
        &fresh_block_e,
        &incoming_block_e,
        &gate_block_e,
        &fold_proof_block_e,
    );
    for (t, lane) in layout.b_lanes.iter().enumerate() {
        if t == slot {
            for (j, p) in acc_block_e.point.iter().enumerate() {
                pin_eq(&mut b, p, &io_cells[lane.point + j]);
            }
            pin_eq(&mut b, &acc_block_e.value, &io_cells[lane.value]);
            // Selected liveness is identically 1 (OR with anything).
            pin_eq(&mut b, &io_cells[lane.live], &one);
        } else {
            for j in lane.point..=lane.live {
                pin_eq(&mut b, &io_cells[j], &prev_io_wires[j]);
            }
        }
    }
    crate::acceptance::row_ledger_mark(&b, &mut ledger, "split: folds + lane routing");

    // ---- Block chaining: the block's start accumulator continues the
    // chain (genesis pins the class constant), its end accumulator IS
    // this link's exposed block accumulator.
    let genesis_start = block_acc_lanes(&class.genesis_block_accumulator);
    for i in 0..super::link::ACC_LANES {
        let sw = &block_io_wires[BLOCK_IO_START_ACC + i];
        let to_genesis = sw.add(&LinExpr::constant(genesis_start[i]));
        let g_gated = mul(&mut b, &g, &to_genesis);
        pin_eq(&mut b, &g_gated, &LinExpr::zero());
        let to_prev = sw.add(&prev_io_wires[layout.block_acc + i]);
        let ng_gated = mul(&mut b, &not_g, &to_prev);
        pin_eq(&mut b, &ng_gated, &LinExpr::zero());
        let ew = &block_io_wires[BLOCK_IO_END_ACC + i];
        pin_eq(&mut b, ew, &io_cells[layout.block_acc + i]);
    }
    crate::acceptance::row_ledger_mark(&b, &mut ledger, "split: chain rules");

    let region_preparation = finalize_r_pcs_link_region(&mut b, r_cols, &[&obs_prev, &obs_block])
        .expect("recording-free link semantic binding");
    assert_eq!(
        region_preparation.vk(),
        class.sidecar_vk(),
        "link sidecar VK drifted from the universal frozen key"
    );
    crate::acceptance::row_ledger_mark(&b, &mut ledger, "split: link sidecar semantic pins");

    // ---- Pad to the class size.
    let target = 1usize << class.shape.m;
    let used = b.num_wires();
    eprintln!(
        "[split-link] build: {used} wires (slot {slot}, genesis={}, freeze={freeze})",
        input.genesis
    );
    assert!(
        used <= target,
        "split link outgrew the class shape: {used} > {target}"
    );
    let (r1cs, witness) = b.build();
    let (r1cs, witness) = super::expand_empty_field_tail(r1cs, witness, class.shape);
    assert_eq!(r1cs.m, class.shape.m, "class shape mismatch after padding");
    assert_eq!(r1cs.useful_rows, used, "link useful-row accounting");
    if !freeze {
        let class_digest = class
            .class_statement_digest
            .get()
            .expect("frozen link matrix digest");
        assert_eq!(
            r1cs.statement_digest(),
            *class_digest,
            "same-slot link matrix drifted from its frozen class"
        );
        r1cs.seed_statement_digest(*class_digest);
    }
    BuiltSplitLink {
        r1cs,
        witness,
        io,
        region_preparation,
    }
}

enum PendingMatrixLane {
    Dead,
    Pending {
        claim: MatrixAccClaim,
        expected_digest: [u8; 32],
    },
    Checked,
}

/// A fully verified split tip whose live accumulated matrix lanes still need
/// local structural evaluation.
///
/// The fields are deliberately private and the type is deliberately not
/// `Clone`: callers may load/rebuild one matrix, check its lane, and release it,
/// but acceptance is returned only by consuming [`Self::finish`] after every
/// live lane has been checked.
#[must_use = "a pending split-tip decision is not accepted until finish() succeeds"]
pub struct PendingSplitTipDecision {
    link_lanes: Vec<PendingMatrixLane>,
    block_lanes: Vec<PendingMatrixLane>,
}

impl PendingSplitTipDecision {
    fn link_lane_is_pending(&self, slot: usize) -> bool {
        matches!(
            self.link_lanes.get(slot),
            Some(PendingMatrixLane::Pending { .. })
        )
    }

    fn block_lane_is_pending(&self, slot: usize) -> bool {
        matches!(
            self.block_lanes.get(slot),
            Some(PendingMatrixLane::Pending { .. })
        )
    }

    fn check_lane_with_evaluation(
        lanes: &mut [PendingMatrixLane],
        slot: usize,
        family: &str,
        shape: FieldShape,
        actual_digest: [u8; 32],
        actual_value: Option<F128>,
    ) -> Result<(), String> {
        let what = format!("{family} lane {slot}");
        let lane = lanes
            .get(slot)
            .ok_or_else(|| format!("{what}: slot out of range"))?;
        let (claim, expected_digest) = match lane {
            PendingMatrixLane::Dead => {
                return Err(format!("{what}: matrix supplied for a dead lane"));
            }
            PendingMatrixLane::Checked => {
                return Err(format!("{what}: matrix lane was already checked"));
            }
            PendingMatrixLane::Pending {
                claim,
                expected_digest,
            } => (claim, expected_digest),
        };

        if &actual_digest != expected_digest {
            return Err(format!(
                "{what}: matrix does not match the published digest"
            ));
        }
        if claim.point.len() != 2 * shape.k_log + 1 {
            return Err(format!(
                "{what}: lane width does not match the matrix shape"
            ));
        }
        if actual_value != Some(claim.value) {
            return Err(format!("{what}: accumulated matrix claim is false"));
        }
        lanes[slot] = PendingMatrixLane::Checked;
        Ok(())
    }

    fn check_lane(
        lanes: &mut [PendingMatrixLane],
        slot: usize,
        matrix: &mut dyn MatrixClaimEvaluator,
        family: &str,
    ) -> Result<(), String> {
        let what = format!("{family} lane {slot}");
        let claim = match lanes.get(slot) {
            Some(PendingMatrixLane::Pending { claim, .. }) => claim.clone(),
            Some(PendingMatrixLane::Dead) => {
                return Err(format!("{what}: matrix supplied for a dead lane"));
            }
            Some(PendingMatrixLane::Checked) => {
                return Err(format!("{what}: matrix lane was already checked"));
            }
            None => return Err(format!("{what}: slot out of range")),
        };
        let shape = matrix.field_shape();
        let evaluated = matrix
            .evaluate_matrix_claims(None, Some(&claim))
            .map_err(|error| format!("{what}: matrix evaluation failed: {error}"))?;
        Self::check_lane_with_evaluation(
            lanes,
            slot,
            family,
            shape,
            evaluated.structural_digest(),
            evaluated.accumulated_value(),
        )
    }

    fn check_lane_field_r1cs(
        lanes: &mut [PendingMatrixLane],
        slot: usize,
        matrix: &FieldR1cs,
        family: &str,
    ) -> Result<(), String> {
        let claim = match lanes.get(slot) {
            Some(PendingMatrixLane::Pending { claim, .. }) => claim,
            Some(PendingMatrixLane::Dead) => {
                return Err(format!(
                    "{family} lane {slot}: matrix supplied for a dead lane"
                ));
            }
            Some(PendingMatrixLane::Checked) => {
                return Err(format!(
                    "{family} lane {slot}: matrix lane was already checked"
                ));
            }
            None => return Err(format!("{family} lane {slot}: slot out of range")),
        };
        Self::check_lane_with_evaluation(
            lanes,
            slot,
            family,
            FieldShape::of(matrix),
            matrix.structural_statement_digest(),
            Some(stacked_matrix_mle_eval(matrix, claim)),
        )
    }

    /// Check one live Link-class accumulator lane against a transient local
    /// matrix. The matrix may be released as soon as this method returns.
    pub fn check_link_matrix(
        &mut self,
        slot: usize,
        matrix: &mut dyn MatrixClaimEvaluator,
    ) -> Result<(), String> {
        Self::check_lane(&mut self.link_lanes, slot, matrix, "link")
    }

    /// Check one live Block-class accumulator lane against a transient local
    /// matrix. The matrix may be released as soon as this method returns.
    pub fn check_block_matrix(
        &mut self,
        slot: usize,
        matrix: &mut dyn MatrixClaimEvaluator,
    ) -> Result<(), String> {
        Self::check_lane(&mut self.block_lanes, slot, matrix, "block")
    }

    /// Accept only after every live Link and Block lane was checked exactly
    /// once. Dead lanes require no matrix and remain dead.
    pub fn finish(self) -> Result<(), String> {
        for (slot, lane) in self.link_lanes.iter().enumerate() {
            if matches!(lane, PendingMatrixLane::Pending { .. }) {
                return Err(format!(
                    "link lane {slot}: live lane was not checked against its matrix"
                ));
            }
        }
        for (slot, lane) in self.block_lanes.iter().enumerate() {
            if matches!(lane, PendingMatrixLane::Pending { .. }) {
                return Err(format!(
                    "block lane {slot}: live lane was not checked against its matrix"
                ));
            }
        }
        Ok(())
    }
}

fn finish_tip_split_decision_with_matrix_banks(
    mut pending: PendingSplitTipDecision,
    link_matrices: &[Option<&FieldR1cs>],
    block_matrices: &[Option<&FieldR1cs>],
) -> Result<(), String> {
    assert_eq!(link_matrices.len(), pending.link_lanes.len());
    assert_eq!(block_matrices.len(), pending.block_lanes.len());
    for (slot, matrix) in link_matrices.iter().enumerate() {
        if pending.link_lane_is_pending(slot) {
            PendingSplitTipDecision::check_lane_field_r1cs(
                &mut pending.link_lanes,
                slot,
                matrix.ok_or_else(|| format!("link lane {slot}: live lane without its matrix"))?,
                "link",
            )?;
        }
    }
    for (slot, matrix) in block_matrices.iter().enumerate() {
        if pending.block_lane_is_pending(slot) {
            PendingSplitTipDecision::check_lane_field_r1cs(
                &mut pending.block_lanes,
                slot,
                matrix.ok_or_else(|| format!("block lane {slot}: live lane without its matrix"))?,
                "block",
            )?;
        }
    }
    pending.finish()
}

fn pending_lane(
    tip: &LinkProofEnvelope,
    lane: &SplitLaneLayout,
    expected_digest: [u8; 32],
    what: &str,
) -> Result<PendingMatrixLane, String> {
    match tip.io()[lane.live] {
        F128::ZERO => Ok(PendingMatrixLane::Dead),
        F128::ONE => Ok(PendingMatrixLane::Pending {
            claim: MatrixAccClaim {
                point: tip.io()[lane.point..lane.value].to_vec(),
                value: tip.io()[lane.value],
            },
            expected_digest,
        }),
        _ => Err(format!("{what}: non-boolean liveness")),
    }
}

fn pending_tip_split_decision_after_verified_proof(
    tip_class: &SplitLinkClass,
    tip: &LinkProofEnvelope,
    link_class_digests: &[[u8; 32]],
    link_post_commit_class_digests: &[[u8; 32]],
) -> Result<PendingSplitTipDecision, String> {
    let layout = tip_class.layout();
    let n = tip_class.ladder.len();
    assert_eq!(link_class_digests.len(), n);
    assert_eq!(link_post_commit_class_digests.len(), n);

    if tip_class.class_statement_digest.get().copied() != Some(link_class_digests[tip_class.slot]) {
        return Err("tip class is not the published one".into());
    }

    if tip_class.post_commit_class_digest() != &link_post_commit_class_digests[tip_class.slot] {
        return Err("tip post-commit class is not the published one".into());
    }
    for (slot, matrix_digest) in link_class_digests.iter().enumerate() {
        let expected = link_post_commit_class_digest(
            matrix_digest,
            &tip_class.spec,
            &tip_class.pcs_params,
            tip_class.sidecar_vk(),
        );
        if link_post_commit_class_digests[slot] != expected {
            return Err(format!(
                "link slot {slot}: composite digest is not derived from its matrix class"
            ));
        }
    }
    if tip.io()[layout.g] != F128::ZERO && tip.io()[layout.g] != F128::ONE {
        return Err("tip has a non-boolean genesis-predecessor flag".into());
    }
    for (a, d) in link_class_digests.iter().enumerate() {
        let lanes = flat_digest_lanes(d);
        if tip.io()[layout.wl + 2 * a] != lanes[0] || tip.io()[layout.wl + 2 * a + 1] != lanes[1] {
            return Err(format!(
                "whitelist lane {a} does not carry the class digest"
            ));
        }
    }
    for (a, digest) in link_post_commit_class_digests.iter().enumerate() {
        let lanes = flat_digest_lanes(digest);
        if tip.io()[layout.wl_post_commit + 2 * a] != lanes[0]
            || tip.io()[layout.wl_post_commit + 2 * a + 1] != lanes[1]
        {
            return Err(format!(
                "post-commit whitelist lane {a} does not carry the class digest"
            ));
        }
    }

    let mut link_lanes = Vec::with_capacity(n);
    let mut block_lanes = Vec::with_capacity(n);
    for slot in 0..n {
        link_lanes.push(pending_lane(
            tip,
            &layout.link_lanes[slot],
            link_class_digests[slot],
            &format!("link lane {slot}"),
        )?);
        block_lanes.push(pending_lane(
            tip,
            &layout.b_lanes[slot],
            tip_class.ladder[slot].b_digest,
            &format!("block lane {slot}"),
        )?);
    }
    Ok(PendingSplitTipDecision {
        link_lanes,
        block_lanes,
    })
}

/// A completely replayed tip proof whose sole remaining obligation is its
/// deferred lincheck final against the canonical Link CSR.
///
/// The fresh claim is private and this type exposes no `finish`: acceptance
/// can only continue by consuming [`Self::discharge_tip_matrix`].  This makes
/// accidentally dropping the matrix check distinct from accepting the tip.
#[must_use = "the deferred tip claim must be discharged against its class matrix"]
pub struct DeferredSplitTipDecision {
    pending: PendingSplitTipDecision,
    fresh: FreshLincheckClaim,
    tip_slot: usize,
    expected_shape: FieldShape,
    expected_digest: [u8; 32],
}

impl DeferredSplitTipDecision {
    /// Consume the deferred state and evaluate its fresh lincheck claim
    /// through the leased authenticated matrix evaluator. Shape and structural
    /// digest checks bind the exact rows used for evaluation; a seeded digest
    /// cache cannot authenticate mutated sparse rows. If the tip Link
    /// accumulator lane is live, it is evaluated in the same pass before the
    /// pending decision is returned. Thus neither tip obligation can be
    /// omitted and an on-disk matrix never needs a resident CSR.
    pub fn discharge_tip_matrix(
        self,
        tip_class_r1cs: &mut dyn MatrixClaimEvaluator,
    ) -> Result<PendingSplitTipDecision, LinkProofError> {
        if tip_class_r1cs.field_shape() != self.expected_shape {
            return Err(LinkProofError::MatrixMismatch);
        }
        let tip_claim = match self.pending.link_lanes.get(self.tip_slot) {
            Some(PendingMatrixLane::Pending { claim, .. }) => Some(claim),
            _ => None,
        };
        let evaluated = tip_class_r1cs
            .evaluate_matrix_claims(Some(&self.fresh), tip_claim)
            .map_err(|_| LinkProofError::MatrixMismatch)?;
        if evaluated.structural_digest() != self.expected_digest {
            return Err(LinkProofError::MatrixMismatch);
        }
        if evaluated.fresh_value() != Some(self.fresh.value) {
            return Err(LinkProofError::MatrixClaimMismatch);
        }
        let mut pending = self.pending;
        if pending.link_lane_is_pending(self.tip_slot) {
            PendingSplitTipDecision::check_lane_with_evaluation(
                &mut pending.link_lanes,
                self.tip_slot,
                "link",
                self.expected_shape,
                evaluated.structural_digest(),
                evaluated.accumulated_value(),
            )
            .map_err(|_| LinkProofError::AccumulatorClaimMismatch)?;
        }
        Ok(pending)
    }
}

/// Replay the tip proof and both published whitelists without constructing a
/// generic lincheck comb or a CSC matrix.  The returned typestate is still not
/// an acceptance result and must be discharged against the canonical CSR.
pub fn begin_tip_split_decision_deferred_matrix(
    tip_class: &SplitLinkClass,
    tip: &LinkProofEnvelope,
    link_class_digests: &[[u8; 32]],
    link_post_commit_class_digests: &[[u8; 32]],
) -> Result<DeferredSplitTipDecision, String> {
    let n = tip_class.ladder.len();
    assert_eq!(link_class_digests.len(), n);
    assert_eq!(link_post_commit_class_digests.len(), n);

    let mut ch = FsLaneChallenger::new(b"history-link-v0");
    let (_claim, fresh) = verify_split_link_proof_deferred_matrix(tip_class, tip, &mut ch)
        .map_err(|error| format!("tip proof rejected: {error:?}"))?;
    let pending = pending_tip_split_decision_after_verified_proof(
        tip_class,
        tip,
        link_class_digests,
        link_post_commit_class_digests,
    )?;
    Ok(DeferredSplitTipDecision {
        pending,
        fresh,
        tip_slot: tip_class.slot,
        expected_shape: tip_class.shape,
        expected_digest: link_class_digests[tip_class.slot],
    })
}

/// Verify the tip proof and both published class whitelists, then return the
/// one-shot set of live matrix claims. Matrix evaluation is intentionally
/// deferred so a synchronizing node can rebuild/load and release one local
/// class matrix at a time.
///
/// This compatibility path retains the generic full Field verifier. New
/// bounded-memory terminal verification uses
/// [`begin_tip_split_decision_deferred_matrix`] and discharges its typestate
/// over the already leased CSR.
pub fn begin_tip_split_decision(
    tip_class: &SplitLinkClass,
    tip_class_r1cs: &FieldR1cs,
    tip: &LinkProofEnvelope,
    link_class_digests: &[[u8; 32]],
    link_post_commit_class_digests: &[[u8; 32]],
) -> Result<PendingSplitTipDecision, String> {
    let n = tip_class.ladder.len();
    assert_eq!(link_class_digests.len(), n);
    assert_eq!(link_post_commit_class_digests.len(), n);

    if tip_class_r1cs.structural_statement_digest() != link_class_digests[tip_class.slot] {
        return Err("tip class matrix is not the published one".into());
    }

    let mut ch = FsLaneChallenger::new(b"history-link-v0");
    verify_split_link_proof(tip_class, tip_class_r1cs, tip, &mut ch)
        .map_err(|e| format!("tip proof rejected: {e:?}"))?;
    pending_tip_split_decision_after_verified_proof(
        tip_class,
        tip,
        link_class_digests,
        link_post_commit_class_digests,
    )
}

/// The split-chain decider: natively verify the tip against its published
/// class matrix, pin the whitelist to the true link-class digests and evaluate
/// every LIVE lane's accumulated claim against its matrix.
///
/// This compatibility entry point retains the simultaneous matrix-bank API;
/// new synchronization code can call [`begin_tip_split_decision`] and stream
/// the same checks one matrix at a time. `None` is valid only for DEAD lanes.
pub fn decide_tip_split(
    tip_class: &SplitLinkClass,
    tip_class_r1cs: &FieldR1cs,
    tip: &LinkProofEnvelope,
    link_class_digests: &[[u8; 32]],
    link_post_commit_class_digests: &[[u8; 32]],
    link_matrices: &[Option<&FieldR1cs>],
    block_matrices: &[Option<&FieldR1cs>],
) -> Result<(), String> {
    let n = tip_class.ladder.len();
    assert_eq!(link_matrices.len(), n);
    assert_eq!(block_matrices.len(), n);
    let pending = begin_tip_split_decision(
        tip_class,
        tip_class_r1cs,
        tip,
        link_class_digests,
        link_post_commit_class_digests,
    )?;
    finish_tip_split_decision_with_matrix_banks(pending, link_matrices, block_matrices)
}

/// Split-link final decider anchored to the node's locally selected canonical
/// tip and transaction-epoch header.
#[allow(clippy::too_many_arguments)]
pub fn decide_block_tip_split(
    tip_class: &SplitLinkClass,
    tip_class_r1cs: &FieldR1cs,
    tip: &LinkProofEnvelope,
    link_class_digests: &[[u8; 32]],
    link_post_commit_class_digests: &[[u8; 32]],
    link_matrices: &[Option<&FieldR1cs>],
    block_matrices: &[Option<&FieldR1cs>],
    local_tip_header: &BlockHeader,
    local_epoch_anchor_header: &BlockHeader,
) -> Result<(), String> {
    decide_tip_split(
        tip_class,
        tip_class_r1cs,
        tip,
        link_class_digests,
        link_post_commit_class_digests,
        link_matrices,
        block_matrices,
    )?;
    let accumulator = tip_block_accumulator_split(tip_class, tip)
        .map_err(|error| format!("tip accumulator decode failed: {error:?}"))?;
    accumulator
        .validate_local_header_boundary(local_tip_header, local_epoch_anchor_header)
        .map_err(|error| format!("tip does not match local canonical headers: {error}"))
}

/// The tip's exposed block chain accumulator — the value a fresh peer
/// anchors against its locally validated headers (I8).
pub fn tip_block_accumulator_split(
    tip_class: &SplitLinkClass,
    tip: &LinkProofEnvelope,
) -> Result<ChainAccumulator, ChainAccumulatorLaneError> {
    let layout = tip_class.layout();
    let lanes =
        std::array::from_fn(|i| Block128::from(flat_to_block(tip.io()[layout.block_acc + i])));
    ChainAccumulator::from_lanes(lanes)
}

/// Recover the u128 a flat IO lane encodes.
fn flat_to_block(v: F128) -> u128 {
    use noid_core::hardware::flat_to_tower_u128;
    flat_to_tower_u128((v.lo as u128) | ((v.hi as u128) << 64))
}

#[cfg(test)]
mod tests {
    use super::*;
    use noid_ivc_core::matrix_claim::{fresh_claim_value, FreshLincheckClaim};

    fn ladder_test_shape(m: usize) -> FieldShape {
        FieldShape {
            m,
            k_log: m,
            k_skip: noid_ivc_core::zerocheck::K_SKIP,
            const_pin: Some(0),
        }
    }

    fn ladder_test_pcs(m: usize) -> PcsParams {
        PcsParams {
            m: m + noid_ivc_core::pcs::LOG_PACKING,
            log_inv_rate: CANONICAL_PCS_LOG_INV_RATE,
            log_batch_size: CANONICAL_PCS_LOG_BATCH_SIZE,
            profile: Default::default(),
        }
    }

    fn canonical_test_slots() -> Vec<LadderSlotInfo> {
        [
            (8usize, 22usize),
            (32usize, 23usize),
            (64usize, 23usize),
            (255usize, 24usize),
        ]
        .into_iter()
        .map(|(tier, m)| LadderSlotInfo {
            tier,
            b_shape: ladder_test_shape(m),
            b_digest: [tier as u8; 32],
            b_pcs_params: ladder_test_pcs(m),
            b_post_commit_class_digest: [tier.wrapping_add(1) as u8; 32],
            b_sidecar_vk_digest: [tier.wrapping_add(2) as u8; 32],
        })
        .collect()
    }

    #[test]
    fn canonical_split_link_ladder_accepts_only_the_consensus_table() {
        let descriptor = CanonicalSplitLinkLadder::try_new(
            ladder_test_shape(24),
            ladder_test_pcs(24),
            canonical_test_slots(),
        )
        .expect("canonical four-slot descriptor");
        assert_eq!(
            descriptor
                .slots()
                .iter()
                .map(|slot| slot.tier)
                .collect::<Vec<_>>(),
            noid_chain::consensus::params::USER_TX_CLASS_TIERS
        );
        assert_eq!(descriptor.link_shape(), ladder_test_shape(24));
        assert!(same_pcs_params(
            descriptor.link_pcs_params(),
            &ladder_test_pcs(24)
        ));

        let short = canonical_test_slots().into_iter().take(3).collect();
        assert_eq!(
            CanonicalSplitLinkLadder::try_new(ladder_test_shape(24), ladder_test_pcs(24), short,)
                .unwrap_err(),
            CanonicalLadderError::SlotCount {
                expected: 4,
                actual: 3,
            }
        );
    }

    #[test]
    fn canonical_split_link_ladder_rejects_tier_mutation_and_order_drift() {
        let mut mutated = canonical_test_slots();
        mutated[2].tier = 63;
        assert_eq!(
            CanonicalSplitLinkLadder::try_new(ladder_test_shape(24), ladder_test_pcs(24), mutated,)
                .unwrap_err(),
            CanonicalLadderError::TierMismatch {
                slot: 2,
                expected: 64,
                actual: 63,
            }
        );

        let mut reordered = canonical_test_slots();
        reordered.swap(0, 1);
        assert_eq!(
            CanonicalSplitLinkLadder::try_new(
                ladder_test_shape(24),
                ladder_test_pcs(24),
                reordered,
            )
            .unwrap_err(),
            CanonicalLadderError::TierMismatch {
                slot: 0,
                expected: 8,
                actual: 32,
            }
        );
    }

    #[test]
    fn canonical_split_link_ladder_rejects_shape_and_pcs_drift() {
        let mut non_block_shape = canonical_test_slots();
        non_block_shape[2].b_shape.k_log -= 1;
        assert_eq!(
            CanonicalSplitLinkLadder::try_new(
                ladder_test_shape(24),
                ladder_test_pcs(24),
                non_block_shape,
            )
            .unwrap_err(),
            CanonicalLadderError::BlockShape { slot: 2 }
        );

        let mut bad_shape = canonical_test_slots();
        bad_shape[1].b_pcs_params.m += 1;
        assert_eq!(
            CanonicalSplitLinkLadder::try_new(
                ladder_test_shape(24),
                ladder_test_pcs(24),
                bad_shape,
            )
            .unwrap_err(),
            CanonicalLadderError::BlockPcsShape { slot: 1 }
        );

        let mut bad_queries = canonical_test_slots();
        bad_queries[3].b_pcs_params.log_inv_rate = 1;
        assert_eq!(
            CanonicalSplitLinkLadder::try_new(
                ladder_test_shape(24),
                ladder_test_pcs(24),
                bad_queries,
            )
            .unwrap_err(),
            CanonicalLadderError::BlockPcsParameters { slot: 3 }
        );

        assert_eq!(
            CanonicalSplitLinkLadder::try_new(
                ladder_test_shape(8),
                ladder_test_pcs(8),
                canonical_test_slots(),
            )
            .unwrap_err(),
            CanonicalLadderError::LinkClassSize {
                expected: CANONICAL_LINK_CLASS_M,
                actual: 8,
            }
        );
    }

    #[test]
    fn canonical_split_link_ladder_rejects_nonproduction_sizes_and_pcs() {
        let mut non_block_link_shape = ladder_test_shape(CANONICAL_LINK_CLASS_M);
        non_block_link_shape.k_log -= 1;
        assert_eq!(
            CanonicalSplitLinkLadder::try_new(
                non_block_link_shape,
                ladder_test_pcs(CANONICAL_LINK_CLASS_M),
                canonical_test_slots(),
            )
            .unwrap_err(),
            CanonicalLadderError::LinkShape
        );

        let mut wrong_link_pcs_m = ladder_test_pcs(CANONICAL_LINK_CLASS_M);
        wrong_link_pcs_m.m += 1;
        assert_eq!(
            CanonicalSplitLinkLadder::try_new(
                ladder_test_shape(CANONICAL_LINK_CLASS_M),
                wrong_link_pcs_m,
                canonical_test_slots(),
            )
            .unwrap_err(),
            CanonicalLadderError::LinkPcsShape
        );

        let mut wrong_block_m = canonical_test_slots();
        wrong_block_m[0].b_shape = ladder_test_shape(23);
        wrong_block_m[0].b_pcs_params = ladder_test_pcs(23);
        assert_eq!(
            CanonicalSplitLinkLadder::try_new(
                ladder_test_shape(CANONICAL_LINK_CLASS_M),
                ladder_test_pcs(CANONICAL_LINK_CLASS_M),
                wrong_block_m,
            )
            .unwrap_err(),
            CanonicalLadderError::BlockClassSize {
                slot: 0,
                expected: CANONICAL_BLOCK_CLASS_MS[0],
                actual: 23,
            }
        );

        let mut wrong_link_rate = ladder_test_pcs(CANONICAL_LINK_CLASS_M);
        wrong_link_rate.log_inv_rate = 1;
        assert_eq!(
            CanonicalSplitLinkLadder::try_new(
                ladder_test_shape(CANONICAL_LINK_CLASS_M),
                wrong_link_rate,
                canonical_test_slots(),
            )
            .unwrap_err(),
            CanonicalLadderError::LinkPcsParameters
        );

        let mut wrong_link_batch = ladder_test_pcs(CANONICAL_LINK_CLASS_M);
        wrong_link_batch.log_batch_size = CANONICAL_PCS_LOG_BATCH_SIZE - 1;
        assert_eq!(
            CanonicalSplitLinkLadder::try_new(
                ladder_test_shape(CANONICAL_LINK_CLASS_M),
                wrong_link_batch,
                canonical_test_slots(),
            )
            .unwrap_err(),
            CanonicalLadderError::LinkPcsParameters
        );

        let mut wrong_link_profile = ladder_test_pcs(CANONICAL_LINK_CLASS_M);
        wrong_link_profile.profile = noid_ivc_core::pcs::ligerito::LigeritoProfile::Slim;
        assert_eq!(
            CanonicalSplitLinkLadder::try_new(
                ladder_test_shape(CANONICAL_LINK_CLASS_M),
                wrong_link_profile,
                canonical_test_slots(),
            )
            .unwrap_err(),
            CanonicalLadderError::LinkPcsParameters
        );

        let mut wrong_block_batch = canonical_test_slots();
        wrong_block_batch[2].b_pcs_params.log_batch_size = CANONICAL_PCS_LOG_BATCH_SIZE - 1;
        assert_eq!(
            CanonicalSplitLinkLadder::try_new(
                ladder_test_shape(CANONICAL_LINK_CLASS_M),
                ladder_test_pcs(CANONICAL_LINK_CLASS_M),
                wrong_block_batch,
            )
            .unwrap_err(),
            CanonicalLadderError::BlockPcsParameters { slot: 2 }
        );
    }

    #[test]
    fn canonical_ladder_slot_identity_includes_post_commit_and_sidecar_vk() {
        let slots = canonical_test_slots();
        let mut post_commit_drift = slots.clone();
        post_commit_drift[1].b_post_commit_class_digest[0] ^= 1;
        assert!(!same_ladder(&slots, &post_commit_drift));

        let mut sidecar_drift = slots.clone();
        sidecar_drift[3].b_sidecar_vk_digest[0] ^= 1;
        assert!(!same_ladder(&slots, &sidecar_drift));
    }

    #[test]
    fn arbitrary_four_class_transition_routing_is_exhaustive_and_rejects_misbinding() {
        const N: usize = CanonicalSplitLinkLadder::SLOT_COUNT;
        let ladder = canonical_test_slots();
        let layout = split_io_layout(CANONICAL_LINK_CLASS_M, &ladder);
        let link_digests: [[u8; 32]; N] = std::array::from_fn(|slot| [0x10 + slot as u8; 32]);
        let post_commit_digests: [[u8; 32]; N] =
            std::array::from_fn(|slot| [0x20 + slot as u8; 32]);
        let marker = |family: u64, index: usize| {
            F128::new(
                family.wrapping_mul(0x0101_0101_0101_0101) ^ index as u64,
                family,
            )
        };

        let mut pair_count = 0usize;
        let mut equal_count = 0usize;
        let mut upward_count = 0usize;
        let mut downward_count = 0usize;
        let mut skipped_count = 0usize;
        for prev_slot in 0..N {
            for current_slot in 0..N {
                pair_count += 1;
                match current_slot.cmp(&prev_slot) {
                    std::cmp::Ordering::Equal => equal_count += 1,
                    std::cmp::Ordering::Greater => upward_count += 1,
                    std::cmp::Ordering::Less => downward_count += 1,
                }
                if current_slot.abs_diff(prev_slot) > 1 {
                    skipped_count += 1;
                }

                let mut prev_io = vec![F128::ZERO; layout.len];
                for (slot, digest) in link_digests.iter().enumerate() {
                    let lanes = flat_digest_lanes(digest);
                    prev_io[layout.wl + 2 * slot] = lanes[0];
                    prev_io[layout.wl + 2 * slot + 1] = lanes[1];
                }
                for (slot, digest) in post_commit_digests.iter().enumerate() {
                    let lanes = flat_digest_lanes(digest);
                    prev_io[layout.wl_post_commit + 2 * slot] = lanes[0];
                    prev_io[layout.wl_post_commit + 2 * slot + 1] = lanes[1];
                }
                for (slot, lane) in layout.link_lanes.iter().enumerate() {
                    for index in lane.point..=lane.value {
                        prev_io[index] = marker(0x40 + slot as u64, index - lane.point);
                    }
                    prev_io[lane.live] = if slot % 2 == 0 { F128::ONE } else { F128::ZERO };
                }
                for (slot, lane) in layout.b_lanes.iter().enumerate() {
                    for index in lane.point..=lane.value {
                        prev_io[index] = marker(0x60 + slot as u64, index - lane.point);
                    }
                    prev_io[lane.live] = if slot % 2 == 1 { F128::ONE } else { F128::ZERO };
                }
                let previous_accumulator = (0..super::super::link::ACC_LANES)
                    .map(|index| marker(0x80, index))
                    .collect::<Vec<_>>();
                prev_io[layout.block_acc..layout.block_acc + super::super::link::ACC_LANES]
                    .copy_from_slice(&previous_accumulator);
                let block_start_accumulator = previous_accumulator.clone();
                let block_end_accumulator = (0..super::super::link::ACC_LANES)
                    .map(|index| marker(0x90, index))
                    .collect::<Vec<_>>();

                let selection = preflight_split_transition(
                    &layout,
                    prev_slot,
                    current_slot,
                    &link_digests,
                    &post_commit_digests,
                    &prev_io,
                    link_digests[prev_slot],
                    post_commit_digests[prev_slot],
                    ladder[current_slot].b_digest,
                    ladder[current_slot].b_digest,
                    &block_start_accumulator,
                    &previous_accumulator,
                )
                .expect("every ordered class pair is a valid transition");
                assert_eq!(selection.digest, link_digests[prev_slot]);
                assert_eq!(selection.post_commit, post_commit_digests[prev_slot]);

                let selected_link_lane = &layout.link_lanes[prev_slot];
                let acc_link = MatrixAccClaim {
                    point: (0..selected_link_lane.value - selected_link_lane.point)
                        .map(|index| marker(0xA0, index))
                        .collect(),
                    value: marker(0xA1, 0),
                };
                let selected_block_lane = &layout.b_lanes[current_slot];
                let acc_block = MatrixAccClaim {
                    point: (0..selected_block_lane.value - selected_block_lane.point)
                        .map(|index| marker(0xB0, index))
                        .collect(),
                    value: marker(0xB1, 0),
                };
                let io = route_split_transition_io(
                    &layout,
                    false,
                    prev_slot,
                    current_slot,
                    &link_digests,
                    &post_commit_digests,
                    &prev_io,
                    &acc_link,
                    &acc_block,
                    &block_end_accumulator,
                )
                .expect("production transition routing");
                assert_eq!(io[layout.g], F128::ZERO);
                for (slot, lane) in layout.link_lanes.iter().enumerate() {
                    if slot == prev_slot {
                        assert_eq!(&io[lane.point..lane.value], &acc_link.point);
                        assert_eq!(io[lane.value], acc_link.value);
                        assert_eq!(io[lane.live], F128::ONE);
                    } else {
                        assert_eq!(
                            &io[lane.point..=lane.live],
                            &prev_io[lane.point..=lane.live],
                            "({prev_slot},{current_slot}) altered Link lane {slot}",
                        );
                    }
                }
                for (slot, lane) in layout.b_lanes.iter().enumerate() {
                    if slot == current_slot {
                        assert_eq!(&io[lane.point..lane.value], &acc_block.point);
                        assert_eq!(io[lane.value], acc_block.value);
                        assert_eq!(io[lane.live], F128::ONE);
                    } else {
                        assert_eq!(
                            &io[lane.point..=lane.live],
                            &prev_io[lane.point..=lane.live],
                            "({prev_slot},{current_slot}) altered Block lane {slot}",
                        );
                    }
                }
                assert_eq!(
                    &io[layout.block_acc..layout.block_acc + super::super::link::ACC_LANES],
                    &block_end_accumulator,
                    "({prev_slot},{current_slot}) direct accumulator output",
                );

                let wrong_prev_slot = (prev_slot + 1) % N;
                assert_eq!(
                    preflight_split_transition(
                        &layout,
                        wrong_prev_slot,
                        current_slot,
                        &link_digests,
                        &post_commit_digests,
                        &prev_io,
                        link_digests[prev_slot],
                        post_commit_digests[wrong_prev_slot],
                        ladder[current_slot].b_digest,
                        ladder[current_slot].b_digest,
                        &block_start_accumulator,
                        &previous_accumulator,
                    ),
                    Err(SplitTransitionError::SelectedLinkMatrix),
                );

                let mut wrong_whitelist = link_digests;
                wrong_whitelist[prev_slot][0] ^= 1;
                assert_eq!(
                    preflight_split_transition(
                        &layout,
                        prev_slot,
                        current_slot,
                        &wrong_whitelist,
                        &post_commit_digests,
                        &prev_io,
                        link_digests[prev_slot],
                        post_commit_digests[prev_slot],
                        ladder[current_slot].b_digest,
                        ladder[current_slot].b_digest,
                        &block_start_accumulator,
                        &previous_accumulator,
                    ),
                    Err(SplitTransitionError::WhitelistInheritance),
                );

                let mut wrong_post_commit = post_commit_digests;
                wrong_post_commit[prev_slot][0] ^= 1;
                assert_eq!(
                    preflight_split_transition(
                        &layout,
                        prev_slot,
                        current_slot,
                        &link_digests,
                        &wrong_post_commit,
                        &prev_io,
                        link_digests[prev_slot],
                        post_commit_digests[prev_slot],
                        ladder[current_slot].b_digest,
                        ladder[current_slot].b_digest,
                        &block_start_accumulator,
                        &previous_accumulator,
                    ),
                    Err(SplitTransitionError::PostCommitWhitelistInheritance),
                );

                let mut wrong_selected_post_commit = post_commit_digests[prev_slot];
                wrong_selected_post_commit[0] ^= 1;
                assert_eq!(
                    preflight_split_transition(
                        &layout,
                        prev_slot,
                        current_slot,
                        &link_digests,
                        &post_commit_digests,
                        &prev_io,
                        link_digests[prev_slot],
                        wrong_selected_post_commit,
                        ladder[current_slot].b_digest,
                        ladder[current_slot].b_digest,
                        &block_start_accumulator,
                        &previous_accumulator,
                    ),
                    Err(SplitTransitionError::SelectedLinkPostCommit),
                );

                let mut wrong_link_matrix = link_digests[prev_slot];
                wrong_link_matrix[0] ^= 1;
                assert_eq!(
                    preflight_split_transition(
                        &layout,
                        prev_slot,
                        current_slot,
                        &link_digests,
                        &post_commit_digests,
                        &prev_io,
                        wrong_link_matrix,
                        post_commit_digests[prev_slot],
                        ladder[current_slot].b_digest,
                        ladder[current_slot].b_digest,
                        &block_start_accumulator,
                        &previous_accumulator,
                    ),
                    Err(SplitTransitionError::SelectedLinkMatrix),
                );

                let mut wrong_block_matrix = ladder[current_slot].b_digest;
                wrong_block_matrix[0] ^= 1;
                assert_eq!(
                    preflight_split_transition(
                        &layout,
                        prev_slot,
                        current_slot,
                        &link_digests,
                        &post_commit_digests,
                        &prev_io,
                        link_digests[prev_slot],
                        post_commit_digests[prev_slot],
                        wrong_block_matrix,
                        ladder[current_slot].b_digest,
                        &block_start_accumulator,
                        &previous_accumulator,
                    ),
                    Err(SplitTransitionError::CurrentBlockMatrix),
                );

                let mut wrong_start = block_start_accumulator.clone();
                wrong_start[0] += F128::ONE;
                assert_eq!(
                    preflight_split_transition(
                        &layout,
                        prev_slot,
                        current_slot,
                        &link_digests,
                        &post_commit_digests,
                        &prev_io,
                        link_digests[prev_slot],
                        post_commit_digests[prev_slot],
                        ladder[current_slot].b_digest,
                        ladder[current_slot].b_digest,
                        &wrong_start,
                        &previous_accumulator,
                    ),
                    Err(SplitTransitionError::AccumulatorContinuity),
                );
            }
        }
        assert_eq!(pair_count, 16);
        assert_eq!(equal_count, 4);
        assert_eq!(upward_count, 6);
        assert_eq!(downward_count, 6);
        assert_eq!(skipped_count, 6);
    }

    #[test]
    fn freeze_all_orchestration_shares_only_compact_bootstrap_without_identity_drift() {
        #[derive(Clone)]
        struct DummyBootstrap {
            sidecar_vk: Arc<&'static str>,
            envelope: Arc<&'static str>,
            post_commit: [u8; 32],
        }

        struct DummyClass {
            slot: usize,
            class_identity: u8,
            bootstrap: DummyBootstrap,
        }

        let first_calls = std::cell::Cell::new(0usize);
        let shared_calls = std::cell::Cell::new(0usize);
        let classes = materialize_with_shared_bootstrap(
            [8u8, 32, 64, 255],
            |slot, class_identity| {
                first_calls.set(first_calls.get() + 1);
                let bootstrap = DummyBootstrap {
                    sidecar_vk: Arc::new("canonical VK"),
                    envelope: Arc::new("canonical envelope"),
                    post_commit: [0xA5; 32],
                };
                (
                    DummyClass {
                        slot,
                        class_identity,
                        bootstrap: bootstrap.clone(),
                    },
                    bootstrap,
                )
            },
            |slot, class_identity, bootstrap| {
                shared_calls.set(shared_calls.get() + 1);
                DummyClass {
                    slot,
                    class_identity,
                    bootstrap: bootstrap.clone(),
                }
            },
        );

        assert_eq!(
            first_calls.get(),
            1,
            "compact T proof metadata is built once"
        );
        assert_eq!(shared_calls.get(), 3);
        assert_eq!(
            std::array::from_fn(|slot| (classes[slot].slot, classes[slot].class_identity)),
            [(0, 8), (1, 32), (2, 64), (3, 255)],
            "sharing bootstrap state must not alias per-slot class identity"
        );
        let reference = &classes[0].bootstrap;
        for class in &classes[1..] {
            assert!(Arc::ptr_eq(
                &reference.sidecar_vk,
                &class.bootstrap.sidecar_vk
            ));
            assert!(Arc::ptr_eq(&reference.envelope, &class.bootstrap.envelope));
            assert_eq!(reference.post_commit, class.bootstrap.post_commit);
        }
    }

    #[test]
    fn split_link_registry_schema_shares_heavy_keys_and_cannot_retain_a_genesis_matrix() {
        let source = include_str!("split_link.rs");
        let block_source = include_str!("block_class.rs");
        let shared_fields = source
            .split("struct SharedSplitLinkGenesis {")
            .nth(1)
            .expect("SharedSplitLinkGenesis declaration")
            .split("pub struct SplitLinkClass {")
            .next()
            .expect("SharedSplitLinkGenesis fields");
        let fields = source
            .split("pub struct SplitLinkClass {")
            .nth(1)
            .expect("SplitLinkClass declaration")
            .split("impl SplitLinkClass {")
            .next()
            .expect("SplitLinkClass fields");
        assert!(!shared_fields.contains("FieldR1cs"));
        assert!(!shared_fields.contains("genesis: Arc"));
        assert!(!fields.contains("FieldR1cs"));
        assert!(!fields.contains("genesis: Arc"));
        assert!(fields.contains("b_sidecar_vk: Arc<crate::region_sidecar::BlockRegionSidecarVk>"));
        assert!(
            source
                .matches("b_sidecar_vk: block_class.sidecar_vk_arc()")
                .count()
                >= 2
        );
        assert!(block_source.contains("Arc::clone(&self.sidecar_vk)"));
        assert!(source.contains("pub fn rebuild_genesis_matrix"));
    }

    fn decider_test_matrix(tag: u64) -> FieldR1cs {
        let shape = FieldShape {
            m: noid_ivc_core::zerocheck::K_SKIP,
            k_log: noid_ivc_core::zerocheck::K_SKIP,
            k_skip: noid_ivc_core::zerocheck::K_SKIP,
            const_pin: Some(0),
        };
        let mut matrix = split_genesis_instance(&shape);
        if tag != 0 {
            matrix.a_0.value_table[0] = F128::new(tag + 1, 0);
        }
        matrix
    }

    fn pending_test_lane(matrix: &FieldR1cs) -> PendingMatrixLane {
        let mut claim = MatrixAccClaim {
            point: vec![F128::ZERO; 2 * matrix.k_log + 1],
            value: F128::ZERO,
        };
        claim.value = stacked_matrix_mle_eval(matrix, &claim);
        PendingMatrixLane::Pending {
            claim,
            expected_digest: matrix.structural_statement_digest(),
        }
    }

    fn pending_test_decision(
        link_matrices: &[Option<&FieldR1cs>],
        block_matrices: &[Option<&FieldR1cs>],
    ) -> PendingSplitTipDecision {
        PendingSplitTipDecision {
            link_lanes: link_matrices
                .iter()
                .map(|matrix| {
                    matrix.map_or(PendingMatrixLane::Dead, |matrix| pending_test_lane(matrix))
                })
                .collect(),
            block_lanes: block_matrices
                .iter()
                .map(|matrix| {
                    matrix.map_or(PendingMatrixLane::Dead, |matrix| pending_test_lane(matrix))
                })
                .collect(),
        }
    }

    fn deferred_test_decision(
        matrix: &FieldR1cs,
        fresh: FreshLincheckClaim,
    ) -> DeferredSplitTipDecision {
        DeferredSplitTipDecision {
            pending: pending_test_decision(&[Some(matrix)], &[]),
            fresh,
            tip_slot: 0,
            expected_shape: FieldShape::of(matrix),
            expected_digest: matrix.structural_statement_digest(),
        }
    }

    #[test]
    fn deferred_tip_csr_discharge_accepts_exact_fresh_claim() {
        let mut matrix = decider_test_matrix(0);
        let fresh = fold_test_fresh(&matrix, 0xD15C_AA6E);
        deferred_test_decision(&matrix, fresh)
            .discharge_tip_matrix(&mut matrix)
            .expect("honest fresh claim must discharge")
            .finish()
            .expect("empty test lane set is complete");
    }

    #[test]
    fn deferred_tip_csr_discharge_rejects_omitted_wrong_and_mutated_claim_authority() {
        let mut matrix = decider_test_matrix(0);

        // An omitted/defaulted final value cannot turn deferred verification
        // into acceptance.  Make the sentinel differ deterministically even
        // in the negligible case where the true value itself is zero.
        let mut omitted = fold_test_fresh(&matrix, 0x0A11_77ED);
        let true_value = omitted.value;
        omitted.value = F128::ZERO;
        if omitted.value == true_value {
            omitted.value = F128::ONE;
        }
        assert_eq!(
            deferred_test_decision(&matrix, omitted)
                .discharge_tip_matrix(&mut matrix)
                .err()
                .expect("omitted claim value must reject"),
            LinkProofError::MatrixClaimMismatch
        );

        let mut wrong = fold_test_fresh(&matrix, 0xBAD0_C1A1);
        wrong.value += F128::ONE;
        assert_eq!(
            deferred_test_decision(&matrix, wrong)
                .discharge_tip_matrix(&mut matrix)
                .err()
                .expect("wrong claim value must reject"),
            LinkProofError::MatrixClaimMismatch
        );

        let fresh = fold_test_fresh(&matrix, 0x51A7_EE55);
        let mut substituted = decider_test_matrix(91);
        substituted.seed_statement_digest(matrix.structural_statement_digest());
        assert_eq!(
            deferred_test_decision(&matrix, fresh.clone())
                .discharge_tip_matrix(&mut substituted)
                .err()
                .expect("mutated CSR must reject"),
            LinkProofError::MatrixMismatch,
            "a seeded digest cache cannot hide mutated CSR entries"
        );

        let mut wrong_shape = decider_test_matrix(0);
        wrong_shape.m += 1;
        assert_eq!(
            deferred_test_decision(&matrix, fresh)
                .discharge_tip_matrix(&mut wrong_shape)
                .err()
                .expect("wrong matrix shape must reject"),
            LinkProofError::MatrixMismatch
        );

        let fresh = fold_test_fresh(&matrix, 0xACC0_0BAD);
        let mut false_accumulator = deferred_test_decision(&matrix, fresh);
        match &mut false_accumulator.pending.link_lanes[0] {
            PendingMatrixLane::Pending { claim, .. } => claim.value += F128::ONE,
            _ => panic!("test tip lane must be live and pending"),
        }
        assert_eq!(
            false_accumulator
                .discharge_tip_matrix(&mut matrix)
                .err()
                .expect("false tip accumulator must reject"),
            LinkProofError::AccumulatorClaimMismatch
        );
    }

    #[test]
    fn deferred_tip_typestate_exposes_no_omission_acceptance_path() {
        let source = include_str!("split_link.rs");
        let declaration = source
            .split("pub struct DeferredSplitTipDecision {")
            .nth(1)
            .expect("deferred tip typestate")
            .split("pub fn begin_tip_split_decision_deferred_matrix(")
            .next()
            .expect("deferred tip implementation boundary");
        assert!(declaration.contains("pub fn discharge_tip_matrix("));
        assert!(!declaration.contains("pub fn finish("));
        assert!(!declaration.contains("pub fresh:"));
        assert!(source.contains("evaluate_matrix_claims(Some(&self.fresh), tip_claim)"));
        assert!(source.contains("evaluated.fresh_value() != Some(self.fresh.value)"));
    }

    #[test]
    fn streamed_tip_decision_rejects_skipped_live_lane() {
        let matrix = decider_test_matrix(0);
        let pending = pending_test_decision(&[Some(&matrix)], &[None]);
        assert_eq!(
            pending.finish().unwrap_err(),
            "link lane 0: live lane was not checked against its matrix"
        );
    }

    #[test]
    fn streamed_tip_decision_rejects_duplicate_and_dead_lane_checks() {
        let mut matrix = decider_test_matrix(0);
        let mut pending = pending_test_decision(&[Some(&matrix), None], &[None, None]);
        pending
            .check_link_matrix(0, &mut matrix)
            .expect("first live-lane check");
        assert_eq!(
            pending.check_link_matrix(0, &mut matrix).unwrap_err(),
            "link lane 0: matrix lane was already checked"
        );
        assert_eq!(
            pending.check_link_matrix(1, &mut matrix).unwrap_err(),
            "link lane 1: matrix supplied for a dead lane"
        );
        assert_eq!(
            pending.check_link_matrix(2, &mut matrix).unwrap_err(),
            "link lane 2: slot out of range"
        );
        pending.finish().expect("only live lane was checked");
    }

    #[test]
    fn streamed_tip_decision_rejects_wrong_slot_and_matrix() {
        let mut matrix_a = decider_test_matrix(0);
        let mut matrix_b = decider_test_matrix(7);
        let mut pending =
            pending_test_decision(&[Some(&matrix_a), Some(&matrix_b)], &[Some(&matrix_b)]);

        assert_eq!(
            pending.check_link_matrix(0, &mut matrix_b).unwrap_err(),
            "link lane 0: matrix does not match the published digest"
        );
        pending
            .check_link_matrix(0, &mut matrix_a)
            .expect("slot 0 receives its matrix");
        assert_eq!(
            pending.check_link_matrix(1, &mut matrix_a).unwrap_err(),
            "link lane 1: matrix does not match the published digest"
        );
        pending
            .check_link_matrix(1, &mut matrix_b)
            .expect("slot 1 receives its matrix");
        assert_eq!(
            pending.check_block_matrix(0, &mut matrix_a).unwrap_err(),
            "block lane 0: matrix does not match the published digest"
        );
        pending
            .check_block_matrix(0, &mut matrix_b)
            .expect("block slot receives its matrix");
        pending.finish().expect("all live lanes were checked");
    }

    #[test]
    fn streamed_tip_decision_ignores_seeded_digest_substitution() {
        let mut honest = decider_test_matrix(0);
        let expected = honest.structural_statement_digest();
        let mut substituted = decider_test_matrix(9);
        substituted.seed_statement_digest(expected);
        assert_eq!(substituted.statement_digest(), expected);

        let mut pending = pending_test_decision(&[Some(&honest)], &[]);
        assert_eq!(
            pending.check_link_matrix(0, &mut substituted).unwrap_err(),
            "link lane 0: matrix does not match the published digest"
        );
        pending
            .check_link_matrix(0, &mut honest)
            .expect("honest structural matrix remains accepted");
        pending.finish().expect("honest replacement completed lane");
    }

    #[test]
    fn streamed_and_matrix_bank_tip_decisions_have_parity() {
        let mut link = decider_test_matrix(0);
        let mut block = decider_test_matrix(11);

        let mut streamed = pending_test_decision(&[Some(&link), None], &[Some(&block), None]);
        streamed
            .check_link_matrix(0, &mut link)
            .expect("streamed Link check");
        streamed
            .check_block_matrix(0, &mut block)
            .expect("streamed Block check");
        streamed.finish().expect("streamed finish");

        let banked = pending_test_decision(&[Some(&link), None], &[Some(&block), None]);
        finish_tip_split_decision_with_matrix_banks(
            banked,
            &[Some(&link), Some(&block)],
            &[Some(&block), Some(&link)],
        )
        .expect("dead-lane matrices stay ignored for compatibility");

        let missing = pending_test_decision(&[Some(&link)], &[Some(&block)]);
        assert_eq!(
            finish_tip_split_decision_with_matrix_banks(missing, &[None], &[Some(&block)])
                .unwrap_err(),
            "link lane 0: live lane without its matrix"
        );
    }

    fn phased_matrix_release_compile_contract<'a>(
        class: &'a SplitLinkClass,
        input: SplitLinkTraceInput<'a>,
        link_matrix: FieldR1cs,
        block_matrix: FieldR1cs,
    ) -> BuiltSplitLink {
        let previous_phase =
            begin_split_link_native_preparation(class, input).expect("split-link preflight");
        let block_phase = previous_phase
            .prepare_previous_link(&link_matrix)
            .expect("previous Link phase");
        drop(link_matrix);
        let prepared = block_phase
            .prepare_current_block(&block_matrix)
            .expect("current Block phase");
        drop(block_matrix);
        prepared.assemble()
    }

    fn combined_and_phased_build_parity_contract<'a>(
        class: &'a SplitLinkClass,
        input: &SplitLinkInput<'a>,
    ) {
        let combined = build_split_link(class, input);
        let previous_phase =
            begin_split_link_native_preparation(class, SplitLinkTraceInput::from_combined(input))
                .expect("split-link preflight");
        let block_phase = previous_phase
            .prepare_previous_link(input.fold_matrix_link)
            .expect("previous Link phase");
        let phased = block_phase
            .prepare_current_block(input.fold_matrix_block)
            .expect("current Block phase")
            .assemble();
        assert_eq!(
            combined.r1cs.structural_statement_digest(),
            phased.r1cs.structural_statement_digest(),
            "combined and phased matrix identities"
        );
        assert_eq!(combined.witness, phased.witness, "phased witness parity");
        assert_eq!(combined.io, phased.io, "phased public-IO parity");
        assert_eq!(
            combined.region_preparation.vk(),
            phased.region_preparation.vk(),
            "phased sidecar preparation parity"
        );
    }

    #[test]
    fn phased_build_api_has_matrix_free_assembly_and_parity_contracts() {
        let _release: for<'a> fn(
            &'a SplitLinkClass,
            SplitLinkTraceInput<'a>,
            FieldR1cs,
            FieldR1cs,
        ) -> BuiltSplitLink = phased_matrix_release_compile_contract;
        let _parity: for<'a> fn(&'a SplitLinkClass, &SplitLinkInput<'a>) =
            combined_and_phased_build_parity_contract;
    }

    fn fold_test_fresh(matrix: &FieldR1cs, mut seed: u128) -> FreshLincheckClaim {
        let mut fresh = FreshLincheckClaim {
            alpha: next(&mut seed),
            z_skip: next(&mut seed),
            x_inner_rest: (matrix.k_skip..matrix.k_log)
                .map(|_| next(&mut seed))
                .collect(),
            r_inner_rest: (matrix.k_skip..matrix.k_log)
                .map(|_| next(&mut seed))
                .collect(),
            z_partial: (0..1usize << matrix.k_skip)
                .map(|_| next(&mut seed))
                .collect(),
            value: F128::ZERO,
        };
        fresh.value = fresh_claim_value(matrix, &fresh);
        fresh
    }

    #[test]
    fn phased_fold_transcripts_match_legacy_small_matrix_path() {
        let link_matrix = decider_test_matrix(0);
        let block_matrix = decider_test_matrix(17);
        let fresh_link = fold_test_fresh(&link_matrix, 0x11);
        let fresh_block = fold_test_fresh(&block_matrix, 0x22);

        let incoming_link = MatrixAccClaim::zero(link_matrix.k_log);
        let mut incoming_block = MatrixAccClaim::zero(block_matrix.k_log);
        incoming_block.value = stacked_matrix_mle_eval(&block_matrix, &incoming_block);

        let mut legacy_link_challenger = FsLaneChallenger::new(b"history-link-fold-v0");
        let legacy_link = prove_matrix_claim_fold(
            &link_matrix,
            &fresh_link,
            &incoming_link,
            false,
            &mut legacy_link_challenger,
        );
        let mut legacy_block_challenger = FsLaneChallenger::new(b"history-block-fold-v0");
        let legacy_block = prove_matrix_claim_fold(
            &block_matrix,
            &fresh_block,
            &incoming_block,
            true,
            &mut legacy_block_challenger,
        );

        let phased_link = prove_split_matrix_fold(
            b"history-link-fold-v0",
            &link_matrix,
            &fresh_link,
            &incoming_link,
            false,
        );
        let phased_block = prove_split_matrix_fold(
            b"history-block-fold-v0",
            &block_matrix,
            &fresh_block,
            &incoming_block,
            true,
        );

        assert_eq!(phased_link, legacy_link, "Link fold bytes/claim parity");
        assert_eq!(phased_block, legacy_block, "Block fold bytes/claim parity");
    }

    #[test]
    fn phased_matrix_identity_rejects_mutation_shape_and_class_mix() {
        let honest = decider_test_matrix(0);
        let expected_shape = FieldShape::of(&honest);
        let expected_digest = honest.structural_statement_digest();
        validate_split_fold_matrix_identity(
            &honest,
            expected_shape,
            expected_digest,
            SplitLinkPreparationError::PreviousMatrixShape,
            SplitLinkPreparationError::PreviousMatrixDigest,
        )
        .expect("honest previous Link matrix");

        let substituted = decider_test_matrix(9);
        substituted.seed_statement_digest(expected_digest);
        assert_eq!(
            substituted.statement_digest(),
            expected_digest,
            "test substitution reaches the seedable digest cache"
        );
        assert_eq!(
            validate_split_fold_matrix_identity(
                &substituted,
                expected_shape,
                expected_digest,
                SplitLinkPreparationError::PreviousMatrixShape,
                SplitLinkPreparationError::PreviousMatrixDigest,
            ),
            Err(SplitLinkPreparationError::PreviousMatrixDigest),
            "phased input authenticates CSR contents, not a seeded cache"
        );

        let foreign_slot_matrix = decider_test_matrix(23);
        assert_eq!(
            validate_split_fold_matrix_identity(
                &foreign_slot_matrix,
                expected_shape,
                expected_digest,
                SplitLinkPreparationError::BlockMatrixShape,
                SplitLinkPreparationError::BlockMatrixDigest,
            ),
            Err(SplitLinkPreparationError::BlockMatrixDigest),
            "a same-shape matrix from another class/slot cannot be mixed in"
        );

        let mut wrong_shape = decider_test_matrix(0);
        wrong_shape.m += 1;
        assert_eq!(
            validate_split_fold_matrix_identity(
                &wrong_shape,
                expected_shape,
                expected_digest,
                SplitLinkPreparationError::PreviousMatrixShape,
                SplitLinkPreparationError::PreviousMatrixDigest,
            ),
            Err(SplitLinkPreparationError::PreviousMatrixShape),
            "shape is rejected before digest work"
        );
    }

    #[test]
    fn production_phased_api_is_public_consuming_and_compatibility_is_thin() {
        let source = include_str!("split_link.rs");
        assert!(source.contains("pub fn begin_split_link_native_preparation<'a>("));
        assert!(source.contains("pub struct SplitLinkPreviousMatrixPhase<'a>"));
        assert!(source.contains("pub struct SplitLinkBlockMatrixPhase<'a>"));
        assert!(source.contains(
            "pub fn prepare_previous_link(\n        self,\n        fold_matrix_link: &FieldR1cs,"
        ));
        assert!(source.contains(
            "pub fn prepare_current_block(\n        self,\n        fold_matrix_block: &FieldR1cs,"
        ));

        let compatibility = source
            .split("fn prepare_split_link_native_inner<'a>(")
            .nth(1)
            .expect("compatibility wrapper")
            .split("fn assemble_prepared_split_link(")
            .next()
            .expect("compatibility wrapper boundary");
        assert!(compatibility.contains("begin_split_link_native_preparation_inner"));
        assert!(compatibility.contains(".prepare_previous_link(fold_matrix_link)"));
        assert!(compatibility.contains(".prepare_current_block(fold_matrix_block)"));
        assert!(!compatibility.contains("verify_field_deferred_matrix"));
        assert!(!compatibility.contains("prove_matrix_claim_fold"));
    }

    fn next(state: &mut u128) -> F128 {
        *state = state
            .wrapping_mul(0x9E37_79B9_7F4A_7C15_D1B5_4A32_D192_ED03)
            .wrapping_add(0xA5A5_5A5A_DEAD_BEEF_0123_4567_89AB_CDEF);
        F128::new(*state as u64, (*state >> 64) as u64)
    }

    #[test]
    fn split_genesis_full_identity_accepts_ghosts_and_baked_value_is_exact() {
        let shape = FieldShape {
            m: 9,
            k_log: 9,
            k_skip: noid_ivc_core::zerocheck::K_SKIP,
            const_pin: Some(0),
        };
        let genesis = split_genesis_instance(&shape);
        let mut seed = 7u128;
        let mut witness = (0..1usize << shape.m)
            .map(|_| next(&mut seed))
            .collect::<Vec<_>>();
        witness[0] = F128::ONE;
        assert!(
            genesis.satisfies(&witness),
            "full-identity T permits canonical nonzero sidecar columns"
        );

        let mut fresh = FreshLincheckClaim {
            alpha: next(&mut seed),
            z_skip: next(&mut seed),
            x_inner_rest: (shape.k_skip..shape.k_log)
                .map(|_| next(&mut seed))
                .collect(),
            r_inner_rest: (shape.k_skip..shape.k_log)
                .map(|_| next(&mut seed))
                .collect(),
            z_partial: (0..1usize << shape.k_skip)
                .map(|_| next(&mut seed))
                .collect(),
            value: F128::ZERO,
        };
        fresh.value = fresh_claim_value(&genesis, &fresh);

        let mut builder = FieldR1csBuilder::new();
        let alloc =
            |builder: &mut FieldR1csBuilder, value| LinExpr::from_wire(builder.alloc_f128(value));
        let trace = super::super::trace::matrix_fold::FreshLincheckClaimTrace {
            alpha: alloc(&mut builder, fresh.alpha),
            z_skip: alloc(&mut builder, fresh.z_skip),
            x_inner_rest: fresh
                .x_inner_rest
                .iter()
                .map(|&value| alloc(&mut builder, value))
                .collect(),
            r_inner_rest: fresh
                .r_inner_rest
                .iter()
                .map(|&value| alloc(&mut builder, value))
                .collect(),
            z_partial: fresh
                .z_partial
                .iter()
                .map(|&value| alloc(&mut builder, value))
                .collect(),
            value: alloc(&mut builder, fresh.value),
        };
        let baked = split_genesis_baked_claim_value(&mut builder, &trace);
        assert_eq!(baked.eval(builder.values()), fresh.value);
        pin_eq(&mut builder, &baked, &trace.value);
        let (relation, relation_witness) = builder.build();
        assert!(relation.satisfies(&relation_witness));
    }
}
