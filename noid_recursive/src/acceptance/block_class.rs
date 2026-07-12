// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! The standalone per-tier BLOCK class `B_t`.
//!
//! A production block proof has one fixed public statement and one mandatory
//! post-commit authority:
//!
//! * public IO is exactly `[start_acc (10 lanes) | end_acc (10 lanes)]`;
//! * the six block-region walks are represented by
//!   [`BlockRegionSidecarProof`], never by public-IO claim descriptors;
//! * their challenges are sampled only after the enclosing witness commitment
//!   and their verifier-derived openings join that proof's terminal PCS batch.
//!
//! Consequently a plain `FieldR1csProof` is not a production block proof.  The
//! only production envelope in this module is [`BlockProofEnvelope`], whose
//! sidecar field is private and non-optional.

use std::sync::{Arc, OnceLock};

use noid_ivc_core::challenger::Challenger;
use noid_ivc_core::field::F128;
use noid_ivc_core::field_circuit::{FieldR1csBuilder, LinExpr};
use noid_ivc_core::field_r1cs::FieldR1cs;
use noid_ivc_core::pcs::{Commitment, PcsParams, LOG_PACKING};
use noid_ivc_core::proof::{pcs_params_statement_bytes, FieldR1csProof, FieldShape, R1csClaim};
use noid_ivc_core::public_io::{PublicIoSpec, WitnessSlice};
use noid_ivc_core::verifier::{verify_field_with_public_io_and_post_commit_context, VerifyError};
use noid_ivc_prover::field_prover::prove_field_with_public_io_and_post_commit_context;

use super::block_slots::{build_block_slots_selected_zk, SelectedZkBlockSlotsAssembly};
use super::block_slots::{build_block_slots_with_config, BlockSlots, BlockSlotsConfig};
use super::link::{block_acc_lanes, LinkBlock, ACC_LANES};
use super::link::{
    SelectedZkB255BlockInput, SelectedZkB32BlockInput, SelectedZkB64BlockInput,
    SelectedZkB8BlockInput, SelectedZkBlockInput,
};
use super::trace::pin_eq;
use super::trace::region_source_binding::RegionDischargeParams;
use crate::region_sidecar::{
    block_post_commit_class_digest, verify_block_region_sidecar_post_commit,
    BlockRegionPreparation, BlockRegionSidecarProof, BlockRegionSidecarVk, RegionSidecarError,
    BLOCK_REGION_SELECTED_ZK_SIDECAR_VERSION, BLOCK_REGION_SIDECAR_VERSION,
};

/// Fixed public-IO offsets of every production block class.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockIoLayout {
    pub start_acc: usize,
    pub end_acc: usize,
    pub len: usize,
}

pub const BLOCK_IO_START_ACC: usize = 0;
pub const BLOCK_IO_END_ACC: usize = ACC_LANES;
pub const BLOCK_IO_LEN: usize = 2 * ACC_LANES;
/// Canonical Fiat--Shamir domain for every standalone production Block class.
/// Production coordinators must not accept a caller-selected domain.
pub const BLOCK_PROOF_TRANSCRIPT_DOMAIN: &[u8] = b"history-block-v0";

pub const fn block_io_layout() -> BlockIoLayout {
    BlockIoLayout {
        start_acc: BLOCK_IO_START_ACC,
        end_acc: BLOCK_IO_END_ACC,
        len: BLOCK_IO_LEN,
    }
}

/// The block statement contains no opening-claim tail.  Terminal region
/// openings are verifier output inside the opaque post-commit context.
pub fn block_io_spec() -> PublicIoSpec {
    PublicIoSpec {
        io_slice: WitnessSlice {
            log2_len: BLOCK_IO_LEN.next_power_of_two().trailing_zeros() as usize,
            index: 1,
        },
        io_len: BLOCK_IO_LEN,
        claims: Vec::new(),
    }
}

/// Immutable protocol constants for one transaction-capacity tier.
pub struct BlockClass {
    tier: usize,
    pub shape: FieldShape,
    /// Kept public while the transitional split-link reads the matrix-class
    /// constant.  It is populated during `freeze`, never by a later proof.
    pub class_statement_digest: OnceLock<[u8; 32]>,
    pub pcs_params: PcsParams,
    pub spec: PublicIoSpec,
    config_template: BlockSlotsConfig,
    sidecar_vk: Arc<BlockRegionSidecarVk>,
    post_commit_class_digest: [u8; 32],
    authorization_backend: BlockClassAuthorizationBackend,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BlockClassAuthorizationBackend {
    Legacy,
    SelectedZk,
}

impl BlockClass {
    /// Rehydrate one selected production class from a compact, locally
    /// provisioned registry artifact.  The artifact supplies identities, not
    /// a matrix or witness: every deterministic class component is rebuilt
    /// here and the complete composite identity is checked before the class
    /// can escape.
    pub(crate) fn from_selected_registry_parts(
        tier: usize,
        shape: FieldShape,
        pcs_params: PcsParams,
        spec: PublicIoSpec,
        matrix_digest: [u8; 32],
        sidecar_vk: BlockRegionSidecarVk,
        post_commit_class_digest: [u8; 32],
    ) -> Result<Self, BlockProofError> {
        if !noid_chain::consensus::params::USER_TX_CLASS_TIERS.contains(&tier) {
            return Err(BlockProofError::ClassIdentityMismatch);
        }
        let class_statement_digest = OnceLock::new();
        class_statement_digest
            .set(matrix_digest)
            .map_err(|_| BlockProofError::ClassIdentityMismatch)?;
        let class = Self {
            tier,
            shape,
            class_statement_digest,
            pcs_params,
            spec,
            config_template: production_config(
                RegionDischargeParams {
                    nq: noid_fri_binius::capsule::CAPSULE_NUM_QUERIES,
                },
                tier,
            ),
            sidecar_vk: Arc::new(sidecar_vk),
            post_commit_class_digest,
            authorization_backend: BlockClassAuthorizationBackend::SelectedZk,
        };
        class.validate_selected_zk_identity_for_tier(tier)?;
        Ok(class)
    }

    pub(crate) fn registry_matrix_digest(&self) -> Result<[u8; 32], BlockProofError> {
        self.matrix_digest()
    }

    /// Freeze both halves of the class from one tier-valid sample: the exact
    /// matrix and the exact ordered six-child sidecar VK.  Since the region
    /// discharge no longer contributes proof-shaped rows or public IO, this is
    /// a real production build rather than the former native-claim probe.
    pub fn freeze(
        shape: FieldShape,
        pcs_params: PcsParams,
        region_params: RegionDischargeParams,
        sample: &LinkBlock<'_>,
        tier: usize,
    ) -> Self {
        assert!(
            !noid_chain::consensus::params::USER_TX_CLASS_TIERS.contains(&tier),
            "production tier authoring requires freeze_selected_zk"
        );
        assert_eq!(
            region_params.nq,
            noid_fri_binius::capsule::CAPSULE_NUM_QUERIES,
            "production block class requires the full capsule query count"
        );
        assert_eq!(
            pcs_params.m,
            shape.m + LOG_PACKING,
            "block class PCS m must match its Field witness shape"
        );
        let config_template = production_config(region_params, tier);
        let spec = block_io_spec();
        let io = accumulator_io(sample);
        let (r1cs, _witness, preparation) =
            build_block_trace_parts(shape, sample, config_template, &spec, &io, tier, None);
        let matrix_digest = r1cs.statement_digest();
        let sidecar_vk = Arc::new(preparation.vk().clone());
        let post_commit_class_digest =
            block_post_commit_class_digest(&matrix_digest, &spec, &pcs_params, &sidecar_vk);
        let class_statement_digest = OnceLock::new();
        class_statement_digest
            .set(matrix_digest)
            .expect("fresh block class matrix digest lock");

        Self {
            tier,
            shape,
            class_statement_digest,
            pcs_params,
            spec,
            config_template,
            sidecar_vk,
            post_commit_class_digest,
            authorization_backend: BlockClassAuthorizationBackend::Legacy,
        }
    }

    /// Freeze one canonical production selected-ZK relation from a consuming
    /// class-typed sample. The resulting identity commits both its exact
    /// matrix and V4 six-child sidecar key; no legacy owner-auth relation can
    /// reproduce either identity.
    pub fn freeze_selected_zk<const TIER: usize>(
        pcs_params: PcsParams,
        sample: SelectedZkBlockInput<'_, TIER>,
    ) -> Self {
        let shape = selected_zk_shape(TIER);
        assert_eq!(
            pcs_params.m,
            shape.m + LOG_PACKING,
            "selected PCS m must match its Field witness shape"
        );
        let built = build_selected_zk_trace_parts(sample, None);
        let matrix_digest = built.r1cs.statement_digest();
        let sidecar_vk = Arc::new(built.region_preparation.vk().clone());
        assert_eq!(
            sidecar_vk.version(),
            BLOCK_REGION_SELECTED_ZK_SIDECAR_VERSION,
            "selected class requires V4 sidecar"
        );
        let spec = block_io_spec();
        let post_commit_class_digest =
            block_post_commit_class_digest(&matrix_digest, &spec, &pcs_params, &sidecar_vk);
        let class_statement_digest = OnceLock::new();
        class_statement_digest
            .set(matrix_digest)
            .expect("fresh selected matrix digest lock");
        let region_params = RegionDischargeParams {
            nq: noid_fri_binius::capsule::CAPSULE_NUM_QUERIES,
        };

        Self {
            tier: TIER,
            shape,
            class_statement_digest,
            pcs_params,
            spec,
            config_template: production_config(region_params, TIER),
            sidecar_vk,
            post_commit_class_digest,
            authorization_backend: BlockClassAuthorizationBackend::SelectedZk,
        }
    }

    pub fn freeze_selected_zk_b8(
        pcs_params: PcsParams,
        sample: SelectedZkB8BlockInput<'_>,
    ) -> Self {
        Self::freeze_selected_zk(pcs_params, sample)
    }

    pub fn freeze_selected_zk_b32(
        pcs_params: PcsParams,
        sample: SelectedZkB32BlockInput<'_>,
    ) -> Self {
        Self::freeze_selected_zk(pcs_params, sample)
    }

    pub fn freeze_selected_zk_b64(
        pcs_params: PcsParams,
        sample: SelectedZkB64BlockInput<'_>,
    ) -> Self {
        Self::freeze_selected_zk(pcs_params, sample)
    }

    pub fn freeze_selected_zk_b255(
        pcs_params: PcsParams,
        sample: SelectedZkB255BlockInput<'_>,
    ) -> Self {
        Self::freeze_selected_zk(pcs_params, sample)
    }

    pub fn sidecar_vk(&self) -> &BlockRegionSidecarVk {
        self.sidecar_vk.as_ref()
    }

    /// Share the immutable hosted VK with its Link class without copying the
    /// descriptor-derived fixed tables.
    pub(crate) fn sidecar_vk_arc(&self) -> Arc<BlockRegionSidecarVk> {
        Arc::clone(&self.sidecar_vk)
    }

    pub fn tier(&self) -> usize {
        self.tier
    }

    /// Fail-closed preflight for a production selected-ZK registry slot.
    ///
    /// This is the public coordinator boundary: callers can validate a cached
    /// class before allocating an m22/m23/m24 witness, rather than reaching an
    /// assertion inside the consuming trace builder with a legacy class.
    pub fn validate_selected_zk_identity_for_tier(
        &self,
        expected_tier: usize,
    ) -> Result<(), BlockProofError> {
        if self.tier != expected_tier {
            return Err(BlockProofError::TierMismatch {
                expected: expected_tier,
                actual: self.tier,
            });
        }
        if self.authorization_backend != BlockClassAuthorizationBackend::SelectedZk {
            return Err(BlockProofError::LegacyAuthorizationBackend);
        }
        self.validate_frozen_identity().map(|_| ())
    }

    pub fn post_commit_class_digest(&self) -> &[u8; 32] {
        &self.post_commit_class_digest
    }

    fn matrix_digest(&self) -> Result<[u8; 32], BlockProofError> {
        self.class_statement_digest
            .get()
            .copied()
            .ok_or(BlockProofError::UnfrozenClass)
    }

    /// Validate every component of the immutable production identity.  Kept
    /// within the acceptance boundary so the universal split-link ladder can
    /// reject a partially or inconsistently frozen block class before copying
    /// any of its descriptors.
    pub(super) fn validate_frozen_identity(&self) -> Result<[u8; 32], BlockProofError> {
        let matrix_digest = self.matrix_digest()?;
        if !is_production_block_io_spec(&self.spec)
            || self.shape.m.checked_add(LOG_PACKING) != Some(self.pcs_params.m)
            || !is_production_config(&self.config_template, self.tier)
            || match self.authorization_backend {
                BlockClassAuthorizationBackend::Legacy => {
                    self.tier == noid_chain::consensus::params::BLOCK_MAX_USER_TXS
                        || self.sidecar_vk.version() != BLOCK_REGION_SIDECAR_VERSION
                }
                BlockClassAuthorizationBackend::SelectedZk => {
                    crate::region_sidecar::selected_zk_block_geometry(self.tier).is_none()
                        || self.shape != selected_zk_shape(self.tier)
                        || self.sidecar_vk.version() != BLOCK_REGION_SELECTED_ZK_SIDECAR_VERSION
                }
            }
        {
            return Err(BlockProofError::ClassIdentityMismatch);
        }
        let expected = block_post_commit_class_digest(
            &matrix_digest,
            &self.spec,
            &self.pcs_params,
            self.sidecar_vk.as_ref(),
        );
        if expected != self.post_commit_class_digest {
            return Err(BlockProofError::ClassIdentityMismatch);
        }
        Ok(matrix_digest)
    }
}

/// One assembled production block trace.  Its sidecar preparation is
/// mandatory and owns all six endpoint families until the post-commit phase.
pub struct BuiltBlock {
    pub r1cs: FieldR1cs,
    pub witness: Vec<F128>,
    pub io: Vec<F128>,
    pub region_preparation: BlockRegionPreparation,
}

/// Unforgeable selected-region finalization authority.  The type is visible
/// to the consuming candidate/sidecar boundary, but its field is private to
/// this owning Block module.  Consequently only code here can create a seal,
/// and the two constructors below do so strictly after builder completion.
pub(crate) struct SelectedBlockAssemblyFinalizationSeal(());

/// Full matrix build produced by the non-default selected-ZK measurement
/// facade.  No production verifier accepts this object: it exists only to
/// measure the mutually exclusive B255 replacement and freeze a matrix for
/// the witness-only fixity pass.
#[cfg(feature = "selected-zk-measurement")]
pub struct SelectedZkB255FullMeasurement {
    r1cs: FieldR1cs,
    witness: Vec<F128>,
    io: Vec<F128>,
    region_vk: BlockRegionSidecarVk,
}

#[cfg(feature = "selected-zk-measurement")]
impl SelectedZkB255FullMeasurement {
    pub fn r1cs(&self) -> &FieldR1cs {
        &self.r1cs
    }

    pub fn witness(&self) -> &[F128] {
        &self.witness
    }

    pub fn io(&self) -> &[F128] {
        &self.io
    }

    pub fn region_vk(&self) -> &BlockRegionSidecarVk {
        &self.region_vk
    }

    /// Exact decoded relation equality, independent of coefficient-table
    /// interning order and any seeded digest cache.
    pub fn has_identical_relation(&self, other: &Self) -> bool {
        self.r1cs.m == other.r1cs.m
            && self.r1cs.k_log == other.r1cs.k_log
            && self.r1cs.k_skip == other.r1cs.k_skip
            && self.r1cs.useful_rows == other.r1cs.useful_rows
            && self.r1cs.const_pin == other.r1cs.const_pin
            && self.r1cs.a_0 == other.r1cs.a_0
            && self.r1cs.b_0 == other.r1cs.b_0
    }
}

/// Witness-only replay against a previously materialized selected B255
/// matrix.  The V4 key is rebuilt independently from the new witness and must
/// match the frozen key before this value is returned.
#[cfg(feature = "selected-zk-measurement")]
pub struct SelectedZkB255WitnessMeasurement {
    useful_rows: usize,
    witness: Vec<F128>,
    io: Vec<F128>,
    region_vk: BlockRegionSidecarVk,
}

#[cfg(feature = "selected-zk-measurement")]
impl SelectedZkB255WitnessMeasurement {
    pub fn useful_rows(&self) -> usize {
        self.useful_rows
    }

    pub fn witness(&self) -> &[F128] {
        &self.witness
    }

    pub fn io(&self) -> &[F128] {
        &self.io
    }

    pub fn region_vk(&self) -> &BlockRegionSidecarVk {
        &self.region_vk
    }
}

fn selected_zk_shape(tier: usize) -> FieldShape {
    let m = match tier {
        8 => 22,
        32 | 64 => 23,
        255 => 24,
        _ => panic!("selected tier is not canonical"),
    };
    FieldShape {
        m,
        k_log: m,
        k_skip: 6,
        const_pin: Some(0),
    }
}

fn assert_selected_zk_inputs(block: &LinkBlock<'_>, tier: usize) {
    let shape = selected_zk_shape(tier);
    assert_eq!(shape.m, shape.k_log, "selected Block square shape");
    assert_eq!(shape.k_skip, 6, "selected Block k-skip drift");
    assert_eq!(shape.const_pin, Some(0), "selected Block const pin drift");
    let config = block.config;
    assert!(
        config.discharge_wallet_pcs
            && config.owner_auth_region
            && config.exact_state_region
            && config.tx_root_region
            && config.spine_region,
        "selected Block requires the complete canonical region stack"
    );
    assert_eq!(
        config.tier_user_tx_capacity,
        Some(tier),
        "selected production backend tier mismatch"
    );
    assert_eq!(
        config.wallet_pcs_params.nq,
        noid_fri_binius::capsule::CAPSULE_NUM_QUERIES,
        "selected production backend requires every capsule query"
    );
}

fn assemble_selected_zk<const TIER: usize>(
    mut builder: FieldR1csBuilder,
    input: SelectedZkBlockInput<'_, TIER>,
) -> (FieldR1csBuilder, Vec<F128>, SelectedZkBlockSlotsAssembly) {
    let (block, authorization) = input.into_parts();
    assert_selected_zk_inputs(&block, TIER);
    let spec = block_io_spec();
    let io = accumulator_io(&block);
    let io_cells = allocate_block_io_cells(&mut builder, &spec, &io);
    let assembly = build_block_slots_selected_zk(
        &mut builder,
        block.start_accumulator,
        block.end_accumulator,
        block.inputs,
        block.proof,
        block.config,
        authorization,
    );
    pin_block_io_cells(&mut builder, assembly.slots(), &io_cells);
    (builder, io, assembly)
}

fn build_selected_zk_trace_parts<const TIER: usize>(
    input: SelectedZkBlockInput<'_, TIER>,
    expected_vk: Option<&BlockRegionSidecarVk>,
) -> BuiltBlock {
    let shape = selected_zk_shape(TIER);
    let (builder, io, assembly) = assemble_selected_zk(FieldR1csBuilder::new(), input);
    let useful_rows = builder.num_wires();
    let binding = assembly.into_region_binding();
    let (r1cs, witness) = builder.build();
    let (r1cs, witness) = expand_empty_field_tail(r1cs, witness, shape);
    assert_eq!(r1cs.useful_rows, useful_rows, "selected useful-row drift");
    let seal = SelectedBlockAssemblyFinalizationSeal(());
    let region_preparation = binding
        .finalize_after_block_build(seal, r1cs.m)
        .expect("selected V4 preparation after matrix build");
    if let Some(expected) = expected_vk {
        assert_eq!(
            region_preparation.vk(),
            expected,
            "selected sidecar VK drifted from the frozen class"
        );
    }
    BuiltBlock {
        r1cs,
        witness,
        io,
        region_preparation,
    }
}

/// Materialize the exact selected-ZK B255 production matrix through the
/// opt-in geometry benchmark facade.  It calls the same consuming trace
/// builder as [`BlockClass::freeze_selected_zk_b255`] but does not author a
/// proof envelope.
#[cfg(feature = "selected-zk-measurement")]
pub fn build_selected_zk_b255_measurement_full(
    input: SelectedZkB255BlockInput<'_>,
) -> SelectedZkB255FullMeasurement {
    let built = build_selected_zk_trace_parts(input, None);
    let frozen_vk = built.region_preparation.vk().clone();
    SelectedZkB255FullMeasurement {
        r1cs: built.r1cs,
        witness: built.witness,
        io: built.io,
        region_vk: frozen_vk,
    }
}

/// Rebuild only the selected B255 witness against the frozen matrix.  The
/// same assembly code runs with row recording disabled; exact wire count and
/// V4 key equality are checked before returning the witness.
#[cfg(feature = "selected-zk-measurement")]
pub fn build_selected_zk_b255_measurement_witness_only(
    input: SelectedZkB255BlockInput<'_>,
    frozen: &SelectedZkB255FullMeasurement,
) -> SelectedZkB255WitnessMeasurement {
    let shape = selected_zk_shape(255);
    assert_eq!(FieldShape::of(&frozen.r1cs), shape, "frozen shape drift");
    let (builder, io, assembly) = assemble_selected_zk(FieldR1csBuilder::new_witness_only(), input);
    let rebuilt_vk = assembly.region_vk().clone();
    let binding = assembly.into_region_binding();
    let (useful_rows, mut witness) = builder.build_witness_only();
    assert_eq!(
        useful_rows, frozen.r1cs.useful_rows,
        "selected witness-only wire-count drift"
    );
    witness.resize(1usize << shape.m, F128::ZERO);
    let seal = SelectedBlockAssemblyFinalizationSeal(());
    let preparation = binding
        .finalize_after_block_build(seal, shape.m)
        .expect("selected V4 preparation after witness-only build");
    assert_eq!(preparation.vk(), &rebuilt_vk, "rebuilt V4 key drift");
    assert_eq!(
        rebuilt_vk, frozen.region_vk,
        "selected witness-only V4 key differs from frozen key"
    );
    SelectedZkB255WitnessMeasurement {
        useful_rows,
        witness,
        io,
        region_vk: rebuilt_vk,
    }
}

/// Assemble a block instance and require bit-exact reproduction of both the
/// frozen matrix and the frozen sidecar VK.
pub fn build_block_proof_trace(class: &BlockClass, block: &LinkBlock<'_>) -> BuiltBlock {
    assert_eq!(
        class.authorization_backend,
        BlockClassAuthorizationBackend::Legacy,
        "selected class requires build_selected_zk_block_proof_trace"
    );
    let matrix_digest = class
        .validate_frozen_identity()
        .expect("production BlockClass must remain freeze-locked");
    let io = accumulator_io(block);
    let (r1cs, witness, region_preparation) = build_block_trace_parts(
        class.shape,
        block,
        class.config_template,
        &class.spec,
        &io,
        class.tier,
        Some(class.sidecar_vk()),
    );
    let actual_digest = r1cs.statement_digest();
    assert_eq!(
        actual_digest, matrix_digest,
        "same-tier block matrix drifted from the frozen class"
    );
    r1cs.seed_statement_digest(matrix_digest);
    BuiltBlock {
        r1cs,
        witness,
        io,
        region_preparation,
    }
}

/// Assemble one production selected witness against a class frozen by
/// [`BlockClass::freeze_selected_zk`]. The consuming input makes the
/// exact live proof set plus the canonical ghost proof mandatory, while the
/// frozen matrix and V4 key checks reject any fallback to legacy authoring.
pub fn build_selected_zk_block_proof_trace<const TIER: usize>(
    class: &BlockClass,
    input: SelectedZkBlockInput<'_, TIER>,
) -> BuiltBlock {
    assert_eq!(
        class.authorization_backend,
        BlockClassAuthorizationBackend::SelectedZk,
        "selected build requires a selected-ZK class"
    );
    assert_eq!(class.tier, TIER, "selected input/class tier mismatch");
    let matrix_digest = class
        .validate_frozen_identity()
        .expect("selected BlockClass must remain freeze-locked");
    let built = build_selected_zk_trace_parts(input, Some(class.sidecar_vk()));
    let actual_digest = built.r1cs.statement_digest();
    assert_eq!(
        actual_digest, matrix_digest,
        "selected matrix drifted from the frozen class"
    );
    built.r1cs.seed_statement_digest(matrix_digest);
    built
}

pub fn build_selected_zk_b8_block_proof_trace(
    class: &BlockClass,
    input: SelectedZkB8BlockInput<'_>,
) -> BuiltBlock {
    build_selected_zk_block_proof_trace(class, input)
}

pub fn build_selected_zk_b32_block_proof_trace(
    class: &BlockClass,
    input: SelectedZkB32BlockInput<'_>,
) -> BuiltBlock {
    build_selected_zk_block_proof_trace(class, input)
}

pub fn build_selected_zk_b64_block_proof_trace(
    class: &BlockClass,
    input: SelectedZkB64BlockInput<'_>,
) -> BuiltBlock {
    build_selected_zk_block_proof_trace(class, input)
}

pub fn build_selected_zk_b255_block_proof_trace(
    class: &BlockClass,
    input: SelectedZkB255BlockInput<'_>,
) -> BuiltBlock {
    build_selected_zk_block_proof_trace(class, input)
}

/// Mandatory wire-format object for a production block proof.  Private fields
/// make an omitted or optional sidecar unrepresentable through the typed API.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct BlockProofEnvelope {
    field_proof: FieldR1csProof,
    commitment: Commitment,
    io: Vec<F128>,
    region_sidecar: BlockRegionSidecarProof,
}

impl BlockProofEnvelope {
    pub fn field_proof(&self) -> &FieldR1csProof {
        &self.field_proof
    }

    pub fn commitment(&self) -> &Commitment {
        &self.commitment
    }

    pub fn io(&self) -> &[F128] {
        &self.io
    }

    pub fn region_sidecar(&self) -> &BlockRegionSidecarProof {
        &self.region_sidecar
    }

    pub fn byte_len(&self) -> usize {
        bincode::serialized_size(self).expect("block proof envelope serialized length") as usize
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BlockProofError {
    UnfrozenClass,
    TierMismatch { expected: usize, actual: usize },
    LegacyAuthorizationBackend,
    ClassIdentityMismatch,
    MatrixMismatch,
    SidecarVkMismatch,
    PcsParamsMismatch,
    InvalidIo,
    Sidecar(RegionSidecarError),
    Field(VerifyError),
}

impl std::fmt::Display for BlockProofError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnfrozenClass => write!(f, "block class has no frozen matrix digest"),
            Self::TierMismatch { expected, actual } => {
                write!(
                    f,
                    "selected block class B{actual} occupies B{expected} registry slot"
                )
            }
            Self::LegacyAuthorizationBackend => {
                write!(
                    f,
                    "legacy authorization backend is not production-authorable"
                )
            }
            Self::ClassIdentityMismatch => write!(f, "block post-commit class identity drift"),
            Self::MatrixMismatch => write!(f, "block matrix does not match its frozen class"),
            Self::SidecarVkMismatch => write!(f, "block sidecar VK does not match its class"),
            Self::PcsParamsMismatch => {
                write!(f, "block commitment PCS parameters do not match its class")
            }
            Self::InvalidIo => write!(f, "block envelope must contain exactly 20 IO lanes"),
            Self::Sidecar(err) => write!(f, "block sidecar error: {err:?}"),
            Self::Field(err) => write!(f, "block Field proof error: {err:?}"),
        }
    }
}

impl std::error::Error for BlockProofError {}

impl From<RegionSidecarError> for BlockProofError {
    fn from(value: RegionSidecarError) -> Self {
        Self::Sidecar(value)
    }
}

impl From<VerifyError> for BlockProofError {
    fn from(value: VerifyError) -> Self {
        Self::Field(value)
    }
}

/// Prove the Field instance and all six region authorities on one causally
/// post-commit challenger and one terminal PCS batch.
pub fn prove_built_block<Ch: Challenger>(
    class: &BlockClass,
    built: &BuiltBlock,
    challenger: &mut Ch,
) -> Result<BlockProofEnvelope, BlockProofError> {
    let matrix_digest = class.validate_frozen_identity()?;
    if built.r1cs.statement_digest() != matrix_digest || FieldShape::of(&built.r1cs) != class.shape
    {
        return Err(BlockProofError::MatrixMismatch);
    }
    if built.region_preparation.vk() != class.sidecar_vk() {
        return Err(BlockProofError::SidecarVkMismatch);
    }
    if built.io.len() != BLOCK_IO_LEN {
        return Err(BlockProofError::InvalidIo);
    }
    let plan = built.region_preparation.prover_plan()?;
    let (field_proof, region_sidecar, commitment, _) =
        prove_field_with_public_io_and_post_commit_context(
            &built.r1cs,
            &built.witness,
            &class.pcs_params,
            &class.spec,
            &built.io,
            &class.post_commit_class_digest,
            challenger,
            |context| plan.prove_post_commit(context),
        );
    Ok(BlockProofEnvelope {
        field_proof,
        commitment,
        io: built.io.clone(),
        region_sidecar: region_sidecar?,
    })
}

/// Verify a complete production block proof.  The sidecar callback is inside
/// the opaque Field typestate; accepting the core proof while discarding the
/// six verifier-derived opening families is therefore impossible here.
pub fn verify_block_proof<Ch: Challenger>(
    class: &BlockClass,
    matrix: &FieldR1cs,
    envelope: &BlockProofEnvelope,
    challenger: &mut Ch,
) -> Result<R1csClaim, BlockProofError> {
    let matrix_digest = class.validate_frozen_identity()?;
    if matrix.statement_digest() != matrix_digest || FieldShape::of(matrix) != class.shape {
        return Err(BlockProofError::MatrixMismatch);
    }
    if envelope.io.len() != BLOCK_IO_LEN {
        return Err(BlockProofError::InvalidIo);
    }
    if !same_pcs_params(&envelope.commitment.params, &class.pcs_params) {
        return Err(BlockProofError::PcsParamsMismatch);
    }
    verify_field_with_public_io_and_post_commit_context(
        matrix,
        &envelope.commitment,
        &envelope.field_proof,
        &class.spec,
        &envelope.io,
        &class.post_commit_class_digest,
        &envelope.region_sidecar,
        challenger,
        |sidecar, context| {
            verify_block_region_sidecar_post_commit(class.sidecar_vk(), sidecar, context)
                .map_err(|_| VerifyError::Auxiliary)
        },
    )
    .map_err(BlockProofError::Field)
}

fn production_config(region_params: RegionDischargeParams, tier: usize) -> BlockSlotsConfig {
    BlockSlotsConfig {
        discharge_wallet_pcs: true,
        wallet_pcs_params: region_params,
        owner_auth_region: true,
        exact_state_region: true,
        tx_root_region: true,
        spine_region: true,
        tier_user_tx_capacity: Some(tier),
    }
}

fn is_production_config(config: &BlockSlotsConfig, tier: usize) -> bool {
    config.discharge_wallet_pcs
        && config.owner_auth_region
        && config.exact_state_region
        && config.tx_root_region
        && config.spine_region
        && config.tier_user_tx_capacity == Some(tier)
        && config.wallet_pcs_params.nq == noid_fri_binius::capsule::CAPSULE_NUM_QUERIES
}

pub(in crate::acceptance) fn accumulator_io(block: &LinkBlock<'_>) -> Vec<F128> {
    let layout = block_io_layout();
    let mut io = vec![F128::ZERO; layout.len];
    io[layout.start_acc..layout.start_acc + ACC_LANES]
        .copy_from_slice(&block_acc_lanes(block.start_accumulator));
    io[layout.end_acc..layout.end_acc + ACC_LANES]
        .copy_from_slice(&block_acc_lanes(block.end_accumulator));
    io
}

/// Allocate the canonical fixed-position Block IO slice.  The selected-ZK
/// production path reuses this exact helper so its row ledger cannot drift
/// from the other Block classes.
pub(in crate::acceptance) fn allocate_block_io_cells(
    b: &mut FieldR1csBuilder,
    spec: &PublicIoSpec,
    io_vals: &[F128],
) -> Vec<LinExpr> {
    assert!(
        is_production_block_io_spec(spec),
        "production block IO spec drift"
    );
    assert_eq!(io_vals.len(), BLOCK_IO_LEN, "production block IO length");
    let io_start = 1usize << spec.io_slice.log2_len;
    while b.num_wires() < io_start {
        b.alloc_f128(F128::ZERO);
    }
    (0..1usize << spec.io_slice.log2_len)
        .map(|index| {
            let value = io_vals.get(index).copied().unwrap_or(F128::ZERO);
            LinExpr::from_wire(b.alloc_f128(value))
        })
        .collect()
}

/// Bind the canonical Block accumulator aliases to the fixed IO slice.
/// Keeping this common with the production builder makes the selected
/// diagnostic an exact replacement measurement, not a reduced proxy.
pub(in crate::acceptance) fn pin_block_io_cells(
    b: &mut FieldR1csBuilder,
    slots: &BlockSlots,
    io_cells: &[LinExpr],
) {
    let layout = block_io_layout();
    for (index, wire) in slots.start_acc.ordered_lanes().iter().enumerate() {
        pin_eq(b, wire, &io_cells[layout.start_acc + index]);
    }
    for (index, wire) in slots.end_acc.ordered_lanes().iter().enumerate() {
        pin_eq(b, wire, &io_cells[layout.end_acc + index]);
    }
}

/// Shared production assembly.  There is no freeze mode, native region probe,
/// `RegionPcsClaim`, or claim-tail pinning: every call builds the exact class
/// relation and returns the mandatory post-commit preparation.
fn build_block_trace_parts(
    shape: FieldShape,
    block: &LinkBlock<'_>,
    config: BlockSlotsConfig,
    spec: &PublicIoSpec,
    io_vals: &[F128],
    tier: usize,
    expected_vk: Option<&BlockRegionSidecarVk>,
) -> (FieldR1cs, Vec<F128>, BlockRegionPreparation) {
    assert!(
        is_production_block_io_spec(spec),
        "production block IO spec drift"
    );
    assert_eq!(io_vals.len(), BLOCK_IO_LEN, "production block IO length");
    let mut b = FieldR1csBuilder::new();
    let mut ledger = 0usize;

    let io_cells = allocate_block_io_cells(&mut b, spec, io_vals);
    crate::acceptance::row_ledger_mark(&b, &mut ledger, "block: IO cells");

    let mut slots = build_block_slots_with_config(
        &mut b,
        block.start_accumulator,
        block.end_accumulator,
        block.inputs,
        block.proof,
        config,
    );
    assert!(
        slots.pending_wallet_pcs.is_empty(),
        "production block cannot export a RegionPcsClaim tail"
    );
    let preparation = slots
        .region_preparation
        .take()
        .expect("production block must return six-region preparation");
    if let Some(expected) = expected_vk {
        assert_eq!(
            preparation.vk(),
            expected,
            "same-tier block sidecar VK drifted from the frozen class"
        );
    }
    crate::acceptance::row_ledger_mark(&b, &mut ledger, "block: slots total");

    pin_block_io_cells(&mut b, &slots, &io_cells);
    crate::acceptance::row_ledger_mark(&b, &mut ledger, "block: IO pins");

    let used = b.num_wires();
    eprintln!("[block-class] build: {used} wires (tier {tier})");
    let target = 1usize << shape.m;
    assert!(
        used <= target,
        "block trace outgrew the class: {used} > {target}"
    );
    let (r1cs, witness) = b.build();
    let (r1cs, witness) = expand_empty_field_tail(r1cs, witness, shape);
    assert_eq!(
        FieldShape::of(&r1cs),
        shape,
        "block class shape after padding"
    );
    assert_eq!(r1cs.useful_rows, used, "block useful-row accounting");
    (r1cs, witness, preparation)
}

/// Expand the builder's natural dyadic matrix to the protocol class without
/// manufacturing identity constraints in the padding tail.  `useful_rows` is
/// statement-bound and drives the padded zerocheck/lincheck kernels, so every
/// skipped row must have both an empty A/B row and a zero witness value.
fn expand_empty_field_tail(
    mut r1cs: FieldR1cs,
    mut witness: Vec<F128>,
    shape: FieldShape,
) -> (FieldR1cs, Vec<F128>) {
    assert_eq!(r1cs.m, r1cs.k_log, "builder emits one base block");
    assert_eq!(shape.m, shape.k_log, "block class is one base block");
    assert_eq!(r1cs.k_skip, shape.k_skip, "block class k_skip drift");
    assert_eq!(r1cs.const_pin, shape.const_pin, "block const pin drift");
    assert!(r1cs.m <= shape.m, "cannot shrink a built block class");
    assert!(
        r1cs.digest_cache.get().is_none() && r1cs.csc_cache.get().is_none(),
        "padding must precede matrix digest/CSC caching"
    );

    let natural_rows = 1usize << r1cs.k_log;
    let target_rows = 1usize << shape.k_log;
    assert_eq!(witness.len(), natural_rows, "natural witness size");
    assert!(
        witness[r1cs.useful_rows..]
            .iter()
            .all(|value| *value == F128::ZERO),
        "natural builder padding witness must be zero"
    );
    for matrix in [&r1cs.a_0, &r1cs.b_0] {
        let tail = &matrix.row_offsets[r1cs.useful_rows..];
        assert!(
            tail.windows(2).all(|pair| pair[0] == pair[1]),
            "natural builder padding matrix rows must be empty"
        );
    }

    let expand_matrix = |matrix: &mut noid_ivc_core::field_r1cs::SparseFieldMatrix| {
        let terminal = *matrix
            .row_offsets
            .last()
            .expect("CSR has terminal row offset");
        matrix.row_offsets.resize(target_rows + 1, terminal);
        matrix.num_rows = target_rows;
        matrix.num_cols = target_rows;
    };
    expand_matrix(&mut r1cs.a_0);
    expand_matrix(&mut r1cs.b_0);
    witness.resize(target_rows, F128::ZERO);
    r1cs.m = shape.m;
    r1cs.k_log = shape.k_log;
    r1cs.validate_shape();

    for matrix in [&r1cs.a_0, &r1cs.b_0] {
        let tail = &matrix.row_offsets[r1cs.useful_rows..];
        assert!(
            tail.windows(2).all(|pair| pair[0] == pair[1]),
            "expanded block padding matrix rows must be empty"
        );
    }
    assert!(
        witness[r1cs.useful_rows..]
            .iter()
            .all(|value| *value == F128::ZERO),
        "expanded block padding witness must be zero"
    );
    assert_eq!(FieldShape::of(&r1cs), shape);
    (r1cs, witness)
}

pub(super) fn is_production_block_io_spec(spec: &PublicIoSpec) -> bool {
    let canonical = block_io_spec();
    spec.io_slice == canonical.io_slice && spec.io_len == canonical.io_len && spec.claims.is_empty()
}

fn same_pcs_params(left: &PcsParams, right: &PcsParams) -> bool {
    pcs_params_statement_bytes(left) == pcs_params_statement_bytes(right)
}

#[cfg(test)]
mod tests {
    use super::*;
    use noid_ivc_core::pcs::ligerito::LigeritoProfile;

    #[test]
    fn production_block_io_is_exactly_twenty_accumulator_lanes() {
        let layout = block_io_layout();
        let spec = block_io_spec();
        assert_eq!(layout.start_acc, 0);
        assert_eq!(layout.end_acc, ACC_LANES);
        assert_eq!(layout.len, 20);
        assert_eq!(spec.io_len, 20);
        assert_eq!(spec.io_slice.log2_len, 5);
        assert_eq!(spec.io_slice.index, 1);
        assert!(spec.claims.is_empty());
    }

    #[test]
    fn commitment_params_match_is_exact_not_shape_only() {
        let canonical = PcsParams {
            m: 29,
            log_inv_rate: 2,
            log_batch_size: 5,
            profile: LigeritoProfile::Fast,
        };
        assert!(same_pcs_params(&canonical, &canonical.clone()));

        let mut mutated = canonical.clone();
        mutated.m += 1;
        assert!(!same_pcs_params(&canonical, &mutated));
        mutated = canonical.clone();
        mutated.log_inv_rate += 1;
        assert!(!same_pcs_params(&canonical, &mutated));
        mutated = canonical.clone();
        mutated.log_batch_size += 1;
        assert!(!same_pcs_params(&canonical, &mutated));
        mutated = canonical.clone();
        mutated.profile = LigeritoProfile::Secure;
        assert!(!same_pcs_params(&canonical, &mutated));
    }

    #[test]
    fn production_config_metadata_is_tier_and_query_locked() {
        let params = RegionDischargeParams {
            nq: noid_fri_binius::capsule::CAPSULE_NUM_QUERIES,
        };
        let mut config = production_config(params, 8);
        assert!(is_production_config(&config, 8));
        assert!(!is_production_config(&config, 32));

        config.owner_auth_region = false;
        assert!(!is_production_config(&config, 8));
        config = production_config(params, 8);
        config.wallet_pcs_params.nq -= 1;
        assert!(!is_production_config(&config, 8));
    }

    #[test]
    fn selected_production_carrier_is_consuming_fixed_and_not_a_wire_envelope() {
        let link_source = include_str!("link.rs");
        let carrier_attributes = link_source
            .split("pub struct SelectedZkBlockInput")
            .next()
            .expect("selected production carrier declaration prefix")
            .rsplit("/// Owned, consuming input carrier")
            .next()
            .expect("selected production carrier attributes");
        assert!(
            !carrier_attributes.contains("#[derive"),
            "selected production carrier became derivably clonable or serializable"
        );
        let carrier = link_source
            .split("pub struct SelectedZkBlockInput")
            .nth(1)
            .expect("selected production carrier declaration")
            .split("/// Everything a link exposes to its successor")
            .next()
            .expect("bounded selected production carrier source");
        let fields = carrier
            .split('}')
            .next()
            .expect("selected production carrier fields");
        assert!(fields.contains("block: LinkBlock<'a>"));
        assert!(fields.contains("authorization: SelectedZkAuthorizationProofBundle"));
        assert!(!fields.contains("pub "), "carrier field became public");
        assert!(!fields.contains("Option<"), "authorization became optional");
        assert!(!carrier.contains("impl Clone for SelectedZkBlockInput"));
        assert!(!carrier.contains("impl Default for SelectedZkBlockInput"));
        assert!(!carrier.contains("Serialize"));
        assert!(!carrier.contains("Deserialize"));
        assert!(carrier.contains("pub fn try_new("));
        assert!(carrier.contains("live_proofs: Vec<ZkAuthorizationProof>"));
        assert!(carrier.contains("ghost_proof: ZkAuthorizationProof"));
        assert!(carrier.contains("tier_user_tx_capacity: Some("));
        assert!(carrier.contains("CAPSULE_NUM_QUERIES"));
        assert!(carrier.contains("pub(in crate::acceptance) fn into_parts("));

        let bundle_source = include_str!("trace/zk_authorization_candidate.rs");
        let bundle_prefix = bundle_source
            .split("pub(in crate::acceptance) struct SelectedZkAuthorizationProofBundle")
            .next()
            .expect("selected proof-bundle declaration prefix");
        let bundle_attributes = bundle_prefix
            .rsplit("/// Owned, still-unverified inputs")
            .next()
            .expect("selected proof-bundle attributes");
        assert!(
            !bundle_attributes.contains("derive(Clone)"),
            "owned authorization bundle became clonable"
        );

        let production = include_str!("block_class.rs")
            .split("pub fn build_selected_zk_block_proof_trace")
            .nth(1)
            .expect("selected production Block facade");
        let production_signature = production
            .split('{')
            .next()
            .expect("production facade signature");
        assert!(production_signature.contains("input: SelectedZkBlockInput<'_, TIER>"));
        assert!(!production_signature.contains("FieldShape"));
        assert!(!production_signature.contains("Vec<ZkAuthorizationProof>"));
        assert!(!production_signature.contains("ghost_proof"));

        let envelope = include_str!("block_class.rs")
            .split("pub struct BlockProofEnvelope")
            .nth(1)
            .expect("Block proof envelope")
            .split('}')
            .next()
            .expect("Block proof envelope fields");
        assert!(!envelope.contains("ZkAuthorizationProof"));
        assert!(!envelope.contains("SelectedZkBlockInput"));
    }

    #[test]
    fn class_expansion_preserves_a_genuinely_empty_zero_tail() {
        let mut builder = FieldR1csBuilder::new();
        for _ in 0..130 {
            builder.alloc_f128(F128::ZERO);
        }
        let used = builder.num_wires();
        let (natural, witness) = builder.build();
        assert_eq!(natural.m, 8);
        assert_eq!(natural.useful_rows, used);
        let shape = FieldShape {
            m: 10,
            k_log: 10,
            k_skip: natural.k_skip,
            const_pin: natural.const_pin,
        };
        let (expanded, witness) = expand_empty_field_tail(natural, witness, shape);
        assert_eq!(FieldShape::of(&expanded), shape);
        assert_eq!(expanded.useful_rows, used);
        assert_eq!(witness.len(), 1 << shape.m);
        assert!(witness[used..].iter().all(|value| *value == F128::ZERO));
        for matrix in [&expanded.a_0, &expanded.b_0] {
            assert!(matrix.row_offsets[used..]
                .windows(2)
                .all(|pair| pair[0] == pair[1]));
        }
        assert!(expanded.satisfies(&witness));
    }
}
