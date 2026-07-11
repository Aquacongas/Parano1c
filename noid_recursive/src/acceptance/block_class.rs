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

use std::sync::OnceLock;

use noid_ivc_core::challenger::Challenger;
use noid_ivc_core::field::F128;
use noid_ivc_core::field_circuit::{FieldR1csBuilder, LinExpr};
use noid_ivc_core::field_r1cs::FieldR1cs;
use noid_ivc_core::pcs::{Commitment, PcsParams, LOG_PACKING};
use noid_ivc_core::proof::{pcs_params_statement_bytes, FieldR1csProof, FieldShape, R1csClaim};
use noid_ivc_core::public_io::{PublicIoSpec, WitnessSlice};
use noid_ivc_core::verifier::{verify_field_with_public_io_and_post_commit_context, VerifyError};
use noid_ivc_prover::field_prover::prove_field_with_public_io_and_post_commit_context;

use super::block_slots::{build_block_slots_with_config, BlockSlotsConfig};
use super::link::{block_acc_lanes, LinkBlock, ACC_LANES};
use super::trace::pin_eq;
use super::trace::region_source_binding::RegionDischargeParams;
use crate::region_sidecar::{
    block_post_commit_class_digest, verify_block_region_sidecar_post_commit,
    BlockRegionPreparation, BlockRegionSidecarProof, BlockRegionSidecarVk, RegionSidecarError,
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
    sidecar_vk: BlockRegionSidecarVk,
    post_commit_class_digest: [u8; 32],
}

impl BlockClass {
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
        let sidecar_vk = preparation.vk().clone();
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
        }
    }

    pub fn sidecar_vk(&self) -> &BlockRegionSidecarVk {
        &self.sidecar_vk
    }

    pub fn tier(&self) -> usize {
        self.tier
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
        {
            return Err(BlockProofError::ClassIdentityMismatch);
        }
        let expected = block_post_commit_class_digest(
            &matrix_digest,
            &self.spec,
            &self.pcs_params,
            &self.sidecar_vk,
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

/// Assemble a block instance and require bit-exact reproduction of both the
/// frozen matrix and the frozen sidecar VK.
pub fn build_block_proof_trace(class: &BlockClass, block: &LinkBlock<'_>) -> BuiltBlock {
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
        Some(&class.sidecar_vk),
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
    if built.region_preparation.vk() != &class.sidecar_vk {
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
            verify_block_region_sidecar_post_commit(&class.sidecar_vk, sidecar, context)
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

fn accumulator_io(block: &LinkBlock<'_>) -> Vec<F128> {
    let layout = block_io_layout();
    let mut io = vec![F128::ZERO; layout.len];
    io[layout.start_acc..layout.start_acc + ACC_LANES]
        .copy_from_slice(&block_acc_lanes(block.start_accumulator));
    io[layout.end_acc..layout.end_acc + ACC_LANES]
        .copy_from_slice(&block_acc_lanes(block.end_accumulator));
    io
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

    let io_start = 1usize << spec.io_slice.log2_len;
    while b.num_wires() < io_start {
        b.alloc_f128(F128::ZERO);
    }
    let io_cells: Vec<LinExpr> = (0..1usize << spec.io_slice.log2_len)
        .map(|index| {
            let value = io_vals.get(index).copied().unwrap_or(F128::ZERO);
            LinExpr::from_wire(b.alloc_f128(value))
        })
        .collect();
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

    let layout = block_io_layout();
    for (index, wire) in slots.start_acc.ordered_lanes().iter().enumerate() {
        pin_eq(&mut b, wire, &io_cells[layout.start_acc + index]);
    }
    for (index, wire) in slots.end_acc.ordered_lanes().iter().enumerate() {
        pin_eq(&mut b, wire, &io_cells[layout.end_acc + index]);
    }
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
