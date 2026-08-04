// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Allocation-safe bincode-v1 shape preflight for fixed-class sidecars.
//!
//! Bincode's byte limit is not an allocation bound: a forged sequence length
//! can be consumed before the decoder discovers that the input is truncated.
//! This module walks the exact legacy fixed-int wire shape without allocating,
//! validates every sequence length against canonical class metadata, and only
//! then permits serde deserialization.

use noid_ivc_core::deep_chain::relations::{claimed_refs, ColRef, RELATION_DEGREE};
use noid_ivc_core::deep_chain::schedule::{
    carry_selection_terms, duplex_substitution_terms, DuplexFamilyRefs,
};
use noid_ivc_core::deep_chain::WALK_DEGREE;
use noid_ivc_core::field::F128;
use noid_poseidon2b::native::permutation::{N_ROUNDS, STATE_SIZE};

use crate::acceptance::trace::region_source_binding::{
    merkle_protocol_substitution_terms, merkle_protocol_zero_terms, DuplexUnionProof,
};

use super::merkle_trace::preflight_merkle_authority;
use super::trace::preflight_duplex_authority;
use super::{
    DuplexRegionSidecarProof, DuplexRegionVk, MerkleProtocolFamily, MerkleRegionSidecarProof,
    MerkleRegionVk, RegionSidecarError, DUPLEX_REGION_SIDECAR_VERSION,
    MERKLE_REGION_SIDECAR_VERSION,
};

const U64_BYTES: usize = 8;
const F128_BYTES: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct RelationShape {
    pub(super) rounds: usize,
    pub(super) values: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ProofTailShape {
    None,
    RelationOption(Option<RelationShape>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct FixedProofShape {
    pub(super) version: u8,
    pub(super) w_log: usize,
    pub(super) selection_values: usize,
    pub(super) substitution_values: usize,
    pub(super) shifts: usize,
    pub(super) tail: ProofTailShape,
}

/// Exact wire shape of a `version + authority` fixed-family child whose
/// deep-chain walk is serialized once by its enclosing proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct DeferredFixedProofShape {
    pub(super) version: u8,
    pub(super) w_log: usize,
    pub(super) selection_values: usize,
    pub(super) substitution_values: usize,
    pub(super) shifts: usize,
    pub(super) tail: ProofTailShape,
}

impl FixedProofShape {
    /// Preserve every V1 authority dimension while removing only the embedded
    /// walk field from the serialized child wrapper.
    pub(super) fn walk_deferred(self) -> DeferredFixedProofShape {
        DeferredFixedProofShape {
            version: self.version,
            w_log: self.w_log,
            selection_values: self.selection_values,
            substitution_values: self.substitution_values,
            shifts: self.shifts,
            tail: self.tail,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct MerkleProofShape {
    pub(super) version: u8,
    pub(super) w_log: usize,
    pub(super) zero_values: usize,
    pub(super) zero_shifts: usize,
    pub(super) selection_values: usize,
    pub(super) substitution_values: usize,
    pub(super) shifts: usize,
}

/// Exact wire shape of a `version + authority` Merkle child with its walk
/// deferred to an enclosing multi-instance proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct DeferredMerkleProofShape {
    pub(super) version: u8,
    pub(super) w_log: usize,
    pub(super) zero_values: usize,
    pub(super) zero_shifts: usize,
    pub(super) selection_values: usize,
    pub(super) substitution_values: usize,
    pub(super) shifts: usize,
}

impl MerkleProofShape {
    /// Preserve all relation/shift dimensions and omit exactly the walk.
    pub(super) fn walk_deferred(self) -> DeferredMerkleProofShape {
        DeferredMerkleProofShape {
            version: self.version,
            w_log: self.w_log,
            zero_values: self.zero_values,
            zero_shifts: self.zero_shifts,
            selection_values: self.selection_values,
            substitution_values: self.substitution_values,
            shifts: self.shifts,
        }
    }
}

/// Exact shape of [`noid_ivc_core::deep_chain::MultiDeepChainWalkProof`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct MultiWalkProofShape {
    pub(super) w_log: usize,
    pub(super) instances: usize,
}

pub(super) fn multi_walk_proof_shape(
    w_log: usize,
    instances: usize,
) -> Result<MultiWalkProofShape, RegionSidecarError> {
    if instances == 0 {
        return Err(RegionSidecarError::InvalidProof);
    }
    Ok(MultiWalkProofShape { w_log, instances })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum SidecarProofShape {
    #[cfg(test)]
    Fixed(FixedProofShape),
    DeferredFixed(DeferredFixedProofShape),
    /// Recording child: one fixed F128 selector followed by the ordinary
    /// walk-deferred duplex authority.
    RecordingDeferredFixed(DeferredFixedProofShape),
    DeferredMerkle(DeferredMerkleProofShape),
    MultiWalk(MultiWalkProofShape),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum VecClass {
    ZeroRounds,
    ZeroValues,
    ZeroShifts,
    ZeroShiftRounds,
    SelectionRounds,
    SelectionValues,
    WalkLayers,
    WalkLayerRounds,
    MultiWalkLayers,
    MultiWalkLayerRounds,
    MultiWalkNextInstances,
    SubstitutionRounds,
    SubstitutionValues,
    Shifts,
    ShiftRounds,
    SpineRounds,
    SpineValues,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum LayoutField {
    Version,
    VecLength(VecClass),
    OptionTag,
}

struct FixedIntCursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> FixedIntCursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn position(&self) -> usize {
        self.position
    }

    fn read_u8(&mut self) -> Result<u8, RegionSidecarError> {
        let value = *self
            .bytes
            .get(self.position)
            .ok_or(RegionSidecarError::InvalidProof)?;
        self.position += 1;
        Ok(value)
    }

    fn read_u64(&mut self) -> Result<u64, RegionSidecarError> {
        let end = self
            .position
            .checked_add(U64_BYTES)
            .ok_or(RegionSidecarError::InvalidProof)?;
        let raw: [u8; U64_BYTES] = self
            .bytes
            .get(self.position..end)
            .ok_or(RegionSidecarError::InvalidProof)?
            .try_into()
            .map_err(|_| RegionSidecarError::InvalidProof)?;
        self.position = end;
        Ok(u64::from_le_bytes(raw))
    }

    fn expect_vec_len(
        &mut self,
        expected: usize,
        class: VecClass,
        observe: &mut impl FnMut(LayoutField, usize),
    ) -> Result<(), RegionSidecarError> {
        observe(LayoutField::VecLength(class), self.position);
        let expected = u64::try_from(expected).map_err(|_| RegionSidecarError::InvalidProof)?;
        if self.read_u64()? != expected {
            return Err(RegionSidecarError::InvalidProof);
        }
        Ok(())
    }

    fn skip(&mut self, count: usize) -> Result<(), RegionSidecarError> {
        let end = self
            .position
            .checked_add(count)
            .ok_or(RegionSidecarError::InvalidProof)?;
        if end > self.bytes.len() {
            return Err(RegionSidecarError::InvalidProof);
        }
        self.position = end;
        Ok(())
    }

    fn skip_f128s(&mut self, count: usize) -> Result<(), RegionSidecarError> {
        self.skip(checked_mul(count, F128_BYTES)?)
    }

    fn finish(self) -> Result<(), RegionSidecarError> {
        if self.position != self.bytes.len() {
            return Err(RegionSidecarError::InvalidProof);
        }
        Ok(())
    }
}

/// Decode one homogeneous Duplex sidecar only after an allocation-free exact
/// bincode-v1 fixed-int shape pass tied to `vk` and `total_vars`.
pub fn decode_duplex_region_sidecar_bounded(
    vk: &DuplexRegionVk,
    total_vars: usize,
    bytes: &[u8],
) -> Result<DuplexRegionSidecarProof, RegionSidecarError> {
    vk.validate_in_witness(total_vars)?;
    let shape = duplex_proof_shape(vk);
    preflight_fixed_proof(bytes, &shape)?;
    record_serde_attempt();
    let proof: DuplexRegionSidecarProof =
        bincode::deserialize(bytes).map_err(|_| RegionSidecarError::InvalidProof)?;
    if proof.version != DUPLEX_REGION_SIDECAR_VERSION {
        return Err(RegionSidecarError::UnsupportedVersion);
    }
    preflight_duplex_authority(vk.w_log, &vk.refs, authority(&proof))?;
    Ok(proof)
}

/// Decode one canonical Walk-B sidecar after validating every zero/selection/
/// walk/substitution/shift sequence length without allocating.
pub fn decode_merkle_region_sidecar_bounded(
    vk: &MerkleRegionVk,
    total_vars: usize,
    bytes: &[u8],
) -> Result<MerkleRegionSidecarProof, RegionSidecarError> {
    vk.validate_in_witness(total_vars)?;
    let families = vk.protocol_families();
    let shape = merkle_proof_shape(vk, &families);
    preflight_merkle_proof(bytes, &shape)?;
    record_serde_attempt();
    let proof: MerkleRegionSidecarProof =
        bincode::deserialize(bytes).map_err(|_| RegionSidecarError::InvalidProof)?;
    if proof.version != MERKLE_REGION_SIDECAR_VERSION {
        return Err(RegionSidecarError::UnsupportedVersion);
    }
    preflight_merkle_authority(
        vk.w_log,
        &vk.fixed,
        &[0, 1, 2, 3],
        &families,
        &proof.authority,
    )?;
    Ok(proof)
}

fn authority(proof: &DuplexRegionSidecarProof) -> &DuplexUnionProof {
    &proof.authority
}

pub(super) fn duplex_proof_shape(vk: &DuplexRegionVk) -> FixedProofShape {
    duplex_like_proof_shape(DUPLEX_REGION_SIDECAR_VERSION, vk.w_log, &vk.refs)
}

pub(super) fn duplex_shape_for_vk(
    vk: &DuplexRegionVk,
    total_vars: usize,
) -> Result<FixedProofShape, RegionSidecarError> {
    vk.validate_in_witness(total_vars)?;
    Ok(duplex_proof_shape(vk))
}

pub(super) fn duplex_like_proof_shape(
    version: u8,
    w_log: usize,
    refs: &DuplexFamilyRefs,
) -> FixedProofShape {
    let selection_values = claimed_refs(&carry_selection_terms(&refs.c, F128::ONE)).len();
    let substitution_refs = claimed_refs(&duplex_substitution_terms(refs, F128::ONE));
    let shifts = substitution_refs
        .iter()
        .filter(|reference| {
            matches!(
                reference,
                noid_ivc_core::deep_chain::relations::ColRef::CommittedShift(_)
                    | noid_ivc_core::deep_chain::relations::ColRef::CommittedShift2(_)
            )
        })
        .count();
    FixedProofShape {
        version,
        w_log,
        selection_values,
        substitution_values: substitution_refs.len(),
        shifts,
        tail: ProofTailShape::None,
    }
}

pub(super) fn merkle_shape_for_vk(
    vk: &MerkleRegionVk,
    total_vars: usize,
) -> Result<MerkleProofShape, RegionSidecarError> {
    vk.validate_in_witness(total_vars)?;
    let families = vk.protocol_families();
    Ok(merkle_proof_shape(vk, &families))
}

fn merkle_proof_shape(vk: &MerkleRegionVk, families: &[MerkleProtocolFamily]) -> MerkleProofShape {
    let zero_refs = claimed_refs(&merkle_protocol_zero_terms(families, F128::ONE));
    let selection_values = claimed_refs(&carry_selection_terms(&[0, 1, 2, 3], F128::ONE)).len();
    let substitution_refs = claimed_refs(&merkle_protocol_substitution_terms(families, F128::ONE));
    MerkleProofShape {
        version: MERKLE_REGION_SIDECAR_VERSION,
        w_log: vk.w_log,
        zero_values: zero_refs.len(),
        zero_shifts: shift_count(&zero_refs),
        selection_values,
        substitution_values: substitution_refs.len(),
        shifts: shift_count(&substitution_refs),
    }
}

fn shift_count(references: &[ColRef]) -> usize {
    references
        .iter()
        .filter(|reference| {
            matches!(
                reference,
                ColRef::CommittedShift(_) | ColRef::CommittedShift2(_)
            )
        })
        .count()
}

pub(super) fn preflight_fixed_proof(
    bytes: &[u8],
    shape: &FixedProofShape,
) -> Result<(), RegionSidecarError> {
    scan_fixed_proof(bytes, shape, &mut |_, _| {})
}

pub(super) fn preflight_deferred_fixed_proof(
    bytes: &[u8],
    shape: &DeferredFixedProofShape,
) -> Result<(), RegionSidecarError> {
    let ceiling = deferred_fixed_proof_encoded_len(shape)?;
    if bytes.len() > ceiling {
        return Err(RegionSidecarError::InvalidProof);
    }
    let mut cursor = FixedIntCursor::new(bytes);
    scan_deferred_fixed_proof_body(&mut cursor, shape, &mut |_, _| {})?;
    cursor.finish()
}

pub(super) fn preflight_merkle_proof(
    bytes: &[u8],
    shape: &MerkleProofShape,
) -> Result<(), RegionSidecarError> {
    let ceiling = merkle_proof_encoded_len(shape)?;
    if bytes.len() > ceiling {
        return Err(RegionSidecarError::InvalidProof);
    }
    let mut cursor = FixedIntCursor::new(bytes);
    scan_merkle_proof_body(&mut cursor, shape, &mut |_, _| {})?;
    cursor.finish()
}

#[cfg(test)]
pub(super) fn preflight_deferred_merkle_proof(
    bytes: &[u8],
    shape: &DeferredMerkleProofShape,
) -> Result<(), RegionSidecarError> {
    let ceiling = deferred_merkle_proof_encoded_len(shape)?;
    if bytes.len() > ceiling {
        return Err(RegionSidecarError::InvalidProof);
    }
    let mut cursor = FixedIntCursor::new(bytes);
    scan_deferred_merkle_proof_body(&mut cursor, shape, &mut |_, _| {})?;
    cursor.finish()
}

#[cfg(test)]
pub(super) fn preflight_multi_walk_proof(
    bytes: &[u8],
    shape: &MultiWalkProofShape,
) -> Result<(), RegionSidecarError> {
    let ceiling = multi_walk_proof_encoded_len(shape)?;
    if bytes.len() > ceiling {
        return Err(RegionSidecarError::InvalidProof);
    }
    let mut cursor = FixedIntCursor::new(bytes);
    scan_multi_walk_proof_body(&mut cursor, shape, &mut |_, _| {})?;
    cursor.finish()
}

pub(super) fn preflight_composite_proof(
    bytes: &[u8],
    version: u8,
    children: &[SidecarProofShape],
) -> Result<(), RegionSidecarError> {
    scan_composite_proof(bytes, version, children, &mut |_, _| {})
}

fn scan_fixed_proof(
    bytes: &[u8],
    shape: &FixedProofShape,
    observe: &mut impl FnMut(LayoutField, usize),
) -> Result<(), RegionSidecarError> {
    let ceiling = fixed_proof_encoded_len(shape)?;
    if bytes.len() > ceiling {
        return Err(RegionSidecarError::InvalidProof);
    }

    let mut cursor = FixedIntCursor::new(bytes);
    scan_fixed_proof_body(&mut cursor, shape, observe)?;
    cursor.finish()
}

fn scan_fixed_proof_body(
    cursor: &mut FixedIntCursor<'_>,
    shape: &FixedProofShape,
    observe: &mut impl FnMut(LayoutField, usize),
) -> Result<(), RegionSidecarError> {
    observe(LayoutField::Version, cursor.position());
    if cursor.read_u8()? != shape.version {
        return Err(RegionSidecarError::UnsupportedVersion);
    }
    scan_relation(
        cursor,
        RelationShape {
            rounds: shape.w_log,
            values: shape.selection_values,
        },
        VecClass::SelectionRounds,
        VecClass::SelectionValues,
        observe,
    )?;
    scan_walk(cursor, shape.w_log, observe)?;
    scan_relation(
        cursor,
        RelationShape {
            rounds: shape.w_log,
            values: shape.substitution_values,
        },
        VecClass::SubstitutionRounds,
        VecClass::SubstitutionValues,
        observe,
    )?;
    scan_shifts(
        cursor,
        shape.w_log,
        shape.shifts,
        VecClass::Shifts,
        VecClass::ShiftRounds,
        observe,
    )?;
    match shape.tail {
        ProofTailShape::None => {}
        ProofTailShape::RelationOption(expected) => {
            observe(LayoutField::OptionTag, cursor.position());
            let tag = cursor.read_u8()?;
            match (expected, tag) {
                (None, 0) => {}
                (Some(relation), 1) => scan_relation(
                    cursor,
                    relation,
                    VecClass::SpineRounds,
                    VecClass::SpineValues,
                    observe,
                )?,
                _ => return Err(RegionSidecarError::InvalidProof),
            }
        }
    }
    Ok(())
}

fn scan_deferred_fixed_proof_body(
    cursor: &mut FixedIntCursor<'_>,
    shape: &DeferredFixedProofShape,
    observe: &mut impl FnMut(LayoutField, usize),
) -> Result<(), RegionSidecarError> {
    observe(LayoutField::Version, cursor.position());
    if cursor.read_u8()? != shape.version {
        return Err(RegionSidecarError::UnsupportedVersion);
    }
    scan_relation(
        cursor,
        RelationShape {
            rounds: shape.w_log,
            values: shape.selection_values,
        },
        VecClass::SelectionRounds,
        VecClass::SelectionValues,
        observe,
    )?;
    scan_relation(
        cursor,
        RelationShape {
            rounds: shape.w_log,
            values: shape.substitution_values,
        },
        VecClass::SubstitutionRounds,
        VecClass::SubstitutionValues,
        observe,
    )?;
    scan_shifts(
        cursor,
        shape.w_log,
        shape.shifts,
        VecClass::Shifts,
        VecClass::ShiftRounds,
        observe,
    )?;
    match shape.tail {
        ProofTailShape::None => {}
        ProofTailShape::RelationOption(expected) => {
            observe(LayoutField::OptionTag, cursor.position());
            let tag = cursor.read_u8()?;
            match (expected, tag) {
                (None, 0) => {}
                (Some(relation), 1) => scan_relation(
                    cursor,
                    relation,
                    VecClass::SpineRounds,
                    VecClass::SpineValues,
                    observe,
                )?,
                _ => return Err(RegionSidecarError::InvalidProof),
            }
        }
    }
    Ok(())
}

fn scan_merkle_proof_body(
    cursor: &mut FixedIntCursor<'_>,
    shape: &MerkleProofShape,
    observe: &mut impl FnMut(LayoutField, usize),
) -> Result<(), RegionSidecarError> {
    observe(LayoutField::Version, cursor.position());
    if cursor.read_u8()? != shape.version {
        return Err(RegionSidecarError::UnsupportedVersion);
    }
    scan_relation(
        cursor,
        RelationShape {
            rounds: shape.w_log,
            values: shape.zero_values,
        },
        VecClass::ZeroRounds,
        VecClass::ZeroValues,
        observe,
    )?;
    scan_shifts(
        cursor,
        shape.w_log,
        shape.zero_shifts,
        VecClass::ZeroShifts,
        VecClass::ZeroShiftRounds,
        observe,
    )?;
    scan_relation(
        cursor,
        RelationShape {
            rounds: shape.w_log,
            values: shape.selection_values,
        },
        VecClass::SelectionRounds,
        VecClass::SelectionValues,
        observe,
    )?;
    scan_walk(cursor, shape.w_log, observe)?;
    scan_relation(
        cursor,
        RelationShape {
            rounds: shape.w_log,
            values: shape.substitution_values,
        },
        VecClass::SubstitutionRounds,
        VecClass::SubstitutionValues,
        observe,
    )?;
    scan_shifts(
        cursor,
        shape.w_log,
        shape.shifts,
        VecClass::Shifts,
        VecClass::ShiftRounds,
        observe,
    )
}

fn scan_deferred_merkle_proof_body(
    cursor: &mut FixedIntCursor<'_>,
    shape: &DeferredMerkleProofShape,
    observe: &mut impl FnMut(LayoutField, usize),
) -> Result<(), RegionSidecarError> {
    observe(LayoutField::Version, cursor.position());
    if cursor.read_u8()? != shape.version {
        return Err(RegionSidecarError::UnsupportedVersion);
    }
    scan_relation(
        cursor,
        RelationShape {
            rounds: shape.w_log,
            values: shape.zero_values,
        },
        VecClass::ZeroRounds,
        VecClass::ZeroValues,
        observe,
    )?;
    scan_shifts(
        cursor,
        shape.w_log,
        shape.zero_shifts,
        VecClass::ZeroShifts,
        VecClass::ZeroShiftRounds,
        observe,
    )?;
    scan_relation(
        cursor,
        RelationShape {
            rounds: shape.w_log,
            values: shape.selection_values,
        },
        VecClass::SelectionRounds,
        VecClass::SelectionValues,
        observe,
    )?;
    scan_relation(
        cursor,
        RelationShape {
            rounds: shape.w_log,
            values: shape.substitution_values,
        },
        VecClass::SubstitutionRounds,
        VecClass::SubstitutionValues,
        observe,
    )?;
    scan_shifts(
        cursor,
        shape.w_log,
        shape.shifts,
        VecClass::Shifts,
        VecClass::ShiftRounds,
        observe,
    )
}

fn scan_multi_walk_proof_body(
    cursor: &mut FixedIntCursor<'_>,
    shape: &MultiWalkProofShape,
    observe: &mut impl FnMut(LayoutField, usize),
) -> Result<(), RegionSidecarError> {
    if shape.instances == 0 {
        return Err(RegionSidecarError::InvalidProof);
    }
    cursor.expect_vec_len(N_ROUNDS, VecClass::MultiWalkLayers, observe)?;
    for _ in 0..N_ROUNDS {
        cursor.expect_vec_len(shape.w_log, VecClass::MultiWalkLayerRounds, observe)?;
        cursor.skip_f128s(checked_mul(shape.w_log, WALK_DEGREE)?)?;
        cursor.expect_vec_len(shape.instances, VecClass::MultiWalkNextInstances, observe)?;
        cursor.skip_f128s(checked_mul(shape.instances, STATE_SIZE)?)?;
    }
    Ok(())
}

fn scan_composite_proof(
    bytes: &[u8],
    version: u8,
    children: &[SidecarProofShape],
    observe: &mut impl FnMut(LayoutField, usize),
) -> Result<(), RegionSidecarError> {
    let ceiling = children.iter().try_fold(1usize, |length, child| {
        checked_add(length, sidecar_proof_encoded_len(child)?)
    })?;
    if bytes.len() > ceiling {
        return Err(RegionSidecarError::InvalidProof);
    }
    let mut cursor = FixedIntCursor::new(bytes);
    observe(LayoutField::Version, cursor.position());
    if cursor.read_u8()? != version {
        return Err(RegionSidecarError::UnsupportedVersion);
    }
    for child in children {
        match child {
            #[cfg(test)]
            SidecarProofShape::Fixed(shape) => scan_fixed_proof_body(&mut cursor, shape, observe)?,
            SidecarProofShape::DeferredFixed(shape) => {
                scan_deferred_fixed_proof_body(&mut cursor, shape, observe)?
            }
            SidecarProofShape::RecordingDeferredFixed(shape) => {
                cursor.skip_f128s(1)?;
                scan_deferred_fixed_proof_body(&mut cursor, shape, observe)?
            }
            SidecarProofShape::DeferredMerkle(shape) => {
                scan_deferred_merkle_proof_body(&mut cursor, shape, observe)?
            }
            SidecarProofShape::MultiWalk(shape) => {
                scan_multi_walk_proof_body(&mut cursor, shape, observe)?
            }
        }
    }
    cursor.finish()
}

fn scan_relation(
    cursor: &mut FixedIntCursor<'_>,
    shape: RelationShape,
    rounds_class: VecClass,
    values_class: VecClass,
    observe: &mut impl FnMut(LayoutField, usize),
) -> Result<(), RegionSidecarError> {
    cursor.expect_vec_len(shape.rounds, rounds_class, observe)?;
    cursor.skip_f128s(checked_mul(shape.rounds, RELATION_DEGREE)?)?;
    cursor.expect_vec_len(shape.values, values_class, observe)?;
    cursor.skip_f128s(shape.values)
}

fn scan_shifts(
    cursor: &mut FixedIntCursor<'_>,
    w_log: usize,
    count: usize,
    shifts_class: VecClass,
    rounds_class: VecClass,
    observe: &mut impl FnMut(LayoutField, usize),
) -> Result<(), RegionSidecarError> {
    cursor.expect_vec_len(count, shifts_class, observe)?;
    for _ in 0..count {
        cursor.expect_vec_len(w_log, rounds_class, observe)?;
        cursor.skip_f128s(checked_mul(w_log, 2)?)?;
        cursor.skip_f128s(1)?;
    }
    Ok(())
}

fn scan_walk(
    cursor: &mut FixedIntCursor<'_>,
    w_log: usize,
    observe: &mut impl FnMut(LayoutField, usize),
) -> Result<(), RegionSidecarError> {
    cursor.expect_vec_len(N_ROUNDS, VecClass::WalkLayers, observe)?;
    for _ in 0..N_ROUNDS {
        cursor.expect_vec_len(w_log, VecClass::WalkLayerRounds, observe)?;
        cursor.skip_f128s(checked_mul(w_log, WALK_DEGREE)?)?;
        cursor.skip_f128s(STATE_SIZE)?;
    }
    Ok(())
}

pub(super) fn sidecar_proof_encoded_len(
    shape: &SidecarProofShape,
) -> Result<usize, RegionSidecarError> {
    match shape {
        #[cfg(test)]
        SidecarProofShape::Fixed(shape) => fixed_proof_encoded_len(shape),
        SidecarProofShape::DeferredFixed(shape) => deferred_fixed_proof_encoded_len(shape),
        SidecarProofShape::RecordingDeferredFixed(shape) => {
            checked_add(F128_BYTES, deferred_fixed_proof_encoded_len(shape)?)
        }
        SidecarProofShape::DeferredMerkle(shape) => deferred_merkle_proof_encoded_len(shape),
        SidecarProofShape::MultiWalk(shape) => multi_walk_proof_encoded_len(shape),
    }
}

fn fixed_proof_encoded_len(shape: &FixedProofShape) -> Result<usize, RegionSidecarError> {
    let selection = relation_encoded_len(RelationShape {
        rounds: shape.w_log,
        values: shape.selection_values,
    })?;
    let substitution = relation_encoded_len(RelationShape {
        rounds: shape.w_log,
        values: shape.substitution_values,
    })?;
    let walk = walk_encoded_len(shape.w_log)?;
    let shifts = shifts_encoded_len(shape.w_log, shape.shifts)?;
    let tail = match shape.tail {
        ProofTailShape::None => 0,
        ProofTailShape::RelationOption(None) => 1,
        ProofTailShape::RelationOption(Some(relation)) => {
            checked_add(1, relation_encoded_len(relation)?)?
        }
    };
    [1usize, selection, walk, substitution, shifts, tail]
        .into_iter()
        .try_fold(0usize, checked_add)
}

pub(super) fn deferred_fixed_proof_encoded_len(
    shape: &DeferredFixedProofShape,
) -> Result<usize, RegionSidecarError> {
    let selection = relation_encoded_len(RelationShape {
        rounds: shape.w_log,
        values: shape.selection_values,
    })?;
    let substitution = relation_encoded_len(RelationShape {
        rounds: shape.w_log,
        values: shape.substitution_values,
    })?;
    let shifts = shifts_encoded_len(shape.w_log, shape.shifts)?;
    let tail = match shape.tail {
        ProofTailShape::None => 0,
        ProofTailShape::RelationOption(None) => 1,
        ProofTailShape::RelationOption(Some(relation)) => {
            checked_add(1, relation_encoded_len(relation)?)?
        }
    };
    [1usize, selection, substitution, shifts, tail]
        .into_iter()
        .try_fold(0usize, checked_add)
}

fn merkle_proof_encoded_len(shape: &MerkleProofShape) -> Result<usize, RegionSidecarError> {
    let zero = relation_encoded_len(RelationShape {
        rounds: shape.w_log,
        values: shape.zero_values,
    })?;
    let zero_shifts = shifts_encoded_len(shape.w_log, shape.zero_shifts)?;
    let selection = relation_encoded_len(RelationShape {
        rounds: shape.w_log,
        values: shape.selection_values,
    })?;
    let walk = walk_encoded_len(shape.w_log)?;
    let substitution = relation_encoded_len(RelationShape {
        rounds: shape.w_log,
        values: shape.substitution_values,
    })?;
    let shifts = shifts_encoded_len(shape.w_log, shape.shifts)?;
    [
        1usize,
        zero,
        zero_shifts,
        selection,
        walk,
        substitution,
        shifts,
    ]
    .into_iter()
    .try_fold(0usize, checked_add)
}

pub(super) fn deferred_merkle_proof_encoded_len(
    shape: &DeferredMerkleProofShape,
) -> Result<usize, RegionSidecarError> {
    let zero = relation_encoded_len(RelationShape {
        rounds: shape.w_log,
        values: shape.zero_values,
    })?;
    let zero_shifts = shifts_encoded_len(shape.w_log, shape.zero_shifts)?;
    let selection = relation_encoded_len(RelationShape {
        rounds: shape.w_log,
        values: shape.selection_values,
    })?;
    let substitution = relation_encoded_len(RelationShape {
        rounds: shape.w_log,
        values: shape.substitution_values,
    })?;
    let shifts = shifts_encoded_len(shape.w_log, shape.shifts)?;
    [1usize, zero, zero_shifts, selection, substitution, shifts]
        .into_iter()
        .try_fold(0usize, checked_add)
}

pub(super) fn multi_walk_proof_encoded_len(
    shape: &MultiWalkProofShape,
) -> Result<usize, RegionSidecarError> {
    if shape.instances == 0 {
        return Err(RegionSidecarError::InvalidProof);
    }
    let round_coefficients = checked_mul(checked_mul(shape.w_log, WALK_DEGREE)?, F128_BYTES)?;
    let next_values = checked_mul(checked_mul(shape.instances, STATE_SIZE)?, F128_BYTES)?;
    let layer = [U64_BYTES, round_coefficients, U64_BYTES, next_values]
        .into_iter()
        .try_fold(0usize, checked_add)?;
    checked_add(U64_BYTES, checked_mul(N_ROUNDS, layer)?)
}

fn walk_encoded_len(w_log: usize) -> Result<usize, RegionSidecarError> {
    let layer = checked_add(
        U64_BYTES,
        checked_add(
            checked_mul(checked_mul(w_log, WALK_DEGREE)?, F128_BYTES)?,
            checked_mul(STATE_SIZE, F128_BYTES)?,
        )?,
    )?;
    checked_add(U64_BYTES, checked_mul(N_ROUNDS, layer)?)
}

fn shifts_encoded_len(w_log: usize, count: usize) -> Result<usize, RegionSidecarError> {
    let shift = checked_add(
        U64_BYTES,
        checked_add(checked_mul(checked_mul(w_log, 2)?, F128_BYTES)?, F128_BYTES)?,
    )?;
    checked_add(U64_BYTES, checked_mul(count, shift)?)
}

fn relation_encoded_len(shape: RelationShape) -> Result<usize, RegionSidecarError> {
    [
        U64_BYTES,
        checked_mul(checked_mul(shape.rounds, RELATION_DEGREE)?, F128_BYTES)?,
        U64_BYTES,
        checked_mul(shape.values, F128_BYTES)?,
    ]
    .into_iter()
    .try_fold(0usize, checked_add)
}

fn checked_add(left: usize, right: usize) -> Result<usize, RegionSidecarError> {
    left.checked_add(right)
        .ok_or(RegionSidecarError::InvalidProof)
}

fn checked_mul(left: usize, right: usize) -> Result<usize, RegionSidecarError> {
    left.checked_mul(right)
        .ok_or(RegionSidecarError::InvalidProof)
}

#[cfg(test)]
pub(super) fn layout_offsets(
    bytes: &[u8],
    shape: &FixedProofShape,
) -> Result<Vec<(LayoutField, usize)>, RegionSidecarError> {
    let mut offsets = Vec::new();
    scan_fixed_proof(bytes, shape, &mut |field, offset| {
        if !offsets.iter().any(|(seen, _)| *seen == field) {
            offsets.push((field, offset));
        }
    })?;
    Ok(offsets)
}

#[cfg(test)]
pub(super) fn layout_offsets_merkle(
    bytes: &[u8],
    shape: &MerkleProofShape,
) -> Result<Vec<(LayoutField, usize)>, RegionSidecarError> {
    let ceiling = merkle_proof_encoded_len(shape)?;
    if bytes.len() > ceiling {
        return Err(RegionSidecarError::InvalidProof);
    }
    let mut cursor = FixedIntCursor::new(bytes);
    let mut offsets = Vec::new();
    scan_merkle_proof_body(&mut cursor, shape, &mut |field, offset| {
        if !offsets.iter().any(|(seen, _)| *seen == field) {
            offsets.push((field, offset));
        }
    })?;
    cursor.finish()?;
    Ok(offsets)
}

#[cfg(test)]
pub(super) fn layout_offsets_deferred_fixed(
    bytes: &[u8],
    shape: &DeferredFixedProofShape,
) -> Result<Vec<(LayoutField, usize)>, RegionSidecarError> {
    let ceiling = deferred_fixed_proof_encoded_len(shape)?;
    if bytes.len() > ceiling {
        return Err(RegionSidecarError::InvalidProof);
    }
    let mut cursor = FixedIntCursor::new(bytes);
    let mut offsets = Vec::new();
    scan_deferred_fixed_proof_body(&mut cursor, shape, &mut |field, offset| {
        offsets.push((field, offset));
    })?;
    cursor.finish()?;
    Ok(offsets)
}

#[cfg(test)]
pub(super) fn layout_offsets_deferred_merkle(
    bytes: &[u8],
    shape: &DeferredMerkleProofShape,
) -> Result<Vec<(LayoutField, usize)>, RegionSidecarError> {
    let ceiling = deferred_merkle_proof_encoded_len(shape)?;
    if bytes.len() > ceiling {
        return Err(RegionSidecarError::InvalidProof);
    }
    let mut cursor = FixedIntCursor::new(bytes);
    let mut offsets = Vec::new();
    scan_deferred_merkle_proof_body(&mut cursor, shape, &mut |field, offset| {
        offsets.push((field, offset));
    })?;
    cursor.finish()?;
    Ok(offsets)
}

#[cfg(test)]
pub(super) fn layout_offsets_multi_walk(
    bytes: &[u8],
    shape: &MultiWalkProofShape,
) -> Result<Vec<(LayoutField, usize)>, RegionSidecarError> {
    let ceiling = multi_walk_proof_encoded_len(shape)?;
    if bytes.len() > ceiling {
        return Err(RegionSidecarError::InvalidProof);
    }
    let mut cursor = FixedIntCursor::new(bytes);
    let mut offsets = Vec::new();
    scan_multi_walk_proof_body(&mut cursor, shape, &mut |field, offset| {
        offsets.push((field, offset));
    })?;
    cursor.finish()?;
    Ok(offsets)
}

#[cfg(test)]
pub(super) fn composite_layout_offsets(
    bytes: &[u8],
    version: u8,
    children: &[SidecarProofShape],
) -> Result<Vec<(LayoutField, usize)>, RegionSidecarError> {
    let mut offsets = Vec::new();
    scan_composite_proof(bytes, version, children, &mut |field, offset| {
        offsets.push((field, offset));
    })?;
    Ok(offsets)
}

#[cfg(test)]
thread_local! {
    static SERDE_ATTEMPTS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub(super) fn record_serde_attempt() {
    SERDE_ATTEMPTS.with(|attempts| attempts.set(attempts.get() + 1));
}

#[cfg(not(test))]
pub(super) fn record_serde_attempt() {}

#[cfg(test)]
pub(super) fn serde_attempts() -> usize {
    SERDE_ATTEMPTS.with(std::cell::Cell::get)
}

#[cfg(test)]
mod deferred_tests {
    use super::*;
    use noid_ivc_core::deep_chain::relations::{ColumnRelationProof, ShiftDischargeProof};
    use noid_ivc_core::deep_chain::{MultiDeepChainWalkProof, MultiWalkLayerProof};

    use crate::acceptance::trace::region_source_binding::{
        MerkleUnionWalkDeferredProof, WalkAUnionWalkDeferredProof,
    };
    use crate::region_sidecar::{
        MerkleRegionWalkDeferredProof, WalkARegionWalkDeferredProof, MERKLE_REGION_SIDECAR_VERSION,
        WALK_A_REGION_SIDECAR_VERSION,
    };

    fn value(seed: u64) -> F128 {
        F128 {
            lo: seed,
            hi: seed.rotate_left(17),
        }
    }

    fn relation(rounds: usize, values: usize, seed: u64) -> ColumnRelationProof {
        ColumnRelationProof {
            rounds: (0..rounds)
                .map(|round| {
                    std::array::from_fn(|coefficient| {
                        value(seed + (round * RELATION_DEGREE + coefficient) as u64)
                    })
                })
                .collect(),
            final_values: (0..values)
                .map(|index| value(seed + 0x1000 + index as u64))
                .collect(),
        }
    }

    fn shifts(count: usize, w_log: usize, seed: u64) -> Vec<ShiftDischargeProof> {
        (0..count)
            .map(|shift| ShiftDischargeProof {
                rounds: (0..w_log)
                    .map(|round| {
                        [
                            value(seed + (2 * (shift * w_log + round)) as u64),
                            value(seed + (2 * (shift * w_log + round) + 1) as u64),
                        ]
                    })
                    .collect(),
                final_value: value(seed + 0x2000 + shift as u64),
            })
            .collect()
    }

    fn fixed_fixture() -> (WalkARegionWalkDeferredProof, DeferredFixedProofShape) {
        let w_log = 2;
        let selection_values = 3;
        let substitution_values = 5;
        let shift_count = 2;
        let spine = RelationShape {
            rounds: 3,
            values: 4,
        };
        let proof = WalkARegionWalkDeferredProof::new(WalkAUnionWalkDeferredProof {
            selection: relation(w_log, selection_values, 0x100),
            substitution: relation(w_log, substitution_values, 0x200),
            shifts: shifts(shift_count, w_log, 0x300),
            spine_exposure: Some(relation(spine.rounds, spine.values, 0x400)),
        });
        let shape = FixedProofShape {
            version: WALK_A_REGION_SIDECAR_VERSION,
            w_log,
            selection_values,
            substitution_values,
            shifts: shift_count,
            tail: ProofTailShape::RelationOption(Some(spine)),
        }
        .walk_deferred();
        (proof, shape)
    }

    fn merkle_fixture() -> (MerkleRegionWalkDeferredProof, DeferredMerkleProofShape) {
        let w_log = 2;
        let zero_values = 4;
        let zero_shifts = 1;
        let selection_values = 3;
        let substitution_values = 6;
        let shift_count = 2;
        let proof = MerkleRegionWalkDeferredProof::new(MerkleUnionWalkDeferredProof {
            zero: relation(w_log, zero_values, 0x500),
            zero_shifts: shifts(zero_shifts, w_log, 0x600),
            selection: relation(w_log, selection_values, 0x700),
            substitution: relation(w_log, substitution_values, 0x800),
            shifts: shifts(shift_count, w_log, 0x900),
        });
        let shape = MerkleProofShape {
            version: MERKLE_REGION_SIDECAR_VERSION,
            w_log,
            zero_values,
            zero_shifts,
            selection_values,
            substitution_values,
            shifts: shift_count,
        }
        .walk_deferred();
        (proof, shape)
    }

    fn multi_fixture(w_log: usize, instances: usize) -> MultiDeepChainWalkProof {
        MultiDeepChainWalkProof {
            layers: (0..N_ROUNDS)
                .map(|layer| MultiWalkLayerProof {
                    round_coeffs: (0..w_log)
                        .map(|round| {
                            std::array::from_fn(|coefficient| {
                                value(
                                    0xA000
                                        + (layer * w_log * WALK_DEGREE
                                            + round * WALK_DEGREE
                                            + coefficient)
                                            as u64,
                                )
                            })
                        })
                        .collect(),
                    next_values: (0..instances)
                        .map(|instance| {
                            std::array::from_fn(|lane| {
                                value(
                                    0xB000
                                        + (layer * instances * STATE_SIZE
                                            + instance * STATE_SIZE
                                            + lane)
                                            as u64,
                                )
                            })
                        })
                        .collect(),
                })
                .collect(),
        }
    }

    fn overwrite_u64(bytes: &[u8], offset: usize, value: u64) -> Vec<u8> {
        let mut malformed = bytes.to_vec();
        malformed[offset..offset + U64_BYTES].copy_from_slice(&value.to_le_bytes());
        malformed
    }

    #[test]
    fn deferred_fixed_scans_version_relations_shifts_and_both_option_tags() {
        let (proof, shape) = fixed_fixture();
        let bytes = bincode::serialize(&proof).expect("serialize deferred fixed child");
        assert_eq!(
            bytes.len(),
            deferred_fixed_proof_encoded_len(&shape).unwrap()
        );
        preflight_deferred_fixed_proof(&bytes, &shape).unwrap();
        assert_eq!(
            fixed_proof_encoded_len(&FixedProofShape {
                version: shape.version,
                w_log: shape.w_log,
                selection_values: shape.selection_values,
                substitution_values: shape.substitution_values,
                shifts: shape.shifts,
                tail: shape.tail,
            })
            .unwrap()
                - bytes.len(),
            walk_encoded_len(shape.w_log).unwrap(),
            "deferred fixed wrapper must remove exactly one walk"
        );

        let offsets = layout_offsets_deferred_fixed(&bytes, &shape).unwrap();
        assert!(
            !offsets.iter().any(|(field, _)| matches!(
                field,
                LayoutField::VecLength(VecClass::WalkLayers | VecClass::WalkLayerRounds)
            )),
            "deferred fixed layout still contains a walk"
        );
        assert!(offsets
            .iter()
            .any(|(field, _)| *field == LayoutField::OptionTag));
        let attempts = serde_attempts();
        for (field, offset) in &offsets {
            if matches!(field, LayoutField::VecLength(_)) {
                let malformed = overwrite_u64(&bytes, *offset, u64::MAX);
                assert_eq!(
                    preflight_deferred_fixed_proof(&malformed, &shape),
                    Err(RegionSidecarError::InvalidProof),
                    "forged {field:?} reached serde"
                );
            }
        }
        let option_offset = offsets
            .iter()
            .find_map(|(field, offset)| (*field == LayoutField::OptionTag).then_some(*offset))
            .unwrap();
        let mut bad_option = bytes.clone();
        bad_option[option_offset] = 2;
        assert_eq!(
            preflight_deferred_fixed_proof(&bad_option, &shape),
            Err(RegionSidecarError::InvalidProof)
        );
        let mut wrong_version = bytes.clone();
        wrong_version[0] = shape.version.wrapping_add(1);
        assert_eq!(
            preflight_deferred_fixed_proof(&wrong_version, &shape),
            Err(RegionSidecarError::UnsupportedVersion)
        );

        let no_spine = WalkARegionWalkDeferredProof::new(WalkAUnionWalkDeferredProof {
            selection: relation(shape.w_log, shape.selection_values, 0xC00),
            substitution: relation(shape.w_log, shape.substitution_values, 0xD00),
            shifts: shifts(shape.shifts, shape.w_log, 0xE00),
            spine_exposure: None,
        });
        let no_spine_shape = DeferredFixedProofShape {
            tail: ProofTailShape::RelationOption(None),
            ..shape
        };
        let no_spine_bytes = bincode::serialize(&no_spine).unwrap();
        preflight_deferred_fixed_proof(&no_spine_bytes, &no_spine_shape).unwrap();
        let no_spine_option = layout_offsets_deferred_fixed(&no_spine_bytes, &no_spine_shape)
            .unwrap()
            .into_iter()
            .find_map(|(field, offset)| (field == LayoutField::OptionTag).then_some(offset))
            .unwrap();
        let mut forged_some = no_spine_bytes;
        forged_some[no_spine_option] = 1;
        assert_eq!(
            preflight_deferred_fixed_proof(&forged_some, &no_spine_shape),
            Err(RegionSidecarError::InvalidProof)
        );
        assert_eq!(serde_attempts(), attempts);
    }

    #[test]
    fn deferred_merkle_scans_every_relation_and_shift_without_walk() {
        let (proof, shape) = merkle_fixture();
        let bytes = bincode::serialize(&proof).expect("serialize deferred Merkle child");
        assert_eq!(
            bytes.len(),
            deferred_merkle_proof_encoded_len(&shape).unwrap()
        );
        preflight_deferred_merkle_proof(&bytes, &shape).unwrap();
        assert_eq!(
            merkle_proof_encoded_len(&MerkleProofShape {
                version: shape.version,
                w_log: shape.w_log,
                zero_values: shape.zero_values,
                zero_shifts: shape.zero_shifts,
                selection_values: shape.selection_values,
                substitution_values: shape.substitution_values,
                shifts: shape.shifts,
            })
            .unwrap()
                - bytes.len(),
            walk_encoded_len(shape.w_log).unwrap(),
            "deferred Merkle wrapper must remove exactly one walk"
        );
        let offsets = layout_offsets_deferred_merkle(&bytes, &shape).unwrap();
        assert!(
            !offsets.iter().any(|(field, _)| matches!(
                field,
                LayoutField::VecLength(VecClass::WalkLayers | VecClass::WalkLayerRounds)
            )),
            "deferred Merkle layout still contains a walk"
        );
        assert!(offsets
            .iter()
            .any(|(field, _)| { *field == LayoutField::VecLength(VecClass::ZeroShiftRounds) }));
        let attempts = serde_attempts();
        for (field, offset) in &offsets {
            if matches!(field, LayoutField::VecLength(_)) {
                let malformed = overwrite_u64(&bytes, *offset, u64::MAX);
                assert_eq!(
                    preflight_deferred_merkle_proof(&malformed, &shape),
                    Err(RegionSidecarError::InvalidProof),
                    "forged {field:?} reached serde"
                );
            }
        }
        assert_eq!(serde_attempts(), attempts);
    }

    #[test]
    fn multi_walk_scans_all_nested_lengths_and_exact_encoded_size() {
        let w_log = 3;
        let instances = 2;
        let proof = multi_fixture(w_log, instances);
        let bytes = bincode::serialize(&proof).expect("serialize multi walk");
        let shape = multi_walk_proof_shape(w_log, instances).unwrap();
        let layer_len = U64_BYTES
            + w_log * WALK_DEGREE * F128_BYTES
            + U64_BYTES
            + instances * STATE_SIZE * F128_BYTES;
        assert_eq!(bytes.len(), U64_BYTES + N_ROUNDS * layer_len);
        assert_eq!(bytes.len(), multi_walk_proof_encoded_len(&shape).unwrap());
        preflight_multi_walk_proof(&bytes, &shape).unwrap();

        let offsets = layout_offsets_multi_walk(&bytes, &shape).unwrap();
        assert_eq!(
            offsets
                .iter()
                .filter(|(field, _)| {
                    *field == LayoutField::VecLength(VecClass::MultiWalkLayers)
                })
                .count(),
            1
        );
        assert_eq!(
            offsets
                .iter()
                .filter(|(field, _)| {
                    *field == LayoutField::VecLength(VecClass::MultiWalkLayerRounds)
                })
                .count(),
            N_ROUNDS
        );
        assert_eq!(
            offsets
                .iter()
                .filter(|(field, _)| {
                    *field == LayoutField::VecLength(VecClass::MultiWalkNextInstances)
                })
                .count(),
            N_ROUNDS
        );

        let attempts = serde_attempts();
        for (field, offset) in &offsets {
            let LayoutField::VecLength(_) = field else {
                continue;
            };
            let malformed = overwrite_u64(&bytes, *offset, u64::MAX);
            assert_eq!(
                preflight_multi_walk_proof(&malformed, &shape),
                Err(RegionSidecarError::InvalidProof),
                "forged {field:?} reached serde"
            );
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert_eq!(
            preflight_multi_walk_proof(&trailing, &shape),
            Err(RegionSidecarError::InvalidProof)
        );
        assert_eq!(
            preflight_multi_walk_proof(&bytes[..bytes.len() - 1], &shape),
            Err(RegionSidecarError::InvalidProof)
        );
        assert_eq!(
            preflight_multi_walk_proof(
                &bytes,
                &multi_walk_proof_shape(w_log, instances + 1).unwrap()
            ),
            Err(RegionSidecarError::InvalidProof)
        );
        assert_eq!(
            multi_walk_proof_shape(w_log, 0),
            Err(RegionSidecarError::InvalidProof)
        );
        assert_eq!(
            multi_walk_proof_encoded_len(&MultiWalkProofShape {
                w_log: usize::MAX,
                instances,
            }),
            Err(RegionSidecarError::InvalidProof)
        );
        assert_eq!(serde_attempts(), attempts);
    }

    #[test]
    fn composite_accepts_versioned_deferred_children_then_multi_walk() {
        let outer_version = 9;
        let (fixed, fixed_shape) = fixed_fixture();
        let (merkle, merkle_shape) = merkle_fixture();
        let multi = multi_fixture(2, 2);
        let multi_shape = multi_walk_proof_shape(2, 2).unwrap();
        // Bincode tuples and structs both serialize fields without tags; this
        // is the proposed outer order: version, child wrappers, shared walk.
        let bytes = bincode::serialize(&(outer_version, fixed, merkle, multi)).unwrap();
        let parts = [
            SidecarProofShape::DeferredFixed(fixed_shape),
            SidecarProofShape::DeferredMerkle(merkle_shape),
            SidecarProofShape::MultiWalk(multi_shape),
        ];
        preflight_composite_proof(&bytes, outer_version, &parts).unwrap();
        let expected = parts.iter().try_fold(1usize, |length, part| {
            checked_add(length, sidecar_proof_encoded_len(part)?)
        });
        assert_eq!(Ok(bytes.len()), expected);

        let offsets = composite_layout_offsets(&bytes, outer_version, &parts).unwrap();
        assert_eq!(
            offsets
                .iter()
                .filter(|(field, _)| *field == LayoutField::Version)
                .count(),
            3,
            "outer plus two child-wrapper versions"
        );
        assert!(offsets.iter().any(|(field, _)| {
            *field == LayoutField::VecLength(VecClass::MultiWalkNextInstances)
        }));
        let attempts = serde_attempts();
        for (field, offset) in offsets {
            if matches!(field, LayoutField::VecLength(_)) {
                let malformed = overwrite_u64(&bytes, offset, u64::MAX);
                assert_eq!(
                    preflight_composite_proof(&malformed, outer_version, &parts),
                    Err(RegionSidecarError::InvalidProof),
                    "composite forged {field:?} reached serde"
                );
            }
        }
        assert_eq!(serde_attempts(), attempts);
    }
}
