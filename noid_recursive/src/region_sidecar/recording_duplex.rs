// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Post-commit authority for a RECORDINGS-ONLY duplex union: committed
//! Fiat-Shamir transcript regions whose Poseidon chain is proven by the
//! enclosing multi-instance deep-chain walk instead of inline sponge
//! permutations.
//!
//! Every block of the union is one recorded child transcript (a compiled
//! [`DuplexLayout`] over the union-recorder capacity IV), gated to its own
//! dyadic offset. A V5 selected instance carries the authenticated parent
//! arm's block-sidecar child and `[R]_prev` transcript. The other arm remains
//! in the class-fixed layout table, so one verification key covers both
//! parent classes without adding another committed recording region.
//! The serialized child authority reuses the duplex
//! walk-deferred wire shape byte-for-byte: recordings change relation TERMS
//! (per-set gated wiring), never the claimed-column set, so selection /
//! substitution / shift dimensions equal the recording-free duplex child.

use noid_ivc_core::challenger::Challenger;
use noid_ivc_core::deep_chain::c1::C1LaneClaimGroup;
use noid_ivc_core::deep_chain::relations::{claimed_refs, ColRef, FixedPattern};
use noid_ivc_core::deep_chain::schedule::{
    carry_selection_terms, duplex_family_refs, duplex_fixed_patterns, DuplexFamilyRefs,
    DuplexLayout,
};
use noid_ivc_core::deep_chain::LaneClaimGroup;
use noid_ivc_core::field::{F128, F256};
use noid_ivc_core::field_circuit::{FsChannelOps, FsChannelUnionRecorder};
use noid_ivc_core::pcs::{C1QuirkyDirectClaim, QuirkyDirectClaim};
use noid_ivc_core::public_io::WitnessSlice;
use noid_poseidon2b::native::permutation::STATE_SIZE;
use noid_poseidon2b::native::poseidon2b_hash_byte_slices;

use crate::acceptance::trace::deep_chain::{
    verify_column_relation_trace, verify_shift_discharge_trace, ColumnRelationProofTrace,
    LaneClaimGroupTrace, ShiftDischargeProofTrace,
};
use crate::acceptance::trace::region_source_binding::{
    duplex_sub_terms_trace_multi, duplex_sub_terms_trace_selected,
    duplex_substitution_terms_selected, duplex_substitution_terms_sets,
    prove_duplex_union_walk_prefix_with_challenger,
    prove_duplex_union_walk_suffix_selected_with_challenger,
    prove_duplex_union_walk_suffix_with_challenger, rec_hi_bits,
    verify_duplex_union_walk_prefix_with_challenger,
    verify_duplex_union_walk_suffix_selected_with_challenger,
    verify_duplex_union_walk_suffix_with_challenger, DuplexColumnClaim,
    DuplexUnionProverWalkPrefix, DuplexUnionVerifierWalkPrefix, DuplexUnionWalkDeferredProof,
};
use crate::acceptance::trace::region_source_binding_c1::{
    prove_c1_duplex_walk_prefix, prove_c1_duplex_walk_suffix, prove_c1_duplex_walk_suffix_selected,
    verify_c1_duplex_walk_prefix, verify_c1_duplex_walk_suffix,
    verify_c1_duplex_walk_suffix_selected, C1DuplexColumnClaim, C1DuplexProverWalkPrefix,
    C1DuplexUnionWalkDeferredProof, C1DuplexVerifierWalkPrefix,
};
use crate::acceptance::trace::self_verify::{FieldPostCommitTraceContext, QuirkyDirectClaimTrace};
use crate::acceptance::trace::{mul, FieldR1csBuilder, LinExpr};

use super::trace::{
    preflight_duplex_deferred_authority, verify_duplex_union_walk_prefix_trace,
    DuplexColumnClaimTrace, DuplexUnionTraceWalkPrefix,
};
use super::{
    duplex_layout_digest, push_usize, RegionSidecarError, RegionWalkEndpoints,
    DUPLEX_REGION_COMMITTED_COLUMNS, DUPLEX_REGION_SIDECAR_VERSION,
};

const RECORDING_DUPLEX_LAYOUT_DIGEST_DOMAIN: &[u8] =
    b"NOID/REGION-SIDECAR/RECORDING-DUPLEX-LAYOUT/V3";
const RECORDING_DUPLEX_VK_DIGEST_DOMAIN: &[u8] = b"NOID/REGION-SIDECAR/RECORDING-DUPLEX-VK/V3";
pub(crate) const RECORDING_DUPLEX_SIDECAR_TRANSCRIPT_LABEL: &[u8] =
    b"history-region-sidecar-recording-duplex-v3";
const RECORDING_DUPLEX_SELECTOR_TRANSCRIPT_LABEL: &[u8] =
    b"history-region-sidecar-recording-selector-v1";
const DUPLEX_PATTERNS_PER_SET: usize = 7;
/// Four fixed-pattern chunks per selected role. One split gave less m24
/// headroom; sixteen chunks made native rec-C substantially slower. Four is
/// the measured row/performance point frozen into the V5 verification key.
const SELECTED_RECORDING_CHUNK_LOG_REDUCTION: usize = 2;

#[derive(Clone, Debug, PartialEq, Eq)]
struct SelectedRecordingLayouts {
    selector_slice: WitnessSlice,
    /// Two alternatives with the same role count and dyadic role geometry.
    /// A selector of zero chooses arm 0; one chooses arm 1.
    arms: [Vec<(DuplexLayout, usize)>; 2],
}

/// Canonical verification key for one recordings-only duplex vertical.
///
/// The per-block layouts are protocol constants (derived by replaying the
/// enclosing verifier's transcript schedule against a shape-only proof), so
/// the fixed tables, refs and packing are all recomputed and validated from
/// the stored blocks — no caller-supplied pattern table is trusted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordingDuplexRegionVk {
    purpose: [u8; 32],
    w_log: usize,
    slices: [WitnessSlice; DUPLEX_REGION_COMMITTED_COLUMNS],
    /// Per recording block, in CALLER (protocol) order: compiled child
    /// layout and its dyadic offset inside the union domain.
    blocks: Vec<(DuplexLayout, usize)>,
    selected: Option<SelectedRecordingLayouts>,
    fixed: Vec<FixedPattern>,
    refs: DuplexFamilyRefs,
    rec_refs: Vec<DuplexFamilyRefs>,
    layout_digest: [u8; 32],
}

impl RecordingDuplexRegionVk {
    #[cfg(test)]
    pub(crate) fn new(
        purpose: [u8; 32],
        w_log: usize,
        slices: [WitnessSlice; DUPLEX_REGION_COMMITTED_COLUMNS],
        blocks: Vec<(DuplexLayout, usize)>,
    ) -> Result<Self, RegionSidecarError> {
        let (fixed, refs, rec_refs) = canonical_recording_fixed(w_log, &blocks)?;
        let layout_digest = recording_layout_digest(w_log, &blocks, None);
        let vk = Self {
            purpose,
            w_log,
            slices,
            blocks,
            selected: None,
            fixed,
            refs,
            rec_refs,
            layout_digest,
        };
        vk.validate_structure()?;
        Ok(vk)
    }

    /// One fixed key for two recording-layout alternatives.  Corresponding
    /// roles share their dyadic offset and block size; the fixed bank stores
    /// arm 0 plus the characteristic-two arm delta.
    pub(crate) fn new_selected(
        purpose: [u8; 32],
        w_log: usize,
        slices: [WitnessSlice; DUPLEX_REGION_COMMITTED_COLUMNS],
        selector_slice: WitnessSlice,
        arms: [Vec<(DuplexLayout, usize)>; 2],
    ) -> Result<Self, RegionSidecarError> {
        let selected = SelectedRecordingLayouts {
            selector_slice,
            arms,
        };
        let (fixed, refs, rec_refs) = canonical_selected_recording_fixed(w_log, &selected)?;
        let layout_digest = recording_layout_digest(w_log, &[], Some(&selected));
        let vk = Self {
            purpose,
            w_log,
            slices,
            blocks: Vec::new(),
            selected: Some(selected),
            fixed,
            refs,
            rec_refs,
            layout_digest,
        };
        vk.validate_structure()?;
        Ok(vk)
    }

    pub fn purpose(&self) -> &[u8; 32] {
        &self.purpose
    }

    pub fn w_log(&self) -> usize {
        self.w_log
    }

    pub fn slices(&self) -> &[WitnessSlice; DUPLEX_REGION_COMMITTED_COLUMNS] {
        &self.slices
    }

    pub(crate) fn selected_block(&self, arm: usize, role: usize) -> Option<&(DuplexLayout, usize)> {
        self.selected.as_ref()?.arms.get(arm)?.get(role)
    }

    fn selector_slice(&self) -> Option<WitnessSlice> {
        self.selected
            .as_ref()
            .map(|selected| selected.selector_slice)
    }

    fn is_selected(&self) -> bool {
        self.selected.is_some()
    }

    pub fn layout_digest(&self) -> &[u8; 32] {
        &self.layout_digest
    }

    pub fn transcript_digest(&self) -> [u8; 32] {
        let mut bytes = Vec::new();
        bytes.push(DUPLEX_REGION_SIDECAR_VERSION);
        bytes.extend_from_slice(&self.purpose);
        push_usize(&mut bytes, self.w_log);
        for slice in self.slices {
            push_usize(&mut bytes, slice.log2_len);
            push_usize(&mut bytes, slice.index);
        }
        bytes.extend_from_slice(&self.layout_digest);
        poseidon2b_hash_byte_slices(RECORDING_DUPLEX_VK_DIGEST_DOMAIN, &[&bytes])
    }

    fn validate_structure(&self) -> Result<(), RegionSidecarError> {
        if self.w_log == 0
            || self.w_log >= usize::BITS as usize
            || (self.blocks.is_empty() && self.selected.is_none())
            || (!self.blocks.is_empty() && self.selected.is_some())
            || self
                .selected
                .as_ref()
                .is_some_and(|selected| selected.selector_slice.log2_len != 0)
        {
            return Err(RegionSidecarError::BadVk);
        }
        let (fixed, refs, rec_refs) = if let Some(selected) = &self.selected {
            canonical_selected_recording_fixed(self.w_log, selected)?
        } else {
            canonical_recording_fixed(self.w_log, &self.blocks)?
        };
        if self.fixed != fixed
            || self.refs != refs
            || self.rec_refs != rec_refs
            || self.layout_digest
                != recording_layout_digest(self.w_log, &self.blocks, self.selected.as_ref())
        {
            return Err(RegionSidecarError::UnsupportedVkShape);
        }
        let base = self.slices[0].index;
        for (column, slice) in self.slices.into_iter().enumerate() {
            if slice.log2_len != self.w_log {
                return Err(RegionSidecarError::BadSlice);
            }
            if slice.index
                != base
                    .checked_add(column)
                    .ok_or(RegionSidecarError::BadSlice)?
            {
                return Err(RegionSidecarError::BadSlice);
            }
        }
        Ok(())
    }

    fn validate_in_witness(&self, total_vars: usize) -> Result<(), RegionSidecarError> {
        self.validate_structure()?;
        if self.slices.iter().any(|slice| !slice.fits(total_vars)) {
            return Err(RegionSidecarError::BadSlice);
        }
        if self
            .selector_slice()
            .is_some_and(|slice| slice.log2_len != 0 || !slice.fits(total_vars))
        {
            return Err(RegionSidecarError::BadSlice);
        }
        Ok(())
    }

    /// Per-proof witness gate for a recording VK already authenticated by
    /// `new` or `new_selected`. The expensive fixed-bank reconstruction is a
    /// constructor obligation, not adversarial proof work.
    fn validate_certified_c1_in_witness(
        &self,
        total_vars: usize,
    ) -> Result<(), RegionSidecarError> {
        if self.slices.iter().any(|slice| !slice.fits(total_vars)) {
            return Err(RegionSidecarError::BadSlice);
        }
        if self
            .selector_slice()
            .is_some_and(|slice| slice.log2_len != 0 || !slice.fits(total_vars))
        {
            return Err(RegionSidecarError::BadSlice);
        }
        Ok(())
    }

    fn substitution_terms(
        &self,
        selector: F128,
        alpha: F128,
    ) -> Vec<noid_ivc_core::deep_chain::relations::RelationTerm> {
        if self.is_selected() {
            duplex_substitution_terms_selected(&recording_ref_sets(self), selector, alpha)
        } else {
            duplex_substitution_terms_sets(&self.refs, &self.rec_refs, alpha)
        }
    }
}

/// Recompute the canonical gated pattern sets and ref sets of the block
/// list.  Every block must be self-aligned, non-overlapping, in-domain and
/// gated (no block may swallow the whole multi-block domain).
fn canonical_recording_fixed(
    w_log: usize,
    blocks: &[(DuplexLayout, usize)],
) -> Result<(Vec<FixedPattern>, DuplexFamilyRefs, Vec<DuplexFamilyRefs>), RegionSidecarError> {
    if blocks.is_empty() || w_log >= usize::BITS as usize {
        return Err(RegionSidecarError::BadVk);
    }
    let domain = 1usize
        .checked_shl(w_log as u32)
        .ok_or(RegionSidecarError::BadVk)?;
    let iv = FsChannelUnionRecorder::capacity_iv_flat_c1();
    let mut fixed = Vec::with_capacity(blocks.len() * DUPLEX_PATTERNS_PER_SET);
    let mut set_refs = Vec::with_capacity(blocks.len());
    let mut ranges: Vec<(usize, usize)> = Vec::with_capacity(blocks.len());
    for (layout, offset) in blocks {
        let size = layout
            .slots
            .len()
            .max(1)
            .checked_next_power_of_two()
            .ok_or(RegionSidecarError::BadVk)?;
        let s_log = size.trailing_zeros() as usize;
        let end = offset.checked_add(size).ok_or(RegionSidecarError::BadVk)?;
        if *offset % size != 0 || end > domain || (blocks.len() > 1 && size >= domain) {
            return Err(RegionSidecarError::UnsupportedVkShape);
        }
        ranges.push((*offset, end));
        let base = fixed.len();
        for pattern in duplex_fixed_patterns(layout, iv, s_log) {
            if s_log == w_log {
                fixed.push(pattern);
            } else {
                fixed.push(pattern.gated(s_log, rec_hi_bits(*offset, s_log, w_log)));
            }
        }
        set_refs.push(duplex_family_refs(0, base));
    }
    for (index, left) in ranges.iter().enumerate() {
        for right in &ranges[index + 1..] {
            if left.0 < right.1 && right.0 < left.1 {
                return Err(RegionSidecarError::UnsupportedVkShape);
            }
        }
    }
    let refs = set_refs[0];
    let rec_refs = set_refs[1..].to_vec();
    Ok((fixed, refs, rec_refs))
}

fn selected_recording_chunk_patterns(
    w_log: usize,
    layout: &DuplexLayout,
    offset: usize,
) -> Result<Vec<Vec<FixedPattern>>, RegionSidecarError> {
    let domain = 1usize
        .checked_shl(w_log as u32)
        .ok_or(RegionSidecarError::BadVk)?;
    let size = layout
        .slots
        .len()
        .max(1)
        .checked_next_power_of_two()
        .ok_or(RegionSidecarError::BadVk)?;
    let s_log = size.trailing_zeros() as usize;
    let end = offset.checked_add(size).ok_or(RegionSidecarError::BadVk)?;
    if offset % size != 0 || end > domain || s_log < SELECTED_RECORDING_CHUNK_LOG_REDUCTION {
        return Err(RegionSidecarError::UnsupportedVkShape);
    }
    let iv = FsChannelUnionRecorder::capacity_iv_flat_c1();
    let full = duplex_fixed_patterns(layout, iv, s_log);
    let chunk_log = s_log - SELECTED_RECORDING_CHUNK_LOG_REDUCTION;
    let chunk_size = 1usize << chunk_log;
    let chunk_count = 1usize << SELECTED_RECORDING_CHUNK_LOG_REDUCTION;
    Ok((0..chunk_count)
        .map(|chunk| {
            let chunk_offset = offset + chunk * chunk_size;
            full.iter()
                .map(|pattern| {
                    let table =
                        pattern.table[chunk * chunk_size..(chunk + 1) * chunk_size].to_vec();
                    FixedPattern::new(chunk_log, table)
                        .gated(chunk_log, rec_hi_bits(chunk_offset, chunk_log, w_log))
                })
                .collect()
        })
        .collect())
}

fn add_fixed_patterns(
    left: &FixedPattern,
    right: &FixedPattern,
) -> Result<FixedPattern, RegionSidecarError> {
    if left.low_log != right.low_log
        || left.hi_gate != right.hi_gate
        || left.table.len() != right.table.len()
    {
        return Err(RegionSidecarError::UnsupportedVkShape);
    }
    Ok(FixedPattern {
        low_log: left.low_log,
        table: left
            .table
            .iter()
            .zip(&right.table)
            .map(|(left, right)| *left + *right)
            .collect(),
        hi_gate: left.hi_gate.clone(),
    })
}

fn canonical_selected_recording_fixed(
    w_log: usize,
    selected: &SelectedRecordingLayouts,
) -> Result<(Vec<FixedPattern>, DuplexFamilyRefs, Vec<DuplexFamilyRefs>), RegionSidecarError> {
    let role_count = selected.arms[0].len();
    if role_count == 0 || selected.arms[1].len() != role_count {
        return Err(RegionSidecarError::BadVk);
    }
    let chunk_count = 1usize << SELECTED_RECORDING_CHUNK_LOG_REDUCTION;
    let mut fixed = Vec::with_capacity(role_count * chunk_count * 2 * DUPLEX_PATTERNS_PER_SET);
    let mut set_refs = Vec::with_capacity(role_count * chunk_count * 2);
    for role in 0..role_count {
        let (base_layout, base_offset) = &selected.arms[0][role];
        let (alternative_layout, alternative_offset) = &selected.arms[1][role];
        let base_size = base_layout.slots.len().max(1).next_power_of_two();
        let alternative_size = alternative_layout.slots.len().max(1).next_power_of_two();
        if base_offset != alternative_offset || base_size != alternative_size {
            return Err(RegionSidecarError::UnsupportedVkShape);
        }
        let base_chunks = selected_recording_chunk_patterns(w_log, base_layout, *base_offset)?;
        let alternative_chunks =
            selected_recording_chunk_patterns(w_log, alternative_layout, *alternative_offset)?;
        if base_chunks.len() != chunk_count || alternative_chunks.len() != chunk_count {
            return Err(RegionSidecarError::UnsupportedVkShape);
        }
        for (base_patterns, alternative_patterns) in base_chunks.iter().zip(&alternative_chunks) {
            if base_patterns.len() != DUPLEX_PATTERNS_PER_SET
                || alternative_patterns.len() != DUPLEX_PATTERNS_PER_SET
            {
                return Err(RegionSidecarError::UnsupportedVkShape);
            }
            let base = fixed.len();
            fixed.extend(base_patterns.iter().cloned());
            set_refs.push(duplex_family_refs(0, base));
            let delta = fixed.len();
            fixed.extend(
                base_patterns
                    .iter()
                    .zip(alternative_patterns)
                    .map(|(left, right)| add_fixed_patterns(left, right))
                    .collect::<Result<Vec<_>, _>>()?,
            );
            set_refs.push(duplex_family_refs(0, delta));
        }
    }

    // Each arm must itself be a valid non-overlapping recording packing.
    for arm in &selected.arms {
        let mut ranges = Vec::with_capacity(role_count);
        for (layout, offset) in arm {
            let size = layout.slots.len().max(1).next_power_of_two();
            ranges.push((*offset, offset + size));
        }
        for (index, left) in ranges.iter().enumerate() {
            for right in &ranges[index + 1..] {
                if left.0 < right.1 && right.0 < left.1 {
                    return Err(RegionSidecarError::UnsupportedVkShape);
                }
            }
        }
    }
    let refs = set_refs[0];
    Ok((fixed, refs, set_refs[1..].to_vec()))
}

/// Stable digest over the complete recording packing.
fn recording_layout_digest(
    w_log: usize,
    blocks: &[(DuplexLayout, usize)],
    selected: Option<&SelectedRecordingLayouts>,
) -> [u8; 32] {
    let mut bytes = Vec::new();
    bytes.push(DUPLEX_REGION_SIDECAR_VERSION);
    push_usize(&mut bytes, w_log);
    if let Some(selected) = selected {
        bytes.push(1);
        push_usize(&mut bytes, selected.selector_slice.log2_len);
        push_usize(&mut bytes, selected.selector_slice.index);
        push_usize(&mut bytes, selected.arms[0].len());
        for arm in &selected.arms {
            for (layout, offset) in arm {
                push_usize(&mut bytes, *offset);
                bytes.extend_from_slice(&duplex_layout_digest(layout));
            }
        }
    } else {
        bytes.push(0);
        push_usize(&mut bytes, blocks.len());
        for (layout, offset) in blocks {
            push_usize(&mut bytes, *offset);
            bytes.extend_from_slice(&duplex_layout_digest(layout));
        }
    }
    poseidon2b_hash_byte_slices(RECORDING_DUPLEX_LAYOUT_DIGEST_DOMAIN, &[&bytes])
}

fn recording_ref_sets(vk: &RecordingDuplexRegionVk) -> Vec<DuplexFamilyRefs> {
    let mut sets = vec![vk.refs];
    sets.extend_from_slice(&vk.rec_refs);
    sets
}

fn bind_recording_vk<Ch: Challenger>(challenger: &mut Ch, vk: &RecordingDuplexRegionVk) {
    challenger.observe_label(RECORDING_DUPLEX_SIDECAR_TRANSCRIPT_LABEL);
    challenger.observe_bytes(&vk.transcript_digest());
}

fn bind_recording_selector<Ch: Challenger>(challenger: &mut Ch, selector: F128) {
    challenger.observe_label(RECORDING_DUPLEX_SELECTOR_TRANSCRIPT_LABEL);
    challenger.observe_f128(selector);
}

fn resolve_recording_terminal_claims(
    vk: &RecordingDuplexRegionVk,
    total_vars: usize,
    selector: F128,
    terminal: Vec<DuplexColumnClaim>,
) -> Result<Vec<QuirkyDirectClaim>, RegionSidecarError> {
    let mut claims = Vec::with_capacity(terminal.len() + usize::from(vk.is_selected()));
    for claim in terminal {
        let slice = *vk
            .slices
            .get(claim.column)
            .ok_or(RegionSidecarError::InvalidProof)?;
        if claim.point.len() != slice.log2_len {
            return Err(RegionSidecarError::InvalidProof);
        }
        let mut x_rest = claim.point;
        x_rest.extend(slice.prefix_coords(total_vars));
        claims.push(QuirkyDirectClaim {
            z_skip: F128::ZERO,
            k_skip: 0,
            x_rest,
            value: claim.value,
        });
    }
    if let Some(slice) = vk.selector_slice() {
        claims.push(QuirkyDirectClaim {
            z_skip: F128::ZERO,
            k_skip: 0,
            x_rest: slice.prefix_coords(total_vars),
            value: selector,
        });
    }
    Ok(claims)
}

fn resolve_c1_recording_terminal_claims(
    vk: &RecordingDuplexRegionVk,
    total_vars: usize,
    selector: F128,
    terminal: Vec<C1DuplexColumnClaim>,
) -> Result<Vec<C1QuirkyDirectClaim>, RegionSidecarError> {
    let mut claims = Vec::with_capacity(terminal.len() + usize::from(vk.is_selected()));
    for claim in terminal {
        let slice = *vk
            .slices
            .get(claim.column)
            .ok_or(RegionSidecarError::InvalidProof)?;
        if claim.point.len() != slice.log2_len {
            return Err(RegionSidecarError::InvalidProof);
        }
        let mut x_rest = claim.point;
        x_rest.extend(
            slice
                .prefix_coords(total_vars)
                .into_iter()
                .map(F256::from_base),
        );
        claims.push(C1QuirkyDirectClaim {
            z_skip: F256::ZERO,
            k_skip: 0,
            x_rest,
            value: claim.value,
        });
    }
    if let Some(slice) = vk.selector_slice() {
        claims.push(C1QuirkyDirectClaim {
            z_skip: F256::ZERO,
            k_skip: 0,
            x_rest: slice
                .prefix_coords(total_vars)
                .into_iter()
                .map(F256::from_base)
                .collect(),
            value: F256::from_base(selector),
        });
    }
    Ok(claims)
}

/// Recording authority plus the arm selector that chooses its fixed-layout
/// bank.  The selector is transcript-bound and independently discharged as a
/// one-cell opening of the enclosing Field witness.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct RecordingDuplexRegionWalkDeferredProof {
    selector: F128,
    authority: super::DuplexRegionWalkDeferredProof,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct C1RecordingDuplexRegionWalkDeferredProof {
    selector: F128,
    version: u8,
    authority: C1DuplexUnionWalkDeferredProof,
}

impl RecordingDuplexRegionWalkDeferredProof {
    pub(crate) fn new(selector: F128, authority: DuplexUnionWalkDeferredProof) -> Self {
        Self {
            selector,
            authority: super::DuplexRegionWalkDeferredProof::new(authority),
        }
    }

    pub(crate) fn selector(&self) -> F128 {
        self.selector
    }

    pub(crate) fn version(&self) -> u8 {
        self.authority.version()
    }

    pub(crate) fn authority(&self) -> &DuplexUnionWalkDeferredProof {
        self.authority.authority()
    }
}

impl C1RecordingDuplexRegionWalkDeferredProof {
    pub(crate) fn new(selector: F128, authority: C1DuplexUnionWalkDeferredProof) -> Self {
        Self {
            selector,
            version: DUPLEX_REGION_SIDECAR_VERSION,
            authority,
        }
    }

    pub(crate) fn selector(&self) -> F128 {
        self.selector
    }

    pub(crate) fn version(&self) -> u8 {
        self.version
    }

    pub(crate) fn authority(&self) -> &C1DuplexUnionWalkDeferredProof {
        &self.authority
    }
}

// ---------------------------------------------------------------------------
// Prover
// ---------------------------------------------------------------------------

pub struct RecordingDuplexRegionProverPlan<'a> {
    vk: &'a RecordingDuplexRegionVk,
    s0: &'a [Vec<F128>; STATE_SIZE],
    s_out: &'a [Vec<F128>; STATE_SIZE],
}

pub(crate) struct RecordingDuplexProverWalkContinuation<'a, 'z> {
    vk: &'a RecordingDuplexRegionVk,
    total_vars: usize,
    committed: [&'z [F128]; DUPLEX_REGION_COMMITTED_COLUMNS],
    s0: &'a [Vec<F128>; STATE_SIZE],
    selector: F128,
    prefix: DuplexUnionProverWalkPrefix,
}

impl RecordingDuplexProverWalkContinuation<'_, '_> {
    pub(crate) fn group(&self) -> &LaneClaimGroup {
        self.prefix.walk_group()
    }

    pub(crate) fn s0(&self) -> &[Vec<F128>; STATE_SIZE] {
        self.s0
    }

    pub(crate) fn finish<Ch: Challenger>(
        self,
        terminal: &LaneClaimGroup,
        challenger: &mut Ch,
    ) -> Result<
        (
            RecordingDuplexRegionWalkDeferredProof,
            Vec<QuirkyDirectClaim>,
        ),
        RegionSidecarError,
    > {
        let (authority, terminal_claims) = if self.vk.is_selected() {
            prove_duplex_union_walk_suffix_selected_with_challenger(
                self.vk.w_log,
                &self.vk.fixed,
                &recording_ref_sets(self.vk),
                self.selector,
                &self.committed,
                self.prefix,
                terminal,
                challenger,
            )
        } else {
            prove_duplex_union_walk_suffix_with_challenger(
                self.vk.w_log,
                &self.vk.fixed,
                &self.vk.refs,
                &self.vk.rec_refs,
                &self.committed,
                self.prefix,
                terminal,
                challenger,
            )
        };
        let claims = resolve_recording_terminal_claims(
            self.vk,
            self.total_vars,
            self.selector,
            terminal_claims,
        )?;
        Ok((
            RecordingDuplexRegionWalkDeferredProof::new(self.selector, authority),
            claims,
        ))
    }
}

pub(crate) struct C1RecordingDuplexProverWalkContinuation<'a, 'z> {
    vk: &'a RecordingDuplexRegionVk,
    total_vars: usize,
    committed: [&'z [F128]; DUPLEX_REGION_COMMITTED_COLUMNS],
    s0: &'a [Vec<F128>; STATE_SIZE],
    selector: F128,
    prefix: C1DuplexProverWalkPrefix,
}

impl C1RecordingDuplexProverWalkContinuation<'_, '_> {
    pub(crate) fn group(&self) -> &C1LaneClaimGroup {
        self.prefix.walk_group()
    }

    pub(crate) fn s0(&self) -> &[Vec<F128>; STATE_SIZE] {
        self.s0
    }

    pub(crate) fn finish<Ch: Challenger>(
        self,
        terminal: &C1LaneClaimGroup,
        challenger: &mut Ch,
    ) -> Result<
        (
            C1RecordingDuplexRegionWalkDeferredProof,
            Vec<C1QuirkyDirectClaim>,
        ),
        RegionSidecarError,
    > {
        let (authority, terminal_claims) = if self.vk.is_selected() {
            prove_c1_duplex_walk_suffix_selected(
                self.vk.w_log,
                &self.vk.fixed,
                &recording_ref_sets(self.vk),
                self.selector,
                &self.committed,
                self.prefix,
                terminal,
                challenger,
            )
        } else {
            prove_c1_duplex_walk_suffix(
                self.vk.w_log,
                &self.vk.fixed,
                &self.vk.refs,
                &self.vk.rec_refs,
                &self.committed,
                self.prefix,
                terminal,
                challenger,
            )
        };
        let claims = resolve_c1_recording_terminal_claims(
            self.vk,
            self.total_vars,
            self.selector,
            terminal_claims,
        )?;
        Ok((
            C1RecordingDuplexRegionWalkDeferredProof::new(self.selector, authority),
            claims,
        ))
    }
}

impl<'a> RecordingDuplexRegionProverPlan<'a> {
    pub fn new(
        vk: &'a RecordingDuplexRegionVk,
        s0: &'a [Vec<F128>; STATE_SIZE],
        s_out: &'a [Vec<F128>; STATE_SIZE],
    ) -> Result<Self, RegionSidecarError> {
        vk.validate_structure()?;
        let expected = 1usize << vk.w_log;
        if s0.iter().any(|column| column.len() != expected)
            || s_out.iter().any(|column| column.len() != expected)
        {
            return Err(RegionSidecarError::BadWalkColumns);
        }
        Ok(Self { vk, s0, s_out })
    }

    pub(crate) fn prove_walk_deferred_prefix<'z, Ch: Challenger>(
        &self,
        z: &'z [F128],
        challenger: &mut Ch,
    ) -> Result<RecordingDuplexProverWalkContinuation<'a, 'z>, RegionSidecarError> {
        if z.is_empty() || !z.len().is_power_of_two() {
            return Err(RegionSidecarError::WitnessShape);
        }
        let total_vars = z.len().trailing_zeros() as usize;
        self.vk.validate_in_witness(total_vars)?;
        let committed: [&[F128]; DUPLEX_REGION_COMMITTED_COLUMNS] = std::array::from_fn(|column| {
            let slice = self.vk.slices[column];
            &z[slice.start()..slice.start() + slice.len()]
        });
        let selector = if let Some(slice) = self.vk.selector_slice() {
            z[slice.start()]
        } else {
            F128::ZERO
        };
        if selector != F128::ZERO && selector != F128::ONE {
            return Err(RegionSidecarError::InvalidProof);
        }
        bind_recording_vk(challenger, self.vk);
        bind_recording_selector(challenger, selector);
        let prefix = prove_duplex_union_walk_prefix_with_challenger(
            self.vk.w_log,
            &self.vk.fixed,
            &self.vk.refs,
            &committed,
            self.s_out,
            challenger,
        );
        Ok(RecordingDuplexProverWalkContinuation {
            vk: self.vk,
            total_vars,
            committed,
            s0: self.s0,
            selector,
            prefix,
        })
    }

    pub(crate) fn prove_c1_walk_deferred_prefix<'z, Ch: Challenger>(
        &self,
        z: &'z [F128],
        challenger: &mut Ch,
    ) -> Result<C1RecordingDuplexProverWalkContinuation<'a, 'z>, RegionSidecarError> {
        if z.is_empty() || !z.len().is_power_of_two() {
            return Err(RegionSidecarError::WitnessShape);
        }
        let total_vars = z.len().trailing_zeros() as usize;
        self.vk.validate_in_witness(total_vars)?;
        let committed: [&[F128]; DUPLEX_REGION_COMMITTED_COLUMNS] = std::array::from_fn(|column| {
            let slice = self.vk.slices[column];
            &z[slice.start()..slice.start() + slice.len()]
        });
        let selector = if let Some(slice) = self.vk.selector_slice() {
            z[slice.start()]
        } else {
            F128::ZERO
        };
        if selector != F128::ZERO && selector != F128::ONE {
            return Err(RegionSidecarError::InvalidProof);
        }
        bind_recording_vk(challenger, self.vk);
        bind_recording_selector(challenger, selector);
        let prefix = prove_c1_duplex_walk_prefix(
            self.vk.w_log,
            &self.vk.fixed,
            &self.vk.refs,
            &committed,
            self.s_out,
            challenger,
        );
        Ok(C1RecordingDuplexProverWalkContinuation {
            vk: self.vk,
            total_vars,
            committed,
            s0: self.s0,
            selector,
            prefix,
        })
    }
}

// ---------------------------------------------------------------------------
// Native verifier
// ---------------------------------------------------------------------------

pub(crate) struct RecordingDuplexVerifierWalkContinuation<'a> {
    vk: &'a RecordingDuplexRegionVk,
    total_vars: usize,
    selector: F128,
    prefix: DuplexUnionVerifierWalkPrefix<'a>,
}

impl RecordingDuplexVerifierWalkContinuation<'_> {
    pub(crate) fn group(&self) -> &LaneClaimGroup {
        self.prefix.walk_group()
    }

    pub(crate) fn finish<Ch: Challenger>(
        self,
        terminal: &LaneClaimGroup,
        challenger: &mut Ch,
    ) -> Result<Vec<QuirkyDirectClaim>, RegionSidecarError> {
        let terminal_claims = if self.vk.is_selected() {
            verify_duplex_union_walk_suffix_selected_with_challenger(
                self.vk.w_log,
                &self.vk.fixed,
                &recording_ref_sets(self.vk),
                self.selector,
                self.prefix,
                terminal,
                challenger,
            )
        } else {
            verify_duplex_union_walk_suffix_with_challenger(
                self.vk.w_log,
                &self.vk.fixed,
                &self.vk.refs,
                &self.vk.rec_refs,
                self.prefix,
                terminal,
                challenger,
            )
        }
        .map_err(|_| RegionSidecarError::InvalidProof)?;
        resolve_recording_terminal_claims(self.vk, self.total_vars, self.selector, terminal_claims)
    }
}

pub(crate) struct C1RecordingDuplexVerifierWalkContinuation<'a> {
    vk: &'a RecordingDuplexRegionVk,
    total_vars: usize,
    selector: F128,
    prefix: C1DuplexVerifierWalkPrefix<'a>,
}

impl C1RecordingDuplexVerifierWalkContinuation<'_> {
    pub(crate) fn group(&self) -> &C1LaneClaimGroup {
        self.prefix.walk_group()
    }

    pub(crate) fn finish<Ch: Challenger>(
        self,
        terminal: &C1LaneClaimGroup,
        challenger: &mut Ch,
    ) -> Result<Vec<C1QuirkyDirectClaim>, RegionSidecarError> {
        let terminal_claims = if self.vk.is_selected() {
            verify_c1_duplex_walk_suffix_selected(
                self.vk.w_log,
                &self.vk.fixed,
                &recording_ref_sets(self.vk),
                self.selector,
                self.prefix,
                terminal,
                challenger,
            )
        } else {
            verify_c1_duplex_walk_suffix(
                self.vk.w_log,
                &self.vk.fixed,
                &self.vk.refs,
                &self.vk.rec_refs,
                self.prefix,
                terminal,
                challenger,
            )
        }
        .map_err(|_| RegionSidecarError::InvalidProof)?;
        resolve_c1_recording_terminal_claims(
            self.vk,
            self.total_vars,
            self.selector,
            terminal_claims,
        )
    }
}

pub(crate) fn verify_recording_duplex_region_walk_deferred_prefix<'a, Ch: Challenger>(
    vk: &'a RecordingDuplexRegionVk,
    total_vars: usize,
    proof: &'a RecordingDuplexRegionWalkDeferredProof,
    challenger: &mut Ch,
) -> Result<RecordingDuplexVerifierWalkContinuation<'a>, RegionSidecarError> {
    preflight_recording_duplex_region_walk_deferred(vk, total_vars, proof)?;
    bind_recording_vk(challenger, vk);
    bind_recording_selector(challenger, proof.selector());
    let prefix = verify_duplex_union_walk_prefix_with_challenger(
        vk.w_log,
        &vk.fixed,
        &vk.refs,
        proof.authority().as_ref(),
        challenger,
    )
    .map_err(|_| RegionSidecarError::InvalidProof)?;
    Ok(RecordingDuplexVerifierWalkContinuation {
        vk,
        total_vars,
        selector: proof.selector(),
        prefix,
    })
}

pub(crate) fn verify_c1_recording_duplex_region_walk_deferred_prefix<'a, Ch: Challenger>(
    vk: &'a RecordingDuplexRegionVk,
    total_vars: usize,
    proof: &'a C1RecordingDuplexRegionWalkDeferredProof,
    challenger: &mut Ch,
) -> Result<C1RecordingDuplexVerifierWalkContinuation<'a>, RegionSidecarError> {
    let timing = std::env::var_os("NOIDH_C1_VERIFY_TIMING").is_some();
    let total_started = std::time::Instant::now();
    vk.validate_certified_c1_in_witness(total_vars)?;
    let validate_micros = total_started.elapsed().as_micros();
    if proof.version() != DUPLEX_REGION_SIDECAR_VERSION
        || (vk.is_selected() && proof.selector() != F128::ZERO && proof.selector() != F128::ONE)
        || (!vk.is_selected() && proof.selector() != F128::ZERO)
    {
        return Err(RegionSidecarError::InvalidProof);
    }
    bind_recording_vk(challenger, vk);
    bind_recording_selector(challenger, proof.selector());
    let bind_micros = total_started.elapsed().as_micros() - validate_micros;
    let prefix_started = std::time::Instant::now();
    let prefix = verify_c1_duplex_walk_prefix(
        vk.w_log,
        &vk.fixed,
        &vk.refs,
        proof.authority().as_ref(),
        challenger,
    )
    .map_err(|_| RegionSidecarError::InvalidProof)?;
    if timing {
        eprintln!(
            "[recording-duplex-c1 prefix] w_log={} validate_us={validate_micros} bind_us={bind_micros} proof_us={} total_us={}",
            vk.w_log,
            prefix_started.elapsed().as_micros(),
            total_started.elapsed().as_micros(),
        );
    }
    Ok(C1RecordingDuplexVerifierWalkContinuation {
        vk,
        total_vars,
        selector: proof.selector(),
        prefix,
    })
}

/// Allocation-free shape gate.  Recording sets never change the claimed
/// column set, so the walk-deferred wire dimensions equal the recording-free
/// duplex child's and the shared single-set preflight is exact.
pub(crate) fn preflight_recording_duplex_region_walk_deferred(
    vk: &RecordingDuplexRegionVk,
    total_vars: usize,
    proof: &RecordingDuplexRegionWalkDeferredProof,
) -> Result<(), RegionSidecarError> {
    vk.validate_in_witness(total_vars)?;
    if proof.version() != DUPLEX_REGION_SIDECAR_VERSION {
        return Err(RegionSidecarError::UnsupportedVersion);
    }
    if (vk.is_selected() && proof.selector() != F128::ZERO && proof.selector() != F128::ONE)
        || (!vk.is_selected() && proof.selector() != F128::ZERO)
    {
        return Err(RegionSidecarError::InvalidProof);
    }
    let multi = claimed_refs(&vk.substitution_terms(F128::ONE, F128::ONE));
    let deferred = proof.authority().as_ref();
    preflight_duplex_deferred_authority(vk.w_log, &vk.refs, deferred)?;
    if deferred.substitution.final_values.len() != multi.len() {
        return Err(RegionSidecarError::InvalidProof);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Trace twins
// ---------------------------------------------------------------------------

pub(crate) struct RecordingDuplexTraceWalkContinuation<'a> {
    vk: &'a RecordingDuplexRegionVk,
    total_vars: usize,
    selector: LinExpr,
    prefix: DuplexUnionTraceWalkPrefix<'a>,
}

impl RecordingDuplexTraceWalkContinuation<'_> {
    pub(crate) fn walk_group(&self) -> LaneClaimGroupTrace {
        self.prefix.walk_group().clone()
    }

    pub(crate) fn finish<C: FsChannelOps>(
        self,
        b: &mut FieldR1csBuilder,
        context: &mut FieldPostCommitTraceContext<'_, C>,
        walk_terminal: &LaneClaimGroupTrace,
    ) -> Result<Vec<QuirkyDirectClaimTrace>, RegionSidecarError> {
        if context.total_vars() != self.total_vars {
            return Err(RegionSidecarError::InvalidProof);
        }
        let terminal = verify_recording_duplex_suffix_trace(
            b,
            context,
            self.vk,
            &self.selector,
            self.prefix,
            walk_terminal,
        )?;
        let mut claims = terminal
            .into_iter()
            .map(|claim| {
                let slice = *self
                    .vk
                    .slices
                    .get(claim.column)
                    .ok_or(RegionSidecarError::InvalidProof)?;
                if claim.point.len() != slice.log2_len {
                    return Err(RegionSidecarError::InvalidProof);
                }
                let mut x_rest = claim.point;
                x_rest.extend(
                    slice
                        .prefix_coords(self.total_vars)
                        .into_iter()
                        .map(LinExpr::constant),
                );
                Ok(QuirkyDirectClaimTrace {
                    z_skip: LinExpr::zero(),
                    k_skip: 0,
                    x_rest,
                    value: claim.value,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        if let Some(slice) = self.vk.selector_slice() {
            claims.push(QuirkyDirectClaimTrace {
                z_skip: LinExpr::zero(),
                k_skip: 0,
                x_rest: slice
                    .prefix_coords(self.total_vars)
                    .into_iter()
                    .map(LinExpr::constant)
                    .collect(),
                value: self.selector,
            });
        }
        Ok(claims)
    }
}

/// Bind and replay a walk-deferred recording child through carry selection.
pub(crate) fn verify_recording_duplex_region_walk_deferred_prefix_trace<'a, C: FsChannelOps>(
    b: &mut FieldR1csBuilder,
    context: &mut FieldPostCommitTraceContext<'_, C>,
    vk: &'a RecordingDuplexRegionVk,
    proof: &'a RecordingDuplexRegionWalkDeferredProof,
) -> Result<RecordingDuplexTraceWalkContinuation<'a>, RegionSidecarError> {
    let total_vars = context.total_vars();
    preflight_recording_duplex_region_walk_deferred(vk, total_vars, proof)?;
    context.observe_label(b, RECORDING_DUPLEX_SIDECAR_TRANSCRIPT_LABEL);
    crate::acceptance::trace::self_verify::observe_pinned_digest(
        b,
        context,
        &vk.transcript_digest(),
    );
    let selector = if vk.is_selected() {
        LinExpr::from_wire(b.alloc_bool(proof.selector() == F128::ONE))
    } else {
        LinExpr::zero()
    };
    context.observe_label(b, RECORDING_DUPLEX_SELECTOR_TRANSCRIPT_LABEL);
    context.observe_f128(b, &selector);
    let prefix = verify_duplex_union_walk_prefix_trace(
        b,
        context,
        vk.w_log,
        &vk.fixed,
        &vk.refs,
        proof.authority().as_ref(),
    )?;
    Ok(RecordingDuplexTraceWalkContinuation {
        vk,
        total_vars,
        selector,
        prefix,
    })
}

/// Multi-set trace suffix: substitution terms carry every gated pattern set
/// (the primary block plus each further recording block) while the claimed
/// column set stays the six A/C columns.
fn verify_recording_duplex_suffix_trace<C: FsChannelOps>(
    b: &mut FieldR1csBuilder,
    channel: &mut C,
    vk: &RecordingDuplexRegionVk,
    selector: &LinExpr,
    prefix: DuplexUnionTraceWalkPrefix<'_>,
    walk_terminal: &LaneClaimGroupTrace,
) -> Result<Vec<DuplexColumnClaimTrace>, RegionSidecarError> {
    if walk_terminal.point.len() != vk.w_log {
        return Err(RegionSidecarError::InvalidProof);
    }
    let (proof, mut terminal_claims) = prefix.into_parts();

    let alpha = channel.sample_f128(b);
    // Mirror the native `duplex_terms_from_refs` dispatch exactly: a
    // single-block union keeps the original single-set term order, while a
    // multi-block union uses the multi-set form (the relation header absorbs
    // the term structure, so the order is transcript-significant).
    let (substitution_terms, alpha_powers) = if vk.is_selected() {
        duplex_sub_terms_trace_selected(b, &recording_ref_sets(vk), selector, &alpha)
    } else if vk.rec_refs.is_empty() {
        crate::acceptance::trace::region_source_binding::duplex_sub_terms_trace(b, &vk.refs, &alpha)
    } else {
        let sets = recording_ref_sets(vk);
        duplex_sub_terms_trace_multi(b, &sets, &alpha)
    };
    let substitution_refs = claimed_refs(&vk.substitution_terms(F128::ONE, F128::ONE));
    let mut target = LinExpr::zero();
    for lane in 0..STATE_SIZE {
        target = target.add(&mul(b, &alpha_powers[lane], &walk_terminal.values[lane]));
    }
    let substitution =
        ColumnRelationProofTrace::alloc(b, proof.substitution, vk.w_log, substitution_refs.len());
    let substitution_point = verify_column_relation_trace(
        b,
        channel,
        vk.w_log,
        &target,
        &walk_terminal.point,
        &substitution_terms,
        &vk.fixed,
        &substitution,
    );

    let mut shift_cursor = 0usize;
    for (reference, value) in substitution_refs.iter().zip(&substitution.final_values) {
        match reference {
            ColRef::Committed(column) => terminal_claims.push(DuplexColumnClaimTrace {
                column: *column,
                point: substitution_point.clone(),
                value: value.clone(),
            }),
            ColRef::CommittedShift(column) => {
                let native_shift = proof
                    .shifts
                    .get(shift_cursor)
                    .ok_or(RegionSidecarError::InvalidProof)?;
                shift_cursor += 1;
                let shift = ShiftDischargeProofTrace::alloc(b, native_shift, vk.w_log);
                let point = verify_shift_discharge_trace(
                    b,
                    channel,
                    vk.w_log,
                    &substitution_point,
                    value,
                    0,
                    &shift,
                );
                terminal_claims.push(DuplexColumnClaimTrace {
                    column: *column,
                    point,
                    value: shift.final_value,
                });
            }
            _ => return Err(RegionSidecarError::InvalidProof),
        }
    }
    if shift_cursor != proof.shifts.len() {
        return Err(RegionSidecarError::InvalidProof);
    }
    Ok(terminal_claims)
}

/// Shared bounded-decode dimensions: identical to the recording-free duplex
/// child (recording sets change relation terms, not claimed columns).
pub(super) fn recording_duplex_bounded_shape(
    vk: &RecordingDuplexRegionVk,
    total_vars: usize,
) -> Result<super::bounded_decode::FixedProofShape, RegionSidecarError> {
    vk.validate_in_witness(total_vars)?;
    let selection_values = claimed_refs(&carry_selection_terms(&vk.refs.c, F128::ONE)).len();
    let substitution_refs = claimed_refs(&vk.substitution_terms(F128::ONE, F128::ONE));
    let shifts = substitution_refs
        .iter()
        .filter(|reference| {
            matches!(
                reference,
                ColRef::CommittedShift(_) | ColRef::CommittedShift2(_)
            )
        })
        .count();
    Ok(super::bounded_decode::FixedProofShape {
        version: DUPLEX_REGION_SIDECAR_VERSION,
        w_log: vk.w_log,
        selection_values,
        substitution_values: substitution_refs.len(),
        shifts,
        tail: super::bounded_decode::ProofTailShape::None,
    })
}

/// Recording endpoints validated against the key (mirrors the duplex plan
/// constructor for the enclosing prover-input aggregation).
pub(crate) fn validate_recording_endpoints(
    vk: &RecordingDuplexRegionVk,
    endpoints: &RegionWalkEndpoints,
) -> Result<(), RegionSidecarError> {
    RecordingDuplexRegionProverPlan::new(vk, endpoints.s0(), endpoints.s_out()).map(|_| ())
}

#[cfg(test)]
mod tests {
    use noid_ivc_core::deep_chain::schedule::{compile_duplex, TranscriptOp};

    use super::*;

    fn selected_layouts_fixture() -> SelectedRecordingLayouts {
        let arm0_role0 = compile_duplex(&[
            TranscriptOp::Absorb(vec![None, None, None, None]),
            TranscriptOp::Squeeze(1),
        ]);
        let arm1_role0 = compile_duplex(&[
            TranscriptOp::Absorb(vec![Some(7), None, None, None]),
            TranscriptOp::Squeeze(1),
        ]);
        let arm0_role1 = compile_duplex(&[
            TranscriptOp::Absorb(vec![None; 8]),
            TranscriptOp::Squeeze(2),
        ]);
        let arm1_role1 = compile_duplex(&[
            TranscriptOp::Absorb(vec![None, Some(11), None, None, None, None, None, None]),
            TranscriptOp::Squeeze(2),
        ]);
        assert_eq!(arm0_role0.slots.len().max(1).next_power_of_two(), 4);
        assert_eq!(arm1_role0.slots.len().max(1).next_power_of_two(), 4);
        assert_eq!(arm0_role1.slots.len().max(1).next_power_of_two(), 8);
        assert_eq!(arm1_role1.slots.len().max(1).next_power_of_two(), 8);
        SelectedRecordingLayouts {
            selector_slice: WitnessSlice {
                log2_len: 0,
                index: 31,
            },
            arms: [
                vec![(arm0_role0, 0), (arm0_role1, 8)],
                vec![(arm1_role0, 0), (arm1_role1, 8)],
            ],
        }
    }

    #[test]
    fn selected_chunks_recompose_each_complete_arm_fixed_bank() {
        let w_log = 4;
        let domain = 1usize << w_log;
        let selected = selected_layouts_fixture();
        let (fixed, _, rec_refs) =
            canonical_selected_recording_fixed(w_log, &selected).expect("selected fixed bank");
        let sets = 1 + rec_refs.len();
        let chunk_count = 1usize << SELECTED_RECORDING_CHUNK_LOG_REDUCTION;
        assert_eq!(sets, selected.arms[0].len() * chunk_count * 2);

        for (arm, selector) in [F128::ZERO, F128::ONE].into_iter().enumerate() {
            let mut actual = vec![vec![F128::ZERO; domain]; DUPLEX_PATTERNS_PER_SET];
            for pair in 0..sets / 2 {
                for pattern in 0..DUPLEX_PATTERNS_PER_SET {
                    let base =
                        fixed[(2 * pair) * DUPLEX_PATTERNS_PER_SET + pattern].materialize(domain);
                    let delta = fixed[(2 * pair + 1) * DUPLEX_PATTERNS_PER_SET + pattern]
                        .materialize(domain);
                    for row in 0..domain {
                        actual[pattern][row] += base[row] + selector * delta[row];
                    }
                }
            }

            let mut expected = vec![vec![F128::ZERO; domain]; DUPLEX_PATTERNS_PER_SET];
            for (layout, offset) in &selected.arms[arm] {
                let size = layout.slots.len().max(1).next_power_of_two();
                let s_log = size.trailing_zeros() as usize;
                for (pattern, full) in duplex_fixed_patterns(
                    layout,
                    FsChannelUnionRecorder::capacity_iv_flat_c1(),
                    s_log,
                )
                .into_iter()
                .enumerate()
                {
                    let gated = if s_log == w_log {
                        full
                    } else {
                        full.gated(s_log, rec_hi_bits(*offset, s_log, w_log))
                    };
                    let materialized = gated.materialize(domain);
                    for row in 0..domain {
                        expected[pattern][row] += materialized[row];
                    }
                }
            }
            assert_eq!(actual, expected, "selector {arm} fixed bank");
        }
    }
}
