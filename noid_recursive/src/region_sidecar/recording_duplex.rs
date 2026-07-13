// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Post-commit authority for a RECORDINGS-ONLY duplex union: committed
//! Fiat-Shamir transcript regions whose Poseidon chain is proven by the
//! enclosing multi-instance deep-chain walk instead of inline sponge
//! permutations.
//!
//! Every block of the union is one recorded child transcript (a compiled
//! [`DuplexLayout`] over the union-recorder capacity IV), gated to its own
//! dyadic offset.  A built instance carries exactly one LIVE block per
//! recording ROLE (the recordings its enclosing relation actually pinned:
//! the hosted slot's block-sidecar child and `[R]_B` channel plus the
//! universal `[R]_prev` channel) and canonical zero-data ghosts on the
//! remaining blocks, so ONE verification key covers every ladder slot.
//! The serialized child authority reuses the duplex
//! walk-deferred wire shape byte-for-byte: recordings change relation TERMS
//! (per-set gated wiring), never the claimed-column set, so selection /
//! substitution / shift dimensions equal the recording-free duplex child.

use noid_ivc_core::challenger::Challenger;
use noid_ivc_core::deep_chain::relations::{claimed_refs, ColRef, FixedPattern};
use noid_ivc_core::deep_chain::schedule::{
    carry_selection_terms, duplex_family_refs, duplex_fixed_patterns, DuplexFamilyRefs,
    DuplexLayout,
};
use noid_ivc_core::deep_chain::LaneClaimGroup;
use noid_ivc_core::field::F128;
use noid_ivc_core::field_circuit::{FsChannelOps, FsChannelUnionRecorder};
use noid_ivc_core::pcs::QuirkyDirectClaim;
use noid_ivc_core::public_io::WitnessSlice;
use noid_poseidon2b::native::permutation::STATE_SIZE;
use noid_poseidon2b::native::poseidon2b_hash_byte_slices;

use crate::acceptance::trace::deep_chain::{
    verify_column_relation_trace, verify_shift_discharge_trace, ColumnRelationProofTrace,
    LaneClaimGroupTrace, ShiftDischargeProofTrace,
};
use crate::acceptance::trace::region_source_binding::{
    duplex_sub_terms_trace_multi, duplex_substitution_terms_sets, rec_hi_bits,
    prove_duplex_union_walk_prefix_with_challenger, prove_duplex_union_walk_suffix_with_challenger,
    verify_duplex_union_walk_prefix_with_challenger,
    verify_duplex_union_walk_suffix_with_challenger, DuplexColumnClaim, DuplexUnion,
    DuplexUnionProverWalkPrefix, DuplexUnionVerifierWalkPrefix,
};
use crate::acceptance::trace::self_verify::{FieldPostCommitTraceContext, QuirkyDirectClaimTrace};
use crate::acceptance::trace::{mul, FieldR1csBuilder, LinExpr};

use super::trace::{
    preflight_duplex_deferred_authority, verify_duplex_union_walk_prefix_trace,
    DuplexColumnClaimTrace, DuplexUnionTraceWalkPrefix,
};
use super::{
    duplex_layout_digest, push_usize, DuplexRegionWalkDeferredProof, RegionSidecarError,
    RegionWalkEndpoints, DUPLEX_REGION_COMMITTED_COLUMNS, DUPLEX_REGION_SIDECAR_VERSION,
};

const RECORDING_DUPLEX_LAYOUT_DIGEST_DOMAIN: &[u8] =
    b"NOID/REGION-SIDECAR/RECORDING-DUPLEX-LAYOUT/V1";
const RECORDING_DUPLEX_VK_DIGEST_DOMAIN: &[u8] = b"NOID/REGION-SIDECAR/RECORDING-DUPLEX-VK/V1";
pub(crate) const RECORDING_DUPLEX_SIDECAR_TRANSCRIPT_LABEL: &[u8] =
    b"history-region-sidecar-recording-duplex-v1";
const DUPLEX_PATTERNS_PER_SET: usize = 7;

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
    fixed: Vec<FixedPattern>,
    refs: DuplexFamilyRefs,
    rec_refs: Vec<DuplexFamilyRefs>,
    layout_digest: [u8; 32],
}

impl RecordingDuplexRegionVk {
    pub(crate) fn new(
        purpose: [u8; 32],
        w_log: usize,
        slices: [WitnessSlice; DUPLEX_REGION_COMMITTED_COLUMNS],
        blocks: Vec<(DuplexLayout, usize)>,
    ) -> Result<Self, RegionSidecarError> {
        let (fixed, refs, rec_refs) = canonical_recording_fixed(w_log, &blocks)?;
        let layout_digest = recording_layout_digest(w_log, &blocks);
        let vk = Self {
            purpose,
            w_log,
            slices,
            blocks,
            fixed,
            refs,
            rec_refs,
            layout_digest,
        };
        vk.validate_structure()?;
        Ok(vk)
    }

    /// Bridge from an assembled recordings-only union: the union's packing,
    /// fixed tables and refs must equal the canonical derivation.
    pub(crate) fn from_union(
        purpose: [u8; 32],
        slices: [WitnessSlice; DUPLEX_REGION_COMMITTED_COLUMNS],
        union: &DuplexUnion,
    ) -> Result<Self, RegionSidecarError> {
        if union.rec_blocks.len() != union.rec_refs.len() + 1 {
            return Err(RegionSidecarError::UnsupportedVkShape);
        }
        let vk = Self::new(purpose, union.w_log, slices, union.rec_blocks.clone())?;
        if vk.fixed != union.fixed
            || vk.refs != union.refs
            || vk.rec_refs != union.rec_refs
        {
            return Err(RegionSidecarError::BadVk);
        }
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

    pub(crate) fn blocks(&self) -> &[(DuplexLayout, usize)] {
        &self.blocks
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
        if self.w_log == 0 || self.w_log >= usize::BITS as usize || self.blocks.is_empty() {
            return Err(RegionSidecarError::BadVk);
        }
        let (fixed, refs, rec_refs) = canonical_recording_fixed(self.w_log, &self.blocks)?;
        if self.fixed != fixed
            || self.refs != refs
            || self.rec_refs != rec_refs
            || self.layout_digest != recording_layout_digest(self.w_log, &self.blocks)
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
        Ok(())
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
    let iv = FsChannelUnionRecorder::capacity_iv_flat();
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

/// Stable digest over the complete recording packing.
fn recording_layout_digest(w_log: usize, blocks: &[(DuplexLayout, usize)]) -> [u8; 32] {
    let mut bytes = Vec::new();
    bytes.push(DUPLEX_REGION_SIDECAR_VERSION);
    push_usize(&mut bytes, w_log);
    push_usize(&mut bytes, blocks.len());
    for (layout, offset) in blocks {
        push_usize(&mut bytes, *offset);
        bytes.extend_from_slice(&duplex_layout_digest(layout));
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

fn resolve_recording_terminal_claims(
    vk: &RecordingDuplexRegionVk,
    total_vars: usize,
    terminal: Vec<DuplexColumnClaim>,
) -> Result<Vec<QuirkyDirectClaim>, RegionSidecarError> {
    let mut claims = Vec::with_capacity(terminal.len());
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
    Ok(claims)
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
    ) -> Result<(DuplexRegionWalkDeferredProof, Vec<QuirkyDirectClaim>), RegionSidecarError> {
        let (authority, terminal_claims) = prove_duplex_union_walk_suffix_with_challenger(
            self.vk.w_log,
            &self.vk.fixed,
            &self.vk.refs,
            &self.vk.rec_refs,
            &self.committed,
            self.prefix,
            terminal,
            challenger,
        );
        let claims = resolve_recording_terminal_claims(self.vk, self.total_vars, terminal_claims)?;
        Ok((DuplexRegionWalkDeferredProof::new(authority), claims))
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
        bind_recording_vk(challenger, self.vk);
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
        let terminal_claims = verify_duplex_union_walk_suffix_with_challenger(
            self.vk.w_log,
            &self.vk.fixed,
            &self.vk.refs,
            &self.vk.rec_refs,
            self.prefix,
            terminal,
            challenger,
        )
        .map_err(|_| RegionSidecarError::InvalidProof)?;
        resolve_recording_terminal_claims(self.vk, self.total_vars, terminal_claims)
    }
}

pub(crate) fn verify_recording_duplex_region_walk_deferred_prefix<'a, Ch: Challenger>(
    vk: &'a RecordingDuplexRegionVk,
    total_vars: usize,
    proof: &'a DuplexRegionWalkDeferredProof,
    challenger: &mut Ch,
) -> Result<RecordingDuplexVerifierWalkContinuation<'a>, RegionSidecarError> {
    preflight_recording_duplex_region_walk_deferred(vk, total_vars, proof)?;
    bind_recording_vk(challenger, vk);
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
        prefix,
    })
}

/// Allocation-free shape gate.  Recording sets never change the claimed
/// column set, so the walk-deferred wire dimensions equal the recording-free
/// duplex child's and the shared single-set preflight is exact.
pub(crate) fn preflight_recording_duplex_region_walk_deferred(
    vk: &RecordingDuplexRegionVk,
    total_vars: usize,
    proof: &DuplexRegionWalkDeferredProof,
) -> Result<(), RegionSidecarError> {
    vk.validate_in_witness(total_vars)?;
    if proof.version() != DUPLEX_REGION_SIDECAR_VERSION {
        return Err(RegionSidecarError::UnsupportedVersion);
    }
    let sets = recording_ref_sets(vk);
    let multi = claimed_refs(&duplex_substitution_terms_sets(
        &vk.refs,
        &vk.rec_refs,
        F128::ONE,
    ));
    debug_assert_eq!(sets.len(), vk.blocks.len(), "one ref set per block");
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
            self.prefix,
            walk_terminal,
        )?;
        terminal
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
            .collect()
    }
}

/// Bind and replay a walk-deferred recording child through carry selection.
pub(crate) fn verify_recording_duplex_region_walk_deferred_prefix_trace<'a, C: FsChannelOps>(
    b: &mut FieldR1csBuilder,
    context: &mut FieldPostCommitTraceContext<'_, C>,
    vk: &'a RecordingDuplexRegionVk,
    proof: &'a DuplexRegionWalkDeferredProof,
) -> Result<RecordingDuplexTraceWalkContinuation<'a>, RegionSidecarError> {
    let total_vars = context.total_vars();
    preflight_recording_duplex_region_walk_deferred(vk, total_vars, proof)?;
    context.observe_label(b, RECORDING_DUPLEX_SIDECAR_TRANSCRIPT_LABEL);
    // WITNESS lanes pinned to the digest constants (same FS_OP_BYTES header
    // and packed lanes as the native `observe_bytes`).  The recordings-only
    // vertical hosts the very [R]-replay recording whose schedule this
    // replay produces; a constant absorb would bake the vertical's digest
    // into its own layout (a hash fixed point), so the digest must ride the
    // matrix pins instead of the recording schedule.
    let digest_lanes = crate::acceptance::trace::self_verify::flat_digest_lanes(
        &vk.transcript_digest(),
    )
    .map(|lane| {
        let wire = LinExpr::from_wire(b.alloc_f128(lane));
        crate::acceptance::trace::pin_eq(b, &wire, &LinExpr::constant(lane));
        wire
    });
    context.observe_lanes(b, 32, &digest_lanes);
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
    let (substitution_terms, alpha_powers) = if vk.rec_refs.is_empty() {
        crate::acceptance::trace::region_source_binding::duplex_sub_terms_trace(
            b, &vk.refs, &alpha,
        )
    } else {
        let sets = recording_ref_sets(vk);
        duplex_sub_terms_trace_multi(b, &sets, &alpha)
    };
    let substitution_refs = claimed_refs(&duplex_substitution_terms_sets(
        &vk.refs,
        &vk.rec_refs,
        F128::ONE,
    ));
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
    let substitution_refs = claimed_refs(&duplex_substitution_terms_sets(
        &vk.refs,
        &vk.rec_refs,
        F128::ONE,
    ));
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
