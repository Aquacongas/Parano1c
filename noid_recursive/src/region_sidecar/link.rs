// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Mandatory terminal post-commit authority for one production link proof.
//!
//! Link-local replay has exactly three independent verticals: heterogeneous
//! leaf/transcript Walk L-A, feed-forward Merkle Walk L-B, and the
//! recordings region Walk L-C.  Each proof is a sibling field, never data
//! recorded into another vertical's committed columns.
//!
//! Since V4, walk L-C hosts THREE recorded transcript roles per link: the
//! block-sidecar child transcript, the `[R]_B` replay's complete outer
//! Fiat-Shamir channel and the `[R]_prev` replay's complete outer channel
//! (which itself contains the previous link's full sidecar verify).  The
//! resulting trust chain, link by link:
//!
//! 1. Link N's CIRCUIT runs both `[R]` replays' verifier algebra inline but
//!    commits their Fiat-Shamir traffic as walk L-C columns: every absorbed
//!    witness lane is pinned to an A-cell, every squeezed challenge to the
//!    carry cell the chain produces it in, and every protocol-constant lane
//!    is a VK fixed pattern.  Nothing about the transcript is proven by the
//!    circuit itself beyond these bindings.
//! 2. Link N's post-commit SIDECAR (proven by link N's prover, bound to
//!    link N's own Field transcript through the post-commit context) proves
//!    the three walks over those committed columns — i.e. that every
//!    recorded Poseidon chain actually permutes as recorded, from the
//!    capacity IV through every absorb to every challenge cell.
//! 3. Link N+1's `[R]_prev` replay verifies link N's Field proof AND its
//!    complete sidecar (prefixes, the 3-instance ragged multi-walk,
//!    suffixes) — with N+1's own channel traffic recorded into N+1's walk
//!    L-C and proven by N+1's sidecar, and so on up the chain.
//! 4. The induction closes at the tip: the terminal decider natively
//!    verifies the tip link's Field proof and its FULL sidecar
//!    ([`verify_link_region_sidecar_post_commit`], no recording anywhere in
//!    the native path), which covers all three verticals including both
//!    recorded `[R]` channels.  A sound tip sidecar makes the tip's recorded
//!    challenges sound, which makes the tip's in-circuit verification of
//!    link N−1 sound, and so on down to genesis.
//!
//! The one self-reference this introduces — the `[R]_prev` recording layout
//! hosts the very sidecar-verify transcript that binds the VK describing
//! that layout — is broken by absorbing the VK digests (the link VK's here
//! and the rec-C child VK's in `recording_duplex`) as WITNESS lanes pinned
//! to constants by the class matrix, never as schedule constants, so no VK
//! digest feeds its own preimage.

use noid_ivc_core::challenger::Challenger;
use noid_ivc_core::deep_chain::{
    prove_ragged_multi_deep_chain_walk, verify_ragged_multi_deep_chain_walk,
    MultiDeepChainWalkProof,
};
use noid_ivc_core::field::F128;
use noid_ivc_core::field_circuit::FsChannelOps;
use noid_ivc_core::pcs::{PcsParams, QuirkyDirectClaim};
use noid_ivc_core::public_io::PublicIoSpec;
use noid_ivc_core::verifier::FieldPostCommitVerifierContext;
use noid_ivc_prover::field_prover::FieldPostCommitProverContext;
use noid_poseidon2b::native::permutation::N_ROUNDS;
use noid_poseidon2b::native::poseidon2b_hash_byte_slices;

use crate::acceptance::trace::deep_chain::{
    verify_ragged_multi_deep_chain_walk_trace, MultiDeepChainWalkProofTrace,
};
use crate::acceptance::trace::r_pcs_region::{
    link_r_pcs_leaf_sidecar_purpose, link_r_pcs_path_sidecar_purpose, link_recordings_purpose,
};
use crate::acceptance::trace::self_verify::FieldPostCommitTraceContext;
use crate::acceptance::trace::FieldR1csBuilder;

use super::bounded_decode::{
    merkle_shape_for_vk, multi_walk_proof_shape, preflight_composite_proof, record_serde_attempt,
    SidecarProofShape,
};
use super::combined_duplex::{
    combined_walk_deferred_bounded_shape, preflight_combined_duplex_region_walk_deferred_trace,
    verify_combined_duplex_region_walk_deferred_prefix,
    verify_combined_duplex_region_walk_deferred_prefix_trace,
    CombinedDuplexRegionWalkDeferredProof,
};
use super::recording_duplex::{
    preflight_recording_duplex_region_walk_deferred, recording_duplex_bounded_shape,
    validate_recording_endpoints, verify_recording_duplex_region_walk_deferred_prefix,
    verify_recording_duplex_region_walk_deferred_prefix_trace, RecordingDuplexRegionProverPlan,
    RecordingDuplexRegionVk,
};
use super::{
    preflight_merkle_region_walk_deferred_trace, verify_merkle_region_walk_deferred_prefix,
    verify_merkle_region_walk_deferred_prefix_trace, CombinedDuplexRegionProverPlan,
    CombinedDuplexRegionVk, DuplexRegionWalkDeferredProof, MerkleRegionProverPlan, MerkleRegionVk,
    MerkleRegionWalkDeferredProof, RegionSidecarError, RegionWalkEndpoints,
};

pub const LINK_REGION_SIDECAR_VERSION: u8 = 4;

const LINK_REGION_VK_DIGEST_DOMAIN: &[u8] = b"NOID/REGION-SIDECAR/LINK-VK/V4";
const LINK_POST_COMMIT_CLASS_DIGEST_DOMAIN: &[u8] =
    b"NOID/REGION-SIDECAR/LINK-POST-COMMIT-CLASS/V4";
const LINK_REGION_TRANSCRIPT_LABEL: &[u8] = b"history-region-sidecar-link-v4";

/// Canonical key for the three mandatory link-region verticals.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinkRegionSidecarVk {
    leaf_a: CombinedDuplexRegionVk,
    path_b: MerkleRegionVk,
    rec_c: RecordingDuplexRegionVk,
    transcript_digest: [u8; 32],
}

impl LinkRegionSidecarVk {
    pub fn new(
        leaf_a: CombinedDuplexRegionVk,
        path_b: MerkleRegionVk,
        rec_c: RecordingDuplexRegionVk,
    ) -> Result<Self, RegionSidecarError> {
        let transcript_digest = link_region_sidecar_vk_digest(&leaf_a, &path_b, &rec_c);
        let vk = Self {
            leaf_a,
            path_b,
            rec_c,
            transcript_digest,
        };
        vk.validate_roles()?;
        Ok(vk)
    }

    pub fn leaf_a(&self) -> &CombinedDuplexRegionVk {
        &self.leaf_a
    }

    pub fn path_b(&self) -> &MerkleRegionVk {
        &self.path_b
    }

    pub fn rec_c(&self) -> &RecordingDuplexRegionVk {
        &self.rec_c
    }

    pub fn transcript_digest(&self) -> [u8; 32] {
        self.transcript_digest
    }

    fn validate_roles(&self) -> Result<(), RegionSidecarError> {
        if self.leaf_a.purpose() != &link_r_pcs_leaf_sidecar_purpose()
            || self.path_b.purpose() != &link_r_pcs_path_sidecar_purpose()
            || self.rec_c.purpose() != &link_recordings_purpose()
        {
            return Err(RegionSidecarError::UnsupportedVkShape);
        }
        Ok(())
    }
}

fn link_region_sidecar_vk_digest(
    leaf_a: &CombinedDuplexRegionVk,
    path_b: &MerkleRegionVk,
    rec_c: &RecordingDuplexRegionVk,
) -> [u8; 32] {
    let version = [LINK_REGION_SIDECAR_VERSION];
    poseidon2b_hash_byte_slices(
        LINK_REGION_VK_DIGEST_DOMAIN,
        &[
            &version,
            b"leaf-a",
            &leaf_a.transcript_digest(),
            b"path-b",
            &path_b.transcript_digest(),
            b"rec-c",
            &rec_c.transcript_digest(),
        ],
    )
}

/// Stable identity bound at the link Field proof's post-commit boundary.
pub fn link_post_commit_class_digest(
    matrix_digest: &[u8; 32],
    spec: &PublicIoSpec,
    pcs_params: &PcsParams,
    sidecar_vk: &LinkRegionSidecarVk,
) -> [u8; 32] {
    let mut spec_bytes = Vec::new();
    push_u64(&mut spec_bytes, spec.io_slice.log2_len);
    push_u64(&mut spec_bytes, spec.io_slice.index);
    push_u64(&mut spec_bytes, spec.io_len);
    push_u64(&mut spec_bytes, spec.claims.len());
    for claim in &spec.claims {
        push_u64(&mut spec_bytes, claim.slice.log2_len);
        push_u64(&mut spec_bytes, claim.slice.index);
        push_u64(&mut spec_bytes, claim.point.start);
        push_u64(&mut spec_bytes, claim.point.end);
        push_u64(&mut spec_bytes, claim.value);
    }

    let mut pcs_bytes = Vec::new();
    push_u64(&mut pcs_bytes, pcs_params.m);
    push_u64(&mut pcs_bytes, pcs_params.log_inv_rate);
    push_u64(&mut pcs_bytes, pcs_params.log_batch_size);
    let profile = pcs_params.profile.as_str().as_bytes();
    push_u64(&mut pcs_bytes, profile.len());
    pcs_bytes.extend_from_slice(profile);

    let version = [LINK_REGION_SIDECAR_VERSION];
    poseidon2b_hash_byte_slices(
        LINK_POST_COMMIT_CLASS_DIGEST_DOMAIN,
        &[
            &version,
            b"link",
            matrix_digest,
            &spec_bytes,
            &pcs_bytes,
            &sidecar_vk.transcript_digest(),
        ],
    )
}

/// Owned link-side walk endpoints.  Committed columns remain exclusively in
/// the enclosing Field witness and are selected through the two VKs.
pub struct LinkRegionProverInput {
    leaf_a: RegionWalkEndpoints,
    path_b: RegionWalkEndpoints,
    rec_c: RegionWalkEndpoints,
}

impl LinkRegionProverInput {
    pub fn new(
        vk: &LinkRegionSidecarVk,
        leaf_a: RegionWalkEndpoints,
        path_b: RegionWalkEndpoints,
        rec_c: RegionWalkEndpoints,
    ) -> Result<Self, RegionSidecarError> {
        vk.validate_roles()?;
        let input = Self {
            leaf_a,
            path_b,
            rec_c,
        };
        input.validate(vk)?;
        Ok(input)
    }

    fn validate(&self, vk: &LinkRegionSidecarVk) -> Result<(), RegionSidecarError> {
        CombinedDuplexRegionProverPlan::new(vk.leaf_a(), self.leaf_a.s0(), self.leaf_a.s_out())?;
        MerkleRegionProverPlan::new(vk.path_b(), self.path_b.s0(), self.path_b.s_out())?;
        validate_recording_endpoints(vk.rec_c(), &self.rec_c)?;
        Ok(())
    }
}

pub struct LinkRegionProverPlan<'a> {
    vk: &'a LinkRegionSidecarVk,
    input: &'a LinkRegionProverInput,
}

impl<'a> LinkRegionProverPlan<'a> {
    pub fn new(
        vk: &'a LinkRegionSidecarVk,
        input: &'a LinkRegionProverInput,
    ) -> Result<Self, RegionSidecarError> {
        vk.validate_roles()?;
        input.validate(vk)?;
        Ok(Self { vk, input })
    }

    fn prove<Ch: Challenger>(
        &self,
        z: &[F128],
        challenger: &mut Ch,
    ) -> Result<(LinkRegionSidecarProof, Vec<QuirkyDirectClaim>), RegionSidecarError> {
        // Env-gated stage timing, mirroring the Block sidecar.  Keeping this
        // local to the prover plan makes the production transcript and proof
        // bytes completely independent of whether diagnostics are enabled.
        let timing = std::env::var_os("NOIDH_SIDECAR_TIMING").is_some();
        let mut t = std::time::Instant::now();
        let lap = move |label: &str, t: &mut std::time::Instant| {
            if timing {
                eprintln!(
                    "[link-sidecar] {label}: {:.1} ms",
                    t.elapsed().as_secs_f64() * 1e3
                );
            }
            *t = std::time::Instant::now();
        };
        bind_link_vk(challenger, self.vk);

        let leaf_plan = CombinedDuplexRegionProverPlan::new(
            self.vk.leaf_a(),
            self.input.leaf_a.s0(),
            self.input.leaf_a.s_out(),
        )?;
        let path_plan = MerkleRegionProverPlan::new(
            self.vk.path_b(),
            self.input.path_b.s0(),
            self.input.path_b.s_out(),
        )?;
        let rec_plan = RecordingDuplexRegionProverPlan::new(
            self.vk.rec_c(),
            self.input.rec_c.s0(),
            self.input.rec_c.s_out(),
        )?;
        lap("bind + plans", &mut t);
        let leaf_a_prefix = leaf_plan.prove_walk_deferred_prefix(z, challenger)?;
        lap("leaf-A prefix", &mut t);
        let path_b_prefix = path_plan.prove_walk_deferred_prefix(z, challenger)?;
        lap("path-B prefix", &mut t);
        let rec_c_prefix = rec_plan.prove_walk_deferred_prefix(z, challenger)?;
        lap("rec-C prefix", &mut t);
        let groups = vec![
            vec![leaf_a_prefix.group().clone()],
            vec![path_b_prefix.group().clone()],
            vec![rec_c_prefix.group().clone()],
        ];
        let s0 = [leaf_a_prefix.s0(), path_b_prefix.s0(), rec_c_prefix.s0()];
        let (walk, terminals) = prove_ragged_multi_deep_chain_walk(&s0, &groups, challenger);
        lap("three-child multi-walk", &mut t);
        let [leaf_a_terminal, path_b_terminal, rec_c_terminal]: [_; 3] = terminals
            .try_into()
            .expect("leaf-A/path-B/rec-C multi-walk terminal count");
        let (leaf_a, mut claims) = leaf_a_prefix.finish(&leaf_a_terminal, challenger)?;
        lap("leaf-A finish", &mut t);
        let (path_b, path_claims) = path_b_prefix.finish(&path_b_terminal, challenger)?;
        claims.extend(path_claims);
        lap("path-B finish", &mut t);
        let (rec_c, rec_claims) = rec_c_prefix.finish(&rec_c_terminal, challenger)?;
        claims.extend(rec_claims);
        lap("rec-C finish", &mut t);

        Ok((
            LinkRegionSidecarProof {
                version: LINK_REGION_SIDECAR_VERSION,
                leaf_a,
                path_b,
                rec_c,
                walk,
            },
            claims,
        ))
    }

    /// Production entry point: proof creation and claim contribution are one
    /// indivisible operation on the enclosing post-commit capability.
    pub fn prove_post_commit<Ch: Challenger>(
        &self,
        context: &mut FieldPostCommitProverContext<'_, Ch>,
    ) -> Result<LinkRegionSidecarProof, RegionSidecarError> {
        let witness = context.witness();
        let (proof, claims) = self.prove(witness, context)?;
        context.append_claims(claims);
        Ok(proof)
    }
}

/// Fixed V4 link sidecar.  All three children retain their complete
/// role-local prefix/suffix authority; only their deep-chain walks are
/// reduced by one mandatory ragged-domain multi-instance proof.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LinkRegionSidecarProof {
    version: u8,
    leaf_a: CombinedDuplexRegionWalkDeferredProof,
    path_b: MerkleRegionWalkDeferredProof,
    rec_c: DuplexRegionWalkDeferredProof,
    walk: MultiDeepChainWalkProof,
}

impl LinkRegionSidecarProof {
    pub fn byte_len(&self) -> usize {
        bincode::serialized_size(self).expect("link region sidecar serialized length") as usize
    }
}

pub(crate) fn encode_link_region_sidecar_canonical(
    vk: &LinkRegionSidecarVk,
    total_vars: usize,
    proof: &LinkRegionSidecarProof,
) -> Result<Vec<u8>, RegionSidecarError> {
    use super::canonical_codec as canonical;

    let [SidecarProofShape::DeferredFixed(leaf_shape), SidecarProofShape::DeferredMerkle(path_shape), SidecarProofShape::DeferredFixed(rec_shape), SidecarProofShape::MultiWalk(walk_shape)] =
        link_bounded_shapes(vk, total_vars)?
    else {
        return Err(RegionSidecarError::UnsupportedVkShape);
    };
    let expected = canonical_link_region_sidecar_len(vk, total_vars)?;
    if proof.version != LINK_REGION_SIDECAR_VERSION {
        return Err(RegionSidecarError::UnsupportedVersion);
    }
    let mut out = Vec::with_capacity(expected);
    out.push(proof.version);
    canonical::encode_duplex_deferred(
        &mut out,
        proof.leaf_a.version(),
        proof.leaf_a.authority(),
        &leaf_shape,
    )?;
    canonical::encode_merkle_deferred(
        &mut out,
        proof.path_b.version(),
        proof.path_b.authority(),
        &path_shape,
    )?;
    canonical::encode_duplex_deferred(
        &mut out,
        proof.rec_c.version(),
        proof.rec_c.authority(),
        &rec_shape,
    )?;
    canonical::encode_multi_walk(&mut out, &proof.walk, &walk_shape)?;
    if out.len() != expected {
        return Err(RegionSidecarError::InvalidProof);
    }
    Ok(out)
}

pub(crate) fn decode_link_region_sidecar_canonical(
    vk: &LinkRegionSidecarVk,
    total_vars: usize,
    bytes: &[u8],
) -> Result<LinkRegionSidecarProof, RegionSidecarError> {
    use super::canonical_codec as canonical;

    let [SidecarProofShape::DeferredFixed(leaf_shape), SidecarProofShape::DeferredMerkle(path_shape), SidecarProofShape::DeferredFixed(rec_shape), SidecarProofShape::MultiWalk(walk_shape)] =
        link_bounded_shapes(vk, total_vars)?
    else {
        return Err(RegionSidecarError::UnsupportedVkShape);
    };
    let expected = canonical_link_region_sidecar_len(vk, total_vars)?;
    let mut reader = canonical::CanonicalProofReader::exact(bytes, expected)?;
    if reader.u8()? != LINK_REGION_SIDECAR_VERSION {
        return Err(RegionSidecarError::UnsupportedVersion);
    }
    let leaf_a = CombinedDuplexRegionWalkDeferredProof::new(canonical::decode_duplex_deferred(
        &mut reader,
        &leaf_shape,
    )?);
    let path_b = MerkleRegionWalkDeferredProof::new(canonical::decode_merkle_deferred(
        &mut reader,
        &path_shape,
    )?);
    let rec_c = DuplexRegionWalkDeferredProof::new(canonical::decode_duplex_deferred(
        &mut reader,
        &rec_shape,
    )?);
    let walk = canonical::decode_multi_walk(&mut reader, &walk_shape)?;
    reader.finish()?;
    Ok(LinkRegionSidecarProof {
        version: LINK_REGION_SIDECAR_VERSION,
        leaf_a,
        path_b,
        rec_c,
        walk,
    })
}

pub(crate) fn canonical_link_region_sidecar_len(
    vk: &LinkRegionSidecarVk,
    total_vars: usize,
) -> Result<usize, RegionSidecarError> {
    use super::canonical_codec as canonical;

    let [SidecarProofShape::DeferredFixed(leaf_shape), SidecarProofShape::DeferredMerkle(path_shape), SidecarProofShape::DeferredFixed(rec_shape), SidecarProofShape::MultiWalk(walk_shape)] =
        link_bounded_shapes(vk, total_vars)?
    else {
        return Err(RegionSidecarError::UnsupportedVkShape);
    };
    [
        canonical::deferred_fixed_len(&leaf_shape)?,
        canonical::deferred_merkle_len(&path_shape)?,
        canonical::deferred_fixed_len(&rec_shape)?,
        canonical::multi_walk_len(&walk_shape)?,
    ]
    .into_iter()
    .try_fold(1usize, |sum, len| {
        sum.checked_add(len).ok_or(RegionSidecarError::InvalidProof)
    })
}

/// Decode the mandatory V4 link envelope only after all three deferred
/// children and their shared multi-walk have passed one allocation-free,
/// class-aware bincode scan.
pub fn decode_link_region_sidecar_bounded(
    vk: &LinkRegionSidecarVk,
    total_vars: usize,
    bytes: &[u8],
) -> Result<LinkRegionSidecarProof, RegionSidecarError> {
    let shapes = link_bounded_shapes(vk, total_vars)?;
    preflight_composite_proof(bytes, LINK_REGION_SIDECAR_VERSION, &shapes)?;
    record_serde_attempt();
    let proof: LinkRegionSidecarProof =
        bincode::deserialize(bytes).map_err(|_| RegionSidecarError::InvalidProof)?;
    if proof.version != LINK_REGION_SIDECAR_VERSION {
        return Err(RegionSidecarError::UnsupportedVersion);
    }
    preflight_combined_duplex_region_walk_deferred_trace(vk.leaf_a(), total_vars, &proof.leaf_a)?;
    preflight_merkle_region_walk_deferred_trace(vk.path_b(), total_vars, &proof.path_b)?;
    preflight_recording_duplex_region_walk_deferred(vk.rec_c(), total_vars, &proof.rec_c)?;
    let w_logs = link_w_logs(vk);
    preflight_multi_walk(&proof.walk, max_w_log(&w_logs), w_logs.len())?;
    Ok(proof)
}

fn link_bounded_shapes(
    vk: &LinkRegionSidecarVk,
    total_vars: usize,
) -> Result<[SidecarProofShape; 4], RegionSidecarError> {
    vk.validate_roles()?;
    let w_logs = link_w_logs(vk);
    Ok([
        SidecarProofShape::DeferredFixed(combined_walk_deferred_bounded_shape(
            vk.leaf_a(),
            total_vars,
        )?),
        SidecarProofShape::DeferredMerkle(
            merkle_shape_for_vk(vk.path_b(), total_vars)?.walk_deferred(),
        ),
        SidecarProofShape::DeferredFixed(
            recording_duplex_bounded_shape(vk.rec_c(), total_vars)?.walk_deferred(),
        ),
        SidecarProofShape::MultiWalk(multi_walk_proof_shape(max_w_log(&w_logs), w_logs.len())?),
    ])
}

/// Zero-valued link-sidecar proof of the exact universal shape.  It cannot
/// verify; its only role is deriving the value-independent [R]_prev-replay
/// transcript SCHEDULE (the recorded op stream of the HistoryStep parent-
/// proof replay) when the recording layout is frozen before any real parent
/// proof exists.  Mirror of `shape_only_block_region_sidecar_proof`.
pub(crate) fn shape_only_link_region_sidecar_proof(
    vk: &LinkRegionSidecarVk,
    total_vars: usize,
) -> Result<LinkRegionSidecarProof, RegionSidecarError> {
    use noid_ivc_core::deep_chain::relations::{
        ColumnRelationProof, ShiftDischargeProof, RELATION_DEGREE,
    };
    use noid_ivc_core::deep_chain::{MultiWalkLayerProof, WALK_DEGREE};

    use crate::acceptance::trace::region_source_binding::{
        DuplexUnionWalkDeferredProof, MerkleUnionWalkDeferredProof,
    };

    let relation = |rounds: usize, values: usize| ColumnRelationProof {
        rounds: vec![[F128::ZERO; RELATION_DEGREE]; rounds],
        final_values: vec![F128::ZERO; values],
    };
    let shifts = |count: usize, w_log: usize| -> Vec<ShiftDischargeProof> {
        (0..count)
            .map(|_| ShiftDischargeProof {
                rounds: vec![[F128::ZERO; 2]; w_log],
                final_value: F128::ZERO,
            })
            .collect()
    };

    let shapes = link_bounded_shapes(vk, total_vars)?;
    let [SidecarProofShape::DeferredFixed(leaf_shape), SidecarProofShape::DeferredMerkle(path_shape), SidecarProofShape::DeferredFixed(rec_shape), SidecarProofShape::MultiWalk(walk_shape)] =
        shapes
    else {
        return Err(RegionSidecarError::UnsupportedVkShape);
    };
    if !matches!(
        leaf_shape.tail,
        super::bounded_decode::ProofTailShape::None
            | super::bounded_decode::ProofTailShape::RelationOption(None)
    ) || !matches!(
        rec_shape.tail,
        super::bounded_decode::ProofTailShape::None
            | super::bounded_decode::ProofTailShape::RelationOption(None)
    ) {
        return Err(RegionSidecarError::UnsupportedVkShape);
    }

    let leaf_a = CombinedDuplexRegionWalkDeferredProof::new(DuplexUnionWalkDeferredProof {
        selection: relation(leaf_shape.w_log, leaf_shape.selection_values),
        substitution: relation(leaf_shape.w_log, leaf_shape.substitution_values),
        shifts: shifts(leaf_shape.shifts, leaf_shape.w_log),
    });
    let path_b = MerkleRegionWalkDeferredProof::new(MerkleUnionWalkDeferredProof {
        zero: relation(path_shape.w_log, path_shape.zero_values),
        zero_shifts: shifts(path_shape.zero_shifts, path_shape.w_log),
        selection: relation(path_shape.w_log, path_shape.selection_values),
        substitution: relation(path_shape.w_log, path_shape.substitution_values),
        shifts: shifts(path_shape.shifts, path_shape.w_log),
    });
    let rec_c = DuplexRegionWalkDeferredProof::new(
        crate::acceptance::trace::region_source_binding::DuplexUnionWalkDeferredProof {
            selection: relation(rec_shape.w_log, rec_shape.selection_values),
            substitution: relation(rec_shape.w_log, rec_shape.substitution_values),
            shifts: shifts(rec_shape.shifts, rec_shape.w_log),
        },
    );
    Ok(LinkRegionSidecarProof {
        version: LINK_REGION_SIDECAR_VERSION,
        leaf_a,
        path_b,
        rec_c,
        walk: MultiDeepChainWalkProof {
            layers: (0..N_ROUNDS)
                .map(|_| MultiWalkLayerProof {
                    round_coeffs: vec![[F128::ZERO; WALK_DEGREE]; walk_shape.w_log],
                    next_values: vec![[F128::ZERO; 4]; walk_shape.instances],
                })
                .collect(),
        },
    })
}

fn verify_link_region_sidecar<Ch: Challenger>(
    vk: &LinkRegionSidecarVk,
    total_vars: usize,
    proof: &LinkRegionSidecarProof,
    challenger: &mut Ch,
) -> Result<Vec<QuirkyDirectClaim>, RegionSidecarError> {
    vk.validate_roles()?;
    if proof.version != LINK_REGION_SIDECAR_VERSION {
        return Err(RegionSidecarError::UnsupportedVersion);
    }
    bind_link_vk(challenger, vk);
    let leaf_a_prefix = verify_combined_duplex_region_walk_deferred_prefix(
        vk.leaf_a(),
        total_vars,
        &proof.leaf_a,
        challenger,
    )?;
    let path_b_prefix = verify_merkle_region_walk_deferred_prefix(
        vk.path_b(),
        total_vars,
        &proof.path_b,
        challenger,
    )?;
    let rec_c_prefix = verify_recording_duplex_region_walk_deferred_prefix(
        vk.rec_c(),
        total_vars,
        &proof.rec_c,
        challenger,
    )?;
    let groups = vec![
        vec![leaf_a_prefix.group().clone()],
        vec![path_b_prefix.group().clone()],
        vec![rec_c_prefix.group().clone()],
    ];
    let [leaf_a_terminal, path_b_terminal, rec_c_terminal]: [_; 3] =
        verify_ragged_multi_deep_chain_walk(&link_w_logs(vk), &groups, &proof.walk, challenger)
            .map_err(|_| RegionSidecarError::InvalidProof)?
            .try_into()
            .expect("verified leaf-A/path-B/rec-C terminal count");
    let mut claims = leaf_a_prefix.finish(&leaf_a_terminal, challenger)?;
    claims.extend(path_b_prefix.finish(&path_b_terminal, challenger)?);
    claims.extend(rec_c_prefix.finish(&rec_c_terminal, challenger)?);
    Ok(claims)
}

/// Production verifier entry point with an automatic append-only claim sink.
pub fn verify_link_region_sidecar_post_commit<Ch: Challenger>(
    vk: &LinkRegionSidecarVk,
    proof: &LinkRegionSidecarProof,
    context: &mut FieldPostCommitVerifierContext<'_, Ch>,
) -> Result<(), RegionSidecarError> {
    let claims = verify_link_region_sidecar(vk, context.total_vars(), proof, context)?;
    context.append_claims(claims);
    Ok(())
}

/// Recursive trace verifier for the mandatory V4 link sidecar. All three
/// deferred children and the ragged multi-walk are shape-preflighted before
/// the first proof witness is allocated. Prefix, walk, and suffix order
/// exactly matches the native prover/verifier transcript.
pub fn verify_link_region_sidecar_trace_post_commit<C: FsChannelOps>(
    b: &mut FieldR1csBuilder,
    context: &mut FieldPostCommitTraceContext<'_, C>,
    vk: &LinkRegionSidecarVk,
    proof: &LinkRegionSidecarProof,
) -> Result<(), RegionSidecarError> {
    vk.validate_roles()?;
    if proof.version != LINK_REGION_SIDECAR_VERSION {
        return Err(RegionSidecarError::UnsupportedVersion);
    }
    let total_vars = context.total_vars();
    let w_logs = link_w_logs(vk);
    preflight_combined_duplex_region_walk_deferred_trace(vk.leaf_a(), total_vars, &proof.leaf_a)?;
    preflight_merkle_region_walk_deferred_trace(vk.path_b(), total_vars, &proof.path_b)?;
    preflight_recording_duplex_region_walk_deferred(vk.rec_c(), total_vars, &proof.rec_c)?;
    preflight_multi_walk(&proof.walk, max_w_log(&w_logs), w_logs.len())?;

    context.observe_label(b, LINK_REGION_TRANSCRIPT_LABEL);
    crate::acceptance::trace::self_verify::observe_pinned_digest(
        b,
        context,
        &vk.transcript_digest(),
    );
    let mut ledger = b.num_wires();
    let leaf_a_prefix = verify_combined_duplex_region_walk_deferred_prefix_trace(
        b,
        context,
        vk.leaf_a(),
        &proof.leaf_a,
    )?;
    let path_b_prefix =
        verify_merkle_region_walk_deferred_prefix_trace(b, context, vk.path_b(), &proof.path_b)?;
    let rec_c_prefix = verify_recording_duplex_region_walk_deferred_prefix_trace(
        b,
        context,
        vk.rec_c(),
        &proof.rec_c,
    )?;
    crate::acceptance::row_ledger_mark(b, &mut ledger, "link-sidecar: three-child prefixes");

    let groups = vec![
        vec![leaf_a_prefix.walk_group()],
        vec![path_b_prefix.walk_group()],
        vec![rec_c_prefix.walk_group()],
    ];
    let walk = MultiDeepChainWalkProofTrace::alloc_ragged(b, &proof.walk, &w_logs);
    let terminals = verify_ragged_multi_deep_chain_walk_trace(b, context, &w_logs, &groups, &walk);
    if terminals.len() != 3 {
        return Err(RegionSidecarError::InvalidProof);
    }
    let mut terminals = terminals.into_iter();
    let leaf_a_terminal = terminals.next().expect("checked terminal count");
    let path_b_terminal = terminals.next().expect("checked terminal count");
    let rec_c_terminal = terminals.next().expect("checked terminal count");
    crate::acceptance::row_ledger_mark(b, &mut ledger, "link-sidecar: three-child multi-walk");

    let claims = leaf_a_prefix.finish(b, context, &leaf_a_terminal)?;
    context.append_claims(claims);
    let claims = path_b_prefix.finish(b, context, &path_b_terminal)?;
    context.append_claims(claims);
    let claims = rec_c_prefix.finish(b, context, &rec_c_terminal)?;
    context.append_claims(claims);
    crate::acceptance::row_ledger_mark(b, &mut ledger, "link-sidecar: three-child suffixes");
    Ok(())
}

fn preflight_multi_walk(
    proof: &MultiDeepChainWalkProof,
    w_log: usize,
    instances: usize,
) -> Result<(), RegionSidecarError> {
    if instances == 0
        || proof.layers.len() != N_ROUNDS
        || proof
            .layers
            .iter()
            .any(|layer| layer.round_coeffs.len() != w_log || layer.next_values.len() != instances)
    {
        return Err(RegionSidecarError::InvalidProof);
    }
    Ok(())
}

fn link_w_logs(vk: &LinkRegionSidecarVk) -> [usize; 3] {
    [vk.leaf_a().w_log(), vk.path_b().w_log(), vk.rec_c().w_log()]
}

fn max_w_log(w_logs: &[usize]) -> usize {
    *w_logs.iter().max().expect("non-empty link walk group")
}

fn bind_link_vk<Ch: Challenger>(challenger: &mut Ch, vk: &LinkRegionSidecarVk) {
    challenger.observe_label(LINK_REGION_TRANSCRIPT_LABEL);
    challenger.observe_bytes(&vk.transcript_digest());
}

fn push_u64(bytes: &mut Vec<u8>, value: usize) {
    let value = u64::try_from(value).expect("link sidecar class index exceeds u64");
    bytes.extend_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use noid_ivc_core::deep_chain::relations::{
        ColumnRelationProof, ShiftDischargeProof, RELATION_DEGREE,
    };
    use noid_ivc_core::deep_chain::schedule::{compile_duplex, TranscriptOp};
    use noid_ivc_core::deep_chain::{DeepChainWalkProof, MultiWalkLayerProof, WALK_DEGREE};
    use noid_ivc_core::public_io::WitnessSlice;

    use super::super::bounded_decode;
    use super::super::combined_duplex::tests::composite_decode_fixture as combined_fixture;
    use super::super::tests::merkle_decode_fixture_with_purpose;
    use super::*;

    /// Minimal recording vertical fixture: two ghost blocks and a zero-valued
    /// walk-deferred authority of the exact canonical shape.
    fn recording_fixture() -> (
        RecordingDuplexRegionVk,
        usize,
        super::super::DuplexRegionWalkDeferredProof,
        DeepChainWalkProof,
    ) {
        let layout = || {
            compile_duplex(&[
                TranscriptOp::Absorb(vec![None, None]),
                TranscriptOp::Squeeze(1),
            ])
        };
        let block = layout().slots.len().max(1).next_power_of_two();
        let w_log = (2 * block).next_power_of_two().trailing_zeros() as usize;
        let slices = std::array::from_fn(|column| WitnessSlice {
            log2_len: w_log,
            index: 64 + column,
        });
        let vk = RecordingDuplexRegionVk::new(
            link_recordings_purpose(),
            w_log,
            slices,
            vec![(layout(), 0), (layout(), block)],
        )
        .expect("minimal recording vertical fixture");
        let relation = |values: usize| ColumnRelationProof {
            rounds: vec![[noid_ivc_core::field::F128::ZERO; RELATION_DEGREE]; w_log],
            final_values: vec![noid_ivc_core::field::F128::ZERO; values],
        };
        let shifts = (0..4)
            .map(|_| ShiftDischargeProof {
                rounds: vec![[noid_ivc_core::field::F128::ZERO; 2]; w_log],
                final_value: noid_ivc_core::field::F128::ZERO,
            })
            .collect();
        let proof = super::super::DuplexRegionWalkDeferredProof::new(
            crate::acceptance::trace::region_source_binding::DuplexUnionWalkDeferredProof {
                selection: relation(8),
                substitution: relation(6),
                shifts,
            },
        );
        let walk = DeepChainWalkProof {
            layers: (0..N_ROUNDS)
                .map(|_| noid_ivc_core::deep_chain::WalkLayerProof {
                    round_coeffs: vec![[noid_ivc_core::field::F128::ZERO; WALK_DEGREE]; w_log],
                    next_values: [noid_ivc_core::field::F128::ZERO; 4],
                })
                .collect(),
        };
        (vk, 10, proof, walk)
    }

    fn shape_only_multi_walk(walks: &[DeepChainWalkProof]) -> MultiDeepChainWalkProof {
        assert!(!walks.is_empty());
        assert!(walks.iter().all(|walk| walk.layers.len() == N_ROUNDS));
        let widest = walks
            .iter()
            .max_by_key(|walk| walk.layers[0].round_coeffs.len())
            .expect("one shape-only walk");
        MultiDeepChainWalkProof {
            layers: (0..N_ROUNDS)
                .map(|layer| MultiWalkLayerProof {
                    round_coeffs: widest.layers[layer].round_coeffs.clone(),
                    next_values: walks
                        .iter()
                        .map(|walk| walk.layers[layer].next_values)
                        .collect(),
                })
                .collect(),
        }
    }

    #[test]
    fn link_v3_bounded_decode_preflights_children_and_multi_walk_before_serde() {
        let (leaf_vk, leaf_vars, leaf_a) = combined_fixture(link_r_pcs_leaf_sidecar_purpose());
        let (path_vk, path_vars, path_b, _) =
            merkle_decode_fixture_with_purpose(link_r_pcs_path_sidecar_purpose());
        let (rec_vk, rec_vars, rec_c, rec_walk) = recording_fixture();
        let leaf_w_log = leaf_vk.w_log();
        let path_w_log = path_vk.w_log();
        let total_vars = leaf_vars.max(path_vars).max(rec_vars);
        let vk = LinkRegionSidecarVk::new(leaf_vk, path_vk, rec_vk).unwrap();
        let (leaf_a, leaf_a_walk) = leaf_a.into_walk_deferred_parts();
        let (path_b, path_b_walk) = path_b.into_walk_deferred_parts(path_w_log);
        assert_eq!(leaf_a_walk.layers[0].round_coeffs.len(), leaf_w_log);
        let walk = shape_only_multi_walk(&[leaf_a_walk, path_b_walk, rec_walk]);
        let proof = LinkRegionSidecarProof {
            version: LINK_REGION_SIDECAR_VERSION,
            leaf_a,
            path_b,
            rec_c,
            walk,
        };
        let encoded = bincode::serialize(&proof).unwrap();

        let before = bounded_decode::serde_attempts();
        assert_eq!(
            decode_link_region_sidecar_bounded(&vk, total_vars, &encoded).unwrap(),
            proof
        );
        assert_eq!(bounded_decode::serde_attempts(), before + 1);
        let malformed_start = bounded_decode::serde_attempts();

        let mut trailing = encoded.clone();
        trailing.push(0);
        assert_eq!(
            decode_link_region_sidecar_bounded(&vk, total_vars, &trailing).unwrap_err(),
            RegionSidecarError::InvalidProof
        );
        assert_eq!(
            decode_link_region_sidecar_bounded(&vk, total_vars, &encoded[..encoded.len() - 1],)
                .unwrap_err(),
            RegionSidecarError::InvalidProof
        );
        let mut wrong_version = encoded.clone();
        wrong_version[0] = LINK_REGION_SIDECAR_VERSION.wrapping_add(1);
        assert_eq!(
            decode_link_region_sidecar_bounded(&vk, total_vars, &wrong_version).unwrap_err(),
            RegionSidecarError::UnsupportedVersion
        );

        let shapes = link_bounded_shapes(&vk, total_vars).unwrap();
        let offsets = bounded_decode::composite_layout_offsets(
            &encoded,
            LINK_REGION_SIDECAR_VERSION,
            &shapes,
        )
        .unwrap();
        let versions = offsets
            .iter()
            .filter_map(|(field, offset)| {
                (*field == bounded_decode::LayoutField::Version).then_some(*offset)
            })
            .collect::<Vec<_>>();
        assert_eq!(versions.len(), 4, "envelope plus three child versions");
        for offset in &versions[1..] {
            let mut forged = encoded.clone();
            forged[*offset] ^= 1;
            assert_eq!(
                decode_link_region_sidecar_bounded(&vk, total_vars, &forged).unwrap_err(),
                RegionSidecarError::UnsupportedVersion
            );
        }
        for child in 0..3 {
            let start = versions[child + 1];
            let end = versions.get(child + 2).copied().unwrap_or(encoded.len());
            let offset = offsets
                .iter()
                .find_map(|(field, offset)| {
                    (matches!(field, bounded_decode::LayoutField::VecLength(_))
                        && *offset > start
                        && *offset < end)
                        .then_some(*offset)
                })
                .expect("child Vec length");
            let mut forged = encoded.clone();
            forged[offset..offset + 8].copy_from_slice(&u64::MAX.to_le_bytes());
            assert_eq!(
                decode_link_region_sidecar_bounded(&vk, total_vars, &forged).unwrap_err(),
                RegionSidecarError::InvalidProof
            );
        }
        for class in [
            bounded_decode::VecClass::MultiWalkLayers,
            bounded_decode::VecClass::MultiWalkLayerRounds,
            bounded_decode::VecClass::MultiWalkNextInstances,
        ] {
            let offset = offsets
                .iter()
                .find_map(|(field, offset)| {
                    (*field == bounded_decode::LayoutField::VecLength(class)).then_some(*offset)
                })
                .expect("multi-walk Vec length");
            let mut forged_multi = encoded.clone();
            forged_multi[offset..offset + 8].copy_from_slice(&u64::MAX.to_le_bytes());
            assert_eq!(
                decode_link_region_sidecar_bounded(&vk, total_vars, &forged_multi).unwrap_err(),
                RegionSidecarError::InvalidProof
            );
        }
        assert_eq!(
            bounded_decode::serde_attempts(),
            malformed_start,
            "malformed link envelope reached allocation-bearing serde"
        );
    }
}
