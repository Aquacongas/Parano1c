// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Mandatory terminal post-commit authority for one production link proof.
//!
//! Link-local replay has exactly three independent verticals: heterogeneous
//! leaf/transcript Walk L-A, feed-forward Merkle Walk L-B, and the
//! recordings region Walk L-C.  Each proof is a sibling field, never data
//! recorded into another vertical's committed columns.
//!
//! In V5, walk L-C hosts the two transcripts needed by the authenticated
//! parent arm: its block-sidecar child and the `[R]_prev` replay's complete
//! outer Fiat-Shamir channel (which itself contains the previous link's full
//! sidecar verify). One transcript selector is committed and constrained to
//! the same one-hot parent selector used by the recursive verifier. The
//! resulting trust chain, link by link:
//!
//! 1. Link N's CIRCUIT runs both parent verifier arms inline but commits the
//!    selected arm's two Fiat-Shamir transcripts as walk L-C columns: every absorbed
//!    witness lane is pinned to an A-cell, every squeezed challenge to the
//!    carry cell the chain produces it in, and every protocol-constant lane
//!    is a VK fixed pattern.  Nothing about the transcript is proven by the
//!    circuit itself beyond these bindings.
//! 2. Link N's post-commit SIDECAR (proven by link N's prover, bound to
//!    link N's own Field transcript through the post-commit context) proves
//!    L-A, L-B and L-C walks over those committed columns, proving that every
//!    recorded Poseidon chain actually permutes as recorded, from the
//!    capacity IV through every absorb to every challenge cell.
//! 3. Link N+1's `[R]_prev` replay verifies link N's Field proof AND its
//!    complete sidecar (prefixes, the 3-instance ragged multi-walk,
//!    suffixes) — with N+1's own channel traffic recorded into N+1's walk
//!    L-C and proven by N+1's sidecar, and so on up the chain.
//! 4. The induction closes at the tip: the terminal decider natively
//!    verifies the tip link's Field proof and its FULL sidecar
//!    ([`verify_link_region_sidecar_post_commit`], no recording anywhere in
//!    the native path), which covers all three verticals including the two
//!    selected L-C transcripts. A sound tip sidecar makes the tip's recorded
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
use noid_ivc_core::deep_chain::c1::C1LaneClaimGroup;
use noid_ivc_core::deep_chain::{
    prove_ragged_multi_deep_chain_walk, verify_ragged_multi_deep_chain_walk,
    MultiDeepChainWalkProof,
};
use noid_ivc_core::field::F128;
use noid_ivc_core::field_circuit::FsChannelOps;
use noid_ivc_core::pcs::{C1QuirkyDirectClaim, PcsParams, QuirkyDirectClaim};
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
use super::c1_repeat::{WideResponseLowChallenger, SIDECAR_C1_REPETITIONS};
use super::combined_duplex::{
    combined_walk_deferred_bounded_shape, preflight_combined_duplex_region_walk_deferred_trace,
    verify_c1_combined_duplex_region_walk_deferred_prefix,
    verify_combined_duplex_region_walk_deferred_prefix,
    verify_combined_duplex_region_walk_deferred_prefix_trace,
    C1CombinedDuplexRegionWalkDeferredProof, CombinedDuplexRegionWalkDeferredProof,
};
use super::recording_duplex::{
    preflight_recording_duplex_region_walk_deferred, recording_duplex_bounded_shape,
    validate_recording_endpoints, verify_c1_recording_duplex_region_walk_deferred_prefix,
    verify_recording_duplex_region_walk_deferred_prefix,
    verify_recording_duplex_region_walk_deferred_prefix_trace,
    C1RecordingDuplexRegionWalkDeferredProof, RecordingDuplexRegionProverPlan,
    RecordingDuplexRegionVk, RecordingDuplexRegionWalkDeferredProof,
};
use super::{
    preflight_merkle_region_walk_deferred_trace, verify_c1_merkle_region_walk_deferred_prefix,
    verify_merkle_region_walk_deferred_prefix, verify_merkle_region_walk_deferred_prefix_trace,
    C1MerkleRegionWalkDeferredProof, CombinedDuplexRegionProverPlan, CombinedDuplexRegionVk,
    MerkleRegionProverPlan, MerkleRegionVk, MerkleRegionWalkDeferredProof, RegionSidecarError,
    RegionWalkEndpoints,
};

pub const LINK_REGION_SIDECAR_VERSION: u8 = 5;

const LINK_REGION_VK_DIGEST_DOMAIN: &[u8] = b"NOID/REGION-SIDECAR/LINK-VK/V5";
const LINK_POST_COMMIT_CLASS_DIGEST_DOMAIN: &[u8] =
    b"NOID/REGION-SIDECAR/LINK-POST-COMMIT-CLASS/V5";
const LINK_REGION_TRANSCRIPT_LABEL: &[u8] = b"history-region-sidecar-link-v5";
const LINK_C1_REPETITION_LABEL: &[u8] = b"history-region-sidecar-link-c1-repeat-v1";
const LINK_C1_REPETITION_LABELS: [&[u8]; SIDECAR_C1_REPETITIONS] = [
    b"history-region-sidecar-link-c1-repeat-0",
    b"history-region-sidecar-link-c1-repeat-1",
];

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

pub(crate) struct C1LinkRegionProverWalkContinuation<'a, 'z> {
    leaf_a: super::combined_duplex::C1CombinedDuplexRegionProverWalkContinuation<'a, 'z>,
    path_b: super::C1MerkleRegionProverWalkContinuation<'a, 'z>,
    rec_c: super::recording_duplex::C1RecordingDuplexProverWalkContinuation<'a, 'z>,
}

impl C1LinkRegionProverWalkContinuation<'_, '_> {
    pub(crate) fn groups(&self) -> [C1LaneClaimGroup; 3] {
        [
            self.leaf_a.group().clone(),
            self.path_b.group().clone(),
            self.rec_c.group().clone(),
        ]
    }

    pub(crate) fn states(&self) -> [&[Vec<F128>; 4]; 3] {
        [self.leaf_a.s0(), self.path_b.s0(), self.rec_c.s0()]
    }

    pub(crate) fn finish<Ch: Challenger>(
        self,
        terminals: &[C1LaneClaimGroup; 3],
        challenger: &mut Ch,
    ) -> Result<(C1LinkRegionWalkDeferredProof, Vec<C1QuirkyDirectClaim>), RegionSidecarError> {
        let (leaf_a, mut claims) = self.leaf_a.finish(&terminals[0], challenger)?;
        let (path_b, child_claims) = self.path_b.finish(&terminals[1], challenger)?;
        claims.extend(child_claims);
        let (rec_c, child_claims) = self.rec_c.finish(&terminals[2], challenger)?;
        claims.extend(child_claims);
        Ok((
            C1LinkRegionWalkDeferredProof {
                leaf_a,
                path_b,
                rec_c,
            },
            claims,
        ))
    }
}

pub(crate) struct C1LinkRegionVerifierWalkContinuation<'a> {
    leaf_a: super::combined_duplex::C1CombinedDuplexRegionVerifierWalkContinuation<'a>,
    path_b: super::C1MerkleRegionVerifierWalkContinuation<'a>,
    rec_c: super::recording_duplex::C1RecordingDuplexVerifierWalkContinuation<'a>,
}

impl C1LinkRegionVerifierWalkContinuation<'_> {
    pub(crate) fn groups(&self) -> [C1LaneClaimGroup; 3] {
        [
            self.leaf_a.group().clone(),
            self.path_b.group().clone(),
            self.rec_c.group().clone(),
        ]
    }

    pub(crate) fn finish<Ch: Challenger>(
        self,
        terminals: &[C1LaneClaimGroup; 3],
        challenger: &mut Ch,
    ) -> Result<Vec<C1QuirkyDirectClaim>, RegionSidecarError> {
        let mut claims = self.leaf_a.finish(&terminals[0], challenger)?;
        claims.extend(self.path_b.finish(&terminals[1], challenger)?);
        claims.extend(self.rec_c.finish(&terminals[2], challenger)?);
        Ok(claims)
    }
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

    pub(crate) fn prove_c1_walk_deferred_prefix<'z, Ch: Challenger>(
        &self,
        z: &'z [F128],
        challenger: &mut Ch,
    ) -> Result<C1LinkRegionProverWalkContinuation<'a, 'z>, RegionSidecarError> {
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
        Ok(C1LinkRegionProverWalkContinuation {
            leaf_a: leaf_plan.prove_c1_walk_deferred_prefix(z, challenger)?,
            path_b: path_plan.prove_c1_walk_deferred_prefix(z, challenger)?,
            rec_c: rec_plan.prove_c1_walk_deferred_prefix(z, challenger)?,
        })
    }

    fn prove_repetition<Ch: Challenger>(
        &self,
        z: &[F128],
        challenger: &mut Ch,
    ) -> Result<(LinkRegionSidecarRepetitionProof, Vec<QuirkyDirectClaim>), RegionSidecarError>
    {
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
            LinkRegionSidecarRepetitionProof {
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
        context.observe_label(LINK_C1_REPETITION_LABEL);
        let mut repetitions = Vec::with_capacity(SIDECAR_C1_REPETITIONS);
        for label in LINK_C1_REPETITION_LABELS {
            context.observe_label(label);
            let (proof, claims) = {
                let mut channel = WideResponseLowChallenger::new(context);
                self.prove_repetition(witness, &mut channel)?
            };
            context.append_claims(claims);
            repetitions.push(proof);
        }
        Ok(LinkRegionSidecarProof {
            version: LINK_REGION_SIDECAR_VERSION,
            repetitions: repetitions
                .try_into()
                .expect("fixed C1 link-sidecar repetition count"),
        })
    }
}

/// One algebraic repetition of the link authority.  It is private so no
/// caller can present a single base-field transcript as a production proof.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct LinkRegionSidecarRepetitionProof {
    leaf_a: CombinedDuplexRegionWalkDeferredProof,
    path_b: MerkleRegionWalkDeferredProof,
    rec_c: RecordingDuplexRegionWalkDeferredProof,
    walk: MultiDeepChainWalkProof,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct C1LinkRegionWalkDeferredProof {
    leaf_a: C1CombinedDuplexRegionWalkDeferredProof,
    path_b: C1MerkleRegionWalkDeferredProof,
    rec_c: C1RecordingDuplexRegionWalkDeferredProof,
}

pub(crate) fn verify_c1_link_region_walk_deferred_prefix<'a, Ch: Challenger>(
    vk: &'a LinkRegionSidecarVk,
    total_vars: usize,
    proof: &'a C1LinkRegionWalkDeferredProof,
    challenger: &mut Ch,
) -> Result<C1LinkRegionVerifierWalkContinuation<'a>, RegionSidecarError> {
    let timing = std::env::var_os("NOIDH_C1_VERIFY_TIMING").is_some();
    let total_started = std::time::Instant::now();
    vk.validate_roles()?;
    let validate_micros = total_started.elapsed().as_micros();
    bind_link_vk(challenger, vk);
    let bind_micros = total_started.elapsed().as_micros() - validate_micros;
    let leaf_started = std::time::Instant::now();
    let leaf_a = verify_c1_combined_duplex_region_walk_deferred_prefix(
        vk.leaf_a(),
        total_vars,
        &proof.leaf_a,
        challenger,
    )?;
    let leaf_micros = leaf_started.elapsed().as_micros();
    let path_started = std::time::Instant::now();
    let path_b = verify_c1_merkle_region_walk_deferred_prefix(
        vk.path_b(),
        total_vars,
        &proof.path_b,
        challenger,
    )?;
    let path_micros = path_started.elapsed().as_micros();
    let recording_started = std::time::Instant::now();
    let rec_c = verify_c1_recording_duplex_region_walk_deferred_prefix(
        vk.rec_c(),
        total_vars,
        &proof.rec_c,
        challenger,
    )?;
    let recording_micros = recording_started.elapsed().as_micros();
    if timing {
        eprintln!(
            "[link-c1 prefix] validate_us={validate_micros} bind_us={bind_micros} leaf_us={leaf_micros} path_us={path_micros} recording_us={recording_micros} total_us={}",
            total_started.elapsed().as_micros(),
        );
    }
    Ok(C1LinkRegionVerifierWalkContinuation {
        leaf_a,
        path_b,
        rec_c,
    })
}

/// Fixed V5 link sidecar.  All three children retain their complete
/// role-local prefix/suffix authority; only their deep-chain walks are
/// reduced by one mandatory ragged-domain multi-instance proof.  Two
/// sequential repetitions consume independent C1-wide response streams.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LinkRegionSidecarProof {
    version: u8,
    repetitions: [LinkRegionSidecarRepetitionProof; SIDECAR_C1_REPETITIONS],
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

    let [SidecarProofShape::DeferredFixed(leaf_shape), SidecarProofShape::DeferredMerkle(path_shape), SidecarProofShape::RecordingDeferredFixed(rec_shape), SidecarProofShape::MultiWalk(walk_shape)] =
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
    for repetition in &proof.repetitions {
        canonical::encode_duplex_deferred(
            &mut out,
            repetition.leaf_a.version(),
            repetition.leaf_a.authority(),
            &leaf_shape,
        )?;
        canonical::encode_merkle_deferred(
            &mut out,
            repetition.path_b.version(),
            repetition.path_b.authority(),
            &path_shape,
        )?;
        preflight_recording_duplex_region_walk_deferred(vk.rec_c(), total_vars, &repetition.rec_c)?;
        canonical::put_f128(&mut out, repetition.rec_c.selector());
        canonical::encode_duplex_deferred(
            &mut out,
            repetition.rec_c.version(),
            repetition.rec_c.authority(),
            &rec_shape,
        )?;
        canonical::encode_multi_walk(&mut out, &repetition.walk, &walk_shape)?;
    }
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

    let [SidecarProofShape::DeferredFixed(leaf_shape), SidecarProofShape::DeferredMerkle(path_shape), SidecarProofShape::RecordingDeferredFixed(rec_shape), SidecarProofShape::MultiWalk(walk_shape)] =
        link_bounded_shapes(vk, total_vars)?
    else {
        return Err(RegionSidecarError::UnsupportedVkShape);
    };
    let expected = canonical_link_region_sidecar_len(vk, total_vars)?;
    let mut reader = canonical::CanonicalProofReader::exact(bytes, expected)?;
    if reader.u8()? != LINK_REGION_SIDECAR_VERSION {
        return Err(RegionSidecarError::UnsupportedVersion);
    }
    let mut repetitions = Vec::with_capacity(SIDECAR_C1_REPETITIONS);
    for _ in 0..SIDECAR_C1_REPETITIONS {
        let leaf_a = CombinedDuplexRegionWalkDeferredProof::new(canonical::decode_duplex_deferred(
            &mut reader,
            &leaf_shape,
        )?);
        let path_b = MerkleRegionWalkDeferredProof::new(canonical::decode_merkle_deferred(
            &mut reader,
            &path_shape,
        )?);
        let rec_selector = reader.f128()?;
        let rec_c = RecordingDuplexRegionWalkDeferredProof::new(
            rec_selector,
            canonical::decode_duplex_deferred(&mut reader, &rec_shape)?,
        );
        preflight_recording_duplex_region_walk_deferred(vk.rec_c(), total_vars, &rec_c)?;
        let walk = canonical::decode_multi_walk(&mut reader, &walk_shape)?;
        repetitions.push(LinkRegionSidecarRepetitionProof {
            leaf_a,
            path_b,
            rec_c,
            walk,
        });
    }
    reader.finish()?;
    Ok(LinkRegionSidecarProof {
        version: LINK_REGION_SIDECAR_VERSION,
        repetitions: repetitions
            .try_into()
            .expect("fixed C1 link-sidecar repetition count"),
    })
}

pub(crate) fn canonical_link_region_sidecar_len(
    vk: &LinkRegionSidecarVk,
    total_vars: usize,
) -> Result<usize, RegionSidecarError> {
    use super::canonical_codec as canonical;

    let [SidecarProofShape::DeferredFixed(leaf_shape), SidecarProofShape::DeferredMerkle(path_shape), SidecarProofShape::RecordingDeferredFixed(rec_shape), SidecarProofShape::MultiWalk(walk_shape)] =
        link_bounded_shapes(vk, total_vars)?
    else {
        return Err(RegionSidecarError::UnsupportedVkShape);
    };
    let repetition_len = [
        canonical::deferred_fixed_len(&leaf_shape)?,
        canonical::deferred_merkle_len(&path_shape)?,
        canonical::deferred_fixed_len(&rec_shape)?
            .checked_add(16)
            .ok_or(RegionSidecarError::InvalidProof)?,
        canonical::multi_walk_len(&walk_shape)?,
    ]
    .into_iter()
    .try_fold(0usize, |sum, len| {
        sum.checked_add(len).ok_or(RegionSidecarError::InvalidProof)
    })?;
    repetition_len
        .checked_mul(SIDECAR_C1_REPETITIONS)
        .and_then(|len| len.checked_add(1))
        .ok_or(RegionSidecarError::InvalidProof)
}

/// Decode the mandatory V5 link envelope only after both repetitions of all
/// three deferred children and their shared multi-walk have passed one
/// allocation-free, class-aware bincode scan.
pub fn decode_link_region_sidecar_bounded(
    vk: &LinkRegionSidecarVk,
    total_vars: usize,
    bytes: &[u8],
) -> Result<LinkRegionSidecarProof, RegionSidecarError> {
    let shapes = link_bounded_shapes(vk, total_vars)?;
    let repeated_shapes = (0..SIDECAR_C1_REPETITIONS)
        .flat_map(|_| shapes.iter().cloned())
        .collect::<Vec<_>>();
    preflight_composite_proof(bytes, LINK_REGION_SIDECAR_VERSION, &repeated_shapes)?;
    record_serde_attempt();
    let proof: LinkRegionSidecarProof =
        bincode::deserialize(bytes).map_err(|_| RegionSidecarError::InvalidProof)?;
    if proof.version != LINK_REGION_SIDECAR_VERSION {
        return Err(RegionSidecarError::UnsupportedVersion);
    }
    let w_logs = link_w_logs(vk);
    for repetition in &proof.repetitions {
        preflight_combined_duplex_region_walk_deferred_trace(
            vk.leaf_a(),
            total_vars,
            &repetition.leaf_a,
        )?;
        preflight_merkle_region_walk_deferred_trace(vk.path_b(), total_vars, &repetition.path_b)?;
        preflight_recording_duplex_region_walk_deferred(vk.rec_c(), total_vars, &repetition.rec_c)?;
        preflight_multi_walk(&repetition.walk, max_w_log(&w_logs), w_logs.len())?;
    }
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
        SidecarProofShape::RecordingDeferredFixed(
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
    let [SidecarProofShape::DeferredFixed(leaf_shape), SidecarProofShape::DeferredMerkle(path_shape), SidecarProofShape::RecordingDeferredFixed(rec_shape), SidecarProofShape::MultiWalk(walk_shape)] =
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
    let rec_c = RecordingDuplexRegionWalkDeferredProof::new(
        F128::ZERO,
        crate::acceptance::trace::region_source_binding::DuplexUnionWalkDeferredProof {
            selection: relation(rec_shape.w_log, rec_shape.selection_values),
            substitution: relation(rec_shape.w_log, rec_shape.substitution_values),
            shifts: shifts(rec_shape.shifts, rec_shape.w_log),
        },
    );
    let repetition = LinkRegionSidecarRepetitionProof {
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
    };
    Ok(LinkRegionSidecarProof {
        version: LINK_REGION_SIDECAR_VERSION,
        repetitions: [repetition.clone(), repetition],
    })
}

fn verify_link_region_sidecar_repetition<Ch: Challenger>(
    vk: &LinkRegionSidecarVk,
    total_vars: usize,
    proof: &LinkRegionSidecarRepetitionProof,
    challenger: &mut Ch,
) -> Result<Vec<QuirkyDirectClaim>, RegionSidecarError> {
    macro_rules! verify_stage {
        ($label:literal, $expression:expr) => {
            match $expression {
                Ok(value) => value,
                Err(error) => {
                    if std::env::var_os("NOID_HISTORY_STEP_AUX_DEBUG").is_some() {
                        eprintln!("[link-sidecar verify] {}: {error:?}", $label);
                    }
                    return Err(error);
                }
            }
        };
    }

    vk.validate_roles()?;
    bind_link_vk(challenger, vk);
    let leaf_a_prefix = verify_stage!(
        "leaf-A prefix",
        verify_combined_duplex_region_walk_deferred_prefix(
            vk.leaf_a(),
            total_vars,
            &proof.leaf_a,
            challenger,
        )
    );
    let path_b_prefix = verify_stage!(
        "path-B prefix",
        verify_merkle_region_walk_deferred_prefix(
            vk.path_b(),
            total_vars,
            &proof.path_b,
            challenger,
        )
    );
    let rec_c_prefix = verify_stage!(
        "recording-C prefix",
        verify_recording_duplex_region_walk_deferred_prefix(
            vk.rec_c(),
            total_vars,
            &proof.rec_c,
            challenger,
        )
    );
    let groups = vec![
        vec![leaf_a_prefix.group().clone()],
        vec![path_b_prefix.group().clone()],
        vec![rec_c_prefix.group().clone()],
    ];
    let [leaf_a_terminal, path_b_terminal, rec_c_terminal]: [_; 3] = verify_stage!(
        "three-child multi-walk",
        verify_ragged_multi_deep_chain_walk(&link_w_logs(vk), &groups, &proof.walk, challenger,)
            .map_err(|_| RegionSidecarError::InvalidProof)
    )
    .try_into()
    .expect("verified leaf-A/path-B/rec-C terminal count");
    let mut claims = verify_stage!(
        "leaf-A finish",
        leaf_a_prefix.finish(&leaf_a_terminal, challenger)
    );
    claims.extend(verify_stage!(
        "path-B finish",
        path_b_prefix.finish(&path_b_terminal, challenger)
    ));
    claims.extend(verify_stage!(
        "recording-C finish",
        rec_c_prefix.finish(&rec_c_terminal, challenger)
    ));
    Ok(claims)
}

/// Production verifier entry point with an automatic append-only claim sink.
pub fn verify_link_region_sidecar_post_commit<Ch: Challenger>(
    vk: &LinkRegionSidecarVk,
    proof: &LinkRegionSidecarProof,
    context: &mut FieldPostCommitVerifierContext<'_, Ch>,
) -> Result<(), RegionSidecarError> {
    if proof.version != LINK_REGION_SIDECAR_VERSION {
        return Err(RegionSidecarError::UnsupportedVersion);
    }
    context.observe_label(LINK_C1_REPETITION_LABEL);
    for (label, repetition) in LINK_C1_REPETITION_LABELS
        .into_iter()
        .zip(&proof.repetitions)
    {
        context.observe_label(label);
        let claims = {
            let total_vars = context.total_vars();
            let mut channel = WideResponseLowChallenger::new(context);
            verify_link_region_sidecar_repetition(vk, total_vars, repetition, &mut channel)?
        };
        context.append_claims(claims);
    }
    Ok(())
}

/// Recursive trace verifier for the mandatory V5 link sidecar. Both complete
/// repetitions are shape-preflighted before the first proof witness is
/// allocated. Each repetition then runs against C1-wide responses projected
/// to their uniform low coordinate.
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
    for repetition in &proof.repetitions {
        preflight_combined_duplex_region_walk_deferred_trace(
            vk.leaf_a(),
            total_vars,
            &repetition.leaf_a,
        )?;
        preflight_merkle_region_walk_deferred_trace(vk.path_b(), total_vars, &repetition.path_b)?;
        preflight_recording_duplex_region_walk_deferred(vk.rec_c(), total_vars, &repetition.rec_c)?;
        preflight_multi_walk(&repetition.walk, max_w_log(&w_logs), w_logs.len())?;
    }

    context.observe_label(b, LINK_C1_REPETITION_LABEL);
    for (label, repetition) in LINK_C1_REPETITION_LABELS
        .into_iter()
        .zip(&proof.repetitions)
    {
        context.observe_label(b, label);
        context.set_wide_response_low(true);
        let result = verify_link_region_sidecar_repetition_trace(b, context, vk, repetition);
        context.set_wide_response_low(false);
        result?;
    }
    Ok(())
}

fn verify_link_region_sidecar_repetition_trace<C: FsChannelOps>(
    b: &mut FieldR1csBuilder,
    context: &mut FieldPostCommitTraceContext<'_, C>,
    vk: &LinkRegionSidecarVk,
    proof: &LinkRegionSidecarRepetitionProof,
) -> Result<(), RegionSidecarError> {
    let w_logs = link_w_logs(vk);
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
    fn recording_fixture_for_selector(
        selector: Option<F128>,
    ) -> (
        RecordingDuplexRegionVk,
        usize,
        RecordingDuplexRegionWalkDeferredProof,
        DeepChainWalkProof,
    ) {
        let layout = || {
            compile_duplex(&[
                TranscriptOp::Absorb(vec![None, None, None, None]),
                TranscriptOp::Squeeze(1),
            ])
        };
        let block = layout().slots.len().max(1).next_power_of_two();
        let w_log = (2 * block).next_power_of_two().trailing_zeros() as usize;
        let slices = std::array::from_fn(|column| WitnessSlice {
            log2_len: w_log,
            index: 64 + column,
        });
        let blocks = vec![(layout(), 0), (layout(), block)];
        let vk = match selector {
            Some(_) => RecordingDuplexRegionVk::new_selected(
                link_recordings_purpose(),
                w_log,
                slices,
                WitnessSlice {
                    log2_len: 0,
                    index: 900,
                },
                [blocks.clone(), blocks],
            ),
            None => RecordingDuplexRegionVk::new(link_recordings_purpose(), w_log, slices, blocks),
        }
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
        let proof = RecordingDuplexRegionWalkDeferredProof::new(
            selector.unwrap_or(F128::ZERO),
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

    fn recording_fixture() -> (
        RecordingDuplexRegionVk,
        usize,
        RecordingDuplexRegionWalkDeferredProof,
        DeepChainWalkProof,
    ) {
        recording_fixture_for_selector(None)
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
    fn link_sidecar_trace_row_ledger() {
        use noid_ivc_core::field_circuit::{FsChannelTrace, FsChannelUnionRecorder};

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
        let repetition = LinkRegionSidecarRepetitionProof {
            leaf_a,
            path_b,
            rec_c,
            walk: shape_only_multi_walk(&[leaf_a_walk, path_b_walk, rec_walk]),
        };
        let proof = LinkRegionSidecarProof {
            version: LINK_REGION_SIDECAR_VERSION,
            repetitions: [repetition.clone(), repetition],
        };
        let mut builder = FieldR1csBuilder::new_witness_only();
        let root = [
            crate::acceptance::trace::LinExpr::zero(),
            crate::acceptance::trace::LinExpr::zero(),
        ];
        let mut channel = FsChannelTrace::new_c1(&mut builder, b"link-sidecar-row-ledger-c1");
        let mut context = FieldPostCommitTraceContext::detached(&root, total_vars, &mut channel);
        let start = builder.num_wires();
        verify_link_region_sidecar_trace_post_commit(&mut builder, &mut context, &vk, &proof)
            .unwrap();
        eprintln!(
            "[sidecar-row-ledger] link: {} wires",
            builder.num_wires() - start
        );

        let mut builder = FieldR1csBuilder::new_witness_only();
        let root = [
            crate::acceptance::trace::LinExpr::zero(),
            crate::acceptance::trace::LinExpr::zero(),
        ];
        let mut channel = FsChannelUnionRecorder::new_c1(b"link-sidecar-recorded-row-ledger-c1");
        let mut context = FieldPostCommitTraceContext::detached(&root, total_vars, &mut channel);
        let start = builder.num_wires();
        verify_link_region_sidecar_trace_post_commit(&mut builder, &mut context, &vk, &proof)
            .unwrap();
        eprintln!(
            "[sidecar-row-ledger] link-recorded: {} wires, {} ops",
            builder.num_wires() - start,
            channel.finish().ops.len(),
        );
    }

    #[test]
    fn selected_recording_selector_roundtrips_and_rejects_non_boolean_values() {
        let (leaf_vk, leaf_vars, leaf_a) = combined_fixture(link_r_pcs_leaf_sidecar_purpose());
        let (path_vk, path_vars, path_b, _) =
            merkle_decode_fixture_with_purpose(link_r_pcs_path_sidecar_purpose());
        let (rec_vk, rec_vars, rec_c, rec_walk) = recording_fixture_for_selector(Some(F128::ZERO));
        let leaf_w_log = leaf_vk.w_log();
        let path_w_log = path_vk.w_log();
        let total_vars = leaf_vars.max(path_vars).max(rec_vars);
        let vk = LinkRegionSidecarVk::new(leaf_vk, path_vk, rec_vk).unwrap();
        let (leaf_a, leaf_a_walk) = leaf_a.into_walk_deferred_parts();
        let (path_b, path_b_walk) = path_b.into_walk_deferred_parts(path_w_log);
        assert_eq!(leaf_a_walk.layers[0].round_coeffs.len(), leaf_w_log);
        let walk = shape_only_multi_walk(&[leaf_a_walk, path_b_walk, rec_walk]);
        let proof_with_selector = |selector| {
            let repetition = LinkRegionSidecarRepetitionProof {
                leaf_a: leaf_a.clone(),
                path_b: path_b.clone(),
                rec_c: RecordingDuplexRegionWalkDeferredProof::new(
                    selector,
                    rec_c.authority().clone(),
                ),
                walk: walk.clone(),
            };
            LinkRegionSidecarProof {
                version: LINK_REGION_SIDECAR_VERSION,
                repetitions: [repetition.clone(), repetition],
            }
        };

        for selector in [F128::ZERO, F128::ONE] {
            let proof = proof_with_selector(selector);
            let canonical = encode_link_region_sidecar_canonical(&vk, total_vars, &proof).unwrap();
            assert_eq!(
                decode_link_region_sidecar_canonical(&vk, total_vars, &canonical).unwrap(),
                proof
            );
            let bincode = bincode::serialize(&proof).unwrap();
            assert_eq!(
                decode_link_region_sidecar_bounded(&vk, total_vars, &bincode).unwrap(),
                proof
            );
        }

        let non_boolean = F128 { lo: 2, hi: 0 };
        let forged = proof_with_selector(non_boolean);
        assert_eq!(
            encode_link_region_sidecar_canonical(&vk, total_vars, &forged).unwrap_err(),
            RegionSidecarError::InvalidProof
        );
        let forged_bincode = bincode::serialize(&forged).unwrap();
        let before = bounded_decode::serde_attempts();
        assert_eq!(
            decode_link_region_sidecar_bounded(&vk, total_vars, &forged_bincode).unwrap_err(),
            RegionSidecarError::InvalidProof
        );
        assert_eq!(bounded_decode::serde_attempts(), before + 1);

        let zero_proof = proof_with_selector(F128::ZERO);
        let mut forged_canonical =
            encode_link_region_sidecar_canonical(&vk, total_vars, &zero_proof).unwrap();
        let [SidecarProofShape::DeferredFixed(leaf_shape), SidecarProofShape::DeferredMerkle(path_shape), SidecarProofShape::RecordingDeferredFixed(_), SidecarProofShape::MultiWalk(_)] =
            link_bounded_shapes(&vk, total_vars).unwrap()
        else {
            panic!("canonical selected Link shape");
        };
        let selector_offset = 1
            + super::super::canonical_codec::deferred_fixed_len(&leaf_shape).unwrap()
            + super::super::canonical_codec::deferred_merkle_len(&path_shape).unwrap();
        let mut selector_bytes = Vec::new();
        super::super::canonical_codec::put_f128(&mut selector_bytes, non_boolean);
        forged_canonical[selector_offset..selector_offset + selector_bytes.len()]
            .copy_from_slice(&selector_bytes);
        assert_eq!(
            decode_link_region_sidecar_canonical(&vk, total_vars, &forged_canonical).unwrap_err(),
            RegionSidecarError::InvalidProof
        );
    }

    #[test]
    fn link_v5_bounded_decode_preflights_both_repetitions_before_serde() {
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
        let repetition = LinkRegionSidecarRepetitionProof {
            leaf_a,
            path_b,
            rec_c,
            walk,
        };
        let proof = LinkRegionSidecarProof {
            version: LINK_REGION_SIDECAR_VERSION,
            repetitions: [repetition.clone(), repetition],
        };
        let canonical = encode_link_region_sidecar_canonical(&vk, total_vars, &proof).unwrap();
        assert_eq!(
            canonical.len(),
            canonical_link_region_sidecar_len(&vk, total_vars).unwrap()
        );
        assert_eq!(
            decode_link_region_sidecar_canonical(&vk, total_vars, &canonical).unwrap(),
            proof
        );
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
        let repeated_shapes = (0..SIDECAR_C1_REPETITIONS)
            .flat_map(|_| shapes.iter().cloned())
            .collect::<Vec<_>>();
        let offsets = bounded_decode::composite_layout_offsets(
            &encoded,
            LINK_REGION_SIDECAR_VERSION,
            &repeated_shapes,
        )
        .unwrap();
        let versions = offsets
            .iter()
            .filter_map(|(field, offset)| {
                (*field == bounded_decode::LayoutField::Version).then_some(*offset)
            })
            .collect::<Vec<_>>();
        assert_eq!(
            versions.len(),
            1 + 3 * SIDECAR_C1_REPETITIONS,
            "envelope plus three child versions per repetition"
        );
        for offset in &versions[1..] {
            let mut forged = encoded.clone();
            forged[*offset] ^= 1;
            assert_eq!(
                decode_link_region_sidecar_bounded(&vk, total_vars, &forged).unwrap_err(),
                RegionSidecarError::UnsupportedVersion
            );
        }
        for child in 0..(3 * SIDECAR_C1_REPETITIONS) {
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
