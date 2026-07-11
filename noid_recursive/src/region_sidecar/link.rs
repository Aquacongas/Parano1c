// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Mandatory terminal post-commit authority for one production link proof.
//!
//! Link-local PCS replay has exactly two independent verticals: heterogeneous
//! leaf/transcript Walk L-A and feed-forward Merkle Walk L-B.  The L-B proof
//! is a sibling field, never data recorded into L-A's committed columns.

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
    link_r_pcs_leaf_sidecar_purpose, link_r_pcs_path_sidecar_purpose,
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
use super::{
    preflight_merkle_region_walk_deferred_trace, verify_merkle_region_walk_deferred_prefix,
    verify_merkle_region_walk_deferred_prefix_trace, CombinedDuplexRegionProverPlan,
    CombinedDuplexRegionVk, MerkleRegionProverPlan, MerkleRegionVk, MerkleRegionWalkDeferredProof,
    RegionSidecarError, RegionWalkEndpoints,
};

pub const LINK_REGION_SIDECAR_VERSION: u8 = 2;

const LINK_REGION_VK_DIGEST_DOMAIN: &[u8] = b"NOID/REGION-SIDECAR/LINK-VK/V2";
const LINK_POST_COMMIT_CLASS_DIGEST_DOMAIN: &[u8] =
    b"NOID/REGION-SIDECAR/LINK-POST-COMMIT-CLASS/V2";
const LINK_REGION_TRANSCRIPT_LABEL: &[u8] = b"history-region-sidecar-link-v2";

/// Canonical key for the two mandatory link-region verticals.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinkRegionSidecarVk {
    leaf_a: CombinedDuplexRegionVk,
    path_b: MerkleRegionVk,
}

impl LinkRegionSidecarVk {
    pub fn new(
        leaf_a: CombinedDuplexRegionVk,
        path_b: MerkleRegionVk,
    ) -> Result<Self, RegionSidecarError> {
        let vk = Self { leaf_a, path_b };
        vk.validate_roles()?;
        Ok(vk)
    }

    pub fn leaf_a(&self) -> &CombinedDuplexRegionVk {
        &self.leaf_a
    }

    pub fn path_b(&self) -> &MerkleRegionVk {
        &self.path_b
    }

    pub fn transcript_digest(&self) -> [u8; 32] {
        let version = [LINK_REGION_SIDECAR_VERSION];
        poseidon2b_hash_byte_slices(
            LINK_REGION_VK_DIGEST_DOMAIN,
            &[
                &version,
                b"leaf-a",
                &self.leaf_a.transcript_digest(),
                b"path-b",
                &self.path_b.transcript_digest(),
            ],
        )
    }

    fn validate_roles(&self) -> Result<(), RegionSidecarError> {
        if self.leaf_a.purpose() != &link_r_pcs_leaf_sidecar_purpose()
            || self.path_b.purpose() != &link_r_pcs_path_sidecar_purpose()
        {
            return Err(RegionSidecarError::UnsupportedVkShape);
        }
        Ok(())
    }
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
}

impl LinkRegionProverInput {
    pub fn new(
        vk: &LinkRegionSidecarVk,
        leaf_a: RegionWalkEndpoints,
        path_b: RegionWalkEndpoints,
    ) -> Result<Self, RegionSidecarError> {
        vk.validate_roles()?;
        let input = Self { leaf_a, path_b };
        input.validate(vk)?;
        Ok(input)
    }

    fn validate(&self, vk: &LinkRegionSidecarVk) -> Result<(), RegionSidecarError> {
        CombinedDuplexRegionProverPlan::new(vk.leaf_a(), self.leaf_a.s0(), self.leaf_a.s_out())?;
        MerkleRegionProverPlan::new(vk.path_b(), self.path_b.s0(), self.path_b.s_out())?;
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
        let leaf_a_prefix = leaf_plan.prove_walk_deferred_prefix(z, challenger)?;
        let path_b_prefix = path_plan.prove_walk_deferred_prefix(z, challenger)?;
        let groups = vec![
            vec![leaf_a_prefix.group().clone()],
            vec![path_b_prefix.group().clone()],
        ];
        let s0 = [leaf_a_prefix.s0(), path_b_prefix.s0()];
        let (leaf_a_path_b_walk, terminals) =
            prove_ragged_multi_deep_chain_walk(&s0, &groups, challenger);
        let [leaf_a_terminal, path_b_terminal]: [_; 2] = terminals
            .try_into()
            .expect("leaf-A/path-B multi-walk terminal count");
        let (leaf_a, mut claims) = leaf_a_prefix.finish(&leaf_a_terminal, challenger)?;
        let (path_b, path_claims) = path_b_prefix.finish(&path_b_terminal, challenger)?;
        claims.extend(path_claims);

        Ok((
            LinkRegionSidecarProof {
                version: LINK_REGION_SIDECAR_VERSION,
                leaf_a,
                path_b,
                leaf_a_path_b_walk,
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

/// Fixed V2 link sidecar.  Both children retain their complete role-local
/// prefix/suffix authority; only their deep-chain walks are reduced by one
/// mandatory ragged-domain multi-instance proof.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LinkRegionSidecarProof {
    version: u8,
    leaf_a: CombinedDuplexRegionWalkDeferredProof,
    path_b: MerkleRegionWalkDeferredProof,
    leaf_a_path_b_walk: MultiDeepChainWalkProof,
}

impl LinkRegionSidecarProof {
    pub fn byte_len(&self) -> usize {
        bincode::serialized_size(self).expect("link region sidecar serialized length") as usize
    }

    pub(crate) fn leaf_a(&self) -> &CombinedDuplexRegionWalkDeferredProof {
        &self.leaf_a
    }

    pub(crate) fn path_b(&self) -> &MerkleRegionWalkDeferredProof {
        &self.path_b
    }

    #[cfg(test)]
    pub(crate) fn with_multi_walk_message_mutated(
        &self,
        vk: &LinkRegionSidecarVk,
        total_vars: usize,
    ) -> Self {
        self.with_first_vec_payload_mutated(
            vk,
            total_vars,
            super::bounded_decode::VecClass::MultiWalkLayerRounds,
        )
    }

    #[cfg(test)]
    pub(crate) fn with_leaf_prefix_message_mutated(
        &self,
        vk: &LinkRegionSidecarVk,
        total_vars: usize,
    ) -> Self {
        self.with_first_vec_payload_mutated(
            vk,
            total_vars,
            super::bounded_decode::VecClass::SelectionRounds,
        )
    }

    #[cfg(test)]
    pub(crate) fn with_path_prefix_message_mutated(
        &self,
        vk: &LinkRegionSidecarVk,
        total_vars: usize,
    ) -> Self {
        self.with_first_vec_payload_mutated(
            vk,
            total_vars,
            super::bounded_decode::VecClass::ZeroRounds,
        )
    }

    #[cfg(test)]
    fn with_first_vec_payload_mutated(
        &self,
        vk: &LinkRegionSidecarVk,
        total_vars: usize,
        target: super::bounded_decode::VecClass,
    ) -> Self {
        let mut bytes = bincode::serialize(self).expect("serialize Link mutation fixture");
        let shapes = link_bounded_shapes(vk, total_vars).expect("valid Link mutation VK");
        let offsets = super::bounded_decode::composite_layout_offsets(
            &bytes,
            LINK_REGION_SIDECAR_VERSION,
            &shapes,
        )
        .expect("valid Link mutation proof shape");
        let length_offset = offsets
            .into_iter()
            .find_map(|(field, offset)| {
                (field == super::bounded_decode::LayoutField::VecLength(target)).then_some(offset)
            })
            .expect("target Link proof message exists");
        bytes[length_offset + 8] ^= 1;
        bincode::deserialize(&bytes).expect("shape-preserving Link proof mutation")
    }
}

/// Decode the mandatory V2 link envelope only after both deferred children
/// and their shared multi-walk have passed one allocation-free, class-aware
/// bincode scan.
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
    let w_logs = link_w_logs(vk);
    preflight_multi_walk(&proof.leaf_a_path_b_walk, max_w_log(&w_logs), w_logs.len())?;
    Ok(proof)
}

fn link_bounded_shapes(
    vk: &LinkRegionSidecarVk,
    total_vars: usize,
) -> Result<[SidecarProofShape; 3], RegionSidecarError> {
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
        SidecarProofShape::MultiWalk(multi_walk_proof_shape(max_w_log(&w_logs), w_logs.len())?),
    ])
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
    let groups = vec![
        vec![leaf_a_prefix.group().clone()],
        vec![path_b_prefix.group().clone()],
    ];
    let [leaf_a_terminal, path_b_terminal]: [_; 2] = verify_ragged_multi_deep_chain_walk(
        &link_w_logs(vk),
        &groups,
        &proof.leaf_a_path_b_walk,
        challenger,
    )
    .map_err(|_| RegionSidecarError::InvalidProof)?
    .try_into()
    .expect("verified leaf-A/path-B terminal count");
    let mut claims = leaf_a_prefix.finish(&leaf_a_terminal, challenger)?;
    claims.extend(path_b_prefix.finish(&path_b_terminal, challenger)?);
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

/// Recursive trace verifier for the mandatory V2 link sidecar. Both deferred
/// children and the ragged multi-walk are shape-preflighted before the first
/// proof witness is allocated. Prefix, walk, and suffix order exactly matches
/// the native prover/verifier transcript.
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
    preflight_multi_walk(&proof.leaf_a_path_b_walk, max_w_log(&w_logs), w_logs.len())?;

    context.observe_label(b, LINK_REGION_TRANSCRIPT_LABEL);
    context.observe_bytes_const(b, &vk.transcript_digest());
    let mut ledger = b.num_wires();
    let leaf_a_prefix = verify_combined_duplex_region_walk_deferred_prefix_trace(
        b,
        context,
        vk.leaf_a(),
        &proof.leaf_a,
    )?;
    let path_b_prefix =
        verify_merkle_region_walk_deferred_prefix_trace(b, context, vk.path_b(), &proof.path_b)?;
    crate::acceptance::row_ledger_mark(b, &mut ledger, "link-sidecar: leaf-A/path-B prefixes");

    let groups = vec![
        vec![leaf_a_prefix.walk_group()],
        vec![path_b_prefix.walk_group()],
    ];
    let walk = MultiDeepChainWalkProofTrace::alloc_ragged(b, &proof.leaf_a_path_b_walk, &w_logs);
    let terminals = verify_ragged_multi_deep_chain_walk_trace(b, context, &w_logs, &groups, &walk);
    if terminals.len() != 2 {
        return Err(RegionSidecarError::InvalidProof);
    }
    let mut terminals = terminals.into_iter();
    let leaf_a_terminal = terminals.next().expect("checked terminal count");
    let path_b_terminal = terminals.next().expect("checked terminal count");
    crate::acceptance::row_ledger_mark(b, &mut ledger, "link-sidecar: leaf-A/path-B multi-walk");

    let claims = leaf_a_prefix.finish(b, context, &leaf_a_terminal)?;
    context.append_claims(claims);
    let claims = path_b_prefix.finish(b, context, &path_b_terminal)?;
    context.append_claims(claims);
    crate::acceptance::row_ledger_mark(b, &mut ledger, "link-sidecar: leaf-A/path-B suffixes");
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

fn link_w_logs(vk: &LinkRegionSidecarVk) -> [usize; 2] {
    [vk.leaf_a().w_log(), vk.path_b().w_log()]
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
    use noid_ivc_core::deep_chain::{DeepChainWalkProof, MultiWalkLayerProof};

    use super::super::bounded_decode;
    use super::super::combined_duplex::tests::composite_decode_fixture as combined_fixture;
    use super::super::tests::merkle_decode_fixture_with_purpose;
    use super::*;

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
    fn link_v2_bounded_decode_preflights_children_and_multi_walk_before_serde() {
        let (leaf_vk, leaf_vars, leaf_a) = combined_fixture(link_r_pcs_leaf_sidecar_purpose());
        let (path_vk, path_vars, path_b, _) =
            merkle_decode_fixture_with_purpose(link_r_pcs_path_sidecar_purpose());
        let leaf_w_log = leaf_vk.w_log();
        let path_w_log = path_vk.w_log();
        let total_vars = leaf_vars.max(path_vars);
        let vk = LinkRegionSidecarVk::new(leaf_vk, path_vk).unwrap();
        let (leaf_a, leaf_a_walk) = leaf_a.into_walk_deferred_parts();
        let (path_b, path_b_walk) = path_b.into_walk_deferred_parts(path_w_log);
        assert_eq!(leaf_a_walk.layers[0].round_coeffs.len(), leaf_w_log);
        let leaf_a_path_b_walk = shape_only_multi_walk(&[leaf_a_walk, path_b_walk]);
        let proof = LinkRegionSidecarProof {
            version: LINK_REGION_SIDECAR_VERSION,
            leaf_a,
            path_b,
            leaf_a_path_b_walk,
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
        assert_eq!(versions.len(), 3, "envelope plus two child versions");
        for offset in &versions[1..] {
            let mut forged = encoded.clone();
            forged[*offset] ^= 1;
            assert_eq!(
                decode_link_region_sidecar_bounded(&vk, total_vars, &forged).unwrap_err(),
                RegionSidecarError::UnsupportedVersion
            );
        }
        for child in 0..2 {
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
