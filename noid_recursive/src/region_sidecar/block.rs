// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Mandatory terminal post-commit authority for one production block proof.
//!
//! The six fields are the complete block-region authority.  None is optional:
//! wallet/meta Walk-A, wallet/meta Walk-B, owner-auth C' and the main FRICHANL
//! C walk all replay on the enclosing Field proof's already post-commit
//! challenger.  Terminal PCS claims are verifier output and therefore never
//! appear in the serialized proof.

use noid_ivc_core::challenger::Challenger;
use noid_ivc_core::deep_chain::capsule_leaf::raw_flat_lane;
use noid_ivc_core::deep_chain::schedule::{
    duplex_family_refs, duplex_fixed_patterns, flat_of_tower_u128,
};
use noid_ivc_core::deep_chain::source_tree::compress_iv_flat;
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
use noid_poseidon2b::native::domain::{
    capacity_iv, capacity_iv_flat, TAG_CAPSNODE, TAG_EXSTNOD, TAG_KSCHANNL,
};
use noid_poseidon2b::native::permutation::N_ROUNDS;
use noid_poseidon2b::native::poseidon2b_hash_byte_slices;

use crate::acceptance::block_class::SelectedBlockAssemblyFinalizationSeal;
use crate::acceptance::trace::deep_chain::{
    verify_ragged_multi_deep_chain_walk_trace, MultiDeepChainWalkProofTrace,
};
use crate::acceptance::trace::region_source_binding::{
    auth_pcs_main_c_sidecar_purpose, auth_pcs_meta_a_sidecar_purpose,
    auth_pcs_meta_b_sidecar_purpose, auth_pcs_wallet_a_sidecar_purpose,
    auth_pcs_wallet_b_sidecar_purpose, owner_auth_duplex_sidecar_purpose,
};
use crate::acceptance::trace::self_verify::FieldPostCommitTraceContext;
use crate::acceptance::trace::FieldR1csBuilder;
use crate::acceptance::zk_auth_capsule_schedule::{
    selected_zk_auth_main_sidecar_purpose, selected_zk_auth_owner_sidecar_purpose,
    selected_zk_auth_wallet_a_sidecar_purpose, selected_zk_auth_wallet_b_sidecar_purpose,
    ZkAuthCapsuleDuplexSchedules, ZK_AUTH_MAIN_TILE_LOG, ZK_AUTH_OWNER_TILE_LOG,
};

use super::bounded_decode::{
    duplex_shape_for_vk, merkle_shape_for_vk, multi_walk_proof_shape, preflight_composite_proof,
    record_serde_attempt, SidecarProofShape,
};
use super::walk_a::walk_a_bounded_shape;
use super::{
    preflight_duplex_region_walk_deferred_trace, preflight_merkle_region_walk_deferred_trace,
    preflight_merkle_sidecar_trace, preflight_walk_a_region_walk_deferred_trace,
    verify_duplex_region_walk_deferred_prefix, verify_duplex_region_walk_deferred_prefix_trace,
    verify_merkle_region_sidecar, verify_merkle_region_sidecar_trace_post_commit,
    verify_merkle_region_walk_deferred_prefix, verify_merkle_region_walk_deferred_prefix_trace,
    verify_walk_a_region_walk_deferred_prefix, verify_walk_a_region_walk_deferred_prefix_trace,
    DuplexRegionProverPlan, DuplexRegionVk, DuplexRegionWalkDeferredProof, MerkleRegionProverPlan,
    MerkleRegionSidecarProof, MerkleRegionVk, MerkleRegionWalkDeferredProof, RegionSidecarError,
    WalkARegionProverPlan, WalkARegionVk, WalkARegionWalkDeferredProof,
};

pub const BLOCK_REGION_SIDECAR_VERSION: u8 = 3;
pub const BLOCK_REGION_SELECTED_ZK_SIDECAR_VERSION: u8 = 4;

/// Exact selected B255 authorization screening geometry.  This first
/// provenance gate is intentionally B255-only; it is not the final four-tier
/// selected registry.
pub(crate) const SELECTED_ZK_AUTH_TILE_COUNT: usize = 256;
const SELECTED_ZK_AUTH_TX_LOG: usize = 8;
const SELECTED_ZK_AUTH_QUERY_LOG: usize = 6;
const SELECTED_ZK_AUTH_OWNER_W_LOG: usize = 15;
const SELECTED_ZK_AUTH_MAIN_W_LOG: usize = 16;
const SELECTED_ZK_AUTH_WALLET_A_W_LOG: usize = 19;
const SELECTED_ZK_AUTH_WALLET_B_W_LOG: usize = 18;
const SELECTED_ZK_AUTH_META_A_W_LOG: usize = 15;
const SELECTED_ZK_AUTH_META_B_W_LOG: usize = 17;

const BLOCK_REGION_VK_DIGEST_DOMAIN: &[u8] = b"NOID/REGION-SIDECAR/BLOCK-VK/V3";
const BLOCK_REGION_SELECTED_ZK_VK_DIGEST_DOMAIN: &[u8] = b"NOID/REGION-SIDECAR/BLOCK-ZK-AUTH-VK/V4";
const BLOCK_POST_COMMIT_CLASS_DIGEST_DOMAIN: &[u8] =
    b"NOID/REGION-SIDECAR/BLOCK-POST-COMMIT-CLASS/V3";
const BLOCK_SELECTED_ZK_POST_COMMIT_CLASS_DIGEST_DOMAIN: &[u8] =
    b"NOID/REGION-SIDECAR/BLOCK-ZK-AUTH-POST-COMMIT-CLASS/V4";
const BLOCK_REGION_TRANSCRIPT_LABEL: &[u8] = b"history-region-sidecar-block-v3";
const BLOCK_REGION_SELECTED_ZK_TRANSCRIPT_LABEL: &[u8] = b"history-region-sidecar-block-zk-auth-v4";

/// Canonical verification key for all six production block-region verticals.
///
/// Private fields make partial block keys unrepresentable outside this module.
/// The constructor accepts already validated child keys and freezes their role
/// and order into one digest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockRegionSidecarVk {
    version: u8,
    wallet_a: WalkARegionVk,
    meta_a: WalkARegionVk,
    wallet_b: MerkleRegionVk,
    meta_b: MerkleRegionVk,
    owner_c: DuplexRegionVk,
    main_c: DuplexRegionVk,
}

impl BlockRegionSidecarVk {
    pub fn new(
        wallet_a: WalkARegionVk,
        meta_a: WalkARegionVk,
        wallet_b: MerkleRegionVk,
        meta_b: MerkleRegionVk,
        owner_c: DuplexRegionVk,
        main_c: DuplexRegionVk,
    ) -> Result<Self, RegionSidecarError> {
        let vk = Self {
            version: BLOCK_REGION_SIDECAR_VERSION,
            wallet_a,
            meta_a,
            wallet_b,
            meta_b,
            owner_c,
            main_c,
        };
        vk.validate_roles()?;
        Ok(vk)
    }

    /// Construct the selected ZK-authorization six-child key.
    ///
    /// This is a VK shape certificate only.  It is deliberately not a
    /// committed-region capability: the only path to a selected mandatory
    /// preparation additionally consumes the all-256-tile binding typestate.
    pub(crate) fn new_selected_zk(
        wallet_a: WalkARegionVk,
        meta_a: WalkARegionVk,
        wallet_b: MerkleRegionVk,
        meta_b: MerkleRegionVk,
        owner_c: DuplexRegionVk,
        main_c: DuplexRegionVk,
    ) -> Result<Self, RegionSidecarError> {
        let vk = Self {
            version: BLOCK_REGION_SELECTED_ZK_SIDECAR_VERSION,
            wallet_a,
            meta_a,
            wallet_b,
            meta_b,
            owner_c,
            main_c,
        };
        vk.validate_selected_zk_roles()?;
        Ok(vk)
    }

    pub fn wallet_a(&self) -> &WalkARegionVk {
        &self.wallet_a
    }

    pub fn meta_a(&self) -> &WalkARegionVk {
        &self.meta_a
    }

    pub fn wallet_b(&self) -> &MerkleRegionVk {
        &self.wallet_b
    }

    pub fn meta_b(&self) -> &MerkleRegionVk {
        &self.meta_b
    }

    pub fn owner_c(&self) -> &DuplexRegionVk {
        &self.owner_c
    }

    pub fn main_c(&self) -> &DuplexRegionVk {
        &self.main_c
    }

    pub fn version(&self) -> u8 {
        self.version
    }

    /// Digest of the complete ordered block sidecar VK.  This digest is a
    /// component of the enclosing block class digest; the exact child keys
    /// are also absorbed here before any child proof message is sampled.
    pub fn transcript_digest(&self) -> [u8; 32] {
        let child = [
            self.wallet_a.transcript_digest(),
            self.meta_a.transcript_digest(),
            self.wallet_b.transcript_digest(),
            self.meta_b.transcript_digest(),
            self.owner_c.transcript_digest(),
            self.main_c.transcript_digest(),
        ];
        let version = [self.version];
        poseidon2b_hash_byte_slices(
            self.vk_digest_domain(),
            &[
                &version,
                b"wallet-a",
                &child[0],
                b"meta-a",
                &child[1],
                b"wallet-b",
                &child[2],
                b"meta-b",
                &child[3],
                b"owner-c",
                &child[4],
                b"main-c",
                &child[5],
            ],
        )
    }

    fn validate_roles(&self) -> Result<(), RegionSidecarError> {
        use super::WalkARegionDescriptor;

        if self.version != BLOCK_REGION_SIDECAR_VERSION
            || !matches!(
                self.wallet_a.descriptor(),
                WalkARegionDescriptor::Wallet { .. }
            )
            || !matches!(
                self.meta_a.descriptor(),
                WalkARegionDescriptor::Meta {
                    exact_state_region_log: Some(_),
                    spine_cap_log: Some(_),
                    ..
                }
            )
            || self.wallet_a.purpose() != &auth_pcs_wallet_a_sidecar_purpose()
            || self.meta_a.purpose() != &auth_pcs_meta_a_sidecar_purpose()
            || self.wallet_b.purpose() != &auth_pcs_wallet_b_sidecar_purpose()
            || self.meta_b.purpose() != &auth_pcs_meta_b_sidecar_purpose()
            || self.owner_c.purpose() != &owner_auth_duplex_sidecar_purpose()
            || self.main_c.purpose() != &auth_pcs_main_c_sidecar_purpose()
        {
            return Err(RegionSidecarError::UnsupportedVkShape);
        }
        Ok(())
    }

    fn validate_versioned_roles(&self) -> Result<(), RegionSidecarError> {
        match self.version {
            BLOCK_REGION_SIDECAR_VERSION => self.validate_roles(),
            BLOCK_REGION_SELECTED_ZK_SIDECAR_VERSION => self.validate_selected_zk_roles(),
            _ => Err(RegionSidecarError::UnsupportedVersion),
        }
    }

    fn vk_digest_domain(&self) -> &'static [u8] {
        match self.version {
            BLOCK_REGION_SIDECAR_VERSION => BLOCK_REGION_VK_DIGEST_DOMAIN,
            BLOCK_REGION_SELECTED_ZK_SIDECAR_VERSION => BLOCK_REGION_SELECTED_ZK_VK_DIGEST_DOMAIN,
            _ => b"NOID/REGION-SIDECAR/BLOCK-UNSUPPORTED",
        }
    }

    fn transcript_label(&self) -> &'static [u8] {
        match self.version {
            BLOCK_REGION_SIDECAR_VERSION => BLOCK_REGION_TRANSCRIPT_LABEL,
            BLOCK_REGION_SELECTED_ZK_SIDECAR_VERSION => BLOCK_REGION_SELECTED_ZK_TRANSCRIPT_LABEL,
            _ => b"history-region-sidecar-block-unsupported",
        }
    }

    /// Exact selected-B255 certificate over all six child roles, layouts,
    /// domains and slices.  Success does not by itself authorize proving: the
    /// Block builder must still bind every tile and consume the resulting
    /// private typestate before a selected preparation can exist.
    pub(crate) fn validate_selected_zk_roles(&self) -> Result<(), RegionSidecarError> {
        use super::{MerkleRegionFamily, WalkARegionDescriptor};

        if self.version != BLOCK_REGION_SELECTED_ZK_SIDECAR_VERSION
            || self.wallet_a.purpose() != &selected_zk_auth_wallet_a_sidecar_purpose()
            || self.meta_a.purpose() != &auth_pcs_meta_a_sidecar_purpose()
            || self.wallet_b.purpose() != &selected_zk_auth_wallet_b_sidecar_purpose()
            || self.meta_b.purpose() != &auth_pcs_meta_b_sidecar_purpose()
            || self.owner_c.purpose() != &selected_zk_auth_owner_sidecar_purpose()
            || self.main_c.purpose() != &selected_zk_auth_main_sidecar_purpose()
            || self.wallet_a.descriptor()
                != (WalkARegionDescriptor::Wallet {
                    tx_log: SELECTED_ZK_AUTH_TX_LOG,
                    nq_log: SELECTED_ZK_AUTH_QUERY_LOG,
                })
            || self.wallet_a.w_log() != SELECTED_ZK_AUTH_WALLET_A_W_LOG
            || self.meta_a.descriptor()
                != (WalkARegionDescriptor::Meta {
                    tx_log: SELECTED_ZK_AUTH_TX_LOG,
                    exact_state_region_log: Some(13),
                    spine_cap_log: Some(0),
                })
            || self.meta_a.w_log() != SELECTED_ZK_AUTH_META_A_W_LOG
            || self.wallet_b.w_log() != SELECTED_ZK_AUTH_WALLET_B_W_LOG
            || self.wallet_b.block_log() != 10
            || self.meta_b.w_log() != SELECTED_ZK_AUTH_META_B_W_LOG
            || self.meta_b.block_log() != 9
        {
            return Err(RegionSidecarError::UnsupportedVkShape);
        }

        let capsule_iv = capacity_iv_flat(TAG_CAPSNODE).map(raw_flat_lane);
        let expected_wallet_b = [
            MerkleRegionFamily::FeedForward {
                offset: 0,
                depth: 8,
                n_paths: 64,
                iv: capsule_iv,
            },
            MerkleRegionFamily::FeedForward {
                offset: 512,
                depth: 8,
                n_paths: 64,
                iv: capsule_iv,
            },
        ];
        if self.wallet_b.families() != expected_wallet_b {
            return Err(RegionSidecarError::UnsupportedVkShape);
        }

        let exact_state_iv = capacity_iv_flat(TAG_EXSTNOD).map(raw_flat_lane);
        let expected_meta_b = [
            MerkleRegionFamily::PairedUpdate {
                offset: 0,
                n_updates: 6,
                iv: exact_state_iv,
            },
            MerkleRegionFamily::PairedUpdate {
                offset: 384,
                n_updates: 1,
                iv: exact_state_iv,
            },
            MerkleRegionFamily::TwoPermutation {
                offset: 448,
                depth: 8,
                n_paths: 1,
                iv: compress_iv_flat(),
            },
        ];
        if self.meta_b.families() != expected_meta_b {
            return Err(RegionSidecarError::UnsupportedVkShape);
        }

        let schedules = ZkAuthCapsuleDuplexSchedules::selected();
        if !selected_duplex_vk_matches(
            self.owner_c(),
            &schedules.owner_layout(),
            selected_zk_auth_owner_sidecar_purpose(),
            SELECTED_ZK_AUTH_OWNER_W_LOG,
            ZK_AUTH_OWNER_TILE_LOG,
        ) || !selected_duplex_vk_matches(
            self.main_c(),
            &schedules.main_layout(),
            selected_zk_auth_main_sidecar_purpose(),
            SELECTED_ZK_AUTH_MAIN_W_LOG,
            ZK_AUTH_MAIN_TILE_LOG,
        ) {
            return Err(RegionSidecarError::UnsupportedVkShape);
        }

        let slices = self
            .wallet_a
            .slices()
            .iter()
            .chain(self.meta_a.slices())
            .chain(self.wallet_b.slices())
            .chain(self.meta_b.slices())
            .chain(self.owner_c.slices())
            .chain(self.main_c.slices())
            .collect::<Vec<_>>();
        for (index, left) in slices.iter().enumerate() {
            let left_start = left.start();
            let left_end = left_start
                .checked_add(left.len())
                .ok_or(RegionSidecarError::BadSlice)?;
            for right in &slices[index + 1..] {
                let right_start = right.start();
                let right_end = right_start
                    .checked_add(right.len())
                    .ok_or(RegionSidecarError::BadSlice)?;
                if left_start < right_end && right_start < left_end {
                    return Err(RegionSidecarError::BadSlice);
                }
            }
        }
        Ok(())
    }
}

fn selected_duplex_vk_matches(
    vk: &DuplexRegionVk,
    layout: &noid_ivc_core::deep_chain::schedule::DuplexLayout,
    purpose: [u8; 32],
    w_log: usize,
    tile_log: usize,
) -> bool {
    let [iv_hi, iv_lo] = capacity_iv(TAG_KSCHANNL);
    let iv = [flat_of_tower_u128(iv_hi.0), flat_of_tower_u128(iv_lo.0)];
    vk.purpose() == &purpose
        && vk.w_log() == w_log
        && vk.refs() == duplex_family_refs(0, 0)
        && vk.fixed() == duplex_fixed_patterns(layout, iv, tile_log)
        && vk.layout_digest() == &super::duplex_compiled_layout_digest(layout, w_log)
}

/// Stable post-commit class identity bound by the enclosing Field typestate
/// API.  It covers the matrix content, exact public-IO spec, PCS parameters,
/// and all six sidecar verification keys.  A proof from any ordinary Field
/// class or from a differently sliced region class therefore enters a
/// different transcript before the first sidecar challenge.
pub fn block_post_commit_class_digest(
    matrix_digest: &[u8; 32],
    spec: &PublicIoSpec,
    pcs_params: &PcsParams,
    sidecar_vk: &BlockRegionSidecarVk,
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

    let (domain, role) = match sidecar_vk.version() {
        BLOCK_REGION_SIDECAR_VERSION => (BLOCK_POST_COMMIT_CLASS_DIGEST_DOMAIN, b"block" as &[u8]),
        BLOCK_REGION_SELECTED_ZK_SIDECAR_VERSION => (
            BLOCK_SELECTED_ZK_POST_COMMIT_CLASS_DIGEST_DOMAIN,
            b"block-zk-auth" as &[u8],
        ),
        _ => (
            b"NOID/REGION-SIDECAR/BLOCK-POST-COMMIT-UNSUPPORTED" as &[u8],
            b"unsupported" as &[u8],
        ),
    };
    let version = [sidecar_vk.version()];
    poseidon2b_hash_byte_slices(
        domain,
        &[
            &version,
            role,
            matrix_digest,
            &spec_bytes,
            &pcs_bytes,
            &sidecar_vk.transcript_digest(),
        ],
    )
}

/// Owned layer-0/layer-66 columns for one post-commit walk.  The committed
/// columns are deliberately absent: every child plan reads them from the
/// enclosing witness through its exact VK slices.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegionWalkEndpoints {
    s0: [Vec<F128>; 4],
    s_out: [Vec<F128>; 4],
}

impl RegionWalkEndpoints {
    pub fn new(s0: [Vec<F128>; 4], s_out: [Vec<F128>; 4]) -> Self {
        Self { s0, s_out }
    }

    pub(crate) fn s0(&self) -> &[Vec<F128>; 4] {
        &self.s0
    }

    pub(crate) fn s_out(&self) -> &[Vec<F128>; 4] {
        &self.s_out
    }
}

/// Prover-only inputs for the six mandatory block verticals.
///
/// Construction validates every endpoint length against the corresponding
/// child key, so a class cannot reach proving with a missing or cross-wired
/// family.
pub struct BlockRegionProverInput {
    wallet_a: RegionWalkEndpoints,
    meta_a: RegionWalkEndpoints,
    wallet_b: RegionWalkEndpoints,
    meta_b: RegionWalkEndpoints,
    owner_c: RegionWalkEndpoints,
    main_c: RegionWalkEndpoints,
}

impl BlockRegionProverInput {
    pub fn new(
        vk: &BlockRegionSidecarVk,
        wallet_a: RegionWalkEndpoints,
        meta_a: RegionWalkEndpoints,
        wallet_b: RegionWalkEndpoints,
        meta_b: RegionWalkEndpoints,
        owner_c: RegionWalkEndpoints,
        main_c: RegionWalkEndpoints,
    ) -> Result<Self, RegionSidecarError> {
        let input = Self {
            wallet_a,
            meta_a,
            wallet_b,
            meta_b,
            owner_c,
            main_c,
        };
        input.validate(vk)?;
        Ok(input)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_selected_zk(
        vk: &BlockRegionSidecarVk,
        wallet_a: RegionWalkEndpoints,
        meta_a: RegionWalkEndpoints,
        wallet_b: RegionWalkEndpoints,
        meta_b: RegionWalkEndpoints,
        owner_c: RegionWalkEndpoints,
        main_c: RegionWalkEndpoints,
    ) -> Result<Self, RegionSidecarError> {
        let input = Self {
            wallet_a,
            meta_a,
            wallet_b,
            meta_b,
            owner_c,
            main_c,
        };
        input.validate_selected_zk(vk)?;
        Ok(input)
    }

    fn validate(&self, vk: &BlockRegionSidecarVk) -> Result<(), RegionSidecarError> {
        vk.validate_roles()?;
        self.validate_children(vk)
    }

    fn validate_selected_zk(&self, vk: &BlockRegionSidecarVk) -> Result<(), RegionSidecarError> {
        vk.validate_selected_zk_roles()?;
        self.validate_children(vk)
    }

    fn validate_children(&self, vk: &BlockRegionSidecarVk) -> Result<(), RegionSidecarError> {
        WalkARegionProverPlan::new(vk.wallet_a(), self.wallet_a.s0(), self.wallet_a.s_out())?;
        WalkARegionProverPlan::new(vk.meta_a(), self.meta_a.s0(), self.meta_a.s_out())?;
        MerkleRegionProverPlan::new(vk.wallet_b(), self.wallet_b.s0(), self.wallet_b.s_out())?;
        MerkleRegionProverPlan::new(vk.meta_b(), self.meta_b.s0(), self.meta_b.s_out())?;
        DuplexRegionProverPlan::new(vk.owner_c(), self.owner_c.s0(), self.owner_c.s_out())?;
        DuplexRegionProverPlan::new(vk.main_c(), self.main_c.s0(), self.main_c.s_out())?;
        Ok(())
    }
}

/// Borrowed proving plan.  It has no challenger constructor; callers must run
/// it inside the enclosing Field proof's post-commit context.
pub struct BlockRegionProverPlan<'a> {
    vk: &'a BlockRegionSidecarVk,
    input: &'a BlockRegionProverInput,
}

/// Owning handoff from block-trace assembly to the causally post-commit
/// prover.  Keeping the VK and its validated endpoint input together avoids
/// cross-class wiring when a built block is queued for proving.
pub struct BlockRegionPreparation {
    vk: BlockRegionSidecarVk,
    input: BlockRegionProverInput,
    kind: BlockRegionPreparationKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BlockRegionPreparationKind {
    Legacy,
    SelectedZkOwnedAssembly,
}

/// Unbound selected preparation state.  It owns the exact six-child key and
/// native endpoints, but cannot enter the prover until the Block matrix has
/// constrained every one of its 256 authorization tiles.
pub(crate) struct SelectedZkBlockRegionDraft {
    vk: BlockRegionSidecarVk,
    input: BlockRegionProverInput,
}

impl SelectedZkBlockRegionDraft {
    pub(crate) fn new(
        vk: BlockRegionSidecarVk,
        input: BlockRegionProverInput,
    ) -> Result<Self, RegionSidecarError> {
        vk.validate_selected_zk_roles()?;
        input.validate_selected_zk(&vk)?;
        Ok(Self { vk, input })
    }

    pub(crate) fn vk(&self) -> &BlockRegionSidecarVk {
        &self.vk
    }

    fn into_parts(self) -> (BlockRegionSidecarVk, BlockRegionProverInput) {
        (self.vk, self.input)
    }
}

impl BlockRegionPreparation {
    pub fn new(
        vk: BlockRegionSidecarVk,
        input: BlockRegionProverInput,
    ) -> Result<Self, RegionSidecarError> {
        input.validate(&vk)?;
        Ok(Self {
            vk,
            input,
            kind: BlockRegionPreparationKind::Legacy,
        })
    }

    /// Selected-ZK finalization is sealed by the owning Block assembly. The
    /// seal's field is private to that module, so no draft/VK-only caller can
    /// construct it or obtain a preparation before the same owner has bound
    /// all tiles and retained the builder through final `build()`.
    pub(crate) fn from_selected_zk_owned_assembly(
        draft: SelectedZkBlockRegionDraft,
        _seal: SelectedBlockAssemblyFinalizationSeal,
        total_vars: usize,
    ) -> Result<Self, RegionSidecarError> {
        let (vk, input) = draft.into_parts();
        vk.validate_selected_zk_roles()?;
        input.validate_selected_zk(&vk)?;
        // All 44 selected slices — including unchanged Meta-A/B, which the
        // authorization candidate does not read — must live inside the matrix
        // that the owner just built. Reject availability drift atomically at
        // finish rather than deferring it to a prover-plan failure.
        let _ = block_bounded_shapes(&vk, total_vars)?;
        Ok(Self {
            vk,
            input,
            kind: BlockRegionPreparationKind::SelectedZkOwnedAssembly,
        })
    }

    pub fn vk(&self) -> &BlockRegionSidecarVk {
        &self.vk
    }

    pub fn prover_input(&self) -> &BlockRegionProverInput {
        &self.input
    }

    pub fn prover_plan(&self) -> Result<BlockRegionProverPlan<'_>, RegionSidecarError> {
        match self.kind {
            BlockRegionPreparationKind::Legacy => BlockRegionProverPlan::new(&self.vk, &self.input),
            BlockRegionPreparationKind::SelectedZkOwnedAssembly => {
                BlockRegionProverPlan::new_selected_zk(&self.vk, &self.input)
            }
        }
    }

    pub fn into_parts(self) -> (BlockRegionSidecarVk, BlockRegionProverInput) {
        (self.vk, self.input)
    }
}

impl<'a> BlockRegionProverPlan<'a> {
    pub fn new(
        vk: &'a BlockRegionSidecarVk,
        input: &'a BlockRegionProverInput,
    ) -> Result<Self, RegionSidecarError> {
        vk.validate_roles()?;
        input.validate(vk)?;
        Ok(Self { vk, input })
    }

    fn new_selected_zk(
        vk: &'a BlockRegionSidecarVk,
        input: &'a BlockRegionProverInput,
    ) -> Result<Self, RegionSidecarError> {
        input.validate_selected_zk(vk)?;
        Ok(Self { vk, input })
    }

    fn prove<Ch: Challenger>(
        &self,
        z: &[F128],
        challenger: &mut Ch,
    ) -> Result<(BlockRegionSidecarProof, Vec<QuirkyDirectClaim>), RegionSidecarError> {
        bind_block_vk(challenger, self.vk);
        let mut claims = Vec::new();

        // Batch only the deep-chain walk shared by these ordered children.
        // V3's ragged embedding retains every child's native domain width;
        // no committed column or outer witness is padded to the group max.
        // Every prefix/suffix relation and every terminal opening remains a
        // separate role-bound proof.  The exact order below is the V3 block
        // sidecar transcript and is mirrored by both verifier twins.
        let wallet_a_plan = WalkARegionProverPlan::new(
            self.vk.wallet_a(),
            self.input.wallet_a.s0(),
            self.input.wallet_a.s_out(),
        )?;
        let meta_b_plan = MerkleRegionProverPlan::new(
            self.vk.meta_b(),
            self.input.meta_b.s0(),
            self.input.meta_b.s_out(),
        )?;
        let wallet_a_prefix = wallet_a_plan.prove_walk_deferred_prefix(z, challenger)?;
        let meta_b_prefix = meta_b_plan.prove_walk_deferred_prefix(z, challenger)?;
        let groups = vec![
            vec![wallet_a_prefix.group().clone()],
            vec![meta_b_prefix.group().clone()],
        ];
        let s0 = [wallet_a_prefix.s0(), meta_b_prefix.s0()];
        let (wallet_a_meta_b_walk, terminals) =
            prove_ragged_multi_deep_chain_walk(&s0, &groups, challenger);
        let [wallet_a_terminal, meta_b_terminal]: [_; 2] = terminals
            .try_into()
            .expect("wallet-A/meta-B multi-walk terminal count");
        let (wallet_a, child_claims) = wallet_a_prefix.finish(&wallet_a_terminal, challenger)?;
        claims.extend(child_claims);
        let (meta_b, child_claims) = meta_b_prefix.finish(&meta_b_terminal, challenger)?;
        claims.extend(child_claims);

        let meta_a_plan = WalkARegionProverPlan::new(
            self.vk.meta_a(),
            self.input.meta_a.s0(),
            self.input.meta_a.s_out(),
        )?;
        let owner_c_plan = DuplexRegionProverPlan::new(
            self.vk.owner_c(),
            self.input.owner_c.s0(),
            self.input.owner_c.s_out(),
        )?;
        let main_c_plan = DuplexRegionProverPlan::new(
            self.vk.main_c(),
            self.input.main_c.s0(),
            self.input.main_c.s_out(),
        )?;
        let meta_a_prefix = meta_a_plan.prove_walk_deferred_prefix(z, challenger)?;
        let owner_c_prefix = owner_c_plan.prove_walk_deferred_prefix(z, challenger)?;
        let main_c_prefix = main_c_plan.prove_walk_deferred_prefix(z, challenger)?;
        let groups = vec![
            vec![meta_a_prefix.group().clone()],
            vec![owner_c_prefix.group().clone()],
            vec![main_c_prefix.group().clone()],
        ];
        let s0 = [meta_a_prefix.s0(), owner_c_prefix.s0(), main_c_prefix.s0()];
        let (meta_a_owner_main_walk, terminals) =
            prove_ragged_multi_deep_chain_walk(&s0, &groups, challenger);
        let [meta_a_terminal, owner_c_terminal, main_c_terminal]: [_; 3] = terminals
            .try_into()
            .expect("meta-A/owner-C/main-C multi-walk terminal count");
        let (meta_a, child_claims) = meta_a_prefix.finish(&meta_a_terminal, challenger)?;
        claims.extend(child_claims);
        let (owner_c, child_claims) = owner_c_prefix.finish(&owner_c_terminal, challenger)?;
        claims.extend(child_claims);
        let (main_c, child_claims) = main_c_prefix.finish(&main_c_terminal, challenger)?;
        claims.extend(child_claims);

        // wallet-B has the only unmatched production domain and therefore
        // retains its ordinary single-instance authority.
        let wallet_b = prove_merkle(
            self.vk.wallet_b(),
            &self.input.wallet_b,
            z,
            challenger,
            &mut claims,
        )?;

        Ok((
            BlockRegionSidecarProof {
                version: self.vk.version(),
                wallet_a,
                meta_b,
                wallet_a_meta_b_walk,
                meta_a,
                owner_c,
                main_c,
                meta_a_owner_main_walk,
                wallet_b,
            },
            claims,
        ))
    }

    /// Sound production entry point.  The opaque capability can only be
    /// created by the enclosing Field prover after committing to `z`; this
    /// method also deposits every derived claim into its private sink before
    /// returning the sidecar proof.
    pub fn prove_post_commit<Ch: Challenger>(
        &self,
        context: &mut FieldPostCommitProverContext<'_, Ch>,
    ) -> Result<BlockRegionSidecarProof, RegionSidecarError> {
        let witness = context.witness();
        let (proof, claims) = self.prove(witness, context)?;
        context.append_claims(claims);
        Ok(proof)
    }
}

/// The fixed-shape block sidecar envelope (legacy V3 or selected-ZK V4).
///
/// Five children carry independent prefix/suffix authority with their walk
/// deliberately absent; two mandatory multi-walks reduce those exact child
/// groups. Wallet-B remains the one unmatched full child. No relation proof,
/// shift discharge, or terminal opening is shared or omitted.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BlockRegionSidecarProof {
    version: u8,
    wallet_a: WalkARegionWalkDeferredProof,
    meta_b: MerkleRegionWalkDeferredProof,
    wallet_a_meta_b_walk: MultiDeepChainWalkProof,
    meta_a: WalkARegionWalkDeferredProof,
    owner_c: DuplexRegionWalkDeferredProof,
    main_c: DuplexRegionWalkDeferredProof,
    meta_a_owner_main_walk: MultiDeepChainWalkProof,
    wallet_b: MerkleRegionSidecarProof,
}

impl BlockRegionSidecarProof {
    pub fn byte_len(&self) -> usize {
        bincode::serialized_size(self).expect("block region sidecar serialized length") as usize
    }

    pub(crate) fn wallet_a(&self) -> &WalkARegionWalkDeferredProof {
        &self.wallet_a
    }

    pub(crate) fn meta_a(&self) -> &WalkARegionWalkDeferredProof {
        &self.meta_a
    }

    pub(crate) fn wallet_b(&self) -> &MerkleRegionSidecarProof {
        &self.wallet_b
    }

    pub(crate) fn meta_b(&self) -> &MerkleRegionWalkDeferredProof {
        &self.meta_b
    }

    pub(crate) fn owner_c(&self) -> &DuplexRegionWalkDeferredProof {
        &self.owner_c
    }

    pub(crate) fn main_c(&self) -> &DuplexRegionWalkDeferredProof {
        &self.main_c
    }
}

/// Decode the mandatory version-keyed block envelope only after every deferred child,
/// both multi-walks, and the unmatched full child have passed one
/// allocation-free class-aware scan.
pub fn decode_block_region_sidecar_bounded(
    vk: &BlockRegionSidecarVk,
    total_vars: usize,
    bytes: &[u8],
) -> Result<BlockRegionSidecarProof, RegionSidecarError> {
    let shapes = block_bounded_shapes(vk, total_vars)?;
    preflight_composite_proof(bytes, vk.version(), &shapes)?;
    record_serde_attempt();
    let proof: BlockRegionSidecarProof =
        bincode::deserialize(bytes).map_err(|_| RegionSidecarError::InvalidProof)?;
    if proof.version != vk.version() {
        return Err(RegionSidecarError::UnsupportedVersion);
    }
    Ok(proof)
}

fn block_bounded_shapes(
    vk: &BlockRegionSidecarVk,
    total_vars: usize,
) -> Result<[SidecarProofShape; 8], RegionSidecarError> {
    vk.validate_versioned_roles()?;
    let wallet_meta_w_logs = wallet_meta_w_logs(vk);
    let meta_duplex_w_logs = meta_duplex_w_logs(vk);
    Ok([
        SidecarProofShape::DeferredFixed(
            walk_a_bounded_shape(vk.wallet_a(), total_vars)?.walk_deferred(),
        ),
        SidecarProofShape::DeferredMerkle(
            merkle_shape_for_vk(vk.meta_b(), total_vars)?.walk_deferred(),
        ),
        SidecarProofShape::MultiWalk(multi_walk_proof_shape(
            max_w_log(&wallet_meta_w_logs),
            wallet_meta_w_logs.len(),
        )?),
        SidecarProofShape::DeferredFixed(
            walk_a_bounded_shape(vk.meta_a(), total_vars)?.walk_deferred(),
        ),
        SidecarProofShape::DeferredFixed(
            duplex_shape_for_vk(vk.owner_c(), total_vars)?.walk_deferred(),
        ),
        SidecarProofShape::DeferredFixed(
            duplex_shape_for_vk(vk.main_c(), total_vars)?.walk_deferred(),
        ),
        SidecarProofShape::MultiWalk(multi_walk_proof_shape(
            max_w_log(&meta_duplex_w_logs),
            meta_duplex_w_logs.len(),
        )?),
        SidecarProofShape::Merkle(merkle_shape_for_vk(vk.wallet_b(), total_vars)?),
    ])
}

/// Replay the version-keyed phased block authority and derive the complete outer PCS
/// claim list. No claim descriptor is accepted from the prover.
fn verify_block_region_sidecar<Ch: Challenger>(
    vk: &BlockRegionSidecarVk,
    total_vars: usize,
    proof: &BlockRegionSidecarProof,
    challenger: &mut Ch,
) -> Result<Vec<QuirkyDirectClaim>, RegionSidecarError> {
    vk.validate_versioned_roles()?;
    if proof.version != vk.version() {
        return Err(RegionSidecarError::UnsupportedVersion);
    }

    bind_block_vk(challenger, vk);
    let mut claims = Vec::new();

    let wallet_a_prefix = verify_walk_a_region_walk_deferred_prefix(
        vk.wallet_a(),
        total_vars,
        &proof.wallet_a,
        challenger,
    )?;
    let meta_b_prefix = verify_merkle_region_walk_deferred_prefix(
        vk.meta_b(),
        total_vars,
        &proof.meta_b,
        challenger,
    )?;
    let groups = vec![
        vec![wallet_a_prefix.group().clone()],
        vec![meta_b_prefix.group().clone()],
    ];
    let [wallet_a_terminal, meta_b_terminal]: [_; 2] = verify_ragged_multi_deep_chain_walk(
        &wallet_meta_w_logs(vk),
        &groups,
        &proof.wallet_a_meta_b_walk,
        challenger,
    )
    .map_err(|_| RegionSidecarError::InvalidProof)?
    .try_into()
    .expect("verified wallet-A/meta-B terminal count");
    claims.extend(wallet_a_prefix.finish(&wallet_a_terminal, challenger)?);
    claims.extend(meta_b_prefix.finish(&meta_b_terminal, challenger)?);

    let meta_a_prefix = verify_walk_a_region_walk_deferred_prefix(
        vk.meta_a(),
        total_vars,
        &proof.meta_a,
        challenger,
    )?;
    let owner_c_prefix = verify_duplex_region_walk_deferred_prefix(
        vk.owner_c(),
        total_vars,
        &proof.owner_c,
        challenger,
    )?;
    let main_c_prefix = verify_duplex_region_walk_deferred_prefix(
        vk.main_c(),
        total_vars,
        &proof.main_c,
        challenger,
    )?;
    let groups = vec![
        vec![meta_a_prefix.group().clone()],
        vec![owner_c_prefix.group().clone()],
        vec![main_c_prefix.group().clone()],
    ];
    let [meta_a_terminal, owner_c_terminal, main_c_terminal]: [_; 3] =
        verify_ragged_multi_deep_chain_walk(
            &meta_duplex_w_logs(vk),
            &groups,
            &proof.meta_a_owner_main_walk,
            challenger,
        )
        .map_err(|_| RegionSidecarError::InvalidProof)?
        .try_into()
        .expect("verified meta-A/owner-C/main-C terminal count");
    claims.extend(meta_a_prefix.finish(&meta_a_terminal, challenger)?);
    claims.extend(owner_c_prefix.finish(&owner_c_terminal, challenger)?);
    claims.extend(main_c_prefix.finish(&main_c_terminal, challenger)?);

    claims.extend(verify_merkle_region_sidecar(
        vk.wallet_b(),
        total_vars,
        &proof.wallet_b,
        challenger,
    )?);
    Ok(claims)
}

/// Sound production verifier entry point.  Claims reconstructed from the six
/// authorities are placed directly in the enclosing verifier's private PCS
/// sink; callers cannot accidentally verify a sidecar and then discard its
/// openings.
pub fn verify_block_region_sidecar_post_commit<Ch: Challenger>(
    vk: &BlockRegionSidecarVk,
    proof: &BlockRegionSidecarProof,
    context: &mut FieldPostCommitVerifierContext<'_, Ch>,
) -> Result<(), RegionSidecarError> {
    let claims = verify_block_region_sidecar(vk, context.total_vars(), proof, context)?;
    context.append_claims(claims);
    Ok(())
}

/// Recursive trace verifier for the fixed version-keyed block authority. Every deferred
/// child, multi-walk, and the unmatched wallet-B proof is shape-preflighted
/// before the first proof witness allocation. Prefixes and suffixes remain
/// role-local; only the ragged-domain deep walks are random-linearly batched.
pub fn verify_block_region_sidecar_trace_post_commit<C: FsChannelOps>(
    b: &mut FieldR1csBuilder,
    context: &mut FieldPostCommitTraceContext<'_, C>,
    vk: &BlockRegionSidecarVk,
    proof: &BlockRegionSidecarProof,
) -> Result<(), RegionSidecarError> {
    vk.validate_versioned_roles()?;
    if proof.version != vk.version() {
        return Err(RegionSidecarError::UnsupportedVersion);
    }
    let total_vars = context.total_vars();
    let wallet_meta_w_logs = wallet_meta_w_logs(vk);
    let meta_duplex_w_logs = meta_duplex_w_logs(vk);
    preflight_walk_a_region_walk_deferred_trace(vk.wallet_a(), total_vars, &proof.wallet_a)?;
    preflight_merkle_region_walk_deferred_trace(vk.meta_b(), total_vars, &proof.meta_b)?;
    preflight_multi_walk(
        &proof.wallet_a_meta_b_walk,
        max_w_log(&wallet_meta_w_logs),
        wallet_meta_w_logs.len(),
    )?;
    preflight_walk_a_region_walk_deferred_trace(vk.meta_a(), total_vars, &proof.meta_a)?;
    preflight_duplex_region_walk_deferred_trace(vk.owner_c(), total_vars, &proof.owner_c)?;
    preflight_duplex_region_walk_deferred_trace(vk.main_c(), total_vars, &proof.main_c)?;
    preflight_multi_walk(
        &proof.meta_a_owner_main_walk,
        max_w_log(&meta_duplex_w_logs),
        meta_duplex_w_logs.len(),
    )?;
    preflight_merkle_sidecar_trace(vk.wallet_b(), total_vars, &proof.wallet_b)?;

    context.observe_label(b, vk.transcript_label());
    context.observe_bytes_const(b, &vk.transcript_digest());
    let mut ledger = b.num_wires();

    let wallet_a_prefix = verify_walk_a_region_walk_deferred_prefix_trace(
        b,
        context,
        vk.wallet_a(),
        &proof.wallet_a,
    )?;
    let meta_b_prefix =
        verify_merkle_region_walk_deferred_prefix_trace(b, context, vk.meta_b(), &proof.meta_b)?;
    crate::acceptance::row_ledger_mark(b, &mut ledger, "block-sidecar: wallet-A/meta-B prefixes");
    let groups = vec![
        vec![wallet_a_prefix.walk_group()],
        vec![meta_b_prefix.walk_group()],
    ];
    let walk = MultiDeepChainWalkProofTrace::alloc_ragged(
        b,
        &proof.wallet_a_meta_b_walk,
        &wallet_meta_w_logs,
    );
    let terminals =
        verify_ragged_multi_deep_chain_walk_trace(b, context, &wallet_meta_w_logs, &groups, &walk);
    if terminals.len() != 2 {
        return Err(RegionSidecarError::InvalidProof);
    }
    let mut terminals = terminals.into_iter();
    let wallet_a_terminal = terminals.next().expect("checked terminal count");
    let meta_b_terminal = terminals.next().expect("checked terminal count");
    crate::acceptance::row_ledger_mark(b, &mut ledger, "block-sidecar: wallet-A/meta-B multi-walk");
    let claims = wallet_a_prefix.finish(b, context, &wallet_a_terminal)?;
    context.append_claims(claims);
    let claims = meta_b_prefix.finish(b, context, &meta_b_terminal)?;
    context.append_claims(claims);
    crate::acceptance::row_ledger_mark(b, &mut ledger, "block-sidecar: wallet-A/meta-B suffixes");

    let meta_a_prefix =
        verify_walk_a_region_walk_deferred_prefix_trace(b, context, vk.meta_a(), &proof.meta_a)?;
    let owner_c_prefix =
        verify_duplex_region_walk_deferred_prefix_trace(b, context, vk.owner_c(), &proof.owner_c)?;
    let main_c_prefix =
        verify_duplex_region_walk_deferred_prefix_trace(b, context, vk.main_c(), &proof.main_c)?;
    crate::acceptance::row_ledger_mark(
        b,
        &mut ledger,
        "block-sidecar: meta-A/owner-C/main-C prefixes",
    );
    let groups = vec![
        vec![meta_a_prefix.walk_group()],
        vec![owner_c_prefix.walk_group()],
        vec![main_c_prefix.walk_group()],
    ];
    let walk = MultiDeepChainWalkProofTrace::alloc_ragged(
        b,
        &proof.meta_a_owner_main_walk,
        &meta_duplex_w_logs,
    );
    let terminals =
        verify_ragged_multi_deep_chain_walk_trace(b, context, &meta_duplex_w_logs, &groups, &walk);
    if terminals.len() != 3 {
        return Err(RegionSidecarError::InvalidProof);
    }
    let mut terminals = terminals.into_iter();
    let meta_a_terminal = terminals.next().expect("checked terminal count");
    let owner_c_terminal = terminals.next().expect("checked terminal count");
    let main_c_terminal = terminals.next().expect("checked terminal count");
    crate::acceptance::row_ledger_mark(
        b,
        &mut ledger,
        "block-sidecar: meta-A/owner-C/main-C multi-walk",
    );
    let claims = meta_a_prefix.finish(b, context, &meta_a_terminal)?;
    context.append_claims(claims);
    let claims = owner_c_prefix.finish(b, context, &owner_c_terminal)?;
    context.append_claims(claims);
    let claims = main_c_prefix.finish(b, context, &main_c_terminal)?;
    context.append_claims(claims);
    crate::acceptance::row_ledger_mark(
        b,
        &mut ledger,
        "block-sidecar: meta-A/owner-C/main-C suffixes",
    );

    verify_merkle_region_sidecar_trace_post_commit(b, context, vk.wallet_b(), &proof.wallet_b)?;
    crate::acceptance::row_ledger_mark(b, &mut ledger, "block-sidecar: wallet-B");
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

fn wallet_meta_w_logs(vk: &BlockRegionSidecarVk) -> [usize; 2] {
    [vk.wallet_a().w_log(), vk.meta_b().w_log()]
}

fn meta_duplex_w_logs(vk: &BlockRegionSidecarVk) -> [usize; 3] {
    [
        vk.meta_a().w_log(),
        vk.owner_c().w_log(),
        vk.main_c().w_log(),
    ]
}

fn max_w_log(w_logs: &[usize]) -> usize {
    *w_logs.iter().max().expect("non-empty block walk group")
}

fn bind_block_vk<Ch: Challenger>(challenger: &mut Ch, vk: &BlockRegionSidecarVk) {
    challenger.observe_label(vk.transcript_label());
    challenger.observe_bytes(&vk.transcript_digest());
}

fn prove_merkle<Ch: Challenger>(
    vk: &MerkleRegionVk,
    endpoints: &RegionWalkEndpoints,
    z: &[F128],
    challenger: &mut Ch,
    claims: &mut Vec<QuirkyDirectClaim>,
) -> Result<MerkleRegionSidecarProof, RegionSidecarError> {
    let plan = MerkleRegionProverPlan::new(vk, endpoints.s0(), endpoints.s_out())?;
    let (proof, child_claims) = plan.prove(z, challenger)?;
    claims.extend(child_claims);
    Ok(proof)
}

fn push_u64(bytes: &mut Vec<u8>, value: usize) {
    let value = u64::try_from(value).expect("block sidecar class index exceeds u64");
    bytes.extend_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use noid_ivc_core::deep_chain::{DeepChainWalkProof, MultiWalkLayerProof};
    use noid_ivc_core::public_io::WitnessSlice;

    use super::super::bounded_decode;
    use super::super::tests::{
        duplex_decode_fixture_with_purpose, merkle_decode_fixture_with_purpose,
    };
    use super::super::walk_a::tests::composite_decode_fixture as walk_a_fixture;
    use super::*;

    fn aligned_slices<const N: usize>(cursor: &mut usize, w_log: usize) -> [WitnessSlice; N] {
        let len = 1usize << w_log;
        *cursor = cursor.next_multiple_of(len);
        let base = *cursor / len;
        *cursor += N * len;
        std::array::from_fn(|column| WitnessSlice {
            log2_len: w_log,
            index: base + column,
        })
    }

    fn selected_duplex_vk(
        purpose: [u8; 32],
        layout: &noid_ivc_core::deep_chain::schedule::DuplexLayout,
        w_log: usize,
        tile_log: usize,
        slices: [WitnessSlice; 6],
    ) -> DuplexRegionVk {
        let [iv_hi, iv_lo] = capacity_iv(TAG_KSCHANNL);
        let iv = [flat_of_tower_u128(iv_hi.0), flat_of_tower_u128(iv_lo.0)];
        DuplexRegionVk::new(
            purpose,
            w_log,
            slices,
            duplex_fixed_patterns(layout, iv, tile_log),
            duplex_family_refs(0, 0),
            layout,
        )
        .expect("selected duplex VK fixture")
    }

    fn selected_b255_vk_fixture() -> BlockRegionSidecarVk {
        let mut cursor = 0usize;
        let wallet_a = WalkARegionVk::new_wallet(
            selected_zk_auth_wallet_a_sidecar_purpose(),
            SELECTED_ZK_AUTH_TX_LOG,
            SELECTED_ZK_AUTH_QUERY_LOG,
            aligned_slices(&mut cursor, SELECTED_ZK_AUTH_WALLET_A_W_LOG),
        )
        .unwrap();
        let meta_a = WalkARegionVk::new_meta(
            auth_pcs_meta_a_sidecar_purpose(),
            SELECTED_ZK_AUTH_TX_LOG,
            Some(13),
            Some(0),
            aligned_slices(&mut cursor, SELECTED_ZK_AUTH_META_A_W_LOG),
        )
        .unwrap();
        let capsule_iv = capacity_iv_flat(TAG_CAPSNODE).map(raw_flat_lane);
        let wallet_b = MerkleRegionVk::new(
            selected_zk_auth_wallet_b_sidecar_purpose(),
            SELECTED_ZK_AUTH_WALLET_B_W_LOG,
            aligned_slices(&mut cursor, SELECTED_ZK_AUTH_WALLET_B_W_LOG),
            10,
            vec![
                super::super::MerkleRegionFamily::FeedForward {
                    offset: 0,
                    depth: 8,
                    n_paths: 64,
                    iv: capsule_iv,
                },
                super::super::MerkleRegionFamily::FeedForward {
                    offset: 512,
                    depth: 8,
                    n_paths: 64,
                    iv: capsule_iv,
                },
            ],
        )
        .unwrap();
        let exact_state_iv = capacity_iv_flat(TAG_EXSTNOD).map(raw_flat_lane);
        let meta_b = MerkleRegionVk::new(
            auth_pcs_meta_b_sidecar_purpose(),
            SELECTED_ZK_AUTH_META_B_W_LOG,
            aligned_slices(&mut cursor, SELECTED_ZK_AUTH_META_B_W_LOG),
            9,
            vec![
                super::super::MerkleRegionFamily::PairedUpdate {
                    offset: 0,
                    n_updates: 6,
                    iv: exact_state_iv,
                },
                super::super::MerkleRegionFamily::PairedUpdate {
                    offset: 384,
                    n_updates: 1,
                    iv: exact_state_iv,
                },
                super::super::MerkleRegionFamily::TwoPermutation {
                    offset: 448,
                    depth: 8,
                    n_paths: 1,
                    iv: compress_iv_flat(),
                },
            ],
        )
        .unwrap();
        let schedules = ZkAuthCapsuleDuplexSchedules::selected();
        let owner_c = selected_duplex_vk(
            selected_zk_auth_owner_sidecar_purpose(),
            &schedules.owner_layout(),
            SELECTED_ZK_AUTH_OWNER_W_LOG,
            ZK_AUTH_OWNER_TILE_LOG,
            aligned_slices(&mut cursor, SELECTED_ZK_AUTH_OWNER_W_LOG),
        );
        let main_c = selected_duplex_vk(
            selected_zk_auth_main_sidecar_purpose(),
            &schedules.main_layout(),
            SELECTED_ZK_AUTH_MAIN_W_LOG,
            ZK_AUTH_MAIN_TILE_LOG,
            aligned_slices(&mut cursor, SELECTED_ZK_AUTH_MAIN_W_LOG),
        );
        BlockRegionSidecarVk::new_selected_zk(wallet_a, meta_a, wallet_b, meta_b, owner_c, main_c)
            .unwrap()
    }

    #[test]
    fn selected_b255_certificate_is_exact_v4_and_domain_separated() {
        let vk = selected_b255_vk_fixture();
        assert_eq!(vk.version(), BLOCK_REGION_SELECTED_ZK_SIDECAR_VERSION);
        vk.validate_selected_zk_roles().unwrap();
        assert_eq!(vk.wallet_a().w_log(), 19);
        assert_eq!(vk.wallet_b().w_log(), 18);
        assert_eq!(vk.owner_c().w_log(), 15);
        assert_eq!(vk.main_c().w_log(), 16);
        assert_eq!(
            block_bounded_shapes(&vk, 22).unwrap_err(),
            RegionSidecarError::BadSlice,
            "selected child slice outside the enclosing witness survived preflight"
        );

        let mut legacy_framed = vk.clone();
        legacy_framed.version = BLOCK_REGION_SIDECAR_VERSION;
        assert_ne!(vk.transcript_digest(), legacy_framed.transcript_digest());
        assert_eq!(
            legacy_framed.validate_roles(),
            Err(RegionSidecarError::UnsupportedVkShape)
        );
    }

    #[test]
    fn selected_certificate_rejects_purpose_layout_domain_k_and_mixed_pairs() {
        let exact = selected_b255_vk_fixture();

        let mut wrong_purpose = exact.clone();
        wrong_purpose.wallet_a = WalkARegionVk::new_wallet(
            auth_pcs_wallet_a_sidecar_purpose(),
            SELECTED_ZK_AUTH_TX_LOG,
            SELECTED_ZK_AUTH_QUERY_LOG,
            exact.wallet_a().slices().try_into().unwrap(),
        )
        .unwrap();
        assert_eq!(
            wrong_purpose.validate_selected_zk_roles(),
            Err(RegionSidecarError::UnsupportedVkShape)
        );

        let mut wrong_wallet_b_purpose = exact.clone();
        wrong_wallet_b_purpose.wallet_b = MerkleRegionVk::new(
            auth_pcs_wallet_b_sidecar_purpose(),
            exact.wallet_b().w_log(),
            *exact.wallet_b().slices(),
            exact.wallet_b().block_log(),
            exact.wallet_b().families().to_vec(),
        )
        .unwrap();
        assert_eq!(
            wrong_wallet_b_purpose.validate_selected_zk_roles(),
            Err(RegionSidecarError::UnsupportedVkShape)
        );

        let mut wrong_layout = exact.clone();
        wrong_layout.owner_c.layout_digest = [0xA5; 32];
        assert_eq!(
            wrong_layout.validate_selected_zk_roles(),
            Err(RegionSidecarError::UnsupportedVkShape)
        );

        let mut wrong_domain = exact.clone();
        let owner_layout = ZkAuthCapsuleDuplexSchedules::selected().owner_layout();
        let [iv_hi, iv_lo] = capacity_iv(noid_poseidon2b::native::domain::TAG_FRICHANL);
        wrong_domain.owner_c.fixed = duplex_fixed_patterns(
            &owner_layout,
            [flat_of_tower_u128(iv_hi.0), flat_of_tower_u128(iv_lo.0)],
            ZK_AUTH_OWNER_TILE_LOG,
        );
        assert_eq!(
            wrong_domain.validate_selected_zk_roles(),
            Err(RegionSidecarError::UnsupportedVkShape)
        );

        let mut wrong_k = exact.clone();
        wrong_k.wallet_a = WalkARegionVk::new_wallet(
            selected_zk_auth_wallet_a_sidecar_purpose(),
            SELECTED_ZK_AUTH_TX_LOG - 1,
            SELECTED_ZK_AUTH_QUERY_LOG,
            std::array::from_fn(|column| WitnessSlice {
                log2_len: SELECTED_ZK_AUTH_WALLET_A_W_LOG - 1,
                index: column,
            }),
        )
        .unwrap();
        assert_eq!(
            wrong_k.validate_selected_zk_roles(),
            Err(RegionSidecarError::UnsupportedVkShape)
        );

        let mut mixed = exact.clone();
        mixed.main_c.purpose = auth_pcs_main_c_sidecar_purpose();
        assert_eq!(
            mixed.validate_selected_zk_roles(),
            Err(RegionSidecarError::UnsupportedVkShape)
        );
        assert_eq!(
            mixed.validate_roles(),
            Err(RegionSidecarError::UnsupportedVkShape)
        );

        let mut overlap = exact.clone();
        let owner_layout = ZkAuthCapsuleDuplexSchedules::selected().owner_layout();
        overlap.owner_c = selected_duplex_vk(
            selected_zk_auth_owner_sidecar_purpose(),
            &owner_layout,
            SELECTED_ZK_AUTH_OWNER_W_LOG,
            ZK_AUTH_OWNER_TILE_LOG,
            std::array::from_fn(|column| WitnessSlice {
                log2_len: SELECTED_ZK_AUTH_OWNER_W_LOG,
                index: column,
            }),
        );
        assert_eq!(
            overlap.validate_selected_zk_roles(),
            Err(RegionSidecarError::BadSlice)
        );

        let mut wrong_meta = exact;
        wrong_meta.meta_b.families[2] = super::super::MerkleRegionFamily::TwoPermutation {
            offset: 448,
            depth: 7,
            n_paths: 1,
            iv: compress_iv_flat(),
        };
        assert_eq!(
            wrong_meta.validate_selected_zk_roles(),
            Err(RegionSidecarError::UnsupportedVkShape)
        );
    }

    fn resize_merkle_vk(mut vk: MerkleRegionVk, w_log: usize) -> MerkleRegionVk {
        vk.w_log = w_log;
        vk.slices = std::array::from_fn(|index| WitnessSlice {
            log2_len: w_log,
            index,
        });
        vk.layout_digest =
            super::super::merkle_layout_digest(vk.w_log, vk.block_log, &vk.fixed, &vk.families);
        vk
    }

    fn resize_duplex_vk(mut vk: DuplexRegionVk, w_log: usize) -> DuplexRegionVk {
        vk.w_log = w_log;
        vk.slices = std::array::from_fn(|index| WitnessSlice {
            log2_len: w_log,
            index,
        });
        vk
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
    fn block_bounded_decode_preflights_every_child_before_serde() {
        let (wallet_a_vk, wallet_a_vars, wallet_a) =
            walk_a_fixture(false, auth_pcs_wallet_a_sidecar_purpose());
        let (meta_a_vk, meta_a_vars, meta_a) =
            walk_a_fixture(true, auth_pcs_meta_a_sidecar_purpose());
        let (wallet_b_vk, wallet_b_vars, wallet_b, _) =
            merkle_decode_fixture_with_purpose(auth_pcs_wallet_b_sidecar_purpose());
        let (meta_b_vk, _meta_b_vars, meta_b, _) =
            merkle_decode_fixture_with_purpose(auth_pcs_meta_b_sidecar_purpose());
        let (owner_c_vk, _owner_c_vars, owner_c, _) =
            duplex_decode_fixture_with_purpose(owner_auth_duplex_sidecar_purpose());
        let (main_c_vk, _main_c_vars, main_c, _) =
            duplex_decode_fixture_with_purpose(auth_pcs_main_c_sidecar_purpose());
        let wallet_a_w_log = wallet_a_vk.w_log();
        let meta_b_w_log = wallet_a_w_log
            .checked_sub(1)
            .expect("wallet fixture has a non-trivial walk domain");
        let meta_a_w_log = meta_a_vk.w_log();
        let owner_c_w_log = meta_a_w_log + 1;
        let main_c_w_log = meta_a_w_log
            .checked_sub(1)
            .expect("meta fixture has a non-trivial walk domain");
        let meta_b_vk = resize_merkle_vk(meta_b_vk, meta_b_w_log);
        let owner_c_vk = resize_duplex_vk(owner_c_vk, owner_c_w_log);
        let main_c_vk = resize_duplex_vk(main_c_vk, main_c_w_log);
        let total_vars = [
            wallet_a_vars,
            meta_a_vars,
            wallet_b_vars,
            wallet_a_w_log + 4,
            meta_b_w_log + 4,
            meta_a_w_log + 3,
            owner_c_w_log + 3,
            main_c_w_log + 3,
        ]
        .into_iter()
        .max()
        .unwrap();
        let vk = BlockRegionSidecarVk::new(
            wallet_a_vk,
            meta_a_vk,
            wallet_b_vk,
            meta_b_vk,
            owner_c_vk,
            main_c_vk,
        )
        .unwrap();
        let (wallet_a, wallet_a_walk) = wallet_a.into_walk_deferred_parts(wallet_a_w_log);
        let (meta_b, meta_b_walk) = meta_b.into_walk_deferred_parts(meta_b_w_log);
        let wallet_a_meta_b_walk = shape_only_multi_walk(&[wallet_a_walk, meta_b_walk]);
        let (meta_a, meta_a_walk) = meta_a.into_walk_deferred_parts(meta_a_w_log);
        let (owner_c, owner_c_walk) = owner_c.into_walk_deferred_parts(owner_c_w_log);
        let (main_c, main_c_walk) = main_c.into_walk_deferred_parts(main_c_w_log);
        let meta_a_owner_main_walk =
            shape_only_multi_walk(&[meta_a_walk, owner_c_walk, main_c_walk]);
        let proof = BlockRegionSidecarProof {
            version: BLOCK_REGION_SIDECAR_VERSION,
            wallet_a,
            meta_b,
            wallet_a_meta_b_walk,
            meta_a,
            owner_c,
            main_c,
            meta_a_owner_main_walk,
            wallet_b,
        };
        let encoded = bincode::serialize(&proof).unwrap();

        // Envelope versions are keyed, not negotiable. A legacy V3 proof is
        // rejected before child parsing under the selected V4 composite VK.
        assert_eq!(encoded[0], BLOCK_REGION_SIDECAR_VERSION);
        assert_eq!(
            decode_block_region_sidecar_bounded(&selected_b255_vk_fixture(), 30, &encoded)
                .unwrap_err(),
            RegionSidecarError::UnsupportedVersion
        );

        let before = bounded_decode::serde_attempts();
        assert_eq!(
            decode_block_region_sidecar_bounded(&vk, total_vars, &encoded).unwrap(),
            proof
        );
        assert_eq!(bounded_decode::serde_attempts(), before + 1);
        let malformed_start = bounded_decode::serde_attempts();

        let mut trailing = encoded.clone();
        trailing.push(0);
        assert_eq!(
            decode_block_region_sidecar_bounded(&vk, total_vars, &trailing).unwrap_err(),
            RegionSidecarError::InvalidProof
        );
        assert_eq!(
            decode_block_region_sidecar_bounded(&vk, total_vars, &encoded[..encoded.len() - 1],)
                .unwrap_err(),
            RegionSidecarError::InvalidProof
        );
        let mut wrong_version = encoded.clone();
        wrong_version[0] = BLOCK_REGION_SIDECAR_VERSION.wrapping_add(1);
        assert_eq!(
            decode_block_region_sidecar_bounded(&vk, total_vars, &wrong_version).unwrap_err(),
            RegionSidecarError::UnsupportedVersion
        );

        let shapes = block_bounded_shapes(&vk, total_vars).unwrap();
        let offsets = bounded_decode::composite_layout_offsets(
            &encoded,
            BLOCK_REGION_SIDECAR_VERSION,
            &shapes,
        )
        .unwrap();
        let versions = offsets
            .iter()
            .filter_map(|(field, offset)| {
                (*field == bounded_decode::LayoutField::Version).then_some(*offset)
            })
            .collect::<Vec<_>>();
        assert_eq!(versions.len(), 7, "envelope plus six child versions");
        for offset in &versions[1..] {
            let mut forged = encoded.clone();
            forged[*offset] ^= 1;
            assert_eq!(
                decode_block_region_sidecar_bounded(&vk, total_vars, &forged).unwrap_err(),
                RegionSidecarError::UnsupportedVersion
            );
        }

        for child in 0..6 {
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
                decode_block_region_sidecar_bounded(&vk, total_vars, &forged).unwrap_err(),
                RegionSidecarError::InvalidProof
            );
        }

        let option_offsets = offsets
            .iter()
            .filter_map(|(field, offset)| {
                (*field == bounded_decode::LayoutField::OptionTag).then_some(*offset)
            })
            .collect::<Vec<_>>();
        assert_eq!(option_offsets.len(), 2, "wallet/meta Walk-A options");
        for offset in option_offsets {
            let mut forged = encoded.clone();
            forged[offset] ^= 1;
            assert_eq!(
                decode_block_region_sidecar_bounded(&vk, total_vars, &forged).unwrap_err(),
                RegionSidecarError::InvalidProof
            );
        }

        assert_eq!(
            bounded_decode::serde_attempts(),
            malformed_start,
            "malformed block envelope reached allocation-bearing serde"
        );
    }
}
