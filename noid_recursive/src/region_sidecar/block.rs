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
use noid_ivc_core::public_io::{PublicIoSpec, WitnessSlice};
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
    auth_pcs_meta_a_sidecar_purpose, auth_pcs_meta_b_sidecar_purpose,
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

pub const BLOCK_REGION_SELECTED_ZK_SIDECAR_VERSION: u8 = 4;

/// Compact retained portion of a selected Block sidecar VK.
///
/// Every schedule, purpose, family descriptor, fixed table and walk geometry
/// is canonical for the tier and is regenerated on load.  Only the outer
/// witness locations vary with the frozen matrix layout and therefore need to
/// be persisted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SelectedZkBlockRegionVkSlices {
    pub wallet_a: [WitnessSlice; super::WALK_A_WALLET_COMMITTED_COLUMNS],
    pub meta_a: [WitnessSlice; super::WALK_A_META_COMMITTED_COLUMNS],
    pub wallet_b: [WitnessSlice; super::MERKLE_REGION_COMMITTED_COLUMNS],
    pub meta_b: [WitnessSlice; super::MERKLE_REGION_COMMITTED_COLUMNS],
    pub owner_c: [WitnessSlice; super::DUPLEX_REGION_COMMITTED_COLUMNS],
    pub main_c: [WitnessSlice; super::DUPLEX_REGION_COMMITTED_COLUMNS],
}

/// Exact selected authorization geometry for one canonical block class.
///
/// The four entries below are protocol certificates, not estimates.  Keeping
/// them explicit makes it impossible for a lower class to silently inherit
/// B255's 256 authorization tiles (and its RAM footprint), while the V4 VK
/// validation still rejects every geometry outside the canonical ladder.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SelectedZkBlockGeometry {
    pub tier: usize,
    pub auth_tiles: usize,
    pub tx_log: usize,
    pub owner_w_log: usize,
    pub main_w_log: usize,
    pub wallet_a_w_log: usize,
    pub wallet_b_w_log: usize,
    pub exact_state_region_log: usize,
    pub spine_cap_log: usize,
    pub meta_a_w_log: usize,
    pub meta_b_w_log: usize,
    pub meta_b_block_log: usize,
    pub touched_capacity: usize,
    pub segment_capacity: usize,
    pub paired_caps_per_block: [usize; 2],
    pub paired_bases: [usize; 2],
    pub tx_root_base: usize,
    pub tx_root_paths_per_block: usize,
}

pub(crate) const fn selected_zk_block_geometry(tier: usize) -> Option<SelectedZkBlockGeometry> {
    let geometry = match tier {
        8 => SelectedZkBlockGeometry {
            tier: 8,
            auth_tiles: 8,
            tx_log: 3,
            owner_w_log: 10,
            main_w_log: 11,
            wallet_a_w_log: 14,
            wallet_b_w_log: 13,
            exact_state_region_log: 9,
            spine_cap_log: 1,
            meta_a_w_log: 11,
            meta_b_w_log: 14,
            meta_b_block_log: 11,
            touched_capacity: 81,
            segment_capacity: 81,
            paired_caps_per_block: [11, 11],
            paired_bases: [0, 704],
            tx_root_base: 1_408,
            tx_root_paths_per_block: 32,
        },
        32 => SelectedZkBlockGeometry {
            tier: 32,
            auth_tiles: 32,
            tx_log: 5,
            owner_w_log: 12,
            main_w_log: 13,
            wallet_a_w_log: 16,
            wallet_b_w_log: 15,
            exact_state_region_log: 11,
            spine_cap_log: 1,
            meta_a_w_log: 13,
            meta_b_w_log: 16,
            meta_b_block_log: 11,
            touched_capacity: 321,
            segment_capacity: 256,
            paired_caps_per_block: [11, 8],
            paired_bases: [0, 704],
            tx_root_base: 1_216,
            tx_root_paths_per_block: 8,
        },
        64 => SelectedZkBlockGeometry {
            tier: 64,
            auth_tiles: 64,
            tx_log: 6,
            owner_w_log: 13,
            main_w_log: 14,
            wallet_a_w_log: 17,
            wallet_b_w_log: 16,
            exact_state_region_log: 12,
            spine_cap_log: 1,
            meta_a_w_log: 14,
            meta_b_w_log: 16,
            meta_b_block_log: 10,
            touched_capacity: 641,
            segment_capacity: 256,
            paired_caps_per_block: [11, 4],
            paired_bases: [0, 704],
            tx_root_base: 960,
            tx_root_paths_per_block: 4,
        },
        255 => SelectedZkBlockGeometry {
            tier: 255,
            auth_tiles: 256,
            tx_log: 8,
            owner_w_log: 15,
            main_w_log: 16,
            wallet_a_w_log: 19,
            wallet_b_w_log: 18,
            exact_state_region_log: 13,
            spine_cap_log: 0,
            meta_a_w_log: 15,
            meta_b_w_log: 17,
            meta_b_block_log: 9,
            touched_capacity: 1_531,
            segment_capacity: 256,
            paired_caps_per_block: [6, 1],
            paired_bases: [0, 384],
            tx_root_base: 448,
            tx_root_paths_per_block: 1,
        },
        _ => return None,
    };
    Some(geometry)
}

pub(crate) fn selected_zk_block_geometry_for_auth_tiles(
    auth_tiles: usize,
) -> Option<SelectedZkBlockGeometry> {
    noid_chain::consensus::params::USER_TX_CLASS_TIERS
        .into_iter()
        .filter_map(selected_zk_block_geometry)
        .find(|geometry| geometry.auth_tiles == auth_tiles)
}

const SELECTED_ZK_AUTH_QUERY_LOG: usize = 6;
#[cfg(test)]
const SELECTED_ZK_AUTH_TX_LOG: usize = 8;
#[cfg(test)]
const SELECTED_ZK_AUTH_OWNER_W_LOG: usize = 15;
#[cfg(test)]
const SELECTED_ZK_AUTH_WALLET_A_W_LOG: usize = 19;

const BLOCK_REGION_SELECTED_ZK_VK_DIGEST_DOMAIN: &[u8] = b"NOID/REGION-SIDECAR/BLOCK-ZK-AUTH-VK/V4";
const BLOCK_SELECTED_ZK_POST_COMMIT_CLASS_DIGEST_DOMAIN: &[u8] =
    b"NOID/REGION-SIDECAR/BLOCK-ZK-AUTH-POST-COMMIT-CLASS/V4";
const BLOCK_REGION_SELECTED_ZK_TRANSCRIPT_LABEL: &[u8] = b"history-region-sidecar-block-zk-auth-v4";

/// Canonical verification key for all six production block-region verticals.
///
/// Private fields make partial block keys unrepresentable outside this module.
/// The constructor accepts already validated child keys and freezes their role
/// and order into one digest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockRegionSidecarVk {
    wallet_a: WalkARegionVk,
    meta_a: WalkARegionVk,
    wallet_b: MerkleRegionVk,
    meta_b: MerkleRegionVk,
    owner_c: DuplexRegionVk,
    main_c: DuplexRegionVk,
}

impl BlockRegionSidecarVk {
    /// Rebuild a selected VK from its compact registry carrier.  This is a
    /// checked constructor, not a raw-field deserializer: all omitted data is
    /// regenerated from the canonical tier certificate, and the final
    /// six-child role validator compares the resulting duplex schedules and
    /// Merkle families byte-for-byte with production geometry.
    pub(crate) fn from_selected_registry_slices(
        tier: usize,
        slices: SelectedZkBlockRegionVkSlices,
    ) -> Result<Self, RegionSidecarError> {
        let geometry =
            selected_zk_block_geometry(tier).ok_or(RegionSidecarError::UnsupportedVkShape)?;
        let wallet_a = WalkARegionVk::new_wallet(
            selected_zk_auth_wallet_a_sidecar_purpose(),
            geometry.tx_log,
            SELECTED_ZK_AUTH_QUERY_LOG,
            slices.wallet_a,
        )?;
        let meta_a = WalkARegionVk::new_meta(
            auth_pcs_meta_a_sidecar_purpose(),
            geometry.tx_log,
            Some(geometry.exact_state_region_log),
            Some(geometry.spine_cap_log),
            slices.meta_a,
        )?;
        let capsule_iv = capacity_iv_flat(TAG_CAPSNODE).map(raw_flat_lane);
        let wallet_b = MerkleRegionVk::new(
            selected_zk_auth_wallet_b_sidecar_purpose(),
            geometry.wallet_b_w_log,
            slices.wallet_b,
            10,
            vec![
                super::MerkleRegionFamily::FeedForward {
                    offset: 0,
                    depth: 8,
                    n_paths: 64,
                    iv: capsule_iv,
                },
                super::MerkleRegionFamily::FeedForward {
                    offset: 512,
                    depth: 8,
                    n_paths: 64,
                    iv: capsule_iv,
                },
            ],
        )?;
        let exact_state_iv = capacity_iv_flat(TAG_EXSTNOD).map(raw_flat_lane);
        let meta_b = MerkleRegionVk::new(
            auth_pcs_meta_b_sidecar_purpose(),
            geometry.meta_b_w_log,
            slices.meta_b,
            geometry.meta_b_block_log,
            vec![
                super::MerkleRegionFamily::PairedUpdate {
                    offset: geometry.paired_bases[0],
                    n_updates: geometry.paired_caps_per_block[0],
                    iv: exact_state_iv,
                },
                super::MerkleRegionFamily::PairedUpdate {
                    offset: geometry.paired_bases[1],
                    n_updates: geometry.paired_caps_per_block[1],
                    iv: exact_state_iv,
                },
                super::MerkleRegionFamily::TwoPermutation {
                    offset: geometry.tx_root_base,
                    depth: 8,
                    n_paths: geometry.tx_root_paths_per_block,
                    iv: compress_iv_flat(),
                },
            ],
        )?;
        let schedules = ZkAuthCapsuleDuplexSchedules::selected();
        let [iv_hi, iv_lo] = capacity_iv(TAG_KSCHANNL);
        let iv = [flat_of_tower_u128(iv_hi.0), flat_of_tower_u128(iv_lo.0)];
        let owner_layout = schedules.owner_layout();
        let owner_c = DuplexRegionVk::new(
            selected_zk_auth_owner_sidecar_purpose(),
            geometry.owner_w_log,
            slices.owner_c,
            duplex_fixed_patterns(&owner_layout, iv, ZK_AUTH_OWNER_TILE_LOG),
            duplex_family_refs(0, 0),
            &owner_layout,
        )?;
        let main_layout = schedules.main_layout();
        let main_c = DuplexRegionVk::new(
            selected_zk_auth_main_sidecar_purpose(),
            geometry.main_w_log,
            slices.main_c,
            duplex_fixed_patterns(&main_layout, iv, ZK_AUTH_MAIN_TILE_LOG),
            duplex_family_refs(0, 0),
            &main_layout,
        )?;
        Self::new_selected_zk(wallet_a, meta_a, wallet_b, meta_b, owner_c, main_c)
    }

    pub(crate) fn selected_registry_slices(
        &self,
    ) -> Result<SelectedZkBlockRegionVkSlices, RegionSidecarError> {
        self.validate_selected_zk_roles()?;
        Ok(SelectedZkBlockRegionVkSlices {
            wallet_a: self
                .wallet_a
                .slices()
                .try_into()
                .map_err(|_| RegionSidecarError::UnsupportedVkShape)?,
            meta_a: self
                .meta_a
                .slices()
                .try_into()
                .map_err(|_| RegionSidecarError::UnsupportedVkShape)?,
            wallet_b: *self.wallet_b.slices(),
            meta_b: *self.meta_b.slices(),
            owner_c: *self.owner_c.slices(),
            main_c: *self.main_c.slices(),
        })
    }

    /// Construct the selected ZK-authorization six-child key.
    ///
    /// This is a VK shape certificate only.  It is deliberately not a
    /// committed-region capability: the only path to a selected mandatory
    /// preparation additionally consumes the all-class-tiles binding typestate.
    pub(crate) fn new_selected_zk(
        wallet_a: WalkARegionVk,
        meta_a: WalkARegionVk,
        wallet_b: MerkleRegionVk,
        meta_b: MerkleRegionVk,
        owner_c: DuplexRegionVk,
        main_c: DuplexRegionVk,
    ) -> Result<Self, RegionSidecarError> {
        let vk = Self {
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
        BLOCK_REGION_SELECTED_ZK_SIDECAR_VERSION
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
        let version = [BLOCK_REGION_SELECTED_ZK_SIDECAR_VERSION];
        poseidon2b_hash_byte_slices(
            BLOCK_REGION_SELECTED_ZK_VK_DIGEST_DOMAIN,
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

    fn transcript_label(&self) -> &'static [u8] {
        BLOCK_REGION_SELECTED_ZK_TRANSCRIPT_LABEL
    }

    /// Exact four-class selected certificate over all six child roles,
    /// layouts, domains and slices. Success does not by itself authorize
    /// proving: the Block builder must still bind every class tile and consume
    /// the resulting private typestate before a selected preparation can
    /// exist.
    pub(crate) fn validate_selected_zk_roles(&self) -> Result<(), RegionSidecarError> {
        use super::{MerkleRegionFamily, WalkARegionDescriptor};

        let tx_log = match self.wallet_a.descriptor() {
            WalkARegionDescriptor::Wallet {
                tx_log,
                nq_log: SELECTED_ZK_AUTH_QUERY_LOG,
            } => tx_log,
            _ => return Err(RegionSidecarError::UnsupportedVkShape),
        };
        let geometry = noid_chain::consensus::params::USER_TX_CLASS_TIERS
            .into_iter()
            .filter_map(selected_zk_block_geometry)
            .find(|geometry| geometry.tx_log == tx_log)
            .ok_or(RegionSidecarError::UnsupportedVkShape)?;

        if self.wallet_a.purpose() != &selected_zk_auth_wallet_a_sidecar_purpose()
            || self.meta_a.purpose() != &auth_pcs_meta_a_sidecar_purpose()
            || self.wallet_b.purpose() != &selected_zk_auth_wallet_b_sidecar_purpose()
            || self.meta_b.purpose() != &auth_pcs_meta_b_sidecar_purpose()
            || self.owner_c.purpose() != &selected_zk_auth_owner_sidecar_purpose()
            || self.main_c.purpose() != &selected_zk_auth_main_sidecar_purpose()
            || self.wallet_a.descriptor()
                != (WalkARegionDescriptor::Wallet {
                    tx_log: geometry.tx_log,
                    nq_log: SELECTED_ZK_AUTH_QUERY_LOG,
                })
            || self.wallet_a.w_log() != geometry.wallet_a_w_log
            || self.meta_a.descriptor()
                != (WalkARegionDescriptor::Meta {
                    tx_log: geometry.tx_log,
                    exact_state_region_log: Some(geometry.exact_state_region_log),
                    spine_cap_log: Some(geometry.spine_cap_log),
                })
            || self.meta_a.w_log() != geometry.meta_a_w_log
            || self.wallet_b.w_log() != geometry.wallet_b_w_log
            || self.wallet_b.block_log() != 10
            || self.meta_b.w_log() != geometry.meta_b_w_log
            || self.meta_b.block_log() != geometry.meta_b_block_log
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
                offset: geometry.paired_bases[0],
                n_updates: geometry.paired_caps_per_block[0],
                iv: exact_state_iv,
            },
            MerkleRegionFamily::PairedUpdate {
                offset: geometry.paired_bases[1],
                n_updates: geometry.paired_caps_per_block[1],
                iv: exact_state_iv,
            },
            MerkleRegionFamily::TwoPermutation {
                offset: geometry.tx_root_base,
                depth: 8,
                n_paths: geometry.tx_root_paths_per_block,
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
            geometry.owner_w_log,
            ZK_AUTH_OWNER_TILE_LOG,
        ) || !selected_duplex_vk_matches(
            self.main_c(),
            &schedules.main_layout(),
            selected_zk_auth_main_sidecar_purpose(),
            geometry.main_w_log,
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
    block_post_commit_class_digest_from_vk_digest(
        matrix_digest,
        spec,
        pcs_params,
        sidecar_vk.transcript_digest(),
    )
}

/// Recompute the selected-ZK Block composite identity from the compact VK
/// digest carried by an externally pinned class registry.
///
/// This is deliberately fixed to the selected-ZK version and domain.  It is
/// used by terminal-only registry materialization, which never verifies a
/// standalone Block sidecar and therefore does not need the large child VK
/// tables resident.  Prover materialization continues to rebuild the full VK.
pub(crate) fn selected_zk_block_post_commit_class_digest_from_vk_digest(
    matrix_digest: &[u8; 32],
    spec: &PublicIoSpec,
    pcs_params: &PcsParams,
    sidecar_vk_digest: [u8; 32],
) -> [u8; 32] {
    block_post_commit_class_digest_from_vk_digest(
        matrix_digest,
        spec,
        pcs_params,
        sidecar_vk_digest,
    )
}

/// Rebuild the aggregate selected-ZK Block VK identity without expanding any
/// child key.  The ordered child identities are already authenticated by the
/// external registry pin; this check prevents an inconsistent aggregate
/// carrier from entering the terminal class binding.
pub(crate) fn selected_zk_block_vk_digest_from_child_digests(child: &[[u8; 32]; 6]) -> [u8; 32] {
    let version = [BLOCK_REGION_SELECTED_ZK_SIDECAR_VERSION];
    poseidon2b_hash_byte_slices(
        BLOCK_REGION_SELECTED_ZK_VK_DIGEST_DOMAIN,
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

fn block_post_commit_class_digest_from_vk_digest(
    matrix_digest: &[u8; 32],
    spec: &PublicIoSpec,
    pcs_params: &PcsParams,
    sidecar_vk_digest: [u8; 32],
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

    let version = [BLOCK_REGION_SELECTED_ZK_SIDECAR_VERSION];
    poseidon2b_hash_byte_slices(
        BLOCK_SELECTED_ZK_POST_COMMIT_CLASS_DIGEST_DOMAIN,
        &[
            &version,
            b"block-zk-auth",
            matrix_digest,
            &spec_bytes,
            &pcs_bytes,
            &sidecar_vk_digest,
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
        Ok(Self { vk, input })
    }

    pub fn vk(&self) -> &BlockRegionSidecarVk {
        &self.vk
    }

    pub fn prover_input(&self) -> &BlockRegionProverInput {
        &self.input
    }

    pub fn prover_plan(&self) -> Result<BlockRegionProverPlan<'_>, RegionSidecarError> {
        BlockRegionProverPlan::new_selected_zk(&self.vk, &self.input)
    }

    pub fn into_parts(self) -> (BlockRegionSidecarVk, BlockRegionProverInput) {
        (self.vk, self.input)
    }
}

impl<'a> BlockRegionProverPlan<'a> {
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
        // Env-gated stage timing, mirroring NOIDH_FIELD_PROVE_TIMING.
        let timing = std::env::var_os("NOIDH_SIDECAR_TIMING").is_some();
        let mut t = std::time::Instant::now();
        let lap = move |label: &str, t: &mut std::time::Instant| {
            if timing {
                eprintln!(
                    "[block-sidecar] {label}: {:.1} ms",
                    t.elapsed().as_secs_f64() * 1e3
                );
            }
            *t = std::time::Instant::now();
        };
        bind_block_vk(challenger, self.vk);
        let mut claims = Vec::new();

        // Batch only the deep-chain walk shared by these ordered children.
        // The ragged embedding retains every child's native domain width; no
        // committed column or outer witness is padded to the group max.
        // Every prefix/suffix relation and every terminal opening remains a
        // separate role-bound proof.  The exact order below is the canonical
        // V4 block sidecar transcript and is mirrored by both verifier twins.
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
        lap("wallet-A prefix", &mut t);
        let meta_b_prefix = meta_b_plan.prove_walk_deferred_prefix(z, challenger)?;
        lap("meta-B prefix", &mut t);
        let groups = vec![
            vec![wallet_a_prefix.group().clone()],
            vec![meta_b_prefix.group().clone()],
        ];
        let s0 = [wallet_a_prefix.s0(), meta_b_prefix.s0()];
        let (wallet_a_meta_b_walk, terminals) =
            prove_ragged_multi_deep_chain_walk(&s0, &groups, challenger);
        lap("wallet-A/meta-B multi-walk", &mut t);
        let [wallet_a_terminal, meta_b_terminal]: [_; 2] = terminals
            .try_into()
            .expect("wallet-A/meta-B multi-walk terminal count");
        let (wallet_a, child_claims) = wallet_a_prefix.finish(&wallet_a_terminal, challenger)?;
        claims.extend(child_claims);
        let (meta_b, child_claims) = meta_b_prefix.finish(&meta_b_terminal, challenger)?;
        claims.extend(child_claims);
        lap("wallet-A/meta-B finish", &mut t);

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
        lap("meta-A prefix", &mut t);
        let owner_c_prefix = owner_c_plan.prove_walk_deferred_prefix(z, challenger)?;
        lap("owner-C prefix", &mut t);
        let main_c_prefix = main_c_plan.prove_walk_deferred_prefix(z, challenger)?;
        lap("main-C prefix", &mut t);
        let groups = vec![
            vec![meta_a_prefix.group().clone()],
            vec![owner_c_prefix.group().clone()],
            vec![main_c_prefix.group().clone()],
        ];
        let s0 = [meta_a_prefix.s0(), owner_c_prefix.s0(), main_c_prefix.s0()];
        let (meta_a_owner_main_walk, terminals) =
            prove_ragged_multi_deep_chain_walk(&s0, &groups, challenger);
        lap("meta-A/owner-C/main-C multi-walk", &mut t);
        let [meta_a_terminal, owner_c_terminal, main_c_terminal]: [_; 3] = terminals
            .try_into()
            .expect("meta-A/owner-C/main-C multi-walk terminal count");
        let (meta_a, child_claims) = meta_a_prefix.finish(&meta_a_terminal, challenger)?;
        claims.extend(child_claims);
        let (owner_c, child_claims) = owner_c_prefix.finish(&owner_c_terminal, challenger)?;
        claims.extend(child_claims);
        let (main_c, child_claims) = main_c_prefix.finish(&main_c_terminal, challenger)?;
        claims.extend(child_claims);
        lap("meta/owner/main finish", &mut t);

        // wallet-B has the only unmatched production domain and therefore
        // retains its ordinary single-instance authority.
        let wallet_b = prove_merkle(
            self.vk.wallet_b(),
            &self.input.wallet_b,
            z,
            challenger,
            &mut claims,
        )?;
        lap("wallet-B full", &mut t);

        Ok((
            BlockRegionSidecarProof {
                version: BLOCK_REGION_SELECTED_ZK_SIDECAR_VERSION,
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

/// The fixed-shape selected-ZK V4 block sidecar envelope.
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

/// Decode the mandatory V4 block envelope only after every deferred child,
/// both multi-walks, and the unmatched full child have passed one
/// allocation-free class-aware scan.
pub fn decode_block_region_sidecar_bounded(
    vk: &BlockRegionSidecarVk,
    total_vars: usize,
    bytes: &[u8],
) -> Result<BlockRegionSidecarProof, RegionSidecarError> {
    let shapes = block_bounded_shapes(vk, total_vars)?;
    preflight_composite_proof(bytes, BLOCK_REGION_SELECTED_ZK_SIDECAR_VERSION, &shapes)?;
    record_serde_attempt();
    let proof: BlockRegionSidecarProof =
        bincode::deserialize(bytes).map_err(|_| RegionSidecarError::InvalidProof)?;
    if proof.version != BLOCK_REGION_SELECTED_ZK_SIDECAR_VERSION {
        return Err(RegionSidecarError::UnsupportedVersion);
    }
    Ok(proof)
}

fn block_bounded_shapes(
    vk: &BlockRegionSidecarVk,
    total_vars: usize,
) -> Result<[SidecarProofShape; 8], RegionSidecarError> {
    vk.validate_selected_zk_roles()?;
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

/// Replay the canonical phased block authority and derive the complete outer PCS
/// claim list. No claim descriptor is accepted from the prover.
fn verify_block_region_sidecar<Ch: Challenger>(
    vk: &BlockRegionSidecarVk,
    total_vars: usize,
    proof: &BlockRegionSidecarProof,
    challenger: &mut Ch,
) -> Result<Vec<QuirkyDirectClaim>, RegionSidecarError> {
    vk.validate_selected_zk_roles()?;
    if proof.version != BLOCK_REGION_SELECTED_ZK_SIDECAR_VERSION {
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

/// Recursive trace verifier for the fixed V4 block authority. Every deferred
/// child, multi-walk, and the unmatched wallet-B proof is shape-preflighted
/// before the first proof witness allocation. Prefixes and suffixes remain
/// role-local; only the ragged-domain deep walks are random-linearly batched.
pub fn verify_block_region_sidecar_trace_post_commit<C: FsChannelOps>(
    b: &mut FieldR1csBuilder,
    context: &mut FieldPostCommitTraceContext<'_, C>,
    vk: &BlockRegionSidecarVk,
    proof: &BlockRegionSidecarProof,
) -> Result<(), RegionSidecarError> {
    vk.validate_selected_zk_roles()?;
    if proof.version != BLOCK_REGION_SELECTED_ZK_SIDECAR_VERSION {
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
    use noid_ivc_core::public_io::WitnessSlice;

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

    fn selected_vk_fixture(tier: usize) -> BlockRegionSidecarVk {
        let geometry = selected_zk_block_geometry(tier).unwrap();
        let mut cursor = 0usize;
        let wallet_a = WalkARegionVk::new_wallet(
            selected_zk_auth_wallet_a_sidecar_purpose(),
            geometry.tx_log,
            SELECTED_ZK_AUTH_QUERY_LOG,
            aligned_slices(&mut cursor, geometry.wallet_a_w_log),
        )
        .unwrap();
        let meta_a = WalkARegionVk::new_meta(
            auth_pcs_meta_a_sidecar_purpose(),
            geometry.tx_log,
            Some(geometry.exact_state_region_log),
            Some(geometry.spine_cap_log),
            aligned_slices(&mut cursor, geometry.meta_a_w_log),
        )
        .unwrap();
        let capsule_iv = capacity_iv_flat(TAG_CAPSNODE).map(raw_flat_lane);
        let wallet_b = MerkleRegionVk::new(
            selected_zk_auth_wallet_b_sidecar_purpose(),
            geometry.wallet_b_w_log,
            aligned_slices(&mut cursor, geometry.wallet_b_w_log),
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
            geometry.meta_b_w_log,
            aligned_slices(&mut cursor, geometry.meta_b_w_log),
            geometry.meta_b_block_log,
            vec![
                super::super::MerkleRegionFamily::PairedUpdate {
                    offset: geometry.paired_bases[0],
                    n_updates: geometry.paired_caps_per_block[0],
                    iv: exact_state_iv,
                },
                super::super::MerkleRegionFamily::PairedUpdate {
                    offset: geometry.paired_bases[1],
                    n_updates: geometry.paired_caps_per_block[1],
                    iv: exact_state_iv,
                },
                super::super::MerkleRegionFamily::TwoPermutation {
                    offset: geometry.tx_root_base,
                    depth: 8,
                    n_paths: geometry.tx_root_paths_per_block,
                    iv: compress_iv_flat(),
                },
            ],
        )
        .unwrap();
        let schedules = ZkAuthCapsuleDuplexSchedules::selected();
        let owner_c = selected_duplex_vk(
            selected_zk_auth_owner_sidecar_purpose(),
            &schedules.owner_layout(),
            geometry.owner_w_log,
            ZK_AUTH_OWNER_TILE_LOG,
            aligned_slices(&mut cursor, geometry.owner_w_log),
        );
        let main_c = selected_duplex_vk(
            selected_zk_auth_main_sidecar_purpose(),
            &schedules.main_layout(),
            geometry.main_w_log,
            ZK_AUTH_MAIN_TILE_LOG,
            aligned_slices(&mut cursor, geometry.main_w_log),
        );
        BlockRegionSidecarVk::new_selected_zk(wallet_a, meta_a, wallet_b, meta_b, owner_c, main_c)
            .unwrap()
    }

    fn selected_b255_vk_fixture() -> BlockRegionSidecarVk {
        selected_vk_fixture(255)
    }

    #[test]
    fn selected_v4_registry_accepts_exactly_four_canonical_geometries() {
        let mut digests = std::collections::BTreeSet::new();
        for tier in [8usize, 32, 64, 255] {
            let geometry = selected_zk_block_geometry(tier).unwrap();
            let vk = selected_vk_fixture(tier);
            vk.validate_selected_zk_roles().unwrap();
            assert_eq!(vk.wallet_a().w_log(), geometry.wallet_a_w_log);
            assert_eq!(vk.wallet_b().w_log(), geometry.wallet_b_w_log);
            assert_eq!(vk.meta_a().w_log(), geometry.meta_a_w_log);
            assert_eq!(vk.meta_b().w_log(), geometry.meta_b_w_log);
            assert_eq!(vk.owner_c().w_log(), geometry.owner_w_log);
            assert_eq!(vk.main_c().w_log(), geometry.main_w_log);
            assert!(digests.insert(vk.transcript_digest()));
        }
        assert!(selected_zk_block_geometry(0).is_none());
        assert!(selected_zk_block_geometry(9).is_none());
        assert!(selected_zk_block_geometry(256).is_none());
    }

    #[test]
    fn compact_selected_vk_slices_rehydrate_exact_identity() {
        for tier in noid_chain::consensus::params::USER_TX_CLASS_TIERS {
            let original = selected_vk_fixture(tier);
            let slices = original
                .selected_registry_slices()
                .expect("canonical selected VK compact carrier");
            let restored = BlockRegionSidecarVk::from_selected_registry_slices(tier, slices)
                .expect("compact carrier must regenerate the canonical VK");
            assert_eq!(restored, original);
            assert_eq!(restored.transcript_digest(), original.transcript_digest());
            let child = [
                original.wallet_a().transcript_digest(),
                original.meta_a().transcript_digest(),
                original.wallet_b().transcript_digest(),
                original.meta_b().transcript_digest(),
                original.owner_c().transcript_digest(),
                original.main_c().transcript_digest(),
            ];
            assert_eq!(
                selected_zk_block_vk_digest_from_child_digests(&child),
                original.transcript_digest(),
                "compact aggregate digest must be transcript-identical"
            );
            let matrix_digest = [tier as u8; 32];
            let spec = crate::acceptance::block_class::block_io_spec();
            let pcs = PcsParams {
                m: selected_zk_block_geometry(tier).unwrap().main_w_log + 12,
                log_inv_rate: 2,
                log_batch_size: 5,
                profile: Default::default(),
            };
            assert_eq!(
                selected_zk_block_post_commit_class_digest_from_vk_digest(
                    &matrix_digest,
                    &spec,
                    &pcs,
                    original.transcript_digest(),
                ),
                block_post_commit_class_digest(&matrix_digest, &spec, &pcs, &original),
                "compact post-commit computation must be transcript-identical"
            );
        }
    }

    #[test]
    fn selected_b255_certificate_is_exact_v4() {
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
    }

    #[test]
    fn selected_certificate_rejects_purpose_layout_domain_k_and_mixed_pairs() {
        let exact = selected_b255_vk_fixture();

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
}
