// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! HistoryStep parent PCS hashing discharged through the mandatory LinkRegion
//! sidecar ([`super::self_verify::PcsWalkObligations`] consumer).
//!
//! The predecessor replay records every PCS leaf sponge and
//! Merkle path as an obligation instead of replaying it inline (~90% of
//! the replay). This module hosts those obligations on two shared walks:
//!
//! - **walk L-A (leaves)** — one combined duplex union: each (proof,
//!   query) is a tile whose sub-channels are that query's leaf hashes,
//!   compiled as absorb-only schedules with the length-bound `IVCPCSF_`
//!   capacity IV (every [R] PCS leaf is even-lane, fixed no-pad mode).
//!   A leaf's digest is the C0/C1 carry cells at its sub-channel's last
//!   real slot; its absorbed lanes pin to the A-lane cells (the same
//!   proof wires the fold algebra consumes — Stage-2 cell pins).
//! - **walk L-B (paths)** — one ff-Merkle union with the `IVCPCSN_`
//!   capacity IV (the 1-permutation feed-forward node of the proof-core
//!   PCS): one max-depth carrier per tree position, with (proof role, query)
//!   on the path-block axis.  The actual authentication path is a causal
//!   prefix of its carrier. Entry binding: fresh digest wires pin to BOTH
//!   the walk L-A digest cells and `CR(start)`; direction cells pin to the
//!   transcript-bound query-position bits; `CR(actual_depth)`, proven by the
//!   carrier's chain relation, pins directly to the FS-observed root wire
//!   (commitment root / post-row-batch commit / epoch commits — all absorbed
//!   before the query draw, the capsule's authentication-root rule). The
//!   remaining suffix is relation-valid padding and has no semantic role.
//!
//! HistoryStep allocates both walks before the predecessor `[R]` replay,
//! add only the semantic cell pins in phase 2, and prove both relation
//! authorities after the enclosing Field commitment through
//! [`crate::region_sidecar::LinkRegionProverPlan`]. No opening-claim IO tail
//! and no B-to-A transcript recording is part of that path.
//!
//! Tree-structure invariant: every ladder shape yields the same leaf
//! signature — `[2^log_batch_size, 2^a0, 2^a0, 2^a0]` lanes (the
//! trailing sub-arity-`a0` fold layers live in the plaintext tail, never
//! behind a commitment) — asserted at assembly, so one sub-channel
//! schedule serves every tile.

use noid_ivc_core::deep_chain::ff_merkle::{
    build_ff_merkle_path_columns, ff_merkle_fixed_patterns, FfMerklePathFamily, FfMerklePathWitness,
};
use noid_ivc_core::deep_chain::relations::FixedPattern;
use noid_ivc_core::deep_chain::schedule::{compile_duplex, TranscriptOp};
use noid_ivc_core::field::F128;
use noid_ivc_core::field_circuit::{
    FieldR1csBuilder, FsChannelUnionRecorder, LayoutRecordedChannel, LinExpr,
};
use noid_ivc_core::pcs::{self, PcsParams};
use noid_ivc_core::proof::pcs_params_statement_bytes;
use noid_ivc_core::public_io::WitnessSlice;
use noid_poseidon2b::native::permutation::STATE_SIZE;
use noid_poseidon2b::native::poseidon2b_hash_byte_slices;

use crate::region_sidecar::{
    CombinedDuplexRegionDescriptor, CombinedDuplexRegionVk, CombinedDuplexSubChannelDescriptor,
    LinkRegionProverInput, LinkRegionSidecarVk, MerkleRegionFamily, MerkleRegionVk,
    RecordingDuplexRegionVk, RegionSidecarError, RegionWalkEndpoints,
    MAX_COMBINED_DUPLEX_DATA_LANES,
};

use noid_ivc_core::deep_chain::schedule::DuplexLayout;
use noid_ivc_core::field_circuit::RecordedChannel as FsRecordedChannel;

use super::pin_eq;
use super::region_source_binding::{
    alloc_boolean_column_slice_values_only, alloc_column_slice_values_only,
    build_combined_duplex_union, build_recording_only_duplex_union, common_period_ones,
    common_period_pattern, duplex_data_positions, pack_recording_only_blocks, place_ff, slot_cell,
    DuplexUnion, RecordingSpec, SubChannel,
};
use super::self_verify::{
    flat_digest_lanes, pcs_leaf_iv_flat, pcs_node_iv_flat, PcsWalkObligations,
};

const DOMAIN_LA: &[u8] = b"r-pcs-leaf-union-v0";
const DOMAIN_LB: &[u8] = b"r-pcs-merkle-union-v0";
const LINK_R_PCS_LEAF_SIDECAR_PURPOSE_DOMAIN: &[u8] = b"NOID/REGION-SIDECAR/LINK-R-PCS-LEAF-A/V1";
const LINK_R_PCS_PATH_SIDECAR_PURPOSE_DOMAIN: &[u8] = b"NOID/REGION-SIDECAR/LINK-R-PCS-PATH-B/V1";

/// Canonical role identifier for link-local `[R]` leaf Walk L-A.
pub fn link_r_pcs_leaf_sidecar_purpose() -> [u8; 32] {
    poseidon2b_hash_byte_slices(LINK_R_PCS_LEAF_SIDECAR_PURPOSE_DOMAIN, &[DOMAIN_LA])
}

/// Canonical role identifier for link-local `[R]` path Walk L-B.
pub fn link_r_pcs_path_sidecar_purpose() -> [u8; 32] {
    poseidon2b_hash_byte_slices(LINK_R_PCS_PATH_SIDECAR_PURPOSE_DOMAIN, &[DOMAIN_LB])
}

const LINK_RECORDINGS_REC_PURPOSE_DOMAIN: &[u8] = b"NOID/REGION-SIDECAR/HISTORY-STEP-RECORDINGS/V1";
/// Canonical role identifier for HistoryStep's recordings vertical (walk
/// L-C): two possible predecessor Block-child transcripts followed by two
/// possible `[R]_prev` transcripts. Exactly one block in each bank is live.
pub fn link_recordings_purpose() -> [u8; 32] {
    poseidon2b_hash_byte_slices(
        LINK_RECORDINGS_REC_PURPOSE_DOMAIN,
        &[
            crate::region_sidecar::BLOCK_SIDECAR_CHILD_DOMAIN,
            crate::acceptance::history_step::HISTORY_STEP_PROOF_DOMAIN,
        ],
    )
}

/// Walk L-B committed column layout (the wallet walk-B convention):
/// `C0..C3` at 0..4, `CR0..CR1` at 4..6, `SIB0..SIB1` at 6..8, `D` at 8.
const N_COMMITTED_B: usize = 9;

/// One verified proof's PCS side, as the assembly consumes it.
pub struct RPcsProof<'a> {
    pub native: &'a pcs::BaseFoldProof,
    pub params: &'a PcsParams,
    /// The initial codeword commitment root (flat lanes) — tree 0's root;
    /// the later trees' roots live in the proof itself.
    pub commitment_root: [F128; 2],
}

/// One authenticated tree of a proof: its leaf lane count and path depth.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TreeInfo {
    lanes: usize,
    depth: usize,
}

/// Canonical PCS carrier shared by the two possible HistoryStep parent tiers.
/// One predecessor proof occupies the tile/path axis; group selection changes
/// only witness data and never verifier topology.
#[derive(Clone, Debug)]
pub(crate) struct HistoryStepPcsCarrierGeometry {
    group_params: Vec<PcsParams>,
    groups: Vec<Vec<TreeInfo>>,
    n_queries: usize,
    proof_roles: usize,
}

impl HistoryStepPcsCarrierGeometry {
    fn subchannel_count(&self) -> usize {
        self.groups.iter().map(Vec::len).max().unwrap_or(0)
    }

    /// Exact L-A leaf schedule at each tree position. A smaller tier may omit a
    /// trailing committed FRI tree, in which case its tile carries a
    /// relation-valid ghost on that position; an existing tree may never
    /// change the lane count / leaf IV selected by the universal descriptor.
    fn leaf_lanes(&self) -> Result<Vec<usize>, RegionSidecarError> {
        let positions = self.subchannel_count();
        if positions < 2 {
            return Err(RegionSidecarError::UnsupportedVkShape);
        }
        let mut lanes = Vec::with_capacity(positions);
        for position in 0..positions {
            let mut present = self
                .groups
                .iter()
                .filter_map(|group| group.get(position))
                .map(|tree| tree.lanes);
            let first = present
                .next()
                .ok_or(RegionSidecarError::UnsupportedVkShape)?;
            if first < 2
                || first % 2 != 0
                || first > MAX_COMBINED_DUPLEX_DATA_LANES
                || present.any(|candidate| candidate != first)
            {
                return Err(RegionSidecarError::UnsupportedVkShape);
            }
            lanes.push(first);
        }
        Ok(lanes)
    }

    /// L-B's causal carrier depth at each tree position.  The carrier must
    /// expose `CR(actual_depth)` for a direct root pin.  A non-power-of-two
    /// maximum already has the ff-family root-copy tail; a power-of-two
    /// maximum needs one extra NODE so the same CR cell is selected by
    /// NODENS.  Production rate-1/4 depths are `[21, 17, 13, 9]`, all with a
    /// spare root-copy cell and therefore no increment.
    fn path_carrier_depths(&self) -> Result<Vec<usize>, RegionSidecarError> {
        let positions = self.subchannel_count();
        let mut depths = Vec::with_capacity(positions);
        for position in 0..positions {
            let max_actual = self
                .groups
                .iter()
                .filter_map(|group| group.get(position))
                .map(|tree| tree.depth)
                .max()
                .ok_or(RegionSidecarError::UnsupportedVkShape)?;
            let carrier = if max_actual.is_power_of_two() {
                max_actual.checked_add(1).ok_or(RegionSidecarError::BadVk)?
            } else {
                max_actual
            };
            if carrier == 0 {
                return Err(RegionSidecarError::UnsupportedVkShape);
            }
            depths.push(carrier);
        }
        Ok(depths)
    }

    fn path_block_log(&self) -> Result<usize, RegionSidecarError> {
        let slots = self
            .path_carrier_depths()?
            .into_iter()
            .try_fold(0usize, |sum, depth| {
                sum.checked_add(
                    depth
                        .checked_next_power_of_two()
                        .ok_or(RegionSidecarError::BadVk)?,
                )
                .ok_or(RegionSidecarError::BadVk)
            })?;
        slots
            .checked_next_power_of_two()
            .ok_or(RegionSidecarError::BadVk)
            .map(|block| block.trailing_zeros() as usize)
    }
}

/// One-role universal carrier for HistoryStep recursion.
///
/// The four groups are the possible predecessor output tiers.  L-A/L-B carry
/// exactly one active predecessor PCS proof, while L-C contains two banks in
/// canonical tier order: the predecessor Block-sidecar child transcript and
/// the enclosing HistoryStep `[R]_prev` transcript.  Exactly one block in
/// each bank is live.  Padding is relation-valid universal geometry, not an
/// omitted proof role.
#[derive(Clone, Debug)]
pub(crate) struct HistoryStepParentGeometry {
    carrier: HistoryStepPcsCarrierGeometry,
    child_layouts: Vec<DuplexLayout>,
    r_prev_layouts: Vec<DuplexLayout>,
    recording_blocks: Vec<(DuplexLayout, usize)>,
    rec_w_log: usize,
}

impl HistoryStepParentGeometry {
    fn from_parts(
        parent_params: &[PcsParams],
        child_layouts: Vec<DuplexLayout>,
        r_prev_layouts: Vec<DuplexLayout>,
    ) -> Result<Self, RegionSidecarError> {
        if parent_params.is_empty()
            || child_layouts.len() != parent_params.len()
            || r_prev_layouts.len() != parent_params.len()
            || child_layouts.iter().any(|layout| layout.slots.is_empty())
            || r_prev_layouts.iter().any(|layout| layout.slots.is_empty())
        {
            return Err(RegionSidecarError::BadVk);
        }
        let first = parent_params.first().ok_or(RegionSidecarError::BadVk)?;
        let n_queries = pcs::checked_fri_configuration(first.log_dim(), first.log_inv_rate)
            .map_err(|_| RegionSidecarError::UnsupportedVkShape)?
            .query_count;
        for params in parent_params {
            let config = pcs::checked_fri_configuration(params.log_dim(), params.log_inv_rate)
                .map_err(|_| RegionSidecarError::UnsupportedVkShape)?;
            if config.query_count != n_queries {
                return Err(RegionSidecarError::UnsupportedVkShape);
            }
        }
        let groups = parent_params
            .iter()
            .map(checked_tree_structure)
            .collect::<Result<Vec<_>, _>>()?;
        if groups.iter().any(|group| group.len() < 2) {
            return Err(RegionSidecarError::UnsupportedVkShape);
        }
        let carrier = HistoryStepPcsCarrierGeometry {
            group_params: parent_params.to_vec(),
            groups,
            n_queries,
            proof_roles: 1,
        };
        carrier.leaf_lanes()?;
        carrier.path_carrier_depths()?;
        let ordered = child_layouts
            .iter()
            .chain(r_prev_layouts.iter())
            .collect::<Vec<_>>();
        let (offsets, rec_w_log) = pack_recording_only_blocks(&ordered);
        let recording_blocks = ordered
            .into_iter()
            .cloned()
            .zip(offsets)
            .collect::<Vec<_>>();
        Ok(Self {
            carrier,
            child_layouts,
            r_prev_layouts,
            recording_blocks,
            rec_w_log,
        })
    }

    pub(crate) fn new(
        parent_params: &[PcsParams],
        child_layouts: Vec<DuplexLayout>,
        r_prev_layouts: Vec<DuplexLayout>,
    ) -> Result<Self, RegionSidecarError> {
        let tier_count = noid_chain::consensus::params::BLOCK_PAGE_CLASS_TIERS.len();
        if parent_params.len() != tier_count
            || child_layouts.len() != tier_count
            || r_prev_layouts.len() != tier_count
        {
            return Err(RegionSidecarError::BadVk);
        }
        Self::from_parts(parent_params, child_layouts, r_prev_layouts)
    }

    pub(crate) fn tier_count(&self) -> usize {
        self.child_layouts.len()
    }

    pub(crate) fn r_prev_layout(&self, slot: usize) -> Option<&DuplexLayout> {
        self.r_prev_layouts.get(slot)
    }

    #[cfg(test)]
    pub(crate) fn child_block_index(&self, slot: usize) -> usize {
        debug_assert!(slot < self.tier_count());
        slot
    }

    pub(crate) fn r_prev_block_index(&self, slot: usize) -> usize {
        debug_assert!(slot < self.tier_count());
        self.tier_count() + slot
    }

    #[cfg(test)]
    pub(crate) fn recording_blocks(&self) -> &[(DuplexLayout, usize)] {
        &self.recording_blocks
    }

    pub(crate) fn canonical_vk(
        &self,
        spec: &noid_ivc_core::public_io::PublicIoSpec,
    ) -> Result<LinkRegionSidecarVk, RegionSidecarError> {
        let leaf_w_log = crate::region_sidecar::combined_duplex_protocol_w_log(
            &combined_leaf_descriptor(&self.carrier)?,
        )?;
        let (_, path_w_log) = link_path_geometry(&self.carrier)?;
        let (leaf, path, rec) =
            canonical_link_walk_slices(spec, leaf_w_log, path_w_log, self.rec_w_log);
        self.vk_from_slices(leaf, path, rec)
    }

    fn recording_union(
        &self,
        active_slot: usize,
        children: &[LayoutRecordedChannel],
        r_prev: &LayoutRecordedChannel,
    ) -> Result<DuplexUnion, RegionSidecarError> {
        if children.len() != self.tier_count() {
            return Err(RegionSidecarError::UnsupportedVkShape);
        }
        for (child, expected) in children.iter().zip(self.child_layouts.iter()) {
            if &child.layout != expected || child.data_flat.len() != expected.n_data {
                return Err(RegionSidecarError::UnsupportedVkShape);
            }
        }
        // The banked parent envelope makes the outer transcript — and with it
        // all four banked `[R]_prev` layouts — independent of the live parent
        // tier, so the live recording always occupies (and is always pinned
        // at) the slot-zero block: the matrix must not encode the tier.
        let _ = active_slot;
        let expected_r_prev = self.r_prev_layout(0).ok_or(RegionSidecarError::BadVk)?;
        if &r_prev.layout != expected_r_prev || r_prev.data_flat.len() != expected_r_prev.n_data {
            return Err(RegionSidecarError::UnsupportedVkShape);
        }

        let zero_data = self
            .r_prev_layouts
            .iter()
            .map(|layout| vec![F128::ZERO; layout.n_data])
            .collect::<Vec<_>>();
        let mut specs = children
            .iter()
            .map(|child| (child.layout.clone(), child.data_flat.as_slice()))
            .chain(
                self.r_prev_layouts
                    .iter()
                    .zip(zero_data.iter())
                    .map(|(layout, zero)| (layout.clone(), zero.as_slice())),
            )
            .map(|(layout, data)| RecordingSpec {
                layout,
                iv_flat: FsChannelUnionRecorder::capacity_iv_flat(),
                data,
            })
            .collect::<Vec<_>>();
        specs[self.r_prev_block_index(0)].data = &r_prev.data_flat;
        Ok(build_recording_only_duplex_union(&specs))
    }

    fn vk_from_slices(
        &self,
        leaf_slices: [WitnessSlice; 6],
        path_slices: [WitnessSlice; N_COMMITTED_B],
        rec_slices: [WitnessSlice; 6],
    ) -> Result<LinkRegionSidecarVk, RegionSidecarError> {
        let leaf = CombinedDuplexRegionVk::new(
            link_r_pcs_leaf_sidecar_purpose(),
            combined_leaf_descriptor(&self.carrier)?,
            leaf_slices,
        )?;
        let carrier_depths = self.carrier.path_carrier_depths()?;
        let (block_log, w_log) = link_path_geometry(&self.carrier)?;
        let mut offset = 0usize;
        let mut families = Vec::with_capacity(carrier_depths.len());
        for depth in carrier_depths {
            families.push(MerkleRegionFamily::FeedForward {
                offset,
                depth,
                n_paths: 1,
                iv: pcs_node_iv_flat(),
            });
            offset = offset
                .checked_add(
                    depth
                        .checked_next_power_of_two()
                        .ok_or(RegionSidecarError::BadVk)?,
                )
                .ok_or(RegionSidecarError::BadVk)?;
        }
        if offset.next_power_of_two().trailing_zeros() as usize != block_log {
            return Err(RegionSidecarError::BadVk);
        }
        let path = MerkleRegionVk::new(
            link_r_pcs_path_sidecar_purpose(),
            w_log,
            path_slices,
            block_log,
            families,
        )?;
        let rec = RecordingDuplexRegionVk::new(
            link_recordings_purpose(),
            self.rec_w_log,
            rec_slices,
            self.recording_blocks.clone(),
        )?;
        LinkRegionSidecarVk::new(leaf, path, rec)
    }
}

/// The per-proof tree ladder, mirroring `basefold_verify_trace`'s shape
/// math: the initial codeword tree, the post-row-batch tree, then one
/// tree per FRI epoch commitment.
fn checked_tree_structure(params: &PcsParams) -> Result<Vec<TreeInfo>, RegionSidecarError> {
    if !(1..=5).contains(&params.log_inv_rate) {
        return Err(RegionSidecarError::UnsupportedVkShape);
    }
    let log_msg_len = params
        .m
        .checked_sub(pcs::LOG_PACKING)
        .ok_or(RegionSidecarError::UnsupportedVkShape)?;
    let log_batch_size = params.log_batch_size;
    let log_dim = log_msg_len
        .checked_sub(log_batch_size)
        .ok_or(RegionSidecarError::UnsupportedVkShape)?;
    let k_code = log_dim
        .checked_add(params.log_inv_rate)
        .ok_or(RegionSidecarError::BadVk)?;
    // Query-position sampling accepts at most 64 bits, while every concrete
    // vector/domain below also needs `2^log` to fit in `usize`.
    if log_batch_size >= usize::BITS as usize
        || k_code == 0
        || k_code > 64
        || k_code >= usize::BITS as usize
    {
        return Err(RegionSidecarError::UnsupportedVkShape);
    }
    let arities = pcs::compute_fri_arities(log_dim);
    let (num_fri_commits, _) = pcs::fri_commit_layout(k_code, &arities);
    let arity_0 = arities.first().copied().unwrap_or(0);
    let initial_lanes = 1usize << log_batch_size;
    if initial_lanes > MAX_COMBINED_DUPLEX_DATA_LANES {
        return Err(RegionSidecarError::UnsupportedVkShape);
    }
    let mut trees = vec![TreeInfo {
        lanes: initial_lanes,
        depth: k_code,
    }];
    if !arities.is_empty() {
        trees.push(TreeInfo {
            lanes: 1usize << arity_0,
            depth: k_code
                .checked_sub(arity_0)
                .ok_or(RegionSidecarError::BadVk)?,
        });
        let mut cum = arity_0;
        for i in 0..num_fri_commits {
            let next = *arities.get(i + 1).ok_or(RegionSidecarError::BadVk)?;
            let depth = k_code
                .checked_sub(cum)
                .and_then(|remaining| remaining.checked_sub(next))
                .ok_or(RegionSidecarError::BadVk)?;
            trees.push(TreeInfo {
                lanes: 1usize << next,
                depth,
            });
            cum = cum.checked_add(next).ok_or(RegionSidecarError::BadVk)?;
        }
    }
    if trees.iter().any(|tree| tree.depth == 0) {
        return Err(RegionSidecarError::UnsupportedVkShape);
    }
    Ok(trees)
}

/// The native leaf lanes of tree `t` for query `q`.
fn native_leaf_lanes<'a>(q: &'a pcs::basefold::QueryOpening, t: usize) -> &'a [F128] {
    match t {
        0 => &q.initial_leaf,
        1 => &q.post_row_batch_leaf,
        _ => &q.epoch_leaves[t - 2],
    }
}

/// The native sibling digests of tree `t` for query `q`, bottom-up flat.
fn native_path(q: &pcs::basefold::QueryOpening, t: usize) -> Vec<[F128; 2]> {
    let path = match t {
        0 => &q.initial_path,
        1 => &q.post_row_batch_path,
        _ => &q.epoch_paths[t - 2],
    };
    path.iter().map(flat_digest_lanes).collect()
}

/// The native root lanes of tree `t` (tree 0's root is the commitment,
/// supplied by the caller).
fn native_root(p: &RPcsProof<'_>, t: usize) -> [F128; 2] {
    match t {
        0 => p.commitment_root,
        1 => flat_digest_lanes(&p.native.post_row_batch_commit.root),
        _ => flat_digest_lanes(&p.native.round_commitments[t - 2].root),
    }
}

/// The direction-bit offset of tree `t`'s path within the query-position
/// bits (mirror of the replay's `&bits[..]` slices).
fn dir_bit_offset(trees: &[TreeInfo], t: usize, k_code: usize) -> usize {
    // depth = k_code - offset for every tree.
    k_code - trees[t].depth
}

/// Native leaf digest: `merkle::hash_leaf` over the flat lane bytes.
fn native_leaf_digest(lanes: &[F128]) -> [F128; 2] {
    let mut bytes = Vec::with_capacity(lanes.len() * 16);
    for l in lanes {
        let v = (l.lo as u128) | ((l.hi as u128) << 64);
        bytes.extend_from_slice(&v.to_le_bytes());
    }
    flat_digest_lanes(&noid_ivc_core::merkle::hash_leaf(&bytes))
}

/// HistoryStep parent walk assembly. Its L-A union is the exact
/// recording-free output of [`build_combined_duplex_union`], while L-B remains
/// an independent sibling vertical.
struct RecordingFreeLinkAssembly {
    u_a: DuplexUnion,
    leaf_descriptor: CombinedDuplexRegionDescriptor,
    digests: Vec<Vec<Vec<[F128; 2]>>>,
    /// Actual tree ladders of the two verified proofs.
    trees: Vec<Vec<TreeInfo>>,
    /// Global-within-tile `(slot, A-lane)` data cells per tree-position
    /// subchannel.
    leaf_data_positions: Vec<Vec<(usize, usize)>>,
    s_log: usize,
    n_queries: usize,
    cb: Vec<Vec<F128>>,
    s0b: [Vec<F128>; STATE_SIZE],
    soutb: [Vec<F128>; STATE_SIZE],
    fixed_b: Vec<FixedPattern>,
    path_families: Vec<MerkleRegionFamily>,
    /// L-B max-depth carrier offset indexed by tree position.
    leg_offsets: Vec<usize>,
    block_log_b: usize,
    w_log_b: usize,
}

fn combined_leaf_descriptor(
    geometry: &HistoryStepPcsCarrierGeometry,
) -> Result<CombinedDuplexRegionDescriptor, RegionSidecarError> {
    let subchannels = geometry
        .leaf_lanes()?
        .into_iter()
        .map(|lanes| {
            CombinedDuplexSubChannelDescriptor::new(
                vec![TranscriptOp::Absorb(vec![None; lanes])],
                pcs_leaf_iv_flat(lanes),
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    // HistoryStep has exactly one predecessor proof/query role.
    let live_tiles = geometry
        .proof_roles
        .checked_mul(geometry.n_queries)
        .ok_or(RegionSidecarError::BadVk)?;
    let padded_tiles = live_tiles
        .max(1)
        .checked_next_power_of_two()
        .ok_or(RegionSidecarError::BadVk)?;
    let tx_tile_log = padded_tiles.trailing_zeros() as usize;
    CombinedDuplexRegionDescriptor::new(tx_tile_log, subchannels)
}

/// Path carrier packing of the universal link walk L-B: `(block_log, w_log)`.
fn link_path_geometry(
    geometry: &HistoryStepPcsCarrierGeometry,
) -> Result<(usize, usize), RegionSidecarError> {
    let block_log = geometry.path_block_log()?;
    let live_blocks = geometry
        .proof_roles
        .checked_mul(geometry.n_queries)
        .ok_or(RegionSidecarError::BadVk)?;
    let blocks = live_blocks
        .max(1)
        .checked_next_power_of_two()
        .ok_or(RegionSidecarError::BadVk)?;
    let block = 1usize
        .checked_shl(block_log as u32)
        .ok_or(RegionSidecarError::BadVk)?;
    let cells = blocks.checked_mul(block).ok_or(RegionSidecarError::BadVk)?;
    if !cells.is_power_of_two() {
        return Err(RegionSidecarError::BadVk);
    }
    Ok((block_log, cells.trailing_zeros() as usize))
}

/// The canonical walk-column [`WitnessSlice`] table of every HistoryStep class:
/// columns are allocated right after the public-IO block, leaf family first,
/// then paths, then recordings, each family aligned to its own width.
/// Mirrors `alloc_column_slice` exactly.
pub(crate) fn canonical_link_walk_slices(
    spec: &noid_ivc_core::public_io::PublicIoSpec,
    leaf_w_log: usize,
    path_w_log: usize,
    rec_w_log: usize,
) -> (
    [WitnessSlice; 6],
    [WitnessSlice; N_COMMITTED_B],
    [WitnessSlice; 6],
) {
    fn family<const N: usize>(cursor: &mut usize, w_log: usize) -> [WitnessSlice; N] {
        let len = 1usize << w_log;
        *cursor = cursor.next_multiple_of(len);
        let base = *cursor / len;
        *cursor += N * len;
        std::array::from_fn(|column| WitnessSlice {
            log2_len: w_log,
            index: base + column,
        })
    }
    let mut cursor = spec.io_slice.start() + (1usize << spec.io_slice.log2_len);
    let leaf = family(&mut cursor, leaf_w_log);
    let path = family(&mut cursor, path_w_log);
    let rec = family(&mut cursor, rec_w_log);
    (leaf, path, rec)
}

fn build_recording_free_link_assembly(
    proofs: &[RPcsProof<'_>],
    geometry: &HistoryStepPcsCarrierGeometry,
    active_groups: &[usize],
) -> Result<RecordingFreeLinkAssembly, RegionSidecarError> {
    if proofs.is_empty()
        || proofs.len() != active_groups.len()
        || proofs.len() != geometry.proof_roles
        || proofs.len() > 2
    {
        return Err(RegionSidecarError::UnsupportedVkShape);
    }
    // The active group is the predecessor's output tier; universal carrier
    // topology stays unchanged by that selection.
    if active_groups
        .iter()
        .any(|group| *group >= geometry.groups.len())
        || (proofs.len() == 2 && (active_groups[0] != 0 || active_groups[1] == 0))
    {
        return Err(RegionSidecarError::UnsupportedVkShape);
    }
    let trees = proofs
        .iter()
        .map(|proof| checked_tree_structure(proof.params))
        .collect::<Result<Vec<_>, _>>()?;
    let n_queries = geometry.n_queries;
    if proofs
        .iter()
        .any(|proof| proof.native.queries.len() != n_queries)
    {
        return Err(RegionSidecarError::UnsupportedVkShape);
    }
    for (proof_index, actual) in trees.iter().enumerate() {
        let active_group = active_groups[proof_index];
        if actual != &geometry.groups[active_group]
            || pcs_params_statement_bytes(proofs[proof_index].params)
                != pcs_params_statement_bytes(&geometry.group_params[active_group])
        {
            return Err(RegionSidecarError::UnsupportedVkShape);
        }
    }
    let leaf_descriptor = combined_leaf_descriptor(geometry)?;
    let subs = leaf_descriptor
        .subchannels()
        .iter()
        .map(|descriptor| SubChannel {
            layout: compile_duplex(descriptor.schedule()),
            iv_flat: descriptor.iv_flat(),
        })
        .collect::<Vec<_>>();
    let s = subs
        .iter()
        .map(|subchannel| subchannel.layout.slots.len())
        .max()
        .unwrap_or(1)
        .max(1)
        .next_power_of_two();
    let s_log = s.trailing_zeros() as usize;

    let leaf_data_positions = subs
        .iter()
        .enumerate()
        .map(|(subchannel, sub)| {
            duplex_data_positions(&sub.layout)
                .into_iter()
                .map(|(slot, lane)| (subchannel * s + slot, lane))
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();

    let tile_capacity = proofs
        .len()
        .checked_mul(n_queries)
        .ok_or(RegionSidecarError::BadVk)?;
    let mut tiles = Vec::with_capacity(tile_capacity);
    let mut digests = Vec::with_capacity(proofs.len());
    for proof in proofs {
        let mut per_proof = Vec::with_capacity(n_queries);
        for query in &proof.native.queries {
            let mut tile = subs
                .iter()
                .map(|sub| vec![F128::ZERO; sub.layout.n_data])
                .collect::<Vec<_>>();
            let proof_index = digests.len();
            let mut query_digests = Vec::with_capacity(trees[proof_index].len());
            for tree in 0..trees[proof_index].len() {
                let lanes = native_leaf_lanes(query, tree);
                if lanes.len() != trees[proof_index][tree].lanes {
                    return Err(RegionSidecarError::UnsupportedVkShape);
                }
                tile[tree] = lanes.to_vec();
                query_digests.push(native_leaf_digest(lanes));
            }
            tiles.push(tile);
            per_proof.push(query_digests);
        }
        digests.push(per_proof);
    }
    let u_a = build_combined_duplex_union(&subs, &tiles);
    if !u_a.rec_blocks.is_empty() || !u_a.rec_refs.is_empty() || !u_a.rec_challenges.is_empty() {
        return Err(RegionSidecarError::UnsupportedVkShape);
    }

    let iv_node = pcs_node_iv_flat();
    let carrier_depths = geometry.path_carrier_depths()?;
    let mut leg_offsets = Vec::with_capacity(carrier_depths.len());
    let mut offset = 0usize;
    for &depth in &carrier_depths {
        leg_offsets.push(offset);
        offset = offset
            .checked_add(
                depth
                    .checked_next_power_of_two()
                    .ok_or(RegionSidecarError::BadVk)?,
            )
            .ok_or(RegionSidecarError::BadVk)?;
    }
    let block_b = offset
        .checked_next_power_of_two()
        .ok_or(RegionSidecarError::BadVk)?;
    let block_log_b = block_b.trailing_zeros() as usize;
    let live_blocks_b = proofs
        .len()
        .checked_mul(n_queries)
        .ok_or(RegionSidecarError::BadVk)?;
    let n_blocks_b = live_blocks_b
        .max(1)
        .checked_next_power_of_two()
        .ok_or(RegionSidecarError::BadVk)?;
    let pb = n_blocks_b
        .checked_mul(block_b)
        .ok_or(RegionSidecarError::BadVk)?;
    let w_log_b = pb.trailing_zeros() as usize;

    let mut cb = (0..N_COMMITTED_B)
        .map(|_| vec![F128::ZERO; pb])
        .collect::<Vec<_>>();
    let mut s0b: [Vec<F128>; STATE_SIZE] = std::array::from_fn(|_| vec![F128::ZERO; pb]);
    let mut soutb: [Vec<F128>; STATE_SIZE] = std::array::from_fn(|_| vec![F128::ZERO; pb]);
    let (ghost_s0, ghost_out) =
        noid_ivc_core::deep_chain::source_tree::run_perm([F128::ZERO; STATE_SIZE]);
    for slot in 0..pb {
        for lane in 0..STATE_SIZE {
            s0b[lane][slot] = ghost_s0[lane];
            soutb[lane][slot] = ghost_out[lane];
            cb[lane][slot] = ghost_out[lane];
        }
    }

    let mut fixed_b = Vec::new();
    let mut path_families = Vec::new();
    for (tree_index, &carrier_depth) in carrier_depths.iter().enumerate() {
        let family = FfMerklePathFamily {
            depth: carrier_depth,
            n_paths: 1,
        };
        let stride = family.stride();
        for pattern in ff_merkle_fixed_patterns(&family, iv_node) {
            fixed_b.push(common_period_pattern(
                &pattern.table,
                leg_offsets[tree_index],
                1,
                block_log_b,
            ));
        }
        fixed_b.push(common_period_ones(
            leg_offsets[tree_index],
            stride,
            block_log_b,
        ));
        path_families.push(MerkleRegionFamily::FeedForward {
            offset: leg_offsets[tree_index],
            depth: carrier_depth,
            n_paths: 1,
            iv: iv_node,
        });

        let family_w_log = stride.trailing_zeros() as usize;
        for block_index in 0..n_blocks_b {
            let live = (block_index < live_blocks_b).then(|| {
                let proof_index = block_index / n_queries;
                let query_index = block_index % n_queries;
                (proof_index, query_index)
            });
            let actual = live.and_then(|(proof_index, query_index)| {
                trees[proof_index].get(tree_index).map(|tree| {
                    (
                        proof_index,
                        query_index,
                        *tree,
                        &proofs[proof_index].native.queries[query_index],
                    )
                })
            });
            let witness = if let Some((proof_index, query_index, tree, query)) = actual {
                let bit_offset =
                    dir_bit_offset(&trees[proof_index], tree_index, trees[proof_index][0].depth);
                let mut siblings = native_path(query, tree_index);
                siblings.resize(carrier_depth, [F128::ZERO; 2]);
                let mut directions = (0..tree.depth)
                    .map(|level| (query.position >> (bit_offset + level)) & 1 == 1)
                    .collect::<Vec<_>>();
                directions.resize(carrier_depth, false);
                FfMerklePathWitness {
                    entry: digests[proof_index][query_index][tree_index],
                    siblings,
                    directions,
                }
            } else {
                FfMerklePathWitness {
                    entry: [F128::ZERO; 2],
                    siblings: vec![[F128::ZERO; 2]; carrier_depth],
                    directions: vec![false; carrier_depth],
                }
            };
            let columns = build_ff_merkle_path_columns(&family, iv_node, &[witness], family_w_log);
            if let Some((proof_index, _, tree, _)) = actual {
                assert_eq!(
                    [columns.cr[0][tree.depth], columns.cr[1][tree.depth]],
                    native_root(&proofs[proof_index], tree_index),
                    "ff carrier prefix root != committed root (proof {proof_index}, tree {tree_index}, block {block_index})"
                );
            }
            place_ff(
                &mut cb,
                &mut s0b,
                &mut soutb,
                &columns,
                block_index * block_b + leg_offsets[tree_index],
                stride,
            );
        }
    }

    let per_tile = 1usize << u_a.block_log;
    for (proof_index, per_proof) in digests.iter().enumerate() {
        for (query_index, query_digests) in per_proof.iter().enumerate() {
            let tile_offset = (proof_index * n_queries + query_index) * per_tile;
            for (tree_index, digest) in query_digests.iter().enumerate() {
                let digest_slot =
                    tile_offset + tree_index * s + trees[proof_index][tree_index].lanes / 2 - 1;
                assert_eq!(
                    [u_a.committed[2][digest_slot], u_a.committed[3][digest_slot]],
                    *digest,
                    "leaf digest cell mismatch (proof {proof_index}, query {query_index}, tree {tree_index})"
                );
            }
        }
    }

    Ok(RecordingFreeLinkAssembly {
        u_a,
        leaf_descriptor,
        digests,
        trees,
        leaf_data_positions,
        s_log,
        n_queries,
        cb,
        s0b,
        soutb,
        fixed_b,
        path_families,
        leg_offsets,
        block_log_b,
        w_log_b,
    })
}

/// Self-recursive HistoryStep columns over the universal two-tier parent
/// geometry.  The only live proof role is the exact predecessor; walk L-C
/// additionally carries that predecessor's nested Block-sidecar child chain
/// and its complete enclosing `[R]_prev` chain.
pub(crate) struct HistoryStepParentColumns {
    asm: RecordingFreeLinkAssembly,
    slices_a: [WitnessSlice; 6],
    slices_b: [WitnessSlice; N_COMMITTED_B],
    slices_rec: [WitnessSlice; 6],
    u_rec: DuplexUnion,
    child_scratches: Vec<LayoutRecordedChannel>,
    r_prev_scratch: LayoutRecordedChannel,
    r_prev_block: usize,
    vk: LinkRegionSidecarVk,
}

pub(crate) fn prepare_history_step_parent_columns(
    b: &mut FieldR1csBuilder,
    proof: &RPcsProof<'_>,
    geometry: &HistoryStepParentGeometry,
    active_slot: usize,
    child_recordings: Vec<LayoutRecordedChannel>,
    r_prev_recording: LayoutRecordedChannel,
) -> Result<HistoryStepParentColumns, RegionSidecarError> {
    if active_slot >= geometry.tier_count() {
        return Err(RegionSidecarError::BadVk);
    }
    let proofs = [RPcsProof {
        native: proof.native,
        params: proof.params,
        commitment_root: proof.commitment_root,
    }];
    let asm = build_recording_free_link_assembly(&proofs, &geometry.carrier, &[active_slot])?;
    let slices_a = std::array::from_fn(|column| {
        alloc_column_slice_values_only(b, &asm.u_a.committed[column], asm.u_a.w_log)
    });
    let slices_b = std::array::from_fn(|column| {
        if column == 8 {
            alloc_boolean_column_slice_values_only(b, &asm.cb[column], asm.w_log_b)
        } else {
            alloc_column_slice_values_only(b, &asm.cb[column], asm.w_log_b)
        }
    });
    let u_rec = geometry.recording_union(active_slot, &child_recordings, &r_prev_recording)?;
    let slices_rec = std::array::from_fn(|column| {
        alloc_column_slice_values_only(b, &u_rec.committed[column], u_rec.w_log)
    });

    let leaf_vk = CombinedDuplexRegionVk::from_union(
        link_r_pcs_leaf_sidecar_purpose(),
        asm.leaf_descriptor.clone(),
        slices_a,
        &asm.u_a,
    )?;
    let path_vk = MerkleRegionVk::from_fixed(
        link_r_pcs_path_sidecar_purpose(),
        asm.w_log_b,
        slices_b,
        asm.block_log_b,
        asm.path_families.clone(),
        &asm.fixed_b,
    )?;
    let rec_vk =
        RecordingDuplexRegionVk::from_union(link_recordings_purpose(), slices_rec, &u_rec)?;
    let vk = LinkRegionSidecarVk::new(leaf_vk, path_vk, rec_vk)?;
    if vk != geometry.vk_from_slices(slices_a, slices_b, slices_rec)? {
        return Err(RegionSidecarError::UnsupportedVkShape);
    }
    Ok(HistoryStepParentColumns {
        asm,
        slices_a,
        slices_b,
        slices_rec,
        u_rec,
        child_scratches: child_recordings,
        r_prev_scratch: r_prev_recording,
        r_prev_block: geometry.r_prev_block_index(0),
        vk,
    })
}

/// Production predecessor-recursion preparation for the three HistoryStep
/// parent sidecar verticals.
pub(crate) struct HistoryStepParentRegionPreparation {
    vk: LinkRegionSidecarVk,
    input: LinkRegionProverInput,
}

impl HistoryStepParentRegionPreparation {
    pub(crate) fn vk(&self) -> &LinkRegionSidecarVk {
        &self.vk
    }

    pub(crate) fn prover_input(&self) -> &LinkRegionProverInput {
        &self.input
    }
}

/// Pin one live recording block: the real recorded replay must reproduce the
/// prefill scratch exactly; its absorbed-data wires pin to the block's A-lane
/// cells and its squeezed challenges to the carry cells, so the union walk
/// (proven by the link sidecar and verified by the NEXT link / the terminal
/// decider) carries the whole recorded Fiat-Shamir chain.
#[allow(clippy::too_many_arguments)]
fn pin_recording_block(
    b: &mut FieldR1csBuilder,
    what: &str,
    scratch: &LayoutRecordedChannel,
    recorded: &FsRecordedChannel,
    vk: &LinkRegionSidecarVk,
    u_rec: &DuplexUnion,
    slices_rec: &[WitnessSlice; 6],
    block: usize,
) {
    assert_eq!(
        compile_duplex(&recorded.ops),
        scratch.layout,
        "{what} recording schedule drift"
    );
    assert_eq!(
        recorded.data_flat, scratch.data_flat,
        "{what} recording data drift"
    );
    assert_eq!(
        recorded.post_state, scratch.post_state,
        "{what} recording post-state drift"
    );
    assert_eq!(
        recorded.perms, scratch.perms,
        "{what} permutation-count drift"
    );
    let (rec_layout, rec_offset) = &vk.rec_c().blocks()[block];
    assert_eq!(
        recorded.challenge_wires.len(),
        rec_layout.challenges.len(),
        "{what} recording challenge count"
    );
    assert_eq!(
        recorded.data_wires.len(),
        rec_layout.n_data,
        "{what} recording data count"
    );
    for (k, &(slot, lane)) in rec_layout.challenges.iter().enumerate() {
        if let Some(native) = scratch.challenges[k] {
            assert_eq!(
                recorded.challenge_wires[k].eval(b.values()),
                native,
                "{what} native/trace challenge {k} drift"
            );
        }
        assert_eq!(
            recorded.challenge_wires[k].eval(b.values()),
            u_rec.rec_challenges[block][k],
            "{what} recording challenge {k} lockstep"
        );
        let cell = slot_cell(&slices_rec[2 + lane], rec_offset + slot);
        pin_eq(b, &recorded.challenge_wires[k], &cell);
    }
    for (k, &(slot, lane)) in duplex_data_positions(rec_layout).iter().enumerate() {
        let cell = slot_cell(&slices_rec[lane], rec_offset + slot);
        pin_eq(b, &recorded.data_wires[k], &cell);
    }
}

/// Self-recursive twin of [`finalize_r_pcs_history_step_region`].  Besides the
/// predecessor PCS obligations it pins every banked child recording block and
/// the live `[R]_prev` block; omitting the previous envelope's direct-Block
/// child transcript is therefore structurally impossible.
pub(crate) fn finalize_history_step_parent_region(
    b: &mut FieldR1csBuilder,
    columns: HistoryStepParentColumns,
    obligations: &PcsWalkObligations,
    recorded_children: &[FsRecordedChannel],
    recorded_r_prev: &FsRecordedChannel,
) -> Result<HistoryStepParentRegionPreparation, RegionSidecarError> {
    let HistoryStepParentColumns {
        asm,
        slices_a,
        slices_b,
        slices_rec,
        u_rec,
        child_scratches,
        r_prev_scratch,
        r_prev_block,
        vk,
    } = columns;
    if recorded_children.len() != child_scratches.len() {
        return Err(RegionSidecarError::UnsupportedVkShape);
    }
    if asm.trees.len() != 1 {
        return Err(RegionSidecarError::UnsupportedVkShape);
    }
    let n_trees = asm.trees[0].len();
    assert_eq!(
        obligations.leaves.len(),
        asm.n_queries * n_trees,
        "HistoryStep parent leaf obligation count"
    );
    assert_eq!(
        obligations.paths.len(),
        obligations.leaves.len(),
        "HistoryStep parent path/leaf pairing"
    );

    let per_tile = 1usize << asm.u_a.block_log;
    let subchannel_slots = 1usize << asm.s_log;
    let path_block = 1usize << asm.block_log_b;
    for query_index in 0..asm.n_queries {
        let tile_offset = query_index * per_tile;
        for tree_index in 0..n_trees {
            let leaf = &obligations.leaves[query_index * n_trees + tree_index];
            let positions = &asm.leaf_data_positions[tree_index];
            assert_eq!(
                leaf.lanes.len(),
                positions.len(),
                "HistoryStep parent leaf lanes"
            );
            for (wire, &(slot, lane)) in leaf.lanes.iter().zip(positions) {
                pin_eq(b, wire, &slot_cell(&slices_a[lane], tile_offset + slot));
            }

            let obligation = &obligations.paths[query_index * n_trees + tree_index];
            assert_eq!(
                obligation.leaf,
                query_index * n_trees + tree_index,
                "HistoryStep parent leaf/path pairing"
            );
            let depth = asm.trees[0][tree_index].depth;
            assert_eq!(obligation.dir_bits.len(), depth);
            let digest_slot =
                tile_offset + tree_index * subchannel_slots + asm.trees[0][tree_index].lanes / 2
                    - 1;
            let leg_slot = query_index * path_block + asm.leg_offsets[tree_index];
            for lane in 0..2 {
                let digest_wire =
                    LinExpr::from_wire(b.alloc_f128(asm.digests[0][query_index][tree_index][lane]));
                pin_eq(
                    b,
                    &digest_wire,
                    &slot_cell(&slices_a[2 + lane], digest_slot),
                );
                pin_eq(b, &digest_wire, &slot_cell(&slices_b[4 + lane], leg_slot));
            }
            for (level, bit) in obligation.dir_bits.iter().enumerate() {
                pin_eq(b, bit, &slot_cell(&slices_b[8], leg_slot + level));
            }
            let root_slot = leg_slot + depth;
            for lane in 0..2 {
                pin_eq(
                    b,
                    &slot_cell(&slices_b[4 + lane], root_slot),
                    &obligation.root[lane],
                );
            }
        }
    }
    for (block, (scratch, recorded)) in child_scratches
        .iter()
        .zip(recorded_children.iter())
        .enumerate()
    {
        // Child block index == tier slot by the geometry's packing order.
        pin_recording_block(
            b,
            "walk L-C HistoryStep parent Block child",
            scratch,
            recorded,
            &vk,
            &u_rec,
            &slices_rec,
            block,
        );
    }
    pin_recording_block(
        b,
        "walk L-C HistoryStep [R]_prev",
        &r_prev_scratch,
        recorded_r_prev,
        &vk,
        &u_rec,
        &slices_rec,
        r_prev_block,
    );

    let input = LinkRegionProverInput::new(
        &vk,
        RegionWalkEndpoints::new(asm.u_a.s0, asm.u_a.s_out),
        RegionWalkEndpoints::new(asm.s0b, asm.soutb),
        RegionWalkEndpoints::new(u_rec.s0, u_rec.s_out),
    )?;
    Ok(HistoryStepParentRegionPreparation { vk, input })
}

#[cfg(test)]
mod tests {
    use super::*;
    use noid_ivc_core::pcs::LOG_PACKING;
    use noid_ivc_core::public_io::PublicIoSpec;

    #[test]
    fn history_step_parent_geometry_has_two_tiers_and_four_recordings() {
        let params = [23usize, 24].map(|m| PcsParams {
            m: m + LOG_PACKING,
            log_inv_rate: 2,
            log_batch_size: 5,
            profile: Default::default(),
        });
        let layout = compile_duplex(&[
            TranscriptOp::Absorb(vec![None, Some(7), None]),
            TranscriptOp::Squeeze(2),
        ]);
        let geometry =
            HistoryStepParentGeometry::new(&params, vec![layout.clone(); 2], vec![layout; 2])
                .expect("two-tier HistoryStep geometry");
        assert_eq!(geometry.carrier.proof_roles, 1);
        assert_eq!(geometry.carrier.groups.len(), 2);
        assert_eq!(geometry.carrier.n_queries, 125);
        assert_eq!(geometry.recording_blocks().len(), 4);
        assert_eq!(geometry.child_block_index(1), 1);
        assert_eq!(geometry.r_prev_block_index(1), 3);

        let spec = PublicIoSpec {
            io_slice: WitnessSlice {
                log2_len: 10,
                index: 1,
            },
            io_len: 900,
            claims: Vec::new(),
        };
        geometry
            .canonical_vk(&spec)
            .expect("canonical HistoryStep parent sidecar VK");
    }
}
