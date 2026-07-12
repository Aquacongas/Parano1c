// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! The [R] PCS hashing discharged through LINK-LOCAL region walks — the
//! split link's diet ([`super::self_verify::PcsWalkObligations`] consumer).
//!
//! A deferred [R] replay in region mode records every PCS leaf sponge and
//! Merkle path as an obligation instead of replaying it inline (~90% of
//! the replay). This module hosts the obligations of BOTH of the split
//! link's [R]s on TWO shared walks:
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
//! Production links allocate both walks before the deferred `[R]` replays,
//! add only the semantic cell pins in phase 2, and prove both relation
//! authorities after the enclosing Field commitment through
//! [`crate::region_sidecar::LinkRegionProverPlan`]. No opening-claim IO tail
//! and no B-to-A transcript recording is part of that path. The older native
//! point/value and inline-discharge APIs remain below for transitional tests.
//!
//! Tree-structure invariant: every ladder shape yields the same leaf
//! signature — `[2^log_batch_size, 2^a0, 2^a0, 2^a0]` lanes (the
//! trailing sub-arity-`a0` fold layers live in the plaintext tail, never
//! behind a commitment) — asserted at assembly, so one sub-channel
//! schedule serves every tile.

use noid_ivc_core::deep_chain::ff_merkle::{
    build_ff_merkle_path_columns, ff_merkle_fixed_patterns, FfMerkleFamilyRefs, FfMerklePathFamily,
    FfMerklePathWitness,
};
use noid_ivc_core::deep_chain::relations::FixedPattern;
use noid_ivc_core::deep_chain::schedule::{compile_duplex, TranscriptOp};
use noid_ivc_core::field::F128;
use noid_ivc_core::field_circuit::{
    FieldR1csBuilder, FsChannelTrace, FsChannelUnionRecorder, LinExpr, RecordedChannel,
};
use noid_ivc_core::pcs::{self, PcsParams};
use noid_ivc_core::proof::pcs_params_statement_bytes;
use noid_ivc_core::public_io::WitnessSlice;
use noid_poseidon2b::native::permutation::STATE_SIZE;
use noid_poseidon2b::native::poseidon2b_hash_byte_slices;

use crate::region_sidecar::{
    CombinedDuplexRegionDescriptor, CombinedDuplexRegionVk, CombinedDuplexSubChannelDescriptor,
    LinkRegionProverInput, LinkRegionSidecarVk, MerkleRegionFamily, MerkleRegionVk,
    RegionSidecarError, RegionWalkEndpoints, MAX_COMBINED_DUPLEX_DATA_LANES,
};

use super::region_source_binding::{
    alloc_boolean_column_slice, alloc_column_slice, build_combined_duplex_union,
    build_combined_duplex_union_with_recordings, common_period_ones, common_period_pattern,
    discharge_duplex_union, discharge_merkle_union, duplex_data_positions, place_ff,
    run_duplex_union_native, run_merkle_union_native, slot_cell, DuplexUnion, FfLegSpec, MerkleLeg,
    MerkleUnionNative, RecordingSpec, RegionPcsClaim, SubChannel,
};
use super::self_verify::{
    flat_digest_lanes, pcs_leaf_iv_flat, pcs_node_iv_flat, PcsWalkObligations,
};
use super::{mul, pin_eq};

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

/// Canonical link-side PCS geometry shared by every link class in a ladder.
///
/// Group zero is the (fixed-shape) previous-link proof.  The remaining
/// groups are the block-class ladder in canonical slot order.  Groups select
/// proof *data*, never verifier topology: L-A has one subchannel per tree
/// position and L-B has one max-depth carrier per tree position.  The two
/// mandatory proof roles (previous link and hosted block) live on the tile /
/// path-block axis.  Consequently every slot freezes the same two sidecar
/// authorities without paying a disjoint verifier bank for every block tier.
#[derive(Clone, Debug)]
pub(crate) struct RPcsLinkUniversalGeometry {
    group_params: Vec<PcsParams>,
    groups: Vec<Vec<TreeInfo>>,
    n_queries: usize,
}

impl RPcsLinkUniversalGeometry {
    /// Build the universal carrier topology from one fixed link PCS and every
    /// block-class PCS. Groups may have different tree counts and path depths,
    /// while every present tree at one position must share its leaf schedule.
    /// The query count is derived from each group's PCS rate and must agree.
    pub(crate) fn new(
        link_params: &PcsParams,
        block_params: &[PcsParams],
        n_queries: usize,
    ) -> Result<Self, RegionSidecarError> {
        if block_params.is_empty() || n_queries == 0 {
            return Err(RegionSidecarError::BadVk);
        }
        let query_count_matches = |params: &PcsParams| {
            (1..=5).contains(&params.log_inv_rate)
                && pcs::default_fri_queries(params.log_inv_rate) == n_queries
        };
        if !query_count_matches(link_params)
            || block_params
                .iter()
                .any(|params| !query_count_matches(params))
        {
            return Err(RegionSidecarError::UnsupportedVkShape);
        }
        let group_params = std::iter::once(link_params.clone())
            .chain(block_params.iter().cloned())
            .collect::<Vec<_>>();
        let groups = group_params
            .iter()
            .map(checked_tree_structure)
            .collect::<Result<Vec<_>, _>>()?;
        // The universal key must also admit the mandatory genesis carrier,
        // whose canonical BaseFold geometry has an initial and post-row tree.
        if groups.iter().any(|group| group.len() < 2) {
            return Err(RegionSidecarError::UnsupportedVkShape);
        }
        let geometry = Self {
            group_params,
            groups,
            n_queries,
        };
        // Freeze the role/tile carrier topology here, before any witness is
        // allocated.  Present trees at one position must share the exact leaf
        // hash schedule; path depths may differ and are covered by the
        // position's causal max-depth carrier.
        geometry.leaf_lanes()?;
        geometry.path_carrier_depths()?;
        Ok(geometry)
    }

    fn exact_for(proofs: &[RPcsProof<'_>]) -> Result<Self, RegionSidecarError> {
        if proofs.is_empty() {
            return Err(RegionSidecarError::BadVk);
        }
        let n_queries = proofs[0].native.queries.len();
        if n_queries == 0
            || proofs
                .iter()
                .any(|proof| proof.native.queries.len() != n_queries)
        {
            return Err(RegionSidecarError::UnsupportedVkShape);
        }
        let group_params = proofs
            .iter()
            .map(|proof| proof.params.clone())
            .collect::<Vec<_>>();
        let groups = group_params
            .iter()
            .map(checked_tree_structure)
            .collect::<Result<Vec<_>, _>>()?;
        if groups.iter().any(|group| group.len() < 2) {
            return Err(RegionSidecarError::UnsupportedVkShape);
        }
        let geometry = Self {
            group_params,
            groups,
            n_queries,
        };
        geometry.leaf_lanes()?;
        geometry.path_carrier_depths()?;
        Ok(geometry)
    }

    pub(crate) fn group_count(&self) -> usize {
        self.groups.len()
    }

    pub(crate) fn n_queries(&self) -> usize {
        self.n_queries
    }

    fn subchannel_count(&self) -> usize {
        self.groups.iter().map(Vec::len).max().unwrap_or(0)
    }

    /// Exact L-A leaf schedule at each tree position.  A tier may omit a
    /// trailing committed FRI tree (B8 does), in which case its tile carries a
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

/// Transitional callers still use assertion-style shape handling; all
/// production universal-geometry entry points call the checked twin above.
fn tree_structure(params: &PcsParams) -> Vec<TreeInfo> {
    checked_tree_structure(params).expect("supported BaseFold tree geometry")
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

fn hash_of_flat_lanes(lanes: [F128; 2]) -> [u8; 32] {
    let mut hash = [0u8; 32];
    for (lane, chunk) in lanes.into_iter().zip(hash.chunks_exact_mut(16)) {
        let value = (lane.lo as u128) | ((lane.hi as u128) << 64);
        chunk.copy_from_slice(&value.to_le_bytes());
    }
    hash
}

/// Canonical zero-data carrier used only to materialize the genesis ghost
/// sidecar columns before there is a previous recursive proof.  It is not
/// accepted as a Field proof: only the shape-derived leaves, paths and roots
/// are consumed by the recording-free column builder.
fn ghost_basefold_geometry(
    trees: &[TreeInfo],
    n_queries: usize,
) -> Result<(pcs::BaseFoldProof, [F128; 2]), RegionSidecarError> {
    if trees.len() < 2 || n_queries == 0 {
        return Err(RegionSidecarError::UnsupportedVkShape);
    }
    let zero_hash = [0u8; 32];
    let mut roots = Vec::with_capacity(trees.len());
    for tree in trees {
        let leaf = vec![F128::ZERO; tree.lanes];
        let family = FfMerklePathFamily {
            depth: tree.depth,
            n_paths: 1,
        };
        let columns = build_ff_merkle_path_columns(
            &family,
            pcs_node_iv_flat(),
            &[FfMerklePathWitness {
                entry: native_leaf_digest(&leaf),
                siblings: vec![[F128::ZERO; 2]; tree.depth],
                directions: vec![false; tree.depth],
            }],
            family.stride_log(),
        );
        roots.push(columns.roots[0]);
    }
    let query = pcs::basefold::QueryOpening {
        position: 0,
        initial_leaf: vec![F128::ZERO; trees[0].lanes],
        initial_path: vec![zero_hash; trees[0].depth],
        post_row_batch_leaf: vec![F128::ZERO; trees[1].lanes],
        post_row_batch_path: vec![zero_hash; trees[1].depth],
        epoch_leaves: trees[2..]
            .iter()
            .map(|tree| vec![F128::ZERO; tree.lanes])
            .collect(),
        epoch_paths: trees[2..]
            .iter()
            .map(|tree| vec![zero_hash; tree.depth])
            .collect(),
    };
    Ok((
        pcs::BaseFoldProof {
            round_messages: Vec::new(),
            post_row_batch_commit: pcs::RoundCommitment {
                root: hash_of_flat_lanes(roots[1]),
            },
            round_commitments: roots[2..]
                .iter()
                .copied()
                .map(|root| pcs::RoundCommitment {
                    root: hash_of_flat_lanes(root),
                })
                .collect(),
            final_a: F128::ZERO,
            final_b: F128::ZERO,
            final_codeword: Vec::new(),
            plaintext_tail: Vec::new(),
            pow_nonce: 0,
            queries: vec![query; n_queries],
        },
        roots[0],
    ))
}

/// Everything both the native mirror and the trace discharge derive from
/// the native proofs — built ONCE, deterministically.
struct Assembly {
    u_a: DuplexUnion,
    /// Per (proof, query, tree): the native leaf digest.
    digests: Vec<Vec<Vec<[F128; 2]>>>,
    /// Per proof: the tree ladder.
    trees: Vec<Vec<TreeInfo>>,
    /// Sub-channel stride log of walk L-A (`S = 2^s_log` slots per sub).
    s_log: usize,
    n_queries: usize,
    // ---- walk L-B ----
    cb: Vec<Vec<F128>>,
    s0b: [Vec<F128>; STATE_SIZE],
    soutb: [Vec<F128>; STATE_SIZE],
    fixed_b: Vec<FixedPattern>,
    ff_specs: Vec<FfLegSpec>,
    /// Per (proof, tree): the leg's slot offset within a query block.
    leg_offsets: Vec<Vec<usize>>,
    block_log_b: usize,
    w_log_b: usize,
    /// The walk L-B native run (proves + verifies once; phase 2 reuses it).
    native_b: MerkleUnionNative,
    /// The scratch recording of the walk L-B discharge transcript — the
    /// values walk L-A's region-2 block carries; phase 2's real discharge
    /// must reproduce it op-for-op.
    rec_b_scratch: RecordedChannel,
}

fn build_assembly(proofs: &[RPcsProof<'_>]) -> Assembly {
    assert!(!proofs.is_empty(), "at least one [R] proof");
    let trees: Vec<Vec<TreeInfo>> = proofs.iter().map(|p| tree_structure(p.params)).collect();
    let n_queries = proofs[0].native.queries.len();
    for p in proofs {
        assert_eq!(p.native.queries.len(), n_queries, "query counts must agree");
    }
    // One shared leaf-schedule signature (lane counts per tree).
    let lanes_sig: Vec<usize> = trees[0].iter().map(|t| t.lanes).collect();
    for tr in &trees {
        let sig: Vec<usize> = tr.iter().map(|t| t.lanes).collect();
        assert_eq!(
            sig, lanes_sig,
            "the [R] proofs must share the leaf-schedule signature (lanes per tree)"
        );
    }
    let n_trees = lanes_sig.len();

    // ---- Walk L-A: sub-channels + tiles.
    let subs: Vec<SubChannel> = lanes_sig
        .iter()
        .map(|&lanes| {
            assert!(lanes >= 2 && lanes % 2 == 0, "even-lane leaves only");
            SubChannel {
                layout: compile_duplex(&[TranscriptOp::Absorb(vec![None; lanes])]),
                iv_flat: pcs_leaf_iv_flat(lanes),
            }
        })
        .collect();
    let s = subs
        .iter()
        .map(|c| c.layout.slots.len())
        .max()
        .unwrap()
        .max(1)
        .next_power_of_two();
    let s_log = s.trailing_zeros() as usize;
    let mut tiles: Vec<Vec<Vec<F128>>> = Vec::with_capacity(proofs.len() * n_queries);
    let mut digests: Vec<Vec<Vec<[F128; 2]>>> = Vec::with_capacity(proofs.len());
    for p in proofs {
        let mut per_proof = Vec::with_capacity(n_queries);
        for q in &p.native.queries {
            let mut tile = Vec::with_capacity(n_trees);
            let mut ds = Vec::with_capacity(n_trees);
            for t in 0..n_trees {
                let lanes = native_leaf_lanes(q, t);
                assert_eq!(lanes.len(), lanes_sig[t], "native leaf off signature");
                tile.push(lanes.to_vec());
                ds.push(native_leaf_digest(lanes));
            }
            tiles.push(tile);
            per_proof.push(ds);
        }
        digests.push(per_proof);
    }
    // ---- Walk L-B: ff legs per (proof, tree), one path per query block.
    let iv_node = pcs_node_iv_flat();
    let mut leg_offsets: Vec<Vec<usize>> = Vec::with_capacity(proofs.len());
    let mut off = 0usize;
    for tr in &trees {
        let mut per_proof = Vec::with_capacity(tr.len());
        for t in tr {
            per_proof.push(off);
            off += t.depth.next_power_of_two();
        }
        leg_offsets.push(per_proof);
    }
    let block_b = off.next_power_of_two();
    let block_log_b = block_b.trailing_zeros() as usize;
    let n_blocks_b = n_queries.next_power_of_two();
    let pb = n_blocks_b * block_b;
    let w_log_b = pb.trailing_zeros() as usize;

    let mut cb: Vec<Vec<F128>> = (0..N_COMMITTED_B).map(|_| vec![F128::ZERO; pb]).collect();
    let mut s0b: [Vec<F128>; STATE_SIZE] = std::array::from_fn(|_| vec![F128::ZERO; pb]);
    let mut soutb: [Vec<F128>; STATE_SIZE] = std::array::from_fn(|_| vec![F128::ZERO; pb]);
    let (gh0, gho) = noid_ivc_core::deep_chain::source_tree::run_perm([F128::ZERO; STATE_SIZE]);
    for slot in 0..pb {
        for j in 0..STATE_SIZE {
            s0b[j][slot] = gh0[j];
            soutb[j][slot] = gho[j];
            cb[j][slot] = gho[j];
        }
    }
    let mut fixed_b: Vec<FixedPattern> = Vec::new();
    let mut ff_specs: Vec<FfLegSpec> = Vec::new();
    for (pi, p) in proofs.iter().enumerate() {
        for (t, tree) in trees[pi].iter().enumerate() {
            let family = FfMerklePathFamily {
                depth: tree.depth,
                n_paths: 1,
            };
            let stride = family.stride();
            let base = fixed_b.len();
            for pat in ff_merkle_fixed_patterns(&family, iv_node) {
                fixed_b.push(common_period_pattern(
                    &pat.table,
                    leg_offsets[pi][t],
                    1,
                    block_log_b,
                ));
            }
            fixed_b.push(common_period_ones(leg_offsets[pi][t], stride, block_log_b));
            ff_specs.push(FfLegSpec {
                refs: FfMerkleFamilyRefs {
                    cr: [4, 5],
                    sib: [6, 7],
                    d: 8,
                    c: std::array::from_fn(|i| i),
                    node: base,
                    nodens: base + 1,
                    start: base + 2,
                    iv: [base + 3, base + 4],
                },
                region: base + 5,
            });
            // Place every query's path chain for this leg. The query axis
            // is padded to a power of two and the family patterns are
            // PERIODIC over the query blocks, so the pad blocks must
            // carry VALID (zero-witness) chains — never bare ghost
            // permutations.
            let fam_wlog = stride.trailing_zeros() as usize;
            let root = native_root(p, t);
            let bit_off = dir_bit_offset(&trees[pi], t, trees[pi][0].depth);
            for qi in 0..n_blocks_b {
                let wit = if let Some(q) = p.native.queries.get(qi) {
                    FfMerklePathWitness {
                        entry: digests[pi][qi][t],
                        siblings: native_path(q, t),
                        directions: (0..tree.depth)
                            .map(|kk| (q.position >> (bit_off + kk)) & 1 == 1)
                            .collect(),
                    }
                } else {
                    FfMerklePathWitness {
                        entry: [F128::ZERO; 2],
                        siblings: vec![[F128::ZERO; 2]; tree.depth],
                        directions: vec![false; tree.depth],
                    }
                };
                let fcols = build_ff_merkle_path_columns(&family, iv_node, &[wit], fam_wlog);
                if qi < n_queries {
                    assert_eq!(
                        fcols.roots[0], root,
                        "ff leg root != committed root (proof {pi}, tree {t}, query {qi})"
                    );
                }
                place_ff(
                    &mut cb,
                    &mut s0b,
                    &mut soutb,
                    &fcols,
                    qi * block_b + leg_offsets[pi][t],
                    stride,
                );
            }
        }
    }

    // ---- Walk L-B native + the SCRATCH-RECORDED trace discharge. The
    // walk L-B discharge transcript rides walk L-A as a REGION-2 recording
    // block instead of an inline permutation replay (the 4f.1c diet applied
    // to the link walks; L-A's own transcript stays inline — a walk cannot
    // host its own transcript). The recording's VALUES must exist before
    // the L-A columns are built (the split link allocates walk columns
    // right after its IO cells), so a throwaway builder runs the discharge
    // twin once here; phase 2 re-runs it for real and asserts op/data/
    // challenge identity against this scratch recording.
    let committed_b: Vec<&[F128]> = cb.iter().map(|c| c.as_slice()).collect();
    let c_refs: [usize; STATE_SIZE] = std::array::from_fn(|i| i);
    let legs: Vec<MerkleLeg> = Vec::new();
    let native_b = run_merkle_union_native(
        &committed_b,
        &s0b,
        &soutb,
        &fixed_b,
        &c_refs,
        &ff_specs,
        &legs,
        w_log_b,
        DOMAIN_LB,
    );
    let mut scratch = FieldR1csBuilder::new();
    let mut rec_ch = FsChannelUnionRecorder::new(DOMAIN_LB);
    let (_, scratch_pins) = discharge_merkle_union(
        &mut scratch,
        &mut rec_ch,
        &fixed_b,
        &c_refs,
        &ff_specs,
        &legs,
        w_log_b,
        &native_b,
    );
    assert!(scratch_pins.is_empty(), "no 2-perm legs in the link walks");
    let rec_b_scratch = rec_ch.finish();

    // ---- Walk L-A: the combined union hosting the leaf tiles (region 1)
    // and the walk L-B discharge recording (region 2).
    let rec_spec = RecordingSpec {
        layout: compile_duplex(&rec_b_scratch.ops),
        iv_flat: FsChannelUnionRecorder::capacity_iv_flat(),
        data: &rec_b_scratch.data_flat,
    };
    let u_a = build_combined_duplex_union_with_recordings(&subs, &tiles, &[rec_spec]);
    // Sanity: the C0/C1 cells at each sub-channel's last real slot carry
    // the native leaf digest (the fixed no-pad sponge reads its state
    // directly after the last absorb permutation).
    let per_tile = 1usize << u_a.block_log;
    for (pi, per_proof) in digests.iter().enumerate() {
        for (qi, ds) in per_proof.iter().enumerate() {
            let tile_off = (pi * n_queries + qi) * per_tile;
            for (t, d) in ds.iter().enumerate() {
                let dslot = tile_off + t * s + lanes_sig[t] / 2 - 1;
                assert_eq!(
                    [u_a.committed[2][dslot], u_a.committed[3][dslot]],
                    *d,
                    "leaf digest cell mismatch (proof {pi}, query {qi}, tree {t})"
                );
            }
        }
    }

    Assembly {
        u_a,
        digests,
        trees,
        s_log,
        n_queries,
        cb,
        s0b,
        soutb,
        fixed_b,
        ff_specs,
        leg_offsets,
        block_log_b,
        w_log_b,
        native_b,
        rec_b_scratch,
    }
}

/// Production-only link walk assembly.  Unlike [`Assembly`], this type has no
/// native relation proof and no recorded channel: its L-A union is the exact
/// recording-free output of [`build_combined_duplex_union`], while L-B remains
/// an independent sibling vertical.
#[allow(dead_code)] // consumed by split_link after the recursive trace twin lands
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

#[allow(dead_code)]
fn combined_leaf_descriptor(
    geometry: &RPcsLinkUniversalGeometry,
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
    // Exactly two proof/query roles are live in every production link.  The
    // tier selector changes tile data only; it never changes topology.
    let live_tiles = 2usize
        .checked_mul(geometry.n_queries)
        .ok_or(RegionSidecarError::BadVk)?;
    let padded_tiles = live_tiles
        .max(1)
        .checked_next_power_of_two()
        .ok_or(RegionSidecarError::BadVk)?;
    let tx_tile_log = padded_tiles.trailing_zeros() as usize;
    CombinedDuplexRegionDescriptor::new(tx_tile_log, subchannels)
}

/// Rebuild the unique production Link sidecar VK from the canonical PCS
/// ladder and the compact outer-witness slices retained by the registry.
///
/// Unlike the general manual VK codec this constructor admits no caller-
/// selected schedule or Merkle family topology.  Terminal-only registry
/// loading uses it to keep the materialization bound tied to the four frozen
/// BaseFold tree positions instead of the much larger generic codec caps.
pub(crate) fn canonical_selected_link_region_sidecar_vk(
    link_params: &PcsParams,
    block_params: &[PcsParams],
    leaf_slices: [WitnessSlice; 6],
    path_slices: [WitnessSlice; N_COMMITTED_B],
) -> Result<LinkRegionSidecarVk, RegionSidecarError> {
    if !(1..=5).contains(&link_params.log_inv_rate) {
        return Err(RegionSidecarError::UnsupportedVkShape);
    }
    let n_queries = pcs::default_fri_queries(link_params.log_inv_rate);
    let geometry = RPcsLinkUniversalGeometry::new(link_params, block_params, n_queries)?;

    let leaf = CombinedDuplexRegionVk::new(
        link_r_pcs_leaf_sidecar_purpose(),
        combined_leaf_descriptor(&geometry)?,
        leaf_slices,
    )?;

    let carrier_depths = geometry.path_carrier_depths()?;
    let block_log = geometry.path_block_log()?;
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
    if offset
        .checked_next_power_of_two()
        .ok_or(RegionSidecarError::BadVk)?
        .trailing_zeros() as usize
        != block_log
    {
        return Err(RegionSidecarError::BadVk);
    }
    let live_blocks = 2usize
        .checked_mul(n_queries)
        .ok_or(RegionSidecarError::BadVk)?;
    let blocks = live_blocks
        .max(1)
        .checked_next_power_of_two()
        .ok_or(RegionSidecarError::BadVk)?;
    let block = 1usize
        .checked_shl(block_log as u32)
        .ok_or(RegionSidecarError::BadVk)?;
    let cells = blocks.checked_mul(block).ok_or(RegionSidecarError::BadVk)?;
    let w_log = cells.trailing_zeros() as usize;
    if !cells.is_power_of_two() {
        return Err(RegionSidecarError::BadVk);
    }
    let path = MerkleRegionVk::new(
        link_r_pcs_path_sidecar_purpose(),
        w_log,
        path_slices,
        block_log,
        families,
    )?;
    LinkRegionSidecarVk::new(leaf, path)
}

#[allow(dead_code)]
fn build_recording_free_link_assembly(
    proofs: &[RPcsProof<'_>],
    geometry: &RPcsLinkUniversalGeometry,
    active_groups: &[usize],
) -> Result<RecordingFreeLinkAssembly, RegionSidecarError> {
    if proofs.len() != 2 || active_groups.len() != 2 {
        return Err(RegionSidecarError::UnsupportedVkShape);
    }
    // Production roles are positional protocol constants, not a topology
    // choice: proof 0 is always the previous link (group 0), while proof 1
    // is one explicit block-ladder group.  Shape equality alone cannot infer
    // this mapping because B32/B64 and link/B255 legitimately share shapes.
    if active_groups[0] != 0 || active_groups[1] == 0 || active_groups[1] >= geometry.groups.len() {
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

    let tile_capacity = 2usize
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

/// The native (point, value) stream of every walk opening claim, in the
/// exact discharge order — the split link's IO fill (mirror of
/// `region_wallet_pcs_native`). Deterministic in the proofs alone.
pub fn r_pcs_region_native(proofs: &[RPcsProof<'_>]) -> Vec<(Vec<F128>, F128)> {
    let asm = build_assembly(proofs);
    let native_a = run_duplex_union_native(&asm.u_a, DOMAIN_LA);
    let mut out: Vec<(Vec<F128>, F128)> = Vec::new();
    for (_, pt, v) in &native_a.pending {
        out.push((pt.clone(), *v));
    }
    for (_, pt, v) in &asm.native_b.pending {
        out.push((pt.clone(), *v));
    }
    out
}

/// Phase-1 production handoff. Both committed walk matrices and their exact
/// sidecar VK are frozen before the deferred `[R]` obligations allocate any
/// class-specific wires. No native relation proof or point/value stream is
/// stored here.
#[allow(dead_code)]
pub(crate) struct RPcsLinkColumns {
    asm: RecordingFreeLinkAssembly,
    slices_a: [WitnessSlice; 6],
    slices_b: [WitnessSlice; N_COMMITTED_B],
    vk: LinkRegionSidecarVk,
}

/// Allocate the two independent recording-free link walk verticals. This is
/// the production phase-1 API; [`alloc_r_pcs_columns`] remains the transitional
/// recording-bearing twin.
#[allow(dead_code)]
pub(crate) fn prepare_r_pcs_link_columns(
    b: &mut FieldR1csBuilder,
    proofs: &[RPcsProof<'_>],
) -> Result<RPcsLinkColumns, RegionSidecarError> {
    let geometry = RPcsLinkUniversalGeometry::exact_for(proofs)?;
    let active_groups = (0..proofs.len()).collect::<Vec<_>>();
    prepare_r_pcs_link_columns_universal(b, proofs, &geometry, &active_groups)
}

/// Universal-ladder phase 1. `active_groups` maps the two verified proofs to
/// group zero (previous link) and `1 + current_block_slot`. The selection is
/// validated against the registry, then only chooses data for the shared
/// role/tile carriers; all link classes freeze the same sidecar VK and exact
/// witness-slice geometry.
pub(crate) fn prepare_r_pcs_link_columns_universal(
    b: &mut FieldR1csBuilder,
    proofs: &[RPcsProof<'_>],
    geometry: &RPcsLinkUniversalGeometry,
    active_groups: &[usize],
) -> Result<RPcsLinkColumns, RegionSidecarError> {
    let asm = build_recording_free_link_assembly(proofs, geometry, active_groups)?;
    let slices_a = std::array::from_fn(|column| {
        alloc_column_slice(b, &asm.u_a.committed[column], asm.u_a.w_log).0
    });
    let slices_b = std::array::from_fn(|column| {
        if column == 8 {
            alloc_boolean_column_slice(b, &asm.cb[column], asm.w_log_b).0
        } else {
            alloc_column_slice(b, &asm.cb[column], asm.w_log_b).0
        }
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
    let vk = LinkRegionSidecarVk::new(leaf_vk, path_vk)?;
    Ok(RPcsLinkColumns {
        asm,
        slices_a,
        slices_b,
        vk,
    })
}

/// Owning production output of phase 2. The outer link prover borrows these
/// two values to construct [`crate::region_sidecar::LinkRegionProverPlan`]
/// only inside its typestate post-commit callback.
#[allow(dead_code)]
pub(crate) struct RPcsLinkRegionPreparation {
    vk: LinkRegionSidecarVk,
    input: LinkRegionProverInput,
}

#[allow(dead_code)]
impl RPcsLinkRegionPreparation {
    pub(crate) fn vk(&self) -> &LinkRegionSidecarVk {
        &self.vk
    }

    pub(crate) fn prover_input(&self) -> &LinkRegionProverInput {
        &self.input
    }
}

/// Allocate the explicit genesis ghost using the same universal L-A/L-B key
/// as every ordinary link.  There are deliberately no deferred `[R]`
/// obligations to bind: the bootstrap relation verifies no predecessor.
/// Nevertheless both recording-free relations are real post-commit
/// authorities. The honest constructor uses canonical zero-data/zero-path
/// columns; verification requires a relation-valid ghost, not uniqueness of
/// that zero witness. Thus genesis T and an ordinary link share one transcript
/// shape without inventing deferred obligations at bootstrap.
pub(crate) fn prepare_r_pcs_link_genesis_ghost(
    b: &mut FieldR1csBuilder,
    geometry: &RPcsLinkUniversalGeometry,
) -> Result<RPcsLinkRegionPreparation, RegionSidecarError> {
    if geometry.groups.len() < 2 || geometry.group_params.len() != geometry.groups.len() {
        return Err(RegionSidecarError::BadVk);
    }
    let (link_proof, link_root) = ghost_basefold_geometry(&geometry.groups[0], geometry.n_queries)?;
    let (block_proof, block_root) =
        ghost_basefold_geometry(&geometry.groups[1], geometry.n_queries)?;
    let proofs = [
        RPcsProof {
            native: &link_proof,
            params: &geometry.group_params[0],
            commitment_root: link_root,
        },
        RPcsProof {
            native: &block_proof,
            params: &geometry.group_params[1],
            commitment_root: block_root,
        },
    ];
    let columns = prepare_r_pcs_link_columns_universal(b, &proofs, geometry, &[0, 1])?;
    let RPcsLinkColumns { asm, vk, .. } = columns;
    let input = LinkRegionProverInput::new(
        &vk,
        RegionWalkEndpoints::new(asm.u_a.s0, asm.u_a.s_out),
        RegionWalkEndpoints::new(asm.s0b, asm.soutb),
    )?;
    Ok(RPcsLinkRegionPreparation { vk, input })
}

/// Phase-2 production binding. It adds the same leaf/data/digest/cross-walk/
/// direction/root semantic pins as the transitional discharge, but creates no
/// relation proof, no FS channel, no recording block and no `RegionPcsClaim`.
#[allow(dead_code)]
pub(crate) fn finalize_r_pcs_link_region(
    b: &mut FieldR1csBuilder,
    columns: RPcsLinkColumns,
    obligations: &[&PcsWalkObligations],
) -> Result<RPcsLinkRegionPreparation, RegionSidecarError> {
    let RPcsLinkColumns {
        asm,
        slices_a,
        slices_b,
        vk,
    } = columns;
    assert_eq!(
        obligations.len(),
        asm.trees.len(),
        "one obligation set per proof"
    );
    for (proof_index, proof_obligations) in obligations.iter().enumerate() {
        let n_trees = asm.trees[proof_index].len();
        assert_eq!(
            proof_obligations.leaves.len(),
            asm.n_queries * n_trees,
            "proof {proof_index}: leaf obligation count off the tree ladder"
        );
        assert_eq!(
            proof_obligations.paths.len(),
            proof_obligations.leaves.len(),
            "proof {proof_index}: path/leaf pairing"
        );
    }

    let mut ledger = b.num_wires();
    let per_tile = 1usize << asm.u_a.block_log;
    let subchannel_slots = 1usize << asm.s_log;
    let path_block = 1usize << asm.block_log_b;
    for (proof_index, proof_obligations) in obligations.iter().enumerate() {
        let n_trees = asm.trees[proof_index].len();
        for query_index in 0..asm.n_queries {
            let tile_offset = (proof_index * asm.n_queries + query_index) * per_tile;
            for tree_index in 0..n_trees {
                let subchannel = tree_index;
                let leaf = &proof_obligations.leaves[query_index * n_trees + tree_index];
                let positions = &asm.leaf_data_positions[subchannel];
                assert_eq!(
                    leaf.lanes.len(),
                    positions.len(),
                    "proof {proof_index}, tree {tree_index}: leaf lane count vs universal subchannel"
                );
                for (wire, &(slot, lane)) in leaf.lanes.iter().zip(positions) {
                    pin_eq(b, wire, &slot_cell(&slices_a[lane], tile_offset + slot));
                }

                let obligation = &proof_obligations.paths[query_index * n_trees + tree_index];
                assert_eq!(
                    obligation.leaf,
                    query_index * n_trees + tree_index,
                    "leaf/path pairing"
                );
                let depth = asm.trees[proof_index][tree_index].depth;
                assert_eq!(obligation.dir_bits.len(), depth, "direction bit count");
                let digest_slot = tile_offset
                    + subchannel * subchannel_slots
                    + asm.trees[proof_index][tree_index].lanes / 2
                    - 1;
                let path_block_index = proof_index * asm.n_queries + query_index;
                let leg_slot = path_block_index * path_block + asm.leg_offsets[tree_index];
                for lane in 0..2 {
                    let digest_wire = LinExpr::from_wire(
                        b.alloc_f128(asm.digests[proof_index][query_index][tree_index][lane]),
                    );
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
                // `NODENS(root_slot)` proves that this committed CR cell is
                // exactly the feed-forward output of the final real prefix
                // node.  Carrier suffix nodes are relation-valid padding and
                // cannot change the already committed prefix root.
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
    }
    crate::acceptance::row_ledger_mark(b, &mut ledger, "r-pcs: recording-free link semantic pins");

    let leaf_endpoints = RegionWalkEndpoints::new(asm.u_a.s0, asm.u_a.s_out);
    let path_endpoints = RegionWalkEndpoints::new(asm.s0b, asm.soutb);
    let input = LinkRegionProverInput::new(&vk, leaf_endpoints, path_endpoints)?;
    Ok(RPcsLinkRegionPreparation { vk, input })
}

/// Phase 1 of the walk discharge: build the assembly from the native
/// proofs and ALLOCATE the committed walk columns. The caller runs this
/// right after its public-IO cells, BEFORE anything class-specific (the
/// verified envelopes, the replays), so the columns' [`WitnessSlice`]s —
/// hence the class's opening-claim spec — depend on the two PCS parameter
/// sets alone and stay IDENTICAL across every link class of a ladder.
pub(crate) struct RPcsColumns {
    asm: Assembly,
    slices_a: Vec<WitnessSlice>,
    slices_b: Vec<WitnessSlice>,
}

pub(crate) fn alloc_r_pcs_columns(
    b: &mut FieldR1csBuilder,
    proofs: &[RPcsProof<'_>],
) -> RPcsColumns {
    let asm = build_assembly(proofs);
    let slices_a: Vec<WitnessSlice> = asm
        .u_a
        .committed
        .iter()
        .map(|c| alloc_column_slice(b, c, asm.u_a.w_log).0)
        .collect();
    let slices_b: Vec<WitnessSlice> = asm
        .cb
        .iter()
        .map(|c| alloc_column_slice(b, c, asm.w_log_b).0)
        .collect();
    RPcsColumns {
        asm,
        slices_a,
        slices_b,
    }
}

/// Phase 2: discharge BOTH [R]s' PCS obligations on the two link walks —
/// replay each walk's discharge in-trace and bind every obligation (leaf
/// lanes → A cells, leaf digests → L-A digest cells AND L-B entry cells,
/// direction bits → D cells, recomputed roots → the FS-observed root
/// wires). Returns the committed-column opening claims for the caller's
/// public-IO tail — claim order matches [`r_pcs_region_native`].
pub(crate) fn discharge_r_pcs_via_region(
    b: &mut FieldR1csBuilder,
    cols: RPcsColumns,
    obligations: &[&PcsWalkObligations],
) -> Vec<RegionPcsClaim> {
    let RPcsColumns {
        asm,
        slices_a,
        slices_b,
    } = cols;
    let n_trees = asm.trees[0].len();
    assert_eq!(
        obligations.len(),
        asm.trees.len(),
        "one obligation set per proof"
    );
    for (pi, obs) in obligations.iter().enumerate() {
        assert_eq!(
            obs.leaves.len(),
            asm.n_queries * n_trees,
            "proof {pi}: leaf obligation count off the tree ladder"
        );
        assert_eq!(
            obs.paths.len(),
            obs.leaves.len(),
            "proof {pi}: path/leaf pairing"
        );
    }

    // ---- Walk L-A native (over the recording-bearing domain; walk L-B's
    // native run rides the assembly).
    let native_a = run_duplex_union_native(&asm.u_a, DOMAIN_LA);
    let c_refs: [usize; STATE_SIZE] = std::array::from_fn(|i| i);
    let legs: Vec<MerkleLeg> = Vec::new();

    // ---- Walk L-B discharge FIRST, on a RECORDER: its transcript rides
    // walk L-A's region-2 block; the real recording must reproduce the
    // assembly's scratch recording exactly (same native inputs — any drift
    // is a bug, caught loudly here before the cell pins).
    let mut ledger = b.num_wires();
    let mut ch_b = FsChannelUnionRecorder::new(DOMAIN_LB);
    let (mut claims_b, leg_pins) = discharge_merkle_union(
        b,
        &mut ch_b,
        &asm.fixed_b,
        &c_refs,
        &asm.ff_specs,
        &legs,
        asm.w_log_b,
        &asm.native_b,
    );
    assert!(leg_pins.is_empty(), "no 2-perm legs in the link walks");
    let rec_b = ch_b.finish();
    assert_eq!(
        rec_b.ops, asm.rec_b_scratch.ops,
        "walk L-B recording schedule drift"
    );
    assert_eq!(
        rec_b.data_flat, asm.rec_b_scratch.data_flat,
        "walk L-B recording data drift"
    );
    assert_eq!(
        rec_b.post_state, asm.rec_b_scratch.post_state,
        "walk L-B recording post-state drift"
    );
    crate::acceptance::row_ledger_mark(b, &mut ledger, "r-pcs: walk L-B twin (recorded)");

    // ---- Walk L-A discharge (inline transcript — a walk cannot host its
    // own transcript; L-A is the one inline replay the link pays for).
    let mut ch_a = FsChannelTrace::new(b, DOMAIN_LA);
    let mut claims = discharge_duplex_union(b, &mut ch_a, &asm.u_a, &native_a, 0);
    crate::acceptance::row_ledger_mark(b, &mut ledger, "r-pcs: walk L-A twin (inline)");

    // ---- Region-2 recording cell pins: the walk L-B discharge's absorbed
    // proof data pins to the recording block's A-lane cells and its
    // squeezed challenges to the carry cells — walk L-A then proves the
    // whole transcript chain, replacing the deleted inline replay.
    {
        let (rec_layout, off) = &asm.u_a.rec_blocks[0];
        assert_eq!(
            rec_b.challenge_wires.len(),
            rec_layout.challenges.len(),
            "walk L-B recording challenge count"
        );
        assert_eq!(
            rec_b.data_wires.len(),
            rec_layout.n_data,
            "walk L-B recording data count"
        );
        for (kk, &(slot, lane)) in rec_layout.challenges.iter().enumerate() {
            assert_eq!(
                rec_b.challenge_wires[kk].eval(b.values()),
                asm.u_a.rec_challenges[0][kk],
                "walk L-B recording challenge {kk} lockstep"
            );
            let cell = slot_cell(&slices_a[asm.u_a.refs.c[lane]], off + slot);
            pin_eq(b, &rec_b.challenge_wires[kk], &cell);
        }
        for (kk, &(slot, lane)) in duplex_data_positions(rec_layout).iter().enumerate() {
            let cell = slot_cell(&slices_a[asm.u_a.refs.a[lane]], off + slot);
            pin_eq(b, &rec_b.data_wires[kk], &cell);
        }
    }

    for c in claims_b.iter_mut() {
        c.slice += slices_a.len();
    }
    claims.extend(claims_b);

    // ---- Stage-2 cell pins.
    let per_tile = 1usize << asm.u_a.block_log;
    let s = 1usize << asm.s_log;
    let block_b = 1usize << asm.block_log_b;
    let data_positions = duplex_data_positions(&asm.u_a.layout);
    for (pi, obs) in obligations.iter().enumerate() {
        for qi in 0..asm.n_queries {
            let tile_off = (pi * asm.n_queries + qi) * per_tile;
            // Leaf lanes → A-lane cells (tile-flattened sub order == the
            // obligation push order: initial, post, epochs).
            let flat: Vec<&LinExpr> = (0..n_trees)
                .flat_map(|t| obs.leaves[qi * n_trees + t].lanes.iter())
                .collect();
            assert_eq!(
                flat.len(),
                data_positions.len(),
                "leaf lane count vs layout"
            );
            for (wire, &(slot, lane)) in flat.iter().zip(data_positions.iter()) {
                pin_eq(
                    b,
                    wire,
                    &slot_cell(&slices_a[asm.u_a.refs.a[lane]], tile_off + slot),
                );
            }
            for t in 0..n_trees {
                let ob = &obs.paths[qi * n_trees + t];
                assert_eq!(ob.leaf, qi * n_trees + t, "leaf/path pairing");
                let depth = asm.trees[pi][t].depth;
                assert_eq!(ob.dir_bits.len(), depth, "direction bit count");
                // Digest wires: pinned to BOTH the L-A digest cells and
                // the leg's CR(start) cells (the cross-walk entry join).
                let dslot = tile_off + t * s + asm.trees[pi][t].lanes / 2 - 1;
                let leg_slot = qi * block_b + asm.leg_offsets[pi][t];
                for lane in 0..2 {
                    let w = LinExpr::from_wire(b.alloc_f128(asm.digests[pi][qi][t][lane]));
                    pin_eq(b, &w, &slot_cell(&slices_a[asm.u_a.refs.c[lane]], dslot));
                    pin_eq(b, &w, &slot_cell(&slices_b[4 + lane], leg_slot));
                }
                // Direction cells → the transcript-bound position bits.
                for (kk, bit) in ob.dir_bits.iter().enumerate() {
                    pin_eq(b, bit, &slot_cell(&slices_b[8], leg_slot + kk));
                }
                // Recomputed root == the FS-observed root wire.
                let last = leg_slot + depth - 1;
                let d_cell = slot_cell(&slices_b[8], last);
                for lane in 0..2 {
                    let c_cell = slot_cell(&slices_b[lane], last);
                    let cr_cell = slot_cell(&slices_b[4 + lane], last);
                    let sib_cell = slot_cell(&slices_b[6 + lane], last);
                    let mix = mul(b, &d_cell, &cr_cell.add(&sib_cell));
                    pin_eq(b, &c_cell.add(&cr_cell).add(&mix), &ob.root[lane]);
                }
            }
        }
    }

    // ---- Resolve column indices to committed slices.
    let all_slices: Vec<WitnessSlice> = slices_a.into_iter().chain(slices_b).collect();
    claims
        .into_iter()
        .map(|c| RegionPcsClaim {
            slice: all_slices[c.slice],
            point: c.point,
            value: c.value,
            native_point: c.native_point,
            native_value: c.native_value,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acceptance::trace::self_verify::{
        alloc_flat_digest, verify_field_trace_deferred_region,
        verify_field_trace_deferred_region_with_post_commit_context, FieldR1csProofTrace,
        PcsLeafObligation, PcsPathObligation,
    };
    use crate::region_sidecar::{
        link_post_commit_class_digest, verify_link_region_sidecar_post_commit,
        verify_link_region_sidecar_trace_post_commit, LinkRegionProverPlan,
    };
    use noid_ivc_core::challenger::{Challenger, FsLaneChallenger};
    use noid_ivc_core::field_r1cs::synthetic_satisfiable;
    use noid_ivc_core::pcs::LOG_PACKING;
    use noid_ivc_core::proof::FieldShape;
    use noid_ivc_core::public_io::PublicIoSpec;
    use noid_ivc_core::verifier::{
        verify_field_deferred_matrix_with_post_commit_context, verify_field_with_public_io,
        verify_field_with_public_io_and_post_commit_context, VerifyError,
    };
    use noid_ivc_prover::field_prover::{
        prove_field_with_public_io, prove_field_with_public_io_and_post_commit_context,
    };

    fn hash_of_flat_lanes(lanes: [F128; 2]) -> [u8; 32] {
        let mut hash = [0u8; 32];
        for (lane, chunk) in lanes.into_iter().zip(hash.chunks_exact_mut(16)) {
            let value = (lane.lo as u128) | ((lane.hi as u128) << 64);
            chunk.copy_from_slice(&value.to_le_bytes());
        }
        hash
    }

    /// Shape-correct zero-data BaseFold carrier for sidecar-geometry tests.
    /// It is not a cryptographic proof; the recording-free assembly consumes
    /// only its canonical leaves, paths, roots and query positions.
    fn mock_basefold_geometry(
        params: &PcsParams,
        n_queries: usize,
    ) -> (pcs::BaseFoldProof, [F128; 2]) {
        let trees = tree_structure(params);
        let zero_hash = [0u8; 32];
        let mut roots = Vec::with_capacity(trees.len());
        for tree in &trees {
            let leaf = vec![F128::ZERO; tree.lanes];
            let family = FfMerklePathFamily {
                depth: tree.depth,
                n_paths: 1,
            };
            let columns = build_ff_merkle_path_columns(
                &family,
                pcs_node_iv_flat(),
                &[FfMerklePathWitness {
                    entry: native_leaf_digest(&leaf),
                    siblings: vec![[F128::ZERO; 2]; tree.depth],
                    directions: vec![false; tree.depth],
                }],
                family.stride_log(),
            );
            roots.push(columns.roots[0]);
        }
        let query = pcs::basefold::QueryOpening {
            position: 0,
            initial_leaf: vec![F128::ZERO; trees[0].lanes],
            initial_path: vec![zero_hash; trees[0].depth],
            post_row_batch_leaf: vec![F128::ZERO; trees[1].lanes],
            post_row_batch_path: vec![zero_hash; trees[1].depth],
            epoch_leaves: trees[2..]
                .iter()
                .map(|tree| vec![F128::ZERO; tree.lanes])
                .collect(),
            epoch_paths: trees[2..]
                .iter()
                .map(|tree| vec![zero_hash; tree.depth])
                .collect(),
        };
        let proof = pcs::BaseFoldProof {
            round_messages: Vec::new(),
            post_row_batch_commit: pcs::RoundCommitment {
                root: hash_of_flat_lanes(roots[1]),
            },
            round_commitments: roots[2..]
                .iter()
                .copied()
                .map(|root| pcs::RoundCommitment {
                    root: hash_of_flat_lanes(root),
                })
                .collect(),
            final_a: F128::ZERO,
            final_b: F128::ZERO,
            final_codeword: Vec::new(),
            plaintext_tail: Vec::new(),
            pow_nonce: 0,
            queries: vec![query; n_queries],
        };
        (proof, roots[0])
    }

    fn alloc_native_walk_obligations(
        b: &mut FieldR1csBuilder,
        proof: &RPcsProof<'_>,
    ) -> PcsWalkObligations {
        let trees = tree_structure(proof.params);
        let mut obligations = PcsWalkObligations::default();
        for query in &proof.native.queries {
            for (tree_index, tree) in trees.iter().enumerate() {
                let leaf = obligations.leaves.len();
                let lanes = native_leaf_lanes(query, tree_index)
                    .iter()
                    .map(|&value| LinExpr::from_wire(b.alloc_f128(value)))
                    .collect();
                obligations.leaves.push(PcsLeafObligation { lanes });

                let bit_offset = dir_bit_offset(&trees, tree_index, trees[0].depth);
                let dir_bits = (0..tree.depth)
                    .map(|level| {
                        let bit = ((query.position >> (bit_offset + level)) & 1) as u64;
                        LinExpr::from_wire(b.alloc_f128(F128::new(bit, 0)))
                    })
                    .collect();
                let root = native_root(proof, tree_index)
                    .map(|value| LinExpr::from_wire(b.alloc_f128(value)));
                obligations.paths.push(PcsPathObligation {
                    leaf,
                    dir_bits,
                    root,
                });
            }
        }
        obligations
    }

    /// The full [R] PCS walk discharge on TWO proofs of DIFFERENT shapes:
    /// path-free region replays collect the obligations, the two link
    /// walks discharge them, the trace satisfies, the native mirror
    /// agrees claim-for-claim, and one-flip negatives break each binding
    /// class (leaf lane, direction bit, observed root).
    #[test]
    fn r_pcs_region_discharge_two_proofs_and_negatives() {
        let mk = |m: usize, seed: u64| {
            let (inner, z) = synthetic_satisfiable(m, m, seed);
            let spec = PublicIoSpec {
                io_slice: noid_ivc_core::public_io::WitnessSlice {
                    log2_len: 2,
                    index: 4,
                },
                io_len: 4,
                claims: vec![],
            };
            let io: Vec<F128> = (16..20).map(|t| z[t]).collect();
            let params = PcsParams {
                m: m + LOG_PACKING,
                log_inv_rate: 2,
                log_batch_size: 2,
                profile: Default::default(),
            };
            let mut ch = FsLaneChallenger::new(b"r-pcs-region-test");
            let (proof, commitment, _) =
                prove_field_with_public_io(&inner, &z, &params, &spec, &io, &mut ch);
            let digest = inner.statement_digest();
            (
                FieldShape::of(&inner),
                params,
                spec,
                io,
                proof,
                commitment,
                digest,
            )
        };
        let (shape0, params0, spec0, io0, proof0, com0, dig0) = mk(10, 0xA11CE);
        let (shape1, params1, spec1, io1, proof1, com1, dig1) = mk(11, 0xB0B);

        let mut b = FieldR1csBuilder::new();
        let run = |b: &mut FieldR1csBuilder,
                   shape: &FieldShape,
                   params: &PcsParams,
                   spec: &PublicIoSpec,
                   io: &[F128],
                   proof: &noid_ivc_core::proof::FieldR1csProof,
                   com: &noid_ivc_core::pcs::Commitment,
                   dig: &[u8; 32]|
         -> PcsWalkObligations {
            let digest_e = alloc_flat_digest(b, dig);
            let root = alloc_flat_digest(b, &com.root);
            let io_wires: Vec<LinExpr> = io
                .iter()
                .map(|&v| LinExpr::from_wire(b.alloc_f128(v)))
                .collect();
            let proof_e = FieldR1csProofTrace::alloc_shape_mode(b, proof, shape, params, false);
            let mut ch = FsChannelTrace::new(b, b"r-pcs-region-test");
            let mut obs = PcsWalkObligations::default();
            let _ = verify_field_trace_deferred_region(
                b,
                &mut ch,
                shape,
                params,
                &digest_e,
                &root,
                &proof_e,
                spec,
                &io_wires,
                Some(&mut obs),
            );
            obs
        };
        let obs0 = run(
            &mut b, &shape0, &params0, &spec0, &io0, &proof0, &com0, &dig0,
        );
        let obs1 = run(
            &mut b, &shape1, &params1, &spec1, &io1, &proof1, &com1, &dig1,
        );

        let proofs = [
            RPcsProof {
                native: &proof0.pcs_open,
                params: &params0,
                commitment_root: flat_digest_lanes(&com0.root),
            },
            RPcsProof {
                native: &proof1.pcs_open,
                params: &params1,
                commitment_root: flat_digest_lanes(&com1.root),
            },
        ];
        let cols = alloc_r_pcs_columns(&mut b, &proofs);
        // Recording-region cell coordinates (captured before `cols` moves):
        // the hosted walk L-B discharge transcript's first data cell and a
        // carry-chain cell inside the recording block.
        let (rec_layout, rec_off) = {
            let (l, o) = &cols.asm.u_a.rec_blocks[0];
            (l.clone(), *o)
        };
        let rec_data0 = duplex_data_positions(&rec_layout)[0];
        let rec_data_cell = slot_cell(
            &cols.slices_a[cols.asm.u_a.refs.a[rec_data0.1]],
            rec_off + rec_data0.0,
        );
        let rec_chal0 = rec_layout.challenges[0];
        let rec_chal_cell = slot_cell(
            &cols.slices_a[cols.asm.u_a.refs.c[rec_chal0.1]],
            rec_off + rec_chal0.0,
        );
        let claims = discharge_r_pcs_via_region(&mut b, cols, &[&obs0, &obs1]);
        assert!(!claims.is_empty(), "walk opening claims present");
        let rows = b.num_wires();
        eprintln!(
            "[r-pcs-region] two-proof discharge: {rows} wires, {} claims, {} obligations",
            claims.len(),
            obs0.leaves.len() + obs1.leaves.len()
        );

        // Native mirror parity: same claim stream, same (point, value)s.
        let natives = r_pcs_region_native(&proofs);
        assert_eq!(natives.len(), claims.len(), "native mirror claim count");
        for (i, ((npt, nv), c)) in natives.iter().zip(claims.iter()).enumerate() {
            assert_eq!(&c.native_point, npt, "claim {i} native point");
            assert_eq!(c.native_value, *nv, "claim {i} native value");
            for (e, n) in c.point.iter().zip(npt.iter()) {
                assert_eq!(e.eval(b.values()), *n, "claim {i} point wire vs native");
            }
            assert_eq!(
                c.value.eval(b.values()),
                *nv,
                "claim {i} value wire vs native"
            );
        }

        let (r1cs, z) = b.build();
        assert!(
            r1cs.satisfies(&z),
            "honest r-pcs walk discharge unsatisfiable"
        );

        // One-flip negatives on each binding class.
        let wire_of = |e: &LinExpr| -> usize {
            assert_eq!(e.terms.len(), 1, "single-wire expression expected");
            e.terms[0].0 as usize
        };
        let mut flips: Vec<(usize, &str)> = Vec::new();
        flips.push((wire_of(&obs0.leaves[0].lanes[0]), "leaf lane (proof 0)"));
        flips.push((wire_of(&obs1.leaves[3].lanes[1]), "leaf lane (proof 1)"));
        flips.push((wire_of(&obs0.paths[0].dir_bits[0]), "direction bit"));
        flips.push((wire_of(&obs1.paths[1].root[0]), "observed root lane"));
        // Hosted-recording negatives: a data cell and a squeezed-challenge
        // carry cell of the walk L-B discharge recording — each pinned
        // (pin_eq) to the discharge twin's wire, so a flip breaks the
        // binding row. (Unpinned interior carry cells are bound by the
        // column OPENING claim, which only a consumer of the claim tail
        // enforces — the standalone gate cannot flip those.)
        flips.push((wire_of(&rec_data_cell), "recording data cell"));
        flips.push((wire_of(&rec_chal_cell), "recording challenge cell"));
        for (w, what) in flips {
            let mut bad = z.clone();
            bad[w] += F128::ONE;
            assert!(!r1cs.satisfies(&bad), "{what} flip slipped through");
        }
    }

    #[test]
    fn recording_free_link_descriptor_covers_two_rate_half_proofs() {
        let n_queries = noid_ivc_core::pcs::basefold::default_fri_queries(1);
        assert_eq!(n_queries, 204);
        let params = PcsParams {
            m: 24 + LOG_PACKING,
            log_inv_rate: 1,
            log_batch_size: 6,
            profile: Default::default(),
        };
        let geometry =
            RPcsLinkUniversalGeometry::new(&params, std::slice::from_ref(&params), n_queries)
                .expect("rate-1/2 proof groups share a leaf signature");
        let descriptor =
            combined_leaf_descriptor(&geometry).expect("two production rate-1/2 proofs fit V1");
        assert_eq!(2 * n_queries, 408);
        assert_eq!((2 * n_queries).next_power_of_two(), 512);
        assert_eq!(descriptor.tx_tile_log(), 9);
        assert_ne!(
            link_r_pcs_leaf_sidecar_purpose(),
            link_r_pcs_path_sidecar_purpose(),
            "L-A and L-B roles must be domain-separated"
        );
    }

    #[test]
    fn universal_link_geometry_covers_m22_m23_m24_without_vk_branching() {
        let params = |field_m| PcsParams {
            m: field_m + LOG_PACKING,
            log_inv_rate: 2,
            log_batch_size: 5,
            profile: Default::default(),
        };
        let link = params(24);
        // Canonical capacity slots may share a Field shape; they select only
        // role/tile data under one four-position carrier topology.
        let blocks = [params(22), params(23), params(23), params(24)];
        let n_queries = pcs::default_fri_queries(link.log_inv_rate);
        let geometry = RPcsLinkUniversalGeometry::new(&link, &blocks, n_queries)
            .expect("canonical ladder has one leaf signature");
        assert_eq!(geometry.group_count(), 5);
        assert_eq!(geometry.n_queries(), n_queries);
        assert_eq!(geometry.subchannel_count(), 4);
        assert_eq!(geometry.path_carrier_depths().unwrap(), [21, 17, 13, 9]);
        assert_eq!(geometry.path_block_log().unwrap(), 7);

        let descriptor = combined_leaf_descriptor(&geometry).unwrap();
        assert_eq!(descriptor.subchannels().len(), 4);
        assert_eq!(
            descriptor.tx_tile_log(),
            (2 * n_queries).next_power_of_two().trailing_zeros() as usize
        );
        let common_s = descriptor
            .subchannels()
            .iter()
            .map(|subchannel| compile_duplex(subchannel.schedule()).slots.len())
            .max()
            .unwrap()
            .next_power_of_two();
        let common_block = descriptor.subchannels().len().next_power_of_two() * common_s;
        assert_eq!(common_block, 64);
        assert_eq!(
            descriptor.tx_tile_log() + common_block.trailing_zeros() as usize,
            14,
            "production role/tile L-A geometry"
        );

        let wrong_rate = params(22);
        let mut wrong_rate = wrong_rate;
        wrong_rate.log_inv_rate = 1;
        assert!(
            matches!(
                RPcsLinkUniversalGeometry::new(&link, &[wrong_rate], n_queries),
                Err(RegionSidecarError::UnsupportedVkShape)
            ),
            "query-count drift must fail before column allocation"
        );
    }

    #[test]
    fn terminal_link_vk_reconstruction_has_exact_small_fixed_table_footprint() {
        let params = |field_m| PcsParams {
            m: field_m + LOG_PACKING,
            log_inv_rate: 2,
            log_batch_size: 5,
            profile: Default::default(),
        };
        let link = params(24);
        let blocks = [params(22), params(23), params(23), params(24)];
        let leaf_slices = std::array::from_fn(|column| WitnessSlice {
            log2_len: 14,
            index: 10 + column,
        });
        let path_slices = std::array::from_fn(|column| WitnessSlice {
            log2_len: 15,
            index: 20 + column,
        });
        let vk =
            canonical_selected_link_region_sidecar_vk(&link, &blocks, leaf_slices, path_slices)
                .expect("canonical terminal Link VK");

        assert_eq!(vk.leaf_a().descriptor().subchannels().len(), 4);
        assert_eq!(vk.leaf_a().descriptor().tx_tile_log(), 8);
        assert_eq!(vk.leaf_a().block_log(), 6);
        assert_eq!(vk.leaf_a().w_log(), 14);
        assert_eq!(
            vk.leaf_a()
                .fixed()
                .iter()
                .map(|pattern| pattern.table.len())
                .sum::<usize>(),
            448
        );
        assert_eq!(vk.path_b().families().len(), 4);
        assert_eq!(vk.path_b().block_log(), 7);
        assert_eq!(vk.path_b().w_log(), 15);
        assert_eq!(
            vk.path_b()
                .fixed()
                .iter()
                .map(|pattern| pattern.table.len())
                .sum::<usize>(),
            3_072
        );
    }

    #[test]
    fn production_role_tile_walk_column_ledger_is_425984() {
        let params = |field_m| PcsParams {
            m: field_m + LOG_PACKING,
            log_inv_rate: 2,
            log_batch_size: 5,
            profile: Default::default(),
        };
        let link_params = params(24);
        let block_params = [params(22), params(23), params(23), params(24)];
        let n_queries = pcs::default_fri_queries(link_params.log_inv_rate);
        let geometry =
            RPcsLinkUniversalGeometry::new(&link_params, &block_params, n_queries).unwrap();
        let (link_proof, link_root) = mock_basefold_geometry(&link_params, n_queries);
        let (block_proof, block_root) = mock_basefold_geometry(&block_params[0], n_queries);
        let proofs = [
            RPcsProof {
                native: &link_proof,
                params: &link_params,
                commitment_root: link_root,
            },
            RPcsProof {
                native: &block_proof,
                params: &block_params[0],
                commitment_root: block_root,
            },
        ];

        let mut builder = FieldR1csBuilder::new();
        let columns =
            prepare_r_pcs_link_columns_universal(&mut builder, &proofs, &geometry, &[0, 1])
                .unwrap();
        assert_eq!(columns.asm.u_a.block_log, 6);
        assert_eq!(columns.asm.u_a.w_log, 14);
        assert_eq!(columns.asm.block_log_b, 7);
        assert_eq!(columns.asm.w_log_b, 15);
        assert_eq!(columns.asm.leg_offsets, [0, 32, 64, 80]);
        assert_eq!(
            columns.asm.path_families,
            [(0, 21), (32, 17), (64, 13), (80, 9),].map(|(offset, depth)| {
                MerkleRegionFamily::FeedForward {
                    offset,
                    depth,
                    n_paths: 1,
                    iv: pcs_node_iv_flat(),
                }
            })
        );
        // Includes wire zero and the canonical dyadic slice-alignment rows:
        // align→2^14, 6·2^14 L-A, align→2^15, 9·2^15 L-B.
        assert_eq!(builder.num_wires(), 425_984);
    }

    #[test]
    fn universal_link_geometry_rejects_malformed_params_without_panicking() {
        let valid = PcsParams {
            m: 24 + LOG_PACKING,
            log_inv_rate: 1,
            log_batch_size: 5,
            profile: Default::default(),
        };
        let n_queries = pcs::default_fri_queries(1);
        let malformed = [
            PcsParams {
                m: LOG_PACKING - 1,
                log_inv_rate: 1,
                log_batch_size: 0,
                profile: Default::default(),
            },
            PcsParams {
                m: LOG_PACKING + 2,
                log_inv_rate: 1,
                log_batch_size: 3,
                profile: Default::default(),
            },
            PcsParams {
                m: LOG_PACKING + usize::BITS as usize,
                log_inv_rate: 1,
                log_batch_size: 0,
                profile: Default::default(),
            },
            PcsParams {
                m: LOG_PACKING + 5,
                log_inv_rate: 1,
                log_batch_size: 5,
                profile: Default::default(),
            },
            PcsParams {
                m: LOG_PACKING + 21,
                log_inv_rate: 1,
                log_batch_size: 20,
                profile: Default::default(),
            },
        ];

        for params in &malformed {
            let outcome = std::panic::catch_unwind(|| {
                RPcsLinkUniversalGeometry::new(params, std::slice::from_ref(&valid), n_queries)
            });
            assert!(
                outcome.is_ok(),
                "malformed PCS params reached a shape panic"
            );
            assert!(
                outcome.unwrap().is_err(),
                "malformed PCS params produced a universal geometry"
            );
        }

        let outcome = std::panic::catch_unwind(|| {
            RPcsLinkUniversalGeometry::new(&valid, std::slice::from_ref(&malformed[0]), n_queries)
        });
        assert!(
            outcome.is_ok(),
            "malformed block group reached a shape panic"
        );
        assert!(outcome.unwrap().is_err());
    }

    #[test]
    fn universal_link_vk_is_identical_for_b8_and_b255_active_groups() {
        let params = |field_m| PcsParams {
            m: field_m + LOG_PACKING,
            log_inv_rate: 2,
            log_batch_size: 5,
            profile: Default::default(),
        };
        let link_params = params(24);
        let block_params = [params(22), params(23), params(23), params(24)];
        // One query keeps this all-tier semantic gate lightweight.  The
        // production row snapshot below locks the derived query axis.
        let geometry = RPcsLinkUniversalGeometry {
            group_params: std::iter::once(link_params.clone())
                .chain(block_params.iter().cloned())
                .collect(),
            groups: std::iter::once(tree_structure(&link_params))
                .chain(block_params.iter().map(tree_structure))
                .collect(),
            n_queries: 1,
        };
        let (link_proof, link_root) = mock_basefold_geometry(&link_params, 1);
        let (b8_proof, b8_root) = mock_basefold_geometry(&block_params[0], 1);
        let (b32_proof, b32_root) = mock_basefold_geometry(&block_params[1], 1);
        let (b64_proof, b64_root) = mock_basefold_geometry(&block_params[2], 1);
        let (b255_proof, b255_root) = mock_basefold_geometry(&block_params[3], 1);

        let build_vk = |block_proof: &pcs::BaseFoldProof,
                        block_params: &PcsParams,
                        block_root,
                        active_block_group| {
            let proofs = [
                RPcsProof {
                    native: &link_proof,
                    params: &link_params,
                    commitment_root: link_root,
                },
                RPcsProof {
                    native: block_proof,
                    params: block_params,
                    commitment_root: block_root,
                },
            ];
            let mut builder = FieldR1csBuilder::new();
            let columns = prepare_r_pcs_link_columns_universal(
                &mut builder,
                &proofs,
                &geometry,
                &[0, active_block_group],
            )
            .expect("universal recording-free columns");
            assert_eq!(columns.asm.path_families.len(), 4);
            assert_eq!(columns.asm.block_log_b, 7);
            assert_eq!(columns.asm.u_a.block_log, 6);
            assert!(matches!(
                columns.asm.path_families[0],
                MerkleRegionFamily::FeedForward { depth, .. }
                    if depth == 21
            ));
            let block_leg =
                (columns.asm.n_queries << columns.asm.block_log_b) + columns.asm.leg_offsets[0];
            let block_root_cell = block_leg + columns.asm.trees[1][0].depth;
            let entry_cr_wire = columns.slices_b[4].start() + block_leg;
            let root_cr_wire = columns.slices_b[4].start() + block_root_cell;
            let vk = columns.vk.clone();
            let obs_link = alloc_native_walk_obligations(&mut builder, &proofs[0]);
            let obs_block = alloc_native_walk_obligations(&mut builder, &proofs[1]);
            let root_wire = {
                let root = &obs_block.paths[0].root[0];
                assert_eq!(root.terms.len(), 1, "root is one allocated wire");
                root.terms[0].0 as usize
            };
            let preparation =
                finalize_r_pcs_link_region(&mut builder, columns, &[&obs_link, &obs_block])
                    .expect("universal semantic pins");
            assert_eq!(preparation.vk(), &vk);
            let (r1cs, witness) = builder.build();
            assert!(r1cs.satisfies(&witness), "active real-depth root pin");
            let mut bad = witness;
            bad[root_wire] += F128::ONE;
            assert!(
                !r1cs.satisfies(&bad),
                "active root mutation escaped its real-depth L-B cell pin"
            );
            for (wire, role) in [
                (entry_cr_wire, "L-A digest to L-B CR(start)"),
                (root_cr_wire, "proven CR(actual_depth) root"),
            ] {
                let mut bad = bad.clone();
                // Undo the preceding root-wire mutation, then flip precisely
                // one committed carrier cell.
                bad[root_wire] += F128::ONE;
                bad[wire] += F128::ONE;
                assert!(!r1cs.satisfies(&bad), "{role} pin missing");
            }
            vk
        };

        let b8_vk = build_vk(&b8_proof, &block_params[0], b8_root, 1);
        let b32_vk = build_vk(&b32_proof, &block_params[1], b32_root, 2);
        let b64_vk = build_vk(&b64_proof, &block_params[2], b64_root, 3);
        let b255_vk = build_vk(&b255_proof, &block_params[3], b255_root, 4);
        assert_eq!(b8_vk, b32_vk, "B32 selected a different VK topology");
        assert_eq!(b8_vk, b64_vk, "B64 selected a different VK topology");
        assert_eq!(b8_vk, b255_vk, "B255 selected a different VK topology");
        assert_eq!(b8_vk.leaf_a().descriptor().subchannels().len(), 4);
        assert_eq!(b8_vk.path_b().families().len(), 4);
        assert_eq!(b8_vk.leaf_a().w_log(), 7);
        assert_eq!(b8_vk.path_b().w_log(), 8);
    }

    #[test]
    fn universal_link_active_groups_reject_swapped_or_nonzero_link_role() {
        let params = |field_m| PcsParams {
            m: field_m + LOG_PACKING,
            log_inv_rate: 2,
            log_batch_size: 5,
            profile: Default::default(),
        };
        let link_params = params(24);
        let block_params = [params(22), params(23), params(23), params(24)];
        let geometry = RPcsLinkUniversalGeometry {
            group_params: std::iter::once(link_params.clone())
                .chain(block_params.iter().cloned())
                .collect(),
            groups: std::iter::once(tree_structure(&link_params))
                .chain(block_params.iter().map(tree_structure))
                .collect(),
            n_queries: 1,
        };
        let (link_proof, link_root) = mock_basefold_geometry(&link_params, 1);
        let (b8_proof, b8_root) = mock_basefold_geometry(&block_params[0], 1);
        let (b255_proof, b255_root) = mock_basefold_geometry(&block_params[3], 1);

        let rejected = |block_proof: &pcs::BaseFoldProof,
                        block_params: &PcsParams,
                        block_root,
                        active_groups: [usize; 2]| {
            let proofs = [
                RPcsProof {
                    native: &link_proof,
                    params: &link_params,
                    commitment_root: link_root,
                },
                RPcsProof {
                    native: block_proof,
                    params: block_params,
                    commitment_root: block_root,
                },
            ];
            let mut builder = FieldR1csBuilder::new();
            assert!(matches!(
                prepare_r_pcs_link_columns_universal(
                    &mut builder,
                    &proofs,
                    &geometry,
                    &active_groups,
                ),
                Err(RegionSidecarError::UnsupportedVkShape)
            ));
        };

        // Link and B255 share an exact tree shape, so shape equality used to
        // permit a full role swap.  The positional protocol rule must reject it.
        rejected(&b255_proof, &block_params[3], b255_root, [4, 0]);
        // This mapping is also shape-correct at both positions, but group 4 is
        // never a valid previous-link role; B32/B64 remain selectable as the
        // SECOND role through their explicit groups 2 and 3 in the VK test.
        rejected(&b8_proof, &block_params[0], b8_root, [4, 1]);

        // The BaseFold tree topology does not depend on the Ligerito profile,
        // while the full PCS statement encoding does.  Registry selection
        // must therefore reject this shape-identical parameter substitution.
        let mut statement_substitution = block_params[0].clone();
        statement_substitution.profile = noid_ivc_core::pcs::ligerito::LigeritoProfile::Secure;
        rejected(&b8_proof, &statement_substitution, b8_root, [0, 1]);
    }

    #[test]
    fn recording_free_link_sidecar_field_typestate_e2e_and_negatives() {
        let make_inner = |m: usize, seed: u64| {
            let (inner, z) = synthetic_satisfiable(m, m, seed);
            let spec = PublicIoSpec {
                io_slice: WitnessSlice {
                    log2_len: 2,
                    index: 4,
                },
                io_len: 4,
                claims: Vec::new(),
            };
            let io = z[16..20].to_vec();
            let params = PcsParams {
                m: m + LOG_PACKING,
                log_inv_rate: 2,
                log_batch_size: 2,
                profile: Default::default(),
            };
            let mut challenger = FsLaneChallenger::new(b"r-pcs-link-sidecar-inner-v1");
            let (mut proof, commitment, _) =
                prove_field_with_public_io(&inner, &z, &params, &spec, &io, &mut challenger);
            // The production geometry is locked separately above. Two real
            // authenticated openings keep this outer sidecar E2E lightweight.
            proof.pcs_open.queries.truncate(2);
            (params, proof, commitment)
        };
        let (params0, proof0, commitment0) = make_inner(10, 0xA11CE5);
        let (params1, proof1, commitment1) = make_inner(11, 0xB0B5EED);
        let proofs = [
            RPcsProof {
                native: &proof0.pcs_open,
                params: &params0,
                commitment_root: flat_digest_lanes(&commitment0.root),
            },
            RPcsProof {
                native: &proof1.pcs_open,
                params: &params1,
                commitment_root: flat_digest_lanes(&commitment1.root),
            },
        ];

        let mut builder = FieldR1csBuilder::new();
        let columns = prepare_r_pcs_link_columns(&mut builder, &proofs).unwrap();
        assert!(columns.asm.u_a.rec_blocks.is_empty());
        assert!(columns.asm.u_a.rec_refs.is_empty());
        assert!(columns.asm.u_a.rec_challenges.is_empty());
        assert_eq!(columns.asm.u_a.fixed.len(), 7);
        assert_eq!(
            columns.vk.leaf_a().purpose(),
            &link_r_pcs_leaf_sidecar_purpose()
        );
        assert_eq!(
            columns.vk.path_b().purpose(),
            &link_r_pcs_path_sidecar_purpose()
        );
        let carrier_depths = RPcsLinkUniversalGeometry::exact_for(&proofs)
            .unwrap()
            .path_carrier_depths()
            .unwrap();
        assert_eq!(
            columns.vk.path_b().families().len(),
            columns.asm.trees.iter().map(Vec::len).max().unwrap()
        );
        let d_column_wire = columns.slices_b[8].start();
        let mut expected_offset = 0usize;
        for (actual, &depth) in columns.vk.path_b().families().iter().zip(&carrier_depths) {
            assert_eq!(
                *actual,
                MerkleRegionFamily::FeedForward {
                    offset: expected_offset,
                    depth,
                    n_paths: 1,
                    iv: pcs_node_iv_flat(),
                }
            );
            expected_offset += depth.next_power_of_two();
        }

        let obligations0 = alloc_native_walk_obligations(&mut builder, &proofs[0]);
        let obligations1 = alloc_native_walk_obligations(&mut builder, &proofs[1]);
        let lane_wire = obligations0.leaves[0].lanes[0].terms[0].0 as usize;
        let direction_wire = obligations0.paths[0].dir_bits[0].terms[0].0 as usize;
        let root_wire = obligations1.paths[1].root[0].terms[0].0 as usize;
        let preparation =
            finalize_r_pcs_link_region(&mut builder, columns, &[&obligations0, &obligations1])
                .unwrap();
        let (r1cs, witness) = builder.build();
        assert!(r1cs.satisfies(&witness));
        for (wire, role) in [
            (lane_wire, "leaf lane"),
            (direction_wire, "direction"),
            (root_wire, "observed root"),
        ] {
            let mut bad = witness.clone();
            bad[wire] += F128::ONE;
            assert!(!r1cs.satisfies(&bad), "{role} semantic pin missing");
        }
        let mut non_boolean_d = witness.clone();
        non_boolean_d[d_column_wire] = F128::new(2, 0);
        assert!(
            !r1cs.satisfies(&non_boolean_d),
            "Walk L-B D slice lost its unconditional boolean rows"
        );

        let spec = PublicIoSpec {
            io_slice: WitnessSlice {
                log2_len: 0,
                index: 0,
            },
            io_len: 1,
            claims: Vec::new(),
        };
        let io = [witness[0]];
        let outer_params = PcsParams {
            m: r1cs.m + LOG_PACKING,
            log_inv_rate: 2,
            log_batch_size: 2,
            profile: Default::default(),
        };
        let class_digest = link_post_commit_class_digest(
            &r1cs.statement_digest(),
            &spec,
            &outer_params,
            preparation.vk(),
        );
        let plan = LinkRegionProverPlan::new(preparation.vk(), preparation.prover_input()).unwrap();
        let mut prover = FsLaneChallenger::new(b"r-pcs-link-sidecar-outer-v1");
        let (field_proof, sidecar, commitment, _) =
            prove_field_with_public_io_and_post_commit_context(
                &r1cs,
                &witness,
                &outer_params,
                &spec,
                &io,
                &class_digest,
                &mut prover,
                |context| plan.prove_post_commit(context).unwrap(),
            );
        let encoded = bincode::serialize(&sidecar).unwrap();
        assert_eq!(encoded.len(), sidecar.byte_len());
        let decoded = bincode::deserialize(&encoded).unwrap();
        assert_eq!(decoded, sidecar);

        let verify =
            |candidate_vk: &LinkRegionSidecarVk,
             candidate_class: &[u8; 32],
             candidate_proof: &crate::region_sidecar::LinkRegionSidecarProof| {
                let mut verifier = FsLaneChallenger::new(b"r-pcs-link-sidecar-outer-v1");
                verify_field_with_public_io_and_post_commit_context(
                    &r1cs,
                    &commitment,
                    &field_proof,
                    &spec,
                    &io,
                    candidate_class,
                    candidate_proof,
                    &mut verifier,
                    |proof, context| {
                        verify_link_region_sidecar_post_commit(candidate_vk, proof, context)
                            .map_err(|_| VerifyError::Auxiliary)
                    },
                )
            };
        assert!(verify(preparation.vk(), &class_digest, &decoded).is_ok());
        for (candidate, message) in [
            (
                decoded.with_multi_walk_message_mutated(preparation.vk(), r1cs.m),
                "shared ragged walk",
            ),
            (
                decoded.with_leaf_prefix_message_mutated(preparation.vk(), r1cs.m),
                "deferred L-A prefix",
            ),
            (
                decoded.with_path_prefix_message_mutated(preparation.vk(), r1cs.m),
                "deferred L-B prefix",
            ),
        ] {
            assert!(
                verify(preparation.vk(), &class_digest, &candidate).is_err(),
                "Link V2 accepted a mutated {message} message"
            );
        }

        // Full recursive verifier lockstep: the outer Field transcript binds
        // the Link class, then replays mandatory L-A and L-B sidecars on the
        // same trace context before zerocheck/lincheck/PCS.
        let shape = FieldShape::of(&r1cs);
        let statement_digest = r1cs.statement_digest();
        let mut native_recursive = FsLaneChallenger::new(b"r-pcs-link-sidecar-outer-v1");
        let (_, native_fresh) = verify_field_deferred_matrix_with_post_commit_context(
            &shape,
            &statement_digest,
            &commitment,
            &field_proof,
            &spec,
            &io,
            &class_digest,
            &decoded,
            &mut native_recursive,
            |proof, context| {
                verify_link_region_sidecar_post_commit(preparation.vk(), proof, context)
                    .map_err(|_| VerifyError::Auxiliary)
            },
        )
        .unwrap();
        let native_post = native_recursive.sample_f128();

        let mut recursive_builder = FieldR1csBuilder::new();
        let mut recursive_channel =
            FsChannelTrace::new(&mut recursive_builder, b"r-pcs-link-sidecar-outer-v1");
        let digest_expr = alloc_flat_digest(&mut recursive_builder, &statement_digest);
        let root_expr = alloc_flat_digest(&mut recursive_builder, &commitment.root);
        let io_expr = io
            .iter()
            .map(|&value| LinExpr::from_wire(recursive_builder.alloc_f128(value)))
            .collect::<Vec<_>>();
        let proof_expr = FieldR1csProofTrace::alloc_shape(
            &mut recursive_builder,
            &field_proof,
            &shape,
            &outer_params,
        );
        let (_, trace_fresh) = verify_field_trace_deferred_region_with_post_commit_context(
            &mut recursive_builder,
            &mut recursive_channel,
            &shape,
            &outer_params,
            &digest_expr,
            &root_expr,
            &proof_expr,
            &spec,
            &io_expr,
            &class_digest,
            None,
            |builder, context| {
                verify_link_region_sidecar_trace_post_commit(
                    builder,
                    context,
                    preparation.vk(),
                    &decoded,
                )
                .unwrap();
            },
        );
        let trace_post = recursive_channel
            .sample_f128(&mut recursive_builder)
            .eval(recursive_builder.values());
        assert_eq!(
            trace_fresh.value.eval(recursive_builder.values()),
            native_fresh.value
        );
        assert_eq!(trace_post, native_post);
        let (recursive_r1cs, recursive_witness) = recursive_builder.build();
        assert!(
            recursive_r1cs.satisfies(&recursive_witness),
            "recursive Link sidecar context is unsatisfied"
        );

        let mut core_only = FsLaneChallenger::new(b"r-pcs-link-sidecar-outer-v1");
        assert!(verify_field_with_public_io(
            &r1cs,
            &commitment,
            &field_proof,
            &spec,
            &io,
            &mut core_only,
        )
        .is_err());

        let mut wrong_class = class_digest;
        wrong_class[0] ^= 1;
        assert!(verify(preparation.vk(), &wrong_class, &decoded).is_err());

        let mut version_bytes = encoded.clone();
        version_bytes[0] = 0;
        let bad_version = bincode::deserialize(&version_bytes).unwrap();
        assert!(verify(preparation.vk(), &class_digest, &bad_version).is_err());

        let honest_leaf = preparation.vk().leaf_a();
        let wrong_leaf = CombinedDuplexRegionVk::new(
            [0xD5; 32],
            honest_leaf.descriptor().clone(),
            *honest_leaf.slices(),
        )
        .unwrap();
        assert_eq!(
            LinkRegionSidecarVk::new(wrong_leaf, preparation.vk().path_b().clone()),
            Err(RegionSidecarError::UnsupportedVkShape)
        );
    }
}
