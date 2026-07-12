// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

#![allow(dead_code)]

//! Raw selected authorization-region reconstruction for the canonical ladder.
//!
//! This module reconstructs the four authorization children changed by the ZK
//! capsule: Owner/Main duplex, Wallet-A capsule leaves and Wallet-B FF paths.
//! Its only proof input is the opaque policy-verified batch owned by the
//! selected Block assembly. It accepts no independent statements, applies no
//! second proof-reuse policy, and reuses the batch's one ghost entry by
//! reference for every dead/PAD slot.
//!
//! The result is deliberately pre-allocation data: raw columns, native walk
//! endpoints and duplex layouts only. It cannot allocate a `WitnessSlice`,
//! construct a region VK, mint a preparation, or switch production LinkBlock.
//! A future common allocator must join it with canonical Meta data while the
//! same private selected assembly still owns the Block builder.

use std::collections::BTreeMap;

use noid_core::Block128;
#[cfg(test)]
use noid_fri::hasher::CryptographicHasher;
use noid_fri_binius::capsule::{capsule_leaf_hash, CapsuleNodeHasher};
use noid_fri_binius::compact_fri::{
    expand_batched_merkle_proof_to_cap, BatchedMerkleProof, IndependentMerklePath,
};
use noid_fri_binius::interleaved_commit::{SourceBatchedMerkleProof, SourceHash};
use noid_fri_binius::zk_capsule_algebra::{
    map_source_query_leaf, ZkCapsuleAlgebraError, JOINT_SOURCE_LEAF_SYMBOLS, MID_STANDARD_FOLDS,
};
use noid_fri_binius::zk_capsule_pcs::{
    ZK_CAPSULE_PCS_MID_CAP_DEPTH, ZK_CAPSULE_PCS_MID_LEAF_HASH_LOG, ZK_CAPSULE_PCS_MID_PATH_DEPTH,
    ZK_CAPSULE_PCS_MID_TREE_DEPTH, ZK_CAPSULE_PCS_QUERY_COUNT, ZK_CAPSULE_PCS_SOURCE_CAP_DEPTH,
    ZK_CAPSULE_PCS_SOURCE_LEAF_HASH_LOG, ZK_CAPSULE_PCS_SOURCE_PATH_DEPTH,
    ZK_CAPSULE_PCS_SOURCE_TREE_DEPTH,
};
use noid_gkr::zk_authorization::{
    zk_auth_capsule_owner_dynamic_data, zk_authorization_main_dynamic_data, ZkAuthorizationError,
    ZK_AUTH_MAIN_TILE_LOG, ZK_AUTH_OWNER_TILE_LOG,
};
#[cfg(test)]
use noid_ivc_core::deep_chain::capsule_leaf::CAPSULE_LEAF_DIGEST_SLOT;
use noid_ivc_core::deep_chain::capsule_leaf::{
    build_capsule_leaf_columns, raw_flat_lane, CapsuleLeafData, CAPSULE_LEAF_STRIDE,
};
use noid_ivc_core::deep_chain::ff_merkle::{
    build_ff_merkle_path_columns, FfMerklePathFamily, FfMerklePathWitness,
};
use noid_ivc_core::deep_chain::schedule::flat_of_tower_u128;
use noid_ivc_core::field::F128;
use noid_poseidon2b::native::domain::{capacity_iv, capacity_iv_flat, TAG_CAPSNODE, TAG_KSCHANNL};

use super::region_source_binding::place_ff;
use super::region_source_binding::{build_duplex_union, DuplexUnion};
use super::zk_authorization_candidate::SelectedZkAuthorizationProofBatch;
use crate::acceptance::zk_auth_capsule_schedule::ZkAuthCapsuleDuplexSchedules;

const WALLET_A_TILE_LOG: usize = 11;
const WALLET_B_TILE_LOG: usize = 10;
const WALLET_A_FAMILY_SLOTS: usize = ZK_CAPSULE_PCS_QUERY_COUNT * CAPSULE_LEAF_STRIDE;
const WALLET_B_PATH_DEPTH: usize = 8;
const WALLET_B_PATH_STRIDE: usize = 8;
const WALLET_B_FAMILY_SLOTS: usize = ZK_CAPSULE_PCS_QUERY_COUNT * WALLET_B_PATH_STRIDE;
const SELECTED_CHANGED_COMMITTED_COLUMNS: usize = 6 + 6 + 6 + 9;

const _: () = assert!(ZK_CAPSULE_PCS_QUERY_COUNT == 64);
const _: () = assert!(ZK_CAPSULE_PCS_SOURCE_PATH_DEPTH == WALLET_B_PATH_DEPTH);
const _: () = assert!(ZK_CAPSULE_PCS_MID_PATH_DEPTH == WALLET_B_PATH_DEPTH);
const _: () = assert!(2 * WALLET_A_FAMILY_SLOTS == 1 << WALLET_A_TILE_LOG);
const _: () = assert!(2 * WALLET_B_FAMILY_SLOTS == 1 << WALLET_B_TILE_LOG);
const _: () = assert!(SELECTED_CHANGED_COMMITTED_COLUMNS == 27);

#[derive(Debug)]
pub(super) enum SelectedZkAuthorizationRegionError {
    VerifiedProjection {
        index: usize,
        source: ZkAuthorizationError,
    },
    QueryMapping {
        tx: usize,
        query: usize,
        source: ZkCapsuleAlgebraError,
    },
    PathExpansion {
        tx: usize,
        family: &'static str,
        source: String,
    },
    MissingExpandedPath {
        tx: usize,
        family: &'static str,
        leaf: usize,
    },
    LeafDigestMismatch {
        tx: usize,
        family: &'static str,
        query: usize,
    },
    PathRootMismatch {
        tx: usize,
        family: &'static str,
        query: usize,
    },
    TranscriptMismatch {
        tx: usize,
        family: &'static str,
    },
    Geometry(&'static str),
}

pub(super) struct SelectedZkAuthorizationRawWalk<const N: usize> {
    committed: [Vec<F128>; N],
    s0: [Vec<F128>; 4],
    s_out: [Vec<F128>; 4],
}

impl<const N: usize> SelectedZkAuthorizationRawWalk<N> {
    pub(super) fn committed(&self) -> &[Vec<F128>; N] {
        &self.committed
    }

    pub(super) fn s0(&self) -> &[Vec<F128>; 4] {
        &self.s0
    }

    pub(super) fn s_out(&self) -> &[Vec<F128>; 4] {
        &self.s_out
    }

    /// Zero-copy handoff reserved for the future common six-child allocator.
    pub(super) fn into_parts(self) -> ([Vec<F128>; N], [Vec<F128>; 4], [Vec<F128>; 4]) {
        (self.committed, self.s0, self.s_out)
    }
}

/// Exact pre-allocation data for the four selected authorization children.
/// Fields and construction stay inside `acceptance::trace`; no sidecar key or
/// builder handle can be obtained from this value.
pub(super) struct SelectedZkAuthorizationRegionDraft {
    owner: DuplexUnion,
    main: DuplexUnion,
    wallet_a: SelectedZkAuthorizationRawWalk<6>,
    wallet_b: SelectedZkAuthorizationRawWalk<9>,
}

impl SelectedZkAuthorizationRegionDraft {
    pub(super) fn owner(&self) -> &DuplexUnion {
        &self.owner
    }

    pub(super) fn main(&self) -> &DuplexUnion {
        &self.main
    }

    pub(super) fn wallet_a(&self) -> &SelectedZkAuthorizationRawWalk<6> {
        &self.wallet_a
    }

    pub(super) fn wallet_b(&self) -> &SelectedZkAuthorizationRawWalk<9> {
        &self.wallet_b
    }

    pub(super) fn changed_committed_columns(&self) -> usize {
        self.owner.committed.len()
            + self.main.committed.len()
            + self.wallet_a.committed.len()
            + self.wallet_b.committed.len()
    }

    pub(super) fn committed_cells(&self) -> usize {
        self.owner
            .committed
            .iter()
            .chain(self.main.committed.iter())
            .chain(self.wallet_a.committed.iter())
            .chain(self.wallet_b.committed.iter())
            .map(Vec::len)
            .sum()
    }

    /// Zero-copy handoff reserved for the future common authorization+Meta
    /// allocator. Keeping the fields private prevents piecemeal replacement.
    pub(super) fn into_parts(
        self,
    ) -> (
        DuplexUnion,
        DuplexUnion,
        SelectedZkAuthorizationRawWalk<6>,
        SelectedZkAuthorizationRawWalk<9>,
    ) {
        (self.owner, self.main, self.wallet_a, self.wallet_b)
    }
}

/// Reconstruct every selected authorization tile of one canonical class from
/// the sole policy-verified batch. Native proof verification and duplicate
/// policy have already completed before this boundary.
pub(super) fn build_selected_zk_authorization_region_draft(
    batch: &SelectedZkAuthorizationProofBatch,
) -> Result<SelectedZkAuthorizationRegionDraft, SelectedZkAuthorizationRegionError> {
    let geometry = crate::region_sidecar::selected_zk_block_geometry_for_auth_tiles(batch.len())
        .ok_or(SelectedZkAuthorizationRegionError::Geometry(
            "selected authorization batch is not a canonical class",
        ))?;
    let schedules = ZkAuthCapsuleDuplexSchedules::selected();
    let owner_layout = schedules.owner_layout();
    let main_layout = schedules.main_layout();
    let iv = kschannl_iv_flat();

    let mut owner_streams = Vec::with_capacity(geometry.auth_tiles);
    let mut main_streams = Vec::with_capacity(geometry.auth_tiles);
    let mut ghost_streams: Option<(Vec<F128>, Vec<F128>)> = None;
    for tx in 0..batch.len() {
        let entry = batch.entry_for_slot(tx);
        if std::ptr::eq(entry, batch.ghost_entry()) {
            if ghost_streams.is_none() {
                ghost_streams = Some(build_dynamic_streams(tx, entry)?);
            }
            let (owner, main) = ghost_streams
                .as_ref()
                .expect("ghost streams were initialized");
            owner_streams.push(owner.clone());
            main_streams.push(main.clone());
        } else {
            let (owner, main) = build_dynamic_streams(tx, entry)?;
            owner_streams.push(owner);
            main_streams.push(main);
        }
    }

    let owner_union = build_duplex_union(&owner_layout, iv, &owner_streams);
    let main_union = build_duplex_union(&main_layout, iv, &main_streams);
    // The unions own their reconstructed columns; the per-tile absorbed-data
    // streams are no longer needed while the much larger Wallet columns are
    // materialized below.
    drop(owner_streams);
    drop(main_streams);
    drop(ghost_streams);
    if owner_union.w_log != geometry.owner_w_log || owner_union.block_log != ZK_AUTH_OWNER_TILE_LOG
    {
        return Err(SelectedZkAuthorizationRegionError::Geometry(
            "selected Owner union has the wrong canonical class geometry",
        ));
    }
    if main_union.w_log != geometry.main_w_log || main_union.block_log != ZK_AUTH_MAIN_TILE_LOG {
        return Err(SelectedZkAuthorizationRegionError::Geometry(
            "selected Main union has the wrong canonical class geometry",
        ));
    }
    for tx in 0..batch.len() {
        let verified = batch.entry_for_slot(tx).verified();
        let expected_owner = verified.owner.transcript_challenges().map(phi);
        let expected_main = verified.main_transcript_challenges().map(phi);
        if owner_union.challenges[tx] != expected_owner {
            return Err(SelectedZkAuthorizationRegionError::TranscriptMismatch {
                tx,
                family: "Owner",
            });
        }
        if main_union.challenges[tx] != expected_main {
            return Err(SelectedZkAuthorizationRegionError::TranscriptMismatch {
                tx,
                family: "Main",
            });
        }
    }

    let (
        wallet_a_columns,
        wallet_a_s0,
        wallet_a_s_out,
        wallet_b_columns,
        wallet_b_s0,
        wallet_b_s_out,
    ) = build_wallet_columns(batch, geometry.wallet_a_w_log, geometry.wallet_b_w_log)?;

    Ok(SelectedZkAuthorizationRegionDraft {
        owner: owner_union,
        main: main_union,
        wallet_a: SelectedZkAuthorizationRawWalk {
            committed: wallet_a_columns,
            s0: wallet_a_s0,
            s_out: wallet_a_s_out,
        },
        wallet_b: SelectedZkAuthorizationRawWalk {
            committed: wallet_b_columns,
            s0: wallet_b_s0,
            s_out: wallet_b_s_out,
        },
    })
}

fn build_dynamic_streams(
    tx: usize,
    entry: &super::zk_authorization_candidate::SelectedZkAuthorizationVerifiedEntry,
) -> Result<(Vec<F128>, Vec<F128>), SelectedZkAuthorizationRegionError> {
    let proof = entry.proof();
    let source_cap = proof.source_commitment.transcript_lanes().map_err(|_| {
        SelectedZkAuthorizationRegionError::Geometry("verified source cap shape drift")
    })?;
    let owner = zk_auth_capsule_owner_dynamic_data(entry.statement(), &source_cap, &proof.owner)
        .into_iter()
        .map(phi)
        .collect();
    let main = zk_authorization_main_dynamic_data(&entry.verified().owner, proof)
        .map_err(
            |source| SelectedZkAuthorizationRegionError::VerifiedProjection { index: tx, source },
        )?
        .into_iter()
        .map(phi)
        .collect();
    Ok((owner, main))
}

fn kschannl_iv_flat() -> [F128; 2] {
    let [hi, lo] = capacity_iv(TAG_KSCHANNL);
    [flat_of_tower_u128(hi.0), flat_of_tower_u128(lo.0)]
}

fn phi(value: Block128) -> F128 {
    flat_of_tower_u128(value.0)
}

fn raw_digest_lanes(digest: &SourceHash) -> [F128; 2] {
    [
        raw_flat_lane(u128::from_le_bytes(digest[..16].try_into().unwrap())),
        raw_flat_lane(u128::from_le_bytes(digest[16..].try_into().unwrap())),
    ]
}

type WalletColumns = (
    [Vec<F128>; 6],
    [Vec<F128>; 4],
    [Vec<F128>; 4],
    [Vec<F128>; 9],
    [Vec<F128>; 4],
    [Vec<F128>; 4],
);

fn build_wallet_columns(
    batch: &SelectedZkAuthorizationProofBatch,
    wallet_a_w_log: usize,
    wallet_b_w_log: usize,
) -> Result<WalletColumns, SelectedZkAuthorizationRegionError> {
    let expected = crate::region_sidecar::selected_zk_block_geometry_for_auth_tiles(batch.len())
        .ok_or(SelectedZkAuthorizationRegionError::Geometry(
            "wallet assembly requires a canonical authorization class",
        ))?;
    if wallet_a_w_log != expected.wallet_a_w_log || wallet_b_w_log != expected.wallet_b_w_log {
        return Err(SelectedZkAuthorizationRegionError::Geometry(
            "wallet assembly class geometry drift",
        ));
    }
    let mut wallet_a: [Vec<F128>; 6] =
        std::array::from_fn(|_| vec![F128::ZERO; 1 << wallet_a_w_log]);
    let mut wallet_a_s0: [Vec<F128>; 4] =
        std::array::from_fn(|_| vec![F128::ZERO; 1 << wallet_a_w_log]);
    let mut wallet_a_s_out: [Vec<F128>; 4] =
        std::array::from_fn(|_| vec![F128::ZERO; 1 << wallet_a_w_log]);
    let mut wallet_b: [Vec<F128>; 9] =
        std::array::from_fn(|_| vec![F128::ZERO; 1 << wallet_b_w_log]);
    let mut wallet_b_s0: [Vec<F128>; 4] =
        std::array::from_fn(|_| vec![F128::ZERO; 1 << wallet_b_w_log]);
    let mut wallet_b_s_out: [Vec<F128>; 4] =
        std::array::from_fn(|_| vec![F128::ZERO; 1 << wallet_b_w_log]);

    let mut first_ghost_tile = None;
    for tx in 0..batch.len() {
        let entry = batch.entry_for_slot(tx);
        if std::ptr::eq(entry, batch.ghost_entry()) {
            if let Some(source_tx) = first_ghost_tile {
                copy_wallet_tile(
                    source_tx,
                    tx,
                    &mut wallet_a,
                    &mut wallet_a_s0,
                    &mut wallet_a_s_out,
                    &mut wallet_b,
                    &mut wallet_b_s0,
                    &mut wallet_b_s_out,
                );
                continue;
            }
            first_ghost_tile = Some(tx);
        }
        let proof = entry.proof();
        fill_wallet_opening(
            tx,
            &entry.verified().queries,
            &proof.opening.source_joint_symbols,
            &proof.opening.source_batch,
            &proof.source_commitment.cap.hashes,
            &proof.opening.mid_symbols,
            &proof.opening.mid_batch,
            &proof.mid_commitment.cap.hashes,
            &mut wallet_a,
            &mut wallet_a_s0,
            &mut wallet_a_s_out,
            &mut wallet_b,
            &mut wallet_b_s0,
            &mut wallet_b_s_out,
        )?;
    }
    Ok((
        wallet_a,
        wallet_a_s0,
        wallet_a_s_out,
        wallet_b,
        wallet_b_s0,
        wallet_b_s_out,
    ))
}

fn copy_tile<const N: usize>(
    columns: &mut [Vec<F128>; N],
    source_base: usize,
    destination_base: usize,
    tile_slots: usize,
) {
    let source = source_base..source_base + tile_slots;
    for column in columns {
        column.copy_within(source.clone(), destination_base);
    }
}

#[allow(clippy::too_many_arguments)]
fn copy_wallet_tile(
    source_tx: usize,
    destination_tx: usize,
    wallet_a: &mut [Vec<F128>; 6],
    wallet_a_s0: &mut [Vec<F128>; 4],
    wallet_a_s_out: &mut [Vec<F128>; 4],
    wallet_b: &mut [Vec<F128>; 9],
    wallet_b_s0: &mut [Vec<F128>; 4],
    wallet_b_s_out: &mut [Vec<F128>; 4],
) {
    let wallet_a_source = source_tx << WALLET_A_TILE_LOG;
    let wallet_a_destination = destination_tx << WALLET_A_TILE_LOG;
    let wallet_a_slots = 1 << WALLET_A_TILE_LOG;
    copy_tile(
        wallet_a,
        wallet_a_source,
        wallet_a_destination,
        wallet_a_slots,
    );
    copy_tile(
        wallet_a_s0,
        wallet_a_source,
        wallet_a_destination,
        wallet_a_slots,
    );
    copy_tile(
        wallet_a_s_out,
        wallet_a_source,
        wallet_a_destination,
        wallet_a_slots,
    );

    let wallet_b_source = source_tx << WALLET_B_TILE_LOG;
    let wallet_b_destination = destination_tx << WALLET_B_TILE_LOG;
    let wallet_b_slots = 1 << WALLET_B_TILE_LOG;
    copy_tile(
        wallet_b,
        wallet_b_source,
        wallet_b_destination,
        wallet_b_slots,
    );
    copy_tile(
        wallet_b_s0,
        wallet_b_source,
        wallet_b_destination,
        wallet_b_slots,
    );
    copy_tile(
        wallet_b_s_out,
        wallet_b_source,
        wallet_b_destination,
        wallet_b_slots,
    );
}

#[allow(clippy::too_many_arguments)]
fn fill_wallet_opening(
    tx: usize,
    queries: &[usize; ZK_CAPSULE_PCS_QUERY_COUNT],
    source_symbols: &[Block128],
    source_batch: &SourceBatchedMerkleProof,
    source_cap: &[SourceHash],
    mid_symbols: &[Block128],
    mid_batch: &SourceBatchedMerkleProof,
    mid_cap: &[SourceHash],
    wallet_a: &mut [Vec<F128>; 6],
    wallet_a_s0: &mut [Vec<F128>; 4],
    wallet_a_s_out: &mut [Vec<F128>; 4],
    wallet_b: &mut [Vec<F128>; 9],
    wallet_b_s0: &mut [Vec<F128>; 4],
    wallet_b_s_out: &mut [Vec<F128>; 4],
) -> Result<(), SelectedZkAuthorizationRegionError> {
    if source_symbols.len() != ZK_CAPSULE_PCS_QUERY_COUNT * JOINT_SOURCE_LEAF_SYMBOLS
        || mid_symbols.len() != ZK_CAPSULE_PCS_QUERY_COUNT * (1 << MID_STANDARD_FOLDS)
        || source_cap.len() != 1 << ZK_CAPSULE_PCS_SOURCE_CAP_DEPTH
        || mid_cap.len() != 1 << ZK_CAPSULE_PCS_MID_CAP_DEPTH
    {
        return Err(SelectedZkAuthorizationRegionError::Geometry(
            "verified wallet opening shape drift",
        ));
    }

    let mappings = queries
        .iter()
        .enumerate()
        .map(|(query, &index)| {
            map_source_query_leaf(index).map_err(|source| {
                SelectedZkAuthorizationRegionError::QueryMapping { tx, query, source }
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let source_indices = mappings
        .iter()
        .map(|mapping| mapping.source_leaf_index)
        .collect::<Vec<_>>();
    let mid_indices = mappings
        .iter()
        .map(|mapping| mapping.mid_leaf_index)
        .collect::<Vec<_>>();

    let source_hashes = source_indices
        .iter()
        .enumerate()
        .map(|(query, &leaf)| {
            let start = query * JOINT_SOURCE_LEAF_SYMBOLS;
            capsule_leaf_hash(
                ZK_CAPSULE_PCS_SOURCE_LEAF_HASH_LOG,
                leaf,
                &source_symbols[start..start + JOINT_SOURCE_LEAF_SYMBOLS],
            )
        })
        .collect::<Vec<_>>();
    let mid_hashes = mid_indices
        .iter()
        .enumerate()
        .map(|(query, &leaf)| {
            let start = query * (1 << MID_STANDARD_FOLDS);
            capsule_leaf_hash(
                ZK_CAPSULE_PCS_MID_LEAF_HASH_LOG,
                leaf,
                &mid_symbols[start..start + (1 << MID_STANDARD_FOLDS)],
            )
        })
        .collect::<Vec<_>>();

    let source_paths = expand_paths(
        tx,
        "source",
        source_batch,
        ZK_CAPSULE_PCS_SOURCE_TREE_DEPTH,
        ZK_CAPSULE_PCS_SOURCE_CAP_DEPTH,
        &source_indices,
        &source_hashes,
    )?;
    let mid_paths = expand_paths(
        tx,
        "mid",
        mid_batch,
        ZK_CAPSULE_PCS_MID_TREE_DEPTH,
        ZK_CAPSULE_PCS_MID_CAP_DEPTH,
        &mid_indices,
        &mid_hashes,
    )?;

    let wallet_a_base = tx << WALLET_A_TILE_LOG;
    let wallet_b_base = tx << WALLET_B_TILE_LOG;
    let mut family_digests: [Vec<[F128; 2]>; 2] = [Vec::new(), Vec::new()];
    for family in 0..2 {
        let (msg_log, symbols, indices) = if family == 0 {
            (
                ZK_CAPSULE_PCS_SOURCE_LEAF_HASH_LOG,
                source_symbols,
                source_indices.as_slice(),
            )
        } else {
            (
                ZK_CAPSULE_PCS_MID_LEAF_HASH_LOG,
                mid_symbols,
                mid_indices.as_slice(),
            )
        };
        let tiles = (0..ZK_CAPSULE_PCS_QUERY_COUNT)
            .map(|query| {
                let start = query * 16;
                CapsuleLeafData {
                    msg_log,
                    leaf_index: indices[query],
                    syms: std::array::from_fn(|symbol| phi(symbols[start + symbol])),
                }
            })
            .collect::<Vec<_>>();
        let (columns, digests) = build_capsule_leaf_columns(&tiles, 10);
        let base = wallet_a_base + family * WALLET_A_FAMILY_SLOTS;
        for lane in 0..2 {
            wallet_a[lane][base..base + WALLET_A_FAMILY_SLOTS]
                .copy_from_slice(&columns.in_[lane][..WALLET_A_FAMILY_SLOTS]);
        }
        for lane in 0..4 {
            wallet_a[2 + lane][base..base + WALLET_A_FAMILY_SLOTS]
                .copy_from_slice(&columns.c[lane][..WALLET_A_FAMILY_SLOTS]);
            wallet_a_s0[lane][base..base + WALLET_A_FAMILY_SLOTS]
                .copy_from_slice(&columns.s0[lane][..WALLET_A_FAMILY_SLOTS]);
            wallet_a_s_out[lane][base..base + WALLET_A_FAMILY_SLOTS]
                .copy_from_slice(&columns.s_out[lane][..WALLET_A_FAMILY_SLOTS]);
        }
        for query in 0..ZK_CAPSULE_PCS_QUERY_COUNT {
            let native = if family == 0 {
                raw_digest_lanes(&source_hashes[query])
            } else {
                raw_digest_lanes(&mid_hashes[query])
            };
            if digests[query] != native {
                return Err(SelectedZkAuthorizationRegionError::LeafDigestMismatch {
                    tx,
                    family: if family == 0 { "source" } else { "mid" },
                    query,
                });
            }
        }
        family_digests[family] = digests;
    }

    let capsule_iv = capacity_iv_flat(TAG_CAPSNODE).map(raw_flat_lane);
    for family in 0..2 {
        let (indices, paths, cap) = if family == 0 {
            (&source_indices, &source_paths, source_cap)
        } else {
            (&mid_indices, &mid_paths, mid_cap)
        };
        let witnesses = indices
            .iter()
            .enumerate()
            .map(|(query, &leaf)| {
                let path = paths.get(&leaf).ok_or(
                    SelectedZkAuthorizationRegionError::MissingExpandedPath {
                        tx,
                        family: if family == 0 { "source" } else { "mid" },
                        leaf,
                    },
                )?;
                Ok(FfMerklePathWitness {
                    entry: family_digests[family][query],
                    siblings: path.siblings.iter().map(raw_digest_lanes).collect(),
                    directions: path.directions.clone(),
                })
            })
            .collect::<Result<Vec<_>, SelectedZkAuthorizationRegionError>>()?;
        let columns = build_ff_merkle_path_columns(
            &FfMerklePathFamily {
                depth: WALLET_B_PATH_DEPTH,
                n_paths: ZK_CAPSULE_PCS_QUERY_COUNT,
            },
            capsule_iv,
            &witnesses,
            9,
        );
        let base = wallet_b_base + family * WALLET_B_FAMILY_SLOTS;
        place_ff(
            wallet_b,
            wallet_b_s0,
            wallet_b_s_out,
            &columns,
            base,
            WALLET_B_FAMILY_SLOTS,
        );
        for (query, mapping) in mappings.iter().enumerate() {
            let cap_index = if family == 0 {
                mapping.source_cap_index
            } else {
                mapping.mid_cap_index
            };
            if columns.roots[query] != raw_digest_lanes(&cap[cap_index]) {
                return Err(SelectedZkAuthorizationRegionError::PathRootMismatch {
                    tx,
                    family: if family == 0 { "source" } else { "mid" },
                    query,
                });
            }
        }
    }
    Ok(())
}

fn expand_paths(
    tx: usize,
    family: &'static str,
    batch: &SourceBatchedMerkleProof,
    depth: usize,
    cap_depth: usize,
    indices: &[usize],
    hashes: &[SourceHash],
) -> Result<BTreeMap<usize, IndependentMerklePath>, SelectedZkAuthorizationRegionError> {
    let batch = BatchedMerkleProof {
        siblings: batch.siblings.clone(),
    };
    let paths = expand_batched_merkle_proof_to_cap(
        &batch,
        depth,
        cap_depth,
        indices,
        hashes,
        &CapsuleNodeHasher,
    )
    .map_err(|source| SelectedZkAuthorizationRegionError::PathExpansion {
        tx,
        family,
        source,
    })?;
    Ok(paths
        .into_iter()
        .map(|path| (path.leaf_index, path))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(seed: u64) -> SourceHash {
        let mut out = [0u8; 32];
        out[..8].copy_from_slice(&seed.to_le_bytes());
        out[8..16].copy_from_slice(&seed.rotate_left(17).to_le_bytes());
        out[16..24].copy_from_slice(&seed.rotate_left(31).to_le_bytes());
        out[24..].copy_from_slice(&seed.rotate_left(47).to_le_bytes());
        out
    }

    fn cap_for_leftmost_leaf(
        leaf: SourceHash,
        siblings: &[SourceHash],
        width: usize,
    ) -> Vec<SourceHash> {
        let mut node = leaf;
        for sibling in siblings {
            node = CapsuleNodeHasher.compress(&node, sibling);
        }
        let mut cap = (0..width)
            .map(|index| hash(10_000 + index as u64))
            .collect::<Vec<_>>();
        cap[0] = node;
        cap
    }

    #[test]
    fn selected_four_class_authorization_geometry_is_exact() {
        let schedules = ZkAuthCapsuleDuplexSchedules::selected();
        assert_eq!(
            schedules.owner_layout().slots.len().next_power_of_two(),
            1 << 7
        );
        assert_eq!(
            schedules.main_layout().slots.len().next_power_of_two(),
            1 << 8
        );
        for tier in [8usize, 32, 64, 255] {
            let geometry = crate::region_sidecar::selected_zk_block_geometry(tier).unwrap();
            assert_eq!(geometry.auth_tiles << 7, 1 << geometry.owner_w_log);
            assert_eq!(geometry.auth_tiles << 8, 1 << geometry.main_w_log);
            assert_eq!(geometry.auth_tiles << 11, 1 << geometry.wallet_a_w_log);
            assert_eq!(geometry.auth_tiles << 10, 1 << geometry.wallet_b_w_log);
        }
        assert_eq!(SELECTED_CHANGED_COMMITTED_COLUMNS, 27);
    }

    #[test]
    fn raw_reconstructor_has_no_independent_proof_or_allocation_surface() {
        let source = include_str!("zk_authorization_region.rs");
        let production = source
            .split("#[cfg(test)]\nmod tests")
            .next()
            .expect("production raw-region source");
        assert!(!production.contains("verify_zk_authorization("));
        assert!(!production.contains("Vec<ZkAuthorizationProof>"));
        assert!(!production.contains("Vec<ZkAuthCapsuleOwnerStatement>"));
        assert!(!production.contains("use super::FieldR1csBuilder"));
        assert!(!production.contains("-> WitnessSlice"));
        assert!(!production.contains("RegionVk::"));
        assert!(!production.contains("BlockRegionPreparation::"));
        assert!(production.contains("batch.entry_for_slot(tx)"));
    }

    #[test]
    fn deterministic_one_tile_metadata_digests_and_depth8_roots_match() {
        let queries = [0usize; ZK_CAPSULE_PCS_QUERY_COUNT];
        let source_leaf = (0..JOINT_SOURCE_LEAF_SYMBOLS)
            .map(|index| Block128::from(0x5100 + index as u128))
            .collect::<Vec<_>>();
        let mid_leaf = (0..1 << MID_STANDARD_FOLDS)
            .map(|index| Block128::from(0xA100 + index as u128))
            .collect::<Vec<_>>();
        let source_symbols = source_leaf
            .iter()
            .copied()
            .cycle()
            .take(ZK_CAPSULE_PCS_QUERY_COUNT * JOINT_SOURCE_LEAF_SYMBOLS)
            .collect::<Vec<_>>();
        let mid_symbols = mid_leaf
            .iter()
            .copied()
            .cycle()
            .take(ZK_CAPSULE_PCS_QUERY_COUNT * (1 << MID_STANDARD_FOLDS))
            .collect::<Vec<_>>();
        let source_hash = capsule_leaf_hash(ZK_CAPSULE_PCS_SOURCE_LEAF_HASH_LOG, 0, &source_leaf);
        let mid_hash = capsule_leaf_hash(ZK_CAPSULE_PCS_MID_LEAF_HASH_LOG, 0, &mid_leaf);
        let source_siblings = (0..8).map(|level| hash(100 + level)).collect::<Vec<_>>();
        let mid_siblings = (0..8).map(|level| hash(200 + level)).collect::<Vec<_>>();
        let source_cap = cap_for_leftmost_leaf(source_hash, &source_siblings, 32);
        let mid_cap = cap_for_leftmost_leaf(mid_hash, &mid_siblings, 2);

        let mut wallet_a: [Vec<F128>; 6] = std::array::from_fn(|_| vec![F128::ZERO; 1 << 11]);
        let mut wallet_a_s0: [Vec<F128>; 4] = std::array::from_fn(|_| vec![F128::ZERO; 1 << 11]);
        let mut wallet_a_s_out: [Vec<F128>; 4] = std::array::from_fn(|_| vec![F128::ZERO; 1 << 11]);
        let mut wallet_b: [Vec<F128>; 9] = std::array::from_fn(|_| vec![F128::ZERO; 1 << 10]);
        let mut wallet_b_s0: [Vec<F128>; 4] = std::array::from_fn(|_| vec![F128::ZERO; 1 << 10]);
        let mut wallet_b_s_out: [Vec<F128>; 4] = std::array::from_fn(|_| vec![F128::ZERO; 1 << 10]);
        fill_wallet_opening(
            0,
            &queries,
            &source_symbols,
            &SourceBatchedMerkleProof {
                siblings: source_siblings,
            },
            &source_cap,
            &mid_symbols,
            &SourceBatchedMerkleProof {
                siblings: mid_siblings,
            },
            &mid_cap,
            &mut wallet_a,
            &mut wallet_a_s0,
            &mut wallet_a_s_out,
            &mut wallet_b,
            &mut wallet_b_s0,
            &mut wallet_b_s_out,
        )
        .expect("deterministic one-tile selected wallet columns");

        assert_eq!(
            wallet_a[0][0],
            raw_flat_lane(ZK_CAPSULE_PCS_SOURCE_LEAF_HASH_LOG as u128)
        );
        assert_eq!(wallet_a[1][0], F128::ZERO);
        assert_eq!(
            wallet_a[0][WALLET_A_FAMILY_SLOTS],
            raw_flat_lane(ZK_CAPSULE_PCS_MID_LEAF_HASH_LOG as u128)
        );
        assert_eq!(wallet_a[1][WALLET_A_FAMILY_SLOTS], F128::ZERO);
        assert_eq!(
            [
                wallet_a[2][CAPSULE_LEAF_DIGEST_SLOT],
                wallet_a[3][CAPSULE_LEAF_DIGEST_SLOT],
            ],
            raw_digest_lanes(&source_hash)
        );
        assert_eq!(
            [
                wallet_a[2][WALLET_A_FAMILY_SLOTS + CAPSULE_LEAF_DIGEST_SLOT],
                wallet_a[3][WALLET_A_FAMILY_SLOTS + CAPSULE_LEAF_DIGEST_SLOT],
            ],
            raw_digest_lanes(&mid_hash)
        );
        assert_eq!(wallet_b[8][..8], [F128::ZERO; 8]);
    }
}
