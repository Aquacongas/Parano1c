// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! MDBX-backed persistent storage for the chain .
//!
//! `MdbxStore` owns the MDBX `Database` and provides methods for
//! all persistent chain data: headers, undo logs, segments, recent blocks,
//! and chain tip.
//!
//! The core operation is `commit_block`, which writes all block-related data in
//! one atomic MDBX transaction.

use std::path::Path;

use libmdbx::{Database, DatabaseOptions, Mode, NoWriteMap, TableFlags, WriteFlags};
use noid_poseidon2b::primitives::TxBodyHash;
use noid_tx::unpack_amount_creation_id;

use crate::block_header::BlockHeader;
use crate::checkpoint::{CheckpointCoverage, ImmutableCheckpointPackage};
use crate::consensus::da_prune::BlockUndoLog;
use crate::consensus::params::{RECENT_BLOCK_RETENTION_DEPTH, UNDO_RETENTION_DEPTH};
use crate::header_anchor::{
    compute_header_chain_anchor, extend_header_chain_anchor, HeaderChainAnchor,
    HeaderChainAnchorError,
};
use crate::reuse_guard::{GuardBucket, REUSE_GUARD_BUCKETS};
use crate::segmented_state::SegmentColumns;
use crate::storage::meta::ConsensusMeta;
use crate::storage::serial::{
    decode_chain_tip, decode_chain_work, decode_checkpoint_coverage, decode_checkpoint_package,
    decode_consensus_meta, decode_header, decode_header_chain_anchor, decode_reuse_guard_buckets,
    decode_segment, decode_state_meta, decode_tx_index_value, decode_undo_log, encode_chain_tip,
    encode_chain_work, encode_checkpoint_coverage, encode_checkpoint_package,
    encode_consensus_meta, encode_header, encode_header_chain_anchor, encode_reuse_guard_buckets,
    encode_segment, encode_state_meta, encode_tx_index_value, encode_undo_log, u64_from_key,
    u64_key,
};

// ---------------------------------------------------------------------------
// Table names
// ---------------------------------------------------------------------------
const T_HEADERS: &str = "headers";
const T_HEADER_ANCHORS: &str = "header_anchors";
const T_HASH_TO_HEIGHT: &str = "h2h";
const T_CHAIN_TIP: &str = "tip";
const T_CONSENSUS_META: &str = "consensus_meta";
const T_CHAIN_WORK: &str = "chain_work";
const T_UNDO_LOGS: &str = "undo";
const T_SEGMENTS: &str = "segments";
const T_STATE_META: &str = "state_meta";
const T_REUSE_GUARD: &str = "reuse_guard";
const T_RECENT_BLOCKS: &str = "recent";
/// Transaction index for receipt lookup. Key: TxBodyHash (32B). Value: (height, tx_pos) (12B).
const T_TX_INDEX: &str = "tx_index";
/// BlockProofs retained until finalized and covered by a real immutable checkpoint proof.
/// Key: height (u64 LE). Value: bincode BlockProof bytes.
const T_BLOCK_PROOFS: &str = "block_proofs";
/// Public AuthGKR sidecars retained with block bodies until checkpoint coverage.
/// Key: height (u64 LE).
const T_BLOCK_AUTH_SIDECARS: &str = "block_auth_sidecars";
/// Accepted state-transition history claims retained until checkpoint package
/// coverage consumes them. Key: height (u64 LE). Value: raw bincode bytes.
const T_HISTORY_CLAIMS: &str = "history_claims";
/// Accepted-block certificate records produced at block acceptance time.
/// Key: height (u64 LE). Value: raw bincode bytes owned by noid_block/noid_recursive.
const T_ACCEPTED_BLOCK_CERTIFICATES: &str = "accepted_block_certificates";
/// Full accepted-block checkpoint batch packages.
/// Key: end height (u64 LE). Value: raw bincode bytes owned by noid_block/noid_recursive.
const T_ACCEPTED_BLOCK_BATCH_CERTIFICATE_PACKAGES: &str =
    "accepted_block_batch_certificate_packages";
/// Verified recursive checkpoint head records.
/// Key: checkpoint height (u64 LE). Value: raw bincode bytes owned by noid_recursive.
const T_HISTORY_CHECKPOINT_HEADS: &str = "history_checkpoint_heads";
/// Owner UTXO index. Key: owner[32]. Value: packed (slot:u32, value:u64)[] = 12 bytes each.
/// Maintained incrementally in commit_block. Used for O(1) wallet scan.
const T_OWNER_INDEX: &str = "owner_idx";
/// Immutable checkpoint package. Key: checkpoint height (u64 LE).
const T_CHECKPOINT_PACKAGES: &str = "checkpoint_packages";
/// Latest local checkpoint package coverage metadata. Key: KEY_CHECKPOINT_COVERAGE.
const T_CHECKPOINT_COVERAGE: &str = "checkpoint_coverage";
const N_TABLES: u64 = 32;

// Single-entry table keys
const KEY_TIP: &[u8] = &[0u8];
const KEY_META: &[u8] = &[0u8];
const KEY_REUSE_GUARD: &[u8] = &[0u8];
const KEY_CONSENSUS_META: &[u8] = &[0u8];
const KEY_CHECKPOINT_COVERAGE: &[u8] = &[0u8];

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum StoreError {
    Mdbx(libmdbx::Error),
    Decode(&'static str),
    HeaderAnchor(HeaderChainAnchorError),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Mdbx(e) => write!(f, "mdbx: {e}"),
            Self::Decode(ctx) => write!(f, "decode error: {ctx}"),
            Self::HeaderAnchor(e) => write!(f, "header anchor: {e}"),
        }
    }
}

impl std::error::Error for StoreError {}

impl From<libmdbx::Error> for StoreError {
    fn from(e: libmdbx::Error) -> Self {
        Self::Mdbx(e)
    }
}

impl From<HeaderChainAnchorError> for StoreError {
    fn from(e: HeaderChainAnchorError) -> Self {
        Self::HeaderAnchor(e)
    }
}

// ---------------------------------------------------------------------------
// MdbxStore
// ---------------------------------------------------------------------------

pub struct MdbxStore {
    db: Database<NoWriteMap>,
}

// ---------------------------------------------------------------------------
// Owner index helpers
// ---------------------------------------------------------------------------

/// Extract the 32-byte owner key from a slot's owner fields.
#[inline]
fn owner_key_from_fields(owner_hi: noid_core::Block128, owner_lo: noid_core::Block128) -> [u8; 32] {
    let mut key = [0u8; 32];
    key[..16].copy_from_slice(&owner_hi.0.to_le_bytes());
    key[16..].copy_from_slice(&owner_lo.0.to_le_bytes());
    key
}

/// Encode a list of (slot_index, value) pairs for MDBX storage.
#[inline]
fn encode_owner_entries(entries: &[(u32, u64)]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(entries.len() * 12);
    for &(slot, val) in entries {
        buf.extend_from_slice(&slot.to_le_bytes());
        buf.extend_from_slice(&val.to_le_bytes());
    }
    buf
}

/// Decode a packed (slot_index, value) list from MDBX bytes.
#[inline]
fn decode_owner_entries(bytes: &[u8]) -> Vec<(u32, u64)> {
    bytes
        .chunks_exact(12)
        .map(|c| {
            let slot = u32::from_le_bytes(c[..4].try_into().unwrap());
            let val = u64::from_le_bytes(c[4..12].try_into().unwrap());
            (slot, val)
        })
        .collect()
}

#[inline]
fn segment_columns_empty(cols: &SegmentColumns) -> bool {
    cols.values.iter().all(|v| v.0 == 0)
        && cols.owners_hi.iter().all(|v| v.0 == 0)
        && cols.owners_lo.iter().all(|v| v.0 == 0)
}

impl MdbxStore {
    /// Open or create the MDBX database at `path`.
    /// Creates all tables on first run; subsequent opens reuse them.
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        use libmdbx::{ReadWriteOptions, SyncMode};
        // Set explicit MDBX geometry via ReadWriteOptions.
        //
        // Default libmdbx pre-allocates ~256 MB on first open regardless of actual data
        // size. For a node with 160 active UTXOs this wastes disk and inflates VmSize.
        //
        // Sizing rationale:
        //   min_size  = 4 MB  — enough for genesis + a few hundred blocks
        //   max_size  = 16 GB — full state at log_slots=32: ~768 MB segments
        //                        + headers + undo logs + margin
        //   growth_step = 64 MB — incremental growth to avoid excessive resize churn
        let rw = ReadWriteOptions {
            sync_mode: SyncMode::Durable,
            min_size: Some(4 * 1024 * 1024),         //  4 MB
            max_size: Some(16 * 1024 * 1024 * 1024), // 16 GB
            growth_step: Some(64 * 1024 * 1024),     // 64 MB steps
            ..Default::default()
        };
        let db = Database::<NoWriteMap>::open_with_options(
            path,
            DatabaseOptions {
                max_tables: Some(N_TABLES),
                mode: Mode::ReadWrite(rw),
                ..Default::default()
            },
        )?;
        // Ensure all named tables exist — idempotent on re-open.
        let txn = db.begin_rw_txn()?;
        for name in [
            T_HEADERS,
            T_HEADER_ANCHORS,
            T_HASH_TO_HEIGHT,
            T_CHAIN_TIP,
            T_CONSENSUS_META,
            T_CHAIN_WORK,
            T_UNDO_LOGS,
            T_SEGMENTS,
            T_STATE_META,
            T_REUSE_GUARD,
            T_RECENT_BLOCKS,
            T_TX_INDEX,
            T_BLOCK_PROOFS,
            T_BLOCK_AUTH_SIDECARS,
            T_HISTORY_CLAIMS,
            T_ACCEPTED_BLOCK_CERTIFICATES,
            T_ACCEPTED_BLOCK_BATCH_CERTIFICATE_PACKAGES,
            T_HISTORY_CHECKPOINT_HEADS,
            T_OWNER_INDEX,
            T_CHECKPOINT_PACKAGES,
            T_CHECKPOINT_COVERAGE,
        ] {
            txn.create_table(Some(name), TableFlags::empty())?;
        }
        txn.commit()?;
        Ok(Self { db })
    }

    // -----------------------------------------------------------------------
    // Reads
    // -----------------------------------------------------------------------

    pub fn get_chain_tip(&self) -> Result<Option<(u64, [u8; 32])>, StoreError> {
        let txn = self.db.begin_ro_txn()?;
        let tbl = txn.open_table(Some(T_CHAIN_TIP))?;
        let raw: Option<Vec<u8>> = txn.get(&tbl, KEY_TIP)?;
        Ok(raw.and_then(|b| decode_chain_tip(&b)))
    }

    pub fn get_consensus_meta(&self) -> Result<Option<ConsensusMeta>, StoreError> {
        let txn = self.db.begin_ro_txn()?;
        let tbl = txn.open_table(Some(T_CONSENSUS_META))?;
        let raw: Option<Vec<u8>> = txn.get(&tbl, KEY_CONSENSUS_META)?;
        Ok(raw.and_then(|b| decode_consensus_meta(&b)))
    }

    pub fn get_chain_work(&self, height: u64) -> Result<Option<[u8; 32]>, StoreError> {
        let txn = self.db.begin_ro_txn()?;
        let tbl = txn.open_table(Some(T_CHAIN_WORK))?;
        let raw: Option<Vec<u8>> = txn.get(&tbl, &u64_key(height))?;
        Ok(raw.and_then(|b| decode_chain_work(&b)))
    }

    pub fn put_consensus_meta(&self, meta: &ConsensusMeta) -> Result<(), StoreError> {
        let txn = self.db.begin_rw_txn()?;
        let tbl = txn.open_table(Some(T_CONSENSUS_META))?;
        txn.put(
            &tbl,
            KEY_CONSENSUS_META,
            encode_consensus_meta(meta),
            WriteFlags::empty(),
        )?;
        txn.commit()?;
        Ok(())
    }

    pub fn get_state_meta(&self) -> Result<Option<(u32, u64, u64)>, StoreError> {
        let txn = self.db.begin_ro_txn()?;
        let tbl = txn.open_table(Some(T_STATE_META))?;
        let raw: Option<Vec<u8>> = txn.get(&tbl, KEY_META)?;
        Ok(raw.and_then(|b| decode_state_meta(&b)))
    }

    #[cfg(test)]
    pub(crate) fn overwrite_state_meta_for_test(
        &self,
        log_slots: u32,
        active_slot_count: u64,
        alloc_counter: u64,
    ) -> Result<(), StoreError> {
        let txn = self.db.begin_rw_txn()?;
        let tbl = txn.open_table(Some(T_STATE_META))?;
        txn.put(
            &tbl,
            KEY_META,
            encode_state_meta(log_slots, active_slot_count, alloc_counter),
            WriteFlags::empty(),
        )?;
        txn.commit()?;
        Ok(())
    }

    pub fn get_reuse_guard_buckets(
        &self,
    ) -> Result<Option<[GuardBucket; REUSE_GUARD_BUCKETS]>, StoreError> {
        let txn = self.db.begin_ro_txn()?;
        let tbl = txn.open_table(Some(T_REUSE_GUARD))?;
        let raw: Option<Vec<u8>> = txn.get(&tbl, KEY_REUSE_GUARD)?;
        Ok(raw.and_then(|b| decode_reuse_guard_buckets(&b)))
    }

    pub fn get_header(&self, height: u64) -> Result<Option<BlockHeader>, StoreError> {
        let txn = self.db.begin_ro_txn()?;
        let tbl = txn.open_table(Some(T_HEADERS))?;
        let raw: Option<Vec<u8>> = txn.get(&tbl, &u64_key(height))?;
        Ok(raw.and_then(|b| decode_header(&b)))
    }

    pub fn get_header_anchor(&self, height: u64) -> Result<Option<HeaderChainAnchor>, StoreError> {
        let txn = self.db.begin_ro_txn()?;
        let tbl = txn.open_table(Some(T_HEADER_ANCHORS))?;
        let raw: Option<Vec<u8>> = txn.get(&tbl, &u64_key(height))?;
        raw.map(|b| decode_header_chain_anchor(&b).ok_or(StoreError::Decode("header chain anchor")))
            .transpose()
    }

    /// Look up a header by its `H_BLOCK` hash (O(1) via the h2h index).
    pub fn get_header_by_hash(&self, hash: &[u8; 32]) -> Result<Option<BlockHeader>, StoreError> {
        // Scope the first transaction so it is dropped before we open a second.
        let height = {
            let txn = self.db.begin_ro_txn()?;
            let h_tbl = txn.open_table(Some(T_HASH_TO_HEIGHT))?;
            let height_raw: Option<Vec<u8>> = txn.get(&h_tbl, hash.as_slice())?;
            match height_raw.and_then(|b| u64_from_key(&b)) {
                Some(h) => h,
                None => return Ok(None),
            }
            // h_tbl and txn are dropped here
        };
        match self.get_header(height)? {
            Some(header) if crate::consensus::pow::block_id(&header) == *hash => Ok(Some(header)),
            _ => Ok(None),
        }
    }

    /// Persist a historical header and its hash index without changing chain tip,
    /// state metadata, undo logs, or recent blocks.
    ///
    /// Snapshot header sync should use `put_verified_header_only`, which also
    /// records exact cumulative chainwork.
    pub fn put_header_only(&self, header: &BlockHeader, hash: &[u8; 32]) -> Result<(), StoreError> {
        let txn = self.db.begin_rw_txn()?;

        let hdr_tbl = txn.open_table(Some(T_HEADERS))?;
        txn.put(
            &hdr_tbl,
            u64_key(header.height),
            encode_header(header),
            WriteFlags::empty(),
        )?;

        let h2h_tbl = txn.open_table(Some(T_HASH_TO_HEIGHT))?;
        txn.put(
            &h2h_tbl,
            hash.as_slice(),
            u64_key(header.height),
            WriteFlags::empty(),
        )?;

        txn.commit()?;
        Ok(())
    }

    /// Persist a fully validated canonical header plus exact cumulative chainwork
    /// without changing state tip, consensus metadata, undo logs, or block bodies.
    pub fn put_verified_header_only(
        &self,
        header: &BlockHeader,
        hash: &[u8; 32],
        cumulative_chainwork: &[u8; 32],
    ) -> Result<(), StoreError> {
        let txn = self.db.begin_rw_txn()?;

        let hdr_tbl = txn.open_table(Some(T_HEADERS))?;
        txn.put(
            &hdr_tbl,
            u64_key(header.height),
            encode_header(header),
            WriteFlags::empty(),
        )?;

        let h2h_tbl = txn.open_table(Some(T_HASH_TO_HEIGHT))?;
        txn.put(
            &h2h_tbl,
            hash.as_slice(),
            u64_key(header.height),
            WriteFlags::empty(),
        )?;

        let work_tbl = txn.open_table(Some(T_CHAIN_WORK))?;
        txn.put(
            &work_tbl,
            u64_key(header.height),
            encode_chain_work(cumulative_chainwork),
            WriteFlags::empty(),
        )?;

        let anchor_tbl = txn.open_table(Some(T_HEADER_ANCHORS))?;
        let anchor = if header.height == 0 {
            compute_header_chain_anchor(std::iter::once(header), *cumulative_chainwork)?
        } else {
            let previous_raw: Option<Vec<u8>> =
                txn.get(&anchor_tbl, &u64_key(header.height - 1))?;
            let previous = previous_raw
                .as_deref()
                .and_then(decode_header_chain_anchor)
                .ok_or(StoreError::Decode("missing previous header chain anchor"))?;
            extend_header_chain_anchor(&previous, header, *cumulative_chainwork)?
        };
        if anchor.block_id != *hash {
            return Err(StoreError::Decode("header anchor block id mismatch"));
        }
        txn.put(
            &anchor_tbl,
            u64_key(header.height),
            encode_header_chain_anchor(&anchor),
            WriteFlags::empty(),
        )?;

        txn.commit()?;
        Ok(())
    }

    pub fn get_undo_log(&self, height: u64) -> Result<Option<BlockUndoLog>, StoreError> {
        let txn = self.db.begin_ro_txn()?;
        let tbl = txn.open_table(Some(T_UNDO_LOGS))?;
        let raw: Option<Vec<u8>> = txn.get(&tbl, &u64_key(height))?;
        Ok(raw.and_then(|b| decode_undo_log(&b)))
    }

    pub fn get_segment(&self, seg_id: u16) -> Result<Option<(u8, SegmentColumns)>, StoreError> {
        let txn = self.db.begin_ro_txn()?;
        let tbl = txn.open_table(Some(T_SEGMENTS))?;
        let raw: Option<Vec<u8>> = txn.get(&tbl, &seg_id.to_le_bytes())?;
        Ok(raw.and_then(|b| decode_segment(&b)))
    }

    #[cfg(test)]
    pub(crate) fn overwrite_segment_for_test(
        &self,
        seg_id: u16,
        effective_log_seg: u8,
        cols: &SegmentColumns,
    ) -> Result<(), StoreError> {
        let txn = self.db.begin_rw_txn()?;
        let tbl = txn.open_table(Some(T_SEGMENTS))?;
        txn.put(
            &tbl,
            seg_id.to_le_bytes(),
            encode_segment(cols, effective_log_seg),
            WriteFlags::empty(),
        )?;
        txn.commit()?;
        Ok(())
    }

    pub fn get_recent_block(&self, height: u64) -> Result<Option<Vec<u8>>, StoreError> {
        let txn = self.db.begin_ro_txn()?;
        let tbl = txn.open_table(Some(T_RECENT_BLOCKS))?;
        Ok(txn.get(&tbl, &u64_key(height))?)
    }

    /// Store a serialised `BlockProof` for `height`.
    /// Retained until a real immutable checkpoint proof covers `height`.
    pub fn put_block_proof(&self, height: u64, bytes: &[u8]) -> Result<(), StoreError> {
        let txn = self.db.begin_rw_txn()?;
        let tbl = txn.open_table(Some(T_BLOCK_PROOFS))?;
        txn.put(&tbl, u64_key(height), bytes, WriteFlags::empty())?;
        txn.commit()?;
        Ok(())
    }

    /// Retrieve the `BlockProof` bytes for `height`, or `None` if pruned / not yet stored.
    pub fn get_block_proof(&self, height: u64) -> Result<Option<Vec<u8>>, StoreError> {
        let txn = self.db.begin_ro_txn()?;
        let tbl = txn.open_table(Some(T_BLOCK_PROOFS))?;
        let raw: Option<Vec<u8>> = txn.get(&tbl, &u64_key(height))?;
        Ok(raw)
    }

    /// Store a serialised `BlockAuthSidecar` for `height`.
    /// Retained with the block body and `BlockProof` until checkpoint coverage.
    pub fn put_block_auth_sidecar(&self, height: u64, bytes: &[u8]) -> Result<(), StoreError> {
        let txn = self.db.begin_rw_txn()?;
        let tbl = txn.open_table(Some(T_BLOCK_AUTH_SIDECARS))?;
        txn.put(&tbl, u64_key(height), bytes, WriteFlags::empty())?;
        txn.commit()?;
        Ok(())
    }

    /// Retrieve the `BlockAuthSidecar` bytes for `height`, or `None` if pruned / not yet stored.
    pub fn get_block_auth_sidecar(&self, height: u64) -> Result<Option<Vec<u8>>, StoreError> {
        let txn = self.db.begin_ro_txn()?;
        let tbl = txn.open_table(Some(T_BLOCK_AUTH_SIDECARS))?;
        let raw: Option<Vec<u8>> = txn.get(&tbl, &u64_key(height))?;
        Ok(raw)
    }

    /// Store accepted state-transition claim fields for `height`.
    pub fn put_history_claim(&self, height: u64, bytes: &[u8]) -> Result<(), StoreError> {
        let txn = self.db.begin_rw_txn()?;
        let tbl = txn.open_table(Some(T_HISTORY_CLAIMS))?;
        txn.put(&tbl, u64_key(height), bytes, WriteFlags::empty())?;
        txn.commit()?;
        Ok(())
    }

    /// Retrieve accepted state-transition claim fields for `height`.
    pub fn get_history_claim(&self, height: u64) -> Result<Option<Vec<u8>>, StoreError> {
        let txn = self.db.begin_ro_txn()?;
        let tbl = txn.open_table(Some(T_HISTORY_CLAIMS))?;
        let raw: Option<Vec<u8>> = txn.get(&tbl, &u64_key(height))?;
        Ok(raw)
    }

    /// Store accepted-block certificate material for `height`.
    ///
    /// The record bytes are intentionally owned by `noid_block`/`noid_recursive`
    /// so `noid_chain` does not depend on the recursive proof crate.
    pub fn put_accepted_block_certificate(
        &self,
        height: u64,
        bytes: &[u8],
    ) -> Result<(), StoreError> {
        let txn = self.db.begin_rw_txn()?;
        let tbl = txn.open_table(Some(T_ACCEPTED_BLOCK_CERTIFICATES))?;
        txn.put(&tbl, u64_key(height), bytes, WriteFlags::empty())?;
        txn.commit()?;
        Ok(())
    }

    /// Retrieve accepted-block certificate material for `height`.
    pub fn get_accepted_block_certificate(
        &self,
        height: u64,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        let txn = self.db.begin_ro_txn()?;
        let tbl = txn.open_table(Some(T_ACCEPTED_BLOCK_CERTIFICATES))?;
        Ok(txn.get(&tbl, &u64_key(height))?)
    }

    /// Store full accepted-block checkpoint batch package material.
    ///
    /// The bytes are intentionally owned by `noid_block`/`noid_recursive`
    /// so `noid_chain` stays independent of the recursive proof crate.
    pub fn put_accepted_block_batch_certificate_package(
        &self,
        end_height: u64,
        bytes: &[u8],
    ) -> Result<(), StoreError> {
        let txn = self.db.begin_rw_txn()?;
        let tbl = txn.open_table(Some(T_ACCEPTED_BLOCK_BATCH_CERTIFICATE_PACKAGES))?;
        txn.put(&tbl, u64_key(end_height), bytes, WriteFlags::empty())?;
        txn.commit()?;
        Ok(())
    }

    /// Retrieve full accepted-block checkpoint batch package material by end height.
    pub fn get_accepted_block_batch_certificate_package(
        &self,
        end_height: u64,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        let txn = self.db.begin_ro_txn()?;
        let tbl = txn.open_table(Some(T_ACCEPTED_BLOCK_BATCH_CERTIFICATE_PACKAGES))?;
        Ok(txn.get(&tbl, &u64_key(end_height))?)
    }

    /// Return the greatest end height that has a full accepted-block batch package.
    pub fn latest_accepted_block_batch_certificate_package_height(
        &self,
    ) -> Result<Option<u64>, StoreError> {
        let txn = self.db.begin_ro_txn()?;
        let tbl = txn.open_table(Some(T_ACCEPTED_BLOCK_BATCH_CERTIFICATE_PACKAGES))?;
        let mut cur = txn.cursor(&tbl)?;
        let mut latest = None;
        let mut item: Option<(Vec<u8>, Vec<u8>)> = cur.first()?;
        while let Some((k, _)) = item {
            if let Some(height) = u64_from_key(&k) {
                latest = Some(latest.map_or(height, |current: u64| current.max(height)));
            }
            item = cur.next()?;
        }
        Ok(latest)
    }

    /// Delete a full accepted-block batch package by end height.
    pub fn delete_accepted_block_batch_certificate_package(
        &self,
        end_height: u64,
    ) -> Result<(), StoreError> {
        let txn = self.db.begin_rw_txn()?;
        let tbl = txn.open_table(Some(T_ACCEPTED_BLOCK_BATCH_CERTIFICATE_PACKAGES))?;
        txn.del(&tbl, u64_key(end_height), None)?;
        txn.commit()?;
        Ok(())
    }

    /// Store verified recursive checkpoint head material.
    ///
    /// The record bytes are intentionally owned by `noid_recursive` so
    /// `noid_chain` stays independent of the recursive proof crate.
    pub fn put_history_checkpoint_head_record(
        &self,
        height: u64,
        bytes: &[u8],
    ) -> Result<(), StoreError> {
        let txn = self.db.begin_rw_txn()?;
        let tbl = txn.open_table(Some(T_HISTORY_CHECKPOINT_HEADS))?;
        txn.put(&tbl, u64_key(height), bytes, WriteFlags::empty())?;
        txn.commit()?;
        Ok(())
    }

    /// Retrieve verified recursive checkpoint head material by checkpoint height.
    pub fn get_history_checkpoint_head_record(
        &self,
        height: u64,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        let txn = self.db.begin_ro_txn()?;
        let tbl = txn.open_table(Some(T_HISTORY_CHECKPOINT_HEADS))?;
        Ok(txn.get(&tbl, &u64_key(height))?)
    }

    /// Return the greatest checkpoint height that has a verified head record.
    pub fn latest_history_checkpoint_head_height(&self) -> Result<Option<u64>, StoreError> {
        let txn = self.db.begin_ro_txn()?;
        let tbl = txn.open_table(Some(T_HISTORY_CHECKPOINT_HEADS))?;
        let mut cur = txn.cursor(&tbl)?;
        let mut latest = None;
        let mut item: Option<(Vec<u8>, Vec<u8>)> = cur.first()?;
        while let Some((k, _)) = item {
            if let Some(height) = u64_from_key(&k) {
                latest = Some(latest.map_or(height, |current: u64| current.max(height)));
            }
            item = cur.next()?;
        }
        Ok(latest)
    }

    /// Delete a verified recursive checkpoint head record by checkpoint height.
    pub fn delete_history_checkpoint_head_record(&self, height: u64) -> Result<(), StoreError> {
        let txn = self.db.begin_rw_txn()?;
        let tbl = txn.open_table(Some(T_HISTORY_CHECKPOINT_HEADS))?;
        txn.del(&tbl, u64_key(height), None)?;
        txn.commit()?;
        Ok(())
    }

    /// Store an immutable local checkpoint package for a finalized prefix.
    pub fn put_checkpoint_package(
        &self,
        package: &ImmutableCheckpointPackage,
    ) -> Result<(), StoreError> {
        let txn = self.db.begin_rw_txn()?;
        let tbl = txn.open_table(Some(T_CHECKPOINT_PACKAGES))?;
        txn.put(
            &tbl,
            u64_key(package.manifest.height),
            encode_checkpoint_package(package),
            WriteFlags::empty(),
        )?;
        txn.commit()?;
        Ok(())
    }

    /// Retrieve a local checkpoint package by height.
    pub fn get_checkpoint_package(
        &self,
        height: u64,
    ) -> Result<Option<ImmutableCheckpointPackage>, StoreError> {
        let txn = self.db.begin_ro_txn()?;
        let tbl = txn.open_table(Some(T_CHECKPOINT_PACKAGES))?;
        let raw: Option<Vec<u8>> = txn.get(&tbl, &u64_key(height))?;
        Ok(raw.and_then(|b| decode_checkpoint_package(&b)))
    }

    /// Persist latest local checkpoint package coverage metadata.
    pub fn put_checkpoint_coverage(&self, coverage: &CheckpointCoverage) -> Result<(), StoreError> {
        let txn = self.db.begin_rw_txn()?;
        let tbl = txn.open_table(Some(T_CHECKPOINT_COVERAGE))?;
        txn.put(
            &tbl,
            KEY_CHECKPOINT_COVERAGE,
            encode_checkpoint_coverage(coverage),
            WriteFlags::empty(),
        )?;
        txn.commit()?;
        Ok(())
    }

    /// Atomically store a checkpoint package and the latest coverage pointer.
    pub fn put_checkpoint_package_and_coverage(
        &self,
        package: &ImmutableCheckpointPackage,
        coverage: &CheckpointCoverage,
    ) -> Result<(), StoreError> {
        let txn = self.db.begin_rw_txn()?;
        let pkg_tbl = txn.open_table(Some(T_CHECKPOINT_PACKAGES))?;
        txn.put(
            &pkg_tbl,
            u64_key(package.manifest.height),
            encode_checkpoint_package(package),
            WriteFlags::empty(),
        )?;
        let cov_tbl = txn.open_table(Some(T_CHECKPOINT_COVERAGE))?;
        txn.put(
            &cov_tbl,
            KEY_CHECKPOINT_COVERAGE,
            encode_checkpoint_coverage(coverage),
            WriteFlags::empty(),
        )?;
        txn.commit()?;
        Ok(())
    }

    pub fn get_checkpoint_coverage(&self) -> Result<Option<CheckpointCoverage>, StoreError> {
        let txn = self.db.begin_ro_txn()?;
        let tbl = txn.open_table(Some(T_CHECKPOINT_COVERAGE))?;
        let raw: Option<Vec<u8>> = txn.get(&tbl, KEY_CHECKPOINT_COVERAGE)?;
        Ok(raw.and_then(|b| decode_checkpoint_coverage(&b)))
    }

    /// Look up all live UTXOs for a given owner address.
    ///
    /// Returns `Vec<(slot_index, value_micronoid)>` — all UTXOs currently
    /// owned by `owner` according to the incremental owner index.
    ///
    /// Returns an empty vec if the owner has no UTXOs OR if the index has
    /// not yet been populated (e.g. on first startup before any blocks).
    pub fn get_utxos_by_owner(&self, owner: &[u8; 32]) -> Result<Vec<(u32, u64)>, StoreError> {
        let txn = self.db.begin_ro_txn()?;
        let tbl = txn.open_table(Some(T_OWNER_INDEX))?;
        let raw: Option<Vec<u8>> = txn.get(&tbl, owner.as_slice())?;
        Ok(raw.map(|b| decode_owner_entries(&b)).unwrap_or_default())
    }

    /// Rebuild the owner index from a set of segment columns (used after
    /// applying a state snapshot when the index is empty).
    ///
    /// Clears the existing index and rebuilds it from scratch. O(active_slots).
    pub fn rebuild_owner_index_from_segments(
        &self,
        segments: &[(u16, u8, &crate::segmented_state::SegmentColumns)],
    ) -> Result<(), StoreError> {
        use std::collections::HashMap;

        // Build in-memory map: owner_key → Vec<(slot, value)>
        let mut owner_map: HashMap<[u8; 32], Vec<(u32, u64)>> = HashMap::new();
        for &(seg_id, eff_log, cols) in segments {
            let eff_log = eff_log as u32;
            let seg_size = cols.values.len();
            for local in 0..seg_size {
                let v = cols.values[local];
                let oh = cols.owners_hi[local];
                let ol = cols.owners_lo[local];
                if v.0 == 0 && oh.0 == 0 && ol.0 == 0 {
                    continue; // empty slot
                }
                let owner_key = owner_key_from_fields(oh, ol);
                let slot = ((seg_id as u32) << eff_log) | (local as u32);
                let value = unpack_amount_creation_id(v).0;
                owner_map.entry(owner_key).or_default().push((slot, value));
            }
        }

        // Write to MDBX atomically.
        let txn = self.db.begin_rw_txn()?;
        let tbl = txn.open_table(Some(T_OWNER_INDEX))?;

        // Clear existing entries (cursor-based delete all).
        {
            let mut cur = txn.cursor(&tbl)?;
            let mut item: Option<(Vec<u8>, Vec<u8>)> = cur.first()?;
            let mut keys: Vec<Vec<u8>> = Vec::new();
            while let Some((k, _)) = item {
                keys.push(k);
                item = cur.next()?;
            }
            drop(cur);
            for k in keys {
                let _ = txn.del(&tbl, &k, None);
            }
        }

        // Write new entries.
        for (owner_key, entries) in &owner_map {
            let encoded = encode_owner_entries(entries);
            txn.put(&tbl, owner_key.as_slice(), &encoded, WriteFlags::empty())?;
        }

        txn.commit()?;
        Ok(())
    }

    /// Populate T_TX_INDEX from snapshot tx hash blocks.
    ///
    /// Called after `apply_state_snapshot` so that `getTx` works for the blocks
    /// covered by the snapshot. Without this, T_TX_INDEX is
    /// empty on freshly-snapshotted nodes and `getTx` returns null for recent history.
    ///
    /// `start_height`: the block height of `tx_hash_blocks[0]`.
    /// `tx_hash_blocks[i][j]`: tx_body_hash at position j in block start_height+i.
    pub fn rebuild_tx_index_from_tx_hash_blocks(
        &self,
        tx_hash_blocks: &[Vec<noid_poseidon2b::primitives::TxBodyHash>],
        start_height: u64,
    ) -> Result<(), StoreError> {
        if tx_hash_blocks.is_empty() {
            return Ok(());
        }
        let txn = self.db.begin_rw_txn()?;
        let tbl = txn.open_table(Some(T_TX_INDEX))?;
        for (i, block_hashes) in tx_hash_blocks.iter().enumerate() {
            let height = start_height + i as u64;
            for (pos, hash) in block_hashes.iter().enumerate() {
                txn.put(
                    &tbl,
                    hash.0.as_slice(),
                    encode_tx_index_value(height, pos as u32),
                    libmdbx::WriteFlags::empty(),
                )?;
            }
        }
        txn.commit()?;
        Ok(())
    }

    /// Atomically install a snapshot state at an already-verified canonical header.
    ///
    /// This replaces volatile state tables only. Canonical headers, hash->height,
    /// chainwork, and local history/checkpoint tables are preserved.
    #[allow(clippy::too_many_arguments)]
    pub fn install_state_snapshot(
        &self,
        tip_header: &BlockHeader,
        tip_hash: &[u8; 32],
        consensus_meta: &ConsensusMeta,
        segments: &[(u16, u8, &SegmentColumns)],
        reuse_guard_buckets: &[GuardBucket; REUSE_GUARD_BUCKETS],
    ) -> Result<(), StoreError> {
        use std::collections::HashMap;

        let txn = self.db.begin_rw_txn()?;

        for name in [
            T_SEGMENTS,
            T_UNDO_LOGS,
            T_RECENT_BLOCKS,
            T_TX_INDEX,
            T_BLOCK_PROOFS,
            T_BLOCK_AUTH_SIDECARS,
            T_HISTORY_CLAIMS,
            T_ACCEPTED_BLOCK_CERTIFICATES,
            T_ACCEPTED_BLOCK_BATCH_CERTIFICATE_PACKAGES,
            T_OWNER_INDEX,
        ] {
            let tbl = txn.open_table(Some(name))?;
            let keys: Vec<Vec<u8>> = {
                let mut cur = txn.cursor(&tbl)?;
                let mut keys = Vec::new();
                let mut item: Option<(Vec<u8>, Vec<u8>)> = cur.first()?;
                while let Some((k, _)) = item {
                    keys.push(k);
                    item = cur.next()?;
                }
                keys
            };
            for key in keys {
                let _ = txn.del(&tbl, &key, None);
            }
        }

        let seg_tbl = txn.open_table(Some(T_SEGMENTS))?;
        for &(seg_id, eff_log, cols) in segments {
            if segment_columns_empty(cols) {
                continue;
            }
            txn.put(
                &seg_tbl,
                seg_id.to_le_bytes(),
                encode_segment(cols, eff_log),
                WriteFlags::empty(),
            )?;
        }

        let tip_tbl = txn.open_table(Some(T_CHAIN_TIP))?;
        txn.put(
            &tip_tbl,
            KEY_TIP,
            encode_chain_tip(tip_header.height, tip_hash),
            WriteFlags::empty(),
        )?;

        let consensus_tbl = txn.open_table(Some(T_CONSENSUS_META))?;
        txn.put(
            &consensus_tbl,
            KEY_CONSENSUS_META,
            encode_consensus_meta(consensus_meta),
            WriteFlags::empty(),
        )?;

        let work_tbl = txn.open_table(Some(T_CHAIN_WORK))?;
        txn.put(
            &work_tbl,
            u64_key(tip_header.height),
            encode_chain_work(&consensus_meta.cumulative_chainwork),
            WriteFlags::empty(),
        )?;

        let meta_tbl = txn.open_table(Some(T_STATE_META))?;
        txn.put(
            &meta_tbl,
            KEY_META,
            encode_state_meta(
                tip_header.log_slots,
                tip_header.active_slot_count,
                tip_header.alloc_counter,
            ),
            WriteFlags::empty(),
        )?;

        let guard_tbl = txn.open_table(Some(T_REUSE_GUARD))?;
        txn.put(
            &guard_tbl,
            KEY_REUSE_GUARD,
            encode_reuse_guard_buckets(reuse_guard_buckets),
            WriteFlags::empty(),
        )?;

        let mut owner_map: HashMap<[u8; 32], Vec<(u32, u64)>> = HashMap::new();
        for &(seg_id, eff_log, cols) in segments {
            let eff_log = eff_log as u32;
            for local in 0..cols.values.len() {
                let value = cols.values[local];
                let owner_hi = cols.owners_hi[local];
                let owner_lo = cols.owners_lo[local];
                if value.0 == 0 && owner_hi.0 == 0 && owner_lo.0 == 0 {
                    continue;
                }
                let owner = owner_key_from_fields(owner_hi, owner_lo);
                let slot = ((seg_id as u32) << eff_log) | (local as u32);
                owner_map
                    .entry(owner)
                    .or_default()
                    .push((slot, unpack_amount_creation_id(value).0));
            }
        }

        let owner_tbl = txn.open_table(Some(T_OWNER_INDEX))?;
        for (owner, entries) in owner_map {
            txn.put(
                &owner_tbl,
                owner.as_slice(),
                encode_owner_entries(&entries),
                WriteFlags::empty(),
            )?;
        }

        txn.commit()?;
        Ok(())
    }

    /// Look up a transaction by its body hash. Returns `(block_height, tx_pos_in_block)`.
    pub fn get_tx_index(&self, hash: &[u8; 32]) -> Result<Option<(u64, u32)>, StoreError> {
        let txn = self.db.begin_ro_txn()?;
        let tbl = txn.open_table(Some(T_TX_INDEX))?;
        let raw: Option<Vec<u8>> = txn.get(&tbl, hash.as_slice())?;
        Ok(raw.and_then(|b| decode_tx_index_value(&b)))
    }

    /// Iterate over all stored segment IDs and their column data.
    pub fn all_segments(&self) -> Result<Vec<(u16, u8, SegmentColumns)>, StoreError> {
        let txn = self.db.begin_ro_txn()?;
        let tbl = txn.open_table(Some(T_SEGMENTS))?;
        let mut cursor = txn.cursor(&tbl)?;
        let mut results = Vec::new();
        // Use first() to position at the start, then next() to advance.
        let mut item: Option<(Vec<u8>, Vec<u8>)> = cursor.first()?;
        while let Some((k, v)) = item {
            if k.len() >= 2 {
                let seg_id = u16::from_le_bytes([k[0], k[1]]);
                if let Some((eff, cols)) = decode_segment(&v) {
                    results.push((seg_id, eff, cols));
                }
            }
            item = cursor.next()?;
        }
        Ok(results)
    }

    // -----------------------------------------------------------------------
    // Atomic block commit (P.18 — 7-step protocol)
    // -----------------------------------------------------------------------

    /// Atomically commit all data for a newly applied block.
    ///
    /// Steps (all in ONE MDBX transaction, either fully committed or fully aborted):
    /// 1. Write dirty segment columns
    /// 2. Write BlockHeader (height → bytes)
    /// 3. Write hash→height index
    /// 4. Write chain_tip and consensus_meta
    /// 5. Write exact cumulative chainwork at this height
    /// 6. Write state_meta (log_slots, active_slot_count, alloc_counter)
    /// 7. Write BlockUndoLog
    /// 8. Write recent_block bytes
    ///
    /// After commit (non-atomic, re-runnable):
    ///   - Prune old undo_logs beyond UNDO_RETENTION_DEPTH.
    ///   - Prune retained block bodies, BlockProofs, Auth sidecars, and local
    ///     accepted-claim witnesses once checkpoint package coverage reaches
    ///     the same heights and they are outside the recent serving window.
    #[allow(clippy::too_many_arguments)]
    pub fn commit_block(
        &self,
        header: &BlockHeader,
        hash: &[u8; 32],
        undo_log: &BlockUndoLog,
        dirty_segments: &[(u16, u8, &SegmentColumns)], // (seg_id, effective_log_seg, cols)
        reuse_guard_buckets: &[GuardBucket; REUSE_GUARD_BUCKETS],
        tx_hashes: &[TxBodyHash],
        block_bytes: Option<&[u8]>, // None = don't store (DA already pruned)
        consensus_meta: &ConsensusMeta,
        rebuild_owner_index: bool,
    ) -> Result<(), StoreError> {
        let txn = self.db.begin_rw_txn()?;

        // --- 1. Dirty segments ---
        let seg_tbl = txn.open_table(Some(T_SEGMENTS))?;
        for (seg_id, eff_log, cols) in dirty_segments {
            let key = seg_id.to_le_bytes();
            if segment_columns_empty(cols) {
                // Do not persist fully-empty segments. This keeps disk and snapshot
                // size proportional to live UTXOs, not historical touched ranges.
                let _ = txn.del(&seg_tbl, key, None);
            } else {
                let val = encode_segment(cols, *eff_log);
                txn.put(&seg_tbl, key, val, WriteFlags::empty())?;
            }
        }

        // --- 2. BlockHeader ---
        let hdr_tbl = txn.open_table(Some(T_HEADERS))?;
        txn.put(
            &hdr_tbl,
            u64_key(header.height),
            encode_header(header),
            WriteFlags::empty(),
        )?;

        // --- 3. hash → height ---
        let h2h_tbl = txn.open_table(Some(T_HASH_TO_HEIGHT))?;
        txn.put(
            &h2h_tbl,
            hash.as_slice(),
            u64_key(header.height),
            WriteFlags::empty(),
        )?;

        // --- 4. chain_tip + consensus_meta ---
        debug_assert_eq!(consensus_meta.tip_height, header.height);
        debug_assert_eq!(consensus_meta.tip_hash, *hash);

        let tip_tbl = txn.open_table(Some(T_CHAIN_TIP))?;
        txn.put(
            &tip_tbl,
            KEY_TIP,
            encode_chain_tip(header.height, hash),
            WriteFlags::empty(),
        )?;

        let consensus_tbl = txn.open_table(Some(T_CONSENSUS_META))?;
        txn.put(
            &consensus_tbl,
            KEY_CONSENSUS_META,
            encode_consensus_meta(consensus_meta),
            WriteFlags::empty(),
        )?;

        // --- 5. exact chainwork at canonical height ---
        let work_tbl = txn.open_table(Some(T_CHAIN_WORK))?;
        txn.put(
            &work_tbl,
            u64_key(header.height),
            encode_chain_work(&consensus_meta.cumulative_chainwork),
            WriteFlags::empty(),
        )?;

        // --- 5.5. persistent header-chain anchor ---
        let anchor_tbl = txn.open_table(Some(T_HEADER_ANCHORS))?;
        let anchor = if header.height == 0 {
            compute_header_chain_anchor(
                std::iter::once(header),
                consensus_meta.cumulative_chainwork,
            )?
        } else {
            let previous_raw: Option<Vec<u8>> =
                txn.get(&anchor_tbl, &u64_key(header.height - 1))?;
            let previous = previous_raw
                .as_deref()
                .and_then(decode_header_chain_anchor)
                .ok_or(StoreError::Decode("missing previous header chain anchor"))?;
            extend_header_chain_anchor(&previous, header, consensus_meta.cumulative_chainwork)?
        };
        if anchor.block_id != *hash {
            return Err(StoreError::Decode("header anchor block id mismatch"));
        }
        txn.put(
            &anchor_tbl,
            u64_key(header.height),
            encode_header_chain_anchor(&anchor),
            WriteFlags::empty(),
        )?;

        // --- 6. state_meta ---
        let meta_tbl = txn.open_table(Some(T_STATE_META))?;
        txn.put(
            &meta_tbl,
            KEY_META,
            encode_state_meta(
                header.log_slots,
                header.active_slot_count,
                header.alloc_counter,
            ),
            WriteFlags::empty(),
        )?;

        let guard_tbl = txn.open_table(Some(T_REUSE_GUARD))?;
        txn.put(
            &guard_tbl,
            KEY_REUSE_GUARD,
            encode_reuse_guard_buckets(reuse_guard_buckets),
            WriteFlags::empty(),
        )?;

        // --- 7. BlockUndoLog ---
        let undo_tbl = txn.open_table(Some(T_UNDO_LOGS))?;
        txn.put(
            &undo_tbl,
            u64_key(header.height),
            encode_undo_log(undo_log),
            WriteFlags::empty(),
        )?;

        // --- 8. Recent block ---
        let recent_tbl = txn.open_table(Some(T_RECENT_BLOCKS))?;
        if let Some(bytes) = block_bytes {
            txn.put(
                &recent_tbl,
                u64_key(header.height),
                bytes,
                WriteFlags::empty(),
            )?;
        }

        // --- 8.5. tx_index: TxBodyHash → (height, position_in_block) ---
        // Enables O(1) receipt lookup: given a tx_body_hash, find the block
        // and position to reconstruct the Merkle inclusion path.
        let tx_idx_tbl = txn.open_table(Some(T_TX_INDEX))?;
        for (pos, h) in tx_hashes.iter().enumerate() {
            txn.put(
                &tx_idx_tbl,
                h.0,
                encode_tx_index_value(header.height, pos as u32),
                WriteFlags::empty(),
            )?;
        }

        // --- 9. Owner index: update live-UTXO index incrementally, or rebuild
        // it from the post-write segment table for a reorg checkpoint. A reorg
        // restores an ancestor using that ancestor's historical undo log; that
        // log is not a forward delta and must never drive the incremental path.
        // Uses undo_log (which records pre-block slot values) and dirty_segments
        // (which hold post-block slot values) to determine what changed.
        {
            use crate::fri_state::SlotValue;
            let oidx_tbl = txn.open_table(Some(T_OWNER_INDEX))?;
            if rebuild_owner_index {
                let mut old_keys = Vec::new();
                {
                    let mut cursor = txn.cursor(&oidx_tbl)?;
                    let mut item: Option<(Vec<u8>, Vec<u8>)> = cursor.first()?;
                    while let Some((key, _)) = item {
                        old_keys.push(key);
                        item = cursor.next()?;
                    }
                }
                for key in old_keys {
                    let _ = txn.del(&oidx_tbl, key, None);
                }

                let mut owner_map: std::collections::HashMap<[u8; 32], Vec<(u32, u64)>> =
                    std::collections::HashMap::new();
                {
                    let mut cursor = txn.cursor(&seg_tbl)?;
                    let mut item: Option<(Vec<u8>, Vec<u8>)> = cursor.first()?;
                    while let Some((key, raw)) = item {
                        if key.len() >= 2 {
                            let seg_id = u16::from_le_bytes([key[0], key[1]]);
                            let (eff_log, cols) = decode_segment(&raw).ok_or(
                                StoreError::Decode("invalid segment during owner rebuild"),
                            )?;
                            for local in 0..cols.values.len() {
                                let value = cols.values[local];
                                let owner_hi = cols.owners_hi[local];
                                let owner_lo = cols.owners_lo[local];
                                if value.0 != 0 || owner_hi.0 != 0 || owner_lo.0 != 0 {
                                    let owner = owner_key_from_fields(owner_hi, owner_lo);
                                    let slot = ((seg_id as u32) << eff_log) | local as u32;
                                    owner_map
                                        .entry(owner)
                                        .or_default()
                                        .push((slot, unpack_amount_creation_id(value).0));
                                }
                            }
                        }
                        item = cursor.next()?;
                    }
                }
                for entries in owner_map.values_mut() {
                    entries.sort_unstable_by_key(|(slot, _)| *slot);
                }
                for (owner, entries) in owner_map {
                    txn.put(
                        &oidx_tbl,
                        owner.as_slice(),
                        encode_owner_entries(&entries),
                        WriteFlags::empty(),
                    )?;
                }
            } else {
                // eff_log = log2(slots_per_segment) — same for every dirty segment.
                let eff_log: u32 = dirty_segments
                    .first()
                    .map(|(_, e, _)| *e as u32)
                    .unwrap_or(crate::consensus::params::LOG_SEGMENT_SIZE);

                for &(slot_index, ref prev_value) in &undo_log.slot_changes {
                    // Remove the pre-block owner, if any.
                    if *prev_value != SlotValue::EMPTY {
                        let owner_key =
                            owner_key_from_fields(prev_value.owner_hi, prev_value.owner_lo);
                        let existing: Option<Vec<u8>> = txn.get(&oidx_tbl, owner_key.as_slice())?;
                        if let Some(raw) = existing {
                            let entries: Vec<(u32, u64)> = decode_owner_entries(&raw)
                                .into_iter()
                                .filter(|(slot, _)| *slot != slot_index)
                                .collect();
                            if entries.is_empty() {
                                let _ = txn.del(&oidx_tbl, owner_key.as_slice(), None);
                            } else {
                                txn.put(
                                    &oidx_tbl,
                                    owner_key.as_slice(),
                                    encode_owner_entries(&entries),
                                    WriteFlags::empty(),
                                )?;
                            }
                        }
                    }

                    // Add the post-block owner, if any. Doing both halves for
                    // every first-touch slot also handles live→live physical
                    // reuse once the legacy ReuseGuard is removed.
                    let seg_id = (slot_index >> eff_log) as u16;
                    let local = (slot_index & ((1u32 << eff_log) - 1)) as usize;
                    let (value, owner_hi, owner_lo) = dirty_segments
                        .iter()
                        .find(|(id, _, _)| *id == seg_id)
                        .and_then(|(_, _, cols)| {
                            (local < cols.values.len()).then(|| {
                                (
                                    cols.values[local],
                                    cols.owners_hi[local],
                                    cols.owners_lo[local],
                                )
                            })
                        })
                        .ok_or(StoreError::Decode(
                            "owner-index delta slot missing from dirty segments",
                        ))?;
                    if value.0 != 0 || owner_hi.0 != 0 || owner_lo.0 != 0 {
                        let owner_key = owner_key_from_fields(owner_hi, owner_lo);
                        let amount = unpack_amount_creation_id(value).0;
                        let existing: Option<Vec<u8>> = txn.get(&oidx_tbl, owner_key.as_slice())?;
                        let mut entries = existing
                            .as_deref()
                            .map(decode_owner_entries)
                            .unwrap_or_default();
                        entries.retain(|(slot, _)| *slot != slot_index);
                        entries.push((slot_index, amount));
                        entries.sort_unstable_by_key(|(slot, _)| *slot);
                        txn.put(
                            &oidx_tbl,
                            owner_key.as_slice(),
                            encode_owner_entries(&entries),
                            WriteFlags::empty(),
                        )?;
                    }
                }
            }
        }

        // Commit atomically — all steps or none.
        txn.commit()?;

        // Post-commit pruning is non-atomic and non-critical.
        // A prune failure leaves stale undo entries until
        // the next commit, but the chain state is already
        // fully consistent after the commit above.  We must NOT propagate the
        // error here: doing so would cause `apply_next_block` to return Err
        // after the block is already durably in MDBX, leaving RAM and MDBX
        // desynchronised until the next restart.
        if let Err(_e) = self.prune_after_commit(header.height) {
            // Safe to ignore: prune is retried on the next commit.
        }

        Ok(())
    }

    fn prune_after_commit(&self, current_height: u64) -> Result<(), StoreError> {
        let txn = self.db.begin_rw_txn()?;
        macro_rules! prune_height_table {
            ($tbl:expr, $cutoff:expr) => {{
                let keys_to_del: Vec<u64> = {
                    let mut cur = txn.cursor(&$tbl)?;
                    let mut keys = Vec::new();
                    let mut item: Option<(Vec<u8>, Vec<u8>)> = cur.first()?;
                    while let Some((k, _)) = item {
                        match u64_from_key(&k) {
                            Some(h) if h <= $cutoff => keys.push(h),
                            _ => break,
                        }
                        item = cur.next()?;
                    }
                    keys
                };
                for h in keys_to_del {
                    txn.del(&$tbl, u64_key(h), None)?;
                }
            }};
        }

        // --- Prune undo_logs older than UNDO_RETENTION_DEPTH ---
        if current_height > UNDO_RETENTION_DEPTH {
            let undo_tbl = txn.open_table(Some(T_UNDO_LOGS))?;
            let cutoff = current_height - UNDO_RETENTION_DEPTH;
            prune_height_table!(undo_tbl, cutoff);
        }

        // --- Prune retained block payloads after O(1) history coverage ---
        //
        // The node stores headers forever. Full block bytes, BlockProof bytes,
        // Auth sidecars, and accepted-claim witnesses are transient witnesses.
        // They may be deleted once both conditions are true:
        //
        // 1. The height is outside the recent serving/reorg window.
        // 2. The local O(1) checkpoint package coverage has consumed it.
        //
        // A height is pruned only after accepted-block certificate material
        // exists for it and proven checkpoint coverage explicitly reaches it.
        if current_height > RECENT_BLOCK_RETENTION_DEPTH {
            let retention_cutoff = current_height - RECENT_BLOCK_RETENTION_DEPTH;
            let real_checkpoint_coverage = {
                let cov_tbl = txn.open_table(Some(T_CHECKPOINT_COVERAGE))?;
                let raw: Option<Vec<u8>> = txn.get(&cov_tbl, KEY_CHECKPOINT_COVERAGE)?;
                raw.and_then(|b| decode_checkpoint_coverage(&b))
                    .and_then(|coverage| coverage.history_proof_covered_to)
            };
            if let Some(coverage_height) = real_checkpoint_coverage {
                let cutoff = retention_cutoff.min(coverage_height);
                let cert_tbl = txn.open_table(Some(T_ACCEPTED_BLOCK_CERTIFICATES))?;
                for table_name in [
                    T_RECENT_BLOCKS,
                    T_BLOCK_PROOFS,
                    T_BLOCK_AUTH_SIDECARS,
                    T_HISTORY_CLAIMS,
                ] {
                    let tbl = txn.open_table(Some(table_name))?;
                    let candidates: Vec<u64> = {
                        let mut cur = txn.cursor(&tbl)?;
                        let mut keys = Vec::new();
                        let mut item: Option<(Vec<u8>, Vec<u8>)> = cur.first()?;
                        while let Some((k, _)) = item {
                            match u64_from_key(&k) {
                                Some(h) if h <= cutoff => keys.push(h),
                                _ => break,
                            }
                            item = cur.next()?;
                        }
                        keys
                    };
                    for h in candidates {
                        let certificate: Option<Vec<u8>> = txn.get(&cert_tbl, &u64_key(h))?;
                        if certificate.is_some() {
                            txn.del(&tbl, u64_key(h), None)?;
                        }
                    }
                }
            }
        }

        txn.commit()?;
        Ok(())
    }

    /// Clear volatile tables after local state corruption is detected, keeping
    /// append-only headers, hash->height index, header anchors, and chainwork.
    ///
    /// Normal startup does NOT clear these tables: `MdbxChainContext::open_or_create`
    /// first tries to restore persisted current state from MDBX and checks it against
    /// the tip header's `state_root`. This function is the local recovery path
    /// for corrupt local state; peer snapshot recovery goes through the
    /// manifest/proof sync pipeline instead.
    pub fn clear_for_restart(&self) -> Result<(), StoreError> {
        let txn = self.db.begin_rw_txn()?;
        let volatile = [
            T_SEGMENTS,
            T_RECENT_BLOCKS,
            T_UNDO_LOGS,
            T_BLOCK_PROOFS,
            T_BLOCK_AUTH_SIDECARS,
            T_ACCEPTED_BLOCK_CERTIFICATES,
            T_ACCEPTED_BLOCK_BATCH_CERTIFICATE_PACKAGES,
            T_HISTORY_CHECKPOINT_HEADS,
            T_CHECKPOINT_COVERAGE,
            T_OWNER_INDEX,
            T_STATE_META,
            T_CHAIN_TIP,
            T_CONSENSUS_META,
            T_TX_INDEX,
        ];
        for name in volatile {
            let tbl = txn.open_table(Some(name))?;
            let keys: Vec<Vec<u8>> = {
                let mut cur = txn.cursor(&tbl)?;
                let mut keys = Vec::new();
                let mut item: Option<(Vec<u8>, Vec<u8>)> = cur.first()?;
                while let Some((k, _)) = item {
                    keys.push(k);
                    item = cur.next()?;
                }
                keys
            };
            for k in keys {
                let _ = txn.del(&tbl, &k, None);
            }
        }
        txn.commit()?;
        Ok(())
    }

    /// Returns `true` if the store has never had a block committed (fresh database).
    pub fn is_empty(&self) -> Result<bool, StoreError> {
        Ok(self.get_chain_tip()?.is_none())
    }
}

// ---------------------------------------------------------------------------
// BlockStore trait implementation
// ---------------------------------------------------------------------------

impl crate::storage::BlockStore for MdbxStore {
    fn best_tip(&self) -> Option<(u64, [u8; 32])> {
        self.get_chain_tip().ok().flatten()
    }

    fn get_header(
        &self,
        height: u64,
    ) -> Result<Option<crate::block_header::BlockHeader>, StoreError> {
        MdbxStore::get_header(self, height)
    }

    fn get_header_by_hash(
        &self,
        hash: &[u8; 32],
    ) -> Result<Option<crate::block_header::BlockHeader>, StoreError> {
        MdbxStore::get_header_by_hash(self, hash)
    }

    fn get_recent_block(&self, height: u64) -> Result<Option<Vec<u8>>, StoreError> {
        MdbxStore::get_recent_block(self, height)
    }

    fn get_tx_index(&self, hash: &[u8; 32]) -> Result<Option<(u64, u32)>, StoreError> {
        MdbxStore::get_tx_index(self, hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn undo_counter_snapshots_survive_durable_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let header = crate::consensus::genesis::genesis_header();
        let hash = crate::hash_block_header(&header);
        let guard = crate::reuse_guard::ReuseGuard::new_empty();
        let undo = BlockUndoLog {
            block_height: header.height,
            active_slot_count_before: 37,
            alloc_counter_before: 91,
            slot_changes: vec![],
            tx_hashes: vec![TxBodyHash([0xA5; 32])],
            reuse_guard_before: (*guard.buckets()).clone(),
        };
        let meta = ConsensusMeta {
            tip_height: header.height,
            tip_hash: hash,
            cumulative_chainwork: [1u8; 32],
            finalized: crate::storage::meta::FinalizedCheckpoint {
                height: header.height,
                hash,
            },
        };

        {
            let store = MdbxStore::open(dir.path()).unwrap();
            store
                .commit_block(
                    &header,
                    &hash,
                    &undo,
                    &[],
                    guard.buckets(),
                    &undo.tx_hashes,
                    None,
                    &meta,
                    false,
                )
                .unwrap();
        }

        let reopened = MdbxStore::open(dir.path()).unwrap();
        assert_eq!(reopened.get_undo_log(header.height).unwrap(), Some(undo));
    }

    #[test]
    fn reorg_checkpoint_rebuilds_owner_index_from_restored_segments() {
        use noid_poseidon2b::primitives::Address;

        let dir = tempfile::tempdir().unwrap();
        let store = MdbxStore::open(dir.path()).unwrap();
        let owner_a = Address([0x11; 32]);
        let owner_b = Address([0x22; 32]);
        let mut header = crate::consensus::genesis::genesis_header();
        header.active_slot_count = 1;
        header.alloc_counter = 1;
        let hash = crate::hash_block_header(&header);
        let guard = crate::reuse_guard::ReuseGuard::new_empty();
        let meta = ConsensusMeta {
            tip_height: 0,
            tip_hash: hash,
            cumulative_chainwork: [1u8; 32],
            finalized: crate::storage::meta::FinalizedCheckpoint { height: 0, hash },
        };
        let undo = BlockUndoLog {
            block_height: 0,
            active_slot_count_before: 0,
            alloc_counter_before: 0,
            slot_changes: vec![(1, crate::fri_state::SlotValue::EMPTY)],
            tx_hashes: vec![],
            reuse_guard_before: (*guard.buckets()).clone(),
        };

        let mut branch_cols = SegmentColumns::new_zero(2);
        let branch_slot =
            crate::fri_state::SlotValue::with_owner_fields(77, 1, owner_b.as_fields());
        branch_cols.values[1] = branch_slot.value;
        branch_cols.owners_hi[1] = branch_slot.owner_hi;
        branch_cols.owners_lo[1] = branch_slot.owner_lo;
        store
            .commit_block(
                &header,
                &hash,
                &undo,
                &[(0, 1, &branch_cols)],
                guard.buckets(),
                &[],
                None,
                &meta,
                false,
            )
            .unwrap();
        assert_eq!(store.get_utxos_by_owner(&owner_b.0).unwrap(), vec![(1, 77)]);

        let mut restored_cols = SegmentColumns::new_zero(2);
        let restored_slot =
            crate::fri_state::SlotValue::with_owner_fields(91, 1, owner_a.as_fields());
        restored_cols.values[1] = restored_slot.value;
        restored_cols.owners_hi[1] = restored_slot.owner_hi;
        restored_cols.owners_lo[1] = restored_slot.owner_lo;
        store
            .commit_block(
                &header,
                &hash,
                &undo,
                &[(0, 1, &restored_cols)],
                guard.buckets(),
                &[],
                None,
                &meta,
                true,
            )
            .unwrap();

        assert!(store.get_utxos_by_owner(&owner_b.0).unwrap().is_empty());
        assert_eq!(store.get_utxos_by_owner(&owner_a.0).unwrap(), vec![(1, 91)]);

        // The incremental path must also replace a live slot's index entry
        // when an incarnation-safe block eventually permits spend→remint at
        // the same physical slot.
        let replacement =
            crate::fri_state::SlotValue::with_owner_fields(93, 2, owner_b.as_fields());
        let mut replacement_cols = SegmentColumns::new_zero(2);
        replacement_cols.values[1] = replacement.value;
        replacement_cols.owners_hi[1] = replacement.owner_hi;
        replacement_cols.owners_lo[1] = replacement.owner_lo;
        let replacement_undo = BlockUndoLog {
            slot_changes: vec![(1, restored_slot)],
            ..undo.clone()
        };
        store
            .commit_block(
                &header,
                &hash,
                &replacement_undo,
                &[(0, 1, &replacement_cols)],
                guard.buckets(),
                &[],
                None,
                &meta,
                false,
            )
            .unwrap();
        assert!(store.get_utxos_by_owner(&owner_a.0).unwrap().is_empty());
        assert_eq!(store.get_utxos_by_owner(&owner_b.0).unwrap(), vec![(1, 93)]);
    }

    #[test]
    fn history_claim_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let store = MdbxStore::open(dir.path()).unwrap();
        let bytes = vec![1u8, 2, 3, 4, 5];

        assert_eq!(store.get_history_claim(7).unwrap(), None);
        store.put_history_claim(7, &bytes).unwrap();
        assert_eq!(store.get_history_claim(7).unwrap(), Some(bytes));
    }

    #[test]
    fn accepted_block_certificate_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let store = MdbxStore::open(dir.path()).unwrap();
        let bytes = b"certificate-record".to_vec();

        assert_eq!(store.get_accepted_block_certificate(7).unwrap(), None);
        store
            .put_accepted_block_certificate(7, &bytes)
            .expect("store certificate bytes");
        assert_eq!(
            store.get_accepted_block_certificate(7).unwrap(),
            Some(bytes)
        );
    }

    #[test]
    fn accepted_block_batch_certificate_package_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let store = MdbxStore::open(dir.path()).unwrap();
        let bytes = b"full-batch-checkpoint-package".to_vec();

        assert_eq!(
            store
                .get_accepted_block_batch_certificate_package(16)
                .unwrap(),
            None
        );
        store
            .put_accepted_block_batch_certificate_package(16, &bytes)
            .expect("store full batch package bytes");
        assert_eq!(
            store
                .get_accepted_block_batch_certificate_package(16)
                .unwrap(),
            Some(bytes)
        );
        assert_eq!(
            store
                .latest_accepted_block_batch_certificate_package_height()
                .unwrap(),
            Some(16)
        );
        store
            .put_accepted_block_batch_certificate_package(32, b"second")
            .expect("store second package");
        assert_eq!(
            store
                .latest_accepted_block_batch_certificate_package_height()
                .unwrap(),
            Some(32)
        );
        store
            .delete_accepted_block_batch_certificate_package(32)
            .expect("delete second package");
        assert_eq!(
            store
                .latest_accepted_block_batch_certificate_package_height()
                .unwrap(),
            Some(16)
        );
    }

    #[test]
    fn history_checkpoint_head_record_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let store = MdbxStore::open(dir.path()).unwrap();
        let bytes = b"recursive-head-record".to_vec();

        assert_eq!(store.get_history_checkpoint_head_record(16).unwrap(), None);
        store
            .put_history_checkpoint_head_record(16, &bytes)
            .expect("store recursive head record bytes");
        assert_eq!(
            store.get_history_checkpoint_head_record(16).unwrap(),
            Some(bytes)
        );
        assert_eq!(
            store.latest_history_checkpoint_head_height().unwrap(),
            Some(16)
        );
        store
            .put_history_checkpoint_head_record(32, b"second")
            .expect("store second recursive head record");
        assert_eq!(
            store.latest_history_checkpoint_head_height().unwrap(),
            Some(32)
        );
        store
            .delete_history_checkpoint_head_record(32)
            .expect("delete second recursive head record");
        assert_eq!(
            store.latest_history_checkpoint_head_height().unwrap(),
            Some(16)
        );
    }

    #[test]
    fn verified_headers_persist_header_chain_anchors() {
        let dir = tempfile::tempdir().unwrap();
        let h0 = crate::consensus::genesis::genesis_header();
        let h0_hash = crate::hash_block_header(&h0);
        let h0_work = [1u8; 32];

        {
            let store = MdbxStore::open(dir.path()).unwrap();
            store
                .put_verified_header_only(&h0, &h0_hash, &h0_work)
                .unwrap();
            let expected_h0 = compute_header_chain_anchor(std::iter::once(&h0), h0_work).unwrap();
            assert_eq!(store.get_header_anchor(0).unwrap(), Some(expected_h0));

            let h1 = BlockHeader {
                prev_block_hash: h0_hash,
                state_root: [2u8; 32],
                tx_root: [3u8; 32],
                timestamp: h0.timestamp + 15,
                height: 1,
                miner_address: h0.miner_address,
                nonce: 1,
                difficulty_target: h0.difficulty_target,
                log_slots: h0.log_slots,
                active_slot_count: 1,
                alloc_counter: 1,
            };
            let h1_hash = crate::hash_block_header(&h1);
            let h1_work = [2u8; 32];
            store
                .put_verified_header_only(&h1, &h1_hash, &h1_work)
                .unwrap();
            let expected_h1 = compute_header_chain_anchor([h0, h1].iter(), h1_work).unwrap();
            assert_eq!(store.get_header_anchor(1).unwrap(), Some(expected_h1));
        }

        let store = MdbxStore::open(dir.path()).unwrap();
        let anchor = store
            .get_header_anchor(1)
            .unwrap()
            .expect("header anchor survives reopen");
        assert_eq!(anchor.height, 1);
        assert_eq!(anchor.cumulative_chainwork, [2u8; 32]);
        assert_eq!(
            anchor.block_id,
            crate::hash_block_header(&store.get_header(1).unwrap().unwrap())
        );
    }
}
