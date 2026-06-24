// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! MDBX-backed persistent storage for the chain .
//!
//! `MdbxStore` owns the MDBX `Database` and provides methods for
//! all persistent chain data: headers, undo logs, segments, recent blocks,
//! and chain tip.
//!
//! The core operation is `commit_block` which writes all block-related
//! data in ONE atomic MDBX transaction (P.18 7-step protocol).

use std::path::Path;

use libmdbx::{Database, DatabaseOptions, Mode, NoWriteMap, TableFlags, WriteFlags};
use noid_poseidon2b::primitives::TxBodyHash;

use crate::block_header::BlockHeader;
use crate::consensus::da_prune::BlockUndoLog;
use crate::consensus::params::UNDO_RETENTION_DEPTH;
use crate::reuse_guard::{GuardBucket, REUSE_GUARD_BUCKETS};
use crate::segmented_state::SegmentColumns;
use crate::storage::meta::ConsensusMeta;
use crate::storage::serial::{
    decode_chain_tip, decode_chain_work, decode_consensus_meta, decode_header,
    decode_reuse_guard_buckets, decode_segment, decode_state_meta, decode_tx_index_value,
    decode_undo_log, encode_chain_tip, encode_chain_work, encode_consensus_meta, encode_header,
    encode_reuse_guard_buckets, encode_segment, encode_state_meta, encode_tx_index_value,
    encode_undo_log, u64_from_key, u64_key,
};

// ---------------------------------------------------------------------------
// Table names
// ---------------------------------------------------------------------------
const T_HEADERS: &str = "headers";
const T_HASH_TO_HEIGHT: &str = "h2h";
const T_CHAIN_TIP: &str = "tip";
const T_CONSENSUS_META: &str = "consensus_meta";
const T_CHAIN_WORK: &str = "chain_work";
const T_UNDO_LOGS: &str = "undo";
const T_SEGMENTS: &str = "segments";
const T_STATE_META: &str = "state_meta";
const T_REUSE_GUARD: &str = "reuse_guard";
const T_RECENT_BLOCKS: &str = "recent";
/// Recursive chain proof (~38 KB encoded, FOREVER). Key: KEY_REC. Value: raw proof bytes.
const T_RECURSIVE_PROOF: &str = "rec_proof";
/// Transaction index for receipt lookup. Key: TxBodyHash (32B). Value: (height, tx_pos) (12B).
const T_TX_INDEX: &str = "tx_index";
/// BlockProofs retained until finalized and covered by a real immutable checkpoint proof.
/// Key: height (u64 LE). Value: bincode BlockProof bytes.
const T_BLOCK_PROOFS: &str = "block_proofs";
/// Public AuthGKR sidecars retained with block bodies until checkpoint coverage.
/// Key: height (u64 LE).
const T_BLOCK_AUTH_SIDECARS: &str = "block_auth_sidecars";
/// Owner UTXO index. Key: owner[32]. Value: packed (slot:u32, value:u64)[] = 12 bytes each.
/// Maintained incrementally in commit_block. Used for O(1) wallet scan.
const T_OWNER_INDEX: &str = "owner_idx";
const N_TABLES: u64 = 15;

// Single-entry table keys
const KEY_TIP: &[u8] = &[0u8];
const KEY_META: &[u8] = &[0u8];
const KEY_REUSE_GUARD: &[u8] = &[0u8];
const KEY_CONSENSUS_META: &[u8] = &[0u8];
const KEY_REC: &[u8] = &[0u8];
const KEY_REC_HEIGHT: &[u8] = &[1u8];

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum StoreError {
    Mdbx(libmdbx::Error),
    Decode(&'static str),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Mdbx(e) => write!(f, "mdbx: {e}"),
            Self::Decode(ctx) => write!(f, "decode error: {ctx}"),
        }
    }
}

impl std::error::Error for StoreError {}

impl From<libmdbx::Error> for StoreError {
    fn from(e: libmdbx::Error) -> Self {
        Self::Mdbx(e)
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
            T_HASH_TO_HEIGHT,
            T_CHAIN_TIP,
            T_CONSENSUS_META,
            T_CHAIN_WORK,
            T_UNDO_LOGS,
            T_SEGMENTS,
            T_STATE_META,
            T_REUSE_GUARD,
            T_RECENT_BLOCKS,
            T_RECURSIVE_PROOF,
            T_TX_INDEX,
            T_BLOCK_PROOFS,
            T_BLOCK_AUTH_SIDECARS,
            T_OWNER_INDEX,
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
            Some(header) if crate::consensus::pow::full_block_hash(&header) == *hash => {
                Ok(Some(header))
            }
            _ => Ok(None),
        }
    }

    /// Persist a historical header and its hash index without changing chain tip,
    /// state metadata, undo logs, or recent blocks.
    ///
    /// FIX1: snapshot candidate headers must not be written into this canonical
    /// table before full acceptance; public snapshot sync is fail-closed.
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

    pub fn get_recent_block(&self, height: u64) -> Result<Option<Vec<u8>>, StoreError> {
        let txn = self.db.begin_ro_txn()?;
        let tbl = txn.open_table(Some(T_RECENT_BLOCKS))?;
        Ok(txn.get(&tbl, &u64_key(height))?)
    }

    /// Read the persisted recursive chain proof (~38 KB encoded), if present.
    pub fn get_recursive_proof(&self) -> Result<Option<Vec<u8>>, StoreError> {
        let txn = self.db.begin_ro_txn()?;
        let tbl = txn.open_table(Some(T_RECURSIVE_PROOF))?;
        Ok(txn.get(&tbl, KEY_REC)?)
    }

    /// Read the height of the persisted recursive chain proof, if known.
    pub fn get_recursive_proof_height(&self) -> Result<Option<u64>, StoreError> {
        let txn = self.db.begin_ro_txn()?;
        let tbl = txn.open_table(Some(T_RECURSIVE_PROOF))?;
        let raw: Option<Vec<u8>> = txn.get(&tbl, KEY_REC_HEIGHT)?;
        Ok(raw.and_then(|b| u64_from_key(&b)))
    }

    /// Persist the recursive chain proof (~38 KB encoded, FOREVER, single entry).
    ///
    /// Prefer `put_recursive_proof_at` in node code so proof-byte pruning can
    /// retain finalized block proofs until recursive history has consumed them.
    pub fn put_recursive_proof(&self, bytes: &[u8]) -> Result<(), StoreError> {
        let txn = self.db.begin_rw_txn()?;
        let tbl = txn.open_table(Some(T_RECURSIVE_PROOF))?;
        txn.put(&tbl, KEY_REC, bytes, WriteFlags::empty())?;
        txn.commit()?;
        Ok(())
    }

    /// Persist the recursive chain proof and its block height atomically.
    pub fn put_recursive_proof_at(&self, height: u64, bytes: &[u8]) -> Result<(), StoreError> {
        let txn = self.db.begin_rw_txn()?;
        let tbl = txn.open_table(Some(T_RECURSIVE_PROOF))?;
        txn.put(&tbl, KEY_REC, bytes, WriteFlags::empty())?;
        txn.put(&tbl, KEY_REC_HEIGHT, u64_key(height), WriteFlags::empty())?;
        txn.commit()?;
        Ok(())
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
                if v.0 == 0 {
                    continue; // empty slot
                }
                let oh = cols.owners_hi[local];
                let ol = cols.owners_lo[local];
                let owner_key = owner_key_from_fields(oh, ol);
                let slot = ((seg_id as u32) << eff_log) | (local as u32);
                let value = v.0 as u64;
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
    ///   - Prune old undo_logs beyond UNDO_RETENTION_DEPTH
    ///   - Keep block bodies, BlockProofs, and Auth sidecars until a real
    ///     immutable checkpoint proof covers them.
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

        // --- 9. Owner index: update live-UTXO index incrementally ---
        // Uses undo_log (which records pre-block slot values) and dirty_segments
        // (which hold post-block slot values) to determine what changed.
        {
            use crate::fri_state::SlotValue;
            let oidx_tbl = txn.open_table(Some(T_OWNER_INDEX))?;
            // eff_log = log2(slots_per_segment) — same for every dirty segment.
            let eff_log: u32 = dirty_segments
                .first()
                .map(|(_, e, _)| *e as u32)
                .unwrap_or(crate::consensus::params::LOG_SEGMENT_SIZE);

            for &(slot_index, ref prev_value) in &undo_log.slot_changes {
                if *prev_value == SlotValue::EMPTY {
                    // ----------------------------------------------------------
                    // This slot was EMPTY before → a new UTXO was minted here.
                    // Find its new value in the dirty segments.
                    // ----------------------------------------------------------
                    let seg_id = (slot_index >> eff_log) as u16;
                    let local = (slot_index & ((1u32 << eff_log) - 1)) as usize;

                    let new_val = dirty_segments
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
                        });

                    if let Some((v, oh, ol)) = new_val {
                        if v.0 != 0 {
                            let owner_key = owner_key_from_fields(oh, ol);
                            let value = v.0 as u64;
                            // Append (slot, value) to this owner's list.
                            let existing: Option<Vec<u8>> =
                                txn.get(&oidx_tbl, owner_key.as_slice())?;
                            let mut entries = existing
                                .as_deref()
                                .map(decode_owner_entries)
                                .unwrap_or_default();
                            entries.push((slot_index, value));
                            txn.put(
                                &oidx_tbl,
                                owner_key.as_slice(),
                                encode_owner_entries(&entries),
                                WriteFlags::empty(),
                            )?;
                        }
                    }
                } else {
                    // ----------------------------------------------------------
                    // This slot was LIVE before → a UTXO was spent (now EMPTY).
                    // Remove slot_index from the old owner's list.
                    // ----------------------------------------------------------
                    let owner_key = owner_key_from_fields(prev_value.owner_hi, prev_value.owner_lo);
                    let existing: Option<Vec<u8>> = txn.get(&oidx_tbl, owner_key.as_slice())?;
                    if let Some(raw) = existing {
                        let entries: Vec<(u32, u64)> = decode_owner_entries(&raw)
                            .into_iter()
                            .filter(|(s, _)| *s != slot_index)
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

        // --- Prune undo_logs older than UNDO_RETENTION_DEPTH ---
        if current_height > UNDO_RETENTION_DEPTH {
            let undo_tbl = txn.open_table(Some(T_UNDO_LOGS))?;
            let cutoff = current_height - UNDO_RETENTION_DEPTH;
            // Collect keys first (cursor must be dropped before del).
            let keys_to_del: Vec<u64> = {
                let mut cur = txn.cursor(&undo_tbl)?;
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
            for h in keys_to_del {
                txn.del(&undo_tbl, u64_key(h), None)?;
            }
        }

        // Block bodies, BlockProofs, and Auth sidecars are checkpoint inputs.
        // They are pruned only after a future immutable checkpoint package covers
        // the exact heights being removed. No such coverage table exists in this
        // implementation yet, so pruning these tables is intentionally disabled.
        txn.commit()?;
        Ok(())
    }

    /// Clear volatile tables after local state corruption is detected, keeping
    /// append-only headers, hash->height index, and the recursive proof.
    ///
    /// Normal startup does NOT clear these tables: `MdbxChainContext::open_or_create`
    /// first tries to restore persisted current state from MDBX and checks it against
    /// the tip header's `state_root`. This function is the recovery fallback for corrupt
    /// local state; after clearing, the node resyncs current state from peers and verifies
    /// it with the recursive chain proof.
    pub fn clear_for_restart(&self) -> Result<(), StoreError> {
        let txn = self.db.begin_rw_txn()?;
        let volatile = [
            T_SEGMENTS,
            T_RECENT_BLOCKS,
            T_UNDO_LOGS,
            T_BLOCK_PROOFS,
            T_BLOCK_AUTH_SIDECARS,
            T_OWNER_INDEX,
            T_STATE_META,
            T_CHAIN_TIP,
            T_CONSENSUS_META,
            T_CHAIN_WORK,
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

    fn get_recursive_proof(&self) -> Result<Option<Vec<u8>>, StoreError> {
        MdbxStore::get_recursive_proof(self)
    }

    fn put_recursive_proof(&self, bytes: &[u8]) -> Result<(), StoreError> {
        MdbxStore::put_recursive_proof(self, bytes)
    }

    fn get_tx_index(&self, hash: &[u8; 32]) -> Result<Option<(u64, u32)>, StoreError> {
        MdbxStore::get_tx_index(self, hash)
    }
}
