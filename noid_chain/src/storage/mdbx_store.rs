// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! MDBX-backed persistent storage for the chain (Phase 2).
//!
//! `MdbxStore` owns the MDBX `Database` and provides methods for
//! all persistent chain data: headers, nullifiers, undo logs, segments,
//! recent blocks, and chain tip.
//!
//! The core operation is `commit_block` which writes all block-related
//! data in ONE atomic MDBX transaction (P.18 7-step protocol).

use std::path::Path;

use libmdbx::{Database, DatabaseOptions, Mode, NoWriteMap, TableFlags, WriteFlags};
use noid_poseidon2b::primitives::TxBodyHash;

use crate::block_header::BlockHeader;
use crate::consensus::da_prune::BlockUndoLog;
use crate::consensus::params::{ANCHOR_DEPTH, FINALITY_DEPTH, RECENT_BLOCK_RETENTION};
use crate::segmented_state::SegmentColumns;
use crate::storage::serial::{
    decode_chain_tip, decode_header, decode_segment, decode_state_meta, decode_tx_index_value,
    decode_undo_log, encode_chain_tip, encode_header, encode_segment, encode_state_meta,
    encode_tx_index_value, encode_undo_log, u64_from_key, u64_key,
};

// ---------------------------------------------------------------------------
// Table names
// ---------------------------------------------------------------------------
const T_HEADERS: &str = "headers";
const T_HASH_TO_HEIGHT: &str = "h2h";
const T_CHAIN_TIP: &str = "tip";
const T_NULLIFIERS: &str = "nullifiers";
const T_NULLIFIER_BLOCKS: &str = "nul_blk";
const T_UNDO_LOGS: &str = "undo";
const T_SEGMENTS: &str = "segments";
const T_STATE_META: &str = "state_meta";
const T_RECENT_BLOCKS: &str = "recent";
/// Recursive chain proof (6.5 KB, FOREVER). Key: KEY_REC. Value: raw proof bytes.
const T_RECURSIVE_PROOF: &str = "rec_proof";
/// Transaction index for receipt lookup. Key: TxBodyHash (32B). Value: (height, tx_pos) (12B).
const T_TX_INDEX: &str = "tx_index";
const N_TABLES: u64 = 11;

// Single-entry table keys
const KEY_TIP: &[u8] = &[0u8];
const KEY_META: &[u8] = &[0u8];
const KEY_REC: &[u8] = &[0u8];

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
        //                        + headers + nullifiers + undo logs + margin
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
            T_NULLIFIERS,
            T_NULLIFIER_BLOCKS,
            T_UNDO_LOGS,
            T_SEGMENTS,
            T_STATE_META,
            T_RECENT_BLOCKS,
            T_RECURSIVE_PROOF,
            T_TX_INDEX,
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

    pub fn get_state_meta(&self) -> Result<Option<(u32, u64, u64)>, StoreError> {
        let txn = self.db.begin_ro_txn()?;
        let tbl = txn.open_table(Some(T_STATE_META))?;
        let raw: Option<Vec<u8>> = txn.get(&tbl, KEY_META)?;
        Ok(raw.and_then(|b| decode_state_meta(&b)))
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
        self.get_header(height)
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

    /// Read nullifier hashes for blocks in `[from_height, to_height]`, oldest first.
    ///
    /// Used on startup to rebuild the RAM `NullifierSet` from durable storage.
    pub fn get_nullifier_blocks_range(
        &self,
        from_height: u64,
        to_height: u64,
    ) -> Result<Vec<(u64, Vec<TxBodyHash>)>, StoreError> {
        let txn = self.db.begin_ro_txn()?;
        let tbl = txn.open_table(Some(T_NULLIFIER_BLOCKS))?;
        let mut result = Vec::new();
        for h in from_height..=to_height {
            let raw: Option<Vec<u8>> = txn.get(&tbl, &u64_key(h))?;
            if let Some(bytes) = raw {
                let hashes: Vec<TxBodyHash> = bytes
                    .chunks_exact(32)
                    .map(|chunk| TxBodyHash(chunk.try_into().expect("chunk is 32 bytes")))
                    .collect();
                result.push((h, hashes));
            }
        }
        Ok(result)
    }

    /// Read the persisted recursive chain proof (6.5 KB), if present.
    pub fn get_recursive_proof(&self) -> Result<Option<Vec<u8>>, StoreError> {
        let txn = self.db.begin_ro_txn()?;
        let tbl = txn.open_table(Some(T_RECURSIVE_PROOF))?;
        Ok(txn.get(&tbl, KEY_REC)?)
    }

    /// Persist the recursive chain proof (6.5 KB, FOREVER, single entry).
    pub fn put_recursive_proof(&self, bytes: &[u8]) -> Result<(), StoreError> {
        let txn = self.db.begin_rw_txn()?;
        let tbl = txn.open_table(Some(T_RECURSIVE_PROOF))?;
        txn.put(&tbl, KEY_REC, bytes, WriteFlags::empty())?;
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
    /// 4. Write chain_tip
    /// 5. Write state_meta (log_slots, active_slot_count, alloc_counter)
    /// 6. Write BlockUndoLog
    /// 7. Write nullifier hashes for this block; write recent_block bytes
    ///
    /// After commit (non-atomic, re-runnable):
    ///   - Prune old undo_logs beyond FINALITY_DEPTH
    ///   - Prune old recent_blocks beyond RECENT_BLOCK_RETENTION
    ///   - Prune old nullifier entries beyond ANCHOR_DEPTH
    pub fn commit_block(
        &self,
        header: &BlockHeader,
        hash: &[u8; 32],
        undo_log: &BlockUndoLog,
        dirty_segments: &[(u16, u8, &SegmentColumns)], // (seg_id, effective_log_seg, cols)
        nullifier_hashes: &[TxBodyHash],
        block_bytes: Option<&[u8]>, // None = don't store (DA already pruned)
    ) -> Result<(), StoreError> {
        let txn = self.db.begin_rw_txn()?;

        // --- 1. Dirty segments ---
        let seg_tbl = txn.open_table(Some(T_SEGMENTS))?;
        for (seg_id, eff_log, cols) in dirty_segments {
            let key = seg_id.to_le_bytes();
            let val = encode_segment(cols, *eff_log);
            txn.put(&seg_tbl, &key, &val, WriteFlags::empty())?;
        }

        // --- 2. BlockHeader ---
        let hdr_tbl = txn.open_table(Some(T_HEADERS))?;
        txn.put(
            &hdr_tbl,
            &u64_key(header.height),
            &encode_header(header),
            WriteFlags::empty(),
        )?;

        // --- 3. hash → height ---
        let h2h_tbl = txn.open_table(Some(T_HASH_TO_HEIGHT))?;
        txn.put(
            &h2h_tbl,
            hash.as_slice(),
            &u64_key(header.height),
            WriteFlags::empty(),
        )?;

        // --- 4. chain_tip ---
        let tip_tbl = txn.open_table(Some(T_CHAIN_TIP))?;
        txn.put(
            &tip_tbl,
            KEY_TIP,
            &encode_chain_tip(header.height, hash),
            WriteFlags::empty(),
        )?;

        // --- 5. state_meta ---
        let meta_tbl = txn.open_table(Some(T_STATE_META))?;
        txn.put(
            &meta_tbl,
            KEY_META,
            &encode_state_meta(
                header.log_slots,
                header.active_slot_count,
                header.alloc_counter,
            ),
            WriteFlags::empty(),
        )?;

        // --- 6. BlockUndoLog ---
        let undo_tbl = txn.open_table(Some(T_UNDO_LOGS))?;
        txn.put(
            &undo_tbl,
            &u64_key(header.height),
            &encode_undo_log(undo_log),
            WriteFlags::empty(),
        )?;

        // --- 7. Nullifiers + recent block ---
        let nul_tbl = txn.open_table(Some(T_NULLIFIERS))?;
        let nul_blk_tbl = txn.open_table(Some(T_NULLIFIER_BLOCKS))?;
        // Store each tx nullifier mapped to this block's height.
        for h in nullifier_hashes {
            txn.put(&nul_tbl, &h.0, &u64_key(header.height), WriteFlags::empty())?;
        }
        // Store the block's full hash list (32 bytes × n) for bulk pruning later.
        // Only write an entry when there are actual nullifiers to avoid polluting
        // T_NULLIFIER_BLOCKS with empty entries for coinbase-only / empty blocks.
        if !nullifier_hashes.is_empty() {
            let hash_bytes: Vec<u8> = nullifier_hashes.iter().flat_map(|h| h.0).collect();
            txn.put(
                &nul_blk_tbl,
                &u64_key(header.height),
                &hash_bytes,
                WriteFlags::empty(),
            )?;
        }

        let recent_tbl = txn.open_table(Some(T_RECENT_BLOCKS))?;
        if let Some(bytes) = block_bytes {
            txn.put(
                &recent_tbl,
                &u64_key(header.height),
                bytes,
                WriteFlags::empty(),
            )?;
        }

        // --- 7.5. tx_index: TxBodyHash → (height, position_in_block) ---
        // Enables O(1) receipt lookup: given a tx_body_hash, find the block
        // and position to reconstruct the Merkle inclusion path.
        let tx_idx_tbl = txn.open_table(Some(T_TX_INDEX))?;
        for (pos, h) in nullifier_hashes.iter().enumerate() {
            txn.put(
                &tx_idx_tbl,
                &h.0,
                &encode_tx_index_value(header.height, pos as u32),
                WriteFlags::empty(),
            )?;
        }

        // Commit atomically — all seven steps or none.
        txn.commit()?;

        // Post-commit pruning is non-atomic and non-critical.
        // A prune failure leaves stale entries (undo logs, recent blocks, old
        // nullifiers) until the next commit, but the chain state is already
        // fully consistent after the commit above.  We must NOT propagate the
        // error here: doing so would cause `apply_next_block` to return Err
        // after the block is already durably in MDBX, leaving RAM and MDBX
        // desynchronised until the next restart.
        if let Err(_e) = self.prune_after_commit(header.height) {
            // TODO Phase 3: tracing::warn!("prune_after_commit failed: {_e}");
            // Safe to ignore: prune is retried on the next commit.
        }

        Ok(())
    }

    fn prune_after_commit(&self, current_height: u64) -> Result<(), StoreError> {
        let txn = self.db.begin_rw_txn()?;

        // --- Prune undo_logs older than FINALITY_DEPTH ---
        if current_height > FINALITY_DEPTH {
            let undo_tbl = txn.open_table(Some(T_UNDO_LOGS))?;
            let cutoff = current_height - FINALITY_DEPTH;
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
                txn.del(&undo_tbl, &u64_key(h), None)?;
            }
        }

        // --- Prune recent_blocks older than RECENT_BLOCK_RETENTION ---
        if current_height > RECENT_BLOCK_RETENTION {
            let recent_tbl = txn.open_table(Some(T_RECENT_BLOCKS))?;
            let cutoff = current_height - RECENT_BLOCK_RETENTION;
            let keys_to_del: Vec<u64> = {
                let mut cur = txn.cursor(&recent_tbl)?;
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
                txn.del(&recent_tbl, &u64_key(h), None)?;
            }
        }

        // --- Prune nullifiers older than ANCHOR_DEPTH ---
        if current_height > ANCHOR_DEPTH {
            let nul_tbl = txn.open_table(Some(T_NULLIFIERS))?;
            let nul_blk_tbl = txn.open_table(Some(T_NULLIFIER_BLOCKS))?;
            let cutoff = current_height - ANCHOR_DEPTH;
            // Gather block heights that are beyond the anchor window.
            let heights: Vec<u64> = {
                let mut cur = txn.cursor(&nul_blk_tbl)?;
                let mut hs = Vec::new();
                let mut item: Option<(Vec<u8>, Vec<u8>)> = cur.first()?;
                while let Some((k, _)) = item {
                    match u64_from_key(&k) {
                        Some(h) if h <= cutoff => hs.push(h),
                        _ => break,
                    }
                    item = cur.next()?;
                }
                hs
            };
            for h in heights {
                // Retrieve the packed hash list and delete each nullifier entry.
                // Use `let _ =` on T_NULLIFIERS deletes: a partial-prune crash
                // could have already removed some entries, and
                // "key not found" must not abort the recovery run.
                let hash_bytes: Option<Vec<u8>> = txn.get(&nul_blk_tbl, &u64_key(h))?;
                if let Some(hashes) = hash_bytes {
                    for chunk in hashes.chunks_exact(32) {
                        // Idempotent: ignore not-found (already pruned).
                        let _ = txn.del(&nul_tbl, chunk, None);
                    }
                }
                txn.del(&nul_blk_tbl, &u64_key(h), None)?;
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
