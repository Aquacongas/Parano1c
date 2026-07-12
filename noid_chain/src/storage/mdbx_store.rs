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

use std::{path::Path, sync::Arc};

use libmdbx::{Database, DatabaseOptions, Mode, NoWriteMap, ObjectLength, TableFlags, WriteFlags};
use noid_poseidon2b::primitives::TxBodyHash;
use noid_tx::unpack_amount_creation_id;

use crate::block_header::BlockHeader;
use crate::checkpoint::{CheckpointCoverage, ImmutableCheckpointPackage};
use crate::consensus::da_prune::BlockUndoLog;
use crate::consensus::params::{RECENT_BLOCK_RETENTION_DEPTH, UNDO_RETENTION_DEPTH};
use crate::exact_state_hash::slot_leaf_hash;
use crate::fri_state::{compute_segment_root, SlotValue};
use crate::header_anchor::{
    compute_header_chain_anchor, extend_header_chain_anchor, HeaderChainAnchor,
    HeaderChainAnchorError,
};
use crate::segmented_state::SegmentColumns;
use crate::state::{exact_segment_root_from_columns, ChainState, StreamingSparseRoot};
use crate::storage::meta::ConsensusMeta;
use crate::storage::serial::{
    decode_chain_tip, decode_chain_work, decode_checkpoint_coverage, decode_checkpoint_package,
    decode_consensus_meta, decode_header, decode_header_chain_anchor, decode_segment,
    decode_state_meta, decode_tx_index_value, decode_undo_log, encode_chain_tip, encode_chain_work,
    encode_checkpoint_coverage, encode_checkpoint_package, encode_consensus_meta, encode_header,
    encode_header_chain_anchor, encode_segment, encode_state_meta, encode_tx_index_value,
    encode_undo_log, u64_from_key, u64_key,
};
use crate::storage::snapshot_staging::{FinalizedSnapshotStaging, SnapshotStagingError};

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
/// Owner UTXO index. Key: `owner[32] || slot_be[4]`. Value:
/// `packed_value_le[16]`. `packed_value` contains both the amount and the
/// allocation-counter creation id, so an index lookup can be checked exactly
/// against the durable state segment before it is exposed.  One MDBX record
/// per live slot avoids ever materializing one owner's complete UTXO set while
/// updating or rebuilding the index. Maintained incrementally in
/// `commit_block`.
const T_OWNER_INDEX: &str = "owner_idx";
/// Immutable checkpoint package. Key: checkpoint height (u64 LE).
const T_CHECKPOINT_PACKAGES: &str = "checkpoint_packages";
/// Latest local checkpoint package coverage metadata. Key: KEY_CHECKPOINT_COVERAGE.
const T_CHECKPOINT_COVERAGE: &str = "checkpoint_coverage";
/// Crash-resumable selected recursive proof work queue. Key: canonical height
/// as u64 big-endian; value: fixed-width [`RecursiveProofJob`] metadata.
const T_RECURSIVE_PROOF_JOBS: &str = "recursive_proof_jobs";
/// Opaque bounded selected recursive proof result, keyed by the same numeric
/// big-endian height and hash-bound independently from the job record.
const T_RECURSIVE_PROOF_RESULTS: &str = "recursive_proof_results";
const N_TABLES: u64 = 32;

// Single-entry table keys
const KEY_TIP: &[u8] = &[0u8];
const KEY_META: &[u8] = &[0u8];
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
    SnapshotStaging(SnapshotStagingError),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Mdbx(e) => write!(f, "mdbx: {e}"),
            Self::Decode(ctx) => write!(f, "decode error: {ctx}"),
            Self::HeaderAnchor(e) => write!(f, "header anchor: {e}"),
            Self::SnapshotStaging(e) => write!(f, "snapshot staging: {e}"),
        }
    }
}

impl std::error::Error for StoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Mdbx(error) => Some(error),
            Self::HeaderAnchor(error) => Some(error),
            Self::SnapshotStaging(error) => Some(error),
            Self::Decode(_) => None,
        }
    }
}

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

impl From<SnapshotStagingError> for StoreError {
    fn from(e: SnapshotStagingError) -> Self {
        Self::SnapshotStaging(e)
    }
}

// ---------------------------------------------------------------------------
// MdbxStore
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct MdbxStore {
    db: Arc<Database<NoWriteMap>>,
}

// ---------------------------------------------------------------------------
// Owner index helpers
// ---------------------------------------------------------------------------

const OWNER_INDEX_KEY_BYTES: usize = 32 + 4;
const OWNER_INDEX_VALUE_BYTES: usize = 16;

/// One owner-index entry after exact verification against the durable state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedOwnerUtxo {
    pub slot_index: u32,
    pub amount: u64,
    pub creation_id: u64,
}

/// Exact owner view tied to one atomic durable chain snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedOwnerSnapshot {
    /// Owner key whose complete derived index entry was queried.
    pub owner: [u8; 32],
    pub height: u64,
    pub tip_hash: [u8; 32],
    pub state_root: [u8; 32],
    pub log_slots: u32,
    pub active_slot_count: u64,
    pub alloc_counter: u64,
    pub utxos: Vec<VerifiedOwnerUtxo>,
}

/// Detached proof material committed atomically with one accepted block.
///
/// The byte payloads remain owned by the block/recursive crates so the chain
/// store does not depend on their proof types.  An empty proof/sidecar pair is
/// canonical for a coinbase-only block and deletes any stale same-height
/// payload left by a reverted branch.  History and certificate bytes are
/// mandatory for every accepted non-genesis block.
#[derive(Debug, Clone, Copy)]
pub struct AcceptedBlockCommitData<'a> {
    pub block_proof_bytes: &'a [u8],
    pub block_auth_sidecar_bytes: &'a [u8],
    pub history_claim_bytes: &'a [u8],
    pub accepted_block_certificate_bytes: &'a [u8],
}

/// Owned per-block material accumulated while a replacement branch is fully
/// validated in RAM.  `commit_reorg` writes the entire vector together with
/// the final exact state in one MDBX transaction.
#[derive(Debug, Clone)]
pub(crate) struct StagedAcceptedBlockCommit {
    pub header: BlockHeader,
    pub hash: [u8; 32],
    pub cumulative_chainwork: [u8; 32],
    pub undo_log: BlockUndoLog,
    pub history_claim_bytes: Vec<u8>,
    pub accepted_block_certificate_bytes: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Selected recursive proof-job journal
// ---------------------------------------------------------------------------

const RECURSIVE_PROOF_JOB_MAGIC: [u8; 4] = *b"RPJ1";
const RECURSIVE_PROOF_JOB_ENCODED_BYTES: usize = 44;
const RECURSIVE_PROOF_RESULT_MAGIC: [u8; 4] = *b"RPR1";
const RECURSIVE_PROOF_RESULT_HEADER_BYTES: usize = 40;

/// Hard storage cap for one opaque selected recursive proof result.
///
/// The chain store does not decode recursive proofs, but it must bound every
/// allocation before accepting bytes from a worker. Four MiB leaves margin
/// above the measured selected envelopes while preventing a worker from using
/// the durable queue as an unbounded blob store.
pub const MAX_RECURSIVE_PROOF_JOB_RESULT_BYTES: usize = 4 * 1024 * 1024;

/// The only selected recursive block-class tiers. This storage type remains
/// independent of `noid_recursive`; workers map it to their own class type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RecursiveProofJobTier {
    B8 = 0,
    B32 = 1,
    B64 = 2,
    B255 = 3,
}

impl RecursiveProofJobTier {
    pub fn for_user_transaction_count(count: usize) -> Option<Self> {
        match crate::consensus::params::user_tx_class_tier(count)? {
            8 => Some(Self::B8),
            32 => Some(Self::B32),
            64 => Some(Self::B64),
            255 => Some(Self::B255),
            _ => None,
        }
    }

    pub const fn capacity(self) -> usize {
        match self {
            Self::B8 => 8,
            Self::B32 => 32,
            Self::B64 => 64,
            Self::B255 => 255,
        }
    }

    fn decode(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(Self::B8),
            1 => Some(Self::B32),
            2 => Some(Self::B64),
            3 => Some(Self::B255),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RecursiveProofJobState {
    Pending = 0,
    Running = 1,
    Complete = 2,
}

impl RecursiveProofJobState {
    fn decode(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(Self::Pending),
            1 => Some(Self::Running),
            2 => Some(Self::Complete),
            _ => None,
        }
    }
}

/// Fixed-width crash-resumable metadata for one canonical block height.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecursiveProofJob {
    pub height: u64,
    pub block_hash: [u8; 32],
    pub tier: RecursiveProofJobTier,
    pub state: RecursiveProofJobState,
    /// Number of successful Pending -> Running claims across restarts.
    pub attempt_counter: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecursiveProofJobResult {
    pub height: u64,
    pub block_hash: [u8; 32],
    pub bytes: Vec<u8>,
}

#[inline]
fn recursive_proof_height_key(height: u64) -> [u8; 8] {
    height.to_be_bytes()
}

#[inline]
fn recursive_proof_height_from_key(key: &[u8]) -> Option<u64> {
    Some(u64::from_be_bytes(key.try_into().ok()?))
}

fn encode_recursive_proof_job(job: &RecursiveProofJob) -> [u8; RECURSIVE_PROOF_JOB_ENCODED_BYTES] {
    let mut encoded = [0u8; RECURSIVE_PROOF_JOB_ENCODED_BYTES];
    encoded[..4].copy_from_slice(&RECURSIVE_PROOF_JOB_MAGIC);
    encoded[4] = job.tier as u8;
    encoded[5] = job.state as u8;
    // bytes 6..8 are reserved and must remain zero.
    encoded[8..12].copy_from_slice(&job.attempt_counter.to_le_bytes());
    encoded[12..44].copy_from_slice(&job.block_hash);
    encoded
}

fn decode_recursive_proof_job(height: u64, bytes: &[u8]) -> Option<RecursiveProofJob> {
    if bytes.len() != RECURSIVE_PROOF_JOB_ENCODED_BYTES
        || bytes[..4] != RECURSIVE_PROOF_JOB_MAGIC
        || bytes[6..8] != [0u8; 2]
    {
        return None;
    }
    Some(RecursiveProofJob {
        height,
        tier: RecursiveProofJobTier::decode(bytes[4])?,
        state: RecursiveProofJobState::decode(bytes[5])?,
        attempt_counter: u32::from_le_bytes(bytes[8..12].try_into().ok()?),
        block_hash: bytes[12..44].try_into().ok()?,
    })
}

fn encode_recursive_proof_result(
    block_hash: [u8; 32],
    result: &[u8],
) -> Result<Vec<u8>, StoreError> {
    if result.len() > MAX_RECURSIVE_PROOF_JOB_RESULT_BYTES {
        return Err(StoreError::Decode(
            "recursive proof result exceeds hard byte cap",
        ));
    }
    let result_len = u32::try_from(result.len())
        .map_err(|_| StoreError::Decode("recursive proof result length exceeds u32"))?;
    let mut encoded = Vec::with_capacity(RECURSIVE_PROOF_RESULT_HEADER_BYTES + result.len());
    encoded.extend_from_slice(&RECURSIVE_PROOF_RESULT_MAGIC);
    encoded.extend_from_slice(&block_hash);
    encoded.extend_from_slice(&result_len.to_le_bytes());
    encoded.extend_from_slice(result);
    Ok(encoded)
}

fn decode_recursive_proof_result(
    height: u64,
    mut encoded: Vec<u8>,
) -> Option<RecursiveProofJobResult> {
    if encoded.len() < RECURSIVE_PROOF_RESULT_HEADER_BYTES
        || encoded.len()
            > RECURSIVE_PROOF_RESULT_HEADER_BYTES
                .checked_add(MAX_RECURSIVE_PROOF_JOB_RESULT_BYTES)?
        || encoded[..4] != RECURSIVE_PROOF_RESULT_MAGIC
    {
        return None;
    }
    let block_hash: [u8; 32] = encoded[4..36].try_into().ok()?;
    let declared = u32::from_le_bytes(encoded[36..40].try_into().ok()?) as usize;
    if declared > MAX_RECURSIVE_PROOF_JOB_RESULT_BYTES
        || encoded.len() != RECURSIVE_PROOF_RESULT_HEADER_BYTES.checked_add(declared)?
    {
        return None;
    }
    encoded.copy_within(RECURSIVE_PROOF_RESULT_HEADER_BYTES.., 0);
    encoded.truncate(declared);
    Some(RecursiveProofJobResult {
        height,
        block_hash,
        bytes: encoded,
    })
}

#[inline]
fn canonical_hash_from_encoded_header(bytes: &[u8]) -> Option<[u8; 32]> {
    decode_header(bytes).map(|header| crate::block_header::block_id(&header))
}

/// Extract the 32-byte owner key from a slot's owner fields.
#[inline]
fn owner_key_from_fields(owner_hi: noid_core::Block128, owner_lo: noid_core::Block128) -> [u8; 32] {
    let mut key = [0u8; 32];
    key[..16].copy_from_slice(&owner_hi.0.to_le_bytes());
    key[16..].copy_from_slice(&owner_lo.0.to_le_bytes());
    key
}

#[inline]
fn owner_index_key(owner: &[u8; 32], slot_index: u32) -> [u8; OWNER_INDEX_KEY_BYTES] {
    let mut key = [0u8; OWNER_INDEX_KEY_BYTES];
    key[..32].copy_from_slice(owner);
    // Big endian is consensus-adjacent storage canonicalization: MDBX prefix
    // iteration is then also strictly increasing by physical slot.
    key[32..].copy_from_slice(&slot_index.to_be_bytes());
    key
}

/// Decode the only accepted pre-launch owner-index key format. There is no
/// aggregate `owner -> Vec<entry>` legacy decoder.
#[inline]
fn decode_owner_index_key(bytes: &[u8]) -> Result<([u8; 32], u32), StoreError> {
    if bytes.len() != OWNER_INDEX_KEY_BYTES {
        return Err(StoreError::Decode("invalid owner-index key length"));
    }
    let mut owner = [0u8; 32];
    owner.copy_from_slice(&bytes[..32]);
    let slot_index = u32::from_be_bytes(bytes[32..].try_into().unwrap());
    Ok((owner, slot_index))
}

#[inline]
fn encode_owner_index_value(packed_value: u128) -> [u8; OWNER_INDEX_VALUE_BYTES] {
    packed_value.to_le_bytes()
}

#[inline]
fn decode_owner_index_value(bytes: &[u8]) -> Result<u128, StoreError> {
    if bytes.len() != OWNER_INDEX_VALUE_BYTES {
        return Err(StoreError::Decode("invalid owner-index value length"));
    }
    Ok(u128::from_le_bytes(bytes.try_into().unwrap()))
}

fn sort_unique_segment_ids(mut segment_ids: Vec<u16>) -> Result<Vec<u16>, StoreError> {
    segment_ids.sort_unstable();
    if segment_ids.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(StoreError::Decode("duplicate stored segment key"));
    }
    Ok(segment_ids)
}

#[inline]
fn segment_columns_empty(cols: &SegmentColumns) -> bool {
    cols.values.iter().all(|v| v.0 == 0)
        && cols.owners_hi.iter().all(|v| v.0 == 0)
        && cols.owners_lo.iter().all(|v| v.0 == 0)
}

/// Stream every live owner-index record in one segment without building an
/// owner map or a segment-sized side vector.
fn visit_live_owner_records(
    segment_id: u16,
    effective_log: u8,
    columns: &SegmentColumns,
    mut visitor: impl FnMut([u8; 32], u32, u128) -> Result<(), StoreError>,
) -> Result<(), StoreError> {
    if columns.values.len() != columns.owners_hi.len()
        || columns.values.len() != columns.owners_lo.len()
    {
        return Err(StoreError::Decode("owner-index segment columns disagree"));
    }
    let segment_capacity = 1usize
        .checked_shl(u32::from(effective_log))
        .ok_or(StoreError::Decode("owner-index segment log is invalid"))?;
    if columns.values.len() > segment_capacity {
        return Err(StoreError::Decode(
            "owner-index segment exceeds effective domain",
        ));
    }
    let segment_base = u64::from(segment_id)
        .checked_shl(u32::from(effective_log))
        .ok_or(StoreError::Decode("owner-index segment base overflow"))?;
    for local in 0..columns.values.len() {
        let value = columns.values[local];
        let owner_hi = columns.owners_hi[local];
        let owner_lo = columns.owners_lo[local];
        if value.0 == 0 && owner_hi.0 == 0 && owner_lo.0 == 0 {
            continue;
        }
        let slot_index = segment_base
            .checked_add(local as u64)
            .and_then(|slot| u32::try_from(slot).ok())
            .ok_or(StoreError::Decode("owner-index slot exceeds u32 domain"))?;
        visitor(
            owner_key_from_fields(owner_hi, owner_lo),
            slot_index,
            value.0,
        )?;
    }
    Ok(())
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
            T_RECURSIVE_PROOF_JOBS,
            T_RECURSIVE_PROOF_RESULTS,
        ] {
            txn.create_table(Some(name), TableFlags::empty())?;
        }
        txn.commit()?;
        let store = Self { db: Arc::new(db) };
        store.reset_running_recursive_proof_jobs()?;
        Ok(store)
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

    // -----------------------------------------------------------------------
    // Crash-resumable selected recursive proof jobs
    // -----------------------------------------------------------------------

    /// Atomically enqueue one canonical-height proof job.
    ///
    /// The caller supplies the selected tier because the chain store does not
    /// depend on the recursive prover. The block hash is checked against the
    /// canonical header in this same transaction. Re-enqueue of the identical
    /// `(height, hash, tier)` is idempotent; a canonical fork replacement
    /// overwrites old metadata and deletes its result.
    pub fn enqueue_recursive_proof_job(
        &self,
        height: u64,
        block_hash: [u8; 32],
        tier: RecursiveProofJobTier,
    ) -> Result<RecursiveProofJob, StoreError> {
        let txn = self.db.begin_rw_txn()?;
        let header_tbl = txn.open_table(Some(T_HEADERS))?;
        let header_raw: Option<Vec<u8>> = txn.get(&header_tbl, &u64_key(height))?;
        if header_raw
            .as_deref()
            .and_then(canonical_hash_from_encoded_header)
            != Some(block_hash)
        {
            return Err(StoreError::Decode(
                "recursive proof job hash is not canonical at height",
            ));
        }

        let key = recursive_proof_height_key(height);
        let jobs = txn.open_table(Some(T_RECURSIVE_PROOF_JOBS))?;
        let existing_raw: Option<[u8; RECURSIVE_PROOF_JOB_ENCODED_BYTES]> = txn.get(&jobs, &key)?;
        if let Some(raw) = existing_raw {
            let existing = decode_recursive_proof_job(height, &raw)
                .ok_or(StoreError::Decode("invalid recursive proof job metadata"))?;
            if existing.block_hash == block_hash {
                if existing.tier != tier {
                    return Err(StoreError::Decode(
                        "recursive proof job tier changed for the same block",
                    ));
                }
                txn.commit()?;
                return Ok(existing);
            }
        }

        let results = txn.open_table(Some(T_RECURSIVE_PROOF_RESULTS))?;
        let _ = txn.del(&results, &key, None);
        let job = RecursiveProofJob {
            height,
            block_hash,
            tier,
            state: RecursiveProofJobState::Pending,
            attempt_counter: 0,
        };
        txn.put(
            &jobs,
            key,
            encode_recursive_proof_job(&job),
            WriteFlags::empty(),
        )?;
        txn.commit()?;
        Ok(job)
    }

    /// Claim the numerically-lowest canonical pending job.
    ///
    /// Big-endian height keys make the cursor order numeric even across byte
    /// boundaries such as 255 -> 256. Only the selected fixed-width record is
    /// retained; no queue or result payload collection is allocated.
    pub fn claim_next_recursive_proof_job(&self) -> Result<Option<RecursiveProofJob>, StoreError> {
        let txn = self.db.begin_rw_txn()?;
        let jobs = txn.open_table(Some(T_RECURSIVE_PROOF_JOBS))?;
        let headers = txn.open_table(Some(T_HEADERS))?;
        let selected = {
            let mut cursor = txn.cursor(&jobs)?;
            let mut item: Option<([u8; 8], [u8; RECURSIVE_PROOF_JOB_ENCODED_BYTES])> =
                cursor.first()?;
            let mut selected = None;
            while let Some((key, raw)) = item {
                let height = recursive_proof_height_from_key(&key)
                    .ok_or(StoreError::Decode("invalid recursive proof job height key"))?;
                let job = decode_recursive_proof_job(height, &raw)
                    .ok_or(StoreError::Decode("invalid recursive proof job metadata"))?;
                if job.state == RecursiveProofJobState::Pending {
                    let header_raw: Option<Vec<u8>> = txn.get(&headers, &u64_key(height))?;
                    if header_raw
                        .as_deref()
                        .and_then(canonical_hash_from_encoded_header)
                        == Some(job.block_hash)
                    {
                        selected = Some(job);
                        break;
                    }
                }
                item = cursor.next()?;
            }
            selected
        };

        let Some(mut job) = selected else {
            txn.commit()?;
            return Ok(None);
        };
        job.attempt_counter = job
            .attempt_counter
            .checked_add(1)
            .ok_or(StoreError::Decode(
                "recursive proof job attempt counter overflow",
            ))?;
        job.state = RecursiveProofJobState::Running;
        txn.put(
            &jobs,
            recursive_proof_height_key(job.height),
            encode_recursive_proof_job(&job),
            WriteFlags::empty(),
        )?;
        txn.commit()?;
        Ok(Some(job))
    }

    /// Store one bounded opaque proof and mark its running job complete in the
    /// same transaction. A failure cannot expose either half independently.
    pub fn complete_recursive_proof_job(
        &self,
        height: u64,
        block_hash: [u8; 32],
        result: &[u8],
    ) -> Result<RecursiveProofJob, StoreError> {
        let encoded_result = encode_recursive_proof_result(block_hash, result)?;
        let txn = self.db.begin_rw_txn()?;
        let key = recursive_proof_height_key(height);
        let jobs = txn.open_table(Some(T_RECURSIVE_PROOF_JOBS))?;
        let raw: Option<[u8; RECURSIVE_PROOF_JOB_ENCODED_BYTES]> = txn.get(&jobs, &key)?;
        let mut job = raw
            .as_ref()
            .and_then(|raw| decode_recursive_proof_job(height, raw))
            .ok_or(StoreError::Decode("recursive proof job is missing"))?;
        if job.block_hash != block_hash || job.state != RecursiveProofJobState::Running {
            return Err(StoreError::Decode(
                "recursive proof completion does not match a running job",
            ));
        }
        let headers = txn.open_table(Some(T_HEADERS))?;
        let header_raw: Option<Vec<u8>> = txn.get(&headers, &u64_key(height))?;
        if header_raw
            .as_deref()
            .and_then(canonical_hash_from_encoded_header)
            != Some(block_hash)
        {
            return Err(StoreError::Decode(
                "recursive proof completion block is no longer canonical",
            ));
        }

        let results = txn.open_table(Some(T_RECURSIVE_PROOF_RESULTS))?;
        txn.put(&results, key, encoded_result, WriteFlags::empty())?;
        job.state = RecursiveProofJobState::Complete;
        txn.put(
            &jobs,
            key,
            encode_recursive_proof_job(&job),
            WriteFlags::empty(),
        )?;
        txn.commit()?;
        Ok(job)
    }

    /// Cancellation/backpressure handoff: release one canonical running job
    /// back to Pending without erasing its attempt history.
    ///
    /// Complete jobs and stale/fork-mismatched hashes are rejected. Any
    /// impossible partial result is deleted in the same transaction.
    pub fn release_recursive_proof_job(
        &self,
        height: u64,
        block_hash: [u8; 32],
    ) -> Result<RecursiveProofJob, StoreError> {
        let txn = self.db.begin_rw_txn()?;
        let key = recursive_proof_height_key(height);
        let jobs = txn.open_table(Some(T_RECURSIVE_PROOF_JOBS))?;
        let raw: Option<[u8; RECURSIVE_PROOF_JOB_ENCODED_BYTES]> = txn.get(&jobs, &key)?;
        let mut job = raw
            .as_ref()
            .and_then(|raw| decode_recursive_proof_job(height, raw))
            .ok_or(StoreError::Decode("recursive proof job is missing"))?;
        if job.block_hash != block_hash || job.state != RecursiveProofJobState::Running {
            return Err(StoreError::Decode(
                "recursive proof release does not match a running job",
            ));
        }
        let headers = txn.open_table(Some(T_HEADERS))?;
        let header_raw: Option<Vec<u8>> = txn.get(&headers, &u64_key(height))?;
        if header_raw
            .as_deref()
            .and_then(canonical_hash_from_encoded_header)
            != Some(block_hash)
        {
            return Err(StoreError::Decode(
                "recursive proof release block is no longer canonical",
            ));
        }

        job.state = RecursiveProofJobState::Pending;
        txn.put(
            &jobs,
            key,
            encode_recursive_proof_job(&job),
            WriteFlags::empty(),
        )?;
        let results = txn.open_table(Some(T_RECURSIVE_PROOF_RESULTS))?;
        let _ = txn.del(&results, &key, None);
        txn.commit()?;
        Ok(job)
    }

    /// Read one completed result only if job, result and the current canonical
    /// header all bind the same block hash.
    pub fn get_recursive_proof_job_result(
        &self,
        height: u64,
    ) -> Result<Option<RecursiveProofJobResult>, StoreError> {
        let txn = self.db.begin_ro_txn()?;
        let key = recursive_proof_height_key(height);
        let jobs = txn.open_table(Some(T_RECURSIVE_PROOF_JOBS))?;
        let job_raw: Option<[u8; RECURSIVE_PROOF_JOB_ENCODED_BYTES]> = txn.get(&jobs, &key)?;
        let Some(job) = job_raw
            .as_ref()
            .and_then(|raw| decode_recursive_proof_job(height, raw))
        else {
            return Ok(None);
        };
        if job.state != RecursiveProofJobState::Complete {
            return Ok(None);
        }
        let headers = txn.open_table(Some(T_HEADERS))?;
        let header_raw: Option<Vec<u8>> = txn.get(&headers, &u64_key(height))?;
        if header_raw
            .as_deref()
            .and_then(canonical_hash_from_encoded_header)
            != Some(job.block_hash)
        {
            return Ok(None);
        }
        let results = txn.open_table(Some(T_RECURSIVE_PROOF_RESULTS))?;
        let result_length: Option<ObjectLength> = txn.get(&results, &key)?;
        let Some(ObjectLength(result_length)) = result_length else {
            return Ok(None);
        };
        if result_length < RECURSIVE_PROOF_RESULT_HEADER_BYTES
            || result_length
                > RECURSIVE_PROOF_RESULT_HEADER_BYTES + MAX_RECURSIVE_PROOF_JOB_RESULT_BYTES
        {
            return Err(StoreError::Decode(
                "recursive proof result stored length exceeds hard bounds",
            ));
        }
        let result_raw: Option<Vec<u8>> = txn.get(&results, &key)?;
        let Some(result) = result_raw.and_then(|raw| decode_recursive_proof_result(height, raw))
        else {
            return Ok(None);
        };
        if result.block_hash != job.block_hash {
            return Ok(None);
        }
        Ok(Some(result))
    }

    /// Read fixed-width metadata for diagnostics without loading a result.
    pub fn get_recursive_proof_job(
        &self,
        height: u64,
    ) -> Result<Option<RecursiveProofJob>, StoreError> {
        let txn = self.db.begin_ro_txn()?;
        let jobs = txn.open_table(Some(T_RECURSIVE_PROOF_JOBS))?;
        let raw: Option<[u8; RECURSIVE_PROOF_JOB_ENCODED_BYTES]> =
            txn.get(&jobs, &recursive_proof_height_key(height))?;
        raw.map(|raw| {
            decode_recursive_proof_job(height, &raw)
                .ok_or(StoreError::Decode("invalid recursive proof job metadata"))
        })
        .transpose()
    }

    /// Startup recovery: every interrupted Running job becomes Pending while
    /// retaining its attempt counter. Any impossible partial result is removed
    /// in the same transaction.
    pub fn reset_running_recursive_proof_jobs(&self) -> Result<u64, StoreError> {
        let txn = self.db.begin_rw_txn()?;
        let jobs = txn.open_table(Some(T_RECURSIVE_PROOF_JOBS))?;
        let results = txn.open_table(Some(T_RECURSIVE_PROOF_RESULTS))?;
        let mut reset = 0u64;
        let mut cursor = txn.cursor(&jobs)?;
        let mut item: Option<([u8; 8], [u8; RECURSIVE_PROOF_JOB_ENCODED_BYTES])> =
            cursor.first()?;
        while let Some((key, raw)) = item {
            let height = recursive_proof_height_from_key(&key)
                .ok_or(StoreError::Decode("invalid recursive proof job height key"))?;
            let mut job = decode_recursive_proof_job(height, &raw)
                .ok_or(StoreError::Decode("invalid recursive proof job metadata"))?;
            if job.state == RecursiveProofJobState::Running {
                job.state = RecursiveProofJobState::Pending;
                cursor.put(&key, &encode_recursive_proof_job(&job), WriteFlags::CURRENT)?;
                let _ = txn.del(&results, &key, None);
                reset = reset
                    .checked_add(1)
                    .ok_or(StoreError::Decode("recursive proof reset count overflow"))?;
            }
            item = cursor.next()?;
        }
        drop(cursor);
        txn.commit()?;
        Ok(reset)
    }

    /// Delete every job and result strictly above a retained canonical
    /// ancestor. Used by reorg and explicit epoch-reset paths.
    pub fn delete_recursive_proof_jobs_above(
        &self,
        ancestor_height: u64,
    ) -> Result<(), StoreError> {
        let Some(first_deleted) = ancestor_height.checked_add(1) else {
            return Ok(());
        };
        let txn = self.db.begin_rw_txn()?;
        let start = recursive_proof_height_key(first_deleted);
        for name in [T_RECURSIVE_PROOF_JOBS, T_RECURSIVE_PROOF_RESULTS] {
            let table = txn.open_table(Some(name))?;
            loop {
                let deleted = {
                    let mut cursor = txn.cursor(&table)?;
                    let item: Option<([u8; 8], ())> = cursor.set_range(&start)?;
                    if item.is_some() {
                        cursor.del(WriteFlags::empty())?;
                        true
                    } else {
                        false
                    }
                };
                if !deleted {
                    break;
                }
            }
        }
        txn.commit()?;
        Ok(())
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

    /// Read one segment from the same MDBX snapshot that still names the
    /// caller's expected canonical tip.  Mempool views use this to avoid
    /// mixing slot data from a newly committed block with old anchor metadata.
    pub fn get_segment_at_tip(
        &self,
        expected_height: u64,
        expected_hash: [u8; 32],
        seg_id: u16,
    ) -> Result<Option<(u8, SegmentColumns)>, StoreError> {
        let txn = self.db.begin_ro_txn()?;
        let tip_tbl = txn.open_table(Some(T_CHAIN_TIP))?;
        let tip_raw: Option<Vec<u8>> = txn.get(&tip_tbl, KEY_TIP)?;
        if tip_raw.as_deref().and_then(decode_chain_tip) != Some((expected_height, expected_hash)) {
            return Ok(None);
        }
        let segment_tbl = txn.open_table(Some(T_SEGMENTS))?;
        let raw: Option<Vec<u8>> = txn.get(&segment_tbl, &seg_id.to_le_bytes())?;
        raw.map(|bytes| decode_segment(&bytes).ok_or(StoreError::Decode("invalid stored segment")))
            .transpose()
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

    #[cfg(test)]
    pub(crate) fn put_raw_segment_record_for_test(
        &self,
        key: &[u8],
        value: &[u8],
    ) -> Result<(), StoreError> {
        let txn = self.db.begin_rw_txn()?;
        let tbl = txn.open_table(Some(T_SEGMENTS))?;
        txn.put(&tbl, key, value, WriteFlags::empty())?;
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

    /// Look up one owner's live UTXOs and verify every secondary-index entry
    /// against the exact durable state in the same MDBX read transaction.
    ///
    /// The owner index is only an accelerator. A malformed, stale, duplicate,
    /// out-of-domain, or value-mismatched entry fails closed rather than being
    /// returned to the wallet. Absence of an owner key canonically means that
    /// the owner currently has no live UTXOs.
    pub fn get_verified_utxos_by_owner(
        &self,
        owner: &[u8; 32],
    ) -> Result<VerifiedOwnerSnapshot, StoreError> {
        let txn = self.db.begin_ro_txn()?;

        // Bind the returned owner view to the exact chain/state identity from
        // this same MDBX snapshot. Callers never supply log_slots from a
        // separately locked in-memory view.
        let tip_tbl = txn.open_table(Some(T_CHAIN_TIP))?;
        let tip_raw: Vec<u8> = txn.get(&tip_tbl, KEY_TIP)?.ok_or(StoreError::Decode(
            "missing chain tip for owner-index query",
        ))?;
        let (height, tip_hash) = decode_chain_tip(&tip_raw).ok_or(StoreError::Decode(
            "invalid chain tip for owner-index query",
        ))?;
        let header_tbl = txn.open_table(Some(T_HEADERS))?;
        let header_raw: Vec<u8> =
            txn.get(&header_tbl, &u64_key(height))?
                .ok_or(StoreError::Decode(
                    "missing tip header for owner-index query",
                ))?;
        let header = decode_header(&header_raw).ok_or(StoreError::Decode(
            "invalid tip header for owner-index query",
        ))?;
        if header.height != height || crate::consensus::pow::block_id(&header) != tip_hash {
            return Err(StoreError::Decode(
                "tip identity mismatch during owner-index query",
            ));
        }
        let state_meta_tbl = txn.open_table(Some(T_STATE_META))?;
        let state_meta_raw: Vec<u8> =
            txn.get(&state_meta_tbl, KEY_META)?
                .ok_or(StoreError::Decode(
                    "missing state metadata for owner-index query",
                ))?;
        let (log_slots, active_slot_count, alloc_counter) = decode_state_meta(&state_meta_raw)
            .ok_or(StoreError::Decode(
                "invalid state metadata for owner-index query",
            ))?;
        if header.log_slots != log_slots
            || header.active_slot_count != active_slot_count
            || header.alloc_counter != alloc_counter
        {
            return Err(StoreError::Decode(
                "tip header and state metadata disagree during owner-index query",
            ));
        }
        if !(1..=32).contains(&log_slots) {
            return Err(StoreError::Decode(
                "owner-index query log_slots is outside the u32 slot domain",
            ));
        }
        let effective_log = log_slots.min(crate::consensus::params::LOG_SEGMENT_SIZE);
        let slot_domain = 1u64 << log_slots;

        let owner_tbl = txn.open_table(Some(T_OWNER_INDEX))?;
        let segment_tbl = txn.open_table(Some(T_SEGMENTS))?;
        // Composite keys are strictly slot-sorted within this owner prefix,
        // hence segment-sorted. Verify records as the cursor yields them and
        // retain only one decoded dense segment at a time.
        let mut owner_cursor = txn.cursor(&owner_tbl)?;
        let mut item: Option<(Vec<u8>, Vec<u8>)> = owner_cursor.set_range(owner.as_slice())?;
        let mut current_segment: Option<(u16, SegmentColumns)> = None;
        let mut previous_slot = None;
        let mut verified = Vec::new();
        while let Some((key, raw_value)) = item {
            // Reaching another owner's prefix is the canonical end of this
            // owner's range. A key that begins with the requested owner but
            // has any non-canonical length is corruption, including the old
            // aggregate owner-only encoding.
            if key.get(..32) != Some(owner.as_slice()) {
                break;
            }
            let (indexed_owner, slot_index) = decode_owner_index_key(&key)?;
            if indexed_owner != *owner {
                return Err(StoreError::Decode("owner-index prefix mismatch"));
            }
            if previous_slot.is_some_and(|previous| previous >= slot_index) {
                return Err(StoreError::Decode(
                    "owner-index slots are not strictly sorted and unique",
                ));
            }
            previous_slot = Some(slot_index);
            if verified.len() as u64 >= slot_domain {
                return Err(StoreError::Decode(
                    "owner-index entry count exceeds slot domain",
                ));
            }
            if slot_index as u64 >= slot_domain {
                return Err(StoreError::Decode(
                    "owner-index slot is outside current state domain",
                ));
            }
            let packed_value = decode_owner_index_value(&raw_value)?;
            let segment_id = (slot_index >> effective_log) as u16;
            if current_segment
                .as_ref()
                .is_none_or(|(loaded_id, _)| *loaded_id != segment_id)
            {
                let segment_raw: Option<Vec<u8>> =
                    txn.get(&segment_tbl, &segment_id.to_le_bytes())?;
                let segment_raw = segment_raw.ok_or(StoreError::Decode(
                    "owner-index slot references a missing durable segment",
                ))?;
                let (stored_effective_log, columns) = decode_segment(&segment_raw).ok_or(
                    StoreError::Decode("invalid durable segment referenced by owner index"),
                )?;
                if u32::from(stored_effective_log) != effective_log {
                    return Err(StoreError::Decode(
                        "owner-index segment effective log mismatch",
                    ));
                }
                current_segment = Some((segment_id, columns));
            }

            let local_mask = (1u32 << effective_log) - 1;
            let local = (slot_index & local_mask) as usize;
            let columns = &current_segment
                .as_ref()
                .expect("segment was inserted above")
                .1;
            if local >= columns.values.len()
                || local >= columns.owners_hi.len()
                || local >= columns.owners_lo.len()
            {
                return Err(StoreError::Decode(
                    "owner-index slot exceeds durable segment columns",
                ));
            }
            let value = columns.values[local];
            let owner_hi = columns.owners_hi[local];
            let owner_lo = columns.owners_lo[local];
            if value.0 == 0 && owner_hi.0 == 0 && owner_lo.0 == 0 {
                return Err(StoreError::Decode(
                    "owner-index slot is empty in durable state",
                ));
            }
            if owner_key_from_fields(owner_hi, owner_lo) != *owner {
                return Err(StoreError::Decode(
                    "owner-index owner does not match durable state",
                ));
            }
            if value.0 != packed_value {
                return Err(StoreError::Decode(
                    "owner-index packed value does not match durable state",
                ));
            }
            let (amount, creation_id) = unpack_amount_creation_id(value);
            verified.push(VerifiedOwnerUtxo {
                slot_index,
                amount,
                creation_id,
            });
            item = owner_cursor.next()?;
        }
        Ok(VerifiedOwnerSnapshot {
            owner: *owner,
            height,
            tip_hash,
            state_root: header.state_root,
            log_slots,
            active_slot_count,
            alloc_counter,
            utxos: verified,
        })
    }

    /// Rebuild the owner index from a set of segment columns (used after
    /// applying a state snapshot when the index is empty).
    ///
    /// Clears the existing index and rebuilds it from scratch. O(active_slots).
    #[cfg(test)]
    #[allow(dead_code)]
    pub fn rebuild_owner_index_from_segments(
        &self,
        segments: &[(u16, u8, &crate::segmented_state::SegmentColumns)],
    ) -> Result<(), StoreError> {
        // Clear and stream directly into MDBX in one transaction. The caller
        // may already hold all snapshot segments, but the index rebuild adds
        // only constant auxiliary memory rather than a second state-sized map.
        let txn = self.db.begin_rw_txn()?;
        let tbl = txn.open_table(Some(T_OWNER_INDEX))?;
        txn.clear_table(&tbl)?;
        for &(segment_id, effective_log, columns) in segments {
            visit_live_owner_records(
                segment_id,
                effective_log,
                columns,
                |owner, slot_index, packed_value| {
                    txn.put(
                        &tbl,
                        owner_index_key(&owner, slot_index),
                        encode_owner_index_value(packed_value),
                        WriteFlags::empty(),
                    )?;
                    Ok(())
                },
            )?;
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

    /// Atomically install a finalized, disk-staged snapshot without ever
    /// materializing the complete state in process RAM.
    ///
    /// The staging handle has already passed receiver finalization, but every
    /// file is re-opened and independently checked inside this single RW
    /// transaction.  Segment payload, composite owner-index records, exact and
    /// FRI summaries are consumed one segment at a time.  Any error drops the
    /// transaction, preserving the complete previous volatile state epoch.
    ///
    /// The returned `ChainState` contains only compact exact/FRI summaries and
    /// evicted-segment metadata.  It is returned only after MDBX commit, so the
    /// context can switch hot state without a fallible post-commit disk reload.
    pub(crate) fn install_finalized_snapshot_staging(
        &self,
        staging: &FinalizedSnapshotStaging,
        consensus_meta: &ConsensusMeta,
        canonical_recent_headers: &[BlockHeader],
    ) -> Result<ChainState, StoreError> {
        let metadata = staging.metadata();
        let tip_header = *metadata.header();
        let tip_hash = metadata.tip_hash();
        let effective_log = metadata.effective_log_segment();

        if crate::block_header::block_id(&tip_header) != tip_hash
            || consensus_meta.tip_height != tip_header.height
            || consensus_meta.tip_hash != tip_hash
            || consensus_meta.finalized.height != tip_header.height
            || consensus_meta.finalized.hash != tip_hash
        {
            return Err(StoreError::Decode(
                "staged snapshot metadata and consensus boundary disagree",
            ));
        }
        if canonical_recent_headers.last() != Some(&tip_header)
            || canonical_recent_headers.is_empty()
            || canonical_recent_headers.windows(2).any(|pair| {
                pair[1].height != pair[0].height.saturating_add(1)
                    || pair[1].prev_block_hash != crate::block_header::block_id(&pair[0])
            })
        {
            return Err(StoreError::Decode(
                "staged snapshot recent header window is not canonical",
            ));
        }
        let expected_effective_log = tip_header
            .log_slots
            .min(crate::consensus::params::LOG_SEGMENT_SIZE)
            as u8;
        if effective_log != expected_effective_log {
            return Err(StoreError::Decode(
                "staged snapshot effective segment log mismatch",
            ));
        }

        let mut segmented =
            crate::segmented_state::SegmentedFriState::new_empty(tip_header.log_slots as usize);
        let expected_segment_len =
            1usize
                .checked_shl(u32::from(effective_log))
                .ok_or(StoreError::Decode(
                    "staged snapshot segment geometry overflows",
                ))?;
        let mut exact = StreamingSparseRoot::new(tip_header.log_slots)
            .map_err(|_| StoreError::Decode("invalid staged snapshot exact-root depth"))?;
        let mut exact_segment_roots = Vec::with_capacity(staging.descriptors().len());
        let mut counted_live = 0u64;
        let mut previous_segment = None;

        let txn = self.db.begin_rw_txn()?;

        // Recheck the authenticated boundary in the same transaction that
        // replaces state. Context-level checks alone would leave a race if a
        // second store handle changed canonical headers between validation and
        // this commit.
        let header_tbl = txn.open_table(Some(T_HEADERS))?;
        let stored_header_raw: Option<Vec<u8>> =
            txn.get(&header_tbl, &u64_key(tip_header.height))?;
        let stored_header =
            stored_header_raw
                .as_deref()
                .and_then(decode_header)
                .ok_or(StoreError::Decode(
                    "staged snapshot canonical header is missing",
                ))?;
        if stored_header != tip_header {
            return Err(StoreError::Decode(
                "staged snapshot header differs from canonical store",
            ));
        }
        for header in canonical_recent_headers {
            let raw: Option<Vec<u8>> = txn.get(&header_tbl, &u64_key(header.height))?;
            if raw.as_deref().and_then(decode_header) != Some(*header) {
                return Err(StoreError::Decode(
                    "staged snapshot recent header changed before install",
                ));
            }
        }
        let hash_to_height_tbl = txn.open_table(Some(T_HASH_TO_HEIGHT))?;
        let stored_height: Option<Vec<u8>> = txn.get(&hash_to_height_tbl, tip_hash.as_slice())?;
        if stored_height.as_deref().and_then(u64_from_key) != Some(tip_header.height) {
            return Err(StoreError::Decode(
                "staged snapshot canonical hash index mismatch",
            ));
        }
        let work_tbl = txn.open_table(Some(T_CHAIN_WORK))?;
        let stored_work: Option<Vec<u8>> = txn.get(&work_tbl, &u64_key(tip_header.height))?;
        if stored_work.as_deref().and_then(decode_chain_work)
            != Some(consensus_meta.cumulative_chainwork)
        {
            return Err(StoreError::Decode(
                "staged snapshot cumulative chainwork mismatch",
            ));
        }
        let anchor_tbl = txn.open_table(Some(T_HEADER_ANCHORS))?;
        let stored_anchor_raw: Option<Vec<u8>> =
            txn.get(&anchor_tbl, &u64_key(tip_header.height))?;
        let stored_anchor = stored_anchor_raw
            .as_deref()
            .and_then(decode_header_chain_anchor)
            .ok_or(StoreError::Decode(
                "staged snapshot canonical header anchor is missing",
            ))?;
        let expected_anchor = HeaderChainAnchor {
            height: tip_header.height,
            block_id: tip_hash,
            state_root: tip_header.state_root,
            tx_root: tip_header.tx_root,
            miner_address: tip_header.miner_address,
            log_slots: tip_header.log_slots,
            active_slot_count: tip_header.active_slot_count,
            alloc_counter: tip_header.alloc_counter,
            cumulative_chainwork: consensus_meta.cumulative_chainwork,
        };
        if stored_anchor != expected_anchor {
            return Err(StoreError::Decode(
                "staged snapshot canonical header anchor mismatch",
            ));
        }

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
            T_HISTORY_CHECKPOINT_HEADS,
            T_OWNER_INDEX,
            T_CHECKPOINT_PACKAGES,
            T_CHECKPOINT_COVERAGE,
            T_RECURSIVE_PROOF_JOBS,
            T_RECURSIVE_PROOF_RESULTS,
        ] {
            let table = txn.open_table(Some(name))?;
            txn.clear_table(&table)?;
        }

        let segment_tbl = txn.open_table(Some(T_SEGMENTS))?;
        let owner_tbl = txn.open_table(Some(T_OWNER_INDEX))?;
        for staged_file in staging.encoded_files() {
            let descriptor = *staged_file.descriptor();
            if previous_segment.is_some_and(|previous| previous >= descriptor.segment_id) {
                return Err(StoreError::Decode(
                    "staged snapshot segment ids are not strictly increasing",
                ));
            }
            previous_segment = Some(descriptor.segment_id);
            if staged_file.effective_log_segment() != effective_log {
                return Err(StoreError::Decode(
                    "staged snapshot file effective log mismatch",
                ));
            }

            // `read_encoded` closes finalize-to-install file corruption. Decode
            // again here because MDBX installation and owner-index construction
            // consume the typed columns; the encoded bytes are written directly
            // after all checks, without a second state-sized collection.
            let encoded = staged_file.read_encoded()?;
            let (encoded_log, columns) = decode_segment(&encoded).ok_or(StoreError::Decode(
                "staged snapshot segment decode failed during install",
            ))?;
            if encoded_log != effective_log
                || columns.values.len() != expected_segment_len
                || columns.owners_hi.len() != expected_segment_len
                || columns.owners_lo.len() != expected_segment_len
            {
                return Err(StoreError::Decode(
                    "staged snapshot decoded segment shape mismatch",
                ));
            }
            let fri_root = compute_segment_root(
                effective_log as usize,
                &columns.values,
                &columns.owners_hi,
                &columns.owners_lo,
            );
            if fri_root != descriptor.segment_root {
                return Err(StoreError::Decode(
                    "staged snapshot segment FRI root mismatch during install",
                ));
            }

            let segment_base = u64::from(descriptor.segment_id) << effective_log;
            let mut segment_live = 0u32;
            for local in 0..expected_segment_len {
                let slot = SlotValue {
                    value: columns.values[local],
                    owner_hi: columns.owners_hi[local],
                    owner_lo: columns.owners_lo[local],
                };
                if slot.is_empty() {
                    continue;
                }
                if slot.creation_id() > tip_header.alloc_counter {
                    return Err(StoreError::Decode(
                        "staged snapshot creation_id exceeds target allocator",
                    ));
                }
                segment_live = segment_live.checked_add(1).ok_or(StoreError::Decode(
                    "staged snapshot segment live-count overflow",
                ))?;
                counted_live = counted_live
                    .checked_add(1)
                    .ok_or(StoreError::Decode("staged snapshot active-count overflow"))?;
                let global = segment_base
                    .checked_add(local as u64)
                    .and_then(|index| u32::try_from(index).ok())
                    .ok_or(StoreError::Decode(
                        "staged snapshot live slot exceeds u32 domain",
                    ))?;
                exact.push_leaf(global, slot_leaf_hash(slot)).map_err(|_| {
                    StoreError::Decode("staged snapshot exact leaf is out of range")
                })?;
                let owner = owner_key_from_fields(slot.owner_hi, slot.owner_lo);
                txn.put(
                    &owner_tbl,
                    owner_index_key(&owner, global),
                    encode_owner_index_value(slot.value.0),
                    WriteFlags::empty(),
                )?;
            }
            if segment_live == 0 {
                return Err(StoreError::Decode(
                    "staged snapshot advertises an empty segment",
                ));
            }

            txn.put(
                &segment_tbl,
                descriptor.segment_id.to_le_bytes(),
                &encoded,
                WriteFlags::empty(),
            )?;
            segmented
                .install_evicted_segment_summary(descriptor.segment_id, segment_live, fri_root)
                .map_err(StoreError::Decode)?;
            exact_segment_roots.push((
                descriptor.segment_id,
                exact_segment_root_from_columns(effective_log as usize, &columns),
            ));
            // `columns` and `encoded` drop here before the iterator opens the
            // next file. Only compact roots/counts survive the pass.
        }

        if counted_live != tip_header.active_slot_count {
            return Err(StoreError::Decode(
                "staged snapshot active count does not match target header",
            ));
        }
        let exact_root = exact
            .finish()
            .map_err(|_| StoreError::Decode("staged snapshot exact-root build failed"))?;
        if exact_root != tip_header.state_root {
            return Err(StoreError::Decode(
                "staged snapshot exact root does not match target header",
            ));
        }
        segmented.finish_evicted_segment_summaries();
        let hot_state = ChainState::from_evicted_parts(
            segmented,
            tip_header.active_slot_count,
            tip_header.alloc_counter,
            exact_root,
            &exact_segment_roots,
        )
        .map_err(|_| StoreError::Decode("staged snapshot compact exact cache mismatch"))?;

        let tip_tbl = txn.open_table(Some(T_CHAIN_TIP))?;
        txn.put(
            &tip_tbl,
            KEY_TIP,
            encode_chain_tip(tip_header.height, &tip_hash),
            WriteFlags::empty(),
        )?;
        let consensus_tbl = txn.open_table(Some(T_CONSENSUS_META))?;
        txn.put(
            &consensus_tbl,
            KEY_CONSENSUS_META,
            encode_consensus_meta(consensus_meta),
            WriteFlags::empty(),
        )?;
        txn.put(
            &work_tbl,
            u64_key(tip_header.height),
            encode_chain_work(&consensus_meta.cumulative_chainwork),
            WriteFlags::empty(),
        )?;
        let state_meta_tbl = txn.open_table(Some(T_STATE_META))?;
        txn.put(
            &state_meta_tbl,
            KEY_META,
            encode_state_meta(
                tip_header.log_slots,
                tip_header.active_slot_count,
                tip_header.alloc_counter,
            ),
            WriteFlags::empty(),
        )?;

        txn.commit()?;
        Ok(hot_state)
    }

    /// Atomically install a snapshot state at an already-verified canonical header.
    ///
    /// Test-only transitional materialized installer. Production uses
    /// `install_finalized_snapshot_staging`; this helper retains no release
    /// entry point that could accidentally collect every segment in RAM.
    #[cfg(test)]
    pub fn install_state_snapshot(
        &self,
        tip_header: &BlockHeader,
        tip_hash: &[u8; 32],
        consensus_meta: &ConsensusMeta,
        segments: &[(u16, u8, &SegmentColumns)],
    ) -> Result<(), StoreError> {
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
            T_HISTORY_CHECKPOINT_HEADS,
            T_OWNER_INDEX,
            T_CHECKPOINT_PACKAGES,
            T_CHECKPOINT_COVERAGE,
            T_RECURSIVE_PROOF_JOBS,
            T_RECURSIVE_PROOF_RESULTS,
        ] {
            let tbl = txn.open_table(Some(name))?;
            txn.clear_table(&tbl)?;
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

        let owner_tbl = txn.open_table(Some(T_OWNER_INDEX))?;
        for &(segment_id, effective_log, columns) in segments {
            visit_live_owner_records(
                segment_id,
                effective_log,
                columns,
                |owner, slot_index, packed_value| {
                    txn.put(
                        &owner_tbl,
                        owner_index_key(&owner, slot_index),
                        encode_owner_index_value(packed_value),
                        WriteFlags::empty(),
                    )?;
                    Ok(())
                },
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

    /// Return the numeric, strictly unique durable segment ID set without
    /// copying or decoding any segment payload.
    ///
    /// Segment keys predate this API and are little-endian, so MDBX's
    /// lexicographic cursor order is not numeric once IDs exceed 255.  The
    /// complete u16 namespace costs at most 128 KiB here; values are decoded
    /// as `()` so even corrupt or very large payloads are not materialized.
    pub(crate) fn segment_ids(&self) -> Result<Vec<u16>, StoreError> {
        let txn = self.db.begin_ro_txn()?;
        let tbl = txn.open_table(Some(T_SEGMENTS))?;
        let mut cursor = txn.cursor(&tbl)?;
        let mut segment_ids = Vec::new();
        let mut item: Option<(Vec<u8>, ())> = cursor.first()?;
        while let Some((key, ())) = item {
            if key.len() != 2 {
                return Err(StoreError::Decode("invalid stored segment key"));
            }
            segment_ids.push(u16::from_le_bytes([key[0], key[1]]));
            item = cursor.next()?;
        }
        sort_unique_segment_ids(segment_ids)
    }

    /// Stream stored segments through a one-segment ownership boundary.
    ///
    /// Startup and reorg recovery use this path so the node never materializes
    /// a second `Vec` containing the complete durable state.  Peak temporary
    /// memory is one encoded segment plus one decoded `SegmentColumns`.
    pub(crate) fn visit_segments(
        &self,
        mut visitor: impl FnMut(u16, u8, SegmentColumns) -> Result<(), StoreError>,
    ) -> Result<(), StoreError> {
        for segment_id in self.segment_ids()? {
            let (effective_log, columns) = self.get_segment(segment_id)?.ok_or(
                StoreError::Decode("stored segment disappeared while streaming"),
            )?;
            visitor(segment_id, effective_log, columns)?;
        }
        Ok(())
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
    /// 9. Remove reverted tx-index entries and index this block's transactions
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
        dirty_segments: &[(u16, u8, Option<&SegmentColumns>)],
        tx_hashes: &[TxBodyHash],
        tx_index_deletes: &[TxBodyHash],
        block_bytes: Option<&[u8]>, // None = don't store (DA already pruned)
        accepted_block: Option<AcceptedBlockCommitData<'_>>,
        consensus_meta: &ConsensusMeta,
        rebuild_owner_index: bool,
    ) -> Result<(), StoreError> {
        let txn = self.db.begin_rw_txn()?;

        // --- 1. Dirty segments ---
        let seg_tbl = txn.open_table(Some(T_SEGMENTS))?;
        for (seg_id, eff_log, cols) in dirty_segments {
            let key = seg_id.to_le_bytes();
            match cols {
                None => {
                    // Do not persist fully-empty segments. This keeps disk and
                    // snapshot size proportional to live UTXOs.
                    let _ = txn.del(&seg_tbl, key, None);
                }
                Some(cols) => {
                    if segment_columns_empty(cols) {
                        return Err(StoreError::Decode("non-delete dirty segment is empty"));
                    }
                    let val = encode_segment(cols, *eff_log);
                    txn.put(&seg_tbl, key, val, WriteFlags::empty())?;
                }
            }
        }
        // Reorg rollback may cross a slot-domain expansion. Purge every
        // persisted segment outside the ancestor header's domain in this same
        // atomic checkpoint transaction; otherwise a restart could reload
        // stale upper-half data under the smaller depth.
        let domain_segments = if header.log_slots > crate::consensus::params::LOG_SEGMENT_SIZE {
            1usize
                .checked_shl(header.log_slots - crate::consensus::params::LOG_SEGMENT_SIZE)
                .ok_or(StoreError::Decode(
                    "header log_slots exceeds segment domain",
                ))?
        } else {
            1
        };
        let out_of_domain_keys: Vec<Vec<u8>> = {
            let mut cursor = txn.cursor(&seg_tbl)?;
            let mut keys = Vec::new();
            let mut item: Option<(Vec<u8>, Vec<u8>)> = cursor.first()?;
            while let Some((key, _)) = item {
                if key.len() != 2 {
                    return Err(StoreError::Decode("invalid segment key"));
                }
                let seg_id = u16::from_le_bytes([key[0], key[1]]) as usize;
                if seg_id >= domain_segments {
                    keys.push(key);
                }
                item = cursor.next()?;
            }
            keys
        };
        for key in out_of_domain_keys {
            txn.del(&seg_tbl, &key, None)?;
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

        // --- 8.25. Detached accepted-block proof material ---
        //
        // These records are part of the same durability boundary as the tip,
        // exact state, undo log, and body.  A restart can therefore never see
        // an accepted canonical block without the witnesses needed by the
        // checkpoint worker.  Explicit deletion on an empty coinbase pair is
        // required when a reorg replaces a user block at the same height.
        if let Some(accepted) = accepted_block {
            if accepted.block_proof_bytes.is_empty() != accepted.block_auth_sidecar_bytes.is_empty()
            {
                return Err(StoreError::Decode(
                    "accepted proof and auth sidecar presence mismatch",
                ));
            }
            if accepted.history_claim_bytes.is_empty() {
                return Err(StoreError::Decode("accepted history claim is empty"));
            }
            if accepted.accepted_block_certificate_bytes.is_empty() {
                return Err(StoreError::Decode("accepted block certificate is empty"));
            }

            let height_key = u64_key(header.height);
            let proof_tbl = txn.open_table(Some(T_BLOCK_PROOFS))?;
            let sidecar_tbl = txn.open_table(Some(T_BLOCK_AUTH_SIDECARS))?;
            if accepted.block_proof_bytes.is_empty() {
                let _ = txn.del(&proof_tbl, height_key, None);
                let _ = txn.del(&sidecar_tbl, height_key, None);
            } else {
                txn.put(
                    &proof_tbl,
                    height_key,
                    accepted.block_proof_bytes,
                    WriteFlags::empty(),
                )?;
                txn.put(
                    &sidecar_tbl,
                    height_key,
                    accepted.block_auth_sidecar_bytes,
                    WriteFlags::empty(),
                )?;
            }

            let history_tbl = txn.open_table(Some(T_HISTORY_CLAIMS))?;
            txn.put(
                &history_tbl,
                height_key,
                accepted.history_claim_bytes,
                WriteFlags::empty(),
            )?;
            let certificate_tbl = txn.open_table(Some(T_ACCEPTED_BLOCK_CERTIFICATES))?;
            txn.put(
                &certificate_tbl,
                height_key,
                accepted.accepted_block_certificate_bytes,
                WriteFlags::empty(),
            )?;
        }

        // --- 8.4. Selected recursive proof job ---
        //
        // Tier is derived from the canonical transaction count already owned
        // by this commit, so no recursive-crate type or new accepted-material
        // field crosses the storage boundary. Genesis and commits without
        // accepted proof-native material deliberately enqueue nothing.
        if header.height != 0 && accepted_block.is_some() {
            let user_transaction_count = tx_hashes.len().checked_sub(1).ok_or(
                StoreError::Decode("accepted block proof job is missing coinbase tx hash"),
            )?;
            let tier = RecursiveProofJobTier::for_user_transaction_count(user_transaction_count)
                .ok_or(StoreError::Decode(
                    "accepted block transaction count has no canonical proof tier",
                ))?;
            let job_key = recursive_proof_height_key(header.height);
            let jobs = txn.open_table(Some(T_RECURSIVE_PROOF_JOBS))?;
            let existing_raw: Option<[u8; RECURSIVE_PROOF_JOB_ENCODED_BYTES]> =
                txn.get(&jobs, &job_key)?;
            match existing_raw {
                Some(raw) => {
                    let existing = decode_recursive_proof_job(header.height, &raw).ok_or(
                        StoreError::Decode("invalid existing recursive proof job metadata"),
                    )?;
                    if existing.block_hash != *hash || existing.tier != tier {
                        return Err(StoreError::Decode(
                            "accepted block conflicts with existing recursive proof job",
                        ));
                    }
                }
                None => {
                    let results = txn.open_table(Some(T_RECURSIVE_PROOF_RESULTS))?;
                    let _ = txn.del(&results, &job_key, None);
                    let job = RecursiveProofJob {
                        height: header.height,
                        block_hash: *hash,
                        tier,
                        state: RecursiveProofJobState::Pending,
                        attempt_counter: 0,
                    };
                    txn.put(
                        &jobs,
                        job_key,
                        encode_recursive_proof_job(&job),
                        WriteFlags::empty(),
                    )?;
                }
            }
        }

        // --- 8.5. tx_index: TxBodyHash → (height, position_in_block) ---
        // Enables O(1) receipt lookup: given a tx_body_hash, find the block
        // and position to reconstruct the Merkle inclusion path. Reorg
        // deletions live in this same transaction as the ancestor checkpoint,
        // so a crash can never expose an orphan transaction as canonical.
        let tx_idx_tbl = txn.open_table(Some(T_TX_INDEX))?;
        for h in tx_index_deletes {
            let raw: Option<Vec<u8>> = txn.get(&tx_idx_tbl, h.0.as_slice())?;
            if let Some(raw) = raw {
                let (indexed_height, _) = decode_tx_index_value(&raw)
                    .ok_or(StoreError::Decode("invalid tx index entry during reorg"))?;
                // Preserve an older canonical occurrence defensively. Valid
                // user transaction hashes are one-shot, but this guard keeps a
                // malformed delete list from erasing ancestor history.
                if indexed_height > header.height {
                    txn.del(&tx_idx_tbl, h.0.as_slice(), None)?;
                }
            }
        }
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
                txn.clear_table(&oidx_tbl)?;
                let mut cursor = txn.cursor(&seg_tbl)?;
                let mut item: Option<(Vec<u8>, Vec<u8>)> = cursor.first()?;
                while let Some((key, raw)) = item {
                    if key.len() != 2 {
                        return Err(StoreError::Decode(
                            "invalid segment key during owner rebuild",
                        ));
                    }
                    let segment_id = u16::from_le_bytes([key[0], key[1]]);
                    let (effective_log, columns) = decode_segment(&raw)
                        .ok_or(StoreError::Decode("invalid segment during owner rebuild"))?;
                    visit_live_owner_records(
                        segment_id,
                        effective_log,
                        &columns,
                        |owner, slot_index, packed_value| {
                            txn.put(
                                &oidx_tbl,
                                owner_index_key(&owner, slot_index),
                                encode_owner_index_value(packed_value),
                                WriteFlags::empty(),
                            )?;
                            Ok(())
                        },
                    )?;
                    item = cursor.next()?;
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
                        let index_key = owner_index_key(&owner_key, slot_index);
                        let existing: Option<Vec<u8>> = txn.get(&oidx_tbl, &index_key)?;
                        let existing = existing
                            .ok_or(StoreError::Decode("missing pre-block owner-index record"))?;
                        if decode_owner_index_value(&existing)? != prev_value.value.0 {
                            return Err(StoreError::Decode("pre-block owner-index value mismatch"));
                        }
                        txn.del(&oidx_tbl, index_key, None)?;
                    }

                    // Add the post-block owner, if any. Doing both halves for
                    // every first-touch slot also handles live→live physical
                    // reuse with a fresh creation ID.
                    let seg_id = (slot_index >> eff_log) as u16;
                    let local = (slot_index & ((1u32 << eff_log) - 1)) as usize;
                    let post_value = match dirty_segments.iter().find(|(id, _, _)| *id == seg_id) {
                        // A proven transient EMPTY→mint→spend→EMPTY action
                        // collapses to no final slot update. The segment is
                        // legitimately absent and durable post == pre.
                        None => *prev_value,
                        // Spending the last live slot dematerializes the dirty
                        // segment; persistence represents its post-state as an
                        // empty/zero-length column payload.
                        Some((_, _, None)) => SlotValue::EMPTY,
                        Some((_, _, Some(cols))) => {
                            if local >= cols.values.len()
                                || local >= cols.owners_hi.len()
                                || local >= cols.owners_lo.len()
                            {
                                return Err(StoreError::Decode(
                                    "owner-index dirty segment is truncated",
                                ));
                            }
                            SlotValue {
                                value: cols.values[local],
                                owner_hi: cols.owners_hi[local],
                                owner_lo: cols.owners_lo[local],
                            }
                        }
                    };
                    let SlotValue {
                        value,
                        owner_hi,
                        owner_lo,
                    } = post_value;
                    if value.0 != 0 || owner_hi.0 != 0 || owner_lo.0 != 0 {
                        let owner_key = owner_key_from_fields(owner_hi, owner_lo);
                        let index_key = owner_index_key(&owner_key, slot_index);
                        if txn.get::<Vec<u8>>(&oidx_tbl, &index_key)?.is_some() {
                            return Err(StoreError::Decode(
                                "duplicate post-block owner-index record",
                            ));
                        }
                        txn.put(
                            &oidx_tbl,
                            index_key,
                            encode_owner_index_value(value.0),
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

    /// Atomically replace the canonical suffix above `ancestor_height`.
    ///
    /// Every replacement block has already passed the normal proof-native
    /// `AcceptBlock` path in RAM.  This transaction installs the final exact
    /// state, all replacement headers/undo/proof records, and the final tip at
    /// once.  A validation or MDBX failure therefore leaves the old canonical
    /// branch byte-for-byte durable.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn commit_reorg(
        &self,
        ancestor_height: u64,
        final_header: &BlockHeader,
        final_hash: &[u8; 32],
        final_dirty_segments: &[(u16, u8, Option<&SegmentColumns>)],
        reverted_tx_hashes: &[TxBodyHash],
        replacement_payloads: &[crate::storage::mdbx_context::ReorgBlockPayload<'_>],
        replacement: &[StagedAcceptedBlockCommit],
        consensus_meta: &ConsensusMeta,
    ) -> Result<(), StoreError> {
        if final_header.height < ancestor_height
            || consensus_meta.tip_height != final_header.height
            || consensus_meta.tip_hash != *final_hash
        {
            return Err(StoreError::Decode("invalid staged reorg tip"));
        }
        if replacement_payloads.len() != replacement.len() {
            return Err(StoreError::Decode("staged reorg payload count mismatch"));
        }
        let mut expected_height = ancestor_height.saturating_add(1);
        for (payload, block) in replacement_payloads.iter().zip(replacement) {
            if block.header.height != expected_height
                || payload.block.header != block.header
                || block.hash != crate::hash_block_header(&block.header)
                || payload.block_proof_bytes.is_empty()
                    != payload.block_auth_sidecar_bytes.is_empty()
                || block.history_claim_bytes.is_empty()
                || block.accepted_block_certificate_bytes.is_empty()
            {
                return Err(StoreError::Decode("invalid staged reorg block"));
            }
            expected_height = expected_height
                .checked_add(1)
                .ok_or(StoreError::Decode("staged reorg height overflow"))?;
        }
        match replacement.last() {
            Some(last)
                if last.header != *final_header
                    || last.hash != *final_hash
                    || last.cumulative_chainwork != consensus_meta.cumulative_chainwork =>
            {
                return Err(StoreError::Decode("staged reorg final block mismatch"));
            }
            None if final_header.height != ancestor_height => {
                return Err(StoreError::Decode("empty staged reorg changed height"));
            }
            _ => {}
        }

        let txn = self.db.begin_rw_txn()?;

        // Install the final post-reorg exact segments once.  Dirty tracking is
        // deliberately retained across every staged block, so this is the
        // union of rollback and replacement writes.
        let seg_tbl = txn.open_table(Some(T_SEGMENTS))?;
        for (seg_id, eff_log, cols) in final_dirty_segments {
            let key = seg_id.to_le_bytes();
            match cols {
                None => {
                    let _ = txn.del(&seg_tbl, key, None);
                }
                Some(cols) => {
                    if segment_columns_empty(cols) {
                        return Err(StoreError::Decode("non-delete reorg segment is empty"));
                    }
                    txn.put(
                        &seg_tbl,
                        key,
                        encode_segment(cols, *eff_log),
                        WriteFlags::empty(),
                    )?;
                }
            }
        }
        let domain_segments = if final_header.log_slots > crate::consensus::params::LOG_SEGMENT_SIZE
        {
            1usize
                .checked_shl(final_header.log_slots - crate::consensus::params::LOG_SEGMENT_SIZE)
                .ok_or(StoreError::Decode(
                    "reorg final log_slots exceeds segment domain",
                ))?
        } else {
            1
        };
        let out_of_domain_keys: Vec<Vec<u8>> = {
            let mut cursor = txn.cursor(&seg_tbl)?;
            let mut keys = Vec::new();
            let mut item: Option<(Vec<u8>, Vec<u8>)> = cursor.first()?;
            while let Some((key, _)) = item {
                if key.len() != 2 {
                    return Err(StoreError::Decode("invalid segment key"));
                }
                if u16::from_le_bytes([key[0], key[1]]) as usize >= domain_segments {
                    keys.push(key);
                }
                item = cursor.next()?;
            }
            keys
        };
        for key in out_of_domain_keys {
            txn.del(&seg_tbl, &key, None)?;
        }

        // Remove every old canonical height record above the ancestor before
        // installing the replacement.  Hash and tx indexes are cleaned in the
        // same transaction, so shorter replacement branches cannot expose a
        // stale suffix after restart.
        let hdr_tbl = txn.open_table(Some(T_HEADERS))?;
        let old_headers: Vec<(u64, [u8; 32])> = {
            let mut cursor = txn.cursor(&hdr_tbl)?;
            let mut old = Vec::new();
            let mut item: Option<(Vec<u8>, Vec<u8>)> = cursor.first()?;
            while let Some((key, raw)) = item {
                if let Some(height) = u64_from_key(&key) {
                    if height > ancestor_height {
                        let header = decode_header(&raw)
                            .ok_or(StoreError::Decode("invalid header during reorg"))?;
                        old.push((height, crate::hash_block_header(&header)));
                    }
                }
                item = cursor.next()?;
            }
            old
        };
        let h2h_tbl = txn.open_table(Some(T_HASH_TO_HEIGHT))?;
        for (height, hash) in &old_headers {
            txn.del(&hdr_tbl, u64_key(*height), None)?;
            let _ = txn.del(&h2h_tbl, hash.as_slice(), None);
        }

        macro_rules! truncate_height_table_above {
            ($name:expr) => {{
                let table = txn.open_table(Some($name))?;
                let keys: Vec<u64> = {
                    let mut cursor = txn.cursor(&table)?;
                    let mut keys = Vec::new();
                    let mut item: Option<(Vec<u8>, Vec<u8>)> = cursor.first()?;
                    while let Some((key, _)) = item {
                        if let Some(height) = u64_from_key(&key) {
                            if height > ancestor_height {
                                keys.push(height);
                            }
                        }
                        item = cursor.next()?;
                    }
                    keys
                };
                for height in keys {
                    txn.del(&table, u64_key(height), None)?;
                }
            }};
        }
        for table_name in [
            T_HEADER_ANCHORS,
            T_CHAIN_WORK,
            T_UNDO_LOGS,
            T_RECENT_BLOCKS,
            T_BLOCK_PROOFS,
            T_BLOCK_AUTH_SIDECARS,
            T_HISTORY_CLAIMS,
            T_ACCEPTED_BLOCK_CERTIFICATES,
        ] {
            truncate_height_table_above!(table_name);
        }
        if let Some(first_reverted_height) = ancestor_height.checked_add(1) {
            let start = recursive_proof_height_key(first_reverted_height);
            for table_name in [T_RECURSIVE_PROOF_JOBS, T_RECURSIVE_PROOF_RESULTS] {
                let table = txn.open_table(Some(table_name))?;
                // Re-open at the same numeric lower bound after every delete.
                // This is constant-memory and avoids depending on cursor
                // post-delete positioning semantics.
                loop {
                    let deleted = {
                        let mut cursor = txn.cursor(&table)?;
                        let item: Option<([u8; 8], ())> = cursor.set_range(&start)?;
                        if item.is_some() {
                            cursor.del(WriteFlags::empty())?;
                            true
                        } else {
                            false
                        }
                    };
                    if !deleted {
                        break;
                    }
                }
            }
        }

        let tx_idx_tbl = txn.open_table(Some(T_TX_INDEX))?;
        for tx_hash in reverted_tx_hashes {
            let raw: Option<Vec<u8>> = txn.get(&tx_idx_tbl, tx_hash.0.as_slice())?;
            if raw
                .as_deref()
                .and_then(decode_tx_index_value)
                .is_some_and(|(height, _)| height > ancestor_height)
            {
                txn.del(&tx_idx_tbl, tx_hash.0.as_slice(), None)?;
            }
        }

        let anchor_tbl = txn.open_table(Some(T_HEADER_ANCHORS))?;
        let work_tbl = txn.open_table(Some(T_CHAIN_WORK))?;
        let undo_tbl = txn.open_table(Some(T_UNDO_LOGS))?;
        let recent_tbl = txn.open_table(Some(T_RECENT_BLOCKS))?;
        let proof_tbl = txn.open_table(Some(T_BLOCK_PROOFS))?;
        let sidecar_tbl = txn.open_table(Some(T_BLOCK_AUTH_SIDECARS))?;
        let history_tbl = txn.open_table(Some(T_HISTORY_CLAIMS))?;
        let certificate_tbl = txn.open_table(Some(T_ACCEPTED_BLOCK_CERTIFICATES))?;
        let recursive_jobs_tbl = txn.open_table(Some(T_RECURSIVE_PROOF_JOBS))?;
        let recursive_results_tbl = txn.open_table(Some(T_RECURSIVE_PROOF_RESULTS))?;

        for (payload, block) in replacement_payloads.iter().zip(replacement) {
            let height_key = u64_key(block.header.height);
            txn.put(
                &hdr_tbl,
                height_key,
                encode_header(&block.header),
                WriteFlags::empty(),
            )?;
            txn.put(
                &h2h_tbl,
                block.hash.as_slice(),
                height_key,
                WriteFlags::empty(),
            )?;
            txn.put(
                &work_tbl,
                height_key,
                encode_chain_work(&block.cumulative_chainwork),
                WriteFlags::empty(),
            )?;

            let previous_raw: Option<Vec<u8>> =
                txn.get(&anchor_tbl, &u64_key(block.header.height - 1))?;
            let previous = previous_raw
                .as_deref()
                .and_then(decode_header_chain_anchor)
                .ok_or(StoreError::Decode("missing staged reorg parent anchor"))?;
            let anchor =
                extend_header_chain_anchor(&previous, &block.header, block.cumulative_chainwork)?;
            if anchor.block_id != block.hash {
                return Err(StoreError::Decode("staged reorg anchor mismatch"));
            }
            txn.put(
                &anchor_tbl,
                height_key,
                encode_header_chain_anchor(&anchor),
                WriteFlags::empty(),
            )?;
            txn.put(
                &undo_tbl,
                height_key,
                encode_undo_log(&block.undo_log),
                WriteFlags::empty(),
            )?;
            let block_bytes = payload.block.to_bytes();
            txn.put(&recent_tbl, height_key, &block_bytes, WriteFlags::empty())?;
            if payload.block_proof_bytes.is_empty() {
                let _ = txn.del(&proof_tbl, height_key, None);
                let _ = txn.del(&sidecar_tbl, height_key, None);
            } else {
                txn.put(
                    &proof_tbl,
                    height_key,
                    payload.block_proof_bytes,
                    WriteFlags::empty(),
                )?;
                txn.put(
                    &sidecar_tbl,
                    height_key,
                    payload.block_auth_sidecar_bytes,
                    WriteFlags::empty(),
                )?;
            }
            txn.put(
                &history_tbl,
                height_key,
                &block.history_claim_bytes,
                WriteFlags::empty(),
            )?;
            txn.put(
                &certificate_tbl,
                height_key,
                &block.accepted_block_certificate_bytes,
                WriteFlags::empty(),
            )?;
            if block.header.height != 0 {
                if block.undo_log.tx_hashes.len() != payload.block.transactions.len() {
                    return Err(StoreError::Decode(
                        "staged reorg tx hashes disagree with canonical block",
                    ));
                }
                let user_transaction_count =
                    block
                        .undo_log
                        .tx_hashes
                        .len()
                        .checked_sub(1)
                        .ok_or(StoreError::Decode(
                            "staged reorg proof job is missing coinbase tx hash",
                        ))?;
                let tier =
                    RecursiveProofJobTier::for_user_transaction_count(user_transaction_count)
                        .ok_or(StoreError::Decode(
                            "staged reorg transaction count has no canonical proof tier",
                        ))?;
                let job_key = recursive_proof_height_key(block.header.height);
                if txn.get::<()>(&recursive_jobs_tbl, &job_key)?.is_some() {
                    return Err(StoreError::Decode(
                        "staged reorg recursive proof job was not truncated",
                    ));
                }
                let _ = txn.del(&recursive_results_tbl, &job_key, None);
                let job = RecursiveProofJob {
                    height: block.header.height,
                    block_hash: block.hash,
                    tier,
                    state: RecursiveProofJobState::Pending,
                    attempt_counter: 0,
                };
                txn.put(
                    &recursive_jobs_tbl,
                    job_key,
                    encode_recursive_proof_job(&job),
                    WriteFlags::empty(),
                )?;
            }
            for (position, transaction) in payload.block.transactions.iter().enumerate() {
                let tx_hash = transaction.txid();
                txn.put(
                    &tx_idx_tbl,
                    tx_hash.0,
                    encode_tx_index_value(block.header.height, position as u32),
                    WriteFlags::empty(),
                )?;
            }
        }

        let tip_tbl = txn.open_table(Some(T_CHAIN_TIP))?;
        txn.put(
            &tip_tbl,
            KEY_TIP,
            encode_chain_tip(final_header.height, final_hash),
            WriteFlags::empty(),
        )?;
        let consensus_tbl = txn.open_table(Some(T_CONSENSUS_META))?;
        txn.put(
            &consensus_tbl,
            KEY_CONSENSUS_META,
            encode_consensus_meta(consensus_meta),
            WriteFlags::empty(),
        )?;
        let meta_tbl = txn.open_table(Some(T_STATE_META))?;
        txn.put(
            &meta_tbl,
            KEY_META,
            encode_state_meta(
                final_header.log_slots,
                final_header.active_slot_count,
                final_header.alloc_counter,
            ),
            WriteFlags::empty(),
        )?;

        // Rebuild the owner accelerator from the exact post-reorg segment
        // table. Clear is an MDBX operation (no all-key Vec), and records are
        // written as each single decoded segment is visited (no owner map).
        let owner_tbl = txn.open_table(Some(T_OWNER_INDEX))?;
        txn.clear_table(&owner_tbl)?;
        let mut cursor = txn.cursor(&seg_tbl)?;
        let mut item: Option<(Vec<u8>, Vec<u8>)> = cursor.first()?;
        while let Some((key, raw)) = item {
            if key.len() != 2 {
                return Err(StoreError::Decode(
                    "invalid segment key during reorg owner rebuild",
                ));
            }
            let segment_id = u16::from_le_bytes([key[0], key[1]]);
            let (effective_log, columns) = decode_segment(&raw).ok_or(StoreError::Decode(
                "invalid segment during reorg owner rebuild",
            ))?;
            visit_live_owner_records(
                segment_id,
                effective_log,
                &columns,
                |owner, slot_index, packed_value| {
                    txn.put(
                        &owner_tbl,
                        owner_index_key(&owner, slot_index),
                        encode_owner_index_value(packed_value),
                        WriteFlags::empty(),
                    )?;
                    Ok(())
                },
            )?;
            item = cursor.next()?;
        }

        txn.commit()?;
        if let Err(_error) = self.prune_after_commit(final_header.height) {
            // The accepted branch is already durable.  Pruning is retryable
            // maintenance and must not masquerade as a failed reorg.
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

    /// Atomically clear every chain table.
    ///
    /// The on-disk format has one canonical epoch. A database that cannot be
    /// restored must never retain headers, claims, indexes, or checkpoints while
    /// installing a fresh genesis state; that would create a mixed-epoch store.
    pub fn clear_all(&self) -> Result<(), StoreError> {
        let txn = self.db.begin_rw_txn()?;
        let tables = [
            T_HEADERS,
            T_HEADER_ANCHORS,
            T_HASH_TO_HEIGHT,
            T_CHAIN_TIP,
            T_CONSENSUS_META,
            T_CHAIN_WORK,
            T_UNDO_LOGS,
            T_SEGMENTS,
            T_STATE_META,
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
            T_RECURSIVE_PROOF_JOBS,
            T_RECURSIVE_PROOF_RESULTS,
        ];
        for name in tables {
            let tbl = txn.open_table(Some(name))?;
            txn.clear_table(&tbl)?;
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

    fn put_recursive_job_header(
        store: &MdbxStore,
        height: u64,
        nonce_tag: u128,
    ) -> (BlockHeader, [u8; 32]) {
        let mut header = crate::consensus::genesis::genesis_header();
        header.height = height;
        header.timestamp = header.timestamp.saturating_add(height);
        header.nonce = nonce_tag;
        let hash = crate::hash_block_header(&header);
        store.put_header_only(&header, &hash).unwrap();
        (header, hash)
    }

    fn overwrite_owner_index_record(store: &MdbxStore, key: &[u8], value: &[u8]) {
        let txn = store.db.begin_rw_txn().unwrap();
        let table = txn.open_table(Some(T_OWNER_INDEX)).unwrap();
        txn.clear_table(&table).unwrap();
        txn.put(&table, key, value, WriteFlags::empty()).unwrap();
        txn.commit().unwrap();
    }

    #[test]
    fn recursive_proof_job_codec_is_fixed_width_and_fail_closed() {
        let job = RecursiveProofJob {
            height: 256,
            block_hash: [0xA5; 32],
            tier: RecursiveProofJobTier::B255,
            state: RecursiveProofJobState::Running,
            attempt_counter: 7,
        };
        let encoded = encode_recursive_proof_job(&job);
        assert_eq!(encoded.len(), RECURSIVE_PROOF_JOB_ENCODED_BYTES);
        assert_eq!(decode_recursive_proof_job(job.height, &encoded), Some(job));

        for index in [0usize, 4, 5, 6] {
            let mut malformed = encoded;
            malformed[index] = 0xFF;
            assert!(decode_recursive_proof_job(job.height, &malformed).is_none());
        }
        assert!(decode_recursive_proof_job(job.height, &encoded[..43]).is_none());
        let mut trailing = encoded.to_vec();
        trailing.push(0);
        assert!(decode_recursive_proof_job(job.height, &trailing).is_none());

        let mut keys = [256u64, 1, 255, 2].map(recursive_proof_height_key);
        keys.sort_unstable();
        assert_eq!(
            keys.map(|key| recursive_proof_height_from_key(&key).unwrap()),
            [1, 2, 255, 256]
        );
    }

    #[test]
    fn recursive_proof_claim_uses_numeric_height_order_without_queue_collection() {
        let directory = tempfile::tempdir().unwrap();
        let store = MdbxStore::open(directory.path()).unwrap();
        for (height, tier) in [
            (256, RecursiveProofJobTier::B255),
            (1, RecursiveProofJobTier::B8),
            (255, RecursiveProofJobTier::B64),
            (2, RecursiveProofJobTier::B32),
        ] {
            let (_, hash) = put_recursive_job_header(&store, height, height as u128);
            store
                .enqueue_recursive_proof_job(height, hash, tier)
                .unwrap();
        }

        for expected in [1, 2, 255, 256] {
            let claimed = store.claim_next_recursive_proof_job().unwrap().unwrap();
            assert_eq!(claimed.height, expected);
            assert_eq!(claimed.state, RecursiveProofJobState::Running);
            assert_eq!(claimed.attempt_counter, 1);
        }
        assert!(store.claim_next_recursive_proof_job().unwrap().is_none());
    }

    #[test]
    fn recursive_proof_running_job_resumes_pending_after_reopen() {
        let directory = tempfile::tempdir().unwrap();
        let hash;
        {
            let store = MdbxStore::open(directory.path()).unwrap();
            (_, hash) = put_recursive_job_header(&store, 7, 1);
            store
                .enqueue_recursive_proof_job(7, hash, RecursiveProofJobTier::B8)
                .unwrap();
            let claimed = store.claim_next_recursive_proof_job().unwrap().unwrap();
            assert_eq!(claimed.state, RecursiveProofJobState::Running);
            assert_eq!(claimed.attempt_counter, 1);
        }

        let reopened = MdbxStore::open(directory.path()).unwrap();
        let resumed = reopened.get_recursive_proof_job(7).unwrap().unwrap();
        assert_eq!(resumed.state, RecursiveProofJobState::Pending);
        assert_eq!(resumed.attempt_counter, 1);
        let reclaimed = reopened.claim_next_recursive_proof_job().unwrap().unwrap();
        assert_eq!(reclaimed.block_hash, hash);
        assert_eq!(reclaimed.state, RecursiveProofJobState::Running);
        assert_eq!(reclaimed.attempt_counter, 2);
    }

    #[test]
    fn recursive_proof_running_job_can_be_released_for_backpressure() {
        let directory = tempfile::tempdir().unwrap();
        let store = MdbxStore::open(directory.path()).unwrap();
        let (_, hash) = put_recursive_job_header(&store, 9, 1);
        store
            .enqueue_recursive_proof_job(9, hash, RecursiveProofJobTier::B8)
            .unwrap();
        let claimed = store.claim_next_recursive_proof_job().unwrap().unwrap();
        assert_eq!(claimed.attempt_counter, 1);
        assert!(store.release_recursive_proof_job(9, [0xFF; 32]).is_err());
        assert_eq!(
            store.get_recursive_proof_job(9).unwrap().unwrap().state,
            RecursiveProofJobState::Running
        );

        let released = store.release_recursive_proof_job(9, hash).unwrap();
        assert_eq!(released.state, RecursiveProofJobState::Pending);
        assert_eq!(released.attempt_counter, 1);
        let reclaimed = store.claim_next_recursive_proof_job().unwrap().unwrap();
        assert_eq!(reclaimed.attempt_counter, 2);
        store
            .complete_recursive_proof_job(9, hash, b"complete")
            .unwrap();
        assert!(store.release_recursive_proof_job(9, hash).is_err());
        assert_eq!(
            store.get_recursive_proof_job(9).unwrap().unwrap().state,
            RecursiveProofJobState::Complete
        );
    }

    #[test]
    fn recursive_proof_result_is_atomic_bounded_and_fork_gated() {
        let directory = tempfile::tempdir().unwrap();
        let store = MdbxStore::open(directory.path()).unwrap();
        let (_, first_hash) = put_recursive_job_header(&store, 10, 1);
        store
            .enqueue_recursive_proof_job(10, first_hash, RecursiveProofJobTier::B32)
            .unwrap();
        store.claim_next_recursive_proof_job().unwrap().unwrap();

        let oversized = vec![0u8; MAX_RECURSIVE_PROOF_JOB_RESULT_BYTES + 1];
        assert!(store
            .complete_recursive_proof_job(10, first_hash, &oversized)
            .is_err());
        drop(oversized);
        assert_eq!(
            store.get_recursive_proof_job(10).unwrap().unwrap().state,
            RecursiveProofJobState::Running
        );
        assert!(store.get_recursive_proof_job_result(10).unwrap().is_none());

        let proof = b"opaque-selected-recursive-proof";
        let completed = store
            .complete_recursive_proof_job(10, first_hash, proof)
            .unwrap();
        assert_eq!(completed.state, RecursiveProofJobState::Complete);
        assert_eq!(
            store
                .get_recursive_proof_job_result(10)
                .unwrap()
                .unwrap()
                .bytes,
            proof
        );

        let (_, replacement_hash) = put_recursive_job_header(&store, 10, 2);
        assert_ne!(first_hash, replacement_hash);
        assert!(store.get_recursive_proof_job_result(10).unwrap().is_none());
        let replacement = store
            .enqueue_recursive_proof_job(10, replacement_hash, RecursiveProofJobTier::B32)
            .unwrap();
        assert_eq!(replacement.state, RecursiveProofJobState::Pending);
        assert_eq!(replacement.attempt_counter, 0);
        assert!(store.get_recursive_proof_job_result(10).unwrap().is_none());
    }

    #[test]
    fn recursive_proof_delete_above_removes_jobs_and_results_numerically() {
        let directory = tempfile::tempdir().unwrap();
        let store = MdbxStore::open(directory.path()).unwrap();
        for height in [1u64, 2, 256] {
            let (_, hash) = put_recursive_job_header(&store, height, height as u128);
            store
                .enqueue_recursive_proof_job(height, hash, RecursiveProofJobTier::B8)
                .unwrap();
        }
        for height in [1u64, 2, 256] {
            let job = store.claim_next_recursive_proof_job().unwrap().unwrap();
            assert_eq!(job.height, height);
            store
                .complete_recursive_proof_job(height, job.block_hash, &[height as u8])
                .unwrap();
        }

        store.delete_recursive_proof_jobs_above(1).unwrap();
        assert!(store.get_recursive_proof_job(1).unwrap().is_some());
        assert!(store.get_recursive_proof_job_result(1).unwrap().is_some());
        for height in [2u64, 256] {
            assert!(store.get_recursive_proof_job(height).unwrap().is_none());
            assert!(store
                .get_recursive_proof_job_result(height)
                .unwrap()
                .is_none());
        }
    }

    #[test]
    fn accepted_block_commit_enqueues_job_and_failed_commit_leaves_none() {
        use noid_poseidon2b::primitives::{Address, TxBodyHash};

        let directory = tempfile::tempdir().unwrap();
        let store = MdbxStore::open(directory.path()).unwrap();
        let (parent, parent_meta) = commit_owner_fixture(&store, Address([0x91; 32]));
        let parent_hash = crate::hash_block_header(&parent);

        let mut accepted_header = parent;
        accepted_header.height = 1;
        accepted_header.prev_block_hash = parent_hash;
        accepted_header.timestamp = accepted_header.timestamp.saturating_add(1);
        accepted_header.nonce = accepted_header.nonce.wrapping_add(1);
        let accepted_hash = crate::hash_block_header(&accepted_header);
        let accepted_meta = ConsensusMeta {
            tip_height: 1,
            tip_hash: accepted_hash,
            cumulative_chainwork: [2; 32],
            finalized: crate::storage::meta::FinalizedCheckpoint {
                height: 1,
                hash: accepted_hash,
            },
        };
        let accepted_artifacts = AcceptedBlockCommitData {
            block_proof_bytes: &[],
            block_auth_sidecar_bytes: &[],
            history_claim_bytes: b"history-one",
            accepted_block_certificate_bytes: b"certificate-one",
        };
        let coinbase_hash = TxBodyHash([0x11; 32]);
        store
            .commit_block(
                &accepted_header,
                &accepted_hash,
                &BlockUndoLog::empty(1, accepted_header.log_slots),
                &[],
                &[coinbase_hash],
                &[],
                None,
                Some(accepted_artifacts),
                &accepted_meta,
                false,
            )
            .unwrap();
        assert_eq!(
            store.get_recursive_proof_job(1).unwrap(),
            Some(RecursiveProofJob {
                height: 1,
                block_hash: accepted_hash,
                tier: RecursiveProofJobTier::B8,
                state: RecursiveProofJobState::Pending,
                attempt_counter: 0,
            })
        );

        let mut rejected_header = accepted_header;
        rejected_header.height = 2;
        rejected_header.prev_block_hash = accepted_hash;
        rejected_header.timestamp = rejected_header.timestamp.saturating_add(1);
        rejected_header.nonce = rejected_header.nonce.wrapping_add(1);
        let rejected_hash = crate::hash_block_header(&rejected_header);
        let rejected_meta = ConsensusMeta {
            tip_height: 2,
            tip_hash: rejected_hash,
            cumulative_chainwork: [3; 32],
            finalized: crate::storage::meta::FinalizedCheckpoint {
                height: 2,
                hash: rejected_hash,
            },
        };
        let nonexistent_preimage =
            SlotValue::with_owner_fields(5, 1, Address([0xEE; 32]).as_fields());
        let rejected_coinbase_hash = TxBodyHash([0x22; 32]);
        assert!(store
            .commit_block(
                &rejected_header,
                &rejected_hash,
                &BlockUndoLog {
                    block_height: 2,
                    log_slots_before: rejected_header.log_slots,
                    active_slot_count_before: rejected_header.active_slot_count,
                    alloc_counter_before: rejected_header.alloc_counter,
                    // The proof job is inserted first; owner-index validation
                    // later rejects this nonexistent pre-block record.
                    slot_changes: vec![(2, nonexistent_preimage)],
                    tx_hashes: vec![rejected_coinbase_hash],
                },
                &[],
                &[rejected_coinbase_hash],
                &[],
                None,
                Some(AcceptedBlockCommitData {
                    block_proof_bytes: &[],
                    block_auth_sidecar_bytes: &[],
                    history_claim_bytes: b"history-two",
                    accepted_block_certificate_bytes: b"certificate-two",
                }),
                &rejected_meta,
                false,
            )
            .is_err());
        assert_eq!(store.get_chain_tip().unwrap(), Some((1, accepted_hash)));
        assert!(store.get_header(2).unwrap().is_none());
        assert!(store.get_recursive_proof_job(2).unwrap().is_none());
        assert_eq!(parent_meta.tip_height, 0);
    }

    #[test]
    fn reorg_atomically_replaces_proof_jobs_and_failed_replacement_preserves_them() {
        use crate::block::Block;
        use crate::storage::mdbx_context::ReorgBlockPayload;
        use noid_poseidon2b::primitives::Address;
        use noid_tx::{
            output_bitmap_bit, Transaction, TxBody, TxInput, TxOutput, TX_INPUTS, TX_OUTPUTS,
        };

        fn coinbase(tag: u8) -> Transaction {
            let mut outputs = [TxOutput::dummy(); TX_OUTPUTS];
            outputs[0] = TxOutput {
                slot_index: u32::from(tag),
                amount: 1,
                owner: Address([tag; 32]),
            };
            Transaction::new(TxBody {
                epoch_anchor: [tag; 32],
                fee: 0,
                input_owner: Address([0; 32]),
                inputs: [TxInput::dummy(); TX_INPUTS],
                outputs,
                validity_bitmap: output_bitmap_bit(0),
                is_coinbase: true,
            })
        }

        let directory = tempfile::tempdir().unwrap();
        let store = MdbxStore::open(directory.path()).unwrap();
        let genesis = crate::consensus::genesis::genesis_header();
        let genesis_hash = crate::hash_block_header(&genesis);
        let genesis_meta = ConsensusMeta {
            tip_height: 0,
            tip_hash: genesis_hash,
            cumulative_chainwork: [1; 32],
            finalized: crate::storage::meta::FinalizedCheckpoint {
                height: 0,
                hash: genesis_hash,
            },
        };
        store
            .commit_block(
                &genesis,
                &genesis_hash,
                &BlockUndoLog::empty(0, genesis.log_slots),
                &[],
                &[],
                &[],
                None,
                None,
                &genesis_meta,
                false,
            )
            .unwrap();

        let old_tx = coinbase(1);
        let mut old_header = genesis;
        old_header.height = 1;
        old_header.prev_block_hash = genesis_hash;
        old_header.timestamp = old_header.timestamp.saturating_add(1);
        old_header.nonce = 1;
        let old_hash = crate::hash_block_header(&old_header);
        let old_meta = ConsensusMeta {
            tip_height: 1,
            tip_hash: old_hash,
            cumulative_chainwork: [2; 32],
            finalized: crate::storage::meta::FinalizedCheckpoint {
                height: 0,
                hash: genesis_hash,
            },
        };
        let old_tx_hash = old_tx.txid();
        let old_undo = BlockUndoLog {
            block_height: 1,
            log_slots_before: genesis.log_slots,
            active_slot_count_before: genesis.active_slot_count,
            alloc_counter_before: genesis.alloc_counter,
            slot_changes: vec![],
            tx_hashes: vec![old_tx_hash],
        };
        let old_block = Block {
            header: old_header,
            transactions: vec![old_tx],
        };
        let old_bytes = old_block.to_bytes();
        store
            .commit_block(
                &old_header,
                &old_hash,
                &old_undo,
                &[],
                &[old_tx_hash],
                &[],
                Some(&old_bytes),
                Some(AcceptedBlockCommitData {
                    block_proof_bytes: &[],
                    block_auth_sidecar_bytes: &[],
                    history_claim_bytes: b"old-history",
                    accepted_block_certificate_bytes: b"old-certificate",
                }),
                &old_meta,
                false,
            )
            .unwrap();
        store.claim_next_recursive_proof_job().unwrap().unwrap();
        store
            .complete_recursive_proof_job(1, old_hash, b"old-result")
            .unwrap();

        let replacement_tx = coinbase(2);
        let replacement_tx_hash = replacement_tx.txid();
        let mut replacement_header = old_header;
        replacement_header.nonce = 2;
        let replacement_hash = crate::hash_block_header(&replacement_header);
        let replacement_block = Block {
            header: replacement_header,
            transactions: vec![replacement_tx],
        };
        let replacement_undo = BlockUndoLog {
            block_height: 1,
            log_slots_before: genesis.log_slots,
            active_slot_count_before: genesis.active_slot_count,
            alloc_counter_before: genesis.alloc_counter,
            slot_changes: vec![],
            tx_hashes: vec![replacement_tx_hash],
        };
        let replacement_staged = StagedAcceptedBlockCommit {
            header: replacement_header,
            hash: replacement_hash,
            cumulative_chainwork: [3; 32],
            undo_log: replacement_undo,
            history_claim_bytes: b"replacement-history".to_vec(),
            accepted_block_certificate_bytes: b"replacement-certificate".to_vec(),
        };
        let replacement_payload = ReorgBlockPayload::new(&replacement_block, &[], &[]);
        let replacement_meta = ConsensusMeta {
            tip_height: 1,
            tip_hash: replacement_hash,
            cumulative_chainwork: [3; 32],
            finalized: crate::storage::meta::FinalizedCheckpoint {
                height: 0,
                hash: genesis_hash,
            },
        };
        store
            .commit_reorg(
                0,
                &replacement_header,
                &replacement_hash,
                &[],
                &[old_tx_hash],
                &[replacement_payload],
                &[replacement_staged],
                &replacement_meta,
            )
            .unwrap();
        assert_eq!(
            store.get_recursive_proof_job(1).unwrap(),
            Some(RecursiveProofJob {
                height: 1,
                block_hash: replacement_hash,
                tier: RecursiveProofJobTier::B8,
                state: RecursiveProofJobState::Pending,
                attempt_counter: 0,
            })
        );
        assert!(store.get_recursive_proof_job_result(1).unwrap().is_none());

        store.claim_next_recursive_proof_job().unwrap().unwrap();
        store
            .complete_recursive_proof_job(1, replacement_hash, b"replacement-result")
            .unwrap();

        let failed_tx = coinbase(3);
        let mut failed_header = replacement_header;
        failed_header.height = 2;
        failed_header.prev_block_hash = replacement_hash;
        failed_header.timestamp = failed_header.timestamp.saturating_add(1);
        failed_header.nonce = 3;
        let failed_hash = crate::hash_block_header(&failed_header);
        let failed_block = Block {
            header: failed_header,
            transactions: vec![failed_tx],
        };
        let failed_staged = StagedAcceptedBlockCommit {
            header: failed_header,
            hash: failed_hash,
            cumulative_chainwork: [4; 32],
            undo_log: BlockUndoLog {
                block_height: 2,
                log_slots_before: replacement_header.log_slots,
                active_slot_count_before: replacement_header.active_slot_count,
                alloc_counter_before: replacement_header.alloc_counter,
                slot_changes: vec![],
                tx_hashes: vec![], // fails after the RW transaction has started
            },
            history_claim_bytes: b"failed-history".to_vec(),
            accepted_block_certificate_bytes: b"failed-certificate".to_vec(),
        };
        let failed_payload = ReorgBlockPayload::new(&failed_block, &[], &[]);
        let failed_meta = ConsensusMeta {
            tip_height: 2,
            tip_hash: failed_hash,
            cumulative_chainwork: [4; 32],
            finalized: replacement_meta.finalized,
        };
        assert!(store
            .commit_reorg(
                1,
                &failed_header,
                &failed_hash,
                &[],
                &[],
                &[failed_payload],
                &[failed_staged],
                &failed_meta,
            )
            .is_err());
        assert_eq!(store.get_chain_tip().unwrap(), Some((1, replacement_hash)));
        assert!(store.get_header(2).unwrap().is_none());
        assert!(store.get_recursive_proof_job(2).unwrap().is_none());
        assert_eq!(
            store
                .get_recursive_proof_job_result(1)
                .unwrap()
                .unwrap()
                .bytes,
            b"replacement-result"
        );
    }

    fn commit_owner_fixture(
        store: &MdbxStore,
        owner: noid_poseidon2b::primitives::Address,
    ) -> (BlockHeader, ConsensusMeta) {
        let mut header = crate::consensus::genesis::genesis_header();
        header.log_slots = 3;
        header.active_slot_count = 2;
        header.alloc_counter = 8;
        let hash = crate::hash_block_header(&header);
        let meta = ConsensusMeta {
            tip_height: header.height,
            tip_hash: hash,
            cumulative_chainwork: [1u8; 32],
            finalized: crate::storage::meta::FinalizedCheckpoint {
                height: header.height,
                hash,
            },
        };
        let undo = BlockUndoLog {
            block_height: header.height,
            log_slots_before: header.log_slots,
            active_slot_count_before: 0,
            alloc_counter_before: 0,
            slot_changes: vec![
                (1, crate::fri_state::SlotValue::EMPTY),
                (6, crate::fri_state::SlotValue::EMPTY),
            ],
            tx_hashes: vec![],
        };
        let mut columns = SegmentColumns::new_zero(8);
        for (slot_index, amount, creation_id) in [(1usize, 11u64, 7u64), (6, 22, 8)] {
            let slot = crate::fri_state::SlotValue::with_owner_fields(
                amount,
                creation_id,
                owner.as_fields(),
            );
            columns.values[slot_index] = slot.value;
            columns.owners_hi[slot_index] = slot.owner_hi;
            columns.owners_lo[slot_index] = slot.owner_lo;
        }
        store
            .commit_block(
                &header,
                &hash,
                &undo,
                &[(0, 3, Some(&columns))],
                &[],
                &[],
                None,
                None,
                &meta,
                false,
            )
            .unwrap();
        (header, meta)
    }

    #[test]
    fn owner_index_codec_rejects_noncanonical_values() {
        let owner = [0x31; 32];
        let first = owner_index_key(&owner, 1);
        let second = owner_index_key(&owner, 256);
        assert!(first < second, "slot_be must preserve numeric cursor order");
        assert_eq!(decode_owner_index_key(&first).unwrap(), (owner, 1));
        assert_eq!(decode_owner_index_key(&second).unwrap(), (owner, 256));
        assert!(decode_owner_index_key(&first[..35]).is_err());
        assert!(decode_owner_index_key(&owner).is_err());

        let value = encode_owner_index_value(7);
        assert_eq!(decode_owner_index_value(&value).unwrap(), 7);
        assert!(decode_owner_index_value(&value[..15]).is_err());
    }

    #[test]
    fn segment_ids_ignore_payloads_and_sort_keys_numerically() {
        let dir = tempfile::tempdir().unwrap();
        let store = MdbxStore::open(dir.path()).unwrap();
        for segment_id in [511u16, 1, 256] {
            store
                .put_raw_segment_record_for_test(
                    &segment_id.to_le_bytes(),
                    b"deliberately not a segment payload",
                )
                .unwrap();
        }

        assert_eq!(store.segment_ids().unwrap(), vec![1, 256, 511]);
    }

    #[test]
    fn segment_ids_reject_malformed_and_duplicate_keys() {
        let dir = tempfile::tempdir().unwrap();
        let store = MdbxStore::open(dir.path()).unwrap();
        store
            .put_raw_segment_record_for_test(&[0xAA], b"payload is irrelevant")
            .unwrap();
        assert!(matches!(
            store.segment_ids(),
            Err(StoreError::Decode("invalid stored segment key"))
        ));

        assert!(matches!(
            sort_unique_segment_ids(vec![7, 2, 7]),
            Err(StoreError::Decode("duplicate stored segment key"))
        ));
    }

    #[test]
    fn verified_owner_lookup_checks_exact_amount_and_creation_id() {
        use noid_poseidon2b::primitives::Address;

        let dir = tempfile::tempdir().unwrap();
        let store = MdbxStore::open(dir.path()).unwrap();
        let owner = Address([0x41; 32]);
        let other = Address([0x42; 32]);
        let (header, _) = commit_owner_fixture(&store, owner);

        {
            let txn = store.db.begin_ro_txn().unwrap();
            let table = txn.open_table(Some(T_OWNER_INDEX)).unwrap();
            let mut cursor = txn.cursor(&table).unwrap();
            let (first_key, first_value): (Vec<u8>, Vec<u8>) = cursor.first().unwrap().unwrap();
            let (second_key, second_value): (Vec<u8>, Vec<u8>) = cursor.next().unwrap().unwrap();
            assert_eq!(decode_owner_index_key(&first_key).unwrap(), (owner.0, 1));
            assert_eq!(decode_owner_index_key(&second_key).unwrap(), (owner.0, 6));
            assert_eq!(first_value.len(), OWNER_INDEX_VALUE_BYTES);
            assert_eq!(second_value.len(), OWNER_INDEX_VALUE_BYTES);
            assert!(cursor.next::<Vec<u8>, Vec<u8>>().unwrap().is_none());
        }

        let snapshot = store.get_verified_utxos_by_owner(&owner.0).unwrap();
        assert_eq!(snapshot.owner, owner.0);
        assert_eq!(snapshot.height, header.height);
        assert_eq!(snapshot.tip_hash, crate::hash_block_header(&header));
        assert_eq!(snapshot.state_root, header.state_root);
        assert_eq!(snapshot.log_slots, header.log_slots);
        assert_eq!(snapshot.active_slot_count, header.active_slot_count);
        assert_eq!(snapshot.alloc_counter, header.alloc_counter);
        assert_eq!(
            snapshot.utxos,
            vec![
                VerifiedOwnerUtxo {
                    slot_index: 1,
                    amount: 11,
                    creation_id: 7,
                },
                VerifiedOwnerUtxo {
                    slot_index: 6,
                    amount: 22,
                    creation_id: 8,
                },
            ]
        );
        let empty_snapshot = store.get_verified_utxos_by_owner(&other.0).unwrap();
        assert_eq!(empty_snapshot.owner, other.0);
        assert_eq!(empty_snapshot.tip_hash, snapshot.tip_hash);
        assert!(empty_snapshot.utxos.is_empty());
    }

    #[test]
    fn verified_owner_lookup_rejects_state_identity_split_brain() {
        use noid_poseidon2b::primitives::Address;

        let dir = tempfile::tempdir().unwrap();
        let store = MdbxStore::open(dir.path()).unwrap();
        let owner = Address([0x43; 32]);
        let (header, _) = commit_owner_fixture(&store, owner);
        store
            .overwrite_state_meta_for_test(
                header.log_slots,
                header.active_slot_count + 1,
                header.alloc_counter,
            )
            .unwrap();
        assert!(store.get_verified_utxos_by_owner(&owner.0).is_err());
    }

    #[test]
    fn verified_owner_lookup_rejects_stale_or_malformed_index_entries() {
        use noid_poseidon2b::primitives::Address;
        use noid_tx::pack_amount_creation_id;

        let dir = tempfile::tempdir().unwrap();
        let store = MdbxStore::open(dir.path()).unwrap();
        let owner = Address([0x51; 32]);
        let (_header, _) = commit_owner_fixture(&store, owner);
        let amount_11_id_7 = pack_amount_creation_id(11, 7).0;

        for (key, value) in [
            (owner_index_key(&owner.0, 1).to_vec(), vec![0xAA]),
            // The removed aggregate owner -> Vec format must fail closed.
            (owner.0.to_vec(), amount_11_id_7.to_le_bytes().to_vec()),
            (
                owner_index_key(&owner.0, 1).to_vec(),
                encode_owner_index_value(pack_amount_creation_id(12, 7).0).to_vec(),
            ),
            (
                owner_index_key(&owner.0, 1).to_vec(),
                encode_owner_index_value(pack_amount_creation_id(11, 9).0).to_vec(),
            ),
            (
                owner_index_key(&owner.0, 2).to_vec(),
                encode_owner_index_value(amount_11_id_7).to_vec(),
            ),
            (
                owner_index_key(&owner.0, 8).to_vec(),
                encode_owner_index_value(amount_11_id_7).to_vec(),
            ),
        ] {
            overwrite_owner_index_record(&store, &key, &value);
            assert!(store.get_verified_utxos_by_owner(&owner.0).is_err());
        }

        let wrong_owner = Address([0x52; 32]);
        overwrite_owner_index_record(
            &store,
            &owner_index_key(&wrong_owner.0, 1),
            &encode_owner_index_value(amount_11_id_7),
        );
        assert!(store.get_verified_utxos_by_owner(&wrong_owner.0).is_err());
    }

    #[test]
    fn snapshot_install_builds_exact_verified_owner_index() {
        use noid_poseidon2b::primitives::Address;

        let dir = tempfile::tempdir().unwrap();
        let store = MdbxStore::open(dir.path()).unwrap();
        let owner = Address([0x61; 32]);
        let mut header = crate::consensus::genesis::genesis_header();
        header.log_slots = 3;
        header.active_slot_count = 1;
        header.alloc_counter = 19;
        let hash = crate::hash_block_header(&header);
        let meta = ConsensusMeta {
            tip_height: header.height,
            tip_hash: hash,
            cumulative_chainwork: [1u8; 32],
            finalized: crate::storage::meta::FinalizedCheckpoint {
                height: header.height,
                hash,
            },
        };
        let mut columns = SegmentColumns::new_zero(8);
        let slot = crate::fri_state::SlotValue::with_owner_fields(123, 19, owner.as_fields());
        columns.values[5] = slot.value;
        columns.owners_hi[5] = slot.owner_hi;
        columns.owners_lo[5] = slot.owner_lo;

        store.put_header_only(&header, &hash).unwrap();
        store
            .install_state_snapshot(&header, &hash, &meta, &[(0, 3, &columns)])
            .unwrap();
        assert_eq!(
            store.get_verified_utxos_by_owner(&owner.0).unwrap().utxos,
            vec![VerifiedOwnerUtxo {
                slot_index: 5,
                amount: 123,
                creation_id: 19,
            }]
        );
    }

    fn staged_snapshot_install_fixture(
        store: &MdbxStore,
        staging_parent: &std::path::Path,
    ) -> (
        crate::storage::FinalizedSnapshotStaging,
        BlockHeader,
        BlockHeader,
        noid_poseidon2b::primitives::Address,
        noid_poseidon2b::primitives::Address,
    ) {
        use crate::state::ChainState;
        use crate::storage::{
            AuthenticatedSnapshotMetadata, SnapshotSegmentDescriptor, SnapshotStagingSession,
        };
        use noid_poseidon2b::primitives::Address;

        let old_owner = Address([0x71; 32]);
        let new_owner = Address([0x72; 32]);
        let old_slot = SlotValue::with_owner_fields(41, 1, old_owner.as_fields());
        let new_slot = SlotValue::with_owner_fields(73, 2, new_owner.as_fields());
        let old_state = ChainState::from_sparse_utxos(3, &[(1, old_slot)], 1).unwrap();
        let new_state = ChainState::from_sparse_utxos(3, &[(6, new_slot)], 2).unwrap();

        let mut old_header = crate::consensus::genesis::genesis_header();
        old_header.log_slots = 3;
        old_header.active_slot_count = 1;
        old_header.alloc_counter = 1;
        old_header.state_root = old_state.utxo_root;
        let old_hash = crate::hash_block_header(&old_header);
        store
            .put_verified_header_only(&old_header, &old_hash, &[1; 32])
            .unwrap();
        let old_meta = ConsensusMeta {
            tip_height: 0,
            tip_hash: old_hash,
            cumulative_chainwork: [1; 32],
            finalized: crate::storage::meta::FinalizedCheckpoint {
                height: 0,
                hash: old_hash,
            },
        };
        let mut old_columns = SegmentColumns::new_zero(8);
        old_columns.values[1] = old_slot.value;
        old_columns.owners_hi[1] = old_slot.owner_hi;
        old_columns.owners_lo[1] = old_slot.owner_lo;
        store
            .install_state_snapshot(&old_header, &old_hash, &old_meta, &[(0, 3, &old_columns)])
            .unwrap();

        let mut new_header = old_header;
        new_header.height = 1;
        new_header.prev_block_hash = old_hash;
        new_header.active_slot_count = 1;
        new_header.alloc_counter = 2;
        new_header.state_root = new_state.utxo_root;
        let new_hash = crate::hash_block_header(&new_header);
        store
            .put_verified_header_only(&new_header, &new_hash, &[2; 32])
            .unwrap();

        let mut new_columns = SegmentColumns::new_zero(8);
        new_columns.values[6] = new_slot.value;
        new_columns.owners_hi[6] = new_slot.owner_hi;
        new_columns.owners_lo[6] = new_slot.owner_lo;
        let encoded = encode_segment(&new_columns, 3);
        let descriptor = SnapshotSegmentDescriptor {
            segment_id: 0,
            segment_root: compute_segment_root(
                3,
                &new_columns.values,
                &new_columns.owners_hi,
                &new_columns.owners_lo,
            ),
            encoded_len: encoded.len() as u32,
        };
        let authenticated =
            AuthenticatedSnapshotMetadata::from_authenticated_header(new_header, new_hash, 3)
                .unwrap();
        let mut session =
            SnapshotStagingSession::new(staging_parent, authenticated, vec![descriptor]).unwrap();
        session.accept_segment(0, 3, &encoded).unwrap();
        let finalized = session.finalize().unwrap();
        (finalized, old_header, new_header, old_owner, new_owner)
    }

    #[test]
    fn finalized_staging_installs_segments_owner_index_and_compact_hot_state_atomically() {
        let database = tempfile::tempdir().unwrap();
        let staging_parent = tempfile::tempdir().unwrap();
        let store = MdbxStore::open(database.path()).unwrap();
        let (staging, old_header, new_header, old_owner, new_owner) =
            staged_snapshot_install_fixture(&store, staging_parent.path());
        let new_hash = crate::hash_block_header(&new_header);
        let meta = ConsensusMeta {
            tip_height: 1,
            tip_hash: new_hash,
            cumulative_chainwork: [2; 32],
            finalized: crate::storage::meta::FinalizedCheckpoint {
                height: 1,
                hash: new_hash,
            },
        };
        store
            .put_history_checkpoint_head_record(0, b"stale-history-head")
            .unwrap();
        store
            .put_accepted_block_batch_certificate_package(0, b"stale-batch")
            .unwrap();
        let old_hash = crate::hash_block_header(&old_header);
        store
            .enqueue_recursive_proof_job(0, old_hash, RecursiveProofJobTier::B8)
            .unwrap();
        store.claim_next_recursive_proof_job().unwrap().unwrap();
        store
            .complete_recursive_proof_job(0, old_hash, b"stale-proof-result")
            .unwrap();

        let hot_state = store
            .install_finalized_snapshot_staging(&staging, &meta, &[old_header, new_header])
            .unwrap();
        assert_eq!(store.get_chain_tip().unwrap(), Some((1, new_hash)));
        assert_eq!(store.get_state_meta().unwrap(), Some((3, 1, 2)));
        assert_eq!(hot_state.cached_state_root(), new_header.state_root);
        assert_eq!(hot_state.state.materialized_segment_ids().count(), 0);
        assert_eq!(
            hot_state.state.active_segment_ids().collect::<Vec<_>>(),
            vec![0]
        );
        assert!(hot_state.state.is_evicted(0));
        assert_eq!(store.get_history_checkpoint_head_record(0).unwrap(), None);
        assert!(store.get_recursive_proof_job(0).unwrap().is_none());
        assert!(store.get_recursive_proof_job_result(0).unwrap().is_none());
        assert_eq!(
            store
                .get_accepted_block_batch_certificate_package(0)
                .unwrap(),
            None
        );
        assert!(store
            .get_verified_utxos_by_owner(&old_owner.0)
            .unwrap()
            .utxos
            .is_empty());
        assert_eq!(
            store
                .get_verified_utxos_by_owner(&new_owner.0)
                .unwrap()
                .utxos,
            vec![VerifiedOwnerUtxo {
                slot_index: 6,
                amount: 73,
                creation_id: 2,
            }]
        );
    }

    #[test]
    fn finalized_staging_failure_aborts_clears_and_preserves_old_state_epoch() {
        let database = tempfile::tempdir().unwrap();
        let staging_parent = tempfile::tempdir().unwrap();
        let store = MdbxStore::open(database.path()).unwrap();
        let (staging, old_header, new_header, old_owner, new_owner) =
            staged_snapshot_install_fixture(&store, staging_parent.path());
        let old_hash = crate::hash_block_header(&old_header);
        let new_hash = crate::hash_block_header(&new_header);
        let staged_path = staging.staging_directory().join("segment-00000.bin");
        let mut permissions = std::fs::metadata(&staged_path).unwrap().permissions();
        permissions.set_readonly(false);
        std::fs::set_permissions(&staged_path, permissions).unwrap();
        let mut tampered = std::fs::read(&staged_path).unwrap();
        *tampered.last_mut().unwrap() ^= 1;
        std::fs::write(&staged_path, tampered).unwrap();
        store
            .put_history_checkpoint_head_record(0, b"old-authority")
            .unwrap();
        store
            .put_accepted_block_batch_certificate_package(0, b"old-batch")
            .unwrap();

        let meta = ConsensusMeta {
            tip_height: 1,
            tip_hash: new_hash,
            cumulative_chainwork: [2; 32],
            finalized: crate::storage::meta::FinalizedCheckpoint {
                height: 1,
                hash: new_hash,
            },
        };
        assert!(store
            .install_finalized_snapshot_staging(&staging, &meta, &[old_header, new_header])
            .is_err());

        assert_eq!(store.get_chain_tip().unwrap(), Some((0, old_hash)));
        assert_eq!(store.get_state_meta().unwrap(), Some((3, 1, 1)));
        assert_eq!(
            store.get_history_checkpoint_head_record(0).unwrap(),
            Some(b"old-authority".to_vec())
        );
        assert_eq!(
            store
                .get_accepted_block_batch_certificate_package(0)
                .unwrap(),
            Some(b"old-batch".to_vec())
        );
        assert_eq!(
            store
                .get_verified_utxos_by_owner(&old_owner.0)
                .unwrap()
                .utxos,
            vec![VerifiedOwnerUtxo {
                slot_index: 1,
                amount: 41,
                creation_id: 1,
            }]
        );
        assert!(store
            .get_verified_utxos_by_owner(&new_owner.0)
            .unwrap()
            .utxos
            .is_empty());
    }

    #[test]
    fn clear_all_removes_chain_and_certificate_epochs_together() {
        let dir = tempfile::tempdir().unwrap();
        let store = MdbxStore::open(dir.path()).unwrap();
        let header = crate::consensus::genesis::genesis_header();
        let hash = crate::hash_block_header(&header);
        let undo = BlockUndoLog::empty(0, header.log_slots);
        let meta = ConsensusMeta {
            tip_height: 0,
            tip_hash: hash,
            cumulative_chainwork: [1u8; 32],
            finalized: crate::storage::meta::FinalizedCheckpoint { height: 0, hash },
        };

        store
            .commit_block(
                &header,
                &hash,
                &undo,
                &[],
                &[],
                &[],
                None,
                None,
                &meta,
                false,
            )
            .unwrap();
        store.put_history_claim(0, b"history").unwrap();
        store
            .put_accepted_block_certificate(0, b"certificate")
            .unwrap();
        store
            .put_accepted_block_batch_certificate_package(0, b"batch")
            .unwrap();
        store
            .put_history_checkpoint_head_record(0, b"head")
            .unwrap();
        store
            .enqueue_recursive_proof_job(0, hash, RecursiveProofJobTier::B8)
            .unwrap();
        store.claim_next_recursive_proof_job().unwrap().unwrap();
        store
            .complete_recursive_proof_job(0, hash, b"proof-result")
            .unwrap();

        store.clear_all().unwrap();

        assert!(store.is_empty().unwrap());
        assert_eq!(store.get_header(0).unwrap(), None);
        assert_eq!(store.get_history_claim(0).unwrap(), None);
        assert_eq!(store.get_accepted_block_certificate(0).unwrap(), None);
        assert_eq!(
            store
                .get_accepted_block_batch_certificate_package(0)
                .unwrap(),
            None
        );
        assert_eq!(store.get_history_checkpoint_head_record(0).unwrap(), None);
        assert!(store.get_recursive_proof_job(0).unwrap().is_none());
        assert!(store.get_recursive_proof_job_result(0).unwrap().is_none());
    }

    #[test]
    fn accepted_material_is_atomic_and_coinbase_replacement_clears_stale_proof() {
        let dir = tempfile::tempdir().unwrap();
        let store = MdbxStore::open(dir.path()).unwrap();
        let header = crate::consensus::genesis::genesis_header();
        let hash = crate::hash_block_header(&header);
        let undo = BlockUndoLog::empty(0, header.log_slots);
        let meta = ConsensusMeta {
            tip_height: 0,
            tip_hash: hash,
            cumulative_chainwork: [1u8; 32],
            finalized: crate::storage::meta::FinalizedCheckpoint { height: 0, hash },
        };

        store
            .commit_block(
                &header,
                &hash,
                &undo,
                &[],
                &[],
                &[],
                Some(b"first-body"),
                Some(AcceptedBlockCommitData {
                    block_proof_bytes: b"first-proof",
                    block_auth_sidecar_bytes: b"first-sidecar",
                    history_claim_bytes: b"first-history",
                    accepted_block_certificate_bytes: b"first-certificate",
                }),
                &meta,
                false,
            )
            .unwrap();

        let invalid = store.commit_block(
            &header,
            &hash,
            &undo,
            &[],
            &[],
            &[],
            Some(b"uncommitted-body"),
            Some(AcceptedBlockCommitData {
                block_proof_bytes: b"uncommitted-proof",
                block_auth_sidecar_bytes: b"uncommitted-sidecar",
                history_claim_bytes: b"",
                accepted_block_certificate_bytes: b"uncommitted-certificate",
            }),
            &meta,
            false,
        );
        assert!(matches!(
            invalid,
            Err(StoreError::Decode("accepted history claim is empty"))
        ));
        assert_eq!(
            store.get_recent_block(0).unwrap().as_deref(),
            Some(b"first-body".as_slice())
        );
        assert_eq!(
            store.get_block_proof(0).unwrap().as_deref(),
            Some(b"first-proof".as_slice())
        );
        assert_eq!(
            store.get_block_auth_sidecar(0).unwrap().as_deref(),
            Some(b"first-sidecar".as_slice())
        );
        assert_eq!(
            store.get_history_claim(0).unwrap().as_deref(),
            Some(b"first-history".as_slice())
        );

        store
            .commit_block(
                &header,
                &hash,
                &undo,
                &[],
                &[],
                &[],
                Some(b"replacement-body"),
                Some(AcceptedBlockCommitData {
                    block_proof_bytes: b"",
                    block_auth_sidecar_bytes: b"",
                    history_claim_bytes: b"replacement-history",
                    accepted_block_certificate_bytes: b"replacement-certificate",
                }),
                &meta,
                false,
            )
            .unwrap();
        assert_eq!(store.get_block_proof(0).unwrap(), None);
        assert_eq!(store.get_block_auth_sidecar(0).unwrap(), None);
        assert_eq!(
            store.get_history_claim(0).unwrap().as_deref(),
            Some(b"replacement-history".as_slice())
        );
        assert_eq!(
            store.get_accepted_block_certificate(0).unwrap().as_deref(),
            Some(b"replacement-certificate".as_slice())
        );
    }

    #[test]
    fn tx_index_reorg_delete_preserves_ancestor_entry() {
        let dir = tempfile::tempdir().unwrap();
        let store = MdbxStore::open(dir.path()).unwrap();
        let header = crate::consensus::genesis::genesis_header();
        let hash = crate::hash_block_header(&header);
        let ancestor_tx = TxBodyHash([0xC3; 32]);
        let undo = BlockUndoLog::empty(0, header.log_slots);
        let meta = ConsensusMeta {
            tip_height: 0,
            tip_hash: hash,
            cumulative_chainwork: [1u8; 32],
            finalized: crate::storage::meta::FinalizedCheckpoint { height: 0, hash },
        };

        store
            .commit_block(
                &header,
                &hash,
                &undo,
                &[],
                std::slice::from_ref(&ancestor_tx),
                &[],
                None,
                None,
                &meta,
                false,
            )
            .unwrap();
        store
            .commit_block(
                &header,
                &hash,
                &undo,
                &[],
                &[],
                std::slice::from_ref(&ancestor_tx),
                None,
                None,
                &meta,
                false,
            )
            .unwrap();

        assert_eq!(store.get_tx_index(&ancestor_tx.0).unwrap(), Some((0, 0)));
    }

    #[test]
    fn undo_counter_snapshots_survive_durable_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let header = crate::consensus::genesis::genesis_header();
        let hash = crate::hash_block_header(&header);
        let undo = BlockUndoLog {
            block_height: header.height,
            log_slots_before: header.log_slots,
            active_slot_count_before: 37,
            alloc_counter_before: 91,
            slot_changes: vec![],
            tx_hashes: vec![TxBodyHash([0xA5; 32])],
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
                    &undo.tx_hashes,
                    &[],
                    None,
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
        header.log_slots = 1;
        header.active_slot_count = 1;
        header.alloc_counter = 1;
        let hash = crate::hash_block_header(&header);
        let meta = ConsensusMeta {
            tip_height: 0,
            tip_hash: hash,
            cumulative_chainwork: [1u8; 32],
            finalized: crate::storage::meta::FinalizedCheckpoint { height: 0, hash },
        };
        let undo = BlockUndoLog {
            block_height: 0,
            log_slots_before: header.log_slots,
            active_slot_count_before: 0,
            alloc_counter_before: 0,
            slot_changes: vec![(1, crate::fri_state::SlotValue::EMPTY)],
            tx_hashes: vec![],
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
                &[(0, 1, Some(&branch_cols))],
                &[],
                &[],
                None,
                None,
                &meta,
                false,
            )
            .unwrap();
        assert_eq!(
            store.get_verified_utxos_by_owner(&owner_b.0).unwrap().utxos,
            vec![VerifiedOwnerUtxo {
                slot_index: 1,
                amount: 77,
                creation_id: 1,
            }]
        );

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
                &[(0, 1, Some(&restored_cols))],
                &[],
                &[],
                None,
                None,
                &meta,
                true,
            )
            .unwrap();

        assert!(store
            .get_verified_utxos_by_owner(&owner_b.0)
            .unwrap()
            .utxos
            .is_empty());
        assert_eq!(
            store.get_verified_utxos_by_owner(&owner_a.0).unwrap().utxos,
            vec![VerifiedOwnerUtxo {
                slot_index: 1,
                amount: 91,
                creation_id: 1,
            }]
        );

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
                &[(0, 1, Some(&replacement_cols))],
                &[],
                &[],
                None,
                None,
                &meta,
                false,
            )
            .unwrap();
        assert!(store
            .get_verified_utxos_by_owner(&owner_a.0)
            .unwrap()
            .utxos
            .is_empty());
        assert_eq!(
            store.get_verified_utxos_by_owner(&owner_b.0).unwrap().utxos,
            vec![VerifiedOwnerUtxo {
                slot_index: 1,
                amount: 93,
                creation_id: 2,
            }]
        );

        // Spending the last live slot dematerializes the segment. The
        // incremental owner index must treat that dirty empty payload as an
        // EMPTY post-value rather than requiring a local column entry.
        let spent_undo = BlockUndoLog {
            slot_changes: vec![(1, replacement)],
            ..undo.clone()
        };
        store
            .commit_block(
                &header,
                &hash,
                &spent_undo,
                &[(0, 1, None)],
                &[],
                &[],
                None,
                None,
                &meta,
                false,
            )
            .unwrap();
        assert!(store
            .get_verified_utxos_by_owner(&owner_b.0)
            .unwrap()
            .utxos
            .is_empty());
        drop(store);
        let reopened = MdbxStore::open(dir.path()).unwrap();
        assert!(reopened
            .get_verified_utxos_by_owner(&owner_b.0)
            .unwrap()
            .utxos
            .is_empty());
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
