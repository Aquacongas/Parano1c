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

use std::{borrow::Cow, path::Path, sync::Arc};

use libmdbx::{
    Database, DatabaseOptions, Mode, NoWriteMap, ObjectLength, Table, TableFlags, Transaction,
    WriteFlags, RO, RW,
};
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
use crate::state::{
    exact_segment_root_from_columns, exact_state_root_from_segment_summaries, ChainState,
    SelectedHistoryLadderUpdate, StreamingSparseRoot,
};
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

// Deterministic mutation-boundary fault injection lives in this module rather
// than in the MDBX wrapper so release builds cannot accidentally carry a
// process-global switch on consensus writes.  Every call site below expands to
// an empty block outside `cfg(test)`.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthoritativeMutationFault {
    VerifiedHeaderBeforeCommit,
    VerifiedHeaderAfterCommit,
    AcceptedBlockBeforeCommit,
    AcceptedBlockAfterCommit,
    ReorgBeforeCommit,
    ReorgAfterCommit,
    SnapshotInstallBeforeCommit,
    SnapshotInstallAfterCommit,
    DeleteAboveBeforeCommit,
    DeleteAboveAfterCommit,
    SelectedPromotionBeforeCommit,
    SelectedPromotionAfterCommit,
    SelectedImportBeforeCommit,
    SelectedImportAfterCommit,
    RetainedPayloadPruneBeforeCommit,
    RetainedPayloadPruneAfterCommit,
    SelectedJournalPruneBeforeCommit,
    SelectedJournalPruneAfterCommit,
    EpochClearBeforeCommit,
    EpochClearAfterCommit,
}

#[cfg(test)]
thread_local! {
    static AUTHORITATIVE_MUTATION_FAULT: std::cell::Cell<Option<AuthoritativeMutationFault>> =
        const { std::cell::Cell::new(None) };
}

/// One-thread, one-shot guard used by restart tests.  TLS keeps parallel Rust
/// tests independent, and consuming the point before returning the synthetic
/// crash makes reopening the database exercise normal startup recovery.
#[cfg(test)]
pub(crate) struct AuthoritativeMutationFaultGuard;

#[cfg(test)]
impl Drop for AuthoritativeMutationFaultGuard {
    fn drop(&mut self) {
        AUTHORITATIVE_MUTATION_FAULT.with(|armed| armed.set(None));
    }
}

#[cfg(test)]
pub(crate) fn arm_authoritative_mutation_fault(
    fault: AuthoritativeMutationFault,
) -> AuthoritativeMutationFaultGuard {
    AUTHORITATIVE_MUTATION_FAULT.with(|armed| {
        assert!(
            armed.replace(Some(fault)).is_none(),
            "an authoritative MDBX mutation fault is already armed on this test thread"
        );
    });
    AuthoritativeMutationFaultGuard
}

#[cfg(test)]
fn hit_authoritative_mutation_fault(fault: AuthoritativeMutationFault) -> Result<(), StoreError> {
    let hit = AUTHORITATIVE_MUTATION_FAULT.with(|armed| {
        if armed.get() == Some(fault) {
            armed.set(None);
            true
        } else {
            false
        }
    });
    if hit {
        Err(StoreError::InjectedCrash(fault))
    } else {
        Ok(())
    }
}

macro_rules! authoritative_mutation_boundary {
    ($fault:ident) => {{
        #[cfg(test)]
        hit_authoritative_mutation_fault(AuthoritativeMutationFault::$fault)?;
    }};
}

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
/// Detached coverage attestations (selected-history Link terminal envelopes)
/// carried by blocks that advanced `header.attested_coverage`. Retained and
/// served with the block so peers can natively re-verify the advancement.
/// Key: height (u64 LE). Value: serialized terminal package bytes.
const T_COVERAGE_ATTESTATIONS: &str = "coverage_attestations";
/// Accepted state-transition history claims retained until checkpoint package
/// coverage consumes them. Key: height (u64 LE). Value: raw bincode bytes.
const T_HISTORY_CLAIMS: &str = "history_claims";
/// Accepted-block certificate records produced at block acceptance time.
/// Key: height (u64 LE). Value: raw bincode bytes owned by noid_block/noid_recursive.
const T_ACCEPTED_BLOCK_CERTIFICATES: &str = "accepted_block_certificates";
/// Fixed-width canonical bindings for opaque accepted-block certificates.
/// Key: height (u64 LE). Value: magic, height, canonical block hash and the
/// exact opaque certificate byte length.  The chain crate cannot deserialize
/// `noid_block` proof types without introducing a dependency cycle, so this
/// acceptance-time record is the durable fail-closed authority used by
/// retained-payload maintenance.
const T_ACCEPTED_BLOCK_CERTIFICATE_BINDINGS: &str = "accepted_block_certificate_bindings";
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
/// Forward ladder cursor payloads: the selected-history prover's own exact
/// raw segment columns at the cursor height, independent of the canonical
/// tip's undo window. Key: segment_id (u16 BE); value: `encode_segment`.
const T_LADDER_SEGMENTS: &str = "ladder_segments";
/// Single fixed-key boundary record for the forward ladder cursor. Only live
/// segments carry summary entries; `T_LADDER_SEGMENTS` must back exactly them.
const T_LADDER_META: &str = "ladder_meta";
const N_TABLES: u64 = 32;

// Single-entry table keys
const KEY_TIP: &[u8] = &[0u8];
const KEY_META: &[u8] = &[0u8];
const KEY_LADDER_META: &[u8] = &[0u8];
const KEY_CONSENSUS_META: &[u8] = &[0u8];
const KEY_CHECKPOINT_COVERAGE: &[u8] = &[0u8];
const KEY_SELECTED_HISTORY_COVERAGE: &[u8] = &[1u8];
const KEY_RETAINED_PAYLOAD_PRUNE_WATERMARK: &[u8] = &[2u8];

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum StoreError {
    Mdbx(libmdbx::Error),
    Decode(&'static str),
    HeaderAnchor(HeaderChainAnchorError),
    SnapshotStaging(SnapshotStagingError),
    #[cfg(test)]
    InjectedCrash(AuthoritativeMutationFault),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Mdbx(e) => write!(f, "mdbx: {e}"),
            Self::Decode(ctx) => write!(f, "decode error: {ctx}"),
            Self::HeaderAnchor(e) => write!(f, "header anchor: {e}"),
            Self::SnapshotStaging(e) => write!(f, "snapshot staging: {e}"),
            #[cfg(test)]
            Self::InjectedCrash(boundary) => {
                write!(
                    f,
                    "injected crash at authoritative MDBX boundary {boundary:?}"
                )
            }
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
            #[cfg(test)]
            Self::InjectedCrash(_) => None,
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

/// Maximum authenticated header records promoted by one MDBX write
/// transaction.  Deep snapshot sync streams as many bounded batches as
/// necessary instead of collecting the candidate chain in memory.
pub const MAX_VERIFIED_HEADER_BATCH_RECORDS: usize = 512;

/// One owned, already native-validated canonical header staged for durable
/// promotion after selected-history verification authenticates its tip.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedHeaderBatchRecord {
    pub header: BlockHeader,
    pub hash: [u8; 32],
    pub cumulative_chainwork: [u8; 32],
}

/// Exact outcome of one idempotent bounded header promotion transaction.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct VerifiedHeaderBatchOutcome {
    pub existing: usize,
    pub promoted: usize,
}

/// One stable MVCC view used by bounded historical-state reconstruction.
///
/// The transaction owns no decoded payload collection. Each requested header,
/// undo record, or segment is read on demand from the same database version,
/// while a concurrent writer may advance the live canonical tip.
pub(super) struct MdbxHistoricalReadSnapshot<'a> {
    txn: Transaction<'a, RO, NoWriteMap>,
}

impl MdbxHistoricalReadSnapshot<'_> {
    pub(super) fn get_chain_tip(&self) -> Result<Option<(u64, [u8; 32])>, StoreError> {
        let table = self.txn.open_table(Some(T_CHAIN_TIP))?;
        let raw: Option<[u8; 40]> = self.txn.get(&table, KEY_TIP)?;
        Ok(raw.as_ref().and_then(|raw| decode_chain_tip(raw)))
    }

    pub(super) fn get_state_meta(&self) -> Result<Option<(u32, u64, u64)>, StoreError> {
        let table = self.txn.open_table(Some(T_STATE_META))?;
        let raw: Option<Vec<u8>> = self.txn.get(&table, KEY_META)?;
        Ok(raw.and_then(|raw| decode_state_meta(&raw)))
    }

    pub(super) fn get_header(&self, height: u64) -> Result<Option<BlockHeader>, StoreError> {
        let table = self.txn.open_table(Some(T_HEADERS))?;
        let raw: Option<Vec<u8>> = self.txn.get(&table, &u64_key(height))?;
        Ok(raw.and_then(|raw| decode_header(&raw)))
    }

    pub(super) fn get_undo_log(&self, height: u64) -> Result<Option<BlockUndoLog>, StoreError> {
        let table = self.txn.open_table(Some(T_UNDO_LOGS))?;
        let raw: Option<Vec<u8>> = self.txn.get(&table, &u64_key(height))?;
        Ok(raw.and_then(|raw| decode_undo_log(&raw)))
    }

    pub(super) fn get_segment(
        &self,
        segment_id: u16,
    ) -> Result<Option<(u8, SegmentColumns)>, StoreError> {
        let table = self.txn.open_table(Some(T_SEGMENTS))?;
        let raw: Option<Vec<u8>> = self.txn.get(&table, &segment_id.to_le_bytes())?;
        raw.map(|raw| {
            decode_segment(&raw).ok_or(StoreError::Decode("invalid stored historical segment"))
        })
        .transpose()
    }

    pub(super) fn get_selected_history_ladder_meta(
        &self,
    ) -> Result<Option<SelectedHistoryLadderMeta>, StoreError> {
        let table = self.txn.open_table(Some(T_LADDER_META))?;
        let raw: Option<Vec<u8>> = self.txn.get(&table, KEY_LADDER_META)?;
        raw.map(|raw| {
            decode_selected_history_ladder_meta(&raw)
                .ok_or(StoreError::Decode("invalid selected-history ladder meta"))
        })
        .transpose()
    }

    pub(super) fn get_selected_history_ladder_segment(
        &self,
        segment_id: u16,
    ) -> Result<Option<(u8, SegmentColumns)>, StoreError> {
        let table = self.txn.open_table(Some(T_LADDER_SEGMENTS))?;
        let raw: Option<Vec<u8>> = self.txn.get(&table, &ladder_segment_key(segment_id))?;
        raw.map(|raw| {
            decode_segment(&raw).ok_or(StoreError::Decode("invalid stored ladder segment"))
        })
        .transpose()
    }
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
    /// Tip header `attested_coverage` bound to this same MDBX snapshot.
    /// Gates coinbase maturity in wallet balance/selection views.
    pub attested_coverage: u64,
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
    /// Serialized selected-history Link terminal envelope attesting the
    /// header's advanced coverage. Empty is canonical for a block that keeps
    /// its parent's `attested_coverage` and deletes any stale same-height
    /// payload left by a reverted branch.
    pub coverage_attestation_bytes: &'a [u8],
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
const SELECTED_HISTORY_COVERAGE_MAGIC: [u8; 4] = *b"SHC1";
const SELECTED_HISTORY_COVERAGE_ENCODED_BYTES: usize = 44;
// version + height + hash + canonical class slot + canonical tier.
// The opaque recursive envelope follows this fixed metadata.
const SELECTED_HISTORY_TERMINAL_PREFIX_BYTES: usize = 2 + 8 + 32 + 1 + 2;
const SELECTED_HISTORY_TERMINAL_VERSION: u16 = 1;
const ACCEPTED_BLOCK_CERTIFICATE_BINDING_MAGIC: [u8; 4] = *b"ACB1";
const ACCEPTED_BLOCK_CERTIFICATE_BINDING_BYTES: usize = 4 + 8 + 32 + 8;
const RETAINED_PAYLOAD_PRUNE_WATERMARK_MAGIC: [u8; 4] = *b"RPW1";
const RETAINED_PAYLOAD_PRUNE_WATERMARK_BYTES: usize = 4 + 8;
/// Bound numeric work even when selected coverage jumps millions of heights.
const RETAINED_PAYLOAD_PRUNE_HEIGHT_LIMIT: usize = 16;
/// A valid accepted block is bounded to 48 MiB of proof/sidecar bytes plus a
/// small body and derived acceptance material.  A corrupt oversized record
/// fails closed instead of turning maintenance into an unbounded page-retire.
const RETAINED_PAYLOAD_PRUNE_BYTE_LIMIT: usize = 64 * 1024 * 1024;
/// Bound page deletions independently from the height cap. A fully populated
/// height consumes six deletes, so at most ten such heights retire per call.
const RETAINED_PAYLOAD_PRUNE_DELETE_LIMIT: usize = 64;
/// Bound both page retirement and cursor work in one selected-history journal
/// maintenance transaction. One result may occupy the full history-proof wire
/// cap, so this count is deliberately small and maintenance is incremental.
const SELECTED_HISTORY_JOURNAL_COMPACTION_ENTRY_LIMIT: usize = 16;

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

/// Fixed-width pointer to the newest locally verified contiguous selected
/// history result. The proof bytes remain in the result table and are loaded
/// only by an explicit serving/snapshot request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelectedHistoryCoverage {
    pub height: u64,
    pub block_hash: [u8; 32],
}

/// A selected terminal package already verified by the recursive decider and
/// bound to the snapshot header chosen by local header consensus.
///
/// The chain store remains recursion-independent: it rechecks canonical
/// height/hash, fixed wire framing, byte bounds and tier metadata, then seeds
/// the Complete job/result/coverage records in the same transaction that
/// installs snapshot state.
#[derive(Debug, Clone, Copy)]
pub struct SelectedHistorySnapshotSeed<'a> {
    pub height: u64,
    pub block_hash: [u8; 32],
    pub tier: RecursiveProofJobTier,
    pub terminal_package_bytes: &'a [u8],
}

/// One selected-history terminal that was cryptographically verified by the
/// ordinary-node recursive verifier before entering chain storage.
///
/// This type is an import contract, not recursive authority: `MdbxStore`
/// deliberately has no dependency on `noid_recursive`.  The atomic import
/// rechecks every storage-level binding (wire cap and prefix, canonical target,
/// terminal tier, and the exact transaction-epoch anchor identity) before it
/// changes durable coverage.
#[derive(Debug, Clone, Copy)]
pub struct VerifiedSelectedHistoryTerminalImport<'a> {
    pub height: u64,
    pub block_hash: [u8; 32],
    pub epoch_anchor_height: u64,
    pub epoch_anchor_hash: [u8; 32],
    pub tier: RecursiveProofJobTier,
    pub terminal_package_bytes: &'a [u8],
}

/// One atomically loaded, ownership-transferring input bundle for the selected
/// recursive proof worker.
///
/// All fields come from one MDBX read snapshot.  In particular,
/// `source_tip` names the exact canonical tip against which the current and
/// parent headers were checked.  Large records are length-preflighted before
/// allocation and this type deliberately does not implement `Clone`: the
/// worker must move each payload into the next phase instead of duplicating a
/// block proof or authorization sidecar in RAM.
#[derive(Debug)]
pub struct ClaimedRecursiveProofJobInputs {
    pub job: RecursiveProofJob,
    pub source_tip: (u64, [u8; 32]),
    pub parent_header: BlockHeader,
    pub block_header: BlockHeader,
    pub user_transaction_count: usize,
    pub block_bytes: Vec<u8>,
    pub block_proof_bytes: Vec<u8>,
    pub block_auth_sidecar_bytes: Vec<u8>,
    pub previous_result: Option<RecursiveProofJobResult>,
}

#[derive(Debug, Clone, Copy)]
struct ClaimedRecursiveProofInputLengths {
    block: Option<usize>,
    proof: Option<usize>,
    sidecar: Option<usize>,
    previous_result: Option<usize>,
}

fn validate_claimed_recursive_proof_input_lengths(
    height: u64,
    lengths: ClaimedRecursiveProofInputLengths,
    require_previous_result: bool,
) -> Result<(), StoreError> {
    use crate::consensus::wire_limits::{
        proof_sidecar_combined_len_ok, MAX_BLOCK_AUTH_SIDECAR_BYTES, MAX_BLOCK_BYTES,
        MAX_BLOCK_PROOF_BYTES,
    };

    let block_len = lengths.block.ok_or(StoreError::Decode(
        "recursive proof source block is missing or pruned",
    ))?;
    if block_len == 0 || block_len > MAX_BLOCK_BYTES {
        return Err(StoreError::Decode(
            "recursive proof source block stored length exceeds hard bounds",
        ));
    }

    if lengths.proof.is_some() != lengths.sidecar.is_some() {
        return Err(StoreError::Decode(
            "recursive proof source proof/sidecar presence mismatch",
        ));
    }
    if let (Some(proof_len), Some(sidecar_len)) = (lengths.proof, lengths.sidecar) {
        if proof_len > MAX_BLOCK_PROOF_BYTES
            || sidecar_len > MAX_BLOCK_AUTH_SIDECAR_BYTES
            || !proof_sidecar_combined_len_ok(proof_len, sidecar_len)
        {
            return Err(StoreError::Decode(
                "recursive proof source proof/sidecar stored length exceeds hard bounds",
            ));
        }
    }

    if height == 1 || !require_previous_result {
        if lengths.previous_result.is_some() {
            return Err(StoreError::Decode(
                "recursive proof input unexpectedly selected a predecessor result",
            ));
        }
    } else {
        let result_len = lengths.previous_result.ok_or(StoreError::Decode(
            "previous recursive proof result is missing",
        ))?;
        if result_len < RECURSIVE_PROOF_RESULT_HEADER_BYTES
            || result_len
                > RECURSIVE_PROOF_RESULT_HEADER_BYTES + MAX_RECURSIVE_PROOF_JOB_RESULT_BYTES
        {
            return Err(StoreError::Decode(
                "previous recursive proof result stored length exceeds hard bounds",
            ));
        }
    }
    Ok(())
}

/// Check the retained block framing and detached-witness class without
/// materializing a second transaction vector.
fn inspect_recursive_proof_source_block(
    bytes: &[u8],
    expected_header: &BlockHeader,
    expected_tier: RecursiveProofJobTier,
) -> Result<usize, StoreError> {
    use crate::block::{
        canonical_block_wire_len, BLOCK_WIRE_FIXED_OVERHEAD, BLOCK_WIRE_HEADER_OFFSET,
        BLOCK_WIRE_MARKER,
    };
    use crate::wire::BLOCK_HEADER_WIRE_SIZE;

    if bytes.len() < BLOCK_WIRE_FIXED_OVERHEAD || bytes[0] != BLOCK_WIRE_MARKER {
        return Err(StoreError::Decode(
            "recursive proof source block framing is invalid",
        ));
    }
    let header_end = BLOCK_WIRE_HEADER_OFFSET + BLOCK_HEADER_WIRE_SIZE;
    let stored_header = decode_header(&bytes[BLOCK_WIRE_HEADER_OFFSET..header_end]).ok_or(
        StoreError::Decode("recursive proof source block header is invalid"),
    )?;
    if stored_header != *expected_header {
        return Err(StoreError::Decode(
            "recursive proof source block header is not canonical",
        ));
    }
    let tx_count = u32::from_le_bytes(
        bytes[header_end..BLOCK_WIRE_FIXED_OVERHEAD]
            .try_into()
            .map_err(|_| StoreError::Decode("recursive proof source tx count is invalid"))?,
    ) as usize;
    let expected_len = canonical_block_wire_len(tx_count)
        .map_err(|_| StoreError::Decode("recursive proof source tx count exceeds hard bounds"))?;
    if bytes.len() != expected_len || tx_count == 0 {
        return Err(StoreError::Decode(
            "recursive proof source block has a non-canonical stored length",
        ));
    }

    let transaction_bytes = &bytes[BLOCK_WIRE_FIXED_OVERHEAD..];
    for (index, encoded) in transaction_bytes
        .chunks_exact(noid_tx::TX_BODY_WIRE_SIZE)
        .enumerate()
    {
        let body = noid_tx::TxBody::from_bytes(encoded)
            .map_err(|_| StoreError::Decode("recursive proof source transaction is invalid"))?;
        if (index == 0) != body.is_coinbase {
            return Err(StoreError::Decode(
                "recursive proof source block has a non-canonical coinbase position",
            ));
        }
    }
    let user_transaction_count = tx_count - 1;
    if RecursiveProofJobTier::for_user_transaction_count(user_transaction_count)
        != Some(expected_tier)
    {
        return Err(StoreError::Decode(
            "recursive proof job tier does not match its retained block",
        ));
    }
    Ok(user_transaction_count)
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
    let (block_hash, payload) = decode_recursive_proof_result_ref(&encoded)?;
    let declared = payload.len();
    encoded.copy_within(RECURSIVE_PROOF_RESULT_HEADER_BYTES.., 0);
    encoded.truncate(declared);
    Some(RecursiveProofJobResult {
        height,
        block_hash,
        bytes: encoded,
    })
}

/// Borrow a proof result directly from an MDBX page.  Coverage validation uses
/// this view so a monotonic import never allocates the previous terminal proof.
fn decode_recursive_proof_result_ref(encoded: &[u8]) -> Option<([u8; 32], &[u8])> {
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
    Some((block_hash, &encoded[RECURSIVE_PROOF_RESULT_HEADER_BYTES..]))
}

fn encode_selected_history_coverage(
    coverage: SelectedHistoryCoverage,
) -> [u8; SELECTED_HISTORY_COVERAGE_ENCODED_BYTES] {
    let mut encoded = [0u8; SELECTED_HISTORY_COVERAGE_ENCODED_BYTES];
    encoded[..4].copy_from_slice(&SELECTED_HISTORY_COVERAGE_MAGIC);
    encoded[4..12].copy_from_slice(&coverage.height.to_le_bytes());
    encoded[12..44].copy_from_slice(&coverage.block_hash);
    encoded
}

fn decode_selected_history_coverage(bytes: &[u8]) -> Option<SelectedHistoryCoverage> {
    if bytes.len() != SELECTED_HISTORY_COVERAGE_ENCODED_BYTES
        || bytes[..4] != SELECTED_HISTORY_COVERAGE_MAGIC
    {
        return None;
    }
    Some(SelectedHistoryCoverage {
        height: u64::from_le_bytes(bytes[4..12].try_into().ok()?),
        block_hash: bytes[12..44].try_into().ok()?,
    })
}

// ---------------------------------------------------------------------------
// Selected-history forward ladder cursor
// ---------------------------------------------------------------------------

const SELECTED_HISTORY_LADDER_META_MAGIC: [u8; 4] = *b"SLM1";
const SELECTED_HISTORY_LADDER_META_HEADER_BYTES: usize = 4 + 8 + 32 + 4 + 8 + 8 + 2;
const SELECTED_HISTORY_LADDER_META_ENTRY_BYTES: usize = 2 + 4 + 32;

/// Durable boundary of the selected-history forward ladder cursor.
///
/// `segment_summaries` holds `(segment_id, live_count, exact_segment_root)`
/// for every live segment at the covered height, strictly ascending. The raw
/// columns live in `T_LADDER_SEGMENTS` under the same segment identities.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectedHistoryLadderMeta {
    pub height: u64,
    pub block_hash: [u8; 32],
    pub log_slots: u32,
    pub active_slot_count: u64,
    pub alloc_counter: u64,
    pub segment_summaries: Vec<(u16, u32, [u8; 32])>,
}

#[inline]
fn ladder_segment_key(segment_id: u16) -> [u8; 2] {
    segment_id.to_be_bytes()
}

#[inline]
fn ladder_segment_domain(log_slots: u32) -> Option<usize> {
    if log_slots == 0 || log_slots > crate::consensus::params::LOG_SLOTS_MAX {
        return None;
    }
    if log_slots <= crate::consensus::params::LOG_SEGMENT_SIZE {
        return Some(1);
    }
    1usize.checked_shl(log_slots - crate::consensus::params::LOG_SEGMENT_SIZE)
}

#[inline]
fn ladder_effective_log(log_slots: u32) -> u8 {
    log_slots.min(crate::consensus::params::LOG_SEGMENT_SIZE) as u8
}

fn encode_selected_history_ladder_meta(
    meta: &SelectedHistoryLadderMeta,
) -> Result<Vec<u8>, StoreError> {
    let entry_count = u16::try_from(meta.segment_summaries.len())
        .map_err(|_| StoreError::Decode("ladder meta summary count exceeds the record format"))?;
    let mut encoded = Vec::with_capacity(
        SELECTED_HISTORY_LADDER_META_HEADER_BYTES
            + meta.segment_summaries.len() * SELECTED_HISTORY_LADDER_META_ENTRY_BYTES,
    );
    encoded.extend_from_slice(&SELECTED_HISTORY_LADDER_META_MAGIC);
    encoded.extend_from_slice(&meta.height.to_le_bytes());
    encoded.extend_from_slice(&meta.block_hash);
    encoded.extend_from_slice(&meta.log_slots.to_le_bytes());
    encoded.extend_from_slice(&meta.active_slot_count.to_le_bytes());
    encoded.extend_from_slice(&meta.alloc_counter.to_le_bytes());
    encoded.extend_from_slice(&entry_count.to_le_bytes());
    for &(segment_id, live_count, exact_root) in &meta.segment_summaries {
        encoded.extend_from_slice(&segment_id.to_le_bytes());
        encoded.extend_from_slice(&live_count.to_le_bytes());
        encoded.extend_from_slice(&exact_root);
    }
    Ok(encoded)
}

fn decode_selected_history_ladder_meta(bytes: &[u8]) -> Option<SelectedHistoryLadderMeta> {
    if bytes.len() < SELECTED_HISTORY_LADDER_META_HEADER_BYTES
        || bytes[..4] != SELECTED_HISTORY_LADDER_META_MAGIC
    {
        return None;
    }
    let height = u64::from_le_bytes(bytes[4..12].try_into().ok()?);
    let block_hash: [u8; 32] = bytes[12..44].try_into().ok()?;
    let log_slots = u32::from_le_bytes(bytes[44..48].try_into().ok()?);
    let active_slot_count = u64::from_le_bytes(bytes[48..56].try_into().ok()?);
    let alloc_counter = u64::from_le_bytes(bytes[56..64].try_into().ok()?);
    let entry_count = usize::from(u16::from_le_bytes(bytes[64..66].try_into().ok()?));

    let domain = ladder_segment_domain(log_slots)?;
    let capacity = 1u64.checked_shl(log_slots)?;
    if entry_count > domain
        || active_slot_count > capacity
        || active_slot_count > alloc_counter
        || bytes.len()
            != SELECTED_HISTORY_LADDER_META_HEADER_BYTES
                .checked_add(entry_count.checked_mul(SELECTED_HISTORY_LADDER_META_ENTRY_BYTES)?)?
    {
        return None;
    }

    let mut segment_summaries = Vec::with_capacity(entry_count);
    let mut counted_live = 0u64;
    let mut previous_segment = None;
    for index in 0..entry_count {
        let offset = SELECTED_HISTORY_LADDER_META_HEADER_BYTES
            + index * SELECTED_HISTORY_LADDER_META_ENTRY_BYTES;
        let segment_id = u16::from_le_bytes(bytes[offset..offset + 2].try_into().ok()?);
        let live_count = u32::from_le_bytes(bytes[offset + 2..offset + 6].try_into().ok()?);
        let exact_root: [u8; 32] = bytes[offset + 6..offset + 38].try_into().ok()?;
        if live_count == 0
            || usize::from(segment_id) >= domain
            || previous_segment.is_some_and(|previous| previous >= segment_id)
        {
            return None;
        }
        previous_segment = Some(segment_id);
        counted_live = counted_live.checked_add(u64::from(live_count))?;
        segment_summaries.push((segment_id, live_count, exact_root));
    }
    if counted_live != active_slot_count {
        return None;
    }

    Some(SelectedHistoryLadderMeta {
        height,
        block_hash,
        log_slots,
        active_slot_count,
        alloc_counter,
        segment_summaries,
    })
}

fn selected_history_ladder_meta_in_rw_txn(
    txn: &Transaction<'_, RW, NoWriteMap>,
) -> Result<Option<SelectedHistoryLadderMeta>, StoreError> {
    let table = txn.open_table(Some(T_LADDER_META))?;
    let raw: Option<Vec<u8>> = txn.get(&table, KEY_LADDER_META)?;
    raw.map(|raw| {
        decode_selected_history_ladder_meta(&raw)
            .ok_or(StoreError::Decode("invalid selected-history ladder meta"))
    })
    .transpose()
}

fn clear_selected_history_ladder_cursor_in_rw_txn(
    txn: &Transaction<'_, RW, NoWriteMap>,
) -> Result<(), StoreError> {
    for name in [T_LADDER_META, T_LADDER_SEGMENTS] {
        let table = txn.open_table(Some(name))?;
        txn.clear_table(&table)?;
    }
    Ok(())
}

/// Validate one ladder cursor advance against its canonical header and apply
/// it. A self-contained update (dirty columns cover every live segment)
/// atomically replaces the whole cursor; a layered update requires the exact
/// predecessor boundary to already be durable.
fn apply_selected_history_ladder_update_in_rw_txn(
    txn: &Transaction<'_, RW, NoWriteMap>,
    header: &BlockHeader,
    block_hash: [u8; 32],
    update: &SelectedHistoryLadderUpdate,
) -> Result<(), StoreError> {
    if update.log_slots != header.log_slots
        || update.active_slot_count != header.active_slot_count
        || update.alloc_counter != header.alloc_counter
        || update.state_root != header.state_root
    {
        return Err(StoreError::Decode(
            "ladder update does not match its canonical header",
        ));
    }
    let domain = ladder_segment_domain(header.log_slots).ok_or(StoreError::Decode(
        "ladder update header slot depth is outside the consensus domain",
    ))?;
    let effective_log = ladder_effective_log(header.log_slots);
    let segment_len = 1usize << effective_log;

    let mut counted_live = 0u64;
    let mut previous_segment = None;
    for &(segment_id, live_count, _) in &update.segment_summaries {
        if live_count == 0
            || usize::from(segment_id) >= domain
            || previous_segment.is_some_and(|previous| previous >= segment_id)
        {
            return Err(StoreError::Decode(
                "ladder update segment summaries are malformed",
            ));
        }
        previous_segment = Some(segment_id);
        counted_live = counted_live
            .checked_add(u64::from(live_count))
            .ok_or(StoreError::Decode("ladder update live count overflow"))?;
    }
    if counted_live != header.active_slot_count {
        return Err(StoreError::Decode(
            "ladder update live counts disagree with the canonical header",
        ));
    }
    let exact_entries: Vec<(u16, [u8; 32])> = update
        .segment_summaries
        .iter()
        .map(|&(segment_id, _, exact_root)| (segment_id, exact_root))
        .collect();
    if exact_state_root_from_segment_summaries(header.log_slots as usize, &exact_entries)
        != Some(header.state_root)
    {
        return Err(StoreError::Decode(
            "ladder update summaries do not commit to the header state root",
        ));
    }

    let mut previous_dirty = None;
    for (segment_id, columns) in &update.dirty_segments {
        if usize::from(*segment_id) >= domain
            || previous_dirty.is_some_and(|previous| previous >= *segment_id)
        {
            return Err(StoreError::Decode(
                "ladder update dirty segments are malformed",
            ));
        }
        previous_dirty = Some(*segment_id);
        let live = update
            .segment_summaries
            .binary_search_by_key(segment_id, |&(id, _, _)| id)
            .is_ok();
        match (live, columns) {
            (true, Some(columns)) => {
                if columns.values.len() != segment_len
                    || columns.owners_hi.len() != segment_len
                    || columns.owners_lo.len() != segment_len
                    || segment_columns_empty(columns)
                {
                    return Err(StoreError::Decode(
                        "ladder update dirty columns do not match their summary",
                    ));
                }
            }
            (false, None) => {}
            _ => {
                return Err(StoreError::Decode(
                    "ladder update dirty payload presence disagrees with its summary",
                ));
            }
        }
    }

    let self_contained = update.segment_summaries.iter().all(|&(segment_id, _, _)| {
        update
            .dirty_segments
            .binary_search_by_key(&segment_id, |(id, _)| *id)
            .is_ok()
    });
    if self_contained {
        clear_selected_history_ladder_cursor_in_rw_txn(txn)?;
    } else {
        let previous = selected_history_ladder_meta_in_rw_txn(txn)?.ok_or(StoreError::Decode(
            "layered ladder update requires an existing cursor boundary",
        ))?;
        if previous.height.checked_add(1) != Some(header.height)
            || previous.block_hash != header.prev_block_hash
        {
            return Err(StoreError::Decode(
                "ladder update is not the exact successor of the durable cursor",
            ));
        }
        if ladder_effective_log(previous.log_slots) != effective_log
            || (header.log_slots != previous.log_slots
                && header.log_slots != previous.log_slots.saturating_add(1))
        {
            return Err(StoreError::Decode(
                "ladder update slot-domain transition is invalid",
            ));
        }
    }

    let segments = txn.open_table(Some(T_LADDER_SEGMENTS))?;
    for (segment_id, columns) in &update.dirty_segments {
        let key = ladder_segment_key(*segment_id);
        match columns {
            None => {
                let _ = txn.del(&segments, key, None);
            }
            Some(columns) => {
                txn.put(
                    &segments,
                    key,
                    encode_segment(columns, effective_log),
                    WriteFlags::empty(),
                )?;
            }
        }
    }
    let meta_table = txn.open_table(Some(T_LADDER_META))?;
    txn.put(
        &meta_table,
        KEY_LADDER_META,
        encode_selected_history_ladder_meta(&SelectedHistoryLadderMeta {
            height: header.height,
            block_hash,
            log_slots: header.log_slots,
            active_slot_count: header.active_slot_count,
            alloc_counter: header.alloc_counter,
            segment_summaries: update.segment_summaries.clone(),
        })?,
        WriteFlags::empty(),
    )?;
    Ok(())
}

/// Roll the ladder cursor back to the reorg ancestor inside the caller's
/// canonical write transaction, using the same undo logs the reorg consumes.
///
/// Any local inconsistency clears the cursor instead of failing the reorg;
/// the fail-closed bootstrap rebuilds it afterwards. Only MDBX-level errors
/// propagate. Must run before the transaction truncates old undo records.
fn rewind_selected_history_ladder_cursor(
    txn: &Transaction<'_, RW, NoWriteMap>,
    ancestor_height: u64,
) -> Result<(), StoreError> {
    let meta_table = txn.open_table(Some(T_LADDER_META))?;
    let raw: Option<Vec<u8>> = txn.get(&meta_table, KEY_LADDER_META)?;
    let Some(raw) = raw else {
        return Ok(());
    };
    let Some(meta) = decode_selected_history_ladder_meta(&raw) else {
        return clear_selected_history_ladder_cursor_in_rw_txn(txn);
    };
    if meta.height <= ancestor_height {
        return Ok(());
    }
    match rewind_selected_history_ladder_cursor_inner(txn, ancestor_height, meta) {
        Ok(()) => Ok(()),
        Err(StoreError::Decode(_)) => clear_selected_history_ladder_cursor_in_rw_txn(txn),
        Err(error) => Err(error),
    }
}

fn rewind_selected_history_ladder_cursor_inner(
    txn: &Transaction<'_, RW, NoWriteMap>,
    ancestor_height: u64,
    meta: SelectedHistoryLadderMeta,
) -> Result<(), StoreError> {
    use crate::consensus::params::{BLOCK_MAX_ACTIONS, UNDO_RETENTION_DEPTH};
    use crate::fri_state::SlotValue;

    if meta.height - ancestor_height > UNDO_RETENTION_DEPTH {
        return Err(StoreError::Decode(
            "ladder rewind depth exceeds the retained undo window",
        ));
    }
    let headers = txn.open_table(Some(T_HEADERS))?;
    let ancestor_raw: Option<Vec<u8>> = txn.get(&headers, &u64_key(ancestor_height))?;
    let ancestor = ancestor_raw
        .as_deref()
        .and_then(decode_header)
        .filter(|header| header.height == ancestor_height)
        .ok_or(StoreError::Decode(
            "ladder rewind ancestor header is missing",
        ))?;
    let effective_log = ladder_effective_log(meta.log_slots);
    if ladder_effective_log(ancestor.log_slots) != effective_log
        || ancestor.log_slots > meta.log_slots
    {
        return Err(StoreError::Decode(
            "ladder rewind slot-domain transition is unsupported",
        ));
    }
    let meta_domain = ladder_segment_domain(meta.log_slots)
        .ok_or(StoreError::Decode("ladder rewind cursor domain is invalid"))?;
    let ancestor_domain = ladder_segment_domain(ancestor.log_slots).ok_or(StoreError::Decode(
        "ladder rewind ancestor domain is invalid",
    ))?;

    // Group pre-images newest-first exactly like historical reconstruction.
    let undo_table = txn.open_table(Some(T_UNDO_LOGS))?;
    let mut grouped: std::collections::BTreeMap<u16, Vec<(u32, SlotValue)>> =
        std::collections::BTreeMap::new();
    for height in (ancestor_height + 1..=meta.height).rev() {
        let undo_raw: Option<Vec<u8>> = txn.get(&undo_table, &u64_key(height))?;
        let undo = undo_raw
            .as_deref()
            .and_then(decode_undo_log)
            .filter(|undo| undo.block_height == height)
            .ok_or(StoreError::Decode("ladder rewind undo log is missing"))?;
        if undo.slot_changes.len() > BLOCK_MAX_ACTIONS {
            return Err(StoreError::Decode("ladder rewind undo log is oversized"));
        }
        if height == ancestor_height + 1
            && (undo.log_slots_before != ancestor.log_slots
                || undo.active_slot_count_before != ancestor.active_slot_count
                || undo.alloc_counter_before != ancestor.alloc_counter)
        {
            return Err(StoreError::Decode(
                "ladder rewind undo boundary does not match the ancestor header",
            ));
        }
        for &(slot_index, previous) in undo.slot_changes.iter().rev() {
            let segment_id = (slot_index >> effective_log) as u16;
            if usize::from(segment_id) >= meta_domain {
                return Err(StoreError::Decode(
                    "ladder rewind undo slot lies outside the cursor domain",
                ));
            }
            grouped
                .entry(segment_id)
                .or_default()
                .push((slot_index, previous));
        }
    }

    let mut summaries: std::collections::BTreeMap<u16, (u32, [u8; 32])> = meta
        .segment_summaries
        .iter()
        .map(|&(segment_id, live_count, exact_root)| (segment_id, (live_count, exact_root)))
        .collect();
    let segments = txn.open_table(Some(T_LADDER_SEGMENTS))?;
    let segment_len = 1usize << effective_log;
    let local_mask = (1u32 << effective_log) - 1;
    for (segment_id, changes) in grouped {
        let key = ladder_segment_key(segment_id);
        let record: Option<Vec<u8>> = txn.get(&segments, &key)?;
        let mut columns = match record {
            Some(record) => {
                let (stored_log, columns) = decode_segment(&record).ok_or(StoreError::Decode(
                    "ladder rewind stored segment is invalid",
                ))?;
                if stored_log != effective_log || columns.values.len() != segment_len {
                    return Err(StoreError::Decode(
                        "ladder rewind stored segment shape mismatch",
                    ));
                }
                if !summaries.contains_key(&segment_id) {
                    return Err(StoreError::Decode(
                        "ladder rewind found a payload for an empty segment",
                    ));
                }
                columns
            }
            None => {
                if summaries.contains_key(&segment_id) {
                    return Err(StoreError::Decode(
                        "ladder rewind live segment has no payload",
                    ));
                }
                SegmentColumns::new_zero(segment_len)
            }
        };
        let mut live_count = 0u32;
        for &(slot_index, previous) in &changes {
            let local = (slot_index & local_mask) as usize;
            columns.values[local] = previous.value;
            columns.owners_hi[local] = previous.owner_hi;
            columns.owners_lo[local] = previous.owner_lo;
        }
        for local in 0..segment_len {
            let slot = SlotValue {
                value: columns.values[local],
                owner_hi: columns.owners_hi[local],
                owner_lo: columns.owners_lo[local],
            };
            if !slot.is_empty() {
                live_count = live_count
                    .checked_add(1)
                    .ok_or(StoreError::Decode("ladder rewind live count overflow"))?;
            }
        }
        if live_count == 0 {
            let _ = txn.del(&segments, key, None);
            summaries.remove(&segment_id);
        } else {
            txn.put(
                &segments,
                key,
                encode_segment(&columns, effective_log),
                WriteFlags::empty(),
            )?;
            summaries.insert(
                segment_id,
                (
                    live_count,
                    exact_segment_root_from_columns(usize::from(effective_log), &columns),
                ),
            );
        }
    }

    // A rewind across an expansion shrinks the domain; the discarded upper
    // half must already be canonical zero.
    if summaries
        .keys()
        .any(|segment_id| usize::from(*segment_id) >= ancestor_domain)
    {
        return Err(StoreError::Decode(
            "ladder rewind upper-half segment is still live below the expansion",
        ));
    }
    if ancestor_domain < meta_domain {
        let mut stale = Vec::new();
        {
            let mut cursor = txn.cursor(&segments)?;
            let mut item: Option<(Vec<u8>, ())> =
                cursor.set_range(&ladder_segment_key(ancestor_domain as u16))?;
            while let Some((key, ())) = item {
                stale.push(key);
                item = cursor.next()?;
            }
        }
        for key in stale {
            txn.del(&segments, &key, None)?;
        }
    }

    let mut counted_live = 0u64;
    let mut segment_summaries = Vec::with_capacity(summaries.len());
    let mut exact_entries = Vec::with_capacity(summaries.len());
    for (segment_id, (live_count, exact_root)) in summaries {
        counted_live = counted_live
            .checked_add(u64::from(live_count))
            .ok_or(StoreError::Decode("ladder rewind live count overflow"))?;
        segment_summaries.push((segment_id, live_count, exact_root));
        exact_entries.push((segment_id, exact_root));
    }
    if counted_live != ancestor.active_slot_count
        || exact_state_root_from_segment_summaries(ancestor.log_slots as usize, &exact_entries)
            != Some(ancestor.state_root)
    {
        return Err(StoreError::Decode(
            "ladder rewind does not commit to the ancestor header",
        ));
    }

    let meta_table = txn.open_table(Some(T_LADDER_META))?;
    txn.put(
        &meta_table,
        KEY_LADDER_META,
        encode_selected_history_ladder_meta(&SelectedHistoryLadderMeta {
            height: ancestor_height,
            block_hash: crate::block_header::block_id(&ancestor),
            log_slots: ancestor.log_slots,
            active_slot_count: ancestor.active_slot_count,
            alloc_counter: ancestor.alloc_counter,
            segment_summaries,
        })?,
        WriteFlags::empty(),
    )?;
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AcceptedBlockCertificateBinding {
    height: u64,
    block_hash: [u8; 32],
    certificate_len: u64,
}

fn encode_accepted_block_certificate_binding(
    height: u64,
    block_hash: [u8; 32],
    certificate_len: usize,
) -> Result<[u8; ACCEPTED_BLOCK_CERTIFICATE_BINDING_BYTES], StoreError> {
    let certificate_len = u64::try_from(certificate_len)
        .map_err(|_| StoreError::Decode("accepted block certificate length exceeds u64"))?;
    let mut encoded = [0u8; ACCEPTED_BLOCK_CERTIFICATE_BINDING_BYTES];
    encoded[..4].copy_from_slice(&ACCEPTED_BLOCK_CERTIFICATE_BINDING_MAGIC);
    encoded[4..12].copy_from_slice(&height.to_le_bytes());
    encoded[12..44].copy_from_slice(&block_hash);
    encoded[44..52].copy_from_slice(&certificate_len.to_le_bytes());
    Ok(encoded)
}

fn decode_accepted_block_certificate_binding(
    encoded: &[u8],
) -> Option<AcceptedBlockCertificateBinding> {
    if encoded.len() != ACCEPTED_BLOCK_CERTIFICATE_BINDING_BYTES
        || encoded[..4] != ACCEPTED_BLOCK_CERTIFICATE_BINDING_MAGIC
    {
        return None;
    }
    Some(AcceptedBlockCertificateBinding {
        height: u64::from_le_bytes(encoded[4..12].try_into().ok()?),
        block_hash: encoded[12..44].try_into().ok()?,
        certificate_len: u64::from_le_bytes(encoded[44..52].try_into().ok()?),
    })
}

fn encode_retained_payload_prune_watermark(
    height: u64,
) -> [u8; RETAINED_PAYLOAD_PRUNE_WATERMARK_BYTES] {
    let mut encoded = [0u8; RETAINED_PAYLOAD_PRUNE_WATERMARK_BYTES];
    encoded[..4].copy_from_slice(&RETAINED_PAYLOAD_PRUNE_WATERMARK_MAGIC);
    encoded[4..].copy_from_slice(&height.to_le_bytes());
    encoded
}

fn decode_retained_payload_prune_watermark(encoded: &[u8]) -> Option<u64> {
    if encoded.len() != RETAINED_PAYLOAD_PRUNE_WATERMARK_BYTES
        || encoded[..4] != RETAINED_PAYLOAD_PRUNE_WATERMARK_MAGIC
    {
        return None;
    }
    Some(u64::from_le_bytes(encoded[4..12].try_into().ok()?))
}

fn retained_payload_prune_watermark_in_rw_txn(
    txn: &Transaction<'_, RW, NoWriteMap>,
) -> Result<Option<u64>, StoreError> {
    let table = txn.open_table(Some(T_CHECKPOINT_COVERAGE))?;
    let raw: Option<[u8; RETAINED_PAYLOAD_PRUNE_WATERMARK_BYTES]> =
        txn.get(&table, KEY_RETAINED_PAYLOAD_PRUNE_WATERMARK)?;
    raw.as_ref()
        .map(|raw| {
            decode_retained_payload_prune_watermark(raw).ok_or(StoreError::Decode(
                "invalid retained payload prune watermark",
            ))
        })
        .transpose()
}

fn set_retained_payload_prune_watermark(
    txn: &Transaction<'_, RW, NoWriteMap>,
    height: u64,
) -> Result<(), StoreError> {
    let table = txn.open_table(Some(T_CHECKPOINT_COVERAGE))?;
    txn.put(
        &table,
        KEY_RETAINED_PAYLOAD_PRUNE_WATERMARK,
        encode_retained_payload_prune_watermark(height),
        WriteFlags::empty(),
    )?;
    Ok(())
}

fn rewind_retained_payload_prune_watermark(
    txn: &Transaction<'_, RW, NoWriteMap>,
    ancestor_height: u64,
) -> Result<(), StoreError> {
    let Some(current) = retained_payload_prune_watermark_in_rw_txn(txn)? else {
        return Ok(());
    };
    if current <= ancestor_height {
        return Ok(());
    }
    if ancestor_height == 0 {
        let table = txn.open_table(Some(T_CHECKPOINT_COVERAGE))?;
        let _ = txn.del(&table, KEY_RETAINED_PAYLOAD_PRUNE_WATERMARK, None);
    } else {
        set_retained_payload_prune_watermark(txn, ancestor_height)?;
    }
    Ok(())
}

fn selected_history_terminal_prefix_matches(
    bytes: &[u8],
    height: u64,
    block_hash: [u8; 32],
) -> bool {
    selected_history_terminal_metadata(bytes).is_some_and(|(actual_height, actual_hash, _)| {
        actual_height == height && actual_hash == block_hash
    })
}

fn selected_history_terminal_matches_job(
    bytes: &[u8],
    height: u64,
    block_hash: [u8; 32],
    tier: RecursiveProofJobTier,
) -> bool {
    selected_history_terminal_metadata(bytes).is_some_and(
        |(actual_height, actual_hash, actual_tier)| {
            actual_height == height && actual_hash == block_hash && actual_tier == tier
        },
    )
}

fn selected_history_terminal_metadata(
    bytes: &[u8],
) -> Option<(u64, [u8; 32], RecursiveProofJobTier)> {
    if bytes.len() < SELECTED_HISTORY_TERMINAL_PREFIX_BYTES
        || u16::from_le_bytes(bytes[..2].try_into().ok()?) != SELECTED_HISTORY_TERMINAL_VERSION
    {
        return None;
    }
    let height = u64::from_le_bytes(bytes[2..10].try_into().ok()?);
    let block_hash = bytes[10..42].try_into().ok()?;
    let slot = bytes[42];
    let tier = u16::from_le_bytes(bytes[43..45].try_into().ok()?);
    let job_tier = match (slot, tier) {
        (0, 8) => RecursiveProofJobTier::B8,
        (1, 32) => RecursiveProofJobTier::B32,
        (2, 64) => RecursiveProofJobTier::B64,
        (3, 255) => RecursiveProofJobTier::B255,
        _ => return None,
    };
    Some((height, block_hash, job_tier))
}

/// Validate the current compact coverage authority without copying its proof
/// out of the MDBX page.  An import must not silently paper over a torn,
/// forked, or malformed older pointer.
fn validate_selected_history_coverage_in_rw_txn(
    txn: &Transaction<'_, RW, NoWriteMap>,
    coverage: SelectedHistoryCoverage,
) -> Result<(), StoreError> {
    let headers = txn.open_table(Some(T_HEADERS))?;
    let header_raw: Option<Vec<u8>> = txn.get(&headers, &u64_key(coverage.height))?;
    let header = header_raw
        .as_deref()
        .and_then(decode_header)
        .ok_or(StoreError::Decode(
            "selected history coverage canonical header is missing",
        ))?;
    if header.height != coverage.height
        || crate::block_header::block_id(&header) != coverage.block_hash
    {
        return Err(StoreError::Decode(
            "selected history coverage is no longer canonical",
        ));
    }

    let key = recursive_proof_height_key(coverage.height);
    let jobs = txn.open_table(Some(T_RECURSIVE_PROOF_JOBS))?;
    let job_raw: Option<[u8; RECURSIVE_PROOF_JOB_ENCODED_BYTES]> = txn.get(&jobs, &key)?;
    let job = job_raw
        .as_ref()
        .and_then(|raw| decode_recursive_proof_job(coverage.height, raw))
        .ok_or(StoreError::Decode(
            "selected history coverage job is missing or malformed",
        ))?;
    if job.state != RecursiveProofJobState::Complete || job.block_hash != coverage.block_hash {
        return Err(StoreError::Decode(
            "selected history coverage job is not complete and canonical",
        ));
    }

    let results = txn.open_table(Some(T_RECURSIVE_PROOF_RESULTS))?;
    let result_length: Option<ObjectLength> = txn.get(&results, &key)?;
    let maximum = RECURSIVE_PROOF_RESULT_HEADER_BYTES
        + crate::consensus::wire_limits::MAX_HISTORY_PROOF_BYTES;
    let Some(ObjectLength(length)) = result_length else {
        return Err(StoreError::Decode(
            "selected history coverage result is missing",
        ));
    };
    if !(RECURSIVE_PROOF_RESULT_HEADER_BYTES..=maximum).contains(&length) {
        return Err(StoreError::Decode(
            "selected history coverage result exceeds hard bounds",
        ));
    }
    let encoded: Cow<'_, [u8]> = txn.get(&results, &key)?.ok_or(StoreError::Decode(
        "selected history coverage result disappeared",
    ))?;
    if encoded.len() != length {
        return Err(StoreError::Decode(
            "selected history coverage result length changed during validation",
        ));
    }
    let (result_hash, terminal) = decode_recursive_proof_result_ref(encoded.as_ref()).ok_or(
        StoreError::Decode("selected history coverage result wrapper is malformed"),
    )?;
    if result_hash != coverage.block_hash
        || !selected_history_terminal_matches_job(
            terminal,
            coverage.height,
            coverage.block_hash,
            job.tier,
        )
    {
        return Err(StoreError::Decode(
            "selected history coverage terminal binding is malformed",
        ));
    }
    Ok(())
}

/// Read and validate the one selected-history serving authority from the same
/// transaction that will use it. Covered journal records may remain while
/// bounded maintenance catches up, so callers must use this pointer rather
/// than infer coverage from the oldest retained job.
fn validated_selected_history_coverage_in_rw_txn(
    txn: &Transaction<'_, RW, NoWriteMap>,
) -> Result<Option<SelectedHistoryCoverage>, StoreError> {
    let coverage_table = txn.open_table(Some(T_CHECKPOINT_COVERAGE))?;
    let raw: Option<[u8; SELECTED_HISTORY_COVERAGE_ENCODED_BYTES]> =
        txn.get(&coverage_table, KEY_SELECTED_HISTORY_COVERAGE)?;
    let coverage = raw
        .as_ref()
        .map(|raw| {
            decode_selected_history_coverage(raw).ok_or(StoreError::Decode(
                "invalid selected history coverage pointer",
            ))
        })
        .transpose()?;
    if let Some(coverage) = coverage {
        validate_selected_history_coverage_in_rw_txn(txn, coverage)?;
    }
    Ok(coverage)
}

/// Rewind only the compact serving pointer inside an existing canonical reorg
/// transaction. Proof payloads are neither decoded nor loaded here.
fn rewind_selected_history_coverage(
    txn: &Transaction<'_, RW, NoWriteMap>,
    ancestor_height: u64,
) -> Result<(), StoreError> {
    let coverage_table = txn.open_table(Some(T_CHECKPOINT_COVERAGE))?;
    let raw: Option<[u8; SELECTED_HISTORY_COVERAGE_ENCODED_BYTES]> =
        txn.get(&coverage_table, KEY_SELECTED_HISTORY_COVERAGE)?;
    let Some(current) = raw
        .as_ref()
        .and_then(|raw| decode_selected_history_coverage(raw))
    else {
        if raw.is_some() {
            return Err(StoreError::Decode(
                "invalid selected history coverage pointer",
            ));
        }
        return Ok(());
    };
    if current.height <= ancestor_height {
        return Ok(());
    }

    let replacement = if ancestor_height == 0 {
        None
    } else {
        let key = recursive_proof_height_key(ancestor_height);
        let jobs = txn.open_table(Some(T_RECURSIVE_PROOF_JOBS))?;
        let job_raw: Option<[u8; RECURSIVE_PROOF_JOB_ENCODED_BYTES]> = txn.get(&jobs, &key)?;
        let job = job_raw
            .as_ref()
            .and_then(|raw| decode_recursive_proof_job(ancestor_height, raw));
        let headers = txn.open_table(Some(T_HEADERS))?;
        let canonical_hash = txn
            .get::<Vec<u8>>(&headers, &u64_key(ancestor_height))?
            .as_deref()
            .and_then(canonical_hash_from_encoded_header);
        let results = txn.open_table(Some(T_RECURSIVE_PROOF_RESULTS))?;
        let result_length = txn
            .get::<ObjectLength>(&results, &key)?
            .map(|ObjectLength(length)| length);
        job.filter(|job| {
            job.state == RecursiveProofJobState::Complete
                && canonical_hash == Some(job.block_hash)
                && result_length.is_some_and(|length| {
                    (RECURSIVE_PROOF_RESULT_HEADER_BYTES
                        ..=RECURSIVE_PROOF_RESULT_HEADER_BYTES
                            + crate::consensus::wire_limits::MAX_HISTORY_PROOF_BYTES)
                        .contains(&length)
                })
        })
        .map(|job| SelectedHistoryCoverage {
            height: ancestor_height,
            block_hash: job.block_hash,
        })
    };

    if let Some(replacement) = replacement {
        txn.put(
            &coverage_table,
            KEY_SELECTED_HISTORY_COVERAGE,
            encode_selected_history_coverage(replacement),
            WriteFlags::empty(),
        )?;
    } else {
        let _ = txn.del(&coverage_table, KEY_SELECTED_HISTORY_COVERAGE, None);
    }
    Ok(())
}

#[inline]
fn retained_payload_prune_budget_allows(
    retired_bytes: usize,
    deletes: usize,
    height_bytes: usize,
    height_deletes: usize,
) -> bool {
    retired_bytes
        .checked_add(height_bytes)
        .is_some_and(|total| total <= RETAINED_PAYLOAD_PRUNE_BYTE_LIMIT)
        && deletes
            .checked_add(height_deletes)
            .is_some_and(|total| total <= RETAINED_PAYLOAD_PRUNE_DELETE_LIMIT)
}

/// Delete at most one fixed numeric batch of selected-history-covered payloads.
///
/// Height tables retain legacy little-endian keys, so cursor order is not
/// numeric.  The durable watermark makes direct `u64_key(height)` reads both
/// crash-resumable and independent of table cardinality.  Every candidate
/// height is preflighted in full before the first delete at that height; the
/// transaction therefore never exposes a partially-pruned watermark.
fn prune_retained_payloads_bounded(
    txn: &Transaction<'_, RW, NoWriteMap>,
    current_height: u64,
) -> Result<(), StoreError> {
    if current_height <= RECENT_BLOCK_RETENTION_DEPTH {
        return Ok(());
    }

    let Some(coverage) = validated_selected_history_coverage_in_rw_txn(txn)? else {
        // Absence of recursive prefix authority is a normal prover/relay state.
        // In particular, it must not manufacture a prune frontier.
        return Ok(());
    };

    let consensus_table = txn.open_table(Some(T_CONSENSUS_META))?;
    let consensus_raw: Option<Cow<'_, [u8]>> = txn.get(&consensus_table, KEY_CONSENSUS_META)?;
    let consensus = consensus_raw
        .as_deref()
        .and_then(decode_consensus_meta)
        .ok_or(StoreError::Decode(
            "consensus metadata is missing during retained payload pruning",
        ))?;
    if consensus.tip_height != current_height || consensus.finalized.height > current_height {
        return Err(StoreError::Decode(
            "consensus heights disagree during retained payload pruning",
        ));
    }
    let headers = txn.open_table(Some(T_HEADERS))?;
    let finalized_raw: Option<Cow<'_, [u8]>> =
        txn.get(&headers, &u64_key(consensus.finalized.height))?;
    let finalized = finalized_raw
        .as_deref()
        .and_then(decode_header)
        .ok_or(StoreError::Decode(
            "finalized header is missing during retained payload pruning",
        ))?;
    if finalized.height != consensus.finalized.height
        || crate::block_header::block_id(&finalized) != consensus.finalized.hash
    {
        return Err(StoreError::Decode(
            "finalized checkpoint is not canonical during retained payload pruning",
        ));
    }

    let cutoff = (current_height - RECENT_BLOCK_RETENTION_DEPTH)
        .min(consensus.finalized.height)
        .min(coverage.height);
    let watermark = retained_payload_prune_watermark_in_rw_txn(txn)?;
    if watermark.is_some_and(|height| height > current_height) {
        return Err(StoreError::Decode(
            "retained payload prune watermark exceeds canonical tip",
        ));
    }
    let Some(mut height) = watermark.unwrap_or(0).checked_add(1) else {
        return Ok(());
    };
    if height > cutoff {
        return Ok(());
    }

    let recent = txn.open_table(Some(T_RECENT_BLOCKS))?;
    let proofs = txn.open_table(Some(T_BLOCK_PROOFS))?;
    let sidecars = txn.open_table(Some(T_BLOCK_AUTH_SIDECARS))?;
    let attestations = txn.open_table(Some(T_COVERAGE_ATTESTATIONS))?;
    let history = txn.open_table(Some(T_HISTORY_CLAIMS))?;
    let certificates = txn.open_table(Some(T_ACCEPTED_BLOCK_CERTIFICATES))?;
    let certificate_bindings = txn.open_table(Some(T_ACCEPTED_BLOCK_CERTIFICATE_BINDINGS))?;

    let mut processed_heights = 0usize;
    let mut retired_bytes = 0usize;
    let mut deletes = 0usize;
    let mut last_processed = None;
    while height <= cutoff && processed_heights < RETAINED_PAYLOAD_PRUNE_HEIGHT_LIMIT {
        let key = u64_key(height);
        let header_raw: Option<Cow<'_, [u8]>> = txn.get(&headers, &key)?;
        let canonical_hash = header_raw
            .as_deref()
            .and_then(decode_header)
            .filter(|header| header.height == height)
            .map(|header| crate::block_header::block_id(&header))
            .ok_or(StoreError::Decode(
                "canonical header is missing during retained payload pruning",
            ))?;

        let payload_lengths = [
            txn.get::<ObjectLength>(&recent, &key)?
                .map(|ObjectLength(length)| length),
            txn.get::<ObjectLength>(&proofs, &key)?
                .map(|ObjectLength(length)| length),
            txn.get::<ObjectLength>(&sidecars, &key)?
                .map(|ObjectLength(length)| length),
            txn.get::<ObjectLength>(&attestations, &key)?
                .map(|ObjectLength(length)| length),
            txn.get::<ObjectLength>(&history, &key)?
                .map(|ObjectLength(length)| length),
        ];
        let certificate_len = txn
            .get::<ObjectLength>(&certificates, &key)?
            .map(|ObjectLength(length)| length);
        let binding_len = txn
            .get::<ObjectLength>(&certificate_bindings, &key)?
            .map(|ObjectLength(length)| length);

        match (certificate_len, binding_len) {
            (None, None) if payload_lengths.iter().all(Option::is_none) => {}
            (None, None) => {
                return Err(StoreError::Decode(
                    "retained payload has no accepted block certificate",
                ));
            }
            (Some(_), None) | (None, Some(_)) => {
                return Err(StoreError::Decode(
                    "accepted block certificate binding is missing during pruning",
                ));
            }
            (Some(certificate_len), Some(binding_len)) => {
                if certificate_len == 0 || binding_len != ACCEPTED_BLOCK_CERTIFICATE_BINDING_BYTES {
                    return Err(StoreError::Decode(
                        "accepted block certificate is malformed during pruning",
                    ));
                }
                let binding_raw: [u8; ACCEPTED_BLOCK_CERTIFICATE_BINDING_BYTES] = txn
                    .get(&certificate_bindings, &key)?
                    .ok_or(StoreError::Decode(
                        "accepted block certificate binding disappeared during pruning",
                    ))?;
                let binding = decode_accepted_block_certificate_binding(&binding_raw).ok_or(
                    StoreError::Decode(
                        "accepted block certificate binding is malformed during pruning",
                    ),
                )?;
                if binding.height != height
                    || binding.block_hash != canonical_hash
                    || usize::try_from(binding.certificate_len).ok() != Some(certificate_len)
                {
                    return Err(StoreError::Decode(
                        "accepted block certificate is not canonical during pruning",
                    ));
                }
            }
        }

        let height_bytes = payload_lengths
            .iter()
            .flatten()
            .copied()
            .chain(certificate_len)
            .chain(binding_len)
            .try_fold(0usize, |total, length| total.checked_add(length))
            .ok_or(StoreError::Decode(
                "retained payload prune byte accounting overflow",
            ))?;
        let height_deletes = payload_lengths.iter().flatten().count()
            + usize::from(certificate_len.is_some())
            + usize::from(binding_len.is_some());
        if height_bytes > RETAINED_PAYLOAD_PRUNE_BYTE_LIMIT
            || height_deletes > RETAINED_PAYLOAD_PRUNE_DELETE_LIMIT
        {
            return Err(StoreError::Decode(
                "one retained payload height exceeds maintenance budget",
            ));
        }
        if !retained_payload_prune_budget_allows(
            retired_bytes,
            deletes,
            height_bytes,
            height_deletes,
        ) {
            break;
        }

        for (table, present) in [
            (&recent, payload_lengths[0].is_some()),
            (&proofs, payload_lengths[1].is_some()),
            (&sidecars, payload_lengths[2].is_some()),
            (&attestations, payload_lengths[3].is_some()),
            (&history, payload_lengths[4].is_some()),
        ] {
            if present {
                txn.del(table, &key, None)?;
            }
        }
        if certificate_len.is_some() {
            txn.del(&certificates, &key, None)?;
            txn.del(&certificate_bindings, &key, None)?;
        }

        retired_bytes += height_bytes;
        deletes += height_deletes;
        processed_heights += 1;
        last_processed = Some(height);
        let Some(next) = height.checked_add(1) else {
            break;
        };
        height = next;
    }

    if let Some(last_processed) = last_processed {
        set_retained_payload_prune_watermark(txn, last_processed)?;
    }
    Ok(())
}

/// Delete legacy little-endian height keys without collecting the table or
/// assuming that lexicographic cursor order is numeric.
fn delete_height_keys_at_or_below(
    txn: &Transaction<'_, RW, NoWriteMap>,
    table: &Table<'_>,
    cutoff: u64,
) -> Result<(), StoreError> {
    const DELETE_KEY_CHUNK: usize = 64;
    const DELETE_SCAN_CHUNK: usize = 4096;
    let mut resume_after: Option<Vec<u8>> = None;
    loop {
        let (deletions, last_scanned, reached_end) = {
            let mut cursor = txn.cursor(table)?;
            let mut item: Option<(Vec<u8>, ())> = if let Some(resume) = resume_after.as_deref() {
                let found: Option<(Vec<u8>, ())> = cursor.set_range(resume)?;
                match found {
                    Some((key, _)) if key.as_slice() == resume => cursor.next()?,
                    other => other,
                }
            } else {
                cursor.first()?
            };
            let mut deletions = Vec::with_capacity(DELETE_KEY_CHUNK);
            let mut last_scanned = None;
            let mut scanned = 0usize;
            let reached_end = loop {
                let Some((key, _)) = item.take() else {
                    break true;
                };
                let height = u64_from_key(&key).ok_or(StoreError::Decode(
                    "invalid durable height key during pruning",
                ))?;
                if height <= cutoff {
                    deletions.push(height);
                }
                last_scanned = Some(key);
                scanned += 1;
                if deletions.len() == DELETE_KEY_CHUNK || scanned == DELETE_SCAN_CHUNK {
                    break false;
                }
                item = cursor.next()?;
            };
            (deletions, last_scanned, reached_end)
        };
        for height in deletions {
            txn.del(table, u64_key(height), None)?;
        }
        if reached_end {
            return Ok(());
        }
        resume_after = last_scanned;
    }
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
            T_COVERAGE_ATTESTATIONS,
            T_HISTORY_CLAIMS,
            T_ACCEPTED_BLOCK_CERTIFICATES,
            T_ACCEPTED_BLOCK_CERTIFICATE_BINDINGS,
            T_ACCEPTED_BLOCK_BATCH_CERTIFICATE_PACKAGES,
            T_HISTORY_CHECKPOINT_HEADS,
            T_OWNER_INDEX,
            T_CHECKPOINT_PACKAGES,
            T_CHECKPOINT_COVERAGE,
            T_RECURSIVE_PROOF_JOBS,
            T_RECURSIVE_PROOF_RESULTS,
            T_LADDER_SEGMENTS,
            T_LADDER_META,
        ] {
            txn.create_table(Some(name), TableFlags::empty())?;
        }
        txn.commit()?;
        let store = Self { db: Arc::new(db) };
        store.reset_running_recursive_proof_jobs()?;
        store.validate_selected_history_ladder_cursor_on_open()?;
        Ok(store)
    }

    // -----------------------------------------------------------------------
    // Reads
    // -----------------------------------------------------------------------

    pub(super) fn historical_read_snapshot(
        &self,
    ) -> Result<MdbxHistoricalReadSnapshot<'_>, StoreError> {
        Ok(MdbxHistoricalReadSnapshot {
            txn: self.db.begin_ro_txn()?,
        })
    }

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

    /// Claim the numerically-lowest canonical pending job strictly above valid
    /// selected-history coverage.
    ///
    /// Big-endian height keys make the cursor order numeric even across byte
    /// boundaries such as 255 -> 256. Only the selected fixed-width record is
    /// retained; no queue or result payload collection is allocated.
    pub fn claim_next_recursive_proof_job(&self) -> Result<Option<RecursiveProofJob>, StoreError> {
        let txn = self.db.begin_rw_txn()?;
        let coverage = validated_selected_history_coverage_in_rw_txn(&txn)?;
        let jobs = txn.open_table(Some(T_RECURSIVE_PROOF_JOBS))?;
        let headers = txn.open_table(Some(T_HEADERS))?;
        let selected = {
            let mut cursor = txn.cursor(&jobs)?;
            let mut item: Option<([u8; 8], [u8; RECURSIVE_PROOF_JOB_ENCODED_BYTES])> =
                match coverage {
                    Some(coverage) => match coverage.height.checked_add(1) {
                        Some(first_uncovered) => {
                            cursor.set_range(&recursive_proof_height_key(first_uncovered))?
                        }
                        None => None,
                    },
                    None => cursor.first()?,
                };
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

    /// Load every retained byte object needed to prove one already-claimed
    /// selected recursive job from a single canonical MDBX snapshot.
    ///
    /// The exact fixed-width `claimed` record must still be Running. The
    /// method validates the source tip, current/parent header link, retained
    /// block framing and tier, detached witness presence, and (above height
    /// one) the canonical completed predecessor. Every large value is queried
    /// as [`ObjectLength`] and all individual/combined limits are checked
    /// before the first large `Vec` is allocated.
    pub fn load_claimed_recursive_proof_job_inputs(
        &self,
        claimed: RecursiveProofJob,
    ) -> Result<ClaimedRecursiveProofJobInputs, StoreError> {
        self.load_claimed_recursive_proof_job_inputs_inner(claimed, false, None)
            .map(|(inputs, _)| inputs)
    }

    /// Strictly load one claimed job and, from the same read snapshot, report
    /// whether its durable predecessor is the exact in-memory lane tail the
    /// caller expects. The comparison reuses the single decoded predecessor
    /// result already owned by the returned inputs; it does not fetch or copy
    /// the result payload a second time.
    pub fn load_claimed_recursive_proof_job_inputs_with_expected_predecessor(
        &self,
        claimed: RecursiveProofJob,
        expected_height: u64,
        expected_block_hash: [u8; 32],
        expected_bytes: &[u8],
    ) -> Result<(ClaimedRecursiveProofJobInputs, bool), StoreError> {
        self.load_claimed_recursive_proof_job_inputs_inner(
            claimed,
            false,
            Some((expected_height, expected_block_hash, expected_bytes)),
        )
    }

    /// Pipelined variant of [`Self::load_claimed_recursive_proof_job_inputs`]
    /// for the in-memory chained history worker: the immediate predecessor
    /// job may still be `Running` when it is bound to the exact canonical
    /// parent hash — its terminal result then arrives through the worker's
    /// in-memory lane handoff and `previous_result` is `None`.  A `Complete`
    /// predecessor (for example after a raced verified import) behaves
    /// exactly like the strict loader.  Every other validation is identical.
    pub fn load_claimed_recursive_proof_job_inputs_with_running_predecessor(
        &self,
        claimed: RecursiveProofJob,
    ) -> Result<ClaimedRecursiveProofJobInputs, StoreError> {
        self.load_claimed_recursive_proof_job_inputs_inner(claimed, true, None)
            .map(|(inputs, _)| inputs)
    }

    fn load_claimed_recursive_proof_job_inputs_inner(
        &self,
        claimed: RecursiveProofJob,
        allow_running_predecessor: bool,
        expected_predecessor: Option<(u64, [u8; 32], &[u8])>,
    ) -> Result<(ClaimedRecursiveProofJobInputs, bool), StoreError> {
        use crate::wire::BLOCK_HEADER_WIRE_SIZE;

        if claimed.height == 0 {
            return Err(StoreError::Decode(
                "genesis cannot be a selected recursive proof job",
            ));
        }
        if claimed.state != RecursiveProofJobState::Running {
            return Err(StoreError::Decode(
                "recursive proof input loader requires a running claim",
            ));
        }

        let txn = self.db.begin_ro_txn()?;
        let jobs = txn.open_table(Some(T_RECURSIVE_PROOF_JOBS))?;
        let key = recursive_proof_height_key(claimed.height);
        let durable_job_raw: Option<[u8; RECURSIVE_PROOF_JOB_ENCODED_BYTES]> =
            txn.get(&jobs, &key)?;
        let durable_job = durable_job_raw
            .as_ref()
            .and_then(|raw| decode_recursive_proof_job(claimed.height, raw))
            .ok_or(StoreError::Decode(
                "recursive proof job is missing or malformed",
            ))?;
        if durable_job != claimed || durable_job.state != RecursiveProofJobState::Running {
            return Err(StoreError::Decode(
                "recursive proof input does not match the running durable claim",
            ));
        }

        let tip_table = txn.open_table(Some(T_CHAIN_TIP))?;
        let tip_raw: Option<[u8; 40]> = txn.get(&tip_table, KEY_TIP)?;
        let source_tip = tip_raw
            .as_ref()
            .and_then(|raw| decode_chain_tip(raw))
            .ok_or(StoreError::Decode(
                "canonical source tip is missing or malformed",
            ))?;
        if source_tip.0 < claimed.height {
            return Err(StoreError::Decode(
                "recursive proof job is above the canonical source tip",
            ));
        }

        let headers = txn.open_table(Some(T_HEADERS))?;
        let header_raw: Option<[u8; BLOCK_HEADER_WIRE_SIZE]> =
            txn.get(&headers, &u64_key(claimed.height))?;
        let block_header = header_raw
            .as_ref()
            .and_then(|raw| decode_header(raw))
            .ok_or(StoreError::Decode(
                "recursive proof current canonical header is missing or malformed",
            ))?;
        if block_header.height != claimed.height
            || crate::block_header::block_id(&block_header) != claimed.block_hash
        {
            return Err(StoreError::Decode(
                "recursive proof job hash is not canonical at height",
            ));
        }

        let parent_height = claimed.height - 1;
        let parent_raw: Option<[u8; BLOCK_HEADER_WIRE_SIZE]> =
            txn.get(&headers, &u64_key(parent_height))?;
        let parent_header = parent_raw
            .as_ref()
            .and_then(|raw| decode_header(raw))
            .ok_or(StoreError::Decode(
                "recursive proof parent canonical header is missing or malformed",
            ))?;
        let parent_hash = crate::block_header::block_id(&parent_header);
        if parent_header.height != parent_height || block_header.prev_block_hash != parent_hash {
            return Err(StoreError::Decode(
                "recursive proof current/parent canonical header link is invalid",
            ));
        }

        let expected_predecessor_identity_matches =
            expected_predecessor.is_some_and(|(height, block_hash, _)| {
                height == parent_height && block_hash == parent_hash
            });
        let expected_predecessor_coverage_matches = if expected_predecessor.is_some() {
            let coverage_table = txn.open_table(Some(T_CHECKPOINT_COVERAGE))?;
            let coverage_raw: Option<[u8; SELECTED_HISTORY_COVERAGE_ENCODED_BYTES]> =
                txn.get(&coverage_table, KEY_SELECTED_HISTORY_COVERAGE)?;
            let coverage = coverage_raw
                .as_ref()
                .map(|raw| {
                    decode_selected_history_coverage(raw).ok_or(StoreError::Decode(
                        "invalid selected history coverage pointer",
                    ))
                })
                .transpose()?;
            coverage
                == Some(SelectedHistoryCoverage {
                    height: parent_height,
                    block_hash: parent_hash,
                })
        } else {
            false
        };

        if source_tip.0 == claimed.height {
            if source_tip.1 != claimed.block_hash {
                return Err(StoreError::Decode(
                    "recursive proof source tip hash disagrees with current header",
                ));
            }
        } else {
            let source_header_raw: Option<[u8; BLOCK_HEADER_WIRE_SIZE]> =
                txn.get(&headers, &u64_key(source_tip.0))?;
            let source_header = source_header_raw
                .as_ref()
                .and_then(|raw| decode_header(raw))
                .ok_or(StoreError::Decode(
                    "recursive proof source tip header is missing or malformed",
                ))?;
            if source_header.height != source_tip.0
                || crate::block_header::block_id(&source_header) != source_tip.1
            {
                return Err(StoreError::Decode(
                    "recursive proof source tip is not bound to its canonical header",
                ));
            }
        }

        // Query all large record lengths before allocating any of their byte
        // vectors. A malformed combined proof/sidecar therefore cannot leave
        // a valid 32 MiB sibling resident while failing its second preflight.
        let recent_blocks = txn.open_table(Some(T_RECENT_BLOCKS))?;
        let block_length: Option<ObjectLength> =
            txn.get(&recent_blocks, &u64_key(claimed.height))?;
        let block_proofs = txn.open_table(Some(T_BLOCK_PROOFS))?;
        let proof_length: Option<ObjectLength> =
            txn.get(&block_proofs, &u64_key(claimed.height))?;
        let sidecars = txn.open_table(Some(T_BLOCK_AUTH_SIDECARS))?;
        let sidecar_length: Option<ObjectLength> = txn.get(&sidecars, &u64_key(claimed.height))?;

        let results = txn.open_table(Some(T_RECURSIVE_PROOF_RESULTS))?;
        let mut previous_job = None;
        let previous_result_length = if claimed.height == 1 {
            None
        } else {
            let previous_key = recursive_proof_height_key(parent_height);
            let previous_job_raw: Option<[u8; RECURSIVE_PROOF_JOB_ENCODED_BYTES]> =
                txn.get(&jobs, &previous_key)?;
            let decoded = previous_job_raw
                .as_ref()
                .and_then(|raw| decode_recursive_proof_job(parent_height, raw))
                .ok_or(StoreError::Decode(
                    "previous recursive proof job is missing or malformed",
                ))?;
            if decoded.block_hash != parent_hash {
                return Err(StoreError::Decode(
                    "previous recursive proof job is not canonical",
                ));
            }
            match decoded.state {
                RecursiveProofJobState::Complete => {
                    previous_job = Some(decoded);
                    txn.get::<ObjectLength>(&results, &previous_key)?
                }
                // The pipelined worker proves consecutive heights before the
                // lower one is promoted; the predecessor terminal then comes
                // from the in-memory lane handoff, never from this snapshot.
                RecursiveProofJobState::Running if allow_running_predecessor => None,
                _ => {
                    return Err(StoreError::Decode(
                        "previous recursive proof job is not complete and canonical",
                    ));
                }
            }
        };

        let lengths = ClaimedRecursiveProofInputLengths {
            block: block_length.map(|ObjectLength(length)| length),
            proof: proof_length.map(|ObjectLength(length)| length),
            sidecar: sidecar_length.map(|ObjectLength(length)| length),
            previous_result: previous_result_length.map(|ObjectLength(length)| length),
        };
        validate_claimed_recursive_proof_input_lengths(
            claimed.height,
            lengths,
            previous_job.is_some(),
        )?;

        let block_bytes: Vec<u8> =
            txn.get(&recent_blocks, &u64_key(claimed.height))?
                .ok_or(StoreError::Decode(
                    "recursive proof source block disappeared during atomic load",
                ))?;
        if Some(block_bytes.len()) != lengths.block {
            return Err(StoreError::Decode(
                "recursive proof source block length changed during atomic load",
            ));
        }
        let user_transaction_count =
            inspect_recursive_proof_source_block(&block_bytes, &block_header, claimed.tier)?;

        let (block_proof_bytes, block_auth_sidecar_bytes) = match (lengths.proof, lengths.sidecar) {
            (None, None) => (Vec::new(), Vec::new()),
            (Some(expected_proof_len), Some(expected_sidecar_len)) => {
                let proof: Vec<u8> =
                    txn.get(&block_proofs, &u64_key(claimed.height))?
                        .ok_or(StoreError::Decode(
                            "recursive proof source BlockProof disappeared during atomic load",
                        ))?;
                if proof.len() != expected_proof_len {
                    return Err(StoreError::Decode(
                        "recursive proof source BlockProof length changed during atomic load",
                    ));
                }
                let sidecar: Vec<u8> =
                    txn.get(&sidecars, &u64_key(claimed.height))?
                        .ok_or(StoreError::Decode(
                            "recursive proof source auth sidecar disappeared during atomic load",
                        ))?;
                if sidecar.len() != expected_sidecar_len {
                    return Err(StoreError::Decode(
                        "recursive proof source auth sidecar length changed during atomic load",
                    ));
                }
                (proof, sidecar)
            }
            _ => unreachable!("presence equality checked before allocation"),
        };
        if user_transaction_count == 0 {
            if lengths.proof.is_some() {
                return Err(StoreError::Decode(
                    "coinbase-only recursive proof source retained detached witnesses",
                ));
            }
        } else if block_proof_bytes.is_empty() || block_auth_sidecar_bytes.is_empty() {
            return Err(StoreError::Decode(
                "user recursive proof source is missing detached witnesses",
            ));
        }

        let previous_result = if let Some(previous_job) = previous_job {
            let previous_key = recursive_proof_height_key(parent_height);
            let encoded: Vec<u8> = txn.get(&results, &previous_key)?.ok_or(StoreError::Decode(
                "previous recursive proof result disappeared during atomic load",
            ))?;
            if Some(encoded.len()) != lengths.previous_result {
                return Err(StoreError::Decode(
                    "previous recursive proof result length changed during atomic load",
                ));
            }
            let decoded = decode_recursive_proof_result(parent_height, encoded).ok_or(
                StoreError::Decode("previous recursive proof result is malformed"),
            )?;
            if decoded.block_hash != previous_job.block_hash
                || decoded.block_hash != parent_hash
                || !selected_history_terminal_matches_job(
                    &decoded.bytes,
                    parent_height,
                    parent_hash,
                    previous_job.tier,
                )
            {
                return Err(StoreError::Decode(
                    "previous recursive proof result does not match the current parent job",
                ));
            }
            Some(decoded)
        } else {
            None
        };

        let expected_predecessor_matches = match (expected_predecessor, previous_result.as_ref()) {
            (Some((height, block_hash, bytes)), Some(result)) => {
                expected_predecessor_identity_matches
                    && expected_predecessor_coverage_matches
                    && result.height == height
                    && result.block_hash == block_hash
                    && result.bytes.as_slice() == bytes
            }
            _ => false,
        };

        Ok((
            ClaimedRecursiveProofJobInputs {
                job: claimed,
                source_tip,
                parent_header,
                block_header,
                user_transaction_count,
                block_bytes,
                block_proof_bytes,
                block_auth_sidecar_bytes,
                previous_result,
            },
            expected_predecessor_matches,
        ))
    }

    /// Store one bounded opaque proof and mark its running job complete in the
    /// same transaction. A failure cannot expose either half independently.
    pub fn complete_recursive_proof_job(
        &self,
        height: u64,
        block_hash: [u8; 32],
        result: &[u8],
    ) -> Result<RecursiveProofJob, StoreError> {
        self.complete_recursive_proof_job_inner(height, block_hash, result, None)
    }

    /// Atomically complete one locally verified selected terminal package and
    /// advance its fixed-width serving pointer. The pointer never owns proof
    /// bytes, and promotion checks the immediately preceding completed job
    /// without loading its envelope.
    ///
    /// `ladder` is the proven block's end-state cursor advance; it commits in
    /// this same transaction so the forward ladder can never lag coverage.
    pub fn complete_recursive_proof_job_and_promote_selected_history(
        &self,
        height: u64,
        block_hash: [u8; 32],
        result: &[u8],
        ladder: &SelectedHistoryLadderUpdate,
    ) -> Result<RecursiveProofJob, StoreError> {
        self.complete_recursive_proof_job_inner(height, block_hash, result, Some(ladder))
    }

    fn complete_recursive_proof_job_inner(
        &self,
        height: u64,
        block_hash: [u8; 32],
        result: &[u8],
        ladder: Option<&SelectedHistoryLadderUpdate>,
    ) -> Result<RecursiveProofJob, StoreError> {
        let promote_selected_history = ladder.is_some();
        if promote_selected_history {
            if result.len() > crate::consensus::wire_limits::MAX_HISTORY_PROOF_BYTES {
                return Err(StoreError::Decode(
                    "selected history terminal result exceeds wire cap",
                ));
            }
            if !selected_history_terminal_prefix_matches(result, height, block_hash) {
                return Err(StoreError::Decode(
                    "selected history terminal result prefix does not match its job",
                ));
            }
        }
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
        if promote_selected_history
            && !selected_history_terminal_matches_job(result, height, block_hash, job.tier)
        {
            return Err(StoreError::Decode(
                "selected history terminal class does not match its running job",
            ));
        }
        let headers = txn.open_table(Some(T_HEADERS))?;
        let header_raw: Option<Vec<u8>> = txn.get(&headers, &u64_key(height))?;
        let header = header_raw
            .as_deref()
            .and_then(decode_header)
            .ok_or(StoreError::Decode(
                "recursive proof completion canonical header is missing",
            ))?;
        if crate::block_header::block_id(&header) != block_hash {
            return Err(StoreError::Decode(
                "recursive proof completion block is no longer canonical",
            ));
        }

        let results = txn.open_table(Some(T_RECURSIVE_PROOF_RESULTS))?;
        if promote_selected_history {
            let coverage_table = txn.open_table(Some(T_CHECKPOINT_COVERAGE))?;
            let coverage_raw: Option<[u8; SELECTED_HISTORY_COVERAGE_ENCODED_BYTES]> =
                txn.get(&coverage_table, KEY_SELECTED_HISTORY_COVERAGE)?;
            let previous_coverage = coverage_raw
                .as_ref()
                .map(|raw| {
                    decode_selected_history_coverage(raw).ok_or(StoreError::Decode(
                        "invalid selected history predecessor coverage pointer",
                    ))
                })
                .transpose()?;
            if height == 1 {
                if previous_coverage.is_some() {
                    return Err(StoreError::Decode(
                        "selected history genesis successor requires empty coverage",
                    ));
                }
            } else {
                let parent_height = height - 1;
                if previous_coverage
                    != Some(SelectedHistoryCoverage {
                        height: parent_height,
                        block_hash: header.prev_block_hash,
                    })
                {
                    return Err(StoreError::Decode(
                        "selected history coverage is not the exact predecessor",
                    ));
                }
                let parent_key = recursive_proof_height_key(parent_height);
                let parent_raw: Option<[u8; RECURSIVE_PROOF_JOB_ENCODED_BYTES]> =
                    txn.get(&jobs, &parent_key)?;
                let parent = parent_raw
                    .as_ref()
                    .and_then(|raw| decode_recursive_proof_job(parent_height, raw))
                    .ok_or(StoreError::Decode(
                        "selected history predecessor job is missing",
                    ))?;
                if parent.state != RecursiveProofJobState::Complete
                    || parent.block_hash != header.prev_block_hash
                {
                    return Err(StoreError::Decode(
                        "selected history predecessor is not complete and canonical",
                    ));
                }
                let parent_result_length: Option<ObjectLength> = txn.get(&results, &parent_key)?;
                if !parent_result_length.is_some_and(|ObjectLength(length)| {
                    (RECURSIVE_PROOF_RESULT_HEADER_BYTES
                        ..=RECURSIVE_PROOF_RESULT_HEADER_BYTES
                            + crate::consensus::wire_limits::MAX_HISTORY_PROOF_BYTES)
                        .contains(&length)
                }) {
                    return Err(StoreError::Decode(
                        "selected history predecessor result is missing or oversized",
                    ));
                }
            }
        }
        txn.put(&results, key, encoded_result, WriteFlags::empty())?;
        job.state = RecursiveProofJobState::Complete;
        txn.put(
            &jobs,
            key,
            encode_recursive_proof_job(&job),
            WriteFlags::empty(),
        )?;
        if let Some(ladder) = ladder {
            let coverage = txn.open_table(Some(T_CHECKPOINT_COVERAGE))?;
            txn.put(
                &coverage,
                KEY_SELECTED_HISTORY_COVERAGE,
                encode_selected_history_coverage(SelectedHistoryCoverage { height, block_hash }),
                WriteFlags::empty(),
            )?;
            apply_selected_history_ladder_update_in_rw_txn(&txn, &header, block_hash, ladder)?;
        }
        #[cfg(test)]
        if promote_selected_history {
            hit_authoritative_mutation_fault(
                AuthoritativeMutationFault::SelectedPromotionBeforeCommit,
            )?;
        }
        txn.commit()?;
        #[cfg(test)]
        if promote_selected_history {
            hit_authoritative_mutation_fault(
                AuthoritativeMutationFault::SelectedPromotionAfterCommit,
            )?;
        }
        Ok(job)
    }

    /// Atomically import a terminal already accepted by the recursive verifier
    /// on an ordinary relay.
    ///
    /// Unlike the local prover completion path, this operation intentionally
    /// permits a strict forward coverage jump: the recursive terminal already
    /// proves the complete prefix through `height`.  It still requires the
    /// canonical accepted-block journal entry at the target, rejects a Running
    /// target job, and never accepts an equal or lower coverage height. The
    /// exact target result and fixed-width serving pointer commit atomically;
    /// covered predecessor cleanup is separate, bounded maintenance.
    pub fn import_verified_selected_history_terminal(
        &self,
        imported: VerifiedSelectedHistoryTerminalImport<'_>,
    ) -> Result<SelectedHistoryCoverage, StoreError> {
        let VerifiedSelectedHistoryTerminalImport {
            height,
            block_hash,
            epoch_anchor_height,
            epoch_anchor_hash,
            tier,
            terminal_package_bytes,
        } = imported;

        if terminal_package_bytes.len() > crate::consensus::wire_limits::MAX_HISTORY_PROOF_BYTES {
            return Err(StoreError::Decode(
                "verified selected history terminal exceeds wire cap",
            ));
        }
        if !selected_history_terminal_matches_job(terminal_package_bytes, height, block_hash, tier)
        {
            return Err(StoreError::Decode(
                "verified selected history terminal prefix or tier is invalid",
            ));
        }
        let encoded_result = encode_recursive_proof_result(block_hash, terminal_package_bytes)?;

        let txn = self.db.begin_rw_txn()?;
        // A remote coverage jump makes predecessor jobs/results redundant and
        // bounded maintenance may remove them later. It is therefore admitted
        // only inside the durable hard-finalized prefix: a shallow reorg still
        // retains the exact finalized terminal needed to resume recursion.
        let consensus_table = txn.open_table(Some(T_CONSENSUS_META))?;
        let consensus_raw: Option<Vec<u8>> = txn.get(&consensus_table, KEY_CONSENSUS_META)?;
        let consensus = consensus_raw
            .as_deref()
            .and_then(decode_consensus_meta)
            .ok_or(StoreError::Decode(
                "verified selected history import requires valid consensus metadata",
            ))?;
        if consensus.finalized.height > consensus.tip_height || height > consensus.finalized.height
        {
            return Err(StoreError::Decode(
                "verified selected history import target is not hard-finalized",
            ));
        }

        let headers = txn.open_table(Some(T_HEADERS))?;
        let finalized_raw: Option<Vec<u8>> =
            txn.get(&headers, &u64_key(consensus.finalized.height))?;
        let finalized_header =
            finalized_raw
                .as_deref()
                .and_then(decode_header)
                .ok_or(StoreError::Decode(
                    "verified selected history finalized header is missing",
                ))?;
        if finalized_header.height != consensus.finalized.height
            || crate::block_header::block_id(&finalized_header) != consensus.finalized.hash
        {
            return Err(StoreError::Decode(
                "verified selected history finalized checkpoint is not canonical",
            ));
        }
        let target_raw: Option<Vec<u8>> = txn.get(&headers, &u64_key(height))?;
        let target_header =
            target_raw
                .as_deref()
                .and_then(decode_header)
                .ok_or(StoreError::Decode(
                    "verified selected history target header is missing",
                ))?;
        if target_header.height != height
            || crate::block_header::block_id(&target_header) != block_hash
        {
            return Err(StoreError::Decode(
                "verified selected history target is not canonical",
            ));
        }

        let expected_epoch_anchor_height = (height / crate::consensus::params::TX_EPOCH_BLOCKS)
            * crate::consensus::params::TX_EPOCH_BLOCKS;
        if epoch_anchor_height != expected_epoch_anchor_height {
            return Err(StoreError::Decode(
                "verified selected history epoch anchor height is invalid",
            ));
        }
        let epoch_raw: Option<Vec<u8>> =
            txn.get(&headers, &u64_key(expected_epoch_anchor_height))?;
        let epoch_header =
            epoch_raw
                .as_deref()
                .and_then(decode_header)
                .ok_or(StoreError::Decode(
                    "verified selected history epoch anchor is missing",
                ))?;
        if epoch_header.height != expected_epoch_anchor_height
            || crate::block_header::block_id(&epoch_header) != epoch_anchor_hash
        {
            return Err(StoreError::Decode(
                "verified selected history epoch anchor is not canonical",
            ));
        }

        let coverage_table = txn.open_table(Some(T_CHECKPOINT_COVERAGE))?;
        let coverage_raw: Option<[u8; SELECTED_HISTORY_COVERAGE_ENCODED_BYTES]> =
            txn.get(&coverage_table, KEY_SELECTED_HISTORY_COVERAGE)?;
        let previous_coverage = coverage_raw
            .as_ref()
            .map(|raw| {
                decode_selected_history_coverage(raw).ok_or(StoreError::Decode(
                    "invalid selected history coverage pointer before verified import",
                ))
            })
            .transpose()?;
        if let Some(previous) = previous_coverage {
            validate_selected_history_coverage_in_rw_txn(&txn, previous)?;
            if height <= previous.height {
                return Err(StoreError::Decode(
                    "verified selected history import does not advance coverage",
                ));
            }
        }

        let key = recursive_proof_height_key(height);
        let jobs = txn.open_table(Some(T_RECURSIVE_PROOF_JOBS))?;
        let target_job_raw: Option<[u8; RECURSIVE_PROOF_JOB_ENCODED_BYTES]> =
            txn.get(&jobs, &key)?;
        let mut target_job = target_job_raw
            .as_ref()
            .and_then(|raw| decode_recursive_proof_job(height, raw))
            .ok_or(StoreError::Decode(
                "verified selected history target job is missing or malformed",
            ))?;
        if target_job.block_hash != block_hash || target_job.tier != tier {
            return Err(StoreError::Decode(
                "verified selected history target job identity or tier differs",
            ));
        }
        if !matches!(
            target_job.state,
            RecursiveProofJobState::Pending | RecursiveProofJobState::Complete
        ) {
            return Err(StoreError::Decode(
                "verified selected history target job is running",
            ));
        }
        let results = txn.open_table(Some(T_RECURSIVE_PROOF_RESULTS))?;
        txn.put(&results, key, encoded_result, WriteFlags::empty())?;
        target_job.state = RecursiveProofJobState::Complete;
        txn.put(
            &jobs,
            key,
            encode_recursive_proof_job(&target_job),
            WriteFlags::empty(),
        )?;
        let coverage = SelectedHistoryCoverage { height, block_hash };
        txn.put(
            &coverage_table,
            KEY_SELECTED_HISTORY_COVERAGE,
            encode_selected_history_coverage(coverage),
            WriteFlags::empty(),
        )?;
        authoritative_mutation_boundary!(SelectedImportBeforeCommit);
        txn.commit()?;
        authoritative_mutation_boundary!(SelectedImportAfterCommit);
        // Coverage is already durable. Cleanup is retryable maintenance and a
        // failure must not masquerade as a rejected verified import.
        let _ = self.compact_selected_history_journal_bounded();
        Ok(coverage)
    }

    /// Delete a small bounded batch of redundant selected-history journal
    /// records in one short MDBX transaction.
    ///
    /// The strict cutoff is `min(verified coverage, durable finality)`. Keeping
    /// the record exactly at that cutoff preserves the finalized terminal used
    /// for snapshot serving and gives a shallow-reorg prover a restart anchor.
    /// Cursor visits and successful deletes share one fixed budget, while any
    /// in-process `Running` job is skipped rather than invalidated.
    pub fn compact_selected_history_journal_bounded(&self) -> Result<usize, StoreError> {
        let txn = self.db.begin_rw_txn()?;
        let Some(coverage) = validated_selected_history_coverage_in_rw_txn(&txn)? else {
            txn.commit()?;
            return Ok(0);
        };

        let consensus_table = txn.open_table(Some(T_CONSENSUS_META))?;
        let consensus_raw: Option<Vec<u8>> = txn.get(&consensus_table, KEY_CONSENSUS_META)?;
        let consensus = consensus_raw
            .as_deref()
            .and_then(decode_consensus_meta)
            .ok_or(StoreError::Decode(
                "selected history compaction requires valid consensus metadata",
            ))?;
        if consensus.finalized.height > consensus.tip_height {
            return Err(StoreError::Decode(
                "selected history compaction finality exceeds the durable tip",
            ));
        }
        let headers = txn.open_table(Some(T_HEADERS))?;
        let finalized_raw: Option<Vec<u8>> =
            txn.get(&headers, &u64_key(consensus.finalized.height))?;
        let finalized_header =
            finalized_raw
                .as_deref()
                .and_then(decode_header)
                .ok_or(StoreError::Decode(
                    "selected history compaction finalized header is missing",
                ))?;
        if finalized_header.height != consensus.finalized.height
            || crate::block_header::block_id(&finalized_header) != consensus.finalized.hash
        {
            return Err(StoreError::Decode(
                "selected history compaction finalized checkpoint is not canonical",
            ));
        }

        let cutoff = coverage.height.min(consensus.finalized.height);
        if cutoff == 0 {
            txn.commit()?;
            return Ok(0);
        }

        let mut visited = 0usize;
        let mut deleted = 0usize;
        let jobs = txn.open_table(Some(T_RECURSIVE_PROOF_JOBS))?;
        let job_keys = {
            let mut cursor = txn.cursor(&jobs)?;
            let mut item: Option<([u8; 8], [u8; RECURSIVE_PROOF_JOB_ENCODED_BYTES])> =
                cursor.first()?;
            let mut keys = Vec::with_capacity(SELECTED_HISTORY_JOURNAL_COMPACTION_ENTRY_LIMIT);
            while visited < SELECTED_HISTORY_JOURNAL_COMPACTION_ENTRY_LIMIT {
                let Some((key, raw)) = item else {
                    break;
                };
                let height = recursive_proof_height_from_key(&key).ok_or(StoreError::Decode(
                    "invalid recursive proof job key during bounded compaction",
                ))?;
                if height >= cutoff {
                    break;
                }
                let job = decode_recursive_proof_job(height, &raw).ok_or(StoreError::Decode(
                    "invalid recursive proof job during bounded compaction",
                ))?;
                visited += 1;
                if job.state != RecursiveProofJobState::Running {
                    keys.push(key);
                }
                item = cursor.next()?;
            }
            keys
        };
        for key in job_keys {
            txn.del(&jobs, &key, None)?;
            deleted += 1;
        }

        if visited < SELECTED_HISTORY_JOURNAL_COMPACTION_ENTRY_LIMIT {
            let results = txn.open_table(Some(T_RECURSIVE_PROOF_RESULTS))?;
            let result_keys = {
                let mut cursor = txn.cursor(&results)?;
                let mut item: Option<([u8; 8], ())> = cursor.first()?;
                let mut keys =
                    Vec::with_capacity(SELECTED_HISTORY_JOURNAL_COMPACTION_ENTRY_LIMIT - visited);
                while visited < SELECTED_HISTORY_JOURNAL_COMPACTION_ENTRY_LIMIT {
                    let Some((key, ())) = item else {
                        break;
                    };
                    let height =
                        recursive_proof_height_from_key(&key).ok_or(StoreError::Decode(
                            "invalid recursive proof result key during bounded compaction",
                        ))?;
                    if height >= cutoff {
                        break;
                    }
                    visited += 1;
                    keys.push(key);
                    item = cursor.next()?;
                }
                keys
            };
            for key in result_keys {
                txn.del(&results, &key, None)?;
                deleted += 1;
            }
        }

        #[cfg(test)]
        if deleted != 0 {
            hit_authoritative_mutation_fault(
                AuthoritativeMutationFault::SelectedJournalPruneBeforeCommit,
            )?;
        }
        txn.commit()?;
        #[cfg(test)]
        if deleted != 0 {
            hit_authoritative_mutation_fault(
                AuthoritativeMutationFault::SelectedJournalPruneAfterCommit,
            )?;
        }
        Ok(deleted)
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

    /// Read only the compact selected-history serving pointer.
    pub fn get_selected_history_coverage(
        &self,
    ) -> Result<Option<SelectedHistoryCoverage>, StoreError> {
        let txn = self.db.begin_ro_txn()?;
        let table = txn.open_table(Some(T_CHECKPOINT_COVERAGE))?;
        let raw: Option<[u8; SELECTED_HISTORY_COVERAGE_ENCODED_BYTES]> =
            txn.get(&table, KEY_SELECTED_HISTORY_COVERAGE)?;
        raw.map(|raw| {
            decode_selected_history_coverage(&raw).ok_or(StoreError::Decode(
                "invalid selected history coverage pointer",
            ))
        })
        .transpose()
    }

    /// Load the single promoted terminal package from one read snapshot.
    ///
    /// No result queue is collected or scanned. Fixed metadata, canonical
    /// header and object length are checked before the one proof `Vec` is
    /// allocated, then the stored wrapper is decoded in place.
    pub fn get_selected_history_terminal_result(
        &self,
    ) -> Result<Option<RecursiveProofJobResult>, StoreError> {
        let txn = self.db.begin_ro_txn()?;
        let coverage_table = txn.open_table(Some(T_CHECKPOINT_COVERAGE))?;
        let coverage_raw: Option<[u8; SELECTED_HISTORY_COVERAGE_ENCODED_BYTES]> =
            txn.get(&coverage_table, KEY_SELECTED_HISTORY_COVERAGE)?;
        let Some(coverage) = coverage_raw
            .as_ref()
            .and_then(|raw| decode_selected_history_coverage(raw))
        else {
            if coverage_raw.is_some() {
                return Err(StoreError::Decode(
                    "invalid selected history coverage pointer",
                ));
            }
            return Ok(None);
        };

        let headers = txn.open_table(Some(T_HEADERS))?;
        let header_raw: Option<Vec<u8>> = txn.get(&headers, &u64_key(coverage.height))?;
        if header_raw
            .as_deref()
            .and_then(canonical_hash_from_encoded_header)
            != Some(coverage.block_hash)
        {
            return Ok(None);
        }

        let key = recursive_proof_height_key(coverage.height);
        let jobs = txn.open_table(Some(T_RECURSIVE_PROOF_JOBS))?;
        let job_raw: Option<[u8; RECURSIVE_PROOF_JOB_ENCODED_BYTES]> = txn.get(&jobs, &key)?;
        let Some(job) = job_raw
            .as_ref()
            .and_then(|raw| decode_recursive_proof_job(coverage.height, raw))
        else {
            return Ok(None);
        };
        if job.state != RecursiveProofJobState::Complete || job.block_hash != coverage.block_hash {
            return Ok(None);
        }

        let results = txn.open_table(Some(T_RECURSIVE_PROOF_RESULTS))?;
        let result_length: Option<ObjectLength> = txn.get(&results, &key)?;
        let Some(ObjectLength(result_length)) = result_length else {
            return Ok(None);
        };
        let maximum = RECURSIVE_PROOF_RESULT_HEADER_BYTES
            + crate::consensus::wire_limits::MAX_HISTORY_PROOF_BYTES;
        if !(RECURSIVE_PROOF_RESULT_HEADER_BYTES..=maximum).contains(&result_length) {
            return Err(StoreError::Decode(
                "selected history terminal stored length exceeds hard bounds",
            ));
        }
        let encoded: Vec<u8> = txn
            .get(&results, &key)?
            .ok_or(StoreError::Decode("selected history terminal disappeared"))?;
        if encoded.len() != result_length {
            return Err(StoreError::Decode(
                "selected history terminal length changed during read",
            ));
        }
        let result = decode_recursive_proof_result(coverage.height, encoded).ok_or(
            StoreError::Decode("selected history terminal wrapper is malformed"),
        )?;
        if result.block_hash != coverage.block_hash
            || !selected_history_terminal_matches_job(
                &result.bytes,
                coverage.height,
                coverage.block_hash,
                job.tier,
            )
        {
            return Err(StoreError::Decode(
                "selected history terminal payload does not match coverage",
            ));
        }
        Ok(Some(result))
    }

    /// Load one exact canonical selected-history result by its locally chosen
    /// boundary instead of implicitly using the newest coverage pointer.
    ///
    /// Snapshot serving uses this when local proof coverage has advanced past
    /// finality: it serves the result at the finalized height without scanning
    /// or collecting the intervening result table. All fixed metadata and the
    /// stored object length are checked before allocating the one proof value.
    pub fn get_selected_history_terminal_result_at(
        &self,
        height: u64,
        block_hash: [u8; 32],
    ) -> Result<Option<RecursiveProofJobResult>, StoreError> {
        let txn = self.db.begin_ro_txn()?;
        let headers = txn.open_table(Some(T_HEADERS))?;
        let header_raw: Option<Vec<u8>> = txn.get(&headers, &u64_key(height))?;
        if header_raw
            .as_deref()
            .and_then(canonical_hash_from_encoded_header)
            != Some(block_hash)
        {
            return Ok(None);
        }

        let key = recursive_proof_height_key(height);
        let jobs = txn.open_table(Some(T_RECURSIVE_PROOF_JOBS))?;
        let job_raw: Option<[u8; RECURSIVE_PROOF_JOB_ENCODED_BYTES]> = txn.get(&jobs, &key)?;
        let Some(job) = job_raw
            .as_ref()
            .and_then(|raw| decode_recursive_proof_job(height, raw))
        else {
            return Ok(None);
        };
        if job.state != RecursiveProofJobState::Complete || job.block_hash != block_hash {
            return Ok(None);
        }

        let results = txn.open_table(Some(T_RECURSIVE_PROOF_RESULTS))?;
        let result_length: Option<ObjectLength> = txn.get(&results, &key)?;
        let Some(ObjectLength(result_length)) = result_length else {
            return Ok(None);
        };
        let maximum = RECURSIVE_PROOF_RESULT_HEADER_BYTES
            + crate::consensus::wire_limits::MAX_HISTORY_PROOF_BYTES;
        if !(RECURSIVE_PROOF_RESULT_HEADER_BYTES..=maximum).contains(&result_length) {
            return Err(StoreError::Decode(
                "selected history terminal stored length exceeds hard bounds",
            ));
        }
        let encoded: Vec<u8> = txn
            .get(&results, &key)?
            .ok_or(StoreError::Decode("selected history terminal disappeared"))?;
        if encoded.len() != result_length {
            return Err(StoreError::Decode(
                "selected history terminal length changed during read",
            ));
        }
        let result = decode_recursive_proof_result(height, encoded).ok_or(StoreError::Decode(
            "selected history terminal wrapper is malformed",
        ))?;
        if result.block_hash != block_hash
            || !selected_history_terminal_matches_job(&result.bytes, height, block_hash, job.tier)
        {
            return Err(StoreError::Decode(
                "selected history terminal payload does not match requested boundary",
            ));
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

    /// Read the durable forward ladder cursor boundary, if any.
    pub fn get_selected_history_ladder_meta(
        &self,
    ) -> Result<Option<SelectedHistoryLadderMeta>, StoreError> {
        self.historical_read_snapshot()?
            .get_selected_history_ladder_meta()
    }

    /// Advance the forward ladder cursor by one canonical block without
    /// completing any proof job. Bootstrap fast-forward uses this to rebuild
    /// the cursor from retained canonical blocks; promotion advances it inside
    /// the same transaction as the proof result instead.
    pub(crate) fn advance_selected_history_ladder_cursor(
        &self,
        header: &BlockHeader,
        update: &SelectedHistoryLadderUpdate,
    ) -> Result<(), StoreError> {
        let txn = self.db.begin_rw_txn()?;
        let headers = txn.open_table(Some(T_HEADERS))?;
        let stored_raw: Option<Vec<u8>> = txn.get(&headers, &u64_key(header.height))?;
        if stored_raw.as_deref().and_then(decode_header).as_ref() != Some(header) {
            return Err(StoreError::Decode(
                "ladder cursor advance header is not canonical",
            ));
        }
        apply_selected_history_ladder_update_in_rw_txn(
            &txn,
            header,
            crate::block_header::block_id(header),
            update,
        )?;
        txn.commit()?;
        Ok(())
    }

    /// Whether a retained block body exists at `height`, without loading it.
    pub(crate) fn has_recent_block(&self, height: u64) -> Result<bool, StoreError> {
        let txn = self.db.begin_ro_txn()?;
        let table = txn.open_table(Some(T_RECENT_BLOCKS))?;
        let length: Option<ObjectLength> = txn.get(&table, &u64_key(height))?;
        Ok(length.is_some())
    }

    /// Startup validation: the ladder cursor boundary must decode and match
    /// the canonical header at its height; otherwise it is cleared so the
    /// fail-closed bootstrap rebuilds it. Segment payloads stay lazily
    /// root-checked at load time.
    fn validate_selected_history_ladder_cursor_on_open(&self) -> Result<(), StoreError> {
        let txn = self.db.begin_rw_txn()?;
        let meta_table = txn.open_table(Some(T_LADDER_META))?;
        let raw: Option<Vec<u8>> = txn.get(&meta_table, KEY_LADDER_META)?;
        let Some(raw) = raw else {
            txn.commit()?;
            return Ok(());
        };
        let headers = txn.open_table(Some(T_HEADERS))?;
        let valid = decode_selected_history_ladder_meta(&raw).is_some_and(|meta| {
            let header = txn
                .get::<Vec<u8>>(&headers, &u64_key(meta.height))
                .ok()
                .flatten()
                .as_deref()
                .and_then(decode_header);
            let exact_entries: Vec<(u16, [u8; 32])> = meta
                .segment_summaries
                .iter()
                .map(|&(segment_id, _, exact_root)| (segment_id, exact_root))
                .collect();
            header.is_some_and(|header| {
                header.height == meta.height
                    && crate::block_header::block_id(&header) == meta.block_hash
                    && header.log_slots == meta.log_slots
                    && header.active_slot_count == meta.active_slot_count
                    && header.alloc_counter == meta.alloc_counter
                    && exact_state_root_from_segment_summaries(
                        meta.log_slots as usize,
                        &exact_entries,
                    ) == Some(header.state_root)
            })
        });
        if !valid {
            clear_selected_history_ladder_cursor_in_rw_txn(&txn)?;
        }
        txn.commit()?;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn put_raw_selected_history_ladder_meta_for_test(
        &self,
        bytes: &[u8],
    ) -> Result<(), StoreError> {
        let txn = self.db.begin_rw_txn()?;
        let table = txn.open_table(Some(T_LADDER_META))?;
        txn.put(&table, KEY_LADDER_META, bytes, WriteFlags::empty())?;
        txn.commit()?;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn put_raw_selected_history_ladder_segment_for_test(
        &self,
        segment_id: u16,
        bytes: &[u8],
    ) -> Result<(), StoreError> {
        let txn = self.db.begin_rw_txn()?;
        let table = txn.open_table(Some(T_LADDER_SEGMENTS))?;
        txn.put(
            &table,
            ladder_segment_key(segment_id),
            bytes,
            WriteFlags::empty(),
        )?;
        txn.commit()?;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn delete_undo_log_for_test(&self, height: u64) -> Result<(), StoreError> {
        let txn = self.db.begin_rw_txn()?;
        let table = txn.open_table(Some(T_UNDO_LOGS))?;
        let _ = txn.del(&table, u64_key(height), None);
        txn.commit()?;
        Ok(())
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
        rewind_selected_history_ladder_cursor(&txn, ancestor_height)?;
        rewind_selected_history_coverage(&txn, ancestor_height)?;
        rewind_retained_payload_prune_watermark(&txn, ancestor_height)?;
        authoritative_mutation_boundary!(DeleteAboveBeforeCommit);
        txn.commit()?;
        authoritative_mutation_boundary!(DeleteAboveAfterCommit);
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

        authoritative_mutation_boundary!(VerifiedHeaderBeforeCommit);
        txn.commit()?;
        authoritative_mutation_boundary!(VerifiedHeaderAfterCommit);
        Ok(())
    }

    /// Atomically promote at most 512 contiguous authenticated headers.
    ///
    /// The transaction accepts an exact already-present prefix followed by a
    /// missing suffix.  Every existing row and secondary record must match;
    /// every new child must extend a complete parent record and exact
    /// cumulative chainwork in this same MDBX view.  Consequently retry after
    /// a crash is idempotent, while any gap, partial row, or canonical conflict
    /// aborts the complete batch without exposing a partial prefix.
    pub fn put_verified_headers_batch(
        &self,
        records: &[VerifiedHeaderBatchRecord],
    ) -> Result<VerifiedHeaderBatchOutcome, StoreError> {
        if records.is_empty() {
            return Ok(VerifiedHeaderBatchOutcome::default());
        }
        if records.len() > MAX_VERIFIED_HEADER_BATCH_RECORDS {
            return Err(StoreError::Decode(
                "verified header batch exceeds bounded record cap",
            ));
        }

        for (index, record) in records.iter().enumerate() {
            if crate::block_header::block_id(&record.header) != record.hash {
                return Err(StoreError::Decode(
                    "verified header batch supplied hash mismatch",
                ));
            }
            if let Some(previous) = index.checked_sub(1).map(|i| &records[i]) {
                let expected_height = previous
                    .header
                    .height
                    .checked_add(1)
                    .ok_or(StoreError::Decode("verified header batch height overflow"))?;
                if record.header.height != expected_height {
                    return Err(StoreError::Decode(
                        "verified header batch heights are not contiguous",
                    ));
                }
            }
        }

        let txn = self.db.begin_rw_txn()?;
        let hdr_tbl = txn.open_table(Some(T_HEADERS))?;
        let h2h_tbl = txn.open_table(Some(T_HASH_TO_HEIGHT))?;
        let work_tbl = txn.open_table(Some(T_CHAIN_WORK))?;
        let anchor_tbl = txn.open_table(Some(T_HEADER_ANCHORS))?;
        let mut outcome = VerifiedHeaderBatchOutcome::default();
        let mut encountered_missing = false;

        for record in records {
            let height_key = u64_key(record.header.height);

            let anchor = if record.header.height == 0 {
                compute_header_chain_anchor(
                    std::iter::once(&record.header),
                    record.cumulative_chainwork,
                )?
            } else {
                let parent_height = record.header.height - 1;
                let parent_key = u64_key(parent_height);
                let parent_header_raw: Option<Vec<u8>> = txn.get(&hdr_tbl, &parent_key)?;
                let parent_header = parent_header_raw.as_deref().and_then(decode_header).ok_or(
                    StoreError::Decode("verified header batch parent header is missing or invalid"),
                )?;
                let parent_hash = crate::block_header::block_id(&parent_header);
                if record.header.prev_block_hash != parent_hash {
                    return Err(StoreError::Decode(
                        "verified header batch parent hash mismatch",
                    ));
                }
                let parent_height_raw: Option<Vec<u8>> =
                    txn.get(&h2h_tbl, parent_hash.as_slice())?;
                if parent_height_raw.as_deref().and_then(u64_from_key) != Some(parent_height) {
                    return Err(StoreError::Decode(
                        "verified header batch parent hash index is missing or inconsistent",
                    ));
                }
                let parent_work_raw: Option<Vec<u8>> = txn.get(&work_tbl, &parent_key)?;
                let parent_work = parent_work_raw
                    .as_deref()
                    .and_then(decode_chain_work)
                    .ok_or(StoreError::Decode(
                        "verified header batch parent chainwork is missing or invalid",
                    ))?;
                let parent_anchor_raw: Option<Vec<u8>> = txn.get(&anchor_tbl, &parent_key)?;
                let parent_anchor = parent_anchor_raw
                    .as_deref()
                    .and_then(decode_header_chain_anchor)
                    .ok_or(StoreError::Decode(
                        "verified header batch parent anchor is missing or invalid",
                    ))?;
                let expected_parent_anchor = HeaderChainAnchor {
                    height: parent_height,
                    block_id: parent_hash,
                    state_root: parent_header.state_root,
                    tx_root: parent_header.tx_root,
                    miner_address: parent_header.miner_address,
                    log_slots: parent_header.log_slots,
                    active_slot_count: parent_header.active_slot_count,
                    alloc_counter: parent_header.alloc_counter,
                    cumulative_chainwork: parent_work,
                };
                if parent_anchor != expected_parent_anchor {
                    return Err(StoreError::Decode(
                        "verified header batch parent anchor is inconsistent",
                    ));
                }
                let expected_work = crate::consensus::add_work(
                    &parent_work,
                    &crate::consensus::block_work(&record.header.difficulty_target),
                );
                if record.cumulative_chainwork != expected_work {
                    return Err(StoreError::Decode(
                        "verified header batch cumulative chainwork mismatch",
                    ));
                }
                extend_header_chain_anchor(
                    &parent_anchor,
                    &record.header,
                    record.cumulative_chainwork,
                )?
            };
            if anchor.block_id != record.hash {
                return Err(StoreError::Decode(
                    "verified header batch anchor block id mismatch",
                ));
            }

            let stored_header_raw: Option<Vec<u8>> = txn.get(&hdr_tbl, &height_key)?;
            let stored_hash_height_raw: Option<Vec<u8>> =
                txn.get(&h2h_tbl, record.hash.as_slice())?;
            let stored_work_raw: Option<Vec<u8>> = txn.get(&work_tbl, &height_key)?;
            let stored_anchor_raw: Option<Vec<u8>> = txn.get(&anchor_tbl, &height_key)?;

            if let Some(stored_header_raw) = stored_header_raw {
                if encountered_missing {
                    return Err(StoreError::Decode(
                        "verified header batch canonical table contains a gap",
                    ));
                }
                if decode_header(&stored_header_raw) != Some(record.header)
                    || stored_hash_height_raw.as_deref().and_then(u64_from_key)
                        != Some(record.header.height)
                    || stored_work_raw.as_deref().and_then(decode_chain_work)
                        != Some(record.cumulative_chainwork)
                    || stored_anchor_raw
                        .as_deref()
                        .and_then(decode_header_chain_anchor)
                        != Some(anchor)
                {
                    return Err(StoreError::Decode(
                        "verified header batch conflicts with canonical records",
                    ));
                }
                outcome.existing += 1;
                continue;
            }

            encountered_missing = true;
            if stored_hash_height_raw.is_some()
                || stored_work_raw.is_some()
                || stored_anchor_raw.is_some()
            {
                return Err(StoreError::Decode(
                    "verified header batch found partial canonical records",
                ));
            }

            txn.put(
                &hdr_tbl,
                height_key,
                encode_header(&record.header),
                WriteFlags::empty(),
            )?;
            txn.put(
                &h2h_tbl,
                record.hash.as_slice(),
                height_key,
                WriteFlags::empty(),
            )?;
            txn.put(
                &work_tbl,
                height_key,
                encode_chain_work(&record.cumulative_chainwork),
                WriteFlags::empty(),
            )?;
            txn.put(
                &anchor_tbl,
                height_key,
                encode_header_chain_anchor(&anchor),
                WriteFlags::empty(),
            )?;
            outcome.promoted += 1;
        }

        authoritative_mutation_boundary!(VerifiedHeaderBeforeCommit);
        txn.commit()?;
        authoritative_mutation_boundary!(VerifiedHeaderAfterCommit);
        Ok(outcome)
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

    /// Load one retained block/proof/authorization/attestation bundle from a
    /// single MDBX snapshot after checking every stored length with
    /// `ObjectLength`.
    ///
    /// This is the P2P serving boundary: corrupt or substituted database values
    /// cannot make the node allocate beyond consensus wire caps before their
    /// lengths are rejected. The four payloads are mutually snapshot-stable.
    #[allow(clippy::type_complexity)]
    pub fn get_recent_block_bundle_bounded(
        &self,
        height: u64,
    ) -> Result<Option<(Vec<u8>, Option<Vec<u8>>, Option<Vec<u8>>, Option<Vec<u8>>)>, StoreError>
    {
        use crate::consensus::wire_limits::{
            proof_sidecar_combined_len_ok, MAX_BLOCK_AUTH_SIDECAR_BYTES, MAX_BLOCK_BYTES,
            MAX_BLOCK_PROOF_BYTES, MAX_COVERAGE_ATTESTATION_BYTES,
        };

        let txn = self.db.begin_ro_txn()?;
        let key = u64_key(height);
        let blocks = txn.open_table(Some(T_RECENT_BLOCKS))?;
        let proofs = txn.open_table(Some(T_BLOCK_PROOFS))?;
        let sidecars = txn.open_table(Some(T_BLOCK_AUTH_SIDECARS))?;
        let attestations = txn.open_table(Some(T_COVERAGE_ATTESTATIONS))?;
        let block_len: Option<ObjectLength> = txn.get(&blocks, &key)?;
        let proof_len: Option<ObjectLength> = txn.get(&proofs, &key)?;
        let sidecar_len: Option<ObjectLength> = txn.get(&sidecars, &key)?;
        let attestation_len: Option<ObjectLength> = txn.get(&attestations, &key)?;

        let Some(ObjectLength(block_len)) = block_len else {
            if proof_len.is_some() || sidecar_len.is_some() || attestation_len.is_some() {
                return Err(StoreError::Decode(
                    "retained proof material exists without its block",
                ));
            }
            return Ok(None);
        };
        if block_len == 0 || block_len > MAX_BLOCK_BYTES {
            return Err(StoreError::Decode(
                "retained block stored length exceeds hard bounds",
            ));
        }
        if proof_len.is_some() != sidecar_len.is_some() {
            return Err(StoreError::Decode(
                "retained block proof and authorization sidecar presence mismatch",
            ));
        }
        let proof_bytes_len = proof_len.map_or(0, |ObjectLength(length)| length);
        let sidecar_bytes_len = sidecar_len.map_or(0, |ObjectLength(length)| length);
        if proof_bytes_len > MAX_BLOCK_PROOF_BYTES
            || sidecar_bytes_len > MAX_BLOCK_AUTH_SIDECAR_BYTES
            || !proof_sidecar_combined_len_ok(proof_bytes_len, sidecar_bytes_len)
        {
            return Err(StoreError::Decode(
                "retained block proof material exceeds hard bounds",
            ));
        }
        if let Some(ObjectLength(length)) = attestation_len {
            if length == 0 || length > MAX_COVERAGE_ATTESTATION_BYTES {
                return Err(StoreError::Decode(
                    "retained coverage attestation exceeds hard bounds",
                ));
            }
        }

        let block: Vec<u8> = txn
            .get(&blocks, &key)?
            .ok_or(StoreError::Decode("retained block disappeared during read"))?;
        if block.len() != block_len {
            return Err(StoreError::Decode(
                "retained block length changed during read",
            ));
        }
        let proof = if let Some(ObjectLength(expected)) = proof_len {
            let bytes: Vec<u8> = txn.get(&proofs, &key)?.ok_or(StoreError::Decode(
                "retained block proof disappeared during read",
            ))?;
            if bytes.len() != expected {
                return Err(StoreError::Decode(
                    "retained block proof length changed during read",
                ));
            }
            Some(bytes)
        } else {
            None
        };
        let sidecar = if let Some(ObjectLength(expected)) = sidecar_len {
            let bytes: Vec<u8> = txn.get(&sidecars, &key)?.ok_or(StoreError::Decode(
                "retained block authorization sidecar disappeared during read",
            ))?;
            if bytes.len() != expected {
                return Err(StoreError::Decode(
                    "retained block authorization sidecar length changed during read",
                ));
            }
            Some(bytes)
        } else {
            None
        };
        let attestation = if let Some(ObjectLength(expected)) = attestation_len {
            let bytes: Vec<u8> = txn.get(&attestations, &key)?.ok_or(StoreError::Decode(
                "retained coverage attestation disappeared during read",
            ))?;
            if bytes.len() != expected {
                return Err(StoreError::Decode(
                    "retained coverage attestation length changed during read",
                ));
            }
            Some(bytes)
        } else {
            None
        };
        Ok(Some((block, proof, sidecar, attestation)))
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

    /// Store the serialized coverage-attestation envelope carried by the
    /// accepted block at `height`. Retained with the block body so peers can
    /// re-verify the coverage advancement.
    pub fn put_coverage_attestation(&self, height: u64, bytes: &[u8]) -> Result<(), StoreError> {
        if bytes.len() > crate::consensus::wire_limits::MAX_COVERAGE_ATTESTATION_BYTES {
            return Err(StoreError::Decode("coverage attestation exceeds wire cap"));
        }
        let txn = self.db.begin_rw_txn()?;
        let tbl = txn.open_table(Some(T_COVERAGE_ATTESTATIONS))?;
        txn.put(&tbl, u64_key(height), bytes, WriteFlags::empty())?;
        txn.commit()?;
        Ok(())
    }

    /// Retrieve the coverage-attestation envelope bytes carried by the block
    /// at `height`, or `None` when that block kept its parent's coverage.
    pub fn get_coverage_attestation(&self, height: u64) -> Result<Option<Vec<u8>>, StoreError> {
        let txn = self.db.begin_ro_txn()?;
        let tbl = txn.open_table(Some(T_COVERAGE_ATTESTATIONS))?;
        let raw: Option<Vec<u8>> = txn.get(&tbl, &u64_key(height))?;
        if let Some(raw) = raw.as_ref() {
            if raw.is_empty()
                || raw.len() > crate::consensus::wire_limits::MAX_COVERAGE_ATTESTATION_BYTES
            {
                return Err(StoreError::Decode(
                    "stored coverage attestation violates wire cap",
                ));
            }
        }
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
        if bytes.is_empty() {
            return Err(StoreError::Decode("accepted block certificate is empty"));
        }
        let txn = self.db.begin_rw_txn()?;
        let headers = txn.open_table(Some(T_HEADERS))?;
        let header_raw: Option<Vec<u8>> = txn.get(&headers, &u64_key(height))?;
        let block_hash = header_raw
            .as_deref()
            .and_then(canonical_hash_from_encoded_header)
            .ok_or(StoreError::Decode(
                "accepted block certificate canonical header is missing",
            ))?;
        let tbl = txn.open_table(Some(T_ACCEPTED_BLOCK_CERTIFICATES))?;
        txn.put(&tbl, u64_key(height), bytes, WriteFlags::empty())?;
        let bindings = txn.open_table(Some(T_ACCEPTED_BLOCK_CERTIFICATE_BINDINGS))?;
        txn.put(
            &bindings,
            u64_key(height),
            encode_accepted_block_certificate_binding(height, block_hash, bytes.len())?,
            WriteFlags::empty(),
        )?;
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
        let certificate_len = txn
            .get::<ObjectLength>(&tbl, &u64_key(height))?
            .map(|ObjectLength(length)| length);
        let bindings = txn.open_table(Some(T_ACCEPTED_BLOCK_CERTIFICATE_BINDINGS))?;
        let binding_raw: Option<[u8; ACCEPTED_BLOCK_CERTIFICATE_BINDING_BYTES]> =
            txn.get(&bindings, &u64_key(height))?;
        let (Some(certificate_len), Some(binding_raw)) = (certificate_len, binding_raw) else {
            if certificate_len.is_none() && binding_raw.is_none() {
                return Ok(None);
            }
            return Err(StoreError::Decode(
                "accepted block certificate and binding disagree",
            ));
        };
        if certificate_len == 0 {
            return Err(StoreError::Decode("accepted block certificate is empty"));
        }
        let binding = decode_accepted_block_certificate_binding(&binding_raw).ok_or(
            StoreError::Decode("accepted block certificate binding is malformed"),
        )?;
        let headers = txn.open_table(Some(T_HEADERS))?;
        let header_raw: Option<Vec<u8>> = txn.get(&headers, &u64_key(height))?;
        let canonical_hash = header_raw
            .as_deref()
            .and_then(canonical_hash_from_encoded_header)
            .ok_or(StoreError::Decode(
                "accepted block certificate canonical header is missing",
            ))?;
        if binding.height != height
            || binding.block_hash != canonical_hash
            || usize::try_from(binding.certificate_len).ok() != Some(certificate_len)
        {
            return Err(StoreError::Decode(
                "accepted block certificate binding is not canonical",
            ));
        }
        let certificate: Vec<u8> = txn.get(&tbl, &u64_key(height))?.ok_or(StoreError::Decode(
            "accepted block certificate disappeared after preflight",
        ))?;
        if certificate.len() != certificate_len {
            return Err(StoreError::Decode(
                "accepted block certificate length changed during read",
            ));
        }
        Ok(Some(certificate))
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
            attested_coverage: header.attested_coverage,
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
        self.install_finalized_snapshot_staging_inner(
            staging,
            consensus_meta,
            canonical_recent_headers,
            None,
        )
    }

    /// Production snapshot installer that atomically seeds the recursive
    /// boundary used by the next selected-history job. A crash can expose
    /// neither snapshot state without its verified terminal package nor the
    /// package without the matching state epoch.
    pub(crate) fn install_finalized_snapshot_staging_with_selected_history(
        &self,
        staging: &FinalizedSnapshotStaging,
        consensus_meta: &ConsensusMeta,
        canonical_recent_headers: &[BlockHeader],
        selected_history: SelectedHistorySnapshotSeed<'_>,
    ) -> Result<ChainState, StoreError> {
        self.install_finalized_snapshot_staging_inner(
            staging,
            consensus_meta,
            canonical_recent_headers,
            Some(selected_history),
        )
    }

    fn install_finalized_snapshot_staging_inner(
        &self,
        staging: &FinalizedSnapshotStaging,
        consensus_meta: &ConsensusMeta,
        canonical_recent_headers: &[BlockHeader],
        selected_history: Option<SelectedHistorySnapshotSeed<'_>>,
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
        let selected_history = selected_history
            .map(|seed| {
                if seed.height == 0
                    || seed.height != tip_header.height
                    || seed.block_hash != tip_hash
                    || seed.terminal_package_bytes.len()
                        > crate::consensus::wire_limits::MAX_HISTORY_PROOF_BYTES
                    || !selected_history_terminal_matches_job(
                        seed.terminal_package_bytes,
                        seed.height,
                        seed.block_hash,
                        seed.tier,
                    )
                {
                    return Err(StoreError::Decode(
                        "selected history snapshot seed does not match snapshot boundary",
                    ));
                }
                let encoded =
                    encode_recursive_proof_result(seed.block_hash, seed.terminal_package_bytes)?;
                Ok((seed, encoded))
            })
            .transpose()?;

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
            T_COVERAGE_ATTESTATIONS,
            T_HISTORY_CLAIMS,
            T_ACCEPTED_BLOCK_CERTIFICATES,
            T_ACCEPTED_BLOCK_CERTIFICATE_BINDINGS,
            T_ACCEPTED_BLOCK_BATCH_CERTIFICATE_PACKAGES,
            T_HISTORY_CHECKPOINT_HEADS,
            T_OWNER_INDEX,
            T_CHECKPOINT_PACKAGES,
            T_CHECKPOINT_COVERAGE,
            T_RECURSIVE_PROOF_JOBS,
            T_RECURSIVE_PROOF_RESULTS,
            T_LADDER_SEGMENTS,
            T_LADDER_META,
        ] {
            let table = txn.open_table(Some(name))?;
            txn.clear_table(&table)?;
        }

        // Every older retained payload table was cleared atomically above.
        // Seed the numeric maintenance frontier at the installed boundary so
        // a later selected-coverage jump never rescans the absent prefix.
        set_retained_payload_prune_watermark(&txn, tip_header.height)?;

        let seed_ladder_cursor = selected_history.is_some();
        if let Some((seed, encoded_result)) = selected_history {
            let job = RecursiveProofJob {
                height: seed.height,
                block_hash: seed.block_hash,
                tier: seed.tier,
                state: RecursiveProofJobState::Complete,
                attempt_counter: 0,
            };
            let key = recursive_proof_height_key(seed.height);
            let jobs = txn.open_table(Some(T_RECURSIVE_PROOF_JOBS))?;
            txn.put(
                &jobs,
                key,
                encode_recursive_proof_job(&job),
                WriteFlags::empty(),
            )?;
            let results = txn.open_table(Some(T_RECURSIVE_PROOF_RESULTS))?;
            txn.put(&results, key, encoded_result, WriteFlags::empty())?;
            let coverage = txn.open_table(Some(T_CHECKPOINT_COVERAGE))?;
            txn.put(
                &coverage,
                KEY_SELECTED_HISTORY_COVERAGE,
                encode_selected_history_coverage(SelectedHistoryCoverage {
                    height: seed.height,
                    block_hash: seed.block_hash,
                }),
                WriteFlags::empty(),
            )?;
        }

        let segment_tbl = txn.open_table(Some(T_SEGMENTS))?;
        let owner_tbl = txn.open_table(Some(T_OWNER_INDEX))?;
        let ladder_segment_tbl = txn.open_table(Some(T_LADDER_SEGMENTS))?;
        let mut ladder_summaries = Vec::with_capacity(staging.descriptors().len());
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
                let creation_in_target =
                    if crate::consensus::params::is_coinbase_creation_id(slot.creation_id()) {
                        crate::consensus::params::coinbase_creation_height(slot.creation_id())
                            <= tip_header.height
                    } else {
                        slot.creation_id() <= tip_header.alloc_counter
                    };
                if !creation_in_target {
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
            let exact_root = exact_segment_root_from_columns(effective_log as usize, &columns);
            exact_segment_roots.push((descriptor.segment_id, exact_root));
            if seed_ladder_cursor {
                // The recursive boundary seed makes this snapshot the prover's
                // next Link predecessor; the same validated payloads seed the
                // forward ladder cursor at the identical boundary.
                txn.put(
                    &ladder_segment_tbl,
                    ladder_segment_key(descriptor.segment_id),
                    &encoded,
                    WriteFlags::empty(),
                )?;
                ladder_summaries.push((descriptor.segment_id, segment_live, exact_root));
            }
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
        if seed_ladder_cursor {
            let ladder_meta_tbl = txn.open_table(Some(T_LADDER_META))?;
            txn.put(
                &ladder_meta_tbl,
                KEY_LADDER_META,
                encode_selected_history_ladder_meta(&SelectedHistoryLadderMeta {
                    height: tip_header.height,
                    block_hash: tip_hash,
                    log_slots: tip_header.log_slots,
                    active_slot_count: tip_header.active_slot_count,
                    alloc_counter: tip_header.alloc_counter,
                    segment_summaries: ladder_summaries,
                })?,
                WriteFlags::empty(),
            )?;
        }

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

        authoritative_mutation_boundary!(SnapshotInstallBeforeCommit);
        txn.commit()?;
        authoritative_mutation_boundary!(SnapshotInstallAfterCommit);
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
            T_COVERAGE_ATTESTATIONS,
            T_HISTORY_CLAIMS,
            T_ACCEPTED_BLOCK_CERTIFICATES,
            T_ACCEPTED_BLOCK_CERTIFICATE_BINDINGS,
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

        set_retained_payload_prune_watermark(&txn, tip_header.height)?;

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

            // Coverage attestation follows the same delete-on-empty contract
            // so a reorg replacing an attesting block cannot leave a stale
            // envelope bound to a different header at this height.
            let attestation_tbl = txn.open_table(Some(T_COVERAGE_ATTESTATIONS))?;
            if accepted.coverage_attestation_bytes.is_empty() {
                let _ = txn.del(&attestation_tbl, height_key, None);
            } else {
                if accepted.coverage_attestation_bytes.len()
                    > crate::consensus::wire_limits::MAX_COVERAGE_ATTESTATION_BYTES
                {
                    return Err(StoreError::Decode(
                        "accepted coverage attestation exceeds wire cap",
                    ));
                }
                txn.put(
                    &attestation_tbl,
                    height_key,
                    accepted.coverage_attestation_bytes,
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
            let certificate_binding_tbl =
                txn.open_table(Some(T_ACCEPTED_BLOCK_CERTIFICATE_BINDINGS))?;
            txn.put(
                &certificate_binding_tbl,
                height_key,
                encode_accepted_block_certificate_binding(
                    header.height,
                    *hash,
                    accepted.accepted_block_certificate_bytes.len(),
                )?,
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
        authoritative_mutation_boundary!(AcceptedBlockBeforeCommit);
        txn.commit()?;
        authoritative_mutation_boundary!(AcceptedBlockAfterCommit);

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

        // Roll the prover's forward ladder cursor back to the ancestor while
        // this transaction still holds the reverted branch's undo logs; the
        // truncation below deletes them. Reorgs deeper than the retained undo
        // window are rejected upstream, so the rewind is always in range.
        rewind_selected_history_ladder_cursor(&txn, ancestor_height)?;

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
            T_COVERAGE_ATTESTATIONS,
            T_HISTORY_CLAIMS,
            T_ACCEPTED_BLOCK_CERTIFICATES,
            T_ACCEPTED_BLOCK_CERTIFICATE_BINDINGS,
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
        rewind_selected_history_coverage(&txn, ancestor_height)?;
        rewind_retained_payload_prune_watermark(&txn, ancestor_height)?;

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
        let attestation_tbl = txn.open_table(Some(T_COVERAGE_ATTESTATIONS))?;
        let history_tbl = txn.open_table(Some(T_HISTORY_CLAIMS))?;
        let certificate_tbl = txn.open_table(Some(T_ACCEPTED_BLOCK_CERTIFICATES))?;
        let certificate_binding_tbl =
            txn.open_table(Some(T_ACCEPTED_BLOCK_CERTIFICATE_BINDINGS))?;
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
            if payload.coverage_attestation_bytes.is_empty() {
                let _ = txn.del(&attestation_tbl, height_key, None);
            } else {
                txn.put(
                    &attestation_tbl,
                    height_key,
                    payload.coverage_attestation_bytes,
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
            txn.put(
                &certificate_binding_tbl,
                height_key,
                encode_accepted_block_certificate_binding(
                    block.header.height,
                    block.hash,
                    block.accepted_block_certificate_bytes.len(),
                )?,
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

        authoritative_mutation_boundary!(ReorgBeforeCommit);
        txn.commit()?;
        authoritative_mutation_boundary!(ReorgAfterCommit);
        if let Err(_error) = self.prune_after_commit(final_header.height) {
            // The accepted branch is already durable.  Pruning is retryable
            // maintenance and must not masquerade as a failed reorg.
        }
        Ok(())
    }

    fn prune_after_commit(&self, current_height: u64) -> Result<(), StoreError> {
        // Retained payload maintenance owns one short transaction whose work
        // is bounded simultaneously by numeric heights, retired bytes, and
        // delete count. The watermark and deletions commit atomically.
        let txn = self.db.begin_rw_txn()?;
        prune_retained_payloads_bounded(&txn, current_height)?;
        authoritative_mutation_boundary!(RetainedPayloadPruneBeforeCommit);
        txn.commit()?;
        authoritative_mutation_boundary!(RetainedPayloadPruneAfterCommit);

        // --- Prune undo_logs older than UNDO_RETENTION_DEPTH ---
        if current_height > UNDO_RETENTION_DEPTH {
            let txn = self.db.begin_rw_txn()?;
            let undo_tbl = txn.open_table(Some(T_UNDO_LOGS))?;
            let cutoff = current_height - UNDO_RETENTION_DEPTH;
            delete_height_keys_at_or_below(&txn, &undo_tbl, cutoff)?;
            txn.commit()?;
        }
        // Journal cleanup is deliberately a separate short transaction. The
        // accepted block/pruning transaction is already durable and must not
        // be reported as failed if retryable maintenance cannot run.
        let _ = self.compact_selected_history_journal_bounded();
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
            T_COVERAGE_ATTESTATIONS,
            T_HISTORY_CLAIMS,
            T_ACCEPTED_BLOCK_CERTIFICATES,
            T_ACCEPTED_BLOCK_CERTIFICATE_BINDINGS,
            T_ACCEPTED_BLOCK_BATCH_CERTIFICATE_PACKAGES,
            T_HISTORY_CHECKPOINT_HEADS,
            T_OWNER_INDEX,
            T_CHECKPOINT_PACKAGES,
            T_CHECKPOINT_COVERAGE,
            T_RECURSIVE_PROOF_JOBS,
            T_RECURSIVE_PROOF_RESULTS,
            T_LADDER_SEGMENTS,
            T_LADDER_META,
        ];
        for name in tables {
            let tbl = txn.open_table(Some(name))?;
            txn.clear_table(&tbl)?;
        }
        authoritative_mutation_boundary!(EpochClearBeforeCommit);
        txn.commit()?;
        authoritative_mutation_boundary!(EpochClearAfterCommit);
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

    struct RecursiveLoaderFixture {
        claimed: RecursiveProofJob,
        parent_header: BlockHeader,
        block_header: BlockHeader,
        block_bytes: Vec<u8>,
        block_proof_bytes: Vec<u8>,
        block_auth_sidecar_bytes: Vec<u8>,
        previous_result_bytes: Vec<u8>,
    }

    fn recursive_loader_coinbase(tag: u8) -> noid_tx::Transaction {
        use noid_poseidon2b::primitives::Address;
        use noid_tx::{output_bitmap_bit, TxBody, TxInput, TxOutput, TX_INPUTS, TX_OUTPUTS};

        let mut outputs = [TxOutput::dummy(); TX_OUTPUTS];
        outputs[0] = TxOutput {
            slot_index: u32::from(tag),
            amount: 50,
            owner: Address([tag; 32]),
        };
        noid_tx::Transaction::new(TxBody {
            epoch_anchor: [tag; 32],
            fee: 0,
            input_owner: Address([0; 32]),
            inputs: [TxInput::dummy(); TX_INPUTS],
            outputs,
            validity_bitmap: output_bitmap_bit(0),
            is_coinbase: true,
        })
    }

    fn recursive_loader_user(tag: u8) -> noid_tx::Transaction {
        use noid_poseidon2b::primitives::Address;
        use noid_tx::{output_bitmap_bit, TxBody, TxInput, TxOutput, TX_INPUTS, TX_OUTPUTS};

        let mut inputs = [TxInput::dummy(); TX_INPUTS];
        inputs[0] = TxInput {
            slot_index: 100 + u32::from(tag),
            amount: 11,
            creation_id: u64::from(tag),
        };
        let mut outputs = [TxOutput::dummy(); TX_OUTPUTS];
        outputs[0] = TxOutput {
            slot_index: 200 + u32::from(tag),
            amount: 10,
            owner: Address([tag.wrapping_add(1); 32]),
        };
        noid_tx::Transaction::new(TxBody {
            epoch_anchor: [tag; 32],
            fee: 1,
            input_owner: Address([tag; 32]),
            inputs,
            outputs,
            validity_bitmap: 1 | output_bitmap_bit(0),
            is_coinbase: false,
        })
    }

    fn put_recursive_loader_records(
        store: &MdbxStore,
        height: u64,
        tip_hash: [u8; 32],
        block_bytes: &[u8],
        proof: Option<&[u8]>,
        sidecar: Option<&[u8]>,
    ) {
        let txn = store.db.begin_rw_txn().unwrap();
        let tip_table = txn.open_table(Some(T_CHAIN_TIP)).unwrap();
        txn.put(
            &tip_table,
            KEY_TIP,
            encode_chain_tip(height, &tip_hash),
            WriteFlags::empty(),
        )
        .unwrap();
        let recent = txn.open_table(Some(T_RECENT_BLOCKS)).unwrap();
        txn.put(&recent, u64_key(height), block_bytes, WriteFlags::empty())
            .unwrap();
        if let Some(proof) = proof {
            let table = txn.open_table(Some(T_BLOCK_PROOFS)).unwrap();
            txn.put(&table, u64_key(height), proof, WriteFlags::empty())
                .unwrap();
        }
        if let Some(sidecar) = sidecar {
            let table = txn.open_table(Some(T_BLOCK_AUTH_SIDECARS)).unwrap();
            txn.put(&table, u64_key(height), sidecar, WriteFlags::empty())
                .unwrap();
        }
        txn.commit().unwrap();
    }

    fn overwrite_selected_history_coverage_for_test(store: &MdbxStore, encoded: &[u8]) {
        let txn = store.db.begin_rw_txn().unwrap();
        let table = txn.open_table(Some(T_CHECKPOINT_COVERAGE)).unwrap();
        txn.put(
            &table,
            KEY_SELECTED_HISTORY_COVERAGE,
            encoded,
            WriteFlags::empty(),
        )
        .unwrap();
        txn.commit().unwrap();
    }

    fn recursive_loader_fixture(store: &MdbxStore) -> RecursiveLoaderFixture {
        use crate::block::Block;

        let genesis = crate::consensus::genesis::genesis_header();
        let genesis_hash = crate::hash_block_header(&genesis);
        store.put_header_only(&genesis, &genesis_hash).unwrap();

        let block_one_transactions = vec![recursive_loader_coinbase(1)];
        let mut parent_header = genesis;
        parent_header.height = 1;
        parent_header.prev_block_hash = genesis_hash;
        parent_header.timestamp = parent_header.timestamp.saturating_add(1);
        parent_header.nonce = 0x101;
        parent_header.tx_root = crate::block::compute_tx_root(&block_one_transactions);
        let parent_hash = crate::hash_block_header(&parent_header);
        store.put_header_only(&parent_header, &parent_hash).unwrap();
        store
            .enqueue_recursive_proof_job(1, parent_hash, RecursiveProofJobTier::B8)
            .unwrap();
        let parent_claim = store.claim_next_recursive_proof_job().unwrap().unwrap();
        let previous_result_bytes = selected_terminal_bytes(1, parent_claim.block_hash);
        store
            .complete_recursive_proof_job(1, parent_claim.block_hash, &previous_result_bytes)
            .unwrap();

        let transactions = vec![recursive_loader_coinbase(2), recursive_loader_user(2)];
        let mut block_header = parent_header;
        block_header.height = 2;
        block_header.prev_block_hash = parent_hash;
        block_header.timestamp = block_header.timestamp.saturating_add(1);
        block_header.nonce = 0x202;
        block_header.tx_root = crate::block::compute_tx_root(&transactions);
        let block_hash = crate::hash_block_header(&block_header);
        store.put_header_only(&block_header, &block_hash).unwrap();
        let block_bytes = Block {
            header: block_header,
            transactions,
        }
        .to_bytes();
        let block_proof_bytes = b"bounded-block-proof".to_vec();
        let block_auth_sidecar_bytes = b"bounded-auth-sidecar".to_vec();
        put_recursive_loader_records(
            store,
            2,
            block_hash,
            &block_bytes,
            Some(&block_proof_bytes),
            Some(&block_auth_sidecar_bytes),
        );
        store
            .enqueue_recursive_proof_job(2, block_hash, RecursiveProofJobTier::B8)
            .unwrap();
        let claimed = store.claim_next_recursive_proof_job().unwrap().unwrap();

        RecursiveLoaderFixture {
            claimed,
            parent_header,
            block_header,
            block_bytes,
            block_proof_bytes,
            block_auth_sidecar_bytes,
            previous_result_bytes,
        }
    }

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

    fn selected_terminal_bytes(height: u64, block_hash: [u8; 32]) -> Vec<u8> {
        selected_terminal_bytes_for_tier(height, block_hash, RecursiveProofJobTier::B8)
    }

    /// Ladder advance for synthetic fixture headers that carry the canonical
    /// empty state. Its empty dirty set is trivially self-contained, so no
    /// predecessor cursor boundary needs seeding.
    fn empty_ladder_update(header: &BlockHeader) -> SelectedHistoryLadderUpdate {
        SelectedHistoryLadderUpdate {
            log_slots: header.log_slots,
            active_slot_count: header.active_slot_count,
            alloc_counter: header.alloc_counter,
            state_root: header.state_root,
            segment_summaries: Vec::new(),
            dirty_segments: Vec::new(),
        }
    }

    fn selected_terminal_bytes_for_tier(
        height: u64,
        block_hash: [u8; 32],
        tier: RecursiveProofJobTier,
    ) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(SELECTED_HISTORY_TERMINAL_PREFIX_BYTES);
        bytes.extend_from_slice(&SELECTED_HISTORY_TERMINAL_VERSION.to_le_bytes());
        bytes.extend_from_slice(&height.to_le_bytes());
        bytes.extend_from_slice(&block_hash);
        bytes.push(tier as u8);
        bytes.extend_from_slice(&(tier.capacity() as u16).to_le_bytes());
        bytes
    }

    fn put_selected_history_header_chain(
        store: &MdbxStore,
        last_height: u64,
    ) -> Vec<(BlockHeader, [u8; 32])> {
        let genesis = crate::consensus::genesis::genesis_header();
        let genesis_hash = crate::hash_block_header(&genesis);
        store.put_header_only(&genesis, &genesis_hash).unwrap();
        let mut chain = vec![(genesis, genesis_hash)];
        for height in 1..=last_height {
            let (parent, parent_hash) = *chain.last().unwrap();
            let mut header = parent;
            header.height = height;
            header.prev_block_hash = parent_hash;
            header.timestamp = parent.timestamp.saturating_add(1);
            header.nonce = u128::from(height).saturating_add(0x51EC7ED);
            let hash = crate::hash_block_header(&header);
            store.put_header_only(&header, &hash).unwrap();
            chain.push((header, hash));
        }
        let (tip, tip_hash) = *chain.last().unwrap();
        store
            .put_consensus_meta(&ConsensusMeta {
                tip_height: tip.height,
                tip_hash,
                cumulative_chainwork: [0u8; 32],
                finalized: crate::storage::meta::FinalizedCheckpoint {
                    height: tip.height,
                    hash: tip_hash,
                },
            })
            .unwrap();
        chain
    }

    fn retained_payload_prune_watermark(store: &MdbxStore) -> Option<u64> {
        let txn = store.db.begin_ro_txn().unwrap();
        let table = txn.open_table(Some(T_CHECKPOINT_COVERAGE)).unwrap();
        let raw: Option<[u8; RETAINED_PAYLOAD_PRUNE_WATERMARK_BYTES]> = txn
            .get(&table, KEY_RETAINED_PAYLOAD_PRUNE_WATERMARK)
            .unwrap();
        raw.as_ref().map(|raw| {
            decode_retained_payload_prune_watermark(raw)
                .expect("valid retained payload prune watermark")
        })
    }

    fn put_retained_payload_fixture(store: &MdbxStore, height: u64) {
        let txn = store.db.begin_rw_txn().unwrap();
        for (table_name, bytes) in [
            (T_RECENT_BLOCKS, b"retained-block".as_slice()),
            (T_BLOCK_PROOFS, b"retained-proof".as_slice()),
            (T_BLOCK_AUTH_SIDECARS, b"retained-sidecar".as_slice()),
            (T_HISTORY_CLAIMS, b"retained-claim".as_slice()),
        ] {
            let table = txn.open_table(Some(table_name)).unwrap();
            txn.put(&table, u64_key(height), bytes, WriteFlags::empty())
                .unwrap();
        }
        txn.commit().unwrap();
        store
            .put_accepted_block_certificate(height, b"accepted-certificate")
            .unwrap();
    }

    fn install_selected_prune_authority(
        store: &MdbxStore,
        coverage_height: u64,
    ) -> (Vec<(BlockHeader, [u8; 32])>, u64) {
        let current_height = coverage_height + RECENT_BLOCK_RETENTION_DEPTH;
        let chain = put_selected_history_header_chain(store, current_height);
        let block_hash = chain[coverage_height as usize].1;
        store
            .enqueue_recursive_proof_job(coverage_height, block_hash, RecursiveProofJobTier::B8)
            .unwrap();
        store
            .import_verified_selected_history_terminal(VerifiedSelectedHistoryTerminalImport {
                height: coverage_height,
                block_hash,
                epoch_anchor_height: 0,
                epoch_anchor_hash: chain[0].1,
                tier: RecursiveProofJobTier::B8,
                terminal_package_bytes: &selected_terminal_bytes(coverage_height, block_hash),
            })
            .unwrap();
        (chain, current_height)
    }

    #[test]
    fn selected_terminal_metadata_binds_canonical_slot_tier_to_job() {
        let hash = [0xA5; 32];
        let mut bytes = selected_terminal_bytes(7, hash);
        assert!(selected_history_terminal_matches_job(
            &bytes,
            7,
            hash,
            RecursiveProofJobTier::B8,
        ));

        bytes[42] = 1;
        bytes[43..45].copy_from_slice(&32u16.to_le_bytes());
        assert!(selected_history_terminal_matches_job(
            &bytes,
            7,
            hash,
            RecursiveProofJobTier::B32,
        ));
        assert!(!selected_history_terminal_matches_job(
            &bytes,
            7,
            hash,
            RecursiveProofJobTier::B8,
        ));

        bytes[42] = 0;
        assert!(!selected_history_terminal_prefix_matches(&bytes, 7, hash));
    }

    fn overwrite_owner_index_record(store: &MdbxStore, key: &[u8], value: &[u8]) {
        let txn = store.db.begin_rw_txn().unwrap();
        let table = txn.open_table(Some(T_OWNER_INDEX)).unwrap();
        txn.clear_table(&table).unwrap();
        txn.put(&table, key, value, WriteFlags::empty()).unwrap();
        txn.commit().unwrap();
    }

    #[test]
    fn claimed_recursive_proof_inputs_load_one_atomic_owned_snapshot() {
        let directory = tempfile::tempdir().unwrap();
        let store = MdbxStore::open(directory.path()).unwrap();
        let fixture = recursive_loader_fixture(&store);

        let loaded = store
            .load_claimed_recursive_proof_job_inputs(fixture.claimed)
            .unwrap();
        assert_eq!(loaded.job, fixture.claimed);
        assert_eq!(loaded.source_tip, (2, fixture.claimed.block_hash));
        assert_eq!(loaded.parent_header, fixture.parent_header);
        assert_eq!(loaded.block_header, fixture.block_header);
        assert_eq!(loaded.user_transaction_count, 1);
        assert_eq!(loaded.block_bytes, fixture.block_bytes);
        assert_eq!(loaded.block_proof_bytes, fixture.block_proof_bytes);
        assert_eq!(
            loaded.block_auth_sidecar_bytes,
            fixture.block_auth_sidecar_bytes
        );
        let predecessor = loaded.previous_result.unwrap();
        assert_eq!(predecessor.height, 1);
        assert_eq!(
            predecessor.block_hash,
            crate::hash_block_header(&fixture.parent_header)
        );
        assert_eq!(predecessor.bytes, fixture.previous_result_bytes);
    }

    #[test]
    fn claimed_recursive_proof_expected_predecessor_matches_in_one_snapshot() {
        let directory = tempfile::tempdir().unwrap();
        let store = MdbxStore::open(directory.path()).unwrap();
        let fixture = recursive_loader_fixture(&store);
        let parent_hash = crate::hash_block_header(&fixture.parent_header);
        overwrite_selected_history_coverage_for_test(
            &store,
            &encode_selected_history_coverage(SelectedHistoryCoverage {
                height: fixture.parent_header.height,
                block_hash: parent_hash,
            }),
        );

        let (loaded, matches) = store
            .load_claimed_recursive_proof_job_inputs_with_expected_predecessor(
                fixture.claimed,
                fixture.parent_header.height,
                parent_hash,
                &fixture.previous_result_bytes,
            )
            .unwrap();

        assert!(matches);
        let predecessor = loaded.previous_result.unwrap();
        assert_eq!(predecessor.height, fixture.parent_header.height);
        assert_eq!(predecessor.block_hash, parent_hash);
        assert_eq!(predecessor.bytes, fixture.previous_result_bytes);
    }

    #[test]
    fn claimed_recursive_proof_expected_predecessor_mismatches_fail_closed() {
        let directory = tempfile::tempdir().unwrap();
        let store = MdbxStore::open(directory.path()).unwrap();
        let fixture = recursive_loader_fixture(&store);
        let parent_height = fixture.parent_header.height;
        let parent_hash = crate::hash_block_header(&fixture.parent_header);
        overwrite_selected_history_coverage_for_test(
            &store,
            &encode_selected_history_coverage(SelectedHistoryCoverage {
                height: parent_height,
                block_hash: parent_hash,
            }),
        );

        let (_, height_matches) = store
            .load_claimed_recursive_proof_job_inputs_with_expected_predecessor(
                fixture.claimed,
                parent_height + 1,
                parent_hash,
                &fixture.previous_result_bytes,
            )
            .unwrap();
        assert!(!height_matches);

        let mut wrong_hash = parent_hash;
        wrong_hash[0] ^= 1;
        let (_, hash_matches) = store
            .load_claimed_recursive_proof_job_inputs_with_expected_predecessor(
                fixture.claimed,
                parent_height,
                wrong_hash,
                &fixture.previous_result_bytes,
            )
            .unwrap();
        assert!(!hash_matches);

        let mut wrong_bytes = fixture.previous_result_bytes.clone();
        wrong_bytes.push(0);
        let (_, bytes_match) = store
            .load_claimed_recursive_proof_job_inputs_with_expected_predecessor(
                fixture.claimed,
                parent_height,
                parent_hash,
                &wrong_bytes,
            )
            .unwrap();
        assert!(!bytes_match);

        overwrite_selected_history_coverage_for_test(
            &store,
            &encode_selected_history_coverage(SelectedHistoryCoverage {
                height: 0,
                block_hash: [0xA5; 32],
            }),
        );
        let (_, coverage_matches) = store
            .load_claimed_recursive_proof_job_inputs_with_expected_predecessor(
                fixture.claimed,
                parent_height,
                parent_hash,
                &fixture.previous_result_bytes,
            )
            .unwrap();
        assert!(!coverage_matches);

        overwrite_selected_history_coverage_for_test(
            &store,
            &[0xFF; SELECTED_HISTORY_COVERAGE_ENCODED_BYTES],
        );
        assert!(store
            .load_claimed_recursive_proof_job_inputs_with_expected_predecessor(
                fixture.claimed,
                parent_height,
                parent_hash,
                &fixture.previous_result_bytes,
            )
            .is_err());
    }

    #[test]
    fn height_one_recursive_proof_inputs_have_no_predecessor_allocation() {
        use crate::block::Block;

        let directory = tempfile::tempdir().unwrap();
        let store = MdbxStore::open(directory.path()).unwrap();
        let genesis = crate::consensus::genesis::genesis_header();
        let genesis_hash = crate::hash_block_header(&genesis);
        store.put_header_only(&genesis, &genesis_hash).unwrap();
        let transactions = vec![recursive_loader_coinbase(7)];
        let mut header = genesis;
        header.height = 1;
        header.prev_block_hash = genesis_hash;
        header.timestamp = header.timestamp.saturating_add(1);
        header.nonce = 7;
        header.tx_root = crate::block::compute_tx_root(&transactions);
        let hash = crate::hash_block_header(&header);
        store.put_header_only(&header, &hash).unwrap();
        let block = Block {
            header,
            transactions,
        }
        .to_bytes();
        put_recursive_loader_records(&store, 1, hash, &block, None, None);
        store
            .enqueue_recursive_proof_job(1, hash, RecursiveProofJobTier::B8)
            .unwrap();
        let claimed = store.claim_next_recursive_proof_job().unwrap().unwrap();

        let loaded = store
            .load_claimed_recursive_proof_job_inputs(claimed)
            .unwrap();
        assert_eq!(loaded.user_transaction_count, 0);
        assert!(loaded.block_proof_bytes.is_empty());
        assert!(loaded.block_auth_sidecar_bytes.is_empty());
        assert!(loaded.previous_result.is_none());
    }

    #[test]
    fn claimed_recursive_proof_input_loader_rejects_fork_hash_and_job_state() {
        let directory = tempfile::tempdir().unwrap();
        let store = MdbxStore::open(directory.path()).unwrap();
        let fixture = recursive_loader_fixture(&store);

        let mut wrong_claim = fixture.claimed;
        wrong_claim.block_hash[0] ^= 1;
        assert!(store
            .load_claimed_recursive_proof_job_inputs(wrong_claim)
            .is_err());

        store
            .release_recursive_proof_job(fixture.claimed.height, fixture.claimed.block_hash)
            .unwrap();
        assert!(store
            .load_claimed_recursive_proof_job_inputs(fixture.claimed)
            .is_err());

        let claimed = store.claim_next_recursive_proof_job().unwrap().unwrap();
        let mut fork_parent = fixture.parent_header;
        fork_parent.nonce = fork_parent.nonce.wrapping_add(1);
        let fork_parent_hash = crate::hash_block_header(&fork_parent);
        store
            .put_header_only(&fork_parent, &fork_parent_hash)
            .unwrap();
        assert!(store
            .load_claimed_recursive_proof_job_inputs(claimed)
            .is_err());
    }

    #[test]
    fn claimed_recursive_proof_input_loader_rejects_missing_and_oversized_material() {
        use crate::consensus::wire_limits::MAX_BLOCK_BYTES;

        let missing_directory = tempfile::tempdir().unwrap();
        let missing_store = MdbxStore::open(missing_directory.path()).unwrap();
        let missing_fixture = recursive_loader_fixture(&missing_store);
        let txn = missing_store.db.begin_rw_txn().unwrap();
        let proofs = txn.open_table(Some(T_BLOCK_PROOFS)).unwrap();
        txn.del(&proofs, &u64_key(2), None).unwrap();
        txn.commit().unwrap();
        assert!(missing_store
            .load_claimed_recursive_proof_job_inputs(missing_fixture.claimed)
            .is_err());

        let oversized_directory = tempfile::tempdir().unwrap();
        let oversized_store = MdbxStore::open(oversized_directory.path()).unwrap();
        let oversized_fixture = recursive_loader_fixture(&oversized_store);
        let oversized = vec![0u8; MAX_BLOCK_BYTES + 1];
        let txn = oversized_store.db.begin_rw_txn().unwrap();
        let recent = txn.open_table(Some(T_RECENT_BLOCKS)).unwrap();
        txn.put(&recent, u64_key(2), &oversized, WriteFlags::empty())
            .unwrap();
        txn.commit().unwrap();
        assert!(oversized_store
            .load_claimed_recursive_proof_job_inputs(oversized_fixture.claimed)
            .is_err());
    }

    #[test]
    fn claimed_recursive_proof_input_loader_requires_completed_predecessor() {
        let directory = tempfile::tempdir().unwrap();
        let store = MdbxStore::open(directory.path()).unwrap();
        let fixture = recursive_loader_fixture(&store);

        let txn = store.db.begin_rw_txn().unwrap();
        let jobs = txn.open_table(Some(T_RECURSIVE_PROOF_JOBS)).unwrap();
        let previous_key = recursive_proof_height_key(1);
        let previous_raw: [u8; RECURSIVE_PROOF_JOB_ENCODED_BYTES] =
            txn.get(&jobs, &previous_key).unwrap().unwrap();
        let mut previous = decode_recursive_proof_job(1, &previous_raw).unwrap();
        previous.state = RecursiveProofJobState::Pending;
        txn.put(
            &jobs,
            previous_key,
            encode_recursive_proof_job(&previous),
            WriteFlags::empty(),
        )
        .unwrap();
        txn.commit().unwrap();

        assert!(store
            .load_claimed_recursive_proof_job_inputs(fixture.claimed)
            .is_err());

        let malformed_directory = tempfile::tempdir().unwrap();
        let malformed_store = MdbxStore::open(malformed_directory.path()).unwrap();
        let malformed_fixture = recursive_loader_fixture(&malformed_store);
        let txn = malformed_store.db.begin_rw_txn().unwrap();
        let results = txn.open_table(Some(T_RECURSIVE_PROOF_RESULTS)).unwrap();
        let previous_key = recursive_proof_height_key(1);
        let mut encoded: Vec<u8> = txn.get(&results, &previous_key).unwrap().unwrap();
        encoded[36..40].copy_from_slice(&u32::MAX.to_le_bytes());
        txn.put(&results, previous_key, encoded, WriteFlags::empty())
            .unwrap();
        txn.commit().unwrap();
        assert!(malformed_store
            .load_claimed_recursive_proof_job_inputs(malformed_fixture.claimed)
            .is_err());
    }

    #[test]
    fn pipelined_input_loader_admits_running_predecessor_bound_to_parent_hash() {
        let directory = tempfile::tempdir().unwrap();
        let store = MdbxStore::open(directory.path()).unwrap();
        let fixture = recursive_loader_fixture(&store);

        // With a complete predecessor both loaders return identical inputs.
        let strict = store
            .load_claimed_recursive_proof_job_inputs(fixture.claimed)
            .unwrap();
        let pipelined = store
            .load_claimed_recursive_proof_job_inputs_with_running_predecessor(fixture.claimed)
            .unwrap();
        assert_eq!(
            strict.previous_result.as_ref().map(|result| &result.bytes),
            Some(&fixture.previous_result_bytes)
        );
        assert_eq!(strict.previous_result, pipelined.previous_result);
        assert_eq!(strict.block_bytes, pipelined.block_bytes);

        // Rewind the predecessor to the pipelined in-flight shape: Running
        // under the exact canonical parent hash, no durable result yet.
        let set_previous_state = |state: RecursiveProofJobState, hash_flip: bool| {
            let txn = store.db.begin_rw_txn().unwrap();
            let jobs = txn.open_table(Some(T_RECURSIVE_PROOF_JOBS)).unwrap();
            let previous_key = recursive_proof_height_key(1);
            let raw: [u8; RECURSIVE_PROOF_JOB_ENCODED_BYTES] =
                txn.get(&jobs, &previous_key).unwrap().unwrap();
            let mut previous = decode_recursive_proof_job(1, &raw).unwrap();
            previous.state = state;
            if hash_flip {
                previous.block_hash[0] ^= 1;
            }
            txn.put(
                &jobs,
                previous_key,
                encode_recursive_proof_job(&previous),
                WriteFlags::empty(),
            )
            .unwrap();
            let results = txn.open_table(Some(T_RECURSIVE_PROOF_RESULTS)).unwrap();
            let _ = txn.del(&results, &previous_key, None);
            txn.commit().unwrap();
        };
        set_previous_state(RecursiveProofJobState::Running, false);

        assert!(
            store
                .load_claimed_recursive_proof_job_inputs(fixture.claimed)
                .is_err(),
            "the strict loader must stay strict"
        );
        let inflight = store
            .load_claimed_recursive_proof_job_inputs_with_running_predecessor(fixture.claimed)
            .unwrap();
        assert!(inflight.previous_result.is_none());
        assert_eq!(inflight.block_bytes, fixture.block_bytes);
        assert_eq!(inflight.block_header, fixture.block_header);
        assert_eq!(inflight.parent_header, fixture.parent_header);

        // A running predecessor bound to a fork hash is rejected.
        set_previous_state(RecursiveProofJobState::Running, true);
        assert!(store
            .load_claimed_recursive_proof_job_inputs_with_running_predecessor(fixture.claimed)
            .is_err());

        // A pending predecessor is rejected even by the pipelined loader.
        set_previous_state(RecursiveProofJobState::Pending, true);
        assert!(store
            .load_claimed_recursive_proof_job_inputs_with_running_predecessor(fixture.claimed)
            .is_err());
    }

    #[test]
    fn claimed_recursive_proof_input_length_preflight_covers_all_large_records() {
        use crate::consensus::wire_limits::{
            MAX_BLOCK_AUTH_SIDECAR_BYTES, MAX_BLOCK_BYTES, MAX_BLOCK_PROOF_BYTES,
            MAX_BLOCK_PROOF_PLUS_SIDECAR_BYTES,
        };

        let valid = ClaimedRecursiveProofInputLengths {
            block: Some(MAX_BLOCK_BYTES),
            proof: Some(MAX_BLOCK_PROOF_BYTES),
            sidecar: Some(MAX_BLOCK_PROOF_PLUS_SIDECAR_BYTES - MAX_BLOCK_PROOF_BYTES),
            previous_result: Some(RECURSIVE_PROOF_RESULT_HEADER_BYTES),
        };
        assert!(validate_claimed_recursive_proof_input_lengths(2, valid, true).is_ok());
        // The pipelined in-memory predecessor form carries no durable result.
        assert!(validate_claimed_recursive_proof_input_lengths(
            2,
            ClaimedRecursiveProofInputLengths {
                previous_result: None,
                ..valid
            },
            false,
        )
        .is_ok());
        assert!(validate_claimed_recursive_proof_input_lengths(2, valid, false).is_err());
        assert!(
            validate_claimed_recursive_proof_input_lengths(
                2,
                ClaimedRecursiveProofInputLengths {
                    previous_result: None,
                    ..valid
                },
                true,
            )
            .is_err(),
            "a complete predecessor must still present its durable result"
        );
        for invalid in [
            ClaimedRecursiveProofInputLengths {
                block: Some(MAX_BLOCK_BYTES + 1),
                ..valid
            },
            ClaimedRecursiveProofInputLengths {
                proof: Some(MAX_BLOCK_PROOF_BYTES + 1),
                ..valid
            },
            ClaimedRecursiveProofInputLengths {
                sidecar: Some(MAX_BLOCK_AUTH_SIDECAR_BYTES + 1),
                ..valid
            },
            ClaimedRecursiveProofInputLengths {
                sidecar: Some(MAX_BLOCK_PROOF_PLUS_SIDECAR_BYTES - MAX_BLOCK_PROOF_BYTES + 1),
                ..valid
            },
            ClaimedRecursiveProofInputLengths {
                previous_result: Some(RECURSIVE_PROOF_RESULT_HEADER_BYTES - 1),
                ..valid
            },
            ClaimedRecursiveProofInputLengths {
                previous_result: Some(
                    RECURSIVE_PROOF_RESULT_HEADER_BYTES + MAX_RECURSIVE_PROOF_JOB_RESULT_BYTES + 1,
                ),
                ..valid
            },
        ] {
            assert!(validate_claimed_recursive_proof_input_lengths(2, invalid, true).is_err());
        }
        assert!(validate_claimed_recursive_proof_input_lengths(
            2,
            ClaimedRecursiveProofInputLengths {
                sidecar: None,
                ..valid
            },
            true,
        )
        .is_err());
    }

    #[test]
    fn claimed_recursive_proof_loader_source_keeps_preflight_and_no_clone_contract() {
        let source = include_str!("mdbx_store.rs");
        let dto = source
            .find("pub struct ClaimedRecursiveProofJobInputs")
            .unwrap();
        let dto_prefix = &source[dto.saturating_sub(32)..dto];
        assert!(dto_prefix.contains("#[derive(Debug)]"));
        assert!(!dto_prefix.contains("Clone"));

        let method = source
            .find("pub fn load_claimed_recursive_proof_job_inputs")
            .unwrap();
        let body = &source[method..];
        let block_length = body.find("let block_length: Option<ObjectLength>").unwrap();
        let proof_length = body.find("let proof_length: Option<ObjectLength>").unwrap();
        let sidecar_length = body
            .find("let sidecar_length: Option<ObjectLength>")
            .unwrap();
        let predecessor_length = body.find("let previous_result_length").unwrap();
        let all_limits = body
            .find("validate_claimed_recursive_proof_input_lengths")
            .unwrap();
        let first_large_get = body.find("let block_bytes: Vec<u8>").unwrap();
        assert!(block_length < all_limits);
        assert!(proof_length < all_limits);
        assert!(sidecar_length < all_limits);
        assert!(predecessor_length < all_limits);
        assert!(all_limits < first_large_get);
    }

    #[test]
    fn p2p_block_bundle_is_snapshot_stable_and_presence_gated() {
        let directory = tempfile::tempdir().unwrap();
        let store = MdbxStore::open(directory.path()).unwrap();
        put_recursive_loader_records(
            &store,
            3,
            [3; 32],
            b"bounded-block",
            Some(b"bounded-proof"),
            Some(b"bounded-sidecar"),
        );
        let (block, proof, sidecar, attestation) =
            store.get_recent_block_bundle_bounded(3).unwrap().unwrap();
        assert_eq!(block, b"bounded-block");
        assert_eq!(proof.as_deref(), Some(b"bounded-proof".as_slice()));
        assert_eq!(sidecar.as_deref(), Some(b"bounded-sidecar".as_slice()));
        assert_eq!(attestation, None);

        store
            .put_coverage_attestation(3, b"bounded-attestation")
            .unwrap();
        let (_, _, _, attestation) = store.get_recent_block_bundle_bounded(3).unwrap().unwrap();
        assert_eq!(
            attestation.as_deref(),
            Some(b"bounded-attestation".as_slice())
        );

        let txn = store.db.begin_rw_txn().unwrap();
        let sidecars = txn.open_table(Some(T_BLOCK_AUTH_SIDECARS)).unwrap();
        txn.del(&sidecars, &u64_key(3), None).unwrap();
        txn.commit().unwrap();
        assert!(store.get_recent_block_bundle_bounded(3).is_err());

        let source = include_str!("mdbx_store.rs");
        let body = source
            .split("pub fn get_recent_block_bundle_bounded(")
            .nth(1)
            .expect("bounded P2P block loader")
            .split("/// Store a serialised `BlockProof`")
            .next()
            .expect("bounded loader boundary");
        let length_preflight = body.find("let block_len: Option<ObjectLength>").unwrap();
        let first_payload = body.find("let block: Vec<u8>").unwrap();
        assert!(length_preflight < first_payload);
    }

    #[test]
    fn pruning_waits_for_canonical_selected_recursive_result() {
        let dir = tempfile::tempdir().unwrap();
        let store = MdbxStore::open(dir.path()).unwrap();
        let pruning_height = 1 + RECENT_BLOCK_RETENTION_DEPTH;
        let chain = put_selected_history_header_chain(&store, pruning_height);
        let hash = chain[1].1;
        put_retained_payload_fixture(&store, 1);
        store
            .put_checkpoint_coverage(&crate::checkpoint::CheckpointCoverage {
                checkpoint_id: [1u8; 32],
                height: 1,
                block_hash: hash,
                covered_from: 1,
                covered_to: 1,
                history_proof_covered_to: Some(1),
            })
            .unwrap();
        store
            .enqueue_recursive_proof_job(1, hash, RecursiveProofJobTier::B8)
            .unwrap();

        store.prune_after_commit(pruning_height).unwrap();
        assert_eq!(retained_payload_prune_watermark(&store), None);
        assert_eq!(
            store.get_recent_block(1).unwrap().as_deref(),
            Some(b"retained-block".as_slice())
        );
        assert_eq!(
            store.get_block_proof(1).unwrap().as_deref(),
            Some(b"retained-proof".as_slice())
        );
        assert_eq!(
            store.get_block_auth_sidecar(1).unwrap().as_deref(),
            Some(b"retained-sidecar".as_slice())
        );

        store.claim_next_recursive_proof_job().unwrap().unwrap();
        store
            .complete_recursive_proof_job_and_promote_selected_history(
                1,
                hash,
                &selected_terminal_bytes(1, hash),
                &empty_ladder_update(&chain[1].0),
            )
            .unwrap();
        store.prune_after_commit(pruning_height).unwrap();
        assert!(store.get_recent_block(1).unwrap().is_none());
        assert!(store.get_block_proof(1).unwrap().is_none());
        assert!(store.get_block_auth_sidecar(1).unwrap().is_none());
        assert!(store.get_history_claim(1).unwrap().is_none());
        assert!(store.get_accepted_block_certificate(1).unwrap().is_none());
        assert_eq!(retained_payload_prune_watermark(&store), Some(1));
        assert!(store.get_recursive_proof_job_result(1).unwrap().is_some());
    }

    #[test]
    fn retained_payload_pruning_resumes_after_restart_and_caps_far_jumps() {
        let directory = tempfile::tempdir().unwrap();
        let coverage_height = RETAINED_PAYLOAD_PRUNE_HEIGHT_LIMIT as u64 + 3;
        let current_height;
        let coverage_hash;
        let full_payload_batch = (RETAINED_PAYLOAD_PRUNE_DELETE_LIMIT / 6)
            .min(RETAINED_PAYLOAD_PRUNE_HEIGHT_LIMIT) as u64;
        {
            let store = MdbxStore::open(directory.path()).unwrap();
            let (chain, current) = install_selected_prune_authority(&store, coverage_height);
            current_height = current;
            coverage_hash = chain[coverage_height as usize].1;
            for height in 1..=coverage_height + 1 {
                put_retained_payload_fixture(&store, height);
            }

            store.prune_after_commit(current_height).unwrap();
            assert_eq!(
                retained_payload_prune_watermark(&store),
                Some(full_payload_batch)
            );
            assert!(store
                .get_recent_block(full_payload_batch)
                .unwrap()
                .is_none());
            assert!(store
                .get_recent_block(full_payload_batch + 1)
                .unwrap()
                .is_some());
        }

        let reopened = MdbxStore::open(directory.path()).unwrap();
        reopened.prune_after_commit(current_height).unwrap();
        assert_eq!(
            retained_payload_prune_watermark(&reopened),
            Some(coverage_height)
        );
        assert!(reopened
            .get_recent_block(coverage_height)
            .unwrap()
            .is_none());
        assert!(reopened
            .get_recent_block(coverage_height + 1)
            .unwrap()
            .is_some());
        assert!(reopened
            .get_accepted_block_certificate(coverage_height + 1)
            .unwrap()
            .is_some());
        assert!(reopened
            .get_selected_history_terminal_result_at(coverage_height, coverage_hash)
            .unwrap()
            .is_some());
    }

    #[test]
    fn retained_payload_pruning_missing_or_malformed_certificate_rolls_back_batch() {
        let directory = tempfile::tempdir().unwrap();
        let store = MdbxStore::open(directory.path()).unwrap();
        let (_chain, current_height) = install_selected_prune_authority(&store, 2);
        put_retained_payload_fixture(&store, 1);

        let txn = store.db.begin_rw_txn().unwrap();
        for table_name in [
            T_RECENT_BLOCKS,
            T_BLOCK_PROOFS,
            T_BLOCK_AUTH_SIDECARS,
            T_HISTORY_CLAIMS,
        ] {
            let table = txn.open_table(Some(table_name)).unwrap();
            txn.put(&table, u64_key(2), b"uncertified", WriteFlags::empty())
                .unwrap();
        }
        txn.commit().unwrap();

        assert!(store.prune_after_commit(current_height).is_err());
        assert_eq!(retained_payload_prune_watermark(&store), None);
        assert!(store.get_recent_block(1).unwrap().is_some());
        assert!(store.get_accepted_block_certificate(1).unwrap().is_some());

        // A raw opaque record without its fixed-width acceptance-time binding
        // is malformed, not sufficient authorization for deletion.
        let txn = store.db.begin_rw_txn().unwrap();
        let certificates = txn.open_table(Some(T_ACCEPTED_BLOCK_CERTIFICATES)).unwrap();
        txn.put(
            &certificates,
            u64_key(2),
            b"unbound-certificate",
            WriteFlags::empty(),
        )
        .unwrap();
        txn.commit().unwrap();
        assert!(store.prune_after_commit(current_height).is_err());
        assert_eq!(retained_payload_prune_watermark(&store), None);
        assert!(store.get_recent_block(1).unwrap().is_some());

        let txn = store.db.begin_rw_txn().unwrap();
        let certificates = txn.open_table(Some(T_ACCEPTED_BLOCK_CERTIFICATES)).unwrap();
        txn.del(&certificates, u64_key(2), None).unwrap();
        txn.commit().unwrap();
        store
            .put_accepted_block_certificate(2, b"accepted-certificate")
            .unwrap();
        store.prune_after_commit(current_height).unwrap();
        assert_eq!(retained_payload_prune_watermark(&store), Some(2));
        assert!(store.get_recent_block(1).unwrap().is_none());
        assert!(store.get_recent_block(2).unwrap().is_none());
    }

    #[test]
    fn retained_payload_pruning_stops_at_durable_finality_and_keeps_terminal() {
        let directory = tempfile::tempdir().unwrap();
        let store = MdbxStore::open(directory.path()).unwrap();
        let (chain, current_height) = install_selected_prune_authority(&store, 3);
        put_retained_payload_fixture(&store, 2);
        put_retained_payload_fixture(&store, 3);
        store
            .put_consensus_meta(&ConsensusMeta {
                tip_height: current_height,
                tip_hash: chain[current_height as usize].1,
                cumulative_chainwork: [0u8; 32],
                finalized: crate::storage::meta::FinalizedCheckpoint {
                    height: 2,
                    hash: chain[2].1,
                },
            })
            .unwrap();

        store.prune_after_commit(current_height).unwrap();
        assert_eq!(retained_payload_prune_watermark(&store), Some(2));
        assert!(store.get_recent_block(2).unwrap().is_none());
        assert!(store.get_recent_block(3).unwrap().is_some());
        assert!(store
            .get_selected_history_terminal_result_at(3, chain[3].1)
            .unwrap()
            .is_some());
    }

    #[test]
    fn retained_payload_prune_watermark_rewinds_and_clears_with_epoch() {
        let directory = tempfile::tempdir().unwrap();
        let store = MdbxStore::open(directory.path()).unwrap();
        let (_chain, current_height) = install_selected_prune_authority(&store, 20);
        store.prune_after_commit(current_height).unwrap();
        assert_eq!(
            retained_payload_prune_watermark(&store),
            Some(RETAINED_PAYLOAD_PRUNE_HEIGHT_LIMIT as u64)
        );

        store.delete_recursive_proof_jobs_above(5).unwrap();
        assert_eq!(retained_payload_prune_watermark(&store), Some(5));
        assert!(store.get_selected_history_coverage().unwrap().is_none());
        store.prune_after_commit(current_height).unwrap();
        assert_eq!(
            retained_payload_prune_watermark(&store),
            Some(5),
            "ordinary no-coverage maintenance must not advance the frontier"
        );

        store.clear_all().unwrap();
        assert_eq!(retained_payload_prune_watermark(&store), None);
    }

    #[test]
    fn retained_payload_pruner_has_no_prefix_scan_or_payload_allocation() {
        assert!(retained_payload_prune_budget_allows(
            0,
            0,
            RETAINED_PAYLOAD_PRUNE_BYTE_LIMIT,
            RETAINED_PAYLOAD_PRUNE_DELETE_LIMIT,
        ));
        assert!(!retained_payload_prune_budget_allows(
            1,
            0,
            RETAINED_PAYLOAD_PRUNE_BYTE_LIMIT,
            0,
        ));
        assert!(!retained_payload_prune_budget_allows(
            0,
            1,
            0,
            RETAINED_PAYLOAD_PRUNE_DELETE_LIMIT,
        ));
        assert!(!retained_payload_prune_budget_allows(
            usize::MAX,
            usize::MAX,
            1,
            1,
        ));

        let source = include_str!("mdbx_store.rs");
        let body = source
            .split("fn prune_retained_payloads_bounded(")
            .nth(1)
            .expect("bounded retained payload pruner")
            .split("/// Delete legacy little-endian height keys")
            .next()
            .expect("bounded retained payload pruner boundary");
        assert!(!body.contains("cursor("));
        assert!(!body.contains("Vec::"));
        assert!(!body.contains("Vec<"));
        assert!(body.contains("RETAINED_PAYLOAD_PRUNE_HEIGHT_LIMIT"));
        assert!(body.contains("RETAINED_PAYLOAD_PRUNE_BYTE_LIMIT"));
        assert!(body.contains("RETAINED_PAYLOAD_PRUNE_DELETE_LIMIT"));
        assert!(body.contains("ObjectLength"));
        assert!(body.contains("let key = u64_key(height)"));
        let preflight = body.find("let payload_lengths").unwrap();
        let first_delete = body.find("txn.del(table").unwrap();
        assert!(preflight < first_delete);
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
    fn selected_history_completion_promotes_one_bounded_pointer_and_rewinds_on_reorg() {
        let directory = tempfile::tempdir().unwrap();
        let store = MdbxStore::open(directory.path()).unwrap();

        let (first_header, first_hash) = put_recursive_job_header(&store, 1, 1);
        store
            .enqueue_recursive_proof_job(1, first_hash, RecursiveProofJobTier::B8)
            .unwrap();
        store.claim_next_recursive_proof_job().unwrap().unwrap();
        assert!(store
            .complete_recursive_proof_job_and_promote_selected_history(
                1,
                first_hash,
                b"opaque-not-a-terminal-package",
                &empty_ladder_update(&first_header),
            )
            .is_err());
        assert!(store.get_selected_history_coverage().unwrap().is_none());

        let first_terminal = selected_terminal_bytes(1, first_hash);
        store
            .complete_recursive_proof_job_and_promote_selected_history(
                1,
                first_hash,
                &first_terminal,
                &empty_ladder_update(&first_header),
            )
            .unwrap();
        assert_eq!(
            store.get_selected_history_coverage().unwrap(),
            Some(SelectedHistoryCoverage {
                height: 1,
                block_hash: first_hash,
            })
        );
        assert_eq!(
            store
                .get_selected_history_terminal_result()
                .unwrap()
                .unwrap()
                .bytes,
            first_terminal
        );

        let mut second_header = first_header;
        second_header.height = 2;
        second_header.prev_block_hash = first_hash;
        second_header.timestamp = second_header.timestamp.saturating_add(1);
        second_header.nonce = 2;
        let second_hash = crate::hash_block_header(&second_header);
        store.put_header_only(&second_header, &second_hash).unwrap();
        store
            .enqueue_recursive_proof_job(2, second_hash, RecursiveProofJobTier::B8)
            .unwrap();
        store.claim_next_recursive_proof_job().unwrap().unwrap();
        let second_terminal = selected_terminal_bytes(2, second_hash);
        store
            .complete_recursive_proof_job_and_promote_selected_history(
                2,
                second_hash,
                &second_terminal,
                &empty_ladder_update(&second_header),
            )
            .unwrap();
        assert_eq!(
            store
                .get_selected_history_coverage()
                .unwrap()
                .unwrap()
                .height,
            2
        );
        assert_eq!(
            store
                .get_selected_history_terminal_result_at(1, first_hash)
                .unwrap()
                .unwrap()
                .bytes,
            first_terminal,
            "finalized serving can select an older exact boundary without scanning results"
        );
        assert_eq!(
            store
                .get_selected_history_terminal_result_at(2, second_hash)
                .unwrap()
                .unwrap()
                .bytes,
            second_terminal
        );
        assert!(store
            .get_selected_history_terminal_result_at(1, second_hash)
            .unwrap()
            .is_none());

        store.delete_recursive_proof_jobs_above(1).unwrap();
        assert_eq!(
            store.get_selected_history_coverage().unwrap(),
            Some(SelectedHistoryCoverage {
                height: 1,
                block_hash: first_hash,
            })
        );
        assert_eq!(
            store
                .get_selected_history_terminal_result()
                .unwrap()
                .unwrap()
                .bytes,
            first_terminal
        );
    }

    #[test]
    fn selected_history_promotion_rejects_an_opaque_complete_predecessor() {
        let directory = tempfile::tempdir().unwrap();
        let store = MdbxStore::open(directory.path()).unwrap();
        let (first_header, first_hash) = put_recursive_job_header(&store, 1, 11);
        store
            .enqueue_recursive_proof_job(1, first_hash, RecursiveProofJobTier::B8)
            .unwrap();
        store.claim_next_recursive_proof_job().unwrap().unwrap();
        store
            .complete_recursive_proof_job(1, first_hash, b"opaque")
            .unwrap();

        let mut second_header = first_header;
        second_header.height = 2;
        second_header.prev_block_hash = first_hash;
        second_header.timestamp = second_header.timestamp.saturating_add(1);
        second_header.nonce = 12;
        let second_hash = crate::hash_block_header(&second_header);
        store.put_header_only(&second_header, &second_hash).unwrap();
        store
            .enqueue_recursive_proof_job(2, second_hash, RecursiveProofJobTier::B8)
            .unwrap();
        store.claim_next_recursive_proof_job().unwrap().unwrap();
        assert!(store
            .complete_recursive_proof_job_and_promote_selected_history(
                2,
                second_hash,
                &selected_terminal_bytes(2, second_hash),
                &empty_ladder_update(&second_header),
            )
            .is_err());
        assert!(store.get_selected_history_coverage().unwrap().is_none());
        assert_eq!(
            store.get_recursive_proof_job(2).unwrap().unwrap().state,
            RecursiveProofJobState::Running
        );
    }

    #[test]
    fn verified_selected_history_import_jumps_and_compacts_in_constant_space() {
        let directory = tempfile::tempdir().unwrap();
        let store = MdbxStore::open(directory.path()).unwrap();
        let pruning_height = 4 + RECENT_BLOCK_RETENTION_DEPTH;
        let chain = put_selected_history_header_chain(&store, pruning_height);
        for height in 1..=5 {
            store
                .enqueue_recursive_proof_job(
                    height,
                    chain[height as usize].1,
                    RecursiveProofJobTier::B8,
                )
                .unwrap();
        }
        let txn = store.db.begin_rw_txn().unwrap();
        let recent = txn.open_table(Some(T_RECENT_BLOCKS)).unwrap();
        txn.put(
            &recent,
            u64_key(2),
            b"covered-intermediate-block",
            WriteFlags::empty(),
        )
        .unwrap();
        txn.commit().unwrap();
        store
            .put_accepted_block_certificate(2, b"accepted-certificate")
            .unwrap();

        // Establish a valid older pointer. The relay import below skips two
        // Pending intermediates and does not require exact predecessor proof
        // coverage.
        let first_hash = chain[1].1;
        store.claim_next_recursive_proof_job().unwrap().unwrap();
        store
            .complete_recursive_proof_job_and_promote_selected_history(
                1,
                first_hash,
                &selected_terminal_bytes(1, first_hash),
                &empty_ladder_update(&chain[1].0),
            )
            .unwrap();

        let target_hash = chain[4].1;
        let terminal = selected_terminal_bytes(4, target_hash);
        let coverage = store
            .import_verified_selected_history_terminal(VerifiedSelectedHistoryTerminalImport {
                height: 4,
                block_hash: target_hash,
                epoch_anchor_height: 0,
                epoch_anchor_hash: chain[0].1,
                tier: RecursiveProofJobTier::B8,
                terminal_package_bytes: &terminal,
            })
            .unwrap();
        assert_eq!(
            coverage,
            SelectedHistoryCoverage {
                height: 4,
                block_hash: target_hash,
            }
        );
        assert_eq!(
            store.get_selected_history_coverage().unwrap(),
            Some(coverage)
        );
        for covered in 1..4 {
            assert!(store.get_recursive_proof_job(covered).unwrap().is_none());
            assert!(store
                .get_recursive_proof_job_result(covered)
                .unwrap()
                .is_none());
        }
        let target_job = store.get_recursive_proof_job(4).unwrap().unwrap();
        assert_eq!(target_job.state, RecursiveProofJobState::Complete);
        assert_eq!(target_job.tier, RecursiveProofJobTier::B8);
        assert_eq!(
            store
                .get_selected_history_terminal_result()
                .unwrap()
                .unwrap()
                .bytes,
            terminal
        );
        assert_eq!(
            store.get_recursive_proof_job(5).unwrap().unwrap().state,
            RecursiveProofJobState::Pending,
            "future work must not be compacted by the imported prefix"
        );
        store.prune_after_commit(pruning_height).unwrap();
        assert!(store.get_recent_block(2).unwrap().is_none());

        // A reorg below the imported target cannot rewind to a compacted proof
        // that no longer exists. Both target authority and coverage disappear
        // atomically, forcing a new canonical verification/import.
        store.delete_recursive_proof_jobs_above(2).unwrap();
        assert!(store.get_selected_history_coverage().unwrap().is_none());
        assert!(store.get_recursive_proof_job(4).unwrap().is_none());
        assert!(store.get_recursive_proof_job_result(4).unwrap().is_none());
    }

    #[test]
    fn verified_selected_history_import_rejects_stale_fork_tier_epoch_and_running() {
        let directory = tempfile::tempdir().unwrap();
        let store = MdbxStore::open(directory.path()).unwrap();
        let chain = put_selected_history_header_chain(&store, 5);
        for height in 1..=5 {
            store
                .enqueue_recursive_proof_job(
                    height,
                    chain[height as usize].1,
                    RecursiveProofJobTier::B8,
                )
                .unwrap();
        }
        let target_hash = chain[4].1;
        let terminal = selected_terminal_bytes(4, target_hash);
        let imported = VerifiedSelectedHistoryTerminalImport {
            height: 4,
            block_hash: target_hash,
            epoch_anchor_height: 0,
            epoch_anchor_hash: chain[0].1,
            tier: RecursiveProofJobTier::B8,
            terminal_package_bytes: &terminal,
        };
        let expected_coverage = store
            .import_verified_selected_history_terminal(imported)
            .unwrap();

        assert!(
            store
                .import_verified_selected_history_terminal(imported)
                .is_err(),
            "equal-height stale import must fail"
        );

        let regression_terminal = selected_terminal_bytes(3, chain[3].1);
        assert!(
            store
                .import_verified_selected_history_terminal(VerifiedSelectedHistoryTerminalImport {
                    height: 3,
                    block_hash: chain[3].1,
                    epoch_anchor_height: 0,
                    epoch_anchor_hash: chain[0].1,
                    tier: RecursiveProofJobTier::B8,
                    terminal_package_bytes: &regression_terminal,
                },)
                .is_err(),
            "coverage regression must fail"
        );

        let fork_hash = [0xF0; 32];
        let fork_terminal = selected_terminal_bytes(5, fork_hash);
        assert!(
            store
                .import_verified_selected_history_terminal(VerifiedSelectedHistoryTerminalImport {
                    height: 5,
                    block_hash: fork_hash,
                    epoch_anchor_height: 0,
                    epoch_anchor_hash: chain[0].1,
                    tier: RecursiveProofJobTier::B8,
                    terminal_package_bytes: &fork_terminal,
                },)
                .is_err(),
            "fork terminal must fail canonical target binding"
        );

        let wrong_tier_terminal =
            selected_terminal_bytes_for_tier(5, chain[5].1, RecursiveProofJobTier::B32);
        assert!(
            store
                .import_verified_selected_history_terminal(VerifiedSelectedHistoryTerminalImport {
                    height: 5,
                    block_hash: chain[5].1,
                    epoch_anchor_height: 0,
                    epoch_anchor_hash: chain[0].1,
                    tier: RecursiveProofJobTier::B32,
                    terminal_package_bytes: &wrong_tier_terminal,
                },)
                .is_err(),
            "terminal tier must equal the accepted-block job tier"
        );

        let next_terminal = selected_terminal_bytes(5, chain[5].1);
        for (epoch_anchor_height, epoch_anchor_hash) in [(1, chain[1].1), (0, [0xE0; 32])] {
            assert!(
                store
                    .import_verified_selected_history_terminal(
                        VerifiedSelectedHistoryTerminalImport {
                            height: 5,
                            block_hash: chain[5].1,
                            epoch_anchor_height,
                            epoch_anchor_hash,
                            tier: RecursiveProofJobTier::B8,
                            terminal_package_bytes: &next_terminal,
                        },
                    )
                    .is_err(),
                "epoch anchor height and identity are both canonical inputs"
            );
        }

        let claimed = store.claim_next_recursive_proof_job().unwrap().unwrap();
        assert_eq!(claimed.height, 5);
        assert!(
            store
                .import_verified_selected_history_terminal(VerifiedSelectedHistoryTerminalImport {
                    height: 5,
                    block_hash: chain[5].1,
                    epoch_anchor_height: 0,
                    epoch_anchor_hash: chain[0].1,
                    tier: RecursiveProofJobTier::B8,
                    terminal_package_bytes: &next_terminal,
                },)
                .is_err(),
            "a Running target owns the durable job until release"
        );

        assert_eq!(
            store.get_selected_history_coverage().unwrap(),
            Some(expected_coverage),
            "every rejected import must leave coverage unchanged"
        );
        assert_eq!(
            store.get_recursive_proof_job(5).unwrap().unwrap().state,
            RecursiveProofJobState::Running
        );
    }

    #[test]
    fn verified_selected_history_import_survives_restart_with_only_target_terminal() {
        let directory = tempfile::tempdir().unwrap();
        let target_hash;
        let terminal;
        {
            let store = MdbxStore::open(directory.path()).unwrap();
            let chain = put_selected_history_header_chain(&store, 3);
            for height in 1..=3 {
                store
                    .enqueue_recursive_proof_job(
                        height,
                        chain[height as usize].1,
                        RecursiveProofJobTier::B8,
                    )
                    .unwrap();
            }
            target_hash = chain[3].1;
            terminal = selected_terminal_bytes(3, target_hash);
            store
                .import_verified_selected_history_terminal(VerifiedSelectedHistoryTerminalImport {
                    height: 3,
                    block_hash: target_hash,
                    epoch_anchor_height: 0,
                    epoch_anchor_hash: chain[0].1,
                    tier: RecursiveProofJobTier::B8,
                    terminal_package_bytes: &terminal,
                })
                .unwrap();
        }

        let reopened = MdbxStore::open(directory.path()).unwrap();
        assert_eq!(
            reopened.get_selected_history_coverage().unwrap(),
            Some(SelectedHistoryCoverage {
                height: 3,
                block_hash: target_hash,
            })
        );
        for covered in 1..3 {
            assert!(reopened.get_recursive_proof_job(covered).unwrap().is_none());
            assert!(reopened
                .get_recursive_proof_job_result(covered)
                .unwrap()
                .is_none());
        }
        assert_eq!(
            reopened.get_recursive_proof_job(3).unwrap().unwrap().state,
            RecursiveProofJobState::Complete
        );
        assert_eq!(
            reopened
                .get_selected_history_terminal_result()
                .unwrap()
                .unwrap()
                .bytes,
            terminal
        );
    }

    #[test]
    fn verified_selected_history_import_rejects_unfinalized_target_atomically() {
        let directory = tempfile::tempdir().unwrap();
        let store = MdbxStore::open(directory.path()).unwrap();
        let chain = put_selected_history_header_chain(&store, 5);
        store
            .put_consensus_meta(&ConsensusMeta {
                tip_height: 5,
                tip_hash: chain[5].1,
                cumulative_chainwork: [0u8; 32],
                finalized: crate::storage::meta::FinalizedCheckpoint {
                    height: 3,
                    hash: chain[3].1,
                },
            })
            .unwrap();
        store
            .enqueue_recursive_proof_job(4, chain[4].1, RecursiveProofJobTier::B8)
            .unwrap();
        let terminal = selected_terminal_bytes(4, chain[4].1);

        assert!(store
            .import_verified_selected_history_terminal(VerifiedSelectedHistoryTerminalImport {
                height: 4,
                block_hash: chain[4].1,
                epoch_anchor_height: 0,
                epoch_anchor_hash: chain[0].1,
                tier: RecursiveProofJobTier::B8,
                terminal_package_bytes: &terminal,
            })
            .is_err());
        assert!(store.get_selected_history_coverage().unwrap().is_none());
        assert_eq!(
            store.get_recursive_proof_job(4).unwrap().unwrap().state,
            RecursiveProofJobState::Pending
        );
        assert!(store.get_recursive_proof_job_result(4).unwrap().is_none());
    }

    #[test]
    fn verified_import_supersedes_but_never_deletes_running_covered_work() {
        let directory = tempfile::tempdir().unwrap();
        let store = MdbxStore::open(directory.path()).unwrap();
        let chain = put_selected_history_header_chain(&store, 6);
        for height in 1..=6 {
            store
                .enqueue_recursive_proof_job(
                    height,
                    chain[height as usize].1,
                    RecursiveProofJobTier::B8,
                )
                .unwrap();
        }
        let running = store.claim_next_recursive_proof_job().unwrap().unwrap();
        assert_eq!(running.height, 1);

        let terminal = selected_terminal_bytes(5, chain[5].1);
        store
            .import_verified_selected_history_terminal(VerifiedSelectedHistoryTerminalImport {
                height: 5,
                block_hash: chain[5].1,
                epoch_anchor_height: 0,
                epoch_anchor_hash: chain[0].1,
                tier: RecursiveProofJobTier::B8,
                terminal_package_bytes: &terminal,
            })
            .unwrap();
        assert_eq!(
            store.get_recursive_proof_job(1).unwrap().unwrap().state,
            RecursiveProofJobState::Running,
            "bounded cleanup must not invalidate memory owned by a prover"
        );
        assert!(store
            .complete_recursive_proof_job_and_promote_selected_history(
                1,
                chain[1].1,
                &selected_terminal_bytes(1, chain[1].1),
                &empty_ladder_update(&chain[1].0),
            )
            .is_err());
        assert_eq!(
            store
                .get_selected_history_coverage()
                .unwrap()
                .unwrap()
                .height,
            5,
            "stale covered work cannot regress imported authority"
        );
        store.release_recursive_proof_job(1, chain[1].1).unwrap();
        assert!(store.compact_selected_history_journal_bounded().unwrap() >= 1);
        assert!(store.get_recursive_proof_job(1).unwrap().is_none());
        assert_eq!(
            store
                .claim_next_recursive_proof_job()
                .unwrap()
                .unwrap()
                .height,
            6
        );
    }

    #[test]
    fn bounded_selected_history_compaction_never_reclaims_or_claims_coverage() {
        let directory = tempfile::tempdir().unwrap();
        let store = MdbxStore::open(directory.path()).unwrap();
        let chain = put_selected_history_header_chain(&store, 41);
        for height in 1..=41 {
            store
                .enqueue_recursive_proof_job(
                    height,
                    chain[height as usize].1,
                    RecursiveProofJobTier::B8,
                )
                .unwrap();
        }
        let terminal = selected_terminal_bytes(40, chain[40].1);
        store
            .import_verified_selected_history_terminal(VerifiedSelectedHistoryTerminalImport {
                height: 40,
                block_hash: chain[40].1,
                epoch_anchor_height: 0,
                epoch_anchor_hash: chain[0].1,
                tier: RecursiveProofJobTier::B8,
                terminal_package_bytes: &terminal,
            })
            .unwrap();

        let retained_covered_jobs = (1..40)
            .filter(|height| store.get_recursive_proof_job(*height).unwrap().is_some())
            .count();
        assert_eq!(
            retained_covered_jobs,
            39 - SELECTED_HISTORY_JOURNAL_COMPACTION_ENTRY_LIMIT,
            "the post-import transaction may retire only one fixed-size batch"
        );
        assert_eq!(
            store.compact_selected_history_journal_bounded().unwrap(),
            SELECTED_HISTORY_JOURNAL_COMPACTION_ENTRY_LIMIT
        );
        assert_eq!(
            store
                .claim_next_recursive_proof_job()
                .unwrap()
                .unwrap()
                .height,
            41,
            "durable coverage, not delayed physical cleanup, sets the claim floor"
        );
        assert_eq!(
            store
                .get_selected_history_terminal_result_at(40, chain[40].1)
                .unwrap()
                .unwrap()
                .bytes,
            terminal,
            "the strict compaction cutoff must retain its serving terminal"
        );
    }

    #[test]
    fn bounded_selected_history_compaction_keeps_exact_finalized_terminal() {
        let directory = tempfile::tempdir().unwrap();
        let store = MdbxStore::open(directory.path()).unwrap();
        let chain = put_selected_history_header_chain(&store, 3);
        for height in 1..=3 {
            store
                .enqueue_recursive_proof_job(
                    height,
                    chain[height as usize].1,
                    RecursiveProofJobTier::B8,
                )
                .unwrap();
            assert_eq!(
                store
                    .claim_next_recursive_proof_job()
                    .unwrap()
                    .unwrap()
                    .height,
                height
            );
            store
                .complete_recursive_proof_job_and_promote_selected_history(
                    height,
                    chain[height as usize].1,
                    &selected_terminal_bytes(height, chain[height as usize].1),
                    &empty_ladder_update(&chain[height as usize].0),
                )
                .unwrap();
        }
        store
            .put_consensus_meta(&ConsensusMeta {
                tip_height: 3,
                tip_hash: chain[3].1,
                cumulative_chainwork: [0u8; 32],
                finalized: crate::storage::meta::FinalizedCheckpoint {
                    height: 2,
                    hash: chain[2].1,
                },
            })
            .unwrap();

        assert_eq!(
            store.compact_selected_history_journal_bounded().unwrap(),
            2,
            "height one contributes one job and one result"
        );
        assert!(store.get_recursive_proof_job(1).unwrap().is_none());
        assert!(store.get_recursive_proof_job_result(1).unwrap().is_none());
        assert!(store
            .get_selected_history_terminal_result_at(2, chain[2].1)
            .unwrap()
            .is_some());
        assert!(store
            .get_selected_history_terminal_result_at(3, chain[3].1)
            .unwrap()
            .is_some());
    }

    #[test]
    fn bounded_height_pruner_handles_little_endian_cursor_order() {
        let directory = tempfile::tempdir().unwrap();
        let store = MdbxStore::open(directory.path()).unwrap();
        let txn = store.db.begin_rw_txn().unwrap();
        let table = txn.open_table(Some(T_UNDO_LOGS)).unwrap();
        for height in [1u64, 2, 255, 256, 257, 65_536] {
            txn.put(&table, u64_key(height), [0xAA], WriteFlags::empty())
                .unwrap();
        }
        delete_height_keys_at_or_below(&txn, &table, 256).unwrap();
        for height in [1u64, 2, 255, 256] {
            assert!(txn
                .get::<ObjectLength>(&table, &u64_key(height))
                .unwrap()
                .is_none());
        }
        for height in [257u64, 65_536] {
            assert!(txn
                .get::<ObjectLength>(&table, &u64_key(height))
                .unwrap()
                .is_some());
        }
        txn.commit().unwrap();
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
            coverage_attestation_bytes: &[],
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
                    coverage_attestation_bytes: &[],
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
                    coverage_attestation_bytes: &[],
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
        let replacement_payload = ReorgBlockPayload::new(&replacement_block, &[], &[], &[]);
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
        let failed_payload = ReorgBlockPayload::new(&failed_block, &[], &[], &[]);
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
    fn finalized_staging_installs_state_and_seeds_retained_payload_prune_watermark_atomically() {
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

        let terminal = selected_terminal_bytes(1, new_hash);
        assert!(store
            .install_finalized_snapshot_staging_with_selected_history(
                &staging,
                &meta,
                &[old_header, new_header],
                SelectedHistorySnapshotSeed {
                    height: 1,
                    block_hash: old_hash,
                    tier: RecursiveProofJobTier::B8,
                    terminal_package_bytes: &selected_terminal_bytes(1, old_hash),
                },
            )
            .is_err());
        assert_eq!(store.get_chain_tip().unwrap(), Some((0, old_hash)));
        let hot_state = store
            .install_finalized_snapshot_staging_with_selected_history(
                &staging,
                &meta,
                &[old_header, new_header],
                SelectedHistorySnapshotSeed {
                    height: 1,
                    block_hash: new_hash,
                    tier: RecursiveProofJobTier::B8,
                    terminal_package_bytes: &terminal,
                },
            )
            .unwrap();
        assert_eq!(store.get_chain_tip().unwrap(), Some((1, new_hash)));
        assert_eq!(retained_payload_prune_watermark(&store), Some(1));
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
            store.get_recursive_proof_job(1).unwrap().unwrap().state,
            RecursiveProofJobState::Complete
        );
        assert_eq!(
            store
                .get_selected_history_terminal_result()
                .unwrap()
                .unwrap()
                .bytes,
            terminal
        );
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
                    coverage_attestation_bytes: &[],
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
                coverage_attestation_bytes: &[],
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
                    coverage_attestation_bytes: &[],
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
        put_recursive_job_header(&store, 7, 7);
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

    fn verified_header_batch_chain(count: usize) -> Vec<VerifiedHeaderBatchRecord> {
        assert!(count > 0);
        let genesis = crate::consensus::genesis::genesis_header();
        let genesis_hash = crate::hash_block_header(&genesis);
        let genesis_work = crate::block_work(&genesis.difficulty_target);
        let mut records = Vec::with_capacity(count);
        records.push(VerifiedHeaderBatchRecord {
            header: genesis,
            hash: genesis_hash,
            cumulative_chainwork: genesis_work,
        });

        while records.len() < count {
            let parent = *records.last().unwrap();
            let height = parent.header.height + 1;
            let mut header = parent.header;
            header.height = height;
            header.prev_block_hash = parent.hash;
            header.timestamp = genesis.timestamp.saturating_add(height);
            header.nonce = u128::from(height);
            header.state_root[0] = height as u8;
            let hash = crate::hash_block_header(&header);
            let cumulative_chainwork = crate::add_work(
                &parent.cumulative_chainwork,
                &crate::block_work(&header.difficulty_target),
            );
            records.push(VerifiedHeaderBatchRecord {
                header,
                hash,
                cumulative_chainwork,
            });
        }
        records
    }

    #[test]
    fn verified_header_batch_enforces_512_record_cap() {
        let directory = tempfile::tempdir().unwrap();
        let store = MdbxStore::open(directory.path()).unwrap();
        let records = verified_header_batch_chain(MAX_VERIFIED_HEADER_BATCH_RECORDS + 1);

        assert!(store.put_verified_headers_batch(&records).is_err());
        assert_eq!(store.get_header(0).unwrap(), None);

        let outcome = store
            .put_verified_headers_batch(&records[..MAX_VERIFIED_HEADER_BATCH_RECORDS])
            .unwrap();
        assert_eq!(
            outcome,
            VerifiedHeaderBatchOutcome {
                existing: 0,
                promoted: MAX_VERIFIED_HEADER_BATCH_RECORDS,
            }
        );
        assert_eq!(
            store
                .get_header((MAX_VERIFIED_HEADER_BATCH_RECORDS - 1) as u64)
                .unwrap(),
            Some(records[MAX_VERIFIED_HEADER_BATCH_RECORDS - 1].header)
        );
        assert_eq!(
            store
                .put_verified_headers_batch(&[])
                .expect("empty batch is a bounded no-op"),
            VerifiedHeaderBatchOutcome::default()
        );
    }

    #[test]
    fn verified_header_batch_retry_is_exactly_idempotent() {
        let directory = tempfile::tempdir().unwrap();
        let store = MdbxStore::open(directory.path()).unwrap();
        let records = verified_header_batch_chain(4);

        assert_eq!(
            store.put_verified_headers_batch(&records).unwrap(),
            VerifiedHeaderBatchOutcome {
                existing: 0,
                promoted: 4,
            }
        );
        assert_eq!(
            store.put_verified_headers_batch(&records).unwrap(),
            VerifiedHeaderBatchOutcome {
                existing: 4,
                promoted: 0,
            }
        );

        for record in records {
            assert_eq!(
                store.get_header(record.header.height).unwrap(),
                Some(record.header)
            );
            assert_eq!(
                store.get_header_by_hash(&record.hash).unwrap(),
                Some(record.header)
            );
            assert_eq!(
                store.get_chain_work(record.header.height).unwrap(),
                Some(record.cumulative_chainwork)
            );
            assert_eq!(
                store.get_header_anchor(record.header.height).unwrap(),
                Some(HeaderChainAnchor {
                    height: record.header.height,
                    block_id: record.hash,
                    state_root: record.header.state_root,
                    tx_root: record.header.tx_root,
                    miner_address: record.header.miner_address,
                    log_slots: record.header.log_slots,
                    active_slot_count: record.header.active_slot_count,
                    alloc_counter: record.header.alloc_counter,
                    cumulative_chainwork: record.cumulative_chainwork,
                })
            );
        }
    }

    #[test]
    fn verified_header_batch_rejects_invalid_input_without_partial_write() {
        let records = verified_header_batch_chain(3);

        {
            let directory = tempfile::tempdir().unwrap();
            let store = MdbxStore::open(directory.path()).unwrap();
            let mut discontinuous = records[..2].to_vec();
            discontinuous[1].header.height = 2;
            discontinuous[1].hash = crate::hash_block_header(&discontinuous[1].header);
            assert!(store.put_verified_headers_batch(&discontinuous).is_err());
            assert_eq!(store.get_header(0).unwrap(), None);
        }

        {
            let directory = tempfile::tempdir().unwrap();
            let store = MdbxStore::open(directory.path()).unwrap();
            let mut bad_hash = records.clone();
            bad_hash[2].hash[0] ^= 1;
            assert!(store.put_verified_headers_batch(&bad_hash).is_err());
            assert_eq!(store.get_header(0).unwrap(), None);
            assert_eq!(store.get_header(1).unwrap(), None);
        }

        {
            let directory = tempfile::tempdir().unwrap();
            let store = MdbxStore::open(directory.path()).unwrap();
            let mut bad_work = records.clone();
            bad_work[2].cumulative_chainwork[0] ^= 1;
            assert!(store.put_verified_headers_batch(&bad_work).is_err());
            assert_eq!(store.get_header(0).unwrap(), None);
            assert_eq!(store.get_header(1).unwrap(), None);
        }

        {
            let directory = tempfile::tempdir().unwrap();
            let store = MdbxStore::open(directory.path()).unwrap();
            let mut bad_parent = records.clone();
            bad_parent[2].header.prev_block_hash[0] ^= 1;
            bad_parent[2].hash = crate::hash_block_header(&bad_parent[2].header);
            assert!(store.put_verified_headers_batch(&bad_parent).is_err());
            assert_eq!(store.get_header(0).unwrap(), None);
            assert_eq!(store.get_header(1).unwrap(), None);
        }
    }

    #[test]
    fn verified_header_batch_rejects_partial_parent_conflict_and_gap() {
        let records = verified_header_batch_chain(3);

        {
            let directory = tempfile::tempdir().unwrap();
            let store = MdbxStore::open(directory.path()).unwrap();
            store
                .put_header_only(&records[0].header, &records[0].hash)
                .unwrap();
            assert!(store.put_verified_headers_batch(&records[..1]).is_err());
            assert!(store.put_verified_headers_batch(&records[1..2]).is_err());
            assert_eq!(store.get_header(1).unwrap(), None);
        }

        {
            let directory = tempfile::tempdir().unwrap();
            let store = MdbxStore::open(directory.path()).unwrap();
            store.put_verified_headers_batch(&records[..1]).unwrap();
            let mut conflict = records[0];
            conflict.header.state_root[0] ^= 1;
            conflict.hash = crate::hash_block_header(&conflict.header);
            assert!(store.put_verified_headers_batch(&[conflict]).is_err());
            assert_eq!(store.get_header(0).unwrap(), Some(records[0].header));
        }

        {
            let directory = tempfile::tempdir().unwrap();
            let store = MdbxStore::open(directory.path()).unwrap();
            store
                .put_header_only(&records[2].header, &records[2].hash)
                .unwrap();
            assert!(store.put_verified_headers_batch(&records).is_err());
            assert_eq!(store.get_header(0).unwrap(), None);
            assert_eq!(store.get_header(1).unwrap(), None);
            assert_eq!(store.get_header(2).unwrap(), Some(records[2].header));
        }
    }

    #[test]
    fn verified_header_batch_crash_restart_is_exactly_old_or_new() {
        for (fault, committed) in [
            (
                AuthoritativeMutationFault::VerifiedHeaderBeforeCommit,
                false,
            ),
            (AuthoritativeMutationFault::VerifiedHeaderAfterCommit, true),
        ] {
            let directory = tempfile::tempdir().unwrap();
            let store = MdbxStore::open(directory.path()).unwrap();
            let records = verified_header_batch_chain(3);
            store
                .put_verified_headers_batch(&records[..1])
                .expect("seed exact genesis parent");

            let guard = arm_authoritative_mutation_fault(fault);
            assert_injected_crash(store.put_verified_headers_batch(&records[1..]), fault);
            drop(guard);
            drop(store);

            let reopened = MdbxStore::open(directory.path()).unwrap();
            assert_eq!(reopened.get_header(0).unwrap(), Some(records[0].header));
            for record in &records[1..] {
                assert_eq!(
                    reopened.get_header(record.header.height).unwrap(),
                    committed.then_some(record.header)
                );
                assert_eq!(
                    reopened.get_header_by_hash(&record.hash).unwrap(),
                    committed.then_some(record.header)
                );
                assert_eq!(
                    reopened.get_chain_work(record.header.height).unwrap(),
                    committed.then_some(record.cumulative_chainwork)
                );
                assert_eq!(
                    reopened.get_header_anchor(record.header.height).unwrap(),
                    committed.then_some(HeaderChainAnchor {
                        height: record.header.height,
                        block_id: record.hash,
                        state_root: record.header.state_root,
                        tx_root: record.header.tx_root,
                        miner_address: record.header.miner_address,
                        log_slots: record.header.log_slots,
                        active_slot_count: record.header.active_slot_count,
                        alloc_counter: record.header.alloc_counter,
                        cumulative_chainwork: record.cumulative_chainwork,
                    })
                );
            }
        }
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
                attested_coverage: 0,
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

    fn assert_injected_crash<T>(
        result: Result<T, StoreError>,
        expected: AuthoritativeMutationFault,
    ) {
        assert!(
            matches!(result, Err(StoreError::InjectedCrash(actual)) if actual == expected),
            "operation did not stop at the armed authoritative MDBX boundary"
        );
    }

    fn crash_test_coinbase(tag: u8) -> noid_tx::Transaction {
        use noid_poseidon2b::primitives::Address;
        use noid_tx::{output_bitmap_bit, TxBody, TxInput, TxOutput, TX_INPUTS, TX_OUTPUTS};

        let mut outputs = [TxOutput::dummy(); TX_OUTPUTS];
        outputs[0] = TxOutput {
            slot_index: u32::from(tag),
            amount: 1,
            owner: Address([tag; 32]),
        };
        noid_tx::Transaction::new(TxBody {
            epoch_anchor: [tag; 32],
            fee: 0,
            input_owner: Address([0; 32]),
            inputs: [TxInput::dummy(); TX_INPUTS],
            outputs,
            validity_bitmap: output_bitmap_bit(0),
            is_coinbase: true,
        })
    }

    struct ProductionResizeRestartFixture {
        parent: BlockHeader,
        parent_hash: [u8; 32],
        parent_meta: ConsensusMeta,
        child: BlockHeader,
        child_hash: [u8; 32],
        child_meta: ConsensusMeta,
        child_tx_hash: TxBodyHash,
        child_undo: BlockUndoLog,
        lower_owner: noid_poseidon2b::primitives::Address,
        upper_owner: noid_poseidon2b::primitives::Address,
        upper_slot_index: u32,
    }

    /// Install a depth-24 parent and its accepted depth-25 child using the
    /// production 2^16-slot segment geometry.  Only segments 0 and 256 are
    /// materialized, so this exercises the real grow/shrink boundary while
    /// retaining bounded memory and disk work.
    fn install_production_resize_restart_fixture(
        store: &MdbxStore,
        promote_child_coverage: bool,
        child_fault: Option<AuthoritativeMutationFault>,
    ) -> ProductionResizeRestartFixture {
        use crate::consensus::params::LOG_SEGMENT_SIZE;
        use noid_poseidon2b::primitives::Address;

        const PARENT_LOG_SLOTS: u32 = 24;
        const CHILD_LOG_SLOTS: u32 = PARENT_LOG_SLOTS + 1;
        const LOWER_SLOT_INDEX: u32 = 1;

        let upper_slot_index = 1u32 << PARENT_LOG_SLOTS;
        let upper_segment_id = (upper_slot_index >> LOG_SEGMENT_SIZE) as u16;
        assert_eq!(upper_segment_id, 256);

        let lower_owner = Address([0xD1; 32]);
        let upper_owner = Address([0xD2; 32]);
        let lower_slot = SlotValue::with_owner_fields(41, 1, lower_owner.as_fields());
        let upper_slot = SlotValue::with_owner_fields(73, 2, upper_owner.as_fields());

        let mut lower_columns = SegmentColumns::new_zero(1usize << LOG_SEGMENT_SIZE);
        lower_columns.values[LOWER_SLOT_INDEX as usize] = lower_slot.value;
        lower_columns.owners_hi[LOWER_SLOT_INDEX as usize] = lower_slot.owner_hi;
        lower_columns.owners_lo[LOWER_SLOT_INDEX as usize] = lower_slot.owner_lo;

        let mut parent = crate::consensus::genesis::genesis_header();
        parent.log_slots = PARENT_LOG_SLOTS;
        // Real exact roots: ladder promotion validates the cursor summary
        // commitment against the canonical header state root.
        parent.state_root =
            crate::state::ChainState::from_sparse_utxos(24, &[(LOWER_SLOT_INDEX, lower_slot)], 1)
                .unwrap()
                .cached_state_root();
        parent.active_slot_count = 1;
        parent.alloc_counter = 1;
        let parent_hash = crate::hash_block_header(&parent);
        let parent_meta = ConsensusMeta {
            tip_height: 0,
            tip_hash: parent_hash,
            cumulative_chainwork: [1; 32],
            finalized: crate::storage::meta::FinalizedCheckpoint {
                height: 0,
                hash: parent_hash,
            },
        };
        let parent_undo = BlockUndoLog {
            block_height: 0,
            log_slots_before: PARENT_LOG_SLOTS,
            active_slot_count_before: 0,
            alloc_counter_before: 0,
            slot_changes: vec![(LOWER_SLOT_INDEX, SlotValue::EMPTY)],
            tx_hashes: vec![],
        };
        store
            .commit_block(
                &parent,
                &parent_hash,
                &parent_undo,
                &[(0, LOG_SEGMENT_SIZE as u8, Some(&lower_columns))],
                &[],
                &[],
                None,
                None,
                &parent_meta,
                false,
            )
            .unwrap();

        let mut upper_columns = SegmentColumns::new_zero(1usize << LOG_SEGMENT_SIZE);
        upper_columns.values[0] = upper_slot.value;
        upper_columns.owners_hi[0] = upper_slot.owner_hi;
        upper_columns.owners_lo[0] = upper_slot.owner_lo;

        let mut child = parent;
        child.height = 1;
        child.prev_block_hash = parent_hash;
        child.timestamp = child.timestamp.saturating_add(1);
        child.nonce = 0xD25;
        child.log_slots = CHILD_LOG_SLOTS;
        child.state_root = crate::state::ChainState::from_sparse_utxos(
            25,
            &[
                (LOWER_SLOT_INDEX, lower_slot),
                (upper_slot_index, upper_slot),
            ],
            2,
        )
        .unwrap()
        .cached_state_root();
        child.active_slot_count = 2;
        child.alloc_counter = 2;
        let child_hash = crate::hash_block_header(&child);
        let child_tx_hash = TxBodyHash([0xD3; 32]);
        let child_undo = BlockUndoLog {
            block_height: 1,
            log_slots_before: PARENT_LOG_SLOTS,
            active_slot_count_before: 1,
            alloc_counter_before: 1,
            slot_changes: vec![(upper_slot_index, SlotValue::EMPTY)],
            tx_hashes: vec![child_tx_hash],
        };
        let child_meta = ConsensusMeta {
            tip_height: 1,
            tip_hash: child_hash,
            cumulative_chainwork: [2; 32],
            finalized: parent_meta.finalized,
        };
        let fault_guard = child_fault.map(arm_authoritative_mutation_fault);
        let child_commit = store.commit_block(
            &child,
            &child_hash,
            &child_undo,
            &[(
                upper_segment_id,
                LOG_SEGMENT_SIZE as u8,
                Some(&upper_columns),
            )],
            &[child_tx_hash],
            &[],
            Some(b"production-grow-body"),
            Some(AcceptedBlockCommitData {
                block_proof_bytes: b"production-grow-proof",
                block_auth_sidecar_bytes: b"production-grow-sidecar",
                coverage_attestation_bytes: &[],
                history_claim_bytes: b"production-grow-history",
                accepted_block_certificate_bytes: b"production-grow-certificate",
            }),
            &child_meta,
            false,
        );
        if let Some(fault) = child_fault {
            assert_injected_crash(child_commit, fault);
        } else {
            child_commit.unwrap();
        }
        drop(fault_guard);

        if promote_child_coverage {
            assert!(child_fault.is_none());
            let claimed = store.claim_next_recursive_proof_job().unwrap().unwrap();
            assert_eq!((claimed.height, claimed.block_hash), (1, child_hash));
            let ladder_update = SelectedHistoryLadderUpdate {
                log_slots: CHILD_LOG_SLOTS,
                active_slot_count: 2,
                alloc_counter: 2,
                state_root: child.state_root,
                segment_summaries: vec![
                    (
                        0,
                        1,
                        exact_segment_root_from_columns(
                            crate::fri_state::LOG_SEGMENT_SIZE,
                            &lower_columns,
                        ),
                    ),
                    (
                        upper_segment_id,
                        1,
                        exact_segment_root_from_columns(
                            crate::fri_state::LOG_SEGMENT_SIZE,
                            &upper_columns,
                        ),
                    ),
                ],
                dirty_segments: vec![
                    (0, Some(std::sync::Arc::new(lower_columns))),
                    (upper_segment_id, Some(std::sync::Arc::new(upper_columns))),
                ],
            };
            store
                .complete_recursive_proof_job_and_promote_selected_history(
                    1,
                    child_hash,
                    &selected_terminal_bytes(1, child_hash),
                    &ladder_update,
                )
                .unwrap();
        }

        ProductionResizeRestartFixture {
            parent,
            parent_hash,
            parent_meta,
            child,
            child_hash,
            child_meta,
            child_tx_hash,
            child_undo,
            lower_owner,
            upper_owner,
            upper_slot_index,
        }
    }

    #[test]
    fn verified_header_crash_restart_is_exactly_old_or_new() {
        for (fault, committed) in [
            (
                AuthoritativeMutationFault::VerifiedHeaderBeforeCommit,
                false,
            ),
            (AuthoritativeMutationFault::VerifiedHeaderAfterCommit, true),
        ] {
            let directory = tempfile::tempdir().unwrap();
            let store = MdbxStore::open(directory.path()).unwrap();
            let genesis = crate::consensus::genesis::genesis_header();
            let genesis_hash = crate::hash_block_header(&genesis);
            store
                .put_verified_header_only(&genesis, &genesis_hash, &[1; 32])
                .unwrap();

            let mut next = genesis;
            next.height = 1;
            next.prev_block_hash = genesis_hash;
            next.timestamp = next.timestamp.saturating_add(1);
            next.nonce = 11;
            let next_hash = crate::hash_block_header(&next);
            let next_work = [2; 32];

            let guard = arm_authoritative_mutation_fault(fault);
            assert_injected_crash(
                store.put_verified_header_only(&next, &next_hash, &next_work),
                fault,
            );
            drop(guard);
            drop(store);

            let reopened = MdbxStore::open(directory.path()).unwrap();
            assert_eq!(reopened.get_header(0).unwrap(), Some(genesis));
            assert_eq!(reopened.get_header(1).unwrap(), committed.then_some(next));
            assert_eq!(
                reopened.get_header_by_hash(&next_hash).unwrap(),
                committed.then_some(next)
            );
            assert_eq!(
                reopened.get_chain_work(1).unwrap(),
                committed.then_some(next_work)
            );
            assert_eq!(
                reopened
                    .get_header_anchor(1)
                    .unwrap()
                    .map(|anchor| (anchor.block_id, anchor.cumulative_chainwork,)),
                committed.then_some((next_hash, next_work))
            );
            assert_eq!(reopened.get_chain_tip().unwrap(), None);
        }
    }

    #[test]
    fn accepted_block_crash_restart_keeps_one_complete_epoch() {
        use noid_poseidon2b::primitives::{Address, TxBodyHash};

        for (fault, committed) in [
            (AuthoritativeMutationFault::AcceptedBlockBeforeCommit, false),
            (AuthoritativeMutationFault::AcceptedBlockAfterCommit, true),
        ] {
            let directory = tempfile::tempdir().unwrap();
            let store = MdbxStore::open(directory.path()).unwrap();
            let owner = Address([0xC1; 32]);
            let (parent, parent_meta) = commit_owner_fixture(&store, owner);
            let parent_hash = crate::hash_block_header(&parent);
            let parent_segment = store
                .get_segment(0)
                .unwrap()
                .map(|(effective_log, columns)| encode_segment(&columns, effective_log));
            let parent_utxos = store.get_verified_utxos_by_owner(&owner.0).unwrap();

            let mut header = parent;
            header.height = 1;
            header.prev_block_hash = parent_hash;
            header.timestamp = header.timestamp.saturating_add(1);
            header.nonce = 0xA11CE;
            let hash = crate::hash_block_header(&header);
            let tx_hash = TxBodyHash([0xA1; 32]);
            let undo = BlockUndoLog {
                block_height: 1,
                log_slots_before: parent.log_slots,
                active_slot_count_before: parent.active_slot_count,
                alloc_counter_before: parent.alloc_counter,
                slot_changes: vec![],
                tx_hashes: vec![tx_hash],
            };
            let meta = ConsensusMeta {
                tip_height: 1,
                tip_hash: hash,
                cumulative_chainwork: [2; 32],
                finalized: parent_meta.finalized,
            };
            let accepted = AcceptedBlockCommitData {
                block_proof_bytes: b"accepted-proof",
                block_auth_sidecar_bytes: b"accepted-sidecar",
                coverage_attestation_bytes: &[],
                history_claim_bytes: b"accepted-history",
                accepted_block_certificate_bytes: b"accepted-certificate",
            };

            let guard = arm_authoritative_mutation_fault(fault);
            assert_injected_crash(
                store.commit_block(
                    &header,
                    &hash,
                    &undo,
                    &[],
                    &[tx_hash],
                    &[],
                    Some(b"accepted-body"),
                    Some(accepted),
                    &meta,
                    false,
                ),
                fault,
            );
            drop(guard);
            drop(store);

            let reopened = MdbxStore::open(directory.path()).unwrap();
            assert_eq!(
                reopened.get_chain_tip().unwrap(),
                Some(if committed {
                    (1, hash)
                } else {
                    (0, parent_hash)
                })
            );
            assert_eq!(
                reopened.get_consensus_meta().unwrap(),
                Some(if committed {
                    meta.clone()
                } else {
                    parent_meta.clone()
                })
            );
            assert_eq!(reopened.get_header(1).unwrap(), committed.then_some(header));
            assert_eq!(
                reopened.get_chain_work(1).unwrap(),
                committed.then_some([2; 32])
            );
            assert_eq!(
                reopened
                    .get_header_anchor(1)
                    .unwrap()
                    .map(|anchor| (anchor.block_id, anchor.cumulative_chainwork)),
                committed.then_some((hash, [2; 32]))
            );
            assert_eq!(
                reopened.get_state_meta().unwrap(),
                Some((
                    parent.log_slots,
                    parent.active_slot_count,
                    parent.alloc_counter
                ))
            );
            assert_eq!(
                reopened
                    .get_segment(0)
                    .unwrap()
                    .map(|(effective_log, columns)| encode_segment(&columns, effective_log)),
                parent_segment
            );
            let owner_snapshot = reopened.get_verified_utxos_by_owner(&owner.0).unwrap();
            assert_eq!(owner_snapshot.utxos, parent_utxos.utxos);
            assert_eq!(owner_snapshot.state_root, parent_utxos.state_root);
            assert_eq!(owner_snapshot.log_slots, parent_utxos.log_slots);
            assert_eq!(
                owner_snapshot.active_slot_count,
                parent_utxos.active_slot_count
            );
            assert_eq!(owner_snapshot.alloc_counter, parent_utxos.alloc_counter);
            assert_eq!(owner_snapshot.height, if committed { 1 } else { 0 });
            assert_eq!(
                owner_snapshot.tip_hash,
                if committed { hash } else { parent_hash }
            );
            assert_eq!(
                reopened.get_tx_index(&tx_hash.0).unwrap(),
                committed.then_some((1, 0))
            );
            assert_eq!(
                reopened.get_undo_log(1).unwrap(),
                committed.then_some(undo.clone())
            );
            assert_eq!(
                reopened.get_recent_block(1).unwrap().as_deref(),
                committed.then_some(b"accepted-body".as_slice())
            );
            assert_eq!(
                reopened.get_block_proof(1).unwrap().as_deref(),
                committed.then_some(b"accepted-proof".as_slice())
            );
            assert_eq!(
                reopened.get_block_auth_sidecar(1).unwrap().as_deref(),
                committed.then_some(b"accepted-sidecar".as_slice())
            );
            assert_eq!(
                reopened.get_history_claim(1).unwrap().as_deref(),
                committed.then_some(b"accepted-history".as_slice())
            );
            assert_eq!(
                reopened
                    .get_accepted_block_certificate(1)
                    .unwrap()
                    .as_deref(),
                committed.then_some(b"accepted-certificate".as_slice())
            );
            assert_eq!(
                reopened
                    .get_recursive_proof_job(1)
                    .unwrap()
                    .map(|job| (job.block_hash, job.state,)),
                committed.then_some((hash, RecursiveProofJobState::Pending))
            );
            assert_eq!(reopened.get_selected_history_coverage().unwrap(), None);
        }
    }

    #[test]
    fn production_geometry_grow_crash_restart_keeps_one_exact_epoch() {
        use crate::consensus::params::LOG_SEGMENT_SIZE;

        for (fault, committed) in [
            (AuthoritativeMutationFault::AcceptedBlockBeforeCommit, false),
            (AuthoritativeMutationFault::AcceptedBlockAfterCommit, true),
        ] {
            let directory = tempfile::tempdir().unwrap();
            let store = MdbxStore::open(directory.path()).unwrap();
            let fixture = install_production_resize_restart_fixture(&store, false, Some(fault));
            drop(store);

            let reopened = MdbxStore::open(directory.path()).unwrap();
            assert_eq!(
                reopened.get_chain_tip().unwrap(),
                Some(if committed {
                    (1, fixture.child_hash)
                } else {
                    (0, fixture.parent_hash)
                })
            );
            assert_eq!(
                reopened.get_consensus_meta().unwrap(),
                Some(if committed {
                    fixture.child_meta.clone()
                } else {
                    fixture.parent_meta.clone()
                })
            );
            assert_eq!(
                reopened.get_header(1).unwrap(),
                committed.then_some(fixture.child)
            );
            assert_eq!(
                reopened.get_state_meta().unwrap(),
                Some(if committed { (25, 2, 2) } else { (24, 1, 1) })
            );
            assert_eq!(
                reopened.segment_ids().unwrap(),
                if committed { vec![0, 256] } else { vec![0] }
            );

            let (effective_log, lower_columns) =
                reopened.get_segment(0).unwrap().expect("lower segment");
            assert_eq!(effective_log, LOG_SEGMENT_SIZE as u8);
            let lower_value = SlotValue {
                value: lower_columns.values[1],
                owner_hi: lower_columns.owners_hi[1],
                owner_lo: lower_columns.owners_lo[1],
            };
            assert_eq!(
                lower_value,
                SlotValue::with_owner_fields(41, 1, fixture.lower_owner.as_fields())
            );
            drop(lower_columns);

            let upper = reopened.get_segment(256).unwrap();
            assert_eq!(upper.is_some(), committed);
            if let Some((effective_log, upper_columns)) = upper {
                assert_eq!(effective_log, LOG_SEGMENT_SIZE as u8);
                let upper_value = SlotValue {
                    value: upper_columns.values[0],
                    owner_hi: upper_columns.owners_hi[0],
                    owner_lo: upper_columns.owners_lo[0],
                };
                assert_eq!(
                    upper_value,
                    SlotValue::with_owner_fields(73, 2, fixture.upper_owner.as_fields())
                );
            }

            let lower_snapshot = reopened
                .get_verified_utxos_by_owner(&fixture.lower_owner.0)
                .unwrap();
            assert_eq!(
                lower_snapshot.utxos,
                vec![VerifiedOwnerUtxo {
                    slot_index: 1,
                    amount: 41,
                    creation_id: 1,
                }]
            );
            assert_eq!(lower_snapshot.height, u64::from(committed));
            assert_eq!(
                lower_snapshot.tip_hash,
                if committed {
                    fixture.child_hash
                } else {
                    fixture.parent_hash
                }
            );
            assert_eq!(lower_snapshot.log_slots, if committed { 25 } else { 24 });
            assert_eq!(
                lower_snapshot.active_slot_count,
                if committed { 2 } else { 1 }
            );
            assert_eq!(lower_snapshot.alloc_counter, if committed { 2 } else { 1 });

            let upper_snapshot = reopened
                .get_verified_utxos_by_owner(&fixture.upper_owner.0)
                .unwrap();
            assert_eq!(
                upper_snapshot.utxos,
                if committed {
                    vec![VerifiedOwnerUtxo {
                        slot_index: fixture.upper_slot_index,
                        amount: 73,
                        creation_id: 2,
                    }]
                } else {
                    vec![]
                }
            );
            assert_eq!(
                reopened.get_tx_index(&fixture.child_tx_hash.0).unwrap(),
                committed.then_some((1, 0))
            );
            assert_eq!(
                reopened.get_undo_log(1).unwrap(),
                committed.then_some(fixture.child_undo.clone())
            );
            assert_eq!(
                reopened.get_block_proof(1).unwrap().as_deref(),
                committed.then_some(b"production-grow-proof".as_slice())
            );
            assert_eq!(
                reopened
                    .get_recursive_proof_job(1)
                    .unwrap()
                    .map(|job| (job.block_hash, job.state)),
                committed.then_some((fixture.child_hash, RecursiveProofJobState::Pending))
            );
            assert_eq!(reopened.get_selected_history_coverage().unwrap(), None);
        }
    }

    #[test]
    fn production_geometry_shrink_reorg_crash_restart_rewinds_complete_epoch() {
        for (fault, committed) in [
            (AuthoritativeMutationFault::ReorgBeforeCommit, false),
            (AuthoritativeMutationFault::ReorgAfterCommit, true),
        ] {
            let directory = tempfile::tempdir().unwrap();
            let store = MdbxStore::open(directory.path()).unwrap();
            let fixture = install_production_resize_restart_fixture(&store, true, None);
            assert_eq!(
                store.get_selected_history_coverage().unwrap(),
                Some(SelectedHistoryCoverage {
                    height: 1,
                    block_hash: fixture.child_hash,
                })
            );

            let guard = arm_authoritative_mutation_fault(fault);
            assert_injected_crash(
                store.commit_reorg(
                    0,
                    &fixture.parent,
                    &fixture.parent_hash,
                    &[],
                    &[fixture.child_tx_hash],
                    &[],
                    &[],
                    &fixture.parent_meta,
                ),
                fault,
            );
            drop(guard);
            drop(store);

            let reopened = MdbxStore::open(directory.path()).unwrap();
            assert_eq!(
                reopened.get_chain_tip().unwrap(),
                Some(if committed {
                    (0, fixture.parent_hash)
                } else {
                    (1, fixture.child_hash)
                })
            );
            assert_eq!(
                reopened.get_consensus_meta().unwrap(),
                Some(if committed {
                    fixture.parent_meta.clone()
                } else {
                    fixture.child_meta.clone()
                })
            );
            assert_eq!(
                reopened.get_header(1).unwrap(),
                (!committed).then_some(fixture.child)
            );
            assert_eq!(
                reopened.get_state_meta().unwrap(),
                Some(if committed { (24, 1, 1) } else { (25, 2, 2) })
            );
            assert_eq!(
                reopened.segment_ids().unwrap(),
                if committed { vec![0] } else { vec![0, 256] }
            );
            assert_eq!(reopened.get_segment(256).unwrap().is_some(), !committed);

            let lower_snapshot = reopened
                .get_verified_utxos_by_owner(&fixture.lower_owner.0)
                .unwrap();
            assert_eq!(
                lower_snapshot.utxos,
                vec![VerifiedOwnerUtxo {
                    slot_index: 1,
                    amount: 41,
                    creation_id: 1,
                }]
            );
            assert_eq!(lower_snapshot.height, if committed { 0 } else { 1 });
            assert_eq!(lower_snapshot.log_slots, if committed { 24 } else { 25 });
            assert_eq!(
                lower_snapshot.active_slot_count,
                if committed { 1 } else { 2 }
            );
            assert_eq!(lower_snapshot.alloc_counter, if committed { 1 } else { 2 });

            let upper_snapshot = reopened
                .get_verified_utxos_by_owner(&fixture.upper_owner.0)
                .unwrap();
            assert_eq!(
                upper_snapshot.utxos,
                if committed {
                    vec![]
                } else {
                    vec![VerifiedOwnerUtxo {
                        slot_index: fixture.upper_slot_index,
                        amount: 73,
                        creation_id: 2,
                    }]
                }
            );
            assert_eq!(
                reopened.get_tx_index(&fixture.child_tx_hash.0).unwrap(),
                (!committed).then_some((1, 0))
            );
            assert_eq!(
                reopened.get_undo_log(1).unwrap(),
                (!committed).then_some(fixture.child_undo.clone())
            );
            assert_eq!(
                reopened.get_block_proof(1).unwrap().as_deref(),
                (!committed).then_some(b"production-grow-proof".as_slice())
            );
            assert_eq!(
                reopened.get_selected_history_coverage().unwrap(),
                (!committed).then_some(SelectedHistoryCoverage {
                    height: 1,
                    block_hash: fixture.child_hash,
                })
            );
            assert_eq!(
                reopened
                    .get_recursive_proof_job(1)
                    .unwrap()
                    .map(|job| (job.block_hash, job.state)),
                (!committed).then_some((fixture.child_hash, RecursiveProofJobState::Complete))
            );
            assert_eq!(
                reopened
                    .get_recursive_proof_job_result(1)
                    .unwrap()
                    .map(|result| result.bytes),
                (!committed).then_some(selected_terminal_bytes(1, fixture.child_hash))
            );
        }
    }

    #[test]
    fn reorg_crash_restart_never_mixes_canonical_suffixes() {
        use crate::block::Block;
        use crate::storage::mdbx_context::ReorgBlockPayload;
        use noid_poseidon2b::primitives::Address;

        for (fault, committed) in [
            (AuthoritativeMutationFault::ReorgBeforeCommit, false),
            (AuthoritativeMutationFault::ReorgAfterCommit, true),
        ] {
            let directory = tempfile::tempdir().unwrap();
            let store = MdbxStore::open(directory.path()).unwrap();
            let owner = Address([0xC2; 32]);
            let (parent, parent_meta) = commit_owner_fixture(&store, owner);
            let parent_hash = crate::hash_block_header(&parent);
            let parent_segment = store
                .get_segment(0)
                .unwrap()
                .map(|(effective_log, columns)| encode_segment(&columns, effective_log));
            let parent_utxos = store.get_verified_utxos_by_owner(&owner.0).unwrap();

            let old_tx = crash_test_coinbase(1);
            let old_tx_hash = old_tx.txid();
            let mut old_header = parent;
            old_header.height = 1;
            old_header.prev_block_hash = parent_hash;
            old_header.timestamp = old_header.timestamp.saturating_add(1);
            old_header.nonce = 1;
            let old_hash = crate::hash_block_header(&old_header);
            let old_undo = BlockUndoLog {
                block_height: 1,
                log_slots_before: parent.log_slots,
                active_slot_count_before: parent.active_slot_count,
                alloc_counter_before: parent.alloc_counter,
                slot_changes: vec![],
                tx_hashes: vec![old_tx_hash],
            };
            let old_block = Block {
                header: old_header,
                transactions: vec![old_tx],
            };
            let old_bytes = old_block.to_bytes();
            let old_meta = ConsensusMeta {
                tip_height: 1,
                tip_hash: old_hash,
                cumulative_chainwork: [2; 32],
                finalized: parent_meta.finalized,
            };
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
                        block_proof_bytes: b"old-proof",
                        block_auth_sidecar_bytes: b"old-sidecar",
                        coverage_attestation_bytes: &[],
                        history_claim_bytes: b"old-history",
                        accepted_block_certificate_bytes: b"old-certificate",
                    }),
                    &old_meta,
                    false,
                )
                .unwrap();

            let new_tx = crash_test_coinbase(2);
            let new_tx_hash = new_tx.txid();
            let mut new_header = old_header;
            new_header.nonce = 2;
            let new_hash = crate::hash_block_header(&new_header);
            let new_undo = BlockUndoLog {
                block_height: 1,
                log_slots_before: parent.log_slots,
                active_slot_count_before: parent.active_slot_count,
                alloc_counter_before: parent.alloc_counter,
                slot_changes: vec![],
                tx_hashes: vec![new_tx_hash],
            };
            let new_block = Block {
                header: new_header,
                transactions: vec![new_tx],
            };
            let new_bytes = new_block.to_bytes();
            let staged = StagedAcceptedBlockCommit {
                header: new_header,
                hash: new_hash,
                cumulative_chainwork: [3; 32],
                undo_log: new_undo.clone(),
                history_claim_bytes: b"new-history".to_vec(),
                accepted_block_certificate_bytes: b"new-certificate".to_vec(),
            };
            let payload = ReorgBlockPayload::new(&new_block, b"new-proof", b"new-sidecar", b"");
            let new_meta = ConsensusMeta {
                tip_height: 1,
                tip_hash: new_hash,
                cumulative_chainwork: [3; 32],
                finalized: parent_meta.finalized,
            };

            let guard = arm_authoritative_mutation_fault(fault);
            assert_injected_crash(
                store.commit_reorg(
                    0,
                    &new_header,
                    &new_hash,
                    &[],
                    &[old_tx_hash],
                    &[payload],
                    &[staged],
                    &new_meta,
                ),
                fault,
            );
            drop(guard);
            drop(store);

            let reopened = MdbxStore::open(directory.path()).unwrap();
            let (expected_header, expected_hash, expected_meta, expected_tx, expected_undo) =
                if committed {
                    (new_header, new_hash, new_meta, new_tx_hash, new_undo)
                } else {
                    (old_header, old_hash, old_meta, old_tx_hash, old_undo)
                };
            assert_eq!(reopened.get_chain_tip().unwrap(), Some((1, expected_hash)));
            assert_eq!(reopened.get_consensus_meta().unwrap(), Some(expected_meta));
            assert_eq!(reopened.get_header(1).unwrap(), Some(expected_header));
            assert_eq!(
                reopened.get_chain_work(1).unwrap(),
                Some(if committed { [3; 32] } else { [2; 32] })
            );
            assert_eq!(
                reopened
                    .get_header_anchor(1)
                    .unwrap()
                    .map(|anchor| (anchor.block_id, anchor.cumulative_chainwork)),
                Some((expected_hash, if committed { [3; 32] } else { [2; 32] },))
            );
            assert_eq!(
                reopened.get_header_by_hash(&old_hash).unwrap().is_some(),
                !committed
            );
            assert_eq!(
                reopened.get_header_by_hash(&new_hash).unwrap().is_some(),
                committed
            );
            assert_eq!(
                reopened.get_tx_index(&old_tx_hash.0).unwrap().is_some(),
                !committed
            );
            assert_eq!(
                reopened.get_tx_index(&new_tx_hash.0).unwrap(),
                committed.then_some((1, 0))
            );
            assert_eq!(reopened.get_undo_log(1).unwrap(), Some(expected_undo));
            assert_eq!(
                reopened.get_recent_block(1).unwrap(),
                Some(if committed {
                    new_bytes.clone()
                } else {
                    old_bytes.clone()
                })
            );
            assert_eq!(
                reopened.get_block_proof(1).unwrap().as_deref(),
                Some(if committed {
                    b"new-proof".as_slice()
                } else {
                    b"old-proof".as_slice()
                })
            );
            assert_eq!(
                reopened.get_history_claim(1).unwrap().as_deref(),
                Some(if committed {
                    b"new-history".as_slice()
                } else {
                    b"old-history".as_slice()
                })
            );
            assert_eq!(
                reopened
                    .get_accepted_block_certificate(1)
                    .unwrap()
                    .as_deref(),
                Some(if committed {
                    b"new-certificate".as_slice()
                } else {
                    b"old-certificate".as_slice()
                })
            );
            assert_eq!(
                reopened
                    .get_recursive_proof_job(1)
                    .unwrap()
                    .map(|job| (job.block_hash, job.state,)),
                Some((expected_hash, RecursiveProofJobState::Pending))
            );
            assert_eq!(
                reopened
                    .get_segment(0)
                    .unwrap()
                    .map(|(effective_log, columns)| encode_segment(&columns, effective_log)),
                parent_segment
            );
            let owner_snapshot = reopened.get_verified_utxos_by_owner(&owner.0).unwrap();
            assert_eq!(owner_snapshot.utxos, parent_utxos.utxos);
            assert_eq!(owner_snapshot.state_root, parent_utxos.state_root);
            assert_eq!(owner_snapshot.log_slots, parent_utxos.log_slots);
            assert_eq!(
                owner_snapshot.active_slot_count,
                parent_utxos.active_slot_count
            );
            assert_eq!(owner_snapshot.alloc_counter, parent_utxos.alloc_counter);
            assert_eq!(owner_snapshot.height, 1);
            assert_eq!(owner_snapshot.tip_hash, expected_hash);
            assert_eq!(
                reopened.get_state_meta().unwrap(),
                Some((
                    parent.log_slots,
                    parent.active_slot_count,
                    parent.alloc_counter
                ))
            );
            assert_eq!(reopened.get_tx_index(&expected_tx.0).unwrap(), Some((1, 0)));
        }
    }

    #[test]
    fn staged_snapshot_crash_restart_keeps_one_state_and_authority_epoch() {
        use noid_poseidon2b::primitives::TxBodyHash;

        for (fault, committed) in [
            (
                AuthoritativeMutationFault::SnapshotInstallBeforeCommit,
                false,
            ),
            (AuthoritativeMutationFault::SnapshotInstallAfterCommit, true),
        ] {
            let database = tempfile::tempdir().unwrap();
            let staging_parent = tempfile::tempdir().unwrap();
            let store = MdbxStore::open(database.path()).unwrap();
            let (staging, old_header, new_header, old_owner, new_owner) =
                staged_snapshot_install_fixture(&store, staging_parent.path());
            let old_hash = crate::hash_block_header(&old_header);
            let new_hash = crate::hash_block_header(&new_header);
            let old_consensus = store.get_consensus_meta().unwrap().unwrap();
            let stale_tx = TxBodyHash([0xD1; 32]);
            store
                .put_accepted_block_certificate(0, b"old-certificate")
                .unwrap();
            let txn = store.db.begin_rw_txn().unwrap();
            let recent = txn.open_table(Some(T_RECENT_BLOCKS)).unwrap();
            txn.put(&recent, u64_key(0), b"old-body", WriteFlags::empty())
                .unwrap();
            let undo = txn.open_table(Some(T_UNDO_LOGS)).unwrap();
            txn.put(
                &undo,
                u64_key(0),
                encode_undo_log(&BlockUndoLog::empty(0, old_header.log_slots)),
                WriteFlags::empty(),
            )
            .unwrap();
            let tx_index = txn.open_table(Some(T_TX_INDEX)).unwrap();
            txn.put(
                &tx_index,
                stale_tx.0,
                encode_tx_index_value(0, 0),
                WriteFlags::empty(),
            )
            .unwrap();
            txn.commit().unwrap();

            let terminal = selected_terminal_bytes(1, new_hash);
            let meta = ConsensusMeta {
                tip_height: 1,
                tip_hash: new_hash,
                cumulative_chainwork: [2; 32],
                finalized: crate::storage::meta::FinalizedCheckpoint {
                    height: 1,
                    hash: new_hash,
                },
            };
            let guard = arm_authoritative_mutation_fault(fault);
            assert_injected_crash(
                store.install_finalized_snapshot_staging_with_selected_history(
                    &staging,
                    &meta,
                    &[old_header, new_header],
                    SelectedHistorySnapshotSeed {
                        height: 1,
                        block_hash: new_hash,
                        tier: RecursiveProofJobTier::B8,
                        terminal_package_bytes: &terminal,
                    },
                ),
                fault,
            );
            drop(guard);
            drop(store);

            let reopened = MdbxStore::open(database.path()).unwrap();
            assert_eq!(
                reopened.get_chain_tip().unwrap(),
                Some(if committed {
                    (1, new_hash)
                } else {
                    (0, old_hash)
                })
            );
            assert_eq!(
                reopened.get_consensus_meta().unwrap(),
                Some(if committed {
                    meta.clone()
                } else {
                    old_consensus
                })
            );
            assert_eq!(reopened.get_header(0).unwrap(), Some(old_header));
            assert_eq!(reopened.get_header(1).unwrap(), Some(new_header));
            assert_eq!(
                reopened.get_state_meta().unwrap(),
                Some(if committed { (3, 1, 2) } else { (3, 1, 1) })
            );
            assert_eq!(
                reopened
                    .get_verified_utxos_by_owner(&old_owner.0)
                    .unwrap()
                    .utxos,
                if committed {
                    vec![]
                } else {
                    vec![VerifiedOwnerUtxo {
                        slot_index: 1,
                        amount: 41,
                        creation_id: 1,
                    }]
                }
            );
            assert_eq!(
                reopened
                    .get_verified_utxos_by_owner(&new_owner.0)
                    .unwrap()
                    .utxos,
                if committed {
                    vec![VerifiedOwnerUtxo {
                        slot_index: 6,
                        amount: 73,
                        creation_id: 2,
                    }]
                } else {
                    vec![]
                }
            );
            assert_eq!(
                reopened.get_recent_block(0).unwrap().as_deref(),
                (!committed).then_some(b"old-body".as_slice())
            );
            assert_eq!(reopened.get_undo_log(0).unwrap().is_some(), !committed);
            assert_eq!(
                reopened.get_tx_index(&stale_tx.0).unwrap(),
                (!committed).then_some((0, 0))
            );
            assert_eq!(
                reopened
                    .get_accepted_block_certificate(0)
                    .unwrap()
                    .as_deref(),
                (!committed).then_some(b"old-certificate".as_slice())
            );
            assert_eq!(
                reopened.get_selected_history_coverage().unwrap(),
                committed.then_some(SelectedHistoryCoverage {
                    height: 1,
                    block_hash: new_hash,
                })
            );
            assert_eq!(
                reopened
                    .get_recursive_proof_job(1)
                    .unwrap()
                    .map(|job| (job.block_hash, job.state,)),
                committed.then_some((new_hash, RecursiveProofJobState::Complete))
            );
            assert_eq!(
                reopened
                    .get_selected_history_terminal_result()
                    .unwrap()
                    .map(|result| result.bytes),
                committed.then_some(terminal)
            );
            assert_eq!(
                retained_payload_prune_watermark(&reopened),
                Some(if committed { 1 } else { 0 })
            );
        }
    }

    #[test]
    fn selected_promotion_and_import_crash_restart_are_atomic() {
        for (fault, committed) in [
            (
                AuthoritativeMutationFault::SelectedPromotionBeforeCommit,
                false,
            ),
            (
                AuthoritativeMutationFault::SelectedPromotionAfterCommit,
                true,
            ),
        ] {
            let directory = tempfile::tempdir().unwrap();
            let store = MdbxStore::open(directory.path()).unwrap();
            let chain = put_selected_history_header_chain(&store, 1);
            let hash = chain[1].1;
            store
                .enqueue_recursive_proof_job(1, hash, RecursiveProofJobTier::B8)
                .unwrap();
            store.claim_next_recursive_proof_job().unwrap().unwrap();
            let terminal = selected_terminal_bytes(1, hash);
            let guard = arm_authoritative_mutation_fault(fault);
            assert_injected_crash(
                store.complete_recursive_proof_job_and_promote_selected_history(
                    1,
                    hash,
                    &terminal,
                    &empty_ladder_update(&chain[1].0),
                ),
                fault,
            );
            drop(guard);
            drop(store);

            let reopened = MdbxStore::open(directory.path()).unwrap();
            assert_eq!(
                reopened.get_recursive_proof_job(1).unwrap().unwrap().state,
                if committed {
                    RecursiveProofJobState::Complete
                } else {
                    // Startup recovery turns the exact old Running epoch back
                    // into its resumable Pending representation.
                    RecursiveProofJobState::Pending
                }
            );
            assert_eq!(
                reopened
                    .get_recursive_proof_job_result(1)
                    .unwrap()
                    .map(|result| result.bytes),
                committed.then_some(terminal.clone())
            );
            assert_eq!(
                reopened.get_selected_history_coverage().unwrap(),
                committed.then_some(SelectedHistoryCoverage {
                    height: 1,
                    block_hash: hash,
                })
            );
        }

        for (fault, committed) in [
            (
                AuthoritativeMutationFault::SelectedImportBeforeCommit,
                false,
            ),
            (AuthoritativeMutationFault::SelectedImportAfterCommit, true),
        ] {
            let directory = tempfile::tempdir().unwrap();
            let store = MdbxStore::open(directory.path()).unwrap();
            let chain = put_selected_history_header_chain(&store, 2);
            let hash = chain[2].1;
            store
                .enqueue_recursive_proof_job(2, hash, RecursiveProofJobTier::B8)
                .unwrap();
            let terminal = selected_terminal_bytes(2, hash);
            let guard = arm_authoritative_mutation_fault(fault);
            assert_injected_crash(
                store.import_verified_selected_history_terminal(
                    VerifiedSelectedHistoryTerminalImport {
                        height: 2,
                        block_hash: hash,
                        epoch_anchor_height: 0,
                        epoch_anchor_hash: chain[0].1,
                        tier: RecursiveProofJobTier::B8,
                        terminal_package_bytes: &terminal,
                    },
                ),
                fault,
            );
            drop(guard);
            drop(store);

            let reopened = MdbxStore::open(directory.path()).unwrap();
            assert_eq!(
                reopened.get_recursive_proof_job(2).unwrap().unwrap().state,
                if committed {
                    RecursiveProofJobState::Complete
                } else {
                    RecursiveProofJobState::Pending
                }
            );
            assert_eq!(
                reopened
                    .get_recursive_proof_job_result(2)
                    .unwrap()
                    .map(|result| result.bytes),
                committed.then_some(terminal.clone())
            );
            assert_eq!(
                reopened.get_selected_history_coverage().unwrap(),
                committed.then_some(SelectedHistoryCoverage {
                    height: 2,
                    block_hash: hash,
                })
            );
        }
    }

    #[test]
    fn delete_above_crash_restart_rewinds_jobs_results_coverage_and_watermark_together() {
        for (fault, committed) in [
            (AuthoritativeMutationFault::DeleteAboveBeforeCommit, false),
            (AuthoritativeMutationFault::DeleteAboveAfterCommit, true),
        ] {
            let directory = tempfile::tempdir().unwrap();
            let store = MdbxStore::open(directory.path()).unwrap();
            let chain = put_selected_history_header_chain(&store, 2);
            for height in 1..=2 {
                let hash = chain[height as usize].1;
                store
                    .enqueue_recursive_proof_job(height, hash, RecursiveProofJobTier::B8)
                    .unwrap();
                store.claim_next_recursive_proof_job().unwrap().unwrap();
                store
                    .complete_recursive_proof_job_and_promote_selected_history(
                        height,
                        hash,
                        &selected_terminal_bytes(height, hash),
                        &empty_ladder_update(&chain[height as usize].0),
                    )
                    .unwrap();
            }
            let txn = store.db.begin_rw_txn().unwrap();
            set_retained_payload_prune_watermark(&txn, 2).unwrap();
            txn.commit().unwrap();

            let guard = arm_authoritative_mutation_fault(fault);
            assert_injected_crash(store.delete_recursive_proof_jobs_above(1), fault);
            drop(guard);
            drop(store);

            let reopened = MdbxStore::open(directory.path()).unwrap();
            assert!(reopened.get_recursive_proof_job(1).unwrap().is_some());
            assert!(reopened
                .get_recursive_proof_job_result(1)
                .unwrap()
                .is_some());
            assert_eq!(
                reopened.get_recursive_proof_job(2).unwrap().is_some(),
                !committed
            );
            assert_eq!(
                reopened
                    .get_recursive_proof_job_result(2)
                    .unwrap()
                    .is_some(),
                !committed
            );
            let expected_height = if committed { 1 } else { 2 };
            assert_eq!(
                reopened.get_selected_history_coverage().unwrap(),
                Some(SelectedHistoryCoverage {
                    height: expected_height,
                    block_hash: chain[expected_height as usize].1,
                })
            );
            assert_eq!(
                retained_payload_prune_watermark(&reopened),
                Some(expected_height)
            );
            assert_eq!(reopened.get_header(2).unwrap(), Some(chain[2].0));
        }
    }

    #[test]
    fn maintenance_crash_restart_is_atomic_for_payloads_and_selected_journal() {
        for (fault, committed) in [
            (
                AuthoritativeMutationFault::RetainedPayloadPruneBeforeCommit,
                false,
            ),
            (
                AuthoritativeMutationFault::RetainedPayloadPruneAfterCommit,
                true,
            ),
        ] {
            let directory = tempfile::tempdir().unwrap();
            let store = MdbxStore::open(directory.path()).unwrap();
            let (chain, current_height) = install_selected_prune_authority(&store, 2);
            put_retained_payload_fixture(&store, 1);
            put_retained_payload_fixture(&store, 2);

            let guard = arm_authoritative_mutation_fault(fault);
            assert_injected_crash(store.prune_after_commit(current_height), fault);
            drop(guard);
            drop(store);

            let reopened = MdbxStore::open(directory.path()).unwrap();
            for height in 1..=2 {
                assert_eq!(
                    reopened.get_recent_block(height).unwrap().is_some(),
                    !committed
                );
                assert_eq!(
                    reopened.get_block_proof(height).unwrap().is_some(),
                    !committed
                );
                assert_eq!(
                    reopened.get_block_auth_sidecar(height).unwrap().is_some(),
                    !committed
                );
                assert_eq!(
                    reopened.get_history_claim(height).unwrap().is_some(),
                    !committed
                );
                assert_eq!(
                    reopened
                        .get_accepted_block_certificate(height)
                        .unwrap()
                        .is_some(),
                    !committed
                );
            }
            assert_eq!(
                retained_payload_prune_watermark(&reopened),
                committed.then_some(2)
            );
            assert_eq!(
                reopened.get_selected_history_coverage().unwrap(),
                Some(SelectedHistoryCoverage {
                    height: 2,
                    block_hash: chain[2].1,
                })
            );
            assert!(reopened
                .get_selected_history_terminal_result_at(2, chain[2].1)
                .unwrap()
                .is_some());
        }

        for (fault, committed) in [
            (
                AuthoritativeMutationFault::SelectedJournalPruneBeforeCommit,
                false,
            ),
            (
                AuthoritativeMutationFault::SelectedJournalPruneAfterCommit,
                true,
            ),
        ] {
            let directory = tempfile::tempdir().unwrap();
            let store = MdbxStore::open(directory.path()).unwrap();
            let chain = put_selected_history_header_chain(&store, 2);
            for height in 1..=2 {
                let hash = chain[height as usize].1;
                store
                    .enqueue_recursive_proof_job(height, hash, RecursiveProofJobTier::B8)
                    .unwrap();
                store.claim_next_recursive_proof_job().unwrap().unwrap();
                store
                    .complete_recursive_proof_job_and_promote_selected_history(
                        height,
                        hash,
                        &selected_terminal_bytes(height, hash),
                        &empty_ladder_update(&chain[height as usize].0),
                    )
                    .unwrap();
            }

            let guard = arm_authoritative_mutation_fault(fault);
            assert_injected_crash(store.compact_selected_history_journal_bounded(), fault);
            drop(guard);
            drop(store);

            let reopened = MdbxStore::open(directory.path()).unwrap();
            assert_eq!(
                reopened.get_recursive_proof_job(1).unwrap().is_some(),
                !committed
            );
            assert_eq!(
                reopened
                    .get_recursive_proof_job_result(1)
                    .unwrap()
                    .is_some(),
                !committed
            );
            assert!(reopened.get_recursive_proof_job(2).unwrap().is_some());
            assert!(reopened
                .get_recursive_proof_job_result(2)
                .unwrap()
                .is_some());
            assert_eq!(
                reopened.get_selected_history_coverage().unwrap(),
                Some(SelectedHistoryCoverage {
                    height: 2,
                    block_hash: chain[2].1,
                })
            );
        }
    }

    #[test]
    fn epoch_clear_crash_restart_is_all_tables_or_none() {
        use noid_poseidon2b::primitives::{Address, TxBodyHash};

        for (fault, committed) in [
            (AuthoritativeMutationFault::EpochClearBeforeCommit, false),
            (AuthoritativeMutationFault::EpochClearAfterCommit, true),
        ] {
            let directory = tempfile::tempdir().unwrap();
            let store = MdbxStore::open(directory.path()).unwrap();
            let owner = Address([0xC3; 32]);
            let (header, _) = commit_owner_fixture(&store, owner);
            let hash = crate::hash_block_header(&header);
            store
                .put_accepted_block_certificate(0, b"epoch-certificate")
                .unwrap();
            store
                .enqueue_recursive_proof_job(0, hash, RecursiveProofJobTier::B8)
                .unwrap();
            let terminal = selected_terminal_bytes(0, hash);
            store
                .import_verified_selected_history_terminal(VerifiedSelectedHistoryTerminalImport {
                    height: 0,
                    block_hash: hash,
                    epoch_anchor_height: 0,
                    epoch_anchor_hash: hash,
                    tier: RecursiveProofJobTier::B8,
                    terminal_package_bytes: &terminal,
                })
                .unwrap();
            let tx_hash = TxBodyHash([0xC3; 32]);
            let txn = store.db.begin_rw_txn().unwrap();
            let recent = txn.open_table(Some(T_RECENT_BLOCKS)).unwrap();
            txn.put(&recent, u64_key(0), b"epoch-body", WriteFlags::empty())
                .unwrap();
            let tx_index = txn.open_table(Some(T_TX_INDEX)).unwrap();
            txn.put(
                &tx_index,
                tx_hash.0,
                encode_tx_index_value(0, 0),
                WriteFlags::empty(),
            )
            .unwrap();
            set_retained_payload_prune_watermark(&txn, 0).unwrap();
            txn.commit().unwrap();

            let guard = arm_authoritative_mutation_fault(fault);
            assert_injected_crash(store.clear_all(), fault);
            drop(guard);
            drop(store);

            let reopened = MdbxStore::open(directory.path()).unwrap();
            assert_eq!(reopened.is_empty().unwrap(), committed);
            assert_eq!(reopened.get_header(0).unwrap().is_some(), !committed);
            assert_eq!(
                reopened.get_header_by_hash(&hash).unwrap().is_some(),
                !committed
            );
            assert_eq!(reopened.get_consensus_meta().unwrap().is_some(), !committed);
            assert_eq!(reopened.get_state_meta().unwrap().is_some(), !committed);
            assert_eq!(reopened.get_segment(0).unwrap().is_some(), !committed);
            let owner_txn = reopened.db.begin_ro_txn().unwrap();
            let owner_table = owner_txn.open_table(Some(T_OWNER_INDEX)).unwrap();
            for slot_index in [1, 6] {
                assert_eq!(
                    owner_txn
                        .get::<ObjectLength>(&owner_table, &owner_index_key(&owner.0, slot_index))
                        .unwrap()
                        .is_some(),
                    !committed
                );
            }
            drop(owner_txn);
            if committed {
                assert!(reopened.get_verified_utxos_by_owner(&owner.0).is_err());
            } else {
                assert!(!reopened
                    .get_verified_utxos_by_owner(&owner.0)
                    .unwrap()
                    .utxos
                    .is_empty());
            }
            assert_eq!(reopened.get_undo_log(0).unwrap().is_some(), !committed);
            assert_eq!(reopened.get_recent_block(0).unwrap().is_some(), !committed);
            assert_eq!(
                reopened.get_tx_index(&tx_hash.0).unwrap().is_some(),
                !committed
            );
            assert_eq!(
                reopened
                    .get_accepted_block_certificate(0)
                    .unwrap()
                    .is_some(),
                !committed
            );
            assert_eq!(
                reopened.get_recursive_proof_job(0).unwrap().is_some(),
                !committed
            );
            assert_eq!(
                reopened
                    .get_recursive_proof_job_result(0)
                    .unwrap()
                    .is_some(),
                !committed
            );
            assert_eq!(
                reopened.get_selected_history_coverage().unwrap().is_some(),
                !committed
            );
            assert_eq!(
                retained_payload_prune_watermark(&reopened).is_some(),
                !committed
            );
        }
    }
}
