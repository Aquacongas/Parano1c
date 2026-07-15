// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Bounded-memory immutable state-snapshot generation.
//!
//! The durable MDBX state always describes the current canonical tip.  This
//! module reconstructs any target inside the retained undo window without
//! cloning that state: undo pre-images are grouped by segment, the numeric
//! union of durable and touched segment IDs is visited once, and at most one
//! decoded [`SegmentColumns`] plus its encoded bytes is resident at a time.
//!
//! Segment payloads are written and synced into a private temporary generation
//! directory as they are reconstructed.  The manifest is created only after
//! the exact sparse root, live counter, creation-id bound, target header and
//! source-tip stability have all been checked.  Renaming the complete
//! directory publishes the immutable generation atomically.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use bincode::Options;
use noid_poseidon2b::native::poseidon2b_hash_byte_slices;
use serde::{Deserialize, Serialize};

use crate::block_header::{block_id, BlockHeader};
use crate::consensus::params::{BLOCK_MAX_ACTIONS, LOG_SLOTS_MAX, UNDO_RETENTION_DEPTH};
use crate::consensus::wire_limits::{MAX_SEGMENT_BYTES, MAX_SNAPSHOT_MANIFEST_SEGMENTS};
use crate::exact_state_hash::slot_leaf_hash;
use crate::fri_state::{compute_segment_root, SlotValue, LOG_SEGMENT_SIZE};
use crate::segmented_state::SegmentColumns;
use crate::state::StreamingSparseRoot;
use crate::storage::serial::{decode_segment, encode_segment, encoded_segment_len_for_eff_log};
use crate::storage::{MdbxStore, StoreError};

const SNAPSHOT_MANIFEST_DOMAIN: &[u8] = b"NOID_DISK_SNAPSHOT_GENERATION_MANIFEST_V1";
const SNAPSHOT_GENERATION_VERSION: u32 = 1;
const MANIFEST_FILE_NAME: &str = "manifest.bin";
const MANIFEST_TEMP_FILE_NAME: &str = ".manifest.tmp";
const SEGMENTS_DIRECTORY_NAME: &str = "segments";

/// A manifest contains only bounded segment metadata, never segment payloads.
/// The complete `u16` segment namespace occupies less than 4 MiB here.
const MAX_MANIFEST_BYTES: u64 = 8 * 1024 * 1024;

/// Consensus bounds make the retained rollback journal independent of state
/// size: at most one action pre-image per accepted block action.
const MAX_GROUPED_UNDO_CHANGES: usize = UNDO_RETENTION_DEPTH as usize * BLOCK_MAX_ACTIONS;

static NEXT_TEMP_GENERATION: AtomicU64 = AtomicU64::new(0);

/// Metadata for one non-empty immutable segment payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotSegmentDescriptor {
    pub segment_id: u16,
    /// Raw FRI commitment over the three decoded segment columns.
    pub segment_root: [u8; 32],
    /// Exact byte length of `storage::encode_segment` output.
    pub encoded_len: u32,
}

/// Exact state boundary described by one disk-backed snapshot generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotGenerationManifest {
    pub version: u32,
    pub target_height: u64,
    pub target_hash: [u8; 32],
    pub cumulative_chainwork: [u8; 32],
    pub log_slots: u32,
    pub active_slot_count: u64,
    pub alloc_counter: u64,
    pub state_root: [u8; 32],
    pub effective_log_segment_size: u8,
    /// Strictly increasing non-empty segment descriptors.  Payloads live in
    /// separate files and are never accumulated in this vector.
    pub segments: Vec<SnapshotSegmentDescriptor>,
}

impl SnapshotGenerationManifest {
    /// Domain-separated immutable generation identifier.
    pub fn generation_id(&self) -> Result<[u8; 32], SnapshotGenerationError> {
        let encoded = encode_manifest(self)?;
        Ok(poseidon2b_hash_byte_slices(
            SNAPSHOT_MANIFEST_DOMAIN,
            &[&encoded],
        ))
    }

    /// Look up a segment without allocating a second ID table.
    pub fn segment(&self, segment_id: u16) -> Option<&SnapshotSegmentDescriptor> {
        self.segments
            .binary_search_by_key(&segment_id, |entry| entry.segment_id)
            .ok()
            .map(|index| &self.segments[index])
    }
}

/// Open handle to an already-published immutable generation.
#[derive(Debug, Clone)]
pub struct SnapshotGeneration {
    directory: PathBuf,
    manifest: SnapshotGenerationManifest,
}

impl SnapshotGeneration {
    pub fn directory(&self) -> &Path {
        &self.directory
    }

    pub fn manifest(&self) -> &SnapshotGenerationManifest {
        &self.manifest
    }

    /// Stable canonical boundary key used by P2P export registries.
    pub fn key(&self) -> (u64, [u8; 32]) {
        (self.manifest.target_height, self.manifest.target_hash)
    }

    /// Content-derived key for distinguishing separately encoded generations
    /// of the same canonical boundary.
    pub fn generation_id(&self) -> Result<[u8; 32], SnapshotGenerationError> {
        self.manifest.generation_id()
    }

    /// Read and authenticate one encoded segment.  Peak transient memory is
    /// the encoded payload plus one decoded `SegmentColumns`; no other segment
    /// is read.
    pub fn read_encoded_segment(
        &self,
        segment_id: u16,
    ) -> Result<Vec<u8>, SnapshotGenerationError> {
        let descriptor = self
            .manifest
            .segment(segment_id)
            .ok_or(SnapshotGenerationError::SegmentNotInManifest(segment_id))?;
        let path = segment_path(&self.directory, segment_id);
        let mut file = File::open(&path)?;
        let metadata_len = file.metadata()?.len();
        if metadata_len != u64::from(descriptor.encoded_len)
            || metadata_len > MAX_SEGMENT_BYTES as u64
        {
            return Err(SnapshotGenerationError::InvalidSegment(
                segment_id,
                "encoded length does not match manifest",
            ));
        }

        let mut encoded = Vec::with_capacity(descriptor.encoded_len as usize);
        Read::by_ref(&mut file)
            .take(u64::from(descriptor.encoded_len) + 1)
            .read_to_end(&mut encoded)?;
        if encoded.len() != descriptor.encoded_len as usize {
            return Err(SnapshotGenerationError::InvalidSegment(
                segment_id,
                "short or overlong segment file",
            ));
        }
        let (effective_log, columns) = decode_segment(&encoded).ok_or(
            SnapshotGenerationError::InvalidSegment(segment_id, "segment decode failed"),
        )?;
        if effective_log != self.manifest.effective_log_segment_size {
            return Err(SnapshotGenerationError::InvalidSegment(
                segment_id,
                "effective segment log does not match manifest",
            ));
        }
        let (live, root) = validate_segment_columns(
            segment_id,
            effective_log,
            &columns,
            self.manifest.alloc_counter,
            self.manifest.target_height,
        )?;
        if live == 0 {
            return Err(SnapshotGenerationError::InvalidSegment(
                segment_id,
                "manifest contains an empty segment",
            ));
        }
        if root != descriptor.segment_root {
            return Err(SnapshotGenerationError::InvalidSegment(
                segment_id,
                "raw segment root does not match manifest",
            ));
        }
        Ok(encoded)
    }
}

#[derive(Debug)]
pub enum SnapshotGenerationError {
    Store(StoreError),
    Io(io::Error),
    ManifestCodec(String),
    MissingChainTip,
    MissingStateMeta,
    MissingHeader(u64),
    MissingChainwork(u64),
    MissingUndo(u64),
    TargetAboveTip {
        target: u64,
        tip: u64,
    },
    TargetOutsideUndoWindow {
        target: u64,
        tip: u64,
    },
    SourceChanged,
    Corrupt(&'static str),
    UndoTooLarge(u64),
    UnsupportedGeometry {
        target_log: u32,
        tip_log: u32,
    },
    InvalidSegment(u16, &'static str),
    SegmentNotInManifest(u16),
    CreationIdExceedsTarget {
        segment_id: u16,
        local_index: u32,
        creation_id: u64,
        alloc_counter: u64,
    },
    ActiveSlotCountMismatch {
        expected: u64,
        actual: u64,
    },
    ExactStateRootMismatch,
    PublishedGenerationConflict(PathBuf),
}

impl std::fmt::Display for SnapshotGenerationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Store(error) => write!(f, "snapshot store read: {error}"),
            Self::Io(error) => write!(f, "snapshot filesystem: {error}"),
            Self::ManifestCodec(error) => write!(f, "snapshot manifest codec: {error}"),
            Self::MissingChainTip => f.write_str("durable chain tip is missing"),
            Self::MissingStateMeta => f.write_str("durable state metadata is missing"),
            Self::MissingHeader(height) => write!(f, "canonical header {height} is missing"),
            Self::MissingChainwork(height) => {
                write!(f, "cumulative chainwork at height {height} is missing")
            }
            Self::MissingUndo(height) => write!(f, "undo log at height {height} is missing"),
            Self::TargetAboveTip { target, tip } => {
                write!(f, "snapshot target {target} is above durable tip {tip}")
            }
            Self::TargetOutsideUndoWindow { target, tip } => write!(
                f,
                "snapshot target {target} is outside the retained undo window at tip {tip}"
            ),
            Self::SourceChanged => {
                f.write_str("durable canonical source changed during snapshot generation")
            }
            Self::Corrupt(context) => write!(f, "corrupt durable snapshot source: {context}"),
            Self::UndoTooLarge(height) => {
                write!(f, "undo log {height} exceeds the consensus action bound")
            }
            Self::UnsupportedGeometry {
                target_log,
                tip_log,
            } => write!(
                f,
                "snapshot rollback changes segment geometry ({tip_log} -> {target_log})"
            ),
            Self::InvalidSegment(id, context) => {
                write!(f, "invalid snapshot segment {id}: {context}")
            }
            Self::SegmentNotInManifest(id) => {
                write!(f, "segment {id} is not present in this snapshot manifest")
            }
            Self::CreationIdExceedsTarget {
                segment_id,
                local_index,
                creation_id,
                alloc_counter,
            } => write!(
                f,
                "segment {segment_id} slot {local_index} creation id {creation_id} exceeds target allocator {alloc_counter}"
            ),
            Self::ActiveSlotCountMismatch { expected, actual } => write!(
                f,
                "snapshot live count {actual} does not match target header {expected}"
            ),
            Self::ExactStateRootMismatch => {
                f.write_str("snapshot exact state root does not match target header")
            }
            Self::PublishedGenerationConflict(path) => write!(
                f,
                "a different snapshot generation is already published at {}",
                path.display()
            ),
        }
    }
}

impl std::error::Error for SnapshotGenerationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Store(error) => Some(error),
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<StoreError> for SnapshotGenerationError {
    fn from(error: StoreError) -> Self {
        Self::Store(error)
    }
}

impl From<io::Error> for SnapshotGenerationError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// Export `target_height` from the current durable MDBX tip into `export_root`.
///
/// The target must be canonical and no deeper than `UNDO_RETENTION_DEPTH`.
/// Published generations are content-addressed and never overwritten.
pub fn export_snapshot_generation(
    store: &MdbxStore,
    export_root: &Path,
    target_height: u64,
) -> Result<SnapshotGeneration, SnapshotGenerationError> {
    let (tip_height, tip_hash) = store
        .get_chain_tip()?
        .ok_or(SnapshotGenerationError::MissingChainTip)?;
    if target_height > tip_height {
        return Err(SnapshotGenerationError::TargetAboveTip {
            target: target_height,
            tip: tip_height,
        });
    }
    if tip_height.saturating_sub(target_height) > UNDO_RETENTION_DEPTH {
        return Err(SnapshotGenerationError::TargetOutsideUndoWindow {
            target: target_height,
            tip: tip_height,
        });
    }

    let tip_header = canonical_header(store, tip_height)?;
    if block_id(&tip_header) != tip_hash {
        return Err(SnapshotGenerationError::Corrupt(
            "tip hash does not match canonical tip header",
        ));
    }
    let state_meta = store
        .get_state_meta()?
        .ok_or(SnapshotGenerationError::MissingStateMeta)?;
    if state_meta
        != (
            tip_header.log_slots,
            tip_header.active_slot_count,
            tip_header.alloc_counter,
        )
    {
        return Err(SnapshotGenerationError::Corrupt(
            "tip state metadata does not match tip header",
        ));
    }

    let target_header = canonical_header(store, target_height)?;
    let target_hash = block_id(&target_header);
    let cumulative_chainwork = store
        .get_chain_work(target_height)?
        .ok_or(SnapshotGenerationError::MissingChainwork(target_height))?;
    validate_log_slots(tip_header.log_slots)?;
    validate_log_slots(target_header.log_slots)?;

    let tip_effective_log = effective_log(tip_header.log_slots);
    let target_effective_log = effective_log(target_header.log_slots);
    if tip_effective_log != target_effective_log {
        return Err(SnapshotGenerationError::UnsupportedGeometry {
            target_log: target_header.log_slots,
            tip_log: tip_header.log_slots,
        });
    }
    let effective_log = tip_effective_log;

    let rollback_by_segment =
        collect_grouped_undo(store, target_height, tip_height, tip_hash, effective_log)?;

    // Discover only the strict numeric u16 key set. Segment payloads remain in
    // MDBX until the one-segment reconstruction loop below needs each one.
    let durable_ids = store.segment_ids()?;

    let tip_segment_count = segment_count(tip_header.log_slots)?;
    if durable_ids
        .last()
        .is_some_and(|id| usize::from(*id) >= tip_segment_count)
    {
        return Err(SnapshotGenerationError::Corrupt(
            "durable segment lies outside tip slot domain",
        ));
    }

    // Payload-free metadata union.  The ordered vector drives both exact-root
    // streaming and deterministic file/manifest order.
    let mut union_ids = durable_ids.clone();
    union_ids.extend(rollback_by_segment.keys().copied());
    union_ids.sort_unstable();
    union_ids.dedup();
    if union_ids.len() > MAX_SNAPSHOT_MANIFEST_SEGMENTS {
        return Err(SnapshotGenerationError::Corrupt(
            "segment id union exceeds manifest cap",
        ));
    }

    fs::create_dir_all(export_root)?;
    let mut temporary = TemporaryGeneration::create(export_root)?;
    let segments_directory = temporary.path().join(SEGMENTS_DIRECTORY_NAME);
    fs::create_dir(&segments_directory)?;

    let target_segment_count = segment_count(target_header.log_slots)?;
    let segment_size = 1usize << effective_log;
    let mut exact = StreamingSparseRoot::new(target_header.log_slots)
        .map_err(|_| SnapshotGenerationError::Corrupt("invalid target exact-root depth"))?;
    let mut counted_live = 0u64;
    let mut descriptors = Vec::new();

    for segment_id in union_ids {
        let was_durable = durable_ids.binary_search(&segment_id).is_ok();
        let mut columns = match store.get_segment_at_tip(tip_height, tip_hash, segment_id)? {
            Some((stored_log, columns)) => {
                if stored_log != effective_log
                    || columns.values.len() != segment_size
                    || columns.owners_hi.len() != segment_size
                    || columns.owners_lo.len() != segment_size
                {
                    return Err(SnapshotGenerationError::InvalidSegment(
                        segment_id,
                        "durable segment shape does not match tip geometry",
                    ));
                }
                columns
            }
            None if was_durable => {
                return Err(SnapshotGenerationError::InvalidSegment(
                    segment_id,
                    "durable segment disappeared during export",
                ));
            }
            None => SegmentColumns::new_zero(segment_size),
        };

        if let Some(changes) = rollback_by_segment.get(&segment_id) {
            apply_segment_rollbacks(&mut columns, changes)?;
        }

        if usize::from(segment_id) >= target_segment_count {
            if segment_has_live_slots(&columns) {
                return Err(SnapshotGenerationError::InvalidSegment(
                    segment_id,
                    "rollback left live data outside target slot domain",
                ));
            }
            continue;
        }

        let base = (u32::from(segment_id)) << effective_log;
        let mut segment_live = 0u32;
        for local_index in 0..segment_size {
            let slot = slot_at(&columns, local_index);
            if slot.is_empty() {
                continue;
            }
            // Tagged coinbase ids live in the `TAG | mint_height` namespace
            // and are bounded by the target height, not the allocator counter.
            let creation_in_target = crate::consensus::params::creation_id_within_boundary(
                slot.creation_id(),
                target_header.alloc_counter,
                target_header.height,
            );
            if !creation_in_target {
                return Err(SnapshotGenerationError::CreationIdExceedsTarget {
                    segment_id,
                    local_index: local_index as u32,
                    creation_id: slot.creation_id(),
                    alloc_counter: target_header.alloc_counter,
                });
            }
            segment_live = segment_live
                .checked_add(1)
                .ok_or(SnapshotGenerationError::Corrupt(
                    "segment live count overflow",
                ))?;
            exact
                .push_leaf(base | local_index as u32, slot_leaf_hash(slot))
                .map_err(|_| {
                    SnapshotGenerationError::InvalidSegment(
                        segment_id,
                        "live slot lies outside target exact-state domain",
                    )
                })?;
        }
        counted_live = counted_live.checked_add(u64::from(segment_live)).ok_or(
            SnapshotGenerationError::Corrupt("snapshot live count overflow"),
        )?;
        if segment_live == 0 {
            continue;
        }

        let segment_root = compute_segment_root(
            effective_log as usize,
            &columns.values,
            &columns.owners_hi,
            &columns.owners_lo,
        );
        let encoded = encode_segment(&columns, effective_log);
        if encoded.len() > MAX_SEGMENT_BYTES {
            return Err(SnapshotGenerationError::InvalidSegment(
                segment_id,
                "encoded segment exceeds wire/storage cap",
            ));
        }
        let encoded_len = u32::try_from(encoded.len()).map_err(|_| {
            SnapshotGenerationError::InvalidSegment(
                segment_id,
                "encoded segment length exceeds u32",
            )
        })?;
        write_synced_file(&segment_path(temporary.path(), segment_id), &encoded)?;
        descriptors.push(SnapshotSegmentDescriptor {
            segment_id,
            segment_root,
            encoded_len,
        });
        // `encoded` and `columns` drop here before the next segment is loaded.
    }

    sync_directory(&segments_directory)?;
    if counted_live != target_header.active_slot_count {
        return Err(SnapshotGenerationError::ActiveSlotCountMismatch {
            expected: target_header.active_slot_count,
            actual: counted_live,
        });
    }
    let exact_root = exact
        .finish()
        .map_err(|_| SnapshotGenerationError::Corrupt("exact-root stream did not close"))?;
    if exact_root != target_header.state_root {
        return Err(SnapshotGenerationError::ExactStateRootMismatch);
    }

    let manifest = SnapshotGenerationManifest {
        version: SNAPSHOT_GENERATION_VERSION,
        target_height,
        target_hash,
        cumulative_chainwork,
        log_slots: target_header.log_slots,
        active_slot_count: target_header.active_slot_count,
        alloc_counter: target_header.alloc_counter,
        state_root: target_header.state_root,
        effective_log_segment_size: effective_log,
        segments: descriptors,
    };
    validate_manifest(&manifest)?;

    // This is deliberately the last MDBX check before manifest publication.
    // Every segment read was also pinned to this exact tip.
    if store.get_chain_tip()? != Some((tip_height, tip_hash))
        || store.get_state_meta()? != Some(state_meta)
        || canonical_header(store, target_height)? != target_header
        || store.get_chain_work(target_height)? != Some(cumulative_chainwork)
    {
        return Err(SnapshotGenerationError::SourceChanged);
    }

    let manifest_bytes = encode_manifest(&manifest)?;
    let temporary_manifest = temporary.path().join(MANIFEST_TEMP_FILE_NAME);
    write_synced_file(&temporary_manifest, &manifest_bytes)?;
    fs::rename(
        &temporary_manifest,
        temporary.path().join(MANIFEST_FILE_NAME),
    )?;
    sync_directory(temporary.path())?;

    let generation_id = manifest.generation_id()?;
    let final_directory = export_root.join(format!(
        "snapshot-v{}-{:020}-{}",
        SNAPSHOT_GENERATION_VERSION,
        target_height,
        hex_digest(&generation_id)
    ));
    match fs::rename(temporary.path(), &final_directory) {
        Ok(()) => {
            temporary.disarm();
            sync_directory(export_root)?;
        }
        Err(_error) if final_directory.exists() => {
            let existing = open_snapshot_generation(&final_directory)?;
            if existing.manifest != manifest {
                return Err(SnapshotGenerationError::PublishedGenerationConflict(
                    final_directory,
                ));
            }
            return Ok(existing);
        }
        Err(error) => return Err(SnapshotGenerationError::Io(error)),
    }

    open_snapshot_generation(&final_directory)
}

/// Open and validate a published manifest without loading any segment payload.
pub fn open_snapshot_generation(
    directory: impl AsRef<Path>,
) -> Result<SnapshotGeneration, SnapshotGenerationError> {
    let directory = directory.as_ref().to_path_buf();
    let manifest_path = directory.join(MANIFEST_FILE_NAME);
    let mut file = File::open(&manifest_path)?;
    let length = file.metadata()?.len();
    if length == 0 || length > MAX_MANIFEST_BYTES {
        return Err(SnapshotGenerationError::Corrupt(
            "snapshot manifest length is outside bounds",
        ));
    }
    let mut encoded = Vec::with_capacity(length as usize);
    Read::by_ref(&mut file)
        .take(MAX_MANIFEST_BYTES + 1)
        .read_to_end(&mut encoded)?;
    if encoded.len() as u64 != length {
        return Err(SnapshotGenerationError::Corrupt(
            "snapshot manifest changed while reading",
        ));
    }
    let manifest = decode_manifest(&encoded)?;
    validate_manifest(&manifest)?;
    Ok(SnapshotGeneration {
        directory,
        manifest,
    })
}

fn canonical_header(
    store: &MdbxStore,
    height: u64,
) -> Result<crate::block_header::BlockHeader, SnapshotGenerationError> {
    store
        .get_header(height)?
        .ok_or(SnapshotGenerationError::MissingHeader(height))
}

fn validate_log_slots(log_slots: u32) -> Result<(), SnapshotGenerationError> {
    if log_slots > LOG_SLOTS_MAX {
        return Err(SnapshotGenerationError::Corrupt(
            "header log_slots exceeds consensus maximum",
        ));
    }
    Ok(())
}

fn effective_log(log_slots: u32) -> u8 {
    log_slots.min(LOG_SEGMENT_SIZE as u32) as u8
}

fn segment_count(log_slots: u32) -> Result<usize, SnapshotGenerationError> {
    if log_slots <= LOG_SEGMENT_SIZE as u32 {
        return Ok(1);
    }
    1usize
        .checked_shl(log_slots - LOG_SEGMENT_SIZE as u32)
        .ok_or(SnapshotGenerationError::Corrupt(
            "segment domain does not fit usize",
        ))
}

fn slot_is_in_domain(slot_index: u32, log_slots: u32) -> bool {
    log_slots >= 32 || u64::from(slot_index) < (1u64 << log_slots)
}

fn validate_undo_preimage_creation_boundary(
    previous: SlotValue,
    parent: &BlockHeader,
) -> Result<(), &'static str> {
    if previous.is_empty()
        || crate::consensus::params::creation_id_within_boundary(
            previous.creation_id(),
            parent.alloc_counter,
            parent.height,
        )
    {
        Ok(())
    } else {
        Err("undo pre-image creation id exceeds parent boundary")
    }
}

type SegmentRollback = (u32, SlotValue);

fn collect_grouped_undo(
    store: &MdbxStore,
    target_height: u64,
    tip_height: u64,
    tip_hash: [u8; 32],
    segment_log: u8,
) -> Result<BTreeMap<u16, Vec<SegmentRollback>>, SnapshotGenerationError> {
    let mut grouped: BTreeMap<u16, Vec<SegmentRollback>> = BTreeMap::new();
    let mut total_changes = 0usize;

    for height in (target_height + 1..=tip_height).rev() {
        let child = canonical_header(store, height)?;
        let parent = canonical_header(store, height - 1)?;
        if child.prev_block_hash != block_id(&parent) {
            return Err(SnapshotGenerationError::Corrupt(
                "retained canonical headers are not linked",
            ));
        }
        if height == tip_height && block_id(&child) != tip_hash {
            return Err(SnapshotGenerationError::SourceChanged);
        }
        if effective_log(parent.log_slots) != segment_log {
            return Err(SnapshotGenerationError::UnsupportedGeometry {
                target_log: parent.log_slots,
                tip_log: child.log_slots,
            });
        }
        let undo = store
            .get_undo_log(height)?
            .ok_or(SnapshotGenerationError::MissingUndo(height))?;
        if undo.block_height != height
            || undo.log_slots_before != parent.log_slots
            || undo.active_slot_count_before != parent.active_slot_count
            || undo.alloc_counter_before != parent.alloc_counter
        {
            return Err(SnapshotGenerationError::Corrupt(
                "undo metadata does not match parent header",
            ));
        }
        if undo.slot_changes.len() > BLOCK_MAX_ACTIONS {
            return Err(SnapshotGenerationError::UndoTooLarge(height));
        }
        total_changes = total_changes
            .checked_add(undo.slot_changes.len())
            .ok_or(SnapshotGenerationError::UndoTooLarge(height))?;
        if total_changes > MAX_GROUPED_UNDO_CHANGES {
            return Err(SnapshotGenerationError::UndoTooLarge(height));
        }

        let mut seen_slots = BTreeSet::new();
        // Match `revert_block`: within-block order is reversed even though a
        // valid undo contains each physical slot exactly once.
        for &(slot_index, previous) in undo.slot_changes.iter().rev() {
            if !seen_slots.insert(slot_index) {
                return Err(SnapshotGenerationError::Corrupt(
                    "undo contains a duplicate physical slot",
                ));
            }
            if !slot_is_in_domain(slot_index, child.log_slots) {
                return Err(SnapshotGenerationError::Corrupt(
                    "undo slot lies outside child slot domain",
                ));
            }
            if !slot_is_in_domain(slot_index, parent.log_slots) && !previous.is_empty() {
                return Err(SnapshotGenerationError::Corrupt(
                    "new expansion-half undo pre-image is not empty",
                ));
            }
            validate_undo_preimage_creation_boundary(previous, &parent)
                .map_err(SnapshotGenerationError::Corrupt)?;
            let segment_id = (slot_index >> segment_log) as u16;
            let local_index = slot_index & ((1u32 << segment_log) - 1);
            grouped
                .entry(segment_id)
                .or_default()
                .push((local_index, previous));
        }
    }
    Ok(grouped)
}

fn apply_segment_rollbacks(
    columns: &mut SegmentColumns,
    changes: &[SegmentRollback],
) -> Result<(), SnapshotGenerationError> {
    for &(local_index, previous) in changes {
        let local = local_index as usize;
        if local >= columns.values.len()
            || local >= columns.owners_hi.len()
            || local >= columns.owners_lo.len()
        {
            return Err(SnapshotGenerationError::Corrupt(
                "segment-local undo index is out of range",
            ));
        }
        columns.values[local] = previous.value;
        columns.owners_hi[local] = previous.owner_hi;
        columns.owners_lo[local] = previous.owner_lo;
    }
    Ok(())
}

fn slot_at(columns: &SegmentColumns, local: usize) -> SlotValue {
    SlotValue {
        value: columns.values[local],
        owner_hi: columns.owners_hi[local],
        owner_lo: columns.owners_lo[local],
    }
}

fn segment_has_live_slots(columns: &SegmentColumns) -> bool {
    (0..columns.values.len()).any(|index| !slot_at(columns, index).is_empty())
}

fn validate_segment_columns(
    segment_id: u16,
    effective_log: u8,
    columns: &SegmentColumns,
    alloc_counter: u64,
    target_height: u64,
) -> Result<(u32, [u8; 32]), SnapshotGenerationError> {
    let expected_len =
        1usize
            .checked_shl(effective_log as u32)
            .ok_or(SnapshotGenerationError::InvalidSegment(
                segment_id,
                "effective log overflows usize",
            ))?;
    if columns.values.len() != expected_len
        || columns.owners_hi.len() != expected_len
        || columns.owners_lo.len() != expected_len
    {
        return Err(SnapshotGenerationError::InvalidSegment(
            segment_id,
            "decoded column lengths are inconsistent",
        ));
    }
    let mut live = 0u32;
    for local in 0..expected_len {
        let slot = slot_at(columns, local);
        if slot.is_empty() {
            continue;
        }
        // Same tag-aware namespace rule as the historical carrier.
        let creation_in_target = crate::consensus::params::creation_id_within_boundary(
            slot.creation_id(),
            alloc_counter,
            target_height,
        );
        if !creation_in_target {
            return Err(SnapshotGenerationError::CreationIdExceedsTarget {
                segment_id,
                local_index: local as u32,
                creation_id: slot.creation_id(),
                alloc_counter,
            });
        }
        live = live
            .checked_add(1)
            .ok_or(SnapshotGenerationError::InvalidSegment(
                segment_id,
                "live count overflows u32",
            ))?;
    }
    let root = compute_segment_root(
        effective_log as usize,
        &columns.values,
        &columns.owners_hi,
        &columns.owners_lo,
    );
    Ok((live, root))
}

fn validate_manifest(manifest: &SnapshotGenerationManifest) -> Result<(), SnapshotGenerationError> {
    if manifest.version != SNAPSHOT_GENERATION_VERSION {
        return Err(SnapshotGenerationError::Corrupt(
            "unsupported snapshot manifest version",
        ));
    }
    validate_log_slots(manifest.log_slots)?;
    if manifest.effective_log_segment_size != effective_log(manifest.log_slots) {
        return Err(SnapshotGenerationError::Corrupt(
            "manifest effective segment log is inconsistent",
        ));
    }
    if manifest.segments.len() > MAX_SNAPSHOT_MANIFEST_SEGMENTS {
        return Err(SnapshotGenerationError::Corrupt(
            "manifest segment count exceeds cap",
        ));
    }
    if !manifest
        .segments
        .windows(2)
        .all(|pair| pair[0].segment_id < pair[1].segment_id)
    {
        return Err(SnapshotGenerationError::Corrupt(
            "manifest segment ids are not strictly increasing",
        ));
    }
    let domain_segments = segment_count(manifest.log_slots)?;
    let expected_encoded_len = encoded_segment_len_for_eff_log(manifest.effective_log_segment_size)
        .ok_or(SnapshotGenerationError::Corrupt(
            "manifest segment geometry overflows",
        ))?;
    if expected_encoded_len > MAX_SEGMENT_BYTES {
        return Err(SnapshotGenerationError::Corrupt(
            "manifest segment geometry exceeds segment byte cap",
        ));
    }
    for descriptor in &manifest.segments {
        if usize::from(descriptor.segment_id) >= domain_segments {
            return Err(SnapshotGenerationError::InvalidSegment(
                descriptor.segment_id,
                "manifest id lies outside target domain",
            ));
        }
        if descriptor.encoded_len as usize != expected_encoded_len {
            return Err(SnapshotGenerationError::InvalidSegment(
                descriptor.segment_id,
                "manifest encoded length is noncanonical",
            ));
        }
    }
    Ok(())
}

fn encode_manifest(
    manifest: &SnapshotGenerationManifest,
) -> Result<Vec<u8>, SnapshotGenerationError> {
    let encoded = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .serialize(manifest)
        .map_err(|error| SnapshotGenerationError::ManifestCodec(error.to_string()))?;
    if encoded.len() as u64 > MAX_MANIFEST_BYTES {
        return Err(SnapshotGenerationError::Corrupt(
            "encoded snapshot manifest exceeds byte cap",
        ));
    }
    Ok(encoded)
}

fn decode_manifest(bytes: &[u8]) -> Result<SnapshotGenerationManifest, SnapshotGenerationError> {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(MAX_MANIFEST_BYTES)
        .reject_trailing_bytes()
        .deserialize(bytes)
        .map_err(|error| SnapshotGenerationError::ManifestCodec(error.to_string()))
}

fn segment_path(generation_directory: &Path, segment_id: u16) -> PathBuf {
    generation_directory
        .join(SEGMENTS_DIRECTORY_NAME)
        .join(format!("{segment_id:05}.segment"))
}

fn write_synced_file(path: &Path, bytes: &[u8]) -> Result<(), SnapshotGenerationError> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn sync_directory(path: &Path) -> Result<(), SnapshotGenerationError> {
    File::open(path)?.sync_all()?;
    Ok(())
}

fn hex_digest(digest: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in digest {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

struct TemporaryGeneration {
    path: PathBuf,
    armed: bool,
}

impl TemporaryGeneration {
    fn create(export_root: &Path) -> Result<Self, SnapshotGenerationError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        for _ in 0..32 {
            let sequence = NEXT_TEMP_GENERATION.fetch_add(1, Ordering::Relaxed);
            let path = export_root.join(format!(
                ".snapshot-generation-{}-{now}-{sequence}.tmp",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self { path, armed: true }),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(SnapshotGenerationError::Io(error)),
            }
        }
        Err(SnapshotGenerationError::Io(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not allocate a unique temporary snapshot directory",
        )))
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for TemporaryGeneration {
    fn drop(&mut self) {
        if self.armed {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use noid_core::Block128;

    use crate::consensus::genesis::genesis_header;
    use crate::consensus::params::coinbase_creation_id;

    #[test]
    fn spent_coinbase_undo_preimage_uses_parent_height_boundary() {
        let mut parent = genesis_header();
        parent.height = 7;
        parent.alloc_counter = 3;

        let at_parent_height = SlotValue::from_parts(
            1,
            coinbase_creation_id(parent.height),
            Block128(1),
            Block128(2),
        );
        assert!(validate_undo_preimage_creation_boundary(at_parent_height, &parent).is_ok());

        let from_future_height = SlotValue::from_parts(
            1,
            coinbase_creation_id(parent.height + 1),
            Block128(1),
            Block128(2),
        );
        assert_eq!(
            validate_undo_preimage_creation_boundary(from_future_height, &parent),
            Err("undo pre-image creation id exceeds parent boundary")
        );
    }

    #[test]
    fn manifest_sequence_length_bomb_is_bounded_and_rejected() {
        let manifest = SnapshotGenerationManifest {
            version: SNAPSHOT_GENERATION_VERSION,
            target_height: 1,
            target_hash: [1; 32],
            cumulative_chainwork: [2; 32],
            log_slots: 16,
            active_slot_count: 0,
            alloc_counter: 0,
            state_root: crate::exact_state_hash::zero_slot_roots(16)[16],
            effective_log_segment_size: 16,
            segments: Vec::new(),
        };
        let mut encoded = encode_manifest(&manifest).unwrap();
        // Fixed-int bincode places the Vec length in the final eight bytes for
        // this empty fixture.  The decoder limit and Serde cautious reserve
        // must reject the hostile declaration without attempting that capacity.
        let length_offset = encoded.len() - core::mem::size_of::<u64>();
        encoded[length_offset..].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(matches!(
            decode_manifest(&encoded),
            Err(SnapshotGenerationError::ManifestCodec(_))
        ));
    }

    #[test]
    fn oversized_manifest_file_rejects_before_payload_allocation() {
        let generation = tempfile::tempdir().unwrap();
        let path = generation.path().join(MANIFEST_FILE_NAME);
        let file = File::create(path).unwrap();
        file.set_len(MAX_MANIFEST_BYTES + 1).unwrap();
        drop(file);
        assert!(matches!(
            open_snapshot_generation(generation.path()),
            Err(SnapshotGenerationError::Corrupt(
                "snapshot manifest length is outside bounds"
            ))
        ));
    }
}
