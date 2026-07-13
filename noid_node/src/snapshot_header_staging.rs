// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Bounded-memory candidate-header staging for deep snapshot synchronization.
//!
//! Peer headers are consensus-validated against one fixed canonical base and
//! appended to a private, crash-disposable file.  They are deliberately not
//! inserted into the canonical MDBX tables until the selected-history
//! terminal has authenticated the exact staged tip.  The file uses fixed-size
//! records, so validation and restart recovery retain only the consensus
//! windows (currently at most 18 headers) in memory regardless of candidate
//! chain length.

use std::collections::VecDeque;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use noid_chain::block_header::BlockHeader;
use noid_chain::consensus::header::validate_header_timeless;
use noid_chain::consensus::params::{
    EPOCH_LENGTH, EXPANSION_WINDOW, MEDIAN_TIME_BLOCKS, TX_EPOCH_BLOCKS,
};
use noid_chain::consensus::{add_work, asert_anchor_height, block_work};
use noid_chain::storage::{
    MdbxStore, StoreError, VerifiedHeaderBatchRecord, MAX_VERIFIED_HEADER_BATCH_RECORDS,
};
use noid_chain::wire::BLOCK_HEADER_WIRE_SIZE;
use noid_chain::{hash_block_header, HeaderChainAnchor};

const FILE_MAGIC: [u8; 8] = *b"NHSTAGE1";
const FILE_VERSION: u32 = 1;
const FILE_HEADER_SIZE: u64 = 8 + 4 + 4 + 8 + 32 + 32;
const RECORD_SIZE: usize = BLOCK_HEADER_WIRE_SIZE + 32 + 32;

/// Matches the P2P header response cap.  Keeping this explicit prevents an
/// accidentally unbounded caller-provided slice from becoming the temporary
/// working set even though the on-disk chain itself is not RAM-bounded.
pub const MAX_STAGED_HEADER_BATCH: usize = MAX_VERIFIED_HEADER_BATCH_RECORDS;

#[derive(Debug, thiserror::Error)]
pub enum SnapshotHeaderStagingError {
    #[error("snapshot header staging I/O: {0}")]
    Io(#[from] io::Error),
    #[error("snapshot header staging store error: {0}")]
    Store(String),
    #[error("snapshot header staging format error: {0}")]
    Format(&'static str),
    #[error("snapshot header candidate rejected at h={height}: {reason}")]
    InvalidCandidate { height: u64, reason: String },
    #[error("snapshot header canonical conflict at h={height}: {reason}")]
    CanonicalConflict { height: u64, reason: String },
    #[error("selected-history terminal rejected staged headers: {0}")]
    TerminalRejected(String),
    #[error("authenticated snapshot header staging changed after terminal verification: {0}")]
    VerifiedFileChanged(&'static str),
    #[error("snapshot header staging is poisoned by a failed durable write; reopen it")]
    Poisoned,
}

type Result<T> = std::result::Result<T, SnapshotHeaderStagingError>;

/// Immutable canonical boundary from which one candidate suffix is built.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CanonicalHeaderBoundary {
    pub header: BlockHeader,
    pub block_hash: [u8; 32],
    pub cumulative_chainwork: [u8; 32],
}

impl CanonicalHeaderBoundary {
    /// Load a boundary which is backed by the canonical header-anchor table.
    /// Merely finding a loose header row is not sufficient authority.
    pub fn load(store: &MdbxStore, height: u64) -> Result<Self> {
        let header = store
            .get_header(height)
            .map_err(store_error)?
            .ok_or_else(|| SnapshotHeaderStagingError::CanonicalConflict {
                height,
                reason: "canonical base header is missing".into(),
            })?;
        let block_hash = hash_block_header(&header);
        let cumulative_chainwork = store
            .get_chain_work(height)
            .map_err(store_error)?
            .ok_or_else(|| SnapshotHeaderStagingError::CanonicalConflict {
                height,
                reason: "canonical base chainwork is missing".into(),
            })?;
        let boundary = Self {
            header,
            block_hash,
            cumulative_chainwork,
        };
        boundary.validate_against(store)?;
        Ok(boundary)
    }

    fn validate_against(&self, store: &MdbxStore) -> Result<()> {
        if self.header.height == u64::MAX {
            return Err(SnapshotHeaderStagingError::CanonicalConflict {
                height: self.header.height,
                reason: "canonical base has no representable child height".into(),
            });
        }
        if hash_block_header(&self.header) != self.block_hash {
            return Err(SnapshotHeaderStagingError::CanonicalConflict {
                height: self.header.height,
                reason: "base header does not match its claimed hash".into(),
            });
        }
        let stored_header = store
            .get_header(self.header.height)
            .map_err(store_error)?
            .ok_or_else(|| SnapshotHeaderStagingError::CanonicalConflict {
                height: self.header.height,
                reason: "canonical base header disappeared".into(),
            })?;
        if stored_header != self.header {
            return Err(SnapshotHeaderStagingError::CanonicalConflict {
                height: self.header.height,
                reason: "canonical base header changed".into(),
            });
        }
        if store
            .get_chain_work(self.header.height)
            .map_err(store_error)?
            != Some(self.cumulative_chainwork)
        {
            return Err(SnapshotHeaderStagingError::CanonicalConflict {
                height: self.header.height,
                reason: "canonical base chainwork changed".into(),
            });
        }
        let expected_anchor = HeaderChainAnchor {
            height: self.header.height,
            block_id: self.block_hash,
            state_root: self.header.state_root,
            tx_root: self.header.tx_root,
            miner_address: self.header.miner_address,
            log_slots: self.header.log_slots,
            active_slot_count: self.header.active_slot_count,
            alloc_counter: self.header.alloc_counter,
            cumulative_chainwork: self.cumulative_chainwork,
        };
        if store
            .get_header_anchor(self.header.height)
            .map_err(store_error)?
            != Some(expected_anchor)
        {
            return Err(SnapshotHeaderStagingError::CanonicalConflict {
                height: self.header.height,
                reason: "canonical base header anchor is missing or inconsistent".into(),
            });
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct StagedHeaderRecord {
    header: BlockHeader,
    block_hash: [u8; 32],
    cumulative_chainwork: [u8; 32],
}

/// Stable identity captured when the writable staging handle is sealed.  The
/// length is part of the authority: an appended complete or partial record is
/// a different candidate even when the original prefix remains valid.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct StagingFileIdentity {
    len: u64,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
}

impl StagingFileIdentity {
    fn capture(file: &File) -> io::Result<Self> {
        let metadata = file.metadata()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            Ok(Self {
                len: metadata.len(),
                device: metadata.dev(),
                inode: metadata.ino(),
            })
        }
        #[cfg(not(unix))]
        {
            Ok(Self {
                len: metadata.len(),
            })
        }
    }

    fn same_file(&self, other: &Self) -> bool {
        #[cfg(unix)]
        {
            self.device == other.device && self.inode == other.inode
        }
        #[cfg(not(unix))]
        {
            // The staging directory is private to the node.  On platforms
            // without a stable std file-id API, the already-open handle is
            // still authoritative and the exact length/content checks below
            // fail closed for ordinary local drift.
            let _ = other;
            true
        }
    }
}

/// Exact header inputs supplied to selected-terminal verification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SelectedTerminalHeaderBoundary {
    pub tip_header: BlockHeader,
    pub tip_hash: [u8; 32],
    pub cumulative_chainwork: [u8; 32],
    pub epoch_anchor_header: BlockHeader,
}

/// One isolated candidate suffix.  `count` is derived from fixed-size durable
/// records, never from an attacker-controlled decoded collection.
pub struct SnapshotHeaderStaging {
    path: PathBuf,
    file: File,
    base: CanonicalHeaderBoundary,
    count: u64,
    poisoned: bool,
}

impl SnapshotHeaderStaging {
    /// Create a new staging file.  The base child must be the first currently
    /// missing canonical height, preventing accidental staging over a known
    /// canonical suffix.
    pub fn create(path: &Path, store: &MdbxStore, base: CanonicalHeaderBoundary) -> Result<Self> {
        base.validate_against(store)?;
        let first_missing = base.header.height + 1;
        if store
            .get_header(first_missing)
            .map_err(store_error)?
            .is_some()
        {
            return Err(SnapshotHeaderStagingError::CanonicalConflict {
                height: first_missing,
                reason: "candidate base is not immediately before the first missing header".into(),
            });
        }

        Self::create_file(path, base)
    }

    /// Create an empty candidate at an already-canonical exact target. This
    /// keeps zero-missing-header syncs on the same terminal-verification
    /// typestate path without pretending that the target's child is missing.
    pub fn create_at_canonical_boundary(
        path: &Path,
        store: &MdbxStore,
        base: CanonicalHeaderBoundary,
    ) -> Result<Self> {
        base.validate_against(store)?;
        Self::create_file(path, base)
    }

    fn create_file(path: &Path, base: CanonicalHeaderBoundary) -> Result<Self> {
        let mut file = secure_create_new(path)?;
        write_file_header(&mut file, &base)?;
        file.sync_all()?;
        sync_parent(path)?;
        Ok(Self {
            path: path.to_owned(),
            file,
            base,
            count: 0,
            poisoned: false,
        })
    }

    /// Reopen a crash-left staging file.  A partial final fixed-size record is
    /// truncated; every complete record is revalidated sequentially with a
    /// bounded consensus window before it is trusted.
    pub fn open(path: &Path, store: &MdbxStore) -> Result<Self> {
        let mut file = secure_open_existing(path)?;
        let encoded_base = read_file_header(&mut file)?;
        let base = CanonicalHeaderBoundary::load(store, encoded_base.height)?;
        if base.block_hash != encoded_base.block_hash
            || base.cumulative_chainwork != encoded_base.cumulative_chainwork
        {
            return Err(SnapshotHeaderStagingError::CanonicalConflict {
                height: base.header.height,
                reason: "staging file is pinned to a different canonical base".into(),
            });
        }

        let len = file.metadata()?.len();
        if len < FILE_HEADER_SIZE {
            return Err(SnapshotHeaderStagingError::Format(
                "file is shorter than its header",
            ));
        }
        let payload_len = len - FILE_HEADER_SIZE;
        let complete_len = payload_len - payload_len % RECORD_SIZE as u64;
        if complete_len != payload_len {
            file.set_len(FILE_HEADER_SIZE + complete_len)?;
            file.sync_all()?;
        }
        let count = complete_len / RECORD_SIZE as u64;
        let mut staging = Self {
            path: path.to_owned(),
            file,
            base,
            count,
            poisoned: false,
        };
        staging.revalidate_complete_file(store)?;
        Ok(staging)
    }

    pub fn base(&self) -> CanonicalHeaderBoundary {
        self.base
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn staged_len(&self) -> u64 {
        self.count
    }

    pub fn next_height(&self) -> Result<u64> {
        self.base
            .header
            .height
            .checked_add(self.count)
            .and_then(|height| height.checked_add(1))
            .ok_or(SnapshotHeaderStagingError::Format(
                "candidate height overflow",
            ))
    }

    /// Validate a response atomically at the batch level, then append it.
    /// A peer error leaves the previous durable prefix unchanged.  A process
    /// crash may leave a valid complete prefix plus one partial record, which
    /// `open` safely repairs.
    pub fn append_batch(&mut self, store: &MdbxStore, headers: &[BlockHeader]) -> Result<u64> {
        if self.poisoned {
            return Err(SnapshotHeaderStagingError::Poisoned);
        }
        if headers.is_empty() {
            return Err(SnapshotHeaderStagingError::InvalidCandidate {
                height: self.next_height()?,
                reason: "empty header batch".into(),
            });
        }
        if headers.len() > MAX_STAGED_HEADER_BATCH {
            return Err(SnapshotHeaderStagingError::InvalidCandidate {
                height: self.next_height()?,
                reason: format!(
                    "batch has {} headers, maximum is {MAX_STAGED_HEADER_BATCH}",
                    headers.len()
                ),
            });
        }
        self.base.validate_against(store)?;

        // First pass: consensus validation only.  The bounded window makes a
        // bad later header unable to partially commit an otherwise valid batch.
        let tip = self.tip_record()?;
        let mut expected_height =
            tip.header
                .height
                .checked_add(1)
                .ok_or(SnapshotHeaderStagingError::Format(
                    "candidate height overflow",
                ))?;
        let mut chainwork = tip.cumulative_chainwork;
        let mut window = self.load_consensus_window(store, tip.header.height)?;
        for header in headers {
            validate_next_header(header, expected_height, &window)?;
            chainwork = add_work(&chainwork, &block_work(&header.difficulty_target));
            push_window(&mut window, *header);
            expected_height =
                expected_height
                    .checked_add(1)
                    .ok_or(SnapshotHeaderStagingError::Format(
                        "candidate height overflow",
                    ))?;
        }

        // Second pass: fixed-size sequential records and one durability point.
        let original_len = FILE_HEADER_SIZE
            .checked_add(self.count.checked_mul(RECORD_SIZE as u64).ok_or(
                SnapshotHeaderStagingError::Format("staging file length overflow"),
            )?)
            .ok_or(SnapshotHeaderStagingError::Format(
                "staging file length overflow",
            ))?;
        let mut previous_work = tip.cumulative_chainwork;
        let write_result = (|| -> io::Result<()> {
            self.file.seek(SeekFrom::Start(original_len))?;
            for header in headers {
                let work = add_work(&previous_work, &block_work(&header.difficulty_target));
                let record = StagedHeaderRecord {
                    header: *header,
                    block_hash: hash_block_header(header),
                    cumulative_chainwork: work,
                };
                write_record(&mut self.file, &record)?;
                previous_work = work;
            }
            self.file.sync_data()
        })();
        if let Err(error) = write_result {
            self.poisoned = true;
            let _ = self.file.set_len(original_len);
            let _ = self.file.sync_all();
            return Err(SnapshotHeaderStagingError::Io(error));
        }
        self.count = self.count.checked_add(headers.len() as u64).ok_or(
            SnapshotHeaderStagingError::Format("staged header count overflow"),
        )?;
        Ok(expected_height)
    }

    /// Read one canonical-or-staged header without materializing the suffix.
    pub fn header_at(&mut self, store: &MdbxStore, height: u64) -> Result<Option<BlockHeader>> {
        if height <= self.base.header.height {
            return store.get_header(height).map_err(store_error);
        }
        let index = height - self.base.header.height - 1;
        if index >= self.count {
            return Ok(None);
        }
        Ok(Some(self.read_record(index)?.header))
    }

    /// Bind the staged tip, exact work and transaction-epoch header before the
    /// expensive selected-terminal verifier is invoked.
    pub fn terminal_boundary(
        &mut self,
        store: &MdbxStore,
        expected_height: u64,
        expected_hash: [u8; 32],
        expected_chainwork: [u8; 32],
    ) -> Result<SelectedTerminalHeaderBoundary> {
        let tip = self.tip_record()?;
        if tip.header.height != expected_height {
            return Err(SnapshotHeaderStagingError::InvalidCandidate {
                height: tip.header.height,
                reason: format!("staged tip does not equal requested h={expected_height}"),
            });
        }
        if tip.block_hash != expected_hash {
            return Err(SnapshotHeaderStagingError::InvalidCandidate {
                height: expected_height,
                reason: "staged tip hash does not match candidate manifest".into(),
            });
        }
        if tip.cumulative_chainwork != expected_chainwork {
            return Err(SnapshotHeaderStagingError::InvalidCandidate {
                height: expected_height,
                reason: "staged exact chainwork does not match candidate manifest".into(),
            });
        }
        let epoch_height = (expected_height / TX_EPOCH_BLOCKS) * TX_EPOCH_BLOCKS;
        let epoch_anchor_header = self.header_at(store, epoch_height)?.ok_or(
            SnapshotHeaderStagingError::InvalidCandidate {
                height: epoch_height,
                reason: "transaction-epoch anchor header is missing".into(),
            },
        )?;
        Ok(SelectedTerminalHeaderBoundary {
            tip_header: tip.header,
            tip_hash: tip.block_hash,
            cumulative_chainwork: tip.cumulative_chainwork,
            epoch_anchor_header,
        })
    }

    /// The only transition to a promotable stage.  The closure is expected to
    /// run selected-terminal verification using exactly the supplied boundary;
    /// an error preserves the isolated file and exposes no canonical writer.
    pub fn verify_terminal<F>(
        mut self,
        store: &MdbxStore,
        expected_height: u64,
        expected_hash: [u8; 32],
        expected_chainwork: [u8; 32],
        verifier: F,
    ) -> Result<VerifiedSnapshotHeaderStaging>
    where
        F: FnOnce(&SelectedTerminalHeaderBoundary) -> std::result::Result<(), String>,
    {
        let boundary =
            self.terminal_boundary(store, expected_height, expected_hash, expected_chainwork)?;
        verifier(&boundary).map_err(SnapshotHeaderStagingError::TerminalRejected)?;

        // Terminal verification can be expensive.  Treat the file as
        // untrusted again afterwards: validate every record, re-derive both
        // terminal header inputs, and require exact equality with what the
        // verifier saw.  Only then replace our writable descriptor with a
        // read-only O_NOFOLLOW descriptor for the same inode.
        self.revalidate_complete_file(store)?;
        let revalidated = self.terminal_boundary(
            store,
            boundary.tip_header.height,
            boundary.tip_hash,
            boundary.cumulative_chainwork,
        )?;
        ensure_exact_terminal_boundary(&boundary, &revalidated)?;

        let writable_identity = StagingFileIdentity::capture(&self.file)?;
        let expected_len = staged_file_len(self.count)?;
        if writable_identity.len != expected_len {
            return Err(SnapshotHeaderStagingError::VerifiedFileChanged(
                "staging length changed before read-only sealing",
            ));
        }
        let read_only = secure_open_existing_read_only(&self.path)?;
        let read_only_identity = StagingFileIdentity::capture(&read_only)?;
        if !writable_identity.same_file(&read_only_identity)
            || read_only_identity.len != writable_identity.len
        {
            return Err(SnapshotHeaderStagingError::VerifiedFileChanged(
                "staging path no longer names the verified inode and length",
            ));
        }
        self.file = read_only;

        // Revalidate through the descriptor that promotion will actually use.
        // This closes the path-reopen interval and drops the last writable
        // descriptor owned by the node before promotable typestate exists.
        self.revalidate_complete_file(store)?;
        let sealed_boundary = self.terminal_boundary(
            store,
            boundary.tip_header.height,
            boundary.tip_hash,
            boundary.cumulative_chainwork,
        )?;
        ensure_exact_terminal_boundary(&boundary, &sealed_boundary)?;
        let sealed_identity = StagingFileIdentity::capture(&self.file)?;
        if sealed_identity != read_only_identity {
            return Err(SnapshotHeaderStagingError::VerifiedFileChanged(
                "staging metadata changed while sealing",
            ));
        }
        Ok(VerifiedSnapshotHeaderStaging {
            staging: self,
            boundary,
            file_identity: sealed_identity,
        })
    }

    /// Explicitly destroy a rejected or superseded candidate.
    pub fn discard(self) -> Result<()> {
        let identity = StagingFileIdentity::capture(&self.file)?;
        let path = self.path.clone();
        drop(self);
        remove_staging_file_if_same(&path, identity)
    }

    fn tip_record(&mut self) -> Result<StagedHeaderRecord> {
        if self.count == 0 {
            return Ok(StagedHeaderRecord {
                header: self.base.header,
                block_hash: self.base.block_hash,
                cumulative_chainwork: self.base.cumulative_chainwork,
            });
        }
        self.read_record(self.count - 1)
    }

    fn read_record(&mut self, index: u64) -> Result<StagedHeaderRecord> {
        if index >= self.count {
            return Err(SnapshotHeaderStagingError::Format(
                "record index is beyond staged suffix",
            ));
        }
        let offset = record_offset(index)?;
        self.file.seek(SeekFrom::Start(offset))?;
        let mut bytes = [0u8; RECORD_SIZE];
        self.file.read_exact(&mut bytes)?;
        decode_record(&bytes)
    }

    fn load_consensus_window(
        &mut self,
        store: &MdbxStore,
        tip_height: u64,
    ) -> Result<VecDeque<BlockHeader>> {
        let max_window = consensus_window_len();
        let start = tip_height.saturating_sub(max_window as u64 - 1);
        let mut window = VecDeque::with_capacity(max_window);
        for height in start..=tip_height {
            let header = self.header_at(store, height)?.ok_or_else(|| {
                SnapshotHeaderStagingError::CanonicalConflict {
                    height,
                    reason: "header needed by the bounded consensus window is missing".into(),
                }
            })?;
            window.push_back(header);
        }
        Ok(window)
    }

    fn revalidate_complete_file(&mut self, store: &MdbxStore) -> Result<()> {
        self.base.validate_against(store)?;
        let identity = StagingFileIdentity::capture(&self.file)?;
        if identity.len != staged_file_len(self.count)? {
            return Err(SnapshotHeaderStagingError::VerifiedFileChanged(
                "staging file has an appended or partial record",
            ));
        }
        let encoded_base = read_file_header(&mut self.file)?;
        if encoded_base.height != self.base.header.height
            || encoded_base.block_hash != self.base.block_hash
            || encoded_base.cumulative_chainwork != self.base.cumulative_chainwork
        {
            return Err(SnapshotHeaderStagingError::CanonicalConflict {
                height: self.base.header.height,
                reason: "staging file base header changed".into(),
            });
        }
        let mut window = self.load_canonical_window(store)?;
        let mut previous_work = self.base.cumulative_chainwork;
        let mut expected_height = self.base.header.height + 1;
        for index in 0..self.count {
            let record = self.read_record(index)?;
            validate_next_header(&record.header, expected_height, &window)?;
            if hash_block_header(&record.header) != record.block_hash {
                return Err(SnapshotHeaderStagingError::InvalidCandidate {
                    height: expected_height,
                    reason: "record hash does not match header".into(),
                });
            }
            let expected_work = add_work(
                &previous_work,
                &block_work(&record.header.difficulty_target),
            );
            if record.cumulative_chainwork != expected_work {
                return Err(SnapshotHeaderStagingError::InvalidCandidate {
                    height: expected_height,
                    reason: "record does not contain exact cumulative chainwork".into(),
                });
            }
            previous_work = expected_work;
            push_window(&mut window, record.header);
            expected_height =
                expected_height
                    .checked_add(1)
                    .ok_or(SnapshotHeaderStagingError::Format(
                        "candidate height overflow",
                    ))?;
        }
        Ok(())
    }

    fn load_canonical_window(&self, store: &MdbxStore) -> Result<VecDeque<BlockHeader>> {
        let max_window = consensus_window_len();
        let start = self
            .base
            .header
            .height
            .saturating_sub(max_window as u64 - 1);
        let mut window = VecDeque::with_capacity(max_window);
        for height in start..=self.base.header.height {
            let header = store
                .get_header(height)
                .map_err(store_error)?
                .ok_or_else(|| SnapshotHeaderStagingError::CanonicalConflict {
                    height,
                    reason: "canonical consensus-window header is missing".into(),
                })?;
            window.push_back(header);
        }
        Ok(window)
    }
}

/// A stage for which selected-terminal verification has succeeded.  No public
/// constructor exists, so canonical promotion cannot be reached through the
/// ordinary unverified staging path.
pub struct VerifiedSnapshotHeaderStaging {
    staging: SnapshotHeaderStaging,
    boundary: SelectedTerminalHeaderBoundary,
    file_identity: StagingFileIdentity,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HeaderPromotionReport {
    pub already_canonical: u64,
    pub promoted: u64,
}

impl VerifiedSnapshotHeaderStaging {
    pub fn boundary(&self) -> SelectedTerminalHeaderBoundary {
        self.boundary
    }

    /// Promote the authenticated suffix through fixed-size atomic MDBX
    /// batches.  The staging file is streamed and never materialized as one
    /// chain-sized vector.  Every batch independently checks its exact
    /// existing prefix, parent link, cumulative work, hash index and anchor;
    /// a crash or later conflict therefore leaves only an authenticated
    /// prefix and retry is idempotent.
    ///
    /// The caller must serialize this operation with normal canonical-chain
    /// mutation (the daemon does so with its chain write guard).
    pub fn promote(&mut self, store: &MdbxStore) -> Result<HeaderPromotionReport> {
        self.assert_file_unchanged_before_read()?;
        self.staging.revalidate_complete_file(store)?;
        let current_boundary = self.staging.terminal_boundary(
            store,
            self.boundary.tip_header.height,
            self.boundary.tip_hash,
            self.boundary.cumulative_chainwork,
        )?;
        ensure_exact_terminal_boundary(&self.boundary, &current_boundary)?;
        self.assert_file_unchanged_before_read()?;
        let mut report = HeaderPromotionReport::default();
        let mut next_index = 0u64;
        while next_index < self.staging.count {
            self.assert_file_unchanged_before_read()?;
            let remaining = self.staging.count - next_index;
            let batch_len = remaining.min(MAX_VERIFIED_HEADER_BATCH_RECORDS as u64) as usize;
            let mut batch = Vec::with_capacity(batch_len);
            for offset in 0..batch_len {
                let record = self.staging.read_record(next_index + offset as u64)?;
                batch.push(VerifiedHeaderBatchRecord {
                    header: record.header,
                    hash: record.block_hash,
                    cumulative_chainwork: record.cumulative_chainwork,
                });
            }
            self.assert_file_unchanged_before_read()?;
            let outcome =
                store
                    .put_verified_headers_batch(&batch)
                    .map_err(|error| match error {
                        StoreError::Decode(reason) => {
                            SnapshotHeaderStagingError::CanonicalConflict {
                                height: batch[0].header.height,
                                reason: reason.to_owned(),
                            }
                        }
                        other => store_error(other),
                    })?;
            report.already_canonical = report
                .already_canonical
                .checked_add(outcome.existing as u64)
                .ok_or(SnapshotHeaderStagingError::Format(
                    "header promotion report overflow",
                ))?;
            report.promoted = report.promoted.checked_add(outcome.promoted as u64).ok_or(
                SnapshotHeaderStagingError::Format("header promotion report overflow"),
            )?;
            next_index += batch_len as u64;
        }
        Ok(report)
    }

    pub fn discard(self) -> Result<()> {
        self.staging.discard()
    }

    fn assert_file_unchanged_before_read(&self) -> Result<()> {
        let current = StagingFileIdentity::capture(&self.staging.file)?;
        if current != self.file_identity {
            return Err(SnapshotHeaderStagingError::VerifiedFileChanged(
                "verified descriptor identity or length changed",
            ));
        }
        Ok(())
    }
}

fn ensure_exact_terminal_boundary(
    authenticated: &SelectedTerminalHeaderBoundary,
    current: &SelectedTerminalHeaderBoundary,
) -> Result<()> {
    if authenticated != current {
        return Err(SnapshotHeaderStagingError::VerifiedFileChanged(
            "tip header/hash/work or transaction-epoch header changed",
        ));
    }
    Ok(())
}

fn validate_next_header(
    header: &BlockHeader,
    expected_height: u64,
    window: &VecDeque<BlockHeader>,
) -> Result<()> {
    if header.height != expected_height {
        return Err(SnapshotHeaderStagingError::InvalidCandidate {
            height: header.height,
            reason: format!("expected contiguous h={expected_height}"),
        });
    }
    let parent = window
        .back()
        .ok_or(SnapshotHeaderStagingError::Format("empty consensus window"))?;
    let timestamp_start = window.len().saturating_sub(MEDIAN_TIME_BLOCKS);
    let timestamp_len = window.len() - timestamp_start;
    let mut prev_timestamps = [0u64; MEDIAN_TIME_BLOCKS];
    for (slot, ancestor) in prev_timestamps
        .iter_mut()
        .zip(window.iter().skip(timestamp_start))
    {
        *slot = ancestor.timestamp;
    }
    let expansion_len = usize::try_from(EXPANSION_WINDOW)
        .unwrap_or(usize::MAX)
        .min(window.len());
    let active_start = window.len() - expansion_len;
    let mut prev_active_counts = [0u64; EXPANSION_WINDOW as usize];
    for (slot, ancestor) in prev_active_counts
        .iter_mut()
        .zip(window.iter().skip(active_start))
    {
        *slot = ancestor.active_slot_count;
    }
    let anchor_height = asert_anchor_height(parent.height);
    let anchor = window
        .iter()
        .find(|ancestor| ancestor.height == anchor_height)
        .ok_or(SnapshotHeaderStagingError::InvalidCandidate {
            height: header.height,
            reason: format!("ASERT anchor h={anchor_height} is outside the validated window"),
        })?;
    validate_header_timeless(
        header,
        parent,
        &prev_timestamps[..timestamp_len],
        &prev_active_counts[..expansion_len],
        anchor_height,
        anchor.timestamp,
        &anchor.difficulty_target,
    )
    .map_err(|error| SnapshotHeaderStagingError::InvalidCandidate {
        height: header.height,
        reason: error.to_string(),
    })
}

fn consensus_window_len() -> usize {
    usize::try_from(EXPANSION_WINDOW)
        .unwrap_or(usize::MAX)
        .max(MEDIAN_TIME_BLOCKS)
        .max(usize::try_from(EPOCH_LENGTH).unwrap_or(usize::MAX))
        .max(1)
}

fn push_window(window: &mut VecDeque<BlockHeader>, header: BlockHeader) {
    if window.len() == consensus_window_len() {
        window.pop_front();
    }
    window.push_back(header);
}

fn write_file_header(file: &mut File, base: &CanonicalHeaderBoundary) -> io::Result<()> {
    file.write_all(&FILE_MAGIC)?;
    file.write_all(&FILE_VERSION.to_le_bytes())?;
    file.write_all(&(RECORD_SIZE as u32).to_le_bytes())?;
    file.write_all(&base.header.height.to_le_bytes())?;
    file.write_all(&base.block_hash)?;
    file.write_all(&base.cumulative_chainwork)
}

#[derive(Clone, Copy)]
struct EncodedBase {
    height: u64,
    block_hash: [u8; 32],
    cumulative_chainwork: [u8; 32],
}

fn read_file_header(file: &mut File) -> Result<EncodedBase> {
    file.seek(SeekFrom::Start(0))?;
    let mut bytes = [0u8; FILE_HEADER_SIZE as usize];
    file.read_exact(&mut bytes)?;
    if bytes[..8] != FILE_MAGIC {
        return Err(SnapshotHeaderStagingError::Format("bad file magic"));
    }
    if u32::from_le_bytes(bytes[8..12].try_into().expect("fixed range")) != FILE_VERSION {
        return Err(SnapshotHeaderStagingError::Format(
            "unsupported file version",
        ));
    }
    if u32::from_le_bytes(bytes[12..16].try_into().expect("fixed range")) as usize != RECORD_SIZE {
        return Err(SnapshotHeaderStagingError::Format(
            "record size does not match this build",
        ));
    }
    let height = u64::from_le_bytes(bytes[16..24].try_into().expect("fixed range"));
    let block_hash = bytes[24..56].try_into().expect("fixed range");
    let cumulative_chainwork = bytes[56..88].try_into().expect("fixed range");
    // The header itself is deliberately sourced from canonical MDBX during
    // `open`; only its identity and work are persisted in this untrusted file.
    Ok(EncodedBase {
        height,
        block_hash,
        cumulative_chainwork,
    })
}

fn write_record(file: &mut File, record: &StagedHeaderRecord) -> io::Result<()> {
    file.write_all(&record.header.to_bytes())?;
    file.write_all(&record.block_hash)?;
    file.write_all(&record.cumulative_chainwork)
}

fn decode_record(bytes: &[u8; RECORD_SIZE]) -> Result<StagedHeaderRecord> {
    let header = BlockHeader::from_bytes(&bytes[..BLOCK_HEADER_WIRE_SIZE])
        .map_err(|_| SnapshotHeaderStagingError::Format("record contains an invalid header"))?;
    let block_hash = bytes[BLOCK_HEADER_WIRE_SIZE..BLOCK_HEADER_WIRE_SIZE + 32]
        .try_into()
        .expect("fixed range");
    let cumulative_chainwork = bytes[BLOCK_HEADER_WIRE_SIZE + 32..]
        .try_into()
        .expect("fixed range");
    Ok(StagedHeaderRecord {
        header,
        block_hash,
        cumulative_chainwork,
    })
}

fn record_offset(index: u64) -> Result<u64> {
    FILE_HEADER_SIZE
        .checked_add(
            index
                .checked_mul(RECORD_SIZE as u64)
                .ok_or(SnapshotHeaderStagingError::Format("record offset overflow"))?,
        )
        .ok_or(SnapshotHeaderStagingError::Format("record offset overflow"))
}

fn staged_file_len(count: u64) -> Result<u64> {
    FILE_HEADER_SIZE
        .checked_add(count.checked_mul(RECORD_SIZE as u64).ok_or(
            SnapshotHeaderStagingError::Format("staging file length overflow"),
        )?)
        .ok_or(SnapshotHeaderStagingError::Format(
            "staging file length overflow",
        ))
}

fn store_error(error: impl std::fmt::Display) -> SnapshotHeaderStagingError {
    SnapshotHeaderStagingError::Store(error.to_string())
}

fn secure_create_new(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    options.open(path)
}

fn secure_open_existing(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    options.open(path)
}

fn secure_open_existing_read_only(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    options.open(path)
}

fn remove_staging_file_if_same(path: &Path, expected: StagingFileIdentity) -> Result<()> {
    let current = match secure_open_existing_read_only(path) {
        Ok(file) => StagingFileIdentity::capture(&file)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(SnapshotHeaderStagingError::Io(error)),
    };
    if !expected.same_file(&current) {
        return Err(SnapshotHeaderStagingError::VerifiedFileChanged(
            "cleanup path no longer names the staged inode",
        ));
    }
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(SnapshotHeaderStagingError::Io(error)),
    }
}

fn sync_parent(path: &Path) -> io::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    File::open(parent)?.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn promotion_is_streamed_through_the_storage_batch_cap() {
        assert_eq!(MAX_STAGED_HEADER_BATCH, MAX_VERIFIED_HEADER_BATCH_RECORDS);
        let source = include_str!("snapshot_header_staging.rs");
        let promote = source
            .split("pub fn promote(&mut self, store: &MdbxStore)")
            .nth(1)
            .expect("verified promotion entry point")
            .split("pub fn discard(self)")
            .next()
            .expect("promotion boundary");
        assert!(promote.contains("remaining.min(MAX_VERIFIED_HEADER_BATCH_RECORDS as u64)"));
        assert!(promote.contains("Vec::with_capacity(batch_len)"));
        assert!(promote.contains("put_verified_headers_batch(&batch)"));
        assert!(!promote.contains("put_verified_header_only"));
    }
    use noid_chain::consensus::genesis::genesis_header;
    use noid_chain::consensus::next_target;
    use noid_chain::consensus::params::BLOCK_TIME;
    use std::sync::OnceLock;

    fn fixture_chain() -> &'static [BlockHeader] {
        static HEADERS: OnceLock<Vec<BlockHeader>> = OnceLock::new();
        HEADERS.get_or_init(|| {
            let mut headers = vec![genesis_header()];
            for height in 1..=1u64 {
                let parent = *headers.last().expect("genesis");
                let anchor_height = asert_anchor_height(parent.height);
                let anchor = headers
                    .iter()
                    .find(|header| header.height == anchor_height)
                    .expect("short fixture anchor");
                let timestamp = parent.timestamp + BLOCK_TIME;
                let header = BlockHeader {
                    prev_block_hash: hash_block_header(&parent),
                    state_root: [height as u8; 32],
                    tx_root: [0x40 + height as u8; 32],
                    timestamp,
                    height,
                    miner_address: parent.miner_address,
                    // Pre-mined for this exact deterministic fixture. Keeping
                    // it fixed avoids debug-mode PoW work in CI. Re-mined for
                    // the `attested_coverage` header layout via the ignored
                    // `print_new_fixture_nonce` test below.
                    nonce: 106_729,
                    difficulty_target: next_target(
                        anchor_height,
                        anchor.timestamp,
                        &anchor.difficulty_target,
                        height,
                        timestamp,
                    ),
                    log_slots: parent.log_slots,
                    active_slot_count: parent.active_slot_count,
                    alloc_counter: parent.alloc_counter,
                    attested_coverage: 0,
                };
                headers.push(header);
            }
            headers
        })
    }

    /// Print a fresh pre-mined nonce for `fixture_chain` after header-layout
    /// changes. Run with:
    /// `cargo test --release -p noid_node print_new_fixture_nonce -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn print_new_fixture_nonce() {
        let mut header = fixture_chain()[1];
        header.nonce = 0;
        let nonce = noid_chain::consensus::pow::search_pow(&header, 0, 2_000_000_000)
            .expect("fixture target is satisfiable");
        println!("\nNew fixture nonce: {nonce}");
    }

    fn canonical_base(store: &MdbxStore) -> CanonicalHeaderBoundary {
        let genesis = genesis_header();
        let hash = hash_block_header(&genesis);
        let work = block_work(&genesis.difficulty_target);
        store
            .put_verified_header_only(&genesis, &hash, &work)
            .expect("persist fixture genesis");
        CanonicalHeaderBoundary::load(store, 0).expect("load base")
    }

    #[test]
    fn invalid_late_header_does_not_partially_append_batch() {
        let db = tempfile::tempdir().unwrap();
        let stage_dir = tempfile::tempdir().unwrap();
        let store = MdbxStore::open(db.path()).unwrap();
        let base = canonical_base(&store);
        let mut staging =
            SnapshotHeaderStaging::create(&stage_dir.path().join("candidate"), &store, base)
                .unwrap();
        let mut bad_second = fixture_chain()[1];
        bad_second.height = 2;
        bad_second.timestamp += BLOCK_TIME;
        bad_second.prev_block_hash = [0xAA; 32];
        assert!(staging
            .append_batch(&store, &[fixture_chain()[1], bad_second])
            .is_err());
        assert_eq!(staging.staged_len(), 0);
        assert!(store.get_header(1).unwrap().is_none());
    }

    #[test]
    fn restart_recovers_complete_prefix_and_truncates_partial_tail() {
        let db = tempfile::tempdir().unwrap();
        let stage_dir = tempfile::tempdir().unwrap();
        let path = stage_dir.path().join("candidate");
        let store = MdbxStore::open(db.path()).unwrap();
        let base = canonical_base(&store);
        {
            let mut staging = SnapshotHeaderStaging::create(&path, &store, base).unwrap();
            staging
                .append_batch(&store, &fixture_chain()[1..=1])
                .unwrap();
        }
        {
            let mut file = OpenOptions::new().append(true).open(&path).unwrap();
            file.write_all(&[0xCC; 17]).unwrap();
            file.sync_all().unwrap();
        }
        let reopened = SnapshotHeaderStaging::open(&path, &store).unwrap();
        assert_eq!(reopened.staged_len(), 1);
        assert_eq!(reopened.next_height().unwrap(), 2);
    }

    #[test]
    fn adversarial_fork_cannot_replace_canonical_header_on_promotion() {
        let db = tempfile::tempdir().unwrap();
        let stage_dir = tempfile::tempdir().unwrap();
        let store = MdbxStore::open(db.path()).unwrap();
        let base = canonical_base(&store);
        let mut staging =
            SnapshotHeaderStaging::create(&stage_dir.path().join("candidate"), &store, base)
                .unwrap();
        staging
            .append_batch(&store, &fixture_chain()[1..=1])
            .unwrap();
        let tip = staging.tip_record().unwrap();
        let mut verified = staging
            .verify_terminal(
                &store,
                tip.header.height,
                tip.block_hash,
                tip.cumulative_chainwork,
                |_| Ok(()),
            )
            .unwrap();

        let mut conflicting = fixture_chain()[1];
        conflicting.state_root = [0xFE; 32];
        let conflicting_hash = hash_block_header(&conflicting);
        let conflicting_work = add_work(
            &base.cumulative_chainwork,
            &block_work(&conflicting.difficulty_target),
        );
        store
            .put_verified_header_only(&conflicting, &conflicting_hash, &conflicting_work)
            .unwrap();

        assert!(matches!(
            verified.promote(&store),
            Err(SnapshotHeaderStagingError::CanonicalConflict { height: 1, .. })
        ));
        assert_eq!(store.get_header(1).unwrap(), Some(conflicting));
        assert!(store.get_header(2).unwrap().is_none());
    }

    #[test]
    fn rejected_terminal_has_no_canonical_write_path() {
        let db = tempfile::tempdir().unwrap();
        let stage_dir = tempfile::tempdir().unwrap();
        let store = MdbxStore::open(db.path()).unwrap();
        let base = canonical_base(&store);
        let mut staging =
            SnapshotHeaderStaging::create(&stage_dir.path().join("candidate"), &store, base)
                .unwrap();
        staging
            .append_batch(&store, &fixture_chain()[1..=1])
            .unwrap();
        let tip = staging.tip_record().unwrap();

        assert!(matches!(
            staging.verify_terminal(
                &store,
                tip.header.height,
                tip.block_hash,
                tip.cumulative_chainwork,
                |_| Err("synthetic selected-terminal failure".into()),
            ),
            Err(SnapshotHeaderStagingError::TerminalRejected(_))
        ));
        assert!(store.get_header(1).unwrap().is_none());
        assert!(store.get_chain_work(1).unwrap().is_none());
    }

    #[test]
    fn tampered_valid_looking_tip_after_terminal_cannot_promote() {
        let db = tempfile::tempdir().unwrap();
        let stage_dir = tempfile::tempdir().unwrap();
        let path = stage_dir.path().join("candidate");
        let store = MdbxStore::open(db.path()).unwrap();
        let base = canonical_base(&store);
        let mut staging = SnapshotHeaderStaging::create(&path, &store, base).unwrap();
        staging
            .append_batch(&store, &fixture_chain()[1..=1])
            .unwrap();
        let tip = staging.tip_record().unwrap();
        let mut verified = staging
            .verify_terminal(
                &store,
                tip.header.height,
                tip.block_hash,
                tip.cumulative_chainwork,
                |_| Ok(()),
            )
            .unwrap();

        // The replacement is a complete, parseable fixed-size record with a
        // self-consistent header hash.  It is nevertheless not the exact
        // terminal-authenticated tip and must never reach canonical storage.
        let mut changed_header = fixture_chain()[1];
        changed_header.state_root = [0xA5; 32];
        let changed = StagedHeaderRecord {
            header: changed_header,
            block_hash: hash_block_header(&changed_header),
            cumulative_chainwork: tip.cumulative_chainwork,
        };
        let mut writer = OpenOptions::new().write(true).open(&path).unwrap();
        writer
            .seek(SeekFrom::Start(record_offset(0).unwrap()))
            .unwrap();
        write_record(&mut writer, &changed).unwrap();
        writer.sync_all().unwrap();
        drop(writer);

        assert!(verified.promote(&store).is_err());
        assert!(store.get_header(1).unwrap().is_none());
        assert!(store.get_chain_work(1).unwrap().is_none());
    }

    #[test]
    fn terminal_transition_revalidates_file_after_verifier_returns() {
        let db = tempfile::tempdir().unwrap();
        let stage_dir = tempfile::tempdir().unwrap();
        let path = stage_dir.path().join("candidate");
        let store = MdbxStore::open(db.path()).unwrap();
        let base = canonical_base(&store);
        let mut staging = SnapshotHeaderStaging::create(&path, &store, base).unwrap();
        staging
            .append_batch(&store, &fixture_chain()[1..=1])
            .unwrap();
        let tip = staging.tip_record().unwrap();

        let result = staging.verify_terminal(
            &store,
            tip.header.height,
            tip.block_hash,
            tip.cumulative_chainwork,
            |_| {
                let mut writer = OpenOptions::new().append(true).open(&path).unwrap();
                writer.write_all(&[0xDD; 9]).unwrap();
                writer.sync_all().unwrap();
                Ok(())
            },
        );
        assert!(matches!(
            result,
            Err(SnapshotHeaderStagingError::VerifiedFileChanged(_))
        ));
        assert!(store.get_header(1).unwrap().is_none());
        assert!(store.get_chain_work(1).unwrap().is_none());
    }

    #[test]
    fn appended_partial_record_after_terminal_cannot_promote() {
        let db = tempfile::tempdir().unwrap();
        let stage_dir = tempfile::tempdir().unwrap();
        let path = stage_dir.path().join("candidate");
        let store = MdbxStore::open(db.path()).unwrap();
        let base = canonical_base(&store);
        let mut staging = SnapshotHeaderStaging::create(&path, &store, base).unwrap();
        staging
            .append_batch(&store, &fixture_chain()[1..=1])
            .unwrap();
        let tip = staging.tip_record().unwrap();
        let mut verified = staging
            .verify_terminal(
                &store,
                tip.header.height,
                tip.block_hash,
                tip.cumulative_chainwork,
                |_| Ok(()),
            )
            .unwrap();

        let mut writer = OpenOptions::new().append(true).open(&path).unwrap();
        writer.write_all(&[0xCC; 17]).unwrap();
        writer.sync_all().unwrap();
        drop(writer);

        assert!(matches!(
            verified.promote(&store),
            Err(SnapshotHeaderStagingError::VerifiedFileChanged(_))
        ));
        assert!(store.get_header(1).unwrap().is_none());
    }

    #[test]
    fn appended_complete_record_after_terminal_cannot_promote() {
        let db = tempfile::tempdir().unwrap();
        let stage_dir = tempfile::tempdir().unwrap();
        let path = stage_dir.path().join("candidate");
        let store = MdbxStore::open(db.path()).unwrap();
        let base = canonical_base(&store);
        let mut staging = SnapshotHeaderStaging::create(&path, &store, base).unwrap();
        staging
            .append_batch(&store, &fixture_chain()[1..=1])
            .unwrap();
        let tip = staging.tip_record().unwrap();
        let mut verified = staging
            .verify_terminal(
                &store,
                tip.header.height,
                tip.block_hash,
                tip.cumulative_chainwork,
                |_| Ok(()),
            )
            .unwrap();

        let mut writer = OpenOptions::new().append(true).open(&path).unwrap();
        write_record(&mut writer, &tip).unwrap();
        writer.sync_all().unwrap();
        drop(writer);

        assert!(matches!(
            verified.promote(&store),
            Err(SnapshotHeaderStagingError::VerifiedFileChanged(_))
        ));
        assert!(store.get_header(1).unwrap().is_none());
    }

    #[test]
    fn changed_epoch_boundary_after_terminal_cannot_promote() {
        let db = tempfile::tempdir().unwrap();
        let stage_dir = tempfile::tempdir().unwrap();
        let path = stage_dir.path().join("candidate");
        let store = MdbxStore::open(db.path()).unwrap();
        let base = canonical_base(&store);
        let mut staging = SnapshotHeaderStaging::create(&path, &store, base).unwrap();
        staging
            .append_batch(&store, &fixture_chain()[1..=1])
            .unwrap();
        let tip = staging.tip_record().unwrap();
        let mut verified = staging
            .verify_terminal(
                &store,
                tip.header.height,
                tip.block_hash,
                tip.cumulative_chainwork,
                |_| Ok(()),
            )
            .unwrap();

        // Exercise the exact four-field reseal check independently of record
        // validation: even an epoch header with the right height is distinct
        // authority and cannot be silently substituted.
        verified.boundary.epoch_anchor_header.state_root = [0xE0; 32];
        assert!(matches!(
            verified.promote(&store),
            Err(SnapshotHeaderStagingError::VerifiedFileChanged(_))
        ));
        assert!(store.get_header(1).unwrap().is_none());
    }

    #[test]
    fn empty_exact_target_uses_typestate_even_with_canonical_child() {
        let db = tempfile::tempdir().unwrap();
        let stage_dir = tempfile::tempdir().unwrap();
        let store = MdbxStore::open(db.path()).unwrap();
        let genesis_base = canonical_base(&store);
        let child = fixture_chain()[1];
        let child_work = add_work(
            &genesis_base.cumulative_chainwork,
            &block_work(&child.difficulty_target),
        );
        store
            .put_verified_header_only(&child, &hash_block_header(&child), &child_work)
            .unwrap();

        let ordinary =
            SnapshotHeaderStaging::create(&stage_dir.path().join("ordinary"), &store, genesis_base);
        assert!(matches!(
            ordinary,
            Err(SnapshotHeaderStagingError::CanonicalConflict { height: 1, .. })
        ));
        let exact = SnapshotHeaderStaging::create_at_canonical_boundary(
            &stage_dir.path().join("exact"),
            &store,
            genesis_base,
        )
        .unwrap();
        assert_eq!(exact.staged_len(), 0);
        assert_eq!(exact.next_height().unwrap(), 1);
    }

    #[test]
    fn verified_promotion_is_idempotent_and_never_buffers_suffix() {
        let db = tempfile::tempdir().unwrap();
        let stage_dir = tempfile::tempdir().unwrap();
        let path = stage_dir.path().join("candidate");
        let store = MdbxStore::open(db.path()).unwrap();
        let base = canonical_base(&store);
        let mut staging = SnapshotHeaderStaging::create(&path, &store, base).unwrap();
        staging
            .append_batch(&store, &fixture_chain()[1..=1])
            .unwrap();
        let tip = staging.tip_record().unwrap();
        let mut verified = staging
            .verify_terminal(
                &store,
                tip.header.height,
                tip.block_hash,
                tip.cumulative_chainwork,
                |boundary| {
                    assert_eq!(boundary.tip_header, fixture_chain()[1]);
                    assert_eq!(boundary.epoch_anchor_header, genesis_header());
                    Ok(())
                },
            )
            .unwrap();
        assert_eq!(
            verified.promote(&store).unwrap(),
            HeaderPromotionReport {
                already_canonical: 0,
                promoted: 1,
            }
        );

        let reopened = SnapshotHeaderStaging::open(&path, &store).unwrap();
        let tip = fixture_chain()[1];
        let tip_work = store.get_chain_work(1).unwrap().unwrap();
        let mut verified = reopened
            .verify_terminal(&store, 1, hash_block_header(&tip), tip_work, |_| Ok(()))
            .unwrap();
        assert_eq!(
            verified.promote(&store).unwrap(),
            HeaderPromotionReport {
                already_canonical: 1,
                promoted: 0,
            }
        );
    }
}
