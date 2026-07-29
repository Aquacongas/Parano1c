// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Disk-backed accepted-bundle tail for finalized snapshot synchronization.
//!
//! A snapshot generation owns the immutable bundles immediately following its
//! finalized state boundary. The receiver seals those bundles, then any newer
//! live suffix, into this append-only file before downloading state segments.
//! Snapshot installation can therefore replay the exact suffix even after the
//! serving node's ordinary retained-block window has advanced.

use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, Read, Seek, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use noid_chain::{
    AcceptedBlockBundle, Block, ACCEPTED_BLOCK_BUNDLE_HEADER_BYTES, ACCEPTED_BLOCK_BUNDLE_MAGIC,
    MAX_ACCEPTED_BLOCK_BUNDLE_BYTES,
};

const FILE_MAGIC: [u8; 4] = *b"NST2";
const FILE_HEADER_BYTES: u64 = 4 + 8 + 32 + 32;
const RECORD_HEADER_BYTES: u64 = 4;
static NEXT_TAIL_FILE_ID: AtomicU64 = AtomicU64::new(0);

/// Transient, not consensus: enough for hours of full-rate catch-up while
/// bounding hostile disk growth. A client that cannot ingest chain data
/// within this limit restarts from a newer finalized generation.
pub const MAX_SNAPSHOT_TAIL_BYTES: u64 = 512 * 1024 * 1024;
pub const MAX_SNAPSHOT_TAIL_BLOCKS: u64 = 4096;

#[derive(Debug)]
pub struct SnapshotTailStaging {
    path: PathBuf,
    boundary_height: u64,
    boundary_hash: [u8; 32],
    boundary_chainwork: [u8; 32],
    tip_height: u64,
    tip_hash: [u8; 32],
    tip_chainwork: [u8; 32],
    block_count: u64,
    payload_bytes: u64,
    armed: bool,
}

#[derive(Debug)]
pub struct FinalizedSnapshotTail {
    path: PathBuf,
    boundary_height: u64,
    boundary_hash: [u8; 32],
    boundary_chainwork: [u8; 32],
    tip_height: u64,
    tip_hash: [u8; 32],
    block_count: u64,
    payload_bytes: u64,
    armed: bool,
}

pub struct SnapshotTailReader {
    reader: BufReader<File>,
    next_height: u64,
    previous_hash: [u8; 32],
    expected_tip_height: u64,
    expected_tip_hash: [u8; 32],
    remaining: u64,
    remaining_payload_bytes: u64,
}

impl SnapshotTailStaging {
    pub fn create(
        root: &Path,
        boundary_height: u64,
        boundary_hash: [u8; 32],
        boundary_chainwork: [u8; 32],
    ) -> Result<Self, String> {
        fs::create_dir_all(root).map_err(|error| format!("create tail staging root: {error}"))?;
        // A reset can abandon an append worker while a fresh sync for the same
        // boundary starts. Give every in-process session a distinct path so
        // the stale handle's Drop can never unlink the replacement file.
        let file_id = NEXT_TAIL_FILE_ID.fetch_add(1, Ordering::Relaxed);
        let path = root.join(format!(
            "tail-{boundary_height:020}-{}-{file_id:016x}.bin",
            short_hash(boundary_hash)
        ));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|error| format!("create tail staging file: {error}"))?;
        file.write_all(&FILE_MAGIC)
            .and_then(|()| file.write_all(&boundary_height.to_le_bytes()))
            .and_then(|()| file.write_all(&boundary_hash))
            .and_then(|()| file.write_all(&boundary_chainwork))
            .and_then(|()| file.sync_all())
            .map_err(|error| format!("seal tail staging header: {error}"))?;
        sync_parent(&path).map_err(|error| format!("sync tail staging directory: {error}"))?;
        Ok(Self {
            path,
            boundary_height,
            boundary_hash,
            boundary_chainwork,
            tip_height: boundary_height,
            tip_hash: boundary_hash,
            tip_chainwork: boundary_chainwork,
            block_count: 0,
            payload_bytes: 0,
            armed: true,
        })
    }

    pub fn next_height(&self) -> u64 {
        self.tip_height.saturating_add(1)
    }

    pub fn tip_height(&self) -> u64 {
        self.tip_height
    }

    pub fn tip_hash(&self) -> [u8; 32] {
        self.tip_hash
    }

    pub fn tip_chainwork(&self) -> [u8; 32] {
        self.tip_chainwork
    }

    pub fn block_count(&self) -> u64 {
        self.block_count
    }

    pub fn payload_bytes(&self) -> u64 {
        self.payload_bytes
    }

    pub fn append(mut self, bundle: AcceptedBlockBundle) -> Result<Self, String> {
        let height = bundle.height();
        if height != self.next_height() {
            return Err(format!(
                "tail bundle height {height} does not follow {}",
                self.tip_height
            ));
        }
        let block = Block::from_bytes(bundle.block_bytes())
            .map_err(|error| format!("decode tail block {height}: {error:?}"))?;
        if block.header.height != height || block.header.prev_block_hash != self.tip_hash {
            return Err(format!("tail block {height} is not linked to staged tip"));
        }
        if bundle.block_hash() != noid_chain::hash_block_header(&block.header) {
            return Err(format!("tail block {height} hash is inconsistent"));
        }
        let block_len = bundle.block_bytes().len();
        let terminal_len = bundle.history_step_terminal_bytes().len();
        let encoded_len = ACCEPTED_BLOCK_BUNDLE_HEADER_BYTES
            .checked_add(block_len)
            .and_then(|length| length.checked_add(terminal_len))
            .ok_or_else(|| format!("tail block {height} length overflows"))?;
        if encoded_len > MAX_ACCEPTED_BLOCK_BUNDLE_BYTES {
            return Err(format!(
                "tail block {height} exceeds accepted-bundle bounds"
            ));
        }
        let encoded_len_u32 = u32::try_from(encoded_len)
            .map_err(|_| format!("tail block {height} length does not fit u32"))?;
        let block_len_u32 = u32::try_from(block_len)
            .map_err(|_| format!("tail block {height} block length does not fit u32"))?;
        let terminal_len_u32 = u32::try_from(terminal_len)
            .map_err(|_| format!("tail block {height} terminal length does not fit u32"))?;
        let next_count = self
            .block_count
            .checked_add(1)
            .ok_or_else(|| "tail block counter overflow".to_string())?;
        let next_bytes = self
            .payload_bytes
            .checked_add(encoded_len as u64)
            .ok_or_else(|| "tail byte counter overflow".to_string())?;
        if next_count > MAX_SNAPSHOT_TAIL_BLOCKS || next_bytes > MAX_SNAPSHOT_TAIL_BYTES {
            return Err("snapshot live-tail staging limit exceeded".to_string());
        }

        let mut file = OpenOptions::new()
            .append(true)
            .open(&self.path)
            .map_err(|error| format!("open tail staging append: {error}"))?;
        // The entire staging root is discarded after a process restart, so a
        // per-block fsync buys no recovery. Seal once in `finalize` instead.
        file.write_all(&encoded_len_u32.to_le_bytes())
            .and_then(|()| file.write_all(&ACCEPTED_BLOCK_BUNDLE_MAGIC))
            .and_then(|()| file.write_all(&block_len_u32.to_le_bytes()))
            .and_then(|()| file.write_all(&terminal_len_u32.to_le_bytes()))
            .and_then(|()| file.write_all(bundle.block_bytes()))
            .and_then(|()| file.write_all(bundle.history_step_terminal_bytes()))
            .map_err(|error| format!("append tail block {height}: {error}"))?;

        self.tip_height = height;
        self.tip_hash = bundle.block_hash();
        self.tip_chainwork = noid_chain::add_work(
            &self.tip_chainwork,
            &noid_chain::block_work(&block.header.difficulty_target),
        );
        self.block_count = next_count;
        self.payload_bytes = next_bytes;
        Ok(self)
    }

    pub fn finalize(mut self) -> Result<FinalizedSnapshotTail, String> {
        File::open(&self.path)
            .and_then(|file| file.sync_all())
            .map_err(|error| format!("finalize snapshot tail: {error}"))?;
        self.armed = false;
        Ok(FinalizedSnapshotTail {
            path: self.path.clone(),
            boundary_height: self.boundary_height,
            boundary_hash: self.boundary_hash,
            boundary_chainwork: self.boundary_chainwork,
            tip_height: self.tip_height,
            tip_hash: self.tip_hash,
            block_count: self.block_count,
            payload_bytes: self.payload_bytes,
            armed: true,
        })
    }
}

impl FinalizedSnapshotTail {
    pub fn boundary_height(&self) -> u64 {
        self.boundary_height
    }

    pub fn boundary_hash(&self) -> [u8; 32] {
        self.boundary_hash
    }

    pub fn tip_height(&self) -> u64 {
        self.tip_height
    }

    pub fn tip_hash(&self) -> [u8; 32] {
        self.tip_hash
    }

    pub fn block_count(&self) -> u64 {
        self.block_count
    }

    pub fn payload_bytes(&self) -> u64 {
        self.payload_bytes
    }

    pub fn reader(&self) -> Result<SnapshotTailReader, String> {
        let mut file =
            File::open(&self.path).map_err(|error| format!("open finalized tail: {error}"))?;
        let mut header = [0u8; FILE_HEADER_BYTES as usize];
        file.read_exact(&mut header)
            .map_err(|error| format!("read finalized tail header: {error}"))?;
        if header[..4] != FILE_MAGIC
            || u64::from_le_bytes(header[4..12].try_into().unwrap()) != self.boundary_height
            || header[12..44] != self.boundary_hash
            || header[44..76] != self.boundary_chainwork
        {
            return Err("finalized tail header does not match its session".to_string());
        }
        Ok(SnapshotTailReader {
            reader: BufReader::new(file),
            next_height: self.boundary_height.saturating_add(1),
            previous_hash: self.boundary_hash,
            expected_tip_height: self.tip_height,
            expected_tip_hash: self.tip_hash,
            remaining: self.block_count,
            remaining_payload_bytes: self.payload_bytes,
        })
    }
}

impl SnapshotTailReader {
    pub fn next_bundle(&mut self) -> Result<Option<AcceptedBlockBundle>, String> {
        if self.remaining == 0 {
            if self.remaining_payload_bytes != 0 {
                return Err("finalized tail byte accounting did not close".to_string());
            }
            if self.next_height.saturating_sub(1) != self.expected_tip_height
                || self.previous_hash != self.expected_tip_hash
            {
                return Err("finalized tail does not end at its sealed tip".to_string());
            }
            let position = self
                .reader
                .stream_position()
                .map_err(|error| format!("inspect finalized tail position: {error}"))?;
            let length = self
                .reader
                .get_ref()
                .metadata()
                .map_err(|error| format!("inspect finalized tail length: {error}"))?
                .len();
            if position != length {
                return Err("finalized tail contains trailing bytes".to_string());
            }
            return Ok(None);
        }

        let mut encoded_len = [0u8; RECORD_HEADER_BYTES as usize];
        self.reader
            .read_exact(&mut encoded_len)
            .map_err(|error| format!("read tail record length: {error}"))?;
        let encoded_len = u32::from_le_bytes(encoded_len) as usize;
        if encoded_len == 0 || encoded_len > MAX_ACCEPTED_BLOCK_BUNDLE_BYTES {
            return Err("finalized tail record length is outside bounds".to_string());
        }
        if encoded_len as u64 > self.remaining_payload_bytes {
            return Err("finalized tail record exceeds byte accounting".to_string());
        }
        let mut bundle_header = [0u8; ACCEPTED_BLOCK_BUNDLE_HEADER_BYTES];
        self.reader
            .read_exact(&mut bundle_header)
            .map_err(|error| format!("read finalized tail bundle header: {error}"))?;
        if bundle_header[..4] != ACCEPTED_BLOCK_BUNDLE_MAGIC {
            return Err("finalized tail bundle has invalid magic".to_string());
        }
        let block_len = u32::from_le_bytes(bundle_header[4..8].try_into().unwrap()) as usize;
        let terminal_len = u32::from_le_bytes(bundle_header[8..12].try_into().unwrap()) as usize;
        let payload_len =
            AcceptedBlockBundle::validate_declared_lengths(block_len as u64, terminal_len as u64)
                .map_err(|error| format!("decode finalized tail lengths: {error}"))?;
        if ACCEPTED_BLOCK_BUNDLE_HEADER_BYTES
            .checked_add(payload_len)
            .is_none_or(|expected| expected != encoded_len)
        {
            return Err("finalized tail record length is inconsistent".to_string());
        }
        let mut block_bytes = Vec::new();
        block_bytes
            .try_reserve_exact(block_len)
            .map_err(|_| "allocate finalized tail block".to_string())?;
        block_bytes.resize(block_len, 0);
        let mut terminal_bytes = Vec::new();
        terminal_bytes
            .try_reserve_exact(terminal_len)
            .map_err(|_| "allocate finalized tail terminal".to_string())?;
        terminal_bytes.resize(terminal_len, 0);
        self.reader
            .read_exact(&mut block_bytes)
            .and_then(|()| self.reader.read_exact(&mut terminal_bytes))
            .map_err(|error| format!("read finalized tail payload: {error}"))?;
        let bundle = AcceptedBlockBundle::try_from_parts(block_bytes, terminal_bytes)
            .map_err(|error| format!("decode finalized tail bundle: {error}"))?;
        if bundle.height() != self.next_height {
            return Err(format!(
                "finalized tail block {} is outside its staged sequence",
                bundle.height()
            ));
        }
        self.next_height = self.next_height.saturating_add(1);
        self.previous_hash = bundle.block_hash();
        self.remaining -= 1;
        self.remaining_payload_bytes -= encoded_len as u64;
        Ok(Some(bundle))
    }
}

impl Drop for SnapshotTailStaging {
    fn drop(&mut self) {
        if self.armed {
            let _ = fs::remove_file(&self.path);
        }
    }
}

impl Drop for FinalizedSnapshotTail {
    fn drop(&mut self) {
        if self.armed {
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn short_hash(hash: [u8; 32]) -> String {
    let mut out = String::with_capacity(16);
    for byte in hash.iter().take(8) {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn sync_parent(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        File::open(path.parent().unwrap_or_else(|| Path::new(".")))?.sync_all()?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use noid_chain::consensus::genesis::genesis_header;

    fn linked_bundle(parent: &Block, height: u64) -> AcceptedBlockBundle {
        let mut header = parent.header;
        header.height = height;
        header.prev_block_hash = noid_chain::hash_block_header(&parent.header);
        header.timestamp = header.timestamp.saturating_add(15);
        let block = Block {
            header,
            transactions: Vec::new(),
        };
        let mut terminal = noid_chain::HistoryStepTerminalMetadata::new(
            height,
            noid_chain::block_header::semantic_header_id(&block.header),
            0,
        )
        .unwrap()
        .encode_prefix()
        .to_vec();
        terminal.push(1);
        AcceptedBlockBundle::try_from_parts(block.to_bytes(), terminal).unwrap()
    }

    #[test]
    fn empty_tail_round_trips_and_rejects_trailing_bytes() {
        let root = tempfile::tempdir().unwrap();
        let boundary = genesis_header();
        let hash = noid_chain::hash_block_header(&boundary);
        let finalized = SnapshotTailStaging::create(root.path(), 0, hash, [0; 32])
            .unwrap()
            .finalize()
            .unwrap();
        assert!(finalized.reader().unwrap().next_bundle().unwrap().is_none());
        let mut file = OpenOptions::new()
            .append(true)
            .open(&finalized.path)
            .unwrap();
        file.write_all(&[1]).unwrap();
        assert!(finalized.reader().unwrap().next_bundle().is_err());
    }

    #[test]
    fn linked_tail_round_trips_height_hash_and_chainwork() {
        let root = tempfile::tempdir().unwrap();
        let genesis = Block {
            header: genesis_header(),
            transactions: Vec::new(),
        };
        let boundary_hash = noid_chain::hash_block_header(&genesis.header);
        let boundary_work = noid_chain::block_work(&genesis.header.difficulty_target);
        let first = linked_bundle(&genesis, 1);
        let first_block = Block::from_bytes(first.block_bytes()).unwrap();
        let second = linked_bundle(&first_block, 2);
        let expected_work = noid_chain::add_work(
            &noid_chain::add_work(
                &boundary_work,
                &noid_chain::block_work(&first_block.header.difficulty_target),
            ),
            &noid_chain::block_work(
                &Block::from_bytes(second.block_bytes())
                    .unwrap()
                    .header
                    .difficulty_target,
            ),
        );

        let staged = SnapshotTailStaging::create(root.path(), 0, boundary_hash, boundary_work)
            .unwrap()
            .append(first.clone())
            .unwrap()
            .append(second.clone())
            .unwrap();
        assert_eq!(staged.tip_height(), 2);
        assert_eq!(staged.tip_hash(), second.block_hash());
        assert_eq!(staged.tip_chainwork(), expected_work);

        let finalized = staged.finalize().unwrap();
        let mut reader = finalized.reader().unwrap();
        assert_eq!(reader.next_bundle().unwrap(), Some(first));
        assert_eq!(reader.next_bundle().unwrap(), Some(second));
        assert_eq!(reader.next_bundle().unwrap(), None);
    }
}
