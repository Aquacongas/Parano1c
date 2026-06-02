// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Canonical byte serialization for MDBX-persisted chain data (Phase 2, P.18).
//!
//! All formats are little-endian, fixed-width where possible.
//! These are NOT network formats — they are storage-internal and may evolve
//! across software versions (the MDBX file is not portable between major versions).

use noid_core::field::{CanonicalDeserialize, CanonicalSerialize, TowerField};
use noid_core::Block128;

use crate::block_header::BlockHeader;
use crate::consensus::da_prune::BlockUndoLog;
use crate::fri_state::SlotValue;
use crate::segmented_state::SegmentColumns;
use crate::wire::BLOCK_HEADER_WIRE_SIZE;
use noid_poseidon2b::primitives::TxBodyHash;

// ---------------------------------------------------------------------------
// u64 / u32 key helpers
// ---------------------------------------------------------------------------

pub fn u64_key(v: u64) -> [u8; 8] {
    v.to_le_bytes()
}

pub fn u64_from_key(b: &[u8]) -> Option<u64> {
    b.get(..8)?.try_into().ok().map(u64::from_le_bytes)
}

pub fn u32_key(v: u32) -> [u8; 4] {
    v.to_le_bytes()
}

// ---------------------------------------------------------------------------
// BlockHeader
// ---------------------------------------------------------------------------

/// Serialize a `BlockHeader` to exactly `BLOCK_HEADER_WIRE_SIZE` bytes.
pub fn encode_header(h: &BlockHeader) -> Vec<u8> {
    let mut buf = Vec::with_capacity(BLOCK_HEADER_WIRE_SIZE);
    h.encode(&mut buf);
    debug_assert_eq!(buf.len(), BLOCK_HEADER_WIRE_SIZE);
    buf
}

/// Deserialize a `BlockHeader` from bytes.
pub fn decode_header(bytes: &[u8]) -> Option<BlockHeader> {
    BlockHeader::from_bytes(bytes).ok()
}

// ---------------------------------------------------------------------------
// Block128
// ---------------------------------------------------------------------------

fn encode_b128(b: &Block128) -> [u8; 16] {
    let v = b.to_bytes();
    debug_assert_eq!(v.len(), 16);
    v.try_into().unwrap_or([0u8; 16])
}

fn decode_b128(bytes: &[u8; 16]) -> Block128 {
    Block128::deserialize(bytes).unwrap_or(Block128::ZERO)
}

// ---------------------------------------------------------------------------
// SlotValue  (48 bytes)
// ---------------------------------------------------------------------------

pub fn encode_slot_value(sv: &SlotValue) -> [u8; 48] {
    let mut out = [0u8; 48];
    out[0..16].copy_from_slice(&encode_b128(&sv.value));
    out[16..32].copy_from_slice(&encode_b128(&sv.owner_hi));
    out[32..48].copy_from_slice(&encode_b128(&sv.owner_lo));
    out
}

pub fn decode_slot_value(bytes: &[u8]) -> Option<SlotValue> {
    if bytes.len() < 48 {
        return None;
    }
    Some(SlotValue {
        value: decode_b128(bytes[0..16].try_into().ok()?),
        owner_hi: decode_b128(bytes[16..32].try_into().ok()?),
        owner_lo: decode_b128(bytes[32..48].try_into().ok()?),
    })
}

// ---------------------------------------------------------------------------
// BlockUndoLog
// ---------------------------------------------------------------------------
//
// Wire format:
//   block_height : u64 LE  (8 bytes)
//   n_changes    : u32 LE  (4 bytes)
//   [slot_index  : u32 LE  (4 bytes)
//    slot_value  : 48 bytes          ] × n_changes

pub fn encode_undo_log(u: &BlockUndoLog) -> Vec<u8> {
    let mut buf = Vec::with_capacity(16 + u.slot_changes.len() * 52 + u.tx_hashes.len() * 32);
    buf.extend_from_slice(&u.block_height.to_le_bytes());
    buf.extend_from_slice(&(u.slot_changes.len() as u32).to_le_bytes());
    buf.extend_from_slice(&(u.tx_hashes.len() as u32).to_le_bytes());
    for (idx, sv) in &u.slot_changes {
        buf.extend_from_slice(&idx.to_le_bytes());
        buf.extend_from_slice(&encode_slot_value(sv));
    }
    for h in &u.tx_hashes {
        buf.extend_from_slice(&h.0);
    }
    buf
}

pub fn decode_undo_log(bytes: &[u8]) -> Option<BlockUndoLog> {
    if bytes.len() < 16 {
        return None;
    }
    let block_height = u64::from_le_bytes(bytes[0..8].try_into().ok()?);
    let n = u32::from_le_bytes(bytes[8..12].try_into().ok()?) as usize;
    let n_hashes = u32::from_le_bytes(bytes[12..16].try_into().ok()?) as usize;
    let mut slot_changes = Vec::with_capacity(n);
    let mut pos = 16;
    for _ in 0..n {
        if bytes.len() < pos + 52 {
            return None;
        }
        let idx = u32::from_le_bytes(bytes[pos..pos + 4].try_into().ok()?);
        let sv = decode_slot_value(&bytes[pos + 4..pos + 52])?;
        slot_changes.push((idx, sv));
        pos += 52;
    }
    let mut tx_hashes = Vec::with_capacity(n_hashes);
    for _ in 0..n_hashes {
        if bytes.len() < pos + 32 {
            return None;
        }
        let h: [u8; 32] = bytes[pos..pos + 32].try_into().ok()?;
        tx_hashes.push(TxBodyHash(h));
        pos += 32;
    }
    Some(BlockUndoLog {
        block_height,
        slot_changes,
        tx_hashes,
    })
}

// ---------------------------------------------------------------------------
// SegmentColumns
// ---------------------------------------------------------------------------
//
// Wire format:
//   effective_log_seg : u8          (1 byte)
//   n_elems           : u32 LE      (4 bytes) = 2^effective_log_seg
//   values            : n_elems × 16 bytes
//   owners_hi         : n_elems × 16 bytes
//   owners_lo         : n_elems × 16 bytes

pub fn encode_segment(seg: &SegmentColumns, effective_log_seg: u8) -> Vec<u8> {
    let n = seg.values.len();
    debug_assert_eq!(n, seg.owners_hi.len());
    debug_assert_eq!(n, seg.owners_lo.len());
    let mut buf = Vec::with_capacity(5 + n * 3 * 16);
    buf.push(effective_log_seg);
    buf.extend_from_slice(&(n as u32).to_le_bytes());
    for b in &seg.values {
        buf.extend_from_slice(&encode_b128(b));
    }
    for b in &seg.owners_hi {
        buf.extend_from_slice(&encode_b128(b));
    }
    for b in &seg.owners_lo {
        buf.extend_from_slice(&encode_b128(b));
    }
    buf
}

/// Returns `(effective_log_seg, SegmentColumns)`.
pub fn decode_segment(bytes: &[u8]) -> Option<(u8, SegmentColumns)> {
    if bytes.len() < 5 {
        return None;
    }
    let effective_log_seg = bytes[0];
    let n = u32::from_le_bytes(bytes[1..5].try_into().ok()?) as usize;
    let values_end = 5 + n * 16;
    let hi_end = values_end + n * 16;
    let lo_end = hi_end + n * 16;
    if bytes.len() < lo_end {
        return None;
    }
    // Bounds are already verified above (bytes.len() >= lo_end), so unwrap is safe.
    let values = (0..n)
        .map(|i| decode_b128(bytes[5 + i * 16..5 + i * 16 + 16].try_into().unwrap()))
        .collect::<Vec<_>>();
    let owners_hi = (0..n)
        .map(|i| {
            decode_b128(
                bytes[values_end + i * 16..values_end + i * 16 + 16]
                    .try_into()
                    .unwrap(),
            )
        })
        .collect::<Vec<_>>();
    let owners_lo = (0..n)
        .map(|i| {
            decode_b128(
                bytes[hi_end + i * 16..hi_end + i * 16 + 16]
                    .try_into()
                    .unwrap(),
            )
        })
        .collect::<Vec<_>>();
    Some((
        effective_log_seg,
        SegmentColumns {
            values,
            owners_hi,
            owners_lo,
        },
    ))
}

// ---------------------------------------------------------------------------
// TxIndex  (height + position within block)
// ---------------------------------------------------------------------------
//
// Value format:
//   height  : u64 LE  (8 bytes)
//   tx_pos  : u32 LE  (4 bytes)

pub fn encode_tx_index_value(height: u64, tx_pos: u32) -> [u8; 12] {
    let mut out = [0u8; 12];
    out[0..8].copy_from_slice(&height.to_le_bytes());
    out[8..12].copy_from_slice(&tx_pos.to_le_bytes());
    out
}

pub fn decode_tx_index_value(bytes: &[u8]) -> Option<(u64, u32)> {
    if bytes.len() < 12 {
        return None;
    }
    let height = u64::from_le_bytes(bytes[0..8].try_into().ok()?);
    let pos = u32::from_le_bytes(bytes[8..12].try_into().ok()?);
    Some((height, pos))
}

// ---------------------------------------------------------------------------
// Chain meta (tip + state counters)
// ---------------------------------------------------------------------------
//
// chain_tip value: height(u64) + hash([u8;32]) = 40 bytes

pub fn encode_chain_tip(height: u64, hash: &[u8; 32]) -> [u8; 40] {
    let mut out = [0u8; 40];
    out[0..8].copy_from_slice(&height.to_le_bytes());
    out[8..40].copy_from_slice(hash);
    out
}

pub fn decode_chain_tip(bytes: &[u8]) -> Option<(u64, [u8; 32])> {
    if bytes.len() < 40 {
        return None;
    }
    let height = u64::from_le_bytes(bytes[0..8].try_into().ok()?);
    let hash: [u8; 32] = bytes[8..40].try_into().ok()?;
    Some((height, hash))
}

// state_meta value: log_slots(u32) + active_slot_count(u64) + alloc_counter(u64) = 20 bytes

pub fn encode_state_meta(log_slots: u32, active: u64, alloc: u64) -> [u8; 20] {
    let mut out = [0u8; 20];
    out[0..4].copy_from_slice(&log_slots.to_le_bytes());
    out[4..12].copy_from_slice(&active.to_le_bytes());
    out[12..20].copy_from_slice(&alloc.to_le_bytes());
    out
}

pub fn decode_state_meta(bytes: &[u8]) -> Option<(u32, u64, u64)> {
    if bytes.len() < 20 {
        return None;
    }
    let log_slots = u32::from_le_bytes(bytes[0..4].try_into().ok()?);
    let active = u64::from_le_bytes(bytes[4..12].try_into().ok()?);
    let alloc = u64::from_le_bytes(bytes[12..20].try_into().ok()?);
    Some((log_slots, active, alloc))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use noid_core::Block128;
    use noid_core::TowerField;

    #[test]
    fn u64_key_roundtrip() {
        let v = 12345678u64;
        assert_eq!(u64_from_key(&u64_key(v)), Some(v));
        assert_eq!(u64_from_key(&[]), None);
    }

    #[test]
    fn header_roundtrip() {
        use crate::block_header::BlockHeader;
        use noid_poseidon2b::primitives::Address;
        let h = BlockHeader {
            prev_block_hash: [1u8; 32],
            state_root: [2u8; 32],
            tx_root: [3u8; 32],
            timestamp: 9999,
            height: 42,
            miner_address: Address([4u8; 32]),
            nonce: 12345u128,
            difficulty_target: [5u8; 32],
            proof_transcript_hash: [6u8; 32],
            witness_root: [7u8; 32],
            log_slots: 24,
            active_slot_count: 100,
            alloc_counter: 200,
        };
        let bytes = encode_header(&h);
        assert_eq!(bytes.len(), BLOCK_HEADER_WIRE_SIZE);
        let h2 = decode_header(&bytes).expect("decode");
        assert_eq!(h, h2);
    }

    #[test]
    fn slot_value_roundtrip() {
        let sv = SlotValue {
            value: Block128::from(12345u128),
            owner_hi: Block128::from(0xABCDEFu128),
            owner_lo: Block128::from(0x123456u128),
        };
        let bytes = encode_slot_value(&sv);
        let sv2 = decode_slot_value(&bytes).expect("decode");
        assert_eq!(sv.value, sv2.value);
        assert_eq!(sv.owner_hi, sv2.owner_hi);
        assert_eq!(sv.owner_lo, sv2.owner_lo);
    }

    #[test]
    fn undo_log_roundtrip() {
        use noid_poseidon2b::primitives::TxBodyHash;
        let sv = SlotValue {
            value: Block128::from(1u128),
            owner_hi: Block128::ZERO,
            owner_lo: Block128::ZERO,
        };
        let undo = BlockUndoLog {
            block_height: 7,
            slot_changes: vec![(3u32, sv), (9u32, SlotValue::EMPTY)],
            tx_hashes: vec![TxBodyHash([0xABu8; 32])],
        };
        let bytes = encode_undo_log(&undo);
        let undo2 = decode_undo_log(&bytes).expect("decode");
        assert_eq!(undo2.block_height, 7);
        assert_eq!(undo2.slot_changes.len(), 2);
        assert_eq!(undo2.slot_changes[0].0, 3);
        assert_eq!(undo2.tx_hashes.len(), 1);
    }

    #[test]
    fn undo_log_empty_roundtrip() {
        let undo = BlockUndoLog::empty(42);
        let bytes = encode_undo_log(&undo);
        let undo2 = decode_undo_log(&bytes).expect("decode");
        assert_eq!(undo2.block_height, 42);
        assert!(undo2.slot_changes.is_empty());
        assert!(undo2.tx_hashes.is_empty());
    }

    #[test]
    fn chain_tip_roundtrip() {
        let hash = [0xABu8; 32];
        let bytes = encode_chain_tip(999, &hash);
        let (h, hh) = decode_chain_tip(&bytes).expect("decode");
        assert_eq!(h, 999);
        assert_eq!(hh, hash);
    }

    #[test]
    fn state_meta_roundtrip() {
        let bytes = encode_state_meta(25, 1234567, 999999);
        let (ls, active, alloc) = decode_state_meta(&bytes).expect("decode");
        assert_eq!(ls, 25);
        assert_eq!(active, 1234567);
        assert_eq!(alloc, 999999);
    }

    #[test]
    fn segment_roundtrip_small() {
        // 4 elements per column (effective_log_seg=2)
        let seg = SegmentColumns {
            values: vec![
                Block128::from(1u128),
                Block128::from(2u128),
                Block128::from(3u128),
                Block128::ZERO,
            ],
            owners_hi: vec![Block128::ZERO; 4],
            owners_lo: vec![Block128::ONE; 4],
        };
        let bytes = encode_segment(&seg, 2);
        let (els, seg2) = decode_segment(&bytes).expect("decode");
        assert_eq!(els, 2);
        assert_eq!(seg2.values.len(), 4);
        assert_eq!(seg2.values[0], Block128::from(1u128));
        assert_eq!(seg2.owners_lo[0], Block128::ONE);
    }
}
