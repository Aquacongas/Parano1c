// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Header projections for the final O(1) history chunk boundary.
//!
//! Nodes validate and store headers from genesis natively. The O(1) layer must
//! bind accepted-block receipts to those local headers, but must not re-prove
//! PoW, ASERT, MTP, timestamp windows, or cumulative-work arithmetic. This
//! module therefore carries proof-facing header projections and validates only
//! local projection/anchor continuity.

use noid_chain::block_header::BlockHeader;
use noid_chain::header_anchor::HeaderChainAnchor;
use noid_core::Block128;
use noid_poseidon2b::native::domain::{capacity_iv, TAG_HDRANCH, TAG_HDRPROJ};
use noid_poseidon2b::native::Poseidon2bSponge;
use noid_poseidon2b::primitives::{Address, Digest};

pub const HEADER_PROJECTION_CHUNK_CAPACITY: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HeaderProjectionSlot {
    pub height: u64,
    pub block_id: Digest,
    pub parent_block_id: Digest,
    pub state_root: Digest,
    pub tx_root: Digest,
    pub timestamp: u64,
    pub miner_address: Address,
    pub nonce: u128,
    pub difficulty_target: Digest,
    pub log_slots: u32,
    pub active_slot_count: u64,
    pub alloc_counter: u64,
}

impl HeaderProjectionSlot {
    pub fn from_header(header: &BlockHeader, block_id: Digest) -> Self {
        Self {
            height: header.height,
            block_id,
            parent_block_id: header.prev_block_hash,
            state_root: header.state_root,
            tx_root: header.tx_root,
            timestamp: header.timestamp,
            miner_address: header.miner_address,
            nonce: header.nonce,
            difficulty_target: header.difficulty_target,
            log_slots: header.log_slots,
            active_slot_count: header.active_slot_count,
            alloc_counter: header.alloc_counter,
        }
    }

    pub fn to_header(&self) -> BlockHeader {
        BlockHeader {
            prev_block_hash: self.parent_block_id,
            state_root: self.state_root,
            tx_root: self.tx_root,
            timestamp: self.timestamp,
            height: self.height,
            miner_address: self.miner_address,
            nonce: self.nonce,
            difficulty_target: self.difficulty_target,
            log_slots: self.log_slots,
            active_slot_count: self.active_slot_count,
            alloc_counter: self.alloc_counter,
        }
    }

    pub fn byte_len(&self) -> usize {
        bincode::serialized_size(self).expect("serialized HeaderProjectionSlot length fits usize")
            as usize
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HeaderProjectionChunk {
    pub start_anchor: HeaderChainAnchor,
    pub slots: Vec<HeaderProjectionSlot>,
    pub end_anchor: HeaderChainAnchor,
}

impl HeaderProjectionChunk {
    pub fn byte_len(&self) -> usize {
        bincode::serialized_size(self).expect("serialized HeaderProjectionChunk length fits usize")
            as usize
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeaderProjectionChunkError {
    Empty,
    TooManySlots {
        actual: usize,
    },
    NonContiguousHeight {
        index: usize,
        expected: u64,
        actual: u64,
    },
    ParentBlockMismatch {
        index: usize,
    },
    EndAnchorMismatch,
}

impl std::fmt::Display for HeaderProjectionChunkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "empty header projection chunk"),
            Self::TooManySlots { actual } => write!(
                f,
                "too many header projection slots: {actual} > {HEADER_PROJECTION_CHUNK_CAPACITY}"
            ),
            Self::NonContiguousHeight {
                index,
                expected,
                actual,
            } => write!(
                f,
                "non-contiguous header projection slot {index}: expected h={expected}, got h={actual}"
            ),
            Self::ParentBlockMismatch { index } => {
                write!(f, "header projection parent block mismatch at slot {index}")
            }
            Self::EndAnchorMismatch => write!(f, "header projection chunk end anchor mismatch"),
        }
    }
}

impl std::error::Error for HeaderProjectionChunkError {}

pub fn header_projection_slot_digest(slot: &HeaderProjectionSlot) -> Digest {
    let mut sponge = Poseidon2bSponge::with_iv(capacity_iv(TAG_HDRPROJ));
    absorb_digest(&mut sponge, &slot.block_id);
    absorb_digest(&mut sponge, &slot.parent_block_id);
    absorb_digest(&mut sponge, &slot.state_root);
    absorb_digest(&mut sponge, &slot.tx_root);
    sponge.absorb(Block128::from(slot.timestamp as u128));
    sponge.absorb(Block128::from(slot.height as u128));
    absorb_address(&mut sponge, &slot.miner_address);
    sponge.absorb(Block128::from(slot.nonce));
    absorb_digest(&mut sponge, &slot.difficulty_target);
    sponge.absorb(Block128::from(slot.log_slots as u128));
    sponge.absorb(Block128::from(slot.active_slot_count as u128));
    sponge.absorb(Block128::from(slot.alloc_counter as u128));
    sponge.finalize()
}

pub fn extend_header_projection_root_from_slot(
    previous_root: &Digest,
    slot: &HeaderProjectionSlot,
) -> Digest {
    let item = header_projection_slot_digest(slot);
    let mut sponge = Poseidon2bSponge::with_iv(capacity_iv(TAG_HDRANCH));
    absorb_digest(&mut sponge, previous_root);
    absorb_digest(&mut sponge, &item);
    sponge.absorb(Block128::from(slot.height as u128));
    sponge.finalize()
}

pub fn validate_header_projection_chunk(
    chunk: &HeaderProjectionChunk,
) -> Result<(), HeaderProjectionChunkError> {
    if chunk.slots.is_empty() {
        return Err(HeaderProjectionChunkError::Empty);
    }
    if chunk.slots.len() > HEADER_PROJECTION_CHUNK_CAPACITY {
        return Err(HeaderProjectionChunkError::TooManySlots {
            actual: chunk.slots.len(),
        });
    }

    let mut expected_height = chunk.start_anchor.height.saturating_add(1);
    let mut previous_block_id = chunk.start_anchor.block_id;
    let mut projection_root = chunk.start_anchor.projection_root;
    let mut last_slot = None;

    for (index, slot) in chunk.slots.iter().enumerate() {
        if slot.height != expected_height {
            return Err(HeaderProjectionChunkError::NonContiguousHeight {
                index,
                expected: expected_height,
                actual: slot.height,
            });
        }
        if slot.parent_block_id != previous_block_id {
            return Err(HeaderProjectionChunkError::ParentBlockMismatch { index });
        }

        projection_root = extend_header_projection_root_from_slot(&projection_root, slot);
        previous_block_id = slot.block_id;
        expected_height = expected_height.saturating_add(1);
        last_slot = Some(slot);
    }

    let last = last_slot.expect("non-empty checked above");
    if chunk.end_anchor.height != last.height
        || chunk.end_anchor.block_id != last.block_id
        || chunk.end_anchor.state_root != last.state_root
        || chunk.end_anchor.tx_root != last.tx_root
        || chunk.end_anchor.miner_address != last.miner_address
        || chunk.end_anchor.log_slots != last.log_slots
        || chunk.end_anchor.active_slot_count != last.active_slot_count
        || chunk.end_anchor.alloc_counter != last.alloc_counter
        || chunk.end_anchor.projection_root != projection_root
    {
        return Err(HeaderProjectionChunkError::EndAnchorMismatch);
    }

    Ok(())
}

pub fn header_projection_chunk_from_slots(
    start_anchor: HeaderChainAnchor,
    slots: Vec<HeaderProjectionSlot>,
    end_anchor: HeaderChainAnchor,
) -> Result<HeaderProjectionChunk, HeaderProjectionChunkError> {
    let chunk = HeaderProjectionChunk {
        start_anchor,
        slots,
        end_anchor,
    };
    validate_header_projection_chunk(&chunk)?;
    Ok(chunk)
}

#[inline]
fn absorb_digest(sponge: &mut Poseidon2bSponge, digest: &Digest) {
    let lo = Block128::from(u128::from_le_bytes(digest[..16].try_into().unwrap()));
    let hi = Block128::from(u128::from_le_bytes(digest[16..].try_into().unwrap()));
    sponge.absorb_pair(lo, hi);
}

#[inline]
fn absorb_address(sponge: &mut Poseidon2bSponge, address: &Address) {
    absorb_digest(sponge, address.as_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use noid_chain::block_header::hash_block_header;

    fn anchor_from_header(header: &BlockHeader, projection_root: Digest) -> HeaderChainAnchor {
        HeaderChainAnchor {
            height: header.height,
            block_id: hash_block_header(header),
            state_root: header.state_root,
            tx_root: header.tx_root,
            miner_address: header.miner_address,
            log_slots: header.log_slots,
            active_slot_count: header.active_slot_count,
            alloc_counter: header.alloc_counter,
            cumulative_chainwork: [0xAA; 32],
            projection_root,
        }
    }

    fn header(height: u64, prev: Digest, seed: u8) -> BlockHeader {
        BlockHeader {
            prev_block_hash: prev,
            state_root: [seed; 32],
            tx_root: [seed ^ 0x55; 32],
            timestamp: 1_700_000_000 + height,
            height,
            miner_address: Address([0x44; 32]),
            nonce: height as u128,
            difficulty_target: [0x7f; 32],
            log_slots: 24,
            active_slot_count: height,
            alloc_counter: height * 2,
        }
    }

    #[test]
    fn chunk_validates_projection_root_without_header_consensus() {
        let h0 = header(0, [0u8; 32], 1);
        let h0_id = hash_block_header(&h0);
        let h0_slot = HeaderProjectionSlot::from_header(&h0, h0_id);
        let h0_root = extend_header_projection_root_from_slot(&[0u8; 32], &h0_slot);
        let start = anchor_from_header(&h0, h0_root);

        let h1 = header(1, h0_id, 2);
        let h1_id = hash_block_header(&h1);
        let h1_slot = HeaderProjectionSlot::from_header(&h1, h1_id);
        let h1_root = extend_header_projection_root_from_slot(&h0_root, &h1_slot);
        let end = anchor_from_header(&h1, h1_root);

        let chunk = HeaderProjectionChunk {
            start_anchor: start,
            slots: vec![h1_slot],
            end_anchor: end,
        };
        validate_header_projection_chunk(&chunk).expect("projection chunk validates");
    }

    #[test]
    fn chunk_rejects_wrong_parent() {
        let h0 = header(0, [0u8; 32], 1);
        let h0_id = hash_block_header(&h0);
        let h0_slot = HeaderProjectionSlot::from_header(&h0, h0_id);
        let h0_root = extend_header_projection_root_from_slot(&[0u8; 32], &h0_slot);
        let start = anchor_from_header(&h0, h0_root);

        let mut h1 = header(1, h0_id, 2);
        let h1_id = hash_block_header(&h1);
        let mut h1_slot = HeaderProjectionSlot::from_header(&h1, h1_id);
        let h1_root = extend_header_projection_root_from_slot(&h0_root, &h1_slot);
        let end = anchor_from_header(&h1, h1_root);
        h1.prev_block_hash = [0x33; 32];
        h1_slot.parent_block_id = h1.prev_block_hash;

        let chunk = HeaderProjectionChunk {
            start_anchor: start,
            slots: vec![h1_slot],
            end_anchor: end,
        };
        assert_eq!(
            validate_header_projection_chunk(&chunk),
            Err(HeaderProjectionChunkError::ParentBlockMismatch { index: 0 })
        );
    }
}
