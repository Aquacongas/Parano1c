// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Header-chain anchor for public history proofs.
//!
//! Nodes store and validate canonical headers from genesis.  Public O(1)
//! history proofs should bind to those headers without storing a second copy.
//! This module defines the small rolling commitment over the header fields that
//! proof relations need to consume: state roots, transaction root, miner, and
//! state counters, plus the canonical block id.

use noid_core::Block128;
use noid_poseidon2b::native::compression::Poseidon2bSponge;
use noid_poseidon2b::native::domain::{capacity_iv, TAG_HDRANCH, TAG_HDRPROJ};
use noid_poseidon2b::primitives::{Address, Digest};

use crate::block_header::{hash_block_header, BlockHeader};

/// Public commitment to a verified canonical header prefix.
///
/// `projection_root` is a rolling commitment over header projections from
/// genesis through `height`.  `cumulative_chainwork` is the exact chainwork
/// recorded by header validation for the same tip.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HeaderChainAnchor {
    pub height: u64,
    pub block_id: Digest,
    pub state_root: Digest,
    pub tx_root: Digest,
    pub miner_address: Address,
    pub log_slots: u32,
    pub active_slot_count: u64,
    pub alloc_counter: u64,
    pub cumulative_chainwork: Digest,
    pub projection_root: Digest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeaderChainAnchorError {
    Empty,
    StartsAfterGenesis { first_height: u64 },
    NonContiguous { expected: u64, actual: u64 },
    BadParentLink { height: u64 },
}

impl std::fmt::Display for HeaderChainAnchorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "empty header prefix"),
            Self::StartsAfterGenesis { first_height } => {
                write!(f, "header prefix starts at h={first_height}, expected h=0")
            }
            Self::NonContiguous { expected, actual } => {
                write!(
                    f,
                    "non-contiguous header prefix: expected h={expected}, got h={actual}"
                )
            }
            Self::BadParentLink { height } => {
                write!(f, "bad parent link at h={height}")
            }
        }
    }
}

impl std::error::Error for HeaderChainAnchorError {}

/// Compute the digest of the proof-facing header projection.
///
/// The schedule deliberately includes `block_id` and the canonical header
/// fields needed by future execution/history relations.  Header consensus
/// checks remain native node work; this commitment binds proof witnesses to the
/// exact header values the node already accepted.
pub fn header_projection_digest(header: &BlockHeader, block_id: &Digest) -> Digest {
    let mut sponge = Poseidon2bSponge::with_iv(capacity_iv(TAG_HDRPROJ));
    absorb_digest(&mut sponge, block_id);
    absorb_digest(&mut sponge, &header.prev_block_hash);
    absorb_digest(&mut sponge, &header.state_root);
    absorb_digest(&mut sponge, &header.tx_root);
    sponge.absorb(Block128::from(header.timestamp as u128));
    sponge.absorb(Block128::from(header.height as u128));
    absorb_address(&mut sponge, &header.miner_address);
    sponge.absorb(Block128::from(header.nonce));
    absorb_digest(&mut sponge, &header.difficulty_target);
    sponge.absorb(Block128::from(header.log_slots as u128));
    sponge.absorb(Block128::from(header.active_slot_count as u128));
    sponge.absorb(Block128::from(header.alloc_counter as u128));
    sponge.finalize()
}

/// Extend the rolling header projection root by one canonical header.
pub fn extend_header_projection_root(
    previous_root: &Digest,
    header: &BlockHeader,
    block_id: &Digest,
) -> Digest {
    let item = header_projection_digest(header, block_id);
    let mut sponge = Poseidon2bSponge::with_iv(capacity_iv(TAG_HDRANCH));
    absorb_digest(&mut sponge, previous_root);
    absorb_digest(&mut sponge, &item);
    sponge.absorb(Block128::from(header.height as u128));
    sponge.finalize()
}

/// Extend a verified header-chain anchor by one canonical child header.
///
/// This stores no header copy.  It only carries forward the small rolling
/// projection commitment and the exact cumulative chainwork already validated
/// by the native header path.
pub fn extend_header_chain_anchor(
    previous: &HeaderChainAnchor,
    header: &BlockHeader,
    cumulative_chainwork: Digest,
) -> Result<HeaderChainAnchor, HeaderChainAnchorError> {
    let expected = previous.height.saturating_add(1);
    if header.height != expected {
        return Err(HeaderChainAnchorError::NonContiguous {
            expected,
            actual: header.height,
        });
    }
    if header.prev_block_hash != previous.block_id {
        return Err(HeaderChainAnchorError::BadParentLink {
            height: header.height,
        });
    }

    let block_id = hash_block_header(header);
    let projection_root =
        extend_header_projection_root(&previous.projection_root, header, &block_id);
    Ok(HeaderChainAnchor {
        height: header.height,
        block_id,
        state_root: header.state_root,
        tx_root: header.tx_root,
        miner_address: header.miner_address,
        log_slots: header.log_slots,
        active_slot_count: header.active_slot_count,
        alloc_counter: header.alloc_counter,
        cumulative_chainwork,
        projection_root,
    })
}

/// Build an anchor for a contiguous header prefix from genesis through tip.
pub fn compute_header_chain_anchor<'a, I>(
    headers: I,
    cumulative_chainwork: Digest,
) -> Result<HeaderChainAnchor, HeaderChainAnchorError>
where
    I: IntoIterator<Item = &'a BlockHeader>,
{
    let mut iter = headers.into_iter();
    let first = iter.next().ok_or(HeaderChainAnchorError::Empty)?;
    if first.height != 0 {
        return Err(HeaderChainAnchorError::StartsAfterGenesis {
            first_height: first.height,
        });
    }

    let mut expected_height = 0u64;
    let mut previous_block_id = [0u8; 32];
    let mut projection_root = [0u8; 32];
    let mut tip = None;

    for header in std::iter::once(first).chain(iter) {
        if header.height != expected_height {
            return Err(HeaderChainAnchorError::NonContiguous {
                expected: expected_height,
                actual: header.height,
            });
        }
        if header.height > 0 && header.prev_block_hash != previous_block_id {
            return Err(HeaderChainAnchorError::BadParentLink {
                height: header.height,
            });
        }

        let block_id = hash_block_header(header);
        projection_root = extend_header_projection_root(&projection_root, header, &block_id);
        previous_block_id = block_id;
        tip = Some((*header, block_id));
        expected_height = expected_height.saturating_add(1);
    }

    let (tip_header, block_id) = tip.expect("non-empty iterator handled above");
    Ok(HeaderChainAnchor {
        height: tip_header.height,
        block_id,
        state_root: tip_header.state_root,
        tx_root: tip_header.tx_root,
        miner_address: tip_header.miner_address,
        log_slots: tip_header.log_slots,
        active_slot_count: tip_header.active_slot_count,
        alloc_counter: tip_header.alloc_counter,
        cumulative_chainwork,
        projection_root,
    })
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
    use noid_poseidon2b::primitives::Address;

    fn header(height: u64, prev: Digest, state_seed: u8) -> BlockHeader {
        BlockHeader {
            prev_block_hash: prev,
            state_root: [state_seed; 32],
            tx_root: [state_seed ^ 0x55; 32],
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

    fn three_headers() -> Vec<BlockHeader> {
        let h0 = header(0, [0u8; 32], 1);
        let h0_hash = hash_block_header(&h0);
        let h1 = header(1, h0_hash, 2);
        let h1_hash = hash_block_header(&h1);
        let h2 = header(2, h1_hash, 3);
        vec![h0, h1, h2]
    }

    #[test]
    fn anchor_binds_tip_and_projection_root() {
        let headers = three_headers();
        let work = [0xAA; 32];
        let anchor = compute_header_chain_anchor(headers.iter(), work).unwrap();

        assert_eq!(anchor.height, 2);
        assert_eq!(anchor.block_id, hash_block_header(&headers[2]));
        assert_eq!(anchor.state_root, headers[2].state_root);
        assert_eq!(anchor.tx_root, headers[2].tx_root);
        assert_eq!(anchor.cumulative_chainwork, work);
        assert_ne!(anchor.projection_root, [0u8; 32]);
    }

    #[test]
    fn anchor_changes_when_proof_relevant_header_field_changes() {
        let headers = three_headers();
        let mut changed = headers.clone();
        changed[2].active_slot_count += 1;
        let original = compute_header_chain_anchor(headers.iter(), [1u8; 32]).unwrap();
        let changed = compute_header_chain_anchor(changed.iter(), [1u8; 32]).unwrap();

        assert_ne!(original.projection_root, changed.projection_root);
    }

    #[test]
    fn rejects_non_contiguous_prefix() {
        let mut headers = three_headers();
        headers[2].height = 3;
        assert_eq!(
            compute_header_chain_anchor(headers.iter(), [0u8; 32]),
            Err(HeaderChainAnchorError::NonContiguous {
                expected: 2,
                actual: 3
            })
        );
    }

    #[test]
    fn rejects_bad_parent_link() {
        let mut headers = three_headers();
        headers[2].prev_block_hash[0] ^= 1;
        assert_eq!(
            compute_header_chain_anchor(headers.iter(), [0u8; 32]),
            Err(HeaderChainAnchorError::BadParentLink { height: 2 })
        );
    }

    #[test]
    fn incremental_anchor_matches_full_prefix() {
        let headers = three_headers();
        let a0 = compute_header_chain_anchor(headers[..1].iter(), [1u8; 32]).unwrap();
        let a1 = extend_header_chain_anchor(&a0, &headers[1], [2u8; 32]).unwrap();
        let a2 = extend_header_chain_anchor(&a1, &headers[2], [3u8; 32]).unwrap();
        let full = compute_header_chain_anchor(headers.iter(), [3u8; 32]).unwrap();

        assert_eq!(a2, full);
    }
}
