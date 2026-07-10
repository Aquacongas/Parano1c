// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Deterministic transaction epoch-anchor transition.
//!
//! This schedule is intentionally independent from ASERT's difficulty epochs.
//! Every user transaction in a child block binds the anchor that was current at
//! the start of that block. Coinbase instead binds the immediate parent id.

use noid_poseidon2b::primitives::Digest;

use crate::block::Block;
use crate::consensus::{params::TX_EPOCH_BLOCKS, pow::block_id, ConsensusError};

/// Height of the canonical header that supplies a child block's user anchor.
///
/// Boundary block `k * TX_EPOCH_BLOCKS` still consumes the preceding anchor;
/// its own id becomes active only after that block is accepted.
#[inline]
pub const fn tx_epoch_anchor_height_for_child(child_height: u64) -> u64 {
    if child_height == 0 {
        0
    } else {
        ((child_height - 1) / TX_EPOCH_BLOCKS) * TX_EPOCH_BLOCKS
    }
}

/// Validate the exact start-of-block anchors for every serialized body.
pub fn validate_block_epoch_anchors(
    block: &Block,
    user_epoch_anchor_id: Digest,
    parent_id: Digest,
) -> Result<(), ConsensusError> {
    for tx in &block.transactions {
        let expected = if tx.body.is_coinbase {
            parent_id
        } else {
            user_epoch_anchor_id
        };
        if tx.body.epoch_anchor != expected {
            return Err(if tx.body.is_coinbase {
                ConsensusError::BadCoinbaseAnchor
            } else {
                ConsensusError::BadEpochAnchor
            });
        }
    }
    Ok(())
}

/// Deterministic accumulator transition for the epoch-anchor lane.
#[inline]
pub fn next_tx_epoch_anchor_id(
    start_anchor_id: Digest,
    accepted_child_height: u64,
    accepted_child_id: Digest,
) -> Digest {
    if accepted_child_height != 0 && accepted_child_height % TX_EPOCH_BLOCKS == 0 {
        accepted_child_id
    } else {
        start_anchor_id
    }
}

/// Resolve the expected user anchor from a canonical header lookup.
pub fn resolve_user_epoch_anchor_id(
    child_height: u64,
    mut header_at: impl FnMut(u64) -> Option<crate::block_header::BlockHeader>,
) -> Option<Digest> {
    let height = tx_epoch_anchor_height_for_child(child_height);
    header_at(height).map(|header| block_id(&header))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boundary_block_consumes_old_anchor_then_advances() {
        assert_eq!(tx_epoch_anchor_height_for_child(1), 0);
        assert_eq!(tx_epoch_anchor_height_for_child(143), 0);
        assert_eq!(tx_epoch_anchor_height_for_child(144), 0);
        assert_eq!(tx_epoch_anchor_height_for_child(145), 144);
        assert_eq!(tx_epoch_anchor_height_for_child(288), 144);
        assert_eq!(tx_epoch_anchor_height_for_child(289), 288);

        let old = [1u8; 32];
        let boundary = [2u8; 32];
        assert_eq!(next_tx_epoch_anchor_id(old, 143, boundary), old);
        assert_eq!(next_tx_epoch_anchor_id(old, 144, boundary), boundary);
    }
}
