// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Production wire, memory and decode limits shared by node, P2P, RPC and mempool.
//!
//! These are not cryptographic security parameters. They are DoS guardrails around
//! the accepted-bundle protocol: every large object must be bounded before expensive
//! decode, allocation, verification or storage.

/// Maximum serialized authorization and canonical PagedSpend intent sizes.
pub const MAX_AUTHORIZATION_BYTES: usize = noid_tx::MAX_TX_AUTHORIZATION_BYTES;
pub const MAX_TX_INTENT_BYTES_GLOBAL: usize = noid_tx::MAX_PAGED_SPEND_INTENT_BYTES;

/// Maximum admitted mempool transactions kept in RAM.
pub const MAX_MEMPOOL_TXS: usize = 1024;

/// Maximum serialized PagedSpendIntent bytes kept in mempool RAM.
pub const MAX_MEMPOOL_BYTES: usize = 384 * 1024 * 1024;

/// Maximum transactions returned in one mempool-sync response.
pub const MAX_MEMPOOL_SYNC_TXS: usize = 128;

/// Maximum bytes returned in one mempool-sync response.
pub const MAX_MEMPOOL_SYNC_BYTES: usize = 16 * 1024 * 1024;

/// Exact largest canonical block: marker + header + count + 256 Tx8x2 bodies.
pub const MAX_BLOCK_BYTES: usize =
    1 + crate::wire::BLOCK_HEADER_WIRE_SIZE + 4 + 256 * noid_tx::TX_BODY_WIRE_SIZE;

/// Maximum block resource weight accepted before expensive proof verification.
///
/// This is an admission/DoS guard, not the consensus semantic throughput
/// budget. Consensus semantic limits live in `consensus::params` and are
/// calibrated to 255 maximum fixed-shape user transactions.
pub const MAX_BLOCK_RESOURCE_WEIGHT: usize = 64 * 1024 * 1024;

pub const BLOCK_WEIGHT_PER_USER_TX: usize = 16 * 1024;
pub const BLOCK_WEIGHT_PER_LIVE_INPUT: usize = 2 * 1024;
pub const BLOCK_WEIGHT_PER_OUTPUT: usize = 1024;
/// Charge per missing digest in the canonical sibling frontier. Touched leaf
/// work is charged separately through the live-input/output terms; this is a
/// conservative admission guard, not a literal count of old/new hash calls.
pub const BLOCK_WEIGHT_PER_STATE_FRONTIER_NODE: usize = 256;

/// Gossipsub message size. Large blocks must use compact announce + pull.
pub const GOSSIP_MAX_TRANSMIT_BYTES: usize = 2 * 1024 * 1024;

/// Inline gossip threshold for one complete accepted block bundle.
pub const INLINE_BLOCK_GOSSIP_THRESHOLD: usize = 1024 * 1024;

/// Maximum serialized fused `HistoryStep` terminal carried by one
/// [`AcceptedBlockBundle`](crate::accepted_block_bundle::AcceptedBlockBundle).
///
/// One MiB leaves bounded codec framing margin without coupling the wire cap to
/// an exact serialization snapshot. This remains constant in chain height.
pub const MAX_HISTORY_STEP_TERMINAL_BYTES: usize = 1024 * 1024;

/// Maximum encoded block header bytes accepted over P2P/RPC paths.
pub const MAX_HEADER_BYTES: usize = 512;

/// Maximum state snapshot segment bytes.
pub const MAX_SEGMENT_BYTES: usize = 8 * 1024 * 1024;

/// Maximum state snapshot segment IDs/roots described by one manifest.
///
/// Segment IDs are `u16`, so this is the full representable sparse segment
/// namespace for `LOG_SEGMENT_SIZE = 16` and `LOG_SLOTS_MAX = 32`.
pub const MAX_SNAPSHOT_MANIFEST_SEGMENTS: usize = 1usize << 16;

/// Maximum state snapshot segment requests in flight.
pub const MAX_INFLIGHT_SEGMENTS: usize = 8;

/// Maximum orphan blocks retained by count.
pub const MAX_ORPHAN_POOL: usize = 36;

/// Maximum orphan accepted-bundle bytes retained in RAM.
pub const MAX_ORPHAN_POOL_BYTES: usize = 128 * 1024 * 1024;

/// Maximum receipt bytes accepted via RPC before decode.
pub const MAX_RPC_RECEIPT_BYTES: usize = 128 * 1024;

/// Maximum optional salt bytes accepted via RPC before decode.
pub const MAX_RPC_SALT_BYTES: usize = 256;

#[inline]
pub const fn hex_chars_for_bytes(bytes: usize) -> usize {
    bytes.saturating_mul(2)
}

#[inline]
pub fn block_resource_weight(
    block_body_len: usize,
    history_step_terminal_len: usize,
    user_txs: usize,
    live_inputs: usize,
    outputs: usize,
    state_frontier_nodes: usize,
) -> Option<usize> {
    let mut weight = block_body_len.checked_add(history_step_terminal_len)?;
    weight = weight.checked_add(user_txs.checked_mul(BLOCK_WEIGHT_PER_USER_TX)?)?;
    weight = weight.checked_add(live_inputs.checked_mul(BLOCK_WEIGHT_PER_LIVE_INPUT)?)?;
    weight = weight.checked_add(outputs.checked_mul(BLOCK_WEIGHT_PER_OUTPUT)?)?;
    weight = weight
        .checked_add(state_frontier_nodes.checked_mul(BLOCK_WEIGHT_PER_STATE_FRONTIER_NODE)?)?;
    Some(weight)
}

#[inline]
pub fn block_resource_weight_ok(
    block_body_len: usize,
    history_step_terminal_len: usize,
    user_txs: usize,
    live_inputs: usize,
    outputs: usize,
    state_frontier_nodes: usize,
) -> bool {
    block_resource_weight(
        block_body_len,
        history_step_terminal_len,
        user_txs,
        live_inputs,
        outputs,
        state_frontier_nodes,
    )
    .is_some_and(|weight| weight <= MAX_BLOCK_RESOURCE_WEIGHT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn final_wire_caps_match_canonical_constructions() {
        assert_eq!(MAX_AUTHORIZATION_BYTES, noid_tx::MAX_TX_AUTHORIZATION_BYTES);
        assert_eq!(
            MAX_TX_INTENT_BYTES_GLOBAL,
            noid_tx::MAX_PAGED_SPEND_INTENT_BYTES
        );
        assert_eq!(MAX_BLOCK_BYTES, 82_905);
        assert!(MAX_HISTORY_STEP_TERMINAL_BYTES > 580_495);
    }

    #[test]
    fn resource_weight_uses_checked_arithmetic() {
        assert!(block_resource_weight(1, 2, 3, 4, 5, 6).is_some());
        assert!(block_resource_weight(usize::MAX, 1, 0, 0, 0, 0).is_none());
    }

    #[test]
    fn legal_depth32_b255_frontier_fits_resource_weight() {
        use crate::consensus::params::{
            BLOCK_MAX_ACTIONS, BLOCK_MAX_DISTINCT_SEGMENTS, BLOCK_MAX_LIVE_INPUTS, BLOCK_MAX_TXS,
            BLOCK_MAX_USER_OUTPUTS, BLOCK_MAX_USER_TXS, LOG_SEGMENT_SIZE,
        };

        let frontier = crate::sparse_merkle::maximum_sibling_count_with_segment_cap(
            BLOCK_MAX_ACTIONS,
            32,
            LOG_SEGMENT_SIZE,
            BLOCK_MAX_DISTINCT_SEGMENTS,
        );
        assert_eq!(frontier, 22_468);
        let weight = block_resource_weight(
            MAX_BLOCK_BYTES,
            MAX_HISTORY_STEP_TERMINAL_BYTES,
            BLOCK_MAX_USER_TXS,
            BLOCK_MAX_LIVE_INPUTS,
            BLOCK_MAX_USER_OUTPUTS + 1,
            frontier,
        )
        .unwrap();
        assert_eq!(BLOCK_MAX_TXS, 256);
        assert_eq!(weight, 13_673_433);
        assert!(weight <= MAX_BLOCK_RESOURCE_WEIGHT);
    }
}
