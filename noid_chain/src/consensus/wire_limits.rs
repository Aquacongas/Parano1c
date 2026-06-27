// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Production wire, memory and decode limits shared by node, P2P, RPC and mempool.
//!
//! These are not cryptographic security parameters. They are DoS guardrails around
//! the proof-native protocol: every large object must be bounded before expensive
//! decode, allocation, verification or storage.

/// Maximum serialized TxIntent accepted by P2P/RPC/mempool admission.
pub const MAX_TX_INTENT_BYTES_GLOBAL: usize = 512 * 1024;

/// Maximum serialized Standard4x8 wallet authorization bytes.
pub const MAX_STANDARD_AUTHORIZATION_BYTES: usize = 192 * 1024;

/// Maximum serialized Sweep25x2 wallet authorization bytes.
pub const MAX_SWEEP_AUTHORIZATION_BYTES: usize = 256 * 1024;

/// Shape-specific serialized TxIntent cap for Standard4x8 auth-only wallet artifacts.
pub const MAX_STANDARD_TX_INTENT_BYTES: usize = 256 * 1024;

/// Shape-specific serialized TxIntent cap for Sweep25x2 auth-only wallet artifacts.
pub const MAX_SWEEP_TX_INTENT_BYTES: usize = 320 * 1024;

/// Maximum admitted mempool transactions kept in RAM.
pub const MAX_MEMPOOL_TXS: usize = 1024;

/// Maximum serialized TxIntent bytes kept in mempool RAM.
pub const MAX_MEMPOOL_BYTES: usize = 384 * 1024 * 1024;

/// Maximum transactions returned in one mempool-sync response.
pub const MAX_MEMPOOL_SYNC_TXS: usize = 128;

/// Maximum bytes returned in one mempool-sync response.
pub const MAX_MEMPOOL_SYNC_BYTES: usize = 16 * 1024 * 1024;

/// Maximum serialized block body/header payload.
pub const MAX_BLOCK_BYTES: usize = 1024 * 1024;

/// Maximum serialized canonical BlockProof payload.
pub const MAX_BLOCK_PROOF_BYTES: usize = 32 * 1024 * 1024;

/// Maximum serialized public BlockAuthSidecar payload.
pub const MAX_BLOCK_AUTH_SIDECAR_BYTES: usize = 32 * 1024 * 1024;

/// Maximum combined BlockProof + BlockAuthSidecar payload.
pub const MAX_BLOCK_PROOF_PLUS_SIDECAR_BYTES: usize = 48 * 1024 * 1024;

/// Maximum block resource weight accepted before expensive proof verification.
///
/// This is an admission/DoS guard, not the consensus semantic throughput
/// budget. Consensus semantic limits live in `consensus::params` and are
/// calibrated to 255 maximum Standard4x8 user transactions.
pub const MAX_BLOCK_RESOURCE_WEIGHT: usize = 64 * 1024 * 1024;

pub const BLOCK_WEIGHT_PER_USER_TX: usize = 16 * 1024;
pub const BLOCK_WEIGHT_PER_LIVE_INPUT: usize = 2 * 1024;
pub const BLOCK_WEIGHT_PER_OUTPUT: usize = 1024;
pub const BLOCK_WEIGHT_PER_STATE_FRONTIER_NODE: usize = 256;

/// Gossipsub message size. Large blocks must use compact announce + pull.
pub const GOSSIP_MAX_TRANSMIT_BYTES: usize = 2 * 1024 * 1024;

/// Inline block gossip threshold for block + proof + sidecar.
pub const INLINE_BLOCK_GOSSIP_THRESHOLD: usize = 1024 * 1024;

/// Maximum history proof bytes accepted over RPC/P2P.
pub const MAX_HISTORY_PROOF_BYTES: usize = 64 * 1024;

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

/// Maximum orphan block/proof/sidecar bytes retained in RAM.
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
pub fn max_tx_intent_bytes_for_shape(shape: noid_tx::TxShape) -> usize {
    match shape {
        noid_tx::TxShape::Standard4x8 => MAX_STANDARD_TX_INTENT_BYTES,
        noid_tx::TxShape::Sweep25x2 => MAX_SWEEP_TX_INTENT_BYTES,
    }
}

#[inline]
pub fn max_authorization_bytes_for_shape(shape: noid_tx::TxShape) -> usize {
    match shape {
        noid_tx::TxShape::Standard4x8 => MAX_STANDARD_AUTHORIZATION_BYTES,
        noid_tx::TxShape::Sweep25x2 => MAX_SWEEP_AUTHORIZATION_BYTES,
    }
}

#[inline]
pub fn proof_sidecar_combined_len_ok(proof_len: usize, sidecar_len: usize) -> bool {
    proof_len.saturating_add(sidecar_len) <= MAX_BLOCK_PROOF_PLUS_SIDECAR_BYTES
}

#[inline]
#[allow(clippy::too_many_arguments)]
pub fn block_resource_weight(
    block_body_len: usize,
    proof_len: usize,
    sidecar_len: usize,
    user_txs: usize,
    live_inputs: usize,
    outputs: usize,
    state_frontier_nodes: usize,
) -> Option<usize> {
    let mut weight = block_body_len
        .checked_add(proof_len)?
        .checked_add(sidecar_len)?;
    weight = weight.checked_add(user_txs.checked_mul(BLOCK_WEIGHT_PER_USER_TX)?)?;
    weight = weight.checked_add(live_inputs.checked_mul(BLOCK_WEIGHT_PER_LIVE_INPUT)?)?;
    weight = weight.checked_add(outputs.checked_mul(BLOCK_WEIGHT_PER_OUTPUT)?)?;
    weight = weight
        .checked_add(state_frontier_nodes.checked_mul(BLOCK_WEIGHT_PER_STATE_FRONTIER_NODE)?)?;
    Some(weight)
}

#[inline]
#[allow(clippy::too_many_arguments)]
pub fn block_resource_weight_ok(
    block_body_len: usize,
    proof_len: usize,
    sidecar_len: usize,
    user_txs: usize,
    live_inputs: usize,
    outputs: usize,
    state_frontier_nodes: usize,
) -> bool {
    block_resource_weight(
        block_body_len,
        proof_len,
        sidecar_len,
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
    #[allow(clippy::assertions_on_constants)]
    fn production_wire_caps_are_ordered() {
        assert!(MAX_STANDARD_TX_INTENT_BYTES <= MAX_TX_INTENT_BYTES_GLOBAL);
        assert!(MAX_SWEEP_TX_INTENT_BYTES <= MAX_TX_INTENT_BYTES_GLOBAL);
        assert!(
            MAX_BLOCK_PROOF_PLUS_SIDECAR_BYTES
                <= MAX_BLOCK_PROOF_BYTES + MAX_BLOCK_AUTH_SIDECAR_BYTES
        );
        assert!(MAX_BLOCK_BYTES <= INLINE_BLOCK_GOSSIP_THRESHOLD);
        assert!(INLINE_BLOCK_GOSSIP_THRESHOLD <= GOSSIP_MAX_TRANSMIT_BYTES);
        assert!(MAX_MEMPOOL_SYNC_BYTES <= MAX_MEMPOOL_BYTES);
        assert_eq!(MAX_SNAPSHOT_MANIFEST_SEGMENTS, u16::MAX as usize + 1);
        assert!(MAX_SEGMENT_BYTES.saturating_mul(MAX_INFLIGHT_SEGMENTS) == 64 * 1024 * 1024);
        assert!(MAX_ORPHAN_POOL_BYTES >= MAX_BLOCK_PROOF_PLUS_SIDECAR_BYTES);
        assert!(MAX_BLOCK_PROOF_PLUS_SIDECAR_BYTES <= MAX_BLOCK_RESOURCE_WEIGHT);
    }

    #[test]
    fn proof_sidecar_combined_cap_is_saturating() {
        assert!(proof_sidecar_combined_len_ok(
            MAX_BLOCK_PROOF_PLUS_SIDECAR_BYTES,
            0
        ));
        assert!(proof_sidecar_combined_len_ok(
            MAX_BLOCK_PROOF_PLUS_SIDECAR_BYTES / 2,
            MAX_BLOCK_PROOF_PLUS_SIDECAR_BYTES / 2
        ));
        assert!(!proof_sidecar_combined_len_ok(
            MAX_BLOCK_PROOF_PLUS_SIDECAR_BYTES,
            1
        ));
        assert!(!proof_sidecar_combined_len_ok(usize::MAX, usize::MAX));
    }

    #[test]
    fn block_resource_weight_counts_work_units() {
        let light = block_resource_weight(1024, 1024, 1024, 1, 1, 2, 3).unwrap();
        let heavy = block_resource_weight(1024, 1024, 1024, 1, 25, 2, 27).unwrap();
        assert!(heavy > light);
        assert!(block_resource_weight_ok(1024, 1024, 1024, 1, 25, 2, 27));
        assert!(!block_resource_weight_ok(
            MAX_BLOCK_RESOURCE_WEIGHT,
            1,
            0,
            0,
            0,
            0,
            0
        ));
    }

    #[test]
    fn tx_shape_caps_are_below_global_cap() {
        assert_eq!(
            max_tx_intent_bytes_for_shape(noid_tx::TxShape::Standard4x8),
            MAX_STANDARD_TX_INTENT_BYTES
        );
        assert_eq!(
            max_tx_intent_bytes_for_shape(noid_tx::TxShape::Sweep25x2),
            MAX_SWEEP_TX_INTENT_BYTES
        );
    }
}
