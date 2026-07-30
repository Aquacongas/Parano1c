// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Wire message types for the Paranoid P2P protocol.
//!
//! ## Block propagation
//!
//! Blocks use one all-or-none bundle in two propagation modes:
//!
//! 1. **Inline** (common case): small blocks (coinbase-only or few txs, total
//!    < 1 MB) carry one complete accepted-block bundle via gossipsub. Receivers
//!    can validate immediately —
//!    no round-trip, no race condition.
//!
//! 2. **Compact** (large blocks): header-only gossip (~310 bytes).  Receivers
//!    pull the complete bundle via `GetRecentBlockRequest`. This mirrors
//!    Bitcoin's compact block protocol and Ethereum's `NewBlockHashes`.
//!
//! The 1 MB inline threshold is well below the 2 MB gossipsub transmit limit
//! and handles 99%+ of real-world blocks (coinbase-only through ~100 txs).
//!
//! ## State sync
//!
//! State snapshots are served in two stages to avoid single responses that can
//! reach hundreds of MB or even gigabytes on a mature network:
//!
//! 1. Client requests `GetStateManifestRequest` → receives metadata + list of
//!    active segment IDs (tiny, ~few KB).
//! 2. Client requests each segment individually via `GetStateSegmentRequest`
//!    → receives one 3 MB segment per response.
//!    Segments are downloaded in parallel for speed.
//!
//! This enables progress reporting, resumable sync, and correct memory usage
//! regardless of total state size.

use noid_chain::{
    block::BLOCK_WIRE_HEADER_OFFSET, AcceptedBlockBundle, BlockHeader, BLOCK_HEADER_WIRE_SIZE,
    MAX_ACCEPTED_BLOCK_BUNDLE_BYTES,
};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Block pull: headers
// ---------------------------------------------------------------------------

/// Get block headers by height range.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetHeadersRequest {
    pub start_height: u64,
    pub count: u16, // max 512
}

/// Response: canonical serialized BlockHeader bytes, 212 bytes each.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetHeadersResponse {
    pub headers: Vec<Vec<u8>>,
}

// ---------------------------------------------------------------------------
// Block pull: complete accepted-block bundle
// ---------------------------------------------------------------------------

/// Payload requested from the bounded recent-block window.
///
/// `BlockBody` is the snapshot fast path: the suffix's final recursive
/// HistoryStep terminal authenticates the complete linked body sequence, so
/// transferring the same proof-sized terminal with every body is redundant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecentBlockPayloadKind {
    Complete,
    BlockBody,
}

/// Maximum canonical block bodies returned by one snapshot-tail request.
///
/// This is exactly the consensus retention window.  It keeps the fast path to
/// one bounded response without allowing an unbounded range allocation.
pub const MAX_BLOCK_BODY_BATCH: u16 =
    noid_chain::consensus::params::RECENT_BLOCK_RETENTION_DEPTH as u16;

/// Request one retained proof bundle or one bounded range of block bodies.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetRecentBlockRequest {
    pub height: u64,
    pub count: u16,
    pub payload_kind: RecentBlockPayloadKind,
}

/// One bounded recent-block payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecentBlockPayload {
    /// Canonical block plus its current-height HistoryStep terminal.
    Complete(AcceptedBlockBundle),
    /// Consecutive canonical block bodies. Used exclusively by snapshot
    /// suffix sync and bounded by [`MAX_BLOCK_BODY_BATCH`].
    BlockBodies(Vec<Vec<u8>>),
}

/// Response: the requested payload, or `None` when it is unavailable.
#[derive(Debug, Clone)]
pub struct GetRecentBlockResponse {
    pub height: u64,
    pub count: u16,
    pub payload_kind: RecentBlockPayloadKind,
    pub payload: Option<RecentBlockPayload>,
    /// Process-global inbound block-byte budget retained until the node has
    /// consumed this response. It is local flow-control state, never wire data.
    pub(crate) inbound_memory_permit: Option<std::sync::Arc<tokio::sync::OwnedSemaphorePermit>>,
    /// Process-wide outbound byte admission retained through the codec write.
    /// Local flow-control state; never serialized.
    pub(crate) outbound_memory_permit: Option<crate::outbound_budget::OutboundMemoryPermit>,
}

// ---------------------------------------------------------------------------
// HistoryStep terminal for O(1) snapshot sync
// ---------------------------------------------------------------------------

/// Request the fused HistoryStep terminal at one exact snapshot boundary.
#[derive(Debug, Clone)]
pub struct GetHistoryStepTerminalRequest {
    pub height: u64,
    pub block_hash: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct GetHistoryStepTerminalResponse {
    /// Exact request boundary echoed by the server so delayed responses cannot
    /// consume a newer manifest session for the same peer. This is the
    /// nonce-bearing chain-link block id.
    pub height: u64,
    pub block_hash: [u8; 32],
    /// Serialized fused HistoryStep terminal bound to `height` and the
    /// nonce-free semantic id of the same header. Node-side snapshot
    /// verification checks both ids against that authenticated staged header.
    pub terminal_bytes: Option<Vec<u8>>,
    /// Process-wide inbound byte admission retained until node-side terminal
    /// verification has consumed the response.
    pub(crate) inbound_memory_permit: Option<std::sync::Arc<tokio::sync::OwnedSemaphorePermit>>,
    /// Process-wide outbound byte admission retained through the codec write.
    pub(crate) outbound_memory_permit: Option<crate::outbound_budget::OutboundMemoryPermit>,
}

// ---------------------------------------------------------------------------
// State sync — manifest (step 1)
// ---------------------------------------------------------------------------

/// Request the state manifest: metadata + list of active segment IDs.
///
/// The manifest describes the state snapshot authorized by the corresponding
/// fused HistoryStep terminal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetStateManifestRequest {
    /// Requester's current tip height (0 for fresh nodes).
    pub requester_height: u64,
}

/// Manifest response: chain metadata + list of active segment IDs.
///
/// `tip_height = 0` means no snapshot is being advertised.
/// `tip_height`, `tip_hash`, and `cumulative_chainwork` describe the finalized
/// snapshot boundary `F`, not the peer's live tip.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GetStateManifestResponse {
    /// Finalized snapshot boundary height. 0 = "use block sync instead".
    pub tip_height: u64,
    pub tip_hash: [u8; 32],
    /// Exact cumulative chainwork at `tip_height`, as validated with headers.
    pub cumulative_chainwork: [u8; 32],
    pub log_slots: u32,
    pub active_slot_count: u64,
    pub alloc_counter: u64,
    /// Effective log segment size (determines each segment's slot capacity).
    pub eff_log: u8,
    /// Last immutable accepted bundle captured with this snapshot generation.
    /// The complete range `tip_height + 1 ..= bridge_tip_height` is served
    /// from generation-owned files and cannot be pruned by the live chain.
    pub bridge_tip_height: u64,
    pub bridge_tip_hash: [u8; 32],
    pub bridge_cumulative_chainwork: [u8; 32],
    /// IDs of all non-empty state segments.  Each must be fetched individually.
    pub segment_ids: Vec<u16>,
    /// Exact Poseidon subtree roots aligned with `segment_ids`. Each sparse
    /// payload is checked directly against its subtree root; the receiver then
    /// independently rebuilds the global root committed by the tip header.
    pub segment_roots: Vec<[u8; 32]>,
    /// Canonical sparse payload lengths aligned with `segment_ids`. The length
    /// commits the number of live entries before any payload allocation.
    pub segment_lengths: Vec<u32>,
}

// ---------------------------------------------------------------------------
// State sync — single segment (step 2)
// ---------------------------------------------------------------------------

/// Request one state segment by ID.
///
/// Segment data is bound to the exact manifest snapshot boundary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetStateSegmentRequest {
    pub segment_id: u16,
    /// Expected snapshot height from the manifest (for staleness guard).
    pub expected_tip_height: u64,
    /// Expected snapshot hash from the manifest. Height alone is not enough across
    /// reorgs or competing blocks at the same height.
    pub expected_tip_hash: [u8; 32],
}

/// Response: one encoded state segment (~3 MB).
///
/// `None` if the peer cannot serve this exact snapshot segment, usually
/// because the requested export expired or the peer never advertised it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetStateSegmentResponse {
    pub segment_id: u16,
    /// Exact snapshot height echoed from the request.
    pub expected_tip_height: u64,
    /// Exact snapshot hash echoed from the request. Together with the segment
    /// ID and libp2p request ID this prevents cross-session response reuse.
    pub expected_tip_hash: [u8; 32],
    pub eff_log: u8,
    /// Column data encoded by `noid_chain::storage::serial::encode_segment`.
    /// `None` if the peer cannot serve this segment.
    pub data: Option<Vec<u8>>,
    /// Inbound payload admission retained until the node consumes the segment.
    #[serde(skip)]
    pub(crate) inbound_memory_permit: Option<std::sync::Arc<tokio::sync::OwnedSemaphorePermit>>,
    /// Process-wide outbound byte admission retained through the codec write.
    #[serde(skip)]
    pub(crate) outbound_memory_permit: Option<crate::outbound_budget::OutboundMemoryPermit>,
}

// ---------------------------------------------------------------------------
// Mempool sync — request-response on peer connect
// ---------------------------------------------------------------------------

/// One bounded mempool exchange request.
///
/// `Pull` fills the late-join gap on peer connect. `Push` gives a newly
/// admitted transaction bounded independent first-hop paths; ordinary
/// propagation still uses gossipsub.
#[derive(Debug, Clone)]
pub enum MempoolRequest {
    Pull,
    Push {
        intent_bytes: Vec<u8>,
        /// Process-wide inbound byte admission retained until node-side
        /// submission has consumed the pushed intent. Local flow-control
        /// state; never serialized.
        inbound_memory_permit: Option<std::sync::Arc<tokio::sync::OwnedSemaphorePermit>>,
    },
}

/// Response: raw TxIntent bytes for every pending transaction.
///
/// The receiver submits each entry to its own mempool; duplicates are silently
/// ignored by the admission pipeline (hash already present → Ok(existing_hash)).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GetMempoolResponse {
    /// Raw `TxIntent` bytes, one per pending transaction.
    /// Empty when the peer's mempool is empty or the node is just starting.
    pub txs: Vec<Vec<u8>>,
    /// Process-wide inbound byte admission retained until node-side mempool
    /// submission has consumed every decoded intent. Local flow-control state;
    /// never serialized.
    #[serde(skip)]
    pub(crate) inbound_memory_permit: Option<std::sync::Arc<tokio::sync::OwnedSemaphorePermit>>,
    /// Process-wide outbound byte admission retained through the codec write.
    /// Local flow-control state; never serialized.
    #[serde(skip)]
    pub(crate) outbound_memory_permit: Option<crate::outbound_budget::OutboundMemoryPermit>,
}

// ---------------------------------------------------------------------------
// Block announcement (gossip)
// ---------------------------------------------------------------------------

/// Canonical block-gossip tagged union. A partial block has no representable
/// shape: gossip carries either one header or one complete accepted bundle.
#[derive(Debug, Clone)]
pub enum BlockGossipMsg {
    Header(BlockHeader),
    Complete(AcceptedBlockBundle),
}

const BLOCK_GOSSIP_MAGIC: [u8; 4] = *b"NBG1";
const BLOCK_GOSSIP_HEADER: u8 = 0;
const BLOCK_GOSSIP_COMPLETE: u8 = 1;
pub const BLOCK_GOSSIP_FIXED_BYTES: usize = 4 + 1 + 4;

impl BlockGossipMsg {
    pub fn from_bundle(bundle: AcceptedBlockBundle, inline: bool) -> Self {
        if inline {
            return Self::Complete(bundle);
        }
        let block_bytes = bundle.block_bytes();
        let header_end = BLOCK_WIRE_HEADER_OFFSET
            .checked_add(BLOCK_HEADER_WIRE_SIZE)
            .expect("canonical block header range fits usize");
        let header_bytes = block_bytes
            .get(BLOCK_WIRE_HEADER_OFFSET..header_end)
            .expect("AcceptedBlockBundle contains a canonical block header");
        Self::Header(
            BlockHeader::from_bytes(header_bytes)
                .expect("AcceptedBlockBundle contains a canonical BlockHeader"),
        )
    }

    pub fn encode(&self) -> Vec<u8> {
        let (tag, payload) = match self {
            Self::Header(header) => {
                let mut bytes = Vec::with_capacity(BLOCK_HEADER_WIRE_SIZE);
                header.encode(&mut bytes);
                (BLOCK_GOSSIP_HEADER, bytes)
            }
            Self::Complete(bundle) => (BLOCK_GOSSIP_COMPLETE, bundle.encode()),
        };
        let mut encoded = Vec::with_capacity(BLOCK_GOSSIP_FIXED_BYTES + payload.len());
        encoded.extend_from_slice(&BLOCK_GOSSIP_MAGIC);
        encoded.push(tag);
        encoded.extend_from_slice(
            &u32::try_from(payload.len())
                .expect("bounded block gossip payload length fits u32")
                .to_le_bytes(),
        );
        encoded.extend_from_slice(&payload);
        encoded
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, String> {
        if encoded.len() < BLOCK_GOSSIP_FIXED_BYTES {
            return Err("block gossip message is truncated".to_string());
        }
        if encoded[..4] != BLOCK_GOSSIP_MAGIC {
            return Err("invalid block gossip magic/version".to_string());
        }
        let tag = encoded[4];
        let payload_len = u32::from_le_bytes(encoded[5..9].try_into().unwrap()) as usize;
        match tag {
            BLOCK_GOSSIP_HEADER if payload_len != BLOCK_HEADER_WIRE_SIZE => {
                return Err("block gossip header length is noncanonical".to_string());
            }
            BLOCK_GOSSIP_COMPLETE if payload_len > MAX_ACCEPTED_BLOCK_BUNDLE_BYTES => {
                return Err("inline accepted-block bundle exceeds its wire cap".to_string());
            }
            BLOCK_GOSSIP_HEADER | BLOCK_GOSSIP_COMPLETE => {}
            _ => return Err("block gossip tag is unknown".to_string()),
        }
        let expected = BLOCK_GOSSIP_FIXED_BYTES
            .checked_add(payload_len)
            .ok_or_else(|| "block gossip length overflow".to_string())?;
        if encoded.len() != expected {
            return Err("block gossip message length is noncanonical".to_string());
        }
        let payload = &encoded[BLOCK_GOSSIP_FIXED_BYTES..];
        match tag {
            BLOCK_GOSSIP_HEADER => BlockHeader::from_bytes(payload)
                .map(Self::Header)
                .map_err(|error| format!("block gossip header decode failed: {error:?}")),
            BLOCK_GOSSIP_COMPLETE => AcceptedBlockBundle::decode(payload)
                .map(Self::Complete)
                .map_err(|error| format!("inline accepted-block bundle: {error}")),
            _ => unreachable!("tag was validated"),
        }
    }
}

// ---------------------------------------------------------------------------
// GossipSub topics
// ---------------------------------------------------------------------------

pub struct Topics;

impl Topics {
    pub const BLOCKS: &'static str = "/noid/devnet/blocks/1";
    pub const TXS: &'static str = "/noid/devnet/txs/1";
}

#[derive(Debug, Clone)]
pub struct NetworkTopics {
    pub blocks: String,
    pub txs: String,
    pub protocol_id: String,
}

impl NetworkTopics {
    pub fn for_network_cfg(cfg: &noid_chain::consensus::NetworkConfig) -> Self {
        Self {
            blocks: cfg.topic_blocks.to_string(),
            txs: cfg.topic_txs.to_string(),
            protocol_id: cfg.p2p_protocol_id.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bundle(height: u64) -> AcceptedBlockBundle {
        let mut header = noid_chain::consensus::genesis_header();
        header.height = height;
        let block = noid_chain::Block {
            header,
            transactions: Vec::new(),
        };
        let mut terminal = Vec::new();
        terminal.extend_from_slice(&noid_chain::HISTORY_STEP_TERMINAL_VERSION.to_le_bytes());
        terminal.extend_from_slice(&height.to_le_bytes());
        terminal.extend_from_slice(&noid_chain::block_header::semantic_header_id(&block.header));
        terminal.push(1);
        terminal.push(0xA5);
        AcceptedBlockBundle::try_from_parts(block.to_bytes(), terminal).unwrap()
    }

    #[test]
    fn gossip_round_trips_each_union_variant() {
        let bundle = bundle(9);
        let inline = BlockGossipMsg::from_bundle(bundle.clone(), true);
        let decoded = BlockGossipMsg::decode(&inline.encode()).unwrap();
        assert!(matches!(decoded, BlockGossipMsg::Complete(decoded) if decoded == bundle));

        let announcement = BlockGossipMsg::from_bundle(bundle.clone(), false);
        let decoded = BlockGossipMsg::decode(&announcement.encode()).unwrap();
        assert!(matches!(decoded, BlockGossipMsg::Header(header)
            if header.height == bundle.height()
                && noid_chain::hash_block_header(&header) == bundle.block_hash()));
    }

    #[test]
    fn gossip_has_no_partial_shape_or_unknown_tag() {
        let mut header = BlockGossipMsg::from_bundle(bundle(9), false).encode();
        header[4] = 2;
        assert!(BlockGossipMsg::decode(&header).is_err());

        let mut complete = BlockGossipMsg::from_bundle(bundle(9), true).encode();
        complete.truncate(complete.len() - 1);
        assert!(BlockGossipMsg::decode(&complete).is_err());
    }

    #[test]
    fn gossip_rejects_bundle_length_bomb_before_decode() {
        let mut encoded = BlockGossipMsg::from_bundle(bundle(9), true).encode();
        encoded[5..9].copy_from_slice(
            &u32::try_from(MAX_ACCEPTED_BLOCK_BUNDLE_BYTES + 1)
                .unwrap()
                .to_le_bytes(),
        );
        assert!(BlockGossipMsg::decode(&encoded).is_err());
    }
}
