// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Wire message types for the Paranoid P2P protocol.
//!
//! ## Block propagation
//!
//! Blocks use dual-mode gossip:
//!
//! 1. **Inline** (common case): small blocks (coinbase-only or few txs, total
//!    < 1 MB) are sent in full via gossipsub.  Receivers apply immediately —
//!    no round-trip, no race condition.
//!
//! 2. **Compact** (large blocks): header-only gossip (~310 bytes).  Receivers
//!    pull the full block + proof via `GetRecentBlockRequest`.  This mirrors
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
// Block pull: full block + proof
// ---------------------------------------------------------------------------

/// Request a retained full block from the bounded suffix window.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetRecentBlockRequest {
    pub height: u64,
}

/// Response: full block bytes + BlockProof bytes + public AuthGKR sidecar bytes.
///
/// All optional fields are `None` when the peer does not have the block.
/// `block_proof_bytes` and `block_auth_sidecar_bytes` are `None` (not empty)
/// for coinbase-only blocks that carry no user transactions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetRecentBlockResponse {
    pub height: u64,
    /// `Block::to_bytes()` — header + transactions.
    pub block_bytes: Option<Vec<u8>>,
    /// `BlockProof` bincode bytes.  `None` for coinbase-only blocks.
    pub block_proof_bytes: Option<Vec<u8>>,
    /// `BlockAuthSidecar` bincode bytes.  `None` for coinbase-only blocks.
    pub block_auth_sidecar_bytes: Option<Vec<u8>>,
    /// Serialized Link terminal envelope attesting the header's advanced
    /// `attested_coverage`.  `None` when the block keeps its parent's coverage.
    pub coverage_attestation_bytes: Option<Vec<u8>>,
    /// Process-global inbound block-byte budget retained until the node has
    /// consumed this response. It is local flow-control state, never wire data.
    #[serde(skip)]
    pub(crate) inbound_memory_permit: Option<std::sync::Arc<tokio::sync::OwnedSemaphorePermit>>,
    /// Process-wide outbound byte admission retained through the codec write.
    /// Local flow-control state; never serialized.
    #[serde(skip)]
    pub(crate) outbound_memory_permit: Option<crate::outbound_budget::OutboundMemoryPermit>,
}

// ---------------------------------------------------------------------------
// Public history proof
// ---------------------------------------------------------------------------

/// Request the constant-size selected-history proof at one exact manifest
/// boundary. Height alone is insufficient across a reorg; the server must
/// return no proof unless both fields still name its canonical retained chain.
///
/// A peer returns `None` until verified selected-history coverage reaches this
/// finalized retained boundary. Snapshot acceptance depends on the local
/// recursive decider and the node-selected header chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetHistoryProofRequest {
    pub height: u64,
    pub block_hash: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetHistoryProofResponse {
    /// Exact request boundary echoed by the server so delayed responses cannot
    /// consume a newer manifest session for the same peer.
    pub height: u64,
    pub block_hash: [u8; 32],
    /// Serialized selected-history terminal package bytes.
    pub proof_bytes: Option<Vec<u8>>,
    /// Canonical serialized tip BlockHeader bytes (212 bytes).
    pub tip_header_bytes: Option<Vec<u8>>,
    /// Process-wide inbound byte admission retained until node-side proof
    /// verification has consumed the response.
    #[serde(skip)]
    pub(crate) inbound_memory_permit: Option<std::sync::Arc<tokio::sync::OwnedSemaphorePermit>>,
    /// Process-wide outbound byte admission retained through the codec write.
    #[serde(skip)]
    pub(crate) outbound_memory_permit: Option<crate::outbound_budget::OutboundMemoryPermit>,
}

// ---------------------------------------------------------------------------
// State sync — manifest (step 1)
// ---------------------------------------------------------------------------

/// Request the state manifest: metadata + list of active segment IDs.
///
/// The manifest describes the state snapshot authorized by the corresponding
/// O(1) selected-history terminal package.
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
    /// Effective log segment size (determines each segment's data size).
    pub eff_log: u8,
    /// IDs of all non-empty state segments.  Each must be fetched individually.
    pub segment_ids: Vec<u16>,
    /// Raw FRI segment roots aligned with `segment_ids`. These authenticate
    /// downloaded payloads; after decoding, the receiver independently rebuilds
    /// the exact sparse UTXO root and compares it with the tip header.
    pub segment_roots: Vec<[u8; 32]>,
    /// Wire-encoded recent headers (last ~155 blocks) for PoW validation.
    pub recent_headers: Vec<Vec<u8>>,
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

/// Request all pending transactions from a peer.
/// Sent immediately when a new peer connects to ensure both sides have
/// each other's mempool. This is necessary because gossipsub only propagates
/// NEW events — existing mempool entries are not retransmitted to late-joining
/// peers via gossipsub (which would be deduplicated away).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GetMempoolRequest;

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
// Compact block announcement (gossip)
// ---------------------------------------------------------------------------

/// Gossipsub block message — compact announcement OR inline full block.
///
/// For small blocks (coinbase-only or few txs) that fit within the gossipsub
/// message size limit (2 MB), the full block + proof are inlined.  This
/// eliminates the request-response round-trip, removing the race condition
/// where the pull target hasn't fetched the block yet.
///
/// For large blocks (many txs, proof > 1 MB), only the header is sent and
/// receivers pull the full block via `GetRecentBlockRequest`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BlockGossipMsg {
    /// Compact: header only.  Receivers must pull full block.
    Compact {
        height: u64,
        hash: [u8; 32],
        header_bytes: Vec<u8>,
    },
    /// Inline: full block + proof in gossip message.  No pull needed.
    Inline {
        height: u64,
        hash: [u8; 32],
        block_bytes: Vec<u8>,
        block_proof_bytes: Vec<u8>,
        block_auth_sidecar_bytes: Vec<u8>,
        /// Serialized Link terminal envelope for coverage-advancing blocks.
        /// Empty when the header keeps its parent's `attested_coverage`.
        coverage_attestation_bytes: Vec<u8>,
    },
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
