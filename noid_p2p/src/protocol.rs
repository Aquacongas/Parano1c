// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

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

/// Response: serialized BlockHeader bytes, one per header (276 bytes each).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetHeadersResponse {
    pub headers: Vec<Vec<u8>>,
}

// ---------------------------------------------------------------------------
// Block pull: full block + proof
// ---------------------------------------------------------------------------

/// Request a recent full block (only last FINALITY_DEPTH blocks available).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetRecentBlockRequest {
    pub height: u64,
}

/// Response: full block bytes + ZK proof bytes.
///
/// Both fields are `None` when the peer does not have the block.
/// `block_proof_bytes` is `None` (not empty) for coinbase-only blocks that
/// carry no user transactions — those blocks have no ZK proof to serve.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetRecentBlockResponse {
    /// `Block::to_bytes()` — header + transactions.
    pub block_bytes: Option<Vec<u8>>,
    /// `BlockProof` bincode bytes.  `None` for coinbase-only blocks.
    pub block_proof_bytes: Option<Vec<u8>>,
}

// ---------------------------------------------------------------------------
// Recursive chain proof
// ---------------------------------------------------------------------------

/// Get the current recursive chain proof (6.5 KB, O(1) sync).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetRecursiveProofRequest;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetRecursiveProofResponse {
    /// Serialized RecursiveBlockProof bytes (~6.5 KB).
    pub proof_bytes: Option<Vec<u8>>,
    /// Serialized tip BlockHeader bytes (276 bytes).
    pub tip_header_bytes: Option<Vec<u8>>,
}

// ---------------------------------------------------------------------------
// State sync — manifest (step 1)
// ---------------------------------------------------------------------------

/// Request the state manifest: metadata + list of active segment IDs.
///
/// This is the first step of snapshot sync.  The manifest is tiny (~few KB)
/// regardless of state size and establishes what needs to be downloaded.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetStateManifestRequest {
    /// Requester's current tip height (0 for fresh nodes).
    pub requester_height: u64,
}

/// Manifest response: chain metadata + list of active segment IDs.
///
/// Does NOT include segment data — segments are fetched individually.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GetStateManifestResponse {
    /// Tip height at snapshot time.  0 = "use block sync instead".
    pub tip_height: u64,
    pub tip_hash: [u8; 32],
    pub log_slots: u32,
    pub active_slot_count: u64,
    pub alloc_counter: u64,
    /// Effective log segment size (determines each segment's data size).
    pub eff_log: u8,
    /// IDs of all non-empty state segments.  Each must be fetched individually.
    pub segment_ids: Vec<u16>,
    /// Wire-encoded recent headers (last ~155 blocks) for PoW validation.
    pub recent_headers: Vec<Vec<u8>>,
    /// TX hashes per block for nullifier-set rebuild (last ANCHOR_DEPTH blocks).
    pub nullifier_blocks: Vec<Vec<[u8; 32]>>,
}

// ---------------------------------------------------------------------------
// State sync — single segment (step 2)
// ---------------------------------------------------------------------------

/// Request one state segment by ID.
///
/// The `tip_height` must match the manifest's tip_height.  The peer rejects
/// requests where its current tip has moved beyond `tip_height + FINALITY_DEPTH`
/// to prevent serving stale segments from a forked state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetStateSegmentRequest {
    pub segment_id: u16,
    /// Expected tip height from the manifest (for staleness guard).
    pub expected_tip_height: u64,
}

/// Response: one encoded state segment (~3 MB).
///
/// `None` if the peer no longer has this segment at the expected tip height.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetStateSegmentResponse {
    pub segment_id: u16,
    pub eff_log: u8,
    /// Column data encoded by `noid_chain::storage::serial::encode_segment`.
    /// `None` if the peer cannot serve this segment.
    pub data: Option<Vec<u8>>,
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
    },
}

// ---------------------------------------------------------------------------
// Recursive proof gossip message
// ---------------------------------------------------------------------------

/// Gossipsub message broadcast when the recursive chain proof advances.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecursiveProofGossipMsg {
    pub height: u64,
    pub tip_hash: [u8; 32],
    /// `RecursiveBlockProof` bincode bytes (~6.5 KB).
    pub proof_bytes: Vec<u8>,
}

// ---------------------------------------------------------------------------
// GossipSub topics
// ---------------------------------------------------------------------------

pub struct Topics;

impl Topics {
    pub const BLOCKS: &'static str = "/noid/devnet/blocks/1";
    pub const TXS: &'static str = "/noid/devnet/txs/1";
    pub const REC_PROOFS: &'static str = "/noid/devnet/recproofs/1";
}

#[derive(Debug, Clone)]
pub struct NetworkTopics {
    pub blocks: String,
    pub txs: String,
    pub rec_proofs: String,
    pub protocol_id: String,
}

impl NetworkTopics {
    pub fn for_network_cfg(cfg: &noid_chain::consensus::NetworkConfig) -> Self {
        Self {
            blocks: cfg.topic_blocks.to_string(),
            txs: cfg.topic_txs.to_string(),
            rec_proofs: cfg.topic_rec_proofs.to_string(),
            protocol_id: cfg.p2p_protocol_id.to_string(),
        }
    }
}
