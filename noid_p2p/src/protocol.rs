// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Wire message types for the Paranoid P2P protocol (/paranoid/1.0.0).

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Request-Response protocol (direct peer queries)
// ---------------------------------------------------------------------------

/// Get block headers by height range.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetHeadersRequest {
    pub start_height: u64,
    pub count: u16, // max 512
}

/// Response: serialized BlockHeader bytes, one per header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetHeadersResponse {
    pub headers: Vec<Vec<u8>>, // each entry = 276 bytes (wire format)
}

/// Get a recent full block (only last 18 blocks available).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetRecentBlockRequest {
    pub height: u64,
}

/// Response: serialized Block bytes, or empty if not available.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetRecentBlockResponse {
    pub block_bytes: Option<Vec<u8>>,
}

/// Get the current recursive chain proof (6.5 KB, O(1) sync).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetRecursiveProofRequest;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetRecursiveProofResponse {
    /// Serialized RecursiveBlockProof bytes (6.5 KB).
    pub proof_bytes: Option<Vec<u8>>,
    /// Serialized tip BlockHeader bytes (276 bytes).
    pub tip_header_bytes: Option<Vec<u8>>,
}

// ---------------------------------------------------------------------------
// GossipSub topics
// ---------------------------------------------------------------------------

/// Topics used for broadcast gossip.
///
/// Use `NetworkTopics::for_network(kind)` in production — these constants
/// are kept for backward-compat / devnet default only.
pub struct Topics;

impl Topics {
    /// Devnet defaults (used when no network is specified).
    pub const BLOCKS: &'static str = "/noid/devnet/blocks/1";
    pub const TXS: &'static str = "/noid/devnet/txs/1";
}

/// Per-network topic configuration.
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
