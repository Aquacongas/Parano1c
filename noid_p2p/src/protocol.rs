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
// State snapshot sync
// ---------------------------------------------------------------------------

/// Request a full state snapshot for initial sync.
///
/// Paranoid does NOT store block history (DA delete-immediately policy).
/// New nodes synchronise by downloading the CURRENT STATE from a peer,
/// not by replaying blocks from genesis.
///
/// The state is proven valid by the recursive chain proof (see noid_recursive).
/// For testnet, nodes accept snapshots from trusted peers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetStateSnapshotRequest {
    /// Requester's current tip height (0 for fresh nodes).
    pub requester_height: u64,
}

/// One serialised state segment (seg_id, effective_log, encoded columns).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateSegmentEntry {
    pub seg_id: u16,
    pub eff_log: u8,
    /// Column data encoded by `noid_chain::storage::serial::encode_segment`.
    pub data: Vec<u8>,
}

/// Full current state snapshot for a joining node.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GetStateSnapshotResponse {
    /// Tip height at snapshot time. 0 = "use block sync instead".
    pub tip_height: u64,
    pub tip_hash: [u8; 32],
    pub log_slots: u32,
    pub active_slot_count: u64,
    pub alloc_counter: u64,
    /// Non-zero state segments (everything the peer's SegmentedFriState holds).
    pub segments: Vec<StateSegmentEntry>,
    /// Wire-encoded recent headers (last ~155 blocks) for validation.
    pub recent_headers: Vec<Vec<u8>>,
    /// TX hashes per block for nullifier-set rebuild (last ANCHOR_DEPTH blocks).
    pub nullifier_blocks: Vec<Vec<[u8; 32]>>,
}

// ---------------------------------------------------------------------------
// Block gossip wire message
// ---------------------------------------------------------------------------

/// Gossipsub message for block announcements.
///
/// `block_proof_bytes` carries the `BlockProof` (bincode-encoded) alongside
/// the block. For coinbase-only blocks (no user transactions)
/// `block_proof_bytes` is empty — those blocks are validated by native
/// consensus only (PoW + state_root). The `STUB_MARKER [1u8;32]` in the
/// header guards against fake "no proof" blocks that contain user transactions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockGossipMsg {
    /// `Block::to_bytes()` — header + transactions.
    pub block_bytes: Vec<u8>,
    /// `BlockProof` bincode bytes; empty for coinbase-only blocks.
    pub block_proof_bytes: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Recursive proof gossip message
// ---------------------------------------------------------------------------

/// Gossipsub message broadcast when the recursive chain proof advances.
///
/// Sent by any node (miner or relay) ~2s after a block is committed, once
/// `prove_recursive_step` completes. Receiving nodes verify via
/// `verify_step_stark_only` before storing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecursiveProofGossipMsg {
    /// Height of the block this proof covers.
    pub height: u64,
    /// Hash of the tip block at proof time (for staleness checks).
    pub tip_hash: [u8; 32],
    /// `RecursiveBlockProof` bincode bytes (~6.5 KB).
    pub proof_bytes: Vec<u8>,
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
    pub const REC_PROOFS: &'static str = "/noid/devnet/recproofs/1";
}

/// Per-network topic configuration.
#[derive(Debug, Clone)]
pub struct NetworkTopics {
    pub blocks: String,
    pub txs: String,
    /// Topic for `RecursiveProofGossipMsg` broadcasts.
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
