// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Exact, source-independent identifiers used by network actors.

use serde::{Deserialize, Serialize};

pub type Hash32 = [u8; 32];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ChainPoint {
    pub height: u64,
    pub hash: Hash32,
}

impl ChainPoint {
    pub const fn new(height: u64, hash: Hash32) -> Self {
        Self { height, hash }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainView {
    pub tip: ChainPoint,
    pub cumulative_work: Hash32,
    pub finalized: ChainPoint,
    pub sequence: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FailureDomain(pub u64);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PlanId(pub Hash32);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BlockBodyClaimId {
    pub height: u64,
    pub block_hash: Hash32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BlockBodyObjectId {
    pub claim: BlockBodyClaimId,
    pub byte_digest: Hash32,
    pub encoded_len: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TerminalClaimId {
    pub height: u64,
    pub semantic_header_id: Hash32,
    pub proof_class: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TerminalObjectId {
    pub claim: TerminalClaimId,
    pub byte_digest: Hash32,
    pub encoded_len: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SnapshotId {
    pub boundary: ChainPoint,
    pub state_root: Hash32,
    pub manifest_digest: Hash32,
    pub format_version: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct StateSegmentId {
    pub snapshot: SnapshotId,
    pub segment_id: u16,
    pub segment_root: Hash32,
    pub encoded_len: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ObjectClaimId {
    BlockBody(BlockBodyClaimId),
    Terminal(TerminalClaimId),
    SnapshotManifest(SnapshotId),
    StateSegment(StateSegmentId),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ObjectId {
    BlockBody(BlockBodyObjectId),
    Terminal(TerminalObjectId),
    SnapshotManifest(SnapshotId),
    StateSegment(StateSegmentId),
}

impl ObjectId {
    pub const fn claim(self) -> ObjectClaimId {
        match self {
            Self::BlockBody(object) => ObjectClaimId::BlockBody(object.claim),
            Self::Terminal(object) => ObjectClaimId::Terminal(object.claim),
            Self::SnapshotManifest(snapshot) => ObjectClaimId::SnapshotManifest(snapshot),
            Self::StateSegment(segment) => ObjectClaimId::StateSegment(segment),
        }
    }

    pub const fn encoded_len(self) -> Option<u32> {
        match self {
            Self::BlockBody(object) => Some(object.encoded_len),
            Self::Terminal(object) => Some(object.encoded_len),
            Self::SnapshotManifest(_) => None,
            Self::StateSegment(segment) => Some(segment.encoded_len),
        }
    }
}
