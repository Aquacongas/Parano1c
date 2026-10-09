// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Exact, source-independent identifiers used by network actors.

use serde::{Deserialize, Serialize};

pub use noid_p2p::object_protocol::{
    BlockBodyClaimId, BlockBodyObjectId, ChainPoint, Hash32, ObjectClaimId, ObjectId, SnapshotId,
    StateSegmentId, TerminalClaimId, TerminalObjectId,
};

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
