// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Node-side state machines for the header-first networking architecture.
//!
//! These modules deliberately contain no socket or database mutation code.
//! They make authority, source selection, mining readiness and health
//! independently testable before the legacy event loop is replaced.

pub mod chain_committer;
pub mod header_dag;
pub mod header_planner;
pub mod health;
pub mod mining_readiness;
pub mod object_fetcher;
pub mod snapshot_header_staging;
pub mod snapshot_sync;
pub mod suffix_sync;
pub mod sync_plan;
pub mod topology;
pub mod types;
pub mod verifier_pool;

pub use types::{
    BlockBodyClaimId, ChainPoint, ChainView, FailureDomain, ObjectClaimId, ObjectId, PlanId,
    SnapshotId, StateSegmentId, TerminalClaimId, TerminalObjectId,
};
