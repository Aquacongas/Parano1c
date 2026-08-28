// SPDX-License-Identifier: Apache-2.0

//! Compatibility facade for the shared networking/sync implementation.
//!
//! Full desktop node and mobile node now use the same networking,
//! sync-plan, header-DAG, object-fetching and chain-commit logic.

pub use noid_networking::*;

pub use noid_networking::{
    chain_committer, header_dag, health, mining_readiness, object_fetcher, snapshot_sync,
    suffix_sync, sync_plan, topology, types, verifier_pool,
};
