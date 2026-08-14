// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! # noid_p2p — libp2p Networking for Paranoid
//!
//! Implements:
//! - GossipSub broadcast: blocks (/paranoid/blocks/1), txs (/paranoid/txs/1)
//! - Request-Response: headers, complete recent-block bundles, and HistoryStep terminals
//! - Identify + Ping for peer management

pub mod behaviour;
pub mod block_sync_codec;
mod event_dispatch;
pub mod header_protocol;
pub mod header_sync_codec;
pub mod history_step_codec;
mod identity_store;
mod inbound_budget;
pub mod mempool_sync_codec;
pub mod network;
pub mod network_profile;
pub mod object_codec;
pub mod object_protocol;
mod outbound_budget;
mod peer_diversity;
pub mod peer_store;
pub mod protocol;
pub mod state_manifest_codec;
pub mod state_segment_codec;

pub use network::{
    NetworkCommand, NetworkEvent, NetworkEventReceiver, NetworkEventRecvError, P2PNetwork,
    RequestFailureKind,
};
pub use protocol::{NetworkTopics, Topics};
