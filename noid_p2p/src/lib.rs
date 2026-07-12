// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! # noid_p2p — libp2p Networking for Paranoid
//!
//! Implements:
//! - GossipSub broadcast: blocks (/paranoid/blocks/1), txs (/paranoid/txs/1)
//! - Request-Response: headers, recent blocks, and the public checkpoint proof endpoint
//! - Identify + Ping for peer management

pub mod behaviour;
pub mod block_sync_codec;
pub mod history_proof_codec;
pub mod network;
mod outbound_budget;
pub mod peer_store;
pub mod protocol;
pub mod state_segment_codec;

pub use network::{
    NetworkCommand, NetworkEvent, NetworkEventReceiver, NetworkEventRecvError, P2PNetwork,
};
pub use protocol::{NetworkTopics, Topics};
