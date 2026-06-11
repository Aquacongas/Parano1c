// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! # noid_p2p — libp2p Networking for Paranoid
//!
//! Implements:
//! - GossipSub broadcast: blocks (/paranoid/blocks/1), txs (/paranoid/txs/1)
//! - Request-Response: headers, recent blocks, recursive proof (O(1) sync)
//! - Identify + Ping for peer management

pub mod behaviour;
pub mod network;
pub mod peer_store;
pub mod protocol;

pub use network::{NetworkCommand, NetworkEvent, P2PNetwork};
pub use protocol::{NetworkTopics, Topics};
