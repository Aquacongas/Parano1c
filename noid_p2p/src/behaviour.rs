// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Combined libp2p NetworkBehaviour for the Paranoid full node.
//!
//! Composes:
//! - `gossipsub` — block and tx broadcast
//! - `request_response` — direct block sync (GetHeaders, GetRecentBlock, GetRecursiveProof)
//! - `identify` — protocol/address advertisement (required by gossipsub routing)
//! - `ping` — liveness probing

use libp2p::{
    gossipsub, identify, ping, request_response, swarm::NetworkBehaviour, StreamProtocol,
};

use crate::protocol::{
    GetHeadersRequest, GetHeadersResponse, GetRecentBlockRequest, GetRecentBlockResponse,
    GetRecursiveProofRequest, GetRecursiveProofResponse, GetStateSnapshotRequest,
    GetStateSnapshotResponse,
};

/// All P2P behaviours composed via the derive macro.
///
/// Field order matters: libp2p polls in struct order.
/// gossipsub and request_response are polled first for lower latency.
#[derive(NetworkBehaviour)]
pub struct NodeBehaviour {
    /// Block and TxIntent gossip broadcast.
    pub gossipsub: gossipsub::Behaviour,

    /// Typed request-response for chain sync (headers, blocks, recursive proof).
    pub chain_sync: request_response::cbor::Behaviour<GetHeadersRequest, GetHeadersResponse>,

    /// Block sync (recent blocks).
    pub block_sync:
        request_response::cbor::Behaviour<GetRecentBlockRequest, GetRecentBlockResponse>,

    /// Recursive proof sync (O(1) light client sync).
    pub proof_sync:
        request_response::cbor::Behaviour<GetRecursiveProofRequest, GetRecursiveProofResponse>,

    /// Peer identification — required for gossipsub routing.
    pub identify: identify::Behaviour,

    /// Liveness probing.
    pub ping: ping::Behaviour,

    /// State snapshot sync — allows joining nodes to download the full current
    /// state without block history (Paranoid's designed sync mechanism).
    pub snapshot_sync:
        request_response::cbor::Behaviour<GetStateSnapshotRequest, GetStateSnapshotResponse>,
}

impl NodeBehaviour {
    /// Build the combined behaviour from a libp2p keypair.
    ///
    /// `protocol_id` is the network-specific prefix used for all sync stream
    /// protocols (e.g. `/noid/mainnet/1.0.0`).  This ensures mainnet and
    /// testnet nodes can never accidentally sync with each other.
    pub fn new(
        key: &libp2p::identity::Keypair,
        protocol_id: &str,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        use libp2p::gossipsub::MessageAuthenticity;
        use libp2p::request_response::ProtocolSupport;
        use std::time::Duration;

        // Gossipsub config tuned for small networks (2–50 peers).
        //
        // flood_publish=true: publish to ALL connected peers, not just mesh peers.
        // This ensures propagation with 2 nodes where the mesh can't form (D=6).
        //
        // mesh_n=2, mesh_n_low=1, mesh_n_high=4: allow small meshes so GRAFT
        // succeeds and the mesh forms when there are only a few peers.
        //
        // heartbeat_interval=1s: fast mesh maintenance for local testing.
        let gossipsub_cfg = gossipsub::ConfigBuilder::default()
            .heartbeat_interval(Duration::from_millis(700))
            .mesh_n(2)
            .mesh_n_low(1)
            .mesh_n_high(4)
            .mesh_outbound_min(0)
            .flood_publish(true)
            .validation_mode(gossipsub::ValidationMode::Strict)
            .message_id_fn(|msg| {
                // Content-addressed: hash the message data (not author+seq).
                let hash = blake3::hash(&msg.data);
                gossipsub::MessageId::from(hash.as_bytes().to_vec())
            })
            .build()
            .map_err(|e| format!("gossipsub config: {e}"))?;

        let gossipsub =
            gossipsub::Behaviour::new(MessageAuthenticity::Signed(key.clone()), gossipsub_cfg)
                .map_err(|e| format!("gossipsub: {e}"))?;

        // Network-aware protocol IDs — use the network's protocol_id prefix.
        // This ensures mainnet and testnet sync protocols are fully isolated:
        // a mainnet node and a testnet node will never negotiate a shared
        // stream protocol and therefore can never accidentally sync.
        let chain_sync = request_response::cbor::Behaviour::new(
            [(
                StreamProtocol::try_from_owned(format!("{}/sync/headers/1", protocol_id))?,
                ProtocolSupport::Full,
            )],
            request_response::Config::default().with_request_timeout(Duration::from_secs(30)),
        );

        let block_sync = request_response::cbor::Behaviour::new(
            [(
                StreamProtocol::try_from_owned(format!("{}/sync/block/1", protocol_id))?,
                ProtocolSupport::Full,
            )],
            request_response::Config::default()
                .with_request_timeout(Duration::from_secs(30))
                .with_max_concurrent_streams(64),
        );

        let proof_sync = request_response::cbor::Behaviour::new(
            [(
                StreamProtocol::try_from_owned(format!("{}/sync/proof/1", protocol_id))?,
                ProtocolSupport::Full,
            )],
            request_response::Config::default().with_request_timeout(Duration::from_secs(10)),
        );

        let identify = identify::Behaviour::new(
            identify::Config::new("/noid/1.0.0".into(), key.public())
                .with_push_listen_addr_updates(true),
        );

        let ping = ping::Behaviour::new(ping::Config::new().with_interval(Duration::from_secs(30)));

        let snapshot_sync = request_response::cbor::Behaviour::new(
            [(
                StreamProtocol::try_from_owned(format!("{}/sync/snapshot/1", protocol_id))?,
                ProtocolSupport::Full,
            )],
            // Generous timeout: full state transfer can be several hundred MB
            // at high occupancy; 120 s is safe even on slow connections.
            request_response::Config::default()
                .with_request_timeout(Duration::from_secs(120))
                .with_max_concurrent_streams(32),
        );

        Ok(Self {
            gossipsub,
            chain_sync,
            block_sync,
            proof_sync,
            identify,
            ping,
            snapshot_sync,
        })
    }
}
