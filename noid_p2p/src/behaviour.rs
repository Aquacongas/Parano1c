// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Combined libp2p NetworkBehaviour for the Paranoid full node.
//!
//! ## Peer discovery stack
//!
//! Paranoid uses three complementary mechanisms, mirroring the approach taken
//! by Substrate/Polkadot:
//!
//! 1. **Bootstrap nodes** — hard-coded seed addresses dialled on startup.
//! 2. **Kademlia DHT** — once connected, random `FIND_NODE` walks propagate
//!    the network view across all nodes.  Critical lesson from all libp2p
//!    chains: Kademlia is useless without Identify hooked to it.  Every time
//!    `identify::Event::Received` fires the handler must call
//!    `kad.add_address(peer_id, addr)` for every listen address.  Without
//!    this, remote nodes cannot put us into their routing tables and discovery
//!    stops at the boot nodes.
//! 3. **mDNS** — UDP broadcast on the local network.  Useful for local dev
//!    and private clusters; has no effect on the public internet.
//!
//! Additionally, **GossipSub peer exchange** (`do_px`) lets mesh peers share
//! peer lists in PRUNE messages, giving organic topology growth on top of
//! what Kademlia provides.

use std::time::Duration;

use libp2p::{
    gossipsub, identify, kad, mdns, ping, request_response, swarm::NetworkBehaviour, StreamProtocol,
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

    /// Kademlia DHT — primary peer discovery mechanism.
    ///
    /// Performs random `FIND_NODE` walks once connected to bootstrap peers.
    /// MUST be integrated with `identify`: every `identify::Event::Received`
    /// must call `kad.add_address()` to populate the routing table.
    pub kad: kad::Behaviour<kad::store::MemoryStore>,

    /// mDNS — LAN peer discovery (zero-config for local clusters and dev).
    ///
    /// Silent on the public internet (UDP broadcast is LAN-scoped).
    /// Discovered peers are immediately dialled.
    pub mdns: mdns::tokio::Behaviour,

    /// Peer identification — required for Kademlia routing table population.
    ///
    /// Every `identify::Event::Received` MUST call `kad.add_address()` for
    /// each listen address.  This is the #1 lesson from all libp2p chains:
    /// Kademlia alone cannot discover peers beyond boot nodes without Identify.
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

        // ----------------------------------------------------------------
        // GossipSub
        // ----------------------------------------------------------------
        //
        // Tuned for heterogeneous network sizes (2 → 10 000+ peers):
        //
        //  flood_publish=true   publish to ALL connected peers, not just mesh
        //                       peers. Ensures propagation with 2 nodes where
        //                       the mesh can't form (D=6 minimum).
        //
        //  mesh_n / _low / _high  scaled-down so a mesh FORMS with as few as
        //                         2 nodes in local tests; still works at scale.
        //
        //  do_px()              enable peer exchange in PRUNE messages so nodes
        //                       organically discover neighbours beyond their
        //                       initial seed connections.
        //
        //  heartbeat 700ms      fast mesh maintenance for dev/test; fine at
        //                       scale (Ethereum uses 700ms too).
        let gossipsub_cfg = gossipsub::ConfigBuilder::default()
            .heartbeat_interval(Duration::from_millis(700))
            .mesh_n(6)
            .mesh_n_low(4)
            .mesh_n_high(12)
            .mesh_outbound_min(2)
            .flood_publish(true)
            // Peer exchange: when the mesh prunes a peer it advertises up to 6
            // alternative peers (PeerInfo with signed address records). The
            // receiving node dials those peers automatically, enabling organic
            // topology growth without DNS seeds or manual configuration.
            .do_px()
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

        // ----------------------------------------------------------------
        // Request-response protocols
        // ----------------------------------------------------------------
        //
        // Network-aware protocol IDs — use the network's protocol_id prefix.
        // This ensures mainnet and testnet sync protocols are fully isolated.
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

        // ----------------------------------------------------------------
        // Kademlia DHT
        // ----------------------------------------------------------------
        //
        // Network-isolated: each chain gets its own protocol ID so mainnet
        // and testnet never pollute each other's routing tables.
        //
        // KBucketInserts::OnConnected: only insert peers we actually have
        // open connections to. This prevents phantom entries from stale
        // `FIND_NODE` responses from filling the table.
        let kad_protocol = StreamProtocol::try_from_owned(format!("{}/kad/1.0.0", protocol_id))?;
        let mut kad_cfg = kad::Config::new(kad_protocol);
        kad_cfg
            // Refresh the routing table every 5 minutes.
            .set_replication_factor(std::num::NonZeroUsize::new(20).unwrap())
            .set_query_timeout(Duration::from_secs(60))
            // Only insert peers into the routing table when we have an
            // established connection (not from hearsay in FIND_NODE responses).
            .set_kbucket_inserts(kad::BucketInserts::OnConnected);
        let kad_store = kad::store::MemoryStore::new(key.public().to_peer_id());
        let mut kad = kad::Behaviour::with_config(key.public().to_peer_id(), kad_store, kad_cfg);
        // Start in server mode: respond to Kademlia queries from other nodes.
        // Client mode would only query, not serve — wrong for a full node.
        kad.set_mode(Some(kad::Mode::Server));

        // ----------------------------------------------------------------
        // mDNS (LAN discovery)
        // ----------------------------------------------------------------
        //
        // Broadcasts UDP packets on the local network. Peers that respond
        // are immediately dialled. Completely harmless on the public internet
        // (broadcast is LAN-scoped; no external packets are sent).
        // This makes local clusters and dev setups zero-config.
        let mdns = mdns::tokio::Behaviour::new(
            mdns::Config {
                // Re-query every 60s so long-lived LANs stay connected.
                query_interval: Duration::from_secs(60),
                ..Default::default()
            },
            key.public().to_peer_id(),
        )?;

        // ----------------------------------------------------------------
        // Identify
        // ----------------------------------------------------------------
        //
        // Tells connected peers our listen addresses and supported protocols.
        // CRITICAL: the event handler in network.rs MUST call
        //   `kad.add_address(peer_id, addr)` for every listen address
        //   received via `identify::Event::Received`.
        // Without this, Kademlia cannot populate its routing table because
        // the DHT only stores addresses it has been explicitly told about.
        let identify = identify::Behaviour::new(
            identify::Config::new("/noid/1.0.0".into(), key.public())
                .with_push_listen_addr_updates(true)
                // Re-identify periodically so address changes propagate.
                .with_interval(Duration::from_secs(300)),
        );

        let ping = ping::Behaviour::new(ping::Config::new().with_interval(Duration::from_secs(30)));

        Ok(Self {
            gossipsub,
            chain_sync,
            block_sync,
            proof_sync,
            kad,
            mdns,
            identify,
            ping,
            snapshot_sync,
        })
    }
}
