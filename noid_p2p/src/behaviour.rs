// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

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
    autonat, dcutr, gossipsub, identify, kad, mdns, ping, relay, request_response,
    swarm::NetworkBehaviour, StreamProtocol,
};
use libp2p_connection_limits as connection_limits;
use noid_chain::consensus::wire_limits::GOSSIP_MAX_TRANSMIT_BYTES;
use noid_poseidon2b::native::poseidon2b_hash_bytes;

const GOSSIPSUB_MESSAGE_ID_DOMAIN: &[u8] = b"NOID_P2P_GOSSIPSUB_MESSAGE_ID";

use crate::block_sync_codec::BlockSyncCodec;
use crate::header_sync_codec::HeaderSyncCodec;
use crate::history_proof_codec::HistoryProofCodec;
use crate::mempool_sync_codec::MempoolSyncCodec;
use crate::state_manifest_codec::StateManifestCodec;
use crate::state_segment_codec::StateSegmentCodec;

/// All P2P behaviours composed via the derive macro.
///
/// Field order matters: libp2p polls in struct order.
/// gossipsub and request_response are polled first for lower latency.
#[derive(NetworkBehaviour)]
pub struct NodeBehaviour {
    /// Block and TxIntent gossip broadcast.
    pub gossipsub: gossipsub::Behaviour,

    /// Typed request-response for chain sync (headers, blocks, history proof).
    pub chain_sync: request_response::Behaviour<HeaderSyncCodec>,

    /// Block sync (recent blocks).
    pub block_sync: request_response::Behaviour<BlockSyncCodec>,

    /// History proof sync (O(1) chain-history verification).
    pub proof_sync: request_response::Behaviour<HistoryProofCodec>,

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

    /// AutoNAT — probes whether this node is reachable from the internet.
    ///
    /// Periodically asks connected peers to dial us back.  If all probes
    /// fail, the node is behind NAT and should activate the relay client
    /// to make itself reachable.
    pub autonat: autonat::Behaviour,

    /// Circuit relay client — routes traffic through relay nodes when
    /// direct connections are not possible (NAT, firewall).
    ///
    /// When AutoNAT confirms NAT, the node makes a reservation at one of
    /// its connected peers that supports the relay server protocol.
    /// Other peers can then reach us via:
    ///   /ip4/<relay>/tcp/<port>/p2p/<relay_id>/p2p-circuit/p2p/<our_id>
    pub relay_client: relay::client::Behaviour,

    /// DCUtR — Direct Connection Upgrade Through Relay.
    ///
    /// Once two NAT'd nodes are connected through a relay, DCUtR coordinates
    /// simultaneous TCP/UDP connection attempts to punch through both NATs.
    /// On success the relay connection is replaced by a direct connection.
    pub dcutr: dcutr::Behaviour,

    /// Hard connection limits — enforced by the swarm before any other
    /// behaviour sees the connection.  Prevents file-descriptor exhaustion
    /// and connection-flood DoS.
    ///
    /// Limits (production defaults, tunable via config):
    ///   128 established inbound  — matches Substrate's default
    ///    64 established outbound — we initiate fewer than we accept
    ///    64 pending inbound      — cap half-open handshakes
    ///    32 pending outbound     — cap simultaneous dial attempts
    pub connection_limits: connection_limits::Behaviour,

    /// State manifest sync — step 1: request chain metadata + active segment IDs.
    /// Tiny response (~few KB), establishes what needs downloading.
    pub state_manifest_sync: request_response::Behaviour<StateManifestCodec>,

    /// State segment sync — step 2: request individual segments (~3 MB each).
    /// Downloaded in parallel after manifest is received.
    pub state_segment_sync: request_response::Behaviour<StateSegmentCodec>,

    /// Mempool sync — exchange pending TXs on peer connect.
    /// When a new peer joins, both sides request each other's mempool so that
    /// TXs submitted before connection are immediately propagated.
    /// This complements gossipsub (which only delivers NEW events) with a
    /// state-sync mechanism for existing mempool entries.
    pub mempool_sync: request_response::Behaviour<MempoolSyncCodec>,
}

impl NodeBehaviour {
    /// Build the combined behaviour from a libp2p keypair.
    ///
    /// `protocol_id` is the network-specific prefix used for all sync stream
    /// protocols (e.g. `/noid/mainnet/1.0.0`).  This ensures mainnet and
    /// testnet nodes can never accidentally sync with each other.
    /// Build the combined behaviour.
    ///
    /// `relay_client` MUST come from `SwarmBuilder::with_relay_client()` —
    /// it cannot be constructed manually because it is wired into the relay
    /// transport layer by the builder.
    pub fn new(
        key: &libp2p::identity::Keypair,
        protocol_id: &str,
        relay_client: relay::client::Behaviour,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        use libp2p::gossipsub::MessageAuthenticity;
        use libp2p::request_response::ProtocolSupport;

        // ----------------------------------------------------------------
        // GossipSub
        // ----------------------------------------------------------------
        //
        // Tuned for heterogeneous network sizes (2 → 10 000+ peers):
        //
        //  flood_publish=false  rely on the mesh for propagation at scale.
        //                       With flood_publish=true every block would be
        //                       sent to all 192 connections simultaneously
        //                       (~400 MB/s egress at max capacity).  The mesh
        //                       handles small networks fine once formed.
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
        // Max gossipsub message size.
        //
        // Block bodies are fixed-form and capped at 82,905 bytes for all 256
        // canonical transaction slots, including coinbase.
        //
        // Block proof sizes (block_proof_bytes):
        //   coinbase:  0 B (empty)
        //   user-tx blocks carry BlockProof bytes. The proof caps remain
        //   conservative until final production row-ledger measurements.
        //
        // Strategy: inline blocks up to 1 MB via gossip for low-tx blocks.
        // Larger blocks use compact announcement + pull sync via block_sync
        // request-response so peers pull block/proof bytes on demand.

        let gossipsub_cfg = gossipsub::ConfigBuilder::default()
            .heartbeat_interval(Duration::from_millis(700))
            // Mesh params tuned for 2-1000 peers:
            //   mesh_n(4)           — target mesh; forms with as few as 4 peers
            //   mesh_n_low(2)       — expand if fewer than 2 mesh peers
            //   mesh_n_high(8)      — prune above 8 (vs 12 before)
            //   mesh_outbound_min(1)— CRITICAL: was 2, blocked publish with ≤1 outbound
            //                        (every spoke node connecting to a single seed
            //                         has exactly 1 outbound; publish was silently
            //                         failing with InsufficientPeers for all of them)
            .mesh_n(4)
            .mesh_n_low(2)
            .mesh_n_high(8)
            .mesh_outbound_min(1)
            .max_transmit_size(GOSSIP_MAX_TRANSMIT_BYTES)
            // Mainnet: rely on the mesh for publish fanout. Flood-publishing to
            // every connected peer turns inbound spam into O(connected_peers)
            // outbound bandwidth even when downstream validation drops it.
            .flood_publish(false)
            // Peer exchange: when the mesh prunes a peer it advertises up to 6
            // alternative peers (PeerInfo with signed address records). The
            // receiving node dials those peers automatically, enabling organic
            // topology growth without DNS seeds or manual configuration.
            .do_px()
            .validation_mode(gossipsub::ValidationMode::Strict)
            .message_id_fn(|msg| {
                // Content-addressed: hash the message data (not author+seq).
                let hash = poseidon2b_hash_bytes(GOSSIPSUB_MESSAGE_ID_DOMAIN, &msg.data);
                gossipsub::MessageId::from(hash.to_vec())
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
        let chain_sync = request_response::Behaviour::new(
            [(
                // v2 validates the header count before reserving the batch and
                // carries only exact canonical 212-byte headers.
                StreamProtocol::try_from_owned(format!("{}/sync/headers/2", protocol_id))?,
                ProtocolSupport::Full,
            )],
            request_response::Config::default()
                .with_request_timeout(Duration::from_secs(30))
                .with_max_concurrent_streams(8),
        );

        let block_sync = request_response::Behaviour::new(
            [(
                // v2 is an allocation-bounded fixed-header stream codec.  It
                // intentionally cannot negotiate with the old 10 MiB CBOR wire.
                StreamProtocol::try_from_owned(format!("{}/sync/block/2", protocol_id))?,
                ProtocolSupport::Full,
            )],
            request_response::Config::default()
                .with_request_timeout(Duration::from_secs(30))
                // A response can contain 48 MiB of proof material. One stream
                // per connection reduces scheduling pressure; the codec's
                // process-global 64 MiB permit is the peer-count-independent
                // RAM bound. Suffix advancement requests the next block only
                // after the current block has been consumed.
                .with_max_concurrent_streams(1),
        );

        let proof_sync = request_response::Behaviour::new(
            [(
                StreamProtocol::try_from_owned(format!("{}/sync/proof/2", protocol_id))?,
                ProtocolSupport::Full,
            )],
            request_response::Config::default()
                .with_request_timeout(Duration::from_secs(10))
                .with_max_concurrent_streams(4),
        );

        // Manifest: tiny request/response, short timeout is fine.
        let state_manifest_sync = request_response::Behaviour::new(
            [(
                // v2 checks segment/header counts and snapshot geometry before
                // allocating either manifest vector.
                StreamProtocol::try_from_owned(format!("{}/sync/manifest/2", protocol_id))?,
                ProtocolSupport::Full,
            )],
            request_response::Config::default()
                .with_request_timeout(Duration::from_secs(30))
                .with_max_concurrent_streams(8),
        );

        // Segment: each response is ~3 MB; 60s per segment is generous.
        // 16 concurrent streams lets us pipeline downloads aggressively.
        let state_segment_sync = request_response::Behaviour::new(
            [(
                // v3 additionally echoes the exact snapshot boundary in every
                // response, while retaining pre-allocation length validation.
                StreamProtocol::try_from_owned(format!("{}/sync/segment/3", protocol_id))?,
                ProtocolSupport::Full,
            )],
            request_response::Config::default()
                .with_request_timeout(Duration::from_secs(60))
                .with_max_concurrent_streams(8),
        );

        // Mempool sync v2 declares and validates every intent length before
        // allocation and streams payload slices without a duplicate CBOR Vec.
        let mempool_sync = request_response::Behaviour::new(
            [(
                StreamProtocol::try_from_owned(format!("{}/sync/mempool/2", protocol_id))?,
                ProtocolSupport::Full,
            )],
            request_response::Config::default()
                .with_request_timeout(Duration::from_secs(10))
                .with_max_concurrent_streams(1),
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

        // ----------------------------------------------------------------
        // NAT traversal: AutoNAT + DCUtR
        // ----------------------------------------------------------------
        //
        // AutoNAT probes our reachability every 90s by asking peers to
        // dial us back.  Result is logged so operators know if their node
        // is publicly reachable.
        let autonat = autonat::Behaviour::new(
            key.public().to_peer_id(),
            autonat::Config {
                boot_delay: Duration::from_secs(30),
                refresh_interval: Duration::from_secs(90),
                retry_interval: Duration::from_secs(30),
                // 3 confirmations before declaring public/private.
                confidence_max: 3,
                ..Default::default()
            },
        );

        // DCUtR: coordinates simultaneous dial attempts between two NAT'd
        // nodes connected through a relay, upgrading to a direct connection.
        let dcutr = dcutr::Behaviour::new(key.public().to_peer_id());

        // ----------------------------------------------------------------
        // Connection limits
        // ----------------------------------------------------------------
        //
        // Enforced at the swarm level before any behaviour receives events.
        // Substrate defaults: 100 in / 25 out.  We use slightly higher
        // values because Paranoid nodes actively push block proofs and
        // have higher per-connection bandwidth.
        let connection_limits = connection_limits::Behaviour::new(
            connection_limits::ConnectionLimits::default()
                .with_max_established_incoming(Some(128))
                .with_max_established_outgoing(Some(64))
                .with_max_pending_incoming(Some(64))
                .with_max_pending_outgoing(Some(32)),
        );

        Ok(Self {
            gossipsub,
            chain_sync,
            block_sync,
            proof_sync,
            kad,
            mdns,
            identify,
            ping,
            autonat,
            relay_client,
            dcutr,
            connection_limits,
            state_manifest_sync,
            state_segment_sync,
            mempool_sync,
        })
    }
}
