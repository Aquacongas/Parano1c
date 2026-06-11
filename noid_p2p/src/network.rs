// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! `P2PNetwork` — the libp2p swarm event loop.
//!
//! Handles:
//! - GossipSub: receiving blocks and txs from peers, broadcasting our blocks/txs
//! - Request-Response: serving header/block/proof requests from syncing nodes
//! - Identify: maintaining peer address books
//! - Ping: pruning stale connections

use std::sync::Arc;

use futures::StreamExt;
use libp2p::{
    autonat, dcutr, gossipsub, identify, kad, mdns, relay, request_response, swarm::SwarmEvent,
    Multiaddr, PeerId,
};
use tokio::sync::{mpsc, RwLock};

use noid_chain::storage::MdbxChainContext;
use noid_mempool::AsyncMempool;

use crate::behaviour::{NodeBehaviour, NodeBehaviourEvent};
use crate::protocol::{
    BlockGossipMsg, GetHeadersResponse, GetRecentBlockResponse, GetRecursiveProofResponse,
    GetStateManifestResponse, GetStateSegmentResponse, NetworkTopics, RecursiveProofGossipMsg,
};

// Hard caps on incoming response sizes to prevent OOM from malicious peers.
const MAX_BLOCK_BYTES: usize = 512 * 1024; // 512 KB (256 txs × ~750 B each + header)
const MAX_BLOCK_PROOF_BYTES: usize = 6 * 1024 * 1024; // 6 MB (5 MB at max 256 txs + margin)
const MAX_SEGMENT_BYTES: usize = 8 * 1024 * 1024; // 8 MB per segment (3 MB typical + margin)
const MAX_RECURSIVE_PROOF_BYTES: usize = 64 * 1024; // 64 KB (6.5 KB typical)
const MAX_HEADER_BYTES: usize = 512; // 276 bytes typical + margin

/// Commands sent to the P2P network event loop.
#[derive(Debug)]
pub enum NetworkCommand {
    /// Announce a new block to all peers.
    ///
    /// If `block_bytes` + `block_proof_bytes` fit within the inline threshold
    /// (1 MB), the full block is gossiped directly (no round-trip needed).
    /// Otherwise only the header is sent and peers pull via request-response.
    AnnounceBlock {
        height: u64,
        hash: [u8; 32],
        /// Wire-encoded BlockHeader (276 bytes).
        header_bytes: Vec<u8>,
        /// Full block bytes (for inline mode). Empty = compact-only.
        block_bytes: Vec<u8>,
        /// Block proof bytes (for inline mode). Empty = compact-only.
        block_proof_bytes: Vec<u8>,
    },
    /// Broadcast a new recursive proof update to all peers.
    BroadcastRecursiveProof {
        height: u64,
        tip_hash: [u8; 32],
        proof_bytes: Vec<u8>,
    },
    /// Broadcast a new TxIntent to all peers.
    BroadcastTx { intent_bytes: Vec<u8> },
    /// Connect to a seed peer.
    Dial { addr: Multiaddr },
    /// Get current peer count.
    PeerCount {
        reply: tokio::sync::oneshot::Sender<usize>,
    },
    /// Request recent blocks from a specific peer for initial sync.
    /// Fetches blocks from `from_height` to `from_height + count - 1`.
    /// Emits `NetworkEvent::NewBlock` for each successfully fetched block.
    SyncBlocksFrom {
        peer: PeerId,
        from_height: u64,
        count: u16,
    },
    /// Request a specific block by height from a peer (orphan resolution).
    /// Emits `NetworkEvent::NewBlock` if the peer has the block.
    RequestBlock { peer: PeerId, height: u64 },
    /// Fetch a range of headers from a peer for reorg ancestor search.
    /// Emits `NetworkEvent::HeadersBatch` with the decoded headers.
    /// Used to find the common ancestor efficiently in O(1) round-trips
    /// instead of O(depth) hop-by-hop backwards traversal.
    FetchHeaders {
        peer: PeerId,
        start_height: u64,
        count: u16, // max 512
    },
    /// Request the state manifest from a peer (step 1 of snapshot sync).
    /// Returns metadata + active segment IDs.  Emits `NetworkEvent::StateManifest`.
    RequestStateManifest { peer: PeerId },
    /// Request a single state segment from a peer (step 2, one per segment).
    /// Emits `NetworkEvent::StateSegment`.
    RequestStateSegment {
        peer: PeerId,
        segment_id: u16,
        expected_tip_height: u64,
    },
    /// Request the latest recursive chain proof from a peer.
    /// Used to cryptographically verify a state snapshot before applying it.
    /// Emits `NetworkEvent::RecursiveProof` when the response arrives.
    RequestRecursiveProof { peer: PeerId },
    /// Request a peer's mempool contents (all pending TxIntent bytes).
    /// Triggered on peer connect so late-joining nodes receive existing TXs.
    /// Emits `NetworkEvent::MempoolSyncResponse` when the response arrives.
    RequestMempoolSync { peer: PeerId },
}

/// Events emitted by the P2P layer to the node.
#[derive(Debug, Clone)]
pub enum NetworkEvent {
    /// A compact block announcement arrived from a peer.
    ///
    /// Contains only the header; the full block must be pulled via
    /// `NetworkCommand::SyncBlocksFrom` or `RequestBlock`.
    NewBlockAnnouncement {
        from: PeerId,
        height: u64,
        hash: [u8; 32],
        /// Wire-encoded BlockHeader (276 bytes).
        header_bytes: Vec<u8>,
    },
    /// A full block + proof arrived (response to a pull request).
    NewBlock {
        from: PeerId,
        block_bytes: Vec<u8>,
        /// `BlockProof` bincode bytes.  Empty Vec for coinbase-only blocks.
        block_proof_bytes: Vec<u8>,
    },
    /// A recursive proof update arrived from a peer.
    RecursiveProofUpdate {
        from: PeerId,
        height: u64,
        tip_hash: [u8; 32],
        proof_bytes: Vec<u8>,
    },
    /// A new TxIntent arrived from a peer.
    NewTx { from: PeerId, intent_bytes: Vec<u8> },
    /// Response to FetchHeaders: decoded headers from the peer.
    /// Used by reorg detection to find the common ancestor quickly.
    HeadersBatch {
        from: PeerId,
        headers: Vec<noid_chain::block_header::BlockHeader>,
    },
    /// State manifest received from a peer (step 1 of snapshot sync).
    StateManifest {
        from: PeerId,
        manifest: Box<crate::protocol::GetStateManifestResponse>,
    },
    /// One state segment received from a peer (step 2).
    StateSegment {
        from: PeerId,
        response: crate::protocol::GetStateSegmentResponse,
    },
    /// Recursive chain proof received from a peer (response to RequestRecursiveProof).
    /// Contains serialized `RecursiveBlockProof` bytes and the peer's tip header bytes.
    /// Used to cryptographically verify a state snapshot before applying it.
    RecursiveProof {
        from: PeerId,
        /// Serialized `RecursiveBlockProof` bytes, or empty if peer has no proof yet.
        proof_bytes: Vec<u8>,
        /// Serialized tip `BlockHeader` bytes (276 bytes), or empty.
        tip_header_bytes: Vec<u8>,
    },
    /// Mempool sync response: raw TxIntent bytes from a peer's mempool.
    /// Received after sending `RequestMempoolSync` on peer connect.
    MempoolSyncResponse {
        from: PeerId,
        /// Raw TxIntent bytes, one per pending transaction.
        txs: Vec<Vec<u8>>,
    },
    /// A peer connected.
    PeerConnected(PeerId),
    /// A peer disconnected.
    PeerDisconnected(PeerId),
}

/// The P2P network manager.
pub struct P2PNetwork {
    /// Channel to send commands to the event loop.
    pub cmd_tx: mpsc::Sender<NetworkCommand>,
    /// Subscribe to events from the event loop.
    pub event_tx: tokio::sync::broadcast::Sender<NetworkEvent>,
}

impl P2PNetwork {
    /// Build and start the P2P network.
    ///
    /// `topics` controls which gossipsub topics to subscribe to and which
    /// stream protocol IDs to use for sync — use
    /// `NetworkTopics::for_network_cfg(cfg)` to get the right network.
    pub fn start(
        listen_addr: Multiaddr,
        chain: Arc<RwLock<MdbxChainContext>>,
        mempool: AsyncMempool,
        topics: NetworkTopics,
        data_dir: std::path::PathBuf,
    ) -> (Self, tokio::task::JoinHandle<()>) {
        let (cmd_tx, cmd_rx) = mpsc::channel(256);
        let (event_tx, _) = tokio::sync::broadcast::channel(256);

        let event_tx_clone = event_tx.clone();
        let handle = tokio::spawn(async move {
            if let Err(e) = run_swarm(
                listen_addr,
                cmd_rx,
                event_tx_clone,
                chain,
                mempool,
                topics,
                data_dir,
            )
            .await
            {
                tracing::error!("P2P network error: {e}");
            }
        });

        (Self { cmd_tx, event_tx }, handle)
    }

    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<NetworkEvent> {
        self.event_tx.subscribe()
    }

    /// Announce a new block to all peers.  Small blocks are inlined in gossip.
    pub async fn announce_block(
        &self,
        height: u64,
        hash: [u8; 32],
        header_bytes: Vec<u8>,
        block_bytes: Vec<u8>,
        block_proof_bytes: Vec<u8>,
    ) {
        let _ = self
            .cmd_tx
            .send(NetworkCommand::AnnounceBlock {
                height,
                hash,
                header_bytes,
                block_bytes,
                block_proof_bytes,
            })
            .await;
    }

    pub async fn broadcast_recursive_proof(
        &self,
        height: u64,
        tip_hash: [u8; 32],
        proof_bytes: Vec<u8>,
    ) {
        let _ = self
            .cmd_tx
            .send(NetworkCommand::BroadcastRecursiveProof {
                height,
                tip_hash,
                proof_bytes,
            })
            .await;
    }

    pub async fn broadcast_tx(&self, intent_bytes: Vec<u8>) {
        let _ = self
            .cmd_tx
            .send(NetworkCommand::BroadcastTx { intent_bytes })
            .await;
    }

    pub async fn dial(&self, addr: Multiaddr) {
        let _ = self.cmd_tx.send(NetworkCommand::Dial { addr }).await;
    }

    pub async fn sync_blocks_from(&self, peer: PeerId, from_height: u64, count: u16) {
        let _ = self
            .cmd_tx
            .send(NetworkCommand::SyncBlocksFrom {
                peer,
                from_height,
                count,
            })
            .await;
    }

    /// Request a specific block by height from a peer (orphan resolution).
    pub async fn request_block(&self, peer: PeerId, height: u64) {
        let _ = self
            .cmd_tx
            .send(NetworkCommand::RequestBlock { peer, height })
            .await;
    }

    /// Request the state manifest from a peer (step 1 of snapshot sync).
    pub async fn request_state_manifest(&self, peer: PeerId) {
        let _ = self
            .cmd_tx
            .send(NetworkCommand::RequestStateManifest { peer })
            .await;
    }

    /// Request a single state segment from a peer (step 2).
    pub async fn request_state_segment(
        &self,
        peer: PeerId,
        segment_id: u16,
        expected_tip_height: u64,
    ) {
        let _ = self
            .cmd_tx
            .send(NetworkCommand::RequestStateSegment {
                peer,
                segment_id,
                expected_tip_height,
            })
            .await;
    }

    /// Request the latest recursive chain proof from a peer.
    /// The response arrives as `NetworkEvent::RecursiveProof`.
    pub async fn request_recursive_proof(&self, peer: PeerId) {
        let _ = self
            .cmd_tx
            .send(NetworkCommand::RequestRecursiveProof { peer })
            .await;
    }

    /// Request all pending transactions from a peer's mempool.
    /// Used on peer connect so late-joining nodes receive existing TXs.
    pub async fn request_mempool_sync(&self, peer: PeerId) {
        let _ = self
            .cmd_tx
            .send(NetworkCommand::RequestMempoolSync { peer })
            .await;
    }

    /// Get peer count via an existing command channel (for RPC handler).
    pub async fn peer_count_via(cmd: &tokio::sync::mpsc::Sender<NetworkCommand>) -> usize {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let _ = cmd.send(NetworkCommand::PeerCount { reply: tx }).await;
        rx.await.unwrap_or(0)
    }

    pub async fn peer_count(&self) -> usize {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let _ = self
            .cmd_tx
            .send(NetworkCommand::PeerCount { reply: tx })
            .await;
        rx.await.unwrap_or(0)
    }
}

// ---------------------------------------------------------------------------
// Swarm event loop
// ---------------------------------------------------------------------------

async fn run_swarm(
    listen_addr: Multiaddr,
    mut cmd_rx: mpsc::Receiver<NetworkCommand>,
    event_tx: tokio::sync::broadcast::Sender<NetworkEvent>,
    chain: Arc<RwLock<MdbxChainContext>>,
    mempool: AsyncMempool,
    topics: NetworkTopics,
    data_dir: std::path::PathBuf,
) -> anyhow::Result<()> {
    use libp2p::{noise, tcp, yamux, SwarmBuilder};

    let protocol_id = topics.protocol_id.clone();
    let mut swarm = SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_dns()?
        // Relay client transport: enables dialling and listening through relay
        // nodes.  The relay::client::Behaviour is wired here by the builder
        // and passed into NodeBehaviour::new() via the closure below.
        .with_relay_client(noise::Config::new, yamux::Config::default)?
        .with_behaviour(|key, relay_client| NodeBehaviour::new(key, &protocol_id, relay_client))?
        .with_swarm_config(|cfg| {
            cfg.with_idle_connection_timeout(std::time::Duration::from_secs(300))
        })
        .build();

    // Subscribe to network-specific gossip topics.
    let blocks_topic = gossipsub::IdentTopic::new(topics.blocks.clone());
    let txs_topic = gossipsub::IdentTopic::new(topics.txs.clone());
    let rec_proofs_topic = gossipsub::IdentTopic::new(topics.rec_proofs.clone());
    swarm.behaviour_mut().gossipsub.subscribe(&blocks_topic)?;
    swarm.behaviour_mut().gossipsub.subscribe(&txs_topic)?;
    swarm
        .behaviour_mut()
        .gossipsub
        .subscribe(&rec_proofs_topic)?;

    swarm.listen_on(listen_addr)?;

    // After subscribing and listening, kick off Kademlia bootstrap.
    // This triggers FIND_NODE walks starting from any peers already in the
    // routing table (populated when seeds connect and identify fires).
    // The bootstrap is a no-op if the routing table is empty; it will be
    // re-triggered automatically when the first peer is added via identify.
    // Load persisted peers and add to Kademlia routing table.
    // This makes cold restarts resilient when DNS seeds are temporarily down.
    let cached_peers = crate::peer_store::load(&data_dir);
    if !cached_peers.is_empty() {
        tracing::debug!(
            count = cached_peers.len(),
            "peer store: seeding Kademlia from cache"
        );
        for (peer_id, addrs) in &cached_peers {
            for addr in addrs {
                swarm.behaviour_mut().kad.add_address(peer_id, addr.clone());
            }
        }
    }

    if let Err(e) = swarm.behaviour_mut().kad.bootstrap() {
        tracing::debug!("kad bootstrap deferred (no peers yet): {e}");
    }

    // Reconnect list: peers whose addresses we know, to re-dial after disconnect.
    // Maps PeerId -> (Multiaddr, next_retry_at, retry_count).
    // Uses exponential backoff: 10s, 20s, 40s, 80s ... capped at 10 minutes.
    let mut reconnect: std::collections::HashMap<
        libp2p::PeerId,
        (Multiaddr, tokio::time::Instant, u32),
    > = std::collections::HashMap::new();

    // Reconnect timer: poll the reconnect list every 5 seconds.
    let mut reconnect_timer = tokio::time::interval(std::time::Duration::from_secs(5));
    reconnect_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    reconnect_timer.tick().await; // skip first immediate tick

    // Peer store save timer: persist routing table every 5 minutes.
    let mut peer_store_timer = tokio::time::interval(std::time::Duration::from_secs(5 * 60));
    peer_store_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    peer_store_timer.tick().await; // skip first immediate tick

    // Periodic Kademlia random walk timer.
    //
    // Every 5 minutes we issue a FIND_NODE for a random key.  This spreads
    // knowledge of our node through the DHT and refreshes stale k-buckets.
    // Substrate does the same; Ethereum's discv5 equivalent is the random
    // lookup triggered by the routing table refresh timer.
    let mut kad_walk_interval = tokio::time::interval(std::time::Duration::from_secs(5 * 60));
    kad_walk_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // Skip the first immediate tick so we don't walk before any peers exist.
    kad_walk_interval.tick().await;

    loop {
        // Drain all pending commands first (priority: outgoing blocks must propagate
        // immediately without waiting for swarm event processing).
        while let Ok(cmd) = cmd_rx.try_recv() {
            handle_network_command(&mut swarm, cmd, &topics);
        }

        tokio::select! {
            // Swarm events.
            event = swarm.select_next_some() => {
                handle_swarm_event(&mut swarm, event, &event_tx, &chain, &mempool, &topics, &mut reconnect).await;
            }

            // Commands from the node (when no swarm event pending).
            cmd = cmd_rx.recv() => {
                match cmd {
                    Some(cmd) => handle_network_command(&mut swarm, cmd, &topics),
                    None => break, // cmd_tx dropped
                }
            }

            // Periodic Kademlia random walk for topology health.
            _ = kad_walk_interval.tick() => {
                let random_peer = libp2p::PeerId::random();
                swarm.behaviour_mut().kad.get_closest_peers(random_peer);
                tracing::debug!("kad: periodic random walk");
            }

            // Peer store: persist routing table for cold-restart resilience.
            _ = peer_store_timer.tick() => {
                // Collect addresses from Kademlia routing table.
                // We iterate kbuckets and collect all known (peer, addrs) pairs.
                let peers: Vec<(PeerId, Vec<Multiaddr>)> = swarm
                    .behaviour_mut()
                    .kad
                    .kbuckets()
                    .flat_map(|bucket| {
                        bucket.iter().map(|entry| {
                            let peer_id = *entry.node.key.preimage();
                            let addrs: Vec<Multiaddr> = entry.node.value.iter().cloned().collect();
                            (peer_id, addrs)
                        }).collect::<Vec<_>>()
                    })
                    .filter(|(_, addrs)| !addrs.is_empty())
                    .collect();
                let data_dir = data_dir.clone();
                tokio::task::spawn_blocking(move || {
                    crate::peer_store::save(&data_dir, &peers);
                });
            }

            // Reconnect: re-dial known peers after disconnect with backoff.
            _ = reconnect_timer.tick() => {
                let now = tokio::time::Instant::now();
                let to_dial: Vec<_> = reconnect
                    .iter()
                    .filter(|(peer, (_, retry_at, _))| {
                        now >= *retry_at
                            && !swarm.is_connected(peer)
                    })
                    .map(|(peer, (addr, _, count))| (*peer, addr.clone(), *count))
                    .collect();
                // Max reconnect attempts before giving up.
                // Prevents unbounded map growth for permanently-offline peers.
                const MAX_RECONNECT_ATTEMPTS: u32 = 10;

                for (peer, addr, count) in to_dial {
                    if count >= MAX_RECONNECT_ATTEMPTS {
                        tracing::debug!(
                            peer = %peer,
                            attempts = count,
                            "reconnect: giving up after max attempts"
                        );
                        reconnect.remove(&peer);
                        continue;
                    }
                    tracing::debug!(peer = %peer, attempt = count + 1, "reconnecting");
                    if let Err(e) = swarm.dial(addr.clone()) {
                        tracing::debug!(peer = %peer, err = %e, "reconnect dial failed");
                    }
                    // Exponential backoff: 10s * 2^count, capped at 10min.
                    let delay_secs = (10u64 * (1u64 << count.min(6))).min(600);
                    let next_retry = tokio::time::Instant::now()
                        + std::time::Duration::from_secs(delay_secs);
                    reconnect.insert(peer, (addr, next_retry, count + 1));
                }
                // Remove peers that are now connected (reconnect succeeded).
                reconnect.retain(|peer, _| !swarm.is_connected(peer));
            }
        }
    }
    Ok(())
}

/// Process a single network command. Separated from the select! loop so that
/// pending commands can be drained synchronously via `try_recv` before blocking.
fn handle_network_command(
    swarm: &mut libp2p::Swarm<NodeBehaviour>,
    cmd: NetworkCommand,
    topics: &NetworkTopics,
) {
    match cmd {
        NetworkCommand::AnnounceBlock {
            height,
            hash,
            header_bytes,
            block_bytes,
            block_proof_bytes,
        } => {
            // Inline threshold: if block + proof fit in 1 MB, gossip the full
            // block directly.  Eliminates the round-trip for the common case
            // (coinbase-only and low-tx blocks).
            const INLINE_THRESHOLD: usize = 1024 * 1024; // 1 MB
            let total = block_bytes.len() + block_proof_bytes.len();
            let msg = if !block_bytes.is_empty() && total <= INLINE_THRESHOLD {
                BlockGossipMsg::Inline {
                    height,
                    hash,
                    block_bytes,
                    block_proof_bytes,
                }
            } else {
                BlockGossipMsg::Compact {
                    height,
                    hash,
                    header_bytes,
                }
            };
            match bincode::serialize(&msg) {
                Ok(encoded) => {
                    let topic = gossipsub::IdentTopic::new(topics.blocks.clone());
                    if let Err(e) = swarm.behaviour_mut().gossipsub.publish(topic, encoded) {
                        tracing::debug!(height, err = %e, "gossipsub: block announcement");
                    }
                }
                Err(e) => tracing::error!("BlockGossipMsg serialize: {e}"),
            }
        }
        NetworkCommand::BroadcastRecursiveProof {
            height,
            tip_hash,
            proof_bytes,
        } => {
            let msg = RecursiveProofGossipMsg {
                height,
                tip_hash,
                proof_bytes,
            };
            match bincode::serialize(&msg) {
                Ok(encoded) => {
                    let topic = gossipsub::IdentTopic::new(topics.rec_proofs.clone());
                    if let Err(e) = swarm.behaviour_mut().gossipsub.publish(topic, encoded) {
                        tracing::debug!("gossipsub rec_proof: {e}");
                    }
                }
                Err(e) => tracing::error!("RecursiveProofGossipMsg serialize: {e}"),
            }
        }
        NetworkCommand::BroadcastTx { intent_bytes } => {
            let topic = gossipsub::IdentTopic::new(topics.txs.clone());
            if let Err(e) = swarm.behaviour_mut().gossipsub.publish(topic, intent_bytes) {
                tracing::debug!("gossipsub: {e} (block delivered via direct peer connections)");
            }
        }
        NetworkCommand::Dial { addr } => {
            if let Err(e) = swarm.dial(addr) {
                tracing::warn!("dial: {e}");
            }
        }
        NetworkCommand::PeerCount { reply } => {
            let count = swarm.connected_peers().count();
            let _ = reply.send(count);
        }
        NetworkCommand::SyncBlocksFrom {
            peer,
            from_height,
            count,
        } => {
            // Only send the first SYNC_WINDOW requests simultaneously.
            // Remaining blocks are requested as responses arrive, preventing
            // a burst of N parallel requests to a single peer.
            const SYNC_WINDOW: u64 = 4;
            for h in from_height..(from_height + (count as u64).min(SYNC_WINDOW)) {
                let _ = swarm
                    .behaviour_mut()
                    .block_sync
                    .send_request(&peer, crate::protocol::GetRecentBlockRequest { height: h });
            }
        }
        NetworkCommand::RequestBlock { peer, height } => {
            let _ = swarm
                .behaviour_mut()
                .block_sync
                .send_request(&peer, crate::protocol::GetRecentBlockRequest { height });
        }
        NetworkCommand::RequestStateManifest { peer } => {
            let _ = swarm.behaviour_mut().state_manifest_sync.send_request(
                &peer,
                crate::protocol::GetStateManifestRequest {
                    requester_height: 0,
                },
            );
            tracing::debug!(peer = %peer, "requesting state manifest");
        }
        NetworkCommand::RequestStateSegment {
            peer,
            segment_id,
            expected_tip_height,
        } => {
            let _ = swarm.behaviour_mut().state_segment_sync.send_request(
                &peer,
                crate::protocol::GetStateSegmentRequest {
                    segment_id,
                    expected_tip_height,
                },
            );
            tracing::debug!(peer = %peer, segment_id, "requesting state segment");
        }
        NetworkCommand::RequestRecursiveProof { peer } => {
            let _ = swarm
                .behaviour_mut()
                .proof_sync
                .send_request(&peer, crate::protocol::GetRecursiveProofRequest);
            tracing::debug!(peer = %peer, "requesting recursive proof for snapshot verification");
        }
        NetworkCommand::FetchHeaders {
            peer,
            start_height,
            count,
        } => {
            let count = count.min(512);
            let _ = swarm.behaviour_mut().chain_sync.send_request(
                &peer,
                crate::protocol::GetHeadersRequest {
                    start_height,
                    count,
                },
            );
        }
        NetworkCommand::RequestMempoolSync { peer } => {
            let _ = swarm
                .behaviour_mut()
                .mempool_sync
                .send_request(&peer, crate::protocol::GetMempoolRequest);
            tracing::debug!(peer = %peer, "requesting mempool sync");
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_swarm_event(
    swarm: &mut libp2p::Swarm<NodeBehaviour>,
    event: SwarmEvent<NodeBehaviourEvent>,
    event_tx: &tokio::sync::broadcast::Sender<NetworkEvent>,
    chain: &Arc<RwLock<MdbxChainContext>>,
    mempool: &AsyncMempool,
    topics: &NetworkTopics,
    reconnect: &mut std::collections::HashMap<
        libp2p::PeerId,
        (Multiaddr, tokio::time::Instant, u32),
    >,
) {
    match event {
        // --- GossipSub: received broadcast ---
        SwarmEvent::Behaviour(NodeBehaviourEvent::Gossipsub(gossipsub::Event::Message {
            propagation_source,
            message,
            ..
        })) => {
            // Prefer the original publisher (message.source) if we have a direct
            // connection — they definitely have the full block. Fall back to
            // propagation_source (forwarder) for nodes not directly connected to
            // the publisher (common in large networks with multi-hop gossip).
            let origin = message
                .source
                .filter(|src| swarm.is_connected(src))
                .unwrap_or(propagation_source);

            let topic = message.topic.as_str();
            if topic == topics.blocks.as_str() {
                match bincode::deserialize::<BlockGossipMsg>(&message.data) {
                    Ok(BlockGossipMsg::Compact {
                        height,
                        hash,
                        header_bytes,
                    }) => {
                        let _ = event_tx.send(NetworkEvent::NewBlockAnnouncement {
                            from: origin,
                            height,
                            hash,
                            header_bytes,
                        });
                    }
                    Ok(BlockGossipMsg::Inline {
                        height,
                        hash: _,
                        block_bytes,
                        block_proof_bytes,
                    }) => {
                        if block_bytes.len() > MAX_BLOCK_BYTES {
                            tracing::warn!(peer = %propagation_source, len = block_bytes.len(), "inline block too large — dropped");
                        } else if block_proof_bytes.len() > MAX_BLOCK_PROOF_BYTES {
                            tracing::warn!(peer = %propagation_source, len = block_proof_bytes.len(), "inline proof too large — dropped");
                        } else {
                            tracing::debug!(height, peer = %propagation_source, "received inline block via gossip");
                            let _ = event_tx.send(NetworkEvent::NewBlock {
                                from: origin,
                                block_bytes,
                                block_proof_bytes,
                            });
                        }
                    }
                    Err(e) => {
                        tracing::debug!(
                            peer = %propagation_source,
                            err = %e,
                            "block gossip message deserialize failed"
                        );
                    }
                }
            } else if topic == topics.txs.as_str() {
                let _ = event_tx.send(NetworkEvent::NewTx {
                    from: propagation_source,
                    intent_bytes: message.data,
                });
            } else if topic == topics.rec_proofs.as_str() {
                match bincode::deserialize::<crate::protocol::RecursiveProofGossipMsg>(
                    &message.data,
                ) {
                    Ok(msg) => {
                        let _ = event_tx.send(NetworkEvent::RecursiveProofUpdate {
                            from: origin,
                            height: msg.height,
                            tip_hash: msg.tip_hash,
                            proof_bytes: msg.proof_bytes,
                        });
                    }
                    Err(e) => tracing::debug!("RecursiveProofGossipMsg decode: {e}"),
                }
            }
        }

        // --- Identify: populate Kademlia routing table + address book ---
        //
        // This is the critical integration point that all libp2p chains must
        // implement.  Without it, Kademlia only knows bootstrap nodes and
        // discovery stops there.
        //
        // Reference: libp2p docs — "Peer Discovery with Identify:
        //   the Identify protocol must be manually hooked up to Kademlia
        //   through calls to Behaviour::add_address."
        SwarmEvent::Behaviour(NodeBehaviourEvent::Identify(identify::Event::Received {
            peer_id,
            info,
            ..
        })) => {
            // 1. Add every advertised listen address to the Kademlia routing
            //    table.  This is what makes the DHT actually work: Kademlia
            //    can now answer FIND_NODE queries with this peer's address.
            for addr in &info.listen_addrs {
                swarm
                    .behaviour_mut()
                    .kad
                    .add_address(&peer_id, addr.clone());
                // Also populate the swarm's address book so GossipSub PX
                // can build signed PeerInfo records for this peer.
                swarm.add_peer_address(peer_id, addr.clone());
            }

            // 2. Add to gossipsub explicit peers so the mesh can form even
            //    with fewer than mesh_n connections.
            swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);

            // 3. If this was the first peer added to an empty routing table,
            //    kick off the bootstrap walk now.
            let _ = swarm.behaviour_mut().kad.bootstrap();

            tracing::debug!(
                peer = %peer_id,
                protocols = ?info.protocols,
                addrs = info.listen_addrs.len(),
                "peer identified"
            );
        }

        // --- mDNS: dial LAN peers immediately ---
        //
        // Discovered peers are on the same LAN — dial them directly.
        // On the public internet mDNS never fires (UDP broadcast is LAN-scoped).
        SwarmEvent::Behaviour(NodeBehaviourEvent::Mdns(mdns::Event::Discovered(peers))) => {
            for (peer_id, addr) in peers {
                tracing::debug!(peer = %peer_id, addr = %addr, "mDNS: discovered LAN peer");
                swarm
                    .behaviour_mut()
                    .kad
                    .add_address(&peer_id, addr.clone());
                if let Err(e) = swarm.dial(addr) {
                    tracing::debug!("mDNS dial: {e}");
                }
            }
        }

        SwarmEvent::Behaviour(NodeBehaviourEvent::Mdns(mdns::Event::Expired(peers))) => {
            for (peer_id, addr) in peers {
                tracing::debug!(peer = %peer_id, addr = %addr, "mDNS: LAN peer expired");
                swarm.behaviour_mut().kad.remove_address(&peer_id, &addr);
            }
        }

        // --- Kademlia: log routing table events ---
        SwarmEvent::Behaviour(NodeBehaviourEvent::Kad(ev)) => match ev {
            kad::Event::RoutingUpdated {
                peer, is_new_peer, ..
            } => {
                if is_new_peer {
                    tracing::debug!(peer = %peer, "kad: new peer in routing table");
                }
            }
            kad::Event::OutboundQueryProgressed {
                result: kad::QueryResult::Bootstrap(Ok(kad::BootstrapOk { num_remaining, .. })),
                ..
            } => {
                if num_remaining == 0 {
                    tracing::debug!("kad: bootstrap complete");
                }
            }
            kad::Event::OutboundQueryProgressed {
                result: kad::QueryResult::GetClosestPeers(Ok(kad::GetClosestPeersOk { peers, .. })),
                ..
            } => {
                tracing::debug!(found = peers.len(), "kad: FIND_NODE returned peers");
            }
            _ => {}
        },

        // --- AutoNAT: log reachability status ---
        //
        // Operators need to know if their node is publicly reachable.
        // If private: advise configuring port forwarding or using a relay.
        SwarmEvent::Behaviour(NodeBehaviourEvent::Autonat(autonat::Event::StatusChanged {
            old,
            new,
        })) => match &new {
            autonat::NatStatus::Public(addr) => {
                tracing::info!(addr = %addr, "autonat: node is publicly reachable");
            }
            autonat::NatStatus::Private => {
                tracing::warn!(
                    prev = ?old,
                    "autonat: node is behind NAT — inbound connections will \
                     use relay; consider port forwarding tcp/9400 for better connectivity"
                );
            }
            autonat::NatStatus::Unknown => {
                tracing::debug!(prev = ?old, "autonat: NAT status unknown (probing)");
            }
        },

        // --- Relay client: reservation / circuit events ---
        SwarmEvent::Behaviour(NodeBehaviourEvent::RelayClient(ev)) => match ev {
            relay::client::Event::ReservationReqAccepted { relay_peer_id, .. } => {
                tracing::info!(relay = %relay_peer_id, "relay: reservation accepted — reachable via circuit");
            }
            relay::client::Event::OutboundCircuitEstablished { relay_peer_id, .. } => {
                tracing::debug!(relay = %relay_peer_id, "relay: outbound circuit established");
            }
            relay::client::Event::InboundCircuitEstablished { src_peer_id, .. } => {
                tracing::debug!(peer = %src_peer_id, "relay: inbound circuit from peer");
            }
        },

        // --- DCUtR: direct connection upgrade through relay ---
        SwarmEvent::Behaviour(NodeBehaviourEvent::Dcutr(dcutr::Event {
            remote_peer_id,
            result,
        })) => match result {
            Ok(_conn_id) => {
                tracing::debug!(
                    peer = %remote_peer_id,
                    "dcutr: hole punch succeeded — direct connection established"
                );
            }
            Err(e) => {
                tracing::debug!(
                    peer = %remote_peer_id,
                    err = %e,
                    "dcutr: hole punch failed — relay connection kept"
                );
            }
        },

        // --- Request-Response: headers client side (response to our FetchHeaders) ---
        SwarmEvent::Behaviour(NodeBehaviourEvent::ChainSync(
            request_response::Event::Message {
                message: request_response::Message::Response { response, .. },
                peer,
            },
        )) => {
            // Decode wire-format headers into BlockHeader structs.
            let mut decoded = Vec::with_capacity(response.headers.len());
            for bytes in &response.headers {
                if let Ok(hdr) = noid_chain::block_header::BlockHeader::from_bytes(bytes) {
                    decoded.push(hdr);
                }
            }
            if !decoded.is_empty() {
                let _ = event_tx.send(NetworkEvent::HeadersBatch {
                    from: peer,
                    headers: decoded,
                });
            }
        }

        // --- Request-Response: headers server side ---
        SwarmEvent::Behaviour(NodeBehaviourEvent::ChainSync(
            request_response::Event::Message {
                message:
                    request_response::Message::Request {
                        request, channel, ..
                    },
                ..
            },
        )) => {
            let ctx = chain.read().await;
            let mut headers = Vec::new();
            for h in request.start_height..(request.start_height + request.count as u64) {
                if let Ok(Some(hdr)) = ctx.get_header_from_store(h) {
                    let mut buf = Vec::new();
                    hdr.encode(&mut buf);
                    headers.push(buf);
                }
            }
            drop(ctx);
            let _ = swarm
                .behaviour_mut()
                .chain_sync
                .send_response(channel, GetHeadersResponse { headers });
        }

        // --- Block pull: client received block + proof ---
        SwarmEvent::Behaviour(NodeBehaviourEvent::BlockSync(
            request_response::Event::Message {
                message: request_response::Message::Response { response, .. },
                peer,
            },
        )) => {
            if let Some(block_bytes) = response.block_bytes {
                if block_bytes.len() > MAX_BLOCK_BYTES {
                    tracing::warn!(peer = %peer, len = block_bytes.len(), "block pull response too large — dropped");
                } else {
                    let proof_bytes = response.block_proof_bytes.unwrap_or_default();
                    if proof_bytes.len() > MAX_BLOCK_PROOF_BYTES {
                        tracing::warn!(peer = %peer, len = proof_bytes.len(), "block proof too large — dropped");
                    } else {
                        tracing::debug!(peer = %peer, "received block via pull");
                        let _ = event_tx.send(NetworkEvent::NewBlock {
                            from: peer,
                            block_bytes,
                            block_proof_bytes: proof_bytes,
                        });
                    }
                }
            }
        }

        // --- Block pull: server side — serve block + proof to requesting peer ---
        //
        // Only last FINALITY_DEPTH blocks are available; pruned blocks return None.
        // Peers that request pruned blocks must do a full state sync instead.
        SwarmEvent::Behaviour(NodeBehaviourEvent::BlockSync(
            request_response::Event::Message {
                message:
                    request_response::Message::Request {
                        request, channel, ..
                    },
                ..
            },
        )) => {
            let ctx = chain.read().await;
            let block_bytes = ctx.store.get_recent_block(request.height).ok().flatten();
            // Also load the block proof if we have it.
            // Proofs are stored temporarily (last FINALITY_DEPTH blocks) for the
            // recursive prover and for serving to syncing peers.
            let block_proof_bytes = ctx.store.get_block_proof(request.height).ok().flatten();
            drop(ctx);
            let _ = swarm.behaviour_mut().block_sync.send_response(
                channel,
                GetRecentBlockResponse {
                    block_bytes,
                    block_proof_bytes,
                },
            );
        }

        // --- Request-Response: recursive proof ---
        SwarmEvent::Behaviour(NodeBehaviourEvent::ProofSync(
            request_response::Event::Message {
                message: request_response::Message::Request { channel, .. },
                ..
            },
        )) => {
            let ctx = chain.read().await;
            let proof_bytes = ctx.store.get_recursive_proof().ok().flatten();
            let tip_bytes = {
                let mut buf = Vec::new();
                ctx.tip_header().encode(&mut buf);
                Some(buf)
            };
            drop(ctx);
            let _ = swarm.behaviour_mut().proof_sync.send_response(
                channel,
                GetRecursiveProofResponse {
                    proof_bytes,
                    tip_header_bytes: tip_bytes,
                },
            );
        }

        // --- Request-Response: recursive proof client side (our proof request answered) ---
        SwarmEvent::Behaviour(NodeBehaviourEvent::ProofSync(
            request_response::Event::Message {
                message: request_response::Message::Response { response, .. },
                peer,
            },
        )) => {
            let proof_bytes = response.proof_bytes.unwrap_or_default();
            let tip_header_bytes = response.tip_header_bytes.unwrap_or_default();
            if proof_bytes.len() > MAX_RECURSIVE_PROOF_BYTES {
                tracing::warn!(peer = %peer, len = proof_bytes.len(), "recursive proof response too large — dropped");
                return;
            }
            if tip_header_bytes.len() > MAX_HEADER_BYTES {
                tracing::warn!(peer = %peer, len = tip_header_bytes.len(), "tip header in proof response too large — dropped");
                return;
            }
            tracing::debug!(
                from = %peer,
                proof_len = proof_bytes.len(),
                "received recursive proof from peer"
            );
            let _ = event_tx.send(NetworkEvent::RecursiveProof {
                from: peer,
                proof_bytes,
                tip_header_bytes,
            });
        }

        // --- State sync: manifest server (step 1) ---
        //
        // Serves metadata + active segment IDs.  Tiny response (~few KB).
        // Client uses this to know which segments to request next.
        SwarmEvent::Behaviour(NodeBehaviourEvent::StateManifestSync(
            request_response::Event::Message {
                message:
                    request_response::Message::Request {
                        request, channel, ..
                    },
                ..
            },
        )) => {
            use noid_chain::consensus::params::ANCHOR_DEPTH;
            let manifest = {
                let ctx = chain.write().await;
                let tip_h = ctx.tip_height();
                if tip_h == 0 || tip_h <= request.requester_height {
                    GetStateManifestResponse::default()
                } else {
                    let eff_log = ctx.state.state.effective_log_segment_size() as u8;
                    let segment_ids: Vec<u16> = ctx.state.state.active_segment_ids().collect();
                    let header_start = tip_h.saturating_sub(154);
                    let recent_headers = (header_start..=tip_h)
                        .filter_map(|h| {
                            ctx.recent_headers
                                .get(&h)
                                .cloned()
                                .or_else(|| ctx.get_header_from_store(h).ok().flatten())
                        })
                        .map(|hdr| {
                            let mut b = Vec::new();
                            hdr.encode(&mut b);
                            b
                        })
                        .collect();
                    let null_start = tip_h.saturating_sub(ANCHOR_DEPTH - 1);
                    let nullifier_blocks = (null_start..=tip_h)
                        .map(|h| {
                            ctx.store
                                .get_undo_log(h)
                                .ok()
                                .flatten()
                                .map(|u| u.tx_hashes.iter().map(|t| t.0).collect())
                                .unwrap_or_default()
                        })
                        .collect();
                    let tip_hdr = ctx.tip_header().clone();
                    tracing::info!(
                        requester_height = request.requester_height,
                        our_height = tip_h,
                        segments = segment_ids.len(),
                        "serving state manifest"
                    );
                    GetStateManifestResponse {
                        tip_height: tip_h,
                        tip_hash: noid_chain::consensus::pow::full_block_hash(&tip_hdr),
                        log_slots: tip_hdr.log_slots,
                        active_slot_count: tip_hdr.active_slot_count,
                        alloc_counter: tip_hdr.alloc_counter,
                        eff_log,
                        segment_ids,
                        recent_headers,
                        nullifier_blocks,
                    }
                }
            };
            let _ = swarm
                .behaviour_mut()
                .state_manifest_sync
                .send_response(channel, manifest);
        }

        // --- State sync: manifest client (step 1 response) ---
        SwarmEvent::Behaviour(NodeBehaviourEvent::StateManifestSync(
            request_response::Event::Message {
                message: request_response::Message::Response { response, .. },
                peer,
            },
        )) => {
            if response.tip_height > 0 {
                const MAX_RECENT_HEADERS: usize = 512;
                if response.recent_headers.len() > MAX_RECENT_HEADERS {
                    tracing::warn!(from = %peer, "manifest: too many headers, dropping");
                    return;
                }
                if response.recent_headers.iter().any(|h| h.len() > MAX_HEADER_BYTES) {
                    tracing::warn!(from = %peer, "manifest: oversized header entry, dropping");
                    return;
                }
                if response.segment_ids.len() > 4096 {
                    tracing::warn!(from = %peer, "manifest: too many segment IDs, dropping");
                    return;
                }
                tracing::info!(
                    from = %peer,
                    tip = response.tip_height,
                    segments = response.segment_ids.len(),
                    "received state manifest"
                );
                let _ = event_tx.send(NetworkEvent::StateManifest {
                    from: peer,
                    manifest: Box::new(response),
                });
            }
        }

        // --- State sync: segment server (step 2) ---
        //
        // Serves one encoded segment (~3 MB) per request.
        // Lock is held only during column clone; encoding happens outside.
        // Rejects requests if our tip has moved more than FINALITY_DEPTH
        // past the expected_tip_height to prevent serving stale segments.
        SwarmEvent::Behaviour(NodeBehaviourEvent::StateSegmentSync(
            request_response::Event::Message {
                message:
                    request_response::Message::Request {
                        request, channel, ..
                    },
                ..
            },
        )) => {
            use noid_chain::consensus::params::FINALITY_DEPTH;
            use noid_chain::storage::serial::encode_segment;
            let seg_id = request.segment_id;
            let result = {
                let mut ctx = chain.write().await;
                let our_tip = ctx.tip_height();
                // Exact match: if our state has advanced past the manifest's tip,
                // the segment data won't match the client's expected state_root.
                // Return None so the client re-requests a fresh manifest.
                // Also reject if we're far ahead (stale client on a fork).
                if our_tip != request.expected_tip_height
                    && our_tip > request.expected_tip_height + FINALITY_DEPTH
                {
                    None
                } else if our_tip != request.expected_tip_height {
                    tracing::debug!(
                        our_tip,
                        expected = request.expected_tip_height,
                        "segment request tip mismatch — state advanced"
                    );
                    None
                } else {
                    let eff_log = ctx.state.state.effective_log_segment_size() as u8;
                    let cols = ctx.state.state.segment_columns(seg_id).clone();
                    Some((eff_log, cols))
                }
            };
            let response = match result {
                None => GetStateSegmentResponse {
                    segment_id: seg_id,
                    eff_log: 0,
                    data: None,
                },
                Some((eff_log, cols)) => {
                    // Encode OUTSIDE the lock (CPU-heavy, ~3 MB allocation).
                    let data = encode_segment(&cols, eff_log);
                    GetStateSegmentResponse {
                        segment_id: seg_id,
                        eff_log,
                        data: Some(data),
                    }
                }
            };
            let _ = swarm
                .behaviour_mut()
                .state_segment_sync
                .send_response(channel, response);
        }

        // --- State sync: segment client (step 2 response) ---
        SwarmEvent::Behaviour(NodeBehaviourEvent::StateSegmentSync(
            request_response::Event::Message {
                message: request_response::Message::Response { response, .. },
                peer,
            },
        )) => {
            if let Some(ref data) = response.data {
                if data.len() > MAX_SEGMENT_BYTES {
                    tracing::warn!(peer = %peer, segment = response.segment_id, len = data.len(), "segment response too large — dropped");
                    return;
                }
            }
            tracing::debug!(
                from = %peer,
                segment_id = response.segment_id,
                present = response.data.is_some(),
                "received state segment"
            );
            let _ = event_tx.send(NetworkEvent::StateSegment {
                from: peer,
                response,
            });
        }

        // --- Mempool sync: server side (peer requests our mempool) ---
        SwarmEvent::Behaviour(NodeBehaviourEvent::MempoolSync(
            request_response::Event::Message {
                message:
                    request_response::Message::Request { channel, .. },
                peer,
            },
        )) => {
            let txs = mempool.all_intent_bytes().await;
            tracing::debug!(
                peer = %peer,
                tx_count = txs.len(),
                "serving mempool sync request"
            );
            let _ = swarm
                .behaviour_mut()
                .mempool_sync
                .send_response(channel, crate::protocol::GetMempoolResponse { txs });
        }

        // --- Mempool sync: client side (response to our request) ---
        SwarmEvent::Behaviour(NodeBehaviourEvent::MempoolSync(
            request_response::Event::Message {
                message: request_response::Message::Response { response, .. },
                peer,
            },
        )) => {
            const MAX_SYNC_TXS: usize = 8192;
            let mut txs = response.txs;
            if txs.len() > MAX_SYNC_TXS {
                tracing::warn!(
                    from = %peer,
                    count = txs.len(),
                    "mempool sync response oversized, truncating to {MAX_SYNC_TXS}"
                );
                txs.truncate(MAX_SYNC_TXS);
            }
            if !txs.is_empty() {
                tracing::debug!(
                    from = %peer,
                    tx_count = txs.len(),
                    "received mempool sync response"
                );
                let _ = event_tx.send(NetworkEvent::MempoolSyncResponse {
                    from: peer,
                    txs,
                });
            }
        }

        // --- Mempool sync: outbound failure ---
        SwarmEvent::Behaviour(NodeBehaviourEvent::MempoolSync(
            request_response::Event::OutboundFailure { peer, error, .. },
        )) => {
            tracing::debug!(peer = %peer, err = %error, "mempool sync request failed");
        }

        // --- Connection events ---
        SwarmEvent::ConnectionEstablished {
            peer_id,
            num_established,
            ..
        } => {
            // Only emit PeerConnected on the FIRST connection to a peer.
            // Multiple connections to the same peer are common (simultaneous dials,
            // mDNS re-discovery, relay + direct). Emitting for each one causes
            // redundant SyncBlocksFrom and RequestMempoolSync from the node handler.
            if num_established.get() == 1 {
                let _ = event_tx.send(NetworkEvent::PeerConnected(peer_id));
                tracing::debug!(peer = %peer_id, "peer connected");
            }
            // Clear any pending reconnect entry — connection succeeded.
            reconnect.remove(&peer_id);
        }
        SwarmEvent::ConnectionClosed {
            peer_id,
            num_established,
            endpoint,
            cause,
            ..
        } => {
            // Only emit PeerDisconnected when the LAST connection to a peer closes.
            if num_established == 0 {
                let _ = event_tx.send(NetworkEvent::PeerDisconnected(peer_id));
                tracing::debug!(peer = %peer_id, cause = ?cause, "peer disconnected");
                // Schedule reconnect for peers we dialled (outbound connections).
                // We don't attempt to reconnect inbound peers — they should re-dial us.
                if let libp2p::core::ConnectedPoint::Dialer { address, .. } = endpoint {
                    if !reconnect.contains_key(&peer_id) {
                        let retry_at =
                            tokio::time::Instant::now() + std::time::Duration::from_secs(10);
                        reconnect.insert(peer_id, (address, retry_at, 0));
                        tracing::debug!(peer = %peer_id, "scheduled reconnect in 10s");
                    }
                }
            }
        }

        // --- Outgoing connection failed (dial error) ---
        SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
            tracing::debug!(peer = ?peer_id, err = %error, "outgoing connection error");
            // The error is already logged; Kademlia / GossipSub will try
            // other peers.  No explicit action needed here.
        }

        // --- Request-response failure: emit event so consumers can retry ---
        SwarmEvent::Behaviour(NodeBehaviourEvent::BlockSync(
            request_response::Event::OutboundFailure { peer, error, .. },
        )) => {
            tracing::debug!(peer = %peer, err = %error, "block sync request failed");
            // Emit a generic disconnect so the sync state machine can retry.
            let _ = event_tx.send(NetworkEvent::PeerDisconnected(peer));
        }

        SwarmEvent::Behaviour(NodeBehaviourEvent::StateManifestSync(
            request_response::Event::OutboundFailure { peer, error, .. },
        )) => {
            tracing::debug!(peer = %peer, err = %error, "manifest sync request failed");
        }

        SwarmEvent::Behaviour(NodeBehaviourEvent::StateSegmentSync(
            request_response::Event::OutboundFailure { peer, error, .. },
        )) => {
            tracing::debug!(peer = %peer, err = %error, "segment sync request failed");
        }

        SwarmEvent::Behaviour(NodeBehaviourEvent::ProofSync(
            request_response::Event::OutboundFailure { peer, error, .. },
        )) => {
            tracing::debug!(peer = %peer, err = %error, "proof sync request failed");
        }

        SwarmEvent::NewListenAddr { address, .. } => {
            tracing::debug!(%address, "P2P listening");
        }

        _ => {}
    }
}
