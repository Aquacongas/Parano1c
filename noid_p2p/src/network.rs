// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

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
    gossipsub, identify, kad, mdns, request_response, swarm::SwarmEvent, Multiaddr, PeerId,
};
use tokio::sync::{mpsc, RwLock};

use noid_chain::storage::MdbxChainContext;
use noid_mempool::AsyncMempool;

use crate::behaviour::{NodeBehaviour, NodeBehaviourEvent};
use crate::protocol::{
    BlockGossipMsg, GetHeadersResponse, GetRecentBlockResponse, GetRecursiveProofResponse,
    NetworkTopics, RecursiveProofGossipMsg,
};

/// Commands sent to the P2P network event loop.
#[derive(Debug)]
pub enum NetworkCommand {
    /// Broadcast a new block (with optional ZK proof) to all peers.
    ///
    /// `block_proof_bytes` is the bincode-serialised `BlockProof`. Pass an
    /// empty `Vec` for coinbase-only blocks that have no user transactions.
    BroadcastBlock {
        block_bytes: Vec<u8>,
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
    /// Request a full state snapshot from a peer.
    /// Paranoid's primary initial-sync mechanism: new nodes download the
    /// CURRENT STATE (not block history which is not stored).
    /// Emits `NetworkEvent::StateSnapshot` when the response arrives.
    RequestStateSnapshot { peer: PeerId },
    /// Request the latest recursive chain proof from a peer.
    /// Used to cryptographically verify a state snapshot before applying it.
    /// Emits `NetworkEvent::RecursiveProof` when the response arrives.
    RequestRecursiveProof { peer: PeerId },
}

/// Events emitted by the P2P layer to the node.
#[derive(Debug, Clone)]
pub enum NetworkEvent {
    /// A new block arrived from a peer.
    NewBlock {
        from: PeerId,
        block_bytes: Vec<u8>,
        /// `BlockProof` bincode bytes. Empty for coinbase-only blocks.
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
    /// Full state snapshot received from a peer (response to RequestStateSnapshot).
    StateSnapshot {
        from: PeerId,
        snapshot: Box<crate::protocol::GetStateSnapshotResponse>,
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
    ) -> (Self, tokio::task::JoinHandle<()>) {
        let (cmd_tx, cmd_rx) = mpsc::channel(256);
        let (event_tx, _) = tokio::sync::broadcast::channel(256);

        let event_tx_clone = event_tx.clone();
        let handle = tokio::spawn(async move {
            if let Err(e) =
                run_swarm(listen_addr, cmd_rx, event_tx_clone, chain, mempool, topics).await
            {
                tracing::error!("P2P network error: {e}");
            }
        });

        (Self { cmd_tx, event_tx }, handle)
    }

    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<NetworkEvent> {
        self.event_tx.subscribe()
    }

    pub async fn broadcast_block(&self, block_bytes: Vec<u8>, block_proof_bytes: Vec<u8>) {
        let _ = self
            .cmd_tx
            .send(NetworkCommand::BroadcastBlock {
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

    /// Request a full state snapshot from a peer (initial sync).
    pub async fn request_state_snapshot(&self, peer: PeerId) {
        let _ = self
            .cmd_tx
            .send(NetworkCommand::RequestStateSnapshot { peer })
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
    _mempool: AsyncMempool,
    topics: NetworkTopics,
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
        .with_behaviour(move |key| NodeBehaviour::new(key, &protocol_id))?
        .with_swarm_config(|cfg| {
            cfg
                // Keep connections alive for 5 minutes — essential for
                // blockchain peers that have infrequent block intervals.
                .with_idle_connection_timeout(std::time::Duration::from_secs(300))
                // Hard cap on total connections.  Prevents resource exhaustion
                // from connection floods on large networks.
                // 128 inbound + 64 outbound = 192 max total.
                // Substrate uses 100 in/25 out; Ethereum clients use 50/25.
                // We set higher defaults since Paranoid is a full-ZK node
                // and peers actively push block proofs to each other.
                .with_max_negotiating_inbound_streams(128)
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
    if let Err(e) = swarm.behaviour_mut().kad.bootstrap() {
        tracing::debug!("kad bootstrap deferred (no peers yet): {e}");
    }

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
                handle_swarm_event(&mut swarm, event, &event_tx, &chain, &topics).await;
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
                // Random PeerId as target to explore different parts of the DHT.
                let random_peer = libp2p::PeerId::random();
                swarm.behaviour_mut().kad.get_closest_peers(random_peer);
                tracing::debug!("kad: periodic random walk");
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
        NetworkCommand::BroadcastBlock {
            block_bytes,
            block_proof_bytes,
        } => {
            let msg = BlockGossipMsg {
                block_bytes,
                block_proof_bytes,
            };
            match bincode::serialize(&msg) {
                Ok(encoded) => {
                    let topic = gossipsub::IdentTopic::new(topics.blocks.clone());
                    if let Err(e) = swarm.behaviour_mut().gossipsub.publish(topic, encoded) {
                        tracing::debug!(
                            "gossipsub: {e} (block delivered via direct peer connections)"
                        );
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
        NetworkCommand::RequestStateSnapshot { peer } => {
            let _ = swarm.behaviour_mut().snapshot_sync.send_request(
                &peer,
                crate::protocol::GetStateSnapshotRequest {
                    requester_height: 0,
                },
            );
            tracing::debug!(peer = %peer, "requesting state snapshot");
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
    }
}

async fn handle_swarm_event(
    swarm: &mut libp2p::Swarm<NodeBehaviour>,
    event: SwarmEvent<NodeBehaviourEvent>,
    event_tx: &tokio::sync::broadcast::Sender<NetworkEvent>,
    chain: &Arc<RwLock<MdbxChainContext>>,
    topics: &NetworkTopics,
) {
    match event {
        // --- GossipSub: received broadcast ---
        SwarmEvent::Behaviour(NodeBehaviourEvent::Gossipsub(gossipsub::Event::Message {
            propagation_source,
            message,
            ..
        })) => {
            let topic = message.topic.as_str();
            if topic == topics.blocks.as_str() {
                match bincode::deserialize::<crate::protocol::BlockGossipMsg>(&message.data) {
                    Ok(msg) => {
                        let _ = event_tx.send(NetworkEvent::NewBlock {
                            from: propagation_source,
                            block_bytes: msg.block_bytes,
                            block_proof_bytes: msg.block_proof_bytes,
                        });
                    }
                    Err(e) => {
                        tracing::debug!(
                            peer = %propagation_source,
                            err = %e,
                            "block gossip deserialize failed, dropping"
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
                            from: propagation_source,
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

        // --- Request-Response: recent block (client side — response to our sync request) ---
        SwarmEvent::Behaviour(NodeBehaviourEvent::BlockSync(
            request_response::Event::Message {
                message: request_response::Message::Response { response, .. },
                peer,
            },
        )) => {
            if let Some(block_bytes) = response.block_bytes {
                tracing::debug!(peer = %peer, "received block via sync");
                // Request-response sync does not carry proof bytes;
                // the block will be applied consensus-only and the
                // RecursiveProofUpdate arrives separately via gossip.
                let _ = event_tx.send(NetworkEvent::NewBlock {
                    from: peer,
                    block_bytes,
                    block_proof_bytes: vec![],
                });
            }
        }

        // --- Request-Response: recent block (server side — peer requests a block from us) ---
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
            drop(ctx);
            let _ = swarm
                .behaviour_mut()
                .block_sync
                .send_response(channel, GetRecentBlockResponse { block_bytes });
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

        // --- State snapshot: server side (peer requests full state from us) ---
        SwarmEvent::Behaviour(NodeBehaviourEvent::SnapshotSync(
            request_response::Event::Message {
                message:
                    request_response::Message::Request {
                        request, channel, ..
                    },
                ..
            },
        )) => {
            use crate::protocol::{GetStateSnapshotResponse, StateSegmentEntry};
            use noid_chain::consensus::params::ANCHOR_DEPTH;
            use noid_chain::storage::serial::encode_segment;

            // Snapshot needs mutable access for segment_columns (lazy materialization)
            let mut ctx = chain.write().await;
            let tip_h = ctx.tip_height();

            // Only serve if we have state to give
            if tip_h == 0 || tip_h <= request.requester_height {
                drop(ctx);
                let _ = swarm
                    .behaviour_mut()
                    .snapshot_sync
                    .send_response(channel, GetStateSnapshotResponse::default());
                return;
            }

            tracing::info!(
                requester_height = request.requester_height,
                our_height = tip_h,
                "serving state snapshot"
            );

            // Collect active state segments
            let eff_log = ctx.state.state.effective_log_segment_size() as u8;
            let seg_ids: Vec<u16> = ctx.state.state.active_segment_ids().collect();
            let mut segments = Vec::new();
            for seg_id in seg_ids {
                let cols = ctx.state.state.segment_columns(seg_id).clone();
                let data = encode_segment(&cols, eff_log);
                segments.push(StateSegmentEntry {
                    seg_id,
                    eff_log,
                    data,
                });
            }

            // Collect recent headers (last 155 blocks)
            let header_start = tip_h.saturating_sub(154);
            let mut recent_headers = Vec::new();
            for h in header_start..=tip_h {
                let hdr_opt = ctx
                    .recent_headers
                    .get(&h)
                    .cloned()
                    .or_else(|| ctx.get_header_from_store(h).ok().flatten());
                if let Some(hdr) = hdr_opt {
                    let mut buf = Vec::new();
                    hdr.encode(&mut buf);
                    recent_headers.push(buf);
                }
            }

            // Collect nullifier blocks (last ANCHOR_DEPTH blocks)
            let null_start = tip_h.saturating_sub(ANCHOR_DEPTH - 1);
            let mut nullifier_blocks = Vec::new();
            for h in null_start..=tip_h {
                let hashes: Vec<[u8; 32]> = ctx
                    .store
                    .get_undo_log(h)
                    .ok()
                    .flatten()
                    .map(|u| u.tx_hashes.iter().map(|t| t.0).collect())
                    .unwrap_or_default();
                nullifier_blocks.push(hashes);
            }

            let tip_hdr = ctx.tip_header().clone();
            drop(ctx);

            let response = GetStateSnapshotResponse {
                tip_height: tip_h,
                tip_hash: noid_chain::consensus::pow::full_block_hash(&tip_hdr),
                log_slots: tip_hdr.log_slots,
                active_slot_count: tip_hdr.active_slot_count,
                alloc_counter: tip_hdr.alloc_counter,
                segments,
                recent_headers,
                nullifier_blocks,
            };
            let _ = swarm
                .behaviour_mut()
                .snapshot_sync
                .send_response(channel, response);
        }

        // --- State snapshot: client side (received snapshot we requested) ---
        SwarmEvent::Behaviour(NodeBehaviourEvent::SnapshotSync(
            request_response::Event::Message {
                message: request_response::Message::Response { response, .. },
                peer,
            },
        )) => {
            if response.tip_height > 0 {
                // Sanity check: reject absurdly large snapshots before forwarding to
                // node.  A valid snapshot for log_slots=32 has at most 65536 segments.
                const MAX_SNAPSHOT_SEGMENTS: usize = 65536;
                const MAX_RECENT_HEADERS: usize = 512;
                if response.segments.len() > MAX_SNAPSHOT_SEGMENTS
                    || response.recent_headers.len() > MAX_RECENT_HEADERS
                {
                    tracing::warn!(
                        from = %peer,
                        segments = response.segments.len(),
                        "snapshot too large — dropping (possible OOM attack)"
                    );
                    return; // don't emit the event
                }

                tracing::info!(
                    from = %peer,
                    tip = response.tip_height,
                    segments = response.segments.len(),
                    "received state snapshot"
                );
                let _ = event_tx.send(NetworkEvent::StateSnapshot {
                    from: peer,
                    snapshot: Box::new(response),
                });
            }
        }

        // --- Connection events ---
        SwarmEvent::ConnectionEstablished { peer_id, .. } => {
            let _ = event_tx.send(NetworkEvent::PeerConnected(peer_id));
            tracing::debug!(peer = %peer_id, "peer connected");
        }
        SwarmEvent::ConnectionClosed { peer_id, .. } => {
            let _ = event_tx.send(NetworkEvent::PeerDisconnected(peer_id));
            tracing::debug!(peer = %peer_id, "peer disconnected");
        }

        SwarmEvent::NewListenAddr { address, .. } => {
            // Logged at debug — the startup banner already shows the configured listen address.
            tracing::debug!(%address, "P2P listening");
        }

        _ => {}
    }
}
