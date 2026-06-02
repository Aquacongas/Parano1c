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
use libp2p::{gossipsub, identify, request_response, swarm::SwarmEvent, Multiaddr, PeerId};
use tokio::sync::{mpsc, RwLock};

use noid_chain::storage::MdbxChainContext;
use noid_mempool::AsyncMempool;

use crate::behaviour::{NodeBehaviour, NodeBehaviourEvent};
use crate::protocol::{
    GetHeadersResponse, GetRecentBlockResponse, GetRecursiveProofResponse, Topics,
};

/// Commands sent to the P2P network event loop.
#[derive(Debug)]
pub enum NetworkCommand {
    /// Broadcast a new block to all peers.
    BroadcastBlock { block_bytes: Vec<u8> },
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
}

/// Events emitted by the P2P layer to the node.
#[derive(Debug, Clone)]
pub enum NetworkEvent {
    /// A new block arrived from a peer.
    NewBlock { from: PeerId, block_bytes: Vec<u8> },
    /// A new TxIntent arrived from a peer.
    NewTx { from: PeerId, intent_bytes: Vec<u8> },
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
    /// `topics` controls which gossipsub topics to subscribe to — use
    /// `NetworkTopics::for_network_cfg(cfg)` to get the right network.
    pub fn start(
        listen_addr: Multiaddr,
        chain: Arc<RwLock<MdbxChainContext>>,
        mempool: AsyncMempool,
    ) -> (Self, tokio::task::JoinHandle<()>) {
        let (cmd_tx, cmd_rx) = mpsc::channel(256);
        let (event_tx, _) = tokio::sync::broadcast::channel(256);

        let event_tx_clone = event_tx.clone();
        let handle = tokio::spawn(async move {
            if let Err(e) = run_swarm(listen_addr, cmd_rx, event_tx_clone, chain, mempool).await {
                tracing::error!("P2P network error: {e}");
            }
        });

        (Self { cmd_tx, event_tx }, handle)
    }

    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<NetworkEvent> {
        self.event_tx.subscribe()
    }

    pub async fn broadcast_block(&self, block_bytes: Vec<u8>) {
        let _ = self
            .cmd_tx
            .send(NetworkCommand::BroadcastBlock { block_bytes })
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
) -> anyhow::Result<()> {
    use libp2p::{noise, tcp, yamux, SwarmBuilder};

    let mut swarm = SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_behaviour(|key| NodeBehaviour::new(key))?
        .with_swarm_config(|cfg| {
            // Keep connections alive for 5 minutes — essential for blockchain peers.
            cfg.with_idle_connection_timeout(std::time::Duration::from_secs(300))
        })
        .build();

    // Subscribe to gossip topics.
    let blocks_topic = gossipsub::IdentTopic::new(Topics::BLOCKS);
    let txs_topic = gossipsub::IdentTopic::new(Topics::TXS);
    swarm.behaviour_mut().gossipsub.subscribe(&blocks_topic)?;
    swarm.behaviour_mut().gossipsub.subscribe(&txs_topic)?;

    swarm.listen_on(listen_addr)?;

    loop {
        tokio::select! {
            // Swarm events.
            event = swarm.select_next_some() => {
                handle_swarm_event(&mut swarm, event, &event_tx, &chain).await;
            }

            // Commands from the node.
            cmd = cmd_rx.recv() => {
                match cmd {
                    Some(NetworkCommand::BroadcastBlock { block_bytes }) => {
                        let topic = gossipsub::IdentTopic::new(Topics::BLOCKS);
                        if let Err(e) = swarm.behaviour_mut().gossipsub.publish(topic, block_bytes) {
                            tracing::warn!("gossipsub publish block: {e}");
                        }
                    }
                    Some(NetworkCommand::BroadcastTx { intent_bytes }) => {
                        let topic = gossipsub::IdentTopic::new(Topics::TXS);
                        if let Err(e) = swarm.behaviour_mut().gossipsub.publish(topic, intent_bytes) {
                            tracing::warn!("gossipsub publish tx: {e}");
                        }
                    }
                    Some(NetworkCommand::Dial { addr }) => {
                        if let Err(e) = swarm.dial(addr) {
                            tracing::warn!("dial: {e}");
                        }
                    }
                    Some(NetworkCommand::PeerCount { reply }) => {
                        let count = swarm.connected_peers().count();
                        let _ = reply.send(count);
                    }
                    Some(NetworkCommand::SyncBlocksFrom { peer, from_height, count }) => {
                        for h in from_height..(from_height + count as u64) {
                            let req_id = swarm
                                .behaviour_mut()
                                .block_sync
                                .send_request(&peer, crate::protocol::GetRecentBlockRequest { height: h });
                            tracing::debug!(peer = %peer, height = h, "requesting block for sync");
                            let _ = req_id;
                        }
                    }
                    Some(NetworkCommand::RequestBlock { peer, height }) => {
                        // Orphan resolution: request a specific block by height.
                        // Used when we receive a block whose parent is unknown.
                        let req_id = swarm
                            .behaviour_mut()
                            .block_sync
                            .send_request(&peer, crate::protocol::GetRecentBlockRequest { height });
                        tracing::debug!(peer = %peer, height, "requesting block for orphan resolution");
                        let _ = req_id;
                    }
                    None => break, // cmd_tx dropped
                }
            }
        }
    }
    Ok(())
}

async fn handle_swarm_event(
    swarm: &mut libp2p::Swarm<NodeBehaviour>,
    event: SwarmEvent<NodeBehaviourEvent>,
    event_tx: &tokio::sync::broadcast::Sender<NetworkEvent>,
    chain: &Arc<RwLock<MdbxChainContext>>,
) {
    match event {
        // --- GossipSub: received broadcast ---
        SwarmEvent::Behaviour(NodeBehaviourEvent::Gossipsub(gossipsub::Event::Message {
            propagation_source,
            message,
            ..
        })) => {
            let topic = message.topic.as_str();
            if topic == Topics::BLOCKS {
                let _ = event_tx.send(NetworkEvent::NewBlock {
                    from: propagation_source,
                    block_bytes: message.data,
                });
            } else if topic == Topics::TXS {
                let _ = event_tx.send(NetworkEvent::NewTx {
                    from: propagation_source,
                    intent_bytes: message.data,
                });
            }
        }

        // --- Identify: update peer routing ---
        SwarmEvent::Behaviour(NodeBehaviourEvent::Identify(identify::Event::Received {
            peer_id,
            info,
            ..
        })) => {
            // After identify, add the peer to gossipsub routing.
            swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
            tracing::debug!(
                peer = %peer_id,
                protocols = ?info.protocols,
                "peer identified"
            );
        }

        // --- Request-Response: headers ---
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
                let _ = event_tx.send(NetworkEvent::NewBlock {
                    from: peer,
                    block_bytes,
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
            tracing::info!(%address, "P2P listening");
        }

        _ => {}
    }
}
