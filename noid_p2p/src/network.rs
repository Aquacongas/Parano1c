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
}

/// Events emitted by the P2P layer to the node.
#[derive(Debug, Clone)]
pub enum NetworkEvent {
    /// A new block arrived from a peer.
    NewBlock { from: PeerId, block_bytes: Vec<u8> },
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

    /// Request a full state snapshot from a peer (initial sync).
    pub async fn request_state_snapshot(&self, peer: PeerId) {
        let _ = self
            .cmd_tx
            .send(NetworkCommand::RequestStateSnapshot { peer })
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
        // Drain all pending commands first (priority: outgoing blocks must propagate
        // immediately without waiting for swarm event processing).
        while let Ok(cmd) = cmd_rx.try_recv() {
            handle_network_command(&mut swarm, cmd);
        }

        tokio::select! {
            // Swarm events.
            event = swarm.select_next_some() => {
                handle_swarm_event(&mut swarm, event, &event_tx, &chain).await;
            }

            // Commands from the node (when no swarm event pending).
            cmd = cmd_rx.recv() => {
                match cmd {
                    Some(cmd) => handle_network_command(&mut swarm, cmd),
                    None => break, // cmd_tx dropped
                }
            }
        }
    }
    Ok(())
}

/// Process a single network command. Separated from the select! loop so that
/// pending commands can be drained synchronously via `try_recv` before blocking.
fn handle_network_command(swarm: &mut libp2p::Swarm<NodeBehaviour>, cmd: NetworkCommand) {
    match cmd {
        NetworkCommand::BroadcastBlock { block_bytes } => {
            let topic = gossipsub::IdentTopic::new(Topics::BLOCKS);
            if let Err(e) = swarm.behaviour_mut().gossipsub.publish(topic, block_bytes) {
                tracing::warn!("gossipsub publish block: {e}");
            }
        }
        NetworkCommand::BroadcastTx { intent_bytes } => {
            let topic = gossipsub::IdentTopic::new(Topics::TXS);
            if let Err(e) = swarm.behaviour_mut().gossipsub.publish(topic, intent_bytes) {
                tracing::warn!("gossipsub publish tx: {e}");
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
            for h in from_height..(from_height + count as u64) {
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
            tracing::info!(%address, "P2P listening");
        }

        _ => {}
    }
}
