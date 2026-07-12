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
use std::time::{Duration, Instant};

use futures::StreamExt;
use libp2p::{
    autonat, dcutr, gossipsub, identify, kad, mdns, relay, request_response, swarm::SwarmEvent,
    Multiaddr, PeerId,
};
use tokio::sync::{mpsc, RwLock, Semaphore};

use noid_chain::consensus::wire_limits::{
    proof_sidecar_combined_len_ok, INLINE_BLOCK_GOSSIP_THRESHOLD, MAX_BLOCK_AUTH_SIDECAR_BYTES,
    MAX_BLOCK_BYTES, MAX_BLOCK_PROOF_BYTES, MAX_BLOCK_PROOF_PLUS_SIDECAR_BYTES, MAX_HEADER_BYTES,
    MAX_HISTORY_PROOF_BYTES, MAX_MEMPOOL_SYNC_BYTES, MAX_MEMPOOL_SYNC_TXS, MAX_SEGMENT_BYTES,
    MAX_SNAPSHOT_MANIFEST_SEGMENTS, MAX_TX_INTENT_BYTES_GLOBAL,
};
use noid_chain::storage::{encoded_segment_len_for_eff_log, MdbxChainContext};
use noid_chain::storage::{
    export_snapshot_generation, open_snapshot_generation, SnapshotGeneration,
};
use noid_mempool::AsyncMempool;

use crate::behaviour::{NodeBehaviour, NodeBehaviourEvent};
use crate::outbound_budget::OutboundResponseBudget;
use crate::protocol::{
    BlockGossipMsg, GetHeadersResponse, GetHistoryProofResponse, GetRecentBlockResponse,
    GetStateManifestResponse, GetStateSegmentResponse, NetworkTopics,
};

struct PendingStateSegmentResponse {
    channel: request_response::ResponseChannel<GetStateSegmentResponse>,
    response: GetStateSegmentResponse,
}

struct PendingBlockResponse {
    channel: request_response::ResponseChannel<GetRecentBlockResponse>,
    response: GetRecentBlockResponse,
}

struct PendingHistoryProofResponse {
    channel: request_response::ResponseChannel<GetHistoryProofResponse>,
    response: GetHistoryProofResponse,
}

type SnapshotExportKey = (u64, [u8; 32]);
type SnapshotExport = Arc<SnapshotGeneration>;

const MAX_SNAPSHOT_EXPORTS: usize = 2;
const MAX_OUTBOUND_BLOCK_RESPONSE_BYTES: usize =
    MAX_BLOCK_BYTES + MAX_BLOCK_PROOF_PLUS_SIDECAR_BYTES;
const MAX_OUTBOUND_HISTORY_RESPONSE_BYTES: usize = MAX_HISTORY_PROOF_BYTES + MAX_HEADER_BYTES;

// Hard caps on incoming response sizes are shared via noid_chain::consensus::wire_limits.

fn snapshot_suffix_is_retained(tip_height: u64, proof_height: u64) -> bool {
    proof_height <= tip_height
        && tip_height.saturating_sub(proof_height)
            <= noid_chain::consensus::params::RECENT_BLOCK_RETENTION_DEPTH
}

fn local_checkpoint_history_proof(ctx: &MdbxChainContext) -> Option<(u64, Vec<u8>)> {
    let coverage = ctx.store.get_checkpoint_coverage().ok().flatten()?;
    let height = coverage.history_proof_covered_to?;
    if height == 0 || height > ctx.tip_height() {
        return None;
    }
    if !snapshot_suffix_is_retained(ctx.tip_height(), height) {
        tracing::debug!(
            proof_height = height,
            tip_height = ctx.tip_height(),
            retention = noid_chain::consensus::params::RECENT_BLOCK_RETENTION_DEPTH,
            "checkpoint proof is too old to serve with retained suffix"
        );
        return None;
    }
    let record_bytes = ctx
        .store
        .get_history_checkpoint_head_record(height)
        .ok()
        .flatten()?;
    let record: noid_recursive::StoredHistoryCheckpointHeadRecord =
        match bincode::deserialize(&record_bytes) {
            Ok(record) => record,
            Err(e) => {
                tracing::warn!(
                    height,
                    err = ?e,
                    "checkpoint head record decode failed while serving proof"
                );
                return None;
            }
        };
    if record.height != height {
        tracing::warn!(
            height,
            record_height = record.height,
            "checkpoint head record height mismatch while serving proof"
        );
        return None;
    }
    if let Err(e) = noid_recursive::verify_history_checkpoint_head_record(&record) {
        tracing::warn!(height, err = ?e, "checkpoint head record self-check failed");
        return None;
    }
    let local_end_anchor = ctx.store.get_header_anchor(height).ok().flatten()?;
    let proof = match noid_recursive::public_history_checkpoint_proof_from_head_record(&record) {
        Ok(proof) => proof,
        Err(e) => {
            tracing::warn!(
                height,
                err = ?e,
                "checkpoint public proof decode failed while serving proof"
            );
            return None;
        }
    };
    if let Err(e) = noid_recursive::verify_history_checkpoint_proof_checkpoint(
        &proof,
        &proof.start_anchor,
        &local_end_anchor,
    ) {
        tracing::warn!(
            height,
            err = ?e,
            "checkpoint public proof self-check failed while serving proof"
        );
        return None;
    }
    let bytes = record.proof_bytes;
    if bytes.len() > MAX_HISTORY_PROOF_BYTES {
        tracing::warn!(
            height,
            len = bytes.len(),
            cap = MAX_HISTORY_PROOF_BYTES,
            "checkpoint public proof exceeds wire cap"
        );
        return None;
    }
    Some((height, bytes))
}

fn local_public_history_proof(ctx: &MdbxChainContext) -> Option<(u64, Vec<u8>)> {
    local_checkpoint_history_proof(ctx)
}

fn sanitize_stored_block_response(
    height: u64,
    mut block_bytes: Option<Vec<u8>>,
    mut block_proof_bytes: Option<Vec<u8>>,
    mut block_auth_sidecar_bytes: Option<Vec<u8>>,
) -> (Option<Vec<u8>>, Option<Vec<u8>>, Option<Vec<u8>>) {
    if block_bytes
        .as_ref()
        .is_some_and(|bytes| bytes.len() > MAX_BLOCK_BYTES)
    {
        tracing::warn!(height, "stored block exceeds wire cap — not serving");
        return (None, None, None);
    }
    if block_bytes.is_none() {
        return (None, None, None);
    }
    if block_proof_bytes
        .as_ref()
        .is_some_and(|bytes| bytes.len() > MAX_BLOCK_PROOF_BYTES)
    {
        tracing::warn!(
            height,
            "stored block proof exceeds wire cap — not serving proof"
        );
        block_proof_bytes = None;
    }
    if block_auth_sidecar_bytes
        .as_ref()
        .is_some_and(|bytes| bytes.len() > MAX_BLOCK_AUTH_SIDECAR_BYTES)
    {
        tracing::warn!(
            height,
            "stored auth sidecar exceeds wire cap — not serving sidecar"
        );
        block_auth_sidecar_bytes = None;
    }
    let proof_len = block_proof_bytes.as_ref().map_or(0, Vec::len);
    let sidecar_len = block_auth_sidecar_bytes.as_ref().map_or(0, Vec::len);
    if !proof_sidecar_combined_len_ok(proof_len, sidecar_len) {
        tracing::warn!(
            height,
            proof_len,
            sidecar_len,
            "stored proof+sidecar exceed combined wire cap — not serving proof data"
        );
        block_proof_bytes = None;
        block_auth_sidecar_bytes = None;
    }
    if block_proof_bytes.is_some() != block_auth_sidecar_bytes.is_some() {
        tracing::warn!(
            height,
            "stored proof/authorization sidecar presence mismatch — not serving proof data"
        );
        block_proof_bytes = None;
        block_auth_sidecar_bytes = None;
    }
    (
        block_bytes.take(),
        block_proof_bytes,
        block_auth_sidecar_bytes,
    )
}

#[inline]
fn should_inline_block_gossip(
    block_bytes_len: usize,
    block_proof_bytes_len: usize,
    block_auth_sidecar_bytes_len: usize,
) -> bool {
    block_bytes_len > 0
        && block_bytes_len
            .saturating_add(block_proof_bytes_len)
            .saturating_add(block_auth_sidecar_bytes_len)
            <= INLINE_BLOCK_GOSSIP_THRESHOLD
}

/// Commands sent to the P2P network event loop.
#[derive(Debug)]
pub enum NetworkCommand {
    /// Announce a new block to all peers.
    ///
    /// If `block_bytes` + `block_proof_bytes` + `block_auth_sidecar_bytes` fit
    /// within the inline threshold (1 MB), the full block is gossiped directly.
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
        /// Public AuthGKR sidecar bytes (for inline mode). Empty = compact-only.
        block_auth_sidecar_bytes: Vec<u8>,
    },
    /// Broadcast a new TxIntent to all peers.
    BroadcastTx { intent_bytes: Arc<[u8]> },
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
    /// Request the state manifest from a peer (step 1 of snapshot sync, or a
    /// lightweight snapshot-boundary probe for persisted-state catch-up).
    /// Returns metadata + active segment IDs. Emits `NetworkEvent::StateManifest`.
    RequestStateManifest { peer: PeerId, requester_height: u64 },
    /// Request a single state segment from a peer (step 2, one per segment).
    /// Emits `NetworkEvent::StateSegment`.
    RequestStateSegment {
        peer: PeerId,
        segment_id: u16,
        expected_tip_height: u64,
        expected_tip_hash: [u8; 32],
    },
    /// Request the public checkpoint/history proof from a peer.
    /// Peers return no proof until promoted checkpoint package coverage is ready.
    /// Emits `NetworkEvent::HistoryProof` when the response arrives.
    RequestHistoryProof { peer: PeerId },
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
    /// A full block + proof + public AuthGKR sidecar arrived.
    NewBlock {
        from: PeerId,
        block_bytes: Vec<u8>,
        /// `BlockProof` bincode bytes. Empty Vec for coinbase-only blocks.
        block_proof_bytes: Vec<u8>,
        /// `BlockAuthSidecar` bincode bytes. Empty Vec for coinbase-only blocks.
        block_auth_sidecar_bytes: Vec<u8>,
        /// Holds the process-global inbound byte budget until node-side
        /// validation and persistence have consumed the pulled response.
        inbound_memory_permit: Option<Arc<tokio::sync::OwnedSemaphorePermit>>,
    },
    /// A requested retained full block is no longer available from this peer.
    RecentBlockUnavailable { from: PeerId, height: u64 },
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
    /// Public checkpoint/history proof envelope response received from a peer.
    ///
    /// Empty `proof_bytes` means the peer has no servable checkpoint proof ready.
    HistoryProof {
        from: PeerId,
        /// Serialized public checkpoint/history proof envelope bytes, or empty.
        proof_bytes: Vec<u8>,
        /// Serialized tip `BlockHeader` bytes (276 bytes), or empty.
        tip_header_bytes: Vec<u8>,
        /// Holds the process-global inbound history byte budget until the node
        /// finishes verifying this response.
        inbound_memory_permit: Option<Arc<tokio::sync::OwnedSemaphorePermit>>,
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

/// Receive side for node-facing P2P events.
///
/// Required request/response results use a bounded, backpressured MPSC queue;
/// recoverable gossip and peer-lifecycle notifications use broadcast and may
/// report lag.  This prevents a slow proof verifier from either retaining 256
/// maximum-sized blocks or silently losing a requested suffix response.
pub struct NetworkEventReceiver {
    required_rx: mpsc::Receiver<NetworkEvent>,
    gossip_rx: tokio::sync::broadcast::Receiver<NetworkEvent>,
    required_closed: bool,
    gossip_closed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkEventRecvError {
    /// Recoverable gossip notifications were overwritten while the consumer
    /// was busy. Required sync responses never use this queue.
    Lagged(u64),
    /// Both event producers have closed.
    Closed,
}

impl NetworkEventReceiver {
    pub async fn recv(&mut self) -> Result<NetworkEvent, NetworkEventRecvError> {
        loop {
            match (self.required_closed, self.gossip_closed) {
                (true, true) => return Err(NetworkEventRecvError::Closed),
                (true, false) => match self.gossip_rx.recv().await {
                    Ok(event) => return Ok(event),
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                        return Err(NetworkEventRecvError::Lagged(skipped));
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        self.gossip_closed = true;
                    }
                },
                (false, true) => match self.required_rx.recv().await {
                    Some(event) => return Ok(event),
                    None => self.required_closed = true,
                },
                (false, false) => {
                    tokio::select! {
                        // Sync progress is authoritative and should not sit behind
                        // a flood of replaceable announcements.
                        biased;
                        event = self.required_rx.recv() => match event {
                            Some(event) => return Ok(event),
                            None => self.required_closed = true,
                        },
                        event = self.gossip_rx.recv() => match event {
                            Ok(event) => return Ok(event),
                            Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                                return Err(NetworkEventRecvError::Lagged(skipped));
                            }
                            Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                                self.gossip_closed = true;
                            }
                        }
                    }
                }
            }
        }
    }
}

// The node requests at most eight authenticated state segments concurrently;
// block pull is one stream and other bounded sync responses occupy the
// remaining slots. Backpressure begins before a second wave can accumulate.
const REQUIRED_EVENT_QUEUE_CAPACITY: usize = 16;
const GOSSIP_EVENT_QUEUE_CAPACITY: usize = 64;

/// The P2P network manager.
pub struct P2PNetwork {
    /// Channel to send commands to the event loop.
    pub cmd_tx: mpsc::Sender<NetworkCommand>,
    /// Subscribe to events from the event loop.
    gossip_event_tx: tokio::sync::broadcast::Sender<NetworkEvent>,
    required_event_rx: std::sync::Mutex<Option<mpsc::Receiver<NetworkEvent>>>,
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
        let (gossip_event_tx, _) = tokio::sync::broadcast::channel(GOSSIP_EVENT_QUEUE_CAPACITY);
        let (required_event_tx, required_event_rx) = mpsc::channel(REQUIRED_EVENT_QUEUE_CAPACITY);

        let gossip_event_tx_clone = gossip_event_tx.clone();
        let handle = tokio::spawn(async move {
            if let Err(e) = run_swarm(
                listen_addr,
                cmd_rx,
                gossip_event_tx_clone,
                required_event_tx,
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

        (
            Self {
                cmd_tx,
                gossip_event_tx,
                required_event_rx: std::sync::Mutex::new(Some(required_event_rx)),
            },
            handle,
        )
    }

    /// Attach the node's single authoritative event consumer.
    ///
    /// Sync responses cannot be broadcast safely because lagging receivers
    /// silently lose entries. There is deliberately exactly one such consumer.
    pub fn subscribe(&self) -> NetworkEventReceiver {
        let required_rx = self
            .required_event_rx
            .lock()
            .expect("P2P required event receiver mutex poisoned")
            .take()
            .expect("P2P event receiver may only be subscribed once");
        NetworkEventReceiver {
            required_rx,
            gossip_rx: self.gossip_event_tx.subscribe(),
            required_closed: false,
            gossip_closed: false,
        }
    }

    /// Announce a new block to all peers.  Small blocks are inlined in gossip.
    pub async fn announce_block(
        &self,
        height: u64,
        hash: [u8; 32],
        header_bytes: Vec<u8>,
        block_bytes: Vec<u8>,
        block_proof_bytes: Vec<u8>,
        block_auth_sidecar_bytes: Vec<u8>,
    ) {
        let _ = self
            .cmd_tx
            .send(NetworkCommand::AnnounceBlock {
                height,
                hash,
                header_bytes,
                block_bytes,
                block_proof_bytes,
                block_auth_sidecar_bytes,
            })
            .await;
    }

    pub async fn broadcast_tx(&self, intent_bytes: Vec<u8>) {
        let _ = self
            .cmd_tx
            .send(NetworkCommand::BroadcastTx {
                intent_bytes: intent_bytes.into(),
            })
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
            .send(NetworkCommand::RequestStateManifest {
                peer,
                requester_height: 0,
            })
            .await;
    }

    /// Request a single state segment from a peer (step 2).
    pub async fn request_state_segment(
        &self,
        peer: PeerId,
        segment_id: u16,
        expected_tip_height: u64,
        expected_tip_hash: [u8; 32],
    ) {
        let _ = self
            .cmd_tx
            .send(NetworkCommand::RequestStateSegment {
                peer,
                segment_id,
                expected_tip_height,
                expected_tip_hash,
            })
            .await;
    }

    /// Request the public history proof from a peer.
    /// The response arrives as `NetworkEvent::HistoryProof`.
    pub async fn request_history_proof(&self, peer: PeerId) {
        let _ = self
            .cmd_tx
            .send(NetworkCommand::RequestHistoryProof { peer })
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
    gossip_event_tx: tokio::sync::broadcast::Sender<NetworkEvent>,
    required_event_tx: mpsc::Sender<NetworkEvent>,
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
    swarm.behaviour_mut().gossipsub.subscribe(&blocks_topic)?;
    swarm.behaviour_mut().gossipsub.subscribe(&txs_topic)?;

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

    // Cheap P2P-layer DoS guards that run before emitting NetworkEvent into
    // the bounded broadcast channel.
    let mut block_event_rate: std::collections::HashMap<PeerId, (u32, Instant)> =
        std::collections::HashMap::new();
    let mut tx_gossip_rate: std::collections::HashMap<PeerId, (u32, Instant)> =
        std::collections::HashMap::new();
    let mut mempool_sync_last_request: std::collections::HashMap<PeerId, Instant> =
        std::collections::HashMap::new();
    let mut snapshot_manifest_last_request: std::collections::HashMap<PeerId, Instant> =
        std::collections::HashMap::new();
    let mut snapshot_segment_rate: std::collections::HashMap<PeerId, (u32, Instant)> =
        std::collections::HashMap::new();

    // One waiting response of each kind is sufficient: the request-response
    // behaviour owns the next response while its codec writes it. Byte permits
    // retained by both stages are the process-wide RAM bound.
    let (block_response_tx, mut block_response_rx) = mpsc::channel::<PendingBlockResponse>(1);
    let (history_response_tx, mut history_response_rx) =
        mpsc::channel::<PendingHistoryProofResponse>(1);
    let (segment_response_tx, mut segment_response_rx) =
        mpsc::channel::<PendingStateSegmentResponse>(1);
    let block_response_prepare_semaphore = Arc::new(Semaphore::new(2));
    let history_response_prepare_semaphore = Arc::new(Semaphore::new(4));
    let segment_encode_semaphore = Arc::new(Semaphore::new(2));
    let outbound_response_budget = OutboundResponseBudget::process_global();
    let snapshot_export_root = data_dir.join("snapshot-exports");
    std::fs::create_dir_all(&snapshot_export_root)?;
    let mut snapshot_exports = load_snapshot_exports(&snapshot_export_root);
    prune_snapshot_exports(&mut snapshot_exports);
    let (snapshot_export_tx, mut snapshot_export_rx) =
        mpsc::channel::<(SnapshotExportKey, Result<SnapshotGeneration, String>)>(1);
    let mut snapshot_export_inflight: Option<SnapshotExportKey> = None;
    let mut snapshot_export_timer = tokio::time::interval(Duration::from_secs(30));
    snapshot_export_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

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
            handle_network_command(&mut swarm, cmd, &topics, &mut mempool_sync_last_request);
        }

        tokio::select! {
            // Swarm events.
            event = swarm.select_next_some() => {
                handle_swarm_event(
                    &mut swarm,
                    event,
                    &gossip_event_tx,
                    &required_event_tx,
                    &chain,
                    &mempool,
                    &topics,
                    &block_response_tx,
                    &block_response_prepare_semaphore,
                    &history_response_tx,
                    &history_response_prepare_semaphore,
                    &segment_response_tx,
                    &segment_encode_semaphore,
                    &outbound_response_budget,
                    &mut snapshot_exports,
                    &mut reconnect,
                    &mut block_event_rate,
                    &mut tx_gossip_rate,
                    &mut mempool_sync_last_request,
                    &mut snapshot_manifest_last_request,
                    &mut snapshot_segment_rate,
                )
                .await;
            }

            prepared = block_response_rx.recv() => {
                if let Some(prepared) = prepared {
                    let _ = swarm
                        .behaviour_mut()
                        .block_sync
                        .send_response(prepared.channel, prepared.response);
                }
            }

            prepared = history_response_rx.recv() => {
                if let Some(prepared) = prepared {
                    let _ = swarm
                        .behaviour_mut()
                        .proof_sync
                        .send_response(prepared.channel, prepared.response);
                }
            }

            // Completed bounded disk reads. Responses must be sent from the
            // swarm task, while segment authentication/I/O runs on workers.
            encoded = segment_response_rx.recv() => {
                if let Some(encoded) = encoded {
                    let _ = swarm
                        .behaviour_mut()
                        .state_segment_sync
                        .send_response(encoded.channel, encoded.response);
                }
            }

            completed = snapshot_export_rx.recv() => {
                if let Some((key, result)) = completed {
                    snapshot_export_inflight = None;
                    match result {
                        Ok(generation) if generation.key() == key => {
                            tracing::info!(height = key.0, "published bounded disk snapshot generation");
                            snapshot_exports.insert(key, Arc::new(generation));
                            prune_snapshot_exports(&mut snapshot_exports);
                        }
                        Ok(_) => tracing::warn!(height = key.0, "snapshot generation boundary mismatch"),
                        Err(error) => tracing::warn!(height = key.0, err = %error, "snapshot generation build failed"),
                    }
                }
            }

            _ = snapshot_export_timer.tick() => {
                if snapshot_export_inflight.is_none() {
                    let candidate = {
                        let ctx = chain.read().await;
                        local_public_history_proof(&ctx).and_then(|(height, _)| {
                            let header = ctx.store.get_header(height).ok().flatten()?;
                            let key = (height, noid_chain::hash_block_header(&header));
                            if snapshot_exports.contains_key(&key) {
                                None
                            } else {
                                Some((key, ctx.store.clone()))
                            }
                        })
                    };
                    if let Some((key, store)) = candidate {
                        snapshot_export_inflight = Some(key);
                        let export_root = snapshot_export_root.clone();
                        let completion = snapshot_export_tx.clone();
                        tokio::task::spawn_blocking(move || {
                            let result = export_snapshot_generation(&store, &export_root, key.0)
                                .map_err(|error| error.to_string());
                            let _ = completion.blocking_send((key, result));
                        });
                    }
                }
            }

            // Commands from the node (when no swarm event pending).
            cmd = cmd_rx.recv() => {
                match cmd {
                    Some(cmd) => handle_network_command(
                        &mut swarm,
                        cmd,
                        &topics,
                        &mut mempool_sync_last_request,
                    ),
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

fn load_snapshot_exports(
    root: &std::path::Path,
) -> std::collections::HashMap<SnapshotExportKey, SnapshotExport> {
    let mut exports = std::collections::HashMap::new();
    let Ok(entries) = std::fs::read_dir(root) else {
        return exports;
    };
    for entry in entries.flatten() {
        if !entry.file_type().is_ok_and(|kind| kind.is_dir()) {
            continue;
        }
        match open_snapshot_generation(entry.path()) {
            Ok(generation) => {
                exports.insert(generation.key(), Arc::new(generation));
            }
            Err(error) => {
                tracing::warn!(path = %entry.path().display(), err = %error, "ignoring invalid snapshot generation");
            }
        }
    }
    exports
}

fn prune_snapshot_exports(
    exports: &mut std::collections::HashMap<SnapshotExportKey, SnapshotExport>,
) {
    let mut keys: Vec<_> = exports.keys().copied().collect();
    keys.sort_unstable_by_key(|(height, _)| std::cmp::Reverse(*height));
    for key in keys.into_iter().skip(MAX_SNAPSHOT_EXPORTS) {
        let removable = exports
            .get(&key)
            .is_some_and(|generation| Arc::strong_count(generation) == 1);
        if removable {
            if let Some(generation) = exports.remove(&key) {
                if let Err(error) = std::fs::remove_dir_all(generation.directory()) {
                    tracing::warn!(path = %generation.directory().display(), err = %error, "snapshot generation GC failed");
                }
            }
        }
    }
}

fn allow_peer_rate(
    rates: &mut std::collections::HashMap<PeerId, (u32, Instant)>,
    peer: PeerId,
    max: u32,
    window: Duration,
) -> bool {
    let now = Instant::now();
    let entry = rates.entry(peer).or_insert((0, now));
    if now.duration_since(entry.1) > window {
        *entry = (1, now);
        true
    } else if entry.0 >= max {
        false
    } else {
        entry.0 += 1;
        true
    }
}

fn is_routable_identify_addr(addr: &Multiaddr) -> bool {
    for protocol in addr.iter() {
        match protocol {
            libp2p::multiaddr::Protocol::Ip4(ip) => {
                if ip.is_loopback()
                    || ip.is_private()
                    || ip.is_link_local()
                    || ip.is_multicast()
                    || ip.is_broadcast()
                    || ip.is_unspecified()
                {
                    return false;
                }
            }
            libp2p::multiaddr::Protocol::Ip6(ip) => {
                let octets = ip.octets();
                let unique_local = (octets[0] & 0xfe) == 0xfc;
                let link_local = octets[0] == 0xfe && (octets[1] & 0xc0) == 0x80;
                if ip.is_loopback()
                    || ip.is_unspecified()
                    || ip.is_multicast()
                    || unique_local
                    || link_local
                {
                    return false;
                }
            }
            _ => {}
        }
    }
    true
}

/// Process a single network command. Separated from the select! loop so that
/// pending commands can be drained synchronously via `try_recv` before blocking.
fn handle_network_command(
    swarm: &mut libp2p::Swarm<NodeBehaviour>,
    cmd: NetworkCommand,
    topics: &NetworkTopics,
    mempool_sync_last_request: &mut std::collections::HashMap<PeerId, Instant>,
) {
    match cmd {
        NetworkCommand::AnnounceBlock {
            height,
            hash,
            header_bytes,
            block_bytes,
            block_proof_bytes,
            block_auth_sidecar_bytes,
        } => {
            // Inline threshold: if block + proof + sidecar fit in 1 MB, gossip
            // the full block directly. Larger blocks use compact announcement.
            let msg = if should_inline_block_gossip(
                block_bytes.len(),
                block_proof_bytes.len(),
                block_auth_sidecar_bytes.len(),
            ) {
                BlockGossipMsg::Inline {
                    height,
                    hash,
                    block_bytes,
                    block_proof_bytes,
                    block_auth_sidecar_bytes,
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
        NetworkCommand::BroadcastTx { intent_bytes } => {
            let topic = gossipsub::IdentTopic::new(topics.txs.clone());
            if let Err(e) = swarm
                .behaviour_mut()
                .gossipsub
                .publish(topic, intent_bytes.as_ref().to_vec())
            {
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
            // Proof-native responses may consume the full 64 MiB inbound byte
            // budget. Request exactly one suffix block; after it is validated
            // and committed the node asks for height+1. This also prevents the
            // old overlapping four-wide windows from growing libp2p's pending
            // request queue after every applied response.
            const SYNC_WINDOW: u64 = 1;
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
        NetworkCommand::RequestStateManifest {
            peer,
            requester_height,
        } => {
            let _ = swarm.behaviour_mut().state_manifest_sync.send_request(
                &peer,
                crate::protocol::GetStateManifestRequest { requester_height },
            );
            tracing::debug!(peer = %peer, requester_height, "requesting state manifest");
        }
        NetworkCommand::RequestStateSegment {
            peer,
            segment_id,
            expected_tip_height,
            expected_tip_hash,
        } => {
            let _ = swarm.behaviour_mut().state_segment_sync.send_request(
                &peer,
                crate::protocol::GetStateSegmentRequest {
                    segment_id,
                    expected_tip_height,
                    expected_tip_hash,
                },
            );
            tracing::debug!(peer = %peer, segment_id, "requesting state segment");
        }
        NetworkCommand::RequestHistoryProof { peer } => {
            let _ = swarm
                .behaviour_mut()
                .proof_sync
                .send_request(&peer, crate::protocol::GetHistoryProofRequest);
            tracing::debug!(peer = %peer, "requesting history proof for snapshot verification");
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
            const MEMPOOL_SYNC_REQUEST_COOLDOWN: Duration = Duration::from_secs(30);
            let now = Instant::now();
            if let Some(last) = mempool_sync_last_request.get(&peer) {
                if now.duration_since(*last) < MEMPOOL_SYNC_REQUEST_COOLDOWN {
                    tracing::debug!(peer = %peer, "mempool sync request suppressed by cooldown");
                    return;
                }
            }
            mempool_sync_last_request.insert(peer, now);
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
    gossip_event_tx: &tokio::sync::broadcast::Sender<NetworkEvent>,
    required_event_tx: &mpsc::Sender<NetworkEvent>,
    chain: &Arc<RwLock<MdbxChainContext>>,
    mempool: &AsyncMempool,
    topics: &NetworkTopics,
    block_response_tx: &mpsc::Sender<PendingBlockResponse>,
    block_response_prepare_semaphore: &Arc<Semaphore>,
    history_response_tx: &mpsc::Sender<PendingHistoryProofResponse>,
    history_response_prepare_semaphore: &Arc<Semaphore>,
    segment_response_tx: &mpsc::Sender<PendingStateSegmentResponse>,
    segment_encode_semaphore: &Arc<Semaphore>,
    outbound_response_budget: &OutboundResponseBudget,
    snapshot_exports: &mut std::collections::HashMap<SnapshotExportKey, SnapshotExport>,
    reconnect: &mut std::collections::HashMap<
        libp2p::PeerId,
        (Multiaddr, tokio::time::Instant, u32),
    >,
    block_event_rate: &mut std::collections::HashMap<PeerId, (u32, Instant)>,
    tx_gossip_rate: &mut std::collections::HashMap<PeerId, (u32, Instant)>,
    mempool_sync_last_request: &mut std::collections::HashMap<PeerId, Instant>,
    snapshot_manifest_last_request: &mut std::collections::HashMap<PeerId, Instant>,
    snapshot_segment_rate: &mut std::collections::HashMap<PeerId, (u32, Instant)>,
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
                        const BLOCK_RATE_WINDOW: Duration = Duration::from_secs(10);
                        const BLOCK_RATE_MAX: u32 = 40;
                        if !allow_peer_rate(
                            block_event_rate,
                            origin,
                            BLOCK_RATE_MAX,
                            BLOCK_RATE_WINDOW,
                        ) {
                            tracing::debug!(peer = %origin, "block announcement rate limit exceeded — dropped before event channel");
                            return;
                        }
                        let _ = gossip_event_tx.send(NetworkEvent::NewBlockAnnouncement {
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
                        block_auth_sidecar_bytes,
                    }) => {
                        if block_bytes.len() > MAX_BLOCK_BYTES {
                            tracing::warn!(peer = %propagation_source, len = block_bytes.len(), "inline block too large — dropped");
                        } else if block_proof_bytes.len() > MAX_BLOCK_PROOF_BYTES {
                            tracing::warn!(peer = %propagation_source, len = block_proof_bytes.len(), "inline proof too large — dropped");
                        } else if block_auth_sidecar_bytes.len() > MAX_BLOCK_AUTH_SIDECAR_BYTES {
                            tracing::warn!(peer = %propagation_source, len = block_auth_sidecar_bytes.len(), "inline auth sidecar too large — dropped");
                        } else if !proof_sidecar_combined_len_ok(
                            block_proof_bytes.len(),
                            block_auth_sidecar_bytes.len(),
                        ) {
                            tracing::warn!(peer = %propagation_source, proof_len = block_proof_bytes.len(), sidecar_len = block_auth_sidecar_bytes.len(), "inline proof+sidecar combined cap exceeded — dropped");
                        } else {
                            const BLOCK_RATE_WINDOW: Duration = Duration::from_secs(10);
                            const BLOCK_RATE_MAX: u32 = 40;
                            if !allow_peer_rate(
                                block_event_rate,
                                origin,
                                BLOCK_RATE_MAX,
                                BLOCK_RATE_WINDOW,
                            ) {
                                tracing::debug!(peer = %origin, "inline block rate limit exceeded — dropped before event channel");
                                return;
                            }
                            tracing::debug!(height, peer = %propagation_source, "received inline block via gossip");
                            let _ = gossip_event_tx.send(NetworkEvent::NewBlock {
                                from: origin,
                                block_bytes,
                                block_proof_bytes,
                                block_auth_sidecar_bytes,
                                inbound_memory_permit: None,
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
                if message.data.len() > MAX_TX_INTENT_BYTES_GLOBAL {
                    tracing::warn!(peer = %propagation_source, len = message.data.len(), "tx gossip too large — dropped");
                } else {
                    const TX_RATE_WINDOW: Duration = Duration::from_secs(10);
                    const TX_RATE_MAX: u32 = 50;
                    if !allow_peer_rate(
                        tx_gossip_rate,
                        propagation_source,
                        TX_RATE_MAX,
                        TX_RATE_WINDOW,
                    ) {
                        tracing::debug!(peer = %propagation_source, "tx gossip rate limit exceeded — dropped before event channel");
                        return;
                    }
                    let _ = gossip_event_tx.send(NetworkEvent::NewTx {
                        from: propagation_source,
                        intent_bytes: message.data,
                    });
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
            // 1. Add a bounded, routable subset of advertised listen addresses
            //    to Kademlia and the swarm address book. Blindly accepting all
            //    Identify addresses lets a peer bloat our peer store/routing state
            //    or advertise localhost/private addresses that are useless off-LAN.
            const MAX_IDENTIFY_ADDRS_PER_PEER: usize = 8;
            let mut accepted_addrs = 0usize;
            let mut dropped_addrs = 0usize;
            for addr in &info.listen_addrs {
                if accepted_addrs >= MAX_IDENTIFY_ADDRS_PER_PEER {
                    dropped_addrs += 1;
                    continue;
                }
                if !is_routable_identify_addr(addr) {
                    dropped_addrs += 1;
                    continue;
                }
                swarm
                    .behaviour_mut()
                    .kad
                    .add_address(&peer_id, addr.clone());
                // Also populate the swarm's address book so GossipSub PX
                // can build signed PeerInfo records for this peer.
                swarm.add_peer_address(peer_id, addr.clone());
                accepted_addrs += 1;
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
                advertised_addrs = info.listen_addrs.len(),
                accepted_addrs,
                dropped_addrs,
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
            let _ = required_event_tx
                .send(NetworkEvent::HeadersBatch {
                    from: peer,
                    headers: decoded,
                })
                .await;
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
            let count = request.count.min(512);
            let end = request.start_height.saturating_add(count as u64);
            for h in request.start_height..end {
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
            let inbound_memory_permit = response.inbound_memory_permit.clone();
            if let Some(block_bytes) = response.block_bytes {
                if block_bytes.len() > MAX_BLOCK_BYTES {
                    tracing::warn!(peer = %peer, len = block_bytes.len(), "block pull response too large — dropped");
                } else {
                    let proof_bytes = response.block_proof_bytes.unwrap_or_default();
                    let auth_sidecar_bytes = response.block_auth_sidecar_bytes.unwrap_or_default();
                    if proof_bytes.len() > MAX_BLOCK_PROOF_BYTES {
                        tracing::warn!(peer = %peer, len = proof_bytes.len(), "block proof too large — dropped");
                    } else if auth_sidecar_bytes.len() > MAX_BLOCK_AUTH_SIDECAR_BYTES {
                        tracing::warn!(peer = %peer, len = auth_sidecar_bytes.len(), "block auth sidecar too large — dropped");
                    } else if !proof_sidecar_combined_len_ok(
                        proof_bytes.len(),
                        auth_sidecar_bytes.len(),
                    ) {
                        tracing::warn!(peer = %peer, proof_len = proof_bytes.len(), sidecar_len = auth_sidecar_bytes.len(), "block proof+sidecar combined cap exceeded — dropped");
                    } else {
                        const BLOCK_RATE_WINDOW: Duration = Duration::from_secs(10);
                        const BLOCK_RATE_MAX: u32 = 40;
                        if !allow_peer_rate(
                            block_event_rate,
                            peer,
                            BLOCK_RATE_MAX,
                            BLOCK_RATE_WINDOW,
                        ) {
                            tracing::debug!(peer = %peer, "pulled block response rate limit exceeded — dropped before event channel");
                            return;
                        }
                        tracing::debug!(peer = %peer, "received block via pull");
                        let _ = required_event_tx
                            .send(NetworkEvent::NewBlock {
                                from: peer,
                                block_bytes,
                                block_proof_bytes: proof_bytes,
                                block_auth_sidecar_bytes: auth_sidecar_bytes,
                                inbound_memory_permit,
                            })
                            .await;
                    }
                }
            } else {
                tracing::debug!(
                    peer = %peer,
                    height = response.height,
                    "requested recent block unavailable"
                );
                let _ = required_event_tx
                    .send(NetworkEvent::RecentBlockUnavailable {
                        from: peer,
                        height: response.height,
                    })
                    .await;
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
            // Reserve the consensus upper bound before the first MDBX value is
            // copied into a Vec. The task waits off the swarm loop so the
            // current response can continue being polled/written and release
            // its permit. The permit then follows the response into the codec.
            let Ok(preparation_permit) =
                block_response_prepare_semaphore.clone().try_acquire_owned()
            else {
                tracing::debug!(
                    height = request.height,
                    "block response preparation saturated"
                );
                // Dropping the response channel reports a transient outbound
                // failure; it must not masquerade as a durable pruned block.
                return;
            };
            let chain = chain.clone();
            let budget = outbound_response_budget.clone();
            let completion = block_response_tx.clone();
            let height = request.height;
            tokio::spawn(async move {
                let _preparation_permit = preparation_permit;
                let Ok(Some(outbound_memory_permit)) =
                    budget.acquire(MAX_OUTBOUND_BLOCK_RESPONSE_BYTES).await
                else {
                    return;
                };
                let loaded = tokio::task::spawn_blocking(move || {
                    let ctx = chain.blocking_read();
                    match ctx.store.get_recent_block_bundle_bounded(height) {
                        Ok(Some((block, proof, sidecar))) => sanitize_stored_block_response(
                            height,
                            Some(block),
                            proof,
                            sidecar,
                        ),
                        Ok(None) => (None, None, None),
                        Err(error) => {
                            tracing::warn!(height, err = %error, "bounded block response read failed");
                            (None, None, None)
                        }
                    }
                })
                .await;
                let (block_bytes, block_proof_bytes, block_auth_sidecar_bytes) = match loaded {
                    Ok(loaded) => loaded,
                    Err(error) => {
                        tracing::warn!(height, err = %error, "block response storage worker failed");
                        (None, None, None)
                    }
                };
                let response = GetRecentBlockResponse {
                    height,
                    block_bytes,
                    block_proof_bytes,
                    block_auth_sidecar_bytes,
                    inbound_memory_permit: None,
                    outbound_memory_permit: Some(outbound_memory_permit),
                };
                let _ = completion
                    .send(PendingBlockResponse { channel, response })
                    .await;
            });
        }

        // --- Request-Response: public history proof ---
        SwarmEvent::Behaviour(NodeBehaviourEvent::ProofSync(
            request_response::Event::Message {
                message: request_response::Message::Request { channel, .. },
                ..
            },
        )) => {
            let Ok(preparation_permit) = history_response_prepare_semaphore
                .clone()
                .try_acquire_owned()
            else {
                tracing::debug!("history response preparation saturated");
                return;
            };
            let chain = chain.clone();
            let budget = outbound_response_budget.clone();
            let completion = history_response_tx.clone();
            tokio::spawn(async move {
                let _preparation_permit = preparation_permit;
                let Ok(Some(outbound_memory_permit)) =
                    budget.acquire(MAX_OUTBOUND_HISTORY_RESPONSE_BYTES).await
                else {
                    return;
                };
                let loaded = tokio::task::spawn_blocking(move || {
                    let ctx = chain.blocking_read();
                    let proof_bytes = local_public_history_proof(&ctx).map(|(_, bytes)| bytes);
                    let mut tip_header_bytes = Vec::new();
                    ctx.tip_header().encode(&mut tip_header_bytes);
                    (proof_bytes, Some(tip_header_bytes))
                })
                .await;
                let (proof_bytes, tip_header_bytes) = match loaded {
                    Ok(loaded) => loaded,
                    Err(error) => {
                        tracing::warn!(err = %error, "history response storage worker failed");
                        (None, None)
                    }
                };
                let response = GetHistoryProofResponse {
                    proof_bytes,
                    tip_header_bytes,
                    inbound_memory_permit: None,
                    outbound_memory_permit: Some(outbound_memory_permit),
                };
                let _ = completion
                    .send(PendingHistoryProofResponse { channel, response })
                    .await;
            });
        }

        // --- Request-Response: public history proof client side ---
        SwarmEvent::Behaviour(NodeBehaviourEvent::ProofSync(
            request_response::Event::Message {
                message: request_response::Message::Response { response, .. },
                peer,
            },
        )) => {
            let inbound_memory_permit = response.inbound_memory_permit.clone();
            let proof_bytes = response.proof_bytes.unwrap_or_default();
            let tip_header_bytes = response.tip_header_bytes.unwrap_or_default();
            if proof_bytes.len() > MAX_HISTORY_PROOF_BYTES {
                tracing::warn!(peer = %peer, len = proof_bytes.len(), "history proof response too large — dropped");
                return;
            }
            if tip_header_bytes.len() > MAX_HEADER_BYTES {
                tracing::warn!(peer = %peer, len = tip_header_bytes.len(), "tip header in proof response too large — dropped");
                return;
            }
            tracing::debug!(
                from = %peer,
                proof_len = proof_bytes.len(),
                "received history proof from peer"
            );
            let _ = required_event_tx
                .send(NetworkEvent::HistoryProof {
                    from: peer,
                    proof_bytes,
                    tip_header_bytes,
                    inbound_memory_permit,
                })
                .await;
        }

        // --- State sync: manifest server (step 1) ---
        //
        // Serve only a fully validated immutable disk generation keyed by the
        // advertised boundary. Live mining cannot mutate its segment files.
        SwarmEvent::Behaviour(NodeBehaviourEvent::StateManifestSync(
            request_response::Event::Message {
                message:
                    request_response::Message::Request {
                        request, channel, ..
                    },
                peer,
                ..
            },
        )) => {
            const MANIFEST_REQUEST_COOLDOWN: Duration = Duration::from_secs(10);
            let now = Instant::now();
            if snapshot_manifest_last_request
                .get(&peer)
                .is_some_and(|last| now.duration_since(*last) < MANIFEST_REQUEST_COOLDOWN)
            {
                tracing::debug!(peer = %peer, "snapshot manifest request suppressed by cooldown");
                let _ = swarm
                    .behaviour_mut()
                    .state_manifest_sync
                    .send_response(channel, GetStateManifestResponse::default());
                return;
            }
            snapshot_manifest_last_request.insert(peer, now);
            prune_snapshot_exports(snapshot_exports);
            let response = 'ready_manifest: {
                let ctx = chain.read().await;
                let Some((snapshot_height, _)) = local_public_history_proof(&ctx) else {
                    break 'ready_manifest GetStateManifestResponse::default();
                };
                if snapshot_height == 0
                    || snapshot_height <= request.requester_height
                    || snapshot_height > ctx.tip_height()
                    || ctx.tip_height().saturating_sub(snapshot_height)
                        > noid_chain::consensus::params::RECENT_BLOCK_RETENTION_DEPTH
                {
                    break 'ready_manifest GetStateManifestResponse::default();
                }
                let Some(snapshot_header) = ctx.store.get_header(snapshot_height).ok().flatten()
                else {
                    break 'ready_manifest GetStateManifestResponse::default();
                };
                let key = (
                    snapshot_height,
                    noid_chain::hash_block_header(&snapshot_header),
                );
                let Some(generation) = snapshot_exports.get(&key) else {
                    tracing::debug!(snapshot_height, "bounded snapshot generation is not ready");
                    break 'ready_manifest GetStateManifestResponse::default();
                };
                let manifest = generation.manifest();
                if manifest.state_root != snapshot_header.state_root
                    || manifest.log_slots != snapshot_header.log_slots
                    || manifest.active_slot_count != snapshot_header.active_slot_count
                    || manifest.alloc_counter != snapshot_header.alloc_counter
                {
                    tracing::warn!(snapshot_height, "disk snapshot manifest/header mismatch");
                    break 'ready_manifest GetStateManifestResponse::default();
                }

                let header_window = noid_chain::consensus::params::MEDIAN_TIME_BLOCKS as u64
                    + noid_chain::consensus::params::TX_EPOCH_BLOCKS;
                let start_height = snapshot_height.saturating_sub(header_window);
                let mut recent_headers =
                    Vec::with_capacity(snapshot_height.saturating_sub(start_height) as usize + 1);
                for height in start_height..=snapshot_height {
                    let Some(header) = ctx.get_header_from_store(height).ok().flatten() else {
                        break 'ready_manifest GetStateManifestResponse::default();
                    };
                    let mut encoded = Vec::new();
                    header.encode(&mut encoded);
                    recent_headers.push(encoded);
                }
                let segment_ids = manifest
                    .segments
                    .iter()
                    .map(|descriptor| descriptor.segment_id)
                    .collect();
                let segment_roots = manifest
                    .segments
                    .iter()
                    .map(|descriptor| descriptor.segment_root)
                    .collect();
                tracing::info!(
                    requester_height = request.requester_height,
                    snapshot_height,
                    segments = manifest.segments.len(),
                    "serving precomputed disk snapshot manifest"
                );
                GetStateManifestResponse {
                    tip_height: snapshot_height,
                    tip_hash: key.1,
                    cumulative_chainwork: manifest.cumulative_chainwork,
                    log_slots: manifest.log_slots,
                    active_slot_count: manifest.active_slot_count,
                    alloc_counter: manifest.alloc_counter,
                    eff_log: manifest.effective_log_segment_size,
                    segment_ids,
                    segment_roots,
                    recent_headers,
                }
            };
            let _ = swarm
                .behaviour_mut()
                .state_manifest_sync
                .send_response(channel, response);
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
                if response
                    .recent_headers
                    .iter()
                    .any(|h| h.len() > MAX_HEADER_BYTES)
                {
                    tracing::warn!(from = %peer, "manifest: oversized header entry, dropping");
                    return;
                }
                if response.segment_ids.len() != response.segment_roots.len() {
                    tracing::warn!(from = %peer, "manifest: segment_ids/segment_roots length mismatch, dropping");
                    return;
                }
                if !response.segment_ids.windows(2).all(|w| w[0] < w[1]) {
                    tracing::warn!(from = %peer, "manifest: segment IDs are not strictly sorted, dropping");
                    return;
                }
                let segment_span = response.log_slots.saturating_sub(response.eff_log as u32);
                let max_possible_segments = 1usize.checked_shl(segment_span).unwrap_or(usize::MAX);
                if response.segment_ids.len() > max_possible_segments {
                    tracing::warn!(
                        from = %peer,
                        segments = response.segment_ids.len(),
                        max_possible_segments,
                        log_slots = response.log_slots,
                        eff_log = response.eff_log,
                        "manifest: impossible segment count, dropping"
                    );
                    return;
                }
                if response.segment_ids.len() > MAX_SNAPSHOT_MANIFEST_SEGMENTS {
                    tracing::warn!(
                        from = %peer,
                        segments = response.segment_ids.len(),
                        max_segments = MAX_SNAPSHOT_MANIFEST_SEGMENTS,
                        "manifest: too many segment IDs, dropping"
                    );
                    return;
                }
                let Some(expected_segment_bytes) =
                    encoded_segment_len_for_eff_log(response.eff_log)
                else {
                    tracing::warn!(from = %peer, eff_log = response.eff_log, "manifest: invalid effective segment log, dropping");
                    return;
                };
                if expected_segment_bytes > MAX_SEGMENT_BYTES {
                    tracing::warn!(
                        from = %peer,
                        eff_log = response.eff_log,
                        expected_segment_bytes,
                        max_segment = MAX_SEGMENT_BYTES,
                        "manifest: segment encoding exceeds per-segment cap, dropping"
                    );
                    return;
                }
                tracing::info!(
                    from = %peer,
                    tip = response.tip_height,
                    segments = response.segment_ids.len(),
                    "received state manifest"
                );
                let _ = required_event_tx
                    .send(NetworkEvent::StateManifest {
                        from: peer,
                        manifest: Box::new(response),
                    })
                    .await;
            } else {
                // tip=0 is still a valid response for sync coordination: the node
                // layer counts it as "peer responded but has no usable state", so
                // it can proceed with another valid candidate without waiting for
                // the manifest timeout.
                tracing::debug!(from = %peer, "received empty state manifest");
                let _ = required_event_tx
                    .send(NetworkEvent::StateManifest {
                        from: peer,
                        manifest: Box::new(response),
                    })
                    .await;
            }
        }

        // --- State sync: segment server (step 2) ---
        //
        // Responses are pinned to the exact manifest snapshot boundary
        // (height + hash). The immutable disk generation remains available
        // while a live miner advances; only one segment is read per worker.
        SwarmEvent::Behaviour(NodeBehaviourEvent::StateSegmentSync(
            request_response::Event::Message {
                message:
                    request_response::Message::Request {
                        request, channel, ..
                    },
                peer,
                ..
            },
        )) => {
            const SEGMENT_RATE_WINDOW: Duration = Duration::from_secs(1);
            const MAX_SEGMENT_REQUESTS_PER_WINDOW: u32 = 64;
            let now = Instant::now();
            let entry = snapshot_segment_rate.entry(peer).or_insert((0, now));
            if now.duration_since(entry.1) >= SEGMENT_RATE_WINDOW {
                *entry = (0, now);
            }
            if entry.0 >= MAX_SEGMENT_REQUESTS_PER_WINDOW {
                tracing::debug!(peer = %peer, "snapshot segment request rate limited");
                let _ = swarm.behaviour_mut().state_segment_sync.send_response(
                    channel,
                    GetStateSegmentResponse {
                        segment_id: request.segment_id,
                        eff_log: 0,
                        data: None,
                        inbound_memory_permit: None,
                        outbound_memory_permit: None,
                    },
                );
                return;
            }
            entry.0 += 1;
            prune_snapshot_exports(snapshot_exports);
            let key = (request.expected_tip_height, request.expected_tip_hash);
            let Some(export) = snapshot_exports.get(&key).cloned() else {
                let _ = swarm.behaviour_mut().state_segment_sync.send_response(
                    channel,
                    GetStateSegmentResponse {
                        segment_id: request.segment_id,
                        eff_log: 0,
                        data: None,
                        inbound_memory_permit: None,
                        outbound_memory_permit: None,
                    },
                );
                return;
            };
            let Some(descriptor) = export.manifest().segment(request.segment_id).copied() else {
                let _ = swarm.behaviour_mut().state_segment_sync.send_response(
                    channel,
                    GetStateSegmentResponse {
                        segment_id: request.segment_id,
                        eff_log: 0,
                        data: None,
                        inbound_memory_permit: None,
                        outbound_memory_permit: None,
                    },
                );
                return;
            };
            let Ok(permit) = segment_encode_semaphore.clone().try_acquire_owned() else {
                let _ = swarm.behaviour_mut().state_segment_sync.send_response(
                    channel,
                    GetStateSegmentResponse {
                        segment_id: request.segment_id,
                        eff_log: 0,
                        data: None,
                        inbound_memory_permit: None,
                        outbound_memory_permit: None,
                    },
                );
                return;
            };
            let effective_log = export.manifest().effective_log_segment_size;
            let expected_len = encoded_segment_len_for_eff_log(effective_log);
            let declared_len = descriptor.encoded_len as usize;
            if expected_len != Some(declared_len) || declared_len > MAX_SEGMENT_BYTES {
                tracing::warn!(
                    segment = descriptor.segment_id,
                    declared_len,
                    "snapshot descriptor has non-canonical segment length"
                );
                let _ = swarm.behaviour_mut().state_segment_sync.send_response(
                    channel,
                    GetStateSegmentResponse {
                        segment_id: request.segment_id,
                        eff_log: 0,
                        data: None,
                        inbound_memory_permit: None,
                        outbound_memory_permit: None,
                    },
                );
                return;
            }
            let completion = segment_response_tx.clone();
            let budget = outbound_response_budget.clone();
            tokio::spawn(async move {
                let Ok(Some(outbound_memory_permit)) = budget.acquire(declared_len).await else {
                    return;
                };
                // The exact descriptor length has been admitted before the
                // generation opens or allocates its encoded payload Vec.
                let loaded = tokio::task::spawn_blocking(move || {
                    let _encode_permit = permit;
                    export.read_encoded_segment(descriptor.segment_id)
                })
                .await;
                let response = match loaded {
                    Ok(Ok(data)) => GetStateSegmentResponse {
                        segment_id: descriptor.segment_id,
                        eff_log: effective_log,
                        data: Some(data),
                        inbound_memory_permit: None,
                        outbound_memory_permit: Some(outbound_memory_permit),
                    },
                    Ok(Err(error)) => {
                        tracing::warn!(segment = descriptor.segment_id, err = %error, "disk snapshot segment read failed");
                        GetStateSegmentResponse {
                            segment_id: descriptor.segment_id,
                            eff_log: 0,
                            data: None,
                            inbound_memory_permit: None,
                            // The permit is harmless for an empty response and
                            // is retained until the codec reports completion.
                            outbound_memory_permit: Some(outbound_memory_permit),
                        }
                    }
                    Err(error) => {
                        tracing::warn!(segment = descriptor.segment_id, err = %error, "snapshot segment worker failed");
                        GetStateSegmentResponse {
                            segment_id: descriptor.segment_id,
                            eff_log: 0,
                            data: None,
                            inbound_memory_permit: None,
                            outbound_memory_permit: Some(outbound_memory_permit),
                        }
                    }
                };
                let _ = completion
                    .send(PendingStateSegmentResponse { channel, response })
                    .await;
            });
        }

        // --- State sync: segment client (step 2 response) ---
        SwarmEvent::Behaviour(NodeBehaviourEvent::StateSegmentSync(
            request_response::Event::Message {
                message: request_response::Message::Response { response, .. },
                peer,
            },
        )) => {
            if let Some(ref data) = response.data {
                let Some(expected_len) = encoded_segment_len_for_eff_log(response.eff_log) else {
                    tracing::warn!(peer = %peer, segment = response.segment_id, eff_log = response.eff_log, "segment response has invalid effective segment log — dropped");
                    return;
                };
                if data.len() != expected_len {
                    tracing::warn!(
                        peer = %peer,
                        segment = response.segment_id,
                        len = data.len(),
                        expected = expected_len,
                        "segment response encoded length mismatch — dropped"
                    );
                    return;
                }
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
            let _ = required_event_tx
                .send(NetworkEvent::StateSegment {
                    from: peer,
                    response,
                })
                .await;
        }

        // --- Mempool sync: server side (peer requests our mempool) ---
        SwarmEvent::Behaviour(NodeBehaviourEvent::MempoolSync(
            request_response::Event::Message {
                message: request_response::Message::Request { channel, .. },
                peer,
            },
        )) => {
            let txs = mempool
                .intent_bytes_prefix(
                    MAX_MEMPOOL_SYNC_TXS,
                    MAX_MEMPOOL_SYNC_BYTES,
                    MAX_TX_INTENT_BYTES_GLOBAL,
                )
                .await;
            let total_bytes: usize = txs.iter().map(Vec::len).sum();
            tracing::debug!(
                peer = %peer,
                tx_count = txs.len(),
                total_bytes,
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
            let mut txs = response.txs;
            if txs.len() > MAX_MEMPOOL_SYNC_TXS {
                tracing::warn!(
                    from = %peer,
                    count = txs.len(),
                    "mempool sync response oversized, truncating to {MAX_MEMPOOL_SYNC_TXS}"
                );
                txs.truncate(MAX_MEMPOOL_SYNC_TXS);
            }
            let mut total_bytes = 0usize;
            txs.retain(|tx| {
                if tx.len() > MAX_TX_INTENT_BYTES_GLOBAL {
                    tracing::warn!(from = %peer, len = tx.len(), "mempool sync tx too large — dropped");
                    return false;
                }
                total_bytes = total_bytes.saturating_add(tx.len());
                if total_bytes > MAX_MEMPOOL_SYNC_BYTES {
                    tracing::warn!(from = %peer, total_bytes, "mempool sync response total bytes exceeded cap — truncating");
                    return false;
                }
                true
            });
            if !txs.is_empty() {
                tracing::debug!(
                    from = %peer,
                    tx_count = txs.len(),
                    "received mempool sync response"
                );
                let _ = gossip_event_tx.send(NetworkEvent::MempoolSyncResponse { from: peer, txs });
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
                let _ = gossip_event_tx.send(NetworkEvent::PeerConnected(peer_id));
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
                let _ = gossip_event_tx.send(NetworkEvent::PeerDisconnected(peer_id));
                tracing::debug!(peer = %peer_id, cause = ?cause, "peer disconnected");
                block_event_rate.remove(&peer_id);
                tx_gossip_rate.remove(&peer_id);
                mempool_sync_last_request.remove(&peer_id);
                snapshot_manifest_last_request.remove(&peer_id);
                snapshot_segment_rate.remove(&peer_id);
                // Schedule reconnect for peers we dialled (outbound connections).
                // We don't attempt to reconnect inbound peers — they should re-dial us.
                if let libp2p::core::ConnectedPoint::Dialer { address, .. } = endpoint {
                    if let std::collections::hash_map::Entry::Vacant(e) = reconnect.entry(peer_id) {
                        let retry_at =
                            tokio::time::Instant::now() + std::time::Duration::from_secs(10);
                        e.insert((address, retry_at, 0));
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
            let _ = gossip_event_tx.send(NetworkEvent::PeerDisconnected(peer));
        }

        SwarmEvent::Behaviour(NodeBehaviourEvent::StateManifestSync(
            request_response::Event::OutboundFailure { peer, error, .. },
        )) => {
            tracing::debug!(peer = %peer, err = %error, "manifest sync request failed");
            let _ = gossip_event_tx.send(NetworkEvent::PeerDisconnected(peer));
        }

        SwarmEvent::Behaviour(NodeBehaviourEvent::StateSegmentSync(
            request_response::Event::OutboundFailure { peer, error, .. },
        )) => {
            tracing::debug!(peer = %peer, err = %error, "segment sync request failed");
            let _ = gossip_event_tx.send(NetworkEvent::PeerDisconnected(peer));
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inline_block_gossip_policy_uses_combined_block_proof_and_sidecar_size() {
        assert!(should_inline_block_gossip(1, 0, 0));
        assert!(should_inline_block_gossip(
            512 * 1024,
            256 * 1024,
            INLINE_BLOCK_GOSSIP_THRESHOLD - 768 * 1024,
        ));
        assert!(!should_inline_block_gossip(0, 0, 0));
        assert!(!should_inline_block_gossip(
            512 * 1024,
            256 * 1024,
            INLINE_BLOCK_GOSSIP_THRESHOLD - 768 * 1024 + 1,
        ));
    }

    #[test]
    fn snapshot_proof_serving_requires_retained_suffix() {
        let retention = noid_chain::consensus::params::RECENT_BLOCK_RETENTION_DEPTH;
        assert!(snapshot_suffix_is_retained(100, 100));
        assert!(snapshot_suffix_is_retained(100, 100 - retention));
        assert!(!snapshot_suffix_is_retained(100, 100 - retention - 1));
        assert!(!snapshot_suffix_is_retained(100, 101));
    }

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn canonical_wire_caps_are_ordered() {
        assert!(MAX_BLOCK_PROOF_BYTES > INLINE_BLOCK_GOSSIP_THRESHOLD);
        assert!(MAX_BLOCK_AUTH_SIDECAR_BYTES > INLINE_BLOCK_GOSSIP_THRESHOLD);
        assert!(MAX_TX_INTENT_BYTES_GLOBAL < INLINE_BLOCK_GOSSIP_THRESHOLD);
        assert!(MAX_MEMPOOL_SYNC_BYTES >= MAX_TX_INTENT_BYTES_GLOBAL);
        assert!(MAX_HISTORY_PROOF_BYTES < MAX_BLOCK_PROOF_BYTES);
    }

    #[tokio::test]
    async fn required_event_queue_is_hard_bounded_and_backpressured() {
        let (tx, mut rx) = mpsc::channel(REQUIRED_EVENT_QUEUE_CAPACITY);
        let peer = libp2p::identity::Keypair::generate_ed25519()
            .public()
            .to_peer_id();
        for height in 0..REQUIRED_EVENT_QUEUE_CAPACITY {
            tx.try_send(NetworkEvent::RecentBlockUnavailable {
                from: peer,
                height: height as u64,
            })
            .unwrap();
        }
        assert!(matches!(
            tx.try_send(NetworkEvent::RecentBlockUnavailable {
                from: peer,
                height: u64::MAX,
            }),
            Err(mpsc::error::TrySendError::Full(_))
        ));

        assert!(rx.recv().await.is_some());
        tx.try_send(NetworkEvent::RecentBlockUnavailable {
            from: peer,
            height: u64::MAX,
        })
        .unwrap();
    }

    #[tokio::test]
    async fn required_response_survives_recoverable_gossip_lag() {
        let (required_tx, required_rx) = mpsc::channel(1);
        let (gossip_tx, gossip_rx) = tokio::sync::broadcast::channel(2);
        let peer = libp2p::identity::Keypair::generate_ed25519()
            .public()
            .to_peer_id();
        let mut receiver = NetworkEventReceiver {
            required_rx,
            gossip_rx,
            required_closed: false,
            gossip_closed: false,
        };

        for height in 0..3 {
            gossip_tx
                .send(NetworkEvent::NewBlockAnnouncement {
                    from: peer,
                    height,
                    hash: [height as u8; 32],
                    header_bytes: Vec::new(),
                })
                .unwrap();
        }
        required_tx
            .send(NetworkEvent::RecentBlockUnavailable {
                from: peer,
                height: 99,
            })
            .await
            .unwrap();

        assert!(matches!(
            receiver.recv().await,
            Ok(NetworkEvent::RecentBlockUnavailable { height: 99, .. })
        ));
        assert!(matches!(
            receiver.recv().await,
            Err(NetworkEventRecvError::Lagged(1))
        ));
    }
}
