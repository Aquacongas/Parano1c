// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! `P2PNetwork` — the libp2p swarm event loop.
//!
//! Handles:
//! - GossipSub: receiving blocks and txs from peers, broadcasting our blocks/txs
//! - Request-Response: serving headers, accepted-block bundles, and HistoryStep terminals
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
    INLINE_BLOCK_GOSSIP_THRESHOLD, MAX_HISTORY_STEP_TERMINAL_BYTES, MAX_MEMPOOL_SYNC_BYTES,
    MAX_MEMPOOL_SYNC_TXS, MAX_SEGMENT_BYTES, MAX_SNAPSHOT_MANIFEST_SEGMENTS,
    MAX_TX_INTENT_BYTES_GLOBAL,
};
use noid_chain::storage::{encoded_segment_len_for_eff_log, MdbxChainContext};
use noid_chain::storage::{
    export_snapshot_generation, open_snapshot_generation, SnapshotGeneration,
};
use noid_chain::{AcceptedBlockBundle, MAX_ACCEPTED_BLOCK_BUNDLE_BYTES};
use noid_mempool::AsyncMempool;

use crate::behaviour::{NodeBehaviour, NodeBehaviourEvent};
use crate::outbound_budget::OutboundResponseBudget;
use crate::protocol::{
    BlockGossipMsg, GetHeadersResponse, GetHistoryStepTerminalResponse, GetMempoolResponse,
    GetRecentBlockResponse, GetStateManifestResponse, GetStateSegmentRequest,
    GetStateSegmentResponse, NetworkTopics, BLOCK_GOSSIP_FIXED_BYTES,
};

struct PendingStateSegmentResponse {
    channel: request_response::ResponseChannel<GetStateSegmentResponse>,
    response: GetStateSegmentResponse,
}

struct PendingBlockResponse {
    channel: request_response::ResponseChannel<GetRecentBlockResponse>,
    response: GetRecentBlockResponse,
}

struct PendingHistoryStepTerminalResponse {
    channel: request_response::ResponseChannel<GetHistoryStepTerminalResponse>,
    response: GetHistoryStepTerminalResponse,
}

struct PendingMempoolResponse {
    channel: request_response::ResponseChannel<GetMempoolResponse>,
    response: GetMempoolResponse,
}

/// Admit the maximum legal response before invoking the payload loader.
/// Keeping this boundary in one helper makes it impossible for a serving path
/// to accidentally move mempool cloning ahead of process-wide byte admission.
async fn prepare_mempool_response_after_admission<Load, Loaded>(
    budget: OutboundResponseBudget,
    load: Load,
) -> std::io::Result<GetMempoolResponse>
where
    Load: FnOnce() -> Loaded,
    Loaded: std::future::Future<Output = Vec<Vec<u8>>>,
{
    let outbound_memory_permit =
        budget
            .acquire(MAX_MEMPOOL_SYNC_BYTES)
            .await?
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "non-empty mempool reservation returned no permit",
                )
            })?;
    let txs = load().await;
    Ok(GetMempoolResponse {
        txs,
        inbound_memory_permit: None,
        outbound_memory_permit: Some(outbound_memory_permit),
    })
}

type SnapshotExportKey = (u64, [u8; 32]);
type SnapshotExport = Arc<SnapshotGeneration>;

const MAX_SNAPSHOT_EXPORTS: usize = 2;
const MAX_OUTBOUND_BLOCK_RESPONSE_BYTES: usize = MAX_ACCEPTED_BLOCK_BUNDLE_BYTES;
const MAX_OUTBOUND_HISTORY_STEP_RESPONSE_BYTES: usize = MAX_HISTORY_STEP_TERMINAL_BYTES;
const MAX_PENDING_RETAINED_BLOCK_REQUESTS: usize = 256;
const MAX_PENDING_STATE_SEGMENT_REQUESTS: usize = 64;
const _: () = assert!(
    MAX_PENDING_STATE_SEGMENT_REQUESTS >= noid_chain::consensus::wire_limits::MAX_INFLIGHT_SEGMENTS
);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PendingRetainedBlockRequest {
    peer: PeerId,
    height: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PendingStateSegmentRequest {
    peer: PeerId,
    segment_id: u16,
    expected_tip_height: u64,
    expected_tip_hash: [u8; 32],
}

/// A fixed-capacity request correlation table. Request IDs are local transport
/// capabilities: a response is consumed exactly once and only by the peer and
/// request tuple recorded when `send_request` returned that ID.
struct BoundedPendingRequests<K, V> {
    entries: std::collections::HashMap<K, V>,
    max_len: usize,
}

impl<K: std::hash::Hash + Eq, V> BoundedPendingRequests<K, V> {
    fn new(max_len: usize) -> Self {
        Self {
            entries: std::collections::HashMap::with_capacity(max_len),
            max_len,
        }
    }

    fn has_capacity(&self) -> bool {
        self.entries.len() < self.max_len
    }

    fn try_insert(&mut self, request_id: K, pending: V) -> bool {
        if !self.has_capacity() || self.entries.contains_key(&request_id) {
            return false;
        }
        self.entries.insert(request_id, pending);
        true
    }

    fn remove(&mut self, request_id: &K) -> Option<V> {
        self.entries.remove(request_id)
    }

    fn retain(&mut self, keep: impl FnMut(&K, &mut V) -> bool) {
        self.entries.retain(keep);
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.len()
    }
}

fn retained_block_response_matches_pending(
    pending: PendingRetainedBlockRequest,
    peer: PeerId,
    response_height: u64,
) -> bool {
    pending.peer == peer && pending.height == response_height
}

fn state_segment_response_matches_pending(
    pending: PendingStateSegmentRequest,
    peer: PeerId,
    response: &GetStateSegmentResponse,
) -> bool {
    pending.peer == peer
        && pending.segment_id == response.segment_id
        && pending.expected_tip_height == response.expected_tip_height
        && pending.expected_tip_hash == response.expected_tip_hash
}

fn unavailable_state_segment_response(request: &GetStateSegmentRequest) -> GetStateSegmentResponse {
    GetStateSegmentResponse {
        segment_id: request.segment_id,
        expected_tip_height: request.expected_tip_height,
        expected_tip_hash: request.expected_tip_hash,
        eff_log: 0,
        data: None,
        inbound_memory_permit: None,
        outbound_memory_permit: None,
    }
}

fn notify_outbound_request_failed(
    event_tx: &tokio::sync::broadcast::Sender<NetworkEvent>,
    peer: PeerId,
) {
    // This is the same retry-driving signal used for request-response
    // OutboundFailure. The connection may still be live; node sync state must
    // nevertheless release the logical request and choose/retry a peer.
    let _ = event_tx.send(NetworkEvent::PeerDisconnected(peer));
}

fn clear_peer_request_correlations(
    pending_retained_block_requests: &mut BoundedPendingRequests<
        request_response::OutboundRequestId,
        PendingRetainedBlockRequest,
    >,
    pending_state_segment_requests: &mut BoundedPendingRequests<
        request_response::OutboundRequestId,
        PendingStateSegmentRequest,
    >,
    peer: PeerId,
) {
    pending_retained_block_requests.retain(|_, pending| pending.peer != peer);
    pending_state_segment_requests.retain(|_, pending| pending.peer != peer);
}

fn fail_peer_requests(
    pending_retained_block_requests: &mut BoundedPendingRequests<
        request_response::OutboundRequestId,
        PendingRetainedBlockRequest,
    >,
    pending_state_segment_requests: &mut BoundedPendingRequests<
        request_response::OutboundRequestId,
        PendingStateSegmentRequest,
    >,
    event_tx: &tokio::sync::broadcast::Sender<NetworkEvent>,
    peer: PeerId,
) {
    clear_peer_request_correlations(
        pending_retained_block_requests,
        pending_state_segment_requests,
        peer,
    );
    notify_outbound_request_failed(event_tx, peer);
}

// Hard caps on incoming response sizes are shared via noid_chain::consensus::wire_limits.

fn snapshot_suffix_is_retained(tip_height: u64, terminal_height: u64) -> bool {
    terminal_height <= tip_height
        && tip_height.saturating_sub(terminal_height)
            <= noid_chain::consensus::params::RECENT_BLOCK_RETENTION_DEPTH
}

/// Choose the finalized snapshot boundary only when its exact HistoryStep
/// terminal is durably available.
fn local_history_step_boundary(ctx: &MdbxChainContext) -> Option<(u64, [u8; 32])> {
    let finalized = ctx.finalized_checkpoint();
    let height = finalized.height;
    if height == 0
        || height > ctx.tip_height()
        || !snapshot_suffix_is_retained(ctx.tip_height(), height)
    {
        return None;
    }
    let header = ctx.store.get_header(height).ok().flatten()?;
    let block_hash = noid_chain::hash_block_header(&header);
    if block_hash != finalized.hash {
        return None;
    }
    if !ctx
        .store
        .has_history_step_terminal_at(height, block_hash)
        .ok()?
    {
        return None;
    }
    Some((height, block_hash))
}

/// Load only the exact HistoryStep terminal requested for a finalized manifest.
fn local_history_step_terminal(
    ctx: &MdbxChainContext,
    height: u64,
    block_hash: [u8; 32],
) -> Option<Vec<u8>> {
    let finalized = ctx.finalized_checkpoint();
    if height == 0
        || height > finalized.height
        || !snapshot_suffix_is_retained(ctx.tip_height(), height)
    {
        return None;
    }
    ctx.store
        .get_history_step_terminal_at(height, block_hash)
        .ok()
        .flatten()
}

fn decode_stored_accepted_block_bundle(
    height: u64,
    encoded: Option<Vec<u8>>,
) -> Option<AcceptedBlockBundle> {
    let encoded = encoded?;
    match AcceptedBlockBundle::decode(&encoded) {
        Ok(bundle) if bundle.height() == height => Some(bundle),
        Ok(_) => {
            tracing::warn!(height, "stored accepted-block bundle has the wrong height");
            None
        }
        Err(error) => {
            tracing::warn!(height, %error, "stored accepted-block bundle is invalid");
            None
        }
    }
}

/// Decode one fixed-framed batch as a single contiguous chain fragment.
/// A malformed entry invalidates the complete response; silently shortening a
/// hostile batch would make its transport identity ambiguous to the sync FSM.
fn decode_linked_header_batch(
    encoded_headers: Vec<Vec<u8>>,
) -> Result<Vec<noid_chain::block_header::BlockHeader>, &'static str> {
    if encoded_headers.len() > 512 {
        return Err("header count exceeds cap");
    }
    let mut decoded: Vec<noid_chain::block_header::BlockHeader> = Vec::new();
    decoded
        .try_reserve_exact(encoded_headers.len())
        .map_err(|_| "header batch allocation failed")?;
    for encoded in encoded_headers {
        if encoded.len() != noid_chain::BLOCK_HEADER_WIRE_SIZE {
            return Err("noncanonical header length");
        }
        let header = noid_chain::block_header::BlockHeader::from_bytes(&encoded)
            .map_err(|_| "header decode failed")?;
        if let Some(parent) = decoded.last() {
            if header.height
                != parent
                    .height
                    .checked_add(1)
                    .ok_or("header height overflow")?
            {
                return Err("header batch is not height-contiguous");
            }
            if header.prev_block_hash != noid_chain::hash_block_header(parent) {
                return Err("header batch is not hash-linked");
            }
        }
        decoded.push(header);
    }
    Ok(decoded)
}

fn accepted_block_bundle_wire_len(bundle: &AcceptedBlockBundle) -> usize {
    noid_chain::ACCEPTED_BLOCK_BUNDLE_HEADER_BYTES
        + bundle.block_bytes().len()
        + bundle.history_step_terminal_bytes().len()
}

fn should_inline_accepted_block_bundle(bundle: &AcceptedBlockBundle) -> bool {
    accepted_block_bundle_wire_len(bundle).saturating_add(BLOCK_GOSSIP_FIXED_BYTES)
        <= INLINE_BLOCK_GOSSIP_THRESHOLD
}

/// Commands sent to the P2P network event loop.
#[derive(Debug)]
pub enum NetworkCommand {
    /// Announce one complete accepted-block bundle. The event loop chooses
    /// inline gossip or header-only gossip from its canonical encoded size.
    AnnounceBlock { bundle: AcceptedBlockBundle },
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
    /// Emits `NetworkEvent::RecentBlock` for each successfully fetched bundle.
    SyncBlocksFrom {
        peer: PeerId,
        from_height: u64,
        count: u16,
    },
    /// Request a specific block by height from a peer (orphan resolution).
    /// Emits `NetworkEvent::RecentBlock` if the peer has the bundle.
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
    /// Request the fused HistoryStep terminal for an exact snapshot boundary.
    RequestHistoryStepTerminal {
        peer: PeerId,
        height: u64,
        block_hash: [u8; 32],
    },
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
    BlockAnnouncement {
        from: PeerId,
        header: noid_chain::BlockHeader,
    },
    /// A complete accepted-block bundle arrived inline via gossip.
    IncomingBlock {
        from: PeerId,
        bundle: AcceptedBlockBundle,
        /// Inline gossip is bounded by its codec, so this is always `None`.
        inbound_memory_permit: Option<Arc<tokio::sync::OwnedSemaphorePermit>>,
    },
    /// A complete retained bundle arrived through block pull.
    RecentBlock {
        from: PeerId,
        bundle: AcceptedBlockBundle,
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
    /// Fused HistoryStep terminal response for O(1) snapshot sync.
    HistoryStepTerminal {
        from: PeerId,
        height: u64,
        block_hash: [u8; 32],
        /// Exact-bound HistoryStep terminal bytes, or empty when unavailable.
        terminal_bytes: Vec<u8>,
        /// Holds the process-global inbound terminal byte budget until the node
        /// finishes verifying this response.
        inbound_memory_permit: Option<Arc<tokio::sync::OwnedSemaphorePermit>>,
    },
    /// Mempool sync response: raw TxIntent bytes from a peer's mempool.
    /// Received after sending `RequestMempoolSync` on peer connect.
    MempoolSyncResponse {
        from: PeerId,
        /// Raw TxIntent bytes, one per pending transaction.
        txs: Vec<Vec<u8>>,
        /// Holds the process-global inbound mempool byte budget until node-side
        /// submission has consumed this response.
        inbound_memory_permit: Option<Arc<tokio::sync::OwnedSemaphorePermit>>,
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
/// report lag. This prevents a slow consumer from retaining an unbounded
/// number of bundles or silently losing a requested suffix response.
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

    /// Announce one complete accepted block to all peers.
    pub async fn announce_block(&self, bundle: AcceptedBlockBundle) {
        let _ = self
            .cmd_tx
            .send(NetworkCommand::AnnounceBlock { bundle })
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

    /// Request the HistoryStep terminal for an exact snapshot boundary.
    pub async fn request_history_step_terminal(
        &self,
        peer: PeerId,
        height: u64,
        block_hash: [u8; 32],
    ) {
        let _ = self
            .cmd_tx
            .send(NetworkCommand::RequestHistoryStepTerminal {
                peer,
                height,
                block_hash,
            })
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
    let mut pending_retained_block_requests =
        BoundedPendingRequests::new(MAX_PENDING_RETAINED_BLOCK_REQUESTS);
    let mut pending_state_segment_requests =
        BoundedPendingRequests::new(MAX_PENDING_STATE_SEGMENT_REQUESTS);

    // One waiting response of each kind is sufficient: the request-response
    // behaviour owns the next response while its codec writes it. Byte permits
    // retained by both stages are the process-wide RAM bound.
    let (block_response_tx, mut block_response_rx) = mpsc::channel::<PendingBlockResponse>(1);
    let (history_step_response_tx, mut history_step_response_rx) =
        mpsc::channel::<PendingHistoryStepTerminalResponse>(1);
    let (segment_response_tx, mut segment_response_rx) =
        mpsc::channel::<PendingStateSegmentResponse>(1);
    let (mempool_response_tx, mut mempool_response_rx) = mpsc::channel::<PendingMempoolResponse>(1);
    let block_response_prepare_semaphore = Arc::new(Semaphore::new(2));
    let history_step_response_prepare_semaphore = Arc::new(Semaphore::new(4));
    let segment_encode_semaphore = Arc::new(Semaphore::new(2));
    let mempool_response_prepare_semaphore = Arc::new(Semaphore::new(1));
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
            handle_network_command(
                &mut swarm,
                cmd,
                &topics,
                &mut mempool_sync_last_request,
                &gossip_event_tx,
                &mut pending_retained_block_requests,
                &mut pending_state_segment_requests,
            );
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
                    &history_step_response_tx,
                    &history_step_response_prepare_semaphore,
                    &segment_response_tx,
                    &segment_encode_semaphore,
                    &mempool_response_tx,
                    &mempool_response_prepare_semaphore,
                    &outbound_response_budget,
                    &mut snapshot_exports,
                    &mut reconnect,
                    &mut block_event_rate,
                    &mut tx_gossip_rate,
                    &mut mempool_sync_last_request,
                    &mut snapshot_manifest_last_request,
                    &mut snapshot_segment_rate,
                    &mut pending_retained_block_requests,
                    &mut pending_state_segment_requests,
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

            prepared = history_step_response_rx.recv() => {
                if let Some(prepared) = prepared {
                    let height = prepared.response.height;
                    let terminal_len = prepared
                        .response
                        .terminal_bytes
                        .as_ref()
                        .map_or(0, Vec::len);
                    match swarm
                        .behaviour_mut()
                        .history_step_sync
                        .send_response(prepared.channel, prepared.response)
                    {
                        Ok(()) => tracing::debug!(
                            height,
                            terminal_len,
                            "queued HistoryStep terminal response"
                        ),
                        Err(_) => tracing::warn!(
                            height,
                            terminal_len,
                            "HistoryStep response channel closed before queueing"
                        ),
                    }
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

            prepared = mempool_response_rx.recv() => {
                if let Some(prepared) = prepared {
                    let _ = swarm
                        .behaviour_mut()
                        .mempool_sync
                        .send_response(prepared.channel, prepared.response);
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
                        local_history_step_boundary(&ctx).and_then(|key| {
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
                        &gossip_event_tx,
                        &mut pending_retained_block_requests,
                        &mut pending_state_segment_requests,
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
    failure_event_tx: &tokio::sync::broadcast::Sender<NetworkEvent>,
    pending_retained_block_requests: &mut BoundedPendingRequests<
        request_response::OutboundRequestId,
        PendingRetainedBlockRequest,
    >,
    pending_state_segment_requests: &mut BoundedPendingRequests<
        request_response::OutboundRequestId,
        PendingStateSegmentRequest,
    >,
) {
    match cmd {
        NetworkCommand::AnnounceBlock { bundle } => {
            let height = bundle.height();
            let inline = should_inline_accepted_block_bundle(&bundle);
            let message = BlockGossipMsg::from_bundle(bundle, inline);
            let topic = gossipsub::IdentTopic::new(topics.blocks.clone());
            if let Err(error) = swarm
                .behaviour_mut()
                .gossipsub
                .publish(topic, message.encode())
            {
                tracing::debug!(height, err = %error, "gossipsub: block announcement");
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
                if !pending_retained_block_requests.has_capacity() {
                    tracing::warn!(
                        peer = %peer,
                        height = h,
                        limit = MAX_PENDING_RETAINED_BLOCK_REQUESTS,
                        "retained-block request correlation table full"
                    );
                    fail_peer_requests(
                        pending_retained_block_requests,
                        pending_state_segment_requests,
                        failure_event_tx,
                        peer,
                    );
                    break;
                }
                let request_id = swarm
                    .behaviour_mut()
                    .block_sync
                    .send_request(&peer, crate::protocol::GetRecentBlockRequest { height: h });
                let inserted = pending_retained_block_requests
                    .try_insert(request_id, PendingRetainedBlockRequest { peer, height: h });
                debug_assert!(inserted, "fresh block-sync request ID must be unique");
            }
        }
        NetworkCommand::RequestBlock { peer, height } => {
            if !pending_retained_block_requests.has_capacity() {
                tracing::warn!(
                    peer = %peer,
                    height,
                    limit = MAX_PENDING_RETAINED_BLOCK_REQUESTS,
                    "retained-block request correlation table full"
                );
                fail_peer_requests(
                    pending_retained_block_requests,
                    pending_state_segment_requests,
                    failure_event_tx,
                    peer,
                );
                return;
            }
            let request_id = swarm
                .behaviour_mut()
                .block_sync
                .send_request(&peer, crate::protocol::GetRecentBlockRequest { height });
            let inserted = pending_retained_block_requests
                .try_insert(request_id, PendingRetainedBlockRequest { peer, height });
            debug_assert!(inserted, "fresh block-sync request ID must be unique");
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
            // The node owns exactly one active snapshot session. Retire request
            // IDs from superseded sessions immediately instead of retaining
            // them for the 60-second libp2p timeout. A delayed response for a
            // retired ID is consequently unknown and inert.
            pending_state_segment_requests.retain(|_, pending| {
                pending.peer == peer
                    && pending.expected_tip_height == expected_tip_height
                    && pending.expected_tip_hash == expected_tip_hash
            });
            if !pending_state_segment_requests.has_capacity() {
                tracing::warn!(
                    peer = %peer,
                    segment_id,
                    limit = MAX_PENDING_STATE_SEGMENT_REQUESTS,
                    "state-segment request correlation table full"
                );
                fail_peer_requests(
                    pending_retained_block_requests,
                    pending_state_segment_requests,
                    failure_event_tx,
                    peer,
                );
                return;
            }
            let request_id = swarm.behaviour_mut().state_segment_sync.send_request(
                &peer,
                crate::protocol::GetStateSegmentRequest {
                    segment_id,
                    expected_tip_height,
                    expected_tip_hash,
                },
            );
            let inserted = pending_state_segment_requests.try_insert(
                request_id,
                PendingStateSegmentRequest {
                    peer,
                    segment_id,
                    expected_tip_height,
                    expected_tip_hash,
                },
            );
            debug_assert!(inserted, "fresh segment-sync request ID must be unique");
            tracing::debug!(peer = %peer, segment_id, "requesting state segment");
        }
        NetworkCommand::RequestHistoryStepTerminal {
            peer,
            height,
            block_hash,
        } => {
            let _ = swarm.behaviour_mut().history_step_sync.send_request(
                &peer,
                crate::protocol::GetHistoryStepTerminalRequest { height, block_hash },
            );
            tracing::debug!(peer = %peer, height, "requesting HistoryStep terminal for snapshot verification");
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
    history_step_response_tx: &mpsc::Sender<PendingHistoryStepTerminalResponse>,
    history_step_response_prepare_semaphore: &Arc<Semaphore>,
    segment_response_tx: &mpsc::Sender<PendingStateSegmentResponse>,
    segment_encode_semaphore: &Arc<Semaphore>,
    mempool_response_tx: &mpsc::Sender<PendingMempoolResponse>,
    mempool_response_prepare_semaphore: &Arc<Semaphore>,
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
    pending_retained_block_requests: &mut BoundedPendingRequests<
        request_response::OutboundRequestId,
        PendingRetainedBlockRequest,
    >,
    pending_state_segment_requests: &mut BoundedPendingRequests<
        request_response::OutboundRequestId,
        PendingStateSegmentRequest,
    >,
) {
    macro_rules! fail_peer {
        ($peer:expr) => {
            fail_peer_requests(
                pending_retained_block_requests,
                pending_state_segment_requests,
                gossip_event_tx,
                $peer,
            )
        };
    }

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
                match BlockGossipMsg::decode(&message.data) {
                    Ok(message) => {
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
                        match message {
                            BlockGossipMsg::Complete(bundle) => {
                                tracing::debug!(height = bundle.height(), peer = %propagation_source, "received complete block bundle via gossip");
                                let _ = gossip_event_tx.send(NetworkEvent::IncomingBlock {
                                    from: origin,
                                    bundle,
                                    inbound_memory_permit: None,
                                });
                            }
                            BlockGossipMsg::Header(header) => {
                                let _ = gossip_event_tx.send(NetworkEvent::BlockAnnouncement {
                                    from: origin,
                                    header,
                                });
                            }
                        }
                    }
                    Err(error) => {
                        tracing::debug!(
                            peer = %propagation_source,
                            %error,
                            "block gossip message decode failed"
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
            let decoded = match decode_linked_header_batch(response.headers) {
                Ok(decoded) => decoded,
                Err(error) => {
                    tracing::warn!(from = %peer, error, "invalid header batch response — dropped");
                    return;
                }
            };
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
                message:
                    request_response::Message::Response {
                        request_id,
                        response,
                    },
                peer,
            },
        )) => {
            let Some(pending) = pending_retained_block_requests.remove(&request_id) else {
                tracing::warn!(
                    peer = %peer,
                    request_id = %request_id,
                    response_height = response.height,
                    "unknown or delayed retained-block response — dropped"
                );
                return;
            };
            if !retained_block_response_matches_pending(pending, peer, response.height) {
                tracing::warn!(
                    peer = %peer,
                    request_id = %request_id,
                    requested_peer = %pending.peer,
                    requested_height = pending.height,
                    response_height = response.height,
                    "retained-block response does not match its exact request — dropped"
                );
                fail_peer!(pending.peer);
                return;
            }
            let inbound_memory_permit = response.inbound_memory_permit.clone();
            if let Some(bundle) = response.bundle {
                const BLOCK_RATE_WINDOW: Duration = Duration::from_secs(10);
                const BLOCK_RATE_MAX: u32 = 40;
                if !allow_peer_rate(block_event_rate, peer, BLOCK_RATE_MAX, BLOCK_RATE_WINDOW) {
                    tracing::debug!(peer = %peer, "pulled block response rate limit exceeded — dropped before event channel");
                    fail_peer!(pending.peer);
                    return;
                }
                tracing::debug!(peer = %peer, height = bundle.height(), "received accepted-block bundle via pull");
                let _ = required_event_tx
                    .send(NetworkEvent::RecentBlock {
                        from: peer,
                        bundle,
                        inbound_memory_permit,
                    })
                    .await;
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

        // --- Block pull: server side — serve one complete retained bundle ---
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
                    match ctx.store.get_recent_accepted_block_bundle_bounded(height) {
                        Ok(encoded) => decode_stored_accepted_block_bundle(height, encoded),
                        Err(error) => {
                            tracing::warn!(height, err = %error, "bounded block response read failed");
                            None
                        }
                    }
                })
                .await;
                let bundle = match loaded {
                    Ok(loaded) => loaded,
                    Err(error) => {
                        tracing::warn!(height, err = %error, "block response storage worker failed");
                        None
                    }
                };
                let response = GetRecentBlockResponse {
                    height,
                    bundle,
                    inbound_memory_permit: None,
                    outbound_memory_permit: Some(outbound_memory_permit),
                };
                let _ = completion
                    .send(PendingBlockResponse { channel, response })
                    .await;
            });
        }

        // --- Request-Response: HistoryStep terminal server ---
        SwarmEvent::Behaviour(NodeBehaviourEvent::HistoryStepSync(
            request_response::Event::Message {
                message:
                    request_response::Message::Request {
                        request,
                        channel,
                        request_id,
                    },
                peer,
            },
        )) => {
            tracing::debug!(
                %peer,
                ?request_id,
                height = request.height,
                "received HistoryStep terminal request"
            );
            let Ok(preparation_permit) = history_step_response_prepare_semaphore
                .clone()
                .try_acquire_owned()
            else {
                tracing::warn!(
                    %peer,
                    ?request_id,
                    height = request.height,
                    "HistoryStep response preparation saturated"
                );
                return;
            };
            let chain = chain.clone();
            let budget = outbound_response_budget.clone();
            let completion = history_step_response_tx.clone();
            let request_height = request.height;
            let request_hash = request.block_hash;
            tokio::spawn(async move {
                let _preparation_permit = preparation_permit;
                let Ok(Some(outbound_memory_permit)) = budget
                    .acquire(MAX_OUTBOUND_HISTORY_STEP_RESPONSE_BYTES)
                    .await
                else {
                    return;
                };
                let loaded = tokio::task::spawn_blocking(move || {
                    let ctx = chain.blocking_read();
                    local_history_step_terminal(&ctx, request_height, request_hash)
                })
                .await;
                let terminal_bytes = match loaded {
                    Ok(terminal_bytes) => terminal_bytes,
                    Err(error) => {
                        tracing::warn!(err = %error, "HistoryStep response storage worker failed");
                        None
                    }
                };
                let terminal_len = terminal_bytes.as_ref().map_or(0, Vec::len);
                tracing::debug!(
                    %peer,
                    ?request_id,
                    height = request_height,
                    terminal_len,
                    "prepared HistoryStep terminal response"
                );
                let response = GetHistoryStepTerminalResponse {
                    height: request_height,
                    block_hash: request_hash,
                    terminal_bytes,
                    inbound_memory_permit: None,
                    outbound_memory_permit: Some(outbound_memory_permit),
                };
                if completion
                    .send(PendingHistoryStepTerminalResponse { channel, response })
                    .await
                    .is_err()
                {
                    tracing::warn!(
                        %peer,
                        ?request_id,
                        height = request_height,
                        "HistoryStep response completion queue closed"
                    );
                }
            });
        }

        // --- Request-Response: HistoryStep terminal client ---
        SwarmEvent::Behaviour(NodeBehaviourEvent::HistoryStepSync(
            request_response::Event::Message {
                message: request_response::Message::Response { response, .. },
                peer,
            },
        )) => {
            let inbound_memory_permit = response.inbound_memory_permit.clone();
            let height = response.height;
            let block_hash = response.block_hash;
            let terminal_bytes = response.terminal_bytes.unwrap_or_default();
            tracing::debug!(
                from = %peer,
                terminal_len = terminal_bytes.len(),
                "received HistoryStep terminal from peer"
            );
            let _ = required_event_tx
                .send(NetworkEvent::HistoryStepTerminal {
                    from: peer,
                    height,
                    block_hash,
                    terminal_bytes,
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
                let Some((snapshot_height, snapshot_hash)) = local_history_step_boundary(&ctx)
                else {
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
                let key = (snapshot_height, snapshot_hash);
                if noid_chain::hash_block_header(&snapshot_header) != snapshot_hash {
                    break 'ready_manifest GetStateManifestResponse::default();
                }
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
                let _ = swarm
                    .behaviour_mut()
                    .state_segment_sync
                    .send_response(channel, unavailable_state_segment_response(&request));
                return;
            }
            entry.0 += 1;
            prune_snapshot_exports(snapshot_exports);
            let key = (request.expected_tip_height, request.expected_tip_hash);
            let Some(export) = snapshot_exports.get(&key).cloned() else {
                let _ = swarm
                    .behaviour_mut()
                    .state_segment_sync
                    .send_response(channel, unavailable_state_segment_response(&request));
                return;
            };
            let Some(descriptor) = export.manifest().segment(request.segment_id).copied() else {
                let _ = swarm
                    .behaviour_mut()
                    .state_segment_sync
                    .send_response(channel, unavailable_state_segment_response(&request));
                return;
            };
            let Ok(permit) = segment_encode_semaphore.clone().try_acquire_owned() else {
                let _ = swarm
                    .behaviour_mut()
                    .state_segment_sync
                    .send_response(channel, unavailable_state_segment_response(&request));
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
                let _ = swarm
                    .behaviour_mut()
                    .state_segment_sync
                    .send_response(channel, unavailable_state_segment_response(&request));
                return;
            }
            let requested_tip_height = request.expected_tip_height;
            let requested_tip_hash = request.expected_tip_hash;
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
                        expected_tip_height: requested_tip_height,
                        expected_tip_hash: requested_tip_hash,
                        eff_log: effective_log,
                        data: Some(data),
                        inbound_memory_permit: None,
                        outbound_memory_permit: Some(outbound_memory_permit),
                    },
                    Ok(Err(error)) => {
                        tracing::warn!(segment = descriptor.segment_id, err = %error, "disk snapshot segment read failed");
                        GetStateSegmentResponse {
                            segment_id: descriptor.segment_id,
                            expected_tip_height: requested_tip_height,
                            expected_tip_hash: requested_tip_hash,
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
                            expected_tip_height: requested_tip_height,
                            expected_tip_hash: requested_tip_hash,
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
                message:
                    request_response::Message::Response {
                        request_id,
                        response,
                    },
                peer,
            },
        )) => {
            let Some(pending) = pending_state_segment_requests.remove(&request_id) else {
                tracing::warn!(
                    peer = %peer,
                    request_id = %request_id,
                    segment = response.segment_id,
                    "unknown or delayed state-segment response — dropped"
                );
                return;
            };
            if !state_segment_response_matches_pending(pending, peer, &response) {
                tracing::warn!(
                    peer = %peer,
                    request_id = %request_id,
                    requested_peer = %pending.peer,
                    requested_segment = pending.segment_id,
                    requested_height = pending.expected_tip_height,
                    response_segment = response.segment_id,
                    response_height = response.expected_tip_height,
                    "state-segment response does not match its exact request — dropped"
                );
                fail_peer!(pending.peer);
                return;
            }
            if let Some(ref data) = response.data {
                let Some(expected_len) = encoded_segment_len_for_eff_log(response.eff_log) else {
                    tracing::warn!(peer = %peer, segment = response.segment_id, eff_log = response.eff_log, "segment response has invalid effective segment log — dropped");
                    fail_peer!(pending.peer);
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
                    fail_peer!(pending.peer);
                    return;
                }
                if data.len() > MAX_SEGMENT_BYTES {
                    tracing::warn!(peer = %peer, segment = response.segment_id, len = data.len(), "segment response too large — dropped");
                    fail_peer!(pending.peer);
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
            let Ok(preparation_permit) =
                Arc::clone(mempool_response_prepare_semaphore).try_acquire_owned()
            else {
                // Mempool state is recoverable through gossip and a later sync.
                // Dropping the channel rejects excess preparation without ever
                // stalling the swarm task or cloning payload bytes.
                tracing::debug!(peer = %peer, "mempool sync preparation already occupied");
                return;
            };
            let budget = outbound_response_budget.clone();
            let mempool = mempool.clone();
            let completion = mempool_response_tx.clone();
            tokio::spawn(async move {
                // Reserve the maximum legal response before taking the mempool
                // lock or cloning the first retained intent. The same permit is
                // carried by the response until the codec's final write.
                let response = match prepare_mempool_response_after_admission(budget, || async {
                    mempool
                        .intent_bytes_prefix(
                            MAX_MEMPOOL_SYNC_TXS,
                            MAX_MEMPOOL_SYNC_BYTES,
                            MAX_TX_INTENT_BYTES_GLOBAL,
                        )
                        .await
                })
                .await
                {
                    Ok(response) => response,
                    Err(error) => {
                        tracing::debug!(peer = %peer, err = %error, "mempool sync byte admission failed");
                        return;
                    }
                };
                let total_bytes: usize = response.txs.iter().map(Vec::len).sum();
                tracing::debug!(
                    peer = %peer,
                    tx_count = response.txs.len(),
                    total_bytes,
                    "serving mempool sync request"
                );
                let _preparation_permit = preparation_permit;
                let _ = completion
                    .send(PendingMempoolResponse { channel, response })
                    .await;
            });
        }

        // --- Mempool sync: client side (response to our request) ---
        SwarmEvent::Behaviour(NodeBehaviourEvent::MempoolSync(
            request_response::Event::Message {
                message: request_response::Message::Response { response, .. },
                peer,
            },
        )) => {
            let GetMempoolResponse {
                txs,
                inbound_memory_permit,
                outbound_memory_permit: _,
            } = response;
            if !txs.is_empty() {
                tracing::debug!(
                    from = %peer,
                    tx_count = txs.len(),
                    "received mempool sync response"
                );
                // The fixed codec has already validated all caps. Mempool sync
                // is recoverable, so do not block the swarm if authoritative
                // sync events currently occupy the bounded node queue.
                if let Err(error) = required_event_tx.try_send(NetworkEvent::MempoolSyncResponse {
                    from: peer,
                    txs,
                    inbound_memory_permit,
                }) {
                    tracing::debug!(peer = %peer, err = %error, "mempool sync response dropped under node backpressure");
                }
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
                clear_peer_request_correlations(
                    pending_retained_block_requests,
                    pending_state_segment_requests,
                    peer_id,
                );
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
            request_response::Event::OutboundFailure {
                peer,
                request_id,
                error,
            },
        )) => {
            tracing::debug!(peer = %peer, err = %error, "block sync request failed");
            let correlated = pending_retained_block_requests
                .remove(&request_id)
                .is_some_and(|pending| pending.peer == peer);
            if !correlated {
                tracing::debug!(peer = %peer, request_id = %request_id, "ignoring stale block-sync failure");
                return;
            }
            // Emit a generic disconnect so the sync state machine can retry.
            fail_peer!(peer);
        }

        SwarmEvent::Behaviour(NodeBehaviourEvent::StateManifestSync(
            request_response::Event::OutboundFailure { peer, error, .. },
        )) => {
            tracing::debug!(peer = %peer, err = %error, "manifest sync request failed");
            let _ = gossip_event_tx.send(NetworkEvent::PeerDisconnected(peer));
        }

        SwarmEvent::Behaviour(NodeBehaviourEvent::StateSegmentSync(
            request_response::Event::OutboundFailure {
                peer,
                request_id,
                error,
            },
        )) => {
            tracing::debug!(peer = %peer, err = %error, "segment sync request failed");
            let correlated = pending_state_segment_requests
                .remove(&request_id)
                .is_some_and(|pending| pending.peer == peer);
            if !correlated {
                tracing::debug!(peer = %peer, request_id = %request_id, "ignoring stale segment-sync failure");
                return;
            }
            fail_peer!(peer);
        }

        SwarmEvent::Behaviour(NodeBehaviourEvent::HistoryStepSync(
            request_response::Event::OutboundFailure { peer, error, .. },
        )) => {
            tracing::debug!(peer = %peer, err = %error, "HistoryStep terminal request failed");
        }

        SwarmEvent::Behaviour(NodeBehaviourEvent::HistoryStepSync(
            request_response::Event::InboundFailure {
                peer,
                request_id,
                error,
            },
        )) => {
            tracing::warn!(
                %peer,
                ?request_id,
                err = %error,
                "HistoryStep terminal response failed"
            );
        }

        SwarmEvent::Behaviour(NodeBehaviourEvent::HistoryStepSync(
            request_response::Event::ResponseSent { peer, request_id },
        )) => {
            tracing::debug!(
                %peer,
                ?request_id,
                "HistoryStep terminal response flushed"
            );
        }

        SwarmEvent::NewListenAddr { address, .. } => {
            tracing::debug!(%address, "P2P listening");
        }

        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::*;

    fn accepted_bundle(height: u64, recursive_payload_bytes: usize) -> AcceptedBlockBundle {
        let mut header = noid_chain::consensus::genesis::genesis_header();
        header.height = height;
        let block = noid_chain::Block {
            header,
            transactions: Vec::new(),
        };
        let terminal_len =
            noid_chain::HISTORY_STEP_TERMINAL_BINDING_BYTES + recursive_payload_bytes;
        let mut terminal = Vec::with_capacity(terminal_len);
        terminal.extend_from_slice(&noid_chain::HISTORY_STEP_TERMINAL_VERSION.to_le_bytes());
        terminal.extend_from_slice(&height.to_le_bytes());
        terminal.extend_from_slice(&noid_chain::block_header::semantic_header_id(&block.header));
        terminal.resize(terminal_len, 1);
        AcceptedBlockBundle::try_from_parts(block.to_bytes(), terminal).unwrap()
    }

    #[test]
    fn inline_policy_counts_the_complete_bundle_and_announcement() {
        assert!(should_inline_accepted_block_bundle(&accepted_bundle(1, 1)));
        assert!(!should_inline_accepted_block_bundle(&accepted_bundle(
            1,
            MAX_HISTORY_STEP_TERMINAL_BYTES - noid_chain::HISTORY_STEP_TERMINAL_BINDING_BYTES,
        )));
    }

    #[test]
    fn snapshot_terminal_serving_requires_retained_suffix() {
        let retention = noid_chain::consensus::params::RECENT_BLOCK_RETENTION_DEPTH;
        assert!(snapshot_suffix_is_retained(100, 100));
        assert!(snapshot_suffix_is_retained(100, 100 - retention));
        assert!(!snapshot_suffix_is_retained(100, 100 - retention - 1));
        assert!(!snapshot_suffix_is_retained(100, 101));
    }

    #[test]
    fn stored_bundle_decode_is_all_or_none_and_height_bound() {
        let bundle = accepted_bundle(77, 1);
        assert_eq!(
            decode_stored_accepted_block_bundle(77, Some(bundle.encode())),
            Some(bundle.clone())
        );
        assert!(decode_stored_accepted_block_bundle(78, Some(bundle.encode())).is_none());
        assert!(decode_stored_accepted_block_bundle(77, Some(vec![1, 2, 3])).is_none());
    }

    #[test]
    fn retained_block_transport_rejects_unknown_peer_height_and_replay() {
        let peer = PeerId::random();
        let other_peer = PeerId::random();
        let pending = PendingRetainedBlockRequest { peer, height: 77 };
        assert!(retained_block_response_matches_pending(pending, peer, 77));
        assert!(!retained_block_response_matches_pending(
            pending, other_peer, 77
        ));
        assert!(!retained_block_response_matches_pending(pending, peer, 78));

        let mut registry = BoundedPendingRequests::new(2);
        assert!(registry.try_insert(10u64, pending));
        assert!(registry.try_insert(11, PendingRetainedBlockRequest { peer, height: 78 }));
        assert!(!registry.try_insert(12, PendingRetainedBlockRequest { peer, height: 79 }));
        assert_eq!(registry.len(), 2);
        assert!(
            registry.remove(&999).is_none(),
            "unknown delayed ID is inert"
        );
        assert_eq!(registry.remove(&10), Some(pending));
        assert!(
            registry.remove(&10).is_none(),
            "one request ID is single-use"
        );
        assert!(registry.try_insert(12, PendingRetainedBlockRequest { peer, height: 79 }));
        registry.retain(|_, entry| entry.peer != peer);
        assert_eq!(registry.len(), 0, "disconnect clears peer-owned requests");

        let (failure_tx, mut failure_rx) = tokio::sync::broadcast::channel(1);
        notify_outbound_request_failed(&failure_tx, peer);
        assert!(matches!(
            failure_rx.try_recv(),
            Ok(NetworkEvent::PeerDisconnected(failed_peer)) if failed_peer == peer
        ));
    }

    #[test]
    fn state_segment_transport_rejects_same_peer_cross_session_response() {
        let peer = PeerId::random();
        let old = PendingStateSegmentRequest {
            peer,
            segment_id: 7,
            expected_tip_height: 144,
            expected_tip_hash: [0xA5; 32],
        };
        let response = GetStateSegmentResponse {
            segment_id: 7,
            expected_tip_height: 144,
            expected_tip_hash: [0xA5; 32],
            eff_log: 0,
            data: None,
            inbound_memory_permit: None,
            outbound_memory_permit: None,
        };
        assert!(state_segment_response_matches_pending(old, peer, &response));

        let new_session = PendingStateSegmentRequest {
            expected_tip_height: 145,
            expected_tip_hash: [0x5A; 32],
            ..old
        };
        assert!(!state_segment_response_matches_pending(
            new_session,
            peer,
            &response
        ));
        assert!(!state_segment_response_matches_pending(
            old,
            PeerId::random(),
            &response
        ));

        let mut registry = BoundedPendingRequests::new(2);
        assert!(registry.try_insert(1u64, old));
        assert!(registry.try_insert(
            2,
            PendingStateSegmentRequest {
                segment_id: 8,
                ..old
            }
        ));
        registry.retain(|_, pending| {
            pending.peer == new_session.peer
                && pending.expected_tip_height == new_session.expected_tip_height
                && pending.expected_tip_hash == new_session.expected_tip_hash
        });
        assert_eq!(registry.len(), 0, "new snapshot session retires old IDs");
        assert!(registry.try_insert(3, new_session));

        let request = GetStateSegmentRequest {
            segment_id: 9,
            expected_tip_height: 200,
            expected_tip_hash: [0xCC; 32],
        };
        let unavailable = unavailable_state_segment_response(&request);
        assert_eq!(unavailable.segment_id, request.segment_id);
        assert_eq!(unavailable.expected_tip_height, request.expected_tip_height);
        assert_eq!(unavailable.expected_tip_hash, request.expected_tip_hash);
    }

    #[test]
    fn header_batch_rejects_partial_decode_noncontiguity_and_broken_links() {
        let mut first = noid_chain::consensus::genesis::genesis_header();
        first.height = 77;
        let mut second = first;
        second.height = 78;
        second.prev_block_hash = noid_chain::hash_block_header(&first);
        let valid =
            decode_linked_header_batch(vec![first.to_bytes().to_vec(), second.to_bytes().to_vec()])
                .unwrap();
        assert_eq!(valid.len(), 2);

        let mut skipped = second;
        skipped.height = 79;
        assert_eq!(
            decode_linked_header_batch(vec![
                first.to_bytes().to_vec(),
                skipped.to_bytes().to_vec(),
            ]),
            Err("header batch is not height-contiguous")
        );

        let mut wrong_parent = second;
        wrong_parent.prev_block_hash[0] ^= 1;
        assert_eq!(
            decode_linked_header_batch(vec![
                first.to_bytes().to_vec(),
                wrong_parent.to_bytes().to_vec(),
            ]),
            Err("header batch is not hash-linked")
        );
        assert_eq!(
            decode_linked_header_batch(vec![vec![0; noid_chain::BLOCK_HEADER_WIRE_SIZE - 1]]),
            Err("noncanonical header length")
        );
    }

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn canonical_wire_caps_are_ordered() {
        assert!(MAX_TX_INTENT_BYTES_GLOBAL < INLINE_BLOCK_GOSSIP_THRESHOLD);
        assert!(MAX_MEMPOOL_SYNC_BYTES >= MAX_TX_INTENT_BYTES_GLOBAL);
        assert!(MAX_ACCEPTED_BLOCK_BUNDLE_BYTES > INLINE_BLOCK_GOSSIP_THRESHOLD);
        assert!(MAX_HISTORY_STEP_TERMINAL_BYTES < MAX_ACCEPTED_BLOCK_BUNDLE_BYTES);
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
            let mut header = noid_chain::consensus::genesis_header();
            header.height = height;
            gossip_tx
                .send(NetworkEvent::BlockAnnouncement { from: peer, header })
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

    #[tokio::test]
    async fn mempool_serving_admits_bytes_before_invoking_payload_source() {
        let budget = OutboundResponseBudget::with_capacity(MAX_MEMPOOL_SYNC_BYTES);
        let source_invoked = Arc::new(AtomicBool::new(false));
        let observed_budget = budget.clone();
        let observed_source = source_invoked.clone();
        let response =
            prepare_mempool_response_after_admission(budget.clone(), move || async move {
                assert_eq!(observed_budget.available_bytes(), 0);
                observed_source.store(true, Ordering::SeqCst);
                vec![vec![0xA5]]
            })
            .await
            .unwrap();

        assert!(source_invoked.load(Ordering::SeqCst));
        assert_eq!(budget.available_bytes(), 0);
        drop(response);
        assert_eq!(budget.available_bytes(), MAX_MEMPOOL_SYNC_BYTES);
    }
}
