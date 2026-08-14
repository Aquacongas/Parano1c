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
    dcutr, gossipsub, identify, kad, mdns, relay, request_response, swarm::SwarmEvent, Multiaddr,
    PeerId,
};
use rand::seq::SliceRandom;
use tokio::sync::{mpsc, OwnedSemaphorePermit, RwLock, Semaphore};

use noid_chain::consensus::wire_limits::{
    MAX_BLOCK_BYTES, MAX_HISTORY_STEP_TERMINAL_BYTES, MAX_MEMPOOL_SYNC_BYTES, MAX_MEMPOOL_SYNC_TXS,
    MAX_SEGMENT_BYTES, MAX_SNAPSHOT_MANIFEST_SEGMENTS, MAX_TX_INTENT_BYTES_GLOBAL,
};
use noid_chain::storage::{
    encoded_segment_live_count_from_len, max_encoded_segment_len_for_eff_log, MdbxChainContext,
    MdbxStore,
};
use noid_chain::storage::{
    export_snapshot_boundary_generation, open_snapshot_generation, SnapshotGeneration,
};
use noid_chain::{AcceptedBlockBundle, MAX_ACCEPTED_BLOCK_BUNDLE_BYTES};
use noid_mempool::AsyncMempool;

use crate::behaviour::{NodeBehaviour, NodeBehaviourEvent};
use crate::event_dispatch::{self, RequiredEventReceiver, RequiredEventSender};
use crate::header_protocol::{HeaderAnnouncement, HeaderInventoryRecord, ProviderFlags};
use crate::network_profile::{NetworkProfile, NetworkProfileRequest, NetworkProfileResponse};
use crate::object_protocol::{GetObjectsRequest, GetObjectsResponse, ObjectId, ObjectPayload};
use crate::outbound_budget::OutboundResponseBudget;
use crate::peer_diversity::{PeerDiversity, PublicNetworkGroup};
use crate::protocol::{
    GetHeadersResponse, GetHistoryStepTerminalResponse, GetMempoolResponse, GetRecentBlockResponse,
    GetStateManifestResponse, GetStateSegmentRequest, GetStateSegmentResponse, MempoolRequest,
    NetworkTopics, RecentBlockPayload, RecentBlockPayloadKind, MAX_BLOCK_BODY_BATCH,
};

struct PendingStateSegmentResponse {
    channel: request_response::ResponseChannel<GetStateSegmentResponse>,
    response: GetStateSegmentResponse,
}

struct PendingBlockResponse {
    channel: request_response::ResponseChannel<GetRecentBlockResponse>,
    response: GetRecentBlockResponse,
}

struct PendingHeaderResponse {
    channel: request_response::ResponseChannel<GetHeadersResponse>,
    response: GetHeadersResponse,
}

struct PendingHistoryStepTerminalResponse {
    channel: request_response::ResponseChannel<GetHistoryStepTerminalResponse>,
    response: GetHistoryStepTerminalResponse,
}

struct PendingMempoolResponse {
    channel: request_response::ResponseChannel<GetMempoolResponse>,
    response: GetMempoolResponse,
}

struct PendingObjectResponse {
    channel: request_response::ResponseChannel<GetObjectsResponse>,
    response: GetObjectsResponse,
}

/// Fair admission shared by proof, body and State serving. Header/profile
/// traffic deliberately bypasses it, so bulk clients cannot occupy the
/// control plane. One peer may hold at most two of eight active data slots.
struct DataPlaneServingAdmission {
    global: Arc<Semaphore>,
    global_outstanding: Arc<Semaphore>,
    peers: std::collections::HashMap<PeerId, Arc<PeerDataPlaneSlots>>,
}

struct PeerDataPlaneSlots {
    active: Arc<Semaphore>,
    outstanding: Arc<Semaphore>,
}

struct DataPlaneServingLease {
    global: Arc<Semaphore>,
    peer: Arc<PeerDataPlaneSlots>,
    outstanding: Vec<OwnedSemaphorePermit>,
}

impl DataPlaneServingLease {
    async fn acquire(self) -> Result<Vec<OwnedSemaphorePermit>, ()> {
        // Take the per-peer slot first. At most two requests from one identity
        // can therefore enter the global FIFO, even if that peer fills every
        // request-response stream on every bulk protocol.
        let peer = Arc::clone(&self.peer.active)
            .acquire_owned()
            .await
            .map_err(|_| ())?;
        let global = self.global.acquire_owned().await.map_err(|_| ())?;
        let mut permits = self.outstanding;
        permits.push(peer);
        permits.push(global);
        Ok(permits)
    }
}

impl DataPlaneServingAdmission {
    const GLOBAL_SLOTS: usize = 8;
    const PER_PEER_SLOTS: usize = 2;
    const GLOBAL_OUTSTANDING: usize = 64;
    const PER_PEER_OUTSTANDING: usize = 4;

    fn new() -> Self {
        Self {
            global: Arc::new(Semaphore::new(Self::GLOBAL_SLOTS)),
            global_outstanding: Arc::new(Semaphore::new(Self::GLOBAL_OUTSTANDING)),
            peers: std::collections::HashMap::new(),
        }
    }

    fn lease(&mut self, peer: PeerId) -> Option<DataPlaneServingLease> {
        let peer_slots = self
            .peers
            .entry(peer)
            .or_insert_with(|| {
                Arc::new(PeerDataPlaneSlots {
                    active: Arc::new(Semaphore::new(Self::PER_PEER_SLOTS)),
                    outstanding: Arc::new(Semaphore::new(Self::PER_PEER_OUTSTANDING)),
                })
            })
            .clone();
        let peer_outstanding = Arc::clone(&peer_slots.outstanding)
            .try_acquire_owned()
            .ok()?;
        let global_outstanding = Arc::clone(&self.global_outstanding)
            .try_acquire_owned()
            .ok()?;
        Some(DataPlaneServingLease {
            global: Arc::clone(&self.global),
            peer: peer_slots,
            outstanding: vec![peer_outstanding, global_outstanding],
        })
    }

    fn prune(&mut self, connected: impl Fn(&PeerId) -> bool) {
        self.peers
            .retain(|peer, slots| connected(peer) || Arc::strong_count(slots) > 1);
    }

    fn active_slots(&self) -> usize {
        Self::GLOBAL_SLOTS.saturating_sub(self.global.available_permits())
    }

    fn outstanding_slots(&self) -> usize {
        Self::GLOBAL_OUTSTANDING.saturating_sub(self.global_outstanding.available_permits())
    }
}

#[derive(Clone, Copy, Debug)]
struct PendingNetworkProfileRequest {
    peer: PeerId,
    issued_at: Instant,
}

#[derive(Clone, Debug)]
struct PendingObjectRequest {
    token: u64,
    peer: PeerId,
    objects: Vec<ObjectId>,
    issued_at: Instant,
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
struct SnapshotExportEntry {
    generation: SnapshotGeneration,
    network_manifest: GetStateManifestResponse,
}

impl SnapshotExportEntry {
    fn new(generation: SnapshotGeneration) -> Option<Self> {
        let manifest = generation.manifest();
        if manifest.bridge_tip_height != manifest.target_height
            || manifest.bridge_tip_hash != manifest.target_hash
            || manifest.bridge_cumulative_chainwork != manifest.cumulative_chainwork
        {
            return None;
        }
        let mut network_manifest = GetStateManifestResponse {
            tip_height: manifest.target_height,
            tip_hash: manifest.target_hash,
            cumulative_chainwork: manifest.cumulative_chainwork,
            format_version: crate::protocol::SNAPSHOT_MANIFEST_FORMAT_VERSION,
            state_root: manifest.state_root,
            manifest_digest: [0; 32],
            log_slots: manifest.log_slots,
            active_slot_count: manifest.active_slot_count,
            alloc_counter: manifest.alloc_counter,
            eff_log: manifest.effective_log_segment_size,
            bridge_tip_height: manifest.bridge_tip_height,
            bridge_tip_hash: manifest.bridge_tip_hash,
            bridge_cumulative_chainwork: manifest.bridge_cumulative_chainwork,
            segment_ids: manifest
                .segments
                .iter()
                .map(|segment| segment.segment_id)
                .collect(),
            segment_roots: manifest
                .segments
                .iter()
                .map(|segment| segment.segment_root)
                .collect(),
            segment_lengths: manifest
                .segments
                .iter()
                .map(|segment| segment.encoded_len)
                .collect(),
        };
        network_manifest.seal_manifest_digest().then_some(Self {
            generation,
            network_manifest,
        })
    }
}

impl std::ops::Deref for SnapshotExportEntry {
    type Target = SnapshotGeneration;

    fn deref(&self) -> &Self::Target {
        &self.generation
    }
}

type SnapshotExport = Arc<SnapshotExportEntry>;

const MAX_SNAPSHOT_EXPORTS: usize = 2;
const SNAPSHOT_EXPORT_LEASE_TTL: Duration = Duration::from_secs(15 * 60);
/// All honest exporters use the same finalized height buckets. Their cached
/// manifests therefore have a source-independent identity and a client can
/// rotate individual State objects across peers. Six blocks add at most five
/// blocks to the ordinary 18-block finalized lag and remain inside undo and
/// retained-payload windows.
const SNAPSHOT_BOUNDARY_INTERVAL: u64 = 6;
const _: () = assert!(SNAPSHOT_BOUNDARY_INTERVAL > 0);
const _: () =
    assert!(SNAPSHOT_BOUNDARY_INTERVAL <= noid_chain::consensus::params::CONSENSUS_FINALITY_DEPTH);
/// Keep six blocks of serving reserve beyond the largest suffix admitted from
/// a cached immutable State boundary. The current retention policy preserves
/// 42 exact bodies, so a fresh finalized boundary starts 18 blocks behind the
/// live tip and remains useful without racing the payload pruner.
const SNAPSHOT_BOUNDARY_MAX_LIVE_GAP: u64 =
    noid_chain::consensus::params::RETAINED_BLOCK_SERVING_DEPTH - 6;
const MAX_OUTBOUND_BLOCK_RESPONSE_BYTES: usize = MAX_ACCEPTED_BLOCK_BUNDLE_BYTES;
const MAX_OUTBOUND_BLOCK_BODY_BATCH_BYTES: usize =
    (MAX_BLOCK_BYTES + 4) * MAX_BLOCK_BODY_BATCH as usize;
const MAX_OUTBOUND_BLOCK_BODY_BATCH_RESERVATION: usize =
    MAX_OUTBOUND_BLOCK_BODY_BATCH_BYTES + 2 * MAX_ACCEPTED_BLOCK_BUNDLE_BYTES;
const MAX_OUTBOUND_HISTORY_STEP_RESPONSE_BYTES: usize = MAX_HISTORY_STEP_TERMINAL_BYTES;
const MAX_PENDING_RETAINED_BLOCK_REQUESTS: usize = 256;
const MAX_PENDING_NETWORK_PROFILE_REQUESTS: usize = 256;
const MAX_PENDING_OBJECT_REQUESTS: usize = 64;
const MAX_PENDING_HEADER_REQUESTS: usize = 64;
const MAX_PENDING_STATE_MANIFEST_REQUESTS: usize = 16;
const MAX_PENDING_STATE_SEGMENT_REQUESTS: usize = 64;
const MAX_PENDING_HISTORY_STEP_REQUESTS: usize = 8;
/// The request-response transport timeout starts only after substream open.
/// These complete-local deadlines also cover time queued before that point.
const SMALL_SYNC_PENDING_DEADLINE: Duration = Duration::from_secs(35);
const NETWORK_PROFILE_PENDING_DEADLINE: Duration = Duration::from_secs(15);
const OBJECT_PENDING_DEADLINE: Duration = Duration::from_secs(65);
const STATE_SEGMENT_PENDING_DEADLINE: Duration = Duration::from_secs(65);
/// libp2p starts its request timeout only after an outbound substream opens.
/// Bound the complete local lifetime as well, including time spent waiting in
/// the stream-capacity queue.
const HISTORY_STEP_PENDING_DEADLINE: Duration = Duration::from_secs(65);
/// In a small network, direct-push to every connected peer so an edge wallet
/// cannot depend on an already-formed gossipsub mesh to reach the miner.
const TX_DIRECT_SMALL_NETWORK_MAX_PEERS: usize = 8;
/// At scale gossipsub remains primary, while a constant direct fanout gives
/// every newly admitted transaction independent first-hop paths without
/// flooding all connections.
const TX_DIRECT_LARGE_NETWORK_FANOUT: usize = 4;
const TX_RELAY_RATE_WINDOW: Duration = Duration::from_secs(10);
const TX_RELAY_RATE_MAX: u32 = 50;
/// Raw GossipSub payloads accepted for propagation in one fixed window.
/// GossipSub retains accepted messages for several heartbeats. Bounding bytes
/// globally, in addition to the per-peer event count, prevents a Sybil set of
/// individually compliant peers from filling that cache with proof-sized
/// competing blocks. 64 MiB per ten seconds is orders of magnitude above the
/// honest 15-second block and bounded transaction workload.
const GOSSIP_ACCEPT_WINDOW: Duration = Duration::from_secs(10);
const GOSSIP_ACCEPT_BYTES_PER_WINDOW: usize = 64 * 1024 * 1024;
const AUTOMATIC_OUTBOUND_TARGET: usize = 12;
// The shipped topology contains four individual DNS seeds. Probe all of them
// when necessary, but leave room in the global pending table for ordinary
// peers learned through Kademlia.
const MAX_PENDING_BOOTSTRAP_DIALS: usize = 4;
const MAX_UNCONFIRMED_AUTOMATIC_CONNECTIONS: usize =
    AUTOMATIC_OUTBOUND_TARGET + MAX_PENDING_BOOTSTRAP_DIALS + 1;
// Twelve peers may legitimately use two relay/direct paths each. Keep room
// for those paths while bounding all automatic transports well below the
// swarm's 64 established-outbound ceiling.
const MAX_AUTOMATIC_TRANSPORT_OCCUPANCY: usize = 32;
// The swarm itself admits at most 32 pending outbound transports.
const _: () = assert!(MAX_UNCONFIRMED_AUTOMATIC_CONNECTIONS <= 32);
// Mining requires two independently confirming authenticated peers, and most
// GUI nodes discovered through Kademlia are not publicly dialable through
// their NAT. Keep two bootstrap transports until stable ordinary peers replace
// them one-for-one. This preserves the mining quorum without pinning clients
// to every public seed.
const INITIAL_BOOTSTRAP_FANOUT: usize = 2;
const MAX_AUTOMATIC_PEER_CANDIDATES: usize = 512;
const MAX_AUTOMATIC_ADDRS_PER_PEER: usize = 8;
const AUTOMATIC_PEER_HEALTHY_AFTER: Duration = Duration::from_secs(30);
const DISCOVERY_RETRY_MIN: Duration = Duration::from_secs(10);
const DISCOVERY_RETRY_MAX: Duration = Duration::from_secs(5 * 60);

fn direct_tx_relay_limit(connected_peers: usize) -> usize {
    if connected_peers <= TX_DIRECT_SMALL_NETWORK_MAX_PEERS {
        connected_peers
    } else {
        connected_peers.min(TX_DIRECT_LARGE_NETWORK_FANOUT)
    }
}

#[derive(Clone, Debug)]
struct BootstrapCandidate {
    peer: Option<PeerId>,
    failures: u8,
    next_attempt: Instant,
}

#[derive(Clone, Debug)]
struct AutomaticPeerCandidate {
    addrs: Vec<Multiaddr>,
    failures: u8,
    next_attempt: Instant,
    last_seen: Instant,
}

#[derive(Clone, Copy, Debug)]
struct SyncPath {
    peer: PeerId,
    direct: bool,
    dialer: bool,
    identified: bool,
    closing: bool,
}

/// Mirrors every connection visible to request-response and exposes only
/// peers for which arbitrary per-peer connection selection is safe.
///
/// libp2p request-response distributes requests across every established
/// connection for one PeerId. A second direct connection must therefore be
/// collapsed before the node issues another sync request. Relay and direct
/// paths may coexist during a DCUtR upgrade.
#[derive(Default)]
struct PeerSyncPaths {
    paths: std::collections::HashMap<libp2p::swarm::ConnectionId, SyncPath>,
    announced: std::collections::HashSet<PeerId>,
    profile_verified: std::collections::HashSet<PeerId>,
}

impl PeerSyncPaths {
    fn insert(
        &mut self,
        connection_id: libp2p::swarm::ConnectionId,
        peer: PeerId,
        direct: bool,
        dialer: bool,
    ) {
        let previous = self.paths.insert(
            connection_id,
            SyncPath {
                peer,
                direct,
                dialer,
                identified: false,
                closing: false,
            },
        );
        debug_assert!(previous.is_none(), "libp2p connection IDs are unique");
    }

    /// Select one canonical direct path and return exact connections to close.
    fn canonicalize_direct(
        &mut self,
        local: PeerId,
        peer: PeerId,
        new_connection: libp2p::swarm::ConnectionId,
    ) -> Vec<libp2p::swarm::ConnectionId> {
        let Some(new_path) = self.paths.get(&new_connection).copied() else {
            return Vec::new();
        };
        if !new_path.direct || new_path.closing {
            return Vec::new();
        }

        let existing = self
            .paths
            .iter()
            .filter_map(|(connection_id, path)| {
                (*connection_id != new_connection
                    && path.peer == peer
                    && path.direct
                    && !path.closing)
                    .then_some((*connection_id, *path))
            })
            .collect::<Vec<_>>();
        if existing.is_empty() {
            return Vec::new();
        }

        let has_dialer = new_path.dialer || existing.iter().any(|(_, path)| path.dialer);
        let has_listener = !new_path.dialer || existing.iter().any(|(_, path)| !path.dialer);
        let losers = if has_dialer && has_listener {
            // Opposite-direction cross-dials must retain the same physical
            // path at both endpoints even if Identify completes in a different
            // order. PeerId ordering makes that choice independent of local
            // ConnectionIds, arrival order and handshake speed.
            let prefer_dialer = local.to_bytes() < peer.to_bytes();
            if new_path.dialer == prefer_dialer {
                existing
                    .iter()
                    .filter_map(|(connection_id, path)| {
                        (path.dialer != prefer_dialer).then_some(*connection_id)
                    })
                    .collect()
            } else if existing
                .iter()
                .any(|(_, path)| path.dialer == prefer_dialer)
            {
                vec![new_connection]
            } else {
                Vec::new()
            }
        } else if existing.iter().any(|(_, path)| path.identified) {
            // For same-direction duplicates, preserve an already usable path.
            // This is the common cached-peer plus unresolved-DNS case.
            vec![new_connection]
        } else if has_dialer {
            // Repeated outbound DNS dials have one owner. Keep the path that
            // was already established and close the new duplicate.
            vec![new_connection]
        } else {
            // Repeated inbound paths are resolved by their remote dialer.
            // Until its close arrives, two direct paths keep this peer
            // non-dispatchable.
            Vec::new()
        };

        for connection_id in &losers {
            if let Some(path) = self.paths.get_mut(connection_id) {
                path.closing = true;
            }
        }
        losers
    }

    fn mark_identified(&mut self, connection_id: libp2p::swarm::ConnectionId) {
        if let Some(path) = self.paths.get_mut(&connection_id) {
            path.identified = true;
        }
    }

    fn mark_closing(&mut self, connection_id: libp2p::swarm::ConnectionId) {
        if let Some(path) = self.paths.get_mut(&connection_id) {
            path.closing = true;
        }
    }

    fn is_closing(&self, connection_id: libp2p::swarm::ConnectionId) -> bool {
        self.paths
            .get(&connection_id)
            .is_some_and(|path| path.closing)
    }

    fn remove(&mut self, connection_id: libp2p::swarm::ConnectionId) -> Option<PeerId> {
        self.paths.remove(&connection_id).map(|path| path.peer)
    }

    fn has_identified_path(&self, peer: PeerId) -> bool {
        self.paths
            .values()
            .any(|path| path.peer == peer && path.identified && !path.closing)
    }

    fn is_dispatchable(&self, peer: PeerId) -> bool {
        if !self.profile_verified.contains(&peer) {
            return false;
        }
        let paths = self
            .paths
            .values()
            .filter(|path| path.peer == peer)
            .collect::<Vec<_>>();
        if paths.is_empty() || paths.iter().any(|path| !path.identified || path.closing) {
            return false;
        }
        paths.iter().filter(|path| path.direct).count() <= 1
    }

    fn try_mark_announced(&mut self, peer: PeerId) -> bool {
        self.is_dispatchable(peer) && self.announced.insert(peer)
    }

    fn mark_profile_verified(&mut self, peer: PeerId) {
        self.profile_verified.insert(peer);
    }

    fn clear_profile_verified(&mut self, peer: PeerId) {
        self.profile_verified.remove(&peer);
    }

    fn is_announced(&self, peer: PeerId) -> bool {
        self.announced.contains(&peer)
    }

    fn clear_announced(&mut self, peer: PeerId) {
        self.announced.remove(&peer);
    }

    fn dispatchable_peer_count(&self) -> usize {
        self.paths
            .values()
            .map(|path| path.peer)
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .filter(|peer| self.is_dispatchable(*peer))
            .count()
    }
}

#[derive(Clone, Debug)]
enum PendingAutomaticDial {
    Bootstrap(Multiaddr),
    Peer {
        peer: PeerId,
        group: PublicNetworkGroup,
    },
}

#[derive(Clone, Debug)]
enum ManagedOutboundKind {
    Bootstrap(Multiaddr),
    Peer,
}

#[derive(Clone, Debug)]
struct ManagedOutboundConnection {
    peer: PeerId,
    kind: ManagedOutboundKind,
    established_at: Instant,
    identified: bool,
}

struct AutomaticPeerState {
    bootstrap: std::collections::HashMap<Multiaddr, BootstrapCandidate>,
    peers: std::collections::HashMap<PeerId, AutomaticPeerCandidate>,
    pending: std::collections::HashMap<libp2p::swarm::ConnectionId, PendingAutomaticDial>,
    /// Every outbound transport, including short Kademlia sessions.
    /// These are useful for DNS classification and duplicate suppression but
    /// do not count toward the maintained neighbour target by themselves.
    outbound_connections: std::collections::HashMap<libp2p::swarm::ConnectionId, PeerId>,
    managed_connections:
        std::collections::HashMap<libp2p::swarm::ConnectionId, ManagedOutboundConnection>,
    outbound_counts: std::collections::HashMap<PeerId, usize>,
    bootstrap_complete: bool,
    kad_bootstrap_started: bool,
    kad_bootstrap_query: Option<kad::QueryId>,
    retry_salt: Vec<u8>,
    discovery_query: Option<kad::QueryId>,
    discovery_learned: bool,
    discovery_failures: u8,
    next_discovery_at: Instant,
}

impl AutomaticPeerState {
    fn new(local_peer: PeerId) -> Self {
        Self {
            bootstrap: std::collections::HashMap::new(),
            peers: std::collections::HashMap::new(),
            pending: std::collections::HashMap::new(),
            outbound_connections: std::collections::HashMap::new(),
            managed_connections: std::collections::HashMap::new(),
            outbound_counts: std::collections::HashMap::new(),
            bootstrap_complete: false,
            kad_bootstrap_started: false,
            kad_bootstrap_query: None,
            retry_salt: local_peer.to_bytes(),
            discovery_query: None,
            discovery_learned: false,
            discovery_failures: 0,
            next_discovery_at: Instant::now(),
        }
    }

    fn register_bootstrap(&mut self, addr: Multiaddr) {
        self.bootstrap.entry(addr).or_insert(BootstrapCandidate {
            peer: None,
            failures: 0,
            next_attempt: Instant::now(),
        });
    }

    fn add_peer_candidate(
        &mut self,
        local: PeerId,
        peer: PeerId,
        addrs: impl IntoIterator<Item = Multiaddr>,
    ) -> bool {
        if peer == local || self.is_bootstrap_peer(peer) {
            return false;
        }
        let mut accepted = addrs
            .into_iter()
            .filter_map(|addr| sanitize_automatic_peer_addr(peer, addr))
            .collect::<Vec<_>>();
        accepted.sort_unstable_by(|a, b| a.to_string().cmp(&b.to_string()));
        accepted.dedup();
        if accepted.is_empty() {
            return false;
        }
        if !self.peers.contains_key(&peer) && self.peers.len() >= MAX_AUTOMATIC_PEER_CANDIDATES {
            let pending = self
                .pending
                .values()
                .filter_map(|dial| match dial {
                    PendingAutomaticDial::Peer { peer, .. } => Some(*peer),
                    PendingAutomaticDial::Bootstrap(_) => None,
                })
                .collect::<std::collections::HashSet<_>>();
            let evict = self
                .peers
                .iter()
                .filter(|(candidate, _)| {
                    !self.outbound_counts.contains_key(candidate) && !pending.contains(candidate)
                })
                .min_by_key(|(_, candidate)| candidate.last_seen)
                .map(|(candidate, _)| *candidate);
            if let Some(evict) = evict {
                self.peers.remove(&evict);
            }
            if self.peers.len() >= MAX_AUTOMATIC_PEER_CANDIDATES {
                return false;
            }
        }
        let now = Instant::now();
        let candidate = self.peers.entry(peer).or_insert(AutomaticPeerCandidate {
            addrs: Vec::new(),
            failures: 0,
            next_attempt: now,
            last_seen: now,
        });
        candidate.last_seen = now;
        let mut changed = false;
        for addr in accepted {
            if candidate.addrs.contains(&addr) {
                continue;
            }
            if candidate.addrs.len() == MAX_AUTOMATIC_ADDRS_PER_PEER {
                candidate.addrs.remove(0);
            }
            candidate.addrs.push(addr);
            changed = true;
        }
        changed
    }

    fn outbound_peer_count(&self) -> usize {
        self.managed_connections
            .values()
            .filter_map(|connection| connection.identified.then_some(connection.peer))
            .collect::<std::collections::HashSet<_>>()
            .len()
    }

    fn is_outbound(&self, peer: PeerId) -> bool {
        self.outbound_connections
            .values()
            .any(|known| *known == peer)
    }

    fn bootstrap_peer_ids(&self) -> std::collections::HashSet<PeerId> {
        self.bootstrap
            .values()
            .filter_map(|candidate| candidate.peer)
            .collect()
    }

    fn is_bootstrap_peer(&self, peer: PeerId) -> bool {
        self.bootstrap
            .values()
            .any(|candidate| candidate.peer == Some(peer))
    }

    fn connected_bootstrap_peer_ids(&self) -> Vec<PeerId> {
        let bootstrap_peers = self.bootstrap_peer_ids();
        self.managed_connections
            .values()
            .filter_map(|connection| {
                (connection.identified && bootstrap_peers.contains(&connection.peer))
                    .then_some(connection.peer)
            })
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect()
    }

    fn stable_non_bootstrap_peer_count(&self, now: Instant) -> usize {
        let bootstrap_peers = self.bootstrap_peer_ids();
        self.managed_connections
            .values()
            .filter_map(|connection| {
                (!bootstrap_peers.contains(&connection.peer)
                    && matches!(connection.kind, ManagedOutboundKind::Peer)
                    && connection.identified
                    && now.duration_since(connection.established_at)
                        >= AUTOMATIC_PEER_HEALTHY_AFTER)
                    .then_some(connection.peer)
            })
            .collect::<std::collections::HashSet<_>>()
            .len()
    }

    fn note_connection_established(
        &mut self,
        connection_id: libp2p::swarm::ConnectionId,
        peer: PeerId,
        outbound: bool,
    ) {
        let pending = self.pending.remove(&connection_id);
        let managed_kind = match pending {
            Some(pending) => match pending {
                PendingAutomaticDial::Bootstrap(addr) => {
                    if let Some(candidate) = self.bootstrap.get_mut(&addr) {
                        candidate.peer = Some(peer);
                    }
                    Some(ManagedOutboundKind::Bootstrap(addr))
                }
                PendingAutomaticDial::Peer { peer: expected, .. } if expected == peer => {
                    Some(ManagedOutboundKind::Peer)
                }
                PendingAutomaticDial::Peer { .. } => None,
            },
            None => self.bootstrap.iter().find_map(|(addr, candidate)| {
                (candidate.peer == Some(peer)).then(|| ManagedOutboundKind::Bootstrap(addr.clone()))
            }),
        };
        if matches!(&managed_kind, Some(ManagedOutboundKind::Bootstrap(_))) {
            // A seed may already exist in the successful-peer cache from an
            // earlier release. Once its identity is learned through an
            // explicit bootstrap dial, it must no longer compete for an
            // ordinary neighbour slot.
            self.peers.remove(&peer);
        }
        if outbound {
            self.outbound_connections.insert(connection_id, peer);
            let managed_kind = managed_kind.or_else(|| {
                self.peers
                    .contains_key(&peer)
                    .then_some(ManagedOutboundKind::Peer)
            });
            if let Some(kind) = managed_kind {
                // Keep up to the transport's two-path hard limit. A second
                // connection may be the direct half of an active relay→DCUtR
                // upgrade, so blindly closing every duplicate PeerId here
                // would strand NATed wallets on the relay path.
                self.track_managed_connection(connection_id, peer, kind);
            }
        }
    }

    fn track_managed_connection(
        &mut self,
        connection_id: libp2p::swarm::ConnectionId,
        peer: PeerId,
        kind: ManagedOutboundKind,
    ) {
        if self.managed_connections.contains_key(&connection_id) {
            return;
        }
        self.managed_connections.insert(
            connection_id,
            ManagedOutboundConnection {
                peer,
                kind,
                established_at: Instant::now(),
                identified: false,
            },
        );
        *self.outbound_counts.entry(peer).or_default() += 1;
    }

    fn note_identified(&mut self, connection_id: libp2p::swarm::ConnectionId, peer: PeerId) {
        if !self.managed_connections.contains_key(&connection_id)
            && self.outbound_connections.get(&connection_id) == Some(&peer)
        {
            let kind = self.bootstrap.iter().find_map(|(addr, candidate)| {
                (candidate.peer == Some(peer)).then(|| ManagedOutboundKind::Bootstrap(addr.clone()))
            });
            if let Some(kind) = kind {
                self.track_managed_connection(connection_id, peer, kind);
            } else if self.peers.contains_key(&peer) {
                self.track_managed_connection(connection_id, peer, ManagedOutboundKind::Peer);
            }
        }
        if let Some(connection) = self.managed_connections.get_mut(&connection_id) {
            connection.identified = true;
        }
    }

    fn refresh_healthy_connections(&mut self, now: Instant) {
        for connection in self.managed_connections.values() {
            if !connection.identified
                || now.duration_since(connection.established_at) < AUTOMATIC_PEER_HEALTHY_AFTER
            {
                continue;
            }
            match &connection.kind {
                ManagedOutboundKind::Bootstrap(addr) => {
                    if let Some(candidate) = self.bootstrap.get_mut(addr) {
                        candidate.failures = 0;
                        candidate.next_attempt = now;
                    }
                }
                ManagedOutboundKind::Peer => {
                    if let Some(candidate) = self.peers.get_mut(&connection.peer) {
                        candidate.failures = 0;
                        candidate.next_attempt = now;
                    }
                }
            }
        }
    }

    fn expired_unidentified_connections(
        &self,
        now: Instant,
    ) -> Vec<(libp2p::swarm::ConnectionId, PeerId)> {
        self.managed_connections
            .iter()
            .filter_map(|(connection_id, connection)| {
                (!connection.identified
                    && now.duration_since(connection.established_at)
                        >= AUTOMATIC_PEER_HEALTHY_AFTER)
                    .then_some((*connection_id, connection.peer))
            })
            .collect()
    }

    fn note_connection_closed(&mut self, connection_id: libp2p::swarm::ConnectionId) {
        self.outbound_connections.remove(&connection_id);
        let Some(managed) = self.managed_connections.remove(&connection_id) else {
            return;
        };
        let peer = managed.peer;
        let accelerate_discovery =
            managed.identified || matches!(&managed.kind, ManagedOutboundKind::Peer);
        if let Some(count) = self.outbound_counts.get_mut(&peer) {
            *count -= 1;
            if *count == 0 {
                self.outbound_counts.remove(&peer);
                match managed.kind {
                    ManagedOutboundKind::Peer => {
                        schedule_peer_retry(
                            self.peers.get_mut(&peer),
                            peer.to_bytes(),
                            &self.retry_salt,
                        );
                    }
                    ManagedOutboundKind::Bootstrap(addr) => {
                        if let Some(candidate) = self.bootstrap.get_mut(&addr) {
                            schedule_bootstrap_retry(candidate, addr.as_ref(), &self.retry_salt);
                        }
                    }
                }
            }
        }
        if accelerate_discovery {
            self.accelerate_discovery();
        }
    }

    fn note_dial_failed(&mut self, connection_id: libp2p::swarm::ConnectionId) {
        let Some(pending) = self.pending.remove(&connection_id) else {
            return;
        };
        let accelerate_discovery = matches!(&pending, PendingAutomaticDial::Peer { .. });
        match pending {
            PendingAutomaticDial::Bootstrap(addr) => {
                if let Some(candidate) = self.bootstrap.get_mut(&addr) {
                    // DNS pools may legitimately rotate to a different node
                    // identity. One identity-bound reconnect is attempted;
                    // after failure the next dial re-resolves without pinning
                    // the obsolete PeerId.
                    candidate.peer = None;
                    schedule_bootstrap_retry(candidate, addr.as_ref(), &self.retry_salt);
                }
            }
            PendingAutomaticDial::Peer { peer, .. } => {
                schedule_peer_retry(self.peers.get_mut(&peer), peer.to_bytes(), &self.retry_salt);
            }
        }
        // DNS sources have their own bounded retry schedule. Accelerating a
        // Kademlia walk for every dead hostname would defeat discovery
        // backoff when several future seed names are intentionally offline.
        if accelerate_discovery {
            self.accelerate_discovery();
        }
    }

    fn pending_group_count(&self, group: PublicNetworkGroup) -> usize {
        self.pending
            .values()
            .filter_map(|pending| match pending {
                PendingAutomaticDial::Peer {
                    peer,
                    group: candidate_group,
                } if *candidate_group == group => Some(*peer),
                _ => None,
            })
            .collect::<std::collections::HashSet<_>>()
            .len()
    }

    fn pending_bootstrap_count(&self) -> usize {
        self.pending
            .values()
            .filter(|pending| matches!(pending, PendingAutomaticDial::Bootstrap(_)))
            .count()
    }

    fn pending_ordinary_count(&self) -> usize {
        self.pending
            .values()
            .filter(|pending| matches!(pending, PendingAutomaticDial::Peer { .. }))
            .count()
    }

    fn automatic_occupancy(&self) -> usize {
        self.managed_connections
            .len()
            .saturating_add(self.pending.len())
    }

    fn automatic_dial_capacity(&self) -> usize {
        let unconfirmed = self
            .managed_connections
            .values()
            .filter(|connection| !connection.identified)
            .count()
            .saturating_add(self.pending.len());
        MAX_UNCONFIRMED_AUTOMATIC_CONNECTIONS
            .saturating_sub(unconfirmed)
            .min(MAX_AUTOMATIC_TRANSPORT_OCCUPANCY.saturating_sub(self.automatic_occupancy()))
    }

    fn accelerate_discovery(&mut self) {
        if !self.discovery_active() {
            self.next_discovery_at = Instant::now();
        }
    }

    fn discovery_active(&self) -> bool {
        self.kad_bootstrap_query.is_some() || self.discovery_query.is_some()
    }

    fn begin_kad_bootstrap(&mut self, query: kad::QueryId) {
        self.kad_bootstrap_started = true;
        self.kad_bootstrap_query = Some(query);
    }

    fn finish_kad_bootstrap(&mut self, query: kad::QueryId) {
        if self.kad_bootstrap_query == Some(query) {
            self.kad_bootstrap_query = None;
        }
    }

    fn begin_discovery(&mut self, query: kad::QueryId) {
        self.discovery_query = Some(query);
        self.discovery_learned = false;
    }

    fn observe_discovery(&mut self, query: kad::QueryId, learned: bool, complete: bool) {
        if self.discovery_query != Some(query) {
            return;
        }
        self.discovery_learned |= learned;
        if !complete {
            return;
        }
        self.discovery_query = None;
        if self.discovery_learned {
            self.discovery_failures = 0;
        } else {
            self.discovery_failures = self.discovery_failures.saturating_add(1);
        }
        let multiplier = 1u64 << self.discovery_failures.min(5);
        let delay = DISCOVERY_RETRY_MIN
            .saturating_mul(multiplier as u32)
            .min(DISCOVERY_RETRY_MAX);
        self.next_discovery_at = Instant::now() + delay;
        self.discovery_learned = false;
    }
}

fn automatic_retry_delay(
    failures: u8,
    salt: impl AsRef<[u8]>,
    local_salt: impl AsRef<[u8]>,
) -> Duration {
    let exponential = 5u64.saturating_mul(1u64 << failures.saturating_sub(1).min(6));
    let capped = exponential.min(300);
    let jitter = salt
        .as_ref()
        .iter()
        .chain(local_salt.as_ref())
        .fold(0xcbf2_9ce4_8422_2325u64, |hash, byte| {
            (hash ^ u64::from(*byte)).wrapping_mul(0x0000_0100_0000_01b3)
        })
        % 5;
    Duration::from_secs(capped + jitter)
}

fn schedule_bootstrap_retry(
    candidate: &mut BootstrapCandidate,
    salt: impl AsRef<[u8]>,
    local_salt: impl AsRef<[u8]>,
) {
    candidate.failures = candidate.failures.saturating_add(1);
    candidate.next_attempt =
        Instant::now() + automatic_retry_delay(candidate.failures, salt, local_salt);
}

fn schedule_peer_retry(
    candidate: Option<&mut AutomaticPeerCandidate>,
    salt: impl AsRef<[u8]>,
    local_salt: impl AsRef<[u8]>,
) {
    let Some(candidate) = candidate else {
        return;
    };
    candidate.failures = candidate.failures.saturating_add(1);
    candidate.next_attempt =
        Instant::now() + automatic_retry_delay(candidate.failures, salt, local_salt);
}
const _: () = assert!(
    MAX_PENDING_STATE_SEGMENT_REQUESTS >= noid_chain::consensus::wire_limits::MAX_INFLIGHT_SEGMENTS
);

#[derive(Clone, Copy, Debug)]
struct SnapshotExportLease {
    key: SnapshotExportKey,
    manifest_digest: [u8; 32],
    last_activity: Instant,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PendingRetainedBlockRequest {
    peer: PeerId,
    height: u64,
    count: u16,
    payload_kind: RecentBlockPayloadKind,
    issued_at: Instant,
    notify_node: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PendingStateSegmentRequest {
    peer: PeerId,
    segment_id: u16,
    expected_tip_height: u64,
    expected_tip_hash: [u8; 32],
    manifest_digest: [u8; 32],
    issued_at: Instant,
    notify_node: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PendingStateManifestRequest {
    generation: u64,
    peer: PeerId,
    requester_height: u64,
    issued_at: Instant,
    notify_node: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PendingHeaderRequest {
    peer: PeerId,
    start_height: u64,
    count: u16,
    kind: HeaderRequestKind,
    issued_at: Instant,
    notify_node: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HeaderRequestKind {
    General,
    Snapshot { generation: u64, token: u64 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PendingHistoryStepTerminalRequest {
    token: u64,
    peer: PeerId,
    height: u64,
    block_hash: [u8; 32],
    issued_at: Instant,
    notify_node: bool,
}

/// Make room for a new logical terminal race without disturbing newer races.
/// A race may own more than one transport request because exact requests to
/// different peers share one node-local token. If the bounded table is full,
/// retire the complete oldest race; delayed responses then become unknown and
/// inert in the normal response-correlation path.
fn admit_history_step_terminal_race<K: std::hash::Hash + Eq + Clone>(
    pending: &mut BoundedPendingRequests<K, PendingHistoryStepTerminalRequest>,
) -> Vec<(K, PendingHistoryStepTerminalRequest)> {
    if pending.has_capacity() {
        return Vec::new();
    }
    let Some(oldest) = pending
        .entries
        .values()
        .min_by_key(|request| request.issued_at)
        .map(|request| request.token)
    else {
        return Vec::new();
    };
    pending.take_where_entries(|request| request.token == oldest)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequestFailureKind {
    Dial,
    Timeout,
    ConnectionClosed,
    UnsupportedProtocol,
    Io,
    InvalidResponse,
}

impl From<&request_response::OutboundFailure> for RequestFailureKind {
    fn from(failure: &request_response::OutboundFailure) -> Self {
        match failure {
            request_response::OutboundFailure::DialFailure => Self::Dial,
            request_response::OutboundFailure::Timeout => Self::Timeout,
            request_response::OutboundFailure::ConnectionClosed => Self::ConnectionClosed,
            request_response::OutboundFailure::UnsupportedProtocols => Self::UnsupportedProtocol,
            request_response::OutboundFailure::Io(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::InvalidData | std::io::ErrorKind::UnexpectedEof
                ) =>
            {
                Self::InvalidResponse
            }
            request_response::OutboundFailure::Io(_) => Self::Io,
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct MempoolSyncRetry {
    failures: u8,
    next_attempt: Instant,
}

const MAX_MEMPOOL_SYNC_FAILURES: u8 = 7;
const MEMPOOL_SYNC_RETRY_INFLIGHT: Duration = Duration::from_secs(35);

fn mempool_sync_retry_jitter(local: PeerId, remote: PeerId) -> Duration {
    // Every client requesting the same busy peer must get a different retry
    // phase. Hashing only `remote` synchronizes the entire fan-in on one tick.
    // FNV-1a is sufficient here: this is load spreading, not authentication.
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for byte in local.to_bytes().iter().chain(remote.to_bytes().iter()) {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    Duration::from_millis(hash % 4_000)
}

fn schedule_mempool_sync_retry(
    retries: &mut std::collections::HashMap<PeerId, MempoolSyncRetry>,
    local: PeerId,
    peer: PeerId,
) -> Option<MempoolSyncRetry> {
    let previous_failures = retries.get(&peer).map_or(0, |retry| retry.failures);
    if previous_failures >= MAX_MEMPOOL_SYNC_FAILURES {
        retries.remove(&peer);
        return None;
    }
    let failures = previous_failures + 1;
    let exponential_secs = 1u64 << failures.saturating_sub(1).min(5);
    let retry = MempoolSyncRetry {
        failures,
        next_attempt: Instant::now()
            + Duration::from_secs(exponential_secs)
            + mempool_sync_retry_jitter(local, peer),
    };
    retries.insert(peer, retry);
    Some(retry)
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

    fn len(&self) -> usize {
        self.entries.len()
    }
}

impl<K: std::hash::Hash + Eq + Clone, V> BoundedPendingRequests<K, V> {
    fn take_where_entries(&mut self, mut matches: impl FnMut(&V) -> bool) -> Vec<(K, V)> {
        let ids = self
            .entries
            .iter()
            .filter_map(|(id, pending)| matches(pending).then_some(id.clone()))
            .collect::<Vec<_>>();
        ids.into_iter()
            .filter_map(|id| self.entries.remove(&id).map(|pending| (id, pending)))
            .collect()
    }

    fn take_where(&mut self, matches: impl FnMut(&V) -> bool) -> Vec<V> {
        self.take_where_entries(matches)
            .into_iter()
            .map(|(_, pending)| pending)
            .collect()
    }
}

fn retained_block_response_matches_pending(
    pending: PendingRetainedBlockRequest,
    peer: PeerId,
    response_height: u64,
    response_count: u16,
) -> bool {
    pending.peer == peer && pending.height == response_height && pending.count == response_count
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
        && pending.manifest_digest == response.manifest_digest
}

fn unavailable_state_segment_response(request: &GetStateSegmentRequest) -> GetStateSegmentResponse {
    GetStateSegmentResponse {
        segment_id: request.segment_id,
        expected_tip_height: request.expected_tip_height,
        expected_tip_hash: request.expected_tip_hash,
        manifest_digest: request.manifest_digest,
        eff_log: 0,
        data: None,
        inbound_memory_permit: None,
        outbound_memory_permit: None,
    }
}

// Hard caps on incoming response sizes are shared via noid_chain::consensus::wire_limits.

fn snapshot_suffix_is_retained(tip_height: u64, terminal_height: u64) -> bool {
    terminal_height <= tip_height
        && tip_height.saturating_sub(terminal_height)
            <= noid_chain::consensus::params::RECENT_BLOCK_RETENTION_DEPTH
}

/// Choose the finalized snapshot boundary only when its exact HistoryStep
/// terminal is durably available.
fn local_history_step_boundary(store: &MdbxStore) -> Option<(u64, [u8; 32])> {
    let meta = store.get_consensus_meta().ok().flatten()?;
    if meta.finalized.height > meta.tip_height {
        return None;
    }
    let newest = meta.finalized.height.min(meta.tip_height);
    let newest = newest - newest % SNAPSHOT_BOUNDARY_INTERVAL;
    let oldest = meta
        .tip_height
        .saturating_sub(noid_chain::consensus::params::RECENT_BLOCK_RETENTION_DEPTH);
    if newest == 0 || newest < oldest {
        return None;
    }

    // Snapshot-installed compact suffix rows intentionally carry local
    // authorization markers rather than duplicate full terminals. Select the
    // newest deterministic checkpoint whose complete terminal is durable.
    // Never fall back to an arbitrary per-node height: exact cross-peer object
    // failover depends on independent exporters producing the same manifest.
    for height in (oldest.max(1)..=newest)
        .rev()
        .filter(|height| height % SNAPSHOT_BOUNDARY_INTERVAL == 0)
    {
        let header = store.get_header(height).ok().flatten()?;
        let block_hash = noid_chain::hash_block_header(&header);
        if height == meta.finalized.height && block_hash != meta.finalized.hash {
            return None;
        }
        let has_canonical = store
            .has_history_step_terminal_at(height, block_hash)
            .ok()?;
        let has_cached = store
            .has_any_history_step_proof_object(
                height,
                noid_chain::block_header::semantic_header_id(&header),
            )
            .ok()?;
        if has_canonical || has_cached {
            return Some((height, block_hash));
        }
    }
    None
}

fn load_exact_object(store: &MdbxStore, object: ObjectId) -> Result<Option<Vec<u8>>, String> {
    match object {
        ObjectId::BlockBody(expected) => {
            let canonical = store
                .get_recent_block(expected.claim.height)
                .map_err(|error| format!("read retained block: {error}"))?;
            let bytes = match canonical {
                Some(bytes) => {
                    let matches = noid_chain::Block::from_bytes(&bytes)
                        .ok()
                        .is_some_and(|block| {
                            block.header.height == expected.claim.height
                                && noid_chain::block_header::block_id(&block.header)
                                    == expected.claim.block_hash
                                && expected.matches_bytes(&bytes)
                        });
                    if matches {
                        return Ok(Some(bytes));
                    }
                    store
                        .get_block_body_object(expected.claim.height, expected.claim.block_hash)
                        .map_err(|error| format!("read cached block object: {error}"))?
                }
                None => store
                    .get_block_body_object(expected.claim.height, expected.claim.block_hash)
                    .map_err(|error| format!("read cached block object: {error}"))?,
            };
            let Some(bytes) = bytes else {
                return Ok(None);
            };
            let block = noid_chain::Block::from_bytes(&bytes)
                .map_err(|error| format!("decode cached block object: {error:?}"))?;
            if block.header.height != expected.claim.height
                || noid_chain::block_header::block_id(&block.header) != expected.claim.block_hash
                || !expected.matches_bytes(&bytes)
            {
                return Ok(None);
            }
            Ok(Some(bytes))
        }
        ObjectId::Terminal(expected) => {
            let canonical = store
                .get_header(expected.claim.height)
                .map_err(|error| format!("read terminal header: {error}"))?
                .filter(|header| {
                    noid_chain::block_header::semantic_header_id(header)
                        == expected.claim.semantic_header_id
                });
            let canonical_bytes = match canonical {
                Some(header) => store
                    .get_history_step_terminal_at(
                        expected.claim.height,
                        noid_chain::block_header::block_id(&header),
                    )
                    .map_err(|error| format!("read retained terminal: {error}"))?,
                None => None,
            };
            let Some(bytes) = canonical_bytes.or(store
                .get_history_step_proof_object(
                    expected.claim.height,
                    expected.claim.semantic_header_id,
                    expected.claim.proof_class,
                )
                .map_err(|error| format!("read cached terminal object: {error}"))?)
            else {
                return Ok(None);
            };
            let metadata =
                noid_chain::history_step::HistoryStepTerminalMetadata::decode_prefix(&bytes)
                    .map_err(|error| format!("decode retained terminal metadata: {error}"))?;
            if metadata.terminal_height() != expected.claim.height
                || metadata.terminal_hash() != expected.claim.semantic_header_id
                || metadata.class_id() != expected.claim.proof_class
                || !expected.matches_bytes(&bytes)
            {
                return Ok(None);
            }
            Ok(Some(bytes))
        }
        ObjectId::SnapshotManifest(_) | ObjectId::StateSegment(_) => Ok(None),
    }
}

fn snapshot_boundary_has_live_headroom(live_tip: u64, boundary_height: u64) -> bool {
    boundary_height <= live_tip
        && live_tip.saturating_sub(boundary_height) <= SNAPSHOT_BOUNDARY_MAX_LIVE_GAP
}

fn snapshot_export_selection_rank(
    key: SnapshotExportKey,
    bridge_tip_height: u64,
    leased_keys: &std::collections::HashSet<SnapshotExportKey>,
) -> (bool, u64, u64) {
    (leased_keys.contains(&key), key.0, bridge_tip_height)
}

/// Select one complete immutable generation with ample live-window headroom.
/// New peers join the freshest still-usable leased generation instead of
/// splitting an active bootstrap cohort every time the 30-second exporter
/// publishes a newer boundary. If no leased generation remains usable, select
/// the freshest generation and let lease admission retire the oldest cohort.
/// The state boundary itself may be older than the node's newest finalized
/// checkpoint: its terminal and State segments are generation-owned. The
/// client selects the moving suffix independently from validated headers.
fn select_snapshot_export(
    store: &MdbxStore,
    exports: &std::collections::HashMap<SnapshotExportKey, SnapshotExport>,
    leases: &std::collections::HashMap<PeerId, SnapshotExportLease>,
    requester_height: u64,
    requested_manifest_digest: [u8; 32],
) -> Option<SnapshotExport> {
    let meta = store.get_consensus_meta().ok().flatten()?;
    let exact_generation_requested = requested_manifest_digest != [0; 32];
    let leased_keys = leases
        .values()
        .map(|lease| lease.key)
        .collect::<std::collections::HashSet<_>>();
    exports
        .values()
        .filter(|generation| {
            let manifest = generation.manifest();
            if exact_generation_requested
                && generation.network_manifest.manifest_digest != requested_manifest_digest
            {
                return false;
            }
            if manifest.target_height == 0
                || manifest.target_height > meta.finalized.height
                || manifest.bridge_tip_height < manifest.target_height
                || (!exact_generation_requested && manifest.target_height <= requester_height)
                || (!exact_generation_requested
                    && !snapshot_boundary_has_live_headroom(
                        meta.tip_height,
                        manifest.target_height,
                    ))
            {
                return false;
            }
            let boundary_matches = store
                .get_header(manifest.target_height)
                .ok()
                .flatten()
                .is_some_and(|header| {
                    noid_chain::hash_block_header(&header) == manifest.target_hash
                        && header.state_root == manifest.state_root
                        && header.log_slots == manifest.log_slots
                        && header.active_slot_count == manifest.active_slot_count
                        && header.alloc_counter == manifest.alloc_counter
                });
            let bridge_matches = store
                .get_header(manifest.bridge_tip_height)
                .ok()
                .flatten()
                .is_some_and(|header| {
                    noid_chain::hash_block_header(&header) == manifest.bridge_tip_hash
                });
            let work_matches = store.get_chain_work(manifest.target_height).ok().flatten()
                == Some(manifest.cumulative_chainwork)
                && store
                    .get_chain_work(manifest.bridge_tip_height)
                    .ok()
                    .flatten()
                    == Some(manifest.bridge_cumulative_chainwork);
            boundary_matches && bridge_matches && work_matches
        })
        .max_by_key(|generation| {
            snapshot_export_selection_rank(
                generation.key(),
                generation.manifest().bridge_tip_height,
                &leased_keys,
            )
        })
        .cloned()
}

/// Load one exact canonical HistoryStep terminal from the bounded recent
/// window. Snapshot state boundaries are finalized, while the compact suffix
/// tip may legitimately be newer when blocks arrive during state download.
fn local_history_step_terminal(
    store: &MdbxStore,
    height: u64,
    block_hash: [u8; 32],
) -> Option<Vec<u8>> {
    let tip_height = store.get_consensus_meta().ok().flatten()?.tip_height;
    if height == 0 || height > tip_height || !snapshot_suffix_is_retained(tip_height, height) {
        return None;
    }
    let canonical = store
        .get_history_step_terminal_at(height, block_hash)
        .ok()
        .flatten();
    canonical.or_else(|| {
        let header = store.get_header(height).ok().flatten()?;
        (noid_chain::block_header::block_id(&header) == block_hash)
            .then(|| {
                store
                    .get_any_history_step_proof_object(
                        height,
                        noid_chain::block_header::semantic_header_id(&header),
                    )
                    .ok()
                    .flatten()
            })
            .flatten()
    })
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

/// Check the cheap structural shape of one already allocation-bounded decoded
/// batch. Parent hashes, PoW, ASERT and the remaining consensus rules are
/// checked once by the authoritative node-side header path.
fn validate_header_batch_shape(records: &[HeaderInventoryRecord]) -> Result<(), &'static str> {
    if records.len() > crate::header_sync_codec::MAX_HEADERS_PER_BATCH {
        return Err("header count exceeds cap");
    }
    for pair in records.windows(2) {
        let [parent, header] = pair else {
            unreachable!("windows(2) always has two entries")
        };
        if header.header.height
            != parent
                .header
                .height
                .checked_add(1)
                .ok_or("header height overflow")?
        {
            return Err("header batch is not height-contiguous");
        }
    }
    Ok(())
}

fn snapshot_header_request_is_superseded(
    pending: &PendingHeaderRequest,
    generation: u64,
    start_height: u64,
) -> bool {
    matches!(
        pending.kind,
        HeaderRequestKind::Snapshot {
            generation: pending_generation,
            ..
        } if pending_generation != generation || pending.start_height == start_height
    )
}

/// Commands sent to the P2P network event loop.
#[derive(Debug)]
pub enum NetworkCommand {
    /// Announce one complete accepted-block bundle. The event loop chooses
    /// inline gossip or header-only gossip from its canonical encoded size.
    AnnounceBlock { bundle: AcceptedBlockBundle },
    /// Broadcast a new TxIntent to all peers.
    BroadcastTx { intent_bytes: Arc<[u8]> },
    /// Register a bootstrap address with automatic retry and peer maintenance.
    Dial { addr: Multiaddr },
    /// Initial chain synchronization is complete; bootstrap connections may be
    /// released once enough ordinary outbound peers are available.
    BootstrapComplete,
    /// Get current peer count.
    PeerCount {
        reply: tokio::sync::oneshot::Sender<usize>,
    },
    /// Fetch one exact content-addressed object set from one candidate source.
    /// The token is node-local and is returned unchanged in the result.
    FetchObjects {
        token: u64,
        peer: PeerId,
        objects: Vec<ObjectId>,
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
    /// Request one bounded consecutive range of canonical block bodies for
    /// authenticated snapshot-tail staging.
    RequestBlockBodies {
        peer: PeerId,
        height: u64,
        count: u16,
    },
    /// Fetch a range of headers from a peer for reorg ancestor search.
    /// Emits `NetworkEvent::HeaderInventoryBatch` with decoded headers and
    /// exact retained-object availability.
    /// Used to find the common ancestor efficiently in O(1) round-trips
    /// instead of O(depth) hop-by-hop backwards traversal.
    FetchHeaders {
        peer: PeerId,
        start_height: u64,
        count: u16, // bounded by the fixed header codec
    },
    /// Fetch one exactly correlated header range for snapshot disk staging.
    ///
    /// Unlike `FetchHeaders`, this request belongs to the exact snapshot
    /// generation and single bounded transfer lane.
    /// `generation`, the node-local `token`, `start_height`, and `count` are
    /// returned unchanged so the node can reject stale or out-of-order
    /// responses without confusing them with reorg/tip probes.
    FetchSnapshotHeaders {
        generation: u64,
        /// Node-local correlation token. It is never sent on the wire.
        token: u64,
        peer: PeerId,
        start_height: u64,
        count: u16,
    },
    /// Request the state manifest from a peer (step 1 of snapshot sync).
    /// Returns metadata + active segment IDs. Emits `NetworkEvent::StateManifest`.
    RequestStateManifest {
        /// Node-local snapshot generation. It is never sent on the wire.
        generation: u64,
        peer: PeerId,
        requester_height: u64,
        requested_manifest_digest: [u8; 32],
    },
    /// Request a single state segment from a peer (step 2, one per segment).
    /// Emits `NetworkEvent::StateSegment`.
    RequestStateSegment {
        peer: PeerId,
        segment_id: u16,
        expected_tip_height: u64,
        expected_tip_hash: [u8; 32],
        manifest_digest: [u8; 32],
    },
    /// Request the fused HistoryStep terminal for an exact snapshot boundary.
    RequestHistoryStepTerminal {
        /// Node-local correlation token. It is never sent on the wire.
        token: u64,
        peer: PeerId,
        height: u64,
        block_hash: [u8; 32],
    },
    /// Retire node notifications for one completed terminal race. Transport
    /// correlation remains until response, failure, or the local deadline so
    /// a pre-substream stall can still be detected and flushed.
    CancelHistoryStepTerminalRace { token: u64 },
    /// Request a peer's mempool contents (all pending TxIntent bytes).
    /// Triggered on peer connect so late-joining nodes receive existing TXs.
    /// Emits `NetworkEvent::MempoolSyncResponse` when the response arrives.
    RequestMempoolSync { peer: PeerId },
}

/// Events emitted by the P2P layer to the node.
#[derive(Debug, Clone)]
pub enum NetworkEvent {
    /// Fixed-size network-v3 header announcement with exact body/terminal IDs.
    HeaderAnnouncement {
        from: PeerId,
        announcement: HeaderAnnouncement,
        /// True only when `from` is the directly connected original
        /// publisher and advertised both exact objects. A gossipsub forwarder
        /// is a header source, not automatically a body/proof provider.
        source_has_objects: bool,
    },
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
    /// Consecutive canonical block bytes pulled for an authenticated snapshot
    /// suffix.
    SnapshotBlockBodies {
        from: PeerId,
        height: u64,
        block_bodies: Vec<Vec<u8>>,
        /// Holds the process-global inbound byte budget until disk staging has
        /// consumed the body.
        inbound_memory_permit: Option<Arc<tokio::sync::OwnedSemaphorePermit>>,
    },
    /// A requested retained full block is no longer available from this peer.
    RecentBlockUnavailable {
        from: PeerId,
        height: u64,
        payload_kind: RecentBlockPayloadKind,
    },
    /// Transport failed for one exact retained-block request.  Keeping the
    /// requested height lets snapshot sync distinguish its immutable bridge
    /// from the optional live tail without discarding unrelated peer requests.
    RecentBlockRequestFailed {
        from: PeerId,
        height: u64,
        payload_kind: RecentBlockPayloadKind,
    },
    /// Exact-object response correlated to one immutable planner job.
    ObjectsResponse {
        token: u64,
        from: PeerId,
        objects: Vec<ObjectPayload>,
        inbound_memory_permit: Option<Arc<tokio::sync::OwnedSemaphorePermit>>,
    },
    /// Transport or protocol failure for one exact-object source lease.
    ObjectsRequestFailed {
        token: u64,
        from: PeerId,
        objects: Vec<ObjectId>,
        kind: RequestFailureKind,
    },
    /// A new TxIntent arrived from a peer.
    NewTx {
        from: PeerId,
        intent_bytes: Vec<u8>,
        /// Direct-push requests reserve their decoded bytes process-globally
        /// until node-side admission finishes. Gossip messages carry `None`.
        inbound_memory_permit: Option<Arc<tokio::sync::OwnedSemaphorePermit>>,
    },
    /// Response to FetchHeaders: decoded headers plus exact retained-object
    /// availability from the peer. Used by HeaderDAG and immutable plans.
    HeaderInventoryBatch {
        from: PeerId,
        records: Vec<HeaderInventoryRecord>,
    },
    /// Transport or decoding failed for one exact header request.
    HeadersRequestFailed {
        from: PeerId,
        start_height: u64,
        count: u16,
    },
    /// Exactly correlated response for snapshot header staging.
    SnapshotHeadersBatch {
        generation: u64,
        token: u64,
        from: PeerId,
        start_height: u64,
        requested_count: u16,
        headers: Vec<noid_chain::block_header::BlockHeader>,
    },
    /// Transport or decoding failed for one exact snapshot header range.
    SnapshotHeadersRequestFailed {
        generation: u64,
        token: u64,
        from: PeerId,
        start_height: u64,
        count: u16,
        kind: RequestFailureKind,
    },
    /// State manifest received from a peer (step 1 of snapshot sync).
    StateManifest {
        generation: u64,
        from: PeerId,
        requester_height: u64,
        manifest: Box<crate::protocol::GetStateManifestResponse>,
    },
    /// Transport failed for one exactly correlated state-manifest request.
    StateManifestRequestFailed {
        generation: u64,
        from: PeerId,
        requester_height: u64,
        kind: RequestFailureKind,
    },
    /// One state segment received from a peer (step 2).
    StateSegment {
        from: PeerId,
        response: crate::protocol::GetStateSegmentResponse,
    },
    /// Transport failed for one exact state-segment request.
    StateSegmentRequestFailed {
        from: PeerId,
        segment_id: u16,
        expected_tip_height: u64,
        expected_tip_hash: [u8; 32],
        manifest_digest: [u8; 32],
    },
    /// Fused HistoryStep terminal response for O(1) snapshot sync.
    HistoryStepTerminal {
        /// Exact node-local token supplied with the corresponding request.
        token: u64,
        from: PeerId,
        height: u64,
        block_hash: [u8; 32],
        /// Exact-bound HistoryStep terminal bytes, or empty when unavailable.
        terminal_bytes: Vec<u8>,
        /// Holds the process-global inbound terminal byte budget until the node
        /// finishes verifying this response.
        inbound_memory_permit: Option<Arc<tokio::sync::OwnedSemaphorePermit>>,
    },
    /// Transport failed for one exact HistoryStep terminal request. The
    /// request tuple remains available so snapshot sync can preserve unrelated
    /// staged headers and report the real transport failure.
    HistoryStepTerminalRequestFailed {
        token: u64,
        from: PeerId,
        height: u64,
        block_hash: [u8; 32],
        kind: RequestFailureKind,
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
    PeerConnected {
        peer: PeerId,
        /// Coarse public network group (IPv4 /16, IPv6 /32), or an
        /// identity-derived domain for private/LAN transports.
        failure_domain: u64,
    },
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
    required_rx: RequiredEventReceiver,
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
const GOSSIP_EVENT_QUEUE_CAPACITY: usize = 64;

/// The P2P network manager.
pub struct P2PNetwork {
    /// Channel to send commands to the event loop.
    pub cmd_tx: mpsc::Sender<NetworkCommand>,
    /// Subscribe to events from the event loop.
    gossip_event_tx: tokio::sync::broadcast::Sender<NetworkEvent>,
    required_event_rx: std::sync::Mutex<Option<RequiredEventReceiver>>,
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
    ) -> anyhow::Result<(Self, tokio::task::JoinHandle<()>)> {
        // Load before spawning so an absent, corrupt, symlinked, or publicly
        // readable private identity fails node startup instead of silently
        // leaving RPC alive with a dead P2P task.
        let identity = crate::identity_store::load_or_create(&data_dir)?;
        let local_peer_id = identity.public().to_peer_id();
        tracing::info!(peer = %local_peer_id, "loaded persistent P2P identity");
        let (cmd_tx, cmd_rx) = mpsc::channel(256);
        let (gossip_event_tx, _) = tokio::sync::broadcast::channel(GOSSIP_EVENT_QUEUE_CAPACITY);
        let (required_event_tx, required_event_rx) = event_dispatch::channel();

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
                identity,
            )
            .await
            {
                tracing::error!("P2P network error: {e}");
            }
        });

        Ok((
            Self {
                cmd_tx,
                gossip_event_tx,
                required_event_rx: std::sync::Mutex::new(Some(required_event_rx)),
            },
            handle,
        ))
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

    pub async fn mark_bootstrap_complete(&self) {
        let _ = self.cmd_tx.send(NetworkCommand::BootstrapComplete).await;
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

    /// Request only the bounded canonical block range needed by snapshot
    /// suffix sync.
    pub async fn request_block_bodies(&self, peer: PeerId, height: u64, count: u16) {
        let _ = self
            .cmd_tx
            .send(NetworkCommand::RequestBlockBodies {
                peer,
                height,
                count,
            })
            .await;
    }

    /// Request the state manifest from a peer (step 1 of snapshot sync).
    pub async fn request_state_manifest(&self, peer: PeerId) {
        let _ = self
            .cmd_tx
            .send(NetworkCommand::RequestStateManifest {
                generation: 0,
                peer,
                requester_height: 0,
                requested_manifest_digest: [0; 32],
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
        manifest_digest: [u8; 32],
    ) {
        let _ = self
            .cmd_tx
            .send(NetworkCommand::RequestStateSegment {
                peer,
                segment_id,
                expected_tip_height,
                expected_tip_hash,
                manifest_digest,
            })
            .await;
    }

    /// Request the HistoryStep terminal for an exact snapshot boundary.
    pub async fn request_history_step_terminal(
        &self,
        token: u64,
        peer: PeerId,
        height: u64,
        block_hash: [u8; 32],
    ) {
        let _ = self
            .cmd_tx
            .send(NetworkCommand::RequestHistoryStepTerminal {
                token,
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
    required_event_tx: RequiredEventSender,
    chain: Arc<RwLock<MdbxChainContext>>,
    mempool: AsyncMempool,
    topics: NetworkTopics,
    data_dir: std::path::PathBuf,
    identity: libp2p::identity::Keypair,
) -> anyhow::Result<()> {
    use libp2p::{noise, tcp, yamux, SwarmBuilder};

    // P2P data serving must remain responsive while expensive block proof
    // verification owns the mutable hot chain context. MDBX readers use
    // independent MVCC snapshots and never need that application-level lock.
    let chain_store = {
        let ctx = chain.read().await;
        ctx.store.clone()
    };

    let protocol_id = topics.protocol_id.clone();
    let mut swarm = SwarmBuilder::with_existing_identity(identity)
        .with_tokio()
        .with_tcp(
            tcp::Config::default().nodelay(true),
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
    // Load only previously successful outbound peers. They seed Kademlia and
    // enter the same bounded automatic manager as DNS bootstrap sources, so a
    // restart cannot create a second untracked dial burst.
    let mut successful_peer_cache = crate::peer_store::load(&data_dir);
    let local_peer_id = *swarm.local_peer_id();
    let mut automatic_peers = AutomaticPeerState::new(local_peer_id);
    for peer in successful_peer_cache.entries() {
        automatic_peers.add_peer_candidate(local_peer_id, peer.peer_id, peer.addrs.iter().cloned());
    }
    let cached_peer_count = successful_peer_cache.entries().count();
    if cached_peer_count > 0 {
        tracing::debug!(
            count = cached_peer_count,
            "peer store: seeding Kademlia from successful outbound cache"
        );
        for peer in successful_peer_cache.entries() {
            for addr in &peer.addrs {
                swarm
                    .behaviour_mut()
                    .kad
                    .add_address(&peer.peer_id, addr.clone());
            }
        }
    }

    // Do not start a Kademlia walk from disk cache alone. A stale cached
    // address can otherwise hold the single discovery slot for the full query
    // timeout while a live DNS seed is already connected. Identify starts the
    // first bootstrap only after a transport has proved live.

    // Cheap P2P-layer DoS guards that run before emitting NetworkEvent into
    // the bounded broadcast channel.
    let mut block_event_rate: std::collections::HashMap<PeerId, (u32, Instant)> =
        std::collections::HashMap::new();
    let mut tx_gossip_rate: std::collections::HashMap<PeerId, (u32, Instant)> =
        std::collections::HashMap::new();
    let mut gossip_accept_bytes = GossipByteWindow::new();
    let mut mempool_sync_last_request: std::collections::HashMap<PeerId, Instant> =
        std::collections::HashMap::new();
    let mut mempool_sync_retries: std::collections::HashMap<PeerId, MempoolSyncRetry> =
        std::collections::HashMap::new();
    let mut snapshot_segment_rate: std::collections::HashMap<PeerId, (u32, Instant)> =
        std::collections::HashMap::new();
    let mut pending_retained_block_requests =
        BoundedPendingRequests::new(MAX_PENDING_RETAINED_BLOCK_REQUESTS);
    let mut pending_network_profile_requests =
        BoundedPendingRequests::new(MAX_PENDING_NETWORK_PROFILE_REQUESTS);
    let mut pending_object_requests = BoundedPendingRequests::new(MAX_PENDING_OBJECT_REQUESTS);
    let mut pending_header_requests = BoundedPendingRequests::new(MAX_PENDING_HEADER_REQUESTS);
    let mut pending_state_manifest_requests =
        BoundedPendingRequests::new(MAX_PENDING_STATE_MANIFEST_REQUESTS);
    let mut pending_state_segment_requests =
        BoundedPendingRequests::new(MAX_PENDING_STATE_SEGMENT_REQUESTS);
    let mut pending_history_step_requests =
        BoundedPendingRequests::new(MAX_PENDING_HISTORY_STEP_REQUESTS);
    let mut peer_diversity = PeerDiversity::default();
    let mut sync_paths = PeerSyncPaths::default();

    // One waiting response of each kind is sufficient: the request-response
    // behaviour owns the next response while its codec writes it. Byte permits
    // retained by both stages are the process-wide RAM bound.
    let (block_response_tx, mut block_response_rx) = mpsc::channel::<PendingBlockResponse>(1);
    let (header_response_tx, mut header_response_rx) = mpsc::channel::<PendingHeaderResponse>(1);
    let (history_step_response_tx, mut history_step_response_rx) =
        mpsc::channel::<PendingHistoryStepTerminalResponse>(1);
    let (segment_response_tx, mut segment_response_rx) =
        mpsc::channel::<PendingStateSegmentResponse>(1);
    let (mempool_response_tx, mut mempool_response_rx) = mpsc::channel::<PendingMempoolResponse>(1);
    let (object_response_tx, mut object_response_rx) = mpsc::channel::<PendingObjectResponse>(4);
    let block_response_prepare_semaphore = Arc::new(Semaphore::new(2));
    let header_response_prepare_semaphore = Arc::new(Semaphore::new(2));
    let history_step_response_prepare_semaphore = Arc::new(Semaphore::new(4));
    let segment_encode_semaphore = Arc::new(Semaphore::new(2));
    let mempool_response_prepare_semaphore = Arc::new(Semaphore::new(1));
    let outbound_response_budget = OutboundResponseBudget::process_global();
    let mut data_plane_serving = DataPlaneServingAdmission::new();
    let snapshot_export_root = data_dir.join("snapshot-exports");
    std::fs::create_dir_all(&snapshot_export_root)?;
    let mut snapshot_exports = load_snapshot_exports(&snapshot_export_root);
    let mut snapshot_export_leases: std::collections::HashMap<PeerId, SnapshotExportLease> =
        std::collections::HashMap::new();
    prune_snapshot_exports(&mut snapshot_exports, &snapshot_export_leases);
    let (snapshot_export_tx, mut snapshot_export_rx) = mpsc::channel::<(
        SnapshotExportKey,
        Result<SnapshotGeneration, noid_chain::storage::SnapshotGenerationError>,
    )>(1);
    let mut snapshot_export_inflight: Option<SnapshotExportKey> = None;
    let mut snapshot_export_timer = tokio::time::interval(Duration::from_secs(30));
    snapshot_export_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut reactor_health_timer = tokio::time::interval(Duration::from_secs(10));
    reactor_health_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    reactor_health_timer.tick().await;

    // Keep retry jitter effective under a large simultaneous fan-in. Folding
    // this into the two-second peer-maintenance tick would release every due peer
    // as one batch and recreate the handshake herd we are avoiding.
    let mut mempool_retry_timer = tokio::time::interval(Duration::from_millis(250));
    mempool_retry_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    mempool_retry_timer.tick().await; // skip first immediate tick

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
    let mut automatic_peer_timer = tokio::time::interval(Duration::from_secs(2));
    automatic_peer_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        // Drain all pending commands first (priority: outgoing blocks must propagate
        // immediately without waiting for swarm event processing).
        for _ in 0..32 {
            let Ok(cmd) = cmd_rx.try_recv() else {
                break;
            };
            handle_network_command(
                &mut swarm,
                cmd,
                &topics,
                &mut mempool_sync_last_request,
                &mut mempool_sync_retries,
                &required_event_tx,
                &mut pending_retained_block_requests,
                &mut pending_object_requests,
                &mut pending_header_requests,
                &mut pending_state_manifest_requests,
                &mut pending_state_segment_requests,
                &mut pending_history_step_requests,
                &mut automatic_peers,
                &sync_paths,
            )
            .await;
        }

        tokio::select! {
            // Swarm events.
            event = swarm.select_next_some() => {
                handle_swarm_event(
                    &mut swarm,
                    event,
                    &gossip_event_tx,
                    &required_event_tx,
                    &chain_store,
                    &mempool,
                    &topics,
                    &block_response_tx,
                    &block_response_prepare_semaphore,
                    &header_response_tx,
                    &header_response_prepare_semaphore,
                    &history_step_response_tx,
                    &history_step_response_prepare_semaphore,
                    &segment_response_tx,
                    &segment_encode_semaphore,
                    &mempool_response_tx,
                    &mempool_response_prepare_semaphore,
                    &object_response_tx,
                    &outbound_response_budget,
                    &mut data_plane_serving,
                    &mut snapshot_exports,
                    &mut snapshot_export_leases,
                    &mut block_event_rate,
                    &mut tx_gossip_rate,
                    &mut gossip_accept_bytes,
                    &mut mempool_sync_last_request,
                    &mut mempool_sync_retries,
                    &mut snapshot_segment_rate,
                    &mut pending_retained_block_requests,
                    &mut pending_network_profile_requests,
                    &mut pending_object_requests,
                    &mut pending_header_requests,
                    &mut pending_state_manifest_requests,
                    &mut pending_state_segment_requests,
                    &mut pending_history_step_requests,
                    &mut automatic_peers,
                    &mut peer_diversity,
                    &mut sync_paths,
                    &mut successful_peer_cache,
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

            prepared = header_response_rx.recv() => {
                if let Some(prepared) = prepared {
                    let _ = swarm
                        .behaviour_mut()
                        .chain_sync
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

            prepared = object_response_rx.recv() => {
                if let Some(prepared) = prepared {
                    let _ = swarm
                        .behaviour_mut()
                        .object_sync
                        .send_response(prepared.channel, prepared.response);
                }
            }

            completed = snapshot_export_rx.recv() => {
                if let Some((key, result)) = completed {
                    snapshot_export_inflight = None;
                    match result {
                        Ok(generation) if generation.key() == key => {
                            if let Some(export) = SnapshotExportEntry::new(generation) {
                                tracing::info!(height = key.0, "published bounded disk snapshot generation");
                                snapshot_exports.insert(key, Arc::new(export));
                                prune_snapshot_export_leases(&mut snapshot_export_leases);
                                refresh_snapshot_object_retention_floor(
                                    &chain_store,
                                    &snapshot_export_leases,
                                );
                                prune_snapshot_exports(&mut snapshot_exports, &snapshot_export_leases);
                            } else {
                                tracing::error!(height = key.0, "snapshot generation has no canonical network manifest identity");
                            }
                        }
                        Ok(_) => tracing::warn!(height = key.0, "snapshot generation boundary mismatch"),
                        Err(error) => {
                            let retry_after_tail_install = matches!(
                                error,
                                noid_chain::storage::SnapshotGenerationError::MissingBridgeTerminal(_)
                                    | noid_chain::storage::SnapshotGenerationError::MissingBoundaryTerminal(_)
                            );
                            tracing::warn!(height = key.0, err = %error, "snapshot generation build failed");
                            if retry_after_tail_install {
                                // The exporter may race the atomic compact-tail
                                // installer and pin an intermediate marker.
                                // Retry after that fixed local race instead of
                                // waiting for the regular 30-second cadence.
                                snapshot_export_timer.reset_after(Duration::from_secs(1));
                            }
                        }
                    }
                }
            }

            _ = snapshot_export_timer.tick() => {
                prune_snapshot_export_leases(&mut snapshot_export_leases);
                refresh_snapshot_object_retention_floor(
                    &chain_store,
                    &snapshot_export_leases,
                );
                prune_snapshot_exports(&mut snapshot_exports, &snapshot_export_leases);
                if snapshot_export_inflight.is_none() {
                    let candidate = local_history_step_boundary(&chain_store).and_then(|key| {
                        if snapshot_exports.contains_key(&key) {
                            None
                        } else {
                            let previous = snapshot_exports
                                .iter()
                                .filter(|((height, _), _)| *height < key.0)
                                .max_by_key(|((height, _), _)| *height)
                                .map(|(_, generation)| Arc::clone(generation));
                            Some((key, chain_store.clone(), previous))
                        }
                    });
                    if let Some((key, store, previous)) = candidate {
                        snapshot_export_inflight = Some(key);
                        let export_root = snapshot_export_root.clone();
                        let completion = snapshot_export_tx.clone();
                        tokio::task::spawn_blocking(move || {
                            let result = export_snapshot_boundary_generation(
                                &store,
                                &export_root,
                                key.0,
                                previous.as_ref().map(|entry| &entry.generation),
                            );
                            let _ = completion.blocking_send((key, result));
                        });
                    }
                }
            }

            _ = reactor_health_timer.tick() => {
                let queues = required_event_tx.queue_depths();
                let pending_requests = pending_retained_block_requests.len()
                    + pending_network_profile_requests.len()
                    + pending_object_requests.len()
                    + pending_header_requests.len()
                    + pending_state_manifest_requests.len()
                    + pending_state_segment_requests.len()
                    + pending_history_step_requests.len();
                let outbound_bytes_in_use =
                    crate::outbound_budget::OUTBOUND_RESPONSE_BUDGET_BYTES
                        .saturating_sub(outbound_response_budget.available_bytes());
                data_plane_serving.prune(|peer| swarm.is_connected(peer));
                let active_data_serving_slots = data_plane_serving.active_slots();
                let outstanding_data_serving_slots = data_plane_serving.outstanding_slots();
                if queues.control != 0 || queues.header != 0 {
                    tracing::warn!(
                        control_queue = queues.control,
                        header_queue = queues.header,
                        live_queue = queues.live,
                        historical_queue = queues.historical,
                        background_queue = queues.background,
                        queue_total = queues.total(),
                        pending_requests,
                        outbound_bytes_in_use,
                        active_data_serving_slots,
                        outstanding_data_serving_slots,
                        "P2P control-plane queue pressure"
                    );
                } else {
                    tracing::debug!(
                        live_queue = queues.live,
                        historical_queue = queues.historical,
                        background_queue = queues.background,
                        queue_total = queues.total(),
                        pending_requests,
                        outbound_bytes_in_use,
                        active_data_serving_slots,
                        outstanding_data_serving_slots,
                        "P2P reactor health"
                    );
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
                        &mut mempool_sync_retries,
                        &required_event_tx,
                        &mut pending_retained_block_requests,
                        &mut pending_object_requests,
                        &mut pending_header_requests,
                        &mut pending_state_manifest_requests,
                        &mut pending_state_segment_requests,
                        &mut pending_history_step_requests,
                        &mut automatic_peers,
                        &sync_paths,
                    )
                    .await,
                    None => break, // cmd_tx dropped
                }
            }

            // Periodic Kademlia random walk for topology health.
            _ = kad_walk_interval.tick() => {
                if automatic_peers.kad_bootstrap_started
                    && !automatic_peers.discovery_active()
                {
                    let query = swarm
                        .behaviour_mut()
                        .kad
                        .get_closest_peers(libp2p::PeerId::random());
                    automatic_peers.begin_discovery(query);
                    tracing::debug!("kad: periodic random walk");
                }
            }

            _ = automatic_peer_timer.tick() => {
                let now = Instant::now();
                let mut wedged_sync_peers = std::collections::HashSet::new();

                let expired_profiles = pending_network_profile_requests.take_where_entries(
                    |request| {
                        now.saturating_duration_since(request.issued_at)
                            >= NETWORK_PROFILE_PENDING_DEADLINE
                    },
                );
                for (request_id, request) in expired_profiles {
                    let transport_stuck = swarm
                        .behaviour()
                        .network_profile_sync
                        .is_pending_outbound(&request.peer, &request_id);
                    tracing::warn!(
                        peer = %request.peer,
                        transport_stuck,
                        "network-v3 profile handshake timed out"
                    );
                    let _ = swarm.disconnect_peer_id(request.peer);
                }

                let expired_objects = pending_object_requests.take_where_entries(|request| {
                    now.saturating_duration_since(request.issued_at) >= OBJECT_PENDING_DEADLINE
                });
                for (request_id, request) in expired_objects {
                    let transport_stuck = swarm
                        .behaviour()
                        .object_sync
                        .is_pending_outbound(&request.peer, &request_id);
                    tracing::warn!(
                        peer = %request.peer,
                        token = request.token,
                        transport_stuck,
                        "exact-object request exceeded its complete local deadline"
                    );
                    let _ = required_event_tx
                        .send(NetworkEvent::ObjectsRequestFailed {
                            token: request.token,
                            from: request.peer,
                            objects: request.objects,
                            kind: RequestFailureKind::Timeout,
                        })
                        .await;
                    if transport_stuck {
                        wedged_sync_peers.insert(request.peer);
                    }
                }

                let expired_blocks = pending_retained_block_requests.take_where_entries(
                    |request| {
                        now.saturating_duration_since(request.issued_at)
                            >= SMALL_SYNC_PENDING_DEADLINE
                    },
                );
                for (request_id, request) in expired_blocks {
                    let transport_stuck = swarm
                        .behaviour()
                        .block_sync
                        .is_pending_outbound(&request.peer, &request_id);
                    if transport_stuck {
                        tracing::warn!(
                            protocol = "block",
                            peer = %request.peer,
                            height = request.height,
                            count = request.count,
                            payload = ?request.payload_kind,
                            active = request.notify_node,
                            "sync request exceeded its complete local deadline"
                        );
                        wedged_sync_peers.insert(request.peer);
                    }
                    if request.notify_node {
                        let _ = required_event_tx
                            .send(NetworkEvent::RecentBlockRequestFailed {
                                from: request.peer,
                                height: request.height,
                                payload_kind: request.payload_kind,
                            })
                            .await;
                    }
                }

                let expired_headers = pending_header_requests.take_where_entries(|request| {
                    now.saturating_duration_since(request.issued_at)
                        >= SMALL_SYNC_PENDING_DEADLINE
                });
                for (request_id, request) in expired_headers {
                    let transport_stuck = swarm
                        .behaviour()
                        .chain_sync
                        .is_pending_outbound(&request.peer, &request_id);
                    if transport_stuck {
                        tracing::warn!(
                            protocol = "headers",
                            peer = %request.peer,
                            start_height = request.start_height,
                            count = request.count,
                            kind = ?request.kind,
                            active = request.notify_node,
                            "sync request exceeded its complete local deadline"
                        );
                        wedged_sync_peers.insert(request.peer);
                    }
                    if request.notify_node {
                        match request.kind {
                            HeaderRequestKind::General => {
                                let _ = required_event_tx
                                    .send(NetworkEvent::HeadersRequestFailed {
                                        from: request.peer,
                                        start_height: request.start_height,
                                        count: request.count,
                                    })
                                    .await;
                            }
                            HeaderRequestKind::Snapshot { generation, token } => {
                                let _ = required_event_tx
                                    .send(NetworkEvent::SnapshotHeadersRequestFailed {
                                        generation,
                                        token,
                                        from: request.peer,
                                        start_height: request.start_height,
                                        count: request.count,
                                        kind: RequestFailureKind::Timeout,
                                    })
                                    .await;
                            }
                        }
                    }
                }

                let expired_manifests = pending_state_manifest_requests.take_where_entries(
                    |request| {
                        now.saturating_duration_since(request.issued_at)
                            >= SMALL_SYNC_PENDING_DEADLINE
                    },
                );
                for (request_id, request) in expired_manifests {
                    let transport_stuck = swarm
                        .behaviour()
                        .state_manifest_sync
                        .is_pending_outbound(&request.peer, &request_id);
                    if transport_stuck {
                        tracing::warn!(
                            protocol = "manifest",
                            peer = %request.peer,
                            generation = request.generation,
                            requester_height = request.requester_height,
                            active = request.notify_node,
                            "sync request exceeded its complete local deadline"
                        );
                        wedged_sync_peers.insert(request.peer);
                    }
                    if request.notify_node {
                        let _ = required_event_tx
                            .send(NetworkEvent::StateManifestRequestFailed {
                                generation: request.generation,
                                from: request.peer,
                                requester_height: request.requester_height,
                                kind: RequestFailureKind::Timeout,
                            })
                            .await;
                    }
                }

                let expired_segments = pending_state_segment_requests.take_where_entries(
                    |request| {
                        now.saturating_duration_since(request.issued_at)
                            >= STATE_SEGMENT_PENDING_DEADLINE
                    },
                );
                for (request_id, request) in expired_segments {
                    let transport_stuck = swarm
                        .behaviour()
                        .state_segment_sync
                        .is_pending_outbound(&request.peer, &request_id);
                    if transport_stuck {
                        tracing::warn!(
                            protocol = "segment",
                            peer = %request.peer,
                            segment = request.segment_id,
                            snapshot_height = request.expected_tip_height,
                            active = request.notify_node,
                            "sync request exceeded its complete local deadline"
                        );
                        wedged_sync_peers.insert(request.peer);
                    }
                    if request.notify_node {
                        let _ = required_event_tx
                            .send(NetworkEvent::StateSegmentRequestFailed {
                                from: request.peer,
                                segment_id: request.segment_id,
                                expected_tip_height: request.expected_tip_height,
                                expected_tip_hash: request.expected_tip_hash,
                                manifest_digest: request.manifest_digest,
                            })
                            .await;
                    }
                }

                let expired_terminals = pending_history_step_requests.take_where_entries(
                    |request| {
                        now.saturating_duration_since(request.issued_at)
                            >= HISTORY_STEP_PENDING_DEADLINE
                    },
                );
                for (request_id, request) in expired_terminals {
                    if swarm
                        .behaviour()
                        .history_step_sync
                        .is_pending_outbound(&request.peer, &request_id)
                    {
                        wedged_sync_peers.insert(request.peer);
                    }
                    tracing::warn!(
                        token = request.token,
                        peer = %request.peer,
                        height = request.height,
                        "HistoryStep terminal request exceeded its complete local deadline"
                    );
                    if request.notify_node {
                        let _ = required_event_tx
                            .send(NetworkEvent::HistoryStepTerminalRequestFailed {
                                token: request.token,
                                from: request.peer,
                                height: request.height,
                                block_hash: request.block_hash,
                                kind: RequestFailureKind::Timeout,
                            })
                            .await;
                    }
                }
                for peer in wedged_sync_peers {
                    tracing::warn!(
                        peer = %peer,
                        "closing connection to flush a sync request stuck before its transport timeout"
                    );
                    let _ = swarm.disconnect_peer_id(peer);
                }
                maintain_automatic_outbound(
                    &mut swarm,
                    &mut automatic_peers,
                    &peer_diversity,
                );
                let under_target = automatic_peers
                    .outbound_peer_count()
                    // A slow or unresolved DNS seed is only a probe. It must
                    // not suppress discovery of a real ordinary neighbour.
                    .saturating_add(automatic_peers.pending_ordinary_count())
                    < AUTOMATIC_OUTBOUND_TARGET;
                if under_target
                    && swarm.connected_peers().next().is_some()
                    && automatic_peers.kad_bootstrap_started
                    && !automatic_peers.discovery_active()
                    && Instant::now() >= automatic_peers.next_discovery_at
                {
                    let query = swarm
                        .behaviour_mut()
                        .kad
                        .get_closest_peers(libp2p::PeerId::random());
                    automatic_peers.begin_discovery(query);
                    tracing::debug!(
                        outbound = automatic_peers.outbound_peer_count(),
                        pending = automatic_peers.pending.len(),
                        target = AUTOMATIC_OUTBOUND_TARGET,
                        "kad: accelerated lookup below outbound target"
                    );
                }
            }

            // Persist only peers confirmed by successful outbound transport.
            _ = peer_store_timer.tick() => {
                let cache = successful_peer_cache.clone();
                let data_dir = data_dir.clone();
                tokio::task::spawn_blocking(move || {
                    crate::peer_store::save(&data_dir, &cache);
                });
            }

            // Recover a mempool exchange rejected during a busy simultaneous
            // multi-peer handshake. State is bounded by connected PeerIds,
            // attempts are finite, and local+remote jitter spreads clients
            // requesting the same server across timer ticks.
            _ = mempool_retry_timer.tick() => {
                let mempool_now = Instant::now();
                let retry_peers: Vec<_> = mempool_sync_retries
                    .iter()
                    .filter(|(peer, retry)| {
                        mempool_now >= retry.next_attempt
                            && sync_paths.is_dispatchable(**peer)
                    })
                    .map(|(peer, retry)| (*peer, retry.failures))
                    .collect();
                mempool_sync_retries.retain(|peer, _| swarm.is_connected(peer));
                for (peer, failures) in retry_peers {
                    let _ = swarm
                        .behaviour_mut()
                        .mempool_sync
                        .send_request(&peer, MempoolRequest::Pull);
                    mempool_sync_last_request.insert(peer, mempool_now);
                    if let Some(retry) = mempool_sync_retries.get_mut(&peer) {
                        // Do not issue a duplicate while the request-response
                        // timeout is still in flight.
                        retry.next_attempt = mempool_now + MEMPOOL_SYNC_RETRY_INFLIGHT;
                    }
                    tracing::debug!(peer = %peer, failures, "retrying mempool sync");
                }
            }
        }
    }
    crate::peer_store::save(&data_dir, &successful_peer_cache);
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
                let key = generation.key();
                if let Some(export) = SnapshotExportEntry::new(generation) {
                    exports.insert(key, Arc::new(export));
                } else {
                    tracing::warn!(
                        height = key.0,
                        "ignoring snapshot generation with invalid network manifest identity"
                    );
                }
            }
            Err(error) => {
                tracing::warn!(path = %entry.path().display(), err = %error, "ignoring invalid snapshot generation");
            }
        }
    }
    exports
}

fn prune_snapshot_export_leases(
    leases: &mut std::collections::HashMap<PeerId, SnapshotExportLease>,
) {
    let now = Instant::now();
    leases.retain(|_, lease| now.duration_since(lease.last_activity) <= SNAPSHOT_EXPORT_LEASE_TTL);
}

fn refresh_snapshot_object_retention_floor(
    store: &MdbxStore,
    leases: &std::collections::HashMap<PeerId, SnapshotExportLease>,
) {
    store.set_block_body_object_retention_floor(leases.values().map(|lease| lease.key.0).min());
}

fn lease_snapshot_export(
    leases: &mut std::collections::HashMap<PeerId, SnapshotExportLease>,
    peer: PeerId,
    key: SnapshotExportKey,
    manifest_digest: [u8; 32],
) -> bool {
    prune_snapshot_export_leases(leases);
    if MAX_SNAPSHOT_EXPORTS == 0 {
        return false;
    }
    let mut distinct_other_keys = leases
        .iter()
        .filter(|(leased_peer, _)| **leased_peer != peer)
        .map(|(_, lease)| lease.key)
        .collect::<std::collections::HashSet<_>>();
    while !distinct_other_keys.contains(&key) && distinct_other_keys.len() >= MAX_SNAPSHOT_EXPORTS {
        // A connected client may keep refreshing an obsolete generation while
        // retrying a failed suffix.  Letting that activity renew the lease
        // forever allows two stalled clients to deny every later bootstrap
        // request.  Retire the oldest pinned generation when a fresh exact
        // generation needs admission.  Requests still holding an Arc finish
        // safely; subsequent exact requests fail closed and the node FSM
        // reacquires a current manifest.
        let Some(oldest_key) = distinct_other_keys
            .iter()
            .copied()
            .min_by_key(|(height, _)| *height)
        else {
            return false;
        };
        leases.retain(|_, lease| lease.key != oldest_key);
        distinct_other_keys.remove(&oldest_key);
        tracing::info!(
            retired_snapshot_height = oldest_key.0,
            replacement_snapshot_height = key.0,
            "retiring obsolete snapshot lease for fresh bootstrap admission"
        );
    }
    leases.insert(
        peer,
        SnapshotExportLease {
            key,
            manifest_digest,
            last_activity: Instant::now(),
        },
    );
    true
}

fn prune_snapshot_exports(
    exports: &mut std::collections::HashMap<SnapshotExportKey, SnapshotExport>,
    leases: &std::collections::HashMap<PeerId, SnapshotExportLease>,
) {
    let protected = leases
        .values()
        .map(|lease| lease.key)
        .collect::<std::collections::HashSet<_>>();
    let mut keys: Vec<_> = exports.keys().copied().collect();
    keys.sort_unstable_by_key(|(height, _)| std::cmp::Reverse(*height));
    let mut unprotected_kept = 0usize;
    for key in keys {
        if protected.contains(&key) {
            continue;
        }
        unprotected_kept += 1;
        if unprotected_kept <= MAX_SNAPSHOT_EXPORTS {
            continue;
        }
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

#[derive(Debug)]
struct GossipByteWindow {
    bytes: usize,
    started_at: Instant,
}

impl GossipByteWindow {
    fn new() -> Self {
        Self {
            bytes: 0,
            started_at: Instant::now(),
        }
    }

    fn admit(&mut self, bytes: usize, max_bytes: usize, window: Duration) -> bool {
        let now = Instant::now();
        if now.duration_since(self.started_at) > window {
            self.bytes = 0;
            self.started_at = now;
        }
        let Some(next) = self.bytes.checked_add(bytes) else {
            return false;
        };
        if next > max_bytes {
            return false;
        }
        self.bytes = next;
        true
    }
}

fn report_gossip_validation(
    swarm: &mut libp2p::Swarm<NodeBehaviour>,
    message_id: &gossipsub::MessageId,
    propagation_source: &PeerId,
    acceptance: gossipsub::MessageAcceptance,
) {
    if let Err(error) = swarm
        .behaviour_mut()
        .gossipsub
        .report_message_validation_result(message_id, propagation_source, acceptance)
    {
        tracing::debug!(
            peer = %propagation_source,
            message = %message_id,
            %error,
            "GossipSub validation result could not be applied"
        );
    }
}

fn is_routable_identify_addr(addr: &Multiaddr) -> bool {
    // DNS names advertised by an untrusted peer are cheap aliases around one
    // attacker-controlled host and bypass IP-group diversity. Explicit DNS
    // seeds remain supported by the node CLI; Identify learns only resolved,
    // globally-routable transport addresses.
    crate::peer_diversity::contains_public_ip(addr)
}

fn sanitize_automatic_peer_addr(peer: PeerId, mut addr: Multiaddr) -> Option<Multiaddr> {
    if let Some(libp2p::multiaddr::Protocol::P2p(advertised_peer)) = addr.iter().last() {
        if advertised_peer != peer {
            return None;
        }
        addr.pop();
    }
    let has_tcp = addr
        .iter()
        .any(|protocol| matches!(protocol, libp2p::multiaddr::Protocol::Tcp(port) if port != 0));
    (is_routable_identify_addr(&addr) && has_tcp).then_some(addr)
}

fn begin_bootstrap_dial(
    swarm: &mut libp2p::Swarm<NodeBehaviour>,
    automatic: &mut AutomaticPeerState,
    addr: Multiaddr,
    peer: Option<PeerId>,
) -> bool {
    let options = if let Some(peer) = peer {
        libp2p::swarm::dial_opts::DialOpts::peer_id(peer)
            .condition(libp2p::swarm::dial_opts::PeerCondition::DisconnectedAndNotDialing)
            .addresses(vec![addr.clone()])
            .build()
    } else {
        libp2p::swarm::dial_opts::DialOpts::unknown_peer_id()
            .address(addr.clone())
            .build()
    };
    let connection_id = options.connection_id();
    automatic
        .pending
        .insert(connection_id, PendingAutomaticDial::Bootstrap(addr.clone()));
    match swarm.dial(options) {
        Ok(()) => {
            tracing::debug!(address = %addr, "automatic bootstrap dial started");
            true
        }
        Err(error) => {
            automatic.note_dial_failed(connection_id);
            tracing::debug!(address = %addr, err = %error, "automatic bootstrap dial rejected");
            false
        }
    }
}

fn begin_peer_dial(
    swarm: &mut libp2p::Swarm<NodeBehaviour>,
    automatic: &mut AutomaticPeerState,
    peer: PeerId,
    addr: Multiaddr,
    group: PublicNetworkGroup,
) -> bool {
    let options = libp2p::swarm::dial_opts::DialOpts::peer_id(peer)
        .condition(libp2p::swarm::dial_opts::PeerCondition::DisconnectedAndNotDialing)
        .addresses(vec![addr])
        .build();
    let connection_id = options.connection_id();
    automatic
        .pending
        .insert(connection_id, PendingAutomaticDial::Peer { peer, group });
    match swarm.dial(options) {
        Ok(()) => {
            tracing::debug!(peer = %peer, "automatic peer dial started");
            true
        }
        Err(error) => {
            automatic.note_dial_failed(connection_id);
            tracing::debug!(peer = %peer, err = %error, "automatic peer dial rejected");
            false
        }
    }
}

fn maintain_automatic_outbound(
    swarm: &mut libp2p::Swarm<NodeBehaviour>,
    automatic: &mut AutomaticPeerState,
    peer_diversity: &PeerDiversity,
) {
    let now = Instant::now();
    automatic.refresh_healthy_connections(now);
    let expired_unidentified = automatic.expired_unidentified_connections(now);
    if !expired_unidentified.is_empty() {
        for (connection_id, peer) in expired_unidentified {
            if swarm.close_connection(connection_id) {
                tracing::debug!(
                    peer = %peer,
                    "closing automatic outbound connection that did not identify in time"
                );
            }
        }
        // Let the close events retire their exact transport records before
        // starting replacement dials on the next two-second maintenance tick.
        return;
    }
    let stable_non_bootstrap = automatic.stable_non_bootstrap_peer_count(now);
    let desired_bootstrap = desired_bootstrap_connections(
        automatic.bootstrap_complete,
        stable_non_bootstrap,
        automatic.bootstrap.len(),
    );
    let connected_bootstrap = automatic.connected_bootstrap_peer_ids();
    let bootstrap_peers = automatic.bootstrap_peer_ids();

    // `desired_bootstrap` falls to zero only after a stable ordinary
    // replacement exists. Extra bootstrap transports can therefore be closed
    // immediately without waiting for the complete twelve-peer target; that
    // target is filled independently from Kademlia below.
    let release_seed = connected_bootstrap.len() > desired_bootstrap;
    let release_ordinary =
        !release_seed && automatic.outbound_peer_count() > AUTOMATIC_OUTBOUND_TARGET;
    if release_seed || release_ordinary {
        let mut releasable = automatic
            .managed_connections
            .iter()
            .filter(|(_, connection)| {
                if release_seed {
                    bootstrap_peers.contains(&connection.peer)
                } else {
                    matches!(connection.kind, ManagedOutboundKind::Peer)
                        && !bootstrap_peers.contains(&connection.peer)
                }
            })
            .map(|(connection_id, connection)| (*connection_id, connection.peer))
            .collect::<Vec<_>>();
        releasable.shuffle(&mut rand::thread_rng());
        if let Some((connection_id, peer)) = releasable.first().copied() {
            if release_seed {
                // Do not let later Kademlia maintenance immediately redial a
                // seed that has just handed us off to ordinary neighbours.
                swarm.behaviour_mut().kad.remove_peer(&peer);
            }
            if swarm.close_connection(connection_id) {
                tracing::debug!(
                    peer = %peer,
                    desired_bootstrap,
                    "released replaced automatic outbound connection"
                );
            }
        }
        return;
    }

    let pending_capacity = automatic.automatic_dial_capacity();
    if pending_capacity == 0 {
        return;
    }

    let pending_bootstrap = automatic.pending_bootstrap_count();
    // Pending DNS work is not connectivity. Start a small staggered reserve
    // probe on later maintenance ticks instead of waiting for one dead seed's
    // transport timeout before trying the next hostname.
    let bootstrap_needed = desired_bootstrap.saturating_sub(connected_bootstrap.len());
    if bootstrap_needed > 0 {
        let occupied = automatic
            .outbound_peer_count()
            .saturating_add(automatic.pending.len());
        let available = bootstrap_probe_capacity(
            desired_bootstrap,
            connected_bootstrap.len(),
            pending_bootstrap,
            pending_capacity,
            AUTOMATIC_OUTBOUND_TARGET
                .saturating_add(1)
                .saturating_sub(occupied),
        );
        let pending_addrs = automatic
            .pending
            .values()
            .filter_map(|pending| match pending {
                PendingAutomaticDial::Bootstrap(addr) => Some(addr.clone()),
                PendingAutomaticDial::Peer { .. } => None,
            })
            .collect::<std::collections::HashSet<_>>();
        let mut due = automatic
            .bootstrap
            .iter()
            .filter(|(addr, candidate)| {
                candidate.next_attempt <= now
                    && !pending_addrs.contains(*addr)
                    && candidate.peer.is_none_or(|peer| !swarm.is_connected(&peer))
            })
            .map(|(addr, candidate)| (addr.clone(), candidate.peer))
            .collect::<Vec<_>>();
        due.shuffle(&mut rand::thread_rng());
        for (addr, peer) in due.into_iter().take(available) {
            begin_bootstrap_dial(swarm, automatic, addr, peer);
        }
    }

    let pending_peers = automatic
        .pending
        .values()
        .filter_map(|pending| match pending {
            PendingAutomaticDial::Peer { peer, .. } => Some(*peer),
            PendingAutomaticDial::Bootstrap(_) => None,
        })
        .collect::<std::collections::HashSet<_>>();
    let mut candidates = automatic
        .peers
        .iter()
        .filter(|(peer, candidate)| {
            candidate.next_attempt <= now
                && !candidate.addrs.is_empty()
                && !bootstrap_peers.contains(peer)
                && !pending_peers.contains(peer)
                && !swarm.is_connected(peer)
        })
        .map(|(peer, candidate)| (*peer, candidate.addrs.clone()))
        .collect::<Vec<_>>();
    candidates.shuffle(&mut rand::thread_rng());

    let pending_ordinary = automatic.pending_ordinary_count();
    // A slow DNS bootstrap attempt must not hold a real neighbour slot
    // hostage. If it later succeeds above target, the swap branch releases
    // one ordinary connection without ever dropping below target.
    let mut available = automatic_ordinary_dial_capacity(
        automatic.outbound_peer_count(),
        pending_ordinary,
        connected_bootstrap.len() > desired_bootstrap,
        automatic.automatic_dial_capacity(),
    );
    for (peer, mut addrs) in candidates {
        if available == 0 {
            break;
        }
        addrs.shuffle(&mut rand::thread_rng());
        let selected = addrs.into_iter().find_map(|addr| {
            let group = crate::peer_diversity::public_network_group(&addr)?;
            let pending_same_group = automatic.pending_group_count(group);
            peer_diversity
                .outbound_candidate_allowed_with_pending(peer, &addr, pending_same_group)
                .then_some((addr, group))
        });
        let Some((addr, group)) = selected else {
            continue;
        };
        if begin_peer_dial(swarm, automatic, peer, addr, group) {
            available -= 1;
        }
    }
}

fn desired_bootstrap_connections(
    bootstrap_complete: bool,
    stable_non_bootstrap: usize,
    configured_bootstraps: usize,
) -> usize {
    let fanout = INITIAL_BOOTSTRAP_FANOUT.min(configured_bootstraps);
    if !bootstrap_complete {
        return fanout;
    }
    // Once sync is complete, one independently discovered connection replaces
    // the bootstrap transport. The replacement is established first by the
    // caller, so releasing the seed never creates a connectivity gap.
    fanout.saturating_sub(stable_non_bootstrap)
}

/// Pending DNS transports are probes, not authenticated connectivity. Keep
/// opening staggered alternatives until the desired number is established,
/// while the hard pending and transport caps bound simultaneous work.
fn bootstrap_probe_capacity(
    desired: usize,
    connected: usize,
    pending: usize,
    transport_capacity: usize,
    target_capacity: usize,
) -> usize {
    desired
        .saturating_sub(connected)
        .min(MAX_PENDING_BOOTSTRAP_DIALS.saturating_sub(pending))
        .min(transport_capacity)
        .min(target_capacity)
}

fn automatic_ordinary_dial_capacity(
    outbound_peers: usize,
    pending_ordinary: usize,
    seed_replacement_needed: bool,
    transport_capacity: usize,
) -> usize {
    let occupied = outbound_peers.saturating_add(pending_ordinary);
    let replacement = usize::from(seed_replacement_needed && occupied >= AUTOMATIC_OUTBOUND_TARGET);
    AUTOMATIC_OUTBOUND_TARGET
        .saturating_add(replacement)
        .saturating_sub(occupied)
        .min(transport_capacity)
}

/// Process a single network command. Separated from the select! loop so that
/// pending commands can be drained via `try_recv` before blocking.
async fn handle_network_command(
    swarm: &mut libp2p::Swarm<NodeBehaviour>,
    cmd: NetworkCommand,
    topics: &NetworkTopics,
    mempool_sync_last_request: &mut std::collections::HashMap<PeerId, Instant>,
    mempool_sync_retries: &mut std::collections::HashMap<PeerId, MempoolSyncRetry>,
    required_event_tx: &RequiredEventSender,
    pending_retained_block_requests: &mut BoundedPendingRequests<
        request_response::OutboundRequestId,
        PendingRetainedBlockRequest,
    >,
    pending_object_requests: &mut BoundedPendingRequests<
        request_response::OutboundRequestId,
        PendingObjectRequest,
    >,
    pending_header_requests: &mut BoundedPendingRequests<
        request_response::OutboundRequestId,
        PendingHeaderRequest,
    >,
    pending_state_manifest_requests: &mut BoundedPendingRequests<
        request_response::OutboundRequestId,
        PendingStateManifestRequest,
    >,
    pending_state_segment_requests: &mut BoundedPendingRequests<
        request_response::OutboundRequestId,
        PendingStateSegmentRequest,
    >,
    pending_history_step_requests: &mut BoundedPendingRequests<
        request_response::OutboundRequestId,
        PendingHistoryStepTerminalRequest,
    >,
    automatic_peers: &mut AutomaticPeerState,
    sync_paths: &PeerSyncPaths,
) {
    match cmd {
        NetworkCommand::AnnounceBlock { bundle } => {
            let height = bundle.height();
            let message = match HeaderAnnouncement::from_accepted_bundle(
                &bundle,
                ProviderFlags::new(true, true, false),
            )
            .and_then(HeaderAnnouncement::encode)
            {
                Ok(message) => message,
                Err(error) => {
                    tracing::error!(height, %error, "refusing to announce an invalid local block object set");
                    return;
                }
            };
            let topic = gossipsub::IdentTopic::new(topics.blocks.clone());
            if let Err(error) = swarm
                .behaviour_mut()
                .gossipsub
                .publish(topic, message.to_vec())
            {
                tracing::debug!(height, err = %error, "gossipsub: block announcement");
            }
        }
        NetworkCommand::BroadcastTx { intent_bytes } => {
            let topic = gossipsub::IdentTopic::new(topics.txs.clone());
            let gossip_result = swarm
                .behaviour_mut()
                .gossipsub
                .publish(topic, intent_bytes.as_ref().to_vec());
            if let Err(error) = &gossip_result {
                tracing::debug!(err = %error, "gossipsub: transaction publish");
            }

            let mut connected: Vec<_> = swarm
                .connected_peers()
                .copied()
                .filter(|peer| sync_paths.is_dispatchable(*peer))
                .collect();
            let direct_limit = direct_tx_relay_limit(connected.len());
            if direct_limit > 0 {
                connected.shuffle(&mut rand::thread_rng());
                connected.truncate(direct_limit);
                for peer in connected {
                    let _ = swarm.behaviour_mut().mempool_sync.send_request(
                        &peer,
                        MempoolRequest::Push {
                            intent_bytes: intent_bytes.as_ref().to_vec(),
                            inbound_memory_permit: None,
                        },
                    );
                }
                tracing::debug!(
                    peers = direct_limit,
                    gossip_ok = gossip_result.is_ok(),
                    "direct transaction relay queued"
                );
            }
        }
        NetworkCommand::Dial { addr } => {
            tracing::debug!(address = %addr, "registered automatic bootstrap candidate");
            automatic_peers.register_bootstrap(addr);
        }
        NetworkCommand::BootstrapComplete => {
            automatic_peers.bootstrap_complete = true;
            tracing::debug!("initial synchronization complete — bootstrap peers are releasable");
        }
        NetworkCommand::PeerCount { reply } => {
            let count = sync_paths.dispatchable_peer_count();
            let _ = reply.send(count);
        }
        NetworkCommand::FetchObjects {
            token,
            peer,
            objects,
        } => {
            let shape_valid = !objects.is_empty()
                && objects.len() <= crate::object_protocol::MAX_OBJECTS_PER_REQUEST
                && objects
                    .iter()
                    .all(|object| object.is_live_transfer_object())
                && {
                    let terminal_count = objects
                        .iter()
                        .filter(|object| matches!(object, ObjectId::Terminal(_)))
                        .count();
                    terminal_count == 0 || (terminal_count == 1 && objects.len() == 1)
                }
                && objects
                    .iter()
                    .try_fold(0usize, |total, object| {
                        total.checked_add(object.encoded_len()? as usize)
                    })
                    .is_some_and(|total| {
                        total <= crate::object_protocol::MAX_OBJECT_RESPONSE_PAYLOAD_BYTES
                    })
                && objects
                    .iter()
                    .copied()
                    .collect::<std::collections::HashSet<_>>()
                    .len()
                    == objects.len();
            if !shape_valid || !sync_paths.is_dispatchable(peer) {
                let _ = required_event_tx
                    .send(NetworkEvent::ObjectsRequestFailed {
                        token,
                        from: peer,
                        objects,
                        kind: if shape_valid {
                            RequestFailureKind::ConnectionClosed
                        } else {
                            RequestFailureKind::InvalidResponse
                        },
                    })
                    .await;
                return;
            }
            if !pending_object_requests.has_capacity() {
                let _ = required_event_tx
                    .send(NetworkEvent::ObjectsRequestFailed {
                        token,
                        from: peer,
                        objects,
                        kind: RequestFailureKind::Timeout,
                    })
                    .await;
                return;
            }
            let request_id = swarm.behaviour_mut().object_sync.send_request(
                &peer,
                GetObjectsRequest {
                    objects: objects.clone(),
                },
            );
            let inserted = pending_object_requests.try_insert(
                request_id,
                PendingObjectRequest {
                    token,
                    peer,
                    objects,
                    issued_at: Instant::now(),
                },
            );
            debug_assert!(inserted, "object capacity checked before request");
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
                if !sync_paths.is_dispatchable(peer) {
                    let _ = required_event_tx
                        .send(NetworkEvent::RecentBlockRequestFailed {
                            from: peer,
                            height: h,
                            payload_kind: RecentBlockPayloadKind::Complete,
                        })
                        .await;
                    break;
                }
                pending_retained_block_requests.retain(|_, pending| {
                    if pending.peer == peer
                        && pending.height == h
                        && pending.count == 1
                        && pending.payload_kind == RecentBlockPayloadKind::Complete
                    {
                        pending.notify_node = false;
                    }
                    true
                });
                if !pending_retained_block_requests.has_capacity() {
                    tracing::warn!(
                        peer = %peer,
                        height = h,
                        limit = MAX_PENDING_RETAINED_BLOCK_REQUESTS,
                        "retained-block request correlation table full"
                    );
                    let _ = required_event_tx
                        .send(NetworkEvent::RecentBlockRequestFailed {
                            from: peer,
                            height: h,
                            payload_kind: RecentBlockPayloadKind::Complete,
                        })
                        .await;
                    break;
                }
                let request_id = swarm.behaviour_mut().block_sync.send_request(
                    &peer,
                    crate::protocol::GetRecentBlockRequest {
                        height: h,
                        count: 1,
                        payload_kind: RecentBlockPayloadKind::Complete,
                    },
                );
                let inserted = pending_retained_block_requests.try_insert(
                    request_id,
                    PendingRetainedBlockRequest {
                        peer,
                        height: h,
                        count: 1,
                        payload_kind: RecentBlockPayloadKind::Complete,
                        issued_at: Instant::now(),
                        notify_node: true,
                    },
                );
                debug_assert!(inserted, "fresh block-sync request ID must be unique");
            }
        }
        NetworkCommand::RequestBlock { peer, height } => {
            if !sync_paths.is_dispatchable(peer) {
                let _ = required_event_tx
                    .send(NetworkEvent::RecentBlockRequestFailed {
                        from: peer,
                        height,
                        payload_kind: RecentBlockPayloadKind::Complete,
                    })
                    .await;
                return;
            }
            pending_retained_block_requests.retain(|_, pending| {
                if pending.peer == peer
                    && pending.height == height
                    && pending.count == 1
                    && pending.payload_kind == RecentBlockPayloadKind::Complete
                {
                    pending.notify_node = false;
                }
                true
            });
            if !pending_retained_block_requests.has_capacity() {
                tracing::warn!(
                    peer = %peer,
                    height,
                    limit = MAX_PENDING_RETAINED_BLOCK_REQUESTS,
                    "retained-block request correlation table full"
                );
                let _ = required_event_tx
                    .send(NetworkEvent::RecentBlockRequestFailed {
                        from: peer,
                        height,
                        payload_kind: RecentBlockPayloadKind::Complete,
                    })
                    .await;
                return;
            }
            let request_id = swarm.behaviour_mut().block_sync.send_request(
                &peer,
                crate::protocol::GetRecentBlockRequest {
                    height,
                    count: 1,
                    payload_kind: RecentBlockPayloadKind::Complete,
                },
            );
            let inserted = pending_retained_block_requests.try_insert(
                request_id,
                PendingRetainedBlockRequest {
                    peer,
                    height,
                    count: 1,
                    payload_kind: RecentBlockPayloadKind::Complete,
                    issued_at: Instant::now(),
                    notify_node: true,
                },
            );
            debug_assert!(inserted, "fresh block-sync request ID must be unique");
        }
        NetworkCommand::RequestBlockBodies {
            peer,
            height,
            count,
        } => {
            if count == 0 || count > crate::protocol::MAX_BLOCK_BODY_BATCH {
                tracing::warn!(
                    peer = %peer,
                    height,
                    count,
                    "invalid snapshot block-body batch request"
                );
                let _ = required_event_tx
                    .send(NetworkEvent::RecentBlockRequestFailed {
                        from: peer,
                        height,
                        payload_kind: RecentBlockPayloadKind::BlockBody,
                    })
                    .await;
                return;
            }
            if !sync_paths.is_dispatchable(peer) {
                let _ = required_event_tx
                    .send(NetworkEvent::RecentBlockRequestFailed {
                        from: peer,
                        height,
                        payload_kind: RecentBlockPayloadKind::BlockBody,
                    })
                    .await;
                return;
            }
            pending_retained_block_requests.retain(|_, pending| {
                if pending.peer == peer
                    && pending.height == height
                    && pending.count == count
                    && pending.payload_kind == RecentBlockPayloadKind::BlockBody
                {
                    pending.notify_node = false;
                }
                true
            });
            if !pending_retained_block_requests.has_capacity() {
                tracing::warn!(
                    peer = %peer,
                    height,
                    count,
                    limit = MAX_PENDING_RETAINED_BLOCK_REQUESTS,
                    "retained-block request correlation table full"
                );
                let _ = required_event_tx
                    .send(NetworkEvent::RecentBlockRequestFailed {
                        from: peer,
                        height,
                        payload_kind: RecentBlockPayloadKind::BlockBody,
                    })
                    .await;
                return;
            }
            let request_id = swarm.behaviour_mut().block_sync.send_request(
                &peer,
                crate::protocol::GetRecentBlockRequest {
                    height,
                    count,
                    payload_kind: RecentBlockPayloadKind::BlockBody,
                },
            );
            let inserted = pending_retained_block_requests.try_insert(
                request_id,
                PendingRetainedBlockRequest {
                    peer,
                    height,
                    count,
                    payload_kind: RecentBlockPayloadKind::BlockBody,
                    issued_at: Instant::now(),
                    notify_node: true,
                },
            );
            debug_assert!(inserted, "fresh block-sync request ID must be unique");
        }
        NetworkCommand::RequestStateManifest {
            generation,
            peer,
            requester_height,
            requested_manifest_digest,
        } => {
            if !sync_paths.is_dispatchable(peer) {
                let _ = required_event_tx
                    .send(NetworkEvent::StateManifestRequestFailed {
                        generation,
                        from: peer,
                        requester_height,
                        kind: RequestFailureKind::ConnectionClosed,
                    })
                    .await;
                return;
            }
            // Exact generation correlation makes superseded responses inert.
            // Keep their transport IDs until completion or local expiry so a
            // request stuck before substream negotiation can still be flushed.
            pending_state_manifest_requests.retain(|_, pending| {
                if pending.peer == peer {
                    pending.notify_node = false;
                }
                true
            });
            if !pending_state_manifest_requests.has_capacity() {
                tracing::warn!(
                    generation,
                    peer = %peer,
                    requester_height,
                    limit = MAX_PENDING_STATE_MANIFEST_REQUESTS,
                    "state-manifest request correlation table full"
                );
                let _ = required_event_tx
                    .send(NetworkEvent::StateManifestRequestFailed {
                        generation,
                        from: peer,
                        requester_height,
                        kind: RequestFailureKind::Io,
                    })
                    .await;
                return;
            }
            let request_id = swarm.behaviour_mut().state_manifest_sync.send_request(
                &peer,
                crate::protocol::GetStateManifestRequest {
                    requester_height,
                    requested_manifest_digest,
                },
            );
            let inserted = pending_state_manifest_requests.try_insert(
                request_id,
                PendingStateManifestRequest {
                    generation,
                    peer,
                    requester_height,
                    issued_at: Instant::now(),
                    notify_node: true,
                },
            );
            debug_assert!(inserted, "fresh manifest request ID must be unique");
            tracing::debug!(generation, peer = %peer, requester_height, "requesting state manifest");
        }
        NetworkCommand::RequestStateSegment {
            peer,
            segment_id,
            expected_tip_height,
            expected_tip_hash,
            manifest_digest,
        } => {
            if !sync_paths.is_dispatchable(peer) {
                let _ = required_event_tx
                    .send(NetworkEvent::StateSegmentRequestFailed {
                        from: peer,
                        segment_id,
                        expected_tip_height,
                        expected_tip_hash,
                        manifest_digest,
                    })
                    .await;
                return;
            }
            // Exact peer, segment and tip correlation makes superseded
            // responses inert. Retain old transport IDs until completion or
            // local expiry so pre-substream stalls remain observable.
            pending_state_segment_requests.retain(|_, pending| {
                let same_session = pending.peer == peer
                    && pending.expected_tip_height == expected_tip_height
                    && pending.expected_tip_hash == expected_tip_hash
                    && pending.manifest_digest == manifest_digest;
                if !same_session || pending.segment_id == segment_id {
                    pending.notify_node = false;
                }
                true
            });
            if !pending_state_segment_requests.has_capacity() {
                tracing::warn!(
                    peer = %peer,
                    segment_id,
                    limit = MAX_PENDING_STATE_SEGMENT_REQUESTS,
                    "state-segment request correlation table full"
                );
                let _ = required_event_tx
                    .send(NetworkEvent::StateSegmentRequestFailed {
                        from: peer,
                        segment_id,
                        expected_tip_height,
                        expected_tip_hash,
                        manifest_digest,
                    })
                    .await;
                return;
            }
            let request_id = swarm.behaviour_mut().state_segment_sync.send_request(
                &peer,
                crate::protocol::GetStateSegmentRequest {
                    segment_id,
                    expected_tip_height,
                    expected_tip_hash,
                    manifest_digest,
                },
            );
            let inserted = pending_state_segment_requests.try_insert(
                request_id,
                PendingStateSegmentRequest {
                    peer,
                    segment_id,
                    expected_tip_height,
                    expected_tip_hash,
                    manifest_digest,
                    issued_at: Instant::now(),
                    notify_node: true,
                },
            );
            debug_assert!(inserted, "fresh segment-sync request ID must be unique");
            tracing::debug!(peer = %peer, segment_id, "requesting state segment");
        }
        NetworkCommand::RequestHistoryStepTerminal {
            token,
            peer,
            height,
            block_hash,
        } => {
            if !sync_paths.is_dispatchable(peer) {
                let _ = required_event_tx
                    .send(NetworkEvent::HistoryStepTerminalRequestFailed {
                        token,
                        from: peer,
                        height,
                        block_hash,
                        kind: RequestFailureKind::ConnectionClosed,
                    })
                    .await;
                return;
            }
            // Boundary, bridge-tip and recent-suffix terminals are independent
            // logical races and may all be useful concurrently. Never retire
            // one merely because another token was issued.
            let retired = admit_history_step_terminal_race(pending_history_step_requests);
            let mut wedged_retired_peers = std::collections::HashSet::new();
            for (request_id, request) in retired {
                if swarm
                    .behaviour()
                    .history_step_sync
                    .is_pending_outbound(&request.peer, &request_id)
                {
                    wedged_retired_peers.insert(request.peer);
                }
                tracing::warn!(
                    retired_token = request.token,
                    token,
                    peer = %request.peer,
                    height = request.height,
                    "retired oldest HistoryStep terminal race at correlation capacity"
                );
                if request.notify_node {
                    let _ = required_event_tx
                        .send(NetworkEvent::HistoryStepTerminalRequestFailed {
                            token: request.token,
                            from: request.peer,
                            height: request.height,
                            block_hash: request.block_hash,
                            kind: RequestFailureKind::Timeout,
                        })
                        .await;
                }
            }
            for retired_peer in wedged_retired_peers {
                tracing::warn!(
                    peer = %retired_peer,
                    "closing connection to flush an evicted HistoryStep terminal race"
                );
                let _ = swarm.disconnect_peer_id(retired_peer);
            }
            if !pending_history_step_requests.has_capacity() {
                tracing::warn!(
                    token,
                    peer = %peer,
                    height,
                    limit = MAX_PENDING_HISTORY_STEP_REQUESTS,
                    "HistoryStep request correlation table full"
                );
                let _ = required_event_tx
                    .send(NetworkEvent::HistoryStepTerminalRequestFailed {
                        token,
                        from: peer,
                        height,
                        block_hash,
                        kind: RequestFailureKind::Io,
                    })
                    .await;
                return;
            }
            let request_id = swarm.behaviour_mut().history_step_sync.send_request(
                &peer,
                crate::protocol::GetHistoryStepTerminalRequest { height, block_hash },
            );
            let inserted = pending_history_step_requests.try_insert(
                request_id,
                PendingHistoryStepTerminalRequest {
                    token,
                    peer,
                    height,
                    block_hash,
                    issued_at: Instant::now(),
                    notify_node: true,
                },
            );
            debug_assert!(inserted, "fresh HistoryStep request ID must be unique");
            tracing::debug!(token, peer = %peer, height, "requesting HistoryStep terminal for snapshot verification");
        }
        NetworkCommand::CancelHistoryStepTerminalRace { token } => {
            let mut retired = 0usize;
            pending_history_step_requests.retain(|_, request| {
                if request.token == token {
                    request.notify_node = false;
                    retired += 1;
                }
                true
            });
            tracing::debug!(
                token,
                requests = retired,
                "retired node notification for HistoryStep terminal race"
            );
        }
        NetworkCommand::FetchHeaders {
            peer,
            start_height,
            count,
        } => {
            let count = count.min(
                crate::header_sync_codec::MAX_HEADERS_PER_BATCH
                    .try_into()
                    .expect("header batch cap fits u16"),
            );
            if !sync_paths.is_dispatchable(peer) {
                let _ = required_event_tx
                    .send(NetworkEvent::HeadersRequestFailed {
                        from: peer,
                        start_height,
                        count,
                    })
                    .await;
                return;
            }
            // Exact range correlation makes superseded responses inert. Keep
            // their transport IDs until completion or local expiry so a
            // request stuck before substream negotiation can be flushed.
            pending_header_requests.retain(|_, pending| {
                if pending.peer == peer && pending.kind == HeaderRequestKind::General {
                    pending.notify_node = false;
                }
                true
            });
            if !pending_header_requests.has_capacity() {
                let _ = required_event_tx
                    .send(NetworkEvent::HeadersRequestFailed {
                        from: peer,
                        start_height,
                        count,
                    })
                    .await;
                return;
            }
            let request_id = swarm.behaviour_mut().chain_sync.send_request(
                &peer,
                crate::protocol::GetHeadersRequest {
                    start_height,
                    count,
                    include_inventory: true,
                },
            );
            let inserted = pending_header_requests.try_insert(
                request_id,
                PendingHeaderRequest {
                    peer,
                    start_height,
                    count,
                    kind: HeaderRequestKind::General,
                    issued_at: Instant::now(),
                    notify_node: true,
                },
            );
            debug_assert!(inserted, "fresh header request ID must be unique");
        }
        NetworkCommand::FetchSnapshotHeaders {
            generation,
            token,
            peer,
            start_height,
            count,
        } => {
            let count = count.min(
                crate::header_sync_codec::MAX_HEADERS_PER_BATCH
                    .try_into()
                    .expect("header batch cap fits u16"),
            );
            if !sync_paths.is_dispatchable(peer) {
                let _ = required_event_tx
                    .send(NetworkEvent::SnapshotHeadersRequestFailed {
                        generation,
                        token,
                        from: peer,
                        start_height,
                        count,
                        kind: RequestFailureKind::ConnectionClosed,
                    })
                    .await;
                return;
            }
            // Keep distinct ranges in the same generation live: the node uses
            // a bounded ordered window against one selected peer. Only an old
            // generation or a replacement of this exact start height is
            // superseded. Transport IDs remain until completion or local
            // expiry so pre-substream stalls stay observable.
            pending_header_requests.retain(|_, pending| {
                if snapshot_header_request_is_superseded(pending, generation, start_height) {
                    pending.notify_node = false;
                }
                true
            });
            if !pending_header_requests.has_capacity() {
                let _ = required_event_tx
                    .send(NetworkEvent::SnapshotHeadersRequestFailed {
                        generation,
                        token,
                        from: peer,
                        start_height,
                        count,
                        kind: RequestFailureKind::Io,
                    })
                    .await;
                return;
            }
            let request_id = swarm.behaviour_mut().chain_sync.send_request(
                &peer,
                crate::protocol::GetHeadersRequest {
                    start_height,
                    count,
                    include_inventory: false,
                },
            );
            let inserted = pending_header_requests.try_insert(
                request_id,
                PendingHeaderRequest {
                    peer,
                    start_height,
                    count,
                    kind: HeaderRequestKind::Snapshot { generation, token },
                    issued_at: Instant::now(),
                    notify_node: true,
                },
            );
            debug_assert!(inserted, "fresh snapshot header request ID must be unique");
        }
        NetworkCommand::RequestMempoolSync { peer } => {
            if !sync_paths.is_dispatchable(peer) {
                let local = *swarm.local_peer_id();
                let _ = schedule_mempool_sync_retry(mempool_sync_retries, local, peer);
                return;
            }
            const MEMPOOL_SYNC_REQUEST_COOLDOWN: Duration = Duration::from_secs(30);
            let now = Instant::now();
            if let Some(last) = mempool_sync_last_request.get(&peer) {
                if now.duration_since(*last) < MEMPOOL_SYNC_REQUEST_COOLDOWN {
                    tracing::debug!(peer = %peer, "mempool sync request suppressed by cooldown");
                    return;
                }
            }
            mempool_sync_last_request.insert(peer, now);
            mempool_sync_retries.remove(&peer);
            let _ = swarm
                .behaviour_mut()
                .mempool_sync
                .send_request(&peer, MempoolRequest::Pull);
            tracing::debug!(peer = %peer, "requesting mempool sync");
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_swarm_event(
    swarm: &mut libp2p::Swarm<NodeBehaviour>,
    event: SwarmEvent<NodeBehaviourEvent>,
    gossip_event_tx: &tokio::sync::broadcast::Sender<NetworkEvent>,
    required_event_tx: &RequiredEventSender,
    chain_store: &MdbxStore,
    mempool: &AsyncMempool,
    topics: &NetworkTopics,
    block_response_tx: &mpsc::Sender<PendingBlockResponse>,
    block_response_prepare_semaphore: &Arc<Semaphore>,
    header_response_tx: &mpsc::Sender<PendingHeaderResponse>,
    header_response_prepare_semaphore: &Arc<Semaphore>,
    history_step_response_tx: &mpsc::Sender<PendingHistoryStepTerminalResponse>,
    history_step_response_prepare_semaphore: &Arc<Semaphore>,
    segment_response_tx: &mpsc::Sender<PendingStateSegmentResponse>,
    segment_encode_semaphore: &Arc<Semaphore>,
    mempool_response_tx: &mpsc::Sender<PendingMempoolResponse>,
    mempool_response_prepare_semaphore: &Arc<Semaphore>,
    object_response_tx: &mpsc::Sender<PendingObjectResponse>,
    outbound_response_budget: &OutboundResponseBudget,
    data_plane_serving: &mut DataPlaneServingAdmission,
    snapshot_exports: &mut std::collections::HashMap<SnapshotExportKey, SnapshotExport>,
    snapshot_export_leases: &mut std::collections::HashMap<PeerId, SnapshotExportLease>,
    block_event_rate: &mut std::collections::HashMap<PeerId, (u32, Instant)>,
    tx_gossip_rate: &mut std::collections::HashMap<PeerId, (u32, Instant)>,
    gossip_accept_bytes: &mut GossipByteWindow,
    mempool_sync_last_request: &mut std::collections::HashMap<PeerId, Instant>,
    mempool_sync_retries: &mut std::collections::HashMap<PeerId, MempoolSyncRetry>,
    snapshot_segment_rate: &mut std::collections::HashMap<PeerId, (u32, Instant)>,
    pending_retained_block_requests: &mut BoundedPendingRequests<
        request_response::OutboundRequestId,
        PendingRetainedBlockRequest,
    >,
    pending_network_profile_requests: &mut BoundedPendingRequests<
        request_response::OutboundRequestId,
        PendingNetworkProfileRequest,
    >,
    pending_object_requests: &mut BoundedPendingRequests<
        request_response::OutboundRequestId,
        PendingObjectRequest,
    >,
    pending_header_requests: &mut BoundedPendingRequests<
        request_response::OutboundRequestId,
        PendingHeaderRequest,
    >,
    pending_state_manifest_requests: &mut BoundedPendingRequests<
        request_response::OutboundRequestId,
        PendingStateManifestRequest,
    >,
    pending_state_segment_requests: &mut BoundedPendingRequests<
        request_response::OutboundRequestId,
        PendingStateSegmentRequest,
    >,
    pending_history_step_requests: &mut BoundedPendingRequests<
        request_response::OutboundRequestId,
        PendingHistoryStepTerminalRequest,
    >,
    automatic_peers: &mut AutomaticPeerState,
    peer_diversity: &mut PeerDiversity,
    sync_paths: &mut PeerSyncPaths,
    successful_peer_cache: &mut crate::peer_store::SuccessfulPeerCache,
) {
    macro_rules! fail_retained_request {
        ($pending:expr) => {{
            let pending = $pending;
            if pending.notify_node {
                let _ = required_event_tx
                    .send(NetworkEvent::RecentBlockRequestFailed {
                        from: pending.peer,
                        height: pending.height,
                        payload_kind: pending.payload_kind,
                    })
                    .await;
            }
        }};
    }
    macro_rules! fail_state_segment_request {
        ($pending:expr) => {{
            let pending = $pending;
            if pending.notify_node {
                let _ = required_event_tx
                    .send(NetworkEvent::StateSegmentRequestFailed {
                        from: pending.peer,
                        segment_id: pending.segment_id,
                        expected_tip_height: pending.expected_tip_height,
                        expected_tip_hash: pending.expected_tip_hash,
                        manifest_digest: pending.manifest_digest,
                    })
                    .await;
            }
        }};
    }

    match event {
        // --- GossipSub: received broadcast ---
        SwarmEvent::Behaviour(NodeBehaviourEvent::Gossipsub(gossipsub::Event::Message {
            propagation_source,
            message_id,
            message,
        })) => {
            // Prefer the original publisher (message.source) if we have a direct
            // connection — they definitely have the full block. Fall back to
            // propagation_source (forwarder) for nodes not directly connected to
            // the publisher (common in large networks with multi-hop gossip).
            let direct_origin = message.source.filter(|src| swarm.is_connected(src));
            let origin = direct_origin.unwrap_or(propagation_source);

            let topic = message.topic.as_str();
            if topic == topics.blocks.as_str() {
                match HeaderAnnouncement::decode(&message.data) {
                    Ok(announcement) => {
                        const BLOCK_RATE_WINDOW: Duration = Duration::from_secs(10);
                        const BLOCK_RATE_MAX: u32 = 40;
                        if !sync_paths.is_dispatchable(propagation_source)
                            || !allow_peer_rate(
                                block_event_rate,
                                propagation_source,
                                BLOCK_RATE_MAX,
                                BLOCK_RATE_WINDOW,
                            )
                            || !gossip_accept_bytes.admit(
                                message.data.len(),
                                GOSSIP_ACCEPT_BYTES_PER_WINDOW,
                                GOSSIP_ACCEPT_WINDOW,
                            )
                        {
                            report_gossip_validation(
                                swarm,
                                &message_id,
                                &propagation_source,
                                gossipsub::MessageAcceptance::Ignore,
                            );
                            tracing::debug!(peer = %propagation_source, "block announcement rate limit exceeded — dropped before propagation");
                            return;
                        }
                        let source_has_objects = direct_origin.is_some()
                            && announcement.providers.serves_body()
                            && announcement.providers.serves_terminal();
                        let queued = required_event_tx.try_send(NetworkEvent::HeaderAnnouncement {
                            from: origin,
                            announcement,
                            source_has_objects,
                        });
                        report_gossip_validation(
                            swarm,
                            &message_id,
                            &propagation_source,
                            if queued.is_ok() {
                                gossipsub::MessageAcceptance::Accept
                            } else {
                                gossipsub::MessageAcceptance::Ignore
                            },
                        );
                        if let Err(error) = queued {
                            tracing::warn!(peer = %propagation_source, %error, "reserved header event lane is full");
                        }
                    }
                    Err(error) => {
                        report_gossip_validation(
                            swarm,
                            &message_id,
                            &propagation_source,
                            gossipsub::MessageAcceptance::Reject,
                        );
                        tracing::debug!(
                            peer = %propagation_source,
                            %error,
                            "network-v3 header announcement decode failed"
                        );
                    }
                }
            } else if topic == topics.txs.as_str() {
                if message.data.len() > MAX_TX_INTENT_BYTES_GLOBAL {
                    report_gossip_validation(
                        swarm,
                        &message_id,
                        &propagation_source,
                        gossipsub::MessageAcceptance::Reject,
                    );
                    tracing::warn!(peer = %propagation_source, len = message.data.len(), "tx gossip too large — dropped");
                } else {
                    if !allow_peer_rate(
                        tx_gossip_rate,
                        propagation_source,
                        TX_RELAY_RATE_MAX,
                        TX_RELAY_RATE_WINDOW,
                    ) {
                        report_gossip_validation(
                            swarm,
                            &message_id,
                            &propagation_source,
                            gossipsub::MessageAcceptance::Ignore,
                        );
                        tracing::debug!(peer = %propagation_source, "tx gossip rate limit exceeded — dropped before propagation");
                        return;
                    }
                    if !gossip_accept_bytes.admit(
                        message.data.len(),
                        GOSSIP_ACCEPT_BYTES_PER_WINDOW,
                        GOSSIP_ACCEPT_WINDOW,
                    ) {
                        report_gossip_validation(
                            swarm,
                            &message_id,
                            &propagation_source,
                            gossipsub::MessageAcceptance::Ignore,
                        );
                        tracing::debug!(peer = %propagation_source, bytes = message.data.len(), "global gossip byte budget exhausted — transaction dropped before propagation");
                        return;
                    }
                    report_gossip_validation(
                        swarm,
                        &message_id,
                        &propagation_source,
                        gossipsub::MessageAcceptance::Accept,
                    );
                    let _ = gossip_event_tx.send(NetworkEvent::NewTx {
                        from: propagation_source,
                        intent_bytes: message.data,
                        inbound_memory_permit: None,
                    });
                }
            } else {
                report_gossip_validation(
                    swarm,
                    &message_id,
                    &propagation_source,
                    gossipsub::MessageAcceptance::Ignore,
                );
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
            connection_id,
            info,
            ..
        })) => {
            // A duplicate or policy-rejected endpoint remains visible to
            // request-response until its exact ConnectionClosed event. Do not
            // promote it while the close is in flight.
            if sync_paths.is_closing(connection_id) {
                return;
            }
            // Identify is only capability discovery. The endpoint becomes a
            // usable network-v3 peer after the explicit profile round trip
            // below proves the exact genesis, caps, finality and proof bank.
            let profile_protocol = format!("{}/sync/profile/2", topics.protocol_id);
            let object_protocol = format!("{}/sync/objects/2", topics.protocol_id);
            let header_protocol = format!("{}/sync/headers/4", topics.protocol_id);
            let supports = |required: &str| {
                info.protocols
                    .iter()
                    .any(|protocol| protocol.as_ref() == required)
            };
            if !supports(&profile_protocol)
                || !supports(&object_protocol)
                || !supports(&header_protocol)
            {
                sync_paths.mark_closing(connection_id);
                let _ = swarm.close_connection(connection_id);
                swarm.behaviour_mut().kad.remove_peer(&peer_id);
                tracing::debug!(
                    peer = %peer_id,
                    profile_protocol,
                    object_protocol,
                    header_protocol,
                    "closing endpoint without the complete network-v3 protocol set"
                );
                return;
            }

            // 1. Add a bounded, routable subset of advertised listen addresses
            //    to Kademlia and the swarm address book. Blindly accepting all
            //    Identify addresses lets a peer bloat our peer store/routing state
            //    or advertise localhost/private addresses that are useless off-LAN.
            const MAX_IDENTIFY_ADDRS_PER_PEER: usize = 8;
            let mut accepted_addrs = 0usize;
            let mut dropped_addrs = 0usize;
            let mut routable_addrs = Vec::new();
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
                routable_addrs.push(addr.clone());
                accepted_addrs += 1;
            }
            if automatic_peers
                .outbound_connections
                .contains_key(&connection_id)
            {
                if let Some(addr) = routable_addrs.first() {
                    if let Err(reason) = peer_diversity.classify_outbound_dns_connection(
                        connection_id,
                        peer_id,
                        addr,
                    ) {
                        sync_paths.mark_closing(connection_id);
                        let _ = swarm.close_connection(connection_id);
                        swarm.behaviour_mut().kad.remove_peer(&peer_id);
                        tracing::debug!(
                            peer = %peer_id,
                            address = %addr,
                            ?reason,
                            "closing DNS connection that violates public peer diversity"
                        );
                        return;
                    }
                }
            }
            automatic_peers.add_peer_candidate(
                *swarm.local_peer_id(),
                peer_id,
                routable_addrs.iter().cloned(),
            );
            automatic_peers.note_identified(connection_id, peer_id);
            sync_paths.mark_identified(connection_id);
            let profile_request_active = pending_network_profile_requests
                .entries
                .values()
                .any(|pending| pending.peer == peer_id);
            if !sync_paths.profile_verified.contains(&peer_id) && !profile_request_active {
                if !pending_network_profile_requests.has_capacity() {
                    sync_paths.mark_closing(connection_id);
                    let _ = swarm.close_connection(connection_id);
                    tracing::warn!(peer = %peer_id, "network-profile correlation table is full");
                    return;
                }
                let expected_profile_id = NetworkProfile::current().profile_id;
                let request_id = swarm.behaviour_mut().network_profile_sync.send_request(
                    &peer_id,
                    NetworkProfileRequest {
                        expected_profile_id,
                    },
                );
                let inserted = pending_network_profile_requests.try_insert(
                    request_id,
                    PendingNetworkProfileRequest {
                        peer: peer_id,
                        issued_at: Instant::now(),
                    },
                );
                debug_assert!(inserted, "profile capacity checked before request");
                tracing::debug!(peer = %peer_id, "network-v3 profile handshake started");
            }
            if sync_paths.try_mark_announced(peer_id) {
                let _ = required_event_tx
                    .send(NetworkEvent::PeerConnected {
                        peer: peer_id,
                        failure_domain: peer_diversity.failure_domain(peer_id),
                    })
                    .await;
                tracing::debug!(peer = %peer_id, "peer network-v3 profile ready");
            }
            if automatic_peers.is_bootstrap_peer(peer_id) {
                // Older releases recorded seeds as generic successful peers.
                // Retire that derived cache entry once the bootstrap identity
                // is known so restarts do not recreate permanent seed load.
                successful_peer_cache.remove(&peer_id);
            } else if automatic_peers.is_outbound(peer_id) {
                for addr in routable_addrs {
                    successful_peer_cache.record_success(peer_id, addr);
                }
            }

            // 2. Kick off the bootstrap walk now that at least one routable
            //    peer may be present. Ordinary peers intentionally stay out
            //    of GossipSub's explicit set: explicit peers receive every
            //    publication outside the bounded mesh, producing O(degree)
            //    block and transaction fan-out on large networks.
            if !automatic_peers.kad_bootstrap_started {
                if let Ok(query) = swarm.behaviour_mut().kad.bootstrap() {
                    automatic_peers.begin_kad_bootstrap(query);
                }
            }

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
            let mut dial_addresses: std::collections::HashMap<PeerId, Vec<Multiaddr>> =
                std::collections::HashMap::new();
            for (peer_id, addr) in peers {
                tracing::debug!(peer = %peer_id, addr = %addr, "mDNS: discovered LAN peer");
                swarm
                    .behaviour_mut()
                    .kad
                    .add_address(&peer_id, addr.clone());
                dial_addresses.entry(peer_id).or_default().push(addr);
            }
            for (peer_id, addresses) in dial_addresses {
                if peer_id == *swarm.local_peer_id() || swarm.is_connected(&peer_id) {
                    continue;
                }
                // One mDNS answer commonly contains the same PeerId on Wi-Fi,
                // Ethernet and container bridges. Treat those as alternative
                // paths in one conditional attempt; dialing each address as a
                // separate connection races request streams against paths the
                // per-peer limit then closes.
                let options = libp2p::swarm::dial_opts::DialOpts::peer_id(peer_id)
                    .condition(libp2p::swarm::dial_opts::PeerCondition::DisconnectedAndNotDialing)
                    .addresses(addresses)
                    .build();
                if let Err(e) = swarm.dial(options) {
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
                id,
                step,
                result: kad::QueryResult::Bootstrap(Ok(kad::BootstrapOk { num_remaining, .. })),
                ..
            } => {
                if num_remaining == 0 {
                    tracing::debug!("kad: bootstrap complete");
                }
                if step.last {
                    automatic_peers.finish_kad_bootstrap(id);
                }
            }
            kad::Event::OutboundQueryProgressed {
                id,
                step,
                result: kad::QueryResult::Bootstrap(Err(error)),
                ..
            } => {
                if step.last {
                    automatic_peers.finish_kad_bootstrap(id);
                }
                tracing::debug!(err = %error, "kad: bootstrap query timed out");
            }
            kad::Event::OutboundQueryProgressed {
                id,
                step,
                result: kad::QueryResult::GetClosestPeers(Ok(kad::GetClosestPeersOk { peers, .. })),
                ..
            } => {
                let found = peers.len();
                let local = *swarm.local_peer_id();
                let mut learned = false;
                for peer in peers {
                    learned |= automatic_peers.add_peer_candidate(local, peer.peer_id, peer.addrs);
                }
                automatic_peers.observe_discovery(id, learned, step.last);
                tracing::debug!(found, learned, "kad: FIND_NODE returned peers");
            }
            kad::Event::OutboundQueryProgressed {
                id,
                step,
                result:
                    kad::QueryResult::GetClosestPeers(Err(kad::GetClosestPeersError::Timeout {
                        peers,
                        ..
                    })),
                ..
            } => {
                let found = peers.len();
                let local = *swarm.local_peer_id();
                let mut learned = false;
                for peer in peers {
                    learned |= automatic_peers.add_peer_candidate(local, peer.peer_id, peer.addrs);
                }
                automatic_peers.observe_discovery(id, learned, step.last);
                tracing::debug!(
                    found,
                    learned,
                    "kad: timed-out FIND_NODE retained partial peers"
                );
            }
            _ => {}
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

        // --- Network-v2 profile handshake ---
        SwarmEvent::Behaviour(NodeBehaviourEvent::NetworkProfileSync(
            request_response::Event::Message {
                message:
                    request_response::Message::Request {
                        request, channel, ..
                    },
                peer,
                ..
            },
        )) => {
            let current = NetworkProfile::current();
            if request.expected_profile_id != current.profile_id {
                tracing::debug!(
                    peer = %peer,
                    expected = ?request.expected_profile_id,
                    local = ?current.profile_id,
                    "peer requested a different network profile"
                );
            }
            let _ = swarm
                .behaviour_mut()
                .network_profile_sync
                .send_response(channel, NetworkProfileResponse { profile: current });
        }

        SwarmEvent::Behaviour(NodeBehaviourEvent::NetworkProfileSync(
            request_response::Event::Message {
                message:
                    request_response::Message::Response {
                        request_id,
                        response,
                    },
                peer,
            },
        )) => {
            let Some(pending) = pending_network_profile_requests.remove(&request_id) else {
                tracing::debug!(peer = %peer, request_id = %request_id, "ignoring stale network-profile response");
                return;
            };
            if pending.peer != peer || !response.profile.is_current() {
                tracing::warn!(
                    peer = %peer,
                    requested_peer = %pending.peer,
                    profile = ?response.profile.profile_id,
                    "network-v3 profile mismatch; closing peer"
                );
                let _ = swarm.disconnect_peer_id(peer);
                return;
            }
            sync_paths.mark_profile_verified(peer);
            if sync_paths.try_mark_announced(peer) {
                let _ = required_event_tx
                    .send(NetworkEvent::PeerConnected {
                        peer,
                        failure_domain: peer_diversity.failure_domain(peer),
                    })
                    .await;
            }
            tracing::debug!(peer = %peer, profile = ?response.profile.profile_id, "network-v3 profile verified");
        }

        SwarmEvent::Behaviour(NodeBehaviourEvent::NetworkProfileSync(
            request_response::Event::OutboundFailure {
                peer,
                request_id,
                error,
            },
        )) => {
            if pending_network_profile_requests
                .remove(&request_id)
                .is_some()
            {
                tracing::warn!(peer = %peer, err = %error, "network-v3 profile handshake failed");
                let _ = swarm.disconnect_peer_id(peer);
            }
        }

        SwarmEvent::Behaviour(NodeBehaviourEvent::NetworkProfileSync(
            request_response::Event::InboundFailure {
                peer,
                request_id,
                error,
            },
        )) => {
            tracing::debug!(peer = %peer, ?request_id, err = %error, "network-profile response failed");
        }

        SwarmEvent::Behaviour(NodeBehaviourEvent::NetworkProfileSync(
            request_response::Event::ResponseSent { .. },
        )) => {}

        // --- Content-addressed body/terminal transfer ---
        SwarmEvent::Behaviour(NodeBehaviourEvent::ObjectSync(
            request_response::Event::Message {
                message:
                    request_response::Message::Request {
                        request, channel, ..
                    },
                peer,
                ..
            },
        )) => {
            if let Some(lease) = snapshot_export_leases.get_mut(&peer) {
                lease.last_activity = Instant::now();
                refresh_snapshot_object_retention_floor(chain_store, snapshot_export_leases);
            }
            let Some(serving_lease) = data_plane_serving.lease(peer) else {
                tracing::debug!(peer = %peer, "exact-object serving queue is full");
                return;
            };
            let declared_bytes = request
                .objects
                .iter()
                .filter_map(|object| object.encoded_len())
                .fold(0usize, |total, length| {
                    total.saturating_add(length as usize)
                });
            let store = chain_store.clone();
            let budget = outbound_response_budget.clone();
            let completion = object_response_tx.clone();
            tokio::spawn(async move {
                let Ok(serving_permits) = serving_lease.acquire().await else {
                    return;
                };
                let Ok(outbound_memory_permit) = budget
                    .acquire_with_serving(declared_bytes, serving_permits)
                    .await
                else {
                    tracing::warn!(peer = %peer, declared_bytes, "exact-object response admission failed");
                    return;
                };
                let requested = request.objects;
                let loaded = tokio::task::spawn_blocking(move || {
                    requested
                        .into_iter()
                        .map(|object| {
                            let bytes = match load_exact_object(&store, object) {
                                Ok(bytes) => bytes,
                                Err(error) => {
                                    tracing::warn!(peer = %peer, ?object, %error, "exact-object storage read failed");
                                    None
                                }
                            };
                            ObjectPayload { object, bytes }
                        })
                        .collect::<Vec<_>>()
                })
                .await;
                let Ok(objects) = loaded else {
                    tracing::warn!(peer = %peer, "exact-object storage worker failed");
                    return;
                };
                let response = GetObjectsResponse {
                    objects,
                    inbound_memory_permit: None,
                    outbound_memory_permit,
                };
                let _ = completion
                    .send(PendingObjectResponse { channel, response })
                    .await;
            });
        }

        SwarmEvent::Behaviour(NodeBehaviourEvent::ObjectSync(
            request_response::Event::Message {
                message:
                    request_response::Message::Response {
                        request_id,
                        response,
                    },
                peer,
            },
        )) => {
            let Some(pending) = pending_object_requests.remove(&request_id) else {
                tracing::debug!(peer = %peer, request_id = %request_id, "ignoring stale exact-object response");
                return;
            };
            let response_ids = response
                .objects
                .iter()
                .map(|payload| payload.object)
                .collect::<Vec<_>>();
            if pending.peer != peer || response_ids != pending.objects {
                drop(response);
                let _ = required_event_tx
                    .send(NetworkEvent::ObjectsRequestFailed {
                        token: pending.token,
                        from: pending.peer,
                        objects: pending.objects,
                        kind: RequestFailureKind::InvalidResponse,
                    })
                    .await;
                return;
            }
            let GetObjectsResponse {
                objects,
                inbound_memory_permit,
                outbound_memory_permit,
            } = response;
            debug_assert!(outbound_memory_permit.is_none());
            let _ = required_event_tx
                .send(NetworkEvent::ObjectsResponse {
                    token: pending.token,
                    from: peer,
                    objects,
                    inbound_memory_permit,
                })
                .await;
        }

        SwarmEvent::Behaviour(NodeBehaviourEvent::ObjectSync(
            request_response::Event::OutboundFailure {
                peer,
                request_id,
                error,
            },
        )) => {
            let Some(pending) = pending_object_requests.remove(&request_id) else {
                return;
            };
            let _ = required_event_tx
                .send(NetworkEvent::ObjectsRequestFailed {
                    token: pending.token,
                    from: peer,
                    objects: pending.objects,
                    kind: RequestFailureKind::from(&error),
                })
                .await;
        }

        SwarmEvent::Behaviour(NodeBehaviourEvent::ObjectSync(
            request_response::Event::InboundFailure {
                peer,
                request_id,
                error,
            },
        )) => {
            tracing::debug!(peer = %peer, ?request_id, err = %error, "exact-object response failed");
        }

        SwarmEvent::Behaviour(NodeBehaviourEvent::ObjectSync(
            request_response::Event::ResponseSent { .. },
        )) => {}

        // --- Request-Response: headers client side (response to our FetchHeaders) ---
        SwarmEvent::Behaviour(NodeBehaviourEvent::ChainSync(
            request_response::Event::Message {
                message:
                    request_response::Message::Response {
                        request_id,
                        response,
                    },
                peer,
            },
        )) => {
            let Some(pending) = pending_header_requests.remove(&request_id) else {
                tracing::debug!(
                    peer = %peer,
                    request_id = %request_id,
                    "ignoring stale header response"
                );
                return;
            };
            if !pending.notify_node {
                tracing::debug!(peer = %peer, request_id = %request_id, "discarding superseded header response");
                return;
            }
            if pending.peer != peer {
                match pending.kind {
                    HeaderRequestKind::General => {
                        let _ = required_event_tx
                            .send(NetworkEvent::HeadersRequestFailed {
                                from: pending.peer,
                                start_height: pending.start_height,
                                count: pending.count,
                            })
                            .await;
                    }
                    HeaderRequestKind::Snapshot { generation, token } => {
                        let _ = required_event_tx
                            .send(NetworkEvent::SnapshotHeadersRequestFailed {
                                generation,
                                token,
                                from: pending.peer,
                                start_height: pending.start_height,
                                count: pending.count,
                                kind: RequestFailureKind::InvalidResponse,
                            })
                            .await;
                    }
                }
                return;
            }
            let records = response.records;
            if let Err(error) = validate_header_batch_shape(&records) {
                tracing::warn!(from = %peer, error, "invalid header batch response — dropped");
                match pending.kind {
                    HeaderRequestKind::General => {
                        let _ = required_event_tx
                            .send(NetworkEvent::HeadersRequestFailed {
                                from: pending.peer,
                                start_height: pending.start_height,
                                count: pending.count,
                            })
                            .await;
                    }
                    HeaderRequestKind::Snapshot { generation, token } => {
                        let _ = required_event_tx
                            .send(NetworkEvent::SnapshotHeadersRequestFailed {
                                generation,
                                token,
                                from: pending.peer,
                                start_height: pending.start_height,
                                count: pending.count,
                                kind: RequestFailureKind::InvalidResponse,
                            })
                            .await;
                    }
                }
                return;
            }
            match pending.kind {
                HeaderRequestKind::General => {
                    let _ = required_event_tx
                        .send(NetworkEvent::HeaderInventoryBatch {
                            from: peer,
                            records,
                        })
                        .await;
                }
                HeaderRequestKind::Snapshot { generation, token } => {
                    let headers = records.into_iter().map(|record| record.header).collect();
                    let _ = required_event_tx
                        .send(NetworkEvent::SnapshotHeadersBatch {
                            generation,
                            token,
                            from: peer,
                            start_height: pending.start_height,
                            requested_count: pending.count,
                            headers,
                        })
                        .await;
                }
            }
        }

        SwarmEvent::Behaviour(NodeBehaviourEvent::ChainSync(
            request_response::Event::OutboundFailure {
                peer,
                request_id,
                error,
            },
        )) => {
            let kind = RequestFailureKind::from(&error);
            let Some(pending) = pending_header_requests.remove(&request_id) else {
                tracing::debug!(
                    peer = %peer,
                    request_id = %request_id,
                    "ignoring stale header request failure"
                );
                return;
            };
            if !pending.notify_node {
                tracing::debug!(peer = %peer, request_id = %request_id, "discarding superseded header request failure");
                return;
            }
            tracing::debug!(
                peer = %peer,
                request_id = %request_id,
                err = %error,
                "header request transport failed"
            );
            match pending.kind {
                HeaderRequestKind::General => {
                    let _ = required_event_tx
                        .send(NetworkEvent::HeadersRequestFailed {
                            from: pending.peer,
                            start_height: pending.start_height,
                            count: pending.count,
                        })
                        .await;
                }
                HeaderRequestKind::Snapshot { generation, token } => {
                    let _ = required_event_tx
                        .send(NetworkEvent::SnapshotHeadersRequestFailed {
                            generation,
                            token,
                            from: pending.peer,
                            start_height: pending.start_height,
                            count: pending.count,
                            kind,
                        })
                        .await;
                }
            }
        }

        // --- Request-Response: headers server side ---
        SwarmEvent::Behaviour(NodeBehaviourEvent::ChainSync(
            request_response::Event::Message {
                message:
                    request_response::Message::Request {
                        request, channel, ..
                    },
                peer: _,
                ..
            },
        )) => {
            let count = request.count.min(
                crate::header_sync_codec::MAX_HEADERS_PER_BATCH
                    .try_into()
                    .expect("header batch cap fits u16"),
            );
            let start_height = request.start_height;
            let include_inventory = request.include_inventory;
            let store = chain_store.clone();
            let preparation_admission = header_response_prepare_semaphore.clone();
            let completion = header_response_tx.clone();
            tokio::spawn(async move {
                let Ok(preparation_permit) = preparation_admission.acquire_owned().await else {
                    return;
                };
                let _preparation_permit = preparation_permit;
                let loaded = tokio::task::spawn_blocking(move || {
                    match store.get_headers(start_height, count) {
                        Ok(headers) => {
                            let tip_height = store
                                .get_chain_tip()
                                .ok()
                                .flatten()
                                .map(|(height, _)| height);
                            let retained_floor = tip_height.map(|height| {
                                height.saturating_sub(
                                    noid_chain::consensus::params::RECENT_BLOCK_RETENTION_DEPTH,
                                )
                            });
                            let target_height = headers.last().map(|header| header.height);
                            headers
                                .into_iter()
                                .map(|header| {
                                    if !include_inventory {
                                        return HeaderInventoryRecord::header_only(header);
                                    }
                                    let body = retained_floor
                                        .is_some_and(|floor| header.height >= floor)
                                        .then(|| {
                                            store.get_recent_block(header.height).ok().flatten()
                                        })
                                        .flatten();
                                    let terminal = (Some(header.height) == target_height)
                                        .then(|| {
                                            let canonical = store
                                                .get_history_step_terminal_at(
                                                    header.height,
                                                    noid_chain::block_header::block_id(&header),
                                                )
                                                .ok()
                                                .flatten();
                                            canonical.or_else(|| {
                                                store
                                                    .get_any_history_step_proof_object(
                                                        header.height,
                                                        noid_chain::block_header::semantic_header_id(
                                                            &header,
                                                        ),
                                                    )
                                                    .ok()
                                                    .flatten()
                                            })
                                        })
                                        .flatten();
                                    match HeaderInventoryRecord::from_retained_objects(
                                        header,
                                        body.as_deref(),
                                        terminal.as_deref(),
                                    ) {
                                        Ok(record) => record,
                                        Err(error) => {
                                            tracing::warn!(
                                                height = header.height,
                                                %error,
                                                "retained header inventory is inconsistent"
                                            );
                                            HeaderInventoryRecord::header_only(header)
                                        }
                                    }
                                })
                                .collect()
                        }
                        Err(error) => {
                            tracing::warn!(
                                start_height,
                                count,
                                err = %error,
                                "canonical header range read failed"
                            );
                            Vec::new()
                        }
                    }
                })
                .await;
                let records = match loaded {
                    Ok(records) => records,
                    Err(error) => {
                        tracing::warn!(
                            start_height,
                            count,
                            err = %error,
                            "header response storage worker failed"
                        );
                        Vec::new()
                    }
                };
                let _ = completion
                    .send(PendingHeaderResponse {
                        channel,
                        response: GetHeadersResponse { records },
                    })
                    .await;
            });
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
            if !pending.notify_node {
                tracing::debug!(peer = %peer, request_id = %request_id, "discarding superseded retained-block response");
                return;
            }
            if !retained_block_response_matches_pending(
                pending,
                peer,
                response.height,
                response.count,
            ) || response.payload_kind != pending.payload_kind
            {
                tracing::warn!(
                    peer = %peer,
                    request_id = %request_id,
                    requested_peer = %pending.peer,
                    requested_height = pending.height,
                    requested_count = pending.count,
                    response_height = response.height,
                    response_count = response.count,
                    "retained-block response does not match its exact request — dropped"
                );
                fail_retained_request!(pending);
                return;
            }
            let inbound_memory_permit = response.inbound_memory_permit.clone();
            if let Some(payload) = response.payload {
                const BLOCK_RATE_WINDOW: Duration = Duration::from_secs(10);
                const BLOCK_RATE_MAX: u32 = 40;
                if !allow_peer_rate(block_event_rate, peer, BLOCK_RATE_MAX, BLOCK_RATE_WINDOW) {
                    tracing::debug!(peer = %peer, "pulled block response rate limit exceeded — dropped before event channel");
                    fail_retained_request!(pending);
                    return;
                }
                match (pending.payload_kind, payload) {
                    (RecentBlockPayloadKind::Complete, RecentBlockPayload::Complete(bundle)) => {
                        tracing::debug!(peer = %peer, height = bundle.height(), "received accepted-block bundle via pull");
                        let _ = required_event_tx
                            .send(NetworkEvent::RecentBlock {
                                from: peer,
                                bundle,
                                inbound_memory_permit,
                            })
                            .await;
                    }
                    (
                        RecentBlockPayloadKind::BlockBody,
                        RecentBlockPayload::BlockBodies(block_bodies),
                    ) => {
                        let bytes = block_bodies.iter().map(Vec::len).sum::<usize>();
                        tracing::debug!(
                            peer = %peer,
                            height = response.height,
                            count = response.count,
                            bytes,
                            "received compact snapshot block-body batch"
                        );
                        let _ = required_event_tx
                            .send(NetworkEvent::SnapshotBlockBodies {
                                from: peer,
                                height: response.height,
                                block_bodies,
                                inbound_memory_permit,
                            })
                            .await;
                    }
                    (RecentBlockPayloadKind::BlockBody, RecentBlockPayload::Complete(bundle)) => {
                        let height = bundle.height();
                        drop(bundle);
                        drop(inbound_memory_permit);
                        tracing::warn!(
                            peer = %peer,
                            height,
                            "complete response cannot satisfy body-only request"
                        );
                        fail_retained_request!(pending);
                    }
                    (
                        RecentBlockPayloadKind::Complete,
                        RecentBlockPayload::BlockBodies(block_bodies),
                    ) => {
                        drop(block_bodies);
                        drop(inbound_memory_permit);
                        tracing::warn!(
                            peer = %peer,
                            height = response.height,
                            "body-batch response cannot satisfy complete-block request"
                        );
                        fail_retained_request!(pending);
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
                        payload_kind: pending.payload_kind,
                    })
                    .await;
            }
        }

        // --- Block pull: serve one complete bundle or one bounded body range ---
        //
        // Only last FINALITY_DEPTH blocks are available; pruned blocks return None.
        // Peers that request pruned blocks must do a full state sync instead.
        SwarmEvent::Behaviour(NodeBehaviourEvent::BlockSync(
            request_response::Event::Message {
                message:
                    request_response::Message::Request {
                        request, channel, ..
                    },
                peer,
            },
        )) => {
            let Some(serving_lease) = data_plane_serving.lease(peer) else {
                tracing::debug!(peer = %peer, "block serving queue is full");
                return;
            };
            // Reserve the consensus upper bound before the first MDBX value is
            // copied into a Vec. Waiting happens off the swarm loop. The
            // request-response stream cap bounds the waiter count, so a busy
            // disk worker delays this exact response instead of manufacturing
            // a transport failure that makes the client repeat the range.
            let preparation_admission = block_response_prepare_semaphore.clone();
            let store = chain_store.clone();
            let budget = outbound_response_budget.clone();
            let completion = block_response_tx.clone();
            let height = request.height;
            let count = request.count;
            let payload_kind = request.payload_kind;
            let response_reservation = match payload_kind {
                RecentBlockPayloadKind::Complete => MAX_OUTBOUND_BLOCK_RESPONSE_BYTES,
                RecentBlockPayloadKind::BlockBody => MAX_OUTBOUND_BLOCK_BODY_BATCH_RESERVATION,
            };
            let end_height = height.saturating_add(count.saturating_sub(1) as u64);
            let leased_bridge = snapshot_export_leases.get_mut(&peer).and_then(|lease| {
                let generation = snapshot_exports.get(&lease.key)?;
                if generation.manifest().bridge_block(height).is_some()
                    && generation.manifest().bridge_block(end_height).is_some()
                {
                    lease.last_activity = Instant::now();
                    Some(generation.clone())
                } else {
                    None
                }
            });
            tokio::spawn(async move {
                let Ok(serving_permits) = serving_lease.acquire().await else {
                    return;
                };
                let Ok(preparation_permit) = preparation_admission.acquire_owned().await else {
                    return;
                };
                let _preparation_permit = preparation_permit;
                let Ok(Some(outbound_memory_permit)) = budget
                    .acquire_with_serving(response_reservation, serving_permits)
                    .await
                else {
                    return;
                };
                let loaded = tokio::task::spawn_blocking(move || {
                    match payload_kind {
                        RecentBlockPayloadKind::Complete => {
                            match store.get_recent_accepted_block_bundle_bounded(height) {
                                Ok(encoded) => decode_stored_accepted_block_bundle(height, encoded)
                                    .map(RecentBlockPayload::Complete),
                                Err(error) => {
                                    tracing::warn!(height, err = %error, "bounded block response read failed");
                                    None
                                }
                            }
                        }
                        RecentBlockPayloadKind::BlockBody => {
                            if let Some(generation) = leased_bridge {
                                let mut bodies = Vec::with_capacity(count as usize);
                                for current_height in height..=end_height {
                                    let Ok(block_bytes) =
                                        generation.read_bridge_block_body(current_height)
                                    else {
                                        return None;
                                    };
                                    bodies.push(block_bytes);
                                }
                                return Some(RecentBlockPayload::BlockBodies(bodies));
                            }
                            let mut bodies = Vec::with_capacity(count as usize);
                            for current_height in height..=end_height {
                                match store.get_recent_block(current_height) {
                                    Ok(Some(block_bytes)) => bodies.push(block_bytes),
                                    Ok(None) => return None,
                                    Err(error) => {
                                        tracing::warn!(
                                            height = current_height,
                                            err = %error,
                                            "bounded block-body response read failed"
                                        );
                                        return None;
                                    }
                                }
                            }
                            Some(RecentBlockPayload::BlockBodies(bodies))
                        }
                    }
                })
                .await;
                let payload = match loaded {
                    Ok(loaded) => loaded,
                    Err(error) => {
                        tracing::warn!(height, err = %error, "block response storage worker failed");
                        None
                    }
                };
                let response = GetRecentBlockResponse {
                    height,
                    count,
                    payload_kind,
                    payload,
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
            let Some(serving_lease) = data_plane_serving.lease(peer) else {
                tracing::debug!(peer = %peer, height = request.height, "terminal serving queue is full");
                return;
            };
            // The protocol admits at most four concurrent terminal streams.
            // Queue those streams behind the four storage workers off the
            // swarm loop rather than dropping an exact, immutable terminal
            // request and forcing a second near-megabyte transfer.
            let preparation_admission = history_step_response_prepare_semaphore.clone();
            let store = chain_store.clone();
            let budget = outbound_response_budget.clone();
            let completion = history_step_response_tx.clone();
            let request_height = request.height;
            let request_hash = request.block_hash;
            let leased_generation = snapshot_export_leases.get_mut(&peer).and_then(|lease| {
                let generation = snapshot_exports.get(&lease.key)?;
                let manifest = generation.manifest();
                let exact_boundary = manifest.target_height == request_height
                    && manifest.target_hash == request_hash;
                let exact_bridge = manifest.bridge_tip_height == request_height
                    && manifest.bridge_tip_hash == request_hash;
                if !exact_boundary && !exact_bridge {
                    return None;
                }
                lease.last_activity = Instant::now();
                Some(generation.clone())
            });
            tokio::spawn(async move {
                let Ok(serving_permits) = serving_lease.acquire().await else {
                    return;
                };
                let Ok(preparation_permit) = preparation_admission.acquire_owned().await else {
                    return;
                };
                let _preparation_permit = preparation_permit;
                let Ok(Some(outbound_memory_permit)) = budget
                    .acquire_with_serving(MAX_OUTBOUND_HISTORY_STEP_RESPONSE_BYTES, serving_permits)
                    .await
                else {
                    return;
                };
                let loaded = tokio::task::spawn_blocking(move || {
                    if let Some(generation) = leased_generation {
                        return generation
                            .read_terminal_at(request_height, request_hash)
                            .ok();
                    }
                    local_history_step_terminal(&store, request_height, request_hash)
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
                message:
                    request_response::Message::Response {
                        request_id,
                        response,
                    },
                peer,
            },
        )) => {
            let Some(pending) = pending_history_step_requests.remove(&request_id) else {
                tracing::debug!(
                    peer = %peer,
                    request_id = %request_id,
                    "ignoring stale HistoryStep terminal response"
                );
                return;
            };
            if !pending.notify_node {
                tracing::debug!(
                    token = pending.token,
                    peer = %peer,
                    request_id = %request_id,
                    "discarding response for a completed HistoryStep terminal race"
                );
                return;
            }
            if pending.peer != peer
                || pending.height != response.height
                || pending.block_hash != response.block_hash
            {
                tracing::warn!(
                    token = pending.token,
                    peer = %peer,
                    request_id = %request_id,
                    "ignoring mismatched HistoryStep terminal response"
                );
                let _ = required_event_tx
                    .send(NetworkEvent::HistoryStepTerminalRequestFailed {
                        token: pending.token,
                        from: pending.peer,
                        height: pending.height,
                        block_hash: pending.block_hash,
                        kind: RequestFailureKind::InvalidResponse,
                    })
                    .await;
                return;
            }
            if response.terminal_bytes.is_none() {
                tracing::warn!(
                    token = pending.token,
                    peer = %peer,
                    request_id = %request_id,
                    "HistoryStep terminal is unavailable from peer"
                );
                let _ = required_event_tx
                    .send(NetworkEvent::HistoryStepTerminalRequestFailed {
                        token: pending.token,
                        from: pending.peer,
                        height: pending.height,
                        block_hash: pending.block_hash,
                        kind: RequestFailureKind::InvalidResponse,
                    })
                    .await;
                return;
            }
            let inbound_memory_permit = response.inbound_memory_permit.clone();
            let height = response.height;
            let block_hash = response.block_hash;
            let terminal_bytes = response
                .terminal_bytes
                .expect("availability checked before terminal delivery");
            tracing::debug!(
                token = pending.token,
                from = %peer,
                terminal_len = terminal_bytes.len(),
                "received HistoryStep terminal from peer"
            );
            let _ = required_event_tx
                .send(NetworkEvent::HistoryStepTerminal {
                    token: pending.token,
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
            prune_snapshot_export_leases(snapshot_export_leases);
            refresh_snapshot_object_retention_floor(chain_store, snapshot_export_leases);
            prune_snapshot_exports(snapshot_exports, snapshot_export_leases);
            let response = 'ready_manifest: {
                let Some(generation) = select_snapshot_export(
                    &chain_store,
                    snapshot_exports,
                    snapshot_export_leases,
                    request.requester_height,
                    request.requested_manifest_digest,
                ) else {
                    break 'ready_manifest GetStateManifestResponse::default();
                };
                let key = generation.key();
                let manifest = generation.manifest();
                let live_tip = chain_store
                    .get_consensus_meta()
                    .ok()
                    .flatten()
                    .map_or(manifest.bridge_tip_height, |meta| meta.tip_height);

                tracing::debug!(
                    requester_height = request.requester_height,
                    snapshot_height = manifest.target_height,
                    live_tip,
                    segments = manifest.segments.len(),
                    "serving cached immutable snapshot manifest"
                );
                let response = generation.network_manifest.clone();
                if !lease_snapshot_export(
                    snapshot_export_leases,
                    peer,
                    key,
                    response.manifest_digest,
                ) {
                    tracing::debug!(
                        peer = %peer,
                        snapshot_height = key.0,
                        "snapshot generation lease capacity is full"
                    );
                    break 'ready_manifest GetStateManifestResponse::default();
                }
                refresh_snapshot_object_retention_floor(chain_store, snapshot_export_leases);
                response
            };
            let _ = swarm
                .behaviour_mut()
                .state_manifest_sync
                .send_response(channel, response);
        }

        // --- State sync: manifest client (step 1 response) ---
        SwarmEvent::Behaviour(NodeBehaviourEvent::StateManifestSync(
            request_response::Event::Message {
                message:
                    request_response::Message::Response {
                        request_id,
                        response,
                    },
                peer,
            },
        )) => {
            let Some(pending) = pending_state_manifest_requests.remove(&request_id) else {
                tracing::debug!(peer = %peer, request_id = %request_id, "ignoring stale state-manifest response");
                return;
            };
            if !pending.notify_node {
                tracing::debug!(peer = %peer, request_id = %request_id, "discarding superseded state-manifest response");
                return;
            }
            macro_rules! reject_manifest_response {
                ($failed_peer:expr) => {{
                    let _ = required_event_tx
                        .send(NetworkEvent::StateManifestRequestFailed {
                            generation: pending.generation,
                            from: $failed_peer,
                            requester_height: pending.requester_height,
                            kind: RequestFailureKind::InvalidResponse,
                        })
                        .await;
                    return;
                }};
            }
            if pending.peer != peer {
                tracing::debug!(
                    peer = %peer,
                    requested_peer = %pending.peer,
                    request_id = %request_id,
                    "ignoring mismatched state-manifest response"
                );
                reject_manifest_response!(pending.peer);
            }
            if response.tip_height > 0 {
                if response.bridge_tip_height < response.tip_height
                    || response
                        .bridge_tip_height
                        .saturating_sub(response.tip_height)
                        > noid_chain::consensus::params::RECENT_BLOCK_RETENTION_DEPTH
                    || (response.bridge_tip_height == response.tip_height
                        && response.bridge_tip_hash != response.tip_hash)
                {
                    tracing::warn!(
                        from = %peer,
                        snapshot = response.tip_height,
                        bridge_tip = response.bridge_tip_height,
                        "manifest: immutable bridge geometry is invalid"
                    );
                    reject_manifest_response!(peer);
                }
                if response.segment_ids.len() != response.segment_roots.len()
                    || response.segment_ids.len() != response.segment_lengths.len()
                {
                    tracing::warn!(from = %peer, "manifest: descriptor vector length mismatch, dropping");
                    reject_manifest_response!(peer);
                }
                if !response.segment_ids.windows(2).all(|w| w[0] < w[1]) {
                    tracing::warn!(from = %peer, "manifest: segment IDs are not strictly sorted, dropping");
                    reject_manifest_response!(peer);
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
                    reject_manifest_response!(peer);
                }
                if response.segment_ids.len() > MAX_SNAPSHOT_MANIFEST_SEGMENTS {
                    tracing::warn!(
                        from = %peer,
                        segments = response.segment_ids.len(),
                        max_segments = MAX_SNAPSHOT_MANIFEST_SEGMENTS,
                        "manifest: too many segment IDs, dropping"
                    );
                    reject_manifest_response!(peer);
                }
                let Some(maximum_segment_bytes) =
                    max_encoded_segment_len_for_eff_log(response.eff_log)
                else {
                    tracing::warn!(from = %peer, eff_log = response.eff_log, "manifest: invalid effective segment log, dropping");
                    reject_manifest_response!(peer);
                };
                if maximum_segment_bytes > MAX_SEGMENT_BYTES {
                    tracing::warn!(
                        from = %peer,
                        eff_log = response.eff_log,
                        maximum_segment_bytes,
                        max_segment = MAX_SEGMENT_BYTES,
                        "manifest: segment encoding exceeds per-segment cap, dropping"
                    );
                    reject_manifest_response!(peer);
                }
                let mut declared_live_count = 0u64;
                for &encoded_len in &response.segment_lengths {
                    let Some(live_count) =
                        encoded_segment_live_count_from_len(response.eff_log, encoded_len as usize)
                    else {
                        tracing::warn!(from = %peer, encoded_len, "manifest: non-canonical sparse segment length, dropping");
                        reject_manifest_response!(peer);
                    };
                    if live_count == 0 {
                        tracing::warn!(from = %peer, "manifest: empty segment descriptor, dropping");
                        reject_manifest_response!(peer);
                    }
                    let Some(next) = declared_live_count.checked_add(u64::from(live_count)) else {
                        tracing::warn!(from = %peer, "manifest: live-entry count overflow, dropping");
                        reject_manifest_response!(peer);
                    };
                    declared_live_count = next;
                }
                if declared_live_count != response.active_slot_count {
                    tracing::warn!(from = %peer, declared_live_count, active_slot_count = response.active_slot_count, "manifest: sparse lengths disagree with active count, dropping");
                    reject_manifest_response!(peer);
                }
                tracing::info!(
                    from = %peer,
                    tip = response.tip_height,
                    segments = response.segment_ids.len(),
                    "received state manifest"
                );
                let _ = required_event_tx
                    .send(NetworkEvent::StateManifest {
                        generation: pending.generation,
                        from: peer,
                        requester_height: pending.requester_height,
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
                        generation: pending.generation,
                        from: peer,
                        requester_height: pending.requester_height,
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
            prune_snapshot_export_leases(snapshot_export_leases);
            refresh_snapshot_object_retention_floor(chain_store, snapshot_export_leases);
            prune_snapshot_exports(snapshot_exports, snapshot_export_leases);
            let key = (request.expected_tip_height, request.expected_tip_hash);
            let lease_matches = snapshot_export_leases.get_mut(&peer).is_some_and(|lease| {
                if lease.key == key && lease.manifest_digest == request.manifest_digest {
                    lease.last_activity = Instant::now();
                    true
                } else {
                    false
                }
            });
            if !lease_matches {
                let _ = swarm
                    .behaviour_mut()
                    .state_segment_sync
                    .send_response(channel, unavailable_state_segment_response(&request));
                return;
            }
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
            let effective_log = export.manifest().effective_log_segment_size;
            let declared_len = descriptor.encoded_len as usize;
            if declared_len > MAX_SEGMENT_BYTES
                || encoded_segment_live_count_from_len(effective_log, declared_len)
                    .is_none_or(|live_count| live_count == 0)
            {
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
            let Some(serving_lease) = data_plane_serving.lease(peer) else {
                tracing::debug!(peer = %peer, segment = request.segment_id, "State segment serving queue is full");
                return;
            };
            let requested_tip_height = request.expected_tip_height;
            let requested_tip_hash = request.expected_tip_hash;
            let requested_manifest_digest = request.manifest_digest;
            let completion = segment_response_tx.clone();
            let budget = outbound_response_budget.clone();
            let encode_admission = Arc::clone(segment_encode_semaphore);
            tokio::spawn(async move {
                let Ok(serving_permits) = serving_lease.acquire().await else {
                    return;
                };
                // Stream concurrency and the request rate cap already bound the
                // waiter count. Queue behind the two disk encoders instead of
                // lying that an immutable advertised segment is unavailable.
                let Ok(permit) = encode_admission.acquire_owned().await else {
                    return;
                };
                let Ok(Some(outbound_memory_permit)) = budget
                    .acquire_with_serving(declared_len, serving_permits)
                    .await
                else {
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
                        manifest_digest: requested_manifest_digest,
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
                            manifest_digest: requested_manifest_digest,
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
                            manifest_digest: requested_manifest_digest,
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
            if !pending.notify_node {
                tracing::debug!(peer = %peer, request_id = %request_id, "discarding superseded state-segment response");
                return;
            }
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
                fail_state_segment_request!(pending);
                return;
            }
            if let Some(ref data) = response.data {
                let Some(maximum_len) = max_encoded_segment_len_for_eff_log(response.eff_log)
                else {
                    tracing::warn!(peer = %peer, segment = response.segment_id, eff_log = response.eff_log, "segment response has invalid effective segment log — dropped");
                    fail_state_segment_request!(pending);
                    return;
                };
                if maximum_len > MAX_SEGMENT_BYTES
                    || encoded_segment_live_count_from_len(response.eff_log, data.len())
                        .is_none_or(|live_count| live_count == 0)
                {
                    tracing::warn!(
                        peer = %peer,
                        segment = response.segment_id,
                        len = data.len(),
                        "segment response has non-canonical sparse length — dropped"
                    );
                    fail_state_segment_request!(pending);
                    return;
                }
                if data.len() > MAX_SEGMENT_BYTES {
                    tracing::warn!(peer = %peer, segment = response.segment_id, len = data.len(), "segment response too large — dropped");
                    fail_state_segment_request!(pending);
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

        // --- Mempool exchange: pull existing entries or push one new TX ---
        SwarmEvent::Behaviour(NodeBehaviourEvent::MempoolSync(
            request_response::Event::Message {
                message:
                    request_response::Message::Request {
                        request, channel, ..
                    },
                peer,
            },
        )) => match request {
            MempoolRequest::Pull => {
                let Ok(preparation_permit) =
                    Arc::clone(mempool_response_prepare_semaphore).try_acquire_owned()
                else {
                    // Mempool state is recoverable through gossip and a later
                    // sync. Dropping the channel rejects excess preparation
                    // without stalling the swarm task or cloning payload bytes.
                    tracing::debug!(peer = %peer, "mempool sync preparation already occupied");
                    return;
                };
                let budget = outbound_response_budget.clone();
                let mempool = mempool.clone();
                let completion = mempool_response_tx.clone();
                tokio::spawn(async move {
                    // Reserve the maximum legal response before taking the
                    // mempool lock or cloning the first retained intent.
                    let response = match prepare_mempool_response_after_admission(
                        budget,
                        || async {
                            mempool
                                .intent_bytes_prefix(
                                    MAX_MEMPOOL_SYNC_TXS,
                                    MAX_MEMPOOL_SYNC_BYTES,
                                    MAX_TX_INTENT_BYTES_GLOBAL,
                                )
                                .await
                        },
                    )
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
            MempoolRequest::Push {
                intent_bytes,
                inbound_memory_permit,
            } => {
                let response = GetMempoolResponse {
                    txs: Vec::new(),
                    inbound_memory_permit: None,
                    outbound_memory_permit: None,
                };
                let _ = swarm
                    .behaviour_mut()
                    .mempool_sync
                    .send_response(channel, response);
                if !allow_peer_rate(
                    tx_gossip_rate,
                    peer,
                    TX_RELAY_RATE_MAX,
                    TX_RELAY_RATE_WINDOW,
                ) {
                    tracing::debug!(peer = %peer, "direct tx relay rate limit exceeded");
                    return;
                }
                let len = intent_bytes.len();
                if let Err(error) = required_event_tx.try_send(NetworkEvent::NewTx {
                    from: peer,
                    intent_bytes,
                    inbound_memory_permit,
                }) {
                    tracing::debug!(
                        peer = %peer,
                        len,
                        err = %error,
                        "direct tx relay dropped under node backpressure"
                    );
                } else {
                    tracing::debug!(peer = %peer, len, "received direct transaction relay");
                }
            }
        },

        // --- Mempool sync: client side (response to our request) ---
        SwarmEvent::Behaviour(NodeBehaviourEvent::MempoolSync(
            request_response::Event::Message {
                message: request_response::Message::Response { response, .. },
                peer,
            },
        )) => {
            mempool_sync_retries.remove(&peer);
            let GetMempoolResponse {
                txs,
                inbound_memory_permit,
                outbound_memory_permit: _,
            } = response;
            tracing::debug!(
                from = %peer,
                tx_count = txs.len(),
                "mempool sync response complete"
            );
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
            // A simultaneous handshake or a busy bounded response worker is
            // transient. Keep the one-stream memory discipline and retry with
            // bounded exponential backoff plus per-peer jitter.
            mempool_sync_last_request.remove(&peer);
            let local = *swarm.local_peer_id();
            if let Some(retry) = schedule_mempool_sync_retry(mempool_sync_retries, local, peer) {
                tracing::debug!(
                    peer = %peer,
                    err = %error,
                    failures = retry.failures,
                    retry_ms = retry.next_attempt.saturating_duration_since(Instant::now()).as_millis(),
                    "mempool sync request failed — retry scheduled"
                );
            } else {
                tracing::debug!(
                    peer = %peer,
                    err = %error,
                    failures = MAX_MEMPOOL_SYNC_FAILURES,
                    "mempool sync request failed — retry limit reached"
                );
            }
        }

        // --- Connection events ---
        SwarmEvent::ConnectionEstablished {
            peer_id,
            connection_id,
            endpoint,
            ..
        } => {
            let dialer = endpoint.is_dialer();
            let direct = !endpoint.is_relayed();
            sync_paths.insert(connection_id, peer_id, direct, dialer);
            if let Err(reason) = peer_diversity.try_admit(
                connection_id,
                peer_id,
                endpoint.get_remote_address(),
                dialer,
            ) {
                sync_paths.mark_closing(connection_id);
                automatic_peers.note_dial_failed(connection_id);
                let _ = swarm.close_connection(connection_id);
                // `BucketInserts::OnConnected` may have admitted the peer just
                // before the outer swarm event reached us. Do not let a
                // rejected Sybil occupy Kademlia and trigger repeated dials.
                swarm.behaviour_mut().kad.remove_peer(&peer_id);
                tracing::debug!(
                    peer = %peer_id,
                    address = %endpoint.get_remote_address(),
                    ?reason,
                    "closing connection that violates public peer diversity"
                );
                return;
            }
            automatic_peers.note_connection_established(connection_id, peer_id, dialer);
            let duplicate_losers =
                sync_paths.canonicalize_direct(*swarm.local_peer_id(), peer_id, connection_id);
            for loser in &duplicate_losers {
                let _ = swarm.close_connection(*loser);
            }
            tracing::debug!(
                peer = %peer_id,
                ?connection_id,
                dialer,
                direct,
                duplicate_losers = ?duplicate_losers,
                "peer transport connected; awaiting Identify"
            );
        }
        SwarmEvent::ConnectionClosed {
            peer_id,
            connection_id,
            num_established,
            cause,
            ..
        } => {
            let removed_sync_path = sync_paths.remove(connection_id);
            if peer_diversity.remove(connection_id) {
                automatic_peers.note_connection_closed(connection_id);
            } else {
                tracing::debug!(
                    peer = %peer_id,
                    "diversity-rejected connection closed"
                );
            }
            debug_assert!(
                removed_sync_path.is_none_or(|path_peer| path_peer == peer_id),
                "ConnectionClosed peer must match the tracked sync path"
            );
            let sync_peer_became_unready =
                sync_paths.is_announced(peer_id) && !sync_paths.has_identified_path(peer_id);
            if sync_peer_became_unready {
                sync_paths.clear_announced(peer_id);
                // Deliver exact request failures before the generic
                // disconnect event. This deterministic ordering lets the node
                // retain or fail over its disk staging without racing the
                // broader peer cleanup path.
                let failed_objects =
                    pending_object_requests.take_where(|pending| pending.peer == peer_id);
                for pending in failed_objects {
                    let _ = required_event_tx
                        .send(NetworkEvent::ObjectsRequestFailed {
                            token: pending.token,
                            from: pending.peer,
                            objects: pending.objects,
                            kind: RequestFailureKind::ConnectionClosed,
                        })
                        .await;
                }
                let failed_blocks =
                    pending_retained_block_requests.take_where(|pending| pending.peer == peer_id);
                for pending in failed_blocks {
                    fail_retained_request!(pending);
                }
                let failed_headers =
                    pending_header_requests.take_where(|pending| pending.peer == peer_id);
                for pending in failed_headers {
                    if !pending.notify_node {
                        continue;
                    }
                    match pending.kind {
                        HeaderRequestKind::General => {
                            let _ = required_event_tx
                                .send(NetworkEvent::HeadersRequestFailed {
                                    from: pending.peer,
                                    start_height: pending.start_height,
                                    count: pending.count,
                                })
                                .await;
                        }
                        HeaderRequestKind::Snapshot { generation, token } => {
                            let _ = required_event_tx
                                .send(NetworkEvent::SnapshotHeadersRequestFailed {
                                    generation,
                                    token,
                                    from: pending.peer,
                                    start_height: pending.start_height,
                                    count: pending.count,
                                    kind: RequestFailureKind::ConnectionClosed,
                                })
                                .await;
                        }
                    }
                }
                let failed_segments =
                    pending_state_segment_requests.take_where(|pending| pending.peer == peer_id);
                for pending in failed_segments {
                    fail_state_segment_request!(pending);
                }
                let failed_terminals =
                    pending_history_step_requests.take_where(|pending| pending.peer == peer_id);
                for pending in failed_terminals {
                    if pending.notify_node {
                        let _ = required_event_tx
                            .send(NetworkEvent::HistoryStepTerminalRequestFailed {
                                token: pending.token,
                                from: pending.peer,
                                height: pending.height,
                                block_hash: pending.block_hash,
                                kind: RequestFailureKind::ConnectionClosed,
                            })
                            .await;
                    }
                }
                let failed_manifests =
                    pending_state_manifest_requests.take_where(|pending| pending.peer == peer_id);
                for pending in failed_manifests {
                    if pending.notify_node {
                        let _ = required_event_tx
                            .send(NetworkEvent::StateManifestRequestFailed {
                                generation: pending.generation,
                                from: pending.peer,
                                requester_height: pending.requester_height,
                                kind: RequestFailureKind::ConnectionClosed,
                            })
                            .await;
                    }
                }
                let _ = required_event_tx
                    .send(NetworkEvent::PeerDisconnected(peer_id))
                    .await;
                tracing::debug!(peer = %peer_id, cause = ?cause, "peer lost its last sync-ready connection");
            }
            if sync_paths.try_mark_announced(peer_id) {
                let _ = required_event_tx
                    .send(NetworkEvent::PeerConnected {
                        peer: peer_id,
                        failure_domain: peer_diversity.failure_domain(peer_id),
                    })
                    .await;
                tracing::debug!(peer = %peer_id, "peer sync protocols ready after duplicate path closed");
            }
            if num_established == 0 {
                sync_paths.clear_profile_verified(peer_id);
                pending_network_profile_requests.take_where(|pending| pending.peer == peer_id);
                block_event_rate.remove(&peer_id);
                tx_gossip_rate.remove(&peer_id);
                mempool_sync_last_request.remove(&peer_id);
                mempool_sync_retries.remove(&peer_id);
                snapshot_segment_rate.remove(&peer_id);
                snapshot_export_leases.remove(&peer_id);
                refresh_snapshot_object_retention_floor(chain_store, snapshot_export_leases);
                prune_snapshot_exports(snapshot_exports, snapshot_export_leases);
            }
        }

        // --- Outgoing connection failed (dial error) ---
        SwarmEvent::OutgoingConnectionError {
            peer_id,
            connection_id,
            error,
            ..
        } => {
            automatic_peers.note_dial_failed(connection_id);
            tracing::debug!(peer = ?peer_id, err = %error, "outgoing connection error");
            // The automatic manager retries bootstrap addresses and replaces
            // ordinary peers with bounded backoff.
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
            let Some(pending) = pending_retained_block_requests.remove(&request_id) else {
                tracing::debug!(peer = %peer, request_id = %request_id, "ignoring stale block-sync failure");
                return;
            };
            if !pending.notify_node {
                tracing::debug!(peer = %peer, request_id = %request_id, "discarding superseded block-sync failure");
                return;
            }
            if pending.peer != peer {
                tracing::debug!(
                    peer = %peer,
                    request_id = %request_id,
                    requested_peer = %pending.peer,
                    "ignoring mismatched block-sync failure"
                );
                return;
            }
            // A block pull is an exact, independently correlated request.  Do
            // not clear this peer's state-segment or other block requests when
            // one stream fails.
            let _ = required_event_tx
                .send(NetworkEvent::RecentBlockRequestFailed {
                    from: peer,
                    height: pending.height,
                    payload_kind: pending.payload_kind,
                })
                .await;
        }

        SwarmEvent::Behaviour(NodeBehaviourEvent::StateManifestSync(
            request_response::Event::OutboundFailure {
                peer,
                request_id,
                error,
            },
        )) => {
            let kind = RequestFailureKind::from(&error);
            tracing::debug!(peer = %peer, err = %error, "manifest sync request failed");
            let Some(pending) = pending_state_manifest_requests.remove(&request_id) else {
                tracing::debug!(peer = %peer, request_id = %request_id, "ignoring stale state-manifest failure");
                return;
            };
            if !pending.notify_node {
                tracing::debug!(peer = %peer, request_id = %request_id, "discarding superseded state-manifest failure");
                return;
            }
            if pending.peer != peer {
                tracing::debug!(
                    peer = %peer,
                    requested_peer = %pending.peer,
                    request_id = %request_id,
                    "ignoring mismatched state-manifest failure"
                );
                return;
            }
            let _ = required_event_tx
                .send(NetworkEvent::StateManifestRequestFailed {
                    generation: pending.generation,
                    from: peer,
                    requester_height: pending.requester_height,
                    kind,
                })
                .await;
        }

        SwarmEvent::Behaviour(NodeBehaviourEvent::StateSegmentSync(
            request_response::Event::OutboundFailure {
                peer,
                request_id,
                error,
            },
        )) => {
            tracing::debug!(peer = %peer, err = %error, "segment sync request failed");
            let Some(pending) = pending_state_segment_requests.remove(&request_id) else {
                tracing::debug!(peer = %peer, request_id = %request_id, "ignoring stale segment-sync failure");
                return;
            };
            if !pending.notify_node {
                tracing::debug!(peer = %peer, request_id = %request_id, "discarding superseded state-segment failure");
                return;
            }
            if pending.peer != peer {
                tracing::debug!(
                    peer = %peer,
                    requested_peer = %pending.peer,
                    request_id = %request_id,
                    "ignoring mismatched segment-sync failure"
                );
                return;
            }
            fail_state_segment_request!(pending);
        }

        SwarmEvent::Behaviour(NodeBehaviourEvent::HistoryStepSync(
            request_response::Event::OutboundFailure {
                peer,
                request_id,
                error,
            },
        )) => {
            let kind = RequestFailureKind::from(&error);
            tracing::warn!(
                peer = %peer,
                request_id = %request_id,
                ?kind,
                err = %error,
                "HistoryStep terminal request transport failed"
            );
            let Some(pending) = pending_history_step_requests.remove(&request_id) else {
                tracing::debug!(
                    peer = %peer,
                    request_id = %request_id,
                    "ignoring stale HistoryStep request failure"
                );
                return;
            };
            if pending.peer != peer {
                tracing::debug!(
                    peer = %peer,
                    requested_peer = %pending.peer,
                    request_id = %request_id,
                    "ignoring mismatched HistoryStep request failure"
                );
                return;
            }
            if pending.notify_node {
                let _ = required_event_tx
                    .send(NetworkEvent::HistoryStepTerminalRequestFailed {
                        token: pending.token,
                        from: peer,
                        height: pending.height,
                        block_hash: pending.block_hash,
                        kind,
                    })
                    .await;
            }
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

    fn ordered_peer_ids() -> (PeerId, PeerId) {
        let first = PeerId::random();
        let second = PeerId::random();
        if first.to_bytes() < second.to_bytes() {
            (first, second)
        } else {
            (second, first)
        }
    }

    #[test]
    fn identify_alone_cannot_authorize_network_v2_dispatch() {
        let peer = PeerId::random();
        let connection = libp2p::swarm::ConnectionId::new_unchecked(10_000);
        let mut paths = PeerSyncPaths::default();

        paths.insert(connection, peer, true, true);
        paths.mark_identified(connection);
        assert!(!paths.is_dispatchable(peer));
        assert!(!paths.try_mark_announced(peer));

        paths.mark_profile_verified(peer);
        assert!(paths.is_dispatchable(peer));
        assert!(paths.try_mark_announced(peer));

        paths.clear_profile_verified(peer);
        assert!(!paths.is_dispatchable(peer));
    }

    #[test]
    fn identified_direct_path_wins_over_a_late_dns_duplicate() {
        let local = PeerId::random();
        let peer = PeerId::random();
        let established = libp2p::swarm::ConnectionId::new_unchecked(10_001);
        let duplicate = libp2p::swarm::ConnectionId::new_unchecked(10_002);
        let mut paths = PeerSyncPaths::default();

        paths.insert(established, peer, true, true);
        paths.mark_identified(established);
        paths.mark_profile_verified(peer);
        assert!(paths.is_dispatchable(peer));
        assert!(paths.try_mark_announced(peer));

        paths.insert(duplicate, peer, true, true);
        assert_eq!(
            paths.canonicalize_direct(local, peer, duplicate),
            vec![duplicate]
        );
        assert!(paths.is_closing(duplicate));
        assert!(!paths.is_dispatchable(peer));

        assert_eq!(paths.remove(duplicate), Some(peer));
        assert!(paths.is_dispatchable(peer));
        assert!(!paths.try_mark_announced(peer));
    }

    #[test]
    fn opposite_cross_dials_keep_the_same_physical_path() {
        let (lower, higher) = ordered_peer_ids();
        let lower_inbound = libp2p::swarm::ConnectionId::new_unchecked(10_101);
        let lower_outbound = libp2p::swarm::ConnectionId::new_unchecked(10_102);
        let mut lower_paths = PeerSyncPaths::default();
        lower_paths.insert(lower_inbound, higher, true, false);
        lower_paths.mark_identified(lower_inbound);
        lower_paths.insert(lower_outbound, higher, true, true);
        assert_eq!(
            lower_paths.canonicalize_direct(lower, higher, lower_outbound),
            vec![lower_inbound],
            "the lower PeerId keeps its outbound half"
        );

        let higher_outbound = libp2p::swarm::ConnectionId::new_unchecked(10_201);
        let higher_inbound = libp2p::swarm::ConnectionId::new_unchecked(10_202);
        let mut higher_paths = PeerSyncPaths::default();
        higher_paths.insert(higher_outbound, lower, true, true);
        higher_paths.mark_identified(higher_outbound);
        higher_paths.insert(higher_inbound, lower, true, false);
        assert_eq!(
            higher_paths.canonicalize_direct(higher, lower, higher_inbound),
            vec![higher_outbound],
            "the higher PeerId keeps the matching inbound half"
        );
    }

    #[test]
    fn repeated_outbound_dns_dial_keeps_the_established_path() {
        let local = PeerId::random();
        let peer = PeerId::random();
        let first = libp2p::swarm::ConnectionId::new_unchecked(10_301);
        let duplicate = libp2p::swarm::ConnectionId::new_unchecked(10_302);
        let mut paths = PeerSyncPaths::default();

        paths.insert(first, peer, true, true);
        paths.insert(duplicate, peer, true, true);
        assert_eq!(
            paths.canonicalize_direct(local, peer, duplicate),
            vec![duplicate]
        );
        assert!(!paths.is_closing(first));
        assert!(paths.is_closing(duplicate));
    }

    #[test]
    fn inbound_duplicates_block_dispatch_until_the_remote_dialer_closes_one() {
        let local = PeerId::random();
        let peer = PeerId::random();
        let first = libp2p::swarm::ConnectionId::new_unchecked(10_401);
        let duplicate = libp2p::swarm::ConnectionId::new_unchecked(10_402);
        let mut paths = PeerSyncPaths::default();

        paths.insert(first, peer, true, false);
        paths.insert(duplicate, peer, true, false);
        assert!(
            paths.canonicalize_direct(local, peer, duplicate).is_empty(),
            "the listener cannot choose between remote-owned duplicate dials"
        );
        paths.mark_identified(first);
        paths.mark_identified(duplicate);
        paths.mark_profile_verified(peer);
        assert!(!paths.is_dispatchable(peer));

        assert_eq!(paths.remove(duplicate), Some(peer));
        assert!(paths.is_dispatchable(peer));
    }

    #[test]
    fn identified_direct_and_relay_paths_can_coexist() {
        let peer = PeerId::random();
        let direct = libp2p::swarm::ConnectionId::new_unchecked(10_501);
        let relay = libp2p::swarm::ConnectionId::new_unchecked(10_502);
        let mut paths = PeerSyncPaths::default();

        paths.insert(direct, peer, true, true);
        paths.insert(relay, peer, false, true);
        paths.mark_identified(direct);
        paths.mark_identified(relay);
        paths.mark_profile_verified(peer);
        assert!(paths.is_dispatchable(peer));
        assert_eq!(paths.dispatchable_peer_count(), 1);
    }

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
    fn direct_tx_relay_covers_small_networks_and_stays_bounded_at_scale() {
        assert_eq!(direct_tx_relay_limit(0), 0);
        assert_eq!(direct_tx_relay_limit(3), 3);
        assert_eq!(
            direct_tx_relay_limit(TX_DIRECT_SMALL_NETWORK_MAX_PEERS),
            TX_DIRECT_SMALL_NETWORK_MAX_PEERS
        );
        assert_eq!(
            direct_tx_relay_limit(TX_DIRECT_SMALL_NETWORK_MAX_PEERS + 1),
            TX_DIRECT_LARGE_NETWORK_FANOUT
        );
        assert_eq!(direct_tx_relay_limit(1_000), TX_DIRECT_LARGE_NETWORK_FANOUT);
    }

    #[test]
    fn global_gossip_byte_window_is_exact_and_resets() {
        let mut budget = GossipByteWindow::new();
        assert!(budget.admit(40, 64, Duration::from_secs(10)));
        assert!(budget.admit(24, 64, Duration::from_secs(10)));
        assert!(!budget.admit(1, 64, Duration::from_secs(10)));
        assert!(!budget.admit(usize::MAX, 64, Duration::from_secs(10)));

        budget.started_at = Instant::now() - Duration::from_secs(11);
        assert!(budget.admit(64, 64, Duration::from_secs(10)));
        assert_eq!(budget.bytes, 64);
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
    fn snapshot_boundary_keeps_payload_pruning_headroom() {
        let allowance = SNAPSHOT_BOUNDARY_MAX_LIVE_GAP;
        assert!(snapshot_boundary_has_live_headroom(100, 100));
        assert!(snapshot_boundary_has_live_headroom(100, 100 - allowance));
        assert!(!snapshot_boundary_has_live_headroom(
            100,
            100 - allowance - 1
        ));
        assert!(!snapshot_boundary_has_live_headroom(100, 101));
    }

    #[test]
    fn snapshot_selection_keeps_a_live_leased_cohort() {
        let leased = (100, [1; 32]);
        let fresh = (101, [2; 32]);
        let leased_keys = std::collections::HashSet::from([leased]);

        assert!(
            snapshot_export_selection_rank(leased, 109, &leased_keys)
                > snapshot_export_selection_rank(fresh, 110, &leased_keys),
            "a newer disk generation must not split an active bootstrap cohort"
        );
    }

    #[test]
    fn snapshot_generation_leases_retire_the_oldest_key_for_fresh_admission() {
        let first = PeerId::random();
        let second = PeerId::random();
        let third = PeerId::random();
        let key_a = (100, [1; 32]);
        let key_b = (101, [2; 32]);
        let key_c = (102, [3; 32]);
        let mut leases = std::collections::HashMap::new();

        assert!(lease_snapshot_export(&mut leases, first, key_a, [1; 32]));
        assert!(lease_snapshot_export(&mut leases, second, key_b, [2; 32]));
        assert!(lease_snapshot_export(&mut leases, third, key_a, [1; 32]));
        assert!(lease_snapshot_export(&mut leases, third, key_c, [3; 32]));
        assert!(!leases.contains_key(&first));
        assert_eq!(leases.get(&second).map(|lease| lease.key), Some(key_b));
        assert_eq!(leases.get(&third).map(|lease| lease.key), Some(key_c));
        assert_eq!(
            leases
                .values()
                .map(|lease| lease.key)
                .collect::<std::collections::HashSet<_>>()
                .len(),
            MAX_SNAPSHOT_EXPORTS
        );

        leases.get_mut(&second).unwrap().last_activity =
            Instant::now() - SNAPSHOT_EXPORT_LEASE_TTL - Duration::from_secs(1);
        prune_snapshot_export_leases(&mut leases);
        assert!(!leases.contains_key(&second));
        assert_eq!(leases.get(&third).map(|lease| lease.key), Some(key_c));
    }

    #[test]
    fn automatic_peer_state_recovers_bootstrap_and_unique_outbound_slots() {
        let addr: Multiaddr = "/dns4/seed.example/tcp/9400".parse().unwrap();
        let peer = PeerId::random();
        let connection_id = libp2p::swarm::ConnectionId::new_unchecked(1);
        let mut state = AutomaticPeerState::new(PeerId::random());
        state.register_bootstrap(addr.clone());
        state
            .pending
            .insert(connection_id, PendingAutomaticDial::Bootstrap(addr.clone()));
        state.note_connection_established(connection_id, peer, true);

        assert_eq!(
            state.outbound_peer_count(),
            0,
            "transport alone is not a usable network peer"
        );
        state.note_identified(connection_id, peer);
        assert_eq!(state.outbound_peer_count(), 1);
        assert_eq!(state.bootstrap.get(&addr).unwrap().peer, Some(peer));
        assert!(state.pending.is_empty());

        state.note_connection_closed(connection_id);
        assert_eq!(state.outbound_peer_count(), 0);
        let candidate = state.bootstrap.get(&addr).unwrap();
        assert_eq!(candidate.failures, 1);
        assert!(candidate.next_attempt > Instant::now());
    }

    #[test]
    fn automatic_retry_is_bounded_and_jittered() {
        let first = automatic_retry_delay(1, b"first", b"local-a");
        let later = automatic_retry_delay(u8::MAX, b"later", b"local-b");
        assert!((Duration::from_secs(5)..Duration::from_secs(10)).contains(&first));
        assert!((Duration::from_secs(300)..Duration::from_secs(305)).contains(&later));
    }

    #[test]
    fn malformed_history_transport_is_not_classified_as_transient_io() {
        let malformed = request_response::OutboundFailure::Io(std::io::Error::from(
            std::io::ErrorKind::InvalidData,
        ));
        let truncated = request_response::OutboundFailure::Io(std::io::Error::from(
            std::io::ErrorKind::UnexpectedEof,
        ));
        let transient = request_response::OutboundFailure::Io(std::io::Error::from(
            std::io::ErrorKind::ConnectionReset,
        ));

        assert_eq!(
            RequestFailureKind::from(&malformed),
            RequestFailureKind::InvalidResponse
        );
        assert_eq!(
            RequestFailureKind::from(&truncated),
            RequestFailureKind::InvalidResponse
        );
        assert_eq!(RequestFailureKind::from(&transient), RequestFailureKind::Io);
    }

    #[test]
    fn bootstrap_preserves_two_peer_quorum_until_ordinary_replacement() {
        for (ordinary, expected_seeds) in [(0, 2), (1, 1), (2, 0), (12, 0)] {
            assert_eq!(
                desired_bootstrap_connections(true, ordinary, 6),
                expected_seeds,
                "ordinary={ordinary}"
            );
        }
        assert_eq!(desired_bootstrap_connections(false, 12, 3), 2);
        assert_eq!(desired_bootstrap_connections(true, 0, 3), 2);
        assert_eq!(desired_bootstrap_connections(true, 0, 1), 1);
        assert_eq!(desired_bootstrap_connections(true, 0, 0), 0);
    }

    #[test]
    fn pending_dns_probe_does_not_impersonate_connected_bootstrap_quorum() {
        assert_eq!(
            bootstrap_probe_capacity(2, 1, 1, 8, 8),
            1,
            "one connected seed still requires one staggered alternative"
        );
        assert_eq!(
            bootstrap_probe_capacity(2, 0, 2, 8, 8),
            2,
            "two unresolved DNS transports must not stop alternate probes"
        );
        assert_eq!(bootstrap_probe_capacity(2, 0, 4, 8, 8), 0);
        assert_eq!(bootstrap_probe_capacity(2, 2, 0, 8, 8), 0);
    }

    #[tokio::test]
    async fn data_plane_admission_prevents_one_peer_from_occupying_all_slots() {
        let mut admission = DataPlaneServingAdmission::new();
        let first = PeerId::random();
        let second = PeerId::random();
        let first_a = admission.lease(first).unwrap().acquire().await.unwrap();
        let _first_b = admission.lease(first).unwrap().acquire().await.unwrap();
        let third_from_first = tokio::spawn(admission.lease(first).unwrap().acquire());
        tokio::task::yield_now().await;
        assert!(!third_from_first.is_finished());
        let _fourth_from_first = admission.lease(first).unwrap();
        assert!(admission.lease(first).is_none());

        let _second = admission.lease(second).unwrap().acquire().await.unwrap();
        assert_eq!(admission.active_slots(), 3);

        drop(first_a);
        assert!(
            tokio::time::timeout(Duration::from_secs(1), third_from_first)
                .await
                .unwrap()
                .unwrap()
                .is_ok()
        );
    }

    #[test]
    fn data_plane_waiters_are_globally_bounded() {
        let mut admission = DataPlaneServingAdmission::new();
        let mut leases = Vec::new();
        for _ in 0..(DataPlaneServingAdmission::GLOBAL_OUTSTANDING
            / DataPlaneServingAdmission::PER_PEER_OUTSTANDING)
        {
            let peer = PeerId::random();
            for _ in 0..DataPlaneServingAdmission::PER_PEER_OUTSTANDING {
                leases.push(admission.lease(peer).unwrap());
            }
        }
        assert_eq!(leases.len(), DataPlaneServingAdmission::GLOBAL_OUTSTANDING);
        assert!(admission.lease(PeerId::random()).is_none());
        drop(leases.pop());
        assert!(admission.lease(PeerId::random()).is_some());
    }

    #[test]
    fn failed_dns_identity_pin_is_cleared_before_reresolution() {
        let local = PeerId::random();
        let old_peer = PeerId::random();
        let addr: Multiaddr = "/dns4/seed.example/tcp/9400".parse().unwrap();
        let connection_id = libp2p::swarm::ConnectionId::new_unchecked(7);
        let mut state = AutomaticPeerState::new(local);
        state.register_bootstrap(addr.clone());
        state.bootstrap.get_mut(&addr).unwrap().peer = Some(old_peer);
        state
            .pending
            .insert(connection_id, PendingAutomaticDial::Bootstrap(addr.clone()));

        state.note_dial_failed(connection_id);

        let candidate = state.bootstrap.get(&addr).unwrap();
        assert_eq!(candidate.peer, None);
        assert_eq!(candidate.failures, 1);
        assert!(candidate.next_attempt > Instant::now());
    }

    #[test]
    fn aggregate_and_individual_dns_sources_count_one_target_peer() {
        let local = PeerId::random();
        let peer = PeerId::random();
        let aggregate: Multiaddr = "/dnsaddr/noid.network".parse().unwrap();
        let individual: Multiaddr = "/dns4/seed1.noid.network/tcp/9400".parse().unwrap();
        let first = libp2p::swarm::ConnectionId::new_unchecked(71);
        let duplicate = libp2p::swarm::ConnectionId::new_unchecked(72);
        let mut state = AutomaticPeerState::new(local);
        state.add_peer_candidate(local, peer, ["/ip4/8.8.8.8/tcp/9400".parse().unwrap()]);
        assert!(state.peers.contains_key(&peer));
        state.register_bootstrap(aggregate.clone());
        state.register_bootstrap(individual.clone());
        state
            .pending
            .insert(first, PendingAutomaticDial::Bootstrap(aggregate.clone()));
        state.pending.insert(
            duplicate,
            PendingAutomaticDial::Bootstrap(individual.clone()),
        );

        state.note_connection_established(first, peer, true);
        assert!(!state.peers.contains_key(&peer));
        assert!(!state.add_peer_candidate(local, peer, ["/ip4/8.8.4.4/tcp/9400".parse().unwrap()]));
        assert!(!state.peers.contains_key(&peer));
        state.note_connection_established(duplicate, peer, true);
        state.note_identified(first, peer);
        state.note_identified(duplicate, peer);
        assert_eq!(state.outbound_peer_count(), 1);
        assert_eq!(state.managed_connections.len(), 2);
        assert_eq!(state.outbound_connections.get(&first), Some(&peer));
        assert_eq!(state.outbound_connections.get(&duplicate), Some(&peer));
        assert_eq!(state.bootstrap.get(&aggregate).unwrap().peer, Some(peer));
        assert_eq!(state.bootstrap.get(&individual).unwrap().peer, Some(peer));
    }

    #[test]
    fn unresolved_seed_probes_do_not_reserve_ordinary_peer_slots() {
        let local = PeerId::random();
        let mut state = AutomaticPeerState::new(local);
        for id in 1..=MAX_PENDING_BOOTSTRAP_DIALS {
            let addr: Multiaddr = format!("/dns4/seed{id}.example/tcp/9400").parse().unwrap();
            state.pending.insert(
                libp2p::swarm::ConnectionId::new_unchecked(id),
                PendingAutomaticDial::Bootstrap(addr),
            );
        }
        for id in 100..100 + AUTOMATIC_OUTBOUND_TARGET {
            state.pending.insert(
                libp2p::swarm::ConnectionId::new_unchecked(id),
                PendingAutomaticDial::Peer {
                    peer: PeerId::random(),
                    group: PublicNetworkGroup::Ipv4([8, 8]),
                },
            );
        }

        assert_eq!(state.pending_bootstrap_count(), MAX_PENDING_BOOTSTRAP_DIALS);
        assert_eq!(state.pending_ordinary_count(), AUTOMATIC_OUTBOUND_TARGET);
        assert!(state.pending.len() < MAX_UNCONFIRMED_AUTOMATIC_CONNECTIONS);
        assert_eq!(
            state
                .outbound_peer_count()
                .saturating_add(state.pending_ordinary_count()),
            AUTOMATIC_OUTBOUND_TARGET
        );
        assert_eq!(
            automatic_ordinary_dial_capacity(
                0,
                0,
                false,
                MAX_UNCONFIRMED_AUTOMATIC_CONNECTIONS - MAX_PENDING_BOOTSTRAP_DIALS,
            ),
            AUTOMATIC_OUTBOUND_TARGET
        );
    }

    #[test]
    fn unidentified_transports_are_bounded_without_counting_as_healthy_peers() {
        let mut state = AutomaticPeerState::new(PeerId::random());
        for id in 0..MAX_UNCONFIRMED_AUTOMATIC_CONNECTIONS {
            state.track_managed_connection(
                libp2p::swarm::ConnectionId::new_unchecked(1_000 + id),
                PeerId::random(),
                ManagedOutboundKind::Peer,
            );
        }
        assert_eq!(state.outbound_peer_count(), 0);
        assert_eq!(
            state.automatic_occupancy(),
            MAX_UNCONFIRMED_AUTOMATIC_CONNECTIONS
        );
        assert_eq!(
            automatic_ordinary_dial_capacity(
                state.outbound_peer_count(),
                state.pending_ordinary_count(),
                false,
                state.automatic_dial_capacity(),
            ),
            0
        );

        let released = *state.managed_connections.keys().next().unwrap();
        state.note_connection_closed(released);
        assert_eq!(
            state.automatic_occupancy(),
            MAX_UNCONFIRMED_AUTOMATIC_CONNECTIONS - 1
        );
        assert_eq!(
            automatic_ordinary_dial_capacity(
                state.outbound_peer_count(),
                state.pending_ordinary_count(),
                false,
                state.automatic_dial_capacity(),
            ),
            1
        );
    }

    #[test]
    fn two_healthy_paths_per_peer_still_reach_the_unique_peer_target() {
        let mut state = AutomaticPeerState::new(PeerId::random());
        for peer_index in 0..AUTOMATIC_OUTBOUND_TARGET {
            let peer = PeerId::random();
            for path in 0..2 {
                let connection_id =
                    libp2p::swarm::ConnectionId::new_unchecked(2_000 + peer_index * 2 + path);
                state.track_managed_connection(connection_id, peer, ManagedOutboundKind::Peer);
                state.note_identified(connection_id, peer);
            }
        }
        assert_eq!(state.outbound_peer_count(), AUTOMATIC_OUTBOUND_TARGET);
        assert_eq!(state.automatic_occupancy(), AUTOMATIC_OUTBOUND_TARGET * 2);
        assert_eq!(
            automatic_ordinary_dial_capacity(
                state.outbound_peer_count(),
                state.pending_ordinary_count(),
                false,
                state.automatic_dial_capacity(),
            ),
            0
        );
    }

    #[test]
    fn seed_replacement_has_exactly_one_overlap_slot() {
        assert_eq!(
            automatic_ordinary_dial_capacity(
                AUTOMATIC_OUTBOUND_TARGET,
                0,
                true,
                MAX_UNCONFIRMED_AUTOMATIC_CONNECTIONS,
            ),
            1
        );
        assert_eq!(
            automatic_ordinary_dial_capacity(
                AUTOMATIC_OUTBOUND_TARGET,
                1,
                true,
                MAX_UNCONFIRMED_AUTOMATIC_CONNECTIONS,
            ),
            0,
            "one pending replacement must suppress another overlap dial"
        );
        assert_eq!(
            automatic_ordinary_dial_capacity(
                AUTOMATIC_OUTBOUND_TARGET - 1,
                0,
                false,
                MAX_UNCONFIRMED_AUTOMATIC_CONNECTIONS,
            ),
            1
        );
    }

    #[test]
    fn invalid_kad_candidates_cannot_fill_the_bounded_pool() {
        let local = PeerId::random();
        let mut state = AutomaticPeerState::new(local);
        for _ in 0..(MAX_AUTOMATIC_PEER_CANDIDATES + 50) {
            assert!(!state.add_peer_candidate(
                local,
                PeerId::random(),
                ["/ip4/127.0.0.1/tcp/9400".parse().unwrap()]
            ));
        }
        assert!(state.peers.is_empty());

        let valid = PeerId::random();
        assert!(state.add_peer_candidate(local, valid, ["/ip4/8.8.8.8/tcp/9400".parse().unwrap()]));
        assert!(state.peers.contains_key(&valid));

        let mismatched = PeerId::random();
        let advertised = PeerId::random();
        assert!(!state.add_peer_candidate(
            local,
            mismatched,
            [format!("/ip4/9.9.9.9/tcp/9400/p2p/{advertised}")
                .parse()
                .unwrap()]
        ));
    }

    #[test]
    fn pending_outbound_dials_reserve_public_network_group_capacity() {
        let local = PeerId::random();
        let mut state = AutomaticPeerState::new(local);
        let group =
            crate::peer_diversity::public_network_group(&"/ip4/8.8.1.1/tcp/9400".parse().unwrap())
                .unwrap();
        for id in 1..=2 {
            state.pending.insert(
                libp2p::swarm::ConnectionId::new_unchecked(id),
                PendingAutomaticDial::Peer {
                    peer: PeerId::random(),
                    group,
                },
            );
        }
        let candidate = PeerId::random();
        let addr: Multiaddr = "/ip4/8.8.2.2/tcp/9400".parse().unwrap();
        assert_eq!(state.pending_group_count(group), 2);
        assert!(
            !PeerDiversity::default().outbound_candidate_allowed_with_pending(
                candidate,
                &addr,
                state.pending_group_count(group)
            )
        );
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
        let pending = PendingRetainedBlockRequest {
            peer,
            height: 77,
            count: 1,
            payload_kind: RecentBlockPayloadKind::Complete,
            issued_at: Instant::now(),
            notify_node: true,
        };
        assert!(retained_block_response_matches_pending(
            pending, peer, 77, 1
        ));
        assert!(!retained_block_response_matches_pending(
            pending, other_peer, 77, 1
        ));
        assert!(!retained_block_response_matches_pending(
            pending, peer, 78, 1
        ));
        assert!(!retained_block_response_matches_pending(
            pending, peer, 77, 2
        ));

        let mut registry = BoundedPendingRequests::new(2);
        assert!(registry.try_insert(10u64, pending));
        assert!(registry.try_insert(
            11,
            PendingRetainedBlockRequest {
                peer,
                height: 78,
                count: 2,
                payload_kind: RecentBlockPayloadKind::BlockBody,
                issued_at: Instant::now(),
                notify_node: true,
            }
        ));
        assert!(!registry.try_insert(
            12,
            PendingRetainedBlockRequest {
                peer,
                height: 79,
                count: 1,
                payload_kind: RecentBlockPayloadKind::Complete,
                issued_at: Instant::now(),
                notify_node: true,
            }
        ));
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
        assert!(registry.try_insert(
            12,
            PendingRetainedBlockRequest {
                peer,
                height: 79,
                count: 1,
                payload_kind: RecentBlockPayloadKind::Complete,
                issued_at: Instant::now(),
                notify_node: true,
            }
        ));
        registry.retain(|_, entry| entry.peer != peer);
        assert_eq!(registry.len(), 0, "disconnect clears peer-owned requests");
    }

    #[test]
    fn state_segment_transport_rejects_same_peer_cross_session_response() {
        let peer = PeerId::random();
        let old = PendingStateSegmentRequest {
            peer,
            segment_id: 7,
            expected_tip_height: 144,
            expected_tip_hash: [0xA5; 32],
            manifest_digest: [0x11; 32],
            issued_at: Instant::now(),
            notify_node: true,
        };
        let response = GetStateSegmentResponse {
            segment_id: 7,
            expected_tip_height: 144,
            expected_tip_hash: [0xA5; 32],
            manifest_digest: [0x11; 32],
            eff_log: 0,
            data: None,
            inbound_memory_permit: None,
            outbound_memory_permit: None,
        };
        assert!(state_segment_response_matches_pending(old, peer, &response));

        let new_session = PendingStateSegmentRequest {
            manifest_digest: [0x22; 32],
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

        let request = GetStateSegmentRequest {
            segment_id: 9,
            expected_tip_height: 200,
            expected_tip_hash: [0xCC; 32],
            manifest_digest: [0x33; 32],
        };
        let unavailable = unavailable_state_segment_response(&request);
        assert_eq!(unavailable.segment_id, request.segment_id);
        assert_eq!(unavailable.expected_tip_height, request.expected_tip_height);
        assert_eq!(unavailable.expected_tip_hash, request.expected_tip_hash);
        assert_eq!(unavailable.manifest_digest, request.manifest_digest);
    }

    #[test]
    fn distinct_history_step_terminal_races_coexist_and_evict_only_the_oldest() {
        let first_peer = PeerId::random();
        let second_peer = PeerId::random();
        let issued_at = Instant::now();
        let request = |token, peer, height| PendingHistoryStepTerminalRequest {
            token,
            peer,
            height,
            block_hash: [height as u8; 32],
            issued_at: issued_at + Duration::from_millis(token),
            notify_node: true,
        };
        let mut registry = BoundedPendingRequests::new(4);
        assert!(registry.try_insert(1u64, request(10, first_peer, 100)));
        assert!(registry.try_insert(2u64, request(10, second_peer, 100)));
        assert!(registry.try_insert(3u64, request(11, first_peer, 118)));
        assert!(registry.try_insert(4u64, request(11, second_peer, 118)));

        let retired = admit_history_step_terminal_race(&mut registry);
        assert_eq!(retired.len(), 2);
        assert!(retired.iter().all(|(_, pending)| pending.token == 10));
        assert_eq!(registry.len(), 2);
        assert!(registry.entries.values().all(|pending| pending.token == 11));
        assert!(registry.try_insert(5u64, request(12, first_peer, 119)));
        assert!(admit_history_step_terminal_race(&mut registry).is_empty());
    }

    #[test]
    fn superseded_snapshot_header_transport_is_retained_until_expiry() {
        let peer = PeerId::random();
        let now = Instant::now();
        let expired_at = now
            .checked_sub(SMALL_SYNC_PENDING_DEADLINE)
            .expect("process monotonic clock exceeds request deadline");
        let mut registry = BoundedPendingRequests::new(4);
        assert!(registry.try_insert(
            1u64,
            PendingHeaderRequest {
                peer,
                start_height: 1,
                count: 512,
                kind: HeaderRequestKind::Snapshot {
                    generation: 7,
                    token: 11,
                },
                issued_at: expired_at,
                notify_node: false,
            }
        ));
        assert!(registry.try_insert(
            2u64,
            PendingHeaderRequest {
                peer,
                start_height: 513,
                count: 512,
                kind: HeaderRequestKind::Snapshot {
                    generation: 8,
                    token: 12,
                },
                issued_at: now,
                notify_node: true,
            }
        ));
        assert!(registry.try_insert(
            3u64,
            PendingHeaderRequest {
                peer,
                start_height: 99,
                count: 20,
                kind: HeaderRequestKind::General,
                issued_at: now,
                notify_node: true,
            }
        ));

        assert_eq!(registry.len(), 3);
        let expired = registry.take_where_entries(|pending| {
            now.saturating_duration_since(pending.issued_at) >= SMALL_SYNC_PENDING_DEADLINE
        });
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].0, 1);
        assert_eq!(registry.len(), 2);
        assert!(registry.remove(&1).is_none());
        assert!(registry.remove(&2).is_some());
        assert!(
            registry.remove(&3).is_some(),
            "general tip probes are independent"
        );
    }

    #[test]
    fn snapshot_header_window_keeps_distinct_ranges_in_one_generation_live() {
        let peer = PeerId::random();
        let request = |generation, start_height| PendingHeaderRequest {
            peer,
            start_height,
            count: 512,
            kind: HeaderRequestKind::Snapshot {
                generation,
                token: start_height,
            },
            issued_at: Instant::now(),
            notify_node: true,
        };

        let first = request(9, 1);
        let second = request(9, 513);
        let old = request(8, 1025);
        assert!(snapshot_header_request_is_superseded(&first, 9, 1));
        assert!(!snapshot_header_request_is_superseded(&first, 9, 513));
        assert!(!snapshot_header_request_is_superseded(&second, 9, 1));
        assert!(snapshot_header_request_is_superseded(&old, 9, 1));

        let general = PendingHeaderRequest {
            kind: HeaderRequestKind::General,
            ..first
        };
        assert!(!snapshot_header_request_is_superseded(&general, 9, 1));
    }

    #[test]
    fn header_batch_shape_rejects_noncontiguity_without_rehashing_links() {
        let mut first = noid_chain::consensus::genesis::genesis_header();
        first.height = 77;
        let mut second = first;
        second.height = 78;
        second.prev_block_hash = noid_chain::hash_block_header(&first);
        assert_eq!(
            validate_header_batch_shape(&[
                HeaderInventoryRecord::header_only(first),
                HeaderInventoryRecord::header_only(second),
            ]),
            Ok(())
        );

        let mut skipped = second;
        skipped.height = 79;
        assert_eq!(
            validate_header_batch_shape(&[
                HeaderInventoryRecord::header_only(first),
                HeaderInventoryRecord::header_only(skipped),
            ]),
            Err("header batch is not height-contiguous")
        );

        // Parent-link hashing belongs to the single authoritative consensus
        // pass in snapshot staging, not the transport-shape layer.
        let mut wrong_parent = second;
        wrong_parent.prev_block_hash[0] ^= 1;
        assert_eq!(
            validate_header_batch_shape(&[
                HeaderInventoryRecord::header_only(first),
                HeaderInventoryRecord::header_only(wrong_parent),
            ]),
            Ok(())
        );
    }

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn canonical_wire_caps_are_ordered() {
        assert!(crate::header_protocol::HEADER_ANNOUNCE_BYTES < MAX_TX_INTENT_BYTES_GLOBAL);
        assert!(MAX_MEMPOOL_SYNC_BYTES >= MAX_TX_INTENT_BYTES_GLOBAL);
        assert!(MAX_HISTORY_STEP_TERMINAL_BYTES < MAX_ACCEPTED_BLOCK_BUNDLE_BYTES);
    }

    #[tokio::test]
    async fn required_response_survives_recoverable_gossip_lag() {
        let (required_tx, required_rx) = event_dispatch::channel();
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
                payload_kind: RecentBlockPayloadKind::Complete,
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

    #[test]
    fn mempool_retry_is_per_peer_bounded_and_exponential() {
        let local = libp2p::identity::Keypair::generate_ed25519()
            .public()
            .to_peer_id();
        let peer = libp2p::identity::Keypair::generate_ed25519()
            .public()
            .to_peer_id();
        let mut retries = std::collections::HashMap::new();
        let before = Instant::now();
        schedule_mempool_sync_retry(&mut retries, local, peer).unwrap();
        let first = retries[&peer];
        assert_eq!(first.failures, 1);
        assert!(first.next_attempt >= before + Duration::from_secs(1));
        assert!(first.next_attempt <= before + Duration::from_secs(5));

        schedule_mempool_sync_retry(&mut retries, local, peer).unwrap();
        let second = retries[&peer];
        assert_eq!(second.failures, 2);
        assert!(second.next_attempt > first.next_attempt);
        for expected_failures in 3..=MAX_MEMPOOL_SYNC_FAILURES {
            let retry = schedule_mempool_sync_retry(&mut retries, local, peer).unwrap();
            assert_eq!(retry.failures, expected_failures);
        }
        assert!(schedule_mempool_sync_retry(&mut retries, local, peer).is_none());
        assert!(retries.is_empty());
        assert!(mempool_sync_retry_jitter(local, peer) < Duration::from_secs(4));
    }
}
