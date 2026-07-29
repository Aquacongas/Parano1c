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
use rand::seq::SliceRandom;
use tokio::sync::{mpsc, RwLock, Semaphore};

use noid_chain::consensus::wire_limits::{
    INLINE_BLOCK_GOSSIP_THRESHOLD, MAX_BLOCK_BYTES, MAX_HISTORY_STEP_TERMINAL_BYTES,
    MAX_MEMPOOL_SYNC_BYTES, MAX_MEMPOOL_SYNC_TXS, MAX_SEGMENT_BYTES,
    MAX_SNAPSHOT_MANIFEST_SEGMENTS, MAX_TX_INTENT_BYTES_GLOBAL,
};
use noid_chain::storage::{
    encoded_segment_live_count_from_len, max_encoded_segment_len_for_eff_log, MdbxChainContext,
};
use noid_chain::storage::{
    export_snapshot_generation, open_snapshot_generation, SnapshotGeneration,
};
use noid_chain::{AcceptedBlockBundle, MAX_ACCEPTED_BLOCK_BUNDLE_BYTES};
use noid_mempool::AsyncMempool;

use crate::behaviour::{NodeBehaviour, NodeBehaviourEvent};
use crate::outbound_budget::OutboundResponseBudget;
use crate::peer_diversity::{PeerDiversity, PublicNetworkGroup};
use crate::protocol::{
    BlockGossipMsg, GetHeadersResponse, GetHistoryStepTerminalResponse, GetMempoolResponse,
    GetRecentBlockResponse, GetStateManifestResponse, GetStateSegmentRequest,
    GetStateSegmentResponse, NetworkTopics, RecentBlockPayload, RecentBlockPayloadKind,
    BLOCK_GOSSIP_FIXED_BYTES, MAX_BLOCK_BODY_BATCH,
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
const SNAPSHOT_EXPORT_LEASE_TTL: Duration = Duration::from_secs(15 * 60);
const SNAPSHOT_BRIDGE_MAX_LIVE_GAP: u64 =
    noid_chain::consensus::params::RECENT_BLOCK_RETENTION_DEPTH / 2;
const MAX_OUTBOUND_BLOCK_RESPONSE_BYTES: usize = MAX_ACCEPTED_BLOCK_BUNDLE_BYTES;
const MAX_OUTBOUND_BLOCK_BODY_BATCH_BYTES: usize =
    (MAX_BLOCK_BYTES + 4) * MAX_BLOCK_BODY_BATCH as usize;
const MAX_OUTBOUND_BLOCK_BODY_BATCH_RESERVATION: usize =
    MAX_OUTBOUND_BLOCK_BODY_BATCH_BYTES + 2 * MAX_ACCEPTED_BLOCK_BUNDLE_BYTES;
const MAX_OUTBOUND_HISTORY_STEP_RESPONSE_BYTES: usize = MAX_HISTORY_STEP_TERMINAL_BYTES;
const MAX_PENDING_RETAINED_BLOCK_REQUESTS: usize = 256;
const MAX_PENDING_HEADER_REQUESTS: usize = 64;
const MAX_PENDING_STATE_SEGMENT_REQUESTS: usize = 64;
const MAX_PENDING_HISTORY_STEP_REQUESTS: usize = 8;
const AUTOMATIC_OUTBOUND_TARGET: usize = 12;
// The shipped topology contains six individual DNS seeds plus one aggregate
// dnsaddr source. Probe all of them when necessary, but leave room in the
// global pending table for ordinary peers learned through Kademlia.
const MAX_PENDING_BOOTSTRAP_DIALS: usize = 7;
const MAX_UNCONFIRMED_AUTOMATIC_CONNECTIONS: usize =
    AUTOMATIC_OUTBOUND_TARGET + MAX_PENDING_BOOTSTRAP_DIALS + 1;
// Twelve peers may legitimately use two relay/direct paths each. Keep room
// for those paths while bounding all automatic transports well below the
// swarm's 64 established-outbound ceiling.
const MAX_AUTOMATIC_TRANSPORT_OCCUPANCY: usize = 32;
// The swarm itself admits at most 32 pending outbound transports.
const _: () = assert!(MAX_UNCONFIRMED_AUTOMATIC_CONNECTIONS <= 32);
const INITIAL_BOOTSTRAP_FANOUT: usize = 3;
const BOOTSTRAP_RELEASE_NON_SEED_PEERS: usize = 8;
const MAX_AUTOMATIC_PEER_CANDIDATES: usize = 512;
const MAX_AUTOMATIC_ADDRS_PER_PEER: usize = 8;
const AUTOMATIC_PEER_HEALTHY_AFTER: Duration = Duration::from_secs(30);
const DISCOVERY_RETRY_MIN: Duration = Duration::from_secs(10);
const DISCOVERY_RETRY_MAX: Duration = Duration::from_secs(5 * 60);

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
    /// Every outbound transport, including short Kademlia/AutoNAT sessions.
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
        if peer == local {
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
    last_activity: Instant,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PendingRetainedBlockRequest {
    peer: PeerId,
    height: u64,
    count: u16,
    payload_kind: RecentBlockPayloadKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PendingStateSegmentRequest {
    peer: PeerId,
    segment_id: u16,
    expected_tip_height: u64,
    expected_tip_hash: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PendingHeaderRequest {
    peer: PeerId,
    start_height: u64,
    count: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PendingHistoryStepTerminalRequest {
    token: u64,
    peer: PeerId,
    height: u64,
    block_hash: [u8; 32],
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

    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.len()
    }
}

impl<K: std::hash::Hash + Eq + Clone, V> BoundedPendingRequests<K, V> {
    fn take_where(&mut self, mut matches: impl FnMut(&V) -> bool) -> Vec<V> {
        let ids = self
            .entries
            .iter()
            .filter_map(|(id, pending)| matches(pending).then_some(id.clone()))
            .collect::<Vec<_>>();
        ids.into_iter()
            .filter_map(|id| self.entries.remove(&id))
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

fn snapshot_bridge_has_live_headroom(live_tip: u64, bridge_tip: u64) -> bool {
    bridge_tip <= live_tip && live_tip.saturating_sub(bridge_tip) <= SNAPSHOT_BRIDGE_MAX_LIVE_GAP
}

/// Select the freshest complete immutable generation that still has ample
/// live-window headroom after its captured bridge. The state boundary itself
/// may be older than the node's newest finalized checkpoint: its terminal and
/// complete initial suffix are generation-owned and therefore cannot race
/// pruning.
fn select_snapshot_export(
    ctx: &MdbxChainContext,
    exports: &std::collections::HashMap<SnapshotExportKey, SnapshotExport>,
    requester_height: u64,
) -> Option<SnapshotExport> {
    exports
        .values()
        .filter(|generation| {
            let manifest = generation.manifest();
            if manifest.target_height == 0
                || manifest.target_height <= requester_height
                || manifest.target_height > ctx.finalized_checkpoint().height
                || manifest.bridge_tip_height < manifest.target_height
                || !snapshot_bridge_has_live_headroom(ctx.tip_height(), manifest.bridge_tip_height)
            {
                return false;
            }
            let boundary_matches = ctx
                .store
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
            let bridge_matches = ctx
                .store
                .get_header(manifest.bridge_tip_height)
                .ok()
                .flatten()
                .is_some_and(|header| {
                    noid_chain::hash_block_header(&header) == manifest.bridge_tip_hash
                });
            let work_matches = ctx
                .store
                .get_chain_work(manifest.target_height)
                .ok()
                .flatten()
                == Some(manifest.cumulative_chainwork)
                && ctx
                    .store
                    .get_chain_work(manifest.bridge_tip_height)
                    .ok()
                    .flatten()
                    == Some(manifest.bridge_cumulative_chainwork);
            boundary_matches && bridge_matches && work_matches
        })
        .max_by_key(|generation| {
            (
                generation.manifest().target_height,
                generation.manifest().bridge_tip_height,
            )
        })
        .cloned()
}

/// Load one exact canonical HistoryStep terminal from the bounded recent
/// window. Snapshot state boundaries are finalized, while the compact suffix
/// tip may legitimately be newer when blocks arrive during state download.
fn local_history_step_terminal(
    ctx: &MdbxChainContext,
    height: u64,
    block_hash: [u8; 32],
) -> Option<Vec<u8>> {
    if height == 0
        || height > ctx.tip_height()
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
    /// Register a bootstrap address with automatic retry and peer maintenance.
    Dial { addr: Multiaddr },
    /// Initial chain synchronization is complete; bootstrap connections may be
    /// released once enough ordinary outbound peers are available.
    BootstrapComplete,
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
    /// Request one bounded consecutive range of canonical block bodies for
    /// authenticated snapshot-tail staging.
    RequestBlockBodies {
        peer: PeerId,
        height: u64,
        count: u16,
    },
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
        /// Node-local correlation token. It is never sent on the wire.
        token: u64,
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
    /// A new TxIntent arrived from a peer.
    NewTx { from: PeerId, intent_bytes: Vec<u8> },
    /// Response to FetchHeaders: decoded headers from the peer.
    /// Used by reorg detection to find the common ancestor quickly.
    HeadersBatch {
        from: PeerId,
        headers: Vec<noid_chain::block_header::BlockHeader>,
    },
    /// Transport or decoding failed for one exact header request.
    HeadersRequestFailed {
        from: PeerId,
        start_height: u64,
        count: u16,
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
    /// Transport failed for one exact state-segment request.
    StateSegmentRequestFailed {
        from: PeerId,
        segment_id: u16,
        expected_tip_height: u64,
        expected_tip_hash: [u8; 32],
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
    PeerConnected(PeerId),
    /// A peer disconnected.
    PeerDisconnected(PeerId),
    /// A peer-owned sync request failed while the connection may remain live.
    PeerRequestFailed(PeerId),
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
    ) -> anyhow::Result<(Self, tokio::task::JoinHandle<()>)> {
        // Load before spawning so an absent, corrupt, symlinked, or publicly
        // readable private identity fails node startup instead of silently
        // leaving RPC alive with a dead P2P task.
        let identity = crate::identity_store::load_or_create(&data_dir)?;
        let local_peer_id = identity.public().to_peer_id();
        tracing::info!(peer = %local_peer_id, "loaded persistent P2P identity");
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
    required_event_tx: mpsc::Sender<NetworkEvent>,
    chain: Arc<RwLock<MdbxChainContext>>,
    mempool: AsyncMempool,
    topics: NetworkTopics,
    data_dir: std::path::PathBuf,
    identity: libp2p::identity::Keypair,
) -> anyhow::Result<()> {
    use libp2p::{noise, tcp, yamux, SwarmBuilder};

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
    let mut mempool_sync_last_request: std::collections::HashMap<PeerId, Instant> =
        std::collections::HashMap::new();
    let mut mempool_sync_retries: std::collections::HashMap<PeerId, MempoolSyncRetry> =
        std::collections::HashMap::new();
    let mut snapshot_manifest_last_request: std::collections::HashMap<PeerId, Instant> =
        std::collections::HashMap::new();
    let mut snapshot_segment_rate: std::collections::HashMap<PeerId, (u32, Instant)> =
        std::collections::HashMap::new();
    let mut pending_retained_block_requests =
        BoundedPendingRequests::new(MAX_PENDING_RETAINED_BLOCK_REQUESTS);
    let mut pending_header_requests = BoundedPendingRequests::new(MAX_PENDING_HEADER_REQUESTS);
    let mut pending_state_segment_requests =
        BoundedPendingRequests::new(MAX_PENDING_STATE_SEGMENT_REQUESTS);
    let mut pending_history_step_requests =
        BoundedPendingRequests::new(MAX_PENDING_HISTORY_STEP_REQUESTS);
    let mut peer_diversity = PeerDiversity::default();

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
    let mut snapshot_export_leases: std::collections::HashMap<PeerId, SnapshotExportLease> =
        std::collections::HashMap::new();
    prune_snapshot_exports(&mut snapshot_exports, &snapshot_export_leases);
    let (snapshot_export_tx, mut snapshot_export_rx) =
        mpsc::channel::<(SnapshotExportKey, Result<SnapshotGeneration, String>)>(1);
    let mut snapshot_export_inflight: Option<SnapshotExportKey> = None;
    let mut snapshot_export_timer = tokio::time::interval(Duration::from_secs(30));
    snapshot_export_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

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
        while let Ok(cmd) = cmd_rx.try_recv() {
            handle_network_command(
                &mut swarm,
                cmd,
                &topics,
                &mut mempool_sync_last_request,
                &mut mempool_sync_retries,
                &required_event_tx,
                &mut pending_retained_block_requests,
                &mut pending_header_requests,
                &mut pending_state_segment_requests,
                &mut pending_history_step_requests,
                &mut automatic_peers,
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
                    &mut snapshot_export_leases,
                    &mut block_event_rate,
                    &mut tx_gossip_rate,
                    &mut mempool_sync_last_request,
                    &mut mempool_sync_retries,
                    &mut snapshot_manifest_last_request,
                    &mut snapshot_segment_rate,
                    &mut pending_retained_block_requests,
                    &mut pending_header_requests,
                    &mut pending_state_segment_requests,
                    &mut pending_history_step_requests,
                    &mut automatic_peers,
                    &mut peer_diversity,
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
                            prune_snapshot_export_leases(&mut snapshot_export_leases);
                            prune_snapshot_exports(&mut snapshot_exports, &snapshot_export_leases);
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
                                let previous = snapshot_exports
                                    .iter()
                                    .filter(|((height, _), _)| *height < key.0)
                                    .max_by_key(|((height, _), _)| *height)
                                    .map(|(_, generation)| generation.clone());
                                Some((key, ctx.store.clone(), previous))
                            }
                        })
                    };
                    if let Some((key, store, previous)) = candidate {
                        snapshot_export_inflight = Some(key);
                        let export_root = snapshot_export_root.clone();
                        let completion = snapshot_export_tx.clone();
                        tokio::task::spawn_blocking(move || {
                            let result = export_snapshot_generation(
                                &store,
                                &export_root,
                                key.0,
                                previous.as_deref(),
                            )
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
                        &mut mempool_sync_retries,
                        &required_event_tx,
                        &mut pending_retained_block_requests,
                        &mut pending_header_requests,
                        &mut pending_state_segment_requests,
                        &mut pending_history_step_requests,
                        &mut automatic_peers,
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
                        mempool_now >= retry.next_attempt && swarm.is_connected(peer)
                    })
                    .map(|(peer, retry)| (*peer, retry.failures))
                    .collect();
                mempool_sync_retries.retain(|peer, _| swarm.is_connected(peer));
                for (peer, failures) in retry_peers {
                    let _ = swarm
                        .behaviour_mut()
                        .mempool_sync
                        .send_request(&peer, crate::protocol::GetMempoolRequest);
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
                exports.insert(generation.key(), Arc::new(generation));
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

fn lease_snapshot_export(
    leases: &mut std::collections::HashMap<PeerId, SnapshotExportLease>,
    peer: PeerId,
    key: SnapshotExportKey,
) -> bool {
    prune_snapshot_export_leases(leases);
    let distinct_other_keys = leases
        .iter()
        .filter(|(leased_peer, _)| **leased_peer != peer)
        .map(|(_, lease)| lease.key)
        .collect::<std::collections::HashSet<_>>();
    if !distinct_other_keys.contains(&key) && distinct_other_keys.len() >= MAX_SNAPSHOT_EXPORTS {
        return false;
    }
    leases.insert(
        peer,
        SnapshotExportLease {
            key,
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

    // A replacement is connected before the old neighbour is released. This
    // keeps the maintained set at the target throughout seed→ordinary and
    // ordinary→seed transitions instead of creating a visible connectivity
    // dip every time the topology changes.
    // At the exact target, first establish an ordinary replacement below.
    // Closing a seed here would create a visible 12→11 connectivity dip.
    let release_seed = connected_bootstrap.len() > desired_bootstrap
        && automatic.outbound_peer_count() > AUTOMATIC_OUTBOUND_TARGET;
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
        let available = AUTOMATIC_OUTBOUND_TARGET
            .saturating_add(1)
            .saturating_sub(occupied)
            .min(pending_capacity)
            .min(MAX_PENDING_BOOTSTRAP_DIALS.saturating_sub(pending_bootstrap))
            .min(bootstrap_needed);
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
    if !bootstrap_complete || stable_non_bootstrap < BOOTSTRAP_RELEASE_NON_SEED_PEERS {
        return fanout;
    }
    fanout.saturating_sub(stable_non_bootstrap - BOOTSTRAP_RELEASE_NON_SEED_PEERS)
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
    required_event_tx: &mpsc::Sender<NetworkEvent>,
    pending_retained_block_requests: &mut BoundedPendingRequests<
        request_response::OutboundRequestId,
        PendingRetainedBlockRequest,
    >,
    pending_header_requests: &mut BoundedPendingRequests<
        request_response::OutboundRequestId,
        PendingHeaderRequest,
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
            tracing::debug!(address = %addr, "registered automatic bootstrap candidate");
            automatic_peers.register_bootstrap(addr);
        }
        NetworkCommand::BootstrapComplete => {
            automatic_peers.bootstrap_complete = true;
            tracing::debug!("initial synchronization complete — bootstrap peers are releasable");
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
                    },
                );
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
                },
            );
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
                let _ = required_event_tx
                    .send(NetworkEvent::StateSegmentRequestFailed {
                        from: peer,
                        segment_id,
                        expected_tip_height,
                        expected_tip_hash,
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
            token,
            peer,
            height,
            block_hash,
        } => {
            // The node owns one snapshot state machine. Both requests in one
            // exact-boundary hedge share a token; a newer logical token
            // supersedes every older transport.
            pending_history_step_requests.retain(|_, pending| pending.token == token);
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
                },
            );
            debug_assert!(inserted, "fresh HistoryStep request ID must be unique");
            tracing::debug!(token, peer = %peer, height, "requesting HistoryStep terminal for snapshot verification");
        }
        NetworkCommand::FetchHeaders {
            peer,
            start_height,
            count,
        } => {
            let count = count.min(512);
            // Node-side fetch state is per peer. Retire an older request from
            // the same peer before issuing its replacement so a delayed stream
            // cannot consume correlation capacity or reset a newer session.
            pending_header_requests.retain(|_, pending| pending.peer != peer);
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
                },
            );
            let inserted = pending_header_requests.try_insert(
                request_id,
                PendingHeaderRequest {
                    peer,
                    start_height,
                    count,
                },
            );
            debug_assert!(inserted, "fresh header request ID must be unique");
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
            mempool_sync_retries.remove(&peer);
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
    snapshot_export_leases: &mut std::collections::HashMap<PeerId, SnapshotExportLease>,
    block_event_rate: &mut std::collections::HashMap<PeerId, (u32, Instant)>,
    tx_gossip_rate: &mut std::collections::HashMap<PeerId, (u32, Instant)>,
    mempool_sync_last_request: &mut std::collections::HashMap<PeerId, Instant>,
    mempool_sync_retries: &mut std::collections::HashMap<PeerId, MempoolSyncRetry>,
    snapshot_manifest_last_request: &mut std::collections::HashMap<PeerId, Instant>,
    snapshot_segment_rate: &mut std::collections::HashMap<PeerId, (u32, Instant)>,
    pending_retained_block_requests: &mut BoundedPendingRequests<
        request_response::OutboundRequestId,
        PendingRetainedBlockRequest,
    >,
    pending_header_requests: &mut BoundedPendingRequests<
        request_response::OutboundRequestId,
        PendingHeaderRequest,
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
    successful_peer_cache: &mut crate::peer_store::SuccessfulPeerCache,
) {
    macro_rules! fail_retained_request {
        ($pending:expr) => {{
            let pending = $pending;
            let _ = required_event_tx
                .send(NetworkEvent::RecentBlockRequestFailed {
                    from: pending.peer,
                    height: pending.height,
                    payload_kind: pending.payload_kind,
                })
                .await;
        }};
    }
    macro_rules! fail_state_segment_request {
        ($pending:expr) => {{
            let pending = $pending;
            let _ = required_event_tx
                .send(NetworkEvent::StateSegmentRequestFailed {
                    from: pending.peer,
                    segment_id: pending.segment_id,
                    expected_tip_height: pending.expected_tip_height,
                    expected_tip_hash: pending.expected_tip_hash,
                })
                .await;
        }};
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
            connection_id,
            info,
            ..
        })) => {
            // A Noise/libp2p endpoint is not yet a usable ParanO(1)d peer.
            // Require the current network's exact header protocol before this
            // connection can satisfy bootstrap fanout or the ordinary peer
            // target. Old releases are intentionally not wire-compatible.
            let required_protocol = format!("{}/sync/headers/2", topics.protocol_id);
            if !info
                .protocols
                .iter()
                .any(|protocol| protocol.as_ref() == required_protocol)
            {
                let _ = swarm.close_connection(connection_id);
                swarm.behaviour_mut().kad.remove_peer(&peer_id);
                tracing::debug!(
                    peer = %peer_id,
                    required_protocol,
                    "closing endpoint without the current ParanO(1)d sync protocol"
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
            if automatic_peers.is_outbound(peer_id) {
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
            if pending.peer != peer {
                let _ = required_event_tx
                    .send(NetworkEvent::HeadersRequestFailed {
                        from: pending.peer,
                        start_height: pending.start_height,
                        count: pending.count,
                    })
                    .await;
                return;
            }
            let decoded = match decode_linked_header_batch(response.headers) {
                Ok(decoded) => decoded,
                Err(error) => {
                    tracing::warn!(from = %peer, error, "invalid header batch response — dropped");
                    let _ = required_event_tx
                        .send(NetworkEvent::HeadersRequestFailed {
                            from: pending.peer,
                            start_height: pending.start_height,
                            count: pending.count,
                        })
                        .await;
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

        SwarmEvent::Behaviour(NodeBehaviourEvent::ChainSync(
            request_response::Event::OutboundFailure {
                peer,
                request_id,
                error,
            },
        )) => {
            let Some(pending) = pending_header_requests.remove(&request_id) else {
                tracing::debug!(
                    peer = %peer,
                    request_id = %request_id,
                    "ignoring stale header request failure"
                );
                return;
            };
            tracing::debug!(
                peer = %peer,
                request_id = %request_id,
                err = %error,
                "header request transport failed"
            );
            let _ = required_event_tx
                .send(NetworkEvent::HeadersRequestFailed {
                    from: pending.peer,
                    start_height: pending.start_height,
                    count: pending.count,
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
                peer: _,
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
                let _preparation_permit = preparation_permit;
                let Ok(Some(outbound_memory_permit)) = budget.acquire(response_reservation).await
                else {
                    return;
                };
                let loaded = tokio::task::spawn_blocking(move || {
                    match payload_kind {
                        RecentBlockPayloadKind::Complete => {
                            if let Some(generation) = leased_bridge {
                                return generation
                                    .read_bridge_block(height)
                                    .ok()
                                    .map(RecentBlockPayload::Complete);
                            }
                            let ctx = chain.blocking_read();
                            match ctx.store.get_recent_accepted_block_bundle_bounded(height) {
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
                                    let Ok(bundle) =
                                        generation.read_bridge_block(current_height)
                                    else {
                                        return None;
                                    };
                                    let (block_bytes, terminal_bytes) = bundle.into_parts();
                                    drop(terminal_bytes);
                                    bodies.push(block_bytes);
                                }
                                return Some(RecentBlockPayload::BlockBodies(bodies));
                            }
                            let ctx = chain.blocking_read();
                            let mut bodies = Vec::with_capacity(count as usize);
                            for current_height in height..=end_height {
                                match ctx.store.get_recent_block(current_height) {
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
            let leased_generation = snapshot_export_leases.get_mut(&peer).and_then(|lease| {
                let generation = snapshot_exports.get(&lease.key)?;
                let manifest = generation.manifest();
                let exact_boundary = manifest.target_height == request_height
                    && manifest.target_hash == request_hash;
                let exact_bridge = manifest
                    .bridge_block(request_height)
                    .is_some_and(|descriptor| descriptor.block_hash == request_hash);
                if !exact_boundary && !exact_bridge {
                    return None;
                }
                lease.last_activity = Instant::now();
                Some(generation.clone())
            });
            tokio::spawn(async move {
                let _preparation_permit = preparation_permit;
                let Ok(Some(outbound_memory_permit)) = budget
                    .acquire(MAX_OUTBOUND_HISTORY_STEP_RESPONSE_BYTES)
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
            prune_snapshot_export_leases(snapshot_export_leases);
            prune_snapshot_exports(snapshot_exports, snapshot_export_leases);
            let response = 'ready_manifest: {
                let ctx = chain.read().await;
                let Some(generation) =
                    select_snapshot_export(&ctx, snapshot_exports, request.requester_height)
                else {
                    break 'ready_manifest GetStateManifestResponse::default();
                };
                let key = generation.key();
                if !lease_snapshot_export(snapshot_export_leases, peer, key) {
                    tracing::debug!(
                        peer = %peer,
                        snapshot_height = key.0,
                        "snapshot generation lease capacity is full"
                    );
                    break 'ready_manifest GetStateManifestResponse::default();
                }
                let manifest = generation.manifest();

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
                let segment_lengths = manifest
                    .segments
                    .iter()
                    .map(|descriptor| descriptor.encoded_len)
                    .collect();
                tracing::info!(
                    requester_height = request.requester_height,
                    snapshot_height = manifest.target_height,
                    bridge_tip = manifest.bridge_tip_height,
                    live_tip = ctx.tip_height(),
                    segments = manifest.segments.len(),
                    "serving immutable snapshot manifest and bridge"
                );
                GetStateManifestResponse {
                    tip_height: manifest.target_height,
                    tip_hash: key.1,
                    cumulative_chainwork: manifest.cumulative_chainwork,
                    log_slots: manifest.log_slots,
                    active_slot_count: manifest.active_slot_count,
                    alloc_counter: manifest.alloc_counter,
                    eff_log: manifest.effective_log_segment_size,
                    bridge_tip_height: manifest.bridge_tip_height,
                    bridge_tip_hash: manifest.bridge_tip_hash,
                    bridge_cumulative_chainwork: manifest.bridge_cumulative_chainwork,
                    segment_ids,
                    segment_roots,
                    segment_lengths,
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
                    return;
                }
                if response.segment_ids.len() != response.segment_roots.len()
                    || response.segment_ids.len() != response.segment_lengths.len()
                {
                    tracing::warn!(from = %peer, "manifest: descriptor vector length mismatch, dropping");
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
                let Some(maximum_segment_bytes) =
                    max_encoded_segment_len_for_eff_log(response.eff_log)
                else {
                    tracing::warn!(from = %peer, eff_log = response.eff_log, "manifest: invalid effective segment log, dropping");
                    return;
                };
                if maximum_segment_bytes > MAX_SEGMENT_BYTES {
                    tracing::warn!(
                        from = %peer,
                        eff_log = response.eff_log,
                        maximum_segment_bytes,
                        max_segment = MAX_SEGMENT_BYTES,
                        "manifest: segment encoding exceeds per-segment cap, dropping"
                    );
                    return;
                }
                let mut declared_live_count = 0u64;
                for &encoded_len in &response.segment_lengths {
                    let Some(live_count) =
                        encoded_segment_live_count_from_len(response.eff_log, encoded_len as usize)
                    else {
                        tracing::warn!(from = %peer, encoded_len, "manifest: non-canonical sparse segment length, dropping");
                        return;
                    };
                    if live_count == 0 {
                        tracing::warn!(from = %peer, "manifest: empty segment descriptor, dropping");
                        return;
                    }
                    let Some(next) = declared_live_count.checked_add(u64::from(live_count)) else {
                        tracing::warn!(from = %peer, "manifest: live-entry count overflow, dropping");
                        return;
                    };
                    declared_live_count = next;
                }
                if declared_live_count != response.active_slot_count {
                    tracing::warn!(from = %peer, declared_live_count, active_slot_count = response.active_slot_count, "manifest: sparse lengths disagree with active count, dropping");
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
            prune_snapshot_export_leases(snapshot_export_leases);
            prune_snapshot_exports(snapshot_exports, snapshot_export_leases);
            let key = (request.expected_tip_height, request.expected_tip_hash);
            let lease_matches = snapshot_export_leases.get_mut(&peer).is_some_and(|lease| {
                if lease.key == key {
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
            let Ok(permit) = segment_encode_semaphore.clone().try_acquire_owned() else {
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
            num_established,
            ..
        } => {
            if let Err(reason) = peer_diversity.try_admit(
                connection_id,
                peer_id,
                endpoint.get_remote_address(),
                endpoint.is_dialer(),
            ) {
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
            automatic_peers.note_connection_established(
                connection_id,
                peer_id,
                endpoint.is_dialer(),
            );
            // Only emit PeerConnected on the FIRST connection to a peer.
            // Multiple connections to the same peer are common (simultaneous dials,
            // mDNS re-discovery, relay + direct). Emitting for each one causes
            if num_established.get() == 1 {
                let _ = required_event_tx
                    .send(NetworkEvent::PeerConnected(peer_id))
                    .await;
                tracing::debug!(peer = %peer_id, "peer connected");
            }
        }
        SwarmEvent::ConnectionClosed {
            peer_id,
            connection_id,
            num_established,
            cause,
            ..
        } => {
            if !peer_diversity.remove(connection_id) {
                tracing::debug!(
                    peer = %peer_id,
                    "diversity-rejected connection closed"
                );
                return;
            }
            automatic_peers.note_connection_closed(connection_id);
            // Only emit PeerDisconnected when the LAST connection to a peer closes.
            if num_established == 0 {
                // Deliver exact request failures before the generic
                // disconnect event. This deterministic ordering lets the node
                // retain or fail over its disk staging without racing the
                // broader peer cleanup path.
                let failed_blocks =
                    pending_retained_block_requests.take_where(|pending| pending.peer == peer_id);
                for pending in failed_blocks {
                    fail_retained_request!(pending);
                }
                let failed_headers =
                    pending_header_requests.take_where(|pending| pending.peer == peer_id);
                for pending in failed_headers {
                    let _ = required_event_tx
                        .send(NetworkEvent::HeadersRequestFailed {
                            from: pending.peer,
                            start_height: pending.start_height,
                            count: pending.count,
                        })
                        .await;
                }
                let failed_segments =
                    pending_state_segment_requests.take_where(|pending| pending.peer == peer_id);
                for pending in failed_segments {
                    fail_state_segment_request!(pending);
                }
                let failed_terminals =
                    pending_history_step_requests.take_where(|pending| pending.peer == peer_id);
                for pending in failed_terminals {
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
                let _ = required_event_tx
                    .send(NetworkEvent::PeerDisconnected(peer_id))
                    .await;
                tracing::debug!(peer = %peer_id, cause = ?cause, "peer disconnected");
                block_event_rate.remove(&peer_id);
                tx_gossip_rate.remove(&peer_id);
                mempool_sync_last_request.remove(&peer_id);
                mempool_sync_retries.remove(&peer_id);
                snapshot_manifest_last_request.remove(&peer_id);
                snapshot_segment_rate.remove(&peer_id);
                snapshot_export_leases.remove(&peer_id);
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
            request_response::Event::OutboundFailure { peer, error, .. },
        )) => {
            tracing::debug!(peer = %peer, err = %error, "manifest sync request failed");
            let _ = gossip_event_tx.send(NetworkEvent::PeerRequestFailed(peer));
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
    fn snapshot_bridge_keeps_half_window_for_the_live_tail() {
        let allowance = SNAPSHOT_BRIDGE_MAX_LIVE_GAP;
        assert!(snapshot_bridge_has_live_headroom(100, 100));
        assert!(snapshot_bridge_has_live_headroom(100, 100 - allowance));
        assert!(!snapshot_bridge_has_live_headroom(100, 100 - allowance - 1));
        assert!(!snapshot_bridge_has_live_headroom(100, 101));
    }

    #[test]
    fn snapshot_generation_leases_bound_distinct_pinned_generations() {
        let first = PeerId::random();
        let second = PeerId::random();
        let third = PeerId::random();
        let key_a = (100, [1; 32]);
        let key_b = (101, [2; 32]);
        let key_c = (102, [3; 32]);
        let mut leases = std::collections::HashMap::new();

        assert!(lease_snapshot_export(&mut leases, first, key_a));
        assert!(lease_snapshot_export(&mut leases, second, key_b));
        assert!(lease_snapshot_export(&mut leases, third, key_a));
        assert!(!lease_snapshot_export(&mut leases, third, key_c));

        leases.get_mut(&first).unwrap().last_activity =
            Instant::now() - SNAPSHOT_EXPORT_LEASE_TTL - Duration::from_secs(1);
        prune_snapshot_export_leases(&mut leases);
        assert!(!leases.contains_key(&first));
        assert!(lease_snapshot_export(&mut leases, third, key_c));
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
    fn bootstrap_release_is_gradual_and_tiny_network_keeps_every_seed() {
        for (ordinary, expected_seeds) in [(0, 3), (8, 3), (9, 2), (10, 1), (11, 0), (12, 0)] {
            assert_eq!(
                desired_bootstrap_connections(true, ordinary, 6),
                expected_seeds,
                "ordinary={ordinary}"
            );
        }
        assert_eq!(desired_bootstrap_connections(false, 12, 3), 3);
        assert_eq!(desired_bootstrap_connections(true, 0, 3), 3);
        assert_eq!(desired_bootstrap_connections(true, 0, 2), 2);
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
            }
        ));
        assert!(!registry.try_insert(
            12,
            PendingRetainedBlockRequest {
                peer,
                height: 79,
                count: 1,
                payload_kind: RecentBlockPayloadKind::Complete,
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
                payload_kind: RecentBlockPayloadKind::Complete,
            })
            .unwrap();
        }
        assert!(matches!(
            tx.try_send(NetworkEvent::RecentBlockUnavailable {
                from: peer,
                height: u64::MAX,
                payload_kind: RecentBlockPayloadKind::Complete,
            }),
            Err(mpsc::error::TrySendError::Full(_))
        ));

        assert!(rx.recv().await.is_some());
        tx.try_send(NetworkEvent::RecentBlockUnavailable {
            from: peer,
            height: u64::MAX,
            payload_kind: RecentBlockPayloadKind::Complete,
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
