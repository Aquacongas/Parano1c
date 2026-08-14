// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! # parano1d — ParanO(1)d Full Node Binary
//!
//! Startup sequence:
//! 1. Load config + init tracing
//! 2. Open MDBX (open_or_create — genesis if first run)
//! 3. Start mempool (ChainView snapshot from MDBX)
//! 4. Start P2P network (gossipsub + req-resp)
//! 5. Dial seed peers
//! 6. Start RPC server (JSON-RPC on configured address)
//! 7. Start miner (if --mine or config.mining.enabled)
//! 8. Shutdown on Ctrl-C

#![allow(clippy::items_after_test_module)]

// ---------------------------------------------------------------------------
// Global allocator: jemalloc
//
// glibc malloc retains freed pages from large proof-generation allocations (FRI/NTT Vecs,
// often 10-100 MB each) indefinitely, causing 3-4 GB RSS fragmentation on
// a full node even with only a few hundred active UTXOs.
//
// jemalloc with background_threads enabled returns dirty pages to the OS
// within dirty_decay_ms (default 10 000 ms) via a background reclaim thread.
// This keeps the node's RSS proportional to actual working set size.
// ---------------------------------------------------------------------------
#[cfg(unix)]
#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::{
    fs::OpenOptions,
    io::{Read, Write},
};

use anyhow::Context;
use clap::Parser;
use tokio::sync::RwLock;
use tracing_subscriber::EnvFilter;

use noid_chain::consensus::wire_limits::{
    MAX_ORPHAN_POOL, MAX_ORPHAN_POOL_BYTES, MAX_SEGMENT_BYTES, MAX_SNAPSHOT_MANIFEST_SEGMENTS,
    MAX_TX_INTENT_BYTES_GLOBAL,
};
use noid_chain::consensus::NetworkConfig;
use noid_chain::storage::snapshot_staging::{
    AuthenticatedSnapshotMetadata, FinalizedSnapshotStaging, SnapshotStagingSession,
};
use noid_chain::storage::{
    encoded_segment_live_count_from_len, max_encoded_segment_len_for_eff_log, MdbxChainContext,
    MdbxStore, SnapshotSegmentDescriptor,
};
use noid_mempool::{AsyncMempool, ChainView, MempoolConfig};
use noid_miner::{BlockMiner, MinerConfig};
use noid_node::snapshot_header_staging::{
    validate_bounded_header_extension, CanonicalHeaderBoundary, SnapshotHeaderBoundary,
    SnapshotHeaderStaging, SnapshotHeaderStagingError, ValidatedSnapshotHeaderStaging,
    MAX_STAGED_HEADER_BATCH,
};
use noid_node::snapshot_tail_staging::{
    FinalizedSnapshotTail, SnapshotTailFinalizeError, SnapshotTailStaging,
};
use noid_p2p::{NetworkEvent, P2PNetwork};
use noid_rpc::{start_rpc_server, ExternalMiningAttemptInvalidator, WalletOperationGate};

struct AcceptedBlockCandidate {
    block: noid_chain::block::Block,
    bundle: noid_chain::AcceptedBlockBundle,
}

impl AcceptedBlockCandidate {
    fn from_bundle(bundle: noid_chain::AcceptedBlockBundle) -> Self {
        let block = noid_chain::block::Block::from_bytes(bundle.block_bytes())
            .expect("AcceptedBlockBundle contains a canonical Block");
        Self { block, bundle }
    }

    fn retained_bytes(&self) -> usize {
        noid_chain::ACCEPTED_BLOCK_BUNDLE_HEADER_BYTES
            .saturating_add(self.bundle.block_bytes().len())
            .saturating_add(self.bundle.history_step_terminal_bytes().len())
    }
}

struct AppliedP2pBlock {
    block_hash: [u8; 32],
    height: u64,
    confirmed_tx_hashes: Vec<noid_poseidon2b::primitives::TxBodyHash>,
    view: ChainView,
}

struct AppliedCompactSuffix {
    height: u64,
    block_hash: [u8; 32],
    confirmed_tx_hashes: Vec<noid_poseidon2b::primitives::TxBodyHash>,
    view: ChainView,
    applied_blocks: u64,
    payload_bytes: u64,
    apply_elapsed: std::time::Duration,
    trailing_error: Option<String>,
}

#[derive(Debug)]
enum CompactSuffixApplyError {
    Terminal(String),
    Other(String),
}

impl From<String> for CompactSuffixApplyError {
    fn from(error: String) -> Self {
        Self::Other(error)
    }
}

impl std::fmt::Display for CompactSuffixApplyError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Terminal(error) | Self::Other(error) => formatter.write_str(error),
        }
    }
}

fn compact_apply_signals(
    applied_blocks: u64,
    applied_height: u64,
    target_height: u64,
    has_trailing_error: bool,
) -> (bool, bool) {
    let advanced = applied_blocks != 0;
    let complete = !has_trailing_error && applied_height == target_height;
    (advanced, complete)
}

fn snapshot_bridge_requires_tail(boundary_height: u64, bridge_tip_height: u64) -> Option<bool> {
    (bridge_tip_height >= boundary_height).then_some(bridge_tip_height > boundary_height)
}

struct AppliedReorg {
    result: noid_chain::consensus::ReorgResult,
    confirmed_tx_hashes: Vec<noid_poseidon2b::primitives::TxBodyHash>,
    view: ChainView,
}

struct OrphanBlock {
    header: noid_chain::BlockHeader,
    bundle: noid_chain::AcceptedBlockBundle,
    received_at: Instant,
}

/// One bounded shallow-fork download selected from an authenticated peer's
/// linked header response.
///
/// Accepted bundles are deliberately pulled one at a time.  A block bundle
/// can consume the complete process-wide inbound byte budget; opening one
/// request per finality height both violates the block-sync stream limit and
/// lets a many-miner race amplify memory pressure.  The complete replacement
/// is applied atomically only after every expected bundle has arrived.
struct PendingShallowFork {
    peer: libp2p::PeerId,
    ancestor_height: u64,
    ancestor_hash: [u8; 32],
    expected_headers: Vec<noid_chain::BlockHeader>,
    candidates: Vec<AcceptedBlockCandidate>,
    retained_bytes: usize,
    advertised_work: [u8; 32],
    /// Peers that failed to serve the current exact replacement bundle.
    /// The set is cleared after every correlated bundle makes progress, so a
    /// healthy peer remains eligible for the next height while one bad or
    /// stale peer cannot restart the same fixed download indefinitely.
    attempted_bundle_peers: std::collections::HashSet<libp2p::PeerId>,
    /// Deadline is measured from exact correlated progress, not from the
    /// beginning of the whole sequential transfer. A maximum-depth recovery
    /// can legitimately take longer than one request timeout on a slow link.
    last_progress_at: Instant,
}

/// Canonical common ancestor from which a verified fork-choice-winning snapshot may
/// replace only the local, non-final suffix.  This is armed only after native
/// header validation and ordinary fork-choice comparison have already selected
/// a better branch; the atomic installer independently rechecks work and
/// finality before replacing anything.
#[derive(Clone, Copy)]
struct SnapshotRebaseHint {
    ancestor_height: u64,
    ancestor_hash: [u8; 32],
    competing_tip_height: u64,
    competing_tip_hash: [u8; 32],
    armed_at: Instant,
}

impl PendingShallowFork {
    fn expected_header(&self) -> Option<&noid_chain::BlockHeader> {
        self.expected_headers.get(self.candidates.len())
    }

    fn tip_height(&self) -> u64 {
        self.expected_headers
            .last()
            .expect("a shallow-fork session is never empty")
            .height
    }

    fn tip_hash(&self) -> [u8; 32] {
        noid_chain::consensus::pow::block_id(
            self.expected_headers
                .last()
                .expect("a shallow-fork session is never empty"),
        )
    }
}

impl OrphanBlock {
    fn from_candidate(candidate: AcceptedBlockCandidate) -> Self {
        Self {
            header: candidate.block.header,
            bundle: candidate.bundle,
            received_at: Instant::now(),
        }
    }

    fn into_candidate(self) -> AcceptedBlockCandidate {
        AcceptedBlockCandidate::from_bundle(self.bundle)
    }

    fn retained_bytes(&self) -> usize {
        noid_chain::ACCEPTED_BLOCK_BUNDLE_HEADER_BYTES
            .saturating_add(self.bundle.block_bytes().len())
            .saturating_add(self.bundle.history_step_terminal_bytes().len())
    }
}

fn gap_requires_snapshot_sync(local_height: u64, peer_height: u64) -> bool {
    peer_height
        > local_height.saturating_add(noid_chain::consensus::params::RECENT_BLOCK_RETENTION_DEPTH)
}

fn retained_suffix_has_more(local_height: u64, announced_height: u64) -> bool {
    local_height < announced_height
}

fn compact_suffix_eligible(local_height: u64, ancestor_height: u64, peer_height: u64) -> bool {
    if ancestor_height != local_height || peer_height <= local_height {
        return false;
    }
    let gap = peer_height - local_height;
    (2..=noid_chain::consensus::params::RECENT_BLOCK_RETENTION_DEPTH).contains(&gap)
}

fn next_block_has_competing_parent(
    local_height: u64,
    local_tip_hash: [u8; 32],
    header: &noid_chain::BlockHeader,
) -> bool {
    header.height == local_height.saturating_add(1) && header.prev_block_hash != local_tip_hash
}

fn unavailable_block_requires_snapshot(
    local_height: u64,
    requested_height: u64,
    announced_height: u64,
) -> bool {
    requested_height == local_height.saturating_add(1)
        && retained_suffix_has_more(local_height, announced_height)
}

fn snapshot_parent_mismatch_is_at_base(
    staged_len: u64,
    base_height: u64,
    start_height: u64,
    error: &SnapshotHeaderStagingError,
) -> bool {
    staged_len == 0
        && start_height == base_height.saturating_add(1)
        && matches!(
            error,
            SnapshotHeaderStagingError::ParentMismatch { height }
                if *height == start_height
        )
}

fn finalized_header_search_floor(local_height: u64) -> u64 {
    local_height.saturating_sub(noid_chain::consensus::params::CONSENSUS_FINALITY_DEPTH)
}

fn header_batch_exhausts_nonfinal_window(local_height: u64, oldest_height: u64) -> bool {
    oldest_height <= finalized_header_search_floor(local_height)
}

fn competing_suffix_wins(
    competing_work: &[u8; 32],
    competing_tip_hash: &[u8; 32],
    local_work: &[u8; 32],
    local_tip_hash: &[u8; 32],
) -> bool {
    matches!(
        noid_chain::choose_chain_by_work(
            competing_work,
            competing_tip_hash,
            local_work,
            local_tip_hash,
        ),
        noid_chain::consensus::fork_choice::ChainChoice::A
    )
}

fn competing_suffix_tip(competing: &[noid_chain::BlockHeader]) -> Option<(u64, [u8; 32])> {
    competing
        .last()
        .map(|header| (header.height, noid_chain::consensus::pow::block_id(header)))
}

fn nonfinal_header_discovery_range(local_height: u64) -> Option<(u64, u16)> {
    if local_height == 0 {
        return None;
    }
    let start_height = finalized_header_search_floor(local_height);
    let count = local_height.saturating_sub(start_height).saturating_add(1);
    Some((
        start_height,
        u16::try_from(count).expect("finality-bounded header discovery count fits u16"),
    ))
}

fn authenticated_height_after_reorg(
    previous_highest: u64,
    old_tip_height: u64,
    new_tip_height: u64,
) -> u64 {
    if new_tip_height <= old_tip_height {
        // A height-only routing hint from the losing branch must not prevent
        // exact confirmation of the newly selected fork-choice winner.
        new_tip_height
    } else {
        previous_highest.max(new_tip_height)
    }
}

fn mark_initial_sync_ready(sender: &tokio::sync::watch::Sender<bool>) {
    let already_ready = *sender.borrow();
    if !already_ready {
        sender.send_replace(true);
    }
}

fn initial_sync_may_skip_peer_confirmation(isolated_genesis: bool) -> bool {
    isolated_genesis
}

const MINING_PEER_QUORUM: usize = 2;
const CONNECTED_TIP_PROBE_HEADERS: u16 =
    noid_chain::consensus::params::RECENT_BLOCK_RETENTION_DEPTH as u16 + 2;
/// Keep one low-rate authenticated tip lane alive after mining readiness.
/// Gossip is intentionally only a latency hint; a dropped announcement must
/// never leave a healthy connected node permanently parked on an old tip.
const STEADY_TIP_PROBE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(10);
/// At most two exact-tip quorum lanes are opened per interval. Failed or
/// non-confirming identities rotate least-recently-first.
const MINING_QUORUM_PROBE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(3);
/// A peer's tip confirmation is an expiring authorization, not a permanent
/// property of the connection.  If authenticated tip traffic stops, mining
/// must stop before the node can keep extending a stale parent indefinitely.
const MINING_PEER_CONFIRMATION_TTL: std::time::Duration = std::time::Duration::from_secs(45);
/// Abort a sequential shallow-fork download only when the exact correlated
/// bundle stream stops making progress. A healthy maximum-depth replacement
/// is deliberately allowed to span more than one per-request timeout.
const SHALLOW_FORK_NO_PROGRESS_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(45);

fn shallow_fork_progress_deadline_due(last_progress_at: Instant, now: Instant) -> bool {
    now.saturating_duration_since(last_progress_at) >= SHALLOW_FORK_NO_PROGRESS_TIMEOUT
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct MiningTipConfirmation {
    height: u64,
    hash: [u8; 32],
    confirmed_at: Instant,
}

struct MiningPeerQuorum {
    isolated: bool,
    connected: std::collections::HashSet<libp2p::PeerId>,
    canonical_tip: Option<(u64, [u8; 32])>,
    confirmed: std::collections::HashMap<libp2p::PeerId, MiningTipConfirmation>,
    /// Last exact-tip probe issued to each connected identity. Unconfirmed
    /// peers are selected least-recently-first, so two stalled connections
    /// cannot monopolize both bounded quorum lanes forever.
    probe_attempts: std::collections::HashMap<libp2p::PeerId, Instant>,
    ready: tokio::sync::watch::Sender<bool>,
    count: tokio::sync::watch::Sender<usize>,
}

impl MiningPeerQuorum {
    fn new(
        isolated: bool,
        ready: tokio::sync::watch::Sender<bool>,
        count: tokio::sync::watch::Sender<usize>,
    ) -> Self {
        let quorum = Self {
            isolated,
            connected: std::collections::HashSet::new(),
            canonical_tip: None,
            confirmed: std::collections::HashMap::new(),
            probe_attempts: std::collections::HashMap::new(),
            ready,
            count,
        };
        quorum.publish();
        quorum
    }

    fn connect(&mut self, peer: libp2p::PeerId) {
        self.connected.insert(peer);
    }

    fn set_canonical_tip(&mut self, height: u64, hash: [u8; 32]) {
        let tip = (height, hash);
        if self.canonical_tip == Some(tip) {
            return;
        }
        self.canonical_tip = Some(tip);
        let before = self.confirmed.len();
        self.confirmed
            .retain(|_, confirmation| (confirmation.height, confirmation.hash) == tip);
        if self.confirmed.len() != before {
            self.publish();
        }
    }

    fn confirm_tip(&mut self, peer: libp2p::PeerId, height: u64, hash: [u8; 32]) {
        self.confirm_tip_at(peer, height, hash, Instant::now());
    }

    fn confirm_tip_at(
        &mut self,
        peer: libp2p::PeerId,
        height: u64,
        hash: [u8; 32],
        confirmed_at: Instant,
    ) {
        // Connectivity is owned exclusively by PeerConnected/Disconnected.
        // A delayed verification result from a closed sync peer must never
        // resurrect that identity. Likewise, an exact response for an old tip
        // must never authorize mining after the canonical tip has changed.
        if self.connected.contains(&peer) && self.canonical_tip == Some((height, hash)) {
            let newly_confirmed = self
                .confirmed
                .insert(
                    peer,
                    MiningTipConfirmation {
                        height,
                        hash,
                        confirmed_at,
                    },
                )
                .is_none();
            if newly_confirmed {
                self.publish();
            }
        }
    }

    fn expire_stale(&mut self, now: Instant) {
        let before = self.confirmed.len();
        let connected = &self.connected;
        let canonical_tip = self.canonical_tip;
        self.confirmed.retain(|peer, confirmation| {
            connected.contains(peer)
                && canonical_tip == Some((confirmation.height, confirmation.hash))
                && now.duration_since(confirmation.confirmed_at) < MINING_PEER_CONFIRMATION_TTL
        });
        if self.confirmed.len() != before {
            self.publish();
        }
    }

    fn disconnect(&mut self, peer: libp2p::PeerId) {
        self.connected.remove(&peer);
        self.probe_attempts.remove(&peer);
        if self.confirmed.remove(&peer).is_some() {
            self.publish();
        }
    }

    fn invalidate_all(&mut self) {
        if !self.confirmed.is_empty() {
            self.confirmed.clear();
            self.publish();
        }
    }

    fn waiting_for_quorum(&self) -> bool {
        !self.isolated && self.confirmed.len() < MINING_PEER_QUORUM
    }

    fn probe_candidates(&self, limit: usize) -> Vec<libp2p::PeerId> {
        let mut confirmed = self
            .confirmed
            .iter()
            .filter(|(peer, _)| self.connected.contains(peer))
            .map(|(peer, confirmation)| (*peer, confirmation.confirmed_at))
            .collect::<Vec<_>>();
        confirmed.sort_by(|(left_peer, left_at), (right_peer, right_at)| {
            left_at
                .cmp(right_at)
                .then_with(|| left_peer.to_bytes().cmp(&right_peer.to_bytes()))
        });
        let mut unconfirmed = self
            .connected
            .iter()
            .filter(|peer| !self.confirmed.contains_key(peer))
            .map(|peer| (*peer, self.probe_attempts.get(peer).copied()))
            .collect::<Vec<_>>();
        unconfirmed.sort_by(|(left_peer, left_at), (right_peer, right_at)| {
            left_at
                .cmp(right_at)
                .then_with(|| left_peer.to_bytes().cmp(&right_peer.to_bytes()))
        });
        unconfirmed
            .into_iter()
            .map(|(peer, _)| peer)
            .chain(confirmed.into_iter().map(|(peer, _)| peer))
            .take(limit)
            .collect()
    }

    fn mark_probe_sent(&mut self, peer: libp2p::PeerId, now: Instant) {
        if self.connected.contains(&peer) {
            self.probe_attempts.insert(peer, now);
        }
    }

    fn publish(&self) {
        let count = self.confirmed.len();
        if *self.count.borrow() != count {
            self.count.send_replace(count);
        }
        let ready = self.isolated || count >= MINING_PEER_QUORUM;
        if *self.ready.borrow() != ready {
            self.ready.send_replace(ready);
            tracing::info!(
                confirmed_peers = count,
                required_peers = MINING_PEER_QUORUM,
                isolated = self.isolated,
                ready,
                "mining network gate changed"
            );
        }
    }
}

/// A state-manifest round with no usable candidate is re-requested after this
/// deadline. A dropped stream must not wedge sync: with few peers there may
/// never be another PeerConnected event to retrigger the probe. This fallback
/// runs only after the request-response layer's 30-second deadline and the
/// P2P event loop's complete-local 35-second deadline. The extra margin lets
/// that layer flush a request which never opened a substream before the node
/// starts another manifest generation.
const STATE_MANIFEST_RESPONSE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(38);
/// A fresh node must not finalize the first valid snapshot merely because its
/// response won a network race. During this short window it keeps only the
/// strongest advertised candidate by cumulative work. The selected candidate
/// is still fully revalidated from canonical headers before any State is
/// installed, so manifest work remains an untrusted scheduling hint.
const STATE_MANIFEST_CANDIDATE_SETTLE: std::time::Duration = std::time::Duration::from_secs(5);
/// A terminal normally arrives in about two seconds on the live seed network.
/// libp2p starts its transport timeout only after an outbound substream opens,
/// so a request queued behind stream capacity otherwise has no node-visible
/// deadline. Hedge the same exact terminal to one advertised alternate before
/// that internal queue can stall cold sync.
const HISTORY_STEP_TERMINAL_HEDGE_AFTER: std::time::Duration = std::time::Duration::from_secs(3);
/// Bound the whole logical race, including time before libp2p opens either
/// outbound substream. This is deliberately longer than the transport's
/// 60-second request timeout, plus the hedge offset and timer sweep, so both
/// honest candidates keep their complete transport budget.
const HISTORY_STEP_TERMINAL_HARD_DEADLINE: std::time::Duration = std::time::Duration::from_secs(70);
const MINER_SHUTDOWN_GRACE: std::time::Duration = std::time::Duration::from_secs(30);

fn manifest_round_retry_due(started_at: Option<Instant>, now: Instant) -> bool {
    started_at.is_some_and(|started| now.duration_since(started) >= STATE_MANIFEST_RESPONSE_TIMEOUT)
}

fn manifest_candidate_selection_due(started_at: Option<Instant>, now: Instant) -> bool {
    started_at.is_some_and(|started| now.duration_since(started) >= STATE_MANIFEST_CANDIDATE_SETTLE)
}

fn state_manifest_candidate_is_preferred(
    candidate: &noid_p2p::protocol::GetStateManifestResponse,
    current: &noid_p2p::protocol::GetStateManifestResponse,
) -> bool {
    matches!(
        noid_chain::consensus::fork_choice::choose_chain_by_work(
            &candidate.bridge_cumulative_chainwork,
            &candidate.bridge_tip_hash,
            &current.bridge_cumulative_chainwork,
            &current.bridge_tip_hash,
        ),
        noid_chain::consensus::fork_choice::ChainChoice::A
    )
}

fn steady_tip_probe_due(
    last_probe: Instant,
    now: Instant,
    waiting_for_quorum: bool,
    canonical_sync_idle: bool,
) -> bool {
    !waiting_for_quorum
        && canonical_sync_idle
        && now.duration_since(last_probe) >= STEADY_TIP_PROBE_INTERVAL
}

fn mining_quorum_probe_due(
    last_probe: Instant,
    now: Instant,
    waiting_for_quorum: bool,
    canonical_sync_idle: bool,
) -> bool {
    waiting_for_quorum
        && canonical_sync_idle
        && now.duration_since(last_probe) >= MINING_QUORUM_PROBE_INTERVAL
}

fn manifest_round_gap_is_resolved(local_height: u64, highest_announced: u64) -> bool {
    local_height >= highest_announced
}

fn terminal_transport_can_retry_same_peer(kind: noid_p2p::RequestFailureKind) -> bool {
    matches!(
        kind,
        noid_p2p::RequestFailureKind::Timeout | noid_p2p::RequestFailureKind::Io
    )
}

fn rotating_manifest_peers(
    peers: &std::collections::HashSet<libp2p::PeerId>,
    excluded_peers: &std::collections::HashSet<libp2p::PeerId>,
    failed_peer: Option<libp2p::PeerId>,
    allow_failed_peer: bool,
    cursor: &mut usize,
    limit: usize,
) -> Vec<libp2p::PeerId> {
    let mut candidates = peers
        .iter()
        .copied()
        .filter(|peer| Some(*peer) != failed_peer)
        .filter(|peer| !excluded_peers.contains(peer))
        .collect::<Vec<_>>();
    candidates.sort_unstable_by_key(|peer| peer.to_bytes());
    if candidates.is_empty() {
        return failed_peer
            .filter(|peer| {
                allow_failed_peer && peers.contains(peer) && !excluded_peers.contains(peer)
            })
            .into_iter()
            .collect();
    }

    let start = *cursor % candidates.len();
    let selected = (0..limit.min(candidates.len()))
        .map(|offset| candidates[(start + offset) % candidates.len()])
        .collect::<Vec<_>>();
    *cursor = (start + selected.len()) % candidates.len();
    selected
}

fn history_step_cache_directory(data_dir: &Path, metadata_digest: [u8; 32]) -> PathBuf {
    let mut digest_hex = String::with_capacity(64);
    for byte in metadata_digest {
        use std::fmt::Write as _;
        write!(&mut digest_hex, "{byte:02x}").expect("writing to String cannot fail");
    }
    data_dir.join("history-step-cache").join(digest_hex)
}

fn embedded_history_step_cache_file(
    data_dir: &Path,
    class: HistoryStepCacheClass,
) -> Option<PathBuf> {
    let pack = embedded_history_step_pack::embedded_history_step_pack()?;
    Some(
        history_step_cache_directory(data_dir, pack.runtime_metadata_digest()).join(
            noid_miner::history_step_runtime_image_file_name(class.class_id()),
        ),
    )
}

fn embedded_history_step_cache_ready(data_dir: &Path, class: HistoryStepCacheClass) -> bool {
    embedded_history_step_cache_file(data_dir, class)
        .and_then(|path| std::fs::metadata(path).ok())
        .is_some_and(|metadata| metadata.is_file() && metadata.len() > 0)
}

fn embedded_history_step_runtime(
    data_dir: &Path,
) -> Result<Option<Arc<noid_recursive::acceptance::history_step::HistoryStepRuntime>>, String> {
    let Some(pack) = embedded_history_step_pack::embedded_history_step_pack() else {
        return Ok(None);
    };
    let metadata = noid_miner::decode_history_step_runtime_metadata_pinned(
        pack.runtime_metadata(),
        pack.runtime_metadata_digest(),
    )
    .map_err(|error| format!("embedded HistoryStep metadata rejected: {error}"))?;
    // The packed runtime layout is derived from the embedded canonical
    // leaves once per release build (keyed by the pinned metadata digest)
    // and reused on later starts.
    let cache_directory = history_step_cache_directory(data_dir, pack.runtime_metadata_digest());
    let matrix_source = pack
        .matrix_source(Some(cache_directory))
        .map_err(|error| format!("embedded HistoryStep matrices rejected: {error}"))?;
    let (bank, runtime_parts) = metadata.into_parts();
    let runtime = noid_recursive::acceptance::history_step::HistoryStepRuntime::new(
        bank,
        Box::new(matrix_source),
        runtime_parts,
    )
    .map_err(|error| format!("embedded HistoryStep runtime rejected: {error}"))?;
    tracing::debug!(
        embedded_matrix_mib = pack.embedded_bytes_total() / (1024 * 1024),
        "build-authenticated HistoryStep runtime images loaded from the executable"
    );
    Ok(Some(Arc::new(runtime)))
}

fn prepare_history_step_ghost_authorization() -> Result<
    Arc<noid_recursive::acceptance::history_step::PreparedHistoryStepGhostAuthorization>,
    String,
> {
    noid_miner::install_history_step_phase_cpu(|| {
        let proof = noid_gkr::ghost_tx::prove_selected_ghost_authorization()
            .map_err(|error| format!("canonical ghost authorization proof failed: {error}"))?;
        noid_recursive::acceptance::history_step::prepare_history_step_ghost_authorization(proof)
            .map(Arc::new)
            .map_err(|error| format!("canonical ghost authorization rejected: {error}"))
    })
    .map_err(|error| format!("HistoryStep ghost CPU phase failed: {error}"))?
}

mod config;
mod embedded_history_step_pack;
mod sync_phase_telemetry;
mod wallet;
use config::NodeConfig;
use sync_phase_telemetry::{SnapshotSyncTelemetry, SyncPhase, SyncPhaseMeasurement};
use wallet::{SharedWallet, WalletHandle, WalletState};

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

/// Operating mode for the full node.
///
/// Exactly one mode must be active. The default is `node`.
#[derive(Debug, Clone, PartialEq, Eq, clap::ValueEnum, Default)]
pub enum NodeMode {
    /// Ordinary node and wallet (default). No mining or template serving.
    /// Verifies all complete blocks and serves recent block/header sync.
    /// Snapshot sync uses the same manifest/HistoryStep pipeline that the O(1)
    /// verifier will authorize.
    #[default]
    Node,
    /// Mining node with built-in all-core PoW followed by the required
    /// all-core HistoryStep and atomic complete-block commit.
    Miner,
    /// Mining node with an external PoW worker. The node owns the immutable
    /// template; the worker returns only a nonce, after which the node proves
    /// and commits the complete block. Requires `--mining-key`.
    Extminer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum HistoryStepCacheClass {
    B25,
    B255,
}

impl HistoryStepCacheClass {
    fn class_id(self) -> noid_recursive::CanonicalHistoryStepClassId {
        noid_recursive::CanonicalHistoryStepClassId::new(match self {
            Self::B25 => 0,
            Self::B255 => 1,
        })
        .expect("GUI cache class is canonical")
    }

    fn label(self) -> &'static str {
        match self {
            Self::B25 => "B25/m22",
            Self::B255 => "B255/m24",
        }
    }
}

#[derive(Parser, Debug)]
#[command(
    name = "parano1d",
    about = "ParanO(1)d full node daemon — proof-native HistoryStep UTXO network",
    version = env!("CARGO_PKG_VERSION"),
    long_about = "Run a ParanO(1)d node and wallet.\n\nExample:\n  parano1d --miner --data-dir ~/.parano1d/data\n  parano1d --p2p-listen 0.0.0.0:9400 --seed 1.2.3.4:9400",
)]
struct Cli {
    /// Path to TOML config file. A missing file is created with safe defaults.
    /// Default: ~/.parano1d/parano1d.toml
    #[arg(short = 'c', long, value_name = "FILE")]
    config: Option<PathBuf>,

    /// Node operating mode.
    ///
    /// node     — ordinary node and wallet, no mining (default)
    /// miner    — mining node with built-in PoW and automatic proof pipeline
    /// extminer — mining node with external PoW nonce search; requires --mining-key
    #[arg(long, value_enum, default_value_t = NodeMode::Node)]
    mode: NodeMode,

    /// Shorthand for `--mode miner`.
    #[arg(long, conflicts_with = "extminer")]
    miner: bool,

    /// Shorthand for `--mode extminer`.
    #[arg(long, conflicts_with = "miner")]
    extminer: bool,

    /// Permit isolated block production without a peer quorum.
    /// Used for the first network node and explicit local-chain testing.
    #[arg(long, hide = true)]
    genesis: bool,

    /// Miner payout address (canonical bech32m, beginning with `o1`).
    /// Defaults to the wallet's active address.
    #[arg(long, value_name = "ADDRESS")]
    miner_address: Option<String>,

    /// Logical CPU threads used by the built-in miner and its proof phases.
    /// Defaults to every CPU visible to the process.
    #[arg(long, value_name = "N")]
    cpu_threads: Option<usize>,

    /// Data directory for the MDBX database and wallet key.
    /// Default: ~/.parano1d/data
    #[arg(long, value_name = "PATH")]
    data_dir: Option<PathBuf>,

    /// P2P listen address in HOST:PORT format. Default: 0.0.0.0:9400
    #[arg(long, value_name = "HOST:PORT")]
    p2p_listen: Option<String>,

    /// JSON-RPC listen address in HOST:PORT format. Default: 127.0.0.1:9401
    #[arg(long, value_name = "HOST:PORT")]
    rpc_listen: Option<String>,

    /// Seed peer address (HOST:PORT). Repeat for multiple seeds.
    /// Example: --seed 1.2.3.4:9400 --seed 5.6.7.8:9400
    #[arg(long, value_name = "HOST:PORT", action = clap::ArgAction::Append)]
    seed: Vec<String>,

    /// Do not dial the embedded DNS bootstrap set.
    /// Used by isolated multi-node protocol tests with explicit loopback seeds.
    #[arg(long, hide = true)]
    disable_dns_seeds: bool,

    /// Log level filter. Examples: debug, info, warn, error.
    #[arg(long, default_value = "info", value_name = "LEVEL")]
    log: String,

    /// Bearer token required for external mining API (getBlockTemplate / submitBlock).
    ///
    /// When set, external callers must include `Authorization: Bearer <TOKEN>` in
    /// HTTP requests to use the mining methods. Without this flag the mining API
    /// only accepts connections from 127.0.0.1 (enforced by --rpc-listen default).
    ///
    /// Pool example:
    ///   parano1d --rpc-listen 0.0.0.0:9401 --mining-key s3cr3t
    ///   # External miner: Authorization: Bearer s3cr3t
    #[arg(long, value_name = "TOKEN")]
    mining_key: Option<String>,

    /// Allow external miners to specify their own coinbase address in getBlockTemplate.
    ///
    /// REQUIRES --mining-key to be set. Without --mining-key this flag is rejected
    /// at startup to prevent unauthenticated access to custom-coinbase templates.
    ///
    /// Use case: infrastructure pool where the node prepares and proves complete blocks and
    /// relays them over P2P, while each miner receives rewards directly to its own address.
    /// The node operator earns via an off-chain service fee, not via coinbase.
    ///
    /// Example:
    ///   parano1d --rpc-listen 0.0.0.0:9401 --mining-key s3cr3t --allow-custom-coinbase
    ///   # Miner: getBlockTemplate("o1their_own_address")
    #[arg(long, requires = "mining_key")]
    allow_custom_coinbase: bool,

    /// Clear the complete chain database on startup and synchronize it again.
    /// Wallet files, receipts and the P2P identity are stored separately and remain.
    /// Use after an incompatible chain-data upgrade or suspected corruption.
    #[arg(long)]
    purge_state: bool,

    /// Check production CPU support and exit without touching node data.
    #[arg(long, exclusive = true)]
    check_hardware: bool,

    /// Print the generated master secret as 64 hexadecimal characters, then exit.
    #[arg(long, hide = true, conflicts_with = "import_wallet_secret")]
    export_wallet_secret: bool,

    /// Read a 64-character master secret from stdin, replace the wallet, then exit.
    #[arg(long, hide = true, conflicts_with = "export_wallet_secret")]
    import_wallet_secret: bool,

    /// Materialize one HistoryStep packed cache image, then exit.
    #[arg(long, value_enum, value_name = "CLASS", hide = true)]
    prepare_history_step_cache: Option<HistoryStepCacheClass>,
}

/// Resolve a seed string to a libp2p Multiaddr.
///
/// Handles four formats:
///
/// 1. `HOST:PORT`            — IP or hostname + port  → `/ip4/H/tcp/P` or `/dns/H/tcp/P`
/// 2. `hostname`             — bare DNS name           → `/dns/hostname/tcp/{default_port}`
/// 3. `/ip4/.../tcp/...`     — libp2p multiaddr, passed through unchanged
/// 4. `dnsaddr:hostname`     — _dnsaddr TXT lookup     → `/dnsaddr/hostname`
///
/// Format 4 is the production DNS seed mechanism.  libp2p resolves
/// `_dnsaddr.<hostname>` TXT records at dial time, each encoding a full
/// multiaddr with PeerID.  This gives cryptographic peer verification and
/// easy multi-node seed rotation via DNS.
///
/// DNS setup for format 4:
///   _dnsaddr.example.org  TXT  "dnsaddr=/ip4/1.2.3.4/tcp/9400/p2p/12D3KooW..."
///   _dnsaddr.example.org  TXT  "dnsaddr=/ip4/5.6.7.8/tcp/9400/p2p/12D3KooW..."
fn seed_to_multiaddr(s: &str, default_port: u16) -> anyhow::Result<libp2p::Multiaddr> {
    let seed = s.trim();

    // Format 3: an explicit multiaddr is already complete. In particular,
    // retain a trailing /p2p/<PeerId>: it cryptographically binds the dial to
    // the identity selected by the operator.
    if seed.starts_with('/') {
        return seed
            .parse()
            .with_context(|| format!("parse multiaddr: {seed}"));
    }

    // Format 4: "dnsaddr:<hostname>" → /dnsaddr/<hostname>
    // Resolves _dnsaddr.<hostname> TXT records (libp2p standard).
    if let Some(host) = seed.strip_prefix("dnsaddr:") {
        let ma_str = format!("/dnsaddr/{}", host.trim());
        return ma_str
            .parse()
            .with_context(|| format!("build dnsaddr multiaddr for {host:?}"));
    }

    // Format 1: HOST:PORT
    if seed.contains(':') {
        return seed_host_port_to_multiaddr(seed);
    }

    // Format 2: bare hostname — use default network port. `/dns/` lets
    // libp2p try both A and AAAA answers (up to its bounded dial limit).
    let ma_str = format!("/dns/{seed}/tcp/{default_port}");
    ma_str
        .parse()
        .with_context(|| format!("build DNS multiaddr for {seed:?}"))
}

fn split_host_port(addr: &str) -> anyhow::Result<(&str, &str)> {
    if let Some(rest) = addr.strip_prefix('[') {
        let (host, port) = rest
            .split_once("]:")
            .with_context(|| format!("invalid bracketed IPv6 address {addr:?}"))?;
        return Ok((host, port));
    }
    addr.rsplit_once(':').with_context(|| {
        format!(
            "invalid address {:?}: expected HOST:PORT (e.g. 127.0.0.1:9400)",
            addr
        )
    })
}

fn seed_host_port_to_multiaddr(addr: &str) -> anyhow::Result<libp2p::Multiaddr> {
    let (host, port_str) = split_host_port(addr)?;
    let port: u16 = port_str
        .parse()
        .with_context(|| format!("invalid port in {addr:?}"))?;
    let protocol = match host.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(ip)) => format!("/ip4/{ip}"),
        Ok(std::net::IpAddr::V6(ip)) => format!("/ip6/{ip}"),
        Err(_) => format!("/dns/{host}"),
    };
    format!("{protocol}/tcp/{port}")
        .parse()
        .with_context(|| format!("build seed multiaddr from {addr:?}"))
}

/// Convert a user-friendly "HOST:PORT" string into a libp2p Multiaddr.
///
/// Users type:  `127.0.0.1:9400`  or  `0.0.0.0:9400`
/// libp2p needs: `/ip4/127.0.0.1/tcp/9400`
///
/// This conversion is purely internal — users never see multiaddrs.
fn ip_port_to_multiaddr(addr: &str) -> anyhow::Result<libp2p::Multiaddr> {
    let (host, port_str) = split_host_port(addr)?;
    let port: u16 = port_str
        .parse()
        .with_context(|| format!("invalid port in {:?}", addr))?;

    let ma_str = match host.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(ip)) => format!("/ip4/{ip}/tcp/{port}"),
        Ok(std::net::IpAddr::V6(ip)) => format!("/ip6/{ip}/tcp/{port}"),
        Err(error) => {
            anyhow::bail!("invalid IP address {host:?} in {addr:?}: {error}");
        }
    };
    ma_str
        .parse()
        .with_context(|| format!("build multiaddr from {:?}", addr))
}

/// Parse a P2P listen address from either the friendly `HOST:PORT` form used
/// by the CLI or the libp2p multiaddr form accepted by existing config files.
fn p2p_listen_to_multiaddr(addr: &str) -> anyhow::Result<libp2p::Multiaddr> {
    let addr = addr.trim();
    if addr.starts_with('/') {
        return addr
            .parse()
            .with_context(|| format!("parse P2P listen multiaddr {addr:?}"));
    }
    ip_port_to_multiaddr(addr)
}

// v1.0.0 could durably finalize the first valid snapshot manifest before a
// stronger peer's manifest arrived.  The patched bootstrap election cannot
// safely cross that already-finalized local boundary.  Advance one explicit
// local chain-data epoch instead: preserve wallet/receipt/identity files,
// clear only MDBX chain tables, and let the patched verifier select the best
// available snapshot from genesis.  This is deliberately not a general
// deep-reorg escape hatch.
const CHAIN_DATA_EPOCH_MARKER_FILE: &str = ".chain-data-epoch";
const CHAIN_DATA_EPOCH_MARKER_BYTES: &[u8] = b"parano1d-mainnet-bootstrap-selection-v2\n";

fn chain_data_epoch_is_current(data_dir: &Path) -> anyhow::Result<bool> {
    let marker = data_dir.join(CHAIN_DATA_EPOCH_MARKER_FILE);
    match std::fs::read(&marker) {
        Ok(bytes) => Ok(bytes == CHAIN_DATA_EPOCH_MARKER_BYTES),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| format!("read {}", marker.display())),
    }
}

fn persist_chain_data_epoch_marker(data_dir: &Path) -> anyhow::Result<()> {
    let marker = data_dir.join(CHAIN_DATA_EPOCH_MARKER_FILE);
    let temporary = data_dir.join(format!(
        "{CHAIN_DATA_EPOCH_MARKER_FILE}.tmp.{}",
        std::process::id()
    ));
    match std::fs::remove_file(&temporary) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error)
                .with_context(|| format!("remove stale marker {}", temporary.display()));
        }
    }

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&temporary)
        .with_context(|| format!("create chain-data epoch marker {}", temporary.display()))?;
    if let Err(error) = file
        .write_all(CHAIN_DATA_EPOCH_MARKER_BYTES)
        .and_then(|()| file.sync_all())
    {
        drop(file);
        let _ = std::fs::remove_file(&temporary);
        return Err(error).context("write chain-data epoch marker");
    }
    drop(file);

    #[cfg(target_os = "windows")]
    if marker.exists() {
        std::fs::remove_file(&marker)
            .with_context(|| format!("replace chain-data epoch marker {}", marker.display()))?;
    }
    if let Err(error) = std::fs::rename(&temporary, &marker) {
        let _ = std::fs::remove_file(&temporary);
        return Err(error)
            .with_context(|| format!("install chain-data epoch marker {}", marker.display()));
    }
    #[cfg(unix)]
    std::fs::File::open(data_dir)
        .and_then(|directory| directory.sync_all())
        .with_context(|| format!("sync data directory {}", data_dir.display()))?;
    Ok(())
}

fn prepare_chain_data_epoch(data_dir: &Path, explicit_purge: bool) -> anyhow::Result<bool> {
    if !explicit_purge && chain_data_epoch_is_current(data_dir)? {
        return Ok(false);
    }

    let store = MdbxStore::open(data_dir).context("open MDBX for chain-data reset")?;
    let previous_height = store
        .get_chain_tip()
        .context("read chain tip before chain-data reset")?
        .map(|(height, _)| height);
    if explicit_purge {
        tracing::info!(
            ?previous_height,
            "--purge-state: clearing the chain database"
        );
    } else if let Some(height) = previous_height {
        tracing::warn!(
            height,
            "one-time sync upgrade: clearing chain state and preserving wallet data"
        );
    } else {
        tracing::debug!("initializing current chain-data epoch");
    }
    store.clear_all().context("clear MDBX chain state")?;
    drop(store);
    persist_chain_data_epoch_marker(data_dir)?;
    Ok(true)
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut cli = Cli::parse();
    if cli.check_hardware {
        let report = noid_core::cpu::ProductionHardwareReport::detect();
        print!("{report}");
        if report.ready() {
            return Ok(());
        }
        let _ = std::io::Write::flush(&mut std::io::stdout());
        std::process::exit(1);
    }
    let production_hardware = noid_core::cpu::ensure_production_hardware()?;

    // Shorthand role flags override the default mode; clap already rejects
    // combining them with each other.
    if cli.miner {
        cli.mode = NodeMode::Miner;
    } else if cli.extminer {
        cli.mode = NodeMode::Extminer;
    }

    // --- Tracing ---
    // Log format: HH:MM:SS LEVEL target: message
    //
    // libp2p internal chatter is suppressed by default. Pass --log debug
    // or RUST_LOG=libp2p=debug to see everything.
    let mut log_filter = EnvFilter::new(&cli.log)
        // libp2p internals — suppress unless user asks for debug
        .add_directive("libp2p_swarm=warn".parse().unwrap_or_default())
        .add_directive("libp2p_tcp=warn".parse().unwrap_or_default())
        .add_directive("libp2p_noise=warn".parse().unwrap_or_default())
        .add_directive("libp2p_yamux=warn".parse().unwrap_or_default())
        // yamux logs a warning when a peer closes the socket before our
        // best-effort closing frame is flushed. The connection is already
        // closed at that point, so this is not an operator-actionable fault.
        .add_directive("yamux=error".parse().unwrap_or_default())
        .add_directive("libp2p_gossipsub=error".parse().unwrap_or_default())
        .add_directive("libp2p_request_response=warn".parse().unwrap_or_default())
        .add_directive("libp2p_identify=warn".parse().unwrap_or_default())
        .add_directive("libp2p_ping=warn".parse().unwrap_or_default())
        .add_directive("libp2p_mdns=warn".parse().unwrap_or_default())
        .add_directive("multiaddr=warn".parse().unwrap_or_default());
    if cli.genesis {
        // An isolated genesis node has no Kademlia peers yet. The library's
        // periodic bootstrap warning is expected and not actionable.
        log_filter = log_filter.add_directive("libp2p_kad=error".parse().unwrap_or_default());
    }

    tracing_subscriber::fmt()
        .with_env_filter(log_filter)
        .with_timer(UtcHms) // HH:MM:SS instead of full ISO timestamp
        .with_target(false) // no module path clutter
        .with_thread_ids(false)
        .compact() // single-line events
        .init();

    // --- Mode validation ---
    if cli.mode == NodeMode::Extminer && cli.mining_key.is_none() {
        anyhow::bail!("--mode extminer requires --mining-key <TOKEN>");
    }
    if cli.mode == NodeMode::Miner && cli.mining_key.is_some() {
        tracing::warn!(
            "--mining-key is ignored in --mode miner (internal miner needs no bearer token)"
        );
    }
    if cli.cpu_threads.is_some() && cli.mode != NodeMode::Miner {
        anyhow::bail!("--cpu-threads requires --mode miner");
    }
    // allow_custom_coinbase only makes sense with extminer mode
    if cli.allow_custom_coinbase && cli.mode != NodeMode::Extminer {
        anyhow::bail!("--allow-custom-coinbase requires --mode extminer");
    }
    let wallet_maintenance = cli.export_wallet_secret || cli.import_wallet_secret;
    if wallet_maintenance && cli.prepare_history_step_cache.is_some() {
        anyhow::bail!("owner secret maintenance and matrix preparation are separate operations");
    }
    if wallet_maintenance
        && (cli.mode != NodeMode::Node
            || cli.genesis
            || cli.purge_state
            || cli.miner_address.is_some()
            || cli.cpu_threads.is_some()
            || cli.mining_key.is_some()
            || cli.allow_custom_coinbase)
    {
        anyhow::bail!("owner secret maintenance cannot be combined with node or mining actions");
    }
    if cli.prepare_history_step_cache.is_some()
        && (cli.mode != NodeMode::Node
            || cli.genesis
            || cli.purge_state
            || cli.miner_address.is_some()
            || cli.cpu_threads.is_some()
            || cli.mining_key.is_some()
            || cli.allow_custom_coinbase)
    {
        anyhow::bail!("matrix preparation cannot be combined with node or mining actions");
    }
    // --- Network ---
    let net = NetworkConfig::mainnet();
    tracing::debug!(network = %net.kind, "daemon starting");

    // --- Config file ---
    let config_path = cli
        .config
        .unwrap_or_else(|| expand_tilde(&PathBuf::from("~/.parano1d/parano1d.toml")));
    let mut config_defaults = NodeConfig::default();
    config_defaults.network.listen = Some(format!("0.0.0.0:{}", net.default_p2p_port));
    config_defaults.rpc.listen = Some(net.default_rpc_listen());
    let (mut cfg, config_created) = load_or_create_config(&config_path, &config_defaults)?;
    if config_created {
        tracing::info!(path = %config_path.display(), "created default node config");
    }

    // CLI flags override config.
    if let Some(dir) = cli.data_dir {
        cfg.storage.path = dir;
    }
    // The CLI mode is authoritative: node/extminer never start the internal
    // miner even if a stale config file has mining.enabled=true.
    cfg.mining.enabled = cli.mode == NodeMode::Miner;
    if let Some(addr) = cli.miner_address {
        cfg.mining.miner_address = addr;
    }
    // Validate both listeners before artifact prewarm, database opening, or
    // wallet creation. A typo in user configuration must fail immediately.
    let p2p_listen_str = cli.p2p_listen.unwrap_or_else(|| {
        cfg.network
            .listen
            .clone()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| net.default_p2p_listen())
    });
    let listen_addr = p2p_listen_to_multiaddr(&p2p_listen_str).context("--p2p-listen")?;
    let rpc_addr_str = cli.rpc_listen.unwrap_or_else(|| {
        cfg.rpc
            .listen
            .clone()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| net.default_rpc_listen())
    });
    let rpc_listen: std::net::SocketAddr = rpc_addr_str.parse().context("parse RPC listen")?;

    // Establish the process-wide all-core phase pool before the embedded
    // registry/matrix prewarm or any verifier can enter Rayon. Internal PoW,
    // HistoryStep and inbound verification reuse this same fixed worker set;
    // `BlockMiner::new` sees the identical idempotent plan.
    let cpu_budget_mode = if cli.mode == NodeMode::Miner {
        noid_miner::ProcessCpuBudgetMode::InternalMiner
    } else {
        noid_miner::ProcessCpuBudgetMode::ProofOnly
    };
    let cpu_plan = noid_miner::configure_process_cpu_budget_with_threads(
        cpu_budget_mode,
        if cli.mode == NodeMode::Miner {
            cli.cpu_threads
        } else {
            None
        },
    )
    .context("configure process CPU budget")?;
    tracing::info!(
        backend = %production_hardware.backend,
        threads = cpu_plan.shared_pool_threads,
        "CPU proof and mining backend selected"
    );
    // GUI Settings and the CLI share the complete seed syntax accepted by
    // seed_to_multiaddr (hostname, IP, dnsaddr, or explicit multiaddr).
    for raw_seed in cli.seed {
        let ma = seed_to_multiaddr(&raw_seed, net.default_p2p_port)
            .with_context(|| format!("--seed {raw_seed}"))?;
        cfg.network.seeds.push(ma.to_string());
    }

    // --- Data directory: ~/.parano1d/data by default (no network subdir) ---
    let data_dir = if cfg.storage.path == Path::new("~/.parano1d/data") {
        expand_tilde(Path::new("~/.parano1d/data"))
    } else {
        expand_tilde(&cfg.storage.path)
    };
    std::fs::create_dir_all(&data_dir)
        .with_context(|| format!("create data dir: {}", data_dir.display()))?;
    let wallet_path = data_dir.join("wallet.key");
    if cli.export_wallet_secret {
        let master_secret = wallet::state::export_generated_master_secret(&wallet_path)
            .map_err(anyhow::Error::msg)?;
        println!("{}", master_secret.as_str());
        return Ok(());
    }
    if cli.import_wallet_secret {
        let mut master_secret = zeroize::Zeroizing::new(String::new());
        std::io::stdin()
            .take(4_097)
            .read_to_string(&mut master_secret)
            .context("read master secret from stdin")?;
        wallet::state::import_generated_master_secret(&wallet_path, &master_secret)
            .map_err(anyhow::Error::msg)?;
        println!("Master secret imported");
        return Ok(());
    }
    if let Some(class) = cli.prepare_history_step_cache {
        if embedded_history_step_cache_ready(&data_dir, class) {
            println!("HistoryStep {} matrix cache is ready", class.label());
            return Ok(());
        }
    }
    let history_step_runtime =
        embedded_history_step_runtime(&data_dir).map_err(anyhow::Error::msg)?;
    match &history_step_runtime {
        None => tracing::warn!(
            "HistoryStep verification unavailable in this pack-free development build"
        ),
        Some(_) => {
            tracing::debug!("HistoryStep verifier uses executable-embedded registry and matrices")
        }
    }
    if let Some(class) = cli.prepare_history_step_cache {
        let runtime = history_step_runtime.clone().ok_or_else(|| {
            anyhow::anyhow!("matrix preparation requires an embedded release pack")
        })?;
        tokio::task::spawn_blocking(move || runtime.prepare_matrix_cache(class.class_id()))
            .await
            .context("HistoryStep cache preparation task panicked")?
            .map_err(anyhow::Error::msg)?;
        println!("HistoryStep {} matrix cache is ready", class.label());
        return Ok(());
    }
    // Receiver snapshots are transactional scratch data. A crash can leave
    // sealed segment files behind, but they are never authoritative and must
    // not survive into a new sync session. Maintenance helpers return above:
    // a cache prewarm running beside a live node must never touch sync state.
    let snapshot_staging_root = data_dir.join("snapshot-staging");
    match std::fs::remove_dir_all(&snapshot_staging_root) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "remove stale snapshot staging: {}",
                    snapshot_staging_root.display()
                )
            });
        }
    }
    std::fs::create_dir_all(&snapshot_staging_root).with_context(|| {
        format!(
            "create snapshot staging directory: {}",
            snapshot_staging_root.display()
        )
    })?;
    let block_production_enabled = cli.mode != NodeMode::Node;
    if block_production_enabled && history_step_runtime.is_none() {
        anyhow::bail!(
            "block production requires the release-pinned HistoryStep runtime and 2 matrices"
        );
    }
    let history_step_ghost = if block_production_enabled {
        Some(
            tokio::task::spawn_blocking(prepare_history_step_ghost_authorization)
                .await
                .context("HistoryStep ghost preparation task panicked")?
                .map_err(anyhow::Error::msg)?,
        )
    } else {
        None
    };

    // --- Storage ---
    tracing::debug!(path = %data_dir.display(), "opening MDBX");
    prepare_chain_data_epoch(&data_dir, cli.purge_state)?;
    let ctx = MdbxChainContext::open_or_create(&data_dir).context("open MDBX")?;
    let tip_height = ctx.tip_height();
    let state_root = hex::encode(ctx.tip_header().state_root);
    tracing::debug!(height = tip_height, state_root = %state_root, "chain loaded");
    let chain = Arc::new(RwLock::new(ctx));

    // Durable initial readiness is separate from edge-triggered tip changes.
    // A Notify permit can be consumed by one of many mempool/miner waiters;
    // watch preserves the state for every current and future subscriber.
    let (initial_sync_ready_tx, initial_sync_ready_rx) = tokio::sync::watch::channel(false);
    let (mining_network_ready_tx, mining_network_ready_rx) =
        tokio::sync::watch::channel(cli.genesis);
    let (mining_confirmed_peer_count_tx, mining_confirmed_peer_count_rx) =
        tokio::sync::watch::channel(0usize);
    // Edge-triggered changes cancel active proof/PoW work when either the
    // canonical parent or a dynamic wallet payout changes.
    let (template_change_tx, _) = tokio::sync::broadcast::channel::<()>(16);
    // Extminer mode owns one prepared/proving attempt. P2P canonical advances
    // use this same handle to invalidate stale ready capabilities immediately.
    let external_mining_attempts = ExternalMiningAttemptInvalidator::new();
    // A recent local timestamp is not evidence that the durable tip is the
    // network tip. Ordinary restarts remain unready until an authenticated
    // peer confirms the exact tip or the sync pipeline applies its extension.

    // --- Mempool ---
    let view = ChainView::from_mdbx(&*chain.read().await);
    let authorization_verification_executor: noid_mempool::AuthorizationVerificationExecutor =
        Arc::new(|task: noid_mempool::AuthorizationVerificationTask| {
            noid_miner::install_inbound_verifier_cpu(task).map_err(|error| {
                format!("authorization verification CPU admission failed: {error}")
            })?
        });
    let mempool = AsyncMempool::new(view, MempoolConfig::default())
        .with_authorization_verification_executor(authorization_verification_executor);
    tracing::debug!("mempool ready");

    // --- Wallet ---
    let wallet_state = match WalletState::create_or_load(wallet_path) {
        Ok(w) => {
            tracing::debug!(address = %w.active_address(), "wallet ready");
            w
        }
        Err(e) => {
            tracing::error!(err = %e, "wallet init failed");
            return Err(anyhow::anyhow!("wallet: {e}"));
        }
    };
    let shared_wallet: SharedWallet = Arc::new(std::sync::Mutex::new(Some(wallet_state)));
    {
        let ctx = chain.read().await;
        let (active_index, next_index, owner, receipts_removed, receipts_recovered) = {
            let mut guard = shared_wallet.lock().unwrap();
            match guard.as_mut() {
                None => unreachable!("wallet just initialized"),
                Some(wallet) => {
                    let (removed, recovered) = wallet::reconcile_receipts_at_startup(wallet, &ctx)
                        .map_err(|error| anyhow::anyhow!("wallet receipt recovery: {error}"))?;
                    (
                        wallet.active_index,
                        wallet.next_index,
                        wallet.active_address().0,
                        removed,
                        recovered,
                    )
                }
            }
        };
        let snapshot = ctx
            .store
            .get_verified_utxos_by_owner(&owner)
            .map_err(|error| anyhow::anyhow!("wallet owner lookup: {error}"))?;
        let height = snapshot.height;
        let found = snapshot.utxos.len();
        let balance = snapshot
            .utxos
            .iter()
            .map(|utxo| utxo.amount)
            .fold(0u64, u64::saturating_add);
        let (reserved_inputs, reserved_outputs) = mempool.reserved_slots().await;
        {
            let mut guard = shared_wallet.lock().unwrap();
            if let Some(w) = guard.as_mut() {
                w.commit_verified_activation(
                    active_index,
                    next_index,
                    active_index,
                    owner,
                    snapshot,
                    &reserved_inputs,
                    &reserved_outputs,
                )
                .map_err(|error| anyhow::anyhow!("wallet owner reload: {error}"))?;
            }
        }
        drop(ctx);
        tracing::info!(
            height,
            active_index,
            utxos = found,
            balance,
            receipts_removed,
            receipts_recovered,
            "wallet active address loaded"
        );
    }
    let wallet = WalletHandle::new(shared_wallet.clone());
    let wallet_operation_gate = Arc::new(tokio::sync::Mutex::new(()));

    // --- P2P Network ---
    let topics = noid_p2p::protocol::NetworkTopics::for_network_cfg(&net);
    let (p2p, _p2p_task) = P2PNetwork::start(
        listen_addr.clone(),
        chain.clone(),
        mempool.clone(),
        topics,
        data_dir.clone(),
    )
    .context("start P2P network")?;
    tracing::debug!(listen = %listen_addr, "P2P started");

    // Dial seeds: CLI seeds + config seeds + the embedded DNS bootstrap set.
    // Isolated release-binary protocol tests disable only the final source;
    // explicit loopback seeds still exercise the normal P2P dial path.
    let dns_seeds = if cli.disable_dns_seeds {
        tracing::debug!("embedded DNS bootstrap disabled for isolated protocol test");
        &[][..]
    } else {
        net.dns_seeds
    };
    let all_seeds: Vec<String> = cfg
        .network
        .seeds
        .clone()
        .into_iter()
        .chain(dns_seeds.iter().map(|s| s.to_string()))
        .collect();
    for seed_addr in &all_seeds {
        let ma = seed_to_multiaddr(seed_addr, net.default_p2p_port);
        match ma {
            Ok(addr) => {
                tracing::debug!(addr = %addr, "dialing seed");
                p2p.dial(addr).await;
            }
            Err(e) => {
                tracing::warn!(addr = %seed_addr, err = %e, "cannot parse seed address");
            }
        }
    }

    // --genesis is an explicit isolated-mining override for network bootstrap
    // and local-chain tests. It remains valid after restart at any local height.
    // Normal miners require confirmed ordinary P2P nodes; peers need not mine.
    if initial_sync_may_skip_peer_confirmation(cli.genesis) {
        tracing::debug!("genesis mode: marking initial sync ready immediately");
        mark_initial_sync_ready(&initial_sync_ready_tx);
    }

    // Background P2P event handler.
    let p2p_chain = chain.clone();
    let p2p_mempool = mempool.clone();
    let p2p_wallet = shared_wallet.clone();
    let p2p_events = p2p.subscribe();
    let p2p_cmd_for_events = p2p.cmd_tx.clone();
    let p2p_template_changes = template_change_tx.clone();
    let p2p_initial_sync_ready = initial_sync_ready_tx.clone();
    let p2p_mining_peer_quorum = MiningPeerQuorum::new(
        cli.genesis,
        mining_network_ready_tx,
        mining_confirmed_peer_count_tx,
    );
    let p2p_wallet_operation_gate = Arc::clone(&wallet_operation_gate);
    let p2p_snapshot_staging_root = snapshot_staging_root.clone();
    let p2p_history_step_runtime = history_step_runtime.clone();
    let p2p_external_mining_attempts = external_mining_attempts.clone();
    tokio::spawn(async move {
        handle_p2p_events(
            p2p_events,
            p2p_chain,
            p2p_mempool,
            p2p_wallet,
            p2p_cmd_for_events,
            p2p_initial_sync_ready,
            p2p_mining_peer_quorum,
            p2p_template_changes,
            p2p_wallet_operation_gate,
            p2p_snapshot_staging_root,
            p2p_history_step_runtime,
            p2p_external_mining_attempts,
        )
        .await;
    });

    // Relay mempool TxAdmitted → P2P gossip.
    let mut mp_events = mempool.subscribe();
    let p2p_tx_relay = p2p.cmd_tx.clone();
    tokio::spawn(async move {
        loop {
            match mp_events.recv().await {
                Ok(noid_mempool::MempoolEvent::TxAdmitted { intent_bytes, .. }) => {
                    let _ = p2p_tx_relay
                        .send(noid_p2p::NetworkCommand::BroadcastTx { intent_bytes })
                        .await;
                }
                Ok(_) => {}
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    tracing::warn!(skipped = n, "mempool relay: lagged, some TXs not gossiped");
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            }
        }
    });

    // --- RPC Server ---
    // Payout address for the mining template API: explicit override or active wallet address.
    let mining_payout_address = if cfg.mining.miner_address.is_empty() {
        None
    } else {
        Some(parse_address(&cfg.mining.miner_address)?)
    };
    if let Some(ref key) = cli.mining_key {
        if key.len() < 16 {
            tracing::warn!(
                "--mining-key is short (<16 chars) — use a longer random token in production"
            );
        }
        tracing::info!(
            allow_custom_coinbase = cli.allow_custom_coinbase,
            "mining API: external access enabled with bearer token authentication"
        );
        if cli.allow_custom_coinbase {
            tracing::info!(
                "mining API: --allow-custom-coinbase active — \
                 authenticated miners may specify their own payout address"
            );
        }
    }
    let (rpc_handle, rpc_stop_rx) = start_rpc_server(
        rpc_listen,
        chain.clone(),
        mempool.clone(),
        wallet,
        Arc::clone(&wallet_operation_gate),
        p2p.cmd_tx.clone(),
        initial_sync_ready_rx.clone(),
        mining_network_ready_rx.clone(),
        mining_confirmed_peer_count_rx.clone(),
        MINING_PEER_QUORUM,
        cli.genesis,
        cfg.mining.enabled,
        noid_core::cpu::selected_backend().to_string(),
        cpu_plan.available_threads,
        cpu_plan.shared_pool_threads,
        history_step_runtime.clone(),
        history_step_ghost.clone(),
        external_mining_attempts,
        template_change_tx.clone(),
        cli.mode == NodeMode::Extminer,
        mining_payout_address,
        cli.mining_key,
        cli.allow_custom_coinbase,
    )
    .await
    .context("start RPC server")?;
    tracing::debug!(listen = %rpc_listen, "RPC ready");

    // --- Miner (optional) ---
    let miner_handle = if cfg.mining.enabled {
        // If no miner address is configured, resolve the active wallet address
        // afresh for every template.
        // This ensures coinbase rewards go directly to the built-in wallet.
        let miner_addr = if cfg.mining.miner_address.is_empty() {
            let guard = shared_wallet.lock().unwrap();
            guard
                .as_ref()
                .map(|w| w.active_address())
                .unwrap_or(noid_poseidon2b::primitives::Address([0u8; 32]))
        } else {
            parse_address(&cfg.mining.miner_address)?
        };
        tracing::debug!(address = %miner_addr, "miner coinbase address");
        let miner_cfg = MinerConfig {
            miner_address: miner_addr,
            ..Default::default()
        };
        let (mut miner, mut miner_rx) = BlockMiner::new(
            miner_cfg,
            mempool.clone(),
            chain.clone(),
            mining_network_ready_rx,
            template_change_tx.clone(),
            Arc::clone(
                history_step_runtime
                    .as_ref()
                    .expect("producer runtime checked at startup"),
            ),
            Arc::clone(
                history_step_ghost
                    .as_ref()
                    .expect("producer ghost checked at startup"),
            ),
        );
        miner.set_chain_operation_gate(Arc::clone(&wallet_operation_gate));

        if cfg.mining.miner_address.is_empty() {
            let payout_wallet = shared_wallet.clone();
            let fallback_payout = miner_addr;
            miner.set_payout_resolver(std::sync::Arc::new(move || {
                payout_wallet
                    .lock()
                    .ok()
                    .and_then(|wallet| wallet.as_ref().map(|wallet| wallet.active_address()))
                    .unwrap_or(fallback_payout)
            }));
        }

        // Register wallet hook: called synchronously in apply_found_block BEFORE
        // on_new_block. Guarantees receipt is stored before getMempoolSize drops to 0.
        // Works at any mining speed — no channel, no capacity limit, no race.
        // Remote wallets use P2P block subscription independently.
        {
            let hook_wallet = shared_wallet.clone();
            miner.set_block_applied_hook(std::sync::Arc::new(move |block| {
                update_wallet_for_block(&hook_wallet, block);
            }));
        }

        let miner_stop = miner.stop_handle(); // cancel_pow — aborts current PoW chunk
        let miner_stopped = miner.stopped_handle(); // permanent stop — breaks the loop

        let p2p_block_relay = p2p.cmd_tx.clone();
        tokio::spawn(async move {
            loop {
                match miner_rx.recv().await {
                    Ok(noid_miner::MinerEvent::BlockFound {
                        bundle,
                        height,
                        hash,
                        n_txs,
                        ..
                    }) => {
                        tracing::debug!(
                            height,
                            hash = %hex::encode(hash),
                            txs = n_txs,
                            "broadcast block"
                        );
                        let _ = p2p_block_relay
                            .send(noid_p2p::NetworkCommand::AnnounceBlock { bundle })
                            .await;
                    }
                    Ok(noid_miner::MinerEvent::ProveFailed { height, error }) => {
                        tracing::warn!(height, err = %error, "block prove failed");
                    }
                    Ok(_) => {} // TemplateRefreshed, MiningCancelled — no action needed
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        // Channel lagged (fast mining at genesis difficulty).
                        // Wallet updates are unaffected — they go through the hook, not here.
                        tracing::warn!(skipped = n, "miner event channel lagged (broadcast only)");
                    }
                    Err(_) => break, // channel closed (miner stopped)
                }
            }
        });

        let task = tokio::spawn(async move { miner.run().await });
        tracing::debug!("miner started");
        Some((task, miner_stop, miner_stopped))
    } else {
        None
    };

    // --- Startup Banner ---
    {
        use noid_chain::consensus::emission::block_reward;
        use noid_chain::fri_state::LOG_SEGMENT_SIZE;

        let wallet_bech32 = {
            let g = shared_wallet.lock().unwrap();
            g.as_ref().map(|w| w.active_address().to_bech32())
        };
        let miner_bech32 = if cfg.mining.enabled {
            mining_payout_address
                .map(|address| address.to_bech32())
                .or_else(|| {
                    let wallet = shared_wallet.lock().unwrap();
                    wallet
                        .as_ref()
                        .map(|wallet| wallet.active_address().to_bech32())
                })
        } else {
            None
        };
        let ctx = chain.read().await;
        let tip_hdr = *ctx.tip_header();

        let log_slots = tip_hdr.log_slots;
        let active = tip_hdr.active_slot_count;
        let num_segs = if log_slots as usize > LOG_SEGMENT_SIZE {
            1usize << (log_slots as usize - LOG_SEGMENT_SIZE)
        } else {
            1
        };
        let mat_segs = ctx.state.state.active_segment_ids().count();
        let encoded_state_bytes = ctx
            .store
            .encoded_state_bytes()
            .context("read encoded state size for startup banner")?;
        let reward = block_reward(log_slots) as f64 / 1_000_000.0;

        drop(ctx);

        let p2p_display = listen_addr
            .to_string()
            .replace("/ip4/", "")
            .replace("/ip6/", "")
            .replace("/tcp/", ":");

        print_startup_banner(
            net.kind.as_str(),
            cli.genesis,
            &p2p_display,
            &rpc_listen.to_string(),
            tip_height,
            &tip_hdr.state_root,
            active,
            log_slots,
            mat_segs,
            num_segs,
            encoded_state_bytes,
            reward,
            wallet_bech32.as_deref(),
            cfg.mining.enabled,
            miner_bech32.as_deref(),
            env!("CARGO_PKG_VERSION"),
        );
    }

    // --- Shutdown ---
    // Wait for either Ctrl-C or a `paranoid_stop` RPC call.
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("Ctrl-C received");
        }
        _ = rpc_stop_rx => {
            tracing::info!("stop command received via RPC");
        }
    }

    tracing::info!("shutting down — cancelling miner and closing connections");

    // 1. Signal the miner to stop: set `stopped` (breaks the loop) then
    //    `cancel_pow` (aborts the current PoW chunk so the loop reaches the
    //    top-of-loop check quickly).
    if let Some((_, ref stop_flag, ref stopped_flag)) = miner_handle {
        stopped_flag.store(true, std::sync::atomic::Ordering::Release);
        stop_flag.store(true, std::sync::atomic::Ordering::SeqCst);
        tracing::debug!("miner stop flags set");
    }
    // 2. Stop RPC server (no new requests accepted).
    let _ = rpc_handle.stop();

    // 3. Wait for the miner task to exit cleanly. The miner checks `stopped`
    //    at the top of each loop iteration; `cancel_pow` ensures the current
    //    PoW chunk finishes quickly. Nonce-independent preparation and the
    //    atomic HistoryStep proof are deliberately not interrupted midway,
    //    so allow one bounded production phase to finish cleanly.
    if let Some((task, _, _)) = miner_handle {
        match tokio::time::timeout(MINER_SHUTDOWN_GRACE, task).await {
            Ok(Ok(_)) => tracing::debug!("miner task exited cleanly"),
            Ok(Err(e)) if e.is_cancelled() => tracing::debug!("miner task cancelled"),
            Ok(Err(e)) => tracing::warn!("miner task error: {e}"),
            Err(_) => tracing::warn!(
                grace_secs = MINER_SHUTDOWN_GRACE.as_secs(),
                "miner task did not finish its bounded phase before shutdown grace elapsed"
            ),
        }
    }
    tracing::info!("goodbye — MDBX flushed on drop");
    Ok(())
}

// ---------------------------------------------------------------------------
// P2P event handler
// ---------------------------------------------------------------------------

fn log_sync_phase_measurement(measurement: SyncPhaseMeasurement) {
    tracing::info!(
        phase = measurement.phase.label(),
        scaling = measurement.phase.scaling(),
        count = measurement.count,
        bytes = measurement.bytes,
        elapsed_ms = measurement.elapsed_ms(),
        timing_basis = "active_work",
        outcome = if measurement.succeeded {
            "accepted"
        } else {
            "rejected"
        },
        "snapshot sync phase measurement"
    );
}

struct PendingSnapshotHeaderSync {
    /// Peer that supplied the selected manifest and will serve its leased
    /// state generation.
    from: libp2p::PeerId,
    manifest: Box<noid_p2p::protocol::GetStateManifestResponse>,
    staging: SnapshotHeaderStaging,
    next_height: u64,
    target_height: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ManifestTerminalCapability {
    boundary_height: u64,
    boundary_hash: [u8; 32],
    bridge_height: u64,
    bridge_hash: [u8; 32],
}

impl ManifestTerminalCapability {
    fn advertises(self, height: u64, block_hash: [u8; 32]) -> bool {
        (self.boundary_height == height && self.boundary_hash == block_hash)
            || (self.bridge_height == height && self.bridge_hash == block_hash)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PendingTerminalRequest {
    peer: libp2p::PeerId,
    token: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TerminalRequestRace {
    primary: PendingTerminalRequest,
    primary_active: bool,
    hedge: Option<PendingTerminalRequest>,
    hedge_active: bool,
    started_at: Instant,
}

impl TerminalRequestRace {
    fn new(peer: libp2p::PeerId, token: u64) -> Self {
        Self {
            primary: PendingTerminalRequest { peer, token },
            primary_active: true,
            hedge: None,
            hedge_active: false,
            started_at: Instant::now(),
        }
    }

    fn hedge_due(&self, now: Instant) -> bool {
        self.primary_active
            && self.hedge.is_none()
            && now.saturating_duration_since(self.started_at) >= HISTORY_STEP_TERMINAL_HEDGE_AFTER
    }

    fn deadline_due(&self, now: Instant) -> bool {
        self.has_active()
            && now.saturating_duration_since(self.started_at) >= HISTORY_STEP_TERMINAL_HARD_DEADLINE
    }

    fn matches(&self, peer: libp2p::PeerId, token: u64) -> bool {
        (self.primary_active && self.primary == PendingTerminalRequest { peer, token })
            || (self.hedge_active && self.hedge == Some(PendingTerminalRequest { peer, token }))
    }

    fn has_active(&self) -> bool {
        self.primary_active || self.hedge_active
    }

    fn used_peer(&self, peer: libp2p::PeerId) -> bool {
        self.primary.peer == peer || self.hedge.is_some_and(|request| request.peer == peer)
    }

    fn install_hedge(&mut self, peer: libp2p::PeerId) {
        debug_assert!(self.hedge.is_none());
        self.hedge = Some(PendingTerminalRequest {
            peer,
            token: self.primary.token,
        });
        self.hedge_active = true;
    }

    fn mark_failed(&mut self, peer: libp2p::PeerId, token: u64) -> bool {
        let request = PendingTerminalRequest { peer, token };
        if self.primary_active && self.primary == request {
            self.primary_active = false;
            return true;
        }
        if self.hedge_active && self.hedge == Some(request) {
            self.hedge_active = false;
            return true;
        }
        false
    }

    fn mark_succeeded(&mut self, peer: libp2p::PeerId, token: u64) -> bool {
        if !self.matches(peer, token) {
            return false;
        }
        self.primary_active = false;
        self.hedge_active = false;
        true
    }
}

fn terminal_alternate_peer(
    peers: &std::collections::HashSet<libp2p::PeerId>,
    rejected: &std::collections::HashSet<libp2p::PeerId>,
    requests: &TerminalRequestRace,
) -> Option<libp2p::PeerId> {
    peers
        .iter()
        .copied()
        .filter(|peer| !requests.used_peer(*peer))
        .filter(|peer| !rejected.contains(peer))
        .min_by_key(|peer| peer.to_bytes())
}

fn advertised_terminal_alternate_peer(
    peers: &std::collections::HashSet<libp2p::PeerId>,
    capabilities: &std::collections::HashMap<libp2p::PeerId, ManifestTerminalCapability>,
    rejected: &std::collections::HashSet<libp2p::PeerId>,
    requests: &TerminalRequestRace,
    height: u64,
    block_hash: [u8; 32],
) -> Option<libp2p::PeerId> {
    peers
        .iter()
        .copied()
        .filter(|peer| !requests.used_peer(*peer))
        .filter(|peer| !rejected.contains(peer))
        .filter(|peer| {
            capabilities
                .get(peer)
                .is_some_and(|capability| capability.advertises(height, block_hash))
        })
        .min_by_key(|peer| peer.to_bytes())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SnapshotHeaderNextAction {
    Fetch { start_height: u64, count: u16 },
    RequestTerminal,
}

/// Consecutive, non-overlapping ranges requested from one selected peer. They
/// may arrive out of order, but only the exact next height enters native
/// validation. This hides request/response latency without racing sources.
const SNAPSHOT_HEADER_REQUEST_WINDOW: usize = 4;
/// Use the codec's allocation-bounded response cap directly. The bounded
/// ordered window avoids paying one request-response round trip per range.
const SNAPSHOT_HEADER_BATCH: u64 = MAX_STAGED_HEADER_BATCH as u64;
/// A timeout on a slow path reduces only the failed range. Successful paths
/// retain the full bulk batch, while a VPN or constrained relay can make
/// progress without repeatedly timing out on the same full-size response.
const SNAPSHOT_HEADER_MIN_BATCH: u16 = 512;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SnapshotHeaderRequestPlan {
    peer: libp2p::PeerId,
    token: u64,
    start_height: u64,
    count: u16,
}

#[derive(Clone, Debug)]
struct SnapshotHeaderAttempt {
    peer: libp2p::PeerId,
    token: u64,
}

#[derive(Clone, Debug)]
struct OutstandingSnapshotHeaderRequest {
    count: u16,
    primary: SnapshotHeaderAttempt,
    attempted_peers: std::collections::HashSet<libp2p::PeerId>,
}

impl OutstandingSnapshotHeaderRequest {
    fn accepts(&self, peer: libp2p::PeerId, token: u64) -> bool {
        self.primary.peer == peer && self.primary.token == token
    }
}

#[derive(Debug)]
struct ReadySnapshotHeaderRange {
    source_peer: libp2p::PeerId,
    count: u16,
    attempted_peers: std::collections::HashSet<libp2p::PeerId>,
    headers: Vec<noid_chain::BlockHeader>,
}

#[derive(Debug)]
struct SnapshotHeaderPipeline {
    generation: u64,
    /// Peer that owns the selected immutable snapshot generation.
    from: libp2p::PeerId,
    /// Exact headers are ordinary chain data. A peer that wins a range becomes
    /// the preferred source for later ranges without changing snapshot owner.
    header_peer: libp2p::PeerId,
    target_height: u64,
    next_request_height: u64,
    next_request_token: u64,
    batch_cap: u16,
    peer_cursor: usize,
    outstanding: std::collections::BTreeMap<u64, OutstandingSnapshotHeaderRequest>,
    ready: std::collections::BTreeMap<u64, ReadySnapshotHeaderRange>,
}

impl SnapshotHeaderPipeline {
    fn new(generation: u64, from: libp2p::PeerId, next_height: u64, target_height: u64) -> Self {
        Self {
            generation,
            from,
            header_peer: from,
            target_height,
            next_request_height: next_height,
            next_request_token: 0,
            batch_cap: SNAPSHOT_HEADER_BATCH as u16,
            peer_cursor: 0,
            outstanding: std::collections::BTreeMap::new(),
            ready: std::collections::BTreeMap::new(),
        }
    }

    fn allocate_token(&mut self) -> u64 {
        self.next_request_token = self.next_request_token.wrapping_add(1);
        self.next_request_token
    }

    fn refill_plan(&mut self, locally_staging: bool) -> Vec<SnapshotHeaderRequestPlan> {
        let mut plan = Vec::with_capacity(SNAPSHOT_HEADER_REQUEST_WINDOW);
        let reserved = usize::from(locally_staging);
        while self.outstanding.len() + self.ready.len() + reserved < SNAPSHOT_HEADER_REQUEST_WINDOW
            && self.next_request_height <= self.target_height
        {
            let start_height = self.next_request_height;
            let count = (self.target_height - start_height + 1)
                .min(u64::from(self.batch_cap))
                .min(MAX_STAGED_HEADER_BATCH as u64) as u16;
            self.next_request_height += u64::from(count);
            let token = self.allocate_token();
            self.outstanding.insert(
                start_height,
                OutstandingSnapshotHeaderRequest {
                    count,
                    primary: SnapshotHeaderAttempt {
                        peer: self.header_peer,
                        token,
                    },
                    attempted_peers: std::iter::once(self.header_peer).collect(),
                },
            );
            plan.push(SnapshotHeaderRequestPlan {
                peer: self.header_peer,
                token,
                start_height,
                count,
            });
        }
        plan
    }

    fn matches_generation(&self, generation: u64) -> bool {
        self.generation == generation
    }

    fn accept(
        &mut self,
        generation: u64,
        token: u64,
        from: libp2p::PeerId,
        start_height: u64,
        requested_count: u16,
        headers: Vec<noid_chain::BlockHeader>,
    ) -> Result<(), String> {
        if generation != self.generation {
            return Err("snapshot header response belongs to another session".into());
        }
        let Some(expected) = self.outstanding.remove(&start_height) else {
            return Err("snapshot header response has no matching outstanding range".into());
        };
        let response_valid = (|| {
            if !expected.accepts(from, token) {
                return Err("snapshot header response has a stale correlation token".to_owned());
            }
            if expected.count != requested_count || headers.len() != usize::from(expected.count) {
                return Err(
                    "snapshot header response length does not match its exact request".to_owned(),
                );
            }
            if headers
                .first()
                .is_none_or(|header| header.height != start_height)
            {
                return Err("snapshot header response starts at the wrong height".to_owned());
            }
            let expected_end = start_height + u64::from(expected.count) - 1;
            if headers
                .last()
                .is_none_or(|header| header.height != expected_end)
            {
                return Err("snapshot header response ends at the wrong height".to_owned());
            }
            Ok(())
        })();
        if let Err(error) = response_valid {
            self.outstanding.insert(start_height, expected);
            return Err(error);
        }
        self.header_peer = from;
        if self
            .ready
            .insert(
                start_height,
                ReadySnapshotHeaderRange {
                    source_peer: from,
                    count: expected.count,
                    attempted_peers: expected.attempted_peers,
                    headers,
                },
            )
            .is_some()
        {
            return Err("duplicate snapshot header response".into());
        }
        Ok(())
    }

    fn matches_outstanding(
        &self,
        peer: libp2p::PeerId,
        start_height: u64,
        count: u16,
        token: u64,
    ) -> bool {
        self.outstanding
            .get(&start_height)
            .is_some_and(|request| request.count == count && request.accepts(peer, token))
    }

    fn rotating_peer(
        &mut self,
        peers: &std::collections::HashSet<libp2p::PeerId>,
        attempted: &std::collections::HashSet<libp2p::PeerId>,
    ) -> Option<libp2p::PeerId> {
        let mut candidates = peers
            .iter()
            .copied()
            .filter(|peer| !attempted.contains(peer))
            .collect::<Vec<_>>();
        candidates.sort_by_key(|peer| peer.to_bytes());
        if candidates.is_empty() {
            return None;
        }
        let index = self.peer_cursor % candidates.len();
        self.peer_cursor = self.peer_cursor.wrapping_add(1);
        Some(candidates[index])
    }

    fn restart_range(
        &mut self,
        start_height: u64,
        peer: libp2p::PeerId,
        count: u16,
        mut attempted_peers: std::collections::HashSet<libp2p::PeerId>,
    ) -> SnapshotHeaderRequestPlan {
        let token = self.allocate_token();
        attempted_peers.insert(peer);
        self.outstanding.insert(
            start_height,
            OutstandingSnapshotHeaderRequest {
                count,
                primary: SnapshotHeaderAttempt { peer, token },
                attempted_peers,
            },
        );
        SnapshotHeaderRequestPlan {
            peer,
            token,
            start_height,
            count,
        }
    }

    fn failure_plan(
        &mut self,
        peer: libp2p::PeerId,
        start_height: u64,
        count: u16,
        token: u64,
        kind: noid_p2p::RequestFailureKind,
        peers: &std::collections::HashSet<libp2p::PeerId>,
    ) -> Option<SnapshotHeaderRequestPlan> {
        let (mut retry_count, mut attempted_peers, failed_peer) = {
            let request = self.outstanding.remove(&start_height)?;
            if request.count != count {
                self.outstanding.insert(start_height, request);
                return None;
            }
            if request.primary.peer != peer || request.primary.token != token {
                self.outstanding.insert(start_height, request);
                return None;
            }
            (request.count, request.attempted_peers, request.primary.peer)
        };

        // Every later range was scheduled from the failed prefix. Retire it
        // deterministically and rebuild from this exact height. Earlier ranges
        // remain useful and are still consumed in order.
        self.outstanding
            .retain(|range_start, _| *range_start < start_height);
        self.ready
            .retain(|range_start, _| *range_start < start_height);

        if matches!(kind, noid_p2p::RequestFailureKind::Timeout)
            && retry_count > SNAPSHOT_HEADER_MIN_BATCH
        {
            retry_count = (retry_count / 2).max(SNAPSHOT_HEADER_MIN_BATCH);
            self.batch_cap = self.batch_cap.min(retry_count);
            attempted_peers.clear();
            if peers.len() > 1 {
                attempted_peers.insert(failed_peer);
            }
        }
        self.next_request_height = start_height.saturating_add(u64::from(retry_count));
        let alternate = self.rotating_peer(peers, &attempted_peers)?;
        Some(self.restart_range(start_height, alternate, retry_count, attempted_peers))
    }

    fn retry_rejected_range(
        &mut self,
        start_height: u64,
        count: u16,
        attempted_peers: std::collections::HashSet<libp2p::PeerId>,
        peers: &std::collections::HashSet<libp2p::PeerId>,
    ) -> Option<SnapshotHeaderRequestPlan> {
        if self.next_request_height < start_height.saturating_add(u64::from(count)) {
            return None;
        }
        // Later ranges may have overlapped local validation of this batch. They
        // are based on the rejected prefix, so retire their correlation tokens
        // and rebuild the ordered pipeline from this exact height.
        self.outstanding
            .retain(|range_start, _| *range_start < start_height);
        self.ready
            .retain(|range_start, _| *range_start < start_height);
        self.next_request_height = start_height.saturating_add(u64::from(count));
        let alternate = self.rotating_peer(peers, &attempted_peers)?;
        Some(self.restart_range(start_height, alternate, count, attempted_peers))
    }

    fn take_ready(&mut self, next_height: u64) -> Option<ReadySnapshotHeaderRange> {
        self.ready.remove(&next_height)
    }

    fn is_drained(&self) -> bool {
        self.next_request_height > self.target_height
            && self.outstanding.is_empty()
            && self.ready.is_empty()
    }
}

fn snapshot_header_next_action(
    next_height: u64,
    target_height: u64,
) -> Result<SnapshotHeaderNextAction, String> {
    if next_height <= target_height {
        let count = (target_height - next_height + 1)
            .min(SNAPSHOT_HEADER_BATCH)
            .min(MAX_STAGED_HEADER_BATCH as u64) as u16;
        return Ok(SnapshotHeaderNextAction::Fetch {
            start_height: next_height,
            count,
        });
    }
    if target_height.checked_add(1) == Some(next_height) {
        return Ok(SnapshotHeaderNextAction::RequestTerminal);
    }
    Err("snapshot header staging advanced beyond its exact target".into())
}

fn validate_snapshot_header_batch_admission(
    next_height: u64,
    target_height: u64,
    batch_len: usize,
) -> Result<(), String> {
    if next_height > target_height {
        return Err("snapshot exact header target is already staged".into());
    }
    let remaining = target_height - next_height + 1;
    if batch_len == 0 {
        return Err("snapshot header batch is empty".into());
    }
    if batch_len > MAX_STAGED_HEADER_BATCH {
        return Err("snapshot header batch exceeds the bounded response cap".into());
    }
    if batch_len as u64 > remaining {
        return Err("snapshot header batch crosses the exact target".into());
    }
    Ok(())
}

fn snapshot_header_staging_path(
    staging_root: &Path,
    manifest: &noid_p2p::protocol::GetStateManifestResponse,
) -> PathBuf {
    staging_root.join("headers").join(format!(
        "{}-{}.stage",
        manifest.tip_height,
        hex::encode(manifest.tip_hash)
    ))
}

fn prune_superseded_snapshot_header_staging(directory: &Path, keep: &Path) -> Result<(), String> {
    let entries = std::fs::read_dir(directory)
        .map_err(|error| format!("read snapshot header staging directory: {error}"))?;
    for entry in entries {
        let entry =
            entry.map_err(|error| format!("read snapshot header staging entry: {error}"))?;
        let path = entry.path();
        if path == keep || path.extension().and_then(|ext| ext.to_str()) != Some("stage") {
            continue;
        }
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(format!(
                    "remove superseded snapshot header staging {}: {error}",
                    path.display()
                ));
            }
        }
    }
    Ok(())
}

/// Find the highest contiguous canonical header boundary at or below target.
/// Header anchors are created strictly in height order, so a binary search is
/// sufficient and never materializes an O(H) header collection.
fn highest_snapshot_header_boundary(
    store: &noid_chain::storage::MdbxStore,
    target_height: u64,
) -> Result<CanonicalHeaderBoundary, String> {
    let state_tip = store
        .get_chain_tip()
        .map_err(|error| format!("snapshot canonical tip read failed: {error}"))?
        .ok_or_else(|| "snapshot canonical tip is missing".to_owned())?
        .0;
    let floor = state_tip.min(target_height);
    CanonicalHeaderBoundary::load(store, floor)
        .map_err(|error| format!("snapshot canonical floor rejected: {error}"))?;
    if floor == target_height {
        return CanonicalHeaderBoundary::load(store, floor)
            .map_err(|error| format!("snapshot target boundary rejected: {error}"));
    }
    if store
        .get_header_anchor(target_height)
        .map_err(|error| format!("snapshot target anchor read failed: {error}"))?
        .is_some()
    {
        return CanonicalHeaderBoundary::load(store, target_height)
            .map_err(|error| format!("snapshot target boundary rejected: {error}"));
    }

    let mut present = floor;
    let mut missing = target_height;
    while present + 1 < missing {
        let middle = present + (missing - present) / 2;
        if store
            .get_header_anchor(middle)
            .map_err(|error| format!("snapshot header anchor read h={middle}: {error}"))?
            .is_some()
        {
            present = middle;
        } else {
            missing = middle;
        }
    }
    CanonicalHeaderBoundary::load(store, present)
        .map_err(|error| format!("snapshot canonical base rejected: {error}"))
}

fn prepare_snapshot_header_sync(
    staging_root: &Path,
    store: &noid_chain::storage::MdbxStore,
    from: libp2p::PeerId,
    manifest: Box<noid_p2p::protocol::GetStateManifestResponse>,
    rebase_base: Option<(u64, [u8; 32])>,
) -> Result<PendingSnapshotHeaderSync, String> {
    let target_height = manifest.tip_height;
    let after_target = target_height
        .checked_add(1)
        .ok_or_else(|| "snapshot target height has no representable successor".to_owned())?;
    let base = match rebase_base.filter(|(height, _)| *height < target_height) {
        Some((height, expected_hash)) => {
            let base = CanonicalHeaderBoundary::load(store, height)
                .map_err(|error| format!("snapshot rebase boundary rejected: {error}"))?;
            if base.block_hash != expected_hash {
                return Err("snapshot rebase boundary changed before staging".into());
            }
            base
        }
        None => highest_snapshot_header_boundary(store, target_height)?,
    };
    let directory = staging_root.join("headers");
    std::fs::create_dir_all(&directory)
        .map_err(|error| format!("create snapshot header staging directory: {error}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))
            .map_err(|error| format!("secure snapshot header staging directory: {error}"))?;
    }
    let path = snapshot_header_staging_path(staging_root, &manifest);
    // A failed exact terminal may leave one expensive header prefix available
    // for immediate failover. Once a different boundary wins, delete the old
    // file before opening the new session so disk use stays bounded to one
    // O(height) staging artifact.
    prune_superseded_snapshot_header_staging(&directory, &path)?;

    let staging = if path.exists() {
        match SnapshotHeaderStaging::open(&path, store) {
            Ok(staging)
                if staging.base() == base
                    && staging.next_height().map_err(|e| e.to_string())? <= after_target =>
            {
                staging
            }
            Ok(staging) => {
                staging.discard().map_err(|error| error.to_string())?;
                if base.header.height == target_height {
                    SnapshotHeaderStaging::create_at_canonical_boundary(&path, store, base)
                } else {
                    SnapshotHeaderStaging::create(&path, store, base)
                }
                .map_err(|error| error.to_string())?
            }
            Err(_) => {
                match std::fs::remove_file(&path) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => {
                        return Err(format!("discard corrupt snapshot header staging: {error}"));
                    }
                }
                if base.header.height == target_height {
                    SnapshotHeaderStaging::create_at_canonical_boundary(&path, store, base)
                } else {
                    SnapshotHeaderStaging::create(&path, store, base)
                }
                .map_err(|error| error.to_string())?
            }
        }
    } else {
        if base.header.height == target_height {
            SnapshotHeaderStaging::create_at_canonical_boundary(&path, store, base)
        } else {
            SnapshotHeaderStaging::create(&path, store, base)
        }
        .map_err(|error| error.to_string())?
    };
    let next_height = staging.next_height().map_err(|error| error.to_string())?;
    Ok(PendingSnapshotHeaderSync {
        from,
        manifest,
        staging,
        next_height,
        target_height,
    })
}

struct VerifiedHistoryStepSnapshot {
    height: u64,
    block_hash: [u8; 32],
    boundary: noid_chain::VerifiedSnapshotBoundary,
    headers: ValidatedSnapshotHeaderStaging,
    allow_nonfinal_rebase: bool,
    /// The exact inbound allocation remains charged until the terminal bytes
    /// have entered the same MDBX transaction as the snapshot state.
    inbound_memory_permit: Option<Arc<tokio::sync::OwnedSemaphorePermit>>,
}

#[derive(Debug)]
enum SnapshotBoundaryVerificationError {
    Terminal(String),
    Other(String),
}

impl std::fmt::Display for SnapshotBoundaryVerificationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Terminal(error) | Self::Other(error) => formatter.write_str(error),
        }
    }
}

#[derive(Debug)]
struct AppliedVerifiedSnapshot {
    height: u64,
    block_hash: [u8; 32],
    tail_blocks: u64,
    tail_bytes: u64,
    tail_apply_elapsed: std::time::Duration,
    state_install_elapsed: std::time::Duration,
}

#[derive(Debug)]
enum SnapshotInstallError {
    BeforeCommit(String),
    AfterCommit {
        applied: AppliedVerifiedSnapshot,
        error: String,
        terminal_rejected: bool,
    },
}

impl std::fmt::Display for SnapshotInstallError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BeforeCommit(error) | Self::AfterCommit { error, .. } => {
                formatter.write_str(error)
            }
        }
    }
}

fn validate_snapshot_staged_header_boundary(
    manifest: &noid_p2p::protocol::GetStateManifestResponse,
    boundary: &SnapshotHeaderBoundary,
) -> Result<(), String> {
    if manifest.tip_height == 0 {
        return Err("snapshot manifest has no tip".into());
    }
    if boundary.tip_header.height != manifest.tip_height || boundary.tip_hash != manifest.tip_hash {
        return Err("snapshot manifest boundary does not match staged header tip".into());
    }
    if boundary.tip_header.log_slots != manifest.log_slots {
        return Err("snapshot manifest log_slots does not match staged header".into());
    }
    if boundary.tip_header.active_slot_count != manifest.active_slot_count {
        return Err("snapshot manifest active_slot_count does not match staged header".into());
    }
    if boundary.tip_header.alloc_counter != manifest.alloc_counter {
        return Err("snapshot manifest alloc_counter does not match staged header".into());
    }
    if boundary.cumulative_chainwork != manifest.cumulative_chainwork {
        return Err("snapshot manifest chainwork does not match staged headers".into());
    }
    let bridge_span = manifest
        .bridge_tip_height
        .checked_sub(manifest.tip_height)
        .ok_or_else(|| "snapshot bridge precedes its boundary".to_string())?;
    if bridge_span > noid_chain::consensus::params::RECENT_BLOCK_RETENTION_DEPTH {
        return Err("snapshot bridge exceeds retained suffix depth".into());
    }
    if bridge_span == 0 {
        if manifest.bridge_tip_hash != manifest.tip_hash
            || manifest.bridge_cumulative_chainwork != manifest.cumulative_chainwork
        {
            return Err("empty snapshot bridge differs from its boundary".into());
        }
    } else if !noid_chain::work_gt(
        &manifest.bridge_cumulative_chainwork,
        &manifest.cumulative_chainwork,
    ) {
        return Err("snapshot bridge does not advance cumulative chainwork".into());
    }
    // A boundary block still consumes the preceding transaction-epoch
    // anchor; its own header becomes active only for the following child.
    let expected_epoch_height =
        noid_chain::consensus::tx_epoch_anchor_height_for_child(manifest.tip_height);
    if boundary.epoch_anchor_header.height != expected_epoch_height {
        return Err("snapshot staged transaction-epoch anchor has wrong height".into());
    }
    Ok(())
}

/// Verify the fused HistoryStep terminal for the exact uncommitted block.
fn verify_history_step_terminal(
    claim: &noid_chain::storage::HistoryStepTerminalClaim<'_>,
    runtime: Option<&noid_recursive::acceptance::history_step::HistoryStepRuntime>,
) -> Result<(), String> {
    let Some(runtime) = runtime else {
        return Err("embedded HistoryStep verifier unavailable".to_string());
    };
    noid_miner::install_inbound_verifier_cpu(|| {
        noid_recursive::acceptance::history_step::decode_verify_history_step_terminal(
            runtime,
            claim.terminal_bytes,
            &claim.header,
            &claim.epoch_anchor_header,
        )
    })
    .map_err(|error| format!("HistoryStep verification CPU admission failed: {error}"))?
    .map(|_| ())
    .map_err(|error| format!("HistoryStep terminal rejected: {error}"))
}

fn history_step_context_error_is_terminal_peer_fault(
    error: &noid_chain::storage::MdbxContextError,
) -> bool {
    match error {
        noid_chain::storage::MdbxContextError::Consensus(
            noid_chain::consensus::ConsensusError::BadHistoryStepTerminal(message),
        ) => {
            message.contains("terminal exceeds the wire cap")
                || message.contains("terminal metadata is invalid")
                || message.contains("terminal does not bind")
                || message.contains("HistoryStep terminal rejected:")
        }
        _ => false,
    }
}

/// Local time admission is checked at the last fixed-width
/// boundary before expensive terminal verification.  Historical header
/// validation is timeless, but a snapshot must not make a locally
/// far-future tip authoritative merely because its recursive proof is valid.
fn validate_history_step_tip_future_drift(
    boundary: &SnapshotHeaderBoundary,
    local_time: u64,
) -> Result<(), String> {
    noid_chain::consensus::validate_future_drift(boundary.tip_header.timestamp, local_time)
        .map_err(|error| format!("HistoryStep target tip exceeds local future drift: {error}"))
}

// ---------------------------------------------------------------------------
// Blocking-I/O helpers
// ---------------------------------------------------------------------------

/// Verify and apply a single P2P block off the tokio executor.
///
/// The fused HistoryStep terminal is verified against the exact block and
/// pre-state before the complete bundle is atomically committed to MDBX.
async fn apply_p2p_block_offthread(
    chain: &Arc<RwLock<MdbxChainContext>>,
    wallet: &SharedWallet,
    candidate: AcceptedBlockCandidate,
    local_time: u64,
    history_step_runtime: Option<Arc<noid_recursive::acceptance::history_step::HistoryStepRuntime>>,
) -> Result<
    AppliedP2pBlock,
    (
        noid_chain::storage::MdbxContextError,
        AcceptedBlockCandidate,
    ),
> {
    let chain = chain.clone();
    let wallet = wallet.clone();
    tokio::task::spawn_blocking(move || {
        let confirmed_tx_hashes =
            match noid_chain::try_compute_logical_txids(&candidate.block.transactions) {
                Ok(txids) => txids,
                Err(_) => {
                    return Err((
                        noid_chain::storage::MdbxContextError::Corrupt(
                            "candidate block has a non-canonical logical tx stream",
                        ),
                        candidate,
                    ));
                }
            };
        let mut ctx = chain.blocking_write();
        let apply_result = ctx.apply_next_block(
            &candidate.bundle,
            local_time,
            |block, state| {
                noid_chain::materialize_accepted_block_state(state, block)
                    .map_err(|error| format!("{error:?}"))
            },
            |claim| verify_history_step_terminal(claim, history_step_runtime.as_deref()),
        );
        match apply_result {
            Ok(_) => {}
            Err(error) => return Err((error, candidate)),
        }
        // Keep the chain writer through the incremental wallet update. This
        // shares the same `chain -> wallet` order as account activation and
        // prevents an exact newer snapshot from receiving this delta twice.
        update_wallet_for_block(&wallet, &candidate.block);
        let height = candidate.block.header.height;
        let view = ChainView::from_mdbx(&ctx);
        drop(ctx);
        let block_hash = candidate.bundle.block_hash();
        // The complete candidate is dropped before this compact success value
        // crosses back to async code.
        Ok(AppliedP2pBlock {
            block_hash,
            height,
            confirmed_tx_hashes,
            view,
        })
    })
    .await
    .expect("apply_p2p_block_offthread panicked in spawn_blocking")
}

/// Apply one exact recent canonical suffix from compact bodies plus a single
/// terminal proof. The recursive terminal authorizes the fixed suffix tip;
/// every body still passes the native parent, header, PoW, epoch,
/// transaction, and state-root checks before its individual MDBX commit.
#[allow(clippy::too_many_arguments)]
async fn apply_compact_suffix_offthread(
    chain: &Arc<RwLock<MdbxChainContext>>,
    mempool: &AsyncMempool,
    wallet: &SharedWallet,
    tail: FinalizedSnapshotTail,
    expected_base_height: u64,
    expected_base_hash: [u8; 32],
    history_step_runtime: Option<Arc<noid_recursive::acceptance::history_step::HistoryStepRuntime>>,
    wallet_operation_gate: &WalletOperationGate,
) -> Result<AppliedCompactSuffix, CompactSuffixApplyError> {
    let _wallet_operation = wallet_operation_gate.lock().await;
    let apply_chain = Arc::clone(chain);
    let apply_wallet = Arc::clone(wallet);
    let result = tokio::task::spawn_blocking(
        move || -> Result<AppliedCompactSuffix, CompactSuffixApplyError> {
            let expected_blocks = tail.block_count();
            let payload_bytes = tail.payload_bytes();
            let mut tail = tail;
            let mut ctx = apply_chain.blocking_write();
            if ctx.tip_height() != expected_base_height || ctx.tip_hash() != expected_base_hash {
                return Err("compact suffix base changed before atomic admission"
                    .to_owned()
                    .into());
            }
            if tail.boundary_height() != expected_base_height
                || tail.boundary_hash() != expected_base_hash
            {
                return Err("compact suffix staging is bound to another base"
                    .to_owned()
                    .into());
            }

            let tip_header = tail.tip_header()?;
            let epoch_height =
                noid_chain::consensus::tx_epoch_anchor_height_for_child(tip_header.height);
            let epoch_anchor_header = if epoch_height <= ctx.tip_height() {
                ctx.get_header_from_store(epoch_height)
                    .map_err(|error| format!("load compact suffix epoch anchor: {error}"))?
                    .ok_or_else(|| "compact suffix epoch anchor is missing".to_owned())?
            } else {
                tail.header_at(epoch_height)?.ok_or_else(|| {
                    "compact suffix epoch anchor is absent from staged bodies".to_owned()
                })?
            };
            let terminal_bytes = tail.take_terminal_bytes();
            let mut authority = ctx
                .verify_recursive_suffix(tip_header, epoch_anchor_header, terminal_bytes, |claim| {
                    verify_history_step_terminal(claim, history_step_runtime.as_deref())
                })
                .map_err(|error| {
                    let message = format!("verify compact suffix terminal: {error}");
                    if history_step_context_error_is_terminal_peer_fault(&error) {
                        CompactSuffixApplyError::Terminal(message)
                    } else {
                        CompactSuffixApplyError::Other(message)
                    }
                })?;

            let started = Instant::now();
            let mut confirmed_tx_hashes = Vec::new();
            let mut applied_blocks = 0u64;
            let mut trailing_error = None;
            let mut reader = tail.reader()?;
            loop {
                let block_bytes = match reader.next_block() {
                    Ok(Some(bytes)) => bytes,
                    Ok(None) => break,
                    Err(error) => {
                        trailing_error = Some(error);
                        break;
                    }
                };
                let block = match noid_chain::Block::from_bytes(&block_bytes) {
                    Ok(block) => block,
                    Err(error) => {
                        trailing_error = Some(format!("decode compact suffix block: {error:?}"));
                        break;
                    }
                };
                let txids = match noid_chain::try_compute_logical_txids(&block.transactions) {
                    Ok(txids) => txids,
                    Err(error) => {
                        trailing_error = Some(format!(
                            "compact suffix logical transaction stream: {error}"
                        ));
                        break;
                    }
                };
                if let Err(error) = ctx.apply_verified_recursive_suffix_block(
                    &mut authority,
                    &block_bytes,
                    unix_now(),
                    |block, state| {
                        noid_chain::materialize_accepted_block_state(state, block)
                            .map_err(|error| format!("{error:?}"))
                    },
                ) {
                    trailing_error = Some(format!(
                        "apply compact suffix block {}: {error}",
                        block.header.height
                    ));
                    break;
                }
                update_wallet_for_block(&apply_wallet, &block);
                confirmed_tx_hashes.extend(txids);
                applied_blocks = applied_blocks.saturating_add(1);
            }
            if trailing_error.is_none() && !authority.is_complete() {
                trailing_error = Some("compact suffix ended before its verified tip".to_owned());
            }
            if trailing_error.is_none() && applied_blocks != expected_blocks {
                trailing_error = Some("compact suffix applied an unexpected body count".to_owned());
            }
            let view = ChainView::from_mdbx(&ctx);
            let height = ctx.tip_height();
            let block_hash = ctx.tip_hash();
            drop(ctx);
            drop(tail);
            Ok(AppliedCompactSuffix {
                height,
                block_hash,
                confirmed_tx_hashes,
                view,
                applied_blocks,
                payload_bytes,
                apply_elapsed: started.elapsed(),
                trailing_error,
            })
        },
    )
    .await
    .map_err(|error| {
        CompactSuffixApplyError::Other(format!("compact suffix worker panicked: {error}"))
    })??;

    if result.applied_blocks != 0 {
        mempool
            .on_new_block(
                &result.confirmed_tx_hashes,
                result.height,
                result.view.clone(),
            )
            .await;
    }
    Ok(result)
}

/// Apply a chain reorg off the tokio executor.  Same `fsync` rationale.
///
/// The owned replacement payloads are retained only on failure.  On success
/// they are dropped on the blocking worker and only compact mempool metadata
/// crosses back to async code.
#[allow(clippy::too_many_arguments)]
async fn apply_reorg_offthread(
    chain: &Arc<RwLock<MdbxChainContext>>,
    wallet: &SharedWallet,
    reserved_input_slots: std::collections::HashSet<u32>,
    reserved_output_slots: std::collections::HashSet<u32>,
    ancestor_height: u64,
    new_blocks: Vec<AcceptedBlockCandidate>,
    local_time: u64,
    history_step_runtime: Option<Arc<noid_recursive::acceptance::history_step::HistoryStepRuntime>>,
) -> Result<
    AppliedReorg,
    (
        noid_chain::storage::MdbxContextError,
        Vec<AcceptedBlockCandidate>,
    ),
> {
    let chain = chain.clone();
    let wallet = wallet.clone();
    tokio::task::spawn_blocking(move || {
        let mut ctx = chain.blocking_write();
        if ancestor_height > ctx.tip_height() {
            return Err((
                noid_chain::storage::MdbxContextError::Consensus(
                    noid_chain::consensus::ConsensusError::BadParentHash,
                ),
                new_blocks,
            ));
        }
        let ancestor_header = match ctx.get_header_from_store(ancestor_height) {
            Ok(Some(header)) => header,
            Ok(None) => {
                return Err((
                    noid_chain::storage::MdbxContextError::Corrupt(
                        "reorg ancestor header is missing before atomic admission",
                    ),
                    new_blocks,
                ));
            }
            Err(error) => return Err((error.into(), new_blocks)),
        };
        let mut candidate_work = match ctx.store.get_chain_work(ancestor_height) {
            Ok(Some(work)) => work,
            Ok(None) => {
                return Err((
                    noid_chain::storage::MdbxContextError::Corrupt(
                        "reorg ancestor chainwork is missing before atomic admission",
                    ),
                    new_blocks,
                ));
            }
            Err(error) => return Err((error.into(), new_blocks)),
        };
        let mut expected_height = ancestor_height.saturating_add(1);
        let mut expected_parent = noid_chain::consensus::pow::block_id(&ancestor_header);
        for candidate in &new_blocks {
            if candidate.block.header.height != expected_height
                || candidate.block.header.prev_block_hash != expected_parent
            {
                return Err((
                    noid_chain::storage::MdbxContextError::Consensus(
                        noid_chain::consensus::ConsensusError::BadParentHash,
                    ),
                    new_blocks,
                ));
            }
            expected_parent = noid_chain::consensus::pow::block_id(&candidate.block.header);
            candidate_work = noid_chain::consensus::add_work(
                &candidate_work,
                &noid_chain::consensus::block_work(
                    &candidate.block.header.difficulty_target,
                ),
            );
            expected_height = expected_height.saturating_add(1);
        }
        if new_blocks.is_empty()
            || !competing_suffix_wins(
                &candidate_work,
                &expected_parent,
                ctx.tip_chain_work(),
                &ctx.tip_hash(),
            )
        {
            // The selected branch may have stopped winning while the async
            // caller waited for the chain write lock. Refuse before undo or
            // durable state mutation; a later authenticated probe can choose
            // the now-current branch again.
            return Err((
                noid_chain::storage::MdbxContextError::Consensus(
                    noid_chain::consensus::ConsensusError::BadParentHash,
                ),
                new_blocks,
            ));
        }
        let mut replacement_blocks = Vec::with_capacity(new_blocks.len());
        let mut replacement_bundles = Vec::with_capacity(new_blocks.len());
        for candidate in new_blocks {
            replacement_blocks.push(candidate.block);
            replacement_bundles.push(candidate.bundle);
        }
        let result = ctx.apply_reorg_mdbx_with_applier(
            ancestor_height,
            &replacement_bundles,
            local_time,
            |ctx, bundle, block_local_time| {
                let history_step_runtime = history_step_runtime.clone();
                ctx.apply_next_block(
                    bundle,
                    block_local_time,
                    |block, state| {
                        noid_chain::materialize_accepted_block_state(state, block)
                            .map_err(|error| format!("{error:?}"))
                    },
                    |claim| {
                        verify_history_step_terminal(claim, history_step_runtime.as_deref())
                    },
                )?;
                Ok(())
            },
        );
        match result {
            Ok(reorg) => {
                let selection = match wallet.lock() {
                    Ok(guard) => guard
                        .as_ref()
                        .map(|wallet| (wallet.active_index, wallet.next_index, wallet.active_address().0)),
                    Err(_) => {
                        tracing::error!("wallet state lock poisoned after committed reorg");
                        None
                    }
                };
                if let Some((active_index, next_index, owner)) = selection {
                    match ctx.store.get_verified_utxos_by_owner(&owner) {
                        Ok(snapshot) => {
                            let replacement_block_refs: Vec<_> =
                                replacement_blocks.iter().collect();
                            if let Err(error) = wallet::install_reorg_snapshot_and_artifacts(
                                &wallet,
                                active_index,
                                next_index,
                                owner,
                                snapshot,
                                &reserved_input_slots,
                                &reserved_output_slots,
                                &reorg.reclaimed_tx_hashes,
                                &replacement_block_refs,
                            ) {
                                tracing::error!(%error, "post-reorg wallet snapshot install failed");
                                wallet::invalidate_active_cache(&wallet);
                            }
                        }
                        Err(error) => {
                            tracing::error!(%error, "post-reorg owner lookup failed");
                            wallet::invalidate_active_cache(&wallet);
                        }
                    }
                }
                let confirmed_tx_hashes = replacement_blocks
                    .iter()
                    .flat_map(|block| {
                        noid_chain::try_compute_logical_txids(&block.transactions)
                            .expect("committed reorg blocks have canonical logical tx streams")
                    })
                    .collect();
                let view = ChainView::from_mdbx(&ctx);
                Ok(AppliedReorg {
                    result: reorg,
                    confirmed_tx_hashes,
                    view,
                })
            }
            Err(error) => {
                let rejected = replacement_blocks
                    .into_iter()
                    .zip(replacement_bundles)
                    .map(|(block, bundle)| AcceptedBlockCandidate { block, bundle })
                    .collect();
                Err((error, rejected))
            }
        }
    })
    .await
    .expect("apply_reorg_mdbx panicked in spawn_blocking")
}

fn state_segment_response_matches_snapshot_boundary(
    response_tip_height: u64,
    response_tip_hash: [u8; 32],
    expected_tip_height: u64,
    expected_tip_hash: [u8; 32],
) -> bool {
    response_tip_height == expected_tip_height && response_tip_hash == expected_tip_hash
}

#[cfg(test)]
mod tests {
    use super::{
        admit_snapshot_segment_response, apply_reorg_offthread, authenticated_height_after_reorg,
        chain_data_epoch_is_current, compact_apply_signals, compact_suffix_eligible,
        competing_suffix_tip, competing_suffix_wins, gap_requires_snapshot_sync,
        header_batch_exhausts_nonfinal_window, initial_sync_may_skip_peer_confirmation,
        load_or_create_config, manifest_candidate_selection_due, manifest_round_gap_is_resolved,
        manifest_round_retry_due, mark_initial_sync_ready, mining_quorum_probe_due,
        next_block_has_competing_parent, nonfinal_header_discovery_range, p2p_listen_to_multiaddr,
        persist_chain_data_epoch_marker, prune_superseded_snapshot_header_staging,
        rotating_manifest_peers, seed_to_multiaddr, shallow_fork_progress_deadline_due,
        snapshot_bridge_requires_tail, snapshot_header_next_action,
        snapshot_parent_mismatch_is_at_base, snapshot_segment_request_capacity,
        state_manifest_candidate_is_preferred, state_segment_response_matches_snapshot_boundary,
        steady_tip_probe_due, terminal_alternate_peer, terminal_transport_can_retry_same_peer,
        unavailable_block_requires_snapshot, validate_history_step_tip_future_drift,
        validate_snapshot_header_batch_admission, validate_snapshot_staged_header_boundary,
        AcceptedBlockCandidate, MiningPeerQuorum, NodeConfig, SnapshotHeaderBoundary,
        SnapshotHeaderNextAction, SnapshotHeaderPipeline, SnapshotHeaderStagingError,
        SnapshotSegmentResponseAdmission, TerminalRequestRace, CONNECTED_TIP_PROBE_HEADERS,
        HISTORY_STEP_TERMINAL_HARD_DEADLINE, HISTORY_STEP_TERMINAL_HEDGE_AFTER,
        MINING_PEER_CONFIRMATION_TTL, MINING_PEER_QUORUM, MINING_QUORUM_PROBE_INTERVAL,
        SHALLOW_FORK_NO_PROGRESS_TIMEOUT, SNAPSHOT_HEADER_BATCH, SNAPSHOT_HEADER_REQUEST_WINDOW,
        STATE_MANIFEST_CANDIDATE_SETTLE, STATE_MANIFEST_RESPONSE_TIMEOUT,
        STEADY_TIP_PROBE_INTERVAL,
    };

    #[test]
    fn chain_data_epoch_marker_requires_exact_durable_value() {
        let directory = tempfile::tempdir().unwrap();
        assert!(!chain_data_epoch_is_current(directory.path()).unwrap());

        persist_chain_data_epoch_marker(directory.path()).unwrap();
        assert!(chain_data_epoch_is_current(directory.path()).unwrap());

        std::fs::write(directory.path().join(".chain-data-epoch"), b"incomplete").unwrap();
        assert!(!chain_data_epoch_is_current(directory.path()).unwrap());
    }

    #[test]
    fn initial_sync_readiness_is_durable_for_all_subscribers() {
        let (sender, first) = tokio::sync::watch::channel(false);
        let second = sender.subscribe();
        mark_initial_sync_ready(&sender);
        let late = sender.subscribe();

        assert!(*first.borrow());
        assert!(*second.borrow());
        assert!(*late.borrow());
    }

    #[test]
    fn durable_tip_needs_peer_confirmation_outside_genesis_mode() {
        assert!(!initial_sync_may_skip_peer_confirmation(false));
        assert!(initial_sync_may_skip_peer_confirmation(true));
    }

    #[test]
    fn history_step_terminal_failover_keeps_both_exact_requests_correlated() {
        let primary = libp2p::PeerId::random();
        let alternate = libp2p::PeerId::random();
        let mut requests = TerminalRequestRace::new(primary, 41);

        requests.install_hedge(alternate);
        assert!(requests.matches(primary, 41));
        assert!(requests.matches(alternate, 41));

        assert!(requests.mark_failed(primary, 41));
        assert!(requests.has_active());
        assert!(requests.matches(alternate, 41));
        assert!(requests.mark_failed(alternate, 41));
        assert!(!requests.has_active());

        let mut successful = TerminalRequestRace::new(primary, 42);
        successful.install_hedge(alternate);
        assert!(successful.mark_succeeded(primary, 42));
        assert!(!successful.has_active());
        assert!(!successful.matches(alternate, 42));
    }

    #[test]
    fn history_step_terminal_hedge_uses_one_distinct_connected_peer() {
        let primary = libp2p::PeerId::random();
        let alternate = libp2p::PeerId::random();
        let third = libp2p::PeerId::random();
        let mut peers = std::collections::HashSet::from([primary, alternate, third]);
        let mut requests = TerminalRequestRace::new(primary, 1);

        let rejected = std::collections::HashSet::new();
        let selected = terminal_alternate_peer(&peers, &rejected, &requests)
            .expect("one alternate must be selected");
        assert_ne!(selected, primary);
        requests.install_hedge(selected);
        assert_eq!(
            terminal_alternate_peer(&peers, &rejected, &requests),
            Some(if selected == alternate {
                third
            } else {
                alternate
            })
        );

        peers.retain(|peer| requests.used_peer(*peer));
        assert_eq!(terminal_alternate_peer(&peers, &rejected, &requests), None);
    }

    #[test]
    fn history_step_terminal_hedge_has_a_node_local_deadline() {
        let primary = libp2p::PeerId::random();
        let alternate = libp2p::PeerId::random();
        let mut requests = TerminalRequestRace::new(primary, 7);

        assert!(!requests.hedge_due(
            requests.started_at + HISTORY_STEP_TERMINAL_HEDGE_AFTER
                - std::time::Duration::from_millis(1)
        ));
        assert!(requests.hedge_due(requests.started_at + HISTORY_STEP_TERMINAL_HEDGE_AFTER));

        requests.install_hedge(alternate);
        assert!(!requests.hedge_due(requests.started_at + HISTORY_STEP_TERMINAL_HEDGE_AFTER));
        assert!(!requests.deadline_due(
            requests.started_at + HISTORY_STEP_TERMINAL_HARD_DEADLINE
                - std::time::Duration::from_millis(1)
        ));
        assert!(requests.deadline_due(requests.started_at + HISTORY_STEP_TERMINAL_HARD_DEADLINE));
        assert!(requests.mark_succeeded(primary, 7));
        assert!(!requests.deadline_due(requests.started_at + HISTORY_STEP_TERMINAL_HARD_DEADLINE));
    }

    #[test]
    fn only_transient_terminal_transport_failures_retry_the_same_peer() {
        use noid_p2p::RequestFailureKind;

        assert!(terminal_transport_can_retry_same_peer(
            RequestFailureKind::Timeout
        ));
        assert!(terminal_transport_can_retry_same_peer(
            RequestFailureKind::Io
        ));
        assert!(!terminal_transport_can_retry_same_peer(
            RequestFailureKind::ConnectionClosed
        ));
        assert!(!terminal_transport_can_retry_same_peer(
            RequestFailureKind::Dial
        ));
        assert!(!terminal_transport_can_retry_same_peer(
            RequestFailureKind::UnsupportedProtocol
        ));
        assert!(!terminal_transport_can_retry_same_peer(
            RequestFailureKind::InvalidResponse
        ));
    }

    #[test]
    fn mining_quorum_counts_two_confirmed_ordinary_peers() {
        let (ready_tx, ready_rx) = tokio::sync::watch::channel(false);
        let (count_tx, count_rx) = tokio::sync::watch::channel(0usize);
        let mut quorum = MiningPeerQuorum::new(false, ready_tx, count_tx);
        let first = libp2p::PeerId::random();
        let second = libp2p::PeerId::random();
        let height = 17;
        let hash = [0x17; 32];

        quorum.set_canonical_tip(height, hash);
        quorum.connect(first);
        quorum.connect(second);
        assert_eq!(quorum.probe_candidates(MINING_PEER_QUORUM).len(), 2);
        assert_eq!(*count_rx.borrow(), 0);
        assert!(!*ready_rx.borrow());

        quorum.confirm_tip(first, height, hash);
        assert_eq!(*count_rx.borrow(), 1);
        assert!(!*ready_rx.borrow());

        quorum.confirm_tip(second, height, hash);
        assert_eq!(*count_rx.borrow(), MINING_PEER_QUORUM);
        assert!(*ready_rx.borrow());

        quorum.disconnect(first);
        assert_eq!(*count_rx.borrow(), 1);
        assert!(!*ready_rx.borrow());

        quorum.confirm_tip(first, height, hash);
        assert_eq!(
            *count_rx.borrow(),
            1,
            "a delayed result cannot resurrect a disconnected peer"
        );
        assert!(!*ready_rx.borrow());
    }

    #[test]
    fn mining_quorum_expires_stale_tip_authority() {
        let (ready_tx, ready_rx) = tokio::sync::watch::channel(false);
        let (count_tx, count_rx) = tokio::sync::watch::channel(0usize);
        let mut quorum = MiningPeerQuorum::new(false, ready_tx, count_tx);
        let first = libp2p::PeerId::random();
        let second = libp2p::PeerId::random();
        let confirmed_at = std::time::Instant::now();
        let height = 23;
        let hash = [0x23; 32];

        quorum.set_canonical_tip(height, hash);
        quorum.connect(first);
        quorum.connect(second);
        quorum.confirm_tip_at(first, height, hash, confirmed_at);
        quorum.confirm_tip_at(second, height, hash, confirmed_at);
        assert!(*ready_rx.borrow());

        quorum.expire_stale(
            confirmed_at + MINING_PEER_CONFIRMATION_TTL - std::time::Duration::from_millis(1),
        );
        assert_eq!(*count_rx.borrow(), MINING_PEER_QUORUM);
        assert!(*ready_rx.borrow());

        quorum.expire_stale(confirmed_at + MINING_PEER_CONFIRMATION_TTL);
        assert_eq!(*count_rx.borrow(), 0);
        assert!(!*ready_rx.borrow());
        assert_eq!(quorum.probe_candidates(MINING_PEER_QUORUM).len(), 2);
    }

    #[test]
    fn mining_quorum_reacquisition_prioritizes_unconfirmed_public_peers() {
        let (ready_tx, _ready_rx) = tokio::sync::watch::channel(false);
        let (count_tx, _count_rx) = tokio::sync::watch::channel(0usize);
        let mut quorum = MiningPeerQuorum::new(false, ready_tx, count_tx);
        let peers = (0..64)
            .map(|_| libp2p::PeerId::random())
            .collect::<Vec<_>>();
        for peer in &peers {
            quorum.connect(*peer);
        }
        let height = 31;
        let hash = [0x31; 32];
        quorum.set_canonical_tip(height, hash);
        assert_eq!(quorum.probe_candidates(MINING_PEER_QUORUM).len(), 2);

        quorum.confirm_tip(peers[0], height, hash);
        quorum.confirm_tip(peers[1], height, hash);
        let candidates = quorum.probe_candidates(MINING_PEER_QUORUM);
        assert_eq!(candidates.len(), 2);
        assert!(!candidates.contains(&peers[0]));
        assert!(!candidates.contains(&peers[1]));
    }

    #[test]
    fn mining_quorum_rotates_unconfirmed_probe_lanes() {
        let (ready_tx, _ready_rx) = tokio::sync::watch::channel(false);
        let (count_tx, _count_rx) = tokio::sync::watch::channel(0usize);
        let mut quorum = MiningPeerQuorum::new(false, ready_tx, count_tx);
        let peers = (0..6).map(|_| libp2p::PeerId::random()).collect::<Vec<_>>();
        for peer in &peers {
            quorum.connect(*peer);
        }

        let first = quorum.probe_candidates(MINING_PEER_QUORUM);
        assert_eq!(first.len(), MINING_PEER_QUORUM);
        let attempted_at = std::time::Instant::now();
        for peer in &first {
            quorum.mark_probe_sent(*peer, attempted_at);
        }
        let second = quorum.probe_candidates(MINING_PEER_QUORUM);
        assert_eq!(second.len(), MINING_PEER_QUORUM);
        assert!(first.iter().all(|peer| !second.contains(peer)));

        assert!(MINING_QUORUM_PROBE_INTERVAL < MINING_PEER_CONFIRMATION_TTL);
    }

    #[test]
    fn mining_quorum_is_bound_to_the_exact_current_tip() {
        let (ready_tx, ready_rx) = tokio::sync::watch::channel(false);
        let (count_tx, count_rx) = tokio::sync::watch::channel(0usize);
        let mut quorum = MiningPeerQuorum::new(false, ready_tx, count_tx);
        let first = libp2p::PeerId::random();
        let second = libp2p::PeerId::random();
        quorum.connect(first);
        quorum.connect(second);

        quorum.set_canonical_tip(40, [0x40; 32]);
        quorum.confirm_tip(first, 40, [0x40; 32]);
        quorum.confirm_tip(second, 40, [0x40; 32]);
        assert!(*ready_rx.borrow());

        quorum.set_canonical_tip(41, [0x41; 32]);
        assert_eq!(*count_rx.borrow(), 0);
        assert!(!*ready_rx.borrow());

        // Delayed old-tip responses cannot resurrect the mining gate.
        quorum.confirm_tip(first, 40, [0x40; 32]);
        quorum.confirm_tip(second, 40, [0x40; 32]);
        assert_eq!(*count_rx.borrow(), 0);
        assert!(!*ready_rx.borrow());

        quorum.confirm_tip(first, 41, [0x41; 32]);
        quorum.confirm_tip(second, 41, [0x41; 32]);
        assert!(*ready_rx.borrow());
    }

    #[test]
    fn isolated_mining_bypasses_peer_quorum_at_any_height() {
        let (ready_tx, ready_rx) = tokio::sync::watch::channel(false);
        let (count_tx, count_rx) = tokio::sync::watch::channel(0usize);
        let _quorum = MiningPeerQuorum::new(true, ready_tx, count_tx);

        assert_eq!(*count_rx.borrow(), 0);
        assert!(*ready_rx.borrow());
    }

    #[test]
    fn p2p_listener_accepts_socket_and_multiaddr_forms() {
        assert_eq!(
            p2p_listen_to_multiaddr("0.0.0.0:9400").unwrap().to_string(),
            "/ip4/0.0.0.0/tcp/9400"
        );
        assert_eq!(
            p2p_listen_to_multiaddr("/ip4/0.0.0.0/tcp/9400")
                .unwrap()
                .to_string(),
            "/ip4/0.0.0.0/tcp/9400"
        );
    }

    #[test]
    fn seed_parser_accepts_gui_and_operator_forms_without_losing_peer_id() {
        let peer = libp2p::PeerId::random();
        assert_eq!(
            seed_to_multiaddr("seed.example:9400", 9400)
                .unwrap()
                .to_string(),
            "/dns/seed.example/tcp/9400"
        );
        assert_eq!(
            seed_to_multiaddr("203.0.113.10:9400", 9400)
                .unwrap()
                .to_string(),
            "/ip4/203.0.113.10/tcp/9400"
        );
        assert_eq!(
            seed_to_multiaddr("[2001:db8::10]:9400", 9400)
                .unwrap()
                .to_string(),
            "/ip6/2001:db8::10/tcp/9400"
        );
        assert_eq!(
            seed_to_multiaddr("dnsaddr:example.net", 9400)
                .unwrap()
                .to_string(),
            "/dnsaddr/example.net"
        );
        let explicit = format!("/ip4/203.0.113.10/tcp/9400/p2p/{peer}");
        assert_eq!(
            seed_to_multiaddr(&explicit, 9400).unwrap().to_string(),
            explicit
        );
    }

    #[test]
    fn snapshot_header_failover_keeps_only_the_exact_candidate_file() {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("headers");
        std::fs::create_dir(&directory).unwrap();
        let keep = directory.join("current.stage");
        let stale_a = directory.join("old-a.stage");
        let stale_b = directory.join("old-b.stage");
        let unrelated = directory.join("README");
        for path in [&keep, &stale_a, &stale_b, &unrelated] {
            std::fs::write(path, b"bounded test artifact").unwrap();
        }

        prune_superseded_snapshot_header_staging(&directory, &keep).unwrap();

        assert!(keep.exists());
        assert!(!stale_a.exists());
        assert!(!stale_b.exists());
        assert!(unrelated.exists());
    }

    #[test]
    fn first_start_creates_and_reuses_default_config() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("nested/parano1d.toml");
        let mut defaults = NodeConfig::default();
        defaults.network.listen = Some("0.0.0.0:9400".into());
        defaults.rpc.listen = Some("127.0.0.1:9401".into());

        let (created_config, created) = load_or_create_config(&path, &defaults).unwrap();
        assert!(created);
        assert_eq!(created_config.network.listen, defaults.network.listen);
        assert!(path.is_file());

        let original = std::fs::read(&path).unwrap();
        let (loaded_config, created_again) = load_or_create_config(&path, &defaults).unwrap();
        assert!(!created_again);
        assert_eq!(loaded_config.network.listen, defaults.network.listen);
        assert_eq!(std::fs::read(&path).unwrap(), original);
    }

    #[test]
    fn malformed_config_is_reported_instead_of_silently_ignored() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("parano1d.toml");
        std::fs::write(&path, "[network\n").unwrap();

        let error = load_or_create_config(&path, &NodeConfig::default()).unwrap_err();
        assert!(error.to_string().contains("parse node config"));
    }

    #[test]
    fn snapshot_segment_rejects_delayed_same_peer_cross_session_boundary() {
        assert!(state_segment_response_matches_snapshot_boundary(
            144, [0xA5; 32], 144, [0xA5; 32]
        ));
        assert!(!state_segment_response_matches_snapshot_boundary(
            144, [0xA5; 32], 145, [0xA5; 32]
        ));
        assert!(!state_segment_response_matches_snapshot_boundary(
            144, [0xA5; 32], 144, [0x5A; 32]
        ));
    }

    #[test]
    fn sync_mode_uses_retained_block_window_boundary() {
        let retention = noid_chain::consensus::params::RECENT_BLOCK_RETENTION_DEPTH;
        assert_eq!(
            retention, 18,
            "consensus retained full-block window is 18 blocks"
        );
        let local_height = 100;

        assert!(!gap_requires_snapshot_sync(local_height, local_height));
        assert!(!gap_requires_snapshot_sync(local_height, local_height + 17));
        assert!(!gap_requires_snapshot_sync(local_height, local_height + 18));
        assert!(gap_requires_snapshot_sync(local_height, local_height + 19));
    }

    #[test]
    fn serving_reserve_does_not_change_finality_or_snapshot_suffix() {
        assert_eq!(noid_chain::consensus::params::CONSENSUS_FINALITY_DEPTH, 18);
        assert_eq!(
            noid_chain::consensus::params::RECENT_BLOCK_RETENTION_DEPTH,
            18
        );
        assert_eq!(
            noid_chain::consensus::params::RETAINED_BLOCK_SERVING_DEPTH,
            42
        );
    }

    #[test]
    fn fork_choice_is_work_first_and_uses_the_canonical_hash_tie_break() {
        let less = [1u8; 32];
        let more = [2u8; 32];
        let smaller_hash = [0x11; 32];
        let larger_hash = [0x22; 32];
        assert!(competing_suffix_wins(
            &more,
            &larger_hash,
            &less,
            &smaller_hash,
        ));
        assert!(!competing_suffix_wins(
            &less,
            &smaller_hash,
            &more,
            &larger_hash,
        ));
        assert!(competing_suffix_wins(
            &more,
            &smaller_hash,
            &more,
            &larger_hash,
        ));
        assert!(!competing_suffix_wins(
            &more,
            &larger_hash,
            &more,
            &smaller_hash,
        ));
        assert!(!competing_suffix_wins(
            &more,
            &smaller_hash,
            &more,
            &smaller_hash,
        ));
    }

    #[test]
    fn an_empty_suffix_from_a_shorter_canonical_peer_is_not_a_fork_candidate() {
        assert_eq!(competing_suffix_tip(&[]), None);

        let mut header = noid_chain::consensus::genesis::genesis_header();
        header.height = 7;
        assert_eq!(
            competing_suffix_tip(&[header]),
            Some((7, noid_chain::consensus::pow::block_id(&header)))
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reorg_admission_rechecks_the_tip_after_waiting_for_the_write_lock() {
        let directory = tempfile::tempdir().unwrap();
        let context =
            noid_chain::storage::MdbxChainContext::open_or_create(directory.path()).unwrap();
        let genesis = *context.tip_header();
        let genesis_hash = noid_chain::consensus::pow::block_id(&genesis);
        let mut candidate_header = genesis;
        candidate_header.height = 1;
        candidate_header.prev_block_hash = genesis_hash;
        candidate_header.timestamp = genesis.timestamp.saturating_add(1);
        candidate_header.tx_root[0] ^= 0xA5;
        candidate_header.difficulty_target = [0xFF; 32];
        let candidate_block = noid_chain::Block {
            header: candidate_header,
            transactions: Vec::new(),
        };
        let mut terminal = noid_chain::history_step::HistoryStepTerminalMetadata::new(
            candidate_header.height,
            noid_chain::block_header::semantic_header_id(&candidate_header),
            0,
        )
        .unwrap()
        .encode_prefix()
        .to_vec();
        terminal.push(0xA5);
        let bundle =
            noid_chain::AcceptedBlockBundle::try_from_parts(candidate_block.to_bytes(), terminal)
                .unwrap();
        let candidate = AcceptedBlockCandidate::from_bundle(bundle);
        let candidate_total_work = noid_chain::consensus::add_work(
            context.tip_chain_work(),
            &noid_chain::consensus::block_work(&candidate_header.difficulty_target),
        );

        let chain = std::sync::Arc::new(tokio::sync::RwLock::new(context));
        let wallet: crate::wallet::SharedWallet = std::sync::Arc::new(std::sync::Mutex::new(None));

        // The branch wins against genesis when selected. Hold the write lock
        // so the blocking admission worker cannot observe the chain until its
        // tip has advanced to a strictly heavier competing view.
        let mut current = chain.write().await;
        let task_chain = std::sync::Arc::clone(&chain);
        let task_wallet = std::sync::Arc::clone(&wallet);
        let task = tokio::spawn(async move {
            apply_reorg_offthread(
                &task_chain,
                &task_wallet,
                std::collections::HashSet::new(),
                std::collections::HashSet::new(),
                0,
                vec![candidate],
                candidate_header.timestamp,
                None,
            )
            .await
        });
        tokio::task::yield_now().await;
        current.tip_height = 1;
        current.tip_hash = [0xEE; 32];
        current.tip_chain_work = noid_chain::consensus::add_work(
            &candidate_total_work,
            &noid_chain::consensus::block_work(&candidate_header.difficulty_target),
        );
        drop(current);

        let result = tokio::time::timeout(std::time::Duration::from_secs(5), task)
            .await
            .expect("reorg admission must not stall")
            .expect("reorg admission task must not panic");
        assert!(matches!(
            result,
            Err((
                noid_chain::storage::MdbxContextError::Consensus(
                    noid_chain::consensus::ConsensusError::BadParentHash
                ),
                rejected
            )) if rejected.len() == 1
        ));
    }

    #[test]
    fn shorter_peer_discovery_reads_only_the_complete_nonfinal_window() {
        assert_eq!(nonfinal_header_discovery_range(100), Some((82, 19)));
        assert_eq!(nonfinal_header_discovery_range(10), Some((0, 11)));
        assert_eq!(nonfinal_header_discovery_range(0), None);
    }

    #[test]
    fn accepted_shorter_work_reorg_retires_losing_height_hint() {
        assert_eq!(authenticated_height_after_reorg(120, 100, 99), 99);
        assert_eq!(authenticated_height_after_reorg(120, 100, 100), 100);
        assert_eq!(authenticated_height_after_reorg(120, 100, 101), 120);
        assert_eq!(authenticated_height_after_reorg(100, 100, 101), 101);
    }

    #[test]
    fn steady_tip_probe_survives_completed_mining_quorum() {
        let started = std::time::Instant::now();
        assert!(!steady_tip_probe_due(
            started,
            started + STEADY_TIP_PROBE_INTERVAL,
            true,
            true,
        ));
        assert!(!steady_tip_probe_due(
            started,
            started + STEADY_TIP_PROBE_INTERVAL,
            false,
            false,
        ));
        assert!(!steady_tip_probe_due(
            started,
            started + STEADY_TIP_PROBE_INTERVAL - std::time::Duration::from_millis(1),
            false,
            true,
        ));
        assert!(steady_tip_probe_due(
            started,
            started + STEADY_TIP_PROBE_INTERVAL,
            false,
            true,
        ));
    }

    #[test]
    fn mining_quorum_refresh_stays_off_the_canonical_sync_path() {
        let started = std::time::Instant::now();
        assert!(!mining_quorum_probe_due(
            started,
            started + MINING_QUORUM_PROBE_INTERVAL,
            true,
            false,
        ));
        assert!(!mining_quorum_probe_due(
            started,
            started + MINING_QUORUM_PROBE_INTERVAL - std::time::Duration::from_millis(1),
            true,
            true,
        ));
        assert!(!mining_quorum_probe_due(
            started,
            started + MINING_QUORUM_PROBE_INTERVAL,
            false,
            true,
        ));
        assert!(mining_quorum_probe_due(
            started,
            started + MINING_QUORUM_PROBE_INTERVAL,
            true,
            true,
        ));
    }

    #[test]
    fn shallow_fork_deadline_tracks_exact_bundle_progress() {
        let started = std::time::Instant::now();
        assert!(!shallow_fork_progress_deadline_due(
            started,
            started + SHALLOW_FORK_NO_PROGRESS_TIMEOUT - std::time::Duration::from_millis(1),
        ));
        assert!(shallow_fork_progress_deadline_due(
            started,
            started + SHALLOW_FORK_NO_PROGRESS_TIMEOUT,
        ));

        let progressed = started + std::time::Duration::from_secs(30);
        assert!(!shallow_fork_progress_deadline_due(
            progressed,
            started + SHALLOW_FORK_NO_PROGRESS_TIMEOUT,
        ));
    }

    #[test]
    fn exact_recent_extensions_use_one_compact_suffix_terminal() {
        let local = 100;
        assert!(!compact_suffix_eligible(local, local, local + 1));
        assert!(compact_suffix_eligible(local, local, local + 2));
        assert!(compact_suffix_eligible(local, local, local + 18));
        assert!(!compact_suffix_eligible(local, local, local + 19));
        assert!(!compact_suffix_eligible(local, local - 1, local + 2));
    }

    #[test]
    fn compact_suffix_signals_only_real_and_complete_progress() {
        assert_eq!(compact_apply_signals(0, 100, 102, true), (false, false));
        assert_eq!(compact_apply_signals(1, 101, 102, true), (true, false));
        assert_eq!(compact_apply_signals(2, 102, 102, false), (true, true));
        assert_eq!(compact_apply_signals(2, 101, 102, false), (true, false));
    }

    #[test]
    fn connected_tip_probe_covers_only_the_retained_decision_window() {
        assert_eq!(
            CONNECTED_TIP_PROBE_HEADERS,
            noid_chain::consensus::params::RECENT_BLOCK_RETENTION_DEPTH as u16 + 2
        );
        assert_eq!(CONNECTED_TIP_PROBE_HEADERS, 20);
    }

    #[test]
    fn snapshot_parent_mismatch_requires_ancestor_discovery_only_at_the_base() {
        let mismatch = SnapshotHeaderStagingError::ParentMismatch { height: 83 };
        assert!(snapshot_parent_mismatch_is_at_base(0, 82, 83, &mismatch));
        assert!(!snapshot_parent_mismatch_is_at_base(1, 82, 83, &mismatch));
        assert!(!snapshot_parent_mismatch_is_at_base(0, 81, 83, &mismatch));
        let malformed = SnapshotHeaderStagingError::InvalidCandidate {
            height: 83,
            reason: "BadDifficultyTarget".into(),
        };
        assert!(!snapshot_parent_mismatch_is_at_base(0, 82, 83, &malformed));
    }

    #[test]
    fn ancestor_search_stops_after_the_complete_nonfinal_window() {
        assert!(header_batch_exhausts_nonfinal_window(100, 82));
        assert!(!header_batch_exhausts_nonfinal_window(100, 83));
        assert!(header_batch_exhausts_nonfinal_window(10, 0));
    }

    #[test]
    fn snapshot_header_pipeline_uses_one_ordered_same_peer_window() {
        let peer = libp2p::PeerId::random();
        let target = SNAPSHOT_HEADER_BATCH * 5;
        let mut pipeline = SnapshotHeaderPipeline::new(7, peer, 1, target);
        let initial = pipeline.refill_plan(false);
        assert_eq!(initial.len(), SNAPSHOT_HEADER_REQUEST_WINDOW);
        assert!(initial.iter().all(|request| request.peer == peer));
        assert_eq!(
            initial
                .iter()
                .map(|request| request.start_height)
                .collect::<Vec<_>>(),
            vec![
                1,
                SNAPSHOT_HEADER_BATCH + 1,
                SNAPSHOT_HEADER_BATCH * 2 + 1,
                SNAPSHOT_HEADER_BATCH * 3 + 1,
            ]
        );
        assert!(pipeline.refill_plan(false).is_empty());

        let headers = |start: u64, count: u16| {
            (start..start + u64::from(count))
                .map(|height| {
                    let mut header = noid_chain::consensus::genesis::genesis_header();
                    header.height = height;
                    header
                })
                .collect::<Vec<_>>()
        };
        // A later response may arrive first, but it cannot advance the
        // authoritative staging height.
        pipeline
            .accept(
                7,
                initial[1].token,
                peer,
                SNAPSHOT_HEADER_BATCH + 1,
                SNAPSHOT_HEADER_BATCH as u16,
                headers(SNAPSHOT_HEADER_BATCH + 1, SNAPSHOT_HEADER_BATCH as u16),
            )
            .unwrap();
        assert!(pipeline.take_ready(1).is_none());
        pipeline
            .accept(
                7,
                initial[0].token,
                peer,
                1,
                SNAPSHOT_HEADER_BATCH as u16,
                headers(1, SNAPSHOT_HEADER_BATCH as u16),
            )
            .unwrap();
        assert_eq!(
            pipeline.take_ready(1).unwrap().headers.len(),
            SNAPSHOT_HEADER_BATCH as usize
        );
        assert!(pipeline.refill_plan(true).is_empty());
        assert!(pipeline.take_ready(SNAPSHOT_HEADER_BATCH + 1).is_some());
        let refill = pipeline.refill_plan(true);
        assert_eq!(refill.len(), 1);
        assert_eq!(refill[0].start_height, SNAPSHOT_HEADER_BATCH * 4 + 1);
    }

    #[test]
    fn snapshot_header_transport_failure_retries_only_its_exact_range() {
        let peer = libp2p::PeerId::random();
        let alternate = libp2p::PeerId::random();
        let peers = std::collections::HashSet::from([peer, alternate]);
        let mut pipeline = SnapshotHeaderPipeline::new(7, peer, 1, SNAPSHOT_HEADER_BATCH * 3);
        let initial = pipeline.refill_plan(false);
        assert_eq!(initial.len(), 3);
        let failed = initial[1];
        let retry = pipeline
            .failure_plan(
                peer,
                failed.start_height,
                SNAPSHOT_HEADER_BATCH as u16,
                failed.token,
                noid_p2p::RequestFailureKind::Io,
                &peers,
            )
            .expect("failed exact range must be retried");
        assert_eq!(
            (retry.peer, retry.start_height, retry.count),
            (
                alternate,
                SNAPSHOT_HEADER_BATCH + 1,
                SNAPSHOT_HEADER_BATCH as u16
            )
        );
        assert!(pipeline.matches_outstanding(
            peer,
            1,
            SNAPSHOT_HEADER_BATCH as u16,
            initial[0].token
        ));
        assert!(!pipeline.matches_outstanding(
            peer,
            SNAPSHOT_HEADER_BATCH * 2 + 1,
            SNAPSHOT_HEADER_BATCH as u16,
            initial[2].token
        ));
        assert!(pipeline.matches_outstanding(
            alternate,
            SNAPSHOT_HEADER_BATCH + 1,
            SNAPSHOT_HEADER_BATCH as u16,
            retry.token
        ));
    }

    #[test]
    fn snapshot_header_timeout_reduces_only_the_slow_range() {
        let peer = libp2p::PeerId::random();
        let peers = std::collections::HashSet::from([peer]);
        let mut pipeline = SnapshotHeaderPipeline::new(9, peer, 1, SNAPSHOT_HEADER_BATCH * 2);
        let initial = pipeline.refill_plan(false).remove(0);
        let retry = pipeline
            .failure_plan(
                peer,
                initial.start_height,
                initial.count,
                initial.token,
                noid_p2p::RequestFailureKind::Timeout,
                &peers,
            )
            .unwrap();
        assert_eq!(retry.start_height, 1);
        assert_eq!(retry.count, (SNAPSHOT_HEADER_BATCH as u16) / 2);
        assert_eq!(pipeline.next_request_height, 1 + u64::from(retry.count));
    }

    #[test]
    fn snapshot_header_failures_try_every_connected_peer_before_reuse() {
        let first = libp2p::PeerId::random();
        let second = libp2p::PeerId::random();
        let third = libp2p::PeerId::random();
        let peers = std::collections::HashSet::from([first, second, third]);
        let mut pipeline = SnapshotHeaderPipeline::new(11, first, 1, SNAPSHOT_HEADER_BATCH);
        let initial = pipeline.refill_plan(false).pop().unwrap();
        let retry_one = pipeline
            .failure_plan(
                first,
                initial.start_height,
                initial.count,
                initial.token,
                noid_p2p::RequestFailureKind::InvalidResponse,
                &peers,
            )
            .unwrap();
        assert_ne!(retry_one.peer, first);
        let retry_two = pipeline
            .failure_plan(
                retry_one.peer,
                retry_one.start_height,
                retry_one.count,
                retry_one.token,
                noid_p2p::RequestFailureKind::InvalidResponse,
                &peers,
            )
            .unwrap();
        assert_ne!(retry_two.peer, first);
        assert_ne!(retry_two.peer, retry_one.peer);
    }

    #[test]
    fn snapshot_empty_bridge_reuses_the_verified_boundary() {
        assert_eq!(snapshot_bridge_requires_tail(144, 144), Some(false));
        assert_eq!(snapshot_bridge_requires_tail(144, 145), Some(true));
        assert_eq!(snapshot_bridge_requires_tail(144, 162), Some(true));
        assert_eq!(snapshot_bridge_requires_tail(144, 143), None);
    }

    #[test]
    fn delayed_snapshot_header_generation_is_inert() {
        let current_peer = libp2p::PeerId::random();
        let mut pipeline = SnapshotHeaderPipeline::new(8, current_peer, 1, 5_000);
        let plan = pipeline.refill_plan(false);
        assert_eq!(plan.len(), 2);
        assert_eq!(
            (plan[0].start_height, plan[0].count),
            (1, SNAPSHOT_HEADER_BATCH as u16)
        );
        assert!(!pipeline.matches_generation(7));
        assert!(pipeline.matches_generation(8));
        assert!(
            pipeline.matches_outstanding(
                current_peer,
                1,
                SNAPSHOT_HEADER_BATCH as u16,
                plan[0].token
            ),
            "stale response filtering cannot consume the active window"
        );
    }

    #[test]
    fn snapshot_segment_pipeline_uses_one_network_lane_with_cpu_overlap() {
        assert_eq!(snapshot_segment_request_capacity(0, false, false), 1);
        assert_eq!(snapshot_segment_request_capacity(0, true, false), 1);
        assert_eq!(snapshot_segment_request_capacity(0, true, true), 0);
        assert_eq!(snapshot_segment_request_capacity(1, true, false), 0);
        assert_eq!(snapshot_segment_request_capacity(1, false, false), 0);

        let mut pending = std::collections::HashSet::from([3u16, 7u16]);
        let mut queue = std::collections::VecDeque::from([11u16, 13u16]);
        assert_eq!(
            admit_snapshot_segment_response(7, false, false, &mut pending, &mut queue),
            SnapshotSegmentResponseAdmission::StageNow
        );
        assert_eq!(
            admit_snapshot_segment_response(3, true, false, &mut pending, &mut queue),
            SnapshotSegmentResponseAdmission::BufferOne
        );
        assert!(
            pending.is_empty(),
            "both out-of-order responses are consumed exactly once"
        );
        assert_eq!(
            admit_snapshot_segment_response(3, true, true, &mut pending, &mut queue),
            SnapshotSegmentResponseAdmission::Stale,
            "a delayed duplicate is never downloaded or staged twice"
        );

        let mut impossible_pending = std::collections::HashSet::from([17u16]);
        assert_eq!(
            admit_snapshot_segment_response(17, true, true, &mut impossible_pending, &mut queue,),
            SnapshotSegmentResponseAdmission::RetryOverflow
        );
        assert_eq!(queue.front(), Some(&17));
    }

    #[test]
    fn caught_up_retained_suffix_does_not_fall_back_to_snapshot() {
        assert!(!unavailable_block_requires_snapshot(10, 11, 10));
        assert!(unavailable_block_requires_snapshot(10, 11, 11));
        assert!(unavailable_block_requires_snapshot(10, 11, 20));
        assert!(!unavailable_block_requires_snapshot(10, 12, 20));
    }

    #[test]
    fn empty_manifest_response_round_is_retried_after_deadline() {
        let started = std::time::Instant::now();
        assert!(!manifest_round_retry_due(
            Some(started),
            started + STATE_MANIFEST_RESPONSE_TIMEOUT - std::time::Duration::from_millis(1),
        ));
        assert!(manifest_round_retry_due(
            Some(started),
            started + STATE_MANIFEST_RESPONSE_TIMEOUT,
        ));
    }

    #[test]
    fn snapshot_manifest_election_waits_then_prefers_cumulative_work() {
        let started = std::time::Instant::now();
        assert!(!manifest_candidate_selection_due(
            Some(started),
            started + STATE_MANIFEST_CANDIDATE_SETTLE - std::time::Duration::from_millis(1),
        ));
        assert!(manifest_candidate_selection_due(
            Some(started),
            started + STATE_MANIFEST_CANDIDATE_SETTLE,
        ));

        let mut weaker = noid_p2p::protocol::GetStateManifestResponse::default();
        weaker.bridge_tip_height = 562;
        weaker.bridge_tip_hash = [0x22; 32];
        weaker.bridge_cumulative_chainwork[0] = 1;

        let mut stronger = weaker.clone();
        stronger.bridge_tip_height = 1250;
        stronger.bridge_tip_hash = [0x11; 32];
        stronger.bridge_cumulative_chainwork[0] = 2;

        assert!(state_manifest_candidate_is_preferred(&stronger, &weaker));
        assert!(!state_manifest_candidate_is_preferred(&weaker, &stronger));

        let mut equal_work_better_hash = weaker.clone();
        equal_work_better_hash.bridge_tip_hash = [0x10; 32];
        assert!(state_manifest_candidate_is_preferred(
            &equal_work_better_hash,
            &weaker,
        ));
    }

    #[test]
    fn bounded_manifest_retries_rotate_across_six_peers() {
        let peers = (0..6)
            .map(|_| libp2p::PeerId::random())
            .collect::<std::collections::HashSet<_>>();
        let mut cursor = 0;
        let excluded = std::collections::HashSet::new();
        let first = rotating_manifest_peers(&peers, &excluded, None, false, &mut cursor, 3);
        let second = rotating_manifest_peers(&peers, &excluded, None, false, &mut cursor, 3);
        assert_eq!(first.len(), 3);
        assert_eq!(second.len(), 3);
        assert_eq!(
            first
                .into_iter()
                .chain(second)
                .collect::<std::collections::HashSet<_>>(),
            peers
        );
    }

    #[test]
    fn manifest_round_becomes_obsolete_when_announced_gap_is_closed() {
        assert!(!manifest_round_gap_is_resolved(99, 100));
        assert!(manifest_round_gap_is_resolved(100, 100));
        assert!(manifest_round_gap_is_resolved(101, 100));
    }

    #[test]
    fn next_full_block_on_competing_parent_requires_header_fork_choice() {
        let local_tip_hash = [0x11; 32];
        let mut header = noid_chain::consensus::genesis_header();
        header.height = 11;
        header.prev_block_hash = [0x22; 32];

        assert!(next_block_has_competing_parent(10, local_tip_hash, &header));

        header.prev_block_hash = local_tip_hash;
        assert!(!next_block_has_competing_parent(
            10,
            local_tip_hash,
            &header
        ));

        header.prev_block_hash = [0x22; 32];
        header.height = 10;
        assert!(!next_block_has_competing_parent(
            10,
            local_tip_hash,
            &header
        ));
        header.height = 12;
        assert!(!next_block_has_competing_parent(
            10,
            local_tip_hash,
            &header
        ));
    }
    #[test]
    fn snapshot_header_progress_rejects_delayed_and_oversized_batches() {
        assert_eq!(
            snapshot_header_next_action(10, 20).unwrap(),
            SnapshotHeaderNextAction::Fetch {
                start_height: 10,
                count: 11,
            }
        );
        assert_eq!(
            snapshot_header_next_action(21, 20).unwrap(),
            SnapshotHeaderNextAction::RequestTerminal
        );
        assert!(snapshot_header_next_action(22, 20).is_err());

        assert!(validate_snapshot_header_batch_admission(20, 20, 1).is_ok());
        assert!(validate_snapshot_header_batch_admission(21, 20, 1).is_err());
        assert!(validate_snapshot_header_batch_admission(20, 20, 0).is_err());
        assert!(validate_snapshot_header_batch_admission(20, 20, 2).is_err());
        assert!(validate_snapshot_header_batch_admission(
            1,
            1_000,
            super::MAX_STAGED_HEADER_BATCH + 1,
        )
        .is_err());
    }

    fn test_coinbase_child(
        parent: &noid_chain::BlockHeader,
        state: &noid_chain::ChainState,
    ) -> noid_chain::block::Block {
        let timestamp = parent.timestamp + noid_chain::consensus::params::BLOCK_TIME;
        let difficulty_target = noid_chain::consensus::difficulty::next_target(
            0,
            parent.timestamp,
            &parent.difficulty_target,
            parent.height + 1,
            timestamp,
        );
        let template = noid_chain::consensus::build_block_template(
            parent,
            state,
            &[parent.active_slot_count],
            vec![],
            noid_poseidon2b::primitives::Address([0x22; 32]),
            timestamp,
            difficulty_target,
        )
        .expect("canonical coinbase child template");
        let transactions = template.all_txs();
        let header = template.into_header(0);
        noid_chain::block::Block {
            header,
            transactions,
        }
    }

    #[test]
    fn snapshot_history_boundary_checks_staged_header_chainwork() {
        let state = noid_chain::ChainState::with_log_slots(
            noid_chain::consensus::params::LOG_SLOTS_GENESIS
                .try_into()
                .expect("genesis log_slots fits usize"),
        );
        let h0 = noid_chain::consensus::genesis_header();
        let h0_hash = noid_chain::hash_block_header(&h0);
        let high_start_work = noid_chain::consensus::block_work(&h0.difficulty_target);

        let block = test_coinbase_child(&h0, &state);
        let h1 = block.header;
        let h1_hash = noid_chain::hash_block_header(&h1);
        let h1_work = noid_chain::consensus::add_work(
            &high_start_work,
            &noid_chain::consensus::block_work(&h1.difficulty_target),
        );
        let manifest = noid_p2p::protocol::GetStateManifestResponse {
            tip_height: 1,
            tip_hash: h1_hash,
            cumulative_chainwork: h1_work,
            log_slots: h1.log_slots,
            active_slot_count: h1.active_slot_count,
            alloc_counter: h1.alloc_counter,
            bridge_tip_height: 1,
            bridge_tip_hash: h1_hash,
            bridge_cumulative_chainwork: h1_work,
            ..Default::default()
        };
        let boundary = SnapshotHeaderBoundary {
            tip_header: h1,
            tip_hash: h1_hash,
            cumulative_chainwork: h1_work,
            epoch_anchor_header: h0,
        };
        validate_snapshot_staged_header_boundary(&manifest, &boundary)
            .expect("staged snapshot boundary preflight succeeds");
        assert_eq!(boundary.tip_header, h1);
        assert_eq!(boundary.epoch_anchor_header, h0);

        let mut wrong_fork = boundary;
        wrong_fork.tip_hash = h0_hash;
        assert!(
            validate_snapshot_staged_header_boundary(&manifest, &wrong_fork)
                .expect_err("manifest for another staged fork must reject")
                .contains("boundary")
        );

        let mut bad = manifest.clone();
        bad.cumulative_chainwork = [3u8; 32];
        assert!(validate_snapshot_staged_header_boundary(&bad, &boundary)
            .expect_err("bad chainwork must reject")
            .contains("chainwork"));
    }

    #[test]
    fn snapshot_epoch_anchor_obeys_start_of_block_boundaries() {
        for (tip_height, expected_epoch_height) in [
            (143, 0),
            (144, 0),
            (145, 144),
            (5_327, 5_184),
            (5_328, 5_184),
            (5_329, 5_328),
        ] {
            let mut tip_header = noid_chain::consensus::genesis_header();
            tip_header.height = tip_height;
            let tip_hash = noid_chain::hash_block_header(&tip_header);
            let cumulative_chainwork = [0xA5; 32];
            let manifest = noid_p2p::protocol::GetStateManifestResponse {
                tip_height,
                tip_hash,
                cumulative_chainwork,
                log_slots: tip_header.log_slots,
                active_slot_count: tip_header.active_slot_count,
                alloc_counter: tip_header.alloc_counter,
                bridge_tip_height: tip_height,
                bridge_tip_hash: tip_hash,
                bridge_cumulative_chainwork: cumulative_chainwork,
                ..Default::default()
            };
            let mut epoch_anchor_header = noid_chain::consensus::genesis_header();
            epoch_anchor_header.height = expected_epoch_height;
            let boundary = SnapshotHeaderBoundary {
                tip_header,
                tip_hash,
                cumulative_chainwork,
                epoch_anchor_header,
            };

            validate_snapshot_staged_header_boundary(&manifest, &boundary).unwrap_or_else(
                |error| {
                    panic!(
                        "tip {tip_height} must accept epoch anchor {expected_epoch_height}: {error}"
                    )
                },
            );
        }

        let tip_height = noid_chain::consensus::params::TX_EPOCH_BLOCKS;
        let mut tip_header = noid_chain::consensus::genesis_header();
        tip_header.height = tip_height;
        let tip_hash = noid_chain::hash_block_header(&tip_header);
        let cumulative_chainwork = [0x5A; 32];
        let manifest = noid_p2p::protocol::GetStateManifestResponse {
            tip_height,
            tip_hash,
            cumulative_chainwork,
            log_slots: tip_header.log_slots,
            active_slot_count: tip_header.active_slot_count,
            alloc_counter: tip_header.alloc_counter,
            bridge_tip_height: tip_height,
            bridge_tip_hash: tip_hash,
            bridge_cumulative_chainwork: cumulative_chainwork,
            ..Default::default()
        };
        let mut wrong_anchor = noid_chain::consensus::genesis_header();
        wrong_anchor.height = tip_height;
        let boundary = SnapshotHeaderBoundary {
            tip_header,
            tip_hash,
            cumulative_chainwork,
            epoch_anchor_header: wrong_anchor,
        };
        assert!(
            validate_snapshot_staged_header_boundary(&manifest, &boundary)
                .expect_err("a boundary block cannot activate itself as its own epoch anchor")
                .contains("epoch anchor")
        );
    }

    #[test]
    fn snapshot_history_step_tip_obeys_local_future_drift_admission() {
        let local_time = 1_000_000u64;
        let mut tip = noid_chain::consensus::genesis::genesis_header();
        tip.timestamp = local_time + noid_chain::consensus::params::MAX_FUTURE_DRIFT;
        let mut boundary = SnapshotHeaderBoundary {
            tip_header: tip,
            tip_hash: noid_chain::hash_block_header(&tip),
            cumulative_chainwork: [0u8; 32],
            epoch_anchor_header: tip,
        };
        validate_history_step_tip_future_drift(&boundary, local_time)
            .expect("exact future-drift boundary is admitted");

        boundary.tip_header.timestamp += 1;
        assert!(
            validate_history_step_tip_future_drift(&boundary, local_time)
                .expect_err("far-future HistoryStep terminal tip must reject")
                .contains("future drift")
        );
    }
}

async fn handle_p2p_events(
    mut rx: noid_p2p::NetworkEventReceiver,
    chain: Arc<RwLock<MdbxChainContext>>,
    mempool: AsyncMempool,
    wallet: SharedWallet,
    p2p_cmd: tokio::sync::mpsc::Sender<noid_p2p::NetworkCommand>,
    initial_sync_ready: tokio::sync::watch::Sender<bool>,
    mut mining_peer_quorum: MiningPeerQuorum,
    template_changes: tokio::sync::broadcast::Sender<()>,
    wallet_operation_gate: WalletOperationGate,
    snapshot_staging_root: PathBuf,
    history_step_runtime: Option<Arc<noid_recursive::acceptance::history_step::HistoryStepRuntime>>,
    external_mining_attempts: ExternalMiningAttemptInvalidator,
) {
    // Orphan pool: blocks whose parent is not yet known.
    // When the parent arrives, we re-apply the orphan.
    // Keyed by parent_hash, limited to CONSENSUS_FINALITY_DEPTH entries.
    use noid_chain::consensus::params::CONSENSUS_FINALITY_DEPTH;
    use std::collections::HashMap;
    let mut orphan_pool: HashMap<[u8; 32], OrphanBlock> = HashMap::new();
    let mut pending_shallow_fork: Option<PendingShallowFork> = None;
    let mut snapshot_rebase_hint: Option<SnapshotRebaseHint> = None;
    {
        let ctx = chain.read().await;
        mining_peer_quorum.set_canonical_tip(ctx.tip_height(), ctx.tip_hash());
    }

    // --- Snapshot verification state ---
    //
    // Snapshot sync:
    //   (1) receive an immutable exact-state snapshot manifest
    //   (2) verify the O(1) HistoryStep terminal for that boundary
    //       before segment download
    // --- Segmented state sync state ---
    //
    // Sync flow:
    //   1. Recent gaps that fit RECENT_BLOCK_RETENTION_DEPTH use SyncBlocksFrom
    //      and complete bundle validation.
    //   2. Deep gaps beyond the retained-block window request a snapshot manifest.
    //
    // Normal restart (state persisted): our_height > 0 → block-by-block sync
    // for recent gaps only.
    //
    // A manifest starts bounded speculative work immediately. Concurrent peer
    // probes remain live so PoW fork choice is not frozen by connection order.
    // Recovery: any failure resets ALL state and clears requested_peers
    // so the next PeerConnected event starts fresh.
    struct PendingManifest {
        from: libp2p::PeerId,
        manifest: Box<noid_p2p::protocol::GetStateManifestResponse>,
        history_step: Option<VerifiedHistoryStepSnapshot>,
    }
    struct SnapshotManifestCandidate {
        from: libp2p::PeerId,
        manifest: Box<noid_p2p::protocol::GetStateManifestResponse>,
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum SnapshotHeaderStagingOperationKey {
        Prepare {
            generation: u64,
            token: u64,
            from: libp2p::PeerId,
            height: u64,
            block_hash: [u8; 32],
        },
        Append {
            generation: u64,
            token: u64,
            manifest_from: libp2p::PeerId,
            range_from: libp2p::PeerId,
            start_height: u64,
            count: u16,
        },
    }
    enum SnapshotHeaderStagingResult {
        Success(PendingSnapshotHeaderSync),
        CandidateRejected {
            sync: PendingSnapshotHeaderSync,
            attempted_peers: std::collections::HashSet<libp2p::PeerId>,
            error: SnapshotHeaderStagingError,
        },
        Fatal(String),
    }
    struct SnapshotHeaderStagingCompletion {
        key: SnapshotHeaderStagingOperationKey,
        work_elapsed: std::time::Duration,
        result: SnapshotHeaderStagingResult,
    }
    #[derive(Clone, Copy, PartialEq, Eq)]
    struct HistoryStepVerificationKey {
        token: u64,
        terminal_request_token: u64,
        /// Peer that owns the selected manifest/state lease.
        from: libp2p::PeerId,
        /// Peer that supplied the terminal bytes being verified.
        terminal_from: libp2p::PeerId,
        height: u64,
        block_hash: [u8; 32],
    }
    struct HistoryStepVerificationCompletion {
        key: HistoryStepVerificationKey,
        generation: u64,
        manifest: Box<noid_p2p::protocol::GetStateManifestResponse>,
        header_validation_elapsed: std::time::Duration,
        terminal_measurement: Option<SyncPhaseMeasurement>,
        staged_header_count: u64,
        result: Result<VerifiedHistoryStepSnapshot, SnapshotBoundaryVerificationError>,
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum SnapshotStagingOperationKey {
        Accept {
            generation: u64,
            from: libp2p::PeerId,
            segment_id: u16,
        },
        Finalize {
            generation: u64,
            from: libp2p::PeerId,
        },
    }
    enum SnapshotStagingCompletion {
        Accepted {
            key: SnapshotStagingOperationKey,
            payload_bytes: u64,
            work_elapsed: std::time::Duration,
            result: Result<SnapshotStagingSession, String>,
        },
        Finalized {
            key: SnapshotStagingOperationKey,
            segment_count: usize,
            work_elapsed: std::time::Duration,
            result: Result<FinalizedSnapshotStaging, String>,
        },
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct SnapshotTailAppendKey {
        generation: u64,
        from: libp2p::PeerId,
        height: u64,
        count: u16,
    }
    impl SnapshotTailAppendKey {
        fn end_height(self) -> u64 {
            self.height + u64::from(self.count - 1)
        }
    }
    struct SnapshotTailAppendCompletion {
        key: SnapshotTailAppendKey,
        result: Result<SnapshotTailStaging, String>,
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct SnapshotBoundaryTerminalKey {
        generation: u64,
        manifest_from: libp2p::PeerId,
        requests: TerminalRequestRace,
        height: u64,
        block_hash: [u8; 32],
    }
    struct PrefetchedHistoryStepTerminal {
        token: u64,
        from: libp2p::PeerId,
        terminal_bytes: Vec<u8>,
        inbound_memory_permit: Option<Arc<tokio::sync::OwnedSemaphorePermit>>,
    }
    struct PendingRecentSuffix {
        generation: u64,
        peer: libp2p::PeerId,
        base_height: u64,
        base_hash: [u8; 32],
        target_height: u64,
        target_hash: [u8; 32],
        expected_headers: Vec<noid_chain::BlockHeader>,
        staging: Option<SnapshotTailStaging>,
        body_request_active: bool,
        append_active: bool,
        terminal_requests: TerminalRequestRace,
        terminal_payload: Option<PrefetchedHistoryStepTerminal>,
    }
    struct RecentSuffixAppendCompletion {
        generation: u64,
        result: Result<SnapshotTailStaging, String>,
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct RecentSuffixApplyKey {
        generation: u64,
        peer: libp2p::PeerId,
        terminal_from: libp2p::PeerId,
        terminal_request_token: u64,
        base_height: u64,
        target_height: u64,
    }
    struct RecentSuffixApplyCompletion {
        key: RecentSuffixApplyKey,
        result: Result<AppliedCompactSuffix, CompactSuffixApplyError>,
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct SnapshotTailTerminalKey {
        generation: u64,
        manifest_from: libp2p::PeerId,
        requests: TerminalRequestRace,
        height: u64,
        block_hash: [u8; 32],
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct SnapshotInstallKey {
        generation: u64,
        from: libp2p::PeerId,
        terminal_from: Option<libp2p::PeerId>,
        terminal_request_token: Option<u64>,
        height: u64,
        block_hash: [u8; 32],
    }
    struct SnapshotInstallCompletion {
        key: SnapshotInstallKey,
        result: Result<AppliedVerifiedSnapshot, SnapshotInstallError>,
    }
    let mut pending_manifest: Option<PendingManifest> = None;
    // A bounded pre-install election prevents connection order from becoming
    // fork choice. Only one manifest body is retained: the strongest advertised
    // bridge by cumulative work, with the canonical hash tie-break. Its claim
    // is not authority; exact native header validation follows immediately.
    let mut best_manifest_candidate: Option<SnapshotManifestCandidate> = None;
    let mut manifest_candidate_started_at: Option<std::time::Instant> = None;
    let mut pending_snapshot_header_sync: Option<PendingSnapshotHeaderSync> = None;
    let mut snapshot_header_pipeline: Option<SnapshotHeaderPipeline> = None;
    let (snapshot_header_staging_tx, mut snapshot_header_staging_rx) =
        tokio::sync::mpsc::channel::<SnapshotHeaderStagingCompletion>(1);
    let mut snapshot_header_staging_inflight: Option<SnapshotHeaderStagingOperationKey> = None;
    let mut snapshot_header_staging_token = 0u64;
    let (history_step_verification_tx, mut history_step_verification_rx) =
        tokio::sync::mpsc::channel::<HistoryStepVerificationCompletion>(1);
    let mut history_step_verification_inflight: Option<HistoryStepVerificationKey> = None;
    let mut history_step_verification_token = 0u64;
    // Snapshot payload CPU/disk work is strictly serialized.  The bounded
    // completion channels cannot accumulate segment-sized allocations: each
    // completion owns only the compact staging session or finalized handle.
    let (snapshot_staging_completion_tx, mut snapshot_staging_completion_rx) =
        tokio::sync::mpsc::channel::<SnapshotStagingCompletion>(1);
    let mut snapshot_staging_inflight: Option<SnapshotStagingOperationKey> = None;
    let (snapshot_tail_append_tx, mut snapshot_tail_append_rx) =
        tokio::sync::mpsc::channel::<SnapshotTailAppendCompletion>(1);
    let mut snapshot_tail_staging: Option<SnapshotTailStaging> = None;
    let mut snapshot_tail_request_inflight: Option<SnapshotTailAppendKey> = None;
    let mut snapshot_tail_append_inflight: Option<SnapshotTailAppendKey> = None;
    let mut snapshot_boundary_terminal_inflight: Option<SnapshotBoundaryTerminalKey> = None;
    let mut prefetched_snapshot_boundary_terminal: Option<PrefetchedHistoryStepTerminal> = None;
    let mut snapshot_tail_terminal_inflight: Option<SnapshotTailTerminalKey> = None;
    let mut prefetched_snapshot_tail_terminal: Option<PrefetchedHistoryStepTerminal> = None;
    let (recent_suffix_append_tx, mut recent_suffix_append_rx) =
        tokio::sync::mpsc::channel::<RecentSuffixAppendCompletion>(1);
    let (recent_suffix_apply_tx, mut recent_suffix_apply_rx) =
        tokio::sync::mpsc::channel::<RecentSuffixApplyCompletion>(1);
    let mut pending_recent_suffix: Option<PendingRecentSuffix> = None;
    let mut recent_suffix_apply_inflight: Option<RecentSuffixApplyKey> = None;
    let mut recent_suffix_generation = 0u64;
    let mut history_step_request_token = 0u64;
    let mut finalized_snapshot_waiting: Option<(FinalizedSnapshotStaging, usize, libp2p::PeerId)> =
        None;
    let mut snapshot_tail_install_target: Option<u64> = None;
    let (snapshot_install_completion_tx, mut snapshot_install_completion_rx) =
        tokio::sync::mpsc::channel::<SnapshotInstallCompletion>(1);
    let mut snapshot_install_inflight: Option<SnapshotInstallKey> = None;
    let mut snapshot_sync_generation = 0u64;
    let snapshot_sync_generation_guard = Arc::new(std::sync::atomic::AtomicU64::new(0));
    // One fixed-size set of scalar phase totals for the active snapshot sync.
    // No per-header, per-segment, or per-block timing history is retained.
    let mut sync_phase_telemetry = SnapshotSyncTelemetry::default();
    let snapshot_header_store = {
        let ctx = chain.read().await;
        ctx.store.clone()
    };
    // Segment staging is intentionally wiped on startup; validated header
    // candidates are separately crash-resumable and therefore use a sibling.
    let snapshot_header_staging_root =
        snapshot_staging_root.with_file_name("snapshot-header-staging");
    // Tracks peers already asked; cleared on failure so recovery is automatic.
    let mut manifest_requested_peers: std::collections::HashSet<libp2p::PeerId> =
        std::collections::HashSet::new();
    // Tracks peers for forced snapshot attempts. The manifest advertises the
    // snapshot boundary, so non-empty responses stay on the snapshot path.
    let mut manifest_force_snapshot_peers: std::collections::HashSet<libp2p::PeerId> =
        std::collections::HashSet::new();
    // Count of manifest responses received (including tip=0 "no state" replies).
    // Used only to diagnose and recover rounds that produced no usable response.
    let mut manifest_response_count: usize = 0;
    // Set while a manifest round is waiting for at least one usable candidate.
    // Empty responses mean the peer has no usable immutable generation, so
    // receiving a response alone must not disarm the retry timer.
    let mut manifest_round_started_at: Option<std::time::Instant> = None;
    // Connected peers eligible for manifest (re-)requests.
    let mut manifest_peers: std::collections::HashSet<libp2p::PeerId> =
        std::collections::HashSet::new();
    let mut manifest_terminal_capabilities: std::collections::HashMap<
        libp2p::PeerId,
        ManifestTerminalCapability,
    > = std::collections::HashMap::new();
    // A peer that supplied an exact-bound but cryptographically invalid
    // recursive terminal has proved that its terminal service is unusable for
    // this process lifetime. Do not let a fast invalid hedge preempt an honest
    // peer again on the next snapshot generation.
    let mut rejected_terminal_peers: std::collections::HashSet<libp2p::PeerId> =
        std::collections::HashSet::new();
    // A peer whose authenticated header view has no common ancestor in our
    // complete non-final window cannot be used for an automatic rebase. Keep
    // it out of snapshot selection for this connection lifetime instead of
    // cycling through manifests guaranteed to fail at the first parent link.
    let mut finalized_divergent_peers: std::collections::HashSet<libp2p::PeerId> =
        std::collections::HashSet::new();
    let mut mempool_sync_requested_peers: std::collections::HashSet<libp2p::PeerId> =
        std::collections::HashSet::new();
    // Bounded retries rotate through the connected set instead of repeatedly
    // selecting the same HashSet iteration prefix.
    let mut manifest_retry_cursor = 0usize;
    // Independent round-robin cursor for the single steady-state tip lane.
    // This never fans one logical probe out across the peer set.
    let mut steady_tip_probe_cursor = 0usize;
    let mut last_steady_tip_probe = Instant::now();
    let mut last_mining_quorum_probe = Instant::now()
        .checked_sub(MINING_QUORUM_PROBE_INTERVAL)
        .unwrap_or_else(Instant::now);
    // Payloads are authenticated one at a time and sealed to disk.  The
    // session retains only compact descriptors and a received bitset.
    let mut snapshot_staging: Option<SnapshotStagingSession> = None;
    // One complete response may wait behind the single disk/authentication
    // worker. Together they form a strict two-segment pipeline; no response is
    // discarded and downloaded again merely because the worker is busy.
    let mut queued_segment_response: Option<(
        libp2p::PeerId,
        noid_p2p::protocol::GetStateSegmentResponse,
    )> = None;
    // Segment IDs still outstanding.
    let mut pending_segment_ids: std::collections::HashSet<u16> = std::collections::HashSet::new();
    let mut snapshot_segment_retry_counts: std::collections::HashMap<u16, u8> =
        std::collections::HashMap::new();
    // Segment IDs queued but not yet requested (concurrency cap).
    let mut segment_queue: std::collections::VecDeque<u16> = std::collections::VecDeque::new();

    // Clear only manifest-round bookkeeping. Unlike reset_sync_state!, this
    // does not disturb an already-applied direct suffix, orphan pool, or any
    // unrelated recovery state.
    macro_rules! clear_manifest_round_state {
        () => {{
            manifest_requested_peers.clear();
            manifest_force_snapshot_peers.clear();
            manifest_response_count = 0;
            manifest_round_started_at = None;
            best_manifest_candidate = None;
            manifest_candidate_started_at = None;
        }};
    }

    // Transport loss must not erase the expensive exact header prefix. The
    // staging file is already native-validated and crash-safe. Dropping its
    // handle closes the descriptor but deliberately leaves the exact-boundary
    // file for the next manifest lease to reopen and revalidate.
    macro_rules! preserve_active_snapshot_headers {
        () => {{
            if let Some(sync) = pending_snapshot_header_sync.take() {
                let staged_headers = sync.staging.staged_len();
                let staging_path = sync.staging.path().to_owned();
                drop(sync.staging);
                tracing::debug!(
                    staged_headers,
                    path = %staging_path.display(),
                    "retained exact snapshot header staging across transport loss"
                );
            }
            if let Some(verified) = pending_manifest
                .as_mut()
                .and_then(|pending| pending.history_step.take())
            {
                let boundary_height = verified.height;
                drop(verified);
                tracing::debug!(
                    boundary_height,
                    "retained verified snapshot headers across transport loss"
                );
            }
        }};
    }

    // Helper: reset all segment-sync state on any failure.
    // Called whenever sync needs to restart (bad terminal, apply failure, missing segment).
    // Clearing manifest_requested_peers lets the next PeerConnected start fresh.
    macro_rules! reset_sync_state {
        () => {{
            snapshot_sync_generation = snapshot_sync_generation.wrapping_add(1);
            sync_phase_telemetry.reset();
            snapshot_sync_generation_guard.store(
                snapshot_sync_generation,
                std::sync::atomic::Ordering::Release,
            );
            if let Some(mut stale_manifest) = pending_manifest.take() {
                if let Some(verified) = stale_manifest.history_step.take() {
                    drop_verified_history_step(verified);
                }
            }
            if let Some(stale_headers) = pending_snapshot_header_sync.take() {
                cleanup_snapshot_header_staging_offthread(stale_headers.staging);
            }
            snapshot_header_pipeline = None;
            clear_manifest_round_state!();
            if let Some(stale_staging) = snapshot_staging.take() {
                cleanup_snapshot_staging_session_offthread(stale_staging);
            }
            queued_segment_response = None;
            drop(snapshot_tail_staging.take());
            snapshot_tail_request_inflight = None;
            if let Some(request) = snapshot_boundary_terminal_inflight.take() {
                let _ = p2p_cmd
                    .send(noid_p2p::NetworkCommand::CancelHistoryStepTerminalRace {
                        token: request.requests.primary.token,
                    })
                    .await;
            }
            prefetched_snapshot_boundary_terminal = None;
            if let Some(request) = snapshot_tail_terminal_inflight.take() {
                let _ = p2p_cmd
                    .send(noid_p2p::NetworkCommand::CancelHistoryStepTerminalRace {
                        token: request.requests.primary.token,
                    })
                    .await;
            }
            prefetched_snapshot_tail_terminal = None;
            snapshot_tail_install_target = None;
            if let Some((finalized, _, _)) = finalized_snapshot_waiting.take() {
                cleanup_finalized_snapshot_staging_offthread(finalized);
            }
            pending_segment_ids.clear();
            snapshot_segment_retry_counts.clear();
            segment_queue.clear();
            pending_shallow_fork = None;
            if history_step_verification_inflight.is_some() {
                tracing::debug!(
                    "sync state reset — waiting for the bounded verifier to release its admission"
                );
            } else if snapshot_header_staging_inflight.is_some()
                || snapshot_staging_inflight.is_some()
                || snapshot_tail_append_inflight.is_some()
                || snapshot_install_inflight.is_some()
            {
                tracing::debug!(
                    "sync state reset — waiting for bounded snapshot I/O to complete"
                );
            } else {
                tracing::debug!("sync state reset — ready for fresh manifest retry");
            }
        }};
    }

    macro_rules! request_bounded_manifest_failover {
        ($failed_peer:expr, $allow_failed_peer:expr) => {{
            let failed_peer = $failed_peer;
            let our_height = {
                let ctx = chain.read().await;
                ctx.tip_height()
            };
            let excluded_peers = rejected_terminal_peers
                .union(&finalized_divergent_peers)
                .copied()
                .collect::<std::collections::HashSet<_>>();
            let candidates = rotating_manifest_peers(
                &manifest_peers,
                &excluded_peers,
                Some(failed_peer),
                $allow_failed_peer,
                &mut manifest_retry_cursor,
                3,
            );
            for peer in candidates {
                manifest_requested_peers.insert(peer);
                let _ = p2p_cmd
                    .send(noid_p2p::NetworkCommand::RequestStateManifest {
                        generation: snapshot_sync_generation,
                        peer,
                        requester_height: our_height,
                    })
                    .await;
            }
            if !manifest_requested_peers.is_empty() {
                manifest_round_started_at = Some(Instant::now());
            }
        }};
    }

    macro_rules! selected_snapshot_peer {
        () => {{
            pending_manifest
                .as_ref()
                .map(|pending| pending.from)
                .or_else(|| {
                    pending_snapshot_header_sync
                        .as_ref()
                        .map(|pending| pending.from)
                })
                .or_else(|| {
                    snapshot_header_staging_inflight
                        .as_ref()
                        .map(|key| match key {
                            SnapshotHeaderStagingOperationKey::Prepare { from, .. } => *from,
                            SnapshotHeaderStagingOperationKey::Append { manifest_from, .. } => {
                                *manifest_from
                            }
                        })
                })
                .or_else(|| history_step_verification_inflight.map(|pending| pending.from))
        }};
    }

    macro_rules! request_snapshot_tail_blocks {
        ($from:expr, $height:expr, $count:expr) => {{
            let from = $from;
            let height = $height;
            let count = $count;
            if snapshot_tail_request_inflight.is_none() && snapshot_tail_append_inflight.is_none() {
                let key = SnapshotTailAppendKey {
                    generation: snapshot_sync_generation,
                    from,
                    height,
                    count,
                };
                snapshot_tail_request_inflight = Some(key);
                if p2p_cmd
                    .send(noid_p2p::NetworkCommand::RequestBlockBodies {
                        peer: from,
                        height,
                        count,
                    })
                    .await
                    .is_err()
                {
                    snapshot_tail_request_inflight = None;
                }
            }
        }};
    }

    macro_rules! begin_snapshot_header_staging {
        ($from:expr, $manifest:expr) => {{
            sync_phase_telemetry.begin_snapshot();
            let from = $from;
            let manifest = $manifest;
            let header_manifest = manifest.clone();
            let terminal_height = manifest.tip_height;
            let terminal_hash = manifest.tip_hash;
            let rebase_base = snapshot_rebase_hint.and_then(|hint| {
                (hint.ancestor_height < terminal_height)
                    .then_some((hint.ancestor_height, hint.ancestor_hash))
            });

            // The manifest fixes a bounded immutable generation. Consecutive
            // ranges come from one selected peer through a bounded ordered
            // window. Local validation and disk staging overlap later ranges,
            // while terminals, state and bridge bodies do not compete with the
            // header phase on the same connection.
            let bridge_is_empty = snapshot_bridge_requires_tail(
                manifest.tip_height,
                manifest.bridge_tip_height,
            ) == Some(false);
            let tail = if bridge_is_empty {
                None
            } else {
                let tail_root = snapshot_staging_root.join("tail");
                match SnapshotTailStaging::create(
                    &tail_root,
                    manifest.tip_height,
                    manifest.tip_hash,
                    manifest.cumulative_chainwork,
                ) {
                    Ok(tail) => Some(tail),
                    Err(error) => {
                        tracing::warn!(
                            peer = %from,
                            err = %error,
                            "snapshot tail staging initialization failed"
                        );
                        reset_sync_state!();
                        request_bounded_manifest_failover!(from, true);
                        continue;
                    }
                }
            };
            let bridge_tip = manifest.bridge_tip_height;
            pending_manifest = Some(PendingManifest {
                from,
                manifest,
                history_step: None,
            });
            snapshot_tail_staging = tail;
            snapshot_tail_install_target = Some(bridge_tip);

            snapshot_header_staging_token = snapshot_header_staging_token.wrapping_add(1);
            let key = SnapshotHeaderStagingOperationKey::Prepare {
                generation: snapshot_sync_generation,
                token: snapshot_header_staging_token,
                from,
                height: terminal_height,
                block_hash: terminal_hash,
            };
            snapshot_header_staging_inflight = Some(key);
            let completion = snapshot_header_staging_tx.clone();
            let store = snapshot_header_store.clone();
            let staging_root = snapshot_header_staging_root.clone();
            tokio::task::spawn_blocking(move || {
                let started = Instant::now();
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    prepare_snapshot_header_sync(
                        &staging_root,
                        &store,
                        from,
                        header_manifest,
                        rebase_base,
                    )
                }))
                .map_err(|_| "snapshot header preparation worker panicked".to_owned())
                .and_then(|result| result);
                let _ = completion.blocking_send(SnapshotHeaderStagingCompletion {
                    key,
                    work_elapsed: started.elapsed(),
                    result: match result {
                        Ok(sync) => SnapshotHeaderStagingResult::Success(sync),
                        Err(error) => SnapshotHeaderStagingResult::Fatal(error),
                    },
                });
            });
            tracing::info!(
                peer = %from,
                target_height = terminal_height,
                bridge_tip,
                rebase_base_height = rebase_base.map(|(height, _)| height),
                "snapshot: staging exact headers"
            );
        }};
    }

    macro_rules! spawn_snapshot_header_append {
        ($sync:expr, $range:expr) => {{
            let sync = $sync;
            let range: ReadySnapshotHeaderRange = $range;
            let manifest_from = sync.from;
            let range_from = range.source_peer;
            let start_height = sync.next_height;
            let count = range.count;
            snapshot_header_staging_token = snapshot_header_staging_token.wrapping_add(1);
            let key = SnapshotHeaderStagingOperationKey::Append {
                generation: snapshot_sync_generation,
                token: snapshot_header_staging_token,
                manifest_from,
                range_from,
                start_height,
                count,
            };
            snapshot_header_staging_inflight = Some(key);
            let completion = snapshot_header_staging_tx.clone();
            let store = snapshot_header_store.clone();
            tokio::task::spawn_blocking(move || {
                let started = Instant::now();
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                    let mut sync = sync;
                    match sync.staging.append_batch(&store, &range.headers) {
                        Ok(next_height) => {
                            sync.next_height = next_height;
                            SnapshotHeaderStagingResult::Success(sync)
                        }
                        Err(
                            error @ (SnapshotHeaderStagingError::InvalidCandidate { .. }
                            | SnapshotHeaderStagingError::ParentMismatch { .. }),
                        ) => SnapshotHeaderStagingResult::CandidateRejected {
                            sync,
                            attempted_peers: range.attempted_peers,
                            error,
                        },
                        Err(error) => {
                            let message = error.to_string();
                            let _ = sync.staging.discard();
                            SnapshotHeaderStagingResult::Fatal(message)
                        }
                    }
                }))
                .unwrap_or_else(|_| {
                    SnapshotHeaderStagingResult::Fatal(
                        "snapshot header append worker panicked".to_owned(),
                    )
                });
                let _ = completion.blocking_send(SnapshotHeaderStagingCompletion {
                    key,
                    work_elapsed: started.elapsed(),
                    result,
                });
            });
        }};
    }

    macro_rules! start_snapshot_boundary_verification {
        ($sync:expr, $payload:expr) => {{
            let sync = $sync;
            let payload = $payload;
            let terminal_from = payload.from;
            let terminal_request_token = payload.token;
            let Some(runtime) = history_step_runtime.clone() else {
                tracing::error!(
                    from = %sync.from,
                    tip = sync.manifest.tip_height,
                    "snapshot rejected: HistoryStep verifier unavailable"
                );
                let _ = p2p_cmd
                    .send(noid_p2p::NetworkCommand::CancelHistoryStepTerminalRace {
                        token: terminal_request_token,
                    })
                    .await;
                cleanup_snapshot_header_staging_offthread(sync.staging);
                drop(payload);
                reset_sync_state!();
                continue;
            };
            let expected_height = sync.manifest.tip_height;
            let expected_hash = sync.manifest.tip_hash;
            let manifest_from = sync.from;
            history_step_verification_token =
                history_step_verification_token.wrapping_add(1);
            let key = HistoryStepVerificationKey {
                token: history_step_verification_token,
                terminal_request_token,
                from: manifest_from,
                terminal_from,
                height: expected_height,
                block_hash: expected_hash,
            };
            let generation = snapshot_sync_generation;
            let completion = history_step_verification_tx.clone();
            let generation_guard = Arc::clone(&snapshot_sync_generation_guard);
            let store = snapshot_header_store.clone();
            let verification_chain = Arc::clone(&chain);
            let manifest = sync.manifest;
            let allow_nonfinal_rebase = snapshot_rebase_hint.is_some_and(|hint| {
                let base = sync.staging.base();
                base.header.height == hint.ancestor_height
                    && base.block_hash == hint.ancestor_hash
            });
            let staging = sync.staging;
            let staged_header_count = staging.staged_len();
            let terminal_bytes = payload.terminal_bytes;
            let inbound_memory_permit = payload.inbound_memory_permit;
            history_step_verification_inflight = Some(key);
            tokio::task::spawn_blocking(move || {
                let mut header_validation_elapsed = std::time::Duration::ZERO;
                let mut terminal_measurement = None;
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    if generation_guard.load(std::sync::atomic::Ordering::Acquire) != generation {
                        return Err(SnapshotBoundaryVerificationError::Other(
                            "HistoryStep verification superseded before start".to_owned(),
                        ));
                    }
                    let header_started = Instant::now();
                    let validated_headers = staging
                        .validate_complete(
                            &store,
                            expected_height,
                            expected_hash,
                            manifest.cumulative_chainwork,
                        )
                        .map_err(|error| {
                            SnapshotBoundaryVerificationError::Other(error.to_string())
                        })?;
                    let boundary = validated_headers.boundary();
                    validate_snapshot_staged_header_boundary(&manifest, &boundary)
                        .map_err(SnapshotBoundaryVerificationError::Other)?;
                    validate_history_step_tip_future_drift(&boundary, unix_now())
                        .map_err(SnapshotBoundaryVerificationError::Other)?;
                    header_validation_elapsed = header_started.elapsed();
                    if generation_guard.load(std::sync::atomic::Ordering::Acquire) != generation {
                        return Err(SnapshotBoundaryVerificationError::Other(
                            "HistoryStep verification superseded before completion".to_owned(),
                        ));
                    }

                    let terminal_len = terminal_bytes.len() as u64;
                    let terminal_started = Instant::now();
                    let terminal_result = {
                        let ctx = verification_chain.blocking_read();
                        ctx.verify_snapshot_boundary(
                            boundary.tip_header,
                            boundary.epoch_anchor_header,
                            terminal_bytes,
                            |claim| verify_history_step_terminal(claim, Some(runtime.as_ref())),
                        )
                        .map_err(|error| {
                            let message =
                                format!("verify snapshot HistoryStep boundary: {error}");
                            if history_step_context_error_is_terminal_peer_fault(&error) {
                                SnapshotBoundaryVerificationError::Terminal(message)
                            } else {
                                SnapshotBoundaryVerificationError::Other(message)
                            }
                        })
                    };
                    terminal_measurement = Some(SyncPhaseMeasurement::new(
                        SyncPhase::HistoryStepTerminal,
                        1,
                        terminal_len,
                        terminal_started.elapsed(),
                        terminal_result.is_ok(),
                    ));
                    let verified_boundary = terminal_result?;
                    Ok(VerifiedHistoryStepSnapshot {
                        height: expected_height,
                        block_hash: expected_hash,
                        boundary: verified_boundary,
                        headers: validated_headers,
                        allow_nonfinal_rebase,
                        inbound_memory_permit,
                    })
                }))
                .map_err(|_| {
                    SnapshotBoundaryVerificationError::Other(
                        "HistoryStep verifier worker panicked".to_owned(),
                    )
                })
                .and_then(|result| result);
                let _ = completion.blocking_send(HistoryStepVerificationCompletion {
                    key,
                    generation,
                    manifest,
                    header_validation_elapsed,
                    terminal_measurement,
                    staged_header_count,
                    result,
                });
            });
            tracing::info!(
                from = %manifest_from,
                terminal_from = %terminal_from,
                tip = expected_height,
                "snapshot HistoryStep verification started off-thread"
            );
        }};
    }

    macro_rules! stage_snapshot_segment_response {
        ($from:expr, $response:expr) => {{
            let from = $from;
            let response = $response;
            let Some(mut staging) = snapshot_staging.take() else {
                tracing::warn!(
                    from = %from,
                    segment = response.segment_id,
                    "segment received without snapshot staging session"
                );
                drop(response);
                reset_sync_state!();
                continue;
            };
            let key = SnapshotStagingOperationKey::Accept {
                generation: snapshot_sync_generation,
                from,
                segment_id: response.segment_id,
            };
            snapshot_staging_inflight = Some(key);
            let completion = snapshot_staging_completion_tx.clone();
            let response_effective_log = response.eff_log;
            let segment_id = response.segment_id;
            let payload_bytes = response
                .data
                .as_ref()
                .map_or(0u64, |data| data.len() as u64);
            tokio::task::spawn_blocking(move || {
                let started = Instant::now();
                let result =
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                        let result = staging
                            .accept_segment(
                                segment_id,
                                response_effective_log,
                                response
                                    .data
                                    .as_deref()
                                    .expect("present segment payload moved intact"),
                            )
                            .map(|()| staging)
                            .map_err(|error| error.to_string());
                        // The wire allocation and inbound permit stay charged
                        // until authentication and atomic disk publication.
                        drop(response);
                        result
                    }))
                    .map_err(|_| "snapshot segment staging worker panicked".to_owned())
                    .and_then(|result| result);
                let _ = completion.blocking_send(SnapshotStagingCompletion::Accepted {
                    key,
                    payload_bytes,
                    work_elapsed: started.elapsed(),
                    result,
                });
            });
            tracing::debug!(
                from = %from,
                segment = segment_id,
                "snapshot segment queued for bounded authentication/staging"
            );
        }};
    }

    macro_rules! stage_snapshot_tail_bodies {
        ($from:expr, $height:expr, $block_bodies:expr, $inbound_permit:expr) => {{
            let from = $from;
            let height = $height;
            let block_bodies = $block_bodies;
            let count = u16::try_from(block_bodies.len())
                .expect("P2P codec bounds snapshot block-body batch count");
            let Some(staging) = snapshot_tail_staging.take() else {
                tracing::warn!(from = %from, height, count, "snapshot tail bodies arrived without staging");
                drop(block_bodies);
                drop($inbound_permit);
                reset_sync_state!();
                continue;
            };
            let key = SnapshotTailAppendKey {
                generation: snapshot_sync_generation,
                from,
                height,
                count,
            };
            snapshot_tail_append_inflight = Some(key);
            let completion = snapshot_tail_append_tx.clone();
            let inbound_permit = $inbound_permit;
            tokio::task::spawn_blocking(move || {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                    let result = staging.append_batch(block_bodies);
                    drop(inbound_permit);
                    result
                }))
                .map_err(|_| "snapshot tail append worker panicked".to_owned())
                .and_then(|result| result);
                let _ = completion.blocking_send(SnapshotTailAppendCompletion { key, result });
            });
        }};
    }

    macro_rules! request_snapshot_tail_terminal {
        ($from:expr) => {{
            let from = $from;
            if snapshot_tail_terminal_inflight.is_none()
                && prefetched_snapshot_tail_terminal.is_none()
            {
                if let Some(pending) = pending_manifest.as_ref().filter(|pending| pending.from == from)
                {
                    let height = pending.manifest.bridge_tip_height;
                    let block_hash = pending.manifest.bridge_tip_hash;
                    if height > pending.manifest.tip_height {
                        history_step_request_token = history_step_request_token.wrapping_add(1);
                        let key = SnapshotTailTerminalKey {
                            generation: snapshot_sync_generation,
                            manifest_from: from,
                            requests: TerminalRequestRace::new(from, history_step_request_token),
                            height,
                            block_hash,
                        };
                        snapshot_tail_terminal_inflight = Some(key);
                        if p2p_cmd
                            .send(noid_p2p::NetworkCommand::RequestHistoryStepTerminal {
                                token: key.requests.primary.token,
                                peer: from,
                                height,
                                block_hash,
                            })
                            .await
                            .is_err()
                        {
                            snapshot_tail_terminal_inflight = None;
                        } else {
                            tracing::info!(
                                peer = %from,
                                height,
                                "snapshot: prefetching immutable bridge terminal in parallel"
                            );
                        }
                    }
                }
            }
        }};
    }

    macro_rules! start_snapshot_install {
        ($finalized:expr, $segment_count:expr, $from:expr, $tail:expr, $terminal_from:expr, $terminal_request_token:expr) => {{
            let finalized = $finalized;
            let segment_count = $segment_count;
            let from = $from;
            let tail: Option<FinalizedSnapshotTail> = $tail;
            let terminal_from: Option<libp2p::PeerId> = $terminal_from;
            let terminal_request_token: Option<u64> = $terminal_request_token;
            let Some(mut pending) = pending_manifest.take() else {
                tracing::warn!(from = %from, "snapshot finalized without selected manifest");
                if let Some(token) = terminal_request_token {
                    let _ = p2p_cmd
                        .send(noid_p2p::NetworkCommand::CancelHistoryStepTerminalRace { token })
                        .await;
                }
                cleanup_finalized_snapshot_staging_offthread(finalized);
                drop(tail);
                reset_sync_state!();
                continue;
            };
            if pending.from != from {
                tracing::warn!(from = %from, expected = %pending.from, "snapshot finalization peer changed");
                if let Some(token) = terminal_request_token {
                    let _ = p2p_cmd
                        .send(noid_p2p::NetworkCommand::CancelHistoryStepTerminalRace { token })
                        .await;
                }
                cleanup_finalized_snapshot_staging_offthread(finalized);
                drop(tail);
                reset_sync_state!();
                continue;
            }
            let Some(history_step) = pending.history_step.take() else {
                tracing::error!(from = %from, "verified snapshot lost HistoryStep authority");
                if let Some(token) = terminal_request_token {
                    let _ = p2p_cmd
                        .send(noid_p2p::NetworkCommand::CancelHistoryStepTerminalRace { token })
                        .await;
                }
                cleanup_finalized_snapshot_staging_offthread(finalized);
                drop(tail);
                reset_sync_state!();
                continue;
            };

            let manifest = *pending.manifest;
            let tail_matches_manifest = if snapshot_bridge_requires_tail(
                manifest.tip_height,
                manifest.bridge_tip_height,
            ) == Some(false)
            {
                tail.is_none()
            } else {
                tail.as_ref().is_some_and(|tail| {
                    tail.boundary_height() == manifest.tip_height
                        && tail.boundary_hash() == manifest.tip_hash
                        && tail.tip_height() == manifest.bridge_tip_height
                        && tail.tip_hash() == manifest.bridge_tip_hash
                })
            };
            if !tail_matches_manifest {
                tracing::error!(
                    from = %from,
                    snapshot = manifest.tip_height,
                    bridge_tip = manifest.bridge_tip_height,
                    staged_tip = tail.as_ref().map(FinalizedSnapshotTail::tip_height),
                    "snapshot tail does not cover the immutable bridge"
                );
                if let Some(token) = terminal_request_token {
                    let _ = p2p_cmd
                        .send(noid_p2p::NetworkCommand::CancelHistoryStepTerminalRace { token })
                        .await;
                }
                cleanup_finalized_snapshot_staging_offthread(finalized);
                drop_verified_history_step(history_step);
                drop(tail);
                reset_sync_state!();
                continue;
            }
            let key = SnapshotInstallKey {
                generation: snapshot_sync_generation,
                from,
                terminal_from,
                terminal_request_token,
                height: manifest.tip_height,
                block_hash: manifest.tip_hash,
            };
            snapshot_install_inflight = Some(key);
            let install_chain = Arc::clone(&chain);
            let install_mempool = mempool.clone();
            let install_wallet = Arc::clone(&wallet);
            let install_wallet_operation_gate = Arc::clone(&wallet_operation_gate);
            let install_external_mining_attempts = external_mining_attempts.clone();
            let install_history_step_runtime = history_step_runtime.clone();
            let completion = snapshot_install_completion_tx.clone();
            let staged_tail_blocks = tail
                .as_ref()
                .map_or(0, FinalizedSnapshotTail::block_count);
            let staged_tail_bytes = tail
                .as_ref()
                .map_or(0, FinalizedSnapshotTail::payload_bytes);
            let install_task = tokio::spawn(async move {
                apply_verified_snapshot(
                    &install_chain,
                    &install_mempool,
                    &install_wallet,
                    manifest,
                    finalized,
                    history_step,
                    tail,
                    install_history_step_runtime,
                    &install_wallet_operation_gate,
                    &install_external_mining_attempts,
                )
                .await
            });
            tokio::spawn(async move {
                let result = install_task
                    .await
                    .map_err(|error| {
                        SnapshotInstallError::BeforeCommit(format!(
                            "snapshot install task panicked: {error}"
                        ))
                    })
                    .and_then(|result| result);
                let _ = completion
                    .send(SnapshotInstallCompletion { key, result })
                    .await;
            });
            tracing::info!(
                from = %from,
                tip = key.height,
                segments = segment_count,
                staged_tail_blocks,
                staged_tail_bytes,
                "snapshot and immutable tail finalized — atomic catch-up running off event loop"
            );
        }};
    }

    macro_rules! try_start_ready_snapshot_install {
        () => {{
            let bridge_is_empty = pending_manifest.as_ref().is_some_and(|pending| {
                snapshot_bridge_requires_tail(
                    pending.manifest.tip_height,
                    pending.manifest.bridge_tip_height,
                ) == Some(false)
            });
            let bridge_is_ready = bridge_is_empty
                || (prefetched_snapshot_tail_terminal.is_some()
                    && snapshot_tail_request_inflight.is_none()
                    && snapshot_tail_append_inflight.is_none()
                    && snapshot_tail_staging.as_ref().is_some_and(|tail| {
                        snapshot_tail_install_target == Some(tail.tip_height())
                    }));
            let ready = finalized_snapshot_waiting.is_some() && bridge_is_ready;
            if ready {
                let (finalized, segment_count, finalized_from) =
                    finalized_snapshot_waiting
                        .take()
                        .expect("checked finalized snapshot state");
                let (tail, terminal_from, terminal_request_token) = if bridge_is_empty {
                    (None, None, None)
                } else {
                    let staging = snapshot_tail_staging
                        .take()
                        .expect("checked complete snapshot bridge");
                    let payload = prefetched_snapshot_tail_terminal
                        .take()
                        .expect("checked prefetched bridge terminal");
                    let terminal_from = payload.from;
                    let terminal_request_token = payload.token;
                    match staging.finalize(
                        payload.terminal_bytes,
                        payload.inbound_memory_permit,
                    ) {
                        Ok(tail) => (
                            Some(tail),
                            Some(terminal_from),
                            Some(terminal_request_token),
                        ),
                        Err(error) => {
                            cleanup_finalized_snapshot_staging_offthread(finalized);
                            let terminal_rejected =
                                matches!(&error, SnapshotTailFinalizeError::Terminal(_));
                            if terminal_rejected {
                                rejected_terminal_peers.insert(terminal_from);
                                manifest_terminal_capabilities.remove(&terminal_from);
                            }
                            let _ = p2p_cmd
                                .send(noid_p2p::NetworkCommand::CancelHistoryStepTerminalRace {
                                    token: terminal_request_token,
                                })
                                .await;
                            tracing::warn!(
                                manifest_from = %finalized_from,
                                terminal_from = %terminal_from,
                                err = %error,
                                "snapshot bridge terminal rejected"
                            );
                            reset_sync_state!();
                            if terminal_rejected {
                                request_bounded_manifest_failover!(terminal_from, false);
                            } else {
                                request_bounded_manifest_failover!(finalized_from, true);
                            }
                            continue;
                        }
                    }
                };
                start_snapshot_install!(
                    finalized,
                    segment_count,
                    finalized_from,
                    tail,
                    terminal_from,
                    terminal_request_token
                );
            }
        }};
    }

    // General header request deduplication is shared with compact-suffix
    // recovery, whose macro is defined below.
    let mut fetch_in_progress: std::collections::HashSet<libp2p::PeerId> =
        std::collections::HashSet::new();
    let mut recent_header_fetches: HashMap<(libp2p::PeerId, u64, u16), Instant> = HashMap::new();
    struct PendingBlockFetch {
        peer: libp2p::PeerId,
        requested_at: Instant,
    }
    let mut pending_block_fetches: HashMap<(u64, [u8; 32]), PendingBlockFetch> = HashMap::new();
    const BLOCK_FETCH_INFLIGHT_TTL: Duration = Duration::from_secs(8);
    // One bounded hint retained while compact catch-up owns canonical
    // mutation. It preserves an equal-height competing-fork signal without
    // retaining or validating payloads concurrently with the active suffix.
    let mut deferred_sync_peer: Option<libp2p::PeerId> = None;

    macro_rules! fallback_recent_suffix_to_full_bundles {
        ($reason:expr) => {{
            if let Some(pending) = pending_recent_suffix.take() {
                let _ = p2p_cmd
                    .send(noid_p2p::NetworkCommand::CancelHistoryStepTerminalRace {
                        token: pending.terminal_requests.primary.token,
                    })
                    .await;
                recent_suffix_generation = recent_suffix_generation.wrapping_add(1);
                let count = u16::try_from(
                    pending.target_height.saturating_sub(pending.base_height),
                )
                .expect("recent suffix span fits retained depth");
                let alternate = deferred_sync_peer
                    .take()
                    .filter(|peer| {
                        *peer != pending.peer
                            && manifest_peers.contains(peer)
                            && !rejected_terminal_peers.contains(peer)
                            && !finalized_divergent_peers.contains(peer)
                            && !fetch_in_progress.contains(peer)
                    })
                    .or_else(|| {
                        manifest_peers
                            .iter()
                            .copied()
                            .filter(|peer| *peer != pending.peer)
                            .filter(|peer| !rejected_terminal_peers.contains(peer))
                            .filter(|peer| !finalized_divergent_peers.contains(peer))
                            .filter(|peer| !fetch_in_progress.contains(peer))
                            .min_by_key(|peer| peer.to_bytes())
                    });
                if let Some(peer) = alternate {
                    let header_count = count.saturating_add(1);
                    let request_key = (peer, pending.base_height, header_count);
                    fetch_in_progress.insert(peer);
                    recent_header_fetches.insert(request_key, Instant::now());
                    tracing::warn!(
                        failed_peer = %pending.peer,
                        alternate = %peer,
                        base = pending.base_height,
                        target = pending.target_height,
                        reason = $reason,
                        "compact recent suffix abandoned — probing an alternate peer"
                    );
                    if p2p_cmd
                        .send(noid_p2p::NetworkCommand::FetchHeaders {
                            peer,
                            start_height: pending.base_height,
                            count: header_count,
                        })
                        .await
                        .is_err()
                    {
                        fetch_in_progress.remove(&peer);
                        recent_header_fetches.remove(&request_key);
                    }
                } else {
                    tracing::warn!(
                        peer = %pending.peer,
                        base = pending.base_height,
                        target = pending.target_height,
                        reason = $reason,
                        "compact recent suffix abandoned — no alternate peer, requesting complete bundles"
                    );
                    let _ = p2p_cmd
                        .send(noid_p2p::NetworkCommand::SyncBlocksFrom {
                            peer: pending.peer,
                            from_height: pending.base_height.saturating_add(1),
                            count,
                        })
                        .await;
                }
            }
        }};
    }

    // A branch can advance while its proof-sized bundles are downloaded one
    // at a time.  Retire the stale exact session and ask one rotating peer for
    // a fresh linked header view from the already authenticated ancestor.
    macro_rules! retry_shallow_fork_headers {
        ($pending:expr, $reason:expr) => {{
            let pending: PendingShallowFork = $pending;
            pending_block_fetches.retain(|_, request| request.peer != pending.peer);
            // General header responses are peer-correlated rather than
            // request-token-correlated at this layer. Never open a second
            // same-peer lane while an earlier general request is live.
            let mut excluded = rejected_terminal_peers
                .union(&finalized_divergent_peers)
                .copied()
                .collect::<std::collections::HashSet<_>>();
            excluded.extend(fetch_in_progress.iter().copied());
            let peer = rotating_manifest_peers(
                &manifest_peers,
                &excluded,
                Some(pending.peer),
                true,
                &mut steady_tip_probe_cursor,
                1,
            )
            .into_iter()
            .next();
            if let Some(peer) = peer {
                let span = pending
                    .tip_height()
                    .saturating_sub(pending.ancestor_height)
                    .saturating_add(3)
                    .max(u64::from(CONNECTED_TIP_PROBE_HEADERS));
                let count = u16::try_from(span.min(512)).expect("bounded header retry span");
                let request_key = (peer, pending.ancestor_height, count);
                fetch_in_progress.insert(peer);
                recent_header_fetches.insert(request_key, Instant::now());
                let dispatched = p2p_cmd
                    .send(noid_p2p::NetworkCommand::FetchHeaders {
                        peer,
                        start_height: pending.ancestor_height,
                        count,
                    })
                    .await
                    .is_ok();
                if !dispatched {
                    fetch_in_progress.remove(&peer);
                    recent_header_fetches.remove(&request_key);
                }
                tracing::warn!(
                    failed_peer = %pending.peer,
                    retry_peer = %peer,
                    ancestor = pending.ancestor_height,
                    old_tip = pending.tip_height(),
                    dispatched,
                    reason = $reason,
                    "moving shallow-fork session retired; probing one fresh header view"
                );
            } else {
                tracing::warn!(
                    failed_peer = %pending.peer,
                    ancestor = pending.ancestor_height,
                    reason = $reason,
                    "moving shallow-fork session retired; no dispatchable retry peer"
                );
            }
        }};
    }

    // Keep the native-validated header suffix and every already downloaded
    // bundle when one source cannot serve the next exact block. Only one body
    // request remains active: peers are tried sequentially, and every response
    // is still bound to the fixed expected header hash before it is retained.
    macro_rules! retry_shallow_fork_bundle_peer {
        ($failed_peer:expr, $reason:expr) => {{
            let failed_peer = $failed_peer;
            let alternate_request = pending_shallow_fork.as_mut().and_then(|pending| {
                if pending.peer != failed_peer {
                    return None;
                }
                pending.attempted_bundle_peers.insert(failed_peer);
                let mut excluded = rejected_terminal_peers
                    .union(&finalized_divergent_peers)
                    .copied()
                    .collect::<std::collections::HashSet<_>>();
                excluded.extend(pending.attempted_bundle_peers.iter().copied());
                let alternate = rotating_manifest_peers(
                    &manifest_peers,
                    &excluded,
                    Some(failed_peer),
                    false,
                    &mut steady_tip_probe_cursor,
                    1,
                )
                .into_iter()
                .next()?;
                pending.peer = alternate;
                let expected = pending.expected_header().copied()?;
                Some((
                    alternate,
                    expected.height,
                    noid_chain::consensus::pow::block_id(&expected),
                    pending.candidates.len(),
                    pending.tip_height(),
                ))
            });

            if let Some((peer, height, expected_hash, retained_blocks, tip_height)) =
                alternate_request
            {
                pending_block_fetches.insert(
                    (height, expected_hash),
                    PendingBlockFetch {
                        peer,
                        requested_at: Instant::now(),
                    },
                );
                let dispatched = p2p_cmd
                    .send(noid_p2p::NetworkCommand::RequestBlock { peer, height })
                    .await
                    .is_ok();
                if !dispatched {
                    pending_block_fetches.remove(&(height, expected_hash));
                }
                tracing::warn!(
                    failed_peer = %failed_peer,
                    alternate_peer = %peer,
                    height,
                    tip_height,
                    retained_blocks,
                    dispatched,
                    reason = $reason,
                    "continuing fixed shallow-fork bundle download from an alternate peer"
                );
                dispatched
            } else {
                false
            }
        }};
    }

    // If the first exact replacement bundle has already aged out, the peer
    // cannot complete an ordinary reorg even though its header chain is valid.
    // Preserve the authenticated common ancestor and switch one peer onto the
    // snapshot path.  The durable installer rechecks this hint against current
    // canonical finality and cumulative work before it may truncate a suffix.
    macro_rules! request_snapshot_rebase {
        ($pending:expr, $reason:expr) => {{
            let pending: PendingShallowFork = $pending;
            let hint = SnapshotRebaseHint {
                ancestor_height: pending.ancestor_height,
                ancestor_hash: pending.ancestor_hash,
                competing_tip_height: pending.tip_height(),
                competing_tip_hash: pending.tip_hash(),
                armed_at: Instant::now(),
            };
            snapshot_rebase_hint = Some(hint);
            pending_block_fetches.retain(|_, request| request.peer != pending.peer);
            clear_manifest_round_state!();
            let excluded = rejected_terminal_peers
                .union(&finalized_divergent_peers)
                .copied()
                .collect::<std::collections::HashSet<_>>();
            // Keep manifest, exact headers and State on the same authenticated
            // branch whenever its source is still usable. An arbitrary
            // alternate may be healthy but currently follow another fork.
            let peer = manifest_peers
                .contains(&pending.peer)
                .then_some(pending.peer)
                .filter(|peer| !excluded.contains(peer))
                .or_else(|| {
                    rotating_manifest_peers(
                        &manifest_peers,
                        &excluded,
                        Some(pending.peer),
                        false,
                        &mut manifest_retry_cursor,
                        1,
                    )
                    .into_iter()
                    .next()
                });
            if let Some(peer) = peer {
                manifest_requested_peers.insert(peer);
                manifest_force_snapshot_peers.insert(peer);
                manifest_round_started_at = Some(Instant::now());
                let our_height = {
                    let ctx = chain.read().await;
                    ctx.tip_height()
                };
                let _ = p2p_cmd
                    .send(noid_p2p::NetworkCommand::RequestStateManifest {
                        generation: snapshot_sync_generation,
                        peer,
                        requester_height: our_height,
                    })
                    .await;
                tracing::warn!(
                    failed_peer = %pending.peer,
                    snapshot_peer = %peer,
                    ancestor = hint.ancestor_height,
                    competing_tip = hint.competing_tip_height,
                    competing_tip_hash = %hex::encode(hint.competing_tip_hash),
                    reason = $reason,
                    "selected fork bundle aged out; requesting divergence-aware snapshot"
                );
            } else {
                tracing::warn!(
                    failed_peer = %pending.peer,
                    ancestor = hint.ancestor_height,
                    reason = $reason,
                    "snapshot rebase armed; no dispatchable manifest peer"
                );
            }
        }};
    }

    macro_rules! try_start_recent_suffix_apply {
        () => {{
            let ready = pending_recent_suffix.as_ref().is_some_and(|pending| {
                !pending.body_request_active
                    && !pending.append_active
                    && pending.staging.is_some()
                    && pending.terminal_payload.is_some()
            });
            if ready {
                let mut pending = pending_recent_suffix
                    .take()
                    .expect("checked complete recent suffix");
                let staging = pending
                    .staging
                    .take()
                    .expect("checked staged recent suffix bodies");
                let payload = pending
                    .terminal_payload
                    .take()
                    .expect("checked recent suffix terminal");
                let terminal_from = payload.from;
                let terminal_request_token = payload.token;
                if staging.tip_height() != pending.target_height
                    || staging.tip_hash() != pending.target_hash
                {
                    let _ = p2p_cmd
                        .send(noid_p2p::NetworkCommand::CancelHistoryStepTerminalRace {
                            token: terminal_request_token,
                        })
                        .await;
                    drop(staging);
                    drop(payload);
                    let reason = "staged compact suffix does not match advertised tip";
                    pending_recent_suffix = Some(pending);
                    fallback_recent_suffix_to_full_bundles!(reason);
                    continue;
                }
                let tail = match staging.finalize(
                    payload.terminal_bytes,
                    payload.inbound_memory_permit,
                ) {
                    Ok(tail) => tail,
                    Err(error) => {
                        if matches!(&error, SnapshotTailFinalizeError::Terminal(_)) {
                            rejected_terminal_peers.insert(terminal_from);
                            manifest_terminal_capabilities.remove(&terminal_from);
                        }
                        let _ = p2p_cmd
                            .send(noid_p2p::NetworkCommand::CancelHistoryStepTerminalRace {
                                token: terminal_request_token,
                            })
                            .await;
                        let reason = format!("compact suffix terminal binding failed: {error}");
                        pending_recent_suffix = Some(pending);
                        fallback_recent_suffix_to_full_bundles!(&reason);
                        continue;
                    }
                };
                let key = RecentSuffixApplyKey {
                    generation: pending.generation,
                    peer: pending.peer,
                    terminal_from,
                    terminal_request_token,
                    base_height: pending.base_height,
                    target_height: pending.target_height,
                };
                recent_suffix_apply_inflight = Some(key);
                let apply_chain = Arc::clone(&chain);
                let apply_mempool = mempool.clone();
                let apply_wallet = Arc::clone(&wallet);
                let apply_gate = Arc::clone(&wallet_operation_gate);
                let apply_runtime = history_step_runtime.clone();
                let completion = recent_suffix_apply_tx.clone();
                tokio::spawn(async move {
                    let result = apply_compact_suffix_offthread(
                        &apply_chain,
                        &apply_mempool,
                        &apply_wallet,
                        tail,
                        key.base_height,
                        pending.base_hash,
                        apply_runtime,
                        &apply_gate,
                    )
                    .await;
                    let _ = completion
                        .send(RecentSuffixApplyCompletion { key, result })
                        .await;
                });
                tracing::info!(
                    peer = %key.peer,
                    base = key.base_height,
                    target = key.target_height,
                    blocks = key.target_height - key.base_height,
                    "applying exact compact recent suffix with one terminal"
                );
            }
        }};
    }

    // --- FetchHeaders in-progress guard ---
    //
    // Prevents FetchHeaders from being sent to the same peer thousands of
    // times during a block burst. Entry is removed when HeaderInventoryBatch
    // arrives
    // from that peer (or on disconnect).  Without this guard, 10 peers each
    // sending 40 blocks/s = 400 redundant FetchHeaders/s.
    // --- Per-peer tx rate limiter ---
    //
    // Sliding-window rate limiter: tracks (tx_count_in_window, window_start) per peer.
    // Prevents a single peer from flooding the proof-verification semaphore queue.
    // Short-lived dedup for fork-recovery pulls. During two-miner races the same
    // orphan/fork announcement can be observed many times before the local node
    // reorganizes. Without this, each observation re-sends identical header/block
    // requests and floods logs/P2P with no extra safety.
    let mut recent_block_fetches: HashMap<(libp2p::PeerId, u64), Instant> = HashMap::new();
    const FETCH_DEDUP_TTL: Duration = Duration::from_secs(15);

    let mut peer_tx_rate: HashMap<libp2p::PeerId, (u32, Instant)> = HashMap::new();
    const TX_RATE_WINDOW: Duration = Duration::from_secs(10);
    const TX_RATE_MAX: u32 = 50; // max 50 tx per peer per 10s window
    let mut tx_event_count: u32 = 0;

    // --- Per-peer BLOCK rate limiter ---
    //
    // Txs have a rate limit (50/10s). Blocks need one too: a malicious or
    // buggy peer can flood us with blocks, each requiring chain.write() and
    // full PoW/header validation.
    //
    // Limit: BLOCK_RATE_MAX blocks per peer per BLOCK_RATE_WINDOW.
    // During ASERT convergence (sudden 100x hashrate) blocks can come 20x
    // faster than normal for ~300s, so we allow up to 4/s (4 × BLOCK_TIME).
    let mut peer_block_rate: HashMap<libp2p::PeerId, (u32, Instant)> = HashMap::new();
    const BLOCK_RATE_WINDOW: Duration = Duration::from_secs(10);
    const BLOCK_RATE_MAX: u32 = 40; // 40 blocks per 10s = 4/s max per peer
    let mut block_event_count: u32 = 0;

    // --- Stale-tip detection ---
    //
    // In large networks, block requests may fail (peer doesn't have the block
    // yet, stream capacity hit, etc.) with no retry.  The stale-tip check
    // detects when our chain hasn't advanced despite seeing higher announcements
    // and re-requests from a random connected peer.
    let mut last_tip_advance: Instant = Instant::now();
    let mut highest_announced: u64 = 0;
    let mut last_announcement_peer: Option<libp2p::PeerId> = None;
    let mut bootstrap_complete_sent = false;

    // Raw announcement and manifest heights are routing hints only. This
    // target advances exclusively after native header validation or atomic
    // acceptance, so one dishonest peer cannot hold readiness or recovery at
    // an invented height.
    macro_rules! record_authenticated_height {
        ($height:expr, $peer:expr) => {{
            let height = $height;
            if height > highest_announced {
                highest_announced = height;
                sync_phase_telemetry.extend_suffix_target(height);
                last_announcement_peer = Some($peer);
            }
        }};
    }

    macro_rules! record_authenticated_reorg_height {
        ($old_tip:expr, $new_tip:expr, $peer:expr) => {{
            let old_tip = $old_tip;
            let new_tip = $new_tip;
            let next_highest =
                authenticated_height_after_reorg(highest_announced, old_tip, new_tip);
            if next_highest != highest_announced {
                highest_announced = next_highest;
                sync_phase_telemetry.extend_suffix_target(next_highest);
            }
            last_announcement_peer = Some($peer);
        }};
    }

    macro_rules! request_exact_tip_confirmation {
        ($peer:expr, $local_height:expr) => {{
            let peer = $peer;
            let local_height = $local_height;
            if !*initial_sync_ready.borrow()
                && local_height >= highest_announced
                && manifest_peers.contains(&peer)
            {
                let count = CONNECTED_TIP_PROBE_HEADERS;
                let request_key = (peer, local_height, count);
                let recently_requested = recent_header_fetches
                    .get(&request_key)
                    .is_some_and(|requested| requested.elapsed() < FETCH_DEDUP_TTL);
                if !fetch_in_progress.contains(&peer) && !recently_requested {
                    fetch_in_progress.insert(peer);
                    recent_header_fetches.insert(request_key, Instant::now());
                    if p2p_cmd
                        .send(noid_p2p::NetworkCommand::FetchHeaders {
                            peer,
                            start_height: local_height,
                            count,
                        })
                        .await
                        .is_ok()
                    {
                        mining_peer_quorum.mark_probe_sent(peer, Instant::now());
                        tracing::debug!(
                            peer = %peer,
                            local_height,
                            "requesting exact post-commit tip confirmation"
                        );
                    } else {
                        fetch_in_progress.remove(&peer);
                        recent_header_fetches.remove(&request_key);
                    }
                }
            }
        }};
    }

    macro_rules! mark_bootstrap_complete_if_caught_up {
        ($local_height:expr) => {{
            let local_height = $local_height;
            if !bootstrap_complete_sent
                && *initial_sync_ready.borrow()
                && local_height >= highest_announced
                && !manifest_peers.is_empty()
                && manifest_requested_peers.is_empty()
                && manifest_round_started_at.is_none()
                && best_manifest_candidate.is_none()
                && manifest_candidate_started_at.is_none()
                && pending_manifest.is_none()
                && pending_snapshot_header_sync.is_none()
                && snapshot_header_staging_inflight.is_none()
                && history_step_verification_inflight.is_none()
                && snapshot_staging_inflight.is_none()
                && snapshot_install_inflight.is_none()
                && snapshot_tail_request_inflight.is_none()
                && snapshot_tail_append_inflight.is_none()
                && snapshot_tail_terminal_inflight.is_none()
                && pending_recent_suffix.is_none()
                && recent_suffix_apply_inflight.is_none()
                && pending_segment_ids.is_empty()
                && segment_queue.is_empty()
            {
                if p2p_cmd
                    .send(noid_p2p::NetworkCommand::BootstrapComplete)
                    .await
                    .is_ok()
                {
                    bootstrap_complete_sent = true;
                    tracing::debug!(
                        local_height,
                        highest_announced,
                        "exact initial catch-up complete — bootstrap peers may be replaced"
                    );
                }
            }
        }};
    }

    // Heartbeat for time-dependent checks (manifest timeout, etc.)
    let mut heartbeat = tokio::time::interval(std::time::Duration::from_millis(500));
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    heartbeat.tick().await; // skip first

    loop {
        tokio::select! {
        rx_result = rx.recv() => { let rx_item = rx_result;
        match rx_item {
            Ok(header_event @ (NetworkEvent::BlockAnnouncement { .. }
                | NetworkEvent::HeaderAnnouncement { .. })) => {
                let (from, announced_header) = match header_event {
                    NetworkEvent::BlockAnnouncement { from, header } => (from, header),
                    NetworkEvent::HeaderAnnouncement { from, announcement } => {
                        (from, announcement.header)
                    }
                    _ => unreachable!("matched header announcement event"),
                };
                let height = announced_header.height;
                if selected_snapshot_peer!().is_some_and(|selected| selected != from) {
                    deferred_sync_peer = Some(from);
                    continue;
                }
                if pending_recent_suffix.is_some() || recent_suffix_apply_inflight.is_some() {
                    deferred_sync_peer = Some(from);
                    continue;
                }
                if pending_manifest.is_some() {
                    // The authenticated manifest owns one immutable bridge.
                    // Do not chase a moving live tip while state is staging;
                    // post-install compact catch-up handles newer blocks.
                    continue;
                }
                if snapshot_install_inflight.is_some() {
                    tracing::debug!(
                        peer = %from,
                        height,
                        "snapshot install active — deferring block pull until post-install sync"
                    );
                    continue;
                }
                // Compact block announcement: validate the advertised header before
                // downloading a potentially large accepted bundle. Direct-next
                // headers can be fully checked against the current tip; larger recent
                // gaps first pull headers, then bodies are requested only for the
                // verified competing chain in the HeaderInventoryBatch path.
                let our_height = {
                    let ctx = chain.read().await;
                    ctx.tip_height()
                };
                if height <= our_height {
                    continue;
                }

                if gap_requires_snapshot_sync(our_height, height) {
                    tracing::info!(
                        their_height = height,
                        our_height,
                        retention = noid_chain::consensus::params::RECENT_BLOCK_RETENTION_DEPTH,
                        peer = %from,
                        "deep gap beyond retained-block window — requesting snapshot manifest"
                    );
                    if pending_manifest.is_none()
                        && pending_snapshot_header_sync.is_none()
                        && snapshot_header_staging_inflight.is_none()
                        && history_step_verification_inflight.is_none()
                        && snapshot_staging_inflight.is_none()
                        && snapshot_install_inflight.is_none()
                        && pending_segment_ids.is_empty()
                        && segment_queue.is_empty()
                        && manifest_requested_peers.insert(from)
                    {
                        manifest_force_snapshot_peers.insert(from);
                        let _ = p2p_cmd
                            .send(noid_p2p::NetworkCommand::RequestStateManifest {
                                generation: snapshot_sync_generation,
                                peer: from,
                                requester_height: our_height,
                            })
                            .await;
                    }
                    continue;
                } else if height == our_height + 1 {
                    let precheck = {
                        let ctx = chain.read().await;
                        let parent = *ctx.tip_header();
                        let prev_timestamps = ctx.prev_timestamps();
                        let anchor = ctx.anchor_info();
                        let local_time = unix_now();
                        match ctx.finalized_active_counts() {
                            Ok(finalized_active_counts) => {
                                Some(noid_chain::consensus::validate_header(
                                    &announced_header,
                                    &parent,
                                    &prev_timestamps,
                                    &finalized_active_counts,
                                    local_time,
                                    anchor.anchor_height,
                                    anchor.anchor_timestamp,
                                    &anchor.anchor_target,
                                ))
                            }
                            Err(error) => {
                                tracing::error!(
                                    err = %error,
                                    "canonical finalized expansion window is unavailable"
                                );
                                None
                            }
                        }
                    };
                    let Some(precheck) = precheck else {
                        continue;
                    };
                    if let Err(e) = precheck {
                        if e == noid_chain::consensus::ConsensusError::BadParentHash {
                            // A valid-looking child of another same-height tip is
                            // the normal shape of a two-miner race.  Do not pull
                            // its large body against the wrong pre-state; first
                            // recover a linked header suffix and common ancestor.
                            let fetch_from =
                                our_height.saturating_sub(CONSENSUS_FINALITY_DEPTH);
                            let fetch_count =
                                (CONSENSUS_FINALITY_DEPTH as u16 * 2).min(512);
                            let request_key = (from, fetch_from, fetch_count);
                            let recently_requested = recent_header_fetches
                                .get(&request_key)
                                .is_some_and(|t| t.elapsed() < FETCH_DEDUP_TTL);
                            if !recently_requested && !fetch_in_progress.contains(&from) {
                                fetch_in_progress.insert(from);
                                recent_header_fetches.insert(request_key, Instant::now());
                                tracing::info!(
                                    peer = %from,
                                    our_height,
                                    announced_height = height,
                                    fetch_from,
                                    "competing parent announced — fetching headers for fork choice"
                                );
                                let _ = p2p_cmd
                                    .send(noid_p2p::NetworkCommand::FetchHeaders {
                                        peer: from,
                                        start_height: fetch_from,
                                        count: fetch_count,
                                    })
                                    .await;
                            }
                        } else {
                            tracing::debug!(
                                peer = %from,
                                height,
                                err = %e,
                                "compact block header precheck failed — not pulling block body"
                            );
                        }
                        continue;
                    }

                    // Only a fully native-validated child may become a sync
                    // target. Raw announcement heights never affect readiness
                    // or stale-tip recovery.
                    record_authenticated_height!(height, from);

                    let fetch_key = (
                        height,
                        noid_chain::consensus::pow::block_id(&announced_header),
                    );
                    if let Some(pending) = pending_block_fetches.get(&fetch_key) {
                        if pending.requested_at.elapsed() < BLOCK_FETCH_INFLIGHT_TTL {
                            tracing::debug!(
                                peer = %from,
                                pending_peer = %pending.peer,
                                height,
                                "accepted block bundle already in-flight — suppressing duplicate pull"
                            );
                            continue;
                        }
                    }
                    pending_block_fetches.insert(
                        fetch_key,
                        PendingBlockFetch {
                            peer: from,
                            requested_at: Instant::now(),
                        },
                    );
                    let _ = p2p_cmd
                        .send(noid_p2p::NetworkCommand::RequestBlock { peer: from, height })
                        .await;
                } else {
                    // Recent gap > 1: pull headers first so complete block bundles are
                    // requested only after the header chain is anchored to our tip.
                    let count = (height - our_height + 1).min(512) as u16;
                    let request_key = (from, our_height, count);
                    let recently_requested = recent_header_fetches
                        .get(&request_key)
                        .is_some_and(|t| t.elapsed() < FETCH_DEDUP_TTL);
                    if fetch_in_progress.contains(&from) || recently_requested {
                        tracing::debug!(peer = %from, height, our_height, "header fetch already in-flight for compact gap");
                        continue;
                    }
                    fetch_in_progress.insert(from);
                    recent_header_fetches.insert(request_key, Instant::now());
                    let _ = p2p_cmd
                        .send(noid_p2p::NetworkCommand::FetchHeaders {
                            peer: from,
                            start_height: our_height,
                            count,
                        })
                        .await;
                }
            }
            Ok(NetworkEvent::ObjectsResponse {
                token,
                from,
                objects,
                mut inbound_memory_permit,
            }) => {
                tracing::debug!(
                    token,
                    peer = %from,
                    objects = objects.len(),
                    "dropping exact-object response without an active v2 plan"
                );
                drop(objects);
                drop(inbound_memory_permit.take());
            }
            Ok(NetworkEvent::ObjectsRequestFailed {
                token,
                from,
                objects,
                kind,
            }) => {
                tracing::debug!(
                    token,
                    peer = %from,
                    objects = objects.len(),
                    ?kind,
                    "exact-object source lease failed without an active v2 plan"
                );
            }
            Ok(NetworkEvent::SnapshotBlockBodies {
                from,
                height: advertised_height,
                block_bodies,
                mut inbound_memory_permit,
            }) => {
                let advertised_count = u16::try_from(block_bodies.len())
                    .expect("P2P codec bounds snapshot block-body batch count");
                if let Some(pending) = pending_recent_suffix.as_mut() {
                    let expected_count =
                        u16::try_from(pending.target_height - pending.base_height)
                            .expect("recent suffix span fits u16");
                    let matches = pending.generation == recent_suffix_generation
                        && pending.peer == from
                        && pending.body_request_active
                        && !pending.append_active
                        && pending.staging.is_some()
                        && advertised_height == pending.base_height.saturating_add(1)
                        && advertised_count == expected_count;
                    if !matches {
                        let correlated_invalid = pending.generation == recent_suffix_generation
                            && pending.peer == from
                            && pending.body_request_active
                            && advertised_height == pending.base_height.saturating_add(1);
                        drop(block_bodies);
                        drop(inbound_memory_permit.take());
                        tracing::warn!(
                            peer = %from,
                            advertised_height,
                            advertised_count,
                            expected_count,
                            correlated_invalid,
                            "dropping stale or mismatched compact recent body batch"
                        );
                        if correlated_invalid {
                            fallback_recent_suffix_to_full_bundles!(
                                "compact suffix body batch violated its exact request"
                            );
                        }
                        continue;
                    }
                    let staging = pending
                        .staging
                        .take()
                        .expect("matched recent suffix owns body staging");
                    let expected_headers = pending.expected_headers.clone();
                    let generation = pending.generation;
                    pending.body_request_active = false;
                    pending.append_active = true;
                    let completion = recent_suffix_append_tx.clone();
                    let inbound_permit = inbound_memory_permit.take();
                    tokio::task::spawn_blocking(move || {
                        let result =
                            std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                                if block_bodies.len() != expected_headers.len() {
                                    drop(inbound_permit);
                                    return Err(
                                        "compact suffix body/header count mismatch".to_owned()
                                    );
                                }
                                for (body, expected_header) in
                                    block_bodies.iter().zip(&expected_headers)
                                {
                                    let block = noid_chain::Block::from_bytes(body).map_err(
                                        |error| {
                                            format!(
                                                "decode compact suffix body for header match: {error:?}"
                                            )
                                        },
                                    )?;
                                    if block.header != *expected_header {
                                        return Err(
                                            "compact suffix body differs from authenticated header"
                                                .to_owned(),
                                        );
                                    }
                                }
                                let result = staging.append_batch(block_bodies);
                                drop(inbound_permit);
                                result
                            }))
                            .map_err(|_| "compact suffix append worker panicked".to_owned())
                            .and_then(|result| result);
                        let _ = completion.blocking_send(RecentSuffixAppendCompletion {
                            generation,
                            result,
                        });
                    });
                    continue;
                }
                let request_correlated = snapshot_tail_request_inflight.is_some_and(|request| {
                    request.generation == snapshot_sync_generation
                        && request.from == from
                        && request.height == advertised_height
                });
                let request_matches = request_correlated
                    && snapshot_tail_request_inflight
                        .is_some_and(|request| request.count == advertised_count);
                let expected_height = snapshot_tail_staging
                    .as_ref()
                    .map(SnapshotTailStaging::next_height);
                let selected_peer_matches = pending_manifest
                    .as_ref()
                    .is_some_and(|pending| pending.from == from);
                if !request_matches
                    || !selected_peer_matches
                    || expected_height != Some(advertised_height)
                    || snapshot_tail_append_inflight.is_some()
                    || snapshot_install_inflight.is_some()
                {
                    drop(block_bodies);
                    drop(inbound_memory_permit.take());
                    tracing::warn!(
                        peer = %from,
                        advertised_height,
                        advertised_count,
                        ?expected_height,
                        "dropping stale or mismatched snapshot block-body batch"
                    );
                    if request_correlated {
                        preserve_active_snapshot_headers!();
                        reset_sync_state!();
                        request_bounded_manifest_failover!(from, false);
                    }
                    continue;
                }
                snapshot_tail_request_inflight = None;
                request_snapshot_tail_terminal!(from);
                stage_snapshot_tail_bodies!(
                    from,
                    advertised_height,
                    block_bodies,
                    inbound_memory_permit.take()
                );
                continue;
            }
            Ok(
                block_event @ (NetworkEvent::IncomingBlock { .. }
                | NetworkEvent::RecentBlock { .. }),
            ) => {
                let (from, bundle, mut inbound_memory_permit) = match block_event {
                    NetworkEvent::IncomingBlock {
                        from,
                        bundle,
                        inbound_memory_permit,
                    }
                    | NetworkEvent::RecentBlock {
                        from,
                        bundle,
                        inbound_memory_permit,
                    } => (from, bundle, inbound_memory_permit),
                    _ => unreachable!("matched accepted-block event"),
                };
                let advertised_height = bundle.height();
                if selected_snapshot_peer!().is_some_and(|selected| selected != from) {
                    deferred_sync_peer = Some(from);
                    drop(bundle);
                    drop(inbound_memory_permit.take());
                    continue;
                }
                if snapshot_install_inflight.is_some() {
                    // Atomic snapshot installation owns the chain/mempool/wallet
                    // replacement order.  Release this pulled payload now; the
                    // install task requests the retained suffix after commit.
                    drop(bundle);
                    drop(inbound_memory_permit.take());
                    tracing::debug!(
                        peer = %from,
                        "snapshot install active — released block response for post-install retry"
                    );
                    continue;
                }
                if pending_recent_suffix.is_some() || recent_suffix_apply_inflight.is_some() {
                    deferred_sync_peer = Some(from);
                    drop(bundle);
                    drop(inbound_memory_permit.take());
                    tracing::debug!(
                        peer = %from,
                        height = advertised_height,
                        "compact recent suffix owns canonical mutation — releasing full bundle"
                    );
                    continue;
                }
                // Per-peer block rate limit: prevents flood DoS.
                // Each block requires chain.write() + PoW validation.
                {
                    let now = Instant::now();
                    let entry = peer_block_rate.entry(from).or_insert((0, now));
                    if now.duration_since(entry.1) > BLOCK_RATE_WINDOW {
                        *entry = (1, now);
                    } else if entry.0 >= BLOCK_RATE_MAX {
                        tracing::debug!(peer = %from, "block rate limit exceeded, dropping");
                        continue;
                    } else {
                        entry.0 += 1;
                    }
                }
                // Periodic cleanup of stale entries.
                block_event_count += 1;
                if block_event_count.is_multiple_of(200) {
                    let cutoff = Instant::now() - Duration::from_secs(60);
                    peer_block_rate.retain(|_, (_, t)| *t >= cutoff);
                }

                if pending_manifest.is_some() {
                    // Snapshot catch-up owns canonical mutation. Full bundles
                    // announced in parallel are deliberately ignored; the
                    // compact suffix is advanced only by correlated body pulls.
                    drop(bundle);
                    drop(inbound_memory_permit.take());
                    continue;
                }

                tracing::debug!(peer = %from, "received block from P2P");
                let AcceptedBlockCandidate { block, bundle } =
                    AcceptedBlockCandidate::from_bundle(bundle);
                        // Keep the inbound permit until the complete candidate is
                        // committed, rejected, or transferred to the byte-capped
                        // orphan pool.
                        let local_time = unix_now();
                        let block_hash = noid_chain::consensus::pow::block_id(&block.header);
                        pending_block_fetches.remove(&(block.header.height, block_hash));

                        // A shallow-fork session owns exactly one requested
                        // bundle at a time.  Do not validate that bundle against
                        // the current competing state: coinbase/state anchors
                        // necessarily belong to the common ancestor branch and
                        // would fail before BadParentHash.  Instead bind every
                        // response to the already linked header suffix, retain
                        // it under the orphan-byte cap, and atomically validate
                        // the complete replacement through apply_reorg_mdbx.
                        let expected_shallow = pending_shallow_fork
                            .as_ref()
                            .filter(|pending| pending.peer == from)
                            .and_then(|pending| pending.expected_header().copied());
                        if let Some(expected_header) = expected_shallow {
                            if block.header.height == expected_header.height {
                                let expected_hash =
                                    noid_chain::consensus::pow::block_id(&expected_header);
                                if block_hash != expected_hash {
                                    tracing::warn!(
                                        peer = %from,
                                        height = block.header.height,
                                        expected_hash = %hex::encode(expected_hash),
                                        received_hash = %hex::encode(block_hash),
                                        "shallow-fork bundle does not match requested header"
                                    );
                                    drop(bundle);
                                    drop(inbound_memory_permit.take());
                                    if retry_shallow_fork_bundle_peer!(
                                        from,
                                        "requested peer returned a different block"
                                    ) {
                                        continue;
                                    }
                                    let stale = pending_shallow_fork
                                        .take()
                                        .expect("mismatched shallow-fork session exists");
                                    retry_shallow_fork_headers!(
                                        stale,
                                        "all bundle peers exhausted after a mismatched response"
                                    );
                                    continue;
                                }

                                let candidate = AcceptedBlockCandidate { block, bundle };
                                let candidate_bytes = candidate.retained_bytes();
                                let exceeds_bound = pending_shallow_fork
                                    .as_ref()
                                    .is_none_or(|pending| {
                                        pending
                                            .retained_bytes
                                            .checked_add(candidate_bytes)
                                            .is_none_or(|total| total > MAX_ORPHAN_POOL_BYTES)
                                    });
                                if exceeds_bound {
                                    tracing::warn!(
                                        peer = %from,
                                        height = candidate.block.header.height,
                                        candidate_bytes,
                                        max_bytes = MAX_ORPHAN_POOL_BYTES,
                                        "shallow-fork replacement exceeds bounded retained bytes"
                                    );
                                    pending_shallow_fork = None;
                                    drop(candidate);
                                    drop(inbound_memory_permit.take());
                                    continue;
                                }

                                {
                                    let pending = pending_shallow_fork
                                        .as_mut()
                                        .expect("matched shallow-fork session exists");
                                    pending.retained_bytes += candidate_bytes;
                                    pending.candidates.push(candidate);
                                    pending.attempted_bundle_peers.clear();
                                    pending.last_progress_at = Instant::now();
                                }
                                // From here the explicit fork-session byte cap
                                // owns accounting for retained candidate bytes.
                                drop(inbound_memory_permit.take());

                                if let Some(next_header) = pending_shallow_fork
                                    .as_ref()
                                    .and_then(|pending| pending.expected_header().copied())
                                {
                                    let next_hash =
                                        noid_chain::consensus::pow::block_id(&next_header);
                                    let peer = pending_shallow_fork
                                        .as_ref()
                                        .expect("shallow-fork session remains active")
                                        .peer;
                                    pending_block_fetches.insert(
                                        (next_header.height, next_hash),
                                        PendingBlockFetch {
                                            peer,
                                            requested_at: Instant::now(),
                                        },
                                    );
                                    tracing::debug!(
                                        peer = %peer,
                                        height = next_header.height,
                                        "requesting next shallow-fork bundle"
                                    );
                                    let _ = p2p_cmd
                                        .send(noid_p2p::NetworkCommand::RequestBlock {
                                            peer,
                                            height: next_header.height,
                                        })
                                        .await;
                                    continue;
                                }

                                let completed = pending_shallow_fork
                                    .take()
                                    .expect("complete shallow-fork session exists");
                                let new_tip_height = completed.tip_height();
                                let new_tip_hash = completed.tip_hash();
                                let (
                                    our_tip_height,
                                    our_tip_hash,
                                    canonical_ancestor,
                                    our_extra_work,
                                ) = {
                                    use noid_chain::{add_work, block_work};
                                    let ctx = chain.read().await;
                                    let our_tip_height = ctx.tip_height();
                                    let canonical_ancestor = ctx
                                        .recent_headers
                                        .get(&completed.ancestor_height)
                                        .map(noid_chain::consensus::pow::block_id);
                                    let mut work = [0u8; 32];
                                    if completed.ancestor_height <= our_tip_height {
                                        for height in
                                            (completed.ancestor_height + 1)..=our_tip_height
                                        {
                                            let Some(header) = ctx.recent_headers.get(&height)
                                            else {
                                                work = [0xFF; 32];
                                                break;
                                            };
                                            work = add_work(
                                                &work,
                                                &block_work(&header.difficulty_target),
                                            );
                                        }
                                    } else {
                                        work = [0xFF; 32];
                                    }
                                    (our_tip_height, ctx.tip_hash(), canonical_ancestor, work)
                                };

                                if canonical_ancestor != Some(completed.ancestor_hash) {
                                    tracing::debug!(
                                        peer = %completed.peer,
                                        ancestor = completed.ancestor_height,
                                        "shallow-fork ancestor changed while bundles were downloading"
                                    );
                                    retry_shallow_fork_headers!(
                                        completed,
                                        "canonical ancestor changed during bundle download"
                                    );
                                    continue;
                                }
                                let should_reorg = competing_suffix_wins(
                                    &completed.advertised_work,
                                    &new_tip_hash,
                                    &our_extra_work,
                                    &our_tip_hash,
                                );
                                if !should_reorg {
                                    tracing::debug!(
                                        peer = %completed.peer,
                                        our_tip = our_tip_height,
                                        competing_tip = new_tip_height,
                                        "downloaded shallow fork no longer beats canonical work"
                                    );
                                    drop(completed);
                                    continue;
                                }

                                tracing::info!(
                                    our_tip = our_tip_height,
                                    new_tip = new_tip_height,
                                    ancestor = completed.ancestor_height,
                                    blocks = completed.candidates.len(),
                                    peer = %completed.peer,
                                    "reorg: downloaded shallow fork wins canonical fork choice, reorganising"
                                );
                                let _wallet_operation = wallet_operation_gate.lock().await;
                                let (reorg_reserved_inputs, reorg_reserved_outputs) =
                                    mempool.reserved_slots().await;
                                let reorg_result = apply_reorg_offthread(
                                    &chain,
                                    &wallet,
                                    reorg_reserved_inputs,
                                    reorg_reserved_outputs,
                                    completed.ancestor_height,
                                    completed.candidates,
                                    unix_now(),
                                    history_step_runtime.clone(),
                                )
                                .await;

                                match reorg_result {
                                    Ok(applied_reorg) => {
                                        snapshot_rebase_hint = None;
                                        mining_peer_quorum
                                            .set_canonical_tip(new_tip_height, new_tip_hash);
                                        record_authenticated_reorg_height!(
                                            our_tip_height,
                                            new_tip_height,
                                            from
                                        );
                                        external_mining_attempts
                                            .invalidate_for_tip(new_tip_height, new_tip_hash);
                                        mempool
                                            .on_new_block(
                                                &applied_reorg.confirmed_tx_hashes,
                                                new_tip_height,
                                                applied_reorg.view,
                                            )
                                            .await;
                                        let reverted =
                                            applied_reorg.result.reverted_heights.len();
                                        let applied =
                                            applied_reorg.result.applied_heights.len();
                                        mempool
                                            .readmit_after_reorg(
                                                applied_reorg.result.reclaimed_tx_hashes,
                                            )
                                            .await;
                                        last_tip_advance = Instant::now();
                                        request_exact_tip_confirmation!(from, new_tip_height);
                                        mining_peer_quorum.confirm_tip(
                                            from,
                                            new_tip_height,
                                            new_tip_hash,
                                        );
                                        let _ = template_changes.send(());
                                        tracing::info!(
                                            new_tip = new_tip_height,
                                            reverted,
                                            applied,
                                            "reorg complete"
                                        );
                                    }
                                    Err((error, rejected_chain)) => {
                                        drop(rejected_chain);
                                        tracing::warn!(
                                            peer = %from,
                                            err = ?error,
                                            "downloaded shallow-fork reorg failed, keeping current chain"
                                        );
                                    }
                                }
                                continue;
                            }
                        }

                        // Skip blocks at or below our current tip — we already have them.
                        // This avoids expensive proof verification against a stale pre-state.
                        let next_block_competing_parent = {
                            let (our_tip, our_tip_hash) = {
                                let ctx = chain.read().await;
                                (ctx.tip_height(), ctx.tip_hash())
                            };
                            if block.header.height <= our_tip {
                                tracing::debug!(
                                    peer = %from,
                                    height = block.header.height,
                                    our_tip,
                                    "dropping duplicate/stale block (already at tip)"
                                );
                                continue;
                            }

                            // Inline bundles are themselves block announcements.  A
                            // gossip mesh may legitimately deliver height N+1 after
                            // dropping N, so do not run the expensive state-bound
                            // verification against the wrong pre-state.  Retain the
                            // bounded orphan and use the same authenticated header
                            // probe/direct suffix path as compact announcements.
                            if block.header.height > our_tip.saturating_add(1) {
                                let block_height = block.header.height;
                                let candidate = AcceptedBlockCandidate { block, bundle };
                                if gap_requires_snapshot_sync(our_tip, block_height) {
                                    drop(candidate);
                                    drop(inbound_memory_permit.take());
                                    tracing::info!(
                                        peer = %from,
                                        our_tip,
                                        peer_tip = block_height,
                                        retention = noid_chain::consensus::params::RECENT_BLOCK_RETENTION_DEPTH,
                                        "complete block exposed deep gap — requesting snapshot manifest"
                                    );
                                    if pending_manifest.is_none()
                                        && pending_snapshot_header_sync.is_none()
                                        && snapshot_header_staging_inflight.is_none()
                                        && history_step_verification_inflight.is_none()
                                        && snapshot_staging_inflight.is_none()
                                        && snapshot_install_inflight.is_none()
                                        && pending_segment_ids.is_empty()
                                        && segment_queue.is_empty()
                                        && manifest_requested_peers.insert(from)
                                    {
                                        manifest_force_snapshot_peers.insert(from);
                                        let _ = p2p_cmd
                                            .send(noid_p2p::NetworkCommand::RequestStateManifest {
                                                generation: snapshot_sync_generation,
                                                peer: from,
                                                requester_height: our_tip,
                                            })
                                            .await;
                                    }
                                    continue;
                                }

                                // The orphan pool owns its own strict byte cap, so
                                // release the transport reservation before probing.
                                drop(inbound_memory_permit.take());
                                insert_orphan(
                                    &mut orphan_pool,
                                    OrphanBlock::from_candidate(candidate),
                                );

                                let count = (block_height - our_tip + 1).min(512) as u16;
                                let request_key = (from, our_tip, count);
                                let recently_requested = recent_header_fetches
                                    .get(&request_key)
                                    .is_some_and(|t| t.elapsed() < FETCH_DEDUP_TTL);
                                if !fetch_in_progress.contains(&from) && !recently_requested {
                                    fetch_in_progress.insert(from);
                                    recent_header_fetches.insert(request_key, Instant::now());
                                    tracing::info!(
                                        peer = %from,
                                        our_tip,
                                        block_height,
                                        "complete block exposed recent gap — fetching linked headers"
                                    );
                                    let _ = p2p_cmd
                                        .send(noid_p2p::NetworkCommand::FetchHeaders {
                                            peer: from,
                                            start_height: our_tip,
                                            count,
                                        })
                                        .await;
                                }
                                continue;
                            }

                            next_block_has_competing_parent(
                                our_tip,
                                our_tip_hash,
                                &block.header,
                            )
                        };

                        let suffix_apply_started = Instant::now();
                        let candidate = AcceptedBlockCandidate { block, bundle };
                        let suffix_block_bytes = candidate.retained_bytes() as u64;
                        // Full bundle gossip can arrive without its compact header.
                        // On a competing parent, state-bound validation may report a
                        // coinbase/state-anchor error before it reaches parent hash
                        // validation. Route the intact candidate directly into the
                        // existing BadParentHash orphan/header-fork-choice path.
                        let apply_result = if next_block_competing_parent {
                            Err((
                                noid_chain::storage::MdbxContextError::Consensus(
                                    noid_chain::consensus::ConsensusError::BadParentHash,
                                ),
                                candidate,
                            ))
                        } else {
                            apply_p2p_block_offthread(
                                &chain,
                                &wallet,
                                candidate,
                                local_time,
                                history_step_runtime.clone(),
                            )
                            .await
                        };

                        match apply_result {
                            Ok(applied) => {
                                // The bundle was consumed and dropped by the blocking
                                // worker, so release the transport reservation
                                // before any network or mempool await below.
                                drop(inbound_memory_permit.take());
                                let height = applied.height;
                                mining_peer_quorum
                                    .set_canonical_tip(height, applied.block_hash);
                                record_authenticated_height!(height, from);
                                external_mining_attempts
                                    .invalidate_for_tip(height, applied.block_hash);
                                mempool
                                    .on_new_block(
                                        &applied.confirmed_tx_hashes,
                                        height,
                                        applied.view,
                                    )
                                    .await;
                                if let Some(measurement) = sync_phase_telemetry.record_suffix_block(
                                    height,
                                    suffix_block_bytes,
                                    suffix_apply_started.elapsed(),
                                ) {
                                    log_sync_phase_measurement(measurement);
                                }
                                tracing::info!(height, "applied P2P block");
                                last_tip_advance = Instant::now();
                                request_exact_tip_confirmation!(from, height);
                                mining_peer_quorum.confirm_tip(from, height, applied.block_hash);
                                let _ = template_changes.send(()); // cancel/rebuild any active stale template

                                // Continue only to the authenticated/announced target. Pulling
                                // one height beyond a caught-up tip used to turn an ordinary
                                // `unavailable` response into a needless snapshot-manifest
                                // round after every live block.
                                if retained_suffix_has_more(height, highest_announced) {
                                    let remaining = highest_announced - height;
                                    let _ = p2p_cmd
                                        .send(noid_p2p::NetworkCommand::SyncBlocksFrom {
                                            peer: from,
                                            from_height: height + 1,
                                            count: remaining.min(
                                                noid_chain::consensus::params::RECENT_BLOCK_RETENTION_DEPTH,
                                            ) as u16,
                                        })
                                        .await;
                                }

                                // Apply the chain of orphans that build on the new block.
                                let mut next_hash = applied.block_hash;
                                while let Some(orphan) = orphan_pool.remove(&next_hash) {
                                    let orphan_local_time = unix_now();
                                    let orphan_age_ms = orphan.received_at.elapsed().as_millis();
                                    let orphan_suffix_bytes = orphan.retained_bytes() as u64;
                                    let orphan_candidate = orphan.into_candidate();
                                    let orphan_suffix_started = Instant::now();
                                    let orphan_result = apply_p2p_block_offthread(
                                        &chain,
                                        &wallet,
                                        orphan_candidate,
                                        orphan_local_time,
                                        history_step_runtime.clone(),
                                    )
                                    .await;
                                    match orphan_result {
                                        Ok(applied_orphan) => {
                                            next_hash = applied_orphan.block_hash;
                                            let h = applied_orphan.height;
                                            mining_peer_quorum.set_canonical_tip(
                                                h,
                                                applied_orphan.block_hash,
                                            );
                                            record_authenticated_height!(h, from);
                                            external_mining_attempts
                                                .invalidate_for_tip(h, applied_orphan.block_hash);
                                            mempool
                                                .on_new_block(
                                                    &applied_orphan.confirmed_tx_hashes,
                                                    h,
                                                    applied_orphan.view,
                                                )
                                                .await;
                                            if let Some(measurement) =
                                                sync_phase_telemetry.record_suffix_block(
                                                    h,
                                                    orphan_suffix_bytes,
                                                    orphan_suffix_started.elapsed(),
                                                )
                                            {
                                                log_sync_phase_measurement(measurement);
                                            }
                                            tracing::info!(
                                                height = h,
                                                age_ms = orphan_age_ms,
                                                "applied chained orphan block"
                                            );
                                            last_tip_advance = Instant::now();
                                            mark_bootstrap_complete_if_caught_up!(h);
                                        }
                                        Err((e, rejected_orphan)) => {
                                            drop(rejected_orphan);
                                            tracing::warn!(err = %e, "chained orphan apply failed");
                                            break;
                                        }
                                    }
                                }
                            }
                            Err((
                                noid_chain::storage::MdbxContextError::Consensus(
                                    noid_chain::consensus::ConsensusError::BadParentHash,
                                ),
                                candidate,
                            )) => {
                                // Check if the block's parent is already in our chain (potential reorg point).
                                let parent_hash = candidate.block.header.prev_block_hash;
                                let our_tip = {
                                    let ctx = chain.read().await;
                                    (ctx.tip_height(), ctx.find_ancestor_height(&parent_hash))
                                };
                                let (our_tip_height, ancestor_opt) = our_tip;

                                match ancestor_opt {
                                    Some(ancestor_height) if ancestor_height < our_tip_height => {
                                        // Parent IS in our chain — this block starts or extends a competing fork.
                                        // Collect the new chain: this block + any buffered orphans on top.
                                        let mut next_hash = noid_chain::consensus::pow::block_id(
                                            &candidate.block.header,
                                        );
                                        let mut new_chain = vec![candidate];
                                        while let Some(orphan) = orphan_pool.remove(&next_hash) {
                                            next_hash = noid_chain::consensus::pow::block_id(
                                                &orphan.header,
                                            );
                                            new_chain.push(orphan.into_candidate());
                                        }

                                        // Compare cumulative chainwork: the chain with MORE TOTAL PoW wins.
                                        // This is the correct Bitcoin-style fork choice:
                                        // - a chain of 1000 easy blocks can have LESS work than 100 hard blocks
                                        // - critical for mainnet when a large miner joins suddenly (sub-second blocks)
                                        let new_tip_height =
                                            ancestor_height + new_chain.len() as u64;

                                        // Compute chainwork of the competing chain from ancestor.
                                        let competing_work = {
                                            use noid_chain::{add_work, block_work};
                                            // Add work for each block in the competing chain
                                            let mut w = [0u8; 32];
                                            for b in &new_chain {
                                                w = add_work(
                                                    &w,
                                                    &block_work(&b.block.header.difficulty_target),
                                                );
                                            }
                                            // competing_extra_work = work of new blocks
                                            w
                                        };

                                        let (our_extra_work, our_tip_hash) = {
                                            use noid_chain::{add_work, block_work};
                                            // Work we did from ancestor to our tip
                                            let mut w = [0u8; 32];
                                            let ctx = chain.read().await;
                                            for h in (ancestor_height + 1)..=our_tip_height {
                                                if let Some(hdr) = ctx.recent_headers.get(&h) {
                                                    w = add_work(
                                                        &w,
                                                        &block_work(&hdr.difficulty_target),
                                                    );
                                                }
                                            }
                                            (w, ctx.tip_hash())
                                        };

                                        let competing_tip_hash = new_chain
                                            .last()
                                            .map(|candidate| {
                                                noid_chain::consensus::pow::block_id(
                                                    &candidate.block.header,
                                                )
                                            })
                                            .expect("competing candidate chain is non-empty");
                                        let should_reorg = competing_suffix_wins(
                                            &competing_work,
                                            &competing_tip_hash,
                                            &our_extra_work,
                                            &our_tip_hash,
                                        );

                                        if should_reorg {
                                            tracing::info!(
                                                our_tip = our_tip_height,
                                                new_tip = new_tip_height,
                                                ancestor = ancestor_height,
                                                blocks = new_chain.len(),
                                                peer = %from,
                                                "reorg: competing chain wins canonical fork choice, reorganising"
                                            );

                                            // Serialize the complete chain + active-wallet
                                            // replacement against RPC address switches,
                                            // scans, and submissions. Lock order is:
                                            // wallet_operation_gate -> mempool snapshot/view
                                            // -> chain -> SharedWallet. apply_reorg_offthread
                                            // wallet RPC must not reacquire this gate while
                                            // this guard is held.
                                            let _wallet_operation =
                                                wallet_operation_gate.lock().await;
                                            let local_time = unix_now();
                                            let (reorg_reserved_inputs, reorg_reserved_outputs) =
                                                mempool.reserved_slots().await;
                                            // Reorg off the async executor (MDBX fsync is blocking).
                                            // ChainView is built inside write lock (no extra read lock needed).
                                            let reorg_result = apply_reorg_offthread(
                                                &chain,
                                                &wallet,
                                                reorg_reserved_inputs,
                                                reorg_reserved_outputs,
                                                ancestor_height,
                                                new_chain,
                                                local_time,
                                                history_step_runtime.clone(),
                                            )
                                            .await;

                                            match reorg_result {
                                                Ok(applied_reorg) => {
                                                    let accepted_tip_hash =
                                                        applied_reorg.view.tip_hash;
                                                    mining_peer_quorum.set_canonical_tip(
                                                        new_tip_height,
                                                        accepted_tip_hash,
                                                    );
                                                    record_authenticated_reorg_height!(
                                                        our_tip_height,
                                                        new_tip_height,
                                                        from
                                                    );
                                                    drop(inbound_memory_permit.take());
                                                    external_mining_attempts.invalidate_for_tip(
                                                        new_tip_height,
                                                        accepted_tip_hash,
                                                    );
                                                    mempool
                                                        .on_new_block(
                                                            &applied_reorg.confirmed_tx_hashes,
                                                            new_tip_height,
                                                            applied_reorg.view,
                                                        )
                                                        .await;

                                                    let reverted = applied_reorg
                                                        .result
                                                        .reverted_heights
                                                        .len();
                                                    let applied = applied_reorg
                                                        .result
                                                        .applied_heights
                                                        .len();
                                                    let reclaimed =
                                                        applied_reorg.result.reclaimed_tx_hashes;
                                                    mempool
                                                        .readmit_after_reorg(reclaimed)
                                                        .await;

                                                    last_tip_advance = Instant::now();
                                                    request_exact_tip_confirmation!(
                                                        from,
                                                        new_tip_height
                                                    );
                                                    mining_peer_quorum.confirm_tip(
                                                        from,
                                                        new_tip_height,
                                                        accepted_tip_hash,
                                                    );
                                                    let _ = template_changes.send(());
                                                    let new_tip = new_tip_height;
                                                    tracing::info!(
                                                        new_tip,
                                                        reverted,
                                                        applied,
                                                        "reorg complete"
                                                    );
                                                }
                                                Err((e, rejected_chain)) => {
                                                    drop(rejected_chain);
                                                    drop(inbound_memory_permit.take());
                                                    tracing::warn!(err = ?e, "reorg failed, keeping current chain");
                                                    tracing::info!(
                                                        peer = %from,
                                                        requester_height = our_tip_height,
                                                        "reorg failed — requesting snapshot manifest"
                                                    );
                                                    if pending_manifest.is_none()
                                                        && pending_snapshot_header_sync.is_none()
                                                        && snapshot_header_staging_inflight
                                                            .is_none()
                                                        && history_step_verification_inflight
                                                            .is_none()
                                                        && snapshot_staging_inflight.is_none()
                                                        && snapshot_install_inflight.is_none()
                                                        && pending_segment_ids.is_empty()
                                                        && segment_queue.is_empty()
                                                    {
                                                        manifest_requested_peers.clear();
                                                        manifest_force_snapshot_peers.clear();
                                                        manifest_response_count = 0;
                                                        manifest_requested_peers.insert(from);
                                                        manifest_force_snapshot_peers.insert(from);
                                                        let _ = p2p_cmd
                                                            .send(noid_p2p::NetworkCommand::RequestStateManifest {
                                                                generation: snapshot_sync_generation,
                                                                peer: from,
                                                                requester_height: our_tip_height,
                                                            })
                                                            .await;
                                                    }
                                                }
                                            }
                                        } else {
                                            tracing::debug!(
                                                our_tip = our_tip_height,
                                                new_tip = new_tip_height,
                                                "reorg: competing chain not longer, keeping current chain"
                                            );
                                            // Still buffer in case more blocks arrive from this fork.
                                            let candidate = new_chain
                                                .into_iter()
                                                .next()
                                                .expect("competing chain starts with received block");
                                            // The synchronous insert below immediately transfers
                                            // accounting to the byte-capped orphan pool.
                                            drop(inbound_memory_permit.take());
                                            insert_orphan(
                                                &mut orphan_pool,
                                                OrphanBlock::from_candidate(candidate),
                                            );
                                        }
                                    }
                                    Some(_) => {
                                        // Ancestor IS our current tip — block just has wrong parent somehow.
                                        let height = candidate.block.header.height;
                                        drop(candidate);
                                        drop(inbound_memory_permit.take());
                                        tracing::debug!(peer = %from, height, "block rejected: already at tip height");
                                    }
                                    None => {
                                        // Parent NOT in our chain.
                                        //
                                        // If the competing block is clearly deeper than our finality window,
                                        // block-by-block reorg is not safe/available; request a snapshot manifest.
                                        //
                                        // FetchHeaders is only worth doing for shallow forks (within CONSENSUS_FINALITY_DEPTH)
                                        // where block-by-block reorg is possible.
                                        let block_height = candidate.block.header.height;
                                        let is_deep_fork = block_height > our_tip_height
                                            && (block_height - our_tip_height) > CONSENSUS_FINALITY_DEPTH;

                                        // Avoid double-reserving the same bytes: the synchronous
                                        // insert enforces the independent orphan-pool byte cap.
                                        drop(inbound_memory_permit.take());
                                        insert_orphan(
                                            &mut orphan_pool,
                                            OrphanBlock::from_candidate(candidate),
                                        );

                                        if is_deep_fork {
                                            tracing::info!(
                                                our_tip = our_tip_height,
                                                their_tip = block_height,
                                                gap = block_height - our_tip_height,
                                                peer = %from,
                                                "deep fork beyond consensus finality — requesting snapshot manifest"
                                            );
                                            if pending_manifest.is_none()
                                                && pending_snapshot_header_sync.is_none()
                                                && snapshot_header_staging_inflight.is_none()
                                                && history_step_verification_inflight.is_none()
                                                && snapshot_staging_inflight.is_none()
                                                && snapshot_install_inflight.is_none()
                                                && pending_segment_ids.is_empty()
                                                && segment_queue.is_empty()
                                                && manifest_requested_peers.insert(from)
                                            {
                                                manifest_force_snapshot_peers.insert(from);
                                                let _ = p2p_cmd
                                                    .send(noid_p2p::NetworkCommand::RequestStateManifest {
                                                        generation: snapshot_sync_generation,
                                                        peer: from,
                                                        requester_height: our_tip_height,
                                                    })
                                                    .await;
                                            }
                                        } else {
                                            // Shallow fork: fetch batch headers to find common ancestor.
                                            // Guard: only one outstanding FetchHeaders per peer at a time,
                                            // plus a short dedup window for the same request tuple.
                                            let fetch_from =
                                                our_tip_height.saturating_sub(CONSENSUS_FINALITY_DEPTH);
                                            let fetch_count = (CONSENSUS_FINALITY_DEPTH as u16 * 2).min(512);
                                            let fetch_key = (from, fetch_from, fetch_count);
                                            let recently_requested = recent_header_fetches
                                                .get(&fetch_key)
                                                .is_some_and(|t| t.elapsed() < FETCH_DEDUP_TTL);
                                            if !recently_requested && !fetch_in_progress.contains(&from) {
                                                fetch_in_progress.insert(from);
                                                recent_header_fetches.insert(fetch_key, Instant::now());
                                                tracing::info!(
                                                    our_height = our_tip_height,
                                                    block_height,
                                                    peer = %from,
                                                    fetch_from,
                                                    "shallow orphan — fetching batch headers to find common ancestor"
                                                );
                                                let _ = p2p_cmd
                                                    .send(noid_p2p::NetworkCommand::FetchHeaders {
                                                        peer: from,
                                                        start_height: fetch_from,
                                                        count: fetch_count,
                                                    })
                                                    .await;
                                            } else {
                                                tracing::debug!(
                                                    our_height = our_tip_height,
                                                    block_height,
                                                    peer = %from,
                                                    fetch_from,
                                                    recently_requested,
                                                    in_progress = fetch_in_progress.contains(&from),
                                                    "shallow orphan header fetch already requested"
                                                );
                                            }
                                        }
                                    }
                                }
                            }
                            Err((e, rejected_candidate)) => {
                                drop(rejected_candidate);
                                drop(inbound_memory_permit.take());
                                tracing::warn!(peer = %from, err = %e, "P2P block rejected");
                            }
                        }
            }
            Ok(
                availability_event @ (NetworkEvent::RecentBlockUnavailable { .. }
                | NetworkEvent::RecentBlockRequestFailed { .. }),
            ) => {
                let request_failed = matches!(
                    &availability_event,
                    NetworkEvent::RecentBlockRequestFailed { .. }
                );
                let (from, height, payload_kind) = match availability_event {
                    NetworkEvent::RecentBlockUnavailable {
                        from,
                        height,
                        payload_kind,
                    }
                    | NetworkEvent::RecentBlockRequestFailed {
                        from,
                        height,
                        payload_kind,
                    } => (from, height, payload_kind),
                    _ => unreachable!("matched retained-block availability event"),
                };
                let unavailable_recent = pending_recent_suffix.as_ref().is_some_and(|pending| {
                    pending.peer == from
                        && pending.body_request_active
                        && height == pending.base_height.saturating_add(1)
                        && payload_kind
                            == noid_p2p::protocol::RecentBlockPayloadKind::BlockBody
                });
                if unavailable_recent {
                    fallback_recent_suffix_to_full_bundles!(
                        "compact suffix body batch unavailable"
                    );
                    continue;
                }
                let unavailable_shallow = pending_shallow_fork
                    .as_ref()
                    .filter(|pending| pending.peer == from)
                    .and_then(|pending| pending.expected_header())
                    .is_some_and(|expected| expected.height == height)
                    && payload_kind == noid_p2p::protocol::RecentBlockPayloadKind::Complete;
                if unavailable_shallow {
                    tracing::warn!(
                        peer = %from,
                        height,
                        "peer cannot serve the selected shallow-fork bundle"
                    );
                    if retry_shallow_fork_bundle_peer!(
                        from,
                        "selected peer could not serve the exact replacement bundle"
                    ) {
                        continue;
                    }
                    let stale = pending_shallow_fork
                        .take()
                        .expect("unavailable shallow-fork session exists");
                    let our_tip = {
                        let ctx = chain.read().await;
                        ctx.tip_height()
                    };
                    if gap_requires_snapshot_sync(our_tip, stale.tip_height()) {
                        request_snapshot_rebase!(
                            stale,
                            "first required complete bundle is outside the peer serving window"
                        );
                    } else {
                        // A snapshot boundary is normally tip-18 and is not yet
                        // ahead of this node for a shallow gap. Asking for it
                        // would be a guaranteed no-op. Rotate one linked-header
                        // lane instead; a patched peer keeps the wider serving
                        // reserve and a moving branch is rediscovered here.
                        retry_shallow_fork_headers!(
                            stale,
                            "selected peer could not serve a shallow replacement bundle"
                        );
                    }
                    continue;
                }
                let unavailable_snapshot_tail = snapshot_tail_request_inflight.is_some_and(|request| {
                    request.generation == snapshot_sync_generation
                        && request.from == from
                        && request.height == height
                        && payload_kind
                            == noid_p2p::protocol::RecentBlockPayloadKind::BlockBody
                }) && pending_manifest
                    .as_ref()
                    .is_some_and(|pending| pending.from == from);
                if unavailable_snapshot_tail {
                    snapshot_tail_request_inflight = None;
                    let bridge_tip = pending_manifest
                        .as_ref()
                        .expect("selected snapshot manifest exists")
                        .manifest
                        .bridge_tip_height;
                    if height <= bridge_tip {
                        tracing::warn!(
                            peer = %from,
                            height,
                            request_failed,
                            "immutable snapshot bridge block unavailable — selecting a fresh generation"
                        );
                        preserve_active_snapshot_headers!();
                        reset_sync_state!();
                        request_bounded_manifest_failover!(from, false);
                        continue;
                    }

                    tracing::debug!(
                        peer = %from,
                        height,
                        request_failed,
                        "ignoring stale block-body availability beyond immutable bridge"
                    );
                    continue;
                }
                if payload_kind == noid_p2p::protocol::RecentBlockPayloadKind::BlockBody {
                    tracing::debug!(
                        peer = %from,
                        requested_height = height,
                        "ignoring stale compact snapshot-body availability event"
                    );
                    continue;
                }
                if snapshot_install_inflight.is_some() {
                    tracing::debug!(
                        peer = %from,
                        requested_height = height,
                        "snapshot install active — ignoring stale retained-block response"
                    );
                    continue;
                }
                let our_tip = {
                    let ctx = chain.read().await;
                    ctx.tip_height()
                };
                if unavailable_block_requires_snapshot(our_tip, height, highest_announced) {
                    tracing::info!(
                        peer = %from,
                        requested_height = height,
                        our_tip,
                        highest_announced,
                        "next retained block unavailable — requesting fresh snapshot manifest"
                    );
                    if pending_manifest.is_none()
                        && pending_snapshot_header_sync.is_none()
                        && snapshot_header_staging_inflight.is_none()
                        && history_step_verification_inflight.is_none()
                        && snapshot_staging_inflight.is_none()
                        && snapshot_install_inflight.is_none()
                        && pending_segment_ids.is_empty()
                        && segment_queue.is_empty()
                    {
                        manifest_requested_peers.clear();
                        manifest_force_snapshot_peers.clear();
                        manifest_response_count = 0;
                        manifest_requested_peers.insert(from);
                        manifest_force_snapshot_peers.insert(from);
                        let _ = p2p_cmd
                            .send(noid_p2p::NetworkCommand::RequestStateManifest {
                                generation: snapshot_sync_generation,
                                peer: from,
                                requester_height: our_tip,
                            })
                            .await;
                    }
                } else {
                    tracing::debug!(
                        peer = %from,
                        requested_height = height,
                        our_tip,
                        highest_announced,
                        "retained block unavailable outside an announced suffix gap"
                    );
                }
            }
            Ok(NetworkEvent::MempoolSyncResponse {
                from,
                txs,
                inbound_memory_permit,
            }) => {
                tracing::info!(
                    peer = %from,
                    tx_count = txs.len(),
                    "mempool sync: received pending TXs from peer"
                );
                let mempool_task = mempool.clone();
                let mut initial_sync_ready_task = initial_sync_ready.subscribe();
                let chain_task = Arc::clone(&chain);
                tokio::spawn(async move {
                    {
                        let h = chain_task.read().await.tip_height();
                        if h == 0 && !*initial_sync_ready_task.borrow() {
                            tracing::debug!("mempool sync: waiting for state sync before admitting TXs");
                            if initial_sync_ready_task.changed().await.is_err() {
                                tracing::debug!("mempool sync: readiness channel closed — dropping deferred TXs");
                                return;
                            }
                            tracing::debug!("mempool sync: state ready, submitting {} TXs", txs.len());
                        }
                    }
                    for intent_bytes in txs {
                        if intent_bytes.len() > MAX_TX_INTENT_BYTES_GLOBAL {
                            tracing::debug!(
                                size = intent_bytes.len(),
                                max = MAX_TX_INTENT_BYTES_GLOBAL,
                                "mempool sync: tx dropped before decode due to size cap"
                            );
                            continue;
                        }
                        if let Ok(intent) = noid_tx::PagedSpendIntent::from_bytes(&intent_bytes) {
                            match mempool_task.submit(intent, intent_bytes).await {
                                Ok(hash) => {
                                    tracing::debug!(hash = ?hash, "mempool sync: tx admitted");
                                }
                                Err(e) if e.is_soft() => {}
                                Err(e) => {
                                    tracing::debug!(err = %e, "mempool sync: tx rejected");
                                }
                            }
                        }
                    }
                    // The decoded response owns one process-global inbound
                    // reservation. Release it only after every intent has been
                    // submitted or rejected by the local admission pipeline.
                    drop(inbound_memory_permit);
                });
            }
            Ok(NetworkEvent::NewTx {
                from,
                intent_bytes,
                inbound_memory_permit,
            }) => {
                // Hard cap: reject oversized payloads before any processing.
                if intent_bytes.len() > MAX_TX_INTENT_BYTES_GLOBAL {
                    tracing::debug!(
                        peer = %from,
                        size = intent_bytes.len(),
                        max = MAX_TX_INTENT_BYTES_GLOBAL,
                        "tx dropped: exceeds global TxIntent wire size limit"
                    );
                    continue;
                }

                tracing::debug!(peer = %from, "received tx from P2P");

                // Per-peer rate limiting: enforce before any further processing.
                // This check is synchronous (O(1) HashMap lookup) so the event loop
                // is not blocked; the heavy AuthGKR authorization verification is spawned below.
                {
                    let now = Instant::now();
                    let entry = peer_tx_rate.entry(from).or_insert((0, now));
                    if now.duration_since(entry.1) > TX_RATE_WINDOW {
                        *entry = (1, now);
                    } else if entry.0 >= TX_RATE_MAX {
                        tracing::debug!(peer = %from, "tx rate limit exceeded, dropping");
                        continue;
                    } else {
                        entry.0 += 1;
                    }
                }

                // Periodic cleanup of stale rate-limit entries.
                tx_event_count += 1;
                if tx_event_count.is_multiple_of(100) {
                    let cutoff = Instant::now() - Duration::from_secs(60);
                    peer_tx_rate.retain(|_, (_, window_start)| *window_start >= cutoff);
                }

                // Spawn AuthGKR authorization verification + mempool admit as a background task.
                //
                // WHY: `mempool.submit()` runs an AuthGKR authorization verification (~84ms, CPU-bound via
                // spawn_blocking) under an async semaphore. If we await it here, the
                // entire P2P event loop stalls for 84ms — delaying block propagation.
                //
                // SAFETY: `mempool.submit()` never touches the chain (Arc<RwLock<...>>),
                // only the mempool's internal Arc<Mutex<MempoolState>>. Concurrent task
                // access is safe. P2P relay of admitted txs is handled by the dedicated
                // relay task spawned in main() — no extra work needed here.
                let mempool_task = mempool.clone();
                tokio::spawn(async move {
                    if let Ok(intent) = noid_tx::PagedSpendIntent::from_bytes(&intent_bytes) {
                        match mempool_task.submit(intent, intent_bytes).await {
                            Ok(hash) => {
                                tracing::debug!(hash = ?hash, "P2P tx admitted");
                            }
                            Err(e) if e.is_soft() => {
                                // Soft reject (duplicate, slot conflict) — normal, ignore.
                            }
                            Err(e) => {
                                tracing::debug!(err = %e, "P2P tx rejected");
                            }
                        }
                    }
                    // A direct relay owns one process-global inbound byte
                    // reservation. Gossip messages carry `None`.
                    drop(inbound_memory_permit);
                });
            }
            Ok(NetworkEvent::PeerConnected(peer)) => {
                tracing::info!(peer = %peer, "peer connected");
                mining_peer_quorum.connect(peer);
                manifest_peers.insert(peer);

                let our_height = {
                    let ctx = chain.read().await;
                    ctx.tip_height()
                };

                // Manifest and tip discovery are independent, tiny requests.
                // Starting both removes one full network round trip from cold
                // deep sync while the header probe still selects the shallow
                // retained-suffix path for young chains.
                if snapshot_install_inflight.is_none()
                    && manifest_requested_peers.insert(peer)
                {
                    manifest_round_started_at.get_or_insert_with(Instant::now);
                    p2p_cmd
                        .send(noid_p2p::NetworkCommand::RequestStateManifest {
                            generation: snapshot_sync_generation,
                            peer,
                            requester_height: our_height,
                        })
                        .await
                        .ok();
                }

                // A connection has no fresh block gossip to reveal the peer's
                // current tip. Probe with the existing bounded header protocol,
                // anchored at our exact tip (genesis for an empty node). The
                // response selects direct retained-block sync for gaps <= 18
                // and snapshot sync for deeper gaps. A manifest alone cannot
                // do this because it intentionally describes finalized F, not
                // the live peer tip; for chains shorter than finality it is
                // empty even though direct blocks are available.
                let request_key = (peer, our_height, CONNECTED_TIP_PROBE_HEADERS);
                if fetch_in_progress.insert(peer) {
                    recent_header_fetches.insert(request_key, Instant::now());
                    if p2p_cmd
                        .send(noid_p2p::NetworkCommand::FetchHeaders {
                            peer,
                            start_height: our_height,
                            count: CONNECTED_TIP_PROBE_HEADERS,
                        })
                        .await
                        .is_ok()
                    {
                        mining_peer_quorum.mark_probe_sent(peer, Instant::now());
                        tracing::debug!(
                            peer = %peer,
                            start_height = our_height,
                            "probing connected peer tip with anchored headers"
                        );
                    } else {
                        fetch_in_progress.remove(&peer);
                        recent_header_fetches.remove(&request_key);
                    }
                }

                // Mempool payloads can be much larger than the complete cold
                // snapshot. Do not put their decoding or AuthGKR work on the
                // bootstrap critical path.
                if *initial_sync_ready.borrow()
                    && mempool_sync_requested_peers.insert(peer)
                {
                    p2p_cmd
                        .send(noid_p2p::NetworkCommand::RequestMempoolSync { peer })
                        .await
                        .ok();
                }
            }
            Ok(NetworkEvent::SnapshotHeadersBatch {
                generation,
                token,
                from,
                start_height,
                requested_count,
                headers,
            }) => {
                let Some(pipeline) = snapshot_header_pipeline.as_mut() else {
                    tracing::debug!(
                        peer = %from,
                        generation,
                        start_height,
                        "dropping snapshot headers without an active pipeline"
                    );
                    continue;
                };
                if !pipeline.matches_generation(generation) {
                    tracing::debug!(
                        peer = %from,
                        generation,
                        active_generation = pipeline.generation,
                        start_height,
                        "dropping delayed snapshot headers from a superseded session"
                    );
                    continue;
                }
                if !pipeline.matches_outstanding(from, start_height, requested_count, token) {
                    tracing::debug!(
                        peer = %from,
                        generation,
                        token,
                        start_height,
                        requested_count,
                        "dropping delayed snapshot headers from a retired exact request"
                    );
                    continue;
                }
                if let Err(error) = pipeline.accept(
                    generation,
                    token,
                    from,
                    start_height,
                    requested_count,
                    headers,
                ) {
                    let failed_generation_peer = pipeline.from;
                    let retry = pipeline.failure_plan(
                        from,
                        start_height,
                        requested_count,
                        token,
                        noid_p2p::RequestFailureKind::InvalidResponse,
                        &manifest_peers,
                    );
                    tracing::warn!(
                        peer = %from,
                        generation,
                        start_height,
                        requested_count,
                        err = %error,
                        "snapshot header response failed exact validation"
                    );
                    if let Some(request) = retry {
                        let _ = p2p_cmd
                            .send(noid_p2p::NetworkCommand::FetchSnapshotHeaders {
                                generation,
                                token: request.token,
                                peer: request.peer,
                                start_height: request.start_height,
                                count: request.count,
                            })
                            .await;
                    } else {
                        preserve_active_snapshot_headers!();
                        reset_sync_state!();
                        request_bounded_manifest_failover!(failed_generation_peer, false);
                    }
                    continue;
                }

                if snapshot_header_staging_inflight.is_some() {
                    tracing::debug!(
                        peer = %from,
                        start_height,
                        requested_count,
                        buffered = pipeline.ready.len(),
                        "snapshot header response retained in bounded reorder window"
                    );
                    continue;
                }

                let Some(sync) = pending_snapshot_header_sync.take() else {
                    tracing::warn!(
                        peer = %from,
                        start_height,
                        "snapshot header pipeline lost its disk staging session"
                    );
                    reset_sync_state!();
                    continue;
                };
                let Some(range) = pipeline.take_ready(sync.next_height) else {
                    pending_snapshot_header_sync = Some(sync);
                    continue;
                };
                if let Err(error) = validate_snapshot_header_batch_admission(
                    sync.next_height,
                    sync.target_height,
                    range.headers.len(),
                ) {
                    tracing::warn!(
                        peer = %range.source_peer,
                        headers = range.headers.len(),
                        err = %error,
                        "snapshot header batch failed bounded staging admission"
                    );
                    cleanup_snapshot_header_staging_offthread(sync.staging);
                    reset_sync_state!();
                    continue;
                }
                let refill = pipeline.refill_plan(true);
                for request in refill {
                    let _ = p2p_cmd
                        .send(noid_p2p::NetworkCommand::FetchSnapshotHeaders {
                            generation: snapshot_sync_generation,
                            token: request.token,
                            peer: request.peer,
                            start_height: request.start_height,
                            count: request.count,
                        })
                        .await;
                }
                spawn_snapshot_header_append!(sync, range);
                continue;
            }
            Ok(NetworkEvent::SnapshotHeadersRequestFailed {
                generation,
                token,
                from,
                start_height,
                count,
                kind,
            }) => {
                let correlated = snapshot_header_pipeline.as_ref().is_some_and(|pipeline| {
                    pipeline.matches_generation(generation)
                        && pipeline.matches_outstanding(from, start_height, count, token)
                });
                if !correlated {
                    tracing::debug!(
                        peer = %from,
                        generation,
                        token,
                        start_height,
                        count,
                        "ignoring stale snapshot header request failure"
                    );
                    continue;
                }
                let retry = snapshot_header_pipeline
                    .as_mut()
                    .and_then(|pipeline| {
                        pipeline.failure_plan(
                            from,
                            start_height,
                            count,
                            token,
                            kind,
                            &manifest_peers,
                        )
                    });
                let Some(request) = retry else {
                    let failed_generation_peer = snapshot_header_pipeline
                        .as_ref()
                        .map_or(from, |pipeline| pipeline.from);
                    tracing::warn!(
                        peer = %from,
                        generation,
                        start_height,
                        count,
                        ?kind,
                        "snapshot header range exhausted all connected sources; selecting another generation"
                    );
                    preserve_active_snapshot_headers!();
                    reset_sync_state!();
                    request_bounded_manifest_failover!(
                        failed_generation_peer,
                        terminal_transport_can_retry_same_peer(kind)
                    );
                    continue;
                };
                let _ = p2p_cmd
                    .send(noid_p2p::NetworkCommand::FetchSnapshotHeaders {
                        generation: snapshot_sync_generation,
                        token: request.token,
                        peer: request.peer,
                        start_height: request.start_height,
                        count: request.count,
                    })
                    .await;
                tracing::warn!(
                    peer = %from,
                    retry_peer = %request.peer,
                    start_height,
                    count,
                    ?kind,
                    "snapshot header request failed; retrying only the exact range"
                );
                continue;
            }
            Ok(NetworkEvent::HeaderInventoryBatch { from, records }) => {
                let headers = records
                    .iter()
                    .map(|record| record.header)
                    .collect::<Vec<_>>();
                // Headers batch arrived — clear the in-progress guard.
                fetch_in_progress.remove(&from);
                if selected_snapshot_peer!().is_some() {
                    tracing::debug!(
                        peer = %from,
                        headers = headers.len(),
                        "snapshot session active — dropping unrelated general header batch"
                    );
                    continue;
                }
                if snapshot_install_inflight.is_some() {
                    tracing::debug!(
                        peer = %from,
                        headers = headers.len(),
                        "snapshot install active — dropping stale header batch"
                    );
                    continue;
                }
                if pending_recent_suffix.is_some() || recent_suffix_apply_inflight.is_some() {
                    deferred_sync_peer = Some(from);
                    tracing::debug!(
                        peer = %from,
                        headers = headers.len(),
                        "compact recent suffix active — dropping redundant header batch"
                    );
                    continue;
                }

                // Find common ancestor for reorg.
                if headers.is_empty() {
                    // A peer on a shorter branch cannot answer a request that
                    // starts at our tip. It may nevertheless carry greater
                    // cumulative work. Read exactly the complete non-final
                    // window once so the normal native-validation and fork-
                    // choice path can compare it. Healthy current-tip peers
                    // never take this fallback.
                    let our_tip = {
                        let ctx = chain.read().await;
                        ctx.tip_height()
                    };
                    if let Some((start_height, count)) =
                        nonfinal_header_discovery_range(our_tip)
                    {
                        let request_key = (from, start_height, count);
                        let recently_requested = recent_header_fetches
                            .get(&request_key)
                            .is_some_and(|requested| requested.elapsed() < FETCH_DEDUP_TTL);
                        if !fetch_in_progress.contains(&from) && !recently_requested {
                            fetch_in_progress.insert(from);
                            recent_header_fetches.insert(request_key, Instant::now());
                            if p2p_cmd
                                .send(noid_p2p::NetworkCommand::FetchHeaders {
                                    peer: from,
                                    start_height,
                                    count,
                                })
                                .await
                                .is_err()
                            {
                                fetch_in_progress.remove(&from);
                                recent_header_fetches.remove(&request_key);
                            } else {
                                tracing::debug!(
                                    peer = %from,
                                    our_tip,
                                    start_height,
                                    count,
                                    "peer returned no header at our tip; probing its bounded non-final view"
                                );
                            }
                        }
                    }
                    continue;
                }

                let (our_tip, ancestor_opt) = {
                    let ctx = chain.read().await;
                    let our_tip = ctx.tip_height();
                    // Find the highest header in the batch that is ALSO in our chain.
                    let mut found = None;
                    for hdr in &headers {
                        let hash = noid_chain::consensus::pow::block_id(hdr);
                        if let Some(h) = ctx.find_ancestor_height(&hash) {
                            if found.is_none_or(|(fh, _)| h > fh) {
                                found = Some((h, hash));
                            }
                        }
                    }
                    (our_tip, found)
                };

                if let Some((ancestor_height, ancestor_hash)) = ancestor_opt {
                    finalized_divergent_peers.remove(&from);
                    // Found common ancestor. The competing chain:
                    // headers with height > ancestor_height, ordered ascending.
                    let mut competing: Vec<noid_chain::BlockHeader> = headers
                        .iter()
                        .filter(|h| h.height > ancestor_height)
                        .copied()
                        .collect();
                    competing.sort_by_key(|h| h.height);

                    let competing_tip = competing_suffix_tip(&competing);
                    let new_tip_height = competing_tip
                        .map(|(height, _)| height)
                        .unwrap_or(ancestor_height);

                    if !competing.is_empty() {
                        let store = snapshot_header_store.clone();
                        let validation_headers = competing.clone();
                        let validated = tokio::task::spawn_blocking(move || {
                            validate_bounded_header_extension(
                                &store,
                                ancestor_height,
                                &validation_headers,
                                unix_now(),
                            )
                            .map_err(|error| error.to_string())
                        })
                        .await;
                        match validated {
                            Ok(Ok(_)) => {}
                            Ok(Err(error)) => {
                                tracing::warn!(
                                    peer = %from,
                                    ancestor = ancestor_height,
                                    tip = new_tip_height,
                                    err = %error,
                                    "header extension failed native consensus validation"
                                );
                                continue;
                            }
                            Err(error) => {
                                tracing::warn!(
                                    peer = %from,
                                    err = %error,
                                    "header extension validation worker failed"
                                );
                                continue;
                            }
                        }
                    }

                    if ancestor_height == our_tip
                        && new_tip_height == our_tip
                        && our_tip >= highest_announced
                        && pending_shallow_fork.is_none()
                        && pending_block_fetches.is_empty()
                    {
                        // The peer returned our exact canonical tip and no
                        // extension. This is a completed authenticated initial
                        // sync probe, not an absence of peers. Make readiness
                        // durable so a miner created later starts immediately.
                        clear_manifest_round_state!();
                        mark_initial_sync_ready(&initial_sync_ready);
                        mark_bootstrap_complete_if_caught_up!(our_tip);
                        mining_peer_quorum.confirm_tip(from, our_tip, ancestor_hash);
                        tracing::debug!(
                            peer = %from,
                            height = our_tip,
                            "connected peer confirms local tip is current"
                        );
                    }

                    // A fork may be equal-height or even shorter while carrying
                    // more cumulative work. Height gates only the direct
                    // extension fast path; fork choice below is always work
                    // first.
                    if new_tip_height > our_tip || ancestor_height < our_tip {
                        // A shorter peer on our exact canonical prefix has no
                        // competing suffix at all. The bounded fallback is
                        // still useful to distinguish that harmless case from
                        // a shorter fork-choice winner, but an empty suffix is
                        // never a fork-choice candidate.
                        if competing_tip.is_none() {
                            tracing::debug!(
                                peer = %from,
                                peer_tip = ancestor_height,
                                our_tip,
                                "peer is behind on the accepted canonical prefix"
                            );
                            continue;
                        }
                        if ancestor_height == our_tip {
                            record_authenticated_height!(new_tip_height, from);
                            mining_peer_quorum.invalidate_all();
                        }
                        if ancestor_height == our_tip
                            && gap_requires_snapshot_sync(our_tip, new_tip_height)
                        {
                            tracing::info!(
                                peer = %from,
                                our_tip,
                                peer_tip = new_tip_height,
                                retention = noid_chain::consensus::params::RECENT_BLOCK_RETENTION_DEPTH,
                                "connected header probe found deep gap — requesting snapshot manifest"
                            );
                            if pending_manifest.is_none()
                                && pending_snapshot_header_sync.is_none()
                                && snapshot_header_staging_inflight.is_none()
                                && history_step_verification_inflight.is_none()
                                && snapshot_staging_inflight.is_none()
                                && snapshot_install_inflight.is_none()
                                && pending_segment_ids.is_empty()
                                && segment_queue.is_empty()
                                && manifest_requested_peers.insert(from)
                            {
                                manifest_force_snapshot_peers.insert(from);
                                manifest_round_started_at.get_or_insert_with(Instant::now);
                                let _ = p2p_cmd
                                    .send(noid_p2p::NetworkCommand::RequestStateManifest {
                                        generation: snapshot_sync_generation,
                                        peer: from,
                                        requester_height: our_tip,
                                    })
                                    .await;
                            }
                            continue;
                        }

                        // The batch contains our exact current tip followed by
                        // one linked extension. A one-block gap keeps the normal
                        // complete-bundle path. For 2..18 blocks, stage only
                        // bodies and authenticate the fixed tip once.
                        if ancestor_height == our_tip {
                            let gap = new_tip_height - our_tip;
                            if compact_suffix_eligible(
                                our_tip,
                                ancestor_height,
                                new_tip_height,
                            ) && !rejected_terminal_peers.contains(&from)
                            {
                                let (base_hash, base_work) = {
                                    let ctx = chain.read().await;
                                    if ctx.tip_height() != our_tip
                                        || ctx.tip_hash() != ancestor_hash
                                    {
                                        tracing::debug!(
                                            peer = %from,
                                            our_tip,
                                            "canonical tip changed before compact suffix admission"
                                        );
                                        continue;
                                    }
                                    (ctx.tip_hash(), *ctx.tip_chain_work())
                                };
                                let expected_headers = competing.clone();
                                let target_header = *expected_headers
                                    .last()
                                    .expect("recent extension is non-empty");
                                let target_hash =
                                    noid_chain::consensus::pow::block_id(&target_header);
                                let tail = match SnapshotTailStaging::create(
                                    &snapshot_staging_root.join("recent-tail"),
                                    our_tip,
                                    base_hash,
                                    base_work,
                                ) {
                                    Ok(tail) => tail,
                                    Err(error) => {
                                        tracing::warn!(
                                            peer = %from,
                                            err = %error,
                                            "compact recent suffix staging initialization failed"
                                        );
                                        let _ = p2p_cmd
                                            .send(noid_p2p::NetworkCommand::SyncBlocksFrom {
                                                peer: from,
                                                from_height: our_tip + 1,
                                                count: gap as u16,
                                            })
                                            .await;
                                        continue;
                                    }
                                };
                                // A compact suffix owns canonical catch-up until
                                // its exact terminal/body pair is resolved.
                                // Discard any unselected manifest round so a
                                // delayed response cannot start a competing
                                // snapshot FSM over this session.
                                clear_manifest_round_state!();
                                recent_suffix_generation =
                                    recent_suffix_generation.wrapping_add(1);
                                history_step_request_token =
                                    history_step_request_token.wrapping_add(1);
                                let terminal_requests =
                                    TerminalRequestRace::new(from, history_step_request_token);
                                pending_recent_suffix = Some(PendingRecentSuffix {
                                    generation: recent_suffix_generation,
                                    peer: from,
                                    base_height: our_tip,
                                    base_hash,
                                    target_height: new_tip_height,
                                    target_hash,
                                    expected_headers,
                                    staging: Some(tail),
                                    body_request_active: true,
                                    append_active: false,
                                    terminal_requests,
                                    terminal_payload: None,
                                });
                                let _ = p2p_cmd
                                    .send(noid_p2p::NetworkCommand::RequestBlockBodies {
                                        peer: from,
                                        height: our_tip + 1,
                                        count: gap as u16,
                                    })
                                    .await;
                                let _ = p2p_cmd
                                    .send(noid_p2p::NetworkCommand::RequestHistoryStepTerminal {
                                        token: history_step_request_token,
                                        peer: from,
                                        height: new_tip_height,
                                        block_hash: target_hash,
                                    })
                                    .await;
                                tracing::info!(
                                    peer = %from,
                                    our_tip,
                                    peer_tip = new_tip_height,
                                    gap,
                                    "connected header probe found exact recent extension — fetching compact suffix"
                                );
                            } else {
                                tracing::info!(
                                    peer = %from,
                                    our_tip,
                                    peer_tip = new_tip_height,
                                    gap,
                                    "connected header probe selected complete-bundle sync"
                                );
                                let _ = p2p_cmd
                                    .send(noid_p2p::NetworkCommand::SyncBlocksFrom {
                                        peer: from,
                                        from_height: our_tip + 1,
                                        count: gap as u16,
                                    })
                                    .await;
                            }
                            continue;
                        }

                        let reorg_depth = our_tip.saturating_sub(ancestor_height);
                        if reorg_depth > CONSENSUS_FINALITY_DEPTH {
                            tracing::info!(
                                ancestor = ancestor_height,
                                our_tip,
                                competing_tip = new_tip_height,
                                reorg_depth,
                                peer = %from,
                                "competing fork crosses finalized depth — keeping canonical chain"
                            );
                            continue;
                        }

                        let (competing_work, competing_tip_hash, our_extra_work, our_tip_hash) = {
                            use noid_chain::{add_work, block_work};
                            let mut competing_work = [0u8; 32];
                            for header in &competing {
                                competing_work = add_work(
                                    &competing_work,
                                    &block_work(&header.difficulty_target),
                                );
                            }
                            let mut our_extra_work = [0u8; 32];
                            let competing_tip_hash = competing_tip
                                .expect("guarded competing header suffix is non-empty")
                                .1;
                            let ctx = chain.read().await;
                            for height in (ancestor_height + 1)..=our_tip {
                                let Some(header) = ctx.recent_headers.get(&height) else {
                                    tracing::warn!(
                                        height,
                                        ancestor = ancestor_height,
                                        our_tip,
                                        "canonical reorg comparison header is unavailable"
                                    );
                                    our_extra_work = [0xFF; 32];
                                    break;
                                };
                                our_extra_work = add_work(
                                    &our_extra_work,
                                    &block_work(&header.difficulty_target),
                                );
                            }
                            (
                                competing_work,
                                competing_tip_hash,
                                our_extra_work,
                                ctx.tip_hash(),
                            )
                        };
                        let advertises_better_chain = competing_suffix_wins(
                            &competing_work,
                            &competing_tip_hash,
                            &our_extra_work,
                            &our_tip_hash,
                        );
                        if !advertises_better_chain {
                            tracing::debug!(
                                ancestor = ancestor_height,
                                our_tip,
                                competing_tip = new_tip_height,
                                peer = %from,
                                "shallow fork headers do not beat canonical work"
                            );
                            continue;
                        }
                        mining_peer_quorum.invalidate_all();
                        record_authenticated_height!(new_tip_height, from);

                        if let Some(active) = pending_shallow_fork.as_ref() {
                            tracing::debug!(
                                active_peer = %active.peer,
                                active_tip = active.tip_height(),
                                candidate_peer = %from,
                                candidate_tip = new_tip_height,
                                "bounded shallow-fork download already active"
                            );
                            continue;
                        }

                        let expected_headers = competing;
                        let first = *expected_headers
                            .first()
                            .expect("a competing header suffix is non-empty");
                        let first_hash = noid_chain::consensus::pow::block_id(&first);
                        let replacement = PendingShallowFork {
                            peer: from,
                            ancestor_height,
                            ancestor_hash,
                            expected_headers,
                            candidates: Vec::new(),
                            retained_bytes: 0,
                            advertised_work: competing_work,
                            attempted_bundle_peers: std::collections::HashSet::new(),
                            last_progress_at: Instant::now(),
                        };
                        if gap_requires_snapshot_sync(our_tip, new_tip_height) {
                            request_snapshot_rebase!(
                                replacement,
                                "authenticated better fork is already beyond compact catch-up"
                            );
                            continue;
                        }
                        tracing::info!(
                            ancestor = ancestor_height,
                            our_tip,
                            competing_tip = new_tip_height,
                            peer = %from,
                            bundles = replacement.expected_headers.len(),
                            "shallow fork wins canonical fork choice — starting sequential bundle download"
                        );
                        pending_shallow_fork = Some(replacement);
                        pending_block_fetches.insert(
                            (first.height, first_hash),
                            PendingBlockFetch {
                                peer: from,
                                requested_at: Instant::now(),
                            },
                        );
                        let _ = p2p_cmd
                            .send(noid_p2p::NetworkCommand::RequestBlock {
                                peer: from,
                                height: first.height,
                            })
                            .await;
                    } else {
                        tracing::debug!(
                            our_tip,
                            competing_tip = new_tip_height,
                            "batch headers: competing chain not longer"
                        );
                    }
                } else {
                    // `find_ancestor_height` deliberately recognizes only the
                    // complete non-final window. Once a response begins at its
                    // floor, fetching still older headers cannot authorize a
                    // reorg and a state manifest from this branch is guaranteed
                    // to fail its first parent link. Stop this peer for the
                    // connection lifetime instead of entering a manifest loop.
                    let oldest = headers.first().map(|h| h.height).unwrap_or(0);
                    if header_batch_exhausts_nonfinal_window(our_tip, oldest) {
                        finalized_divergent_peers.insert(from);
                        manifest_requested_peers.remove(&from);
                        manifest_force_snapshot_peers.remove(&from);
                        tracing::warn!(
                            peer = %from,
                            our_tip,
                            finalized_height = finalized_header_search_floor(our_tip),
                            peer_range_start = oldest,
                            "peer branch has no common ancestor inside the accepted non-final window; automatic rebase refused"
                        );
                    } else {
                        let fetch_from = finalized_header_search_floor(our_tip);
                        let count = 512u16;
                        let request_key = (from, fetch_from, count);
                        recent_header_fetches.insert(request_key, Instant::now());
                        fetch_in_progress.insert(from);
                        let _ = p2p_cmd
                            .send(noid_p2p::NetworkCommand::FetchHeaders {
                                peer: from,
                                start_height: fetch_from,
                                count,
                            })
                            .await;
                        tracing::debug!(
                            peer = %from,
                            fetch_from,
                            "batch headers: common ancestor not present; fetching the complete non-final window"
                        );
                    }
                }
            }
            Ok(NetworkEvent::HeadersRequestFailed {
                from,
                start_height,
                count,
            }) => {
                fetch_in_progress.remove(&from);
                recent_header_fetches.remove(&(from, start_height, count));
                tracing::debug!(
                    peer = %from,
                    start_height,
                    count,
                    "general header request failed"
                );
            }
            Ok(NetworkEvent::StateManifest {
                generation,
                from,
                requester_height,
                manifest,
            }) => {
                if generation != snapshot_sync_generation {
                    tracing::debug!(
                        generation,
                        active_generation = snapshot_sync_generation,
                        from = %from,
                        requester_height,
                        "ignoring stale state-manifest response"
                    );
                    continue;
                }
                manifest_requested_peers.remove(&from);
                if finalized_divergent_peers.contains(&from) {
                    tracing::warn!(
                        from = %from,
                        tip = manifest.tip_height,
                        "ignoring manifest from a branch outside the accepted non-final window"
                    );
                    if selected_snapshot_peer!().is_none()
                        && manifest_requested_peers.is_empty()
                    {
                        request_bounded_manifest_failover!(from, false);
                    }
                    continue;
                }
                if rejected_terminal_peers.contains(&from) {
                    tracing::warn!(
                        from = %from,
                        "ignoring manifest from a peer that supplied an invalid recursive terminal"
                    );
                    if selected_snapshot_peer!().is_none()
                        && manifest_requested_peers.is_empty()
                    {
                        request_bounded_manifest_failover!(from, false);
                    }
                    continue;
                }
                let manifest_tip_height = manifest.tip_height;
                if snapshot_install_inflight.is_some() {
                    tracing::debug!(
                        from = %from,
                        tip = manifest.tip_height,
                        "snapshot install active — dropping stale manifest response"
                    );
                    continue;
                }
                if pending_recent_suffix.is_some() || recent_suffix_apply_inflight.is_some() {
                    tracing::debug!(
                        from = %from,
                        tip = manifest.tip_height,
                        "compact recent suffix active — dropping stale manifest response"
                    );
                    continue;
                }
                // Received the state manifest (step 1 of snapshot sync).
                // Structural checks below bound all advertised work. Usable
                // responses enter a short work-ranked election so connection
                // order cannot select the finalized branch. The winner's exact
                // header chain, PoW, recursive terminal, state root and
                // immutable suffix still provide authority before installation.
                let force_snapshot = manifest_force_snapshot_peers.remove(&from);
                manifest_response_count += 1;
                if manifest.tip_height == 0 {
                    tracing::debug!(from = %from, "manifest tip_height=0, peer has no state yet");
                } else {
                    if history_step_runtime.is_none() {
                        tracing::warn!(
                            from = %from,
                            tip = manifest.tip_height,
                            "snapshot manifest ignored: HistoryStep verifier unavailable"
                        );
                        continue;
                    }
                    if manifest.segment_ids.len() != manifest.segment_roots.len()
                        || manifest.segment_ids.len() != manifest.segment_lengths.len()
                    {
                        tracing::warn!(
                            from = %from,
                            ids = manifest.segment_ids.len(),
                            roots = manifest.segment_roots.len(),
                            lengths = manifest.segment_lengths.len(),
                            "manifest descriptor vector length mismatch — dropping"
                        );
                        continue;
                    }
                    if !manifest.segment_ids.windows(2).all(|w| w[0] < w[1]) {
                        tracing::warn!(from = %from, "manifest segment IDs are not strictly sorted — dropping");
                        continue;
                    }
                    let segment_span = manifest
                        .log_slots
                        .saturating_sub(manifest.eff_log as u32);
                    let max_possible_segments = 1usize.checked_shl(segment_span).unwrap_or(usize::MAX);
                    if manifest.segment_ids.len() > max_possible_segments {
                        tracing::warn!(
                            from = %from,
                            segments = manifest.segment_ids.len(),
                            max_possible_segments,
                            log_slots = manifest.log_slots,
                            eff_log = manifest.eff_log,
                            "manifest impossible for advertised log_slots/eff_log — dropping"
                        );
                        continue;
                    }
                    let Some(maximum_segment_bytes) =
                        max_encoded_segment_len_for_eff_log(manifest.eff_log)
                    else {
                        tracing::warn!(
                            from = %from,
                            eff_log = manifest.eff_log,
                            "manifest has invalid effective segment log — dropping"
                        );
                        continue;
                    };
                    if maximum_segment_bytes > MAX_SEGMENT_BYTES {
                        tracing::warn!(
                            from = %from,
                            eff_log = manifest.eff_log,
                            maximum_segment_bytes,
                            max_segment = MAX_SEGMENT_BYTES,
                            "manifest segment encoding exceeds per-segment cap — dropping"
                        );
                        continue;
                    }
                    let mut declared_live_count = 0u64;
                    let mut sparse_lengths_valid = true;
                    for &encoded_len in &manifest.segment_lengths {
                        let Some(live_count) = encoded_segment_live_count_from_len(
                            manifest.eff_log,
                            encoded_len as usize,
                        ) else {
                            sparse_lengths_valid = false;
                            break;
                        };
                        if live_count == 0 {
                            sparse_lengths_valid = false;
                            break;
                        }
                        let Some(next) =
                            declared_live_count.checked_add(u64::from(live_count))
                        else {
                            sparse_lengths_valid = false;
                            break;
                        };
                        declared_live_count = next;
                    }
                    if !sparse_lengths_valid
                        || declared_live_count != manifest.active_slot_count
                    {
                        tracing::warn!(
                            from = %from,
                            declared_live_count,
                            active_slot_count = manifest.active_slot_count,
                            "manifest sparse lengths are noncanonical or disagree with active count — dropping"
                        );
                        continue;
                    }
                    if manifest.segment_ids.len() > MAX_SNAPSHOT_MANIFEST_SEGMENTS {
                        tracing::warn!(
                            from = %from,
                            segments = manifest.segment_ids.len(),
                            max_segments = MAX_SNAPSHOT_MANIFEST_SEGMENTS,
                            "manifest exceeds snapshot manifest segment cap — dropping"
                        );
                        continue;
                    }
                }

                if manifest.tip_height > 0 {
                    manifest_terminal_capabilities.insert(
                        from,
                        ManifestTerminalCapability {
                            boundary_height: manifest.tip_height,
                            boundary_hash: manifest.tip_hash,
                            bridge_height: manifest.bridge_tip_height,
                            bridge_hash: manifest.bridge_tip_hash,
                        },
                    );
                    let our_height = {
                        let ctx = chain.read().await;
                        ctx.tip_height()
                    };
                    if manifest.tip_height <= our_height {
                        tracing::debug!(
                            from = %from,
                            our_height,
                            snapshot_height = manifest.tip_height,
                            "manifest snapshot boundary not ahead"
                        );
                        if manifest_round_gap_is_resolved(our_height, highest_announced)
                            && pending_manifest.is_none()
                            && pending_snapshot_header_sync.is_none()
                            && snapshot_header_staging_inflight.is_none()
                            && history_step_verification_inflight.is_none()
                            && snapshot_staging.is_none()
                            && snapshot_staging_inflight.is_none()
                            && snapshot_install_inflight.is_none()
                            && pending_segment_ids.is_empty()
                            && segment_queue.is_empty()
                        {
                            clear_manifest_round_state!();
                            mark_bootstrap_complete_if_caught_up!(our_height);
                            tracing::debug!(
                                our_height,
                                highest_announced,
                                "announced gap closed — discarded obsolete manifest round"
                            );
                        }
                        continue;
                    }

                    let snapshot_gap = manifest.tip_height.saturating_sub(our_height);
                    tracing::info!(
                        from = %from,
                        our_height,
                        snapshot_height = manifest.tip_height,
                        snapshot_gap,
                        force_snapshot,
                        "manifest snapshot boundary ahead — queueing snapshot candidate"
                    );
                }

                if manifest.tip_height > 0
                    && pending_manifest.is_none()
                    && pending_snapshot_header_sync.is_none()
                    && snapshot_header_staging_inflight.is_none()
                    && history_step_verification_inflight.is_none()
                    && snapshot_staging_inflight.is_none()
                    && snapshot_install_inflight.is_none()
                    && pending_recent_suffix.is_none()
                    && recent_suffix_apply_inflight.is_none()
                {
                    let replace = best_manifest_candidate.as_ref().is_none_or(|current| {
                        state_manifest_candidate_is_preferred(&manifest, &current.manifest)
                    });
                    if replace {
                        tracing::info!(
                            from = %from,
                            tip = manifest.tip_height,
                            bridge_tip = manifest.bridge_tip_height,
                            segments = manifest.segment_ids.len(),
                            "stronger snapshot manifest entered bounded candidate election"
                        );
                        best_manifest_candidate = Some(SnapshotManifestCandidate {
                            from,
                            manifest,
                        });
                    } else {
                        tracing::debug!(
                            from = %from,
                            tip = manifest.tip_height,
                            bridge_tip = manifest.bridge_tip_height,
                            "weaker snapshot manifest ignored during candidate election"
                        );
                    }
                    manifest_candidate_started_at.get_or_insert_with(Instant::now);
                } else if manifest.tip_height > 0 {
                    // Manifest chainwork is only a claim until its exact native
                    // header chain has been validated. Never interrupt useful
                    // work because an unauthenticated peer writes a larger
                    // integer here. Ordinary fork choice probes this peer after
                    // the active, fully authenticated snapshot is installed.
                    deferred_sync_peer = Some(from);
                    tracing::debug!(
                        from = %from,
                        tip = manifest.tip_height,
                        "late manifest deferred to authenticated post-install fork choice"
                    );
                }
                if manifest_tip_height == 0
                    && manifest_requested_peers.is_empty()
                    && selected_snapshot_peer!().is_none()
                    && best_manifest_candidate.is_none()
                {
                    let our_height = {
                        let ctx = chain.read().await;
                        ctx.tip_height()
                    };
                    if manifest_round_gap_is_resolved(our_height, highest_announced) {
                        tracing::debug!(
                            our_height,
                            "empty manifest round settled; awaiting authenticated tip probe"
                        );
                    }
                }
            }

            Ok(NetworkEvent::StateSegment { from, response }) => {
                // Received one segment (step 2 of snapshot sync).
                // Authenticate and seal it to disk immediately; decoded state
                // never accumulates in the node process.  Hashing, decoding,
                // fsync, and atomic publication run one-at-a-time on the
                // blocking pool so the sole P2P event loop keeps draining.
                if snapshot_install_inflight.is_some() {
                    tracing::debug!(
                        from = %from,
                        segment = response.segment_id,
                        "snapshot install active — releasing stale segment response"
                    );
                    drop(response);
                    continue;
                }
                let Some((selected_peer, selected_tip_height, selected_tip_hash)) =
                    pending_manifest.as_ref().map(|pending| {
                        (
                            pending.from,
                            pending.manifest.tip_height,
                            pending.manifest.tip_hash,
                        )
                    })
                else {
                    tracing::warn!(
                        from = %from,
                        segment = response.segment_id,
                        "snapshot segment has no active manifest — dropped"
                    );
                    drop(response);
                    continue;
                };
                if selected_peer != from
                    || !state_segment_response_matches_snapshot_boundary(
                        response.expected_tip_height,
                        response.expected_tip_hash,
                        selected_tip_height,
                        selected_tip_hash,
                    )
                {
                    tracing::warn!(
                        from = %from,
                        selected_peer = %selected_peer,
                        segment = response.segment_id,
                        response_height = response.expected_tip_height,
                        selected_height = selected_tip_height,
                        "snapshot segment belongs to another peer/session boundary — dropped"
                    );
                    drop(response);
                    continue;
                }
                if response.data.is_none() {
                    // The selected immutable generation could not serve an
                    // advertised segment. Preserve the authenticated headers
                    // and immediately rotate away from that generation owner.
                    tracing::warn!(
                        from = %from,
                        segment = response.segment_id,
                        "snapshot segment unavailable or stale; rotating snapshot owner"
                    );
                    preserve_active_snapshot_headers!();
                    reset_sync_state!();
                    request_bounded_manifest_failover!(from, false);
                    continue;
                }

                match admit_snapshot_segment_response(
                    response.segment_id,
                    snapshot_staging_inflight.is_some(),
                    queued_segment_response.is_some(),
                    &mut pending_segment_ids,
                    &mut segment_queue,
                ) {
                    SnapshotSegmentResponseAdmission::StageNow => {
                        snapshot_segment_retry_counts.remove(&response.segment_id);
                        stage_snapshot_segment_response!(from, response);
                    }
                    SnapshotSegmentResponseAdmission::BufferOne => {
                        let segment_id = response.segment_id;
                        snapshot_segment_retry_counts.remove(&segment_id);
                        queued_segment_response = Some((from, response));
                        tracing::debug!(
                            from = %from,
                            segment = segment_id,
                            "snapshot segment retained in the one-response staging buffer"
                        );
                    }
                    SnapshotSegmentResponseAdmission::RetryOverflow => {
                        // Keep a bounded recovery path if a stale transport
                        // violates the one-lane invariant.
                        let segment_id = response.segment_id;
                        drop(response);
                        tracing::warn!(
                            from = %from,
                            segment = segment_id,
                            "snapshot segment response exceeded bounded staging pipeline"
                        );
                    }
                    SnapshotSegmentResponseAdmission::Stale => {
                        tracing::debug!(
                            from = %from,
                            segment = response.segment_id,
                            "dropping stale or duplicate snapshot segment response"
                        );
                        drop(response);
                    }
                }
                if let Some(pending) = pending_manifest.as_ref() {
                    dispatch_queued_snapshot_segments(
                        &p2p_cmd,
                        pending.from,
                        pending.manifest.tip_height,
                        pending.manifest.tip_hash,
                        snapshot_staging_inflight.is_some(),
                        queued_segment_response.is_some(),
                        &mut pending_segment_ids,
                        &mut segment_queue,
                    )
                    .await;
                }
                continue;
            }

            Ok(NetworkEvent::StateSegmentRequestFailed {
                from,
                segment_id,
                expected_tip_height,
                expected_tip_hash,
            }) => {
                let correlated = pending_manifest.as_ref().is_some_and(|pending| {
                    pending.from == from
                        && pending.manifest.tip_height == expected_tip_height
                        && pending.manifest.tip_hash == expected_tip_hash
                        && pending_segment_ids.contains(&segment_id)
                });
                if !correlated {
                    tracing::debug!(
                        peer = %from,
                        segment = segment_id,
                        expected_tip_height,
                        "ignoring stale state-segment request failure"
                    );
                    continue;
                }
                let retry_count = snapshot_segment_retry_counts
                    .entry(segment_id)
                    .and_modify(|count| *count = count.saturating_add(1))
                    .or_insert(1);
                let alternate_available = manifest_peers.iter().any(|peer| *peer != from);
                if *retry_count == 1 && !alternate_available {
                    pending_segment_ids.remove(&segment_id);
                    if !segment_queue.contains(&segment_id) {
                        segment_queue.push_front(segment_id);
                    }
                    tracing::warn!(
                        peer = %from,
                        segment = segment_id,
                        expected_tip_height,
                        retry = *retry_count,
                        "snapshot segment transport failed — retrying only the missing segment"
                    );
                    dispatch_queued_snapshot_segments(
                        &p2p_cmd,
                        from,
                        expected_tip_height,
                        expected_tip_hash,
                        snapshot_staging_inflight.is_some(),
                        queued_segment_response.is_some(),
                        &mut pending_segment_ids,
                        &mut segment_queue,
                    )
                    .await;
                    continue;
                }
                tracing::warn!(
                    peer = %from,
                    segment = segment_id,
                    expected_tip_height,
                    retries = *retry_count,
                    alternate_available,
                    "snapshot segment transport failed; reacquiring immutable generation"
                );
                preserve_active_snapshot_headers!();
                reset_sync_state!();
                request_bounded_manifest_failover!(from, !alternate_available);
            }

            Ok(NetworkEvent::HistoryStepTerminal {
                token,
                from,
                height,
                block_hash,
                terminal_bytes,
                inbound_memory_permit,
            }) => {
                let recent_correlated = pending_recent_suffix.as_ref().is_some_and(|pending| {
                    pending.generation == recent_suffix_generation
                        && pending.terminal_requests.matches(from, token)
                        && pending.target_height == height
                        && pending.target_hash == block_hash
                });
                if recent_correlated {
                    if terminal_bytes.is_empty() {
                        drop(inbound_memory_permit);
                        let pending = pending_recent_suffix
                            .as_mut()
                            .expect("correlated compact suffix is present");
                        let marked = pending.terminal_requests.mark_failed(from, token);
                        debug_assert!(marked, "correlated compact terminal must be active");
                        if pending.terminal_requests.has_active() {
                            continue;
                        }
                        let alternate = (pending.terminal_requests.hedge.is_none())
                            .then(|| {
                                terminal_alternate_peer(
                                    &manifest_peers,
                                    &rejected_terminal_peers,
                                    &pending.terminal_requests,
                                )
                            })
                            .flatten();
                        if let Some(alternate) = alternate {
                            let request_token = pending.terminal_requests.primary.token;
                            pending.terminal_requests.install_hedge(alternate);
                            if p2p_cmd
                                .send(noid_p2p::NetworkCommand::RequestHistoryStepTerminal {
                                    token: request_token,
                                    peer: alternate,
                                    height,
                                    block_hash,
                                })
                                .await
                                .is_ok()
                            {
                                tracing::warn!(
                                    peer = %from,
                                    alternate = %alternate,
                                    height,
                                    "compact suffix terminal unavailable — trying one alternate peer"
                                );
                                continue;
                            }
                        }
                        fallback_recent_suffix_to_full_bundles!(
                            "compact suffix terminal unavailable"
                        );
                        continue;
                    }
                    let pending = pending_recent_suffix
                        .as_mut()
                        .expect("correlated compact suffix is present");
                    // First exact success wins. Close both sides of the race
                    // before retaining the payload so the heartbeat cannot
                    // launch a late hedge and a losing response cannot replace
                    // already accepted terminal bytes.
                    let won = pending.terminal_requests.mark_succeeded(from, token);
                    debug_assert!(won, "correlated compact terminal must win its race");
                    pending.terminal_payload = Some(PrefetchedHistoryStepTerminal {
                        token,
                        from,
                        terminal_bytes,
                        inbound_memory_permit,
                    });
                    tracing::info!(
                        peer = %from,
                        height,
                        "compact recent suffix terminal received"
                    );
                    try_start_recent_suffix_apply!();
                    continue;
                }
                let tail_key = snapshot_tail_terminal_inflight.filter(|pending| {
                        pending.generation == snapshot_sync_generation
                            && pending.requests.matches(from, token)
                            && pending.height == height
                            && pending.block_hash == block_hash
                    });
                if let Some(tail_key) = tail_key {
                    if terminal_bytes.is_empty() {
                        drop(inbound_memory_permit);
                        let mut pending = snapshot_tail_terminal_inflight
                            .take()
                            .expect("correlated bridge terminal is present");
                        let marked = pending.requests.mark_failed(from, token);
                        debug_assert!(marked, "correlated bridge terminal must be active");
                        if pending.requests.has_active() {
                            snapshot_tail_terminal_inflight = Some(pending);
                            continue;
                        }
                        let alternate = (pending.requests.hedge.is_none())
                            .then(|| {
                                advertised_terminal_alternate_peer(
                                    &manifest_peers,
                                    &manifest_terminal_capabilities,
                                    &rejected_terminal_peers,
                                    &pending.requests,
                                    height,
                                    block_hash,
                                )
                            })
                            .flatten();
                        if let Some(alternate) = alternate {
                            let request_token = pending.requests.primary.token;
                            pending.requests.install_hedge(alternate);
                            snapshot_tail_terminal_inflight = Some(pending);
                            if p2p_cmd
                                .send(noid_p2p::NetworkCommand::RequestHistoryStepTerminal {
                                    token: request_token,
                                    peer: alternate,
                                    height,
                                    block_hash,
                                })
                                .await
                                .is_ok()
                            {
                                tracing::warn!(
                                    peer = %from,
                                    alternate = %alternate,
                                    height,
                                    "snapshot bridge terminal unavailable — trying one alternate peer"
                                );
                                continue;
                            }
                        }
                        tracing::warn!(
                            from = %from,
                            height,
                            "snapshot bridge terminal is unavailable"
                        );
                        preserve_active_snapshot_headers!();
                        reset_sync_state!();
                        request_bounded_manifest_failover!(tail_key.manifest_from, true);
                        continue;
                    }
                    let won = snapshot_tail_terminal_inflight
                        .as_mut()
                        .expect("correlated bridge terminal is present")
                        .requests
                        .mark_succeeded(from, token);
                    debug_assert!(won, "correlated bridge terminal must win its race");
                    snapshot_tail_terminal_inflight = None;
                    prefetched_snapshot_tail_terminal = Some(PrefetchedHistoryStepTerminal {
                        token,
                        from,
                        terminal_bytes,
                        inbound_memory_permit,
                    });
                    tracing::info!(
                        from = %from,
                        height,
                        "snapshot bridge terminal prefetched — waiting for state and bodies"
                    );
                    try_start_ready_snapshot_install!();
                    continue;
                }

                let boundary_key = snapshot_boundary_terminal_inflight.filter(|pending| {
                    pending.generation == snapshot_sync_generation
                        && pending.requests.matches(from, token)
                        && pending.height == height
                        && pending.block_hash == block_hash
                });
                let Some(boundary_key) = boundary_key else {
                    drop(terminal_bytes);
                    drop(inbound_memory_permit);
                    tracing::debug!(
                        from = %from,
                        height,
                        "dropping stale or mismatched HistoryStep terminal response"
                    );
                    continue;
                };
                if terminal_bytes.is_empty() {
                    drop(inbound_memory_permit);
                    let mut pending = snapshot_boundary_terminal_inflight
                        .take()
                        .expect("correlated boundary terminal is present");
                    let marked = pending.requests.mark_failed(from, token);
                    debug_assert!(marked, "correlated boundary terminal must be active");
                    if pending.requests.has_active() {
                        snapshot_boundary_terminal_inflight = Some(pending);
                        continue;
                    }
                    let alternate = (pending.requests.hedge.is_none())
                        .then(|| {
                            advertised_terminal_alternate_peer(
                                &manifest_peers,
                                &manifest_terminal_capabilities,
                                &rejected_terminal_peers,
                                &pending.requests,
                                height,
                                block_hash,
                            )
                        })
                        .flatten();
                    if let Some(alternate) = alternate {
                        let request_token = pending.requests.primary.token;
                        pending.requests.install_hedge(alternate);
                        snapshot_boundary_terminal_inflight = Some(pending);
                        if p2p_cmd
                            .send(noid_p2p::NetworkCommand::RequestHistoryStepTerminal {
                                token: request_token,
                                peer: alternate,
                                height,
                                block_hash,
                            })
                            .await
                            .is_ok()
                        {
                            tracing::warn!(
                                peer = %from,
                                alternate = %alternate,
                                height,
                                "snapshot boundary terminal unavailable — trying one alternate peer"
                            );
                            continue;
                        }
                    }
                    tracing::warn!(
                        from = %from,
                        height,
                        "snapshot boundary terminal is unavailable"
                    );
                    preserve_active_snapshot_headers!();
                    reset_sync_state!();
                    request_bounded_manifest_failover!(boundary_key.manifest_from, true);
                    continue;
                }
                let won = snapshot_boundary_terminal_inflight
                    .as_mut()
                    .expect("correlated boundary terminal is present")
                    .requests
                    .mark_succeeded(from, token);
                debug_assert!(won, "correlated boundary terminal must win its race");
                snapshot_boundary_terminal_inflight = None;
                let payload = PrefetchedHistoryStepTerminal {
                    token,
                    from,
                    terminal_bytes,
                    inbound_memory_permit,
                };
                let headers_ready = snapshot_header_staging_inflight.is_none()
                    && pending_snapshot_header_sync.as_ref().is_some_and(|sync| {
                        sync.from == boundary_key.manifest_from
                            && sync.next_height == sync.target_height.saturating_add(1)
                    });
                if headers_ready {
                    let sync = pending_snapshot_header_sync
                        .take()
                        .expect("checked completed snapshot header staging");
                    start_snapshot_boundary_verification!(sync, payload);
                } else {
                    prefetched_snapshot_boundary_terminal = Some(payload);
                    tracing::info!(
                        from = %from,
                        height,
                        "snapshot boundary terminal prefetched — waiting for staged headers"
                    );
                }
                continue;
            }
            Ok(NetworkEvent::HistoryStepTerminalRequestFailed {
                token,
                from,
                height,
                block_hash,
                kind,
            }) => {
                let recent_correlated = pending_recent_suffix.as_ref().is_some_and(|pending| {
                    pending.generation == recent_suffix_generation
                        && pending.terminal_requests.matches(from, token)
                        && pending.target_height == height
                        && pending.target_hash == block_hash
                });
                if recent_correlated {
                    let pending = pending_recent_suffix
                        .as_mut()
                        .expect("correlated compact suffix is present");
                    let marked = pending.terminal_requests.mark_failed(from, token);
                    debug_assert!(marked, "correlated compact terminal request must be active");
                    if pending.terminal_requests.has_active() {
                        continue;
                    }
                    let alternate = (pending.terminal_requests.hedge.is_none())
                        .then(|| {
                            terminal_alternate_peer(
                                &manifest_peers,
                                &rejected_terminal_peers,
                                &pending.terminal_requests,
                            )
                        })
                        .flatten();
                    if let Some(alternate) = alternate {
                        let request_token = pending.terminal_requests.primary.token;
                        pending.terminal_requests.install_hedge(alternate);
                        if p2p_cmd
                            .send(noid_p2p::NetworkCommand::RequestHistoryStepTerminal {
                                token: request_token,
                                peer: alternate,
                                height,
                                block_hash,
                            })
                            .await
                            .is_ok()
                        {
                            tracing::warn!(
                                peer = %from,
                                alternate = %alternate,
                                height,
                                ?kind,
                                "compact suffix terminal failed — trying one alternate peer"
                            );
                            continue;
                        }
                    }
                    fallback_recent_suffix_to_full_bundles!(
                        "compact suffix terminal transport exhausted"
                    );
                    continue;
                }
                let tail_correlated = snapshot_tail_terminal_inflight.is_some_and(|pending| {
                    pending.generation == snapshot_sync_generation
                        && pending.requests.matches(from, token)
                        && pending.height == height
                        && pending.block_hash == block_hash
                });
                if tail_correlated {
                    let mut pending = snapshot_tail_terminal_inflight
                        .take()
                        .expect("correlated suffix terminal is present");
                    let marked = pending.requests.mark_failed(from, token);
                    debug_assert!(marked, "correlated suffix request must be active");
                    if pending.requests.has_active() {
                        snapshot_tail_terminal_inflight = Some(pending);
                        tracing::warn!(
                            peer = %from,
                            height,
                            ?kind,
                            "one snapshot suffix terminal request failed — alternate remains active"
                        );
                        continue;
                    }
                    let alternate = if pending.requests.hedge.is_none() {
                        advertised_terminal_alternate_peer(
                            &manifest_peers,
                            &manifest_terminal_capabilities,
                            &rejected_terminal_peers,
                            &pending.requests,
                            height,
                            block_hash,
                        )
                    } else {
                        None
                    };
                    if let Some(alternate) = alternate {
                        let request_token = pending.requests.primary.token;
                        pending.requests.install_hedge(alternate);
                        snapshot_tail_terminal_inflight = Some(pending);
                        if p2p_cmd
                            .send(noid_p2p::NetworkCommand::RequestHistoryStepTerminal {
                                token: request_token,
                                peer: alternate,
                                height,
                                block_hash,
                            })
                            .await
                            .is_ok()
                        {
                            tracing::warn!(
                                peer = %from,
                                alternate = %alternate,
                                height,
                                ?kind,
                                "snapshot suffix terminal failed — trying one alternate peer"
                            );
                            continue;
                        }
                    }

                    tracing::warn!(
                        peer = %from,
                        height,
                        ?kind,
                        "snapshot suffix terminal exhausted — restarting bounded snapshot sync"
                    );
                    preserve_active_snapshot_headers!();
                    reset_sync_state!();
                    request_bounded_manifest_failover!(
                        from,
                        terminal_transport_can_retry_same_peer(kind)
                    );
                    continue;
                }

                let boundary_correlated =
                    snapshot_boundary_terminal_inflight.is_some_and(|pending| {
                        pending.generation == snapshot_sync_generation
                            && pending.requests.matches(from, token)
                            && pending.height == height
                            && pending.block_hash == block_hash
                    });
                if !boundary_correlated {
                    tracing::debug!(
                        peer = %from,
                        height,
                        ?kind,
                        "ignoring stale HistoryStep transport failure"
                    );
                    continue;
                }

                let manifest_lease_was_lost = snapshot_boundary_terminal_inflight
                    .is_some_and(|pending| {
                        matches!(kind, noid_p2p::RequestFailureKind::ConnectionClosed)
                            && pending.manifest_from == from
                    });
                if !manifest_lease_was_lost {
                    let pending = snapshot_boundary_terminal_inflight
                        .as_mut()
                        .expect("correlated boundary terminal is present");
                    let marked = pending.requests.mark_failed(from, token);
                    debug_assert!(marked, "correlated HistoryStep request must be active");
                    if pending.requests.has_active() {
                        tracing::warn!(
                            peer = %from,
                            height,
                            ?kind,
                            "one HistoryStep terminal request failed — alternate remains active"
                        );
                        continue;
                    }
                }

                let alternate = snapshot_boundary_terminal_inflight.as_ref().and_then(|pending| {
                    (!manifest_lease_was_lost && pending.requests.hedge.is_none())
                        .then(|| {
                            advertised_terminal_alternate_peer(
                                &manifest_peers,
                                &manifest_terminal_capabilities,
                                &rejected_terminal_peers,
                                &pending.requests,
                                height,
                                block_hash,
                            )
                        })
                        .flatten()
                });
                if let Some(alternate) = alternate {
                    let pending = snapshot_boundary_terminal_inflight
                        .as_mut()
                        .expect("correlated boundary terminal is present");
                    let request_token = pending.requests.primary.token;
                    pending.requests.install_hedge(alternate);
                    if p2p_cmd
                        .send(noid_p2p::NetworkCommand::RequestHistoryStepTerminal {
                            token: request_token,
                            peer: alternate,
                            height,
                            block_hash,
                        })
                        .await
                        .is_ok()
                    {
                        tracing::warn!(
                            peer = %from,
                            alternate = %alternate,
                            height,
                            ?kind,
                            "HistoryStep terminal failed — retaining headers and trying one alternate peer"
                        );
                        continue;
                    }
                }

                // Keep the validated native header file on disk. A fresh
                // manifest for the same exact boundary reopens it instead of
                // downloading O(height) headers again.
                if let Some(sync) = pending_snapshot_header_sync.take() {
                    let staged_headers = sync.staging.staged_len();
                    let staging_path = sync.staging.path().to_owned();
                    drop(sync);
                    tracing::warn!(
                        peer = %from,
                        height,
                        ?kind,
                        staged_headers,
                        path = %staging_path.display(),
                        "HistoryStep transport exhausted — retaining exact header staging for failover"
                    );
                }
                preserve_active_snapshot_headers!();
                reset_sync_state!();
                request_bounded_manifest_failover!(
                    from,
                    terminal_transport_can_retry_same_peer(kind)
                );
            }
            Ok(NetworkEvent::StateManifestRequestFailed {
                generation,
                from,
                requester_height,
                kind,
            }) => {
                if generation != snapshot_sync_generation {
                    tracing::debug!(
                        generation,
                        active_generation = snapshot_sync_generation,
                        peer = %from,
                        requester_height,
                        "ignoring stale state-manifest request failure"
                    );
                    continue;
                }
                manifest_requested_peers.remove(&from);
                tracing::debug!(
                    generation,
                    peer = %from,
                    requester_height,
                    ?kind,
                    "state-manifest request failed; active snapshot work is unchanged"
                );
                if selected_snapshot_peer!().is_none() && manifest_requested_peers.is_empty() {
                    request_bounded_manifest_failover!(
                        from,
                        terminal_transport_can_retry_same_peer(kind)
                    );
                    if manifest_round_started_at.is_none() {
                        manifest_round_started_at = Some(Instant::now());
                    }
                }
            }
            Ok(NetworkEvent::PeerDisconnected(peer)) => {
                mining_peer_quorum.disconnect(peer);
                manifest_peers.remove(&peer);
                manifest_terminal_capabilities.remove(&peer);
                tracing::debug!(peer = %peer, "peer disconnected");
                if pending_shallow_fork
                    .as_ref()
                    .is_some_and(|pending| pending.peer == peer)
                {
                    tracing::debug!(
                        peer = %peer,
                        "selected shallow-fork peer disconnected"
                    );
                    if !retry_shallow_fork_bundle_peer!(peer, "selected peer disconnected") {
                        let stale = pending_shallow_fork
                            .take()
                            .expect("disconnected shallow-fork session exists");
                        retry_shallow_fork_headers!(stale, "all bundle peers disconnected");
                    }
                }
                let finalized_tail_no_longer_needs_manifest_peer =
                    finalized_snapshot_waiting.is_some()
                        && snapshot_tail_terminal_inflight.is_some();
                let local_header_work_active = snapshot_header_staging_inflight
                    .as_ref()
                    .is_some_and(|key| match key {
                        SnapshotHeaderStagingOperationKey::Prepare { from, .. } => *from == peer,
                        SnapshotHeaderStagingOperationKey::Append { manifest_from, .. } => {
                            *manifest_from == peer
                        }
                    }) || history_step_verification_inflight
                    .is_some_and(|pending| pending.from == peer);
                let snapshot_sync_lost = pending_manifest.as_ref().is_some_and(|pending| {
                    pending.from == peer && !finalized_tail_no_longer_needs_manifest_peer
                })
                    || pending_snapshot_header_sync
                        .as_ref()
                        .is_some_and(|pending| pending.from == peer)
                    || snapshot_header_staging_inflight.as_ref().is_some_and(|key| match key {
                        SnapshotHeaderStagingOperationKey::Prepare { from, .. } => *from == peer,
                        SnapshotHeaderStagingOperationKey::Append { manifest_from, .. } => {
                            *manifest_from == peer
                        }
                    })
                    || history_step_verification_inflight
                        .is_some_and(|pending| pending.from == peer);
                if snapshot_sync_lost {
                    if local_header_work_active {
                        tracing::debug!(
                            peer = %peer,
                            "snapshot peer disconnected; retaining local header work before failover"
                        );
                    } else {
                        preserve_active_snapshot_headers!();
                        tracing::warn!(
                            peer = %peer,
                            "snapshot peer disconnected; retaining headers and reacquiring the lease"
                        );
                        reset_sync_state!();
                        request_bounded_manifest_failover!(peer, false);
                    }
                }
                fetch_in_progress.remove(&peer);
                recent_header_fetches.retain(|(p, _, _), _| *p != peer);
                recent_block_fetches.retain(|(p, _), _| *p != peer);
                pending_block_fetches.retain(|_, pending| pending.peer != peer);
                manifest_requested_peers.remove(&peer);
                mempool_sync_requested_peers.remove(&peer);
                finalized_divergent_peers.remove(&peer);
                peer_tx_rate.remove(&peer);
                peer_block_rate.remove(&peer);
            }
            Err(noid_p2p::NetworkEventRecvError::Lagged(n)) => {
                tracing::warn!(n, "P2P gossip receiver lagged — recoverable gossip events dropped");
            }
            Err(noid_p2p::NetworkEventRecvError::Closed) => {
                tracing::info!("P2P event channel closed");
                break;
            }
        } // match rx_item
        } // rx_result arm

        completed = snapshot_header_staging_rx.recv() => {
            let Some(completed) = completed else {
                continue;
            };
            if snapshot_header_staging_inflight != Some(completed.key) {
                match completed.result {
                    SnapshotHeaderStagingResult::Success(sync)
                    | SnapshotHeaderStagingResult::CandidateRejected { sync, .. } => {
                        // A retired request does not invalidate the durable
                        // native-validated prefix. The next generation reopens
                        // and revalidates this exact file.
                        drop(sync.staging);
                    }
                    SnapshotHeaderStagingResult::Fatal(_) => {}
                }
                tracing::debug!(
                    key = ?completed.key,
                    "discarding superseded snapshot header staging completion"
                );
                continue;
            }
            snapshot_header_staging_inflight = None;
            let (generation, from, append_range) = match completed.key {
                SnapshotHeaderStagingOperationKey::Prepare {
                    generation, from, ..
                } => (generation, from, None),
                SnapshotHeaderStagingOperationKey::Append {
                    generation,
                    manifest_from,
                    range_from,
                    start_height,
                    count,
                    ..
                } => (
                    generation,
                    manifest_from,
                    Some((range_from, start_height, count)),
                ),
            };
            if generation != snapshot_sync_generation {
                match completed.result {
                    SnapshotHeaderStagingResult::Success(sync)
                    | SnapshotHeaderStagingResult::CandidateRejected { sync, .. } => {
                        // Transport generation churn must not turn completed
                        // local validation into another O(height) download.
                        drop(sync.staging);
                    }
                    SnapshotHeaderStagingResult::Fatal(_) => {}
                }
                tracing::debug!(
                    from = %from,
                    "discarding snapshot headers from a reset sync generation"
                );
                continue;
            }
            sync_phase_telemetry.record_header_work(completed.work_elapsed);
            let sync = match completed.result {
                SnapshotHeaderStagingResult::Success(sync) => sync,
                SnapshotHeaderStagingResult::CandidateRejected {
                    sync,
                    attempted_peers,
                    error,
                } => {
                    let Some((range_from, start_height, count)) = append_range else {
                        cleanup_snapshot_header_staging_offthread(sync.staging);
                        tracing::error!(err = %error, "snapshot header prepare was misclassified as peer input");
                        reset_sync_state!();
                        request_bounded_manifest_failover!(from, true);
                        continue;
                    };
                    let base_height = sync.staging.base().header.height;
                    if snapshot_parent_mismatch_is_at_base(
                        sync.staging.staged_len(),
                        base_height,
                        start_height,
                        &error,
                    )
                    {
                        // A manifest may win the event race before the general
                        // linked-header probe, or the selected branch may move
                        // after an earlier rebase hint was armed. In either
                        // case this exact base is objectively stale. Do not
                        // rotate the same impossible first range across every
                        // peer: retire the hint and establish a fresh native-
                        // validated common ancestor over the complete non-final
                        // window.
                        cleanup_snapshot_header_staging_offthread(sync.staging);
                        snapshot_rebase_hint = None;
                        reset_sync_state!();
                        let our_height = {
                            let ctx = chain.read().await;
                            ctx.tip_height()
                        };
                        let discovery_start = finalized_header_search_floor(our_height);
                        let discovery_tip = sync
                            .manifest
                            .bridge_tip_height
                            .max(sync.manifest.tip_height);
                        let discovery_count = discovery_tip
                            .saturating_sub(discovery_start)
                            .saturating_add(1)
                            .clamp(
                                u64::from(CONNECTED_TIP_PROBE_HEADERS),
                                MAX_STAGED_HEADER_BATCH as u64,
                            ) as u16;
                        let request_key = (range_from, discovery_start, discovery_count);
                        let discovery_dispatched = if fetch_in_progress.insert(range_from) {
                            recent_header_fetches.insert(request_key, Instant::now());
                            if p2p_cmd
                                .send(noid_p2p::NetworkCommand::FetchHeaders {
                                    peer: range_from,
                                    start_height: discovery_start,
                                    count: discovery_count,
                                })
                                .await
                                .is_ok()
                            {
                                true
                            } else {
                                fetch_in_progress.remove(&range_from);
                                recent_header_fetches.remove(&request_key);
                                false
                            }
                        } else {
                            // A general response from this peer is already
                            // correlated and will enter the same bounded
                            // ancestor-discovery path after the snapshot state
                            // above has been reset.
                            false
                        };
                        tracing::warn!(
                            manifest_peer = %from,
                            range_peer = %range_from,
                            base_height,
                            discovery_start,
                            discovery_dispatched,
                            err = %error,
                            "snapshot boundary has a competing parent; discovering an authenticated non-final rebase before retry"
                        );
                        continue;
                    }
                    if sync.from != from || !manifest_peers.contains(&from) {
                        let staged_headers = sync.staging.staged_len();
                        drop(sync.staging);
                        tracing::warn!(
                            manifest_peer = %from,
                            range_peer = %range_from,
                            staged_headers,
                            "snapshot owner disconnected while a header range was rejected; retaining prefix"
                        );
                        reset_sync_state!();
                        request_bounded_manifest_failover!(from, false);
                        continue;
                    }
                    let retry = snapshot_header_pipeline.as_mut().and_then(|pipeline| {
                        (pipeline.generation == generation && pipeline.from == from)
                            .then(|| {
                                pipeline.retry_rejected_range(
                                    start_height,
                                    count,
                                    attempted_peers,
                                    &manifest_peers,
                                )
                            })
                            .flatten()
                    });
                    let Some(request) = retry else {
                        let staged_headers = sync.staging.staged_len();
                        drop(sync.staging);
                        tracing::warn!(
                            manifest_peer = %from,
                            range_peer = %range_from,
                            start_height,
                            count,
                            staged_headers,
                            err = %error,
                            "rejected snapshot header range lost its correlation; retaining prefix for failover"
                        );
                        reset_sync_state!();
                        request_bounded_manifest_failover!(from, false);
                        continue;
                    };
                    pending_snapshot_header_sync = Some(sync);
                    let _ = p2p_cmd
                        .send(noid_p2p::NetworkCommand::FetchSnapshotHeaders {
                            generation,
                            token: request.token,
                            peer: request.peer,
                            start_height: request.start_height,
                            count: request.count,
                        })
                        .await;
                    tracing::warn!(
                        manifest_peer = %from,
                        range_peer = %range_from,
                        retry_peer = %request.peer,
                        start_height,
                        count,
                        err = %error,
                        "snapshot header candidate rejected; retained valid prefix and rotated the exact range"
                    );
                    continue;
                }
                SnapshotHeaderStagingResult::Fatal(error) => {
                    tracing::warn!(
                        from = %from,
                        err = %error,
                        "snapshot header preparation/staging failed"
                    );
                    reset_sync_state!();
                    request_bounded_manifest_failover!(from, true);
                    continue;
                }
            };
            if sync.from != from {
                cleanup_snapshot_header_staging_offthread(sync.staging);
                tracing::warn!(from = %from, "snapshot header staging peer changed");
                reset_sync_state!();
                continue;
            }
            if !manifest_peers.contains(&from) {
                let staged_headers = sync.staging.staged_len();
                let staging_path = sync.staging.path().to_owned();
                drop(sync.staging);
                tracing::warn!(
                    peer = %from,
                    staged_headers,
                    path = %staging_path.display(),
                    "snapshot owner disconnected during local header work; retaining progress for failover"
                );
                reset_sync_state!();
                request_bounded_manifest_failover!(from, false);
                continue;
            }

            let action = match snapshot_header_next_action(sync.next_height, sync.target_height) {
                Ok(action) => action,
                Err(error) => {
                    cleanup_snapshot_header_staging_offthread(sync.staging);
                    tracing::warn!(from = %from, err = %error, "snapshot header staging has invalid progress");
                    reset_sync_state!();
                    continue;
                }
            };
            match action {
                SnapshotHeaderNextAction::Fetch {
                    start_height,
                    count: _,
                } => {
                    let target_height = sync.target_height;
                    if snapshot_header_pipeline.is_none() {
                        snapshot_header_pipeline = Some(SnapshotHeaderPipeline::new(
                            generation,
                            from,
                            start_height,
                            target_height,
                        ));
                    }
                    let pipeline = snapshot_header_pipeline
                        .as_mut()
                        .expect("snapshot header pipeline was initialized");
                    if pipeline.generation != generation || pipeline.from != from {
                        cleanup_snapshot_header_staging_offthread(sync.staging);
                        tracing::warn!(
                            peer = %from,
                            generation,
                            "snapshot header pipeline changed during disk staging"
                        );
                        reset_sync_state!();
                        continue;
                    }

                    if let Some(range) = pipeline.take_ready(sync.next_height) {
                        if let Err(error) = validate_snapshot_header_batch_admission(
                            sync.next_height,
                            sync.target_height,
                            range.headers.len(),
                        ) {
                            cleanup_snapshot_header_staging_offthread(sync.staging);
                            tracing::warn!(
                                peer = %range.source_peer,
                                err = %error,
                                "buffered snapshot header batch failed staging admission"
                            );
                            reset_sync_state!();
                            continue;
                        }
                        let refill = pipeline.refill_plan(true);
                        for request in refill {
                            let _ = p2p_cmd
                                .send(noid_p2p::NetworkCommand::FetchSnapshotHeaders {
                                    generation,
                                    token: request.token,
                                    peer: request.peer,
                                    start_height: request.start_height,
                                    count: request.count,
                                })
                                .await;
                        }
                        spawn_snapshot_header_append!(sync, range);
                        continue;
                    }

                    let refill = pipeline.refill_plan(false);
                    pending_snapshot_header_sync = Some(sync);
                    for request in refill {
                        let _ = p2p_cmd
                            .send(noid_p2p::NetworkCommand::FetchSnapshotHeaders {
                                generation,
                                token: request.token,
                                peer: request.peer,
                                start_height: request.start_height,
                                count: request.count,
                            })
                            .await;
                    }
                    tracing::info!(
                        peer = %from,
                        next_height = start_height,
                        target_height,
                        window = SNAPSHOT_HEADER_REQUEST_WINDOW,
                        "snapshot: pipelining exactly correlated headers into disk staging"
                    );
                }
                SnapshotHeaderNextAction::RequestTerminal => {
                    if snapshot_header_pipeline
                        .as_ref()
                        .is_some_and(|pipeline| !pipeline.is_drained())
                    {
                        cleanup_snapshot_header_staging_offthread(sync.staging);
                        tracing::warn!(
                            peer = %from,
                            "snapshot header target reached with an undrained request window"
                        );
                        reset_sync_state!();
                        continue;
                    }
                    snapshot_header_pipeline = None;
                    let terminal_height = sync.manifest.tip_height;
                    let terminal_hash = sync.manifest.tip_hash;
                    if let Some(payload) = prefetched_snapshot_boundary_terminal.take() {
                        start_snapshot_boundary_verification!(sync, payload);
                    } else {
                        if snapshot_boundary_terminal_inflight.is_none() {
                            history_step_request_token =
                                history_step_request_token.wrapping_add(1);
                            let key = SnapshotBoundaryTerminalKey {
                                generation,
                                manifest_from: from,
                                requests: TerminalRequestRace::new(
                                    from,
                                    history_step_request_token,
                                ),
                                height: terminal_height,
                                block_hash: terminal_hash,
                            };
                            snapshot_boundary_terminal_inflight = Some(key);
                            let _ = p2p_cmd
                                .send(noid_p2p::NetworkCommand::RequestHistoryStepTerminal {
                                    token: key.requests.primary.token,
                                    peer: from,
                                    height: terminal_height,
                                    block_hash: terminal_hash,
                                })
                                .await;
                            tracing::info!(
                                peer = %from,
                                target_height = terminal_height,
                                "snapshot: exact headers staged — retrying HistoryStep terminal"
                            );
                        } else {
                            tracing::info!(
                                peer = %from,
                                target_height = terminal_height,
                                "snapshot: exact headers staged — waiting for prefetched HistoryStep terminal"
                            );
                        }
                        pending_snapshot_header_sync = Some(sync);
                    }
                }
            }
        }

        completed = recent_suffix_append_rx.recv() => {
            let Some(completed) = completed else {
                continue;
            };
            let correlated = pending_recent_suffix.as_ref().is_some_and(|pending| {
                pending.generation == completed.generation
                    && pending.generation == recent_suffix_generation
                    && pending.append_active
            });
            if !correlated {
                drop(completed.result);
                tracing::debug!(
                    generation = completed.generation,
                    "discarding superseded compact suffix append"
                );
                continue;
            }
            match completed.result {
                Ok(staging) => {
                    let pending = pending_recent_suffix
                        .as_mut()
                        .expect("correlated compact suffix is present");
                    pending.append_active = false;
                    if staging.tip_height() != pending.target_height
                        || staging.tip_hash() != pending.target_hash
                    {
                        drop(staging);
                        fallback_recent_suffix_to_full_bundles!(
                            "compact suffix body batch ended at the wrong tip"
                        );
                        continue;
                    }
                    pending.staging = Some(staging);
                    tracing::info!(
                        peer = %pending.peer,
                        base = pending.base_height,
                        target = pending.target_height,
                        "compact recent suffix bodies sealed on disk"
                    );
                    try_start_recent_suffix_apply!();
                }
                Err(error) => {
                    tracing::warn!(
                        generation = completed.generation,
                        err = %error,
                        "compact recent suffix body staging failed"
                    );
                    fallback_recent_suffix_to_full_bundles!(
                        "compact suffix body/header validation failed"
                    );
                }
            }
        }

        completed = recent_suffix_apply_rx.recv() => {
            let Some(completed) = completed else {
                continue;
            };
            if recent_suffix_apply_inflight != Some(completed.key) {
                tracing::debug!(
                    ?completed.key,
                    "discarding superseded compact suffix apply completion"
                );
                continue;
            }
            recent_suffix_apply_inflight = None;
            let terminal_rejected = matches!(
                &completed.result,
                Err(CompactSuffixApplyError::Terminal(_))
            );
            let _ = p2p_cmd
                .send(noid_p2p::NetworkCommand::CancelHistoryStepTerminalRace {
                    token: completed.key.terminal_request_token,
                })
                .await;
            if terminal_rejected {
                rejected_terminal_peers.insert(completed.key.terminal_from);
                manifest_terminal_capabilities.remove(&completed.key.terminal_from);
            }
            match completed.result {
                Ok(mut applied) => {
                    let (advanced, complete) = compact_apply_signals(
                        applied.applied_blocks,
                        applied.height,
                        completed.key.target_height,
                        applied.trailing_error.is_some(),
                    );
                    if advanced {
                        mining_peer_quorum
                            .set_canonical_tip(applied.height, applied.block_hash);
                        record_authenticated_height!(applied.height, completed.key.peer);
                        external_mining_attempts
                            .invalidate_for_tip(applied.height, applied.block_hash);
                        last_tip_advance = Instant::now();
                        let _ = template_changes.send(());
                    }
                    if complete {
                        request_exact_tip_confirmation!(completed.key.peer, applied.height);
                        mining_peer_quorum.confirm_tip(
                            completed.key.peer,
                            applied.height,
                            applied.block_hash,
                        );
                    }
                    tracing::info!(
                        peer = %completed.key.peer,
                        base = completed.key.base_height,
                        target = completed.key.target_height,
                        height = applied.height,
                        blocks = applied.applied_blocks,
                        bytes = applied.payload_bytes,
                        elapsed_ms = applied.apply_elapsed.as_millis(),
                        complete,
                        "compact recent suffix application completed"
                    );
                    if let Some(error) = applied.trailing_error.take() {
                        tracing::warn!(
                            peer = %completed.key.peer,
                            height = applied.height,
                            err = %error,
                            "compact suffix stopped after a valid committed prefix"
                        );
                    }
                    if complete {
                        mark_bootstrap_complete_if_caught_up!(applied.height);
                    }
                    let probe_peer = deferred_sync_peer
                        .take()
                        .filter(|peer| {
                            manifest_peers.contains(peer)
                                && !rejected_terminal_peers.contains(peer)
                        })
                        .or_else(|| {
                            (highest_announced > applied.height)
                                .then_some(last_announcement_peer)
                                .flatten()
                                .filter(|peer| {
                                    manifest_peers.contains(peer)
                                        && !rejected_terminal_peers.contains(peer)
                                })
                        });
                    if let Some(peer) = probe_peer {
                        let count = if highest_announced > applied.height {
                            (highest_announced - applied.height + 1)
                                .min(u64::from(CONNECTED_TIP_PROBE_HEADERS))
                                as u16
                        } else {
                            CONNECTED_TIP_PROBE_HEADERS
                        };
                        if fetch_in_progress.insert(peer) {
                            let _ = p2p_cmd
                                .send(noid_p2p::NetworkCommand::FetchHeaders {
                                    peer,
                                    start_height: applied.height,
                                    count,
                                })
                                .await;
                        }
                    }
                }
                Err(error) => {
                    tracing::warn!(
                        peer = %completed.key.peer,
                        base = completed.key.base_height,
                        target = completed.key.target_height,
                        err = %error,
                        "compact recent suffix apply rejected before mutation"
                    );
                    let our_height = {
                        let ctx = chain.read().await;
                        ctx.tip_height()
                    };
                    let peer = deferred_sync_peer
                        .take()
                        .filter(|peer| {
                            manifest_peers.contains(peer)
                                && !rejected_terminal_peers.contains(peer)
                        })
                        .or_else(|| {
                            manifest_peers
                                .iter()
                                .copied()
                                .filter(|peer| !rejected_terminal_peers.contains(peer))
                                .min_by_key(|peer| peer.to_bytes())
                        });
                    if let Some(peer) = peer.filter(|peer| fetch_in_progress.insert(*peer)) {
                        let _ = p2p_cmd
                            .send(noid_p2p::NetworkCommand::FetchHeaders {
                                peer,
                                start_height: our_height,
                                count: CONNECTED_TIP_PROBE_HEADERS,
                            })
                            .await;
                    }
                }
            }
        }

        completed = snapshot_tail_append_rx.recv() => {
            let Some(completed) = completed else {
                continue;
            };
            if snapshot_tail_append_inflight != Some(completed.key) {
                tracing::debug!(
                    key = ?completed.key,
                    "discarding superseded snapshot tail append"
                );
                drop(completed.result);
                continue;
            }
            snapshot_tail_append_inflight = None;
            if completed.key.generation != snapshot_sync_generation {
                drop(completed.result);
                tracing::debug!(
                    from = %completed.key.from,
                    from_height = completed.key.height,
                    to_height = completed.key.end_height(),
                    "discarding snapshot tail from a reset sync generation"
                );
                continue;
            }
            let from = completed.key.from;
            let staging = match completed.result {
                Ok(staging) => staging,
                Err(error) => {
                    tracing::warn!(
                        from = %from,
                        from_height = completed.key.height,
                        to_height = completed.key.end_height(),
                        err = %error,
                        "snapshot tail batch append failed"
                    );
                    preserve_active_snapshot_headers!();
                    reset_sync_state!();
                    request_bounded_manifest_failover!(from, false);
                    continue;
                }
            };
            let Some(pending) = pending_manifest.as_ref() else {
                drop(staging);
                tracing::warn!(from = %from, "snapshot tail lost its selected manifest");
                reset_sync_state!();
                request_bounded_manifest_failover!(from, true);
                continue;
            };
            if pending.from != from {
                drop(staging);
                tracing::warn!(from = %from, expected = %pending.from, "snapshot tail peer changed");
                preserve_active_snapshot_headers!();
                reset_sync_state!();
                request_bounded_manifest_failover!(from, false);
                continue;
            }
            let bridge_tip = pending.manifest.bridge_tip_height;
            if staging.tip_height() == bridge_tip
                && (staging.tip_hash() != pending.manifest.bridge_tip_hash
                    || staging.tip_chainwork()
                        != pending.manifest.bridge_cumulative_chainwork)
            {
                drop(staging);
                tracing::warn!(
                    from = %from,
                    bridge_tip,
                    "immutable snapshot bridge tip hash/work mismatch"
                );
                preserve_active_snapshot_headers!();
                reset_sync_state!();
                request_bounded_manifest_failover!(from, false);
                continue;
            }
            if staging.tip_height() != bridge_tip {
                drop(staging);
                tracing::warn!(
                    from = %from,
                    from_height = completed.key.height,
                    to_height = completed.key.end_height(),
                    bridge_tip,
                    "snapshot body batch did not end at the immutable bridge"
                );
                preserve_active_snapshot_headers!();
                reset_sync_state!();
                request_bounded_manifest_failover!(from, false);
                continue;
            }
            snapshot_tail_staging = Some(staging);
            tracing::info!(
                from = %from,
                bridge_tip,
                blocks = snapshot_tail_staging.as_ref().map_or(0, SnapshotTailStaging::block_count),
                "immutable snapshot bridge sealed on disk"
            );
            try_start_ready_snapshot_install!();
        }

        completed = snapshot_staging_completion_rx.recv() => {
            let Some(completed) = completed else {
                continue;
            };
            let key = match &completed {
                SnapshotStagingCompletion::Accepted { key, .. }
                | SnapshotStagingCompletion::Finalized { key, .. } => *key,
            };
            if snapshot_staging_inflight != Some(key) {
                tracing::debug!(?key, "discarding superseded snapshot staging completion");
                match completed {
                    SnapshotStagingCompletion::Accepted {
                        result: Ok(staging),
                        ..
                    } => cleanup_snapshot_staging_session_offthread(staging),
                    SnapshotStagingCompletion::Finalized {
                        result: Ok(finalized),
                        ..
                    } => cleanup_finalized_snapshot_staging_offthread(finalized),
                    _ => {}
                }
                continue;
            }
            snapshot_staging_inflight = None;

            match completed {
                SnapshotStagingCompletion::Accepted {
                    key,
                    payload_bytes,
                    work_elapsed,
                    result,
                } => {
                    let SnapshotStagingOperationKey::Accept {
                        generation,
                        from,
                        segment_id,
                    } = key
                    else {
                        unreachable!("accepted completion always has an accept key");
                    };
                    if generation != snapshot_sync_generation {
                        if let Ok(staging) = result {
                            cleanup_snapshot_staging_session_offthread(staging);
                        }
                        tracing::debug!(
                            from = %from,
                            segment = segment_id,
                            "discarding snapshot segment staged for a reset sync generation"
                        );
                        continue;
                    }
                    let staging = match result {
                        Ok(staging) => staging,
                        Err(error) => {
                            tracing::warn!(
                                from = %from,
                                segment = segment_id,
                                err = %error,
                                "snapshot segment authentication/staging failed"
                            );
                            preserve_active_snapshot_headers!();
                            reset_sync_state!();
                            request_bounded_manifest_failover!(from, false);
                            continue;
                        }
                    };
                    sync_phase_telemetry.record_state_segment(payload_bytes, work_elapsed);
                    if !pending_manifest.as_ref().is_some_and(|pending| pending.from == from) {
                        tracing::warn!(
                            from = %from,
                            segment = segment_id,
                            "snapshot staging completion lost its selected manifest"
                        );
                        cleanup_snapshot_staging_session_offthread(staging);
                        reset_sync_state!();
                        request_bounded_manifest_failover!(from, true);
                        continue;
                    }
                    snapshot_staging = Some(staging);

                    if let Some((queued_from, response)) = queued_segment_response.take() {
                        if queued_from != from {
                            drop(response);
                            tracing::warn!(
                                from = %queued_from,
                                expected = %from,
                                "buffered snapshot segment changed peer"
                            );
                            preserve_active_snapshot_headers!();
                            reset_sync_state!();
                            request_bounded_manifest_failover!(queued_from, false);
                            continue;
                        }
                        stage_snapshot_segment_response!(queued_from, response);
                    }

                    if let Some(pending) = pending_manifest.as_ref() {
                        dispatch_queued_snapshot_segments(
                            &p2p_cmd,
                            pending.from,
                            pending.manifest.tip_height,
                            pending.manifest.tip_hash,
                            snapshot_staging_inflight.is_some(),
                            queued_segment_response.is_some(),
                            &mut pending_segment_ids,
                            &mut segment_queue,
                        )
                        .await;
                    }
                    tracing::debug!(
                        from = %from,
                        segment = segment_id,
                        remaining = pending_segment_ids.len() + segment_queue.len(),
                        "snapshot segment authenticated and sealed to disk"
                    );

                    // Once every response is durably staged, independently
                    // reconstruct the exact root in the same one-operation
                    // blocking lane.  `pending_manifest` continues to own the
                    // authenticated HistoryStep boundary and inbound permit during this pass.
                    if snapshot_staging_inflight.is_none()
                        && queued_segment_response.is_none()
                        && pending_segment_ids.is_empty()
                        && segment_queue.is_empty()
                    {
                        let staging = snapshot_staging
                            .take()
                            .expect("accepted snapshot session is available for finalization");
                        let segment_count = staging.descriptors().len();
                        let key = SnapshotStagingOperationKey::Finalize {
                            generation: snapshot_sync_generation,
                            from,
                        };
                        snapshot_staging_inflight = Some(key);
                        let completion = snapshot_staging_completion_tx.clone();
                        tokio::task::spawn_blocking(move || {
                            let started = Instant::now();
                            let result = std::panic::catch_unwind(
                                std::panic::AssertUnwindSafe(move || {
                                    staging.finalize().map_err(|error| error.to_string())
                                }),
                            )
                            .map_err(|_| "snapshot finalization worker panicked".to_owned())
                            .and_then(|result| result);
                            let _ = completion.blocking_send(
                                SnapshotStagingCompletion::Finalized {
                                    key,
                                    segment_count,
                                    work_elapsed: started.elapsed(),
                                    result,
                                },
                            );
                        });
                    }
                }
                SnapshotStagingCompletion::Finalized {
                    key,
                    segment_count,
                    work_elapsed,
                    result,
                } => {
                    let SnapshotStagingOperationKey::Finalize { generation, from } = key else {
                        unreachable!("finalized completion always has a finalize key");
                    };
                    if generation != snapshot_sync_generation {
                        if let Ok(finalized) = result {
                            cleanup_finalized_snapshot_staging_offthread(finalized);
                        }
                        tracing::debug!(
                            from = %from,
                            "discarding snapshot finalization for a reset sync generation"
                        );
                        continue;
                    }
                    let finalized = match result {
                        Ok(finalized) => finalized,
                        Err(error) => {
                            tracing::warn!(
                                from = %from,
                                err = %error,
                                "snapshot exact-state finalization failed"
                            );
                            preserve_active_snapshot_headers!();
                            reset_sync_state!();
                            request_bounded_manifest_failover!(from, false);
                            continue;
                        }
                    };
                    sync_phase_telemetry.record_state_work(work_elapsed);
                    let Some(pending) = pending_manifest.as_ref() else {
                        tracing::warn!(from = %from, "snapshot finalized without selected manifest");
                        cleanup_finalized_snapshot_staging_offthread(finalized);
                        reset_sync_state!();
                        request_bounded_manifest_failover!(from, true);
                        continue;
                    };
                    if pending.from != from {
                        tracing::warn!(from = %from, expected = %pending.from, "snapshot finalization peer changed");
                        cleanup_finalized_snapshot_staging_offthread(finalized);
                        preserve_active_snapshot_headers!();
                        reset_sync_state!();
                        request_bounded_manifest_failover!(from, false);
                        continue;
                    }
                    let target = pending.manifest.bridge_tip_height;
                    snapshot_tail_install_target = Some(target);
                    finalized_snapshot_waiting = Some((finalized, segment_count, from));
                    let boundary = pending.manifest.tip_height;
                    if target > boundary {
                        let height = boundary.saturating_add(1);
                        let count = u16::try_from(target.saturating_sub(boundary))
                            .expect("manifest codec bounds the immutable bridge span");
                        request_snapshot_tail_blocks!(from, height, count);
                        tracing::info!(
                            from = %from,
                            target,
                            "snapshot state finalized — fetching immutable bridge"
                        );
                    } else {
                        tracing::info!(
                            from = %from,
                            target,
                            "snapshot state finalized at the bridge tip"
                        );
                    }
                    try_start_ready_snapshot_install!();
                }
            }
        }

        completed = snapshot_install_completion_rx.recv() => {
            let Some(completed) = completed else {
                continue;
            };
            if snapshot_install_inflight != Some(completed.key) {
                tracing::debug!(?completed.key, "discarding superseded snapshot install completion");
                continue;
            }
            snapshot_install_inflight = None;
            if let Some(token) = completed.key.terminal_request_token {
                let _ = p2p_cmd
                    .send(noid_p2p::NetworkCommand::CancelHistoryStepTerminalRace { token })
                    .await;
            }
            match completed.result {
                Ok(applied) => {
                    snapshot_rebase_hint = None;
                    sync_phase_telemetry.record_state_work(applied.state_install_elapsed);
                    log_sync_phase_measurement(sync_phase_telemetry.finish_headers());
                    log_sync_phase_measurement(sync_phase_telemetry.finish_state());
                    log_sync_phase_measurement(sync_phase_telemetry.complete_staged_tail(
                        applied.tail_blocks,
                        applied.tail_bytes,
                        applied.tail_apply_elapsed,
                    ));

                    let height = applied.height;
                    mining_peer_quorum.set_canonical_tip(height, applied.block_hash);
                    record_authenticated_height!(height, completed.key.from);
                    tracing::info!(
                        height,
                        tail_blocks = applied.tail_blocks,
                        from = %completed.key.from,
                        "snapshot install completed"
                    );
                    reset_sync_state!();
                    if highest_announced > height {
                        let _ = sync_phase_telemetry.begin_suffix(height, highest_announced);
                    }
                    last_tip_advance = Instant::now();
                    mining_peer_quorum.confirm_tip(
                        completed.key.from,
                        height,
                        applied.block_hash,
                    );
                    let _ = template_changes.send(());
                    let followup_peer = deferred_sync_peer
                        .take()
                        .filter(|peer| manifest_peers.contains(peer))
                        .or_else(|| {
                            (highest_announced > height)
                                .then_some(last_announcement_peer)
                                .flatten()
                                .filter(|peer| manifest_peers.contains(peer))
                        });
                    if let Some(peer) = followup_peer {
                        let count = if highest_announced > height {
                            (highest_announced - height + 1)
                                .min(u64::from(CONNECTED_TIP_PROBE_HEADERS))
                                as u16
                        } else {
                            CONNECTED_TIP_PROBE_HEADERS
                        };
                        if fetch_in_progress.insert(peer) {
                            recent_header_fetches.insert((peer, height, count), Instant::now());
                            let _ = p2p_cmd
                                .send(noid_p2p::NetworkCommand::FetchHeaders {
                                    peer,
                                    start_height: height,
                                    count,
                                })
                                .await;
                        }
                        tracing::debug!(
                            peer = %peer,
                            from_height = height,
                            highest_announced,
                            "probing concurrent fork choice immediately after snapshot install"
                        );
                    } else {
                        request_exact_tip_confirmation!(completed.key.from, height);
                    }
                }
                Err(SnapshotInstallError::BeforeCommit(error)) => {
                    tracing::error!(
                        from = %completed.key.from,
                        tip = completed.key.height,
                        err = %error,
                        "failed to apply verified state snapshot"
                    );
                    preserve_active_snapshot_headers!();
                    reset_sync_state!();
                    request_bounded_manifest_failover!(completed.key.from, false);
                }
                Err(SnapshotInstallError::AfterCommit {
                    applied,
                    error,
                    terminal_rejected,
                }) => {
                    snapshot_rebase_hint = None;
                    if terminal_rejected {
                        if let Some(terminal_from) = completed.key.terminal_from {
                            rejected_terminal_peers.insert(terminal_from);
                            manifest_terminal_capabilities.remove(&terminal_from);
                        }
                    }
                    sync_phase_telemetry.record_state_work(applied.state_install_elapsed);
                    log_sync_phase_measurement(sync_phase_telemetry.finish_headers());
                    log_sync_phase_measurement(sync_phase_telemetry.finish_state());
                    log_sync_phase_measurement(sync_phase_telemetry.complete_staged_tail(
                        applied.tail_blocks,
                        applied.tail_bytes,
                        applied.tail_apply_elapsed,
                    ));
                    let height = applied.height;
                    mining_peer_quorum.set_canonical_tip(height, applied.block_hash);
                    record_authenticated_height!(height, completed.key.from);
                    tracing::warn!(
                        from = %completed.key.from,
                        height,
                        block_hash = %hex::encode(applied.block_hash),
                        tail_blocks = applied.tail_blocks,
                        err = %error,
                        "snapshot committed a valid prefix; continuing sync from the durable tip"
                    );
                    reset_sync_state!();
                    last_tip_advance = Instant::now();
                    let _ = template_changes.send(());
                    let recovery_peer = deferred_sync_peer
                        .take()
                        .filter(|peer| {
                            manifest_peers.contains(peer)
                                && !rejected_terminal_peers.contains(peer)
                        })
                        .or_else(|| {
                            manifest_peers
                                .iter()
                                .copied()
                                .filter(|peer| *peer != completed.key.from)
                                .filter(|peer| !rejected_terminal_peers.contains(peer))
                                .min_by_key(|peer| peer.to_bytes())
                        })
                        .or_else(|| {
                            (manifest_peers.contains(&completed.key.from)
                                && !rejected_terminal_peers.contains(&completed.key.from))
                                .then_some(completed.key.from)
                        });
                    if let Some(peer) = recovery_peer {
                        let count = CONNECTED_TIP_PROBE_HEADERS;
                        if fetch_in_progress.insert(peer) {
                            recent_header_fetches.insert((peer, height, count), Instant::now());
                            let _ = p2p_cmd
                                .send(noid_p2p::NetworkCommand::FetchHeaders {
                                    peer,
                                    start_height: height,
                                    count,
                                })
                                .await;
                        }
                    }
                }
            }
        }

        completed = history_step_verification_rx.recv() => {
            let Some(completed) = completed else {
                continue;
            };
            let terminal_rejected = matches!(
                &completed.result,
                Err(SnapshotBoundaryVerificationError::Terminal(_))
            );
            let _ = p2p_cmd
                .send(noid_p2p::NetworkCommand::CancelHistoryStepTerminalRace {
                    token: completed.key.terminal_request_token,
                })
                .await;
            if terminal_rejected {
                rejected_terminal_peers.insert(completed.key.terminal_from);
                manifest_terminal_capabilities.remove(&completed.key.terminal_from);
            }
            if history_step_verification_inflight != Some(completed.key) {
                if let Ok(verified) = completed.result {
                    // Supersession is not proof invalidity. Close the handles
                    // but leave the validated header file for exact failover.
                    drop(verified);
                }
                tracing::debug!(
                    from = %completed.key.from,
                    tip = completed.key.height,
                    "discarding superseded HistoryStep verification"
                );
                continue;
            }
            history_step_verification_inflight = None;
            if completed.generation != snapshot_sync_generation {
                if let Ok(verified) = completed.result {
                    // The new generation may reopen this exact native-validated
                    // prefix; do not turn transport churn into an O(height) retry.
                    drop(verified);
                }
                tracing::debug!(
                    from = %completed.key.from,
                    tip = completed.key.height,
                    "discarding HistoryStep verification from a reset sync generation"
                );
                continue;
            }

            sync_phase_telemetry.record_header_work(completed.header_validation_elapsed);
            sync_phase_telemetry.observe_header_scale(
                completed.staged_header_count,
                completed
                    .staged_header_count
                    .saturating_mul(noid_chain::BLOCK_HEADER_WIRE_SIZE as u64),
            );
            if let Some(measurement) = completed.terminal_measurement {
                log_sync_phase_measurement(measurement);
            }

            let from = completed.key.from;
            let verified_history_step = match completed.result {
                Ok(verified) => verified,
                Err(error) => {
                    let failed_peer = if terminal_rejected {
                        completed.key.terminal_from
                    } else {
                        completed.key.from
                    };
                    tracing::error!(
                        manifest_from = %from,
                        terminal_from = %completed.key.terminal_from,
                        tip = completed.key.height,
                        err = %error,
                        "snapshot rejected: HistoryStep terminal verification failed"
                    );
                    reset_sync_state!();
                    request_bounded_manifest_failover!(failed_peer, false);
                    continue;
                }
            };

            if !manifest_peers.contains(&from) {
                let boundary_height = verified_history_step.height;
                drop(verified_history_step);
                tracing::warn!(
                    peer = %from,
                    boundary_height,
                    "snapshot owner disconnected during authority verification; retaining headers for failover"
                );
                reset_sync_state!();
                request_bounded_manifest_failover!(from, false);
                continue;
            }

            tracing::info!(
                from = %from,
                tip = completed.manifest.tip_height,
                bridge_tip = completed.manifest.bridge_tip_height,
                segments = completed.manifest.segment_ids.len(),
                "snapshot authority accepted — starting exact state staging"
            );
            let boundary_header = *verified_history_step.boundary.header();
            let Some(selected) = pending_manifest.as_mut() else {
                tracing::warn!(
                    peer = %from,
                    "verified snapshot authority lost its selected manifest"
                );
                drop_verified_history_step(verified_history_step);
                reset_sync_state!();
                continue;
            };
            if selected.from != from
                || selected.manifest.tip_height != completed.manifest.tip_height
                || selected.manifest.tip_hash != completed.manifest.tip_hash
                || selected.manifest.bridge_tip_height != completed.manifest.bridge_tip_height
                || selected.manifest.bridge_tip_hash != completed.manifest.bridge_tip_hash
            {
                tracing::warn!(
                    peer = %from,
                    "verified snapshot authority differs from the selected generation"
                );
                drop_verified_history_step(verified_history_step);
                reset_sync_state!();
                continue;
            }
            // The terminal allocation and inbound permit remain owned by the
            // selected manifest until atomic snapshot installation.
            record_authenticated_height!(completed.manifest.tip_height, from);
            selected.history_step = Some(verified_history_step);
            let manifest = pending_manifest
                .as_ref()
                .expect("selected snapshot manifest is installed")
                .manifest
                .clone();
            let bridge_tip = manifest.bridge_tip_height;
            let staging = begin_snapshot_state_download(
                &p2p_cmd,
                &snapshot_staging_root,
                from,
                &manifest,
                boundary_header,
                &mut pending_segment_ids,
                &mut segment_queue,
            )
            .await;
            let staging = match staging {
                Ok(staging) => staging,
                Err(error) => {
                    tracing::warn!(
                        peer = %from,
                        err = %error,
                        "snapshot state staging initialization failed"
                    );
                    reset_sync_state!();
                    continue;
                }
            };
            snapshot_staging = Some(staging);

            if bridge_tip == manifest.tip_height {
                tracing::info!(
                    peer = %from,
                    bridge_tip,
                    "snapshot boundary is current — no immutable bridge replay required"
                );
            }

            if pending_segment_ids.is_empty() && segment_queue.is_empty() {
                let staging = snapshot_staging
                    .take()
                    .expect("snapshot staging exists before empty finalization");
                let segment_count = staging.descriptors().len();
                let key = SnapshotStagingOperationKey::Finalize {
                    generation: snapshot_sync_generation,
                    from,
                };
                snapshot_staging_inflight = Some(key);
                let completion = snapshot_staging_completion_tx.clone();
                tokio::task::spawn_blocking(move || {
                    let started = Instant::now();
                    let result =
                        std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                            staging.finalize().map_err(|error| error.to_string())
                        }))
                        .map_err(|_| "snapshot finalization worker panicked".to_owned())
                        .and_then(|result| result);
                    let _ = completion.blocking_send(SnapshotStagingCompletion::Finalized {
                        key,
                        segment_count,
                        work_elapsed: started.elapsed(),
                        result,
                    });
                });
            }
        }

        // Heartbeat: re-evaluate manifest timeout without waiting for a new P2P event.
        _ = heartbeat.tick() => {
            let now = Instant::now();
            let (our_height, our_hash) = {
                let ctx = chain.read().await;
                (ctx.tip_height(), ctx.tip_hash())
            };
            // This also catches locally mined or RPC-submitted blocks, whose
            // commits do not pass through this P2P event handler. Old-tip
            // confirmations are cleared within one heartbeat and cannot be
            // refreshed by a delayed response for the previous parent.
            mining_peer_quorum.set_canonical_tip(our_height, our_hash);
            mining_peer_quorum.expire_stale(now);
            let fetch_cutoff = now - FETCH_DEDUP_TTL;
            recent_header_fetches.retain(|_, t| *t >= fetch_cutoff);
            recent_block_fetches.retain(|_, t| *t >= fetch_cutoff);
            pending_block_fetches
                .retain(|_, pending| now.duration_since(pending.requested_at) < BLOCK_FETCH_INFLIGHT_TTL);

            if manifest_candidate_selection_due(manifest_candidate_started_at, now)
                && pending_manifest.is_none()
                && pending_snapshot_header_sync.is_none()
                && snapshot_header_staging_inflight.is_none()
                && history_step_verification_inflight.is_none()
                && snapshot_staging_inflight.is_none()
                && snapshot_install_inflight.is_none()
                && pending_recent_suffix.is_none()
                && recent_suffix_apply_inflight.is_none()
            {
                let candidate = best_manifest_candidate
                    .take()
                    .expect("settled manifest election has a candidate");
                manifest_candidate_started_at = None;
                let responses_considered = manifest_response_count;
                manifest_requested_peers.clear();
                manifest_force_snapshot_peers.clear();
                manifest_response_count = 0;
                manifest_round_started_at = None;
                if candidate.manifest.tip_height > our_height {
                    tracing::info!(
                        from = %candidate.from,
                        tip = candidate.manifest.tip_height,
                        bridge_tip = candidate.manifest.bridge_tip_height,
                        responses_considered,
                        "snapshot manifest election settled — validating strongest advertised chain"
                    );
                    begin_snapshot_header_staging!(candidate.from, candidate.manifest);
                } else {
                    tracing::debug!(
                        from = %candidate.from,
                        tip = candidate.manifest.tip_height,
                        our_height,
                        "snapshot manifest candidate became obsolete before election settled"
                    );
                }
            }

            if snapshot_rebase_hint.is_some_and(|hint| {
                now.duration_since(hint.armed_at) >= Duration::from_secs(600)
            }) && selected_snapshot_peer!().is_none()
                && snapshot_install_inflight.is_none()
            {
                let expired = snapshot_rebase_hint
                    .take()
                    .expect("expired snapshot rebase hint exists");
                tracing::warn!(
                    ancestor = expired.ancestor_height,
                    competing_tip = expired.competing_tip_height,
                    "snapshot rebase hint expired without an active authenticated candidate"
                );
            }

            if *initial_sync_ready.borrow() {
                let mempool_peers = manifest_peers
                    .iter()
                    .copied()
                    .filter(|peer| !mempool_sync_requested_peers.contains(peer))
                    .collect::<Vec<_>>();
                for peer in mempool_peers {
                    mempool_sync_requested_peers.insert(peer);
                    let _ = p2p_cmd
                        .send(noid_p2p::NetworkCommand::RequestMempoolSync { peer })
                        .await;
                }
            }

            // Mining-authority refresh must not compete with canonical sync
            // for the bounded general-header request lanes. Connection-time
            // probes still bootstrap discovery; once a snapshot, suffix, or
            // reorg session is active, the readiness gate can safely remain
            // closed until that exact canonical transition has completed.
            let canonical_sync_idle = pending_shallow_fork.is_none()
                && pending_block_fetches.is_empty()
                && pending_recent_suffix.is_none()
                && recent_suffix_apply_inflight.is_none()
                && pending_manifest.is_none()
                && pending_snapshot_header_sync.is_none()
                && snapshot_header_pipeline.is_none()
                && snapshot_header_staging_inflight.is_none()
                && history_step_verification_inflight.is_none()
                && snapshot_boundary_terminal_inflight.is_none()
                && snapshot_tail_terminal_inflight.is_none()
                && snapshot_staging.is_none()
                && snapshot_staging_inflight.is_none()
                && snapshot_tail_request_inflight.is_none()
                && snapshot_tail_append_inflight.is_none()
                && snapshot_install_inflight.is_none()
                && pending_segment_ids.is_empty()
                && segment_queue.is_empty()
                && manifest_requested_peers.is_empty();

            // Reacquire a lost quorum through at most two lanes, preferring
            // peers which have not confirmed the exact current tip. Once the
            // quorum is complete, the single rotating steady lane below keeps
            // confirmations fresh without redundant two-lane traffic.
            const MINING_QUORUM_TIP_PROBE_HEADERS: u16 = CONNECTED_TIP_PROBE_HEADERS;
            let waiting_for_quorum = mining_peer_quorum.waiting_for_quorum();
            if mining_quorum_probe_due(
                last_mining_quorum_probe,
                now,
                waiting_for_quorum,
                canonical_sync_idle,
            ) {
                let mut lane_capacity = MINING_PEER_QUORUM
                    .saturating_sub(fetch_in_progress.len().min(MINING_PEER_QUORUM));
                let mut dispatched = false;
                for peer in mining_peer_quorum.probe_candidates(usize::MAX) {
                    if lane_capacity == 0 {
                        break;
                    }
                    let request_key = (peer, our_height, MINING_QUORUM_TIP_PROBE_HEADERS);
                    let recently_requested = recent_header_fetches
                        .get(&request_key)
                        .is_some_and(|requested| requested.elapsed() < FETCH_DEDUP_TTL);
                    if fetch_in_progress.contains(&peer) || recently_requested {
                        continue;
                    }
                    fetch_in_progress.insert(peer);
                    recent_header_fetches.insert(request_key, now);
                    if p2p_cmd
                        .send(noid_p2p::NetworkCommand::FetchHeaders {
                            peer,
                            start_height: our_height,
                            count: MINING_QUORUM_TIP_PROBE_HEADERS,
                        })
                        .await
                        .is_ok()
                    {
                        mining_peer_quorum.mark_probe_sent(peer, now);
                        lane_capacity -= 1;
                        dispatched = true;
                    } else {
                        fetch_in_progress.remove(&peer);
                        recent_header_fetches.remove(&request_key);
                    }
                }
                if dispatched {
                    last_mining_quorum_probe = now;
                }
            }

            if !waiting_for_quorum {
                if steady_tip_probe_due(
                    last_steady_tip_probe,
                    now,
                    false,
                    canonical_sync_idle,
                ) {
                    let excluded = std::collections::HashSet::new();
                    let candidates = rotating_manifest_peers(
                        &manifest_peers,
                        &excluded,
                        None,
                        false,
                        &mut steady_tip_probe_cursor,
                        1,
                    );
                    for peer in candidates {
                        let request_key = (peer, our_height, CONNECTED_TIP_PROBE_HEADERS);
                        let recently_requested = recent_header_fetches
                            .get(&request_key)
                            .is_some_and(|requested| requested.elapsed() < FETCH_DEDUP_TTL);
                        if fetch_in_progress.contains(&peer) || recently_requested {
                            continue;
                        }
                        fetch_in_progress.insert(peer);
                        recent_header_fetches.insert(request_key, now);
                        if p2p_cmd
                            .send(noid_p2p::NetworkCommand::FetchHeaders {
                                peer,
                                start_height: our_height,
                                count: CONNECTED_TIP_PROBE_HEADERS,
                            })
                            .await
                            .is_ok()
                        {
                            last_steady_tip_probe = now;
                            tracing::debug!(
                                peer = %peer,
                                our_height,
                                "steady authenticated tip probe dispatched"
                            );
                        } else {
                            fetch_in_progress.remove(&peer);
                            recent_header_fetches.remove(&request_key);
                        }
                        break;
                    }
                }
            }

            if pending_shallow_fork
                .as_ref()
                .is_some_and(|pending| {
                    shallow_fork_progress_deadline_due(pending.last_progress_at, now)
                })
            {
                let stale = pending_shallow_fork
                    .take()
                    .expect("timed-out shallow-fork session exists");
                let peer = stale.peer;
                tracing::warn!(
                    peer = %peer,
                    "shallow-fork bundle download made no progress before its deadline — discarding bounded session"
                );
                retry_shallow_fork_headers!(stale, "bundle download progress deadline expired");
            }

            if snapshot_boundary_terminal_inflight
                .as_ref()
                .is_some_and(|pending| pending.requests.deadline_due(now))
            {
                let pending = snapshot_boundary_terminal_inflight
                    .take()
                    .expect("expired boundary terminal race is present");
                let _ = p2p_cmd
                    .send(noid_p2p::NetworkCommand::CancelHistoryStepTerminalRace {
                        token: pending.requests.primary.token,
                    })
                    .await;
                tracing::warn!(
                    manifest_from = %pending.manifest_from,
                    height = pending.height,
                    "snapshot boundary terminal race exceeded its complete local deadline"
                );
                preserve_active_snapshot_headers!();
                reset_sync_state!();
                request_bounded_manifest_failover!(pending.manifest_from, true);
                continue;
            }

            if snapshot_tail_terminal_inflight
                .as_ref()
                .is_some_and(|pending| pending.requests.deadline_due(now))
            {
                let pending = snapshot_tail_terminal_inflight
                    .take()
                    .expect("expired bridge terminal race is present");
                let _ = p2p_cmd
                    .send(noid_p2p::NetworkCommand::CancelHistoryStepTerminalRace {
                        token: pending.requests.primary.token,
                    })
                    .await;
                tracing::warn!(
                    manifest_from = %pending.manifest_from,
                    height = pending.height,
                    "snapshot bridge terminal race exceeded its complete local deadline"
                );
                preserve_active_snapshot_headers!();
                reset_sync_state!();
                request_bounded_manifest_failover!(pending.manifest_from, true);
                continue;
            }

            if pending_recent_suffix.as_ref().is_some_and(|pending| {
                pending.terminal_requests.deadline_due(now)
            }) {
                fallback_recent_suffix_to_full_bundles!(
                    "compact suffix terminal race exceeded its complete local deadline"
                );
                continue;
            }

            // request-response starts its 60-second timeout only after an
            // outbound substream opens. A request waiting inside libp2p's
            // stream-capacity queue therefore needs this node-level hedge.
            // The alternate must advertise the exact immutable terminal, and
            // the first valid response closes the logical race.
            let boundary_terminal_hedge = snapshot_boundary_terminal_inflight
                .as_ref()
                .filter(|pending| pending.requests.hedge_due(now))
                .and_then(|pending| {
                    advertised_terminal_alternate_peer(
                        &manifest_peers,
                        &manifest_terminal_capabilities,
                        &rejected_terminal_peers,
                        &pending.requests,
                        pending.height,
                        pending.block_hash,
                    )
                    .map(|alternate| {
                        (
                            pending.requests.primary.peer,
                            alternate,
                            pending.requests.primary.token,
                            pending.height,
                            pending.block_hash,
                        )
                    })
                });
            if let Some((primary, alternate, token, height, block_hash)) =
                boundary_terminal_hedge
            {
                snapshot_boundary_terminal_inflight
                    .as_mut()
                    .expect("planned boundary terminal hedge is still active")
                    .requests
                    .install_hedge(alternate);
                if p2p_cmd
                    .send(noid_p2p::NetworkCommand::RequestHistoryStepTerminal {
                        token,
                        peer: alternate,
                        height,
                        block_hash,
                    })
                    .await
                    .is_ok()
                {
                    tracing::warn!(
                        primary = %primary,
                        alternate = %alternate,
                        height,
                        "snapshot boundary terminal primary stalled; hedging exact request"
                    );
                }
            }

            let bridge_terminal_hedge = snapshot_tail_terminal_inflight
                .as_ref()
                .filter(|pending| pending.requests.hedge_due(now))
                .and_then(|pending| {
                    advertised_terminal_alternate_peer(
                        &manifest_peers,
                        &manifest_terminal_capabilities,
                        &rejected_terminal_peers,
                        &pending.requests,
                        pending.height,
                        pending.block_hash,
                    )
                    .map(|alternate| {
                        (
                            pending.requests.primary.peer,
                            alternate,
                            pending.requests.primary.token,
                            pending.height,
                            pending.block_hash,
                        )
                    })
                });
            if let Some((primary, alternate, token, height, block_hash)) = bridge_terminal_hedge {
                snapshot_tail_terminal_inflight
                    .as_mut()
                    .expect("planned bridge terminal hedge is still active")
                    .requests
                    .install_hedge(alternate);
                if p2p_cmd
                    .send(noid_p2p::NetworkCommand::RequestHistoryStepTerminal {
                        token,
                        peer: alternate,
                        height,
                        block_hash,
                    })
                    .await
                    .is_ok()
                {
                    tracing::warn!(
                        primary = %primary,
                        alternate = %alternate,
                        height,
                        "snapshot bridge terminal primary stalled; hedging exact request"
                    );
                }
            }

            let recent_terminal_hedge = pending_recent_suffix
                .as_ref()
                .filter(|pending| pending.terminal_requests.hedge_due(now))
                .and_then(|pending| {
                    terminal_alternate_peer(
                        &manifest_peers,
                        &rejected_terminal_peers,
                        &pending.terminal_requests,
                    ).map(
                        |alternate| {
                            (
                                pending.terminal_requests.primary.peer,
                                alternate,
                                pending.terminal_requests.primary.token,
                                pending.target_height,
                                pending.target_hash,
                            )
                        },
                    )
                });
            if let Some((primary, alternate, token, height, block_hash)) = recent_terminal_hedge {
                pending_recent_suffix
                    .as_mut()
                    .expect("planned recent terminal hedge is still active")
                    .terminal_requests
                    .install_hedge(alternate);
                if p2p_cmd
                    .send(noid_p2p::NetworkCommand::RequestHistoryStepTerminal {
                        token,
                        peer: alternate,
                        height,
                        block_hash,
                    })
                    .await
                    .is_ok()
                {
                    tracing::warn!(
                        primary = %primary,
                        alternate = %alternate,
                        height,
                        "recent suffix terminal primary stalled; hedging exact request"
                    );
                }
            }

            // Some manifest request sites are event-driven and may begin a
            // round without explicitly arming its timer. Arm it here so every
            // outstanding round has the same bounded recovery path.
            if manifest_round_started_at.is_none()
                && !manifest_requested_peers.is_empty()
                && best_manifest_candidate.is_none()
                && pending_manifest.is_none()
                && pending_snapshot_header_sync.is_none()
                && snapshot_header_staging_inflight.is_none()
                && history_step_verification_inflight.is_none()
                && snapshot_staging_inflight.is_none()
                && snapshot_install_inflight.is_none()
                && pending_recent_suffix.is_none()
                && recent_suffix_apply_inflight.is_none()
                && pending_segment_ids.is_empty()
                && segment_queue.is_empty()
            {
                manifest_round_started_at = Some(now);
            }

            // A manifest round with no usable candidate is dead air. This
            // includes dropped responses and explicit empty responses. Reset and re-request from
            // a bounded peer set; with a single seed there is no second
            // PeerConnected event to save us.
            if manifest_round_retry_due(manifest_round_started_at, now)
                && best_manifest_candidate.is_none()
                && pending_manifest.is_none()
                && pending_snapshot_header_sync.is_none()
                && snapshot_header_staging_inflight.is_none()
                && history_step_verification_inflight.is_none()
                && snapshot_staging.is_none()
                && snapshot_staging_inflight.is_none()
                && snapshot_install_inflight.is_none()
                && pending_recent_suffix.is_none()
                && recent_suffix_apply_inflight.is_none()
                && pending_segment_ids.is_empty()
                && segment_queue.is_empty()
            {
                let our_height = {
                    let ctx = chain.read().await;
                    ctx.tip_height()
                };
                if manifest_round_gap_is_resolved(our_height, highest_announced) {
                    if *initial_sync_ready.borrow() {
                        clear_manifest_round_state!();
                        mark_bootstrap_complete_if_caught_up!(our_height);
                        tracing::debug!(
                            our_height,
                            highest_announced,
                            "announced gap closed; cancelled manifest retry"
                        );
                    } else {
                        clear_manifest_round_state!();
                        for peer in manifest_peers.iter().copied().collect::<Vec<_>>() {
                            request_exact_tip_confirmation!(peer, our_height);
                        }
                        let _ = manifest_round_started_at.get_or_insert(now);
                        tracing::debug!(
                            our_height,
                            "manifest round settled before tip authority; repeated authenticated tip probe"
                        );
                    }
                } else {
                    tracing::warn!(
                        peers = manifest_peers.len(),
                        responses = manifest_response_count,
                        "state manifest round produced no usable candidate — re-requesting"
                    );
                    reset_sync_state!();
                    let excluded_peers = rejected_terminal_peers
                        .union(&finalized_divergent_peers)
                        .copied()
                        .collect::<std::collections::HashSet<_>>();
                    let retry_peers = rotating_manifest_peers(
                        &manifest_peers,
                        &excluded_peers,
                        None,
                        false,
                        &mut manifest_retry_cursor,
                        3,
                    );
                    for peer in retry_peers {
                        manifest_requested_peers.insert(peer);
                        p2p_cmd
                            .send(noid_p2p::NetworkCommand::RequestStateManifest {
                                generation: snapshot_sync_generation,
                                peer,
                                requester_height: our_height,
                            })
                            .await
                            .ok();
                    }
                    if !manifest_peers.is_empty() {
                        manifest_round_started_at = Some(now);
                    }
                }
            }

            // --- Stale-tip recovery ---
            // If our chain hasn't advanced in 30s but we've seen higher announcements,
            // re-request the missing blocks from the peer that announced highest.
            // This handles the case where all initial block requests failed (peer
            // didn't have the block yet, stream capacity hit, etc.) in large networks.
            let stale_secs = last_tip_advance.elapsed().as_secs();
            if stale_secs >= 30
                && pending_recent_suffix.is_none()
                && recent_suffix_apply_inflight.is_none()
            {
                let our_height = {
                    let ctx = chain.read().await;
                    ctx.tip_height()
                };
                if highest_announced > our_height {
                    if let Some(peer) = last_announcement_peer {
                        let gap = highest_announced - our_height;
                        if gap_requires_snapshot_sync(our_height, highest_announced) {
                            if pending_manifest.is_none()
                                && pending_snapshot_header_sync.is_none()
                                && snapshot_header_staging_inflight.is_none()
                                && history_step_verification_inflight.is_none()
                                && snapshot_staging_inflight.is_none()
                                && snapshot_install_inflight.is_none()
                                && pending_segment_ids.is_empty()
                                && segment_queue.is_empty()
                                && manifest_requested_peers.insert(peer)
                            {
                                manifest_force_snapshot_peers.insert(peer);
                                let _ = p2p_cmd
                                    .send(noid_p2p::NetworkCommand::RequestStateManifest {
                                        generation: snapshot_sync_generation,
                                        peer,
                                        requester_height: our_height,
                                    })
                                    .await;
                                tracing::info!(
                                    our_height,
                                    highest_announced,
                                    stale_secs,
                                    peer = %peer,
                                    "stale deep gap — requesting snapshot manifest"
                                );
                            }
                        } else {
                            let count = (gap + 1)
                                .min(u64::from(CONNECTED_TIP_PROBE_HEADERS))
                                as u16;
                            if fetch_in_progress.insert(peer) {
                                recent_header_fetches
                                    .insert((peer, our_height, count), Instant::now());
                                let _ = p2p_cmd
                                    .send(noid_p2p::NetworkCommand::FetchHeaders {
                                        peer,
                                        start_height: our_height,
                                        count,
                                    })
                                    .await;
                            }
                            tracing::info!(
                                our_height,
                                highest_announced,
                                stale_secs,
                                peer = %peer,
                                "stale recent gap — re-requesting authenticated headers"
                            );
                        }
                        last_tip_advance = Instant::now();
                    }
                }
            }

        }

        } // tokio::select!
    } // loop
}

// ---------------------------------------------------------------------------
// Orphan pool helper
// ---------------------------------------------------------------------------

fn cleanup_snapshot_staging_session_offthread(staging: SnapshotStagingSession) {
    tokio::task::spawn_blocking(move || drop(staging));
}

fn cleanup_snapshot_header_staging_offthread(staging: SnapshotHeaderStaging) {
    tokio::task::spawn_blocking(move || {
        let _ = staging.discard();
    });
}

fn drop_verified_history_step(verified: VerifiedHistoryStepSnapshot) {
    let VerifiedHistoryStepSnapshot {
        headers,
        boundary,
        inbound_memory_permit,
        ..
    } = verified;
    drop(boundary);
    drop(inbound_memory_permit);
    tokio::task::spawn_blocking(move || {
        let _ = headers.discard();
    });
}

fn cleanup_finalized_snapshot_staging_offthread(staging: FinalizedSnapshotStaging) {
    tokio::task::spawn_blocking(move || drop(staging));
}

fn create_snapshot_staging_session(
    staging_root: &Path,
    manifest: &noid_p2p::protocol::GetStateManifestResponse,
    header: noid_chain::BlockHeader,
) -> Result<SnapshotStagingSession, String> {
    if header.height != manifest.tip_height
        || header.log_slots != manifest.log_slots
        || header.active_slot_count != manifest.active_slot_count
        || header.alloc_counter != manifest.alloc_counter
    {
        return Err("snapshot boundary header/manifest metadata mismatch".into());
    }
    let metadata = AuthenticatedSnapshotMetadata::from_authenticated_header(
        header,
        manifest.tip_hash,
        manifest.eff_log,
    )
    .map_err(|error| format!("snapshot staging metadata rejected: {error}"))?;
    if manifest.segment_ids.len() != manifest.segment_roots.len()
        || manifest.segment_ids.len() != manifest.segment_lengths.len()
    {
        return Err("snapshot manifest descriptor vectors are not parallel".into());
    }
    let descriptors = manifest
        .segment_ids
        .iter()
        .copied()
        .zip(manifest.segment_roots.iter().copied())
        .zip(manifest.segment_lengths.iter().copied())
        .map(
            |((segment_id, segment_root), encoded_len)| SnapshotSegmentDescriptor {
                segment_id,
                segment_root,
                encoded_len,
            },
        )
        .collect();
    SnapshotStagingSession::new(staging_root, metadata, descriptors)
        .map_err(|error| format!("snapshot staging session creation failed: {error}"))
}

async fn queue_snapshot_segment_download(
    p2p_cmd: &tokio::sync::mpsc::Sender<noid_p2p::NetworkCommand>,
    peer: libp2p::PeerId,
    manifest: &noid_p2p::protocol::GetStateManifestResponse,
    pending_segment_ids: &mut std::collections::HashSet<u16>,
    segment_queue: &mut std::collections::VecDeque<u16>,
) {
    for &seg_id in &manifest.segment_ids {
        segment_queue.push_back(seg_id);
    }
    dispatch_queued_snapshot_segments(
        p2p_cmd,
        peer,
        manifest.tip_height,
        manifest.tip_hash,
        false,
        false,
        pending_segment_ids,
        segment_queue,
    )
    .await;
}

async fn begin_snapshot_state_download(
    p2p_cmd: &tokio::sync::mpsc::Sender<noid_p2p::NetworkCommand>,
    staging_root: &Path,
    peer: libp2p::PeerId,
    manifest: &noid_p2p::protocol::GetStateManifestResponse,
    header: noid_chain::BlockHeader,
    pending_segment_ids: &mut std::collections::HashSet<u16>,
    segment_queue: &mut std::collections::VecDeque<u16>,
) -> Result<SnapshotStagingSession, String> {
    let staging = create_snapshot_staging_session(staging_root, manifest, header)?;
    queue_snapshot_segment_download(p2p_cmd, peer, manifest, pending_segment_ids, segment_queue)
        .await;
    Ok(staging)
}

fn snapshot_segment_request_capacity(
    outstanding_requests: usize,
    _staging_active: bool,
    response_buffered: bool,
) -> usize {
    if response_buffered {
        return 0;
    }
    1usize.saturating_sub(outstanding_requests)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SnapshotSegmentResponseAdmission {
    StageNow,
    BufferOne,
    RetryOverflow,
    Stale,
}

fn admit_snapshot_segment_response(
    segment_id: u16,
    staging_active: bool,
    response_buffered: bool,
    pending_segment_ids: &mut std::collections::HashSet<u16>,
    segment_queue: &mut std::collections::VecDeque<u16>,
) -> SnapshotSegmentResponseAdmission {
    if !pending_segment_ids.remove(&segment_id) {
        return SnapshotSegmentResponseAdmission::Stale;
    }
    if !staging_active {
        return SnapshotSegmentResponseAdmission::StageNow;
    }
    if !response_buffered {
        return SnapshotSegmentResponseAdmission::BufferOne;
    }
    if !segment_queue.contains(&segment_id) {
        segment_queue.push_front(segment_id);
    }
    SnapshotSegmentResponseAdmission::RetryOverflow
}

/// Fill only the already-admitted network request window.  Snapshot payload
/// authentication itself remains single-operation; this helper never creates
/// another decoder or retains response bytes in the node event loop.
async fn dispatch_queued_snapshot_segments(
    p2p_cmd: &tokio::sync::mpsc::Sender<noid_p2p::NetworkCommand>,
    peer: libp2p::PeerId,
    expected_tip_height: u64,
    expected_tip_hash: [u8; 32],
    staging_active: bool,
    response_buffered: bool,
    pending_segment_ids: &mut std::collections::HashSet<u16>,
    segment_queue: &mut std::collections::VecDeque<u16>,
) {
    let capacity = snapshot_segment_request_capacity(
        pending_segment_ids.len(),
        staging_active,
        response_buffered,
    );
    for _ in 0..capacity {
        if let Some(seg_id) = segment_queue.pop_front() {
            if !pending_segment_ids.insert(seg_id) {
                continue;
            }
            let _ = p2p_cmd
                .send(noid_p2p::NetworkCommand::RequestStateSegment {
                    peer,
                    segment_id: seg_id,
                    expected_tip_height,
                    expected_tip_hash,
                })
                .await;
        } else {
            break;
        }
    }
}

/// Insert a block into the orphan pool, evicting the lowest-height entry when
/// the pool is over count or retained-byte capacity.
///
/// Keyed by `header.prev_block_hash` so that when the missing parent
/// arrives, `orphan_pool.remove(&parent_hash)` instantly finds the child.
///
/// Eviction policy: remove the orphan with the **lowest block height** first.
/// This mimics LRU by height — stale orphans from a long-dead fork are
/// discarded before newer ones that are more likely to be resolved.
fn insert_orphan(pool: &mut std::collections::HashMap<[u8; 32], OrphanBlock>, orphan: OrphanBlock) {
    pool.insert(orphan.header.prev_block_hash, orphan);

    while pool.len() > MAX_ORPHAN_POOL {
        evict_lowest_orphan(pool, "count cap");
    }
    while orphan_pool_retained_bytes(pool) > MAX_ORPHAN_POOL_BYTES && !pool.is_empty() {
        evict_lowest_orphan(pool, "byte cap");
    }
}

fn orphan_pool_retained_bytes(pool: &std::collections::HashMap<[u8; 32], OrphanBlock>) -> usize {
    pool.values().fold(0usize, |sum, orphan| {
        sum.saturating_add(orphan.retained_bytes())
    })
}

fn evict_lowest_orphan(pool: &mut std::collections::HashMap<[u8; 32], OrphanBlock>, reason: &str) {
    if let Some((key, height, bytes)) = pool
        .iter()
        .min_by_key(|(_, orphan)| orphan.header.height)
        .map(|(key, orphan)| (*key, orphan.header.height, orphan.retained_bytes()))
    {
        pool.remove(&key);
        tracing::debug!(height, bytes, reason, "evicted orphan block");
    }
}

// ---------------------------------------------------------------------------
// Wallet block update
// ---------------------------------------------------------------------------

async fn rescan_wallet_from_chain(
    wallet: &SharedWallet,
    chain: &Arc<RwLock<MdbxChainContext>>,
    mempool: &AsyncMempool,
    reason: &'static str,
) -> Result<(), String> {
    let (active_index, next_index, owner) = {
        let guard = wallet
            .lock()
            .map_err(|_| "wallet state lock is poisoned".to_string())?;
        match guard.as_ref() {
            None => return Ok(()),
            Some(w) => (w.active_index, w.next_index, w.active_address().0),
        }
    };
    let (reserved_inputs, reserved_outputs) = mempool.reserved_slots().await;
    let ctx = chain.read().await;
    let snapshot = ctx
        .store
        .get_verified_utxos_by_owner(&owner)
        .map_err(|error| format!("verified owner reload failed: {error}"))?;
    let height = snapshot.height;
    let found = snapshot.utxos.len();
    let balance = snapshot
        .utxos
        .iter()
        .map(|utxo| utxo.amount)
        .fold(0u64, u64::saturating_add);
    {
        let mut guard = wallet
            .lock()
            .map_err(|_| "wallet state lock is poisoned".to_string())?;
        if let Some(w) = guard.as_mut() {
            w.commit_verified_activation(
                active_index,
                next_index,
                active_index,
                owner,
                snapshot,
                &reserved_inputs,
                &reserved_outputs,
            )
            .map_err(|error| format!("active address changed during reload: {error}"))?;
        }
    }
    drop(ctx);
    tracing::info!(
        height,
        active_index,
        utxos = found,
        balance,
        reason,
        "wallet active address reloaded"
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn apply_verified_snapshot(
    chain: &Arc<RwLock<MdbxChainContext>>,
    mempool: &AsyncMempool,
    wallet: &SharedWallet,
    manifest: noid_p2p::protocol::GetStateManifestResponse,
    staging: FinalizedSnapshotStaging,
    history_step: VerifiedHistoryStepSnapshot,
    tail: Option<FinalizedSnapshotTail>,
    history_step_runtime: Option<Arc<noid_recursive::acceptance::history_step::HistoryStepRuntime>>,
    wallet_operation_gate: &WalletOperationGate,
    external_mining_attempts: &ExternalMiningAttemptInvalidator,
) -> Result<AppliedVerifiedSnapshot, SnapshotInstallError> {
    if history_step.height != manifest.tip_height || history_step.block_hash != manifest.tip_hash {
        drop_verified_history_step(history_step);
        return Err(SnapshotInstallError::BeforeCommit(
            "HistoryStep authority does not match snapshot manifest".into(),
        ));
    }
    let snapshot_height = manifest.tip_height;
    let segment_count = staging.descriptors().len();
    let tail_matches_manifest = if snapshot_bridge_requires_tail(
        snapshot_height,
        manifest.bridge_tip_height,
    ) == Some(false)
    {
        tail.is_none()
    } else {
        tail.as_ref().is_some_and(|tail| {
            tail.boundary_height() == snapshot_height
                && tail.boundary_hash() == manifest.tip_hash
                && tail.tip_height() == manifest.bridge_tip_height
                && tail.tip_hash() == manifest.bridge_tip_hash
        })
    };
    if !tail_matches_manifest {
        drop_verified_history_step(history_step);
        drop(tail);
        return Err(SnapshotInstallError::BeforeCommit(
            "snapshot tail does not cover the authenticated manifest bridge".into(),
        ));
    }
    let expected_tail_tip = tail
        .as_ref()
        .map_or(snapshot_height, FinalizedSnapshotTail::tip_height);
    let expected_tail_hash = tail
        .as_ref()
        .map_or(manifest.tip_hash, FinalizedSnapshotTail::tip_hash);
    let expected_tail_blocks = tail.as_ref().map_or(0, FinalizedSnapshotTail::block_count);
    let expected_tail_bytes = tail
        .as_ref()
        .map_or(0, FinalizedSnapshotTail::payload_bytes);
    let VerifiedHistoryStepSnapshot {
        boundary,
        mut headers,
        allow_nonfinal_rebase,
        inbound_memory_permit,
        ..
    } = history_step;

    // Global order for operations that can replace the active wallet cache:
    // wallet_operation_gate -> mempool snapshot/view -> chain -> SharedWallet.
    // Keep this single acquisition across the atomic state install and wallet
    // reload. None of those helpers may enter wallet RPC code that acquires
    // the same gate.
    let wallet_operation = wallet_operation_gate.lock().await;
    let install_chain = Arc::clone(chain);
    let result = tokio::task::spawn_blocking(move || {
        // Keep the verified terminal capability and its process-global inbound
        // charge alive through the atomic HistoryStep/snapshot commit.
        let inbound_memory_permit = inbound_memory_permit;
        let mut tail = tail;
        let mut ctx = install_chain.blocking_write();
        let state_install_started = Instant::now();
        if let Err(error) = ctx.apply_staged_state_snapshot(
            &staging,
            &boundary,
            &mut headers,
            allow_nonfinal_rebase,
        ) {
            drop(ctx);
            let _ = headers.discard();
            return Err(format!("apply authenticated state snapshot: {error:?}"));
        }
        let state_install_elapsed = state_install_started.elapsed();
        // The atomic MDBX commit now owns the snapshot boundary. Verify one
        // recursive terminal for the sealed compact suffix before mutating any
        // post-boundary state. Every body is then materialized through the same
        // native header/PoW/epoch/transaction/state checks as ordinary blocks.
        let tail_apply_started = Instant::now();
        let mut confirmed_tx_hashes = Vec::new();
        let mut applied_tail_blocks = 0u64;
        let mut tail_error = None;
        let mut tail_terminal_rejected = false;

        if let Some(tail) = tail.as_mut() {
            let suffix_tip_header = tail.tip_header();
            let suffix_authority = suffix_tip_header.and_then(|tip_header| {
                let epoch_height =
                    noid_chain::consensus::tx_epoch_anchor_height_for_child(tip_header.height);
                let epoch_anchor_header = if epoch_height <= ctx.tip_height() {
                    ctx.get_header_from_store(epoch_height)
                        .map_err(|error| {
                            format!("load recursive suffix epoch anchor: {error}")
                        })?
                        .ok_or_else(|| {
                            "recursive suffix epoch anchor is missing from snapshot headers"
                                .to_string()
                        })?
                } else {
                    tail.header_at(epoch_height)?.ok_or_else(|| {
                        "recursive suffix epoch anchor is missing from compact tail".to_string()
                    })?
                };
                let terminal_bytes = tail.take_terminal_bytes();
                let terminal_len = terminal_bytes.len();
                let terminal_started = Instant::now();
                let result = ctx.verify_recursive_suffix(
                        tip_header,
                        epoch_anchor_header,
                        terminal_bytes,
                        |claim| {
                            verify_history_step_terminal(claim, history_step_runtime.as_deref())
                        },
                    );
                if let Err(error) = &result {
                    tail_terminal_rejected =
                        history_step_context_error_is_terminal_peer_fault(error);
                }
                let result = result
                    .map_err(|error| format!("verify recursive snapshot suffix: {error}"));
                tracing::info!(
                    height = tip_header.height,
                    terminal_bytes = terminal_len,
                    elapsed_ms = terminal_started.elapsed().as_millis(),
                    accepted = result.is_ok(),
                    "snapshot compact suffix terminal verification completed"
                );
                result
            });

            if let Err(error) = &suffix_authority {
                tail_error = Some(error.clone());
            }
            if let Ok(mut authority) = suffix_authority {
                let mut tail_reader = match tail.reader() {
                    Ok(reader) => Some(reader),
                    Err(error) => {
                        tail_error = Some(error);
                        None
                    }
                };
                while tail_error.is_none() {
                    let block_bytes = match tail_reader
                        .as_mut()
                        .expect("tail reader exists while no error is recorded")
                        .next_block()
                    {
                        Ok(Some(block_bytes)) => block_bytes,
                        Ok(None) => break,
                        Err(error) => {
                            tail_error = Some(error);
                            break;
                        }
                    };
                    let block = match noid_chain::Block::from_bytes(&block_bytes) {
                        Ok(block) => block,
                        Err(error) => {
                            tail_error = Some(format!(
                                "decode staged tail block: {error:?}"
                            ));
                            break;
                        }
                    };
                    let block_height = block.header.height;
                    let txids = match noid_chain::try_compute_logical_txids(&block.transactions) {
                        Ok(txids) => txids,
                        Err(error) => {
                            tail_error = Some(format!(
                                "staged tail block {block_height} has invalid logical transactions: {error}"
                            ));
                            break;
                        }
                    };
                    if let Err(error) = ctx.apply_verified_recursive_suffix_block(
                        &mut authority,
                        &block_bytes,
                        unix_now(),
                        |block, state| {
                            noid_chain::materialize_accepted_block_state(state, block)
                                .map_err(|error| format!("{error:?}"))
                        },
                    ) {
                        tail_error = Some(format!(
                            "apply staged tail block {block_height}: {error}"
                        ));
                        break;
                    }
                    confirmed_tx_hashes.extend(txids);
                    applied_tail_blocks = applied_tail_blocks.saturating_add(1);
                }
                if tail_error.is_none() && !authority.is_complete() {
                    tail_error =
                        Some("recursive snapshot suffix ended before its verified tip".to_string());
                }
            }
        }
        let view = ChainView::from_mdbx(&ctx);
        let height = ctx.tip_height();
        if tail_error.is_none()
            && (height != expected_tail_tip
                || view.tip_hash != expected_tail_hash
                || applied_tail_blocks != expected_tail_blocks)
        {
            tail_error = Some("applied snapshot tail does not end at its sealed tip".to_string());
        }
        drop(ctx);
        // Release temporary files only after every durable mutation and the
        // final compact chain view have been established.
        drop(staging);
        drop(boundary);
        drop(inbound_memory_permit);
        drop(tail);
        if let Err(error) = headers.discard() {
            tracing::warn!(err = %error, "committed snapshot header staging cleanup deferred");
        }
        Ok::<_, String>((
            height,
            view,
            confirmed_tx_hashes,
            tail_error,
            applied_tail_blocks,
            tail_terminal_rejected,
            state_install_elapsed,
            tail_apply_started.elapsed(),
        ))
    })
    .await
    .map_err(|error| {
        SnapshotInstallError::BeforeCommit(format!("snapshot install worker panicked: {error}"))
    })?
    .map_err(|error| {
        SnapshotInstallError::BeforeCommit(format!(
            "failed to apply verified state snapshot: {error}"
        ))
    })?;

    let (
        applied_height,
        view,
        confirmed_tx_hashes,
        tail_error,
        applied_tail_blocks,
        tail_terminal_rejected,
        state_install_elapsed,
        tail_apply_elapsed,
    ) = result;
    let applied = AppliedVerifiedSnapshot {
        height: applied_height,
        block_hash: view.tip_hash,
        tail_blocks: applied_tail_blocks,
        tail_bytes: expected_tail_bytes,
        tail_apply_elapsed,
        state_install_elapsed,
    };
    external_mining_attempts.invalidate_for_tip(applied_height, view.tip_hash);
    mempool
        .on_new_block(&confirmed_tx_hashes, applied_height, view)
        .await;

    // Establish the exact active-owner cache at the final replayed tail. This
    // deliberately replaces incremental wallet updates: the wallet sees one
    // coherent chain state and never an intermediate snapshot boundary.
    if let Err(error) = rescan_wallet_from_chain(wallet, chain, mempool, "snapshot sync").await {
        wallet::invalidate_active_cache(wallet);
        return Err(SnapshotInstallError::AfterCommit {
            applied,
            error: format!("snapshot applied but active-wallet reload failed: {error}"),
            terminal_rejected: tail_terminal_rejected,
        });
    }

    tracing::info!(
        snapshot_height,
        applied_height,
        tail_blocks = applied_tail_blocks,
        segments = segment_count,
        "snapshot boundary and disk tail fully applied"
    );
    drop(wallet_operation);
    if let Some(error) = tail_error {
        return Err(SnapshotInstallError::AfterCommit {
            applied,
            error: format!(
                "snapshot boundary committed at {snapshot_height}, but tail replay stopped at \
                {applied_height}: {error}"
            ),
            terminal_rejected: tail_terminal_rejected,
        });
    }
    Ok(applied)
}

/// Apply a newly confirmed block to the in-process wallet state.
///
/// Must be called after `apply_next_block` succeeds and before block pruning.
/// No-op if the wallet is not initialized.
fn update_wallet_for_block(wallet: &SharedWallet, block: &noid_chain::block::Block) {
    if let Err(error) = wallet::update_for_accepted_block(wallet, block) {
        tracing::error!(
            height = block.header.height,
            %error,
            "committed block but wallet update failed"
        );
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// HH:MM:SS timer for tracing (UTC, no new deps)
// ---------------------------------------------------------------------------

/// Compact UTC time formatter: `HH:MM:SS`.
/// Implements `tracing_subscriber::fmt::time::FormatTime` without the `time`
/// crate dep by reading `SystemTime` directly.
struct UtcHms;

impl tracing_subscriber::fmt::time::FormatTime for UtcHms {
    fn format_time(&self, w: &mut tracing_subscriber::fmt::format::Writer<'_>) -> std::fmt::Result {
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let h = (secs / 3600) % 24;
        let m = (secs / 60) % 60;
        let s = secs % 60;
        write!(w, "{h:02}:{m:02}:{s:02}")
    }
}

// ---------------------------------------------------------------------------
// Startup banner
// ---------------------------------------------------------------------------

/// Print a startup banner after all components are initialised.
///
/// Professional, dense, information-rich. Everything an operator needs
/// at a glance without being verbose. Uses println! so it is always
/// visible regardless of --log level.
#[allow(clippy::too_many_arguments)]
fn print_startup_banner(
    net_kind: &str,
    genesis: bool,
    p2p_listen: &str,
    rpc_listen: &str,
    tip_height: u64,
    state_root: &[u8; 32],
    active_slots: u64,
    log_slots: u32,
    materialized_segs: usize,
    total_segs: usize,
    encoded_state_bytes: u64,
    block_reward_noid: f64,
    wallet_addr: Option<&str>,
    mining: bool,
    coinbase: Option<&str>,
    version: &str,
) {
    // ANSI helpers
    let is_tty =
        std::env::var("TERM").is_ok_and(|t| t != "dumb") && std::env::var("NO_COLOR").is_err();
    macro_rules! col {
        ($c:expr, $s:expr) => {
            if is_tty {
                format!("{}{}{}", $c, $s, "\x1b[0m")
            } else {
                $s.to_string()
            }
        };
    }
    let b = |s: &str| col!("\x1b[1m", s);
    let dim = |s: &str| col!("\x1b[2m", s);
    let ylw = |s: &str| col!("\x1b[33m", s);
    let cyn = |s: &str| col!("\x1b[36m", s);

    let w = 76usize;
    let line = if is_tty {
        format!("\x1b[2m{}\x1b[0m", "─".repeat(w))
    } else {
        "─".repeat(w)
    };

    // Row helper: left-pad key to 14 chars
    let row = |key: &str, val: &str| {
        println!("  {}  {}", cyn(&format!("{key:<13}")), val);
    };

    // Fill bar for state
    let capacity = 1u64.checked_shl(log_slots).unwrap_or(u64::MAX);
    let fill_pct = if capacity > 0 {
        active_slots as f64 / capacity as f64 * 100.0
    } else {
        0.0
    };
    let bar_w = 24usize;
    let filled = ((fill_pct / 100.0) * bar_w as f64).round() as usize;
    let trigger = ((0.75_f64) * bar_w as f64).round() as usize;
    let bar: String = (0..bar_w)
        .map(|i| {
            if i < filled {
                '\u{2588}'
            } else if i == trigger.min(bar_w - 1) {
                '|'
            } else {
                '\u{2591}'
            }
        })
        .collect();
    let effective_log = log_slots.min(noid_chain::fri_state::LOG_SEGMENT_SIZE as u32) as u8;
    let max_segment_bytes = noid_chain::storage::max_encoded_segment_len_for_eff_log(effective_log)
        .unwrap_or(usize::MAX) as u64;
    let max_bytes = (total_segs as u64).saturating_mul(max_segment_bytes);
    let hb = |n: u64| -> String {
        if n >= 1 << 30 {
            format!("{:.1}GB", n as f64 / (1 << 30) as f64)
        } else if n >= 1 << 20 {
            format!("{:.1}MB", n as f64 / (1 << 20) as f64)
        } else if n >= 1 << 10 {
            format!("{:.1}KB", n as f64 / (1 << 10) as f64)
        } else {
            format!("{n}B")
        }
    };

    println!();
    println!("{line}");
    // Title line: name + version + network
    let title = format!(
        "PARANOID  {}   {}",
        b(&format!("v{version}")),
        dim(&format!(
            "·  {net_kind}{}",
            if genesis { "  (genesis mode)" } else { "" }
        ))
    );
    println!("  {}", title);
    println!("{line}");

    // Network
    row(
        "p2p / rpc",
        &format!("{p2p_listen}   {}", dim(&format!("rpc  {rpc_listen}"))),
    );

    // Chain
    row(
        "chain",
        &format!(
            "h={}   state  {}",
            b(&tip_height.to_string()),
            dim(&hex::encode(state_root))
        ),
    );

    // State
    row(
        "state",
        &format!(
            "{}/{} slots  {:.2}%  [{}]  {} seg  {} encoded  {} domain max",
            active_slots,
            capacity,
            fill_pct,
            bar,
            dim(&format!("{}/{}", materialized_segs, total_segs)),
            dim(&hb(encoded_state_bytes)),
            dim(&hb(max_bytes))
        ),
    );

    // Wallet
    if let Some(addr) = wallet_addr {
        row("wallet", &b(addr));
    }

    // Mining
    if mining {
        let cb = coinbase.unwrap_or_else(|| wallet_addr.unwrap_or("(none)"));
        row(
            "mining",
            &format!(
                "{reward:.2} NOID/block   coinbase  {cb}",
                reward = block_reward_noid
            ),
        );
    } else {
        row("mining", &ylw("disabled"));
    }

    println!("{line}");
    println!();

    // If state is near expansion threshold, warn the operator
    if fill_pct >= 70.0 {
        println!(
            "  {} state is {fill_pct:.1}% full \u{2014} expansion requires 10/18 \
             hard-finalized headers at or above 75%",
            ylw("WARN")
        );
        println!();
    }
}

fn load_or_create_config(path: &Path, defaults: &NodeConfig) -> anyhow::Result<(NodeConfig, bool)> {
    let expanded = expand_tilde(path);
    match std::fs::read_to_string(&expanded) {
        Ok(text) => {
            let config = toml::from_str(&text)
                .with_context(|| format!("parse node config: {}", expanded.display()))?;
            Ok((config, false))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if let Some(parent) = expanded
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
            {
                std::fs::create_dir_all(parent).with_context(|| {
                    format!("create node config directory: {}", parent.display())
                })?;
            }

            let encoded =
                toml::to_string_pretty(defaults).context("serialize default node config")?;
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }

            match options.open(&expanded) {
                Ok(mut file) => {
                    let write_result = file
                        .write_all(encoded.as_bytes())
                        .and_then(|()| file.sync_all());
                    if let Err(error) = write_result {
                        drop(file);
                        let _ = std::fs::remove_file(&expanded);
                        return Err(error).with_context(|| {
                            format!("write default node config: {}", expanded.display())
                        });
                    }
                    Ok((defaults.clone(), true))
                }
                // Another node may have created the file after our initial
                // read. Never overwrite it; load and validate that file.
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    let text = std::fs::read_to_string(&expanded).with_context(|| {
                        format!(
                            "read concurrently created node config: {}",
                            expanded.display()
                        )
                    })?;
                    let config = toml::from_str(&text)
                        .with_context(|| format!("parse node config: {}", expanded.display()))?;
                    Ok((config, false))
                }
                Err(error) => Err(error)
                    .with_context(|| format!("create node config: {}", expanded.display())),
            }
        }
        Err(error) => {
            Err(error).with_context(|| format!("read node config: {}", expanded.display()))
        }
    }
}

fn expand_tilde(p: &Path) -> PathBuf {
    let s = p.to_string_lossy();
    let rest = if s == "~" {
        Some("")
    } else {
        s.strip_prefix("~/").or_else(|| s.strip_prefix("~\\"))
    };
    let Some(rest) = rest else {
        return p.to_path_buf();
    };

    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .or_else(|| {
            let drive = std::env::var_os("HOMEDRIVE")?;
            let path = std::env::var_os("HOMEPATH")?;
            let mut home = PathBuf::from(drive);
            home.push(path);
            Some(home)
        });
    match home {
        Some(mut home) => {
            if !rest.is_empty() {
                home.push(rest);
            }
            home
        }
        None => p.to_path_buf(),
    }
}

/// Parse a miner/wallet address from canonical bech32m (`o1…`).
fn parse_address(s: &str) -> anyhow::Result<noid_poseidon2b::primitives::Address> {
    if s.is_empty() {
        return Ok(noid_poseidon2b::primitives::Address([0u8; 32]));
    }
    noid_poseidon2b::primitives::Address::parse(s)
        .map_err(|e| anyhow::anyhow!("invalid address: {e}"))
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
