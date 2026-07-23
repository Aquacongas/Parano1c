// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! # paranoid — Paranoid Full Node Binary
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
use std::time::Instant;
use std::{
    fs::OpenOptions,
    io::{Read, Write},
};

use anyhow::Context;
use clap::Parser;
use tokio::sync::RwLock;
use tracing_subscriber::EnvFilter;

use noid_chain::consensus::wire_limits::{
    MAX_INFLIGHT_SEGMENTS, MAX_ORPHAN_POOL, MAX_ORPHAN_POOL_BYTES, MAX_SEGMENT_BYTES,
    MAX_SNAPSHOT_MANIFEST_SEGMENTS, MAX_TX_INTENT_BYTES_GLOBAL,
};
use noid_chain::consensus::NetworkConfig;
use noid_chain::storage::snapshot_staging::{
    AuthenticatedSnapshotMetadata, FinalizedSnapshotStaging, SnapshotStagingSession,
};
use noid_chain::storage::{
    encoded_segment_live_count_from_len, max_encoded_segment_len_for_eff_log, MdbxChainContext,
    SnapshotSegmentDescriptor,
};
use noid_mempool::{AsyncMempool, ChainView, MempoolConfig};
use noid_miner::{BlockMiner, MinerConfig};
use noid_node::snapshot_header_staging::{
    CanonicalHeaderBoundary, SnapshotHeaderBoundary, SnapshotHeaderStaging,
    ValidatedSnapshotHeaderStaging, MAX_STAGED_HEADER_BATCH,
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
    started_at: Instant,
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

fn mark_initial_sync_ready(sender: &tokio::sync::watch::Sender<bool>) {
    let already_ready = *sender.borrow();
    if !already_ready {
        sender.send_replace(true);
    }
}

const MINING_PEER_QUORUM: usize = 2;

struct MiningPeerQuorum {
    isolated: bool,
    connected: std::collections::HashSet<libp2p::PeerId>,
    confirmed: std::collections::HashSet<libp2p::PeerId>,
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
            confirmed: std::collections::HashSet::new(),
            ready,
            count,
        };
        quorum.publish();
        quorum
    }

    fn connect(&mut self, peer: libp2p::PeerId) {
        self.connected.insert(peer);
    }

    fn confirm(&mut self, peer: libp2p::PeerId) {
        self.connected.insert(peer);
        if self.confirmed.insert(peer) {
            self.publish();
        }
    }

    fn disconnect(&mut self, peer: libp2p::PeerId) {
        self.connected.remove(&peer);
        if self.confirmed.remove(&peer) {
            self.publish();
        }
    }

    fn waiting_for_quorum(&self) -> bool {
        !self.isolated && self.confirmed.len() < MINING_PEER_QUORUM
    }

    fn unconfirmed_connected(&self) -> Vec<libp2p::PeerId> {
        self.connected
            .difference(&self.confirmed)
            .copied()
            .collect()
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

/// A state-manifest round with zero responses is re-requested after this
/// deadline. A dropped response stream must not wedge sync: with few peers
/// there may never be another PeerConnected event to retrigger the probe
/// (live-test finding, 2026-07-12).
const STATE_MANIFEST_RESPONSE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(12);
const MINER_SHUTDOWN_GRACE: std::time::Duration = std::time::Duration::from_secs(30);

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
    B64,
    B255,
}

impl HistoryStepCacheClass {
    fn class_id(self) -> noid_recursive::CanonicalHistoryStepClassId {
        noid_recursive::CanonicalHistoryStepClassId::new(match self {
            Self::B64 => 0,
            Self::B255 => 1,
        })
        .expect("GUI cache class is canonical")
    }

    fn label(self) -> &'static str {
        match self {
            Self::B64 => "B64/m23",
            Self::B255 => "B255/m24",
        }
    }
}

#[derive(Parser, Debug)]
#[command(
    name = "paranoid",
    about = "Paranoid full node daemon — HistoryStep UTXO blockchain",
    version = env!("CARGO_PKG_VERSION"),
    long_about = "Run a Paranoid node and wallet.\n\nExample:\n  paranoid --miner --data-dir ~/.paranoid\n  paranoid --p2p-listen 0.0.0.0:9301 --seed 1.2.3.4:9301",
)]
struct Cli {
    /// Path to TOML config file. A missing file is created with safe defaults.
    /// Default: ~/.paranoid/paranoid.toml
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
    #[arg(long)]
    genesis: bool,

    /// Miner coinbase address (32-byte hex). Defaults to the wallet's ACTIVE address.
    #[arg(long, value_name = "HEX")]
    miner_address: Option<String>,

    /// Logical CPU threads used by the built-in miner and its proof phases.
    /// Defaults to every CPU visible to the process.
    #[arg(long, value_name = "N")]
    cpu_threads: Option<usize>,

    /// Data directory for the MDBX database and wallet key.
    /// Default: ~/.paranoid/data
    #[arg(long, value_name = "PATH")]
    data_dir: Option<PathBuf>,

    /// P2P listen address in HOST:PORT format. Default: 0.0.0.0:9400
    #[arg(long, value_name = "HOST:PORT")]
    p2p_listen: Option<String>,

    /// JSON-RPC listen address in HOST:PORT format. Default: 127.0.0.1:9401
    #[arg(long, value_name = "HOST:PORT")]
    rpc_listen: Option<String>,

    /// Seed peer address (HOST:PORT). Repeat for multiple seeds.
    /// Example: --seed 1.2.3.4:9301 --seed 5.6.7.8:9301
    #[arg(long, value_name = "HOST:PORT", action = clap::ArgAction::Append)]
    seed: Vec<String>,

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
    ///   paranoid --rpc-listen 0.0.0.0:9401 --mining-key s3cr3t
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
    ///   paranoid --rpc-listen 0.0.0.0:9401 --mining-key s3cr3t --allow-custom-coinbase
    ///   # Miner: getBlockTemplate("o1their_own_address")
    #[arg(long, requires = "mining_key")]
    allow_custom_coinbase: bool,

    /// Force-clear all volatile state on startup (segments, undo logs).
    /// The node will re-sync from peers via snapshot. Use after consensus upgrades
    /// or to recover from suspected data corruption.
    #[arg(long)]
    purge_state: bool,

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
/// 1. `HOST:PORT`            — IP or hostname + port  → `/ip4/H/tcp/P` or `/dns4/H/tcp/P`
/// 2. `hostname`             — bare DNS name           → `/dns4/hostname/tcp/{default_port}`
/// 3. `/ip4/.../tcp/...`     — libp2p multiaddr, passed through unchanged
/// 4. `dnsaddr:hostname`     — _dnsaddr TXT lookup     → `/dnsaddr/hostname`
///
/// Format 4 is the production DNS seed mechanism.  libp2p resolves
/// `_dnsaddr.<hostname>` TXT records at dial time, each encoding a full
/// multiaddr with PeerID.  This gives cryptographic peer verification and
/// easy multi-node seed rotation via DNS.
///
/// DNS setup for format 4:
///   _dnsaddr.noid.network  TXT  "dnsaddr=/ip4/1.2.3.4/tcp/9400/p2p/12D3KooW..."
///   _dnsaddr.noid.network  TXT  "dnsaddr=/ip4/5.6.7.8/tcp/9400/p2p/12D3KooW..."
fn seed_to_multiaddr(s: &str, default_port: u16) -> anyhow::Result<libp2p::Multiaddr> {
    // Format 4: "dnsaddr:<hostname>" → /dnsaddr/<hostname>
    // Resolves _dnsaddr.<hostname> TXT records (libp2p standard).
    if let Some(host) = s.strip_prefix("dnsaddr:") {
        let ma_str = format!("/dnsaddr/{}", host.trim());
        return ma_str
            .parse()
            .with_context(|| format!("build dnsaddr multiaddr for {host:?}"));
    }

    // Strip /p2p/<peer-id> suffix if present (format 3 variant)
    let base = s.split("/p2p/").next().unwrap_or(s).trim();

    // Format 3: already a multiaddr?
    if base.starts_with('/') {
        return base
            .parse()
            .with_context(|| format!("parse multiaddr: {base}"));
    }

    // Format 1: HOST:PORT
    if base.contains(':') {
        return ip_port_to_multiaddr(base);
    }

    // Format 2: bare hostname — use default network port.
    // /dns4/ triggers libp2p DNS resolution at dial time.
    let ma_str = format!("/dns4/{base}/tcp/{default_port}");
    ma_str
        .parse()
        .with_context(|| format!("build dns4 multiaddr for {base:?}"))
}

/// Convert a user-friendly "HOST:PORT" string into a libp2p Multiaddr.
///
/// Users type:  `127.0.0.1:9301`  or  `0.0.0.0:9301`
/// libp2p needs: `/ip4/127.0.0.1/tcp/9301`
///
/// This conversion is purely internal — users never see multiaddrs.
fn ip_port_to_multiaddr(addr: &str) -> anyhow::Result<libp2p::Multiaddr> {
    // Parse HOST:PORT
    let (host, port_str) = addr.rsplit_once(':').with_context(|| {
        format!(
            "invalid address {:?}: expected HOST:PORT (e.g. 127.0.0.1:9301)",
            addr
        )
    })?;
    let port: u16 = port_str
        .parse()
        .with_context(|| format!("invalid port in {:?}", addr))?;

    // Build /ip4/<host>/tcp/<port> or /ip6/<host>/tcp/<port>
    let ma_str = if host.contains(':') {
        // IPv6
        format!("/ip6/{host}/tcp/{port}")
    } else {
        format!("/ip4/{host}/tcp/{port}")
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

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut cli = Cli::parse();
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
        .unwrap_or_else(|| expand_tilde(&PathBuf::from("~/.paranoid/paranoid.toml")));
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
        backend = %noid_core::cpu::selected_backend(),
        threads = cpu_plan.shared_pool_threads,
        "CPU proof and mining backend selected"
    );
    // --seed accepts HOST:PORT; convert to multiaddr strings for internal use
    for raw_seed in cli.seed {
        let ma = ip_port_to_multiaddr(&raw_seed).with_context(|| format!("--seed {raw_seed}"))?;
        cfg.network.seeds.push(ma.to_string());
    }

    // --- Data directory: ~/.paranoid/data by default (no network subdir) ---
    let data_dir = if cfg.storage.path == Path::new("~/.paranoid/data") {
        expand_tilde(Path::new("~/.paranoid/data"))
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
    if cli.purge_state {
        tracing::info!("--purge-state: clearing the chain database before startup");
        let tmp_store =
            noid_chain::storage::MdbxStore::open(&data_dir).context("open MDBX for purge")?;
        tmp_store.clear_all().context("purge state")?;
        drop(tmp_store);
    }
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
    {
        let ctx = chain.read().await;
        let h = ctx.tip_height();
        let ts = ctx.tip_header().timestamp;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if h > 0 && ts > 0 && now.saturating_sub(ts) < 60 * 3 {
            mark_initial_sync_ready(&initial_sync_ready_tx);
            tracing::info!(height = h, "chain state is current");
        }
    }

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

    // Dial seeds: CLI seeds + config seeds + DNS seeds.
    let all_seeds: Vec<String> = cfg
        .network
        .seeds
        .clone()
        .into_iter()
        .chain(net.dns_seeds.iter().map(|s| s.to_string()))
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
    if cli.genesis {
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
    from: libp2p::PeerId,
    manifest: Box<noid_p2p::protocol::GetStateManifestResponse>,
    staging: SnapshotHeaderStaging,
    next_height: u64,
    target_height: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SnapshotHeaderNextAction {
    Fetch { start_height: u64, count: u16 },
    RequestTerminal,
}

fn snapshot_header_next_action(
    next_height: u64,
    target_height: u64,
) -> Result<SnapshotHeaderNextAction, String> {
    if next_height <= target_height {
        let count = (target_height - next_height + 1).min(MAX_STAGED_HEADER_BATCH as u64) as u16;
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
) -> Result<PendingSnapshotHeaderSync, String> {
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
    let target_height = manifest.tip_height;
    let after_target = target_height
        .checked_add(1)
        .ok_or_else(|| "snapshot target height has no representable successor".to_owned())?;

    let staging = if path.exists() {
        match SnapshotHeaderStaging::open(&path, store) {
            Ok(staging) if staging.next_height().map_err(|e| e.to_string())? <= after_target => {
                staging
            }
            Ok(staging) => {
                staging.discard().map_err(|error| error.to_string())?;
                let base = highest_snapshot_header_boundary(store, target_height)?;
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
                let base = highest_snapshot_header_boundary(store, target_height)?;
                if base.header.height == target_height {
                    SnapshotHeaderStaging::create_at_canonical_boundary(&path, store, base)
                } else {
                    SnapshotHeaderStaging::create(&path, store, base)
                }
                .map_err(|error| error.to_string())?
            }
        }
    } else {
        let base = highest_snapshot_header_boundary(store, target_height)?;
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
    /// The exact inbound allocation remains charged until the terminal bytes
    /// have entered the same MDBX transaction as the snapshot state.
    inbound_memory_permit: Option<Arc<tokio::sync::OwnedSemaphorePermit>>,
}

struct AppliedVerifiedSnapshot {
    height: u64,
    state_install_elapsed: std::time::Duration,
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
    let expected_epoch_height = (manifest.tip_height
        / noid_chain::consensus::params::TX_EPOCH_BLOCKS)
        * noid_chain::consensus::params::TX_EPOCH_BLOCKS;
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
        compare_manifest_fork_choice, gap_requires_snapshot_sync, load_or_create_config,
        mark_initial_sync_ready, next_block_has_competing_parent, p2p_listen_to_multiaddr,
        snapshot_header_next_action, state_segment_response_matches_snapshot_boundary,
        unavailable_block_requires_snapshot, validate_history_step_tip_future_drift,
        validate_snapshot_header_batch_admission, validate_snapshot_staged_header_boundary,
        MiningPeerQuorum, NodeConfig, SnapshotHeaderBoundary, SnapshotHeaderNextAction,
        MINING_PEER_QUORUM,
    };

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
    fn mining_quorum_counts_two_confirmed_ordinary_peers() {
        let (ready_tx, ready_rx) = tokio::sync::watch::channel(false);
        let (count_tx, count_rx) = tokio::sync::watch::channel(0usize);
        let mut quorum = MiningPeerQuorum::new(false, ready_tx, count_tx);
        let first = libp2p::PeerId::random();
        let second = libp2p::PeerId::random();

        quorum.connect(first);
        quorum.connect(second);
        assert_eq!(quorum.unconfirmed_connected().len(), 2);
        assert_eq!(*count_rx.borrow(), 0);
        assert!(!*ready_rx.borrow());

        quorum.confirm(first);
        assert_eq!(*count_rx.borrow(), 1);
        assert!(!*ready_rx.borrow());

        quorum.confirm(second);
        assert_eq!(*count_rx.borrow(), MINING_PEER_QUORUM);
        assert!(*ready_rx.borrow());

        quorum.disconnect(first);
        assert_eq!(*count_rx.borrow(), 1);
        assert!(!*ready_rx.borrow());
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
    fn first_start_creates_and_reuses_default_config() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("nested/paranoid.toml");
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
        let path = temp.path().join("paranoid.toml");
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
            "pre-launch retained full-block window is 18 blocks"
        );
        let local_height = 100;

        assert!(!gap_requires_snapshot_sync(local_height, local_height));
        assert!(!gap_requires_snapshot_sync(local_height, local_height + 17));
        assert!(!gap_requires_snapshot_sync(local_height, local_height + 18));
        assert!(gap_requires_snapshot_sync(local_height, local_height + 19));
    }

    #[test]
    fn caught_up_retained_suffix_does_not_fall_back_to_snapshot() {
        assert!(!unavailable_block_requires_snapshot(10, 11, 10));
        assert!(unavailable_block_requires_snapshot(10, 11, 11));
        assert!(unavailable_block_requires_snapshot(10, 11, 20));
        assert!(!unavailable_block_requires_snapshot(10, 12, 20));
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

    #[test]
    fn manifest_fork_choice_prefers_chainwork_then_height() {
        let mut low_work_high_height = noid_p2p::protocol::GetStateManifestResponse {
            tip_height: 100,
            ..Default::default()
        };
        low_work_high_height.cumulative_chainwork[0] = 5;

        let mut high_work_low_height = noid_p2p::protocol::GetStateManifestResponse {
            tip_height: 99,
            ..Default::default()
        };
        high_work_low_height.cumulative_chainwork[0] = 6;

        assert_eq!(
            compare_manifest_fork_choice(&high_work_low_height, &low_work_high_height),
            std::cmp::Ordering::Greater
        );

        let equal_work_higher_height = noid_p2p::protocol::GetStateManifestResponse {
            tip_height: 101,
            cumulative_chainwork: high_work_low_height.cumulative_chainwork,
            ..Default::default()
        };
        assert_eq!(
            compare_manifest_fork_choice(&equal_work_higher_height, &high_work_low_height),
            std::cmp::Ordering::Greater
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
    // Eclipse mitigation: collect from up to 3 peers before selecting.
    // Recovery: any failure resets ALL state and clears requested_peers
    // so the next PeerConnected event starts fresh.
    struct PendingManifest {
        from: libp2p::PeerId,
        manifest: Box<noid_p2p::protocol::GetStateManifestResponse>,
        history_step: Option<VerifiedHistoryStepSnapshot>,
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
            from: libp2p::PeerId,
            start_height: u64,
        },
    }
    struct SnapshotHeaderStagingCompletion {
        key: SnapshotHeaderStagingOperationKey,
        work_elapsed: std::time::Duration,
        result: Result<PendingSnapshotHeaderSync, String>,
    }
    #[derive(Clone, Copy, PartialEq, Eq)]
    struct HistoryStepVerificationKey {
        token: u64,
        from: libp2p::PeerId,
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
        result: Result<VerifiedHistoryStepSnapshot, String>,
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
    struct SnapshotInstallKey {
        generation: u64,
        from: libp2p::PeerId,
        height: u64,
        block_hash: [u8; 32],
    }
    struct SnapshotInstallCompletion {
        key: SnapshotInstallKey,
        result: Result<AppliedVerifiedSnapshot, String>,
    }
    let mut pending_manifest: Option<PendingManifest> = None;
    let mut pending_snapshot_header_sync: Option<PendingSnapshotHeaderSync> = None;
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
    let mut manifest_candidates: Vec<(
        libp2p::PeerId,
        Box<noid_p2p::protocol::GetStateManifestResponse>,
    )> = Vec::new();
    // Tracks peers already asked; cleared on failure so recovery is automatic.
    let mut manifest_requested_peers: std::collections::HashSet<libp2p::PeerId> =
        std::collections::HashSet::new();
    // Tracks peers for forced snapshot attempts. The manifest advertises the
    // snapshot boundary, so non-empty responses stay on the snapshot path.
    let mut manifest_force_snapshot_peers: std::collections::HashSet<libp2p::PeerId> =
        std::collections::HashSet::new();
    // Count of manifest responses received (including tip=0 "no state" replies).
    // When this equals manifest_requested_peers.len(), all peers have responded
    // and we proceed with whatever valid candidates we have (even just 1).
    let mut manifest_response_count: usize = 0;
    // Timestamp of the first valid manifest candidate.  If we haven't proceeded
    // within 10 seconds of the first candidate arriving, proceed anyway —
    // some peers may be offline, behind NAT, or not yet synced.
    let mut manifest_first_candidate_at: Option<std::time::Instant> = None;
    // Set when a manifest round begins and no response has arrived yet; any
    // manifest response clears it. The heartbeat re-requests a silent round
    // after STATE_MANIFEST_RESPONSE_TIMEOUT.
    let mut manifest_round_started_at: Option<std::time::Instant> = None;
    // Connected peers eligible for manifest (re-)requests.
    let mut manifest_peers: std::collections::HashSet<libp2p::PeerId> =
        std::collections::HashSet::new();
    // Payloads are authenticated one at a time and sealed to disk.  The
    // session retains only compact descriptors and a received bitset.
    let mut snapshot_staging: Option<SnapshotStagingSession> = None;
    // Segment IDs still outstanding.
    let mut pending_segment_ids: std::collections::HashSet<u16> = std::collections::HashSet::new();
    // Segment IDs queued but not yet requested (concurrency cap).
    let mut segment_queue: std::collections::VecDeque<u16> = std::collections::VecDeque::new();

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
            manifest_candidates.clear();
            manifest_requested_peers.clear();
            manifest_force_snapshot_peers.clear();
            manifest_response_count = 0;
            manifest_first_candidate_at = None;
            manifest_round_started_at = None;
            if let Some(stale_staging) = snapshot_staging.take() {
                cleanup_snapshot_staging_session_offthread(stale_staging);
            }
            pending_segment_ids.clear();
            segment_queue.clear();
            pending_shallow_fork = None;
            if history_step_verification_inflight.is_some() {
                tracing::debug!(
                    "sync state reset — waiting for the bounded verifier to release its admission"
                );
            } else if snapshot_header_staging_inflight.is_some()
                || snapshot_staging_inflight.is_some()
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

    macro_rules! begin_snapshot_header_staging {
        ($from:expr, $manifest:expr) => {{
            sync_phase_telemetry.begin_snapshot();
            let from = $from;
            let manifest = $manifest;
            snapshot_header_staging_token = snapshot_header_staging_token.wrapping_add(1);
            let key = SnapshotHeaderStagingOperationKey::Prepare {
                generation: snapshot_sync_generation,
                token: snapshot_header_staging_token,
                from,
                height: manifest.tip_height,
                block_hash: manifest.tip_hash,
            };
            snapshot_header_staging_inflight = Some(key);
            let completion = snapshot_header_staging_tx.clone();
            let store = snapshot_header_store.clone();
            let staging_root = snapshot_header_staging_root.clone();
            tokio::task::spawn_blocking(move || {
                let started = Instant::now();
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    prepare_snapshot_header_sync(&staging_root, &store, from, manifest)
                }))
                .map_err(|_| "snapshot header preparation worker panicked".to_owned())
                .and_then(|result| result);
                let _ = completion.blocking_send(SnapshotHeaderStagingCompletion {
                    key,
                    work_elapsed: started.elapsed(),
                    result,
                });
            });
        }};
    }

    // --- FetchHeaders in-progress guard ---
    //
    // Prevents FetchHeaders from being sent to the same peer thousands of
    // times during a block burst.  Entry is removed when HeadersBatch arrives
    // from that peer (or on disconnect).  Without this guard, 10 peers each
    // sending 40 blocks/s = 400 redundant FetchHeaders/s.
    let mut fetch_in_progress: std::collections::HashSet<libp2p::PeerId> =
        std::collections::HashSet::new();

    // --- Per-peer tx rate limiter ---
    //
    // Sliding-window rate limiter: tracks (tx_count_in_window, window_start) per peer.
    // Prevents a single peer from flooding the proof-verification semaphore queue.
    use std::time::{Duration, Instant};

    // Short-lived dedup for fork-recovery pulls. During two-miner races the same
    // orphan/fork announcement can be observed many times before the local node
    // reorganizes. Without this, each observation re-sends identical header/block
    // requests and floods logs/P2P with no extra safety.
    let mut recent_header_fetches: HashMap<(libp2p::PeerId, u64, u16), Instant> = HashMap::new();
    let mut recent_block_fetches: HashMap<(libp2p::PeerId, u64), Instant> = HashMap::new();
    const FETCH_DEDUP_TTL: Duration = Duration::from_secs(15);

    struct PendingBlockFetch {
        peer: libp2p::PeerId,
        requested_at: Instant,
    }
    let mut pending_block_fetches: HashMap<(u64, [u8; 32]), PendingBlockFetch> = HashMap::new();
    const BLOCK_FETCH_INFLIGHT_TTL: Duration = Duration::from_secs(8);

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

    // --- FetchHeaders recursion depth limiter ---
    //
    // Caps how many times we fetch further-back headers without finding a common
    // ancestor.  Each step covers 512 blocks, so 4 steps = 2048 blocks, well
    // beyond CONSENSUS_FINALITY_DEPTH.  If the limit is hit we request a full state
    // snapshot instead (the designed deep-sync mechanism).
    let mut fetch_depth: HashMap<libp2p::PeerId, u32> = HashMap::new();
    const MAX_FETCH_DEPTH: u32 = 4;

    // --- Stale-tip detection ---
    //
    // In large networks, block requests may fail (peer doesn't have the block
    // yet, stream capacity hit, etc.) with no retry.  The stale-tip check
    // detects when our chain hasn't advanced despite seeing higher announcements
    // and re-requests from a random connected peer.
    let mut last_tip_advance: Instant = Instant::now();
    let mut highest_announced: u64 = 0;
    let mut last_announcement_peer: Option<libp2p::PeerId> = None;

    // Heartbeat for time-dependent checks (manifest timeout, etc.)
    let mut heartbeat = tokio::time::interval(std::time::Duration::from_secs(2));
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    heartbeat.tick().await; // skip first

    loop {
        tokio::select! {
        rx_result = rx.recv() => { let rx_item = rx_result;
        match rx_item {
            Ok(NetworkEvent::BlockAnnouncement { from, header: announced_header }) => {
                let height = announced_header.height;
                let hash = noid_chain::consensus::pow::block_id(&announced_header);
                if snapshot_install_inflight.is_some() {
                    if height > highest_announced {
                        highest_announced = height;
                        sync_phase_telemetry.extend_suffix_target(height);
                        last_announcement_peer = Some(from);
                    }
                    tracing::debug!(
                        peer = %from,
                        height,
                        "snapshot install active — deferring block pull until post-install sync"
                    );
                    continue;
                }

                if height > highest_announced {
                    highest_announced = height;
                    sync_phase_telemetry.extend_suffix_target(height);
                    last_announcement_peer = Some(from);
                }
                // Compact block announcement: validate the advertised header before
                // downloading a potentially large accepted bundle. Direct-next
                // headers can be fully checked against the current tip; larger recent
                // gaps first pull headers, then bodies are requested only for the
                // verified competing chain in the HeadersBatch path.
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
                        let prev_active_counts = ctx.prev_active_counts();
                        let anchor = ctx.anchor_info();
                        let local_time = unix_now();
                        noid_chain::consensus::validate_header(
                            &announced_header,
                            &parent,
                            &prev_timestamps,
                            &prev_active_counts,
                            local_time,
                            anchor.anchor_height,
                            anchor.anchor_timestamp,
                            &anchor.anchor_target,
                        )
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

                    let fetch_key = (height, hash);
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
            Ok(
                NetworkEvent::IncomingBlock {
                    from,
                    bundle,
                    mut inbound_memory_permit,
                }
                | NetworkEvent::RecentBlock {
                    from,
                    bundle,
                    mut inbound_memory_permit,
                },
            ) => {
                let advertised_height = bundle.height();
                if advertised_height > highest_announced {
                    highest_announced = advertised_height;
                    sync_phase_telemetry.extend_suffix_target(advertised_height);
                    last_announcement_peer = Some(from);
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
                                    pending_shallow_fork = None;
                                    drop(bundle);
                                    drop(inbound_memory_permit.take());
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
                                let (our_tip_height, canonical_ancestor, our_extra_work) = {
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
                                    (our_tip_height, canonical_ancestor, work)
                                };

                                if canonical_ancestor != Some(completed.ancestor_hash) {
                                    tracing::debug!(
                                        peer = %completed.peer,
                                        ancestor = completed.ancestor_height,
                                        "shallow-fork ancestor changed while bundles were downloading"
                                    );
                                    drop(completed);
                                    continue;
                                }
                                let should_reorg = noid_chain::work_gt(
                                    &completed.advertised_work,
                                    &our_extra_work,
                                ) || (completed.advertised_work == our_extra_work
                                    && new_tip_height > our_tip_height);
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
                                    "reorg: downloaded shallow fork has more work, reorganising"
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
                                        mark_initial_sync_ready(&initial_sync_ready);
                                        mining_peer_quorum.confirm(from);
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
                                mark_initial_sync_ready(&initial_sync_ready);
                                mining_peer_quorum.confirm(from);
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

                                        let our_extra_work = {
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
                                            w
                                        };

                                        // Reorg only if competing chain has strictly MORE work
                                        let should_reorg =
                                            noid_chain::work_gt(&competing_work, &our_extra_work)
                                                || (competing_work == our_extra_work
                                                    && new_tip_height > our_tip_height);

                                        if should_reorg {
                                            tracing::info!(
                                                our_tip = our_tip_height,
                                                new_tip = new_tip_height,
                                                ancestor = ancestor_height,
                                                blocks = new_chain.len(),
                                                peer = %from,
                                                "reorg: competing chain has more work, reorganising"
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
                                                    drop(inbound_memory_permit.take());
                                                    external_mining_attempts.invalidate_for_tip(
                                                        new_tip_height,
                                                        applied_reorg.view.tip_hash,
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
                                                    mark_initial_sync_ready(&initial_sync_ready);
                                                    mining_peer_quorum.confirm(from);
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
                                                        manifest_candidates.clear();
                                                        manifest_requested_peers.clear();
                                                        manifest_force_snapshot_peers.clear();
                                                        manifest_response_count = 0;
                                                        manifest_first_candidate_at = None;
                                                        manifest_requested_peers.insert(from);
                                                        manifest_force_snapshot_peers.insert(from);
                                                        let _ = p2p_cmd
                                                            .send(noid_p2p::NetworkCommand::RequestStateManifest {
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
            Ok(NetworkEvent::RecentBlockUnavailable { from, height }) => {
                let unavailable_shallow = pending_shallow_fork
                    .as_ref()
                    .filter(|pending| pending.peer == from)
                    .and_then(|pending| pending.expected_header())
                    .is_some_and(|expected| expected.height == height);
                if unavailable_shallow {
                    tracing::warn!(
                        peer = %from,
                        height,
                        "peer cannot serve the selected shallow-fork bundle — aborting session"
                    );
                    pending_shallow_fork = None;
                    pending_block_fetches.retain(|_, pending| pending.peer != from);
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
                        manifest_candidates.clear();
                        manifest_requested_peers.clear();
                        manifest_force_snapshot_peers.clear();
                        manifest_response_count = 0;
                        manifest_first_candidate_at = None;
                        manifest_requested_peers.insert(from);
                        manifest_force_snapshot_peers.insert(from);
                        let _ = p2p_cmd
                            .send(noid_p2p::NetworkCommand::RequestStateManifest {
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
            Ok(NetworkEvent::NewTx { from, intent_bytes }) => {
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
                });
            }
            Ok(NetworkEvent::PeerConnected(peer)) => {
                tracing::info!(peer = %peer, "peer connected");
                mining_peer_quorum.connect(peer);
                manifest_peers.insert(peer);

                if snapshot_install_inflight.is_some() {
                    tracing::debug!(
                        peer = %peer,
                        "snapshot install active — deferring peer sync probes until new announcements"
                    );
                    continue;
                }

                let our_height = {
                    let ctx = chain.read().await;
                    ctx.tip_height()
                };

                // A connection has no fresh block gossip to reveal the peer's
                // current tip. Probe with the existing bounded header protocol,
                // anchored at our exact tip (genesis for an empty node). The
                // response selects direct retained-block sync for gaps <= 18
                // and snapshot sync for deeper gaps. A manifest alone cannot
                // do this because it intentionally describes finalized F, not
                // the live peer tip; for chains shorter than finality it is
                // empty even though direct blocks are available.
                const CONNECTED_TIP_PROBE_HEADERS: u16 = 512;
                let request_key = (peer, our_height, CONNECTED_TIP_PROBE_HEADERS);
                if fetch_in_progress.insert(peer) {
                    recent_header_fetches.insert(request_key, Instant::now());
                    p2p_cmd
                        .send(noid_p2p::NetworkCommand::FetchHeaders {
                            peer,
                            start_height: our_height,
                            count: CONNECTED_TIP_PROBE_HEADERS,
                        })
                        .await
                        .ok();
                    tracing::debug!(
                        peer = %peer,
                        start_height = our_height,
                        "probing connected peer tip with anchored headers"
                    );
                }

                // Request peer's mempool regardless of sync state.
                // Late-joining nodes miss gossipsub events published before
                // they subscribed; this fills the gap.
                p2p_cmd
                    .send(noid_p2p::NetworkCommand::RequestMempoolSync { peer })
                    .await
                    .ok();
            }
            Ok(NetworkEvent::HeadersBatch { from, headers }) => {
                // Headers batch arrived — clear the in-progress guard.
                fetch_in_progress.remove(&from);
                if snapshot_install_inflight.is_some() {
                    tracing::debug!(
                        peer = %from,
                        headers = headers.len(),
                        "snapshot install active — dropping stale header batch"
                    );
                    continue;
                }

                if snapshot_header_staging_inflight.as_ref().is_some_and(|key| {
                    matches!(
                        key,
                        SnapshotHeaderStagingOperationKey::Append {
                            from: active_from,
                            ..
                        } if *active_from == from
                    )
                }) {
                    tracing::debug!(
                        peer = %from,
                        headers = headers.len(),
                        "snapshot header staging busy — dropping duplicate batch"
                    );
                    continue;
                }

                if pending_snapshot_header_sync.as_ref().is_some_and(|sync| {
                    sync.from == from && sync.next_height > sync.target_height
                }) {
                    tracing::debug!(
                        peer = %from,
                        headers = headers.len(),
                        "snapshot exact header target already staged — dropping late batch"
                    );
                    continue;
                }

                if pending_snapshot_header_sync
                    .as_ref()
                    .is_some_and(|sync| sync.from == from)
                {
                    let sync = pending_snapshot_header_sync
                        .take()
                        .expect("checked pending snapshot header sync");
                    let remaining = sync.target_height - sync.next_height + 1;
                    if let Err(error) = validate_snapshot_header_batch_admission(
                        sync.next_height,
                        sync.target_height,
                        headers.len(),
                    ) {
                        tracing::warn!(
                            peer = %from,
                            headers = headers.len(),
                            remaining,
                            err = %error,
                            "snapshot header sync returned an invalid batch size"
                        );
                        cleanup_snapshot_header_staging_offthread(sync.staging);
                        reset_sync_state!();
                        continue;
                    }

                    snapshot_header_staging_token = snapshot_header_staging_token.wrapping_add(1);
                    let key = SnapshotHeaderStagingOperationKey::Append {
                        generation: snapshot_sync_generation,
                        token: snapshot_header_staging_token,
                        from,
                        start_height: sync.next_height,
                    };
                    snapshot_header_staging_inflight = Some(key);
                    let completion = snapshot_header_staging_tx.clone();
                    let store = snapshot_header_store.clone();
                    let staging_path = sync.staging.path().to_owned();
                    tokio::task::spawn_blocking(move || {
                        let started = Instant::now();
                        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(
                            move || {
                                let mut sync = sync;
                                let next = sync
                                    .staging
                                    .append_batch(&store, &headers)
                                    .map_err(|error| error.to_string())?;
                                sync.next_height = next;
                                Ok(sync)
                            },
                        ))
                        .map_err(|_| "snapshot header append worker panicked".to_owned())
                        .and_then(|result| result);
                        if result.is_err() {
                            let _ = std::fs::remove_file(staging_path);
                        }
                        let _ = completion.blocking_send(SnapshotHeaderStagingCompletion {
                            key,
                            work_elapsed: started.elapsed(),
                            result,
                        });
                    });
                    continue;
                }

                // Find common ancestor for reorg.
                if headers.is_empty() {
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
                    // Found a common ancestor — reset the depth counter for this peer.
                    *fetch_depth.entry(from).or_insert(0) = 0;
                    // Found common ancestor. The competing chain:
                    // headers with height > ancestor_height, ordered ascending.
                    let mut competing: Vec<_> = headers
                        .iter()
                        .filter(|h| h.height > ancestor_height)
                        .collect();
                    competing.sort_by_key(|h| h.height);

                    let new_tip_height = competing
                        .last()
                        .map(|h| h.height)
                        .unwrap_or(ancestor_height);

                    if ancestor_height == our_tip && new_tip_height == our_tip {
                        // The peer returned our exact canonical tip and no
                        // extension. This is a completed authenticated initial
                        // sync probe, not an absence of peers. Make readiness
                        // durable so a miner created later starts immediately.
                        mark_initial_sync_ready(&initial_sync_ready);
                        mining_peer_quorum.confirm(from);
                        tracing::debug!(
                            peer = %from,
                            height = our_tip,
                            "connected peer confirms local tip is current"
                        );
                    }

                    if new_tip_height > our_tip {
                        if new_tip_height > highest_announced {
                            highest_announced = new_tip_height;
                            sync_phase_telemetry.extend_suffix_target(new_tip_height);
                            last_announcement_peer = Some(from);
                        }

                        if gap_requires_snapshot_sync(our_tip, new_tip_height) {
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
                                        peer: from,
                                        requester_height: our_tip,
                                    })
                                    .await;
                            }
                            continue;
                        }

                        // The batch contains our exact current tip followed by
                        // one linked extension. Pull it sequentially through
                        // SyncBlocksFrom; that path keeps only one large
                        // accepted bundle in flight and auto-continues after
                        // each successful commit.
                        if ancestor_height == our_tip {
                            let gap = new_tip_height - our_tip;
                            tracing::info!(
                                peer = %from,
                                our_tip,
                                peer_tip = new_tip_height,
                                gap,
                                "connected header probe found recent extension — starting direct sync"
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

                        let (competing_work, our_extra_work) = {
                            use noid_chain::{add_work, block_work};
                            let mut competing_work = [0u8; 32];
                            for header in &competing {
                                competing_work = add_work(
                                    &competing_work,
                                    &block_work(&header.difficulty_target),
                                );
                            }
                            let mut our_extra_work = [0u8; 32];
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
                            (competing_work, our_extra_work)
                        };
                        let advertises_better_chain =
                            noid_chain::work_gt(&competing_work, &our_extra_work)
                                || (competing_work == our_extra_work
                                    && new_tip_height > our_tip);
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

                        let expected_headers: Vec<noid_chain::BlockHeader> =
                            competing.into_iter().copied().collect();
                        let first = *expected_headers
                            .first()
                            .expect("a competing header suffix is non-empty");
                        let first_hash = noid_chain::consensus::pow::block_id(&first);
                        tracing::info!(
                            ancestor = ancestor_height,
                            our_tip,
                            competing_tip = new_tip_height,
                            peer = %from,
                            bundles = expected_headers.len(),
                            "shallow fork has more work — starting sequential bundle download"
                        );
                        pending_shallow_fork = Some(PendingShallowFork {
                            peer: from,
                            ancestor_height,
                            ancestor_hash,
                            expected_headers,
                            candidates: Vec::new(),
                            retained_bytes: 0,
                            advertised_work: competing_work,
                            started_at: Instant::now(),
                        });
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
                    // Common ancestor not in our recent chain — request more headers
                    // going further back, subject to a recursion depth limit.
                    let oldest = headers.first().map(|h| h.height).unwrap_or(0);
                    if oldest > 0 {
                        let depth = fetch_depth.entry(from).or_insert(0);
                        if *depth >= MAX_FETCH_DEPTH {
                            tracing::info!(
                                peer = %from,
                                depth = *depth,
                                "FetchHeaders depth limit reached — requesting snapshot manifest"
                            );
                            *depth = 0; // reset for next time
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
                                        peer: from,
                                        requester_height: our_tip,
                                    })
                                    .await;
                            }
                        } else {
                            *depth += 1;
                            let fetch_from = oldest.saturating_sub(512);
                            tracing::debug!(
                                fetch_from,
                                depth = *depth,
                                "batch headers: ancestor not found, fetching further back"
                            );
                            let _ = p2p_cmd
                                .send(noid_p2p::NetworkCommand::FetchHeaders {
                                    peer: from,
                                    start_height: fetch_from,
                                    count: 512,
                                })
                                .await;
                        }
                    }
                }
            }
            Ok(NetworkEvent::StateManifest { from, manifest }) => {
                if snapshot_install_inflight.is_some() {
                    tracing::debug!(
                        from = %from,
                        tip = manifest.tip_height,
                        "snapshot install active — dropping stale manifest response"
                    );
                    continue;
                }
                // Received the state manifest (step 1 of snapshot sync).
                // Eclipse mitigation: collect from multiple peers, pick best.
                // Track all responses (including tip=0) to detect when all
                // requested peers have replied, avoiding infinite wait.
                manifest_round_started_at = None;
                let force_snapshot = manifest_force_snapshot_peers.remove(&from);
                manifest_response_count += 1;
                if manifest.tip_height == 0 {
                    tracing::debug!(from = %from, "manifest tip_height=0, peer has no state yet");
                    // Don't add to candidates, but fall through to check if we should
                    // proceed with existing candidates now that we've heard from this peer.
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
                    && (pending_manifest.is_some()
                        || pending_snapshot_header_sync.is_some()
                        || snapshot_header_staging_inflight.is_some()
                        || history_step_verification_inflight.is_some())
                {
                    if manifest_candidates.len() < 3 {
                        tracing::debug!(
                            from = %from, tip = manifest.tip_height,
                            "already verifying a manifest; storing as late candidate"
                        );
                        manifest_candidates.push((from, manifest));
                    }
                } else if manifest.tip_height > 0 && manifest_candidates.len() < 3 {
                    manifest_candidates.push((from, manifest));
                }

                // Check whether to proceed after EVERY response (including tip=0).
                // This prevents the node from waiting forever when some peers have
                // no state yet (fresh network) or return an empty manifest.
                //
                // Proceed when:
                //  a) 2+ valid candidates (Eclipse resistant), OR
                //  b) only 1 peer was ever requested (single-peer network), OR
                //  c) all requested peers have responded (even if some returned tip=0), OR
                //  d) 10 seconds elapsed since the first valid candidate arrived
                //     (handles offline/slow peers that never respond)
                if !manifest_candidates.is_empty() {
                    manifest_first_candidate_at.get_or_insert_with(std::time::Instant::now);
                }
                if pending_manifest.is_none()
                    && pending_snapshot_header_sync.is_none()
                    && snapshot_header_staging_inflight.is_none()
                    && history_step_verification_inflight.is_none()
                    && snapshot_staging_inflight.is_none()
                    && snapshot_install_inflight.is_none()
                    && !manifest_candidates.is_empty()
                {
                    let all_responded = manifest_response_count >= manifest_requested_peers.len();
                    let timed_out = manifest_first_candidate_at
                        .map(|t| t.elapsed() > std::time::Duration::from_secs(10))
                        .unwrap_or(false);
                    let should_proceed = manifest_candidates.len() >= 2
                        || manifest_requested_peers.len() <= 1
                        || all_responded
                        || timed_out;
                    if should_proceed {
                        let (best_peer, best_manifest) = manifest_candidates
                            .drain(..)
                            .max_by(|(_, a), (_, b)| compare_manifest_fork_choice(a, b))
                            .expect("manifest_candidates is non-empty");
                        tracing::info!(
                            from = %best_peer,
                            tip = best_manifest.tip_height,
                            segments = best_manifest.segment_ids.len(),
                            responded = manifest_response_count,
                            requested = manifest_requested_peers.len(),
                            "selected best manifest — staging headers for HistoryStep verification"
                        );
                        begin_snapshot_header_staging!(best_peer, best_manifest);
                    } else {
                        tracing::info!(
                            responded = manifest_response_count,
                            requested = manifest_requested_peers.len(),
                            candidates = manifest_candidates.len(),
                            "manifest received — waiting for more candidates (Eclipse protection)"
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
                if pending_segment_ids.contains(&response.segment_id) {
                    if pending_manifest
                        .as_ref()
                        .is_some_and(|pending| pending.from != from)
                    {
                        tracing::warn!(from = %from, segment = response.segment_id, "ignoring snapshot segment from non-selected peer");
                        continue;
                    }
                    if response.data.is_some() {
                        if let Some(active) = snapshot_staging_inflight {
                            // At most one 8 MiB payload is decoded at a time.
                            // Responses for other already-requested IDs are
                            // released immediately and re-requested after the
                            // active operation, rather than retained in RAM.
                            let duplicate_of_active = matches!(
                                active,
                                SnapshotStagingOperationKey::Accept {
                                    from: active_from,
                                    segment_id: active_segment,
                                    ..
                                } if active_from == from && active_segment == response.segment_id
                            );
                            if !duplicate_of_active
                                && pending_segment_ids.remove(&response.segment_id)
                                && !segment_queue.contains(&response.segment_id)
                            {
                                segment_queue.push_back(response.segment_id);
                            }
                            tracing::debug!(
                                from = %from,
                                segment = response.segment_id,
                                duplicate_of_active,
                                "snapshot staging busy — released payload for bounded retry"
                            );
                            // Drop the complete response so its process-global
                            // inbound permit follows the payload allocation.
                            drop(response);
                            continue;
                        }

                        let Some(mut staging) = snapshot_staging.take() else {
                            tracing::warn!(from = %from, "segment received without snapshot staging session");
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
                            let result = std::panic::catch_unwind(
                                std::panic::AssertUnwindSafe(move || {
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
                                    // The wire allocation and its inbound
                                    // permit are released together only after
                                    // authentication and atomic publication.
                                    drop(response);
                                    result
                                }),
                            )
                            .map_err(|_| "snapshot segment staging worker panicked".to_owned())
                            .and_then(|result| result);
                            let _ = completion.blocking_send(
                                SnapshotStagingCompletion::Accepted {
                                    key,
                                    payload_bytes,
                                    work_elapsed: started.elapsed(),
                                    result,
                                },
                            );
                        });
                        tracing::debug!(
                            from = %from,
                            segment = segment_id,
                            "snapshot segment queued for bounded authentication/staging"
                        );
                    } else {
                        // Peer couldn't serve this exact snapshot segment. Most commonly
                        // the peer mined/applied a newer tip after serving the manifest,
                        // so the old segment no longer matches the authenticated root.
                        // Restart immediately from a fresh manifest instead of waiting for
                        // the next block announcement/peer event.
                        let requester_height = {
                            let ctx = chain.read().await;
                            ctx.tip_height()
                        };
                        tracing::warn!(
                            from = %from,
                            segment = response.segment_id,
                            requester_height,
                            "snapshot segment unavailable or stale — retrying fresh manifest"
                        );
                        reset_sync_state!();
                        manifest_requested_peers.insert(from);
                        let _ = p2p_cmd
                            .send(noid_p2p::NetworkCommand::RequestStateManifest {
                                peer: from,
                                requester_height,
                            })
                            .await;
                        continue;
                    }
                }
            }

            Ok(NetworkEvent::HistoryStepTerminal {
                from,
                height,
                block_hash,
                terminal_bytes,
                inbound_memory_permit,
            }) => {
                let snapshot_correlated = pending_snapshot_header_sync
                    .as_ref()
                    .is_some_and(|pending| {
                        pending.from == from
                            && pending.next_height
                                == pending.target_height.saturating_add(1)
                            && pending.manifest.tip_height == height
                            && pending.manifest.tip_hash == block_hash
                    });

                if !snapshot_correlated {
                    drop(terminal_bytes);
                    drop(inbound_memory_permit);
                    tracing::debug!(
                        from = %from,
                        height,
                        "dropping stale or mismatched HistoryStep terminal response"
                    );
                    continue;
                }

                if snapshot_install_inflight.is_some() {
                    // Drop terminal bytes and their process-global admission as
                    // one response; the installed boundary starts a fresh
                    // suffix sync on completion.
                    drop(terminal_bytes);
                    drop(inbound_memory_permit);
                    tracing::debug!(
                        from = %from,
                        height,
                        "snapshot install active — releasing stale HistoryStep terminal"
                    );
                    continue;
                }
                // Terminal decoding and every streamed matrix check
                // run on the blocking pool with no chain lock held. The
                // private header staging file travels with the terminal.

                // If segment collection is already in progress (pending_segment_ids non-empty),
                // a second HistoryStep terminal would corrupt the active session.
                // Ignore it to protect the in-flight segment download.
                if !pending_segment_ids.is_empty() || !segment_queue.is_empty() {
                    tracing::debug!(
                        from = %from,
                        "ignoring HistoryStep terminal — segment collection already in progress"
                    );
                    continue;
                }

                let sync = match pending_snapshot_header_sync.take() {
                    Some(sync) if sync.from == from => sync,
                    Some(sync) => {
                        tracing::warn!(
                            terminal_from = %from, manifest_from = %sync.from,
                            "HistoryStep terminal from unexpected peer, preserving staged headers"
                        );
                        pending_snapshot_header_sync = Some(sync);
                        continue;
                    }
                    None => {
                        tracing::debug!(from = %from, "unexpected HistoryStep terminal, no staged headers");
                        continue;
                    }
                };

                let Some(runtime) = history_step_runtime.clone() else {
                    tracing::error!(
                        from = %from,
                        tip = sync.manifest.tip_height,
                        "snapshot rejected: HistoryStep verifier unavailable"
                    );
                    cleanup_snapshot_header_staging_offthread(sync.staging);
                    reset_sync_state!();
                    continue;
                };
                let expected_height = sync.manifest.tip_height;
                let expected_hash = sync.manifest.tip_hash;
                history_step_verification_token =
                    history_step_verification_token.wrapping_add(1);
                let key = HistoryStepVerificationKey {
                    token: history_step_verification_token,
                    from,
                    height: expected_height,
                    block_hash: expected_hash,
                };
                let generation = snapshot_sync_generation;
                let completion = history_step_verification_tx.clone();
                let generation_guard = Arc::clone(&snapshot_sync_generation_guard);
                let store = snapshot_header_store.clone();
                let verification_chain = Arc::clone(&chain);
                let manifest = sync.manifest;
                let staging = sync.staging;
                let staged_header_count = staging.staged_len();
                let staging_path = staging.path().to_owned();
                history_step_verification_inflight = Some(key);
                tokio::task::spawn_blocking(move || {
                    let mut header_validation_elapsed = std::time::Duration::ZERO;
                    let mut terminal_measurement = None;
                    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        if generation_guard.load(std::sync::atomic::Ordering::Acquire)
                            != generation
                        {
                            return Err(
                                "HistoryStep verification superseded before start".to_owned(),
                            );
                        }
                        let header_started = Instant::now();
                        let validated_headers = staging
                            .validate_complete(
                                &store,
                                expected_height,
                                expected_hash,
                                manifest.cumulative_chainwork,
                            )
                            .map_err(|error| error.to_string())?;
                        let boundary = validated_headers.boundary();
                        validate_snapshot_staged_header_boundary(&manifest, &boundary)?;
                        validate_history_step_tip_future_drift(&boundary, unix_now())?;
                        header_validation_elapsed = header_started.elapsed();
                        if generation_guard.load(std::sync::atomic::Ordering::Acquire)
                            != generation
                        {
                            let _ = validated_headers.discard();
                            return Err(
                                "HistoryStep verification superseded before completion"
                                    .to_owned(),
                            );
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
                                format!("verify snapshot HistoryStep boundary: {error}")
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
                            inbound_memory_permit,
                        })
                    }))
                    .map_err(|_| "HistoryStep verifier worker panicked".to_owned())
                    .and_then(|result| result);
                    if result.is_err() {
                        let _ = std::fs::remove_file(staging_path);
                    }
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
                    from = %from,
                    tip = expected_height,
                    "snapshot HistoryStep verification started off-thread"
                );
            }
            Ok(event @ NetworkEvent::PeerDisconnected(peer))
            | Ok(event @ NetworkEvent::PeerRequestFailed(peer)) => {
                let connection_closed = matches!(event, NetworkEvent::PeerDisconnected(_));
                if connection_closed {
                    mining_peer_quorum.disconnect(peer);
                    manifest_peers.remove(&peer);
                    tracing::debug!(peer = %peer, "peer disconnected");
                } else {
                    tracing::debug!(peer = %peer, "peer sync request failed");
                }
                if pending_shallow_fork
                    .as_ref()
                    .is_some_and(|pending| pending.peer == peer)
                {
                    tracing::debug!(
                        peer = %peer,
                        "selected shallow-fork peer disconnected; discarding bounded session"
                    );
                    pending_shallow_fork = None;
                }
                let snapshot_sync_lost = pending_manifest
                    .as_ref()
                    .is_some_and(|pending| pending.from == peer)
                    || pending_snapshot_header_sync
                        .as_ref()
                        .is_some_and(|pending| pending.from == peer)
                    || snapshot_header_staging_inflight.as_ref().is_some_and(|key| match key {
                        SnapshotHeaderStagingOperationKey::Prepare { from, .. }
                        | SnapshotHeaderStagingOperationKey::Append { from, .. } => *from == peer,
                    })
                    || history_step_verification_inflight
                        .is_some_and(|pending| pending.from == peer);
                if snapshot_sync_lost {
                    tracing::warn!(peer = %peer, "selected snapshot peer lost; discarding disk staging session");
                    reset_sync_state!();
                }
                fetch_in_progress.remove(&peer);
                recent_header_fetches.retain(|(p, _, _), _| *p != peer);
                recent_block_fetches.retain(|(p, _), _| *p != peer);
                pending_block_fetches.retain(|_, pending| pending.peer != peer);
                manifest_requested_peers.remove(&peer);
                fetch_depth.remove(&peer);
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
                if let Ok(sync) = completed.result {
                    cleanup_snapshot_header_staging_offthread(sync.staging);
                }
                tracing::debug!(
                    key = ?completed.key,
                    "discarding superseded snapshot header staging completion"
                );
                continue;
            }
            snapshot_header_staging_inflight = None;
            let (generation, from) = match completed.key {
                SnapshotHeaderStagingOperationKey::Prepare {
                    generation, from, ..
                }
                | SnapshotHeaderStagingOperationKey::Append {
                    generation, from, ..
                } => (generation, from),
            };
            if generation != snapshot_sync_generation {
                if let Ok(sync) = completed.result {
                    cleanup_snapshot_header_staging_offthread(sync.staging);
                }
                tracing::debug!(
                    from = %from,
                    "discarding snapshot headers from a reset sync generation"
                );
                continue;
            }
            sync_phase_telemetry.record_header_work(completed.work_elapsed);
            let sync = match completed.result {
                Ok(sync) => sync,
                Err(error) => {
                    tracing::warn!(
                        from = %from,
                        err = %error,
                        "snapshot header preparation/staging failed"
                    );
                    reset_sync_state!();
                    continue;
                }
            };
            if sync.from != from {
                cleanup_snapshot_header_staging_offthread(sync.staging);
                tracing::warn!(from = %from, "snapshot header staging peer changed");
                reset_sync_state!();
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
                    count,
                } => {
                    let target_height = sync.target_height;
                    pending_snapshot_header_sync = Some(sync);
                    fetch_in_progress.insert(from);
                    let _ = p2p_cmd
                        .send(noid_p2p::NetworkCommand::FetchHeaders {
                            peer: from,
                            start_height,
                            count,
                        })
                        .await;
                    tracing::info!(
                        peer = %from,
                        next_height = start_height,
                        target_height,
                        "snapshot: fetching headers into isolated disk staging"
                    );
                }
                SnapshotHeaderNextAction::RequestTerminal => {
                    let terminal_height = sync.manifest.tip_height;
                    let terminal_hash = sync.manifest.tip_hash;
                    pending_snapshot_header_sync = Some(sync);
                    let _ = p2p_cmd
                        .send(noid_p2p::NetworkCommand::RequestHistoryStepTerminal {
                            peer: from,
                            height: terminal_height,
                            block_hash: terminal_hash,
                        })
                        .await;
                    tracing::info!(
                        peer = %from,
                        target_height = terminal_height,
                        "snapshot: exact staged header target reached — requesting HistoryStep terminal"
                    );
                }
            }
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
                            reset_sync_state!();
                            continue;
                        }
                    };
                    sync_phase_telemetry.record_state_segment(payload_bytes, work_elapsed);
                    if !pending_manifest.as_ref().is_some_and(|pending| pending.from == from)
                        || !pending_segment_ids.remove(&segment_id)
                    {
                        tracing::warn!(
                            from = %from,
                            segment = segment_id,
                            "snapshot staging completion lost its selected manifest/request"
                        );
                        cleanup_snapshot_staging_session_offthread(staging);
                        reset_sync_state!();
                        continue;
                    }
                    snapshot_staging = Some(staging);

                    if let Some(pending) = pending_manifest.as_ref() {
                        dispatch_queued_snapshot_segments(
                            &p2p_cmd,
                            pending.from,
                            pending.manifest.tip_height,
                            pending.manifest.tip_hash,
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
                    if pending_segment_ids.is_empty() && segment_queue.is_empty() {
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
                            reset_sync_state!();
                            continue;
                        }
                    };
                    sync_phase_telemetry.record_state_work(work_elapsed);
                    let Some(mut pending) = pending_manifest.take() else {
                        tracing::warn!(from = %from, "snapshot finalized without selected manifest");
                        cleanup_finalized_snapshot_staging_offthread(finalized);
                        reset_sync_state!();
                        continue;
                    };
                    if pending.from != from {
                        tracing::warn!(from = %from, expected = %pending.from, "snapshot finalization peer changed");
                        cleanup_finalized_snapshot_staging_offthread(finalized);
                        reset_sync_state!();
                        continue;
                    }
                    let Some(history_step) = pending.history_step.take() else {
                        tracing::error!(from = %from, "verified snapshot lost HistoryStep authority");
                        cleanup_finalized_snapshot_staging_offthread(finalized);
                        reset_sync_state!();
                        continue;
                    };

                    let manifest = *pending.manifest;
                    let key = SnapshotInstallKey {
                        generation: snapshot_sync_generation,
                        from,
                        height: manifest.tip_height,
                        block_hash: manifest.tip_hash,
                    };
                    snapshot_install_inflight = Some(key);
                    let install_chain = Arc::clone(&chain);
                    let install_mempool = mempool.clone();
                    let install_wallet = Arc::clone(&wallet);
                    let install_wallet_operation_gate = Arc::clone(&wallet_operation_gate);
                    let install_external_mining_attempts = external_mining_attempts.clone();
                    let completion = snapshot_install_completion_tx.clone();
                    let install_task = tokio::spawn(async move {
                        apply_verified_snapshot(
                            &install_chain,
                            &install_mempool,
                            &install_wallet,
                            manifest,
                            finalized,
                            history_step,
                            &install_wallet_operation_gate,
                            &install_external_mining_attempts,
                        )
                        .await
                    });
                    tokio::spawn(async move {
                        let result = install_task
                            .await
                            .map_err(|error| format!("snapshot install task panicked: {error}"))
                            .and_then(|result| result);
                        let _ = completion
                            .send(SnapshotInstallCompletion { key, result })
                            .await;
                    });
                    tracing::info!(
                        from = %from,
                        tip = key.height,
                        segments = segment_count,
                        "snapshot finalized on disk — atomic install running off event loop"
                    );
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
            match completed.result {
                Ok(applied) => {
                    sync_phase_telemetry.record_state_work(applied.state_install_elapsed);
                    log_sync_phase_measurement(sync_phase_telemetry.finish_headers());
                    log_sync_phase_measurement(sync_phase_telemetry.finish_state());

                    let height = applied.height;
                    tracing::info!(height, from = %completed.key.from, "snapshot install completed");
                    reset_sync_state!();
                    if let Some(empty_suffix) =
                        sync_phase_telemetry.begin_suffix(height, highest_announced)
                    {
                        log_sync_phase_measurement(empty_suffix);
                    }
                    last_tip_advance = Instant::now();
                    mark_initial_sync_ready(&initial_sync_ready);
                    mining_peer_quorum.confirm(completed.key.from);
                    let _ = template_changes.send(());
                    if highest_announced > height {
                        let peer = last_announcement_peer.unwrap_or(completed.key.from);
                        let count = (highest_announced - height)
                            .min(noid_chain::consensus::params::RECENT_BLOCK_RETENTION_DEPTH)
                            as u16;
                        let _ = p2p_cmd
                            .send(noid_p2p::NetworkCommand::SyncBlocksFrom {
                                peer,
                                from_height: height.saturating_add(1),
                                count,
                            })
                            .await;
                        tracing::debug!(
                            peer = %peer,
                            from_height = height.saturating_add(1),
                            highest_announced,
                            "requested fresh retained suffix after snapshot install"
                        );
                    }
                }
                Err(error) => {
                    tracing::error!(
                        from = %completed.key.from,
                        tip = completed.key.height,
                        err = %error,
                        "failed to apply verified state snapshot"
                    );
                    reset_sync_state!();
                }
            }
        }

        completed = history_step_verification_rx.recv() => {
            let Some(completed) = completed else {
                continue;
            };
            if history_step_verification_inflight != Some(completed.key) {
                if let Ok(verified) = completed.result {
                    drop_verified_history_step(verified);
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
                    drop_verified_history_step(verified);
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
                    tracing::error!(
                        from = %from,
                        tip = completed.key.height,
                        err = %error,
                        "snapshot rejected: HistoryStep terminal verification failed"
                    );
                    reset_sync_state!();
                    continue;
                }
            };

            tracing::info!(
                from = %from,
                tip = completed.manifest.tip_height,
                segments = completed.manifest.segment_ids.len(),
                "snapshot manifest accepted — staging authenticated boundary"
            );
            let staging = match create_snapshot_staging_session(
                &snapshot_staging_root,
                &completed.manifest,
                *verified_history_step.boundary.header(),
            ) {
                Ok(staging) => staging,
                Err(error) => {
                    tracing::warn!(peer = %from, err = %error, "snapshot staging initialization failed");
                    drop_verified_history_step(verified_history_step);
                    reset_sync_state!();
                    continue;
                }
            };
            snapshot_staging = Some(staging);
            queue_snapshot_segment_download(
                &p2p_cmd,
                from,
                &completed.manifest,
                &mut pending_segment_ids,
                &mut segment_queue,
            )
            .await;
            // The terminal allocation and inbound permit remain owned by the
            // selected manifest until atomic snapshot installation.
            pending_manifest = Some(PendingManifest {
                from,
                manifest: completed.manifest,
                history_step: Some(verified_history_step),
            });
            if pending_segment_ids.is_empty() && segment_queue.is_empty() {
                // No segments (fresh network, no UTXOs yet).
                let staging = snapshot_staging
                    .take()
                    .expect("snapshot staging exists before segment download");
                let segment_count = staging.descriptors().len();
                let key = SnapshotStagingOperationKey::Finalize {
                    generation: snapshot_sync_generation,
                    from,
                };
                snapshot_staging_inflight = Some(key);
                let completion = snapshot_staging_completion_tx.clone();
                tokio::task::spawn_blocking(move || {
                    let started = Instant::now();
                    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
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
            let fetch_cutoff = now - FETCH_DEDUP_TTL;
            recent_header_fetches.retain(|_, t| *t >= fetch_cutoff);
            recent_block_fetches.retain(|_, t| *t >= fetch_cutoff);
            pending_block_fetches
                .retain(|_, pending| now.duration_since(pending.requested_at) < BLOCK_FETCH_INFLIGHT_TTL);

            // Ordinary wallet nodes count toward mining readiness once they
            // confirm our canonical tip. A wallet may connect while still
            // catching up, so repeat the bounded tip probe only while the
            // quorum is incomplete. Once two peers confirm, this adds no
            // steady-state network traffic.
            if mining_peer_quorum.waiting_for_quorum() {
                let our_height = {
                    let ctx = chain.read().await;
                    ctx.tip_height()
                };
                const MINING_QUORUM_TIP_PROBE_HEADERS: u16 = 512;
                for peer in mining_peer_quorum.unconfirmed_connected() {
                    let request_key = (peer, our_height, MINING_QUORUM_TIP_PROBE_HEADERS);
                    let recently_requested = recent_header_fetches
                        .get(&request_key)
                        .is_some_and(|requested| requested.elapsed() < FETCH_DEDUP_TTL);
                    if fetch_in_progress.contains(&peer) || recently_requested {
                        continue;
                    }
                    fetch_in_progress.insert(peer);
                    recent_header_fetches.insert(request_key, Instant::now());
                    let _ = p2p_cmd
                        .send(noid_p2p::NetworkCommand::FetchHeaders {
                            peer,
                            start_height: our_height,
                            count: MINING_QUORUM_TIP_PROBE_HEADERS,
                        })
                        .await;
                }
            }

            if pending_shallow_fork
                .as_ref()
                .is_some_and(|pending| pending.started_at.elapsed() >= Duration::from_secs(45))
            {
                let peer = pending_shallow_fork
                    .as_ref()
                    .expect("timed-out shallow-fork session exists")
                    .peer;
                tracing::warn!(
                    peer = %peer,
                    "shallow-fork bundle download timed out — discarding bounded session"
                );
                pending_shallow_fork = None;
                pending_block_fetches.retain(|_, pending| pending.peer != peer);
            }

            // A manifest round that produced zero responses is dead air — a
            // dropped response stream, a peer that never served it. Reset and
            // re-request from every connected peer; with a single seed there
            // is no second PeerConnected event to save us.
            if manifest_round_started_at.is_some_and(|started| {
                now.duration_since(started) >= STATE_MANIFEST_RESPONSE_TIMEOUT
            }) && manifest_response_count == 0
                && pending_manifest.is_none()
                && snapshot_staging.is_none()
                && snapshot_install_inflight.is_none()
            {
                tracing::warn!(
                    peers = manifest_peers.len(),
                    "state manifest round timed out with no responses — re-requesting"
                );
                reset_sync_state!();
                let our_height = {
                    let ctx = chain.read().await;
                    ctx.tip_height()
                };
                for peer in manifest_peers.iter().copied() {
                    manifest_requested_peers.insert(peer);
                    p2p_cmd
                        .send(noid_p2p::NetworkCommand::RequestStateManifest {
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

            // --- Stale-tip recovery ---
            // If our chain hasn't advanced in 30s but we've seen higher announcements,
            // re-request the missing blocks from the peer that announced highest.
            // This handles the case where all initial block requests failed (peer
            // didn't have the block yet, stream capacity hit, etc.) in large networks.
            let stale_secs = last_tip_advance.elapsed().as_secs();
            if stale_secs >= 30 {
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
                            let _ = p2p_cmd
                                .send(noid_p2p::NetworkCommand::SyncBlocksFrom {
                                    peer,
                                    from_height: our_height + 1,
                                    count: gap as u16,
                                })
                                .await;
                            tracing::info!(
                                our_height,
                                highest_announced,
                                stale_secs,
                                peer = %peer,
                                "stale recent gap — re-requesting accepted bundles"
                            );
                        }
                        last_tip_advance = Instant::now();
                    }
                }
            }

            // If we have valid candidates and the timeout has elapsed, proceed now.
            if pending_manifest.is_none()
                && pending_snapshot_header_sync.is_none()
                && snapshot_header_staging_inflight.is_none()
                && history_step_verification_inflight.is_none()
                && snapshot_staging_inflight.is_none()
                && snapshot_install_inflight.is_none()
                && !manifest_candidates.is_empty()
            {
                let timed_out = manifest_first_candidate_at
                    .map(|t| t.elapsed() > std::time::Duration::from_secs(10))
                    .unwrap_or(false);
                if timed_out {
                    let (best_peer, best_manifest) = manifest_candidates
                        .drain(..)
                        .max_by(|(_, a), (_, b)| compare_manifest_fork_choice(a, b))
                        .expect("manifest_candidates is non-empty");
                    tracing::info!(
                        from = %best_peer,
                        tip = best_manifest.tip_height,
                        "manifest timeout — proceeding with best available candidate"
                    );
                    begin_snapshot_header_staging!(best_peer, best_manifest);
                }
            }
        }

        } // tokio::select!
    } // loop
}

// ---------------------------------------------------------------------------
// Orphan pool helper
// ---------------------------------------------------------------------------

fn compare_manifest_fork_choice(
    a: &noid_p2p::protocol::GetStateManifestResponse,
    b: &noid_p2p::protocol::GetStateManifestResponse,
) -> std::cmp::Ordering {
    if noid_chain::work_gt(&a.cumulative_chainwork, &b.cumulative_chainwork) {
        return std::cmp::Ordering::Greater;
    }
    if noid_chain::work_gt(&b.cumulative_chainwork, &a.cumulative_chainwork) {
        return std::cmp::Ordering::Less;
    }
    a.tip_height.cmp(&b.tip_height)
}

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
        pending_segment_ids,
        segment_queue,
    )
    .await;
}

/// Fill only the already-admitted network request window.  Snapshot payload
/// authentication itself remains single-operation; this helper never creates
/// another decoder or retains response bytes in the node event loop.
async fn dispatch_queued_snapshot_segments(
    p2p_cmd: &tokio::sync::mpsc::Sender<noid_p2p::NetworkCommand>,
    peer: libp2p::PeerId,
    expected_tip_height: u64,
    expected_tip_hash: [u8; 32],
    pending_segment_ids: &mut std::collections::HashSet<u16>,
    segment_queue: &mut std::collections::VecDeque<u16>,
) {
    while pending_segment_ids.len() < MAX_INFLIGHT_SEGMENTS {
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
    wallet_operation_gate: &WalletOperationGate,
    external_mining_attempts: &ExternalMiningAttemptInvalidator,
) -> Result<AppliedVerifiedSnapshot, String> {
    if history_step.height != manifest.tip_height || history_step.block_hash != manifest.tip_hash {
        drop_verified_history_step(history_step);
        return Err("HistoryStep authority does not match snapshot manifest".into());
    }
    let snapshot_height = manifest.tip_height;
    let segment_count = staging.descriptors().len();
    let VerifiedHistoryStepSnapshot {
        boundary,
        mut headers,
        inbound_memory_permit,
        ..
    } = history_step;

    // Global order for operations that can replace the active wallet cache:
    // wallet_operation_gate -> mempool snapshot/view -> chain -> SharedWallet.
    // Keep this single acquisition across the atomic state install and wallet
    // reload. None of those helpers may enter wallet RPC code that acquires
    // the same gate.
    let wallet_operation = wallet_operation_gate.lock().await;
    let state_install_started = Instant::now();
    let install_chain = Arc::clone(chain);
    let result = tokio::task::spawn_blocking(move || {
        // Keep the verified terminal capability and its process-global inbound
        // charge alive through the atomic HistoryStep/snapshot commit.
        let inbound_memory_permit = inbound_memory_permit;
        let mut ctx = install_chain.blocking_write();
        if let Err(error) = ctx.apply_staged_state_snapshot(&staging, &boundary, &mut headers) {
            drop(ctx);
            let _ = headers.discard();
            return Err(format!("apply authenticated state snapshot: {error:?}"));
        }
        let view = ChainView::from_mdbx(&ctx);
        let height = ctx.tip_height();
        drop(ctx);
        // The atomic MDBX commit now owns the state; release temporary files
        // before constructing consumers of the new durable view.
        drop(staging);
        drop(boundary);
        drop(inbound_memory_permit);
        if let Err(error) = headers.discard() {
            tracing::warn!(err = %error, "committed snapshot header staging cleanup deferred");
        }
        Ok::<_, String>((height, view))
    })
    .await
    .map_err(|error| format!("snapshot install worker panicked: {error}"))?
    .map_err(|error| format!("failed to apply verified state snapshot: {error}"))?;

    let (applied_height, view) = result;
    external_mining_attempts.invalidate_for_tip(applied_height, view.tip_hash);
    mempool.on_new_block(&[], applied_height, view).await;

    // Establish the exact active-owner cache at the installed snapshot boundary.
    if let Err(error) = rescan_wallet_from_chain(wallet, chain, mempool, "snapshot sync").await {
        wallet::invalidate_active_cache(wallet);
        return Err(format!(
            "snapshot applied but active-wallet reload failed: {error}"
        ));
    }

    tracing::info!(
        snapshot_height,
        segments = segment_count,
        "snapshot boundary fully applied"
    );
    drop(wallet_operation);
    let state_install_elapsed = state_install_started.elapsed();
    Ok(AppliedVerifiedSnapshot {
        height: snapshot_height,
        state_install_elapsed,
    })
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
            "  {} state is {fill_pct:.1}% full \u{2014} expansion at 75%",
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
