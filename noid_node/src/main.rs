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
//! 8. Start background local finalized-coverage updater
//! 9. Shutdown on Ctrl-C

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
#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

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
    encoded_segment_len_for_eff_log, MdbxChainContext, SnapshotSegmentDescriptor,
};
use noid_mempool::{AsyncMempool, ChainView, MempoolConfig};
use noid_miner::{BlockMiner, MinerConfig};
use noid_node::snapshot_header_staging::{
    CanonicalHeaderBoundary, SelectedTerminalHeaderBoundary, SnapshotHeaderStaging,
    VerifiedSnapshotHeaderStaging, MAX_STAGED_HEADER_BATCH,
};
use noid_p2p::{NetworkEvent, P2PNetwork};
use noid_rpc::{start_rpc_server, WalletOperationGate};

struct ProvedBlockCandidate {
    block: noid_chain::block::Block,
    block_bytes_len: usize,
    block_proof_bytes: Vec<u8>,
    block_auth_sidecar_bytes: Vec<u8>,
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
    block: noid_chain::block::Block,
    block_bytes_len: usize,
    block_proof_bytes: Vec<u8>,
    block_auth_sidecar_bytes: Vec<u8>,
    received_at: Instant,
}

impl OrphanBlock {
    fn from_candidate(candidate: ProvedBlockCandidate) -> Self {
        let ProvedBlockCandidate {
            block,
            block_bytes_len,
            block_proof_bytes,
            block_auth_sidecar_bytes,
        } = candidate;
        Self {
            block,
            block_bytes_len,
            block_proof_bytes,
            block_auth_sidecar_bytes,
            received_at: Instant::now(),
        }
    }

    fn into_candidate(self) -> ProvedBlockCandidate {
        ProvedBlockCandidate {
            block: self.block,
            block_bytes_len: self.block_bytes_len,
            block_proof_bytes: self.block_proof_bytes,
            block_auth_sidecar_bytes: self.block_auth_sidecar_bytes,
        }
    }

    fn retained_bytes(&self) -> usize {
        self.block_bytes_len
            .saturating_add(self.block_proof_bytes.len())
            .saturating_add(self.block_auth_sidecar_bytes.len())
    }
}

fn gap_requires_snapshot_sync(local_height: u64, peer_height: u64) -> bool {
    peer_height
        > local_height.saturating_add(noid_chain::consensus::params::RECENT_BLOCK_RETENTION_DEPTH)
}

/// A release build embeds this authority independently of the local artifact.
/// Until a digest is provisioned, deep snapshot admission fails closed while
/// recent full-block synchronization remains available.
const SELECTED_RECURSIVE_REGISTRY_RELEASE_DIGEST_HEX: Option<&str> =
    option_env!("NOID_SELECTED_RECURSIVE_REGISTRY_RELEASE_DIGEST");
const SELECTED_RECURSIVE_ARTIFACT_DIRECTORY: &str = "selected-recursive";

#[derive(Clone)]
struct SelectedHistoryVerifierArtifacts {
    root: PathBuf,
    registry_digest: [u8; 32],
}

const MAX_TRACKED_RELAY_TERMINAL_PEERS: usize = 128;
const REMOTE_SELECTED_HISTORY_REQUEST_TIMEOUT: std::time::Duration =
    std::time::Duration::from_secs(12);
const REMOTE_SELECTED_HISTORY_REQUEST_INTERVAL: std::time::Duration =
    std::time::Duration::from_secs(2);

/// A fixed-capacity rotation of peers eligible for relay terminal imports.
/// It is deliberately a compact control-plane collection: proof bytes are
/// owned only by the single pending response/verifier state below.
#[derive(Default)]
struct BoundedRelayTerminalPeers {
    peers: std::collections::VecDeque<libp2p::PeerId>,
}

impl BoundedRelayTerminalPeers {
    fn insert(&mut self, peer: libp2p::PeerId) -> bool {
        if self.peers.contains(&peer) {
            return true;
        }
        if self.peers.len() == MAX_TRACKED_RELAY_TERMINAL_PEERS {
            let _ = self.peers.pop_front();
            self.peers.push_back(peer);
            return false;
        }
        self.peers.push_back(peer);
        true
    }

    fn remove(&mut self, peer: &libp2p::PeerId) {
        self.peers.retain(|candidate| candidate != peer);
    }

    fn next_rotated(&mut self) -> Option<libp2p::PeerId> {
        let peer = self.peers.pop_front()?;
        self.peers.push_back(peer);
        Some(peer)
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.peers.len()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RemoteSelectedHistoryRequestKey {
    token: u64,
    peer: libp2p::PeerId,
    height: u64,
    block_hash: [u8; 32],
}

impl RemoteSelectedHistoryRequestKey {
    fn matches_response(&self, peer: libp2p::PeerId, height: u64, block_hash: [u8; 32]) -> bool {
        self.peer == peer && self.height == height && self.block_hash == block_hash
    }
}

struct PendingRemoteSelectedHistoryRequest {
    key: RemoteSelectedHistoryRequestKey,
    requested_at: Instant,
}

#[derive(Clone, Copy)]
struct RelaySelectedHistoryImportTarget {
    height: u64,
    block_hash: [u8; 32],
    epoch_anchor_height: u64,
    epoch_anchor_hash: [u8; 32],
    tier: noid_chain::storage::RecursiveProofJobTier,
    boundary: SelectedTerminalHeaderBoundary,
}

struct VerifiedRemoteSelectedHistoryTerminal {
    target: RelaySelectedHistoryImportTarget,
    terminal_package_bytes: Vec<u8>,
    inbound_memory_permit: Option<Arc<tokio::sync::OwnedSemaphorePermit>>,
}

struct RemoteSelectedHistoryVerificationCompletion {
    key: RemoteSelectedHistoryRequestKey,
    result: Result<VerifiedRemoteSelectedHistoryTerminal, String>,
}

fn selected_history_verifier_artifacts(
    data_dir: &Path,
) -> Result<Option<SelectedHistoryVerifierArtifacts>, String> {
    let Some(encoded) = SELECTED_RECURSIVE_REGISTRY_RELEASE_DIGEST_HEX else {
        return Ok(None);
    };
    if encoded.len() != 64 {
        return Err("embedded selected-recursive registry digest must be exactly 32 bytes".into());
    }
    let mut registry_digest = [0u8; 32];
    hex::decode_to_slice(encoded, &mut registry_digest).map_err(|error| {
        format!("embedded selected-recursive registry digest is invalid: {error}")
    })?;
    Ok(Some(SelectedHistoryVerifierArtifacts {
        root: data_dir.join(SELECTED_RECURSIVE_ARTIFACT_DIRECTORY),
        registry_digest,
    }))
}

struct SelectedHistoryWorkerRuntime {
    cancelled: Arc<std::sync::atomic::AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
    stopped: tokio::sync::oneshot::Receiver<()>,
}

impl SelectedHistoryWorkerRuntime {
    fn signal_stop(&self) {
        self.cancelled
            .store(true, std::sync::atomic::Ordering::Release);
        if let Some(thread) = &self.thread {
            thread.thread().unpark();
        }
    }

    async fn shutdown(mut self) {
        self.signal_stop();
        let stopped =
            tokio::time::timeout(std::time::Duration::from_secs(2), &mut self.stopped).await;
        match stopped {
            Ok(Ok(())) => {
                if let Some(thread) = self.thread.take() {
                    match thread.join() {
                        Ok(()) => tracing::info!("selected-history worker exited cleanly"),
                        Err(_) => tracing::warn!("selected-history worker thread panicked"),
                    }
                }
            }
            Ok(Err(_)) => tracing::warn!("selected-history worker stopped without completion"),
            Err(_) => tracing::warn!(
                "selected-history worker is inside a proof phase; process shutdown will release MDBX safely"
            ),
        }
    }
}

fn start_selected_history_worker(
    chain: Arc<RwLock<MdbxChainContext>>,
    store: noid_chain::storage::MdbxStore,
    artifacts: SelectedHistoryVerifierArtifacts,
) -> Result<SelectedHistoryWorkerRuntime, String> {
    // Fail at startup, under the 64 MiB terminal-verifier envelope, if the
    // externally pinned release registry is absent or malformed. The compact
    // validation copy is dropped before the durable worker starts polling.
    let registry_store =
        noid_miner::LocalSelectedRecursiveClassRegistryStore::new(artifacts.root.clone());
    let mut registry_admission = noid_miner::begin_selected_history_terminal_verification_session()
        .map_err(|error| format!("selected-history registry admission failed: {error}"))?;
    registry_admission
        .load_pinned_registry(&registry_store, artifacts.registry_digest)
        .map_err(|error| format!("selected-history release registry rejected: {error}"))?;
    drop(registry_admission);

    let matrix_source = noid_miner::LocalSelectedRecursiveMatrixSource::new(artifacts.root.clone());
    let mut worker = selected_history_worker::SelectedHistoryProverWorker::new(
        store,
        registry_store,
        artifacts.registry_digest,
        matrix_source,
    );
    let cancelled = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let worker_cancelled = Arc::clone(&cancelled);
    let (stopped_tx, stopped) = tokio::sync::oneshot::channel();
    let thread = std::thread::Builder::new()
        .name("selected-history-prover".into())
        .spawn(move || {
            use selected_history_worker::{
                SelectedHistoryWorkerBackoff, SelectedHistoryWorkerOutcome,
            };

            while !worker_cancelled.load(std::sync::atomic::Ordering::Acquire) {
                let outcome = worker.run_once(
                    || {
                        let context = chain.blocking_read();
                        context
                            .state
                            .durable_metadata_clone()
                            .ok_or("chain state is outside a durable metadata boundary")
                    },
                    &worker_cancelled,
                );
                let delay = match outcome {
                    SelectedHistoryWorkerOutcome::Completed(identity) => {
                        tracing::info!(
                            height = identity.height,
                            hash = %hex::encode(identity.block_hash),
                            "selected-history terminal promoted"
                        );
                        None
                    }
                    SelectedHistoryWorkerOutcome::Backoff {
                        job,
                        reason: SelectedHistoryWorkerBackoff::Cancelled,
                        release_error,
                    } => {
                        if let Some(error) = release_error {
                            tracing::warn!(job = ?job, err = %error, "selected-history cancellation release failed");
                        }
                        break;
                    }
                    SelectedHistoryWorkerOutcome::Backoff {
                        job,
                        reason,
                        release_error,
                    } => {
                        if let Some(error) = release_error {
                            tracing::warn!(job = ?job, err = %error, "selected-history durable release failed");
                        }
                        match &reason {
                            SelectedHistoryWorkerBackoff::Idle => {}
                            SelectedHistoryWorkerBackoff::MemoryPressure {
                                required_mib,
                                available_mib,
                            } => tracing::debug!(
                                required_mib,
                                available_mib,
                                "selected-history worker waiting for proof memory"
                            ),
                            SelectedHistoryWorkerBackoff::RetryableFailure { phase, detail } => {
                                tracing::warn!(job = ?job, phase, detail, "selected-history job deferred")
                            }
                            SelectedHistoryWorkerBackoff::Panicked => {
                                tracing::error!(job = ?job, "selected-history proof phase panicked")
                            }
                            SelectedHistoryWorkerBackoff::Cancelled => unreachable!(),
                        }
                        Some(match reason {
                            SelectedHistoryWorkerBackoff::Idle => {
                                std::time::Duration::from_secs(2)
                            }
                            SelectedHistoryWorkerBackoff::MemoryPressure { .. } => {
                                std::time::Duration::from_secs(5)
                            }
                            SelectedHistoryWorkerBackoff::RetryableFailure { .. } => {
                                std::time::Duration::from_secs(10)
                            }
                            SelectedHistoryWorkerBackoff::Panicked => {
                                std::time::Duration::from_secs(30)
                            }
                            SelectedHistoryWorkerBackoff::Cancelled => unreachable!(),
                        })
                    }
                };
                if let Some(delay) = delay {
                    std::thread::park_timeout(delay);
                }
            }
            let _ = stopped_tx.send(());
        })
        .map_err(|error| format!("spawn selected-history prover thread: {error}"))?;

    Ok(SelectedHistoryWorkerRuntime {
        cancelled,
        thread: Some(thread),
        stopped,
    })
}

mod config;
#[allow(dead_code)]
mod selected_history_worker;
mod wallet;
use config::NodeConfig;
use wallet::{SharedWallet, WalletHandle, WalletState};

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

/// Operating mode for the full node.
///
/// Exactly one mode must be active. The default is `relay`.
#[derive(Debug, Clone, PartialEq, Eq, clap::ValueEnum, Default)]
pub enum NodeMode {
    /// Relay node (default). No mining, no block-template serving.
    /// Verifies all blocks (proofs + PoW) and serves recent block/header sync.
    /// Snapshot sync uses the same manifest/proof pipeline that the O(1)
    /// verifier will authorize.
    #[default]
    Relay,
    /// Internal miner. Runs built-in PoW + block-certificate assembly in parallel.
    /// Blocks external miner (extminer) access to the block-template API.
    Miner,
    /// External miner mode. Serves `getBlockTemplate` / `submitBlock`
    /// to `noid-extminer` clients. Requires `--mining-key`. Internal
    /// PoW miner is disabled.
    Extminer,
}

#[derive(Parser, Debug)]
#[command(
    name = "paranoid",
    about = "Paranoid full node daemon — proof-native UTXO blockchain",
    version = env!("CARGO_PKG_VERSION"),
    long_about = "Run a Paranoid full node.\n\nExample:\n  paranoid --mode miner --data-dir ~/.paranoid\n  paranoid --mode relay --p2p-listen 0.0.0.0:9301 --seed 1.2.3.4:9301",
)]
struct Cli {
    /// Path to TOML config file (optional).
    #[arg(short = 'c', long, value_name = "FILE")]
    config: Option<PathBuf>,

    /// Node operating mode.
    ///
    /// relay    — full node, no mining (default)
    /// miner    — internal PoW + block-certificate assembly; blocks extminer access
    /// extminer — serves block templates to noid-extminer; requires --mining-key
    #[arg(long, value_enum, default_value_t = NodeMode::Relay)]
    mode: NodeMode,

    /// Bootstrap a new network: start mining immediately without waiting for peers.
    /// Use ONLY for the very first node on a fresh network.
    #[arg(long)]
    genesis: bool,

    /// Miner coinbase address (32-byte hex). Defaults to the wallet's ACTIVE address.
    #[arg(long, value_name = "HEX")]
    miner_address: Option<String>,

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

    /// Internal PoW mining threads for --mode miner. If omitted, uses a balanced split.
    #[arg(long = "mining-threads", value_name = "N")]
    mining_threads: Option<usize>,

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
    /// Use case: infrastructure pool where the node provides block-certificate assembly and P2P
    /// relay, but each miner receives block rewards directly to their own address.
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

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // --- Tracing ---
    // Log format: HH:MM:SS LEVEL target: message
    //
    // libp2p internal chatter is suppressed by default. Pass --log debug
    // or RUST_LOG=libp2p=debug to see everything.
    let log_filter = EnvFilter::new(&cli.log)
        // libp2p internals — suppress unless user asks for debug
        .add_directive("libp2p_swarm=warn".parse().unwrap_or_default())
        .add_directive("libp2p_tcp=warn".parse().unwrap_or_default())
        .add_directive("libp2p_noise=warn".parse().unwrap_or_default())
        .add_directive("libp2p_yamux=warn".parse().unwrap_or_default())
        .add_directive("libp2p_gossipsub=error".parse().unwrap_or_default())
        .add_directive("libp2p_request_response=warn".parse().unwrap_or_default())
        .add_directive("libp2p_identify=warn".parse().unwrap_or_default())
        .add_directive("libp2p_ping=warn".parse().unwrap_or_default())
        .add_directive("multiaddr=warn".parse().unwrap_or_default());

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
    // allow_custom_coinbase only makes sense with extminer mode
    if cli.allow_custom_coinbase && cli.mode != NodeMode::Extminer {
        anyhow::bail!("--allow-custom-coinbase requires --mode extminer");
    }
    if cli.mode != NodeMode::Miner && cli.mining_threads.is_some() {
        anyhow::bail!("--mining-threads is only valid with --mode miner");
    }
    let selected_history_prover_enabled = matches!(&cli.mode, NodeMode::Miner | NodeMode::Extminer);
    let remote_selected_history_import_enabled = cli.mode == NodeMode::Relay;

    // --- Network ---
    let net = NetworkConfig::mainnet();
    tracing::debug!(network = %net.kind, "daemon starting");

    // --- Config file (optional) ---
    let config_path = cli
        .config
        .unwrap_or_else(|| expand_tilde(&PathBuf::from("~/.paranoid/paranoid.toml")));
    let mut cfg = load_config(&config_path).unwrap_or_else(|| {
        tracing::debug!("no config file, using defaults");
        NodeConfig::default()
    });

    // CLI flags override config.
    if let Some(dir) = cli.data_dir {
        cfg.storage.path = dir;
    }
    // The CLI mode is authoritative: relay/extminer never start the internal
    // miner even if a stale config file has mining.enabled=true.
    cfg.mining.enabled = cli.mode == NodeMode::Miner;
    if let Some(addr) = cli.miner_address {
        cfg.mining.miner_address = addr;
    }
    if let Some(mining_threads) = cli.mining_threads {
        cfg.mining.mining_threads = mining_threads;
    }
    if cli.mode == NodeMode::Miner {
        let available = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);
        if available > 1 && cfg.mining.mining_threads > 0 && cfg.mining.mining_threads >= available
        {
            anyhow::bail!(
                "--mining-threads must be less than available CPU cores ({available}) so the node/prover has capacity"
            );
        }
    }
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
    // Receiver snapshots are transactional scratch data.  A crash can leave
    // sealed segment files behind, but they are never authoritative and must
    // not survive into a new sync session.
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
    let selected_history_verifier =
        selected_history_verifier_artifacts(&data_dir).map_err(anyhow::Error::msg)?;
    if selected_history_verifier.is_none() {
        tracing::warn!(
            "selected-history snapshot admission disabled: release registry authority is not embedded"
        );
    }

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

    // Sync-ready notifier: fires when the chain has caught up to peers.
    let sync_ready = Arc::new(tokio::sync::Notify::new());
    {
        let ctx = chain.read().await;
        let h = ctx.tip_height();
        let ts = ctx.tip_header().timestamp;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if h > 0 && ts > 0 && now.saturating_sub(ts) < 60 * 3 {
            sync_ready.notify_one();
            tracing::info!(height = h, "chain state is current");
        }
    }

    // --- Mempool ---
    let view = ChainView::from_mdbx(&*chain.read().await);
    let mempool = AsyncMempool::new(view, MempoolConfig::default());
    tracing::debug!("mempool ready");

    // --- Wallet ---
    let wallet_path = data_dir.join("wallet.key");
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
        let (active_index, next_index, owner) = {
            let guard = shared_wallet.lock().unwrap();
            match guard.as_ref() {
                None => unreachable!("wallet just initialized"),
                Some(w) => (w.active_index, w.next_index, w.active_address().0),
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
                    false,
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
            "wallet active address loaded"
        );
    }
    let wallet = WalletHandle::new(shared_wallet.clone());
    let wallet_operation_gate = Arc::new(tokio::sync::Mutex::new(()));

    // --- P2P Network ---
    let p2p_listen_str = cli.p2p_listen.unwrap_or_else(|| {
        cfg.network
            .listen
            .clone()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| net.default_p2p_listen())
    });
    // Convert HOST:PORT to libp2p Multiaddr transparently.
    // Users specify --p2p-listen 0.0.0.0:9301; libp2p gets /ip4/0.0.0.0/tcp/9301.
    let listen_addr: libp2p::Multiaddr =
        ip_port_to_multiaddr(&p2p_listen_str).context("--p2p-listen")?;

    let topics = noid_p2p::protocol::NetworkTopics::for_network_cfg(&net);
    let (p2p, _p2p_task) = P2PNetwork::start(
        listen_addr.clone(),
        chain.clone(),
        mempool.clone(),
        topics,
        data_dir.clone(),
    );
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

    // --genesis flag: bootstrap mode for the very first node on a new network.
    // Fires sync_ready immediately so the miner starts without waiting for peers.
    // All other nodes sync automatically when they connect to a genesis node.
    if cli.genesis {
        tracing::debug!("genesis mode: firing sync_ready immediately");
        sync_ready.notify_one();
    }

    // Background P2P event handler.
    let p2p_chain = chain.clone();
    let p2p_mempool = mempool.clone();
    let p2p_wallet = shared_wallet.clone();
    let p2p_events = p2p.subscribe();
    let p2p_cmd_for_events = p2p.cmd_tx.clone();
    let p2p_sync_ready = Arc::clone(&sync_ready);
    let p2p_wallet_operation_gate = Arc::clone(&wallet_operation_gate);
    let p2p_snapshot_staging_root = snapshot_staging_root.clone();
    let p2p_selected_history_verifier = selected_history_verifier.clone();
    tokio::spawn(async move {
        handle_p2p_events(
            p2p_events,
            p2p_chain,
            p2p_mempool,
            p2p_wallet,
            p2p_cmd_for_events,
            p2p_sync_ready,
            p2p_wallet_operation_gate,
            p2p_snapshot_staging_root,
            p2p_selected_history_verifier,
            remote_selected_history_import_enabled,
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
    let rpc_addr_str = cli.rpc_listen.unwrap_or_else(|| {
        cfg.rpc
            .listen
            .clone()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| net.default_rpc_listen())
    });
    let rpc_listen: std::net::SocketAddr = rpc_addr_str.parse().context("parse RPC listen")?;
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
            mining_threads: cfg.mining.mining_threads,
            ..Default::default()
        };
        let (mut miner, mut miner_rx) = BlockMiner::new(
            miner_cfg,
            mempool.clone(),
            chain.clone(),
            Arc::clone(&sync_ready),
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
                        block_bytes,
                        block_proof_bytes,
                        block_auth_sidecar_bytes,
                        height,
                        hash,
                        n_txs,
                        ..
                    }) => {
                        tracing::info!(
                            height,
                            hash = %hex::encode(hash),
                            txs = n_txs,
                            "broadcast block"
                        );
                        // Announce block to all peers.  Small blocks (< 1 MB)
                        // are inlined in gossip — no round-trip.  Large blocks
                        // fall back to compact header + pull.
                        let header_bytes = {
                            let mut buf = Vec::new();
                            if let Ok(block) = noid_chain::block::Block::from_bytes(&block_bytes) {
                                block.header.encode(&mut buf);
                            }
                            buf
                        };
                        let _ = p2p_block_relay
                            .send(noid_p2p::NetworkCommand::AnnounceBlock {
                                height,
                                hash,
                                header_bytes,
                                block_bytes,
                                block_proof_bytes,
                                block_auth_sidecar_bytes,
                            })
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

    // Only explicit prover roles run the 8 GiB Block+Link worker. Relay nodes
    // verify/import compact terminals but never build recursive proofs.
    let selected_history_worker_runtime = if selected_history_prover_enabled {
        let artifacts = selected_history_verifier.clone().ok_or_else(|| {
            anyhow::anyhow!(
                "prover mode requires an embedded NOID_SELECTED_RECURSIVE_REGISTRY_RELEASE_DIGEST"
            )
        })?;
        let store = {
            let context = chain.read().await;
            context.store.clone()
        };
        Some(
            start_selected_history_worker(Arc::clone(&chain), store, artifacts)
                .map_err(anyhow::Error::msg)?,
        )
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
        let reward = block_reward(log_slots) as f64 / 1_000_000.0;

        let history_proof_height = ctx
            .store
            .get_selected_history_coverage()
            .ok()
            .flatten()
            .map(|coverage| coverage.height);
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
            reward,
            history_proof_height,
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
        tracing::info!("miner stop flags set");
    }
    if let Some(runtime) = &selected_history_worker_runtime {
        runtime.signal_stop();
    }

    // 2. Stop RPC server (no new requests accepted).
    let _ = rpc_handle.stop();

    // 3. Wait for the miner task to exit cleanly. The miner checks `stopped`
    //    at the top of each loop iteration; `cancel_pow` ensures the current
    //    PoW chunk finishes quickly (~100ms at genesis difficulty). We give
    //    2 seconds before giving up — MDBX is crash-safe regardless.
    if let Some((task, _, _)) = miner_handle {
        match tokio::time::timeout(std::time::Duration::from_secs(2), task).await {
            Ok(Ok(_)) => tracing::info!("miner task exited cleanly"),
            Ok(Err(e)) if e.is_cancelled() => tracing::debug!("miner task cancelled"),
            Ok(Err(e)) => tracing::warn!("miner task error: {e}"),
            Err(_) => tracing::warn!(
                "miner task did not exit in 2s — MDBX is crash-safe, continuing shutdown"
            ),
        }
    }
    if let Some(runtime) = selected_history_worker_runtime {
        runtime.shutdown().await;
    }

    tracing::info!("goodbye — MDBX flushed on drop");
    Ok(())
}

// ---------------------------------------------------------------------------
// P2P event handler
// ---------------------------------------------------------------------------

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
    RequestProof,
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
        return Ok(SnapshotHeaderNextAction::RequestProof);
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

struct VerifiedSelectedHistorySnapshot {
    height: u64,
    block_hash: [u8; 32],
    tier: noid_chain::storage::RecursiveProofJobTier,
    terminal_package_bytes: Vec<u8>,
    verified_headers: VerifiedSnapshotHeaderStaging,
    /// The exact inbound allocation remains charged until the terminal bytes
    /// have entered the same MDBX transaction as the snapshot state.
    inbound_memory_permit: Option<Arc<tokio::sync::OwnedSemaphorePermit>>,
}

fn validate_snapshot_staged_header_boundary(
    manifest: &noid_p2p::protocol::GetStateManifestResponse,
    boundary: &SelectedTerminalHeaderBoundary,
    minimum_chainwork: &[u8; 32],
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
    if noid_chain::work_gt(minimum_chainwork, &boundary.cumulative_chainwork) {
        return Err("snapshot chainwork below minimum snapshot work floor".into());
    }
    let expected_epoch_height = (manifest.tip_height
        / noid_chain::consensus::params::TX_EPOCH_BLOCKS)
        * noid_chain::consensus::params::TX_EPOCH_BLOCKS;
    if boundary.epoch_anchor_header.height != expected_epoch_height {
        return Err("snapshot staged transaction-epoch anchor has wrong height".into());
    }
    Ok(())
}

fn verify_snapshot_selected_history_terminal(
    expected_height: u64,
    expected_hash: [u8; 32],
    terminal_package_bytes: &[u8],
    boundary: &SelectedTerminalHeaderBoundary,
    artifacts: &SelectedHistoryVerifierArtifacts,
) -> Result<noid_chain::storage::RecursiveProofJobTier, String> {
    if terminal_package_bytes.is_empty() {
        return Err("snapshot selected-history terminal missing".into());
    }
    let package = noid_recursive::decode_selected_history_terminal_package(&terminal_package_bytes)
        .map_err(|error| format!("snapshot selected-history terminal decode failed: {error}"))?;
    if package.terminal_height() != expected_height {
        return Err("snapshot selected-history terminal height does not match manifest".into());
    }
    if package.terminal_hash() != expected_hash {
        return Err("snapshot selected-history terminal hash does not match manifest".into());
    }
    let tier = match package.canonical_tip_tier() {
        8 => noid_chain::storage::RecursiveProofJobTier::B8,
        32 => noid_chain::storage::RecursiveProofJobTier::B32,
        64 => noid_chain::storage::RecursiveProofJobTier::B64,
        255 => noid_chain::storage::RecursiveProofJobTier::B255,
        actual => {
            return Err(format!(
                "snapshot selected-history terminal has unsupported tier {actual}"
            ));
        }
    };

    // Admission is acquired before the release-pinned registry is opened and
    // retained through one-at-a-time seekable matrix verification.
    let registry_store =
        noid_miner::LocalSelectedRecursiveClassRegistryStore::new(artifacts.root.clone());
    let mut matrix_source =
        noid_miner::LocalSelectedRecursiveMatrixSource::new(artifacts.root.clone());
    noid_miner::verify_selected_history_terminal_pinned_governed(
        &package,
        &registry_store,
        artifacts.registry_digest,
        &boundary.tip_header,
        &boundary.epoch_anchor_header,
        &mut matrix_source,
    )
    .map_err(|error| format!("snapshot selected-history terminal rejected: {error}"))?;

    Ok(tier)
}

/// Local admission policy is deliberately checked at the last fixed-width
/// boundary before expensive terminal verification.  Historical header
/// validation is timeless, but a snapshot or relay must not make a locally
/// far-future tip authoritative merely because its recursive proof is valid.
fn validate_selected_terminal_tip_future_drift(
    boundary: &SelectedTerminalHeaderBoundary,
    local_time: u64,
) -> Result<(), String> {
    noid_chain::consensus::validate_future_drift(boundary.tip_header.timestamp, local_time)
        .map_err(|error| format!("selected-history target tip exceeds local future drift: {error}"))
}

/// Select the relay's exact durable hard-finalized terminal target without
/// allocating any proof payload. The chain read guard held by the caller
/// serializes this fixed-width snapshot with local canonical mutation.
fn relay_selected_history_import_target(
    ctx: &MdbxChainContext,
) -> Result<Option<RelaySelectedHistoryImportTarget>, String> {
    let finalized = ctx.finalized_checkpoint();
    if finalized.height == 0 {
        return Ok(None);
    }
    relay_selected_history_import_target_at(ctx, finalized.height, finalized.hash)
}

/// Capture one previously requested finalized boundary. Finality may advance
/// while the response is in flight; the old boundary remains admissible as
/// long as it is still canonical, hard-finalized and ahead of coverage.
fn relay_selected_history_import_target_at(
    ctx: &MdbxChainContext,
    height: u64,
    expected_hash: [u8; 32],
) -> Result<Option<RelaySelectedHistoryImportTarget>, String> {
    let finalized = ctx.finalized_checkpoint();
    if height == 0 || height > finalized.height {
        return Ok(None);
    }
    let finalized_header = ctx
        .store
        .get_header(finalized.height)
        .map_err(|error| format!("load current finalized header: {error}"))?
        .ok_or_else(|| "current finalized header is missing".to_owned())?;
    if finalized_header.height != finalized.height
        || noid_chain::hash_block_header(&finalized_header) != finalized.hash
    {
        return Err("current hard-finalized checkpoint is not canonical".into());
    }

    if let Some(coverage) = ctx
        .store
        .get_selected_history_coverage()
        .map_err(|error| format!("load selected-history coverage: {error}"))?
    {
        if coverage.height > ctx.tip_height() {
            return Err("selected-history coverage exceeds the canonical tip".into());
        }
        let coverage_header = ctx
            .store
            .get_header(coverage.height)
            .map_err(|error| format!("load selected-history coverage header: {error}"))?
            .ok_or_else(|| "selected-history coverage header is missing".to_owned())?;
        if coverage_header.height != coverage.height
            || noid_chain::hash_block_header(&coverage_header) != coverage.block_hash
        {
            return Err("selected-history coverage is not canonical".into());
        }
        if coverage.height >= height {
            return Ok(None);
        }
    }

    let tip_header = ctx
        .store
        .get_header(height)
        .map_err(|error| format!("load finalized selected-history header: {error}"))?
        .ok_or_else(|| "finalized selected-history header is missing".to_owned())?;
    let block_hash = noid_chain::hash_block_header(&tip_header);
    if tip_header.height != height || block_hash != expected_hash {
        return Err("hard-finalized selected-history target is not canonical".into());
    }
    let job = ctx
        .store
        .get_recursive_proof_job(height)
        .map_err(|error| format!("load finalized selected-history job: {error}"))?
        .ok_or_else(|| "hard-finalized selected-history target job is missing".to_owned())?;
    if job.block_hash != block_hash
        || !matches!(
            job.state,
            noid_chain::storage::RecursiveProofJobState::Pending
                | noid_chain::storage::RecursiveProofJobState::Complete
        )
    {
        return Err("hard-finalized selected-history target job is not importable".into());
    }

    let epoch_anchor_height = (height / noid_chain::consensus::params::TX_EPOCH_BLOCKS)
        * noid_chain::consensus::params::TX_EPOCH_BLOCKS;
    let epoch_anchor_header = ctx
        .store
        .get_header(epoch_anchor_height)
        .map_err(|error| format!("load selected-history epoch anchor: {error}"))?
        .ok_or_else(|| "selected-history epoch anchor is missing".to_owned())?;
    let epoch_anchor_hash = noid_chain::hash_block_header(&epoch_anchor_header);
    if epoch_anchor_header.height != epoch_anchor_height {
        return Err("selected-history epoch anchor has the wrong height".into());
    }
    let cumulative_chainwork = ctx
        .store
        .get_chain_work(height)
        .map_err(|error| format!("load finalized selected-history chainwork: {error}"))?
        .ok_or_else(|| "finalized selected-history chainwork is missing".to_owned())?;

    Ok(Some(RelaySelectedHistoryImportTarget {
        height,
        block_hash,
        epoch_anchor_height,
        epoch_anchor_hash,
        tier: job.tier,
        boundary: SelectedTerminalHeaderBoundary {
            tip_header,
            tip_hash: block_hash,
            cumulative_chainwork,
            epoch_anchor_header,
        },
    }))
}

/// Recheck the fixed canonical inputs after expensive verification. Storage
/// performs the same checks atomically again during import, closing the small
/// interval between this read-only check and the write transaction.
fn relay_selected_history_target_still_importable(
    ctx: &MdbxChainContext,
    target: &RelaySelectedHistoryImportTarget,
) -> Result<bool, String> {
    if ctx.finalized_checkpoint().height < target.height {
        return Ok(false);
    }
    if let Some(coverage) = ctx
        .store
        .get_selected_history_coverage()
        .map_err(|error| format!("recheck selected-history coverage: {error}"))?
    {
        if coverage.height >= target.height {
            return Ok(false);
        }
    }
    let Some(tip_header) = ctx
        .store
        .get_header(target.height)
        .map_err(|error| format!("recheck selected-history target: {error}"))?
    else {
        return Ok(false);
    };
    if tip_header != target.boundary.tip_header
        || noid_chain::hash_block_header(&tip_header) != target.block_hash
    {
        return Ok(false);
    }
    let Some(epoch_anchor_header) = ctx
        .store
        .get_header(target.epoch_anchor_height)
        .map_err(|error| format!("recheck selected-history epoch anchor: {error}"))?
    else {
        return Ok(false);
    };
    if epoch_anchor_header != target.boundary.epoch_anchor_header
        || noid_chain::hash_block_header(&epoch_anchor_header) != target.epoch_anchor_hash
    {
        return Ok(false);
    }
    if ctx
        .store
        .get_chain_work(target.height)
        .map_err(|error| format!("recheck selected-history chainwork: {error}"))?
        != Some(target.boundary.cumulative_chainwork)
    {
        return Ok(false);
    }
    let Some(job) = ctx
        .store
        .get_recursive_proof_job(target.height)
        .map_err(|error| format!("recheck selected-history job: {error}"))?
    else {
        return Ok(false);
    };
    Ok(job.block_hash == target.block_hash
        && job.tier == target.tier
        && matches!(
            job.state,
            noid_chain::storage::RecursiveProofJobState::Pending
                | noid_chain::storage::RecursiveProofJobState::Complete
        ))
}

// ---------------------------------------------------------------------------
// Blocking-I/O helpers
// ---------------------------------------------------------------------------

fn accepted_block_certificate_record_bytes(
    acceptance_receipt: noid_block::BlockProofAcceptanceReceipt,
) -> Result<Vec<u8>, noid_block::FullValidationError> {
    let record =
        noid_block::accepted_block_certificate_record(acceptance_receipt).map_err(|e| {
            noid_block::FullValidationError::Consensus(
                noid_chain::consensus::ConsensusError::ShapeMismatch(format!(
                    "accepted-block certificate record build failed: {e}"
                )),
            )
        })?;
    Ok(bincode::serialize(&record).expect("AcceptedBlockCertificateRecord serializes"))
}

/// Owner-auth proof bytes this node already verified at mempool admission
/// for the block's transactions — the byte-exact fast path for AcceptBlock.
async fn preverified_authorization_bytes(
    mempool: &AsyncMempool,
    block: &noid_chain::block::Block,
) -> std::collections::HashMap<[u8; 32], Vec<u8>> {
    let hashes: Vec<_> = block
        .transactions
        .iter()
        .filter(|tx| !tx.body.is_coinbase)
        .map(|tx| tx.txid())
        .collect();
    if hashes.is_empty() {
        return std::collections::HashMap::new();
    }
    mempool.verified_authorization_proof_bytes(&hashes).await
}

/// Verify and apply a single P2P block off the tokio executor.
///
/// User-transaction blocks take the proof-native path: verify the full
/// exact `BlockProof` against the pre-state, apply the proven state transition,
/// then atomically commit to MDBX. Coinbase-only blocks carry no block proof.
/// `preverified_auth` holds mempool-verified proof bytes per tx body hash;
/// matching sidecar proofs skip cryptographic re-verification. The
/// history claim, detached proof material, and certificate record are committed
/// in the same MDBX transaction as the exact post-state.
async fn apply_p2p_block_offthread(
    chain: &Arc<RwLock<MdbxChainContext>>,
    wallet: &SharedWallet,
    candidate: ProvedBlockCandidate,
    local_time: u64,
    preverified_auth: std::collections::HashMap<[u8; 32], Vec<u8>>,
) -> Result<AppliedP2pBlock, (noid_chain::storage::MdbxContextError, ProvedBlockCandidate)> {
    let chain = chain.clone();
    let wallet = wallet.clone();
    tokio::task::spawn_blocking(move || {
        let mut ctx = chain.blocking_write();
        let apply_result = ctx.apply_next_block(
            &candidate.block,
            &candidate.block_proof_bytes,
            &candidate.block_auth_sidecar_bytes,
            local_time,
            |block,
             proof_bytes,
             auth_sidecar_bytes,
             parent,
             prev_timestamps,
             prev_active_counts,
             local_time,
             tx_epoch_anchor_id,
             anchor,
             state| {
                let auth_verifier = noid_block::PreverifiedAuthorizationVerifier {
                    verified_proof_bytes: &preverified_auth,
                };
                let tx_epoch = noid_block::BlockTxEpochContext {
                    expected_user_epoch_anchor_id: *tx_epoch_anchor_id,
                };
                let output = noid_block::accept_block_with_artifacts_with_auth_verifier(
                    block,
                    proof_bytes,
                    auth_sidecar_bytes,
                    parent,
                    prev_timestamps,
                    prev_active_counts,
                    local_time,
                    &tx_epoch,
                    anchor,
                    state,
                    &auth_verifier,
                )?;
                let post_validation = noid_block::accepted_block_post_validation_bundle(
                    block,
                    parent,
                    prev_timestamps,
                    prev_active_counts,
                    anchor,
                    proof_bytes,
                    auth_sidecar_bytes,
                    &output.artifacts,
                )?;
                let history_claim_bytes = bincode::serialize(&post_validation.history_claim_fields)
                    .expect("history claim fields serialize");
                let accepted_block_certificate_bytes =
                    accepted_block_certificate_record_bytes(post_validation.acceptance_receipt)?;
                Ok::<noid_chain::AppliedBlockValidation, noid_block::FullValidationError>(
                    noid_chain::AppliedBlockValidation::new(
                        output.state_root,
                        history_claim_bytes,
                        accepted_block_certificate_bytes,
                    ),
                )
            },
        );
        let hash = match apply_result {
            Ok(hash) => hash,
            Err(error) => return Err((error, candidate)),
        };
        // Keep the chain writer through the incremental wallet update. This
        // shares the same `chain -> wallet` order as account activation and
        // prevents an exact newer snapshot from receiving this delta twice.
        update_wallet_for_block(&wallet, &candidate.block);
        let height = candidate.block.header.height;
        let confirmed_tx_hashes = candidate
            .block
            .transactions
            .iter()
            .map(|tx| tx.txid())
            .collect();
        let view = ChainView::from_mdbx(&ctx);
        drop(ctx);
        // `candidate` (including proof and authorization sidecar buffers) is
        // dropped before this compact success value crosses back to async code.
        Ok(AppliedP2pBlock {
            block_hash: hash,
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
async fn apply_reorg_offthread(
    chain: &Arc<RwLock<MdbxChainContext>>,
    wallet: &SharedWallet,
    reserved_input_slots: std::collections::HashSet<u32>,
    reserved_output_slots: std::collections::HashSet<u32>,
    ancestor_height: u64,
    new_blocks: Vec<ProvedBlockCandidate>,
    local_time: u64,
) -> Result<
    AppliedReorg,
    (
        noid_chain::storage::MdbxContextError,
        Vec<ProvedBlockCandidate>,
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
        let replacement_payloads: Vec<_> = new_blocks
            .iter()
            .map(|candidate| {
                noid_chain::ReorgBlockPayload::new(
                    &candidate.block,
                    &candidate.block_proof_bytes,
                    &candidate.block_auth_sidecar_bytes,
                )
            })
            .collect();
        let result = ctx.apply_reorg_mdbx_with_applier(
            ancestor_height,
            &replacement_payloads,
            local_time,
            |ctx, candidate, block_local_time| {
                ctx.apply_next_block(
                    candidate.block,
                    candidate.block_proof_bytes,
                    candidate.block_auth_sidecar_bytes,
                    block_local_time,
                    |block,
                     proof_bytes,
                     auth_sidecar_bytes,
                     parent,
                     prev_timestamps,
                     prev_active_counts,
                     local_time,
                     tx_epoch_anchor_id,
                     anchor,
                     state| {
                        let tx_epoch = noid_block::BlockTxEpochContext {
                            expected_user_epoch_anchor_id: *tx_epoch_anchor_id,
                        };
                        let output = noid_block::accept_block_with_artifacts(
                            block,
                            proof_bytes,
                            auth_sidecar_bytes,
                            parent,
                            prev_timestamps,
                            prev_active_counts,
                            local_time,
                            &tx_epoch,
                            anchor,
                            state,
                        )?;
                        let post_validation = noid_block::accepted_block_post_validation_bundle(
                            block,
                            parent,
                            prev_timestamps,
                            prev_active_counts,
                            anchor,
                            proof_bytes,
                            auth_sidecar_bytes,
                            &output.artifacts,
                        )?;
                        let history_claim_bytes =
                            bincode::serialize(&post_validation.history_claim_fields)
                                .expect("history claim fields serialize");
                        let certificate_record_bytes = accepted_block_certificate_record_bytes(
                            post_validation.acceptance_receipt,
                        )?;
                        Ok::<noid_chain::AppliedBlockValidation, noid_block::FullValidationError>(
                            noid_chain::AppliedBlockValidation::new(
                                output.state_root,
                                history_claim_bytes,
                                certificate_record_bytes,
                            ),
                        )
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
                            let replacement_blocks: Vec<_> = replacement_payloads
                                .iter()
                                .map(|candidate| candidate.block)
                                .collect();
                            if let Err(error) = wallet::install_reorg_snapshot_and_artifacts(
                                &wallet,
                                active_index,
                                next_index,
                                owner,
                                snapshot,
                                &reserved_input_slots,
                                &reserved_output_slots,
                                &reorg.reclaimed_tx_hashes,
                                &replacement_blocks,
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
                let confirmed_tx_hashes = new_blocks
                    .iter()
                    .flat_map(|candidate| {
                        candidate.block.transactions.iter().map(|tx| tx.txid())
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
                drop(replacement_payloads);
                Err((error, new_blocks))
            }
        }
    })
    .await
    .expect("apply_reorg_mdbx panicked in spawn_blocking")
}

fn validate_p2p_block_proof_binding(
    block: &noid_chain::block::Block,
    block_proof_bytes: &[u8],
    block_auth_sidecar_bytes: &[u8],
) -> Result<(), String> {
    let has_user_txs = block.transactions.iter().any(|tx| !tx.body.is_coinbase);
    if !has_user_txs {
        noid_chain::block::validate_block_proof_binding(block, block_proof_bytes)
            .map_err(|e| format!("proof/header binding invalid: {e}"))?;
        if !block_auth_sidecar_bytes.is_empty() {
            return Err(
                "proof/header binding invalid: coinbase-only block has auth sidecar bytes"
                    .to_string(),
            );
        }
        return Ok(());
    }
    if block_proof_bytes.is_empty() {
        return Err(
            "proof/header binding invalid: user-transaction block is missing BlockProof bytes"
                .to_string(),
        );
    }
    if block_auth_sidecar_bytes.is_empty() {
        return Err("proof/header binding invalid: user-transaction block is missing BlockAuthSidecar bytes".to_string());
    }
    let proof: noid_block::BlockProof = bincode::deserialize(block_proof_bytes)
        .map_err(|e| format!("proof/header binding invalid: proof deserialize failed: {e}"))?;
    let user_txs = block
        .transactions
        .iter()
        .filter(|tx| !tx.body.is_coinbase)
        .count();
    if proof.meta.n_tx as usize != user_txs {
        return Err("proof/header binding invalid: BlockProof tx count mismatch".to_string());
    }
    let sidecar =
        noid_block::BlockAuthSidecar::from_bytes(block_auth_sidecar_bytes).map_err(|e| {
            format!("proof/header binding invalid: auth sidecar deserialize failed: {e}")
        })?;
    if sidecar.tx_auth.len() != user_txs {
        return Err("proof/header binding invalid: auth sidecar tx count mismatch".to_string());
    }
    Ok(())
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
        compare_manifest_fork_choice, gap_requires_snapshot_sync, snapshot_header_next_action,
        state_segment_response_matches_snapshot_boundary,
        validate_selected_terminal_tip_future_drift, validate_snapshot_header_batch_admission,
        validate_snapshot_staged_header_boundary, BoundedRelayTerminalPeers, OrphanBlock,
        ProvedBlockCandidate, RemoteSelectedHistoryRequestKey, SelectedTerminalHeaderBoundary,
        SnapshotHeaderNextAction, MAX_TRACKED_RELAY_TERMINAL_PEERS,
    };

    #[test]
    fn accepted_wallet_callback_stays_post_commit_pre_mempool_and_non_rejecting() {
        let miner_source = include_str!("../../noid_miner/src/miner.rs");
        let apply = miner_source
            .split_once("async fn apply_found_block(")
            .expect("miner accepted-block apply exists")
            .1
            .split_once("// Block certificate assembly")
            .expect("accepted-block apply has a bounded source section")
            .0;
        let durable_apply = apply
            .find("ctx.apply_next_block(")
            .expect("canonical durable apply precedes callbacks");
        let wallet_callback = apply
            .find("h(&block_owned);")
            .expect("wallet callback exists in accepted apply");
        let mempool_publish = apply
            .find(".on_new_block(&confirmed, block.header.height, new_view)")
            .expect("mempool publication follows accepted apply");
        assert!(durable_apply < wallet_callback);
        assert!(wallet_callback < mempool_publish);

        let node_source = include_str!("main.rs");
        let wallet_wrapper_marker = ["fn update_wallet_", "for_block("].concat();
        let wallet_wrapper = node_source
            .split_once(&wallet_wrapper_marker)
            .expect("node wallet callback wrapper exists")
            .1
            .split_once("// Helpers")
            .expect("wallet callback wrapper has a bounded source section")
            .0;
        assert!(wallet_wrapper.contains("if let Err(error) = wallet::update_for_accepted_block"));
        assert!(wallet_wrapper.contains("\"committed block but wallet update failed\""));
        assert!(
            !wallet_wrapper.contains("-> Result"),
            "an already-committed block must not become a rejection through its wallet callback"
        );
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
    fn relay_terminal_response_correlation_rejects_every_identity_mismatch() {
        let peer = libp2p::PeerId::random();
        let other_peer = libp2p::PeerId::random();
        let key = RemoteSelectedHistoryRequestKey {
            token: 7,
            peer,
            height: 144,
            block_hash: [0xA5; 32],
        };
        assert!(key.matches_response(peer, 144, [0xA5; 32]));
        assert!(!key.matches_response(other_peer, 144, [0xA5; 32]));
        assert!(!key.matches_response(peer, 145, [0xA5; 32]));
        assert!(!key.matches_response(peer, 144, [0x5A; 32]));
    }

    #[test]
    fn relay_terminal_peer_rotation_has_a_fixed_capacity() {
        let mut peers = BoundedRelayTerminalPeers::default();
        let mut admitted = Vec::new();
        for _ in 0..MAX_TRACKED_RELAY_TERMINAL_PEERS {
            let peer = libp2p::PeerId::random();
            assert!(peers.insert(peer));
            admitted.push(peer);
        }
        assert_eq!(peers.len(), MAX_TRACKED_RELAY_TERMINAL_PEERS);
        let replacement = libp2p::PeerId::random();
        assert!(!peers.insert(replacement));
        assert_eq!(peers.len(), MAX_TRACKED_RELAY_TERMINAL_PEERS);
        assert_ne!(peers.next_rotated(), Some(admitted[0]));
        let first = peers.next_rotated().expect("non-empty rotation");
        for _ in 1..MAX_TRACKED_RELAY_TERMINAL_PEERS {
            let _ = peers.next_rotated();
        }
        assert_eq!(peers.next_rotated(), Some(first));
        peers.remove(&first);
        assert_eq!(peers.len(), MAX_TRACKED_RELAY_TERMINAL_PEERS - 1);
    }

    #[test]
    fn relay_terminal_import_source_is_single_allocation_and_snapshot_priority() {
        let source = include_str!("main.rs");
        let channel = [
            "mpsc::channel::<",
            "RemoteSelectedHistoryVerificationCompletion",
            ">(1)",
        ]
        .concat();
        assert_eq!(source.matches(&channel).count(), 1);
        let forbidden_queue = ["Vec<VerifiedRemote", "SelectedHistoryTerminal>"].concat();
        let single_pending = [
            "let mut pending_remote_selected_history_request: Option<",
            "PendingRemoteSelectedHistoryRequest>",
        ]
        .concat();
        assert!(!source.contains(&forbidden_queue));
        assert!(source.contains(&single_pending));

        let proof_marker = ["Ok(NetworkEvent::", "HistoryProof"].concat();
        let disconnect_marker = ["Ok(NetworkEvent::", "PeerDisconnected"].concat();
        let arm = source
            .split_once(&proof_marker)
            .expect("history proof event arm exists")
            .1
            .split_once(&disconnect_marker)
            .expect("disconnect follows history proof")
            .0;
        let snapshot_at = arm
            .find("let snapshot_correlated")
            .expect("snapshot response correlation exists");
        let remote_at = arm
            .find("let remote_correlated")
            .expect("relay response correlation exists");
        assert!(snapshot_at < remote_at);
        assert!(arm.contains("drop(proof_bytes)"));
        assert!(arm.contains("drop(inbound_memory_permit)"));
        assert!(arm.contains("tokio::task::spawn_blocking"));
        assert!(arm.contains("std::mem::take(&mut proof_bytes)"));
        let import_marker = ["import_verified_selected_", "history_terminal"].concat();
        let permit_marker = ["let _inbound_permit_", "is_retained"].concat();
        assert!(source.contains(&import_marker));
        assert!(source.contains(&permit_marker));
    }

    #[test]
    fn orphan_transfer_keeps_single_owned_proof_allocations() {
        let block = noid_chain::block::Block {
            header: noid_chain::consensus::genesis_header(),
            transactions: Vec::new(),
        };
        let proof = vec![0xA5; 257];
        let sidecar = vec![0x5A; 129];
        let proof_ptr = proof.as_ptr();
        let sidecar_ptr = sidecar.as_ptr();
        let candidate = ProvedBlockCandidate {
            block,
            block_bytes_len: 33,
            block_proof_bytes: proof,
            block_auth_sidecar_bytes: sidecar,
        };

        let orphan = OrphanBlock::from_candidate(candidate);
        assert_eq!(orphan.block_proof_bytes.as_ptr(), proof_ptr);
        assert_eq!(orphan.block_auth_sidecar_bytes.as_ptr(), sidecar_ptr);
        assert_eq!(orphan.retained_bytes(), 33 + 257 + 129);

        let candidate = orphan.into_candidate();
        assert_eq!(candidate.block_proof_bytes.as_ptr(), proof_ptr);
        assert_eq!(candidate.block_auth_sidecar_bytes.as_ptr(), sidecar_ptr);
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
    fn snapshot_payload_pipeline_source_stays_bounded_and_nonblocking() {
        let source = include_str!("main.rs");
        let staging_channel = ["mpsc::channel::<", "SnapshotStagingCompletion", ">(1)"].concat();
        let install_channel = ["mpsc::channel::<", "SnapshotInstallCompletion", ">(1)"].concat();
        assert_eq!(source.matches(&staging_channel).count(), 1);
        assert_eq!(source.matches(&install_channel).count(), 1);

        let segment_marker = ["Ok(NetworkEvent::", "StateSegment"].concat();
        let history_marker = ["Ok(NetworkEvent::", "HistoryProof"].concat();
        let segment_arm = source
            .split_once(&segment_marker)
            .expect("state-segment event arm exists")
            .1
            .split_once(&history_marker)
            .expect("history-proof arm follows state-segment arm")
            .0;
        assert!(segment_arm.contains("snapshot_staging_inflight"));
        assert!(segment_arm.contains("tokio::task::spawn_blocking"));
        assert!(segment_arm.contains("as_deref()"));
        assert!(segment_arm.contains("drop(response);"));

        let completion_marker = ["completed = ", "snapshot_staging_completion_rx.recv()"].concat();
        let selected_marker = ["completed = ", "selected_history_verification_rx.recv()"].concat();
        let completion_arm = source
            .split_once(&completion_marker)
            .expect("snapshot staging completion arm exists")
            .1
            .split_once(&selected_marker)
            .expect("selected-history completion follows snapshot completions")
            .0;
        assert!(completion_arm.contains("SnapshotStagingCompletion::Accepted"));
        assert!(completion_arm.contains("SnapshotStagingCompletion::Finalized"));
        assert!(completion_arm.contains("let install_task = tokio::spawn(async move"));
        assert!(
            source
                .matches("if snapshot_install_inflight.is_some()")
                .count()
                >= 7
        );
    }

    #[test]
    fn snapshot_header_pipeline_is_isolated_bounded_and_short_locked() {
        let source = include_str!("main.rs");
        let header_channel = [
            "mpsc::channel::<",
            "SnapshotHeaderStagingCompletion",
            ">(1)",
        ]
        .concat();
        assert_eq!(source.matches(&header_channel).count(), 1);
        let legacy_scan = ["first_missing_", "snapshot_header"].concat();
        let legacy_persist = ["persist_snapshot_", "header_batch"].concat();
        let canonical_writer = ["put_verified_", "header_only"].concat();
        assert!(!source.contains(&legacy_scan));
        assert!(!source.contains(&legacy_persist));
        assert!(!source.contains(&canonical_writer));

        let headers_marker = ["Ok(NetworkEvent::", "HeadersBatch"].concat();
        let headers_arm = source
            .split_once(&headers_marker)
            .expect("headers event arm exists")
            .1
            .split_once("// Find common ancestor for reorg.")
            .expect("snapshot branch precedes ordinary reorg headers")
            .0;
        assert!(headers_arm.contains("validate_snapshot_header_batch_admission"));
        let cap_guard = ["batch_len > ", "MAX_STAGED_HEADER_BATCH"].concat();
        assert!(source.contains(&cap_guard));
        assert!(headers_arm.contains("snapshot_header_staging_inflight"));
        assert!(headers_arm.contains("tokio::task::spawn_blocking"));
        assert!(headers_arm.contains("append_batch(&store, &headers)"));

        let proof_marker = ["Ok(NetworkEvent::", "HistoryProof"].concat();
        let disconnect_marker = ["Ok(NetworkEvent::", "PeerDisconnected"].concat();
        let proof_arm = source
            .split_once(&proof_marker)
            .expect("history proof event arm exists")
            .1
            .split_once(&disconnect_marker)
            .expect("peer disconnect follows history proof")
            .0;
        let terminal_transition = ["verify_", "terminal("].concat();
        assert!(proof_arm.contains(&terminal_transition));
        assert!(!proof_arm.contains("blocking_write"));
        let pre_generation_check = proof_arm
            .find("generation_guard.load")
            .expect("generation checked before expensive verification");
        let verify_transition = proof_arm
            .find(&terminal_transition)
            .expect("terminal typestate transition exists");
        assert!(pre_generation_check < verify_transition);

        let install_marker = ["async fn apply_", "verified_snapshot"].concat();
        let install = source
            .split_once(&install_marker)
            .expect("snapshot install helper exists")
            .1;
        let promote_at = install
            .find("verified_headers")
            .and_then(|start| {
                install[start..]
                    .find(".promote(&header_store)")
                    .map(|at| start + at)
            })
            .expect("authenticated headers promote in install worker");
        let wallet_gate_at = install
            .find("wallet_operation_gate.lock().await")
            .expect("wallet gate protects only active-state replacement");
        let chain_write_at = install
            .find("install_chain.blocking_write()")
            .expect("state install takes the chain write guard");
        let apply_at = install
            .find("apply_staged_state_snapshot_with_selected_history")
            .expect("state snapshot applies in install worker");
        assert!(promote_at < wallet_gate_at);
        assert!(wallet_gate_at < chain_write_at && chain_write_at < apply_at);
        assert!(!install[..promote_at].contains("blocking_write"));
        let unlock_at = install
            .find("drop(ctx)")
            .expect("chain guard released before disk cleanup");
        let state_cleanup_at = install
            .find("drop(staging)")
            .expect("finalized staging cleanup is explicit");
        assert!(apply_at < unlock_at && unlock_at < state_cleanup_at);
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
            SnapshotHeaderNextAction::RequestProof
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

    fn minimal_current_block_proof() -> noid_block::BlockProof {
        noid_block::BlockProof::minimal(
            [0u8; 32],
            [0u8; 32],
            0,
            noid_block::ExactStateTransitionProof {
                slot_siblings: vec![],
            },
        )
    }

    #[test]
    fn block_proof_bytes_survive_store_reopen_and_deserialize() {
        let dir = tempfile::tempdir().expect("tempdir");
        let proof = minimal_current_block_proof();
        let bytes = bincode::serialize(&proof).expect("serialize BlockProof");

        {
            let store = noid_chain::storage::MdbxStore::open(dir.path()).expect("open store");
            store.put_block_proof(7, &bytes).expect("store proof bytes");
        }

        let store = noid_chain::storage::MdbxStore::open(dir.path()).expect("reopen store");
        let loaded = store
            .get_block_proof(7)
            .expect("load proof bytes")
            .expect("proof bytes present after reopen");
        assert_eq!(loaded, bytes);

        let decoded: noid_block::BlockProof =
            bincode::deserialize(&loaded).expect("deserialize current BlockProof format");
        assert_eq!(decoded.meta.n_tx, 0);
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
        let boundary = SelectedTerminalHeaderBoundary {
            tip_header: h1,
            tip_hash: h1_hash,
            cumulative_chainwork: h1_work,
            epoch_anchor_header: h0,
        };
        validate_snapshot_staged_header_boundary(&manifest, &boundary, &high_start_work)
            .expect("staged snapshot boundary preflight succeeds");
        assert_eq!(boundary.tip_header, h1);
        assert_eq!(boundary.epoch_anchor_header, h0);

        let mut wrong_fork = boundary;
        wrong_fork.tip_hash = h0_hash;
        assert!(
            validate_snapshot_staged_header_boundary(&manifest, &wrong_fork, &high_start_work,)
                .expect_err("manifest for another staged fork must reject")
                .contains("boundary")
        );

        let mut bad = manifest.clone();
        bad.cumulative_chainwork = [3u8; 32];
        assert!(
            validate_snapshot_staged_header_boundary(&bad, &boundary, &high_start_work,)
                .expect_err("bad chainwork must reject")
                .contains("chainwork")
        );

        let mut low_work = [0u8; 32];
        low_work[0] = 1;
        let low_work_manifest = noid_p2p::protocol::GetStateManifestResponse {
            cumulative_chainwork: low_work,
            ..manifest.clone()
        };
        let low_work_boundary = SelectedTerminalHeaderBoundary {
            cumulative_chainwork: low_work,
            ..boundary
        };
        assert!(validate_snapshot_staged_header_boundary(
            &low_work_manifest,
            &low_work_boundary,
            &high_start_work,
        )
        .expect_err("below minimum snapshot work must reject")
        .contains("minimum snapshot work"));
    }

    #[test]
    fn snapshot_and_relay_terminal_tip_obey_local_future_drift_admission() {
        let local_time = 1_000_000u64;
        let mut tip = noid_chain::consensus::genesis::genesis_header();
        tip.timestamp = local_time + noid_chain::consensus::params::MAX_FUTURE_DRIFT;
        let mut boundary = SelectedTerminalHeaderBoundary {
            tip_header: tip,
            tip_hash: noid_chain::hash_block_header(&tip),
            cumulative_chainwork: [0u8; 32],
            epoch_anchor_header: tip,
        };
        validate_selected_terminal_tip_future_drift(&boundary, local_time)
            .expect("exact future-drift boundary is admitted");

        boundary.tip_header.timestamp += 1;
        assert!(
            validate_selected_terminal_tip_future_drift(&boundary, local_time)
                .expect_err("far-future selected terminal tip must reject")
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
    sync_ready: Arc<tokio::sync::Notify>,
    wallet_operation_gate: WalletOperationGate,
    snapshot_staging_root: PathBuf,
    selected_history_verifier: Option<SelectedHistoryVerifierArtifacts>,
    remote_selected_history_import_enabled: bool,
) {
    // Orphan pool: blocks whose parent is not yet known.
    // When the parent arrives, we re-apply the orphan.
    // Keyed by parent_hash, limited to CONSENSUS_FINALITY_DEPTH entries.
    use noid_chain::consensus::params::CONSENSUS_FINALITY_DEPTH;
    use std::collections::HashMap;
    let mut orphan_pool: HashMap<[u8; 32], OrphanBlock> = HashMap::new();

    // --- Snapshot verification state ---
    //
    // Snapshot sync:
    //   (1) receive an immutable exact-state snapshot manifest
    //   (2) verify the O(1) selected-history terminal for that boundary
    //       before segment download
    // --- Segmented state sync state ---
    //
    // Sync flow:
    //   1. Recent gaps that fit RECENT_BLOCK_RETENTION_DEPTH use SyncBlocksFrom
    //      and full block/proof validation.
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
        selected_history: Option<VerifiedSelectedHistorySnapshot>,
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
        result: Result<PendingSnapshotHeaderSync, String>,
    }
    #[derive(Clone, Copy, PartialEq, Eq)]
    struct SelectedHistoryVerificationKey {
        token: u64,
        from: libp2p::PeerId,
        height: u64,
        block_hash: [u8; 32],
    }
    struct SelectedHistoryVerificationCompletion {
        key: SelectedHistoryVerificationKey,
        generation: u64,
        manifest: Box<noid_p2p::protocol::GetStateManifestResponse>,
        peer_tip_height: u64,
        result: Result<VerifiedSelectedHistorySnapshot, String>,
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
            result: Result<SnapshotStagingSession, String>,
        },
        Finalized {
            key: SnapshotStagingOperationKey,
            segment_count: usize,
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
        result: Result<u64, String>,
    }
    let mut pending_manifest: Option<PendingManifest> = None;
    let mut pending_snapshot_header_sync: Option<PendingSnapshotHeaderSync> = None;
    let (snapshot_header_staging_tx, mut snapshot_header_staging_rx) =
        tokio::sync::mpsc::channel::<SnapshotHeaderStagingCompletion>(1);
    let mut snapshot_header_staging_inflight: Option<SnapshotHeaderStagingOperationKey> = None;
    let mut snapshot_header_staging_token = 0u64;
    let (selected_history_verification_tx, mut selected_history_verification_rx) =
        tokio::sync::mpsc::channel::<SelectedHistoryVerificationCompletion>(1);
    let mut selected_history_verification_inflight: Option<SelectedHistoryVerificationKey> = None;
    let mut selected_history_verification_token = 0u64;
    // Ordinary relays advance durable selected-history coverage by verifying
    // one exact finalized terminal received from one connected peer. There is
    // no proof/result queue: the request, verifier and capacity-1 completion
    // together own at most one inbound terminal allocation.
    let (remote_selected_history_verification_tx, mut remote_selected_history_verification_rx) =
        tokio::sync::mpsc::channel::<RemoteSelectedHistoryVerificationCompletion>(1);
    let mut remote_selected_history_verification_inflight: Option<RemoteSelectedHistoryRequestKey> =
        None;
    let mut pending_remote_selected_history_request: Option<PendingRemoteSelectedHistoryRequest> =
        None;
    let mut remote_selected_history_request_token = 0u64;
    let mut last_remote_selected_history_request_at: Option<Instant> = None;
    let mut relay_terminal_peers = BoundedRelayTerminalPeers::default();
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
    // Payloads are authenticated one at a time and sealed to disk.  The
    // session retains only compact descriptors and a received bitset.
    let mut snapshot_staging: Option<SnapshotStagingSession> = None;
    // Segment IDs still outstanding.
    let mut pending_segment_ids: std::collections::HashSet<u16> = std::collections::HashSet::new();
    // Segment IDs queued but not yet requested (concurrency cap).
    let mut segment_queue: std::collections::VecDeque<u16> = std::collections::VecDeque::new();

    // Helper: reset all segment-sync state on any failure.
    // Called whenever sync needs to restart (bad proof, apply failure, missing segment).
    // Clearing manifest_requested_peers lets the next PeerConnected start fresh.
    macro_rules! reset_sync_state {
        () => {{
            snapshot_sync_generation = snapshot_sync_generation.wrapping_add(1);
            snapshot_sync_generation_guard.store(
                snapshot_sync_generation,
                std::sync::atomic::Ordering::Release,
            );
            if let Some(mut stale_manifest) = pending_manifest.take() {
                if let Some(verified) = stale_manifest.selected_history.take() {
                    cleanup_verified_selected_history_offthread(verified);
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
            if let Some(stale_staging) = snapshot_staging.take() {
                cleanup_snapshot_staging_session_offthread(stale_staging);
            }
            pending_segment_ids.clear();
            segment_queue.clear();
            if selected_history_verification_inflight.is_some() {
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
            debug_assert!(remote_selected_history_verification_inflight.is_none());
            if pending_remote_selected_history_request.take().is_some() {
                remote_selected_history_request_token =
                    remote_selected_history_request_token.wrapping_add(1);
                tracing::debug!("snapshot sync superseded pending relay selected-history request");
            }
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
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    prepare_snapshot_header_sync(&staging_root, &store, from, manifest)
                }))
                .map_err(|_| "snapshot header preparation worker panicked".to_owned())
                .and_then(|result| result);
                let _ = completion.blocking_send(SnapshotHeaderStagingCompletion { key, result });
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
            Ok(NetworkEvent::NewBlockAnnouncement {
                from,
                height,
                hash,
                header_bytes,
            }) => {
                if snapshot_install_inflight.is_some() {
                    if height > highest_announced {
                        highest_announced = height;
                        last_announcement_peer = Some(from);
                    }
                    tracing::debug!(
                        peer = %from,
                        height,
                        "snapshot install active — deferring block pull until post-install sync"
                    );
                    continue;
                }
                let announced_header = match noid_chain::block_header::BlockHeader::from_bytes(&header_bytes) {
                    Ok(header) => header,
                    Err(e) => {
                        tracing::debug!(peer = %from, height, err = ?e, "compact block header decode failed — not pulling block body");
                        continue;
                    }
                };
                if announced_header.height != height {
                    tracing::debug!(
                        peer = %from,
                        announced_height = height,
                        header_height = announced_header.height,
                        "compact block height mismatch — not pulling block body"
                    );
                    continue;
                }
                let header_hash = noid_chain::consensus::pow::block_id(&announced_header);
                if header_hash != hash {
                    tracing::debug!(
                        peer = %from,
                        height,
                        announced_hash = %hex::encode(hash),
                        header_hash = %hex::encode(header_hash),
                        "compact block hash mismatch — not pulling block body"
                    );
                    continue;
                }

                if height > highest_announced {
                    highest_announced = height;
                    last_announcement_peer = Some(from);
                }
                // Compact block announcement: validate the advertised header before
                // downloading a potentially large proof-native block.  Direct-next
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
                        && selected_history_verification_inflight.is_none()
                        && remote_selected_history_verification_inflight.is_none()
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
                        tracing::debug!(
                            peer = %from,
                            height,
                            err = %e,
                            "compact block header precheck failed — not pulling block body"
                        );
                        continue;
                    }

                    let fetch_key = (height, hash);
                    if let Some(pending) = pending_block_fetches.get(&fetch_key) {
                        if pending.requested_at.elapsed() < BLOCK_FETCH_INFLIGHT_TTL {
                            tracing::debug!(
                                peer = %from,
                                pending_peer = %pending.peer,
                                height,
                                "block body/proof already in-flight — suppressing duplicate pull"
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
                    // Recent gap > 1: pull headers first so full block/proof bodies are
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
            Ok(NetworkEvent::NewBlock {
                from,
                block_bytes,
                block_proof_bytes,
                block_auth_sidecar_bytes,
                mut inbound_memory_permit,
            }) => {
                if snapshot_install_inflight.is_some() {
                    // Atomic snapshot installation owns the chain/mempool/wallet
                    // replacement order.  Release this pulled payload now; the
                    // install task requests the retained suffix after commit.
                    drop(block_bytes);
                    drop(block_proof_bytes);
                    drop(block_auth_sidecar_bytes);
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
                let block_bytes_len = block_bytes.len();
                match noid_chain::block::Block::from_bytes(&block_bytes) {
                    Ok(block) => {
                        // The decoded block is now the only retained block body.  Keep
                        // the inbound permit until the owned candidate is committed,
                        // rejected, or transferred to the byte-capped orphan pool.
                        drop(block_bytes);
                        let local_time = unix_now();
                        let block_hash = noid_chain::consensus::pow::block_id(&block.header);
                        pending_block_fetches.remove(&(block.header.height, block_hash));

                        // Skip blocks at or below our current tip — we already have them.
                        // This avoids expensive proof verification against a stale pre-state.
                        {
                            let our_tip = chain.read().await.tip_height();
                            if block.header.height <= our_tip {
                                tracing::debug!(
                                    peer = %from,
                                    height = block.header.height,
                                    our_tip,
                                    "dropping duplicate/stale block (already at tip)"
                                );
                                continue;
                            }
                        }

                        // Fork/orphan blocks are not proof-verified until their parent
                        // becomes the current tip, because exact transition proofs must
                        // be checked against the exact pre-block state. For the current
                        // tip, apply_p2p_block_offthread performs proof-native validation
                        // and atomic commit in one pass; no duplicate apply path.
                        let extends_current_tip = {
                            let ctx = chain.read().await;
                            block.header.height == ctx.tip_height().saturating_add(1)
                                && block.header.prev_block_hash == ctx.tip_hash()
                        };
                        if !extends_current_tip {
                            if let Err(e) = validate_p2p_block_proof_binding(
                                &block,
                                &block_proof_bytes,
                                &block_auth_sidecar_bytes,
                            ) {
                                tracing::warn!(
                                    peer = %from,
                                    height = block.header.height,
                                    err = %e,
                                    "P2P fork/orphan block proof/header binding invalid — rejected"
                                );
                                continue;
                            }
                        }

                        let preverified_auth =
                            preverified_authorization_bytes(&mempool, &block).await;
                        let candidate = ProvedBlockCandidate {
                            block,
                            block_bytes_len,
                            block_proof_bytes,
                            block_auth_sidecar_bytes,
                        };
                        let apply_result = apply_p2p_block_offthread(
                            &chain,
                            &wallet,
                            candidate,
                            local_time,
                            preverified_auth,
                        )
                        .await;

                        match apply_result {
                            Ok(applied) => {
                                // Proof/body buffers were consumed and dropped by the
                                // blocking worker, so release the transport reservation
                                // before any network or mempool await below.
                                drop(inbound_memory_permit.take());
                                let height = applied.height;
                                mempool
                                    .on_new_block(
                                        &applied.confirmed_tx_hashes,
                                        height,
                                        applied.view,
                                    )
                                    .await;
                                tracing::info!(height, "applied P2P block");
                                last_tip_advance = Instant::now();
                                sync_ready.notify_one(); // cancel/rebuild any active stale template

                                // Auto-continue sync: immediately request the next batch from
                                // the same peer. This pulls the chain all the way to the peer's
                                // tip without waiting for gossip mesh to propagate each block.
                                // SyncBlocksFrom for heights beyond peer's recent_blocks returns
                                // None and stops automatically — no infinite loop.
                                let _ = p2p_cmd
                                    .send(noid_p2p::NetworkCommand::SyncBlocksFrom {
                                        peer: from,
                                        from_height: height + 1,
                                        count: noid_chain::consensus::params::RECENT_BLOCK_RETENTION_DEPTH as u16,
                                    })
                                    .await;

                                // Apply the chain of orphans that build on the new block.
                                let mut next_hash = applied.block_hash;
                                while let Some(orphan) = orphan_pool.remove(&next_hash) {
                                    let orphan_local_time = unix_now();
                                    let orphan_age_ms = orphan.received_at.elapsed().as_millis();
                                    let orphan_candidate = orphan.into_candidate();
                                    let orphan_preverified =
                                        preverified_authorization_bytes(
                                            &mempool,
                                            &orphan_candidate.block,
                                        )
                                        .await;
                                    let orphan_result = apply_p2p_block_offthread(
                                        &chain,
                                        &wallet,
                                        orphan_candidate,
                                        orphan_local_time,
                                        orphan_preverified,
                                    )
                                    .await;
                                    match orphan_result {
                                        Ok(applied_orphan) => {
                                            next_hash = applied_orphan.block_hash;
                                            let h = applied_orphan.height;
                                            mempool
                                                .on_new_block(
                                                    &applied_orphan.confirmed_tx_hashes,
                                                    h,
                                                    applied_orphan.view,
                                                )
                                                .await;
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
                                                &orphan.block.header,
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
                                            )
                                            .await;

                                            match reorg_result {
                                                Ok(applied_reorg) => {
                                                    drop(inbound_memory_permit.take());
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
                                                        && selected_history_verification_inflight
                                                            .is_none()
                                                        && remote_selected_history_verification_inflight
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
                                                && selected_history_verification_inflight.is_none()
                                                && remote_selected_history_verification_inflight
                                                    .is_none()
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
                    Err(e) => {
                        tracing::warn!(peer = %from, err = ?e, "P2P block decode failed");
                    }
                }
            }
            Ok(NetworkEvent::RecentBlockUnavailable { from, height }) => {
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
                if height == our_tip.saturating_add(1) {
                    tracing::info!(
                        peer = %from,
                        requested_height = height,
                        our_tip,
                        "next retained block unavailable — requesting fresh snapshot manifest"
                    );
                    if pending_manifest.is_none()
                        && pending_snapshot_header_sync.is_none()
                        && snapshot_header_staging_inflight.is_none()
                        && selected_history_verification_inflight.is_none()
                        && remote_selected_history_verification_inflight.is_none()
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
                        "non-next retained block unavailable"
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
                let sync_ready_task = Arc::clone(&sync_ready);
                let chain_task = Arc::clone(&chain);
                tokio::spawn(async move {
                    {
                        let notified = sync_ready_task.notified();
                        let h = chain_task.read().await.tip_height();
                        if h == 0 {
                            tracing::debug!("mempool sync: waiting for state sync before admitting TXs");
                            notified.await;
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
                        if let Ok(intent) = noid_tx::TxIntent::from_bytes(&intent_bytes) {
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
                    if let Ok(intent) = noid_tx::TxIntent::from_bytes(&intent_bytes) {
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
                if remote_selected_history_import_enabled
                    && !relay_terminal_peers.insert(peer)
                {
                    tracing::debug!(
                        peer = %peer,
                        cap = MAX_TRACKED_RELAY_TERMINAL_PEERS,
                        "relay terminal peer tracker full — rotated out oldest tracked peer"
                    );
                }

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

                if our_height == 0 {
                    // Fresh node: request the state MANIFEST (tiny, ~few KB).
                    //
                    // Paranoid is a proof-native statechain: nodes sync via
                    // current state + history proof, not block replay.
                    // Manifest tells us which segments to download next.
                    // Segments are pulled in parallel after proof verification.
                    //
                    // Request from up to 3 distinct peers for eclipse mitigation.
                    if manifest_candidates.len() < 3 && !manifest_requested_peers.contains(&peer) {
                        tracing::info!(peer = %peer, "fresh node — requesting state manifest (Paranoid sync)");
                        manifest_requested_peers.insert(peer);
                        p2p_cmd
                            .send(noid_p2p::NetworkCommand::RequestStateManifest {
                                peer,
                                requester_height: 0,
                            })
                            .await
                            .ok();
                    }
                } else {
                    // Already have persisted state. The manifest is a snapshot
                    // boundary probe, not a live peer-tip probe: non-empty means
                    // the peer can serve an O(1) snapshot at finalized F. Recent
                    // gaps still use block/header announcements and retained
                    // full-block replay.
                    p2p_cmd
                        .send(noid_p2p::NetworkCommand::RequestStateManifest {
                            peer,
                            requester_height: our_height,
                        })
                        .await
                        .ok();
                    tracing::debug!(
                        requester_height = our_height,
                        "triggered manifest snapshot-boundary probe for persisted-state sync"
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

                if let Some((ancestor_height, _ancestor_hash)) = ancestor_opt {
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

                    if new_tip_height > our_tip {
                            // Shallow fork (≤ CONSENSUS_FINALITY_DEPTH): apply_reorg_mdbx can handle it.
                            // Fetch individual blocks; they arrive quickly and the orphan
                            // pool assembles them into a chain for the reorg comparison.
                            tracing::info!(
                                ancestor = ancestor_height,
                                our_tip,
                                competing_tip = new_tip_height,
                                peer = %from,
                                "shallow fork: fetching {} competing blocks for reorg",
                                competing.len()
                            );
                            for hdr in &competing {
                                let hdr_hash = noid_chain::consensus::pow::block_id(hdr);
                                let inflight_key = (hdr.height, hdr_hash);
                                if let Some(pending) = pending_block_fetches.get(&inflight_key) {
                                    if pending.requested_at.elapsed() < BLOCK_FETCH_INFLIGHT_TTL {
                                        tracing::debug!(
                                            peer = %from,
                                            pending_peer = %pending.peer,
                                            height = hdr.height,
                                            "fork block body/proof already in-flight"
                                        );
                                        continue;
                                    }
                                }

                                let request_key = (from, hdr.height);
                                let recently_requested = recent_block_fetches
                                    .get(&request_key)
                                    .is_some_and(|t| t.elapsed() < FETCH_DEDUP_TTL);
                                if recently_requested {
                                    tracing::debug!(
                                        peer = %from,
                                        height = hdr.height,
                                        "fork block fetch already requested"
                                    );
                                    continue;
                                }
                                pending_block_fetches.insert(
                                    inflight_key,
                                    PendingBlockFetch {
                                        peer: from,
                                        requested_at: Instant::now(),
                                    },
                                );
                                recent_block_fetches.insert(request_key, Instant::now());
                                let _ = p2p_cmd
                                    .send(noid_p2p::NetworkCommand::RequestBlock {
                                        peer: from,
                                        height: hdr.height,
                                    })
                                    .await;
                            }
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
                                && selected_history_verification_inflight.is_none()
                                && remote_selected_history_verification_inflight.is_none()
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
                let force_snapshot = manifest_force_snapshot_peers.remove(&from);
                manifest_response_count += 1;
                if manifest.tip_height == 0 {
                    tracing::debug!(from = %from, "manifest tip_height=0, peer has no state yet");
                    // Don't add to candidates, but fall through to check if we should
                    // proceed with existing candidates now that we've heard from this peer.
                } else {
                    if selected_history_verifier.is_none() {
                        tracing::warn!(
                            from = %from,
                            tip = manifest.tip_height,
                            "snapshot manifest ignored: selected-history release authority unavailable"
                        );
                        continue;
                    }
                    if manifest.segment_ids.len() != manifest.segment_roots.len() {
                        tracing::warn!(
                            from = %from,
                            ids = manifest.segment_ids.len(),
                            roots = manifest.segment_roots.len(),
                            "manifest segment_ids/segment_roots length mismatch — dropping"
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
                    let Some(expected_segment_bytes) =
                        encoded_segment_len_for_eff_log(manifest.eff_log)
                    else {
                        tracing::warn!(
                            from = %from,
                            eff_log = manifest.eff_log,
                            "manifest has invalid effective segment log — dropping"
                        );
                        continue;
                    };
                    if expected_segment_bytes > MAX_SEGMENT_BYTES {
                        tracing::warn!(
                            from = %from,
                            eff_log = manifest.eff_log,
                            expected_segment_bytes,
                            max_segment = MAX_SEGMENT_BYTES,
                            "manifest segment encoding exceeds per-segment cap — dropping"
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
                        || selected_history_verification_inflight.is_some()
                        || remote_selected_history_verification_inflight.is_some())
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
                    && selected_history_verification_inflight.is_none()
                    && remote_selected_history_verification_inflight.is_none()
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
                            "selected best manifest — requesting history proof for verification"
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
                        tokio::task::spawn_blocking(move || {
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
                                SnapshotStagingCompletion::Accepted { key, result },
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

            Ok(NetworkEvent::HistoryProof {
                from,
                height,
                block_hash,
                mut proof_bytes,
                tip_header_bytes,
                inbound_memory_permit,
            }) => {
                // Snapshot correlation always has priority. A relay-import
                // response can never consume a proof requested by the exact
                // staged snapshot state machine.
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
                    let remote_correlated = remote_selected_history_import_enabled
                        && pending_remote_selected_history_request
                            .as_ref()
                            .is_some_and(|pending| {
                                pending.key.matches_response(from, height, block_hash)
                            });
                    if !remote_correlated {
                        drop(proof_bytes);
                        drop(tip_header_bytes);
                        drop(inbound_memory_permit);
                        tracing::debug!(
                            from = %from,
                            height,
                            "dropping stale or mismatched history-proof response"
                        );
                        continue;
                    }
                    let pending = pending_remote_selected_history_request
                        .take()
                        .expect("exact remote history response has a pending request");

                    let snapshot_pipeline_busy = pending_manifest.is_some()
                        || pending_snapshot_header_sync.is_some()
                        || snapshot_header_staging_inflight.is_some()
                        || selected_history_verification_inflight.is_some()
                        || snapshot_staging_inflight.is_some()
                        || snapshot_install_inflight.is_some()
                        || !pending_segment_ids.is_empty()
                        || !segment_queue.is_empty()
                        || !manifest_candidates.is_empty();
                    if snapshot_pipeline_busy
                        || remote_selected_history_verification_inflight.is_some()
                    {
                        drop(proof_bytes);
                        drop(tip_header_bytes);
                        drop(inbound_memory_permit);
                        tracing::debug!(
                            from = %from,
                            height,
                            "dropping relay terminal response while snapshot/verifier pipeline is busy"
                        );
                        continue;
                    }
                    if proof_bytes.is_empty() {
                        drop(tip_header_bytes);
                        drop(inbound_memory_permit);
                        tracing::debug!(
                            from = %from,
                            height,
                            "peer cannot serve exact relay terminal — rotating"
                        );
                        continue;
                    }

                    if !tip_header_bytes.is_empty() {
                        let peer_tip_height = match noid_chain::block_header::BlockHeader::from_bytes(
                            &tip_header_bytes,
                        ) {
                            Ok(header) => header.height,
                            Err(error) => {
                                drop(proof_bytes);
                                drop(inbound_memory_permit);
                                tracing::debug!(
                                    from = %from,
                                    height,
                                    err = ?error,
                                    "relay terminal response carried malformed peer tip"
                                );
                                continue;
                            }
                        };
                        if peer_tip_height < height
                            || peer_tip_height.saturating_sub(height)
                                > noid_chain::consensus::params::RECENT_BLOCK_RETENTION_DEPTH
                        {
                            drop(proof_bytes);
                            drop(inbound_memory_permit);
                            tracing::debug!(
                                from = %from,
                                height,
                                peer_tip_height,
                                "relay terminal response is outside peer retained suffix"
                            );
                            continue;
                        }
                    }
                    drop(tip_header_bytes);

                    let Some(artifacts) = selected_history_verifier.clone() else {
                        drop(proof_bytes);
                        drop(inbound_memory_permit);
                        tracing::warn!(
                            from = %from,
                            height,
                            "relay terminal response rejected: release verifier unavailable"
                        );
                        continue;
                    };
                    let target = {
                        let ctx = chain.read().await;
                        relay_selected_history_import_target_at(
                            &ctx,
                            pending.key.height,
                            pending.key.block_hash,
                        )
                    };
                    let target = match target {
                        Ok(Some(target))
                            if target.height == height && target.block_hash == block_hash => target,
                        Ok(_) => {
                            drop(proof_bytes);
                            drop(inbound_memory_permit);
                            tracing::debug!(
                                from = %from,
                                height,
                                "relay terminal target advanced or is already covered"
                            );
                            continue;
                        }
                        Err(error) => {
                            drop(proof_bytes);
                            drop(inbound_memory_permit);
                            tracing::warn!(
                                from = %from,
                                height,
                                err = %error,
                                "relay terminal canonical target capture failed"
                            );
                            continue;
                        }
                    };

                    let key = pending.key;
                    let completion = remote_selected_history_verification_tx.clone();
                    remote_selected_history_verification_inflight = Some(key);
                    tokio::task::spawn_blocking(move || {
                        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            validate_selected_terminal_tip_future_drift(
                                &target.boundary,
                                unix_now(),
                            )?;
                            let tier = verify_snapshot_selected_history_terminal(
                                target.height,
                                target.block_hash,
                                &proof_bytes,
                                &target.boundary,
                                &artifacts,
                            )?;
                            if tier != target.tier {
                                return Err(
                                    "relay terminal tier differs from canonical job".to_owned(),
                                );
                            }
                            Ok(VerifiedRemoteSelectedHistoryTerminal {
                                target,
                                terminal_package_bytes: std::mem::take(&mut proof_bytes),
                                inbound_memory_permit,
                            })
                        }))
                        .map_err(|_| "relay selected-history verifier worker panicked".to_owned())
                        .and_then(|result| result);
                        let _ = completion.blocking_send(
                            RemoteSelectedHistoryVerificationCompletion { key, result },
                        );
                    });
                    tracing::info!(
                        from = %from,
                        height,
                        "relay selected-history terminal verification started off-thread"
                    );
                    continue;
                }

                if snapshot_install_inflight.is_some() {
                    // Drop proof bytes and their process-global admission as
                    // one response; the installed boundary starts a fresh
                    // suffix sync on completion.
                    drop(proof_bytes);
                    drop(tip_header_bytes);
                    drop(inbound_memory_permit);
                    tracing::debug!(
                        from = %from,
                        height,
                        "snapshot install active — releasing stale history proof"
                    );
                    continue;
                }
                // Selected terminal decoding and every streamed matrix check
                // run on the blocking pool with no chain lock held. The
                // unpromoted header staging file travels with that proof.

                // If segment collection is already in progress (pending_segment_ids non-empty),
                // a second HistoryProof event would corrupt the active session.
                // Ignore it to protect the in-flight segment download.
                if !pending_segment_ids.is_empty() || !segment_queue.is_empty() {
                    tracing::debug!(
                        from = %from,
                        "ignoring history proof — segment collection already in progress"
                    );
                    continue;
                }

                let sync = match pending_snapshot_header_sync.take() {
                    Some(sync) if sync.from == from => sync,
                    Some(sync) => {
                        tracing::warn!(
                            proof_from = %from, manifest_from = %sync.from,
                            "history proof from unexpected peer, preserving staged headers"
                        );
                        pending_snapshot_header_sync = Some(sync);
                        continue;
                    }
                    None => {
                        tracing::debug!(from = %from, "unexpected history proof, no staged headers");
                        continue;
                    }
                };

                let peer_tip_height = if tip_header_bytes.is_empty() {
                    sync.manifest.tip_height
                } else {
                    match noid_chain::block_header::BlockHeader::from_bytes(&tip_header_bytes) {
                        Ok(header) => header.height,
                        Err(error) => {
                            tracing::warn!(from = %from, err = ?error, "snapshot proof response carried bad peer tip header");
                            cleanup_snapshot_header_staging_offthread(sync.staging);
                            reset_sync_state!();
                            continue;
                        }
                    }
                };
                if peer_tip_height < sync.manifest.tip_height {
                    tracing::warn!(
                        from = %from,
                        snapshot_height = sync.manifest.tip_height,
                        peer_tip_height,
                        "snapshot proof peer tip is behind manifest boundary"
                    );
                    cleanup_snapshot_header_staging_offthread(sync.staging);
                    reset_sync_state!();
                    continue;
                }
                let suffix_len = peer_tip_height - sync.manifest.tip_height;
                if suffix_len > noid_chain::consensus::params::RECENT_BLOCK_RETENTION_DEPTH {
                    tracing::warn!(
                        from = %from,
                        snapshot_height = sync.manifest.tip_height,
                        peer_tip_height,
                        suffix_len,
                        "snapshot boundary is outside the peer's retained suffix"
                    );
                    cleanup_snapshot_header_staging_offthread(sync.staging);
                    reset_sync_state!();
                    continue;
                }

                let Some(artifacts) = selected_history_verifier.clone() else {
                    tracing::error!(
                        from = %from,
                        tip = sync.manifest.tip_height,
                        "REJECTED snapshot manifest: selected-history release authority unavailable"
                    );
                    cleanup_snapshot_header_staging_offthread(sync.staging);
                    reset_sync_state!();
                    continue;
                };
                let expected_height = sync.manifest.tip_height;
                let expected_hash = sync.manifest.tip_hash;
                selected_history_verification_token =
                    selected_history_verification_token.wrapping_add(1);
                let key = SelectedHistoryVerificationKey {
                    token: selected_history_verification_token,
                    from,
                    height: expected_height,
                    block_hash: expected_hash,
                };
                let generation = snapshot_sync_generation;
                let completion = selected_history_verification_tx.clone();
                let generation_guard = Arc::clone(&snapshot_sync_generation_guard);
                let store = snapshot_header_store.clone();
                let manifest = sync.manifest;
                let staging = sync.staging;
                let staging_path = staging.path().to_owned();
                selected_history_verification_inflight = Some(key);
                tokio::task::spawn_blocking(move || {
                    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        if generation_guard.load(std::sync::atomic::Ordering::Acquire)
                            != generation
                        {
                            return Err(
                                "selected-history verification superseded before start".to_owned(),
                            );
                        }
                        let mut verified_tier = None;
                        let verified_headers = staging
                            .verify_terminal(
                                &store,
                                expected_height,
                                expected_hash,
                                manifest.cumulative_chainwork,
                                |boundary| {
                                    validate_snapshot_staged_header_boundary(
                                        &manifest,
                                        boundary,
                                        &noid_chain::consensus::params::MIN_SNAPSHOT_CHAINWORK,
                                    )?;
                                    validate_selected_terminal_tip_future_drift(
                                        boundary,
                                        unix_now(),
                                    )?;
                                    verified_tier = Some(
                                        verify_snapshot_selected_history_terminal(
                                            expected_height,
                                            expected_hash,
                                            &proof_bytes,
                                            boundary,
                                            &artifacts,
                                        )?,
                                    );
                                    Ok(())
                                },
                            )
                            .map_err(|error| error.to_string())?;
                        if generation_guard.load(std::sync::atomic::Ordering::Acquire)
                            != generation
                        {
                            let _ = verified_headers.discard();
                            return Err(
                                "selected-history verification superseded before completion"
                                    .to_owned(),
                            );
                        }
                        let tier = verified_tier.ok_or_else(|| {
                            "selected-history verifier returned no canonical tier".to_owned()
                        })?;
                        Ok(VerifiedSelectedHistorySnapshot {
                            height: expected_height,
                            block_hash: expected_hash,
                            tier,
                            terminal_package_bytes: proof_bytes,
                            verified_headers,
                            inbound_memory_permit,
                        })
                    }))
                    .map_err(|_| "selected-history verifier worker panicked".to_owned())
                    .and_then(|result| result);
                    if result.is_err() {
                        let _ = std::fs::remove_file(staging_path);
                    }
                    let _ = completion.blocking_send(SelectedHistoryVerificationCompletion {
                        key,
                        generation,
                        manifest,
                        peer_tip_height,
                        result,
                    });
                });
                tracing::info!(
                    from = %from,
                    tip = expected_height,
                    "snapshot selected-history verification started off-thread"
                );
            }
            Ok(NetworkEvent::PeerDisconnected(peer)) => {
                tracing::debug!(peer = %peer, "peer disconnected");
                relay_terminal_peers.remove(&peer);
                if pending_remote_selected_history_request
                    .as_ref()
                    .is_some_and(|pending| pending.key.peer == peer)
                {
                    pending_remote_selected_history_request = None;
                    remote_selected_history_request_token =
                        remote_selected_history_request_token.wrapping_add(1);
                    tracing::debug!(
                        peer = %peer,
                        "relay terminal request peer disconnected — rotating"
                    );
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
                    || selected_history_verification_inflight
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
                SnapshotHeaderNextAction::RequestProof => {
                    let proof_height = sync.manifest.tip_height;
                    let proof_hash = sync.manifest.tip_hash;
                    pending_snapshot_header_sync = Some(sync);
                    let _ = p2p_cmd
                        .send(noid_p2p::NetworkCommand::RequestHistoryProof {
                            peer: from,
                            height: proof_height,
                            block_hash: proof_hash,
                        })
                        .await;
                    tracing::info!(
                        peer = %from,
                        target_height = proof_height,
                        "snapshot: exact staged header target reached — requesting history proof"
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
                SnapshotStagingCompletion::Accepted { key, result } => {
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
                    // selected proof and inbound permit during this pass.
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
                                    result,
                                },
                            );
                        });
                    }
                }
                SnapshotStagingCompletion::Finalized {
                    key,
                    segment_count,
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
                    let Some(selected_history) = pending.selected_history.take() else {
                        tracing::error!(from = %from, "verified snapshot lost selected-history authority");
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
                    let install_p2p_cmd = p2p_cmd.clone();
                    let install_wallet_operation_gate = Arc::clone(&wallet_operation_gate);
                    let completion = snapshot_install_completion_tx.clone();
                    let install_task = tokio::spawn(async move {
                        apply_verified_snapshot(
                            &install_chain,
                            &install_mempool,
                            &install_wallet,
                            &install_p2p_cmd,
                            from,
                            manifest,
                            finalized,
                            selected_history,
                            &install_wallet_operation_gate,
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
                Ok(height) => {
                    tracing::info!(height, from = %completed.key.from, "snapshot install completed");
                    reset_sync_state!();
                    last_tip_advance = Instant::now();
                    sync_ready.notify_one();
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

        completed = selected_history_verification_rx.recv() => {
            let Some(completed) = completed else {
                continue;
            };
            if selected_history_verification_inflight != Some(completed.key) {
                if let Ok(verified) = completed.result {
                    cleanup_verified_selected_history_offthread(verified);
                }
                tracing::debug!(
                    from = %completed.key.from,
                    tip = completed.key.height,
                    "discarding superseded selected-history verification"
                );
                continue;
            }
            selected_history_verification_inflight = None;
            if completed.generation != snapshot_sync_generation {
                if let Ok(verified) = completed.result {
                    cleanup_verified_selected_history_offthread(verified);
                }
                tracing::debug!(
                    from = %completed.key.from,
                    tip = completed.key.height,
                    "discarding selected-history verification from a reset sync generation"
                );
                continue;
            }

            let from = completed.key.from;
            let verified_selected_history = match completed.result {
                Ok(verified) => verified,
                Err(error) => {
                    tracing::error!(
                        from = %from,
                        tip = completed.key.height,
                        err = %error,
                        "REJECTED snapshot manifest: selected-history terminal verification failed"
                    );
                    reset_sync_state!();
                    continue;
                }
            };

            if completed.peer_tip_height > highest_announced {
                highest_announced = completed.peer_tip_height;
                last_announcement_peer = Some(from);
            }
            tracing::info!(
                from = %from,
                tip = completed.manifest.tip_height,
                peer_tip_height = completed.peer_tip_height,
                segments = completed.manifest.segment_ids.len(),
                "snapshot manifest accepted — staging authenticated boundary"
            );
            let staging = match create_snapshot_staging_session(
                &snapshot_staging_root,
                &completed.manifest,
            ) {
                Ok(staging) => staging,
                Err(error) => {
                    tracing::warn!(peer = %from, err = %error, "snapshot staging initialization failed");
                    cleanup_verified_selected_history_offthread(verified_selected_history);
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
            // The proof allocation and inbound permit remain owned by the
            // selected manifest until atomic snapshot installation.
            pending_manifest = Some(PendingManifest {
                from,
                manifest: completed.manifest,
                selected_history: Some(verified_selected_history),
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
                    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                        staging.finalize().map_err(|error| error.to_string())
                    }))
                    .map_err(|_| "snapshot finalization worker panicked".to_owned())
                    .and_then(|result| result);
                    let _ = completion.blocking_send(SnapshotStagingCompletion::Finalized {
                        key,
                        segment_count,
                        result,
                    });
                });
            }
        }

        completed = remote_selected_history_verification_rx.recv() => {
            let Some(completed) = completed else {
                continue;
            };
            if remote_selected_history_verification_inflight != Some(completed.key) {
                // Dropping a successful superseded completion releases both
                // its sole proof Vec and process-global inbound byte permit.
                drop(completed.result);
                tracing::debug!(
                    from = %completed.key.peer,
                    height = completed.key.height,
                    "discarding superseded relay terminal verification"
                );
                continue;
            }
            remote_selected_history_verification_inflight = None;
            let verified = match completed.result {
                Ok(verified) => verified,
                Err(error) => {
                    tracing::warn!(
                        from = %completed.key.peer,
                        height = completed.key.height,
                        err = %error,
                        "relay selected-history terminal verification rejected"
                    );
                    continue;
                }
            };

            let still_importable = {
                let ctx = chain.read().await;
                relay_selected_history_target_still_importable(&ctx, &verified.target)
            };
            match still_importable {
                Ok(true) => {}
                Ok(false) => {
                    drop(verified);
                    tracing::debug!(
                        from = %completed.key.peer,
                        height = completed.key.height,
                        "verified relay terminal became stale before import"
                    );
                    continue;
                }
                Err(error) => {
                    drop(verified);
                    tracing::warn!(
                        from = %completed.key.peer,
                        height = completed.key.height,
                        err = %error,
                        "relay terminal canonical recheck failed"
                    );
                    continue;
                }
            }

            // Keep ownership of the inbound permit and terminal bytes through
            // the atomic write. The store independently rechecks finality,
            // canonical target/epoch identity, tier and fixed wire framing.
            let _inbound_permit_is_retained = &verified.inbound_memory_permit;
            let import = snapshot_header_store.import_verified_selected_history_terminal(
                noid_chain::storage::VerifiedSelectedHistoryTerminalImport {
                    height: verified.target.height,
                    block_hash: verified.target.block_hash,
                    epoch_anchor_height: verified.target.epoch_anchor_height,
                    epoch_anchor_hash: verified.target.epoch_anchor_hash,
                    tier: verified.target.tier,
                    terminal_package_bytes: &verified.terminal_package_bytes,
                },
            );
            match import {
                Ok(coverage) => tracing::info!(
                    from = %completed.key.peer,
                    height = coverage.height,
                    "verified remote selected-history terminal imported atomically"
                ),
                Err(error) => tracing::warn!(
                    from = %completed.key.peer,
                    height = completed.key.height,
                    err = %error,
                    "verified remote selected-history terminal import failed closed"
                ),
            }
            drop(verified);
        }

        // Heartbeat: re-evaluate manifest timeout without waiting for a new P2P event.
        _ = heartbeat.tick() => {
            let now = Instant::now();
            let fetch_cutoff = now - FETCH_DEDUP_TTL;
            recent_header_fetches.retain(|_, t| *t >= fetch_cutoff);
            recent_block_fetches.retain(|_, t| *t >= fetch_cutoff);
            pending_block_fetches
                .retain(|_, pending| now.duration_since(pending.requested_at) < BLOCK_FETCH_INFLIGHT_TTL);

            if remote_selected_history_import_enabled {
                let snapshot_pipeline_idle = pending_manifest.is_none()
                    && pending_snapshot_header_sync.is_none()
                    && snapshot_header_staging_inflight.is_none()
                    && selected_history_verification_inflight.is_none()
                    && snapshot_staging_inflight.is_none()
                    && snapshot_install_inflight.is_none()
                    && pending_segment_ids.is_empty()
                    && segment_queue.is_empty()
                    && manifest_candidates.is_empty();
                // One fixed-budget cleanup transaction per heartbeat. The
                // store visits at most the journal compaction entry cap and
                // never collects an unbounded result/key list. Avoid opening a
                // writer while snapshot disk/install work owns the pipeline.
                if snapshot_pipeline_idle {
                    if let Err(error) = snapshot_header_store
                        .compact_selected_history_journal_bounded()
                    {
                        tracing::debug!(
                            err = %error,
                            "bounded selected-history journal maintenance deferred"
                        );
                    }
                }

                if pending_remote_selected_history_request
                    .as_ref()
                    .is_some_and(|pending| {
                        now.duration_since(pending.requested_at)
                            >= REMOTE_SELECTED_HISTORY_REQUEST_TIMEOUT
                    })
                {
                    if let Some(expired) = pending_remote_selected_history_request.take() {
                        tracing::debug!(
                            peer = %expired.key.peer,
                            height = expired.key.height,
                            "relay terminal request timed out — rotating peer"
                        );
                    }
                    remote_selected_history_request_token =
                        remote_selected_history_request_token.wrapping_add(1);
                }

                let request_interval_elapsed = last_remote_selected_history_request_at
                    .is_none_or(|last| {
                        now.duration_since(last) >= REMOTE_SELECTED_HISTORY_REQUEST_INTERVAL
                    });
                if request_interval_elapsed
                    && snapshot_pipeline_idle
                    && pending_remote_selected_history_request.is_none()
                    && remote_selected_history_verification_inflight.is_none()
                    && selected_history_verifier.is_some()
                {
                    let target = {
                        let ctx = chain.read().await;
                        relay_selected_history_import_target(&ctx)
                    };
                    match target {
                        Ok(Some(target)) => {
                            if let Some(peer) = relay_terminal_peers.next_rotated() {
                                remote_selected_history_request_token =
                                    remote_selected_history_request_token.wrapping_add(1);
                                let key = RemoteSelectedHistoryRequestKey {
                                    token: remote_selected_history_request_token,
                                    peer,
                                    height: target.height,
                                    block_hash: target.block_hash,
                                };
                                pending_remote_selected_history_request = Some(
                                    PendingRemoteSelectedHistoryRequest {
                                        key,
                                        requested_at: now,
                                    },
                                );
                                last_remote_selected_history_request_at = Some(now);
                                if p2p_cmd
                                    .send(noid_p2p::NetworkCommand::RequestHistoryProof {
                                        peer,
                                        height: target.height,
                                        block_hash: target.block_hash,
                                    })
                                    .await
                                    .is_err()
                                {
                                    pending_remote_selected_history_request = None;
                                } else {
                                    tracing::debug!(
                                        peer = %peer,
                                        height = target.height,
                                        "relay requesting exact hard-finalized selected-history terminal"
                                    );
                                }
                            }
                        }
                        Ok(None) => {}
                        Err(error) => tracing::debug!(
                            err = %error,
                            "relay selected-history target unavailable"
                        ),
                    }
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
                        let gap = (highest_announced - our_height) as u16;
                        tracing::info!(
                            our_height,
                            highest_announced,
                            stale_secs,
                            peer = %peer,
                            "stale tip — re-requesting blocks"
                        );
                        let _ = p2p_cmd
                            .send(noid_p2p::NetworkCommand::SyncBlocksFrom {
                                peer,
                                from_height: our_height + 1,
                                count: gap,
                            })
                            .await;
                        last_tip_advance = Instant::now();
                    }
                }
            }

            // If we have valid candidates and the timeout has elapsed, proceed now.
            if pending_manifest.is_none()
                && pending_snapshot_header_sync.is_none()
                && snapshot_header_staging_inflight.is_none()
                && selected_history_verification_inflight.is_none()
                && remote_selected_history_verification_inflight.is_none()
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

fn cleanup_verified_selected_history_offthread(verified: VerifiedSelectedHistorySnapshot) {
    tokio::task::spawn_blocking(move || {
        let VerifiedSelectedHistorySnapshot {
            terminal_package_bytes,
            verified_headers,
            inbound_memory_permit,
            ..
        } = verified;
        let _ = verified_headers.discard();
        drop(terminal_package_bytes);
        drop(inbound_memory_permit);
    });
}

fn cleanup_finalized_snapshot_staging_offthread(staging: FinalizedSnapshotStaging) {
    tokio::task::spawn_blocking(move || drop(staging));
}

fn create_snapshot_staging_session(
    staging_root: &Path,
    manifest: &noid_p2p::protocol::GetStateManifestResponse,
) -> Result<SnapshotStagingSession, String> {
    let header_bytes = manifest
        .recent_headers
        .last()
        .ok_or_else(|| "snapshot manifest has no boundary header".to_owned())?;
    let header = noid_chain::block_header::BlockHeader::from_bytes(header_bytes)
        .map_err(|_| "snapshot boundary header decode failed".to_owned())?;
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
    let encoded_len = encoded_segment_len_for_eff_log(manifest.eff_log)
        .ok_or_else(|| "snapshot manifest effective segment log is invalid".to_owned())?;
    let encoded_len = u32::try_from(encoded_len)
        .map_err(|_| "snapshot segment encoding length does not fit u32".to_owned())?;
    let descriptors = manifest
        .segment_ids
        .iter()
        .copied()
        .zip(manifest.segment_roots.iter().copied())
        .map(|(segment_id, segment_root)| SnapshotSegmentDescriptor {
            segment_id,
            segment_root,
            encoded_len,
        })
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
/// Keyed by `block.header.prev_block_hash` so that when the missing parent
/// arrives, `orphan_pool.remove(&parent_hash)` instantly finds the child.
///
/// Eviction policy: remove the orphan with the **lowest block height** first.
/// This mimics LRU by height — stale orphans from a long-dead fork are
/// discarded before newer ones that are more likely to be resolved.
fn insert_orphan(pool: &mut std::collections::HashMap<[u8; 32], OrphanBlock>, orphan: OrphanBlock) {
    pool.insert(orphan.block.header.prev_block_hash, orphan);

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
        .min_by_key(|(_, b)| b.block.header.height)
        .map(|(key, orphan)| (*key, orphan.block.header.height, orphan.retained_bytes()))
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
                false,
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
    p2p_cmd: &tokio::sync::mpsc::Sender<noid_p2p::NetworkCommand>,
    peer: libp2p::PeerId,
    manifest: noid_p2p::protocol::GetStateManifestResponse,
    staging: FinalizedSnapshotStaging,
    selected_history: VerifiedSelectedHistorySnapshot,
    wallet_operation_gate: &WalletOperationGate,
) -> Result<u64, String> {
    if selected_history.height != manifest.tip_height
        || selected_history.block_hash != manifest.tip_hash
    {
        return Err("selected-history authority does not match snapshot manifest".into());
    }
    let snapshot_height = manifest.tip_height;
    let segment_count = staging.descriptors().len();
    let recent_headers = manifest.recent_headers;
    let VerifiedSelectedHistorySnapshot {
        height,
        block_hash,
        tier,
        terminal_package_bytes,
        verified_headers,
        inbound_memory_permit,
    } = selected_history;

    // Header history is authenticated already and persisted independently of
    // the active state tip.  Stream it through short 512-record MDBX batches
    // before taking the wallet gate or the chain write guard.  Each batch
    // rechecks its exact canonical parent in its own write transaction; the
    // final snapshot transaction below rechecks the complete target again.
    // Thus a deep O(H) header sync neither accumulates history in RAM nor
    // stalls block/wallet readers for the complete historical scan.
    let header_store = {
        let ctx = chain.read().await;
        ctx.store.clone()
    };
    let (verified_headers, promotion) = tokio::task::spawn_blocking(move || {
        let mut verified_headers = verified_headers;
        match verified_headers.promote(&header_store) {
            Ok(promotion) => Ok((verified_headers, promotion)),
            Err(error) => {
                if let Err(cleanup_error) = verified_headers.discard() {
                    tracing::warn!(
                        err = %cleanup_error,
                        "rejected snapshot header staging cleanup deferred"
                    );
                }
                Err(format!("promote authenticated snapshot headers: {error}"))
            }
        }
    })
    .await
    .map_err(|error| format!("snapshot header promotion worker panicked: {error}"))??;

    // Global order for operations that can replace the active wallet cache:
    // wallet_operation_gate -> mempool snapshot/view -> chain -> SharedWallet.
    // Keep this single acquisition across the atomic state install and wallet
    // reload, but not across the independently crash-safe header stream above.
    // None of those helpers may enter wallet RPC code that acquires the same gate.
    let wallet_operation = wallet_operation_gate.lock().await;
    let install_chain = Arc::clone(chain);
    let result = tokio::task::spawn_blocking(move || {
        // Keep both the wire allocation and its process-global inbound charge
        // alive through the atomic selected-history/snapshot commit.
        let inbound_memory_permit = inbound_memory_permit;
        let verified_headers = verified_headers;
        let mut ctx = install_chain.blocking_write();
        ctx.apply_staged_state_snapshot_with_selected_history(
            &staging,
            &recent_headers,
            noid_chain::storage::SelectedHistorySnapshotSeed {
                height,
                block_hash,
                tier,
                terminal_package_bytes: &terminal_package_bytes,
            },
        )
        .map_err(|error| format!("apply authenticated state snapshot: {error:?}"))?;
        let view = ChainView::from_mdbx(&ctx);
        let height = ctx.tip_height();
        drop(ctx);
        // Header staging cleanup is maintenance, never consensus authority.
        // It is deliberately best-effort and happens only after the snapshot
        // transaction succeeds; an error cannot roll back a safe install.
        if let Err(error) = verified_headers.discard() {
            tracing::warn!(
                err = %error,
                "authenticated snapshot header staging cleanup deferred"
            );
        }
        // The atomic MDBX commit now owns the state; release temporary files
        // before constructing consumers of the new durable view.
        drop(staging);
        drop(terminal_package_bytes);
        drop(inbound_memory_permit);
        tracing::info!(
            promoted_headers = promotion.promoted,
            already_canonical_headers = promotion.already_canonical,
            "authenticated snapshot headers promoted with state install"
        );
        Ok::<_, String>((height, view))
    })
    .await
    .map_err(|error| format!("snapshot install worker panicked: {error}"))?
    .map_err(|error| format!("failed to apply verified state snapshot: {error}"))?;

    let (applied_height, view) = result;
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
    let _ = p2p_cmd
        .send(noid_p2p::NetworkCommand::SyncBlocksFrom {
            peer,
            from_height: snapshot_height.saturating_add(1),
            count: noid_chain::consensus::params::RECENT_BLOCK_RETENTION_DEPTH as u16,
        })
        .await;
    Ok(snapshot_height)
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
    block_reward_noid: f64,
    history_proof_height: Option<u64>,
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
    let seg_size_bytes = 3u64 * 65536 * 16;
    let disk_bytes = materialized_segs as u64 * seg_size_bytes;
    let max_bytes = total_segs as u64 * seg_size_bytes;
    let hb = |n: u64| -> String {
        if n >= 1 << 30 {
            format!("{:.1}GB", n as f64 / (1 << 30) as f64)
        } else if n >= 1 << 20 {
            format!("{:.0}MB", n as f64 / (1 << 20) as f64)
        } else {
            format!("{:.0}KB", n as f64 / 1024.0)
        }
    };

    let history_proof_str = match history_proof_height {
        Some(h) if tip_height > h => format!("h={}  ({} behind)", h, tip_height - h),
        Some(h) => format!("h={h}  current"),
        None => "not available".to_string(),
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
            "{}/{} slots  {:.2}%  [{}]  {} seg  {} disk  {} max",
            active_slots,
            capacity,
            fill_pct,
            bar,
            dim(&format!("{}/{}", materialized_segs, total_segs)),
            dim(&hb(disk_bytes)),
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

    row("history proof", &dim(&history_proof_str));

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

fn load_config(path: &Path) -> Option<NodeConfig> {
    let expanded = expand_tilde(path);
    let text = std::fs::read_to_string(&expanded).ok()?;
    toml::from_str(&text).ok()
}

fn expand_tilde(p: &Path) -> PathBuf {
    let s = p.to_string_lossy();
    if let Some(rest) = s.strip_prefix("~/") {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
        PathBuf::from(format!("{home}/{rest}"))
    } else {
        p.to_path_buf()
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
