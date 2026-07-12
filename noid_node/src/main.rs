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

mod config;
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

    // --- Background checkpoint package worker ---
    let rec_chain = chain.clone();
    tokio::spawn(async move {
        run_checkpoint_package_worker(rec_chain).await;
    });

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

        let checkpoint_proof_height = ctx
            .store
            .get_checkpoint_coverage()
            .ok()
            .flatten()
            .and_then(|coverage| coverage.history_proof_covered_to);
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
            checkpoint_proof_height,
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

    tracing::info!("goodbye — MDBX flushed on drop");
    Ok(())
}

// ---------------------------------------------------------------------------
// P2P event handler
// ---------------------------------------------------------------------------

fn first_missing_snapshot_header(
    store: &noid_chain::storage::MdbxStore,
    target_height: u64,
) -> Result<Option<u64>, String> {
    for h in 0..=target_height {
        if store
            .get_header(h)
            .map_err(|e| format!("header store read h={h}: {e}"))?
            .is_none()
        {
            return Ok(Some(h));
        }
    }
    Ok(None)
}

fn persist_snapshot_header_batch(
    store: &noid_chain::storage::MdbxStore,
    expected_start: u64,
    headers: &[noid_chain::block_header::BlockHeader],
) -> Result<u64, String> {
    use noid_chain::consensus::genesis::genesis_header;
    use noid_chain::consensus::header::validate_header_timeless;
    use noid_chain::consensus::params::{EXPANSION_WINDOW, MEDIAN_TIME_BLOCKS};
    use noid_chain::consensus::pow::{block_id, validate_pow};
    use noid_chain::consensus::{add_work, asert_anchor_height, block_work};

    if headers.is_empty() {
        return Err("snapshot header sync returned an empty batch".into());
    }

    let mut sorted = headers.to_vec();
    sorted.sort_by_key(|h| h.height);
    if sorted.windows(2).any(|w| w[0].height == w[1].height) {
        return Err("snapshot header sync returned duplicate heights".into());
    }

    let mut next_height = expected_start;

    for hdr in sorted {
        if hdr.height != next_height {
            return Err(format!(
                "snapshot header sync expected h={}, got h={}",
                next_height, hdr.height
            ));
        }
        validate_pow(&hdr)
            .map_err(|_| format!("snapshot synced header h={} failed PoW", hdr.height))?;

        let hash = block_id(&hdr);
        if hdr.height == 0 {
            let expected = genesis_header();
            if hash != block_id(&expected) {
                return Err(
                    "snapshot synced genesis header does not match hardcoded genesis".into(),
                );
            }
            let chainwork = block_work(&hdr.difficulty_target);
            if let Some(existing) = store
                .get_header(0)
                .map_err(|e| format!("header store read h=0: {e}"))?
            {
                if block_id(&existing) != hash {
                    return Err("snapshot genesis conflicts with existing local header".into());
                }
            } else {
                store
                    .put_verified_header_only(&hdr, &hash, &chainwork)
                    .map_err(|e| format!("write verified genesis header: {e}"))?;
            }
            next_height = next_height.saturating_add(1);
            continue;
        }

        if let Some(existing) = store
            .get_header(hdr.height)
            .map_err(|e| format!("header store read h={}: {e}", hdr.height))?
        {
            if block_id(&existing) != hash {
                return Err(format!(
                    "snapshot header h={} conflicts with existing local header",
                    hdr.height
                ));
            }
            if store
                .get_chain_work(hdr.height)
                .map_err(|e| format!("chainwork read h={}: {e}", hdr.height))?
                .is_none()
            {
                return Err(format!(
                    "snapshot header h={} exists without chainwork",
                    hdr.height
                ));
            }
        } else {
            let parent_height = hdr.height - 1;
            let parent = store
                .get_header(parent_height)
                .map_err(|e| format!("header store read h={parent_height}: {e}"))?
                .ok_or_else(|| {
                    format!("cannot validate header h={}: missing parent", hdr.height)
                })?;
            let parent_hash = block_id(&parent);
            if hdr.prev_block_hash != parent_hash {
                return Err(format!(
                    "snapshot synced header h={} is not linked to h={}",
                    hdr.height, parent_height
                ));
            }

            let ts_start = parent_height.saturating_sub(MEDIAN_TIME_BLOCKS as u64 - 1);
            let mut prev_timestamps = Vec::new();
            for h in ts_start..=parent_height {
                let header = store
                    .get_header(h)
                    .map_err(|e| format!("timestamp header read h={h}: {e}"))?
                    .ok_or_else(|| format!("missing timestamp header h={h}"))?;
                prev_timestamps.push(header.timestamp);
            }

            let active_start = parent_height.saturating_sub(EXPANSION_WINDOW.saturating_sub(1));
            let mut prev_active_counts = Vec::new();
            for h in active_start..=parent_height {
                let header = store
                    .get_header(h)
                    .map_err(|e| format!("active-count header read h={h}: {e}"))?
                    .ok_or_else(|| format!("missing active-count header h={h}"))?;
                prev_active_counts.push(header.active_slot_count);
            }

            let anchor_height = asert_anchor_height(parent_height);
            let anchor_header = store
                .get_header(anchor_height)
                .map_err(|e| format!("ASERT anchor read h={anchor_height}: {e}"))?
                .ok_or_else(|| format!("missing ASERT anchor h={anchor_height}"))?;

            validate_header_timeless(
                &hdr,
                &parent,
                &prev_timestamps,
                &prev_active_counts,
                anchor_height,
                anchor_header.timestamp,
                &anchor_header.difficulty_target,
            )
            .map_err(|e| {
                format!(
                    "snapshot synced header h={} failed consensus: {e}",
                    hdr.height
                )
            })?;

            let parent_work = store
                .get_chain_work(parent_height)
                .map_err(|e| format!("chainwork read h={parent_height}: {e}"))?
                .ok_or_else(|| format!("missing parent chainwork h={parent_height}"))?;
            let chainwork = add_work(&parent_work, &block_work(&hdr.difficulty_target));
            store
                .put_verified_header_only(&hdr, &hash, &chainwork)
                .map_err(|e| format!("write verified header h={}: {e}", hdr.height))?;
        }

        next_height = next_height.saturating_add(1);
    }

    Ok(next_height)
}

fn verify_snapshot_history_proof_headers_anchored(
    manifest: &noid_p2p::protocol::GetStateManifestResponse,
    proof_bytes: &[u8],
    store: &noid_chain::storage::MdbxStore,
) -> Result<(), String> {
    verify_snapshot_history_proof_headers_anchored_with_minimum(
        manifest,
        proof_bytes,
        store,
        &noid_chain::consensus::params::MIN_SNAPSHOT_CHAINWORK,
    )
}

fn verify_snapshot_history_proof_headers_anchored_with_minimum(
    manifest: &noid_p2p::protocol::GetStateManifestResponse,
    proof_bytes: &[u8],
    store: &noid_chain::storage::MdbxStore,
    minimum_chainwork: &[u8; 32],
) -> Result<(), String> {
    if manifest.tip_height == 0 {
        return Err("snapshot manifest has no tip".into());
    }

    let tip_header = store
        .get_header(manifest.tip_height)
        .map_err(|e| format!("snapshot header anchor read failed: {e}"))?
        .ok_or_else(|| format!("snapshot header anchor missing h={}", manifest.tip_height))?;
    let tip_hash = noid_chain::hash_block_header(&tip_header);
    if tip_hash != manifest.tip_hash {
        return Err("snapshot manifest boundary hash does not match local canonical header".into());
    }
    if tip_header.log_slots != manifest.log_slots {
        return Err("snapshot manifest log_slots does not match local canonical header".into());
    }
    if tip_header.active_slot_count != manifest.active_slot_count {
        return Err(
            "snapshot manifest active_slot_count does not match local canonical header".into(),
        );
    }
    if tip_header.alloc_counter != manifest.alloc_counter {
        return Err("snapshot manifest alloc_counter does not match local canonical header".into());
    }
    let local_chainwork = store
        .get_chain_work(manifest.tip_height)
        .map_err(|e| format!("snapshot chainwork read failed: {e}"))?
        .ok_or_else(|| format!("snapshot chainwork missing h={}", manifest.tip_height))?;
    if local_chainwork != manifest.cumulative_chainwork {
        return Err("snapshot manifest chainwork does not match local canonical headers".into());
    }
    if noid_chain::work_gt(minimum_chainwork, &local_chainwork) {
        return Err("snapshot chainwork below minimum snapshot work floor".into());
    }

    if proof_bytes.is_empty() {
        return Err("snapshot checkpoint proof missing".into());
    }
    let proof: noid_recursive::HistoryCheckpointProof = bincode::deserialize(proof_bytes)
        .map_err(|e| format!("snapshot checkpoint proof decode failed: {e}"))?;
    if proof.engine_id != noid_recursive::HISTORY_CHECKPOINT_ENGINE_STREAMING_TOWER_IVC {
        return Err("snapshot checkpoint proof engine mismatch".into());
    }
    if proof.checkpoint_height != manifest.tip_height
        || proof.end_anchor.height != manifest.tip_height
    {
        return Err("snapshot checkpoint proof height does not match manifest".into());
    }

    let local_start_anchor =
        read_local_header_anchor(store, proof.start_anchor.height, "checkpoint start")?;
    let local_end_anchor =
        read_local_header_anchor(store, proof.end_anchor.height, "checkpoint end")?;
    noid_recursive::verify_history_checkpoint_proof_checkpoint(
        &proof,
        &local_start_anchor,
        &local_end_anchor,
    )
    .map_err(|e| format!("snapshot checkpoint proof rejected: {e}"))
}

fn read_local_header_anchor(
    store: &noid_chain::storage::MdbxStore,
    height: u64,
    label: &str,
) -> Result<noid_chain::HeaderChainAnchor, String> {
    store
        .get_header_anchor(height)
        .map_err(|e| format!("snapshot {label} header anchor read h={height} failed: {e}"))?
        .ok_or_else(|| format!("snapshot {label} header anchor missing h={height}"))
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

#[cfg(test)]
mod tests {
    use super::{
        compare_manifest_fork_choice, gap_requires_snapshot_sync,
        verify_snapshot_history_proof_headers_anchored_with_minimum, OrphanBlock,
        ProvedBlockCandidate,
    };

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
        let mut header = template.into_header(0);
        header.nonce = noid_chain::consensus::pow::search_pow(&header, 0, 1_000_000)
            .expect("easy test target mines");
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
    fn snapshot_history_boundary_checks_local_header_chainwork() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = noid_chain::storage::MdbxStore::open(dir.path()).expect("open store");

        let state = noid_chain::ChainState::with_log_slots(
            noid_chain::consensus::params::LOG_SLOTS_GENESIS
                .try_into()
                .expect("genesis log_slots fits usize"),
        );
        let h0 = noid_chain::consensus::genesis_header();
        let h0_hash = noid_chain::hash_block_header(&h0);
        let high_start_work = noid_chain::consensus::block_work(&h0.difficulty_target);
        store
            .put_verified_header_only(&h0, &h0_hash, &high_start_work)
            .expect("store genesis header");

        let start_consensus = noid_recursive::RecursiveConsensusState::from_header(
            &h0,
            high_start_work,
            0,
            h0.timestamp,
            h0.difficulty_target,
            &[h0.timestamp],
            &[h0.active_slot_count],
        );
        let start_accumulator = noid_recursive::genesis_accumulator();
        let start_anchor = noid_chain::header_anchor::compute_header_chain_anchor(
            std::iter::once(&h0),
            high_start_work,
        )
        .expect("start anchor computes");
        let block = test_coinbase_child(&h0, &state);
        let witness = noid_block::FullAcceptedBlockBatchWitness {
            items: vec![noid_block::FullAcceptedBlockBatchItem {
                block,
                block_proof_bytes: vec![],
                block_auth_sidecar_bytes: vec![],
            }],
        };
        let package =
            noid_block::prove_retained_block_certificate_batch_checkpoint_package_from_boundary(
                &start_anchor,
                &start_consensus,
                &start_accumulator,
                &h0,
                &state,
                &witness,
            )
            .expect("strict checkpoint package proves");
        let h1 = witness.items[0].block.header.clone();
        let h1_hash = noid_chain::hash_block_header(&h1);
        let h1_work = package
            .step_statement
            .batch_summary
            .end_anchor
            .cumulative_chainwork;
        store
            .put_verified_header_only(&h1, &h1_hash, &h1_work)
            .expect("store h1 header");

        let manifest = noid_p2p::protocol::GetStateManifestResponse {
            tip_height: 1,
            tip_hash: h1_hash,
            cumulative_chainwork: h1_work,
            log_slots: h1.log_slots,
            active_slot_count: h1.active_slot_count,
            alloc_counter: h1.alloc_counter,
            ..Default::default()
        };
        assert!(verify_snapshot_history_proof_headers_anchored_with_minimum(
            &manifest,
            &[],
            &store,
            &high_start_work,
        )
        .expect_err("missing proof must reject")
        .contains("checkpoint proof missing"));

        let checkpoint_proof = noid_block::public_history_checkpoint_proof_from_package(
            &start_anchor,
            &start_accumulator,
            &package,
        )
        .expect("public checkpoint proof exports from strict package");
        let checkpoint_proof_bytes =
            bincode::serialize(&checkpoint_proof).expect("serialize checkpoint proof");
        verify_snapshot_history_proof_headers_anchored_with_minimum(
            &manifest,
            &checkpoint_proof_bytes,
            &store,
            &high_start_work,
        )
        .expect("strict checkpoint proof verifies");

        // A proof for another same-height fork must not pass merely because
        // execution roots/counters and chainwork are identical. The local tip
        // block id commits to the selected header and its ancestry.
        let alt_dir = tempfile::tempdir().expect("alternate tempdir");
        let alt_store =
            noid_chain::storage::MdbxStore::open(alt_dir.path()).expect("open alternate store");
        alt_store
            .put_verified_header_only(&h0, &h0_hash, &high_start_work)
            .expect("store alternate genesis header");
        let mut alt_h1 = h1;
        alt_h1.nonce =
            noid_chain::consensus::pow::search_pow(&alt_h1, h1.nonce.wrapping_add(1), 1_000_000)
                .expect("alternate easy test nonce mines");
        let alt_h1_hash = noid_chain::hash_block_header(&alt_h1);
        assert_ne!(alt_h1_hash, h1_hash);
        alt_store
            .put_verified_header_only(&alt_h1, &alt_h1_hash, &h1_work)
            .expect("store alternate h1 header");
        let alt_manifest = noid_p2p::protocol::GetStateManifestResponse {
            tip_hash: alt_h1_hash,
            ..manifest.clone()
        };
        assert!(verify_snapshot_history_proof_headers_anchored_with_minimum(
            &alt_manifest,
            &checkpoint_proof_bytes,
            &alt_store,
            &high_start_work,
        )
        .expect_err("proof for another local fork must reject")
        .contains("end anchor mismatch"));

        let mut tampered_tip = checkpoint_proof.clone();
        tampered_tip.end_anchor.block_id[0] ^= 0x01;
        let tampered_tip_bytes =
            bincode::serialize(&tampered_tip).expect("serialize tampered proof");
        assert!(verify_snapshot_history_proof_headers_anchored_with_minimum(
            &manifest,
            &tampered_tip_bytes,
            &store,
            &high_start_work,
        )
        .expect_err("proof-supplied tip id must not be trusted")
        .contains("end anchor mismatch"));

        let mut bad = manifest.clone();
        bad.cumulative_chainwork = [3u8; 32];
        assert!(verify_snapshot_history_proof_headers_anchored_with_minimum(
            &bad,
            &[],
            &store,
            &high_start_work,
        )
        .expect_err("bad chainwork must reject")
        .contains("chainwork"));

        let mut low_work = [0u8; 32];
        low_work[0] = 1;
        store
            .put_verified_header_only(&h1, &h1_hash, &low_work)
            .expect("overwrite h1 low chainwork");
        let low_work_manifest = noid_p2p::protocol::GetStateManifestResponse {
            cumulative_chainwork: low_work,
            ..manifest
        };
        assert!(verify_snapshot_history_proof_headers_anchored_with_minimum(
            &low_work_manifest,
            &[],
            &store,
            &high_start_work,
        )
        .expect_err("below minimum snapshot work must reject")
        .contains("minimum snapshot work"));
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
    //   (1) receive immutable checkpoint snapshot manifest
    //   (2) verify the O(1) history/checkpoint proof for the manifest boundary
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
    }
    struct PendingSnapshotHeaderSync {
        from: libp2p::PeerId,
        manifest: Box<noid_p2p::protocol::GetStateManifestResponse>,
        next_height: u64,
        target_height: u64,
    }
    let mut pending_manifest: Option<PendingManifest> = None;
    let mut pending_snapshot_header_sync: Option<PendingSnapshotHeaderSync> = None;
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
            pending_manifest = None;
            pending_snapshot_header_sync = None;
            manifest_candidates.clear();
            manifest_requested_peers.clear();
            manifest_force_snapshot_peers.clear();
            manifest_response_count = 0;
            manifest_first_candidate_at = None;
            snapshot_staging = None;
            pending_segment_ids.clear();
            segment_queue.clear();
            tracing::debug!("sync state reset — ready for fresh manifest retry");
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
            Ok(NetworkEvent::MempoolSyncResponse { from, txs }) => {
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

                if pending_snapshot_header_sync
                    .as_ref()
                    .is_some_and(|sync| sync.from == from)
                {
                    let mut sync = pending_snapshot_header_sync
                        .take()
                        .expect("checked pending snapshot header sync");
                    if headers.is_empty() {
                        tracing::warn!(peer = %from, "snapshot header sync returned empty batch");
                        reset_sync_state!();
                        continue;
                    }

                    let next = {
                        let ctx = chain.read().await;
                        persist_snapshot_header_batch(&ctx.store, sync.next_height, &headers)
                    };
                    let next = match next {
                        Ok(next) => next,
                        Err(e) => {
                            tracing::warn!(peer = %from, err = %e, "snapshot header sync rejected batch");
                            reset_sync_state!();
                            continue;
                        }
                    };

                    if next <= sync.target_height {
                        sync.next_height = next;
                        let count = (sync.target_height - next + 1).min(512) as u16;
                        tracing::info!(
                            peer = %from,
                            next_height = next,
                            target_height = sync.target_height,
                            "snapshot: fetching header batch for headers-anchored verification"
                        );
                        pending_snapshot_header_sync = Some(sync);
                        fetch_in_progress.insert(from);
                        let _ = p2p_cmd
                            .send(noid_p2p::NetworkCommand::FetchHeaders {
                                peer: from,
                                start_height: next,
                                count,
                            })
                            .await;
                    } else {
                        tracing::info!(
                            peer = %from,
                            target_height = sync.target_height,
                            "snapshot: header chain synced — requesting history proof again"
                        );
                        pending_manifest = Some(PendingManifest {
                            from,
                            manifest: sync.manifest,
                        });
                        let _ = p2p_cmd
                            .send(noid_p2p::NetworkCommand::RequestHistoryProof { peer: from })
                            .await;
                    }
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

                if manifest.tip_height > 0 && pending_manifest.is_some() {
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
                if pending_manifest.is_none() && !manifest_candidates.is_empty() {
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
                        pending_manifest = Some(PendingManifest {
                            from: best_peer,
                            manifest: best_manifest,
                        });
                        let _ = p2p_cmd
                            .send(noid_p2p::NetworkCommand::RequestHistoryProof {
                                peer: best_peer,
                            })
                            .await;
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
                // never accumulates in the node process.
                if pending_segment_ids.contains(&response.segment_id) {
                    if pending_manifest
                        .as_ref()
                        .is_some_and(|pending| pending.from != from)
                    {
                        tracing::warn!(from = %from, segment = response.segment_id, "ignoring snapshot segment from non-selected peer");
                        continue;
                    }
                    if let Some(data) = response.data {
                        let Some(staging) = snapshot_staging.as_mut() else {
                            tracing::warn!(from = %from, "segment received without snapshot staging session");
                            reset_sync_state!();
                            continue;
                        };
                        if let Err(error) = staging.accept_segment(
                            response.segment_id,
                            response.eff_log,
                            &data,
                        ) {
                            tracing::warn!(
                                from = %from,
                                segment = response.segment_id,
                                err = %error,
                                "snapshot segment authentication/staging failed"
                            );
                            reset_sync_state!();
                            continue;
                        }
                        drop(data);
                        pending_segment_ids.remove(&response.segment_id);
                        // Dispatch next queued segment if available.
                        if !segment_queue.is_empty() {
                            if let Some(ref pm) = pending_manifest {
                                if let Some(next_seg) = segment_queue.pop_front() {
                                    pending_segment_ids.insert(next_seg);
                                    let _ = p2p_cmd
                                        .send(noid_p2p::NetworkCommand::RequestStateSegment {
                                            peer: pm.from,
                                            segment_id: next_seg,
                                            expected_tip_height: pm.manifest.tip_height,
                                            expected_tip_hash: pm.manifest.tip_hash,
                                        })
                                        .await;
                                }
                            }
                        }
                        tracing::debug!(
                            from = %from,
                            segment = response.segment_id,
                            remaining = pending_segment_ids.len() + segment_queue.len(),
                            "segment received"
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

                    // All segments received: independently verify the complete
                    // exact root in a one-segment second pass, then install.
                    if pending_segment_ids.is_empty() && segment_queue.is_empty() {
                        if let Some(pending) = pending_manifest.take() {
                            let Some(staging) = snapshot_staging.take() else {
                                tracing::warn!(from = %from, "snapshot completed without staging session");
                                reset_sync_state!();
                                continue;
                            };
                            let segment_count = staging.descriptors().len();
                            let finalized = match staging.finalize() {
                                Ok(finalized) => finalized,
                                Err(error) => {
                                    tracing::warn!(from = %from, err = %error, "snapshot exact-state finalization failed");
                                    reset_sync_state!();
                                    continue;
                                }
                            };
                            tracing::info!(
                                segments = segment_count,
                                tip = pending.manifest.tip_height,
                                "snapshot: all segments finalized on disk, writing to MDBX…"
                            );
                            match apply_verified_snapshot(
                                &chain,
                                &mempool,
                                &wallet,
                                &p2p_cmd,
                                from,
                                *pending.manifest,
                                finalized,
                                &wallet_operation_gate,
                            )
                            .await
                            {
                                Ok(_) => sync_ready.notify_one(),
                                Err(e) => {
                                    tracing::error!(err = %e, "failed to apply verified state snapshot");
                                    reset_sync_state!();
                                }
                            }
                        }
                    }
                }
            }

            Ok(NetworkEvent::HistoryProof {
                from,
                proof_bytes,
                tip_header_bytes,
            }) => {
                // Check the current checkpoint proof envelope before applying an
                // immutable snapshot. Header consensus is checked natively from
                // stored headers; full trustless O(1) authority requires the
                // recursive decider proof.

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

                let snap = match pending_manifest.take() {
                    Some(p) if p.from == from => p,
                    Some(p) => {
                        tracing::warn!(
                            proof_from = %from, manifest_from = %p.from,
                            "history proof from unexpected peer, discarding pending manifest"
                        );
                        pending_manifest = Some(p);
                        continue;
                    }
                    None => {
                        tracing::debug!(from = %from, "unexpected history proof, no pending manifest");
                        continue;
                    }
                };

                let target_height = snap.manifest.tip_height;
                    let missing_header = {
                        let ctx = chain.read().await;
                        first_missing_snapshot_header(&ctx.store, target_height)
                    };
                    let missing_header = match missing_header {
                        Ok(missing) => missing,
                        Err(e) => {
                            tracing::warn!(from = %from, err = %e, "snapshot header DB check failed");
                            reset_sync_state!();
                            continue;
                        }
                    };

                    if let Some(start_height) = missing_header {
                        let count = (target_height - start_height + 1).min(512) as u16;
                        tracing::info!(
                            from = %from,
                            start_height,
                            target_height,
                            "snapshot: local headers incomplete — fetching headers before proof verification"
                        );
                        pending_snapshot_header_sync = Some(PendingSnapshotHeaderSync {
                            from,
                            manifest: snap.manifest,
                            next_height: start_height,
                            target_height,
                        });
                        fetch_in_progress.insert(from);
                        let _ = p2p_cmd
                            .send(noid_p2p::NetworkCommand::FetchHeaders {
                                peer: from,
                                start_height,
                                count,
                            })
                            .await;
                        continue;
                    }

                    let verify_result = {
                        let ctx = chain.read().await;
                        verify_snapshot_history_proof_headers_anchored(
                            &snap.manifest,
                            &proof_bytes,
                            &ctx.store,
                        )
                    };

                    match verify_result {
                        Ok(()) => {
                            let peer_tip_height = if tip_header_bytes.is_empty() {
                                snap.manifest.tip_height
                            } else {
                                match noid_chain::block_header::BlockHeader::from_bytes(
                                    &tip_header_bytes,
                                ) {
                                    Ok(header) => header.height,
                                    Err(error) => {
                                        tracing::warn!(from = %from, err = ?error, "snapshot proof response carried bad peer tip header");
                                        reset_sync_state!();
                                        continue;
                                    }
                                }
                            };
                            if peer_tip_height < snap.manifest.tip_height {
                                tracing::warn!(
                                    from = %from,
                                    snapshot_height = snap.manifest.tip_height,
                                    peer_tip_height,
                                    "snapshot proof peer tip is behind manifest boundary"
                                );
                                reset_sync_state!();
                                continue;
                            }
                            let suffix_len = peer_tip_height - snap.manifest.tip_height;
                            if suffix_len
                                > noid_chain::consensus::params::RECENT_BLOCK_RETENTION_DEPTH
                            {
                                tracing::warn!(
                                    from = %from,
                                    snapshot_height = snap.manifest.tip_height,
                                    peer_tip_height,
                                    suffix_len,
                                    "snapshot boundary is outside the peer's retained suffix"
                                );
                                reset_sync_state!();
                                continue;
                            }
                            if peer_tip_height > highest_announced {
                                highest_announced = peer_tip_height;
                                last_announcement_peer = Some(from);
                            }
                            tracing::info!(
                                from = %from,
                                tip = snap.manifest.tip_height,
                                peer_tip_height,
                                segments = snap.manifest.segment_ids.len(),
                                "snapshot manifest accepted — staging authenticated boundary"
                            );
                            let staging = match create_snapshot_staging_session(
                                &snapshot_staging_root,
                                &snap.manifest,
                            ) {
                                Ok(staging) => staging,
                                Err(error) => {
                                    tracing::warn!(peer = %from, err = %error, "snapshot staging initialization failed");
                                    reset_sync_state!();
                                    continue;
                                }
                            };
                            snapshot_staging = Some(staging);
                            queue_snapshot_segment_download(
                                &p2p_cmd,
                                from,
                                &snap.manifest,
                                &mut pending_segment_ids,
                                &mut segment_queue,
                            )
                            .await;
                            // Restore pending_manifest for the StateSegment handler to use.
                            pending_manifest = Some(PendingManifest {
                                from,
                                manifest: snap.manifest,
                            });
                            if pending_segment_ids.is_empty() && segment_queue.is_empty() {
                                // No segments (fresh network, no UTXOs yet).
                                // Finalize the authenticated empty-state session.
                                let pending = pending_manifest.take().unwrap();
                                let finalized = match snapshot_staging
                                    .take()
                                    .expect("snapshot staging exists before segment download")
                                    .finalize()
                                {
                                    Ok(finalized) => finalized,
                                    Err(error) => {
                                        tracing::warn!(peer = %from, err = %error, "empty snapshot finalization failed");
                                        reset_sync_state!();
                                        continue;
                                    }
                                };
                                match apply_verified_snapshot(
                                    &chain,
                                    &mempool,
                                    &wallet,
                                    &p2p_cmd,
                                    from,
                                    *pending.manifest,
                                    finalized,
                                    &wallet_operation_gate,
                                )
                                .await
                                {
                                    Ok(_) => sync_ready.notify_one(),
                                    Err(e) => {
                                        tracing::error!(err = %e, "failed to apply empty snapshot");
                                        reset_sync_state!();
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            tracing::error!(
                                from = %from, tip = snap.manifest.tip_height, err = %e,
                                "REJECTED manifest: checkpoint proof verification failed — \
                                 possible Eclipse attack or fabricated state"
                            );
                            reset_sync_state!();
                            continue;
                        }
                    }
            }
            Ok(NetworkEvent::PeerDisconnected(peer)) => {
                tracing::debug!(peer = %peer, "peer disconnected");
                let snapshot_sync_lost = pending_manifest
                    .as_ref()
                    .is_some_and(|pending| pending.from == peer)
                    || pending_snapshot_header_sync
                        .as_ref()
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

        // Heartbeat: re-evaluate manifest timeout without waiting for a new P2P event.
        _ = heartbeat.tick() => {
            let now = Instant::now();
            let fetch_cutoff = now - FETCH_DEDUP_TTL;
            recent_header_fetches.retain(|_, t| *t >= fetch_cutoff);
            recent_block_fetches.retain(|_, t| *t >= fetch_cutoff);
            pending_block_fetches
                .retain(|_, pending| now.duration_since(pending.requested_at) < BLOCK_FETCH_INFLIGHT_TTL);

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
            if pending_manifest.is_none() && !manifest_candidates.is_empty() {
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
                    pending_manifest = Some(PendingManifest {
                        from: best_peer,
                        manifest: best_manifest,
                    });
                    let _ = p2p_cmd
                        .send(noid_p2p::NetworkCommand::RequestHistoryProof { peer: best_peer })
                        .await;
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
    let mut launched = 0usize;
    while launched < MAX_INFLIGHT_SEGMENTS {
        if let Some(seg_id) = segment_queue.pop_front() {
            pending_segment_ids.insert(seg_id);
            let _ = p2p_cmd
                .send(noid_p2p::NetworkCommand::RequestStateSegment {
                    peer,
                    segment_id: seg_id,
                    expected_tip_height: manifest.tip_height,
                    expected_tip_hash: manifest.tip_hash,
                })
                .await;
            launched += 1;
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
    wallet_operation_gate: &WalletOperationGate,
) -> Result<u64, String> {
    // Global order for operations that can replace the active wallet cache:
    // wallet_operation_gate -> mempool snapshot/view -> chain -> SharedWallet.
    // Keep this single acquisition across snapshot install and wallet reload.
    // None of those helpers may enter wallet RPC code that acquires the same gate.
    let wallet_operation = wallet_operation_gate.lock().await;
    let snapshot_height = manifest.tip_height;
    let segment_count = staging.descriptors().len();
    let recent_headers = manifest.recent_headers;
    let install_chain = Arc::clone(chain);
    let result = tokio::task::spawn_blocking(move || {
        let mut ctx = install_chain.blocking_write();
        ctx.apply_staged_state_snapshot(&staging, &recent_headers)?;
        // The atomic MDBX commit now owns the state; release temporary files
        // before constructing consumers of the new durable view.
        drop(staging);
        let view = ChainView::from_mdbx(&ctx);
        let height = ctx.tip_height();
        Ok::<_, noid_chain::storage::MdbxContextError>((height, view))
    })
    .await
    .map_err(|error| format!("snapshot install worker panicked: {error}"))?
    .map_err(|error| format!("failed to apply verified state snapshot: {error:?}"))?;

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
// Accepted-block certificate batch checkpoint package worker helpers
// ---------------------------------------------------------------------------

struct CertificateBatchPackageBuildInput {
    previous_head: noid_recursive::HistoryCheckpointHead,
    start_anchor: noid_chain::HeaderChainAnchor,
    start_consensus: noid_recursive::RecursiveConsensusState,
    start_accumulator: noid_recursive::ChainAccumulator,
    end_anchor: noid_chain::HeaderChainAnchor,
    end_consensus: noid_recursive::RecursiveConsensusState,
    start_height: u64,
    end_height: u64,
    witness: noid_block::AcceptedBlockCertificateBatchWitness,
}

fn recursive_consensus_state_at_height(
    store: &noid_chain::storage::MdbxStore,
    height: u64,
) -> Result<noid_recursive::RecursiveConsensusState, String> {
    use noid_chain::consensus::header::asert_anchor_height;
    use noid_chain::consensus::params::{EXPANSION_WINDOW, MEDIAN_TIME_BLOCKS};

    let header = store
        .get_header(height)
        .map_err(|e| format!("read header h={height}: {e}"))?
        .ok_or_else(|| format!("missing header h={height}"))?;
    let cumulative_chainwork = store
        .get_chain_work(height)
        .map_err(|e| format!("read chainwork h={height}: {e}"))?
        .ok_or_else(|| format!("missing chainwork h={height}"))?;

    let timestamp_start = height.saturating_sub(MEDIAN_TIME_BLOCKS as u64 - 1);
    let mut prev_timestamps = Vec::new();
    for h in timestamp_start..=height {
        let header = store
            .get_header(h)
            .map_err(|e| format!("read timestamp header h={h}: {e}"))?
            .ok_or_else(|| format!("missing timestamp header h={h}"))?;
        prev_timestamps.push(header.timestamp);
    }

    let active_start = height.saturating_sub(EXPANSION_WINDOW.saturating_sub(1));
    let mut prev_active_counts = Vec::new();
    for h in active_start..=height {
        let header = store
            .get_header(h)
            .map_err(|e| format!("read active-count header h={h}: {e}"))?
            .ok_or_else(|| format!("missing active-count header h={h}"))?;
        prev_active_counts.push(header.active_slot_count);
    }

    let anchor_height = asert_anchor_height(height);
    let anchor_header = store
        .get_header(anchor_height)
        .map_err(|e| format!("read ASERT anchor header h={anchor_height}: {e}"))?
        .ok_or_else(|| format!("missing ASERT anchor header h={anchor_height}"))?;

    Ok(noid_recursive::RecursiveConsensusState::from_header(
        &header,
        cumulative_chainwork,
        anchor_height,
        anchor_header.timestamp,
        anchor_header.difficulty_target,
        &prev_timestamps,
        &prev_active_counts,
    ))
}

fn accepted_block_certificate_batch_witness_from_store(
    store: &noid_chain::storage::MdbxStore,
    start_height: u64,
    end_height: u64,
) -> Result<noid_block::AcceptedBlockCertificateBatchWitness, String> {
    let mut items =
        Vec::with_capacity(end_height.saturating_sub(start_height).saturating_add(1) as usize);
    for height in start_height..=end_height {
        let header = store
            .get_header(height)
            .map_err(|e| format!("read canonical header h={height}: {e}"))?
            .ok_or_else(|| format!("missing canonical header h={height}"))?;
        let bytes = store
            .get_accepted_block_certificate(height)
            .map_err(|e| format!("read accepted-block certificate h={height}: {e}"))?
            .ok_or_else(|| format!("missing accepted-block certificate h={height}"))?;
        let certificate_record: noid_block::AcceptedBlockCertificateRecord =
            bincode::deserialize(&bytes)
                .map_err(|e| format!("decode accepted-block certificate h={height}: {e}"))?;
        if certificate_record.height != height || certificate_record.statement.height != height {
            return Err(format!(
                "accepted-block certificate height mismatch h={height}"
            ));
        }
        items.push(noid_block::AcceptedBlockCertificateBatchItem {
            header,
            certificate_record,
        });
    }
    Ok(noid_block::AcceptedBlockCertificateBatchWitness { items })
}

fn certificate_batch_package_matches_canonical(
    store: &noid_chain::storage::MdbxStore,
    package: &noid_block::AcceptedBlockCertificateBatchCheckpointPackage,
) -> Result<bool, String> {
    let start_height = package.start_height();
    let end_height = package.end_height();
    if end_height != package.step_statement.batch_summary.end_anchor.height {
        return Ok(false);
    }
    let local_start_anchor = store
        .get_header_anchor(start_height)
        .map_err(|e| format!("read start anchor h={start_height}: {e}"))?;
    let local_end_anchor = store
        .get_header_anchor(end_height)
        .map_err(|e| format!("read end anchor h={end_height}: {e}"))?;
    Ok(
        local_start_anchor.as_ref() == Some(&package.step_statement.batch_summary.start_anchor)
            && local_end_anchor.as_ref() == Some(&package.step_statement.batch_summary.end_anchor),
    )
}

fn latest_canonical_certificate_batch_package(
    ctx: &MdbxChainContext,
) -> Result<Option<noid_block::AcceptedBlockCertificateBatchCheckpointPackage>, String> {
    loop {
        let Some(height) = ctx
            .store
            .latest_accepted_block_batch_certificate_package_height()
            .map_err(|e| {
                format!("read latest accepted-block certificate batch package height: {e}")
            })?
        else {
            return Ok(None);
        };
        let Some(bytes) = ctx
            .store
            .get_accepted_block_batch_certificate_package(height)
            .map_err(|e| {
                format!("read accepted-block certificate batch package h={height}: {e}")
            })?
        else {
            return Ok(None);
        };
        let package: noid_block::AcceptedBlockCertificateBatchCheckpointPackage =
            match bincode::deserialize(&bytes) {
                Ok(package) => package,
                Err(e) => {
                    tracing::warn!(
                        height,
                        err = %e,
                        "accepted-block certificate batch package decode failed; deleting stale bytes"
                    );
                    ctx.store
                        .delete_accepted_block_batch_certificate_package(height)
                        .map_err(|e| format!("delete bad accepted-block certificate batch package h={height}: {e}"))?;
                    continue;
                }
            };
        if package.end_height() != height
            || !certificate_batch_package_matches_canonical(&ctx.store, &package)?
        {
            tracing::warn!(
                height,
                package_end = package.end_height(),
                "accepted-block certificate batch package no longer matches canonical headers; deleting"
            );
            ctx.store
                .delete_accepted_block_batch_certificate_package(height)
                .map_err(|e| {
                    format!("delete stale accepted-block certificate batch package h={height}: {e}")
                })?;
            continue;
        }
        return Ok(Some(package));
    }
}

fn prepare_certificate_batch_package_build(
    ctx: &mut MdbxChainContext,
) -> Result<Option<CertificateBatchPackageBuildInput>, String> {
    use noid_recursive::{
        genesis_accumulator, history_checkpoint_head_from_boundary,
        HISTORY_CHECKPOINT_BATCH_TARGET_BLOCKS,
    };

    let tip = ctx.tip_height();
    let latest_package = latest_canonical_certificate_batch_package(ctx)?;
    let start_height = latest_package
        .as_ref()
        .map_or(1, |package| package.end_height().saturating_add(1));
    let batch_len = HISTORY_CHECKPOINT_BATCH_TARGET_BLOCKS as u64;
    let end_height = start_height.saturating_add(batch_len).saturating_sub(1);
    if end_height > tip {
        return Ok(None);
    }

    let start_parent_height = start_height.saturating_sub(1);
    let start_anchor = match latest_package.as_ref() {
        Some(package) => package.step_statement.batch_summary.end_anchor.clone(),
        None => ctx
            .store
            .get_header_anchor(start_parent_height)
            .map_err(|e| format!("read genesis/start anchor h={start_parent_height}: {e}"))?
            .ok_or_else(|| format!("missing genesis/start anchor h={start_parent_height}"))?,
    };
    let start_consensus = latest_package.as_ref().map_or_else(
        || recursive_consensus_state_at_height(&ctx.store, start_parent_height),
        |package| Ok(package.step_statement.batch_summary.end_consensus.clone()),
    )?;
    let start_accumulator = latest_package.as_ref().map_or_else(
        || Ok::<noid_recursive::ChainAccumulator, String>(genesis_accumulator()),
        |package| Ok(package.step_statement.batch_summary.end_accumulator.clone()),
    )?;
    let previous_head = match latest_package {
        Some(package) => package.step_statement.next_head,
        None => history_checkpoint_head_from_boundary(
            &start_anchor,
            &start_accumulator,
            &start_consensus,
        )
        .map_err(|e| format!("build initial checkpoint head: {e:?}"))?,
    };
    let end_anchor = ctx
        .store
        .get_header_anchor(end_height)
        .map_err(|e| format!("read package end anchor h={end_height}: {e}"))?
        .ok_or_else(|| format!("missing package end anchor h={end_height}"))?;
    let end_consensus = recursive_consensus_state_at_height(&ctx.store, end_height)?;
    let witness =
        accepted_block_certificate_batch_witness_from_store(&ctx.store, start_height, end_height)?;

    Ok(Some(CertificateBatchPackageBuildInput {
        previous_head,
        start_anchor,
        start_consensus,
        start_accumulator,
        end_anchor,
        end_consensus,
        start_height,
        end_height,
        witness,
    }))
}

async fn try_build_next_certificate_batch_package(chain: &Arc<RwLock<MdbxChainContext>>) -> bool {
    let build_input = {
        let mut ctx = chain.write().await;
        match prepare_certificate_batch_package_build(&mut ctx) {
            Ok(Some(input)) => input,
            Ok(None) => return false,
            Err(e) => {
                tracing::warn!(err = %e, "accepted-block certificate batch package build preparation failed");
                return false;
            }
        }
    };
    let start_height = build_input.start_height;
    let end_height = build_input.end_height;
    tracing::info!(
        start_height,
        end_height,
        "accepted-block certificate batch package: proving checkpoint chunk"
    );
    let prove_started = std::time::Instant::now();
    let result = tokio::task::spawn_blocking(move || {
        let package = noid_block::prove_accepted_block_certificate_batch_checkpoint_package(
            &build_input.previous_head,
            &build_input.start_anchor,
            &build_input.end_anchor,
            &build_input.start_consensus,
            &build_input.end_consensus,
            &build_input.start_accumulator,
            &build_input.witness,
        )
        .map_err(|e| format!("prove accepted-block certificate batch package: {e:?}"))?;
        noid_block::verify_accepted_block_certificate_batch_checkpoint_package(&package)
            .map_err(|e| format!("verify accepted-block certificate batch package: {e:?}"))?;
        let bytes = bincode::serialize(&package)
            .map_err(|e| format!("serialize accepted-block certificate batch package: {e}"))?;
        Ok::<_, String>((package, bytes))
    })
    .await;

    let (package, bytes) = match result {
        Ok(Ok(package)) => package,
        Ok(Err(e)) => {
            tracing::warn!(
                start_height,
                end_height,
                err = %e,
                "accepted-block certificate batch package proof failed"
            );
            return false;
        }
        Err(e) => {
            tracing::error!(
                start_height,
                end_height,
                err = ?e,
                "accepted-block certificate batch package task panicked"
            );
            return false;
        }
    };

    let stored = {
        let ctx = chain.read().await;
        match certificate_batch_package_matches_canonical(&ctx.store, &package) {
            Ok(true) => ctx
                .store
                .put_accepted_block_batch_certificate_package(package.end_height(), &bytes)
                .is_ok(),
            Ok(false) => {
                tracing::warn!(
                    start_height,
                    end_height,
                    "accepted-block certificate batch package became non-canonical before store"
                );
                false
            }
            Err(e) => {
                tracing::warn!(
                    start_height,
                    end_height,
                    err = %e,
                    "accepted-block certificate batch package canonicality check failed before store"
                );
                false
            }
        }
    };
    if stored {
        tracing::info!(
            start_height,
            end_height,
            prove_ms = prove_started.elapsed().as_millis(),
            bytes = bytes.len(),
            "accepted-block certificate batch package stored"
        );
    }
    stored
}

async fn try_promote_certificate_batch_package_coverage(
    chain: &Arc<RwLock<MdbxChainContext>>,
) -> bool {
    use noid_chain::checkpoint::CheckpointCoverage;
    use noid_chain::consensus::params::CONSENSUS_FINALITY_DEPTH;

    let (candidate, previous_record, base_anchor, base_accumulator) = {
        let ctx = chain.read().await;
        let finalized_tip = ctx.tip_height().saturating_sub(CONSENSUS_FINALITY_DEPTH);
        let current_covered = ctx
            .store
            .get_checkpoint_coverage()
            .ok()
            .flatten()
            .and_then(|coverage| coverage.history_proof_covered_to)
            .unwrap_or(0);
        let next_end = current_covered
            .saturating_add(noid_recursive::HISTORY_CHECKPOINT_BATCH_TARGET_BLOCKS as u64);
        if next_end == 0 || next_end > finalized_tip {
            return false;
        }
        let previous_record = if current_covered == 0 {
            None
        } else {
            let Some(bytes) = (match ctx
                .store
                .get_history_checkpoint_head_record(current_covered)
            {
                Ok(bytes) => bytes,
                Err(e) => {
                    tracing::warn!(
                        height = current_covered,
                        err = %e,
                        "history checkpoint head record read failed"
                    );
                    return false;
                }
            }) else {
                tracing::warn!(
                    height = current_covered,
                    "checkpoint coverage exists without matching head record"
                );
                return false;
            };
            let record: noid_recursive::StoredHistoryCheckpointHeadRecord =
                match bincode::deserialize(&bytes) {
                    Ok(record) => record,
                    Err(e) => {
                        tracing::warn!(
                            height = current_covered,
                            err = %e,
                            "history checkpoint head record decode failed"
                        );
                        return false;
                    }
                };
            if let Err(e) = noid_recursive::verify_history_checkpoint_head_record(&record) {
                tracing::warn!(
                    height = current_covered,
                    err = %e,
                    "history checkpoint head record verification failed"
                );
                return false;
            }
            Some(record)
        };
        let Some(bytes) = (match ctx
            .store
            .get_accepted_block_batch_certificate_package(next_end)
        {
            Ok(bytes) => bytes,
            Err(e) => {
                tracing::warn!(
                    end_height = next_end,
                    err = %e,
                    "accepted-block certificate batch package coverage read failed"
                );
                return false;
            }
        }) else {
            return false;
        };
        let package: noid_block::AcceptedBlockCertificateBatchCheckpointPackage =
            match bincode::deserialize(&bytes) {
                Ok(package) => package,
                Err(e) => {
                    tracing::warn!(
                        end_height = next_end,
                        err = %e,
                        "accepted-block certificate batch package coverage decode failed"
                    );
                    return false;
                }
            };
        if package.end_height() != next_end {
            tracing::warn!(
                expected_end = next_end,
                package_end = package.end_height(),
                "accepted-block certificate batch package coverage end mismatch"
            );
            return false;
        }
        let (base_anchor, base_accumulator) = match previous_record.as_ref() {
            Some(record) => {
                let proof = match noid_recursive::public_history_checkpoint_proof_from_head_record(
                    record,
                ) {
                    Ok(proof) => proof,
                    Err(e) => {
                        tracing::warn!(
                            height = record.height,
                            err = %e,
                            "previous history checkpoint head proof decode failed"
                        );
                        return false;
                    }
                };
                (proof.start_anchor, proof.start_accumulator)
            }
            None => (
                package.step_statement.batch_summary.start_anchor.clone(),
                package
                    .step_statement
                    .batch_summary
                    .start_accumulator
                    .clone(),
            ),
        };
        (package, previous_record, base_anchor, base_accumulator)
    };

    let end_height = candidate.end_height();
    let verify_candidate = candidate.clone();
    let previous_record_for_task = previous_record.clone();
    let head_record_result = tokio::task::spawn_blocking(move || {
        noid_block::verify_accepted_block_certificate_batch_checkpoint_package(&verify_candidate)
            .map_err(|e| format!("verify package: {e:?}"))?;
        let head_record = noid_recursive::prove_history_checkpoint_recursive_head_record(
            previous_record_for_task.as_ref(),
            &base_anchor,
            &base_accumulator,
            &verify_candidate.step_statement,
            &verify_candidate.certificate_batch_statement,
            &verify_candidate.checkpoint_step_proof,
        )
        .map_err(|e| format!("prove recursive head record: {e}"))?;
        noid_recursive::verify_history_checkpoint_head_record_transition(
            previous_record_for_task.as_ref(),
            &head_record,
        )
        .map_err(|e| format!("verify recursive head record: {e}"))?;
        let head_record_bytes = bincode::serialize(&head_record)
            .map_err(|e| format!("serialize recursive head record: {e}"))?;
        Ok::<_, String>((head_record, head_record_bytes))
    })
    .await;
    let (head_record, head_record_bytes) = match head_record_result {
        Ok(Ok(record)) => record,
        Ok(Err(e)) => {
            tracing::warn!(
                end_height,
                err = %e,
                "accepted-block certificate batch package recursive head promotion failed"
            );
            return false;
        }
        Err(e) => {
            tracing::error!(
                end_height,
                err = ?e,
                "accepted-block certificate batch package recursive head promotion task panicked"
            );
            return false;
        }
    };

    let promoted = {
        let ctx = chain.read().await;
        let finalized_tip = ctx.tip_height().saturating_sub(CONSENSUS_FINALITY_DEPTH);
        if end_height > finalized_tip {
            return false;
        }
        match certificate_batch_package_matches_canonical(&ctx.store, &candidate) {
            Ok(true) => {}
            Ok(false) => {
                tracing::warn!(
                    end_height,
                    "accepted-block certificate batch package became non-canonical before coverage promotion"
                );
                return false;
            }
            Err(e) => {
                tracing::warn!(
                    end_height,
                    err = %e,
                    "accepted-block certificate batch package canonicality check failed before coverage promotion"
                );
                return false;
            }
        }
        let end_anchor = candidate.step_statement.batch_summary.end_anchor.clone();
        let existing = ctx.store.get_checkpoint_coverage().ok().flatten();
        let current_covered = existing
            .as_ref()
            .and_then(|coverage| coverage.history_proof_covered_to)
            .unwrap_or(0);
        if current_covered >= end_height {
            return false;
        }
        if ctx
            .store
            .put_history_checkpoint_head_record(end_height, &head_record_bytes)
            .is_err()
        {
            return false;
        }
        let mut coverage = existing.unwrap_or(CheckpointCoverage {
            checkpoint_id: head_record.head.recursive_digest,
            height: end_height,
            block_hash: end_anchor.block_id,
            covered_from: 1,
            covered_to: end_height,
            history_proof_covered_to: None,
        });
        coverage.checkpoint_id = head_record.head.recursive_digest;
        coverage.height = end_height;
        coverage.block_hash = end_anchor.block_id;
        coverage.covered_from = 1;
        coverage.covered_to = end_height;
        coverage.history_proof_covered_to = Some(end_height);
        ctx.store.put_checkpoint_coverage(&coverage).is_ok()
    };

    if promoted {
        tracing::info!(
            end_height,
            "accepted-block certificate batch package coverage promoted"
        );
    }
    promoted
}

// ---------------------------------------------------------------------------
// Background checkpoint package worker
// ---------------------------------------------------------------------------

/// Background checkpoint package worker.
///
/// Builds fixed-size accepted-block checkpoint packages from stored certificate
/// records and canonical headers, then promotes proven checkpoint coverage after
/// the package is finalized and still canonical.
///
/// ## Design
///
/// - Does not read retained block bodies/proofs/auth sidecars.
/// - Promotes only finalized sequential package ends.
/// - Recursive/package proving runs in `spawn_blocking` inside the package
///   helpers, so catch-up does not block the async runtime.
async fn run_checkpoint_package_worker(chain: Arc<RwLock<MdbxChainContext>>) {
    use std::time::Duration;

    const POLL_INTERVAL_SECS: u64 = 5;

    let mut just_advanced = false;

    loop {
        // Only sleep when idle (caught up or waiting); skip sleep after advance
        // so we catch up as fast as possible when lagging.
        if !just_advanced {
            tokio::time::sleep(Duration::from_secs(POLL_INTERVAL_SECS)).await;
        }
        just_advanced = false;

        if try_promote_certificate_batch_package_coverage(&chain).await {
            just_advanced = true;
        }
        if try_build_next_certificate_batch_package(&chain).await {
            just_advanced = true;
        }
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
    checkpoint_proof_height: Option<u64>,
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

    let checkpoint_str = match checkpoint_proof_height {
        Some(h) if tip_height > h => format!("h={}  ({} behind)", h, tip_height - h),
        Some(h) => format!("h={h}  current"),
        None => "building...".to_string(),
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

    row("checkpoint", &dim(&checkpoint_str));

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
