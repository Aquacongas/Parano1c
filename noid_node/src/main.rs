// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

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
//! 8. Start background recursive proof updater
//! 9. Shutdown on Ctrl-C

// ---------------------------------------------------------------------------
// Global allocator: jemalloc
//
// glibc malloc retains freed pages from large ZK allocations (FRI/NTT Vecs,
// often 10-100 MB each) indefinitely, causing 3-4 GB RSS fragmentation on
// a full node even with only a few hundred active UTXOs.
//
// jemalloc with background_threads enabled returns dirty pages to the OS
// within dirty_decay_ms (default 10 000 ms) via a background reclaim thread.
// This keeps the node's RSS proportional to actual working set size.
// ---------------------------------------------------------------------------
#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use clap::Parser;
use tokio::sync::RwLock;
use tracing_subscriber::EnvFilter;

use noid_chain::consensus::NetworkConfig;
use noid_chain::storage::MdbxChainContext;
use noid_mempool::{AsyncMempool, ChainView, MempoolConfig};
use noid_miner::{BlockMiner, MinerConfig};
use noid_p2p::{NetworkEvent, P2PNetwork};
use noid_rpc::start_rpc_server;

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
    /// Verifies all blocks (ZK + PoW), serves state snapshots and
    /// recursive proofs to peers. Suitable for exchanges, explorers,
    /// and infrastructure operators.
    #[default]
    Relay,
    /// Internal miner. Runs built-in PoW + ZK proving in parallel.
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
    /// miner    — internal PoW + ZK prover; blocks extminer access
    /// extminer — serves block templates to noid-extminer; requires --mining-key
    #[arg(long, value_enum, default_value_t = NodeMode::Relay)]
    mode: NodeMode,

    /// Bootstrap a new network: start mining immediately without waiting for peers.
    /// Use ONLY for the very first node on a fresh network.
    #[arg(long)]
    genesis: bool,

    /// Miner coinbase address (32-byte hex). Defaults to built-in wallet address.
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

    /// PoW mining threads. 0 = all physical cores.
    #[arg(long, value_name = "N", default_value_t = 0)]
    threads: usize,

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
    /// Use case: infrastructure pool where the node provides ZK-proving and P2P
    /// relay, but each miner receives block rewards directly to their own address.
    /// The node operator earns via an off-chain service fee, not via coinbase.
    ///
    /// Example:
    ///   paranoid --rpc-listen 0.0.0.0:9401 --mining-key s3cr3t --allow-custom-coinbase
    ///   # Miner: getBlockTemplate("noid1their_own_address")
    #[arg(long, requires = "mining_key")]
    allow_custom_coinbase: bool,
}

/// Resolve a seed string to a libp2p Multiaddr.
///
/// Handles three formats:
///
/// 1. `HOST:PORT`          — IP or hostname with explicit port  → `/ip4/H/tcp/P` or `/dns4/H/tcp/P`
/// 2. `hostname`           — bare DNS name (no port)            → `/dns4/hostname/tcp/{default_port}`
/// 3. `/ip4/.../tcp/...`   — legacy multiaddr, passed through
///
/// Format 2 is how DNS seeds work: libp2p resolves the hostname at dial time.
/// When the seed server goes live the node connects automatically without restart.
fn seed_to_multiaddr(s: &str, default_port: u16) -> anyhow::Result<libp2p::Multiaddr> {
    // Strip /p2p/<peer-id> suffix if present
    let base = s.split("/p2p/").next().unwrap_or(s).trim();

    // Already a multiaddr?
    if base.starts_with('/') {
        return base
            .parse()
            .with_context(|| format!("parse multiaddr: {base}"));
    }

    // HOST:PORT format
    if base.contains(':') {
        return ip_port_to_multiaddr(base);
    }

    // Bare hostname (DNS seed) — use default network port.
    // /dns4/ triggers libp2p DNS resolution at dial time, so the node
    // will connect as soon as the seed goes live.
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
    // Already a multiaddr? Pass through for backward-compat.
    if addr.starts_with('/') {
        return addr
            .parse()
            .with_context(|| format!("parse multiaddr: {addr}"));
    }

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
    if cli.mode == NodeMode::Miner {
        cfg.mining.enabled = true;
    }
    if let Some(addr) = cli.miner_address {
        cfg.mining.miner_address = addr;
    }
    if cli.threads > 0 {
        cfg.mining.threads = cli.threads;
    }
    // --seed accepts HOST:PORT; convert to multiaddr strings for internal use
    for raw_seed in cli.seed {
        let ma = ip_port_to_multiaddr(&raw_seed).with_context(|| format!("--seed {raw_seed}"))?;
        cfg.network.seeds.push(ma.to_string());
    }

    // --- Data directory: ~/.paranoid/data by default (no network subdir) ---
    let data_dir = if cfg.storage.path == PathBuf::from("~/.paranoid/data") {
        expand_tilde(&PathBuf::from("~/.paranoid/data"))
    } else {
        expand_tilde(&cfg.storage.path)
    };
    std::fs::create_dir_all(&data_dir)
        .with_context(|| format!("create data dir: {}", data_dir.display()))?;

    // --- Storage ---
    tracing::debug!(path = %data_dir.display(), "opening MDBX");
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
            tracing::debug!(address = %w.primary_address(), "wallet ready");
            w
        }
        Err(e) => {
            tracing::error!(err = %e, "wallet init failed");
            return Err(anyhow::anyhow!("wallet: {e}"));
        }
    };
    let shared_wallet: SharedWallet = Arc::new(std::sync::Mutex::new(Some(wallet_state)));
    let wallet = WalletHandle::new(shared_wallet.clone());

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
    let (p2p, _p2p_task) =
        P2PNetwork::start(listen_addr.clone(), chain.clone(), mempool.clone(), topics);
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
    tokio::spawn(async move {
        handle_p2p_events(
            p2p_events,
            p2p_chain,
            p2p_mempool,
            p2p_wallet,
            p2p_cmd_for_events,
            p2p_sync_ready,
        )
        .await;
    });

    // Relay mempool TxAdmitted → P2P gossip.
    let mut mp_events = mempool.subscribe();
    let p2p_tx_relay = p2p.cmd_tx.clone();
    tokio::spawn(async move {
        while let Ok(noid_mempool::MempoolEvent::TxAdmitted { intent_bytes, .. }) =
            mp_events.recv().await
        {
            let _ = p2p_tx_relay
                .send(noid_p2p::NetworkCommand::BroadcastTx { intent_bytes })
                .await;
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
    // Payout address for the mining template API: --miner-address flag or wallet primary.
    let mining_payout_address = if cfg.mining.miner_address.is_empty() {
        let guard = shared_wallet.lock().unwrap();
        guard
            .as_ref()
            .map(|w| w.primary_address())
            .unwrap_or(noid_poseidon2b::primitives::Address([0u8; 32]))
    } else {
        parse_address(&cfg.mining.miner_address)?
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
        p2p.cmd_tx.clone(),
        mining_payout_address,
        cli.mining_key,
        cli.allow_custom_coinbase,
    )
    .await
    .context("start RPC server")?;
    tracing::debug!(listen = %rpc_listen, "RPC ready");

    // --- Miner (optional) ---
    let miner_handle = if cfg.mining.enabled {
        // If no miner address configured, use the wallet's primary address.
        // This ensures coinbase rewards go directly to the built-in wallet.
        let miner_addr = if cfg.mining.miner_address.is_empty() {
            let guard = shared_wallet.lock().unwrap();
            guard
                .as_ref()
                .map(|w| w.primary_address())
                .unwrap_or(noid_poseidon2b::primitives::Address([0u8; 32]))
        } else {
            parse_address(&cfg.mining.miner_address)?
        };
        tracing::debug!(address = %miner_addr, "miner coinbase address");
        let miner_cfg = MinerConfig {
            miner_address: miner_addr,
            pow_threads: cfg.mining.threads,
            ..Default::default()
        };
        let (mut miner, mut miner_rx) = BlockMiner::new(
            miner_cfg,
            mempool.clone(),
            chain.clone(),
            Arc::clone(&sync_ready),
        );

        // Register wallet hook: called synchronously in apply_found_block BEFORE
        // on_new_block. Guarantees receipt is stored before getMempoolSize drops to 0.
        // Works at any mining speed — no channel, no capacity limit, no race.
        // Light-node wallets use P2P block subscription independently.
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
                        // Wallet update already done in apply_found_block via hook.
                        // Broadcast block + proof so all peers can verify ZK.
                        let _ = p2p_block_relay
                            .send(noid_p2p::NetworkCommand::BroadcastBlock {
                                block_bytes,
                                block_proof_bytes,
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

    // --- Background Recursive Proof Updater (P.19) ---
    let rec_chain = chain.clone();
    let rec_p2p_cmd = p2p.cmd_tx.clone();
    tokio::spawn(async move {
        run_recursive_proof_updater(rec_chain, rec_p2p_cmd).await;
    });

    // --- Startup Banner ---
    {
        use noid_chain::consensus::emission::block_reward;
        use noid_chain::fri_state::LOG_SEGMENT_SIZE;

        let wallet_bech32 = {
            let g = shared_wallet.lock().unwrap();
            g.as_ref().map(|w| w.primary_address().to_bech32())
        };
        let miner_bech32 = if cfg.mining.enabled {
            let g = shared_wallet.lock().unwrap();
            g.as_ref().map(|w| w.primary_address().to_bech32())
        } else {
            None
        };
        let ctx = chain.read().await;
        let tip_hdr = ctx.tip_header().clone();

        let log_slots = tip_hdr.log_slots;
        let active = tip_hdr.active_slot_count;
        let num_segs = if log_slots as usize > LOG_SEGMENT_SIZE {
            1usize << (log_slots as usize - LOG_SEGMENT_SIZE)
        } else {
            1
        };
        let mat_segs = ctx.state.state.active_segment_ids().count();
        let reward = block_reward(log_slots) as f64 / 1_000_000.0;

        // Get recursive proof height from store
        let rec_h = ctx
            .store
            .get_recursive_proof()
            .ok()
            .flatten()
            .and_then(|b| bincode::deserialize::<noid_recursive::RecursiveBlockProof>(&b).ok())
            .map(|p| p.block_height);
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
            rec_h,
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

/// Validate PoW, header linkage, and cumulative chainwork of snapshot headers.
///
/// Returns `(sorted_headers, Option<expected_chain_hash_at_proof_h>)`.
/// `expected_chain_hash` is `Some` only when headers span from height 0 (genesis)
/// so that `verify_tip` can check the full chain_hash from genesis.
///
/// Security guarantee: if this returns `Ok`, the `state_root` values embedded in
/// the returned headers are cryptographically committed to by real PoW work.
/// A fabricated snapshot with fake state_roots would need to out-mine the real
/// network to pass this check, making Eclipse attacks computationally infeasible.
fn validate_snapshot_headers(
    recent_headers_bytes: &[Vec<u8>],
    _genesis_acc: &noid_recursive::ChainAccumulator,
    _proof_h: u64,
) -> Result<(Vec<noid_chain::block_header::BlockHeader>, Option<[u8; 32]>), String> {
    use noid_chain::block_header::BlockHeader;
    use noid_chain::consensus::difficulty::{add_work, block_work, work_gt};
    use noid_chain::consensus::params::MIN_SNAPSHOT_CHAINWORK;
    use noid_chain::consensus::pow::{full_block_hash, validate_pow};

    // Parse and sort by height.
    let mut hdrs: Vec<BlockHeader> = recent_headers_bytes
        .iter()
        .filter_map(|b| BlockHeader::from_bytes(b).ok())
        .collect();
    if hdrs.is_empty() {
        return Err("snapshot contains no parseable recent_headers".into());
    }
    hdrs.sort_by_key(|h| h.height);

    // Validate PoW on each header.
    // Genesis header (height 0) uses a pre-mined nonce with the trivial
    // GENESIS_TARGET and passes validate_pow normally.
    for hdr in &hdrs {
        validate_pow(hdr)
            .map_err(|_| format!("snapshot header h={} failed PoW check", hdr.height))?;
    }

    // Validate linkage for consecutive pairs.
    // Non-consecutive gaps (snapshot window < full chain) are expected and allowed.
    for w in hdrs.windows(2) {
        let (parent, child) = (&w[0], &w[1]);
        if child.height == parent.height + 1 && child.prev_block_hash != full_block_hash(parent) {
            return Err(format!(
                "snapshot headers not linked at h={}: prev_block_hash mismatch",
                child.height
            ));
        }
    }

    // If the snapshot includes the genesis block (height 0), verify it matches
    // our hardcoded genesis — this is the primary chain-anchor check.
    // An attacker cannot forge the genesis hash without breaking Blake3.
    {
        use noid_chain::consensus::genesis::genesis_header;
        use noid_chain::consensus::pow::full_block_hash;
        if let Some(h0) = hdrs.iter().find(|h| h.height == 0) {
            let expected = genesis_header();
            if full_block_hash(h0) != full_block_hash(&expected) {
                return Err("snapshot genesis header does not match hardcoded genesis".into());
            }
        }
    }

    // Cumulative chainwork check.
    //
    // Every real block contributes ≥ block_work(GENESIS_TARGET) because the
    // difficulty floor is always active (ASERT never eases below GENESIS_TARGET).
    // An attacker serving a fake snapshot with trivial-difficulty headers cannot
    // accumulate enough chainwork to pass this threshold.
    let min_chainwork: [u8; 32] = MIN_SNAPSHOT_CHAINWORK;
    let mut work = [0u8; 32];
    for hdr in &hdrs {
        work = add_work(&work, &block_work(&hdr.difficulty_target));
    }
    if min_chainwork != [0u8; 32] && !work_gt(&work, &min_chainwork) {
        return Err(format!(
            "snapshot has insufficient cumulative chainwork \
             ({} headers validated; work must exceed MIN_SNAPSHOT_CHAINWORK)",
            hdrs.len()
        ));
    }

    // The chain_hash formula now folds block_initial_claim into each step:
    //   chain_hash_n = compress(prev, compress(H_BLOCK, claim_bytes_n))
    //
    // Replaying this from headers-only is no longer possible because
    // block_initial_claim is part of the BlockProof (pruned after FINALITY_DEPTH
    // and unavailable here).  We return None; the STARK in verify_tip provides
    // the authoritative chain-validity guarantee.  The hardcoded genesis hash
    // check above is still the primary Eclipse anchor.
    Ok((hdrs, None))
}

// ---------------------------------------------------------------------------
// Blocking-I/O helpers
// ---------------------------------------------------------------------------

/// Apply a single block off the tokio executor.
///
/// `MdbxStore` is opened with `SyncMode::Durable` — every `commit_block`
/// issues `fsync` before returning, a real blocking syscall.  Running it
/// directly on a tokio worker stalls async scheduling for 1–100 ms;
/// `spawn_blocking` offloads it to the dedicated blocking thread pool.
async fn apply_block_offthread(
    chain: &Arc<RwLock<MdbxChainContext>>,
    block: noid_chain::block::Block,
    local_time: u64,
) -> Result<[u8; 32], noid_chain::storage::MdbxContextError> {
    let chain = chain.clone();
    tokio::task::spawn_blocking(move || {
        let mut ctx = chain.blocking_write();
        ctx.apply_next_block(&block, local_time)
    })
    .await
    .expect("apply_next_block panicked in spawn_blocking")
}

/// Apply a chain reorg off the tokio executor.  Same `fsync` rationale.
///
/// Returns `(result, new_blocks)` so the caller can iterate `new_blocks`
/// in the success path without an extra clone.
async fn apply_reorg_offthread(
    chain: &Arc<RwLock<MdbxChainContext>>,
    ancestor_height: u64,
    new_blocks: Vec<noid_chain::block::Block>,
    local_time: u64,
) -> (
    Result<noid_chain::consensus::ReorgResult, noid_chain::storage::MdbxContextError>,
    Vec<noid_chain::block::Block>,
) {
    let chain = chain.clone();
    tokio::task::spawn_blocking(move || {
        let mut ctx = chain.blocking_write();
        let result = ctx.apply_reorg_mdbx(ancestor_height, &new_blocks, local_time);
        (result, new_blocks) // return new_blocks so the caller can use them
    })
    .await
    .expect("apply_reorg_mdbx panicked in spawn_blocking")
}

async fn handle_p2p_events(
    mut rx: tokio::sync::broadcast::Receiver<NetworkEvent>,
    chain: Arc<RwLock<MdbxChainContext>>,
    mempool: AsyncMempool,
    wallet: SharedWallet,
    p2p_cmd: tokio::sync::mpsc::Sender<noid_p2p::NetworkCommand>,
    sync_ready: Arc<tokio::sync::Notify>,
) {
    // Orphan pool: blocks whose parent is not yet known.
    // When the parent arrives, we re-apply the orphan.
    // Keyed by parent_hash, limited to FINALITY_DEPTH entries.
    use noid_chain::consensus::params::FINALITY_DEPTH;
    use std::collections::HashMap;
    let mut orphan_pool: HashMap<[u8; 32], noid_chain::block::Block> = HashMap::new();

    // --- Snapshot verification state ---
    //
    // Two-step snapshot sync:
    //   (1) receive StateSnapshot  → store as pending, request RecursiveProof from same peer
    //   (2) receive RecursiveProof → verify proof → apply snapshot (or discard on failure)
    //
    // The pending snapshot is stored here while we await the proof.
    // If no matching proof arrives (e.g. the peer disconnects), the snapshot
    // remains pending until a RecursiveProof arrives from the expected peer.
    // Subsequent peer connections buffer new snapshots in snapshot_candidates
    // without replacing the pending entry.
    struct PendingSnapshot {
        from: libp2p::PeerId,
        snapshot: Box<noid_p2p::protocol::GetStateSnapshotResponse>,
    }
    let mut pending_snapshot: Option<PendingSnapshot> = None;

    // Eclipse attack mitigation — collect snapshots from multiple peers
    // before selecting the best one, requiring an attacker to control ALL first N
    // peers instead of just the first one.
    //
    // snapshot_candidates: buffered snapshots awaiting selection.
    // snapshot_requested_peers: tracks which peers we already asked, prevents duplicates.
    let mut snapshot_candidates: Vec<(
        libp2p::PeerId,
        Box<noid_p2p::protocol::GetStateSnapshotResponse>,
    )> = Vec::new();
    let mut snapshot_requested_peers: std::collections::HashSet<libp2p::PeerId> =
        std::collections::HashSet::new();

    // --- Per-peer tx rate limiter ---
    //
    // Sliding-window rate limiter: tracks (tx_count_in_window, window_start) per peer.
    // Prevents a single peer from flooding the ZK semaphore queue.
    use std::time::{Duration, Instant};
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
    // beyond FINALITY_DEPTH=18.  If the limit is hit we request a full state
    // snapshot instead (the designed deep-sync mechanism).
    let mut fetch_depth: HashMap<libp2p::PeerId, u32> = HashMap::new();
    const MAX_FETCH_DEPTH: u32 = 4;

    loop {
        match rx.recv().await {
            Ok(NetworkEvent::NewBlock {
                from,
                block_bytes,
                block_proof_bytes,
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
                if block_event_count % 200 == 0 {
                    let cutoff = Instant::now() - Duration::from_secs(60);
                    peer_block_rate.retain(|_, (_, t)| *t >= cutoff);
                }

                tracing::debug!(peer = %from, "received block from P2P");
                match noid_chain::block::Block::from_bytes(&block_bytes) {
                    Ok(block) => {
                        let local_time = unix_now();
                        let block_hash = noid_chain::consensus::pow::full_block_hash(&block.header);

                        // ZK proof verification (when proof bytes are present).
                        //
                        // For coinbase-only blocks (empty proof) this is skipped entirely.
                        // For user-tx blocks: verify_block checks ZK correctness before
                        // we commit to the chain. The spend_secret is NOT needed — all
                        // inputs are reconstructed from public wire data (owner, auth_tag).
                        //
                        // Important: verify_block is called under a READ lock so it does
                        // NOT modify the chain state. apply_next_block (below) then applies
                        // the block under a WRITE lock once ZK is confirmed valid.
                        let zk_reject = if !block_proof_bytes.is_empty() {
                            match bincode::deserialize::<noid_block::BlockProof>(&block_proof_bytes)
                            {
                                Ok(proof) => {
                                    let ctx = chain.read().await;
                                    let spine = noid_block::build_spine_inputs_list(&block);
                                    let auth = noid_block::build_auth_public_list(&block, &proof);
                                    let sb_airs = noid_block::build_state_binding_airs(
                                        &block,
                                        &proof,
                                        &ctx.state.state,
                                    );
                                    drop(ctx);
                                    let tx_airs = noid_block::build_tx_airs(&block);
                                    let air_refs: Vec<&dyn noid_air::Air> =
                                        tx_airs.iter().map(|a| a as &dyn noid_air::Air).collect();
                                    let sb_refs: Vec<
                                        &noid_air::airs::block_state_binding::BlockStateBindingAir,
                                    > = sb_airs.iter().collect();
                                    match noid_block::verify_block(
                                        &air_refs, &proof, &spine, &auth, &sb_refs,
                                    ) {
                                        Ok(()) => None,
                                        Err(e) => {
                                            tracing::warn!(
                                                peer = %from,
                                                height = block.header.height,
                                                err = ?e,
                                                "P2P block ZK proof invalid — rejected"
                                            );
                                            Some(())
                                        }
                                    }
                                }
                                Err(e) => {
                                    tracing::warn!(
                                        peer = %from,
                                        err = ?e,
                                        "P2P block proof deserialize failed"
                                    );
                                    Some(())
                                }
                            }
                        } else {
                            None // no proof bytes — coinbase-only, skip ZK check
                        };
                        if zk_reject.is_some() {
                            continue;
                        }

                        // Apply block off the async executor (MDBX fsync is blocking).
                        // Build ChainView under read lock (shared, non-blocking).
                        // This avoids holding the write lock during SegmentedFriState clone
                        // (~50ms at 256 segments), which was blocking all RPC/miner operations.
                        let apply_result =
                            apply_block_offthread(&chain, block.clone(), local_time).await;
                        let maybe_view = if apply_result.is_ok() {
                            let ctx = chain.read().await;
                            Some(ChainView::from_mdbx(&ctx))
                        } else {
                            None
                        };

                        match apply_result {
                            Ok(_) => {
                                let height = block.header.height;
                                let confirmed: Vec<_> = block
                                    .transactions
                                    .iter()
                                    .map(|tx| tx.tx_body_hash)
                                    .collect();
                                let new_view = maybe_view.unwrap();
                                mempool.on_new_block(&confirmed, height, new_view).await;
                                update_wallet_for_block(&wallet, &block);
                                tracing::info!(height, "applied P2P block");
                                sync_ready.notify_one(); // safe: no-op after first waiter wakes

                                // Store the BlockProof bytes so run_recursive_proof_updater
                                // can build a real (non-null) recursive witness for this block.
                                if !block_proof_bytes.is_empty() {
                                    let ctx = chain.read().await;
                                    if let Err(e) =
                                        ctx.store.put_block_proof(height, &block_proof_bytes)
                                    {
                                        tracing::warn!(
                                            height,
                                            err = %e,
                                            "failed to store received block proof"
                                        );
                                    }
                                }

                                // Auto-continue sync: immediately request the next batch from
                                // the same peer. This pulls the chain all the way to the peer's
                                // tip without waiting for gossip mesh to propagate each block.
                                // SyncBlocksFrom for heights beyond peer's recent_blocks returns
                                // None and stops automatically — no infinite loop.
                                let _ = p2p_cmd
                                    .send(noid_p2p::NetworkCommand::SyncBlocksFrom {
                                        peer: from,
                                        from_height: height + 1,
                                        count: 18,
                                    })
                                    .await;

                                // Apply the chain of orphans that build on the new block.
                                let mut next_hash = block_hash;
                                while let Some(orphan) = orphan_pool.remove(&next_hash) {
                                    let orphan_local_time = unix_now();
                                    next_hash =
                                        noid_chain::consensus::pow::full_block_hash(&orphan.header);
                                    // Write lock: apply only. Read lock: build view.
                                    let orphan_result = apply_block_offthread(
                                        &chain,
                                        orphan.clone(),
                                        orphan_local_time,
                                    )
                                    .await;
                                    match orphan_result {
                                        Ok(_) => {
                                            let h = orphan.header.height;
                                            let conf: Vec<_> = orphan
                                                .transactions
                                                .iter()
                                                .map(|tx| tx.tx_body_hash)
                                                .collect();
                                            let nv = {
                                                let ctx = chain.read().await;
                                                ChainView::from_mdbx(&ctx)
                                            };
                                            mempool.on_new_block(&conf, h, nv).await;
                                            update_wallet_for_block(&wallet, &orphan);
                                            tracing::info!(
                                                height = h,
                                                "applied chained orphan block"
                                            );
                                        }
                                        Err(e) => {
                                            tracing::warn!(err = %e, "chained orphan apply failed");
                                            break;
                                        }
                                    }
                                }
                            }
                            Err(noid_chain::storage::MdbxContextError::Consensus(
                                noid_chain::consensus::ConsensusError::BadParentHash,
                            )) => {
                                // Check if the block's parent is already in our chain (potential reorg point).
                                let parent_hash = block.header.prev_block_hash;
                                let our_tip = {
                                    let ctx = chain.read().await;
                                    (ctx.tip_height(), ctx.find_ancestor_height(&parent_hash))
                                };
                                let (our_tip_height, ancestor_opt) = our_tip;

                                match ancestor_opt {
                                    Some(ancestor_height) if ancestor_height < our_tip_height => {
                                        // Parent IS in our chain — this block starts or extends a competing fork.
                                        // Collect the new chain: this block + any buffered orphans on top.
                                        let mut new_chain = vec![block.clone()];
                                        let mut next_hash =
                                            noid_chain::consensus::pow::full_block_hash(
                                                &block.header,
                                            );
                                        while let Some(orphan) = orphan_pool.remove(&next_hash) {
                                            next_hash = noid_chain::consensus::pow::full_block_hash(
                                                &orphan.header,
                                            );
                                            new_chain.push(orphan);
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
                                                    &block_work(&b.header.difficulty_target),
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

                                            let local_time = unix_now();
                                            // Reorg off the async executor (MDBX fsync is blocking).
                                            // `new_chain` is returned from spawn_blocking to avoid
                                            // an extra clone (used in the success path below).
                                            let (reorg_result, new_chain) = apply_reorg_offthread(
                                                &chain,
                                                ancestor_height,
                                                new_chain,
                                                local_time,
                                            )
                                            .await;
                                            let maybe_reorg_view = if reorg_result.is_ok() {
                                                let ctx = chain.read().await;
                                                Some(ChainView::from_mdbx(&ctx))
                                            } else {
                                                None
                                            };

                                            match reorg_result {
                                                Ok(result) => {
                                                    let new_view = maybe_reorg_view.unwrap();
                                                    let confirmed_in_new: Vec<_> = new_chain
                                                        .iter()
                                                        .flat_map(|b| {
                                                            b.transactions
                                                                .iter()
                                                                .map(|tx| tx.tx_body_hash)
                                                        })
                                                        .collect();
                                                    mempool
                                                        .on_new_block(
                                                            &confirmed_in_new,
                                                            new_tip_height,
                                                            new_view,
                                                        )
                                                        .await;

                                                    for new_block in &new_chain {
                                                        update_wallet_for_block(&wallet, new_block);
                                                    }

                                                    mempool
                                                        .readmit_after_reorg(
                                                            result.reclaimed_tx_hashes,
                                                        )
                                                        .await;

                                                    let new_tip = new_tip_height;
                                                    tracing::info!(
                                                        new_tip,
                                                        reverted = result.reverted_heights.len(),
                                                        applied = result.applied_heights.len(),
                                                        "reorg complete"
                                                    );
                                                }
                                                Err(e) => {
                                                    tracing::warn!(err = ?e, "reorg failed, keeping current chain");
                                                }
                                            }
                                        } else {
                                            tracing::debug!(
                                                our_tip = our_tip_height,
                                                new_tip = new_tip_height,
                                                "reorg: competing chain not longer, keeping current chain"
                                            );
                                            // Still buffer in case more blocks arrive from this fork.
                                            insert_orphan(&mut orphan_pool, block);
                                        }
                                    }
                                    Some(_) => {
                                        // Ancestor IS our current tip — block just has wrong parent somehow.
                                        tracing::debug!(peer = %from, height = block.header.height, "block rejected: already at tip height");
                                    }
                                    None => {
                                        // Parent NOT in our chain.
                                        //
                                        // Heuristic: if the competing block is clearly deeper than our finality
                                        // window, skip FetchHeaders entirely and request a snapshot directly.
                                        // Paranoid's O(1) snapshot sync (snapshot + RecursiveProof) is correct
                                        // regardless of fork depth, and is faster than N round-trips of block
                                        // fetching for deep forks where peers may no longer have the old blocks.
                                        //
                                        // FetchHeaders is only worth doing for shallow forks (within FINALITY_DEPTH)
                                        // where block-by-block reorg is possible.
                                        let block_height = block.header.height;
                                        let is_deep_fork = block_height > our_tip_height
                                            && (block_height - our_tip_height) > FINALITY_DEPTH;

                                        insert_orphan(&mut orphan_pool, block);

                                        if is_deep_fork {
                                            tracing::info!(
                                                our_tip = our_tip_height,
                                                their_tip = block_height,
                                                gap = block_height - our_tip_height,
                                                peer = %from,
                                                "deep fork (gap > FINALITY_DEPTH) — requesting snapshot directly"
                                            );
                                            let _ = p2p_cmd
                                                .send(noid_p2p::NetworkCommand::RequestStateSnapshot { peer: from })
                                                .await;
                                        } else {
                                            // Shallow fork: fetch batch headers to find the common ancestor.
                                            let fetch_from =
                                                our_tip_height.saturating_sub(FINALITY_DEPTH);
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
                                                    count: (FINALITY_DEPTH as u16 * 2).min(512),
                                                })
                                                .await;
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                tracing::warn!(peer = %from, err = %e, "P2P block rejected");
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!(peer = %from, err = ?e, "P2P block decode failed");
                    }
                }
            }
            Ok(NetworkEvent::NewTx { from, intent_bytes }) => {
                tracing::debug!(peer = %from, "received tx from P2P");

                // Per-peer rate limiting: enforce before any further processing.
                // This check is synchronous (O(1) HashMap lookup) so the event loop
                // is not blocked; the heavy ZK verify is spawned below.
                {
                    let now = Instant::now();
                    let entry = peer_tx_rate.entry(from.clone()).or_insert((0, now));
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
                if tx_event_count % 100 == 0 {
                    let cutoff = Instant::now() - Duration::from_secs(60);
                    peer_tx_rate.retain(|_, (_, window_start)| *window_start >= cutoff);
                }

                // Spawn ZK verify + mempool admit as a background task.
                //
                // WHY: `mempool.submit()` runs a ZK proof verify (~84ms, CPU-bound via
                // spawn_blocking) under an async semaphore. If we await it here, the
                // entire P2P event loop stalls for 84ms — delaying block propagation.
                //
                // SAFETY: `mempool.submit()` never touches the chain (Arc<RwLock<...>>),
                // only the mempool's internal Arc<Mutex<MempoolState>>. Concurrent task
                // access is safe. P2P relay of admitted txs is handled by the dedicated
                // relay task spawned in main() — no extra work needed here.
                let mempool_task = mempool.clone();
                tokio::spawn(async move {
                    match noid_tx::TxIntent::from_bytes(&intent_bytes) {
                        Ok(intent) => {
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
                        Err(_) => {} // malformed intent, ignore
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
                    // Fresh node with no state: request a full STATE SNAPSHOT.
                    //
                    // Paranoid does NOT store block history (DA delete-immediately
                    // policy). New nodes sync via the current state, not block replay.
                    // The state is proven valid by the recursive chain proof.
                    //
                    // Request from up to 3 distinct peers; we'll pick the
                    // snapshot with the highest tip_height after collecting >= 2.
                    if snapshot_candidates.len() < 3 && !snapshot_requested_peers.contains(&peer) {
                        tracing::info!(peer = %peer, "fresh node — requesting state snapshot (Paranoid sync)");
                        snapshot_requested_peers.insert(peer);
                        p2p_cmd
                            .send(noid_p2p::NetworkCommand::RequestStateSnapshot { peer })
                            .await
                            .ok();
                    }
                } else {
                    // Already have state — catch up on recent blocks.
                    // Auto-continue (applied in NewBlock handler) iterates
                    // until the peer has no more blocks to serve.
                    let count = noid_chain::consensus::params::FINALITY_DEPTH as u16;
                    p2p_cmd
                        .send(noid_p2p::NetworkCommand::SyncBlocksFrom {
                            peer,
                            from_height: our_height + 1,
                            count,
                        })
                        .await
                        .ok();
                    tracing::debug!(
                        from_height = our_height + 1,
                        count,
                        "triggered recent-block sync"
                    );
                }
            }
            Ok(NetworkEvent::HeadersBatch { from, headers }) => {
                // Headers batch from FetchHeaders — find common ancestor for reorg.
                // We requested headers when we got BadParentHash for a competing block.
                if headers.is_empty() {
                    continue;
                }

                let (our_tip, ancestor_opt) = {
                    let ctx = chain.read().await;
                    let our_tip = ctx.tip_height();
                    // Find the highest header in the batch that is ALSO in our chain.
                    let mut found = None;
                    for hdr in &headers {
                        let hash = noid_chain::consensus::pow::full_block_hash(hdr);
                        if let Some(h) = ctx.find_ancestor_height(&hash) {
                            if found.map_or(true, |(fh, _)| h > fh) {
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
                        use noid_chain::consensus::params::FINALITY_DEPTH;

                        if competing.len() > FINALITY_DEPTH as usize {
                            // Competing fork is deeper than FINALITY_DEPTH.
                            //
                            // WHY SNAPSHOT, NOT BLOCK-BY-BLOCK:
                            // apply_reorg_mdbx enforces reorg_depth ≤ FINALITY_DEPTH, so
                            // block-by-block is structurally impossible here anyway.
                            //
                            // More importantly: blocks arrive as individual NewBlock events.
                            // When the first competing block arrives alone its chainwork is
                            // tiny vs our full chain — the reorg comparison fires prematurely
                            // and always says "keep our chain". Subsequent blocks hit the
                            // None branch (parent not found) → FetchHeaders again → cycle.
                            //
                            // In Paranoid, snapshot sync is O(1) regardless of chain length.
                            // It is always correct and always faster than N round-trips of
                            // block fetching for forks this deep.
                            tracing::info!(
                                ancestor = ancestor_height,
                                our_tip,
                                competing_tip = new_tip_height,
                                blocks_needed = competing.len(),
                                peer = %from,
                                "fork >{} blocks deep — requesting snapshot (O(1) Paranoid sync)",
                                FINALITY_DEPTH
                            );
                            let _ = p2p_cmd
                                .send(noid_p2p::NetworkCommand::RequestStateSnapshot { peer: from })
                                .await;
                        } else {
                            // Shallow fork (≤ FINALITY_DEPTH): apply_reorg_mdbx can handle it.
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
                                let _ = p2p_cmd
                                    .send(noid_p2p::NetworkCommand::RequestBlock {
                                        peer: from,
                                        height: hdr.height,
                                    })
                                    .await;
                            }
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
                            tracing::warn!(
                                peer = %from,
                                depth = *depth,
                                "FetchHeaders depth limit reached — requesting state snapshot instead"
                            );
                            *depth = 0; // reset for next time
                            let _ = p2p_cmd
                                .send(noid_p2p::NetworkCommand::RequestStateSnapshot { peer: from })
                                .await;
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
            Ok(NetworkEvent::StateSnapshot { from, snapshot }) => {
                // SECURITY: Do NOT apply the snapshot yet. Collect snapshots from
                // multiple peers and pick the one with the highest tip_height before
                // entering the 2-step verification flow. This prevents a single
                // malicious first peer from providing a fabricated snapshot (Eclipse
                // attack), since an attacker must now control ALL first N peers.
                // Once a candidate is selected, a RecursiveBlockProof is requested
                // and verified cryptographically before the snapshot is accepted.
                if snapshot.tip_height == 0 {
                    tracing::debug!(from = %from, "snapshot tip_height=0, ignoring");
                } else if pending_snapshot.is_some() {
                    // Already in the 2-step verification flow — do not override.
                    // Buffer this snapshot in case we need it later (e.g. current
                    // proof fails and we want to retry with a different candidate).
                    if snapshot_candidates.len() < 3 {
                        tracing::debug!(
                            from = %from,
                            tip = snapshot.tip_height,
                            "already verifying a snapshot; storing as late candidate"
                        );
                        snapshot_candidates.push((from, snapshot));
                    }
                } else {
                    // Collect into candidates (cap at 3).
                    let tip_h = snapshot.tip_height;
                    if snapshot_candidates.len() < 3 {
                        snapshot_candidates.push((from, snapshot));
                    }

                    // Proceed when we have >= 2 candidates (Eclipse-resistant
                    // multi-peer selection), OR when only 1 peer is reachable.
                    //
                    // Single-peer fallback is safe because validate_snapshot_headers
                    // (called below) enforces PoW + chainwork on every accepted
                    // snapshot: a malicious sole peer would need to out-mine the
                    // real network to forge valid headers. Multi-peer selection is
                    // defence-in-depth on top of that PoW check.
                    let should_proceed =
                        snapshot_candidates.len() >= 2 || snapshot_requested_peers.len() <= 1;

                    if should_proceed {
                        // Pick the snapshot with the highest tip_height (most chainwork).
                        let (best_peer, best_snapshot) = snapshot_candidates
                            .drain(..)
                            .max_by_key(|(_, s)| s.tip_height)
                            .expect("snapshot_candidates is non-empty");

                        tracing::info!(
                            from = %best_peer,
                            tip = best_snapshot.tip_height,
                            segments = best_snapshot.segments.len(),
                            "selected best snapshot — requesting recursive proof for verification"
                        );
                        pending_snapshot = Some(PendingSnapshot {
                            from: best_peer,
                            snapshot: best_snapshot,
                        });
                        // Request the recursive chain proof from the selected peer.
                        // The response arrives as NetworkEvent::RecursiveProof and
                        // triggers (2): verify proof then apply snapshot.
                        let _ = p2p_cmd
                            .send(noid_p2p::NetworkCommand::RequestRecursiveProof {
                                peer: best_peer,
                            })
                            .await;
                    } else {
                        tracing::info!(
                            from = %from,
                            tip = tip_h,
                            candidates = snapshot_candidates.len(),
                            "received snapshot — waiting for more candidates before selecting \
                             (Eclipse attack protection)"
                        );
                    }
                }
            }

            Ok(NetworkEvent::RecursiveProof {
                from,
                proof_bytes,
                tip_header_bytes: _, // tip header from peer; we use recent_headers from snapshot
            }) => {
                // SECURITY: RecursiveProof verification before applying snapshot.
                // Verify the recursive proof against genesis, then apply the pending snapshot.
                use bincode;
                use noid_recursive::{verify_tip, RecursiveBlockAir, RecursiveBlockProof};

                let snap = match pending_snapshot.take() {
                    Some(p) if p.from == from => p,
                    Some(p) => {
                        // Proof arrived from a different peer — discard (could be unsolicited).
                        tracing::warn!(
                            proof_from = %from,
                            snapshot_from = %p.from,
                            "recursive proof from unexpected peer, discarding pending snapshot"
                        );
                        // Restore the pending snapshot so another proof from the right peer can still work.
                        pending_snapshot = Some(p);
                        continue;
                    }
                    None => {
                        // No pending snapshot — this proof was unsolicited, ignore.
                        tracing::debug!(from = %from, "unexpected recursive proof, no pending snapshot");
                        continue;
                    }
                };

                if proof_bytes.is_empty() {
                    // Peer has no recursive proof yet: the proof updater only
                    // starts after FINALITY_DEPTH=18 finalised blocks, so on
                    // a fresh network this is normal for the first few minutes.
                    //
                    // We still accept the snapshot BUT only after validate_snapshot_headers
                    // passes: PoW on every header + linkage + MIN_SNAPSHOT_CHAINWORK.
                    // That check cryptographically commits state_root to real mining work,
                    // providing Eclipse protection equivalent to what the recursive proof
                    // would add once available.
                    use noid_chain::consensus::genesis::{genesis_header, genesis_state_root};
                    use noid_chain::consensus::pow::full_block_hash as fbh;
                    use noid_recursive::genesis_accumulator;
                    let genesis_acc_pow = {
                        let g = genesis_header();
                        genesis_accumulator(genesis_state_root(), fbh(&g))
                    };
                    match validate_snapshot_headers(
                        &snap.snapshot.recent_headers,
                        &genesis_acc_pow,
                        0, // no proof_h: chain_hash not computed (no proof)
                    ) {
                        Ok(_) => tracing::info!(
                            from = %from,
                            tip = snap.snapshot.tip_height,
                            "no recursive proof yet (proof updater catching up) — \
                             accepting snapshot: PoW + chainwork verified on headers"
                        ),
                        Err(e) => {
                            tracing::error!(
                                from = %from,
                                tip = snap.snapshot.tip_height,
                                err = %e,
                                "REJECTED snapshot: header PoW/chainwork check failed \
                                 (peer has no recursive proof)"
                            );
                            continue;
                        }
                    }
                } else {
                    // Verify the recursive proof.
                    //
                    // Two verification modes based on how far the proof has advanced:
                    //
                    // A) FULL VERIFY (proof covers tip-1): call verify_tip for O(1) chain
                    //    verification. Cryptographically proves the entire chain back to genesis.
                    //
                    // B) PARTIAL VERIFY (proof behind tip): verify that the proof's accumulated
                    //    state_root matches the corresponding header in the snapshot's
                    //    recent_headers. This ensures the proof is consistent with the claimed
                    //    chain, even if it hasn't caught up to the tip yet.
                    //
                    // In either case, the state_root check in apply_state_snapshot
                    // independently verifies that slot data matches the tip header state_root.
                    let verify_result: Result<(), String> = (|| {
                        use noid_chain::block_header::BlockHeader;
                        use noid_chain::consensus::genesis::{genesis_header, genesis_state_root};
                        use noid_chain::consensus::pow::full_block_hash;
                        use noid_recursive::genesis_accumulator;

                        let proof: RecursiveBlockProof = bincode::deserialize(&proof_bytes)
                            .map_err(|e| format!("proof deserialize: {e}"))?;

                        let snap_tip_h = snap.snapshot.tip_height;
                        let proof_h = proof.block_height;

                        // Validate PoW + chainwork of snapshot headers.
                        // This is the primary Eclipse-attack protection.
                        // state_root is in header_core so valid PoW cryptographically
                        // commits each state_root to real mining work.
                        let genesis_acc = {
                            let g = genesis_header();
                            genesis_accumulator(genesis_state_root(), full_block_hash(&g))
                        };
                        let (_sorted_hdrs, expected_chain_hash) = validate_snapshot_headers(
                            &snap.snapshot.recent_headers,
                            &genesis_acc,
                            proof_h,
                        )?;

                        // Helper: find state_root of a given height in snapshot's recent_headers.
                        let find_root = |h: u64| -> Option<[u8; 32]> {
                            snap.snapshot.recent_headers.iter().find_map(|b| {
                                BlockHeader::from_bytes(b)
                                    .ok()
                                    .filter(|hdr| hdr.height == h)
                                    .map(|hdr| hdr.state_root)
                            })
                        };

                        if proof_h + 1 == snap_tip_h {
                            // ── ChainProof: recursive proof covers full chain to tip-1 ─────
                            // The stored RecursiveProof is exactly one step behind the
                            // snapshot tip.  `verify_tip` performs O(1) cryptographic
                            // verification of the entire chain history from genesis.
                            let tip_prev_state_root = if snap_tip_h == 0 {
                                genesis_state_root()
                            } else {
                                find_root(snap_tip_h - 1).ok_or_else(|| {
                                    format!(
                                        "snapshot missing header h={} for tip_prev_state_root",
                                        snap_tip_h - 1
                                    )
                                })?
                            };
                            // Genesis edge-case (shared with StepProof path below):
                            // the genesis proof was built with the *pre-genesis*
                            // accumulator whose state_root is [0u8;32], not genesis_state_root().
                            let rec_air_prev_root = if proof_h == 0 {
                                [0u8; 32] // pre-genesis accumulator state_root
                            } else {
                                find_root(proof_h - 1).unwrap_or_else(genesis_state_root)
                            };
                            let rec_air =
                                RecursiveBlockAir::from_prev_state_root(&rec_air_prev_root);
                            tracing::debug!(
                                proof_h,
                                snap_tip_h,
                                "snapshot: chain-proof verify (proof covers tip)"
                            );
                            verify_tip(
                                &proof,
                                &rec_air,
                                &tip_prev_state_root,
                                snap_tip_h,
                                &genesis_acc,
                                expected_chain_hash.as_ref().map(|h| h as &[u8; 32]),
                            )
                            .map_err(|e| format!("chain-proof verify failed: {e:?}"))
                        } else {
                            // ── StepProof: recursive proof is behind snapshot tip ─────────
                            //
                            // Normal operating mode: the RecursiveProof lags FINALITY_DEPTH
                            // (18) blocks behind tip to protect against reorg invalidation.
                            //
                            // We call `verify_step_stark_only` which:
                            //   1. Verifies the STARK over `RecursiveBlockAir(prev_root)` —
                            //      same underlying check as chain-proof.
                            //   2. Checks `proof.acc.state_root == header[proof_h].state_root`
                            //      against the PoW-committed header in recent_headers.
                            // This cryptographically links the proof to real mining work
                            // without requiring the proof to cover the full tip distance.
                            use noid_recursive::verify_step_stark_only;

                            // prev_state_root at proof_h - 1.
                            // When proof_h == 0 (genesis proof), the STARK was proved with
                            // the *pre-genesis* accumulator whose state_root is [0u8;32] —
                            // NOT genesis_state_root().  Using genesis_state_root() here
                            // would pin a different value in the AIR and cause StarkInvalid.
                            let prev_root = if proof_h == 0 {
                                [0u8; 32] // pre-genesis accumulator state_root
                            } else {
                                find_root(proof_h - 1).unwrap_or_else(genesis_state_root)
                            };

                            // expected new state_root from the snapshot's headers.
                            match find_root(proof_h) {
                                Some(expected_new_root) => {
                                    match verify_step_stark_only(
                                        &proof,
                                        &prev_root,
                                        &expected_new_root,
                                    ) {
                                        Ok(()) => {
                                            tracing::info!(
                                                proof_h,
                                                snap_tip_h,
                                                gap = snap_tip_h - proof_h,
                                                "snapshot: step-proof verified \
                                                 (proof {} blocks before tip)",
                                                snap_tip_h - proof_h
                                            );
                                            Ok(())
                                        }
                                        Err(e) => Err(format!(
                                            "step-proof STARK failed at h={proof_h}: {e:?}"
                                        )),
                                    }
                                }
                                None => {
                                    // Header for proof_h not in the recent_headers window.
                                    // A well-formed snapshot always includes sufficient
                                    // headers for step-proof verification.
                                    Err(format!(
                                        "step-proof: header[{proof_h}] not in recent_headers \
                                         (snapshot malformed)"
                                    ))
                                }
                            }
                        }
                    })();

                    match verify_result {
                        Ok(()) => {
                            tracing::info!(
                                from = %from,
                                tip = snap.snapshot.tip_height,
                                "recursive proof VERIFIED — applying snapshot"
                            );
                            // Persist the verified proof so the local recursive-proof
                            // updater can resume from this height instead of
                            // re-proving the entire chain from genesis.
                            {
                                let ctx = chain.read().await;
                                if let Err(e) = ctx.store.put_recursive_proof(&proof_bytes) {
                                    tracing::warn!(
                                        err = ?e,
                                        "failed to persist received recursive proof"
                                    );
                                }
                            }
                        }
                        Err(e) => {
                            tracing::error!(
                                from = %from,
                                tip = snap.snapshot.tip_height,
                                err = %e,
                                "REJECTED snapshot: recursive proof verification failed — \
                                 possible Eclipse attack or fabricated snapshot"
                            );
                            // Discard the snapshot. The node will try again from the next peer.
                            continue;
                        }
                    }
                }

                // --- Apply the (verified) snapshot ---
                let snapshot = snap.snapshot;
                let segments: Vec<(u16, u8, noid_chain::segmented_state::SegmentColumns)> = {
                    use noid_chain::storage::serial::decode_segment;
                    snapshot
                        .segments
                        .iter()
                        .filter_map(|e| {
                            decode_segment(&e.data).map(|(_, cols)| (e.seg_id, e.eff_log, cols))
                        })
                        .collect()
                };
                tracing::info!(
                    segments = segments.len(),
                    tip = snapshot.tip_height,
                    "snapshot: decoded {} segments, writing to MDBX...",
                    segments.len()
                );
                let nullifier_blocks: Vec<Vec<noid_poseidon2b::primitives::TxBodyHash>> = snapshot
                    .nullifier_blocks
                    .iter()
                    .map(|hashes| {
                        hashes
                            .iter()
                            .map(|h| noid_poseidon2b::primitives::TxBodyHash(*h))
                            .collect()
                    })
                    .collect();

                let result = {
                    let mut ctx = chain.write().await;
                    ctx.apply_state_snapshot(
                        snapshot.tip_height,
                        snapshot.tip_hash,
                        snapshot.log_slots,
                        snapshot.active_slot_count,
                        snapshot.alloc_counter,
                        &segments,
                        &snapshot.recent_headers,
                        &nullifier_blocks,
                    )
                };

                match result {
                    Ok(_) => {
                        let ctx = chain.read().await;
                        let new_view = ChainView::from_mdbx(&ctx);
                        let new_height = ctx.tip_height();
                        drop(ctx);
                        mempool.on_new_block(&[], new_height, new_view).await;
                        sync_ready.notify_one();
                        tracing::info!(
                            height = new_height,
                            "snapshot: fully applied and persisted to disk"
                        );
                        tracing::info!(
                            height = new_height,
                            "chain snapshot applied — mining can begin"
                        );
                        // Kick off post-snapshot catch-up.
                        // We request FINALITY_DEPTH blocks at a time; auto-continue
                        // (triggered on each applied block) iterates until the peer
                        // has no more blocks to serve.
                        let _ = p2p_cmd
                            .send(noid_p2p::NetworkCommand::SyncBlocksFrom {
                                peer: from,
                                from_height: new_height + 1,
                                count: noid_chain::consensus::params::FINALITY_DEPTH as u16,
                            })
                            .await;
                    }
                    Err(e) => {
                        tracing::error!(err = ?e, "failed to apply verified state snapshot");
                    }
                }
            }
            Ok(NetworkEvent::RecursiveProofUpdate {
                from,
                height,
                tip_hash: _,
                proof_bytes,
            }) => {
                use noid_recursive::{verify_step_stark_only, RecursiveBlockProof};

                // Only process if this proof is ahead of what we have.
                let our_height = {
                    let ctx = chain.read().await;
                    ctx.store
                        .get_recursive_proof()
                        .ok()
                        .flatten()
                        .and_then(|b| bincode::deserialize::<RecursiveBlockProof>(&b).ok())
                        .map(|p| p.block_height)
                };
                let already_have = our_height.map_or(false, |h| h >= height);
                if already_have {
                    tracing::debug!(
                        from = %from,
                        height,
                        our = our_height.unwrap_or(0),
                        "RecursiveProofUpdate: stale, ignoring"
                    );
                } else {
                    // Lightweight STARK verify before storing.
                    // We need the prev state_root from our recent headers.
                    let prev_root_opt = {
                        let ctx = chain.read().await;
                        if height == 0 {
                            Some([0u8; 32]) // pre-genesis accumulator
                        } else {
                            ctx.recent_headers
                                .get(&(height - 1))
                                .map(|h| h.state_root)
                                .or_else(|| {
                                    ctx.store
                                        .get_header(height - 1)
                                        .ok()
                                        .flatten()
                                        .map(|h| h.state_root)
                                })
                        }
                    };
                    let expected_root_opt = {
                        let ctx = chain.read().await;
                        ctx.recent_headers
                            .get(&height)
                            .map(|h| h.state_root)
                            .or_else(|| {
                                ctx.store
                                    .get_header(height)
                                    .ok()
                                    .flatten()
                                    .map(|h| h.state_root)
                            })
                    };

                    match (prev_root_opt, expected_root_opt) {
                        (Some(prev_root), Some(expected_root)) => {
                            match bincode::deserialize::<RecursiveBlockProof>(&proof_bytes) {
                                Ok(proof) => {
                                    match verify_step_stark_only(&proof, &prev_root, &expected_root)
                                    {
                                        Ok(()) => {
                                            let ctx = chain.read().await;
                                            if let Err(e) =
                                                ctx.store.put_recursive_proof(&proof_bytes)
                                            {
                                                tracing::warn!(
                                                    err = ?e,
                                                    "failed to store RecursiveProofUpdate"
                                                );
                                            } else {
                                                tracing::debug!(
                                                    from = %from,
                                                    height,
                                                    "RecursiveProofUpdate: stored"
                                                );
                                            }
                                        }
                                        Err(e) => {
                                            tracing::debug!(
                                                from = %from,
                                                height,
                                                err = ?e,
                                                "RecursiveProofUpdate: STARK verify failed, ignoring"
                                            );
                                        }
                                    }
                                }
                                Err(e) => tracing::debug!(
                                    from = %from,
                                    "RecursiveProofUpdate: deserialize failed: {e}"
                                ),
                            }
                        }
                        _ => {
                            // Headers for this height not in our window — can't verify yet.
                            // The local updater will produce its own proof when it catches up.
                            tracing::debug!(
                                from = %from,
                                height,
                                "RecursiveProofUpdate: missing headers for STARK verify, skipping"
                            );
                        }
                    }
                }
            }
            Ok(NetworkEvent::PeerDisconnected(peer)) => {
                tracing::debug!(peer = %peer, "peer disconnected");
            }
            Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                tracing::warn!(n, "P2P event receiver lagged — some events dropped");
            }
            Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                tracing::info!("P2P event channel closed");
                break;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Orphan pool helper
// ---------------------------------------------------------------------------

/// Insert a block into the orphan pool, evicting the lowest-height entry when
/// the pool is at capacity.
///
/// Keyed by `block.header.prev_block_hash` so that when the missing parent
/// arrives, `orphan_pool.remove(&parent_hash)` instantly finds the child.
///
/// Eviction policy: remove the orphan with the **lowest block height** first.
/// This mimics LRU by height — stale orphans from a long-dead fork are
/// discarded before newer ones that are more likely to be resolved.
fn insert_orphan(
    pool: &mut std::collections::HashMap<[u8; 32], noid_chain::block::Block>,
    block: noid_chain::block::Block,
) {
    use noid_chain::consensus::params::FINALITY_DEPTH;
    const MAX_ORPHAN_POOL: usize = FINALITY_DEPTH as usize * 2; // 36
    if pool.len() >= MAX_ORPHAN_POOL {
        // Find and evict the orphan with the lowest block height.
        if let Some(key) = pool
            .iter()
            .min_by_key(|(_, b)| b.header.height)
            .map(|(k, _)| *k)
        {
            pool.remove(&key);
        }
    }
    pool.insert(block.header.prev_block_hash, block);
}

// ---------------------------------------------------------------------------
// Wallet block update
// ---------------------------------------------------------------------------

/// Apply a newly confirmed block to the in-process wallet state.
///
/// Must be called after `apply_next_block` succeeds and before block pruning.
/// No-op if the wallet is not initialized.
fn update_wallet_for_block(wallet: &SharedWallet, block: &noid_chain::block::Block) {
    let mut guard = wallet.lock().unwrap();
    if let Some(w) = guard.as_mut() {
        // Borrow distinct fields directly — no HashMap clone needed.
        wallet::scanner::update_wallet_from_block(
            &mut w.utxos,
            &mut w.history,
            &mut w.receipts,
            &w.known_addresses,
            &mut w.pending_input_slots,
            block,
        );
        // Confirm any pending (height=0) txs that appear in this block
        // and clear their output slots from pending_output_slots.
        let height = block.header.height;
        for tx in &block.transactions {
            w.confirm_pending_tx(&tx.tx_body_hash.0, height);
            // Clear pending output slots now that the tx is confirmed.
            let output_slots: Vec<u32> = tx
                .body
                .outputs
                .iter()
                .filter(|o| o.valid)
                .map(|o| o.slot_index)
                .collect();
            w.remove_pending_outputs(&output_slots);
        }
        // Save receipts to disk after updating.
        if !w.receipts.is_empty() {
            w.save_receipts();
        }
    }
}

// ---------------------------------------------------------------------------
// Background recursive proof updater (P.19)
// ---------------------------------------------------------------------------

/// Background recursive proof updater.
///
/// Advances the chain's recursive ZK proof one block at a time, storing the
/// result in MDBX. The recursive proof provides O(1) trustless sync for new
/// nodes: instead of replaying all blocks, they verify one constant-size
/// (~11 KB) STARK proof and trust the committed state root.
///
/// ## Design
///
/// - Advances only for **finalised** blocks (>= FINALITY_DEPTH behind tip)
///   so reorgs never invalidate a stored proof.
/// - Blocks with no real ZK proof (coinbase-only) use a null witness — the
///   chain-hash accumulator still advances correctly.
/// - Runs a tight loop when catching up; sleeps when at finality boundary.
/// - `prove_recursive_step` is ~2s on 8 cores → run in `spawn_blocking`.
async fn run_recursive_proof_updater(
    chain: Arc<RwLock<MdbxChainContext>>,
    p2p_cmd: tokio::sync::mpsc::Sender<noid_p2p::NetworkCommand>,
) {
    use noid_block::{witness_builder::block_proof_to_replay_witness, BlockProof};
    use noid_chain::consensus::params::FINALITY_DEPTH;
    use noid_recursive::{
        null_block_replay_witness, prove_genesis_recursive, prove_recursive_step,
        RecursiveBlockProof,
    };
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

        // --- Read current state ---
        let (tip, rec_proof_opt) = {
            let ctx = chain.read().await;
            let tip = ctx.tip_height();
            let rec = match ctx.store.get_recursive_proof() {
                Ok(Some(b)) => bincode::deserialize::<RecursiveBlockProof>(&b).ok(),
                _ => None,
            };
            (tip, rec)
        };

        let rec_height_opt = rec_proof_opt.as_ref().map(|p| p.block_height);

        // Determine next height to prove.
        // None → start with genesis (height 0).
        let next_height: u64 = match rec_height_opt {
            None => 0,
            Some(h) => h + 1,
        };

        // Only prove blocks that are finalised (FINALITY_DEPTH behind tip).
        // This guarantees a reorg can never invalidate the stored proof.
        let finalized_tip = tip.saturating_sub(FINALITY_DEPTH);
        if next_height > finalized_tip {
            let lag = tip.saturating_sub(rec_height_opt.unwrap_or(0));
            if lag > FINALITY_DEPTH {
                tracing::warn!(
                    lag,
                    tip,
                    rec_height = rec_height_opt.unwrap_or(0),
                    "recursive proof DEGRADED — {lag} blocks behind finality boundary"
                );
            } else {
                // Normal: tracking finality boundary (lag ≈ FINALITY_DEPTH)
                tracing::debug!(
                    lag,
                    tip,
                    rec_height = rec_height_opt.unwrap_or(0),
                    "recursive proof NORMAL — at finality boundary"
                );
            }
            continue;
        }

        // --- Prove genesis (special case) ---
        if next_height == 0 {
            tracing::debug!("recursive proof: proving genesis block");
            let result = tokio::task::spawn_blocking(prove_genesis_recursive).await;
            match result {
                Ok(genesis_proof) => {
                    let bytes = bincode::serialize(&genesis_proof).unwrap_or_default();
                    let (stored, tip_hash) = {
                        let ctx = chain.read().await;
                        let tip_hash = ctx.tip_hash();
                        let ok = ctx.store.put_recursive_proof(&bytes).is_ok();
                        (ok, tip_hash)
                    };
                    if stored {
                        tracing::info!("recursive proof: genesis proved");
                        just_advanced = true;
                        let _ = p2p_cmd
                            .send(noid_p2p::NetworkCommand::BroadcastRecursiveProof {
                                height: 0,
                                tip_hash,
                                proof_bytes: bytes,
                            })
                            .await;
                    } else {
                        tracing::error!("failed to store genesis recursive proof");
                    }
                }
                Err(e) => tracing::error!(err = ?e, "genesis recursive proof task panicked"),
            }
            continue;
        }

        // --- Prove block at next_height ---
        // Fetch the block header and any stored BlockProof bytes.
        let (header_opt, block_proof_bytes_opt) = {
            let ctx = chain.read().await;
            let hdr = ctx.store.get_header(next_height).ok().flatten();
            let bp = ctx.store.get_block_proof(next_height).ok().flatten();
            (hdr, bp)
        };

        let header = match header_opt {
            Some(h) => h,
            None => {
                tracing::debug!(next_height, "no header available yet, waiting");
                continue;
            }
        };

        // Build the replay witness.
        // Real proof available  → extract from BlockProof bytes.
        // Coinbase-only block   → null witness (accumulator still advances correctly).
        let witness = match block_proof_bytes_opt {
            Some(ref bytes) if !bytes.is_empty() => {
                match bincode::deserialize::<BlockProof>(bytes) {
                    Ok(bp) => block_proof_to_replay_witness(&bp),
                    Err(e) => {
                        tracing::warn!(
                            next_height,
                            err = ?e,
                            "block proof decode failed — using null witness"
                        );
                        null_block_replay_witness()
                    }
                }
            }
            _ => null_block_replay_witness(),
        };

        // prev_acc comes from the last proved block's accumulator.
        // safe: we only reach here when next_height > 0 and rec_proof_opt is Some.
        let prev_acc = rec_proof_opt.as_ref().unwrap().acc.clone();
        // Move rec_proof_opt into the closure — RecursiveBlockProof is not Clone.
        // prev_acc is already extracted above (ChainAccumulator: Clone).

        tracing::debug!(next_height, "recursive proof: proving step");
        let result = tokio::task::spawn_blocking(move || {
            prove_recursive_step(&witness, &header, &prev_acc, rec_proof_opt.as_ref())
        })
        .await;

        match result {
            Ok(new_proof) => {
                let h = new_proof.block_height;
                let bytes = bincode::serialize(&new_proof).unwrap_or_default();
                let (stored, tip_hash) = {
                    let ctx = chain.read().await;
                    let tip_hash = ctx.tip_hash();
                    let ok = ctx.store.put_recursive_proof(&bytes).is_ok();
                    (ok, tip_hash)
                };
                if stored {
                    tracing::info!(height = h, "recursive proof advanced");
                    just_advanced = true;
                    let _ = p2p_cmd
                        .send(noid_p2p::NetworkCommand::BroadcastRecursiveProof {
                            height: h,
                            tip_hash,
                            proof_bytes: bytes,
                        })
                        .await;
                } else {
                    tracing::error!(
                        err = "store failed",
                        "failed to store recursive proof at height {h}"
                    );
                }
            }
            Err(e) => {
                tracing::error!(
                    next_height,
                    err = ?e,
                    "recursive proof task panicked — skipping block"
                );
            }
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
    rec_proof_height: Option<u64>,
    wallet_addr: Option<&str>,
    mining: bool,
    coinbase: Option<&str>,
    version: &str,
) {
    // ANSI helpers
    let is_tty =
        std::env::var("TERM").map_or(false, |t| t != "dumb") && std::env::var("NO_COLOR").is_err();
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

    // Recursive proof lag
    let rec_str = match rec_proof_height {
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

    // Recursive proof
    row("rec proof", &dim(&rec_str));

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

fn load_config(path: &PathBuf) -> Option<NodeConfig> {
    let expanded = expand_tilde(path);
    let text = std::fs::read_to_string(&expanded).ok()?;
    toml::from_str(&text).ok()
}

fn expand_tilde(p: &PathBuf) -> PathBuf {
    let s = p.to_string_lossy();
    if let Some(rest) = s.strip_prefix("~/") {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
        PathBuf::from(format!("{home}/{rest}"))
    } else {
        p.clone()
    }
}

/// Parse a miner/wallet address from bech32m (`noid1…`) or legacy 64-char hex.
fn parse_address(s: &str) -> anyhow::Result<noid_poseidon2b::primitives::Address> {
    if s.is_empty() {
        return Ok(noid_poseidon2b::primitives::Address([0u8; 32]));
    }
    noid_poseidon2b::primitives::Address::from_str(s)
        .map_err(|e| anyhow::anyhow!("invalid address: {e}"))
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
