// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! # paranoid — Paranoid Full Node Binary
//!
//! Startup sequence (ROADMAP2.md §Node Binary):
//! 1. Load config + init tracing
//! 2. Open MDBX (open_or_create — genesis if first run)
//! 3. Start mempool (ChainView snapshot from MDBX)
//! 4. Start P2P network (gossipsub + req-resp)
//! 5. Dial seed peers
//! 6. Start RPC server (JSON-RPC on configured address)
//! 7. Start miner (if --mine or config.mining.enabled)
//! 8. Start background recursive proof updater
//! 9. Shutdown on Ctrl-C

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use clap::Parser;
use tokio::sync::RwLock;
use tracing_subscriber::EnvFilter;

use noid_chain::consensus::{NetworkConfig, NetworkKind};
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

#[derive(Parser, Debug)]
#[command(
    name = "paranoid",
    about = "Paranoid full node daemon — proof-native transparent UTXO chain",
    version = env!("CARGO_PKG_VERSION"),
    long_about = None,
)]
struct Cli {
    /// Network to connect to: mainnet or testnet.
    #[arg(long, default_value = "mainnet")]
    network: NetworkKind,

    /// Path to the TOML config file.
    #[arg(short, long)]
    config: Option<PathBuf>,

    /// Enable built-in PoW mining.
    #[arg(long)]
    mine: bool,

    /// Miner reward address (32-byte hex).
    #[arg(long)]
    miner_address: Option<String>,

    /// Override data directory.
    #[arg(long)]
    data_dir: Option<PathBuf>,

    /// P2P listen address (libp2p multiaddr).
    #[arg(long)]
    p2p_listen: Option<String>,

    /// RPC listen address.
    #[arg(long)]
    rpc_listen: Option<String>,

    /// Seed peer multiaddrs (comma-separated).
    #[arg(long, value_delimiter = ',')]
    seeds: Vec<String>,

    /// Log level filter.
    #[arg(long, default_value = "info")]
    log: String,
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // --- Tracing ---
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new(&cli.log))
        .with_target(true)
        .with_thread_ids(false)
        .init();

    // --- Network ---
    let net = NetworkConfig::for_kind(cli.network);
    tracing::info!(network = %net.kind, "Paranoid node daemon starting");

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
    if cli.mine {
        cfg.mining.enabled = true;
    }
    if let Some(addr) = cli.miner_address {
        cfg.mining.miner_address = addr;
    }
    for seed in cli.seeds {
        cfg.network.seeds.push(seed);
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
    tracing::info!(path = %data_dir.display(), network = %net.kind, "opening MDBX");
    let ctx = MdbxChainContext::open_or_create(&data_dir).context("open MDBX")?;
    let tip_height = ctx.tip_height();
    let state_root = hex::encode(ctx.tip_header().state_root);
    tracing::info!(height = tip_height, state_root = %state_root, "chain loaded");
    let chain = Arc::new(RwLock::new(ctx));

    // --- Mempool ---
    let view = ChainView::from_mdbx(&*chain.read().await);
    let mempool = AsyncMempool::new(view, MempoolConfig::default());
    tracing::info!("mempool ready");

    // --- Wallet ---
    let wallet_path = data_dir.join("wallet.key");
    let wallet_state = match WalletState::create_or_load(wallet_path) {
        Ok(w) => {
            tracing::info!(address = %hex::encode(w.primary_address().0), "wallet ready");
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
    let listen_addr: libp2p::Multiaddr =
        p2p_listen_str.parse().context("parse P2P listen address")?;

    let (p2p, _p2p_task) = P2PNetwork::start(listen_addr.clone(), chain.clone(), mempool.clone());
    tracing::info!(listen = %listen_addr, network = %net.kind, "P2P started");

    // Dial seeds: CLI seeds + config seeds + DNS seeds.
    let all_seeds: Vec<String> = cfg
        .network
        .seeds
        .clone()
        .into_iter()
        .chain(net.dns_seeds.iter().map(|s| s.to_string()))
        .collect();
    for seed_addr in &all_seeds {
        // Try to parse the full multiaddr (may include /p2p/<peer-id>).
        // Fallback: strip the /p2p/ suffix and dial TCP-only (local testing).
        let addr = seed_addr.parse::<libp2p::Multiaddr>().or_else(|_| {
            // If parsing fails (e.g. multiaddr crate can't parse /p2p/<id>),
            // strip the peer ID and dial the transport address only.
            seed_addr
                .split("/p2p/")
                .next()
                .filter(|s| !s.is_empty())
                .and_then(|s| s.parse::<libp2p::Multiaddr>().ok())
                .ok_or(())
        });
        match addr {
            Ok(addr) => {
                tracing::info!(addr = %addr, "dialing seed");
                p2p.dial(addr).await;
            }
            Err(_) => {
                if seed_addr.starts_with('/') {
                    tracing::warn!(addr = %seed_addr, "could not parse seed multiaddr, skipping");
                }
                // DNS names (seed1.noid.network) are silently skipped.
            }
        }
    }

    // Background P2P event handler.
    let p2p_chain = chain.clone();
    let p2p_mempool = mempool.clone();
    let p2p_wallet = shared_wallet.clone();
    let p2p_events = p2p.subscribe();
    let p2p_cmd_for_events = p2p.cmd_tx.clone();
    tokio::spawn(async move {
        handle_p2p_events(
            p2p_events,
            p2p_chain,
            p2p_mempool,
            p2p_wallet,
            p2p_cmd_for_events,
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
    let rpc_handle = start_rpc_server(rpc_listen, chain.clone(), mempool.clone(), wallet)
        .await
        .context("start RPC server")?;
    tracing::info!(listen = %rpc_listen, "RPC ready");

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
        tracing::info!(address = %hex::encode(miner_addr.0), "miner coinbase address");
        let miner_cfg = MinerConfig {
            miner_address: miner_addr,
            pow_threads: cfg.mining.threads,
            ..Default::default()
        };
        let (miner, mut miner_rx) = BlockMiner::new(miner_cfg, mempool.clone(), chain.clone());

        let p2p_block_relay = p2p.cmd_tx.clone();
        let miner_wallet = shared_wallet.clone();
        tokio::spawn(async move {
            loop {
                match miner_rx.recv().await {
                    Ok(noid_miner::MinerEvent::BlockFound {
                        block_bytes,
                        height,
                        ..
                    }) => {
                        tracing::info!(height, "broadcasting found block");
                        // Update wallet for locally mined block (before broadcast).
                        // This ensures coinbase UTXOs and change outputs are
                        // reflected immediately without waiting for a P2P round-trip.
                        if let Ok(block) = noid_chain::block::Block::from_bytes(&block_bytes) {
                            update_wallet_for_block(&miner_wallet, &block);
                        }
                        let _ = p2p_block_relay
                            .send(noid_p2p::NetworkCommand::BroadcastBlock { block_bytes })
                            .await;
                    }
                    Ok(noid_miner::MinerEvent::ProveFailed { height, error }) => {
                        tracing::warn!(height, err = %error, "block prove failed");
                    }
                    Ok(_) => {} // TemplateRefreshed, MiningCancelled — no action needed
                    Err(_) => break, // channel closed (miner stopped)
                }
            }
        });

        let task = tokio::spawn(async move { miner.run().await });
        tracing::info!("miner started");
        Some(task)
    } else {
        None
    };

    // --- Background Recursive Proof Updater (P.19) ---
    let rec_chain = chain.clone();
    tokio::spawn(async move {
        run_recursive_proof_updater(rec_chain).await;
    });

    tracing::info!(
        network = %net.kind,
        p2p = %listen_addr,
        rpc = %rpc_listen,
        "paranoid running — press Ctrl-C to stop"
    );

    // --- Shutdown ---
    tokio::signal::ctrl_c().await.context("Ctrl-C")?;
    tracing::info!("shutting down");
    rpc_handle.stop()?;
    if let Some(h) = miner_handle {
        h.abort();
    }
    tracing::info!("goodbye");
    Ok(())
}

// ---------------------------------------------------------------------------
// P2P event handler
// ---------------------------------------------------------------------------

async fn handle_p2p_events(
    mut rx: tokio::sync::broadcast::Receiver<NetworkEvent>,
    chain: Arc<RwLock<MdbxChainContext>>,
    mempool: AsyncMempool,
    wallet: SharedWallet,
    p2p_cmd: tokio::sync::mpsc::Sender<noid_p2p::NetworkCommand>,
) {
    loop {
        match rx.recv().await {
            Ok(NetworkEvent::NewBlock { from, block_bytes }) => {
                tracing::debug!(peer = %from, "received block from P2P");
                match noid_chain::block::Block::from_bytes(&block_bytes) {
                    Ok(block) => {
                        let local_time = unix_now();
                        let mut ctx = chain.write().await;
                        match ctx.apply_next_block(&block, local_time) {
                            Ok(_) => {
                                let height = block.header.height;
                                let confirmed: Vec<_> = block
                                    .transactions
                                    .iter()
                                    .map(|tx| tx.tx_body_hash)
                                    .collect();
                                let new_view = ChainView::from_mdbx(&ctx);
                                drop(ctx);
                                mempool.on_new_block(&confirmed, height, new_view).await;
                                update_wallet_for_block(&wallet, &block);
                                tracing::info!(height, "applied P2P block");
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
                match noid_tx::TxIntent::from_bytes(&intent_bytes) {
                    Ok(intent) => {
                        match mempool.submit(intent, intent_bytes).await {
                            Ok(hash) => {
                                tracing::debug!(hash = ?hash, "P2P tx admitted");
                            }
                            Err(e) if e.is_soft() => {
                                // Soft reject — normal (duplicate, slot conflict). Ignore.
                            }
                            Err(e) => {
                                tracing::debug!(err = %e, "P2P tx rejected");
                            }
                        }
                    }
                    Err(_) => {} // malformed intent, ignore
                }
            }
            Ok(NetworkEvent::PeerConnected(peer)) => {
                tracing::info!(peer = %peer, "peer connected");
                // Trigger initial block sync: request up to RECENT_BLOCK_RETENTION blocks
                // (last 18 blocks stored by peers).
                let our_height = {
                    let ctx = chain.read().await;
                    ctx.tip_height()
                };
                // Request recent blocks from the connected peer starting at our tip + 1.
                let from = our_height + 1;
                let count = 18u16; // FINALITY_DEPTH = recent block retention
                p2p_cmd
                    .send(noid_p2p::NetworkCommand::SyncBlocksFrom {
                        peer,
                        from_height: from,
                        count,
                    })
                    .await
                    .ok();
                tracing::debug!(from_height = from, count, "triggered initial block sync");
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
// Wallet block update
// ---------------------------------------------------------------------------

/// Apply a newly confirmed block to the in-process wallet state.
///
/// Must be called after `apply_next_block` succeeds and before block pruning.
/// No-op if the wallet is not initialized.
fn update_wallet_for_block(wallet: &SharedWallet, block: &noid_chain::block::Block) {
    let mut guard = wallet.lock().unwrap();
    if let Some(w) = guard.as_mut() {
        let known = w.known_addresses.clone();
        wallet::scanner::update_wallet_from_block(
            &mut w.utxos,
            &mut w.history,
            &mut w.receipts,
            &known,
            block,
        );
        // Confirm any pending (height=0) txs that appear in this block.
        let height = block.header.height;
        for tx in &block.transactions {
            w.confirm_pending_tx(&tx.tx_body_hash.0, height);
        }
    }
}

// ---------------------------------------------------------------------------
// Background recursive proof updater (P.19)
// ---------------------------------------------------------------------------

/// Catch up the recursive chain proof if it has fallen behind the tip.
///
/// The recursive proof provides O(1) sync for new nodes. It is NOT required
/// for consensus validity — this task runs in DEGRADED mode silently.
///
/// In Phase 3, this is a stub that logs the lag. Full implementation in
/// Phase 5 will call `prove_recursive_step` for each lagging block.
async fn run_recursive_proof_updater(chain: Arc<RwLock<MdbxChainContext>>) {
    use noid_chain::consensus::params::FINALITY_DEPTH;
    use std::time::Duration;

    const LAG_WARNING: u64 = 3;
    const POLL_INTERVAL_SECS: u64 = 30;

    loop {
        tokio::time::sleep(Duration::from_secs(POLL_INTERVAL_SECS)).await;

        let ctx = chain.read().await;
        let tip = ctx.tip_height();

        // Check recursive proof lag.
        let rec_height = match ctx.store.get_recursive_proof() {
            Ok(Some(_)) => {
                // Proof exists — TODO Phase 5: parse and check block_height field.
                // For now, assume it's at the genesis.
                0u64
            }
            Ok(None) => 0u64,
            Err(_) => continue,
        };
        drop(ctx);

        let lag = tip.saturating_sub(rec_height);
        if lag > FINALITY_DEPTH {
            tracing::warn!(
                lag,
                tip,
                rec_height,
                "recursive proof FALLBACK mode — light clients cannot O(1) sync"
            );
        } else if lag > LAG_WARNING {
            tracing::info!(lag, "recursive proof DEGRADED — catching up");
            // Phase 5: call prove_recursive_step for each lagging block.
        }
        // lag <= LAG_WARNING: NORMAL mode, no action needed.
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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

fn parse_address(hex_str: &str) -> anyhow::Result<noid_poseidon2b::primitives::Address> {
    if hex_str.is_empty() {
        return Ok(noid_poseidon2b::primitives::Address([0u8; 32]));
    }
    let bytes: [u8; 32] = hex::decode(hex_str)
        .context("decode miner_address hex")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("miner_address must be exactly 32 bytes (64 hex chars)"))?;
    Ok(noid_poseidon2b::primitives::Address(bytes))
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
