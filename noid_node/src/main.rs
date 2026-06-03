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
    let (rpc_handle, rpc_stop_rx) =
        start_rpc_server(rpc_listen, chain.clone(), mempool.clone(), wallet)
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
        let miner_stop = miner.stop_handle(); // Arc<AtomicBool> — set true to cancel Rayon threads

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
                        // Broadcast FIRST — minimises propagation delay to peers.
                        // Wallet update is secondary and must not delay P2P delivery.
                        // This matches Bitcoin's compact-block relay approach:
                        // announce the block immediately, handle local bookkeeping after.
                        let _ = p2p_block_relay
                            .send(noid_p2p::NetworkCommand::BroadcastBlock {
                                block_bytes: block_bytes.clone(),
                            })
                            .await;
                        // Update wallet state AFTER broadcast so P2P is not delayed.
                        if let Ok(block) = noid_chain::block::Block::from_bytes(&block_bytes) {
                            update_wallet_for_block(&miner_wallet, &block);
                        }
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
        Some((task, miner_stop))
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

    // 1. Cancel Rayon PoW threads immediately (they check the flag every ~10M nonces).
    if let Some((_, ref stop_flag)) = miner_handle {
        stop_flag.store(true, std::sync::atomic::Ordering::SeqCst);
        tracing::info!("miner stop flag set");
    }

    // 2. Stop RPC server (no new requests accepted).
    let _ = rpc_handle.stop();

    // 3. Abort the miner tokio task (async loop, not the blocking thread).
    if let Some((task, _)) = miner_handle {
        task.abort();
        // Give Rayon threads up to 500ms to finish their current nonce chunk.
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }

    tracing::info!("goodbye — MDBX flushed on drop");
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
    // Orphan pool: blocks whose parent is not yet known.
    // When the parent arrives, we re-apply the orphan.
    // Keyed by parent_hash, limited to FINALITY_DEPTH entries.
    use noid_chain::consensus::params::FINALITY_DEPTH;
    use std::collections::HashMap;
    let mut orphan_pool: HashMap<[u8; 32], noid_chain::block::Block> = HashMap::new();

    loop {
        match rx.recv().await {
            Ok(NetworkEvent::NewBlock { from, block_bytes }) => {
                tracing::debug!(peer = %from, "received block from P2P");
                match noid_chain::block::Block::from_bytes(&block_bytes) {
                    Ok(block) => {
                        let local_time = unix_now();
                        let block_hash = noid_chain::consensus::pow::full_block_hash(&block.header);

                        // Try to apply this block.
                        let apply_result = {
                            let mut ctx = chain.write().await;
                            ctx.apply_next_block(&block, local_time)
                        };

                        match apply_result {
                            Ok(_) => {
                                let height = block.header.height;
                                let confirmed: Vec<_> = block
                                    .transactions
                                    .iter()
                                    .map(|tx| tx.tx_body_hash)
                                    .collect();
                                let new_view = ChainView::from_mdbx(&*chain.read().await);
                                mempool.on_new_block(&confirmed, height, new_view).await;
                                update_wallet_for_block(&wallet, &block);
                                tracing::info!(height, "applied P2P block");

                                // Apply the chain of orphans that build on the new block.
                                let mut next_hash = block_hash;
                                while let Some(orphan) = orphan_pool.remove(&next_hash) {
                                    let orphan_local_time = unix_now();
                                    next_hash =
                                        noid_chain::consensus::pow::full_block_hash(&orphan.header);
                                    let mut ctx = chain.write().await;
                                    match ctx.apply_next_block(&orphan, orphan_local_time) {
                                        Ok(_) => {
                                            let h = orphan.header.height;
                                            let conf: Vec<_> = orphan
                                                .transactions
                                                .iter()
                                                .map(|tx| tx.tx_body_hash)
                                                .collect();
                                            let nv = ChainView::from_mdbx(&ctx);
                                            drop(ctx);
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

                                // Trim orphan pool to FINALITY_DEPTH
                                if orphan_pool.len() > FINALITY_DEPTH as usize {
                                    orphan_pool.clear();
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
                                            // Start from ancestor's chainwork (fetch from our chain)
                                            // Fetch ancestor chainwork for context (not used in comparison
                                            // because we compare extra-work from ancestor, not absolute work).
                                            let _ancestor_work = {
                                                let ctx = chain.read().await;
                                                ctx.tip_chain_work
                                            };
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
                                            let reorg_result = {
                                                let mut ctx = chain.write().await;
                                                ctx.apply_reorg_mdbx(
                                                    ancestor_height,
                                                    &new_chain,
                                                    local_time,
                                                )
                                            };

                                            match reorg_result {
                                                Ok(result) => {
                                                    let new_view =
                                                        ChainView::from_mdbx(&*chain.read().await);
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

                                                    let new_tip = chain.read().await.tip_height();
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
                                            orphan_pool.insert(block.header.prev_block_hash, block);
                                        }
                                    }
                                    Some(_) => {
                                        // Ancestor IS our current tip — block just has wrong parent somehow.
                                        tracing::debug!(peer = %from, height = block.header.height, "block rejected: already at tip height");
                                    }
                                    None => {
                                        // Parent NOT in our chain.
                                        // ALWAYS use batch headers to find the common ancestor efficiently.
                                        // This resolves ANY fork depth in O(1) round-trips:
                                        //   1. Fetch the peer's headers for the last FINALITY_DEPTH*2 blocks
                                        //   2. Find common ancestor by comparing with our stored headers
                                        //   3. Request only the blocks we're missing
                                        //
                                        // We do NOT fall back to single-hop (one parent at a time) because:
                                        //   - At mainnet, a large pool joining makes blocks sub-second temporarily
                                        //   - Single-hop traversal can't keep up when chains diverge by 50+ blocks
                                        //   - Batch headers always resolves in O(1) regardless of fork depth
                                        let fetch_from =
                                            our_tip_height.saturating_sub(FINALITY_DEPTH);

                                        tracing::info!(
                                            our_height = our_tip_height,
                                            block_height = block.header.height,
                                            peer = %from,
                                            fetch_from,
                                            "orphan block — fetching batch headers to find common ancestor"
                                        );

                                        // Buffer the orphan
                                        orphan_pool.insert(block.header.prev_block_hash, block);

                                        // Request batch headers to find ancestor in O(1) round-trip
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

                let our_height = {
                    let ctx = chain.read().await;
                    ctx.tip_height()
                };

                if our_height == 0 {
                    // Fresh node with no state: request a full STATE SNAPSHOT.
                    //
                    // Paranoid does NOT store block history (DA delete-immediately
                    // policy). New nodes sync via the current state, not block replay.
                    // The state is proven valid by the recursive chain proof (Phase 7).
                    tracing::info!(peer = %peer, "fresh node — requesting state snapshot (Paranoid sync)");
                    p2p_cmd
                        .send(noid_p2p::NetworkCommand::RequestStateSnapshot { peer })
                        .await
                        .ok();
                } else {
                    // Already have state — just catch up on recent blocks.
                    let from = our_height + 1;
                    let count = 18u16;
                    p2p_cmd
                        .send(noid_p2p::NetworkCommand::SyncBlocksFrom {
                            peer,
                            from_height: from,
                            count,
                        })
                        .await
                        .ok();
                    tracing::debug!(from_height = from, count, "triggered recent-block sync");
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
                        use noid_chain::consensus::params::RECENT_BLOCK_RETENTION;

                        if competing.len() > RECENT_BLOCK_RETENTION as usize {
                            // The competing chain is longer than what peers store.
                            // Individual block requests would fail (blocks not available).
                            // Request a full state snapshot instead — this is the
                            // designed sync mechanism for Paranoid.
                            tracing::info!(
                                ancestor = ancestor_height,
                                our_tip,
                                competing_tip = new_tip_height,
                                blocks_needed = competing.len(),
                                max_stored = RECENT_BLOCK_RETENTION,
                                peer = %from,
                                "deep reorg: requesting state snapshot (blocks not available)"
                            );
                            let _ = p2p_cmd
                                .send(noid_p2p::NetworkCommand::RequestStateSnapshot { peer: from })
                                .await;
                        } else {
                            tracing::info!(
                                ancestor = ancestor_height,
                                our_tip,
                                competing_tip = new_tip_height,
                                peer = %from,
                                "reorg via batch headers: fetching {} competing blocks",
                                competing.len()
                            );
                            // Request all competing blocks from peer
                            for hdr in &competing {
                                let _ = p2p_cmd
                                    .send(noid_p2p::NetworkCommand::RequestBlock {
                                        peer: from,
                                        height: hdr.height,
                                    })
                                    .await;
                            }
                            // Blocks will arrive as NewBlock events and trigger
                            // the reorg through the normal BadParentHash path.
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
                    // going further back
                    let oldest = headers.first().map(|h| h.height).unwrap_or(0);
                    if oldest > 0 {
                        let fetch_from = oldest.saturating_sub(512);
                        tracing::debug!(
                            fetch_from,
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
            Ok(NetworkEvent::StateSnapshot { from, snapshot }) => {
                // A peer sent us their full state snapshot (we requested it in PeerConnected).
                // Apply it to bootstrap this node's state without block history.
                tracing::info!(
                    from = %from,
                    tip = snapshot.tip_height,
                    segments = snapshot.segments.len(),
                    active_slots = snapshot.active_slot_count,
                    "applying state snapshot from peer"
                );

                // Decode segments
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

                // Decode nullifier blocks
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
                        // Wallet scan will pick up any UTXOs on next call
                        tracing::info!(
                            height = new_height,
                            "state snapshot applied — requesting recent blocks to catch up"
                        );
                        // Request the most recent blocks to catch up from snapshot tip
                        let _ = p2p_cmd
                            .send(noid_p2p::NetworkCommand::SyncBlocksFrom {
                                peer: from,
                                from_height: new_height + 1,
                                count: 18,
                            })
                            .await;
                    }
                    Err(e) => {
                        tracing::warn!(err = ?e, "failed to apply state snapshot");
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

/// Background recursive proof updater (Phase 7).
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
async fn run_recursive_proof_updater(chain: Arc<RwLock<MdbxChainContext>>) {
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
                    let ctx = chain.read().await;
                    if let Err(e) = ctx.store.put_recursive_proof(&bytes) {
                        tracing::error!(err = ?e, "failed to store genesis recursive proof");
                    } else {
                        tracing::info!("recursive proof: genesis proved");
                        just_advanced = true;
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
                let ctx = chain.read().await;
                if let Err(e) = ctx.store.put_recursive_proof(&bytes) {
                    tracing::error!(err = ?e, "failed to store recursive proof at height {h}");
                } else {
                    tracing::info!(height = h, "recursive proof advanced");
                    just_advanced = true;
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
