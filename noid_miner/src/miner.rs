// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! `BlockMiner` — the parallel PoW + BlockProof generation orchestrator.
//!
//! ## Parallel block production design
//!
//! ```text
//! loop {
//!   template = build_template(mempool, ctx)
//!
//!   ┌─────────────────────────┐   ┌─────────────────────────────────┐
//!   │  PoW Search             │   │  BlockProof generation          │
//!   │  Blake3(header_core||n) │   │  prove_block(witnesses, &[])    │
//!   │  < difficulty_target    │   │  ~10s on 8 cores (100 txs)      │
//!   └──────────┬──────────────┘   └──────────────┬──────────────────┘
//!              │                                 │
//!              └────────────┬────────────────────┘
//!                           │ both complete
//!                           ▼
//!   seal(nonce, proof_hash, witness_root) → Block
//!   apply_to_chain + broadcast via P2P
//! }
//! ```
//!
//! Internal miner uses separate Rayon pools for PoW and proving.  With default
//! settings it splits available cores roughly in half and adapts the transaction
//! cap to recent proof throughput instead of always trying to fill 256 txs.
//! External miner mode disables internal PoW, so the node can spend its CPUs on
//! template building, BlockProof generation, validation, RPC, and P2P while miners run elsewhere.
//!
//! Template refresh triggers (see run loop):
//!   1. Heartbeat every `refresh_interval_secs` seconds (safety net)
//!   2. First `TxAdmitted` while a coinbase-only marker proof is done
//!   3. New chain tip from P2P (block received or snapshot applied)

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::{Duration, Instant};

use tokio::sync::{broadcast, RwLock};
use tokio::time::interval;

use noid_chain::block::Block;
use noid_chain::consensus::pow::full_block_hash;
use noid_chain::storage::MdbxChainContext;
use noid_mempool::AsyncMempool;
use noid_poseidon2b::primitives::Address;

use crate::template::{TemplateBuilder, TemplateChainSnapshot, TemplateRefreshTrigger};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for the block miner.
#[derive(Debug, Clone)]
pub struct MinerConfig {
    /// Address that receives the coinbase reward.
    pub miner_address: Address,
    /// Number of Rayon threads for internal PoW search.
    /// 0 = balanced default (roughly half of available cores).
    pub mining_threads: usize,
    /// Safety-net heartbeat interval (seconds).
    ///
    /// Fires only if the miner has been stuck without a block for this long.
    /// Normal template refreshes happen immediately via `sync_ready` (P2P
    /// block received) and `TxAdmitted` for coinbase-only sealed templates.
    /// This timer exists only for edge cases where both are silent.
    ///
    /// Must be > BLOCK_TIME to avoid firing during active proving and
    /// inserting unnecessary coinbase blocks.  Default: 5 × BLOCK_TIME = 75s.
    pub refresh_interval_secs: u64,
}

impl Default for MinerConfig {
    fn default() -> Self {
        Self {
            miner_address: Address([0u8; 32]),
            mining_threads: 0,
            refresh_interval_secs: 75, // 5 × BLOCK_TIME; real triggers are sync_ready + TxAdmitted
        }
    }
}

impl MinerConfig {
    pub fn with_address(mut self, addr: Address) -> Self {
        self.miner_address = addr;
        self
    }
}

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

/// Events emitted by the miner (for P2P broadcast, logging, RPC, recursive proof).
#[derive(Debug, Clone)]
pub enum MinerEvent {
    /// New block found and sealed. Contains the sealed block bytes for P2P.
    BlockFound {
        height: u64,
        hash: [u8; 32],
        n_txs: usize,
        pow_nonce: u128,
        /// Serialized Block bytes for P2P broadcast.
        block_bytes: Vec<u8>,
        /// Serialized BlockProof bytes for P2P broadcast.
        /// Empty for coinbase-only blocks (stub proof).
        block_proof_bytes: Vec<u8>,
        /// Serialized public AuthGKR sidecar bytes bound by header.witness_root.
        /// Empty for coinbase-only blocks.
        block_auth_sidecar_bytes: Vec<u8>,
    },
    /// Template refreshed.
    TemplateRefreshed {
        height: u64,
        n_txs: usize,
        trigger: TemplateRefreshTrigger,
    },
    /// Mining cancelled (new P2P block or heartbeat).
    MiningCancelled { reason: String },
    /// BlockProof generation failed (non-fatal: block is abandoned, new template built).
    ProveFailed { height: u64, error: String },
}

// ---------------------------------------------------------------------------
// CPU split + adaptive block sizing
// ---------------------------------------------------------------------------

fn available_threads() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .max(1)
}

/// Internal mining default: do not give PoW every core.  A balanced split keeps
/// the block prover responsive while still giving PoW more than a token thread.
fn effective_mining_threads(configured: usize) -> usize {
    if configured > 0 {
        return configured.max(1);
    }
    let total = available_threads();
    if total <= 2 {
        1
    } else {
        (total / 2).max(1)
    }
}

fn effective_prover_threads(mining_configured: usize) -> usize {
    let total = available_threads();
    let mining = effective_mining_threads(mining_configured).min(total.saturating_sub(1).max(1));
    total.saturating_sub(mining).max(1)
}

fn adaptive_user_tx_limit(ms_per_tx_ewma: Option<f64>) -> usize {
    let consensus_max = noid_chain::consensus::params::BLOCK_MAX_TXS.saturating_sub(1);
    if consensus_max == 0 {
        return 0;
    }

    // Keep proving comfortably under the 15s consensus target.  PoW runs in
    // parallel, but a full block must still have a ready proof before it can be
    // sealed and propagated.
    let block_time_ms = noid_chain::consensus::params::BLOCK_TIME as f64 * 1_000.0;
    let budget_ms = (block_time_ms * 0.70).max(1_000.0);
    let ms_per_tx = ms_per_tx_ewma.unwrap_or(100.0).max(10.0);
    let cap = (budget_ms / ms_per_tx).floor() as usize;
    cap.clamp(1, consensus_max)
}

// ---------------------------------------------------------------------------
// BlockMiner
// ---------------------------------------------------------------------------

/// The main block production orchestrator.
/// Callback invoked synchronously inside `apply_found_block`, before the mempool
/// is updated. Enables the built-in wallet to capture receipts race-free:
/// by the time `getMempoolSize` drops to 0, the receipt is already stored.
///
/// Remote wallets subscribe via the P2P block event instead.
pub type BlockAppliedHook = Arc<dyn Fn(&noid_chain::block::Block) + Send + Sync>;

pub struct BlockMiner {
    config: MinerConfig,
    mempool: AsyncMempool,
    chain: Arc<RwLock<MdbxChainContext>>,
    events: broadcast::Sender<MinerEvent>,
    pow_pool: Arc<rayon::ThreadPool>,
    prove_pool: Arc<rayon::ThreadPool>,
    /// Cancel flag: set to abort current PoW search and restart.
    cancel_pow: Arc<AtomicBool>,
    /// Permanent stop flag: set only by stop(), never reset. The main loop
    /// checks this at the top of each iteration and breaks cleanly.
    stopped: Arc<AtomicBool>,
    /// Notified when the chain is sufficiently synced to begin mining.
    sync_ready: Arc<tokio::sync::Notify>,
    /// Semaphore (1 permit) preventing concurrent BlockProof generation tasks from accumulating.
    /// Each heartbeat/mempool refresh drops the JoinHandle but NOT the blocking task;
    /// without this guard N × 10s prove tasks pile up and saturate all CPU.
    prove_semaphore: Arc<tokio::sync::Semaphore>,
    /// Optional hook called synchronously after block is applied to chain, before
    /// the mempool is updated. Used by the built-in wallet to generate receipts
    /// race-free (receipt ready before getMempoolSize → 0 is observable).
    on_block_applied: Option<BlockAppliedHook>,
}

impl BlockMiner {
    pub fn new(
        config: MinerConfig,
        mempool: AsyncMempool,
        chain: Arc<RwLock<MdbxChainContext>>,
        sync_ready: Arc<tokio::sync::Notify>,
    ) -> (Self, broadcast::Receiver<MinerEvent>) {
        let (events, rx) = broadcast::channel(32);
        let mining_threads = effective_mining_threads(config.mining_threads);
        let prover_threads = effective_prover_threads(config.mining_threads);
        tracing::info!(mining_threads, prover_threads, "internal miner CPU split");
        let miner = Self {
            config,
            mempool,
            chain,
            events,
            pow_pool: Arc::new(
                rayon::ThreadPoolBuilder::new()
                    .num_threads(mining_threads)
                    .thread_name(|i| format!("noid-pow-{i}"))
                    .build()
                    .expect("create PoW Rayon pool"),
            ),
            prove_pool: Arc::new(
                rayon::ThreadPoolBuilder::new()
                    .num_threads(prover_threads)
                    .thread_name(|i| format!("noid-prove-{i}"))
                    .build()
                    .expect("create prove Rayon pool"),
            ),
            cancel_pow: Arc::new(AtomicBool::new(false)),
            stopped: Arc::new(AtomicBool::new(false)),
            sync_ready,
            prove_semaphore: Arc::new(tokio::sync::Semaphore::new(1)),
            on_block_applied: None,
        };
        (miner, rx)
    }

    /// Register a callback to be called synchronously after each block is applied
    /// to the chain, before the mempool is updated. The built-in wallet uses this
    /// to generate payment receipts race-free at any mining speed.
    pub fn set_block_applied_hook(&mut self, hook: BlockAppliedHook) {
        self.on_block_applied = Some(hook);
    }

    /// Cancel the current PoW search (call when a new P2P block arrives).
    pub fn cancel_current_pow(&self) {
        self.cancel_pow.store(true, Ordering::Relaxed);
    }

    /// Signal the miner to stop after the current search iteration.
    /// Sets both the permanent `stopped` flag (causes the loop to break) and
    /// `cancel_pow` (causes the current PoW chunk to abort quickly).
    pub fn stop(&self) {
        self.stopped.store(true, Ordering::Release);
        self.cancel_pow.store(true, Ordering::SeqCst);
        tracing::info!("miner stop signal sent — Rayon threads will exit at next iteration");
    }

    pub fn subscribe(&self) -> broadcast::Receiver<MinerEvent> {
        self.events.subscribe()
    }

    /// Return a cloned handle to the PoW cancel flag.
    /// Call `handle.store(true, Ordering::SeqCst)` to stop mining cleanly.
    /// This must be called BEFORE `run()` consumes the miner.
    pub fn stop_handle(&self) -> Arc<AtomicBool> {
        self.cancel_pow.clone()
    }

    /// Return a cloned handle to the permanent shutdown flag.
    /// Set to `true` (with `Ordering::Release`) to signal the miner loop to
    /// exit after the current PoW chunk finishes. Combine with `stop_handle()`
    /// to also abort the current PoW immediately.
    /// This must be called BEFORE `run()` consumes the miner.
    pub fn stopped_handle(&self) -> Arc<AtomicBool> {
        self.stopped.clone()
    }

    /// Main mining loop. Run in a dedicated `tokio::spawn` task.
    /// Never returns under normal operation.
    pub async fn run(self) {
        // Sync guard: do not mine until chain is current.
        {
            use noid_chain::consensus::params::BLOCK_TIME;
            let (height, tip_ts) = {
                let ctx = self.chain.read().await;
                (ctx.tip_height(), ctx.tip_header().timestamp)
            };
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            // "Fresh" = tip within 3 block-times of wall clock.
            let is_fresh = tip_ts > 0 && now.saturating_sub(tip_ts) < BLOCK_TIME * 3;

            if height > 0 && is_fresh {
                tracing::debug!(height, "miner: chain current, starting");
            } else if height > 0 {
                let age = now.saturating_sub(tip_ts);
                tracing::info!(height, age_secs = age, "waiting for peer sync (max 30s)");
                tokio::select! {
                    _ = self.sync_ready.notified() => {
                        let h = self.chain.read().await.tip_height();
                        tracing::debug!(height = h, "miner: sync ready, starting");
                    }
                    _ = tokio::time::sleep(std::time::Duration::from_secs(30)) => {
                        let h = self.chain.read().await.tip_height();
                        tracing::info!(height = h, "miner: sync timeout, starting anyway");
                    }
                }
            } else {
                // Fresh chain (height == 0): wait for either a peer snapshot or
                // the sync_ready signal (fired immediately when --genesis is set).
                tracing::debug!("miner: height=0, waiting for sync_ready or 60s timeout");
                tokio::select! {
                    _ = self.sync_ready.notified() => {
                        let h = self.chain.read().await.tip_height();
                        tracing::debug!(height = h, "miner: ready, starting");
                    }
                    _ = tokio::time::sleep(std::time::Duration::from_secs(60)) => {
                        tracing::info!("miner: no peers after 60s, starting from genesis");
                    }
                }
            }
        }

        let builder = TemplateBuilder::new(self.mempool.clone());
        let addr = self.config.miner_address;
        let cancel = self.cancel_pow.clone();
        let mut heartbeat = interval(Duration::from_secs(self.config.refresh_interval_secs));
        let mut mempool_events = self.mempool.subscribe();
        let mut prove_ms_per_tx_ewma: Option<f64> = None;

        tracing::debug!(address = %addr, "BlockMiner started");

        loop {
            // Clean shutdown: stop() sets `stopped` permanently; break before
            // starting a new template build so the task exits promptly.
            if self.stopped.load(Ordering::Acquire) {
                tracing::info!("miner: shutdown flag set, exiting loop");
                break;
            }

            // --- Build template ---
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            let snapshot_result = {
                let mut ctx = self.chain.write().await;
                TemplateChainSnapshot::from_context(&mut ctx)
            };
            let snapshot = match snapshot_result {
                Ok(snapshot) => snapshot,
                Err(e) => {
                    tracing::warn!(err = ?e, "template snapshot failed, retrying in 1s");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
            };
            let prev_state_root = snapshot.prev_state_root();
            let max_user_txs = adaptive_user_tx_limit(prove_ms_per_tx_ewma);
            let tmpl = match builder
                .build_from_snapshot_with_limit(&snapshot, addr, now, max_user_txs)
                .await
            {
                Some(t) => t,
                None => {
                    tracing::warn!("template build failed, retrying in 1s");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
            };

            let height = tmpl.inner.height;
            let n_txs = tmpl.inner.n_txs();

            let _ = self.events.send(MinerEvent::TemplateRefreshed {
                height,
                n_txs,
                trigger: TemplateRefreshTrigger::Startup,
            });
            tracing::debug!(
                height,
                n_txs,
                max_user_txs,
                prove_ms_per_tx_ewma,
                "mining template ready"
            );

            // Track when PoW search started so we can report solve time.
            let pow_start = std::time::Instant::now();
            // The heartbeat is a per-template safety net. Reset it here so an old
            // interval tick from a long previous search cannot cancel a fresh
            // user-transaction template and force the same block proof to be rebuilt.
            heartbeat.reset();

            cancel.store(false, Ordering::Relaxed);

            // Track when prove completes. Coinbase-only proofs are marker proofs; on the
            // first admitted tx we cancel their PoW search and rebuild immediately. For
            // user-tx templates we intentionally do not listen to later mempool events:
            // dropping the JoinHandle would not cancel spawn_blocking proof work and would
            // wastefully rebuild the same block proof in the next loop.
            let prove_done = Arc::new(AtomicBool::new(false));
            let prove_done_clone = prove_done.clone();

            // --- Parallel: PoW + BlockProof generation ---
            // Extract only the PoW header — avoids cloning the full BlockTemplate
            // (which includes all transaction and proof bytes) just for PoW.
            let pow_header = tmpl.header_for_pow(0);
            let tmpl = Arc::new(tmpl);
            let tmpl_prove = tmpl.clone();
            let cancel_pow = cancel.clone();
            let pow_pool = self.pow_pool.clone();
            let prove_pool = self.prove_pool.clone();

            // Try to acquire the single-permit prove semaphore.
            // spawn_blocking tasks are NOT cancelled when JoinHandles are dropped;
            // without this guard each 15s heartbeat can accumulate another ~10s prove
            // task, eventually saturating all CPU cores.
            let prove_permit = self.prove_semaphore.clone().try_acquire_owned();

            // If the semaphore is already held and the template has user txs we
            // cannot legally use a stub proof — skip this iteration and wait for
            // the running prove to release the permit.
            if prove_permit.is_err() && tmpl.n_user_txs() > 0 {
                tracing::debug!(
                    height,
                    "prove task busy and block has user txs — skipping this template iteration"
                );
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
            }

            // PoW: Blake3 over header_core, CPU-bound via the dedicated PoW Rayon pool.
            let pow_handle = tokio::task::spawn_blocking(move || {
                pow_pool.install(|| crate::pow::search_pow_parallel(&pow_header, &cancel_pow))
            });

            // BlockProof generation: run for real (permit held until done) or return a consensus-legal
            // stub for coinbase-only blocks when the prove slot is already occupied.
            let prove_handle = match prove_permit {
                Ok(permit) => tokio::task::spawn_blocking(move || {
                    // Run prove inside a scope so the semaphore permit is released
                    // BEFORE we set prove_done. This guarantees: when the miner loop
                    // sees prove_done=true, the semaphore is already free for the next
                    // template rebuild.
                    let started = Instant::now();
                    let result = {
                        let _permit = permit;
                        prove_pool.install(|| run_prove_block(&*tmpl_prove, prev_state_root))
                    };
                    let elapsed = started.elapsed();
                    prove_done_clone.store(true, Ordering::Release);
                    (result, elapsed)
                }),
                Err(_) => {
                    // Semaphore busy, but coinbase-only block — stub is consensus-legal.
                    tracing::debug!(
                        height,
                        "prove task busy, will use stub proof (coinbase-only this round)"
                    );
                    tokio::task::spawn_blocking(move || {
                        // Stub is instant; mark prove_done so TxAdmitted can trigger rebuild.
                        prove_done_clone.store(true, Ordering::Release);
                        (Ok(([1u8; 32], [1u8; 32], vec![], vec![])), Duration::ZERO)
                    })
                }
            };

            // Wait for both (or cancel from heartbeat/mempool).
            tokio::select! {
                (pow_res, prove_res) = async {
                    let p = pow_handle.await;
                    let r = prove_handle.await;
                    (p, r)
                } => {
                    match (pow_res, prove_res) {
                        (Ok(Some(sol)), Ok((Ok((proof_hash, witness_root, block_proof_bytes, block_auth_sidecar_bytes)), prove_elapsed))) => {
                            let block = tmpl.seal(sol.nonce, proof_hash, witness_root);
                            let block_bytes = block.to_bytes();
                            let hash = full_block_hash(&block.header);
                            let elapsed = pow_start.elapsed();
                            let elapsed_s = elapsed.as_secs_f64();

                            // Count leading zeros of the difficulty target (MSB-first, LE).
                            // Matches block_work() in difficulty.rs — higher = harder.
                            // Genesis = 27lz. ASERT raises this when blocks arrive faster
                            // than BLOCK_TIME (15s) and lowers it when they're slower.
                            let diff_lz: u32 = {
                                let t = &block.header.difficulty_target;
                                let mut lz = 0u32;
                                for i in (0..32).rev() {
                                    if t[i] == 0 { lz += 8; }
                                    else { lz += t[i].leading_zeros(); break; }
                                }
                                lz
                            };

                            let user_txs = tmpl.n_user_txs();
                            if user_txs > 0 && prove_elapsed > Duration::ZERO {
                                let sample = prove_elapsed.as_secs_f64() * 1_000.0 / user_txs as f64;
                                prove_ms_per_tx_ewma = Some(match prove_ms_per_tx_ewma {
                                    Some(prev) => prev * 0.75 + sample * 0.25,
                                    None => sample,
                                });
                            }
                            tracing::info!(
                                height,
                                hash = %hex::encode(hash),
                                n_txs,
                                prove_ms = prove_elapsed.as_millis(),
                                prove_ms_per_tx_ewma,
                                time = %format!("{elapsed_s:.2}s"),
                                diff = %format!("lz{diff_lz}"),
                                "block found"
                            );

                            // IMPORTANT: apply and store the block FIRST, THEN fire the event.
                            // The announcement triggers peers to request the block immediately;
                            // if we fire the event before storing, a fast peer gets None.
                            if let Err(e) = self.apply_found_block(&block, &block_proof_bytes, &block_auth_sidecar_bytes).await {
                                tracing::warn!(height, "miner: block superseded (reorg in progress): {e}");
                            }

                            // Store block proof + public auth sidecar bytes for recursive proof advancement
                            // and for serving compact P2P pull requests.
                            if !block_proof_bytes.is_empty() {
                                let ctx = self.chain.read().await;
                                if let Err(e) = ctx.store.put_block_proof(height, &block_proof_bytes) {
                                    tracing::warn!(height, err = %e, "failed to store block proof bytes");
                                } else {
                                    tracing::debug!(height, bytes = block_proof_bytes.len(), "block proof stored");
                                }
                                if let Err(e) = ctx
                                    .store
                                    .put_block_auth_sidecar(height, &block_auth_sidecar_bytes)
                                {
                                    tracing::warn!(height, err = %e, "failed to store block auth sidecar bytes");
                                } else {
                                    tracing::debug!(height, bytes = block_auth_sidecar_bytes.len(), "block auth sidecar stored");
                                }
                            }

                            // Now safe to announce — block and proof are in MDBX.
                            let _ = self.events.send(MinerEvent::BlockFound {
                                height,
                                hash,
                                n_txs,
                                pow_nonce: sol.nonce,
                                block_bytes: block_bytes.clone(),
                                block_proof_bytes: block_proof_bytes.clone(),
                                block_auth_sidecar_bytes: block_auth_sidecar_bytes.clone(),
                            });
                        }
                        (Ok(Some(_sol)), Ok((Err(e), prove_elapsed))) => {
                            // PoW succeeded but proof failed — abandon block.
                            tracing::error!(prove_ms = prove_elapsed.as_millis(), "prove_block failed at height {height}: {e}");
                            let _ = self.events.send(MinerEvent::ProveFailed {
                                height,
                                error: e,
                            });
                        }
                        (Ok(None), _) => {
                            // PoW cancelled.
                            let _ = self.events.send(MinerEvent::MiningCancelled {
                                reason: "cancelled".into(),
                            });
                        }
                        (Err(e), _) | (_, Err(e)) => {
                            tracing::error!("task panicked: {:?}", e);
                        }
                    }
                }

                _ = heartbeat.tick(), if tmpl.n_user_txs() == 0 => {
                    cancel.store(true, Ordering::Relaxed);
                    tracing::debug!("heartbeat: refreshing coinbase-only template (safety net)");
                }

                event = mempool_events.recv(), if tmpl.n_user_txs() == 0 => {
                    if let Ok(noid_mempool::MempoolEvent::TxAdmitted { .. }) = event {
                        // Coinbase-only template: the proof is a zero-cost marker. Cancel
                        // PoW immediately so the first admitted user transaction is not
                        // delayed by an empty block. If the marker task has not set
                        // prove_done yet, dropping its JoinHandle is still harmless: the
                        // spawn_blocking task finishes quickly and releases the semaphore.
                        let marker_done = prove_done.load(Ordering::Acquire);
                        cancel.store(true, Ordering::Relaxed);
                        tracing::debug!(marker_done, "coinbase-only template: new tx admitted, cancelling PoW for immediate inclusion");
                    }
                }

                _ = self.sync_ready.notified() => {
                    // A new chain tip is available (P2P block applied or snapshot synced).
                    // Cancel current PoW so the next iteration mines on the correct tip.
                    cancel.store(true, Ordering::Relaxed);
                    tracing::debug!("sync_ready: new chain tip, cancelling PoW to rebuild");
                }
            }
        }
    }

    /// Apply a found block to the chain and update the mempool.
    ///
    /// # Lock strategy
    ///
    /// Write lock is held for MDBX commit + wallet hook + ChainView clone.
    /// Building ChainView inside the write lock adds zero contention (the lock
    /// is already exclusive) and eliminates a separate ~50ms read lock.
    async fn apply_found_block(
        &self,
        block: &Block,
        block_proof_bytes: &[u8],
        block_auth_sidecar_bytes: &[u8],
    ) -> anyhow::Result<()> {
        use noid_mempool::ChainView;

        let local_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // --- MDBX commit + ChainView build off the async executor ---
        //
        // SyncMode::Durable means commit_block issues fsync before returning —
        // a blocking syscall.  spawn_blocking keeps it off the tokio worker.
        // The wallet hook fires inside the closure while the write lock is
        // still held, preserving the original "hook before mempool" ordering.
        // ChainView is built inside the write lock (no added contention since
        // the lock is already exclusive).
        let new_view = {
            let chain_clone = self.chain.clone();
            let block_owned = block.clone();
            let proof_bytes = block_proof_bytes.to_vec();
            let auth_sidecar_bytes = block_auth_sidecar_bytes.to_vec();
            let hook = self.on_block_applied.clone();
            tokio::task::spawn_blocking(move || {
                let mut ctx = chain_clone.blocking_write();
                ctx.apply_next_block(
                    &block_owned,
                    &proof_bytes,
                    &auth_sidecar_bytes,
                    local_time,
                    |block,
                     proof_bytes,
                     auth_sidecar_bytes,
                     parent,
                     prev_timestamps,
                     prev_active_counts,
                     local_time,
                     anchor,
                     nullifiers,
                     pre_state,
                     state| {
                        noid_block::validate_block_from_network(
                            block,
                            proof_bytes,
                            auth_sidecar_bytes,
                            parent,
                            prev_timestamps,
                            prev_active_counts,
                            local_time,
                            anchor,
                            nullifiers,
                            pre_state,
                            state,
                        )
                    },
                )?;
                if let Some(h) = &hook {
                    h(&block_owned);
                }
                let view = ChainView::from_mdbx(&ctx);
                Ok::<ChainView, noid_chain::storage::MdbxContextError>(view)
            })
            .await
            .expect("apply_next_block panicked in spawn_blocking")
            .map_err(anyhow::Error::from)?
        };

        // --- Update mempool (no chain lock held) ---
        let confirmed: Vec<_> = block
            .transactions
            .iter()
            .map(|tx| tx.tx_body_hash)
            .collect();
        self.mempool
            .on_new_block(&confirmed, block.header.height, new_view)
            .await;

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// BlockProof generation (CPU-bound, called inside spawn_blocking)
// ---------------------------------------------------------------------------

/// Run `prove_block` with the witnesses from the template's transactions.
///
/// Returns `(proof_transcript_hash, witness_root, proof_bytes, auth_sidecar_bytes)` on success.
///
/// # Correctness
///
/// This uses the `WalletAuthorizationBundle` stored in each `MempoolEntry.cached_authorization`
/// (when pre-proving cache is populated). When no bundles exist, the
/// decoded from `authorization_bytes` at block assembly time.
///
/// # State correctness
///
/// Production block validity is proof-native: every user-transaction block must
/// include NativeDelta state openings proving the header state-root transition.
/// The live node/miner verify the full block proof and then commit the proven
/// delta via the single `apply_next_block` path.
pub(crate) fn run_prove_block(
    tmpl: &crate::template::BlockTemplate,
    prev_state_root: [u8; 32],
) -> Result<([u8; 32], [u8; 32], Vec<u8>, Vec<u8>), String> {
    use noid_block::{
        assemble_sweep_bucket_proof, block_auth_sidecar_root, block_recursive_claim_hash,
        build_block_auth_sidecar, build_block_witnesses, build_state_bindings_from_binding,
        prove_block_with_total_tx_count, prove_state_mle_openings_only, BlockProof,
        BlockPublicMeta, OwnedTxWitness, TxBlockWitness,
    };
    use noid_gkr::WalletAuthorizationBundle;

    // Coinbase-only: marker proof, no full BlockProof generation needed.
    let non_cb_count = tmpl.n_user_txs();
    if non_cb_count == 0 {
        tracing::debug!(
            height = tmpl.inner.height,
            "coinbase-only block — marker proof OK"
        );
        return Ok(([1u8; 32], [1u8; 32], vec![], vec![]));
    }

    let all_txs = tmpl.inner.all_txs();
    let mut bundles: Vec<WalletAuthorizationBundle> = Vec::with_capacity(non_cb_count);
    for (idx, opt) in tmpl.authorization_bytes.iter().enumerate() {
        let bytes = opt.as_ref().ok_or_else(|| {
            format!(
                "missing WalletAuthorizationBundle for non-coinbase tx index {idx} — will retry coinbase-only"
            )
        })?;
        let expected_shape = tmpl.inner.txs[idx].body.shape;
        let bundle = WalletAuthorizationBundle::from_bytes_for_shape(bytes, expected_shape)
            .map_err(|e| {
                format!("WalletAuthorizationBundle decode failed at tx index {idx}: {e}")
            })?;
        bundles.push(bundle);
    }
    if bundles.len() != non_cb_count {
        return Err(format!(
            "authorization bundle count mismatch: have {}, need {}",
            bundles.len(),
            non_cb_count,
        ));
    }
    for (tx, bundle) in all_txs
        .iter()
        .filter(|tx| !tx.body.is_coinbase)
        .zip(&bundles)
    {
        if bundle.shape() != tx.body.shape {
            return Err(format!(
                "WalletAuthorizationBundle shape {:?} does not match tx body shape {:?} for {:?}",
                bundle.shape(),
                tx.body.shape,
                tx.tx_body_hash
            ));
        }
    }

    let log_slots = tmpl.inner.log_slots;
    let owned_witnesses = build_block_witnesses(&all_txs, &bundles, log_slots);
    let mut standard_owned = Vec::new();
    let mut sweep_owned = Vec::new();
    for witness in owned_witnesses {
        match witness {
            OwnedTxWitness::Standard4x8(w) => standard_owned.push(w),
            OwnedTxWitness::Sweep25x2(w) => sweep_owned.push(w),
        }
    }

    let witnesses: Vec<TxBlockWitness<'_>> = standard_owned
        .iter()
        .map(|w| TxBlockWitness {
            block_tx_index: w.block_tx_index,
            air: &w.air as &dyn noid_air::Air,
            trace: &w.trace,
            pi: &w.pi,
            spine_inputs: &w.spine_inputs,
            auth_public: &w.auth_public,
            auth_proof: &w.auth_proof,
        })
        .collect();

    let auth_sidecar = build_block_auth_sidecar(&witnesses, &sweep_owned)
        .map_err(|e| format!("build_block_auth_sidecar failed: {e:?}"))?;
    let auth_sidecar_bytes = bincode::serialize(&auth_sidecar)
        .map_err(|e| format!("BlockAuthSidecar serialize failed: {e}"))?;

    let n_tx = tmpl.n_user_txs() as u32;
    let new_state_root = tmpl.inner.state_root;

    let sweep_bucket = assemble_sweep_bucket_proof(prev_state_root, &sweep_owned)
        .map_err(|e| format!("assemble_sweep_bucket_proof failed: {e:?}"))?;

    let user_bodies: Vec<_> = tmpl.inner.txs.iter().map(|tx| tx.body.clone()).collect();
    let binding = tmpl.inner.state_binding.as_ref().ok_or_else(|| {
        "user-transaction template is missing BlockStateBinding; proof-native block production requires state binding".to_string()
    })?;
    if binding.prev_state_root != prev_state_root || binding.new_state_root != new_state_root {
        return Err("BlockStateBinding roots do not match template/header roots".to_string());
    }
    let owned_state_bindings = build_state_bindings_from_binding(
        binding,
        &user_bodies,
        Some(&tmpl.inner.coinbase.body),
        &tmpl.pre_segs,
        prev_state_root,
        n_tx,
        log_slots,
    );
    let state_bindings: Vec<_> = owned_state_bindings
        .iter()
        .map(|b| b.as_witness())
        .collect();

    let prove_result = if witnesses.is_empty() {
        let Some(bucket) = sweep_bucket else {
            return Err("user-transaction block has no provable bucket".to_string());
        };
        let (pre_state_openings, post_state_openings) =
            prove_state_mle_openings_only(&state_bindings);
        Ok(BlockProof {
            meta: BlockPublicMeta {
                prev_block_state_root: prev_state_root,
                new_state_root,
                n_tx,
                n_air_per_tx: bucket.meta.n_air_per_tx,
                n_auth_slices_per_tx: bucket.meta.n_boundary_slices_per_tx,
                log_rows: bucket.meta.log_rows,
                n_block_spine_slices: bucket.meta.n_block_spine_slices,
                n_state_bindings: state_bindings.len() as u32,
            },
            standard_bucket: None,
            sweep_bucket: Some(bucket),
            pre_state_openings,
            post_state_openings,
        })
    } else {
        let mut proof = prove_block_with_total_tx_count(
            prev_state_root,
            new_state_root,
            &witnesses,
            &state_bindings,
            n_tx,
        )
        .map_err(|e| format!("{e:?}"))?;
        proof.sweep_bucket = sweep_bucket;
        Ok(proof)
    };

    match prove_result {
        Ok(block_proof) => {
            let proof_bytes = bincode::serialize(&block_proof).unwrap_or_default();
            let transcript_hash = block_recursive_claim_hash(&block_proof);
            let root_block = tmpl.seal(0, transcript_hash, [0u8; 32]);
            let witness_root = block_auth_sidecar_root(&root_block, &auth_sidecar)
                .map_err(|e| format!("BlockAuthSidecar root failed: {e:?}"))?;

            tracing::info!(
                proof_bytes = proof_bytes.len(),
                auth_sidecar_bytes = auth_sidecar_bytes.len(),
                "prove_block succeeded"
            );
            Ok((
                transcript_hash,
                witness_root,
                proof_bytes,
                auth_sidecar_bytes,
            ))
        }
        Err(noid_block::ProveBlockError::AuthProofInvalid(k)) => {
            // Auth proof mismatch: wallet proved with a different epoch_anchor or
            // log_slots. We CANNOT produce a stub proof for user-tx blocks (consensus
            // rejects [1u8;32] when user txs are present). Return an error so the
            // miner discards this template and rebuilds coinbase-only.
            Err(format!(
                "AuthProofInvalid at tx_index={k}: epoch_anchor or log_slots mismatch — \
                 discarding template, will rebuild coinbase-only"
            ))
        }
        Err(e) => Err(format!("{e:?}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use bench_prover::{
        prove_standard_wallet, prove_sweep_wallet, standard_bundle, standard_fixture,
        standard_scenario, sweep_bundle, sweep_fixture, sweep_scenario, BENCH_LOG_SLOTS,
    };
    use noid_block::{
        validate_block_bucket_tx_indices, validate_block_proof_transcript_hash, BlockProof,
    };
    use noid_chain::block::{compute_tx_root, Block};
    use noid_chain::consensus::genesis::{genesis_header, GENESIS_TIMESTAMP};
    use noid_chain::consensus::params::{BLOCK_TIME, GENESIS_TARGET};
    use noid_chain::consensus::pow::full_block_hash;
    use noid_chain::consensus::template::BlockTemplate as ChainTemplate;
    use noid_chain::fri_state::SlotValue;
    use noid_chain::segmented_state::SegmentColumns;
    use noid_chain::state::{apply_tx, ChainState};
    use noid_chain::state_binding::BlockStateBinding;
    use noid_gkr::WalletAuthorizationBundle;
    use noid_poseidon2b::primitives::Address;
    use noid_tx::{
        compute_claims_commitment, hash_tx_body_for_shape, Transaction, TxBody, TxOutput, TxShape,
    };
    use std::collections::HashMap;

    fn tx_from_body(body: TxBody) -> Transaction {
        let tx_body_hash = hash_tx_body_for_shape(
            body.shape,
            &body.epoch_anchor,
            body.fee,
            &body.inputs,
            &body.outputs,
            body.is_coinbase,
        );
        Transaction { body, tx_body_hash }
    }

    fn coinbase_tx() -> Transaction {
        tx_from_body(TxBody::standard(
            [0u8; 32],
            0,
            vec![],
            vec![TxOutput {
                slot_index: 42,
                value: 1_000_000,
                owner: Address([0xCB; 32]),
                valid: true,
            }],
            true,
        ))
    }

    fn standard_fixture_with_bundle(
        label: &'static str,
        slot_base: u32,
        seed: u128,
    ) -> (TxBody, WalletAuthorizationBundle) {
        let fixture = standard_fixture(standard_scenario(label, 1, 2, slot_base, seed));
        let proof = prove_standard_wallet(&fixture, 1).proof;
        let body = fixture.scenario.body.clone();
        (body, standard_bundle(&fixture, proof))
    }

    fn sweep_fixture_with_bundle(
        label: &'static str,
        n_inputs: usize,
        slot_base: u32,
        seed: u128,
    ) -> (TxBody, WalletAuthorizationBundle) {
        let fixture = sweep_fixture(sweep_scenario(label, n_inputs, slot_base, seed));
        let proof = prove_sweep_wallet(&fixture, 1).proof;
        let body = fixture.scenario.body.clone();
        (body, sweep_bundle(&fixture, proof))
    }

    fn seed_pre_state(user_bodies: &[TxBody]) -> ChainState {
        let mut state = ChainState::with_log_slots(BENCH_LOG_SLOTS as usize);
        for input in user_bodies
            .iter()
            .flat_map(|body| body.inputs.iter().filter(|i| i.valid))
        {
            let [owner_hi, owner_lo] = input.owner.as_fields();
            state
                .state
                .set_slot(
                    input.slot_index,
                    SlotValue {
                        value: (input.value as u128).into(),
                        owner_hi,
                        owner_lo,
                    },
                )
                .expect("test input slot in range");
            state.active_slot_count += 1;
            state.alloc_counter += 1;
        }
        state
    }

    fn pre_segments_for_template(
        state: &ChainState,
        user_bodies: &[TxBody],
        coinbase_body: &TxBody,
    ) -> HashMap<u16, SegmentColumns> {
        let eff_log = state.state.effective_log_segment_size();
        let seg_size = 1usize << eff_log;
        let mut pre_segs = HashMap::new();
        for slot in user_bodies
            .iter()
            .chain(std::iter::once(coinbase_body))
            .flat_map(|body| {
                body.inputs
                    .iter()
                    .filter(|i| i.valid)
                    .map(|i| i.slot_index)
                    .chain(
                        body.outputs
                            .iter()
                            .filter(|o| o.valid)
                            .map(|o| o.slot_index),
                    )
            })
        {
            let seg_id = (slot >> eff_log) as u16;
            pre_segs.entry(seg_id).or_insert_with(|| {
                state
                    .state
                    .try_get_segment_columns(seg_id)
                    .cloned()
                    .unwrap_or_else(|| SegmentColumns::new_zero(seg_size))
            });
        }
        pre_segs
    }

    fn patch_binding_with_coinbase(
        binding: &mut BlockStateBinding,
        pre_state: &noid_chain::segmented_state::SegmentedFriState,
        mut post_user_state: noid_chain::segmented_state::SegmentedFriState,
        user_bodies: &[TxBody],
        coinbase_body: &TxBody,
    ) {
        for out in coinbase_body.outputs.iter().filter(|o| o.valid) {
            let [owner_hi, owner_lo] = out.owner.as_fields();
            post_user_state
                .set_slot(
                    out.slot_index,
                    SlotValue {
                        value: (out.value as u128).into(),
                        owner_hi,
                        owner_lo,
                    },
                )
                .expect("test coinbase slot in range");
        }

        binding.new_state_root = post_user_state.root();
        binding.tree_depth = post_user_state.tree_depth();
        if binding.tree_depth == 0 {
            return;
        }

        let eff_log = pre_state.effective_log_segment_size();
        let mut touched = std::collections::HashSet::new();
        for body in user_bodies {
            for input in body.inputs.iter().filter(|i| i.valid) {
                touched.insert((input.slot_index >> eff_log) as u16);
            }
            for output in body.outputs.iter().filter(|o| o.valid) {
                touched.insert((output.slot_index >> eff_log) as u16);
            }
        }
        for output in coinbase_body.outputs.iter().filter(|o| o.valid) {
            touched.insert((output.slot_index >> eff_log) as u16);
        }

        for seg_id in touched {
            binding
                .pre_seg_siblings
                .insert(seg_id, pre_state.merkle_siblings(seg_id));
            binding
                .post_seg_siblings
                .insert(seg_id, post_user_state.merkle_siblings(seg_id));
        }
    }

    fn miner_template(
        user: Vec<(TxBody, WalletAuthorizationBundle)>,
    ) -> crate::template::BlockTemplate {
        let coinbase = coinbase_tx();
        let user_bodies: Vec<TxBody> = user.iter().map(|(body, _)| body.clone()).collect();
        let mut pre_state = seed_pre_state(&user_bodies);
        let prev_state_root = pre_state.state_root();
        let mut parent = genesis_header();
        parent.state_root = prev_state_root;
        parent.log_slots = BENCH_LOG_SLOTS;
        parent.active_slot_count = pre_state.active_slot_count;
        parent.alloc_counter = pre_state.alloc_counter;

        let commitments: Vec<_> = user_bodies
            .iter()
            .map(|body| compute_claims_commitment(&body.inputs, &body.outputs))
            .collect();
        let mut binding_state = pre_state.state.clone();
        let mut state_binding =
            BlockStateBinding::build(&mut binding_state, &user_bodies, &commitments)
                .expect("build test BlockStateBinding");
        patch_binding_with_coinbase(
            &mut state_binding,
            &pre_state.state,
            binding_state,
            &user_bodies,
            &coinbase.body,
        );
        let state_root = state_binding.new_state_root;
        let pre_segs = pre_segments_for_template(&pre_state, &user_bodies, &coinbase.body);

        let mut post_state = pre_state.clone();
        for body in &user_bodies {
            apply_tx(&mut post_state, body).expect("test user tx applies");
        }
        apply_tx(&mut post_state, &coinbase.body).expect("test coinbase applies");
        assert_eq!(post_state.state_root(), state_root);

        let txs: Vec<Transaction> = user_bodies.into_iter().map(tx_from_body).collect();
        let authorization_bytes = user
            .into_iter()
            .map(|(_, bundle)| Some(bundle.to_bytes().expect("serialize authorization")))
            .collect();
        let all_txs: Vec<Transaction> = std::iter::once(coinbase.clone())
            .chain(txs.iter().cloned())
            .collect();
        let tx_root = compute_tx_root(&all_txs);
        let inner = ChainTemplate {
            coinbase,
            txs,
            state_root,
            tx_root,
            active_slot_count: post_state.active_slot_count,
            alloc_counter: post_state.alloc_counter,
            log_slots: BENCH_LOG_SLOTS,
            height: parent.height + 1,
            timestamp: GENESIS_TIMESTAMP + BLOCK_TIME,
            miner_address: Address([0xCB; 32]),
            difficulty_target: GENESIS_TARGET,
            prev_block_hash: full_block_hash(&parent),
            state_binding: Some(state_binding),
        };
        crate::template::BlockTemplate {
            inner,
            difficulty_target: GENESIS_TARGET,
            miner_address: Address([0xCB; 32]),
            timestamp: GENESIS_TIMESTAMP + BLOCK_TIME,
            parent,
            authorization_bytes,
            pre_segs,
        }
    }

    fn prove_template(tmpl: &crate::template::BlockTemplate) -> (Block, BlockProof) {
        let (proof_hash, witness_root, proof_bytes, auth_sidecar_bytes) =
            run_prove_block(tmpl, tmpl.parent.state_root).expect("run_prove_block");
        assert!(
            !proof_bytes.is_empty(),
            "user-tx templates must carry BlockProof bytes"
        );
        let block = tmpl.seal(0, proof_hash, witness_root);
        assert!(
            !auth_sidecar_bytes.is_empty(),
            "user-tx templates must carry BlockAuthSidecar bytes"
        );
        let proof: BlockProof = bincode::deserialize(&proof_bytes).expect("decode BlockProof");
        let sidecar: noid_block::BlockAuthSidecar =
            bincode::deserialize(&auth_sidecar_bytes).expect("decode BlockAuthSidecar");
        noid_block::validate_block_auth_sidecar_root(&block, &sidecar).expect("sidecar root");
        validate_block_bucket_tx_indices(&block, &proof).expect("bucket coverage");
        validate_block_proof_transcript_hash(&block, &proof).expect("header/proof binding");
        (block, proof)
    }

    fn assert_shape_counts(proof: &BlockProof, standard: usize, sweep: usize) {
        assert_eq!(
            proof
                .standard_bucket
                .as_ref()
                .map_or(0, |b| b.meta.tx_indices.len()),
            standard
        );
        assert_eq!(
            proof
                .sweep_bucket
                .as_ref()
                .map_or(0, |b| b.meta.tx_indices.len()),
            sweep
        );
        assert_eq!(proof.meta.n_tx as usize, standard + sweep);
    }

    #[test]
    #[cfg_attr(debug_assertions, ignore = "release-only miner proof regression")]
    fn run_prove_block_serializes_standard_only_template() {
        let standard = standard_fixture_with_bundle("std-only", 100, 0xA1);
        let tmpl = miner_template(vec![standard]);
        let (_block, proof) = prove_template(&tmpl);
        assert_shape_counts(&proof, 1, 0);
    }

    #[test]
    #[cfg_attr(debug_assertions, ignore = "release-only miner proof regression")]
    fn run_prove_block_serializes_sweep_only_template() {
        let sweep = sweep_fixture_with_bundle("sweep-only", 5, 1_000, 0xB1);
        let tmpl = miner_template(vec![sweep]);
        let (_block, proof) = prove_template(&tmpl);
        assert_shape_counts(&proof, 0, 1);
    }

    #[test]
    #[cfg_attr(debug_assertions, ignore = "release-only miner proof regression")]
    fn run_prove_block_serializes_mixed_template() {
        let standard = standard_fixture_with_bundle("mixed-std", 100, 0xC1);
        let sweep = sweep_fixture_with_bundle("mixed-sweep", 5, 1_000, 0xD1);
        let tmpl = miner_template(vec![standard, sweep]);
        let (_block, proof) = prove_template(&tmpl);
        assert_shape_counts(&proof, 1, 1);
        assert_eq!(
            proof.standard_bucket.as_ref().unwrap().meta.tx_indices,
            vec![1]
        );
        assert_eq!(
            proof.sweep_bucket.as_ref().unwrap().meta.tx_indices,
            vec![2]
        );
    }

    #[test]
    #[cfg_attr(debug_assertions, ignore = "release-only miner proof regression")]
    fn run_prove_block_serializes_split_sweep_plus_standard_tail_template() {
        let sweep = sweep_fixture_with_bundle(
            "split-sweep-25x2",
            TxShape::Sweep25x2.max_inputs(),
            1_000,
            0xE1,
        );
        let standard_tail = standard_fixture_with_bundle("split-standard-tail", 5_000, 0xF1);
        let tmpl = miner_template(vec![sweep, standard_tail]);
        let (_block, proof) = prove_template(&tmpl);
        assert_shape_counts(&proof, 1, 1);
        assert_eq!(
            proof.sweep_bucket.as_ref().unwrap().meta.tx_indices,
            vec![1]
        );
        assert_eq!(
            proof.standard_bucket.as_ref().unwrap().meta.tx_indices,
            vec![2]
        );
    }

    #[test]
    #[cfg_attr(debug_assertions, ignore = "release-only miner proof regression")]
    fn mismatched_bucket_proof_is_rejected_before_submit_verification() {
        let standard = standard_fixture_with_bundle("bad-std", 100, 0xA11);
        let sweep = sweep_fixture_with_bundle("bad-sweep", 5, 1_000, 0xB11);
        let tmpl = miner_template(vec![standard, sweep]);
        let (block, mut proof) = prove_template(&tmpl);

        proof.sweep_bucket.as_mut().unwrap().meta.tx_indices = vec![1];
        assert!(
            validate_block_bucket_tx_indices(&block, &proof).is_err(),
            "submit-side bucket coverage validation must reject cross-shape proof indices"
        );
    }
}
