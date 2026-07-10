// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! `BlockMiner` — the parallel PoW + block-certificate generation orchestrator.
//!
//! ## Parallel block production design
//!
//! ```text
//! loop {
//!   template = build_template(mempool, ctx)
//!
//!   ┌─────────────────────────┐   ┌─────────────────────────────────┐
//!   │  PoW Search             │   │  Block certificate assembly    │
//!   │  Poseidon2b POW nonce   │   │  build proof + sidecar          │
//!   │  < difficulty_target    │   │  exact state + auth sidecar     │
//!   └──────────┬──────────────┘   └──────────────┬──────────────────┘
//!              │                                 │
//!              └────────────┬────────────────────┘
//!                           │ both complete
//!                           ▼
//!   seal(nonce, detached proof/object ids) → Block
//!   apply_to_chain + broadcast via P2P
//! }
//! ```
//!
//! Internal miner uses separate Rayon pools for PoW and proving.  With default
//! settings it splits available cores roughly in half and adapts the transaction
//! cap to recent proof throughput instead of always trying to fill 256 txs.
//! External miner mode disables internal PoW, so the node can spend its CPUs on
//! template building, certificate assembly, validation, RPC, and P2P while miners run elsewhere.
//!
//! Template refresh triggers (see run loop):
//!   1. Heartbeat every `refresh_interval_secs` seconds (safety net)
//!   2. First `TxAdmitted` while a coinbase-only no-proof block is being mined
//!   3. New chain tip from P2P (block received or snapshot applied)

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::{Duration, Instant};

use tokio::sync::{broadcast, RwLock};
use tokio::time::interval;

use noid_chain::block::Block;
use noid_chain::consensus::pow::block_id;
use noid_chain::storage::MdbxChainContext;
use noid_mempool::AsyncMempool;
use noid_poseidon2b::primitives::Address;

use crate::template::{TemplateBuilder, TemplateChainSnapshot, TemplateRefreshTrigger};

fn history_claim_fields_bytes(
    block: &Block,
    parent: &noid_chain::BlockHeader,
    artifacts: &noid_block::AcceptedBlockValidationArtifacts,
) -> Result<Vec<u8>, noid_block::FullValidationError> {
    let claim =
        noid_block::AcceptedStateTransitionClaim::from_accepted_block(block, parent, artifacts)
            .map_err(noid_block::FullValidationError::from)?;
    Ok(bincode::serialize(&claim.fields().to_vec()).expect("history claim fields serialize"))
}

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

/// Events emitted by the miner for P2P broadcast, logging, RPC, and local
/// finalized-history coverage.
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
        /// Empty for coinbase-only blocks.
        block_proof_bytes: Vec<u8>,
        /// Serialized public AuthGKR sidecar bytes carried as detached witness.
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
    /// Block certificate assembly failed (non-fatal: block is abandoned, new template built).
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

    // Keep certificate work comfortably under the 15s consensus target. PoW
    // runs in parallel, but a user-tx block still needs proof bytes before it
    // can be sealed and propagated.
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
    /// Semaphore (1 permit) preventing concurrent certificate tasks from accumulating.
    /// Each heartbeat/mempool refresh drops the JoinHandle but NOT the blocking task;
    /// without this guard repeated refreshes can pile up blocking proof work.
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

            // Track when prove completes. Coinbase-only blocks have no proof; on the
            // first admitted tx we cancel their PoW search and rebuild immediately. For
            // user-tx templates we intentionally do not listen to later mempool events:
            // dropping the JoinHandle would not cancel spawn_blocking proof work and would
            // wastefully rebuild the same block proof in the next loop.
            let prove_done = Arc::new(AtomicBool::new(false));
            let prove_done_clone = prove_done.clone();

            // --- Parallel: PoW + certificate assembly ---
            // Extract only the PoW header so PoW never depends on detached
            // proof/sidecar witness bytes.
            let pow_header = tmpl.header_for_pow(0);
            let tmpl = Arc::new(tmpl);
            let tmpl_prove = tmpl.clone();
            let cancel_pow = cancel.clone();
            let pow_pool = self.pow_pool.clone();
            let prove_pool = self.prove_pool.clone();

            // Try to acquire the single-permit prove semaphore.
            // spawn_blocking tasks are NOT cancelled when JoinHandles are dropped;
            // without this guard repeated refreshes can accumulate blocking
            // proof work and saturate CPU cores.
            let prove_permit = self.prove_semaphore.clone().try_acquire_owned();

            // If the semaphore is already held and the template has user txs we
            // cannot legally seal without a block proof — skip this iteration and wait for
            // the running prove to release the permit.
            if prove_permit.is_err() && tmpl.n_user_txs() > 0 {
                tracing::debug!(
                    height,
                    "prove task busy and block has user txs — skipping this template iteration"
                );
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
            }

            // PoW: Poseidon2b over semantic header fields, CPU-bound via the dedicated PoW Rayon pool.
            let pow_handle = tokio::task::spawn_blocking(move || {
                pow_pool.install(|| crate::pow::search_pow_parallel(&pow_header, &cancel_pow))
            });

            // Certificate assembly: run for real (permit held until done) or return
            // empty detached witness bytes for coinbase-only blocks when the prove slot is occupied.
            let prove_handle = match prove_permit {
                Ok(permit) => tokio::task::spawn_blocking(move || {
                    // Run prove inside a scope so the semaphore permit is released
                    // BEFORE we set prove_done. This guarantees: when the miner loop
                    // sees prove_done=true, the semaphore is already free for the next
                    // template rebuild.
                    let started = Instant::now();
                    let result = {
                        let _permit = permit;
                        prove_pool.install(|| run_prove_block(&tmpl_prove, prev_state_root))
                    };
                    let elapsed = started.elapsed();
                    prove_done_clone.store(true, Ordering::Release);
                    (result, elapsed)
                }),
                Err(_) => {
                    // Semaphore busy, but coinbase-only block — no proof is required.
                    tracing::debug!(
                        height,
                        "prove task busy, coinbase-only block will carry no proof"
                    );
                    tokio::task::spawn_blocking(move || {
                        // Empty detached witness is instant; mark prove_done so TxAdmitted can trigger rebuild.
                        prove_done_clone.store(true, Ordering::Release);
                        (Ok((vec![], vec![])), Duration::ZERO)
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
                        (Ok(Some(sol)), Ok((Ok((block_proof_bytes, block_auth_sidecar_bytes)), prove_elapsed))) => {
                            let block = tmpl.seal(sol.nonce);
                            let block_bytes = block.to_bytes();
                            let hash = block_id(&block.header);
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

                            // Store block proof + public auth sidecar bytes for local
                            // finalized-history coverage and compact P2P pull requests.
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
                        // Coinbase-only templates have no validation witness. Cancel PoW
                        // immediately so the first admitted user transaction is not
                        // delayed by an empty block. If the empty proof task has not set
                        // prove_done yet, dropping its JoinHandle is still harmless.
                        let empty_proof_done = prove_done.load(Ordering::Acquire);
                        cancel.store(true, Ordering::Relaxed);
                        tracing::debug!(empty_proof_done, "coinbase-only template: new tx admitted, cancelling PoW for immediate inclusion");
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
                let mut history_claim_bytes = None;
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
                     pre_state,
                     state| {
                        let output = noid_block::accept_block_with_artifacts(
                            block,
                            proof_bytes,
                            auth_sidecar_bytes,
                            parent,
                            prev_timestamps,
                            prev_active_counts,
                            local_time,
                            anchor,
                            pre_state,
                            state,
                        )?;
                        history_claim_bytes = Some(history_claim_fields_bytes(
                            block,
                            parent,
                            &output.artifacts,
                        )?);
                        Ok::<[u8; 32], noid_block::FullValidationError>(output.state_root)
                    },
                )?;
                if let Some(bytes) = &history_claim_bytes {
                    if let Err(e) = ctx
                        .store
                        .put_history_claim(block_owned.header.height, bytes)
                    {
                        tracing::warn!(
                            height = block_owned.header.height,
                            err = %e,
                            "failed to store mined history claim fields"
                        );
                    }
                }
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
// Block certificate assembly (CPU-bound, called inside spawn_blocking)
// ---------------------------------------------------------------------------

/// Run `prove_block` with the witnesses from the template's transactions.
///
/// Returns `(proof_bytes, auth_sidecar_bytes)` on success.
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
/// include an exact authenticated state transition proof for the header
/// state-root transition. The live node/miner verify the minimal block proof
/// and then commit the proven transition via the single `apply_next_block` path.
pub(crate) fn run_prove_block(
    tmpl: &crate::template::BlockTemplate,
    prev_state_root: [u8; 32],
) -> Result<crate::ProvedBlockParts, String> {
    use noid_block::{BlockAuthSidecar, BlockProof};
    use noid_gkr::{verify_wallet_authorization, WalletAuthorizationBundle};

    // Coinbase-only: no block certificate needed.
    let non_cb_count = tmpl.n_user_txs();
    if non_cb_count == 0 {
        tracing::debug!(
            height = tmpl.inner.height,
            "coinbase-only block — no block proof required"
        );
        return Ok((vec![], vec![]));
    }

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
        verify_wallet_authorization(&tmpl.inner.txs[idx].body, &bundle).map_err(|e| {
            format!("WalletAuthorizationBundle verify failed at tx index {idx}: {e}")
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

    let auth_sidecar = BlockAuthSidecar {
        tx_auth: bundles.into_iter().map(|bundle| bundle.proof).collect(),
    };
    let auth_sidecar_bytes = bincode::serialize(&auth_sidecar)
        .map_err(|e| format!("BlockAuthSidecar serialize failed: {e}"))?;

    let n_tx = tmpl.n_user_txs() as u32;
    let new_state_root = tmpl.inner.state_root;
    let exact_state_transition = tmpl.exact_state_transition.clone().ok_or_else(|| {
        "user-transaction template is missing ExactStateTransitionProof".to_string()
    })?;
    let block_proof = BlockProof::minimal(
        prev_state_root,
        new_state_root,
        n_tx,
        exact_state_transition,
    );
    let proof_bytes = bincode::serialize(&block_proof).unwrap_or_default();
    tracing::info!(
        proof_bytes = proof_bytes.len(),
        auth_sidecar_bytes = auth_sidecar_bytes.len(),
        "prove_block succeeded"
    );
    Ok((proof_bytes, auth_sidecar_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    use bench_prover::{
        prove_standard_wallet, prove_sweep_wallet, standard_bundle, standard_fixture,
        standard_scenario, sweep_bundle, sweep_fixture, sweep_scenario, BENCH_LOG_SLOTS,
    };
    use noid_block::BlockProof;
    use noid_chain::block::{compute_tx_root, Block};
    use noid_chain::consensus::genesis::{genesis_header, GENESIS_TIMESTAMP};
    use noid_chain::consensus::params::{BLOCK_TIME, GENESIS_TARGET};
    use noid_chain::consensus::pow::block_id;
    use noid_chain::consensus::template::BlockTemplate as ChainTemplate;
    use noid_chain::fri_state::SlotValue;
    use noid_chain::state::{apply_tx, ChainState};
    use noid_gkr::WalletAuthorizationBundle;
    use noid_poseidon2b::primitives::Address;
    use noid_tx::{
        compute_claims_commitment, hash_tx_body_for_shape, Transaction, TxBody, TxOutput, TxShape,
    };

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

        let mut post_state = pre_state.clone();
        apply_tx(&mut post_state, &coinbase.body).expect("test coinbase applies");
        for body in &user_bodies {
            apply_tx(&mut post_state, body).expect("test user tx applies");
        }
        let state_root = post_state.state_root();
        let exact_bodies: Vec<_> = std::iter::once(coinbase.body.clone())
            .chain(user_bodies.iter().cloned())
            .collect();
        let exact_commitments: Vec<_> = exact_bodies
            .iter()
            .map(|body| compute_claims_commitment(&body.inputs, &body.outputs))
            .collect();
        let exact_surface = noid_chain::build_exact_action_surface(
            &pre_state.state,
            &exact_bodies,
            &exact_commitments,
            pre_state.alloc_counter,
        )
        .expect("build exact surface");
        let exact_cache = pre_state
            .state
            .exact_sparse_cache()
            .expect("build exact sparse cache");
        let exact_state_transition =
            noid_block::build_exact_state_transition_proof(&exact_cache, &exact_surface)
        .expect("build exact state proof");

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
            prev_block_hash: block_id(&parent),
        };
        crate::template::BlockTemplate {
            inner,
            difficulty_target: GENESIS_TARGET,
            miner_address: Address([0xCB; 32]),
            timestamp: GENESIS_TIMESTAMP + BLOCK_TIME,
            parent,
            authorization_bytes,
            exact_state_transition: Some(exact_state_transition),
        }
    }

    fn prove_template_wire(
        tmpl: &crate::template::BlockTemplate,
    ) -> (Block, Vec<u8>, Vec<u8>, BlockProof) {
        let (proof_bytes, auth_sidecar_bytes) =
            run_prove_block(tmpl, tmpl.parent.state_root).expect("run_prove_block");
        assert!(
            !proof_bytes.is_empty(),
            "user-tx templates must carry BlockProof bytes"
        );
        let block = tmpl.seal(0);
        assert!(
            !auth_sidecar_bytes.is_empty(),
            "user-tx templates must carry BlockAuthSidecar bytes"
        );
        let proof: BlockProof = bincode::deserialize(&proof_bytes).expect("decode BlockProof");
        let sidecar: noid_block::BlockAuthSidecar =
            bincode::deserialize(&auth_sidecar_bytes).expect("decode BlockAuthSidecar");
        assert_eq!(sidecar.tx_auth.len(), tmpl.n_user_txs());
        noid_block::validate_block_auth_sidecar_shape(&block, &sidecar)
            .expect("detached sidecar shape");
        (block, proof_bytes, auth_sidecar_bytes, proof)
    }

    fn prove_template(tmpl: &crate::template::BlockTemplate) -> (Block, BlockProof) {
        let (block, _proof_bytes, _auth_sidecar_bytes, proof) = prove_template_wire(tmpl);
        (block, proof)
    }

    fn assert_minimal_proof(proof: &BlockProof, n_user_txs: usize) {
        assert_eq!(proof.meta.n_tx as usize, n_user_txs);
    }

    #[test]
    #[cfg_attr(debug_assertions, ignore = "release-only miner proof regression")]
    fn run_prove_block_serializes_standard_only_template() {
        let standard = standard_fixture_with_bundle("std-only", 100, 0xA1);
        let tmpl = miner_template(vec![standard]);
        let (_block, proof) = prove_template(&tmpl);
        assert_minimal_proof(&proof, 1);
    }

    #[test]
    #[cfg_attr(debug_assertions, ignore = "release-only miner proof regression")]
    fn run_prove_block_serializes_sweep_only_template() {
        let sweep = sweep_fixture_with_bundle("sweep-only", 5, 1_000, 0xB1);
        let tmpl = miner_template(vec![sweep]);
        let (_block, proof) = prove_template(&tmpl);
        assert_minimal_proof(&proof, 1);
    }

    #[test]
    #[cfg_attr(debug_assertions, ignore = "release-only miner proof regression")]
    fn run_prove_block_serializes_mixed_template() {
        let standard = standard_fixture_with_bundle("mixed-std", 100, 0xC1);
        let sweep = sweep_fixture_with_bundle("mixed-sweep", 5, 1_000, 0xD1);
        let tmpl = miner_template(vec![standard, sweep]);
        let (_block, proof) = prove_template(&tmpl);
        assert_minimal_proof(&proof, 2);
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
        assert_minimal_proof(&proof, 2);
    }

    #[test]
    #[cfg_attr(debug_assertions, ignore = "release-only miner proof regression")]
    fn minimal_proof_serializes_without_bucket_payload() {
        let standard = standard_fixture_with_bundle("bad-std", 100, 0xA11);
        let sweep = sweep_fixture_with_bundle("bad-sweep", 5, 1_000, 0xB11);
        let tmpl = miner_template(vec![standard, sweep]);
        let (_block, proof_bytes, _auth_sidecar_bytes, proof) = prove_template_wire(&tmpl);

        assert_minimal_proof(&proof, 2);
        assert_eq!(
            proof_bytes.len(),
            bincode::serialize(&proof)
                .expect("serialize minimal proof")
                .len()
        );
    }
}
