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

use crate::memory_governor::ProofMemoryGovernor;
use crate::template::{TemplateBuilder, TemplateChainSnapshot, TemplateRefreshTrigger};

#[allow(clippy::too_many_arguments)]
fn accepted_block_validation(
    block: &Block,
    parent: &noid_chain::BlockHeader,
    prev_timestamps: &[u64],
    prev_active_counts: &[u64],
    anchor: &noid_chain::consensus::validation::AnchorInfo,
    block_proof_bytes: &[u8],
    block_auth_sidecar_bytes: &[u8],
    artifacts: &noid_block::AcceptedBlockValidationArtifacts,
    state_root: [u8; 32],
) -> Result<noid_chain::AppliedBlockValidation, noid_block::FullValidationError> {
    let post_validation = noid_block::accepted_block_post_validation_bundle(
        block,
        parent,
        prev_timestamps,
        prev_active_counts,
        anchor,
        block_proof_bytes,
        block_auth_sidecar_bytes,
        artifacts,
    )?;
    let record = noid_block::accepted_block_certificate_record(post_validation.acceptance_receipt)
        .map_err(|error| {
            noid_block::FullValidationError::Consensus(
                noid_chain::consensus::ConsensusError::ShapeMismatch(format!(
                    "accepted-block certificate record build failed: {error}"
                )),
            )
        })?;
    Ok(noid_chain::AppliedBlockValidation::new(
        state_root,
        bincode::serialize(&post_validation.history_claim_fields)
            .expect("history claim fields serialize"),
        bincode::serialize(&record).expect("accepted-block certificate record serializes"),
    ))
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
    /// Maximum resident-memory envelope admitted for block proof workers, MiB.
    ///
    /// `0` selects a host-aware ceiling from currently available memory while
    /// reserving capacity for validation, networking, and the OS. This is a
    /// local scheduler policy and never changes consensus block limits.
    pub proof_memory_budget_mib: usize,
}

impl Default for MinerConfig {
    fn default() -> Self {
        Self {
            miner_address: Address([0u8; 32]),
            mining_threads: 0,
            refresh_interval_secs: 75, // 5 × BLOCK_TIME; real triggers are sync_ready + TxAdmitted
            proof_memory_budget_mib: 0,
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
        /// Versioned selected-ZK authorization sidecar bytes carried as detached witness.
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
/// Resolves the payout address immediately before each template is built.
/// Used by the built-in wallet when no explicit mining address is configured.
pub type MiningPayoutResolver = Arc<dyn Fn() -> Address + Send + Sync>;
/// Optional node-wide ordering gate for canonical chain operations which also
/// replace wallet/mempool views (snapshot install, reorg, mining apply).
pub type ChainOperationGate = Arc<tokio::sync::Mutex<()>>;
fn resolve_mining_payout(configured: Address, resolver: Option<&MiningPayoutResolver>) -> Address {
    resolver.map(|resolve| resolve()).unwrap_or(configured)
}

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
    /// Shared resident-memory admission gate held for the complete lifetime of
    /// each blocking proof job. It rejects work before Tokio can queue it.
    proof_memory_governor: ProofMemoryGovernor,
    /// Optional hook called synchronously after block is applied to chain, before
    /// the mempool is updated. Used by the built-in wallet to generate receipts
    /// race-free (receipt ready before getMempoolSize → 0 is observable).
    on_block_applied: Option<BlockAppliedHook>,
    /// Optional dynamic payout. Explicitly configured miner addresses leave
    /// this unset and continue to use `config.miner_address`.
    payout_resolver: Option<MiningPayoutResolver>,
    /// When installed by the full node, prevents a template capture or found
    /// block apply from entering the interval between snapshot commit and the
    /// corresponding mempool/wallet reload. Library-only miners may leave it
    /// unset when no external state-replacement path exists.
    chain_operation_gate: Option<ChainOperationGate>,
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
        let proof_memory_governor = ProofMemoryGovernor::global(config.proof_memory_budget_mib);
        tracing::info!(
            mining_threads,
            prover_threads,
            proof_memory_budget_mib = proof_memory_governor.configured_budget_mib(),
            "internal miner CPU and memory budgets"
        );
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
            proof_memory_governor,
            on_block_applied: None,
            payout_resolver: None,
            chain_operation_gate: None,
        };
        (miner, rx)
    }

    /// Register a callback to be called synchronously after each block is applied
    /// to the chain, before the mempool is updated. The built-in wallet uses this
    /// to generate payment receipts race-free at any mining speed.
    pub fn set_block_applied_hook(&mut self, hook: BlockAppliedHook) {
        self.on_block_applied = Some(hook);
    }

    /// Resolve the wallet's active address for every future template.
    pub fn set_payout_resolver(&mut self, resolver: MiningPayoutResolver) {
        self.payout_resolver = Some(resolver);
    }

    /// Serialize template capture and canonical apply with node-wide snapshot
    /// and reorg replacement. The gate is held only while shared boundaries
    /// are captured/updated, never while certificate proving or PoW runs.
    pub fn set_chain_operation_gate(&mut self, gate: ChainOperationGate) {
        self.chain_operation_gate = Some(gate);
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
        let cancel = self.cancel_pow.clone();
        let mut heartbeat = interval(Duration::from_secs(self.config.refresh_interval_secs));
        let mut mempool_events = self.mempool.subscribe();
        let mut prove_ms_per_tx_ewma: Option<f64> = None;

        tracing::debug!("BlockMiner started");

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

            // Resolve payout under the same chain guard that captures the
            // template snapshot. Account activation takes `chain -> wallet`
            // too, so the selected owner and parent snapshot form one instant.
            // An already-built template remains immutable.
            let chain_operation = match &self.chain_operation_gate {
                Some(gate) => Some(gate.lock().await),
                None => None,
            };
            let (snapshot_result, addr) = {
                let mut ctx = self.chain.write().await;
                let addr =
                    resolve_mining_payout(self.config.miner_address, self.payout_resolver.as_ref());
                (TemplateChainSnapshot::from_context(&mut ctx), addr)
            };
            drop(chain_operation);
            let snapshot = match snapshot_result {
                Ok(snapshot) => snapshot,
                Err(e) => {
                    tracing::warn!(err = ?e, "template snapshot failed, retrying in 1s");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
            };
            let prev_state_root = snapshot.prev_state_root();
            let memory_user_tx_limit = self.proof_memory_governor.max_user_txs_now();
            let max_user_txs =
                adaptive_user_tx_limit(prove_ms_per_tx_ewma).min(memory_user_tx_limit);
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
                memory_user_tx_limit,
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
                                continue;
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

        // Snapshot installation retains this gate from before its atomic MDBX
        // commit through mempool and wallet reload. A mined block therefore
        // cannot observe the new parent and publish a newer ChainView halfway
        // through that replacement sequence.
        let chain_operation = match &self.chain_operation_gate {
            Some(gate) => Some(gate.lock().await),
            None => None,
        };

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
                        accepted_block_validation(
                            block,
                            parent,
                            prev_timestamps,
                            prev_active_counts,
                            anchor,
                            proof_bytes,
                            auth_sidecar_bytes,
                            &output.artifacts,
                            output.state_root,
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
        let confirmed: Vec<_> = block.transactions.iter().map(|tx| tx.txid()).collect();
        self.mempool
            .on_new_block(&confirmed, block.header.height, new_view)
            .await;
        drop(chain_operation);

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
/// This uses the `WalletAuthorizationBundle` borrowed from each retained
/// immutable mempool intent and copied only for the bounded selected template.
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
    let _proof_memory_reservation = tmpl
        .take_proof_memory_reservation()
        .ok_or_else(|| "unbudgeted or already-consumed proof template rejected".to_string())?;

    let mut bundles: Vec<WalletAuthorizationBundle> = Vec::with_capacity(non_cb_count);
    for (idx, opt) in tmpl.authorization_bytes.iter().enumerate() {
        let bytes = opt.as_ref().ok_or_else(|| {
            format!(
                "missing WalletAuthorizationBundle for non-coinbase tx index {idx} — will retry coinbase-only"
            )
        })?;
        let bundle = WalletAuthorizationBundle::from_bytes(bytes).map_err(|e| {
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
    let auth_sidecar_bytes = auth_sidecar
        .to_bytes()
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
    use std::sync::atomic::AtomicU8;

    #[test]
    fn payout_resolver_is_dynamic_while_configured_address_is_fixed() {
        let configured = noid_poseidon2b::primitives::Address([0x11; 32]);
        assert_eq!(resolve_mining_payout(configured, None), configured);

        let marker = Arc::new(AtomicU8::new(0x22));
        let resolver_marker = Arc::clone(&marker);
        let resolver: MiningPayoutResolver = Arc::new(move || {
            noid_poseidon2b::primitives::Address([resolver_marker.load(Ordering::Relaxed); 32])
        });
        assert_eq!(
            resolve_mining_payout(configured, Some(&resolver)),
            noid_poseidon2b::primitives::Address([0x22; 32])
        );
        marker.store(0x33, Ordering::Relaxed);
        assert_eq!(
            resolve_mining_payout(configured, Some(&resolver)),
            noid_poseidon2b::primitives::Address([0x33; 32])
        );
    }
}
