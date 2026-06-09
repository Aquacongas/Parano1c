// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! `BlockMiner` — the parallel PoW + Prove orchestrator.
//!
//! ## Parallel proving design
//!
//! ```text
//! loop {
//!   template = build_template(mempool, ctx)
//!
//!   ┌─────────────────────────┐   ┌─────────────────────────────────┐
//!   │  PoW Search             │   │  ZK Block Prove                 │
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
//! Expected timing at 1024 txs on 8 cores:
//!   PoW:   ~60s target (ASERT-controlled)
//!   Prove: ~10s (parallel algebraic STARK + unified GKR + FRI)
//!   → PoW is the bottleneck; no block time wasted on proving.
//!
//! Template refresh triggers (see run loop):
//!   1. Heartbeat every `refresh_interval_secs` seconds (safety net)
//!   2. First `TxAdmitted` while prove is done (Sealed state — semaphore free, PoW running)
//!   3. New chain tip from P2P (block received or snapshot applied)

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Duration;

use tokio::sync::{broadcast, RwLock};
use tokio::time::interval;

use noid_chain::block::Block;
use noid_chain::consensus::pow::full_block_hash;
use noid_chain::storage::MdbxChainContext;
use noid_mempool::AsyncMempool;
use noid_poseidon2b::primitives::Address;

use crate::template::{TemplateBuilder, TemplateRefreshTrigger};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for the block miner.
#[derive(Debug, Clone)]
pub struct MinerConfig {
    /// Address that receives the coinbase reward.
    pub miner_address: Address,
    /// Number of rayon threads for PoW search. 0 = all physical cores.
    pub pow_threads: usize,
    /// Safety-net heartbeat interval (seconds).
    ///
    /// Fires only if the miner has been stuck without a block for this long.
    /// Normal template refreshes happen immediately via `sync_ready` (P2P
    /// block received) and `TxAdmitted` (Sealed state: prove done, PoW
    /// running).  This timer exists only for edge cases where both are silent.
    ///
    /// Must be > BLOCK_TIME to avoid firing during active proving and
    /// inserting unnecessary coinbase blocks.  Default: 5 × BLOCK_TIME = 60s.
    pub refresh_interval_secs: u64,
}

impl Default for MinerConfig {
    fn default() -> Self {
        Self {
            miner_address: Address([0u8; 32]),
            pow_threads: 0,
            refresh_interval_secs: 60, // 5 × BLOCK_TIME; real triggers are sync_ready + TxAdmitted
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
    },
    /// Template refreshed.
    TemplateRefreshed {
        height: u64,
        n_txs: usize,
        trigger: TemplateRefreshTrigger,
    },
    /// Mining cancelled (new P2P block or heartbeat).
    MiningCancelled { reason: String },
    /// ZK proving failed (non-fatal: block is abandoned, new template built).
    ProveFailed { height: u64, error: String },
}

// ---------------------------------------------------------------------------
// BlockMiner
// ---------------------------------------------------------------------------

/// The main block production orchestrator.
/// Callback invoked synchronously inside `apply_found_block`, before the mempool
/// is updated. Enables the built-in wallet to capture receipts race-free:
/// by the time `getMempoolSize` drops to 0, the receipt is already stored.
///
/// Light-node wallets subscribe via the P2P block event instead.
pub type BlockAppliedHook = Arc<dyn Fn(&noid_chain::block::Block) + Send + Sync>;

pub struct BlockMiner {
    config: MinerConfig,
    mempool: AsyncMempool,
    chain: Arc<RwLock<MdbxChainContext>>,
    events: broadcast::Sender<MinerEvent>,
    /// Cancel flag: set to abort current PoW search and restart.
    cancel_pow: Arc<AtomicBool>,
    /// Permanent stop flag: set only by stop(), never reset. The main loop
    /// checks this at the top of each iteration and breaks cleanly.
    stopped: Arc<AtomicBool>,
    /// Notified when the chain is sufficiently synced to begin mining.
    sync_ready: Arc<tokio::sync::Notify>,
    /// Semaphore (1 permit) preventing concurrent ZK prove tasks from accumulating.
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
        let miner = Self {
            config,
            mempool,
            chain,
            events,
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

            let (tmpl, prev_state_root) = {
                let ctx = self.chain.read().await;
                let t = match builder.build(&ctx, addr, now).await {
                    Some(t) => t,
                    None => {
                        tracing::warn!("template build failed, retrying in 1s");
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        continue;
                    }
                };
                let prev_state_root = ctx.tip_header().state_root; // O(1) — no clone
                (t, prev_state_root)
            };

            let height = tmpl.inner.height;
            let n_txs = tmpl.inner.n_txs();

            let _ = self.events.send(MinerEvent::TemplateRefreshed {
                height,
                n_txs,
                trigger: TemplateRefreshTrigger::Startup,
            });
            tracing::debug!(height, n_txs, "mining template ready");

            // Track when PoW search started so we can report solve time.
            let pow_start = std::time::Instant::now();

            cancel.store(false, Ordering::Relaxed);

            // Track when prove completes so the TxAdmitted arm can detect "Sealed" state:
            // prove_done=true means the semaphore has been released and PoW is still running —
            // safe to cancel PoW and rebuild with newly admitted txs at zero prove-work cost.
            let prove_done = Arc::new(AtomicBool::new(false));
            let prove_done_clone = prove_done.clone();

            // --- Parallel: PoW + ZK prove ---
            // Extract only the PoW header — avoids cloning the full BlockTemplate
            // (which includes all transaction and proof bytes) just for PoW.
            let pow_header = tmpl.header_for_pow(0);
            let tmpl_prove = tmpl.clone();
            let cancel_pow = cancel.clone();

            // Try to acquire the single-permit prove semaphore.
            // spawn_blocking tasks are NOT cancelled when JoinHandles are dropped;
            // without this guard each 15s heartbeat can accumulate another ~10s prove
            // task, eventually saturating all CPU cores.
            let prove_permit = self.prove_semaphore.clone().try_acquire_owned();

            // If the semaphore is already held and the template has user txs we
            // cannot legally use a stub proof — skip this iteration and wait for
            // the running prove to release the permit.
            if prove_permit.is_err() && tmpl.n_user_txs() > 0 {
                tracing::warn!(
                    height,
                    "prove task busy and block has user txs — skipping this template iteration"
                );
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
            }

            // PoW: Blake3 over header_core, CPU-bound via rayon.
            let pow_handle = tokio::task::spawn_blocking(move || {
                crate::pow::search_pow_parallel(&pow_header, &cancel_pow)
            });

            // ZK Prove: run for real (permit held until done) or return a consensus-legal
            // stub for coinbase-only blocks when the prove slot is already occupied.
            let prove_handle = match prove_permit {
                Ok(permit) => tokio::task::spawn_blocking(move || {
                    // Run prove inside a scope so the semaphore permit is released
                    // BEFORE we set prove_done. This guarantees: when the miner loop
                    // sees prove_done=true, the semaphore is already free for the next
                    // template rebuild.
                    let result = {
                        let _permit = permit;
                        run_prove_block(&tmpl_prove, prev_state_root)
                    };
                    prove_done_clone.store(true, Ordering::Release);
                    result
                }),
                Err(_) => {
                    // Semaphore busy, but coinbase-only block — stub is consensus-legal.
                    tracing::warn!(
                        height,
                        "prove task busy, will use stub proof (coinbase-only this round)"
                    );
                    tokio::task::spawn_blocking(move || {
                        // Stub is instant; mark prove_done so TxAdmitted can trigger rebuild.
                        prove_done_clone.store(true, Ordering::Release);
                        Ok(([1u8; 32], [1u8; 32], vec![]))
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
                        (Ok(Some(sol)), Ok(Ok((proof_hash, witness_root, block_proof_bytes)))) => {
                            let block = tmpl.seal(sol.nonce, proof_hash, witness_root);
                            let block_bytes = block.to_bytes();
                            let hash = full_block_hash(&block.header);
                            let elapsed = pow_start.elapsed();
                            let elapsed_s = elapsed.as_secs_f64();

                            // Count leading zeros of the difficulty target (MSB-first, LE).
                            // Matches block_work() in difficulty.rs — higher = harder.
                            // Genesis = 27lz. ASERT raises this when blocks arrive faster
                            // than BLOCK_TIME (12s) and lowers it when they're slower.
                            let diff_lz: u32 = {
                                let t = &block.header.difficulty_target;
                                let mut lz = 0u32;
                                for i in (0..32).rev() {
                                    if t[i] == 0 { lz += 8; }
                                    else { lz += t[i].leading_zeros(); break; }
                                }
                                lz
                            };

                            tracing::info!(
                                height,
                                hash = %hex::encode(hash),
                                n_txs,
                                time = %format!("{elapsed_s:.2}s"),
                                diff = %format!("lz{diff_lz}"),
                                "block found"
                            );

                            let _ = self.events.send(MinerEvent::BlockFound {
                                height,
                                hash,
                                n_txs,
                                pow_nonce: sol.nonce,
                                block_bytes: block_bytes.clone(),
                                block_proof_bytes: block_proof_bytes.clone(),
                            });

                            // Apply the block to the chain and update mempool.
                            if let Err(e) = self.apply_found_block(&block, &block_bytes).await {
                                tracing::warn!(height, "miner: block superseded (reorg in progress): {e}");
                            }

                            // Store block proof bytes for recursive proof advancement.
                            // Only store if we have real proof bytes (not marker hashes from coinbase-only blocks).
                            if !block_proof_bytes.is_empty() {
                                let ctx = self.chain.read().await;
                                if let Err(e) = ctx.store.put_block_proof(height, &block_proof_bytes) {
                                    tracing::warn!(height, err = %e, "failed to store block proof bytes");
                                } else {
                                    tracing::debug!(height, bytes = block_proof_bytes.len(), "block proof stored");
                                }
                            }
                        }
                        (Ok(Some(_sol)), Ok(Err(e))) => {
                            // PoW succeeded but proof failed — abandon block.
                            tracing::error!("prove_block failed at height {height}: {e}");
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

                _ = heartbeat.tick() => {
                    cancel.store(true, Ordering::Relaxed);
                    tracing::debug!("heartbeat: refreshing template (safety net)");
                }

                event = mempool_events.recv() => {
                    if let Ok(noid_mempool::MempoolEvent::TxAdmitted { .. }) = event {
                        if prove_done.load(Ordering::Acquire) {
                            // Sealed state: prove is done (semaphore free) and PoW is still
                            // running. We can cancel PoW and rebuild immediately at zero
                            // prove-work cost — the new template will include this tx.
                            cancel.store(true, Ordering::Relaxed);
                            tracing::debug!("sealed-state: new tx admitted, cancelling PoW for immediate inclusion");
                        }
                        // Proving state: don't cancel — the in-flight prove work would be
                        // wasted. The tx sits in mempool and is picked up when prove finishes
                        // and the next template is built.
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
    /// Write lock is held ONLY for the MDBX commit + wallet hook.
    /// `ChainView::from_mdbx` (which clones SegmentedFriState) runs under a
    /// READ lock so it does not block incoming P2P blocks or RPC queries.
    ///
    /// Between write unlock and read lock, another block could arrive and be
    /// applied. In that case `ChainView` reflects height H+2 while we notify
    /// the mempool about confirmed txs at height H+1. This is safe:
    /// - Confirmed tx removal uses the hash list (always correct).
    /// - ChainView slot checks use the newest available state (safe to be ahead).
    async fn apply_found_block(&self, block: &Block, _block_bytes: &[u8]) -> anyhow::Result<()> {
        use noid_mempool::ChainView;

        let local_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // --- MDBX commit off the async executor ---
        //
        // SyncMode::Durable means commit_block issues fsync before returning —
        // a blocking syscall.  spawn_blocking keeps it off the tokio worker.
        // The wallet hook fires inside the closure while the write lock is
        // still held, preserving the original "hook before mempool" ordering.
        {
            let chain_clone = self.chain.clone();
            let block_owned = block.clone();
            let hook = self.on_block_applied.clone();
            tokio::task::spawn_blocking(move || {
                let mut ctx = chain_clone.blocking_write();
                ctx.apply_next_block(&block_owned, local_time)?;
                if let Some(h) = &hook {
                    h(&block_owned);
                }
                Ok::<(), noid_chain::storage::MdbxContextError>(())
            })
            .await
            .expect("apply_next_block panicked in spawn_blocking")
            .map_err(anyhow::Error::from)?
        } // write lock released here

        // --- Build ChainView under read lock (shared, non-blocking) ---
        let confirmed: Vec<_> = block
            .transactions
            .iter()
            .map(|tx| tx.tx_body_hash)
            .collect();
        let new_view = {
            let ctx = self.chain.read().await;
            ChainView::from_mdbx(&ctx)
        }; // read lock released

        // --- Update mempool (no chain lock held) ---
        self.mempool
            .on_new_block(&confirmed, block.header.height, new_view)
            .await;

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// ZK prove_block (CPU-bound, called inside spawn_blocking)
// ---------------------------------------------------------------------------

/// Run `prove_block` with the witnesses from the template's transactions.
///
/// Returns `(proof_transcript_hash, witness_root, proof_bytes)` on success.
///
/// # Correctness
///
/// This uses the `WalletProofBundle` stored in each `MempoolEntry.cached_algebraic_proof`
/// (when pre-proving cache is populated). When no bundles exist, the
/// decoded from `logic_proof_bytes` at block assembly time.
///
/// # State binding
///
/// When `tmpl.inner.state_binding` is `Some`, state bindings are built via
/// `build_state_bindings_from_binding` and passed to `prove_block`. When the
/// template has no state binding (e.g. coinbase-only blocks), empty bindings
/// are used and native consensus checks enforce state correctness.
pub(crate) fn run_prove_block(
    tmpl: &crate::template::BlockTemplate,
    prev_state_root: [u8; 32],
) -> Result<([u8; 32], [u8; 32], Vec<u8>), String> {
    use noid_block::{
        build_block_witnesses, build_empty_state_bindings, build_state_bindings_from_binding,
        prove_block,
    };
    use noid_chain::block::proof_transcript_hash;
    use noid_stark::WalletProofBundle;

    // Coinbase-only: marker proof, no ZK proving needed.
    let non_cb_count = tmpl.n_user_txs();
    if non_cb_count == 0 {
        tracing::debug!(
            height = tmpl.inner.height,
            "coinbase-only block — marker proof OK"
        );
        return Ok(([1u8; 32], [1u8; 32], vec![]));
    }

    let all_txs = tmpl.inner.all_txs();
    let bundles: Vec<WalletProofBundle> = tmpl
        .proof_bytes
        .iter()
        .filter_map(|opt| {
            opt.as_ref()
                .and_then(|b| WalletProofBundle::from_bytes(b).ok())
        })
        .collect();
    if bundles.len() != non_cb_count {
        return Err(format!(
            "missing WalletProofBundles: have {}, need {} — will retry coinbase-only",
            bundles.len(),
            non_cb_count,
        ));
    }

    let log_slots = tmpl.inner.log_slots;
    let owned_witnesses = build_block_witnesses(&all_txs, &bundles, log_slots);
    let witnesses: Vec<_> = owned_witnesses
        .iter()
        .map(|w| w.as_block_witness())
        .collect();

    // Build state bindings (FRI + Merkle path data) if binding is available.
    let n_tx = tmpl.n_user_txs() as u32;
    let non_cb_bodies: Vec<noid_tx::TxBody> =
        tmpl.inner.txs.iter().map(|tx| tx.body.clone()).collect();
    let owned_bindings = match &tmpl.inner.state_binding {
        Some(binding) if !non_cb_bodies.is_empty() => build_state_bindings_from_binding(
            binding,
            &non_cb_bodies,
            &tmpl.pre_segs,
            prev_state_root,
            n_tx,
            log_slots,
        ),
        _ => vec![],
    };
    let empty_bindings = build_empty_state_bindings();
    let state_bindings_owned: Vec<_> = owned_bindings.iter().map(|b| b.as_witness()).collect();
    let state_bindings: &[_] = if state_bindings_owned.is_empty() {
        &empty_bindings
    } else {
        &state_bindings_owned
    };
    let new_state_root = tmpl
        .inner
        .state_binding
        .as_ref()
        .map(|b| b.new_state_root)
        .unwrap_or([0u8; 32]);

    // Run prove_block (CPU-intensive: ~10s at 100 txs on 8 cores).
    match prove_block(prev_state_root, new_state_root, &witnesses, state_bindings) {
        Ok(block_proof) => {
            let proof_bytes = bincode::serialize(&block_proof).unwrap_or_default();
            let transcript_hash = proof_transcript_hash(&proof_bytes);
            // witness_root = DA payload commitment; uses transcript_hash until
            // full Binius DA packing is wired (noid_chain::da::trace_witness_root).
            let witness_root = transcript_hash;

            tracing::info!(bytes = proof_bytes.len(), "prove_block succeeded");
            Ok((transcript_hash, witness_root, proof_bytes))
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
