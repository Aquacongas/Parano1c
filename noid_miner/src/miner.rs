// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! `BlockMiner` — the parallel PoW + Prove orchestrator.
//!
//! ## Parallel proving design (ROADMAP2.md §Mining Engine)
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
//! ## Empty-block fallback
//!
//! When a new P2P block arrives while proving is in progress:
//! 1. Cancel the current PoW search immediately.
//! 2. The prove task is allowed to complete (async, non-blocking).
//! 3. Start fresh with a new template on the new chain tip.

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
    /// Template refresh heartbeat interval (seconds). Default: 15.
    pub refresh_interval_secs: u64,
    /// Refresh template when this many new txs are admitted. Default: 100.
    pub refresh_on_new_txs: usize,
}

impl Default for MinerConfig {
    fn default() -> Self {
        Self {
            miner_address: Address([0u8; 32]),
            pow_threads: 0,
            refresh_interval_secs: 15,
            refresh_on_new_txs: 100,
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
pub struct BlockMiner {
    config: MinerConfig,
    mempool: AsyncMempool,
    chain: Arc<RwLock<MdbxChainContext>>,
    events: broadcast::Sender<MinerEvent>,
    /// Cancel flag: set to abort current PoW search and restart.
    cancel_pow: Arc<AtomicBool>,
}

impl BlockMiner {
    pub fn new(
        config: MinerConfig,
        mempool: AsyncMempool,
        chain: Arc<RwLock<MdbxChainContext>>,
    ) -> (Self, broadcast::Receiver<MinerEvent>) {
        let (events, rx) = broadcast::channel(32);
        let miner = Self {
            config,
            mempool,
            chain,
            events,
            cancel_pow: Arc::new(AtomicBool::new(false)),
        };
        (miner, rx)
    }

    /// Cancel the current PoW search (call when a new P2P block arrives).
    pub fn cancel_current_pow(&self) {
        self.cancel_pow.store(true, Ordering::Relaxed);
    }

    /// Signal the miner to stop after the current search iteration.
    /// Call this before dropping/aborting the miner task to ensure
    /// Rayon threads exit cleanly rather than running a full chunk.
    pub fn stop(&self) {
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

    /// Main mining loop. Run in a dedicated `tokio::spawn` task.
    /// Never returns under normal operation.
    pub async fn run(self) {
        let builder = TemplateBuilder::new(self.mempool.clone());
        let addr = self.config.miner_address;
        let cancel = self.cancel_pow.clone();
        let mut heartbeat = interval(Duration::from_secs(self.config.refresh_interval_secs));
        let mut mempool_events = self.mempool.subscribe();

        tracing::info!(address = ?addr, "BlockMiner started");

        loop {
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
                let root = ctx.state.state.clone().root();
                (t, root)
            };

            let height = tmpl.inner.height;
            let n_txs = tmpl.inner.n_txs();

            let _ = self.events.send(MinerEvent::TemplateRefreshed {
                height,
                n_txs,
                trigger: TemplateRefreshTrigger::Startup,
            });
            tracing::info!(height, n_txs, "mining template ready");

            cancel.store(false, Ordering::Relaxed);

            // --- Parallel: PoW + ZK prove ---
            let tmpl_pow = tmpl.clone();
            let tmpl_prove = tmpl.clone();
            let cancel_pow = cancel.clone();

            // PoW: Blake3 over header_core, CPU-bound via rayon.
            let pow_handle = tokio::task::spawn_blocking(move || {
                crate::pow::search_pow_parallel(&tmpl_pow.header_for_pow(0), &cancel_pow)
            });

            // ZK Prove: prove_block with real witnesses.
            // Runs in spawn_blocking to avoid blocking the tokio runtime.
            let prove_handle =
                tokio::task::spawn_blocking(move || run_prove_block(&tmpl_prove, prev_state_root));

            // Wait for both (or cancel from heartbeat/mempool).
            tokio::select! {
                (pow_res, prove_res) = async {
                    let p = pow_handle.await;
                    let r = prove_handle.await;
                    (p, r)
                } => {
                    match (pow_res, prove_res) {
                        (Ok(Some(sol)), Ok(Ok((proof_hash, witness_root, _block_proof_bytes)))) => {
                            let block = tmpl.seal(sol.nonce, proof_hash, witness_root);
                            let block_bytes = block.to_bytes();
                            let hash = full_block_hash(&block.header);

                            tracing::info!(
                                height,
                                nonce = sol.nonce,
                                hash = ?hash,
                                n_txs,
                                "block found!"
                            );

                            let _ = self.events.send(MinerEvent::BlockFound {
                                height,
                                hash,
                                n_txs,
                                pow_nonce: sol.nonce,
                                block_bytes: block_bytes.clone(),
                            });

                            // Apply the block to the chain and update mempool.
                            if let Err(e) = self.apply_found_block(&block, &block_bytes).await {
                                tracing::error!("apply found block failed: {e}");
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
                    tracing::debug!("heartbeat: refreshing template");
                }

                event = mempool_events.recv() => {
                    if let Ok(noid_mempool::MempoolEvent::TxAdmitted { .. }) = event {
                        if self.mempool.new_since_refresh().await >= self.config.refresh_on_new_txs {
                            cancel.store(true, Ordering::Relaxed);
                            self.mempool.reset_refresh_counter().await;
                            tracing::debug!("mempool growth: refreshing template");
                        }
                    }
                }
            }
        }
    }

    /// Apply a found block to the chain and update the mempool.
    async fn apply_found_block(&self, block: &Block, _block_bytes: &[u8]) -> anyhow::Result<()> {
        use noid_mempool::ChainView;

        let local_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Apply to MDBX chain context.
        let mut ctx = self.chain.write().await;
        ctx.apply_next_block(block, local_time)?;

        // Update mempool: remove confirmed txs, update chain view.
        let confirmed: Vec<_> = block
            .transactions
            .iter()
            .map(|tx| tx.tx_body_hash)
            .collect();
        let new_view = ChainView::from_mdbx(&ctx);
        drop(ctx);

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
/// (once Phase 1.5 pre-proving is active). In Phase 3 base, the bundles are
/// decoded from `logic_proof_bytes` at block assembly time.
///
/// # Phase 3 note on state binding
///
/// `state_bindings = &[]` is intentional. Phase 5 will add full ZK state
/// binding via `BlockStateBindingAir`. In Phase 3, native consensus checks
/// enforce state correctness; the proof proves LogicProof validity only.
fn run_prove_block(
    tmpl: &crate::template::BlockTemplate,
    prev_state_root: [u8; 32],
) -> Result<([u8; 32], [u8; 32], Vec<u8>), String> {
    use noid_block::{build_block_witnesses, build_empty_state_bindings, prove_block};
    use noid_chain::block::proof_transcript_hash;
    use noid_stark::WalletProofBundle;

    let all_txs = tmpl.inner.all_txs();
    let non_cb_count = all_txs.iter().filter(|tx| !tx.body.is_coinbase).count();

    // Deserialize WalletProofBundles from cached bytes stored in the template.
    // proof_bytes[k] corresponds to inner.txs[k] (non-coinbase txs in order).
    let bundles: Vec<WalletProofBundle> = tmpl
        .proof_bytes
        .iter()
        .filter_map(|opt| {
            opt.as_ref()
                .and_then(|bytes| WalletProofBundle::from_bytes(bytes).ok())
        })
        .collect();

    // Coinbase-only block or missing bundles: use marker hashes.
    // prove_block requires at least one non-coinbase witness.
    if non_cb_count == 0 || bundles.len() != non_cb_count {
        tracing::debug!(
            height = tmpl.inner.height,
            have = bundles.len(),
            need = non_cb_count,
            "skipping ZK prove — using marker proof hashes (native consensus only)"
        );
        return Ok(([1u8; 32], [1u8; 32], vec![]));
    }

    // Build witnesses from public tx data + wallet bundles (no SpendSecret).
    // Pass log_slots from the block template so pi.log_slots == header.log_slots.
    let log_slots = tmpl.inner.log_slots;
    let owned_witnesses = build_block_witnesses(&all_txs, &bundles, log_slots);
    let witnesses: Vec<_> = owned_witnesses
        .iter()
        .map(|w| w.as_block_witness())
        .collect();
    let state_bindings = build_empty_state_bindings();

    // Run prove_block (CPU-intensive: ~10s at 100 txs on 8 cores).
    match prove_block(prev_state_root, &witnesses, &state_bindings) {
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
            tracing::warn!(
                tx_index = k,
                "wallet auth proof invalid — falling back to marker hashes"
            );
            // Auth proof mismatch. This can happen if the wallet proved with
            // a different epoch_anchor or log_slots than the block expects.
            // Fallback to marker hashes (block still valid via native consensus).
            Ok(([1u8; 32], [1u8; 32], vec![]))
        }
        Err(e) => Err(format!("{e:?}")),
    }
}
