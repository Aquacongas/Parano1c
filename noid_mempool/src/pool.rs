// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! `AsyncMempool` — async wrapper around the synchronous `noid_chain::Mempool`.
//!
//! ## Architecture
//!
//! ```text
//!  submit(TxIntent)
//!    │
//!    ├─ Phase 0 (no lock):  tx_body_hash consistency — O(1) hash, rejects garbage immediately
//!    │
//!    ├─ Phase 1 (lock, brief): all cheap checks on current view
//!    │   fee floor → consensus → epoch_anchor → slot conflicts → slot state
//!    │   Extracts log_slots: u32 only — NO ChainView clone.
//!    │   DoS guard: invalid txs rejected here, never reach ZK verify.
//!    │
//!    ├─ Phase 2 (no lock): ZK verify ~84ms, semaphore-bounded
//!    │
//!    └─ Phase 3 (lock): re-run all checks against current state (TOCTOU guard)
//!                        anchor_height derived here → pool.admit
//!
//!  on_new_block() ──► [remove confirmed] ──► [evict expired] ──► [update chain view]
//!
//!  select_for_block() ──► fee-sorted list of MempoolEntry (verified txs only)
//!
//!  submit(TxIntent) ──► [fast native checks] ──► [admit] ──► [broadcast TxAdmitted]
//!                                │                               │
//!                                └── rejected → SubmitError     └── P2P gossip
//!                                                                └── RPC subscription
//!                                                                └── block builder wakeup
//!
//!  on_new_block() ──► [remove confirmed] ──► [evict expired] ──► [update chain view]
//!
//!  select_for_block() ──► fee-sorted list of MempoolEntry (verified txs only)
//! ```
//!
//! ## Pre-proving cache
//!
//! When a wallet submits a `TxIntent`, it includes a `WalletProofBundle`
//! (LogicProof + auth_slices). The pool stores this bundle in
//! `MempoolEntry.cached_algebraic_proof` immediately at admission.
//! The block assembler uses cached bundles so that `prove_block` only
//! needs to run the unified block-level SpineGKR + single FRI — the
//! per-tx wallet work is already done.

use std::collections::HashSet;
use std::sync::Arc;

use tokio::sync::{broadcast, Mutex, Semaphore};

use noid_chain::consensus::params::{ANCHOR_DEPTH, BLOCK_MAX_TXS};
use noid_chain::consensus::{checks::validate_tx_consensus, min_fee, pow::full_block_hash};
use noid_chain::fri_state::SlotValue;
use noid_chain::Mempool;
use noid_core::Block128;
use noid_poseidon2b::primitives::TxBodyHash;
use noid_tx::{Transaction, TxIntent};

use crate::config::MempoolConfig;
use crate::error::SubmitError;
use crate::event::{EvictReason, MempoolEvent};
use crate::floor::FeeFloor;
use crate::view::ChainView;

// ---------------------------------------------------------------------------
// Internal state (held under Mutex)
// ---------------------------------------------------------------------------

pub(crate) struct MempoolState {
    /// Synchronous core pool (conflict tracking, fee ordering).
    pub pool: Mempool,
    /// Chain view snapshot — updated on every new block.
    pub view: ChainView,
    /// Dynamic fee floor.
    pub floor: FeeFloor,
    /// Input slot indices currently held by admitted txs. O(1) conflict check.
    pub admitted_input_slots: HashSet<u32>,
    /// Output slot indices currently held by admitted txs. O(1) conflict check.
    pub admitted_output_slots: HashSet<u32>,
}

// ---------------------------------------------------------------------------
// AsyncMempool
// ---------------------------------------------------------------------------

/// Async, thread-safe mempool for the Paranoid full node.
///
/// Clone is O(1) — the inner state is reference-counted.
#[derive(Clone)]
pub struct AsyncMempool {
    state: Arc<Mutex<MempoolState>>,
    events: broadcast::Sender<MempoolEvent>,
    config: Arc<MempoolConfig>,
    /// Semaphore limiting concurrent ZK verification tasks.
    /// Bounds CPU usage: at most `config.zk_verify_workers` ZK proofs in flight.
    /// Set to 0 in config → semaphore with MAX permits (no limit).
    zk_semaphore: Arc<Semaphore>,
}

impl AsyncMempool {
    // -----------------------------------------------------------------------
    // Construction
    // -----------------------------------------------------------------------

    /// Create a new empty mempool with the given initial chain view.
    pub fn new(view: ChainView, config: MempoolConfig) -> Self {
        let (events, _) = broadcast::channel(1024);
        let floor = FeeFloor::new(config.fee_floor_window);
        let state = MempoolState {
            pool: Mempool::new(config.capacity),
            view,
            floor,
            admitted_input_slots: HashSet::new(),
            admitted_output_slots: HashSet::new(),
        };
        let max_permits = if config.zk_verify_workers == 0 {
            // 0 = unlimited (native-only mode or testing)
            usize::MAX / 2 // Semaphore::MAX_PERMITS
        } else {
            config.zk_verify_workers
        };
        let zk_semaphore = Arc::new(Semaphore::new(max_permits));
        Self {
            state: Arc::new(Mutex::new(state)),
            events,
            config: Arc::new(config),
            zk_semaphore,
        }
    }

    /// Subscribe to mempool events (P2P, RPC WebSocket subscriptions, miner wakeup).
    pub fn subscribe(&self) -> broadcast::Receiver<MempoolEvent> {
        self.events.subscribe()
    }

    // -----------------------------------------------------------------------
    // Tx submission
    // -----------------------------------------------------------------------

    /// Submit a `TxIntent` for admission.
    ///
    /// Runs the full native admission pipeline:
    /// 1. Fee ≥ dynamic floor
    /// 2. Basic consensus checks (fee overflow, body hash, anchor, nullifier)
    /// 3. epoch_anchor hash must be a known header within window
    /// 4. No slot conflict with admitted mempool txs
    /// 5. Input slots live in state, output slots empty
    ///
    /// ZK verification (`verify_logic`) is performed synchronously (in a
    /// `spawn_blocking` task) BEFORE the pool mutex is acquired, so invalid
    /// proofs are rejected at the mempool boundary without holding the lock.
    ///
    /// Returns the `TxBodyHash` on success.
    pub async fn submit(
        &self,
        intent: TxIntent,
        intent_bytes: Vec<u8>,
    ) -> Result<TxBodyHash, SubmitError> {
        // ── Phase 0: stateless sanity (no lock, no IO) ────────────────────
        // One hash computation rejects malformed intents before touching any
        // shared state.  Previously this ran after ZK verify — moved here so
        // hash-confusion spam is free to reject.
        if !intent.tx_body.is_coinbase {
            use noid_tx::hash_tx_body;
            let computed = hash_tx_body(
                &intent.tx_body.epoch_anchor,
                intent.tx_body.fee,
                &intent.tx_body.inputs,
                &intent.tx_body.outputs,
                intent.tx_body.is_coinbase,
            );
            if computed != intent.tx_body_hash {
                return Err(SubmitError::MalformedIntent(
                    "tx_body_hash does not match body (hash confusion attack)".into(),
                ));
            }
        }

        let needs_zk = !intent.logic_proof_bytes.is_empty() && !intent.tx_body.is_coinbase;

        // ── Phase 1: cheap pre-filter (lock held briefly) ─────────────────
        // Runs all O(1)–O(ANCHOR_DEPTH) checks on current state.
        // Rejects invalid txs BEFORE ZK verify — the DoS guard.
        // Extracts only `log_slots: u32`; avoids cloning ChainView
        // (which carries SegmentedFriState + ~28 KB of recent headers).
        let log_slots: u32 = {
            let st = self.state.lock().await;
            if st.pool.contains(&intent.tx_body_hash) {
                return Err(SubmitError::AlreadyAdmitted(intent.tx_body_hash));
            }
            let tx = intent_to_transaction(&intent)?;
            // All cheap checks. anchor_height is discarded here — re-derived
            // under lock in Phase 3 against current state (TOCTOU safety).
            let _ = run_admission_checks(&tx, &st)?;
            st.view.log_slots()
        }; // lock released — no ChainView clone

        // ── Phase 2: ZK verify (CPU-heavy, outside lock, semaphore-bounded) ─
        // Runs only when Phase 1 passed — invalid fee/anchor/slot txs are
        // already gone.  Semaphore caps concurrent CPU threads.
        if needs_zk {
            let proof_bytes = intent.logic_proof_bytes.clone();
            let tx_body_clone = intent.tx_body.clone();

            let _permit = self
                .zk_semaphore
                .acquire()
                .await
                .map_err(|_| SubmitError::Internal("zk semaphore closed".into()))?;

            tokio::task::spawn_blocking(move || {
                zk_verify_intent(&tx_body_clone, &proof_bytes, log_slots)
            })
            .await
            .map_err(|e| SubmitError::Internal(format!("spawn_blocking: {e}")))?
            .map_err(|e| SubmitError::InvalidProof(e))?;
        }

        // ── Phase 3: final admission under lock ───────────────────────────
        // Re-run all cheap checks against CURRENT state: the chain may have
        // advanced during the ~84 ms ZK verify window (new block → new
        // nullifiers, spent slots, changed fee floor).  This is the
        // authoritative check; Phase 1 was the DoS guard.
        let mut st = self.state.lock().await;

        let tx = intent_to_transaction(&intent)?;
        let hash = tx.tx_body_hash;

        if st.pool.contains(&hash) {
            return Err(SubmitError::AlreadyAdmitted(hash));
        }

        // Re-derive anchor_height from current state (needed by pool.admit).
        let anchor_height = run_admission_checks(&tx, &st)?;

        // --- Admit ---
        let fee = tx.body.fee.min(u64::MAX as u128) as u64;
        let is_coinbase = tx.body.is_coinbase;
        let has_zk_proof = needs_zk;
        let tip_height = st.view.tip_height;
        match st.pool.admit(tx.clone(), tip_height, anchor_height) {
            Ok(()) => {
                // Maintain persistent slot sets so future checks are O(1).
                for inp in tx.body.inputs.iter().filter(|i| i.valid) {
                    st.admitted_input_slots.insert(inp.slot_index);
                }
                for out in tx.body.outputs.iter().filter(|o| o.valid) {
                    st.admitted_output_slots.insert(out.slot_index);
                }
            }
            Err(noid_chain::mempool::MempoolError::Full) => {
                return Err(SubmitError::Full {
                    capacity: self.config.capacity,
                });
            }
            Err(noid_chain::mempool::MempoolError::AlreadyAdmitted) => {
                return Err(SubmitError::AlreadyAdmitted(hash));
            }
            Err(e) => {
                return Err(SubmitError::Internal(format!("{e:?}")));
            }
        }

        // Store wallet proof bundle bytes for miner block assembly.
        if !intent.logic_proof_bytes.is_empty() {
            st.pool.set_cached_proof(&hash, intent.logic_proof_bytes);
        }

        if !is_coinbase {
            st.floor.record(fee);
        }
        let _ = self.events.send(MempoolEvent::TxAdmitted {
            hash,
            fee,
            intent_bytes,
        });
        if has_zk_proof {
            let _ = self.events.send(MempoolEvent::TxPreProved { hash });
        }

        tracing::debug!(
            hash = ?hash,
            fee = fee,
            tip = st.view.tip_height,
            pool_size = st.pool.len(),
            "tx admitted to mempool"
        );

        Ok(hash)
    }

    // -----------------------------------------------------------------------
    // Block assembly
    // -----------------------------------------------------------------------

    /// Select up to `max_txs` transactions for block assembly.
    ///
    /// Returns a fee-sorted list of `(Transaction, Option<cached_proof>)`.
    /// The caller (block builder) applies conflict resolution and coinbase on top.
    ///
    /// Returned txs are in descending fee-rate order with tx_body_hash tie-break.
    pub async fn select_for_block(&self, max_txs: usize) -> Vec<noid_chain::mempool::MempoolEntry> {
        let st = self.state.lock().await;
        st.pool
            .select_for_block(max_txs.min(BLOCK_MAX_TXS))
            .into_iter()
            .cloned()
            .collect()
    }

    // -----------------------------------------------------------------------
    // Block confirmation
    // -----------------------------------------------------------------------

    /// Called when a new block is confirmed. Updates the chain view, removes
    /// confirmed txs, evicts expired txs, and broadcasts events.
    ///
    /// `confirmed_hashes`: tx_body_hashes of all txs in the confirmed block.
    /// `new_view`: updated chain state snapshot.
    pub async fn on_new_block(
        &self,
        confirmed_hashes: &[TxBodyHash],
        new_height: u64,
        new_view: ChainView,
    ) {
        let mut st = self.state.lock().await;

        // Remove confirmed txs.
        let removed = st.pool.on_block_confirmed(confirmed_hashes);
        for &hash in confirmed_hashes {
            let _ = self.events.send(MempoolEvent::TxConfirmed {
                hash,
                block_height: new_height,
            });
        }

        // Detect state expansion: if log_slots changed, all non-coinbase TXs in the
        // pool were proved with the old log_slots and cannot be included in future
        // blocks (their ZK proofs are bound to log_slots via PublicInputs).
        // Evict them now so the miner doesn't waste time on stale proofs.
        let old_log_slots = st.view.log_slots();
        let new_log_slots = new_view.log_slots();
        if old_log_slots != new_log_slots {
            let stale: Vec<TxBodyHash> = st
                .pool
                .iter()
                .filter(|(_, e)| !e.tx.body.is_coinbase)
                .map(|(h, _)| *h)
                .collect();
            let stale_count = stale.len();
            for hash in stale {
                st.pool.remove(&hash);
                let _ = self.events.send(MempoolEvent::TxEvicted {
                    hash,
                    reason: EvictReason::LogSlotsChanged,
                });
            }
            if stale_count > 0 {
                tracing::info!(
                    old_log_slots,
                    new_log_slots,
                    evicted = stale_count,
                    "state expanded: evicted stale-proof TXs from mempool (wallets must re-prove)"
                );
            }
        }

        // Update chain view BEFORE eviction so anchor check uses new state.
        st.view = new_view;

        // Evict expired (anchor window expired).
        let evicted = st.pool.evict_expired(new_height);
        for hash in evicted {
            let _ = self.events.send(MempoolEvent::TxEvicted {
                hash,
                reason: EvictReason::AnchorExpired,
            });
        }

        // Evict txs whose output slots became occupied in the new block.
        // This happens when a coinbase (from a block mined while the tx was
        // in the mempool) landed on the same slot the wallet chose for its output.
        // The wallet must re-prove with fresh slot hints.
        use noid_chain::fri_state::SlotValue;
        let output_conflicts: Vec<TxBodyHash> =
            st.pool
                .iter()
                .filter_map(|(hash, entry)| {
                    let occupied =
                        entry.tx.body.outputs.iter().any(|out| {
                            out.valid && st.view.slot(out.slot_index) != SlotValue::EMPTY
                        });
                    if occupied {
                        Some(*hash)
                    } else {
                        None
                    }
                })
                .collect();
        for hash in output_conflicts {
            st.pool.remove(&hash);
            tracing::debug!(?hash, "tx evicted: output slot occupied by confirmed block");
            let _ = self.events.send(MempoolEvent::TxEvicted {
                hash,
                reason: EvictReason::InputConsumed, // output slot conflict
            });
        }

        // Evict txs whose INPUT slots are no longer live in the new state.
        //
        // After a block is applied, some input slots of pool txs may have been
        // spent by other confirmed txs (not the same tx). Those pool txs are now
        // invalid: their input slot is EMPTY (was moved elsewhere by the block).
        //
        // Without this eviction, stale txs occupy pool capacity for up to
        // ANCHOR_DEPTH blocks (~28 min at 12s/block) before anchor_expiry.
        // They also fail silently in build_block_template (apply_tx returns Err)
        // wasting template-build cycles.
        let input_consumed: Vec<TxBodyHash> = st
            .pool
            .iter()
            .filter_map(|(hash, entry)| {
                if entry.tx.body.is_coinbase {
                    return None;
                }
                let stale = entry.tx.body.inputs.iter().any(|inp| {
                    if !inp.valid {
                        return false;
                    }
                    // Input must still hold exactly (value, owner) for this tx to
                    // be includable. If the slot is EMPTY or has different content,
                    // the tx cannot be included in any future block.
                    let expected = SlotValue {
                        value: noid_core::Block128::from(inp.value as u128),
                        owner_hi: inp.owner.as_fields()[0],
                        owner_lo: inp.owner.as_fields()[1],
                    };
                    st.view.slot(inp.slot_index) != expected
                });
                if stale {
                    Some(*hash)
                } else {
                    None
                }
            })
            .collect();
        let input_evict_count = input_consumed.len();
        for hash in input_consumed {
            st.pool.remove(&hash);
            tracing::debug!(
                ?hash,
                "tx evicted: input slot consumed or changed by confirmed block"
            );
            let _ = self.events.send(MempoolEvent::TxEvicted {
                hash,
                reason: EvictReason::InputConsumed,
            });
        }
        if input_evict_count > 0 {
            tracing::debug!(
                evicted = input_evict_count,
                "evicted stale txs with consumed input slots"
            );
        }

        // Rebuild slot sets after bulk eviction (O(pool) once/block vs O(N²) per submit).
        rebuild_slot_sets(&mut st);

        tracing::debug!(
            height = new_height,
            confirmed = confirmed_hashes.len(),
            removed_from_pool = removed,
            pool_size = st.pool.len(),
            "mempool updated after new block"
        );
    }

    /// Re-admit transactions that were reclaimed by a chain reorg.
    ///
    /// These TXs were in reverted blocks. We log the count for observability
    /// and evict any that happen to be sitting in the pool already (duplicate
    /// re-submission race). Full re-admission with fresh ZK proofs is the
    /// wallet's responsibility — wallets detect the unconfirmed state via
    /// wallet scan and resubmit.
    ///
    /// NOTE: We do not have the original ZK proof bytes after a reorg (they
    /// are not persisted). Durable TX storage could enable
    /// automatic re-admission without wallet involvement.
    pub async fn readmit_after_reorg(&self, tx_hashes: Vec<TxBodyHash>) {
        if tx_hashes.is_empty() {
            return;
        }

        tracing::info!(
            count = tx_hashes.len(),
            "reorg: {} TX(s) reclaimed — wallets should resubmit if needed",
            tx_hashes.len()
        );

        // Evict any entries with the same hash that may have been re-submitted
        // concurrently (unlikely but keeps the pool clean).
        let mut st = self.state.lock().await;
        for hash in &tx_hashes {
            if st.pool.contains(hash) {
                st.pool.remove(hash);
                tracing::debug!(?hash, "reorg: removed re-submitted duplicate from pool");
            }
        }
    }

    // -----------------------------------------------------------------------
    // Accessors
    // -----------------------------------------------------------------------

    /// Number of transactions currently in the pool.
    pub async fn len(&self) -> usize {
        self.state.lock().await.pool.len()
    }

    pub async fn is_empty(&self) -> bool {
        self.len().await == 0
    }

    /// Current dynamic fee floor (μNOID).
    pub async fn fee_floor(&self) -> u64 {
        self.state.lock().await.floor.current()
    }

    /// Snapshot all current mempool entries (for RPC inspection).
    pub async fn get_all_entries(&self) -> Vec<noid_chain::mempool::MempoolEntry> {
        let st = self.state.lock().await;
        st.pool.iter().map(|(_, e)| e.clone()).collect()
    }

    /// Update the chain view without applying a new block.
    /// Used on startup (initial state) or after a reorg.
    pub async fn update_chain_view(&self, view: ChainView) {
        self.state.lock().await.view = view;
    }
}

// ---------------------------------------------------------------------------
// Helper: all cheap admission checks
// ---------------------------------------------------------------------------

/// Run every O(1)–O(ANCHOR_DEPTH) admission check against `st`.
///
/// Called **twice** per `submit`:
/// - Phase 1 (pre-ZK DoS guard): rejects invalid txs before CPU-heavy work.
/// - Phase 3 (post-ZK TOCTOU guard): final authority against current state.
///
/// Returns `anchor_height` (needed by `pool.admit` for expiry tracking).
/// Phase 1 discards it; Phase 3 uses it.
fn run_admission_checks(tx: &Transaction, st: &MempoolState) -> Result<u64, SubmitError> {
    // Step 0: dynamic fee floor.
    if !tx.body.is_coinbase {
        let n_outputs = tx.body.outputs.iter().filter(|o| o.valid).count() as u64;
        let required = st.floor.current().max(min_fee(n_outputs));
        let actual = tx.body.fee.min(u64::MAX as u128) as u64;
        if actual < required {
            return Err(SubmitError::Consensus(
                noid_chain::consensus::ConsensusError::BelowMinFee { required, actual },
            ));
        }
    }

    // Step 1: basic consensus (fee overflow, body hash non-zero, anchor non-zero, nullifier).
    validate_tx_consensus(tx, &st.view.nullifiers)?;

    // Step 2: epoch_anchor must be a known header within ANCHOR_DEPTH window.
    // Returns anchor_height for pool.admit expiry tracking.
    let anchor_height: u64 = if !tx.body.is_coinbase {
        let anchor_hash = tx.body.epoch_anchor;
        let tip = st.view.tip_height;
        let lo = tip.saturating_sub(ANCHOR_DEPTH);
        let found = (lo..=tip).find(|&h| {
            st.view
                .recent_headers
                .get(&h)
                .map(|hdr| full_block_hash(hdr) == anchor_hash)
                .unwrap_or(false)
        });
        match found {
            Some(h) => h,
            None => {
                return Err(SubmitError::Consensus(
                    noid_chain::consensus::ConsensusError::BadEpochAnchor,
                ));
            }
        }
    } else {
        u64::MAX
    };

    // Step 3: no slot conflict with currently admitted txs (O(inputs + outputs)).
    check_slot_conflicts_with_pool(tx, &st.admitted_input_slots, &st.admitted_output_slots)?;

    // Step 4: input slots must be live in state.
    check_input_slots(tx, &st.view)?;

    // Step 5: output slots must be empty in state.
    check_output_slots(tx, &st.view)?;

    Ok(anchor_height)
}

// ---------------------------------------------------------------------------
// Helper: TxIntent → Transaction
// ---------------------------------------------------------------------------

fn intent_to_transaction(intent: &TxIntent) -> Result<Transaction, SubmitError> {
    // submit() already verified tx_body_hash matches the body before calling this.
    Ok(Transaction {
        body: intent.tx_body.clone(),
        tx_body_hash: intent.tx_body_hash,
    })
}

// ---------------------------------------------------------------------------
// Helper: rebuild admitted slot sets from current pool (O(pool), after eviction)
// ---------------------------------------------------------------------------

fn rebuild_slot_sets(st: &mut MempoolState) {
    st.admitted_input_slots.clear();
    st.admitted_output_slots.clear();
    for (_, entry) in st.pool.iter() {
        for inp in entry.tx.body.inputs.iter().filter(|i| i.valid) {
            st.admitted_input_slots.insert(inp.slot_index);
        }
        for out in entry.tx.body.outputs.iter().filter(|o| o.valid) {
            st.admitted_output_slots.insert(out.slot_index);
        }
    }
}

// ---------------------------------------------------------------------------
// Helper: slot conflict with admitted pool — O(MAX_INPUTS + MAX_OUTPUTS)
// ---------------------------------------------------------------------------

fn check_slot_conflicts_with_pool(
    tx: &Transaction,
    pool_inputs: &HashSet<u32>,
    pool_outputs: &HashSet<u32>,
) -> Result<(), SubmitError> {
    for inp in tx.body.inputs.iter().filter(|i| i.valid) {
        if pool_inputs.contains(&inp.slot_index) {
            return Err(SubmitError::Consensus(
                noid_chain::consensus::ConsensusError::SlotConflict,
            ));
        }
    }
    for out in tx.body.outputs.iter().filter(|o| o.valid) {
        if pool_outputs.contains(&out.slot_index) {
            return Err(SubmitError::Consensus(
                noid_chain::consensus::ConsensusError::SlotConflict,
            ));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Helper: input slots must be live in state
// ---------------------------------------------------------------------------

fn check_input_slots(tx: &Transaction, view: &ChainView) -> Result<(), SubmitError> {
    for inp in &tx.body.inputs {
        if !inp.valid {
            continue;
        }
        let idx = inp.slot_index;
        if (idx as u64) >= view.num_slots {
            return Err(SubmitError::Consensus(
                noid_chain::consensus::ConsensusError::ShapeMismatch(format!(
                    "input slot {idx} out of range"
                )),
            ));
        }
        let expected = SlotValue {
            value: Block128::from(inp.value as u128),
            owner_hi: inp.owner.as_fields()[0],
            owner_lo: inp.owner.as_fields()[1],
        };
        let actual = view.slot(idx);
        if actual != expected {
            // Log diagnostic: expected non-empty slot but got EMPTY.
            // Common cause: the segment containing this slot was evicted from
            // the ChainView's SegmentedFriState. Check preload_all_evicted_segments.
            tracing::warn!(
                slot_index = idx,
                expected_value = inp.value,
                actual_empty = actual.is_empty(),
                "check_input_slots: slot mismatch — likely evicted segment in ChainView"
            );
            return Err(SubmitError::Consensus(
                noid_chain::consensus::ConsensusError::BadStateRoot,
            ));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Helper: output slots must be empty in state
// ---------------------------------------------------------------------------

fn check_output_slots(tx: &Transaction, view: &ChainView) -> Result<(), SubmitError> {
    for out in &tx.body.outputs {
        if !out.valid {
            continue;
        }
        let idx = out.slot_index;
        if (idx as u64) >= view.num_slots {
            return Err(SubmitError::Consensus(
                noid_chain::consensus::ConsensusError::ShapeMismatch(format!(
                    "output slot {idx} out of range"
                )),
            ));
        }
        if view.slot(idx) != SlotValue::EMPTY {
            return Err(SubmitError::Consensus(
                noid_chain::consensus::ConsensusError::SlotConflict,
            ));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Helper: ZK verify_logic
// ---------------------------------------------------------------------------

/// Verify the wallet's LogicProof for a non-coinbase tx.
/// Returns Ok(()) if valid, Err(String) with reason if invalid.
fn zk_verify_intent(
    tx_body: &noid_tx::TxBody,
    proof_bytes: &[u8],
    log_slots: u32,
) -> Result<(), String> {
    use noid_air::composition::tx_logic::{boundary_pins_from_body, TxLogicAir};
    use noid_core::{Block128, TowerField};
    use noid_gkr::SpineInputs;
    use noid_stark::prove_logic::verify_logic;
    use noid_stark::wallet_bundle::WalletProofBundle;
    use noid_tx::{compute_claims_commitment, PublicInputs, MAX_INPUTS, MAX_OUTPUTS};

    // Decode the bundle.
    let bundle =
        WalletProofBundle::from_bytes(proof_bytes).map_err(|e| format!("bundle decode: {e}"))?;

    // Build AIR from public tx body.
    let pins = boundary_pins_from_body(tx_body);
    let air = TxLogicAir::new(pins.clone());

    // Build PublicInputs (same as build_public_inputs in witness_builder.rs).
    let [lo, hi] = pins.tx_body_hash;
    let mut hash_bytes = [0u8; 32];
    hash_bytes[..16].copy_from_slice(&lo.to_u128().to_le_bytes());
    hash_bytes[16..].copy_from_slice(&hi.to_u128().to_le_bytes());

    let n_live_inputs = tx_body.inputs.iter().filter(|i| i.valid).count() as u8;
    let n_live_outputs = tx_body.outputs.iter().filter(|o| o.valid).count() as u8;
    let claims = compute_claims_commitment(&tx_body.inputs, &tx_body.outputs);

    let mut is_activation = [false; MAX_OUTPUTS];
    let mut is_deactivation = [false; MAX_INPUTS];
    for (j, o) in tx_body.outputs.iter().enumerate().take(MAX_OUTPUTS) {
        is_activation[j] = o.valid;
    }
    for (i, inp) in tx_body.inputs.iter().enumerate().take(MAX_INPUTS) {
        is_deactivation[i] = inp.valid;
    }

    let pi = PublicInputs {
        epoch_anchor: tx_body.epoch_anchor,
        tx_body_hash: noid_poseidon2b::primitives::TxBodyHash(hash_bytes),
        fee: tx_body.fee,
        n_live_inputs,
        n_live_outputs,
        coinbase_credit: 0,
        log_slots,
        claims_commitment: claims,
        is_activation,
        is_deactivation,
    };

    // Build SpineInputs from boundary pins.
    let spine_inputs = SpineInputs {
        epoch_anchor: pins.epoch_anchor,
        fee_leaf: pins.fee_leaf,
        input_leaves: pins.input_leaf_absorb,
        output_leaves: pins.output_leaf_absorb,
        is_coinbase_leaf: pins.is_coinbase_leaf,
        pad_leaf: [Block128::ZERO; 2],
    };

    // Run verify_logic. auth_public comes directly from the bundle.
    verify_logic(
        &air,
        &pi,
        &spine_inputs,
        &bundle.auth_public,
        &bundle.logic_proof,
    )
    .map_err(|e| format!("verify_logic: {e:?}"))
}
