// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! `AsyncMempool` — async wrapper around the synchronous `noid_chain::Mempool`.
//!
//! ## Architecture
//!
//! ```text
//!  submit(TxIntent)
//!    │
//!    ├─ Stateless check (no lock): canonical body logic + derived txid
//!    │
//!    ├─ Pre-proof filter (lock, brief): all cheap checks on current view
//!    │   fee floor → consensus → epoch_anchor → slot conflicts → slot state
//!    │   Extracts log_slots: u32 only — NO ChainView clone.
//!    │   DoS guard: invalid txs rejected here, never reach AuthGKR verification.
//!    │
//!    ├─ AuthGKR verification (no lock): ~84ms, semaphore-bounded
//!    │
//!    └─ Final admission (lock): re-run all checks against current state (TOCTOU guard)
//!                        anchor_height derived here → pool.admit
//!
//!  on_new_block() ──► [remove confirmed] ──► [evict expired] ──► [update chain view]
//!
//!  select_for_block() ──► fee-sorted list of MempoolEntry (verified txs only)
//! ```
//!
//! ## Pre-proving cache
//!
//! When a wallet submits a `TxIntent`, it includes a `WalletAuthorizationBundle`
//! (AuthGKR + auth_slices). The pool stores this bundle in
//! `MempoolEntry.cached_authorization` immediately at admission.
//! The block assembler uses cached bundles so that `prove_block` only
//! needs to run the unified block-level SpineGKR + single FRI — the
//! per-tx wallet work is already done.

use std::collections::HashSet;
use std::sync::Arc;

use tokio::sync::{broadcast, Mutex, Semaphore};

use noid_chain::consensus::params::BLOCK_MAX_USER_TXS;
use noid_chain::consensus::wire_limits::{MAX_AUTHORIZATION_BYTES, MAX_TX_INTENT_BYTES_GLOBAL};
use noid_chain::consensus::{
    checks::validate_tx_consensus, required_fee_for_tx_body, tx_epoch_anchor_height_for_child,
};
use noid_chain::fri_state::SlotValue;
use noid_chain::Mempool;
use noid_poseidon2b::primitives::TxBodyHash;
use noid_tx::{validate_public_tx_logic, Transaction, TxIntent};

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
    /// Locally generated maintenance transactions that must be considered
    /// before ordinary fee ordering in the next template. Admission remains
    /// identical to every other transaction; this set is only selection policy.
    pub local_template_priority: HashSet<TxBodyHash>,
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
    /// Semaphore limiting concurrent AuthGKR verification tasks.
    /// Bounds CPU usage: at most `config.auth_verify_workers` proofs in flight.
    /// Set to 0 in config → semaphore with MAX permits (no limit).
    auth_verify_semaphore: Arc<Semaphore>,
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
            local_template_priority: HashSet::new(),
        };
        let max_permits = if config.auth_verify_workers == 0 {
            // 0 = unlimited concurrency; verification is still required
            usize::MAX / 2 // Semaphore::MAX_PERMITS
        } else {
            config.auth_verify_workers
        };
        let auth_verify_semaphore = Arc::new(Semaphore::new(max_permits));
        Self {
            state: Arc::new(Mutex::new(state)),
            events,
            config: Arc::new(config),
            auth_verify_semaphore,
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
    /// 2. Basic consensus checks (fee overflow, body hash, anchor)
    /// 3. epoch_anchor equals the one canonical next-block epoch anchor
    /// 4. No slot conflict with admitted mempool txs
    /// 5. Input slots live in state, output slots empty
    ///
    /// AuthGKR authorization verification is performed synchronously (in a
    /// `spawn_blocking` task) BEFORE the pool mutex is acquired, so invalid
    /// proofs are rejected at the mempool boundary without holding the lock.
    ///
    /// Returns the `TxBodyHash` on success.
    pub async fn submit(
        &self,
        intent: TxIntent,
        intent_bytes: Vec<u8>,
    ) -> Result<TxBodyHash, SubmitError> {
        self.submit_with_policy(intent, intent_bytes, false).await
    }

    /// Submit a locally built consolidation through the identical validation
    /// pipeline and atomically mark it for next-template priority under the
    /// final admission lock. Network callers cannot set this policy bit.
    pub async fn submit_local_consolidation(
        &self,
        intent: TxIntent,
        intent_bytes: Vec<u8>,
    ) -> Result<TxBodyHash, SubmitError> {
        self.submit_with_policy(intent, intent_bytes, true).await
    }

    async fn submit_with_policy(
        &self,
        intent: TxIntent,
        intent_bytes: Vec<u8>,
        local_template_priority: bool,
    ) -> Result<TxBodyHash, SubmitError> {
        if intent_bytes.len() > MAX_TX_INTENT_BYTES_GLOBAL {
            return Err(SubmitError::IntentTooLarge {
                actual: intent_bytes.len(),
                max: MAX_TX_INTENT_BYTES_GLOBAL,
            });
        }
        // ── Stateless sanity check (no lock, no IO) ────────────────────
        // Canonical public logic rejects malformed intents before touching any
        // shared state or invoking the authorization verifier.
        if !intent.tx_body.is_coinbase {
            validate_public_tx_logic(&intent.tx_body)
                .map_err(|e| SubmitError::MalformedIntent(format!("public tx logic: {e}")))?;
        }
        let txid = intent.txid();

        if !intent.tx_body.is_coinbase && intent.authorization_bytes.is_empty() {
            return Err(SubmitError::MissingProof);
        }
        if intent.authorization_bytes.len() > MAX_AUTHORIZATION_BYTES {
            return Err(SubmitError::ProofTooLarge {
                actual: intent.authorization_bytes.len(),
                max: MAX_AUTHORIZATION_BYTES,
            });
        }
        let needs_zk = !intent.tx_body.is_coinbase;

        // ── Cheap pre-filter (lock held briefly) ─────────────────
        // Runs all cheap state checks before expensive Auth verification.
        {
            let st = self.state.lock().await;
            if st.pool.contains(&txid) {
                return Err(SubmitError::AlreadyAdmitted(txid));
            }
            let projected_bytes = st
                .pool
                .total_intent_bytes()
                .saturating_add(intent_bytes.len());
            if projected_bytes > self.config.max_total_intent_bytes {
                return Err(SubmitError::BytesFull {
                    actual: projected_bytes,
                    max: self.config.max_total_intent_bytes,
                });
            }
            let tx = intent_to_transaction(&intent)?;
            let _ = run_admission_checks(&tx, &st)?;
        }

        // ── AuthGKR verification (CPU-heavy, outside lock, semaphore-bounded) ─
        // Runs only when the pre-filter passed — invalid fee/anchor/slot txs are
        // already gone.  Semaphore caps concurrent CPU threads.
        if needs_zk {
            let proof_bytes = intent.authorization_bytes.clone();
            let tx_body_clone = intent.tx_body.clone();

            let _permit =
                self.auth_verify_semaphore.acquire().await.map_err(|_| {
                    SubmitError::Internal("proof-verification semaphore closed".into())
                })?;

            tokio::task::spawn_blocking(move || {
                verify_intent_authorization(&tx_body_clone, &proof_bytes)
            })
            .await
            .map_err(|e| SubmitError::Internal(format!("spawn_blocking: {e}")))?
            .map_err(SubmitError::InvalidProof)?;
        }

        // ── Final admission under lock ───────────────────────
        // Re-run all cheap checks against CURRENT state: the chain may have
        // advanced during the ~84 ms AuthGKR verification window (new block → new
        // spent slots and changed fee floor). This is the
        // authoritative check; the pre-filter was the DoS guard.
        let mut st = self.state.lock().await;

        let tx = intent_to_transaction(&intent)?;
        let hash = tx.txid();

        if st.pool.contains(&hash) {
            return Err(SubmitError::AlreadyAdmitted(hash));
        }
        let projected_bytes = st
            .pool
            .total_intent_bytes()
            .saturating_add(intent_bytes.len());
        if projected_bytes > self.config.max_total_intent_bytes {
            return Err(SubmitError::BytesFull {
                actual: projected_bytes,
                max: self.config.max_total_intent_bytes,
            });
        }

        // Re-derive anchor_height from current state (needed by pool.admit).
        let _anchor_height = run_admission_checks(&tx, &st)?;

        // --- Admit ---
        let fee = tx.body.fee;
        let is_coinbase = tx.body.is_coinbase;
        let has_authorization = needs_zk;
        let tip_height = st.view.tip_height;
        match st.pool.admit(tx.clone(), tip_height) {
            Ok(()) => {
                // Maintain persistent slot sets so future checks are O(1).
                for (_, inp) in tx.body.live_inputs() {
                    st.admitted_input_slots.insert(inp.slot_index);
                }
                for (_, out) in tx.body.live_outputs() {
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
        if !intent.authorization_bytes.is_empty() {
            st.pool
                .set_cached_authorization(&hash, intent.authorization_bytes);
        }
        // Store raw intent bytes for mempool-sync serving to new peers.
        st.pool.set_intent_bytes(&hash, intent_bytes.clone());
        if local_template_priority {
            st.local_template_priority.insert(hash);
        }

        if !is_coinbase {
            st.floor.record(fee);
        }
        let _ = self.events.send(MempoolEvent::TxAdmitted {
            hash,
            fee,
            intent_bytes,
        });
        if has_authorization {
            let _ = self
                .events
                .send(MempoolEvent::TxAuthorizationVerified { hash });
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
    /// Returned txs are in descending fee-rate order with txid tie-break.
    pub async fn select_for_block(&self, max_txs: usize) -> Vec<noid_chain::mempool::MempoolEntry> {
        let st = self.state.lock().await;
        let limit = max_txs.min(BLOCK_MAX_USER_TXS);
        let mut priority_hashes: Vec<TxBodyHash> = st
            .local_template_priority
            .iter()
            .filter(|hash| st.pool.contains(hash))
            .copied()
            .collect();
        priority_hashes.sort_by_key(|hash| hash.0);

        let mut selected = Vec::with_capacity(limit);
        for hash in priority_hashes.into_iter().take(limit) {
            if let Some(entry) = st.pool.get(&hash) {
                selected.push(entry.clone());
            }
        }
        if selected.len() < limit {
            for entry in st.pool.select_for_block(limit) {
                if !st.local_template_priority.contains(&entry.tx.txid()) {
                    selected.push(entry.clone());
                    if selected.len() == limit {
                        break;
                    }
                }
            }
        }
        selected
    }

    // -----------------------------------------------------------------------
    // Block confirmation
    // -----------------------------------------------------------------------

    /// Called when a new block is confirmed. Updates the chain view, removes
    /// confirmed txs, evicts expired txs, and broadcasts events.
    ///
    /// `confirmed_hashes`: derived txids of all txs in the confirmed block.
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
            st.local_template_priority.remove(&hash);
            let _ = self.events.send(MempoolEvent::TxConfirmed {
                hash,
                block_height: new_height,
            });
        }

        // Update chain view BEFORE eviction so anchor check uses new state.
        st.view = new_view;

        // Evict transactions from the previous exact epoch after a boundary.
        let stale_anchor: Vec<TxBodyHash> = st
            .pool
            .iter()
            .filter(|(_, entry)| {
                !entry.tx.body.is_coinbase
                    && entry.tx.body.epoch_anchor != st.view.user_epoch_anchor_id
            })
            .map(|(hash, _)| *hash)
            .collect();
        for hash in stale_anchor {
            st.pool.remove(&hash);
            let _ = self.events.send(MempoolEvent::TxEvicted {
                hash,
                reason: EvictReason::EpochAnchorChanged,
            });
        }

        // Evict txs whose output slots became occupied in the new block.
        // This happens when a coinbase (from a block mined while the tx was
        // in the mempool) landed on the same slot the wallet chose for its output.
        // The wallet must re-prove with fresh slot hints.
        use noid_chain::fri_state::SlotValue;
        let output_conflicts: Vec<TxBodyHash> = st
            .pool
            .iter()
            .filter_map(|(hash, entry)| {
                let occupied = entry
                    .tx
                    .body
                    .live_outputs()
                    .any(|(_, out)| st.view.slot(out.slot_index) != SlotValue::EMPTY);
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
                reason: EvictReason::OutputSlotOccupied,
            });
        }

        // Evict txs whose INPUT slots are no longer live in the new state.
        //
        // After a block is applied, some input slots of pool txs may have been
        // spent by other confirmed txs (not the same tx). Those pool txs are now
        // invalid: their input slot is EMPTY (was moved elsewhere by the block).
        //
        // They also fail silently in build_block_template (apply_tx returns Err),
        // wasting template-build cycles.
        let input_consumed: Vec<TxBodyHash> = st
            .pool
            .iter()
            .filter_map(|(hash, entry)| {
                if entry.tx.body.is_coinbase {
                    return None;
                }
                let stale = entry.tx.body.live_inputs().any(|(_, inp)| {
                    // Input must still hold exactly (value, creation_id, owner)
                    // for this tx to
                    // be includable. If the slot is EMPTY or has different content,
                    // the tx cannot be included in any future block.
                    let expected = SlotValue::with_owner_fields(
                        inp.amount,
                        inp.creation_id,
                        entry.tx.body.input_owner.as_fields(),
                    );
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
        let admitted: HashSet<TxBodyHash> = st.pool.iter().map(|(hash, _)| *hash).collect();
        st.local_template_priority
            .retain(|hash| admitted.contains(hash));

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
    /// re-submission race). Full re-admission with fresh AuthGKRs is the
    /// wallet's responsibility — wallets detect the unconfirmed state via
    /// wallet scan and resubmit.
    ///
    /// NOTE: We do not have the original AuthGKR bytes after a reorg (they
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
                st.local_template_priority.remove(hash);
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

    /// Snapshot of output slots currently reserved by admitted mempool txs.
    pub async fn reserved_output_slots(&self) -> HashSet<u32> {
        self.state.lock().await.admitted_output_slots.clone()
    }

    /// Snapshot of input slots currently reserved by admitted mempool txs.
    pub async fn reserved_input_slots(&self) -> HashSet<u32> {
        self.state.lock().await.admitted_input_slots.clone()
    }

    /// Atomically snapshot both input and output reservations.
    ///
    /// Wallet reloads use this instead of two independent reads so an
    /// intervening admission/eviction cannot leave their pending sets sourced
    /// from different mempool states.
    pub async fn reserved_slots(&self) -> (HashSet<u32>, HashSet<u32>) {
        let state = self.state.lock().await;
        (
            state.admitted_input_slots.clone(),
            state.admitted_output_slots.clone(),
        )
    }

    /// Current chain occupancy used for fee estimation: (active slots, log_slots).
    pub async fn fee_context(&self) -> (u64, u32) {
        let st = self.state.lock().await;
        (st.view.active_slot_count, st.view.log_slots())
    }

    /// Snapshot all current mempool entries (for RPC inspection).
    pub async fn get_all_entries(&self) -> Vec<noid_chain::mempool::MempoolEntry> {
        let st = self.state.lock().await;
        st.pool.iter().map(|(_, e)| e.clone()).collect()
    }

    /// O(1) lookup of a single entry by derived txid.
    pub async fn get_entry_by_hash(
        &self,
        hash: &TxBodyHash,
    ) -> Option<noid_chain::mempool::MempoolEntry> {
        let st = self.state.lock().await;
        st.pool.get(hash).cloned()
    }

    /// All raw TxIntent bytes for every pending transaction (for mempool sync).
    pub async fn all_intent_bytes(&self) -> Vec<Vec<u8>> {
        let st = self.state.lock().await;
        st.pool.all_intent_bytes()
    }

    /// Update the chain view without applying a new block.
    /// Used on startup (initial state) or after a reorg.
    pub async fn update_chain_view(&self, view: ChainView) {
        self.state.lock().await.view = view;
    }

    /// Serialized owner-auth proof bytes for the given admitted tx body
    /// hashes — the byte-exact objects this pool cryptographically verified
    /// at admission. Block acceptance uses them as a re-verification fast
    /// path: a block-carried proof that serializes to the same bytes needs
    /// no second verification; anything else falls back to the full check.
    pub async fn verified_authorization_proof_bytes(
        &self,
        hashes: &[TxBodyHash],
    ) -> std::collections::HashMap<[u8; 32], Vec<u8>> {
        use noid_gkr::WalletAuthorizationBundle;
        let intents: Vec<Vec<u8>> = {
            let st = self.state.lock().await;
            hashes
                .iter()
                .filter_map(|hash| st.pool.get(hash))
                .map(|entry| entry.intent_bytes.clone())
                .collect()
        };
        let mut out = std::collections::HashMap::with_capacity(intents.len());
        for intent_bytes in intents {
            let Ok(intent) = TxIntent::from_bytes(&intent_bytes) else {
                continue;
            };
            let Ok(bundle) = WalletAuthorizationBundle::from_bytes(&intent.authorization_bytes)
            else {
                continue;
            };
            let Some(proof_bytes) = bundle.proof_wire_bytes() else {
                continue;
            };
            out.insert(intent.txid().0, proof_bytes);
        }
        out
    }
}

// ---------------------------------------------------------------------------
// Helper: all cheap admission checks
// ---------------------------------------------------------------------------

/// Run every cheap admission check against `st`.
///
/// Called **twice** per `submit`:
/// - Pre-proof filter (DoS guard): rejects invalid txs before CPU-heavy work.
/// - Post-proof TOCTOU guard: final authority against current state.
///
/// Returns `anchor_height` (needed by `pool.admit` for expiry tracking).
/// The pre-filter discards it; the final admission step uses it.
fn run_admission_checks(tx: &Transaction, st: &MempoolState) -> Result<u64, SubmitError> {
    // Dynamic fee floor layered over the deterministic consensus minimum.
    if !tx.body.is_coinbase {
        let consensus_required =
            required_fee_for_tx_body(&tx.body, st.view.active_slot_count, st.view.log_slots());
        let required = st.floor.current().max(consensus_required);
        let actual = tx.body.fee;
        if actual < required {
            return Err(SubmitError::Consensus(
                noid_chain::consensus::ConsensusError::BelowMinFee { required, actual },
            ));
        }
    }

    // Basic consensus (fee overflow, body hash non-zero, anchor non-zero).
    validate_tx_consensus(tx)?;

    // Epoch anchor is the one start-of-next-block transaction-epoch anchor.
    // Returns its height for deterministic mempool bookkeeping.
    let anchor_height: u64 = if !tx.body.is_coinbase {
        let height = tx_epoch_anchor_height_for_child(st.view.tip_height + 1);
        if st.view.user_epoch_anchor_id == [0u8; 32]
            || tx.body.epoch_anchor != st.view.user_epoch_anchor_id
        {
            return Err(SubmitError::Consensus(
                noid_chain::consensus::ConsensusError::BadEpochAnchor,
            ));
        }
        height
    } else {
        u64::MAX
    };

    // No slot conflict with currently admitted txs (O(inputs + outputs)).
    check_slot_conflicts_with_pool(tx, &st.admitted_input_slots, &st.admitted_output_slots)?;

    // Input slots must be live in state.
    check_input_slots(tx, &st.view)?;

    // Output slots must be empty in state.
    check_output_slots(tx, &st.view)?;

    Ok(anchor_height)
}

// ---------------------------------------------------------------------------
// Helper: TxIntent → Transaction
// ---------------------------------------------------------------------------

fn intent_to_transaction(intent: &TxIntent) -> Result<Transaction, SubmitError> {
    Ok(Transaction::new(intent.tx_body.clone()))
}

// ---------------------------------------------------------------------------
// Helper: rebuild admitted slot sets from current pool (O(pool), after eviction)
// ---------------------------------------------------------------------------

fn rebuild_slot_sets(st: &mut MempoolState) {
    st.admitted_input_slots.clear();
    st.admitted_output_slots.clear();
    for (_, entry) in st.pool.iter() {
        for (_, inp) in entry.tx.body.live_inputs() {
            st.admitted_input_slots.insert(inp.slot_index);
        }
        for (_, out) in entry.tx.body.live_outputs() {
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
    for (_, inp) in tx.body.live_inputs() {
        if pool_inputs.contains(&inp.slot_index) {
            return Err(SubmitError::Consensus(
                noid_chain::consensus::ConsensusError::SlotConflict,
            ));
        }
    }
    for (_, out) in tx.body.live_outputs() {
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
    for (_, inp) in tx.body.live_inputs() {
        let idx = inp.slot_index;
        if (idx as u64) >= view.num_slots {
            return Err(SubmitError::Consensus(
                noid_chain::consensus::ConsensusError::ShapeMismatch(format!(
                    "input slot {idx} out of range"
                )),
            ));
        }
        let expected = SlotValue::with_owner_fields(
            inp.amount,
            inp.creation_id,
            tx.body.input_owner.as_fields(),
        );
        let actual = view.slot(idx);
        if actual != expected {
            // Log diagnostic: expected non-empty slot but got EMPTY.
            // Common cause: the segment containing this slot was evicted from
            // the ChainView's SegmentedFriState. Check preload_all_evicted_segments.
            tracing::warn!(
                slot_index = idx,
                expected_value = inp.amount,
                expected_creation_id = inp.creation_id,
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
    for (_, out) in tx.body.live_outputs() {
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
// Helper: Auth-only wallet authorization verification
// ---------------------------------------------------------------------------

/// Verify the wallet authorization for a non-coinbase tx.
/// Returns Ok(()) if valid, Err(String) with reason if invalid.
fn verify_intent_authorization(
    tx_body: &noid_tx::TxBody,
    authorization_bytes: &[u8],
) -> Result<(), String> {
    use noid_gkr::{verify_wallet_authorization, WalletAuthorizationBundle};

    let bundle = WalletAuthorizationBundle::from_bytes(authorization_bytes)
        .map_err(|e| format!("authorization decode: {e}"))?;
    verify_wallet_authorization(tx_body, &bundle).map_err(|e| format!("authorization verify: {e}"))
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use noid_chain::consensus::genesis::genesis_header;
    use noid_chain::fri_state::SlotValue;
    use noid_chain::state::ChainState;
    use noid_poseidon2b::primitives::Address;
    use noid_tx::{
        output_bitmap_bit, Transaction, TxBody, TxInput, TxOutput, TX_INPUTS, TX_OUTPUTS,
    };

    use super::check_input_slots;
    use crate::view::ChainView;

    #[test]
    fn input_state_match_binds_creation_id() {
        let owner = Address([0xA5; 32]);
        let mut state = ChainState::with_log_slots(6);
        state
            .state
            .set_slot(
                7,
                SlotValue::with_owner_fields(1_000, 42, owner.as_fields()),
            )
            .unwrap();
        let mut headers = HashMap::new();
        headers.insert(0, genesis_header());
        let view = ChainView::new(0, headers, 1, state.state);
        let mut inputs = [TxInput::dummy(); TX_INPUTS];
        inputs[0] = TxInput {
            slot_index: 7,
            amount: 1_000,
            creation_id: 41,
        };
        let mut outputs = [TxOutput::dummy(); TX_OUTPUTS];
        outputs[0] = TxOutput {
            slot_index: 8,
            amount: 999,
            owner: Address([0xB6; 32]),
        };
        let mut tx = Transaction::new(TxBody {
            epoch_anchor: [1; 32],
            fee: 1,
            input_owner: owner,
            inputs,
            outputs,
            validity_bitmap: 1 | output_bitmap_bit(0),
            is_coinbase: false,
        });

        assert!(check_input_slots(&tx, &view).is_err());
        tx.body.inputs[0].creation_id = 42;
        assert!(check_input_slots(&tx, &view).is_ok());
    }

    fn policy_tx(seed: u8, fee: u64) -> Transaction {
        let mut inputs = [TxInput::dummy(); TX_INPUTS];
        inputs[0] = TxInput {
            slot_index: u32::from(seed),
            amount: 1_000 + fee,
            creation_id: u64::from(seed),
        };
        let mut outputs = [TxOutput::dummy(); TX_OUTPUTS];
        outputs[0] = TxOutput {
            slot_index: u32::from(seed) + 100,
            amount: 1_000,
            owner: Address([seed.wrapping_add(1); 32]),
        };
        Transaction::new(TxBody {
            epoch_anchor: [1; 32],
            fee,
            input_owner: Address([seed; 32]),
            inputs,
            outputs,
            validity_bitmap: 1 | output_bitmap_bit(0),
            is_coinbase: false,
        })
    }

    #[tokio::test]
    async fn trusted_local_consolidation_precedes_fee_order() {
        let mut headers = HashMap::new();
        headers.insert(0, genesis_header());
        let view = ChainView::new(0, headers, 0, ChainState::with_log_slots(8).state);
        let pool = crate::AsyncMempool::new(view, crate::MempoolConfig::default());
        let maintenance = policy_tx(1, 1);
        let ordinary = policy_tx(2, 10_000);
        let maintenance_id = maintenance.txid();
        {
            let mut state = pool.state.lock().await;
            state.pool.admit(maintenance, 0).unwrap();
            state.pool.admit(ordinary, 0).unwrap();
            state.local_template_priority.insert(maintenance_id);
        }

        let selected = pool.select_for_block(1).await;
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].tx.txid(), maintenance_id);
    }
}
