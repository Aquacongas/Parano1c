// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! `AsyncMempool` — async wrapper around the synchronous `noid_chain::Mempool`.
//!
//! ## Architecture
//!
//! ```text
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
//! ## Phase 1.5 pre-proving (background task)
//!
//! When `config.pre_prove_enabled = true`, each admitted tx is sent to a
//! background worker that calls `prove_air_algebraic_pretx`.  The result is
//! stored in `MempoolEntry.cached_algebraic_proof` and broadcast as
//! `MempoolEvent::TxPreProved`.  The block assembler can then skip the
//! per-tx proving step and run only the unified block GKR + single FRI.

use std::collections::HashSet;
use std::sync::Arc;

use tokio::sync::{broadcast, Mutex};

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
    /// Count of admitted txs since last template refresh trigger.
    pub new_since_refresh: usize,
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
            new_since_refresh: 0,
        };
        Self {
            state: Arc::new(Mutex::new(state)),
            events,
            config: Arc::new(config),
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
        // Phase 5: ZK verify_logic before pool admission.
        // The wallet's LogicProof (STARK + AuthGKR Kill-Shot) is verified here so
        // invalid proofs are rejected at the mempool boundary, not silently stored.
        // This is CPU-heavy (~84ms); we run it in spawn_blocking BEFORE acquiring
        // the pool mutex to avoid holding the lock during computation.
        if !intent.logic_proof_bytes.is_empty() && !intent.tx_body.is_coinbase {
            // Snapshot the chain view (O(1) clone) before the blocking call.
            let view_snap = {
                let st = self.state.lock().await;
                st.view.clone()
            };

            let proof_bytes = intent.logic_proof_bytes.clone();
            let tx_body_clone = intent.tx_body.clone();
            let log_slots = view_snap.log_slots();

            let verify_result = tokio::task::spawn_blocking(move || {
                zk_verify_intent(&tx_body_clone, &proof_bytes, log_slots)
            })
            .await
            .map_err(|e| SubmitError::Internal(format!("spawn_blocking: {e}")))?;

            verify_result.map_err(|e| SubmitError::InvalidProof(e))?;
        }

        let mut st = self.state.lock().await;

        let tx = intent_to_transaction(&intent)?;
        let hash = tx.tx_body_hash;

        // --- Idempotent: already admitted ---
        if st.pool.contains(&hash) {
            return Err(SubmitError::AlreadyAdmitted(hash));
        }

        // --- Step 0: dynamic fee floor ---
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

        // --- Step 1: basic consensus (fee overflow, body hash, anchor non-zero, nullifier) ---
        validate_tx_consensus(&tx, &st.view.nullifiers)?;

        // --- Step 2: epoch_anchor hash must be a known header within ANCHOR_DEPTH window ---
        if !tx.body.is_coinbase {
            let anchor_hash = tx.body.epoch_anchor;
            let tip = st.view.tip_height;
            let lo = tip.saturating_sub(ANCHOR_DEPTH);
            let anchor_ok = (lo..=tip).any(|h| {
                st.view
                    .recent_headers
                    .get(&h)
                    .map(|hdr| full_block_hash(hdr) == anchor_hash)
                    .unwrap_or(false)
            });
            if !anchor_ok {
                return Err(SubmitError::Consensus(
                    noid_chain::consensus::ConsensusError::BadEpochAnchor,
                ));
            }
        }

        // --- Step 3: no slot conflict with admitted pool txs ---
        let admitted_txs: Vec<Transaction> = st.pool.iter().map(|(_, e)| e.tx.clone()).collect();
        check_slot_conflicts_with_pool(&tx, &admitted_txs)?;

        // --- Step 4: input slots live in state ---
        check_input_slots(&tx, &st.view)?;

        // --- Step 5: output slots empty in state ---
        check_output_slots(&tx, &st.view)?;

        // --- Admit ---
        let fee = tx.body.fee.min(u64::MAX as u128) as u64;
        let is_coinbase = tx.body.is_coinbase; // capture before move
        let has_zk_proof = !intent.logic_proof_bytes.is_empty() && !is_coinbase;
        let tip_height = st.view.tip_height;
        match st.pool.admit(tx, tip_height) {
            Ok(()) => {}
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
        // logic_proof_bytes = serialized WalletProofBundle (LogicProof + auth_slices).
        // The miner deserializes these when building the ZK block proof.
        if !intent.logic_proof_bytes.is_empty() {
            st.pool.set_cached_proof(&hash, intent.logic_proof_bytes);
        }

        // Update fee floor (coinbase exempt) and refresh counter.
        if !is_coinbase {
            st.floor.record(fee);
        }
        st.new_since_refresh += 1;

        // Broadcast (non-blocking: drop if no subscribers).
        let _ = self.events.send(MempoolEvent::TxAdmitted {
            hash,
            fee,
            intent_bytes,
        });

        // Broadcast pre-proved event (ZK verified at admission).
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
                reason: EvictReason::InputConsumed, // slot conflict
            });
        }

        // Reset new-since-refresh counter (block was found — template is stale anyway).
        st.new_since_refresh = 0;

        tracing::debug!(
            height = new_height,
            confirmed = confirmed_hashes.len(),
            removed_from_pool = removed,
            pool_size = st.pool.len(),
            "mempool updated after new block"
        );
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

    /// Number of txs admitted since the last template refresh trigger.
    /// The block builder should refresh the template when this ≥ 100.
    pub async fn new_since_refresh(&self) -> usize {
        self.state.lock().await.new_since_refresh
    }

    /// Reset the new-since-refresh counter (called by block builder after refresh).
    pub async fn reset_refresh_counter(&self) {
        self.state.lock().await.new_since_refresh = 0;
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
// Helper: TxIntent → Transaction
// ---------------------------------------------------------------------------

fn intent_to_transaction(intent: &TxIntent) -> Result<Transaction, SubmitError> {
    use noid_tx::hash_tx_body;
    let expected = hash_tx_body(
        &intent.tx_body.epoch_anchor,
        intent.tx_body.fee,
        &intent.tx_body.inputs,
        &intent.tx_body.outputs,
        intent.tx_body.is_coinbase,
    );
    if expected != intent.tx_body_hash {
        return Err(SubmitError::MalformedIntent(
            "tx_body_hash does not match body".into(),
        ));
    }
    Ok(Transaction {
        body: intent.tx_body.clone(),
        tx_body_hash: intent.tx_body_hash,
    })
}

// ---------------------------------------------------------------------------
// Helper: slot conflict with admitted pool
// ---------------------------------------------------------------------------

fn check_slot_conflicts_with_pool(
    tx: &Transaction,
    admitted: &[Transaction],
) -> Result<(), SubmitError> {
    let mut pool_inputs: HashSet<u32> = HashSet::new();
    let mut pool_outputs: HashSet<u32> = HashSet::new();
    for t in admitted {
        for inp in &t.body.inputs {
            if inp.valid {
                pool_inputs.insert(inp.slot_index);
            }
        }
        for out in &t.body.outputs {
            if out.valid {
                pool_outputs.insert(out.slot_index);
            }
        }
    }
    for inp in &tx.body.inputs {
        if inp.valid && pool_inputs.contains(&inp.slot_index) {
            return Err(SubmitError::Consensus(
                noid_chain::consensus::ConsensusError::SlotConflict,
            ));
        }
    }
    for out in &tx.body.outputs {
        if out.valid && pool_outputs.contains(&out.slot_index) {
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
            return Err(SubmitError::Consensus(
                // Use BadStateRoot as a proxy for "input slot mismatch"
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
// Helper: ZK verify_logic (Phase 5)
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
