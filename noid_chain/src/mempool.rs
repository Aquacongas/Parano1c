// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! In-memory mempool for admitted transactions.
//!
//! `Mempool` is a pure data structure with no I/O, no async, no networking.
//! `AsyncMempool` in `noid_mempool` wraps this in async admission/eviction tasks and connects it to the
//! P2P layer and the block template builder.
//!
//! # Design
//!
//! Admission pipeline (cheapest first):
//!   1. `validate_tx_for_mempool()` — native checks (~0ms)
//!   2. [async] `verify_logic()` — ZK verification (~84ms, semaphore-bounded)
//!
//! When a block is confirmed: `on_block_confirmed()` removes confirmed txs
//! and returns reverted txs (from reorged blocks) to the pool.
//!
//! Eviction: `evict_expired(height)` removes txs whose epoch_anchor has
//! expired (anchor block is more than ANCHOR_DEPTH blocks old).

use std::collections::{BTreeMap, HashMap};

use noid_poseidon2b::primitives::TxBodyHash;
use noid_tx::{Transaction, ANCHOR_DEPTH};

use crate::consensus::params::BLOCK_MAX_TXS;

// ---------------------------------------------------------------------------
// Fee-priority key for BTreeMap index
// ---------------------------------------------------------------------------

/// Ordering key for the fee-priority BTreeMap index.
///
/// BTreeMap iterates in ascending key order, so we use descending fee_rate
/// (via `u64::MAX - fee_rate`) and ascending tx_body_hash as tie-break.
/// This gives us the highest-fee tx at the front of iteration.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct FeeKey {
    /// `u64::MAX - fee_rate`: sorts higher fee_rate to lower BTreeMap key.
    neg_fee_rate: u64,
    /// Ascending tx_body_hash: deterministic tie-break.
    hash: [u8; 32],
}

impl FeeKey {
    fn new(fee_rate: u64, hash: TxBodyHash) -> Self {
        Self {
            neg_fee_rate: u64::MAX - fee_rate,
            hash: hash.0,
        }
    }
}

// ---------------------------------------------------------------------------
// MempoolEntry
// ---------------------------------------------------------------------------

/// A transaction admitted to the mempool.
#[derive(Debug, Clone)]
pub struct MempoolEntry {
    /// The admitted transaction.
    pub tx: Transaction,
    /// Chain height at the time of admission.
    pub admitted_height: u64,
    /// Height of the block referenced by `tx.body.epoch_anchor`.
    ///
    /// The transaction expires when `current_height > anchor_height + ANCHOR_DEPTH`.
    /// This is the correct expiry condition: the tx is valid as long as the anchor
    /// block is within the rolling ANCHOR_DEPTH window.
    ///
    /// `u64::MAX` for coinbase (no anchor, never expires via this mechanism).
    pub anchor_height: u64,
    /// Fee per weighted resource unit.
    ///
    /// The weight is `inputs + outputs + 4 × net_new_slots`, so transactions
    /// that grow live state are deprioritised versus consolidation at similar fees.
    pub fee_rate: u64,

    /// Cached `WalletProofBundle` bytes (LogicProof + auth_slices) provided
    /// by the wallet at submission time.  Populated immediately on admission;
    /// `None` only for coinbase or txs submitted without a proof bundle.
    ///
    /// The block assembler uses this to build `TxBlockWitness` without
    /// re-doing any per-tx work.  `prove_block` then only runs the unified
    /// block-level SpineGKR + single FRI opening.
    pub cached_algebraic_proof: Option<Vec<u8>>,

    /// Raw `TxIntent` bytes as submitted by the wallet.
    /// Stored so the P2P mempool-sync protocol can re-serve existing TXs to
    /// newly connected peers (gossipsub deduplication prevents re-gossiping;
    /// a dedicated request-response exchange is the only reliable mechanism).
    pub intent_bytes: Vec<u8>,
}

impl MempoolEntry {
    /// Compute the fee_rate from the transaction body.
    pub fn compute_fee_rate(tx: &Transaction) -> u64 {
        let n_inputs = tx.body.inputs.iter().filter(|i| i.valid).count() as u64;
        let n_outputs = tx.body.outputs.iter().filter(|o| o.valid).count() as u64;
        let net_new_slots = n_outputs.saturating_sub(n_inputs);
        let weight = n_inputs
            .saturating_add(n_outputs)
            .saturating_add(net_new_slots.saturating_mul(4))
            .max(1);
        (tx.body.fee.min(u64::MAX as u128) as u64) / weight
    }

    /// Create a new entry.
    ///
    /// `current_height` — chain tip at admission time.
    /// `anchor_height` — height of the block whose hash is `tx.body.epoch_anchor`;
    ///   pass `u64::MAX` for coinbase transactions (no anchor).
    pub fn new(tx: Transaction, current_height: u64, anchor_height: u64) -> Self {
        let fee_rate = Self::compute_fee_rate(&tx);
        Self {
            tx,
            admitted_height: current_height,
            anchor_height,
            fee_rate,
            cached_algebraic_proof: None,
            intent_bytes: Vec::new(), // populated by AsyncMempool::submit
        }
    }
}

// ---------------------------------------------------------------------------
// MempoolError
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MempoolError {
    /// Transaction already in the pool.
    AlreadyAdmitted,
    /// Input slot conflict with an already-admitted transaction.
    InputConflict { conflicting_hash: TxBodyHash },
    /// Output slot conflict with an already-admitted transaction.
    OutputConflict { conflicting_hash: TxBodyHash },
    /// Pool is at capacity.
    Full,
}

// ---------------------------------------------------------------------------
// Mempool
// ---------------------------------------------------------------------------

/// In-memory mempool: a conflict-free set of admitted transactions.
///
/// Invariants maintained:
/// - No two txs share an input slot (no double-spend within pool).
/// - No two txs share an output slot (no double-mint within pool).
/// - `fee_index` is always in sync with `entries`.
///
/// # Block selection performance
///
/// `fee_index: BTreeMap<FeeKey, TxBodyHash>` gives O(max_txs) iteration for
/// `select_for_block` instead of O(N log N) sort over all entries.
/// At N=8192, BTreeMap is ~8192x faster for a 1-tx block, and equivalent for
/// a 1024-tx full block (both O(N)). In both cases no allocation occurs.
pub struct Mempool {
    /// Admitted entries, indexed by tx_body_hash.
    entries: HashMap<TxBodyHash, MempoolEntry>,
    /// Fee-priority index: sorted by (desc fee_rate, asc tx_body_hash).
    /// Always in sync with `entries`: insert on `admit`, remove on `remove`.
    fee_index: BTreeMap<FeeKey, TxBodyHash>,
    /// Input slot -> tx_body_hash of the tx that spends it.
    spent_inputs: HashMap<u32, TxBodyHash>,
    /// Output slot -> tx_body_hash of the tx that mints it.
    minted_outputs: HashMap<u32, TxBodyHash>,
    /// Maximum number of entries.
    capacity: usize,
}

impl Mempool {
    /// Create a new empty mempool with the given capacity.
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: HashMap::with_capacity(capacity.min(4096)),
            fee_index: BTreeMap::new(),
            spent_inputs: HashMap::new(),
            minted_outputs: HashMap::new(),
            capacity,
        }
    }

    /// Default capacity = BLOCK_MAX_TXS * 8 (8 blocks worth of txs).
    pub fn with_default_capacity() -> Self {
        Self::new(BLOCK_MAX_TXS * 8)
    }

    /// Number of transactions currently in the pool.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True if the pool contains no transactions.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// True if the pool contains a transaction with the given hash.
    pub fn contains(&self, hash: &TxBodyHash) -> bool {
        self.entries.contains_key(hash)
    }

    /// Get an entry by tx_body_hash. O(1) HashMap lookup.
    pub fn get(&self, hash: &TxBodyHash) -> Option<&MempoolEntry> {
        self.entries.get(hash)
    }

    /// Attempt to add a transaction to the pool.
    ///
    /// Does NOT call `validate_tx_for_mempool()` — the caller is responsible
    /// for pre-validation. This function only checks pool-internal constraints
    /// (capacity, duplicates, slot conflicts with already-admitted txs).
    ///
    /// `anchor_height` — height of the block referenced by `tx.body.epoch_anchor`
    /// (already found by the caller during epoch-anchor validation). Used for
    /// precise expiry: `evict_expired` evicts when `current_height > anchor_height + ANCHOR_DEPTH`.
    /// Pass `u64::MAX` for coinbase transactions.
    pub fn admit(
        &mut self,
        tx: Transaction,
        current_height: u64,
        anchor_height: u64,
    ) -> Result<(), MempoolError> {
        if self.entries.len() >= self.capacity {
            return Err(MempoolError::Full);
        }
        if self.entries.contains_key(&tx.tx_body_hash) {
            return Err(MempoolError::AlreadyAdmitted);
        }

        // Check input slot conflicts.
        for inp in tx.body.inputs.iter().filter(|i| i.valid) {
            if let Some(&existing) = self.spent_inputs.get(&inp.slot_index) {
                return Err(MempoolError::InputConflict {
                    conflicting_hash: existing,
                });
            }
        }
        // Check output slot conflicts.
        for out in tx.body.outputs.iter().filter(|o| o.valid) {
            if let Some(&existing) = self.minted_outputs.get(&out.slot_index) {
                return Err(MempoolError::OutputConflict {
                    conflicting_hash: existing,
                });
            }
        }

        // All checks passed — insert.
        let hash = tx.tx_body_hash;
        let entry = MempoolEntry::new(tx, current_height, anchor_height);
        let fee_key = FeeKey::new(entry.fee_rate, hash);
        for inp in entry.tx.body.inputs.iter().filter(|i| i.valid) {
            self.spent_inputs.insert(inp.slot_index, hash);
        }
        for out in entry.tx.body.outputs.iter().filter(|o| o.valid) {
            self.minted_outputs.insert(out.slot_index, hash);
        }
        self.fee_index.insert(fee_key, hash);
        self.entries.insert(hash, entry);
        Ok(())
    }

    /// Remove a transaction by hash. Returns the removed entry, or `None`.
    pub fn remove(&mut self, hash: &TxBodyHash) -> Option<MempoolEntry> {
        let entry = self.entries.remove(hash)?;
        // Remove from fee_index using the same key that was inserted.
        self.fee_index.remove(&FeeKey::new(entry.fee_rate, *hash));
        for inp in entry.tx.body.inputs.iter().filter(|i| i.valid) {
            self.spent_inputs.remove(&inp.slot_index);
        }
        for out in entry.tx.body.outputs.iter().filter(|o| o.valid) {
            self.minted_outputs.remove(&out.slot_index);
        }
        Some(entry)
    }

    /// Evict transactions whose epoch_anchor has expired.
    ///
    /// A transaction is valid while:
    ///   `current_height <= anchor_height + ANCHOR_DEPTH`
    ///
    /// where `anchor_height` is the chain height of the block referenced by
    /// `tx.body.epoch_anchor` (stored at admission time). This is the
    /// **correct** expiry: the tx expires when its anchor block exits the
    /// rolling ANCHOR_DEPTH window, not based on when the tx was admitted.
    ///
    /// Returns the hashes of evicted transactions (wallets must rebuild).
    pub fn evict_expired(&mut self, current_height: u64) -> Vec<TxBodyHash> {
        let expired: Vec<TxBodyHash> = self
            .entries
            .iter()
            .filter(|(_, e)| {
                // anchor_height == u64::MAX for coinbase — never expires this way.
                e.anchor_height != u64::MAX
                    && current_height > e.anchor_height.saturating_add(ANCHOR_DEPTH)
            })
            .map(|(&h, _)| h)
            .collect();
        for hash in &expired {
            self.remove(hash);
        }
        expired
    }

    /// Select up to `max_txs` transactions for block assembly.
    ///
    /// Returns entries in descending fee_rate order (highest fees first),
    /// with ascending tx_body_hash as a deterministic tie-break.
    ///
    /// Does NOT include coinbase (caller adds it separately).
    /// Does NOT resolve cross-tx slot conflicts — the caller must call
    /// `resolve_slot_conflicts()` on the result.
    ///
    /// # Performance
    ///
    /// O(max_txs × log N) using the `fee_index` BTreeMap instead of
    /// the previous O(N log N) sort-all. At N=8192 and max_txs=1023:
    /// ~1023 BTreeMap lookups (~10K operations) vs ~107K comparisons.
    pub fn select_for_block(&self, max_txs: usize) -> Vec<&MempoolEntry> {
        self.fee_index
            .values()
            .take(max_txs)
            .filter_map(|hash| self.entries.get(hash))
            .collect()
    }

    /// Update the pool after a block is confirmed or after a reorg.
    ///
    /// - `confirmed`: tx_body_hashes that were included in the confirmed block.
    ///   These are removed from the pool (already applied to state).
    ///
    /// - `reverted`: tx_body_hashes from REORGED blocks that should be returned
    ///   to the pool (their state changes were undone). The caller is responsible
    ///   for re-validating these txs against the new chain state before re-admitting.
    ///   This function only removes confirmed; reverted txs must be re-admitted via `admit()`.
    ///
    /// Returns the number of transactions removed.
    pub fn on_block_confirmed(&mut self, confirmed: &[TxBodyHash]) -> usize {
        let mut removed = 0;
        for hash in confirmed {
            if self.remove(hash).is_some() {
                removed += 1;
            }
        }
        removed
    }

    /// Iterate over all entries (no guaranteed order).
    pub fn iter(&self) -> impl Iterator<Item = (&TxBodyHash, &MempoolEntry)> {
        self.entries.iter()
    }

    /// Store cached proof bytes for an admitted transaction.
    /// Called by the async mempool after admission to attach the wallet's
    /// `WalletProofBundle` bytes (from `TxIntent.logic_proof_bytes`).
    pub fn set_cached_proof(&mut self, hash: &TxBodyHash, proof_bytes: Vec<u8>) {
        if let Some(entry) = self.entries.get_mut(hash) {
            entry.cached_algebraic_proof = Some(proof_bytes);
        }
    }

    /// Store raw TxIntent bytes for mempool-sync serving.
    pub fn set_intent_bytes(&mut self, hash: &TxBodyHash, bytes: Vec<u8>) {
        if let Some(entry) = self.entries.get_mut(hash) {
            entry.intent_bytes = bytes;
        }
    }

    /// All intent_bytes for all pending transactions (for mempool sync).
    pub fn all_intent_bytes(&self) -> Vec<Vec<u8>> {
        self.entries
            .values()
            .filter(|e| !e.intent_bytes.is_empty())
            .map(|e| e.intent_bytes.clone())
            .collect()
    }

    /// Total serialized TxIntent bytes retained by this mempool.
    pub fn total_intent_bytes(&self) -> usize {
        self.entries.values().map(|e| e.intent_bytes.len()).sum()
    }

    /// Total fees available in the pool (useful for coinbase computation).
    pub fn total_fees(&self) -> u64 {
        self.entries
            .values()
            .filter(|e| !e.tx.body.is_coinbase)
            .map(|e| e.tx.body.fee.min(u64::MAX as u128) as u64)
            .fold(0u64, |a, f| a.saturating_add(f))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use noid_poseidon2b::primitives::Address;
    use noid_tx::{hash_tx_body, Transaction, TxBody, TxOutput};

    fn make_tx(slot: u32, fee: u128, seed: u8) -> Transaction {
        let body = TxBody {
            shape: noid_tx::TxShape::Standard4x8,
            epoch_anchor: [seed; 32],
            fee,
            inputs: vec![],
            outputs: vec![TxOutput {
                slot_index: slot,
                value: 100,
                owner: Address([seed; 32]),
                valid: true,
            }],
            is_coinbase: false,
        };
        let hash = hash_tx_body(
            &body.epoch_anchor,
            body.fee,
            &body.inputs,
            &body.outputs,
            body.is_coinbase,
        );
        Transaction {
            body,
            tx_body_hash: hash,
        }
    }

    // Helper: anchor_height = current_height - 1 (tx anchored one block ago)
    fn admit_with_anchor(mp: &mut Mempool, tx: Transaction, current_height: u64) {
        let anchor_h = current_height.saturating_sub(1);
        mp.admit(tx, current_height, anchor_h).unwrap();
    }

    #[test]
    fn admit_and_lookup() {
        let mut mp = Mempool::new(100);
        let tx = make_tx(1, 5000, 1);
        let hash = tx.tx_body_hash;
        admit_with_anchor(&mut mp, tx, 10);
        assert!(mp.contains(&hash));
        assert_eq!(mp.len(), 1);
    }

    #[test]
    fn duplicate_rejected() {
        let mut mp = Mempool::new(100);
        let tx = make_tx(1, 5000, 1);
        admit_with_anchor(&mut mp, tx.clone(), 10);
        assert_eq!(mp.admit(tx, 10, 9), Err(MempoolError::AlreadyAdmitted));
    }

    #[test]
    fn output_slot_conflict_rejected() {
        let mut mp = Mempool::new(100);
        admit_with_anchor(&mut mp, make_tx(5, 5000, 1), 10);
        let conflict_result = mp.admit(make_tx(5, 6000, 2), 10, 9);
        assert!(matches!(
            conflict_result,
            Err(MempoolError::OutputConflict { .. })
        ));
    }

    #[test]
    fn on_block_confirmed_removes_txs() {
        let mut mp = Mempool::new(100);
        let tx1 = make_tx(1, 5000, 1);
        let tx2 = make_tx(2, 6000, 2);
        let h1 = tx1.tx_body_hash;
        let h2 = tx2.tx_body_hash;
        admit_with_anchor(&mut mp, tx1, 10);
        admit_with_anchor(&mut mp, tx2, 10);
        let removed = mp.on_block_confirmed(&[h1]);
        assert_eq!(removed, 1);
        assert!(!mp.contains(&h1));
        assert!(mp.contains(&h2));
    }

    #[test]
    fn evict_expired_removes_old_txs() {
        let mut mp = Mempool::new(100);
        let tx = make_tx(1, 5000, 1);
        let hash = tx.tx_body_hash;
        // anchor_height = 5, admitted at height 10
        mp.admit(tx, 10, 5).unwrap();
        // Not expired yet: current = 5 + ANCHOR_DEPTH (boundary, inclusive)
        assert_eq!(mp.evict_expired(5 + ANCHOR_DEPTH).len(), 0);
        assert!(mp.contains(&hash));
        // Expired: current = 5 + ANCHOR_DEPTH + 1
        let evicted = mp.evict_expired(5 + ANCHOR_DEPTH + 1);
        assert_eq!(evicted.len(), 1);
        assert!(!mp.contains(&hash));
    }

    #[test]
    fn select_for_block_orders_by_fee_rate() {
        let mut mp = Mempool::new(100);
        admit_with_anchor(&mut mp, make_tx(1, 1000, 1), 0);
        admit_with_anchor(&mut mp, make_tx(2, 9000, 2), 0);
        admit_with_anchor(&mut mp, make_tx(3, 3000, 3), 0);
        let selected = mp.select_for_block(10);
        let fees: Vec<u64> = selected.iter().map(|e| e.fee_rate).collect();
        for i in 0..fees.len() - 1 {
            assert!(fees[i] >= fees[i + 1]);
        }
    }

    #[test]
    fn capacity_enforced() {
        let mut mp = Mempool::new(2);
        admit_with_anchor(&mut mp, make_tx(1, 100, 1), 0);
        admit_with_anchor(&mut mp, make_tx(2, 100, 2), 0);
        assert_eq!(mp.admit(make_tx(3, 100, 3), 0, 0), Err(MempoolError::Full));
    }

    #[test]
    fn total_fees_sums_non_coinbase() {
        let mut mp = Mempool::new(100);
        admit_with_anchor(&mut mp, make_tx(1, 5_000, 1), 0);
        admit_with_anchor(&mut mp, make_tx(2, 3_000, 2), 0);
        assert_eq!(mp.total_fees(), 8_000);
    }
}
