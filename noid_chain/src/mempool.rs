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
//!   2. [async] `verify_wallet_authorization()` — AuthGKR authorization verification (semaphore-bounded)
//!
//! When a block is confirmed: `on_block_confirmed()` removes confirmed txs
//! and returns reverted txs (from reorged blocks) to the pool.
//!
//! On an epoch boundary or reorg, `evict_wrong_anchor` removes every intent
//! that does not bind the chain's one current transaction-epoch anchor.

use std::collections::{BTreeMap, HashMap};

use noid_poseidon2b::primitives::{Digest, TxBodyHash};
use noid_tx::Transaction;

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
    /// Fee per weighted resource unit.
    ///
    /// The weight is `inputs + outputs + 4 × net_new_slots`, so transactions
    /// that grow live state are deprioritised versus state-shrinking
    /// transactions at similar fees.
    pub fee_rate: u64,

    /// Cached versioned `WalletAuthorizationBundle` bytes provided
    /// by the wallet at submission time.  Populated immediately on admission;
    /// `None` only for coinbase or txs submitted without a proof bundle.
    ///
    /// The block assembler copies this into the public `BlockAuthSidecar`;
    /// exact state-transition proving is built separately from the block body.
    pub cached_authorization: Option<Vec<u8>>,

    /// Raw `TxIntent` bytes as submitted by the wallet.
    /// Stored so the P2P mempool-sync protocol can re-serve existing TXs to
    /// newly connected peers (gossipsub deduplication prevents re-gossiping;
    /// a dedicated request-response exchange is the only reliable mechanism).
    pub intent_bytes: Vec<u8>,
}

impl MempoolEntry {
    /// Compute the fee_rate from the transaction body.
    pub fn compute_fee_rate(tx: &Transaction) -> u64 {
        let n_inputs = tx.body.live_input_count() as u64;
        let n_outputs = tx.body.live_output_count() as u64;
        let net_new_slots = n_outputs.saturating_sub(n_inputs);
        let weight = n_inputs
            .saturating_add(n_outputs)
            .saturating_add(net_new_slots.saturating_mul(4))
            .max(1);
        tx.body.fee / weight
    }

    /// Create a new entry.
    ///
    /// `current_height` — chain tip at admission time.
    pub fn new(tx: Transaction, current_height: u64) -> Self {
        let fee_rate = Self::compute_fee_rate(&tx);
        Self {
            tx,
            admitted_height: current_height,
            fee_rate,
            cached_authorization: None,
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
/// - No two live actions share any physical slot.
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
    pub fn admit(&mut self, tx: Transaction, current_height: u64) -> Result<(), MempoolError> {
        if self.entries.len() >= self.capacity {
            return Err(MempoolError::Full);
        }
        let hash = tx.txid();
        if self.entries.contains_key(&hash) {
            return Err(MempoolError::AlreadyAdmitted);
        }

        // Check input slot conflicts.
        for (_, inp) in tx.body.live_inputs() {
            if let Some(&existing) = self
                .spent_inputs
                .get(&inp.slot_index)
                .or_else(|| self.minted_outputs.get(&inp.slot_index))
            {
                return Err(MempoolError::InputConflict {
                    conflicting_hash: existing,
                });
            }
        }
        // Check output slot conflicts.
        for (_, out) in tx.body.live_outputs() {
            if let Some(&existing) = self
                .minted_outputs
                .get(&out.slot_index)
                .or_else(|| self.spent_inputs.get(&out.slot_index))
            {
                return Err(MempoolError::OutputConflict {
                    conflicting_hash: existing,
                });
            }
        }

        // All checks passed — insert.
        let entry = MempoolEntry::new(tx, current_height);
        let fee_key = FeeKey::new(entry.fee_rate, hash);
        for (_, inp) in entry.tx.body.live_inputs() {
            self.spent_inputs.insert(inp.slot_index, hash);
        }
        for (_, out) in entry.tx.body.live_outputs() {
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
        for (_, inp) in entry.tx.body.live_inputs() {
            self.spent_inputs.remove(&inp.slot_index);
        }
        for (_, out) in entry.tx.body.live_outputs() {
            self.minted_outputs.remove(&out.slot_index);
        }
        Some(entry)
    }

    /// Evict every user intent not bound to the chain's current exact anchor.
    pub fn evict_wrong_anchor(&mut self, current_anchor: &Digest) -> Vec<TxBodyHash> {
        let expired: Vec<TxBodyHash> = self
            .entries
            .iter()
            .filter(|(_, entry)| {
                !entry.tx.body.is_coinbase && &entry.tx.body.epoch_anchor != current_anchor
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
    /// `WalletAuthorizationBundle` bytes (from `TxIntent.authorization_bytes`).
    pub fn set_cached_authorization(&mut self, hash: &TxBodyHash, proof_bytes: Vec<u8>) {
        if let Some(entry) = self.entries.get_mut(hash) {
            entry.cached_authorization = Some(proof_bytes);
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
            .map(|e| e.tx.body.fee)
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
    use noid_tx::{
        output_bitmap_bit, Transaction, TxBody, TxInput, TxOutput, TX_INPUTS, TX_OUTPUTS,
    };

    fn tx(input_slot: u32, output_slot: u32, fee: u64, seed: u8, anchor: Digest) -> Transaction {
        let mut inputs = [TxInput::dummy(); TX_INPUTS];
        inputs[0] = TxInput {
            slot_index: input_slot,
            amount: 100 + fee,
            creation_id: 1,
        };
        let mut outputs = [TxOutput::dummy(); TX_OUTPUTS];
        outputs[0] = TxOutput {
            slot_index: output_slot,
            amount: 100,
            owner: Address([seed; 32]),
        };
        Transaction::new(TxBody {
            epoch_anchor: anchor,
            fee,
            input_owner: Address([seed; 32]),
            inputs,
            outputs,
            validity_bitmap: 1 | output_bitmap_bit(0),
            is_coinbase: false,
        })
    }

    #[test]
    fn derived_txid_keys_and_duplicate_admission() {
        let mut pool = Mempool::new(4);
        let tx = tx(1, 2, 10, 1, [9u8; 32]);
        let hash = tx.txid();
        pool.admit(tx.clone(), 3).unwrap();
        assert!(pool.contains(&hash));
        assert_eq!(pool.admit(tx, 3), Err(MempoolError::AlreadyAdmitted));
        assert_eq!(pool.remove(&hash).unwrap().tx.txid(), hash);
    }

    #[test]
    fn pending_set_is_fully_disjoint() {
        let mut pool = Mempool::new(8);
        pool.admit(tx(1, 2, 10, 1, [9u8; 32]), 3).unwrap();

        assert!(matches!(
            pool.admit(tx(1, 3, 10, 2, [9u8; 32]), 3),
            Err(MempoolError::InputConflict { .. })
        ));
        assert!(matches!(
            pool.admit(tx(4, 2, 10, 3, [9u8; 32]), 3),
            Err(MempoolError::OutputConflict { .. })
        ));
        assert!(matches!(
            pool.admit(tx(2, 5, 10, 4, [9u8; 32]), 3),
            Err(MempoolError::InputConflict { .. })
        ));
        assert!(matches!(
            pool.admit(tx(6, 1, 10, 5, [9u8; 32]), 3),
            Err(MempoolError::OutputConflict { .. })
        ));
    }

    #[test]
    fn epoch_switch_evicts_by_exact_anchor() {
        let mut pool = Mempool::new(8);
        let old = tx(1, 2, 10, 1, [7u8; 32]);
        let old_hash = old.txid();
        pool.admit(old, 3).unwrap();
        pool.admit(tx(3, 4, 10, 2, [8u8; 32]), 3).unwrap();

        let evicted = pool.evict_wrong_anchor(&[8u8; 32]);
        assert_eq!(evicted, vec![old_hash]);
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn fee_index_selects_highest_rate_first_and_capacity_holds() {
        let mut pool = Mempool::new(2);
        let low = tx(1, 2, 1, 1, [9u8; 32]);
        let high = tx(3, 4, 100, 2, [9u8; 32]);
        pool.admit(low, 0).unwrap();
        pool.admit(high.clone(), 0).unwrap();
        assert_eq!(pool.select_for_block(1)[0].tx.txid(), high.txid());
        assert_eq!(
            pool.admit(tx(5, 6, 10, 3, [9u8; 32]), 0),
            Err(MempoolError::Full)
        );
    }
}
