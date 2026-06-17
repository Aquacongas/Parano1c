// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! WalletOps trait — interface between RPC layer and wallet implementation.
//!
//! Implemented by `WalletHandle` in `noid_node/src/wallet/mod.rs`.
//! `RpcHandler` holds `Arc<dyn WalletOps + Send + Sync>`.

use noid_chain::segmented_state::SegmentedFriState;

use crate::types::{
    WalletAddressInfo, WalletBalance, WalletHistoryEntry, WalletScanResult, WalletSendPlan,
    WalletStatus, WalletUtxoInfo,
};

pub trait WalletOps: Send + Sync {
    /// Overall wallet status (exists, address, balance).
    fn status(&self) -> WalletStatus;

    /// Derive the address at `index`. Returns None if wallet is not loaded.
    fn get_address(&self, index: u32) -> Option<String>;

    /// Primary address (index 0). Returns None if wallet is not loaded.
    fn primary_address(&self) -> Option<String>;

    /// Current confirmed balance.
    fn get_balance(&self) -> WalletBalance;

    /// All known UTXOs.
    fn list_utxos(&self) -> Vec<WalletUtxoInfo>;

    /// Transaction history (most recent last).
    fn history(&self) -> Vec<WalletHistoryEntry>;

    /// Full state scan: discover UTXOs owned by this wallet.
    /// Returns a scan summary after updating internal UTXO state.
    /// `state` is the current chain state (read under chain lock by caller).
    fn scan_state(&self, state: &SegmentedFriState, height: u64) -> WalletScanResult;

    /// Plan one logical payment as one or more transaction amounts using a fixed
    /// per-tx fee. Kept for legacy tests and simple callers.
    fn plan_send_splits(
        &self,
        amount_micronoid: u64,
        fee_per_tx_micronoid: u64,
    ) -> Result<Vec<u64>, String>;

    /// Shape-aware dry-run plan for one logical payment.
    ///
    /// `explicit_fee_micronoid = Some(fee)` applies that fee to every planned tx
    /// and rejects it if below the deterministic minimum for the resulting shape.
    /// `None` computes automatic per-chunk relay fee from actual planned
    /// input/output counts.
    fn plan_send(
        &self,
        amount_micronoid: u64,
        explicit_fee_micronoid: Option<u64>,
        active_slot_count: u64,
        log_slots: u32,
        relay_floor: u64,
    ) -> Result<WalletSendPlan, String>;

    /// Build, prove, and serialize a send transaction.
    ///
    /// Returns raw `TxIntent` bytes plus selected input slot indices ready for
    /// mempool submission. The caller must call `add_pending_inputs` only after
    /// successful mempool admission; otherwise retries can self-lock UTXOs.
    ///
    /// This is CPU-heavy (~0.3–3 s): caller must invoke in `spawn_blocking`.
    ///
    /// # Parameters
    /// - `to_address`: recipient 32-byte address
    /// - `amount_micronoid`: payment amount in μNOID
    /// - `fee_micronoid`: transaction fee in μNOID
    /// - `epoch_anchor`: current chain tip full-block hash (from `full_block_hash(tip)`)
    /// - `slot_hints`: 2–4 empty slot indices for outputs (from `get_slot_hints`)
    /// - `log_slots`: current chain `log_slots` (from `tip_header().log_slots`)
    fn build_send(
        &self,
        to_address: [u8; 32],
        amount_micronoid: u64,
        fee_micronoid: u64,
        epoch_anchor: [u8; 32],
        slot_hints: Vec<u32>,
        log_slots: u32,
    ) -> Result<(Vec<u8>, Vec<u32>), String>;

    /// Export a receipt for a past transaction as hex-encoded bytes.
    /// Returns `Err` if the tx is unknown or receipt was not generated
    /// (block already pruned when it was confirmed).
    fn export_receipt(&self, txhash_hex: &str) -> Result<String, String>;

    /// Return how many inputs the next consolidation round would select.
    ///
    /// This is lightweight planning used for shape-aware auto-fee calculation.
    /// It must skip pending input slots and cap at the largest supported wallet
    /// shape (`Sweep25x2`).
    fn plan_consolidate_input_count(&self) -> Result<usize, String>;

    /// Consolidate small UTXOs into one larger UTXO.
    ///
    /// Selects the smallest UTXOs (up to `Sweep25x2` capacity) and sends their
    /// combined value minus fee to the wallet's own primary address.
    ///
    /// Returns `(intent_bytes, input_slot_indices)` on success, or an error
    /// string if there is nothing to consolidate (e.g. only 1 UTXO, or
    /// insufficient funds).  The caller is responsible for calling
    /// `add_pending_inputs` with the returned slot indices **only after**
    /// the transaction is successfully submitted to the mempool, so that a
    /// failed submit does not permanently lock those UTXOs.
    ///
    /// This is CPU-heavy (~0.3–3 s): caller must invoke in `spawn_blocking`.
    fn build_consolidate(
        &self,
        fee_micronoid: u64,
        epoch_anchor: [u8; 32],
        slot_hints: Vec<u32>,
        log_slots: u32,
    ) -> Result<(Vec<u8>, Vec<u32>), String>;

    /// Mark input slot indices as pending (spent by a submitted but
    /// unconfirmed tx).  Prevents subsequent consolidation or send rounds
    /// from double-spending the same UTXOs before the first TX is confirmed.
    ///
    /// For `build_consolidate` this must be called by the RPC layer only
    /// after a successful `mempool.submit`.
    fn add_pending_inputs(&self, slots: &[u32]);

    /// Clear wallet-side pending output/history state for a send attempt that
    /// built successfully but failed mempool admission.
    fn cleanup_failed_send(&self, tx_hash: [u8; 32], output_slots: &[u32]);

    /// Derive and return the next unused address, advancing next_index.
    fn next_address(&self) -> Option<WalletAddressInfo>;

    /// List all addresses that have been used (have UTXOs or history),
    /// plus the next_index address if it's fresh.
    fn list_addresses(&self) -> Vec<WalletAddressInfo>;

    /// Sum of values of UTXOs currently being spent by pending txs.
    fn pending_outbound(&self) -> u64;
}
