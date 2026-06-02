// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! WalletOps trait — interface between RPC layer and wallet implementation.
//!
//! Implemented by `WalletHandle` in `noid_node/src/wallet/mod.rs`.
//! `RpcHandler` holds `Arc<dyn WalletOps + Send + Sync>`.

use noid_chain::segmented_state::SegmentedFriState;

use crate::types::{
    WalletBalance, WalletHistoryEntry, WalletScanResult, WalletStatus, WalletUtxoInfo,
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

    /// Build, prove, and serialize a send transaction.
    ///
    /// Returns raw `TxIntent` bytes ready for mempool submission.
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
    ) -> Result<Vec<u8>, String>;

    /// Export a receipt for a past transaction as hex-encoded bytes.
    /// Returns `Err` if the tx is unknown or receipt was not generated
    /// (block already pruned when it was confirmed).
    fn export_receipt(&self, txhash_hex: &str) -> Result<String, String>;
}
