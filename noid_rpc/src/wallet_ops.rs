// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! WalletOps trait — interface between RPC layer and wallet implementation.
//!
//! Implemented by `WalletHandle` in `noid_node/src/wallet/mod.rs`.
//! `RpcHandler` holds `Arc<dyn WalletOps + Send + Sync>`.

use std::collections::HashSet;

use noid_chain::block::Block;
use noid_chain::storage::VerifiedOwnerSnapshot;

use crate::types::{
    WalletAddressInfo, WalletBalance, WalletHistoryEntry, WalletScanResult, WalletSendPlan,
    WalletStatus, WalletUtxoInfo,
};

/// Immutable activation/reload intent captured under the wallet lock.
/// Commit rejects it if either wallet index changed before installation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletActivationPreview {
    pub expected_active_index: u32,
    pub expected_next_index: u32,
    pub target_index: u32,
    pub owner: [u8; 32],
    pub advance_next_index: bool,
}

pub trait WalletOps: Send + Sync {
    /// Overall wallet status (exists, address, balance).
    fn status(&self) -> WalletStatus;

    /// Derive the address at `index`. Returns None if wallet is not loaded.
    fn get_address(&self, index: u32) -> Option<String>;

    /// Current confirmed balance.
    fn get_balance(&self) -> WalletBalance;

    /// All known UTXOs.
    fn list_utxos(&self) -> Vec<WalletUtxoInfo>;

    /// Transaction history (most recent last).
    fn history(&self) -> Vec<WalletHistoryEntry>;

    /// Preview a reload of the current active address without mutation.
    fn preview_active_reload(&self) -> Result<WalletActivationPreview, String>;

    /// Preview switching to an already-generated address without mutation.
    fn preview_address_switch(&self, index: u32) -> Result<WalletActivationPreview, String>;

    /// Preview generating the next address without mutation.
    fn preview_next_address(&self) -> Result<WalletActivationPreview, String>;

    /// Atomically validate a preview, persist its indices, and install the
    /// exact durable owner snapshot while holding one wallet lock.
    fn commit_activation_snapshot(
        &self,
        preview: WalletActivationPreview,
        snapshot: VerifiedOwnerSnapshot,
        reserved_input_slots: &HashSet<u32>,
        reserved_output_slots: &HashSet<u32>,
    ) -> Result<(WalletAddressInfo, WalletScanResult), String>;

    /// Apply one accepted block to the active-address cache and wallet
    /// artifacts. The caller invokes this while it still holds the chain write
    /// guard, establishing the global `chain -> wallet` lock order.
    fn on_accepted_block(&self, block: &Block) -> Result<(), String>;

    /// Deterministically plan a logical payment as one or more ordinary
    /// canonical transactions. Every chunk uses at most eight active UTXOs.
    ///
    /// `explicit_fee_per_tx_micronoid = Some(fee)` applies that fee to every planned tx
    /// and rejects it if below the deterministic minimum for the resulting I/O.
    /// `None` computes the automatic relay fee independently for each chunk
    /// from its actual input/output counts.
    fn plan_send(
        &self,
        amount_micronoid: u64,
        explicit_fee_per_tx_micronoid: Option<u64>,
        active_slot_count: u64,
        log_slots: u32,
        relay_floor: u64,
    ) -> Result<WalletSendPlan, String>;

    /// Build, prove, and serialize a send transaction.
    ///
    /// Returns raw `TxIntent` bytes plus selected input slot indices. Building
    /// is side-effect free: the async coordinator installs the complete pending
    /// reservation only after `spawn_blocking` returns.
    ///
    /// This is CPU-heavy (~0.3–3 s): caller must invoke in `spawn_blocking`.
    ///
    /// # Parameters
    /// - `to_address`: recipient 32-byte address
    /// - `amount_micronoid`: payment amount in μNOID
    /// - `fee_micronoid`: transaction fee in μNOID
    /// - `epoch_anchor`: exact transaction-epoch anchor for the next block
    /// - `slot_hints`: one or two empty slot indices for outputs
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
    /// This is lightweight planning used for automatic fee calculation. It
    /// skips pending input slots and caps one round at eight inputs.
    fn plan_consolidate_input_count(&self) -> Result<usize, String>;

    /// Consolidate small UTXOs into one larger UTXO.
    ///
    /// Selects up to eight smallest UTXOs and sends their combined value minus
    /// fee to the active address as an ordinary transaction.
    ///
    /// Returns `(intent_bytes, input_slot_indices)` on success, or an error
    /// string if there is nothing to consolidate (e.g. only 1 UTXO, or
    /// insufficient funds). Building is side-effect free; the coordinator owns
    /// the pending reservation around normal mempool admission.
    ///
    /// This is CPU-heavy (~0.3–3 s): caller must invoke in `spawn_blocking`.
    fn build_consolidate(
        &self,
        fee_micronoid: u64,
        epoch_anchor: [u8; 32],
        slot_hints: Vec<u32>,
        log_slots: u32,
    ) -> Result<(Vec<u8>, Vec<u32>), String>;

    /// Atomically reserve every wallet-side artifact immediately before async
    /// mempool admission. The caller wraps this reservation in an owned rollback
    /// guard, so task cancellation cannot strand inputs, outputs, or history.
    fn reserve_pending_submission(
        &self,
        txid: [u8; 32],
        input_slots: &[u32],
        output_slots: &[u32],
        amount_micronoid: u64,
        peer_address: [u8; 32],
    ) -> Result<(), String>;

    /// Roll back the exact reservation installed above. Safe to call from Drop.
    fn rollback_pending_submission(
        &self,
        txid: [u8; 32],
        input_slots: &[u32],
        output_slots: &[u32],
    );

    /// The ACTIVE address (key index + bech32m): every send/consolidation
    /// spends this address's UTXOs only and change returns to it (one owner
    /// per transaction is a consensus rule).
    fn active_address(&self) -> Option<(u32, String)>;

    /// List locally generated address metadata. No inactive address is
    /// scanned and no per-address balances are synthesized.
    fn list_addresses(&self) -> Vec<WalletAddressInfo>;

    /// Sum of values of UTXOs currently being spent by pending txs.
    fn pending_outbound(&self) -> u64;
}
