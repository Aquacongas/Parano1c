// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.
//! JSON response types for the Paranoid RPC API.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Chain types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainInfo {
    pub height: u64,
    pub best_hash: String,
    pub difficulty_target: String,
    pub active_slot_count: u64,
    pub log_slots: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlotInfo {
    pub slot_index: u32,
    pub value: u64,
    pub owner: String,
    pub empty: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptVerifyResult {
    pub merkle_valid: bool,
    pub canonical: bool,
    pub confirmed: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockTemplateResponse {
    /// 212-byte header_core as hex (PoW input for external miner).
    pub header_core_hex: String,
    pub height: u64,
    pub n_txs: usize,
}

// ---------------------------------------------------------------------------
// Wallet types
// ---------------------------------------------------------------------------

/// Overall wallet status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletStatus {
    /// Whether a wallet file exists.
    pub exists: bool,
    /// Primary address (index 0) as 64-char hex, or empty string.
    pub address: String,
    /// Total confirmed balance in μNOID.
    pub balance_micronoid: u64,
    /// Balance in NOID (6 decimal places).
    pub balance_noid: f64,
    /// Number of confirmed UTXOs.
    pub utxo_count: usize,
    /// Number of derived addresses.
    pub address_count: u32,
}

/// Balance breakdown.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletBalance {
    pub total_micronoid: u64,
    pub total_noid: f64,
    pub utxo_count: usize,
}

/// Info about a single UTXO.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletUtxoInfo {
    pub slot_index: u32,
    pub value_micronoid: u64,
    pub value_noid: f64,
    pub address: String,
    pub key_index: u32,
    pub confirmed_height: u64,
}

/// A historical transaction entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletHistoryEntry {
    pub tx_hash: String,
    pub height: u64,
    pub direction: String, // "sent" or "received"
    pub amount_micronoid: u64,
    pub amount_noid: f64,
    pub peer_address: Option<String>,
    pub timestamp: u64,
}

/// Result of a full state scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletScanResult {
    pub found_utxos: usize,
    pub balance_micronoid: u64,
    pub balance_noid: f64,
}

/// Result of a send operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletSendResult {
    /// Transaction body hash (hex).
    pub tx_hash: String,
}

// ---------------------------------------------------------------------------
// Conversion helpers
// ---------------------------------------------------------------------------

/// Convert μNOID to NOID with 6 decimal places.
#[inline]
pub fn micronoid_to_noid(micronoid: u64) -> f64 {
    micronoid as f64 / 1_000_000.0
}

// ---------------------------------------------------------------------------
// Mempool types
// ---------------------------------------------------------------------------

/// Information about a single pending transaction in the mempool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MempoolTxInfo {
    /// Transaction body hash (hex).
    pub tx_hash: String,
    /// Fee in μNOID.
    pub fee_micronoid: u64,
    /// Fee rate (fee / max(1, n_inputs + n_outputs)).
    pub fee_rate: u64,
    /// Number of live inputs.
    pub n_inputs: usize,
    /// Number of live outputs.
    pub n_outputs: usize,
    /// Chain height at admission.
    pub admitted_height: u64,
    /// Whether a ZK proof bundle is cached (wallet proof attached).
    pub has_proof: bool,
}

/// Summary of the current mempool state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MempoolInfo {
    /// Number of pending transactions.
    pub size: usize,
    /// Current dynamic fee floor in μNOID.
    pub fee_floor: u64,
    /// All pending transactions.
    pub txs: Vec<MempoolTxInfo>,
}
