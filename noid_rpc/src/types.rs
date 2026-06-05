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
    /// 212-byte header_core as hex — the exact 212-byte buffer to hash.
    /// Patch bytes [144..160] (the nonce field, 16 bytes LE u128) to try each nonce.
    /// Valid nonce N satisfies: Blake3(patched_header_core) < difficulty_target.
    pub header_core_hex: String,
    /// Full sealed block bytes (hex) with nonce = 0.
    /// External miner: patch bytes at nonce_offset (144..160) with the found nonce
    /// and submit the result directly to `submitBlock`.
    /// No other fields need to change — the ZK proof is already embedded.
    pub block_hex: String,
    /// Byte offset of the nonce field inside `block_hex` (NOT inside `header_core_hex`).
    /// Always 144 bytes from the start of the block header (= start of block bytes).
    pub nonce_offset: usize,
    /// Difficulty target as 64-char little-endian hex. Find N such that Blake3(patched_header_core) < target.
    pub difficulty_target_hex: String,
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
    /// Actual fee paid in μNOID (useful when fee was computed automatically).
    pub fee_micronoid: u64,
}

/// Decoded block header (structured, not raw bytes).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockHeaderInfo {
    pub height: u64,
    /// H_BLOCK hash of this header (64-char hex).
    pub hash: String,
    /// H_BLOCK hash of the parent header.
    pub prev_hash: String,
    /// Poseidon2b Merkle root of UTXO state after this block.
    pub state_root: String,
    /// Poseidon2b Merkle root of transactions in this block.
    pub tx_root: String,
    /// Unix timestamp (seconds).
    pub timestamp: u64,
    /// Coinbase recipient address (bech32m).
    pub miner: String,
    /// Blake3 PoW difficulty target (64-char hex, LE).
    pub difficulty_target: String,
    /// Fiat-Shamir transcript digest of the ZK BlockProof.
    pub proof_transcript_hash: String,
    /// log₂ of total UTXO slot space capacity.
    pub log_slots: u32,
    /// Live UTXO count after this block.
    pub active_slot_count: u64,
    /// Monotonic PRNG seed for coinbase slot allocation.
    pub alloc_counter: u64,
}

/// Transaction location info (from the permanent tx index).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxInfo {
    /// Transaction body hash (64-char hex).
    pub tx_hash: String,
    /// Block height where this tx was confirmed.
    pub height: u64,
    /// H_BLOCK of the confirming block.
    pub block_hash: String,
    /// Zero-based position of the tx within the block.
    pub tx_position: u32,
}

/// Mining / network status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MiningInfo {
    /// Current tip height.
    pub height: u64,
    /// Number of leading zero bits in the current difficulty target.
    pub difficulty_bits: u32,
    /// Difficulty target as 64-char hex (LE 256-bit).
    pub difficulty_target: String,
    /// Block reward for the next block in μNOID.
    pub block_reward_micronoid: u64,
    /// Block reward in NOID.
    pub block_reward_noid: f64,
    /// Number of live UTXOs (determines reward via occupancy formula).
    pub active_slot_count: u64,
    /// Height covered by the latest recursive chain proof, if available.
    pub recursive_proof_height: Option<u64>,
}

/// Current UTXO state dimensions and fill metrics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateInfo {
    /// log₂ of total slot capacity. Capacity = 2^log_slots.
    pub log_slots: u32,
    /// Total slot space capacity (2^log_slots).
    pub capacity: u64,
    /// Live (non-zero) UTXOs.
    pub active_slots: u64,
    /// Fill percentage (active / capacity × 100), rounded to 2 decimal places.
    pub fill_pct: f64,
    /// Slots remaining before the 75% expansion trigger fires.
    /// Negative means the trigger has already fired (expansion pending).
    pub slots_until_expand: i64,
    /// Expansion trigger threshold in percent (always 75).
    pub expand_trigger_pct: u8,
    /// Maximum allowed log_slots (slot space cannot grow beyond 2^log_slots_max).
    pub log_slots_max: u32,
    /// Total on-disk segment size for the current state in bytes.
    /// Formula: capacity × 48 bytes/slot (value 16B + owner_hi 16B + owner_lo 16B).
    pub state_bytes: u64,
    /// Human-readable state size (e.g. "768.0 MB").
    pub state_size_human: String,
}

/// Result of `validateAddress`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressInfo {
    /// Whether the address is valid.
    pub valid: bool,
    /// Canonical bech32m form (`noid1…`).
    pub bech32: Option<String>,
    /// Raw 32-byte payload as hex.
    pub hex: Option<String>,
    /// Error message if invalid.
    pub error: Option<String>,
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
