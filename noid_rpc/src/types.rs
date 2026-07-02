// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.
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
    /// Fixed 16-field Poseidon2b PoW input as hex.
    /// Each field is serialized as 16 little-endian bytes. Patch field 10
    /// with the LE u128 nonce. A valid nonce satisfies:
    /// `Poseidon2b(POWHDR__, patched_fields) < difficulty_target`.
    pub pow_fields_hex: String,
    /// Full sealed block bytes (hex) with nonce = 0.
    /// External miner: patch bytes at nonce_offset (144..160) with the found nonce.
    pub block_hex: String,
    /// Serialized BlockProof bytes as hex. Empty for coinbase-only blocks.
    /// Submit this alongside `block_hex` to `submitBlock`.
    pub block_proof_hex: String,
    /// Serialized BlockAuthSidecar bytes as hex. Empty for coinbase-only blocks.
    /// Submit this alongside `block_hex` and `block_proof_hex` to `submitBlock`.
    #[serde(default)]
    pub block_auth_sidecar_hex: String,
    /// Byte offset of the nonce field inside `block_hex`.
    /// Always 144 bytes from the start of the block header (= start of block bytes).
    pub nonce_offset: usize,
    /// Difficulty target as 64-char little-endian hex.
    pub difficulty_target_hex: String,
    pub height: u64,
    /// Total transaction count including coinbase.
    pub n_txs: usize,
    /// User transaction shapes in canonical block order (coinbase excluded).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tx_shapes: Vec<String>,
    /// Number of `Standard4x8` user transactions in the template.
    pub standard_tx_count: usize,
    /// Number of `Sweep25x2` user transactions in the template.
    pub sweep_tx_count: usize,
    /// Live input counts per user transaction, index-aligned with `tx_shapes`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tx_input_counts: Vec<usize>,
    /// Live output counts per user transaction, index-aligned with `tx_shapes`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tx_output_counts: Vec<usize>,
    /// Coinbase output value in μNOID.
    pub coinbase_value_micronoid: u64,
    /// Sum of user fees claimable by the miner after burned state-growth fees.
    pub claimable_fees_micronoid: u64,
    /// Whether the template carries a serialized proof to submit with the block.
    pub has_block_proof: bool,
    /// Serialized BlockProof size in bytes (`0` for coinbase-only templates).
    pub block_proof_size_bytes: usize,
}

// ---------------------------------------------------------------------------
// Wallet types
// ---------------------------------------------------------------------------

/// Info about a single derived wallet address.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletAddressInfo {
    /// Bech32m address string.
    pub address: String,
    /// HD derivation index (0 = primary).
    pub key_index: u32,
    /// Confirmed balance in μNOID across all UTXOs at this address.
    pub balance_micronoid: u64,
    /// Balance in NOID.
    pub balance_noid: f64,
    /// Number of confirmed UTXOs at this address.
    pub utxo_count: usize,
}

/// Overall wallet status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletStatus {
    /// Whether a wallet file exists.
    pub exists: bool,
    /// Primary address (index 0) as bech32m, or empty string.
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
    /// Confirmed UTXOs being spent by pending (mempool) txs.
    /// These are locked and cannot be spent again until confirmed or evicted.
    pub pending_outbound_micronoid: u64,
    /// Spendable = total - pending_outbound.
    pub spendable_micronoid: u64,
    pub spendable_noid: f64,
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
    /// Which of our own addresses was involved (received-to or sent-from address).
    pub own_address: Option<String>,
    /// Key index of the own address.
    pub own_key_index: Option<u32>,
}

/// Result of a full state scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletScanResult {
    pub found_utxos: usize,
    pub balance_micronoid: u64,
    pub balance_noid: f64,
    /// Total addresses derived during this scan.
    pub addresses_scanned: u32,
    /// Next available key index after scan (use for address --new).
    pub next_index: u32,
}

/// Detailed deterministic fee calculation exposed over RPC.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeBreakdownInfo {
    /// Fixed per-transaction anti-DoS component.
    pub base: u64,
    /// Small anti-DoS/prover-work component for live inputs.
    pub input: u64,
    /// Output component for created live UTXOs.
    pub output: u64,
    /// Aggregate input + output component.
    pub io: u64,
    /// Burned state-growth component for net-new live slots.
    pub state_growth: u64,
    /// Consensus-required minimum before relay floor.
    pub required_total: u64,
    /// Current relay/mempool floor applied by this node.
    pub relay_floor: u64,
    /// Required amount accepted by this node: max(required_total, relay_floor).
    pub relay_total: u64,
    /// Actual fee this estimate/transaction pays. For estimates this equals
    /// `relay_total`; for no-change wallet transactions it can be higher and
    /// the excess is a miner tip.
    pub paid_total: u64,
    /// Portion burned by consensus.
    pub burned: u64,
    /// Miner-claimable portion at `paid_total`.
    pub miner_claimable: u64,
}

/// Shape-aware fee estimate for explicit live input/output counts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeEstimate {
    pub shape: String,
    pub n_inputs: usize,
    pub n_outputs: usize,
    pub net_new_slots: u64,
    pub active_slot_count: u64,
    pub log_slots: u32,
    pub fee_micronoid: u64,
    pub breakdown: FeeBreakdownInfo,
}

/// One planned transaction in a logical wallet send.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletSendChunkPlan {
    pub chunk_index: usize,
    pub amount_micronoid: u64,
    pub shape: String,
    pub selected_input_count: usize,
    pub output_count: usize,
    pub expected_change_micronoid: u64,
    pub fee_micronoid: u64,
    pub fee_breakdown: FeeBreakdownInfo,
}

/// Dry-run plan for a logical wallet send.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletSendPlan {
    pub amount_micronoid: u64,
    pub total_fee_micronoid: u64,
    pub total_spend_micronoid: u64,
    pub split_count: usize,
    pub chunks: Vec<WalletSendChunkPlan>,
}

/// Dry-run plan for one consolidation transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletConsolidatePlan {
    pub shape: String,
    pub selected_input_count: usize,
    pub output_count: usize,
    pub fee_micronoid: u64,
    pub expected_utxo_reduction: usize,
    pub fee_breakdown: FeeBreakdownInfo,
}

/// Result of a send operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletSendResult {
    /// Primary transaction body hash (hex). For split payments this is the first
    /// submitted transaction, kept for backwards-compatible clients.
    pub tx_hash: String,
    /// Total fee paid in μNOID across all submitted transactions.
    pub fee_micronoid: u64,
    /// All transaction body hashes for this logical payment. Single-transaction
    /// sends contain one hash; auto-split sends contain multiple hashes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tx_hashes: Vec<String>,
    /// Number of transactions used for this logical wallet send.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub split_count: Option<usize>,
    /// Shape of the primary transaction (`Standard4x8` or `Sweep25x2`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shape: Option<String>,
    /// Shape per submitted transaction, index-aligned with `tx_hashes`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tx_shapes: Vec<String>,
    /// Live input count per submitted transaction, index-aligned with `tx_hashes`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tx_input_counts: Vec<usize>,
    /// Live output count per submitted transaction, index-aligned with `tx_hashes`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tx_output_counts: Vec<usize>,
    /// Fee per submitted transaction, index-aligned with `tx_hashes`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tx_fees_micronoid: Vec<u64>,
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
    /// Poseidon2b PoW difficulty target (64-char hex, LE).
    pub difficulty_target: String,
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
    /// Height covered by the latest promoted checkpoint proof package, if available.
    pub checkpoint_proof_height: Option<u64>,
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
    /// Canonical bech32m form (`o1…`).
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
    /// Transaction shape (`Standard4x8` or `Sweep25x2`).
    pub shape: String,
    /// Fee in μNOID.
    pub fee_micronoid: u64,
    /// Fee rate using weighted resource units (`inputs + outputs + 4 × net_new_slots`).
    pub fee_rate: u64,
    /// Number of live inputs.
    pub n_inputs: usize,
    /// Number of live outputs.
    pub n_outputs: usize,
    /// Chain height at admission.
    pub admitted_height: u64,
    /// Whether a wallet authorization bundle is cached.
    pub has_authorization: bool,
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
