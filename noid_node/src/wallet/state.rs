// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! In-memory wallet state.
//!
//! Simplified design (no passwords):
//! - On first start: generate random master secret, save to wallet.key
//! - On subsequent starts: load master secret from wallet.key
//! - Wallet is always "unlocked" once loaded (no lock/unlock cycle)
//! - UTXO state updated via state scan + incremental block updates

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use noid_poseidon2b::primitives::{Address, SpendSecret};

use super::keystore::{Keystore, KeystoreError, MasterSecret};

// ---------------------------------------------------------------------------
// TxHistoryEntry
// ---------------------------------------------------------------------------

/// Direction of a historical transaction relative to this wallet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxDirection {
    Sent,
    Received,
}

/// A record of a past transaction involving this wallet.
#[derive(Debug, Clone)]
pub struct TxHistoryEntry {
    /// Transaction body hash (32 bytes).
    pub tx_hash: [u8; 32],
    /// Block height at which this tx was confirmed.
    pub height: u64,
    /// Whether we sent or received in this tx.
    pub direction: TxDirection,
    /// Net amount in μNOID (sent: net sent, received: total received).
    pub amount_micronoid: u64,
    /// Counterparty address (None if unknown).
    pub peer_address: Option<[u8; 32]>,
    /// Block timestamp (Unix seconds).
    pub timestamp: u64,
}

// ---------------------------------------------------------------------------
// WalletUtxo
// ---------------------------------------------------------------------------

/// A single unspent output owned by this wallet.
#[derive(Debug, Clone)]
pub struct WalletUtxo {
    /// Global slot index in the chain state.
    pub slot_index: u32,
    /// Value in μNOID.
    pub value: u64,
    /// The 32-byte address that owns this slot.
    pub address: Address,
    /// Key index used to derive this address.
    pub key_index: u32,
    /// Block height at which this UTXO was confirmed.
    pub confirmed_height: u64,
}

// ---------------------------------------------------------------------------
// WalletState
// ---------------------------------------------------------------------------

/// Live in-memory wallet state.
///
/// The master secret is always loaded (no lock/unlock without passwords).
pub struct WalletState {
    /// Path to the key file on disk.
    pub keystore_path: PathBuf,
    /// Master secret (always present, loaded from disk at startup).
    secret: MasterSecret,
    /// All UTXOs owned by this wallet (slot_index → utxo).
    pub utxos: HashMap<u32, WalletUtxo>,
    /// Next unused key index.
    pub next_index: u32,
    /// All derived addresses: address bytes → key_index.
    pub known_addresses: HashMap<[u8; 32], u32>,
    /// Transaction history (most recent last).
    pub history: Vec<TxHistoryEntry>,
    /// Cached receipts: tx_body_hash → bincode-serialized ParanoidReceipt bytes.
    /// Generated automatically when a block is applied, before pruning.
    pub receipts: HashMap<[u8; 32], Vec<u8>>,
    /// Output slots claimed by pending (submitted but not yet confirmed) txs.
    /// Used to avoid SlotConflict when retrying or sending multiple txs.
    pub pending_output_slots: std::collections::HashSet<u32>,
    /// Input slots being spent by pending (submitted but not yet confirmed) txs.
    /// Used to avoid double-spending the same UTXO in consecutive consolidation
    /// or send rounds before the first TX is confirmed.
    pub pending_input_slots: std::collections::HashSet<u32>,
}

impl WalletState {
    /// Create or load the wallet from `key_path`.
    ///
    /// - If the file does not exist: generate a new random secret and save it.
    /// - If the file exists: load the existing secret.
    pub fn create_or_load(key_path: PathBuf) -> Result<Self, KeystoreError> {
        let ks = Keystore::new(&key_path);
        let secret = if ks.exists() {
            tracing::info!(path = %key_path.display(), "loading wallet");
            ks.load_plain()?
        } else {
            tracing::info!(path = %key_path.display(), "creating new wallet");
            ks.create_plain()?
        };

        // Pre-derive initial lookahead window of addresses.
        const INITIAL_LOOKAHEAD: u32 = 50;
        let mut known_addresses: HashMap<[u8; 32], u32> = HashMap::new();
        for i in 0..INITIAL_LOOKAHEAD {
            let addr = secret.derive_address(i);
            known_addresses.insert(addr.0, i);
        }

        let mut wallet = Self {
            keystore_path: key_path,
            secret,
            utxos: HashMap::new(),
            next_index: INITIAL_LOOKAHEAD,
            known_addresses,
            history: Vec::new(),
            receipts: HashMap::new(),
            pending_output_slots: std::collections::HashSet::new(),
            pending_input_slots: std::collections::HashSet::new(),
        };
        wallet.load_receipts();
        Ok(wallet)
    }

    /// Primary address (index 0).
    pub fn primary_address(&self) -> Address {
        self.secret.derive_address(0)
    }

    /// Address at a specific key index.
    pub fn address_at(&self, index: u32) -> Address {
        // Ensure we have it in known_addresses if needed.
        self.secret.derive_address(index)
    }

    /// Derive the next fresh address and advance next_index.
    /// Used by GUI wallet (Phase 10) for address rotation.
    #[allow(dead_code)]
    pub fn next_address(&mut self) -> (u32, Address) {
        let idx = self.next_index;
        let addr = self.secret.derive_address(idx);
        self.known_addresses.insert(addr.0, idx);
        self.next_index += 1;
        // Extend lookahead window.
        let top = self.next_index + 50;
        for i in self.next_index..top {
            let a = self.secret.derive_address(i);
            self.known_addresses.insert(a.0, i);
        }
        (idx, addr)
    }

    /// Spend secret for a specific key index.
    pub fn spend_secret_for(&self, key_index: u32) -> SpendSecret {
        self.secret.derive_spend_secret(key_index)
    }

    /// Total confirmed balance in μNOID.
    pub fn balance(&self) -> u64 {
        self.utxos
            .values()
            .map(|u| u.value)
            .fold(0u64, |a, v| a.saturating_add(v))
    }

    /// Check if a given address is owned by this wallet.
    /// Used by P2P address scanning and GUI wallet (Phase 10).
    #[allow(dead_code)]
    pub fn owns_address(&self, addr: &Address) -> Option<u32> {
        self.known_addresses.get(&addr.0).copied()
    }

    /// Replace all UTXOs with the result of a full state scan.
    pub fn apply_scan_results(
        &mut self,
        utxos: Vec<WalletUtxo>,
        new_addresses: HashMap<[u8; 32], u32>,
        next_index: u32,
    ) {
        self.utxos.clear();
        for utxo in utxos {
            self.utxos.insert(utxo.slot_index, utxo);
        }
        // Merge new addresses (don't overwrite existing).
        for (addr_bytes, idx) in new_addresses {
            self.known_addresses.entry(addr_bytes).or_insert(idx);
        }
        if next_index > self.next_index {
            self.next_index = next_index;
        }
        // Clear pending slot sets: the scan has replaced the UTXO set from
        // chain state, so any in-flight tracking is now stale.
        self.pending_output_slots.clear();
        self.pending_input_slots.clear();
    }

    /// Store a receipt for a confirmed transaction.
    /// Public API for external callers; scanner uses receipts map directly.
    #[allow(dead_code)]
    pub fn store_receipt(&mut self, tx_hash: [u8; 32], receipt_bytes: Vec<u8>) {
        self.receipts.insert(tx_hash, receipt_bytes);
    }

    /// Get a cached receipt by tx_body_hash.
    pub fn get_receipt(&self, tx_hash: &[u8; 32]) -> Option<&Vec<u8>> {
        self.receipts.get(tx_hash)
    }

    /// Clone the master secret so the wallet lock can be released before scanning.
    /// The cloned secret has the same ZeroizeOnDrop guarantee.
    pub fn secret_clone(&self) -> MasterSecret {
        MasterSecret(self.secret.0)
    }

    /// Record an outgoing send in history (height=0 until confirmed).
    pub fn record_pending_send(
        &mut self,
        tx_hash: [u8; 32],
        amount_micronoid: u64,
        to_address: [u8; 32],
    ) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.history.push(TxHistoryEntry {
            tx_hash,
            height: 0, // updated to real height when block is confirmed
            direction: TxDirection::Sent,
            amount_micronoid,
            peer_address: Some(to_address),
            timestamp: now,
        });
    }

    /// Update the height of a pending (height=0) tx once it's confirmed in a block.
    pub fn confirm_pending_tx(&mut self, tx_hash: &[u8; 32], confirmed_height: u64) {
        for entry in self.history.iter_mut() {
            if &entry.tx_hash == tx_hash && entry.height == 0 {
                entry.height = confirmed_height;
                break;
            }
        }
    }

    /// Register output slots as pending (tx submitted to mempool).
    /// Used to avoid SlotConflict when retrying or calling wallet_send concurrently.
    pub fn add_pending_outputs(&mut self, slot_indices: &[u32]) {
        for &slot in slot_indices {
            self.pending_output_slots.insert(slot);
        }
    }

    /// Clear pending output slots for a confirmed or evicted tx.
    pub fn remove_pending_outputs(&mut self, slot_indices: &[u32]) {
        for slot in slot_indices {
            self.pending_output_slots.remove(slot);
        }
    }

    /// Register input slots as pending (tx submitted to mempool).
    /// Used to prevent a subsequent round from double-spending the same UTXOs
    /// before the first TX is confirmed.
    pub fn add_pending_inputs(&mut self, slot_indices: &[u32]) {
        for &slot in slot_indices {
            self.pending_input_slots.insert(slot);
        }
    }

    /// Clear pending input slots for a confirmed or evicted tx.
    #[allow(dead_code)]
    pub fn remove_pending_inputs(&mut self, slot_indices: &[u32]) {
        for slot in slot_indices {
            self.pending_input_slots.remove(slot);
        }
    }

    /// Simple largest-first coin selection.
    /// Returns `(selected UTXOs, change_amount)` or `None` if insufficient funds.
    pub fn select_utxos(&self, target: u64, fee: u64) -> Option<(Vec<&WalletUtxo>, u64)> {
        let needed = target.saturating_add(fee);
        let mut available: Vec<&WalletUtxo> = self.utxos.values().collect();
        available.sort_by(|a, b| b.value.cmp(&a.value));

        let mut selected = Vec::new();
        let mut total = 0u64;
        for utxo in available {
            selected.push(utxo);
            total = total.saturating_add(utxo.value);
            if total >= needed {
                return Some((selected, total - needed));
            }
        }
        None
    }
}

// ---------------------------------------------------------------------------
// Receipt persistence
// ---------------------------------------------------------------------------

/// Path for the receipts file (JSON format, next to wallet key).
fn receipts_path(wallet_key_path: &Path) -> PathBuf {
    wallet_key_path.with_extension("receipts")
}

impl WalletState {
    /// Save receipts to disk. Called after each new receipt is generated.
    pub fn save_receipts(&self) {
        let path = receipts_path(&self.keystore_path);
        // Serialize as a map of hex_hash → hex_bytes
        let data: std::collections::HashMap<String, String> = self
            .receipts
            .iter()
            .map(|(k, v)| (hex::encode(k), hex::encode(v)))
            .collect();
        if let Ok(json) = serde_json::to_string(&data) {
            let tmp = path.with_extension("receipts.tmp");
            if std::fs::write(&tmp, json).is_ok() {
                let _ = std::fs::rename(&tmp, &path);
            }
        }
    }

    /// Load receipts from disk. Called at startup after create_or_load.
    pub fn load_receipts(&mut self) {
        let path = receipts_path(&self.keystore_path);
        if !path.exists() {
            return;
        }
        let text = match std::fs::read_to_string(&path) {
            Ok(t) => t,
            Err(_) => return,
        };
        if let Ok(data) = serde_json::from_str::<std::collections::HashMap<String, String>>(&text) {
            for (k_hex, v_hex) in data {
                if let (Ok(k), Ok(v)) = (hex::decode(&k_hex), hex::decode(&v_hex)) {
                    if k.len() == 32 {
                        let mut key = [0u8; 32];
                        key.copy_from_slice(&k);
                        self.receipts.insert(key, v);
                    }
                }
            }
            tracing::info!(count = self.receipts.len(), "loaded receipts from disk");
        }
    }
}

// ---------------------------------------------------------------------------
// Shared handle
// ---------------------------------------------------------------------------

/// Thread-safe shared wallet. `None` if wallet is not yet initialized.
pub type SharedWallet = Arc<Mutex<Option<WalletState>>>;
