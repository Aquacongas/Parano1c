// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Built-in wallet for the `paranoid` daemon.
//!
//! The wallet lives inside the daemon process. `SpendSecret` is:
//! 1. Generated randomly on first start
//! 2. Stored on disk in plaintext format (Phase 4 — no password required)
//! 3. Decrypted into memory at startup
//! 4. Zeroized from memory on daemon exit
//! 5. **NEVER transmitted over the network** — not in RPC responses,
//!    not in P2P messages, not in `TxIntent`
//!
//! Transaction flow (all inside the daemon):
//! ```text
//! wallet send(to, amount, fee) →
//!   1. select UTXOs from utxos map
//!   2. get slot hints from local chain state (empty slots for outputs)
//!   3. builder::build_and_prove_tx(...)
//!      a. compute tx_body_hash
//!      b. compute auth_tags = hash_auth_tag(spend_secret, tx_body_hash)
//!      c. prove_tx(body, secrets, log_slots) → WalletProofBundle
//!      d. assemble TxIntent bytes
//!   4. submit to own mempool
//! ```

pub mod builder;
pub mod keystore;
pub mod prover;
pub mod scanner;
pub mod state;

pub use state::{SharedWallet, WalletState};

// ---------------------------------------------------------------------------
// WalletHandle — implements WalletOps for RPC layer
// ---------------------------------------------------------------------------

use std::sync::Arc;

use noid_chain::segmented_state::SegmentedFriState;
use noid_rpc::types::{
    micronoid_to_noid, WalletBalance, WalletHistoryEntry, WalletScanResult, WalletStatus,
    WalletUtxoInfo,
};
use noid_rpc::WalletOps;

use crate::wallet::scanner::scan_state_for_utxos;

/// Thread-safe handle to the in-process wallet.
///
/// Implements `WalletOps` so `RpcHandler` can call wallet methods without
/// depending on noid_node types.
pub struct WalletHandle {
    pub inner: SharedWallet,
}

impl WalletHandle {
    pub fn new(inner: SharedWallet) -> Arc<dyn WalletOps + Send + Sync> {
        Arc::new(Self { inner })
    }
}

impl WalletOps for WalletHandle {
    fn status(&self) -> WalletStatus {
        let guard = self.inner.lock().unwrap();
        match &*guard {
            None => WalletStatus {
                exists: false,
                address: String::new(),
                balance_micronoid: 0,
                balance_noid: 0.0,
                utxo_count: 0,
                address_count: 0,
            },
            Some(w) => {
                let balance = w.balance();
                WalletStatus {
                    exists: true,
                    address: hex::encode(w.primary_address().0),
                    balance_micronoid: balance,
                    balance_noid: micronoid_to_noid(balance),
                    utxo_count: w.utxos.len(),
                    address_count: w.next_index,
                }
            }
        }
    }

    fn get_address(&self, index: u32) -> Option<String> {
        let guard = self.inner.lock().unwrap();
        guard.as_ref().map(|w| hex::encode(w.address_at(index).0))
    }

    fn primary_address(&self) -> Option<String> {
        let guard = self.inner.lock().unwrap();
        guard.as_ref().map(|w| hex::encode(w.primary_address().0))
    }

    fn get_balance(&self) -> WalletBalance {
        let guard = self.inner.lock().unwrap();
        match &*guard {
            None => WalletBalance {
                total_micronoid: 0,
                total_noid: 0.0,
                utxo_count: 0,
            },
            Some(w) => {
                let total = w.balance();
                WalletBalance {
                    total_micronoid: total,
                    total_noid: micronoid_to_noid(total),
                    utxo_count: w.utxos.len(),
                }
            }
        }
    }

    fn list_utxos(&self) -> Vec<WalletUtxoInfo> {
        let guard = self.inner.lock().unwrap();
        match &*guard {
            None => vec![],
            Some(w) => w
                .utxos
                .values()
                .map(|u| WalletUtxoInfo {
                    slot_index: u.slot_index,
                    value_micronoid: u.value,
                    value_noid: micronoid_to_noid(u.value),
                    address: hex::encode(u.address.0),
                    key_index: u.key_index,
                    confirmed_height: u.confirmed_height,
                })
                .collect(),
        }
    }

    fn history(&self) -> Vec<WalletHistoryEntry> {
        let guard = self.inner.lock().unwrap();
        match &*guard {
            None => vec![],
            Some(w) => w
                .history
                .iter()
                .map(|h| WalletHistoryEntry {
                    tx_hash: hex::encode(h.tx_hash),
                    height: h.height,
                    direction: match h.direction {
                        state::TxDirection::Sent => "sent".into(),
                        state::TxDirection::Received => "received".into(),
                    },
                    amount_micronoid: h.amount_micronoid,
                    amount_noid: micronoid_to_noid(h.amount_micronoid),
                    peer_address: h.peer_address.map(hex::encode),
                    timestamp: h.timestamp,
                })
                .collect(),
        }
    }

    fn scan_state(&self, state: &SegmentedFriState, height: u64) -> WalletScanResult {
        // Extract master secret (brief lock, then release).
        let master = {
            let guard = self.inner.lock().unwrap();
            match &*guard {
                None => {
                    return WalletScanResult {
                        found_utxos: 0,
                        balance_micronoid: 0,
                        balance_noid: 0.0,
                    }
                }
                Some(w) => w.secret_clone(),
            }
        };

        let (utxos, known_addresses, next_index) = scan_state_for_utxos(state, &master, height);

        let found = utxos.len();
        let balance: u64 = utxos.iter().map(|u| u.value).sum();

        // Apply results under lock.
        let mut guard = self.inner.lock().unwrap();
        if let Some(w) = guard.as_mut() {
            w.apply_scan_results(utxos, known_addresses, next_index);
        }

        WalletScanResult {
            found_utxos: found,
            balance_micronoid: balance,
            balance_noid: micronoid_to_noid(balance),
        }
    }

    fn build_send(
        &self,
        to_address: [u8; 32],
        amount_micronoid: u64,
        fee_micronoid: u64,
        epoch_anchor: [u8; 32],
        slot_hints: Vec<u32>,
        log_slots: u32,
    ) -> Result<Vec<u8>, String> {
        // Extract build data from wallet (brief lock).
        // Also snapshot pending_output_slots so the prover can avoid re-using them.
        let build_data = {
            let guard = self.inner.lock().unwrap();
            let w = guard
                .as_ref()
                .ok_or_else(|| "wallet not initialized".to_string())?;
            let pending_slots = w.pending_output_slots.clone();
            builder::extract_build_data(
                w,
                amount_micronoid,
                fee_micronoid,
                epoch_anchor,
                slot_hints,
                log_slots,
                &pending_slots,
            )
            .map_err(|e| e.to_string())?
        };

        // Prove outside the lock (CPU-heavy, ~0.3–3 s).
        let (tx_hash, intent_bytes) =
            builder::build_and_prove_tx(to_address, amount_micronoid, fee_micronoid, build_data)
                .map_err(|e| e.to_string())?;

        // Register output slots as pending & record pending send (brief lock).
        // Registering before returning ensures concurrent calls see claimed slots.
        {
            let intent = noid_tx::TxIntent::from_bytes(&intent_bytes)
                .map_err(|e| format!("decode: {e:?}"))?;
            let output_slots: Vec<u32> = intent
                .tx_body
                .outputs
                .iter()
                .filter(|o| o.valid)
                .map(|o| o.slot_index)
                .collect();
            let mut guard = self.inner.lock().unwrap();
            if let Some(w) = guard.as_mut() {
                w.add_pending_outputs(&output_slots);
                w.record_pending_send(tx_hash, amount_micronoid, to_address);
            }
        }

        Ok(intent_bytes)
    }

    fn build_consolidate(
        &self,
        fee_micronoid: u64,
        epoch_anchor: [u8; 32],
        slot_hints: Vec<u32>,
        log_slots: u32,
    ) -> Result<Vec<u8>, String> {
        // Extract consolidation build data from wallet (brief lock).
        let (build_data, consolidation_amount) = {
            let guard = self.inner.lock().unwrap();
            let w = guard
                .as_ref()
                .ok_or_else(|| "wallet not initialized".to_string())?;
            let pending_output_slots = w.pending_output_slots.clone();
            let pending_input_slots = w.pending_input_slots.clone();
            builder::extract_consolidate_data(
                w,
                fee_micronoid,
                epoch_anchor,
                slot_hints,
                log_slots,
                &pending_output_slots,
                &pending_input_slots,
            )
            .map_err(|e| e.to_string())?
        };

        // Capture input slots before build_data is moved into the prover.
        let input_slots: Vec<u32> = build_data
            .selected_utxos
            .iter()
            .map(|u| u.slot_index)
            .collect();

        // Self-address: send consolidated amount to own primary address.
        let self_address = {
            let guard = self.inner.lock().unwrap();
            guard
                .as_ref()
                .ok_or_else(|| "wallet not initialized".to_string())?
                .primary_address()
                .0
        };

        // Prove outside the lock (CPU-heavy).
        let (_tx_hash, intent_bytes) = builder::build_and_prove_tx(
            self_address,
            consolidation_amount,
            fee_micronoid,
            build_data,
        )
        .map_err(|e| e.to_string())?;

        // Register output and input slots as pending (brief lock).
        // Output slots: prevents concurrent TXs from targeting the same empty slot.
        // Input slots: prevents the next consolidation round from double-spending
        //              the same UTXOs before this TX is confirmed.
        {
            let intent = noid_tx::TxIntent::from_bytes(&intent_bytes)
                .map_err(|e| format!("decode: {e:?}"))?;
            let output_slots: Vec<u32> = intent
                .tx_body
                .outputs
                .iter()
                .filter(|o| o.valid)
                .map(|o| o.slot_index)
                .collect();
            let mut guard = self.inner.lock().unwrap();
            if let Some(w) = guard.as_mut() {
                w.add_pending_outputs(&output_slots);
                w.add_pending_inputs(&input_slots);
            }
        }

        Ok(intent_bytes)
    }

    fn export_receipt(&self, txhash_hex: &str) -> Result<String, String> {
        let tx_hash: [u8; 32] = hex::decode(txhash_hex)
            .map_err(|e| format!("invalid hex: {e}"))?
            .try_into()
            .map_err(|_| "tx_hash must be 32 bytes".to_string())?;

        let guard = self.inner.lock().unwrap();
        let w = guard
            .as_ref()
            .ok_or_else(|| "wallet not initialized".to_string())?;

        match w.get_receipt(&tx_hash) {
            Some(bytes) => Ok(hex::encode(bytes)),
            None => Err(format!(
                "no receipt for {txhash_hex} — block already pruned or tx not found"
            )),
        }
    }
}
