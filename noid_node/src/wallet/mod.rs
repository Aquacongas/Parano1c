// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Built-in wallet for the `paranoid` daemon.
//!
//! The wallet lives inside the daemon process. `SpendSecret` is:
//! 1. Generated randomly on first start
//! 2. Stored on disk in plaintext format (no password required for full nodes)
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
    micronoid_to_noid, WalletAddressInfo, WalletBalance, WalletHistoryEntry, WalletScanResult,
    WalletStatus, WalletUtxoInfo,
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
                    address: w.primary_address().to_bech32(),
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
        guard.as_ref().map(|w| w.address_at(index).to_bech32())
    }

    fn primary_address(&self) -> Option<String> {
        let guard = self.inner.lock().unwrap();
        guard.as_ref().map(|w| w.primary_address().to_bech32())
    }

    fn get_balance(&self) -> WalletBalance {
        let guard = self.inner.lock().unwrap();
        match &*guard {
            None => WalletBalance {
                total_micronoid: 0,
                total_noid: 0.0,
                utxo_count: 0,
                pending_outbound_micronoid: 0,
                spendable_micronoid: 0,
                spendable_noid: 0.0,
            },
            Some(w) => {
                let total = w.balance();
                let pending_out: u64 = w
                    .pending_input_slots
                    .iter()
                    .filter_map(|&s| w.utxos.get(&s))
                    .map(|u| u.value)
                    .sum();
                let spendable = total.saturating_sub(pending_out);
                WalletBalance {
                    total_micronoid: total,
                    total_noid: micronoid_to_noid(total),
                    utxo_count: w.utxos.len(),
                    pending_outbound_micronoid: pending_out,
                    spendable_micronoid: spendable,
                    spendable_noid: micronoid_to_noid(spendable),
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
                    address: u.address.to_bech32(),
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
                    peer_address: h
                        .peer_address
                        .map(|a| noid_poseidon2b::primitives::Address(a).to_bech32()),
                    timestamp: h.timestamp,
                    own_address: h.own_address.clone(),
                    own_key_index: h.own_key_index,
                })
                .collect(),
        }
    }

    fn scan_state(&self, state: &SegmentedFriState, height: u64) -> WalletScanResult {
        // Extract master secret and hint_next_index (brief lock, then release).
        let (master, hint_next_index) = {
            let guard = self.inner.lock().unwrap();
            match &*guard {
                None => {
                    return WalletScanResult {
                        found_utxos: 0,
                        balance_micronoid: 0,
                        balance_noid: 0.0,
                        addresses_scanned: 0,
                        next_index: 0,
                    }
                }
                Some(w) => (w.secret_clone(), w.next_index),
            }
        };

        let (utxos, known_addresses, next_index) =
            scan_state_for_utxos(state, &master, height, hint_next_index);

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
            addresses_scanned: next_index,
            next_index,
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
        // Snapshot both pending_output_slots (avoid output reuse) AND
        // pending_input_slots (select_utxos already filters these, but we
        // capture the selected slots here so we can mark them pending below).
        let (build_data, input_slots) = {
            let guard = self.inner.lock().unwrap();
            let w = guard
                .as_ref()
                .ok_or_else(|| "wallet not initialized".to_string())?;
            let pending_outputs = w.pending_output_slots.clone();
            let data = builder::extract_build_data(
                w,
                amount_micronoid,
                fee_micronoid,
                epoch_anchor,
                slot_hints,
                log_slots,
                &pending_outputs,
            )
            .map_err(|e| e.to_string())?;
            // Capture input slots BEFORE build_data is moved into the prover.
            let inputs: Vec<u32> = data.selected_utxos.iter().map(|u| u.slot_index).collect();
            (data, inputs)
        };

        // Prove outside the lock (CPU-heavy, ~0.3–3 s).
        let (tx_hash, intent_bytes) =
            builder::build_and_prove_tx(to_address, amount_micronoid, fee_micronoid, build_data)
                .map_err(|e| e.to_string())?;

        // Register input AND output slots as pending, record the send.
        // Registering before returning ensures concurrent wallet_send calls
        // see claimed slots immediately — preventing SlotConflict on rapid
        // back-to-back sends even before any tx is confirmed.
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
                // Mark input slots as pending so the next wallet_send call's
                // select_utxos skips them (same fix as build_consolidate).
                w.add_pending_inputs(&input_slots);
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
    ) -> Result<(Vec<u8>, Vec<u32>), String> {
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

        // Register output slots as pending (brief lock).
        // Output slots: prevents concurrent TXs from targeting the same empty slot.
        // Input slots are intentionally NOT registered here — the caller
        // (wallet_consolidate in server.rs) must call add_pending_inputs only
        // after a successful mempool.submit.  Registering inputs before submit
        // would permanently lock UTXOs on a failed attempt, making every retry
        // unable to find inputs to consolidate (Bug #3).
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
            }
        }

        Ok((intent_bytes, input_slots))
    }

    fn add_pending_inputs(&self, slots: &[u32]) {
        let mut guard = self.inner.lock().unwrap();
        if let Some(w) = guard.as_mut() {
            w.add_pending_inputs(slots);
        }
    }

    fn next_address(&self) -> Option<WalletAddressInfo> {
        let mut guard = self.inner.lock().unwrap();
        let w = guard.as_mut()?;
        let idx = w.next_index;
        let addr = w.address_at(idx);
        // Register in known_addresses so incremental block updates catch payments to it.
        w.known_addresses.insert(addr.0, idx);
        w.next_index += 1;
        Some(WalletAddressInfo {
            address: addr.to_bech32(),
            key_index: idx,
            balance_micronoid: 0,
            balance_noid: 0.0,
            utxo_count: 0,
        })
    }

    fn list_addresses(&self) -> Vec<WalletAddressInfo> {
        let guard = self.inner.lock().unwrap();
        let w = match &*guard {
            None => return vec![],
            Some(w) => w,
        };

        // Build per-address balance and UTXO count from current UTXO set.
        let mut addr_balance: std::collections::HashMap<u32, (u64, usize)> =
            std::collections::HashMap::new();
        for utxo in w.utxos.values() {
            let e = addr_balance.entry(utxo.key_index).or_default();
            e.0 += utxo.value;
            e.1 += 1;
        }

        // Collect all key indices that have had any activity (UTXOs or history).
        let mut seen_indices: std::collections::BTreeSet<u32> = std::collections::BTreeSet::new();
        for utxo in w.utxos.values() {
            seen_indices.insert(utxo.key_index);
        }
        for entry in &w.history {
            if let Some(idx) = entry.own_key_index {
                seen_indices.insert(idx);
            }
        }
        // Always include index 0 (primary address).
        seen_indices.insert(0);

        let mut result: Vec<WalletAddressInfo> = seen_indices
            .iter()
            .map(|&idx| {
                let addr = w.address_at(idx);
                let (bal, count) = addr_balance.get(&idx).copied().unwrap_or((0, 0));
                WalletAddressInfo {
                    address: addr.to_bech32(),
                    key_index: idx,
                    balance_micronoid: bal,
                    balance_noid: micronoid_to_noid(bal),
                    utxo_count: count,
                }
            })
            .collect();

        // Append next_index as a fresh address if it hasn't appeared yet.
        if !seen_indices.contains(&w.next_index) {
            let addr = w.address_at(w.next_index);
            result.push(WalletAddressInfo {
                address: addr.to_bech32(),
                key_index: w.next_index,
                balance_micronoid: 0,
                balance_noid: 0.0,
                utxo_count: 0,
            });
        }

        result
    }

    fn pending_outbound(&self) -> u64 {
        let guard = self.inner.lock().unwrap();
        match &*guard {
            None => 0,
            Some(w) => w
                .pending_input_slots
                .iter()
                .filter_map(|&s| w.utxos.get(&s))
                .map(|u| u.value)
                .sum(),
        }
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
