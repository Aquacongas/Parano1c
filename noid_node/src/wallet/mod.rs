// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

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
use noid_tx::TxShape;

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

    fn plan_send_splits(
        &self,
        amount_micronoid: u64,
        fee_per_tx_micronoid: u64,
    ) -> Result<Vec<u64>, String> {
        if amount_micronoid == 0 {
            return Err("amount cannot be zero".to_string());
        }

        let guard = self.inner.lock().unwrap();
        let w = guard
            .as_ref()
            .ok_or_else(|| "wallet not initialized".to_string())?;

        let mut available: Vec<&state::WalletUtxo> = w
            .utxos
            .values()
            .filter(|u| !w.pending_input_slots.contains(&u.slot_index))
            .collect();
        available.sort_by(|a, b| b.value.cmp(&a.value));

        let spendable: u64 = available.iter().map(|u| u.value).sum();
        let mut cursor = 0usize;
        let mut remaining = amount_micronoid;
        let mut chunks = Vec::new();

        while remaining > 0 {
            let mut selected_value = 0u64;
            let mut selected_inputs = 0usize;

            while cursor < available.len()
                && selected_inputs < TxShape::Sweep25x2.max_inputs()
                && selected_value < remaining.saturating_add(fee_per_tx_micronoid)
            {
                selected_value = selected_value.saturating_add(available[cursor].value);
                cursor += 1;
                selected_inputs += 1;
            }

            if selected_inputs == 0 || selected_value <= fee_per_tx_micronoid {
                let planned_fees = fee_per_tx_micronoid.saturating_mul(chunks.len() as u64 + 1);
                return Err(format!(
                    "insufficient funds: need at least {} μNOID including split fees, have {} μNOID spendable",
                    amount_micronoid.saturating_add(planned_fees),
                    spendable
                ));
            }

            let max_payment = selected_value - fee_per_tx_micronoid;
            let chunk = max_payment.min(remaining);
            chunks.push(chunk);
            remaining -= chunk;
        }

        Ok(chunks)
    }

    fn build_send(
        &self,
        to_address: [u8; 32],
        amount_micronoid: u64,
        fee_micronoid: u64,
        epoch_anchor: [u8; 32],
        slot_hints: Vec<u32>,
        log_slots: u32,
    ) -> Result<(Vec<u8>, Vec<u32>), String> {
        // Extract build data from wallet (brief lock).
        // Snapshot pending_output_slots (avoid output reuse). Input slots are
        // returned to the RPC layer and marked pending only after successful
        // mempool admission, so failed submit retries cannot self-lock UTXOs.
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

        // Register output slots as pending immediately to avoid output-slot reuse
        // during retries/concurrent sends. Inputs are intentionally NOT marked
        // here; the RPC layer marks them only after mempool.submit succeeds.
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

        Ok((intent_bytes, input_slots))
    }

    fn plan_consolidate_input_count(&self) -> Result<usize, String> {
        let guard = self.inner.lock().unwrap();
        let w = guard
            .as_ref()
            .ok_or_else(|| "wallet not initialized".to_string())?;
        let available = w
            .utxos
            .values()
            .filter(|u| !w.pending_input_slots.contains(&u.slot_index))
            .count();
        if available < 2 {
            return Err(
                "nothing to consolidate — wallet has 1 or fewer available UTXOs".to_string(),
            );
        }
        Ok(available.min(TxShape::Sweep25x2.max_inputs()))
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

    fn cleanup_failed_send(&self, tx_hash: [u8; 32], output_slots: &[u32]) {
        let mut guard = self.inner.lock().unwrap();
        if let Some(w) = guard.as_mut() {
            w.remove_pending_outputs(output_slots);
            w.remove_pending_send(&tx_hash);
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
        w.save_metadata();
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use tempfile::TempDir;

    fn handle_with_utxos(values: &[u64]) -> (TempDir, WalletHandle) {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("wallet.key");
        let mut wallet = WalletState::create_or_load(path).unwrap();
        for (i, value) in values.iter().copied().enumerate() {
            let key_index = i as u32;
            wallet.utxos.insert(
                key_index,
                state::WalletUtxo {
                    slot_index: key_index,
                    value,
                    address: wallet.address_at(key_index),
                    key_index,
                    confirmed_height: 1,
                },
            );
        }
        let handle = WalletHandle {
            inner: Arc::new(Mutex::new(Some(wallet))),
        };
        (dir, handle)
    }

    #[test]
    fn planner_uses_one_sweep_sized_chunk_for_20_inputs() {
        let (_dir, handle) = handle_with_utxos(&vec![1_000; 20]);
        let chunks = handle.plan_send_splits(19_500, 500).unwrap();
        assert_eq!(chunks, vec![19_500]);
    }

    #[test]
    fn planner_splits_after_25_inputs() {
        let (_dir, handle) = handle_with_utxos(&vec![1_000; 26]);
        let chunks = handle.plan_send_splits(25_000, 500).unwrap();
        assert_eq!(chunks, vec![24_500, 500]);
    }

    #[test]
    fn planner_excludes_pending_inputs_from_spendable_balance() {
        let (_dir, handle) = handle_with_utxos(&[10_000, 1_000, 1_000, 1_000, 1_000]);
        {
            let mut guard = handle.inner.lock().unwrap();
            guard.as_mut().unwrap().pending_input_slots.insert(0);
        }
        let err = handle.plan_send_splits(9_000, 500).unwrap_err();
        assert!(err.contains("insufficient funds"));
        assert!(err.contains("4000 μNOID spendable"));
    }

    #[test]
    fn sweep_sized_send_selects_more_than_four_inputs() {
        let (_dir, handle) = handle_with_utxos(&vec![50_000_000; 8]);
        let amount = 200_000_001;
        let fee = 18_500;
        let chunks = handle.plan_send_splits(amount, fee).unwrap();
        assert_eq!(chunks, vec![amount]);

        let guard = handle.inner.lock().unwrap();
        let wallet = guard.as_ref().unwrap();
        let (selected, change) = wallet.select_utxos(amount, fee).expect("select UTXOs");
        assert_eq!(selected.len(), 5);
        assert_eq!(change, 49_981_499);
    }

    #[test]
    fn consolidate_planner_caps_at_sweep_capacity() {
        let (_dir, handle) = handle_with_utxos(&vec![1_000; 30]);
        assert_eq!(handle.plan_consolidate_input_count().unwrap(), 25);
    }

    #[test]
    fn consolidate_planner_skips_pending_inputs() {
        let (_dir, handle) = handle_with_utxos(&vec![1_000; 6]);
        {
            let mut guard = handle.inner.lock().unwrap();
            guard.as_mut().unwrap().pending_input_slots.insert(0);
            guard.as_mut().unwrap().pending_input_slots.insert(1);
        }
        assert_eq!(handle.plan_consolidate_input_count().unwrap(), 4);
    }

    fn extract_consolidate_shape(values: &[u64]) -> (TxShape, usize, u64) {
        let (_dir, handle) = handle_with_utxos(values);
        let guard = handle.inner.lock().unwrap();
        let wallet = guard.as_ref().unwrap();
        let pending_outputs = wallet.pending_output_slots.clone();
        let pending_inputs = wallet.pending_input_slots.clone();
        let (data, amount) = builder::extract_consolidate_data(
            wallet,
            10,
            [0xAA; 32],
            vec![10_000],
            24,
            &pending_outputs,
            &pending_inputs,
        )
        .unwrap();
        (data.shape, data.selected_utxos.len(), amount)
    }

    #[test]
    fn consolidate_four_inputs_uses_standard_shape() {
        let (shape, selected, amount) = extract_consolidate_shape(&vec![1_000; 4]);
        assert_eq!(shape, TxShape::Standard4x8);
        assert_eq!(selected, 4);
        assert_eq!(amount, 3_990);
    }

    #[test]
    fn consolidate_five_inputs_uses_sweep_shape() {
        let (shape, selected, amount) = extract_consolidate_shape(&vec![1_000; 5]);
        assert_eq!(shape, TxShape::Sweep25x2);
        assert_eq!(selected, 5);
        assert_eq!(amount, 4_990);
    }

    #[test]
    fn consolidate_twenty_five_inputs_uses_sweep_shape() {
        let (shape, selected, amount) = extract_consolidate_shape(&vec![1_000; 30]);
        assert_eq!(shape, TxShape::Sweep25x2);
        assert_eq!(selected, 25);
        assert_eq!(amount, 24_990);
    }

    #[test]
    fn consolidate_rejects_one_available_utxo() {
        let (_dir, handle) = handle_with_utxos(&[1_000]);
        let err = handle.plan_consolidate_input_count().unwrap_err();
        assert!(err.contains("nothing to consolidate"));
    }
}
