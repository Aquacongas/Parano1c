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
//!      b. prove_tx(body, secrets) → WalletAuthorizationBundle
//!      c. assemble TxIntent bytes
//!   4. submit to own mempool
//! ```

pub mod builder;
pub mod keystore;
pub mod prover;
pub mod scanner;
pub mod state;

pub use state::{SharedWallet, WalletState};

#[cfg(test)]
use state::MAX_WALLET_ADDRESSES;

// ---------------------------------------------------------------------------
// WalletHandle — implements WalletOps for RPC layer
// ---------------------------------------------------------------------------

use std::sync::Arc;

use noid_chain::storage::VerifiedOwnerSnapshot;
use noid_rpc::types::{
    micronoid_to_noid, FeeBreakdownInfo, WalletAddressInfo, WalletBalance, WalletHistoryEntry,
    WalletScanResult, WalletSendChunkPlan, WalletSendPlan, WalletStatus, WalletUtxoInfo,
};
use noid_rpc::wallet_ops::WalletActivationPreview;
use noid_rpc::WalletOps;
use noid_tx::TxShape;

/// Thread-safe handle to the in-process wallet.
///
/// Implements `WalletOps` so `RpcHandler` can call wallet methods without
/// depending on noid_node types.
pub struct WalletHandle {
    pub inner: SharedWallet,
}

impl WalletHandle {
    #[allow(clippy::new_ret_no_self)]
    pub fn new(inner: SharedWallet) -> Arc<dyn WalletOps + Send + Sync> {
        Arc::new(Self { inner })
    }
}

/// Apply one already-committed block while the caller still holds the chain
/// write guard. This is the only incremental active-wallet update path; keeping
/// the lock order `chain -> wallet` prevents account activation from installing
/// a newer snapshot and then receiving an older block delta.
pub fn update_for_accepted_block(
    wallet: &SharedWallet,
    block: &noid_chain::block::Block,
) -> Result<(), String> {
    let mut guard = wallet
        .lock()
        .map_err(|_| "wallet state lock is poisoned".to_string())?;
    let Some(wallet) = guard.as_mut() else {
        return Ok(());
    };

    let active_address = wallet.active_address();
    let active_index = wallet.active_index;
    scanner::update_active_wallet_from_block(
        &mut wallet.utxos,
        &mut wallet.history,
        &mut wallet.receipts,
        active_address,
        active_index,
        &mut wallet.pending_input_slots,
        block,
    )?;
    wallet.active_snapshot = Some(state::ActiveWalletSnapshot {
        height: block.header.height,
        tip_hash: noid_chain::consensus::pow::block_id(&block.header),
        state_root: block.header.state_root,
        log_slots: block.header.log_slots,
        active_slot_count: block.header.active_slot_count,
        alloc_counter: block.header.alloc_counter,
    });

    for tx in &block.transactions {
        wallet.confirm_pending_tx(&tx.tx_body_hash.0, block.header.height);
        let output_slots: Vec<u32> = tx
            .body
            .outputs
            .iter()
            .filter(|output| output.valid)
            .map(|output| output.slot_index)
            .collect();
        wallet.remove_pending_outputs(&output_slots);
    }
    wallet.save_history();
    if !wallet.receipts.is_empty() {
        wallet.save_receipts();
    }
    Ok(())
}

/// Install the one exact post-reorg active-owner snapshot, then derive only
/// history/receipt artifacts from replacement block bodies. No replacement
/// block is ever replayed onto the old-branch UTXO cache.
#[allow(clippy::too_many_arguments)]
pub fn install_reorg_snapshot_and_artifacts(
    wallet: &SharedWallet,
    expected_active_index: u32,
    expected_next_index: u32,
    owner: [u8; 32],
    snapshot: VerifiedOwnerSnapshot,
    reserved_input_slots: &std::collections::HashSet<u32>,
    reserved_output_slots: &std::collections::HashSet<u32>,
    reclaimed_tx_hashes: &[noid_poseidon2b::primitives::TxBodyHash],
    replacement_blocks: &[noid_chain::block::Block],
) -> Result<(), String> {
    let mut guard = wallet
        .lock()
        .map_err(|_| "wallet state lock is poisoned".to_string())?;
    let Some(wallet) = guard.as_mut() else {
        return Ok(());
    };

    wallet.commit_verified_activation(
        expected_active_index,
        expected_next_index,
        expected_active_index,
        false,
        owner,
        snapshot,
        reserved_input_slots,
        reserved_output_slots,
    )?;

    let reclaimed: std::collections::HashSet<[u8; 32]> =
        reclaimed_tx_hashes.iter().map(|hash| hash.0).collect();
    // Receipts commit to the orphaned block header and transaction position.
    // Remove every reclaimed receipt before replay; a transaction that also
    // appears on the replacement branch gets a fresh canonical receipt below.
    for tx_hash in &reclaimed {
        wallet.receipts.remove(tx_hash);
    }
    let replacement: std::collections::HashSet<[u8; 32]> = replacement_blocks
        .iter()
        .flat_map(|block| block.transactions.iter())
        .map(|transaction| transaction.tx_body_hash.0)
        .collect();
    wallet.history.retain_mut(|entry| {
        if !reclaimed.contains(&entry.tx_hash) {
            return true;
        }
        if replacement.contains(&entry.tx_hash) && entry.direction == state::TxDirection::Sent {
            // Preserve the local source-account tag so the replacement-chain
            // confirmation can produce a receipt at its new height.
            entry.height = 0;
            return true;
        }
        false
    });

    let active_address = wallet.active_address();
    let active_index = wallet.active_index;
    for block in replacement_blocks {
        scanner::update_wallet_artifacts_from_block(
            &mut wallet.history,
            &mut wallet.receipts,
            active_address,
            active_index,
            block,
        );
        for transaction in &block.transactions {
            wallet.confirm_pending_tx(&transaction.tx_body_hash.0, block.header.height);
            let output_slots: Vec<u32> = transaction
                .body
                .outputs
                .iter()
                .filter(|output| output.valid)
                .map(|output| output.slot_index)
                .collect();
            wallet.remove_pending_outputs(&output_slots);
        }
    }
    wallet.save_history();
    // Persist even the empty map: otherwise removing the last orphan-bound
    // receipt in RAM would leave its old file to resurrect after restart.
    wallet.save_receipts();
    Ok(())
}

/// Fail closed if an exact owner snapshot cannot be installed after a chain
/// replacement. A later verified reload restores the cache.
pub fn invalidate_active_cache(wallet: &SharedWallet) {
    let Ok(mut guard) = wallet.lock() else {
        return;
    };
    if let Some(wallet) = guard.as_mut() {
        wallet.utxos.clear();
        wallet.pending_input_slots.clear();
        wallet.active_snapshot = None;
    }
}

fn fee_breakdown_info(
    breakdown: noid_chain::consensus::FeeBreakdown,
    relay_floor: u64,
    paid_total: u64,
) -> FeeBreakdownInfo {
    let relay_total = breakdown.required_total.max(relay_floor);
    let paid_total = paid_total.max(relay_total);
    FeeBreakdownInfo {
        base: breakdown.base,
        input: breakdown.input,
        output: breakdown.output,
        io: breakdown.io,
        state_growth: breakdown.state_growth,
        required_total: breakdown.required_total,
        relay_floor,
        relay_total,
        paid_total,
        burned: breakdown.burned,
        miner_claimable: paid_total.saturating_sub(breakdown.burned),
    }
}

fn wallet_send_shape_for_counts(n_inputs: usize, n_outputs: usize) -> Result<TxShape, String> {
    if n_inputs == 0 {
        return Err("send plan needs at least one input".to_string());
    }
    if n_inputs <= TxShape::Standard4x8.max_inputs()
        && n_outputs <= TxShape::Standard4x8.max_outputs()
    {
        Ok(TxShape::Standard4x8)
    } else if n_inputs <= TxShape::Sweep25x2.max_inputs()
        && n_outputs <= TxShape::Sweep25x2.max_outputs()
    {
        Ok(TxShape::Sweep25x2)
    } else {
        Err(format!(
            "no supported wallet tx shape for {n_inputs} input(s) and {n_outputs} output(s)"
        ))
    }
}

impl WalletOps for WalletHandle {
    fn status(&self) -> WalletStatus {
        let guard = self.inner.lock().unwrap();
        match &*guard {
            None => WalletStatus {
                exists: false,
                address: String::new(),
                active_index: 0,
                balance_micronoid: 0,
                balance_noid: 0.0,
                utxo_count: 0,
                address_count: 0,
            },
            Some(w) => {
                let balance = w.balance();
                WalletStatus {
                    exists: true,
                    address: w.active_address().to_bech32(),
                    active_index: w.active_index,
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
        guard
            .as_ref()
            .and_then(|w| (index < w.next_index).then(|| w.address_at(index).to_bech32()))
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
                    .filter(|u| u.key_index == w.active_index)
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
                    creation_id: u.creation_id,
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
                .filter(|entry| entry.own_key_index == Some(w.active_index))
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

    fn preview_active_reload(&self) -> Result<WalletActivationPreview, String> {
        let guard = self.inner.lock().unwrap();
        let w = guard
            .as_ref()
            .ok_or_else(|| "wallet not initialized".to_string())?;
        let owner = w.active_address();
        Ok(WalletActivationPreview {
            expected_active_index: w.active_index,
            expected_next_index: w.next_index,
            target_index: w.active_index,
            owner: owner.0,
            advance_next_index: false,
        })
    }

    fn preview_address_switch(&self, index: u32) -> Result<WalletActivationPreview, String> {
        let guard = self.inner.lock().unwrap();
        let w = guard
            .as_ref()
            .ok_or_else(|| "wallet not initialized".to_string())?;
        let owner = w.preview_generated_index(index).map_err(str::to_string)?;
        Ok(WalletActivationPreview {
            expected_active_index: w.active_index,
            expected_next_index: w.next_index,
            target_index: index,
            owner: owner.0,
            advance_next_index: false,
        })
    }

    fn preview_next_address(&self) -> Result<WalletActivationPreview, String> {
        let guard = self.inner.lock().unwrap();
        let w = guard
            .as_ref()
            .ok_or_else(|| "wallet not initialized".to_string())?;
        let (index, owner) = w.preview_next_index().map_err(str::to_string)?;
        Ok(WalletActivationPreview {
            expected_active_index: w.active_index,
            expected_next_index: w.next_index,
            target_index: index,
            owner: owner.0,
            advance_next_index: true,
        })
    }

    fn commit_activation_snapshot(
        &self,
        preview: WalletActivationPreview,
        snapshot: VerifiedOwnerSnapshot,
        reserved_input_slots: &std::collections::HashSet<u32>,
        reserved_output_slots: &std::collections::HashSet<u32>,
    ) -> Result<(WalletAddressInfo, WalletScanResult), String> {
        let found = snapshot.utxos.len();
        let balance = snapshot
            .utxos
            .iter()
            .map(|utxo| utxo.amount)
            .fold(0u64, u64::saturating_add);
        let snapshot_height = snapshot.height;
        let snapshot_tip_hash = hex::encode(snapshot.tip_hash);
        let snapshot_state_root = hex::encode(snapshot.state_root);
        let mut guard = self.inner.lock().unwrap();
        let w = guard
            .as_mut()
            .ok_or_else(|| "wallet not initialized".to_string())?;
        w.commit_verified_activation(
            preview.expected_active_index,
            preview.expected_next_index,
            preview.target_index,
            preview.advance_next_index,
            preview.owner,
            snapshot,
            reserved_input_slots,
            reserved_output_slots,
        )?;

        let address_info = WalletAddressInfo {
            address: w.active_address().to_bech32(),
            key_index: preview.target_index,
            is_active: true,
        };
        let scan_result = WalletScanResult {
            found_utxos: found,
            balance_micronoid: balance,
            balance_noid: micronoid_to_noid(balance),
            active_index: w.active_index,
            snapshot_height,
            snapshot_tip_hash,
            snapshot_state_root,
        };
        Ok((address_info, scan_result))
    }

    fn on_accepted_block(&self, block: &noid_chain::block::Block) -> Result<(), String> {
        update_for_accepted_block(&self.inner, block)
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
            .filter(|u| u.key_index == w.active_index)
            .filter(|u| !w.pending_input_slots.contains(&u.slot_index))
            .collect();
        available.sort_by_key(|u| std::cmp::Reverse(u.value));

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

    fn plan_send(
        &self,
        amount_micronoid: u64,
        explicit_fee_micronoid: Option<u64>,
        active_slot_count: u64,
        log_slots: u32,
        relay_floor: u64,
    ) -> Result<WalletSendPlan, String> {
        if amount_micronoid == 0 {
            return Err("amount cannot be zero".to_string());
        }

        let guard = self.inner.lock().unwrap();
        let w = guard
            .as_ref()
            .ok_or_else(|| "wallet not initialized".to_string())?;

        let mut available: Vec<state::WalletUtxo> = w
            .utxos
            .values()
            .filter(|u| u.key_index == w.active_index)
            .filter(|u| !w.pending_input_slots.contains(&u.slot_index))
            .cloned()
            .collect();
        available.sort_by_key(|u| std::cmp::Reverse(u.value));

        let spendable: u64 = available.iter().map(|u| u.value).sum();
        let mut cursor = 0usize;
        let mut remaining = amount_micronoid;
        let mut chunks = Vec::new();

        while remaining > 0 {
            let mut selected_value = 0u64;
            let mut selected_inputs = 0usize;
            let planned = loop {
                if cursor + selected_inputs >= available.len()
                    || selected_inputs >= TxShape::Sweep25x2.max_inputs()
                {
                    if selected_inputs == TxShape::Sweep25x2.max_inputs() {
                        let output_count = 1usize;
                        let shape = wallet_send_shape_for_counts(selected_inputs, output_count)?;
                        let breakdown = noid_chain::consensus::fee_breakdown(
                            selected_inputs as u64,
                            output_count as u64,
                            active_slot_count,
                            log_slots,
                        );
                        let minimum_fee = breakdown.required_total.max(relay_floor);
                        let fee = explicit_fee_micronoid.unwrap_or(minimum_fee);
                        if fee < minimum_fee {
                            return Err(format!(
                                "fee too low for planned {shape:?} tx with {selected_inputs} input(s) and {output_count} output(s): required {minimum_fee} μNOID, got {fee} μNOID"
                            ));
                        }
                        if selected_value > fee {
                            let chunk_amount = selected_value - fee;
                            break (shape, output_count, chunk_amount, 0u64, fee, breakdown);
                        }
                    }
                    let planned_fees = chunks
                        .iter()
                        .map(|c: &WalletSendChunkPlan| c.fee_micronoid)
                        .fold(0u64, |acc, f| acc.saturating_add(f));
                    return Err(format!(
                        "insufficient funds: need at least {} μNOID including planned fees, have {} μNOID spendable",
                        amount_micronoid.saturating_add(planned_fees),
                        spendable
                    ));
                }

                selected_value =
                    selected_value.saturating_add(available[cursor + selected_inputs].value);
                selected_inputs += 1;

                if let Some(explicit_fee) = explicit_fee_micronoid {
                    if selected_value < explicit_fee {
                        continue;
                    }
                    let max_payment = selected_value - explicit_fee;
                    if max_payment >= remaining
                        || selected_inputs == TxShape::Sweep25x2.max_inputs()
                    {
                        let chunk_amount = max_payment.min(remaining);
                        let expected_change = selected_value - explicit_fee - chunk_amount;
                        let output_count = if expected_change > 0 { 2 } else { 1 };
                        let shape = wallet_send_shape_for_counts(selected_inputs, output_count)?;
                        let breakdown = noid_chain::consensus::fee_breakdown(
                            selected_inputs as u64,
                            output_count as u64,
                            active_slot_count,
                            log_slots,
                        );
                        let minimum_fee = breakdown.required_total.max(relay_floor);
                        if explicit_fee < minimum_fee {
                            return Err(format!(
                                "fee too low for planned {shape:?} tx with {selected_inputs} input(s) and {output_count} output(s): required {minimum_fee} μNOID, got {explicit_fee} μNOID"
                            ));
                        }
                        break (
                            shape,
                            output_count,
                            chunk_amount,
                            expected_change,
                            explicit_fee,
                            breakdown,
                        );
                    }
                    continue;
                }

                let one_output_breakdown = noid_chain::consensus::fee_breakdown(
                    selected_inputs as u64,
                    1,
                    active_slot_count,
                    log_slots,
                );
                let one_output_fee = one_output_breakdown.required_total.max(relay_floor);
                if selected_value <= one_output_fee {
                    continue;
                }

                if selected_value >= remaining {
                    let two_output_breakdown = noid_chain::consensus::fee_breakdown(
                        selected_inputs as u64,
                        2,
                        active_slot_count,
                        log_slots,
                    );
                    let two_output_fee = two_output_breakdown.required_total.max(relay_floor);
                    if selected_value > remaining.saturating_add(two_output_fee) {
                        let expected_change = selected_value - remaining - two_output_fee;
                        let shape = wallet_send_shape_for_counts(selected_inputs, 2)?;
                        break (
                            shape,
                            2,
                            remaining,
                            expected_change,
                            two_output_fee,
                            two_output_breakdown,
                        );
                    }

                    let no_change_fee = selected_value - remaining;
                    if no_change_fee >= one_output_fee {
                        let shape = wallet_send_shape_for_counts(selected_inputs, 1)?;
                        break (
                            shape,
                            1,
                            remaining,
                            0u64,
                            no_change_fee,
                            one_output_breakdown,
                        );
                    }
                }

                if selected_inputs == TxShape::Sweep25x2.max_inputs() {
                    let chunk_amount = selected_value - one_output_fee;
                    let shape = wallet_send_shape_for_counts(selected_inputs, 1)?;
                    break (
                        shape,
                        1,
                        chunk_amount,
                        0u64,
                        one_output_fee,
                        one_output_breakdown,
                    );
                }
            };

            let (shape, output_count, chunk_amount, expected_change, fee, breakdown) = planned;
            if chunk_amount == 0 {
                return Err(format!(
                    "insufficient funds: need at least {} μNOID including fee, have {} μNOID spendable",
                    amount_micronoid.saturating_add(fee),
                    spendable
                ));
            }
            let chunk_index = chunks.len();
            chunks.push(WalletSendChunkPlan {
                chunk_index,
                amount_micronoid: chunk_amount,
                shape: format!("{shape:?}"),
                selected_input_count: selected_inputs,
                output_count,
                expected_change_micronoid: expected_change,
                fee_micronoid: fee,
                fee_breakdown: fee_breakdown_info(breakdown, relay_floor, fee),
            });
            cursor += selected_inputs;
            remaining -= chunk_amount;
        }

        let total_fee_micronoid = chunks
            .iter()
            .map(|c| c.fee_micronoid)
            .fold(0u64, |acc, f| acc.saturating_add(f));
        Ok(WalletSendPlan {
            amount_micronoid,
            total_fee_micronoid,
            total_spend_micronoid: amount_micronoid.saturating_add(total_fee_micronoid),
            split_count: chunks.len(),
            chunks,
        })
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
            .filter(|u| u.key_index == w.active_index)
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

        // The destination is captured together with the selected inputs.
        // Never re-read active_index after proving starts: an account switch
        // must not redirect a consolidation built for the previous owner.
        let self_address = build_data.change_address.0;

        // Prove outside the lock (CPU-heavy).
        let (tx_hash, intent_bytes) = builder::build_and_prove_tx(
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
                // Keep a durable source-account tag for receipt generation.
                // A self-consolidation's net outgoing amount is its fee.
                w.record_pending_send(tx_hash, fee_micronoid, self_address);
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

    fn active_address(&self) -> Option<(u32, String)> {
        let guard = self.inner.lock().unwrap();
        guard
            .as_ref()
            .map(|w| (w.active_index, w.active_address().to_bech32()))
    }

    fn list_addresses(&self) -> Vec<WalletAddressInfo> {
        let guard = self.inner.lock().unwrap();
        let w = match &*guard {
            None => return vec![],
            Some(w) => w,
        };

        (0..w.next_index)
            .map(|idx| {
                let addr = w.address_at(idx);
                WalletAddressInfo {
                    address: addr.to_bech32(),
                    key_index: idx,
                    is_active: idx == w.active_index,
                }
            })
            .collect()
    }

    fn pending_outbound(&self) -> u64 {
        let guard = self.inner.lock().unwrap();
        match &*guard {
            None => 0,
            Some(w) => w
                .pending_input_slots
                .iter()
                .filter_map(|&s| w.utxos.get(&s))
                .filter(|u| u.key_index == w.active_index)
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
            let slot_index = i as u32;
            wallet.utxos.insert(
                slot_index,
                state::WalletUtxo {
                    slot_index,
                    value,
                    creation_id: slot_index as u64 + 1,
                    // One owner per tx: fixture UTXOs live on the ACTIVE
                    // (index-0) address.
                    address: wallet.address_at(0),
                    key_index: 0,
                    confirmed_height: 1,
                },
            );
        }
        let handle = WalletHandle {
            inner: Arc::new(Mutex::new(Some(wallet))),
        };
        (dir, handle)
    }

    fn empty_snapshot(owner: [u8; 32]) -> VerifiedOwnerSnapshot {
        VerifiedOwnerSnapshot {
            owner,
            height: 2,
            tip_hash: [0x11; 32],
            state_root: [0x22; 32],
            log_slots: 24,
            active_slot_count: 0,
            alloc_counter: 0,
            utxos: vec![],
        }
    }

    #[test]
    fn planner_uses_one_sweep_sized_chunk_for_20_inputs() {
        let (_dir, handle) = handle_with_utxos(&[1_000; 20]);
        let chunks = handle.plan_send_splits(19_500, 500).unwrap();
        assert_eq!(chunks, vec![19_500]);
    }

    #[test]
    fn planner_splits_after_25_inputs() {
        let (_dir, handle) = handle_with_utxos(&[1_000; 26]);
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
    fn status_and_pending_balance_cover_cached_active_utxos_only() {
        let (_dir, handle) = handle_with_utxos(&[2_000, 2_000]);
        {
            let mut guard = handle.inner.lock().unwrap();
            let wallet = guard.as_mut().unwrap();
            wallet.pending_input_slots.insert(0);
        }

        assert!(handle.plan_send_splits(3_000, 0).is_err());
        let balance = handle.get_balance();
        assert_eq!(balance.total_micronoid, 4_000);
        assert_eq!(balance.pending_outbound_micronoid, 2_000);
        assert_eq!(balance.spendable_micronoid, 2_000);
        assert_eq!(handle.status().utxo_count, 2);
    }

    #[test]
    fn rpc_history_exposes_only_the_active_account() {
        let (_dir, handle) = handle_with_utxos(&[1_000]);
        {
            let mut guard = handle.inner.lock().unwrap();
            let wallet = guard.as_mut().unwrap();
            wallet.record_pending_send([1; 32], 10, [2; 32]);
            wallet.history.push(state::TxHistoryEntry {
                tx_hash: [3; 32],
                height: 7,
                direction: state::TxDirection::Received,
                amount_micronoid: 20,
                peer_address: None,
                timestamp: 8,
                own_address: Some(wallet.address_at(1).to_bech32()),
                own_key_index: Some(1),
            });
        }

        let history = handle.history();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].own_key_index, Some(0));
    }

    #[test]
    fn rpc_wallet_handle_rejects_max_active_index_without_mutation() {
        let (_dir, handle) = handle_with_utxos(&[1_000]);
        let error = handle
            .preview_address_switch(MAX_WALLET_ADDRESSES)
            .unwrap_err();
        assert!(error.contains("has not been generated"));
        let (index, _) = handle.active_address().unwrap();
        assert_eq!(index, 0);
    }

    #[test]
    fn address_derivation_stops_at_shared_wallet_cap() {
        let (_dir, handle) = handle_with_utxos(&[1_000]);
        {
            let mut guard = handle.inner.lock().unwrap();
            guard.as_mut().unwrap().next_index = MAX_WALLET_ADDRESSES;
        }

        assert!(handle.preview_next_address().is_err());
        assert!(handle.get_address(MAX_WALLET_ADDRESSES).is_none());
    }

    #[test]
    fn address_list_is_local_metadata_and_new_address_becomes_active() {
        let (_dir, handle) = handle_with_utxos(&[1_000]);
        let preview = handle.preview_next_address().unwrap();
        let (generated, _scan) = handle
            .commit_activation_snapshot(
                preview.clone(),
                empty_snapshot(preview.owner),
                &std::collections::HashSet::new(),
                &std::collections::HashSet::new(),
            )
            .unwrap();
        assert_eq!(generated.key_index, 1);
        assert!(generated.is_active);

        let addresses = handle.list_addresses();
        assert_eq!(addresses.len(), 2);
        assert!(!addresses[0].is_active);
        assert!(addresses[1].is_active);
        assert!(
            handle.list_utxos().is_empty(),
            "switch clears the old cache"
        );
    }

    #[test]
    fn reorg_installs_exact_snapshot_instead_of_replaying_on_old_cache() {
        let (_dir, handle) = handle_with_utxos(&[111, 222]);
        let owner = handle
            .inner
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .active_address();
        let snapshot = VerifiedOwnerSnapshot {
            owner: owner.0,
            height: 10,
            tip_hash: [0x44; 32],
            state_root: [0x55; 32],
            log_slots: 24,
            active_slot_count: 1,
            alloc_counter: 8,
            utxos: vec![noid_chain::storage::VerifiedOwnerUtxo {
                slot_index: 99,
                amount: 777,
                creation_id: 8,
            }],
        };

        install_reorg_snapshot_and_artifacts(
            &handle.inner,
            0,
            1,
            owner.0,
            snapshot,
            &std::collections::HashSet::new(),
            &std::collections::HashSet::new(),
            &[],
            &[],
        )
        .unwrap();

        let guard = handle.inner.lock().unwrap();
        let wallet = guard.as_ref().unwrap();
        assert_eq!(wallet.utxos.len(), 1);
        assert_eq!(wallet.utxos[&99].value, 777);
        assert!(!wallet.utxos.contains_key(&0));
        assert!(!wallet.utxos.contains_key(&1));
        assert_eq!(wallet.active_snapshot.as_ref().unwrap().height, 10);
    }

    #[test]
    fn reorg_removes_receipts_bound_to_orphaned_blocks() {
        let (dir, handle) = handle_with_utxos(&[111]);
        let orphan_hash = [0x66; 32];
        let owner = {
            let mut guard = handle.inner.lock().unwrap();
            let wallet = guard.as_mut().unwrap();
            wallet.receipts.insert(orphan_hash, vec![1, 2, 3]);
            wallet.save_receipts();
            wallet.history.push(state::TxHistoryEntry {
                tx_hash: orphan_hash,
                height: 9,
                direction: state::TxDirection::Sent,
                amount_micronoid: 7,
                peer_address: None,
                timestamp: 8,
                own_address: Some(wallet.active_address().to_bech32()),
                own_key_index: Some(wallet.active_index),
            });
            wallet.active_address()
        };

        install_reorg_snapshot_and_artifacts(
            &handle.inner,
            0,
            1,
            owner.0,
            empty_snapshot(owner.0),
            &std::collections::HashSet::new(),
            &std::collections::HashSet::new(),
            &[noid_poseidon2b::primitives::TxBodyHash(orphan_hash)],
            &[],
        )
        .unwrap();

        let guard = handle.inner.lock().unwrap();
        let wallet = guard.as_ref().unwrap();
        assert!(!wallet.receipts.contains_key(&orphan_hash));
        assert!(wallet
            .history
            .iter()
            .all(|entry| entry.tx_hash != orphan_hash));
        drop(guard);

        let reloaded = state::WalletState::create_or_load(dir.path().join("wallet.key")).unwrap();
        assert!(
            !reloaded.receipts.contains_key(&orphan_hash),
            "orphan receipt must not return after restart"
        );
    }

    #[test]
    fn rejected_incremental_update_does_not_advance_snapshot_or_cache() {
        let (_dir, handle) = handle_with_utxos(&[111]);
        let owner = handle
            .inner
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .active_address();
        let baseline = state::ActiveWalletSnapshot {
            height: 3,
            tip_hash: [0x31; 32],
            state_root: [0x32; 32],
            log_slots: 24,
            active_slot_count: 1,
            alloc_counter: 1,
        };
        handle
            .inner
            .lock()
            .unwrap()
            .as_mut()
            .unwrap()
            .active_snapshot = Some(baseline.clone());

        let body = noid_tx::TxBody::standard(
            [0; 32],
            0,
            vec![],
            vec![noid_tx::TxOutput {
                slot_index: 9,
                value: 50,
                owner,
                valid: true,
            }],
            true,
        );
        let malformed = noid_chain::block::Block {
            header: noid_chain::BlockHeader {
                prev_block_hash: baseline.tip_hash,
                state_root: [0x41; 32],
                tx_root: [0x42; 32],
                timestamp: 4,
                height: 4,
                miner_address: owner,
                nonce: 0,
                difficulty_target: [0xFF; 32],
                log_slots: 24,
                active_slot_count: 2,
                // One live mint with a zero post-counter is impossible.
                alloc_counter: 0,
            },
            transactions: vec![noid_tx::Transaction {
                body,
                tx_body_hash: noid_poseidon2b::primitives::TxBodyHash([0x43; 32]),
            }],
        };

        assert!(update_for_accepted_block(&handle.inner, &malformed).is_err());
        let guard = handle.inner.lock().unwrap();
        let wallet = guard.as_ref().unwrap();
        assert_eq!(wallet.active_snapshot.as_ref(), Some(&baseline));
        assert_eq!(wallet.utxos.len(), 1);
        assert_eq!(wallet.utxos[&0].value, 111);
        assert!(!wallet.utxos.contains_key(&9));
    }

    #[test]
    fn sweep_sized_send_selects_more_than_four_inputs() {
        let (_dir, handle) = handle_with_utxos(&[50_000_000; 8]);
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
    fn shape_aware_plan_keeps_small_standard_fee_at_baseline() {
        let (_dir, handle) = handle_with_utxos(&[100_000]);
        let plan = handle.plan_send(50_000, None, 0, 24, 0).unwrap();
        assert_eq!(plan.split_count, 1);
        assert_eq!(plan.total_fee_micronoid, 9_000);
        assert_eq!(plan.chunks[0].shape, "Standard4x8");
        assert_eq!(plan.chunks[0].selected_input_count, 1);
        assert_eq!(plan.chunks[0].output_count, 2);
        assert_eq!(plan.chunks[0].fee_breakdown.burned, 2_500);
    }

    #[test]
    fn shape_aware_plan_handles_no_change_boundary_without_oscillation() {
        let (_dir, handle) = handle_with_utxos(&[100_000]);
        let plan = handle.plan_send(91_000, None, 0, 24, 0).unwrap();
        assert_eq!(plan.split_count, 1);
        assert_eq!(plan.total_fee_micronoid, 9_000);
        assert_eq!(plan.chunks[0].shape, "Standard4x8");
        assert_eq!(plan.chunks[0].output_count, 1);
        assert_eq!(plan.chunks[0].expected_change_micronoid, 0);
        assert_eq!(plan.chunks[0].fee_breakdown.paid_total, 9_000);
        assert_eq!(plan.chunks[0].fee_breakdown.relay_total, 5_800);
    }

    #[test]
    fn shape_aware_plan_does_not_apply_sweep_worst_case_to_five_input_send() {
        let (_dir, handle) = handle_with_utxos(&[50_000_000; 8]);
        let plan = handle.plan_send(200_000_001, None, 0, 24, 0).unwrap();
        assert_eq!(plan.split_count, 1);
        assert_eq!(plan.chunks[0].shape, "Sweep25x2");
        assert_eq!(plan.chunks[0].selected_input_count, 5);
        assert_eq!(plan.chunks[0].output_count, 2);
        assert_eq!(plan.chunks[0].fee_micronoid, 6_900);
        assert_eq!(plan.chunks[0].fee_breakdown.state_growth, 0);
    }

    #[test]
    fn consolidate_planner_caps_at_sweep_capacity() {
        let (_dir, handle) = handle_with_utxos(&[1_000; 30]);
        assert_eq!(handle.plan_consolidate_input_count().unwrap(), 25);
    }

    #[test]
    fn consolidate_planner_skips_pending_inputs() {
        let (_dir, handle) = handle_with_utxos(&[1_000; 6]);
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
        let (shape, selected, amount) = extract_consolidate_shape(&[1_000; 4]);
        assert_eq!(shape, TxShape::Standard4x8);
        assert_eq!(selected, 4);
        assert_eq!(amount, 3_990);
    }

    #[test]
    fn consolidate_five_inputs_uses_sweep_shape() {
        let (shape, selected, amount) = extract_consolidate_shape(&[1_000; 5]);
        assert_eq!(shape, TxShape::Sweep25x2);
        assert_eq!(selected, 5);
        assert_eq!(amount, 4_990);
    }

    #[test]
    fn consolidate_twenty_five_inputs_uses_sweep_shape() {
        let (shape, selected, amount) = extract_consolidate_shape(&[1_000; 30]);
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
