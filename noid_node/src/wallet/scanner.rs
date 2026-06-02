// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! UTXO discovery by scanning the chain state.
//!
//! # Architecture
//!
//! Blocks are pruned immediately after `apply_block`. Only the last
//! FINALITY_DEPTH=18 blocks remain. There is NO historical block scan.
//!
//! The SegmentedFriState is kept FOREVER and is the source of truth for all UTXOs.
//!
//! ## Full scan (import on new machine)
//!
//! 1. Collect all active slots from state (O(active_slots))
//! 2. Derive addresses in batches of BATCH_SIZE=20
//! 3. Stop after GAP_LIMIT=1 consecutive batches with no new matches
//! 4. Returns all matching UTXOs and the full set of known_addresses
//!
//! ## Incremental update (new block)
//!
//! O(block_size): check outputs for owned addresses, remove spent inputs.

use std::collections::HashMap;

use noid_chain::block::Block;
use noid_chain::consensus::receipt::{generate_receipt, TxSummary};
use noid_chain::fri_state::SlotValue;
use noid_chain::segmented_state::SegmentedFriState;
use noid_core::Block128;
use noid_poseidon2b::primitives::Address;

use super::keystore::MasterSecret;
use super::state::{TxDirection, TxHistoryEntry, WalletUtxo};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Number of addresses to derive per batch during state scan.
/// Matches the standard HD wallet gap limit.
const BATCH_SIZE: u32 = 20;

/// Stop scanning after this many consecutive batches yield no UTXOs.
/// GAP_LIMIT=1 means stop after 20 unused addresses (one full batch).
const GAP_LIMIT: u32 = 1;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Extract 32-byte owner address from a SlotValue.
/// Layout: owner_hi.0.to_le_bytes() ++ owner_lo.0.to_le_bytes()
#[inline]
pub fn owner_bytes_from_slot(sv: &SlotValue) -> [u8; 32] {
    let mut b = [0u8; 32];
    b[..16].copy_from_slice(&sv.owner_hi.0.to_le_bytes());
    b[16..].copy_from_slice(&sv.owner_lo.0.to_le_bytes());
    b
}

/// Convert an Address to the two Block128 owner fields stored in state.
#[inline]
pub fn address_to_owner_fields(addr: &Address) -> (Block128, Block128) {
    let hi = u128::from_le_bytes(addr.0[..16].try_into().unwrap());
    let lo = u128::from_le_bytes(addr.0[16..].try_into().unwrap());
    (Block128::from(hi), Block128::from(lo))
}

// ---------------------------------------------------------------------------
// Full state scan
// ---------------------------------------------------------------------------

/// Scan the entire chain state for UTXOs owned by this wallet.
///
/// Uses dynamic address discovery: derives addresses in batches of BATCH_SIZE,
/// stopping after GAP_LIMIT consecutive batches find no new UTXOs.
///
/// Returns:
/// - `Vec<WalletUtxo>`: all found UTXOs
/// - `HashMap<[u8;32], u32>`: all derived addresses (address → key_index)
/// - `u32`: highest used key_index + 1 (next_index hint)
///
/// Complexity: O(active_slots) for state traversal + O(n_addresses) for derivation.
pub fn scan_state_for_utxos(
    state: &SegmentedFriState,
    master: &MasterSecret,
    current_height: u64,
) -> (Vec<WalletUtxo>, HashMap<[u8; 32], u32>, u32) {
    let seg_log = state.effective_log_segment_size();
    let seg_size = 1usize << seg_log;

    // Phase 1: Collect all non-empty slots from active segments (O(active_slots))
    // Build reverse map: owner_bytes → Vec<(slot_index, value)>
    let mut owner_to_slots: HashMap<[u8; 32], Vec<(u32, u64)>> = HashMap::new();
    for seg_id in state.active_segment_ids() {
        let base = (seg_id as u32) << seg_log as u32;
        for local in 0..seg_size {
            let idx = base + local as u32;
            let sv = state.slot(idx);
            if sv.is_empty() {
                continue;
            }
            let owner = owner_bytes_from_slot(&sv);
            let value = sv.value.0 as u64;
            owner_to_slots.entry(owner).or_default().push((idx, value));
        }
    }

    if owner_to_slots.is_empty() {
        // Empty state (genesis) — fast path
        let known: HashMap<[u8; 32], u32> = (0..BATCH_SIZE)
            .map(|i| (master.derive_address(i).0, i))
            .collect();
        return (vec![], known, BATCH_SIZE);
    }

    // Phase 2: Derive addresses in batches until gap condition met
    let mut known_addresses: HashMap<[u8; 32], u32> = HashMap::new();
    let mut found_utxos: Vec<WalletUtxo> = Vec::new();
    let mut max_found_index: u32 = 0;
    let mut batch_start: u32 = 0;
    let mut empty_batches: u32 = 0;

    loop {
        let batch_end = batch_start + BATCH_SIZE;
        let mut batch_found = 0u32;

        for i in batch_start..batch_end {
            let addr = master.derive_address(i);
            known_addresses.insert(addr.0, i);

            if let Some(slots) = owner_to_slots.get(&addr.0) {
                for &(slot_idx, value) in slots {
                    found_utxos.push(WalletUtxo {
                        slot_index: slot_idx,
                        value,
                        address: addr,
                        key_index: i,
                        confirmed_height: current_height,
                    });
                }
                if i > max_found_index {
                    max_found_index = i;
                }
                batch_found += 1;
                empty_batches = 0; // reset gap counter
            }
        }

        if batch_found == 0 {
            empty_batches += 1;
        }

        batch_start = batch_end;

        // Stop conditions:
        // 1. GAP_LIMIT consecutive empty batches
        // 2. Safety cap: never derive more than 100_000 addresses
        if empty_batches >= GAP_LIMIT || batch_start >= 100_000 {
            break;
        }
    }

    // Ensure we always have at least BATCH_SIZE addresses beyond the last found
    let next_index = (max_found_index + 1).max(batch_start);

    (found_utxos, known_addresses, next_index)
}

// ---------------------------------------------------------------------------
// Incremental block update
// ---------------------------------------------------------------------------

/// Update wallet state based on a newly confirmed block.
///
/// Must be called BEFORE block pruning (while transactions are still available).
/// O(block_size × known_addresses).
///
/// Updates:
/// - Removes spent UTXOs (inputs consumed by this block)
/// - Adds new UTXOs (outputs addressed to this wallet)
/// - Appends to tx history
/// - Generates and stores Merkle receipts for all wallet-relevant transactions
pub fn update_wallet_from_block(
    utxos: &mut HashMap<u32, WalletUtxo>,
    history: &mut Vec<TxHistoryEntry>,
    receipts: &mut HashMap<[u8; 32], Vec<u8>>,
    known_addresses: &HashMap<[u8; 32], u32>,
    block: &Block,
) {
    let height = block.header.height;
    let timestamp = block.header.timestamp;

    let block_tx_hashes: Vec<[u8; 32]> = block
        .transactions
        .iter()
        .map(|t| t.tx_body_hash.0)
        .collect();

    for (tx_index, tx) in block.transactions.iter().enumerate() {
        if tx.body.is_coinbase {
            // Coinbase: just check outputs for our addresses
            let mut coinbase_received: u64 = 0;
            for output in tx.body.outputs.iter().filter(|o| o.valid) {
                if let Some(&key_idx) = known_addresses.get(&output.owner.0) {
                    let utxo = WalletUtxo {
                        slot_index: output.slot_index,
                        value: output.value,
                        address: output.owner,
                        key_index: key_idx,
                        confirmed_height: height,
                    };
                    utxos.insert(output.slot_index, utxo);
                    coinbase_received = coinbase_received.saturating_add(output.value);
                    history.push(TxHistoryEntry {
                        tx_hash: tx.tx_body_hash.0,
                        height,
                        direction: TxDirection::Received,
                        amount_micronoid: output.value,
                        peer_address: None,
                        timestamp,
                    });
                }
            }
            if coinbase_received > 0 {
                let summary = TxSummary {
                    tx_body_hash: tx.tx_body_hash.0,
                    inputs: vec![],
                    outputs: tx
                        .body
                        .outputs
                        .iter()
                        .filter(|o| o.valid)
                        .map(|o| (o.slot_index, o.value, o.owner))
                        .collect(),
                    fee_micronoid: tx.body.fee as u64,
                    confirmed_height: height,
                    confirmed_unix: timestamp,
                };
                let receipt = generate_receipt(
                    &block.header,
                    tx.tx_body_hash.0,
                    tx_index,
                    &block_tx_hashes,
                    summary,
                    None,
                );
                receipts.insert(tx.tx_body_hash.0, receipt.to_bytes());
            }
            continue;
        }

        // Track value flow for this transaction
        let mut sent_from_wallet: u64 = 0;
        let mut received_by_wallet: u64 = 0;

        // Inputs: remove spent UTXOs
        for input in tx.body.inputs.iter().filter(|i| i.valid) {
            if let Some(spent) = utxos.remove(&input.slot_index) {
                sent_from_wallet = sent_from_wallet.saturating_add(spent.value);
            }
        }

        // Outputs: add new UTXOs owned by this wallet
        for output in tx.body.outputs.iter().filter(|o| o.valid) {
            if let Some(&key_idx) = known_addresses.get(&output.owner.0) {
                let utxo = WalletUtxo {
                    slot_index: output.slot_index,
                    value: output.value,
                    address: output.owner,
                    key_index: key_idx,
                    confirmed_height: height,
                };
                utxos.insert(output.slot_index, utxo);
                received_by_wallet = received_by_wallet.saturating_add(output.value);
            }
        }

        // Record history entry.
        // Skip if this tx_hash is already in history as a pending (height=0) entry
        // from record_pending_send — confirm_pending_tx will update the height.
        let already_pending = history
            .iter()
            .any(|e| e.tx_hash == tx.tx_body_hash.0 && e.height == 0);

        if !already_pending {
            if sent_from_wallet > 0 {
                let net_sent = sent_from_wallet.saturating_sub(received_by_wallet);
                history.push(TxHistoryEntry {
                    tx_hash: tx.tx_body_hash.0,
                    height,
                    direction: TxDirection::Sent,
                    amount_micronoid: net_sent,
                    peer_address: None,
                    timestamp,
                });
            } else if received_by_wallet > 0 {
                history.push(TxHistoryEntry {
                    tx_hash: tx.tx_body_hash.0,
                    height,
                    direction: TxDirection::Received,
                    amount_micronoid: received_by_wallet,
                    peer_address: None,
                    timestamp,
                });
            }
        }

        if sent_from_wallet > 0 || received_by_wallet > 0 {
            let summary = TxSummary {
                tx_body_hash: tx.tx_body_hash.0,
                inputs: tx
                    .body
                    .inputs
                    .iter()
                    .filter(|i| i.valid)
                    .map(|i| (i.slot_index, i.owner))
                    .collect(),
                outputs: tx
                    .body
                    .outputs
                    .iter()
                    .filter(|o| o.valid)
                    .map(|o| (o.slot_index, o.value, o.owner))
                    .collect(),
                fee_micronoid: tx.body.fee as u64,
                confirmed_height: height,
                confirmed_unix: timestamp,
            };
            let receipt = generate_receipt(
                &block.header,
                tx.tx_body_hash.0,
                tx_index,
                &block_tx_hashes,
                summary,
                None,
            );
            receipts.insert(tx.tx_body_hash.0, receipt.to_bytes());
        }
    }
}
