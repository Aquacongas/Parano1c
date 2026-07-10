// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! UTXO discovery by scanning the chain state.
//!
//! # Architecture
//!
//! Blocks are pruned immediately after `apply_block`. Only the last
//! Only the retained recent block window remains. There is NO historical block scan.
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

use super::keystore::MasterSecret;
use super::state::{TxDirection, TxHistoryEntry, WalletUtxo, MAX_WALLET_ADDRESSES};

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
    hint_next_index: u32, // always scan at least to this index
) -> (Vec<WalletUtxo>, HashMap<[u8; 32], u32>, u32) {
    let seg_log = state.effective_log_segment_size();
    let seg_size = 1usize << seg_log;

    // Collect all non-empty slots from active segments (O(active_slots))
    // Build reverse map: owner_bytes → Vec<(slot_index, amount, creation_id)>.
    // Both value limbs are part of the spend claim, so a full scan must retain
    // the incarnation rather than reconstructing it from slot position/history.
    let mut owner_to_slots: HashMap<[u8; 32], Vec<(u32, u64, u64)>> = HashMap::new();
    for seg_id in state.active_segment_ids() {
        let base = (seg_id as u32) << seg_log as u32;
        for local in 0..seg_size {
            let idx = base + local as u32;
            let sv = state.slot(idx);
            if sv.is_empty() {
                continue;
            }
            let owner = owner_bytes_from_slot(&sv);
            owner_to_slots
                .entry(owner)
                .or_default()
                .push((idx, sv.amount(), sv.creation_id()));
        }
    }

    if owner_to_slots.is_empty() {
        // Empty state (genesis) — fast path
        let known: HashMap<[u8; 32], u32> = (0..BATCH_SIZE)
            .map(|i| (master.derive_address(i).0, i))
            .collect();
        return (vec![], known, BATCH_SIZE);
    }

    // Derive addresses in batches until gap condition met
    let mut known_addresses: HashMap<[u8; 32], u32> = HashMap::new();
    let mut found_utxos: Vec<WalletUtxo> = Vec::new();
    let mut max_found_index: u32 = 0;
    let mut batch_start: u32 = 0;
    let mut empty_batches: u32 = 0;

    while batch_start < MAX_WALLET_ADDRESSES {
        let batch_end = batch_start
            .saturating_add(BATCH_SIZE)
            .min(MAX_WALLET_ADDRESSES);
        let mut batch_found = 0u32;

        for i in batch_start..batch_end {
            let addr = master.derive_address(i);
            known_addresses.insert(addr.0, i);

            if let Some(slots) = owner_to_slots.get(&addr.0) {
                for &(slot_idx, value, creation_id) in slots {
                    found_utxos.push(WalletUtxo {
                        slot_index: slot_idx,
                        value,
                        creation_id,
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
        // 1. GAP_LIMIT consecutive empty batches AND we've scanned past hint_next_index
        //    (always cover addresses the user generated via address --new)
        // 2. Safety cap: never derive more than MAX_WALLET_ADDRESSES.
        let min_scan_to = hint_next_index
            .min(MAX_WALLET_ADDRESSES)
            .saturating_add(BATCH_SIZE)
            .min(MAX_WALLET_ADDRESSES);
        if empty_batches >= GAP_LIMIT && batch_start >= min_scan_to {
            break;
        }
    }

    // Ensure we always have at least BATCH_SIZE addresses beyond the last found
    let next_index = (max_found_index + 1)
        .max(batch_start)
        .min(MAX_WALLET_ADDRESSES);

    (found_utxos, known_addresses, next_index)
}

// ---------------------------------------------------------------------------
// Incremental block update
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CreationIdDerivationError {
    MultipleCoinbase,
    CoinbaseNotFirst,
    MintCountOverflow,
    HeaderCounterUnderflow { alloc_counter: u64, live_mints: u64 },
    CounterOverflow,
    FinalCounterMismatch { expected: u64, actual: u64 },
}

impl std::fmt::Display for CreationIdDerivationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MultipleCoinbase => write!(f, "multiple coinbase transactions"),
            Self::CoinbaseNotFirst => write!(f, "coinbase transaction is not first"),
            Self::MintCountOverflow => write!(f, "live output count exceeds u64"),
            Self::HeaderCounterUnderflow {
                alloc_counter,
                live_mints,
            } => write!(
                f,
                "header alloc_counter {alloc_counter} is below live mint count {live_mints}"
            ),
            Self::CounterOverflow => write!(f, "creation_id counter overflow"),
            Self::FinalCounterMismatch { expected, actual } => write!(
                f,
                "derived final alloc_counter {actual} does not match header {expected}"
            ),
        }
    }
}

/// Reconstruct each output's consensus creation id from the post-block
/// allocator counter. IDs follow `block.transactions` and output order exactly.
/// The helper independently rejects a late or duplicate coinbase so malformed
/// data cannot acquire a wallet-only interpretation different from consensus.
///
/// `TxOutput` intentionally carries no caller-chosen creation id. The wallet
/// therefore derives the parent counter as `header.alloc_counter - live_mints`
/// and advances it with checked arithmetic. The returned matrix is aligned
/// with `block.transactions[tx].body.outputs[output]`; dummy outputs map to
/// `None`.
fn derive_output_creation_ids(
    block: &Block,
) -> Result<Vec<Vec<Option<u64>>>, CreationIdDerivationError> {
    let mut seen_coinbase = false;
    for (tx_index, tx) in block.transactions.iter().enumerate() {
        if !tx.body.is_coinbase {
            continue;
        }
        if seen_coinbase {
            return Err(CreationIdDerivationError::MultipleCoinbase);
        }
        if tx_index != 0 {
            return Err(CreationIdDerivationError::CoinbaseNotFirst);
        }
        seen_coinbase = true;
    }

    let live_mints = block
        .transactions
        .iter()
        .flat_map(|tx| tx.body.outputs.iter())
        .filter(|output| output.valid)
        .try_fold(0u64, |count, _| count.checked_add(1))
        .ok_or(CreationIdDerivationError::MintCountOverflow)?;
    let mut counter = block.header.alloc_counter.checked_sub(live_mints).ok_or(
        CreationIdDerivationError::HeaderCounterUnderflow {
            alloc_counter: block.header.alloc_counter,
            live_mints,
        },
    )?;

    let mut ids: Vec<Vec<Option<u64>>> = block
        .transactions
        .iter()
        .map(|tx| vec![None; tx.body.outputs.len()])
        .collect();

    for (tx_index, tx) in block.transactions.iter().enumerate() {
        for (output_index, output) in tx.body.outputs.iter().enumerate() {
            if !output.valid {
                continue;
            }
            counter = counter
                .checked_add(1)
                .ok_or(CreationIdDerivationError::CounterOverflow)?;
            ids[tx_index][output_index] = Some(counter);
        }
    }

    if counter != block.header.alloc_counter {
        return Err(CreationIdDerivationError::FinalCounterMismatch {
            expected: block.header.alloc_counter,
            actual: counter,
        });
    }
    Ok(ids)
}

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
/// - Clears confirmed input slots from `pending_input_slots`
pub fn update_wallet_from_block(
    utxos: &mut HashMap<u32, WalletUtxo>,
    history: &mut Vec<TxHistoryEntry>,
    receipts: &mut HashMap<[u8; 32], Vec<u8>>,
    known_addresses: &HashMap<[u8; 32], u32>,
    pending_input_slots: &mut std::collections::HashSet<u32>,
    block: &Block,
) {
    let height = block.header.height;
    let timestamp = block.header.timestamp;

    // Derive the complete map before mutating wallet state. Consensus-valid
    // blocks always satisfy this relation; rejecting the update here avoids
    // inventing or wrapping an incarnation if corrupt/unvalidated data reaches
    // the product hook.
    let output_creation_ids = match derive_output_creation_ids(block) {
        Ok(ids) => ids,
        Err(error) => {
            tracing::error!(
                height,
                alloc_counter = block.header.alloc_counter,
                %error,
                "wallet: refusing block update with invalid creation-id sequence"
            );
            return;
        }
    };

    let block_tx_hashes: Vec<[u8; 32]> = block
        .transactions
        .iter()
        .map(|t| t.tx_body_hash.0)
        .collect();

    // Build once before the loop: O(history) instead of O(history × txs).
    let pending_hashes: std::collections::HashSet<[u8; 32]> = history
        .iter()
        .filter(|e| e.height == 0)
        .map(|e| e.tx_hash)
        .collect();

    for (tx_index, tx) in block.transactions.iter().enumerate() {
        if tx.body.is_coinbase {
            // Coinbase: track UTXOs for our addresses, record history.
            // No receipt — receipts are proof-of-payment for OUTGOING txs only.
            for (output_index, output) in tx.body.outputs.iter().enumerate() {
                if !output.valid {
                    continue;
                }
                let Some(creation_id) = output_creation_ids[tx_index][output_index] else {
                    tracing::error!(
                        height,
                        tx_index,
                        output_index,
                        "wallet: missing creation id for live coinbase output"
                    );
                    return;
                };
                if let Some(&key_idx) = known_addresses.get(&output.owner.0) {
                    let utxo = WalletUtxo {
                        slot_index: output.slot_index,
                        value: output.value,
                        creation_id,
                        address: output.owner,
                        key_index: key_idx,
                        confirmed_height: height,
                    };
                    utxos.insert(output.slot_index, utxo);
                    let addr_str = output.owner.to_bech32();
                    history.push(TxHistoryEntry {
                        tx_hash: tx.tx_body_hash.0,
                        height,
                        direction: TxDirection::Received,
                        amount_micronoid: output.value,
                        peer_address: None,
                        timestamp,
                        own_address: Some(addr_str),
                        own_key_index: Some(key_idx),
                    });
                }
            }
            continue;
        }

        // Track value flow for this transaction
        let mut sent_from_wallet: u64 = 0;
        let mut received_by_wallet: u64 = 0;
        let mut sent_own_address: Option<String> = None;
        let mut sent_own_key_index: Option<u32> = None;
        let mut recv_own_address: Option<String> = None;
        let mut recv_own_key_index: Option<u32> = None;

        // Inputs: remove spent UTXOs and clear from pending_input_slots.
        for input in tx.body.inputs.iter().filter(|i| i.valid) {
            pending_input_slots.remove(&input.slot_index);
            if let Some(spent) = utxos.remove(&input.slot_index) {
                sent_from_wallet = sent_from_wallet.saturating_add(spent.value);
                // Track the first spent address as the "own" sending address.
                if sent_own_address.is_none() {
                    sent_own_address = Some(spent.address.to_bech32());
                    sent_own_key_index = Some(spent.key_index);
                }
            }
        }

        // Outputs: add new UTXOs owned by this wallet
        for (output_index, output) in tx.body.outputs.iter().enumerate() {
            if !output.valid {
                continue;
            }
            let Some(creation_id) = output_creation_ids[tx_index][output_index] else {
                tracing::error!(
                    height,
                    tx_index,
                    output_index,
                    "wallet: missing creation id for live user output"
                );
                return;
            };
            if let Some(&key_idx) = known_addresses.get(&output.owner.0) {
                let utxo = WalletUtxo {
                    slot_index: output.slot_index,
                    value: output.value,
                    creation_id,
                    address: output.owner,
                    key_index: key_idx,
                    confirmed_height: height,
                };
                utxos.insert(output.slot_index, utxo);
                received_by_wallet = received_by_wallet.saturating_add(output.value);
                // Track the first received-to address as the "own" receiving address.
                if recv_own_address.is_none() {
                    recv_own_address = Some(output.owner.to_bech32());
                    recv_own_key_index = Some(key_idx);
                }
            }
        }

        // Record history entry.
        // Skip if this tx_hash is already in history as a pending (height=0) entry
        // from record_pending_send — confirm_pending_tx will update the height.
        let already_pending = pending_hashes.contains(&tx.tx_body_hash.0);

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
                    own_address: sent_own_address,
                    own_key_index: sent_own_key_index,
                });
            } else if received_by_wallet > 0 {
                history.push(TxHistoryEntry {
                    tx_hash: tx.tx_body_hash.0,
                    height,
                    direction: TxDirection::Received,
                    amount_micronoid: received_by_wallet,
                    peer_address: None,
                    timestamp,
                    own_address: recv_own_address,
                    own_key_index: recv_own_key_index,
                });
            }
        }

        // Receipt = proof of payment. Only generate when WE sent funds.
        // Incoming-only txs need no receipt — the sender holds the proof.
        if sent_from_wallet > 0 {
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

#[cfg(test)]
mod tests {
    use super::*;
    use noid_chain::block_header::BlockHeader;
    use noid_chain::segmented_state::SegmentedFriState;
    use noid_poseidon2b::primitives::{Address, TxBodyHash};
    use noid_tx::{Transaction, TxBody, TxOutput, TxShape};

    fn transaction(is_coinbase: bool, slot_index: u32, owner: Address) -> Transaction {
        Transaction {
            body: TxBody {
                shape: TxShape::Standard4x8,
                epoch_anchor: if is_coinbase { [0; 32] } else { [1; 32] },
                fee: 0,
                inputs: vec![],
                outputs: vec![TxOutput {
                    slot_index,
                    value: u64::from(slot_index) + 100,
                    owner,
                    valid: true,
                }],
                is_coinbase,
            },
            tx_body_hash: TxBodyHash([slot_index as u8; 32]),
        }
    }

    fn block(transactions: Vec<Transaction>, alloc_counter: u64) -> Block {
        Block {
            header: BlockHeader {
                prev_block_hash: [0; 32],
                state_root: [0; 32],
                tx_root: [0; 32],
                timestamp: 123,
                height: 7,
                miner_address: Address([0x77; 32]),
                nonce: 0,
                difficulty_target: [0xFF; 32],
                log_slots: 24,
                active_slot_count: transactions.len() as u64,
                alloc_counter,
            },
            transactions,
        }
    }

    #[test]
    fn incremental_scan_assigns_coinbase_then_user_creation_ids() {
        let owner = Address([0xA1; 32]);
        let block = block(
            vec![transaction(true, 10, owner), transaction(false, 20, owner)],
            102,
        );
        let mut utxos = HashMap::new();
        let mut history = vec![];
        let mut receipts = HashMap::new();
        let known_addresses = HashMap::from([(owner.0, 3)]);
        let mut pending_inputs = std::collections::HashSet::new();

        update_wallet_from_block(
            &mut utxos,
            &mut history,
            &mut receipts,
            &known_addresses,
            &mut pending_inputs,
            &block,
        );

        assert_eq!(utxos[&10].creation_id, 101, "coinbase is first");
        assert_eq!(utxos[&20].creation_id, 102, "user output follows");
    }

    #[test]
    fn incremental_scan_rejects_noncanonical_coinbase_layout() {
        let owner = Address([0xA3; 32]);
        let late = block(
            vec![transaction(false, 20, owner), transaction(true, 10, owner)],
            102,
        );
        assert_eq!(
            derive_output_creation_ids(&late),
            Err(CreationIdDerivationError::CoinbaseNotFirst)
        );

        let duplicate = block(
            vec![transaction(true, 10, owner), transaction(true, 11, owner)],
            102,
        );
        assert_eq!(
            derive_output_creation_ids(&duplicate),
            Err(CreationIdDerivationError::MultipleCoinbase)
        );
    }

    #[test]
    fn full_scan_preserves_packed_creation_id() {
        let master = MasterSecret([0x31; 32]);
        let owner = master.derive_address(0);
        let mut state = SegmentedFriState::new_empty(6);
        state
            .set_slot(9, SlotValue::with_owner_fields(777, 55, owner.as_fields()))
            .unwrap();

        let (utxos, _, _) = scan_state_for_utxos(&state, &master, 12, 1);
        assert_eq!(utxos.len(), 1);
        assert_eq!(utxos[0].slot_index, 9);
        assert_eq!(utxos[0].value, 777);
        assert_eq!(utxos[0].creation_id, 55);
    }

    #[test]
    fn incremental_scan_rejects_counter_underflow_before_mutation() {
        let owner = Address([0xA2; 32]);
        let block = block(
            vec![transaction(true, 10, owner), transaction(false, 20, owner)],
            1,
        );
        let mut utxos = HashMap::new();
        let mut history = vec![];
        let mut receipts = HashMap::new();
        let known_addresses = HashMap::from([(owner.0, 0)]);
        let mut pending_inputs = std::collections::HashSet::new();

        update_wallet_from_block(
            &mut utxos,
            &mut history,
            &mut receipts,
            &known_addresses,
            &mut pending_inputs,
            &block,
        );

        assert!(utxos.is_empty());
        assert!(history.is_empty());
    }
}
