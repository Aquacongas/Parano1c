// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Incremental active-address wallet updates from accepted blocks.
//!
//! # Architecture
//!
//! Blocks are pruned after application, so this hook consumes accepted block
//! bodies while they are available. It never discovers inactive accounts.
//!
//! ## Incremental update (new block)
//!
//! O(block_size): check outputs for the one active address, remove spent inputs.
//! Startup, explicit reload, snapshot install, and reorg recovery use the
//! durable verified owner index instead of traversing state here.

use std::collections::HashMap;

use super::state::{TxDirection, TxHistoryEntry, WalletUtxo};
use noid_chain::block::Block;
use noid_chain::consensus::receipt::generate_receipt;

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
        .flat_map(|tx| tx.body.live_outputs())
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
        for (output_index, _output) in tx.body.outputs.iter().enumerate() {
            if !tx.body.output_is_live(output_index) {
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

/// Record history and receipts from an accepted block without touching the
/// active UTXO cache. Reorg recovery uses this after installing one exact
/// post-reorg owner snapshot; replaying replacement deltas onto the old branch
/// cache would make balance and sent-value inference transiently incorrect.
pub fn update_wallet_artifacts_from_block(
    history: &mut Vec<TxHistoryEntry>,
    receipts: &mut HashMap<[u8; 32], Vec<u8>>,
    active_address: noid_poseidon2b::primitives::Address,
    active_index: u32,
    block: &Block,
) {
    let block_tx_hashes: Vec<[u8; 32]> = block
        .transactions
        .iter()
        .map(|transaction| transaction.txid().0)
        .collect();
    let pending_hashes: std::collections::HashSet<[u8; 32]> = history
        .iter()
        .filter(|entry| entry.height == 0 && entry.direction == TxDirection::Sent)
        .map(|entry| entry.tx_hash)
        .collect();
    let existing_confirmed: std::collections::HashSet<[u8; 32]> = history
        .iter()
        .filter(|entry| entry.height != 0)
        .map(|entry| entry.tx_hash)
        .collect();

    for (tx_index, tx) in block.transactions.iter().enumerate() {
        let tx_hash = tx.txid().0;
        let pending_send = pending_hashes.contains(&tx_hash);

        if pending_send {
            let receipt =
                generate_receipt(&block.header, &tx.body, tx_index, &block_tx_hashes, None);
            receipts.insert(tx_hash, receipt.to_bytes());
            continue;
        }

        if existing_confirmed.contains(&tx_hash) {
            continue;
        }
        let received = tx
            .body
            .live_outputs()
            .map(|(_, output)| output)
            .filter(|output| output.owner == active_address)
            .map(|output| output.amount)
            .fold(0u64, u64::saturating_add);
        if received == 0 {
            continue;
        }
        history.push(TxHistoryEntry {
            tx_hash,
            height: block.header.height,
            direction: TxDirection::Received,
            amount_micronoid: received,
            peer_address: None,
            timestamp: block.header.timestamp,
            own_address: Some(active_address.to_bech32()),
            own_key_index: Some(active_index),
        });
    }
}

/// Update wallet state based on a newly confirmed block.
///
/// Must be called BEFORE block pruning (while transactions are still available).
/// O(block_size).
///
/// Updates:
/// - Removes spent UTXOs (inputs consumed by this block)
/// - Adds new UTXOs (outputs addressed to this wallet)
/// - Appends to tx history
/// - Generates and stores Merkle receipts for all wallet-relevant transactions
/// - Clears confirmed input slots from `pending_input_slots`
pub fn update_active_wallet_from_block(
    utxos: &mut HashMap<u32, WalletUtxo>,
    history: &mut Vec<TxHistoryEntry>,
    receipts: &mut HashMap<[u8; 32], Vec<u8>>,
    active_address: noid_poseidon2b::primitives::Address,
    active_index: u32,
    pending_input_slots: &mut std::collections::HashSet<u32>,
    block: &Block,
) -> Result<(), String> {
    let height = block.header.height;
    let timestamp = block.header.timestamp;

    // Derive the complete map before mutating wallet state. Consensus-valid
    // blocks always satisfy this relation; rejecting the update here avoids
    // inventing or wrapping an incarnation if corrupt/unvalidated data reaches
    // the product hook.
    let output_creation_ids = derive_output_creation_ids(block).map_err(|error| {
        format!(
            "wallet block h={height} has invalid creation-id sequence at alloc_counter {}: {error}",
            block.header.alloc_counter
        )
    })?;

    let block_tx_hashes: Vec<[u8; 32]> = block
        .transactions
        .iter()
        .map(|transaction| transaction.txid().0)
        .collect();

    // Build once before the loop: O(history) instead of O(history × txs).
    let pending_hashes: std::collections::HashSet<[u8; 32]> = history
        .iter()
        .filter(|e| e.height == 0)
        .map(|e| e.tx_hash)
        .collect();

    for (tx_index, tx) in block.transactions.iter().enumerate() {
        let tx_hash = tx.txid().0;
        if tx.body.is_coinbase {
            // Coinbase: track UTXOs for our addresses, record history.
            // No receipt — receipts are proof-of-payment for OUTGOING txs only.
            for (output_index, output) in tx.body.outputs.iter().enumerate() {
                if !tx.body.output_is_live(output_index) {
                    continue;
                }
                let Some(creation_id) = output_creation_ids[tx_index][output_index] else {
                    return Err(format!(
                        "wallet block h={height} is missing creation id for live coinbase output {tx_index}:{output_index}"
                    ));
                };
                if output.owner == active_address {
                    let utxo = WalletUtxo {
                        slot_index: output.slot_index,
                        value: output.amount,
                        creation_id,
                        address: output.owner,
                        key_index: active_index,
                        confirmed_height: height,
                    };
                    utxos.insert(output.slot_index, utxo);
                    let addr_str = output.owner.to_bech32();
                    history.push(TxHistoryEntry {
                        tx_hash,
                        height,
                        direction: TxDirection::Received,
                        amount_micronoid: output.amount,
                        peer_address: None,
                        timestamp,
                        own_address: Some(addr_str),
                        own_key_index: Some(active_index),
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
        for (_, input) in tx.body.live_inputs() {
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
            if !tx.body.output_is_live(output_index) {
                continue;
            }
            let Some(creation_id) = output_creation_ids[tx_index][output_index] else {
                return Err(format!(
                    "wallet block h={height} is missing creation id for live user output {tx_index}:{output_index}"
                ));
            };
            if output.owner == active_address {
                let utxo = WalletUtxo {
                    slot_index: output.slot_index,
                    value: output.amount,
                    creation_id,
                    address: output.owner,
                    key_index: active_index,
                    confirmed_height: height,
                };
                utxos.insert(output.slot_index, utxo);
                received_by_wallet = received_by_wallet.saturating_add(output.amount);
                // Track the first received-to address as the "own" receiving address.
                if recv_own_address.is_none() {
                    recv_own_address = Some(output.owner.to_bech32());
                    recv_own_key_index = Some(active_index);
                }
            }
        }

        // Record history entry.
        // Skip if this tx_hash is already in history as a pending (height=0) entry
        // from record_pending_send — confirm_pending_tx will update the height.
        let already_pending = pending_hashes.contains(&tx_hash);

        if !already_pending {
            if sent_from_wallet > 0 {
                let net_sent = sent_from_wallet.saturating_sub(received_by_wallet);
                history.push(TxHistoryEntry {
                    tx_hash,
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
                    tx_hash,
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

        // A locally pending send remains ours even if the user switched away
        // from its source address before confirmation. In that case its input
        // is intentionally absent from the active-address cache, so the durable
        // pending history tag is the ownership signal for receipt generation.
        // Incoming-only transactions still need no receipt.
        if sent_from_wallet > 0 || already_pending {
            let receipt =
                generate_receipt(&block.header, &tx.body, tx_index, &block_tx_hashes, None);
            receipts.insert(tx_hash, receipt.to_bytes());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use noid_chain::block_header::BlockHeader;
    use noid_poseidon2b::primitives::Address;
    use noid_tx::{
        TX_INPUTS, TX_OUTPUTS, Transaction, TxBody, TxInput, TxOutput, output_bitmap_bit,
    };

    fn transaction(is_coinbase: bool, slot_index: u32, owner: Address) -> Transaction {
        let amount = u64::from(slot_index) + 100;
        let mut inputs = [TxInput::dummy(); TX_INPUTS];
        if !is_coinbase {
            inputs[0] = TxInput {
                slot_index: slot_index + 1_000,
                amount,
                creation_id: 1,
            };
        }
        let mut outputs = [TxOutput::dummy(); TX_OUTPUTS];
        outputs[0] = TxOutput {
            slot_index,
            amount,
            owner,
        };
        Transaction::new(TxBody {
            epoch_anchor: if is_coinbase { [0; 32] } else { [1; 32] },
            fee: 0,
            input_owner: if is_coinbase {
                Address([0; 32])
            } else {
                Address([0xEE; 32])
            },
            inputs,
            outputs,
            validity_bitmap: output_bitmap_bit(0) | u16::from(!is_coinbase),
            is_coinbase,
        })
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
        let mut pending_inputs = std::collections::HashSet::new();

        update_active_wallet_from_block(
            &mut utxos,
            &mut history,
            &mut receipts,
            owner,
            3,
            &mut pending_inputs,
            &block,
        )
        .unwrap();

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
    fn incremental_scan_rejects_counter_underflow_before_mutation() {
        let owner = Address([0xA2; 32]);
        let block = block(
            vec![transaction(true, 10, owner), transaction(false, 20, owner)],
            1,
        );
        let mut utxos = HashMap::new();
        let mut history = vec![];
        let mut receipts = HashMap::new();
        let mut pending_inputs = std::collections::HashSet::new();

        assert!(
            update_active_wallet_from_block(
                &mut utxos,
                &mut history,
                &mut receipts,
                owner,
                0,
                &mut pending_inputs,
                &block,
            )
            .is_err()
        );

        assert!(utxos.is_empty());
        assert!(history.is_empty());
    }

    #[test]
    fn incremental_update_ignores_inactive_owner_outputs() {
        let active = Address([0xA4; 32]);
        let inactive = Address([0xA5; 32]);
        let block = block(vec![transaction(true, 10, inactive)], 1);
        let mut utxos = HashMap::new();
        let mut history = vec![];
        let mut receipts = HashMap::new();
        let mut pending_inputs = std::collections::HashSet::new();

        update_active_wallet_from_block(
            &mut utxos,
            &mut history,
            &mut receipts,
            active,
            0,
            &mut pending_inputs,
            &block,
        )
        .unwrap();

        assert!(utxos.is_empty());
        assert!(history.is_empty());
    }

    #[test]
    fn pending_send_gets_receipt_after_source_account_becomes_inactive() {
        let active = Address([0xA6; 32]);
        let inactive_source = Address([0xA7; 32]);
        let coinbase = transaction(true, 10, Address([0xCC; 32]));
        let outgoing = transaction(false, 20, Address([0xBB; 32]));
        let outgoing_hash = outgoing.txid().0;
        let block = block(vec![coinbase, outgoing], 2);
        let mut utxos = HashMap::new();
        let mut history = vec![TxHistoryEntry {
            tx_hash: outgoing_hash,
            height: 0,
            direction: TxDirection::Sent,
            amount_micronoid: 123,
            peer_address: Some([0xBB; 32]),
            timestamp: 1,
            own_address: Some(inactive_source.to_bech32()),
            own_key_index: Some(9),
        }];
        let mut receipts = HashMap::new();
        let mut pending_inputs = std::collections::HashSet::new();

        update_active_wallet_from_block(
            &mut utxos,
            &mut history,
            &mut receipts,
            active,
            0,
            &mut pending_inputs,
            &block,
        )
        .unwrap();

        assert!(receipts.contains_key(&outgoing_hash));
        assert_eq!(history.len(), 1, "pending history must not be duplicated");
        assert_eq!(history[0].own_key_index, Some(9));
    }

    #[test]
    fn reorg_artifact_replay_does_not_need_or_mutate_utxo_cache() {
        let active = Address([0xD1; 32]);
        let inactive_source = Address([0xD2; 32]);
        let coinbase = transaction(true, 10, Address([0xCC; 32]));
        let outgoing = transaction(false, 20, Address([0xBB; 32]));
        let outgoing_hash = outgoing.txid().0;
        let block = block(vec![coinbase, outgoing], 2);
        let mut history = vec![TxHistoryEntry {
            tx_hash: outgoing_hash,
            height: 0,
            direction: TxDirection::Sent,
            amount_micronoid: 123,
            peer_address: Some([0xBB; 32]),
            timestamp: 1,
            own_address: Some(inactive_source.to_bech32()),
            own_key_index: Some(9),
        }];
        let mut receipts = HashMap::new();

        update_wallet_artifacts_from_block(&mut history, &mut receipts, active, 0, &block);

        assert!(receipts.contains_key(&outgoing_hash));
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].own_key_index, Some(9));
    }
}
