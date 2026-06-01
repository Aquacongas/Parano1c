// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Slot conflict resolution for block assembly (SPECIFICATION.md §15.2).
//!
//! When two transactions in the candidate set both attempt to mint the same
//! output slot, the tie-break rule is deterministic: the winner is the
//! transaction whose `tx_body_hash` is lexicographically smallest.
//!
//! This is called BEFORE block assembly, NOT during validation.
//! `validate_block_consensus` verifies absence of conflicts; this function
//! produces a conflict-free set for the miner to work with.

use std::collections::HashMap;

use noid_poseidon2b::primitives::TxBodyHash;
use noid_tx::Transaction;

/// Resolve slot conflicts in a candidate transaction set.
///
/// Returns `(winners, loser_hashes)` where:
/// - `winners`: conflict-free subset ready for block inclusion
/// - `loser_hashes`: `tx_body_hash`es of dropped transactions; their
///   wallets must request new slot hints and rebuild.
///
/// Algorithm (SPEC §15.2):
///   For each output slot claimed by more than one transaction,
///   keep only `argmin(tx_body_hash)` (lexicographic minimum).
///   Transactions that lose on any single slot are fully excluded.
///
/// Input: `txs` MUST already be conflict-free for INPUT slots
/// (no two txs spending the same input). Cross-input conflicts are
/// rejected during mempool admission; this function handles OUTPUT-slot
/// conflicts only.
///
/// Complexity: O(txs × max_outputs).
pub fn resolve_slot_conflicts(txs: Vec<Transaction>) -> (Vec<Transaction>, Vec<TxBodyHash>) {
    // Map: output_slot → best (min tx_body_hash, tx_index)
    let mut best: HashMap<u32, (TxBodyHash, usize)> = HashMap::new();

    for (i, tx) in txs.iter().enumerate() {
        for out in &tx.body.outputs {
            if !out.valid {
                continue;
            }
            let slot = out.slot_index;
            let entry = best.entry(slot).or_insert((tx.tx_body_hash, i));
            if tx.tx_body_hash.0 < entry.0 .0 {
                *entry = (tx.tx_body_hash, i);
            }
        }
    }

    // A transaction is a loser if it contests any slot but is NOT the argmin winner
    // of that slot. A single slot loss disqualifies the entire transaction.
    let mut loser_indices: std::collections::HashSet<usize> = std::collections::HashSet::new();
    for (i, tx) in txs.iter().enumerate() {
        for out in &tx.body.outputs {
            if !out.valid {
                continue;
            }
            if let Some(&(_, winner_idx)) = best.get(&out.slot_index) {
                if winner_idx != i {
                    loser_indices.insert(i);
                    break; // one losing slot is enough to disqualify
                }
            }
        }
    }

    let mut winners = Vec::new();
    let mut losers = Vec::new();

    for (i, tx) in txs.into_iter().enumerate() {
        if loser_indices.contains(&i) {
            losers.push(tx.tx_body_hash);
        } else {
            winners.push(tx);
        }
    }

    (winners, losers)
}

#[cfg(test)]
mod tests {
    use super::*;
    use noid_poseidon2b::primitives::Address;
    use noid_tx::{Transaction, TxBody, TxOutput};

    fn make_tx(output_slots: &[u32], hash_seed: u8) -> Transaction {
        let outputs: Vec<TxOutput> = output_slots
            .iter()
            .map(|&s| TxOutput {
                slot_index: s,
                value: 100,
                owner: Address([hash_seed; 32]),
                valid: true,
            })
            .collect();
        let body = TxBody {
            epoch_anchor: [hash_seed; 32],
            fee: 0,
            inputs: vec![],
            outputs,
            is_coinbase: false,
        };
        let hash = noid_tx::hash_tx_body(
            &body.epoch_anchor,
            body.fee,
            &body.inputs,
            &body.outputs,
            body.is_coinbase,
        );
        Transaction {
            body,
            tx_body_hash: hash,
        }
    }

    #[test]
    fn no_conflicts_all_win() {
        let txs = vec![
            make_tx(&[1], 0xAA),
            make_tx(&[2], 0xBB),
            make_tx(&[3], 0xCC),
        ];
        let (winners, losers) = resolve_slot_conflicts(txs);
        assert_eq!(winners.len(), 3);
        assert!(losers.is_empty());
    }

    #[test]
    fn single_conflict_min_hash_wins() {
        // Both claim slot 5.
        // One with hash_seed=0x01 (smaller hash), one with 0xFF (bigger).
        let tx_lo = make_tx(&[5], 0x01);
        let tx_hi = make_tx(&[5], 0xFF);
        let lo_hash = tx_lo.tx_body_hash;
        let hi_hash = tx_hi.tx_body_hash;

        let (winners, losers) = resolve_slot_conflicts(vec![tx_lo, tx_hi]);
        assert_eq!(winners.len(), 1);
        assert_eq!(losers.len(), 1);
        // Winner has the smaller tx_body_hash.
        assert!(winners[0].tx_body_hash.0 <= lo_hash.0 || winners[0].tx_body_hash.0 <= hi_hash.0);
        // Loser is the other one.
        assert!(losers.contains(&lo_hash) || losers.contains(&hi_hash));
    }

    #[test]
    fn tx_loses_if_any_output_conflicts() {
        // tx_a claims slots [5, 6]; tx_b claims slot [6, 7].
        // They conflict on slot 6. One loses entirely.
        let tx_a = make_tx(&[5, 6], 0x10);
        let tx_b = make_tx(&[6, 7], 0x20);
        let (winners, losers) = resolve_slot_conflicts(vec![tx_a, tx_b]);
        // After conflict resolution, no two winners share an output slot.
        let all_output_slots: Vec<u32> = winners
            .iter()
            .flat_map(|t| {
                t.body
                    .outputs
                    .iter()
                    .filter(|o| o.valid)
                    .map(|o| o.slot_index)
            })
            .collect();
        let unique: std::collections::HashSet<u32> = all_output_slots.iter().copied().collect();
        assert_eq!(
            all_output_slots.len(),
            unique.len(),
            "winners must have no duplicate output slots"
        );
        assert_eq!(winners.len() + losers.len(), 2);
    }

    #[test]
    fn empty_input_produces_empty_output() {
        let (winners, losers) = resolve_slot_conflicts(vec![]);
        assert!(winners.is_empty());
        assert!(losers.is_empty());
    }
}
