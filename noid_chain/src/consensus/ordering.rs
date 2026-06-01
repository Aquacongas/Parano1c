// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Canonical transaction ordering for block assembly (ROADMAP Phase 1 P.25).
//!
//! This is **miner policy**, not consensus. The block validator only checks
//! that `tx_root == compute_tx_root(block.transactions)` — it does NOT
//! enforce this specific ordering. Two valid blocks from different miners
//! MAY have different orderings of the same transaction set.
//!
//! # Canonical rule (proposed for SPECIFICATION.md §7)
//!
//! 1. Coinbase transaction first (if present).
//! 2. Remaining transactions: descending fee (largest fee first).
//! 3. Tie-break: ascending `tx_body_hash` (lexicographic).
//!
//! This rule is deterministic, fee-incentive-compatible, and easy to replicate.

use noid_tx::Transaction;

/// Order transactions for block assembly using the canonical rule.
///
/// Coinbase is placed first. Non-coinbase txs are sorted by descending fee,
/// then ascending tx_body_hash for equal-fee ties.
///
/// This is O(n log n). Call after `resolve_slot_conflicts`.
pub fn order_block_txs(mut txs: Vec<Transaction>) -> Vec<Transaction> {
    // Stable partition: coinbase first.
    txs.sort_by(|a, b| {
        let a_cb = a.body.is_coinbase;
        let b_cb = b.body.is_coinbase;
        match (a_cb, b_cb) {
            (true, false) => std::cmp::Ordering::Less,
            (false, true) => std::cmp::Ordering::Greater,
            _ => {
                // Both same type: sort by descending fee, then ascending hash.
                b.body
                    .fee
                    .cmp(&a.body.fee)
                    .then_with(|| a.tx_body_hash.0.cmp(&b.tx_body_hash.0))
            }
        }
    });
    txs
}

#[cfg(test)]
mod tests {
    use super::*;
    use noid_poseidon2b::primitives::Address;
    use noid_tx::{Transaction, TxBody, TxOutput};

    fn make_tx(fee: u128, hash_seed: u8, coinbase: bool) -> Transaction {
        let body = TxBody {
            epoch_anchor: if coinbase { [0u8; 32] } else { [hash_seed; 32] },
            fee,
            inputs: vec![],
            outputs: vec![TxOutput {
                slot_index: hash_seed as u32,
                value: 100,
                owner: Address([hash_seed; 32]),
                valid: true,
            }],
            is_coinbase: coinbase,
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
    fn coinbase_is_first() {
        let cb = make_tx(0, 0, true);
        let tx1 = make_tx(1000, 1, false);
        let tx2 = make_tx(2000, 2, false);
        let ordered = order_block_txs(vec![tx1, cb, tx2]);
        assert!(ordered[0].body.is_coinbase, "coinbase must be first");
    }

    #[test]
    fn descending_fee_order() {
        let tx_lo = make_tx(100, 1, false);
        let tx_hi = make_tx(9000, 2, false);
        let tx_mid = make_tx(500, 3, false);
        let ordered = order_block_txs(vec![tx_lo, tx_hi, tx_mid]);
        let fees: Vec<u128> = ordered.iter().map(|t| t.body.fee).collect();
        for i in 0..fees.len() - 1 {
            assert!(fees[i] >= fees[i + 1], "fees must be non-increasing");
        }
    }

    #[test]
    fn equal_fee_tiebreak_by_hash() {
        let tx_a = make_tx(500, 0x01, false); // likely smaller hash
        let tx_b = make_tx(500, 0xFF, false); // likely larger hash
        let ordered = order_block_txs(vec![tx_b.clone(), tx_a.clone()]);
        // Ascending tx_body_hash tie-break.
        assert!(ordered[0].tx_body_hash.0 <= ordered[1].tx_body_hash.0);
    }

    #[test]
    fn empty_input_is_ok() {
        let ordered = order_block_txs(vec![]);
        assert!(ordered.is_empty());
    }

    #[test]
    fn single_tx_unchanged() {
        let tx = make_tx(500, 0xAA, false);
        let hash = tx.tx_body_hash;
        let ordered = order_block_txs(vec![tx]);
        assert_eq!(ordered[0].tx_body_hash, hash);
    }
}
