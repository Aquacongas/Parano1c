// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! ParanoidReceipt — unforgeable proof of transaction inclusion.
//!
//! Reference for Merkle inclusion proof structure:
//!   Bitcoin Core `src/merkle.cpp` (transaction inclusion proofs).
//!   Grin `core/src/core/transaction.rs` (output Merkle paths).
//!
//! # Verification algorithm
//!
//! **Merkle inclusion** (offline): Poseidon2b COMPRESS binary tree.
//!   Must match `noid_chain::block::compute_tx_root` exactly.
//!   Poseidon2b is used because the tx_root feeds into the BlockProof spine and
//!   must stay in the arithmetic consensus hash domain.
//! **Header lookup** (online): `getHeaderByHeight(claimed_height)` → check `tx_root`.
//! **Chain cert verify** (offline): `verify_tip(chain_cert, ...)` with embedded proof.

use crate::block_header::BlockHeader;
use crate::tx_tree;
use noid_poseidon2b::primitives::Address;
use noid_tx::TxBody;

const RECEIPT_CONSTRUCTION_MARKER: u8 = 0x01;

/// Compact summary of a transaction (public on-chain data only).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TxSummary {
    pub tx_body_hash: [u8; 32],
    pub inputs: Vec<(u32, Address)>,
    pub outputs: Vec<(u32, u64, Address)>,
    pub fee_micronoid: u64,
    pub confirmed_height: u64,
    pub confirmed_unix: u64,
}

/// Cryptographic proof that a transaction is in the canonical chain.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ParanoidReceipt {
    /// Fixed construction marker. This is not a negotiable protocol version.
    pub construction_marker: u8,
    /// Canonical authenticated Tx8x2 body bytes. Its derived txid is the leaf.
    pub tx_body: Vec<u8>,
    /// Logical position in the universal namespace. Directions derive from it.
    pub tx_index: u16,
    /// Real block transaction count, including the mandatory coinbase.
    pub tx_count: u16,
    /// Sibling hashes along the Merkle path (leaf → root), always depth 8.
    pub merkle_path: [[u8; 32]; tx_tree::TX_TREE_DEPTH],
    pub claimed_root: [u8; 32],
    pub claimed_height: u64,
    pub summary: TxSummary,
    pub chain_cert: Option<Vec<u8>>,
}

impl ParanoidReceipt {
    /// Serialize to compact bincode bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("ParanoidReceipt serialize")
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiptVerifyResult {
    pub merkle_valid: bool,
    pub canonical: Option<bool>,
    pub confirmed: bool,
}

impl ReceiptVerifyResult {
    pub fn is_confirmed(&self) -> bool {
        self.confirmed
    }
}

/// Generate a receipt for a confirmed transaction.
pub fn generate_receipt(
    header: &BlockHeader,
    tx_body: &TxBody,
    tx_index: usize,
    block_tx_hashes: &[[u8; 32]],
    chain_cert: Option<Vec<u8>>,
) -> ParanoidReceipt {
    let tx_body_hash = tx_body.txid().0;
    assert_eq!(block_tx_hashes.get(tx_index), Some(&tx_body_hash));
    let merkle_path = tx_tree::path_from_hashes(block_tx_hashes, tx_index);
    let summary = summary_from_body(tx_body, header.height, header.timestamp);
    ParanoidReceipt {
        construction_marker: RECEIPT_CONSTRUCTION_MARKER,
        tx_body: tx_body.to_bytes().to_vec(),
        tx_index: tx_index as u16,
        tx_count: block_tx_hashes.len() as u16,
        merkle_path,
        claimed_root: header.tx_root,
        claimed_height: header.height,
        summary,
        chain_cert,
    }
}

/// Derive every payment-relevant summary field from the authenticated body.
pub fn summary_from_body(body: &TxBody, confirmed_height: u64, confirmed_unix: u64) -> TxSummary {
    TxSummary {
        tx_body_hash: body.txid().0,
        inputs: body
            .live_inputs()
            .map(|(_, input)| (input.slot_index, body.input_owner))
            .collect(),
        outputs: body
            .live_outputs()
            .map(|(_, output)| (output.slot_index, output.amount, output.owner))
            .collect(),
        fee_micronoid: body.fee,
        confirmed_height,
        confirmed_unix,
    }
}

/// Verify Merkle inclusion (offline). Returns true iff tx is in claimed_root.
///
/// Also checks summary_hash so an attacker cannot forge payment data
/// (amounts, addresses) while keeping the Merkle proof valid.
///
/// Uses Poseidon2b COMPRESS to match `compute_tx_root` in `noid_chain::block`.
pub fn verify_merkle_inclusion(receipt: &ParanoidReceipt) -> bool {
    if receipt.construction_marker != RECEIPT_CONSTRUCTION_MARKER {
        return false;
    }
    let Ok(body) = TxBody::from_bytes(&receipt.tx_body) else {
        return false;
    };
    let expected_summary = summary_from_body(
        &body,
        receipt.claimed_height,
        receipt.summary.confirmed_unix,
    );
    if receipt.summary != expected_summary {
        return false;
    }

    // Fixed-depth Merkle path plus the header's real-count wrapper.
    tx_tree::verify_path(
        body.txid().0,
        &receipt.merkle_path,
        usize::from(receipt.tx_index),
        usize::from(receipt.tx_count),
        receipt.claimed_root,
    )
}

/// Verify receipt against a canonical header (online step).
pub fn verify_against_header(receipt: &ParanoidReceipt, canonical_header: &BlockHeader) -> bool {
    canonical_header.height == receipt.claimed_height
        && canonical_header.tx_root == receipt.claimed_root
        && canonical_header.timestamp == receipt.summary.confirmed_unix
}

/// Compute the tx_root from a list of tx_body_hashes.
/// Mirrors `compute_tx_root` in `noid_chain::block`.
pub fn tx_root(tx_hashes: &[[u8; 32]]) -> [u8; 32] {
    tx_tree::root_from_hashes(tx_hashes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::params::GENESIS_TARGET;
    use noid_tx::{output_bitmap_bit, TxInput, TxOutput, TX_INPUTS, TX_OUTPUTS};

    fn body(index: u16) -> TxBody {
        let mut inputs = [TxInput::dummy(); TX_INPUTS];
        inputs[0] = TxInput {
            slot_index: u32::from(index) + 1,
            amount: u64::from(index) + 10,
            creation_id: 1,
        };
        let mut outputs = [TxOutput::dummy(); TX_OUTPUTS];
        outputs[0] = TxOutput {
            slot_index: u32::from(index) + 1_000,
            amount: u64::from(index) + 9,
            owner: Address([2u8; 32]),
        };
        let mut anchor = [0u8; 32];
        anchor[..2].copy_from_slice(&index.to_le_bytes());
        anchor[2] = 1;
        TxBody {
            epoch_anchor: anchor,
            fee: 1,
            input_owner: Address([1u8; 32]),
            inputs,
            outputs,
            validity_bitmap: 1 | output_bitmap_bit(0),
            is_coinbase: false,
        }
    }

    fn header(height: u64, root: [u8; 32]) -> BlockHeader {
        BlockHeader {
            prev_block_hash: [0u8; 32],
            state_root: [0u8; 32],
            tx_root: root,
            timestamp: 1_700_000_000,
            height,
            miner_address: Address([0u8; 32]),
            nonce: 0,
            difficulty_target: GENESIS_TARGET,
            log_slots: 24,
            active_slot_count: 0,
            alloc_counter: 0,
        }
    }

    #[test]
    fn all_256_positions_have_authenticated_fixed_paths() {
        let bodies: Vec<_> = (0..256).map(body).collect();
        let hashes: Vec<_> = bodies.iter().map(|body| body.txid().0).collect();
        let header = header(10, tx_root(&hashes));
        for (index, body) in bodies.iter().enumerate() {
            let receipt = generate_receipt(&header, body, index, &hashes, None);
            assert_eq!(receipt.merkle_path.len(), 8);
            assert!(verify_merkle_inclusion(&receipt), "index {index}");
            assert!(verify_against_header(&receipt, &header));
            assert_eq!(
                ParanoidReceipt::from_bytes(&receipt.to_bytes())
                    .unwrap()
                    .tx_body,
                receipt.tx_body
            );
        }
    }

    #[test]
    fn body_summary_count_index_and_header_tamper_fail() {
        let bodies = [body(1), body(2), body(3)];
        let hashes: Vec<_> = bodies.iter().map(|body| body.txid().0).collect();
        let header = header(5, tx_root(&hashes));
        let receipt = generate_receipt(&header, &bodies[1], 1, &hashes, None);

        let mut bad = receipt.clone();
        bad.tx_body[80] ^= 1;
        assert!(!verify_merkle_inclusion(&bad));

        let mut bad = receipt.clone();
        bad.summary.outputs[0].1 += 1;
        assert!(!verify_merkle_inclusion(&bad));

        let mut bad = receipt.clone();
        bad.tx_count = 2;
        assert!(!verify_merkle_inclusion(&bad));

        let mut bad = receipt.clone();
        bad.tx_index = 2;
        assert!(!verify_merkle_inclusion(&bad));

        let mut other_header = header;
        other_header.timestamp += 1;
        assert!(!verify_against_header(&receipt, &other_header));
    }

    #[test]
    fn real_count_is_bound_even_with_zero_suffix() {
        let hashes = [body(1).txid().0, body(2).txid().0];
        assert_ne!(tx_root(&hashes[..1]), tx_root(&hashes));
        assert_eq!(tx_root(&[]), [0u8; 32]);
    }
}
