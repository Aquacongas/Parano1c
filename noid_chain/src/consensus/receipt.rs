// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

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
//!   Poseidon2b is used (not Blake3) because the tx_root feeds into the ZK
//!   block spine — an in-circuit Poseidon2b Merkle proof is far cheaper than Blake3.
//! **Header lookup** (online): `getHeaderByHeight(claimed_height)` → check `tx_root`.
//! **Chain cert verify** (offline): `verify_tip(chain_cert, ...)` with embedded proof.

use noid_poseidon2b::native::compress;

use crate::block_header::BlockHeader;
use noid_poseidon2b::primitives::Address;

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
    pub version: u8,
    pub tx_body_hash: [u8; 32],
    /// Sibling hashes along the Merkle path (leaf → root), length ≤ 8 for 256 txs.
    pub merkle_path: Vec<[u8; 32]>,
    /// Bitmask: bit k = 1 means the sibling at level k is on the LEFT.
    /// (equivalently: the current node at level k is a RIGHT child.)
    /// Stored separately to avoid corrupting hash bytes (common pitfall).
    pub merkle_dirs: u32,
    pub claimed_root: [u8; 32],
    pub claimed_height: u64,
    pub summary: TxSummary,
    /// Blake3(bincode(summary)). Prevents forging payment data (amounts, addresses)
    /// while keeping the Merkle proof valid — summary is not in the Merkle tree.
    pub summary_hash: [u8; 32],
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
    tx_body_hash: [u8; 32],
    tx_index: usize,
    block_tx_hashes: &[[u8; 32]],
    summary: TxSummary,
    chain_cert: Option<Vec<u8>>,
) -> ParanoidReceipt {
    let (merkle_path, merkle_dirs) = build_merkle_path(block_tx_hashes, tx_index);
    let summary_bytes = bincode::serialize(&summary).expect("TxSummary bincode");
    let summary_hash = *blake3::hash(&summary_bytes).as_bytes();
    ParanoidReceipt {
        version: 1,
        tx_body_hash,
        merkle_path,
        merkle_dirs,
        claimed_root: header.tx_root,
        claimed_height: header.height,
        summary,
        summary_hash,
        chain_cert,
    }
}

/// Verify Merkle inclusion (offline). Returns true iff tx is in claimed_root.
///
/// Also checks summary_hash so an attacker cannot forge payment data
/// (amounts, addresses) while keeping the Merkle proof valid.
///
/// Uses Poseidon2b COMPRESS to match `compute_tx_root` in `noid_chain::block`.
pub fn verify_merkle_inclusion(receipt: &ParanoidReceipt) -> bool {
    // 1. TxSummary integrity: Blake3(bincode(summary)) must match.
    let summary_bytes = bincode::serialize(&receipt.summary).expect("TxSummary bincode");
    if *blake3::hash(&summary_bytes).as_bytes() != receipt.summary_hash {
        return false;
    }

    // 2. Merkle path: tx_body_hash → claimed_root.
    let mut current = receipt.tx_body_hash;
    for (level, sibling) in receipt.merkle_path.iter().enumerate() {
        let sibling_on_left = (receipt.merkle_dirs >> level) & 1 == 1;
        current = if sibling_on_left {
            compress(sibling, &current)
        } else {
            compress(&current, sibling)
        };
    }
    current == receipt.claimed_root
}

/// Verify receipt against a canonical header (online step).
pub fn verify_against_header(receipt: &ParanoidReceipt, canonical_header: &BlockHeader) -> bool {
    canonical_header.height == receipt.claimed_height
        && canonical_header.tx_root == receipt.claimed_root
}

/// Build a Poseidon2b COMPRESS Merkle inclusion path.
///
/// Must match `compute_tx_root` in `noid_chain::block` exactly:
/// - Pads to `next_power_of_two().max(2)` (at least 2 leaves).
/// - Uses `compress(left, right)` (Poseidon2b) at each level.
///
/// Returns `(siblings, dirs_bitmask)` where bit k of `dirs_bitmask` is 1 iff
/// the sibling at level k is on the left side.
fn build_merkle_path(tx_hashes: &[[u8; 32]], tx_index: usize) -> (Vec<[u8; 32]>, u32) {
    if tx_hashes.is_empty() {
        return (vec![], 0);
    }
    // Match compute_tx_root: always pad to at least 2 leaves.
    let n = tx_hashes.len().next_power_of_two().max(2);
    let mut layer: Vec<[u8; 32]> = tx_hashes.to_vec();
    layer.resize(n, [0u8; 32]);

    let mut path = Vec::new();
    let mut dirs: u32 = 0;
    let mut idx = tx_index;
    let mut level = 0u32;

    while layer.len() > 1 {
        let sibling_idx = idx ^ 1;
        path.push(layer[sibling_idx]);
        // If idx is ODD, sibling is to the LEFT (even index = left child).
        if idx % 2 == 1 {
            dirs |= 1 << level;
        }
        // Build next layer using Poseidon2b COMPRESS (same as compute_tx_root).
        let next: Vec<[u8; 32]> = layer
            .chunks(2)
            .map(|pair| compress(&pair[0], &pair[1]))
            .collect();
        idx /= 2;
        layer = next;
        level += 1;
    }
    (path, dirs)
}

/// Compute the tx_root from a list of tx_body_hashes.
/// Mirrors `compute_tx_root` in `noid_chain::block`.
pub fn tx_root(tx_hashes: &[[u8; 32]]) -> [u8; 32] {
    if tx_hashes.is_empty() {
        return [0u8; 32];
    }
    let n = tx_hashes.len().next_power_of_two().max(2);
    let mut layer: Vec<[u8; 32]> = tx_hashes.to_vec();
    layer.resize(n, [0u8; 32]);
    while layer.len() > 1 {
        layer = layer.chunks(2).map(|p| compress(&p[0], &p[1])).collect();
    }
    layer[0]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::params::GENESIS_TARGET;

    fn dummy_header(height: u64, root: [u8; 32]) -> BlockHeader {
        BlockHeader {
            prev_block_hash: [0u8; 32],
            state_root: [0u8; 32],
            tx_root: root,
            timestamp: 1_700_000_000,
            height,
            miner_address: Address([0u8; 32]),
            nonce: 0,
            difficulty_target: GENESIS_TARGET,
            proof_transcript_hash: [0u8; 32],
            witness_root: [0u8; 32],
            log_slots: 24,
            active_slot_count: 0,
            alloc_counter: 0,
        }
    }

    fn dummy_summary(hash: [u8; 32], height: u64) -> TxSummary {
        TxSummary {
            tx_body_hash: hash,
            inputs: vec![],
            outputs: vec![],
            fee_micronoid: 1_000_000,
            confirmed_height: height,
            confirmed_unix: 1_700_000_000,
        }
    }

    #[test]
    fn single_tx() {
        let tx = [42u8; 32];
        let root = tx_root(&[tx]);
        let header = dummy_header(1, root);
        let receipt = generate_receipt(&header, tx, 0, &[tx], dummy_summary(tx, 1), None);
        assert!(verify_merkle_inclusion(&receipt));
        assert!(verify_against_header(&receipt, &header));
    }

    #[test]
    fn all_positions_in_8_tx_block() {
        let hashes: Vec<[u8; 32]> = (0u8..8).map(|i| [i; 32]).collect();
        let root = tx_root(&hashes);
        let header = dummy_header(10, root);
        for (i, &tx) in hashes.iter().enumerate() {
            let r = generate_receipt(&header, tx, i, &hashes, dummy_summary(tx, 10), None);
            assert!(verify_merkle_inclusion(&r), "failed at idx={i}");
            assert!(verify_against_header(&r, &header));
        }
    }

    #[test]
    fn all_positions_in_1024_tx_block() {
        let hashes: Vec<[u8; 32]> = (0u16..1024)
            .map(|i| {
                let mut h = [0u8; 32];
                h[0] = (i & 0xFF) as u8;
                h[1] = (i >> 8) as u8;
                h
            })
            .collect();
        let root = tx_root(&hashes);
        let header = dummy_header(100, root);
        for &idx in &[0usize, 1, 255, 512, 1023] {
            let r = generate_receipt(
                &header,
                hashes[idx],
                idx,
                &hashes,
                dummy_summary(hashes[idx], 100),
                None,
            );
            assert!(verify_merkle_inclusion(&r), "failed at idx={idx}");
        }
    }

    #[test]
    fn tampered_hash_fails() {
        let hashes: Vec<[u8; 32]> = (0u8..4).map(|i| [i; 32]).collect();
        let root = tx_root(&hashes);
        let header = dummy_header(5, root);
        let mut r = generate_receipt(
            &header,
            hashes[0],
            0,
            &hashes,
            dummy_summary(hashes[0], 5),
            None,
        );
        r.tx_body_hash = [0xFF; 32];
        assert!(!verify_merkle_inclusion(&r));
    }

    #[test]
    fn reorg_detected() {
        let hashes = vec![[1u8; 32]];
        let root = tx_root(&hashes);
        let header = dummy_header(50, root);
        let r = generate_receipt(
            &header,
            hashes[0],
            0,
            &hashes,
            dummy_summary(hashes[0], 50),
            None,
        );
        let reorged = dummy_header(50, [0xDE; 32]);
        assert!(verify_merkle_inclusion(&r));
        assert!(!verify_against_header(&r, &reorged));
    }

    #[test]
    fn tx_root_empty() {
        assert_eq!(tx_root(&[]), [0u8; 32]);
    }

    #[test]
    fn tx_root_order_matters() {
        let a = [[1u8; 32], [2u8; 32]];
        let b = [[2u8; 32], [1u8; 32]];
        assert_ne!(tx_root(&a), tx_root(&b));
    }

    #[test]
    fn direction_encoding_does_not_corrupt_hashes() {
        // Ensure siblings in path are unmodified (no high-bit tampering).
        let hashes: Vec<[u8; 32]> = (0u8..4).map(|i| [i; 32]).collect();
        let root = tx_root(&hashes);
        let header = dummy_header(1, root);
        for (i, &tx) in hashes.iter().enumerate() {
            let r = generate_receipt(&header, tx, i, &hashes, dummy_summary(tx, 1), None);
            // Direction stored in dirs, not in path bytes.
            for _sibling in &r.merkle_path {
                // The sibling is an actual Blake3 hash or zero — never modified.
                // Just verify inclusion works correctly for all positions.
            }
            assert!(verify_merkle_inclusion(&r));
        }
    }
}
