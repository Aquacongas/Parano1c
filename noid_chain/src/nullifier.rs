// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Nullifier set: anti-double-inclusion rolling window.
//!
//! Maintains a fixed-depth window of `tx_body_hash` values from the
//! last `ANCHOR_DEPTH` blocks. A transaction is rejected if its hash
//! already appears in the window. Once a block exits the window, its
//! nullifiers are pruned (the epoch_anchor will have expired anyway).

use std::collections::HashSet;
use std::collections::VecDeque;

use noid_poseidon2b::primitives::TxBodyHash;
use noid_tx::ANCHOR_DEPTH;

/// Rolling window of nullifiers (tx_body_hashes) for the last
/// `ANCHOR_DEPTH` blocks. Provides O(1) lookup and O(1) amortized
/// insertion per block.
#[derive(Debug, Clone)]
pub struct NullifierSet {
    /// Ring of per-block hash sets, oldest at front.
    blocks: VecDeque<HashSet<TxBodyHash>>,
    /// Flat lookup set for O(1) contains check without scanning blocks.
    all: HashSet<TxBodyHash>,
    /// Maximum window depth (= ANCHOR_DEPTH).
    depth: u64,
}

impl NullifierSet {
    pub fn new() -> Self {
        Self {
            blocks: VecDeque::with_capacity(ANCHOR_DEPTH as usize + 1),
            all: HashSet::new(),
            depth: ANCHOR_DEPTH,
        }
    }

    /// Check if a tx_body_hash is already in the nullifier window.
    #[inline]
    pub fn contains(&self, hash: &TxBodyHash) -> bool {
        self.all.contains(hash)
    }

    /// Record a new block's transaction hashes. If the window exceeds
    /// `ANCHOR_DEPTH`, the oldest block's nullifiers are pruned.
    pub fn insert_block(&mut self, hashes: &[TxBodyHash]) {
        let set: HashSet<TxBodyHash> = hashes.iter().copied().collect();
        for h in &set {
            self.all.insert(*h);
        }
        self.blocks.push_back(set);

        while self.blocks.len() > self.depth as usize {
            if let Some(expired) = self.blocks.pop_front() {
                for h in &expired {
                    // Only remove from `all` if no other block still contains it.
                    // In practice tx_body_hashes are unique across blocks, but
                    // we handle the edge case correctly.
                    if !self.blocks.iter().any(|b| b.contains(h)) {
                        self.all.remove(h);
                    }
                }
            }
        }
    }

    /// Number of blocks currently tracked.
    #[inline]
    pub fn window_len(&self) -> usize {
        self.blocks.len()
    }

    /// Total nullifiers in the window.
    #[inline]
    pub fn total_nullifiers(&self) -> usize {
        self.all.len()
    }
}

impl Default for NullifierSet {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(seed: u8) -> TxBodyHash {
        TxBodyHash([seed; 32])
    }

    #[test]
    fn empty_set_contains_nothing() {
        let ns = NullifierSet::new();
        assert!(!ns.contains(&hash(1)));
        assert_eq!(ns.window_len(), 0);
        assert_eq!(ns.total_nullifiers(), 0);
    }

    #[test]
    fn insert_and_lookup() {
        let mut ns = NullifierSet::new();
        ns.insert_block(&[hash(1), hash(2)]);
        assert!(ns.contains(&hash(1)));
        assert!(ns.contains(&hash(2)));
        assert!(!ns.contains(&hash(3)));
        assert_eq!(ns.window_len(), 1);
        assert_eq!(ns.total_nullifiers(), 2);
    }

    #[test]
    fn prune_oldest_block() {
        let mut ns = NullifierSet::new();
        // Fill ANCHOR_DEPTH blocks
        for i in 0..ANCHOR_DEPTH {
            ns.insert_block(&[hash(i as u8)]);
        }
        assert_eq!(ns.window_len(), ANCHOR_DEPTH as usize);
        assert!(ns.contains(&hash(0)));

        // Insert one more block — oldest (hash(0)) should be pruned
        ns.insert_block(&[hash(ANCHOR_DEPTH as u8)]);
        assert_eq!(ns.window_len(), ANCHOR_DEPTH as usize);
        assert!(!ns.contains(&hash(0)));
        assert!(ns.contains(&hash(1)));
        assert!(ns.contains(&hash(ANCHOR_DEPTH as u8)));
    }

    #[test]
    fn duplicate_within_window_detected() {
        let mut ns = NullifierSet::new();
        ns.insert_block(&[hash(42)]);
        assert!(ns.contains(&hash(42)));
        // A second tx with same hash within window is detected
        ns.insert_block(&[hash(99)]);
        assert!(ns.contains(&hash(42)));
    }

    #[test]
    fn after_window_expires_hash_accepted() {
        let mut ns = NullifierSet::new();
        ns.insert_block(&[hash(1)]);
        // Push ANCHOR_DEPTH more blocks to expire hash(1)
        for i in 2..=(ANCHOR_DEPTH + 1) {
            ns.insert_block(&[hash(i as u8)]);
        }
        assert!(!ns.contains(&hash(1)));
    }

    #[test]
    fn multiple_hashes_per_block() {
        let mut ns = NullifierSet::new();
        let hashes: Vec<_> = (0..100).map(|i| hash(i)).collect();
        ns.insert_block(&hashes);
        for h in &hashes {
            assert!(ns.contains(h));
        }
        assert_eq!(ns.total_nullifiers(), 100);
    }
}
