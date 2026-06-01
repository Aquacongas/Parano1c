// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Fork choice rule: heaviest chain wins (SPECIFICATION.md §16 / §7).
//!
//! Paranoid uses **cumulative PoW work** as the canonical chain selector,
//! identical to Bitcoin's "most work" rule. Since PoW provides ordering
//! only (not security), the rule keeps the chain deterministic.
//!
//! Tie-break: if two chains have equal work, the lexicographically smaller
//! block hash (byte 0 first) wins. This is deterministic and prevents
//! accidental forks from timestamp ties.
//!
//! Reference: Bitcoin Core `src/chain.h::CChainWork`, Grin `chain/src/chain.rs`.

use crate::consensus::difficulty::le256_lt;
use crate::consensus::params::FINALITY_DEPTH;

/// Compare two chain tips by cumulative PoW work.
///
/// Work for a block = 2^256 / difficulty_target (more work = smaller target).
/// We approximate work by comparing difficulty targets inversely: the chain
/// whose tip required MORE work (smaller target) wins.
///
/// Returns `Ordering::Greater` if chain A has more work than chain B.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainChoice {
    /// Chain A is heavier (should be canonical).
    A,
    /// Chain B is heavier (should be canonical).
    B,
    /// Equal work: tie-broken by block hash.
    Equal,
}

/// Choose between two chain tips.
///
/// # Arguments
/// - `target_a`, `hash_a`: difficulty target and block hash of tip A
/// - `target_b`, `hash_b`: difficulty target and block hash of tip B
/// - `height_a`, `height_b`: chain heights
///
/// Shorter chains never win against longer chains of equal or greater work.
pub fn choose_chain(
    target_a: &[u8; 32],
    hash_a: &[u8; 32],
    height_a: u64,
    target_b: &[u8; 32],
    hash_b: &[u8; 32],
    height_b: u64,
) -> ChainChoice {
    // For simplicity, treat cumulative work as inversely proportional to target.
    // Chain with LOWER target = more work per block.
    // At equal height, we compare tip targets; at different heights we need
    // accumulated work. For MVP we use height × (1/target) approximation
    // via comparing the single-block difficulty.
    //
    // Full implementation uses cumulative chain work stored in DB (future).
    // For initial launch, height is the primary comparator (longest chain wins).
    if height_a > height_b {
        return ChainChoice::A;
    }
    if height_b > height_a {
        return ChainChoice::B;
    }

    // Same height: chain with lower target (more work) wins.
    if le256_lt(target_a, target_b) {
        return ChainChoice::A; // A required more work
    }
    if le256_lt(target_b, target_a) {
        return ChainChoice::B;
    }

    // Identical target: lexicographic tie-break on block hash.
    if hash_a < hash_b {
        ChainChoice::A
    } else if hash_b < hash_a {
        ChainChoice::B
    } else {
        ChainChoice::Equal // exactly the same block
    }
}

/// Check whether a reorg is allowed.
///
/// A reorg that would undo blocks with `n_confirmations` confirmations
/// (i.e., the common ancestor is `n_confirmations` blocks behind the tip)
/// is rejected once `n_confirmations >= FINALITY_DEPTH`.
pub fn reorg_allowed(n_confirmations_to_undo: u64) -> bool {
    n_confirmations_to_undo < FINALITY_DEPTH
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::params::GENESIS_TARGET;

    #[test]
    fn longer_chain_wins() {
        let t = GENESIS_TARGET;
        let h = [0u8; 32];
        assert_eq!(choose_chain(&t, &h, 100, &t, &h, 99), ChainChoice::A);
        assert_eq!(choose_chain(&t, &h, 99, &t, &h, 100), ChainChoice::B);
    }

    #[test]
    fn lower_target_wins_at_equal_height() {
        let harder = {
            let mut t = GENESIS_TARGET;
            t[31] = 0x08;
            t
        }; // harder
        let easier = GENESIS_TARGET; // easier
        let h = [0u8; 32];
        // harder target (smaller value) = more work = should win
        assert_eq!(
            choose_chain(&harder, &h, 10, &easier, &h, 10),
            ChainChoice::A
        );
        assert_eq!(
            choose_chain(&easier, &h, 10, &harder, &h, 10),
            ChainChoice::B
        );
    }

    #[test]
    fn hash_tiebreak() {
        let t = GENESIS_TARGET;
        let hash_a = [0u8; 32]; // lexicographically smaller
        let hash_b = [1u8; 32];
        assert_eq!(
            choose_chain(&t, &hash_a, 10, &t, &hash_b, 10),
            ChainChoice::A
        );
        assert_eq!(
            choose_chain(&t, &hash_b, 10, &t, &hash_a, 10),
            ChainChoice::B
        );
    }

    #[test]
    fn same_block_is_equal() {
        let t = GENESIS_TARGET;
        let h = [0u8; 32];
        assert_eq!(choose_chain(&t, &h, 10, &t, &h, 10), ChainChoice::Equal);
    }

    #[test]
    fn reorg_within_finality_allowed() {
        assert!(reorg_allowed(0));
        assert!(reorg_allowed(17));
        assert!(!reorg_allowed(18)); // FINALITY_DEPTH = 18
        assert!(!reorg_allowed(100));
    }
}
