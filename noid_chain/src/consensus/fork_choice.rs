// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Fork choice rule: heaviest chain wins.
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

use crate::consensus::difficulty::{le256_lt, work_gt};
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
/// Delegates to `choose_chain_by_work` with zero chainwork, which falls back
/// to height-based comparison. Use `choose_chain_by_work` when cumulative
/// chainwork is available.
pub fn choose_chain(
    target_a: &[u8; 32],
    hash_a: &[u8; 32],
    height_a: u64,
    target_b: &[u8; 32],
    hash_b: &[u8; 32],
    height_b: u64,
) -> ChainChoice {
    choose_chain_by_work(
        &[0u8; 32], // chainwork unknown for this API - use height fallback
        hash_a, height_a, target_a, &[0u8; 32], hash_b, height_b, target_b,
    )
}

/// Full fork choice using cumulative chainwork (production API).
///
/// Prefer this over `choose_chain` when cumulative chainwork is available.
/// `choose_chain` is a convenience wrapper for callers without chainwork.
///
/// # Arguments
/// - `chainwork_a`: cumulative work for chain A (sum of block_work() for all blocks)
/// - `chainwork_b`: cumulative work for chain B
/// - `hash_a`, `hash_b`: tip hashes for tie-breaking
/// - `target_a`, `target_b`: tip difficulty targets (used in height-fallback path)
///
/// If chainwork is unavailable (zeros), falls back to height comparison.
pub fn choose_chain_by_work(
    chainwork_a: &[u8; 32],
    hash_a: &[u8; 32],
    height_a: u64,
    target_a: &[u8; 32],
    chainwork_b: &[u8; 32],
    hash_b: &[u8; 32],
    height_b: u64,
    target_b: &[u8; 32],
) -> ChainChoice {
    // If cumulative chainwork is available (non-zero), use it as primary.
    let cw_a_nonzero = chainwork_a.iter().any(|&b| b != 0);
    let cw_b_nonzero = chainwork_b.iter().any(|&b| b != 0);

    if cw_a_nonzero || cw_b_nonzero {
        // Use cumulative chainwork as primary criterion.
        if work_gt(chainwork_a, chainwork_b) {
            return ChainChoice::A;
        }
        if work_gt(chainwork_b, chainwork_a) {
            return ChainChoice::B;
        }
        // Equal chainwork: tie-break by hash
        return if hash_a < hash_b {
            ChainChoice::A
        } else if hash_b < hash_a {
            ChainChoice::B
        } else {
            ChainChoice::Equal
        };
    }

    // Fallback: height-based (for tests and genesis bootstrapping).
    if height_a > height_b {
        return ChainChoice::A;
    }
    if height_b > height_a {
        return ChainChoice::B;
    }

    // Same height: lower target = more work per block.
    if le256_lt(target_a, target_b) {
        return ChainChoice::A;
    }
    if le256_lt(target_b, target_a) {
        return ChainChoice::B;
    }

    if hash_a < hash_b {
        ChainChoice::A
    } else if hash_b < hash_a {
        ChainChoice::B
    } else {
        ChainChoice::Equal
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
    use crate::consensus::difficulty::{add_work, block_work};
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
        // harder = smaller value (2^220) < easier (GENESIS_TARGET = 2^228)
        let harder = {
            let mut t = [0u8; 32];
            t[27] = 0x10; // 2^(8*27+4) = 2^220 < 2^228 = GENESIS_TARGET
            t
        };
        let easier = GENESIS_TARGET;
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

    #[test]
    fn more_work_wins_over_longer_chain() {
        // hard = 2^224, easy = 2^252 (old genesis); work_a(10 blocks) >> work_b(100 blocks)
        let hard_target = {
            let mut t = [0u8; 32];
            t[28] = 0x01;
            t
        };
        let easy_target = {
            let mut t = [0u8; 32];
            t[31] = 0x10;
            t
        };

        let mut work_a = [0u8; 32];
        for _ in 0..10 {
            work_a = add_work(&work_a, &block_work(&hard_target));
        }
        let mut work_b = [0u8; 32];
        for _ in 0..100 {
            work_b = add_work(&work_b, &block_work(&easy_target));
        }

        let h = [0u8; 32];
        // With cumulative work, chain A should win even though it's shorter.
        let result = choose_chain_by_work(
            &work_a,
            &h,
            10,
            &hard_target,
            &work_b,
            &h,
            100,
            &easy_target,
        );
        assert_eq!(
            result,
            ChainChoice::A,
            "more work chain should win regardless of height"
        );
    }
}
