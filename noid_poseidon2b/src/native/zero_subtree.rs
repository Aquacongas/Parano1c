// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Precomputed Poseidon2b digests of all-zero subtrees.
//!
//! `zero_subtree_root(k)` returns the root digest of a perfectly
//! balanced binary Poseidon2b Merkle tree of depth `k` whose every
//! leaf is `[0u8; 32]`. Defined by the recurrence
//!
//! ```text
//! Z[0]   = [0u8; 32]
//! Z[k+1] = compress(Z[k], Z[k])
//! ```
//!
//! Per `GENERAL_DESIGN §15.3` the state expansion block computes
//!
//! ```text
//! new_state_root = compress(old_state_root, Z[old_log_slots])
//! ```
//!
//! to lift the slot-space Merkle root from depth `k` to `k + 1` in a
//! single hash (the right half of the fresh level is an all-zero
//! subtree). `LOG_SLOTS` starts at `24` and may grow to at most `32`,
//! so the table carries `Z[k]` for `k ∈ [24, 32]`.
//!
//! The compression function is not `const`, so values are memoized in
//! a `OnceLock`. The first call at program start pays the nine
//! incremental recurrences (`Z[1]` through `Z[32]`); every subsequent
//! call is a table lookup.

use std::sync::OnceLock;

use crate::native::compression::compress;

/// Inclusive lower bound of the `k` range supported by this table.
/// Matches mainnet launch `log_slots` and the lower bound on
/// `PublicInputs::log_slots` (`noid_tx::public::MIN_LOG_SLOTS`).
pub const ZERO_SUBTREE_MIN_K: usize = 24;
/// Inclusive upper bound of the `k` range supported by this table.
/// Matches the expansion ceiling in `GENERAL_DESIGN §15.3` and
/// `noid_tx::public::MAX_LOG_SLOTS`.
pub const ZERO_SUBTREE_MAX_K: usize = 32;
/// Number of entries in the public `ZERO_SUBTREE_ROOT[k]` table
/// returned by [`zero_subtree_root_table`], one per supported depth.
pub const ZERO_SUBTREE_TABLE_LEN: usize = ZERO_SUBTREE_MAX_K - ZERO_SUBTREE_MIN_K + 1;

static TABLE: OnceLock<[[u8; 32]; ZERO_SUBTREE_TABLE_LEN]> = OnceLock::new();

fn build_table() -> [[u8; 32]; ZERO_SUBTREE_TABLE_LEN] {
    // Walk the recurrence from depth 0 upward; only the entries in
    // `[MIN_K, MAX_K]` are retained.
    let mut current = [0u8; 32];
    for _ in 0..ZERO_SUBTREE_MIN_K {
        current = compress(&current, &current);
    }
    let mut out = [[0u8; 32]; ZERO_SUBTREE_TABLE_LEN];
    out[0] = current;
    for i in 1..ZERO_SUBTREE_TABLE_LEN {
        current = compress(&current, &current);
        out[i] = current;
    }
    out
}

/// `Z[k]` for `k ∈ [ZERO_SUBTREE_MIN_K, ZERO_SUBTREE_MAX_K]`.
///
/// Panics for `k` outside the supported range.
pub fn zero_subtree_root(k: usize) -> [u8; 32] {
    assert!(
        (ZERO_SUBTREE_MIN_K..=ZERO_SUBTREE_MAX_K).contains(&k),
        "zero_subtree_root: k={k} outside [{ZERO_SUBTREE_MIN_K}, {ZERO_SUBTREE_MAX_K}]",
    );
    zero_subtree_root_table()[k - ZERO_SUBTREE_MIN_K]
}

/// Full contiguous table `Z[MIN_K .. MAX_K]` (inclusive on both ends).
/// Shares the same memoized storage as [`zero_subtree_root`].
pub fn zero_subtree_root_table() -> &'static [[u8; 32]; ZERO_SUBTREE_TABLE_LEN] {
    TABLE.get_or_init(build_table)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recurrence_holds_across_table() {
        // Each entry is the compression of the previous entry with itself.
        let table = zero_subtree_root_table();
        for i in 1..ZERO_SUBTREE_TABLE_LEN {
            let expect = compress(&table[i - 1], &table[i - 1]);
            assert_eq!(
                table[i],
                expect,
                "Z[{}] != compress(Z[{}], Z[{}])",
                i,
                i - 1,
                i - 1
            );
        }
    }

    #[test]
    fn base_entry_matches_manual_computation() {
        // Recompute Z[MIN_K] directly from Z[0] = [0; 32] and compare.
        let mut current = [0u8; 32];
        for _ in 0..ZERO_SUBTREE_MIN_K {
            current = compress(&current, &current);
        }
        assert_eq!(zero_subtree_root(ZERO_SUBTREE_MIN_K), current);
    }

    #[test]
    fn accessor_and_table_agree() {
        let table = zero_subtree_root_table();
        for k in ZERO_SUBTREE_MIN_K..=ZERO_SUBTREE_MAX_K {
            assert_eq!(zero_subtree_root(k), table[k - ZERO_SUBTREE_MIN_K]);
        }
    }

    #[test]
    #[should_panic(expected = "outside")]
    fn rejects_below_min() {
        let _ = zero_subtree_root(ZERO_SUBTREE_MIN_K - 1);
    }

    #[test]
    #[should_panic(expected = "outside")]
    fn rejects_above_max() {
        let _ = zero_subtree_root(ZERO_SUBTREE_MAX_K + 1);
    }
}
