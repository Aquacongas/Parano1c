// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! P0 measured tier-1 verifier statistics — the empirical shape inputs for the
//! SVT trace (`s4-design.md` §6, `roadmap.md` P0).
//!
//! Measured 2026-07-03 by `bench_prover/benches/tier1_shape_stats.rs`: every
//! killshot verifier that `verify_accepted_block_batch_components` runs for a
//! real accepted block was replayed with a counting Fiat-Shamir channel
//! (exact production challenge stream; exact Poseidon2b permutation counts).
//!
//! These are *measured statistics*, not yet the frozen protocol shape: the
//! final padding maxima and loop bounds (the real `shape_digest` of
//! `s4-design.md` §4.3) are fixed in P3, after the [K] restructuring decisions
//! recorded in `s4-design.md` §6 (drop of the auth-FS-transcript killshot from
//! the trace, squeeze-diet decision after gate G1). Until then, any consumer
//! of these numbers must treat them as the P0 snapshot pinned by
//! [`shape_stats_digest`].
//!
//! Regenerate: `cargo bench -p bench_prover --bench tier1_shape_stats`
//! (update this file and the digest test in the same commit).

use noid_poseidon2b::native::poseidon2b_hash_byte_slices;

/// Constraint cost of one Poseidon2b permutation in the F128 arithmetic trace
/// (option A of `s4-design.md` §4.1): 90 S-boxes x 4 multiplications.
pub const PERM_TRACE_CONSTRAINTS: usize = 360;

/// Aggregate Fiat-Shamir transcript statistics of one verifier component
/// (all instances of that component in the block summed together).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ComponentStats {
    pub name: &'static str,
    /// Number of verifier instances behind the totals (e.g. one owner-auth
    /// verification per user transaction).
    pub instances: u32,
    pub absorbs: u32,
    pub squeezes: u32,
    pub perms: u32,
}

/// Measured statistics of one whole-block case.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CaseStats {
    pub name: &'static str,
    pub user_txs: u32,
    pub components: &'static [ComponentStats],
}

impl CaseStats {
    pub fn total_perms(&self) -> u64 {
        self.components.iter().map(|c| c.perms as u64).sum()
    }

    pub fn total_absorbs(&self) -> u64 {
        self.components.iter().map(|c| c.absorbs as u64).sum()
    }

    pub fn total_squeezes(&self) -> u64 {
        self.components.iter().map(|c| c.squeezes as u64).sum()
    }

    /// Full-replay [K] constraint estimate (option A), FS hashing only.
    pub fn fs_trace_constraints(&self) -> u64 {
        self.total_perms() * PERM_TRACE_CONSTRAINTS as u64
    }

    /// [K] perms excluding the auth-FS-transcript killshot, which has negative
    /// leverage inside the trace (finding F1 in `s4-design.md` §6): replaying
    /// the owner-auth verifier directly is ~3.9x cheaper than verifying the
    /// killshot that proves its transcript hashing.
    pub fn perms_without_auth_fs(&self) -> u64 {
        self.components
            .iter()
            .filter(|c| c.name != AUTH_FS_TRANSCRIPTS)
            .map(|c| c.perms as u64)
            .sum()
    }
}

pub const ACCEPTED_CLAIM_HASH: &str = "accepted_claim_hash";
pub const TX_BODY_STANDARD_SPINE: &str = "tx_body_standard_spine";
pub const TX_ROOT_MERKLE: &str = "tx_root_merkle";
pub const OWNER_AUTH: &str = "owner_auth";
pub const AUTH_FS_TRANSCRIPTS: &str = "auth_fs_transcripts";
pub const CHECKPOINT_HEADER_HASH: &str = "checkpoint_header_hash";
pub const CHECKPOINT_CHAIN_ACCUMULATOR: &str = "checkpoint_chain_accumulator";
pub const EXACT_STATE_SLOT_LEAVES: &str = "exact_state.slot_leaves";
pub const EXACT_STATE_STATE_PATHS: &str = "exact_state.state_paths";
pub const EXACT_STATE_GUARD_BUCKETS: &str = "exact_state.guard_buckets";
pub const EXACT_STATE_GUARD_PATHS: &str = "exact_state.guard_paths";
pub const EXACT_STATE_STATE_ROOTS: &str = "exact_state.state_roots";

/// One coinbase-only block (no user transactions).
pub const CASE_COINBASE_ONLY: CaseStats = CaseStats {
    name: "coinbase_only_1_block",
    user_txs: 0,
    components: &[
        ComponentStats { name: ACCEPTED_CLAIM_HASH, instances: 1, absorbs: 488, squeezes: 245, perms: 421 },
        ComponentStats { name: CHECKPOINT_HEADER_HASH, instances: 1, absorbs: 403, squeezes: 150, perms: 327 },
        ComponentStats { name: CHECKPOINT_CHAIN_ACCUMULATOR, instances: 1, absorbs: 318, squeezes: 81, perms: 240 },
    ],
};

/// One block with 1 standard (Standard4x8) user transaction.
pub const CASE_USER_TXS_1: CaseStats = CaseStats {
    name: "user_txs_1",
    user_txs: 1,
    components: &[
        ComponentStats { name: ACCEPTED_CLAIM_HASH, instances: 1, absorbs: 488, squeezes: 245, perms: 421 },
        ComponentStats { name: TX_BODY_STANDARD_SPINE, instances: 1, absorbs: 405, squeezes: 85, perms: 299 },
        ComponentStats { name: TX_ROOT_MERKLE, instances: 1, absorbs: 511, squeezes: 83, perms: 337 },
        ComponentStats { name: OWNER_AUTH, instances: 1, absorbs: 374, squeezes: 53, perms: 253 },
        ComponentStats { name: AUTH_FS_TRANSCRIPTS, instances: 1, absorbs: 1308, squeezes: 1158, perms: 1295 },
        ComponentStats { name: CHECKPOINT_HEADER_HASH, instances: 1, absorbs: 403, squeezes: 150, perms: 327 },
        ComponentStats { name: CHECKPOINT_CHAIN_ACCUMULATOR, instances: 1, absorbs: 318, squeezes: 81, perms: 240 },
        ComponentStats { name: EXACT_STATE_SLOT_LEAVES, instances: 1, absorbs: 353, squeezes: 108, perms: 274 },
        ComponentStats { name: EXACT_STATE_STATE_PATHS, instances: 1, absorbs: 785, squeezes: 214, perms: 550 },
        ComponentStats { name: EXACT_STATE_GUARD_BUCKETS, instances: 1, absorbs: 320, squeezes: 83, perms: 242 },
        ComponentStats { name: EXACT_STATE_GUARD_PATHS, instances: 1, absorbs: 583, squeezes: 210, perms: 447 },
        ComponentStats { name: EXACT_STATE_STATE_ROOTS, instances: 1, absorbs: 347, squeezes: 96, perms: 265 },
    ],
};

/// One block with 4 standard user transactions.
pub const CASE_USER_TXS_4: CaseStats = CaseStats {
    name: "user_txs_4",
    user_txs: 4,
    components: &[
        ComponentStats { name: ACCEPTED_CLAIM_HASH, instances: 1, absorbs: 488, squeezes: 245, perms: 421 },
        ComponentStats { name: TX_BODY_STANDARD_SPINE, instances: 1, absorbs: 459, squeezes: 101, perms: 341 },
        ComponentStats { name: TX_ROOT_MERKLE, instances: 1, absorbs: 761, squeezes: 145, perms: 500 },
        ComponentStats { name: OWNER_AUTH, instances: 4, absorbs: 1496, squeezes: 212, perms: 1012 },
        ComponentStats { name: AUTH_FS_TRANSCRIPTS, instances: 1, absorbs: 3921, squeezes: 4363, perms: 4210 },
        ComponentStats { name: CHECKPOINT_HEADER_HASH, instances: 1, absorbs: 403, squeezes: 150, perms: 327 },
        ComponentStats { name: CHECKPOINT_CHAIN_ACCUMULATOR, instances: 1, absorbs: 318, squeezes: 81, perms: 240 },
        ComponentStats { name: EXACT_STATE_SLOT_LEAVES, instances: 1, absorbs: 461, squeezes: 238, perms: 400 },
        ComponentStats { name: EXACT_STATE_STATE_PATHS, instances: 1, absorbs: 2069, squeezes: 1149, perms: 1670 },
        ComponentStats { name: EXACT_STATE_GUARD_BUCKETS, instances: 1, absorbs: 347, squeezes: 92, perms: 263 },
        ComponentStats { name: EXACT_STATE_GUARD_PATHS, instances: 1, absorbs: 583, squeezes: 210, perms: 447 },
        ComponentStats { name: EXACT_STATE_STATE_ROOTS, instances: 1, absorbs: 347, squeezes: 96, perms: 265 },
    ],
};

/// One block with 16 standard user transactions.
pub const CASE_USER_TXS_16: CaseStats = CaseStats {
    name: "user_txs_16",
    user_txs: 16,
    components: &[
        ComponentStats { name: ACCEPTED_CLAIM_HASH, instances: 1, absorbs: 488, squeezes: 245, perms: 421 },
        ComponentStats { name: TX_BODY_STANDARD_SPINE, instances: 1, absorbs: 531, squeezes: 135, perms: 401 },
        ComponentStats { name: TX_ROOT_MERKLE, instances: 1, absorbs: 2045, squeezes: 632, perms: 1396 },
        ComponentStats { name: OWNER_AUTH, instances: 16, absorbs: 5984, squeezes: 848, perms: 4048 },
        ComponentStats { name: AUTH_FS_TRANSCRIPTS, instances: 1, absorbs: 14229, squeezes: 17153, perms: 15766 },
        ComponentStats { name: CHECKPOINT_HEADER_HASH, instances: 1, absorbs: 403, squeezes: 150, perms: 327 },
        ComponentStats { name: CHECKPOINT_CHAIN_ACCUMULATOR, instances: 1, absorbs: 318, squeezes: 81, perms: 240 },
        ComponentStats { name: EXACT_STATE_SLOT_LEAVES, instances: 1, absorbs: 749, squeezes: 728, perms: 796 },
        ComponentStats { name: EXACT_STATE_STATE_PATHS, instances: 1, absorbs: 6965, squeezes: 4327, perms: 5714 },
        ComponentStats { name: EXACT_STATE_GUARD_BUCKETS, instances: 1, absorbs: 383, squeezes: 121, perms: 299 },
        ComponentStats { name: EXACT_STATE_GUARD_PATHS, instances: 1, absorbs: 583, squeezes: 210, perms: 447 },
        ComponentStats { name: EXACT_STATE_STATE_ROOTS, instances: 1, absorbs: 347, squeezes: 96, perms: 265 },
    ],
};

pub const MEASURED_CASES: &[&CaseStats] = &[
    &CASE_COINBASE_ONLY,
    &CASE_USER_TXS_1,
    &CASE_USER_TXS_4,
    &CASE_USER_TXS_16,
];

/// Marginal verifier-FS permutations per standard tx, full replay:
/// (30120 - 988) / 16, floored.
pub const MARGINAL_PERMS_PER_STANDARD_TX_FULL: u32 = 1_820;

/// Marginal perms per standard tx once the auth-FS-transcript killshot is
/// dropped from the trace (F1): (14354 - 988) / 16.
pub const MARGINAL_PERMS_PER_STANDARD_TX_NO_AUTH_FS: u32 = 835;

/// Consensus block maxima (source of truth: `noid_chain::consensus::params`).
/// 255 standard user txs + coinbase, or 40 full Sweep25x2 txs.
pub const BLOCK_MAX_STANDARD_USER_TXS: usize = noid_chain::consensus::params::BLOCK_MAX_USER_TXS;
pub const BLOCK_MAX_FULL_SWEEP_TXS: usize =
    noid_chain::consensus::params::BLOCK_MAX_FULL_SWEEP25X2_TXS;

/// Projected full-replay [K] permutations for a block of `n` standard txs,
/// after F1 (auth-FS-transcript killshot dropped). Linear extrapolation of the
/// P0 measurement; refresh after the P0.5 optimization pass.
pub fn projected_perms_std_txs_no_auth_fs(n: usize) -> u64 {
    CASE_COINBASE_ONLY.total_perms() + n as u64 * MARGINAL_PERMS_PER_STANDARD_TX_NO_AUTH_FS as u64
}

const SHAPE_STATS_DOMAIN: &[u8] = b"NOID-TIER1-SHAPE-STATS-P0-V1";

/// Digest pinning this P0 measurement snapshot. Referenced by `s4-design.md`
/// §6 so later phases can detect a stale table. NOT the protocol
/// `shape_digest` of the SVT public interface (that is frozen in P3).
pub fn shape_stats_digest() -> [u8; 32] {
    let mut encoded: Vec<u8> = Vec::new();
    encoded.extend_from_slice(&(PERM_TRACE_CONSTRAINTS as u32).to_le_bytes());
    for case in MEASURED_CASES {
        encoded.extend_from_slice(case.name.as_bytes());
        encoded.push(0);
        encoded.extend_from_slice(&case.user_txs.to_le_bytes());
        for component in case.components {
            encoded.extend_from_slice(component.name.as_bytes());
            encoded.push(0);
            encoded.extend_from_slice(&component.instances.to_le_bytes());
            encoded.extend_from_slice(&component.absorbs.to_le_bytes());
            encoded.extend_from_slice(&component.squeezes.to_le_bytes());
            encoded.extend_from_slice(&component.perms.to_le_bytes());
        }
    }
    poseidon2b_hash_byte_slices(SHAPE_STATS_DOMAIN, &[&encoded])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn case_totals_match_measurement() {
        assert_eq!(CASE_COINBASE_ONLY.total_perms(), 988);
        assert_eq!(CASE_USER_TXS_1.total_perms(), 4_950);
        assert_eq!(CASE_USER_TXS_4.total_perms(), 10_096);
        assert_eq!(CASE_USER_TXS_16.total_perms(), 30_120);
        assert_eq!(CASE_USER_TXS_16.total_absorbs(), 33_025);
        assert_eq!(CASE_USER_TXS_16.total_squeezes(), 24_726);
        assert_eq!(CASE_USER_TXS_16.perms_without_auth_fs(), 14_354);
        assert_eq!(
            MARGINAL_PERMS_PER_STANDARD_TX_FULL as u64,
            (CASE_USER_TXS_16.total_perms() - CASE_COINBASE_ONLY.total_perms()) / 16
        );
        assert_eq!(
            MARGINAL_PERMS_PER_STANDARD_TX_NO_AUTH_FS as u64,
            (CASE_USER_TXS_16.perms_without_auth_fs() - CASE_COINBASE_ONLY.total_perms()) / 16
        );
    }

    #[test]
    fn shape_stats_digest_is_stable() {
        let a = shape_stats_digest();
        let b = shape_stats_digest();
        assert_eq!(a, b);
        assert_ne!(a, [0u8; 32]);
    }
}
