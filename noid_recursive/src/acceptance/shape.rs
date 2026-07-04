// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Measured tier-1 verifier statistics — the empirical shape inputs for the
//! acceptance-proof trace (the arithmetic F128 replay of the block
//! verifiers).
//!
//! Measured 2026-07-05 by `bench_prover/benches/tier1_shape_stats.rs`
//! **after the transcript-freeze diet** (squeeze diet + prefix-decodable
//! Merkle statement absorbs + real-leaf-only tx-root paths + prebound
//! batch-eval claims + compressed sumcheck rounds; the P0 pre-diet
//! snapshot had 24,726 squeezes / 30,120 perms @16 txs): every
//! killshot verifier that `verify_accepted_block_batch_components` runs for a
//! real accepted block was replayed with a counting Fiat-Shamir channel
//! (exact production challenge stream; exact Poseidon2b permutation counts).
//!
//! These are *measured statistics*, not yet the frozen protocol shape: the
//! final padding maxima and loop bounds (the real `shape_digest` of the
//! public proof interface) are frozen together with the shape classes. Note
//! that the auth-FS-transcript killshot is excluded from the trace budget:
//! replaying the owner-auth verifier directly is ~3.9x cheaper than
//! verifying the killshot that proves its transcript hashing. Until the
//! freeze, any consumer of these numbers must treat them as the measurement
//! snapshot pinned by [`shape_stats_digest`].
//!
//! Regenerate: `cargo bench -p bench_prover --bench tier1_shape_stats`
//! (update this file and the digest test in the same commit).

use noid_poseidon2b::native::poseidon2b_hash_byte_slices;

/// Constraint cost of one Poseidon2b permutation in the F128 arithmetic trace
/// (linear layers live in the F128-coefficient matrices for free):
/// 90 S-boxes x 4 multiplications.
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
    /// leverage inside the trace: replaying
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
pub const TX_BODY_SWEEP_SPINE: &str = "tx_body_sweep_spine";
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
        ComponentStats { name: ACCEPTED_CLAIM_HASH, instances: 1, absorbs: 348, squeezes: 82, perms: 255 },
        ComponentStats { name: CHECKPOINT_HEADER_HASH, instances: 1, absorbs: 272, squeezes: 77, perms: 211 },
        ComponentStats { name: CHECKPOINT_CHAIN_ACCUMULATOR, instances: 1, absorbs: 214, squeezes: 62, perms: 168 },
    ],
};

/// One block with 1 standard (Standard4x8) user transaction.
pub const CASE_USER_TXS_1: CaseStats = CaseStats {
    name: "user_txs_1",
    user_txs: 1,
    components: &[
        ComponentStats { name: ACCEPTED_CLAIM_HASH, instances: 1, absorbs: 348, squeezes: 82, perms: 255 },
        ComponentStats { name: TX_BODY_STANDARD_SPINE, instances: 1, absorbs: 265, squeezes: 82, perms: 213 },
        ComponentStats { name: TX_ROOT_MERKLE, instances: 1, absorbs: 198, squeezes: 57, perms: 154 },
        ComponentStats { name: OWNER_AUTH, instances: 1, absorbs: 308, squeezes: 48, perms: 200 },
        ComponentStats { name: AUTH_FS_TRANSCRIPTS, instances: 1, absorbs: 1008, squeezes: 92, perms: 595 },
        ComponentStats { name: CHECKPOINT_HEADER_HASH, instances: 1, absorbs: 272, squeezes: 77, perms: 211 },
        ComponentStats { name: CHECKPOINT_CHAIN_ACCUMULATOR, instances: 1, absorbs: 214, squeezes: 62, perms: 168 },
        ComponentStats { name: EXACT_STATE_SLOT_LEAVES, instances: 1, absorbs: 240, squeezes: 67, perms: 185 },
        ComponentStats { name: EXACT_STATE_STATE_PATHS, instances: 1, absorbs: 306, squeezes: 77, perms: 228 },
        ComponentStats { name: EXACT_STATE_GUARD_BUCKETS, instances: 1, absorbs: 216, squeezes: 62, perms: 169 },
        ComponentStats { name: EXACT_STATE_GUARD_PATHS, instances: 1, absorbs: 294, squeezes: 77, perms: 222 },
        ComponentStats { name: EXACT_STATE_STATE_ROOTS, instances: 1, absorbs: 234, squeezes: 67, perms: 182 },
    ],
};

/// One block with 4 standard user transactions.
pub const CASE_USER_TXS_4: CaseStats = CaseStats {
    name: "user_txs_4",
    user_txs: 4,
    components: &[
        ComponentStats { name: ACCEPTED_CLAIM_HASH, instances: 1, absorbs: 348, squeezes: 82, perms: 255 },
        ComponentStats { name: TX_BODY_STANDARD_SPINE, instances: 1, absorbs: 301, squeezes: 92, perms: 241 },
        ComponentStats { name: TX_ROOT_MERKLE, instances: 1, absorbs: 275, squeezes: 72, perms: 208 },
        ComponentStats { name: OWNER_AUTH, instances: 4, absorbs: 1232, squeezes: 192, perms: 800 },
        ComponentStats { name: AUTH_FS_TRANSCRIPTS, instances: 1, absorbs: 3177, squeezes: 102, perms: 1689 },
        ComponentStats { name: CHECKPOINT_HEADER_HASH, instances: 1, absorbs: 272, squeezes: 77, perms: 211 },
        ComponentStats { name: CHECKPOINT_CHAIN_ACCUMULATOR, instances: 1, absorbs: 214, squeezes: 62, perms: 168 },
        ComponentStats { name: EXACT_STATE_SLOT_LEAVES, instances: 1, absorbs: 330, squeezes: 77, perms: 240 },
        ComponentStats { name: EXACT_STATE_STATE_PATHS, instances: 1, absorbs: 647, squeezes: 92, perms: 414 },
        ComponentStats { name: EXACT_STATE_GUARD_BUCKETS, instances: 1, absorbs: 234, squeezes: 67, perms: 182 },
        ComponentStats { name: EXACT_STATE_GUARD_PATHS, instances: 1, absorbs: 294, squeezes: 77, perms: 222 },
        ComponentStats { name: EXACT_STATE_STATE_ROOTS, instances: 1, absorbs: 234, squeezes: 67, perms: 182 },
    ],
};

/// One block with 16 standard user transactions.
pub const CASE_USER_TXS_16: CaseStats = CaseStats {
    name: "user_txs_16",
    user_txs: 16,
    components: &[
        ComponentStats { name: ACCEPTED_CLAIM_HASH, instances: 1, absorbs: 348, squeezes: 82, perms: 255 },
        ComponentStats { name: TX_BODY_STANDARD_SPINE, instances: 1, absorbs: 355, squeezes: 102, perms: 278 },
        ComponentStats { name: TX_ROOT_MERKLE, instances: 1, absorbs: 504, squeezes: 87, perms: 337 },
        ComponentStats { name: OWNER_AUTH, instances: 16, absorbs: 4928, squeezes: 768, perms: 3200 },
        ComponentStats { name: AUTH_FS_TRANSCRIPTS, instances: 1, absorbs: 11763, squeezes: 112, perms: 5992 },
        ComponentStats { name: CHECKPOINT_HEADER_HASH, instances: 1, absorbs: 272, squeezes: 77, perms: 211 },
        ComponentStats { name: CHECKPOINT_CHAIN_ACCUMULATOR, instances: 1, absorbs: 214, squeezes: 62, perms: 168 },
        ComponentStats { name: EXACT_STATE_SLOT_LEAVES, instances: 1, absorbs: 600, squeezes: 87, perms: 385 },
        ComponentStats { name: EXACT_STATE_STATE_PATHS, instances: 1, absorbs: 1733, squeezes: 102, perms: 967 },
        ComponentStats { name: EXACT_STATE_GUARD_BUCKETS, instances: 1, absorbs: 261, squeezes: 72, perms: 201 },
        ComponentStats { name: EXACT_STATE_GUARD_PATHS, instances: 1, absorbs: 294, squeezes: 77, perms: 222 },
        ComponentStats { name: EXACT_STATE_STATE_ROOTS, instances: 1, absorbs: 234, squeezes: 67, perms: 182 },
    ],
};

/// One block with 1 full Sweep25x2 user transaction (25 live inputs, distinct
/// owner per input, 2 outputs — the heaviest per-tx authorization shape).
pub const CASE_SWEEP_TXS_1: CaseStats = CaseStats {
    name: "sweep_txs_1",
    user_txs: 1,
    components: &[
        ComponentStats { name: ACCEPTED_CLAIM_HASH, instances: 1, absorbs: 348, squeezes: 82, perms: 255 },
        ComponentStats { name: TX_BODY_SWEEP_SPINE, instances: 1, absorbs: 295, squeezes: 92, perms: 238 },
        ComponentStats { name: TX_ROOT_MERKLE, instances: 1, absorbs: 198, squeezes: 57, perms: 154 },
        ComponentStats { name: OWNER_AUTH, instances: 1, absorbs: 508, squeezes: 73, perms: 322 },
        ComponentStats { name: AUTH_FS_TRANSCRIPTS, instances: 1, absorbs: 1473, squeezes: 97, perms: 832 },
        ComponentStats { name: CHECKPOINT_HEADER_HASH, instances: 1, absorbs: 272, squeezes: 77, perms: 211 },
        ComponentStats { name: CHECKPOINT_CHAIN_ACCUMULATOR, instances: 1, absorbs: 214, squeezes: 62, perms: 168 },
        ComponentStats { name: EXACT_STATE_SLOT_LEAVES, instances: 1, absorbs: 550, squeezes: 87, perms: 360 },
        ComponentStats { name: EXACT_STATE_STATE_PATHS, instances: 1, absorbs: 1513, squeezes: 102, perms: 857 },
        ComponentStats { name: EXACT_STATE_GUARD_BUCKETS, instances: 1, absorbs: 270, squeezes: 72, perms: 206 },
        ComponentStats { name: EXACT_STATE_GUARD_PATHS, instances: 1, absorbs: 294, squeezes: 77, perms: 222 },
        ComponentStats { name: EXACT_STATE_STATE_ROOTS, instances: 1, absorbs: 234, squeezes: 67, perms: 182 },
    ],
};

/// One block with 4 full Sweep25x2 user transactions. The dominant component
/// is the exact-state path batch (216 Merkle paths: 27 touched slots per tx).
pub const CASE_SWEEP_TXS_4: CaseStats = CaseStats {
    name: "sweep_txs_4",
    user_txs: 4,
    components: &[
        ComponentStats { name: ACCEPTED_CLAIM_HASH, instances: 1, absorbs: 348, squeezes: 82, perms: 255 },
        ComponentStats { name: TX_BODY_SWEEP_SPINE, instances: 1, absorbs: 331, squeezes: 102, perms: 266 },
        ComponentStats { name: TX_ROOT_MERKLE, instances: 1, absorbs: 275, squeezes: 72, perms: 208 },
        ComponentStats { name: OWNER_AUTH, instances: 4, absorbs: 2032, squeezes: 292, perms: 1288 },
        ComponentStats { name: AUTH_FS_TRANSCRIPTS, instances: 1, absorbs: 4992, squeezes: 107, perms: 2601 },
        ComponentStats { name: CHECKPOINT_HEADER_HASH, instances: 1, absorbs: 272, squeezes: 77, perms: 211 },
        ComponentStats { name: CHECKPOINT_CHAIN_ACCUMULATOR, instances: 1, absorbs: 214, squeezes: 62, perms: 168 },
        ComponentStats { name: EXACT_STATE_SLOT_LEAVES, instances: 1, absorbs: 1390, squeezes: 97, perms: 790 },
        ComponentStats { name: EXACT_STATE_STATE_PATHS, instances: 1, absorbs: 5107, squeezes: 112, perms: 2664 },
        ComponentStats { name: EXACT_STATE_GUARD_BUCKETS, instances: 1, absorbs: 375, squeezes: 82, perms: 268 },
        ComponentStats { name: EXACT_STATE_GUARD_PATHS, instances: 1, absorbs: 294, squeezes: 77, perms: 222 },
        ComponentStats { name: EXACT_STATE_STATE_ROOTS, instances: 1, absorbs: 234, squeezes: 67, perms: 182 },
    ],
};

pub const MEASURED_CASES: &[&CaseStats] = &[
    &CASE_COINBASE_ONLY,
    &CASE_USER_TXS_1,
    &CASE_USER_TXS_4,
    &CASE_USER_TXS_16,
    &CASE_SWEEP_TXS_1,
    &CASE_SWEEP_TXS_4,
];

/// Marginal verifier-FS permutations per standard tx, full replay:
/// (12398 - 634) / 16, floored. (Pre-freeze-diet value: 1,104.)
pub const MARGINAL_PERMS_PER_STANDARD_TX_FULL: u32 = 735;

/// Marginal perms per standard tx once the auth-FS-transcript killshot is
/// dropped from the trace: (12398 - 5992 - 634) / 16, floored.
/// (Pre-freeze-diet value: 656.)
pub const MARGINAL_PERMS_PER_STANDARD_TX_NO_AUTH_FS: u32 = 360;

/// Marginal verifier-FS permutations per full Sweep25x2 tx, full replay:
/// (9123 - 634) / 4, floored.
pub const MARGINAL_PERMS_PER_SWEEP_TX_FULL: u32 = 2_122;

/// Marginal perms per full Sweep25x2 tx (auth-FS-transcript killshot
/// dropped): (9123 - 2601 - 634) / 4. Dominated by the exact-state Merkle
/// path batch (27 touched slots per sweep vs 2 per standard tx).
pub const MARGINAL_PERMS_PER_SWEEP_TX_NO_AUTH_FS: u32 = 1_472;

/// Consensus block maxima (source of truth: `noid_chain::consensus::params`).
/// 255 standard user txs + coinbase, or 40 full Sweep25x2 txs.
pub const BLOCK_MAX_STANDARD_USER_TXS: usize = noid_chain::consensus::params::BLOCK_MAX_USER_TXS;
pub const BLOCK_MAX_FULL_SWEEP_TXS: usize =
    noid_chain::consensus::params::BLOCK_MAX_FULL_SWEEP25X2_TXS;

/// Projected full-replay [K] permutations for a block of `n` standard txs,
/// without the auth-FS-transcript killshot.
///
/// Linear extrapolation of the 16-tx measurement — a conservative UPPER
/// bound: the env-gated 255-tx run (`NOID_SHAPE_MAX_STD=1`, 2026-07-05,
/// post-freeze-diet) measured 71,459 perms (no auth-FS) vs 92,434 projected
/// (−23%), because batched-killshot round/terminal costs amortize with batch
/// size while this projection scales them linearly.
pub fn projected_perms_std_txs_no_auth_fs(n: usize) -> u64 {
    CASE_COINBASE_ONLY.total_perms() + n as u64 * MARGINAL_PERMS_PER_STANDARD_TX_NO_AUTH_FS as u64
}

/// Projected full-replay [K] permutations for a block of `n` full Sweep25x2
/// txs, without the auth-FS-transcript killshot. Same conservative linear
/// extrapolation as
/// [`projected_perms_std_txs_no_auth_fs`].
pub fn projected_perms_sweep_txs_no_auth_fs(n: usize) -> u64 {
    CASE_COINBASE_ONLY.total_perms() + n as u64 * MARGINAL_PERMS_PER_SWEEP_TX_NO_AUTH_FS as u64
}

/// Conservative [K] perms upper bound for the consensus-max standard block
/// (255 user txs). Measured post-freeze-diet @255: 71,459 perms without
/// auth-FS (166,975 full replay, ~2^25.8 constraints full / ~2^24.6
/// without).
pub fn projected_perms_max_standard_block_no_auth_fs() -> u64 {
    projected_perms_std_txs_no_auth_fs(BLOCK_MAX_STANDARD_USER_TXS)
}

/// Conservative [K] perms upper bound for the consensus-max sweep block
/// (40 full Sweep25x2 txs).
pub fn projected_perms_max_sweep_block_no_auth_fs() -> u64 {
    projected_perms_sweep_txs_no_auth_fs(BLOCK_MAX_FULL_SWEEP_TXS)
}

const SHAPE_STATS_DOMAIN: &[u8] = b"NOID-TIER1-SHAPE-STATS-P05-V3";

/// Digest pinning this (post-squeeze-diet) measurement snapshot, so
/// downstream consumers can detect a stale table. NOT the protocol
/// `shape_digest` of the public proof interface (that is frozen with the
/// shape classes).
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
        assert_eq!(CASE_COINBASE_ONLY.total_perms(), 634);
        assert_eq!(CASE_USER_TXS_1.total_perms(), 2_782);
        assert_eq!(CASE_USER_TXS_4.total_perms(), 4_812);
        assert_eq!(CASE_USER_TXS_16.total_perms(), 12_398);
        assert_eq!(CASE_USER_TXS_16.total_absorbs(), 21_506);
        assert_eq!(CASE_USER_TXS_16.total_squeezes(), 1_695);
        assert_eq!(CASE_USER_TXS_16.perms_without_auth_fs(), 6_406);
        assert_eq!(CASE_SWEEP_TXS_1.total_perms(), 4_007);
        assert_eq!(CASE_SWEEP_TXS_1.total_absorbs(), 6_169);
        assert_eq!(CASE_SWEEP_TXS_1.total_squeezes(), 945);
        assert_eq!(CASE_SWEEP_TXS_4.total_perms(), 9_123);
        assert_eq!(CASE_SWEEP_TXS_4.total_absorbs(), 15_864);
        assert_eq!(CASE_SWEEP_TXS_4.total_squeezes(), 1_229);
        assert_eq!(CASE_SWEEP_TXS_4.perms_without_auth_fs(), 6_522);
        assert_eq!(
            MARGINAL_PERMS_PER_STANDARD_TX_FULL as u64,
            (CASE_USER_TXS_16.total_perms() - CASE_COINBASE_ONLY.total_perms()) / 16
        );
        assert_eq!(
            MARGINAL_PERMS_PER_STANDARD_TX_NO_AUTH_FS as u64,
            (CASE_USER_TXS_16.perms_without_auth_fs() - CASE_COINBASE_ONLY.total_perms()) / 16
        );
        assert_eq!(
            MARGINAL_PERMS_PER_SWEEP_TX_FULL as u64,
            (CASE_SWEEP_TXS_4.total_perms() - CASE_COINBASE_ONLY.total_perms()) / 4
        );
        assert_eq!(
            MARGINAL_PERMS_PER_SWEEP_TX_NO_AUTH_FS as u64,
            (CASE_SWEEP_TXS_4.perms_without_auth_fs() - CASE_COINBASE_ONLY.total_perms()) / 4
        );
    }

    #[test]
    fn max_shape_projections_track_consensus_params() {
        assert_eq!(BLOCK_MAX_STANDARD_USER_TXS, 255);
        assert_eq!(BLOCK_MAX_FULL_SWEEP_TXS, 40);
        assert_eq!(projected_perms_max_standard_block_no_auth_fs(), 92_434);
        assert_eq!(projected_perms_max_sweep_block_no_auth_fs(), 59_514);
        // The linear projection must stay an upper bound on the measured
        // env-gated 255-tx run (71,459 perms without auth-FS, 2026-07-05).
        assert!(projected_perms_max_standard_block_no_auth_fs() >= 71_459);
    }

    #[test]
    fn shape_stats_digest_is_stable() {
        let a = shape_stats_digest();
        let b = shape_stats_digest();
        assert_eq!(a, b);
        assert_ne!(a, [0u8; 32]);
    }
}
