// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Measured tier-1 verifier statistics — the empirical shape inputs for the
//! acceptance-proof trace (the arithmetic F128 replay of the block
//! verifiers).
//!
//! Measured 2026-07-03 by `bench_prover/benches/tier1_shape_stats.rs`
//! **after the O3 squeeze diet** (RLC batching weights are powers of one
//! squeezed challenge — `noid_gkr::batch_eval::squeeze_alphas`; the P0
//! pre-diet snapshot had 24,726 squeezes / 30,120 perms @16 txs): every
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
        ComponentStats { name: ACCEPTED_CLAIM_HASH, instances: 1, absorbs: 488, squeezes: 82, perms: 340 },
        ComponentStats { name: CHECKPOINT_HEADER_HASH, instances: 1, absorbs: 403, squeezes: 77, perms: 291 },
        ComponentStats { name: CHECKPOINT_CHAIN_ACCUMULATOR, instances: 1, absorbs: 318, squeezes: 62, perms: 231 },
    ],
};

/// One block with 1 standard (Standard4x8) user transaction.
pub const CASE_USER_TXS_1: CaseStats = CaseStats {
    name: "user_txs_1",
    user_txs: 1,
    components: &[
        ComponentStats { name: ACCEPTED_CLAIM_HASH, instances: 1, absorbs: 488, squeezes: 82, perms: 340 },
        ComponentStats { name: TX_BODY_STANDARD_SPINE, instances: 1, absorbs: 405, squeezes: 82, perms: 298 },
        ComponentStats { name: TX_ROOT_MERKLE, instances: 1, absorbs: 511, squeezes: 62, perms: 327 },
        ComponentStats { name: OWNER_AUTH, instances: 1, absorbs: 374, squeezes: 48, perms: 251 },
        ComponentStats { name: AUTH_FS_TRANSCRIPTS, instances: 1, absorbs: 1298, squeezes: 92, perms: 757 },
        ComponentStats { name: CHECKPOINT_HEADER_HASH, instances: 1, absorbs: 403, squeezes: 77, perms: 291 },
        ComponentStats { name: CHECKPOINT_CHAIN_ACCUMULATOR, instances: 1, absorbs: 318, squeezes: 62, perms: 231 },
        ComponentStats { name: EXACT_STATE_SLOT_LEAVES, instances: 1, absorbs: 353, squeezes: 67, perms: 254 },
        ComponentStats { name: EXACT_STATE_STATE_PATHS, instances: 1, absorbs: 785, squeezes: 77, perms: 482 },
        ComponentStats { name: EXACT_STATE_GUARD_BUCKETS, instances: 1, absorbs: 320, squeezes: 62, perms: 232 },
        ComponentStats { name: EXACT_STATE_GUARD_PATHS, instances: 1, absorbs: 583, squeezes: 77, perms: 381 },
        ComponentStats { name: EXACT_STATE_STATE_ROOTS, instances: 1, absorbs: 347, squeezes: 67, perms: 251 },
    ],
};

/// One block with 4 standard user transactions.
pub const CASE_USER_TXS_4: CaseStats = CaseStats {
    name: "user_txs_4",
    user_txs: 4,
    components: &[
        ComponentStats { name: ACCEPTED_CLAIM_HASH, instances: 1, absorbs: 488, squeezes: 82, perms: 340 },
        ComponentStats { name: TX_BODY_STANDARD_SPINE, instances: 1, absorbs: 459, squeezes: 92, perms: 337 },
        ComponentStats { name: TX_ROOT_MERKLE, instances: 1, absorbs: 761, squeezes: 72, perms: 464 },
        ComponentStats { name: OWNER_AUTH, instances: 4, absorbs: 1496, squeezes: 192, perms: 1004 },
        ComponentStats { name: AUTH_FS_TRANSCRIPTS, instances: 1, absorbs: 3881, squeezes: 102, perms: 2060 },
        ComponentStats { name: CHECKPOINT_HEADER_HASH, instances: 1, absorbs: 403, squeezes: 77, perms: 291 },
        ComponentStats { name: CHECKPOINT_CHAIN_ACCUMULATOR, instances: 1, absorbs: 318, squeezes: 62, perms: 231 },
        ComponentStats { name: EXACT_STATE_SLOT_LEAVES, instances: 1, absorbs: 461, squeezes: 77, perms: 320 },
        ComponentStats { name: EXACT_STATE_STATE_PATHS, instances: 1, absorbs: 2069, squeezes: 92, perms: 1142 },
        ComponentStats { name: EXACT_STATE_GUARD_BUCKETS, instances: 1, absorbs: 347, squeezes: 67, perms: 251 },
        ComponentStats { name: EXACT_STATE_GUARD_PATHS, instances: 1, absorbs: 583, squeezes: 77, perms: 381 },
        ComponentStats { name: EXACT_STATE_STATE_ROOTS, instances: 1, absorbs: 347, squeezes: 67, perms: 251 },
    ],
};

/// One block with 16 standard user transactions.
pub const CASE_USER_TXS_16: CaseStats = CaseStats {
    name: "user_txs_16",
    user_txs: 16,
    components: &[
        ComponentStats { name: ACCEPTED_CLAIM_HASH, instances: 1, absorbs: 488, squeezes: 82, perms: 340 },
        ComponentStats { name: TX_BODY_STANDARD_SPINE, instances: 1, absorbs: 531, squeezes: 102, perms: 385 },
        ComponentStats { name: TX_ROOT_MERKLE, instances: 1, absorbs: 2045, squeezes: 87, perms: 1124 },
        ComponentStats { name: OWNER_AUTH, instances: 16, absorbs: 5984, squeezes: 768, perms: 4016 },
        ComponentStats { name: AUTH_FS_TRANSCRIPTS, instances: 1, absorbs: 14069, squeezes: 112, perms: 7166 },
        ComponentStats { name: CHECKPOINT_HEADER_HASH, instances: 1, absorbs: 403, squeezes: 77, perms: 291 },
        ComponentStats { name: CHECKPOINT_CHAIN_ACCUMULATOR, instances: 1, absorbs: 318, squeezes: 62, perms: 231 },
        ComponentStats { name: EXACT_STATE_SLOT_LEAVES, instances: 1, absorbs: 749, squeezes: 87, perms: 476 },
        ComponentStats { name: EXACT_STATE_STATE_PATHS, instances: 1, absorbs: 6965, squeezes: 102, perms: 3602 },
        ComponentStats { name: EXACT_STATE_GUARD_BUCKETS, instances: 1, absorbs: 383, squeezes: 72, perms: 275 },
        ComponentStats { name: EXACT_STATE_GUARD_PATHS, instances: 1, absorbs: 583, squeezes: 77, perms: 381 },
        ComponentStats { name: EXACT_STATE_STATE_ROOTS, instances: 1, absorbs: 347, squeezes: 67, perms: 251 },
    ],
};

/// One block with 1 full Sweep25x2 user transaction (25 live inputs, distinct
/// owner per input, 2 outputs — the heaviest per-tx authorization shape).
pub const CASE_SWEEP_TXS_1: CaseStats = CaseStats {
    name: "sweep_txs_1",
    user_txs: 1,
    components: &[
        ComponentStats { name: ACCEPTED_CLAIM_HASH, instances: 1, absorbs: 488, squeezes: 82, perms: 340 },
        ComponentStats { name: TX_BODY_SWEEP_SPINE, instances: 1, absorbs: 453, squeezes: 92, perms: 334 },
        ComponentStats { name: TX_ROOT_MERKLE, instances: 1, absorbs: 511, squeezes: 62, perms: 327 },
        ComponentStats { name: OWNER_AUTH, instances: 1, absorbs: 609, squeezes: 73, perms: 400 },
        ComponentStats { name: AUTH_FS_TRANSCRIPTS, instances: 1, absorbs: 1842, squeezes: 97, perms: 1035 },
        ComponentStats { name: CHECKPOINT_HEADER_HASH, instances: 1, absorbs: 403, squeezes: 77, perms: 291 },
        ComponentStats { name: CHECKPOINT_CHAIN_ACCUMULATOR, instances: 1, absorbs: 318, squeezes: 62, perms: 231 },
        ComponentStats { name: EXACT_STATE_SLOT_LEAVES, instances: 1, absorbs: 699, squeezes: 87, perms: 451 },
        ComponentStats { name: EXACT_STATE_STATE_PATHS, instances: 1, absorbs: 5955, squeezes: 102, perms: 3097 },
        ComponentStats { name: EXACT_STATE_GUARD_BUCKETS, instances: 1, absorbs: 392, squeezes: 72, perms: 280 },
        ComponentStats { name: EXACT_STATE_GUARD_PATHS, instances: 1, absorbs: 583, squeezes: 77, perms: 381 },
        ComponentStats { name: EXACT_STATE_STATE_ROOTS, instances: 1, absorbs: 347, squeezes: 67, perms: 251 },
    ],
};

/// One block with 4 full Sweep25x2 user transactions. The dominant component
/// is the exact-state path batch (216 Merkle paths: 27 touched slots per tx).
pub const CASE_SWEEP_TXS_4: CaseStats = CaseStats {
    name: "sweep_txs_4",
    user_txs: 4,
    components: &[
        ComponentStats { name: ACCEPTED_CLAIM_HASH, instances: 1, absorbs: 488, squeezes: 82, perms: 340 },
        ComponentStats { name: TX_BODY_SWEEP_SPINE, instances: 1, absorbs: 507, squeezes: 102, perms: 373 },
        ComponentStats { name: TX_ROOT_MERKLE, instances: 1, absorbs: 761, squeezes: 72, perms: 464 },
        ComponentStats { name: OWNER_AUTH, instances: 4, absorbs: 2436, squeezes: 292, perms: 1600 },
        ComponentStats { name: AUTH_FS_TRANSCRIPTS, instances: 1, absorbs: 5985, squeezes: 107, perms: 3118 },
        ComponentStats { name: CHECKPOINT_HEADER_HASH, instances: 1, absorbs: 403, squeezes: 77, perms: 291 },
        ComponentStats { name: CHECKPOINT_CHAIN_ACCUMULATOR, instances: 1, absorbs: 318, squeezes: 62, perms: 231 },
        ComponentStats { name: EXACT_STATE_SLOT_LEAVES, instances: 1, absorbs: 1557, squeezes: 97, perms: 892 },
        ComponentStats { name: EXACT_STATE_STATE_PATHS, instances: 1, absorbs: 22365, squeezes: 112, perms: 11314 },
        ComponentStats { name: EXACT_STATE_GUARD_BUCKETS, instances: 1, absorbs: 515, squeezes: 82, perms: 353 },
        ComponentStats { name: EXACT_STATE_GUARD_PATHS, instances: 1, absorbs: 583, squeezes: 77, perms: 381 },
        ComponentStats { name: EXACT_STATE_STATE_ROOTS, instances: 1, absorbs: 347, squeezes: 67, perms: 251 },
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
/// (18538 - 862) / 16, floored. (Pre-squeeze-diet value: 1,820.)
pub const MARGINAL_PERMS_PER_STANDARD_TX_FULL: u32 = 1_104;

/// Marginal perms per standard tx once the auth-FS-transcript killshot is
/// dropped from the trace: (11372 - 862) / 16, floored.
/// (Pre-squeeze-diet value: 835.)
pub const MARGINAL_PERMS_PER_STANDARD_TX_NO_AUTH_FS: u32 = 656;

/// Marginal verifier-FS permutations per full Sweep25x2 tx, full replay:
/// (19608 - 862) / 4, floored.
pub const MARGINAL_PERMS_PER_SWEEP_TX_FULL: u32 = 4_686;

/// Marginal perms per full Sweep25x2 tx (auth-FS-transcript killshot
/// dropped): (19608 - 3118 - 862) / 4. Dominated by the exact-state Merkle
/// path batch (27 touched slots per sweep vs 2 per standard tx).
pub const MARGINAL_PERMS_PER_SWEEP_TX_NO_AUTH_FS: u32 = 3_907;

/// Consensus block maxima (source of truth: `noid_chain::consensus::params`).
/// 255 standard user txs + coinbase, or 40 full Sweep25x2 txs.
pub const BLOCK_MAX_STANDARD_USER_TXS: usize = noid_chain::consensus::params::BLOCK_MAX_USER_TXS;
pub const BLOCK_MAX_FULL_SWEEP_TXS: usize =
    noid_chain::consensus::params::BLOCK_MAX_FULL_SWEEP25X2_TXS;

/// Projected full-replay [K] permutations for a block of `n` standard txs,
/// without the auth-FS-transcript killshot.
///
/// Linear extrapolation of the 16-tx measurement — a conservative UPPER
/// bound: the env-gated 255-tx run (`NOID_SHAPE_MAX_STD=1`, 2026-07-03,
/// post-diet) measured 134,904 perms (no auth-FS) vs 168,142 projected (−20%),
/// because batched-killshot round/terminal costs amortize with batch size
/// while this projection scales them linearly.
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
/// (255 user txs). Measured post-diet @255: 134,904 perms without auth-FS
/// (249,138 full replay, ~2^26.4 constraints full / ~2^25.5 without).
pub fn projected_perms_max_standard_block_no_auth_fs() -> u64 {
    projected_perms_std_txs_no_auth_fs(BLOCK_MAX_STANDARD_USER_TXS)
}

/// Conservative [K] perms upper bound for the consensus-max sweep block
/// (40 full Sweep25x2 txs).
pub fn projected_perms_max_sweep_block_no_auth_fs() -> u64 {
    projected_perms_sweep_txs_no_auth_fs(BLOCK_MAX_FULL_SWEEP_TXS)
}

const SHAPE_STATS_DOMAIN: &[u8] = b"NOID-TIER1-SHAPE-STATS-P05-V2";

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
        assert_eq!(CASE_COINBASE_ONLY.total_perms(), 862);
        assert_eq!(CASE_USER_TXS_1.total_perms(), 4_095);
        assert_eq!(CASE_USER_TXS_4.total_perms(), 7_072);
        assert_eq!(CASE_USER_TXS_16.total_perms(), 18_538);
        assert_eq!(CASE_USER_TXS_16.total_absorbs(), 32_865);
        assert_eq!(CASE_USER_TXS_16.total_squeezes(), 1_695);
        assert_eq!(CASE_USER_TXS_16.perms_without_auth_fs(), 11_372);
        assert_eq!(CASE_SWEEP_TXS_1.total_perms(), 7_418);
        assert_eq!(CASE_SWEEP_TXS_1.total_absorbs(), 12_600);
        assert_eq!(CASE_SWEEP_TXS_1.total_squeezes(), 950);
        assert_eq!(CASE_SWEEP_TXS_4.total_perms(), 19_608);
        assert_eq!(CASE_SWEEP_TXS_4.total_absorbs(), 36_265);
        assert_eq!(CASE_SWEEP_TXS_4.total_squeezes(), 1_229);
        assert_eq!(CASE_SWEEP_TXS_4.perms_without_auth_fs(), 16_490);
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
        assert_eq!(projected_perms_max_standard_block_no_auth_fs(), 168_142);
        assert_eq!(projected_perms_max_sweep_block_no_auth_fs(), 157_142);
        // The linear projection must stay an upper bound on the measured
        // env-gated 255-tx run (134,904 perms without auth-FS, 2026-07-03).
        assert!(projected_perms_max_standard_block_no_auth_fs() >= 134_904);
    }

    #[test]
    fn shape_stats_digest_is_stable() {
        let a = shape_stats_digest();
        let b = shape_stats_digest();
        assert_eq!(a, b);
        assert_ne!(a, [0u8; 32]);
    }
}
