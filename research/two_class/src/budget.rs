// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Honest row ledger for strategy selection.
//!
//! The direct-SIMD candidate is tested first. The former 2,307,136 auth-only
//! number is retained nowhere as a gate: the actual authority is the complete
//! m23 relation plus measured preparation/proving performance.

pub const M23_ROWS: usize = 1 << 23;
pub const PREFERRED_USEFUL_ROWS: usize = 7_600_000;

/// Fresh production baseline measured with the canonical B64 direct-Block
/// builder and the frozen four-leaf HistoryStep pack on 2026-07-16.
pub const PRODUCTION_B64_DIRECT_BLOCK_ROWS: usize = 3_770_072;
pub const PRODUCTION_B64_SELECTED_AUTH_META_ROWS: usize = 3_222_366;
pub const PRODUCTION_B64_HISTORY_STEP_ROWS: usize = 6_384_112;
pub const PRODUCTION_B64_SHARED_HISTORY_ROWS: usize =
    PRODUCTION_B64_HISTORY_STEP_ROWS - PRODUCTION_B64_DIRECT_BLOCK_ROWS;

/// A conventional A128 extension doubles B64's six committed authorization
/// and Meta column domains. These cells and the raw per-capsule verifier rows
/// are disjoint allocations, so their sum is an honest floor before any
/// PagedSpend, exact-state connection, recursion or public IO.
pub const STANDARD_A128_COMMITTED_AUTH_META_CELLS: usize = 4_489_216;
pub const STANDARD_AUTH_RAW_ROWS_PER_CAPSULE: usize = 12_241;
pub const STANDARD_A128_RAW_CAPSULE_ROWS: usize = 128 * STANDARD_AUTH_RAW_ROWS_PER_CAPSULE;
pub const STANDARD_A128_AUTH_META_FLOOR: usize =
    STANDARD_A128_COMMITTED_AUTH_META_CELLS + STANDARD_A128_RAW_CAPSULE_ROWS;
pub const STANDARD_A128_WITH_B64_SHARED_BASELINE: usize =
    STANDARD_A128_AUTH_META_FLOOR + PRODUCTION_B64_SHARED_HISTORY_ROWS;

pub const OWNER_ROWS_A128: usize = 98_304;
pub const MAIN_ROWS_A128: usize = 196_608;
pub const TRANSPOSED_WALLET_A_ROWS_A128: usize = 884_736;
pub const FOREST_WALLET_B_ROWS_A128: usize = 845_568;

/// Scalar statement/transcript/wrapper work retained in the main relation.
pub const DIRECT_SIMD_RESIDUAL_ROWS_A128: usize = 173_312;
/// Eighty-two multiplication outputs for each of 128*64 query lanes, kept in
/// the main relation in the simple candidate rather than moved to a child.
pub const DIRECT_SIMD_QUERY_ROWS_A128: usize = 671_744;
pub const DIRECT_SIMD_SCALAR_ROWS_A128: usize =
    DIRECT_SIMD_RESIDUAL_ROWS_A128 + DIRECT_SIMD_QUERY_ROWS_A128;

pub const DIRECT_SIMD_AUTH_ROWS_A128: usize = OWNER_ROWS_A128
    + MAIN_ROWS_A128
    + TRANSPOSED_WALLET_A_ROWS_A128
    + FOREST_WALLET_B_ROWS_A128
    + DIRECT_SIMD_SCALAR_ROWS_A128;

/// The eight Meta-A columns required by the B128 page/exact-state carrier.
pub const META_A_ROWS_A128: usize = 8 * (1 << 15);

/// Every component whose P128 row count is already frozen. This is not the
/// complete relation: tx-root/header/public IO, parent-union replay, sidecar
/// replay and final assembly gaps must consume the remaining budget.
pub const KNOWN_OPTIMIZED_CORE_ROWS_A128: usize =
    crate::partial_candidate::P128_PARTIAL_NONAUTH_ROWS
        + crate::exact_state_relation::P128_EXACT_STATE_STRUCTURAL_ROWS
        + crate::exact_state_relation::P128_EXACT_STATE_CONNECTION_ROWS
        + crate::exact_state_relation::P128_EXACT_STATE_INTERFACE_ALIAS_ROWS
        + crate::exact_state_relation::P128_PAIRED_COMMITTED_CELLS
        + META_A_ROWS_A128
        + DIRECT_SIMD_AUTH_ROWS_A128;
pub const OPTIMIZED_UNRESOLVED_BUDGET_A128: usize = M23_ROWS - KNOWN_OPTIMIZED_CORE_ROWS_A128;
pub const OPTIMIZED_MARGIN_AFTER_B64_SHARED_BASELINE: isize =
    OPTIMIZED_UNRESOLVED_BUDGET_A128 as isize - PRODUCTION_B64_SHARED_HISTORY_ROWS as isize;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CompleteCandidateCensus {
    pub non_authorization_rows: usize,
    pub authorization_rows: usize,
    pub prepare_p95_millis: Option<u64>,
    pub prove_p95_millis: Option<u64>,
    pub verify_p95_millis: Option<u64>,
    pub peak_rss_bytes: Option<u64>,
}

impl CompleteCandidateCensus {
    pub const fn direct_simd(non_authorization_rows: usize) -> Self {
        Self {
            non_authorization_rows,
            authorization_rows: DIRECT_SIMD_AUTH_ROWS_A128,
            prepare_p95_millis: None,
            prove_p95_millis: None,
            verify_p95_millis: None,
            peak_rss_bytes: None,
        }
    }

    pub const fn useful_rows(self) -> usize {
        self.non_authorization_rows + self.authorization_rows
    }

    pub const fn fits_m23(self) -> bool {
        self.useful_rows() <= M23_ROWS
    }

    pub const fn has_measurements(self) -> bool {
        self.prepare_p95_millis.is_some()
            && self.prove_p95_millis.is_some()
            && self.verify_p95_millis.is_some()
            && self.peak_rss_bytes.is_some()
    }

    pub const fn research_gate_complete(self) -> bool {
        self.fits_m23() && self.has_measurements()
    }
}

const _: () = assert!(DIRECT_SIMD_SCALAR_ROWS_A128 == 845_056);
const _: () = assert!(DIRECT_SIMD_AUTH_ROWS_A128 == 2_870_272);
const _: () = assert!(PRODUCTION_B64_SHARED_HISTORY_ROWS == 2_614_040);
const _: () = assert!(STANDARD_A128_AUTH_META_FLOOR == 6_056_064);
const _: () = assert!(STANDARD_A128_WITH_B64_SHARED_BASELINE == 8_670_104);
const _: () = assert!(KNOWN_OPTIMIZED_CORE_ROWS_A128 == 5_721_968);
const _: () = assert!(OPTIMIZED_UNRESOLVED_BUDGET_A128 == 2_666_640);
const _: () = assert!(OPTIMIZED_MARGIN_AFTER_B64_SHARED_BASELINE == 52_600);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direct_simd_is_the_first_honest_candidate() {
        assert_eq!(DIRECT_SIMD_AUTH_ROWS_A128, 2_870_272);
        let census = CompleteCandidateCensus::direct_simd(0);
        assert!(census.fits_m23());
        assert!(!census.research_gate_complete());
    }

    #[test]
    fn total_relation_not_auth_subtotal_is_the_geometry_gate() {
        let fits = CompleteCandidateCensus::direct_simd(M23_ROWS - DIRECT_SIMD_AUTH_ROWS_A128);
        assert!(fits.fits_m23());
        let misses =
            CompleteCandidateCensus::direct_simd(M23_ROWS - DIRECT_SIMD_AUTH_ROWS_A128 + 1);
        assert!(!misses.fits_m23());
    }

    #[test]
    fn production_baseline_rejects_the_conventional_a128_layout() {
        assert_eq!(PRODUCTION_B64_SHARED_HISTORY_ROWS, 2_614_040);
        assert_eq!(STANDARD_A128_AUTH_META_FLOOR, 6_056_064);
        assert!(STANDARD_A128_WITH_B64_SHARED_BASELINE > M23_ROWS);
    }

    #[test]
    fn optimized_candidate_exposes_rather_than_hides_the_remaining_risk() {
        assert_eq!(KNOWN_OPTIMIZED_CORE_ROWS_A128, 5_721_968);
        assert_eq!(OPTIMIZED_UNRESOLVED_BUDGET_A128, 2_666_640);
        assert_eq!(OPTIMIZED_MARGIN_AFTER_B64_SHARED_BASELINE, 52_600);
    }
}
