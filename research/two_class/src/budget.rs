// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Honest row ledger for strategy selection.
//!
//! The direct-SIMD candidate is tested first. The former 2,307,136 auth-only
//! number is retained nowhere as a gate: the actual authority is the complete
//! m23 relation plus measured preparation/proving performance.

pub const M23_ROWS: usize = 1 << 23;
pub const PREFERRED_USEFUL_ROWS: usize = 7_600_000;

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
}
