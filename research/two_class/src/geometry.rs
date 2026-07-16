// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Fixed two-class research geometry and capacity claims.

pub const COMMODITY_PAGE_CAPACITY: usize = 128;
pub const COMMODITY_AUTHORIZATION_CAPACITY: usize = 128;
pub const EXTENDED_PAGE_CAPACITY: usize = 255;
pub const EXTENDED_AUTHORIZATION_CAPACITY: usize = 256;

pub const LOGICAL_PAGE_CAPACITY: usize = COMMODITY_PAGE_CAPACITY;
pub const INPUT_CAPACITY: usize = 1_020;
pub const LOGICAL_OUTPUT_CAPACITY: usize = 256;
pub const BLOCK_OUTPUT_CAPACITY: usize = 510;
pub const MEAN_BLOCK_SECONDS: u64 = 15;

// Compatibility names used by the active B128 relation modules.
pub const PAGE_CAPACITY: usize = COMMODITY_PAGE_CAPACITY;
pub const AUTHORIZATION_CAPACITY: usize = COMMODITY_AUTHORIZATION_CAPACITY;
pub const OUTPUT_CAPACITY: usize = LOGICAL_OUTPUT_CAPACITY;

pub const B128_ACTION_CANDIDATES: usize = 1 + COMMODITY_PAGE_CAPACITY * 10;
pub const B128_LIVE_ACTION_CAPACITY: usize = 1 + INPUT_CAPACITY + LOGICAL_OUTPUT_CAPACITY;
pub const B128_ACTION_SORT_CAPACITY: usize = B128_ACTION_CANDIDATES.next_power_of_two();

pub const B256_ACTION_CANDIDATES: usize = 1 + EXTENDED_PAGE_CAPACITY * 10;
pub const B256_LIVE_ACTION_CAPACITY: usize = 1 + INPUT_CAPACITY + BLOCK_OUTPUT_CAPACITY;
pub const B256_ACTION_SORT_CAPACITY: usize = B256_ACTION_CANDIDATES.next_power_of_two();

// Compatibility names used by existing B128 tests.
pub const ACTION_CANDIDATES: usize = B128_ACTION_CANDIDATES;
pub const LIVE_ACTION_CAPACITY: usize = B128_LIVE_ACTION_CAPACITY;
pub const ACTION_SORT_CAPACITY: usize = B128_ACTION_SORT_CAPACITY;

pub fn reference_l1_tps() -> f64 {
    COMMODITY_AUTHORIZATION_CAPACITY as f64 / MEAN_BLOCK_SECONDS as f64
}

pub fn protocol_l1_tps() -> f64 {
    EXTENDED_PAGE_CAPACITY as f64 / MEAN_BLOCK_SECONDS as f64
}

const _: () = assert!(LOGICAL_PAGE_CAPACITY == 128);
const _: () = assert!(EXTENDED_PAGE_CAPACITY + 1 == 256);
const _: () = assert!(B128_ACTION_CANDIDATES == 1_281);
const _: () = assert!(B128_LIVE_ACTION_CAPACITY == 1_277);
const _: () = assert!(B128_ACTION_SORT_CAPACITY == 2_048);
const _: () = assert!(B256_ACTION_CANDIDATES == 2_551);
const _: () = assert!(B256_LIVE_ACTION_CAPACITY == 1_531);
const _: () = assert!(B256_ACTION_SORT_CAPACITY == 4_096);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_class_geometry_and_capacity_claims_are_exact() {
        assert!((reference_l1_tps() - 8.533_333_333_333_333).abs() < 1e-12);
        assert!((protocol_l1_tps() - 17.0).abs() < 1e-12);
        assert_eq!(LOGICAL_PAGE_CAPACITY * noid_tx::TX_INPUTS, 1_024);
        assert_eq!(INPUT_CAPACITY, 1_020);
    }
}
