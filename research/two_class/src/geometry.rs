// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Exact launch geometry after the A128 cancellation.

pub const BLOCK_TARGET_SECONDS: usize = 15;

pub const B64_PAGE_CAPACITY: usize = 64;
pub const B64_AUTHORIZATION_CAPACITY: usize = 64;
pub const B64_INPUT_CAPACITY: usize = 512;
pub const B64_OUTPUT_CAPACITY: usize = 128;
pub const B64_TOUCHED_CAPACITY: usize = 641;
pub const B64_ACTION_CANDIDATES: usize = 641;
pub const B64_ACTION_SORT_CAPACITY: usize = 1_024;
pub const B64_OUTER_M: usize = 23;

pub const B255_PAGE_CAPACITY: usize = 255;
pub const B255_LIVE_AUTHORIZATION_CAPACITY: usize = 255;
pub const B255_AUTHORIZATION_TILE_CAPACITY: usize = 256;
pub const B255_INPUT_CAPACITY: usize = 1_020;
pub const B255_OUTPUT_CAPACITY: usize = 510;
pub const B255_TOUCHED_CAPACITY: usize = 1_531;
pub const B255_ACTION_CANDIDATES: usize = 2_551;
pub const B255_ACTION_SORT_CAPACITY: usize = 4_096;
pub const B255_OUTER_M: usize = 24;

pub const LOGICAL_PAGE_CAPACITY: usize = 128;
pub const LOGICAL_INPUT_CAPACITY: usize = 1_020;
pub const LOGICAL_OUTPUT_CAPACITY: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProofClass {
    B64,
    B255,
}

impl ProofClass {
    pub const fn for_page_count(page_count: usize) -> Option<Self> {
        if page_count <= B64_PAGE_CAPACITY {
            Some(Self::B64)
        } else if page_count <= B255_PAGE_CAPACITY {
            Some(Self::B255)
        } else {
            None
        }
    }

    pub const fn page_capacity(self) -> usize {
        match self {
            Self::B64 => B64_PAGE_CAPACITY,
            Self::B255 => B255_PAGE_CAPACITY,
        }
    }

    pub const fn live_authorization_capacity(self) -> usize {
        match self {
            Self::B64 => B64_AUTHORIZATION_CAPACITY,
            Self::B255 => B255_LIVE_AUTHORIZATION_CAPACITY,
        }
    }

    pub const fn authorization_tile_capacity(self) -> usize {
        match self {
            Self::B64 => B64_AUTHORIZATION_CAPACITY,
            Self::B255 => B255_AUTHORIZATION_TILE_CAPACITY,
        }
    }

    pub const fn input_capacity(self) -> usize {
        match self {
            Self::B64 => B64_INPUT_CAPACITY,
            Self::B255 => B255_INPUT_CAPACITY,
        }
    }

    pub const fn output_capacity(self) -> usize {
        match self {
            Self::B64 => B64_OUTPUT_CAPACITY,
            Self::B255 => B255_OUTPUT_CAPACITY,
        }
    }

    pub const fn outer_m(self) -> usize {
        match self {
            Self::B64 => B64_OUTER_M,
            Self::B255 => B255_OUTER_M,
        }
    }
}

pub fn b64_saturated_tps() -> f64 {
    B64_PAGE_CAPACITY as f64 / BLOCK_TARGET_SECONDS as f64
}

pub fn protocol_saturated_tps() -> f64 {
    B255_PAGE_CAPACITY as f64 / BLOCK_TARGET_SECONDS as f64
}

const _: () = assert!(B64_PAGE_CAPACITY * noid_tx::TX_INPUTS == B64_INPUT_CAPACITY);
const _: () = assert!(B64_PAGE_CAPACITY * noid_tx::TX_OUTPUTS == B64_OUTPUT_CAPACITY);
const _: () = assert!(B64_INPUT_CAPACITY + B64_OUTPUT_CAPACITY + 1 == B64_TOUCHED_CAPACITY);
const _: () = assert!(B64_PAGE_CAPACITY * noid_tx::TX_ACTIONS + 1 == B64_ACTION_CANDIDATES);
const _: () = assert!(B64_ACTION_CANDIDATES.next_power_of_two() == B64_ACTION_SORT_CAPACITY);
const _: () = assert!(B255_INPUT_CAPACITY + B255_OUTPUT_CAPACITY + 1 == B255_TOUCHED_CAPACITY);
const _: () = assert!(B255_PAGE_CAPACITY * noid_tx::TX_ACTIONS + 1 == B255_ACTION_CANDIDATES);
const _: () = assert!(B255_ACTION_CANDIDATES.next_power_of_two() == B255_ACTION_SORT_CAPACITY);
const _: () = assert!(B255_AUTHORIZATION_TILE_CAPACITY.is_power_of_two());
const _: () = assert!(LOGICAL_PAGE_CAPACITY > B64_PAGE_CAPACITY);
const _: () = assert!(LOGICAL_PAGE_CAPACITY <= B255_PAGE_CAPACITY);
const _: () = assert!(BLOCK_TARGET_SECONDS == noid_chain::consensus::params::BLOCK_TIME as usize);
const _: () = assert!(B255_PAGE_CAPACITY == noid_chain::consensus::params::BLOCK_MAX_USER_TXS);
const _: () = assert!(B255_INPUT_CAPACITY == noid_chain::consensus::params::BLOCK_MAX_LIVE_INPUTS);
const _: () =
    assert!(B255_OUTPUT_CAPACITY == noid_chain::consensus::params::BLOCK_MAX_USER_OUTPUTS);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn class_boundary_is_exact_and_non_overlapping() {
        assert_eq!(ProofClass::for_page_count(0), Some(ProofClass::B64));
        assert_eq!(ProofClass::for_page_count(64), Some(ProofClass::B64));
        assert_eq!(ProofClass::for_page_count(65), Some(ProofClass::B255));
        assert_eq!(ProofClass::for_page_count(255), Some(ProofClass::B255));
        assert_eq!(ProofClass::for_page_count(256), None);
    }

    #[test]
    fn launch_capacity_is_honest() {
        assert!((b64_saturated_tps() - 4.266_666_666).abs() < 1e-9);
        assert_eq!(protocol_saturated_tps(), 17.0);
        assert_eq!(ProofClass::B64.outer_m(), 23);
        assert_eq!(ProofClass::B255.outer_m(), 24);
    }
}
