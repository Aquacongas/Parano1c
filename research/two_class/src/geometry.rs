// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Research-facing names for the production B64/B255 geometry.

pub use noid_chain::consensus::paged_spend::BlockProofClass as ProofClass;

pub const BLOCK_TARGET_SECONDS: usize = noid_chain::consensus::params::BLOCK_TIME as usize;

pub const B64_PAGE_CAPACITY: usize = ProofClass::B64.page_capacity();
pub const B64_AUTHORIZATION_CAPACITY: usize = ProofClass::B64.live_authorization_capacity();
pub const B64_INPUT_CAPACITY: usize = ProofClass::B64.input_capacity();
pub const B64_OUTPUT_CAPACITY: usize = ProofClass::B64.output_capacity();
pub const B64_TOUCHED_CAPACITY: usize = B64_INPUT_CAPACITY + B64_OUTPUT_CAPACITY + 1;
pub const B64_ACTION_CANDIDATES: usize = B64_PAGE_CAPACITY * noid_tx::TX_ACTIONS + 1;
pub const B64_ACTION_SORT_CAPACITY: usize = B64_ACTION_CANDIDATES.next_power_of_two();
pub const B64_OUTER_M: usize = ProofClass::B64.outer_m();

pub const B255_PAGE_CAPACITY: usize = ProofClass::B255.page_capacity();
pub const B255_LIVE_AUTHORIZATION_CAPACITY: usize = ProofClass::B255.live_authorization_capacity();
pub const B255_AUTHORIZATION_TILE_CAPACITY: usize = ProofClass::B255.authorization_tile_capacity();
pub const B255_INPUT_CAPACITY: usize = ProofClass::B255.input_capacity();
pub const B255_OUTPUT_CAPACITY: usize = ProofClass::B255.output_capacity();
pub const B255_TOUCHED_CAPACITY: usize = B255_INPUT_CAPACITY + B255_OUTPUT_CAPACITY + 1;
pub const B255_ACTION_CANDIDATES: usize = B255_PAGE_CAPACITY * noid_tx::TX_ACTIONS + 1;
pub const B255_ACTION_SORT_CAPACITY: usize = B255_ACTION_CANDIDATES.next_power_of_two();
pub const B255_OUTER_M: usize = ProofClass::B255.outer_m();

pub const LOGICAL_PAGE_CAPACITY: usize = noid_tx::MAX_PAGED_SPEND_PAGES;
pub const LOGICAL_INPUT_CAPACITY: usize = noid_tx::MAX_PAGED_SPEND_INPUTS;
pub const LOGICAL_OUTPUT_CAPACITY: usize = noid_tx::MAX_PAGED_SPEND_OUTPUTS;

pub fn b64_saturated_tps() -> f64 {
    B64_PAGE_CAPACITY as f64 / BLOCK_TARGET_SECONDS as f64
}

pub fn protocol_saturated_tps() -> f64 {
    B255_PAGE_CAPACITY as f64 / BLOCK_TARGET_SECONDS as f64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn research_names_are_exact_production_aliases() {
        assert_eq!(ProofClass::for_page_count(0), Some(ProofClass::B64));
        assert_eq!(ProofClass::for_page_count(64), Some(ProofClass::B64));
        assert_eq!(ProofClass::for_page_count(65), Some(ProofClass::B255));
        assert_eq!(ProofClass::for_page_count(255), Some(ProofClass::B255));
        assert_eq!(ProofClass::for_page_count(256), None);
        assert_eq!(B64_OUTER_M, 23);
        assert_eq!(B255_OUTER_M, 24);
        assert_eq!(protocol_saturated_tps(), 17.0);
    }
}
