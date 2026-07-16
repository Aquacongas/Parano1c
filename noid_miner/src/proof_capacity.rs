// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Two-class miner capacity controller.
//!
//! A proof class has essentially fixed work regardless of how many of its
//! physical page slots are live. Capacity decisions therefore use complete
//! B64/B255 preparation timings, never `milliseconds / populated pages`.

use std::time::Duration;

use noid_chain::consensus::paged_spend::BlockProofClass;

const EWMA_PREVIOUS_WEIGHT: f64 = 0.75;

/// Miner-local capacity evidence for the two launch proof classes.
///
/// Every process starts conservatively at B64. Before a real B255 sample
/// exists, its cost is predicted from the one-bit `m23 -> m24` expansion. A
/// real B255 EWMA then becomes authoritative. If that EWMA exceeds the block
/// interval, the process stays at B64 until restart rather than oscillating
/// between an already-known slow B255 probe and B64.
#[derive(Clone, Debug, Default)]
pub struct AdaptiveProofCapacity {
    b64_prepare_ms_ewma: Option<f64>,
    b255_prepare_ms_ewma: Option<f64>,
}

impl AdaptiveProofCapacity {
    /// Physical page budget for the next template: exactly 64 or exactly 255.
    pub fn page_limit(&self) -> usize {
        let target_ms = target_prepare_ms();
        let b255_fits = match self.b255_prepare_ms_ewma {
            Some(measured_ms) => measured_ms <= target_ms,
            None => self
                .b64_prepare_ms_ewma
                .is_some_and(|measured_ms| measured_ms * class_work_ratio() <= target_ms),
        };
        if b255_fits {
            BlockProofClass::B255.page_capacity()
        } else {
            BlockProofClass::B64.page_capacity()
        }
    }

    /// Record one complete nonce-independent HistoryStep preparation.
    pub fn observe_preparation(&mut self, class: BlockProofClass, elapsed: Duration) {
        let sample_ms = elapsed.as_secs_f64() * 1_000.0;
        let ewma = match class {
            BlockProofClass::B64 => &mut self.b64_prepare_ms_ewma,
            BlockProofClass::B255 => &mut self.b255_prepare_ms_ewma,
        };
        *ewma = Some(match *ewma {
            Some(previous) => {
                previous * EWMA_PREVIOUS_WEIGHT + sample_ms * (1.0 - EWMA_PREVIOUS_WEIGHT)
            }
            None => sample_ms,
        });
    }

    /// Current complete-class preparation EWMA in milliseconds.
    pub fn prepare_ms_ewma(&self, class: BlockProofClass) -> Option<f64> {
        match class {
            BlockProofClass::B64 => self.b64_prepare_ms_ewma,
            BlockProofClass::B255 => self.b255_prepare_ms_ewma,
        }
    }
}

#[inline]
fn target_prepare_ms() -> f64 {
    noid_chain::consensus::params::BLOCK_TIME as f64 * 1_000.0
}

#[inline]
fn class_work_ratio() -> f64 {
    let delta = BlockProofClass::B255.outer_m() - BlockProofClass::B64.outer_m();
    (1usize << delta) as f64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn millis(value: u64) -> Duration {
        Duration::from_millis(value)
    }

    #[test]
    fn starts_at_b64_and_has_no_intermediate_limits() {
        let mut capacity = AdaptiveProofCapacity::default();
        assert_eq!(capacity.page_limit(), 64);

        capacity.observe_preparation(BlockProofClass::B64, millis(7_501));
        assert_eq!(capacity.page_limit(), 64);

        let mut exact_boundary = AdaptiveProofCapacity::default();
        exact_boundary.observe_preparation(BlockProofClass::B64, millis(7_500));
        assert_eq!(exact_boundary.page_limit(), 255);
        assert!(matches!(capacity.page_limit(), 64 | 255));
    }

    #[test]
    fn fast_b64_predicts_b255_then_real_b255_becomes_authoritative() {
        let mut capacity = AdaptiveProofCapacity::default();
        capacity.observe_preparation(BlockProofClass::B64, millis(7_000));
        assert_eq!(capacity.page_limit(), 255);

        capacity.observe_preparation(BlockProofClass::B255, millis(14_000));
        assert_eq!(capacity.page_limit(), 255);

        // Later B64 occupancy does not erase direct B255 evidence.
        capacity.observe_preparation(BlockProofClass::B64, millis(20_000));
        assert_eq!(capacity.page_limit(), 255);
    }

    #[test]
    fn slow_real_b255_falls_back_without_oscillation() {
        let mut capacity = AdaptiveProofCapacity::default();
        capacity.observe_preparation(BlockProofClass::B64, millis(5_000));
        assert_eq!(capacity.page_limit(), 255);

        capacity.observe_preparation(BlockProofClass::B255, millis(15_001));
        assert_eq!(capacity.page_limit(), 64);

        capacity.observe_preparation(BlockProofClass::B64, millis(1_000));
        assert_eq!(capacity.page_limit(), 64);
    }
}
