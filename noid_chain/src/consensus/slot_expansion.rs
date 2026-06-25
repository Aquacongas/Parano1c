// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Exact `log_slots` expansion rule.
//!
//! The rule is consensus-critical because `log_slots` is committed by the
//! semantic header and changes transaction fee/reward/state domains.

use crate::consensus::params::{EXPAND_DENOM, EXPAND_NUM, LOG_SLOTS_MAX};
use crate::consensus::timestamps::median_u64;

/// Return the only `log_slots` value valid for the child of a parent header.
///
/// `prev_active_counts` is the oldest-first expansion window ending at the
/// parent. If the chain is too short to fill the window, the caller supplies
/// the available prefix. Empty input falls back to the parent count.
pub fn expected_child_log_slots(
    parent_log_slots: u32,
    parent_active_slot_count: u64,
    prev_active_counts: &[u64],
) -> u32 {
    let prev_capacity = 1u64.checked_shl(parent_log_slots).unwrap_or(u64::MAX);
    let median_active = if prev_active_counts.is_empty() {
        parent_active_slot_count
    } else {
        median_u64(prev_active_counts)
    };
    let trigger =
        median_active.saturating_mul(EXPAND_DENOM) >= prev_capacity.saturating_mul(EXPAND_NUM);
    if trigger {
        parent_log_slots.saturating_add(1).min(LOG_SLOTS_MAX)
    } else {
        parent_log_slots
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_expansion_below_threshold() {
        assert_eq!(expected_child_log_slots(8, 0, &[0; 18]), 8);
    }

    #[test]
    fn expands_at_threshold() {
        assert_eq!(expected_child_log_slots(8, 0, &[192; 18]), 9);
    }

    #[test]
    fn expansion_saturates_at_max() {
        assert_eq!(
            expected_child_log_slots(LOG_SLOTS_MAX, 0, &[u64::MAX; 18]),
            LOG_SLOTS_MAX
        );
    }
}
