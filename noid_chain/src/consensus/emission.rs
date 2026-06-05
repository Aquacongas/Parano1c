// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Block reward schedule.
//!
//! Reward halves with every state expansion (`log_slots += 1`), floored at 1 NOID.
//!
//! ```text
//! log_slots | expansion | reward
//! ----------|-----------|-------
//!    24      |     0     | 50.000000 NOID  (genesis)
//!    25      |     1     | 25.000000 NOID
//!    26      |     2     | 12.500000 NOID
//!    27      |     3     |  6.250000 NOID
//!    28      |     4     |  3.125000 NOID
//!    29      |     5     |  1.562500 NOID
//!    30+     |     6+    |  1.000000 NOID  (floor, forever)
//! ```
//!
//! Anti-spam property: state expands only when ~75% capacity is reached.
//! Filling slots to trigger expansion halves the miner reward.
//! The natural economic consequence of network growth is decreasing inflation.

use crate::consensus::params::{
    BASE_REWARD_MICRONOID, FLOOR_REWARD_MICRONOID, LOG_SLOTS_GENESIS, MICRONOID_PER_NOID,
};
use noid_tx::types::TxBody;

/// Compute the block reward in μNOID for the given `log_slots` value.
///
/// `log_slots` is the current state capacity exponent from the block header.
/// Halves once per state expansion, never below `FLOOR_REWARD_MICRONOID`.
///
/// # Examples
///
/// ```
/// use noid_chain::consensus::emission::block_reward;
/// assert_eq!(block_reward(24), 50_000_000); // 50 NOID at genesis
/// assert_eq!(block_reward(25), 25_000_000); // 25 NOID after first expansion
/// assert_eq!(block_reward(30), 1_000_000);  // 1 NOID floor
/// assert_eq!(block_reward(32), 1_000_000);  // 1 NOID still
/// ```
pub fn block_reward(log_slots: u32) -> u64 {
    let expansions = log_slots.saturating_sub(LOG_SLOTS_GENESIS);
    BASE_REWARD_MICRONOID
        .checked_shr(expansions)
        .unwrap_or(0)
        .max(FLOOR_REWARD_MICRONOID)
}

/// Sum all transaction fees (non-coinbase) in μNOID.
/// Saturates on overflow rather than panicking.
pub fn total_fees(txs: &[TxBody]) -> u64 {
    txs.iter()
        .filter(|tx| !tx.is_coinbase)
        .map(|tx| tx.fee.min(u64::MAX as u128) as u64)
        .fold(0u64, |acc, f| acc.saturating_add(f))
}

/// Maximum value the coinbase output is permitted to carry (μNOID).
///
/// `coinbase_value ≤ block_reward(log_slots) + total_fees(non_coinbase_txs)`
pub fn max_coinbase_value(log_slots: u32, non_coinbase_txs: &[TxBody]) -> u64 {
    block_reward(log_slots).saturating_add(total_fees(non_coinbase_txs))
}

/// Same as `max_coinbase_value` but accepts a pre-computed fee sum.
///
/// Used by `validate_block_consensus` to avoid cloning all non-coinbase
/// `TxBody` objects just to sum their fees. Saves ~1024 × (Vec allocs +
/// TxInput/TxOutput copies) per block at 1024 txs.
#[inline]
pub fn max_coinbase_value_from_fee_sum(log_slots: u32, fee_sum: u64) -> u64 {
    block_reward(log_slots).saturating_add(fee_sum)
}

/// Format a μNOID amount as a human-readable string (not consensus-critical).
pub fn format_noid(micronoid: u64) -> String {
    let whole = micronoid / MICRONOID_PER_NOID;
    let frac = micronoid % MICRONOID_PER_NOID;
    format!("{}.{:06} NOID", whole, frac)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::params::LOG_SLOTS_MAX;

    #[test]
    fn reward_table_matches_spec() {
        // Exact values from ROADMAP2.md emission table.
        assert_eq!(block_reward(24), 50_000_000, "50 NOID at genesis");
        assert_eq!(block_reward(25), 25_000_000, "25 NOID");
        assert_eq!(block_reward(26), 12_500_000, "12.5 NOID");
        assert_eq!(block_reward(27), 6_250_000, "6.25 NOID");
        assert_eq!(block_reward(28), 3_125_000, "3.125 NOID");
        assert_eq!(block_reward(29), 1_562_500, "1.5625 NOID");
        // log_slots=30: 50_000_000 >> 6 = 781_250 < 1_000_000 → floor
        assert_eq!(block_reward(30), 1_000_000, "1 NOID floor at 30");
        assert_eq!(block_reward(31), 1_000_000, "1 NOID floor at 31");
        assert_eq!(block_reward(32), 1_000_000, "1 NOID floor at max");
    }

    #[test]
    fn floor_never_violated_for_any_log_slots() {
        for log_s in LOG_SLOTS_GENESIS..=LOG_SLOTS_MAX + 10 {
            assert!(
                block_reward(log_s) >= FLOOR_REWARD_MICRONOID,
                "floor violated at log_slots={log_s}"
            );
        }
    }

    #[test]
    fn reward_monotone_non_increasing() {
        let mut prev = block_reward(LOG_SLOTS_GENESIS);
        for log_s in (LOG_SLOTS_GENESIS + 1)..=LOG_SLOTS_MAX {
            let curr = block_reward(log_s);
            assert!(
                curr <= prev,
                "reward increased from log_slots={} to {}",
                log_s - 1,
                log_s
            );
            prev = curr;
        }
    }

    #[test]
    fn halving_per_expansion() {
        // Each expansion halves until floor.
        assert_eq!(block_reward(25), block_reward(24) / 2);
        assert_eq!(block_reward(26), block_reward(25) / 2);
        assert_eq!(block_reward(27), block_reward(26) / 2);
        assert_eq!(block_reward(28), block_reward(27) / 2);
        assert_eq!(block_reward(29), block_reward(28) / 2);
        // At 30+, floor prevents further halving.
        assert_eq!(block_reward(30), block_reward(31));
    }

    #[test]
    fn total_fees_sums_non_coinbase() {
        use noid_tx::types::TxBody;
        let coinbase = TxBody {
            fee: 0,
            is_coinbase: true,
            inputs: vec![],
            outputs: vec![],
            epoch_anchor: [0; 32],
        };
        let tx1 = TxBody {
            fee: 5_000_000,
            is_coinbase: false,
            inputs: vec![],
            outputs: vec![],
            epoch_anchor: [0; 32],
        };
        let tx2 = TxBody {
            fee: 3_000_000,
            is_coinbase: false,
            inputs: vec![],
            outputs: vec![],
            epoch_anchor: [0; 32],
        };
        assert_eq!(total_fees(&[coinbase, tx1, tx2]), 8_000_000);
    }

    #[test]
    fn max_coinbase_at_genesis() {
        // No fees, genesis: max coinbase = 50 NOID.
        assert_eq!(max_coinbase_value(24, &[]), 50_000_000);
    }

    #[test]
    fn expansion_is_anti_spam() {
        // Spamming to trigger expansion (24→25) cuts reward from 50 to 25 NOID/block.
        let before = block_reward(24);
        let after = block_reward(25);
        assert_eq!(after, before / 2, "expansion must halve reward");
        // Attacker who fills 2^24 slots triggers expansion,
        // immediately halving their own mining income.
    }

    #[test]
    fn format_noid_display() {
        assert_eq!(format_noid(50_000_000), "50.000000 NOID");
        assert_eq!(format_noid(1_562_500), "1.562500 NOID");
        assert_eq!(format_noid(1_000_000), "1.000000 NOID");
        assert_eq!(format_noid(0), "0.000000 NOID");
    }
}
