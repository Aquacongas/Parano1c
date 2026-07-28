// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Deterministic launch-period development allocation.
//!
//! For the first three target-time years after genesis, miners receive 90% of
//! each block subsidy. O(1) Network Fund and O(1) Lab each receive one
//! mandatory daily payout calculated from the reward tier active in the payout
//! block. A state expansion during that day can therefore make the effective
//! fund share smaller than 5%; the difference is never issued. Fees remain
//! entirely miner-claimable after the existing state-growth burn.

use noid_poseidon2b::primitives::Address;

use super::emission::block_reward;

/// Four 15-second target blocks per minute.
pub const TARGET_BLOCKS_PER_DAY: u64 = 5_760;

/// Three 365-day target-time years, excluding built-in genesis height zero.
pub const DEVELOPMENT_ALLOCATION_END_HEIGHT: u64 = TARGET_BLOCKS_PER_DAY * 365 * 3;

/// Number of mandatory daily payouts over the allocation period.
pub const DEVELOPMENT_ALLOCATION_PAYOUTS: u64 =
    DEVELOPMENT_ALLOCATION_END_HEIGHT / TARGET_BLOCKS_PER_DAY;

/// One maximum fund share is one twentieth (5%) of the block subsidy.
pub const DEVELOPMENT_SHARE_DENOMINATOR: u64 = 20;

/// O(1) Network Fund recipient.
pub const O1_NETWORK_FUND_ADDRESS: Address = Address([
    0xfb, 0xe9, 0xd0, 0xe5, 0x82, 0x00, 0x21, 0x00, 0xcd, 0x23, 0x68, 0x97, 0x0d, 0x18, 0x06, 0xf8,
    0xa3, 0x1b, 0xc0, 0x1d, 0x54, 0xd1, 0x2e, 0xc1, 0x75, 0x4a, 0x89, 0x45, 0x16, 0x89, 0x47, 0x25,
]);

/// O(1) Lab recipient.
pub const O1_LAB_ADDRESS: Address = Address([
    0xd3, 0xa5, 0xc2, 0x08, 0x45, 0x2b, 0x52, 0xe5, 0xaa, 0x7c, 0x9a, 0x79, 0x8f, 0xb7, 0xb5, 0x52,
    0xac, 0xf3, 0x96, 0xb1, 0xdd, 0x1e, 0x48, 0xdd, 0xf3, 0xc0, 0x0c, 0xc8, 0x34, 0xf9, 0x90, 0x96,
]);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DevelopmentAllocation {
    /// The block subsidy is still inside the three-year allocation period.
    pub active: bool,
    /// The block must carry the mandatory two-output daily payout.
    pub payout_due: bool,
    /// Five percent of the reward tier active in this block.
    pub share_each: u64,
    /// Exact amount of each daily payout output.
    pub payout_each: Option<u64>,
    /// Maximum subsidy component claimable by the primary coinbase.
    pub miner_subsidy: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DevelopmentAllocationError {
    InexactRewardShare,
    PayoutOverflow,
}

impl core::fmt::Display for DevelopmentAllocationError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for DevelopmentAllocationError {}

#[inline]
pub const fn development_allocation_active(height: u64) -> bool {
    height > 0 && height <= DEVELOPMENT_ALLOCATION_END_HEIGHT
}

#[inline]
pub const fn development_payout_due(height: u64) -> bool {
    development_allocation_active(height) && height.is_multiple_of(TARGET_BLOCKS_PER_DAY)
}

/// Exact five-percent share of one subsidy.
pub fn development_share_each(subsidy: u64) -> Result<u64, DevelopmentAllocationError> {
    if !subsidy.is_multiple_of(DEVELOPMENT_SHARE_DENOMINATOR) {
        return Err(DevelopmentAllocationError::InexactRewardShare);
    }
    Ok(subsidy / DEVELOPMENT_SHARE_DENOMINATOR)
}

/// Subsidy component available to the primary coinbase at `height`.
#[inline]
pub fn miner_subsidy(height: u64, log_slots: u32) -> u64 {
    let subsidy = block_reward(log_slots);
    if development_allocation_active(height) {
        let share = development_share_each(subsidy)
            .expect("the fixed emission schedule is exactly divisible by twenty");
        subsidy - 2 * share
    } else {
        subsidy
    }
}

/// Compute the complete stateless allocation for one child block.
///
/// Every daily payout uses the reward tier active in that payout block for the
/// whole target-time day. Because state depth and reward are monotone, this can
/// only leave part of the maximum development share unissued; it can never
/// create additional issuance.
pub fn development_allocation(
    child_height: u64,
    child_log_slots: u32,
) -> Result<DevelopmentAllocation, DevelopmentAllocationError> {
    let subsidy = block_reward(child_log_slots);
    if !development_allocation_active(child_height) {
        return Ok(DevelopmentAllocation {
            active: false,
            payout_due: false,
            share_each: 0,
            payout_each: None,
            miner_subsidy: subsidy,
        });
    }

    let share_each = development_share_each(subsidy)?;
    let payout_due = development_payout_due(child_height);
    let payout_each = if payout_due {
        Some(
            share_each
                .checked_mul(TARGET_BLOCKS_PER_DAY)
                .ok_or(DevelopmentAllocationError::PayoutOverflow)?,
        )
    } else {
        None
    };

    Ok(DevelopmentAllocation {
        active: true,
        payout_due,
        share_each,
        payout_each,
        miner_subsidy: subsidy - 2 * share_each,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::params::{LOG_SLOTS_GENESIS, LOG_SLOTS_MAX};

    #[test]
    fn schedule_edges_are_exact() {
        assert!(!development_allocation_active(0));
        assert!(development_allocation_active(1));
        assert!(!development_payout_due(TARGET_BLOCKS_PER_DAY - 1));
        assert!(development_payout_due(TARGET_BLOCKS_PER_DAY));
        assert!(!development_payout_due(TARGET_BLOCKS_PER_DAY + 1));
        assert!(development_allocation_active(
            DEVELOPMENT_ALLOCATION_END_HEIGHT
        ));
        assert!(development_payout_due(DEVELOPMENT_ALLOCATION_END_HEIGHT));
        assert!(!development_allocation_active(
            DEVELOPMENT_ALLOCATION_END_HEIGHT + 1
        ));
        assert_eq!(DEVELOPMENT_ALLOCATION_PAYOUTS, 1_095);
    }

    #[test]
    fn every_reward_tier_reserves_at_most_ninety_five_five() {
        for depth in LOG_SLOTS_GENESIS..=LOG_SLOTS_MAX {
            let subsidy = block_reward(depth);
            let share = development_share_each(subsidy).unwrap();
            let allocation = development_allocation(1, depth).unwrap();
            assert_eq!(allocation.share_each, share);
            assert_eq!(allocation.miner_subsidy + 2 * share, subsidy);
        }
    }

    #[test]
    fn daily_payout_uses_the_payout_blocks_reward_tier() {
        for depth in LOG_SLOTS_GENESIS..=LOG_SLOTS_MAX {
            let share = development_share_each(block_reward(depth)).unwrap();
            let allocation = development_allocation(TARGET_BLOCKS_PER_DAY, depth).unwrap();
            assert_eq!(allocation.payout_each, Some(share * TARGET_BLOCKS_PER_DAY));
        }
    }

    #[test]
    fn expansion_day_conservatively_uses_the_lower_reward() {
        let old_share = development_share_each(block_reward(LOG_SLOTS_GENESIS)).unwrap();
        let new_share = development_share_each(block_reward(LOG_SLOTS_GENESIS + 1)).unwrap();
        let allocation =
            development_allocation(TARGET_BLOCKS_PER_DAY, LOG_SLOTS_GENESIS + 1).unwrap();
        assert_eq!(
            allocation.payout_each,
            Some(new_share * TARGET_BLOCKS_PER_DAY)
        );
        assert!(new_share < old_share);
    }

    #[test]
    fn final_payout_is_followed_by_full_miner_reward() {
        let final_allocation =
            development_allocation(DEVELOPMENT_ALLOCATION_END_HEIGHT, LOG_SLOTS_GENESIS).unwrap();
        assert!(final_allocation.payout_due);
        assert!(final_allocation.payout_each.is_some());

        let post = development_allocation(DEVELOPMENT_ALLOCATION_END_HEIGHT + 1, LOG_SLOTS_GENESIS)
            .unwrap();
        assert!(!post.active);
        assert!(!post.payout_due);
        assert_eq!(post.payout_each, None);
        assert_eq!(post.miner_subsidy, block_reward(LOG_SLOTS_GENESIS));
    }
}
