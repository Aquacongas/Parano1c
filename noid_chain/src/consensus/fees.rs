// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Deterministic transaction fee model.
//!
//! Fees are charged for:
//! - a base anti-DoS component per transaction;
//! - a small input component for anti-DoS/prover work;
//! - an output component for created UTXOs;
//! - a state-growth component for `max(0, outputs - inputs)` net-new UTXO slots.
//!
//! The state-growth component scales with current occupancy and is burned by
//! consensus: miners may claim only `fee - burned_state_growth_fee` in coinbase.

use noid_tx::TxBody;

#[cfg(test)]
use crate::consensus::params::LOG_SLOTS_GENESIS;
use crate::consensus::params::{
    FEE_PER_INPUT, FEE_PER_OUTPUT, MIN_FEE_BASE, STATE_GROWTH_FEE_BASE,
};

/// Occupancy pressure thresholds in basis points.
pub const PRESSURE_LOW_BPS: u64 = 5_000; // 50%
pub const PRESSURE_HIGH_BPS: u64 = 7_500; // 75%
pub const PRESSURE_EXTREME_BPS: u64 = 9_000; // 90%

/// Detailed deterministic fee calculation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeeBreakdown {
    /// Fixed per-tx anti-DoS component.
    pub base: u64,
    /// Fee for live inputs.
    pub input: u64,
    /// Fee for live outputs.
    pub output: u64,
    /// Fee for live inputs + live outputs, kept as a convenient aggregate.
    pub io: u64,
    /// Fee for net-new live UTXO slots. Burned by consensus.
    pub state_growth: u64,
    /// Required minimum total fee.
    pub required_total: u64,
    /// Portion of `required_total` that is burned.
    pub burned: u64,
}

impl FeeBreakdown {
    /// Portion of a fee at exactly `required_total` that a miner may claim.
    #[inline]
    pub fn claimable_at_minimum(self) -> u64 {
        self.required_total.saturating_sub(self.burned)
    }
}

/// Count live inputs and outputs in a tx body.
#[inline]
pub fn tx_shape(body: &TxBody) -> (u64, u64) {
    let n_inputs = body.inputs.iter().filter(|i| i.valid).count() as u64;
    let n_outputs = body.outputs.iter().filter(|o| o.valid).count() as u64;
    (n_inputs, n_outputs)
}

/// Current occupancy in basis points using integer arithmetic.
#[inline]
pub fn occupancy_bps(active_slot_count: u64, log_slots: u32) -> u64 {
    let capacity = 1u128.checked_shl(log_slots).unwrap_or(u128::MAX).max(1);
    ((active_slot_count as u128).saturating_mul(10_000) / capacity) as u64
}

/// Deterministic pressure multiplier for the state-growth component.
///
/// This is intentionally stepwise instead of floating-point. The multiplier only
/// affects net-new state growth; consolidation remains free of this pressure fee.
#[inline]
pub fn pressure_multiplier(active_slot_count: u64, log_slots: u32) -> u64 {
    match occupancy_bps(active_slot_count, log_slots) {
        bps if bps >= PRESSURE_EXTREME_BPS => 8,
        bps if bps >= PRESSURE_HIGH_BPS => 4,
        bps if bps >= PRESSURE_LOW_BPS => 2,
        _ => 1,
    }
}

/// Fee per net-new slot under current occupancy pressure.
#[inline]
pub fn state_growth_fee_per_slot(active_slot_count: u64, log_slots: u32) -> u64 {
    STATE_GROWTH_FEE_BASE.saturating_mul(pressure_multiplier(active_slot_count, log_slots))
}

/// Compute the deterministic required fee for an arbitrary tx shape.
///
/// The formula is intentionally output-centric: inputs pay a small anti-DoS
/// component, outputs pay the larger ordinary I/O component, and only net-new
/// state growth is burned. There is no shape premium; a `Sweep25x2` transaction
/// pays for its actual live inputs/outputs and is naturally cheap when it
/// consolidates or otherwise reduces live slot count.
pub fn fee_breakdown(
    n_inputs: u64,
    n_outputs: u64,
    active_slot_count: u64,
    log_slots: u32,
) -> FeeBreakdown {
    let net_new_slots = n_outputs.saturating_sub(n_inputs);

    let base = MIN_FEE_BASE;
    let input = FEE_PER_INPUT.saturating_mul(n_inputs);
    let output = FEE_PER_OUTPUT.saturating_mul(n_outputs);
    let io = input.saturating_add(output);
    let state_growth =
        state_growth_fee_per_slot(active_slot_count, log_slots).saturating_mul(net_new_slots);
    let required_total = base.saturating_add(io).saturating_add(state_growth);

    FeeBreakdown {
        base,
        input,
        output,
        io,
        state_growth,
        required_total,
        burned: state_growth,
    }
}

/// Compute the deterministic required fee for a concrete transaction body.
#[inline]
pub fn fee_breakdown_for_tx_body(
    body: &TxBody,
    active_slot_count: u64,
    log_slots: u32,
) -> FeeBreakdown {
    let (n_inputs, n_outputs) = tx_shape(body);
    fee_breakdown(n_inputs, n_outputs, active_slot_count, log_slots)
}

/// Required minimum fee for a concrete transaction body.
#[inline]
pub fn required_fee_for_tx_body(body: &TxBody, active_slot_count: u64, log_slots: u32) -> u64 {
    fee_breakdown_for_tx_body(body, active_slot_count, log_slots).required_total
}

/// Burned fee for a concrete transaction body at the protocol-required level.
///
/// Additional tip above the required fee is claimable by miners; only the
/// deterministic state-growth component is burned.
#[inline]
pub fn burned_fee_for_tx_body(body: &TxBody, active_slot_count: u64, log_slots: u32) -> u64 {
    fee_breakdown_for_tx_body(body, active_slot_count, log_slots).burned
}

/// Fee amount claimable by miners for coinbase accounting.
#[inline]
pub fn claimable_fee_for_tx_body(body: &TxBody, active_slot_count: u64, log_slots: u32) -> u64 {
    if body.is_coinbase {
        return 0;
    }
    let actual = body.fee.min(u64::MAX as u128) as u64;
    let burned = burned_fee_for_tx_body(body, active_slot_count, log_slots);
    actual.saturating_sub(burned)
}

#[cfg(test)]
mod tests {
    use super::*;
    use noid_poseidon2b::primitives::{Address, SpendSecret};
    use noid_tx::{TxBody, TxInput, TxOutput};

    fn input(slot: u32) -> TxInput {
        TxInput {
            slot_index: slot,
            value: 100,
            owner: Address([1u8; 32]),
            spend_secret: SpendSecret([2u8; 32]),
            valid: true,
        }
    }

    fn output(slot: u32) -> TxOutput {
        TxOutput {
            slot_index: slot,
            value: 100,
            owner: Address([4u8; 32]),
            valid: true,
        }
    }

    fn body(n_inputs: u32, n_outputs: u32, fee: u128) -> TxBody {
        TxBody {
            shape: noid_tx::TxShape::Standard4x8,
            epoch_anchor: [1u8; 32],
            fee,
            inputs: (0..n_inputs).map(input).collect(),
            outputs: (0..n_outputs).map(|i| output(100 + i)).collect(),
            is_coinbase: false,
        }
    }

    #[test]
    fn low_pressure_standard_send_matches_old_baseline() {
        let b = fee_breakdown(1, 2, 0, LOG_SLOTS_GENESIS);
        assert_eq!(b.input, 100);
        assert_eq!(b.output, 1_400);
        assert_eq!(b.io, 1_500);
        assert_eq!(b.required_total, 9_000);
        assert_eq!(b.burned, 2_500);
        assert_eq!(b.claimable_at_minimum(), 6_500);
    }

    #[test]
    fn consolidation_avoids_state_growth_burn() {
        let b = fee_breakdown(4, 1, 0, LOG_SLOTS_GENESIS);
        assert_eq!(b.state_growth, 0);
        assert_eq!(b.burned, 0);
        assert_eq!(b.required_total, 6_100);
    }

    #[test]
    fn sweep_pays_actual_io_without_shape_premium() {
        let payment = fee_breakdown(25, 2, 0, LOG_SLOTS_GENESIS);
        let consolidation = fee_breakdown(25, 1, 0, LOG_SLOTS_GENESIS);
        assert_eq!(payment.state_growth, 0);
        assert_eq!(consolidation.state_growth, 0);
        assert_eq!(payment.required_total, 8_900);
        assert_eq!(consolidation.required_total, 8_200);
    }

    #[test]
    fn split_tx_pays_for_net_new_slots() {
        let split = fee_breakdown(1, 8, 0, LOG_SLOTS_GENESIS);
        let flat = fee_breakdown(1, 1, 0, LOG_SLOTS_GENESIS);
        assert!(split.required_total > flat.required_total);
        assert_eq!(split.burned, 7 * STATE_GROWTH_FEE_BASE);
    }

    #[test]
    fn pressure_multiplier_steps_are_deterministic() {
        assert_eq!(pressure_multiplier(0, LOG_SLOTS_GENESIS), 1);
        assert_eq!(pressure_multiplier(1u64 << 23, LOG_SLOTS_GENESIS), 2);
        assert_eq!(
            pressure_multiplier((1u64 << 24) * 3 / 4, LOG_SLOTS_GENESIS),
            4
        );
        assert_eq!(
            pressure_multiplier(((1u64 << 24) * 9).div_ceil(10), LOG_SLOTS_GENESIS),
            8
        );
    }

    #[test]
    fn claimable_fee_burns_only_required_growth_component() {
        let tx = body(1, 2, 12_000);
        assert_eq!(burned_fee_for_tx_body(&tx, 0, LOG_SLOTS_GENESIS), 2_500);
        assert_eq!(claimable_fee_for_tx_body(&tx, 0, LOG_SLOTS_GENESIS), 9_500);
    }
}
