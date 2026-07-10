// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Pure planner for producing one active-owner UTXO of an exact target value.
//!
//! The planner never reads wallet state and never mutates reservations.  Its
//! caller must pass only confirmed, unreserved coins belonging to the active
//! owner.  Every planned operation is an ordinary fixed-shape `Tx8x2`:
//! intermediate transactions reduce eight inputs to one active-owner output,
//! and the final transaction creates the exact target plus optional active
//! change.
//!
//! Only the first confirmation wave is executable immediately.  Output slots
//! for later waves do not exist until their parents confirm, so later proving
//! and submission deliberately remain a coordinator concern.

use std::collections::BTreeSet;

use noid_chain::consensus::{fee_breakdown, params::BLOCK_MAX_USER_TXS};
use noid_tx::{TX_INPUTS, TX_OUTPUTS};

const _: () = assert!(TX_INPUTS == 8, "target consolidation assumes Tx8x2");
const _: () = assert!(TX_OUTPUTS == 2, "target consolidation assumes Tx8x2");

/// One confirmed and currently spendable active-owner coin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfirmedCoin {
    pub slot_index: u32,
    pub value_micronoid: u64,
}

/// Fee inputs captured from the same verified chain snapshot as `coins`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TargetConsolidationFeeContext {
    /// If present, this exact fee is paid by every ordinary transaction in the
    /// plan.  Otherwise each transaction pays its current relay minimum.
    pub explicit_fee_per_tx_micronoid: Option<u64>,
    pub active_slot_count: u64,
    pub log_slots: u32,
    pub relay_floor_micronoid: u64,
    /// Maximum number of independent transactions in any projected
    /// confirmation wave. The coordinator may execute one wave's transactions
    /// in any order; excess independent groups carry into another wave.
    pub max_transactions_per_wave: usize,
}

/// An ordinary transaction that can be built in the first confirmation wave.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirstWaveTransaction {
    /// Exact confirmed inputs, in deterministic body order.
    pub inputs: Vec<ConfirmedCoin>,
    /// Output values in body order.  The final transaction puts the exact
    /// target first and optional active change second; reduction transactions
    /// have one active-owner output.
    pub output_amounts_micronoid: Vec<u64>,
    pub fee_micronoid: u64,
    /// True only when this first-wave transaction creates the requested UTXO.
    pub creates_target: bool,
}

/// A deterministic multi-wave plan.  Only `first_wave` has concrete inputs;
/// projected descendants are summarized because their slot indices are not
/// known before earlier waves confirm.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetConsolidationPlan {
    pub target_amount_micronoid: u64,
    /// Minimal capable largest-first prefix (ties use ascending slot index).
    pub selected_sources: Vec<ConfirmedCoin>,
    pub first_wave: Vec<FirstWaveTransaction>,
    pub projected_total_transactions: usize,
    pub projected_confirmation_waves: usize,
    pub projected_total_fee_micronoid: u64,
    pub final_change_micronoid: u64,
}

/// Planning either discovers that no transaction is needed or returns the
/// first executable wave and a complete cost/topology projection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetConsolidationOutcome {
    AlreadyPresent { coin: ConfirmedCoin },
    Planned(TargetConsolidationPlan),
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TargetConsolidationError {
    #[error("target consolidation amount must be non-zero")]
    ZeroTarget,

    #[error("duplicate confirmed input slot {slot_index}")]
    DuplicateInputSlot { slot_index: u32 },

    #[error(
        "insufficient confirmed active-owner funds to create an exact {target_amount_micronoid} μNOID UTXO after projected fees (available {available_micronoid} μNOID)"
    )]
    InsufficientFunds {
        target_amount_micronoid: u64,
        available_micronoid: u64,
    },

    #[error(
        "explicit per-transaction fee is too low for {input_count} input(s) and {output_count} output(s): required {required_micronoid} μNOID, got {provided_micronoid} μNOID"
    )]
    FeeTooLow {
        provided_micronoid: u64,
        required_micronoid: u64,
        input_count: usize,
        output_count: usize,
    },

    #[error("target-consolidation arithmetic overflow")]
    ArithmeticOverflow,

    #[error("first-wave transaction limit must be in 1..={consensus_max}, got {provided}")]
    InvalidFirstWaveLimit {
        provided: usize,
        consensus_max: usize,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum WorkId {
    Confirmed(u32),
    Projected(u64),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct WorkCoin {
    id: WorkId,
    value_micronoid: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Topology {
    intermediate_transactions: usize,
    intermediate_waves: usize,
    final_input_count: usize,
    first_wave_transactions: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FinalShape {
    fee_micronoid: u64,
    change_micronoid: u64,
    output_count: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CandidateProjection {
    topology: Topology,
    intermediate_fee_micronoid: u64,
    final_shape: FinalShape,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FeeShortfall {
    provided_micronoid: u64,
    required_micronoid: u64,
    input_count: usize,
    output_count: usize,
}

enum CandidateAssessment {
    Insufficient,
    FeeTooLow(FeeShortfall),
    Capable(CandidateProjection),
}

/// Plan creation of one exact-value active-owner UTXO.
///
/// Coin selection is deterministic and independent of input iteration order:
/// values sort largest-first and equal values sort by ascending slot.  The
/// first capable prefix wins.  For each reduction wave, its smallest
/// `len % 8` coins carry untouched; all larger coins are distributed
/// round-robin over disjoint eight-input groups to avoid pathological lopsided
/// groups.
pub fn plan_target_consolidation(
    coins: &[ConfirmedCoin],
    target_amount_micronoid: u64,
    fee_context: TargetConsolidationFeeContext,
) -> Result<TargetConsolidationOutcome, TargetConsolidationError> {
    if target_amount_micronoid == 0 {
        return Err(TargetConsolidationError::ZeroTarget);
    }
    if fee_context.max_transactions_per_wave == 0
        || fee_context.max_transactions_per_wave > BLOCK_MAX_USER_TXS
    {
        return Err(TargetConsolidationError::InvalidFirstWaveLimit {
            provided: fee_context.max_transactions_per_wave,
            consensus_max: BLOCK_MAX_USER_TXS,
        });
    }

    let mut seen_slots = BTreeSet::new();
    let mut available_micronoid = 0u64;
    for coin in coins {
        if !seen_slots.insert(coin.slot_index) {
            return Err(TargetConsolidationError::DuplicateInputSlot {
                slot_index: coin.slot_index,
            });
        }
        available_micronoid = available_micronoid
            .checked_add(coin.value_micronoid)
            .ok_or(TargetConsolidationError::ArithmeticOverflow)?;
    }

    if let Some(coin) = coins
        .iter()
        .filter(|coin| coin.value_micronoid == target_amount_micronoid)
        .min_by_key(|coin| coin.slot_index)
    {
        return Ok(TargetConsolidationOutcome::AlreadyPresent { coin: *coin });
    }

    if available_micronoid < target_amount_micronoid {
        return Err(TargetConsolidationError::InsufficientFunds {
            target_amount_micronoid,
            available_micronoid,
        });
    }

    let mut sorted = coins.to_vec();
    sorted.sort_by(|left, right| {
        right
            .value_micronoid
            .cmp(&left.value_micronoid)
            .then_with(|| left.slot_index.cmp(&right.slot_index))
    });

    let mut prefix_total = 0u64;
    let mut best_fee_shortfall: Option<FeeShortfall> = None;
    for prefix_len in 1..=sorted.len() {
        prefix_total = prefix_total
            .checked_add(sorted[prefix_len - 1].value_micronoid)
            .ok_or(TargetConsolidationError::ArithmeticOverflow)?;
        let sources = &sorted[..prefix_len];
        match assess_candidate(
            prefix_len,
            prefix_total,
            target_amount_micronoid,
            fee_context,
        )? {
            CandidateAssessment::Insufficient => continue,
            CandidateAssessment::FeeTooLow(shortfall) => {
                remember_easiest_fee_shortfall(&mut best_fee_shortfall, shortfall);
            }
            CandidateAssessment::Capable(projection) => {
                if let Some(plan) = simulate_candidate(
                    sources,
                    prefix_total,
                    target_amount_micronoid,
                    projection,
                    fee_context.max_transactions_per_wave,
                )? {
                    return Ok(TargetConsolidationOutcome::Planned(plan));
                }
            }
        }
    }

    if let Some(shortfall) = best_fee_shortfall {
        return Err(TargetConsolidationError::FeeTooLow {
            provided_micronoid: shortfall.provided_micronoid,
            required_micronoid: shortfall.required_micronoid,
            input_count: shortfall.input_count,
            output_count: shortfall.output_count,
        });
    }

    Err(TargetConsolidationError::InsufficientFunds {
        target_amount_micronoid,
        available_micronoid,
    })
}

fn topology_for(
    mut input_count: usize,
    max_wave_transactions: usize,
) -> Result<Topology, TargetConsolidationError> {
    let first_wave_transactions = if input_count > TX_INPUTS {
        (input_count / TX_INPUTS).min(max_wave_transactions)
    } else {
        1
    };
    let mut intermediate_transactions = 0usize;
    let mut intermediate_waves = 0usize;
    while input_count > TX_INPUTS {
        let groups = (input_count / TX_INPUTS).min(max_wave_transactions);
        let carry = input_count
            .checked_sub(
                groups
                    .checked_mul(TX_INPUTS)
                    .ok_or(TargetConsolidationError::ArithmeticOverflow)?,
            )
            .ok_or(TargetConsolidationError::ArithmeticOverflow)?;
        intermediate_transactions = intermediate_transactions
            .checked_add(groups)
            .ok_or(TargetConsolidationError::ArithmeticOverflow)?;
        intermediate_waves = intermediate_waves
            .checked_add(1)
            .ok_or(TargetConsolidationError::ArithmeticOverflow)?;
        input_count = groups
            .checked_add(carry)
            .ok_or(TargetConsolidationError::ArithmeticOverflow)?;
    }
    Ok(Topology {
        intermediate_transactions,
        intermediate_waves,
        final_input_count: input_count,
        first_wave_transactions,
    })
}

fn relay_minimum(
    input_count: usize,
    output_count: usize,
    active_slot_count: u64,
    fee_context: TargetConsolidationFeeContext,
) -> u64 {
    fee_breakdown(
        input_count as u64,
        output_count as u64,
        active_slot_count,
        fee_context.log_slots,
    )
    .required_total
    .max(fee_context.relay_floor_micronoid)
}

fn assess_candidate(
    input_count: usize,
    prefix_total: u64,
    target_amount_micronoid: u64,
    fee_context: TargetConsolidationFeeContext,
) -> Result<CandidateAssessment, TargetConsolidationError> {
    let topology = topology_for(input_count, fee_context.max_transactions_per_wave)?;
    let intermediate_required =
        relay_minimum(TX_INPUTS, 1, fee_context.active_slot_count, fee_context);
    let intermediate_fee_micronoid = fee_context
        .explicit_fee_per_tx_micronoid
        .unwrap_or(intermediate_required);
    let intermediate_fee_total = intermediate_fee_micronoid
        .checked_mul(
            u64::try_from(topology.intermediate_transactions)
                .map_err(|_| TargetConsolidationError::ArithmeticOverflow)?,
        )
        .ok_or(TargetConsolidationError::ArithmeticOverflow)?;
    let Some(final_pool_total) = prefix_total.checked_sub(intermediate_fee_total) else {
        return Ok(CandidateAssessment::Insufficient);
    };

    let removed_slots = topology
        .intermediate_transactions
        .checked_mul(TX_INPUTS - 1)
        .ok_or(TargetConsolidationError::ArithmeticOverflow)?;
    let final_active_slot_count = fee_context
        .active_slot_count
        .checked_sub(
            u64::try_from(removed_slots)
                .map_err(|_| TargetConsolidationError::ArithmeticOverflow)?,
        )
        .ok_or(TargetConsolidationError::ArithmeticOverflow)?;

    let Some((final_shape, final_fee_shortfall)) = assess_final_shape(
        topology.final_input_count,
        final_pool_total,
        target_amount_micronoid,
        final_active_slot_count,
        fee_context,
    )?
    else {
        return Ok(CandidateAssessment::Insufficient);
    };

    let intermediate_fee_shortfall =
        fee_context
            .explicit_fee_per_tx_micronoid
            .and_then(|provided| {
                (topology.intermediate_transactions > 0 && provided < intermediate_required)
                    .then_some(FeeShortfall {
                        provided_micronoid: provided,
                        required_micronoid: intermediate_required,
                        input_count: TX_INPUTS,
                        output_count: 1,
                    })
            });
    if let Some(shortfall) = harder_fee_shortfall(intermediate_fee_shortfall, final_fee_shortfall) {
        return Ok(CandidateAssessment::FeeTooLow(shortfall));
    }

    Ok(CandidateAssessment::Capable(CandidateProjection {
        topology,
        intermediate_fee_micronoid,
        final_shape,
    }))
}

fn assess_final_shape(
    input_count: usize,
    final_pool_total: u64,
    target_amount_micronoid: u64,
    active_slot_count: u64,
    fee_context: TargetConsolidationFeeContext,
) -> Result<Option<(FinalShape, Option<FeeShortfall>)>, TargetConsolidationError> {
    if let Some(provided) = fee_context.explicit_fee_per_tx_micronoid {
        let needed = target_amount_micronoid
            .checked_add(provided)
            .ok_or(TargetConsolidationError::ArithmeticOverflow)?;
        if final_pool_total < needed {
            return Ok(None);
        }
        let change_micronoid = final_pool_total - needed;
        let output_count = 1 + usize::from(change_micronoid > 0);
        let required = relay_minimum(input_count, output_count, active_slot_count, fee_context);
        let shortfall = (provided < required).then_some(FeeShortfall {
            provided_micronoid: provided,
            required_micronoid: required,
            input_count,
            output_count,
        });
        return Ok(Some((
            FinalShape {
                fee_micronoid: provided,
                change_micronoid,
                output_count,
            },
            shortfall,
        )));
    }

    let two_output_fee = relay_minimum(input_count, 2, active_slot_count, fee_context);
    let two_output_need = target_amount_micronoid
        .checked_add(two_output_fee)
        .ok_or(TargetConsolidationError::ArithmeticOverflow)?;
    if final_pool_total > two_output_need {
        return Ok(Some((
            FinalShape {
                fee_micronoid: two_output_fee,
                change_micronoid: final_pool_total - two_output_need,
                output_count: 2,
            },
            None,
        )));
    }

    let one_output_fee = relay_minimum(input_count, 1, active_slot_count, fee_context);
    if final_pool_total >= target_amount_micronoid {
        let surplus = final_pool_total - target_amount_micronoid;
        if surplus >= one_output_fee {
            // There is no positive change worth a second output at its relay
            // minimum.  Paying the small surplus as the fee keeps the target
            // exact and avoids creating dust.
            return Ok(Some((
                FinalShape {
                    fee_micronoid: surplus,
                    change_micronoid: 0,
                    output_count: 1,
                },
                None,
            )));
        }
    }
    Ok(None)
}

fn simulate_candidate(
    sources: &[ConfirmedCoin],
    selected_total_micronoid: u64,
    target_amount_micronoid: u64,
    projection: CandidateProjection,
    max_wave_transactions: usize,
) -> Result<Option<TargetConsolidationPlan>, TargetConsolidationError> {
    let mut work: Vec<WorkCoin> = sources
        .iter()
        .map(|coin| WorkCoin {
            id: WorkId::Confirmed(coin.slot_index),
            value_micronoid: coin.value_micronoid,
        })
        .collect();
    let mut next_projected_id = 0u64;
    let mut first_wave = Vec::new();
    let mut projected_total_fee_micronoid = 0u64;
    let mut projected_total_transactions = 0usize;
    let mut projected_confirmation_waves = 0usize;

    while work.len() > TX_INPUTS {
        sort_work_coins(&mut work);
        let group_count = (work.len() / TX_INPUTS).min(max_wave_transactions);
        let grouped_len = group_count
            .checked_mul(TX_INPUTS)
            .ok_or(TargetConsolidationError::ArithmeticOverflow)?;
        let carry = work.split_off(grouped_len);
        let grouped = std::mem::take(&mut work);
        let mut groups = vec![Vec::with_capacity(TX_INPUTS); group_count];
        for (index, coin) in grouped.into_iter().enumerate() {
            groups[index % group_count].push(coin);
        }

        let is_first_wave = projected_confirmation_waves == 0;
        let mut next_work = carry;
        for group in groups {
            debug_assert_eq!(group.len(), TX_INPUTS);
            let group_total = group
                .iter()
                .try_fold(0u64, |sum, coin| sum.checked_add(coin.value_micronoid));
            let Some(group_total) = group_total else {
                return Err(TargetConsolidationError::ArithmeticOverflow);
            };
            let Some(output_amount) =
                group_total.checked_sub(projection.intermediate_fee_micronoid)
            else {
                return Ok(None);
            };
            if output_amount == 0 {
                return Ok(None);
            }

            if is_first_wave {
                let inputs = group
                    .iter()
                    .map(|coin| match coin.id {
                        WorkId::Confirmed(slot_index) => ConfirmedCoin {
                            slot_index,
                            value_micronoid: coin.value_micronoid,
                        },
                        WorkId::Projected(_) => {
                            unreachable!("the first wave cannot consume projected outputs")
                        }
                    })
                    .collect();
                first_wave.push(FirstWaveTransaction {
                    inputs,
                    output_amounts_micronoid: vec![output_amount],
                    fee_micronoid: projection.intermediate_fee_micronoid,
                    creates_target: false,
                });
            }

            next_work.push(WorkCoin {
                id: WorkId::Projected(next_projected_id),
                value_micronoid: output_amount,
            });
            next_projected_id = next_projected_id
                .checked_add(1)
                .ok_or(TargetConsolidationError::ArithmeticOverflow)?;
        }

        projected_total_fee_micronoid = projected_total_fee_micronoid
            .checked_add(
                projection
                    .intermediate_fee_micronoid
                    .checked_mul(
                        u64::try_from(group_count)
                            .map_err(|_| TargetConsolidationError::ArithmeticOverflow)?,
                    )
                    .ok_or(TargetConsolidationError::ArithmeticOverflow)?,
            )
            .ok_or(TargetConsolidationError::ArithmeticOverflow)?;
        projected_total_transactions = projected_total_transactions
            .checked_add(group_count)
            .ok_or(TargetConsolidationError::ArithmeticOverflow)?;
        projected_confirmation_waves = projected_confirmation_waves
            .checked_add(1)
            .ok_or(TargetConsolidationError::ArithmeticOverflow)?;
        work = next_work;
    }

    debug_assert_eq!(work.len(), projection.topology.final_input_count);
    debug_assert_eq!(
        projected_total_transactions,
        projection.topology.intermediate_transactions
    );
    debug_assert_eq!(
        projected_confirmation_waves,
        projection.topology.intermediate_waves
    );
    sort_work_coins(&mut work);
    if projected_confirmation_waves == 0 {
        let inputs = work
            .iter()
            .map(|coin| match coin.id {
                WorkId::Confirmed(slot_index) => ConfirmedCoin {
                    slot_index,
                    value_micronoid: coin.value_micronoid,
                },
                WorkId::Projected(_) => {
                    unreachable!("a no-reduction final cannot consume projected outputs")
                }
            })
            .collect();
        let mut output_amounts_micronoid = vec![target_amount_micronoid];
        if projection.final_shape.change_micronoid > 0 {
            output_amounts_micronoid.push(projection.final_shape.change_micronoid);
        }
        debug_assert_eq!(
            output_amounts_micronoid.len(),
            projection.final_shape.output_count
        );
        first_wave.push(FirstWaveTransaction {
            inputs,
            output_amounts_micronoid,
            fee_micronoid: projection.final_shape.fee_micronoid,
            creates_target: true,
        });
    }
    debug_assert_eq!(
        first_wave.len(),
        projection.topology.first_wave_transactions
    );

    projected_total_fee_micronoid = projected_total_fee_micronoid
        .checked_add(projection.final_shape.fee_micronoid)
        .ok_or(TargetConsolidationError::ArithmeticOverflow)?;
    projected_total_transactions = projected_total_transactions
        .checked_add(1)
        .ok_or(TargetConsolidationError::ArithmeticOverflow)?;
    projected_confirmation_waves = projected_confirmation_waves
        .checked_add(1)
        .ok_or(TargetConsolidationError::ArithmeticOverflow)?;

    let conserved = target_amount_micronoid
        .checked_add(projection.final_shape.change_micronoid)
        .and_then(|sum| sum.checked_add(projected_total_fee_micronoid))
        .ok_or(TargetConsolidationError::ArithmeticOverflow)?;
    if conserved != selected_total_micronoid {
        return Err(TargetConsolidationError::ArithmeticOverflow);
    }

    Ok(Some(TargetConsolidationPlan {
        target_amount_micronoid,
        selected_sources: sources.to_vec(),
        first_wave,
        projected_total_transactions,
        projected_confirmation_waves,
        projected_total_fee_micronoid,
        final_change_micronoid: projection.final_shape.change_micronoid,
    }))
}

fn sort_work_coins(coins: &mut [WorkCoin]) {
    coins.sort_by(|left, right| {
        right
            .value_micronoid
            .cmp(&left.value_micronoid)
            .then_with(|| left.id.cmp(&right.id))
    });
}

fn harder_fee_shortfall(
    left: Option<FeeShortfall>,
    right: Option<FeeShortfall>,
) -> Option<FeeShortfall> {
    match (left, right) {
        (None, None) => None,
        (Some(value), None) | (None, Some(value)) => Some(value),
        (Some(left), Some(right)) => Some(if right.required_micronoid > left.required_micronoid {
            right
        } else {
            left
        }),
    }
}

fn remember_easiest_fee_shortfall(current: &mut Option<FeeShortfall>, candidate: FeeShortfall) {
    if current
        .as_ref()
        .is_none_or(|value| candidate.required_micronoid < value.required_micronoid)
    {
        *current = Some(candidate);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const COIN_VALUE: u64 = 100_000;

    fn auto_fee(active_slot_count: u64) -> TargetConsolidationFeeContext {
        TargetConsolidationFeeContext {
            explicit_fee_per_tx_micronoid: None,
            active_slot_count,
            log_slots: 24,
            relay_floor_micronoid: 0,
            max_transactions_per_wave: BLOCK_MAX_USER_TXS,
        }
    }

    fn equal_coins(count: usize) -> Vec<ConfirmedCoin> {
        (0..count)
            .map(|slot_index| ConfirmedCoin {
                slot_index: slot_index as u32,
                value_micronoid: COIN_VALUE,
            })
            .collect()
    }

    fn planned(
        coins: &[ConfirmedCoin],
        target: u64,
        fee_context: TargetConsolidationFeeContext,
    ) -> TargetConsolidationPlan {
        match plan_target_consolidation(coins, target, fee_context).unwrap() {
            TargetConsolidationOutcome::Planned(plan) => plan,
            TargetConsolidationOutcome::AlreadyPresent { .. } => {
                panic!("test target was unexpectedly already present")
            }
        }
    }

    #[test]
    fn exact_target_coin_short_circuits_without_a_transaction() {
        let coins = vec![
            ConfirmedCoin {
                slot_index: 9,
                value_micronoid: 50_000,
            },
            ConfirmedCoin {
                slot_index: 3,
                value_micronoid: 50_000,
            },
        ];
        assert_eq!(
            plan_target_consolidation(&coins, 50_000, auto_fee(2)).unwrap(),
            TargetConsolidationOutcome::AlreadyPresent { coin: coins[1] }
        );
    }

    #[test]
    fn selection_uses_the_minimal_largest_first_prefix() {
        let coins = vec![
            ConfirmedCoin {
                slot_index: 30,
                value_micronoid: 60_000,
            },
            ConfirmedCoin {
                slot_index: 20,
                value_micronoid: 80_000,
            },
            ConfirmedCoin {
                slot_index: 10,
                value_micronoid: 70_000,
            },
        ];
        let plan = planned(&coins, 140_000, auto_fee(3));
        assert_eq!(
            plan.selected_sources,
            vec![
                ConfirmedCoin {
                    slot_index: 20,
                    value_micronoid: 80_000,
                },
                ConfirmedCoin {
                    slot_index: 10,
                    value_micronoid: 70_000,
                },
            ]
        );
    }

    #[test]
    fn topology_for_8_9_10_15_16_and_100_sources_is_canonical() {
        let cases = [
            (8, 1, 1, 1),
            (9, 2, 2, 1),
            (10, 2, 2, 1),
            (15, 2, 2, 1),
            (16, 3, 2, 2),
            (100, 15, 3, 12),
        ];
        for (source_count, transaction_count, wave_count, first_wave_count) in cases {
            let coins = equal_coins(source_count);
            // The preceding prefix has exactly the target but cannot pay a
            // fee, forcing selection of precisely `source_count` coins.
            let target = (source_count as u64 - 1) * COIN_VALUE;
            let plan = planned(&coins, target, auto_fee(source_count as u64));
            assert_eq!(plan.selected_sources.len(), source_count);
            assert_eq!(plan.projected_total_transactions, transaction_count);
            assert_eq!(plan.projected_confirmation_waves, wave_count);
            assert_eq!(plan.first_wave.len(), first_wave_count);
        }
    }

    #[test]
    fn first_wave_groups_are_deterministic_disjoint_and_carry_the_smallest() {
        let mut coins: Vec<ConfirmedCoin> = (0..18)
            .map(|slot_index| ConfirmedCoin {
                slot_index,
                value_micronoid: (18 - slot_index as u64) * COIN_VALUE,
            })
            .collect();
        let total: u64 = coins.iter().map(|coin| coin.value_micronoid).sum();
        let target = total - 20_000;
        let plan = planned(&coins, target, auto_fee(total));
        assert_eq!(plan.selected_sources.len(), 18);
        assert_eq!(plan.first_wave.len(), 2);

        let first_group_slots: Vec<u32> = plan.first_wave[0]
            .inputs
            .iter()
            .map(|coin| coin.slot_index)
            .collect();
        let second_group_slots: Vec<u32> = plan.first_wave[1]
            .inputs
            .iter()
            .map(|coin| coin.slot_index)
            .collect();
        assert_eq!(first_group_slots, vec![0, 2, 4, 6, 8, 10, 12, 14]);
        assert_eq!(second_group_slots, vec![1, 3, 5, 7, 9, 11, 13, 15]);
        assert!(!first_group_slots
            .iter()
            .any(|slot| second_group_slots.contains(slot)));
        assert!(!first_group_slots.contains(&16));
        assert!(!second_group_slots.contains(&17));

        coins.reverse();
        let reversed = planned(&coins, target, auto_fee(total));
        assert_eq!(reversed, plan);
    }

    #[test]
    fn every_first_wave_tx_and_the_whole_plan_conserve_value() {
        let coins = equal_coins(100);
        let target = 99 * COIN_VALUE;
        let plan = planned(&coins, target, auto_fee(100));

        for tx in &plan.first_wave {
            let inputs: u64 = tx.inputs.iter().map(|coin| coin.value_micronoid).sum();
            let outputs: u64 = tx.output_amounts_micronoid.iter().sum();
            assert_eq!(inputs, outputs + tx.fee_micronoid);
            assert_eq!(tx.inputs.len(), TX_INPUTS);
            assert_eq!(tx.output_amounts_micronoid.len(), 1);
        }
        let selected: u64 = plan
            .selected_sources
            .iter()
            .map(|coin| coin.value_micronoid)
            .sum();
        assert_eq!(
            selected,
            target + plan.final_change_micronoid + plan.projected_total_fee_micronoid
        );
    }

    #[test]
    fn automatic_final_tx_creates_exact_target_and_active_change() {
        let coins = vec![ConfirmedCoin {
            slot_index: 7,
            value_micronoid: 100_000,
        }];
        let plan = planned(&coins, 50_000, auto_fee(1));
        let final_tx = &plan.first_wave[0];
        let expected_fee = fee_breakdown(1, 2, 1, 24).required_total;
        assert!(final_tx.creates_target);
        assert_eq!(final_tx.fee_micronoid, expected_fee);
        assert_eq!(
            final_tx.output_amounts_micronoid,
            vec![50_000, 100_000 - 50_000 - expected_fee]
        );
    }

    #[test]
    fn automatic_final_tx_may_burn_small_surplus_instead_of_making_dust() {
        let coins = vec![ConfirmedCoin {
            slot_index: 7,
            value_micronoid: 100_000,
        }];
        let plan = planned(&coins, 94_000, auto_fee(1));
        let final_tx = &plan.first_wave[0];
        assert_eq!(final_tx.output_amounts_micronoid, vec![94_000]);
        assert_eq!(final_tx.fee_micronoid, 6_000);
        assert_eq!(plan.final_change_micronoid, 0);
    }

    #[test]
    fn relay_floor_and_explicit_fee_are_applied_per_ordinary_transaction() {
        let coins = equal_coins(9);
        let target = 8 * COIN_VALUE;
        let relay_plan = planned(
            &coins,
            target,
            TargetConsolidationFeeContext {
                relay_floor_micronoid: 10_000,
                ..auto_fee(9)
            },
        );
        assert_eq!(relay_plan.projected_total_fee_micronoid, 20_000);
        assert_eq!(relay_plan.first_wave[0].fee_micronoid, 10_000);

        let explicit_plan = planned(
            &coins,
            target,
            TargetConsolidationFeeContext {
                explicit_fee_per_tx_micronoid: Some(11_000),
                ..auto_fee(9)
            },
        );
        assert_eq!(explicit_plan.projected_total_fee_micronoid, 22_000);
        assert_eq!(explicit_plan.first_wave[0].fee_micronoid, 11_000);
    }

    #[test]
    fn low_explicit_fee_is_a_typed_error() {
        let coins = equal_coins(9);
        let error = plan_target_consolidation(
            &coins,
            8 * COIN_VALUE,
            TargetConsolidationFeeContext {
                explicit_fee_per_tx_micronoid: Some(100),
                ..auto_fee(9)
            },
        )
        .unwrap_err();
        assert!(matches!(
            error,
            TargetConsolidationError::FeeTooLow {
                provided_micronoid: 100,
                ..
            }
        ));
    }

    #[test]
    fn insufficient_and_overflow_are_typed_errors() {
        let insufficient =
            plan_target_consolidation(&equal_coins(2), 2 * COIN_VALUE, auto_fee(2)).unwrap_err();
        assert!(matches!(
            insufficient,
            TargetConsolidationError::InsufficientFunds { .. }
        ));

        let overflowing = [
            ConfirmedCoin {
                slot_index: 1,
                value_micronoid: u64::MAX,
            },
            ConfirmedCoin {
                slot_index: 2,
                value_micronoid: 1,
            },
        ];
        assert_eq!(
            plan_target_consolidation(&overflowing, u64::MAX - 1, auto_fee(2)).unwrap_err(),
            TargetConsolidationError::ArithmeticOverflow
        );
    }

    #[test]
    fn caller_filtered_pending_coins_never_enter_the_plan() {
        let pending_slot = 99;
        let mut wallet_view = equal_coins(9);
        wallet_view.push(ConfirmedCoin {
            slot_index: pending_slot,
            value_micronoid: 10 * COIN_VALUE,
        });
        let confirmed_and_unreserved: Vec<ConfirmedCoin> = wallet_view
            .into_iter()
            .filter(|coin| coin.slot_index != pending_slot)
            .collect();
        let plan = planned(
            &confirmed_and_unreserved,
            8 * COIN_VALUE,
            auto_fee(confirmed_and_unreserved.len() as u64),
        );
        assert!(plan
            .selected_sources
            .iter()
            .all(|coin| coin.slot_index != pending_slot));
    }

    #[test]
    fn duplicate_slots_and_zero_target_are_rejected() {
        let duplicate = [
            ConfirmedCoin {
                slot_index: 5,
                value_micronoid: 10,
            },
            ConfirmedCoin {
                slot_index: 5,
                value_micronoid: 20,
            },
        ];
        assert_eq!(
            plan_target_consolidation(&duplicate, 1, auto_fee(2)).unwrap_err(),
            TargetConsolidationError::DuplicateInputSlot { slot_index: 5 }
        );
        assert_eq!(
            plan_target_consolidation(&[], 0, auto_fee(0)).unwrap_err(),
            TargetConsolidationError::ZeroTarget
        );
    }

    #[test]
    fn first_wave_limit_is_consensus_bounded() {
        let invalid = TargetConsolidationFeeContext {
            max_transactions_per_wave: BLOCK_MAX_USER_TXS + 1,
            ..auto_fee(0)
        };
        assert_eq!(
            plan_target_consolidation(&equal_coins(1), 1, invalid).unwrap_err(),
            TargetConsolidationError::InvalidFirstWaveLimit {
                provided: BLOCK_MAX_USER_TXS + 1,
                consensus_max: BLOCK_MAX_USER_TXS,
            }
        );
    }

    #[test]
    fn oversized_source_set_is_batched_without_truncating_projection() {
        const SOURCE_COUNT: usize = 2_048;
        const LARGE_COIN: u64 = 10_000_000;
        let coins: Vec<ConfirmedCoin> = (0..SOURCE_COUNT)
            .map(|slot_index| ConfirmedCoin {
                slot_index: slot_index as u32,
                value_micronoid: LARGE_COIN,
            })
            .collect();
        let target = (SOURCE_COUNT as u64 - 1) * LARGE_COIN;
        let plan = planned(&coins, target, auto_fee(SOURCE_COUNT as u64));

        assert_eq!(plan.selected_sources.len(), SOURCE_COUNT);
        assert_eq!(plan.first_wave.len(), BLOCK_MAX_USER_TXS);
        assert_eq!(plan.projected_total_transactions, 293);
        assert_eq!(plan.projected_confirmation_waves, 5);
        assert!(plan.projected_total_transactions > plan.first_wave.len());

        let first_wave_slots: BTreeSet<u32> = plan
            .first_wave
            .iter()
            .flat_map(|transaction| transaction.inputs.iter())
            .map(|coin| coin.slot_index)
            .collect();
        assert_eq!(first_wave_slots.len(), BLOCK_MAX_USER_TXS * TX_INPUTS);
    }
}
