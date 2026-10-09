// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Shared wallet submission primitives.
//!
//! The operation gate serializes active-owner reload, payment proving, normal
//! mempool admission, and account switches. The reservation guard keeps wallet
//! state cancellation-safe around async admission.

use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;

use noid_chain::consensus::allocator::{generate_zone_segment_hints, splitmix64};
use noid_chain::consensus::pow::block_id;
use noid_chain::storage::MdbxChainContext;
use tokio::sync::Mutex;

pub type WalletOperationGate = Arc<Mutex<()>>;

/// Cancellation-safe wallet reservation around async local mempool admission.
///
/// The reservation is installed only after wallet proving succeeds. If the
/// admission future fails, is cancelled, or this guard is otherwise dropped,
/// every wallet-side pending artifact is rolled back synchronously.
pub struct PendingAdmissionGuard {
    wallet: crate::SharedWallet,
    txid: [u8; 32],
    input_slots: Vec<u32>,
    output_slots: Vec<u32>,
    armed: bool,
}

impl PendingAdmissionGuard {
    pub fn reserve(
        wallet: crate::SharedWallet,
        txid: [u8; 32],
        input_slots: Vec<u32>,
        output_slots: Vec<u32>,
        amount_micronoid: u64,
        peer_address: [u8; 32],
    ) -> Result<Self, String> {
        {
            let mut guard = wallet
                .lock()
                .map_err(|_| "wallet state lock is poisoned".to_string())?;

            let state = guard
                .as_mut()
                .ok_or_else(|| "wallet not initialized".to_string())?;

            if input_slots
                .iter()
                .any(|slot| state.pending_input_slots.contains(slot))
            {
                return Err("wallet input is already reserved by a pending transaction".to_string());
            }

            if output_slots
                .iter()
                .any(|slot| state.pending_output_slots.contains(slot))
            {
                return Err(
                    "wallet output slot is already reserved by a pending transaction".to_string(),
                );
            }

            state.add_pending_inputs(&input_slots);
            state.add_pending_outputs(&output_slots);

            if let Err(error) = state.record_pending_send(txid, amount_micronoid, peer_address) {
                state.remove_pending_inputs(&input_slots);
                state.remove_pending_outputs(&output_slots);
                return Err(error);
            }
        }

        Ok(Self {
            wallet,
            txid,
            input_slots,
            output_slots,
            armed: true,
        })
    }

    pub fn commit(mut self) {
        self.armed = false;
    }

    fn rollback(&self) {
        let Ok(mut guard) = self.wallet.lock() else {
            tracing::error!("wallet state lock poisoned during pending submission rollback");
            return;
        };

        let Some(state) = guard.as_mut() else {
            return;
        };

        state.remove_pending_inputs(&self.input_slots);
        state.remove_pending_outputs(&self.output_slots);

        if let Err(error) = state.remove_pending_send(&self.txid) {
            tracing::error!(
                %error,
                "pending wallet history rollback failed"
            );
        }
    }
}

impl Drop for PendingAdmissionGuard {
    fn drop(&mut self) {
        if self.armed {
            self.rollback();
        }
    }
}

/// Select exact empty slots without treating an evicted live segment as a
/// virtual zero segment. Missing/corrupt durable segment data fails closed.
pub fn collect_empty_slot_hints(
    chain: &MdbxChainContext,
    reserved: &HashSet<u32>,
    seed: u64,
    count: usize,
) -> Result<Vec<u32>, String> {
    if count == 0 {
        return Ok(Vec::new());
    }
    let state = &chain.state.state;
    let segment_log = state.effective_log_segment_size();
    let segment_size = 1usize << segment_log;
    let segment_full = segment_size as u32;
    let local_mask = (segment_size - 1) as u32;
    let mut rng = seed;
    let mut hints = Vec::with_capacity(count);

    // First refill holes in durable live segments. This is the important
    // density invariant: restart eviction must not turn salted wallet hints
    // back into one random 3-MiB segment per send. Salt rotates equal-density
    // choices and the local scan, while compact live counts choose the segment.
    let mut partial_segments = (0..state.num_segments())
        .map(|segment| segment as u16)
        .filter(|segment| {
            let live = state.segment_live_count(*segment);
            live > 0 && live < segment_full
        })
        .collect::<Vec<_>>();
    if !partial_segments.is_empty() {
        let rotation = (splitmix64(&mut rng) as usize) % partial_segments.len();
        partial_segments.rotate_left(rotation);
        // Stable ordering fills the densest segment first; the prior rotation
        // supplies deterministic salt diversity between equal live counts.
        partial_segments.sort_by(|left, right| {
            state
                .segment_live_count(*right)
                .cmp(&state.segment_live_count(*left))
        });
    }

    for segment_id in partial_segments {
        let local_start = (splitmix64(&mut rng) as u32) & local_mask;
        let base = u32::from(segment_id) << segment_log;
        let candidates = (0..segment_size)
            .map(move |step| base | (local_start.wrapping_add(step as u32) & local_mask));
        hints = collect_empty_slot_hints_streaming(
            hints,
            reserved,
            count,
            state.num_slots(),
            segment_log,
            candidates,
            |candidate_segment| state.is_evicted(candidate_segment),
            |index| state.slot(index) == noid_chain::fri_state::SlotValue::EMPTY,
            |candidate_segment| load_durable_segment(chain, candidate_segment, segment_log),
        )?;
        if hints.len() == count {
            return Ok(hints);
        }
    }

    // No durable hole was sufficient. Open a virtual-zero segment in the
    // allocator's zone order, derived from the real monotone alloc_counter —
    // never from the wallet salt. Full zones are skipped in O(segment_count).
    for segment_id in generate_zone_segment_hints(
        chain.state.alloc_counter,
        state.log_slots() as u32,
        state.num_segments(),
    ) {
        if state.segment_live_count(segment_id) != 0 || state.is_evicted(segment_id) {
            continue;
        }
        let local_start = (splitmix64(&mut rng) as u32) & local_mask;
        let base = u32::from(segment_id) << segment_log;
        // Every candidate is empty, so `reserved + missing` probes guarantee
        // enough unreserved hints without constructing a 65,536-entry list.
        let missing = count.saturating_sub(hints.len());
        let probes = segment_size.min(reserved.len().saturating_add(missing));
        let candidates = (0..probes)
            .map(move |step| base | (local_start.wrapping_add(step as u32) & local_mask));
        hints = collect_empty_slot_hints_streaming(
            hints,
            reserved,
            count,
            state.num_slots(),
            segment_log,
            candidates,
            |_| false,
            |index| state.slot(index) == noid_chain::fri_state::SlotValue::EMPTY,
            |_| -> Result<noid_chain::segmented_state::SegmentColumns, String> {
                unreachable!("virtual-zero segment cannot require a durable load")
            },
        )?;
        if hints.len() == count {
            break;
        }
    }
    Ok(hints)
}

fn load_durable_segment(
    chain: &MdbxChainContext,
    segment_id: u16,
    expected_log: usize,
) -> Result<noid_chain::segmented_state::SegmentColumns, String> {
    let Some((stored_log, columns)) = chain
        .store
        .get_segment(segment_id)
        .map_err(|error| error.to_string())?
    else {
        return Err(format!(
            "evicted segment {segment_id} is missing from durable state"
        ));
    };
    if usize::from(stored_log) != expected_log {
        return Err(format!(
            "segment {segment_id} depth mismatch: stored {stored_log}, expected {expected_log}"
        ));
    }
    Ok(columns)
}

trait ExactSegmentSlots {
    fn slot_is_empty(&self, segment_id: u16, local_index: usize) -> Result<bool, String>;
}

impl ExactSegmentSlots for noid_chain::segmented_state::SegmentColumns {
    fn slot_is_empty(&self, segment_id: u16, local_index: usize) -> Result<bool, String> {
        if local_index >= self.values.len()
            || local_index >= self.owners_hi.len()
            || local_index >= self.owners_lo.len()
        {
            return Err(format!(
                "segment {segment_id} is too short for local slot {local_index}"
            ));
        }
        Ok(noid_chain::fri_state::SlotValue {
            value: self.values[local_index],
            owner_hi: self.owners_hi[local_index],
            owner_lo: self.owners_lo[local_index],
        } == noid_chain::fri_state::SlotValue::EMPTY)
    }
}

struct SlotHintCandidate {
    index: u32,
    evicted_segment: Option<u16>,
    is_empty: Option<Result<bool, String>>,
}

/// Resolve fallback candidates in their original rank order while loading at
/// most one durable segment payload at a time.
///
/// Candidate positions are grouped by segment, but the segment containing the
/// earliest unresolved rank is always loaded next.  All later positions in
/// that segment are resolved before its payload is dropped.  This retains the
/// old sequential short-circuit and error semantics without retaining a
/// `SegmentColumns` cache proportional to the candidate spread.
#[allow(clippy::too_many_arguments)]
fn collect_empty_slot_hints_streaming<S, I, IsEvicted, ReadResident, LoadSegment>(
    mut hints: Vec<u32>,
    reserved: &HashSet<u32>,
    count: usize,
    num_slots: u64,
    segment_log: usize,
    candidate_indices: I,
    mut is_evicted: IsEvicted,
    mut read_resident: ReadResident,
    mut load_segment: LoadSegment,
) -> Result<Vec<u32>, String>
where
    S: ExactSegmentSlots,
    I: IntoIterator<Item = u32>,
    IsEvicted: FnMut(u16) -> bool,
    ReadResident: FnMut(u32) -> bool,
    LoadSegment: FnMut(u16) -> Result<S, String>,
{
    if hints.len() >= count {
        return Ok(hints);
    }

    let local_mask = (1u32 << segment_log) - 1;
    let mut seen = reserved.clone();
    seen.extend(hints.iter().copied());
    let mut candidates = Vec::new();
    let mut positions_by_segment = BTreeMap::<u16, Vec<usize>>::new();

    for index in candidate_indices {
        if u64::from(index) >= num_slots || !seen.insert(index) {
            continue;
        }
        let segment_id = (index >> segment_log) as u16;
        let position = candidates.len();
        if is_evicted(segment_id) {
            positions_by_segment
                .entry(segment_id)
                .or_default()
                .push(position);
            candidates.push(SlotHintCandidate {
                index,
                evicted_segment: Some(segment_id),
                is_empty: None,
            });
        } else {
            candidates.push(SlotHintCandidate {
                index,
                evicted_segment: None,
                is_empty: Some(Ok(read_resident(index))),
            });
        }
    }

    let mut cursor = 0usize;
    while cursor < candidates.len() {
        while cursor < candidates.len() {
            let Some(is_empty) = candidates[cursor].is_empty.take() else {
                break;
            };
            if is_empty? {
                hints.push(candidates[cursor].index);
                if hints.len() == count {
                    return Ok(hints);
                }
            }
            cursor += 1;
        }
        if cursor == candidates.len() {
            break;
        }

        let segment_id = candidates[cursor]
            .evicted_segment
            .expect("only an evicted candidate can be unresolved");
        let positions = positions_by_segment
            .remove(&segment_id)
            .expect("every evicted segment has candidate positions");

        // The payload is intentionally scoped to this block. It is dropped
        // before another segment can be loaded.
        {
            let segment = load_segment(segment_id)?;
            for position in positions {
                let local_index = (candidates[position].index & local_mask) as usize;
                candidates[position].is_empty =
                    Some(segment.slot_is_empty(segment_id, local_index));
            }
        }
    }
    Ok(hints)
}

/// Resolve the sole user-transaction anchor accepted in the next child block.
/// Durable lookup is required because it can be 144 blocks behind the tip.
pub fn next_user_epoch_anchor(chain: &MdbxChainContext) -> Result<[u8; 32], String> {
    let child_height = chain
        .tip_height
        .checked_add(1)
        .ok_or_else(|| "child height overflow".to_string())?;
    let anchor_height = noid_chain::consensus::tx_epoch_anchor_height_for_child(child_height);
    let header = chain
        .get_header_from_store(anchor_height)
        .map_err(|error| format!("load transaction epoch anchor: {error}"))?
        .ok_or_else(|| "canonical transaction epoch anchor header is missing".to_string())?;
    Ok(block_id(&header))
}

/// Build and prove a payment while holding the wallet mutex only for coin
/// selection and witness extraction.
pub fn build_send(
    wallet: &crate::SharedWallet,
    to_address: [u8; 32],
    amount_micronoid: u64,
    fee_micronoid: u64,
    epoch_anchor: [u8; 32],
    slot_hints: Vec<u32>,
    log_slots: u32,
) -> Result<(Vec<u8>, Vec<u32>), String> {
    let (data, input_slots) = {
        let guard = wallet
            .lock()
            .map_err(|_| "wallet state lock is poisoned".to_string())?;

        let state = guard
            .as_ref()
            .ok_or_else(|| "wallet not initialized".to_string())?;

        let data = crate::builder::extract_build_data(
            state,
            amount_micronoid,
            fee_micronoid,
            epoch_anchor,
            slot_hints,
            log_slots,
            &state.pending_output_slots,
        )
        .map_err(|error| error.to_string())?;

        let input_slots = data
            .selected_utxos
            .iter()
            .map(|utxo| utxo.slot_index)
            .collect::<Vec<_>>();

        (data, input_slots)
    };

    let (_txid, intent_bytes) =
        crate::builder::build_and_prove_tx(to_address, amount_micronoid, fee_micronoid, data)
            .map_err(|error| error.to_string())?;

    Ok((intent_bytes, input_slots))
}

/// Small transport-independent send plan used by mobile.
#[derive(Debug, Clone)]
pub struct WalletSendPlan {
    pub amount_micronoid: u64,
    pub fee_micronoid: u64,
    pub total_spend_micronoid: u64,
    pub input_count: usize,
    pub output_count: usize,
    pub change_micronoid: u64,
}

/// Deterministic payment planning directly against the shared wallet cache.
///
/// `explicit_fee_micronoid == None` selects the consensus/mempool minimum.
/// The fee is iterated because the required fee itself depends on selected
/// input/output counts.
pub fn plan_send(
    wallet: &crate::SharedWallet,
    amount_micronoid: u64,
    explicit_fee_micronoid: Option<u64>,
    active_slot_count: u64,
    log_slots: u32,
    relay_floor: u64,
) -> Result<WalletSendPlan, String> {
    if amount_micronoid == 0 {
        return Err("payment amount must be greater than zero".to_string());
    }

    let guard = wallet
        .lock()
        .map_err(|_| "wallet state lock is poisoned".to_string())?;

    let state = guard
        .as_ref()
        .ok_or_else(|| "wallet not initialized".to_string())?;

    let spendable = state
        .utxos
        .values()
        .filter(|utxo| !state.pending_input_slots.contains(&utxo.slot_index))
        .map(|utxo| utxo.value)
        .fold(0u64, u64::saturating_add);

    let mut fee = explicit_fee_micronoid.unwrap_or(relay_floor);

    for _ in 0..16 {
        let Some((selected, change)) = state.select_utxos(amount_micronoid, fee) else {
            return Err(format!(
                "InsufficientFunds: need {} μNOID, have {} μNOID spendable",
                amount_micronoid.saturating_add(fee),
                spendable,
            ));
        };

        let input_count = selected.len();

        if input_count > noid_tx::MAX_PAGED_SPEND_INPUTS {
            return Err(format!(
                "InputLimitExceeded: canonical payments support at most {} inputs",
                noid_tx::MAX_PAGED_SPEND_INPUTS,
            ));
        }

        let output_count = if change > 0 { 2 } else { 1 };

        let breakdown = noid_chain::consensus::fee_breakdown(
            input_count as u64,
            output_count as u64,
            active_slot_count,
            log_slots,
        );

        let minimum = relay_floor.max(breakdown.required_total);

        if let Some(explicit) = explicit_fee_micronoid {
            if explicit < minimum {
                return Err(format!(
                    "fee below required minimum: got {explicit}, need {minimum}"
                ));
            }

            return Ok(WalletSendPlan {
                amount_micronoid,
                fee_micronoid: explicit,
                total_spend_micronoid: amount_micronoid.saturating_add(explicit),
                input_count,
                output_count,
                change_micronoid: change,
            });
        }

        if fee == minimum {
            return Ok(WalletSendPlan {
                amount_micronoid,
                fee_micronoid: fee,
                total_spend_micronoid: amount_micronoid.saturating_add(fee),
                input_count,
                output_count,
                change_micronoid: change,
            });
        }

        fee = minimum;
    }

    Err("wallet fee planning did not converge".to_string())
}

/// Plan one canonical no-change payment that spends every currently spendable
/// UTXO belonging to the ACTIVE wallet address.
///
/// This is intentionally not a cross-account sweep. `WalletState::utxos` is
/// the verified cache for the selected active owner only, and pending inputs
/// are excluded exactly as they are for ordinary sends.
///
/// A true SEND ALL must fit into one canonical PagedSpend. If the active
/// address currently needs more than `MAX_PAGED_SPEND_INPUTS`, the caller must
/// consolidate first rather than silently leaving funds behind.
pub fn plan_send_all(
    wallet: &crate::SharedWallet,
    active_slot_count: u64,
    log_slots: u32,
    relay_floor: u64,
) -> Result<WalletSendPlan, String> {
    let guard = wallet
        .lock()
        .map_err(|_| "wallet state lock is poisoned".to_string())?;

    let state = guard
        .as_ref()
        .ok_or_else(|| "wallet not initialized".to_string())?;

    let mut available = state
        .utxos
        .values()
        .filter(|utxo| !state.pending_input_slots.contains(&utxo.slot_index))
        .collect::<Vec<_>>();

    available.sort_by_key(|utxo| {
        (
            std::cmp::Reverse(utxo.value),
            utxo.slot_index >> noid_chain::consensus::params::LOG_SEGMENT_SIZE,
            utxo.slot_index,
        )
    });

    if available.is_empty() {
        return Err("InsufficientFunds: active address has no spendable UTXOs".to_string());
    }

    if available.len() > noid_tx::MAX_PAGED_SPEND_INPUTS {
        return Err(format!(
            "InputLimitExceeded: SEND ALL needs {} inputs but one canonical payment supports at most {}; consolidate first",
            available.len(),
            noid_tx::MAX_PAGED_SPEND_INPUTS,
        ));
    }

    let spendable = available.iter().try_fold(0u64, |sum, utxo| {
        sum.checked_add(utxo.value)
            .ok_or_else(|| "wallet balance arithmetic overflow".to_string())
    })?;

    let input_count = available.len();
    let output_count = 1usize;

    let breakdown = noid_chain::consensus::fee_breakdown(
        input_count as u64,
        output_count as u64,
        active_slot_count,
        log_slots,
    );

    let fee_micronoid = relay_floor.max(breakdown.required_total);

    let amount_micronoid = spendable.checked_sub(fee_micronoid).ok_or_else(|| {
        format!(
            "InsufficientFunds: active balance {} μNOID does not cover SEND ALL fee {} μNOID",
            spendable, fee_micronoid
        )
    })?;

    if amount_micronoid == 0 {
        return Err(format!(
            "InsufficientFunds: active balance equals SEND ALL fee {} μNOID",
            fee_micronoid
        ));
    }

    Ok(WalletSendPlan {
        amount_micronoid,
        fee_micronoid,
        total_spend_micronoid: spendable,
        input_count,
        output_count,
        change_micronoid: 0,
    })
}
