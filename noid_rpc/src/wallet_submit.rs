// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Shared wallet submission primitives.
//!
//! The operation gate serializes active-owner reload, payment proving, normal
//! mempool admission, and account switches. The reservation guard keeps wallet
//! state cancellation-safe around async admission.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use noid_chain::consensus::allocator::generate_slot_hints;
use noid_chain::consensus::pow::block_id;
use noid_chain::storage::MdbxChainContext;
use tokio::sync::Mutex;

use crate::wallet_ops::WalletOps;

pub type WalletOperationGate = Arc<Mutex<()>>;

/// Owned wallet reservation around an async admission future. Dropping the
/// future at any await point synchronously rolls back inputs, outputs, and the
/// pending history record. `commit` disarms it after successful admission.
pub(crate) struct PendingAdmissionGuard {
    rollback: Option<Box<dyn FnOnce() + Send + 'static>>,
}

impl PendingAdmissionGuard {
    fn armed(rollback: impl FnOnce() + Send + 'static) -> Self {
        Self {
            rollback: Some(Box::new(rollback)),
        }
    }

    pub(crate) fn reserve(
        wallet: Arc<dyn WalletOps + Send + Sync>,
        txid: [u8; 32],
        input_slots: Vec<u32>,
        output_slots: Vec<u32>,
        amount_micronoid: u64,
        peer_address: [u8; 32],
    ) -> Result<Self, String> {
        wallet.reserve_pending_submission(
            txid,
            &input_slots,
            &output_slots,
            amount_micronoid,
            peer_address,
        )?;
        Ok(Self::armed(move || {
            wallet.rollback_pending_submission(txid, &input_slots, &output_slots);
        }))
    }

    pub(crate) fn commit(mut self) {
        self.rollback = None;
    }
}

impl Drop for PendingAdmissionGuard {
    fn drop(&mut self) {
        if let Some(rollback) = self.rollback.take() {
            rollback();
        }
    }
}

/// Select exact empty slots without treating an evicted live segment as a
/// virtual zero segment. Missing/corrupt durable segment data fails closed.
pub(crate) fn collect_empty_slot_hints(
    chain: &MdbxChainContext,
    reserved: &HashSet<u32>,
    seed: u64,
    count: usize,
    fallback_candidates: usize,
) -> Result<Vec<u32>, String> {
    if count == 0 {
        return Ok(Vec::new());
    }
    let state = &chain.state.state;
    let mut hints = state.empty_slot_hints_in_populated_segments(seed, count, reserved);
    if hints.len() == count {
        return Ok(hints);
    }

    let mut seen = reserved.clone();
    seen.extend(hints.iter().copied());
    let mut segment_cache = HashMap::new();
    for index in generate_slot_hints(seed, state.log_slots() as u32, fallback_candidates) {
        if u64::from(index) >= state.num_slots() || !seen.insert(index) {
            continue;
        }
        if read_exact_slot(chain, index, &mut segment_cache)?
            == noid_chain::fri_state::SlotValue::EMPTY
        {
            hints.push(index);
            if hints.len() == count {
                break;
            }
        }
    }
    Ok(hints)
}

fn read_exact_slot(
    chain: &MdbxChainContext,
    slot_index: u32,
    segment_cache: &mut HashMap<u16, noid_chain::segmented_state::SegmentColumns>,
) -> Result<noid_chain::fri_state::SlotValue, String> {
    let state = &chain.state.state;
    if u64::from(slot_index) >= state.num_slots() {
        return Err(format!("slot {slot_index} is out of range"));
    }
    let segment_log = state.effective_log_segment_size();
    let segment_id = (slot_index >> segment_log) as u16;
    if !state.is_evicted(segment_id) {
        return Ok(state.slot(slot_index));
    }

    if !segment_cache.contains_key(&segment_id) {
        let Some((stored_log, columns)) = chain
            .store
            .get_segment(segment_id)
            .map_err(|error| error.to_string())?
        else {
            return Err(format!(
                "evicted segment {segment_id} is missing from durable state"
            ));
        };
        if usize::from(stored_log) != segment_log {
            return Err(format!(
                "segment {segment_id} depth mismatch: stored {stored_log}, expected {segment_log}"
            ));
        }
        segment_cache.insert(segment_id, columns);
    }

    let local_mask = (1u32 << segment_log) - 1;
    let local_index = (slot_index & local_mask) as usize;
    let columns = &segment_cache[&segment_id];
    if local_index >= columns.values.len()
        || local_index >= columns.owners_hi.len()
        || local_index >= columns.owners_lo.len()
    {
        return Err(format!(
            "segment {segment_id} is too short for local slot {local_index}"
        ));
    }
    Ok(noid_chain::fri_state::SlotValue {
        value: columns.values[local_index],
        owner_hi: columns.owners_hi[local_index],
        owner_lo: columns.owners_lo[local_index],
    })
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn pending_guard_rolls_back_on_drop_and_disarms_on_commit() {
        let rollbacks = Arc::new(AtomicUsize::new(0));
        {
            let rollbacks = Arc::clone(&rollbacks);
            let _guard = PendingAdmissionGuard::armed(move || {
                rollbacks.fetch_add(1, Ordering::SeqCst);
            });
        }
        assert_eq!(rollbacks.load(Ordering::SeqCst), 1);

        {
            let rollbacks = Arc::clone(&rollbacks);
            PendingAdmissionGuard::armed(move || {
                rollbacks.fetch_add(1, Ordering::SeqCst);
            })
            .commit();
        }
        assert_eq!(rollbacks.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn aborting_admission_future_drops_the_armed_reservation() {
        let rollbacks = Arc::new(AtomicUsize::new(0));
        let task_rollbacks = Arc::clone(&rollbacks);
        let task = tokio::spawn(async move {
            let _guard = PendingAdmissionGuard::armed(move || {
                task_rollbacks.fetch_add(1, Ordering::SeqCst);
            });
            std::future::pending::<()>().await;
        });
        tokio::task::yield_now().await;
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert_eq!(rollbacks.load(Ordering::SeqCst), 1);
    }
}
