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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Default)]
    struct SegmentResidency {
        current: AtomicUsize,
        peak: AtomicUsize,
        loads: AtomicUsize,
    }

    struct TrackedSegment {
        residency: Arc<SegmentResidency>,
        empty_local_index: usize,
    }

    impl TrackedSegment {
        fn load(residency: Arc<SegmentResidency>, empty_local_index: usize) -> Self {
            let current = residency.current.fetch_add(1, Ordering::SeqCst) + 1;
            residency.peak.fetch_max(current, Ordering::SeqCst);
            residency.loads.fetch_add(1, Ordering::SeqCst);
            Self {
                residency,
                empty_local_index,
            }
        }
    }

    impl Drop for TrackedSegment {
        fn drop(&mut self) {
            assert_eq!(self.residency.current.fetch_sub(1, Ordering::SeqCst), 1);
        }
    }

    impl ExactSegmentSlots for TrackedSegment {
        fn slot_is_empty(&self, _segment_id: u16, local_index: usize) -> Result<bool, String> {
            Ok(local_index == self.empty_local_index)
        }
    }

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

    #[test]
    fn fallback_streams_16384_dispersed_candidates_with_one_resident_segment() {
        const SEGMENT_LOG: usize = 16;
        const SEGMENTS: u32 = 256;
        const CANDIDATES_PER_SEGMENT: u32 = 64;

        // Every rank round crosses all 256 production-size segments. Only the
        // final local rank is empty, so selection must account for all 16,384
        // candidates before returning the 256 hints.
        let candidates = (0..CANDIDATES_PER_SEGMENT)
            .flat_map(|local| (0..SEGMENTS).map(move |segment| (segment << SEGMENT_LOG) | local));
        let residency = Arc::new(SegmentResidency::default());
        let load_residency = Arc::clone(&residency);
        let hints = collect_empty_slot_hints_streaming(
            Vec::new(),
            &HashSet::new(),
            SEGMENTS as usize,
            1u64 << 24,
            SEGMENT_LOG,
            candidates,
            |_| true,
            |_| unreachable!("all test segments are evicted"),
            move |_| {
                Ok(TrackedSegment::load(
                    Arc::clone(&load_residency),
                    (CANDIDATES_PER_SEGMENT - 1) as usize,
                ))
            },
        )
        .unwrap();

        let expected = (0..SEGMENTS)
            .map(|segment| (segment << SEGMENT_LOG) | (CANDIDATES_PER_SEGMENT - 1))
            .collect::<Vec<_>>();
        assert_eq!(hints, expected, "candidate rank ordering changed");
        assert_eq!(residency.loads.load(Ordering::SeqCst), SEGMENTS as usize);
        assert_eq!(residency.peak.load(Ordering::SeqCst), 1);
        assert_eq!(residency.current.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn fallback_does_not_touch_missing_segment_after_enough_hints() {
        const SEGMENT_LOG: usize = 16;
        let candidates = vec![(2u32 << SEGMENT_LOG) | 9, (7u32 << SEGMENT_LOG) | 4];
        let loaded = std::cell::RefCell::new(Vec::new());
        let hints = collect_empty_slot_hints_streaming(
            Vec::new(),
            &HashSet::new(),
            1,
            1u64 << 24,
            SEGMENT_LOG,
            candidates,
            |_| true,
            |_| unreachable!("all test segments are evicted"),
            |segment_id| {
                loaded.borrow_mut().push(segment_id);
                if segment_id == 7 {
                    Err("evicted segment 7 is missing from durable state".to_string())
                } else {
                    Ok(TrackedSegment::load(
                        Arc::new(SegmentResidency::default()),
                        9,
                    ))
                }
            },
        )
        .unwrap();

        assert_eq!(hints, vec![(2u32 << SEGMENT_LOG) | 9]);
        assert_eq!(*loaded.borrow(), vec![2]);
    }

    #[test]
    fn fallback_reports_missing_segment_at_its_original_candidate_rank() {
        const SEGMENT_LOG: usize = 16;
        let error = collect_empty_slot_hints_streaming::<TrackedSegment, _, _, _, _>(
            Vec::new(),
            &HashSet::new(),
            1,
            1u64 << 24,
            SEGMENT_LOG,
            vec![(7u32 << SEGMENT_LOG) | 4],
            |_| true,
            |_| unreachable!("all test segments are evicted"),
            |segment_id| {
                Err(format!(
                    "evicted segment {segment_id} is missing from durable state"
                ))
            },
        )
        .unwrap_err();

        assert_eq!(error, "evicted segment 7 is missing from durable state");
    }

    #[test]
    fn fallback_preserves_too_short_segment_failure_order() {
        const SEGMENT_LOG: usize = 16;
        let candidates = vec![
            3u32 << SEGMENT_LOG,
            (3u32 << SEGMENT_LOG) | 1,
            (4u32 << SEGMENT_LOG) | 5,
        ];
        let error = collect_empty_slot_hints_streaming(
            Vec::new(),
            &HashSet::new(),
            1,
            1u64 << 24,
            SEGMENT_LOG,
            candidates,
            |_| true,
            |_| unreachable!("all test segments are evicted"),
            |segment_id| {
                if segment_id == 3 {
                    let mut columns = noid_chain::segmented_state::SegmentColumns::new_zero(1);
                    columns.values[0] = 1u64.into();
                    Ok(columns)
                } else {
                    Ok(noid_chain::segmented_state::SegmentColumns::new_zero(8))
                }
            },
        )
        .unwrap_err();

        assert_eq!(error, "segment 3 is too short for local slot 1");
    }

    #[test]
    fn salted_empty_state_hints_remain_dense_in_one_allocator_segment() {
        let directory = tempfile::tempdir().unwrap();
        let chain = MdbxChainContext::open_or_create(directory.path()).unwrap();
        let first = collect_empty_slot_hints(&chain, &HashSet::new(), 11, 256)
            .expect("first dense hint set");
        let second = collect_empty_slot_hints(&chain, &HashSet::new(), 29, 256)
            .expect("second dense hint set");
        let segment_log = chain.state.state.effective_log_segment_size();
        let first_segments = first
            .iter()
            .map(|slot| slot >> segment_log)
            .collect::<HashSet<_>>();
        let second_segments = second
            .iter()
            .map(|slot| slot >> segment_log)
            .collect::<HashSet<_>>();

        assert_eq!(first_segments.len(), 1);
        assert_eq!(second_segments, first_segments);
        assert_ne!(first, second, "salt must still diversify local positions");
        assert_eq!(
            first.len(),
            first.iter().copied().collect::<HashSet<_>>().len()
        );
        assert_eq!(
            second.len(),
            second.iter().copied().collect::<HashSet<_>>().len()
        );
    }
}
