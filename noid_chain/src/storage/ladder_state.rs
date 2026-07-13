// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Forward ladder cursor for the selected-history proof worker.
//!
//! The worker proves heights sequentially and needs the exact chain state at
//! each job's parent.  Rolling back from the canonical tip is bounded by the
//! retained undo window, so a proof pipeline lagging more than
//! `UNDO_RETENTION_DEPTH` blocks would wedge permanently.  Instead the worker
//! owns a durable forward cursor (`T_LADDER_META` + `T_LADDER_SEGMENTS`):
//! every promotion persists the proven block's end-state boundary, and this
//! loader rebuilds the parent state from that cursor with no dependency on
//! how far the tip has advanced.
//!
//! The returned [`ChainState`] follows the same contract as
//! [`super::HistoricalExactStateView`]: FRI summaries are unavailable and the
//! replay must never call a FRI root/opening API; raw columns are resident
//! only for the caller-declared touched segments; absent segments are virtual
//! zero exactly when their live count is zero.

use crate::block::Block;
use crate::block_header::{block_id, BlockHeader};
use crate::consensus::params::{BLOCK_MAX_DISTINCT_SEGMENTS, UNDO_RETENTION_DEPTH};
use crate::fri_state::LOG_SEGMENT_SIZE;
use crate::segmented_state::SegmentedFriState;
use crate::state::ChainState;

use super::historical_state::{
    reconstruct_historical_exact_state, CanonicalTipBinding, HistoricalStateError,
};
use super::mdbx_context::{MdbxChainContext, MdbxContextError};
use super::mdbx_store::SelectedHistoryLadderMeta;
use super::{MdbxStore, StoreError};

#[derive(Debug)]
pub enum LadderStateError {
    Store(StoreError),
    Corrupt(&'static str),
    MissingHeader(u64),
    MissingRetainedBlock(u64),
    /// The durable cursor is above the requested parent: the claim raced a
    /// reorg rewind and must simply be retried against fresh canonical data.
    CursorAheadOfTarget {
        cursor: u64,
        target: u64,
    },
    /// No cursor exists and neither bootstrap source can rebuild one: the tip
    /// rollback window has passed and retained blocks no longer reach back to
    /// genesis.
    Unrecoverable {
        target: u64,
        tip: u64,
    },
    RequiredSegments(&'static str),
    TouchedSegments(TouchedSegmentError),
    HistoricalSeed(HistoricalStateError),
    Context(MdbxContextError),
}

impl std::fmt::Display for LadderStateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Store(error) => write!(f, "ladder state store read: {error}"),
            Self::Corrupt(context) => write!(f, "corrupt ladder cursor source: {context}"),
            Self::MissingHeader(height) => write!(f, "canonical header {height} is missing"),
            Self::MissingRetainedBlock(height) => {
                write!(f, "retained block {height} is missing")
            }
            Self::CursorAheadOfTarget { cursor, target } => write!(
                f,
                "ladder cursor {cursor} is above the requested parent {target}"
            ),
            Self::Unrecoverable { target, tip } => write!(
                f,
                "ladder cursor at {target} cannot be bootstrapped at tip {tip}: \
                 outside the undo window and the retained block prefix"
            ),
            Self::RequiredSegments(context) => {
                write!(f, "invalid required segment set: {context}")
            }
            Self::TouchedSegments(error) => write!(f, "derive touched segments: {error}"),
            Self::HistoricalSeed(error) => write!(f, "ladder bootstrap seed: {error}"),
            Self::Context(error) => write!(f, "ladder bootstrap tip state: {error}"),
        }
    }
}

impl std::error::Error for LadderStateError {}

impl From<StoreError> for LadderStateError {
    fn from(error: StoreError) -> Self {
        Self::Store(error)
    }
}

/// Load the exact chain state at `parent_header` from the durable forward
/// ladder cursor, hydrating raw columns only for `required_segment_ids`.
///
/// When the cursor is absent or behind, a fail-closed bootstrap first brings
/// it to the parent boundary: the empty genesis state, a one-time rollback
/// seed while the tip is still within the undo window, or a native forward
/// replay of retained canonical blocks (persisted per block, so it is
/// crash-resumable and keeps only one block's touched segments resident).
pub fn load_selected_history_ladder_parent_state(
    store: &MdbxStore,
    parent_header: &BlockHeader,
    required_segment_ids: &[u16],
) -> Result<ChainState, LadderStateError> {
    validate_required_segment_ids(required_segment_ids, parent_header.log_slots)?;

    // Bootstrap and fast-forward both leave the cursor exactly at the parent
    // boundary, so one more pass must terminate.
    for _ in 0..2 {
        let meta = store.get_selected_history_ladder_meta()?;
        match meta {
            Some(meta) if meta.height == parent_header.height => {
                return load_state_at_cursor(store, parent_header, required_segment_ids);
            }
            Some(meta) if meta.height > parent_header.height => {
                return Err(LadderStateError::CursorAheadOfTarget {
                    cursor: meta.height,
                    target: parent_header.height,
                });
            }
            Some(meta) => match fast_forward_ladder_cursor(store, meta, parent_header) {
                Ok(()) => {}
                // A stale cursor behind a pruned prefix (e.g. after a remote
                // coverage import) cannot walk forward; a self-contained
                // bootstrap seed may still replace it while the target is
                // inside the tip's undo window.
                Err(LadderStateError::MissingRetainedBlock(_)) => {
                    bootstrap_ladder_cursor(store, parent_header)?;
                }
                Err(error) => return Err(error),
            },
            None => bootstrap_ladder_cursor(store, parent_header)?,
        }
    }
    Err(LadderStateError::Corrupt(
        "ladder cursor did not converge on the parent boundary",
    ))
}

fn validate_required_segment_ids(
    required_segment_ids: &[u16],
    log_slots: u32,
) -> Result<(), LadderStateError> {
    if required_segment_ids.len() > BLOCK_MAX_DISTINCT_SEGMENTS {
        return Err(LadderStateError::RequiredSegments(
            "required segment count exceeds the block budget",
        ));
    }
    if !required_segment_ids
        .windows(2)
        .all(|pair| pair[0] < pair[1])
    {
        return Err(LadderStateError::RequiredSegments(
            "required segment IDs must be strictly sorted and unique",
        ));
    }
    let domain = segment_domain(log_slots)?;
    if required_segment_ids
        .iter()
        .any(|&segment_id| usize::from(segment_id) >= domain)
    {
        return Err(LadderStateError::RequiredSegments(
            "required segment lies outside the parent domain",
        ));
    }
    Ok(())
}

fn segment_domain(log_slots: u32) -> Result<usize, LadderStateError> {
    if log_slots == 0 || log_slots > crate::consensus::params::LOG_SLOTS_MAX {
        return Err(LadderStateError::Corrupt(
            "header log_slots is outside the consensus domain",
        ));
    }
    if log_slots as usize <= LOG_SEGMENT_SIZE {
        return Ok(1);
    }
    1usize
        .checked_shl(log_slots - LOG_SEGMENT_SIZE as u32)
        .ok_or(LadderStateError::Corrupt(
            "segment domain does not fit usize",
        ))
}

/// Build the replay state from a cursor already at the parent boundary.
///
/// Meta and segment payloads are read from one MDBX MVCC snapshot.  Every
/// hydrated segment is checked against its compact exact-root summary, and
/// the summary set itself must commit to the parent header's state root
/// (enforced by `from_evicted_parts`).
fn load_state_at_cursor(
    store: &MdbxStore,
    parent_header: &BlockHeader,
    required_segment_ids: &[u16],
) -> Result<ChainState, LadderStateError> {
    let snapshot = store.historical_read_snapshot()?;
    let meta = snapshot
        .get_selected_history_ladder_meta()?
        .ok_or(LadderStateError::Corrupt("ladder cursor disappeared"))?;
    if meta.height != parent_header.height
        || meta.block_hash != block_id(parent_header)
        || meta.log_slots != parent_header.log_slots
        || meta.active_slot_count != parent_header.active_slot_count
        || meta.alloc_counter != parent_header.alloc_counter
    {
        return Err(LadderStateError::Corrupt(
            "ladder cursor is not the requested parent boundary",
        ));
    }
    let domain = segment_domain(meta.log_slots)?;
    let mut segmented = SegmentedFriState::new_empty(meta.log_slots as usize);
    for &(segment_id, live_count, _) in &meta.segment_summaries {
        if usize::from(segment_id) >= domain {
            return Err(LadderStateError::Corrupt(
                "ladder cursor summary lies outside its domain",
            ));
        }
        segmented
            .install_evicted_segment_summary_without_fri(segment_id, live_count)
            .map_err(LadderStateError::Corrupt)?;
    }
    let exact_entries: Vec<(u16, [u8; 32])> = meta
        .segment_summaries
        .iter()
        .map(|&(segment_id, _, exact_root)| (segment_id, exact_root))
        .collect();
    let mut state = ChainState::from_evicted_parts(
        segmented,
        meta.active_slot_count,
        meta.alloc_counter,
        parent_header.state_root,
        &exact_entries,
    )
    .map_err(|_| {
        LadderStateError::Corrupt("ladder cursor summaries do not commit to the parent state root")
    })?;

    let effective_log = (meta.log_slots as usize).min(LOG_SEGMENT_SIZE);
    let segment_len = 1usize << effective_log;
    for &segment_id in required_segment_ids {
        let live_count = meta
            .segment_summaries
            .binary_search_by_key(&segment_id, |&(id, _, _)| id)
            .map(|index| meta.segment_summaries[index].1)
            .unwrap_or(0);
        match snapshot.get_selected_history_ladder_segment(segment_id)? {
            Some((stored_log, columns)) => {
                if live_count == 0 {
                    return Err(LadderStateError::Corrupt(
                        "stale ladder payload backs an empty segment",
                    ));
                }
                if usize::from(stored_log) != effective_log
                    || columns.values.len() != segment_len
                    || columns.owners_hi.len() != segment_len
                    || columns.owners_lo.len() != segment_len
                {
                    return Err(LadderStateError::Corrupt(
                        "ladder segment shape does not match the cursor geometry",
                    ));
                }
                state
                    .restore_evicted_segment(segment_id, columns)
                    .map_err(|_| {
                        LadderStateError::Corrupt(
                            "ladder segment does not match its compact exact summary",
                        )
                    })?;
            }
            // Absent payloads are virtual zero only for empty segments.
            None if live_count != 0 => {
                return Err(LadderStateError::Corrupt(
                    "ladder cursor names a live segment with no payload",
                ));
            }
            None => {}
        }
    }
    Ok(state)
}

/// Bring an absent cursor to the parent boundary.
fn bootstrap_ladder_cursor(
    store: &MdbxStore,
    target_header: &BlockHeader,
) -> Result<(), LadderStateError> {
    if target_header.height == 0 {
        // Genesis carries the canonical empty state; persist it explicitly so
        // the first promotion has a durable predecessor boundary.
        let state = ChainState::with_log_slots(target_header.log_slots as usize);
        if state.cached_state_root() != target_header.state_root
            || target_header.active_slot_count != 0
            || target_header.alloc_counter != 0
        {
            return Err(LadderStateError::Corrupt(
                "genesis parent header does not commit to the empty state",
            ));
        }
        let update = state
            .into_selected_history_ladder_snapshot()
            .map_err(LadderStateError::Corrupt)?;
        store.advance_selected_history_ladder_cursor(target_header, &update)?;
        return Ok(());
    }

    let (tip_height, tip_hash) = store
        .get_chain_tip()?
        .ok_or(LadderStateError::Corrupt("canonical tip is missing"))?;
    if tip_height.saturating_sub(target_header.height) <= UNDO_RETENTION_DEPTH {
        return seed_cursor_from_recent_state(store, target_header, tip_height, tip_hash);
    }

    // Outside the undo window the only remaining source is a full native
    // replay of retained blocks from genesis (possible only while nothing
    // below the target was pruned, e.g. a migrated store with lagging
    // maintenance). Preflight cheaply before persisting anything.
    for height in 1..=target_header.height {
        if !store.has_recent_block(height)? {
            return Err(LadderStateError::Unrecoverable {
                target: target_header.height,
                tip: tip_height,
            });
        }
    }
    let genesis = store
        .get_header(0)?
        .ok_or(LadderStateError::MissingHeader(0))?;
    let state = ChainState::with_log_slots(genesis.log_slots as usize);
    if state.cached_state_root() != genesis.state_root {
        return Err(LadderStateError::Corrupt(
            "genesis header does not commit to the empty state",
        ));
    }
    let update = state
        .into_selected_history_ladder_snapshot()
        .map_err(LadderStateError::Corrupt)?;
    store.advance_selected_history_ladder_cursor(&genesis, &update)?;
    // The caller's outer pass fast-forwards from this genesis boundary.
    let meta = store
        .get_selected_history_ladder_meta()?
        .ok_or(LadderStateError::Corrupt("seeded genesis cursor vanished"))?;
    fast_forward_ladder_cursor(store, meta, target_header)
}

/// One-time bootstrap seed while the target is still inside the tip's undo
/// window: reconstruct the complete exact state at the target and persist it
/// as a self-contained cursor snapshot.
///
/// The full-domain hydration is bounded by the block segment budget; larger
/// domains (beyond 2^24 slots) must already own a cursor by construction.
fn seed_cursor_from_recent_state(
    store: &MdbxStore,
    target_header: &BlockHeader,
    tip_height: u64,
    tip_hash: [u8; 32],
) -> Result<(), LadderStateError> {
    let (log_slots, active_slot_count, alloc_counter) = store
        .get_state_meta()?
        .ok_or(LadderStateError::Corrupt("durable state metadata missing"))?;
    let tip_header = store
        .get_header(tip_height)?
        .ok_or(LadderStateError::MissingHeader(tip_height))?;
    if block_id(&tip_header) != tip_hash
        || tip_header.log_slots != log_slots
        || tip_header.active_slot_count != active_slot_count
        || tip_header.alloc_counter != alloc_counter
    {
        return Err(LadderStateError::Corrupt(
            "durable state metadata does not match the canonical tip",
        ));
    }
    let tip_state = MdbxChainContext::load_streamed_chain_state(
        store,
        log_slots,
        active_slot_count,
        alloc_counter,
        tip_header.height,
        tip_header.state_root,
    )
    .map_err(LadderStateError::Context)?;

    let domain = segment_domain(target_header.log_slots)?;
    if domain > BLOCK_MAX_DISTINCT_SEGMENTS {
        return Err(LadderStateError::Corrupt(
            "ladder bootstrap domain exceeds the bounded hydration budget",
        ));
    }
    let all_segment_ids: Vec<u16> = (0..domain as u16).collect();
    let view = reconstruct_historical_exact_state(
        store,
        &tip_state,
        CanonicalTipBinding {
            height: tip_height,
            hash: tip_hash,
        },
        target_header.height,
        &all_segment_ids,
    )
    .map_err(LadderStateError::HistoricalSeed)?;
    drop(tip_state);
    if view.target_header() != target_header {
        return Err(LadderStateError::Corrupt(
            "bootstrap seed target diverged from the requested parent",
        ));
    }
    let state = view.into_exact_state_for_replay();
    let update = state
        .into_selected_history_ladder_snapshot()
        .map_err(LadderStateError::Corrupt)?;
    store.advance_selected_history_ladder_cursor(target_header, &update)?;
    Ok(())
}

/// Advance the cursor to the target by replaying retained canonical blocks.
///
/// Each block hydrates only its touched segments, replays natively against
/// the canonical header (exact roots and counters fail closed), and persists
/// its boundary before the next block, so memory stays bounded and a crash
/// resumes exactly where it stopped.
fn fast_forward_ladder_cursor(
    store: &MdbxStore,
    from: SelectedHistoryLadderMeta,
    target_header: &BlockHeader,
) -> Result<(), LadderStateError> {
    let mut cursor_height = from.height;
    while cursor_height < target_header.height {
        let height = cursor_height + 1;
        let parent = store
            .get_header(cursor_height)?
            .ok_or(LadderStateError::MissingHeader(cursor_height))?;
        let header = if height == target_header.height {
            *target_header
        } else {
            store
                .get_header(height)?
                .ok_or(LadderStateError::MissingHeader(height))?
        };
        if header.height != height || header.prev_block_hash != block_id(&parent) {
            return Err(LadderStateError::Corrupt(
                "retained canonical headers are not linked at the ladder cursor",
            ));
        }
        let block_bytes = store
            .get_recent_block(height)?
            .ok_or(LadderStateError::MissingRetainedBlock(height))?;
        let block = Block::from_bytes(&block_bytes)
            .map_err(|_| LadderStateError::Corrupt("retained block bytes are invalid"))?;
        drop(block_bytes);
        if block.header != header {
            return Err(LadderStateError::Corrupt(
                "retained block header is not canonical",
            ));
        }

        let mut touched = derive_touched_segment_ids(&block, parent.log_slots)
            .map_err(LadderStateError::TouchedSegments)?;
        // A sub-production expansion grows the single segment in place, which
        // requires its columns resident. Production geometry never takes this
        // branch.
        if header.log_slots > parent.log_slots
            && (parent.log_slots as usize) < LOG_SEGMENT_SIZE
            && touched.first() != Some(&0)
        {
            touched.insert(0, 0);
        }
        let mut state = load_state_at_cursor(store, &parent, &touched)?;
        apply_retained_block_to_ladder_state(&mut state, &block)?;
        let update = state
            .into_selected_history_ladder_update()
            .map_err(LadderStateError::Corrupt)?;
        store.advance_selected_history_ladder_cursor(&header, &update)?;
        cursor_height = height;
    }
    Ok(())
}

/// Native single-block replay against the canonical header, without proof
/// verification: retained blocks were already accepted, and the final exact
/// state root, counters, and tx root all fail closed against the header.
fn apply_retained_block_to_ladder_state(
    state: &mut ChainState,
    block: &Block,
) -> Result<(), LadderStateError> {
    if crate::block::compute_tx_root(&block.transactions) != block.header.tx_root {
        return Err(LadderStateError::Corrupt(
            "retained block body does not match its header tx root",
        ));
    }
    crate::consensus::checks::validate_block_slot_conflicts(&block.transactions)
        .map_err(|_| LadderStateError::Corrupt("retained block has conflicting slot actions"))?;
    let current_log_slots = state.state.log_slots() as u32;
    if block.header.log_slots != current_log_slots
        && block.header.log_slots != current_log_slots.saturating_add(1)
    {
        return Err(LadderStateError::Corrupt(
            "retained block slot-domain transition is invalid",
        ));
    }
    if block.header.log_slots == current_log_slots.saturating_add(1) {
        if current_log_slots as usize >= LOG_SEGMENT_SIZE {
            state.expand_exact_metadata_for_replay().map_err(|_| {
                LadderStateError::Corrupt("retained block slot-domain expansion failed")
            })?;
        } else {
            state.expand_one();
        }
    }
    for transaction in &block.transactions {
        transaction
            .body
            .validate_canonical()
            .map_err(|_| LadderStateError::Corrupt("retained block transaction is malformed"))?;
        crate::state::apply_tx_checked_deferred_root(
            state,
            &transaction.body,
            Some(block.header.height),
        )
        .map_err(|_| {
            LadderStateError::Corrupt("retained block does not replay onto the ladder state")
        })?;
    }
    let root = state
        .try_state_root()
        .map_err(|_| LadderStateError::Corrupt("ladder replay left the exact root unavailable"))?;
    if root != block.header.state_root
        || state.active_slot_count != block.header.active_slot_count
        || state.alloc_counter != block.header.alloc_counter
    {
        return Err(LadderStateError::Corrupt(
            "ladder replay does not commit to the canonical header",
        ));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TouchedSegmentError {
    UnsupportedLogSlots(u32),
    InvalidLogSlotsTransition { parent: u32, child: u32 },
    InputSlotOutOfParentDomain(u32),
    SlotOutOfDomain(u32),
    SegmentIdOverflow(u32),
    TooManyDistinctSegments { actual: usize, maximum: usize },
}

impl std::fmt::Display for TouchedSegmentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedLogSlots(log) => write!(f, "unsupported log_slots {log}"),
            Self::InvalidLogSlotsTransition { parent, child } => {
                write!(f, "invalid log_slots transition {parent} -> {child}")
            }
            Self::InputSlotOutOfParentDomain(slot) => {
                write!(f, "live input slot {slot} is outside the parent domain")
            }
            Self::SlotOutOfDomain(slot) => write!(f, "live slot {slot} is outside block domain"),
            Self::SegmentIdOverflow(segment) => {
                write!(f, "derived segment {segment} exceeds u16 storage identity")
            }
            Self::TooManyDistinctSegments { actual, maximum } => write!(
                f,
                "block touches {actual} exact-state segments; maximum is {maximum}"
            ),
        }
    }
}

impl std::error::Error for TouchedSegmentError {}

/// Derive only the raw exact-state segments actually read by the one-block
/// replay. Dead fixed-width actions are ignored; duplicate segment IDs are
/// compacted in place and the consensus distinct-segment cap is enforced.
pub fn derive_touched_segment_ids(
    block: &Block,
    parent_log_slots: u32,
) -> Result<Vec<u16>, TouchedSegmentError> {
    let child_log_slots = block.header.log_slots;
    if parent_log_slots > u32::BITS || child_log_slots > u32::BITS {
        return Err(TouchedSegmentError::UnsupportedLogSlots(
            parent_log_slots.max(child_log_slots),
        ));
    }
    if child_log_slots != parent_log_slots && child_log_slots != parent_log_slots.saturating_add(1)
    {
        return Err(TouchedSegmentError::InvalidLogSlotsTransition {
            parent: parent_log_slots,
            child: child_log_slots,
        });
    }
    let effective_log = usize::try_from(parent_log_slots)
        .unwrap_or(usize::MAX)
        .min(LOG_SEGMENT_SIZE);
    let parent_domain_slots = 1u64
        .checked_shl(parent_log_slots)
        .ok_or(TouchedSegmentError::UnsupportedLogSlots(parent_log_slots))?;
    let child_domain_slots = 1u64
        .checked_shl(child_log_slots)
        .ok_or(TouchedSegmentError::UnsupportedLogSlots(child_log_slots))?;
    let mut segments = Vec::with_capacity(BLOCK_MAX_DISTINCT_SEGMENTS);

    let mut push_parent_slot = |slot: u32| -> Result<(), TouchedSegmentError> {
        let segment = slot >> effective_log;
        let segment_id =
            u16::try_from(segment).map_err(|_| TouchedSegmentError::SegmentIdOverflow(segment))?;
        segments.push(segment_id);
        Ok(())
    };
    for transaction in &block.transactions {
        for (_, input) in transaction.body.live_inputs() {
            if u64::from(input.slot_index) >= parent_domain_slots {
                return Err(TouchedSegmentError::InputSlotOutOfParentDomain(
                    input.slot_index,
                ));
            }
            push_parent_slot(input.slot_index)?;
        }
        for (_, output) in transaction.body.live_outputs() {
            if u64::from(output.slot_index) >= child_domain_slots {
                return Err(TouchedSegmentError::SlotOutOfDomain(output.slot_index));
            }
            // During the sole permitted +1 expansion, the upper half is
            // deterministically virtual zero at the parent boundary.  Loading
            // it from historical MDBX would be both unnecessary and invalid;
            // `apply_block` materializes it only after expanding the state.
            if u64::from(output.slot_index) < parent_domain_slots {
                push_parent_slot(output.slot_index)?;
            }
        }
    }
    segments.sort_unstable();
    segments.dedup();
    if segments.len() > BLOCK_MAX_DISTINCT_SEGMENTS {
        return Err(TouchedSegmentError::TooManyDistinctSegments {
            actual: segments.len(),
            maximum: BLOCK_MAX_DISTINCT_SEGMENTS,
        });
    }
    Ok(segments)
}

#[cfg(test)]
mod tests {
    use super::*;

    use noid_core::Block128;
    use noid_poseidon2b::primitives::Address;
    use noid_tx::{
        output_bitmap_bit, Transaction, TxBody, TxInput, TxOutput, TX_INPUTS, TX_OUTPUTS,
    };

    use crate::consensus::da_prune::BlockUndoLog;
    use crate::consensus::genesis::genesis_header;
    use crate::exact_state_hash::slot_leaf_hash;
    use crate::fri_state::SlotValue;
    use crate::segmented_state::SegmentColumns;
    use crate::state::{
        exact_segment_root_from_columns, SelectedHistoryLadderUpdate, StreamingSparseRoot,
    };
    use crate::storage::meta::{ConsensusMeta, FinalizedCheckpoint};
    use crate::storage::RecursiveProofJobTier;

    const LADDER_LOG: u32 = 18;
    const SEGMENT_LEN: usize = 1 << LOG_SEGMENT_SIZE;

    fn live_slot(amount: u64, creation_id: u64, owner: u128) -> SlotValue {
        SlotValue::from_parts(
            amount,
            creation_id,
            Block128(owner),
            Block128(owner.wrapping_add(1)),
        )
    }

    fn exact_root(log_slots: u32, slots: &[(u32, SlotValue)]) -> [u8; 32] {
        let mut sorted = slots.to_vec();
        sorted.sort_unstable_by_key(|(index, _)| *index);
        let mut stream = StreamingSparseRoot::new(log_slots).unwrap();
        for (index, slot) in sorted {
            stream.push_leaf(index, slot_leaf_hash(slot)).unwrap();
        }
        stream.finish().unwrap()
    }

    fn columns_for_segment(segment_id: u16, slots: &[(u32, SlotValue)]) -> SegmentColumns {
        let mut columns = SegmentColumns::new_zero(SEGMENT_LEN);
        let base = u32::from(segment_id) << LOG_SEGMENT_SIZE;
        for &(global_index, slot) in slots {
            if global_index >> LOG_SEGMENT_SIZE != u32::from(segment_id) {
                continue;
            }
            let local = (global_index - base) as usize;
            columns.values[local] = slot.value;
            columns.owners_hi[local] = slot.owner_hi;
            columns.owners_lo[local] = slot.owner_lo;
        }
        columns
    }

    fn metadata(header: &BlockHeader, work: u8) -> ConsensusMeta {
        let hash = block_id(header);
        ConsensusMeta {
            tip_height: header.height,
            tip_hash: hash,
            cumulative_chainwork: [work; 32],
            finalized: FinalizedCheckpoint {
                height: header.height,
                hash,
            },
        }
    }

    fn selected_terminal_bytes(height: u64, block_hash: [u8; 32]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&1u16.to_le_bytes());
        bytes.extend_from_slice(&height.to_le_bytes());
        bytes.extend_from_slice(&block_hash);
        bytes.push(0);
        bytes.extend_from_slice(&8u16.to_le_bytes());
        bytes
    }

    struct LadderFixture {
        h0: BlockHeader,
        h1: BlockHeader,
        h1_hash: [u8; 32],
        h2: BlockHeader,
        h2_hash: [u8; 32],
        /// Segment 0, minted at height zero and spent at height two.
        slot_a: (u32, SlotValue),
        /// Segment 1, minted at height one.
        slot_b: (u32, SlotValue),
    }

    /// Three-boundary chain at production segment geometry (log 18, four
    /// segments): height one mints into segment 1 and height two empties
    /// segment 0. All headers carry real exact roots.
    fn commit_ladder_chain(store: &MdbxStore) -> LadderFixture {
        let slot_a = (1u32, live_slot(11, 1, 0x11));
        let slot_b = ((1u32 << LOG_SEGMENT_SIZE) | 2, live_slot(22, 2, 0x22));

        let mut h0 = genesis_header();
        h0.log_slots = LADDER_LOG;
        h0.active_slot_count = 1;
        h0.alloc_counter = 1;
        h0.state_root = exact_root(LADDER_LOG, &[slot_a]);
        let h0_hash = block_id(&h0);
        let columns0 = columns_for_segment(0, &[slot_a]);
        store
            .commit_block(
                &h0,
                &h0_hash,
                &BlockUndoLog::empty(0, LADDER_LOG),
                &[(0, LOG_SEGMENT_SIZE as u8, Some(&columns0))],
                &[],
                &[],
                None,
                None,
                &metadata(&h0, 1),
                true,
            )
            .unwrap();

        let mut h1 = h0;
        h1.height = 1;
        h1.prev_block_hash = h0_hash;
        h1.timestamp = h1.timestamp.saturating_add(1);
        h1.nonce = 0xA1;
        h1.active_slot_count = 2;
        h1.alloc_counter = 2;
        h1.state_root = exact_root(LADDER_LOG, &[slot_a, slot_b]);
        let h1_hash = block_id(&h1);
        let columns1 = columns_for_segment(1, &[slot_a, slot_b]);
        let undo1 = BlockUndoLog {
            block_height: 1,
            log_slots_before: LADDER_LOG,
            active_slot_count_before: 1,
            alloc_counter_before: 1,
            slot_changes: vec![(slot_b.0, SlotValue::EMPTY)],
            tx_hashes: vec![],
        };
        store
            .commit_block(
                &h1,
                &h1_hash,
                &undo1,
                &[(1, LOG_SEGMENT_SIZE as u8, Some(&columns1))],
                &[],
                &[],
                None,
                None,
                &metadata(&h1, 2),
                false,
            )
            .unwrap();

        let mut h2 = h1;
        h2.height = 2;
        h2.prev_block_hash = h1_hash;
        h2.timestamp = h2.timestamp.saturating_add(1);
        h2.nonce = 0xA2;
        h2.active_slot_count = 1;
        h2.state_root = exact_root(LADDER_LOG, &[slot_b]);
        let h2_hash = block_id(&h2);
        let undo2 = BlockUndoLog {
            block_height: 2,
            log_slots_before: LADDER_LOG,
            active_slot_count_before: 2,
            alloc_counter_before: 2,
            slot_changes: vec![(slot_a.0, slot_a.1)],
            tx_hashes: vec![],
        };
        store
            .commit_block(
                &h2,
                &h2_hash,
                &undo2,
                &[(0, LOG_SEGMENT_SIZE as u8, None)],
                &[],
                &[],
                None,
                None,
                &metadata(&h2, 3),
                false,
            )
            .unwrap();

        LadderFixture {
            h0,
            h1,
            h1_hash,
            h2,
            h2_hash,
            slot_a,
            slot_b,
        }
    }

    /// Self-contained cursor snapshot at height one.
    fn ladder_update_one(fixture: &LadderFixture) -> SelectedHistoryLadderUpdate {
        let columns0 = columns_for_segment(0, &[fixture.slot_a]);
        let columns1 = columns_for_segment(1, &[fixture.slot_b]);
        SelectedHistoryLadderUpdate {
            log_slots: LADDER_LOG,
            active_slot_count: 2,
            alloc_counter: 2,
            state_root: fixture.h1.state_root,
            segment_summaries: vec![
                (
                    0,
                    1,
                    exact_segment_root_from_columns(LOG_SEGMENT_SIZE, &columns0),
                ),
                (
                    1,
                    1,
                    exact_segment_root_from_columns(LOG_SEGMENT_SIZE, &columns1),
                ),
            ],
            dirty_segments: vec![(0, Some(columns0)), (1, Some(columns1))],
        }
    }

    /// Layered advance to height two: segment 0 became empty.
    fn ladder_update_two(fixture: &LadderFixture) -> SelectedHistoryLadderUpdate {
        let columns1 = columns_for_segment(1, &[fixture.slot_b]);
        SelectedHistoryLadderUpdate {
            log_slots: LADDER_LOG,
            active_slot_count: 1,
            alloc_counter: 2,
            state_root: fixture.h2.state_root,
            segment_summaries: vec![(
                1,
                1,
                exact_segment_root_from_columns(LOG_SEGMENT_SIZE, &columns1),
            )],
            dirty_segments: vec![(0, None)],
        }
    }

    fn promote(
        store: &MdbxStore,
        height: u64,
        block_hash: [u8; 32],
        update: &SelectedHistoryLadderUpdate,
    ) {
        store
            .enqueue_recursive_proof_job(height, block_hash, RecursiveProofJobTier::B8)
            .unwrap();
        let claimed = store.claim_next_recursive_proof_job().unwrap().unwrap();
        assert_eq!((claimed.height, claimed.block_hash), (height, block_hash));
        store
            .complete_recursive_proof_job_and_promote_selected_history(
                height,
                block_hash,
                &selected_terminal_bytes(height, block_hash),
                update,
            )
            .unwrap();
    }

    /// Empty extension blocks that only advance the canonical tip.
    fn extend_chain_with_empty_blocks(
        store: &MdbxStore,
        from: BlockHeader,
        last_height: u64,
    ) -> BlockHeader {
        let mut parent = from;
        for height in (parent.height + 1)..=last_height {
            let mut header = parent;
            header.height = height;
            header.prev_block_hash = block_id(&parent);
            header.timestamp = parent.timestamp.saturating_add(1);
            header.nonce = u128::from(height) + 0xE0000;
            let hash = block_id(&header);
            let undo = BlockUndoLog {
                block_height: height,
                log_slots_before: header.log_slots,
                active_slot_count_before: header.active_slot_count,
                alloc_counter_before: header.alloc_counter,
                slot_changes: vec![],
                tx_hashes: vec![],
            };
            store
                .commit_block(
                    &header,
                    &hash,
                    &undo,
                    &[],
                    &[],
                    &[],
                    None,
                    None,
                    &metadata(&header, 4),
                    false,
                )
                .unwrap();
            parent = header;
        }
        parent
    }

    #[test]
    fn promoted_cursor_loads_parent_state_with_tip_arbitrarily_far_ahead() {
        let directory = tempfile::tempdir().unwrap();
        let store = MdbxStore::open(directory.path()).unwrap();
        let fixture = commit_ladder_chain(&store);
        promote(&store, 1, fixture.h1_hash, &ladder_update_one(&fixture));

        // Simulate a proof pipeline lagging far beyond the undo window: the
        // tip advances thirty blocks and the old rollback source is pruned.
        extend_chain_with_empty_blocks(&store, fixture.h2, 32);
        assert_eq!(store.get_chain_tip().unwrap().unwrap().0, 32);
        assert!(
            store.get_undo_log(2).unwrap().is_none(),
            "tip rollback must be impossible; only the ladder cursor remains"
        );

        let state =
            load_selected_history_ladder_parent_state(&store, &fixture.h1, &[0, 1]).unwrap();
        assert_eq!(state.cached_state_root(), fixture.h1.state_root);
        assert_eq!(state.active_slot_count, 2);
        assert_eq!(state.alloc_counter, 2);
        assert_eq!(state.state.slot(fixture.slot_a.0), fixture.slot_a.1);
        assert_eq!(state.state.slot(fixture.slot_b.0), fixture.slot_b.1);
        let resident: Vec<u16> = state.state.materialized_segment_ids().collect();
        assert_eq!(resident, vec![0, 1]);

        // Partial hydration keeps every unrequested live segment evicted and
        // fail-closed.
        let partial = load_selected_history_ladder_parent_state(&store, &fixture.h1, &[0]).unwrap();
        assert_eq!(partial.state.slot(fixture.slot_a.0), fixture.slot_a.1);
        assert!(partial.state.is_evicted(1));
        assert_eq!(partial.state.materialized_segment_ids().count(), 1);
    }

    #[test]
    fn tampered_ladder_segment_payload_fails_closed_at_load() {
        let directory = tempfile::tempdir().unwrap();
        let store = MdbxStore::open(directory.path()).unwrap();
        let fixture = commit_ladder_chain(&store);
        promote(&store, 1, fixture.h1_hash, &ladder_update_one(&fixture));

        let mut tampered = columns_for_segment(0, &[fixture.slot_a]);
        tampered.values[7] = Block128(999);
        store
            .put_raw_selected_history_ladder_segment_for_test(
                0,
                &crate::storage::serial::encode_segment(&tampered, LOG_SEGMENT_SIZE as u8),
            )
            .unwrap();
        assert!(matches!(
            load_selected_history_ladder_parent_state(&store, &fixture.h1, &[0]),
            Err(LadderStateError::Corrupt(
                "ladder segment does not match its compact exact summary"
            ))
        ));
        // Untouched segments remain loadable.
        assert!(load_selected_history_ladder_parent_state(&store, &fixture.h1, &[1]).is_ok());
    }

    #[test]
    fn layered_promotion_requires_exact_predecessor_boundary() {
        let directory = tempfile::tempdir().unwrap();
        let store = MdbxStore::open(directory.path()).unwrap();
        let fixture = commit_ladder_chain(&store);

        // A layered update without any durable cursor must fail closed and
        // must not advance coverage either (same transaction).
        store
            .enqueue_recursive_proof_job(1, fixture.h1_hash, RecursiveProofJobTier::B8)
            .unwrap();
        store.claim_next_recursive_proof_job().unwrap().unwrap();
        let mut layered = ladder_update_one(&fixture);
        layered.dirty_segments.remove(1);
        assert!(store
            .complete_recursive_proof_job_and_promote_selected_history(
                1,
                fixture.h1_hash,
                &selected_terminal_bytes(1, fixture.h1_hash),
                &layered,
            )
            .is_err());
        assert!(store.get_selected_history_coverage().unwrap().is_none());
        assert!(store.get_selected_history_ladder_meta().unwrap().is_none());

        store
            .complete_recursive_proof_job_and_promote_selected_history(
                1,
                fixture.h1_hash,
                &selected_terminal_bytes(1, fixture.h1_hash),
                &ladder_update_one(&fixture),
            )
            .unwrap();
        promote(&store, 2, fixture.h2_hash, &ladder_update_two(&fixture));

        let meta = store.get_selected_history_ladder_meta().unwrap().unwrap();
        assert_eq!((meta.height, meta.block_hash), (2, fixture.h2_hash));
        let state =
            load_selected_history_ladder_parent_state(&store, &fixture.h2, &[0, 1]).unwrap();
        assert_eq!(state.cached_state_root(), fixture.h2.state_root);
        assert_eq!(state.state.slot(fixture.slot_a.0), SlotValue::EMPTY);
        assert_eq!(state.state.slot(fixture.slot_b.0), fixture.slot_b.1);
    }

    #[test]
    fn reorg_rewinds_cursor_below_ancestor_and_preserves_it_at_or_below() {
        // Rewind: cursor at two, reorg ancestor one.
        let directory = tempfile::tempdir().unwrap();
        let store = MdbxStore::open(directory.path()).unwrap();
        let fixture = commit_ladder_chain(&store);
        promote(&store, 1, fixture.h1_hash, &ladder_update_one(&fixture));
        promote(&store, 2, fixture.h2_hash, &ladder_update_two(&fixture));
        store
            .commit_reorg(
                1,
                &fixture.h1,
                &fixture.h1_hash,
                &[],
                &[],
                &[],
                &[],
                &metadata(&fixture.h1, 2),
            )
            .unwrap();
        let meta = store.get_selected_history_ladder_meta().unwrap().unwrap();
        assert_eq!((meta.height, meta.block_hash), (1, fixture.h1_hash));
        let state =
            load_selected_history_ladder_parent_state(&store, &fixture.h1, &[0, 1]).unwrap();
        assert_eq!(state.cached_state_root(), fixture.h1.state_root);
        assert_eq!(
            state.state.slot(fixture.slot_a.0),
            fixture.slot_a.1,
            "the reorg rewind must restore the spent pre-image from undo",
        );

        // A second, deeper rewind walks the remaining undo step to genesis.
        let h0_hash = block_id(&fixture.h0);
        store
            .commit_reorg(
                0,
                &fixture.h0,
                &h0_hash,
                &[],
                &[],
                &[],
                &[],
                &metadata(&fixture.h0, 1),
            )
            .unwrap();
        let meta = store.get_selected_history_ladder_meta().unwrap().unwrap();
        assert_eq!((meta.height, meta.block_hash), (0, h0_hash));
        let state =
            load_selected_history_ladder_parent_state(&store, &fixture.h0, &[0, 1]).unwrap();
        assert_eq!(state.cached_state_root(), fixture.h0.state_root);
        assert_eq!(state.state.slot(fixture.slot_a.0), fixture.slot_a.1);
        assert_eq!(state.state.slot(fixture.slot_b.0), SlotValue::EMPTY);

        // Preserve: cursor at one is not above the ancestor.
        let directory = tempfile::tempdir().unwrap();
        let store = MdbxStore::open(directory.path()).unwrap();
        let fixture = commit_ladder_chain(&store);
        promote(&store, 1, fixture.h1_hash, &ladder_update_one(&fixture));
        store
            .commit_reorg(
                1,
                &fixture.h1,
                &fixture.h1_hash,
                &[],
                &[],
                &[],
                &[],
                &metadata(&fixture.h1, 2),
            )
            .unwrap();
        let meta = store.get_selected_history_ladder_meta().unwrap().unwrap();
        assert_eq!((meta.height, meta.block_hash), (1, fixture.h1_hash));
        assert!(load_selected_history_ladder_parent_state(&store, &fixture.h1, &[0, 1]).is_ok());
    }

    #[test]
    fn impossible_reorg_rewind_clears_cursor_instead_of_failing_the_reorg() {
        let directory = tempfile::tempdir().unwrap();
        let store = MdbxStore::open(directory.path()).unwrap();
        let fixture = commit_ladder_chain(&store);
        promote(&store, 1, fixture.h1_hash, &ladder_update_one(&fixture));
        promote(&store, 2, fixture.h2_hash, &ladder_update_two(&fixture));

        store.delete_undo_log_for_test(2).unwrap();
        store
            .commit_reorg(
                1,
                &fixture.h1,
                &fixture.h1_hash,
                &[],
                &[],
                &[],
                &[],
                &metadata(&fixture.h1, 2),
            )
            .unwrap();
        assert!(
            store.get_selected_history_ladder_meta().unwrap().is_none(),
            "a rewind without its undo source must clear the cursor, not keep a wrong one"
        );
    }

    #[test]
    fn restart_keeps_valid_cursor_and_clears_corrupt_or_non_canonical_meta() {
        // Valid cursor survives restart.
        let directory = tempfile::tempdir().unwrap();
        {
            let store = MdbxStore::open(directory.path()).unwrap();
            let fixture = commit_ladder_chain(&store);
            promote(&store, 1, fixture.h1_hash, &ladder_update_one(&fixture));
        }
        {
            let store = MdbxStore::open(directory.path()).unwrap();
            let meta = store.get_selected_history_ladder_meta().unwrap().unwrap();
            assert_eq!(meta.height, 1);
            // Corrupt meta bytes are cleared on the next open.
            store
                .put_raw_selected_history_ladder_meta_for_test(b"not-a-ladder-meta")
                .unwrap();
        }
        {
            let store = MdbxStore::open(directory.path()).unwrap();
            assert!(store.get_selected_history_ladder_meta().unwrap().is_none());
        }

        // A cursor whose block is no longer canonical is cleared on open.
        let directory = tempfile::tempdir().unwrap();
        {
            let store = MdbxStore::open(directory.path()).unwrap();
            let fixture = commit_ladder_chain(&store);
            promote(&store, 1, fixture.h1_hash, &ladder_update_one(&fixture));
            let mut replaced = fixture.h1;
            replaced.nonce ^= 1;
            let replaced_hash = block_id(&replaced);
            store.put_header_only(&replaced, &replaced_hash).unwrap();
        }
        {
            let store = MdbxStore::open(directory.path()).unwrap();
            assert!(store.get_selected_history_ladder_meta().unwrap().is_none());
        }
    }

    #[test]
    fn coinbase_only_frontier_comes_from_cursor_segments() {
        let directory = tempfile::tempdir().unwrap();
        let store = MdbxStore::open(directory.path()).unwrap();
        let fixture = commit_ladder_chain(&store);
        promote(&store, 1, fixture.h1_hash, &ladder_update_one(&fixture));

        // Coinbase-only blocks carry no detached exact-state proof; their
        // replay rebuilds the multiproof frontier from resident cursor
        // columns plus the compact upper tree.
        let state = load_selected_history_ladder_parent_state(&store, &fixture.h1, &[0]).unwrap();
        assert!(state.state.is_evicted(1));
        let reference = ChainState::from_sparse_utxos(
            LADDER_LOG as usize,
            &[fixture.slot_a, fixture.slot_b],
            2,
        )
        .unwrap();
        let touched = [fixture.slot_a.0, 9];
        let full = crate::sparse_merkle::build_multiproof(
            &reference.state.exact_sparse_cache().unwrap(),
            &touched,
            LADDER_LOG,
        )
        .unwrap();
        assert_eq!(
            state.exact_frontier_siblings(&touched, LADDER_LOG).unwrap(),
            full.siblings
        );
    }

    #[test]
    fn bootstrap_persists_empty_genesis_cursor() {
        let directory = tempfile::tempdir().unwrap();
        let store = MdbxStore::open(directory.path()).unwrap();
        let genesis = genesis_header();
        let genesis_hash = block_id(&genesis);
        store
            .commit_block(
                &genesis,
                &genesis_hash,
                &BlockUndoLog::empty(0, genesis.log_slots),
                &[],
                &[],
                &[],
                None,
                None,
                &metadata(&genesis, 1),
                false,
            )
            .unwrap();

        let state = load_selected_history_ladder_parent_state(&store, &genesis, &[]).unwrap();
        assert_eq!(state.cached_state_root(), genesis.state_root);
        let meta = store.get_selected_history_ladder_meta().unwrap().unwrap();
        assert_eq!((meta.height, meta.block_hash), (0, genesis_hash));
        assert!(meta.segment_summaries.is_empty());
    }

    #[test]
    fn bootstrap_seeds_cursor_from_recent_tip_state_inside_the_undo_window() {
        let directory = tempfile::tempdir().unwrap();
        let store = MdbxStore::open(directory.path()).unwrap();
        let fixture = commit_ladder_chain(&store);
        assert!(store.get_selected_history_ladder_meta().unwrap().is_none());

        // Parent one is a single undo step below tip two: the one-time seed
        // streams the durable tip state and rolls it back.
        let state =
            load_selected_history_ladder_parent_state(&store, &fixture.h1, &[0, 1]).unwrap();
        assert_eq!(state.cached_state_root(), fixture.h1.state_root);
        assert_eq!(state.state.slot(fixture.slot_a.0), fixture.slot_a.1);
        assert_eq!(state.state.slot(fixture.slot_b.0), fixture.slot_b.1);
        let meta = store.get_selected_history_ladder_meta().unwrap().unwrap();
        assert_eq!((meta.height, meta.block_hash), (1, fixture.h1_hash));
        assert_eq!(meta.segment_summaries.len(), 2);
    }

    #[test]
    fn bootstrap_outside_undo_window_without_retained_blocks_fails_closed() {
        let directory = tempfile::tempdir().unwrap();
        let store = MdbxStore::open(directory.path()).unwrap();
        let fixture = commit_ladder_chain(&store);
        extend_chain_with_empty_blocks(&store, fixture.h2, 32);

        // No cursor, tip 31 blocks ahead, and no retained block bodies: the
        // job is unprovable and the loader must say so instead of wedging in
        // a retry loop with a wrong state.
        assert!(matches!(
            load_selected_history_ladder_parent_state(&store, &fixture.h1, &[0]),
            Err(LadderStateError::Unrecoverable { target: 1, tip: 32 })
        ));
    }

    fn ladder_coinbase(height: u64, owner: Address) -> Transaction {
        let mut outputs = [TxOutput::dummy(); TX_OUTPUTS];
        outputs[0] = TxOutput {
            slot_index: u32::try_from(height).unwrap(),
            amount: 1,
            owner,
        };
        Transaction::new(TxBody {
            epoch_anchor: [height as u8; 32],
            fee: 0,
            input_owner: Address([0; 32]),
            inputs: [TxInput::dummy(); TX_INPUTS],
            outputs,
            validity_bitmap: output_bitmap_bit(0),
            is_coinbase: true,
        })
    }

    #[test]
    fn bootstrap_fast_forwards_natively_over_retained_blocks() {
        let directory = tempfile::tempdir().unwrap();
        let store = MdbxStore::open(directory.path()).unwrap();
        let owner = Address([0x77; 32]);

        // Real canonical coinbase chain with retained bodies; no coverage,
        // so nothing is ever pruned below it.
        let mut running = ChainState::with_log_slots(LADDER_LOG as usize);
        let mut genesis = genesis_header();
        genesis.log_slots = LADDER_LOG;
        genesis.state_root = running.cached_state_root();
        let genesis_hash = block_id(&genesis);
        store
            .commit_block(
                &genesis,
                &genesis_hash,
                &BlockUndoLog::empty(0, LADDER_LOG),
                &[],
                &[],
                &[],
                None,
                None,
                &metadata(&genesis, 1),
                false,
            )
            .unwrap();

        let mut headers = vec![genesis];
        let mut parent = genesis;
        for height in 1..=25u64 {
            let coinbase = ladder_coinbase(height, owner);
            crate::state::apply_tx_at(&mut running, &coinbase.body, height).unwrap();
            let mut header = parent;
            header.height = height;
            header.prev_block_hash = block_id(&parent);
            header.timestamp = parent.timestamp.saturating_add(1);
            header.nonce = u128::from(height) + 0xF0000;
            header.state_root = running.cached_state_root();
            header.active_slot_count = running.active_slot_count;
            header.alloc_counter = running.alloc_counter;
            let transactions = vec![coinbase];
            header.tx_root = crate::block::compute_tx_root(&transactions);
            let hash = block_id(&header);
            let block = Block {
                header,
                transactions,
            };
            let undo = BlockUndoLog {
                block_height: height,
                log_slots_before: LADDER_LOG,
                active_slot_count_before: parent.active_slot_count,
                alloc_counter_before: parent.alloc_counter,
                slot_changes: vec![(u32::try_from(height).unwrap(), SlotValue::EMPTY)],
                tx_hashes: vec![block.transactions[0].txid()],
            };
            let columns = running.state.segment_columns_for_persistence(0);
            store
                .commit_block(
                    &header,
                    &hash,
                    &undo,
                    &[(0, LOG_SEGMENT_SIZE as u8, Some(&columns))],
                    &[block.transactions[0].txid()],
                    &[],
                    Some(&block.to_bytes()),
                    None,
                    &metadata(&header, 2),
                    false,
                )
                .unwrap();
            headers.push(header);
            parent = header;
        }

        // Target five sits far outside the undo window at tip 25; every block
        // body up to it is retained, so the walk replays natively from the
        // empty genesis cursor and persists each boundary.
        let target = headers[5];
        assert!(store.get_selected_history_ladder_meta().unwrap().is_none());
        let state = load_selected_history_ladder_parent_state(&store, &target, &[0]).unwrap();
        assert_eq!(state.cached_state_root(), target.state_root);
        assert_eq!(state.active_slot_count, 5);
        assert_eq!(state.state.slot(3).amount(), 1);
        let meta = store.get_selected_history_ladder_meta().unwrap().unwrap();
        assert_eq!((meta.height, meta.block_hash), (5, block_id(&target)));

        // The persisted walk is crash-uniform: a later, farther target simply
        // resumes from the durable boundary.
        let farther = headers[7];
        let state = load_selected_history_ladder_parent_state(&store, &farther, &[0]).unwrap();
        assert_eq!(state.cached_state_root(), farther.state_root);
        assert_eq!(
            store
                .get_selected_history_ladder_meta()
                .unwrap()
                .unwrap()
                .height,
            7
        );
    }

    #[test]
    fn cursor_ahead_of_target_is_a_retryable_error_not_a_clear() {
        let directory = tempfile::tempdir().unwrap();
        let store = MdbxStore::open(directory.path()).unwrap();
        let fixture = commit_ladder_chain(&store);
        promote(&store, 1, fixture.h1_hash, &ladder_update_one(&fixture));
        promote(&store, 2, fixture.h2_hash, &ladder_update_two(&fixture));

        assert!(matches!(
            load_selected_history_ladder_parent_state(&store, &fixture.h1, &[0]),
            Err(LadderStateError::CursorAheadOfTarget {
                cursor: 2,
                target: 1,
            })
        ));
        assert!(store.get_selected_history_ladder_meta().unwrap().is_some());
    }

    #[test]
    fn touched_segment_derivation_keeps_only_live_unique_segments() {
        let mut header = genesis_header();
        header.log_slots = 24;
        let block = Block {
            header,
            transactions: vec![
                touched_transaction((3 << 16) + 1, true, (7 << 16) + 2, true, false),
                // Dead fixed-width cells must not hydrate segment 200.
                touched_transaction((200 << 16) + 1, false, (3 << 16) + 9, true, false),
            ],
        };
        assert_eq!(derive_touched_segment_ids(&block, 24).unwrap(), vec![3, 7]);

        let mut monolithic = block;
        monolithic.header.log_slots = 16;
        monolithic.transactions = vec![touched_transaction(9, true, 65_000, true, false)];
        assert_eq!(
            derive_touched_segment_ids(&monolithic, 16).unwrap(),
            vec![0]
        );
    }

    #[test]
    fn touched_segment_derivation_rejects_live_out_of_domain_slot() {
        let mut header = genesis_header();
        header.log_slots = 16;
        let block = Block {
            header,
            transactions: vec![touched_transaction(1 << 16, true, 0, false, false)],
        };
        assert_eq!(
            derive_touched_segment_ids(&block, 16),
            Err(TouchedSegmentError::InputSlotOutOfParentDomain(1 << 16))
        );
    }

    #[test]
    fn expansion_upper_outputs_remain_virtual_and_are_not_hydrated() {
        let mut header = genesis_header();
        header.log_slots = 25;
        let upper_slot = (1 << 24) + 7;
        let block = Block {
            header,
            transactions: vec![touched_transaction(
                (9 << 16) + 1,
                true,
                upper_slot,
                true,
                false,
            )],
        };
        assert_eq!(
            derive_touched_segment_ids(&block, 24).unwrap(),
            vec![9],
            "the deterministic empty upper half has no parent MDBX payload"
        );
        assert!(matches!(
            derive_touched_segment_ids(&block, 23),
            Err(TouchedSegmentError::InvalidLogSlotsTransition { .. })
        ));
    }

    fn touched_transaction(
        input_slot: u32,
        input_live: bool,
        output_slot: u32,
        output_live: bool,
        coinbase: bool,
    ) -> Transaction {
        let mut inputs = [TxInput::dummy(); TX_INPUTS];
        inputs[0] = TxInput {
            slot_index: input_slot,
            amount: 1,
            creation_id: 1,
        };
        let mut outputs = [TxOutput::dummy(); TX_OUTPUTS];
        outputs[0] = TxOutput {
            slot_index: output_slot,
            amount: 1,
            owner: Address([7u8; 32]),
        };
        let validity_bitmap =
            u16::from(input_live) | if output_live { output_bitmap_bit(0) } else { 0 };
        Transaction::new(TxBody {
            epoch_anchor: [1u8; 32],
            fee: 0,
            input_owner: Address([2u8; 32]),
            inputs,
            outputs,
            validity_bitmap,
            is_coinbase: coinbase,
        })
    }
}
