// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Native-side state transition for the transparent UTXO chain.
//!
//! The chain state is a segmented raw UTXO slot vector plus exact commitments.
//! A spend zeroes the slot at `input.slot_index`; a mint writes to the
//! wallet-chosen `output.slot_index` only if the verifier-derived prefix state
//! says it is empty. Every mint receives a fresh monotone `creation_id`, so a
//! stale spend cannot consume a later UTXO that reuses the same slot index.
//! The block header state root is the exact sparse-Merkle UTXO root directly.
//!
//! This is the canonical native state engine used by miners, validators,
//! storage and tests.
//! User-transaction block acceptance uses the exact authenticated transition
//! proof, then commits the sealed verifier result atomically.

use std::collections::{BTreeMap, HashSet};

use noid_poseidon2b::primitives::Digest;
use noid_tx::TxBody;

use crate::exact_state_hash::{slot_leaf_hash, state_node_hash, zero_slot_roots, StateHash};
use crate::fri_state::{SlotValue, StateError, LOG_SEGMENT_SIZE, STATE_LOG_SLOTS};
use crate::segmented_state::{
    ExactStateReadError, SegmentColumns, SegmentedFriState, StateResizeError,
};
use crate::sparse_merkle::{frontier_sibling_positions, SparseMerkleError};

/// Chain-level mutable state.
///
/// The wallet picks each output's `slot_index` and binds it into the
/// body hash. The chain only *verifies* that the chosen slot is
/// currently empty and that the outputs of a single tx don't collide.
/// `alloc_counter` assigns the globally monotone `creation_id` packed into
/// every newly minted UTXO. It is also the seed for splitmix64-based wallet
/// slot hints and is therefore consensus-significant on both paths.
#[derive(Debug, Clone)]
pub struct ChainState {
    /// Segmented raw UTXO state (2^16 slots per segment).
    pub state: SegmentedFriState,
    /// Exact sparse Merkle root over the UTXO slot vector.
    pub utxo_root: StateHash,
    /// Number of live (non-empty) slots. Grows on activation, shrinks
    /// on deactivation. This is the consensus-significant occupancy
    /// signal for the `log_slots` expansion trigger.
    pub active_slot_count: u64,
    /// Monotone counter incremented on each successful allocation. The next
    /// live output stores `creation_id = alloc_counter + 1`; the updated value
    /// also seeds deterministic wallet slot hints.
    pub alloc_counter: u64,
    /// Compact exact-root hierarchy: one 32-byte root per 2^16-slot segment
    /// plus its upper binary tree.  Raw columns remain an MDBX-backed cache;
    /// exact root updates therefore need only the segments touched by a block.
    exact_roots: ExactSegmentRootCache,
}

/// O(depth)-memory builder for a sparse Merkle root from sorted non-default
/// leaves.  Gaps are emitted as maximal aligned canonical-zero subtrees, so no
/// live-leaf vector or all-node cache is materialized.
pub(crate) struct StreamingSparseRoot {
    depth: u32,
    position: u64,
    zero_roots: Vec<StateHash>,
    stack: Vec<(u32, StateHash)>,
}

impl StreamingSparseRoot {
    pub(crate) fn new(depth: u32) -> Result<Self, ApplyExactTransitionError> {
        let _ = 1u64
            .checked_shl(depth)
            .ok_or(ApplyExactTransitionError::HeaderLogSlotsMismatch)?;
        Ok(Self {
            depth,
            position: 0,
            zero_roots: zero_slot_roots(depth as usize),
            stack: Vec::with_capacity(depth as usize + 1),
        })
    }

    fn append_block(&mut self, mut level: u32, mut hash: StateHash) {
        while self
            .stack
            .last()
            .is_some_and(|(pending_level, _)| *pending_level == level)
        {
            let (_, left) = self.stack.pop().expect("level checked above");
            hash = state_node_hash(left, hash);
            level += 1;
        }
        self.stack.push((level, hash));
    }

    fn fill_zero_gap(&mut self, end: u64) -> Result<(), ApplyExactTransitionError> {
        let limit = 1u64
            .checked_shl(self.depth)
            .ok_or(ApplyExactTransitionError::HeaderLogSlotsMismatch)?;
        if end < self.position || end > limit {
            return Err(ApplyExactTransitionError::SlotOutOfRange);
        }
        while self.position < end {
            let remaining = end - self.position;
            let by_remaining = 63 - remaining.leading_zeros();
            let by_alignment = if self.position == 0 {
                self.depth
            } else {
                self.position.trailing_zeros().min(self.depth)
            };
            let level = by_remaining.min(by_alignment);
            self.append_block(level, self.zero_roots[level as usize]);
            self.position += 1u64 << level;
        }
        Ok(())
    }

    pub(crate) fn push_leaf(
        &mut self,
        index: u32,
        hash: StateHash,
    ) -> Result<(), ApplyExactTransitionError> {
        let index = u64::from(index);
        self.fill_zero_gap(index)?;
        self.append_block(0, hash);
        self.position = index + 1;
        Ok(())
    }

    pub(crate) fn finish(mut self) -> Result<StateHash, ApplyExactTransitionError> {
        let limit = 1u64
            .checked_shl(self.depth)
            .ok_or(ApplyExactTransitionError::HeaderLogSlotsMismatch)?;
        self.fill_zero_gap(limit)?;
        match self.stack.as_slice() {
            [(level, root)] if *level == self.depth => Ok(*root),
            _ => Err(ApplyExactTransitionError::HeaderLogSlotsMismatch),
        }
    }
}

/// Compact two-level exact-state root cache.
///
/// At mainnet depth 24 this is 256 segment roots plus 255 upper nodes (under
/// 17 KiB), independent of the number of live UTXOs.  It deliberately stores
/// no slot leaves and no full Merkle paths.
#[derive(Debug, Clone)]
struct ExactSegmentRootCache {
    log_slots: usize,
    effective_log_seg: usize,
    segment_roots: Vec<StateHash>,
    tree: Vec<StateHash>,
}

impl ExactSegmentRootCache {
    fn empty(log_slots: usize) -> Self {
        let effective_log_seg = log_slots.min(crate::fri_state::LOG_SEGMENT_SIZE);
        Self::empty_with_segment_log(log_slots, effective_log_seg)
    }

    fn empty_with_segment_log(log_slots: usize, effective_log_seg: usize) -> Self {
        let segment_count = 1usize << (log_slots - effective_log_seg);
        let zero_segment = zero_slot_roots(effective_log_seg)[effective_log_seg];
        let segment_roots = vec![zero_segment; segment_count];
        let tree = Self::build_tree(&segment_roots);
        Self {
            log_slots,
            effective_log_seg,
            segment_roots,
            tree,
        }
    }

    fn build_tree(segment_roots: &[StateHash]) -> Vec<StateHash> {
        let count = segment_roots.len();
        let mut tree = vec![[0u8; 32]; 2 * count];
        for (index, root) in segment_roots.iter().copied().enumerate() {
            tree[count + index] = root;
        }
        for index in (1..count).rev() {
            tree[index] = state_node_hash(tree[2 * index], tree[2 * index + 1]);
        }
        tree
    }

    #[inline]
    fn root(&self) -> StateHash {
        if self.segment_roots.len() == 1 {
            self.segment_roots[0]
        } else {
            self.tree[1]
        }
    }

    fn set_segment_root(&mut self, segment_id: u16, root: StateHash) {
        let index = segment_id as usize;
        self.segment_roots[index] = root;
        if self.segment_roots.len() == 1 {
            return;
        }
        let count = self.segment_roots.len();
        let mut node = count + index;
        self.tree[node] = root;
        while node > 1 {
            node /= 2;
            self.tree[node] = state_node_hash(self.tree[2 * node], self.tree[2 * node + 1]);
        }
    }

    fn segment_node_hash(&self, level: u32, node_index: u64) -> Option<StateHash> {
        let count = self.segment_roots.len();
        let upper_depth = count.ilog2();
        if level > upper_depth || node_index >= ((count as u64) >> level) {
            return None;
        }
        if level == 0 {
            return self.segment_roots.get(node_index as usize).copied();
        }
        let base = count >> level;
        self.tree.get(base + node_index as usize).copied()
    }

    fn expand_one(&mut self) {
        let old_log_slots = self.log_slots;
        let old_root = self.root();
        self.log_slots += 1;
        if self.log_slots <= crate::fri_state::LOG_SEGMENT_SIZE {
            self.effective_log_seg = self.log_slots;
            let empty_right = zero_slot_roots(old_log_slots)[old_log_slots];
            self.segment_roots[0] = state_node_hash(old_root, empty_right);
            self.tree = Self::build_tree(&self.segment_roots);
            return;
        }

        let old_count = self.segment_roots.len();
        let zero_segment = zero_slot_roots(self.effective_log_seg)[self.effective_log_seg];
        self.segment_roots.resize(old_count * 2, zero_segment);
        self.tree = Self::build_tree(&self.segment_roots);
        debug_assert_eq!(
            self.root(),
            state_node_hash(old_root, zero_slot_roots(old_log_slots)[old_log_slots])
        );
    }

    fn shrink_to(&mut self, target: usize) {
        while self.log_slots > target {
            if self.log_slots <= crate::fri_state::LOG_SEGMENT_SIZE {
                self.log_slots -= 1;
                self.effective_log_seg = self.log_slots;
                // The resident segment is recomputed immediately after the raw
                // state shrink; use the canonical empty root as a placeholder.
                self.segment_roots = vec![zero_slot_roots(self.log_slots)[self.log_slots]];
                self.tree = Self::build_tree(&self.segment_roots);
            } else {
                self.log_slots -= 1;
                self.segment_roots.truncate(self.segment_roots.len() / 2);
                self.tree = Self::build_tree(&self.segment_roots);
            }
        }
    }
}

/// Recombine per-segment exact roots into the chain-level exact state root.
///
/// Absent segments contribute the canonical zero-segment root. Returns `None`
/// when an entry lies outside the `log_slots` segment domain.
pub(crate) fn exact_state_root_from_segment_summaries(
    log_slots: usize,
    exact_segment_roots: &[(u16, StateHash)],
) -> Option<StateHash> {
    if log_slots == 0 || log_slots > 64 {
        return None;
    }
    let mut cache = ExactSegmentRootCache::empty(log_slots);
    for &(segment_id, root) in exact_segment_roots {
        if segment_id as usize >= cache.segment_roots.len() {
            return None;
        }
        cache.set_segment_root(segment_id, root);
    }
    Some(cache.root())
}

/// One state boundary of the selected-history forward ladder cursor.
///
/// `segment_summaries` carries `(segment_id, live_count, exact_segment_root)`
/// for every live segment, strictly ascending. `dirty_segments` carries the
/// raw post-block columns of every block-touched segment in ascending order;
/// `None` deletes the durable record of a segment that became empty.
#[derive(Debug)]
pub struct SelectedHistoryLadderUpdate {
    pub log_slots: u32,
    pub active_slot_count: u64,
    pub alloc_counter: u64,
    pub state_root: StateHash,
    pub segment_summaries: Vec<(u16, u32, StateHash)>,
    pub dirty_segments: Vec<(u16, Option<SegmentColumns>)>,
}

impl SelectedHistoryLadderUpdate {
    /// Update describing the canonical empty state at `log_slots`.
    pub fn empty(log_slots: u32) -> Self {
        Self {
            log_slots,
            active_slot_count: 0,
            alloc_counter: 0,
            state_root: zero_slot_roots(log_slots as usize)[log_slots as usize],
            segment_summaries: Vec::new(),
            dirty_segments: Vec::new(),
        }
    }
}

fn exact_segment_root_with_updates(
    effective_log_seg: usize,
    columns: Option<&SegmentColumns>,
    updates: &BTreeMap<u32, SlotValue>,
) -> StateHash {
    let segment_len = 1usize << effective_log_seg;
    let mut stream = StreamingSparseRoot::new(effective_log_seg as u32)
        .expect("effective segment depth is always a valid sparse depth");
    for local in 0..segment_len {
        let local = local as u32;
        let slot = updates.get(&local).copied().unwrap_or_else(|| {
            let Some(columns) = columns else {
                return SlotValue::EMPTY;
            };
            let local = local as usize;
            if local >= columns.values.len() {
                return SlotValue::EMPTY;
            }
            SlotValue {
                value: columns.values[local],
                owner_hi: columns.owners_hi[local],
                owner_lo: columns.owners_lo[local],
            }
        });
        if !slot.is_empty() {
            stream
                .push_leaf(local, slot_leaf_hash(slot))
                .expect("local indices are streamed in canonical order");
        }
    }
    stream
        .finish()
        .expect("complete segment stream has the declared depth")
}

pub(crate) fn exact_segment_root_from_columns(
    effective_log_seg: usize,
    columns: &SegmentColumns,
) -> StateHash {
    exact_segment_root_with_updates(effective_log_seg, Some(columns), &BTreeMap::new())
}

#[derive(Debug)]
pub enum ExactFrontierError {
    SparseMerkle(SparseMerkleError),
    ExactStateRead(ExactStateReadError),
    CompactRootMismatch,
}

impl core::fmt::Display for ExactFrontierError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::SparseMerkle(error) => write!(f, "{error}"),
            Self::ExactStateRead(error) => write!(f, "{error}"),
            Self::CompactRootMismatch => write!(f, "compact exact-root cache mismatch"),
        }
    }
}

impl std::error::Error for ExactFrontierError {}

impl From<SparseMerkleError> for ExactFrontierError {
    fn from(error: SparseMerkleError) -> Self {
        Self::SparseMerkle(error)
    }
}

fn exact_local_subtree_root(
    columns: Option<&SegmentColumns>,
    local_start: usize,
    level: u32,
) -> StateHash {
    let Some(columns) = columns else {
        return zero_slot_roots(level as usize)[level as usize];
    };
    let subtree_len = 1usize << level;
    let mut stream = StreamingSparseRoot::new(level)
        .expect("frontier level is bounded by the exact segment depth");
    for offset in 0..subtree_len {
        let local = local_start + offset;
        let slot = SlotValue {
            value: columns.values[local],
            owner_hi: columns.owners_hi[local],
            owner_lo: columns.owners_lo[local],
        };
        if !slot.is_empty() {
            stream
                .push_leaf(offset as u32, slot_leaf_hash(slot))
                .expect("subtree offsets are canonical and in range");
        }
    }
    stream
        .finish()
        .expect("complete local subtree stream has the declared depth")
}

#[derive(Debug)]
pub enum SparseUtxoBuildError {
    SlotOutOfRange,
    DuplicateSlot(u32),
    EmptySlot(u32),
    CreationIdExceedsAllocCounter {
        slot_index: u32,
        creation_id: u64,
        alloc_counter: u64,
    },
    State(StateError),
    SparseMerkle(SparseMerkleError),
}

impl ChainState {
    /// Fresh mainnet-sized state: `2^STATE_LOG_SLOTS` empty slots.
    pub fn new() -> Self {
        Self::with_log_slots(STATE_LOG_SLOTS)
    }

    /// Fresh state with a custom slot depth. Tests use a small depth to keep
    /// exact sparse-Merkle fixtures cheap.
    pub fn with_log_slots(log_slots: usize) -> Self {
        let utxo_root = zero_slot_roots(log_slots)[log_slots];
        Self {
            state: SegmentedFriState::new_empty(log_slots),
            utxo_root,
            active_slot_count: 0,
            alloc_counter: 0,
            exact_roots: ExactSegmentRootCache::empty(log_slots),
        }
    }

    /// Small-column multi-segment state used only by eviction/rollback tests.
    #[cfg(test)]
    pub(crate) fn with_segment_log_for_test(log_slots: usize, effective_log_seg: usize) -> Self {
        let utxo_root = zero_slot_roots(log_slots)[log_slots];
        Self {
            state: SegmentedFriState::new_empty_with_segment_log_for_test(
                log_slots,
                effective_log_seg,
            ),
            utxo_root,
            active_slot_count: 0,
            alloc_counter: 0,
            exact_roots: ExactSegmentRootCache::empty_with_segment_log(
                log_slots,
                effective_log_seg,
            ),
        }
    }

    /// Snapshot a durable chain boundary without cloning resident raw columns.
    pub fn durable_metadata_clone(&self) -> Option<Self> {
        Some(Self {
            state: self.state.durable_metadata_clone()?,
            utxo_root: self.utxo_root,
            active_slot_count: self.active_slot_count,
            alloc_counter: self.alloc_counter,
            exact_roots: self.exact_roots.clone(),
        })
    }

    /// Build chain state from fully loaded raw segment columns.
    pub fn from_loaded_parts(
        state: SegmentedFriState,
        active_slot_count: u64,
        alloc_counter: u64,
    ) -> Result<Self, ExactStateReadError> {
        let exact_roots = ExactSegmentRootCache::empty(state.log_slots());
        let mut out = Self {
            utxo_root: zero_slot_roots(state.log_slots())[state.log_slots()],
            state,
            active_slot_count,
            alloc_counter,
            exact_roots,
        };
        out.rebuild_exact_utxo_root_loaded()?;
        Ok(out)
    }

    /// Build a hot state from durable per-segment summaries without retaining
    /// any segment columns.  Startup computes and validates each summary while
    /// streaming one MDBX record at a time.
    pub(crate) fn from_evicted_parts(
        state: SegmentedFriState,
        active_slot_count: u64,
        alloc_counter: u64,
        expected_root: StateHash,
        exact_segment_roots: &[(u16, StateHash)],
    ) -> Result<Self, ExactStateReadError> {
        let mut exact_roots = ExactSegmentRootCache::empty(state.log_slots());
        for &(segment_id, root) in exact_segment_roots {
            if segment_id as usize >= exact_roots.segment_roots.len() {
                return Err(ExactStateReadError::SegmentRootMismatch { seg_id: segment_id });
            }
            exact_roots.set_segment_root(segment_id, root);
        }
        if exact_roots.root() != expected_root {
            return Err(ExactStateReadError::SegmentRootMismatch { seg_id: 0 });
        }
        Ok(Self {
            state,
            utxo_root: expected_root,
            active_slot_count,
            alloc_counter,
            exact_roots,
        })
    }

    /// Build state from a sparse set of live UTXO slots.
    ///
    /// This is a loaded-state constructor, not a transaction-application API.
    /// It writes the raw slots without computing the old segment cache root and
    /// computes the consensus exact UTXO root directly from the same leaves.
    /// Callers must provide only live, unique slots.
    pub fn from_sparse_utxos(
        log_slots: usize,
        slots: &[(u32, SlotValue)],
        alloc_counter: u64,
    ) -> Result<Self, SparseUtxoBuildError> {
        let mut seen = HashSet::with_capacity(slots.len());
        let max_slots = 1u64
            .checked_shl(log_slots as u32)
            .ok_or(SparseUtxoBuildError::SlotOutOfRange)?;
        for &(index, slot) in slots {
            if (index as u64) >= max_slots {
                return Err(SparseUtxoBuildError::SlotOutOfRange);
            }
            if !seen.insert(index) {
                return Err(SparseUtxoBuildError::DuplicateSlot(index));
            }
            if slot.is_empty() {
                return Err(SparseUtxoBuildError::EmptySlot(index));
            }
            if slot.creation_id() > alloc_counter {
                return Err(SparseUtxoBuildError::CreationIdExceedsAllocCounter {
                    slot_index: index,
                    creation_id: slot.creation_id(),
                    alloc_counter,
                });
            }
        }

        let mut state = Self::with_log_slots(log_slots);
        state
            .state
            .apply_delta_unrooted(slots)
            .map_err(SparseUtxoBuildError::State)?;
        state.active_slot_count = slots.len() as u64;
        // The highest historical creation ID may already have been spent, so
        // it cannot be reconstructed from the live sparse set. Callers must
        // supply the trusted header/checkpoint counter explicitly.
        state.alloc_counter = alloc_counter;
        state
            .rebuild_exact_utxo_root_loaded()
            .expect("fresh sparse constructor has every live segment resident");
        Ok(state)
    }

    /// Total number of slots in the state vector.
    pub fn num_slots(&self) -> u64 {
        self.state.num_slots()
    }

    /// Slots that can still be allocated without a `log_slots` bump.
    pub fn available_slots(&self) -> u64 {
        self.state.num_slots() - self.active_slot_count
    }

    /// Occupancy fraction used by the `log_slots` expansion trigger.
    pub fn occupancy(&self) -> f64 {
        (self.active_slot_count as f64) / (self.state.num_slots() as f64)
    }

    /// Grow the slot domain by one level while updating the exact root in O(1).
    ///
    /// The old tree becomes the left child and a depth-`old_log_slots` empty
    /// subtree becomes the right child. This remains valid when live segment
    /// columns are evicted and a full exact-root rebuild is unavailable.
    pub fn expand_one(&mut self) {
        let old_log_slots = self.state.log_slots();
        let empty_right = zero_slot_roots(old_log_slots)[old_log_slots];
        self.state.expand();
        self.exact_roots.expand_one();
        self.utxo_root = state_node_hash(self.utxo_root, empty_right);
        debug_assert_eq!(self.exact_roots.root(), self.utxo_root);
    }

    /// Expand one production slot-domain level for exact-only replay.
    ///
    /// The consensus exact cache/root is updated with the same O(1) rule as
    /// [`Self::expand_one`], while segmented FRI metadata is resized without
    /// hashing and remains explicitly unavailable to the caller.
    pub fn expand_exact_metadata_for_replay(&mut self) -> Result<(), StateResizeError> {
        let old_log_slots = self.state.log_slots();
        let empty_right = zero_slot_roots(old_log_slots)[old_log_slots];
        self.state.expand_exact_metadata_for_replay()?;
        self.exact_roots.expand_one();
        self.utxo_root = state_node_hash(self.utxo_root, empty_right);
        debug_assert_eq!(self.exact_roots.root(), self.utxo_root);
        Ok(())
    }

    #[inline]
    pub fn state_root(&mut self) -> Digest {
        self.try_state_root()
            .expect("dirty exact-state segments must be resident")
    }

    /// Refresh only exact subtree roots dirtied by local slot updates.
    /// Untouched live segments may remain evicted; their verified 32-byte
    /// summaries are sufficient for the upper tree.
    #[inline]
    pub fn try_state_root(&mut self) -> Result<Digest, ExactStateReadError> {
        while self.exact_roots.log_slots < self.state.log_slots() {
            self.exact_roots.expand_one();
        }
        if self.exact_roots.log_slots > self.state.log_slots() {
            self.exact_roots.shrink_to(self.state.log_slots());
        }
        let dirty: Vec<u16> = self.state.exact_dirty_segment_ids().collect();
        for segment_id in dirty {
            if self.state.is_evicted(segment_id) {
                return Err(ExactStateReadError::EvictedSegment { seg_id: segment_id });
            }
            let root = exact_segment_root_with_updates(
                self.state.effective_log_segment_size(),
                self.state.try_get_segment_columns(segment_id),
                &BTreeMap::new(),
            );
            self.exact_roots.set_segment_root(segment_id, root);
        }
        self.state.clear_exact_dirty();
        let root = self.exact_roots.root();
        self.utxo_root = root;
        Ok(root)
    }

    #[inline]
    pub fn cached_state_root(&self) -> Digest {
        self.utxo_root
    }

    pub fn rebuild_exact_utxo_root_loaded(&mut self) -> Result<StateHash, ExactStateReadError> {
        self.try_state_root()
    }

    /// Reinstall one durable segment after checking it against the compact
    /// exact-root summary retained in RAM.
    pub fn restore_evicted_segment(
        &mut self,
        segment_id: u16,
        columns: SegmentColumns,
    ) -> Result<(), ExactStateReadError> {
        let actual = exact_segment_root_with_updates(
            self.state.effective_log_segment_size(),
            Some(&columns),
            &BTreeMap::new(),
        );
        if self
            .exact_roots
            .segment_roots
            .get(segment_id as usize)
            .copied()
            != Some(actual)
        {
            return Err(ExactStateReadError::SegmentRootMismatch { seg_id: segment_id });
        }
        self.state.restore_evicted_segment(segment_id, columns);
        Ok(())
    }

    /// Read the canonical exact-state sibling frontier without building a
    /// global sparse-node map.  Local sibling subtrees are streamed from the
    /// already-hydrated touched segments; upper siblings come from the compact
    /// per-segment tree.
    pub fn exact_frontier_siblings(
        &self,
        touched_indices: &[u32],
        depth: u32,
    ) -> Result<Vec<StateHash>, ExactFrontierError> {
        if depth as usize != self.state.log_slots()
            || self.exact_roots.log_slots != self.state.log_slots()
        {
            return Err(ExactFrontierError::SparseMerkle(
                SparseMerkleError::CacheDepthMismatch {
                    cache_depth: self.exact_roots.log_slots as u32,
                    requested_depth: depth,
                },
            ));
        }
        if self.state.exact_dirty_segment_ids().next().is_some()
            || self.exact_roots.root() != self.utxo_root
        {
            return Err(ExactFrontierError::CompactRootMismatch);
        }

        let positions = frontier_sibling_positions(touched_indices, depth)?;
        let effective_log = self.state.effective_log_segment_size() as u32;
        let mut siblings = Vec::with_capacity(positions.len());
        for position in positions {
            let level = u32::from(position.level);
            if level >= effective_log {
                let root = self
                    .exact_roots
                    .segment_node_hash(level - effective_log, position.node_index)
                    .ok_or(ExactFrontierError::CompactRootMismatch)?;
                siblings.push(root);
                continue;
            }

            let nodes_per_segment_shift = effective_log - level;
            let segment_id = (position.node_index >> nodes_per_segment_shift) as u16;
            if self.state.is_evicted(segment_id) {
                return Err(ExactFrontierError::ExactStateRead(
                    ExactStateReadError::EvictedSegment { seg_id: segment_id },
                ));
            }
            let local_node_mask = (1u64 << nodes_per_segment_shift) - 1;
            let local_node = position.node_index & local_node_mask;
            let local_start = (local_node << level) as usize;
            siblings.push(exact_local_subtree_root(
                self.state.try_get_segment_columns(segment_id),
                local_start,
                level,
            ));
        }
        Ok(siblings)
    }

    pub fn exact_sparse_cache(
        &mut self,
    ) -> Result<crate::sparse_merkle::SparseMerkleCache, ExactStateReadError> {
        let cache = self.state.exact_sparse_cache()?;
        self.utxo_root = cache.root();
        Ok(cache)
    }

    pub fn exact_utxo_root_after_slot_updates(
        &self,
        log_slots: u32,
        slot_updates: &[(u32, SlotValue)],
    ) -> Result<StateHash, ApplyExactTransitionError> {
        let current_depth = self.state.log_slots() as u32;
        if log_slots < current_depth || log_slots > current_depth.saturating_add(1) {
            return Err(ApplyExactTransitionError::HeaderLogSlotsMismatch);
        }
        let target_slots = 1u64
            .checked_shl(log_slots)
            .ok_or(ApplyExactTransitionError::HeaderLogSlotsMismatch)?;
        let mut updates_by_segment: BTreeMap<u16, BTreeMap<u32, SlotValue>> = BTreeMap::new();
        let target_effective_log = (log_slots as usize).min(crate::fri_state::LOG_SEGMENT_SIZE);
        let local_mask = (1u32 << target_effective_log) - 1;
        for &(index, value) in slot_updates {
            if u64::from(index) >= target_slots {
                return Err(ApplyExactTransitionError::SlotOutOfRange);
            }
            updates_by_segment
                .entry((index >> target_effective_log) as u16)
                .or_default()
                .insert(index & local_mask, value);
        }

        // Refresh any pre-existing local dirt in a temporary compact cache so
        // this read-only derivation never mutates or clones raw state columns.
        let mut exact_roots = self.exact_roots.clone();
        for segment_id in self.state.exact_dirty_segment_ids() {
            if self.state.is_evicted(segment_id) {
                return Err(ApplyExactTransitionError::ExactStateRead(
                    ExactStateReadError::EvictedSegment { seg_id: segment_id },
                ));
            }
            let root = exact_segment_root_with_updates(
                self.state.effective_log_segment_size(),
                self.state.try_get_segment_columns(segment_id),
                &BTreeMap::new(),
            );
            exact_roots.set_segment_root(segment_id, root);
        }
        if exact_roots.root() != self.utxo_root {
            return Err(ApplyExactTransitionError::CachedRootMismatch);
        }

        if log_slots > current_depth {
            exact_roots.expand_one();
        }
        for (segment_id, local_updates) in updates_by_segment {
            let columns = if segment_id as usize >= self.state.num_segments() {
                None
            } else {
                if self.state.is_evicted(segment_id) {
                    return Err(ApplyExactTransitionError::ExactStateRead(
                        ExactStateReadError::EvictedSegment { seg_id: segment_id },
                    ));
                }
                self.state.try_get_segment_columns(segment_id)
            };
            let root =
                exact_segment_root_with_updates(target_effective_log, columns, &local_updates);
            exact_roots.set_segment_root(segment_id, root);
        }
        Ok(exact_roots.root())
    }

    pub fn apply_verified_exact_transition(
        &mut self,
        log_slots: u32,
        child_state_root: StateHash,
        slot_updates: &[(u32, SlotValue)],
        active_slot_count: u64,
        alloc_counter: u64,
    ) -> Result<Digest, ApplyExactTransitionError> {
        let current_log_slots = self.state.log_slots();
        if (log_slots as usize) < current_log_slots
            || (log_slots as usize) > current_log_slots.saturating_add(1)
        {
            return Err(ApplyExactTransitionError::HeaderLogSlotsMismatch);
        }
        let target_slots = 1u64
            .checked_shl(log_slots)
            .ok_or(ApplyExactTransitionError::HeaderLogSlotsMismatch)?;
        if slot_updates
            .iter()
            .any(|(slot_index, _)| u64::from(*slot_index) >= target_slots)
        {
            return Err(ApplyExactTransitionError::SlotOutOfRange);
        }
        let computed_child = self.exact_utxo_root_after_slot_updates(log_slots, slot_updates)?;
        if computed_child != child_state_root {
            return Err(ApplyExactTransitionError::CachedRootMismatch);
        }
        if log_slots as usize == current_log_slots + 1 {
            if current_log_slots >= LOG_SEGMENT_SIZE {
                self.expand_exact_metadata_for_replay()
                    .map_err(|_| ApplyExactTransitionError::HeaderLogSlotsMismatch)?;
            } else {
                self.expand_one();
            }
        }
        self.state
            .apply_delta_unrooted(slot_updates)
            .map_err(|_| ApplyExactTransitionError::SlotOutOfRange)?;
        let applied_root = self
            .try_state_root()
            .map_err(ApplyExactTransitionError::ExactStateRead)?;
        debug_assert_eq!(applied_root, computed_child);
        self.active_slot_count = active_slot_count;
        self.alloc_counter = alloc_counter;
        Ok(applied_root)
    }

    /// Extract this block's ladder cursor advance: the raw columns of every
    /// MDBX-dirty segment plus the complete compact per-segment summary.
    pub fn into_selected_history_ladder_update(
        self,
    ) -> Result<SelectedHistoryLadderUpdate, &'static str> {
        let mut dirty_segment_ids: Vec<u16> = self.state.dirty_segment_ids().collect();
        dirty_segment_ids.sort_unstable();
        self.into_selected_history_ladder_parts(dirty_segment_ids)
    }

    /// Extract a self-contained ladder cursor snapshot: raw columns for every
    /// live segment. Bootstrap seeding uses this; every live segment must be
    /// resident.
    pub fn into_selected_history_ladder_snapshot(
        self,
    ) -> Result<SelectedHistoryLadderUpdate, &'static str> {
        let live_segment_ids: Vec<u16> = (0..self.state.num_segments())
            .map(|index| index as u16)
            .filter(|&segment_id| self.state.segment_live_count(segment_id) != 0)
            .collect();
        self.into_selected_history_ladder_parts(live_segment_ids)
    }

    fn into_selected_history_ladder_parts(
        mut self,
        dirty_segment_ids: Vec<u16>,
    ) -> Result<SelectedHistoryLadderUpdate, &'static str> {
        if self.state.exact_dirty_segment_ids().next().is_some() {
            return Err("ladder update requires a freshly refreshed exact root");
        }
        if self.exact_roots.log_slots != self.state.log_slots()
            || self.exact_roots.root() != self.utxo_root
        {
            return Err("ladder update exact-root cache is stale");
        }
        let log_slots = u32::try_from(self.state.log_slots())
            .map_err(|_| "ladder update slot depth exceeds u32")?;

        let mut segment_summaries = Vec::new();
        let mut counted_live = 0u64;
        for index in 0..self.state.num_segments() {
            let segment_id = index as u16;
            let live_count = self.state.segment_live_count(segment_id);
            if live_count == 0 {
                continue;
            }
            counted_live = counted_live
                .checked_add(u64::from(live_count))
                .ok_or("ladder update live count overflows u64")?;
            segment_summaries.push((
                segment_id,
                live_count,
                self.exact_roots.segment_roots[index],
            ));
        }
        if counted_live != self.active_slot_count {
            return Err("ladder update live counts disagree with the active slot count");
        }

        let mut dirty_segments = Vec::with_capacity(dirty_segment_ids.len());
        for segment_id in dirty_segment_ids {
            if usize::from(segment_id) >= self.state.num_segments() {
                return Err("ladder update dirty segment lies outside the slot domain");
            }
            if self.state.segment_live_count(segment_id) == 0 {
                dirty_segments.push((segment_id, None));
                continue;
            }
            let columns = self
                .state
                .take_segment_columns(segment_id)
                .ok_or("ladder update dirty live segment has no resident columns")?;
            dirty_segments.push((segment_id, Some(*columns)));
        }

        Ok(SelectedHistoryLadderUpdate {
            log_slots,
            active_slot_count: self.active_slot_count,
            alloc_counter: self.alloc_counter,
            state_root: self.utxo_root,
            segment_summaries,
            dirty_segments,
        })
    }
}

impl Default for ChainState {
    fn default() -> Self {
        Self::new()
    }
}

/// Outcome of applying one transaction: the post-transition state root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StateTransition {
    pub new_state_root: Digest,
}

/// Error cases that invalidate a transaction at the state-transition
/// level (independent of balance / range, which the circuit checks).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplyError {
    /// `input.slot_index` or `output.slot_index` is outside the state
    /// vector.
    SlotOutOfRange,
    /// The slot's `(value, owner)` does not match the input's claimed
    /// fields — spending a non-existent or already-spent UTXO.
    UnknownOrSpentInput,
    /// The wallet-chosen output slot is already occupied in the
    /// prev-state (not `(0,0,0)`). The mint would clobber a live UTXO.
    OutputSlotNotEmpty,
    /// Two valid outputs in the same tx target the same `slot_index`,
    /// which would produce a double-write to one cell.
    DuplicateOutputSlot,
    /// A tx tries to spend and mint to the same slot in one body. Reuse is
    /// allowed after a slot is freed, but not inside the same transaction: the
    /// exact transition surface requires output slots to be empty before the tx.
    InputOutputSlotOverlap,
    /// A live spend was attempted while the occupancy counter was already
    /// zero. Consensus code must fail closed instead of panicking or wrapping.
    ActiveSlotCountUnderflow,
    /// Minting a live output would overflow the occupancy counter.
    ActiveSlotCountOverflow,
    /// No fresh non-zero creation ID can be assigned to the next live output.
    AllocCounterOverflow,
    /// The exact post-state root cannot be recomputed because part of the raw
    /// state is evicted. Acceptance must fail closed or preload the state.
    ExactStateUnavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApplyExactTransitionError {
    SlotOutOfRange,
    HeaderLogSlotsMismatch,
    ExactStateRead(ExactStateReadError),
    CachedRootMismatch,
}

/// Apply a `TxBody` to `state` in place, returning the post-transition
/// root on success. Bitmap-dead slots are skipped entirely.
///
/// State root validation happens at block level via the exact authenticated
/// transition proof — this function purely executes the UTXO state transition
/// without checking anchors.
///
/// On `Err`, `state` is left untouched.
pub fn apply_tx(state: &mut ChainState, body: &TxBody) -> Result<StateTransition, ApplyError> {
    let mut snapshot = state.clone();
    apply_tx_checked_deferred_root(&mut snapshot, body)?;
    let new_state_root = snapshot
        .try_state_root()
        .map_err(|_| ApplyError::ExactStateUnavailable)?;
    *state = snapshot;
    Ok(StateTransition { new_state_root })
}

/// Apply a `TxBody` to `state` while deferring the expensive Merkle root rebuild.
///
/// This preserves the same validation and atomicity semantics as [`apply_tx`],
/// but leaves dirty segment/tree roots to be flushed by a later `state_root()`
/// call. This is a consensus-internal construction helper, not a block
/// acceptance API; callers must compute/bind the final root before publishing or
/// accepting a header.
pub(crate) fn apply_tx_checked_deferred_root(
    state: &mut ChainState,
    body: &TxBody,
) -> Result<(), ApplyError> {
    let mut input_slots = HashSet::new();
    for (_, input) in body.live_inputs() {
        if !input_slots.insert(input.slot_index) {
            return Err(ApplyError::UnknownOrSpentInput);
        }
    }

    // Wallet-chosen output slots: reject duplicates *within this tx*
    // up-front so we don't silently overwrite our own earlier write.
    let mut seen: HashSet<u32> = HashSet::new();
    for (_, output) in body.live_outputs() {
        if !seen.insert(output.slot_index) {
            return Err(ApplyError::DuplicateOutputSlot);
        }
        if input_slots.contains(&output.slot_index) {
            return Err(ApplyError::InputOutputSlotOverlap);
        }
    }

    let effective_log = state.state.effective_log_segment_size();
    let mut deltas = Vec::with_capacity(input_slots.len() + seen.len());
    for (_, input) in body.live_inputs() {
        if (input.slot_index as u64) >= state.state.num_slots() {
            return Err(ApplyError::SlotOutOfRange);
        }
        let segment_id = (input.slot_index >> effective_log) as u16;
        if state.state.is_evicted(segment_id) {
            return Err(ApplyError::ExactStateUnavailable);
        }
        let expected = SlotValue::with_owner_fields(
            input.amount,
            input.creation_id,
            body.input_owner.as_fields(),
        );
        if state.state.slot(input.slot_index) != expected {
            return Err(ApplyError::UnknownOrSpentInput);
        }
        deltas.push((input.slot_index, SlotValue::EMPTY));
    }

    let input_count = body.live_input_count() as u64;
    let output_count = body.live_output_count() as u64;
    let active_after_spends = state
        .active_slot_count
        .checked_sub(input_count)
        .ok_or(ApplyError::ActiveSlotCountUnderflow)?;
    let active_after = active_after_spends
        .checked_add(output_count)
        .ok_or(ApplyError::ActiveSlotCountOverflow)?;
    let final_alloc_counter = state
        .alloc_counter
        .checked_add(output_count)
        .ok_or(ApplyError::AllocCounterOverflow)?;

    let mut creation_id = state.alloc_counter;
    for (_, output) in body.live_outputs() {
        if (output.slot_index as u64) >= state.state.num_slots() {
            return Err(ApplyError::SlotOutOfRange);
        }
        let segment_id = (output.slot_index >> effective_log) as u16;
        if state.state.is_evicted(segment_id) {
            return Err(ApplyError::ExactStateUnavailable);
        }
        if state.state.slot(output.slot_index) != SlotValue::EMPTY {
            return Err(ApplyError::OutputSlotNotEmpty);
        }
        creation_id = creation_id
            .checked_add(1)
            .ok_or(ApplyError::AllocCounterOverflow)?;
        deltas.push((
            output.slot_index,
            SlotValue::with_owner_fields(output.amount, creation_id, output.owner.as_fields()),
        ));
    }

    state
        .state
        .apply_delta_unrooted(&deltas)
        .expect("all transaction delta indices were preflighted");
    state.active_slot_count = active_after;
    state.alloc_counter = final_alloc_counter;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use noid_poseidon2b::primitives::Address;
    use noid_tx::{output_bitmap_bit, TxBody, TxInput, TxOutput, TX_INPUTS, TX_OUTPUTS};

    fn funded() -> ChainState {
        let mut state = ChainState::with_log_slots(8);
        state
            .state
            .set_slot(
                1,
                SlotValue::with_owner_fields(11, 7, Address([1u8; 32]).as_fields()),
            )
            .unwrap();
        state.active_slot_count = 1;
        state.alloc_counter = 7;
        state
    }

    fn body(owner: Address, input_slot: u32, output_slot: u32) -> TxBody {
        let mut inputs = [TxInput::dummy(); TX_INPUTS];
        inputs[0] = TxInput {
            slot_index: input_slot,
            amount: 11,
            creation_id: 7,
        };
        let mut outputs = [TxOutput::dummy(); TX_OUTPUTS];
        outputs[0] = TxOutput {
            slot_index: output_slot,
            amount: 10,
            owner: Address([2u8; 32]),
        };
        TxBody {
            epoch_anchor: [3u8; 32],
            fee: 1,
            input_owner: owner,
            inputs,
            outputs,
            validity_bitmap: 1 | output_bitmap_bit(0),
            is_coinbase: false,
        }
    }

    #[test]
    fn explicit_input_owner_matches_state_and_output_gets_new_incarnation() {
        let mut state = funded();
        apply_tx(&mut state, &body(Address([1u8; 32]), 1, 2)).unwrap();
        assert_eq!(state.state.slot(1), SlotValue::EMPTY);
        assert_eq!(state.state.slot(2).amount(), 10);
        assert_eq!(state.state.slot(2).creation_id(), 8);
        assert_eq!(state.active_slot_count, 1);
        assert_eq!(state.alloc_counter, 8);
    }

    #[test]
    fn wrong_owner_and_occupied_output_fail_atomically() {
        let mut state = funded();
        let root = state.state_root();
        assert_eq!(
            apply_tx(&mut state, &body(Address([9u8; 32]), 1, 2)),
            Err(ApplyError::UnknownOrSpentInput)
        );
        assert_eq!(state.state_root(), root);

        let overlap = body(Address([1u8; 32]), 1, 1);
        assert_eq!(
            apply_tx(&mut state, &overlap),
            Err(ApplyError::InputOutputSlotOverlap)
        );
    }

    #[test]
    fn duplicate_live_outputs_reject() {
        let mut body = body(Address([1u8; 32]), 1, 2);
        body.outputs[1] = body.outputs[0];
        body.validity_bitmap |= output_bitmap_bit(1);
        assert_eq!(
            apply_tx(&mut funded(), &body),
            Err(ApplyError::DuplicateOutputSlot)
        );
    }

    #[test]
    fn streaming_exact_update_root_matches_full_rebuild_without_state_clone() {
        let owner = Address([0x51; 32]);
        let slots = [
            (0, SlotValue::with_owner_fields(3, 1, owner.as_fields())),
            (1, SlotValue::with_owner_fields(5, 2, owner.as_fields())),
            (7, SlotValue::with_owner_fields(7, 3, owner.as_fields())),
            (31, SlotValue::with_owner_fields(11, 4, owner.as_fields())),
            (63, SlotValue::with_owner_fields(13, 5, owner.as_fields())),
        ];
        let state = ChainState::from_sparse_utxos(6, &slots, 5).unwrap();
        let updates = [
            (1, SlotValue::EMPTY),
            (8, SlotValue::with_owner_fields(17, 6, owner.as_fields())),
            (31, SlotValue::with_owner_fields(19, 7, owner.as_fields())),
        ];

        let mut reference = state.clone();
        reference.state.apply_delta_unrooted(&updates).unwrap();
        let expected = reference.rebuild_exact_utxo_root_loaded().unwrap();
        assert_eq!(
            state
                .exact_utxo_root_after_slot_updates(6, &updates)
                .unwrap(),
            expected
        );

        let expansion_update = [(100, SlotValue::with_owner_fields(23, 8, owner.as_fields()))];
        let mut expanded_reference = state.clone();
        expanded_reference.expand_one();
        expanded_reference
            .state
            .apply_delta_unrooted(&expansion_update)
            .unwrap();
        let expanded_expected = expanded_reference.rebuild_exact_utxo_root_loaded().unwrap();
        assert_eq!(
            state
                .exact_utxo_root_after_slot_updates(7, &expansion_update)
                .unwrap(),
            expanded_expected
        );
    }

    #[test]
    fn exact_only_production_expansion_matches_normal_exact_root_rule() {
        let log_slots = LOG_SEGMENT_SIZE;
        let old_root = zero_slot_roots(log_slots)[log_slots];
        let expected = state_node_hash(old_root, old_root);
        let mut state = ChainState {
            state: SegmentedFriState::new_exact_metadata_only_for_test(log_slots),
            utxo_root: old_root,
            active_slot_count: 0,
            alloc_counter: 0,
            exact_roots: ExactSegmentRootCache::empty(log_slots),
        };

        state.expand_exact_metadata_for_replay().unwrap();
        assert_eq!(state.state.log_slots(), log_slots + 1);
        assert_eq!(state.state.num_segments(), 2);
        assert_eq!(state.cached_state_root(), expected);
        assert_eq!(state.exact_roots.root(), expected);
        assert_eq!(state.state.materialized_segment_ids().count(), 0);
    }

    #[test]
    fn streaming_exact_update_rebinds_cached_parent_root() {
        let mut state = ChainState::from_sparse_utxos(
            4,
            &[(
                3,
                SlotValue::with_owner_fields(9, 1, Address([0x61; 32]).as_fields()),
            )],
            1,
        )
        .unwrap();
        state.utxo_root = [0xA5; 32];
        assert_eq!(
            state.exact_utxo_root_after_slot_updates(4, &[]),
            Err(ApplyExactTransitionError::CachedRootMismatch)
        );
    }

    #[test]
    fn compact_frontier_matches_full_cache_with_unrelated_segment_evicted() {
        let owner = Address([0x69; 32]);
        let mut state = ChainState::from_sparse_utxos(
            17,
            &[
                (3, SlotValue::with_owner_fields(9, 1, owner.as_fields())),
                (
                    (1 << 16) + 5,
                    SlotValue::with_owner_fields(11, 2, owner.as_fields()),
                ),
            ],
            2,
        )
        .unwrap();
        let touched = [3, 7];
        let full = crate::sparse_merkle::build_multiproof(
            &state.state.exact_sparse_cache().unwrap(),
            &touched,
            17,
        )
        .unwrap();

        state.state.evict_segment(1);
        assert_eq!(
            state.exact_frontier_siblings(&touched, 17).unwrap(),
            full.siblings
        );
        assert!(matches!(
            state.exact_frontier_siblings(&[(1 << 16) + 5], 17),
            Err(ExactFrontierError::ExactStateRead(
                ExactStateReadError::EvictedSegment { seg_id: 1 }
            ))
        ));
    }

    #[test]
    fn verified_transition_rejects_shape_before_in_place_mutation() {
        let mut state = ChainState::from_sparse_utxos(
            4,
            &[(
                3,
                SlotValue::with_owner_fields(9, 1, Address([0x71; 32]).as_fields()),
            )],
            1,
        )
        .unwrap();
        let root = state.cached_state_root();
        let slot = state.state.slot(3);
        assert_eq!(
            state.apply_verified_exact_transition(4, [0x11; 32], &[(16, SlotValue::EMPTY)], 0, 1,),
            Err(ApplyExactTransitionError::SlotOutOfRange)
        );
        assert_eq!(state.cached_state_root(), root);
        assert_eq!(state.state.slot(3), slot);
        assert_eq!(state.state.log_slots(), 4);
    }
}
