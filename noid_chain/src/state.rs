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

use std::collections::HashSet;

use noid_poseidon2b::primitives::Digest;
use noid_tx::{TxBody, TxInput, TxOutput};

use crate::exact_state_hash::{slot_leaf_hash, state_node_hash, zero_slot_roots, StateHash};
use crate::fri_state::{SlotValue, StateError, STATE_LOG_SLOTS};
use crate::segmented_state::{ExactStateReadError, SegmentedFriState};
use crate::sparse_merkle::{SparseMerkleCache, SparseMerkleError};

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
        }
    }

    /// Build chain state from fully loaded raw segment columns.
    pub fn from_loaded_parts(
        state: SegmentedFriState,
        active_slot_count: u64,
        alloc_counter: u64,
    ) -> Result<Self, ExactStateReadError> {
        let mut out = Self {
            utxo_root: zero_slot_roots(state.log_slots())[state.log_slots()],
            state,
            active_slot_count,
            alloc_counter,
        };
        out.rebuild_exact_utxo_root_loaded()?;
        Ok(out)
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
        let mut leaves = Vec::with_capacity(slots.len());
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
            leaves.push((index, slot_leaf_hash(slot)));
        }

        let mut state = Self::with_log_slots(log_slots);
        state
            .state
            .apply_delta_unrooted(slots)
            .map_err(SparseUtxoBuildError::State)?;
        let cache = SparseMerkleCache::from_leaves(log_slots as u32, &leaves)
            .map_err(SparseUtxoBuildError::SparseMerkle)?;
        state.utxo_root = cache.root();
        state.active_slot_count = slots.len() as u64;
        // The highest historical creation ID may already have been spent, so
        // it cannot be reconstructed from the live sparse set. Callers must
        // supply the trusted header/checkpoint counter explicitly.
        state.alloc_counter = alloc_counter;
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
        self.utxo_root = state_node_hash(self.utxo_root, empty_right);
    }

    #[inline]
    pub fn state_root(&mut self) -> Digest {
        self.try_state_root()
            .expect("state_root requires every live segment to be loaded; use cached_state_root for a trusted persisted root")
    }

    /// Rebuild and return the exact root, failing if any required segment is
    /// evicted. Consensus mutation paths must use this method rather than
    /// silently treating the cached pre-state root as a recomputed post-root.
    #[inline]
    pub fn try_state_root(&mut self) -> Result<Digest, ExactStateReadError> {
        let root = self.state.exact_utxo_root()?;
        self.utxo_root = root;
        Ok(root)
    }

    #[inline]
    pub fn cached_state_root(&self) -> Digest {
        self.utxo_root
    }

    pub fn rebuild_exact_utxo_root_loaded(&mut self) -> Result<StateHash, ExactStateReadError> {
        let root = self.state.exact_utxo_root()?;
        self.utxo_root = root;
        Ok(root)
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
        let mut snapshot = self.clone();
        while log_slots as usize > snapshot.state.log_slots() {
            snapshot.expand_one();
        }
        if log_slots as usize != snapshot.state.log_slots() {
            return Err(ApplyExactTransitionError::HeaderLogSlotsMismatch);
        }
        snapshot
            .state
            .apply_delta_unrooted(slot_updates)
            .map_err(|_| ApplyExactTransitionError::SlotOutOfRange)?;
        snapshot
            .rebuild_exact_utxo_root_loaded()
            .map_err(ApplyExactTransitionError::ExactStateRead)
    }

    pub fn apply_verified_exact_transition(
        &mut self,
        log_slots: u32,
        child_state_root: StateHash,
        slot_updates: &[(u32, SlotValue)],
        active_slot_count: u64,
        alloc_counter: u64,
    ) -> Result<Digest, ApplyExactTransitionError> {
        let mut snapshot = self.clone();
        while log_slots as usize > snapshot.state.log_slots() {
            snapshot.expand_one();
        }
        if log_slots as usize != snapshot.state.log_slots() {
            return Err(ApplyExactTransitionError::HeaderLogSlotsMismatch);
        }
        snapshot
            .state
            .apply_delta_unrooted(slot_updates)
            .map_err(|_| ApplyExactTransitionError::SlotOutOfRange)?;
        snapshot.utxo_root = child_state_root;
        snapshot.active_slot_count = active_slot_count;
        snapshot.alloc_counter = alloc_counter;
        let root = snapshot.cached_state_root();
        *self = snapshot;
        Ok(root)
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
    let mut snapshot = state.clone();

    let input_slots: HashSet<u32> = body
        .live_inputs()
        .map(|(_, input)| input.slot_index)
        .collect();

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

    for (_, input) in body.live_inputs() {
        spend_input(&mut snapshot, input, &body.input_owner)?;
    }

    for (_, output) in body.live_outputs() {
        insert_output(&mut snapshot, output)?;
    }

    *state = snapshot;
    Ok(())
}

fn spend_input(
    state: &mut ChainState,
    input: &TxInput,
    input_owner: &noid_poseidon2b::primitives::Address,
) -> Result<(), ApplyError> {
    if (input.slot_index as u64) >= state.state.num_slots() {
        return Err(ApplyError::SlotOutOfRange);
    }
    let expected =
        SlotValue::with_owner_fields(input.amount, input.creation_id, input_owner.as_fields());
    let current = state.state.slot(input.slot_index);
    if current != expected {
        return Err(ApplyError::UnknownOrSpentInput);
    }
    state
        .state
        .apply_delta_unrooted(&[(input.slot_index, SlotValue::EMPTY)])
        .expect("bounds checked above");
    state.active_slot_count = state
        .active_slot_count
        .checked_sub(1)
        .ok_or(ApplyError::ActiveSlotCountUnderflow)?;
    Ok(())
}

fn insert_output(state: &mut ChainState, out: &TxOutput) -> Result<(), ApplyError> {
    let idx = out.slot_index;
    if (idx as u64) >= state.state.num_slots() {
        return Err(ApplyError::SlotOutOfRange);
    }
    // The wallet-chosen destination must be empty in the current state.
    if state.state.slot(idx) != SlotValue::EMPTY {
        return Err(ApplyError::OutputSlotNotEmpty);
    }
    let creation_id = state
        .alloc_counter
        .checked_add(1)
        .ok_or(ApplyError::AllocCounterOverflow)?;
    let active_slot_count = state
        .active_slot_count
        .checked_add(1)
        .ok_or(ApplyError::ActiveSlotCountOverflow)?;
    let slot = SlotValue::with_owner_fields(out.amount, creation_id, out.owner.as_fields());
    state
        .state
        .apply_delta_unrooted(&[(idx, slot)])
        .expect("bounds checked above");
    state.active_slot_count = active_slot_count;
    state.alloc_counter = creation_id;
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
}
