// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Native-side state transition for the transparent UTXO chain.
//!
//! The chain state is a segmented raw UTXO slot vector plus exact commitments.
//! A spend zeroes the slot at `input.slot_index` and the block-level exact
//! transition records that slot in `ReuseGuard`; a mint writes to the
//! wallet-chosen `output.slot_index` only if the verifier-derived prefix state
//! says it is empty and not active-guarded.
//! The block header state root is the exact composite root:
//! `H(log_slots, UTXO_MerkleRoot, ReuseGuardRoot)`.
//!
//! This is the canonical native state engine used by miners, validators,
//! storage and tests.
//! User-transaction block acceptance uses the exact authenticated transition
//! proof, then commits the sealed verifier result atomically.

use std::collections::HashSet;

use noid_poseidon2b::primitives::Digest;
use noid_tx::{TxBody, TxInput, TxOutput};

use crate::exact_state_hash::{
    composite_state_root, slot_leaf_hash_checked, zero_slot_roots, ExactStateHashError, StateHash,
};
use crate::fri_state::{SlotValue, StateError, STATE_LOG_SLOTS};
use crate::reuse_guard::{GuardBucket, ReuseGuard};
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
    /// Bounded ABA replay guard over recently spent slot indices.
    pub reuse_guard: ReuseGuard,
    /// Number of live (non-empty) slots. Grows on activation, shrinks
    /// on deactivation. This is the consensus-significant occupancy
    /// signal for the `log_slots` expansion trigger (see
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
    ExactHash(ExactStateHashError),
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
            reuse_guard: ReuseGuard::new_empty(),
            active_slot_count: 0,
            alloc_counter: 0,
        }
    }

    /// Build chain state from fully loaded raw segment columns.
    pub fn from_loaded_parts(
        state: SegmentedFriState,
        active_slot_count: u64,
        alloc_counter: u64,
        reuse_guard: ReuseGuard,
    ) -> Result<Self, ExactStateReadError> {
        let mut out = Self {
            utxo_root: zero_slot_roots(state.log_slots())[state.log_slots()],
            state,
            reuse_guard,
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
            leaves.push((
                index,
                slot_leaf_hash_checked(slot).map_err(SparseUtxoBuildError::ExactHash)?,
            ));
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

    #[inline]
    pub fn state_root(&mut self) -> Digest {
        if let Ok(root) = self.state.exact_utxo_root() {
            self.utxo_root = root;
        }
        composite_state_root(
            self.state.log_slots() as u32,
            self.utxo_root,
            self.reuse_guard.root(),
        )
    }

    #[inline]
    pub fn cached_state_root(&self) -> Digest {
        composite_state_root(
            self.state.log_slots() as u32,
            self.utxo_root,
            self.reuse_guard.root(),
        )
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
            snapshot.state.expand();
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

    #[allow(clippy::too_many_arguments)]
    pub fn apply_verified_exact_transition(
        &mut self,
        log_slots: u32,
        child_utxo_root: StateHash,
        child_guard_root: StateHash,
        slot_updates: &[(u32, SlotValue)],
        guard_bucket_update: Option<(usize, GuardBucket)>,
        active_slot_count: u64,
        alloc_counter: u64,
    ) -> Result<Digest, ApplyExactTransitionError> {
        let mut snapshot = self.clone();
        while log_slots as usize > snapshot.state.log_slots() {
            snapshot.state.expand();
        }
        if log_slots as usize != snapshot.state.log_slots() {
            return Err(ApplyExactTransitionError::HeaderLogSlotsMismatch);
        }
        snapshot
            .state
            .apply_delta_unrooted(slot_updates)
            .map_err(|_| ApplyExactTransitionError::SlotOutOfRange)?;
        snapshot.utxo_root = child_utxo_root;
        if let Some((bucket_index, bucket)) = guard_bucket_update {
            snapshot
                .reuse_guard
                .apply_verified_bucket_update(bucket_index, bucket, child_guard_root)
                .map_err(ApplyExactTransitionError::ReuseGuard)?;
        } else if snapshot.reuse_guard.root() != child_guard_root {
            return Err(ApplyExactTransitionError::ReuseGuardRootMismatch);
        }
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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApplyExactTransitionError {
    SlotOutOfRange,
    HeaderLogSlotsMismatch,
    ReuseGuardRootMismatch,
    ExactStateRead(ExactStateReadError),
    ReuseGuard(crate::reuse_guard::ReuseGuardError),
}

/// Apply a `TxBody` to `state` in place, returning the post-transition
/// root on success. Dummy slots (`valid = false`) are skipped entirely.
///
/// State root validation happens at block level via the exact authenticated
/// transition proof — this function purely executes the UTXO state transition
/// without checking anchors.
///
/// On `Err`, `state` is left untouched.
pub fn apply_tx(state: &mut ChainState, body: &TxBody) -> Result<StateTransition, ApplyError> {
    apply_tx_checked_deferred_root(state, body)?;
    let new_state_root = state.state_root();
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
        .inputs
        .iter()
        .filter(|input| input.valid)
        .map(|input| input.slot_index)
        .collect();

    // Wallet-chosen output slots: reject duplicates *within this tx*
    // up-front so we don't silently overwrite our own earlier write.
    let mut seen: HashSet<u32> = HashSet::new();
    for output in &body.outputs {
        if !output.valid {
            continue;
        }
        if !seen.insert(output.slot_index) {
            return Err(ApplyError::DuplicateOutputSlot);
        }
        if input_slots.contains(&output.slot_index) {
            return Err(ApplyError::InputOutputSlotOverlap);
        }
    }

    for input in &body.inputs {
        if !input.valid {
            continue;
        }
        spend_input(&mut snapshot, input)?;
    }

    for output in &body.outputs {
        if !output.valid {
            continue;
        }
        insert_output(&mut snapshot, output)?;
    }

    *state = snapshot;
    Ok(())
}

fn spend_input(state: &mut ChainState, input: &TxInput) -> Result<(), ApplyError> {
    if (input.slot_index as u64) >= state.state.num_slots() {
        return Err(ApplyError::SlotOutOfRange);
    }
    let expected =
        SlotValue::with_owner_fields(input.value, input.creation_id, input.owner.as_fields());
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
    let slot = SlotValue::with_owner_fields(out.value, creation_id, out.owner.as_fields());
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
    use noid_poseidon2b::primitives::{Address, SpendSecret};
    use noid_tx::TxInput;

    const TEST_LOG_SLOTS: usize = 6; // 64 slots — cheap FRI

    fn fresh() -> ChainState {
        ChainState::with_log_slots(TEST_LOG_SLOTS)
    }

    fn mk_output_at(slot: u32, seed: u8) -> TxOutput {
        TxOutput {
            slot_index: slot,
            value: (seed as u64) * 100,
            owner: Address([seed; 32]),
            valid: true,
        }
    }

    fn mk_output(seed: u8) -> TxOutput {
        // Default helper: pick slot = seed so each test output lands
        // somewhere unique in the fresh state.
        mk_output_at(seed as u32, seed)
    }

    fn mk_input_for(slot_index: u32, out: &TxOutput) -> TxInput {
        TxInput {
            slot_index,
            value: out.value,
            creation_id: 1,
            owner: out.owner,
            spend_secret: SpendSecret([0u8; 32]),
            valid: true,
        }
    }

    fn body_with(fee: u128, inputs: Vec<TxInput>, outputs: Vec<TxOutput>) -> TxBody {
        TxBody {
            shape: noid_tx::TxShape::Standard4x8,
            epoch_anchor: [0u8; 32],
            fee,
            inputs,
            outputs,
            is_coinbase: false,
        }
    }

    /// The output's slot_index is wallet-chosen and bound into the
    /// body hash. This helper is a trivial accessor kept so tests
    /// read naturally.
    fn find_slot(_state: &ChainState, out: &TxOutput) -> u32 {
        out.slot_index
    }

    #[test]
    fn fresh_state_accepts_mint_only_body() {
        let mut state = fresh();
        let body = body_with(0, vec![], vec![mk_output(1), mk_output(2)]);
        let out = apply_tx(&mut state, &body).expect("apply");
        assert_eq!(out.new_state_root, state.state_root());
        assert_eq!(state.active_slot_count, 2);
        assert_eq!(state.alloc_counter, 2);
        assert_eq!(state.state.slot(1).creation_id(), 1);
        assert_eq!(state.state.slot(2).creation_id(), 2);
    }

    #[test]
    fn spend_known_utxo_then_double_spend_rejects() {
        let mut state = fresh();
        let out = mk_output(7);
        apply_tx(&mut state, &body_with(0, vec![], vec![out])).unwrap();
        let slot = find_slot(&state, &out);

        let input = mk_input_for(slot, &out);
        apply_tx(&mut state, &body_with(0, vec![input.clone()], vec![])).expect("first spend");

        assert_eq!(
            apply_tx(&mut state, &body_with(0, vec![input], vec![])),
            Err(ApplyError::UnknownOrSpentInput)
        );
    }

    #[test]
    fn dummy_slots_ignored() {
        let mut state = fresh();
        let valid_out = mk_output(1);
        let body = body_with(
            0,
            vec![TxInput::dummy()],
            vec![valid_out, TxOutput::dummy()],
        );
        apply_tx(&mut state, &body).expect("apply");
        assert_eq!(state.active_slot_count, 1);
    }

    #[test]
    fn post_root_flows_into_next_tx() {
        let mut state = fresh();
        let body1 = body_with(0, vec![], vec![mk_output(1)]);
        let st1 = apply_tx(&mut state, &body1).expect("apply 1");

        let body2 = body_with(0, vec![], vec![mk_output(2)]);
        let st2 = apply_tx(&mut state, &body2).expect("apply 2");
        assert_ne!(st1.new_state_root, st2.new_state_root);
    }

    #[test]
    fn err_leaves_state_untouched() {
        let mut state = fresh();
        apply_tx(&mut state, &body_with(0, vec![], vec![mk_output(1)])).unwrap();
        let snap_root = state.state_root();
        let snap_active = state.active_slot_count;
        let snap_counter = state.alloc_counter;

        // Try to mint into the same slot (already occupied) — must fail.
        let bad = body_with(0, vec![], vec![mk_output(1)]);
        assert!(apply_tx(&mut state, &bad).is_err());
        assert_eq!(state.state_root(), snap_root);
        assert_eq!(state.active_slot_count, snap_active);
        assert_eq!(state.alloc_counter, snap_counter);
    }

    #[test]
    fn spent_slot_can_be_reused_by_next_mint() {
        // The wallet is the slot chooser. After a spend frees a slot,
        // the wallet is free to reuse that exact slot in a later mint.
        let mut state = fresh();

        let a = mk_output_at(7, 1);
        apply_tx(&mut state, &body_with(0, vec![], vec![a])).unwrap();
        assert_eq!(state.active_slot_count, 1);

        apply_tx(&mut state, &body_with(0, vec![mk_input_for(7, &a)], vec![])).unwrap();
        assert_eq!(state.active_slot_count, 0);

        // Wallet reuses slot 7 — discovered via random probe.
        let c = mk_output_at(7, 3);
        apply_tx(&mut state, &body_with(0, vec![], vec![c])).unwrap();
        assert_eq!(state.active_slot_count, 1);
    }

    #[test]
    fn same_tx_cannot_reuse_input_slot_as_output() {
        let mut state = fresh();
        let a = mk_output_at(7, 1);
        apply_tx(&mut state, &body_with(0, vec![], vec![a])).unwrap();

        let replacement = mk_output_at(7, 2);
        assert_eq!(
            apply_tx(
                &mut state,
                &body_with(0, vec![mk_input_for(7, &a)], vec![replacement]),
            ),
            Err(ApplyError::InputOutputSlotOverlap),
        );
    }

    #[test]
    fn mint_to_occupied_slot_rejects() {
        let mut state = fresh();
        // First mint lands at slot 1.
        apply_tx(&mut state, &body_with(0, vec![], vec![mk_output_at(1, 1)])).unwrap();

        // Second mint targeting the same slot must reject.
        assert_eq!(
            apply_tx(&mut state, &body_with(0, vec![], vec![mk_output_at(1, 2)]),),
            Err(ApplyError::OutputSlotNotEmpty),
        );
    }

    #[test]
    fn mint_to_out_of_range_slot_rejects() {
        // Depth 1 state: valid slots in {0,1}. Targeting slot 2 must
        // reject with `SlotOutOfRange`.
        let mut state = ChainState::with_log_slots(1);
        assert_eq!(
            apply_tx(&mut state, &body_with(0, vec![], vec![mk_output_at(2, 3)]),),
            Err(ApplyError::SlotOutOfRange),
        );
    }

    #[test]
    fn duplicate_output_slot_in_tx_rejects() {
        let mut state = fresh();
        // Two outputs targeting the same slot within one tx must fail
        // before any write hits the state.
        let a = mk_output_at(5, 1);
        let b = mk_output_at(5, 2);
        assert_eq!(
            apply_tx(&mut state, &body_with(0, vec![], vec![a, b])),
            Err(ApplyError::DuplicateOutputSlot),
        );
        assert_eq!(state.active_slot_count, 0);
    }

    #[test]
    fn deterministic_across_validators() {
        // Two independent states apply the same tx sequence — post
        // roots and counters must match deterministically.
        let mut s1 = fresh();
        let mut s2 = fresh();

        for seed in 1u8..6 {
            let o = mk_output(seed);

            apply_tx(&mut s1, &body_with(0, vec![], vec![o])).unwrap();
            apply_tx(&mut s2, &body_with(0, vec![], vec![o])).unwrap();
        }

        assert_eq!(s1.state_root(), s2.state_root());
        assert_eq!(s1.alloc_counter, s2.alloc_counter);
    }

    #[test]
    fn input_with_wrong_owner_rejects() {
        let mut state = fresh();
        let real = mk_output(5);
        apply_tx(&mut state, &body_with(0, vec![], vec![real])).unwrap();

        let slot = find_slot(&state, &real);
        let mut bogus = mk_input_for(slot, &real);
        bogus.owner = Address([0xDE; 32]);
        assert_eq!(
            apply_tx(&mut state, &body_with(0, vec![bogus], vec![])),
            Err(ApplyError::UnknownOrSpentInput)
        );
    }

    #[test]
    fn stale_creation_id_rejects_even_when_amount_and_owner_match() {
        let mut state = fresh();
        let real = mk_output(5);
        apply_tx(&mut state, &body_with(0, vec![], vec![real])).unwrap();

        let mut stale = mk_input_for(real.slot_index, &real);
        stale.creation_id = 0;
        assert_eq!(
            apply_tx(&mut state, &body_with(0, vec![stale], vec![])),
            Err(ApplyError::UnknownOrSpentInput)
        );
        assert_eq!(state.state.slot(real.slot_index).creation_id(), 1);
    }

    #[test]
    fn allocation_counter_overflow_is_atomic() {
        let mut state = fresh();
        state.alloc_counter = u64::MAX;
        let before = state.state_root();

        assert_eq!(
            apply_tx(&mut state, &body_with(0, vec![], vec![mk_output(1)])),
            Err(ApplyError::AllocCounterOverflow)
        );
        assert_eq!(state.state_root(), before);
        assert_eq!(state.active_slot_count, 0);
        assert_eq!(state.alloc_counter, u64::MAX);
    }

    #[test]
    fn sparse_constructor_rejects_creation_id_above_trusted_counter() {
        let owner = Address([0x44; 32]);
        let slot = SlotValue::with_owner_fields(100, 2, owner.as_fields());
        assert!(matches!(
            ChainState::from_sparse_utxos(TEST_LOG_SLOTS, &[(7, slot)], 1),
            Err(SparseUtxoBuildError::CreationIdExceedsAllocCounter {
                slot_index: 7,
                creation_id: 2,
                alloc_counter: 1,
            })
        ));
    }
}
