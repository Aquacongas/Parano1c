// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Native-side state transition for the transparent UTXO chain.
//!
//! The chain state is a single `FriState` — a FRI-committed vector of
//! `2^STATE_LOG_SLOTS` UTXO slots, each holding a `(value, owner)`
//! pair. A spend zeroes the slot at `input.slot_index` and returns
//! that index to the free-list. Stage E.1: a mint now writes to the
//! wallet-chosen `output.slot_index` and the chain verifies the
//! destination was empty (prev-state `(0,0,0)`) — the AIR (Stage E.2)
//! proves the same opening in-circuit so consensus is four-corner
//! bound. The state root is `FriState::root()`.
//!
//! This is *not* the in-circuit state transition — it is the native
//! reference the prover uses to compute the post-root that the STARK
//! then proves through §FriStateOpen.

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashSet};

use noid_core::Block128;
use noid_poseidon2b::primitives::Digest;
use noid_tx::{TxBody, TxInput, TxOutput};

use crate::fri_state::{FriState, SlotValue, STATE_LOG_SLOTS};

/// Chain-level mutable state.
///
/// Stage E.1: the wallet picks each output's `slot_index` and binds
/// it into the body hash. The chain is no longer an allocator — it
/// only *verifies* that the chosen slot is currently empty and that
/// the outputs of a single tx don't collide. `free_slots` and
/// `alloc_counter` are retained for occupancy tracking and as hints
/// the wallet can consult off-chain; they do not influence the
/// outcome of `apply_tx` beyond the free-list pop on a spend.
#[derive(Debug, Clone)]
pub struct ChainState {
    pub fri: FriState,
    /// Previously-spent indices available for reuse. Min-heap so the
    /// lowest free index is allocated first (deterministic).
    pub free_slots: BinaryHeap<Reverse<u32>>,
    /// Number of live (non-empty) slots. Grows on activation, shrinks
    /// on deactivation. This is the consensus-significant occupancy
    /// signal for the `log_slots` expansion trigger (see
    /// `GENERAL_DESIGN §15.3`).
    pub active_slot_count: u64,
    /// Monotone counter incremented on each successful allocation.
    /// Used only as a seed source for the pseudo-random fallback —
    /// does **not** affect the free-list path. Consensus-significant.
    pub alloc_counter: u64,
}

impl ChainState {
    /// Fresh mainnet-sized state: `2^STATE_LOG_SLOTS` empty slots.
    pub fn new() -> Self {
        Self::with_log_slots(STATE_LOG_SLOTS)
    }

    /// Fresh state with a custom slot depth. Tests use a small depth
    /// to keep the FRI commitment cheap.
    pub fn with_log_slots(log_slots: usize) -> Self {
        Self {
            fri: FriState::new_empty(log_slots),
            free_slots: BinaryHeap::new(),
            active_slot_count: 0,
            alloc_counter: 0,
        }
    }

    /// Slots that can still be allocated without a `log_slots` bump.
    /// Equals the number of empty slots in the FRI vector.
    pub fn available_slots(&self) -> u64 {
        self.fri.num_slots() - self.active_slot_count
    }

    /// Occupancy fraction used by the `log_slots` expansion trigger.
    /// Uses `active_slot_count`, the number of live UTXOs, so
    /// reclaimed slots correctly reduce occupancy.
    pub fn occupancy(&self) -> f64 {
        (self.active_slot_count as f64) / (self.fri.num_slots() as f64)
    }

    #[inline]
    pub fn state_root(&mut self) -> Digest {
        self.fri.root()
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
    /// `body.prev_state_root` does not match the current chain state.
    StaleState,
    /// `input.slot_index` or `output.slot_index` is outside the state
    /// vector.
    SlotOutOfRange,
    /// The slot's `(value, owner)` does not match the input's claimed
    /// fields — spending a non-existent or already-spent UTXO.
    UnknownOrSpentInput,
    /// Stage E.1: the wallet-chosen output slot is already occupied in
    /// the prev-state (not `(0,0,0)`). The mint would clobber a live
    /// UTXO.
    OutputSlotNotEmpty,
    /// Stage E.1: two valid outputs in the same tx target the same
    /// `slot_index`, which would produce a double-write to one cell.
    DuplicateOutputSlot,
}

/// Apply a `TxBody` to `state` in place, returning the post-transition
/// root on success. Dummy slots (`valid = false`) are skipped entirely.
///
/// On `Err`, `state` is left untouched.
pub fn apply_tx(state: &mut ChainState, body: &TxBody) -> Result<StateTransition, ApplyError> {
    if body.prev_state_root != state.state_root() {
        return Err(ApplyError::StaleState);
    }

    let mut snapshot = state.clone();

    for input in &body.inputs {
        if !input.valid {
            continue;
        }
        spend_input(&mut snapshot, input)?;
    }

    // Stage E.1: wallet-chosen output slots. Reject duplicates *within
    // this tx* up-front so we don't silently overwrite our own earlier
    // write. The AIR mirrors this as a per-output `is_mint ⇒
    // prev_state[slot] == (0,0,0)` opening plus a cross-output
    // uniqueness check (Stage E.2/E.3).
    let mut seen: HashSet<u32> = HashSet::new();
    for output in &body.outputs {
        if !output.valid {
            continue;
        }
        if !seen.insert(output.slot_index) {
            return Err(ApplyError::DuplicateOutputSlot);
        }
    }

    for output in &body.outputs {
        if !output.valid {
            continue;
        }
        insert_output(&mut snapshot, output)?;
    }

    let new_state_root = snapshot.state_root();
    *state = snapshot;
    Ok(StateTransition { new_state_root })
}

fn spend_input(state: &mut ChainState, input: &TxInput) -> Result<(), ApplyError> {
    if (input.slot_index as u64) >= state.fri.num_slots() {
        return Err(ApplyError::SlotOutOfRange);
    }
    let expected = SlotValue {
        value: Block128::from(input.value as u128),
        owner_hi: input.owner.as_fields()[0],
        owner_lo: input.owner.as_fields()[1],
    };
    let current = state.fri.slot(input.slot_index);
    if current != expected {
        return Err(ApplyError::UnknownOrSpentInput);
    }
    state
        .fri
        .set_slot(input.slot_index, SlotValue::EMPTY)
        .expect("bounds checked above");
    state.free_slots.push(Reverse(input.slot_index));
    state.active_slot_count = state
        .active_slot_count
        .checked_sub(1)
        .expect("spending a live slot cannot drop active count below zero");
    Ok(())
}

fn insert_output(state: &mut ChainState, out: &TxOutput) -> Result<(), ApplyError> {
    let idx = out.slot_index;
    if (idx as u64) >= state.fri.num_slots() {
        return Err(ApplyError::SlotOutOfRange);
    }
    // Stage E.1 four-corner invariant: the wallet-chosen destination
    // must be empty in prev-state. The STARK's §FriStateOpen proves
    // the same fact in-circuit (Stage E.2 `is_mint ⇒ prev == (0,0,0)`).
    if state.fri.slot(idx) != SlotValue::EMPTY {
        return Err(ApplyError::OutputSlotNotEmpty);
    }
    let slot = SlotValue {
        value: Block128::from(out.value as u128),
        owner_hi: out.owner.as_fields()[0],
        owner_lo: out.owner.as_fields()[1],
    };
    state.fri.set_slot(idx, slot).expect("bounds checked above");
    // Bookkeeping: if the wallet picked a previously-spent slot, drop
    // the matching entry from `free_slots` so it is not re-offered as
    // a hint. The heap is small so a linear drain-and-rebuild is fine.
    if state.free_slots.iter().any(|Reverse(s)| *s == idx) {
        let remaining: Vec<Reverse<u32>> = state
            .free_slots
            .drain()
            .filter(|Reverse(s)| *s != idx)
            .collect();
        state.free_slots = remaining.into_iter().collect();
    }
    state.active_slot_count += 1;
    state.alloc_counter += 1;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use noid_poseidon2b::primitives::{Address, AuthTag, SpendSecret};
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
            owner: out.owner,
            spend_secret: SpendSecret([0u8; 32]),
            auth_tag: AuthTag([0u8; 32]),
            valid: true,
        }
    }

    fn body_with(prev: Digest, fee: u128, inputs: Vec<TxInput>, outputs: Vec<TxOutput>) -> TxBody {
        TxBody {
            prev_state_root: prev,
            new_state_root: [0u8; 32],
            fee,
            inputs,
            outputs,
            is_coinbase: false,
        }
    }

    /// Stage E.1: the output's slot_index is now wallet-chosen and
    /// bound into the body hash. Callers know the target slot from
    /// the `TxOutput` itself — this helper is the trivial accessor
    /// kept so the existing tests read naturally.
    fn find_slot(_state: &ChainState, out: &TxOutput) -> u32 {
        out.slot_index
    }

    #[test]
    fn fresh_state_accepts_mint_only_body() {
        let mut state = fresh();
        let prev = state.state_root();
        let body = body_with(prev, 0, vec![], vec![mk_output(1), mk_output(2)]);
        let out = apply_tx(&mut state, &body).expect("apply");
        assert_eq!(out.new_state_root, state.state_root());
        assert!(state.free_slots.is_empty());
        assert_eq!(state.active_slot_count, 2);
        assert_eq!(state.alloc_counter, 2);
    }

    #[test]
    fn stale_prev_root_rejects() {
        let mut state = fresh();
        let body = body_with([0xFFu8; 32], 0, vec![], vec![mk_output(1)]);
        assert_eq!(apply_tx(&mut state, &body), Err(ApplyError::StaleState));
        assert!(state.free_slots.is_empty());
        assert_eq!(state.active_slot_count, 0);
        assert_eq!(state.alloc_counter, 0);
    }

    #[test]
    fn spend_known_utxo_then_double_spend_rejects() {
        let mut state = fresh();
        let prev = state.state_root();
        let out = mk_output(7);
        apply_tx(&mut state, &body_with(prev, 0, vec![], vec![out])).unwrap();
        let slot = find_slot(&state, &out);

        let prev = state.state_root();
        let input = mk_input_for(slot, &out);
        apply_tx(&mut state, &body_with(prev, 0, vec![input], vec![])).expect("first spend");

        let prev = state.state_root();
        assert_eq!(
            apply_tx(&mut state, &body_with(prev, 0, vec![input], vec![])),
            Err(ApplyError::UnknownOrSpentInput)
        );
    }

    #[test]
    fn dummy_slots_ignored() {
        let mut state = fresh();
        let prev = state.state_root();
        let valid_out = mk_output(1);
        let body = body_with(
            prev,
            0,
            vec![TxInput::dummy()],
            vec![valid_out, TxOutput::dummy()],
        );
        apply_tx(&mut state, &body).expect("apply");
        assert!(state.free_slots.is_empty());
        assert_eq!(state.active_slot_count, 1);
    }

    #[test]
    fn post_root_flows_into_next_tx() {
        let mut state = fresh();
        let prev = state.state_root();
        let body1 = body_with(prev, 0, vec![], vec![mk_output(1)]);
        let st1 = apply_tx(&mut state, &body1).expect("apply 1");

        let body2 = body_with(st1.new_state_root, 0, vec![], vec![mk_output(2)]);
        let st2 = apply_tx(&mut state, &body2).expect("apply 2");
        assert_ne!(st1.new_state_root, st2.new_state_root);
    }

    #[test]
    fn err_leaves_state_untouched() {
        let mut state = fresh();
        let prev = state.state_root();
        apply_tx(&mut state, &body_with(prev, 0, vec![], vec![mk_output(1)])).unwrap();
        let snap_root = state.state_root();
        let snap_active = state.active_slot_count;
        let snap_counter = state.alloc_counter;
        let snap_free = state.free_slots.len();

        let bad = body_with([0u8; 32], 0, vec![], vec![mk_output(2)]);
        assert!(apply_tx(&mut state, &bad).is_err());
        assert_eq!(state.state_root(), snap_root);
        assert_eq!(state.active_slot_count, snap_active);
        assert_eq!(state.alloc_counter, snap_counter);
        assert_eq!(state.free_slots.len(), snap_free);
    }

    #[test]
    fn spent_slot_can_be_reused_by_next_mint() {
        // Stage E.1: the wallet is the slot chooser. After a spend
        // frees a slot, the wallet is free to reuse that exact slot
        // in a later mint.
        let mut state = fresh();

        let prev = state.state_root();
        let a = mk_output_at(7, 1);
        apply_tx(&mut state, &body_with(prev, 0, vec![], vec![a])).unwrap();
        assert_eq!(state.active_slot_count, 1);

        let prev = state.state_root();
        apply_tx(&mut state, &body_with(prev, 0, vec![mk_input_for(7, &a)], vec![])).unwrap();
        assert_eq!(state.active_slot_count, 0);
        assert_eq!(state.free_slots.len(), 1);

        // Wallet reuses slot 7.
        let prev = state.state_root();
        let c = mk_output_at(7, 3);
        apply_tx(&mut state, &body_with(prev, 0, vec![], vec![c])).unwrap();
        assert_eq!(state.active_slot_count, 1);
        // Free-list entry for slot 7 consumed by the mint.
        assert!(state.free_slots.is_empty());
    }

    #[test]
    fn mint_to_occupied_slot_rejects() {
        let mut state = fresh();
        let prev = state.state_root();
        // First mint lands at slot 1.
        apply_tx(&mut state, &body_with(prev, 0, vec![], vec![mk_output_at(1, 1)])).unwrap();

        // Second mint targeting the same slot must reject.
        let prev = state.state_root();
        assert_eq!(
            apply_tx(
                &mut state,
                &body_with(prev, 0, vec![], vec![mk_output_at(1, 2)]),
            ),
            Err(ApplyError::OutputSlotNotEmpty),
        );
    }

    #[test]
    fn mint_to_out_of_range_slot_rejects() {
        // Depth 1 state: valid slots ∈ {0,1}. Targeting slot 2 must
        // reject with `SlotOutOfRange`.
        let mut state = ChainState::with_log_slots(1);
        let prev = state.state_root();
        assert_eq!(
            apply_tx(
                &mut state,
                &body_with(prev, 0, vec![], vec![mk_output_at(2, 3)]),
            ),
            Err(ApplyError::SlotOutOfRange),
        );
    }

    #[test]
    fn duplicate_output_slot_in_tx_rejects() {
        let mut state = fresh();
        let prev = state.state_root();
        // Two outputs targeting the same slot within one tx must fail
        // before any write hits the state.
        let a = mk_output_at(5, 1);
        let b = mk_output_at(5, 2);
        assert_eq!(
            apply_tx(&mut state, &body_with(prev, 0, vec![], vec![a, b])),
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

            let prev1 = s1.state_root();
            apply_tx(&mut s1, &body_with(prev1, 0, vec![], vec![o])).unwrap();

            let prev2 = s2.state_root();
            apply_tx(&mut s2, &body_with(prev2, 0, vec![], vec![o])).unwrap();
        }

        assert_eq!(s1.state_root(), s2.state_root());
        assert_eq!(s1.alloc_counter, s2.alloc_counter);
    }

    #[test]
    fn input_with_wrong_owner_rejects() {
        let mut state = fresh();
        let prev = state.state_root();
        let real = mk_output(5);
        apply_tx(&mut state, &body_with(prev, 0, vec![], vec![real])).unwrap();

        let slot = find_slot(&state, &real);
        let prev = state.state_root();
        let mut bogus = mk_input_for(slot, &real);
        bogus.owner = Address([0xDE; 32]);
        assert_eq!(
            apply_tx(&mut state, &body_with(prev, 0, vec![bogus], vec![])),
            Err(ApplyError::UnknownOrSpentInput)
        );
    }
}
