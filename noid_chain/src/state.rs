// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Native-side state transition for the transparent UTXO chain.
//!
//! The chain state is a single `FriState` — a FRI-committed vector of
//! `2^STATE_LOG_SLOTS` UTXO slots, each holding a `(value, owner)`
//! pair. A spend zeroes the slot at `input.slot_index`; a mint writes
//! `(value, owner)` into the slot at the monotonic `next_slot_index`
//! cursor. The state root is `FriState::root()`.
//!
//! This is *not* the in-circuit state transition — it is the native
//! reference the prover uses to compute the post-root that the STARK
//! then proves through §FriStateOpen.

use noid_core::Block128;
use noid_poseidon2b::primitives::Digest;
use noid_tx::{TxBody, TxInput, TxOutput};

use crate::fri_state::{FriState, SlotValue, STATE_LOG_SLOTS};

/// Chain-level mutable state.
#[derive(Debug, Clone)]
pub struct ChainState {
    pub fri: FriState,
    /// Monotonic cursor: next free slot for a new output.
    pub next_slot_index: u64,
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
            next_slot_index: 0,
        }
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
    /// `input.slot_index` is outside the state vector.
    SlotOutOfRange,
    /// The slot's `(value, owner)` does not match the input's claimed
    /// fields — spending a non-existent or already-spent UTXO.
    UnknownOrSpentInput,
    /// The state vector's append cursor has reached its capacity.
    StateFull,
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
    Ok(())
}

fn insert_output(state: &mut ChainState, out: &TxOutput) -> Result<(), ApplyError> {
    if state.next_slot_index >= state.fri.num_slots() {
        return Err(ApplyError::StateFull);
    }
    let slot = SlotValue {
        value: Block128::from(out.value as u128),
        owner_hi: out.owner.as_fields()[0],
        owner_lo: out.owner.as_fields()[1],
    };
    let idx = state.next_slot_index as u32;
    state.fri.set_slot(idx, slot).expect("bounds checked above");
    state.next_slot_index += 1;
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

    fn mk_output(seed: u8) -> TxOutput {
        TxOutput {
            value: (seed as u64) * 100,
            owner: Address([seed; 32]),
            valid: true,
        }
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
        }
    }

    #[test]
    fn fresh_state_accepts_mint_only_body() {
        let mut state = fresh();
        let prev = state.state_root();
        let body = body_with(prev, 0, vec![], vec![mk_output(1), mk_output(2)]);
        let out = apply_tx(&mut state, &body).expect("apply");
        assert_eq!(out.new_state_root, state.state_root());
        assert_eq!(state.next_slot_index, 2);
    }

    #[test]
    fn stale_prev_root_rejects() {
        let mut state = fresh();
        let body = body_with([0xFFu8; 32], 0, vec![], vec![mk_output(1)]);
        assert_eq!(apply_tx(&mut state, &body), Err(ApplyError::StaleState));
        assert_eq!(state.next_slot_index, 0);
    }

    #[test]
    fn spend_known_utxo_then_double_spend_rejects() {
        let mut state = fresh();
        let prev = state.state_root();
        let out = mk_output(7);
        apply_tx(&mut state, &body_with(prev, 0, vec![], vec![out])).unwrap();

        let prev = state.state_root();
        let input = mk_input_for(0, &out);
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
        assert_eq!(state.next_slot_index, 1);
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
        let snap_idx = state.next_slot_index;

        let bad = body_with([0u8; 32], 0, vec![], vec![mk_output(2)]);
        assert!(apply_tx(&mut state, &bad).is_err());
        assert_eq!(state.state_root(), snap_root);
        assert_eq!(state.next_slot_index, snap_idx);
    }

    #[test]
    fn input_with_wrong_owner_rejects() {
        let mut state = fresh();
        let prev = state.state_root();
        let real = mk_output(5);
        apply_tx(&mut state, &body_with(prev, 0, vec![], vec![real])).unwrap();

        let prev = state.state_root();
        let mut bogus = mk_input_for(0, &real);
        bogus.owner = Address([0xDE; 32]);
        assert_eq!(
            apply_tx(&mut state, &body_with(prev, 0, vec![bogus], vec![])),
            Err(ApplyError::UnknownOrSpentInput)
        );
    }
}
