// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Native-side state transition. CRYPTO.md §6, §7.
//!
//! Drives the two chain-level sparse Merkle trees:
//!
//! - **State tree** (depth 32): coin commitments appended at a monotonic
//!   `next_leaf_index`. Depth is a hard cap (2^32 commitments); chain
//!   logic enforces reuse/compaction before that limit, which is out of
//!   scope here.
//! - **Nullifier tree** (depth 32): each spent nullifier inserted at the
//!   low 32 bits of its digest (little-endian). At chain scale this is a
//!   cryptographic hash keyed tree, so collisions are negligible; we
//!   still reject insertions at an already-populated slot so a
//!   pathological collision surfaces as an error rather than silently
//!   overwriting.
//!
//! This is *not* the in-circuit state transition — it is the native
//! reference the prover uses to compute the post-roots that the STARK
//! then proves.

use noid_poseidon2b::primitives::{Digest, Nullifier};
use noid_poseidon2b::sparse_merkle::{SparseMerkleTree, CHAIN_TREE_DEPTH};
use noid_tx::{TxBody, TxOutput};

/// Chain-level mutable state. Holds the two trees plus the next free
/// commitment index. Clone before `apply_tx` if you need a snapshot.
#[derive(Debug, Clone)]
pub struct ChainState {
    pub state_tree: SparseMerkleTree,
    pub nullifier_tree: SparseMerkleTree,
    pub next_leaf_index: u64,
}

impl ChainState {
    /// Fresh state with both trees empty.
    pub fn new() -> Self {
        Self {
            state_tree: SparseMerkleTree::new(CHAIN_TREE_DEPTH),
            nullifier_tree: SparseMerkleTree::new(CHAIN_TREE_DEPTH),
            next_leaf_index: 0,
        }
    }

    #[inline]
    pub fn state_root(&self) -> Digest {
        self.state_tree.root()
    }

    #[inline]
    pub fn nullifier_root(&self) -> Digest {
        self.nullifier_tree.root()
    }
}

impl Default for ChainState {
    fn default() -> Self {
        Self::new()
    }
}

/// Outcome of applying one transaction: the post-transition roots that
/// will appear as public inputs to the STARK (`new_state_root`,
/// `nullifier_root`) alongside `prev_state_root` and `tx_body_hash`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StateTransition {
    pub new_state_root: Digest,
    pub nullifier_root: Digest,
}

/// Error cases that invalidate a transaction at the state-transition
/// level (independent of balance / range, which the circuit checks).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplyError {
    /// The `prev_state_root` in the body does not match the current
    /// chain state. The transaction is stale or forged.
    StaleState,
    /// A nullifier in the body collides with a previously-spent one.
    /// Real double-spend, or an astronomically unlikely hash collision.
    DoubleSpend,
    /// The state tree's append cursor has reached `2^DEPTH`.
    StateTreeFull,
}

/// Apply a `TxBody` to `state` in place, returning the post-transition
/// roots on success. Dummy slots (`valid = false`) are skipped entirely
/// — they neither insert nullifiers nor consume output indices.
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
        insert_nullifier(&mut snapshot, &input.nullifier)?;
    }

    for output in &body.outputs {
        if !output.valid {
            continue;
        }
        insert_output(&mut snapshot, output)?;
    }

    let out = StateTransition {
        new_state_root: snapshot.state_root(),
        nullifier_root: snapshot.nullifier_root(),
    };
    *state = snapshot;
    Ok(out)
}

fn insert_nullifier(state: &mut ChainState, n: &Nullifier) -> Result<(), ApplyError> {
    let idx = nullifier_index(n);
    if state.nullifier_tree.get(idx) != empty_leaf_digest() {
        return Err(ApplyError::DoubleSpend);
    }
    state.nullifier_tree.insert(idx, n.0);
    Ok(())
}

fn insert_output(state: &mut ChainState, out: &TxOutput) -> Result<(), ApplyError> {
    if (state.next_leaf_index as u128) >= (1u128 << CHAIN_TREE_DEPTH) {
        return Err(ApplyError::StateTreeFull);
    }
    state
        .state_tree
        .insert(state.next_leaf_index, out.commitment.0);
    state.next_leaf_index += 1;
    Ok(())
}

/// Deterministic index assignment for a nullifier: low 32 bits of the
/// digest, interpreted little-endian. The nullifier is a Poseidon2b
/// output, so low bits are uniform — depth-32 is the natural width.
#[inline]
fn nullifier_index(n: &Nullifier) -> u64 {
    let bytes = n.as_bytes();
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as u64
}

/// Empty-leaf digest used by the sparse tree (`Z[0]`). We compare
/// against this when detecting double-spend.
#[inline]
fn empty_leaf_digest() -> Digest {
    noid_poseidon2b::sparse_merkle::zero_root(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use noid_core::{Block128, TowerField};
    use noid_poseidon2b::primitives::{
        derive_view_key, hash_commitment, hash_scan_tag, Address, MasterSecret, Nullifier,
    };
    use noid_tx::TxInput;

    fn mk_output(seed: u8, salt: u128) -> TxOutput {
        let addr = Address([seed; 32]);
        let c = hash_commitment(
            seed as u128,
            &addr,
            Block128::from(seed as u128),
            Block128::ZERO,
        );
        let vk = derive_view_key(&MasterSecret([seed; 32]));
        let salt = Block128::from(salt);
        TxOutput {
            commitment: c,
            salt,
            scan_tag: hash_scan_tag(&vk, salt),
            valid: true,
        }
    }

    fn mk_input(seed: u8) -> TxInput {
        let addr = Address([seed; 32]);
        let c = hash_commitment(
            seed as u128,
            &addr,
            Block128::from(seed as u128),
            Block128::ZERO,
        );
        // A deterministic fake nullifier — not cryptographically
        // sound, but fine for testing state transitions.
        let mut n = [0u8; 32];
        n[0] = seed;
        n[1] = 0xAB;
        TxInput {
            commitment: c,
            nullifier: Nullifier(n),
            valid: true,
        }
    }

    fn body_with(prev: Digest, fee: u128, inputs: Vec<TxInput>, outputs: Vec<TxOutput>) -> TxBody {
        TxBody {
            prev_state_root: prev,
            new_state_root: [0u8; 32],
            nullifier_root: [0u8; 32],
            fee,
            inputs,
            outputs,
        }
    }

    #[test]
    fn fresh_state_accepts_mint_only_body() {
        let mut state = ChainState::new();
        let prev = state.state_root();
        let body = body_with(prev, 0, vec![], vec![mk_output(1, 1), mk_output(2, 2)]);
        let out = apply_tx(&mut state, &body).expect("apply");
        assert_eq!(out.new_state_root, state.state_root());
        assert_eq!(out.nullifier_root, state.nullifier_root());
        assert_eq!(state.next_leaf_index, 2);
    }

    #[test]
    fn stale_prev_root_rejects() {
        let mut state = ChainState::new();
        let body = body_with([0xFFu8; 32], 0, vec![], vec![mk_output(1, 1)]);
        assert_eq!(apply_tx(&mut state, &body), Err(ApplyError::StaleState));
        // state untouched
        assert_eq!(state.next_leaf_index, 0);
    }

    #[test]
    fn double_spend_detected() {
        let mut state = ChainState::new();
        let prev = state.state_root();
        let i = mk_input(7);
        let body1 = body_with(prev, 0, vec![i], vec![]);
        apply_tx(&mut state, &body1).expect("first spend");

        let prev = state.state_root();
        let body2 = body_with(prev, 0, vec![i], vec![]);
        assert_eq!(apply_tx(&mut state, &body2), Err(ApplyError::DoubleSpend));
    }

    #[test]
    fn dummy_slots_ignored() {
        let mut state = ChainState::new();
        let prev = state.state_root();
        let valid_out = mk_output(1, 1);
        let dummy_out = TxOutput::dummy();
        let dummy_in = TxInput::dummy();
        let body = body_with(prev, 0, vec![dummy_in], vec![valid_out, dummy_out]);
        apply_tx(&mut state, &body).expect("apply");
        assert_eq!(state.next_leaf_index, 1);
        // nullifier tree still empty (no valid inputs)
        assert_eq!(state.nullifier_root(), ChainState::new().nullifier_root());
    }

    #[test]
    fn post_roots_flow_into_next_tx() {
        let mut state = ChainState::new();
        let prev = state.state_root();
        let body1 = body_with(prev, 0, vec![], vec![mk_output(1, 1)]);
        let st1 = apply_tx(&mut state, &body1).expect("apply 1");

        // Second tx uses st1.new_state_root as its prev — this is the
        // exact chaining the prover does on a block.
        let body2 = body_with(st1.new_state_root, 0, vec![], vec![mk_output(2, 2)]);
        let st2 = apply_tx(&mut state, &body2).expect("apply 2");
        assert_ne!(st1.new_state_root, st2.new_state_root);
    }

    #[test]
    fn err_leaves_state_untouched() {
        let mut state = ChainState::new();
        let prev = state.state_root();
        // populate once
        apply_tx(
            &mut state,
            &body_with(prev, 0, vec![], vec![mk_output(1, 1)]),
        )
        .unwrap();
        let snap_root = state.state_root();
        let snap_idx = state.next_leaf_index;

        // stale tx with outputs — should not append anything
        let bad = body_with([0u8; 32], 0, vec![], vec![mk_output(2, 2)]);
        assert!(apply_tx(&mut state, &bad).is_err());
        assert_eq!(state.state_root(), snap_root);
        assert_eq!(state.next_leaf_index, snap_idx);
    }
}
