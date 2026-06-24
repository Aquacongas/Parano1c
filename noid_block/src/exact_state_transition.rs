// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Exact authenticated state transition verifier used by production `BlockProof`.
//!
//! The proof authenticates every touched UTXO slot with canonical Poseidon2b
//! sparse-Merkle openings and binds ABA replay protection through `ReuseGuard`.

use std::collections::BTreeSet;

use noid_chain::exact_state_hash::{
    composite_state_root, slot_leaf_hash_checked, state_node_hash, zero_slot_roots, StateHash,
};
use noid_chain::fri_state::SlotValue;
use noid_chain::reuse_guard::{
    bucket_index_for_height, verify_guard_update_roots, GuardBucket, ReuseGuard, ReuseGuardError,
};
use noid_chain::sparse_merkle::{
    build_multiproof, reconstruct_root, SparseMerkleCache, SparseMerkleError,
};
use noid_chain::state_delta::{ExactActionSurface, StateDeltaActionKind};
use noid_tx::TxShape;

/// Maximum user transactions in a block with one coinbase.
pub const MAX_EXACT_USER_TXS: usize = noid_chain::block::BLOCK_MAX_TXS - 1;
/// Max touched slots under current Standard4x8/Sweep25x2 shapes plus coinbase output.
pub const MAX_EXACT_TOUCHED_SLOTS: usize =
    MAX_EXACT_USER_TXS * TxShape::Sweep25x2.max_claimed_slots() + 1;
/// Conservative sibling bound before canonical deduplication.
pub const MAX_EXACT_SLOT_SIBLINGS: usize = MAX_EXACT_TOUCHED_SLOTS * 32;
/// Maximum raw sibling bytes under the conservative bound.
pub const MAX_EXACT_SLOT_SIBLING_BYTES: usize = MAX_EXACT_SLOT_SIBLINGS * 32;
/// Starting cap for serialized exact-state proof bytes.
pub const MAX_EXACT_STATE_PROOF_BYTES: usize = 8 * 1024 * 1024;

/// Exact authenticated state transition proof payload.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ExactStateTransitionProof {
    /// Missing slot-frontier hashes in canonical implicit order.
    pub slot_siblings: Vec<StateHash>,
    /// Present iff this block spends at least one slot.
    pub guard_update: Option<GuardBucketUpdateProof>,
}

impl ExactStateTransitionProof {
    pub fn byte_len(&self) -> usize {
        self.slot_siblings.len() * 32
            + self
                .guard_update
                .as_ref()
                .map_or(0, |proof| proof.siblings.len() * 32)
    }
}

/// Fixed depth-8 ReuseGuard bucket update proof.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct GuardBucketUpdateProof {
    pub siblings: [StateHash; 8],
}

/// Component roots and counters known to the verifier before checking a proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExactStateTransitionInputs {
    pub parent_state_root: StateHash,
    pub parent_log_slots: u32,
    pub parent_utxo_root: StateHash,
    pub parent_guard_root: StateHash,
    pub child_state_root: StateHash,
    pub child_log_slots: u32,
    pub height: u64,
    pub parent_active_slot_count: u64,
    pub parent_alloc_counter: u64,
}

/// Sealed transition object returned only after exact verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedStateTransition {
    parent_state_root: StateHash,
    child_state_root: StateHash,
    child_utxo_root: StateHash,
    child_guard_root: StateHash,
    log_slots: u32,
    slot_updates: Vec<(u32, SlotValue)>,
    guard_bucket_update: Option<(usize, GuardBucket)>,
    active_slot_count: u64,
    alloc_counter: u64,
}

impl VerifiedStateTransition {
    pub fn parent_state_root(&self) -> StateHash {
        self.parent_state_root
    }

    pub fn child_state_root(&self) -> StateHash {
        self.child_state_root
    }

    pub fn child_utxo_root(&self) -> StateHash {
        self.child_utxo_root
    }

    pub fn child_guard_root(&self) -> StateHash {
        self.child_guard_root
    }

    pub fn log_slots(&self) -> u32 {
        self.log_slots
    }

    pub fn slot_updates(&self) -> &[(u32, SlotValue)] {
        &self.slot_updates
    }

    pub fn guard_bucket_update(&self) -> Option<&(usize, GuardBucket)> {
        self.guard_bucket_update.as_ref()
    }

    pub fn active_slot_count(&self) -> u64 {
        self.active_slot_count
    }

    pub fn alloc_counter(&self) -> u64 {
        self.alloc_counter
    }
}

/// Errors from exact state transition verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExactStateTransitionError {
    EmptyTouchedSet,
    SurfaceLengthMismatch,
    InvalidLogSlots,
    ParentRootMismatch,
    ParentGuardRootMismatch,
    ParentUtxoRootMismatch,
    ChildRootMismatch,
    ProofTooLarge { siblings: usize },
    ActiveGuardedSlot { slot_index: u32 },
    MintAfterSpendSameBlock { slot_index: u32 },
    MissingGuardProof,
    UnexpectedGuardProof,
    OldGuardRootMismatch,
    CounterUnderflow,
    CounterOverflow,
    SparseMerkle(SparseMerkleError),
    ReuseGuard(ReuseGuardError),
    NonCanonicalSlot,
}

impl From<SparseMerkleError> for ExactStateTransitionError {
    fn from(err: SparseMerkleError) -> Self {
        Self::SparseMerkle(err)
    }
}

impl From<ReuseGuardError> for ExactStateTransitionError {
    fn from(err: ReuseGuardError) -> Self {
        Self::ReuseGuard(err)
    }
}

/// Build an exact proof from local exact-state caches. Experimental only.
pub fn build_exact_state_transition_proof(
    cache: &SparseMerkleCache,
    surface: &ExactActionSurface,
    guard: &ReuseGuard,
    height: u64,
) -> Result<ExactStateTransitionProof, ExactStateTransitionError> {
    let proof = build_multiproof(cache, &surface.touched_indices, cache.depth())?;
    let guard_update = if surface.spent_slots.is_empty() {
        None
    } else {
        let mut next_guard = guard.clone();
        let update = next_guard
            .apply_spends(height, &surface.spent_slots)?
            .ok_or(ExactStateTransitionError::MissingGuardProof)?;
        Some(GuardBucketUpdateProof {
            siblings: update.siblings,
        })
    };
    Ok(ExactStateTransitionProof {
        slot_siblings: proof.siblings,
        guard_update,
    })
}

/// Verify exact UTXO frontier and ReuseGuard update.
pub fn verify_exact_state_transition(
    inputs: &ExactStateTransitionInputs,
    surface: &ExactActionSurface,
    guard: &ReuseGuard,
    proof: &ExactStateTransitionProof,
) -> Result<VerifiedStateTransition, ExactStateTransitionError> {
    if surface.touched_indices.is_empty() {
        return Err(ExactStateTransitionError::EmptyTouchedSet);
    }
    if surface.touched_indices.len() != surface.old_slots.len()
        || surface.touched_indices.len() != surface.new_slots.len()
    {
        return Err(ExactStateTransitionError::SurfaceLengthMismatch);
    }
    if proof.slot_siblings.len() > MAX_EXACT_SLOT_SIBLINGS {
        return Err(ExactStateTransitionError::ProofTooLarge {
            siblings: proof.slot_siblings.len(),
        });
    }

    let parent_composite = composite_state_root(
        inputs.parent_log_slots,
        inputs.parent_utxo_root,
        inputs.parent_guard_root,
    );
    if parent_composite != inputs.parent_state_root {
        return Err(ExactStateTransitionError::ParentRootMismatch);
    }
    if guard.root() != inputs.parent_guard_root {
        return Err(ExactStateTransitionError::ParentGuardRootMismatch);
    }

    enforce_guard_exclusion(surface, guard, inputs.height)?;

    let proof_depth = inputs.child_log_slots;
    let parent_frontier_utxo_root = match inputs.child_log_slots.cmp(&inputs.parent_log_slots) {
        std::cmp::Ordering::Equal => inputs.parent_utxo_root,
        std::cmp::Ordering::Greater if inputs.child_log_slots == inputs.parent_log_slots + 1 => {
            let zeros = zero_slot_roots(inputs.parent_log_slots as usize);
            state_node_hash(
                inputs.parent_utxo_root,
                zeros[inputs.parent_log_slots as usize],
            )
        }
        _ => return Err(ExactStateTransitionError::InvalidLogSlots),
    };

    let old_leaf_hashes = hash_slots(&surface.old_slots)?;
    let new_leaf_hashes = hash_slots(&surface.new_slots)?;
    let old_root = reconstruct_root(
        &surface.touched_indices,
        &old_leaf_hashes,
        &proof.slot_siblings,
        proof_depth,
    )?;
    if old_root != parent_frontier_utxo_root {
        return Err(ExactStateTransitionError::ParentUtxoRootMismatch);
    }
    let child_utxo_root = reconstruct_root(
        &surface.touched_indices,
        &new_leaf_hashes,
        &proof.slot_siblings,
        proof_depth,
    )?;

    let child_guard_root = verify_guard(inputs, surface, guard, proof)?;
    let child_state_root =
        composite_state_root(inputs.child_log_slots, child_utxo_root, child_guard_root);
    if child_state_root != inputs.child_state_root {
        return Err(ExactStateTransitionError::ChildRootMismatch);
    }

    let active_slot_count = inputs
        .parent_active_slot_count
        .checked_sub(surface.spends as u64)
        .ok_or(ExactStateTransitionError::CounterUnderflow)?
        .checked_add(surface.mints as u64)
        .ok_or(ExactStateTransitionError::CounterOverflow)?;
    let alloc_counter = inputs
        .parent_alloc_counter
        .checked_add(surface.mints as u64)
        .ok_or(ExactStateTransitionError::CounterOverflow)?;

    let slot_updates = surface
        .touched_indices
        .iter()
        .copied()
        .zip(surface.new_slots.iter().copied())
        .collect();
    let guard_bucket_update = if surface.spent_slots.is_empty() {
        None
    } else {
        Some((
            bucket_index_for_height(inputs.height),
            GuardBucket::Occupied {
                absolute_height: inputs.height,
                spent_slots: surface.spent_slots.clone(),
            },
        ))
    };

    Ok(VerifiedStateTransition {
        parent_state_root: inputs.parent_state_root,
        child_state_root,
        child_utxo_root,
        child_guard_root,
        log_slots: inputs.child_log_slots,
        slot_updates,
        guard_bucket_update,
        active_slot_count,
        alloc_counter,
    })
}

fn hash_slots(slots: &[SlotValue]) -> Result<Vec<StateHash>, ExactStateTransitionError> {
    slots
        .iter()
        .copied()
        .map(|slot| {
            slot_leaf_hash_checked(slot).map_err(|_| ExactStateTransitionError::NonCanonicalSlot)
        })
        .collect()
}

fn enforce_guard_exclusion(
    surface: &ExactActionSurface,
    guard: &ReuseGuard,
    height: u64,
) -> Result<(), ExactStateTransitionError> {
    let mut spent_in_block = BTreeSet::new();
    for action in &surface.actions {
        if guard.is_guarded(action.slot_index, height) {
            return Err(ExactStateTransitionError::ActiveGuardedSlot {
                slot_index: action.slot_index,
            });
        }
        match action.kind {
            StateDeltaActionKind::Spend => {
                spent_in_block.insert(action.slot_index);
            }
            StateDeltaActionKind::Mint => {
                if spent_in_block.contains(&action.slot_index) {
                    return Err(ExactStateTransitionError::MintAfterSpendSameBlock {
                        slot_index: action.slot_index,
                    });
                }
            }
        }
    }
    Ok(())
}

fn verify_guard(
    inputs: &ExactStateTransitionInputs,
    surface: &ExactActionSurface,
    guard: &ReuseGuard,
    proof: &ExactStateTransitionProof,
) -> Result<StateHash, ExactStateTransitionError> {
    if surface.spent_slots.is_empty() {
        if proof.guard_update.is_some() {
            return Err(ExactStateTransitionError::UnexpectedGuardProof);
        }
        return Ok(inputs.parent_guard_root);
    }

    let guard_proof = proof
        .guard_update
        .as_ref()
        .ok_or(ExactStateTransitionError::MissingGuardProof)?;
    guard.ensure_bucket_reusable_at(inputs.height)?;
    let index = bucket_index_for_height(inputs.height);
    let new_bucket = GuardBucket::Occupied {
        absolute_height: inputs.height,
        spent_slots: surface.spent_slots.clone(),
    };
    let (old_root, new_root) = verify_guard_update_roots(
        index,
        guard.bucket(index),
        &new_bucket,
        &guard_proof.siblings,
    )?;
    if old_root != inputs.parent_guard_root {
        return Err(ExactStateTransitionError::OldGuardRootMismatch);
    }
    Ok(new_root)
}

#[cfg(test)]
mod tests {
    use super::*;
    use noid_chain::exact_state_hash::{composite_state_root, slot_leaf_hash};
    use noid_chain::reuse_guard::ReuseGuard;
    use noid_chain::state_delta::{StateDeltaAction, StateDeltaActionKind};
    use noid_core::Block128;

    fn sv(value: u64, seed: u128) -> SlotValue {
        SlotValue {
            value: Block128::from(value),
            owner_hi: Block128::from(seed),
            owner_lo: Block128::from(seed + 1),
        }
    }

    fn action(
        slot_index: u32,
        pre: SlotValue,
        post: SlotValue,
        kind: StateDeltaActionKind,
        tx_index: u32,
    ) -> StateDeltaAction {
        StateDeltaAction {
            tx_index,
            op_index: 0,
            slot_index,
            pre,
            post,
            kind,
        }
    }

    fn spend_and_mint_surface(old: SlotValue, new: SlotValue) -> ExactActionSurface {
        ExactActionSurface {
            actions: vec![
                action(2, old, SlotValue::EMPTY, StateDeltaActionKind::Spend, 0),
                action(5, SlotValue::EMPTY, new, StateDeltaActionKind::Mint, 0),
            ],
            touched_indices: vec![2, 5],
            old_slots: vec![old, SlotValue::EMPTY],
            new_slots: vec![SlotValue::EMPTY, new],
            spent_slots: vec![2],
            spends: 1,
            mints: 1,
        }
    }

    fn inputs_for(
        parent_cache: &SparseMerkleCache,
        child_cache: &SparseMerkleCache,
        guard: &ReuseGuard,
        child_guard_root: StateHash,
    ) -> ExactStateTransitionInputs {
        let parent_state_root = composite_state_root(4, parent_cache.root(), guard.root());
        let child_state_root = composite_state_root(4, child_cache.root(), child_guard_root);
        ExactStateTransitionInputs {
            parent_state_root,
            parent_log_slots: 4,
            parent_utxo_root: parent_cache.root(),
            parent_guard_root: guard.root(),
            child_state_root,
            child_log_slots: 4,
            height: 10,
            parent_active_slot_count: 1,
            parent_alloc_counter: 1,
        }
    }

    #[test]
    fn verifies_shared_frontier_and_guard_update() {
        let old = sv(10, 100);
        let new = sv(7, 200);
        let surface = spend_and_mint_surface(old, new);
        let parent_cache = SparseMerkleCache::from_leaves(4, &[(2, slot_leaf_hash(old))]).unwrap();
        let child_cache = SparseMerkleCache::from_leaves(4, &[(5, slot_leaf_hash(new))]).unwrap();
        let guard = ReuseGuard::new_empty();
        let mut next_guard = guard.clone();
        next_guard.apply_spends(10, &[2]).unwrap();
        let inputs = inputs_for(&parent_cache, &child_cache, &guard, next_guard.root());
        let proof =
            build_exact_state_transition_proof(&parent_cache, &surface, &guard, 10).unwrap();

        let verified = verify_exact_state_transition(&inputs, &surface, &guard, &proof).unwrap();

        assert_eq!(verified.child_utxo_root(), child_cache.root());
        assert_eq!(verified.child_guard_root(), next_guard.root());
        assert_eq!(verified.active_slot_count(), 1);
        assert_eq!(verified.alloc_counter(), 2);
        assert_eq!(verified.slot_updates().len(), 2);
        assert!(verified.guard_bucket_update().is_some());
    }

    #[test]
    fn tampered_slot_sibling_rejects() {
        let old = sv(10, 100);
        let new = sv(7, 200);
        let surface = spend_and_mint_surface(old, new);
        let parent_cache = SparseMerkleCache::from_leaves(4, &[(2, slot_leaf_hash(old))]).unwrap();
        let child_cache = SparseMerkleCache::from_leaves(4, &[(5, slot_leaf_hash(new))]).unwrap();
        let guard = ReuseGuard::new_empty();
        let mut next_guard = guard.clone();
        next_guard.apply_spends(10, &[2]).unwrap();
        let inputs = inputs_for(&parent_cache, &child_cache, &guard, next_guard.root());
        let mut proof =
            build_exact_state_transition_proof(&parent_cache, &surface, &guard, 10).unwrap();
        proof.slot_siblings[0][0] ^= 1;

        assert_eq!(
            verify_exact_state_transition(&inputs, &surface, &guard, &proof),
            Err(ExactStateTransitionError::ParentUtxoRootMismatch)
        );
    }

    #[test]
    fn no_spend_requires_no_guard_proof() {
        let new = sv(7, 200);
        let surface = ExactActionSurface {
            actions: vec![action(
                5,
                SlotValue::EMPTY,
                new,
                StateDeltaActionKind::Mint,
                0,
            )],
            touched_indices: vec![5],
            old_slots: vec![SlotValue::EMPTY],
            new_slots: vec![new],
            spent_slots: vec![],
            spends: 0,
            mints: 1,
        };
        let parent_cache = SparseMerkleCache::new(4).unwrap();
        let child_cache = SparseMerkleCache::from_leaves(4, &[(5, slot_leaf_hash(new))]).unwrap();
        let guard = ReuseGuard::new_empty();
        let inputs = inputs_for(&parent_cache, &child_cache, &guard, guard.root());
        let mut proof =
            build_exact_state_transition_proof(&parent_cache, &surface, &guard, 10).unwrap();
        assert!(proof.guard_update.is_none());

        verify_exact_state_transition(&inputs, &surface, &guard, &proof).unwrap();
        proof.guard_update = Some(GuardBucketUpdateProof {
            siblings: [[0u8; 32]; 8],
        });
        assert_eq!(
            verify_exact_state_transition(&inputs, &surface, &guard, &proof),
            Err(ExactStateTransitionError::UnexpectedGuardProof)
        );
    }

    #[test]
    fn guard_rejects_active_slot_and_spend_then_remint() {
        let old = sv(10, 100);
        let new = sv(7, 200);
        let parent_cache = SparseMerkleCache::from_leaves(4, &[(2, slot_leaf_hash(old))]).unwrap();
        let child_cache = SparseMerkleCache::from_leaves(4, &[(2, slot_leaf_hash(new))]).unwrap();
        let mut guard = ReuseGuard::new_empty();
        guard.apply_spends(9, &[2]).unwrap();

        let guarded_surface = ExactActionSurface {
            actions: vec![action(
                2,
                old,
                SlotValue::EMPTY,
                StateDeltaActionKind::Spend,
                0,
            )],
            touched_indices: vec![2],
            old_slots: vec![old],
            new_slots: vec![SlotValue::EMPTY],
            spent_slots: vec![2],
            spends: 1,
            mints: 0,
        };
        let inputs = inputs_for(&parent_cache, &child_cache, &guard, guard.root());
        let proof = build_exact_state_transition_proof(&parent_cache, &guarded_surface, &guard, 10)
            .unwrap();
        assert_eq!(
            verify_exact_state_transition(&inputs, &guarded_surface, &guard, &proof),
            Err(ExactStateTransitionError::ActiveGuardedSlot { slot_index: 2 })
        );

        let empty_guard = ReuseGuard::new_empty();
        let spend_then_remint = ExactActionSurface {
            actions: vec![
                action(2, old, SlotValue::EMPTY, StateDeltaActionKind::Spend, 0),
                action(2, SlotValue::EMPTY, new, StateDeltaActionKind::Mint, 1),
            ],
            touched_indices: vec![2],
            old_slots: vec![old],
            new_slots: vec![new],
            spent_slots: vec![2],
            spends: 1,
            mints: 1,
        };
        let mut next_guard = empty_guard.clone();
        next_guard.apply_spends(10, &[2]).unwrap();
        let inputs = inputs_for(&parent_cache, &child_cache, &empty_guard, next_guard.root());
        let proof =
            build_exact_state_transition_proof(&parent_cache, &spend_then_remint, &empty_guard, 10)
                .unwrap();
        assert_eq!(
            verify_exact_state_transition(&inputs, &spend_then_remint, &empty_guard, &proof),
            Err(ExactStateTransitionError::MintAfterSpendSameBlock { slot_index: 2 })
        );
    }

    #[test]
    fn max_shape_exact_proof_serializes_under_cap() {
        assert_eq!(MAX_EXACT_TOUCHED_SLOTS, 6_886);
        assert_eq!(MAX_EXACT_SLOT_SIBLINGS, 220_352);
        assert_eq!(MAX_EXACT_SLOT_SIBLING_BYTES, 7_051_264);
        let proof = ExactStateTransitionProof {
            slot_siblings: vec![[0u8; 32]; MAX_EXACT_SLOT_SIBLINGS],
            guard_update: Some(GuardBucketUpdateProof {
                siblings: [[0u8; 32]; 8],
            }),
        };
        let encoded = bincode::serialize(&proof).unwrap();
        assert!(encoded.len() > MAX_EXACT_SLOT_SIBLING_BYTES);
        assert!(encoded.len() <= MAX_EXACT_STATE_PROOF_BYTES);
    }
}
