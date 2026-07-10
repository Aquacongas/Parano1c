// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Exact authenticated UTXO-state transition used by production `BlockProof`.
//!
//! The block header state root is the UTXO sparse-Merkle root. A proof carries
//! only the canonical multiproof siblings shared by the old and new touched
//! leaves. On a one-level frontier growth, old leaves are authenticated against
//! `EXSTNOD(parent_root, zero_root[parent_depth])`; otherwise they authenticate
//! directly against the parent header root.

use noid_chain::exact_state_hash::{slot_leaf_hash, state_node_hash, zero_slot_roots, StateHash};
use noid_chain::fri_state::SlotValue;
use noid_chain::sparse_merkle::{
    build_multiproof, expand_multiproof_paths, reconstruct_root, ExpandedMerklePath,
    SparseMerkleCache, SparseMerkleError,
};
use noid_chain::state_delta::ExactActionSurface;
use noid_core::{Block128, TowerField};
use noid_gkr::{MerklePathInputs, SlotLeafInputs, MAX_MERKLE_DEPTH};

/// Maximum user transactions under the consensus semantic block budget.
pub const MAX_EXACT_USER_TXS: usize = noid_chain::consensus::params::BLOCK_MAX_USER_TXS;
/// Maximum bitmap-live touched slots plus the required coinbase output.
pub const MAX_EXACT_TOUCHED_SLOTS: usize =
    noid_chain::consensus::params::BLOCK_MAX_USER_ACTIONS + 1;
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
}

impl ExactStateTransitionProof {
    pub fn byte_len(&self) -> usize {
        self.slot_siblings.len() * 32
    }
}

/// Header roots/depths and parent counters known before proof verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExactStateTransitionInputs {
    pub parent_state_root: StateHash,
    pub parent_log_slots: u32,
    pub child_state_root: StateHash,
    pub child_log_slots: u32,
    pub parent_active_slot_count: u64,
    pub parent_alloc_counter: u64,
}

/// Sealed transition object returned only after exact verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedStateTransition {
    parent_state_root: StateHash,
    child_state_root: StateHash,
    log_slots: u32,
    slot_updates: Vec<(u32, SlotValue)>,
    active_slot_count: u64,
    alloc_counter: u64,
}

/// Public Merkle-path inputs consumed by the EXSTNOD batch relation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExactStateMerkleBatchInputs {
    pub old_root: StateHash,
    pub new_root: StateHash,
    pub old_paths: Vec<MerklePathInputs>,
    pub new_paths: Vec<MerklePathInputs>,
}

/// Public EXSTSLT slot-leaf inputs for old and new exact leaves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExactSlotLeafBatchInputs {
    pub old_leaves: Vec<SlotLeafInputs>,
    pub new_leaves: Vec<SlotLeafInputs>,
}

/// Root-only result shared by the native acceptance path and the proof-input
/// derivation path.  Keeping path expansion out of this step matters at the
/// 255-transaction tier: acceptance reconstructs two roots and stops, while
/// KillShot expands each old/new path family exactly once.
struct VerifiedExactStateRoots {
    old_root: StateHash,
    new_root: StateHash,
    old_leaf_hashes: Vec<StateHash>,
    new_leaf_hashes: Vec<StateHash>,
}

impl VerifiedStateTransition {
    /// Seal a natively recomputed no-user transition. The caller supplies the
    /// exact post-state root calculated from the same canonical slot updates.
    pub(crate) fn from_verified_no_spend_native(
        inputs: &ExactStateTransitionInputs,
        surface: &ExactActionSurface,
        child_state_root: StateHash,
    ) -> Result<Self, ExactStateTransitionError> {
        validate_depth_transition(inputs)?;
        if surface.touched_indices.len() != surface.old_slots.len()
            || surface.touched_indices.len() != surface.new_slots.len()
        {
            return Err(ExactStateTransitionError::SurfaceLengthMismatch);
        }
        if surface.touched_indices.is_empty() {
            if !surface.actions.is_empty() || surface.spends != 0 || surface.mints != 0 {
                return Err(ExactStateTransitionError::SurfaceLengthMismatch);
            }
            let expected_child = old_frontier_root(inputs)?;
            if child_state_root != expected_child || inputs.child_state_root != expected_child {
                return Err(ExactStateTransitionError::ChildRootMismatch);
            }
            return seal_exact_state_transition(inputs, surface);
        }
        if child_state_root != inputs.child_state_root {
            return Err(ExactStateTransitionError::ChildRootMismatch);
        }
        seal_exact_state_transition(inputs, surface)
    }

    pub fn parent_state_root(&self) -> StateHash {
        self.parent_state_root
    }

    pub fn child_state_root(&self) -> StateHash {
        self.child_state_root
    }

    pub fn log_slots(&self) -> u32 {
        self.log_slots
    }

    pub fn slot_updates(&self) -> &[(u32, SlotValue)] {
        &self.slot_updates
    }

    pub fn active_slot_count(&self) -> u64 {
        self.active_slot_count
    }

    pub fn alloc_counter(&self) -> u64 {
        self.alloc_counter
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExactStateTransitionError {
    EmptyTouchedSet,
    SurfaceLengthMismatch,
    InvalidLogSlots,
    ParentRootMismatch,
    ChildRootMismatch,
    ProofTooLarge { siblings: usize },
    CounterUnderflow,
    CounterOverflow,
    SparseMerkle(SparseMerkleError),
    ProofDepthUnsupported { depth: u32, max_depth: usize },
}

impl From<SparseMerkleError> for ExactStateTransitionError {
    fn from(err: SparseMerkleError) -> Self {
        Self::SparseMerkle(err)
    }
}

/// Build the canonical sibling-only proof from the cache at the child depth.
/// For a grow transition the caller passes the parent leaves embedded in the
/// one-level-grown cache, making the top right sibling the canonical zero root.
pub fn build_exact_state_transition_proof(
    cache: &SparseMerkleCache,
    surface: &ExactActionSurface,
) -> Result<ExactStateTransitionProof, ExactStateTransitionError> {
    validate_surface(surface)?;
    let proof = build_multiproof(cache, &surface.touched_indices, cache.depth())?;
    if proof.siblings.len() > MAX_EXACT_SLOT_SIBLINGS {
        return Err(ExactStateTransitionError::ProofTooLarge {
            siblings: proof.siblings.len(),
        });
    }
    Ok(ExactStateTransitionProof {
        slot_siblings: proof.siblings,
    })
}

/// Derive and fully bind the old/new EXSTNOD path statements.
pub fn derive_exact_state_merkle_batch_inputs(
    inputs: &ExactStateTransitionInputs,
    surface: &ExactActionSurface,
    proof: &ExactStateTransitionProof,
) -> Result<ExactStateMerkleBatchInputs, ExactStateTransitionError> {
    let roots = verify_exact_state_roots(inputs, surface, proof)?;

    let old_expanded = expand_multiproof_paths(
        &surface.touched_indices,
        &roots.old_leaf_hashes,
        &proof.slot_siblings,
        inputs.child_log_slots,
    )?;
    let new_expanded = expand_multiproof_paths(
        &surface.touched_indices,
        &roots.new_leaf_hashes,
        &proof.slot_siblings,
        inputs.child_log_slots,
    )?;
    let old_paths = old_expanded
        .iter()
        .map(|path| expanded_to_gkr_path(path, roots.old_root, inputs.child_log_slots))
        .collect::<Result<Vec<_>, _>>()?;
    let new_paths = new_expanded
        .iter()
        .map(|path| expanded_to_gkr_path(path, roots.new_root, inputs.child_log_slots))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(ExactStateMerkleBatchInputs {
        old_root: roots.old_root,
        new_root: roots.new_root,
        old_paths,
        new_paths,
    })
}

pub fn derive_exact_slot_leaf_batch_inputs(
    surface: &ExactActionSurface,
) -> Result<ExactSlotLeafBatchInputs, ExactStateTransitionError> {
    validate_surface(surface)?;
    let old_leaves = surface
        .old_slots
        .iter()
        .copied()
        .map(slot_to_leaf_input)
        .collect();
    let new_leaves = surface
        .new_slots
        .iter()
        .copied()
        .map(slot_to_leaf_input)
        .collect();
    Ok(ExactSlotLeafBatchInputs {
        old_leaves,
        new_leaves,
    })
}

pub fn verify_exact_state_transition(
    inputs: &ExactStateTransitionInputs,
    surface: &ExactActionSurface,
    proof: &ExactStateTransitionProof,
) -> Result<VerifiedStateTransition, ExactStateTransitionError> {
    verify_exact_state_roots(inputs, surface, proof)?;
    seal_exact_state_transition(inputs, surface)
}

pub(crate) fn seal_exact_state_transition(
    inputs: &ExactStateTransitionInputs,
    surface: &ExactActionSurface,
) -> Result<VerifiedStateTransition, ExactStateTransitionError> {
    // Keep sealing fail-closed even if a future crate-local caller bypasses
    // root verification. Empty is valid for the native no-op path; unequal
    // vectors are never valid and `zip` must not silently truncate them.
    if surface.touched_indices.len() != surface.old_slots.len()
        || surface.touched_indices.len() != surface.new_slots.len()
    {
        return Err(ExactStateTransitionError::SurfaceLengthMismatch);
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

    Ok(VerifiedStateTransition {
        parent_state_root: inputs.parent_state_root,
        child_state_root: inputs.child_state_root,
        log_slots: inputs.child_log_slots,
        slot_updates,
        active_slot_count,
        alloc_counter,
    })
}

/// Authenticate the old and new touched leaves against the header boundary
/// without materialising per-leaf paths.  `reconstruct_root` consumes the
/// canonical multiproof frontier directly, so the ordinary accept path stays
/// O(frontier) in memory instead of O(touched_slots * depth).
fn verify_exact_state_roots(
    inputs: &ExactStateTransitionInputs,
    surface: &ExactActionSurface,
    proof: &ExactStateTransitionProof,
) -> Result<VerifiedExactStateRoots, ExactStateTransitionError> {
    validate_surface(surface)?;
    validate_depth_transition(inputs)?;
    validate_proof_shape(inputs, proof)?;

    let old_root = old_frontier_root(inputs)?;
    let old_leaf_hashes = hash_slots(&surface.old_slots);
    let new_leaf_hashes = hash_slots(&surface.new_slots);
    let reconstructed_old = reconstruct_root(
        &surface.touched_indices,
        &old_leaf_hashes,
        &proof.slot_siblings,
        inputs.child_log_slots,
    )?;
    if reconstructed_old != old_root {
        return Err(ExactStateTransitionError::ParentRootMismatch);
    }
    let reconstructed_new = reconstruct_root(
        &surface.touched_indices,
        &new_leaf_hashes,
        &proof.slot_siblings,
        inputs.child_log_slots,
    )?;
    if reconstructed_new != inputs.child_state_root {
        return Err(ExactStateTransitionError::ChildRootMismatch);
    }

    Ok(VerifiedExactStateRoots {
        old_root,
        new_root: inputs.child_state_root,
        old_leaf_hashes,
        new_leaf_hashes,
    })
}

fn validate_surface(surface: &ExactActionSurface) -> Result<(), ExactStateTransitionError> {
    if surface.touched_indices.is_empty() {
        return Err(ExactStateTransitionError::EmptyTouchedSet);
    }
    if surface.touched_indices.len() != surface.old_slots.len()
        || surface.touched_indices.len() != surface.new_slots.len()
    {
        return Err(ExactStateTransitionError::SurfaceLengthMismatch);
    }
    Ok(())
}

fn validate_depth_transition(
    inputs: &ExactStateTransitionInputs,
) -> Result<(), ExactStateTransitionError> {
    if inputs.child_log_slots as usize > MAX_MERKLE_DEPTH {
        return Err(ExactStateTransitionError::ProofDepthUnsupported {
            depth: inputs.child_log_slots,
            max_depth: MAX_MERKLE_DEPTH,
        });
    }
    match inputs.child_log_slots.cmp(&inputs.parent_log_slots) {
        std::cmp::Ordering::Equal => Ok(()),
        std::cmp::Ordering::Greater if inputs.child_log_slots == inputs.parent_log_slots + 1 => {
            Ok(())
        }
        _ => Err(ExactStateTransitionError::InvalidLogSlots),
    }
}

fn validate_proof_shape(
    inputs: &ExactStateTransitionInputs,
    proof: &ExactStateTransitionProof,
) -> Result<(), ExactStateTransitionError> {
    if proof.slot_siblings.len() > MAX_EXACT_SLOT_SIBLINGS {
        return Err(ExactStateTransitionError::ProofTooLarge {
            siblings: proof.slot_siblings.len(),
        });
    }
    if inputs.child_log_slots as usize > MAX_MERKLE_DEPTH {
        return Err(ExactStateTransitionError::ProofDepthUnsupported {
            depth: inputs.child_log_slots,
            max_depth: MAX_MERKLE_DEPTH,
        });
    }
    Ok(())
}

fn old_frontier_root(
    inputs: &ExactStateTransitionInputs,
) -> Result<StateHash, ExactStateTransitionError> {
    match inputs.child_log_slots.cmp(&inputs.parent_log_slots) {
        std::cmp::Ordering::Equal => Ok(inputs.parent_state_root),
        std::cmp::Ordering::Greater if inputs.child_log_slots == inputs.parent_log_slots + 1 => {
            let zeros = zero_slot_roots(inputs.parent_log_slots as usize);
            Ok(state_node_hash(
                inputs.parent_state_root,
                zeros[inputs.parent_log_slots as usize],
            ))
        }
        _ => Err(ExactStateTransitionError::InvalidLogSlots),
    }
}

fn slot_to_leaf_input(slot: SlotValue) -> SlotLeafInputs {
    SlotLeafInputs {
        packed_value: slot.value,
        owner_hi: slot.owner_hi,
        owner_lo: slot.owner_lo,
        expected_leaf: digest_to_fields(slot_leaf_hash(slot)),
    }
}

fn digest_to_fields(hash: StateHash) -> [Block128; 2] {
    let mut lo = [0u8; 16];
    let mut hi = [0u8; 16];
    lo.copy_from_slice(&hash[..16]);
    hi.copy_from_slice(&hash[16..]);
    [
        Block128::from(u128::from_le_bytes(lo)),
        Block128::from(u128::from_le_bytes(hi)),
    ]
}

fn expanded_to_gkr_path(
    path: &ExpandedMerklePath,
    expected_root: StateHash,
    depth: u32,
) -> Result<MerklePathInputs, ExactStateTransitionError> {
    let depth = depth as usize;
    if depth > MAX_MERKLE_DEPTH {
        return Err(ExactStateTransitionError::ProofDepthUnsupported {
            depth: depth as u32,
            max_depth: MAX_MERKLE_DEPTH,
        });
    }
    let mut siblings = [[Block128::ZERO; 2]; MAX_MERKLE_DEPTH];
    let mut directions = [false; MAX_MERKLE_DEPTH];
    for level in 0..depth {
        siblings[level] = digest_to_fields(path.siblings[level]);
        directions[level] = path.directions[level];
    }
    Ok(MerklePathInputs {
        leaf: digest_to_fields(path.leaf),
        siblings,
        directions,
        expected_root: digest_to_fields(expected_root),
        active_depth: depth,
    })
}

fn hash_slots(slots: &[SlotValue]) -> Vec<StateHash> {
    slots.iter().copied().map(slot_leaf_hash).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use noid_chain::exact_state_hash::slot_leaf_hash;
    use noid_chain::state_delta::{
        exact_action_surface_from_surface, StateDeltaAction, StateDeltaActionKind,
        StateDeltaActionSurface,
    };

    fn sv(value: u64, seed: u128) -> SlotValue {
        SlotValue {
            value: Block128::from(value),
            owner_hi: Block128::from(seed),
            owner_lo: Block128::from(seed + 1),
        }
    }

    fn surface(old: SlotValue, new: SlotValue) -> ExactActionSurface {
        exact_action_surface_from_surface(StateDeltaActionSurface {
            actions: vec![
                StateDeltaAction {
                    tx_index: 0,
                    op_index: 0,
                    slot_index: 2,
                    pre: old,
                    post: SlotValue::EMPTY,
                    kind: StateDeltaActionKind::Spend,
                },
                StateDeltaAction {
                    tx_index: 0,
                    op_index: 0,
                    slot_index: 5,
                    pre: SlotValue::EMPTY,
                    post: new,
                    kind: StateDeltaActionKind::Mint,
                },
            ],
            spends: 1,
            mints: 1,
        })
    }

    fn fixture(
        grow: bool,
    ) -> (
        ExactActionSurface,
        ExactStateTransitionInputs,
        ExactStateTransitionProof,
    ) {
        let old = sv(10, 100);
        let new = sv(7, 200);
        let surface = surface(old, new);
        let parent_depth = 4usize;
        let child_depth = parent_depth + usize::from(grow);
        let parent =
            SparseMerkleCache::from_leaves(parent_depth as u32, &[(2, slot_leaf_hash(old))])
                .unwrap();
        let proof_cache =
            SparseMerkleCache::from_leaves(child_depth as u32, &[(2, slot_leaf_hash(old))])
                .unwrap();
        let child = SparseMerkleCache::from_leaves(child_depth as u32, &[(5, slot_leaf_hash(new))])
            .unwrap();
        let inputs = ExactStateTransitionInputs {
            parent_state_root: parent.root(),
            parent_log_slots: parent_depth as u32,
            child_state_root: child.root(),
            child_log_slots: child_depth as u32,
            parent_active_slot_count: 1,
            parent_alloc_counter: 1,
        };
        let proof = build_exact_state_transition_proof(&proof_cache, &surface).unwrap();
        (surface, inputs, proof)
    }

    #[test]
    fn equal_depth_transition_binds_both_header_roots() {
        let (surface, inputs, proof) = fixture(false);
        let verified = verify_exact_state_transition(&inputs, &surface, &proof).unwrap();
        assert_eq!(verified.parent_state_root(), inputs.parent_state_root);
        assert_eq!(verified.child_state_root(), inputs.child_state_root);
        assert_eq!(verified.log_slots(), inputs.child_log_slots);
        assert_eq!(verified.active_slot_count(), 1);
        assert_eq!(verified.alloc_counter(), 2);

        let derived = derive_exact_state_merkle_batch_inputs(&inputs, &surface, &proof).unwrap();
        assert_eq!(derived.old_root, inputs.parent_state_root);
        assert_eq!(derived.new_root, inputs.child_state_root);
        assert!(derived
            .old_paths
            .iter()
            .chain(derived.new_paths.iter())
            .all(|path| path.active_depth == inputs.child_log_slots as usize));
    }

    #[test]
    fn grow_transition_uses_parent_plus_zero_frontier() {
        let (surface, inputs, proof) = fixture(true);
        let derived = derive_exact_state_merkle_batch_inputs(&inputs, &surface, &proof).unwrap();
        let zeros = zero_slot_roots(inputs.parent_log_slots as usize);
        let expected_old = state_node_hash(
            inputs.parent_state_root,
            zeros[inputs.parent_log_slots as usize],
        );
        assert_eq!(derived.old_root, expected_old);
        assert_eq!(derived.new_root, inputs.child_state_root);
        assert!(derived
            .old_paths
            .iter()
            .all(|path| path.expected_root == digest_to_fields(expected_old)));
        assert!(derived
            .new_paths
            .iter()
            .all(|path| path.expected_root == digest_to_fields(inputs.child_state_root)));
        verify_exact_state_transition(&inputs, &surface, &proof).unwrap();
    }

    #[test]
    fn root_depth_and_grow_zero_sibling_tamper_reject() {
        let (surface, inputs, proof) = fixture(false);

        let mut bad_parent = inputs.clone();
        bad_parent.parent_state_root[0] ^= 1;
        assert_eq!(
            verify_exact_state_transition(&bad_parent, &surface, &proof),
            Err(ExactStateTransitionError::ParentRootMismatch)
        );

        let mut bad_child = inputs.clone();
        bad_child.child_state_root[0] ^= 1;
        assert_eq!(
            verify_exact_state_transition(&bad_child, &surface, &proof),
            Err(ExactStateTransitionError::ChildRootMismatch)
        );

        let mut bad_depth = inputs;
        bad_depth.child_log_slots += 2;
        assert_eq!(
            verify_exact_state_transition(&bad_depth, &surface, &proof),
            Err(ExactStateTransitionError::InvalidLogSlots)
        );

        let (grow_surface, grow_inputs, mut grow_proof) = fixture(true);
        let last = grow_proof
            .slot_siblings
            .last_mut()
            .expect("a grow proof carries the top zero sibling");
        last[0] ^= 1;
        assert!(verify_exact_state_transition(&grow_inputs, &grow_surface, &grow_proof).is_err());
    }

    #[test]
    fn sibling_only_proof_serializes_under_cap() {
        let (surface, _, proof) = fixture(false);
        assert!(!surface.touched_indices.is_empty());
        let bytes = bincode::serialize(&proof).unwrap();
        assert!(bytes.len() <= MAX_EXACT_STATE_PROOF_BYTES);
        assert_eq!(proof.byte_len(), proof.slot_siblings.len() * 32);
    }

    #[test]
    fn empty_native_transition_preserves_equal_or_grown_root() {
        let empty = exact_action_surface_from_surface(StateDeltaActionSurface {
            actions: Vec::new(),
            spends: 0,
            mints: 0,
        });
        let parent = [0x41u8; 32];
        for grow in [false, true] {
            let parent_log = 4u32;
            let child_log = parent_log + u32::from(grow);
            let child = if grow {
                let zeros = zero_slot_roots(parent_log as usize);
                state_node_hash(parent, zeros[parent_log as usize])
            } else {
                parent
            };
            let inputs = ExactStateTransitionInputs {
                parent_state_root: parent,
                parent_log_slots: parent_log,
                child_state_root: child,
                child_log_slots: child_log,
                parent_active_slot_count: 7,
                parent_alloc_counter: 11,
            };
            let verified =
                VerifiedStateTransition::from_verified_no_spend_native(&inputs, &empty, child)
                    .unwrap();
            assert_eq!(verified.child_state_root(), child);
            assert!(verified.slot_updates().is_empty());
            assert_eq!(verified.active_slot_count(), 7);
            assert_eq!(verified.alloc_counter(), 11);
        }
    }
}
