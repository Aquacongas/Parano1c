// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Composed KillShot proofs for exact slot leaves and authenticated state.
//!
//! This does not replace the C' action/counter/recombination obligation. It
//! proves only the two Poseidon2b families derived from the canonical exact
//! transition. Retained production proofs use the sibling-only structural
//! frontier exclusively.

use noid_chain::state_delta::ExactActionSurface;
use noid_gkr::{
    prove_batched_slot_leaf_killshot, prove_fixed_field_hash_killshot, FixedFieldHashInputs,
    FixedFieldHashProofKillShot,
};
use noid_poseidon2b::channel::Poseidon2bChannel;
use noid_recursive::block_certificate_backend::{
    derive_exact_state_structural_hash_chunks, exact_state_structural_chunk_channel,
    exact_state_structural_hash_params, exact_state_structural_proof_lanes,
    verify_exact_state_structural_killshot as verify_exact_state_structural_killshot_backend,
    ExactStateKillShotError as BackendExactStateKillShotError,
};
use rayon::prelude::*;

use crate::exact_state_transition::{
    derive_exact_slot_leaf_batch_inputs, seal_exact_state_transition, verify_exact_state_roots,
    ExactStateTransitionError, ExactStateTransitionInputs, ExactStateTransitionProof,
    VerifiedExactStateRoots, VerifiedStateTransition,
};

pub use noid_recursive::block_certificate_backend::{
    ExactStateKillShotProof, ExactStateStructuralFrontierInputs,
    EXACT_STATE_STRUCTURAL_HASH_CHUNK_SIZE,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExactStateKillShotError {
    ExactState(ExactStateTransitionError),
    EmptyDerivedInput,
    SlotLeafProofRejected,
    StructuralFrontierRejected,
    StructuralHashProofRejected,
}

impl From<ExactStateTransitionError> for ExactStateKillShotError {
    fn from(error: ExactStateTransitionError) -> Self {
        Self::ExactState(error)
    }
}

/// Derive the authoritative retained sibling-only exact-state carrier without
/// expanding one directed Merkle path per touched leaf.
pub fn derive_exact_state_structural_killshot_inputs(
    inputs: &ExactStateTransitionInputs,
    surface: &ExactActionSurface,
    proof: &ExactStateTransitionProof,
) -> Result<(ExactStateStructuralFrontierInputs, VerifiedStateTransition), ExactStateKillShotError>
{
    let roots = verify_exact_state_roots(inputs, surface, proof)?;
    let leaf_inputs = derive_exact_slot_leaf_batch_inputs(surface)?;
    let carrier = structural_inputs_from_verified_roots(inputs, surface, proof, leaf_inputs, roots);
    let verified = seal_exact_state_transition(inputs, surface)?;
    Ok((carrier, verified))
}

/// Move the retained sibling-only carrier out of an already sealed native root
/// audit without cloning the frontier or touched-index vector.
pub(crate) fn derive_retained_exact_state_structural_inputs_from_verified_roots(
    inputs: &ExactStateTransitionInputs,
    surface: ExactActionSurface,
    proof: ExactStateTransitionProof,
    roots: VerifiedExactStateRoots,
) -> Result<ExactStateStructuralFrontierInputs, ExactStateKillShotError> {
    if roots.new_root != inputs.child_state_root
        || roots.old_leaf_hashes.len() != surface.touched_indices.len()
        || roots.new_leaf_hashes.len() != surface.touched_indices.len()
    {
        return Err(ExactStateTransitionError::ChildRootMismatch.into());
    }

    let leaf_inputs = derive_exact_slot_leaf_batch_inputs(&surface)?;
    Ok(structural_inputs_from_verified_roots_owned(
        inputs,
        surface,
        proof,
        leaf_inputs,
        roots,
    ))
}

/// Consuming retained projection: the large sibling frontier and touched-index
/// vector move into the structural carrier instead of being cloned after
/// native verification.  The borrowed projector below remains for standalone
/// diagnostic construction where the source witness is still needed.
fn structural_inputs_from_verified_roots_owned(
    inputs: &ExactStateTransitionInputs,
    surface: ExactActionSurface,
    proof: ExactStateTransitionProof,
    leaf_inputs: crate::exact_state_transition::ExactSlotLeafBatchInputs,
    roots: VerifiedExactStateRoots,
) -> ExactStateStructuralFrontierInputs {
    ExactStateStructuralFrontierInputs {
        touched_indices: surface.touched_indices,
        active_depth: inputs.child_log_slots,
        old_slot_leaves: leaf_inputs.old_leaves,
        new_slot_leaves: leaf_inputs.new_leaves,
        live_sibling_digests: proof.slot_siblings,
        old_combine_digests: roots.old_combine_digests,
        new_combine_digests: roots.new_combine_digests,
        old_root: roots.old_root,
        new_root: roots.new_root,
    }
}

fn structural_inputs_from_verified_roots(
    inputs: &ExactStateTransitionInputs,
    surface: &ExactActionSurface,
    proof: &ExactStateTransitionProof,
    leaf_inputs: crate::exact_state_transition::ExactSlotLeafBatchInputs,
    roots: VerifiedExactStateRoots,
) -> ExactStateStructuralFrontierInputs {
    ExactStateStructuralFrontierInputs {
        touched_indices: surface.touched_indices.clone(),
        active_depth: inputs.child_log_slots,
        old_slot_leaves: leaf_inputs.old_leaves,
        new_slot_leaves: leaf_inputs.new_leaves,
        live_sibling_digests: proof.slot_siblings.clone(),
        old_combine_digests: roots.old_combine_digests,
        new_combine_digests: roots.new_combine_digests,
        old_root: roots.old_root,
        new_root: roots.new_root,
    }
}

/// Prove the retained exact-state relation over only live structural combines.
pub fn prove_exact_state_structural_killshot(
    inputs: &ExactStateStructuralFrontierInputs,
) -> Result<ExactStateKillShotProof, ExactStateKillShotError> {
    let mut slot_inputs =
        Vec::with_capacity(inputs.old_slot_leaves.len() + inputs.new_slot_leaves.len());
    slot_inputs.extend_from_slice(&inputs.old_slot_leaves);
    slot_inputs.extend_from_slice(&inputs.new_slot_leaves);
    let structural_chunks = derive_exact_state_structural_hash_chunks(inputs)
        .map_err(|_| ExactStateKillShotError::StructuralFrontierRejected)?;
    if slot_inputs.is_empty() || structural_chunks.is_empty() {
        return Err(ExactStateKillShotError::EmptyDerivedInput);
    }

    let (slot_leaves, structural_hashes) = rayon::join(
        || {
            let mut channel = Poseidon2bChannel::new();
            prove_batched_slot_leaf_killshot(&slot_inputs, &mut channel).0
        },
        || {
            let lanes = exact_state_structural_proof_lanes(structural_chunks.len());
            prove_structural_hash_chunks_with_lanes(&structural_chunks, lanes)
        },
    );
    Ok(ExactStateKillShotProof {
        slot_leaves,
        structural_hashes,
    })
}

fn prove_structural_hash_chunks_with_lanes(
    chunks: &[Vec<FixedFieldHashInputs>],
    lanes: usize,
) -> Vec<FixedFieldHashProofKillShot> {
    assert!(!chunks.is_empty(), "at least one structural hash chunk");
    let total_chunks = chunks.len();
    let lanes = lanes.clamp(1, total_chunks);
    let per_lane = (0..lanes)
        .into_par_iter()
        .map(|lane| {
            let params = exact_state_structural_hash_params();
            (lane..total_chunks)
                .step_by(lanes)
                .map(|chunk_index| {
                    let mut channel =
                        exact_state_structural_chunk_channel(chunk_index, total_chunks);
                    let proof =
                        prove_fixed_field_hash_killshot(params, &chunks[chunk_index], &mut channel)
                            .0;
                    (chunk_index, proof)
                })
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let mut indexed = per_lane.into_iter().flatten().collect::<Vec<_>>();
    indexed.sort_unstable_by_key(|(chunk_index, _)| *chunk_index);
    debug_assert_eq!(
        indexed
            .iter()
            .map(|(chunk_index, _)| *chunk_index)
            .collect::<Vec<_>>(),
        (0..total_chunks).collect::<Vec<_>>()
    );
    indexed.into_iter().map(|(_, proof)| proof).collect()
}

pub fn verify_exact_state_structural_killshot(
    inputs: &ExactStateStructuralFrontierInputs,
    proof: &ExactStateKillShotProof,
) -> Result<(), ExactStateKillShotError> {
    verify_exact_state_structural_killshot_backend(inputs, proof).map_err(|error| match error {
        BackendExactStateKillShotError::EmptyDerivedInput => {
            ExactStateKillShotError::EmptyDerivedInput
        }
        BackendExactStateKillShotError::SlotLeafProofRejected => {
            ExactStateKillShotError::SlotLeafProofRejected
        }
        BackendExactStateKillShotError::StructuralFrontier(_) => {
            ExactStateKillShotError::StructuralFrontierRejected
        }
        BackendExactStateKillShotError::StructuralHashProofRejected => {
            ExactStateKillShotError::StructuralHashProofRejected
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::build_exact_state_transition_proof;
    use noid_chain::exact_state_hash::{slot_leaf_hash, state_node_hash, StateHash};
    use noid_chain::fri_state::SlotValue;
    use noid_chain::sparse_merkle::SparseMerkleCache;
    use noid_chain::state_delta::{
        exact_action_surface_from_surface, StateDeltaAction, StateDeltaActionKind,
        StateDeltaActionSurface,
    };
    use noid_core::Block128;

    fn hash_fields(hash: StateHash) -> [Block128; 2] {
        [
            Block128::from(u128::from_le_bytes(hash[..16].try_into().unwrap())),
            Block128::from(u128::from_le_bytes(hash[16..].try_into().unwrap())),
        ]
    }

    fn structural_hash_claim(seed: u8) -> FixedFieldHashInputs {
        let left = [seed; 32];
        let right = [seed.wrapping_add(1); 32];
        let parent = state_node_hash(left, right);
        let left = hash_fields(left);
        let right = hash_fields(right);
        FixedFieldHashInputs {
            fields: vec![left[0], left[1], right[0], right[1]],
            expected_digest: hash_fields(parent),
        }
    }

    fn sv(value: u64, seed: u128) -> SlotValue {
        SlotValue {
            value: Block128::from(value),
            owner_hi: Block128::from(seed),
            owner_lo: Block128::from(seed + 1),
        }
    }

    fn fixture() -> (
        ExactStateTransitionInputs,
        ExactActionSurface,
        ExactStateTransitionProof,
    ) {
        let old = sv(10, 100);
        let new = sv(7, 200);
        let surface = exact_action_surface_from_surface(StateDeltaActionSurface {
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
        });
        let parent = SparseMerkleCache::from_leaves(4, &[(2, slot_leaf_hash(old))]).unwrap();
        let child = SparseMerkleCache::from_leaves(4, &[(5, slot_leaf_hash(new))]).unwrap();
        let inputs = ExactStateTransitionInputs {
            parent_state_root: parent.root(),
            parent_log_slots: 4,
            child_state_root: child.root(),
            child_log_slots: 4,
            parent_active_slot_count: 1,
            parent_alloc_counter: 1,
        };
        let proof = build_exact_state_transition_proof(&parent, &surface).unwrap();
        (inputs, surface, proof)
    }

    fn retained_projection_fixture(
        touched: usize,
    ) -> (
        ExactStateTransitionInputs,
        ExactActionSurface,
        ExactStateTransitionProof,
    ) {
        let depth = 8u32;
        let touched_indices = (0..touched as u32).collect::<Vec<_>>();
        let old_slots = (0..touched)
            .map(|index| sv(index as u64 + 1, 10_000 + index as u128 * 2))
            .collect::<Vec<_>>();
        let new_slots = (0..touched)
            .map(|index| sv(index as u64 + 2, 20_000 + index as u128 * 2))
            .collect::<Vec<_>>();
        let old_leaves = touched_indices
            .iter()
            .copied()
            .zip(old_slots.iter().copied().map(slot_leaf_hash))
            .collect::<Vec<_>>();
        let new_leaves = touched_indices
            .iter()
            .copied()
            .zip(new_slots.iter().copied().map(slot_leaf_hash))
            .collect::<Vec<_>>();
        let parent = SparseMerkleCache::from_leaves(depth, &old_leaves).unwrap();
        let child = SparseMerkleCache::from_leaves(depth, &new_leaves).unwrap();
        let surface = ExactActionSurface {
            actions: Vec::new(),
            touched_indices,
            old_slots,
            new_slots,
            spends: 0,
            mints: 0,
        };
        let inputs = ExactStateTransitionInputs {
            parent_state_root: parent.root(),
            parent_log_slots: depth,
            child_state_root: child.root(),
            child_log_slots: depth,
            parent_active_slot_count: touched as u64,
            parent_alloc_counter: touched as u64,
        };
        let proof = build_exact_state_transition_proof(&parent, &surface).unwrap();
        (inputs, surface, proof)
    }

    #[test]
    fn structural_exact_state_killshot_roundtrip() {
        let (inputs, surface, exact_proof) = fixture();
        let (structural, verified) =
            derive_exact_state_structural_killshot_inputs(&inputs, &surface, &exact_proof).unwrap();
        assert_eq!(verified.child_state_root(), inputs.child_state_root);
        assert_eq!(structural.touched_indices, surface.touched_indices);
        assert_eq!(structural.live_sibling_digests, exact_proof.slot_siblings);

        let proof = prove_exact_state_structural_killshot(&structural).unwrap();
        assert!(!proof.structural_hashes.is_empty());
        assert!(proof.byte_len() > 0);
        verify_exact_state_structural_killshot(&structural, &proof).unwrap();
    }

    #[test]
    fn retained_projection_moves_only_structural_frontier() {
        let (inputs, surface, proof) = retained_projection_fixture(129);
        let (verified, roots) =
            crate::exact_state_transition::verify_exact_state_transition_with_roots(
                &inputs, &surface, &proof,
            )
            .unwrap();
        let structural = derive_retained_exact_state_structural_inputs_from_verified_roots(
            &inputs, surface, proof, roots,
        )
        .unwrap();

        assert_eq!(verified.child_state_root(), inputs.child_state_root);
        assert_eq!(structural.old_slot_leaves.len(), 129);
        assert_eq!(structural.new_slot_leaves.len(), 129);
        noid_recursive::block_certificate_backend::verify_exact_state_structural_frontier(
            &structural,
        )
        .unwrap();
    }

    #[test]
    fn retained_exact_state_full_path_surface_is_absent() {
        let production_sources = [
            include_str!("exact_state_killshot.rs"),
            include_str!("exact_state_transition.rs"),
            include_str!("accepted_block_batch.rs"),
            include_str!("../../noid_recursive/src/block_certificate_backend.rs"),
            include_str!("../../noid_recursive/src/acceptance/block_slots.rs"),
            include_str!("../../noid_recursive/src/acceptance/trace/exact_state.rs"),
            include_str!("../../noid_recursive/src/acceptance/trace/region_source_binding.rs"),
        ];
        let forbidden = [
            concat!("ExactState", "KillShotInputs"),
            concat!("exact_state_", "killshot_inputs"),
            concat!("state_", "paths"),
            concat!("EXACT_STATE_MERKLE_", "PATH_CHUNK_SIZE"),
            concat!("derive_exact_state_", "merkle_batch_inputs"),
            concat!("prove_transitional_exact_state_", "path_chunks"),
            concat!("ExactState", "PathRegion"),
        ];
        for symbol in forbidden {
            assert!(
                production_sources
                    .iter()
                    .all(|source| !source.contains(symbol)),
                "removed exact-state path surface reappeared: {symbol}"
            );
        }
    }

    #[test]
    fn independent_structural_chunks_are_lane_invariant_and_index_bound() {
        let chunk = vec![structural_hash_claim(7), structural_hash_claim(19)];
        let chunks = vec![chunk.clone(), chunk.clone(), chunk];
        let lane_one = prove_structural_hash_chunks_with_lanes(&chunks, 1);
        let lane_two = prove_structural_hash_chunks_with_lanes(&chunks, 2);
        assert_eq!(lane_one, lane_two);
        assert_eq!(
            bincode::serialize(&lane_one).unwrap(),
            bincode::serialize(&lane_two).unwrap(),
            "scheduling must not change proof bytes"
        );
        assert_ne!(
            lane_one[0], lane_one[1],
            "identical statements at different chunk indices need distinct transcripts"
        );
        noid_recursive::block_certificate_backend::verify_exact_state_structural_hash_chunk_proofs(
            &chunks, &lane_one,
        )
        .unwrap();

        let mut reordered = lane_one.clone();
        reordered.swap(0, 1);
        assert_eq!(
            noid_recursive::block_certificate_backend::verify_exact_state_structural_hash_chunk_proofs(
                &chunks,
                &reordered,
            ),
            Err(BackendExactStateKillShotError::StructuralHashProofRejected)
        );
    }

    #[test]
    fn structural_exact_state_killshot_rejects_carrier_and_chunk_tampering() {
        let (inputs, surface, exact_proof) = fixture();
        let (structural, _) =
            derive_exact_state_structural_killshot_inputs(&inputs, &surface, &exact_proof).unwrap();
        let proof = prove_exact_state_structural_killshot(&structural).unwrap();

        let mut bad_root = structural.clone();
        bad_root.new_root[0] ^= 1;
        assert_eq!(
            verify_exact_state_structural_killshot(&bad_root, &proof),
            Err(ExactStateKillShotError::StructuralFrontierRejected)
        );

        let mut missing_chunk = proof.clone();
        missing_chunk.structural_hashes.pop();
        assert_eq!(
            verify_exact_state_structural_killshot(&structural, &missing_chunk),
            Err(ExactStateKillShotError::StructuralHashProofRejected)
        );
    }

    #[test]
    fn structural_fast_verifier_rejects_changed_dag_node_root_edge_and_order() {
        let (inputs, surface, exact_proof) = fixture();
        let (structural, _) =
            derive_exact_state_structural_killshot_inputs(&inputs, &surface, &exact_proof).unwrap();
        assert!(structural.old_combine_digests.len() > 2);
        let proof = prove_exact_state_structural_killshot(&structural).unwrap();

        let mut changed_intermediate = structural.clone();
        changed_intermediate.old_combine_digests[0][0] ^= 1;
        assert_eq!(
            verify_exact_state_structural_killshot(&changed_intermediate, &proof),
            Err(ExactStateKillShotError::StructuralHashProofRejected)
        );

        let mut changed_order = structural.clone();
        changed_order.old_combine_digests.swap(0, 1);
        assert_eq!(
            verify_exact_state_structural_killshot(&changed_order, &proof),
            Err(ExactStateKillShotError::StructuralHashProofRejected)
        );

        let mut changed_root = structural.clone();
        changed_root.new_root[0] ^= 1;
        *changed_root.new_combine_digests.last_mut().unwrap() = changed_root.new_root;
        assert_eq!(
            verify_exact_state_structural_killshot(&changed_root, &proof),
            Err(ExactStateKillShotError::StructuralHashProofRejected)
        );

        let mut changed_edge = structural.clone();
        changed_edge.touched_indices[0] = 3;
        assert_eq!(
            verify_exact_state_structural_killshot(&changed_edge, &proof),
            Err(ExactStateKillShotError::StructuralHashProofRejected)
        );
    }
}
