// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Composed KillShot proofs for exact slot leaves and authenticated state.
//!
//! This does not replace the C' action/counter/recombination obligation. It
//! proves only the two Poseidon2b families derived from the canonical exact
//! transition. Retained production proofs use the sibling-only structural
//! frontier; directed Merkle paths remain temporarily for the not-yet-migrated
//! outer trace.

use noid_chain::state_delta::ExactActionSurface;
use noid_gkr::{
    prove_batched_merkle_killshot, prove_batched_slot_leaf_killshot,
    prove_fixed_field_hash_killshot, FixedFieldHashInputs, FixedFieldHashProofKillShot,
    MerkleCircuit,
};
use noid_poseidon2b::channel::Poseidon2bChannel;
use noid_poseidon2b::native::domain::TAG_EXSTNOD;
use noid_recursive::block_certificate_backend::{
    derive_exact_state_structural_hash_chunks, exact_state_structural_chunk_channel,
    exact_state_structural_hash_params, exact_state_structural_proof_lanes,
    verify_exact_state_killshot as verify_exact_state_killshot_backend,
    verify_exact_state_structural_killshot as verify_exact_state_structural_killshot_backend,
    ExactStateKillShotError as BackendExactStateKillShotError,
};
use rayon::prelude::*;

use crate::exact_state_transition::{
    derive_exact_slot_leaf_batch_inputs, derive_exact_state_merkle_batch_inputs,
    derive_exact_state_merkle_batch_inputs_from_verified_roots, seal_exact_state_transition,
    verify_exact_state_roots, ExactStateTransitionError, ExactStateTransitionInputs,
    ExactStateTransitionProof, VerifiedExactStateRoots, VerifiedStateTransition,
};

pub use noid_recursive::block_certificate_backend::{
    ExactStateKillShotInputs, ExactStateKillShotProof, ExactStateStructuralFrontierInputs,
    EXACT_STATE_MERKLE_PATH_CHUNK_SIZE, EXACT_STATE_STRUCTURAL_HASH_CHUNK_SIZE,
};

/// Maximum legacy directed paths retained solely for the transitional inline
/// outer trace. Larger production statements (including B255) carry no path
/// proofs and must use the full structural-region configuration.
pub const TRANSITIONAL_INLINE_EXACT_STATE_MAX_PATHS: usize = EXACT_STATE_MERKLE_PATH_CHUNK_SIZE;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExactStateKillShotError {
    ExactState(ExactStateTransitionError),
    EmptyDerivedInput,
    SlotLeafProofRejected,
    StateMerkleProofRejected,
    StructuralFrontierRejected,
    StructuralHashProofRejected,
    NonCanonicalLegacyPathProof,
}

impl From<ExactStateTransitionError> for ExactStateKillShotError {
    fn from(error: ExactStateTransitionError) -> Self {
        Self::ExactState(error)
    }
}

pub fn derive_exact_state_killshot_inputs(
    inputs: &ExactStateTransitionInputs,
    surface: &ExactActionSurface,
    proof: &ExactStateTransitionProof,
) -> Result<(ExactStateKillShotInputs, VerifiedStateTransition), ExactStateKillShotError> {
    let leaf_inputs = derive_exact_slot_leaf_batch_inputs(surface)?;
    let mut slot_leaves =
        Vec::with_capacity(leaf_inputs.old_leaves.len() + leaf_inputs.new_leaves.len());
    slot_leaves.extend(leaf_inputs.old_leaves);
    slot_leaves.extend(leaf_inputs.new_leaves);

    let state_inputs = derive_exact_state_merkle_batch_inputs(inputs, surface, proof)?;
    let mut state_paths =
        Vec::with_capacity(state_inputs.old_paths.len() + state_inputs.new_paths.len());
    state_paths.extend(state_inputs.old_paths);
    state_paths.extend(state_inputs.new_paths);
    let verified = seal_exact_state_transition(inputs, surface)?;

    Ok((
        ExactStateKillShotInputs {
            slot_leaves,
            state_paths,
        },
        verified,
    ))
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

/// Project retained exact-state inputs from the sealed native root audit.
///
/// The structural carrier is unconditional. Directed paths are a transitional
/// inline-only projection and are not even materialized once the combined
/// old/new path count exceeds the audited inline cap.
pub(crate) fn derive_retained_exact_state_inputs_from_verified_roots(
    inputs: &ExactStateTransitionInputs,
    surface: &ExactActionSurface,
    proof: &ExactStateTransitionProof,
    roots: VerifiedExactStateRoots,
) -> Result<(ExactStateKillShotInputs, ExactStateStructuralFrontierInputs), ExactStateKillShotError>
{
    if roots.new_root != inputs.child_state_root
        || roots.old_leaf_hashes.len() != surface.touched_indices.len()
        || roots.new_leaf_hashes.len() != surface.touched_indices.len()
    {
        return Err(ExactStateTransitionError::ChildRootMismatch.into());
    }

    let leaf_inputs = derive_exact_slot_leaf_batch_inputs(surface)?;
    let total_paths = surface
        .touched_indices
        .len()
        .checked_mul(2)
        .unwrap_or(usize::MAX);
    let legacy = if total_paths <= TRANSITIONAL_INLINE_EXACT_STATE_MAX_PATHS {
        let state_inputs = derive_exact_state_merkle_batch_inputs_from_verified_roots(
            inputs, surface, proof, &roots,
        )?;
        let mut slot_leaves = Vec::with_capacity(total_paths);
        slot_leaves.extend(leaf_inputs.old_leaves.iter().cloned());
        slot_leaves.extend(leaf_inputs.new_leaves.iter().cloned());
        let mut state_paths = Vec::with_capacity(total_paths);
        state_paths.extend(state_inputs.old_paths);
        state_paths.extend(state_inputs.new_paths);
        ExactStateKillShotInputs {
            slot_leaves,
            state_paths,
        }
    } else {
        ExactStateKillShotInputs {
            slot_leaves: Vec::new(),
            state_paths: Vec::new(),
        }
    };
    let structural =
        structural_inputs_from_verified_roots(inputs, surface, proof, leaf_inputs, roots);
    Ok((legacy, structural))
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

fn validate_inputs(inputs: &ExactStateKillShotInputs) -> Result<(), ExactStateKillShotError> {
    if inputs.slot_leaves.is_empty() || inputs.state_paths.is_empty() {
        return Err(ExactStateKillShotError::EmptyDerivedInput);
    }
    Ok(())
}

pub(crate) fn prove_transitional_exact_state_path_chunks(
    inputs: &ExactStateKillShotInputs,
) -> Result<Vec<noid_gkr::BatchedMerkleProofKillShot>, ExactStateKillShotError> {
    validate_inputs(inputs)?;
    let circuit = MerkleCircuit::build_with_tag(TAG_EXSTNOD);
    let mut channel = Poseidon2bChannel::new();
    Ok(inputs
        .state_paths
        .chunks(EXACT_STATE_MERKLE_PATH_CHUNK_SIZE)
        .map(|paths| prove_batched_merkle_killshot(&circuit, paths, &mut channel).0)
        .collect())
}

pub fn prove_exact_state_killshot(
    inputs: &ExactStateKillShotInputs,
) -> Result<ExactStateKillShotProof, ExactStateKillShotError> {
    validate_inputs(inputs)?;
    let (slot_leaves, state_paths) = rayon::join(
        || {
            let mut channel = Poseidon2bChannel::new();
            prove_batched_slot_leaf_killshot(&inputs.slot_leaves, &mut channel).0
        },
        || {
            prove_transitional_exact_state_path_chunks(inputs)
                .expect("inputs were validated before the parallel proof")
        },
    );
    Ok(ExactStateKillShotProof {
        slot_leaves,
        state_paths,
        structural_hashes: Vec::new(),
    })
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
        state_paths: Vec::new(),
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

pub fn verify_exact_state_killshot(
    inputs: &ExactStateKillShotInputs,
    proof: &ExactStateKillShotProof,
) -> Result<(), ExactStateKillShotError> {
    verify_exact_state_killshot_backend(inputs, proof).map_err(|error| match error {
        BackendExactStateKillShotError::EmptyDerivedInput => {
            ExactStateKillShotError::EmptyDerivedInput
        }
        BackendExactStateKillShotError::SlotLeafProofRejected => {
            ExactStateKillShotError::SlotLeafProofRejected
        }
        BackendExactStateKillShotError::StateMerkleProofRejected => {
            ExactStateKillShotError::StateMerkleProofRejected
        }
        BackendExactStateKillShotError::StructuralFrontier(_) => {
            ExactStateKillShotError::StructuralFrontierRejected
        }
        BackendExactStateKillShotError::StructuralHashProofRejected => {
            ExactStateKillShotError::StructuralHashProofRejected
        }
        BackendExactStateKillShotError::NonCanonicalLegacyPathProof => {
            ExactStateKillShotError::NonCanonicalLegacyPathProof
        }
    })
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
        BackendExactStateKillShotError::StateMerkleProofRejected => {
            ExactStateKillShotError::StateMerkleProofRejected
        }
        BackendExactStateKillShotError::StructuralFrontier(_) => {
            ExactStateKillShotError::StructuralFrontierRejected
        }
        BackendExactStateKillShotError::StructuralHashProofRejected => {
            ExactStateKillShotError::StructuralHashProofRejected
        }
        BackendExactStateKillShotError::NonCanonicalLegacyPathProof => {
            ExactStateKillShotError::NonCanonicalLegacyPathProof
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
    use noid_core::{Block128, TowerField};

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
    fn exact_state_killshot_roundtrip() {
        let (inputs, surface, exact_proof) = fixture();
        let (killshot_inputs, verified) =
            derive_exact_state_killshot_inputs(&inputs, &surface, &exact_proof).unwrap();
        assert_eq!(verified.child_state_root(), inputs.child_state_root);
        let proof = prove_exact_state_killshot(&killshot_inputs).unwrap();
        verify_exact_state_killshot(&killshot_inputs, &proof).unwrap();
        assert!(proof.byte_len(&killshot_inputs) > 0);
    }

    #[test]
    fn exact_state_killshot_rejects_tampered_path_root() {
        let (inputs, surface, exact_proof) = fixture();
        let (mut killshot_inputs, _) =
            derive_exact_state_killshot_inputs(&inputs, &surface, &exact_proof).unwrap();
        let proof = prove_exact_state_killshot(&killshot_inputs).unwrap();
        killshot_inputs.state_paths[0].expected_root[0] += Block128::ONE;
        assert_eq!(
            verify_exact_state_killshot(&killshot_inputs, &proof),
            Err(ExactStateKillShotError::StateMerkleProofRejected)
        );
    }

    #[test]
    fn structural_exact_state_killshot_roundtrip_has_no_paths() {
        let (inputs, surface, exact_proof) = fixture();
        let (structural, verified) =
            derive_exact_state_structural_killshot_inputs(&inputs, &surface, &exact_proof).unwrap();
        assert_eq!(verified.child_state_root(), inputs.child_state_root);
        assert_eq!(structural.touched_indices, surface.touched_indices);
        assert_eq!(structural.live_sibling_digests, exact_proof.slot_siblings);

        let proof = prove_exact_state_structural_killshot(&structural).unwrap();
        assert!(proof.state_paths.is_empty());
        assert!(!proof.structural_hashes.is_empty());
        verify_exact_state_structural_killshot(&structural, &proof).unwrap();
    }

    #[test]
    fn retained_projection_keeps_legacy_at_exact_inline_path_cap() {
        let (inputs, surface, proof) = retained_projection_fixture(128);
        let (verified, roots) =
            crate::exact_state_transition::verify_exact_state_transition_with_roots(
                &inputs, &surface, &proof,
            )
            .unwrap();
        let (legacy, structural) = derive_retained_exact_state_inputs_from_verified_roots(
            &inputs, &surface, &proof, roots,
        )
        .unwrap();

        assert_eq!(verified.child_state_root(), inputs.child_state_root);
        assert_eq!(legacy.slot_leaves.len(), 256);
        assert_eq!(legacy.state_paths.len(), 256);
        assert_eq!(structural.old_slot_leaves.len(), 128);
        assert_eq!(structural.new_slot_leaves.len(), 128);
    }

    #[test]
    fn retained_projection_omits_legacy_above_inline_path_cap() {
        let (inputs, surface, proof) = retained_projection_fixture(129);
        let (_verified, roots) =
            crate::exact_state_transition::verify_exact_state_transition_with_roots(
                &inputs, &surface, &proof,
            )
            .unwrap();
        let (legacy, structural) = derive_retained_exact_state_inputs_from_verified_roots(
            &inputs, &surface, &proof, roots,
        )
        .unwrap();

        assert!(legacy.slot_leaves.is_empty());
        assert!(legacy.state_paths.is_empty());
        assert_eq!(structural.old_slot_leaves.len(), 129);
        assert_eq!(structural.new_slot_leaves.len(), 129);
        noid_recursive::block_certificate_backend::verify_exact_state_structural_frontier(
            &structural,
        )
        .unwrap();
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

        let (legacy_inputs, _) =
            derive_exact_state_killshot_inputs(&inputs, &surface, &exact_proof).unwrap();
        let legacy_proof = prove_exact_state_killshot(&legacy_inputs).unwrap();
        let mut mixed = proof;
        mixed.state_paths = legacy_proof.state_paths;
        verify_exact_state_structural_killshot(&structural, &mixed).unwrap();
        verify_exact_state_killshot(&legacy_inputs, &mixed).unwrap();
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
