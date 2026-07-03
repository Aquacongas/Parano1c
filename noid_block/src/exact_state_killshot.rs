// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Composed KillShot proof for exact-state hash and Merkle subrelations.
//!
//! This module does not replace the exact action/counter proof obligation.
//! It proves that the derived slot leaves, UTXO paths, ReuseGuard paths, bucket
//! hashes, and composite roots are valid Poseidon2b relations under the
//! production domains.

use noid_chain::reuse_guard::ReuseGuard;
use noid_chain::state_delta::ExactActionSurface;
use noid_gkr::{
    prove_batched_guard_bucket_killshot, prove_batched_merkle_killshot,
    prove_batched_slot_leaf_killshot, prove_batched_state_root_killshot, MerkleCircuit,
};
use noid_poseidon2b::channel::Poseidon2bChannel;
use noid_poseidon2b::native::domain::{TAG_EXSTNOD, TAG_RGDNODE};
use noid_recursive::block_certificate_backend::{
    verify_exact_state_killshot as verify_exact_state_killshot_backend,
    ExactStateKillShotError as BackendExactStateKillShotError,
};

use crate::exact_state_transition::{
    derive_exact_composite_state_root_inputs, derive_exact_guard_bucket_hash_inputs,
    derive_exact_guard_merkle_batch_inputs, derive_exact_slot_leaf_batch_inputs,
    derive_exact_state_merkle_batch_inputs, verify_exact_state_transition,
    ExactStateTransitionError, ExactStateTransitionInputs, ExactStateTransitionProof,
    VerifiedStateTransition,
};

// Shared with the dependency-clean recursive verifier language — the wrapper
// types live in one place so the verifier logic cannot fork between the block
// path and the O(1) path (they used to be 1:1 mirrors with per-verify deep
// conversions).
pub use noid_recursive::block_certificate_backend::{
    ExactStateKillShotInputs, ExactStateKillShotProof,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExactStateKillShotError {
    ExactState(ExactStateTransitionError),
    EmptyDerivedInput,
    GuardPresenceMismatch,
    SlotLeafProofRejected,
    StateMerkleProofRejected,
    GuardBucketProofRejected,
    GuardMerkleProofRejected,
    StateRootProofRejected,
}

impl From<ExactStateTransitionError> for ExactStateKillShotError {
    fn from(error: ExactStateTransitionError) -> Self {
        Self::ExactState(error)
    }
}

pub fn derive_exact_state_killshot_inputs(
    inputs: &ExactStateTransitionInputs,
    surface: &ExactActionSurface,
    guard: &ReuseGuard,
    proof: &ExactStateTransitionProof,
) -> Result<(ExactStateKillShotInputs, VerifiedStateTransition), ExactStateKillShotError> {
    let verified = verify_exact_state_transition(inputs, surface, guard, proof)?;

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

    let guard_buckets = derive_exact_guard_bucket_hash_inputs(inputs, surface, guard, proof)?
        .map(|derived| vec![derived.old_bucket, derived.new_bucket]);
    let guard_paths = derive_exact_guard_merkle_batch_inputs(inputs, surface, guard, proof)?
        .map(|derived| vec![derived.old_path, derived.new_path]);

    if guard_buckets.is_some() != guard_paths.is_some() {
        return Err(ExactStateKillShotError::GuardPresenceMismatch);
    }

    let root_inputs = derive_exact_composite_state_root_inputs(inputs, &verified);
    let state_roots = vec![root_inputs.parent, root_inputs.child];

    Ok((
        ExactStateKillShotInputs {
            slot_leaves,
            state_paths,
            guard_buckets,
            guard_paths,
            state_roots,
        },
        verified,
    ))
}

fn validate_inputs(inputs: &ExactStateKillShotInputs) -> Result<(), ExactStateKillShotError> {
    if inputs.slot_leaves.is_empty()
        || inputs.state_paths.is_empty()
        || inputs.state_roots.is_empty()
        || inputs.state_roots.len() % 2 != 0
    {
        return Err(ExactStateKillShotError::EmptyDerivedInput);
    }
    if inputs.guard_buckets.is_some() != inputs.guard_paths.is_some() {
        return Err(ExactStateKillShotError::GuardPresenceMismatch);
    }
    Ok(())
}

pub fn prove_exact_state_killshot(
    inputs: &ExactStateKillShotInputs,
) -> Result<ExactStateKillShotProof, ExactStateKillShotError> {
    validate_inputs(inputs)?;

    let (slot_leaves, (state_paths, (guard_buckets, (guard_paths, state_roots)))) = rayon::join(
        || {
            let mut channel = Poseidon2bChannel::new();
            prove_batched_slot_leaf_killshot(&inputs.slot_leaves, &mut channel).0
        },
        || {
            rayon::join(
                || {
                    let circuit = MerkleCircuit::build_with_tag(TAG_EXSTNOD);
                    let mut channel = Poseidon2bChannel::new();
                    prove_batched_merkle_killshot(&circuit, &inputs.state_paths, &mut channel).0
                },
                || {
                    rayon::join(
                        || {
                            inputs.guard_buckets.as_ref().map(|guard_buckets| {
                                let mut channel = Poseidon2bChannel::new();
                                prove_batched_guard_bucket_killshot(guard_buckets, &mut channel).0
                            })
                        },
                        || {
                            rayon::join(
                                || {
                                    inputs.guard_paths.as_ref().map(|guard_paths| {
                                        let circuit = MerkleCircuit::build_with_tag(TAG_RGDNODE);
                                        let mut channel = Poseidon2bChannel::new();
                                        prove_batched_merkle_killshot(
                                            &circuit,
                                            guard_paths,
                                            &mut channel,
                                        )
                                        .0
                                    })
                                },
                                || {
                                    let mut channel = Poseidon2bChannel::new();
                                    prove_batched_state_root_killshot(
                                        &inputs.state_roots,
                                        &mut channel,
                                    )
                                    .0
                                },
                            )
                        },
                    )
                },
            )
        },
    );

    Ok(ExactStateKillShotProof {
        slot_leaves,
        state_paths,
        guard_buckets,
        guard_paths,
        state_roots,
    })
}

/// Delegates to the canonical verifier in
/// `noid_recursive::block_certificate_backend` — the logic used to be
/// duplicated here line-for-line on mirror types; one copy must stay the
/// single reference the SVT trace shadows (roadmap O1b / risk R5).
pub fn verify_exact_state_killshot(
    inputs: &ExactStateKillShotInputs,
    proof: &ExactStateKillShotProof,
) -> Result<(), ExactStateKillShotError> {
    verify_exact_state_killshot_backend(inputs, proof).map_err(|error| match error {
        BackendExactStateKillShotError::EmptyDerivedInput => {
            ExactStateKillShotError::EmptyDerivedInput
        }
        BackendExactStateKillShotError::GuardPresenceMismatch => {
            ExactStateKillShotError::GuardPresenceMismatch
        }
        BackendExactStateKillShotError::SlotLeafProofRejected => {
            ExactStateKillShotError::SlotLeafProofRejected
        }
        BackendExactStateKillShotError::StateMerkleProofRejected => {
            ExactStateKillShotError::StateMerkleProofRejected
        }
        BackendExactStateKillShotError::GuardBucketProofRejected => {
            ExactStateKillShotError::GuardBucketProofRejected
        }
        BackendExactStateKillShotError::GuardMerkleProofRejected => {
            ExactStateKillShotError::GuardMerkleProofRejected
        }
        BackendExactStateKillShotError::StateRootProofRejected => {
            ExactStateKillShotError::StateRootProofRejected
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use noid_chain::exact_state_hash::{composite_state_root, slot_leaf_hash, StateHash};
    use noid_chain::fri_state::SlotValue;
    use noid_chain::reuse_guard::ReuseGuard;
    use noid_chain::sparse_merkle::SparseMerkleCache;
    use noid_chain::state_delta::{ExactActionSurface, StateDeltaAction, StateDeltaActionKind};
    use noid_core::{Block128, TowerField};

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

    fn surface(old: SlotValue, new: SlotValue) -> ExactActionSurface {
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
        guard: &ReuseGuard,
        child_guard_root: StateHash,
    ) -> ExactStateTransitionInputs {
        ExactStateTransitionInputs {
            parent_state_root: composite_state_root(4, parent_cache.root(), guard.root()),
            parent_log_slots: 4,
            parent_utxo_root: parent_cache.root(),
            parent_guard_root: guard.root(),
            child_state_root: composite_state_root(
                4,
                {
                    let child =
                        SparseMerkleCache::from_leaves(4, &[(5, slot_leaf_hash(sv(7, 200)))])
                            .unwrap();
                    child.root()
                },
                child_guard_root,
            ),
            child_log_slots: 4,
            height: 10,
            parent_active_slot_count: 1,
            parent_alloc_counter: 1,
        }
    }

    #[test]
    fn exact_state_killshot_roundtrip() {
        let old = sv(10, 100);
        let new = sv(7, 200);
        let surface = surface(old, new);
        let parent_cache = SparseMerkleCache::from_leaves(4, &[(2, slot_leaf_hash(old))]).unwrap();
        let guard = ReuseGuard::new_empty();
        let mut next_guard = guard.clone();
        next_guard.apply_spends(10, &[2]).unwrap();
        let inputs = inputs_for(&parent_cache, &guard, next_guard.root());
        let exact_proof =
            crate::build_exact_state_transition_proof(&parent_cache, &surface, &guard, 10).unwrap();

        let (killshot_inputs, verified) =
            derive_exact_state_killshot_inputs(&inputs, &surface, &guard, &exact_proof).unwrap();
        assert_eq!(verified.child_state_root(), inputs.child_state_root);
        let proof = prove_exact_state_killshot(&killshot_inputs).unwrap();
        verify_exact_state_killshot(&killshot_inputs, &proof).unwrap();
        assert!(proof.byte_len(&killshot_inputs) > 0);
    }

    #[test]
    fn exact_state_killshot_rejects_tampered_slot_leaf_statement() {
        let old = sv(10, 100);
        let new = sv(7, 200);
        let surface = surface(old, new);
        let parent_cache = SparseMerkleCache::from_leaves(4, &[(2, slot_leaf_hash(old))]).unwrap();
        let guard = ReuseGuard::new_empty();
        let mut next_guard = guard.clone();
        next_guard.apply_spends(10, &[2]).unwrap();
        let inputs = inputs_for(&parent_cache, &guard, next_guard.root());
        let exact_proof =
            crate::build_exact_state_transition_proof(&parent_cache, &surface, &guard, 10).unwrap();
        let (mut killshot_inputs, _) =
            derive_exact_state_killshot_inputs(&inputs, &surface, &guard, &exact_proof).unwrap();
        let proof = prove_exact_state_killshot(&killshot_inputs).unwrap();
        killshot_inputs.slot_leaves[0].expected_leaf[0] += Block128::ONE;
        assert_eq!(
            verify_exact_state_killshot(&killshot_inputs, &proof),
            Err(ExactStateKillShotError::SlotLeafProofRejected)
        );
    }
}
