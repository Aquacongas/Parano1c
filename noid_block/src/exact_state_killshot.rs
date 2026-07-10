// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Composed KillShot proof for exact slot-leaf and UTXO-path relations.
//!
//! This does not replace the C' action/counter/recombination obligation. It
//! proves only the two Poseidon2b families derived from the canonical exact
//! transition: EXSTSLT leaf hashes and EXSTNOD Merkle paths.

use noid_chain::state_delta::ExactActionSurface;
use noid_gkr::{prove_batched_merkle_killshot, prove_batched_slot_leaf_killshot, MerkleCircuit};
use noid_poseidon2b::channel::Poseidon2bChannel;
use noid_poseidon2b::native::domain::TAG_EXSTNOD;
use noid_recursive::block_certificate_backend::{
    verify_exact_state_killshot as verify_exact_state_killshot_backend,
    ExactStateKillShotError as BackendExactStateKillShotError,
};

use crate::exact_state_transition::{
    derive_exact_slot_leaf_batch_inputs, derive_exact_state_merkle_batch_inputs,
    seal_exact_state_transition, ExactStateTransitionError, ExactStateTransitionInputs,
    ExactStateTransitionProof, VerifiedStateTransition,
};

pub use noid_recursive::block_certificate_backend::{
    ExactStateKillShotInputs, ExactStateKillShotProof,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExactStateKillShotError {
    ExactState(ExactStateTransitionError),
    EmptyDerivedInput,
    SlotLeafProofRejected,
    StateMerkleProofRejected,
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

fn validate_inputs(inputs: &ExactStateKillShotInputs) -> Result<(), ExactStateKillShotError> {
    if inputs.slot_leaves.is_empty() || inputs.state_paths.is_empty() {
        return Err(ExactStateKillShotError::EmptyDerivedInput);
    }
    Ok(())
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
            let circuit = MerkleCircuit::build_with_tag(TAG_EXSTNOD);
            let mut channel = Poseidon2bChannel::new();
            prove_batched_merkle_killshot(&circuit, &inputs.state_paths, &mut channel).0
        },
    );
    Ok(ExactStateKillShotProof {
        slot_leaves,
        state_paths,
    })
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
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::build_exact_state_transition_proof;
    use noid_chain::exact_state_hash::slot_leaf_hash;
    use noid_chain::fri_state::SlotValue;
    use noid_chain::sparse_merkle::SparseMerkleCache;
    use noid_chain::state_delta::{
        exact_action_surface_from_surface, StateDeltaAction, StateDeltaActionKind,
        StateDeltaActionSurface,
    };
    use noid_core::{Block128, TowerField};

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
}
