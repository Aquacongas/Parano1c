// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Proof-facing verifier for accepted-block certificate batch components.
//!
//! `noid_block` owns block production and retained native replay. This module
//! owns the dependency-clean verifier language that the final O(1) recursive
//! checkpoint backend must prove after `noid_block` has replayed existing
//! `BlockProof`/`BlockAuthSidecar` bytes and reduced them into canonical proof
//! components. This module does not deserialize block bodies or replace the
//! production block verifier in `noid_block`.

use noid_core::Block128;
use noid_gkr::{
    discharge_accepted_claim_hash_reductions_native, discharge_batched_merkle_reductions_native,
    discharge_batched_slot_leaf_reductions_native, discharge_block_spine_reductions_native,
    reconstruct_slot_states, verify_accepted_claim_hash_killshot,
    verify_authorization_statement_proof, verify_batched_merkle_killshot,
    verify_batched_slot_leaf_killshot, verify_block_spine_killshot, AcceptedClaimHashInputs,
    AcceptedClaimHashProofKillShot, BatchedMerkleProofKillShot, BatchedSlotLeafProofKillShot,
    BlockSpineProof, CanonicalAuthorizationStatement, MerkleCircuit, MerklePathInputs,
    OwnerAuthProofKillShot, OwnerAuthPublicInputs, SlotLeafInputs, SpineCircuit, SpineInputs,
    VerifiedAuthorizationBatch,
};
use noid_poseidon2b::channel::Poseidon2bChannel;
use noid_poseidon2b::native::domain::TAG_EXSTNOD;
use rayon::prelude::*;

use crate::accepted_batch::{
    verify_accepted_claim_batch_with_header_trace, AcceptedClaimBatchError,
    AcceptedClaimBatchOutput, AcceptedClaimBatchWitness,
};
use crate::accumulator::ChainAccumulator;
use crate::authorization::AuthorizationVerifierTrace;
use crate::block_certificate::{
    accepted_block_certificate_chain_claim, AcceptedBlockCertificateStatement,
};
use crate::checkpoint::{
    verify_checkpoint_poseidon, CheckpointPoseidonError, CheckpointPoseidonProof,
};
use crate::header_integer::HeaderIntegerBatchTrace;
use crate::pow_header::RecursiveConsensusState;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AuthorizationComponentInput {
    pub block_index: usize,
    pub tx_index: usize,
    pub tx_body_hash: [Block128; 2],
    /// Transitional canonical-body metadata. C' pins this byte to the
    /// transaction validity bitmap; it is deliberately not OwnerAuth public.
    pub live_input_count: u8,
    pub public: OwnerAuthPublicInputs,
}

fn authorization_component_input_shape_ok(input: &AuthorizationComponentInput) -> bool {
    input.public.layout == noid_gkr::OwnerAuthLayout::FIXED
        && (1..=noid_gkr::MAX_AUTHORIZATION_LIVE_INPUTS).contains(&input.live_input_count)
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ExactStateKillShotInputs {
    pub slot_leaves: Vec<SlotLeafInputs>,
    pub state_paths: Vec<MerklePathInputs>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ExactStateKillShotProof {
    pub slot_leaves: BatchedSlotLeafProofKillShot,
    pub state_paths: BatchedMerkleProofKillShot,
}

impl ExactStateKillShotProof {
    pub fn byte_len(&self, inputs: &ExactStateKillShotInputs) -> usize {
        self.slot_leaves.byte_len() + self.state_paths.byte_len(&inputs.state_paths)
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AcceptedBlockBatchComponentInputs {
    pub accepted_claim_witness: AcceptedClaimBatchWitness,
    pub accepted_block_certificate_statements: Vec<AcceptedBlockCertificateStatement>,
    pub accepted_claim_hash_inputs: Vec<AcceptedClaimHashInputs>,
    pub tx_body_inputs: Vec<SpineInputs>,
    pub tx_body_hashes: Vec<[Block128; 2]>,
    pub tx_root_inputs: Vec<MerklePathInputs>,
    pub header_integer_trace: HeaderIntegerBatchTrace,
    pub authorization_inputs: Vec<AuthorizationComponentInput>,
    pub authorization_witnesses: Vec<OwnerAuthProofKillShot>,
    pub authorization_traces: Vec<AuthorizationVerifierTrace>,
    pub exact_state_killshot_inputs: Vec<ExactStateKillShotInputs>,
    pub authorization_totals: VerifiedAuthorizationBatch,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AcceptedBlockBatchComponentProof {
    pub accepted_claim_hash: AcceptedClaimHashProofKillShot,
    pub tx_body: Option<BlockSpineProof>,
    pub tx_root: Option<BatchedMerkleProofKillShot>,
    pub checkpoint_poseidon: CheckpointPoseidonProof,
    pub exact_state: Vec<ExactStateKillShotProof>,
}

impl AcceptedBlockBatchComponentProof {
    pub fn byte_len(&self, inputs: &AcceptedBlockBatchComponentInputs) -> usize {
        self.accepted_claim_hash.byte_len()
            + self.tx_body.as_ref().map_or(0, BlockSpineProof::byte_len)
            + self
                .tx_root
                .as_ref()
                .map_or(0, |proof| proof.byte_len(&inputs.tx_root_inputs))
            + self.checkpoint_poseidon.byte_len()
            + self
                .exact_state
                .iter()
                .zip(inputs.exact_state_killshot_inputs.iter())
                .map(|(proof, inputs)| proof.byte_len(inputs))
                .sum::<usize>()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExactStateKillShotError {
    EmptyDerivedInput,
    SlotLeafProofRejected,
    StateMerkleProofRejected,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcceptedBlockBatchComponentError {
    ComponentShapeMismatch,
    CertificateStatementMismatch {
        index: usize,
    },
    AcceptedClaimHashProofRejected,
    TxBodyHashProofRejected,
    TxRootProofRejected,
    AuthorizationProofRejected {
        index: usize,
        tx_index: usize,
    },
    AcceptedClaimBatch(AcceptedClaimBatchError),
    CheckpointPoseidon(CheckpointPoseidonError),
    ExactState {
        index: usize,
        source: ExactStateKillShotError,
    },
}

pub fn verify_accepted_block_batch_components(
    start_consensus: &RecursiveConsensusState,
    start_accumulator: &ChainAccumulator,
    end_accumulator: &ChainAccumulator,
    inputs: &AcceptedBlockBatchComponentInputs,
    proof: &AcceptedBlockBatchComponentProof,
) -> Result<AcceptedClaimBatchOutput, AcceptedBlockBatchComponentError> {
    validate_component_shape(inputs, proof)?;
    validate_certificate_statement_component_shape(inputs)?;

    // All component verifications are independent, so run them as one parallel
    // join tree (mirroring the prover side in `noid_block`). Results are
    // unwrapped below in the same order the old sequential code checked them,
    // so error precedence is unchanged when several components fail at once.
    let (
        (claim_hash_result, tx_body_result),
        (
            (tx_root_result, authorization_result),
            (claim_batch_result, (checkpoint_result, exact_state_result)),
        ),
    ) = rayon::join(
        || {
            rayon::join(
                || verify_accepted_claim_hash_component(inputs, proof),
                || verify_tx_body_component(inputs, proof),
            )
        },
        || {
            rayon::join(
                || {
                    rayon::join(
                        || verify_tx_root_component(inputs, proof),
                        || verify_authorization_components(inputs),
                    )
                },
                || {
                    rayon::join(
                        || {
                            verify_accepted_claim_batch_with_header_trace(
                                start_consensus,
                                start_accumulator,
                                &inputs.accepted_claim_witness,
                                &inputs.header_integer_trace,
                            )
                            .map_err(AcceptedBlockBatchComponentError::AcceptedClaimBatch)
                        },
                        || {
                            rayon::join(
                                || {
                                    verify_checkpoint_poseidon(
                                        &inputs.accepted_claim_witness,
                                        &proof.checkpoint_poseidon,
                                    )
                                    .map_err(AcceptedBlockBatchComponentError::CheckpointPoseidon)
                                },
                                || {
                                    inputs
                                        .exact_state_killshot_inputs
                                        .par_iter()
                                        .zip(proof.exact_state.par_iter())
                                        .enumerate()
                                        .try_for_each(|(index, (inputs, proof))| {
                                            verify_exact_state_killshot(inputs, proof).map_err(
                                                |source| {
                                                    AcceptedBlockBatchComponentError::ExactState {
                                                        index,
                                                        source,
                                                    }
                                                },
                                            )
                                        })
                                },
                            )
                        },
                    )
                },
            )
        },
    );

    claim_hash_result?;
    tx_body_result?;
    tx_root_result?;
    authorization_result?;
    let accepted_claim_batch = claim_batch_result?;
    if accepted_claim_batch.accumulator != *end_accumulator {
        return Err(AcceptedBlockBatchComponentError::ComponentShapeMismatch);
    }
    checkpoint_result?;
    exact_state_result?;

    Ok(accepted_claim_batch)
}

pub fn verify_exact_state_killshot(
    inputs: &ExactStateKillShotInputs,
    proof: &ExactStateKillShotProof,
) -> Result<(), ExactStateKillShotError> {
    validate_exact_state_inputs(inputs)?;

    let (slot_result, state_result) = rayon::join(
        || {
            let mut channel = Poseidon2bChannel::new();
            let reductions = verify_batched_slot_leaf_killshot(
                &proof.slot_leaves,
                &inputs.slot_leaves,
                &mut channel,
            )
            .ok_or(ExactStateKillShotError::SlotLeafProofRejected)?;
            if discharge_batched_slot_leaf_reductions_native(&inputs.slot_leaves, &reductions) {
                Ok(())
            } else {
                Err(ExactStateKillShotError::SlotLeafProofRejected)
            }
        },
        || {
            let circuit = MerkleCircuit::build_with_tag(TAG_EXSTNOD);
            let mut channel = Poseidon2bChannel::new();
            let reductions = verify_batched_merkle_killshot(
                &circuit,
                &proof.state_paths,
                &inputs.state_paths,
                &mut channel,
            )
            .ok_or(ExactStateKillShotError::StateMerkleProofRejected)?;
            if discharge_batched_merkle_reductions_native(
                &circuit,
                &inputs.state_paths,
                &reductions,
            ) {
                Ok(())
            } else {
                Err(ExactStateKillShotError::StateMerkleProofRejected)
            }
        },
    );
    slot_result?;
    state_result?;
    Ok(())
}

fn validate_component_shape(
    inputs: &AcceptedBlockBatchComponentInputs,
    proof: &AcceptedBlockBatchComponentProof,
) -> Result<(), AcceptedBlockBatchComponentError> {
    if inputs.exact_state_killshot_inputs.len() != proof.exact_state.len()
        || inputs.authorization_inputs.len() != inputs.authorization_witnesses.len()
        || inputs.authorization_traces.len() != inputs.authorization_witnesses.len()
        || inputs.accepted_claim_hash_inputs.len()
            != inputs.accepted_claim_witness.accepted_block_claims.len()
        || inputs.tx_body_inputs.len() != inputs.tx_body_hashes.len()
    {
        return Err(AcceptedBlockBatchComponentError::ComponentShapeMismatch);
    }
    if inputs
        .authorization_inputs
        .iter()
        .any(|input| !authorization_component_input_shape_ok(input))
    {
        return Err(AcceptedBlockBatchComponentError::ComponentShapeMismatch);
    }
    Ok(())
}

fn validate_certificate_statement_component_shape(
    inputs: &AcceptedBlockBatchComponentInputs,
) -> Result<(), AcceptedBlockBatchComponentError> {
    let headers = &inputs.accepted_claim_witness.headers;
    let claims = &inputs.accepted_claim_witness.accepted_block_claims;
    let statements = &inputs.accepted_block_certificate_statements;
    if statements.len() != headers.len() || statements.len() != claims.len() {
        return Err(AcceptedBlockBatchComponentError::ComponentShapeMismatch);
    }
    for (index, ((statement, header_witness), chain_claim)) in statements
        .iter()
        .zip(headers.iter())
        .zip(claims.iter().copied())
        .enumerate()
    {
        if statement.block_id != header_witness.block_id
            || statement.height != header_witness.header.height
            || statement.child_state_root != header_witness.header.state_root
            || statement.tx_root != header_witness.header.tx_root
            || accepted_block_certificate_chain_claim(statement) != chain_claim
        {
            return Err(AcceptedBlockBatchComponentError::CertificateStatementMismatch { index });
        }
    }
    Ok(())
}

fn verify_accepted_claim_hash_component(
    inputs: &AcceptedBlockBatchComponentInputs,
    proof: &AcceptedBlockBatchComponentProof,
) -> Result<(), AcceptedBlockBatchComponentError> {
    for (input, claim) in inputs
        .accepted_claim_hash_inputs
        .iter()
        .zip(inputs.accepted_claim_witness.accepted_block_claims.iter())
    {
        if input.expected_claim != *claim {
            return Err(AcceptedBlockBatchComponentError::ComponentShapeMismatch);
        }
    }
    let mut channel = Poseidon2bChannel::new();
    let reductions = verify_accepted_claim_hash_killshot(
        &proof.accepted_claim_hash,
        &inputs.accepted_claim_hash_inputs,
        &mut channel,
    )
    .ok_or(AcceptedBlockBatchComponentError::AcceptedClaimHashProofRejected)?;
    if discharge_accepted_claim_hash_reductions_native(
        &inputs.accepted_claim_hash_inputs,
        &reductions,
    ) {
        Ok(())
    } else {
        Err(AcceptedBlockBatchComponentError::AcceptedClaimHashProofRejected)
    }
}

fn verify_tx_body_component(
    inputs: &AcceptedBlockBatchComponentInputs,
    proof: &AcceptedBlockBatchComponentProof,
) -> Result<(), AcceptedBlockBatchComponentError> {
    if inputs.tx_body_inputs.is_empty() {
        if proof.tx_body.is_some() {
            return Err(AcceptedBlockBatchComponentError::ComponentShapeMismatch);
        }
        return Ok(());
    }
    let tx_body_proof = proof
        .tx_body
        .as_ref()
        .ok_or(AcceptedBlockBatchComponentError::ComponentShapeMismatch)?;
    let mut channel = Poseidon2bChannel::new();
    let reductions = verify_block_spine_killshot(
        tx_body_proof,
        inputs.tx_body_inputs.len(),
        &inputs.tx_body_hashes,
        &mut channel,
    )
    .ok_or(AcceptedBlockBatchComponentError::TxBodyHashProofRejected)?;
    let slot_state_ins = tx_body_slot_state_ins(&inputs.tx_body_inputs);
    if discharge_block_spine_reductions_native(
        inputs.tx_body_inputs.len(),
        &slot_state_ins,
        &reductions,
    ) {
        Ok(())
    } else {
        Err(AcceptedBlockBatchComponentError::TxBodyHashProofRejected)
    }
}

fn verify_tx_root_component(
    inputs: &AcceptedBlockBatchComponentInputs,
    proof: &AcceptedBlockBatchComponentProof,
) -> Result<(), AcceptedBlockBatchComponentError> {
    if inputs.tx_root_inputs.is_empty() {
        if proof.tx_root.is_some() {
            return Err(AcceptedBlockBatchComponentError::ComponentShapeMismatch);
        }
        return Ok(());
    }
    let tx_root_proof = proof
        .tx_root
        .as_ref()
        .ok_or(AcceptedBlockBatchComponentError::ComponentShapeMismatch)?;
    let circuit = MerkleCircuit::build();
    let mut channel = Poseidon2bChannel::new();
    let reductions = verify_batched_merkle_killshot(
        &circuit,
        tx_root_proof,
        &inputs.tx_root_inputs,
        &mut channel,
    )
    .ok_or(AcceptedBlockBatchComponentError::TxRootProofRejected)?;
    if discharge_batched_merkle_reductions_native(&circuit, &inputs.tx_root_inputs, &reductions) {
        Ok(())
    } else {
        Err(AcceptedBlockBatchComponentError::TxRootProofRejected)
    }
}

fn verify_authorization_components(
    inputs: &AcceptedBlockBatchComponentInputs,
) -> Result<(), AcceptedBlockBatchComponentError> {
    if inputs.authorization_inputs.len() != inputs.authorization_totals.user_tx_count {
        return Err(AcceptedBlockBatchComponentError::ComponentShapeMismatch);
    }
    let auth_counts = inputs
        .authorization_inputs
        .par_iter()
        .zip(inputs.authorization_witnesses.par_iter())
        .enumerate()
        .map(|(index, (input, proof))| {
            let statement = CanonicalAuthorizationStatement {
                tx_index: input.tx_index,
                tx_body_hash: input.tx_body_hash,
                live_input_count: input.live_input_count,
                public: input.public.clone(),
            };
            let verified =
                verify_authorization_statement_proof(&statement, proof).map_err(|_| {
                    AcceptedBlockBatchComponentError::AuthorizationProofRejected {
                        index,
                        tx_index: input.tx_index,
                    }
                })?;
            Ok(verified.live_input_count)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let live_input_count_total = auth_counts.iter().sum::<usize>();
    if live_input_count_total != inputs.authorization_totals.live_input_count_total {
        return Err(AcceptedBlockBatchComponentError::ComponentShapeMismatch);
    }
    Ok(())
}

fn validate_exact_state_inputs(
    inputs: &ExactStateKillShotInputs,
) -> Result<(), ExactStateKillShotError> {
    if inputs.slot_leaves.is_empty() || inputs.state_paths.is_empty() {
        return Err(ExactStateKillShotError::EmptyDerivedInput);
    }
    if inputs.slot_leaves.len() != inputs.state_paths.len() || inputs.state_paths.len() % 2 != 0 {
        return Err(ExactStateKillShotError::EmptyDerivedInput);
    }
    let half = inputs.state_paths.len() / 2;
    let depth = inputs.state_paths[0].active_depth;
    let old_root = inputs.state_paths[0].expected_root;
    let new_root = inputs.state_paths[half].expected_root;
    if inputs.state_paths.iter().enumerate().any(|(index, path)| {
        path.active_depth != depth
            || path.leaf != inputs.slot_leaves[index].expected_leaf
            || path.expected_root != if index < half { old_root } else { new_root }
    }) {
        return Err(ExactStateKillShotError::StateMerkleProofRejected);
    }
    Ok(())
}

fn tx_body_slot_state_ins(inputs: &[SpineInputs]) -> Vec<[Block128; 4]> {
    let circuit = SpineCircuit::build();
    let mut slot_state_ins = Vec::new();
    for input in inputs {
        slot_state_ins.extend(
            reconstruct_slot_states(&circuit, input)
                .iter()
                .map(|(state_in, _)| *state_in),
        );
    }
    slot_state_ins
}

#[cfg(test)]
mod tests {
    use super::*;

    fn authorization_component_input() -> AuthorizationComponentInput {
        AuthorizationComponentInput {
            block_index: 0,
            tx_index: 0,
            tx_body_hash: [Block128::from(7u128), Block128::from(8u128)],
            live_input_count: 1,
            public: OwnerAuthPublicInputs::new(
                [Block128::from(7u128), Block128::from(8u128)],
                [Block128::from(9u128), Block128::from(10u128)],
            ),
        }
    }

    #[test]
    fn authorization_component_boundary_rejects_bad_live_count() {
        let valid = authorization_component_input();
        assert!(authorization_component_input_shape_ok(&valid));

        for count in [0, noid_gkr::MAX_AUTHORIZATION_LIVE_INPUTS + 1] {
            let mut bad_count = valid.clone();
            bad_count.live_input_count = count;
            assert!(!authorization_component_input_shape_ok(&bad_count));
        }
    }
}
