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
    discharge_accepted_claim_hash_reductions_native,
    discharge_batched_guard_bucket_reductions_native, discharge_batched_merkle_reductions_native,
    discharge_batched_slot_leaf_reductions_native, discharge_batched_state_root_reductions_native,
    discharge_block_spine_reductions_native, discharge_sweep_block_spine_reductions_native,
    reconstruct_slot_states, verify_accepted_claim_hash_killshot,
    verify_authorization_statement_proof, verify_batched_guard_bucket_killshot,
    verify_batched_merkle_killshot, verify_batched_slot_leaf_killshot,
    verify_batched_state_root_killshot, verify_block_spine_killshot,
    verify_sweep_block_spine_killshot, AcceptedClaimHashInputs, AcceptedClaimHashProofKillShot,
    BatchedGuardBucketProofKillShot, BatchedMerkleProofKillShot, BatchedSlotLeafProofKillShot,
    BatchedStateRootProofKillShot, BlockSpineProof, CanonicalAuthorizationStatement,
    CompositeStateRootInputs, GuardBucketHashInputs, MerkleCircuit, MerklePathInputs,
    OwnerAuthProofKillShot, OwnerAuthPublicInputs, SlotLeafInputs, SpineCircuit, SpineInputs,
    SweepBlockSpineProof, SweepSpineInputs, VerifiedAuthorizationBatch,
};
use noid_poseidon2b::channel::Poseidon2bChannel;
use noid_poseidon2b::native::domain::{TAG_EXSTNOD, TAG_RGDNODE};
use rayon::prelude::*;

use crate::accepted_batch::{
    verify_accepted_claim_batch_with_header_trace, AcceptedClaimBatchError,
    AcceptedClaimBatchOutput, AcceptedClaimBatchWitness,
};
use crate::accumulator::ChainAccumulator;
use crate::authorization::{AuthorizationVerifierTrace, FiatShamirTraceOp};
use crate::block_certificate::{
    accepted_block_certificate_chain_claim_v1, AcceptedBlockCertificateStatementV1,
    ACCEPTED_BLOCK_CERTIFICATE_STATEMENT_VERSION,
};
use crate::checkpoint::{
    verify_checkpoint_poseidon, CheckpointPoseidonError, CheckpointPoseidonProof,
};
use crate::fs_transcript::{
    discharge_fiat_shamir_transcript_batch_reductions_native,
    verify_fiat_shamir_transcript_batch_killshot, FiatShamirTranscriptBatchProofKillShot,
};
use crate::header_integer::HeaderIntegerBatchTrace;
use crate::pow_header::RecursiveConsensusState;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationComponentInputV1 {
    pub block_index: usize,
    pub tx_index: usize,
    pub tx_body_hash: [Block128; 2],
    pub public: OwnerAuthPublicInputs,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExactStateKillShotInputsV1 {
    pub slot_leaves: Vec<SlotLeafInputs>,
    pub state_paths: Vec<MerklePathInputs>,
    pub guard_buckets: Option<Vec<GuardBucketHashInputs>>,
    pub guard_paths: Option<Vec<MerklePathInputs>>,
    pub state_roots: Vec<CompositeStateRootInputs>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExactStateKillShotProofV1 {
    pub slot_leaves: BatchedSlotLeafProofKillShot,
    pub state_paths: BatchedMerkleProofKillShot,
    pub guard_buckets: Option<BatchedGuardBucketProofKillShot>,
    pub guard_paths: Option<BatchedMerkleProofKillShot>,
    pub state_roots: BatchedStateRootProofKillShot,
}

impl ExactStateKillShotProofV1 {
    pub fn byte_len(&self, inputs: &ExactStateKillShotInputsV1) -> usize {
        self.slot_leaves.byte_len()
            + self.state_paths.byte_len(&inputs.state_paths)
            + self
                .guard_buckets
                .as_ref()
                .map_or(0, BatchedGuardBucketProofKillShot::byte_len)
            + self
                .guard_paths
                .as_ref()
                .zip(inputs.guard_paths.as_ref())
                .map_or(0, |(proof, paths)| proof.byte_len(paths))
            + self.state_roots.byte_len()
    }
}

#[derive(Debug, Clone)]
pub struct AcceptedBlockBatchComponentInputsV1 {
    pub accepted_claim_witness: AcceptedClaimBatchWitness,
    pub accepted_block_certificate_statements: Vec<AcceptedBlockCertificateStatementV1>,
    pub accepted_claim_hash_inputs: Vec<AcceptedClaimHashInputs>,
    pub tx_body_standard_inputs: Vec<SpineInputs>,
    pub tx_body_standard_hashes: Vec<[Block128; 2]>,
    pub tx_body_sweep_inputs: Vec<SweepSpineInputs>,
    pub tx_body_sweep_hashes: Vec<[Block128; 2]>,
    pub tx_root_inputs: Vec<MerklePathInputs>,
    pub header_integer_trace: HeaderIntegerBatchTrace,
    pub authorization_inputs: Vec<AuthorizationComponentInputV1>,
    pub authorization_witnesses: Vec<OwnerAuthProofKillShot>,
    pub authorization_traces: Vec<AuthorizationVerifierTrace>,
    pub exact_state_killshot_inputs: Vec<ExactStateKillShotInputsV1>,
    pub authorization_totals: VerifiedAuthorizationBatch,
}

#[derive(Debug, Clone)]
pub struct AcceptedBlockBatchComponentProofV1 {
    pub accepted_claim_hash: AcceptedClaimHashProofKillShot,
    pub tx_body_standard: Option<BlockSpineProof>,
    pub tx_body_sweep: Option<SweepBlockSpineProof>,
    pub tx_root: Option<BatchedMerkleProofKillShot>,
    pub checkpoint_poseidon: CheckpointPoseidonProof,
    pub exact_state: Vec<ExactStateKillShotProofV1>,
    pub authorization_transcripts: Vec<FiatShamirTranscriptBatchProofKillShot>,
}

impl AcceptedBlockBatchComponentProofV1 {
    pub fn byte_len(&self, inputs: &AcceptedBlockBatchComponentInputsV1) -> usize {
        self.accepted_claim_hash.byte_len()
            + self
                .tx_body_standard
                .as_ref()
                .map_or(0, BlockSpineProof::byte_len)
            + self
                .tx_body_sweep
                .as_ref()
                .map_or(0, SweepBlockSpineProof::byte_len)
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
            + self
                .authorization_transcripts
                .iter()
                .map(FiatShamirTranscriptBatchProofKillShot::byte_len)
                .sum::<usize>()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExactStateKillShotErrorV1 {
    EmptyDerivedInput,
    GuardPresenceMismatch,
    SlotLeafProofRejected,
    StateMerkleProofRejected,
    GuardBucketProofRejected,
    GuardMerkleProofRejected,
    StateRootProofRejected,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcceptedBlockBatchComponentErrorV1 {
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
    AuthorizationTranscriptRejected {
        chunk_index: usize,
        tx_index: usize,
    },
    AcceptedClaimBatch(AcceptedClaimBatchError),
    CheckpointPoseidon(CheckpointPoseidonError),
    ExactState {
        index: usize,
        source: ExactStateKillShotErrorV1,
    },
}

pub fn verify_accepted_block_batch_components_v1(
    start_consensus: &RecursiveConsensusState,
    start_accumulator: &ChainAccumulator,
    end_accumulator: &ChainAccumulator,
    inputs: &AcceptedBlockBatchComponentInputsV1,
    proof: &AcceptedBlockBatchComponentProofV1,
) -> Result<AcceptedClaimBatchOutput, AcceptedBlockBatchComponentErrorV1> {
    validate_component_shape(inputs, proof)?;
    validate_certificate_statement_component_shape(inputs)?;
    verify_accepted_claim_hash_component(inputs, proof)?;
    verify_standard_tx_body_component(inputs, proof)?;
    verify_sweep_tx_body_component(inputs, proof)?;
    verify_tx_root_component(inputs, proof)?;
    verify_authorization_components(inputs)?;
    verify_authorization_transcript_components(inputs, proof)?;

    let accepted_claim_batch = verify_accepted_claim_batch_with_header_trace(
        start_consensus,
        start_accumulator,
        &inputs.accepted_claim_witness,
        &inputs.header_integer_trace,
    )
    .map_err(AcceptedBlockBatchComponentErrorV1::AcceptedClaimBatch)?;
    if accepted_claim_batch.accumulator != *end_accumulator {
        return Err(AcceptedBlockBatchComponentErrorV1::ComponentShapeMismatch);
    }

    verify_checkpoint_poseidon(
        start_accumulator,
        end_accumulator,
        &inputs.accepted_claim_witness,
        &proof.checkpoint_poseidon,
    )
    .map_err(AcceptedBlockBatchComponentErrorV1::CheckpointPoseidon)?;

    inputs
        .exact_state_killshot_inputs
        .par_iter()
        .zip(proof.exact_state.par_iter())
        .enumerate()
        .try_for_each(|(index, (inputs, proof))| {
            verify_exact_state_killshot_v1(inputs, proof)
                .map_err(|source| AcceptedBlockBatchComponentErrorV1::ExactState { index, source })
        })?;

    Ok(accepted_claim_batch)
}

pub fn verify_exact_state_killshot_v1(
    inputs: &ExactStateKillShotInputsV1,
    proof: &ExactStateKillShotProofV1,
) -> Result<(), ExactStateKillShotErrorV1> {
    validate_exact_state_inputs(inputs)?;

    let (slot_result, (state_result, (bucket_result, (guard_path_result, root_result)))) =
        rayon::join(
            || {
                let mut channel = Poseidon2bChannel::new();
                let reductions = verify_batched_slot_leaf_killshot(
                    &proof.slot_leaves,
                    &inputs.slot_leaves,
                    &mut channel,
                )
                .ok_or(ExactStateKillShotErrorV1::SlotLeafProofRejected)?;
                if discharge_batched_slot_leaf_reductions_native(&inputs.slot_leaves, &reductions) {
                    Ok(())
                } else {
                    Err(ExactStateKillShotErrorV1::SlotLeafProofRejected)
                }
            },
            || {
                rayon::join(
                    || {
                        let circuit = MerkleCircuit::build_with_tag(TAG_EXSTNOD);
                        let mut channel = Poseidon2bChannel::new();
                        let reductions = verify_batched_merkle_killshot(
                            &circuit,
                            &proof.state_paths,
                            &inputs.state_paths,
                            &mut channel,
                        )
                        .ok_or(ExactStateKillShotErrorV1::StateMerkleProofRejected)?;
                        if discharge_batched_merkle_reductions_native(
                            &circuit,
                            &inputs.state_paths,
                            &reductions,
                        ) {
                            Ok(())
                        } else {
                            Err(ExactStateKillShotErrorV1::StateMerkleProofRejected)
                        }
                    },
                    || {
                        rayon::join(
                            || match (&inputs.guard_buckets, &proof.guard_buckets) {
                                (Some(inputs), Some(proof)) => {
                                    let mut channel = Poseidon2bChannel::new();
                                    let reductions = verify_batched_guard_bucket_killshot(
                                        proof,
                                        inputs,
                                        &mut channel,
                                    )
                                    .ok_or(ExactStateKillShotErrorV1::GuardBucketProofRejected)?;
                                    if discharge_batched_guard_bucket_reductions_native(
                                        inputs,
                                        &reductions,
                                    ) {
                                        Ok(())
                                    } else {
                                        Err(ExactStateKillShotErrorV1::GuardBucketProofRejected)
                                    }
                                }
                                (None, None) => Ok(()),
                                _ => Err(ExactStateKillShotErrorV1::GuardPresenceMismatch),
                            },
                            || {
                                rayon::join(
                                    || match (&inputs.guard_paths, &proof.guard_paths) {
                                        (Some(inputs), Some(proof)) => {
                                            let circuit =
                                                MerkleCircuit::build_with_tag(TAG_RGDNODE);
                                            let mut channel = Poseidon2bChannel::new();
                                            let reductions = verify_batched_merkle_killshot(
                                                &circuit,
                                                proof,
                                                inputs,
                                                &mut channel,
                                            )
                                            .ok_or(
                                                ExactStateKillShotErrorV1::GuardMerkleProofRejected,
                                            )?;
                                            if discharge_batched_merkle_reductions_native(
                                                &circuit,
                                                inputs,
                                                &reductions,
                                            ) {
                                                Ok(())
                                            } else {
                                                Err(
                                                    ExactStateKillShotErrorV1::GuardMerkleProofRejected,
                                                )
                                            }
                                        }
                                        (None, None) => Ok(()),
                                        _ => Err(ExactStateKillShotErrorV1::GuardPresenceMismatch),
                                    },
                                    || {
                                        let mut channel = Poseidon2bChannel::new();
                                        let reductions = verify_batched_state_root_killshot(
                                            &proof.state_roots,
                                            &inputs.state_roots,
                                            &mut channel,
                                        )
                                        .ok_or(ExactStateKillShotErrorV1::StateRootProofRejected)?;
                                        if discharge_batched_state_root_reductions_native(
                                            &inputs.state_roots,
                                            &reductions,
                                        ) {
                                            Ok(())
                                        } else {
                                            Err(ExactStateKillShotErrorV1::StateRootProofRejected)
                                        }
                                    },
                                )
                            },
                        )
                    },
                )
            },
        );
    slot_result?;
    state_result?;
    bucket_result?;
    guard_path_result?;
    root_result?;
    Ok(())
}

fn validate_component_shape(
    inputs: &AcceptedBlockBatchComponentInputsV1,
    proof: &AcceptedBlockBatchComponentProofV1,
) -> Result<(), AcceptedBlockBatchComponentErrorV1> {
    if inputs.exact_state_killshot_inputs.len() != proof.exact_state.len()
        || inputs.authorization_inputs.len() != inputs.authorization_witnesses.len()
        || inputs.authorization_traces.len() != inputs.authorization_witnesses.len()
        || inputs.authorization_traces.is_empty() != proof.authorization_transcripts.is_empty()
        || inputs.accepted_claim_hash_inputs.len()
            != inputs.accepted_claim_witness.accepted_block_claims.len()
        || inputs.tx_body_standard_inputs.len() != inputs.tx_body_standard_hashes.len()
        || inputs.tx_body_sweep_inputs.len() != inputs.tx_body_sweep_hashes.len()
    {
        return Err(AcceptedBlockBatchComponentErrorV1::ComponentShapeMismatch);
    }
    Ok(())
}

fn validate_certificate_statement_component_shape(
    inputs: &AcceptedBlockBatchComponentInputsV1,
) -> Result<(), AcceptedBlockBatchComponentErrorV1> {
    let headers = &inputs.accepted_claim_witness.headers;
    let claims = &inputs.accepted_claim_witness.accepted_block_claims;
    let statements = &inputs.accepted_block_certificate_statements;
    if statements.len() != headers.len() || statements.len() != claims.len() {
        return Err(AcceptedBlockBatchComponentErrorV1::ComponentShapeMismatch);
    }
    for (index, ((statement, header_witness), chain_claim)) in statements
        .iter()
        .zip(headers.iter())
        .zip(claims.iter().copied())
        .enumerate()
    {
        if statement.version != ACCEPTED_BLOCK_CERTIFICATE_STATEMENT_VERSION
            || statement.block_id != header_witness.block_id
            || statement.height != header_witness.header.height
            || statement.child_state_root != header_witness.header.state_root
            || statement.tx_root != header_witness.header.tx_root
            || accepted_block_certificate_chain_claim_v1(statement) != chain_claim
        {
            return Err(AcceptedBlockBatchComponentErrorV1::CertificateStatementMismatch { index });
        }
    }
    Ok(())
}

fn verify_accepted_claim_hash_component(
    inputs: &AcceptedBlockBatchComponentInputsV1,
    proof: &AcceptedBlockBatchComponentProofV1,
) -> Result<(), AcceptedBlockBatchComponentErrorV1> {
    for (input, claim) in inputs
        .accepted_claim_hash_inputs
        .iter()
        .zip(inputs.accepted_claim_witness.accepted_block_claims.iter())
    {
        if input.expected_claim != *claim {
            return Err(AcceptedBlockBatchComponentErrorV1::ComponentShapeMismatch);
        }
    }
    let mut channel = Poseidon2bChannel::new();
    let reductions = verify_accepted_claim_hash_killshot(
        &proof.accepted_claim_hash,
        &inputs.accepted_claim_hash_inputs,
        &mut channel,
    )
    .ok_or(AcceptedBlockBatchComponentErrorV1::AcceptedClaimHashProofRejected)?;
    if discharge_accepted_claim_hash_reductions_native(
        &inputs.accepted_claim_hash_inputs,
        &reductions,
    ) {
        Ok(())
    } else {
        Err(AcceptedBlockBatchComponentErrorV1::AcceptedClaimHashProofRejected)
    }
}

fn verify_standard_tx_body_component(
    inputs: &AcceptedBlockBatchComponentInputsV1,
    proof: &AcceptedBlockBatchComponentProofV1,
) -> Result<(), AcceptedBlockBatchComponentErrorV1> {
    if inputs.tx_body_standard_inputs.is_empty() {
        if proof.tx_body_standard.is_some() {
            return Err(AcceptedBlockBatchComponentErrorV1::ComponentShapeMismatch);
        }
        return Ok(());
    }
    let tx_body_proof = proof
        .tx_body_standard
        .as_ref()
        .ok_or(AcceptedBlockBatchComponentErrorV1::ComponentShapeMismatch)?;
    let mut channel = Poseidon2bChannel::new();
    let reductions = verify_block_spine_killshot(
        tx_body_proof,
        inputs.tx_body_standard_inputs.len(),
        &inputs.tx_body_standard_hashes,
        &mut channel,
    )
    .ok_or(AcceptedBlockBatchComponentErrorV1::TxBodyHashProofRejected)?;
    let slot_state_ins = standard_tx_body_slot_state_ins(&inputs.tx_body_standard_inputs);
    if discharge_block_spine_reductions_native(
        inputs.tx_body_standard_inputs.len(),
        &slot_state_ins,
        &reductions,
    ) {
        Ok(())
    } else {
        Err(AcceptedBlockBatchComponentErrorV1::TxBodyHashProofRejected)
    }
}

fn verify_sweep_tx_body_component(
    inputs: &AcceptedBlockBatchComponentInputsV1,
    proof: &AcceptedBlockBatchComponentProofV1,
) -> Result<(), AcceptedBlockBatchComponentErrorV1> {
    if inputs.tx_body_sweep_inputs.is_empty() {
        if proof.tx_body_sweep.is_some() {
            return Err(AcceptedBlockBatchComponentErrorV1::ComponentShapeMismatch);
        }
        return Ok(());
    }
    let tx_body_proof = proof
        .tx_body_sweep
        .as_ref()
        .ok_or(AcceptedBlockBatchComponentErrorV1::ComponentShapeMismatch)?;
    let mut channel = Poseidon2bChannel::new();
    let reductions = verify_sweep_block_spine_killshot(
        tx_body_proof,
        inputs.tx_body_sweep_inputs.len(),
        &inputs.tx_body_sweep_hashes,
        &mut channel,
    )
    .ok_or(AcceptedBlockBatchComponentErrorV1::TxBodyHashProofRejected)?;
    if discharge_sweep_block_spine_reductions_native(&inputs.tx_body_sweep_inputs, &reductions) {
        Ok(())
    } else {
        Err(AcceptedBlockBatchComponentErrorV1::TxBodyHashProofRejected)
    }
}

fn verify_tx_root_component(
    inputs: &AcceptedBlockBatchComponentInputsV1,
    proof: &AcceptedBlockBatchComponentProofV1,
) -> Result<(), AcceptedBlockBatchComponentErrorV1> {
    if inputs.tx_root_inputs.is_empty() {
        if proof.tx_root.is_some() {
            return Err(AcceptedBlockBatchComponentErrorV1::ComponentShapeMismatch);
        }
        return Ok(());
    }
    let tx_root_proof = proof
        .tx_root
        .as_ref()
        .ok_or(AcceptedBlockBatchComponentErrorV1::ComponentShapeMismatch)?;
    let circuit = MerkleCircuit::build();
    let mut channel = Poseidon2bChannel::new();
    let reductions = verify_batched_merkle_killshot(
        &circuit,
        tx_root_proof,
        &inputs.tx_root_inputs,
        &mut channel,
    )
    .ok_or(AcceptedBlockBatchComponentErrorV1::TxRootProofRejected)?;
    if discharge_batched_merkle_reductions_native(&circuit, &inputs.tx_root_inputs, &reductions) {
        Ok(())
    } else {
        Err(AcceptedBlockBatchComponentErrorV1::TxRootProofRejected)
    }
}

fn verify_authorization_components(
    inputs: &AcceptedBlockBatchComponentInputsV1,
) -> Result<(), AcceptedBlockBatchComponentErrorV1> {
    if inputs.authorization_inputs.len() != inputs.authorization_totals.user_tx_count {
        return Err(AcceptedBlockBatchComponentErrorV1::ComponentShapeMismatch);
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
                public: input.public.clone(),
            };
            let verified =
                verify_authorization_statement_proof(&statement, proof).map_err(|_| {
                    AcceptedBlockBatchComponentErrorV1::AuthorizationProofRejected {
                        index,
                        tx_index: input.tx_index,
                    }
                })?;
            Ok((verified.owner_count, verified.live_input_count))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let owner_count_total = auth_counts
        .iter()
        .map(|(owner_count, _)| *owner_count)
        .sum::<usize>();
    let live_input_count_total = auth_counts
        .iter()
        .map(|(_, live_inputs)| *live_inputs)
        .sum::<usize>();
    if owner_count_total != inputs.authorization_totals.owner_count_total
        || live_input_count_total != inputs.authorization_totals.live_input_count_total
    {
        return Err(AcceptedBlockBatchComponentErrorV1::ComponentShapeMismatch);
    }
    Ok(())
}

fn verify_authorization_transcript_components(
    inputs: &AcceptedBlockBatchComponentInputsV1,
    proof: &AcceptedBlockBatchComponentProofV1,
) -> Result<(), AcceptedBlockBatchComponentErrorV1> {
    let chunks = authorization_transcript_chunks(inputs)?;
    if chunks.len() != proof.authorization_transcripts.len() {
        return Err(AcceptedBlockBatchComponentErrorV1::ComponentShapeMismatch);
    }
    chunks
        .par_iter()
        .zip(proof.authorization_transcripts.par_iter())
        .enumerate()
        .try_for_each(
            |(chunk_index, ((tx_index, traces), auth_transcript_proof))| {
                let mut channel = Poseidon2bChannel::new();
                let reductions = verify_fiat_shamir_transcript_batch_killshot(
                    traces,
                    auth_transcript_proof,
                    &mut channel,
                )
                .map_err(|_| {
                    AcceptedBlockBatchComponentErrorV1::AuthorizationTranscriptRejected {
                        chunk_index,
                        tx_index: *tx_index,
                    }
                })?;
                if discharge_fiat_shamir_transcript_batch_reductions_native(traces, &reductions) {
                    Ok(())
                } else {
                    Err(
                        AcceptedBlockBatchComponentErrorV1::AuthorizationTranscriptRejected {
                            chunk_index,
                            tx_index: *tx_index,
                        },
                    )
                }
            },
        )
}

fn authorization_transcript_chunks(
    inputs: &AcceptedBlockBatchComponentInputsV1,
) -> Result<Vec<(usize, Vec<Vec<FiatShamirTraceOp>>)>, AcceptedBlockBatchComponentErrorV1> {
    if inputs.authorization_traces.len() != inputs.authorization_witnesses.len() {
        return Err(AcceptedBlockBatchComponentErrorV1::ComponentShapeMismatch);
    }
    Ok(inputs
        .authorization_traces
        .chunks(crate::FIAT_SHAMIR_TRANSCRIPT_MAX_TRACES_PER_BATCH)
        .map(|chunk| {
            let tx_index = chunk[0].tx_index;
            let traces = chunk
                .iter()
                .map(|trace| trace.transcript.clone())
                .collect::<Vec<_>>();
            (tx_index, traces)
        })
        .collect())
}

fn validate_exact_state_inputs(
    inputs: &ExactStateKillShotInputsV1,
) -> Result<(), ExactStateKillShotErrorV1> {
    if inputs.slot_leaves.is_empty()
        || inputs.state_paths.is_empty()
        || inputs.state_roots.is_empty()
        || inputs.state_roots.len() % 2 != 0
    {
        return Err(ExactStateKillShotErrorV1::EmptyDerivedInput);
    }
    if inputs.guard_buckets.is_some() != inputs.guard_paths.is_some() {
        return Err(ExactStateKillShotErrorV1::GuardPresenceMismatch);
    }
    Ok(())
}

fn standard_tx_body_slot_state_ins(inputs: &[SpineInputs]) -> Vec<[Block128; 4]> {
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
