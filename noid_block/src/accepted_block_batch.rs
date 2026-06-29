// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Canonical full `AcceptBlock` batch boundary for public O(1) history proofs.
//!
//! This module defines the relation that the optimized recursive prover must
//! prove. It does not accept previously stored local history-cache claims as
//! authority: it reconstructs each claim only after re-verifying the full
//! timeless `AcceptBlock` predicate.

use noid_chain::block::Block;
use noid_chain::block_header::BlockHeader;
use noid_chain::consensus::validation::AnchorInfo;
use noid_chain::hash_block_header;
use noid_chain::state::ChainState;
use noid_core::{Block128, TowerField};
use noid_gkr::{
    discharge_accepted_claim_hash_reductions_native, discharge_batched_merkle_reductions_native,
    discharge_block_spine_reductions_native, discharge_sweep_block_spine_reductions_native,
    owner_auth_public_from_body, prove_accepted_claim_hash_killshot, prove_batched_merkle_killshot,
    prove_block_spine_killshot, prove_sweep_block_spine_killshot, reconstruct_slot_states,
    spine_inputs_from_body, sweep_spine_inputs_from_body, verify_accepted_claim_hash_killshot,
    verify_authorization_statement_proof, verify_batched_merkle_killshot,
    verify_block_spine_killshot, verify_sweep_block_spine_killshot, AcceptedClaimHashInputs,
    AcceptedClaimHashProofKillShot, BatchedMerkleProofKillShot, BlockSpineMle, BlockSpineProof,
    CanonicalAuthorizationStatement, MerkleCircuit, MerklePathInputs, OwnerAuthProofKillShot,
    OwnerAuthPublicInputs, SpineCircuit, SpineInputs, SweepBlockSpineMle, SweepBlockSpineProof,
    SweepSpineInputs, MAX_MERKLE_DEPTH,
};
use noid_poseidon2b::native::compress;
use noid_recursive::{
    build_header_integer_trace, discharge_fiat_shamir_transcript_batch_reductions_native,
    prove_checkpoint_poseidon, prove_fiat_shamir_transcript_batch_killshot,
    verify_accepted_claim_batch_with_header_trace, verify_authorization_batch_native_with_traces,
    verify_checkpoint_poseidon, verify_fiat_shamir_transcript_batch_killshot,
    verify_pow_header_witness_batch_native, AcceptedClaimBatchError, AcceptedClaimBatchOutput,
    AcceptedClaimBatchWitness, AuthorizationVerifierTrace, ChainAccumulator,
    CheckpointPoseidonError, CheckpointPoseidonProof, FiatShamirTraceOp,
    FiatShamirTranscriptBatchProofKillShot, HeaderIntegerBatchTrace, HeaderIntegerTraceError,
    HeaderWitness, PowHeaderBatchError, RecursiveConsensusState,
    FIAT_SHAMIR_TRANSCRIPT_MAX_TRACES_PER_BATCH,
};

use crate::{
    accept_block_timeless_with_artifacts, accepted_block_claim_fields_from_transcript,
    accepted_block_claim_from_transcript, accepted_block_claim_transcript,
    derive_exact_state_killshot_inputs, BlockAuthSidecar, BlockProof, ExactStateKillShotError,
    ExactStateKillShotInputs, ExactStateKillShotProof, FullValidationError,
    VerifiedAuthorizationBatch, VerifyBlockError,
};
use noid_tx::TxShape;
use rayon::prelude::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FullAcceptedBlockBatchItem {
    pub block: Block,
    pub block_proof_bytes: Vec<u8>,
    pub block_auth_sidecar_bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FullAcceptedBlockBatchWitness {
    pub items: Vec<FullAcceptedBlockBatchItem>,
}

#[derive(Debug)]
pub struct FullAcceptedBlockBatchOutput {
    pub accepted_claim_batch: AcceptedClaimBatchOutput,
    pub end_state: ChainState,
    pub proof_components: FullAcceptedBlockBatchProofComponents,
}

#[derive(Debug, Clone)]
pub struct FullAcceptedBlockBatchProofComponents {
    pub accepted_claim_witness: AcceptedClaimBatchWitness,
    pub accepted_claim_hash_inputs: Vec<AcceptedClaimHashInputs>,
    pub tx_body_standard_inputs: Vec<SpineInputs>,
    pub tx_body_standard_hashes: Vec<[Block128; 2]>,
    pub tx_body_sweep_inputs: Vec<SweepSpineInputs>,
    pub tx_body_sweep_hashes: Vec<[Block128; 2]>,
    pub tx_root_inputs: Vec<MerklePathInputs>,
    pub header_integer_trace: HeaderIntegerBatchTrace,
    pub authorization_inputs: Vec<AuthorizationComponentInput>,
    pub authorization_witnesses: Vec<OwnerAuthProofKillShot>,
    pub authorization_traces: Vec<AuthorizationVerifierTrace>,
    pub exact_state_killshot_inputs: Vec<ExactStateKillShotInputs>,
    pub authorization_totals: VerifiedAuthorizationBatch,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationComponentInput {
    pub block_index: usize,
    pub tx_index: usize,
    pub tx_body_hash: [Block128; 2],
    pub public: OwnerAuthPublicInputs,
}

#[derive(Debug, Clone)]
pub struct RetainedFullAcceptedBlockBatchProof {
    pub accepted_claim_hash: AcceptedClaimHashProofKillShot,
    pub tx_body_standard: Option<BlockSpineProof>,
    pub tx_body_sweep: Option<SweepBlockSpineProof>,
    pub tx_root: Option<BatchedMerkleProofKillShot>,
    pub checkpoint_poseidon: CheckpointPoseidonProof,
    pub exact_state: Vec<ExactStateKillShotProof>,
    pub authorization_transcripts: Vec<FiatShamirTranscriptBatchProofKillShot>,
}

impl RetainedFullAcceptedBlockBatchProof {
    pub fn byte_len(&self, components: &FullAcceptedBlockBatchProofComponents) -> usize {
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
                .map_or(0, |proof| proof.byte_len(&components.tx_root_inputs))
            + self.checkpoint_poseidon.byte_len()
            + self
                .exact_state
                .iter()
                .zip(components.exact_state_killshot_inputs.iter())
                .map(|(proof, inputs)| proof.byte_len(inputs))
                .sum::<usize>()
            + self
                .authorization_transcripts
                .iter()
                .map(FiatShamirTranscriptBatchProofKillShot::byte_len)
                .sum::<usize>()
    }
}

#[derive(Debug)]
pub enum FullAcceptedBlockBatchError {
    EmptyBatch,
    StartParentMismatch,
    StartStateRootMismatch,
    DecodeProof {
        index: usize,
    },
    DecodeSidecar {
        index: usize,
    },
    FullValidation {
        index: usize,
        source: FullValidationError,
    },
    Claim {
        index: usize,
        source: VerifyBlockError,
    },
    HeaderWork {
        index: usize,
        source: PowHeaderBatchError,
    },
    HeaderInteger(HeaderIntegerTraceError),
    ExactStateComponent {
        index: usize,
        source: ExactStateKillShotError,
    },
    AuthorizationComponent {
        index: usize,
        tx_index: usize,
    },
    TxBodyHashComponent,
    TxRootComponent,
    CheckpointPoseidon(CheckpointPoseidonError),
    ComponentShapeMismatch,
    AcceptedClaimBatch(AcceptedClaimBatchError),
}

pub fn verify_full_accepted_block_batch_native(
    start_consensus: &RecursiveConsensusState,
    start_accumulator: &ChainAccumulator,
    start_parent: &BlockHeader,
    start_state: &ChainState,
    witness: &FullAcceptedBlockBatchWitness,
) -> Result<FullAcceptedBlockBatchOutput, FullAcceptedBlockBatchError> {
    if witness.items.is_empty() {
        return Err(FullAcceptedBlockBatchError::EmptyBatch);
    }
    if hash_block_header(start_parent) != start_consensus.block_id
        || start_parent.height != start_consensus.height
        || start_parent.state_root != start_consensus.state_root
        || start_parent.log_slots != start_consensus.log_slots
        || start_parent.active_slot_count != start_consensus.active_slot_count
        || start_parent.alloc_counter != start_consensus.alloc_counter
    {
        return Err(FullAcceptedBlockBatchError::StartParentMismatch);
    }

    let mut state = start_state.clone();
    if state.state_root() != start_consensus.state_root {
        return Err(FullAcceptedBlockBatchError::StartStateRootMismatch);
    }

    let mut parent = start_parent.clone();
    let mut rolling_consensus = start_consensus.clone();
    let mut header_witnesses = Vec::with_capacity(witness.items.len());
    let mut accepted_block_claims = Vec::with_capacity(witness.items.len());
    let mut accepted_claim_hash_inputs = Vec::with_capacity(witness.items.len());
    let mut tx_body_standard_inputs = Vec::new();
    let mut tx_body_standard_hashes = Vec::new();
    let mut tx_body_sweep_inputs = Vec::new();
    let mut tx_body_sweep_hashes = Vec::new();
    let mut tx_root_inputs = Vec::new();
    let mut authorization_inputs = Vec::new();
    let mut authorization_witnesses = Vec::new();
    let mut authorization_traces = Vec::new();
    let mut exact_state_killshot_inputs = Vec::new();
    let mut authorization_totals = VerifiedAuthorizationBatch {
        user_tx_count: 0,
        owner_count_total: 0,
        live_input_count_total: 0,
    };

    for (index, item) in witness.items.iter().enumerate() {
        let prev_timestamps = rolling_consensus.timestamps().to_vec();
        let prev_active_counts = rolling_consensus.active_counts().to_vec();
        let anchor = AnchorInfo {
            anchor_height: rolling_consensus.asert_anchor_height,
            anchor_timestamp: rolling_consensus.asert_anchor_timestamp,
            anchor_target: rolling_consensus.asert_anchor_target,
        };

        let has_user_txs = item
            .block
            .transactions
            .iter()
            .any(|tx| !tx.body.is_coinbase);
        let (proof, sidecar) = if has_user_txs {
            let proof = bincode::deserialize::<BlockProof>(&item.block_proof_bytes)
                .map_err(|_| FullAcceptedBlockBatchError::DecodeProof { index })?;
            let sidecar = bincode::deserialize::<BlockAuthSidecar>(&item.block_auth_sidecar_bytes)
                .map_err(|_| FullAcceptedBlockBatchError::DecodeSidecar { index })?;
            (Some(proof), sidecar)
        } else {
            (None, BlockAuthSidecar::default())
        };

        let pre_validation_guard = state.reuse_guard.clone();
        let validation = accept_block_timeless_with_artifacts(
            &item.block,
            &item.block_proof_bytes,
            &item.block_auth_sidecar_bytes,
            &parent,
            &prev_timestamps,
            &prev_active_counts,
            &anchor,
            &mut state,
        )
        .map_err(|source| FullAcceptedBlockBatchError::FullValidation { index, source })?;

        if has_user_txs {
            let artifacts = validation.artifacts;
            let proof = proof
                .as_ref()
                .expect("user-transaction block proof decoded above");
            let (inputs, verified) = derive_exact_state_killshot_inputs(
                &artifacts.exact_state_inputs,
                &artifacts.exact_action_surface,
                &pre_validation_guard,
                &proof.state_transition,
            )
            .map_err(|source| FullAcceptedBlockBatchError::ExactStateComponent { index, source })?;
            if verified != artifacts.verified_transition {
                return Err(FullAcceptedBlockBatchError::ExactStateComponent {
                    index,
                    source: ExactStateKillShotError::ExactState(
                        crate::ExactStateTransitionError::ChildRootMismatch,
                    ),
                });
            }
            exact_state_killshot_inputs.push(inputs);

            let (traced_authorization, traces) =
                verify_authorization_batch_native_with_traces(&item.block, &sidecar.tx_auth)
                    .map_err(|_| FullAcceptedBlockBatchError::AuthorizationComponent {
                        index,
                        tx_index: 0,
                    })?;
            if traced_authorization != artifacts.authorization {
                return Err(FullAcceptedBlockBatchError::ComponentShapeMismatch);
            }

            for ((tx_index, tx), auth_proof) in item
                .block
                .transactions
                .iter()
                .enumerate()
                .filter(|(_, tx)| !tx.body.is_coinbase)
                .zip(sidecar.tx_auth.iter())
            {
                let public = owner_auth_public_from_body(&tx.body).map_err(|_| {
                    FullAcceptedBlockBatchError::FullValidation {
                        index,
                        source: FullValidationError::ZkProof(
                            VerifyBlockError::AuthSidecarShapeMismatch,
                        ),
                    }
                })?;
                authorization_inputs.push(AuthorizationComponentInput {
                    block_index: index,
                    tx_index,
                    tx_body_hash: tx.tx_body_hash.as_fields(),
                    public,
                });
                authorization_witnesses.push(auth_proof.clone());
            }
            authorization_traces.extend(traces);
            authorization_totals.user_tx_count = authorization_totals
                .user_tx_count
                .saturating_add(artifacts.authorization.user_tx_count);
            authorization_totals.owner_count_total = authorization_totals
                .owner_count_total
                .saturating_add(artifacts.authorization.owner_count_total);
            authorization_totals.live_input_count_total = authorization_totals
                .live_input_count_total
                .saturating_add(artifacts.authorization.live_input_count_total);
        }

        let transcript = accepted_block_claim_transcript(
            &item.block,
            &parent,
            &prev_timestamps,
            &prev_active_counts,
            &anchor,
            proof.as_ref(),
            &sidecar,
        )
        .map_err(|source| FullAcceptedBlockBatchError::Claim { index, source })?;
        let claim = accepted_block_claim_from_transcript(&transcript);
        let fields = accepted_block_claim_fields_from_transcript(&transcript);
        accepted_claim_hash_inputs.push(AcceptedClaimHashInputs {
            fields,
            expected_claim: claim,
        });
        tx_root_inputs.extend(
            tx_root_merkle_inputs(&item.block)
                .map_err(|_| FullAcceptedBlockBatchError::TxRootComponent)?,
        );
        extend_tx_body_hash_component_inputs(
            &item.block,
            &mut tx_body_standard_inputs,
            &mut tx_body_standard_hashes,
            &mut tx_body_sweep_inputs,
            &mut tx_body_sweep_hashes,
        )?;

        let header_witness = HeaderWitness::from_header(&item.block.header);
        rolling_consensus =
            verify_pow_header_witness_batch_native(&rolling_consensus, &[header_witness.clone()])
                .map_err(|source| FullAcceptedBlockBatchError::HeaderWork { index, source })?;
        header_witnesses.push(header_witness);
        accepted_block_claims.push(claim);
        parent = item.block.header.clone();
    }

    let accepted_claim_witness = AcceptedClaimBatchWitness {
        headers: header_witnesses,
        accepted_block_claims,
    };
    let header_integer_trace =
        build_header_integer_trace(start_consensus, &accepted_claim_witness.headers)
            .map_err(FullAcceptedBlockBatchError::HeaderInteger)?;
    let accepted_claim_batch = verify_accepted_claim_batch_with_header_trace(
        start_consensus,
        start_accumulator,
        &accepted_claim_witness,
        &header_integer_trace,
    )
    .map_err(FullAcceptedBlockBatchError::AcceptedClaimBatch)?;

    Ok(FullAcceptedBlockBatchOutput {
        accepted_claim_batch,
        end_state: state,
        proof_components: FullAcceptedBlockBatchProofComponents {
            accepted_claim_witness,
            accepted_claim_hash_inputs,
            tx_body_standard_inputs,
            tx_body_standard_hashes,
            tx_body_sweep_inputs,
            tx_body_sweep_hashes,
            tx_root_inputs,
            header_integer_trace,
            authorization_inputs,
            authorization_witnesses,
            authorization_traces,
            exact_state_killshot_inputs,
            authorization_totals,
        },
    })
}

pub(crate) fn prove_full_accepted_block_batch_components(
    start_accumulator: &ChainAccumulator,
    end_accumulator: &ChainAccumulator,
    components: &FullAcceptedBlockBatchProofComponents,
) -> Result<RetainedFullAcceptedBlockBatchProof, FullAcceptedBlockBatchError> {
    if components.accepted_claim_hash_inputs.len()
        != components
            .accepted_claim_witness
            .accepted_block_claims
            .len()
    {
        return Err(FullAcceptedBlockBatchError::ComponentShapeMismatch);
    }
    if components.authorization_inputs.len() != components.authorization_witnesses.len() {
        return Err(FullAcceptedBlockBatchError::ComponentShapeMismatch);
    }
    if components.authorization_traces.len() != components.authorization_witnesses.len() {
        return Err(FullAcceptedBlockBatchError::ComponentShapeMismatch);
    }
    validate_tx_body_component_shape(components)?;
    let claim_result =
        || -> Result<AcceptedClaimHashProofKillShot, FullAcceptedBlockBatchError> {
            let mut channel = noid_poseidon2b::channel::Poseidon2bChannel::new();
            Ok(prove_accepted_claim_hash_killshot(
                &components.accepted_claim_hash_inputs,
                &mut channel,
            )
            .0)
        };

    let rest_result = || -> Result<
        (
            Option<BlockSpineProof>,
            Option<SweepBlockSpineProof>,
            Option<BatchedMerkleProofKillShot>,
            CheckpointPoseidonProof,
            Vec<ExactStateKillShotProof>,
            Vec<FiatShamirTranscriptBatchProofKillShot>,
        ),
        FullAcceptedBlockBatchError,
    > {
        let (
            (tx_body_standard, tx_body_sweep),
            (tx_root, ((checkpoint_poseidon, exact_state), authorization_transcripts)),
        ) = rayon::join(
                || {
                    rayon::join(
                        || prove_standard_tx_body_component(components),
                        || prove_sweep_tx_body_component(components),
                    )
                },
                || {
                    rayon::join(
                        || prove_tx_root_component(components),
                        || {
                            rayon::join(
                                || {
                                    rayon::join(
                                        || {
                                            prove_checkpoint_poseidon(
                                                start_accumulator,
                                                end_accumulator,
                                                &components.accepted_claim_witness,
                                            )
                                            .map_err(
                                                FullAcceptedBlockBatchError::CheckpointPoseidon,
                                            )
                                        },
                                        || prove_exact_state_components(components),
                                    )
                                },
                                || prove_authorization_transcript_components(components),
                            )
                        },
                    )
                },
            );

        Ok((
            tx_body_standard?,
            tx_body_sweep?,
            tx_root?,
            checkpoint_poseidon?,
            exact_state?,
            authorization_transcripts?,
        ))
    };

    let (accepted_claim_hash, rest) = rayon::join(claim_result, rest_result);
    let accepted_claim_hash = accepted_claim_hash?;
    let (
        tx_body_standard,
        tx_body_sweep,
        tx_root,
        checkpoint_poseidon,
        exact_state,
        authorization_transcripts,
    ) = rest?;

    Ok(RetainedFullAcceptedBlockBatchProof {
        accepted_claim_hash,
        tx_body_standard,
        tx_body_sweep,
        tx_root,
        checkpoint_poseidon,
        exact_state,
        authorization_transcripts,
    })
}

/// Replays the retained batch with the timeless `AcceptBlock` predicate, derives
/// proof component statements from that accepted replay, and proves them.
///
/// Component statements are deliberately not accepted from the caller.
pub fn prove_retained_full_accepted_block_batch_proof(
    start_consensus: &RecursiveConsensusState,
    start_accumulator: &ChainAccumulator,
    start_parent: &BlockHeader,
    start_state: &ChainState,
    witness: &FullAcceptedBlockBatchWitness,
) -> Result<
    (
        FullAcceptedBlockBatchOutput,
        RetainedFullAcceptedBlockBatchProof,
    ),
    FullAcceptedBlockBatchError,
> {
    let output = verify_full_accepted_block_batch_native(
        start_consensus,
        start_accumulator,
        start_parent,
        start_state,
        witness,
    )?;
    let proof = prove_full_accepted_block_batch_components(
        start_accumulator,
        &output.accepted_claim_batch.accumulator,
        &output.proof_components,
    )?;
    Ok((output, proof))
}

/// Verifies retained semantic blocks and detached witnesses, then verifies the
/// proof components derived from that same retained batch.
///
/// This is not a public O(1) history verifier: callers must still provide the
/// retained block bodies, block proofs, auth sidecars, start parent, and start
/// state so the timeless `AcceptBlock` relation can be replayed exactly.
pub fn verify_retained_full_accepted_block_batch_proof(
    start_consensus: &RecursiveConsensusState,
    start_accumulator: &ChainAccumulator,
    start_parent: &BlockHeader,
    start_state: &ChainState,
    witness: &FullAcceptedBlockBatchWitness,
    proof: &RetainedFullAcceptedBlockBatchProof,
) -> Result<FullAcceptedBlockBatchOutput, FullAcceptedBlockBatchError> {
    let output = verify_full_accepted_block_batch_native(
        start_consensus,
        start_accumulator,
        start_parent,
        start_state,
        witness,
    )?;
    verify_full_accepted_block_batch_components(
        start_consensus,
        start_accumulator,
        &output.accepted_claim_batch.accumulator,
        &output.proof_components,
        proof,
    )?;
    Ok(output)
}

pub(crate) fn verify_full_accepted_block_batch_components(
    start_consensus: &RecursiveConsensusState,
    start_accumulator: &ChainAccumulator,
    end_accumulator: &ChainAccumulator,
    components: &FullAcceptedBlockBatchProofComponents,
    proof: &RetainedFullAcceptedBlockBatchProof,
) -> Result<AcceptedClaimBatchOutput, FullAcceptedBlockBatchError> {
    if components.exact_state_killshot_inputs.len() != proof.exact_state.len() {
        return Err(FullAcceptedBlockBatchError::ComponentShapeMismatch);
    }
    if components.authorization_inputs.len() != components.authorization_witnesses.len() {
        return Err(FullAcceptedBlockBatchError::ComponentShapeMismatch);
    }
    if components.authorization_traces.len() != components.authorization_witnesses.len() {
        return Err(FullAcceptedBlockBatchError::ComponentShapeMismatch);
    }
    if components.authorization_traces.is_empty() != proof.authorization_transcripts.is_empty() {
        return Err(FullAcceptedBlockBatchError::ComponentShapeMismatch);
    }
    validate_tx_body_component_shape(components)?;
    if components.accepted_claim_hash_inputs.len()
        != components
            .accepted_claim_witness
            .accepted_block_claims
            .len()
    {
        return Err(FullAcceptedBlockBatchError::ComponentShapeMismatch);
    }
    for (index, (input, claim)) in components
        .accepted_claim_hash_inputs
        .iter()
        .zip(
            components
                .accepted_claim_witness
                .accepted_block_claims
                .iter(),
        )
        .enumerate()
    {
        if input.expected_claim != *claim {
            return Err(FullAcceptedBlockBatchError::Claim {
                index,
                source: VerifyBlockError::ShapeMismatch,
            });
        }
    }

    let mut claim_channel = noid_poseidon2b::channel::Poseidon2bChannel::new();
    let claim_reductions = verify_accepted_claim_hash_killshot(
        &proof.accepted_claim_hash,
        &components.accepted_claim_hash_inputs,
        &mut claim_channel,
    )
    .ok_or(FullAcceptedBlockBatchError::ComponentShapeMismatch)?;
    if !discharge_accepted_claim_hash_reductions_native(
        &components.accepted_claim_hash_inputs,
        &claim_reductions,
    ) {
        return Err(FullAcceptedBlockBatchError::ComponentShapeMismatch);
    }

    verify_standard_tx_body_component(components, proof)?;
    verify_sweep_tx_body_component(components, proof)?;

    if components.tx_root_inputs.is_empty() {
        if proof.tx_root.is_some() {
            return Err(FullAcceptedBlockBatchError::ComponentShapeMismatch);
        }
    } else {
        let tx_root_proof = proof
            .tx_root
            .as_ref()
            .ok_or(FullAcceptedBlockBatchError::ComponentShapeMismatch)?;
        let circuit = MerkleCircuit::build();
        let mut channel = noid_poseidon2b::channel::Poseidon2bChannel::new();
        let reductions = verify_batched_merkle_killshot(
            &circuit,
            tx_root_proof,
            &components.tx_root_inputs,
            &mut channel,
        )
        .ok_or(FullAcceptedBlockBatchError::TxRootComponent)?;
        if !discharge_batched_merkle_reductions_native(
            &circuit,
            &components.tx_root_inputs,
            &reductions,
        ) {
            return Err(FullAcceptedBlockBatchError::TxRootComponent);
        }
    }

    verify_authorization_components_native(
        &components.authorization_inputs,
        &components.authorization_witnesses,
        &components.authorization_totals,
    )?;
    verify_authorization_transcript_components(components, proof)?;

    let accepted_claim_batch = verify_accepted_claim_batch_with_header_trace(
        start_consensus,
        start_accumulator,
        &components.accepted_claim_witness,
        &components.header_integer_trace,
    )
    .map_err(FullAcceptedBlockBatchError::AcceptedClaimBatch)?;

    if accepted_claim_batch.accumulator != *end_accumulator {
        return Err(FullAcceptedBlockBatchError::ComponentShapeMismatch);
    }

    verify_checkpoint_poseidon(
        start_accumulator,
        end_accumulator,
        &components.accepted_claim_witness,
        &proof.checkpoint_poseidon,
    )
    .map_err(FullAcceptedBlockBatchError::CheckpointPoseidon)?;

    components
        .exact_state_killshot_inputs
        .par_iter()
        .zip(proof.exact_state.par_iter())
        .enumerate()
        .try_for_each(|(index, (inputs, proof))| {
            crate::verify_exact_state_killshot(inputs, proof).map_err(|source| {
                FullAcceptedBlockBatchError::ExactStateComponent { index, source }
            })
        })?;

    Ok(accepted_claim_batch)
}

fn prove_tx_root_component(
    components: &FullAcceptedBlockBatchProofComponents,
) -> Result<Option<BatchedMerkleProofKillShot>, FullAcceptedBlockBatchError> {
    if components.tx_root_inputs.is_empty() {
        return Ok(None);
    }
    let circuit = MerkleCircuit::build();
    let mut channel = noid_poseidon2b::channel::Poseidon2bChannel::new();
    Ok(Some(
        prove_batched_merkle_killshot(&circuit, &components.tx_root_inputs, &mut channel).0,
    ))
}

fn prove_exact_state_components(
    components: &FullAcceptedBlockBatchProofComponents,
) -> Result<Vec<ExactStateKillShotProof>, FullAcceptedBlockBatchError> {
    components
        .exact_state_killshot_inputs
        .par_iter()
        .enumerate()
        .map(|(index, inputs)| {
            crate::prove_exact_state_killshot(inputs).map_err(|source| {
                FullAcceptedBlockBatchError::ExactStateComponent { index, source }
            })
        })
        .collect()
}

fn authorization_transcript_chunks(
    components: &FullAcceptedBlockBatchProofComponents,
) -> Result<Vec<(usize, Vec<Vec<FiatShamirTraceOp>>)>, FullAcceptedBlockBatchError> {
    if components.authorization_traces.len() != components.authorization_witnesses.len() {
        return Err(FullAcceptedBlockBatchError::ComponentShapeMismatch);
    }
    Ok(components
        .authorization_traces
        .chunks(FIAT_SHAMIR_TRANSCRIPT_MAX_TRACES_PER_BATCH)
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

fn prove_authorization_transcript_components(
    components: &FullAcceptedBlockBatchProofComponents,
) -> Result<Vec<FiatShamirTranscriptBatchProofKillShot>, FullAcceptedBlockBatchError> {
    let chunks = authorization_transcript_chunks(components)?;
    if chunks.is_empty() {
        return Ok(Vec::new());
    }
    chunks
        .par_iter()
        .enumerate()
        .map(|(chunk_index, (tx_index, traces))| {
            let mut channel = noid_poseidon2b::channel::Poseidon2bChannel::new();
            prove_fiat_shamir_transcript_batch_killshot(traces, &mut channel)
                .map(|(proof, _)| proof)
                .map_err(|_| FullAcceptedBlockBatchError::AuthorizationComponent {
                    index: chunk_index,
                    tx_index: *tx_index,
                })
        })
        .collect()
}

fn verify_authorization_transcript_components(
    components: &FullAcceptedBlockBatchProofComponents,
    proof: &RetainedFullAcceptedBlockBatchProof,
) -> Result<(), FullAcceptedBlockBatchError> {
    let chunks = authorization_transcript_chunks(components)?;
    if chunks.len() != proof.authorization_transcripts.len() {
        return Err(FullAcceptedBlockBatchError::ComponentShapeMismatch);
    }
    chunks
        .par_iter()
        .zip(proof.authorization_transcripts.par_iter())
        .enumerate()
        .try_for_each(
            |(chunk_index, ((tx_index, traces), auth_transcript_proof))| {
                let mut channel = noid_poseidon2b::channel::Poseidon2bChannel::new();
                let reductions = verify_fiat_shamir_transcript_batch_killshot(
                    traces,
                    auth_transcript_proof,
                    &mut channel,
                )
                .map_err(|_| {
                    FullAcceptedBlockBatchError::AuthorizationComponent {
                        index: chunk_index,
                        tx_index: *tx_index,
                    }
                })?;
                if discharge_fiat_shamir_transcript_batch_reductions_native(traces, &reductions) {
                    Ok(())
                } else {
                    Err(FullAcceptedBlockBatchError::AuthorizationComponent {
                        index: chunk_index,
                        tx_index: *tx_index,
                    })
                }
            },
        )
}

fn verify_authorization_components_native(
    inputs: &[AuthorizationComponentInput],
    witnesses: &[OwnerAuthProofKillShot],
    expected_totals: &VerifiedAuthorizationBatch,
) -> Result<(), FullAcceptedBlockBatchError> {
    if inputs.len() != witnesses.len() || inputs.len() != expected_totals.user_tx_count {
        return Err(FullAcceptedBlockBatchError::ComponentShapeMismatch);
    }

    let auth_counts = inputs
        .par_iter()
        .zip(witnesses.par_iter())
        .enumerate()
        .map(|(index, (input, proof))| {
            let statement = CanonicalAuthorizationStatement {
                tx_index: input.tx_index,
                tx_body_hash: input.tx_body_hash,
                public: input.public.clone(),
            };
            let verified =
                verify_authorization_statement_proof(&statement, proof).map_err(|_| {
                    FullAcceptedBlockBatchError::AuthorizationComponent {
                        index,
                        tx_index: input.tx_index,
                    }
                })?;
            Ok((verified.owner_count, verified.live_input_count))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let actual_owner_count = auth_counts
        .iter()
        .map(|(owner_count, _)| *owner_count)
        .sum::<usize>();
    let actual_live_inputs = auth_counts
        .iter()
        .map(|(_, live_inputs)| *live_inputs)
        .sum::<usize>();
    if actual_owner_count != expected_totals.owner_count_total
        || actual_live_inputs != expected_totals.live_input_count_total
    {
        return Err(FullAcceptedBlockBatchError::ComponentShapeMismatch);
    }
    Ok(())
}

fn validate_tx_body_component_shape(
    components: &FullAcceptedBlockBatchProofComponents,
) -> Result<(), FullAcceptedBlockBatchError> {
    if components.tx_body_standard_inputs.len() != components.tx_body_standard_hashes.len()
        || components.tx_body_sweep_inputs.len() != components.tx_body_sweep_hashes.len()
    {
        return Err(FullAcceptedBlockBatchError::ComponentShapeMismatch);
    }
    Ok(())
}

fn extend_tx_body_hash_component_inputs(
    block: &Block,
    standard_inputs: &mut Vec<SpineInputs>,
    standard_hashes: &mut Vec<[Block128; 2]>,
    sweep_inputs: &mut Vec<SweepSpineInputs>,
    sweep_hashes: &mut Vec<[Block128; 2]>,
) -> Result<(), FullAcceptedBlockBatchError> {
    for tx in &block.transactions {
        match tx.body.shape {
            TxShape::Standard4x8 => {
                let inputs = spine_inputs_from_body(&tx.body)
                    .map_err(|_| FullAcceptedBlockBatchError::TxBodyHashComponent)?;
                standard_inputs.push(inputs);
                standard_hashes.push(tx.tx_body_hash.as_fields());
            }
            TxShape::Sweep25x2 => {
                let inputs = sweep_spine_inputs_from_body(&tx.body)
                    .map_err(|_| FullAcceptedBlockBatchError::TxBodyHashComponent)?;
                sweep_inputs.push(inputs);
                sweep_hashes.push(tx.tx_body_hash.as_fields());
            }
        }
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

fn prove_standard_tx_body_component(
    components: &FullAcceptedBlockBatchProofComponents,
) -> Result<Option<BlockSpineProof>, FullAcceptedBlockBatchError> {
    if components.tx_body_standard_inputs.is_empty() {
        return Ok(None);
    }
    let slot_state_ins = standard_tx_body_slot_state_ins(&components.tx_body_standard_inputs);
    let mle = BlockSpineMle::build(components.tx_body_standard_inputs.len(), &slot_state_ins);
    let mut channel = noid_poseidon2b::channel::Poseidon2bChannel::new();
    Ok(Some(
        prove_block_spine_killshot(
            components.tx_body_standard_inputs.len(),
            &mle,
            &components.tx_body_standard_hashes,
            &mut channel,
        )
        .0,
    ))
}

fn prove_sweep_tx_body_component(
    components: &FullAcceptedBlockBatchProofComponents,
) -> Result<Option<SweepBlockSpineProof>, FullAcceptedBlockBatchError> {
    if components.tx_body_sweep_inputs.is_empty() {
        return Ok(None);
    }
    let mle = SweepBlockSpineMle::build(&components.tx_body_sweep_inputs);
    let mut channel = noid_poseidon2b::channel::Poseidon2bChannel::new();
    Ok(Some(
        prove_sweep_block_spine_killshot(
            components.tx_body_sweep_inputs.len(),
            &mle,
            &components.tx_body_sweep_hashes,
            &mut channel,
        )
        .0,
    ))
}

fn verify_standard_tx_body_component(
    components: &FullAcceptedBlockBatchProofComponents,
    proof: &RetainedFullAcceptedBlockBatchProof,
) -> Result<(), FullAcceptedBlockBatchError> {
    if components.tx_body_standard_inputs.is_empty() {
        if proof.tx_body_standard.is_some() {
            return Err(FullAcceptedBlockBatchError::ComponentShapeMismatch);
        }
        return Ok(());
    }

    let tx_body_proof = proof
        .tx_body_standard
        .as_ref()
        .ok_or(FullAcceptedBlockBatchError::ComponentShapeMismatch)?;
    let mut channel = noid_poseidon2b::channel::Poseidon2bChannel::new();
    let reductions = verify_block_spine_killshot(
        tx_body_proof,
        components.tx_body_standard_inputs.len(),
        &components.tx_body_standard_hashes,
        &mut channel,
    )
    .ok_or(FullAcceptedBlockBatchError::TxBodyHashComponent)?;
    let slot_state_ins = standard_tx_body_slot_state_ins(&components.tx_body_standard_inputs);
    if discharge_block_spine_reductions_native(
        components.tx_body_standard_inputs.len(),
        &slot_state_ins,
        &reductions,
    ) {
        Ok(())
    } else {
        Err(FullAcceptedBlockBatchError::TxBodyHashComponent)
    }
}

fn verify_sweep_tx_body_component(
    components: &FullAcceptedBlockBatchProofComponents,
    proof: &RetainedFullAcceptedBlockBatchProof,
) -> Result<(), FullAcceptedBlockBatchError> {
    if components.tx_body_sweep_inputs.is_empty() {
        if proof.tx_body_sweep.is_some() {
            return Err(FullAcceptedBlockBatchError::ComponentShapeMismatch);
        }
        return Ok(());
    }

    let tx_body_proof = proof
        .tx_body_sweep
        .as_ref()
        .ok_or(FullAcceptedBlockBatchError::ComponentShapeMismatch)?;
    let mut channel = noid_poseidon2b::channel::Poseidon2bChannel::new();
    let reductions = verify_sweep_block_spine_killshot(
        tx_body_proof,
        components.tx_body_sweep_inputs.len(),
        &components.tx_body_sweep_hashes,
        &mut channel,
    )
    .ok_or(FullAcceptedBlockBatchError::TxBodyHashComponent)?;
    if discharge_sweep_block_spine_reductions_native(&components.tx_body_sweep_inputs, &reductions)
    {
        Ok(())
    } else {
        Err(FullAcceptedBlockBatchError::TxBodyHashComponent)
    }
}

fn digest_to_fields(hash: [u8; 32]) -> [Block128; 2] {
    [
        Block128::from(u128::from_le_bytes(hash[..16].try_into().unwrap())),
        Block128::from(u128::from_le_bytes(hash[16..].try_into().unwrap())),
    ]
}

fn tx_root_merkle_inputs(block: &Block) -> Result<Vec<MerklePathInputs>, ()> {
    if block.transactions.is_empty() {
        return if block.header.tx_root == [0u8; 32] {
            Ok(Vec::new())
        } else {
            Err(())
        };
    }

    let target = block.transactions.len().next_power_of_two().max(2);
    let depth = target.trailing_zeros() as usize;
    if depth == 0 || depth > MAX_MERKLE_DEPTH {
        return Err(());
    }

    let mut levels = Vec::new();
    let mut level: Vec<[u8; 32]> = block
        .transactions
        .iter()
        .map(|tx| tx.tx_body_hash.0)
        .collect();
    level.resize(target, [0u8; 32]);
    levels.push(level.clone());
    while level.len() > 1 {
        level = level
            .chunks_exact(2)
            .map(|pair| compress(&pair[0], &pair[1]))
            .collect();
        levels.push(level.clone());
    }

    let root = levels
        .last()
        .and_then(|level| level.first())
        .copied()
        .ok_or(())?;
    if root != block.header.tx_root {
        return Err(());
    }

    let expected_root = digest_to_fields(root);
    let mut inputs = Vec::with_capacity(target);
    for leaf_index in 0..target {
        let mut siblings = [[Block128::ZERO; 2]; MAX_MERKLE_DEPTH];
        let mut directions = [false; MAX_MERKLE_DEPTH];
        let mut index = leaf_index;
        for level_index in 0..depth {
            let sibling_index = index ^ 1;
            siblings[level_index] = digest_to_fields(levels[level_index][sibling_index]);
            directions[level_index] = (index & 1) == 1;
            index >>= 1;
        }
        inputs.push(MerklePathInputs {
            leaf: digest_to_fields(levels[0][leaf_index]),
            siblings,
            directions,
            expected_root,
            active_depth: depth,
        });
    }
    Ok(inputs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use noid_chain::block::{compute_tx_root, Block};
    use noid_chain::consensus::difficulty::{block_work, next_target};
    use noid_chain::consensus::fees::required_fee_for_tx_body;
    use noid_chain::consensus::params::{BLOCK_TIME, MAX_TARGET};
    use noid_chain::consensus::pow::search_pow;
    use noid_chain::exact_state_hash::composite_state_root;
    use noid_chain::fri_state::SlotValue;
    use noid_chain::{apply_tx, build_exact_action_surface};
    use noid_core::{Block128, TowerField};
    use noid_gkr::{
        owner_auth_gkr_channel, owner_auth_inputs_from_body_and_live_secrets,
        prove_owner_auth_killshot, OwnerAuthCircuit,
    };
    use noid_poseidon2b::primitives::Address;
    use noid_poseidon2b::primitives::{derive_address, SpendSecret};
    use noid_tx::{hash_tx_body_for_shape, Transaction, TxBody, TxInput, TxOutput, TxShape};

    fn parent_header(state: &mut ChainState) -> BlockHeader {
        BlockHeader {
            prev_block_hash: [0u8; 32],
            state_root: state.state_root(),
            tx_root: compute_tx_root(&[]),
            timestamp: 1_767_225_600,
            height: 0,
            miner_address: Address([0x11; 32]),
            nonce: 0,
            difficulty_target: MAX_TARGET,
            log_slots: state.state.log_slots() as u32,
            active_slot_count: state.active_slot_count,
            alloc_counter: state.alloc_counter,
        }
    }

    fn empty_child(parent: &BlockHeader, state: &mut ChainState) -> Block {
        let timestamp = parent.timestamp + BLOCK_TIME;
        let difficulty_target = next_target(
            0,
            parent.timestamp,
            &parent.difficulty_target,
            parent.height + 1,
            timestamp,
        );
        let mut header = BlockHeader {
            prev_block_hash: hash_block_header(parent),
            state_root: state.state_root(),
            tx_root: compute_tx_root(&[]),
            timestamp,
            height: parent.height + 1,
            miner_address: Address([0x22; 32]),
            nonce: 0,
            difficulty_target,
            log_slots: parent.log_slots,
            active_slot_count: parent.active_slot_count,
            alloc_counter: parent.alloc_counter,
        };
        header.nonce = search_pow(&header, 0, 1_000_000).expect("easy test target mines");
        Block {
            header,
            transactions: vec![],
        }
    }

    fn spend_secret(seed: u8) -> SpendSecret {
        let mut bytes = [0u8; 32];
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = seed.wrapping_mul(19).wrapping_add(i as u8);
        }
        SpendSecret(bytes)
    }

    fn tx_from_body(body: TxBody) -> Transaction {
        let tx_body_hash = hash_tx_body_for_shape(
            body.shape,
            &body.epoch_anchor,
            body.fee,
            &body.inputs,
            &body.outputs,
            body.is_coinbase,
        );
        Transaction { body, tx_body_hash }
    }

    fn auth_proof_for_body(body: &TxBody) -> noid_gkr::OwnerAuthProofKillShot {
        let live_secrets: Vec<_> = body
            .inputs
            .iter()
            .filter(|input| input.valid)
            .map(|input| input.spend_secret.clone())
            .collect();
        let auth_inputs = owner_auth_inputs_from_body_and_live_secrets(body, &live_secrets)
            .expect("test auth inputs");
        let circuit = OwnerAuthCircuit::build(auth_inputs.layout);
        let mut channel = owner_auth_gkr_channel();
        prove_owner_auth_killshot(&circuit, &auth_inputs, &mut channel).0
    }

    fn user_block_fixture() -> (
        RecursiveConsensusState,
        ChainAccumulator,
        BlockHeader,
        ChainState,
        FullAcceptedBlockBatchWitness,
    ) {
        let secret = spend_secret(7);
        let owner = derive_address(&secret);
        let mut start_state = ChainState::with_log_slots(4);
        let input_value = 10_000u64;
        let pre_slot = SlotValue {
            value: Block128::from(input_value as u128),
            owner_hi: owner.as_fields()[0],
            owner_lo: owner.as_fields()[1],
        };
        start_state.state.set_slot(2, pre_slot).unwrap();
        start_state.rebuild_exact_utxo_root_loaded().unwrap();
        start_state.active_slot_count = 1;
        start_state.alloc_counter = 2;
        let parent_state_root = start_state.cached_state_root();
        let parent = BlockHeader {
            prev_block_hash: [0u8; 32],
            state_root: parent_state_root,
            tx_root: compute_tx_root(&[]),
            timestamp: 1_767_225_600,
            height: 0,
            miner_address: Address([0x11; 32]),
            nonce: 0,
            difficulty_target: MAX_TARGET,
            log_slots: start_state.state.log_slots() as u32,
            active_slot_count: start_state.active_slot_count,
            alloc_counter: start_state.alloc_counter,
        };

        let mut body = TxBody {
            shape: TxShape::Standard4x8,
            epoch_anchor: [0x42; 32],
            fee: 0,
            inputs: vec![TxInput {
                slot_index: 2,
                value: input_value,
                owner,
                spend_secret: secret,
                valid: true,
            }],
            outputs: vec![TxOutput {
                slot_index: 5,
                value: input_value,
                owner,
                valid: true,
            }],
            is_coinbase: false,
        };
        let required_fee =
            required_fee_for_tx_body(&body, parent.active_slot_count, parent.log_slots);
        body.fee = required_fee as u128;
        body.outputs[0].value = input_value.saturating_sub(required_fee);
        let tx = tx_from_body(body.clone());
        let txs = vec![tx.clone()];

        let parent_cache = {
            let mut tmp = start_state.clone();
            tmp.exact_sparse_cache().unwrap()
        };
        let claims = vec![noid_tx::compute_claims_commitment(
            &body.inputs,
            &body.outputs,
        )];
        let surface = build_exact_action_surface(&start_state.state, &[body.clone()], &claims)
            .expect("exact action surface");
        let state_transition = crate::build_exact_state_transition_proof(
            &parent_cache,
            &surface,
            &start_state.reuse_guard,
            1,
        )
        .expect("exact proof");

        let mut child_state = start_state.clone();
        apply_tx(&mut child_state, &body).expect("native tx apply");
        let mut child_guard = start_state.reuse_guard.clone();
        child_guard
            .apply_spends(1, &surface.spent_slots)
            .expect("guard spend apply");
        let child_state_root =
            composite_state_root(parent.log_slots, child_state.utxo_root, child_guard.root());
        let mut header = BlockHeader {
            prev_block_hash: hash_block_header(&parent),
            state_root: child_state_root,
            tx_root: compute_tx_root(&txs),
            timestamp: parent.timestamp + BLOCK_TIME,
            height: 1,
            miner_address: Address([0x22; 32]),
            nonce: 0,
            difficulty_target: next_target(
                0,
                parent.timestamp,
                &parent.difficulty_target,
                1,
                parent.timestamp + BLOCK_TIME,
            ),
            log_slots: parent.log_slots,
            active_slot_count: start_state.active_slot_count,
            alloc_counter: start_state.alloc_counter + 1,
        };
        header.nonce = search_pow(&header, 0, 1_000_000).expect("easy test target mines");
        let block = Block {
            header,
            transactions: txs,
        };
        let block_proof = crate::BlockProof::minimal(
            parent.state_root,
            block.header.state_root,
            1,
            state_transition,
        );
        let auth_sidecar = crate::BlockAuthSidecar {
            tx_auth: vec![auth_proof_for_body(&body)],
        };
        let witness = FullAcceptedBlockBatchWitness {
            items: vec![FullAcceptedBlockBatchItem {
                block,
                block_proof_bytes: bincode::serialize(&block_proof).unwrap(),
                block_auth_sidecar_bytes: bincode::serialize(&auth_sidecar).unwrap(),
            }],
        };
        let start_consensus = RecursiveConsensusState::from_header(
            &parent,
            block_work(&parent.difficulty_target),
            0,
            parent.timestamp,
            parent.difficulty_target,
            &[parent.timestamp],
            &[parent.active_slot_count],
        );
        let start_accumulator = ChainAccumulator {
            height: parent.height,
            state_root: parent.state_root,
            chain_hash: [0u8; 32],
        };
        (
            start_consensus,
            start_accumulator,
            parent,
            start_state,
            witness,
        )
    }

    #[test]
    fn full_batch_accepts_coinbase_only_block_without_detached_proof() {
        let mut state = ChainState::with_log_slots(8);
        let parent = parent_header(&mut state);
        let start_consensus = RecursiveConsensusState::from_header(
            &parent,
            block_work(&parent.difficulty_target),
            0,
            parent.timestamp,
            parent.difficulty_target,
            &[parent.timestamp],
            &[parent.active_slot_count],
        );
        let start_accumulator = ChainAccumulator {
            height: parent.height,
            state_root: parent.state_root,
            chain_hash: [0u8; 32],
        };
        let mut block_state = state.clone();
        let block = empty_child(&parent, &mut block_state);
        let witness = FullAcceptedBlockBatchWitness {
            items: vec![FullAcceptedBlockBatchItem {
                block,
                block_proof_bytes: vec![],
                block_auth_sidecar_bytes: vec![],
            }],
        };

        let out = verify_full_accepted_block_batch_native(
            &start_consensus,
            &start_accumulator,
            &parent,
            &state,
            &witness,
        )
        .expect("coinbase-only block without detached proof is a valid timeless accepted block");
        assert_eq!(out.accepted_claim_batch.consensus_state.height, 1);
        assert_eq!(out.end_state.cached_state_root(), parent.state_root);
        assert_eq!(out.proof_components.accepted_claim_witness.headers.len(), 1);
        assert_eq!(out.proof_components.header_integer_trace.steps.len(), 1);
        assert!(out.proof_components.tx_root_inputs.is_empty());
        assert!(out.proof_components.exact_state_killshot_inputs.is_empty());
        assert_eq!(out.proof_components.authorization_totals.user_tx_count, 0);
        assert_eq!(
            out.proof_components.authorization_totals.owner_count_total,
            0
        );
        assert_eq!(
            out.proof_components
                .authorization_totals
                .live_input_count_total,
            0
        );
    }

    #[test]
    fn full_batch_rejects_wrong_start_parent() {
        let mut state = ChainState::with_log_slots(8);
        let mut parent = parent_header(&mut state);
        let start_consensus = RecursiveConsensusState::from_header(
            &parent,
            block_work(&parent.difficulty_target),
            0,
            parent.timestamp,
            parent.difficulty_target,
            &[parent.timestamp],
            &[parent.active_slot_count],
        );
        parent.height = 9;
        let start_accumulator = ChainAccumulator {
            height: start_consensus.height,
            state_root: start_consensus.state_root,
            chain_hash: [0u8; 32],
        };
        let mut original_parent_state = state.clone();
        let original_parent = parent_header(&mut original_parent_state);
        let mut block_state = state.clone();
        let block = empty_child(&original_parent, &mut block_state);
        let witness = FullAcceptedBlockBatchWitness {
            items: vec![FullAcceptedBlockBatchItem {
                block,
                block_proof_bytes: vec![],
                block_auth_sidecar_bytes: vec![],
            }],
        };

        assert!(matches!(
            verify_full_accepted_block_batch_native(
                &start_consensus,
                &start_accumulator,
                &parent,
                &state,
                &witness,
            ),
            Err(FullAcceptedBlockBatchError::StartParentMismatch)
        ));
    }

    #[test]
    fn full_batch_accepts_user_block_and_rejects_tampered_sidecar() {
        let (start_consensus, start_accumulator, parent, state, witness) = user_block_fixture();

        let out = verify_full_accepted_block_batch_native(
            &start_consensus,
            &start_accumulator,
            &parent,
            &state,
            &witness,
        )
        .expect("user block full accepted batch verifies");
        assert_eq!(out.accepted_claim_batch.consensus_state.height, 1);
        assert_eq!(
            out.end_state.cached_state_root(),
            witness.items[0].block.header.state_root
        );
        assert_eq!(out.proof_components.accepted_claim_witness.headers.len(), 1);
        assert_eq!(out.proof_components.header_integer_trace.steps.len(), 1);
        assert_eq!(out.proof_components.tx_body_standard_inputs.len(), 1);
        assert_eq!(out.proof_components.tx_body_standard_hashes.len(), 1);
        assert!(out.proof_components.tx_body_sweep_inputs.is_empty());
        assert!(out.proof_components.tx_body_sweep_hashes.is_empty());
        assert!(!out.proof_components.tx_root_inputs.is_empty());
        assert_eq!(out.proof_components.exact_state_killshot_inputs.len(), 1);
        assert_eq!(out.proof_components.authorization_totals.user_tx_count, 1);
        assert_eq!(
            out.proof_components.authorization_totals.owner_count_total,
            1
        );
        assert_eq!(
            out.proof_components
                .authorization_totals
                .live_input_count_total,
            1
        );
        let exact_inputs = &out.proof_components.exact_state_killshot_inputs[0];
        let exact_proof = crate::prove_exact_state_killshot(exact_inputs)
            .expect("derived exact-state component proves");
        crate::verify_exact_state_killshot(exact_inputs, &exact_proof)
            .expect("derived exact-state component verifies");
        let component_proof = prove_full_accepted_block_batch_components(
            &start_accumulator,
            &out.accepted_claim_batch.accumulator,
            &out.proof_components,
        )
        .expect("component proof proves");
        assert!(component_proof.byte_len(&out.proof_components) > 0);
        assert_eq!(component_proof.authorization_transcripts.len(), 1);
        let verified_components = verify_full_accepted_block_batch_components(
            &start_consensus,
            &start_accumulator,
            &out.accepted_claim_batch.accumulator,
            &out.proof_components,
            &component_proof,
        )
        .expect("component proof verifies");
        assert_eq!(verified_components, out.accepted_claim_batch);
        let (retained_out, retained_proof) = prove_retained_full_accepted_block_batch_proof(
            &start_consensus,
            &start_accumulator,
            &parent,
            &state,
            &witness,
        )
        .expect("retained proof proves");
        assert_eq!(retained_out.accepted_claim_batch, out.accepted_claim_batch);
        verify_retained_full_accepted_block_batch_proof(
            &start_consensus,
            &start_accumulator,
            &parent,
            &state,
            &witness,
            &retained_proof,
        )
        .expect("retained proof verifies from retained block witness");

        let mut bad_components = out.proof_components.clone();
        bad_components.tx_root_inputs[0].leaf[0] += Block128::ONE;
        assert!(matches!(
            verify_full_accepted_block_batch_components(
                &start_consensus,
                &start_accumulator,
                &verified_components.accumulator,
                &bad_components,
                &component_proof,
            ),
            Err(FullAcceptedBlockBatchError::TxRootComponent)
        ));

        let mut bad_components = out.proof_components.clone();
        bad_components.tx_body_standard_hashes[0][0] += Block128::ONE;
        assert!(matches!(
            verify_full_accepted_block_batch_components(
                &start_consensus,
                &start_accumulator,
                &verified_components.accumulator,
                &bad_components,
                &component_proof,
            ),
            Err(FullAcceptedBlockBatchError::TxBodyHashComponent)
        ));

        let mut bad_components = out.proof_components.clone();
        bad_components.authorization_witnesses[0]
            .boundary
            .state_at_r += Block128::ONE;
        assert!(matches!(
            verify_full_accepted_block_batch_components(
                &start_consensus,
                &start_accumulator,
                &verified_components.accumulator,
                &bad_components,
                &component_proof,
            ),
            Err(FullAcceptedBlockBatchError::AuthorizationComponent { .. })
        ));

        let mut bad_components = out.proof_components.clone();
        bad_components.authorization_totals.owner_count_total += 1;
        assert!(matches!(
            verify_full_accepted_block_batch_components(
                &start_consensus,
                &start_accumulator,
                &verified_components.accumulator,
                &bad_components,
                &component_proof,
            ),
            Err(FullAcceptedBlockBatchError::ComponentShapeMismatch)
        ));

        let mut bad_component_proof = component_proof.clone();
        bad_component_proof.authorization_transcripts[0].n_ops += 1;
        assert!(matches!(
            verify_full_accepted_block_batch_components(
                &start_consensus,
                &start_accumulator,
                &verified_components.accumulator,
                &out.proof_components,
                &bad_component_proof,
            ),
            Err(FullAcceptedBlockBatchError::AuthorizationComponent { .. })
                | Err(FullAcceptedBlockBatchError::ComponentShapeMismatch)
        ));

        let mut bad_sidecar =
            bincode::deserialize::<BlockAuthSidecar>(&witness.items[0].block_auth_sidecar_bytes)
                .expect("sidecar decodes");
        bad_sidecar.tx_auth[0].boundary.state_at_r += Block128::ONE;
        let mut bad_retained_witness = witness.clone();
        bad_retained_witness.items[0].block_auth_sidecar_bytes =
            bincode::serialize(&bad_sidecar).expect("sidecar serializes");
        assert!(matches!(
            verify_retained_full_accepted_block_batch_proof(
                &start_consensus,
                &start_accumulator,
                &parent,
                &state,
                &bad_retained_witness,
                &retained_proof,
            ),
            Err(FullAcceptedBlockBatchError::FullValidation { index: 0, .. })
        ));

        let mut tampered = witness.clone();
        tampered.items[0].block_auth_sidecar_bytes[0] ^= 0x01;
        assert!(matches!(
            verify_full_accepted_block_batch_native(
                &start_consensus,
                &start_accumulator,
                &parent,
                &state,
                &tampered,
            ),
            Err(FullAcceptedBlockBatchError::DecodeSidecar { index: 0 })
                | Err(FullAcceptedBlockBatchError::FullValidation { index: 0, .. })
                | Err(FullAcceptedBlockBatchError::Claim { index: 0, .. })
        ));
    }
}
