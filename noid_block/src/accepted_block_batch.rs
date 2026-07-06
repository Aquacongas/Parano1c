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
use noid_chain::header_anchor::{
    extend_header_chain_anchor, HeaderChainAnchor, HeaderChainAnchorError,
};
use noid_chain::state::ChainState;
use noid_core::{Block128, TowerField};
use noid_gkr::{
    prove_accepted_claim_hash_killshot, prove_batched_merkle_killshot,
    prove_block_spine_killshot, prove_sweep_block_spine_killshot, reconstruct_slot_states,
    spine_inputs_from_body, sweep_spine_inputs_from_body, AcceptedClaimHashInputs,
    AcceptedClaimHashProofKillShot, BatchedMerkleProofKillShot, BlockSpineMle, BlockSpineProof,
    MerkleCircuit, MerklePathInputs, SpineCircuit,
    SpineInputs, SweepBlockSpineMle, SweepBlockSpineProof, SweepSpineInputs, MAX_MERKLE_DEPTH,
};
use noid_poseidon2b::native::compress;
use noid_poseidon2b::primitives::Digest;
use noid_recursive::block_certificate_backend::{
    verify_accepted_block_batch_components as verify_recursive_accepted_block_batch_components,
    AcceptedBlockBatchComponentError as RecursiveBlockBatchComponentError,
    AcceptedBlockBatchComponentInputs as RecursiveBlockBatchComponentInputs,
    AcceptedBlockBatchComponentProof as RecursiveBlockBatchComponentProof,
};
use noid_recursive::{
    accepted_block_certificate_receipt,
    accepted_block_certificate_statement_from_acceptance_receipt,
    accepted_block_receipt_projection_handle,
    accepted_claim_batch_digest as recursive_accepted_claim_batch_digest,
    advance_history_checkpoint_head_native, build_header_integer_trace,
    history_checkpoint_head_from_boundary,
    prove_accepted_block_certificate_receipt_projection_proof, prove_checkpoint_poseidon,
    prove_history_checkpoint_recursive_head_record,
    prove_history_checkpoint_step_proof_with_ivc_chunk_certificate_proof_components,
    verify_accepted_block_certificate_proof_checkpoint,
    verify_accepted_block_certificate_receipt_projection,
    verify_accepted_claim_batch_with_header_trace, verify_authorization_statement_proof_with_trace,
    verify_history_checkpoint_step_proof_checkpoint,
    verify_history_checkpoint_step_proof_private_components_native,
    verify_pow_header_witness_batch_native, AcceptedBlockCertificateProof,
    AcceptedBlockCertificateProofError, AcceptedBlockCertificateReceipt,
    AcceptedBlockCertificateReceiptError, AcceptedBlockReceiptProjectionHandle,
    AcceptedBlockReceiptProjectionHandleError, AcceptedClaimBatchError, AcceptedClaimBatchOutput,
    AcceptedClaimBatchWitness, AuthorizationVerifierTrace, BlockProofAcceptanceReceipt,
    ChainAccumulator, CheckpointPoseidonError, CheckpointPoseidonProof,
    HeaderIntegerTraceError,
    HeaderWitness, HistoryCheckpointBatchSummary, HistoryCheckpointHead, HistoryCheckpointProof,
    HistoryCheckpointProofError, HistoryCheckpointStepProof, HistoryCheckpointStepProofError,
    HistoryCheckpointStepStatement, PowHeaderBatchError, RecursiveConsensusState,
    HISTORY_CHECKPOINT_BATCH_TARGET_BLOCKS,
};

use crate::validate::map_verify_authorization_error;
use crate::{
    accept_block_timeless_with_artifacts_with_auth_verifier,
    accepted_block_certificate_batch_statement, accepted_block_certificate_chain_claim,
    accepted_block_claim_fields_from_transcript, accepted_block_claim_from_transcript,
    accepted_block_claim_transcript, block_proof_acceptance_receipt,
    derive_exact_state_killshot_inputs, AcceptedBlockCertificateBatchError,
    AcceptedBlockCertificateBatchStatement, AcceptedBlockCertificateRecord, AuthorizationProof,
    AuthorizationVerifier, BlockAuthSidecar, BlockProof, CanonicalAuthorizationStatement,
    ExactStateKillShotError, ExactStateKillShotProof, FullValidationError, VerifiedAuthorization,
    VerifiedAuthorizationBatch, VerifyBlockError,
};
use noid_tx::TxShape;
use rayon::prelude::*;
use std::sync::Mutex;

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

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AcceptedBlockCertificateBatchItem {
    pub header: BlockHeader,
    pub certificate_record: AcceptedBlockCertificateRecord,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AcceptedBlockCertificateBatchWitness {
    pub items: Vec<AcceptedBlockCertificateBatchItem>,
}

#[derive(Debug)]
pub struct FullAcceptedBlockBatchOutput {
    pub accepted_claim_batch: AcceptedClaimBatchOutput,
    pub end_state: ChainState,
    pub proof_components: FullAcceptedBlockBatchProofComponents,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FullAcceptedBlockBatchProofComponents {
    /// Everything the dependency-clean component verifier consumes, in its
    /// own (shared) type — no mirror structs, no per-verify conversion.
    pub component_inputs: RecursiveBlockBatchComponentInputs,
    pub accepted_block_acceptance_receipts: Vec<BlockProofAcceptanceReceipt>,
    pub accepted_block_certificate_proofs: Vec<AcceptedBlockCertificateProof>,
    pub accepted_block_certificate_receipts: Vec<AcceptedBlockCertificateReceipt>,
    pub accepted_block_receipt_projection_handles: Vec<AcceptedBlockReceiptProjectionHandle>,
}

// The authorization component input and the retained proof are the recursive
// backend's types directly (they were 1:1 mirrors before).
pub use noid_recursive::block_certificate_backend::AuthorizationComponentInput;
pub type RetainedFullAcceptedBlockBatchProof = RecursiveBlockBatchComponentProof;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AcceptedBlockCertificateBatchCheckpointPackage {
    pub step_statement: HistoryCheckpointStepStatement,
    pub certificate_batch_statement: AcceptedBlockCertificateBatchStatement,
    pub checkpoint_step_proof: HistoryCheckpointStepProof,
}

impl AcceptedBlockCertificateBatchCheckpointPackage {
    pub fn start_height(&self) -> u64 {
        self.step_statement.batch_summary.start_anchor.height
    }

    pub fn end_height(&self) -> u64 {
        self.step_statement.batch_summary.end_anchor.height
    }

    pub fn byte_len(&self) -> usize {
        bincode::serialized_size(self)
            .expect("serialized AcceptedBlockCertificateBatchCheckpointPackage length fits usize")
            as usize
    }
}

pub fn public_history_checkpoint_proof_from_package(
    base_anchor: &HeaderChainAnchor,
    base_accumulator: &ChainAccumulator,
    package: &AcceptedBlockCertificateBatchCheckpointPackage,
) -> Result<HistoryCheckpointProof, FullAcceptedBlockBatchError> {
    if base_accumulator.height != base_anchor.height
        || base_accumulator.state_root != base_anchor.state_root
    {
        return Err(FullAcceptedBlockBatchError::CheckpointSummaryStartMismatch);
    }

    let record = prove_history_checkpoint_recursive_head_record(
        None,
        base_anchor,
        base_accumulator,
        &package.step_statement,
        &package.certificate_batch_statement,
        &package.checkpoint_step_proof,
    )
    .map_err(FullAcceptedBlockBatchError::CheckpointHead)?;
    Ok(bincode::deserialize(&record.proof_bytes)
        .expect("stored history checkpoint head record proof bytes decode"))
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
    HeaderAnchor {
        index: usize,
        source: HeaderChainAnchorError,
    },
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
    CertificateBatch(AcceptedBlockCertificateBatchError),
    CertificateReceiptProjectionProof {
        index: usize,
        source: AcceptedBlockCertificateProofError,
    },
    CertificateReceiptProjectionHandle {
        index: usize,
        source: AcceptedBlockReceiptProjectionHandleError,
    },
    CertificateReceipt {
        index: usize,
        source: AcceptedBlockCertificateReceiptError,
    },
    CertificateProofShape {
        acceptance_receipts: usize,
        statements: usize,
        proofs: usize,
        receipts: usize,
        handles: usize,
    },
    CertificateProofStatementMismatch {
        index: usize,
    },
    CertificateReceiptProjectionHandleMismatch {
        index: usize,
    },
    CheckpointHead(HistoryCheckpointProofError),
    CheckpointSummaryStartMismatch,
    CheckpointSummaryEndMismatch,
    CheckpointStep(HistoryCheckpointStepProofError),
}

/// `AcceptBlock` authorization verifier that captures each verified statement
/// and its FS trace for the recursive component inputs, so the batch replay
/// verifies every owner-auth killshot exactly once (the killshot verify is the
/// dominant per-tx cost; a second tracing pass would double it).
#[derive(Default)]
struct TracingOwnerAuthVerifier {
    captured: Mutex<Vec<(CanonicalAuthorizationStatement, AuthorizationVerifierTrace)>>,
}

impl TracingOwnerAuthVerifier {
    /// Captured (statement, trace) pairs in user-tx order. The capture order is
    /// nondeterministic (the accept path verifies per-tx proofs in parallel).
    fn into_captured_ordered(
        self,
    ) -> Vec<(CanonicalAuthorizationStatement, AuthorizationVerifierTrace)> {
        let mut captured = self
            .captured
            .into_inner()
            .expect("owner-auth trace mutex poisoned");
        captured.sort_by_key(|(statement, _)| statement.tx_index);
        captured
    }
}

impl AuthorizationVerifier for TracingOwnerAuthVerifier {
    fn verify(
        &self,
        statement: &CanonicalAuthorizationStatement,
        proof: &AuthorizationProof,
    ) -> Result<VerifiedAuthorization, VerifyBlockError> {
        let (verified, trace) = verify_authorization_statement_proof_with_trace(statement, proof)
            .map_err(|error| map_verify_authorization_error(error, statement.tx_index))?;
        self.captured
            .lock()
            .expect("owner-auth trace mutex poisoned")
            .push((statement.clone(), trace));
        Ok(verified)
    }
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
    let mut accepted_block_acceptance_receipts = Vec::with_capacity(witness.items.len());
    let mut accepted_block_certificate_statements = Vec::with_capacity(witness.items.len());
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
        let auth_tracer = TracingOwnerAuthVerifier::default();
        let validation = accept_block_timeless_with_artifacts_with_auth_verifier(
            &item.block,
            &item.block_proof_bytes,
            &item.block_auth_sidecar_bytes,
            &parent,
            &prev_timestamps,
            &prev_active_counts,
            &anchor,
            &mut state,
            &auth_tracer,
        )
        .map_err(|source| FullAcceptedBlockBatchError::FullValidation { index, source })?;

        if has_user_txs {
            let artifacts = &validation.artifacts;
            let proof = proof
                .as_ref()
                .expect("user-transaction block proof decoded above");
            let (standard_txs, sweep_txs) = item.block.transactions.iter().fold(
                (0usize, 0usize),
                |(s, w), tx| match tx.body.shape {
                    _ if tx.body.is_coinbase => (s, w),
                    noid_tx::TxShape::Standard4x8 => (s + 1, w),
                    noid_tx::TxShape::Sweep25x2 => (s, w + 1),
                },
            );
            let padded_spent_len =
                noid_chain::consensus::params::block_class_spend_capacity_for_counts(
                    standard_txs,
                    sweep_txs,
                )
                .ok_or(FullAcceptedBlockBatchError::ComponentShapeMismatch)?;
            let (inputs, verified) = derive_exact_state_killshot_inputs(
                &artifacts.exact_state_inputs,
                &artifacts.exact_action_surface,
                &pre_validation_guard,
                &proof.state_transition,
                padded_spent_len,
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

            let captured_auth = auth_tracer.into_captured_ordered();
            if captured_auth.len() != sidecar.tx_auth.len()
                || captured_auth.len() != artifacts.authorization.user_tx_count
            {
                return Err(FullAcceptedBlockBatchError::ComponentShapeMismatch);
            }
            for ((statement, trace), auth_proof) in
                captured_auth.into_iter().zip(sidecar.tx_auth.iter())
            {
                authorization_inputs.push(AuthorizationComponentInput {
                    block_index: index,
                    tx_index: statement.tx_index,
                    tx_body_hash: statement.tx_body_hash,
                    public: statement.public,
                });
                authorization_witnesses.push(auth_proof.clone());
                authorization_traces.push(trace);
            }
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
        let acceptance_receipt = block_proof_acceptance_receipt(
            &item.block,
            &parent,
            &prev_timestamps,
            &prev_active_counts,
            &anchor,
            &item.block_proof_bytes,
            &item.block_auth_sidecar_bytes,
            &validation.artifacts,
        )
        .map_err(|source| FullAcceptedBlockBatchError::Claim { index, source })?;
        let certificate_statement =
            accepted_block_certificate_statement_from_acceptance_receipt(&acceptance_receipt);
        let claim = accepted_block_certificate_chain_claim(&certificate_statement);
        if claim != accepted_block_claim_from_transcript(&transcript) {
            return Err(FullAcceptedBlockBatchError::Claim {
                index,
                source: VerifyBlockError::HistoryClaimMismatch,
            });
        }
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
        accepted_block_acceptance_receipts.push(acceptance_receipt);
        accepted_block_certificate_statements.push(certificate_statement);
        parent = item.block.header.clone();
    }

    let accepted_block_certificate_receipts = accepted_block_certificate_statements
        .iter()
        .map(accepted_block_certificate_receipt)
        .collect::<Vec<_>>();
    let certificate_proof_pairs = accepted_block_certificate_statements
        .par_iter()
        .enumerate()
        .map(|(index, statement)| {
            let proof = prove_accepted_block_certificate_receipt_projection_proof(statement)
                .map_err(|source| {
                    FullAcceptedBlockBatchError::CertificateReceiptProjectionProof { index, source }
                })?;
            let handle = accepted_block_receipt_projection_handle(&proof).map_err(|source| {
                FullAcceptedBlockBatchError::CertificateReceiptProjectionHandle { index, source }
            })?;
            Ok((proof, handle))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let (accepted_block_certificate_proofs, accepted_block_receipt_projection_handles): (
        Vec<_>,
        Vec<_>,
    ) = certificate_proof_pairs.into_iter().unzip();

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
            component_inputs: RecursiveBlockBatchComponentInputs {
                accepted_claim_witness,
                accepted_block_certificate_statements,
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
            accepted_block_acceptance_receipts,
            accepted_block_certificate_proofs,
            accepted_block_certificate_receipts,
            accepted_block_receipt_projection_handles,
        },
    })
}

pub(crate) fn prove_full_accepted_block_batch_components(
    start_accumulator: &ChainAccumulator,
    end_accumulator: &ChainAccumulator,
    components: &FullAcceptedBlockBatchProofComponents,
) -> Result<RetainedFullAcceptedBlockBatchProof, FullAcceptedBlockBatchError> {
    if components.component_inputs.accepted_claim_hash_inputs.len()
        != components
            .component_inputs
            .accepted_claim_witness
            .accepted_block_claims
            .len()
    {
        return Err(FullAcceptedBlockBatchError::ComponentShapeMismatch);
    }
    if components.component_inputs.authorization_inputs.len() != components.component_inputs.authorization_witnesses.len() {
        return Err(FullAcceptedBlockBatchError::ComponentShapeMismatch);
    }
    if components.component_inputs.authorization_traces.len() != components.component_inputs.authorization_witnesses.len() {
        return Err(FullAcceptedBlockBatchError::ComponentShapeMismatch);
    }
    validate_tx_body_component_shape(components)?;
    let claim_result =
        || -> Result<AcceptedClaimHashProofKillShot, FullAcceptedBlockBatchError> {
            let mut channel = noid_poseidon2b::channel::Poseidon2bChannel::new();
            Ok(prove_accepted_claim_hash_killshot(
                &components.component_inputs.accepted_claim_hash_inputs,
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
        ),
        FullAcceptedBlockBatchError,
    > {
        let (
            (tx_body_standard, tx_body_sweep),
            (tx_root, (checkpoint_poseidon, exact_state)),
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
                                    prove_checkpoint_poseidon(
                                        start_accumulator,
                                        end_accumulator,
                                        &components.component_inputs.accepted_claim_witness,
                                    )
                                    .map_err(FullAcceptedBlockBatchError::CheckpointPoseidon)
                                },
                                || prove_exact_state_components(components),
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
        ))
    };

    let (accepted_claim_hash, rest) = rayon::join(claim_result, rest_result);
    let accepted_claim_hash = accepted_claim_hash?;
    let (tx_body_standard, tx_body_sweep, tx_root, checkpoint_poseidon, exact_state) = rest?;

    Ok(RetainedFullAcceptedBlockBatchProof {
        accepted_claim_hash,
        tx_body_standard,
        tx_body_sweep,
        tx_root,
        checkpoint_poseidon,
        exact_state,
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

#[allow(clippy::too_many_arguments)]
pub fn prove_retained_block_certificate_batch_checkpoint_package_from_boundary(
    start_anchor: &HeaderChainAnchor,
    start_consensus: &RecursiveConsensusState,
    start_accumulator: &ChainAccumulator,
    start_parent: &BlockHeader,
    start_state: &ChainState,
    witness: &FullAcceptedBlockBatchWitness,
) -> Result<AcceptedBlockCertificateBatchCheckpointPackage, FullAcceptedBlockBatchError> {
    let previous_head =
        history_checkpoint_head_from_boundary(start_anchor, start_accumulator, start_consensus)
            .map_err(FullAcceptedBlockBatchError::CheckpointHead)?;
    prove_retained_block_certificate_batch_checkpoint_package(
        &previous_head,
        start_anchor,
        start_consensus,
        start_accumulator,
        start_parent,
        start_state,
        witness,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn prove_retained_block_certificate_batch_checkpoint_package(
    previous_head: &HistoryCheckpointHead,
    start_anchor: &HeaderChainAnchor,
    start_consensus: &RecursiveConsensusState,
    start_accumulator: &ChainAccumulator,
    start_parent: &BlockHeader,
    start_state: &ChainState,
    witness: &FullAcceptedBlockBatchWitness,
) -> Result<AcceptedBlockCertificateBatchCheckpointPackage, FullAcceptedBlockBatchError> {
    let output = verify_full_accepted_block_batch_native(
        start_consensus,
        start_accumulator,
        start_parent,
        start_state,
        witness,
    )?;
    let accepted_claim_batch_digest = accepted_claim_batch_digest(&output);
    let summary = history_checkpoint_batch_summary_from_full_accepted_output(
        start_anchor,
        start_consensus,
        start_accumulator,
        &output,
        accepted_claim_batch_digest,
    )?;
    let certificate_witness = certificate_batch_witness_from_retained_output(witness, &output)?;
    prove_accepted_block_certificate_batch_checkpoint_package(
        previous_head,
        start_anchor,
        &summary.end_anchor,
        start_consensus,
        &summary.end_consensus,
        start_accumulator,
        &certificate_witness,
    )
}

pub fn verify_accepted_block_certificate_batch_checkpoint_package(
    package: &AcceptedBlockCertificateBatchCheckpointPackage,
) -> Result<(), FullAcceptedBlockBatchError> {
    verify_history_checkpoint_step_proof_checkpoint(
        &package.step_statement,
        &package.certificate_batch_statement,
        &package.checkpoint_step_proof,
    )
    .map_err(FullAcceptedBlockBatchError::CheckpointStep)
}

fn certificate_batch_witness_from_retained_output(
    retained_witness: &FullAcceptedBlockBatchWitness,
    output: &FullAcceptedBlockBatchOutput,
) -> Result<AcceptedBlockCertificateBatchWitness, FullAcceptedBlockBatchError> {
    let components = &output.proof_components;
    let len = retained_witness.items.len();
    if components.accepted_block_acceptance_receipts.len() != len
        || components.component_inputs.accepted_block_certificate_statements.len() != len
        || components.accepted_block_certificate_proofs.len() != len
        || components.accepted_block_certificate_receipts.len() != len
        || components.accepted_block_receipt_projection_handles.len() != len
    {
        return Err(FullAcceptedBlockBatchError::ComponentShapeMismatch);
    }

    let items = (0..len)
        .map(|index| AcceptedBlockCertificateBatchItem {
            header: retained_witness.items[index].block.header.clone(),
            certificate_record: AcceptedBlockCertificateRecord {
                height: components.accepted_block_acceptance_receipts[index].height,
                acceptance_receipt: components.accepted_block_acceptance_receipts[index].clone(),
                statement: components.component_inputs.accepted_block_certificate_statements[index].clone(),
                proof: components.accepted_block_certificate_proofs[index].clone(),
                receipt: components.accepted_block_certificate_receipts[index].clone(),
                receipt_projection_handle: components.accepted_block_receipt_projection_handles
                    [index]
                    .clone(),
            },
        })
        .collect();
    Ok(AcceptedBlockCertificateBatchWitness { items })
}

pub fn prove_accepted_block_certificate_batch_checkpoint_package(
    previous_head: &HistoryCheckpointHead,
    start_anchor: &HeaderChainAnchor,
    end_anchor: &HeaderChainAnchor,
    start_consensus: &RecursiveConsensusState,
    end_consensus: &RecursiveConsensusState,
    start_accumulator: &ChainAccumulator,
    witness: &AcceptedBlockCertificateBatchWitness,
) -> Result<AcceptedBlockCertificateBatchCheckpointPackage, FullAcceptedBlockBatchError> {
    let (accepted_claim_witness, accepted_claim_output, certificate_records) =
        verify_accepted_block_certificate_batch_witness(
            start_anchor,
            end_anchor,
            start_consensus,
            end_consensus,
            start_accumulator,
            witness,
        )?;
    let accepted_claim_batch_digest =
        recursive_accepted_claim_batch_digest(&accepted_claim_witness, &accepted_claim_output)
            .map_err(|_| FullAcceptedBlockBatchError::ComponentShapeMismatch)?;
    let certificate_statements = certificate_records
        .iter()
        .map(|record| record.statement.clone())
        .collect::<Vec<_>>();
    let certificate_proofs = certificate_records
        .iter()
        .map(|record| record.proof.clone())
        .collect::<Vec<_>>();
    let certificate_receipts = certificate_records
        .iter()
        .map(|record| record.receipt.clone())
        .collect::<Vec<_>>();
    let certificate_acceptance_receipts = certificate_records
        .iter()
        .map(|record| record.acceptance_receipt.clone())
        .collect::<Vec<_>>();
    let certificate_batch_statement = accepted_block_certificate_batch_statement(
        &certificate_statements,
        &accepted_claim_witness.accepted_block_claims,
        accepted_claim_batch_digest,
    )
    .map_err(FullAcceptedBlockBatchError::CertificateBatch)?;
    let summary = HistoryCheckpointBatchSummary {
        batch_len: witness
            .items
            .len()
            .try_into()
            .map_err(|_| FullAcceptedBlockBatchError::ComponentShapeMismatch)?,
        start_anchor: start_anchor.clone(),
        end_anchor: end_anchor.clone(),
        start_accumulator: start_accumulator.clone(),
        end_accumulator: accepted_claim_output.accumulator.clone(),
        start_consensus: start_consensus.clone(),
        end_consensus: end_consensus.clone(),
        accepted_claim_batch_digest,
    };
    let next_head = advance_history_checkpoint_head_native(previous_head, &summary)
        .map_err(FullAcceptedBlockBatchError::CheckpointHead)?;
    let step_statement = HistoryCheckpointStepStatement {
        previous_head: previous_head.clone(),
        batch_summary: summary,
        next_head,
    };
    let checkpoint_step_proof =
        prove_history_checkpoint_step_proof_with_ivc_chunk_certificate_proof_components(
            &step_statement,
            &certificate_batch_statement,
            &certificate_acceptance_receipts,
            &certificate_statements,
            &certificate_proofs,
            &certificate_receipts,
            &accepted_claim_witness,
            &accepted_claim_output,
        )
        .map_err(FullAcceptedBlockBatchError::CheckpointStep)?;

    Ok(AcceptedBlockCertificateBatchCheckpointPackage {
        step_statement,
        certificate_batch_statement,
        checkpoint_step_proof,
    })
}

fn verify_accepted_block_certificate_batch_witness(
    start_anchor: &HeaderChainAnchor,
    end_anchor: &HeaderChainAnchor,
    start_consensus: &RecursiveConsensusState,
    end_consensus: &RecursiveConsensusState,
    start_accumulator: &ChainAccumulator,
    witness: &AcceptedBlockCertificateBatchWitness,
) -> Result<
    (
        AcceptedClaimBatchWitness,
        AcceptedClaimBatchOutput,
        Vec<AcceptedBlockCertificateRecord>,
    ),
    FullAcceptedBlockBatchError,
> {
    if witness.items.is_empty() {
        return Err(FullAcceptedBlockBatchError::EmptyBatch);
    }
    if witness.items.len() > HISTORY_CHECKPOINT_BATCH_TARGET_BLOCKS as usize {
        return Err(FullAcceptedBlockBatchError::ComponentShapeMismatch);
    }
    if !anchor_matches_consensus(start_anchor, start_consensus)
        || start_accumulator.height != start_anchor.height
        || start_accumulator.state_root != start_anchor.state_root
    {
        return Err(FullAcceptedBlockBatchError::CheckpointSummaryStartMismatch);
    }

    if !anchor_matches_consensus(end_anchor, end_consensus) {
        return Err(FullAcceptedBlockBatchError::CheckpointSummaryEndMismatch);
    }

    let mut previous_block_id = start_anchor.block_id;
    let mut previous_state_root = start_anchor.state_root;
    let mut previous_log_slots = start_anchor.log_slots;
    let mut previous_active_slot_count = start_anchor.active_slot_count;
    let mut previous_alloc_counter = start_anchor.alloc_counter;
    let mut accumulator = start_accumulator.clone();
    let mut headers = Vec::with_capacity(witness.items.len());
    let mut claims = Vec::with_capacity(witness.items.len());
    let mut records = Vec::with_capacity(witness.items.len());

    for (index, item) in witness.items.iter().enumerate() {
        let expected_height = start_anchor
            .height
            .saturating_add(index as u64)
            .saturating_add(1);
        let header = &item.header;
        let record = &item.certificate_record;
        let statement = &record.statement;
        let expected_statement = accepted_block_certificate_statement_from_acceptance_receipt(
            &record.acceptance_receipt,
        );
        if &expected_statement != statement {
            return Err(FullAcceptedBlockBatchError::ComponentShapeMismatch);
        }
        if header.height != expected_height
            || record.height != expected_height
            || record.acceptance_receipt.height != expected_height
            || statement.height != expected_height
            || statement.block_id != hash_block_header(header)
            || header.prev_block_hash != previous_block_id
            || statement.parent_block_id != previous_block_id
            || statement.parent_state_root != previous_state_root
            || statement.child_state_root != header.state_root
            || statement.tx_root != header.tx_root
            || record.acceptance_receipt.parent_log_slots != previous_log_slots
            || record.acceptance_receipt.child_log_slots != header.log_slots
            || record.acceptance_receipt.parent_active_slot_count != previous_active_slot_count
            || record.acceptance_receipt.child_active_slot_count != header.active_slot_count
            || record.acceptance_receipt.parent_alloc_counter != previous_alloc_counter
            || record.acceptance_receipt.child_alloc_counter != header.alloc_counter
        {
            return Err(FullAcceptedBlockBatchError::ComponentShapeMismatch);
        }

        verify_accepted_block_certificate_receipt_projection(statement, &record.receipt)
            .map_err(|source| FullAcceptedBlockBatchError::CertificateReceipt { index, source })?;
        verify_accepted_block_certificate_proof_checkpoint(statement, &record.proof).map_err(
            |source| FullAcceptedBlockBatchError::CertificateReceiptProjectionProof {
                index,
                source,
            },
        )?;
        let expected_handle =
            accepted_block_receipt_projection_handle(&record.proof).map_err(|source| {
                FullAcceptedBlockBatchError::CertificateReceiptProjectionHandle { index, source }
            })?;
        if expected_handle != record.receipt_projection_handle {
            return Err(
                FullAcceptedBlockBatchError::CertificateReceiptProjectionHandleMismatch { index },
            );
        }

        let header_witness = HeaderWitness::from_header(header);
        let chain_claim = accepted_block_certificate_chain_claim(statement);
        accumulator = accumulator.extend(
            header.state_root,
            statement.block_id,
            header.height,
            chain_claim,
        );
        previous_block_id = statement.block_id;
        previous_state_root = statement.child_state_root;
        previous_log_slots = header.log_slots;
        previous_active_slot_count = header.active_slot_count;
        previous_alloc_counter = header.alloc_counter;

        headers.push(header_witness);
        claims.push(chain_claim);
        records.push(record.clone());
    }

    let accepted_claim_witness = AcceptedClaimBatchWitness {
        headers,
        accepted_block_claims: claims,
    };
    if previous_block_id != end_anchor.block_id
        || previous_state_root != end_anchor.state_root
        || accumulator.height != end_anchor.height
        || accumulator.state_root != end_anchor.state_root
    {
        return Err(FullAcceptedBlockBatchError::CheckpointSummaryEndMismatch);
    }
    let accepted_claim_output = AcceptedClaimBatchOutput {
        consensus_state: end_consensus.clone(),
        accumulator,
    };

    Ok((accepted_claim_witness, accepted_claim_output, records))
}

pub fn history_checkpoint_batch_summary_from_full_accepted_output(
    start_anchor: &HeaderChainAnchor,
    start_consensus: &RecursiveConsensusState,
    start_accumulator: &ChainAccumulator,
    output: &FullAcceptedBlockBatchOutput,
    accepted_claim_batch_digest: Digest,
) -> Result<HistoryCheckpointBatchSummary, FullAcceptedBlockBatchError> {
    let headers = &output.proof_components.component_inputs.accepted_claim_witness.headers;
    if headers.is_empty() || headers.len() > HISTORY_CHECKPOINT_BATCH_TARGET_BLOCKS as usize {
        return Err(FullAcceptedBlockBatchError::ComponentShapeMismatch);
    }
    if !anchor_matches_consensus(start_anchor, start_consensus)
        || start_accumulator.height != start_anchor.height
        || start_accumulator.state_root != start_anchor.state_root
    {
        return Err(FullAcceptedBlockBatchError::CheckpointSummaryStartMismatch);
    }

    let mut rolling_anchor = start_anchor.clone();
    let mut rolling_consensus = start_consensus.clone();
    for (index, header_witness) in headers.iter().enumerate() {
        rolling_consensus = verify_pow_header_witness_batch_native(
            &rolling_consensus,
            std::slice::from_ref(header_witness),
        )
        .map_err(|source| FullAcceptedBlockBatchError::HeaderWork { index, source })?;
        rolling_anchor = extend_header_chain_anchor(
            &rolling_anchor,
            &header_witness.header,
            rolling_consensus.cumulative_chainwork,
        )
        .map_err(|source| FullAcceptedBlockBatchError::HeaderAnchor { index, source })?;
    }

    if rolling_consensus != output.accepted_claim_batch.consensus_state
        || !anchor_matches_consensus(
            &rolling_anchor,
            &output.accepted_claim_batch.consensus_state,
        )
        || output.accepted_claim_batch.accumulator.height != rolling_anchor.height
        || output.accepted_claim_batch.accumulator.state_root != rolling_anchor.state_root
    {
        return Err(FullAcceptedBlockBatchError::CheckpointSummaryEndMismatch);
    }

    Ok(HistoryCheckpointBatchSummary {
        batch_len: headers
            .len()
            .try_into()
            .map_err(|_| FullAcceptedBlockBatchError::ComponentShapeMismatch)?,
        start_anchor: start_anchor.clone(),
        end_anchor: rolling_anchor,
        start_accumulator: start_accumulator.clone(),
        end_accumulator: output.accepted_claim_batch.accumulator.clone(),
        start_consensus: start_consensus.clone(),
        end_consensus: output.accepted_claim_batch.consensus_state.clone(),
        accepted_claim_batch_digest,
    })
}

pub fn accepted_claim_batch_digest(output: &FullAcceptedBlockBatchOutput) -> Digest {
    recursive_accepted_claim_batch_digest(
        &output.proof_components.component_inputs.accepted_claim_witness,
        &output.accepted_claim_batch,
    )
    .expect("verified full accepted batch output has a valid digest shape")
}

pub fn accepted_block_certificate_batch_statement_from_full_accepted_output(
    output: &FullAcceptedBlockBatchOutput,
    accepted_claim_batch_digest: Digest,
) -> Result<AcceptedBlockCertificateBatchStatement, FullAcceptedBlockBatchError> {
    accepted_block_certificate_batch_statement(
        &output
            .proof_components
            .component_inputs
            .accepted_block_certificate_statements,
        &output
            .proof_components
            .component_inputs
            .accepted_claim_witness
            .accepted_block_claims,
        accepted_claim_batch_digest,
    )
    .map_err(FullAcceptedBlockBatchError::CertificateBatch)
}

fn validate_full_accepted_certificate_package(
    components: &FullAcceptedBlockBatchProofComponents,
) -> Result<(), FullAcceptedBlockBatchError> {
    let acceptance_receipts = &components.accepted_block_acceptance_receipts;
    let statements = &components.component_inputs.accepted_block_certificate_statements;
    let proofs = &components.accepted_block_certificate_proofs;
    let receipts = &components.accepted_block_certificate_receipts;
    let handles = &components.accepted_block_receipt_projection_handles;
    if acceptance_receipts.len() != statements.len()
        || proofs.len() != statements.len()
        || receipts.len() != statements.len()
        || handles.len() != statements.len()
    {
        return Err(FullAcceptedBlockBatchError::CertificateProofShape {
            acceptance_receipts: acceptance_receipts.len(),
            statements: statements.len(),
            proofs: proofs.len(),
            receipts: receipts.len(),
            handles: handles.len(),
        });
    }
    for (index, statement) in statements.iter().enumerate() {
        if accepted_block_certificate_statement_from_acceptance_receipt(&acceptance_receipts[index])
            != *statement
        {
            return Err(FullAcceptedBlockBatchError::CertificateProofStatementMismatch { index });
        }
        verify_accepted_block_certificate_receipt_projection(statement, &receipts[index])
            .map_err(|source| FullAcceptedBlockBatchError::CertificateReceipt { index, source })?;
        let statement_digest =
            noid_recursive::accepted_block_certificate_statement_digest(statement);
        if proofs[index].statement_digest != statement_digest {
            return Err(FullAcceptedBlockBatchError::CertificateProofStatementMismatch { index });
        }
        let expected_handle =
            accepted_block_receipt_projection_handle(&proofs[index]).map_err(|source| {
                FullAcceptedBlockBatchError::CertificateReceiptProjectionHandle { index, source }
            })?;
        if expected_handle != handles[index] {
            return Err(
                FullAcceptedBlockBatchError::CertificateReceiptProjectionHandleMismatch { index },
            );
        }
    }
    Ok(())
}

pub fn prove_history_checkpoint_step_proof_from_verified_full_accepted_output(
    statement: &HistoryCheckpointStepStatement,
    output: &FullAcceptedBlockBatchOutput,
) -> Result<
    (
        HistoryCheckpointStepProof,
        AcceptedBlockCertificateBatchStatement,
    ),
    FullAcceptedBlockBatchError,
> {
    validate_full_accepted_certificate_package(&output.proof_components)?;
    let accepted_claim_batch_digest = accepted_claim_batch_digest(output);
    let certificate_batch_statement =
        accepted_block_certificate_batch_statement_from_full_accepted_output(
            output,
            accepted_claim_batch_digest,
        )?;
    let checkpoint_step_proof =
        prove_history_checkpoint_step_proof_with_ivc_chunk_certificate_proof_components(
            statement,
            &certificate_batch_statement,
            &output.proof_components.accepted_block_acceptance_receipts,
            &output
                .proof_components
                .component_inputs
            .accepted_block_certificate_statements,
            &output.proof_components.accepted_block_certificate_proofs,
            &output.proof_components.accepted_block_certificate_receipts,
            &output.proof_components.component_inputs.accepted_claim_witness,
            &output.accepted_claim_batch,
        )
        .map_err(FullAcceptedBlockBatchError::CheckpointStep)?;
    Ok((checkpoint_step_proof, certificate_batch_statement))
}

pub fn verify_history_checkpoint_step_proof_with_verified_full_accepted_output(
    statement: &HistoryCheckpointStepStatement,
    certificate_batch_statement: &AcceptedBlockCertificateBatchStatement,
    output: &FullAcceptedBlockBatchOutput,
    checkpoint_step_proof: &HistoryCheckpointStepProof,
) -> Result<(), FullAcceptedBlockBatchError> {
    validate_full_accepted_certificate_package(&output.proof_components)?;
    verify_history_checkpoint_step_proof_private_components_native(
        statement,
        certificate_batch_statement,
        &output.proof_components.component_inputs.accepted_claim_witness,
        &output.accepted_claim_batch,
        checkpoint_step_proof,
    )
    .map_err(FullAcceptedBlockBatchError::CheckpointStep)
}

pub(crate) fn verify_full_accepted_block_batch_components(
    start_consensus: &RecursiveConsensusState,
    start_accumulator: &ChainAccumulator,
    end_accumulator: &ChainAccumulator,
    components: &FullAcceptedBlockBatchProofComponents,
    proof: &RetainedFullAcceptedBlockBatchProof,
) -> Result<AcceptedClaimBatchOutput, FullAcceptedBlockBatchError> {
    verify_recursive_accepted_block_batch_components(
        start_consensus,
        start_accumulator,
        end_accumulator,
        &components.component_inputs,
        proof,
    )
    .map_err(map_recursive_component_error)
}

fn map_recursive_component_error(
    error: RecursiveBlockBatchComponentError,
) -> FullAcceptedBlockBatchError {
    match error {
        RecursiveBlockBatchComponentError::ComponentShapeMismatch
        | RecursiveBlockBatchComponentError::CertificateStatementMismatch { .. }
        | RecursiveBlockBatchComponentError::AcceptedClaimHashProofRejected
        | RecursiveBlockBatchComponentError::ExactState { .. } => {
            FullAcceptedBlockBatchError::ComponentShapeMismatch
        }
        RecursiveBlockBatchComponentError::TxBodyHashProofRejected => {
            FullAcceptedBlockBatchError::TxBodyHashComponent
        }
        RecursiveBlockBatchComponentError::TxRootProofRejected => {
            FullAcceptedBlockBatchError::TxRootComponent
        }
        RecursiveBlockBatchComponentError::AuthorizationProofRejected { index, tx_index } => {
            FullAcceptedBlockBatchError::AuthorizationComponent { index, tx_index }
        }
        RecursiveBlockBatchComponentError::AcceptedClaimBatch(source) => {
            FullAcceptedBlockBatchError::AcceptedClaimBatch(source)
        }
        RecursiveBlockBatchComponentError::CheckpointPoseidon(source) => {
            FullAcceptedBlockBatchError::CheckpointPoseidon(source)
        }
    }
}

fn anchor_matches_consensus(
    anchor: &HeaderChainAnchor,
    consensus: &RecursiveConsensusState,
) -> bool {
    anchor.height == consensus.height
        && anchor.block_id == consensus.block_id
        && anchor.state_root == consensus.state_root
        && anchor.cumulative_chainwork == consensus.cumulative_chainwork
        && anchor.log_slots == consensus.log_slots
        && anchor.active_slot_count == consensus.active_slot_count
        && anchor.alloc_counter == consensus.alloc_counter
}

fn prove_tx_root_component(
    components: &FullAcceptedBlockBatchProofComponents,
) -> Result<Option<BatchedMerkleProofKillShot>, FullAcceptedBlockBatchError> {
    if components.component_inputs.tx_root_inputs.is_empty() {
        return Ok(None);
    }
    let circuit = MerkleCircuit::build();
    let mut channel = noid_poseidon2b::channel::Poseidon2bChannel::new();
    Ok(Some(
        prove_batched_merkle_killshot(&circuit, &components.component_inputs.tx_root_inputs, &mut channel).0,
    ))
}

fn prove_exact_state_components(
    components: &FullAcceptedBlockBatchProofComponents,
) -> Result<Vec<ExactStateKillShotProof>, FullAcceptedBlockBatchError> {
    components
        .component_inputs
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

fn validate_tx_body_component_shape(
    components: &FullAcceptedBlockBatchProofComponents,
) -> Result<(), FullAcceptedBlockBatchError> {
    if components.component_inputs.tx_body_standard_inputs.len() != components.component_inputs.tx_body_standard_hashes.len()
        || components.component_inputs.tx_body_sweep_inputs.len() != components.component_inputs.tx_body_sweep_hashes.len()
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
    if components.component_inputs.tx_body_standard_inputs.is_empty() {
        return Ok(None);
    }
    let slot_state_ins = standard_tx_body_slot_state_ins(&components.component_inputs.tx_body_standard_inputs);
    let mle = BlockSpineMle::build(components.component_inputs.tx_body_standard_inputs.len(), &slot_state_ins);
    let mut channel = noid_poseidon2b::channel::Poseidon2bChannel::new();
    Ok(Some(
        prove_block_spine_killshot(
            components.component_inputs.tx_body_standard_inputs.len(),
            &mle,
            &components.component_inputs.tx_body_standard_hashes,
            &mut channel,
        )
        .0,
    ))
}

fn prove_sweep_tx_body_component(
    components: &FullAcceptedBlockBatchProofComponents,
) -> Result<Option<SweepBlockSpineProof>, FullAcceptedBlockBatchError> {
    if components.component_inputs.tx_body_sweep_inputs.is_empty() {
        return Ok(None);
    }
    let mle = SweepBlockSpineMle::build(&components.component_inputs.tx_body_sweep_inputs);
    let mut channel = noid_poseidon2b::channel::Poseidon2bChannel::new();
    Ok(Some(
        prove_sweep_block_spine_killshot(
            components.component_inputs.tx_body_sweep_inputs.len(),
            &mle,
            &components.component_inputs.tx_body_sweep_hashes,
            &mut channel,
        )
        .0,
    ))
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

    // Paths are emitted for the REAL leaves only. Padding slots
    // (transactions.len()..target) are constant zero leaves whose subtree
    // hashes appear as the right-hand siblings of the last real path; the
    // root reconstruction above already binds them natively, and a replay
    // that treats siblings as free witness must pin those right-hand
    // siblings to the canonical zero-subtree constants (the last path's
    // sibling at level L is the depth-L zero subtree whenever its direction
    // bit says "left child").
    let expected_root = digest_to_fields(root);
    let mut inputs = Vec::with_capacity(block.transactions.len());
    for leaf_index in 0..block.transactions.len() {
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
    use noid_chain::header_anchor::compute_header_chain_anchor;
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

    /// Cheap probe (no proving): the REAL 1-std-tx block's region wallet-PCS
    /// discharge shape (claim count, arities, standalone wire cost) at a few
    /// `RegionDischargeParams`, to size the region-mode block-bearing class.
    #[test]
    fn region_wallet_pcs_shape_probe() {
        use noid_ivc_core::field_circuit::FieldR1csBuilder;
        use noid_recursive::acceptance::block_slots::{
            build_block_slots_with_config, BlockSlotsConfig,
        };
        use noid_recursive::acceptance::trace::region_source_binding::RegionDischargeParams;

        let units = chained_std_tx_blocks(1);
        for (nq, sb8) in [(4usize, 2usize), (2usize, 1usize)] {
            let cfg = BlockSlotsConfig {
                discharge_wallet_pcs: true,
                wallet_pcs_region: Some(RegionDischargeParams {
                    nq,
                    sb8_auth_layers: sb8,
                }),
            };
            let mut b = FieldR1csBuilder::new();
            let slots = build_block_slots_with_config(
                &mut b,
                &units[0].start_accumulator,
                &units[0].end_accumulator,
                &units[0].inputs,
                &units[0].proof,
                cfg,
            );
            let claims = &slots.pending_wallet_pcs;
            let max_arity = claims.iter().map(|c| c.point.len()).max().unwrap_or(0);
            eprintln!(
                "[probe] nq={nq} sb8={sb8}: block-slot wires={}, claims={}, max_arity={}, \
                 tail_lanes={}",
                b.num_wires(),
                claims.len(),
                max_arity,
                claims.len() * (max_arity + 1)
            );
        }
    }

    /// Size the region-mode block-bearing link: run the freeze (which prints
    /// the full link's used-wire count via build_link's eprintln) at a couple
    /// of `(nq, sb8)` at a given class m, tolerating the class-shape assert so
    /// the printed size is visible even when a choice does not fit.
    #[test]
    #[ignore = "measurement helper; run explicitly to size the region link"]
    fn region_link_size_measure() {
        use noid_ivc_core::pcs::{self, PcsParams};
        use noid_ivc_core::proof::FieldShape;
        use noid_ivc_core::zerocheck::K_SKIP;
        use noid_recursive::acceptance::block_slots::BlockSlotsConfig;
        use noid_recursive::acceptance::link::{LinkBlock, LinkClass};
        use noid_recursive::acceptance::trace::region_source_binding::RegionDischargeParams;

        const CLASS_M: usize = 23;
        let shape = FieldShape {
            m: CLASS_M,
            k_log: CLASS_M,
            k_skip: K_SKIP,
            const_pin: Some(0),
        };
        let params = PcsParams {
            m: CLASS_M + pcs::LOG_PACKING,
            log_inv_rate: 2,
            log_batch_size: 5,
            profile: Default::default(),
        };
        let units = chained_std_tx_blocks(1);
        for (nq, sb8) in [(1usize, 1usize)] {
            let rp = RegionDischargeParams { nq, sb8_auth_layers: sb8 };
            let cfg = BlockSlotsConfig { discharge_wallet_pcs: true, wallet_pcs_region: Some(rp) };
            let sample = LinkBlock {
                start_accumulator: &units[0].start_accumulator,
                end_accumulator: &units[0].end_accumulator,
                inputs: &units[0].inputs,
                proof: &units[0].proof,
                config: cfg,
            };
            let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let class = LinkClass::new_region_block_bearing(
                    shape,
                    params.clone(),
                    units[0].start_accumulator.clone(),
                    rp,
                    &sample,
                );
                (class.region_claims.len(), class.region_max_arity, class.spec.io_len)
            }));
            match r {
                Ok((n, ma, io)) => eprintln!(
                    "[size] nq={nq} sb8={sb8} @m={CLASS_M}: FIT  claims={n} max_arity={ma} io_len={io}"
                ),
                Err(_) => eprintln!("[size] nq={nq} sb8={sb8} @m={CLASS_M}: (see wire count above)"),
            }
        }
    }

    /// One accepted block plus everything the single-block component
    /// verifier consumes, in per-block form (the shape a recursion link
    /// ingests — K = 1 structural).
    #[allow(dead_code)]
    struct BlockUnit {
        start_accumulator: ChainAccumulator,
        end_accumulator: ChainAccumulator,
        inputs: RecursiveBlockBatchComponentInputs,
        proof: RetainedFullAcceptedBlockBatchProof,
        block_header: BlockHeader,
    }

    /// Build one single-standard-tx block spending `input_slot` (owned by
    /// `secret`, holding `input_value`) into `output_slot`, mirroring
    /// `user_block_fixture`'s block construction but parameterized so a
    /// chain of same-tier blocks can be produced.
    fn make_std_tx_block_item(
        start_state: &ChainState,
        start_parent: &BlockHeader,
        anchor: &AnchorInfo,
        input_slot: u32,
        output_slot: u32,
        secret: &SpendSecret,
        input_value: u64,
    ) -> (FullAcceptedBlockBatchItem, BlockHeader, u64) {
        let owner = derive_address(secret);
        let mut body = TxBody {
            shape: TxShape::Standard4x8,
            epoch_anchor: [0x42; 32],
            fee: 0,
            inputs: vec![TxInput {
                slot_index: input_slot,
                value: input_value,
                owner,
                spend_secret: secret.clone(),
                valid: true,
            }],
            outputs: vec![TxOutput {
                slot_index: output_slot,
                value: input_value,
                owner,
                valid: true,
            }],
            is_coinbase: false,
        };
        let required_fee =
            required_fee_for_tx_body(&body, start_parent.active_slot_count, start_parent.log_slots);
        body.fee = required_fee as u128;
        body.outputs[0].value = input_value.saturating_sub(required_fee);
        let tx = tx_from_body(body.clone());
        let txs = vec![tx];

        let height = start_parent.height + 1;
        let parent_cache = {
            let mut tmp = start_state.clone();
            tmp.exact_sparse_cache().unwrap()
        };
        let claims = vec![noid_tx::compute_claims_commitment(&body.inputs, &body.outputs)];
        let surface = build_exact_action_surface(&start_state.state, &[body.clone()], &claims)
            .expect("exact action surface");
        let state_transition = crate::build_exact_state_transition_proof(
            &parent_cache,
            &surface,
            &start_state.reuse_guard,
            height,
        )
        .expect("exact proof");

        let mut child_state = start_state.clone();
        apply_tx(&mut child_state, &body).expect("native tx apply");
        let mut child_guard = start_state.reuse_guard.clone();
        child_guard
            .apply_spends(height, &surface.spent_slots)
            .expect("guard spend apply");
        let child_state_root = composite_state_root(
            start_parent.log_slots,
            child_state.utxo_root,
            child_guard.root(),
        );
        let mut header = BlockHeader {
            prev_block_hash: hash_block_header(start_parent),
            state_root: child_state_root,
            tx_root: compute_tx_root(&txs),
            timestamp: start_parent.timestamp + BLOCK_TIME,
            height: start_parent.height + 1,
            miner_address: Address([0x22; 32]),
            nonce: 0,
            difficulty_target: next_target(
                anchor.anchor_height,
                anchor.anchor_timestamp,
                &anchor.anchor_target,
                start_parent.height + 1,
                start_parent.timestamp + BLOCK_TIME,
            ),
            log_slots: start_parent.log_slots,
            active_slot_count: start_state.active_slot_count,
            alloc_counter: start_state.alloc_counter + 1,
        };
        header.nonce = search_pow(&header, 0, 1_000_000).expect("easy test target mines");
        let block = Block {
            header: header.clone(),
            transactions: txs,
        };
        let block_proof = crate::BlockProof::minimal(
            start_parent.state_root,
            block.header.state_root,
            1,
            state_transition,
        );
        let auth_sidecar = crate::BlockAuthSidecar {
            tx_auth: vec![auth_proof_for_body(&body)],
        };
        let surviving_value = body.outputs[0].value;
        (
            FullAcceptedBlockBatchItem {
                block,
                block_proof_bytes: bincode::serialize(&block_proof).unwrap(),
                block_auth_sidecar_bytes: bincode::serialize(&auth_sidecar).unwrap(),
            },
            header,
            surviving_value,
        )
    }

    /// Produce a chain of `n` same-tier (1 standard tx, 1 owner) blocks,
    /// each spending the previous block's output slot, in per-block link
    /// form. Block 1 spends a premined slot; block i≥2 spends block i−1's
    /// output. Same secret throughout, so every block is one owner / one
    /// input / one output — a fixed class tier.
    fn chained_std_tx_blocks(n: usize) -> Vec<BlockUnit> {
        assert!(n >= 1);
        let secret = spend_secret(7);
        let owner = derive_address(&secret);
        // Large enough that a chain of same-tier blocks stays solvent: each
        // block burns a fixed ~fee, and the surviving value flows forward.
        let input_value = 10_000_000u64;

        let mut state = ChainState::with_log_slots(4);
        let first_input_slot = 2u32;
        state
            .state
            .set_slot(
                first_input_slot,
                SlotValue {
                    value: Block128::from(input_value as u128),
                    owner_hi: owner.as_fields()[0],
                    owner_lo: owner.as_fields()[1],
                },
            )
            .unwrap();
        state.rebuild_exact_utxo_root_loaded().unwrap();
        state.active_slot_count = 1;
        state.alloc_counter = 2;

        let mut parent = BlockHeader {
            prev_block_hash: [0u8; 32],
            state_root: state.cached_state_root(),
            tx_root: compute_tx_root(&[]),
            timestamp: 1_767_225_600,
            height: 0,
            miner_address: Address([0x11; 32]),
            nonce: 0,
            difficulty_target: MAX_TARGET,
            log_slots: state.state.log_slots() as u32,
            active_slot_count: state.active_slot_count,
            alloc_counter: state.alloc_counter,
        };
        let mut consensus = RecursiveConsensusState::from_header(
            &parent,
            block_work(&parent.difficulty_target),
            0,
            parent.timestamp,
            parent.difficulty_target,
            &[parent.timestamp],
            &[parent.active_slot_count],
        );
        let mut accumulator = ChainAccumulator {
            height: parent.height,
            state_root: parent.state_root,
            chain_hash: [0u8; 32],
        };

        let mut units = Vec::with_capacity(n);
        let mut input_slot = first_input_slot;
        let mut value = input_value;
        for i in 0..n {
            let output_slot = input_slot + 3; // stay inside the log_slots-4 space
            let anchor = AnchorInfo {
                anchor_height: consensus.asert_anchor_height,
                anchor_timestamp: consensus.asert_anchor_timestamp,
                anchor_target: consensus.asert_anchor_target,
            };
            let (item, header, surviving_value) = make_std_tx_block_item(
                &state,
                &parent,
                &anchor,
                input_slot,
                output_slot,
                &secret,
                value,
            );
            let witness = FullAcceptedBlockBatchWitness {
                items: vec![item],
            };
            let (output, proof) = prove_retained_full_accepted_block_batch_proof(
                &consensus,
                &accumulator,
                &parent,
                &state,
                &witness,
            )
            .unwrap_or_else(|e| panic!("block {i} proves: {e:?}"));

            units.push(BlockUnit {
                start_accumulator: accumulator.clone(),
                end_accumulator: output.accepted_claim_batch.accumulator.clone(),
                inputs: output.proof_components.component_inputs.clone(),
                proof,
                block_header: header.clone(),
            });

            state = output.end_state;
            consensus = output.accepted_claim_batch.consensus_state;
            accumulator = output.accepted_claim_batch.accumulator;
            parent = header;
            input_slot = output_slot;
            value = surviving_value;
        }
        units
    }

    /// THE stage-2 payoff: a CLOSED recursion over REAL blocks. π₀ (genesis
    /// link over block 0) → π₁ (verifies π₀, block 1) → π₂ (verifies π₁,
    /// block 2), one fixed block-bearing class, decider accepts the tip, the
    /// tip's block accumulator anchors to block 2's end (I8), and both the
    /// chain-continuity and the recursion terminals reject tampering.
    ///
    /// The wallet-capsule PCS opening is OFF (the one component whose trace
    /// structure is proof-dependent — the region-layer target); everything
    /// else about each block is verified in-trace and chained. This closes
    /// the recursion over real block content; flipping the config to ON once
    /// the region-layer wallet-PCS lands makes each link a complete proof.
    #[test]
    fn recursion_over_real_blocks_recursion_ready() {
        use noid_ivc_core::challenger::FsLaneChallenger;
        use noid_ivc_core::field::F128;
        use noid_ivc_core::field_r1cs::FieldR1cs;
        use noid_ivc_core::pcs::{self, PcsParams};
        use noid_ivc_core::proof::FieldShape;
        use noid_ivc_core::zerocheck::K_SKIP;
        use noid_ivc_prover::field_prover::prove_field_with_public_io;
        use noid_recursive::acceptance::block_slots::BlockSlotsConfig;
        use noid_recursive::acceptance::link::{
            build_link, decide_tip, genesis_witness, link_io_layout_for, tip_block_accumulator,
            LinkBlock, LinkClass, LinkEnvelope, LinkInput,
        };
        use std::time::Instant;

        const CLASS_M: usize = 23;
        let shape = FieldShape {
            m: CLASS_M,
            k_log: CLASS_M,
            k_skip: K_SKIP,
            const_pin: Some(0),
        };
        let params = PcsParams {
            m: CLASS_M + pcs::LOG_PACKING,
            log_inv_rate: 2,
            log_batch_size: 5,
            profile: Default::default(),
        };
        let no_pcs = BlockSlotsConfig {
            discharge_wallet_pcs: false,
            wallet_pcs_region: None,
        };
        let layout = link_io_layout_for(shape.k_log, true);

        let units = chained_std_tx_blocks(3);
        let class = LinkClass::new_block_bearing(
            shape,
            params.clone(),
            units[0].start_accumulator.clone(),
        );

        fn mk_block(u: &BlockUnit, config: BlockSlotsConfig) -> LinkBlock<'_> {
            LinkBlock {
                start_accumulator: &u.start_accumulator,
                end_accumulator: &u.end_accumulator,
                inputs: &u.inputs,
                proof: &u.proof,
                config,
            }
        }

        // Genesis dummy T + its proof (class-shaped, exists without the class).
        let t_witness = genesis_witness(&shape);
        let t_io = vec![F128::ZERO; class.spec.io_len];
        let mut ch = FsLaneChallenger::new(b"history-link-v0");
        let (t_proof, t_commitment, _) = prove_field_with_public_io(
            &class.genesis,
            &t_witness,
            &params,
            &class.spec,
            &t_io,
            &mut ch,
        );
        let env_t = LinkEnvelope {
            proof: t_proof,
            commitment: t_commitment,
            io: t_io,
        };

        // π₀: genesis link over block 0. Building its trace CREATES the class.
        let t0 = Instant::now();
        let built0 = build_link(
            &class,
            &LinkInput {
                prev: &env_t,
                verified_digest: class.genesis_digest,
                genesis: true,
                fold_matrix: &class.genesis,
                block: Some(mk_block(&units[0], no_pcs)),
            },
        );
        eprintln!(
            "[recursion-blocks] pi_0 (block h=1) build: {:.1?}, {} wires -> 2^{}",
            t0.elapsed(),
            built0.witness.len(),
            built0.r1cs.k_log
        );
        let class_r1cs: FieldR1cs = built0.r1cs;
        let class_digest = class_r1cs.statement_digest();
        let mut ch = FsLaneChallenger::new(b"history-link-v0");
        let (p0, c0, _) = prove_field_with_public_io(
            &class_r1cs,
            &built0.witness,
            &params,
            &class.spec,
            &built0.io,
            &mut ch,
        );
        let mut prev = LinkEnvelope {
            proof: p0,
            commitment: c0,
            io: built0.io,
        };

        // π₁, π₂ over blocks 1, 2 — the SAME class must come out every time.
        let mut last_battery: Option<(FieldR1cs, Vec<F128>)> = None;
        for step in 1..=2usize {
            let t0 = Instant::now();
            let built = build_link(
                &class,
                &LinkInput {
                    prev: &prev,
                    verified_digest: class_digest,
                    genesis: false,
                    fold_matrix: &class_r1cs,
                    block: Some(mk_block(&units[step], no_pcs)),
                },
            );
            assert!(
                built.r1cs.a_0 == class_r1cs.a_0,
                "link {step}: class A matrix drifted"
            );
            assert!(
                built.r1cs.b_0 == class_r1cs.b_0,
                "link {step}: class B matrix drifted"
            );
            let mut ch = FsLaneChallenger::new(b"history-link-v0");
            let (proof, commitment, _) = prove_field_with_public_io(
                &class_r1cs,
                &built.witness,
                &params,
                &class.spec,
                &built.io,
                &mut ch,
            );
            eprintln!(
                "[recursion-blocks] pi_{step} (block h={}) build+prove: {:.1?}",
                step + 1,
                t0.elapsed()
            );
            if step == 1 {
                last_battery = Some((class_r1cs.clone(), built.witness.clone()));
            }
            prev = LinkEnvelope {
                proof,
                commitment,
                io: built.io,
            };
        }

        // Decider accepts the tip and the block accumulator anchors to block 2.
        decide_tip(&class, &class_r1cs, &prev).expect("decider accepts the block-chain tip");
        let tip_acc = tip_block_accumulator(&class, &prev).expect("block-bearing class");
        assert_eq!(
            tip_acc, units[2].end_accumulator,
            "tip block accumulator must anchor to block 2's end (I8)"
        );
        eprintln!(
            "[recursion-blocks] RECURSION CLOSED over real blocks: pi_2(h=3) -> pi_1(h=2) -> pi_0(h=1); \
             tip acc height {}",
            tip_acc.height
        );

        // I5 flip battery over π₁'s full witness — 0 survivors beyond the
        // pin-helper class (the block slots + chain pins + [R] together).
        let (r1cs_b, z_b) = last_battery.expect("captured pi_1");
        let mut battery = r1cs_b.flip_battery(&z_b);
        let survivors = battery.survivors_excluding_pin_helpers(0..z_b.len());
        assert!(
            survivors.is_empty(),
            "pi_1 flip-battery survivors: {} (first {:?})",
            survivors.len(),
            &survivors[..survivors.len().min(8)]
        );
        eprintln!("[recursion-blocks] I5 flip battery over pi_1: 0 survivors");

        // Negatives at the decider.
        // (a) tampered exposed block accumulator (I8 anchor lane).
        {
            let mut bad = LinkEnvelope {
                proof: prev.proof.clone(),
                commitment: prev.commitment.clone(),
                io: prev.io.clone(),
            };
            bad.io[layout.block_state_root] += F128::ONE;
            assert!(
                decide_tip(&class, &class_r1cs, &bad).is_err(),
                "tampered block accumulator accepted"
            );
        }
        // (b) a genesis link is not a valid tip.
        {
            let mut bad_io = prev.io.clone();
            bad_io[layout.g] = F128::ONE;
            let bad = LinkEnvelope {
                proof: prev.proof.clone(),
                commitment: prev.commitment.clone(),
                io: bad_io,
            };
            assert!(
                decide_tip(&class, &class_r1cs, &bad).is_err(),
                "genesis tip accepted"
            );
        }
        // (c) tampered proof bytes.
        {
            let mut bad = LinkEnvelope {
                proof: prev.proof.clone(),
                commitment: prev.commitment.clone(),
                io: prev.io.clone(),
            };
            if let Some(w) = bad.proof.lincheck.rounds.first_mut() {
                w.0 += F128::ONE;
            }
            assert!(
                decide_tip(&class, &class_r1cs, &bad).is_err(),
                "tampered tip proof accepted"
            );
        }
    }

    /// [G] item 5b step 3b — the COMPLETE block-bearing recursion link: the
    /// wallet-capsule PCS opening is discharged in the shape-fixed region layer
    /// and its committed-column opening claims are THREADED through the link's
    /// public IO (`class.spec.claims` + the region tail lanes). This is the
    /// piece that turns a recursion-ready block link (wallet-PCS off) into a
    /// complete block proof (no shape drift) — the `discharge_wallet_pcs` region
    /// path flipped on and the resulting opening claims carried by the link IO.
    ///
    /// - π₀: a genesis link over block h=1 with the region discharge ON is a
    ///   COMPLETE block proof and VERIFIES;
    /// - NEGATIVE: flipping one region committed-column lane in π₀'s witness
    ///   keeps the trace satisfiable (committed columns are free wires) but
    ///   breaks that column's opening claim → the verifier rejects — proving
    ///   the region claims are genuinely bound through the link IO;
    /// - π₁: a regular link that verifies π₀ opens π₀'s region columns
    ///   GENERICALLY via the same public-IO mechanism (no extra trace code),
    ///   and the decider accepts the tip.
    ///
    /// Class m = 24: the region link is ~9–11M wires (measured > 2^23 at every
    /// param point), so it self-hosts at 2^24. `RegionDischargeParams` are kept
    /// tiny — the discharge flatness and full soundness are gated separately in
    /// `region_source_binding_full_e2e`; here we test only the IO threading.
    #[test]
    #[ignore = "heavy (m=24, several 2^24 proofs + one class digest); run explicitly"]
    fn region_complete_block_bearing_link_e2e() {
        use noid_ivc_core::challenger::FsLaneChallenger;
        use noid_ivc_core::field::F128;
        use noid_ivc_core::field_r1cs::FieldR1cs;
        use noid_ivc_core::pcs::{self, PcsParams};
        use noid_ivc_core::proof::FieldShape;
        use noid_ivc_core::verifier::verify_field_with_public_io;
        use noid_ivc_core::zerocheck::K_SKIP;
        use noid_ivc_prover::field_prover::prove_field_with_public_io;
        use noid_recursive::acceptance::block_slots::BlockSlotsConfig;
        use noid_recursive::acceptance::link::{
            build_link, decide_tip, genesis_witness, link_io_layout_for, LinkBlock, LinkClass,
            LinkEnvelope, LinkInput,
        };
        use noid_recursive::acceptance::trace::region_source_binding::RegionDischargeParams;
        use std::time::Instant;

        const CLASS_M: usize = 24;
        // Kept tiny for memory: a region link self-hosts at 2^24, and this gate
        // proves several 2^24 instances sequentially. π₀'s COMPLETE-proof verify
        // is separately confirmed at nq=4/sb8=2; the discharge soundness /
        // flatness are gated in region_source_binding_full_e2e. Here nq=2/sb8=1
        // keeps the per-proof footprint down so the negative + recursion fit.
        let region_params = RegionDischargeParams {
            nq: 2,
            sb8_auth_layers: 1,
        };
        let shape = FieldShape {
            m: CLASS_M,
            k_log: CLASS_M,
            k_skip: K_SKIP,
            const_pin: Some(0),
        };
        let params = PcsParams {
            m: CLASS_M + pcs::LOG_PACKING,
            log_inv_rate: 2,
            log_batch_size: 5,
            profile: Default::default(),
        };
        let layout = link_io_layout_for(shape.k_log, true);
        let region_cfg = BlockSlotsConfig {
            discharge_wallet_pcs: true,
            wallet_pcs_region: Some(region_params),
        };

        let units = chained_std_tx_blocks(2);
        fn mk(u: &BlockUnit, config: BlockSlotsConfig) -> LinkBlock<'_> {
            LinkBlock {
                start_accumulator: &u.start_accumulator,
                end_accumulator: &u.end_accumulator,
                inputs: &u.inputs,
                proof: &u.proof,
                config,
            }
        }

        // ---- Freeze the COMPLETE region class on block 0.
        let t0 = Instant::now();
        let class = LinkClass::new_region_block_bearing(
            shape,
            params.clone(),
            units[0].start_accumulator.clone(),
            region_params,
            &mk(&units[0], region_cfg),
        );
        eprintln!(
            "[region-link] class frozen in {:.1?}: region_claims={}, max_arity={}, io_len={}",
            t0.elapsed(),
            class.region_claims.len(),
            class.region_max_arity,
            class.spec.io_len,
        );
        assert!(!class.region_claims.is_empty());

        // ---- Genesis dummy T + proof (real region spec, all-zero IO: every
        // region claim opens an all-zero column of T to zero — satisfied by the
        // single-block genesis witness).
        let t_witness = genesis_witness(&shape);
        let t_io = vec![F128::ZERO; class.spec.io_len];
        let mut ch = FsLaneChallenger::new(b"history-link-v0");
        let (t_proof, t_commitment, _) = prove_field_with_public_io(
            &class.genesis,
            &t_witness,
            &params,
            &class.spec,
            &t_io,
            &mut ch,
        );
        let env_t = LinkEnvelope {
            proof: t_proof,
            commitment: t_commitment,
            io: t_io,
        };

        // ---- π₀: genesis link over block 0 — a COMPLETE block proof.
        let t0 = Instant::now();
        let built0 = build_link(
            &class,
            &LinkInput {
                prev: &env_t,
                verified_digest: class.genesis_digest,
                genesis: true,
                fold_matrix: &class.genesis,
                block: Some(mk(&units[0], region_cfg)),
            },
        );
        let class_r1cs: FieldR1cs = built0.r1cs;
        let pi0_io = built0.io;
        let pi0_witness = built0.witness;
        let n_region = built0.region_claims.len();
        assert_eq!(
            n_region,
            class.region_claims.len(),
            "π₀ live region claim count matches the frozen shape"
        );
        drop(env_t); // the genesis dummy proof is no longer needed after π₀'s build.
        eprintln!(
            "[region-link] π₀ build {:.1?}: {} wires -> 2^{}, region_claims={}",
            t0.elapsed(),
            pi0_witness.len(),
            class_r1cs.k_log,
            n_region,
        );
        let class_digest = class_r1cs.statement_digest();

        // Prove π₀ and directly verify — the COMPLETE region block proof.
        let mut ch = FsLaneChallenger::new(b"history-link-v0");
        let (p0, c0, _) = prove_field_with_public_io(
            &class_r1cs,
            &pi0_witness,
            &params,
            &class.spec,
            &pi0_io,
            &mut ch,
        );
        let mut chv = FsLaneChallenger::new(b"history-link-v0");
        verify_field_with_public_io(&class_r1cs, &c0, &p0, &class.spec, &pi0_io, &mut chv)
            .expect("π₀ COMPLETE region block proof verifies");
        eprintln!("[region-link] π₀ COMPLETE region block proof VERIFIES (region discharge ON)");

        // ---- NEGATIVE: flip ONE region committed-column lane in π₀'s witness.
        // The trace stays satisfiable (committed columns are free wires bound
        // only by the region opening claims) and the envelope is unchanged, but
        // that column's opening claim is now false → the PCS layer rejects.
        {
            let bad_slice = class.region_claims[0].slice;
            let mut bad_w = pi0_witness.clone();
            bad_w[bad_slice.start()] += F128::ONE;
            let mut ch = FsLaneChallenger::new(b"history-link-v0");
            let (bp, bc, _) = prove_field_with_public_io(
                &class_r1cs,
                &bad_w,
                &params,
                &class.spec,
                &pi0_io,
                &mut ch,
            );
            let mut chv = FsLaneChallenger::new(b"history-link-v0");
            assert!(
                verify_field_with_public_io(&class_r1cs, &bc, &bp, &class.spec, &pi0_io, &mut chv)
                    .is_err(),
                "tampered region committed-column lane must break its opening claim"
            );
            eprintln!("[region-link] NEGATIVE: tampered region committed column rejected");
        }

        let env0 = LinkEnvelope {
            proof: p0,
            commitment: c0,
            io: pi0_io,
        };
        drop(pi0_witness);

        // ---- π₁: a regular link verifying π₀. Its in-trace [R] replay opens
        // π₀'s region columns via class.spec.claims — the region claims threaded
        // through the LINK's public IO, with NO extra trace code.
        let t0 = Instant::now();
        let built1 = build_link(
            &class,
            &LinkInput {
                prev: &env0,
                verified_digest: class_digest,
                genesis: false,
                fold_matrix: &class_r1cs,
                block: Some(mk(&units[1], region_cfg)),
            },
        );
        assert!(
            built1.r1cs.a_0 == class_r1cs.a_0,
            "π₁ class A matrix drifted"
        );
        assert!(
            built1.r1cs.b_0 == class_r1cs.b_0,
            "π₁ class B matrix drifted"
        );
        let mut ch = FsLaneChallenger::new(b"history-link-v0");
        let (p1, c1, _) = prove_field_with_public_io(
            &class_r1cs,
            &built1.witness,
            &params,
            &class.spec,
            &built1.io,
            &mut ch,
        );
        eprintln!(
            "[region-link] π₁ (verifies π₀) build+prove {:.1?}",
            t0.elapsed()
        );
        let env1 = LinkEnvelope {
            proof: p1,
            commitment: c1,
            io: built1.io,
        };
        decide_tip(&class, &class_r1cs, &env1).expect("decider accepts π₁ over π₀");
        eprintln!(
            "[region-link] RECURSION over COMPLETE region blocks: π₁ ⊳ π₀; decider accepts the tip"
        );

        // ---- Decider negative: a tampered exposed block accumulator lane.
        {
            let mut bad = LinkEnvelope {
                proof: env1.proof.clone(),
                commitment: env1.commitment.clone(),
                io: env1.io.clone(),
            };
            bad.io[layout.block_state_root] += F128::ONE;
            assert!(
                decide_tip(&class, &class_r1cs, &bad).is_err(),
                "tampered block accumulator accepted"
            );
        }
        eprintln!("[region-link] decider negative rejects; COMPLETE region link e2e OK");
    }

    /// The block-bearing recursion class needs two DIFFERENT real blocks of
    /// the same tier to assemble to the SAME FieldR1cs matrix (I1). This
    /// test establishes the exact shape-fixity boundary: with the
    /// wallet-capsule PCS discharge OFF, everything else — [K]/[D] killshots,
    /// owner-auth GKR, exact-state, the accumulator fold, and the integer
    /// height successor (block 1 is at height 2, parent height 1, ODD,
    /// which the ripple-carry increment must accept) — is class-fixed across
    /// blocks. The wallet-capsule PCS opening is the SOLE remaining drift
    /// (proof-dependent compact-FRI structure), localized here and left to
    /// the region layer.
    #[test]
    fn block_slots_fixed_shape_across_two_real_blocks() {
        use noid_ivc_core::field_circuit::FieldR1csBuilder;
        use noid_recursive::acceptance::block_slots::{
            build_block_slots, build_block_slots_with_config, BlockSlotsConfig,
        };

        let units = chained_std_tx_blocks(2);
        let build = |u: &BlockUnit, cfg: BlockSlotsConfig, label: &str| {
            let mut b = FieldR1csBuilder::new();
            let _ = build_block_slots_with_config(
                &mut b,
                &u.start_accumulator,
                &u.end_accumulator,
                &u.inputs,
                &u.proof,
                cfg,
            );
            let (r, z) = b.build();
            assert!(r.satisfies(&z), "{label} satisfies");
            r
        };

        // Recursion-ready part (wallet-PCS off): the matrices must be
        // byte-identical across two different real blocks.
        let no_pcs = BlockSlotsConfig {
            discharge_wallet_pcs: false,
            wallet_pcs_region: None,
        };
        let r0 = build(&units[0], no_pcs, "block 0 (height 1, no wallet-PCS)");
        let r1 = build(&units[1], no_pcs, "block 1 (height 2, no wallet-PCS)");
        assert_eq!(r0.m, r1.m, "class m drifted between blocks");
        assert_eq!(r0.k_log, r1.k_log, "k_log drifted");
        assert!(
            r0.a_0 == r1.a_0,
            "A matrix drifted between blocks (recursion-ready part must be class-fixed)"
        );
        assert!(r0.b_0 == r1.b_0, "B matrix drifted between blocks");
        eprintln!(
            "[block-slots] recursion-ready shape FIXED across 2 real blocks (heights 1,2): 2^{} rows",
            r0.k_log
        );

        // With the wallet-PCS ON, the full block still satisfies for each
        // block, but the matrices drift — localizing the ONE unfixed
        // component (the region-layer target).
        let full0 = build(&units[0], BlockSlotsConfig::default(), "block 0 full");
        let full1 = build(&units[1], BlockSlotsConfig::default(), "block 1 full");
        let _ = build_block_slots; // keep the default-config entry point exercised elsewhere
        assert!(
            full0.a_0 != full1.a_0,
            "wallet-PCS was expected to be the drift source; if this now matches, \
             the fixity boundary moved — update the region-layer obligation"
        );
        eprintln!("[block-slots] wallet-PCS confirmed as the sole shape-drift source");

        // Height-successor NEGATIVE: block 1 is at child height 2. The old
        // XOR proxy accepted the wrong parent 3 (2 XOR 3 XOR 1 = 0, a height
        // DECREMENT); the integer incrementer must reject it. Tamper the
        // start accumulator's height to 3 and require unsatisfiability.
        let mut bad_unit = BlockUnit {
            start_accumulator: units[1].start_accumulator.clone(),
            end_accumulator: units[1].end_accumulator.clone(),
            inputs: units[1].inputs.clone(),
            proof: units[1].proof.clone(),
            block_header: units[1].block_header.clone(),
        };
        bad_unit.start_accumulator.height = 3;
        let mut b = FieldR1csBuilder::new();
        let _ = build_block_slots_with_config(
            &mut b,
            &bad_unit.start_accumulator,
            &bad_unit.end_accumulator,
            &bad_unit.inputs,
            &bad_unit.proof,
            no_pcs,
        );
        let (rbad, zbad) = b.build();
        assert!(
            !rbad.satisfies(&zbad),
            "XOR-passing wrong parent height (3 -> child 2) must be rejected by the incrementer"
        );
        eprintln!("[block-slots] integer height successor rejects the XOR-decrement attack");
    }

    /// The [B] block-slot assembly gate: the single-block component
    /// verifier, replayed as a FieldR1cs trace, is satisfied by the honest
    /// witness, its cross-component pins survive a full flip battery
    /// (0 surviving mutants beyond the pin-helper class), and every
    /// statement-anchor corruption breaks it — the assembled trace binds
    /// the same relation the native verifier checks.
    #[test]
    fn block_slots_assembly_matches_native_and_rejects_mutations() {
        use noid_ivc_core::field_circuit::FieldR1csBuilder;
        use noid_recursive::acceptance::block_slots::build_block_slots;
        use noid_recursive::block_certificate_backend::verify_accepted_block_batch_components;

        let (start_consensus, start_accumulator, start_parent, start_state, witness) =
            user_block_fixture();
        let (output, proof) = prove_retained_full_accepted_block_batch_proof(
            &start_consensus,
            &start_accumulator,
            &start_parent,
            &start_state,
            &witness,
        )
        .expect("fixture proves");
        let inputs = &output.proof_components.component_inputs;
        let end_accumulator = &output.accepted_claim_batch.accumulator;

        // Native ground truth: the component verifier accepts.
        verify_accepted_block_batch_components(
            &start_consensus,
            &start_accumulator,
            end_accumulator,
            inputs,
            &proof,
        )
        .expect("native component verify accepts the fixture");

        // Trace assembly of the same batch.
        let mut b = FieldR1csBuilder::new();
        let slots = build_block_slots(&mut b, &start_accumulator, end_accumulator, inputs, &proof);
        // The projection lanes are the receipt↔header anchors the link
        // exposes; sanity-check the count.
        assert_eq!(slots.projection_lanes().len(), 12);
        let pre_pad = b.num_wires();
        let (r1cs, z) = b.build();
        assert!(r1cs.satisfies(&z), "honest block-slot witness satisfies");
        eprintln!(
            "[block-slots] 1 std tx: {pre_pad} wires (pre-pad), padded to 2^{}",
            r1cs.k_log
        );

        // Flip battery over the whole witness (minus the pin-helper class).
        let mut battery = r1cs.flip_battery(&z);
        let survivors = battery.survivors_excluding_pin_helpers(0..z.len());
        assert!(
            survivors.is_empty(),
            "flip-battery survivors: {} (first few: {:?})",
            survivors.len(),
            &survivors[..survivors.len().min(8)]
        );

        // Semantic [B] negative: a tampered accumulator boundary (multi-lane,
        // beyond a single flip) breaks the claim-fold's end pins. The child
        // state root the fold folds in is the real one, so the recomputed
        // chain hash cannot match a wrong end accumulator.
        let mut bad_end = end_accumulator.clone();
        bad_end.chain_hash[0] ^= 0xA5;
        bad_end.chain_hash[17] ^= 0x5A;
        let mut b2 = FieldR1csBuilder::new();
        let _ = build_block_slots(&mut b2, &start_accumulator, &bad_end, inputs, &proof);
        let (r1cs2, z2) = b2.build();
        assert!(
            !r1cs2.satisfies(&z2),
            "tampered accumulator boundary must break the block-slot trace"
        );
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
        assert_eq!(out.proof_components.component_inputs.accepted_claim_witness.headers.len(), 1);
        assert_eq!(
            out.proof_components
                .component_inputs
            .accepted_block_certificate_statements
                .len(),
            1
        );
        assert_eq!(
            accepted_block_certificate_chain_claim(
                &out.proof_components.component_inputs.accepted_block_certificate_statements[0]
            ),
            out.proof_components
                .component_inputs
            .accepted_claim_witness
                .accepted_block_claims[0]
        );
        assert_ne!(
            crate::accepted_block_certificate_statement_digest(
                &out.proof_components.component_inputs.accepted_block_certificate_statements[0]
            ),
            [0u8; 32]
        );
        assert_eq!(
            out.proof_components
                .accepted_block_certificate_receipts
                .len(),
            1
        );
        assert_eq!(
            out.proof_components.accepted_block_certificate_proofs.len(),
            1
        );
        assert_eq!(
            out.proof_components
                .accepted_block_receipt_projection_handles
                .len(),
            1
        );
        let statement_digest = noid_recursive::accepted_block_certificate_statement_digest(
            &out.proof_components.component_inputs.accepted_block_certificate_statements[0],
        );
        assert_eq!(
            out.proof_components.accepted_block_certificate_receipts[0].statement_digest,
            statement_digest
        );
        noid_recursive::verify_accepted_block_receipt_projection_handle(
            &statement_digest,
            &out.proof_components
                .accepted_block_receipt_projection_handles[0],
        )
        .expect("accepted block certificate receipt projection handle verifies");
        assert_eq!(
            accepted_block_receipt_projection_handle(
                &out.proof_components.accepted_block_certificate_proofs[0],
            )
            .expect("certificate proof derives receipt projection handle"),
            out.proof_components
                .accepted_block_receipt_projection_handles[0]
        );
        assert_eq!(out.proof_components.component_inputs.header_integer_trace.steps.len(), 1);
        assert!(out.proof_components.component_inputs.tx_root_inputs.is_empty());
        assert!(out.proof_components.component_inputs.exact_state_killshot_inputs.is_empty());
        assert_eq!(out.proof_components.component_inputs.authorization_totals.user_tx_count, 0);
        assert_eq!(
            out.proof_components.component_inputs.authorization_totals.owner_count_total,
            0
        );
        assert_eq!(
            out.proof_components
                .component_inputs.authorization_totals
                .live_input_count_total,
            0
        );
    }

    #[test]
    fn full_batch_builds_checkpoint_summary_and_advances_head() {
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
        .expect("full accepted batch verifies");
        let start_anchor = compute_header_chain_anchor(
            std::iter::once(&parent),
            start_consensus.cumulative_chainwork,
        )
        .expect("start anchor computes");
        let summary = history_checkpoint_batch_summary_from_full_accepted_output(
            &start_anchor,
            &start_consensus,
            &start_accumulator,
            &out,
            accepted_claim_batch_digest(&out),
        )
        .expect("checkpoint summary builds from full accepted output");
        assert_eq!(summary.batch_len, 1);
        assert_eq!(summary.end_anchor.height, 1);
        assert_eq!(
            summary.end_anchor.state_root,
            out.accepted_claim_batch.consensus_state.state_root
        );
        let original_claim_batch_digest = summary.accepted_claim_batch_digest;
        let original_certificate_digest = crate::accepted_block_certificate_statement_digest(
            &out.proof_components.component_inputs.accepted_block_certificate_statements[0],
        );
        let certificate_batch_statement =
            accepted_block_certificate_batch_statement_from_full_accepted_output(
                &out,
                original_claim_batch_digest,
            )
            .expect("certificate batch statement builds");
        assert_eq!(certificate_batch_statement.batch_len, 1);
        assert_eq!(
            certificate_batch_statement.certificate_statement_digests[0],
            original_certificate_digest
        );
        assert_ne!(
            crate::accepted_block_certificate_batch_statement_digest(&certificate_batch_statement),
            [0u8; 32]
        );

        let previous = noid_recursive::history_checkpoint_head_from_boundary(
            &summary.start_anchor,
            &summary.start_accumulator,
            &summary.start_consensus,
        )
        .expect("start checkpoint head builds");
        let next = noid_recursive::advance_history_checkpoint_head_native(&previous, &summary)
            .expect("checkpoint head advances");
        let statement = noid_recursive::HistoryCheckpointStepStatement {
            previous_head: previous,
            batch_summary: summary,
            next_head: next,
        };
        noid_recursive::verify_history_checkpoint_step_statement_native(&statement)
            .expect("checkpoint step statement verifies");

        let mut tampered_out = out;
        tampered_out
            .proof_components
            .component_inputs
            .accepted_claim_witness
            .accepted_block_claims[0][0] += Block128::ONE;
        assert_ne!(
            accepted_claim_batch_digest(&tampered_out),
            original_claim_batch_digest
        );
        assert!(matches!(
            accepted_block_certificate_batch_statement_from_full_accepted_output(
                &tampered_out,
                accepted_claim_batch_digest(&tampered_out),
            ),
            Err(FullAcceptedBlockBatchError::CertificateBatch(
                AcceptedBlockCertificateBatchError::ClaimProjectionMismatch { index: 0 }
            ))
        ));
        let mut tampered_statement = tampered_out
            .proof_components
            .component_inputs
            .accepted_block_certificate_statements[0]
            .clone();
        tampered_statement.accepted_block_claim_digest = [0xAB; 32];
        assert_ne!(
            crate::accepted_block_certificate_statement_digest(&tampered_statement),
            original_certificate_digest
        );
    }

    #[test]
    fn full_batch_checkpoint_package_serializes_and_verifies_without_blocks() {
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
        let start_anchor = compute_header_chain_anchor(
            std::iter::once(&parent),
            start_consensus.cumulative_chainwork,
        )
        .expect("start anchor computes");

        let package = prove_retained_block_certificate_batch_checkpoint_package_from_boundary(
            &start_anchor,
            &start_consensus,
            &start_accumulator,
            &parent,
            &state,
            &witness,
        )
        .expect("full accepted checkpoint package proves");
        assert_eq!(package.start_height(), 0);
        assert_eq!(package.end_height(), 1);
        assert!(package.byte_len() > 0);

        let encoded = bincode::serialize(&package).expect("package serializes");
        let decoded: AcceptedBlockCertificateBatchCheckpointPackage =
            bincode::deserialize(&encoded).expect("package decodes");
        verify_accepted_block_certificate_batch_checkpoint_package(&decoded)
            .expect("decoded package verifies without retained blocks");
        let public_proof = public_history_checkpoint_proof_from_package(
            &start_anchor,
            &start_accumulator,
            &decoded,
        )
        .expect("public checkpoint proof exports from package");
        noid_recursive::verify_history_checkpoint_proof_checkpoint(
            &public_proof,
            &start_anchor,
            &decoded.step_statement.batch_summary.end_anchor,
        )
        .expect("exported public checkpoint proof verifies");

        let mut tampered = decoded;
        tampered
            .certificate_batch_statement
            .accepted_claim_batch_digest = [0xAA; 32];
        assert!(matches!(
            verify_accepted_block_certificate_batch_checkpoint_package(&tampered),
            Err(FullAcceptedBlockBatchError::CheckpointStep(_))
        ));
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
        assert_eq!(out.proof_components.component_inputs.accepted_claim_witness.headers.len(), 1);
        assert_eq!(
            out.proof_components
                .component_inputs
            .accepted_block_certificate_statements
                .len(),
            1
        );
        let certificate_statement = &out.proof_components.component_inputs.accepted_block_certificate_statements[0];
        assert_eq!(certificate_statement.user_tx_count, 1);
        assert_eq!(certificate_statement.live_input_count, 1);
        assert_eq!(certificate_statement.touched_slot_count, 2);
        assert_eq!(
            accepted_block_certificate_chain_claim(certificate_statement),
            out.proof_components
                .component_inputs
            .accepted_claim_witness
                .accepted_block_claims[0]
        );
        assert_eq!(out.proof_components.component_inputs.header_integer_trace.steps.len(), 1);
        assert_eq!(out.proof_components.component_inputs.tx_body_standard_inputs.len(), 1);
        assert_eq!(out.proof_components.component_inputs.tx_body_standard_hashes.len(), 1);
        assert!(out.proof_components.component_inputs.tx_body_sweep_inputs.is_empty());
        assert!(out.proof_components.component_inputs.tx_body_sweep_hashes.is_empty());
        assert!(!out.proof_components.component_inputs.tx_root_inputs.is_empty());
        assert_eq!(out.proof_components.component_inputs.exact_state_killshot_inputs.len(), 1);
        assert_eq!(out.proof_components.component_inputs.authorization_totals.user_tx_count, 1);
        assert_eq!(
            out.proof_components.component_inputs.authorization_totals.owner_count_total,
            1
        );
        assert_eq!(
            out.proof_components
                .component_inputs.authorization_totals
                .live_input_count_total,
            1
        );
        let exact_inputs = &out.proof_components.component_inputs.exact_state_killshot_inputs[0];
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
        assert!(component_proof.byte_len(&out.proof_components.component_inputs) > 0);
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

        let start_anchor = compute_header_chain_anchor(
            std::iter::once(&parent),
            start_consensus.cumulative_chainwork,
        )
        .expect("start anchor computes");
        let summary = history_checkpoint_batch_summary_from_full_accepted_output(
            &start_anchor,
            &start_consensus,
            &start_accumulator,
            &out,
            accepted_claim_batch_digest(&out),
        )
        .expect("checkpoint summary builds");
        let previous_head = noid_recursive::history_checkpoint_head_from_boundary(
            &summary.start_anchor,
            &summary.start_accumulator,
            &summary.start_consensus,
        )
        .expect("previous checkpoint head builds");
        let next_head =
            noid_recursive::advance_history_checkpoint_head_native(&previous_head, &summary)
                .expect("next checkpoint head builds");
        let checkpoint_statement = noid_recursive::HistoryCheckpointStepStatement {
            previous_head,
            batch_summary: summary,
            next_head,
        };
        let (checkpoint_step_proof, certificate_batch_statement) =
            prove_history_checkpoint_step_proof_from_verified_full_accepted_output(
                &checkpoint_statement,
                &out,
            )
            .expect("checkpoint step proves from already verified accepted output");
        verify_history_checkpoint_step_proof_with_verified_full_accepted_output(
            &checkpoint_statement,
            &certificate_batch_statement,
            &out,
            &checkpoint_step_proof,
        )
        .expect("checkpoint step verifies already verified accepted output");

        let mut bad_certificate_batch_statement = certificate_batch_statement.clone();
        bad_certificate_batch_statement.accepted_claim_batch_digest = [0x55; 32];
        assert!(matches!(
            verify_history_checkpoint_step_proof_with_verified_full_accepted_output(
                &checkpoint_statement,
                &bad_certificate_batch_statement,
                &out,
                &checkpoint_step_proof,
            ),
            Err(FullAcceptedBlockBatchError::CheckpointStep(_))
        ));

        let mut bad_out = FullAcceptedBlockBatchOutput {
            accepted_claim_batch: out.accepted_claim_batch.clone(),
            end_state: out.end_state.clone(),
            proof_components: out.proof_components.clone(),
        };
        bad_out
            .proof_components
            .accepted_block_receipt_projection_handles[0]
            .proof_digest[0] ^= 1;
        assert!(matches!(
            prove_history_checkpoint_step_proof_from_verified_full_accepted_output(
                &checkpoint_statement,
                &bad_out,
            ),
            Err(
                FullAcceptedBlockBatchError::CertificateReceiptProjectionHandleMismatch {
                    index: 0
                }
            )
        ));
        assert!(matches!(
            verify_history_checkpoint_step_proof_with_verified_full_accepted_output(
                &checkpoint_statement,
                &certificate_batch_statement,
                &bad_out,
                &checkpoint_step_proof,
            ),
            Err(
                FullAcceptedBlockBatchError::CertificateReceiptProjectionHandleMismatch {
                    index: 0
                }
            )
        ));

        let mut bad_out = FullAcceptedBlockBatchOutput {
            accepted_claim_batch: out.accepted_claim_batch.clone(),
            end_state: out.end_state.clone(),
            proof_components: out.proof_components.clone(),
        };
        bad_out.proof_components.accepted_block_certificate_proofs[0].statement_digest[0] ^= 1;
        assert!(matches!(
            prove_history_checkpoint_step_proof_from_verified_full_accepted_output(
                &checkpoint_statement,
                &bad_out,
            ),
            Err(FullAcceptedBlockBatchError::CertificateProofStatementMismatch { index: 0 })
        ));

        let mut bad_components = out.proof_components.clone();
        bad_components.component_inputs.tx_root_inputs[0].leaf[0] += Block128::ONE;
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
        bad_components.component_inputs.accepted_block_certificate_statements[0].child_state_root = [0x44; 32];
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

        let mut bad_components = out.proof_components.clone();
        bad_components.component_inputs.tx_body_standard_hashes[0][0] += Block128::ONE;
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
        bad_components.component_inputs.authorization_witnesses[0]
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
        bad_components.component_inputs.authorization_totals.owner_count_total += 1;
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
