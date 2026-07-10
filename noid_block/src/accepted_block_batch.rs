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
    prove_accepted_claim_hash_killshot, prove_batched_merkle_killshot, prove_block_spine_killshot,
    prove_sweep_block_spine_killshot, reconstruct_slot_states, spine_inputs_from_body,
    sweep_spine_inputs_from_body, AcceptedClaimHashInputs, AcceptedClaimHashProofKillShot,
    BatchedMerkleProofKillShot, BlockSpineMle, BlockSpineProof, MerkleCircuit, MerklePathInputs,
    SpineCircuit, SpineInputs, SweepBlockSpineMle, SweepBlockSpineProof, SweepSpineInputs,
    MAX_MERKLE_DEPTH,
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
    ChainAccumulator, CheckpointPoseidonError, CheckpointPoseidonProof, HeaderIntegerTraceError,
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
        let (verified, trace) =
            verify_authorization_statement_proof_with_trace(statement, proof)
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
            let (inputs, verified) = derive_exact_state_killshot_inputs(
                &artifacts.exact_state_inputs,
                &artifacts.exact_action_surface,
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
                    live_input_count: statement.live_input_count,
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
    if components.component_inputs.authorization_inputs.len()
        != components.component_inputs.authorization_witnesses.len()
    {
        return Err(FullAcceptedBlockBatchError::ComponentShapeMismatch);
    }
    if components.component_inputs.authorization_traces.len()
        != components.component_inputs.authorization_witnesses.len()
    {
        return Err(FullAcceptedBlockBatchError::ComponentShapeMismatch);
    }
    validate_tx_body_component_shape(components)?;
    let claim_result = || -> Result<AcceptedClaimHashProofKillShot, FullAcceptedBlockBatchError> {
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
        || components
            .component_inputs
            .accepted_block_certificate_statements
            .len()
            != len
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
                statement: components
                    .component_inputs
                    .accepted_block_certificate_statements[index]
                    .clone(),
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
            header.active_slot_count,
            header.alloc_counter,
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
    let headers = &output
        .proof_components
        .component_inputs
        .accepted_claim_witness
        .headers;
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
        &output
            .proof_components
            .component_inputs
            .accepted_claim_witness,
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
    let statements = &components
        .component_inputs
        .accepted_block_certificate_statements;
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
            &output
                .proof_components
                .component_inputs
                .accepted_claim_witness,
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
        &output
            .proof_components
            .component_inputs
            .accepted_claim_witness,
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
        prove_batched_merkle_killshot(
            &circuit,
            &components.component_inputs.tx_root_inputs,
            &mut channel,
        )
        .0,
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
    if components.component_inputs.tx_body_standard_inputs.len()
        != components.component_inputs.tx_body_standard_hashes.len()
        || components.component_inputs.tx_body_sweep_inputs.len()
            != components.component_inputs.tx_body_sweep_hashes.len()
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
    if components
        .component_inputs
        .tx_body_standard_inputs
        .is_empty()
    {
        return Ok(None);
    }
    let slot_state_ins =
        standard_tx_body_slot_state_ins(&components.component_inputs.tx_body_standard_inputs);
    let mle = BlockSpineMle::build(
        components.component_inputs.tx_body_standard_inputs.len(),
        &slot_state_ins,
    );
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

    // Tier-quantized capacity padding — the same rule as `compute_tx_root`,
    // so the rebuilt root matches the header.
    let (standard, sweep) = block
        .transactions
        .iter()
        .fold((0usize, 0usize), |(s, w), tx| match tx.body.shape {
            _ if tx.body.is_coinbase => (s, w),
            noid_tx::TxShape::Standard4x8 => (s + 1, w),
            noid_tx::TxShape::Sweep25x2 => (s, w + 1),
        });
    let non_user = block.transactions.len() - standard - sweep;
    let target = noid_chain::consensus::params::tx_tree_target(standard, sweep, non_user);
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
    use noid_chain::build_exact_action_surface;
    use noid_chain::consensus::difficulty::{block_work, next_target};
    use noid_chain::consensus::fees::required_fee_for_tx_body;
    use noid_chain::consensus::params::{BLOCK_TIME, MAX_TARGET};
    use noid_chain::consensus::pow::search_pow;
    use noid_chain::consensus::template::build_block_template;
    use noid_chain::fri_state::SlotValue;
    use noid_chain::header_anchor::compute_header_chain_anchor;
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

    /// A real coinbase-only child (one minting transaction, no detached
    /// block proof or authorization sidecar).
    fn coinbase_only_child(parent: &BlockHeader, state: &ChainState) -> Block {
        let timestamp = parent.timestamp + BLOCK_TIME;
        let difficulty_target = next_target(
            0,
            parent.timestamp,
            &parent.difficulty_target,
            parent.height + 1,
            timestamp,
        );
        let template = build_block_template(
            parent,
            state,
            &[parent.active_slot_count],
            vec![],
            Address([0x22; 32]),
            timestamp,
            difficulty_target,
        )
        .expect("coinbase-only template");
        let nonce =
            search_pow(&template.to_pow_header(0), 0, 64_000_000).expect("easy test target mines");
        Block {
            header: template.clone().into_header(nonce),
            transactions: template.all_txs(),
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
                creation_id: 0,
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

        let timestamp = parent.timestamp + BLOCK_TIME;
        let difficulty_target =
            next_target(0, parent.timestamp, &parent.difficulty_target, 1, timestamp);
        let template = build_block_template(
            &parent,
            &start_state,
            &[parent.active_slot_count],
            vec![tx.clone()],
            Address([0x22; 32]),
            timestamp,
            difficulty_target,
        )
        .expect("canonical user + coinbase template");
        assert_eq!(template.txs, vec![tx], "fixture user tx selected");
        let transactions = template.all_txs();
        assert!(transactions[0].body.is_coinbase);

        let parent_cache = {
            let mut tmp = start_state.clone();
            tmp.exact_sparse_cache().unwrap()
        };
        let block_bodies: Vec<_> = transactions.iter().map(|tx| tx.body.clone()).collect();
        let claims: Vec<_> = block_bodies
            .iter()
            .map(|body| noid_tx::compute_claims_commitment(&body.inputs, &body.outputs))
            .collect();
        let surface = build_exact_action_surface(
            &start_state.state,
            &block_bodies,
            &claims,
            start_state.alloc_counter,
        )
        .expect("coinbase + user exact action surface");
        let state_transition = crate::build_exact_state_transition_proof(&parent_cache, &surface)
            .expect("exact proof");

        let nonce =
            search_pow(&template.to_pow_header(0), 0, 64_000_000).expect("easy test target mines");
        let header = template.into_header(nonce);
        let block = Block {
            header: header.clone(),
            transactions,
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
            active_slot_count: parent.active_slot_count,
            alloc_counter: parent.alloc_counter,
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
        for nq in [4usize, 2usize] {
            let cfg = BlockSlotsConfig {
                discharge_wallet_pcs: true,
                wallet_pcs_params: RegionDischargeParams { nq },
                owner_auth_region: false,
                exact_state_region: false,
                tx_root_region: false,
                spine_region: false,
                tier_user_tx_capacity: None,
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
                "[probe] nq={nq}: block-slot wires={}, claims={}, max_arity={}, \
                 tail_lanes={}",
                b.num_wires(),
                claims.len(),
                max_arity,
                claims.len() * (max_arity + 1)
            );
        }
    }

    /// 4f.3 sizing ladder: freeze the region-mode block-bearing link at
    /// PRODUCTION parameters — the FULL region stack (owner-auth +
    /// exact-state + tx-root + spine + tier capacity) with the wallet-PCS
    /// discharge authenticating EVERY capsule query — across the std tiers
    /// a single m=24 class could host. On fit, prints the freeze time and
    /// the frozen claim ledger; on a class-shape miss the freeze's own
    /// eprintln has already printed the offending wire count.
    #[test]
    #[ignore = "measurement helper; run explicitly to size the region link"]
    fn region_link_size_measure() {
        use noid_ivc_core::pcs::{self, PcsParams};
        use noid_ivc_core::proof::FieldShape;
        use noid_ivc_core::zerocheck::K_SKIP;
        use noid_recursive::acceptance::block_slots::BlockSlotsConfig;
        use noid_recursive::acceptance::link::{LinkBlock, LinkClass};
        use noid_recursive::acceptance::trace::region_source_binding::RegionDischargeParams;

        const CLASS_M: usize = 24;
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
        let nq = BlockSlotsConfig::default().wallet_pcs_params.nq;
        // Real-tx counts landing exactly on the std tiers (the smallest
        // count whose consensus tier is the target keeps the fixtures cheap;
        // the trace is capacity-shaped, so the real count doesn't matter).
        for (n_real, tier) in [(5usize, 8usize), (17, 32), (33, 64), (129, 255)] {
            let units = chained_multi_tx_blocks(1, n_real);
            let rp = RegionDischargeParams { nq };
            let cfg = BlockSlotsConfig {
                discharge_wallet_pcs: true,
                wallet_pcs_params: rp,
                owner_auth_region: true,
                exact_state_region: true,
                tx_root_region: true,
                spine_region: true,
                tier_user_tx_capacity: Some(tier),
            };
            let sample = LinkBlock {
                start_accumulator: &units[0].start_accumulator,
                end_accumulator: &units[0].end_accumulator,
                inputs: &units[0].inputs,
                proof: &units[0].proof,
                config: cfg,
            };
            let t = std::time::Instant::now();
            let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let class = LinkClass::new_region_block_bearing(
                    shape,
                    params.clone(),
                    units[0].start_accumulator.clone(),
                    rp,
                    &sample,
                    true,
                    true,
                    true,
                    true,
                    Some(tier),
                );
                (
                    class.region_claims.len(),
                    class.region_max_arity,
                    class.spec.io_len,
                )
            }));
            match r {
                Ok((n, ma, io)) => eprintln!(
                    "[size] tier={tier} ({n_real} real tx) nq={nq} @m={CLASS_M}: FIT \
                     freeze={:.1?} claims={n} max_arity={ma} io_len={io}",
                    t.elapsed()
                ),
                Err(_) => eprintln!(
                    "[size] tier={tier} ({n_real} real tx) nq={nq} @m={CLASS_M}: \
                     DOES NOT FIT (wire count above)"
                ),
            }
        }
    }

    /// Two-level split ladder sizing: freeze the STANDALONE block class at
    /// each candidate ladder slot (tier, class m) and report the frozen
    /// claim ledger + freeze time; on a class-shape miss the freeze build's
    /// own eprintln has already printed the offending wire count. The
    /// tier-255 slot exercises the power-of-two obligation pad (255 user
    /// slots round up to 256 with one PAD ghost slot).
    ///
    /// One tier per process via `NOID_LADDER_TIER` (the tier-255 freeze is
    /// a ~30M-wire build — run it alone and watch RSS); all four otherwise.
    #[test]
    #[ignore = "measurement helper; run explicitly (multi-million-wire freezes)"]
    fn block_class_ladder_size_measure() {
        use noid_ivc_core::pcs::{self, PcsParams};
        use noid_ivc_core::proof::FieldShape;
        use noid_ivc_core::zerocheck::K_SKIP;
        use noid_recursive::acceptance::block_class::BlockClass;
        use noid_recursive::acceptance::block_slots::BlockSlotsConfig;
        use noid_recursive::acceptance::link::LinkBlock;
        use noid_recursive::acceptance::trace::region_source_binding::RegionDischargeParams;

        let nq = BlockSlotsConfig::default().wallet_pcs_params.nq;
        let only: Option<usize> = std::env::var("NOID_LADDER_TIER")
            .ok()
            .and_then(|t| t.parse().ok());
        // (smallest real-tx count landing on the tier, tier, candidate m).
        for (n_real, tier, m) in [
            (5usize, 8usize, 22usize),
            (17, 32, 23),
            (33, 64, 24),
            (129, 255, 25),
        ] {
            if only.is_some_and(|t| t != tier) {
                continue;
            }
            let shape = FieldShape {
                m,
                k_log: m,
                k_skip: K_SKIP,
                const_pin: Some(0),
            };
            let params = PcsParams {
                m: m + pcs::LOG_PACKING,
                log_inv_rate: 2,
                log_batch_size: 5,
                profile: Default::default(),
            };
            let units = chained_multi_tx_blocks(1, n_real);
            let rp = RegionDischargeParams { nq };
            let cfg = BlockSlotsConfig {
                discharge_wallet_pcs: true,
                wallet_pcs_params: rp,
                owner_auth_region: true,
                exact_state_region: true,
                tx_root_region: true,
                spine_region: true,
                tier_user_tx_capacity: Some(tier),
            };
            let sample = LinkBlock {
                start_accumulator: &units[0].start_accumulator,
                end_accumulator: &units[0].end_accumulator,
                inputs: &units[0].inputs,
                proof: &units[0].proof,
                config: cfg,
            };
            let t0 = std::time::Instant::now();
            let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let class = BlockClass::freeze(shape, params.clone(), rp, &sample, tier);
                (
                    class.region_claims.len(),
                    class.region_max_arity,
                    class.spec.io_len,
                )
            }));
            match r {
                Ok((n, ma, io)) => eprintln!(
                    "[b-size] tier={tier} ({n_real} real tx) nq={nq} @m={m}: FIT \
                     freeze={:.1?} claims={n} max_arity={ma} io_len={io}",
                    t0.elapsed()
                ),
                Err(_) => eprintln!(
                    "[b-size] tier={tier} ({n_real} real tx) nq={nq} @m={m}: \
                     DOES NOT FIT (wire count above)"
                ),
            }
        }
    }

    /// 4f.3 budget gate: ONE miner-shaped prove at production parameters.
    /// Freezes the full-region class at one tier, builds π₀ for a real
    /// block of that tier, runs exactly ONE `prove_field_with_public_io`
    /// and verifies it, reporting wall times and process RSS/HWM at each
    /// stage. A miner's per-block footprint = the frozen class + one
    /// prove (the genesis-T prove is a once-per-class setup cost of the
    /// same instance shape, so the final HWM is a conservative bound for
    /// both). Asserts the acceptance budget: peak RSS ≤ 8 GB.
    ///
    /// Tier via `NOID_REGION_MEASURE_TIER` in {8, 32, 64, 255} (default 8);
    /// prover memory at a fixed class m is tier-independent (the class
    /// pads to 2^m rows), so one tier is representative — the ladder test
    /// above establishes which tiers FIT.
    #[test]
    #[ignore = "measurement gate; run explicitly (ONE at a time, heavy prove)"]
    fn region_link_isolated_prove_budget_measure() {
        use noid_core::mem_profile::current_mem_snapshot;
        use noid_ivc_core::challenger::FsLaneChallenger;
        use noid_ivc_core::field::F128;
        use noid_ivc_core::pcs::{self, PcsParams};
        use noid_ivc_core::proof::FieldShape;
        use noid_ivc_core::verifier::verify_field_with_public_io;
        use noid_ivc_core::zerocheck::K_SKIP;
        use noid_ivc_prover::field_prover::prove_field_with_public_io;
        use noid_recursive::acceptance::block_slots::BlockSlotsConfig;
        use noid_recursive::acceptance::link::{
            build_link, build_link_reusing_matrix, genesis_witness, LinkBlock, LinkClass,
            LinkEnvelope, LinkInput,
        };
        use noid_recursive::acceptance::trace::region_source_binding::RegionDischargeParams;
        use std::time::Instant;

        let tier: usize = std::env::var("NOID_REGION_MEASURE_TIER")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(8);
        let n_real = match tier {
            8 => 5,
            32 => 17,
            64 => 33,
            255 => 129,
            other => panic!("unsupported measure tier {other} (use a ladder tier)"),
        };
        let rss = |label: &str| {
            if let Some(m) = current_mem_snapshot() {
                eprintln!(
                    "[budget] {label}: rss={:.2} GB hwm={:.2} GB",
                    m.rss_mb() / 1024.0,
                    m.hwm_mb() / 1024.0
                );
            }
        };

        const CLASS_M: usize = 24;
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
        let nq = BlockSlotsConfig::default().wallet_pcs_params.nq;
        let rp = RegionDischargeParams { nq };
        let cfg = BlockSlotsConfig {
            discharge_wallet_pcs: true,
            wallet_pcs_params: rp,
            owner_auth_region: true,
            exact_state_region: true,
            tx_root_region: true,
            spine_region: true,
            tier_user_tx_capacity: Some(tier),
        };

        eprintln!("[budget] tier={tier} ({n_real} real tx) nq={nq} @m={CLASS_M}");
        let units = chained_multi_tx_blocks(2, n_real);
        rss("fixtures built");

        fn mk(u: &BlockUnit, config: BlockSlotsConfig) -> LinkBlock<'_> {
            LinkBlock {
                start_accumulator: &u.start_accumulator,
                end_accumulator: &u.end_accumulator,
                inputs: &u.inputs,
                proof: &u.proof,
                config,
            }
        }

        let t = Instant::now();
        let class = LinkClass::new_region_block_bearing(
            shape,
            params.clone(),
            units[0].start_accumulator.clone(),
            rp,
            &mk(&units[0], cfg),
            true,
            true,
            true,
            true,
            Some(tier),
        );
        eprintln!(
            "[budget] class frozen in {:.1?}: claims={} max_arity={} io_len={}",
            t.elapsed(),
            class.region_claims.len(),
            class.region_max_arity,
            class.spec.io_len
        );
        rss("after freeze");

        // Once-per-class setup: the genesis dummy T proof.
        let t_witness = genesis_witness(&shape);
        let t_io = vec![F128::ZERO; class.spec.io_len];
        let t = Instant::now();
        let mut ch = FsLaneChallenger::new(b"history-link-v0");
        let (t_proof, t_commitment, _) = prove_field_with_public_io(
            &class.genesis,
            &t_witness,
            &params,
            &class.spec,
            &t_io,
            &mut ch,
        );
        eprintln!(
            "[budget] genesis T prove (once-per-class setup) {:.1?}",
            t.elapsed()
        );
        drop(t_witness);
        rss("after T prove");
        let env_t = LinkEnvelope {
            proof: t_proof,
            commitment: t_commitment,
            io: t_io,
        };

        // The per-block work a miner repeats: build π₀'s trace + ONE prove.
        let t = Instant::now();
        let built0 = build_link(
            &class,
            &LinkInput {
                prev: &env_t,
                verified_digest: class.genesis_digest,
                genesis: true,
                fold_matrix: &class.genesis,
                block: Some(mk(&units[0], cfg)),
            },
        );
        let build_time = t.elapsed();
        eprintln!(
            "[budget] π₀ build {build_time:.1?}: {} wires -> 2^{}",
            built0.witness.len(),
            built0.r1cs.k_log
        );
        assert!(
            built0.r1cs.satisfies(&built0.witness),
            "π₀ trace unsatisfiable at tier {tier}"
        );
        rss("after π₀ build");

        let t = Instant::now();
        let mut ch = FsLaneChallenger::new(b"history-link-v0");
        let (p0, c0, _) = prove_field_with_public_io(
            &built0.r1cs,
            &built0.witness,
            &params,
            &class.spec,
            &built0.io,
            &mut ch,
        );
        let prove_time = t.elapsed();
        // THE 8 GB BAR: the isolated single-link prove — one class matrix
        // resident, nothing else (fold matrix was the small genesis dummy).
        // Captured here, before the steady-state leg below inflates the
        // process high-water mark with its two-matrix build window.
        let isolated_prove_hwm_gb = current_mem_snapshot()
            .map(|m| m.hwm_mb() / 1024.0)
            .unwrap_or(f64::NAN);
        rss("after π₀ prove");

        // π₁ ⊳ π₀ — the STEADY-STATE per-block work: the class statement
        // digest is now seeded, so this build+prove is what a miner repeats
        // every block.
        let pi0_io = built0.io;
        let pi0_r1cs = built0.r1cs;
        drop(built0.witness);
        drop(built0.region_claims);
        let env0 = LinkEnvelope {
            proof: p0,
            commitment: c0,
            io: pi0_io,
        };
        let class_digest = pi0_r1cs.statement_digest();
        let t = Instant::now();
        // Steady state: the previous instance is MOVED in as both the fold
        // reference and the adopted class matrix — the trace pass runs
        // witness-only, so no second matrix copy ever exists (the old
        // "two-matrix build window" is gone by construction). The satisfies
        // check below runs the full witness against the ADOPTED matrix,
        // end-to-end validating the witness-only rebuild.
        let built1 = build_link_reusing_matrix(
            &class,
            &env0,
            class_digest,
            Some(mk(&units[1], cfg)),
            pi0_r1cs,
        );
        let build1_time = t.elapsed();
        let build_window_hwm_gb = current_mem_snapshot()
            .map(|m| m.hwm_mb() / 1024.0)
            .unwrap_or(f64::NAN);
        rss("after π₁ build (matrix adopted, witness-only)");
        assert!(
            built1.r1cs.satisfies(&built1.witness),
            "π₁ trace unsatisfiable at tier {tier}"
        );
        let t = Instant::now();
        let mut ch = FsLaneChallenger::new(b"history-link-v0");
        let (p1, c1, _) = prove_field_with_public_io(
            &built1.r1cs,
            &built1.witness,
            &params,
            &class.spec,
            &built1.io,
            &mut ch,
        );
        let prove1_time = t.elapsed();
        rss("after π₁ prove");

        // A validator never holds the prover's witness; drop it before
        // measuring the verify (its own memory profile — an O(2^m) matrix
        // pass — stacked here on retained prover state).
        let pi1_io = built1.io;
        let pi1_r1cs = built1.r1cs;
        drop(built1.witness);
        drop(built1.region_claims);
        let t = Instant::now();
        let mut chv = FsLaneChallenger::new(b"history-link-v0");
        verify_field_with_public_io(&pi1_r1cs, &c1, &p1, &class.spec, &pi1_io, &mut chv)
            .expect("π₁ verifies");
        let verify_time = t.elapsed();
        rss("after π₁ verify (validator-side, stacked on retained prover state)");

        eprintln!(
            "[budget] RESULT tier={tier} @m={CLASS_M} nq={nq}: once-per-class π₀ build \
             {build_time:.1?} (includes the one-time class digest) + prove {prove_time:.1?}; \
             STEADY-STATE per block: build {build1_time:.1?} + prove {prove1_time:.1?} \
             (verify {verify_time:.1?}); ISOLATED prove peak {isolated_prove_hwm_gb:.2} GB, \
             steady build window {build_window_hwm_gb:.2} GB (matrix adopted; the residual \
             transient is the deferred fold's dense g_v/g_e/e_c/v tables, ~3*2^(m+5) B)"
        );
        assert!(
            isolated_prove_hwm_gb <= 8.0,
            "isolated single-link prover peak RSS {isolated_prove_hwm_gb:.2} GB busts the \
             8 GB acceptance budget"
        );
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
    /// Build ONE block carrying `specs.len()` standard txs (one owner, each
    /// spending `input_slot` -> `output_slot`, shape `Standard4x8`). A single tx
    /// (`specs.len() == 1`) reproduces the former single-tx builder exactly; a
    /// multi-tx block is the same block with N independent txs (the class tier =
    /// N). Returns the item, its header, and each tx's surviving output value.
    fn make_std_tx_block_item(
        start_state: &ChainState,
        start_parent: &BlockHeader,
        anchor: &AnchorInfo,
        secret: &SpendSecret,
        specs: &[(u32, u32, u64)],
    ) -> (FullAcceptedBlockBatchItem, BlockHeader, Vec<u64>) {
        let owner = derive_address(secret);
        let mut bodies = Vec::with_capacity(specs.len());
        for &(input_slot, output_slot, input_value) in specs {
            let pre_slot = start_state.state.slot(input_slot);
            assert_eq!(
                pre_slot.amount(),
                input_value,
                "fixture input amount must match the canonical parent slot"
            );
            assert_eq!(
                [pre_slot.owner_hi, pre_slot.owner_lo],
                owner.as_fields(),
                "fixture input owner must match the canonical parent slot"
            );
            let mut body = TxBody {
                shape: TxShape::Standard4x8,
                epoch_anchor: [0x42; 32],
                fee: 0,
                inputs: vec![TxInput {
                    slot_index: input_slot,
                    value: input_value,
                    creation_id: pre_slot.creation_id(),
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
            let required_fee = required_fee_for_tx_body(
                &body,
                start_parent.active_slot_count,
                start_parent.log_slots,
            );
            body.fee = required_fee as u128;
            body.outputs[0].value = input_value.saturating_sub(required_fee);
            bodies.push(body);
        }
        let txs: Vec<_> = bodies.iter().map(|b| tx_from_body(b.clone())).collect();

        let timestamp = start_parent.timestamp + BLOCK_TIME;
        let difficulty_target = next_target(
            anchor.anchor_height,
            anchor.anchor_timestamp,
            &anchor.anchor_target,
            start_parent.height + 1,
            timestamp,
        );
        let template = build_block_template(
            start_parent,
            start_state,
            &[start_parent.active_slot_count],
            txs,
            Address([0x22; 32]),
            timestamp,
            difficulty_target,
        )
        .expect("canonical standard-user + coinbase template");
        assert_eq!(
            template.txs.len(),
            bodies.len(),
            "every fixture user transaction is selected"
        );
        let transactions = template.all_txs();
        assert!(transactions[0].body.is_coinbase);

        let parent_cache = {
            let mut tmp = start_state.clone();
            tmp.exact_sparse_cache().unwrap()
        };
        let block_bodies: Vec<_> = transactions.iter().map(|tx| tx.body.clone()).collect();
        let claims: Vec<_> = block_bodies
            .iter()
            .map(|body| noid_tx::compute_claims_commitment(&body.inputs, &body.outputs))
            .collect();
        let surface = build_exact_action_surface(
            &start_state.state,
            &block_bodies,
            &claims,
            start_state.alloc_counter,
        )
        .expect("coinbase + standard-user exact action surface");
        let state_transition = crate::build_exact_state_transition_proof(&parent_cache, &surface)
            .expect("exact proof");

        let nonce =
            search_pow(&template.to_pow_header(0), 0, 64_000_000).expect("easy test target mines");
        let header = template.clone().into_header(nonce);
        let block = Block {
            header: header.clone(),
            transactions,
        };
        let block_proof = crate::BlockProof::minimal(
            start_parent.state_root,
            block.header.state_root,
            specs.len() as u32,
            state_transition,
        );
        let auth_sidecar = crate::BlockAuthSidecar {
            // Coinbase has no authorization proof. Preserve canonical block
            // order for user proofs after template ordering.
            tx_auth: template
                .txs
                .iter()
                .map(|tx| auth_proof_for_body(&tx.body))
                .collect(),
        };
        let surviving_values: Vec<u64> = bodies.iter().map(|b| b.outputs[0].value).collect();
        (
            FullAcceptedBlockBatchItem {
                block,
                block_proof_bytes: bincode::serialize(&block_proof).unwrap(),
                block_auth_sidecar_bytes: bincode::serialize(&auth_sidecar).unwrap(),
            },
            header,
            surviving_values,
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
            active_slot_count: parent.active_slot_count,
            alloc_counter: parent.alloc_counter,
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
            let (item, header, surviving) = make_std_tx_block_item(
                &state,
                &parent,
                &anchor,
                &secret,
                &[(input_slot, output_slot, value)],
            );
            let surviving_value = surviving[0];
            let witness = FullAcceptedBlockBatchWitness { items: vec![item] };
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

    /// A chain of `n_blocks` same-tier blocks, each carrying `tx_per_block`
    /// standard txs (one owner). Block 1 spends the premined slots; block i+1
    /// spends block i's outputs (fresh monotone output slots avoid the reuse
    /// guard). Every block is the same class tier (`tx_per_block` standard txs),
    /// so the region discharge sees `k = tx_per_block` obligations -- this is what
    /// exercises the MULTI-tx wallet-PCS region discharge end to end.
    fn chained_multi_tx_blocks(n_blocks: usize, tx_per_block: usize) -> Vec<BlockUnit> {
        chained_blocks_with_tx_counts(&vec![tx_per_block; n_blocks])
    }

    /// [`chained_multi_tx_blocks`] generalized to a PER-BLOCK tx count:
    /// block i carries `counts[i]` standard txs and spends the first
    /// `counts[i]` outputs of its predecessor (so counts must be
    /// non-increasing). Mixed counts produce chained blocks of DIFFERENT
    /// consensus tiers -- the split-link cross-class fixture.
    fn chained_blocks_with_tx_counts(counts: &[usize]) -> Vec<BlockUnit> {
        assert!(!counts.is_empty() && counts.iter().all(|&c| c >= 1));
        for w in counts.windows(2) {
            assert!(
                w[1] <= w[0],
                "each block can only spend its predecessor's outputs"
            );
        }
        let n_blocks = counts.len();
        let secret = spend_secret(7);
        let owner = derive_address(&secret);
        let input_value = 10_000_000u64;

        // Slot space must hold the premined inputs + every block's fresh outputs.
        let needed = 2 + counts[0] + counts.iter().sum::<usize>();
        let log_slots = needed.next_power_of_two().trailing_zeros().max(4) as usize;
        let mut state = ChainState::with_log_slots(log_slots);
        let mut current_slots: Vec<u32> = (0..counts[0] as u32).map(|i| 2 + i).collect();
        for &s in &current_slots {
            state
                .state
                .set_slot(
                    s,
                    SlotValue {
                        value: Block128::from(input_value as u128),
                        owner_hi: owner.as_fields()[0],
                        owner_lo: owner.as_fields()[1],
                    },
                )
                .unwrap();
        }
        state.rebuild_exact_utxo_root_loaded().unwrap();
        state.active_slot_count = counts[0] as u64;
        state.alloc_counter = 2 + counts[0] as u64;

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
            active_slot_count: parent.active_slot_count,
            alloc_counter: parent.alloc_counter,
        };

        let mut units = Vec::with_capacity(n_blocks);
        let mut values: Vec<u64> = vec![input_value; counts[0]];
        let mut next_free = 2 + counts[0] as u32;
        for i in 0..n_blocks {
            let cnt = counts[i];
            assert!(
                cnt <= current_slots.len(),
                "block {i} overspends its predecessor"
            );
            let output_slots: Vec<u32> = (0..cnt as u32).map(|j| next_free + j).collect();
            next_free += cnt as u32;
            let specs: Vec<(u32, u32, u64)> = (0..cnt)
                .map(|j| (current_slots[j], output_slots[j], values[j]))
                .collect();
            let anchor = AnchorInfo {
                anchor_height: consensus.asert_anchor_height,
                anchor_timestamp: consensus.asert_anchor_timestamp,
                anchor_target: consensus.asert_anchor_target,
            };
            let (item, header, surviving) =
                make_std_tx_block_item(&state, &parent, &anchor, &secret, &specs);
            let witness = FullAcceptedBlockBatchWitness { items: vec![item] };
            let (output, proof) = prove_retained_full_accepted_block_batch_proof(
                &consensus,
                &accumulator,
                &parent,
                &state,
                &witness,
            )
            .unwrap_or_else(|e| panic!("multi-tx block {i} proves: {e:?}"));

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
            current_slots = output_slots;
            values = surviving;
        }
        units
    }

    /// One real Standard4x8 consolidation transaction (two live inputs from
    /// the same owner, one output) plus the mandatory coinbase.  `variant`
    /// changes every content-bearing value while preserving the protocol
    /// shape; this makes two fixtures suitable for a class-matrix equality
    /// check instead of merely rebuilding the same witness twice.
    fn multi_input_coinbase_block_fixture(variant: u8) -> BlockUnit {
        let secret = spend_secret(7u8.wrapping_add(variant));
        let owner = derive_address(&secret);
        let shift = u32::from(variant) * 8;
        let input_slots = [2 + shift, 3 + shift];
        let output_slot = 6 + shift;
        let input_values = [
            5_000_000u64 + u64::from(variant) * 10_000,
            6_000_000u64 + u64::from(variant) * 20_000,
        ];

        let mut state = ChainState::with_log_slots(6);
        for (&slot, &value) in input_slots.iter().zip(input_values.iter()) {
            state
                .state
                .set_slot(
                    slot,
                    SlotValue {
                        value: Block128::from(value as u128),
                        owner_hi: owner.as_fields()[0],
                        owner_lo: owner.as_fields()[1],
                    },
                )
                .unwrap();
        }
        state.rebuild_exact_utxo_root_loaded().unwrap();
        state.active_slot_count = 2;
        state.alloc_counter = 16 + u64::from(variant);
        let parent = parent_header(&mut state);

        let mut body = TxBody {
            shape: TxShape::Standard4x8,
            epoch_anchor: noid_chain::consensus::pow::block_id(&parent),
            fee: 0,
            inputs: input_slots
                .iter()
                .zip(input_values.iter())
                .map(|(&slot_index, &value)| TxInput {
                    slot_index,
                    value,
                    creation_id: 0,
                    owner,
                    spend_secret: secret.clone(),
                    valid: true,
                })
                .collect(),
            outputs: vec![TxOutput {
                slot_index: output_slot,
                value: input_values.iter().sum(),
                owner,
                valid: true,
            }],
            is_coinbase: false,
        };
        let required_fee =
            required_fee_for_tx_body(&body, parent.active_slot_count, parent.log_slots);
        body.fee = required_fee as u128;
        body.outputs[0].value = input_values
            .iter()
            .sum::<u64>()
            .checked_sub(required_fee)
            .expect("fixture remains solvent");
        let user_tx = tx_from_body(body.clone());

        let timestamp = parent.timestamp + BLOCK_TIME;
        let difficulty_target = next_target(
            0,
            parent.timestamp,
            &parent.difficulty_target,
            parent.height + 1,
            timestamp,
        );
        let template = build_block_template(
            &parent,
            &state,
            &[parent.active_slot_count],
            vec![user_tx.clone()],
            Address([0xA0u8.wrapping_add(variant); 32]),
            timestamp,
            difficulty_target,
        )
        .expect("multi-input + coinbase template");
        assert_eq!(template.txs, vec![user_tx], "user transaction selected");
        let transactions = template.all_txs();
        assert_eq!(transactions.len(), 2, "coinbase plus one user transaction");
        assert!(transactions[0].body.is_coinbase, "coinbase is first");
        assert_eq!(
            transactions[1]
                .body
                .inputs
                .iter()
                .filter(|input| input.valid)
                .count(),
            2,
            "real two-input consolidation"
        );

        let parent_cache = {
            let mut tmp = state.clone();
            tmp.exact_sparse_cache().unwrap()
        };
        let bodies: Vec<_> = transactions.iter().map(|tx| tx.body.clone()).collect();
        let claims: Vec<_> = bodies
            .iter()
            .map(|tx| noid_tx::compute_claims_commitment(&tx.inputs, &tx.outputs))
            .collect();
        let surface =
            build_exact_action_surface(&state.state, &bodies, &claims, state.alloc_counter)
                .expect("coinbase + consolidation exact action surface");
        assert_eq!(surface.spends, 2);
        assert_eq!(surface.mints, 2, "user output plus coinbase output");
        let state_transition = crate::build_exact_state_transition_proof(&parent_cache, &surface)
            .expect("coinbase + consolidation exact proof");

        let nonce =
            search_pow(&template.to_pow_header(0), 0, 64_000_000).expect("easy test target mines");
        let header = template.clone().into_header(nonce);
        let block = Block {
            header: header.clone(),
            transactions,
        };
        let block_proof =
            crate::BlockProof::minimal(parent.state_root, header.state_root, 1, state_transition);
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
            active_slot_count: parent.active_slot_count,
            alloc_counter: parent.alloc_counter,
        };
        let (output, proof) = prove_retained_full_accepted_block_batch_proof(
            &start_consensus,
            &start_accumulator,
            &parent,
            &state,
            &witness,
        )
        .expect("multi-input + coinbase fixture proves natively");
        assert_eq!(
            output
                .proof_components
                .component_inputs
                .authorization_inputs
                .len(),
            1
        );
        assert_eq!(
            output
                .proof_components
                .component_inputs
                .authorization_totals
                .live_input_count_total,
            2
        );
        assert_eq!(
            output
                .proof_components
                .component_inputs
                .tx_body_standard_inputs
                .len(),
            2,
            "coinbase and user body both reach the spine component"
        );

        BlockUnit {
            start_accumulator,
            end_accumulator: output.accepted_claim_batch.accumulator,
            inputs: output.proof_components.component_inputs,
            proof,
            block_header: header,
        }
    }

    /// Fixture check: a chain of 2-tx-per-block standard blocks proves NATIVELY
    /// (the `prove_retained_*` call inside the builder validates each multi-tx
    /// block), and each block's component inputs carry 2 authorization inputs.
    /// Light (native accept only, no recursion) -- de-risks the multi-tx region
    /// gate before its heavy m=24 proves.
    #[test]
    fn multi_tx_block_fixture_natively_valid() {
        let units = chained_multi_tx_blocks(2, 2);
        assert_eq!(units.len(), 2, "two chained multi-tx blocks");
        for (i, u) in units.iter().enumerate() {
            assert_eq!(
                u.inputs.authorization_inputs.len(),
                2,
                "block {i} carries 2 authorization inputs (2 std txs)"
            );
            assert_eq!(
                u.inputs.authorization_totals.user_tx_count, 2,
                "block {i} user_tx_count"
            );
        }
        eprintln!("[multi-tx] 2 blocks x 2 std txs proved natively; 2 auth inputs each");
    }

    #[test]
    #[ignore = "heavy C0 retained fixture (~97s); exercised twice by the explicit matrix gate"]
    fn multi_input_coinbase_block_fixture_natively_valid() {
        let unit = multi_input_coinbase_block_fixture(0);
        assert_eq!(unit.inputs.authorization_inputs.len(), 1);
        assert_eq!(unit.inputs.authorization_totals.user_tx_count, 1);
        assert_eq!(unit.inputs.authorization_totals.owner_count_total, 1);
        assert_eq!(unit.inputs.authorization_totals.live_input_count_total, 2);
        assert_eq!(unit.inputs.tx_body_standard_inputs.len(), 2);
        assert_eq!(unit.inputs.tx_root_inputs.len(), 2);
        assert_eq!(unit.inputs.exact_state_killshot_inputs.len(), 1);
    }

    /// The link prefills its region IO envelope from `region_wallet_pcs_native`
    /// (a scratch owner-auth-only discharge) and pins the real block-slots
    /// discharge WIRES to those cells, so the two MUST agree on every claim's
    /// native (point, value) -- else π₀ fails to verify. Compare them for a 2-tx
    /// block. Light (block-slots build only, no m=24 prove) -- localizes any
    /// multi-tx link-threading divergence fast.
    #[test]
    fn region_native_matches_real_build_multitx() {
        use noid_ivc_core::field_circuit::FieldR1csBuilder;
        use noid_recursive::acceptance::block_slots::{
            build_block_slots_with_config, region_wallet_pcs_native, BlockSlotsConfig,
        };
        use noid_recursive::acceptance::trace::region_source_binding::RegionDischargeParams;
        let region_params = RegionDischargeParams { nq: 2 };
        let units = chained_multi_tx_blocks(1, 2);
        let u = &units[0];
        let scratch =
            region_wallet_pcs_native(&u.inputs, region_params, false, false, false, false, None);
        let cfg = BlockSlotsConfig {
            discharge_wallet_pcs: true,
            wallet_pcs_params: region_params,
            owner_auth_region: false,
            exact_state_region: false,
            tx_root_region: false,
            spine_region: false,
            tier_user_tx_capacity: None,
        };
        let mut b = FieldR1csBuilder::new();
        let slots = build_block_slots_with_config(
            &mut b,
            &u.start_accumulator,
            &u.end_accumulator,
            &u.inputs,
            &u.proof,
            cfg,
        );
        let real = &slots.pending_wallet_pcs;
        eprintln!(
            "[region-native] scratch claims={} real claims={}",
            scratch.len(),
            real.len()
        );
        assert_eq!(
            scratch.len(),
            real.len(),
            "claim count matches (scratch vs real)"
        );
        let mut mism = 0usize;
        for (i, (s, r)) in scratch.iter().zip(real.iter()).enumerate() {
            let point_eq = s.0 == r.native_point;
            let value_eq = s.1 == r.native_value;
            if !point_eq || !value_eq {
                mism += 1;
                if mism <= 8 {
                    eprintln!(
                        "[region-native] MISMATCH claim {i}: point_eq={point_eq} (len {}/{}), value_eq={value_eq}",
                        s.0.len(),
                        r.native_point.len()
                    );
                }
            }
        }
        assert_eq!(
            mism, 0,
            "region_wallet_pcs_native must match the real discharge (2-tx)"
        );
        eprintln!(
            "[region-native] scratch == real for {} claims (2-tx)",
            scratch.len()
        );

        // The whole block_slots(2-tx) trace is satisfiable (region columns are
        // free wires bound only by the opening claims; the [K]/block pins -- incl.
        // the integer count summation -- all hold at this tier).
        let (r1cs, z) = b.build();
        assert!(
            r1cs.satisfies(&z),
            "block_slots(2-tx) trace must be satisfiable (a [K]/block pin fails at this tier)"
        );
        eprintln!(
            "[region-native] block_slots(2-tx) IS satisfiable ({} wires)",
            z.len()
        );
    }

    /// Owner-auth region-vs-inline OBLIGATION PARITY on a REAL block's auth data.
    /// The shape-fixed region KSCHANNL walk-C discharge
    /// (`discharge_owner_auth_killshots_via_region`, the `owner_auth_region=true`
    /// path) must produce the SAME `PendingAuthPcsObligation` (reduced r_B /
    /// b_final + commitment cap lanes) the inline per-tx replay
    /// (`build_owner_auth_slot`, the `owner_auth_region=false` path) does — the
    /// invariant the flag rests on, since the region path feeds these obligations
    /// to the wallet-PCS discharge UNCHANGED. Light (no wallet-PCS discharge, no
    /// block-[B] killshots), so it runs in CI.
    #[test]
    fn region_owner_auth_obligation_parity_real_block() {
        use noid_ivc_core::field_circuit::FieldR1csBuilder;
        use noid_recursive::acceptance::trace::owner_auth::{
            build_owner_auth_slot, OwnerAuthProofTrace, OwnerAuthPublicInputsTrace,
        };
        use noid_recursive::acceptance::trace::region_source_binding::discharge_owner_auth_killshots_via_region;

        let units = chained_std_tx_blocks(1);
        let u = &units[0];
        let auth = &u.inputs.authorization_inputs;
        let wit = &u.inputs.authorization_witnesses;
        assert!(
            !auth.is_empty(),
            "the std-tx block carries at least one auth input"
        );

        let mut b = FieldR1csBuilder::new();
        // Inline obligations (the canonical per-tx replay).
        let inline_obs: Vec<_> = auth
            .iter()
            .zip(wit.iter())
            .map(|(inp, wp)| build_owner_auth_slot(&mut b, wp, &inp.public).1)
            .collect();
        // Region obligations on freshly-allocated trace proof/inputs (the SAME
        // alloc the block-slots region path does).
        let proof_ts: Vec<OwnerAuthProofTrace> = auth
            .iter()
            .zip(wit.iter())
            .map(|(inp, wp)| OwnerAuthProofTrace::alloc(&mut b, wp, inp.public.layout))
            .collect();
        let input_ts: Vec<OwnerAuthPublicInputsTrace> = auth
            .iter()
            .map(|inp| OwnerAuthPublicInputsTrace::alloc(&mut b, &inp.public))
            .collect();
        let natives: Vec<_> = wit.iter().cloned().collect();
        let native_inputs: Vec<_> = auth.iter().map(|i| i.public.clone()).collect();
        let (region_obs, oa_claims, _oa_recording) = discharge_owner_auth_killshots_via_region(
            &mut b,
            &proof_ts,
            &input_ts,
            &natives,
            &native_inputs,
        );
        assert!(
            !oa_claims.is_empty(),
            "region discharge produced no walk-C opening claims"
        );

        let (r1cs, z) = b.build();
        assert!(
            r1cs.satisfies(&z),
            "combined inline+region owner-auth trace must be satisfiable"
        );

        assert_eq!(region_obs.len(), inline_obs.len(), "obligation count");
        for (i, (ro, io)) in region_obs.iter().zip(inline_obs.iter()).enumerate() {
            assert_eq!(ro.num_vars, io.num_vars, "obligation {i} num_vars");
            assert_eq!(
                ro.reduction.point.len(),
                io.reduction.point.len(),
                "obligation {i} point arity"
            );
            for (pr, pi) in ro.reduction.point.iter().zip(io.reduction.point.iter()) {
                assert_eq!(
                    pr.eval(&z),
                    pi.eval(&z),
                    "obligation {i} r_B mismatch (region vs inline)"
                );
            }
            assert_eq!(
                ro.reduction.value.eval(&z),
                io.reduction.value.eval(&z),
                "obligation {i} b_final mismatch (region vs inline)"
            );
            assert_eq!(
                ro.commitment_cap_lanes.len(),
                io.commitment_cap_lanes.len(),
                "obligation {i} cap lane count"
            );
            for (lr, li) in ro
                .commitment_cap_lanes
                .iter()
                .zip(io.commitment_cap_lanes.iter())
            {
                assert_eq!(lr[0].eval(&z), li[0].eval(&z), "obligation {i} cap lane 0");
                assert_eq!(lr[1].eval(&z), li[1].eval(&z), "obligation {i} cap lane 1");
            }
        }
        eprintln!(
            "[owner-auth-region] real-block obligation parity: {} obligation(s), {} walk-C claims, {} wires",
            region_obs.len(),
            oa_claims.len(),
            z.len()
        );
    }

    /// The standalone per-tier BLOCK class `B_t` (two-level split, Stage A):
    /// freeze from a sample block, build a real block trace, prove + verify
    /// with the accumulator/region public IO, and assert PER-TIER CLASS
    /// FIXITY — a second (different, chained) block of the same tier
    /// produces a byte-identical class matrix. Negative: a corrupted end-
    /// accumulator IO lane must fail verification (the statement is bound).
    #[test]
    fn block_class_standalone_e2e() {
        use noid_ivc_core::challenger::FsLaneChallenger;
        use noid_ivc_core::field::F128;
        use noid_ivc_core::pcs::{self, PcsParams};
        use noid_ivc_core::proof::FieldShape;
        use noid_ivc_core::verifier::verify_field_with_public_io;
        use noid_ivc_core::zerocheck::K_SKIP;
        use noid_ivc_prover::field_prover::prove_field_with_public_io;
        use noid_recursive::acceptance::block_class::{build_block_proof_trace, BlockClass};
        use noid_recursive::acceptance::link::LinkBlock;
        use noid_recursive::acceptance::trace::region_source_binding::RegionDischargeParams;

        const M: usize = 22;
        let shape = FieldShape {
            m: M,
            k_log: M,
            k_skip: K_SKIP,
            const_pin: Some(0),
        };
        let params = PcsParams {
            m: M + pcs::LOG_PACKING,
            log_inv_rate: 2,
            log_batch_size: 5,
            profile: Default::default(),
        };
        let rp = RegionDischargeParams { nq: 2 };
        let tier = 8usize;
        let units = chained_multi_tx_blocks(2, 3);
        fn mk(u: &BlockUnit) -> LinkBlock<'_> {
            LinkBlock {
                start_accumulator: &u.start_accumulator,
                end_accumulator: &u.end_accumulator,
                inputs: &u.inputs,
                proof: &u.proof,
                config: Default::default(),
            }
        }

        let class = BlockClass::freeze(shape, params.clone(), rp, &mk(&units[0]), tier);
        assert!(!class.region_claims.is_empty(), "frozen claims present");

        let built = build_block_proof_trace(&class, &mk(&units[0]));
        assert!(
            built.r1cs.satisfies(&built.witness),
            "B_t trace unsatisfiable"
        );

        let mut ch = FsLaneChallenger::new(b"history-block-v0");
        let (proof, commitment, _) = prove_field_with_public_io(
            &built.r1cs,
            &built.witness,
            &params,
            &class.spec,
            &built.io,
            &mut ch,
        );
        let mut chv = FsLaneChallenger::new(b"history-block-v0");
        verify_field_with_public_io(
            &built.r1cs,
            &commitment,
            &proof,
            &class.spec,
            &built.io,
            &mut chv,
        )
        .expect("π_block verifies with its public IO");

        // Negative: a corrupted end-accumulator lane must reject.
        let mut bad_io = built.io.clone();
        bad_io[5] += F128::ONE;
        let mut chb = FsLaneChallenger::new(b"history-block-v0");
        assert!(
            verify_field_with_public_io(
                &built.r1cs,
                &commitment,
                &proof,
                &class.spec,
                &bad_io,
                &mut chb,
            )
            .is_err(),
            "corrupted end-accumulator IO lane slipped through"
        );

        // Per-tier class fixity: a DIFFERENT block of the same tier yields a
        // byte-identical class matrix (and a satisfiable trace).
        let built2 = build_block_proof_trace(&class, &mk(&units[1]));
        assert_eq!(
            built.r1cs.statement_digest(),
            built2.r1cs.statement_digest(),
            "B_t class matrix drifted across blocks"
        );
        assert!(
            built.r1cs.a_0 == built2.r1cs.a_0 && built.r1cs.b_0 == built2.r1cs.b_0,
            "B_t matrices differ across blocks of the same tier"
        );
        assert!(
            built2.r1cs.satisfies(&built2.witness),
            "second B_t trace unsatisfiable"
        );
    }

    /// The FULL LADDER freeze (two-level π, task-6 ladder sizing): freeze
    /// all four candidate ladder slots — block classes {tier-8 @ m=22,
    /// tier-32 @ m=23, tier-64 @ m=24, tier-255 @ m=25} — prove one sample
    /// block per class, freeze the four link classes at the m=23 link
    /// shape, and assert the ladder invariant: ALL FOUR link classes share
    /// one spec (io layout + walk opening-claim slices/arities). The
    /// tier-255 slot exercises the power-of-two obligation pad and the
    /// deepest [R]_B replay (m=25: 5-epoch FRI, 2^10 plaintext tail).
    /// Chain proving/decider mechanics are covered by the two-slot gate
    /// below; this measure stops at the frozen classes.
    ///
    /// HEAVY: ~184 wallet proves in the fixture, a 29M-wire tier-255
    /// freeze, and an m=25 block prove (peak RSS well above the 8 GB miner
    /// budget — a measurement artifact of holding four classes at once;
    /// run ALONE and watch RSS).
    #[test]
    #[ignore = "very heavy ladder measure; run explicitly, ONE at a time"]
    fn split_ladder_four_slot_freeze_measure() {
        use noid_ivc_core::challenger::FsLaneChallenger;
        use noid_ivc_core::pcs::{self, PcsParams};
        use noid_ivc_core::proof::FieldShape;
        use noid_ivc_core::zerocheck::K_SKIP;
        use noid_ivc_prover::field_prover::prove_field_with_public_io;
        use noid_recursive::acceptance::block_class::{build_block_proof_trace, BlockClass};
        use noid_recursive::acceptance::link::{LinkBlock, LinkEnvelope};
        use noid_recursive::acceptance::split_link::{LadderSlotInfo, SplitLinkClass};
        use noid_recursive::acceptance::trace::region_source_binding::RegionDischargeParams;
        use std::time::Instant;

        let shape = |m: usize| FieldShape {
            m,
            k_log: m,
            k_skip: K_SKIP,
            const_pin: Some(0),
        };
        let params = |m: usize| PcsParams {
            m: m + pcs::LOG_PACKING,
            log_inv_rate: 2,
            log_batch_size: 5,
            profile: Default::default(),
        };
        const ML: usize = 23;
        let rp = RegionDischargeParams { nq: 64 };
        // Ladder slots ascending; fixture blocks are non-increasing tx
        // counts, so slot t's sample is units[n_slots - 1 - t].
        let slots: [(usize, usize, usize); 4] =
            [(8, 22, 5), (32, 23, 17), (64, 24, 33), (255, 25, 129)];
        let counts: Vec<usize> = slots.iter().rev().map(|&(_, _, n)| n).collect();
        let units = chained_blocks_with_tx_counts(&counts);
        fn mk(u: &BlockUnit) -> LinkBlock<'_> {
            LinkBlock {
                start_accumulator: &u.start_accumulator,
                end_accumulator: &u.end_accumulator,
                inputs: &u.inputs,
                proof: &u.proof,
                config: Default::default(),
            }
        }

        // ---- Phase 1: per slot, freeze the block class and prove the
        // sample block (fills the class digest the ladder needs).
        let mut b_classes = Vec::new();
        let mut b_matrices = Vec::new();
        let mut b_envs = Vec::new();
        for (t, &(tier, mb, _)) in slots.iter().enumerate() {
            let unit = &units[slots.len() - 1 - t];
            let t0 = Instant::now();
            let class = BlockClass::freeze(shape(mb), params(mb), rp, &mk(unit), tier);
            eprintln!(
                "[ladder] B tier={tier} @m={mb}: frozen in {:.1?}",
                t0.elapsed()
            );
            let t0 = Instant::now();
            let built = build_block_proof_trace(&class, &mk(unit));
            assert!(
                built.r1cs.satisfies(&built.witness),
                "π_block trace unsatisfiable"
            );
            let mut ch = FsLaneChallenger::new(b"history-block-v0");
            let (proof, commitment, _) = prove_field_with_public_io(
                &built.r1cs,
                &built.witness,
                &class.pcs_params,
                &class.spec,
                &built.io,
                &mut ch,
            );
            eprintln!(
                "[ladder] B tier={tier} sample block build+prove: {:.1?}",
                t0.elapsed()
            );
            b_classes.push(class);
            b_matrices.push(built.r1cs);
            b_envs.push(LinkEnvelope {
                proof,
                commitment,
                io: built.io,
            });
        }

        // ---- Phase 2: the four link classes over the SAME ladder.
        let ladder: Vec<LadderSlotInfo> = slots
            .iter()
            .zip(&b_classes)
            .map(|(&(tier, mb, _), class)| LadderSlotInfo {
                tier,
                b_shape: shape(mb),
                b_digest: *class.class_statement_digest.get().unwrap(),
            })
            .collect();
        let genesis_acc = units[0].start_accumulator.clone();
        let mut links = Vec::new();
        for (t, &(tier, _, _)) in slots.iter().enumerate() {
            let t0 = Instant::now();
            let link = SplitLinkClass::freeze(
                shape(ML),
                params(ML),
                genesis_acc.clone(),
                ladder.clone(),
                t,
                &b_classes[t],
                &b_envs[t],
                &b_matrices[t],
            );
            eprintln!(
                "[ladder] L slot={t} (tier {tier}) @m={ML}: frozen in {:.1?} \
                 (io {}, {} claims, max_arity {})",
                t0.elapsed(),
                link.spec.io_len,
                link.region_claims.len(),
                link.region_max_arity,
            );
            links.push(link);
        }

        // ---- THE ladder invariant: one shape + one spec across every slot.
        for l in &links[1..] {
            assert_eq!(l.spec.io_len, links[0].spec.io_len, "shared spec io_len");
            assert_eq!(
                l.spec.io_slice.log2_len, links[0].spec.io_slice.log2_len,
                "shared spec slice"
            );
            assert_eq!(
                l.region_max_arity, links[0].region_max_arity,
                "shared walk max arity"
            );
            assert_eq!(
                l.region_claims.len(),
                links[0].region_claims.len(),
                "shared walk claim count"
            );
            for (a, b) in l.region_claims.iter().zip(&links[0].region_claims) {
                assert_eq!(a.slice, b.slice, "shared walk claim slice");
                assert_eq!(a.arity, b.arity, "shared walk claim arity");
            }
        }
        eprintln!("[ladder] ALL FOUR link classes share one spec — ladder invariant holds");
    }

    /// The SPLIT LINK cross-class chain (two-level π, Stage A part 2): two
    /// block classes on different ladder shapes (tier-32 @ m=23, tier-8 @
    /// m=22), two link classes sharing one shape+spec, and the real
    /// chain crossing classes — genesis link (slot hi, covering the tier-32
    /// block 1) → tip link (slot lo, covering the tier-8 block 2) — decided
    /// natively. Exercises: the whitelist-lane digest derivation (`w_D =
    /// Σ β·WL + g·D_T`), whitelist inheritance, the baked block digest +
    /// spec in [R]_B, the two fold twins with per-matrix lanes (link lane
    /// β-routing, block lane pass-through across slots, liveness monotone
    /// OR from a dead genesis), block-accumulator chaining across the two
    /// envelopes, per-class matrix fixity (throwaway vs real builds — the
    /// whitelist values are witness-only), and the split decider with its
    /// negatives (wrong whitelist refs, missing matrix on a live lane,
    /// wrong lane matrix, tampered lane IO, genesis tip).
    #[test]
    #[ignore = "heavy: six proves incl. four at the m=24 link shape"]
    fn split_link_cross_class_chain_e2e() {
        use noid_ivc_core::challenger::FsLaneChallenger;
        use noid_ivc_core::field::F128;
        use noid_ivc_core::pcs::{self, PcsParams};
        use noid_ivc_core::proof::FieldShape;
        use noid_ivc_core::zerocheck::K_SKIP;
        use noid_ivc_prover::field_prover::prove_field_with_public_io;
        use noid_recursive::acceptance::block_class::{build_block_proof_trace, BlockClass};
        use noid_recursive::acceptance::link::{genesis_witness, LinkBlock, LinkEnvelope};
        use noid_recursive::acceptance::split_link::{
            build_split_link, decide_tip_split, tip_block_accumulator_split, LadderSlotInfo,
            SplitLinkClass, SplitLinkInput,
        };
        use noid_recursive::acceptance::trace::region_source_binding::RegionDischargeParams;
        use std::time::Instant;

        let shape = |m: usize| FieldShape {
            m,
            k_log: m,
            k_skip: K_SKIP,
            const_pin: Some(0),
        };
        let params = |m: usize| PcsParams {
            m: m + pcs::LOG_PACKING,
            log_inv_rate: 2,
            log_batch_size: 5,
            profile: Default::default(),
        };
        const MB_LO: usize = 22; // the tier-8 block class shape
        const MB_HI: usize = 23; // the tier-32 block class shape (heterogeneity on purpose)
        const ML: usize = 23; // the link shape: two walk-dieted [R] replays
                              // PRODUCTION region density: the block classes discharge their
                              // wallet PCS at the full query count, so the block specs carry
                              // production-arity claims and the link's [R]_B sees real sizes.
        let rp = RegionDischargeParams { nq: 64 };

        // Block 1: 17 std txs (consensus tier 32); block 2: 5 std txs (tier 8).
        let units = chained_blocks_with_tx_counts(&[17, 5]);
        fn mk(u: &BlockUnit) -> LinkBlock<'_> {
            LinkBlock {
                start_accumulator: &u.start_accumulator,
                end_accumulator: &u.end_accumulator,
                inputs: &u.inputs,
                proof: &u.proof,
                config: Default::default(),
            }
        }

        // ---- Block classes + block proofs.
        let t0 = Instant::now();
        let b_hi = BlockClass::freeze(shape(MB_HI), params(MB_HI), rp, &mk(&units[0]), 32);
        let b_lo = BlockClass::freeze(shape(MB_LO), params(MB_LO), rp, &mk(&units[1]), 8);
        eprintln!("[split-e2e] block classes frozen: {:.1?}", t0.elapsed());
        let prove_block = |class: &BlockClass,
                           unit: &BlockUnit|
         -> (noid_ivc_core::field_r1cs::FieldR1cs, LinkEnvelope) {
            let built = build_block_proof_trace(class, &mk(unit));
            assert!(
                built.r1cs.satisfies(&built.witness),
                "π_block trace unsatisfiable"
            );
            let mut ch = FsLaneChallenger::new(b"history-block-v0");
            let (proof, commitment, _) = prove_field_with_public_io(
                &built.r1cs,
                &built.witness,
                &class.pcs_params,
                &class.spec,
                &built.io,
                &mut ch,
            );
            (
                built.r1cs,
                LinkEnvelope {
                    proof,
                    commitment,
                    io: built.io,
                },
            )
        };
        let t0 = Instant::now();
        let (b_hi_r1cs, env_block1) = prove_block(&b_hi, &units[0]);
        let (b_lo_r1cs, env_block2) = prove_block(&b_lo, &units[1]);
        eprintln!("[split-e2e] block proofs: {:.1?}", t0.elapsed());

        // ---- The ladder + the two link classes (shared shape and spec).
        let ladder = vec![
            LadderSlotInfo {
                tier: 8,
                b_shape: shape(MB_LO),
                b_digest: *b_lo.class_statement_digest.get().unwrap(),
            },
            LadderSlotInfo {
                tier: 32,
                b_shape: shape(MB_HI),
                b_digest: *b_hi.class_statement_digest.get().unwrap(),
            },
        ];
        let genesis_acc = units[0].start_accumulator.clone();
        let t0 = Instant::now();
        let l_lo = SplitLinkClass::freeze(
            shape(ML),
            params(ML),
            genesis_acc.clone(),
            ladder.clone(),
            0,
            &b_lo,
            &env_block2,
            &b_lo_r1cs,
        );
        let l_hi = SplitLinkClass::freeze(
            shape(ML),
            params(ML),
            genesis_acc,
            ladder,
            1,
            &b_hi,
            &env_block1,
            &b_hi_r1cs,
        );
        eprintln!("[split-e2e] link classes frozen: {:.1?}", t0.elapsed());
        assert!(!l_lo.region_claims.is_empty(), "frozen walk claims present");
        eprintln!(
            "[split-e2e] specs: b_lo io {} ({} claims, max_arity {}), b_hi io {} ({} claims, \
             max_arity {}), link io {} ({} claims, max_arity {})",
            b_lo.spec.io_len,
            b_lo.region_claims.len(),
            b_lo.region_max_arity,
            b_hi.spec.io_len,
            b_hi.region_claims.len(),
            b_hi.region_max_arity,
            l_lo.spec.io_len,
            l_lo.region_claims.len(),
            l_lo.region_max_arity,
        );
        assert_eq!(l_lo.spec.io_len, l_hi.spec.io_len, "shared spec io_len");
        assert_eq!(
            l_lo.spec.io_slice.log2_len, l_hi.spec.io_slice.log2_len,
            "shared spec slice"
        );

        // ---- The genesis dummy T: one proof serves both classes.
        let t0 = Instant::now();
        let t_witness = genesis_witness(&shape(ML));
        let t_io = vec![F128::ZERO; l_hi.spec.io_len];
        let mut ch = FsLaneChallenger::new(b"history-link-v0");
        let (t_proof, t_commitment, _) = prove_field_with_public_io(
            &l_hi.genesis,
            &t_witness,
            &l_hi.pcs_params,
            &l_hi.spec,
            &t_io,
            &mut ch,
        );
        let env_t = LinkEnvelope {
            proof: t_proof,
            commitment: t_commitment,
            io: t_io,
        };
        eprintln!("[split-e2e] T proof: {:.1?}", t0.elapsed());

        // ---- Throwaway builds derive the link-class digests (whitelist
        // values are WITNESS data — the matrices ignore them; per-class
        // fixity against the real builds asserts exactly that). A
        // non-genesis throwaway must still satisfy whitelist inheritance
        // and verify its predecessor against `WL[prev_slot]`, so the
        // derivation runs as a chain: zero-WL genesis (digest only) →
        // proven genesis carrying its own digest → the other class.
        let prove_link = |class: &SplitLinkClass,
                          r1cs: &noid_ivc_core::field_r1cs::FieldR1cs,
                          witness: &[F128],
                          io: Vec<F128>|
         -> LinkEnvelope {
            let mut ch = FsLaneChallenger::new(b"history-link-v0");
            let (proof, commitment, _) = prove_field_with_public_io(
                r1cs,
                witness,
                &class.pcs_params,
                &class.spec,
                &io,
                &mut ch,
            );
            LinkEnvelope {
                proof,
                commitment,
                io,
            }
        };
        let t0 = Instant::now();
        let tw0 = build_split_link(
            &l_hi,
            &SplitLinkInput {
                prev: &env_t,
                verified_digest: l_hi.genesis_digest,
                prev_slot: 0,
                genesis: true,
                link_class_digests: vec![[0u8; 32]; 2],
                block: &env_block1,
                fold_matrix_link: &l_hi.genesis,
                fold_matrix_block: &b_hi_r1cs,
            },
        );
        let d_l_hi = *l_hi.class_statement_digest.get().unwrap();
        let tw0_r1cs = tw0.r1cs;
        drop(tw0.witness);
        let tw1 = build_split_link(
            &l_hi,
            &SplitLinkInput {
                prev: &env_t,
                verified_digest: l_hi.genesis_digest,
                prev_slot: 0,
                genesis: true,
                link_class_digests: vec![[0u8; 32], d_l_hi],
                block: &env_block1,
                fold_matrix_link: &l_hi.genesis,
                fold_matrix_block: &b_hi_r1cs,
            },
        );
        assert_eq!(
            tw1.r1cs.statement_digest(),
            tw0_r1cs.statement_digest(),
            "L_hi matrix depends on whitelist values"
        );
        drop(tw0_r1cs);
        assert!(
            tw1.r1cs.satisfies(&tw1.witness),
            "throwaway genesis unsatisfiable"
        );
        let tw1_r1cs = tw1.r1cs;
        let env_tw1 = prove_link(&l_hi, &tw1_r1cs, &tw1.witness, tw1.io);
        drop(tw1.witness);
        let tw_l2 = build_split_link(
            &l_lo,
            &SplitLinkInput {
                prev: &env_tw1,
                verified_digest: d_l_hi,
                prev_slot: 1,
                genesis: false,
                link_class_digests: vec![[0u8; 32], d_l_hi],
                block: &env_block2,
                fold_matrix_link: &tw1_r1cs,
                fold_matrix_block: &b_lo_r1cs,
            },
        );
        let d_l_lo = *l_lo.class_statement_digest.get().unwrap();
        let tw_l2_r1cs = tw_l2.r1cs;
        drop(tw_l2.witness);
        drop(env_tw1);
        eprintln!("[split-e2e] digest derivation chain: {:.1?}", t0.elapsed());

        // ---- The real chain: genesis (slot hi) → tip (slot lo).
        let digests = vec![d_l_lo, d_l_hi];
        let t0 = Instant::now();
        let gen = build_split_link(
            &l_hi,
            &SplitLinkInput {
                prev: &env_t,
                verified_digest: l_hi.genesis_digest,
                prev_slot: 0,
                genesis: true,
                link_class_digests: digests.clone(),
                block: &env_block1,
                fold_matrix_link: &l_hi.genesis,
                fold_matrix_block: &b_hi_r1cs,
            },
        );
        assert_eq!(
            gen.r1cs.statement_digest(),
            tw1_r1cs.statement_digest(),
            "L_hi class fixity (throwaway vs real)"
        );
        assert!(
            gen.r1cs.a_0 == tw1_r1cs.a_0 && gen.r1cs.b_0 == tw1_r1cs.b_0,
            "L_hi matrices differ between throwaway and real build"
        );
        drop(tw1_r1cs);
        assert!(
            gen.r1cs.satisfies(&gen.witness),
            "genesis link unsatisfiable"
        );
        eprintln!(
            "[split-e2e] genesis link build+satisfies: {:.1?}",
            t0.elapsed()
        );
        let gen_r1cs = gen.r1cs;
        let tp = Instant::now();
        let env_gen = prove_link(&l_hi, &gen_r1cs, &gen.witness, gen.io);
        eprintln!(
            "[split-e2e] genesis link PROVE (m=23): {:.1?}",
            tp.elapsed()
        );
        drop(gen.witness);

        let t0 = Instant::now();
        let l2 = build_split_link(
            &l_lo,
            &SplitLinkInput {
                prev: &env_gen,
                verified_digest: d_l_hi,
                prev_slot: 1,
                genesis: false,
                link_class_digests: digests.clone(),
                block: &env_block2,
                fold_matrix_link: &gen_r1cs,
                fold_matrix_block: &b_lo_r1cs,
            },
        );
        assert_eq!(
            l2.r1cs.statement_digest(),
            tw_l2_r1cs.statement_digest(),
            "L_lo class fixity (throwaway vs real)"
        );
        assert!(
            l2.r1cs.a_0 == tw_l2_r1cs.a_0 && l2.r1cs.b_0 == tw_l2_r1cs.b_0,
            "L_lo matrices differ between throwaway and real build"
        );
        drop(tw_l2_r1cs);
        assert!(l2.r1cs.satisfies(&l2.witness), "tip link unsatisfiable");
        eprintln!("[split-e2e] tip link build+satisfies: {:.1?}", t0.elapsed());
        let l2_r1cs = l2.r1cs;
        let tp = Instant::now();
        let mut env_tip = prove_link(&l_lo, &l2_r1cs, &l2.witness, l2.io);
        eprintln!("[split-e2e] tip link PROVE (m=23): {:.1?}", tp.elapsed());
        drop(l2.witness);

        // ---- Lane liveness sanity: link lane hi live (the tip folded the
        // genesis link's claim), link lane lo dead (nobody verified an
        // L_lo proof yet), both block lanes live.
        let layout = l_lo.layout();
        assert_eq!(env_tip.io[layout.link_lanes[0].live], F128::ZERO);
        assert_eq!(env_tip.io[layout.link_lanes[1].live], F128::ONE);
        assert_eq!(env_tip.io[layout.b_lanes[0].live], F128::ONE);
        assert_eq!(env_tip.io[layout.b_lanes[1].live], F128::ONE);

        // ---- The decider accepts; the anchored accumulator is block 2's.
        decide_tip_split(
            &l_lo,
            &l2_r1cs,
            &env_tip,
            &digests,
            &[None, Some(&gen_r1cs)],
            &[Some(&b_lo_r1cs), Some(&b_hi_r1cs)],
        )
        .expect("split decider accepts the cross-class tip");
        let anchored = tip_block_accumulator_split(&l_lo, &env_tip);
        assert_eq!(anchored.height, units[1].end_accumulator.height);
        assert_eq!(anchored.state_root, units[1].end_accumulator.state_root);
        assert_eq!(anchored.chain_hash, units[1].end_accumulator.chain_hash);

        // ---- Decider negatives.
        // Wrong whitelist reference set (swapped digests).
        let swapped = vec![digests[1], digests[0]];
        assert!(
            decide_tip_split(
                &l_lo,
                &l2_r1cs,
                &env_tip,
                &swapped,
                &[None, Some(&gen_r1cs)],
                &[Some(&b_lo_r1cs), Some(&b_hi_r1cs)],
            )
            .is_err(),
            "swapped whitelist references slipped through"
        );
        // A live lane without its matrix.
        assert!(
            decide_tip_split(
                &l_lo,
                &l2_r1cs,
                &env_tip,
                &digests,
                &[None, None],
                &[Some(&b_lo_r1cs), Some(&b_hi_r1cs)],
            )
            .is_err(),
            "live link lane without its matrix slipped through"
        );
        // The wrong matrix on a live block lane (different shape: caught by
        // the lane-width guard).
        assert!(
            decide_tip_split(
                &l_lo,
                &l2_r1cs,
                &env_tip,
                &digests,
                &[None, Some(&gen_r1cs)],
                &[Some(&b_hi_r1cs), Some(&b_lo_r1cs)],
            )
            .is_err(),
            "swapped block matrices slipped through"
        );
        // The wrong matrix of the SAME shape on a live link lane (the tip
        // class instead of the genesis class): the claim must evaluate false.
        assert!(
            decide_tip_split(
                &l_lo,
                &l2_r1cs,
                &env_tip,
                &digests,
                &[None, Some(&l2_r1cs)],
                &[Some(&b_lo_r1cs), Some(&b_hi_r1cs)],
            )
            .is_err(),
            "wrong same-shape link matrix slipped through"
        );
        // Tampered lane IO: the tip proof itself must reject (IO is
        // PCS-bound). Flip, check, flip back (char 2).
        let tamper = layout.b_lanes[0].value;
        env_tip.io[tamper] += F128::ONE;
        assert!(
            decide_tip_split(
                &l_lo,
                &l2_r1cs,
                &env_tip,
                &digests,
                &[None, Some(&gen_r1cs)],
                &[Some(&b_lo_r1cs), Some(&b_hi_r1cs)],
            )
            .is_err(),
            "tampered lane IO slipped through"
        );
        env_tip.io[tamper] += F128::ONE;
        // A genesis link is not an acceptable tip.
        let genesis_verdict = decide_tip_split(
            &l_hi,
            &gen_r1cs,
            &env_gen,
            &digests,
            &[None, None],
            &[None, Some(&b_hi_r1cs)],
        );
        assert!(
            matches!(&genesis_verdict, Err(e) if e.contains("genesis")),
            "genesis tip verdict: {genesis_verdict:?}"
        );
    }

    /// Exact-state REGION parity on a REAL block (task 4b): build the complete
    /// block slots with wallet-PCS + owner-auth + exact-state ALL in the region
    /// and assert (a) the honest trace satisfies (every new cell pin — sponge
    /// absorbs, PAD constant, digest↔expected_leaf, path entries, leg roots —
    /// holds); (b) the sponge digest wires carry φ(native `slot_leaf_hash`) and
    /// the leg-root statement wires carry φ(the direct UTXO-root natives); (c)
    /// the inline path killshot wires are GONE in region mode; and (d) three
    /// one-flip NEGATIVES break satisfiability: a slot-leaf packed-value wire (bound
    /// to its walk-A absorb cell), an expected-leaf wire (the leaf↔path
    /// closure: its ONLY constraints in region mode are the sponge digest-cell
    /// pin and the state-leg entry-cell pin), and a child state-root wire (the
    /// path→header-root closure).
    #[test]
    fn region_exact_state_block_slots_parity_real_block() {
        use noid_chain::exact_state_hash::slot_leaf_hash;
        use noid_chain::fri_state::SlotValue;
        use noid_ivc_core::deep_chain::schedule::flat_of_tower_u128;
        use noid_ivc_core::field::F128;
        use noid_ivc_core::field_circuit::{FieldR1csBuilder, LinExpr};
        use noid_recursive::acceptance::block_slots::{
            build_block_slots_with_config, BlockSlotsConfig,
        };
        use noid_recursive::acceptance::trace::region_source_binding::RegionDischargeParams;

        let phi = |b: Block128| -> F128 { flat_of_tower_u128(b.0) };
        let wire_of = |e: &LinExpr| -> usize {
            assert_eq!(e.terms.len(), 1, "statement wire expected");
            e.terms[0].0 as usize
        };

        let units = chained_std_tx_blocks(1);
        let u = &units[0];
        let cfg = BlockSlotsConfig {
            discharge_wallet_pcs: true,
            wallet_pcs_params: RegionDischargeParams { nq: 2 },
            owner_auth_region: true,
            exact_state_region: true,
            tx_root_region: true,
            spine_region: true,
            tier_user_tx_capacity: None,
        };
        let mut b = FieldR1csBuilder::new();
        let slots = build_block_slots_with_config(
            &mut b,
            &u.start_accumulator,
            &u.end_accumulator,
            &u.inputs,
            &u.proof,
            cfg,
        );
        assert!(
            !slots.pending_wallet_pcs.is_empty(),
            "region claims present"
        );
        let (r1cs, z) = b.build();
        // This constructor checks the honest witness once and caches A·z/B·z;
        // each one-wire negative below then costs only the touched columns.
        let mut battery = r1cs.flip_battery(&z);

        // (b) sponge digest wires == φ(native slot_leaf_hash) — recomputed from
        // the killshot statement, not read back from the derived digest.
        let es_in = &u.inputs.exact_state_killshot_inputs[0];
        assert_eq!(slots.exact_state.slot_leaves.len(), es_in.slot_leaves.len());
        for (t, lw) in slots.exact_state.slot_leaves.iter().enumerate() {
            let native = &es_in.slot_leaves[t];
            let digest = slot_leaf_hash(SlotValue {
                value: native.packed_value,
                owner_hi: native.owner_hi,
                owner_lo: native.owner_lo,
            });
            let lanes = [
                Block128::from(u128::from_le_bytes(digest[..16].try_into().unwrap())),
                Block128::from(u128::from_le_bytes(digest[16..].try_into().unwrap())),
            ];
            for lane in 0..2 {
                assert_eq!(
                    lw.expected_leaf[lane].eval(&z),
                    phi(lanes[lane]),
                    "sponge digest wire {t}/{lane} != φ(slot_leaf_hash)"
                );
            }
        }
        // Leg roots == φ(the derived old/new path statement roots).
        let half = es_in.state_paths.len() / 2;
        for lane in 0..2 {
            assert_eq!(
                slots.exact_state.roots.old_root[lane].eval(&z),
                phi(es_in.state_paths[0].expected_root[lane]),
                "old state-root wire"
            );
            assert_eq!(
                slots.exact_state.roots.new_root[lane].eval(&z),
                phi(es_in.state_paths[half].expected_root[lane]),
                "new state-root wire"
            );
        }
        // (c) inline path slots are gone in region mode — exact-state AND
        // tx-root (its paths ride the walk-B TAG_COMPRESS leg).
        assert!(
            slots.exact_state.state_paths.is_empty(),
            "no inline state-path slot"
        );
        assert!(slots.tx_root_paths.is_empty(), "no inline tx-root slot");
        eprintln!(
            "[es-region] parity OK: {} wires, {} region claims, {} slot leaves",
            z.len(),
            slots.pending_wallet_pcs.len(),
            slots.exact_state.slot_leaves.len()
        );

        // (d) one-flip negatives.
        // 1. Slot-leaf packed-value wire: bound to the walk-A sponge absorb
        //    cell — the flip must be rejected.
        {
            let wire = wire_of(&slots.exact_state.slot_leaves[0].packed_value);
            assert!(!battery.survives_flip(wire), "flipped packed-value wire accepted");
        }
        // 2. Expected-leaf wire — THE leaf↔path closure: in region mode its only
        //    constraints are the sponge digest-cell pin and the state-leg
        //    entry-cell pin, so this isolates the new region binding.
        {
            let wire = wire_of(&slots.exact_state.slot_leaves[0].expected_leaf[0]);
            assert!(!battery.survives_flip(wire), "flipped expected-leaf wire accepted");
        }
        // 3. Child state-root wire — direct path→header-root closure.
        {
            let wire = wire_of(&slots.exact_state.roots.new_root[0]);
            assert!(
                !battery.survives_flip(wire),
                "flipped state-root wire accepted"
            );
        }
        // 4. Spine tx-hash wire — the tx-root leaf closure AND the spine wrap
        //    closure: bound to the walk-B tx-root leg's entry cell and to the
        //    walk-A wrap digest cell (region mode has no inline spine slot).
        {
            let wire = wire_of(&slots.tx_hashes[0][0]);
            assert!(!battery.survives_flip(wire), "flipped spine tx-hash wire accepted");
        }
        // 5. Header tx_root wire — the tx-root root closure (also bound by the
        //    header-hash killshot and the claim pins).
        {
            use noid_recursive::acceptance::block_slots::header_fields;
            let wire = wire_of(&slots.header.fields[header_fields::TX_ROOT]);
            assert!(
                !battery.survives_flip(wire),
                "flipped header tx_root wire accepted"
            );
        }
        // 6. Spine input payload lane — in region mode its ONLY hash binding is
        //    the walk-A tile absorb cell pin; the flip must be rejected there.
        {
            let wire = wire_of(&slots.spine_inputs[0].input_leaves[0][1]);
            assert!(!battery.survives_flip(wire), "flipped spine payload wire accepted");
        }
        // 7. Epoch-anchor lane — bound ONLY by the spine tree's KID leaf-cell
        //    pin (tree leaf L0) in region mode.
        {
            let wire = wire_of(&slots.spine_inputs[0].epoch_anchor[0]);
            assert!(!battery.survives_flip(wire), "flipped epoch-anchor wire accepted");
        }
        eprintln!("[es-region] all seven one-flip negatives rejected");
    }

    /// Multi-tx spine-region parity: a 2-user-tx block (k = 2 obligations,
    /// 2 spine instances — the fixture blocks carry no coinbase) exercises
    /// the CHUNKED spine layout end-to-end: per-block capacity 1, so tx
    /// block 0 carries instance 0 and tx block 1 carries instance 1, with
    /// all region flags on. (The capacity-2 + ghost-instance + instance-
    /// coordinate re-point path is gated separately in
    /// `region_spine_families_multitx_with_ghosts`.) The build must satisfy
    /// (every cell pin lands) and flipping a spine tx-hash wire must break
    /// the wrap-digest cell pin.
    #[test]
    fn region_spine_multitx_block_slots_parity() {
        use noid_ivc_core::field::F128;
        use noid_ivc_core::field_circuit::{FieldR1csBuilder, LinExpr};
        use noid_recursive::acceptance::block_slots::{
            build_block_slots_with_config, BlockSlotsConfig,
        };
        use noid_recursive::acceptance::trace::region_source_binding::RegionDischargeParams;

        let wire_of = |e: &LinExpr| -> usize {
            assert_eq!(e.terms.len(), 1, "statement wire expected");
            e.terms[0].0 as usize
        };
        let units = chained_multi_tx_blocks(1, 2);
        let u = &units[0];
        let cfg = BlockSlotsConfig {
            discharge_wallet_pcs: true,
            wallet_pcs_params: RegionDischargeParams { nq: 2 },
            owner_auth_region: true,
            exact_state_region: true,
            tx_root_region: true,
            spine_region: true,
            tier_user_tx_capacity: None,
        };
        let mut b = FieldR1csBuilder::new();
        let slots = build_block_slots_with_config(
            &mut b,
            &u.start_accumulator,
            &u.end_accumulator,
            &u.inputs,
            &u.proof,
            cfg,
        );
        assert_eq!(
            slots.tx_hashes.len(),
            2,
            "two user txs, no coinbase in the fixture"
        );
        let (r1cs, z) = b.build();
        assert!(
            r1cs.satisfies(&z),
            "multi-tx spine-region block slots must satisfy"
        );
        // The LAST tx's hash lives in tx block 1's chunk — its wrap-digest
        // cell pin must still bind it.
        let last = slots.tx_hashes.len() - 1;
        let mut bad = z.clone();
        bad[wire_of(&slots.tx_hashes[last][0])] += F128::ONE;
        assert!(
            !r1cs.satisfies(&bad),
            "flipped chunked spine tx-hash accepted"
        );
        eprintln!(
            "[spine-region] multitx parity OK: {} wires, {} claims, {} instances",
            z.len(),
            slots.pending_wallet_pcs.len(),
            slots.tx_hashes.len()
        );
    }

    /// MEMORY / SHAPE measurement for `BlockSlotsConfig::owner_auth_region`.
    /// Build the FULL complete block-bearing slots (region wallet-PCS discharge
    /// ON) at 1 std tx with owner-auth INLINE vs owner-auth REGION, and report
    /// each build's matrix `m` + wire count. This is the key number for the
    /// separate-vs-combined walk-C decision: if the region path stays at the same
    /// `m`, a standalone owner-auth walk-C fits alongside the wallet-PCS region
    /// discharge; if `m` grows, the combined `build_combined_duplex_union`
    /// primitive is needed. Also asserts BOTH builds satisfy and that the region
    /// path's wallet-PCS claim natives (the suffix of `pending_wallet_pcs`)
    /// exactly reproduce the inline path's (end-to-end obligation parity, the
    /// owner-auth walk-C claims being the added prefix). Heavy (two full
    /// block-slot builds, no proving); run explicitly and report.
    #[test]
    #[ignore = "measurement (two full block-slot builds); run explicitly to size owner-auth region"]
    fn region_owner_auth_full_block_memory_measure() {
        use noid_ivc_core::field_circuit::FieldR1csBuilder;
        use noid_recursive::acceptance::block_slots::{
            build_block_slots_with_config, region_wallet_pcs_native, BlockSlotsConfig,
        };
        use noid_recursive::acceptance::trace::region_source_binding::RegionDischargeParams;

        let region_params = RegionDischargeParams { nq: 2 };
        let units = chained_std_tx_blocks(1);
        let u = &units[0];

        let cfg_inline = BlockSlotsConfig {
            discharge_wallet_pcs: true,
            wallet_pcs_params: region_params,
            owner_auth_region: false,
            exact_state_region: false,
            tx_root_region: false,
            spine_region: false,
            tier_user_tx_capacity: None,
        };
        let cfg_region = BlockSlotsConfig {
            discharge_wallet_pcs: true,
            wallet_pcs_params: region_params,
            owner_auth_region: true,
            exact_state_region: false,
            tx_root_region: false,
            spine_region: false,
            tier_user_tx_capacity: None,
        };

        // Inline-owner-auth path: build, extract numbers + wallet-PCS claim
        // natives, then drop the (r, z) before the region build to cap peak RAM.
        let (m_inline, wires_inline, sat_inline, pcs_inline) = {
            let mut b = FieldR1csBuilder::new();
            let slots = build_block_slots_with_config(
                &mut b,
                &u.start_accumulator,
                &u.end_accumulator,
                &u.inputs,
                &u.proof,
                cfg_inline,
            );
            let pcs: Vec<_> = slots
                .pending_wallet_pcs
                .iter()
                .map(|c| (c.native_point.clone(), c.native_value))
                .collect();
            let nw = b.num_wires();
            let (r, z) = b.build();
            (r.m, nw, r.satisfies(&z), pcs)
        };
        eprintln!(
            "[owner-auth-region] INLINE owner-auth: m={m_inline} wires={wires_inline} sat={sat_inline} wallet_pcs_claims={}",
            pcs_inline.len()
        );

        // Region-owner-auth path (adds the owner-auth KSCHANNL walk-C).
        let (m_region, wires_region, sat_region, pcs_region_all) = {
            let mut b = FieldR1csBuilder::new();
            let slots = build_block_slots_with_config(
                &mut b,
                &u.start_accumulator,
                &u.end_accumulator,
                &u.inputs,
                &u.proof,
                cfg_region,
            );
            let all: Vec<_> = slots
                .pending_wallet_pcs
                .iter()
                .map(|c| (c.native_point.clone(), c.native_value))
                .collect();
            let nw = b.num_wires();
            let (r, z) = b.build();
            (r.m, nw, r.satisfies(&z), all)
        };
        let n_all = pcs_region_all.len();
        eprintln!(
            "[owner-auth-region] REGION owner-auth: m={m_region} wires={wires_region} sat={sat_region} total_claims={n_all}"
        );
        eprintln!(
            "[owner-auth-region] delta: m {m_inline} -> {m_region} ({}), wires {wires_inline} -> {wires_region} (+{})",
            if m_region == m_inline {
                "SAME class m (a standalone owner-auth walk-C fits)"
            } else {
                "m INCREASED (a combined duplex union may be needed)"
            },
            wires_region as i64 - wires_inline as i64,
        );

        assert!(
            sat_inline,
            "inline-owner-auth complete block must be satisfiable"
        );
        assert!(
            sat_region,
            "region-owner-auth complete block must be satisfiable"
        );

        // End-to-end parity: `pending_wallet_pcs` in the region path is
        // [owner-auth walk-C claims ... , wallet-PCS claims ...]; the wallet-PCS
        // SUFFIX must byte-match the inline path's wallet-PCS claims (identical
        // obligations -> identical wallet-PCS claims). The prefix is the owner-auth
        // transcript binding the region path adds.
        assert!(
            n_all > pcs_inline.len(),
            "region path must ADD owner-auth walk-C claims (got {n_all}, inline {})",
            pcs_inline.len()
        );
        let n_wallet = pcs_inline.len();
        let suffix = &pcs_region_all[n_all - n_wallet..];
        for (i, (sr, si)) in suffix.iter().zip(pcs_inline.iter()).enumerate() {
            assert_eq!(
                sr.0, si.0,
                "wallet-PCS claim {i} point drift (region vs inline)"
            );
            assert_eq!(
                sr.1, si.1,
                "wallet-PCS claim {i} value drift (region vs inline)"
            );
        }
        eprintln!(
            "[owner-auth-region] wallet-PCS suffix ({n_wallet} claims) parity OK; owner-auth added {} walk-C claims",
            n_all - n_wallet
        );

        // The link recovers the region IO envelope via `region_wallet_pcs_native`
        // (an auth-only scratch discharge) BEFORE the real trace allocates the IO
        // cells; its output MUST match the real build's `pending_wallet_pcs`
        // natives, in ORDER, for the owner-auth-region path too (the mirror). Gate
        // it directly against the real region build above.
        let scratch =
            region_wallet_pcs_native(&u.inputs, region_params, true, false, false, false, None);
        assert_eq!(
            scratch.len(),
            pcs_region_all.len(),
            "region_wallet_pcs_native(true) claim count must match the real region build"
        );
        for (i, (s, r)) in scratch.iter().zip(pcs_region_all.iter()).enumerate() {
            assert_eq!(
                s.0, r.0,
                "scratch-vs-real region claim {i} point drift (owner-auth region)"
            );
            assert_eq!(
                s.1, r.1,
                "scratch-vs-real region claim {i} value drift (owner-auth region)"
            );
        }
        eprintln!(
            "[owner-auth-region] region_wallet_pcs_native(true) == real build for {} claims (mirror OK)",
            scratch.len()
        );

        // Guard against an accidental blow-up (region walk-C discharges are
        // ~1M rows each; two in one build must stay bounded).
        assert!(
            m_region <= 24,
            "region owner-auth block-slot m exceeded 2^24 guard: {m_region}"
        );
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
            wallet_pcs_params:
                noid_recursive::acceptance::trace::region_source_binding::RegionDischargeParams {
                    nq: 2,
                },
            owner_auth_region: false,
            exact_state_region: false,
            tx_root_region: false,
            spine_region: false,
            tier_user_tx_capacity: None,
        };
        let layout = link_io_layout_for(shape.k_log, true);

        let units = chained_std_tx_blocks(3);
        let class =
            LinkClass::new_block_bearing(shape, params.clone(), units[0].start_accumulator.clone());

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
    /// Shared body of the COMPLETE region block-bearing recursion gate: freeze the
    /// class on `units[0]`, prove π₀ (a complete region block proof) + its negative
    /// (a tampered region committed column), then π₁ ⊳ π₀ (a regular link opening
    /// π₀'s region columns via `spec.claims`) + the decider + its negative.
    /// Parameterized over the block units (single-tx or multi-tx tier) and the
    /// discharge params, so the SAME logic gates every tier.
    ///
    /// `owner_auth_region` also verifies each block's owner-authorization
    /// killshots in the region (the transaction-count-flat KSCHANNL walk-C
    /// discharge): the frozen class then carries the owner-auth walk-C opening
    /// claims as a prefix in its region tail (a strictly larger, distinct class),
    /// so a COMPLETE region block proof has BOTH owner-auth and wallet-PCS flat.
    fn run_region_block_bearing_gate(
        units: &[BlockUnit],
        region_params: noid_recursive::acceptance::trace::region_source_binding::RegionDischargeParams,
        owner_auth_region: bool,
        exact_state_region: bool,
        tx_root_region: bool,
        spine_region: bool,
        tier_user_tx_capacity: Option<usize>,
    ) {
        use noid_ivc_core::challenger::FsLaneChallenger;
        use noid_ivc_core::field::F128;
        use noid_ivc_core::field_r1cs::FieldR1cs;
        use noid_ivc_core::pcs::{self, PcsParams};
        use noid_ivc_core::proof::FieldShape;
        use noid_ivc_core::verifier::verify_field_with_public_io;
        use noid_ivc_core::zerocheck::K_SKIP;
        use noid_ivc_prover::field_prover::prove_field_with_public_io;
        use noid_recursive::acceptance::block_slots::{region_wallet_pcs_native, BlockSlotsConfig};
        use noid_recursive::acceptance::link::{
            build_link, decide_tip, genesis_witness, link_io_layout_for, LinkBlock, LinkClass,
            LinkEnvelope, LinkInput,
        };
        use std::time::Instant;

        // A region link self-hosts at 2^24; this gate proves several 2^24
        // instances sequentially, so the caller keeps nq small to fit the
        // per-proof footprint (the discharge soundness/flatness are gated in
        // region_source_binding_full_e2e; here we test the IO threading + tier).
        const CLASS_M: usize = 24;
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
            wallet_pcs_params: region_params,
            owner_auth_region,
            exact_state_region,
            tx_root_region,
            spine_region,
            tier_user_tx_capacity,
        };

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
            owner_auth_region,
            exact_state_region,
            tx_root_region,
            spine_region,
            tier_user_tx_capacity,
        );
        eprintln!(
            "[region-link] class frozen in {:.1?}: owner_auth_region={owner_auth_region}, \
             region_claims={}, max_arity={}, io_len={}",
            t0.elapsed(),
            class.region_claims.len(),
            class.region_max_arity,
            class.spec.io_len,
        );
        assert!(!class.region_claims.is_empty());

        // Witness the owner-auth region delta CHEAPLY (no prove): the frozen
        // region tail grows over the wallet-PCS-only class by exactly the
        // owner-auth walk-C opening claims. `region_wallet_pcs_native` mirrors the
        // real build's `pending_wallet_pcs` for each mode, so its lengths are the
        // frozen claim counts. This also confirms the two classes are DISTINCT
        // (different claim count -> different IO layout -> different matrix).
        if owner_auth_region && tier_user_tx_capacity.is_none() {
            let lb = mk(&units[0], region_cfg);
            let wallet_only = region_wallet_pcs_native(
                lb.inputs,
                region_params,
                false,
                exact_state_region,
                tx_root_region,
                spine_region,
                None,
            )
            .len();
            let with_owner_auth = region_wallet_pcs_native(
                lb.inputs,
                region_params,
                true,
                exact_state_region,
                tx_root_region,
                spine_region,
                tier_user_tx_capacity,
            )
            .len();
            eprintln!(
                "[region-link] owner-auth region delta: wallet-PCS-only={wallet_only} claims, \
                 with-owner-auth={with_owner_auth} claims (+{} walk-C); frozen={}",
                with_owner_auth - wallet_only,
                class.region_claims.len(),
            );
            assert_eq!(
                with_owner_auth,
                class.region_claims.len(),
                "frozen region claim count must match the native mirror (owner-auth mode)"
            );
            assert!(
                with_owner_auth > wallet_only,
                "owner-auth region must ADD walk-C opening claims over the wallet-PCS-only class"
            );
        }

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

        // Separate an unsatisfiable trace (a bad block/region constraint at this
        // tier) from a PCS/opening failure -- checked before the expensive prove.
        assert!(
            class_r1cs.satisfies(&pi0_witness),
            "π₀ trace is unsatisfiable at this tier (a block/region constraint fails)"
        );

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
        if let Err(e) =
            verify_field_with_public_io(&class_r1cs, &c0, &p0, &class.spec, &pi0_io, &mut chv)
        {
            panic!("π₀ COMPLETE region block proof verify FAILED: {e:?}");
        }
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
        // Localize any link-level drift (block-slot matrix is class-fixed by
        // `region_block_slots_class_fixed_across_two_blocks`, so a link drift is
        // in the [R] replay or the region claim threading, not the discharge).
        if built1.r1cs.a_0 != class_r1cs.a_0 {
            let (m0, m1) = (&class_r1cs.a_0, &built1.r1cs.a_0);
            let mut n_diff = 0usize;
            let mut shown = 0usize;
            for r in 0..m0.num_rows {
                let r0: Vec<(u32, F128)> = m0.row(r).collect();
                let r1: Vec<(u32, F128)> = m1.row(r).collect();
                if r0 != r1 {
                    n_diff += 1;
                    if shown < 4 {
                        shown += 1;
                        use std::collections::BTreeMap;
                        let a: BTreeMap<u32, F128> = r0.iter().copied().collect();
                        let bb: BTreeMap<u32, F128> = r1.iter().copied().collect();
                        let mut cols: Vec<u32> = a.keys().chain(bb.keys()).copied().collect();
                        cols.sort_unstable();
                        cols.dedup();
                        eprintln!(
                            "[link-diff] A-row {r} ({} vs {} entries), k_log={}, useful_rows={}",
                            r0.len(),
                            r1.len(),
                            built1.r1cs.k_log,
                            built1.r1cs.useful_rows
                        );
                        for c in cols {
                            let (v0, v1) = (a.get(&c).copied(), bb.get(&c).copied());
                            if v0 != v1 {
                                eprintln!(
                                    "[link-diff]   col {c}: class={:?} pi1={:?}",
                                    v0.map(|v| (v.lo, v.hi)),
                                    v1.map(|v| (v.lo, v.hi)),
                                );
                            }
                        }
                    }
                }
            }
            eprintln!("[link-diff] TOTAL A-rows differing: {n_diff}");
        }
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

    /// COMPLETE region block-bearing recursion at the SINGLE-tx tier (1 std tx).
    #[test]
    #[ignore = "heavy (m=24, several 2^24 proofs + one class digest); run explicitly"]
    fn region_complete_block_bearing_link_e2e() {
        use noid_recursive::acceptance::trace::region_source_binding::RegionDischargeParams;
        let units = chained_std_tx_blocks(2);
        run_region_block_bearing_gate(
            &units,
            RegionDischargeParams { nq: 2 },
            false,
            false,
            false,
            false,
            None,
        );
    }

    /// COMPLETE region block-bearing recursion at a MULTI-tx tier (2 std txs per
    /// block): the whole block's wallet-PCS discharges in ONE tiled plural call
    /// (k=2 obligations) and the flat region claims thread through the link IO the
    /// same way -- proving block_slots -> plural(k>1) -> link -> recursion end to
    /// end. Same shared gate body as the single-tx tier; only the block units
    /// (carrying 2 authorization inputs each) differ.
    #[test]
    #[ignore = "heavy (m=24, several 2^24 proofs + one class digest); run explicitly"]
    fn region_complete_block_bearing_link_multitx_e2e() {
        use noid_recursive::acceptance::trace::region_source_binding::RegionDischargeParams;
        let units = chained_multi_tx_blocks(2, 2);
        run_region_block_bearing_gate(
            &units,
            RegionDischargeParams { nq: 2 },
            false,
            false,
            false,
            false,
            None,
        );
    }

    /// COMPLETE region block-bearing recursion with owner-auth ALSO discharged in
    /// the region (the transaction-count-flat KSCHANNL walk-C), at the single-tx
    /// tier. This is the [G] capability with owner-auth flat: π₀ is a COMPLETE
    /// block-bearing proof whose OWNER-AUTH and wallet-PCS are BOTH verified in
    /// the region, π₁ ⊳ π₀ opens π₀'s region columns (owner-auth walk-C claims
    /// first, then wallet-PCS) through the link IO, and the decider accepts the
    /// tip. Same shared gate body as `region_complete_block_bearing_link_e2e`;
    /// the ONLY difference is `owner_auth_region = true`, which grows the frozen
    /// region claim shape by the owner-auth walk-C claims — a DISTINCT, larger
    /// class (a different class matrix + digest than the wallet-PCS-only class).
    #[test]
    #[ignore = "heavy (m=24, several 2^24 proofs + one class digest); run explicitly"]
    fn region_complete_block_bearing_owner_auth_link_e2e() {
        use noid_recursive::acceptance::trace::region_source_binding::RegionDischargeParams;
        let units = chained_std_tx_blocks(2);
        run_region_block_bearing_gate(
            &units,
            RegionDischargeParams { nq: 2 },
            true,
            false,
            false,
            false,
            None,
        );
    }

    /// COMPLETE region block-bearing recursion with the EXACT-STATE hashing
    /// killshots ALSO discharged in the region (task 4b): slot leaves on the
    /// walk-A sponge tiles, state paths as one walk-B leg, owner-auth on
    /// walk C — every per-tx/per-slot-GROWING [K] hashing family flat. π₀ is a
    /// COMPLETE block-bearing proof whose owner-auth, wallet-PCS AND
    /// exact-state hashing are all region-verified; π₁ ⊳ π₀ opens π₀'s region
    /// columns through the link IO; the decider accepts. A DISTINCT, larger
    /// class than the owner-auth-only one (the walk-B exact-state leg adds
    /// frozen claims — a different class matrix + digest).
    #[test]
    #[ignore = "heavy (m=24, several 2^24 proofs + one class digest); run explicitly"]
    fn region_complete_block_bearing_exact_state_link_e2e() {
        use noid_recursive::acceptance::trace::region_source_binding::RegionDischargeParams;
        let units = chained_std_tx_blocks(2);
        run_region_block_bearing_gate(
            &units,
            RegionDischargeParams { nq: 2 },
            true,
            true,
            false,
            false,
            None,
        );
    }

    /// COMPLETE region block-bearing recursion with the TX-ROOT paths ALSO
    /// discharged in the region (task 4c): one TAG_COMPRESS walk-B leg per
    /// block (entries = the spine tx-hash wires, roots = the header tx_root
    /// wires, positions + padding rim const-cell-pinned), on top of
    /// owner-auth (walk C) and exact-state (walk A tiles + walk B legs) —
    /// EVERY per-tx-growing [K] hashing family now rides the region. π₀ is a
    /// COMPLETE block-bearing proof; π₁ ⊳ π₀; the decider accepts. A
    /// DISTINCT, larger class than the exact-state one (the tx-root leg adds
    /// frozen claims — a different class matrix + digest).
    #[test]
    #[ignore = "heavy (m=24, several 2^24 proofs + one class digest); run explicitly"]
    fn region_complete_block_bearing_tx_root_link_e2e() {
        use noid_recursive::acceptance::trace::region_source_binding::RegionDischargeParams;
        let units = chained_std_tx_blocks(2);
        run_region_block_bearing_gate(
            &units,
            RegionDischargeParams { nq: 2 },
            true,
            true,
            true,
            false,
            None,
        );
    }

    /// COMPLETE region block-bearing recursion with the TX-BODY SPINE ALSO
    /// discharged in the region (task 4e.2): every transaction's
    /// 59-permutation body hash rides walk A (the 32-slot leaf/wrap tile +
    /// the 64-slot compress tree with the gated internal-child exposure), on
    /// top of owner-auth (walk C), exact-state (walk A tiles + walk B legs)
    /// and tx-root (walk B leg) — the LAST per-tx-growing [K] hashing family
    /// moves off the inline replay. π₀ is a COMPLETE block-bearing proof;
    /// π₁ ⊳ π₀; the decider accepts. A DISTINCT, larger class than the
    /// tx-root one (the spine tiled exposure adds 4 frozen claims — a
    /// different class matrix + digest).
    #[test]
    #[ignore = "heavy (m=24, several 2^24 proofs + one class digest); run explicitly"]
    fn region_complete_block_bearing_spine_link_e2e() {
        use noid_recursive::acceptance::trace::region_source_binding::RegionDischargeParams;
        let units = chained_std_tx_blocks(2);
        run_region_block_bearing_gate(
            &units,
            RegionDischargeParams { nq: 2 },
            true,
            true,
            true,
            true,
            None,
        );
    }

    /// COMPLETE region block-bearing recursion AT TIER CAPACITY (task 4e.3):
    /// tier-8 blocks carrying 3 REAL user txs assemble with five ghost
    /// authorization slots, ghost spine instances, dead padded-tree
    /// leaves, per-slot liveness bits and liveness-derived count lanes — the
    /// tier-fixity machinery end to end through the link: π₀ COMPLETE at
    /// capacity, π₁ ⊳ π₀, decider + negatives. (Same-tier class identity
    /// across DIFFERENT real counts is gated by
    /// `region_tier_fixity_across_different_tx_counts`.)
    #[test]
    #[ignore = "heavy (m=24, several 2^24 proofs + one class digest); run explicitly"]
    fn region_complete_block_bearing_tier_capacity_link_e2e() {
        use noid_recursive::acceptance::trace::region_source_binding::RegionDischargeParams;
        let units = chained_multi_tx_blocks(2, 3);
        run_region_block_bearing_gate(
            &units,
            RegionDischargeParams { nq: 2 },
            true,
            true,
            true,
            true,
            Some(8),
        );
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
            wallet_pcs_params:
                noid_recursive::acceptance::trace::region_source_binding::RegionDischargeParams {
                    nq: 2,
                },
            owner_auth_region: false,
            exact_state_region: false,
            tx_root_region: false,
            spine_region: false,
            tier_user_tx_capacity: None,
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

        // With the wallet-PCS ON (the REGION discharge — the only mode since
        // the capsule regeometry), the FULL default-config block is also
        // class-fixed: the region discharge derives no matrix structure from
        // the proof's query positions. This assert used to be inverted (the
        // deleted inline replay drifted); the whole 1-tx block trace is now
        // one class matrix.
        let full0 = build(&units[0], BlockSlotsConfig::default(), "block 0 full");
        let full1 = build(&units[1], BlockSlotsConfig::default(), "block 1 full");
        let _ = build_block_slots; // keep the default-config entry point exercised elsewhere
        assert!(
            full0.a_0 == full1.a_0 && full0.b_0 == full1.b_0,
            "full block (region wallet-PCS) matrix drifted between two real blocks — \
             a position-derived value leaked into the class matrix"
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
        let accepted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
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
            rbad.satisfies(&zbad)
        }))
        .unwrap_or(false);
        assert!(
            !accepted,
            "XOR-passing wrong parent height (3 -> child 2) must be rejected by the incrementer"
        );
        eprintln!("[block-slots] integer height successor rejects the XOR-decrement attack");
    }

    /// C0 matrix-equality microfixture over the axes that are already legal
    /// before C': both blocks carry one Standard4x8 user transaction with two
    /// live inputs from ONE owner, one user output, and one coinbase output at
    /// the same state depth.  Owner, slot positions, amounts, roots, hashes,
    /// auth transcript and allocator-selected coinbase slot all differ.  None
    /// of those content values may enter the class matrix.
    ///
    /// This intentionally does not claim the full coinbase-only axis: the
    /// retained collector still omits its exact-state component (pinned by
    /// `full_batch_accepts_coinbase_only_block_without_detached_proof`).
    #[test]
    #[ignore = "C0 matrix diagnostic (two retained fixtures + two block-slot builds)"]
    fn c0_multi_input_coinbase_matrix_equality_on_legal_axes() {
        use noid_ivc_core::field_circuit::FieldR1csBuilder;
        use noid_ivc_core::field_r1cs::SparseFieldMatrix;
        use noid_recursive::acceptance::block_slots::{
            build_block_slots_with_config, BlockSlotsConfig,
        };
        use noid_recursive::acceptance::trace::region_source_binding::RegionDischargeParams;

        let unit0 = multi_input_coinbase_block_fixture(0);
        let unit1 = multi_input_coinbase_block_fixture(1);
        let config = BlockSlotsConfig {
            discharge_wallet_pcs: false,
            wallet_pcs_params: RegionDischargeParams { nq: 2 },
            owner_auth_region: false,
            exact_state_region: false,
            tx_root_region: false,
            spine_region: false,
            tier_user_tx_capacity: None,
        };
        let build = |unit: &BlockUnit, label: &str| {
            let mut b = FieldR1csBuilder::new();
            let _ = build_block_slots_with_config(
                &mut b,
                &unit.start_accumulator,
                &unit.end_accumulator,
                &unit.inputs,
                &unit.proof,
                config,
            );
            let (r1cs, z) = b.build();
            assert!(r1cs.satisfies(&z), "{label} satisfies");
            r1cs
        };
        let r0 = build(&unit0, "multi-input coinbase fixture 0");
        let r1 = build(&unit1, "multi-input coinbase fixture 1");

        let same_matrix_pair =
            |a0: &SparseFieldMatrix,
             b0: &SparseFieldMatrix,
             a1: &SparseFieldMatrix,
             b1: &SparseFieldMatrix| a0 == a1 && b0 == b1;
        assert_eq!(r0.m, r1.m, "class m drifted across content values");
        assert_eq!(r0.k_log, r1.k_log, "k_log drifted across content values");
        assert!(
            same_matrix_pair(&r0.a_0, &r0.b_0, &r1.a_0, &r1.b_0),
            "one-owner multi-input + coinbase class matrix drifted across legal content axes"
        );

        // Comparator negative: crossing the A/B matrix lanes must be detected.
        // This protects the diagnostic itself from a vacuous row-count-only
        // comparison while staying independent of the known coinbase-only gap.
        assert!(
            !same_matrix_pair(&r0.a_0, &r0.b_0, &r1.b_0, &r1.a_0),
            "matrix-drift diagnostic accepted crossed A/B lanes"
        );
    }

    /// Class-fixity gate for the REGION wallet-PCS discharge
    /// (`discharge_wallet_pcs`, region params). Two DIFFERENT real
    /// blocks of the same tier must assemble to a byte-identical FieldR1cs
    /// matrix — the recursion invariant a block-bearing link rests on. The
    /// region discharge derives its structure from the wallet proof's query
    /// positions; every position-derived value (a fold coset/parity, an
    /// index-selected codeword entry, an NTT fold twiddle) must be a witness
    /// bit, not a native constant baked into the matrix, or the shape drifts.
    /// This fast gate (two block-slot builds, NO proving) guards that without
    /// the heavy full-link prove in `region_complete_block_bearing_link_e2e`.
    /// On drift it prints the first divergent row/column to localize the leak.
    #[test]
    #[ignore = "heavy (two region-ON block-slot builds); run explicitly"]
    fn region_block_slots_class_fixed_across_two_blocks() {
        use noid_recursive::acceptance::block_slots::BlockSlotsConfig;
        use noid_recursive::acceptance::trace::region_source_binding::RegionDischargeParams;
        run_region_class_fixity_gate(BlockSlotsConfig {
            discharge_wallet_pcs: true,
            wallet_pcs_params: RegionDischargeParams { nq: 2 },
            owner_auth_region: false,
            exact_state_region: false,
            tx_root_region: false,
            spine_region: false,
            tier_user_tx_capacity: None,
        });
    }

    /// Class-fixity gate for the EXACT-STATE region discharge (task 4b): the
    /// same two-real-blocks matrix + claim-structure comparison with
    /// `exact_state_region = true`. The exact-state extension adds walk-A
    /// sponge tiles, one walk-B state-path leg and its cell pins whose STRUCTURE must
    /// be a pure function of (touched count, K, depths) — any block-content-
    /// derived index in a pin, pattern or claim point/value drifts here.
    #[test]
    #[ignore = "heavy (two region-ON block-slot builds); run explicitly"]
    fn region_exact_state_class_fixed_across_two_blocks() {
        use noid_recursive::acceptance::block_slots::BlockSlotsConfig;
        use noid_recursive::acceptance::trace::region_source_binding::RegionDischargeParams;
        run_region_class_fixity_gate(BlockSlotsConfig {
            discharge_wallet_pcs: true,
            wallet_pcs_params: RegionDischargeParams { nq: 2 },
            owner_auth_region: false,
            exact_state_region: true,
            tx_root_region: false,
            spine_region: false,
            tier_user_tx_capacity: None,
        });
    }

    /// Class-fixity gate for the TX-ROOT region leg (task 4c): the same
    /// two-real-blocks matrix + claim-structure comparison with
    /// `tx_root_region = true` (exact-state ON too — the production stack).
    /// The tx-root leg's direction/rim const pins and path layout must be a
    /// pure function of (tx count, depth, K) — any block-content-derived
    /// index in a pin or claim point/value drifts here.
    #[test]
    #[ignore = "heavy (two region-ON block-slot builds); run explicitly"]
    fn region_tx_root_class_fixed_across_two_blocks() {
        use noid_recursive::acceptance::block_slots::BlockSlotsConfig;
        use noid_recursive::acceptance::trace::region_source_binding::RegionDischargeParams;
        run_region_class_fixity_gate(BlockSlotsConfig {
            discharge_wallet_pcs: true,
            wallet_pcs_params: RegionDischargeParams { nq: 2 },
            owner_auth_region: false,
            exact_state_region: true,
            tx_root_region: true,
            spine_region: false,
            tier_user_tx_capacity: None,
        });
    }

    /// Class-fixity gate for the SPINE region families (task 4e.2): the same
    /// two-real-blocks matrix + claim-structure comparison with
    /// `spine_region = true` (exact-state + tx-root ON too — the production
    /// stack). The spine tile/tree layout, cell pins and the gated tiled
    /// exposure's re-point constants must be a pure function of
    /// (tx count, K) — any block-content-derived index drifts here.
    #[test]
    #[ignore = "heavy (two region-ON block-slot builds); run explicitly"]
    fn region_spine_class_fixed_across_two_blocks() {
        use noid_recursive::acceptance::block_slots::BlockSlotsConfig;
        use noid_recursive::acceptance::trace::region_source_binding::RegionDischargeParams;
        run_region_class_fixity_gate(BlockSlotsConfig {
            discharge_wallet_pcs: true,
            wallet_pcs_params: RegionDischargeParams { nq: 2 },
            owner_auth_region: false,
            exact_state_region: true,
            tx_root_region: true,
            spine_region: true,
            tier_user_tx_capacity: None,
        });
    }

    /// Tier-capacity parity (task 4e.3): a 3-real-user-tx block assembled at
    /// its consensus tier capacity 8 — five GHOST authorization slots (the
    /// protocol `ghost_authorization()`), ghost spine instances, dead
    /// padded-tree leaves — must satisfy, and the liveness machinery must
    /// reject one-flip tampering: a dead→live bit flip (breaks the
    /// USER_TX_COUNT liveness sum), a live→dead flip on a real slot (breaks
    /// monotonicity/sum), and a flipped ghost tx-hash wire (breaks the ghost
    /// spine wrap-digest cell pin).
    #[test]
    fn region_tier_capacity_block_slots_parity() {
        use noid_ivc_core::field::F128;
        use noid_ivc_core::field_circuit::{FieldR1csBuilder, LinExpr};
        use noid_recursive::acceptance::block_slots::{
            build_block_slots_with_config, BlockSlotsConfig,
        };
        use noid_recursive::acceptance::trace::region_source_binding::RegionDischargeParams;

        let wire_of = |e: &LinExpr| -> usize {
            assert_eq!(e.terms.len(), 1, "statement wire expected");
            e.terms[0].0 as usize
        };
        let units = chained_multi_tx_blocks(1, 3);
        let u = &units[0];
        let cfg = BlockSlotsConfig {
            discharge_wallet_pcs: true,
            wallet_pcs_params: RegionDischargeParams { nq: 2 },
            owner_auth_region: true,
            exact_state_region: true,
            tx_root_region: true,
            spine_region: true,
            tier_user_tx_capacity: Some(8),
        };
        let mut b = FieldR1csBuilder::new();
        let slots = build_block_slots_with_config(
            &mut b,
            &u.start_accumulator,
            &u.end_accumulator,
            &u.inputs,
            &u.proof,
            cfg,
        );
        assert_eq!(slots.tx_hashes.len(), 8, "capacity tx-hash vector");
        assert_eq!(slots.auth_inputs.len(), 8, "capacity auth slots");
        assert_eq!(slots.live_bits.len(), 8, "capacity liveness vector");
        let (r1cs, z) = b.build();
        assert!(r1cs.satisfies(&z), "tier-capacity block slots must satisfy");
        eprintln!(
            "[tier-cap] parity OK: {} wires, {} claims, 3 real + 5 ghost slots",
            z.len(),
            slots.pending_wallet_pcs.len()
        );

        // Negative 1: raise the ghost's liveness bit — the USER_TX_COUNT
        // liveness sum no longer matches the claim lane.
        {
            let mut bad = z.clone();
            bad[wire_of(&slots.live_bits[3])] += F128::ONE;
            assert!(!r1cs.satisfies(&bad), "raised ghost live bit accepted");
        }
        // Negative 2: kill a real slot's liveness bit — monotonicity and the
        // liveness sum both break.
        {
            let mut bad = z.clone();
            bad[wire_of(&slots.live_bits[0])] += F128::ONE;
            assert!(!r1cs.satisfies(&bad), "killed real live bit accepted");
        }
        // Negative 3: flip the ghost tx-hash wire — the ghost spine wrap
        // digest cell pin breaks.
        {
            let mut bad = z.clone();
            bad[wire_of(&slots.tx_hashes[3][0])] += F128::ONE;
            assert!(!r1cs.satisfies(&bad), "flipped ghost tx-hash accepted");
        }
        eprintln!("[tier-cap] all three liveness negatives rejected");
    }

    /// THE 4e money gate: two blocks of the SAME consensus tier (standard
    /// tier 8) with DIFFERENT real user-tx counts (3 vs 4) assemble at tier
    /// capacity to ONE class — byte-identical matrices and identical claim
    /// structures. The 3-real block carries one ghost authorization slot,
    /// one ghost spine instance and one dead padded-tree leaf; every
    /// count that reaches the claim lanes is liveness-gated, so no real
    /// count leaks into the matrix.
    #[test]
    #[ignore = "heavy (two region-ON tier-capacity block-slot builds); run explicitly"]
    fn region_tier_fixity_across_different_tx_counts() {
        use noid_recursive::acceptance::block_slots::BlockSlotsConfig;
        use noid_recursive::acceptance::trace::region_source_binding::RegionDischargeParams;
        let a = chained_multi_tx_blocks(1, 3);
        let b = chained_multi_tx_blocks(1, 4);
        run_region_class_fixity_gate_on(
            &a[0],
            &b[0],
            BlockSlotsConfig {
                discharge_wallet_pcs: true,
                wallet_pcs_params: RegionDischargeParams { nq: 2 },
                owner_auth_region: true,
                exact_state_region: true,
                tx_root_region: true,
                spine_region: true,
                tier_user_tx_capacity: Some(8),
            },
        );
    }

    /// Shared body of the region class-fixity gates: two DIFFERENT real blocks
    /// of the same tier, built with `region_cfg`, must produce byte-identical
    /// matrices AND identical claim `(slice, point, value)` structure.
    fn run_region_class_fixity_gate(
        region_cfg: noid_recursive::acceptance::block_slots::BlockSlotsConfig,
    ) {
        let units = chained_std_tx_blocks(2);
        run_region_class_fixity_gate_on(&units[0], &units[1], region_cfg);
    }

    /// [`run_region_class_fixity_gate`] over two caller-supplied blocks (the
    /// tier-fixity money gate compares blocks with DIFFERENT real tx counts).
    fn run_region_class_fixity_gate_on(
        unit0: &BlockUnit,
        unit1: &BlockUnit,
        region_cfg: noid_recursive::acceptance::block_slots::BlockSlotsConfig,
    ) {
        use noid_ivc_core::field::F128;
        use noid_ivc_core::field_circuit::{FieldR1csBuilder, LinExpr};
        use noid_recursive::acceptance::block_slots::build_block_slots_with_config;
        // Each claim's point/value must be class-fixed too — they are NOT part
        // of the block-slot matrix (they are pinned to the IO tail only in the
        // link), so a claim whose point/value LinExpr references a
        // block-dependent WIRE passes the matrix check yet drifts the LINK.
        #[allow(clippy::type_complexity)]
        let build =
            |u: &BlockUnit, label: &str| -> (_, Vec<(usize, usize, Vec<LinExpr>, LinExpr)>) {
                let mut b = FieldR1csBuilder::new();
                let slots = build_block_slots_with_config(
                    &mut b,
                    &u.start_accumulator,
                    &u.end_accumulator,
                    &u.inputs,
                    &u.proof,
                    region_cfg,
                );
                let claims: Vec<(usize, usize, Vec<LinExpr>, LinExpr)> = slots
                    .pending_wallet_pcs
                    .iter()
                    .map(|c| {
                        (
                            c.slice.start(),
                            c.slice.len(),
                            c.point.clone(),
                            c.value.clone(),
                        )
                    })
                    .collect();
                let (r, z) = b.build();
                assert!(r.satisfies(&z), "{label} satisfies");
                (r, claims)
            };

        let (r0, claims0) = build(unit0, "block 0 region-ON");
        let (r1, claims1) = build(unit1, "block 1 region-ON");

        // Claim STRUCTURE + point/value wire references must be class-fixed.
        assert_eq!(claims0.len(), claims1.len(), "region claim count drifted");
        for (ci, (c0, c1)) in claims0.iter().zip(claims1.iter()).enumerate() {
            if c0 != c1 {
                eprintln!("[region-claim-diff] claim {ci} drifts:");
                eprintln!(
                    "[region-claim-diff]   slice: {:?} vs {:?}",
                    (c0.0, c0.1),
                    (c1.0, c1.1)
                );
                for (k, (p0, p1)) in c0.2.iter().zip(c1.2.iter()).enumerate() {
                    if p0 != p1 {
                        eprintln!(
                            "[region-claim-diff]   point[{k}]: {:?} vs {:?}",
                            p0.terms, p1.terms
                        );
                    }
                }
                if c0.3 != c1.3 {
                    eprintln!(
                        "[region-claim-diff]   value: {:?} vs {:?}",
                        c0.3.terms, c1.3.terms
                    );
                }
                panic!("region wallet-PCS claim {ci} point/value drifted between blocks");
            }
        }
        assert_eq!(r0.k_log, r1.k_log, "k_log drifted");
        assert_eq!(r0.a_0.num_rows, r1.a_0.num_rows, "row count drifted");

        // On drift, localize the first divergent row/column before failing.
        let localize = |m0: &noid_ivc_core::field_r1cs::SparseFieldMatrix,
                        m1: &noid_ivc_core::field_r1cs::SparseFieldMatrix,
                        which: &str| {
            for r in 0..m0.num_rows {
                let row0: Vec<(u32, F128)> = m0.row(r).collect();
                let row1: Vec<(u32, F128)> = m1.row(r).collect();
                if row0 != row1 {
                    use std::collections::BTreeMap;
                    let a: BTreeMap<u32, F128> = row0.iter().copied().collect();
                    let bb: BTreeMap<u32, F128> = row1.iter().copied().collect();
                    let mut cols: Vec<u32> = a.keys().chain(bb.keys()).copied().collect();
                    cols.sort_unstable();
                    cols.dedup();
                    for c in cols {
                        let (v0, v1) = (a.get(&c).copied(), bb.get(&c).copied());
                        if v0 != v1 {
                            panic!(
                                "{which} matrix drifted at row {r} col {c}: \
                                 block0={:?} block1={:?} (a position-derived value leaked \
                                 into the class matrix — see region_source_binding)",
                                v0.map(|v| (v.lo, v.hi)),
                                v1.map(|v| (v.lo, v.hi)),
                            );
                        }
                    }
                }
            }
        };
        if r0.a_0 != r1.a_0 {
            localize(&r0.a_0, &r1.a_0, "A");
        }
        if r0.b_0 != r1.b_0 {
            localize(&r0.b_0, &r1.b_0, "B");
        }
    }

    /// The [B] block-slot assembly gate: the single-block component
    /// verifier, replayed as a FieldR1cs trace, is satisfied by the honest
    /// witness, its cross-component pins survive a full flip battery
    /// (0 surviving mutants beyond the pin-helper class), and every
    /// statement-anchor corruption breaks it — the assembled trace binds
    /// the same relation the native verifier checks.
    ///
    /// The wallet-PCS discharge is OFF here: the region discharge (the only
    /// mode) binds its committed columns through link-IO opening claims, not
    /// block-local R1CS rows, so a block-local flip battery cannot see them
    /// — its mutation coverage lives in the dedicated region gates
    /// (`region_source_binding_full_e2e` / `..._multitx_e2e`, which check
    /// the claims through the actual PCS).
    #[test]
    fn block_slots_assembly_matches_native_and_rejects_mutations() {
        use noid_ivc_core::field_circuit::FieldR1csBuilder;
        use noid_recursive::acceptance::block_slots::{
            build_block_slots_with_config, BlockSlotsConfig,
        };
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

        // Trace assembly of the same batch (wallet-PCS off — see the doc).
        let no_pcs = BlockSlotsConfig {
            discharge_wallet_pcs: false,
            ..BlockSlotsConfig::default()
        };
        let mut b = FieldR1csBuilder::new();
        let slots = build_block_slots_with_config(
            &mut b,
            &start_accumulator,
            end_accumulator,
            inputs,
            &proof,
            no_pcs,
        );
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
        // Pin helpers reject a witness-known false equality eagerly in debug
        // builds; optimized builders may instead materialize an unsatisfied
        // row. Both are valid rejection modes for this semantic negative.
        let rejected = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut b2 = FieldR1csBuilder::new();
            let _ = build_block_slots_with_config(
                &mut b2,
                &start_accumulator,
                &bad_end,
                inputs,
                &proof,
                no_pcs,
            );
            let (r1cs2, z2) = b2.build();
            !r1cs2.satisfies(&z2)
        }))
        .unwrap_or(true);
        assert!(
            rejected,
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
            active_slot_count: parent.active_slot_count,
            alloc_counter: parent.alloc_counter,
        };
        let block = coinbase_only_child(&parent, &state);
        let child_state_root = block.header.state_root;
        assert_eq!(block.transactions.len(), 1, "one real coinbase body");
        assert!(block.transactions[0].body.is_coinbase);
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
        assert_eq!(out.end_state.cached_state_root(), child_state_root);
        assert_ne!(
            child_state_root, parent.state_root,
            "coinbase mint changes state"
        );
        assert_eq!(
            out.proof_components
                .component_inputs
                .accepted_claim_witness
                .headers
                .len(),
            1
        );
        assert_eq!(
            out.proof_components
                .component_inputs
                .accepted_block_certificate_statements
                .len(),
            1
        );
        assert_eq!(
            accepted_block_certificate_chain_claim(
                &out.proof_components
                    .component_inputs
                    .accepted_block_certificate_statements[0]
            ),
            out.proof_components
                .component_inputs
                .accepted_claim_witness
                .accepted_block_claims[0]
        );
        assert_ne!(
            crate::accepted_block_certificate_statement_digest(
                &out.proof_components
                    .component_inputs
                    .accepted_block_certificate_statements[0]
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
            &out.proof_components
                .component_inputs
                .accepted_block_certificate_statements[0],
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
        assert_eq!(
            out.proof_components
                .component_inputs
                .header_integer_trace
                .steps
                .len(),
            1
        );
        assert_eq!(
            out.proof_components.component_inputs.tx_root_inputs.len(),
            1
        );
        assert_eq!(
            out.proof_components
                .component_inputs
                .tx_body_standard_inputs
                .len(),
            1,
            "coinbase reaches the spine component"
        );
        // C0 diagnostic: native validation has a real one-mint exact-state
        // surface, but the retained component collector currently appends an
        // exact-state input only inside `has_user_txs`.  `build_block_slots`
        // requires exactly one, so coinbase-only cannot join the class
        // matrix yet.  Keep this assertion explicit instead of calling an
        // empty block a coinbase fixture and hiding the structural gap.
        assert!(
            out.proof_components
                .component_inputs
                .exact_state_killshot_inputs
                .is_empty(),
            "known C' blocker changed: update the coinbase-only matrix gate"
        );
        assert_eq!(
            out.proof_components
                .component_inputs
                .authorization_totals
                .user_tx_count,
            0
        );
        assert_eq!(
            out.proof_components
                .component_inputs
                .authorization_totals
                .owner_count_total,
            0
        );
        assert_eq!(
            out.proof_components
                .component_inputs
                .authorization_totals
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
            active_slot_count: parent.active_slot_count,
            alloc_counter: parent.alloc_counter,
        };
        let block_state = state.clone();
        let block = coinbase_only_child(&parent, &block_state);
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
            &out.proof_components
                .component_inputs
                .accepted_block_certificate_statements[0],
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
            active_slot_count: parent.active_slot_count,
            alloc_counter: parent.alloc_counter,
        };
        let block_state = state.clone();
        let block = coinbase_only_child(&parent, &block_state);
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
            active_slot_count: start_consensus.active_slot_count,
            alloc_counter: start_consensus.alloc_counter,
        };
        let mut original_parent_state = state.clone();
        let original_parent = parent_header(&mut original_parent_state);
        let block_state = state.clone();
        let block = coinbase_only_child(&original_parent, &block_state);
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
        assert_eq!(
            out.proof_components
                .component_inputs
                .accepted_claim_witness
                .headers
                .len(),
            1
        );
        assert_eq!(
            out.proof_components
                .component_inputs
                .accepted_block_certificate_statements
                .len(),
            1
        );
        let certificate_statement = &out
            .proof_components
            .component_inputs
            .accepted_block_certificate_statements[0];
        assert_eq!(certificate_statement.user_tx_count, 1);
        assert_eq!(certificate_statement.live_input_count, 1);
        assert_eq!(
            certificate_statement.touched_slot_count, 3,
            "one user spend, one user output, and the mandatory coinbase output"
        );
        assert_eq!(
            accepted_block_certificate_chain_claim(certificate_statement),
            out.proof_components
                .component_inputs
                .accepted_claim_witness
                .accepted_block_claims[0]
        );
        assert_eq!(
            out.proof_components
                .component_inputs
                .header_integer_trace
                .steps
                .len(),
            1
        );
        assert_eq!(
            out.proof_components
                .component_inputs
                .tx_body_standard_inputs
                .len(),
            2,
            "coinbase and user body both reach the spine component"
        );
        assert_eq!(
            out.proof_components
                .component_inputs
                .tx_body_standard_hashes
                .len(),
            2
        );
        assert!(out
            .proof_components
            .component_inputs
            .tx_body_sweep_inputs
            .is_empty());
        assert!(out
            .proof_components
            .component_inputs
            .tx_body_sweep_hashes
            .is_empty());
        assert!(!out
            .proof_components
            .component_inputs
            .tx_root_inputs
            .is_empty());
        assert_eq!(
            out.proof_components
                .component_inputs
                .exact_state_killshot_inputs
                .len(),
            1
        );
        assert_eq!(
            out.proof_components
                .component_inputs
                .authorization_totals
                .user_tx_count,
            1
        );
        assert_eq!(
            out.proof_components
                .component_inputs
                .authorization_totals
                .owner_count_total,
            1
        );
        assert_eq!(
            out.proof_components
                .component_inputs
                .authorization_totals
                .live_input_count_total,
            1
        );
        let exact_inputs = &out
            .proof_components
            .component_inputs
            .exact_state_killshot_inputs[0];
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
        bad_components
            .component_inputs
            .accepted_block_certificate_statements[0]
            .child_state_root = [0x44; 32];
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
        bad_components
            .component_inputs
            .authorization_totals
            .owner_count_total += 1;
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
