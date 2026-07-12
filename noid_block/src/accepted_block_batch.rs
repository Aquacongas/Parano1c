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
use noid_chain::segmented_state::ExactStateReadError;
use noid_chain::state::ChainState;
use noid_core::{Block128, TowerField};
use noid_gkr::{
    prove_accepted_claim_hash_killshot, prove_batched_merkle_killshot, prove_block_spine_killshot,
    reconstruct_slot_states, spine_inputs_from_body, AcceptedClaimHashInputs,
    AcceptedClaimHashProofKillShot, BatchedMerkleProofKillShot, BlockSpineMle, BlockSpineProof,
    MerkleCircuit, MerklePathInputs, SpineCircuit, SpineInputs, MAX_MERKLE_DEPTH,
};
use noid_poseidon2b::native::compress;
use noid_poseidon2b::primitives::Digest;
use noid_recursive::block_certificate_backend::{
    verify_accepted_block_batch_components_selected_zk as verify_recursive_accepted_block_batch_components,
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
    verify_accepted_claim_batch_with_header_trace, verify_history_checkpoint_step_proof_checkpoint,
    verify_history_checkpoint_step_proof_private_components_native,
    verify_pow_header_witness_batch_native, AcceptedBlockCertificateProof,
    AcceptedBlockCertificateProofError, AcceptedBlockCertificateReceipt,
    AcceptedBlockCertificateReceiptError, AcceptedBlockReceiptProjectionHandle,
    AcceptedBlockReceiptProjectionHandleError, AcceptedClaimBatchError, AcceptedClaimBatchOutput,
    AcceptedClaimBatchWitness, BlockProofAcceptanceReceipt, ChainAccumulator,
    ChainAccumulatorAdvanceError, CheckpointPoseidonError, CheckpointPoseidonProof,
    HeaderIntegerTraceError, HeaderWitness, HistoryCheckpointBatchSummary, HistoryCheckpointHead,
    HistoryCheckpointProof, HistoryCheckpointProofError, HistoryCheckpointStepProof,
    HistoryCheckpointStepProofError, HistoryCheckpointStepStatement, PowHeaderBatchError,
    RecursiveConsensusState, HISTORY_CHECKPOINT_BATCH_TARGET_BLOCKS,
};

use crate::validate::map_verify_authorization_error;
use crate::{
    accept_block_timeless_with_artifacts_with_auth_verifier,
    accepted_block_certificate_batch_statement, accepted_block_certificate_chain_claim,
    accepted_block_claim_fields_from_transcript, accepted_block_claim_from_transcript,
    accepted_block_post_validation_bundle, AcceptedBlockCertificateBatchError,
    AcceptedBlockCertificateBatchStatement, AcceptedBlockCertificateRecord, AuthorizationProof,
    AuthorizationVerifier, BlockAuthSidecar, BlockProof, CanonicalAuthorizationStatement,
    ExactStateKillShotError, ExactStateKillShotProof, FullValidationError, VerifiedAuthorization,
    VerifiedAuthorizationBatch, VerifyBlockError,
};
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

#[derive(Debug, Clone)]
pub struct FullAcceptedBlockBatchProofComponents {
    /// Everything the dependency-clean component verifier consumes, in its
    /// own (shared) type — no mirror structs, no per-verify conversion.
    pub component_inputs: RecursiveBlockBatchComponentInputs,
    /// Canonical selected-ZK proofs in the same order as
    /// `component_inputs.authorization_inputs`. The B255 production builder
    /// consumes this vector; it is intentionally outside the legacy recursive
    /// component DTO and never serde-decoded without the bounded sidecar
    /// codec.
    pub selected_authorization_proofs: Vec<noid_gkr::zk_authorization::ZkAuthorizationProof>,
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
    if !accumulator_matches_anchor(base_accumulator, base_anchor) {
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
    AccumulatorAdvance {
        index: usize,
        source: ChainAccumulatorAdvanceError,
    },
    HeaderAnchor {
        index: usize,
        source: HeaderChainAnchorError,
    },
    ExactStateComponent {
        index: usize,
        source: ExactStateKillShotError,
    },
    ExactStateRead {
        index: usize,
        source: ExactStateReadError,
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

/// `AcceptBlock` authorization verifier that captures each selected-ZK public
/// statement after complete native verification. The production recursive
/// carrier consumes the already decoded proof separately, so no legacy
/// KillShot trace is synthesized or replayed.
#[derive(Default)]
struct TracingOwnerAuthVerifier {
    captured: Mutex<Vec<CanonicalAuthorizationStatement>>,
}

impl TracingOwnerAuthVerifier {
    /// Captured statements in user-tx order. The capture order is
    /// nondeterministic (the accept path verifies per-tx proofs in parallel).
    fn into_captured_ordered(self) -> Vec<CanonicalAuthorizationStatement> {
        let mut captured = self
            .captured
            .into_inner()
            .expect("owner-auth trace mutex poisoned");
        captured.sort_by_key(|statement| statement.tx_index);
        captured
    }
}

impl AuthorizationVerifier for TracingOwnerAuthVerifier {
    fn verify(
        &self,
        statement: &CanonicalAuthorizationStatement,
        proof: &AuthorizationProof,
    ) -> Result<VerifiedAuthorization, VerifyBlockError> {
        let verified = noid_gkr::verify_authorization_statement_proof(statement, proof)
            .map_err(|error| map_verify_authorization_error(error, statement.tx_index))?;
        self.captured
            .lock()
            .expect("owner-auth trace mutex poisoned")
            .push(statement.clone());
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
        || start_accumulator.height != start_parent.height
        || start_accumulator.tip_block_id != hash_block_header(start_parent)
        || start_accumulator.state_root != start_parent.state_root
        || start_accumulator.log_slots != start_parent.log_slots
        || start_accumulator.active_slot_count != start_parent.active_slot_count
        || start_accumulator.alloc_counter != start_parent.alloc_counter
    {
        return Err(FullAcceptedBlockBatchError::StartParentMismatch);
    }

    let mut state = start_state.clone();
    if state.state_root() != start_consensus.state_root {
        return Err(FullAcceptedBlockBatchError::StartStateRootMismatch);
    }

    let mut parent = start_parent.clone();
    let mut rolling_accumulator = start_accumulator.clone();
    let mut rolling_consensus = start_consensus.clone();
    let mut header_witnesses = Vec::with_capacity(witness.items.len());
    let mut accepted_block_claims = Vec::with_capacity(witness.items.len());
    let mut accepted_block_acceptance_receipts = Vec::with_capacity(witness.items.len());
    let mut accepted_block_certificate_statements = Vec::with_capacity(witness.items.len());
    let mut accepted_claim_hash_inputs = Vec::with_capacity(witness.items.len());
    let mut tx_body_inputs = Vec::new();
    let mut tx_body_hashes = Vec::new();
    let mut tx_root_inputs = Vec::new();
    let mut authorization_inputs = Vec::new();
    let authorization_witnesses = Vec::new();
    let authorization_traces = Vec::new();
    let mut selected_authorization_proofs = Vec::new();
    let mut exact_state_killshot_inputs = Vec::new();
    let mut exact_state_structural_inputs = Vec::new();
    let mut authorization_totals = VerifiedAuthorizationBatch {
        user_tx_count: 0,
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
        let tx_epoch = crate::BlockTxEpochContext {
            expected_user_epoch_anchor_id: rolling_accumulator.epoch_anchor_id,
        };

        let has_user_txs = item
            .block
            .transactions
            .iter()
            .any(|tx| !tx.body.is_coinbase);
        let (proof, sidecar) = if has_user_txs {
            let proof = bincode::deserialize::<BlockProof>(&item.block_proof_bytes)
                .map_err(|_| FullAcceptedBlockBatchError::DecodeProof { index })?;
            let sidecar = BlockAuthSidecar::from_bytes(&item.block_auth_sidecar_bytes)
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
            &tx_epoch,
            &anchor,
            &mut state,
            &auth_tracer,
        )
        .map_err(|source| FullAcceptedBlockBatchError::FullValidation { index, source })?;

        // The acceptance receipt and the history claim share one canonical
        // resource/context transcript.  Build the bundle before consuming the
        // proof-facing artifacts below, then reuse its transcript for the
        // retained accepted-claim component.
        let post_validation = accepted_block_post_validation_bundle(
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
        let transcript = post_validation.accepted_claim_transcript;
        let acceptance_receipt = post_validation.acceptance_receipt;

        let artifacts = validation.artifacts;
        if has_user_txs {
            let captured_auth = auth_tracer.into_captured_ordered();
            if captured_auth.len() != sidecar.tx_auth.len()
                || captured_auth.len() != artifacts.authorization.user_tx_count
            {
                return Err(FullAcceptedBlockBatchError::ComponentShapeMismatch);
            }
            for (statement, auth_proof) in
                captured_auth.into_iter().zip(sidecar.tx_auth.into_iter())
            {
                authorization_inputs.push(AuthorizationComponentInput {
                    block_index: index,
                    tx_index: statement.tx_index,
                    tx_body_hash: statement.tx_body_hash,
                    live_input_count: statement.live_input_count,
                    public: statement.public,
                });
                // The decoded retained sidecar has no later consumer; transfer
                // proof ownership into the selected recursive carrier without
                // cloning or fabricating a legacy proof trace.
                selected_authorization_proofs.push(auth_proof);
            }
            authorization_totals.user_tx_count = authorization_totals
                .user_tx_count
                .saturating_add(artifacts.authorization.user_tx_count);
            authorization_totals.live_input_count_total = authorization_totals
                .live_input_count_total
                .saturating_add(artifacts.authorization.live_input_count_total);
        }

        let coinbase_state_transition = if has_user_txs {
            None
        } else {
            // A multiproof frontier contains only subtrees disjoint from every
            // touched leaf, so its siblings are identical in the accepted old
            // and new states. Rebuild them from the already-applied child cache;
            // the common derivation below then independently reconstructs and
            // checks both roots against the sealed native transition.
            let cache = state
                .exact_sparse_cache()
                .map_err(|source| FullAcceptedBlockBatchError::ExactStateRead { index, source })?;
            if cache.depth() != artifacts.exact_state_inputs.child_log_slots {
                return Err(FullAcceptedBlockBatchError::ExactStateComponent {
                    index,
                    source: ExactStateKillShotError::ExactState(
                        crate::ExactStateTransitionError::InvalidLogSlots,
                    ),
                });
            }
            Some(
                crate::build_exact_state_transition_proof(&cache, &artifacts.exact_action_surface)
                    .map_err(|source| FullAcceptedBlockBatchError::ExactStateComponent {
                        index,
                        source: source.into(),
                    })?,
            )
        };
        let state_transition = proof
            .map(|proof| proof.state_transition)
            .or(coinbase_state_transition)
            .expect("every accepted block has a detached or reconstructed exact-state proof");
        let verified_roots = match artifacts.verified_exact_state_roots {
            Some(roots) => roots,
            None if !has_user_txs => crate::exact_state_transition::verify_exact_state_roots(
                &artifacts.exact_state_inputs,
                &artifacts.exact_action_surface,
                &state_transition,
            )
            .map_err(|source| FullAcceptedBlockBatchError::ExactStateComponent {
                index,
                source: source.into(),
            })?,
            None => return Err(FullAcceptedBlockBatchError::ComponentShapeMismatch),
        };
        let (inputs, structural_inputs) =
            crate::exact_state_killshot::derive_retained_exact_state_inputs_from_verified_roots(
                &artifacts.exact_state_inputs,
                artifacts.exact_action_surface,
                state_transition,
                verified_roots,
            )
            .map_err(|source| FullAcceptedBlockBatchError::ExactStateComponent { index, source })?;
        exact_state_killshot_inputs.push(inputs);
        exact_state_structural_inputs.push(structural_inputs);
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
        // Derive every body hash once, then reuse the same accepted leaves for
        // both the body-spine claims and the fixed Merkle256 paths.  Re-hashing
        // the full retained body independently in both component builders is
        // pure duplicate work and creates avoidable peak-temporary pressure.
        let item_tx_body_hashes = canonical_tx_body_hashes(&item.block);
        tx_root_inputs.extend(
            tx_root_merkle_inputs(&item.block, &item_tx_body_hashes)
                .map_err(|_| FullAcceptedBlockBatchError::TxRootComponent)?,
        );
        extend_tx_body_hash_component_inputs(
            &item.block,
            &item_tx_body_hashes,
            &mut tx_body_inputs,
            &mut tx_body_hashes,
        )?;

        let header_witness = HeaderWitness::from_header(&item.block.header);
        rolling_consensus =
            verify_pow_header_witness_batch_native(&rolling_consensus, &[header_witness.clone()])
                .map_err(|source| FullAcceptedBlockBatchError::HeaderWork { index, source })?;
        header_witnesses.push(header_witness);
        accepted_block_claims.push(claim);
        accepted_block_acceptance_receipts.push(acceptance_receipt);
        accepted_block_certificate_statements.push(certificate_statement);
        rolling_accumulator = rolling_accumulator
            .advance(&item.block.header)
            .map_err(|source| FullAcceptedBlockBatchError::AccumulatorAdvance { index, source })?;
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
    if accepted_claim_batch.accumulator != rolling_accumulator {
        return Err(FullAcceptedBlockBatchError::ComponentShapeMismatch);
    }

    Ok(FullAcceptedBlockBatchOutput {
        accepted_claim_batch,
        end_state: state,
        proof_components: FullAcceptedBlockBatchProofComponents {
            component_inputs: RecursiveBlockBatchComponentInputs {
                accepted_claim_witness,
                accepted_block_certificate_statements,
                accepted_claim_hash_inputs,
                tx_body_inputs,
                tx_body_hashes,
                tx_root_inputs,
                header_integer_trace,
                authorization_inputs,
                authorization_witnesses,
                authorization_traces,
                exact_state_killshot_inputs,
                exact_state_structural_inputs,
                authorization_totals,
            },
            selected_authorization_proofs,
            accepted_block_acceptance_receipts,
            accepted_block_certificate_proofs,
            accepted_block_certificate_receipts,
            accepted_block_receipt_projection_handles,
        },
    })
}

pub(crate) fn prove_full_accepted_block_batch_components(
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
    validate_selected_authorization_carrier(components)?;
    let exact_state_count = components
        .component_inputs
        .exact_state_structural_inputs
        .len();
    if exact_state_count
        != components
            .component_inputs
            .accepted_claim_witness
            .headers
            .len()
        || components
            .component_inputs
            .exact_state_killshot_inputs
            .len()
            != exact_state_count
    {
        return Err(FullAcceptedBlockBatchError::ComponentShapeMismatch);
    }
    validate_tx_body_component_shape(components)?;

    // The default keeps independent components parallel for latency. The B255
    // feasibility harness can force a serialized schedule to measure component
    // peaks independently. This is an execution policy only; proof bytes and
    // verification are identical.
    if std::env::var_os("NOID_SERIAL_COMPONENT_PROOFS").is_some() {
        let accepted_claim_hash = measure_component_proof("accepted-claim", || {
            let mut channel = noid_poseidon2b::channel::Poseidon2bChannel::new();
            Ok(prove_accepted_claim_hash_killshot(
                &components.component_inputs.accepted_claim_hash_inputs,
                &mut channel,
            )
            .0)
        })?;
        let tx_body =
            measure_component_proof("tx-body-spine", || prove_tx_body_component(components))?;
        let tx_root = measure_component_proof("tx-root", || prove_tx_root_component(components))?;
        let checkpoint_poseidon = measure_component_proof("checkpoint-poseidon", || {
            prove_checkpoint_poseidon(&components.component_inputs.accepted_claim_witness)
                .map_err(FullAcceptedBlockBatchError::CheckpointPoseidon)
        })?;
        let exact_state =
            measure_component_proof("exact-state", || prove_exact_state_components(components))?;
        return Ok(RetainedFullAcceptedBlockBatchProof {
            accepted_claim_hash,
            tx_body,
            tx_root,
            checkpoint_poseidon,
            exact_state,
        });
    }

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
            Option<BatchedMerkleProofKillShot>,
            CheckpointPoseidonProof,
            Vec<ExactStateKillShotProof>,
        ),
        FullAcceptedBlockBatchError,
    > {
        let (tx_body, (tx_root, (checkpoint_poseidon, exact_state))) = rayon::join(
                || prove_tx_body_component(components),
                || {
                    rayon::join(
                        || prove_tx_root_component(components),
                        || {
                            rayon::join(
                                || {
                                    prove_checkpoint_poseidon(
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
            tx_body?,
            tx_root?,
            checkpoint_poseidon?,
            exact_state?,
        ))
    };

    let (accepted_claim_hash, rest) = rayon::join(claim_result, rest_result);
    let accepted_claim_hash = accepted_claim_hash?;
    let (tx_body, tx_root, checkpoint_poseidon, exact_state) = rest?;

    Ok(RetainedFullAcceptedBlockBatchProof {
        accepted_claim_hash,
        tx_body,
        tx_root,
        checkpoint_poseidon,
        exact_state,
    })
}

fn measure_component_proof<T>(
    label: &str,
    prove: impl FnOnce() -> Result<T, FullAcceptedBlockBatchError>,
) -> Result<T, FullAcceptedBlockBatchError> {
    let profile = std::env::var_os("NOID_COMPONENT_LEDGER").is_some();
    let before = profile
        .then(noid_core::mem_profile::current_mem_snapshot)
        .flatten();
    let started = std::time::Instant::now();
    let result = prove();
    if profile {
        let elapsed = started.elapsed();
        let after = noid_core::mem_profile::current_mem_snapshot();
        match (before, after) {
            (Some(before), Some(after)) => eprintln!(
                "[component-ledger] {label}: {:.3}s, RSS {:.1}->{:.1} MiB, HWM {:.1}->{:.1} MiB",
                elapsed.as_secs_f64(),
                before.rss_mb(),
                after.rss_mb(),
                before.hwm_mb(),
                after.hwm_mb(),
            ),
            _ => eprintln!(
                "[component-ledger] {label}: {:.3}s, RSS unavailable",
                elapsed.as_secs_f64()
            ),
        }
    }
    result
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
    let proof = prove_full_accepted_block_batch_components(&output.proof_components)?;
    Ok((output, proof))
}

/// Verifies retained semantic blocks and detached witnesses, then verifies the
/// proof components derived from that same retained batch.
///
/// This is not a public O(1) history verifier: callers must still provide the
/// retained block bodies, block proofs, auth sidecars, start parent, and start
/// state so the timeless `AcceptBlock` relation can be replayed exactly. It is
/// a retained-package audit boundary, not an additional per-block suffix-sync
/// step: suffix sync runs the native acceptance predicate once, while prefix
/// sync verifies the recursive checkpoint proof.
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
        || !accumulator_matches_anchor(start_accumulator, start_anchor)
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
        accumulator = accumulator
            .advance(header)
            .map_err(|source| FullAcceptedBlockBatchError::AccumulatorAdvance { index, source })?;
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
        || !accumulator_matches_anchor(&accumulator, end_anchor)
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
        || !accumulator_matches_anchor(start_accumulator, start_anchor)
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
        || !accumulator_matches_anchor(&output.accepted_claim_batch.accumulator, &rolling_anchor)
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
    validate_selected_authorization_carrier(components)?;
    verify_recursive_accepted_block_batch_components(
        start_consensus,
        start_accumulator,
        end_accumulator,
        &components.component_inputs,
        proof,
    )
    .map_err(map_recursive_component_error)
}

fn validate_selected_authorization_carrier(
    components: &FullAcceptedBlockBatchProofComponents,
) -> Result<(), FullAcceptedBlockBatchError> {
    if !components
        .component_inputs
        .authorization_witnesses
        .is_empty()
        || !components.component_inputs.authorization_traces.is_empty()
        || components.component_inputs.authorization_inputs.len()
            != components.selected_authorization_proofs.len()
    {
        return Err(FullAcceptedBlockBatchError::ComponentShapeMismatch);
    }
    Ok(())
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

fn accumulator_matches_anchor(accumulator: &ChainAccumulator, anchor: &HeaderChainAnchor) -> bool {
    accumulator.height == anchor.height
        && accumulator.tip_block_id == anchor.block_id
        && accumulator.state_root == anchor.state_root
        && accumulator.log_slots == anchor.log_slots
        && accumulator.active_slot_count == anchor.active_slot_count
        && accumulator.alloc_counter == anchor.alloc_counter
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
        .exact_state_structural_inputs
        .par_iter()
        .zip(
            components
                .component_inputs
                .exact_state_killshot_inputs
                .par_iter(),
        )
        .enumerate()
        .map(|(index, (structural, legacy))| {
            let mut proof =
                crate::prove_exact_state_structural_killshot(structural).map_err(|source| {
                    FullAcceptedBlockBatchError::ExactStateComponent { index, source }
                })?;
            if !legacy.state_paths.is_empty() {
                if legacy.state_paths.len()
                    > crate::exact_state_killshot::TRANSITIONAL_INLINE_EXACT_STATE_MAX_PATHS
                {
                    return Err(FullAcceptedBlockBatchError::ComponentShapeMismatch);
                }
                proof.state_paths =
                    crate::exact_state_killshot::prove_transitional_exact_state_path_chunks(legacy)
                        .map_err(|source| FullAcceptedBlockBatchError::ExactStateComponent {
                            index,
                            source,
                        })?;
            }
            Ok(proof)
        })
        .collect()
}

fn validate_tx_body_component_shape(
    components: &FullAcceptedBlockBatchProofComponents,
) -> Result<(), FullAcceptedBlockBatchError> {
    if components.component_inputs.tx_body_inputs.len()
        != components.component_inputs.tx_body_hashes.len()
    {
        return Err(FullAcceptedBlockBatchError::ComponentShapeMismatch);
    }
    Ok(())
}

fn extend_tx_body_hash_component_inputs(
    block: &Block,
    body_hashes: &[[u8; 32]],
    inputs: &mut Vec<SpineInputs>,
    hashes: &mut Vec<[Block128; 2]>,
) -> Result<(), FullAcceptedBlockBatchError> {
    if body_hashes.len() != block.transactions.len() {
        return Err(FullAcceptedBlockBatchError::ComponentShapeMismatch);
    }
    for (tx, hash) in block.transactions.iter().zip(body_hashes) {
        inputs.push(spine_inputs_from_body(&tx.body));
        hashes.push(digest_to_fields(*hash));
    }
    Ok(())
}

fn canonical_tx_body_hashes(block: &Block) -> Vec<[u8; 32]> {
    block.transactions.iter().map(|tx| tx.txid().0).collect()
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

fn prove_tx_body_component(
    components: &FullAcceptedBlockBatchProofComponents,
) -> Result<Option<BlockSpineProof>, FullAcceptedBlockBatchError> {
    if components.component_inputs.tx_body_inputs.is_empty() {
        return Ok(None);
    }
    let slot_state_ins = tx_body_slot_state_ins(&components.component_inputs.tx_body_inputs);
    let mle = BlockSpineMle::build(
        components.component_inputs.tx_body_inputs.len(),
        &slot_state_ins,
    );
    let mut channel = noid_poseidon2b::channel::Poseidon2bChannel::new();
    Ok(Some(
        prove_block_spine_killshot(
            components.component_inputs.tx_body_inputs.len(),
            &mle,
            &components.component_inputs.tx_body_hashes,
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

fn tx_root_merkle_inputs(
    block: &Block,
    body_hashes: &[[u8; 32]],
) -> Result<Vec<MerklePathInputs>, ()> {
    if body_hashes.len() != block.transactions.len() {
        return Err(());
    }
    if block.transactions.is_empty() {
        return if block.header.tx_root == [0u8; 32] {
            Ok(Vec::new())
        } else {
            Err(())
        };
    }

    let target = noid_chain::tx_tree::TX_TREE_LEAVES;
    let depth = noid_chain::tx_tree::TX_TREE_DEPTH;
    if block.transactions.len() > target || depth > MAX_MERKLE_DEPTH {
        return Err(());
    }

    let mut levels = Vec::new();
    let mut level = body_hashes.to_vec();
    level.resize(target, [0u8; 32]);
    levels.push(level.clone());
    while level.len() > 1 {
        level = level
            .chunks_exact(2)
            .map(|pair| compress(&pair[0], &pair[1]))
            .collect();
        levels.push(level.clone());
    }

    let merkle_root = levels
        .last()
        .and_then(|level| level.first())
        .copied()
        .ok_or(())?;
    if noid_chain::tx_tree::bind_tx_count(merkle_root, body_hashes.len()) != block.header.tx_root {
        return Err(());
    }

    // Paths prove the fixed Merkle256 root M. The recursive block boundary
    // separately applies TAG_TXROOT(M, real_count) before pinning the header.
    let expected_root = digest_to_fields(merkle_root);
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
    use noid_poseidon2b::primitives::Address;
    use noid_tx::{
        output_bitmap_bit, Transaction, TxBody, TxInput, TxOutput, TX_INPUTS, TX_OUTPUTS,
    };

    fn header(height: u64, transactions: &[Transaction]) -> BlockHeader {
        BlockHeader {
            prev_block_hash: [height as u8; 32],
            state_root: [0x11; 32],
            tx_root: compute_tx_root(transactions),
            timestamp: 1_767_225_600 + height,
            height,
            miner_address: Address([0x22; 32]),
            nonce: height as u128,
            difficulty_target: [0xff; 32],
            log_slots: 24,
            active_slot_count: 0,
            alloc_counter: 0,
        }
    }

    fn transaction(index: usize, is_coinbase: bool) -> Transaction {
        let mut inputs = [TxInput::dummy(); TX_INPUTS];
        let mut outputs = [TxOutput::dummy(); TX_OUTPUTS];
        let owner = Address([(index as u8).wrapping_add(1); 32]);
        let validity_bitmap = if is_coinbase {
            outputs[0] = TxOutput {
                slot_index: index as u32,
                amount: 50,
                owner,
            };
            output_bitmap_bit(0)
        } else {
            inputs[0] = TxInput {
                slot_index: index as u32,
                amount: 10,
                creation_id: index as u64,
            };
            outputs[0] = TxOutput {
                slot_index: (index + 256) as u32,
                amount: 10,
                owner,
            };
            1 | output_bitmap_bit(0)
        };
        Transaction::new(TxBody {
            epoch_anchor: [index as u8; 32],
            fee: 0,
            input_owner: if is_coinbase { Address([0; 32]) } else { owner },
            inputs,
            outputs,
            validity_bitmap,
            is_coinbase,
        })
    }

    fn merkle_256_root(transactions: &[Transaction]) -> [u8; 32] {
        let mut layer = vec![[0u8; 32]; noid_chain::tx_tree::TX_TREE_LEAVES];
        for (leaf, tx) in layer.iter_mut().zip(transactions) {
            *leaf = tx.txid().0;
        }
        while layer.len() > 1 {
            layer = layer
                .chunks_exact(2)
                .map(|pair| compress(&pair[0], &pair[1]))
                .collect();
        }
        layer[0]
    }

    #[test]
    fn tx_root_component_proves_fixed_merkle_256_then_header_wraps_count() {
        let transactions = vec![transaction(0, true), transaction(1, false)];
        let block = Block {
            header: header(1, &transactions),
            transactions,
        };
        let body_hashes = canonical_tx_body_hashes(&block);
        let inputs = tx_root_merkle_inputs(&block, &body_hashes).unwrap();
        let merkle_root = merkle_256_root(&block.transactions);

        assert_eq!(inputs.len(), 2);
        assert!(inputs
            .iter()
            .all(|input| input.active_depth == noid_chain::tx_tree::TX_TREE_DEPTH));
        assert!(inputs
            .iter()
            .all(|input| input.expected_root == digest_to_fields(merkle_root)));
        assert_ne!(block.header.tx_root, merkle_root);
        assert!(!inputs[0].directions[0]);
        assert!(inputs[1].directions[0]);
        assert!(inputs[0].directions[noid_chain::tx_tree::TX_TREE_DEPTH..]
            .iter()
            .all(|direction| !direction));
    }

    #[test]
    fn tier_255_has_256_fixed_depth_paths() {
        let mut transactions = Vec::with_capacity(256);
        transactions.push(transaction(0, true));
        transactions.extend((1..=255).map(|index| transaction(index, false)));
        let block = Block {
            header: header(144, &transactions),
            transactions,
        };

        let body_hashes = canonical_tx_body_hashes(&block);
        let inputs = tx_root_merkle_inputs(&block, &body_hashes).unwrap();
        assert_eq!(inputs.len(), 256);
        assert!(inputs.iter().all(|input| input.active_depth == 8));
        assert!(inputs[255].directions[..8]
            .iter()
            .all(|direction| *direction));
    }

    #[test]
    fn tx_body_component_uses_one_final_spine_per_transaction() {
        let transactions = vec![
            transaction(0, true),
            transaction(1, false),
            transaction(2, false),
        ];
        let block = Block {
            header: header(1, &transactions),
            transactions,
        };
        let mut inputs = Vec::new();
        let mut hashes = Vec::new();
        let body_hashes = canonical_tx_body_hashes(&block);
        extend_tx_body_hash_component_inputs(&block, &body_hashes, &mut inputs, &mut hashes)
            .unwrap();

        assert_eq!(inputs.len(), block.transactions.len());
        assert_eq!(hashes.len(), block.transactions.len());
        assert_eq!(
            hashes,
            block
                .transactions
                .iter()
                .map(|tx| tx.txid().as_fields())
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn coinbase_only_retained_proof_has_one_exact_state_component_and_verifies() {
        let parent = noid_chain::consensus::genesis_header();
        let state = ChainState::with_log_slots(parent.log_slots as usize);
        assert_eq!(state.cached_state_root(), parent.state_root);

        let genesis_work = noid_chain::consensus::block_work(&parent.difficulty_target);
        let start_consensus = RecursiveConsensusState::from_header(
            &parent,
            genesis_work,
            0,
            parent.timestamp,
            parent.difficulty_target,
            &[parent.timestamp],
            &[parent.active_slot_count],
        );
        let start_accumulator = noid_recursive::genesis_accumulator();
        let timestamp = parent
            .timestamp
            .checked_add(noid_chain::consensus::params::BLOCK_TIME)
            .unwrap();
        let difficulty_target = noid_chain::consensus::next_target(
            start_consensus.asert_anchor_height,
            start_consensus.asert_anchor_timestamp,
            &start_consensus.asert_anchor_target,
            parent.height + 1,
            timestamp,
        );
        let template = noid_chain::consensus::build_block_template(
            &parent,
            &state,
            start_consensus.active_counts(),
            Vec::new(),
            Address([0xC1; 32]),
            timestamp,
            difficulty_target,
        )
        .unwrap();
        let transactions = template.all_txs();
        let mut child = template.into_header(0);
        child.nonce = noid_chain::consensus::pow::search_pow(&child, 0, 5_000_000)
            .expect("easy canonical test target mines within the fixed range");
        let witness = FullAcceptedBlockBatchWitness {
            items: vec![FullAcceptedBlockBatchItem {
                block: Block {
                    header: child,
                    transactions,
                },
                block_proof_bytes: Vec::new(),
                block_auth_sidecar_bytes: Vec::new(),
            }],
        };

        let (output, proof) = prove_retained_full_accepted_block_batch_proof(
            &start_consensus,
            &start_accumulator,
            &parent,
            &state,
            &witness,
        )
        .unwrap();
        assert_eq!(
            output
                .proof_components
                .component_inputs
                .exact_state_killshot_inputs
                .len(),
            1
        );
        assert_eq!(
            output
                .proof_components
                .component_inputs
                .exact_state_structural_inputs
                .len(),
            1
        );
        assert_eq!(proof.exact_state.len(), 1);
        let legacy = &output
            .proof_components
            .component_inputs
            .exact_state_killshot_inputs[0];
        assert_eq!(legacy.slot_leaves.len(), 2);
        assert_eq!(legacy.state_paths.len(), 2);
        assert_eq!(proof.exact_state[0].state_paths.len(), 1);

        let verified = verify_retained_full_accepted_block_batch_proof(
            &start_consensus,
            &start_accumulator,
            &parent,
            &state,
            &witness,
            &proof,
        )
        .unwrap();
        assert_eq!(
            verified.end_state.cached_state_root(),
            output.end_state.cached_state_root()
        );
    }

    #[test]
    fn tx_root_component_rejects_header_mismatch_and_nonzero_empty_root() {
        let transactions = vec![transaction(0, true)];
        let mut block = Block {
            header: header(1, &transactions),
            transactions,
        };
        block.header.tx_root[0] ^= 1;
        let body_hashes = canonical_tx_body_hashes(&block);
        assert!(tx_root_merkle_inputs(&block, &body_hashes).is_err());

        let genesis = Block {
            header: header(0, &[]),
            transactions: Vec::new(),
        };
        assert!(tx_root_merkle_inputs(&genesis, &[]).unwrap().is_empty());

        let mut malformed_genesis = genesis;
        malformed_genesis.header.tx_root = [1; 32];
        assert!(tx_root_merkle_inputs(&malformed_genesis, &[]).is_err());
    }

    #[test]
    fn direct_accumulator_anchor_match_checks_every_shared_lane() {
        let header = header(7, &[]);
        let block_id = hash_block_header(&header);
        let anchor = HeaderChainAnchor {
            height: header.height,
            block_id,
            state_root: header.state_root,
            tx_root: header.tx_root,
            miner_address: header.miner_address,
            log_slots: header.log_slots,
            active_slot_count: header.active_slot_count,
            alloc_counter: header.alloc_counter,
            cumulative_chainwork: [0x55; 32],
        };
        let accumulator = ChainAccumulator {
            height: header.height,
            tip_block_id: block_id,
            state_root: header.state_root,
            log_slots: header.log_slots,
            active_slot_count: header.active_slot_count,
            alloc_counter: header.alloc_counter,
            epoch_anchor_id: [0x77; 32],
        };
        assert!(accumulator_matches_anchor(&accumulator, &anchor));

        for lane in 0..6 {
            let mut bad = accumulator.clone();
            match lane {
                0 => bad.height += 1,
                1 => bad.tip_block_id[0] ^= 1,
                2 => bad.state_root[0] ^= 1,
                3 => bad.log_slots += 1,
                4 => bad.active_slot_count += 1,
                5 => bad.alloc_counter += 1,
                _ => unreachable!(),
            }
            assert!(!accumulator_matches_anchor(&bad, &anchor), "lane {lane}");
        }
    }
}
