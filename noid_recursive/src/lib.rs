// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Local finalized-history cache and native recursive-boundary relations.
//!
//! Core components:
//! - `ChainAccumulator`: rolling hash commitment to the entire chain history.
//! - `LocalHistoryCache`: local finalized-history accumulator cache.
//! - `advance_local_history_cache`: fold one accepted-block claim into the cache.
//!
//! The local cache is not a proof and is not public snapshot authority. Public
//! O(1) sync is enabled only after a recursive verifier proves the full
//! accepted-block batch relation.

pub mod accepted_batch;
pub mod accumulator;
pub mod authorization;
pub mod block_certificate;
pub mod block_certificate_backend;
pub mod checkpoint;
pub mod checkpoint_ivc_backend;
pub mod checkpoint_proof;
pub mod fs_transcript;
pub mod header_integer;
pub mod history_proof;
pub mod pow_header;
pub mod prove;
pub mod verify;

pub use accepted_batch::{
    accepted_claim_batch_digest_hash_fields_v1, accepted_claim_batch_digest_hash_params_v1,
    accepted_claim_batch_digest_v1, chain_accumulator_proof_inputs,
    prove_accepted_claim_batch_digest_v1, verify_accepted_claim_batch_digest_v1,
    verify_accepted_claim_batch_native, verify_accepted_claim_batch_with_header_trace,
    AcceptedClaimBatchDigestError, AcceptedClaimBatchDigestProofV1, AcceptedClaimBatchError,
    AcceptedClaimBatchOutput, AcceptedClaimBatchWitness, ACCEPTED_CLAIM_BATCH_DIGEST_HASH_FIELDS,
    ACCEPTED_CLAIM_BATCH_DIGEST_VERSION,
};
pub use accumulator::{genesis_accumulator, ChainAccumulator};
pub use authorization::{
    verify_authorization_batch_native, verify_authorization_batch_native_with_traces,
    AuthorizationBatchError, AuthorizationVerifierTrace, FiatShamirTraceOp,
};
pub use block_certificate::{
    accepted_block_certificate_auth_sidecar_digest_v1,
    accepted_block_certificate_batch_statement_digest_v1,
    accepted_block_certificate_batch_statement_hash_fields_v1,
    accepted_block_certificate_batch_statement_hash_params_v1,
    accepted_block_certificate_batch_statement_v1, accepted_block_certificate_block_body_digest_v1,
    accepted_block_certificate_block_proof_digest_v1, accepted_block_certificate_chain_claim_v1,
    accepted_block_certificate_statement_digest_v1, accepted_block_certificate_statement_fields_v1,
    accepted_block_certificate_statement_hash_fields_v1,
    accepted_block_certificate_statement_hash_params_v1,
    prove_accepted_block_certificate_batch_digest_proof_v1,
    prove_accepted_block_certificate_digest_backend_v1,
    prove_accepted_block_certificate_proof_v1_hash_only,
    verify_accepted_block_certificate_batch_digest_proof_v1,
    verify_accepted_block_certificate_digest_backend_v1,
    verify_accepted_block_certificate_proof_v1_untrusted, AcceptedBlockCertificateBackendProofV1,
    AcceptedBlockCertificateBatchDigestProofV1, AcceptedBlockCertificateBatchError,
    AcceptedBlockCertificateBatchStatementV1, AcceptedBlockCertificateProofError,
    AcceptedBlockCertificateProofV1, AcceptedBlockCertificateStatementV1,
    ACCEPTED_BLOCK_CERTIFICATE_BATCH_STATEMENT_HASH_FIELDS,
    ACCEPTED_BLOCK_CERTIFICATE_PROOF_VERSION, ACCEPTED_BLOCK_CERTIFICATE_STATEMENT_FIELDS,
    ACCEPTED_BLOCK_CERTIFICATE_STATEMENT_HASH_FIELDS, ACCEPTED_BLOCK_CERTIFICATE_STATEMENT_VERSION,
};
pub use block_certificate_backend::{
    verify_accepted_block_batch_components_v1, verify_exact_state_killshot_v1,
    AcceptedBlockBatchComponentErrorV1, AcceptedBlockBatchComponentInputsV1,
    AcceptedBlockBatchComponentProofV1, AuthorizationComponentInputV1, ExactStateKillShotErrorV1,
    ExactStateKillShotInputsV1, ExactStateKillShotProofV1,
};
pub use checkpoint::{
    prove_checkpoint_poseidon, verify_checkpoint_poseidon, CheckpointPoseidonError,
    CheckpointPoseidonProof,
};
pub use checkpoint_ivc_backend::{
    prove_history_checkpoint_ivc_chunk_core_v1, verify_history_checkpoint_ivc_chunk_core_v1,
    HistoryCheckpointIvcChunkCoreError, HistoryCheckpointIvcChunkCoreProofV1,
    HISTORY_CHECKPOINT_IVC_CHUNK_CORE_RELATION_V1, HISTORY_CHECKPOINT_IVC_PCS_LOG_BATCH_SIZE,
    HISTORY_CHECKPOINT_IVC_PCS_LOG_INV_RATE,
};
pub use checkpoint_proof::{
    advance_history_checkpoint_head_v1_native, encode_history_checkpoint_recursive_payload_v1,
    history_checkpoint_accumulator_digest, history_checkpoint_anchor_digest,
    history_checkpoint_batch_summary_digest, history_checkpoint_consensus_digest,
    history_checkpoint_head_digest, history_checkpoint_head_from_boundary_v1,
    history_checkpoint_step_relation_digest, history_checkpoint_step_statement_digest,
    history_checkpoint_step_statement_hash_fields, history_checkpoint_step_statement_hash_params,
    prove_history_checkpoint_step_digest_proof_v1,
    prove_history_checkpoint_step_proof_v1_batch_digest_only,
    prove_history_checkpoint_step_proof_v1_from_block_components,
    prove_history_checkpoint_step_proof_v1_from_certificate_statements,
    prove_history_checkpoint_step_proof_v1_with_digest_components,
    verify_history_checkpoint_proof_v1_untrusted, verify_history_checkpoint_step_digest_proof_v1,
    verify_history_checkpoint_step_proof_v1_private_block_components_native,
    verify_history_checkpoint_step_proof_v1_private_components_native,
    verify_history_checkpoint_step_proof_v1_untrusted,
    verify_history_checkpoint_step_statement_v1_native, HistoryCheckpointBatchSummaryV1,
    HistoryCheckpointHeadV1, HistoryCheckpointProofError, HistoryCheckpointProofV1,
    HistoryCheckpointRecursivePayloadV1, HistoryCheckpointStepBackendProofV1,
    HistoryCheckpointStepDigestProofV1, HistoryCheckpointStepProofError,
    HistoryCheckpointStepProofV1, HistoryCheckpointStepStatementV1,
    HISTORY_CHECKPOINT_BATCH_TARGET_BLOCKS, HISTORY_CHECKPOINT_ENGINE_STREAMING_TOWER_IVC_V1,
    HISTORY_CHECKPOINT_PROOF_VERSION, HISTORY_CHECKPOINT_RETAINED_WINDOW_BLOCKS,
    HISTORY_CHECKPOINT_STEP_STATEMENT_HASH_FIELDS,
};
pub use fs_transcript::{
    discharge_fiat_shamir_transcript_batch_reductions_native,
    discharge_fiat_shamir_transcript_reductions_native,
    prove_fiat_shamir_transcript_batch_killshot, prove_fiat_shamir_transcript_killshot,
    verify_fiat_shamir_transcript_batch_killshot, verify_fiat_shamir_transcript_killshot,
    FiatShamirTranscriptBatchProofKillShot, FiatShamirTranscriptError,
    FiatShamirTranscriptProofKillShot, FiatShamirTranscriptReductions,
    FIAT_SHAMIR_TRANSCRIPT_MAX_OPS_PER_TRACE, FIAT_SHAMIR_TRANSCRIPT_MAX_PERMUTATIONS_PER_BATCH,
    FIAT_SHAMIR_TRANSCRIPT_MAX_TRACES_PER_BATCH,
};
pub use header_integer::{
    build_header_integer_trace, verify_header_integer_trace, HeaderIntegerBatchTrace,
    HeaderIntegerStepTrace, HeaderIntegerTraceError,
};
pub use history_proof::{
    advance_history_accumulation_native, advance_history_arc_pcd_accumulator_native,
    build_history_arc_pcd_recursive_step_statement, build_history_pcd_step_statement_from_step,
    build_history_pcd_step_statement_native, build_history_step_statement,
    discharge_history_step_native, history_accumulation_state_digest,
    history_accumulation_state_digest_from_fields,
    history_accumulation_state_digest_from_hash_fields, history_accumulation_state_fields,
    history_accumulation_state_hash_fields, history_accumulation_state_hash_fields_from_fields,
    history_accumulation_state_hash_params, history_arc_pcd_accumulator_digest,
    history_arc_pcd_accumulator_digest_from_fields,
    history_arc_pcd_accumulator_digest_from_hash_fields, history_arc_pcd_accumulator_fields,
    history_arc_pcd_accumulator_hash_fields, history_arc_pcd_accumulator_hash_fields_from_fields,
    history_arc_pcd_accumulator_hash_params, history_arc_pcd_chunk_step_component_digest,
    history_arc_pcd_chunk_step_verifier_traces, history_arc_pcd_one_step_component_digest,
    history_arc_pcd_recursive_base_digest, history_arc_pcd_recursive_chunk_step_hash_params,
    history_arc_pcd_recursive_chunk_step_statement_digest,
    history_arc_pcd_recursive_chunk_step_statement_digest_from_fields,
    history_arc_pcd_recursive_chunk_step_statement_digest_from_hash_fields,
    history_arc_pcd_recursive_chunk_step_statement_fields,
    history_arc_pcd_recursive_chunk_step_statement_hash_fields,
    history_arc_pcd_recursive_chunk_step_statement_hash_fields_from_fields,
    history_arc_pcd_recursive_chunk_step_verifier_traces,
    history_arc_pcd_recursive_step_hash_params, history_arc_pcd_recursive_step_statement_digest,
    history_arc_pcd_recursive_step_statement_digest_from_fields,
    history_arc_pcd_recursive_step_statement_digest_from_hash_fields,
    history_arc_pcd_recursive_step_statement_fields,
    history_arc_pcd_recursive_step_statement_hash_fields,
    history_arc_pcd_recursive_step_statement_hash_fields_from_fields,
    history_arc_pcd_step_relation_digest, history_chain_accumulator_fields,
    history_chain_claim_from_digest, history_claim_digest_from_fields, history_decider_statement,
    history_decider_statement_digest, history_pcd_step_hash_params,
    history_pcd_step_statement_digest, history_pcd_step_statement_digest_from_fields,
    history_pcd_step_statement_digest_from_hash_fields, history_pcd_step_statement_fields,
    history_pcd_step_statement_hash_fields, history_pcd_step_statement_hash_fields_from_fields,
    history_proof_digest, history_step_statement_fields,
    history_tagged_pair_digest_from_hash_fields, history_tagged_pair_hash_fields,
    history_tagged_pair_hash_params, prove_history_arc_pcd_chunk_step_native,
    prove_history_arc_pcd_chunk_step_verifier_transcript_batch_native,
    prove_history_arc_pcd_one_step, prove_history_arc_pcd_recursive_chain_head_native,
    prove_history_arc_pcd_recursive_chain_head_step_native,
    prove_history_arc_pcd_recursive_chunk_chain_head_native,
    prove_history_arc_pcd_recursive_chunk_chain_head_step_native,
    prove_history_arc_pcd_recursive_chunk_step_native,
    prove_history_arc_pcd_recursive_chunk_step_verifier_transcript_batch_native,
    prove_history_arc_pcd_recursive_step_native, prove_history_arc_pcd_step_native,
    prove_history_native, prove_history_step_native,
    verify_history_arc_pcd_chunk_step_proof_native,
    verify_history_arc_pcd_recursive_chain_head_shape_native,
    verify_history_arc_pcd_recursive_chunk_chain_head_shape_native,
    verify_history_arc_pcd_recursive_chunk_step_proof_native,
    verify_history_arc_pcd_recursive_chunk_step_statement_shape,
    verify_history_arc_pcd_recursive_chunk_step_verifier_transcript_batch_native,
    verify_history_arc_pcd_recursive_step_proof_native,
    verify_history_arc_pcd_recursive_step_statement_shape,
    verify_history_arc_pcd_step_proof_native, verify_history_pcd_step_statement_shape,
    verify_history_proof_native, verify_history_proof_untrusted, verify_history_step_native,
    HistoryAccumulationState, HistoryArcPcdAccumulator, HistoryArcPcdChunkStepProof,
    HistoryArcPcdOneStepProof, HistoryArcPcdRecursiveChainHead,
    HistoryArcPcdRecursiveChunkChainHead, HistoryArcPcdRecursiveChunkStepProof,
    HistoryArcPcdRecursiveChunkStepStatement, HistoryArcPcdRecursiveStepProof,
    HistoryArcPcdRecursiveStepStatement, HistoryArcPcdStepProof, HistoryDeciderHashProofs,
    HistoryDeciderProof, HistoryDeciderStatement, HistoryPcdStepStatement, HistoryProof,
    HistoryProofBackend, HistoryProofError, HistoryProofWitness, HistoryStepProof,
    HistoryStepStatement, HistoryTransitionWitnessItem, HISTORY_ACCUMULATION_STATE_FIELDS,
    HISTORY_ACCUMULATION_STATE_HASH_FIELDS, HISTORY_ARC_PCD_ACCUMULATOR_FIELDS,
    HISTORY_ARC_PCD_ACCUMULATOR_HASH_FIELDS, HISTORY_ARC_PCD_CHUNK_MAX_STEPS,
    HISTORY_ARC_PCD_RECURSIVE_CHUNK_STEP_FIELDS, HISTORY_ARC_PCD_RECURSIVE_CHUNK_STEP_HASH_FIELDS,
    HISTORY_ARC_PCD_RECURSIVE_STEP_FIELDS, HISTORY_ARC_PCD_RECURSIVE_STEP_HASH_FIELDS,
    HISTORY_CHAIN_ACCUMULATOR_FIELDS, HISTORY_PCD_STEP_HASH_FIELDS,
    HISTORY_PCD_STEP_STATEMENT_FIELDS, HISTORY_PROOF_VERSION, HISTORY_STEP_STATEMENT_FIELDS,
    HISTORY_TAGGED_PAIR_HASH_FIELDS,
};
pub use pow_header::{
    header_hash_proof_inputs, verify_pow_header_batch_native,
    verify_pow_header_witness_batch_native, HeaderWitness, PowHeaderBatchError,
    RecursiveConsensusState,
};
pub use prove::{
    accepted_block_claim_witness_from_fields, advance_local_history_cache,
    advance_local_history_recursive_chunk_head_cache, advance_local_history_recursive_head_cache,
    empty_accepted_block_witness, init_genesis_history_cache,
    init_genesis_history_cache_with_chainwork, init_local_history_cache_from_anchor,
    init_local_history_recursive_chunk_head_cache, init_local_history_recursive_head_cache,
    prove_history_arc_pcd_from_recursive_chunk_head_cache,
    prove_history_arc_pcd_from_recursive_head_cache, prove_history_from_local_cache,
    AcceptedBlockClaimWitness, LocalHistoryCache, LocalHistoryRecursiveChunkHeadCache,
    LocalHistoryRecursiveHeadCache, LOCAL_HISTORY_CACHE_VERSION,
    LOCAL_HISTORY_RECURSIVE_CHUNK_HEAD_CACHE_VERSION, LOCAL_HISTORY_RECURSIVE_HEAD_CACHE_VERSION,
};
pub use verify::{
    reject_public_snapshot_authority, verify_local_history_cache_step, verify_tip, RecVerifyError,
};
