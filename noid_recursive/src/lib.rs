// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Recursive proof components for the O(1) history path.
//!
//! The target path folds fixed accepted-block certificate chunks and binds them
//! to locally verified header anchors.

pub mod acceptance;
pub mod accepted_batch;
pub mod accumulator;
pub mod authorization;
pub mod block_certificate;
pub mod block_certificate_backend;
pub mod block_certificate_ivc;
pub mod checkpoint;
pub mod checkpoint_ivc_backend;
pub mod checkpoint_proof;
pub mod fs_transcript;
pub mod header_integer;
pub mod pow_header;
pub mod region_sidecar;
pub mod selected_history;

pub use acceptance::{verify_acceptance_against_header, AcceptanceProof, AcceptanceRelationError};
pub use accepted_batch::{
    accepted_claim_batch_digest, accepted_claim_batch_digest_hash_fields,
    accepted_claim_batch_digest_hash_params, prove_accepted_claim_batch_digest,
    verify_accepted_claim_batch_digest, verify_accepted_claim_batch_native,
    verify_accepted_claim_batch_with_header_trace, AcceptedClaimBatchDigestError,
    AcceptedClaimBatchDigestProof, AcceptedClaimBatchError, AcceptedClaimBatchOutput,
    AcceptedClaimBatchWitness, ACCEPTED_CLAIM_BATCH_DIGEST_HASH_FIELDS,
};
pub use accumulator::{
    genesis_accumulator, ChainAccumulator, ChainAccumulatorAdvanceError, ChainAccumulatorLaneError,
    ChainAccumulatorLocalBoundaryError, CHAIN_ACCUMULATOR_LANES,
};
pub use authorization::{
    verify_authorization_batch_native, verify_authorization_batch_native_with_traces,
    verify_authorization_statement_proof_with_trace, AuthorizationBatchError,
    AuthorizationVerifierTrace, FiatShamirTraceOp,
};
pub use block_certificate::{
    accepted_block_certificate_auth_sidecar_digest, accepted_block_certificate_batch_statement,
    accepted_block_certificate_batch_statement_digest,
    accepted_block_certificate_batch_statement_hash_fields,
    accepted_block_certificate_batch_statement_hash_params,
    accepted_block_certificate_block_body_digest, accepted_block_certificate_block_proof_digest,
    accepted_block_certificate_block_proof_meta_digest, accepted_block_certificate_chain_claim,
    accepted_block_certificate_proof_digest, accepted_block_certificate_receipt,
    accepted_block_certificate_receipt_chain_claim, accepted_block_certificate_statement_digest,
    accepted_block_certificate_statement_fields,
    accepted_block_certificate_statement_from_acceptance_receipt,
    accepted_block_certificate_statement_hash_fields,
    accepted_block_certificate_statement_hash_params, accepted_block_receipt_projection_handle,
    block_proof_acceptance_receipt_digest, prove_accepted_block_certificate_batch_digest_proof,
    verify_accepted_block_certificate_batch_digest_proof,
    verify_accepted_block_certificate_proof_checkpoint,
    verify_accepted_block_certificate_receipt_projection,
    verify_accepted_block_receipt_projection_handle, AcceptedBlockCertificateBatchDigestProof,
    AcceptedBlockCertificateBatchError, AcceptedBlockCertificateBatchStatement,
    AcceptedBlockCertificateProof, AcceptedBlockCertificateProofError,
    AcceptedBlockCertificateReceipt, AcceptedBlockCertificateReceiptError,
    AcceptedBlockCertificateStatement, AcceptedBlockReceiptProjectionHandle,
    AcceptedBlockReceiptProjectionHandleError, BlockProofAcceptanceReceipt,
    ACCEPTED_BLOCK_CERTIFICATE_BATCH_STATEMENT_HASH_FIELDS,
    ACCEPTED_BLOCK_CERTIFICATE_STATEMENT_FIELDS, ACCEPTED_BLOCK_CERTIFICATE_STATEMENT_HASH_FIELDS,
};

pub use block_certificate_ivc::{
    accepted_block_receipt_projection_relation_digest,
    decode_and_verify_accepted_block_receipt_projection,
    prove_accepted_block_certificate_receipt_projection_proof,
    prove_accepted_block_receipt_projection, prove_accepted_block_receipt_projection_with_receipt,
    verify_accepted_block_receipt_projection, AcceptedBlockReceiptProjectionError,
    AcceptedBlockReceiptProjectionProof, ACCEPTED_BLOCK_RECEIPT_PROJECTION_K_LOG,
    ACCEPTED_BLOCK_RECEIPT_PROJECTION_LOG_BATCH_SIZE,
    ACCEPTED_BLOCK_RECEIPT_PROJECTION_LOG_INV_RATE, ACCEPTED_BLOCK_RECEIPT_PROJECTION_M,
    ACCEPTED_BLOCK_RECEIPT_PROJECTION_RELATION,
};
pub use checkpoint::{
    prove_checkpoint_poseidon, verify_checkpoint_poseidon, CheckpointPoseidonError,
    CheckpointPoseidonProof,
};
pub use checkpoint_ivc_backend::{
    prove_history_checkpoint_ivc_chunk_core,
    prove_history_checkpoint_ivc_chunk_receipt_handle_core,
    verify_history_checkpoint_ivc_chunk_core, HistoryCheckpointIvcChunkCoreError,
    HistoryCheckpointIvcChunkCoreProof, HISTORY_CHECKPOINT_IVC_CHUNK_CORE_RELATION,
    HISTORY_CHECKPOINT_IVC_CHUNK_CORE_WIRE_BYTES, HISTORY_CHECKPOINT_IVC_PCS_LOG_BATCH_SIZE,
    HISTORY_CHECKPOINT_IVC_PCS_LOG_INV_RATE,
};
pub use checkpoint_proof::{
    advance_history_checkpoint_head_native, history_checkpoint_accumulator_digest,
    history_checkpoint_anchor_digest, history_checkpoint_batch_summary_digest,
    history_checkpoint_consensus_digest, history_checkpoint_head_digest,
    history_checkpoint_head_from_boundary, history_checkpoint_public_proof_bytes_digest,
    history_checkpoint_step_relation_digest, history_checkpoint_step_statement_digest,
    history_checkpoint_step_statement_hash_fields, history_checkpoint_step_statement_hash_params,
    prove_history_checkpoint_recursive_head_record, prove_history_checkpoint_step_digest_proof,
    prove_history_checkpoint_step_proof_from_certificate_statements,
    prove_history_checkpoint_step_proof_with_ivc_chunk_certificate_proof_components,
    prove_history_checkpoint_step_proof_with_ivc_chunk_core_components,
    public_history_checkpoint_proof_from_head_record, verify_history_checkpoint_head_record,
    verify_history_checkpoint_head_record_transition, verify_history_checkpoint_proof_checkpoint,
    verify_history_checkpoint_step_digest_proof, verify_history_checkpoint_step_proof_checkpoint,
    verify_history_checkpoint_step_proof_private_components_native,
    verify_history_checkpoint_step_statement_native, HistoryCheckpointBatchSummary,
    HistoryCheckpointHead, HistoryCheckpointProof, HistoryCheckpointProofError,
    HistoryCheckpointStepBackendProof, HistoryCheckpointStepDigestProof,
    HistoryCheckpointStepProof, HistoryCheckpointStepProofError, HistoryCheckpointStepStatement,
    StoredHistoryCheckpointHeadRecord, HISTORY_CHECKPOINT_BATCH_TARGET_BLOCKS,
    HISTORY_CHECKPOINT_ENGINE_STREAMING_TOWER_IVC, HISTORY_CHECKPOINT_RETAINED_WINDOW_BLOCKS,
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
pub use pow_header::{
    header_hash_proof_inputs, verify_pow_header_batch_native,
    verify_pow_header_witness_batch_native, HeaderWitness, PowHeaderBatchError,
    RecursiveConsensusState,
};
pub use selected_history::{
    decode_selected_history_terminal_package, encode_selected_history_terminal_package,
    verify_selected_history_terminal, CanonicalSelectedHistoryRegistry, SelectedHistoryCodecError,
    SelectedHistoryMatrixFamily, SelectedHistoryMatrixRequest, SelectedHistoryRegistryError,
    SelectedHistoryTerminalPackage, SelectedHistoryVerificationError,
    MAX_SELECTED_HISTORY_TERMINAL_ENVELOPE_BYTES, MAX_SELECTED_HISTORY_TERMINAL_PACKAGE_BYTES,
    SELECTED_HISTORY_LINK_IO_LANES, SELECTED_HISTORY_TERMINAL_VERSION,
};
