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
pub mod checkpoint;
pub mod fs_transcript;
pub mod header_integer;
pub mod pow_header;
pub mod prove;
pub mod verify;

pub use accepted_batch::{
    chain_accumulator_proof_inputs, verify_accepted_claim_batch_native,
    verify_accepted_claim_batch_with_header_trace, AcceptedClaimBatchError,
    AcceptedClaimBatchOutput, AcceptedClaimBatchWitness,
};
pub use accumulator::{genesis_accumulator, ChainAccumulator};
pub use authorization::{
    verify_authorization_batch_native, verify_authorization_batch_native_with_traces,
    AuthorizationBatchError, AuthorizationVerifierTrace, FiatShamirTraceOp,
};
pub use checkpoint::{
    prove_checkpoint_poseidon, verify_checkpoint_poseidon, CheckpointPoseidonError,
    CheckpointPoseidonProof,
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
pub use prove::{
    accepted_block_claim_witness, advance_local_history_cache, empty_accepted_block_witness,
    init_genesis_history_cache, AcceptedBlockClaimWitness, LocalHistoryCache,
};
pub use verify::{
    reject_public_snapshot_authority, verify_local_history_cache_step, verify_tip, RecVerifyError,
};
