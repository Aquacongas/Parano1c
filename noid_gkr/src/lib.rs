// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! GKR-based proving for the Paranoid transaction system.
//!
//! This crate implements the Kill-Shot GKR protocol for Poseidon2b
//! permutation chains. It provides:
//!
//! - **Owner Auth GKR**: proves the transaction's single input owner from one
//!   wallet spend secret.
//! - **Poseidon2b spine components**: reusable Kill-Shot proofs for fixed
//!   permutation batches such as tx-body hashing, accepted-claim hashing,
//!   state-root hashing, and chain accumulation.
//! - **Merkle GKR**: proves batches of Poseidon2b Merkle paths through the
//!   same Kill-Shot permutation relation.

pub mod accepted_claim_killshot;
pub mod auth_pcs;
pub mod batch_eval;
pub mod block_spine;
pub mod circuit;
pub mod fixed_field_hash_killshot;
pub mod ghost_tx;
pub mod header_hash_killshot;
pub mod history_claim_killshot;
pub mod layers;
pub mod merkle_batch_killshot;
pub mod merkle_circuit;
pub mod merkle_oracle;
pub mod mle_layout;
pub mod oracle;
pub mod owner_auth;
pub mod spine_killshot;
pub mod spine_mle;
pub mod spine_shift;
pub mod spine_statement;
pub mod spine_sumcheck;
pub mod spine_unified;
pub mod state_leaf_killshot;
pub mod tx_body_layout;
pub mod wallet_authorization;

pub use accepted_claim_killshot::{
    discharge_accepted_claim_hash_reductions_native, prove_accepted_claim_hash_killshot,
    verify_accepted_claim_hash_killshot, AcceptedClaimHashInputs, AcceptedClaimHashProofKillShot,
    AcceptedClaimHashReductions, ACCEPTED_CLAIM_FIELDS,
};
pub use auth_pcs::{verify_auth_mle_opening, AuthMleOpeningProof, AUTH_PCS_BASE_LOG};
pub use batch_eval::{
    prove_batch_eval, prove_multi_batch_eval, verify_batch_eval, verify_multi_batch_eval,
    BatchEvalProof, BatchEvalReduction, BatchEvalRound, EvalClaim, MultiBatchEvalProof,
};
pub use block_spine::{
    discharge_block_spine_batch_reductions_from_slot_state_ins_native,
    discharge_block_spine_reductions_native, evaluate_block_spine_columns_from_slot_state_ins,
    prove_block_spine_killshot, verify_block_spine_killshot, BlockSpineKillShotProof,
    BlockSpineMle, BlockSpineProof, BlockSpineReductions, BlockSpineShiftProof,
    BlockSpineShiftReduction, BlockSpineUnifiedProof, BlockSpineUnifiedReduction,
    BLOCK_SPINE_ROUND_DEGREE, BLOCK_SPINE_SHIFT_DEGREE,
};
pub use circuit::{SlotDescriptor, SpineCircuit, SpineInputs};
pub use fixed_field_hash_killshot::{
    discharge_fixed_field_hash_reductions_native, prove_fixed_field_hash_killshot,
    verify_fixed_field_hash_killshot, FixedFieldHashInputs, FixedFieldHashParams,
    FixedFieldHashProofKillShot, FixedFieldHashReductions, FIXED_FIELD_HASH_PIN_LANES,
};
pub use header_hash_killshot::{
    discharge_header_hash_reductions_native, discharge_header_hash_reductions_native_padded,
    prove_header_hash_killshot, prove_header_hash_killshot_padded, verify_header_hash_killshot,
    verify_header_hash_killshot_padded, HeaderHashInputs, HeaderHashProofKillShot,
    HeaderHashReductions, HEADER_HASH_FIELDS,
};
pub use history_claim_killshot::{
    discharge_history_claim_hash_reductions_native, prove_history_claim_hash_killshot,
    verify_history_claim_hash_killshot, HistoryClaimHashInputs, HistoryClaimHashProofKillShot,
    HistoryClaimHashReductions, HISTORY_CLAIM_FIELDS,
};
pub use layers::{evaluate_permutation, round_kind, PermLayerWitness, RoundKind};
pub use merkle_batch_killshot::{
    discharge_batched_merkle_reductions_native, prove_batched_merkle_killshot,
    verify_batched_merkle_killshot, BatchedMerkleKillShotReductions, BatchedMerkleProofKillShot,
};
pub use merkle_circuit::{
    MerkleCircuit, MerklePathInputs, MerkleSlotDescriptor, MerkleSlotRole, MAX_MERKLE_DEPTH,
    N_MERKLE_SLOTS, N_PERMS_PER_COMPRESS,
};
pub use merkle_oracle::{compute_merkle_root, evaluate_merkle, MerkleSlotState, MerkleWitness};
pub use mle_layout::{pack_column, PermColumn, PermMle, N_PERM_CELLS, N_PERM_VARS};
pub use oracle::{evaluate_spine, SpineWitness};
pub use owner_auth::{
    build_owner_auth_unified_from_inputs, build_owner_auth_unified_mle,
    compute_owner_auth_boundary, discharge_owner_auth_reductions_native, evaluate_owner_auth,
    init_owner_auth_gkr_channel, owner_auth_gkr_channel, owner_auth_public_from_body,
    owner_auth_public_from_statement, owner_auth_trace_inputs_from_body_and_secret,
    prove_owner_auth_killshot, prove_owner_auth_killshot_from_mle, verify_owner_auth_killshot,
    verify_owner_auth_killshot_with_claims, OwnerAuthBoundaryProof, OwnerAuthBoundaryReduction,
    OwnerAuthCircuit, OwnerAuthInputs, OwnerAuthKillShotProof, OwnerAuthKillShotReductions,
    OwnerAuthLayout, OwnerAuthProofKillShot, OwnerAuthPublicInputs, OwnerAuthShiftProof,
    OwnerAuthShiftReduction, OwnerAuthSlotDescriptor, OwnerAuthSlotRole, OwnerAuthSlotState,
    OwnerAuthStatementError, OwnerAuthTraceWitness, OwnerAuthUnifiedProof,
    OwnerAuthUnifiedReduction, OwnerAuthVerifierClaims, OWNER_AUTH_LIVE_SLOTS, OWNER_AUTH_NUM_VARS,
    OWNER_AUTH_PADDED_SLOTS, OWNER_AUTH_PIN_LANES, OWNER_AUTH_SHIFT_ROUND_DEGREE,
    OWNER_AUTH_SLOT_BITS, OWNER_AUTH_STATE_ROUND_DEGREE, OWNER_AUTH_UNIFIED_ROUND_DEGREE,
};
pub use spine_killshot::{
    build_unified_from_inputs, build_unified_from_states, discharge_reductions_native,
    prove_spine_killshot, prove_spine_killshot_with_states, verify_spine_killshot,
    SpineKillShotReductions, SpineProofKillShot,
};
pub use spine_mle::{
    build_unified_mle, sigma_at, SpineUnifiedMle, N_SPINE_ELEM_VARS, N_SPINE_ROUND_VARS,
    N_SPINE_SLOT_VARS, N_SPINE_UNIFIED_CELLS, N_SPINE_UNIFIED_VARS,
};
pub use spine_shift::{
    build_mds_lane_table, build_mu_table, build_rc_table, build_sigma_table, build_u_table,
    dec_round_index, elem_of, inc_round_index, mds_coeff, mu_evaluate, pack_index, permute_by_dec,
    project_lane, rc_evaluate, round_of, sigma_evaluate, slot_of,
};
pub use spine_shift::{
    build_mds_lane_table_for_live_slots, build_mu_table_for_live_slots,
    build_rc_table_for_live_slots, build_sigma_table_for_live_slots, build_u_table_for_live_slots,
};
pub use spine_statement::spine_inputs_from_body;
pub use spine_sumcheck::{
    build_boundary_mle, compute_tx_body_hash, discharge_boundary_native, reconstruct_slot_states,
    N_BOUNDARY_CELLS, N_BOUNDARY_VARS, N_SLOT_VARS, N_SPINE_SLOTS, N_SPINE_SLOTS_PADDED,
};
pub use spine_unified::{
    prove_spine_shift, prove_spine_unified, prove_spine_unified_for_live_slots, verify_spine_shift,
    verify_spine_unified, verify_spine_unified_for_live_slots, SpineKillShotProof, SpineShiftProof,
    SpineShiftReduction, SpineUnifiedProof, SpineUnifiedReduction, N_UNIFIED_WITNESS_CLAIMS,
    SPINE_SHIFT_ROUND_DEGREE, SPINE_UNIFIED_ROUND_DEGREE,
};
pub use state_leaf_killshot::{
    discharge_batched_slot_leaf_reductions_native, prove_batched_slot_leaf_killshot,
    verify_batched_slot_leaf_killshot, BatchedSlotLeafProofKillShot, BatchedSlotLeafReductions,
    SlotLeafInputs,
};
pub use tx_body_layout::{
    build_instance_layout, InstanceMeta, InstanceRole, TXBODY_N_TREE_LEAVES, TXBODY_TREE_DEPTH,
};
pub use wallet_authorization::{
    authorization_proof_wire_bytes, canonical_authorization_statement_from_body,
    prove_wallet_authorization, validate_authorization_statement,
    verify_authorization_statement_proof, verify_wallet_authorization,
    verify_wallet_authorization_proof, AuthorizationDecodeError, AuthorizationEncodeError,
    CanonicalAuthorizationStatement, OwnerAuthWitness, ProveAuthorizationError,
    VerifiedAuthorization, VerifiedAuthorizationBatch, VerifyAuthorizationError,
    WalletAuthorizationBundle, MAX_AUTHORIZATION_BUNDLE_BYTES, MAX_AUTHORIZATION_LIVE_INPUTS,
};
