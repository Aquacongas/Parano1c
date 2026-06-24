// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! GKR-based proving for the Paranoid transaction system.
//!
//! This crate implements the Kill-Shot GKR protocol for Poseidon2b
//! permutation chains. It provides:
//!
//! - **Owner Auth GKR**: proves spend-secret ownership once per canonical
//!   unique owner group in a transaction.
//! - **Block Spine GKR**: a single unified Kill-Shot for N×59 permutations
//!   across all transactions in a block, with proof size and verification
//!   cost growing O(log N) rather than O(N).
//! - **Merkle GKR**: proves the tx-body Merkle tree hash (59-perm chain).
//!
//! See `SPEC.md` and `AUDIT.md` in this crate for the cryptographic
//! specification and security analysis.

pub mod auth_pcs;
pub mod batch_eval;
pub mod binding;
pub mod block_spine;
pub mod block_spine_sweep;
pub mod circuit;
pub mod circuit_sweep;
pub mod layers;
pub mod merkle_circuit;
pub mod merkle_killshot;
pub mod merkle_mle;
pub mod merkle_oracle;
pub mod merkle_shift;
pub mod merkle_unified;
pub mod mle_layout;
pub mod oracle;
pub mod oracle_sweep;
pub mod owner_auth;
pub mod spine_degree7;
pub mod spine_killshot;
pub mod spine_killshot_sweep;
pub mod spine_mle;
pub mod spine_mle_sweep;
pub mod spine_shift;
pub mod spine_shift_sweep;
pub mod spine_sumcheck;
pub mod spine_sumcheck_sweep;
pub mod spine_unified;
pub mod spine_unified_sweep;
pub mod sweep_spine_statement;
pub mod wallet_authorization;

pub use auth_pcs::{
    commit_auth_mle_columns, open_auth_mle_columns_committed, prove_auth_mle_opening,
    verify_auth_mle_multi_opening, verify_auth_mle_opening, AuthMleMultiOpeningProof,
    AuthMleOpeningProof, AUTH_PCS_BASE_LOG,
};
pub use batch_eval::{
    prove_batch_eval, prove_multi_batch_eval, verify_batch_eval, verify_multi_batch_eval,
    BatchEvalProof, BatchEvalReduction, BatchEvalRound, EvalClaim, MultiBatchEvalProof,
};
pub use binding::BindingCut;
pub use block_spine::{
    discharge_block_spine_reductions_native, prove_block_spine_killshot,
    verify_block_spine_killshot, BlockSpineKillShotProof, BlockSpineMle, BlockSpineProof,
    BlockSpineReductions, BlockSpineShiftProof, BlockSpineShiftReduction, BlockSpineUnifiedProof,
    BlockSpineUnifiedReduction, BLOCK_SPINE_ROUND_DEGREE, BLOCK_SPINE_SHIFT_DEGREE,
};
pub use block_spine_sweep::{
    discharge_sweep_block_spine_reductions_native, prove_sweep_block_spine_killshot,
    verify_sweep_block_spine_killshot, SweepBlockSpineMle, SweepBlockSpineProof,
    SweepBlockSpineReductions,
};
pub use circuit::{SlotDescriptor, SpineCircuit, SpineInputs};
pub use circuit_sweep::{
    SweepSlotDescriptor, SweepSpineCircuit, SweepSpineInputs, SweepSpineSlotRole,
    N_SWEEP_SPINE_SLOTS,
};
pub use layers::{evaluate_permutation, round_kind, PermLayerWitness, RoundKind};
pub use merkle_circuit::{
    MerkleCircuit, MerklePathInputs, MerkleSlotDescriptor, MerkleSlotRole, MAX_MERKLE_DEPTH,
    N_MERKLE_SLOTS, N_PERMS_PER_COMPRESS,
};
pub use merkle_killshot::{
    build_merkle_unified_from_inputs, discharge_merkle_reductions_native, prove_merkle_killshot,
    verify_merkle_killshot, MerkleKillShotReductions, MerkleProofKillShot,
};
pub use merkle_mle::{
    build_merkle_unified_mle, MerkleUnifiedMle, N_MERKLE_MAX_LIVE_SLOTS, N_MERKLE_UNIFIED_CELLS,
    N_MERKLE_UNIFIED_VARS,
};
pub use merkle_oracle::{compute_merkle_root, evaluate_merkle, MerkleSlotState, MerkleWitness};
pub use merkle_unified::{
    prove_merkle_shift, prove_merkle_unified, verify_merkle_shift, verify_merkle_unified,
};
pub use mle_layout::{pack_column, PermColumn, PermMle, N_PERM_CELLS, N_PERM_VARS};
pub use oracle::{evaluate_spine, SpineWitness};
pub use oracle_sweep::{evaluate_sweep_spine, SweepSpineSlotState, SweepSpineWitness};
pub use owner_auth::{
    build_owner_auth_unified_from_inputs, build_owner_auth_unified_mle,
    compute_owner_auth_boundary, discharge_owner_auth_reductions_native, evaluate_owner_auth,
    owner_auth_gkr_channel, owner_auth_inputs_from_body_and_live_secrets,
    owner_auth_public_from_body, owner_auth_public_from_statement, prove_owner_auth_killshot,
    prove_owner_auth_killshot_from_mle, verify_owner_auth_killshot, OwnerAuthBoundaryProof,
    OwnerAuthBoundaryReduction, OwnerAuthCircuit, OwnerAuthInputs, OwnerAuthKillShotProof,
    OwnerAuthKillShotReductions, OwnerAuthLayout, OwnerAuthLayoutError, OwnerAuthProofKillShot,
    OwnerAuthPublicInputs, OwnerAuthShiftProof, OwnerAuthShiftReduction, OwnerAuthSlotDescriptor,
    OwnerAuthSlotRole, OwnerAuthSlotState, OwnerAuthStatementError, OwnerAuthUnifiedMle,
    OwnerAuthUnifiedProof, OwnerAuthUnifiedReduction, OwnerAuthWitness, OWNER_AUTH_MAX_OWNERS,
    OWNER_AUTH_MIN_OWNERS, OWNER_AUTH_PIN_LANES, OWNER_AUTH_SHIFT_ROUND_DEGREE,
    OWNER_AUTH_SLOTS_PER_OWNER, OWNER_AUTH_STATE_ROUND_DEGREE, OWNER_AUTH_UNIFIED_ROUND_DEGREE,
};
pub use spine_degree7::{
    prove_spine_degree7, verify_spine_degree7, SpineD7Proof, SpineD7Reduction,
    SPINE_D7_ROUND_DEGREE,
};
pub use spine_killshot::{
    build_unified_from_inputs, build_unified_from_states, discharge_reductions_native,
    prove_spine_killshot, prove_spine_killshot_with_states, verify_spine_killshot,
    SpineKillShotReductions, SpineProofKillShot,
};
pub use spine_killshot_sweep::{
    build_sweep_spine_unified_from_inputs, build_sweep_spine_unified_from_states,
    discharge_sweep_spine_reductions_native, prove_sweep_spine_killshot,
    prove_sweep_spine_killshot_with_states, verify_sweep_spine_killshot,
    SweepSpineKillShotReductions, SweepSpineProofKillShot,
};
pub use spine_mle::{
    build_unified_mle, sigma_at, SpineUnifiedMle, N_SPINE_ELEM_VARS, N_SPINE_ROUND_VARS,
    N_SPINE_SLOT_VARS, N_SPINE_UNIFIED_CELLS, N_SPINE_UNIFIED_VARS,
};
pub use spine_mle_sweep::{
    build_sweep_spine_unified_mle, sweep_spine_sigma_at, SweepSpineUnifiedMle,
    N_SWEEP_SPINE_ELEM_VARS, N_SWEEP_SPINE_ROUND_VARS, N_SWEEP_SPINE_SLOT_VARS,
    N_SWEEP_SPINE_UNIFIED_CELLS, N_SWEEP_SPINE_UNIFIED_VARS,
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
pub use spine_sumcheck::{
    build_boundary_mle, compute_tx_body_hash, discharge_boundary_native, reconstruct_slot_states,
    N_BOUNDARY_CELLS, N_BOUNDARY_VARS, N_SLOT_VARS, N_SPINE_SLOTS, N_SPINE_SLOTS_PADDED,
};
pub use spine_sumcheck_sweep::{
    build_sweep_boundary_mle, compute_sweep_tx_body_hash, discharge_sweep_boundary_native,
    reconstruct_sweep_spine_slot_states, N_SWEEP_BOUNDARY_CELLS, N_SWEEP_BOUNDARY_VARS,
    N_SWEEP_SLOT_VARS, N_SWEEP_SPINE_SLOTS_PADDED,
};
pub use spine_unified::{
    prove_spine_shift, prove_spine_unified, prove_spine_unified_for_live_slots, verify_spine_shift,
    verify_spine_unified, verify_spine_unified_for_live_slots, SpineKillShotProof, SpineShiftProof,
    SpineShiftReduction, SpineUnifiedProof, SpineUnifiedReduction, N_UNIFIED_WITNESS_CLAIMS,
    SPINE_SHIFT_ROUND_DEGREE, SPINE_UNIFIED_ROUND_DEGREE,
};
pub use spine_unified_sweep::{
    prove_sweep_spine_shift, prove_sweep_spine_unified, prove_sweep_spine_unified_for_live_slots,
    verify_sweep_spine_shift, verify_sweep_spine_unified,
    verify_sweep_spine_unified_for_live_slots, SweepSpineKillShotProof, SweepSpineShiftProof,
    SweepSpineShiftReduction, SweepSpineUnifiedProof, SweepSpineUnifiedReduction,
    N_SWEEP_UNIFIED_WITNESS_CLAIMS, SWEEP_SPINE_SHIFT_ROUND_DEGREE,
    SWEEP_SPINE_UNIFIED_ROUND_DEGREE,
};
pub use sweep_spine_statement::{sweep_spine_inputs_from_body, SweepSpineStatementError};
pub use wallet_authorization::{
    max_authorization_bytes_for_shape, prove_wallet_authorization, verify_wallet_authorization,
    verify_wallet_authorization_proof, AuthorizationDecodeError, AuthorizationEncodeError,
    ProveAuthorizationError, VerifyAuthorizationError, WalletAuthorizationBundle,
    MAX_AUTHORIZATION_BUNDLE_BYTES, MAX_STANDARD_AUTHORIZATION_BYTES,
    MAX_SWEEP_AUTHORIZATION_BYTES,
};
