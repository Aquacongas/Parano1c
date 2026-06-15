// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! GKR-based proving for the Paranoid transaction system.
//!
//! This crate implements the Kill-Shot GKR protocol for Poseidon2b
//! permutation chains. It provides:
//!
//! - **Auth GKR**: proves spend-secret ownership via 20 Poseidon2b
//!   permutations (4 inputs × 5 perms each).
//! - **Block Spine GKR**: a single unified Kill-Shot for N×59 permutations
//!   across all transactions in a block, with proof size and verification
//!   cost growing O(log N) rather than O(N).
//! - **Merkle GKR**: proves the tx-body Merkle tree hash (59-perm chain).
//!
//! See `SPEC.md` and `AUDIT.md` in this crate for the cryptographic
//! specification and security analysis.

pub mod auth_circuit;
pub mod auth_killshot;
pub mod auth_mle_v2;
pub mod auth_oracle;
pub mod auth_shift;
pub mod auth_unified_v2;
pub mod batch_eval;
pub mod binding;
pub mod block_spine;
pub mod circuit;
pub mod layers;
pub mod merkle_circuit;
pub mod merkle_killshot;
pub mod merkle_mle;
pub mod merkle_oracle;
pub mod merkle_shift;
pub mod merkle_unified;
pub mod mle_layout;
pub mod oracle;
pub mod spine_degree7;
pub mod spine_killshot;
pub mod spine_mle;
pub mod spine_shift;
pub mod spine_sumcheck;
pub mod spine_unified;

pub use auth_circuit::{
    AuthCircuit, AuthInputs, AuthPublicInputs, AuthSlotDescriptor, AuthSlotRole, AUTH_PAD_0,
    AUTH_PAD_1, N_AUTH_INPUTS, N_AUTH_SLOTS, N_SLOTS_PER_INPUT,
};
pub use auth_killshot::{
    auth_gkr_channel, build_auth_unified_from_inputs, discharge_auth_reductions_native,
    prove_auth_killshot, prove_auth_killshot_with_mle, verify_auth_killshot,
    AuthKillShotReductions, AuthProofKillShot,
};
pub use auth_mle_v2::{
    build_auth_unified_mle_v2, AuthUnifiedMle, N_AUTH_LIVE_SLOTS, N_AUTH_UNIFIED_CELLS,
    N_AUTH_UNIFIED_VARS,
};
pub use auth_oracle::{compute_auth_boundary, evaluate_auth, AuthSlotState, AuthWitness};
pub use auth_unified_v2::{
    prove_auth_shift, prove_auth_unified, verify_auth_shift, verify_auth_unified,
    AuthKillShotProof, AuthShiftProof, AuthShiftReduction, AuthUnifiedProof, AuthUnifiedReduction,
    AUTH_SHIFT_ROUND_DEGREE, AUTH_UNIFIED_ROUND_DEGREE,
};
pub use batch_eval::{
    prove_batch_eval, verify_batch_eval, BatchEvalProof, BatchEvalReduction, BatchEvalRound,
    EvalClaim,
};
pub use binding::BindingCut;
pub use block_spine::{
    discharge_block_spine_reductions_native, prove_block_spine_killshot,
    verify_block_spine_killshot, BlockSpineKillShotProof, BlockSpineMle, BlockSpineProof,
    BlockSpineReductions, BlockSpineShiftProof, BlockSpineShiftReduction, BlockSpineUnifiedProof,
    BlockSpineUnifiedReduction, BLOCK_SPINE_ROUND_DEGREE, BLOCK_SPINE_SHIFT_DEGREE,
};
pub use circuit::{SlotDescriptor, SpineCircuit, SpineInputs};
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
pub use spine_degree7::{
    prove_spine_degree7, verify_spine_degree7, SpineD7Proof, SpineD7Reduction,
    SPINE_D7_ROUND_DEGREE,
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
