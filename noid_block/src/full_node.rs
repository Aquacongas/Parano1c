// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Full-node block proof orchestration (S.6).
//!
//! Combines LogicProof verification, BlockStateBinding, and the Stage G
//! deferred-opening BlockProof into a single coherent pipeline.
//!
//! # Full-node prove flow
//!
//! 1. Verify each wallet-submitted `LogicProof` against its `PublicInputs`.
//! 2. Build `BlockStateBinding` — opens slots, verifies pre/post state,
//!    bridges `C_claimed`.
//! 3. Derive Fiat-Shamir challenges for the state binding AIR.
//! 4. Build `BlockStateBindingAir` + witness, generate trace columns.
//! 5. Produce the `BlockProof` (deferred-opening aggregation over all txs
//!    + state binding AIR participant).
//!
//! # Full-node verify flow
//!
//! 1. Verify `BlockStateBinding` final root matches the block header's
//!    `new_state_root`.
//! 2. Reconstruct `BlockStateBindingAir` from public data (claims + challenges).
//! 3. Verify the cryptographic `BlockProof` (GKR + algebraic STARK + FRI).

#![allow(clippy::too_many_arguments)]

use noid_air::airs::block_state_binding::{
    BlockStateBindingAir, BlockStateBindingClaim, BlockStateBindingWitness,
};
use noid_air::Air;
use noid_chain::fri_state::FriState;
use noid_chain::state_binding::{BlockStateBinding, StateBindingError};
use noid_core::mle::evaluate::evaluate_slice;
use noid_core::Block128;
use noid_fri::Channel;
use noid_gkr::{AuthPublicInputs, SpineInputs};
use noid_stark::prove_logic::{verify_logic, LogicProof, VerifyLogicError};
use noid_tx::{compute_claims_commitment, PublicInputs, TxBody};

use crate::{
    prove_block, verify_block, BlockProof, ProveBlockError, StateBindingBlockWitness,
    TxBlockWitness, VerifyBlockError,
};

const STATE_BINDING_CHANNEL_TAG: u128 = 0xFFFC_5B00_0000_0000;

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum FullNodeProveError {
    LogicProofInvalid { tx_index: usize, inner: VerifyLogicError },
    StateBinding(StateBindingError),
    BlockProof(ProveBlockError),
}

#[derive(Debug)]
pub enum FullNodeVerifyError {
    StateBinding(StateBindingError),
    StateRootMismatch,
    BlockProof(VerifyBlockError),
}

impl From<StateBindingError> for FullNodeProveError {
    fn from(e: StateBindingError) -> Self {
        Self::StateBinding(e)
    }
}

impl From<ProveBlockError> for FullNodeProveError {
    fn from(e: ProveBlockError) -> Self {
        Self::BlockProof(e)
    }
}

impl From<StateBindingError> for FullNodeVerifyError {
    fn from(e: StateBindingError) -> Self {
        Self::StateBinding(e)
    }
}

impl From<VerifyBlockError> for FullNodeVerifyError {
    fn from(e: VerifyBlockError) -> Self {
        Self::BlockProof(e)
    }
}

// ---------------------------------------------------------------------------
// Full prove result
// ---------------------------------------------------------------------------

/// Output of the full-node prove pipeline.
pub struct FullBlockProof {
    /// Cryptographic block proof (deferred-opening aggregation).
    pub block_proof: BlockProof,
    /// State binding: opened slots + state transition data.
    pub state_binding: BlockStateBinding,
}

// ---------------------------------------------------------------------------
// State binding AIR construction helpers
// ---------------------------------------------------------------------------

/// Build `BlockStateBindingClaim`s from transaction bodies.
/// Order: for each tx in sequence, all valid inputs (spend) then all valid
/// outputs (mint). This matches the order used by `BlockStateBinding::build`.
fn build_claims_from_bodies(bodies: &[TxBody]) -> Vec<BlockStateBindingClaim> {
    let mut claims = Vec::new();
    for body in bodies {
        for inp in body.inputs.iter().filter(|i| i.valid) {
            let [owner_hi, owner_lo] = inp.owner.as_fields();
            claims.push(BlockStateBindingClaim::spend(
                inp.slot_index,
                Block128::from(inp.value as u128),
                owner_hi,
                owner_lo,
            ));
        }
        for out in body.outputs.iter().filter(|o| o.valid) {
            let [owner_hi, owner_lo] = out.owner.as_fields();
            claims.push(BlockStateBindingClaim::mint(
                out.slot_index,
                Block128::from(out.value as u128),
                owner_hi,
                owner_lo,
            ));
        }
    }
    claims
}

/// Derive `eval_point` and `gamma` for the state binding AIR via
/// Fiat-Shamir. Seeded with `prev_state_root` and the claims data so
/// both prover and verifier reproduce identical challenges.
fn derive_state_binding_challenges(
    prev_state_root: &[u8; 32],
    claims: &[BlockStateBindingClaim],
    log_slots: usize,
) -> (Vec<Block128>, Block128) {
    let mut ch = Channel::new();
    ch.observe_field_elem(Block128::from(STATE_BINDING_CHANNEL_TAG));

    let lo = u128::from_le_bytes(prev_state_root[..16].try_into().unwrap());
    let hi = u128::from_le_bytes(prev_state_root[16..].try_into().unwrap());
    ch.observe_field_elem(Block128::from(lo));
    ch.observe_field_elem(Block128::from(hi));

    ch.observe_field_elem(Block128::from(claims.len() as u128));
    ch.observe_field_elem(Block128::from(log_slots as u128));

    for c in claims {
        ch.observe_field_elem(Block128::from(c.slot_index as u128));
        ch.observe_field_elem(c.value);
        ch.observe_field_elem(c.owner_hi);
        ch.observe_field_elem(c.owner_lo);
        let action = if c.is_spend { 1u128 } else if c.is_mint { 2u128 } else { 0u128 };
        ch.observe_field_elem(Block128::from(action));
    }

    let eval_point = ch.get_random_points(log_slots);
    let gamma = ch.get_random_point();
    (eval_point, gamma)
}

/// Evaluate the three state columns at a random point (MLE evaluation).
fn eval_state_columns_at(state: &FriState, point: &[Block128]) -> [Block128; 3] {
    let (values, owners_hi, owners_lo) = state.columns();
    [
        evaluate_slice(values, point),
        evaluate_slice(owners_hi, point),
        evaluate_slice(owners_lo, point),
    ]
}

/// Build the full state binding witness and AIR from chain-level data.
/// Returns `(air, columns)` ready for `StateBindingBlockWitness`.
fn build_state_binding_air_and_columns(
    prev_state_root: &[u8; 32],
    prev_state: &FriState,
    new_state: &FriState,
    bodies: &[TxBody],
) -> (BlockStateBindingAir, Vec<Vec<Block128>>) {
    let log_slots = prev_state.log_slots();
    let claims = build_claims_from_bodies(bodies);
    let (eval_point, gamma) = derive_state_binding_challenges(prev_state_root, &claims, log_slots);

    let prev_lane_openings = eval_state_columns_at(prev_state, &eval_point);
    let new_lane_openings = eval_state_columns_at(new_state, &eval_point);

    let witness = BlockStateBindingWitness::new(
        claims.clone(),
        eval_point.clone(),
        gamma,
        prev_lane_openings,
        new_lane_openings,
    );

    let expected_batched = witness.expected_batched_claims();

    let air = BlockStateBindingAir::new(
        &claims,
        prev_lane_openings,
        new_lane_openings,
        &eval_point,
        gamma,
        expected_batched,
    );

    let columns = air.build_trace(&witness);
    (air, columns)
}

/// Reconstruct the `BlockStateBindingAir` on the verifier side (no state
/// columns needed — only the public claim data).
fn reconstruct_state_binding_air(
    prev_state_root: &[u8; 32],
    prev_lane_openings: [Block128; 3],
    new_lane_openings: [Block128; 3],
    bodies: &[TxBody],
    log_slots: usize,
) -> BlockStateBindingAir {
    let claims = build_claims_from_bodies(bodies);
    let (eval_point, gamma) = derive_state_binding_challenges(prev_state_root, &claims, log_slots);

    let witness = BlockStateBindingWitness::new(
        claims.clone(),
        eval_point.clone(),
        gamma,
        prev_lane_openings,
        new_lane_openings,
    );
    let expected_batched = witness.expected_batched_claims();

    BlockStateBindingAir::new(
        &claims,
        prev_lane_openings,
        new_lane_openings,
        &eval_point,
        gamma,
        expected_batched,
    )
}

// ---------------------------------------------------------------------------
// prove_block_full
// ---------------------------------------------------------------------------

/// Full-node block production pipeline.
///
/// Takes validated `LogicProof`s from wallets plus the miner's full state
/// and produces both the cryptographic `BlockProof` and the `BlockStateBinding`.
///
/// PRIVACY: The block prover receives `AuthPublicInputs` (no spend_secret)
/// plus pre-built auth proofs from wallets. Private keys never leave the
/// wallet.
///
/// # Arguments
///
/// - `airs`: Per-transaction AIR instances (one per tx in the block).
/// - `state`: Mutable reference to the full-node's FRI-committed state.
///   On success, this is updated to reflect all applied transactions.
/// - `bodies`: Transaction bodies in block order.
/// - `logic_proofs`: Wallet-produced stateless proofs (one per tx).
/// - `pis`: PublicInputs for each tx (carries claims_commitment).
/// - `spine_inputs_list`: SpineGKR inputs (one per tx).
/// - `auth_public_list`: Public-only auth boundary (one per tx, no secrets).
/// - `witnesses`: Per-tx block witnesses for the deferred-opening pipeline.
pub fn prove_block_full<'a>(
    airs: &[&dyn Air],
    state: &mut FriState,
    bodies: &[TxBody],
    logic_proofs: &[LogicProof],
    pis: &[PublicInputs],
    spine_inputs_list: &[SpineInputs],
    auth_public_list: &[AuthPublicInputs],
    witnesses: &[TxBlockWitness<'a>],
) -> Result<FullBlockProof, FullNodeProveError> {
    let n_tx = bodies.len();
    assert_eq!(airs.len(), n_tx);
    assert_eq!(logic_proofs.len(), n_tx);
    assert_eq!(pis.len(), n_tx);
    assert_eq!(spine_inputs_list.len(), n_tx);
    assert_eq!(auth_public_list.len(), n_tx);
    assert_eq!(witnesses.len(), n_tx);

    // Step 1: Verify each LogicProof.
    for k in 0..n_tx {
        verify_logic(airs[k], &pis[k], &spine_inputs_list[k], &auth_public_list[k], &logic_proofs[k])
            .map_err(|e| FullNodeProveError::LogicProofInvalid { tx_index: k, inner: e })?;
    }

    // Step 2: Build BlockStateBinding (applies state transitions).
    // Snapshot pre-state for MLE evaluation.
    let prev_state_root = state.root();
    let prev_state_snapshot = state.clone();

    let commitments: Vec<_> = bodies
        .iter()
        .map(|b| compute_claims_commitment(&b.inputs, &b.outputs))
        .collect();
    let state_binding = BlockStateBinding::build(state, bodies, &commitments)?;

    // Step 3: Build state binding AIR + witness columns.
    let (sb_air, sb_columns) = build_state_binding_air_and_columns(
        &prev_state_root,
        &prev_state_snapshot,
        state,
        bodies,
    );

    let sb_witness = StateBindingBlockWitness {
        air: &sb_air,
        columns: sb_columns,
    };

    // Step 4: Produce the deferred-opening BlockProof with state binding.
    let block_proof = prove_block(prev_state_root, witnesses, Some(&sb_witness))?;

    Ok(FullBlockProof {
        block_proof,
        state_binding,
    })
}

// ---------------------------------------------------------------------------
// verify_block_full
// ---------------------------------------------------------------------------

/// Full-node block verification pipeline.
///
/// Verifies both the state binding (slot opens + C_claimed bridge + state
/// transition) and the cryptographic block proof (GKR + STARK + FRI).
///
/// PRIVACY: Accepts `AuthPublicInputs` only — no spend_secret ever reaches
/// the verifier.
///
/// # Arguments
///
/// - `airs`: Per-transaction AIR instances (one per tx in the block).
/// - `full_proof`: The combined proof bundle.
/// - `expected_new_state_root`: The block header's declared new_state_root.
/// - `spine_inputs_list`: SpineGKR inputs (one per tx).
/// - `auth_public_list`: Public-only auth boundary (one per tx, no secrets).
/// - `bodies`: Transaction bodies (needed to reconstruct the state binding AIR).
/// - `prev_lane_openings`: MLE evaluations of the pre-state columns at the
///   Fiat-Shamir eval_point (provided by the block producer alongside the proof).
/// - `new_lane_openings`: MLE evaluations of the post-state columns.
/// - `log_slots`: The state depth (log2 of state vector length).
pub fn verify_block_full(
    airs: &[&dyn Air],
    full_proof: &FullBlockProof,
    expected_new_state_root: &[u8; 32],
    spine_inputs_list: &[SpineInputs],
    auth_public_list: &[AuthPublicInputs],
    bodies: &[TxBody],
    prev_lane_openings: [Block128; 3],
    new_lane_openings: [Block128; 3],
    log_slots: usize,
) -> Result<(), FullNodeVerifyError> {
    let bp = &full_proof.block_proof;
    let sb = &full_proof.state_binding;

    // Cross-check: state binding prev_state_root must match block proof meta.
    if sb.prev_state_root != bp.meta.prev_block_state_root {
        return Err(FullNodeVerifyError::StateRootMismatch);
    }

    // Cross-check: transaction count consistency.
    if sb.tx_openings.len() != bp.meta.n_tx as usize {
        return Err(FullNodeVerifyError::StateBinding(StateBindingError::FinalRootMismatch));
    }

    // Step 1: Verify state binding final root.
    sb.verify_final_root(expected_new_state_root)
        .map_err(|_| FullNodeVerifyError::StateRootMismatch)?;

    // Step 2: Reconstruct the BlockStateBindingAir from public data.
    let sb_air = reconstruct_state_binding_air(
        &bp.meta.prev_block_state_root,
        prev_lane_openings,
        new_lane_openings,
        bodies,
        log_slots,
    );

    // Step 3: Verify the cryptographic block proof.
    verify_block(
        airs,
        bp,
        spine_inputs_list,
        auth_public_list,
        Some(&sb_air),
    )?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_node_error_types_are_debug() {
        let e = FullNodeProveError::StateBinding(StateBindingError::FinalRootMismatch);
        let _ = format!("{:?}", e);
        let e2 = FullNodeVerifyError::StateRootMismatch;
        let _ = format!("{:?}", e2);
    }
}
