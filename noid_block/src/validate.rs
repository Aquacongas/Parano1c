// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Full proof-native block validation.
//!
//! `validate_block_full` is the complete user-transaction validation pipeline
//! for a full node receiving a block from the network:
//!
//! 1. `validate_block_checks()` — cheap header/PoW/fee checks.
//! 2. Verify the detached minimal `BlockProof` and Auth sidecar: exact public
//!    transaction predicates, wallet authorization capsules, and exact
//!    authenticated state transition.
//! 3. Commit the already-verified exact transition without
//!    running native `apply_block` as a second validity source.
//!
//! # OwnerAuthPublicInputs reconstruction
//!
//! `OwnerAuthPublicInputs` are reconstructed from each transaction body and
//! verified through an authorization verifier interface. The block validator
//! does not parse the internal authorization relation; it only checks that the
//! canonical statement verifies against the sidecar proof.
//!
//! The `spend_secret` (private key) is NEVER transmitted, NEVER accessed
//! here, and NEVER needed for verification.

use noid_chain::block::{compute_tx_root, validate_block_proof_binding, Block};
use noid_chain::block_header::BlockHeader;
use noid_chain::consensus::validation::{
    validate_block_checks, validate_block_checks_timeless, validate_block_resource_preflight,
    validate_mandatory_coinbase, AnchorInfo,
};
use noid_chain::consensus::wire_limits::{
    block_resource_weight_ok, proof_sidecar_combined_len_ok, MAX_BLOCK_AUTH_SIDECAR_BYTES,
    MAX_BLOCK_PROOF_BYTES,
};
use noid_chain::consensus::ConsensusError;
use noid_chain::state::ChainState;
use noid_chain::state_delta::{build_exact_action_surface, ExactActionSurface, StateDeltaError};

use crate::{BlockAuthSidecar, BlockProof, VerifyBlockError};

use noid_gkr::{
    canonical_authorization_statement_from_body, verify_authorization_statement_proof,
    VerifyAuthorizationError,
};
use noid_tx::{validate_public_tx_logic, Transaction};
use rayon::prelude::*;

/// Exact transaction-epoch public input for one candidate block.
///
/// This is deliberately separate from ASERT [`AnchorInfo`]. The owning chain
/// context resolves it from the canonical header at the current 144-block
/// boundary before calling any standalone proof-native acceptance entrypoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockTxEpochContext {
    pub expected_user_epoch_anchor_id: [u8; 32],
}

fn validate_tx_epoch_context(
    block: &Block,
    parent: &BlockHeader,
    context: &BlockTxEpochContext,
) -> Result<(), FullValidationError> {
    noid_chain::consensus::validate_block_epoch_anchors(
        block,
        context.expected_user_epoch_anchor_id,
        noid_chain::consensus::pow::block_id(parent),
    )
    .map_err(FullValidationError::Consensus)
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Error returned by `validate_block_full`.
#[derive(Debug)]
pub enum FullValidationError {
    /// Native consensus check failed.
    Consensus(ConsensusError),
    /// BlockProof verification failed.
    ZkProof(VerifyBlockError),
}

impl From<ConsensusError> for FullValidationError {
    fn from(e: ConsensusError) -> Self {
        Self::Consensus(e)
    }
}
impl From<VerifyBlockError> for FullValidationError {
    fn from(e: VerifyBlockError) -> Self {
        Self::ZkProof(e)
    }
}

impl std::fmt::Display for FullValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Consensus(e) => write!(f, "consensus: {e}"),
            Self::ZkProof(e) => write!(f, "zk_proof: {e:?}"),
        }
    }
}
impl std::error::Error for FullValidationError {}

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

pub use noid_gkr::{
    CanonicalAuthorizationStatement, VerifiedAuthorization, VerifiedAuthorizationBatch,
};

pub type AuthorizationProof = noid_gkr::OwnerAuthProofKillShot;

#[derive(Debug, Clone)]
pub struct AcceptedBlockValidationArtifacts {
    pub authorization: VerifiedAuthorizationBatch,
    pub exact_state_inputs: crate::ExactStateTransitionInputs,
    pub exact_action_surface: ExactActionSurface,
    pub verified_transition: crate::VerifiedStateTransition,
}

#[derive(Debug, Clone)]
pub struct AcceptedBlockValidationOutput {
    pub state_root: [u8; 32],
    pub artifacts: AcceptedBlockValidationArtifacts,
}

#[derive(Debug, Clone)]
pub struct AcceptedBlockRawValidationOutput {
    pub state_root: [u8; 32],
    pub artifacts: AcceptedBlockValidationArtifacts,
}

pub trait AuthorizationVerifier: Sync {
    fn verify(
        &self,
        statement: &CanonicalAuthorizationStatement,
        proof: &AuthorizationProof,
    ) -> Result<VerifiedAuthorization, VerifyBlockError>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct OwnerAuthAuthorizationVerifier;

impl AuthorizationVerifier for OwnerAuthAuthorizationVerifier {
    fn verify(
        &self,
        statement: &CanonicalAuthorizationStatement,
        proof: &AuthorizationProof,
    ) -> Result<VerifiedAuthorization, VerifyBlockError> {
        verify_authorization_statement_proof(statement, proof)
            .map_err(|error| map_verify_authorization_error(error, statement.tx_index))
    }
}

/// [`AuthorizationVerifier`] with a byte-exact fast path over authorizations
/// this node already verified — at mempool admission. A hit requires the
/// serialized proof to EQUAL the bytes verified earlier for the same tx body
/// hash, so proof validity stays consensus-exact (a block carrying any other
/// proof for the same statement falls back to full verification); the
/// statement's remaining fields are reconstructed from the block body by the
/// caller either way.
pub struct PreverifiedAuthorizationVerifier<'a> {
    /// tx body hash -> the serialized proof verified at admission.
    pub verified_proof_bytes: &'a std::collections::HashMap<[u8; 32], Vec<u8>>,
}

impl AuthorizationVerifier for PreverifiedAuthorizationVerifier<'_> {
    fn verify(
        &self,
        statement: &CanonicalAuthorizationStatement,
        proof: &AuthorizationProof,
    ) -> Result<VerifiedAuthorization, VerifyBlockError> {
        let mut body_hash = [0u8; 32];
        body_hash[..16].copy_from_slice(&statement.tx_body_hash[0].0.to_le_bytes());
        body_hash[16..].copy_from_slice(&statement.tx_body_hash[1].0.to_le_bytes());
        if let Some(known) = self.verified_proof_bytes.get(&body_hash) {
            if let Some(bytes) = noid_gkr::authorization_proof_wire_bytes(proof) {
                if bytes == *known {
                    noid_gkr::validate_authorization_statement(statement).map_err(|error| {
                        map_verify_authorization_error(error, statement.tx_index)
                    })?;
                    return Ok(VerifiedAuthorization {
                        tx_index: statement.tx_index,
                        live_input_count: usize::from(statement.live_input_count),
                    });
                }
            }
        }
        OwnerAuthAuthorizationVerifier.verify(statement, proof)
    }
}

/// Map [`VerifyAuthorizationError`] to the block-level error exactly as the
/// production `AcceptBlock` authorization step reports it. Shared by every
/// [`AuthorizationVerifier`] implementation so error semantics cannot drift.
pub(crate) fn map_verify_authorization_error(
    error: VerifyAuthorizationError,
    tx_index: usize,
) -> VerifyBlockError {
    match error {
        VerifyAuthorizationError::AuthProof => VerifyBlockError::AuthKillShot(tx_index),
        VerifyAuthorizationError::OwnerAuthStatement(_)
        | VerifyAuthorizationError::PublicLogic(_) => VerifyBlockError::AuthSpineBridge(tx_index),
    }
}

/// Full proof-native block validation.
///
/// Steps (ordered cheapest-first):
/// 1. `validate_block_checks()` — cheap consensus checks that do not mutate state.
/// 2. Minimal `BlockProof` verification: exact public tx predicates, sidecar
///    authorization, and exact authenticated state transition.
/// 3. Apply the verified exact transition to the mutable chain state.
///
/// On success, `state` is updated to the post-block UTXO state.
/// On failure, callers restore the pre-validation state snapshot.
#[allow(clippy::too_many_arguments)]
pub fn validate_block_full(
    block: &Block,
    proof: &BlockProof,
    auth_sidecar: &BlockAuthSidecar,
    parent: &BlockHeader,
    prev_timestamps: &[u64],
    // active_slot_count values from the last EXPANSION_WINDOW finalised headers.
    // Pass &[parent.active_slot_count] when the full window is not available.
    prev_active_counts: &[u64],
    local_time: u64,
    tx_epoch: &BlockTxEpochContext,
    anchor: &AnchorInfo,
    state: &mut ChainState,
) -> Result<[u8; 32], FullValidationError> {
    validate_block_resource_preflight(block).map_err(FullValidationError::Consensus)?;
    validate_tx_epoch_context(block, parent, tx_epoch)?;
    validate_block_full_inner(
        block,
        proof,
        auth_sidecar,
        parent,
        prev_timestamps,
        prev_active_counts,
        TimestampPolicy::Live(local_time),
        anchor,
        state,
        &OwnerAuthAuthorizationVerifier,
    )
    .map(|output| output.state_root)
}

/// Timeless form of the production `AcceptBlock` predicate for recursive
/// history proofs.
///
/// This verifies the same proof-native block validity relation as
/// [`validate_block_full`] while excluding only the local wall-clock
/// future-drift admission policy.
#[allow(clippy::too_many_arguments)]
pub fn validate_block_full_timeless(
    block: &Block,
    proof: &BlockProof,
    auth_sidecar: &BlockAuthSidecar,
    parent: &BlockHeader,
    prev_timestamps: &[u64],
    prev_active_counts: &[u64],
    tx_epoch: &BlockTxEpochContext,
    anchor: &AnchorInfo,
    state: &mut ChainState,
) -> Result<[u8; 32], FullValidationError> {
    validate_block_full_timeless_with_artifacts(
        block,
        proof,
        auth_sidecar,
        parent,
        prev_timestamps,
        prev_active_counts,
        tx_epoch,
        anchor,
        state,
    )
    .map(|output| output.state_root)
}

/// Timeless form of [`validate_block_full_timeless`] that also returns the
/// proof-facing artifacts reconstructed by `AcceptBlock`.
#[allow(clippy::too_many_arguments)]
pub fn validate_block_full_timeless_with_artifacts(
    block: &Block,
    proof: &BlockProof,
    auth_sidecar: &BlockAuthSidecar,
    parent: &BlockHeader,
    prev_timestamps: &[u64],
    prev_active_counts: &[u64],
    tx_epoch: &BlockTxEpochContext,
    anchor: &AnchorInfo,
    state: &mut ChainState,
) -> Result<AcceptedBlockValidationOutput, FullValidationError> {
    validate_block_resource_preflight(block).map_err(FullValidationError::Consensus)?;
    validate_tx_epoch_context(block, parent, tx_epoch)?;
    validate_block_full_inner(
        block,
        proof,
        auth_sidecar,
        parent,
        prev_timestamps,
        prev_active_counts,
        TimestampPolicy::Timeless,
        anchor,
        state,
        &OwnerAuthAuthorizationVerifier,
    )
}

#[derive(Debug, Clone, Copy)]
enum TimestampPolicy {
    Live(u64),
    Timeless,
}

/// Pin the mutable native state snapshot to the parent header before deriving
/// any action surface from it.  A root-only check is insufficient: depth and
/// both monotone counters affect slot interpretation and the child boundary.
fn validate_parent_state_boundary(
    parent: &BlockHeader,
    state: &ChainState,
) -> Result<(), FullValidationError> {
    let mismatch = if state.cached_state_root() != parent.state_root {
        Some("state_root")
    } else if state.state.log_slots() as u32 != parent.log_slots {
        Some("log_slots")
    } else if state.active_slot_count != parent.active_slot_count {
        Some("active_slot_count")
    } else if state.alloc_counter != parent.alloc_counter {
        Some("alloc_counter")
    } else {
        None
    };
    if let Some(field) = mismatch {
        return Err(FullValidationError::Consensus(
            noid_chain::consensus::ConsensusError::ShapeMismatch(format!(
                "parent ChainState {field} mismatch"
            )),
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_block_full_inner<V: AuthorizationVerifier>(
    block: &Block,
    proof: &BlockProof,
    auth_sidecar: &BlockAuthSidecar,
    parent: &BlockHeader,
    prev_timestamps: &[u64],
    prev_active_counts: &[u64],
    timestamp_policy: TimestampPolicy,
    anchor: &AnchorInfo,
    state: &mut ChainState,
    auth_verifier: &V,
) -> Result<AcceptedBlockValidationOutput, FullValidationError> {
    // Header + tx checks (cheap, fail-fast — no state reads, no apply_block).
    match timestamp_policy {
        TimestampPolicy::Live(local_time) => validate_block_checks(
            block,
            parent,
            prev_timestamps,
            prev_active_counts,
            local_time,
            anchor,
        )?,
        TimestampPolicy::Timeless => validate_block_checks_timeless(
            block,
            parent,
            prev_timestamps,
            prev_active_counts,
            anchor,
        )?,
    }
    if block.header.tx_root != compute_tx_root(&block.transactions) {
        return Err(FullValidationError::Consensus(
            noid_chain::consensus::ConsensusError::BadTxRoot,
        ));
    }
    validate_parent_state_boundary(parent, state)?;

    validate_minimal_block_proof_shape(block, proof).map_err(FullValidationError::ZkProof)?;
    if proof.meta.prev_block_state_root != parent.state_root {
        return Err(FullValidationError::ZkProof(
            crate::VerifyBlockError::PrevStateRootMismatch,
        ));
    }
    if proof.meta.new_state_root != block.header.state_root {
        return Err(FullValidationError::ZkProof(
            crate::VerifyBlockError::NewStateRootMismatch,
        ));
    }
    validate_block_public_logic(block).map_err(FullValidationError::ZkProof)?;
    let authorization =
        validate_block_authorizations_with_output(block, auth_sidecar, auth_verifier)
            .map_err(FullValidationError::ZkProof)?;

    let surface =
        build_exact_surface_for_block(block, state).map_err(FullValidationError::ZkProof)?;
    let inputs = crate::ExactStateTransitionInputs {
        parent_state_root: parent.state_root,
        parent_log_slots: state.state.log_slots() as u32,
        child_state_root: block.header.state_root,
        child_log_slots: block.header.log_slots,
        parent_active_slot_count: state.active_slot_count,
        parent_alloc_counter: state.alloc_counter,
    };
    let verified = crate::verify_exact_state_transition(&inputs, &surface, &proof.state_transition)
        .map_err(|e| {
            FullValidationError::ZkProof(crate::VerifyBlockError::ExactStateTransition(e))
        })?;

    if verified.active_slot_count() != block.header.active_slot_count {
        return Err(FullValidationError::Consensus(
            noid_chain::consensus::ConsensusError::ShapeMismatch(
                "active_slot_count mismatch".into(),
            ),
        ));
    }
    if verified.alloc_counter() != block.header.alloc_counter {
        return Err(FullValidationError::Consensus(
            noid_chain::consensus::ConsensusError::ShapeMismatch("alloc_counter mismatch".into()),
        ));
    }

    let applied_root = state
        .apply_verified_exact_transition(
            verified.log_slots(),
            verified.child_state_root(),
            verified.slot_updates(),
            verified.active_slot_count(),
            verified.alloc_counter(),
        )
        .map_err(|e| {
            FullValidationError::Consensus(noid_chain::consensus::ConsensusError::ShapeMismatch(
                format!("exact transition apply failed: {e:?}"),
            ))
        })?;
    if applied_root != block.header.state_root {
        return Err(FullValidationError::Consensus(
            noid_chain::consensus::ConsensusError::ShapeMismatch("state_root mismatch".into()),
        ));
    }

    Ok(AcceptedBlockValidationOutput {
        state_root: block.header.state_root,
        artifacts: AcceptedBlockValidationArtifacts {
            authorization,
            exact_state_inputs: inputs,
            exact_action_surface: surface,
            verified_transition: verified,
        },
    })
}

fn validate_minimal_block_proof_shape(
    block: &Block,
    proof: &BlockProof,
) -> Result<(), VerifyBlockError> {
    let expected_non_coinbase = block
        .transactions
        .iter()
        .filter(|tx| !tx.body.is_coinbase)
        .count();
    if proof.meta.n_tx as usize != expected_non_coinbase {
        return Err(VerifyBlockError::ShapeMismatch);
    }

    Ok(())
}

fn validate_block_public_logic(block: &Block) -> Result<(), VerifyBlockError> {
    let results: Vec<Result<(), VerifyBlockError>> = block
        .transactions
        .par_iter()
        .enumerate()
        .map(|(tx_index, tx)| {
            if tx.body.is_coinbase {
                return Ok(());
            }
            let facts = validate_public_tx_logic(&tx.body)
                .map_err(|error| VerifyBlockError::TxPublicLogic { tx_index, error })?;
            if tx.txid() != facts.tx_body_hash {
                return Err(VerifyBlockError::TxPublicInputsMismatch { tx_index });
            }
            Ok(())
        })
        .collect();
    results.into_iter().collect()
}

pub fn validate_block_authorizations<V: AuthorizationVerifier>(
    block: &Block,
    sidecar: &BlockAuthSidecar,
    verifier: &V,
) -> Result<(), VerifyBlockError> {
    validate_block_authorizations_with_output(block, sidecar, verifier).map(|_| ())
}

pub fn validate_block_authorizations_with_output<V: AuthorizationVerifier>(
    block: &Block,
    sidecar: &BlockAuthSidecar,
    verifier: &V,
) -> Result<VerifiedAuthorizationBatch, VerifyBlockError> {
    validate_block_auth_sidecar_shape(block, sidecar)?;
    let user_txs: Vec<(usize, &Transaction)> = block
        .transactions
        .iter()
        .enumerate()
        .filter(|(_, tx)| !tx.body.is_coinbase)
        .collect();
    if user_txs.len() != sidecar.tx_auth.len() {
        return Err(VerifyBlockError::AuthSidecarShapeMismatch);
    }

    let results: Vec<Result<VerifiedAuthorization, VerifyBlockError>> = user_txs
        .par_iter()
        .zip(sidecar.tx_auth.par_iter())
        .map(|((tx_index, tx), proof)| {
            let statement = canonical_authorization_statement_from_body(
                *tx_index,
                tx.txid().as_fields(),
                &tx.body,
            )
            .map_err(|_| VerifyBlockError::AuthSidecarShapeMismatch)?;
            verifier.verify(&statement, proof)
        })
        .collect();

    let mut live_input_count_total = 0usize;
    for verified in results {
        let verified = verified?;
        if verified.live_input_count == 0 {
            return Err(VerifyBlockError::AuthSidecarShapeMismatch);
        }
        live_input_count_total = live_input_count_total.saturating_add(verified.live_input_count);
    }

    Ok(VerifiedAuthorizationBatch {
        user_tx_count: user_txs.len(),
        live_input_count_total,
    })
}

fn build_exact_surface_for_block(
    block: &Block,
    state: &ChainState,
) -> Result<ExactActionSurface, VerifyBlockError> {
    let mut surface_state = state.state.clone();
    while surface_state.log_slots() < block.header.log_slots as usize {
        surface_state.expand();
    }
    if surface_state.log_slots() != block.header.log_slots as usize {
        return Err(VerifyBlockError::ShapeMismatch);
    }

    // Preserve the consensus block order exactly.  In particular the coinbase
    // is first, so its live outputs consume the first creation IDs.  Reordering
    // it behind user transactions would reconstruct a different packed state
    // surface even when every amount/owner/slot matched.
    let bodies: Vec<_> = block
        .transactions
        .iter()
        .map(|tx| tx.body.clone())
        .collect();
    let commitments: Vec<[u8; 32]> = bodies.iter().map(|body| body.claims_commitment()).collect();
    build_exact_action_surface(&surface_state, &bodies, &commitments, state.alloc_counter)
        .map_err(map_state_delta_error)
}

fn map_state_delta_error(err: StateDeltaError) -> VerifyBlockError {
    match err {
        StateDeltaError::InputMismatch {
            tx_index,
            input_index,
        } => VerifyBlockError::ExactStateSurfaceInputMismatch {
            tx_index,
            input_index,
        },
        StateDeltaError::OutputSlotOccupied {
            tx_index,
            output_index,
        } => VerifyBlockError::ExactStateSurfaceOutputOccupied {
            tx_index,
            output_index,
        },
        StateDeltaError::ClaimsCommitmentMismatch { tx_index } => {
            VerifyBlockError::ExactStateSurfaceClaimsCommitmentMismatch { tx_index }
        }
        StateDeltaError::DuplicateInputSlot { tx_index } => {
            VerifyBlockError::ExactStateSurfaceDuplicateInputSlot { tx_index }
        }
        StateDeltaError::DuplicateOutputSlot { tx_index } => {
            VerifyBlockError::ExactStateSurfaceDuplicateOutputSlot { tx_index }
        }
        StateDeltaError::InputOutputSlotOverlap { tx_index } => {
            VerifyBlockError::ExactStateSurfaceInputOutputSlotOverlap { tx_index }
        }
        StateDeltaError::BlockSlotConflict { tx_index, op_index } => {
            VerifyBlockError::ExactStateSurfaceBlockSlotConflict { tx_index, op_index }
        }
        StateDeltaError::SlotOutOfRange { tx_index } => {
            VerifyBlockError::ExactStateSurfaceSlotOutOfRange { tx_index }
        }
        StateDeltaError::AllocationCounterOverflow {
            tx_index,
            output_index,
        } => VerifyBlockError::ExactStateSurfaceAllocationCounterOverflow {
            tx_index,
            output_index,
        },
        StateDeltaError::ActionCountOverflow => {
            VerifyBlockError::ExactStateSurfaceActionCountOverflow
        }
    }
}

pub fn validate_block_auth_sidecar_shape(
    block: &Block,
    sidecar: &BlockAuthSidecar,
) -> Result<(), VerifyBlockError> {
    let user_tx_count = block
        .transactions
        .iter()
        .filter(|tx| !tx.body.is_coinbase)
        .count();
    if user_tx_count == 0 {
        if !sidecar.tx_auth.is_empty() {
            return Err(VerifyBlockError::AuthSidecarShapeMismatch);
        }
        return Ok(());
    }
    if sidecar.tx_auth.len() != user_tx_count {
        return Err(VerifyBlockError::AuthSidecarShapeMismatch);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Network-facing entry point
// ---------------------------------------------------------------------------

/// Normative production `AcceptBlock` predicate for a receiving full node.
///
/// Takes the raw `block_proof_bytes` received over P2P and:
/// 1. Deserialises the `BlockProof`.
/// 2. Reconstructs `OwnerAuthPublicInputs` and the exact state-transition
///    surface purely from the block's public wire data and the pre-block state.
/// 3. Calls `validate_block_full` (consensus + BlockProof + exact transition).
///
/// # Security
///
/// `spend_secret` is never accessed or needed. All inputs are reconstructed
/// from one-way hash outputs (`owner = H_ADDR(secret)`).
#[allow(clippy::too_many_arguments)]
pub fn accept_block(
    block: &Block,
    block_proof_bytes: &[u8],
    block_auth_sidecar_bytes: &[u8],
    parent: &BlockHeader,
    prev_timestamps: &[u64],
    prev_active_counts: &[u64],
    local_time: u64,
    tx_epoch: &BlockTxEpochContext,
    anchor: &AnchorInfo,
    state: &mut ChainState,
) -> Result<[u8; 32], FullValidationError> {
    accept_block_inner(
        block,
        block_proof_bytes,
        block_auth_sidecar_bytes,
        parent,
        prev_timestamps,
        prev_active_counts,
        TimestampPolicy::Live(local_time),
        tx_epoch,
        anchor,
        state,
    )
}

/// Live raw-witness `AcceptBlock` predicate that also returns proof-facing
/// artifacts for the history accumulator.
#[allow(clippy::too_many_arguments)]
pub fn accept_block_with_artifacts(
    block: &Block,
    block_proof_bytes: &[u8],
    block_auth_sidecar_bytes: &[u8],
    parent: &BlockHeader,
    prev_timestamps: &[u64],
    prev_active_counts: &[u64],
    local_time: u64,
    tx_epoch: &BlockTxEpochContext,
    anchor: &AnchorInfo,
    state: &mut ChainState,
) -> Result<AcceptedBlockRawValidationOutput, FullValidationError> {
    accept_block_inner_with_artifacts(
        block,
        block_proof_bytes,
        block_auth_sidecar_bytes,
        parent,
        prev_timestamps,
        prev_active_counts,
        TimestampPolicy::Live(local_time),
        tx_epoch,
        anchor,
        state,
        &OwnerAuthAuthorizationVerifier,
    )
}

/// [`accept_block_with_artifacts`] with a caller-supplied authorization
/// verifier (the node injects the mempool-preverified fast path here).
#[allow(clippy::too_many_arguments)]
pub fn accept_block_with_artifacts_with_auth_verifier<V: AuthorizationVerifier>(
    block: &Block,
    block_proof_bytes: &[u8],
    block_auth_sidecar_bytes: &[u8],
    parent: &BlockHeader,
    prev_timestamps: &[u64],
    prev_active_counts: &[u64],
    local_time: u64,
    tx_epoch: &BlockTxEpochContext,
    anchor: &AnchorInfo,
    state: &mut ChainState,
    auth_verifier: &V,
) -> Result<AcceptedBlockRawValidationOutput, FullValidationError> {
    accept_block_inner_with_artifacts(
        block,
        block_proof_bytes,
        block_auth_sidecar_bytes,
        parent,
        prev_timestamps,
        prev_active_counts,
        TimestampPolicy::Live(local_time),
        tx_epoch,
        anchor,
        state,
        auth_verifier,
    )
}

/// Timeless raw-witness `AcceptBlock` predicate for recursive batch witnesses.
///
/// This is identical to [`accept_block`] except that local future-drift
/// admission is excluded.
#[allow(clippy::too_many_arguments)]
pub fn accept_block_timeless(
    block: &Block,
    block_proof_bytes: &[u8],
    block_auth_sidecar_bytes: &[u8],
    parent: &BlockHeader,
    prev_timestamps: &[u64],
    prev_active_counts: &[u64],
    tx_epoch: &BlockTxEpochContext,
    anchor: &AnchorInfo,
    state: &mut ChainState,
) -> Result<[u8; 32], FullValidationError> {
    accept_block_inner(
        block,
        block_proof_bytes,
        block_auth_sidecar_bytes,
        parent,
        prev_timestamps,
        prev_active_counts,
        TimestampPolicy::Timeless,
        tx_epoch,
        anchor,
        state,
    )
}

/// Timeless raw-witness `AcceptBlock` predicate that also returns
/// proof-facing artifacts for user-transaction blocks.
#[allow(clippy::too_many_arguments)]
pub fn accept_block_timeless_with_artifacts(
    block: &Block,
    block_proof_bytes: &[u8],
    block_auth_sidecar_bytes: &[u8],
    parent: &BlockHeader,
    prev_timestamps: &[u64],
    prev_active_counts: &[u64],
    tx_epoch: &BlockTxEpochContext,
    anchor: &AnchorInfo,
    state: &mut ChainState,
) -> Result<AcceptedBlockRawValidationOutput, FullValidationError> {
    accept_block_timeless_with_artifacts_with_auth_verifier(
        block,
        block_proof_bytes,
        block_auth_sidecar_bytes,
        parent,
        prev_timestamps,
        prev_active_counts,
        tx_epoch,
        anchor,
        state,
        &OwnerAuthAuthorizationVerifier,
    )
}

/// [`accept_block_timeless_with_artifacts`] with a caller-supplied
/// authorization verifier.
///
/// The batch replay (`verify_full_accepted_block_batch_native`) injects a
/// tracing verifier here so each owner-auth killshot is verified exactly once,
/// with its FS transcript captured for the recursive component inputs, instead
/// of re-verifying the sidecar in a second pass.
#[allow(clippy::too_many_arguments)]
pub fn accept_block_timeless_with_artifacts_with_auth_verifier<V: AuthorizationVerifier>(
    block: &Block,
    block_proof_bytes: &[u8],
    block_auth_sidecar_bytes: &[u8],
    parent: &BlockHeader,
    prev_timestamps: &[u64],
    prev_active_counts: &[u64],
    tx_epoch: &BlockTxEpochContext,
    anchor: &AnchorInfo,
    state: &mut ChainState,
    auth_verifier: &V,
) -> Result<AcceptedBlockRawValidationOutput, FullValidationError> {
    accept_block_inner_with_artifacts(
        block,
        block_proof_bytes,
        block_auth_sidecar_bytes,
        parent,
        prev_timestamps,
        prev_active_counts,
        TimestampPolicy::Timeless,
        tx_epoch,
        anchor,
        state,
        auth_verifier,
    )
}

#[allow(clippy::too_many_arguments)]
fn accept_block_inner(
    block: &Block,
    block_proof_bytes: &[u8],
    block_auth_sidecar_bytes: &[u8],
    parent: &BlockHeader,
    prev_timestamps: &[u64],
    prev_active_counts: &[u64],
    timestamp_policy: TimestampPolicy,
    tx_epoch: &BlockTxEpochContext,
    anchor: &AnchorInfo,
    state: &mut ChainState,
) -> Result<[u8; 32], FullValidationError> {
    accept_block_inner_with_artifacts(
        block,
        block_proof_bytes,
        block_auth_sidecar_bytes,
        parent,
        prev_timestamps,
        prev_active_counts,
        timestamp_policy,
        tx_epoch,
        anchor,
        state,
        &OwnerAuthAuthorizationVerifier,
    )
    .map(|output| output.state_root)
}

#[allow(clippy::too_many_arguments)]
fn accept_block_inner_with_artifacts<V: AuthorizationVerifier>(
    block: &Block,
    block_proof_bytes: &[u8],
    block_auth_sidecar_bytes: &[u8],
    parent: &BlockHeader,
    prev_timestamps: &[u64],
    prev_active_counts: &[u64],
    timestamp_policy: TimestampPolicy,
    tx_epoch: &BlockTxEpochContext,
    anchor: &AnchorInfo,
    state: &mut ChainState,
    auth_verifier: &V,
) -> Result<AcceptedBlockRawValidationOutput, FullValidationError> {
    if block_proof_bytes.len() > MAX_BLOCK_PROOF_BYTES
        || !proof_sidecar_combined_len_ok(block_proof_bytes.len(), block_auth_sidecar_bytes.len())
    {
        return Err(FullValidationError::ZkProof(
            crate::VerifyBlockError::ShapeMismatch,
        ));
    }
    if block_auth_sidecar_bytes.len() > MAX_BLOCK_AUTH_SIDECAR_BYTES {
        return Err(FullValidationError::ZkProof(
            crate::VerifyBlockError::AuthSidecarShapeMismatch,
        ));
    }
    let preflight =
        validate_block_resource_preflight(block).map_err(FullValidationError::Consensus)?;
    let block_body_len = block.canonical_wire_len().map_err(|_| {
        FullValidationError::ZkProof(crate::VerifyBlockError::BlockResourceWeightExceeded)
    })?;
    let user_txs = preflight.user_tx_count;
    let live_inputs = preflight.live_input_count;
    let outputs = preflight.output_count;
    let state_frontier_nodes = preflight.action_count;
    if !block_resource_weight_ok(
        block_body_len,
        block_proof_bytes.len(),
        block_auth_sidecar_bytes.len(),
        user_txs,
        live_inputs,
        outputs,
        state_frontier_nodes,
    ) {
        return Err(FullValidationError::ZkProof(
            crate::VerifyBlockError::BlockResourceWeightExceeded,
        ));
    }
    validate_tx_epoch_context(block, parent, tx_epoch)?;

    if user_txs == 0 {
        validate_block_proof_binding(block, block_proof_bytes)
            .map_err(|_| FullValidationError::ZkProof(crate::VerifyBlockError::ShapeMismatch))?;
        if !block_auth_sidecar_bytes.is_empty() {
            return Err(FullValidationError::ZkProof(
                crate::VerifyBlockError::AuthSidecarShapeMismatch,
            ));
        }
        match timestamp_policy {
            TimestampPolicy::Live(local_time) => validate_block_checks(
                block,
                parent,
                prev_timestamps,
                prev_active_counts,
                local_time,
                anchor,
            )?,
            TimestampPolicy::Timeless => validate_block_checks_timeless(
                block,
                parent,
                prev_timestamps,
                prev_active_counts,
                anchor,
            )?,
        }
        if block.header.tx_root != compute_tx_root(&block.transactions) {
            return Err(FullValidationError::Consensus(
                noid_chain::consensus::ConsensusError::BadTxRoot,
            ));
        }
        let artifacts = derive_coinbase_only_validation_artifacts(block, parent, state)?;
        let applied_root = state
            .apply_verified_exact_transition(
                artifacts.verified_transition.log_slots(),
                artifacts.verified_transition.child_state_root(),
                artifacts.verified_transition.slot_updates(),
                artifacts.verified_transition.active_slot_count(),
                artifacts.verified_transition.alloc_counter(),
            )
            .map_err(|e| {
                FullValidationError::Consensus(
                    noid_chain::consensus::ConsensusError::ShapeMismatch(format!(
                        "coinbase-only apply failed: {e:?}"
                    )),
                )
            })?;
        if applied_root != block.header.state_root {
            return Err(FullValidationError::Consensus(
                noid_chain::consensus::ConsensusError::ShapeMismatch(
                    "coinbase-only state_root mismatch".into(),
                ),
            ));
        }
        return Ok(AcceptedBlockRawValidationOutput {
            state_root: applied_root,
            artifacts,
        });
    }

    if block_proof_bytes.is_empty() {
        return Err(FullValidationError::ZkProof(
            crate::VerifyBlockError::ShapeMismatch,
        ));
    }
    if block_auth_sidecar_bytes.is_empty() {
        return Err(FullValidationError::ZkProof(
            crate::VerifyBlockError::AuthSidecarShapeMismatch,
        ));
    }
    let proof: BlockProof = bincode::deserialize(block_proof_bytes)
        .map_err(|_| FullValidationError::ZkProof(crate::VerifyBlockError::ShapeMismatch))?;
    let sidecar: BlockAuthSidecar =
        bincode::deserialize(block_auth_sidecar_bytes).map_err(|_| {
            FullValidationError::ZkProof(crate::VerifyBlockError::AuthSidecarShapeMismatch)
        })?;

    validate_block_full_inner(
        block,
        &proof,
        &sidecar,
        parent,
        prev_timestamps,
        prev_active_counts,
        timestamp_policy,
        anchor,
        state,
        auth_verifier,
    )
    .map(|output| AcceptedBlockRawValidationOutput {
        state_root: output.state_root,
        artifacts: output.artifacts,
    })
}

/// Derive proof-facing accepted-transition artifacts for a canonical
/// coinbase-only block.
///
/// The shared mandatory-coinbase predicate runs before any state boundary or
/// exact-surface work, so direct callers cannot use this helper to turn a
/// structurally empty child into an accepted transition.
fn derive_coinbase_only_validation_artifacts(
    block: &Block,
    parent: &BlockHeader,
    state: &ChainState,
) -> Result<AcceptedBlockValidationArtifacts, FullValidationError> {
    validate_mandatory_coinbase(block, parent).map_err(FullValidationError::Consensus)?;
    if block.transactions.len() != 1 {
        return Err(FullValidationError::Consensus(
            noid_chain::consensus::ConsensusError::ShapeMismatch(
                "coinbase-only artifact derivation received user transactions".into(),
            ),
        ));
    }
    validate_parent_state_boundary(parent, state)?;
    let surface =
        build_exact_surface_for_block(block, state).map_err(FullValidationError::ZkProof)?;
    let inputs = crate::ExactStateTransitionInputs {
        parent_state_root: parent.state_root,
        parent_log_slots: state.state.log_slots() as u32,
        child_state_root: block.header.state_root,
        child_log_slots: block.header.log_slots,
        parent_active_slot_count: state.active_slot_count,
        parent_alloc_counter: state.alloc_counter,
    };
    let slot_updates: Vec<_> = surface
        .touched_indices
        .iter()
        .copied()
        .zip(surface.new_slots.iter().copied())
        .collect();
    let child_state_root = state
        .exact_utxo_root_after_slot_updates(block.header.log_slots, &slot_updates)
        .map_err(|e| {
            FullValidationError::Consensus(noid_chain::consensus::ConsensusError::ShapeMismatch(
                format!("coinbase-only exact UTXO root derivation failed: {e:?}"),
            ))
        })?;
    let verified = crate::VerifiedStateTransition::from_verified_no_spend_native(
        &inputs,
        &surface,
        child_state_root,
    )
    .map_err(|e| FullValidationError::ZkProof(crate::VerifyBlockError::ExactStateTransition(e)))?;

    if verified.active_slot_count() != block.header.active_slot_count {
        return Err(FullValidationError::Consensus(
            noid_chain::consensus::ConsensusError::ShapeMismatch(
                "active_slot_count mismatch".into(),
            ),
        ));
    }
    if verified.alloc_counter() != block.header.alloc_counter {
        return Err(FullValidationError::Consensus(
            noid_chain::consensus::ConsensusError::ShapeMismatch("alloc_counter mismatch".into()),
        ));
    }

    Ok(AcceptedBlockValidationArtifacts {
        authorization: VerifiedAuthorizationBatch {
            user_tx_count: 0,
            live_input_count_total: 0,
        },
        exact_state_inputs: inputs,
        exact_action_surface: surface,
        verified_transition: verified,
    })
}

pub(crate) fn block_resource_counts(block: &Block) -> (usize, usize, usize, usize) {
    let mut user_txs = 0usize;
    let mut live_inputs = 0usize;
    let mut outputs = 0usize;
    for tx in &block.transactions {
        if !tx.body.is_coinbase {
            user_txs += 1;
            live_inputs += tx.body.live_input_count();
        }
        outputs += tx.body.live_output_count();
    }
    let state_frontier_nodes = live_inputs.saturating_add(outputs);
    (user_txs, live_inputs, outputs, state_frontier_nodes)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use noid_chain::block::{compute_tx_root, Block};
    use noid_chain::consensus::{next_tx_epoch_anchor_id, ConsensusError};
    use noid_poseidon2b::primitives::Address;
    use noid_tx::{
        output_bitmap_bit, Transaction, TxBody, TxInput, TxOutput, TX_INPUTS, TX_OUTPUTS,
    };

    fn header(height: u64) -> BlockHeader {
        BlockHeader {
            prev_block_hash: [height as u8; 32],
            state_root: [0x11; 32],
            tx_root: [0x22; 32],
            timestamp: 1_767_225_600 + height,
            height,
            miner_address: Address([0x33; 32]),
            nonce: height as u128,
            difficulty_target: [0xff; 32],
            log_slots: 6,
            active_slot_count: 0,
            alloc_counter: 0,
        }
    }

    fn coinbase(epoch_anchor: [u8; 32], slot_index: u32) -> Transaction {
        let mut outputs = [TxOutput::dummy(); TX_OUTPUTS];
        outputs[0] = TxOutput {
            slot_index,
            amount: 50,
            owner: Address([0x44; 32]),
        };
        Transaction::new(TxBody {
            epoch_anchor,
            fee: 0,
            input_owner: Address([0; 32]),
            inputs: [TxInput::dummy(); TX_INPUTS],
            outputs,
            validity_bitmap: output_bitmap_bit(0),
            is_coinbase: true,
        })
    }

    fn user_tx(epoch_anchor: [u8; 32], live_inputs: usize) -> Transaction {
        assert!(live_inputs <= TX_INPUTS);
        let owner = Address([0x55; 32]);
        let mut inputs = [TxInput::dummy(); TX_INPUTS];
        let mut validity_bitmap = output_bitmap_bit(0) | output_bitmap_bit(1);
        for (index, input) in inputs.iter_mut().enumerate().take(live_inputs) {
            *input = TxInput {
                slot_index: index as u32,
                amount: 10,
                creation_id: index as u64,
            };
            validity_bitmap |= 1 << index;
        }
        let mut outputs = [TxOutput::dummy(); TX_OUTPUTS];
        outputs[0] = TxOutput {
            slot_index: 20,
            amount: 1,
            owner,
        };
        outputs[1] = TxOutput {
            slot_index: 21,
            amount: 1,
            owner,
        };
        Transaction::new(TxBody {
            epoch_anchor,
            fee: 0,
            input_owner: owner,
            inputs,
            outputs,
            validity_bitmap,
            is_coinbase: false,
        })
    }

    fn block(parent: &BlockHeader, height: u64, user_anchor: [u8; 32]) -> Block {
        let transactions = vec![
            coinbase(noid_chain::hash_block_header(parent), 30),
            user_tx(user_anchor, 1),
        ];
        let mut child = header(height);
        child.prev_block_hash = noid_chain::hash_block_header(parent);
        child.tx_root = compute_tx_root(&transactions);
        Block {
            header: child,
            transactions,
        }
    }

    #[test]
    fn tx_epoch_context_rejects_wrong_user_and_coinbase_anchors() {
        let parent = header(17);
        let expected = [0x66; 32];
        let valid = block(&parent, 18, expected);
        let context = BlockTxEpochContext {
            expected_user_epoch_anchor_id: expected,
        };
        validate_tx_epoch_context(&valid, &parent, &context).unwrap();

        let wrong_context = BlockTxEpochContext {
            expected_user_epoch_anchor_id: [0x67; 32],
        };
        assert!(matches!(
            validate_tx_epoch_context(&valid, &parent, &wrong_context),
            Err(FullValidationError::Consensus(
                ConsensusError::BadEpochAnchor
            ))
        ));

        let mut wrong_coinbase = valid.clone();
        wrong_coinbase.transactions[0].body.epoch_anchor = [0x68; 32];
        assert!(matches!(
            validate_tx_epoch_context(&wrong_coinbase, &parent, &context),
            Err(FullValidationError::Consensus(
                ConsensusError::BadCoinbaseAnchor
            ))
        ));
    }

    #[test]
    fn boundary_block_consumes_old_epoch_then_child_uses_boundary_id() {
        let parent_143 = header(143);
        let old_anchor = [0x71; 32];
        let boundary = block(&parent_143, 144, old_anchor);
        let old_context = BlockTxEpochContext {
            expected_user_epoch_anchor_id: old_anchor,
        };
        validate_tx_epoch_context(&boundary, &parent_143, &old_context).unwrap();

        let boundary_id = noid_chain::hash_block_header(&boundary.header);
        let next_anchor = next_tx_epoch_anchor_id(old_anchor, 144, boundary_id);
        assert_eq!(next_anchor, boundary_id);

        let child_145 = block(&boundary.header, 145, next_anchor);
        let next_context = BlockTxEpochContext {
            expected_user_epoch_anchor_id: next_anchor,
        };
        validate_tx_epoch_context(&child_145, &boundary.header, &next_context).unwrap();
        assert!(matches!(
            validate_tx_epoch_context(&child_145, &boundary.header, &old_context),
            Err(FullValidationError::Consensus(
                ConsensusError::BadEpochAnchor
            ))
        ));
    }

    #[test]
    fn raw_accept_fails_on_epoch_before_proof_or_state_work() {
        let parent = header(8);
        let valid_anchor = [0x81; 32];
        let candidate = block(&parent, 9, valid_anchor);
        let mut state = ChainState::with_log_slots(6);
        let error = accept_block_timeless_with_artifacts(
            &candidate,
            &[],
            &[],
            &parent,
            &[parent.timestamp],
            &[parent.active_slot_count],
            &BlockTxEpochContext {
                expected_user_epoch_anchor_id: [0x82; 32],
            },
            &AnchorInfo {
                anchor_height: 0,
                anchor_timestamp: parent.timestamp,
                anchor_target: parent.difficulty_target,
            },
            &mut state,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            FullValidationError::Consensus(ConsensusError::BadEpochAnchor)
        ));
    }

    #[test]
    fn malformed_in_memory_body_is_rejected_without_encoder_panic() {
        let parent = header(8);
        let user_anchor = [0x83; 32];
        let mut candidate = block(&parent, 9, user_anchor);
        // A dead record must be exactly zero.  The canonical encoder asserts
        // this invariant, so validation must never call it before rejection.
        candidate.transactions[1].body.inputs[7].amount = 1;
        let mut state = ChainState::with_log_slots(6);
        let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            accept_block_timeless_with_artifacts(
                &candidate,
                &[],
                &[],
                &parent,
                &[parent.timestamp],
                &[parent.active_slot_count],
                &BlockTxEpochContext {
                    expected_user_epoch_anchor_id: user_anchor,
                },
                &AnchorInfo {
                    anchor_height: 0,
                    anchor_timestamp: parent.timestamp,
                    anchor_target: parent.difficulty_target,
                },
                &mut state,
            )
        }));
        assert!(
            caught.is_ok(),
            "validation invoked a panic-only encoder path"
        );
        assert!(caught.unwrap().is_err());
    }

    #[test]
    fn oversized_in_memory_block_fails_preflight_before_epoch_scan() {
        let parent = header(8);
        let mut transactions = Vec::with_capacity(noid_chain::BLOCK_MAX_TXS + 1);
        transactions.push(coinbase(noid_chain::hash_block_header(&parent), 30));
        transactions.extend((0..noid_chain::BLOCK_MAX_TXS).map(|_| user_tx([0xa1; 32], 1)));
        let candidate = Block {
            header: header(9),
            transactions,
        };
        let mut state = ChainState::with_log_slots(6);
        let error = accept_block_timeless_with_artifacts(
            &candidate,
            &[],
            &[],
            &parent,
            &[parent.timestamp],
            &[parent.active_slot_count],
            &BlockTxEpochContext {
                expected_user_epoch_anchor_id: [0xa2; 32],
            },
            &AnchorInfo {
                anchor_height: 0,
                anchor_timestamp: parent.timestamp,
                anchor_target: parent.difficulty_target,
            },
            &mut state,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            FullValidationError::Consensus(ConsensusError::TooManyTxs)
        ));
    }

    #[test]
    fn tier_255_resource_ledger_matches_fixed_tx8x2_budget() {
        let parent = header(0);
        let mut transactions = Vec::with_capacity(256);
        transactions.push(coinbase(noid_chain::hash_block_header(&parent), 31));
        transactions.extend((0..255).map(|_| user_tx([0x91; 32], 4)));
        let block = Block {
            header: header(1),
            transactions,
        };

        assert_eq!(block_resource_counts(&block), (255, 1020, 511, 1531));
    }

    #[test]
    fn block_slot_conflict_has_a_distinct_proof_boundary_error() {
        assert!(matches!(
            map_state_delta_error(StateDeltaError::BlockSlotConflict {
                tx_index: 3,
                op_index: 7,
            }),
            VerifyBlockError::ExactStateSurfaceBlockSlotConflict {
                tx_index: 3,
                op_index: 7,
            }
        ));
    }
}
