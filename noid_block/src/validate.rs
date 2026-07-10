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
use noid_chain::segmented_state::SegmentedFriState;
use noid_chain::state::ChainState;
use noid_chain::state_delta::{build_exact_action_surface, ExactActionSurface, StateDeltaError};

use crate::{BlockAuthSidecar, BlockProof, VerifyBlockError};

use noid_gkr::{
    canonical_authorization_statement_from_body, verify_authorization_statement_proof,
    VerifyAuthorizationError,
};
use noid_tx::{compute_claims_commitment, validate_public_tx_logic, Transaction};
use rayon::prelude::*;

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
                        owner_count: statement.public.layout.owner_count,
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
    anchor: &AnchorInfo,
    state: &mut ChainState,
) -> Result<[u8; 32], FullValidationError> {
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
    anchor: &AnchorInfo,
    state: &mut ChainState,
) -> Result<AcceptedBlockValidationOutput, FullValidationError> {
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
            if tx.tx_body_hash != facts.tx_body_hash {
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
                tx.tx_body_hash.as_fields(),
                &tx.body,
            )
            .map_err(|_| VerifyBlockError::AuthSidecarShapeMismatch)?;
            verifier.verify(&statement, proof)
        })
        .collect();

    let mut owner_count_total = 0usize;
    let mut live_input_count_total = 0usize;
    for verified in results {
        let verified = verified?;
        if verified.live_input_count == 0 || verified.owner_count == 0 {
            return Err(VerifyBlockError::AuthSidecarShapeMismatch);
        }
        owner_count_total = owner_count_total.saturating_add(verified.owner_count);
        live_input_count_total = live_input_count_total.saturating_add(verified.live_input_count);
    }

    Ok(VerifiedAuthorizationBatch {
        user_tx_count: user_txs.len(),
        owner_count_total,
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
    let commitments: Vec<[u8; 32]> = bodies
        .iter()
        .map(|body| compute_claims_commitment(&body.inputs, &body.outputs))
        .collect();
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
    anchor: &AnchorInfo,
    pre_state: &noid_chain::segmented_state::SegmentedFriState,
    state: &mut ChainState,
) -> Result<[u8; 32], FullValidationError> {
    let _ = pre_state;
    accept_block_inner(
        block,
        block_proof_bytes,
        block_auth_sidecar_bytes,
        parent,
        prev_timestamps,
        prev_active_counts,
        TimestampPolicy::Live(local_time),
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
    anchor: &AnchorInfo,
    pre_state: &SegmentedFriState,
    state: &mut ChainState,
) -> Result<AcceptedBlockRawValidationOutput, FullValidationError> {
    let _ = pre_state;
    accept_block_inner_with_artifacts(
        block,
        block_proof_bytes,
        block_auth_sidecar_bytes,
        parent,
        prev_timestamps,
        prev_active_counts,
        TimestampPolicy::Live(local_time),
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
    anchor: &AnchorInfo,
    pre_state: &SegmentedFriState,
    state: &mut ChainState,
    auth_verifier: &V,
) -> Result<AcceptedBlockRawValidationOutput, FullValidationError> {
    let _ = pre_state;
    accept_block_inner_with_artifacts(
        block,
        block_proof_bytes,
        block_auth_sidecar_bytes,
        parent,
        prev_timestamps,
        prev_active_counts,
        TimestampPolicy::Live(local_time),
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
    validate_block_resource_preflight(block).map_err(FullValidationError::Consensus)?;
    let (user_txs, live_inputs, outputs, state_frontier_nodes) = block_resource_counts(block);
    if !block_resource_weight_ok(
        block.to_bytes().len(),
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
            owner_count_total: 0,
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
            live_inputs += tx.body.inputs.iter().filter(|input| input.valid).count();
        }
        outputs += tx.body.outputs.iter().filter(|output| output.valid).count();
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
    use noid_chain::block_header::BlockHeader;
    use noid_chain::consensus::wire_limits::{
        proof_sidecar_combined_len_ok, MAX_BLOCK_AUTH_SIDECAR_BYTES,
    };
    use noid_chain::consensus::{
        genesis::GENESIS_TIMESTAMP,
        params::{BLOCK_TIME, GENESIS_TARGET},
        pow::search_pow,
        template::build_block_template,
    };
    use noid_chain::state::ChainState;
    use noid_poseidon2b::primitives::{derive_address, Address, SpendSecret};
    use noid_tx::{Transaction, TxBody, TxInput, TxOutput};

    const TEST_LOG_SLOTS: usize = 6;

    fn make_tx_body(slot: u32, is_coinbase: bool) -> TxBody {
        TxBody {
            shape: noid_tx::TxShape::Standard4x8,
            epoch_anchor: [0u8; 32],
            fee: 0,
            inputs: vec![],
            outputs: vec![TxOutput {
                slot_index: slot,
                value: 100,
                owner: Address([1u8; 32]),
                valid: true,
            }],
            is_coinbase,
        }
    }

    fn make_transaction(body: TxBody) -> Transaction {
        let hash = noid_tx::hash_tx_body(
            &body.epoch_anchor,
            body.fee,
            &body.inputs,
            &body.outputs,
            body.is_coinbase,
        );
        Transaction {
            body,
            tx_body_hash: hash,
        }
    }

    fn history_parent(state: &mut ChainState) -> BlockHeader {
        BlockHeader {
            prev_block_hash: [0u8; 32],
            state_root: state.state_root(),
            tx_root: compute_tx_root(&[]),
            timestamp: GENESIS_TIMESTAMP,
            height: 0,
            miner_address: Address([0x44; 32]),
            nonce: 0,
            difficulty_target: GENESIS_TARGET,
            log_slots: state.state.log_slots() as u32,
            active_slot_count: state.active_slot_count,
            alloc_counter: state.alloc_counter,
        }
    }

    fn history_anchor(parent: &BlockHeader) -> AnchorInfo {
        AnchorInfo {
            anchor_height: parent.height,
            anchor_timestamp: parent.timestamp,
            anchor_target: parent.difficulty_target,
        }
    }

    #[test]
    fn parent_chain_state_boundary_binds_root_depth_and_counters() {
        let mut state = ChainState::with_log_slots(TEST_LOG_SLOTS);
        let parent = history_parent(&mut state);
        validate_parent_state_boundary(&parent, &state).expect("matching parent boundary");

        let mut bad_root = parent.clone();
        bad_root.state_root[0] ^= 1;
        assert!(validate_parent_state_boundary(&bad_root, &state).is_err());

        let mut bad_depth = parent.clone();
        bad_depth.log_slots += 1;
        assert!(validate_parent_state_boundary(&bad_depth, &state).is_err());

        let mut bad_active = parent.clone();
        bad_active.active_slot_count += 1;
        assert!(validate_parent_state_boundary(&bad_active, &state).is_err());

        let mut bad_alloc = parent;
        bad_alloc.alloc_counter += 1;
        assert!(validate_parent_state_boundary(&bad_alloc, &state).is_err());
    }

    #[test]
    fn coinbase_only_block_returns_history_claim_artifacts() {
        let mut state = ChainState::with_log_slots(TEST_LOG_SLOTS);
        let parent = history_parent(&mut state);
        let template = build_block_template(
            &parent,
            &state,
            &[parent.active_slot_count],
            vec![],
            Address([0x55; 32]),
            parent.timestamp + BLOCK_TIME,
            GENESIS_TARGET,
        )
        .expect("coinbase-only template");
        let header = {
            let pow_header = template.to_pow_header(0);
            let nonce =
                search_pow(&pow_header, 0, 100_000_000).expect("test target should mine quickly");
            template.clone().into_header(nonce)
        };
        let block = Block {
            header,
            transactions: template.all_txs(),
        };
        let out = accept_block_timeless_with_artifacts(
            &block,
            &[],
            &[],
            &parent,
            &[parent.timestamp],
            &[parent.active_slot_count],
            &history_anchor(&parent),
            &mut state,
        )
        .expect("coinbase-only block accepted with artifacts");

        assert_eq!(out.state_root, block.header.state_root);
        assert_eq!(out.artifacts.exact_action_surface.spends, 0);
        assert_eq!(out.artifacts.exact_action_surface.mints, 1);
        assert_eq!(
            out.artifacts.verified_transition.child_state_root(),
            block.header.state_root
        );

        let claim = crate::AcceptedStateTransitionClaim::from_accepted_block(
            &block,
            &parent,
            &out.artifacts,
        )
        .expect("history claim from coinbase artifacts");
        assert_ne!(claim.claim_digest, [0u8; 32]);
        assert_eq!(claim.touched_slot_count, 1);
        assert_eq!(claim.mint_count, 1);
        assert_eq!(claim.spend_count, 0);
        assert_eq!(claim.reward_value, claim.minted_value);
        assert!(claim.supply_delta > 0);
    }

    #[test]
    fn coinbase_only_artifact_derivation_rejects_empty_before_state_boundary() {
        let mut state = ChainState::with_log_slots(TEST_LOG_SLOTS);
        let parent = history_parent(&mut state);
        let header = BlockHeader {
            prev_block_hash: noid_chain::hash_block_header(&parent),
            state_root: parent.state_root,
            tx_root: compute_tx_root(&[]),
            timestamp: parent.timestamp + BLOCK_TIME,
            height: parent.height + 1,
            miner_address: Address([0x66; 32]),
            nonce: 0,
            difficulty_target: GENESIS_TARGET,
            log_slots: parent.log_slots,
            active_slot_count: parent.active_slot_count,
            alloc_counter: parent.alloc_counter,
        };
        let block = Block {
            header,
            transactions: vec![],
        };
        let mut mismatched_state = state.clone();
        mismatched_state.alloc_counter += 1;
        let direct_err =
            derive_coinbase_only_validation_artifacts(&block, &parent, &mismatched_state)
                .expect_err("direct artifact derivation must enforce the mandatory coinbase");
        assert!(matches!(
            direct_err,
            FullValidationError::Consensus(noid_chain::consensus::ConsensusError::MissingCoinbase)
        ));

        let template = build_block_template(
            &parent,
            &state,
            &[parent.active_slot_count],
            vec![],
            Address([0x55; 32]),
            parent.timestamp + BLOCK_TIME,
            GENESIS_TARGET,
        )
        .expect("coinbase-only template");
        let mut block_with_user = Block {
            header: template.clone().into_header(0),
            transactions: template.all_txs(),
        };
        block_with_user
            .transactions
            .push(make_transaction(make_spend_body(1)));
        let direct_err =
            derive_coinbase_only_validation_artifacts(&block_with_user, &parent, &mismatched_state)
                .expect_err("coinbase-only artifact derivation must reject user transactions");
        assert!(matches!(
            direct_err,
            FullValidationError::Consensus(noid_chain::consensus::ConsensusError::ShapeMismatch(_))
        ));
    }

    fn make_spend_body(slot: u32) -> TxBody {
        let secret = SpendSecret([0x7Au8; 32]);
        let owner = derive_address(&secret);
        TxBody {
            shape: noid_tx::TxShape::Standard4x8,
            epoch_anchor: [0x42; 32],
            fee: 0,
            inputs: vec![TxInput {
                slot_index: slot,
                value: 100,
                creation_id: 0,
                owner,
                spend_secret: secret,
                valid: true,
            }],
            outputs: vec![TxOutput {
                slot_index: 10_000 + slot,
                value: 100,
                owner,
                valid: true,
            }],
            is_coinbase: false,
        }
    }

    fn auth_proof_for_body(body: &TxBody) -> AuthorizationProof {
        use noid_gkr::{
            owner_auth_gkr_channel, owner_auth_trace_inputs_from_body_and_secret,
            prove_owner_auth_killshot, OwnerAuthCircuit,
        };
        let spend_secret = &body
            .inputs
            .iter()
            .find(|input| input.valid)
            .expect("test body has a live input")
            .spend_secret;
        let auth_inputs = owner_auth_trace_inputs_from_body_and_secret(body, spend_secret)
            .expect("owner auth inputs from test body");
        let circuit = OwnerAuthCircuit::build(auth_inputs.layout);
        let mut channel = owner_auth_gkr_channel();
        prove_owner_auth_killshot(&circuit, &auth_inputs, &mut channel).0
    }

    #[test]
    fn authorization_batch_output_counts_verified_public_relation() {
        let tx = make_transaction(make_spend_body(17));
        let proof = auth_proof_for_body(&tx.body);
        let transactions = vec![tx];
        let block = Block {
            header: {
                let mut state = ChainState::with_log_slots(TEST_LOG_SLOTS);
                BlockHeader {
                    prev_block_hash: [0u8; 32],
                    state_root: state.state_root(),
                    tx_root: noid_chain::compute_tx_root(&transactions),
                    timestamp: GENESIS_TIMESTAMP,
                    height: 1,
                    miner_address: Address([0u8; 32]),
                    nonce: 0,
                    difficulty_target: GENESIS_TARGET,
                    log_slots: TEST_LOG_SLOTS as u32,
                    active_slot_count: 0,
                    alloc_counter: 0,
                }
            },
            transactions,
        };
        let sidecar = BlockAuthSidecar {
            tx_auth: vec![proof],
        };

        let out = validate_block_authorizations_with_output(
            &block,
            &sidecar,
            &OwnerAuthAuthorizationVerifier,
        )
        .expect("authorization batch verifies");

        assert_eq!(
            out,
            VerifiedAuthorizationBatch {
                user_tx_count: 1,
                owner_count_total: 1,
                live_input_count_total: 1,
            }
        );
    }

    #[test]
    #[cfg_attr(debug_assertions, ignore = "release-only max sidecar regression")]
    fn max_255_authorization_sidecar_is_detached_and_fits_caps() {
        let proof = auth_proof_for_body(&make_spend_body(1));
        let mut transactions = Vec::with_capacity(noid_chain::block::BLOCK_MAX_TXS);
        transactions.push(make_transaction(make_tx_body(0, true)));
        for slot in 0..255u32 {
            transactions.push(make_transaction(make_spend_body(1_000 + slot)));
        }
        assert_eq!(transactions.len(), noid_chain::block::BLOCK_MAX_TXS);

        let block = Block {
            header: {
                let mut state = ChainState::with_log_slots(TEST_LOG_SLOTS);
                BlockHeader {
                    prev_block_hash: [0u8; 32],
                    state_root: state.state_root(),
                    tx_root: noid_chain::compute_tx_root(&transactions),
                    timestamp: GENESIS_TIMESTAMP,
                    height: 1,
                    miner_address: Address([0u8; 32]),
                    nonce: 0,
                    difficulty_target: GENESIS_TARGET,
                    log_slots: TEST_LOG_SLOTS as u32,
                    active_slot_count: 0,
                    alloc_counter: 0,
                }
            },
            transactions,
        };
        let sidecar = BlockAuthSidecar {
            tx_auth: vec![proof; 255],
        };
        let sidecar_bytes = bincode::serialize(&sidecar).expect("serialize sidecar");
        assert!(sidecar_bytes.len() <= MAX_BLOCK_AUTH_SIDECAR_BYTES);
        assert!(proof_sidecar_combined_len_ok(0, sidecar_bytes.len()));

        validate_block_auth_sidecar_shape(&block, &sidecar).expect("max sidecar shape verifies");

        let mut short = sidecar.clone();
        short.tx_auth.pop();
        assert!(matches!(
            validate_block_auth_sidecar_shape(&block, &short),
            Err(crate::VerifyBlockError::AuthSidecarShapeMismatch)
        ));
    }
}
