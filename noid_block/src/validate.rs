// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Full proof-native block validation.
//!
//! `validate_block_full` is the complete user-transaction validation pipeline
//! for a full node receiving a block from the network:
//!
//! 1. `validate_block_checks()` — cheap header/PoW/fee checks.
//! 2. Verify the canonical minimal `BlockProof`: exact public transaction
//!    predicates, wallet authorization capsules, and exact authenticated state
//!    transition.
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

use noid_chain::block::Block;
use noid_chain::block_header::BlockHeader;
use noid_chain::consensus::validation::{validate_block_checks, AnchorInfo};
use noid_chain::consensus::wire_limits::{
    proof_sidecar_combined_len_ok, MAX_BLOCK_AUTH_SIDECAR_BYTES, MAX_BLOCK_PROOF_BYTES,
};
use noid_chain::consensus::ConsensusError;
use noid_chain::state::ChainState;
use noid_chain::state_delta::{build_exact_action_surface, ExactActionSurface, StateDeltaError};
use noid_core::Block128;

use crate::{
    block_auth_sidecar_root, block_recursive_claim_hash, BlockAuthSidecar, BlockProof,
    VerifyBlockError,
};

use noid_gkr::{
    owner_auth_gkr_channel, owner_auth_public_from_body, verify_owner_auth_killshot,
    OwnerAuthCircuit, OwnerAuthProofKillShot, OwnerAuthPublicInputs,
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

pub type AuthorizationProof = OwnerAuthProofKillShot;

#[derive(Debug, Clone)]
pub struct CanonicalAuthorizationStatement {
    pub tx_index: usize,
    pub tx_body_hash: [Block128; 2],
    pub public: OwnerAuthPublicInputs,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedAuthorization {
    pub tx_index: usize,
    pub owner_count: usize,
    pub live_input_count: usize,
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
        let circuit = OwnerAuthCircuit::build(statement.public.layout);
        let mut channel = owner_auth_gkr_channel();
        verify_owner_auth_killshot(proof, &circuit, &statement.public, &mut channel)
            .ok_or(VerifyBlockError::AuthKillShot(statement.tx_index))?;

        if statement.public.tx_body_hash != statement.tx_body_hash {
            return Err(VerifyBlockError::AuthSpineBridge(statement.tx_index));
        }

        Ok(VerifiedAuthorization {
            tx_index: statement.tx_index,
            owner_count: statement.public.layout.owner_count,
            live_input_count: statement.public.live_input_positions.len(),
        })
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
    // Header + tx checks (cheap, fail-fast — no state reads, no apply_block).
    validate_block_checks(
        block,
        parent,
        prev_timestamps,
        prev_active_counts,
        local_time,
        anchor,
    )?;

    validate_minimal_block_proof_shape(block, proof).map_err(FullValidationError::ZkProof)?;
    validate_block_proof_transcript_hash(block, proof).map_err(FullValidationError::ZkProof)?;
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
    validate_block_authorizations(block, auth_sidecar, &OwnerAuthAuthorizationVerifier)
        .map_err(FullValidationError::ZkProof)?;

    let surface =
        build_exact_surface_for_block(block, state).map_err(FullValidationError::ZkProof)?;
    let inputs = crate::ExactStateTransitionInputs {
        parent_state_root: parent.state_root,
        parent_log_slots: state.state.log_slots() as u32,
        parent_utxo_root: state.utxo_root,
        parent_guard_root: state.reuse_guard.root(),
        child_state_root: block.header.state_root,
        child_log_slots: block.header.log_slots,
        height: block.header.height,
        parent_active_slot_count: state.active_slot_count,
        parent_alloc_counter: state.alloc_counter,
    };
    let verified = crate::verify_exact_state_transition(
        &inputs,
        &surface,
        &state.reuse_guard,
        &proof.state_transition,
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

    let applied_root = state
        .apply_verified_exact_transition(
            verified.log_slots(),
            verified.child_utxo_root(),
            verified.child_guard_root(),
            verified.slot_updates(),
            verified.guard_bucket_update().cloned(),
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

    Ok(block.header.state_root)
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
    if proof.meta.n_tx as usize != expected_non_coinbase
        || proof.meta.n_air_per_tx != 0
        || proof.meta.n_auth_slices_per_tx != 0
        || proof.meta.log_rows != 0
        || proof.meta.n_block_spine_slices != 0
    {
        return Err(VerifyBlockError::ShapeMismatch);
    }

    Ok(())
}

fn validate_block_public_logic(block: &Block) -> Result<(), VerifyBlockError> {
    for (tx_index, tx) in block.transactions.iter().enumerate() {
        if tx.body.is_coinbase {
            continue;
        }
        let facts = validate_public_tx_logic(&tx.body)
            .map_err(|error| VerifyBlockError::TxPublicLogic { tx_index, error })?;
        if tx.tx_body_hash != facts.tx_body_hash {
            return Err(VerifyBlockError::TxPublicInputsMismatch { tx_index });
        }
    }
    Ok(())
}

pub fn validate_block_authorizations<V: AuthorizationVerifier>(
    block: &Block,
    sidecar: &BlockAuthSidecar,
    verifier: &V,
) -> Result<(), VerifyBlockError> {
    validate_block_auth_sidecar_root(block, sidecar)?;
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
            let public = owner_auth_public_from_body(&tx.body)
                .map_err(|_| VerifyBlockError::AuthSidecarShapeMismatch)?;
            let statement = CanonicalAuthorizationStatement {
                tx_index: *tx_index,
                tx_body_hash: tx.tx_body_hash.as_fields(),
                public,
            };
            verifier.verify(&statement, proof)
        })
        .collect();

    for verified in results {
        let verified = verified?;
        if verified.live_input_count == 0 || verified.owner_count == 0 {
            return Err(VerifyBlockError::AuthSidecarShapeMismatch);
        }
    }

    Ok(())
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

    let mut bodies = Vec::with_capacity(block.transactions.len());
    for tx in block.transactions.iter().filter(|tx| !tx.body.is_coinbase) {
        bodies.push(tx.body.clone());
    }
    if let Some(coinbase) = block.transactions.iter().find(|tx| tx.body.is_coinbase) {
        bodies.push(coinbase.body.clone());
    }
    let commitments: Vec<[u8; 32]> = bodies
        .iter()
        .map(|body| compute_claims_commitment(&body.inputs, &body.outputs))
        .collect();
    build_exact_action_surface(&surface_state, &bodies, &commitments).map_err(map_state_delta_error)
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
    }
}

// ---------------------------------------------------------------------------
// Header/proof transcript binding
// ---------------------------------------------------------------------------

pub fn validate_block_proof_transcript_hash(
    block: &Block,
    proof: &BlockProof,
) -> Result<(), VerifyBlockError> {
    if proof.meta.n_tx > 0
        && block.header.proof_transcript_hash != block_recursive_claim_hash(proof)
    {
        return Err(VerifyBlockError::ProofTranscriptHashMismatch);
    }
    Ok(())
}

pub fn validate_block_auth_sidecar_root(
    block: &Block,
    sidecar: &BlockAuthSidecar,
) -> Result<(), VerifyBlockError> {
    let has_user_txs = block.transactions.iter().any(|tx| !tx.body.is_coinbase);
    if !has_user_txs {
        if !sidecar.tx_auth.is_empty() {
            return Err(VerifyBlockError::AuthSidecarShapeMismatch);
        }
        return Ok(());
    }
    let expected = block_auth_sidecar_root(block, sidecar)?;
    if block.header.witness_root != expected {
        return Err(VerifyBlockError::AuthSidecarRootMismatch);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Network-facing entry point
// ---------------------------------------------------------------------------

/// Full block validation for a receiving full node.
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
pub fn validate_block_from_network(
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

    let proof: BlockProof = bincode::deserialize(block_proof_bytes)
        .map_err(|_| FullValidationError::ZkProof(crate::VerifyBlockError::ShapeMismatch))?;
    let sidecar: BlockAuthSidecar =
        bincode::deserialize(block_auth_sidecar_bytes).map_err(|_| {
            FullValidationError::ZkProof(crate::VerifyBlockError::AuthSidecarShapeMismatch)
        })?;

    validate_block_full(
        block,
        &proof,
        &sidecar,
        parent,
        prev_timestamps,
        prev_active_counts,
        local_time,
        anchor,
        state,
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use noid_chain::block::Block;
    use noid_chain::block_header::BlockHeader;
    use noid_chain::consensus::wire_limits::{
        proof_sidecar_combined_len_ok, MAX_BLOCK_AUTH_SIDECAR_BYTES,
    };
    use noid_chain::consensus::{genesis::GENESIS_TIMESTAMP, params::GENESIS_TARGET};
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

    fn auth_proof_for_body(body: &TxBody) -> OwnerAuthProofKillShot {
        use noid_gkr::{
            owner_auth_gkr_channel, owner_auth_inputs_from_body_and_live_secrets,
            prove_owner_auth_killshot, OwnerAuthCircuit,
        };
        let live_secrets: Vec<_> = body
            .inputs
            .iter()
            .filter(|input| input.valid)
            .map(|input| input.spend_secret.clone())
            .collect();
        let auth_inputs = owner_auth_inputs_from_body_and_live_secrets(body, &live_secrets)
            .expect("owner auth inputs from test body");
        let circuit = OwnerAuthCircuit::build(auth_inputs.layout);
        let mut channel = owner_auth_gkr_channel();
        prove_owner_auth_killshot(&circuit, &auth_inputs, &mut channel).0
    }

    #[test]
    #[cfg_attr(debug_assertions, ignore = "release-only max sidecar regression")]
    fn max_255_authorization_sidecar_binds_and_fits_caps() {
        let proof = auth_proof_for_body(&make_spend_body(1));
        let mut transactions = Vec::with_capacity(noid_chain::block::BLOCK_MAX_TXS);
        transactions.push(make_transaction(make_tx_body(0, true)));
        for slot in 0..255u32 {
            transactions.push(make_transaction(make_spend_body(1_000 + slot)));
        }
        assert_eq!(transactions.len(), noid_chain::block::BLOCK_MAX_TXS);

        let mut block = Block {
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
                    proof_transcript_hash: [1u8; 32],
                    witness_root: [0u8; 32],
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

        block.header.witness_root =
            block_auth_sidecar_root(&block, &sidecar).expect("max sidecar root");
        validate_block_auth_sidecar_root(&block, &sidecar).expect("max sidecar root verifies");

        let mut short = sidecar.clone();
        short.tx_auth.pop();
        assert!(matches!(
            validate_block_auth_sidecar_root(&block, &short),
            Err(crate::VerifyBlockError::AuthSidecarShapeMismatch)
        ));
    }
}
