// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Full proof-native block validation.
//!
//! `validate_block_full` is the complete user-transaction validation pipeline
//! for a full node receiving a block from the network:
//!
//! 1. `validate_block_checks()` — cheap header/PoW/nullifier/fee checks.
//! 2. Verify the canonical `BlockProof`, including bucket proofs and NativeDelta
//!    state-root transition openings.
//! 3. `apply_state_delta()` — commit the already-proven state delta without
//!    running native `apply_block` as a second validity source.
//!
//! # SpineInputs / AuthPublicInputs reconstruction
//!
//! `verify_block` requires `SpineInputs` (slot state for block GKR) and
//! `AuthPublicInputs` (per-tx auth GKR public inputs). These must be
//! reconstructed from the block's public data.
//!
//! All reconstruction uses ONLY public data:
//! - `SpineInputs` — fully derived from `TxBody` (no secrets).
//! - `AuthPublicInputs.expected_address[i]` — from `TxInput.owner`
//!   (= H_ADDR(spend_secret), a one-way hash; spend_secret never leaves
//!   the wallet and never appears on the wire).
//! - `AuthPublicInputs.expected_auth_tag[i]` — from `TxInput.auth_tag`
//!   (= H_AUTH(spend_secret, tx_body_hash), a one-way hash).
//!   For dummy inputs (valid=false) the tag is computed from zero spend_secret.
//! - NativeDelta state summaries — from proof openings + pre-block FRI state.
//!
//! The `spend_secret` (private key) is NEVER transmitted, NEVER accessed
//! here, and NEVER needed for verification.

use noid_air::composition::sweep_logic_air_and_trace_from_body;
use noid_air::composition::tx_logic::{boundary_pins_from_body, TxLogicAir};
use noid_air::Air;
use noid_chain::block::{apply_state_delta, Block};
use noid_chain::block_header::BlockHeader;
use noid_chain::consensus::validation::{validate_block_checks, AnchorInfo};
use noid_chain::consensus::ConsensusError;
use noid_chain::nullifier::NullifierSet;
use noid_chain::state::ChainState;

use crate::{
    block_recursive_claim_hash, channel::state_binding_eval_point_and_gamma, verify_block,
    verify_state_bindings_standalone, BlockProof, VerifyBlockError,
};

use noid_air::airs::block_state_binding::BlockStateBindingAir;
use noid_gkr::{AuthPublicInputs, SpineInputs};
use noid_stark::prove_logic_sweep::sweep_spine_inputs_from_body;
use noid_tx::{
    compute_claims_commitment, hash_tx_body_for_shape, PublicInputs, Transaction, TxShape,
    MAX_INPUTS, MAX_OUTPUTS,
};

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Error returned by `validate_block_full`.
#[derive(Debug)]
pub enum FullValidationError {
    /// Native consensus check failed.
    Consensus(ConsensusError),
    /// ZK proof verification failed.
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

/// Full proof-native block validation.
///
/// Steps (ordered cheapest-first):
/// 1. `validate_block_checks()` — cheap consensus checks that do not mutate state.
/// 2. Full `BlockProof` verification, including standard/sweep bucket proofs and
///    NativeDelta state openings for every dirty segment.
/// 3. `apply_state_delta()` — apply the proven delta to the mutable chain state.
///
/// On success, `state` is updated to the post-block UTXO state.
/// On failure, callers restore the pre-validation state snapshot.
///
/// # Callers must provide
///
/// - `spine_inputs_list`: block GKR slot-state inputs, one per transaction.
///   Build these from the block's transactions and current state.
///
/// - `auth_public_list`: auth GKR public inputs, one per transaction.
///   Derived from the standard bucket public inputs.
///
/// - `state_binding_airs`: temporary NativeDelta summaries for each dirty segment.
pub fn validate_block_full(
    block: &Block,
    proof: &BlockProof,
    spine_inputs_list: &[SpineInputs],
    auth_public_list: &[AuthPublicInputs],
    state_binding_airs: &[&BlockStateBindingAir],
    parent: &BlockHeader,
    prev_timestamps: &[u64],
    // active_slot_count values from the last EXPANSION_WINDOW finalised headers.
    // Pass &[parent.active_slot_count] when the full window is not available.
    prev_active_counts: &[u64],
    local_time: u64,
    anchor: &AnchorInfo,
    nullifiers: &NullifierSet,
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
        nullifiers,
    )?;

    // Verify bucket coverage, canonical proof transcript binding, proof roots,
    // and pi.log_slots == header.log_slots.
    let header_log_slots = block.header.log_slots;
    validate_block_bucket_tx_indices(block, proof).map_err(FullValidationError::ZkProof)?;
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
    if let Some(standard_bucket) = proof.standard_bucket.as_ref() {
        for (block_tx_index, pi) in standard_bucket
            .meta
            .tx_indices
            .iter()
            .copied()
            .zip(standard_bucket.tx_pis.iter())
        {
            if pi.log_slots != header_log_slots {
                return Err(FullValidationError::ZkProof(
                    crate::VerifyBlockError::LogSlotsInconsistent {
                        tx_index: block_tx_index as usize,
                        pi_log_slots: pi.log_slots,
                        header_log_slots,
                    },
                ));
            }
        }
    }
    if let Some(sweep_bucket) = proof.sweep_bucket.as_ref() {
        for (block_tx_index, pi) in sweep_bucket
            .meta
            .tx_indices
            .iter()
            .copied()
            .zip(sweep_bucket.tx_pis.iter())
        {
            if pi.log_slots != header_log_slots {
                return Err(FullValidationError::ZkProof(
                    crate::VerifyBlockError::LogSlotsInconsistent {
                        tx_index: block_tx_index as usize,
                        pi_log_slots: pi.log_slots,
                        header_log_slots,
                    },
                ));
            }
        }
        verify_sweep_bucket_from_block(block, proof).map_err(FullValidationError::ZkProof)?;
    }

    // Verify the full proof. Standard and mixed blocks use the shared block
    // verifier; sweep-only blocks verify their bucket plus standalone state
    // binding proofs.
    if proof.standard_bucket.is_some() {
        let tx_airs: Vec<TxLogicAir> = block
            .transactions
            .iter()
            .filter(|tx| !tx.body.is_coinbase && tx.body.shape == TxShape::Standard4x8)
            .map(|tx| TxLogicAir::new(boundary_pins_from_body(&tx.body)))
            .collect();
        let air_refs: Vec<&dyn Air> = tx_airs.iter().map(|a| a as &dyn Air).collect();
        verify_block(
            &air_refs,
            proof,
            spine_inputs_list,
            auth_public_list,
            state_binding_airs,
        )?;
    } else {
        verify_state_bindings_standalone(proof, state_binding_airs)?;
    }

    // Apply state delta — ZK proved correctness means no pre-state reads are needed.
    apply_state_delta(state, block).map_err(|e| {
        use noid_chain::block::BlockApplyError;
        match e {
            BlockApplyError::HeaderTxRootMismatch => {
                FullValidationError::Consensus(noid_chain::consensus::ConsensusError::BadTxRoot)
            }
            BlockApplyError::HeaderActiveSlotCountMismatch => FullValidationError::Consensus(
                noid_chain::consensus::ConsensusError::ShapeMismatch(
                    "active_slot_count mismatch".into(),
                ),
            ),
            BlockApplyError::HeaderAllocCounterMismatch => FullValidationError::Consensus(
                noid_chain::consensus::ConsensusError::ShapeMismatch(
                    "alloc_counter mismatch".into(),
                ),
            ),
            BlockApplyError::HeaderLogSlotsMismatch => FullValidationError::Consensus(
                noid_chain::consensus::ConsensusError::BadLogSlotsExpansion,
            ),
            _ => FullValidationError::Consensus(
                noid_chain::consensus::ConsensusError::ShapeMismatch(format!("{:?}", e)),
            ),
        }
    })?;

    Ok(block.header.state_root)
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

// ---------------------------------------------------------------------------
// Network-facing entry point
// ---------------------------------------------------------------------------

/// Full block validation for a receiving full node.
///
/// Takes the raw `block_proof_bytes` received over P2P and:
/// 1. Deserialises the `BlockProof`.
/// 2. Reconstructs `SpineInputs`, `AuthPublicInputs`, and NativeDelta state summaries
///    purely from the block's public wire data and the pre-block FRI state.
/// 3. Calls `validate_block_full` (consensus + ZK + state delta).
///
/// # Security
///
/// `spend_secret` is never accessed or needed. All inputs are reconstructed
/// from one-way hash outputs (`owner = H_ADDR(secret)`, `auth_tag = H_AUTH(secret, …)`).
pub fn validate_block_from_network(
    block: &Block,
    block_proof_bytes: &[u8],
    parent: &BlockHeader,
    prev_timestamps: &[u64],
    prev_active_counts: &[u64],
    local_time: u64,
    anchor: &AnchorInfo,
    nullifiers: &NullifierSet,
    pre_state: &noid_chain::segmented_state::SegmentedFriState,
    state: &mut ChainState,
) -> Result<[u8; 32], FullValidationError> {
    let proof: BlockProof = bincode::deserialize(block_proof_bytes)
        .map_err(|_| FullValidationError::ZkProof(crate::VerifyBlockError::ShapeMismatch))?;

    let spine_inputs = build_spine_inputs_list(block);
    let auth_public = build_auth_public_list(block, &proof);
    let sb_airs = build_state_binding_airs(block, &proof, pre_state)?;
    let sb_air_refs: Vec<&BlockStateBindingAir> = sb_airs.iter().collect();

    validate_block_full(
        block,
        &proof,
        &spine_inputs,
        &auth_public,
        &sb_air_refs,
        parent,
        prev_timestamps,
        prev_active_counts,
        local_time,
        anchor,
        nullifiers,
        state,
    )
}

// ---------------------------------------------------------------------------
// Bucket coverage helpers
// ---------------------------------------------------------------------------

/// Validate that all present shape buckets cover exactly the non-coinbase
/// transactions in `block`, in canonical block order and without cross-shape
/// substitution.
///
/// This binds bucket-local public inputs back to concrete block transaction
/// bodies before the lower-level proof verifiers check algebraic consistency.
pub fn validate_block_bucket_tx_indices(
    block: &Block,
    proof: &BlockProof,
) -> Result<(), crate::VerifyBlockError> {
    let mut expected_standard = Vec::new();
    let mut expected_sweep = Vec::new();
    for (idx, tx) in block.transactions.iter().enumerate() {
        if tx.body.is_coinbase {
            continue;
        }
        match tx.body.shape {
            TxShape::Standard4x8 => expected_standard.push(idx as u32),
            TxShape::Sweep25x2 => expected_sweep.push(idx as u32),
        }
    }

    let expected_total = expected_standard.len() + expected_sweep.len();
    if proof.meta.n_tx as usize != expected_total {
        return Err(crate::VerifyBlockError::ShapeMismatch);
    }

    match (&proof.standard_bucket, expected_standard.is_empty()) {
        (Some(bucket), false) => {
            if bucket.meta.shape != TxShape::Standard4x8
                || !bucket.meta.tx_indices.windows(2).all(|w| w[0] < w[1])
                || bucket.meta.tx_indices != expected_standard
                || bucket.tx_pis.len() != expected_standard.len()
                || bucket.tx_auth_proofs.len() != expected_standard.len()
                || bucket.tx_algebraic.len() != expected_standard.len()
            {
                return Err(crate::VerifyBlockError::ShapeMismatch);
            }
            for (pi, block_idx) in bucket.tx_pis.iter().zip(expected_standard.iter().copied()) {
                let tx = &block.transactions[block_idx as usize];
                if tx.body.shape != TxShape::Standard4x8 {
                    return Err(crate::VerifyBlockError::ShapeMismatch);
                }
                validate_public_inputs_for_tx(block_idx as usize, tx, pi)?;
            }
        }
        (None, true) => {}
        _ => return Err(crate::VerifyBlockError::ShapeMismatch),
    }

    match (&proof.sweep_bucket, expected_sweep.is_empty()) {
        (Some(bucket), false) => {
            if bucket.meta.shape != TxShape::Sweep25x2
                || !bucket.meta.tx_indices.windows(2).all(|w| w[0] < w[1])
                || bucket.meta.tx_indices != expected_sweep
                || bucket.tx_pis.len() != expected_sweep.len()
                || bucket.auth_public.len() != expected_sweep.len()
                || bucket.tx_auth_proofs.len() != expected_sweep.len()
                || bucket.spine_inputs.len() != expected_sweep.len()
                || bucket.meta.n_boundary_slices_per_tx != 0
                || bucket.meta.n_block_spine_slices == 0
            {
                return Err(crate::VerifyBlockError::ShapeMismatch);
            }
            for (pi, block_idx) in bucket.tx_pis.iter().zip(expected_sweep.iter().copied()) {
                let tx = &block.transactions[block_idx as usize];
                if tx.body.shape != TxShape::Sweep25x2 {
                    return Err(crate::VerifyBlockError::ShapeMismatch);
                }
                validate_public_inputs_for_tx(block_idx as usize, tx, pi)?;
            }
        }
        (None, true) => {}
        _ => return Err(crate::VerifyBlockError::ShapeMismatch),
    }

    Ok(())
}

fn validate_public_inputs_for_tx(
    tx_index: usize,
    tx: &Transaction,
    pi: &PublicInputs,
) -> Result<(), crate::VerifyBlockError> {
    if tx.body.is_coinbase {
        return Err(crate::VerifyBlockError::ShapeMismatch);
    }

    let canonical_hash = hash_tx_body_for_shape(
        tx.body.shape,
        &tx.body.epoch_anchor,
        tx.body.fee,
        &tx.body.inputs,
        &tx.body.outputs,
        tx.body.is_coinbase,
    );
    let n_live_inputs = tx.body.inputs.iter().filter(|i| i.valid).count() as u8;
    let n_live_outputs = tx.body.outputs.iter().filter(|o| o.valid).count() as u8;
    let claims_commitment = compute_claims_commitment(&tx.body.inputs, &tx.body.outputs);

    let mut is_activation = [false; MAX_OUTPUTS];
    let mut is_deactivation = [false; MAX_INPUTS];
    if tx.body.shape == TxShape::Standard4x8 {
        for (j, out) in tx.body.outputs.iter().enumerate().take(MAX_OUTPUTS) {
            is_activation[j] = out.valid;
        }
        for (i, inp) in tx.body.inputs.iter().enumerate().take(MAX_INPUTS) {
            is_deactivation[i] = inp.valid;
        }
    }

    if tx.tx_body_hash != canonical_hash
        || pi.tx_body_hash != canonical_hash
        || pi.epoch_anchor != tx.body.epoch_anchor
        || pi.shape_id != tx.body.shape.id()
        || pi.fee != tx.body.fee
        || pi.n_live_inputs != n_live_inputs
        || pi.n_live_outputs != n_live_outputs
        || pi.coinbase_credit != 0
        || pi.claims_commitment != claims_commitment
        || pi.is_activation != is_activation
        || pi.is_deactivation != is_deactivation
    {
        return Err(crate::VerifyBlockError::TxPublicInputsMismatch { tx_index });
    }

    Ok(())
}

/// Standard-only compatibility wrapper used by callers that still require the
/// current standard block prover format.
pub fn validate_standard_bucket_tx_indices(
    block: &Block,
    proof: &BlockProof,
) -> Result<(), crate::VerifyBlockError> {
    if proof.sweep_bucket.is_some() {
        return Err(crate::VerifyBlockError::ShapeMismatch);
    }
    validate_block_bucket_tx_indices(block, proof)
}

/// Verify all Sweep25x2 wallet logic proofs carried by `proof.sweep_bucket` and
/// bind their public inputs to the block transaction bodies.
pub fn verify_sweep_bucket_from_block(
    block: &Block,
    proof: &BlockProof,
) -> Result<(), crate::VerifyBlockError> {
    let Some(bucket) = proof.sweep_bucket.as_ref() else {
        return Ok(());
    };
    validate_block_bucket_tx_indices(block, proof)?;

    let mut sweep_airs = Vec::with_capacity(bucket.meta.tx_indices.len());
    for (k, block_idx) in bucket.meta.tx_indices.iter().copied().enumerate() {
        let tx = &block.transactions[block_idx as usize];
        let canonical_spine = sweep_spine_inputs_from_body(&tx.body);
        if bucket.spine_inputs[k] != canonical_spine {
            return Err(crate::VerifyBlockError::ShapeMismatch);
        }

        let (air, _trace) = sweep_logic_air_and_trace_from_body(&tx.body);
        sweep_airs.push(air);
    }

    let sweep_air_refs: Vec<&dyn Air> = sweep_airs.iter().map(|air| air as &dyn Air).collect();
    crate::verify_sweep_bucket_aggregation(
        &proof.meta.prev_block_state_root,
        &sweep_air_refs,
        bucket,
    )?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Reconstruction helpers
// ---------------------------------------------------------------------------

/// Reconstruct `SpineInputs` for each non-coinbase transaction.
///
/// Derived entirely from the tx body — no private key material involved.
pub fn build_spine_inputs_list(block: &Block) -> Vec<SpineInputs> {
    use noid_core::Block128;
    block
        .transactions
        .iter()
        .filter(|tx| !tx.body.is_coinbase && tx.body.shape == TxShape::Standard4x8)
        .map(|tx| {
            let pins = boundary_pins_from_body(&tx.body);
            SpineInputs {
                epoch_anchor: pins.epoch_anchor,
                fee_leaf: pins.fee_leaf,
                input_leaves: pins.input_leaf_absorb,
                output_leaves: pins.output_leaf_absorb,
                is_coinbase_leaf: pins.is_coinbase_leaf,
                pad_leaf: [Block128(0); 2],
            }
        })
        .collect()
}

/// Reconstruct `AuthPublicInputs` for each non-coinbase transaction.
///
/// Live inputs (`valid = true`): `expected_address = inp.owner.as_fields()`,
/// `expected_auth_tag = inp.auth_tag.as_fields()`.  Both values are
/// one-way hashes of the spend_secret — safe to use publicly.
///
/// Dummy inputs (`valid = false`): address/tag are computed from a zero
/// spend_secret via `compute_auth_boundary`.  This matches what the wallet
/// prover supplies and does not reveal any private key material.
pub fn build_auth_public_list(block: &Block, proof: &BlockProof) -> Vec<AuthPublicInputs> {
    use noid_core::Block128;
    use noid_gkr::{compute_auth_boundary, AuthCircuit, N_AUTH_INPUTS};

    let auth_circuit = AuthCircuit::build();

    let Some(bucket) = proof.standard_bucket.as_ref() else {
        return Vec::new();
    };

    bucket
        .meta
        .tx_indices
        .iter()
        .zip(bucket.tx_pis.iter())
        .map(|(block_tx_index, pi)| {
            let tx = &block.transactions[*block_tx_index as usize];
            let tx_body_hash = pi.tx_body_hash.as_fields();

            // Dummy inputs use zero spend_secret.  Compute their boundary once.
            let zero_secrets = [[Block128(0); 2]; N_AUTH_INPUTS];
            let (dummy_addresses, dummy_auth_tags) =
                compute_auth_boundary(&auth_circuit, zero_secrets, tx_body_hash);

            let mut expected_address = [[Block128(0); 2]; N_AUTH_INPUTS];
            let mut expected_auth_tag = [[Block128(0); 2]; N_AUTH_INPUTS];

            for (i, inp) in tx.body.inputs.iter().take(N_AUTH_INPUTS).enumerate() {
                if inp.valid {
                    // Live input: use the one-way hashes from the wire format.
                    // owner = H_ADDR(spend_secret)  — already computed by wallet.
                    // auth_tag = H_AUTH(spend_secret, tx_body_hash) — idem.
                    expected_address[i] = inp.owner.as_fields();
                    expected_auth_tag[i] = inp.auth_tag.as_fields();
                } else {
                    // Dummy input: boundary derived from zero spend_secret.
                    expected_address[i] = dummy_addresses[i];
                    expected_auth_tag[i] = dummy_auth_tags[i];
                }
            }

            AuthPublicInputs {
                tx_body_hash,
                expected_address,
                expected_auth_tag,
            }
        })
        .collect()
}

fn proof_claim_commitments_by_block_index(
    block: &Block,
    proof: &BlockProof,
) -> Result<Vec<Option<[u8; 32]>>, crate::VerifyBlockError> {
    let mut commitments = vec![None; block.transactions.len()];
    let mut seen = 0usize;

    if let Some(bucket) = proof.standard_bucket.as_ref() {
        if bucket.meta.tx_indices.len() != bucket.tx_pis.len() {
            return Err(crate::VerifyBlockError::ShapeMismatch);
        }
        for (block_idx, pi) in bucket
            .meta
            .tx_indices
            .iter()
            .copied()
            .zip(bucket.tx_pis.iter())
        {
            let block_idx = block_idx as usize;
            let Some(tx) = block.transactions.get(block_idx) else {
                return Err(crate::VerifyBlockError::ShapeMismatch);
            };
            validate_public_inputs_for_tx(block_idx, tx, pi)?;
            if commitments[block_idx]
                .replace(pi.claims_commitment)
                .is_some()
            {
                return Err(crate::VerifyBlockError::ShapeMismatch);
            }
            seen += 1;
        }
    }

    if let Some(bucket) = proof.sweep_bucket.as_ref() {
        if bucket.meta.tx_indices.len() != bucket.tx_pis.len() {
            return Err(crate::VerifyBlockError::ShapeMismatch);
        }
        for (block_idx, pi) in bucket
            .meta
            .tx_indices
            .iter()
            .copied()
            .zip(bucket.tx_pis.iter())
        {
            let block_idx = block_idx as usize;
            let Some(tx) = block.transactions.get(block_idx) else {
                return Err(crate::VerifyBlockError::ShapeMismatch);
            };
            validate_public_inputs_for_tx(block_idx, tx, pi)?;
            if commitments[block_idx]
                .replace(pi.claims_commitment)
                .is_some()
            {
                return Err(crate::VerifyBlockError::ShapeMismatch);
            }
            seen += 1;
        }
    }

    if seen != proof.meta.n_tx as usize {
        return Err(crate::VerifyBlockError::ShapeMismatch);
    }

    Ok(commitments)
}

fn collect_state_binding_claims(
    block: &Block,
    commitments_by_block_index: &[Option<[u8; 32]>],
    pre_state: &noid_chain::segmented_state::SegmentedFriState,
) -> Result<crate::state_delta_claims::StateBindingClaimMap, crate::VerifyBlockError> {
    crate::state_delta_claims::collect_state_binding_claims_from_block(
        block,
        commitments_by_block_index,
        pre_state,
    )
}

/// Reconstruct temporary NativeDelta state summaries from proof openings and
/// the pre-block FRI state.
///
/// The verifier reconstructs claims from the canonical tx body, checks the
/// sequential pre-state relation, derives the state evaluation point from endpoint
/// roots, and enforces the native delta-MLE identity before returning the summary.
/// It never copies `(value, owner)` out of the state into a spend claim unless
/// that value equals the transaction's public claim; this is the SC-3 claim bridge.
pub fn build_state_binding_airs(
    block: &Block,
    proof: &BlockProof,
    pre_state: &noid_chain::segmented_state::SegmentedFriState,
) -> Result<Vec<BlockStateBindingAir>, crate::VerifyBlockError> {
    use noid_air::airs::block_state_binding::BlockStateBindingWitness;

    let n_state_bindings = proof.meta.n_state_bindings as usize;
    let has_user_txs = block.transactions.iter().any(|tx| !tx.body.is_coinbase);
    if !has_user_txs && n_state_bindings == 0 {
        return Ok(Vec::new());
    }

    let commitments_by_block_index = proof_claim_commitments_by_block_index(block, proof)?;
    let seg_claims = collect_state_binding_claims(block, &commitments_by_block_index, pre_state)?;

    if seg_claims.len() != n_state_bindings
        || proof.pre_state_openings.len() != n_state_bindings
        || proof.post_state_openings.len() != n_state_bindings
    {
        return Err(crate::VerifyBlockError::ShapeMismatch);
    }
    if n_state_bindings == 0 {
        return Ok(Vec::new());
    }

    let eff_log = pre_state.effective_log_segment_size();
    let prev_state_root = &proof.meta.prev_block_state_root;

    // BTreeMap iteration is already sorted by seg_id.
    tracing::debug!(
        n_state_bindings = seg_claims.len(),
        eff_log,
        "build_state_binding_airs: segments={}",
        seg_claims
            .iter()
            .map(|(s, c)| format!("seg{}:{}", s, c.len()))
            .collect::<Vec<_>>()
            .join(",")
    );

    seg_claims
        .into_iter()
        .enumerate()
        .map(|(sb_idx, (seg_id, claims))| {
            let pre_op = &proof.pre_state_openings[sb_idx];
            let post_op = &proof.post_state_openings[sb_idx];
            if pre_op.seg_id != seg_id || post_op.seg_id != seg_id {
                return Err(crate::VerifyBlockError::StateBindingSegmentMismatch {
                    state_binding_index: sb_idx,
                    expected_seg_id: seg_id,
                    pre_seg_id: pre_op.seg_id,
                    post_seg_id: post_op.seg_id,
                });
            }
            if pre_op.eval_point != post_op.eval_point || pre_op.eval_point.len() != eff_log {
                return Err(crate::VerifyBlockError::ShapeMismatch);
            }

            let (eval_point, gamma) = state_binding_eval_point_and_gamma(
                prev_state_root,
                &proof.meta.new_state_root,
                seg_id,
                sb_idx as u32,
                proof.meta.n_tx,
                eff_log,
            );
            if pre_op.eval_point != eval_point {
                return Err(crate::VerifyBlockError::StateMleOpeningFailed(sb_idx));
            }

            let prev_lane_openings = pre_op.lane_values;
            let new_lane_openings = post_op.lane_values;

            // Native state-delta identity for the current production proof surface:
            // post_lane(r) = pre_lane(r) + Σ eq(r, slot_i) · delta_i.
            //
            // The claims are verifier-reconstructed from the canonical block body
            // and pre-state prefix overlay, while `r` is derived from the endpoint
            // roots above. This replaces the old wide `BlockStateBindingAir` STARK
            // as the soundness-critical transition check; the returned AIR is now
            // only a compact summary used by existing opening-verifier plumbing.
            let witness = BlockStateBindingWitness::new(
                claims.clone(),
                eval_point.clone(),
                gamma,
                prev_lane_openings,
                new_lane_openings,
            );
            if witness.expected_new_lane_openings(prev_lane_openings) != new_lane_openings {
                return Err(crate::VerifyBlockError::StateMleOpeningFailed(sb_idx));
            }
            let expected_batched = witness.expected_batched_claims();

            Ok(BlockStateBindingAir::new(
                &claims,
                prev_lane_openings,
                new_lane_openings,
                &eval_point,
                gamma,
                expected_batched,
            ))
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build `TxLogicAir` instances from a block's transactions.
///
/// Coinbase transactions are excluded from ZK proof coverage (validated by
/// consensus rules only). This function skips them.
///
/// The returned AIRs are in the same order as non-coinbase txs in the block.
pub fn build_tx_airs(block: &Block) -> Vec<TxLogicAir> {
    block
        .transactions
        .iter()
        .filter(|tx| !tx.body.is_coinbase && tx.body.shape == TxShape::Standard4x8)
        .map(|tx| TxLogicAir::new(boundary_pins_from_body(&tx.body)))
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use noid_chain::block::Block;
    use noid_chain::block_header::BlockHeader;
    use noid_chain::consensus::{genesis::GENESIS_TIMESTAMP, params::GENESIS_TARGET};
    use noid_chain::fri_state::SlotValue;
    use noid_chain::state::ChainState;
    use noid_core::Block128;
    use noid_poseidon2b::primitives::{Address, AuthTag, SpendSecret};
    use noid_tx::{compute_claims_commitment, Transaction, TxBody, TxInput, TxOutput};

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

    fn make_input(slot: u32, value: u64, owner: Address) -> TxInput {
        TxInput {
            slot_index: slot,
            value,
            owner,
            spend_secret: SpendSecret([0x55; 32]),
            auth_tag: AuthTag([0x77; 32]),
            valid: true,
        }
    }

    fn seed_slot(state: &mut ChainState, slot: u32, value: u64, owner: Address) {
        let [owner_hi, owner_lo] = owner.as_fields();
        state
            .state
            .set_slot(
                slot,
                SlotValue {
                    value: Block128::from(value as u128),
                    owner_hi,
                    owner_lo,
                },
            )
            .unwrap();
    }

    fn public_inputs_for_body(body: &TxBody) -> PublicInputs {
        let mut is_activation = [false; MAX_OUTPUTS];
        let mut is_deactivation = [false; MAX_INPUTS];
        if body.shape == TxShape::Standard4x8 {
            for (j, output) in body.outputs.iter().enumerate().take(MAX_OUTPUTS) {
                is_activation[j] = output.valid;
            }
            for (i, input) in body.inputs.iter().enumerate().take(MAX_INPUTS) {
                is_deactivation[i] = input.valid;
            }
        }
        PublicInputs {
            epoch_anchor: body.epoch_anchor,
            tx_body_hash: hash_tx_body_for_shape(
                body.shape,
                &body.epoch_anchor,
                body.fee,
                &body.inputs,
                &body.outputs,
                body.is_coinbase,
            ),
            shape_id: body.shape.id(),
            fee: body.fee,
            n_live_inputs: body.inputs.iter().filter(|i| i.valid).count() as u8,
            n_live_outputs: body.outputs.iter().filter(|o| o.valid).count() as u8,
            coinbase_credit: 0,
            log_slots: TEST_LOG_SLOTS as u32,
            claims_commitment: compute_claims_commitment(&body.inputs, &body.outputs),
            is_activation,
            is_deactivation,
        }
    }

    #[test]
    fn canonical_public_inputs_reject_wrong_tx_hash_or_claims_commitment() {
        let body = TxBody {
            shape: TxShape::Standard4x8,
            epoch_anchor: [1u8; 32],
            fee: 0,
            inputs: vec![],
            outputs: vec![TxOutput {
                slot_index: 9,
                value: 100,
                owner: Address([0x33; 32]),
                valid: true,
            }],
            is_coinbase: false,
        };
        let tx = make_transaction(body.clone());
        let pi = public_inputs_for_body(&body);
        validate_public_inputs_for_tx(0, &tx, &pi).expect("canonical public inputs pass");

        let mut bad_tx = tx.clone();
        bad_tx.tx_body_hash.0[0] ^= 1;
        assert!(matches!(
            validate_public_inputs_for_tx(0, &bad_tx, &pi),
            Err(crate::VerifyBlockError::TxPublicInputsMismatch { tx_index: 0 })
        ));

        let mut bad_pi = pi;
        bad_pi.claims_commitment[0] ^= 1;
        assert!(matches!(
            validate_public_inputs_for_tx(0, &tx, &bad_pi),
            Err(crate::VerifyBlockError::TxPublicInputsMismatch { tx_index: 0 })
        ));
    }

    #[test]
    fn state_binding_claim_collection_rejects_input_owner_mismatch() {
        let alice = Address([0x11; 32]);
        let mallory = Address([0x22; 32]);
        let mut state = ChainState::with_log_slots(TEST_LOG_SLOTS);
        seed_slot(&mut state, 3, 100, alice);

        let body = TxBody {
            shape: TxShape::Standard4x8,
            epoch_anchor: [1u8; 32],
            fee: 0,
            inputs: vec![make_input(3, 100, mallory)],
            outputs: vec![],
            is_coinbase: false,
        };
        let commitment = compute_claims_commitment(&body.inputs, &body.outputs);
        let block = Block {
            header: BlockHeader {
                prev_block_hash: [0u8; 32],
                state_root: [0u8; 32],
                tx_root: [0u8; 32],
                timestamp: 0,
                height: 1,
                miner_address: Address([0u8; 32]),
                nonce: 0,
                difficulty_target: GENESIS_TARGET,
                proof_transcript_hash: [1u8; 32],
                witness_root: [1u8; 32],
                log_slots: TEST_LOG_SLOTS as u32,
                active_slot_count: 0,
                alloc_counter: 0,
            },
            transactions: vec![make_transaction(body)],
        };

        let err = collect_state_binding_claims(&block, &[Some(commitment)], &state.state)
            .expect_err("owner mismatch must reject");
        assert!(matches!(
            err,
            crate::VerifyBlockError::StateBindingInputMismatch {
                tx_index: 0,
                input_index: 0
            }
        ));
    }

    #[test]
    fn state_binding_claim_collection_rejects_claim_commitment_mismatch() {
        let alice = Address([0x11; 32]);
        let mut state = ChainState::with_log_slots(TEST_LOG_SLOTS);
        seed_slot(&mut state, 4, 250, alice);

        let body = TxBody {
            shape: TxShape::Standard4x8,
            epoch_anchor: [1u8; 32],
            fee: 0,
            inputs: vec![make_input(4, 250, alice)],
            outputs: vec![],
            is_coinbase: false,
        };
        let block = Block {
            header: BlockHeader {
                prev_block_hash: [0u8; 32],
                state_root: [0u8; 32],
                tx_root: [0u8; 32],
                timestamp: 0,
                height: 1,
                miner_address: Address([0u8; 32]),
                nonce: 0,
                difficulty_target: GENESIS_TARGET,
                proof_transcript_hash: [1u8; 32],
                witness_root: [1u8; 32],
                log_slots: TEST_LOG_SLOTS as u32,
                active_slot_count: 0,
                alloc_counter: 0,
            },
            transactions: vec![make_transaction(body)],
        };

        let err = collect_state_binding_claims(&block, &[Some([0xAB; 32])], &state.state)
            .expect_err("claims commitment mismatch must reject");
        assert!(matches!(
            err,
            crate::VerifyBlockError::StateBindingClaimsCommitmentMismatch { tx_index: 0 }
        ));
    }

    #[test]
    fn build_tx_airs_skips_coinbase() {
        let cb_body = make_tx_body(0, true);
        let tx_body = make_tx_body(1, false);
        let block = Block {
            header: {
                let mut state = ChainState::with_log_slots(TEST_LOG_SLOTS);
                BlockHeader {
                    prev_block_hash: [0u8; 32],
                    state_root: state.state_root(),
                    tx_root: [0u8; 32],
                    timestamp: GENESIS_TIMESTAMP,
                    height: 1,
                    miner_address: Address([0u8; 32]),
                    nonce: 0,
                    difficulty_target: GENESIS_TARGET,
                    proof_transcript_hash: [1u8; 32],
                    witness_root: [1u8; 32],
                    log_slots: TEST_LOG_SLOTS as u32,
                    active_slot_count: 0,
                    alloc_counter: 0,
                }
            },
            transactions: vec![make_transaction(cb_body), make_transaction(tx_body)],
        };
        let airs = build_tx_airs(&block);
        // Only the non-coinbase tx gets an AIR.
        assert_eq!(airs.len(), 1);
    }

    #[test]
    fn build_tx_airs_empty_block() {
        let block = Block {
            header: BlockHeader {
                prev_block_hash: [0u8; 32],
                state_root: [0u8; 32],
                tx_root: [0u8; 32],
                timestamp: 0,
                height: 0,
                miner_address: Address([0u8; 32]),
                nonce: 0,
                difficulty_target: GENESIS_TARGET,
                proof_transcript_hash: [1u8; 32],
                witness_root: [1u8; 32],
                log_slots: 24,
                active_slot_count: 0,
                alloc_counter: 0,
            },
            transactions: vec![],
        };
        let airs = build_tx_airs(&block);
        assert!(airs.is_empty());
    }
}
