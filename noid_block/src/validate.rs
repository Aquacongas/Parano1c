// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Full block validation: consensus checks + ZK proof verification.
//!
//! `validate_block_full` is the complete validation pipeline for a full
//! node receiving a block from the network:
//!
//! 1. `validate_block_consensus()` — all native checks (O(txs))
//! 2. `verify_block()` — ZK proof verification (O(txs × ~84ms))
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
//! - `BlockStateBindingAir` — from proof openings + pre-block FRI state.
//!
//! The `spend_secret` (private key) is NEVER transmitted, NEVER accessed
//! here, and NEVER needed for verification.

use noid_air::composition::sweep25x2_balance_witness_from_body;
use noid_air::composition::tx_logic::{boundary_pins_from_body, TxLogicAir};
use noid_air::Air;
use noid_chain::block::{apply_state_delta, Block};
use noid_chain::block_header::BlockHeader;
use noid_chain::consensus::validation::{validate_block_checks, AnchorInfo};
use noid_chain::consensus::ConsensusError;
use noid_chain::nullifier::NullifierSet;
use noid_chain::state::ChainState;

use crate::{
    block_recursive_claim_hash, verify_block, verify_state_bindings_standalone, BlockProof,
    VerifyBlockError,
};

use noid_air::airs::block_state_binding::BlockStateBindingAir;
use noid_gkr::{AuthPublicInputs, SpineInputs};
use noid_stark::prove_logic_sweep::{
    sweep_spine_inputs_from_body, verify_sweep_logic, N_SWEEP_AUTH_SLICES, SWEEP_BOUNDARY_BASE_LOG,
};
use noid_tx::TxShape;

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

/// Full block validation: native consensus + ZK proof verification.
///
/// Steps (ordered cheapest-first):
/// 1. `validate_block_consensus()` — all native checks
/// 2. `verify_block()` — ZK proof verification
///
/// On success, `state` is updated to the post-block UTXO state.
/// On failure, `state` is left unchanged.
///
/// # Callers must provide
///
/// - `spine_inputs_list`: block GKR slot-state inputs, one per transaction.
///   Build these from the block's transactions and current state.
///
/// - `auth_public_list`: auth GKR public inputs, one per transaction.
///   Derived from the standard bucket public inputs.
///
/// - `state_binding_airs`: BlockStateBinding AIRs for each dirty segment.
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

    // Verify bucket coverage, canonical proof transcript binding, and
    // pi.log_slots == header.log_slots.
    let header_log_slots = block.header.log_slots;
    validate_block_bucket_tx_indices(block, proof).map_err(FullValidationError::ZkProof)?;
    validate_block_proof_transcript_hash(block, proof).map_err(FullValidationError::ZkProof)?;
    if let Some(standard_bucket) = proof.standard_bucket.as_ref() {
        for (tx_index, pi) in standard_bucket.tx_pis.iter().enumerate() {
            if pi.log_slots != header_log_slots {
                return Err(FullValidationError::ZkProof(
                    crate::VerifyBlockError::LogSlotsInconsistent {
                        tx_index,
                        pi_log_slots: pi.log_slots,
                        header_log_slots,
                    },
                ));
            }
        }
    }
    if let Some(sweep_bucket) = proof.sweep_bucket.as_ref() {
        for (tx_index, pi) in sweep_bucket.tx_pis.iter().enumerate() {
            if pi.log_slots != header_log_slots {
                return Err(FullValidationError::ZkProof(
                    crate::VerifyBlockError::LogSlotsInconsistent {
                        tx_index,
                        pi_log_slots: pi.log_slots,
                        header_log_slots,
                    },
                ));
            }
        }
        verify_sweep_bucket_from_block(block, proof).map_err(FullValidationError::ZkProof)?;
    }

    // ZK proof verification for the current standard bucket path. Mixed blocks
    // verify sweep wallet proofs above and state-binding through the standard
    // bucket commitment.
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
/// 2. Reconstructs `SpineInputs`, `AuthPublicInputs`, and `BlockStateBindingAir`
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
    let sb_airs = build_state_binding_airs(block, &proof, pre_state);
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
                if tx.body.shape != TxShape::Standard4x8
                    || pi.tx_body_hash != tx.tx_body_hash
                    || pi.shape_id != TxShape::Standard4x8.id()
                {
                    return Err(crate::VerifyBlockError::ShapeMismatch);
                }
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
                || bucket.auth_slices.len() != expected_sweep.len()
                || bucket.spine_inputs.len() != expected_sweep.len()
                || bucket.logic_proofs.len() != expected_sweep.len()
                || bucket.meta.n_boundary_slices_per_tx as usize != N_SWEEP_AUTH_SLICES
            {
                return Err(crate::VerifyBlockError::ShapeMismatch);
            }
            for ((pi, auth_slices), block_idx) in bucket
                .tx_pis
                .iter()
                .zip(bucket.auth_slices.iter())
                .zip(expected_sweep.iter().copied())
            {
                let tx = &block.transactions[block_idx as usize];
                if tx.body.shape != TxShape::Sweep25x2
                    || pi.tx_body_hash != tx.tx_body_hash
                    || pi.shape_id != TxShape::Sweep25x2.id()
                    || auth_slices.len() != N_SWEEP_AUTH_SLICES
                    || !auth_slices
                        .iter()
                        .all(|slice| slice.len() == (1usize << SWEEP_BOUNDARY_BASE_LOG))
                {
                    return Err(crate::VerifyBlockError::ShapeMismatch);
                }
            }
        }
        (None, true) => {}
        _ => return Err(crate::VerifyBlockError::ShapeMismatch),
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

        let balance = sweep25x2_balance_witness_from_body(&tx.body);
        let (air, _trace) = balance
            .build_air_and_trace_with_log_rows(noid_air::airs::tx_body_spine::SPINE_LOG_ROWS);
        verify_sweep_logic(
            &air,
            &bucket.tx_pis[k],
            &bucket.spine_inputs[k],
            &bucket.auth_public[k],
            &bucket.logic_proofs[k],
        )
        .map_err(|_| crate::VerifyBlockError::SweepLogic(k))?;
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

/// Reconstruct `BlockStateBindingAir` instances from proof openings and
/// the pre-block FRI state.
///
/// Collects per-segment slot-change claims from the block's transactions,
/// reads pre-state slot values from `pre_state`, then re-derives `gamma`
/// and `expected_batched_claims` using the same deterministic channel as
/// the prover.  Returns one `BlockStateBindingAir` per dirty segment in
/// segment-id order.
pub fn build_state_binding_airs(
    block: &Block,
    proof: &BlockProof,
    pre_state: &noid_chain::segmented_state::SegmentedFriState,
) -> Vec<BlockStateBindingAir> {
    use noid_air::airs::block_state_binding::{BlockStateBindingClaim, BlockStateBindingWitness};
    use noid_core::Block128;
    use noid_fri::Channel;
    use std::collections::BTreeMap;

    let n_state_bindings = proof.meta.n_state_bindings as usize;
    if n_state_bindings == 0 {
        return vec![];
    }

    let eff_log = pre_state.effective_log_segment_size();
    let seg_mask = (1u32 << eff_log) - 1;
    let n_tx = proof.meta.n_tx as usize;
    let prev_state_root = &proof.meta.prev_block_state_root;

    // Collect slot changes per segment, sorted by seg_id (BTreeMap).
    let mut seg_claims: BTreeMap<u16, Vec<BlockStateBindingClaim>> = BTreeMap::new();

    for tx in block.transactions.iter() {
        if tx.body.is_coinbase {
            // Coinbase has no inputs. Include its outputs as mint claims so the
            // post-state MLE and seg_root are consistent with the global new_state_root
            // (which includes coinbase changes). Skipping coinbase would cause a Merkle
            // path mismatch when coinbase and user TXs touch the same segment.
            for out in tx.body.outputs.iter().filter(|o| o.valid) {
                let seg_id = (out.slot_index >> eff_log) as u16;
                let local = out.slot_index & seg_mask;
                let [owner_hi, owner_lo] = out.owner.as_fields();
                seg_claims
                    .entry(seg_id)
                    .or_default()
                    .push(BlockStateBindingClaim::mint(
                        local,
                        Block128::from(out.value as u128),
                        owner_hi,
                        owner_lo,
                    ));
            }
            continue;
        }
        // Spend claims: deactivated input slots.
        for inp in tx.body.inputs.iter().filter(|i| i.valid) {
            let seg_id = (inp.slot_index >> eff_log) as u16;
            let local = inp.slot_index & seg_mask;
            let sv = pre_state.slot(inp.slot_index);
            seg_claims
                .entry(seg_id)
                .or_default()
                .push(BlockStateBindingClaim::spend(
                    local,
                    sv.value,
                    sv.owner_hi,
                    sv.owner_lo,
                ));
        }
        // Mint claims: activated output slots.
        for out in tx.body.outputs.iter().filter(|o| o.valid) {
            let seg_id = (out.slot_index >> eff_log) as u16;
            let local = out.slot_index & seg_mask;
            let [owner_hi, owner_lo] = out.owner.as_fields();
            seg_claims
                .entry(seg_id)
                .or_default()
                .push(BlockStateBindingClaim::mint(
                    local,
                    Block128::from(out.value as u128),
                    owner_hi,
                    owner_lo,
                ));
        }
    }

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
        .map(|(sb_idx, (_seg_id, claims))| {
            let pre_op = &proof.pre_state_openings[sb_idx];
            let post_op = &proof.post_state_openings[sb_idx];

            let eval_point = pre_op.eval_point.clone();
            let prev_lane_openings = pre_op.lane_values;
            let new_lane_openings = post_op.lane_values;

            // Re-derive gamma from the same deterministic channel as the prover.
            let gamma = {
                let mut ch = Channel::new();
                let lo = u128::from_le_bytes(prev_state_root[..16].try_into().unwrap());
                let hi = u128::from_le_bytes(prev_state_root[16..].try_into().unwrap());
                ch.observe_field_elem(Block128::from(lo));
                ch.observe_field_elem(Block128::from(hi));
                ch.observe_field_elem(Block128::from((n_tx as u128) + sb_idx as u128));
                // Consume the eval_point squeezes (same count as prover).
                for _ in 0..eval_point.len() {
                    ch.get_random_point();
                }
                ch.get_random_point() // gamma follows the eval_point
            };

            // Compute expected_batched_claims deterministically from claims.
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
    use noid_chain::state::ChainState;
    use noid_poseidon2b::primitives::Address;
    use noid_tx::{Transaction, TxBody, TxOutput};

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
