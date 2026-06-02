// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

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
//! For Phase 2: full reconstruction from block + state will be implemented
//! in `build_spine_inputs_from_block()` and `build_auth_public_inputs()`.
//! In Phase 1 callers that already have these (e.g. from prove_block) can
//! pass them directly.

use noid_air::composition::tx_logic::{boundary_pins_from_body, TxLogicAir};
use noid_air::Air;
use noid_chain::block::Block;
use noid_chain::block_header::BlockHeader;
use noid_chain::consensus::validation::AnchorInfo;
use noid_chain::consensus::ConsensusError;
use noid_chain::nullifier::NullifierSet;
use noid_chain::state::ChainState;

use crate::{verify_block, BlockProof, VerifyBlockError};

use noid_air::airs::block_state_binding::BlockStateBindingAir;
use noid_gkr::{AuthPublicInputs, SpineInputs};

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
///   Phase 2 TODO: add `build_spine_inputs_from_block(block, state)` helper.
///
/// - `auth_public_list`: auth GKR public inputs, one per transaction.
///   Derived from `proof.tx_pis` public inputs.
///   Phase 2 TODO: add `build_auth_public_from_proof(proof)` helper.
///
/// - `state_binding_airs`: BlockStateBinding AIRs for each dirty segment.
///   Phase 2 TODO: add `build_state_binding_airs(block, state)` helper.
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
    use noid_chain::consensus::validation::validate_block_consensus;

    // Step 1: native consensus checks (cheap, fail-fast).
    validate_block_consensus(
        block,
        parent,
        prev_timestamps,
        prev_active_counts,
        local_time,
        anchor,
        nullifiers,
        state,
    )?;

    // Step 2: ZK proof verification (expensive, ~N × 84ms).
    // Build TxLogicAirs from the transactions (coinbase skipped — no logic proof).
    let tx_airs: Vec<TxLogicAir> = block
        .transactions
        .iter()
        .filter(|tx| !tx.body.is_coinbase)
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

    Ok(block.header.state_root)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build `TxLogicAir` instances from a block's transactions.
///
/// Coinbase transactions do not have a TxLogicAir (they are proved directly
/// by BlockStateBinding). This function skips them.
///
/// The returned AIRs are in the same order as non-coinbase txs in the block.
pub fn build_tx_airs(block: &Block) -> Vec<TxLogicAir> {
    block
        .transactions
        .iter()
        .filter(|tx| !tx.body.is_coinbase)
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
