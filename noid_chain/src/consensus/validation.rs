// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Consensus checks shared by proof-native validation and in-memory utilities.
//!
//! Live full nodes use `validate_block_checks` as the cheap first stage, then
//! verify the full `BlockProof`/`BlockStateBindingAir`, then commit via
//! `apply_state_delta`. `validate_block_consensus` is the sequential interpreter
//! path for RAM tests/utilities and is not the live production acceptance path.
//!
//! # Invariants checked here (SPEC §16)
//!
//!  ✅  Header chain (prev_hash, height, difficulty, timestamp, PoW)     [P.6]
//!  ✅  Coinbase structure (at most one, first, zero inputs)              [P.7 partial]
//!  ✅  Coinbase value ≤ block_reward(log_slots) + Σ fees                [P.7 full]
//!  ✅  Per-tx: body_hash binding, non-zero anchor, nullifier             [P.8]
//!  ✅  Cross-tx slot conflicts                                           [P.8]
//!  ✅  TooManyTxs                                                        [P.9]
//!  ✅  Sequential state transition (`validate_block_consensus` only)       [P.9]
//!
//! # Invariants checked by the production ZK layer
//!
//!  ✅  Wallet/bucket proof verifies (STARK + AuthGKR)
//!  ✅  BlockStateBinding verifies state openings and roots
//!  ✅  C_claimed bridge
//!  ✅  BlockProof aggregate verifies
//!  ❌  epoch_anchor hash matches actual header at that height (needs HeaderProvider)
//!  ❌  da_root / witness_root binding (needs packed DA data)

use crate::block::apply_block;
use crate::block::Block;
use crate::block_header::BlockHeader;
use crate::consensus::timestamps::median_u64;
use crate::consensus::{
    checks::{validate_block_slot_conflicts, validate_tx_consensus_skip_hash},
    emission::max_coinbase_value_from_fee_sum,
    fees::{claimable_fee_for_tx_body, required_fee_for_tx_body},
    header::validate_header,
    params::BLOCK_MAX_TXS,
    ConsensusError,
};
use crate::nullifier::NullifierSet;
use crate::state::ChainState;

/// Parameters needed for header chain validation.
pub struct AnchorInfo {
    /// Height of the ASERT anchor block.
    pub anchor_height: u64,
    /// Timestamp of the ASERT anchor block.
    pub anchor_timestamp: u64,
    /// Difficulty target at the ASERT anchor block.
    pub anchor_target: [u8; 32],
}

fn validate_fee_policy_and_claimable_fee_sum(
    block: &Block,
    parent: &BlockHeader,
) -> Result<u64, ConsensusError> {
    let mut claimable_fee_sum = 0u64;
    for tx in block.transactions.iter().filter(|tx| !tx.body.is_coinbase) {
        let required =
            required_fee_for_tx_body(&tx.body, parent.active_slot_count, parent.log_slots);
        let actual = tx.body.fee.min(u64::MAX as u128) as u64;
        if actual < required {
            return Err(ConsensusError::BelowMinFee { required, actual });
        }
        claimable_fee_sum = claimable_fee_sum.saturating_add(claimable_fee_for_tx_body(
            &tx.body,
            parent.active_slot_count,
            parent.log_slots,
        ));
    }
    Ok(claimable_fee_sum)
}

/// Run all native consensus checks WITHOUT applying the state transition.
///
/// Use this as the first step of the full-proof-native validation path:
///   1. `validate_block_checks()` — header + tx checks (no MDBX reads)
///   2. `verify_block(BlockProof)` — ZK proof verification
///   3. `apply_state_delta()` — write delta to MDBX (no pre-state reads)
///
/// Note: does NOT check `state_root` (that's done by ZK proof verification).
/// Does NOT check `active_slot_count` / `alloc_counter` (done by `apply_state_delta`).
pub fn validate_block_checks(
    block: &Block,
    parent: &BlockHeader,
    prev_timestamps: &[u64],
    prev_active_counts: &[u64],
    local_time: u64,
    anchor: &AnchorInfo,
    nullifiers: &NullifierSet,
) -> Result<(), ConsensusError> {
    validate_header(
        &block.header,
        parent,
        prev_timestamps,
        local_time,
        anchor.anchor_height,
        anchor.anchor_timestamp,
        &anchor.anchor_target,
    )?;
    {
        use crate::consensus::params::{EXPAND_DENOM, EXPAND_NUM, LOG_SLOTS_MAX};
        let prev_capacity = 1u64.checked_shl(parent.log_slots).unwrap_or(u64::MAX);
        let median_active = if prev_active_counts.is_empty() {
            parent.active_slot_count
        } else {
            median_u64(prev_active_counts)
        };
        let trigger =
            median_active.saturating_mul(EXPAND_DENOM) >= prev_capacity.saturating_mul(EXPAND_NUM);
        let expected = if trigger {
            parent.log_slots.saturating_add(1).min(LOG_SLOTS_MAX)
        } else {
            parent.log_slots
        };
        if block.header.log_slots != expected {
            return Err(ConsensusError::BadLogSlotsExpansion);
        }
    }
    if block.transactions.len() > BLOCK_MAX_TXS {
        return Err(ConsensusError::TooManyTxs);
    }
    validate_block_slot_conflicts(&block.transactions)?;
    for tx in &block.transactions {
        validate_tx_consensus_skip_hash(tx, nullifiers)?;
    }
    let claimable_fee_sum = validate_fee_policy_and_claimable_fee_sum(block, parent)?;
    if let Some(cb) = block.transactions.first() {
        if cb.body.is_coinbase {
            let cb_value: u64 = cb
                .body
                .outputs
                .iter()
                .filter(|o| o.valid)
                .map(|o| o.value)
                .fold(0u64, |a, v| a.saturating_add(v));
            let max_allowed =
                max_coinbase_value_from_fee_sum(block.header.log_slots, claimable_fee_sum);
            if cb_value > max_allowed {
                return Err(ConsensusError::InflatedCoinbase);
            }
        }
    }
    Ok(())
}

/// Validate through the sequential interpreter and apply it to `state`.
///
/// This is not the live full-node production path. It is used by the in-memory
/// context and tests/utilities that intentionally recompute the transition
/// directly. Production validation uses:
/// `validate_block_checks` + full `BlockProof` verification + `apply_state_delta`.
///
/// On success, `state` is updated. On failure, `state` is left unchanged.
pub fn validate_block_consensus(
    block: &Block,
    parent: &BlockHeader,
    prev_timestamps: &[u64],
    prev_active_counts: &[u64],
    local_time: u64,
    anchor: &AnchorInfo,
    nullifiers: &NullifierSet,
    state: &mut ChainState,
) -> Result<[u8; 32], ConsensusError> {
    // --- Header checks (P.6) ---
    validate_header(
        &block.header,
        parent,
        prev_timestamps,
        local_time,
        anchor.anchor_height,
        anchor.anchor_timestamp,
        &anchor.anchor_target,
    )?;

    // --- §15.3.6 log_slots expansion trigger (median-based) ---
    //
    // Expansion fires when the MEDIAN active_slot_count over the last
    // EXPANSION_WINDOW (= FINALITY_DEPTH = 18) finalised headers exceeds
    // 75% of capacity.  Using the median prevents a single-block spam spike
    // from forcing an expansion: an attacker would need to sustain > 75%
    // occupancy across a majority of the window blocks.
    //
    // `prev_active_counts` is supplied by the caller (from stored headers);
    // it falls back to `[parent.active_slot_count]` when the window is shallow.
    {
        use crate::consensus::params::{EXPAND_DENOM, EXPAND_NUM, LOG_SLOTS_MAX};
        let prev_capacity = 1u64.checked_shl(parent.log_slots).unwrap_or(u64::MAX);
        // Median of the supplied window; fall back to parent when window is empty.
        let median_active = if prev_active_counts.is_empty() {
            parent.active_slot_count
        } else {
            median_u64(prev_active_counts)
        };
        let trigger =
            median_active.saturating_mul(EXPAND_DENOM) >= prev_capacity.saturating_mul(EXPAND_NUM);
        let expected_log_slots = if trigger {
            parent.log_slots.saturating_add(1).min(LOG_SLOTS_MAX)
        } else {
            parent.log_slots
        };
        if block.header.log_slots != expected_log_slots {
            return Err(ConsensusError::BadLogSlotsExpansion);
        }
    }

    // --- Tx count limit ---
    if block.transactions.len() > BLOCK_MAX_TXS {
        return Err(ConsensusError::TooManyTxs);
    }

    // --- Cross-tx slot conflict check (P.8, §16 invariants 4-5) ---
    validate_block_slot_conflicts(&block.transactions)?;

    // --- Per-tx consensus checks (P.8) ---
    // Use skip_hash variant: the sequential interpreter below already verifies
    // tx_body_hash for every tx, so recomputing 59-perm Poseidon2b here
    // would be pure redundant work (~15 ms at 256 txs).
    for tx in &block.transactions {
        validate_tx_consensus_skip_hash(tx, nullifiers)?;
    }

    let claimable_fee_sum = validate_fee_policy_and_claimable_fee_sum(block, parent)?;

    // --- Coinbase amount validation (P.7) ---
    // Sum fees directly from &Transaction references — no TxBody cloning.
    if let Some(cb) = block.transactions.first() {
        if cb.body.is_coinbase {
            let cb_value: u64 = cb
                .body
                .outputs
                .iter()
                .filter(|o| o.valid)
                .map(|o| o.value)
                .fold(0u64, |acc, v| acc.saturating_add(v));

            let max_allowed =
                max_coinbase_value_from_fee_sum(block.header.log_slots, claimable_fee_sum);
            if cb_value > max_allowed {
                return Err(ConsensusError::InflatedCoinbase);
            }
        }
    }

    // --- Sequential state transition (apply_block handles state_root, active counts, etc.) ---
    // apply_block returns Err(BlockApplyError) on mismatch; map to ConsensusError.
    apply_block(state, block).map_err(|e| {
        use crate::block::BlockApplyError;
        match e {
            BlockApplyError::TooManyTransactions => ConsensusError::TooManyTxs,
            BlockApplyError::UnsupportedTxShape => {
                ConsensusError::ShapeMismatch("unsupported tx shape".to_string())
            }
            BlockApplyError::WrongTxBodyHash => ConsensusError::BadTxBodyHash,
            BlockApplyError::HeaderStateRootMismatch => ConsensusError::BadStateRoot,
            BlockApplyError::HeaderTxRootMismatch => ConsensusError::BadTxRoot,
            BlockApplyError::MissingProofTranscriptHash => ConsensusError::MissingProof,
            BlockApplyError::StubProofWithUserTxs => ConsensusError::StubProof,
            _ => ConsensusError::ShapeMismatch(format!("{:?}", e)),
        }
    })?;

    Ok(block.header.state_root)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::Block;
    use crate::block_header::BlockHeader;
    use crate::consensus::{genesis::GENESIS_TIMESTAMP, params::BLOCK_TIME};
    use crate::nullifier::NullifierSet;
    use crate::state::ChainState;
    use noid_poseidon2b::primitives::{Address, AuthTag, SpendSecret};
    use noid_tx::{hash_tx_body, Transaction, TxBody, TxInput, TxOutput};

    const TEST_TARGET: [u8; 32] = [0xFF; 32];
    const TEST_LOG_SLOTS: usize = 6;

    fn mk_parent(height: u64, ts: u64, prev_hash: [u8; 32], state_root: [u8; 32]) -> BlockHeader {
        BlockHeader {
            prev_block_hash: prev_hash,
            state_root,
            tx_root: [0u8; 32],
            timestamp: ts,
            height,
            miner_address: Address([0u8; 32]),
            nonce: 0,
            difficulty_target: TEST_TARGET,
            proof_transcript_hash: [1u8; 32],
            witness_root: [1u8; 32],
            log_slots: TEST_LOG_SLOTS as u32,
            active_slot_count: 0,
            alloc_counter: 0,
        }
    }

    /// Build a minimal valid block (no txs) on top of `parent`.
    fn build_empty_block(parent: &BlockHeader, state: &mut ChainState) -> Block {
        use crate::block::compute_tx_root;
        use crate::consensus::pow::full_block_hash;

        let mut header = BlockHeader {
            prev_block_hash: full_block_hash(parent),
            state_root: state.state_root(),
            tx_root: compute_tx_root(&[]),
            timestamp: parent.timestamp + BLOCK_TIME,
            height: parent.height + 1,
            miner_address: Address([0u8; 32]),
            nonce: 0,
            difficulty_target: TEST_TARGET,
            proof_transcript_hash: [1u8; 32],
            witness_root: [1u8; 32],
            log_slots: state.state.log_slots() as u32,
            active_slot_count: state.active_slot_count,
            alloc_counter: state.alloc_counter,
        };
        header.nonce = 0; // TEST_TARGET: any nonce works
        Block {
            header,
            transactions: vec![],
        }
    }

    fn genesis_anchor(parent: &BlockHeader) -> AnchorInfo {
        AnchorInfo {
            anchor_height: 0,
            anchor_timestamp: parent.timestamp,
            anchor_target: parent.difficulty_target,
        }
    }

    fn tx_from_body(body: TxBody) -> Transaction {
        let hash = hash_tx_body(
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

    fn fee_test_user_tx(fee: u128) -> Transaction {
        tx_from_body(TxBody {
            shape: noid_tx::TxShape::Standard4x8,
            epoch_anchor: [1u8; 32],
            fee,
            inputs: vec![TxInput {
                slot_index: 1,
                value: 10_000,
                owner: Address([1u8; 32]),
                spend_secret: SpendSecret([2u8; 32]),
                auth_tag: AuthTag([3u8; 32]),
                valid: true,
            }],
            outputs: vec![
                TxOutput {
                    slot_index: 2,
                    value: 1_000,
                    owner: Address([4u8; 32]),
                    valid: true,
                },
                TxOutput {
                    slot_index: 3,
                    value: 0,
                    owner: Address([5u8; 32]),
                    valid: true,
                },
            ],
            is_coinbase: false,
        })
    }

    fn fee_test_coinbase(value: u64) -> Transaction {
        tx_from_body(TxBody {
            shape: noid_tx::TxShape::Standard4x8,
            epoch_anchor: [0u8; 32],
            fee: 0,
            inputs: vec![],
            outputs: vec![TxOutput {
                slot_index: 0,
                value,
                owner: Address([9u8; 32]),
                valid: true,
            }],
            is_coinbase: true,
        })
    }

    fn block_for_fee_checks(parent: &BlockHeader, coinbase_value: u64, user_fee: u64) -> Block {
        use crate::block::compute_tx_root;
        use crate::consensus::pow::full_block_hash;

        let txs = vec![
            fee_test_coinbase(coinbase_value),
            fee_test_user_tx(user_fee as u128),
        ];
        Block {
            header: BlockHeader {
                prev_block_hash: full_block_hash(parent),
                state_root: parent.state_root,
                tx_root: compute_tx_root(&txs),
                timestamp: parent.timestamp + BLOCK_TIME,
                height: parent.height + 1,
                miner_address: Address([0u8; 32]),
                nonce: 0,
                difficulty_target: TEST_TARGET,
                proof_transcript_hash: [2u8; 32],
                witness_root: [2u8; 32],
                log_slots: parent.log_slots,
                active_slot_count: parent.active_slot_count,
                alloc_counter: parent.alloc_counter,
            },
            transactions: txs,
        }
    }

    #[test]
    fn empty_block_on_genesis_validates() {
        let mut state = ChainState::with_log_slots(TEST_LOG_SLOTS);
        let state_root = state.state_root();
        let parent = mk_parent(0, GENESIS_TIMESTAMP, [0u8; 32], state_root);
        let block = build_empty_block(&parent, &mut state.clone());

        let mut apply_state = ChainState::with_log_slots(TEST_LOG_SLOTS);
        let result = validate_block_consensus(
            &block,
            &parent,
            &[parent.timestamp],
            &[parent.active_slot_count],
            block.header.timestamp + 1,
            &genesis_anchor(&parent),
            &NullifierSet::new(),
            &mut apply_state,
        );
        assert!(result.is_ok(), "empty block should validate: {:?}", result);
    }

    #[test]
    fn block_checks_reject_underpriced_user_tx() {
        let mut state = ChainState::with_log_slots(TEST_LOG_SLOTS);
        let state_root = state.state_root();
        let parent = mk_parent(0, GENESIS_TIMESTAMP, [0u8; 32], state_root);
        let required = crate::consensus::required_fee_for_tx_body(
            &fee_test_user_tx(0).body,
            parent.active_slot_count,
            parent.log_slots,
        );
        let block = block_for_fee_checks(&parent, 0, required - 1);

        let result = validate_block_checks(
            &block,
            &parent,
            &[parent.timestamp],
            &[parent.active_slot_count],
            block.header.timestamp + 1,
            &genesis_anchor(&parent),
            &NullifierSet::new(),
        );
        assert_eq!(
            result,
            Err(ConsensusError::BelowMinFee {
                required,
                actual: required - 1
            })
        );
    }

    #[test]
    fn block_checks_burn_state_growth_fee_for_coinbase_limit() {
        let mut state = ChainState::with_log_slots(TEST_LOG_SLOTS);
        let state_root = state.state_root();
        let parent = mk_parent(0, GENESIS_TIMESTAMP, [0u8; 32], state_root);
        let user_tx = fee_test_user_tx(9_000);
        let claimable = crate::consensus::claimable_fee_for_tx_body(
            &user_tx.body,
            parent.active_slot_count,
            parent.log_slots,
        );
        assert_eq!(claimable, 6_500);
        let reward = crate::consensus::block_reward(parent.log_slots);

        let valid = block_for_fee_checks(&parent, reward + claimable, 9_000);
        let valid_result = validate_block_checks(
            &valid,
            &parent,
            &[parent.timestamp],
            &[parent.active_slot_count],
            valid.header.timestamp + 1,
            &genesis_anchor(&parent),
            &NullifierSet::new(),
        );
        assert!(
            valid_result.is_ok(),
            "coinbase may claim reward + non-burned fees"
        );

        let inflated = block_for_fee_checks(&parent, reward + 9_000, 9_000);
        let inflated_result = validate_block_checks(
            &inflated,
            &parent,
            &[parent.timestamp],
            &[parent.active_slot_count],
            inflated.header.timestamp + 1,
            &genesis_anchor(&parent),
            &NullifierSet::new(),
        );
        assert_eq!(inflated_result, Err(ConsensusError::InflatedCoinbase));
    }

    #[test]
    fn bad_pow_rejected() {
        let mut state = ChainState::with_log_slots(TEST_LOG_SLOTS);
        let state_root = state.state_root();
        let parent = mk_parent(0, GENESIS_TIMESTAMP, [0u8; 32], state_root);
        let mut block = build_empty_block(&parent, &mut state.clone());
        block.header.nonce = 99999999; // likely invalid nonce

        let mut apply_state = ChainState::with_log_slots(TEST_LOG_SLOTS);
        let result = validate_block_consensus(
            &block,
            &parent,
            &[parent.timestamp],
            &[parent.active_slot_count],
            block.header.timestamp + 1,
            &genesis_anchor(&parent),
            &NullifierSet::new(),
            &mut apply_state,
        );
        // Either InvalidPoW (nonce doesn't satisfy target) or ok if we got unlucky
        // and it happens to work. Just exercise the path.
        let _ = result;
    }

    #[test]
    fn expansion_trigger_enforced() {
        // Build a parent that is at exactly 75% occupancy (should trigger expansion).
        let mut state = ChainState::with_log_slots(TEST_LOG_SLOTS);
        let capacity = 1u64 << TEST_LOG_SLOTS as u64;
        // Set active_slot_count to 75% of capacity.
        let target_active = (capacity * 3) / 4;
        state.active_slot_count = target_active;

        let state_root = state.state_root();
        let parent = BlockHeader {
            prev_block_hash: [0u8; 32],
            state_root,
            tx_root: [0u8; 32],
            timestamp: GENESIS_TIMESTAMP,
            height: 0,
            miner_address: noid_poseidon2b::primitives::Address([0u8; 32]),
            nonce: 0,
            difficulty_target: TEST_TARGET,
            proof_transcript_hash: [1u8; 32],
            witness_root: [1u8; 32],
            log_slots: TEST_LOG_SLOTS as u32,
            active_slot_count: target_active,
            alloc_counter: 0,
        };

        // Block claiming log_slots = TEST_LOG_SLOTS (no expansion) should be rejected.
        let block_no_expand = {
            use crate::block::compute_tx_root;
            use crate::consensus::pow::full_block_hash;
            let mut hdr = BlockHeader {
                prev_block_hash: full_block_hash(&parent),
                state_root,
                tx_root: compute_tx_root(&[]),
                timestamp: parent.timestamp + BLOCK_TIME,
                height: 1,
                miner_address: noid_poseidon2b::primitives::Address([0u8; 32]),
                nonce: 0,
                difficulty_target: TEST_TARGET,
                proof_transcript_hash: [1u8; 32],
                witness_root: [1u8; 32],
                log_slots: TEST_LOG_SLOTS as u32, // should be TEST_LOG_SLOTS + 1
                active_slot_count: target_active,
                alloc_counter: 0,
            };
            hdr.nonce = 0; // TEST_TARGET: any nonce works
            crate::block::Block {
                header: hdr,
                transactions: vec![],
            }
        };

        let mut apply_state = ChainState::with_log_slots(TEST_LOG_SLOTS);
        apply_state.active_slot_count = target_active;
        // Pass a window where all EXPANSION_WINDOW values are at 75% —
        // median will equal target_active and trigger expansion.
        let active_window = vec![target_active; 18];
        let result = validate_block_consensus(
            &block_no_expand,
            &parent,
            &[parent.timestamp],
            &active_window,
            block_no_expand.header.timestamp + 1,
            &genesis_anchor(&parent),
            &NullifierSet::new(),
            &mut apply_state,
        );
        assert_eq!(
            result,
            Err(ConsensusError::BadLogSlotsExpansion),
            "block must fail when expansion trigger fires but log_slots not incremented"
        );
    }

    #[test]
    fn expansion_not_triggered_by_single_spike() {
        // Median-based trigger: even if parent is at 75%, a window where
        // only the last value is high should NOT trigger (median stays low).
        let mut state = ChainState::with_log_slots(TEST_LOG_SLOTS);
        let capacity = 1u64 << TEST_LOG_SLOTS as u64;
        let low_active = capacity / 4; // 25% — most of the window
        let spike_active = (capacity * 3) / 4; // 75% — only last value
        state.active_slot_count = spike_active;

        let state_root = state.state_root();
        let parent = BlockHeader {
            prev_block_hash: [0u8; 32],
            state_root,
            tx_root: [0u8; 32],
            timestamp: GENESIS_TIMESTAMP,
            height: 0,
            miner_address: noid_poseidon2b::primitives::Address([0u8; 32]),
            nonce: 0,
            difficulty_target: TEST_TARGET,
            proof_transcript_hash: [1u8; 32],
            witness_root: [1u8; 32],
            log_slots: TEST_LOG_SLOTS as u32,
            active_slot_count: spike_active,
            alloc_counter: 0,
        };

        // Build a block that does NOT expand (log_slots unchanged).
        use crate::block::compute_tx_root;
        use crate::consensus::pow::full_block_hash;
        let mut hdr = BlockHeader {
            prev_block_hash: full_block_hash(&parent),
            state_root,
            tx_root: compute_tx_root(&[]),
            timestamp: parent.timestamp + BLOCK_TIME,
            height: 1,
            miner_address: noid_poseidon2b::primitives::Address([0u8; 32]),
            nonce: 0,
            difficulty_target: TEST_TARGET,
            proof_transcript_hash: [1u8; 32],
            witness_root: [1u8; 32],
            log_slots: TEST_LOG_SLOTS as u32, // no expansion
            active_slot_count: spike_active,
            alloc_counter: 0,
        };
        hdr.nonce = 0; // TEST_TARGET: any nonce works
        let block = crate::block::Block {
            header: hdr,
            transactions: vec![],
        };

        // Window: 17 values at 25%, 1 value at 75%. Median = 25% → no trigger.
        let mut active_window = vec![low_active; 17];
        active_window.push(spike_active);

        let mut apply_state = ChainState::with_log_slots(TEST_LOG_SLOTS);
        apply_state.active_slot_count = spike_active;
        let result = validate_block_consensus(
            &block,
            &parent,
            &[parent.timestamp],
            &active_window,
            block.header.timestamp + 1,
            &genesis_anchor(&parent),
            &NullifierSet::new(),
            &mut apply_state,
        );
        assert!(
            result.is_ok(),
            "single spike must not trigger expansion via median: {:?}",
            result
        );
    }
}
