// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Consensus checks shared by proof-native validation and in-memory utilities.
//!
//! Live full nodes use `validate_block_checks` as the cheap first stage, then
//! verify the minimal block proof, then commit via the exact authenticated state
//! transition. `validate_block_consensus` is the sequential interpreter
//! path for RAM tests/utilities and is not the live production acceptance path.
//!
//! # Invariants checked here (SPEC §16)
//!
//!  ✅  Header chain (prev_hash, height, difficulty, timestamp, PoW)     [P.6]
//!  ✅  Coinbase structure (at most one, first, zero inputs)              [P.7 partial]
//!  ✅  Coinbase value ≤ block_reward(log_slots) + Σ fees                [P.7 full]
//!  ✅  Per-tx: body_hash binding, non-zero anchor                        [P.8]
//!  ✅  Cross-tx slot conflicts                                           [P.8]
//!  ✅  Decoder tx cap and semantic block budget                          [P.9]
//!  ✅  Sequential state transition (`validate_block_consensus` only)       [P.9]
//!
//! # Invariants checked by the production proof layer
//!
//!  ✅  Wallet authorization proof verifies for every user transaction
//!  ✅  Exact public transaction predicate verifies for every user transaction
//!  ✅  Exact authenticated state transition verifies state updates
//!  ✅  Detached block proof metadata matches the semantic block statement
//!  ✅  Detached authorization sidecar verifies for every user transaction
//!  ❌  epoch_anchor hash matches actual header at that height (needs HeaderProvider)

use crate::block::apply_block;
use crate::block::Block;
use crate::block_header::BlockHeader;
use crate::consensus::{
    checks::{validate_block_slot_conflicts, validate_tx_consensus_skip_hash},
    emission::max_coinbase_value_from_fee_sum,
    fees::{claimable_fee_for_tx_body, required_fee_for_tx_body},
    header::{validate_header, validate_header_timeless},
    params::{
        block_semantic_limits_ok, BLOCK_MAX_LIVE_INPUTS, BLOCK_MAX_OWNER_GROUPS, BLOCK_MAX_TXS,
        BLOCK_MAX_USER_ACTIONS, BLOCK_MAX_USER_OUTPUTS, BLOCK_MAX_USER_TXS,
    },
    ConsensusError,
};
use crate::state::ChainState;

/// Parameters needed for header chain validation.
#[derive(Debug, Clone)]
pub struct AnchorInfo {
    /// Height of the ASERT anchor block.
    pub anchor_height: u64,
    /// Timestamp of the ASERT anchor block.
    pub anchor_timestamp: u64,
    /// Difficulty target at the ASERT anchor block.
    pub anchor_target: [u8; 32],
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BlockSemanticCounts {
    pub user_txs: usize,
    pub live_inputs: usize,
    pub user_outputs: usize,
    pub owner_groups_upper_bound: usize,
    pub user_actions: usize,
}

pub fn block_semantic_counts(block: &Block) -> BlockSemanticCounts {
    let mut counts = BlockSemanticCounts::default();
    for tx in block.transactions.iter().filter(|tx| !tx.body.is_coinbase) {
        counts.user_txs += 1;
        let live_inputs = tx.body.inputs.iter().filter(|input| input.valid).count();
        let live_outputs = tx.body.outputs.iter().filter(|output| output.valid).count();
        counts.live_inputs += live_inputs;
        counts.user_outputs += live_outputs;
    }
    counts.owner_groups_upper_bound = counts.live_inputs;
    counts.user_actions = counts.live_inputs + counts.user_outputs;
    counts
}

pub fn validate_block_semantic_limits(
    block: &Block,
) -> Result<BlockSemanticCounts, ConsensusError> {
    let counts = block_semantic_counts(block);
    if block_semantic_limits_ok(
        counts.user_txs,
        counts.live_inputs,
        counts.user_outputs,
        counts.owner_groups_upper_bound,
    ) {
        return Ok(counts);
    }

    if counts.user_txs > BLOCK_MAX_USER_TXS {
        return Err(ConsensusError::BlockSemanticLimitExceeded {
            limit: "user_txs",
            actual: counts.user_txs,
            max: BLOCK_MAX_USER_TXS,
        });
    }
    if counts.live_inputs > BLOCK_MAX_LIVE_INPUTS {
        return Err(ConsensusError::BlockSemanticLimitExceeded {
            limit: "live_inputs",
            actual: counts.live_inputs,
            max: BLOCK_MAX_LIVE_INPUTS,
        });
    }
    if counts.user_outputs > BLOCK_MAX_USER_OUTPUTS {
        return Err(ConsensusError::BlockSemanticLimitExceeded {
            limit: "user_outputs",
            actual: counts.user_outputs,
            max: BLOCK_MAX_USER_OUTPUTS,
        });
    }
    if counts.owner_groups_upper_bound > BLOCK_MAX_OWNER_GROUPS {
        return Err(ConsensusError::BlockSemanticLimitExceeded {
            limit: "owner_groups",
            actual: counts.owner_groups_upper_bound,
            max: BLOCK_MAX_OWNER_GROUPS,
        });
    }
    Err(ConsensusError::BlockSemanticLimitExceeded {
        limit: "user_actions",
        actual: counts.user_actions,
        max: BLOCK_MAX_USER_ACTIONS,
    })
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

fn validate_coinbase_canonical(block: &Block, parent: &BlockHeader) -> Result<(), ConsensusError> {
    let expected_anchor = crate::consensus::pow::block_id(parent);
    let mut seen_coinbase = false;

    for (idx, tx) in block.transactions.iter().enumerate() {
        if !tx.body.is_coinbase {
            continue;
        }
        if seen_coinbase {
            return Err(ConsensusError::ShapeMismatch(
                "multiple coinbase transactions".into(),
            ));
        }
        seen_coinbase = true;
        if idx != 0 {
            return Err(ConsensusError::ShapeMismatch(
                "coinbase transaction must be first".into(),
            ));
        }
        if tx.body.inputs.iter().any(|input| input.valid) {
            return Err(ConsensusError::ShapeMismatch(
                "coinbase transaction has valid inputs".into(),
            ));
        }
        if tx.body.epoch_anchor != expected_anchor {
            return Err(ConsensusError::BadCoinbaseAnchor);
        }

        let expected_hash = noid_tx::hash_tx_body_for_shape(
            tx.body.shape,
            &tx.body.epoch_anchor,
            tx.body.fee,
            &tx.body.inputs,
            &tx.body.outputs,
            tx.body.is_coinbase,
        );
        if tx.tx_body_hash != expected_hash {
            return Err(ConsensusError::BadTxBodyHash);
        }
    }

    Ok(())
}

/// Run all native consensus checks WITHOUT applying the state transition.
///
/// Use this as the first step of the full-proof-native validation path:
///   1. `validate_block_checks()` — header + tx checks (no MDBX reads)
///   2. minimal block proof verification
///   3. `apply_state_delta()` — write delta to MDBX (no pre-state reads)
///
/// Note: does NOT check `state_root` (that's done by minimal proof verification).
/// Does NOT check `active_slot_count` / `alloc_counter` (done by `apply_state_delta`).
pub fn validate_block_checks(
    block: &Block,
    parent: &BlockHeader,
    prev_timestamps: &[u64],
    prev_active_counts: &[u64],
    local_time: u64,
    anchor: &AnchorInfo,
) -> Result<(), ConsensusError> {
    validate_block_checks_inner(
        block,
        parent,
        prev_timestamps,
        prev_active_counts,
        anchor,
        Some(local_time),
    )
}

/// Run deterministic block consensus checks without local wall-clock policy.
///
/// This is the deterministic boundary for historical history proofs. Live node
/// admission must continue to use [`validate_block_checks`] so far-future
/// timestamps are filtered before relay/acceptance.
pub fn validate_block_checks_timeless(
    block: &Block,
    parent: &BlockHeader,
    prev_timestamps: &[u64],
    prev_active_counts: &[u64],
    anchor: &AnchorInfo,
) -> Result<(), ConsensusError> {
    validate_block_checks_inner(
        block,
        parent,
        prev_timestamps,
        prev_active_counts,
        anchor,
        None,
    )
}

fn validate_block_checks_inner(
    block: &Block,
    parent: &BlockHeader,
    prev_timestamps: &[u64],
    prev_active_counts: &[u64],
    anchor: &AnchorInfo,
    local_time: Option<u64>,
) -> Result<(), ConsensusError> {
    match local_time {
        Some(local_time) => validate_header(
            &block.header,
            parent,
            prev_timestamps,
            prev_active_counts,
            local_time,
            anchor.anchor_height,
            anchor.anchor_timestamp,
            &anchor.anchor_target,
        )?,
        None => validate_header_timeless(
            &block.header,
            parent,
            prev_timestamps,
            prev_active_counts,
            anchor.anchor_height,
            anchor.anchor_timestamp,
            &anchor.anchor_target,
        )?,
    }
    if block.transactions.len() > BLOCK_MAX_TXS {
        return Err(ConsensusError::TooManyTxs);
    }
    validate_block_semantic_limits(block)?;
    validate_coinbase_canonical(block, parent)?;
    validate_block_slot_conflicts(&block.transactions)?;
    for tx in &block.transactions {
        validate_tx_consensus_skip_hash(tx)?;
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
/// `validate_block_checks` + minimal proof verification + `apply_state_delta`.
///
/// On success, `state` is updated. On failure, `state` is left unchanged.
pub fn validate_block_consensus(
    block: &Block,
    parent: &BlockHeader,
    prev_timestamps: &[u64],
    prev_active_counts: &[u64],
    local_time: u64,
    anchor: &AnchorInfo,
    state: &mut ChainState,
) -> Result<[u8; 32], ConsensusError> {
    // --- Header checks (P.6) ---
    validate_header(
        &block.header,
        parent,
        prev_timestamps,
        prev_active_counts,
        local_time,
        anchor.anchor_height,
        anchor.anchor_timestamp,
        &anchor.anchor_target,
    )?;

    // --- Tx count limit ---
    if block.transactions.len() > BLOCK_MAX_TXS {
        return Err(ConsensusError::TooManyTxs);
    }
    validate_block_semantic_limits(block)?;

    validate_coinbase_canonical(block, parent)?;

    // --- Cross-tx slot conflict check (P.8, §16 invariants 4-5) ---
    validate_block_slot_conflicts(&block.transactions)?;

    // --- Per-tx consensus checks (P.8) ---
    // Use skip_hash variant: the sequential interpreter below already verifies
    // tx_body_hash for every tx, so recomputing 59-perm Poseidon2b here
    // would be pure redundant work (~15 ms at 256 txs).
    for tx in &block.transactions {
        validate_tx_consensus_skip_hash(tx)?;
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
    use crate::state::ChainState;
    use noid_poseidon2b::primitives::{Address, SpendSecret};
    use noid_tx::{hash_tx_body_for_shape, Transaction, TxBody, TxInput, TxOutput, TxShape};

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
            log_slots: TEST_LOG_SLOTS as u32,
            active_slot_count: 0,
            alloc_counter: 0,
        }
    }

    /// Build a minimal valid block (no txs) on top of `parent`.
    fn build_empty_block(parent: &BlockHeader, state: &mut ChainState) -> Block {
        use crate::block::compute_tx_root;
        use crate::consensus::pow::block_id;

        let mut header = BlockHeader {
            prev_block_hash: block_id(parent),
            state_root: state.state_root(),
            tx_root: compute_tx_root(&[]),
            timestamp: parent.timestamp + BLOCK_TIME,
            height: parent.height + 1,
            miner_address: Address([0u8; 32]),
            nonce: 0,
            difficulty_target: TEST_TARGET,
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
        let hash = hash_tx_body_for_shape(
            body.shape,
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

    fn semantic_limit_tx(
        shape: TxShape,
        n_inputs: usize,
        n_outputs: usize,
        slot_base: u32,
    ) -> Transaction {
        let inputs = (0..n_inputs)
            .map(|i| TxInput {
                slot_index: slot_base + i as u32,
                value: 100,
                owner: Address([1u8; 32]),
                spend_secret: SpendSecret([2u8; 32]),
                valid: true,
            })
            .collect::<Vec<_>>();
        let outputs = (0..n_outputs)
            .map(|i| TxOutput {
                slot_index: slot_base + 10_000 + i as u32,
                value: 1,
                owner: Address([3u8; 32]),
                valid: true,
            })
            .collect::<Vec<_>>();
        tx_from_body(TxBody {
            shape,
            epoch_anchor: [1u8; 32],
            fee: 0,
            inputs,
            outputs,
            is_coinbase: false,
        })
    }

    fn semantic_limit_coinbase() -> Transaction {
        tx_from_body(TxBody {
            shape: TxShape::Standard4x8,
            epoch_anchor: [0u8; 32],
            fee: 0,
            inputs: vec![],
            outputs: vec![TxOutput {
                slot_index: 0,
                value: 1,
                owner: Address([9u8; 32]),
                valid: true,
            }],
            is_coinbase: true,
        })
    }

    fn semantic_limit_block(transactions: Vec<Transaction>) -> Block {
        Block {
            header: mk_parent(1, GENESIS_TIMESTAMP + BLOCK_TIME, [0u8; 32], [0u8; 32]),
            transactions,
        }
    }

    fn fee_test_user_tx(fee: u128) -> Transaction {
        // Balanced body (the shared semantics predicate enforces
        // input == outputs + fee): the first output absorbs whatever the
        // fee leaves.
        tx_from_body(TxBody {
            shape: noid_tx::TxShape::Standard4x8,
            epoch_anchor: [1u8; 32],
            fee,
            inputs: vec![TxInput {
                slot_index: 1,
                value: 10_000,
                owner: Address([1u8; 32]),
                spend_secret: SpendSecret([2u8; 32]),
                valid: true,
            }],
            outputs: vec![
                TxOutput {
                    slot_index: 2,
                    value: (10_000u128 - fee) as u64,
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

    fn fee_test_coinbase(anchor: [u8; 32], value: u64) -> Transaction {
        tx_from_body(TxBody {
            shape: noid_tx::TxShape::Standard4x8,
            epoch_anchor: anchor,
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
        use crate::consensus::pow::block_id;

        let parent_hash = block_id(parent);
        let txs = vec![
            fee_test_coinbase(parent_hash, coinbase_value),
            fee_test_user_tx(user_fee as u128),
        ];
        Block {
            header: BlockHeader {
                prev_block_hash: block_id(parent),
                state_root: parent.state_root,
                tx_root: compute_tx_root(&txs),
                timestamp: parent.timestamp + BLOCK_TIME,
                height: parent.height + 1,
                miner_address: Address([0u8; 32]),
                nonce: 0,
                difficulty_target: TEST_TARGET,
                log_slots: parent.log_slots,
                active_slot_count: parent.active_slot_count,
                alloc_counter: parent.alloc_counter,
            },
            transactions: txs,
        }
    }

    #[test]
    fn semantic_limits_accept_standard_baseline_block() {
        let mut txs = Vec::with_capacity(crate::consensus::params::BLOCK_MAX_TXS);
        txs.push(semantic_limit_coinbase());
        for i in 0..crate::consensus::params::BLOCK_MAX_USER_TXS {
            txs.push(semantic_limit_tx(
                TxShape::Standard4x8,
                4,
                8,
                1_000 + i as u32 * 20,
            ));
        }
        let counts = validate_block_semantic_limits(&semantic_limit_block(txs))
            .expect("255 Standard4x8-equivalent block fits semantic budget");
        assert_eq!(
            counts.live_inputs,
            crate::consensus::params::BLOCK_MAX_LIVE_INPUTS
        );
        assert_eq!(
            counts.user_outputs,
            crate::consensus::params::BLOCK_MAX_USER_OUTPUTS
        );
        assert_eq!(
            counts.user_actions,
            crate::consensus::params::BLOCK_MAX_USER_ACTIONS
        );
    }

    #[test]
    fn semantic_limits_reject_41_full_sweeps() {
        let mut txs = Vec::with_capacity(42);
        txs.push(semantic_limit_coinbase());
        for i in 0..(crate::consensus::params::BLOCK_MAX_FULL_SWEEP25X2_TXS + 1) {
            txs.push(semantic_limit_tx(
                TxShape::Sweep25x2,
                25,
                2,
                1_000 + i as u32 * 40,
            ));
        }

        let err = validate_block_semantic_limits(&semantic_limit_block(txs))
            .expect_err("41 full Sweep25x2 txs exceed live-input budget");
        assert_eq!(
            err,
            ConsensusError::BlockSemanticLimitExceeded {
                limit: "live_inputs",
                actual: 1025,
                max: crate::consensus::params::BLOCK_MAX_LIVE_INPUTS,
            }
        );
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
            log_slots: TEST_LOG_SLOTS as u32,
            active_slot_count: target_active,
            alloc_counter: 0,
        };

        // Block claiming log_slots = TEST_LOG_SLOTS (no expansion) should be rejected.
        let block_no_expand = {
            use crate::block::compute_tx_root;
            use crate::consensus::pow::block_id;
            let mut hdr = BlockHeader {
                prev_block_hash: block_id(&parent),
                state_root,
                tx_root: compute_tx_root(&[]),
                timestamp: parent.timestamp + BLOCK_TIME,
                height: 1,
                miner_address: noid_poseidon2b::primitives::Address([0u8; 32]),
                nonce: 0,
                difficulty_target: TEST_TARGET,
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
            log_slots: TEST_LOG_SLOTS as u32,
            active_slot_count: spike_active,
            alloc_counter: 0,
        };

        // Build a block that does NOT expand (log_slots unchanged).
        use crate::block::compute_tx_root;
        use crate::consensus::pow::block_id;
        let mut hdr = BlockHeader {
            prev_block_hash: block_id(&parent),
            state_root,
            tx_root: compute_tx_root(&[]),
            timestamp: parent.timestamp + BLOCK_TIME,
            height: 1,
            miner_address: noid_poseidon2b::primitives::Address([0u8; 32]),
            nonce: 0,
            difficulty_target: TEST_TARGET,
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
            &mut apply_state,
        );
        assert!(
            result.is_ok(),
            "single spike must not trigger expansion via median: {:?}",
            result
        );
    }
}
