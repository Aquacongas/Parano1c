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
//!  ✅  Mandatory canonical coinbase (exactly one, first, Standard4x8)   [P.7 partial]
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

use std::collections::BTreeSet;

use crate::block::apply_block;
use crate::block::Block;
use crate::block_header::BlockHeader;
use crate::consensus::{
    checks::{validate_block_slot_conflicts, validate_tx_consensus_skip_hash},
    emission::max_coinbase_value_from_fee_sum,
    fees::{claimable_fee_for_tx_body, required_fee_for_tx_body},
    header::{validate_header, validate_header_timeless},
    params::{
        block_shape_limits_ok, BLOCK_MAX_ACTIONS, BLOCK_MAX_DISTINCT_SEGMENTS,
        BLOCK_MAX_LIVE_INPUTS, BLOCK_MAX_TXS, BLOCK_MAX_USER_ACTIONS, BLOCK_MAX_USER_OUTPUTS,
        BLOCK_MAX_USER_TXS, LOG_SEGMENT_SIZE,
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
pub struct BlockResourcePreflight {
    pub standard_tx_count: usize,
    pub sweep_tx_count: usize,
    pub live_input_count: usize,
    /// All live outputs, including coinbase.
    pub output_count: usize,
    /// Live inputs plus all live outputs, including coinbase.
    pub action_count: usize,
    pub touched_slot_count: usize,
    pub distinct_segment_count: usize,
}

fn resource_limit(
    limit: &'static str,
    actual: usize,
    max: usize,
) -> Result<BlockResourcePreflight, ConsensusError> {
    Err(ConsensusError::BlockResourceLimitExceeded { limit, actual, max })
}

/// Count and bound the complete raw block resource surface before any
/// segment-sized work, proof decode, or state clone.
///
/// Shape budgets are charged by physical user transaction shape, never by the
/// validity bitmap. Live selectors are used only for the accepted public
/// resource counters and touched-slot/segment union. Vector lengths are
/// checked before those sets are allocated, keeping this preflight bounded for
/// programmatically constructed blocks as well as decoder-produced blocks.
pub fn validate_block_resource_preflight(
    block: &Block,
) -> Result<BlockResourcePreflight, ConsensusError> {
    if block.transactions.len() > BLOCK_MAX_TXS {
        return Err(ConsensusError::TooManyTxs);
    }
    if !(1..=32).contains(&block.header.log_slots) {
        return Err(ConsensusError::ShapeMismatch(
            "block log_slots is outside the u32 slot domain".into(),
        ));
    }
    let slot_domain = 1u64 << block.header.log_slots;

    let mut standard_tx_count = 0usize;
    let mut sweep_tx_count = 0usize;
    for tx in &block.transactions {
        if tx.body.inputs.len() > tx.body.shape.max_inputs()
            || tx.body.outputs.len() > tx.body.shape.max_outputs()
        {
            return Err(ConsensusError::ShapeMismatch(format!(
                "{:?} body exceeds its physical capacity",
                tx.body.shape
            )));
        }
        if !tx.body.is_coinbase {
            match tx.body.shape {
                noid_tx::TxShape::Standard4x8 => standard_tx_count += 1,
                noid_tx::TxShape::Sweep25x2 => sweep_tx_count += 1,
            }
        }
    }

    let user_tx_count = standard_tx_count + sweep_tx_count;
    let charged_inputs = standard_tx_count * noid_tx::TxShape::Standard4x8.max_inputs()
        + sweep_tx_count * noid_tx::TxShape::Sweep25x2.max_inputs();
    let charged_outputs = standard_tx_count * noid_tx::TxShape::Standard4x8.max_outputs()
        + sweep_tx_count * noid_tx::TxShape::Sweep25x2.max_outputs();
    let charged_actions = charged_inputs + charged_outputs;
    if !block_shape_limits_ok(standard_tx_count, sweep_tx_count) {
        if user_tx_count > BLOCK_MAX_USER_TXS {
            return resource_limit("user_txs", user_tx_count, BLOCK_MAX_USER_TXS);
        }
        if charged_inputs > BLOCK_MAX_LIVE_INPUTS {
            return resource_limit("shape_inputs", charged_inputs, BLOCK_MAX_LIVE_INPUTS);
        }
        if charged_outputs > BLOCK_MAX_USER_OUTPUTS {
            return resource_limit("shape_outputs", charged_outputs, BLOCK_MAX_USER_OUTPUTS);
        }
        return resource_limit("shape_actions", charged_actions, BLOCK_MAX_USER_ACTIONS);
    }

    let mut live_input_count = 0usize;
    let mut output_count = 0usize;
    let mut touched_slots = BTreeSet::new();
    let mut segments = BTreeSet::new();
    for tx in &block.transactions {
        for input in tx.body.inputs.iter().filter(|input| input.valid) {
            if u64::from(input.slot_index) >= slot_domain {
                return Err(ConsensusError::ShapeMismatch(
                    "live input slot is outside block log_slots".into(),
                ));
            }
            live_input_count += 1;
            touched_slots.insert(input.slot_index);
            segments.insert(input.slot_index >> LOG_SEGMENT_SIZE);
        }
        for output in tx.body.outputs.iter().filter(|output| output.valid) {
            if u64::from(output.slot_index) >= slot_domain {
                return Err(ConsensusError::ShapeMismatch(
                    "live output slot is outside block log_slots".into(),
                ));
            }
            output_count += 1;
            touched_slots.insert(output.slot_index);
            segments.insert(output.slot_index >> LOG_SEGMENT_SIZE);
        }
        if segments.len() > BLOCK_MAX_DISTINCT_SEGMENTS {
            return resource_limit(
                "distinct_segments",
                segments.len(),
                BLOCK_MAX_DISTINCT_SEGMENTS,
            );
        }
    }

    if live_input_count > BLOCK_MAX_LIVE_INPUTS {
        return resource_limit("live_inputs", live_input_count, BLOCK_MAX_LIVE_INPUTS);
    }
    if output_count > BLOCK_MAX_USER_OUTPUTS + 1 {
        return resource_limit("outputs", output_count, BLOCK_MAX_USER_OUTPUTS + 1);
    }
    let action_count = live_input_count + output_count;
    if action_count > BLOCK_MAX_ACTIONS {
        return resource_limit("actions", action_count, BLOCK_MAX_ACTIONS);
    }

    Ok(BlockResourcePreflight {
        standard_tx_count,
        sweep_tx_count,
        live_input_count,
        output_count,
        action_count,
        touched_slot_count: touched_slots.len(),
        distinct_segment_count: segments.len(),
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

/// Validate the complete mandatory coinbase contract for a non-genesis block.
///
/// This is the single cheap, state-free predicate shared by every accepted
/// block entry point. Genesis is deliberately outside this contract and is
/// required to have an empty transaction list by `apply_genesis_block`.
pub fn validate_mandatory_coinbase(
    block: &Block,
    parent: &BlockHeader,
) -> Result<(), ConsensusError> {
    let expected_anchor = crate::consensus::pow::block_id(parent);
    let mut coinbase_positions = block
        .transactions
        .iter()
        .enumerate()
        .filter_map(|(index, tx)| tx.body.is_coinbase.then_some(index));
    let coinbase_index = coinbase_positions
        .next()
        .ok_or(ConsensusError::MissingCoinbase)?;
    if coinbase_positions.next().is_some() {
        return Err(ConsensusError::MultipleCoinbase);
    }
    if coinbase_index != 0 {
        return Err(ConsensusError::CoinbaseNotFirst);
    }

    let coinbase = &block.transactions[0];
    if coinbase.body.shape != noid_tx::TxShape::Standard4x8 {
        return Err(ConsensusError::BadCoinbaseShape);
    }
    // This one shared predicate owns fee/input/output counts and canonical
    // dead-entry encoding. Keeping it here (rather than relying on the later
    // per-transaction loop) makes the complete coinbase contract one atomic
    // cheap preflight.
    noid_tx::validate_body_semantics_no_hash(&coinbase.body)
        .map_err(|error| ConsensusError::ShapeMismatch(format!("coinbase semantics: {error}")))?;

    if coinbase.body.epoch_anchor != expected_anchor {
        return Err(ConsensusError::BadCoinbaseAnchor);
    }
    let output = coinbase
        .body
        .outputs
        .iter()
        .find(|output| output.valid)
        .ok_or_else(|| ConsensusError::ShapeMismatch("coinbase has no live output".into()))?;
    if output.owner != block.header.miner_address {
        return Err(ConsensusError::BadCoinbaseOwner);
    }

    let expected_hash = noid_tx::hash_tx_body_for_shape(
        coinbase.body.shape,
        &coinbase.body.epoch_anchor,
        coinbase.body.fee,
        &coinbase.body.inputs,
        &coinbase.body.outputs,
        coinbase.body.is_coinbase,
    );
    if coinbase.tx_body_hash != expected_hash {
        return Err(ConsensusError::BadTxBodyHash);
    }

    Ok(())
}

/// Run all native consensus checks WITHOUT applying the state transition.
///
/// Use this as the first step of the full-proof-native validation path:
///   1. `validate_block_checks()` — header + tx checks (no MDBX reads)
///   2. exact block transition verification
///   3. commit the verifier-sealed slot updates and counters atomically
///
/// Note: does NOT check `state_root` (that's done by minimal proof verification).
/// Does NOT check `active_slot_count` / `alloc_counter` (done by the exact
/// transition verifier).
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
    validate_block_resource_preflight(block)?;
    validate_mandatory_coinbase(block, parent)?;
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
/// `validate_block_checks` + exact transition verification + sealed commit.
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

    // --- Bounded canonical resource preflight ---
    validate_block_resource_preflight(block)?;

    validate_mandatory_coinbase(block, parent)?;

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

    /// Build a structurally empty child for negative/header-ordering tests.
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
                creation_id: 0,
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
        let mut header = mk_parent(1, GENESIS_TIMESTAMP + BLOCK_TIME, [0u8; 32], [0u8; 32]);
        header.log_slots = 32;
        Block {
            header,
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
                creation_id: 0,
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
                miner_address: Address([9u8; 32]),
                nonce: 0,
                difficulty_target: TEST_TARGET,
                log_slots: parent.log_slots,
                active_slot_count: parent.active_slot_count,
                alloc_counter: parent.alloc_counter,
            },
            transactions: txs,
        }
    }

    fn canonical_coinbase_block(parent: &BlockHeader) -> Block {
        use crate::consensus::pow::block_id;

        let coinbase = fee_test_coinbase(block_id(parent), 1);
        let transactions = vec![coinbase];
        let mut header = mk_parent(
            parent.height + 1,
            parent.timestamp + BLOCK_TIME,
            block_id(parent),
            parent.state_root,
        );
        header.miner_address = Address([9u8; 32]);
        header.tx_root = crate::block::compute_tx_root(&transactions);
        Block {
            header,
            transactions,
        }
    }

    fn rehash(tx: &mut Transaction) {
        tx.tx_body_hash = hash_tx_body_for_shape(
            tx.body.shape,
            &tx.body.epoch_anchor,
            tx.body.fee,
            &tx.body.inputs,
            &tx.body.outputs,
            tx.body.is_coinbase,
        );
    }

    #[test]
    fn canonical_coinbase_contract_accepts_exact_standard_form() {
        let parent = mk_parent(0, GENESIS_TIMESTAMP, [0u8; 32], [0u8; 32]);
        assert_eq!(
            validate_mandatory_coinbase(&canonical_coinbase_block(&parent), &parent),
            Ok(())
        );
    }

    #[test]
    fn canonical_coinbase_contract_rejects_missing_late_and_multiple() {
        let parent = mk_parent(0, GENESIS_TIMESTAMP, [0u8; 32], [0u8; 32]);
        let mut block = canonical_coinbase_block(&parent);

        block.transactions.clear();
        assert_eq!(
            validate_mandatory_coinbase(&block, &parent),
            Err(ConsensusError::MissingCoinbase)
        );

        let coinbase = canonical_coinbase_block(&parent).transactions.remove(0);
        block.transactions = vec![fee_test_user_tx(0), coinbase.clone()];
        assert_eq!(
            validate_mandatory_coinbase(&block, &parent),
            Err(ConsensusError::CoinbaseNotFirst)
        );

        block.transactions = vec![coinbase.clone(), coinbase];
        assert_eq!(
            validate_mandatory_coinbase(&block, &parent),
            Err(ConsensusError::MultipleCoinbase)
        );
    }

    #[test]
    fn canonical_coinbase_contract_binds_shape_semantics_anchor_owner_and_hash() {
        let parent = mk_parent(0, GENESIS_TIMESTAMP, [0u8; 32], [0u8; 32]);

        let mut bad_shape = canonical_coinbase_block(&parent);
        bad_shape.transactions[0].body.shape = TxShape::Sweep25x2;
        rehash(&mut bad_shape.transactions[0]);
        assert_eq!(
            validate_mandatory_coinbase(&bad_shape, &parent),
            Err(ConsensusError::BadCoinbaseShape)
        );

        let mut bad_fee = canonical_coinbase_block(&parent);
        bad_fee.transactions[0].body.fee = 1;
        rehash(&mut bad_fee.transactions[0]);
        assert!(matches!(
            validate_mandatory_coinbase(&bad_fee, &parent),
            Err(ConsensusError::ShapeMismatch(_))
        ));

        let mut bad_inputs = canonical_coinbase_block(&parent);
        bad_inputs.transactions[0].body.inputs.push(TxInput {
            slot_index: 1,
            value: 1,
            creation_id: 1,
            owner: Address([9u8; 32]),
            spend_secret: SpendSecret([1u8; 32]),
            valid: true,
        });
        rehash(&mut bad_inputs.transactions[0]);
        assert!(matches!(
            validate_mandatory_coinbase(&bad_inputs, &parent),
            Err(ConsensusError::ShapeMismatch(_))
        ));

        let mut bad_outputs = canonical_coinbase_block(&parent);
        bad_outputs.transactions[0].body.outputs.clear();
        rehash(&mut bad_outputs.transactions[0]);
        assert!(matches!(
            validate_mandatory_coinbase(&bad_outputs, &parent),
            Err(ConsensusError::ShapeMismatch(_))
        ));

        let mut bad_dead_entry = canonical_coinbase_block(&parent);
        bad_dead_entry.transactions[0].body.outputs.push(TxOutput {
            slot_index: 7,
            value: 0,
            owner: Address([0u8; 32]),
            valid: false,
        });
        rehash(&mut bad_dead_entry.transactions[0]);
        assert!(matches!(
            validate_mandatory_coinbase(&bad_dead_entry, &parent),
            Err(ConsensusError::ShapeMismatch(_))
        ));

        let mut bad_anchor = canonical_coinbase_block(&parent);
        bad_anchor.transactions[0].body.epoch_anchor = [0xAA; 32];
        rehash(&mut bad_anchor.transactions[0]);
        assert_eq!(
            validate_mandatory_coinbase(&bad_anchor, &parent),
            Err(ConsensusError::BadCoinbaseAnchor)
        );

        let mut bad_owner = canonical_coinbase_block(&parent);
        bad_owner.header.miner_address = Address([0xBB; 32]);
        assert_eq!(
            validate_mandatory_coinbase(&bad_owner, &parent),
            Err(ConsensusError::BadCoinbaseOwner)
        );

        let mut bad_hash = canonical_coinbase_block(&parent);
        bad_hash.transactions[0].tx_body_hash.0[0] ^= 1;
        assert_eq!(
            validate_mandatory_coinbase(&bad_hash, &parent),
            Err(ConsensusError::BadTxBodyHash)
        );
    }

    #[test]
    fn resource_preflight_accepts_standard_baseline_block() {
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
        let counts = validate_block_resource_preflight(&semantic_limit_block(txs))
            .expect("255 Standard4x8-equivalent block fits semantic budget");
        assert_eq!(
            counts.live_input_count,
            crate::consensus::params::BLOCK_MAX_LIVE_INPUTS
        );
        assert_eq!(
            counts.output_count,
            crate::consensus::params::BLOCK_MAX_USER_OUTPUTS + 1
        );
        assert_eq!(
            counts.action_count,
            crate::consensus::params::BLOCK_MAX_ACTIONS
        );
        assert_eq!(counts.standard_tx_count, 255);
        assert_eq!(counts.sweep_tx_count, 0);
    }

    #[test]
    fn resource_preflight_rejects_41_sparse_sweeps() {
        let mut txs = Vec::with_capacity(42);
        txs.push(semantic_limit_coinbase());
        for i in 0..(crate::consensus::params::BLOCK_MAX_FULL_SWEEP25X2_TXS + 1) {
            txs.push(semantic_limit_tx(
                TxShape::Sweep25x2,
                1,
                1,
                1_000 + i as u32 * 40,
            ));
        }

        let err = validate_block_resource_preflight(&semantic_limit_block(txs))
            .expect_err("41 sparse Sweep25x2 txs exceed physical shape budget");
        assert_eq!(
            err,
            ConsensusError::BlockResourceLimitExceeded {
                limit: "shape_inputs",
                actual: 1025,
                max: crate::consensus::params::BLOCK_MAX_LIVE_INPUTS,
            }
        );
    }

    fn segment_spread_block(segment_count: usize) -> Block {
        let mut txs = vec![semantic_limit_coinbase()];
        for (tx_index, segment_chunk) in
            (0..segment_count).collect::<Vec<_>>().chunks(4).enumerate()
        {
            let inputs = segment_chunk
                .iter()
                .map(|&segment| TxInput {
                    slot_index: (segment as u32) << crate::consensus::params::LOG_SEGMENT_SIZE,
                    value: 100,
                    creation_id: 0,
                    owner: Address([1u8; 32]),
                    spend_secret: SpendSecret([2u8; 32]),
                    valid: true,
                })
                .collect();
            txs.push(tx_from_body(TxBody {
                shape: TxShape::Standard4x8,
                epoch_anchor: [tx_index as u8 + 1; 32],
                fee: 0,
                inputs,
                outputs: vec![],
                is_coinbase: false,
            }));
        }
        let mut block = semantic_limit_block(txs);
        block.header.log_slots = 32;
        block
    }

    #[test]
    fn resource_preflight_accepts_256_distinct_segments() {
        let counts = validate_block_resource_preflight(&segment_spread_block(256))
            .expect("the availability envelope includes exactly 256 segments");
        assert_eq!(counts.distinct_segment_count, 256);
        assert_eq!(counts.touched_slot_count, 256);
    }

    #[test]
    fn resource_preflight_rejects_257_distinct_segments() {
        let err = validate_block_resource_preflight(&segment_spread_block(257))
            .expect_err("257 segments must fail before preload");
        assert_eq!(
            err,
            ConsensusError::BlockResourceLimitExceeded {
                limit: "distinct_segments",
                actual: 257,
                max: crate::consensus::params::BLOCK_MAX_DISTINCT_SEGMENTS,
            }
        );
    }

    #[test]
    fn resource_preflight_rejects_out_of_domain_slot_before_preload() {
        let mut block = semantic_limit_block(vec![semantic_limit_tx(
            TxShape::Standard4x8,
            1,
            0,
            1u32 << TEST_LOG_SLOTS,
        )]);
        block.header.log_slots = TEST_LOG_SLOTS as u32;
        assert_eq!(
            validate_block_resource_preflight(&block),
            Err(ConsensusError::ShapeMismatch(
                "live input slot is outside block log_slots".into()
            ))
        );
    }

    #[test]
    fn non_genesis_empty_block_is_rejected() {
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
        assert_eq!(result, Err(ConsensusError::MissingCoinbase));
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

        // Window: 17 values at 25%, 1 value at 75%. Median = 25% → no trigger.
        let mut active_window = vec![low_active; 17];
        active_window.push(spike_active);

        // Build the canonical coinbase-only child. The template and validator
        // consume the same active-count window, so this remains an expansion
        // trigger test rather than an obsolete empty-child fixture.
        let template = crate::consensus::template::build_block_template(
            &parent,
            &state,
            &active_window,
            vec![],
            Address([0u8; 32]),
            parent.timestamp + BLOCK_TIME,
            TEST_TARGET,
        )
        .expect("coinbase-only non-expansion template");
        let block = crate::block::Block {
            header: template.clone().into_header(0),
            transactions: template.all_txs(),
        };
        assert_eq!(block.header.log_slots, TEST_LOG_SLOTS as u32);

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
