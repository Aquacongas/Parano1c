// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Block template construction for the mining pipeline .
//!
//! A `BlockTemplate` is a fully computed block ready for PoW search:
//! - Transaction set selected and conflict-resolved
//! - State applied to scratch copy → `state_root` known
//! - All semantic header fields computed except `nonce`
//!
//! The miner receives a semantic header with `nonce = 0` and searches for a
//! valid nonce under the fixed Poseidon2b PoW field schedule.
//! When found, the full node finalises the semantic header and attaches detached
//! proof/sidecar witness bytes for validation.
//!
//! # Why state_root is in the PoW input
//!
//! Including `state_root` in the PoW hash prevents external miners from changing
//! the coinbase address: a different coinbase → different post-state → different
//! `state_root` → different Poseidon2b PoW input → must redo PoW from scratch.
//! This is Paranoid's block-withholding protection.

use std::collections::HashSet;

use noid_poseidon2b::primitives::{Address, Digest};
use noid_tx::Transaction;

use crate::block_header::BlockHeader;
use crate::consensus::pow::block_id;
use crate::state::{apply_tx_checked_deferred_root, ChainState};

// ---------------------------------------------------------------------------
// BlockTemplate
// ---------------------------------------------------------------------------

/// A fully assembled block template ready for PoW search.
///
/// All semantic header fields except `nonce` are fixed.
/// The miner iterates nonces over the fixed Poseidon2b PoW field schedule.
#[derive(Debug, Clone)]
pub struct BlockTemplate {
    /// Coinbase transaction (always first in the block).
    pub coinbase: Transaction,
    /// Non-coinbase transactions in canonical order (coinbase excluded here).
    pub txs: Vec<Transaction>,
    /// Post-apply state root (computed from applying all txs to prev state).
    pub state_root: Digest,
    /// Merkle root of all transactions: compute_tx_root(&[coinbase] + txs).
    pub tx_root: Digest,
    /// Post-apply active slot count.
    pub active_slot_count: u64,
    /// Post-apply alloc counter.
    pub alloc_counter: u64,
    /// Current log_slots depth.
    pub log_slots: u32,
    /// Block height (parent.height + 1).
    pub height: u64,
    /// Block timestamp (wall-clock seconds at template creation).
    pub timestamp: u64,
    /// Miner's payout address (embedded in coinbase).
    pub miner_address: Address,
    /// ASERT difficulty target for this block.
    pub difficulty_target: Digest,
    /// Hash of parent block header.
    pub prev_block_hash: Digest,
}

impl BlockTemplate {
    /// Build a semantic `BlockHeader` from this template with the given nonce.
    pub fn into_header(self, nonce: u128) -> BlockHeader {
        BlockHeader {
            prev_block_hash: self.prev_block_hash,
            state_root: self.state_root,
            tx_root: self.tx_root,
            timestamp: self.timestamp,
            height: self.height,
            miner_address: self.miner_address,
            nonce,
            difficulty_target: self.difficulty_target,
            log_slots: self.log_slots,
            active_slot_count: self.active_slot_count,
            alloc_counter: self.alloc_counter,
        }
    }

    /// Build a `BlockHeader` for PoW purposes with the supplied nonce.
    /// Use `pow_header_fields(hdr)` from pow.rs to get the fixed PoW input.
    pub fn to_pow_header(&self, nonce: u128) -> BlockHeader {
        BlockHeader {
            prev_block_hash: self.prev_block_hash,
            state_root: self.state_root,
            tx_root: self.tx_root,
            timestamp: self.timestamp,
            height: self.height,
            miner_address: self.miner_address,
            nonce,
            difficulty_target: self.difficulty_target,
            log_slots: self.log_slots,
            active_slot_count: self.active_slot_count,
            alloc_counter: self.alloc_counter,
        }
    }

    /// All transactions in block order: coinbase first, then txs.
    pub fn all_txs(&self) -> Vec<Transaction> {
        let mut all = vec![self.coinbase.clone()];
        all.extend(self.txs.iter().cloned());
        all
    }

    /// Total tx count (coinbase + non-coinbase).
    pub fn n_txs(&self) -> usize {
        1 + self.txs.len()
    }
}

// ---------------------------------------------------------------------------
// Template builder
// ---------------------------------------------------------------------------

/// Error returned by `build_block_template`.
#[derive(Debug, Clone)]
pub enum TemplateBuildError {
    /// No empty slot available for the coinbase output.
    NoCoinbaseSlot,
    /// State application failed for a transaction (conflict, out-of-range, etc.).
    StateApplyError(String),
}

/// Build a `BlockTemplate` from a set of candidate transactions.
///
/// Steps:
/// 1. Conflict-resolve candidate txs (winners by min tx_body_hash per slot).
/// 2. Apply all txs to a scratch copy of `state`.
/// 3. Compute coinbase: slot from `alloc_counter + 1`, value = block_reward + fees.
/// 4. Apply coinbase to scratch state.
/// 5. Compute `state_root`, `tx_root`, `active_slot_count`, `alloc_counter`.
/// 6. Return the fully populated `BlockTemplate`.
///
/// `state` is NOT modified — all changes happen on a scratch copy.
///
/// `candidate_txs` must be pre-validated (not yet conflict-resolved).
/// Coinbase is constructed internally using `miner_address`.
pub fn build_block_template(
    parent: &BlockHeader,
    state: &ChainState,
    prev_active_counts: &[u64],
    candidate_txs: Vec<Transaction>,
    miner_address: Address,
    timestamp: u64,
    difficulty_target: Digest,
) -> Result<BlockTemplate, TemplateBuildError> {
    use crate::consensus::allocator::generate_slot_hints;
    use crate::consensus::emission::block_reward;
    use crate::consensus::expected_child_log_slots;
    use crate::consensus::fees::{claimable_fee_for_tx_body, required_fee_for_tx_body};
    use crate::consensus::{conflict::resolve_slot_conflicts, ordering::order_block_txs};
    use noid_tx::{hash_tx_body, TxBody, TxOutput};

    // 1. Resolve slot conflicts among candidate txs.
    let (mut winners, _losers) = resolve_slot_conflicts(candidate_txs);

    // 2. Determine expansion trigger using median over prev_active_counts window.
    //    Must match validate_block_consensus exactly so the block we produce passes
    //    consensus validation.
    let new_log_slots = expected_child_log_slots(
        parent.log_slots,
        parent.active_slot_count,
        prev_active_counts,
    );
    let should_expand = new_log_slots != parent.log_slots;

    // Wallet proofs are bound to log_slots. If this block expands the state,
    // mempool transactions proved against the parent log_slots cannot be valid
    // under the expanded header. Produce a coinbase-only expansion block; wallets
    // will re-prove after observing the new tip.
    if should_expand {
        winners.clear();
    }

    // 3. Apply non-coinbase txs to scratch state.
    let mut selection_scratch = state.clone();
    if should_expand {
        selection_scratch.expand_one();
    }
    // Selection executes users before their fee-dependent coinbase is known.
    // Reserve the coinbase's canonical first creation ID so user outputs get
    // exactly the same IDs here as in the final coinbase -> users replay.
    selection_scratch.alloc_counter =
        selection_scratch
            .alloc_counter
            .checked_add(1)
            .ok_or_else(|| {
                TemplateBuildError::StateApplyError(
                    "alloc_counter exhausted while reserving coinbase creation ID".into(),
                )
            })?;

    let mut applied_winners: Vec<Transaction> = Vec::new();
    let ordered_winners = order_block_txs(winners);
    for tx in ordered_winners {
        let required =
            required_fee_for_tx_body(&tx.body, parent.active_slot_count, parent.log_slots);
        let actual = tx.body.fee.min(u64::MAX as u128) as u64;
        if actual < required {
            continue;
        }
        match apply_tx_checked_deferred_root(&mut selection_scratch, &tx.body) {
            Ok(_) => {
                applied_winners.push(tx);
            }
            Err(_e) => {}
        }
    }
    let ordered_winners = applied_winners;

    // Rebuild the final scratch state in semantic block order. Selection runs
    // users first because coinbase value depends on the selected fee set, but
    // the actual block and exact action stream are coinbase -> users.
    let mut scratch = state.clone();
    if should_expand {
        scratch.expand_one();
    }

    // 4. Build coinbase transaction.
    // Find an empty slot for coinbase output using the allocator.
    // Use the scratch state's actual capacity so hints are always in range.
    let coinbase_slot = {
        let state_log_slots = scratch.state.log_slots() as u32;
        let reserved: HashSet<u32> = ordered_winners
            .iter()
            .flat_map(|tx| {
                tx.body
                    .inputs
                    .iter()
                    .filter(|input| input.valid)
                    .map(|input| input.slot_index)
                    .chain(
                        tx.body
                            .outputs
                            .iter()
                            .filter(|output| output.valid)
                            .map(|output| output.slot_index),
                    )
            })
            .collect();
        let seed =
            scratch.alloc_counter ^ u64::from_le_bytes(parent.state_root[..8].try_into().unwrap());

        // Best case: reuse a hole in an already-populated segment. This avoids
        // materialising a new 3 MB segment just for coinbase.
        let reuse_hints = scratch
            .state
            .empty_slot_hints_in_populated_segments(seed, 32, &reserved);
        if let Some(slot) = reuse_hints
            .into_iter()
            .find(|&slot| scratch.state.slot(slot) == crate::fri_state::SlotValue::EMPTY)
        {
            slot
        } else {
            // Fall back to the virgin-zone allocator. Grow the candidate window
            // so a block is not rejected merely because the first 256 hints were
            // occupied; NoCoinbaseSlot should mean genuinely no reachable empty slot.
            let mut found = None;
            let mut count = 256usize;
            while found.is_none() && count <= 65_536 {
                found = generate_slot_hints(scratch.alloc_counter, state_log_slots, count)
                    .into_iter()
                    .find(|&slot| {
                        !reserved.contains(&slot)
                            && scratch.state.slot(slot) == crate::fri_state::SlotValue::EMPTY
                    });
                count *= 2;
            }
            found.ok_or(TemplateBuildError::NoCoinbaseSlot)?
        }
    };

    // Sum only claimable fees. The deterministic state-growth component is burned.
    let claimable_fee_sum: u64 = ordered_winners
        .iter()
        .filter(|tx| !tx.body.is_coinbase)
        .map(|tx| claimable_fee_for_tx_body(&tx.body, parent.active_slot_count, parent.log_slots))
        .fold(0u64, |acc, f| acc.saturating_add(f));
    let coinbase_value = block_reward(new_log_slots).saturating_add(claimable_fee_sum);

    let prev_block_hash = block_id(parent);
    let cb_body = TxBody::standard(
        prev_block_hash,
        0,
        vec![],
        vec![TxOutput {
            slot_index: coinbase_slot,
            value: coinbase_value,
            owner: miner_address,
            valid: true,
        }],
        true,
    );
    let cb_hash = hash_tx_body(
        &cb_body.epoch_anchor,
        cb_body.fee,
        &cb_body.inputs,
        &cb_body.outputs,
        cb_body.is_coinbase,
    );
    let coinbase = Transaction {
        body: cb_body,
        tx_body_hash: cb_hash,
    };

    // Apply the complete block to scratch in its real semantic order.
    apply_tx_checked_deferred_root(&mut scratch, &coinbase.body)
        .map_err(|e| TemplateBuildError::StateApplyError(format!("{:?}", e)))?;
    for tx in &ordered_winners {
        apply_tx_checked_deferred_root(&mut scratch, &tx.body)
            .map_err(|e| TemplateBuildError::StateApplyError(format!("{:?}", e)))?;
    }

    // 5. Compute final header fields.
    let state_root = scratch
        .try_state_root()
        .map_err(|e| TemplateBuildError::StateApplyError(format!("{e:?}")))?;
    // Collect only tx_body_hashes to avoid cloning full Transaction objects.
    let tx_hashes_for_root: Vec<[u8; 32]> = std::iter::once(coinbase.tx_body_hash.0)
        .chain(ordered_winners.iter().map(|tx| tx.tx_body_hash.0))
        .collect();
    let tx_root = {
        use noid_poseidon2b::native::compress;
        if tx_hashes_for_root.is_empty() {
            [0u8; 32]
        } else {
            // Tier-quantized capacity padding — the same rule as
            // `compute_tx_root` (the winners are user txs; the coinbase is
            // the one non-user leaf).
            let (standard, sweep) =
                ordered_winners
                    .iter()
                    .fold((0usize, 0usize), |(s, w), tx| match tx.body.shape {
                        noid_tx::TxShape::Standard4x8 => (s + 1, w),
                        noid_tx::TxShape::Sweep25x2 => (s, w + 1),
                    });
            let n = crate::consensus::params::tx_tree_target(standard, sweep, 1);
            let mut layer = Vec::with_capacity(n);
            layer.extend_from_slice(&tx_hashes_for_root);
            layer.resize(n, [0u8; 32]);
            while layer.len() > 1 {
                layer = layer
                    .chunks_exact(2)
                    .map(|p| compress(&p[0], &p[1]))
                    .collect();
            }
            layer[0]
        }
    };

    Ok(BlockTemplate {
        coinbase,
        txs: ordered_winners,
        state_root,
        tx_root,
        active_slot_count: scratch.active_slot_count,
        alloc_counter: scratch.alloc_counter,
        log_slots: new_log_slots,
        height: parent.height + 1,
        timestamp,
        miner_address,
        difficulty_target,
        prev_block_hash,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::{
        genesis::{genesis_header, GENESIS_TIMESTAMP},
        params::{BLOCK_TIME, GENESIS_TARGET},
    };
    use crate::fri_state::SlotValue;
    use crate::state::ChainState;
    use noid_poseidon2b::primitives::{Address, SpendSecret};
    use noid_tx::{hash_tx_body, Transaction, TxBody, TxInput, TxOutput};

    const TEST_LOG_SLOTS: usize = 6;

    fn fresh_state() -> ChainState {
        ChainState::with_log_slots(TEST_LOG_SLOTS)
    }

    #[test]
    fn empty_template_builds() {
        let parent = genesis_header();
        let state = fresh_state();
        let miner = Address([0xAB; 32]);

        let result = build_block_template(
            &parent,
            &state,
            &[parent.active_slot_count],
            vec![],
            miner,
            GENESIS_TIMESTAMP + BLOCK_TIME,
            GENESIS_TARGET,
        );
        assert!(result.is_ok(), "empty template should build: {:?}", result);
        let tmpl = result.unwrap();
        assert_eq!(tmpl.height, 1);
        assert_eq!(tmpl.txs.len(), 0);
        // Coinbase is present.
        assert!(tmpl.coinbase.body.is_coinbase);
        assert_eq!(tmpl.n_txs(), 1);
    }

    #[test]
    fn template_state_root_matches_applied() {
        let parent = genesis_header();
        let mut state = fresh_state();
        let miner = Address([0xAB; 32]);

        let tmpl = build_block_template(
            &parent,
            &state,
            &[parent.active_slot_count],
            vec![],
            miner,
            GENESIS_TIMESTAMP + BLOCK_TIME,
            GENESIS_TARGET,
        )
        .unwrap();

        // Apply coinbase to a fresh scratch state and check state_root matches.
        use crate::state::apply_tx;
        apply_tx(&mut state, &tmpl.coinbase.body).unwrap();
        assert_eq!(
            state.state_root(),
            tmpl.state_root,
            "template state_root must match manual application"
        );
    }

    #[test]
    fn template_tx_root_matches_compute() {
        let parent = genesis_header();
        let state = fresh_state();
        let miner = Address([0xAB; 32]);

        let tmpl = build_block_template(
            &parent,
            &state,
            &[parent.active_slot_count],
            vec![],
            miner,
            GENESIS_TIMESTAMP + BLOCK_TIME,
            GENESIS_TARGET,
        )
        .unwrap();

        let expected_tx_root = crate::block::compute_tx_root(&tmpl.all_txs());
        assert_eq!(tmpl.tx_root, expected_tx_root);
    }

    #[test]
    fn user_spend_template_state_root_matches_direct_utxo_root() {
        let owner = Address([0x11; 32]);
        let [owner_hi, owner_lo] = owner.as_fields();
        let mut state = fresh_state();
        state
            .state
            .set_slot(3, SlotValue::from_parts(100_000, 1, owner_hi, owner_lo))
            .unwrap();
        state.active_slot_count = 1;
        state.alloc_counter = 1;
        let parent_root = state.state_root();
        let mut parent = genesis_header();
        parent.state_root = parent_root;
        parent.log_slots = TEST_LOG_SLOTS as u32;
        parent.active_slot_count = state.active_slot_count;
        parent.alloc_counter = state.alloc_counter;

        let input = TxInput {
            slot_index: 3,
            value: 100_000,
            creation_id: 1,
            owner,
            spend_secret: SpendSecret([0x22; 32]),
            valid: true,
        };
        let output = TxOutput {
            slot_index: 4,
            value: 80_000,
            owner: Address([0x44; 32]),
            valid: true,
        };
        let body = TxBody::standard(block_id(&parent), 9_000, vec![input], vec![output], false);
        let tx = Transaction {
            tx_body_hash: hash_tx_body(
                &body.epoch_anchor,
                body.fee,
                &body.inputs,
                &body.outputs,
                body.is_coinbase,
            ),
            body,
        };

        let tmpl = build_block_template(
            &parent,
            &state,
            &[parent.active_slot_count],
            vec![tx.clone()],
            Address([0xAB; 32]),
            GENESIS_TIMESTAMP + BLOCK_TIME,
            GENESIS_TARGET,
        )
        .unwrap();

        let mut expected = state.clone();
        crate::state::apply_tx(&mut expected, &tmpl.coinbase.body).unwrap();
        crate::state::apply_tx(&mut expected, &tx.body).unwrap();
        assert_eq!(
            expected
                .state
                .slot(tmpl.coinbase.body.outputs[0].slot_index)
                .creation_id(),
            2,
            "coinbase must reserve the first child creation ID"
        );
        assert_eq!(
            expected.state.slot(4).creation_id(),
            3,
            "selected user outputs must keep coinbase-first creation IDs"
        );
        assert_eq!(tmpl.alloc_counter, 3);
        let expected_root = expected.state_root();
        assert_eq!(tmpl.state_root, expected_root);

        let mut block_order_state = state.clone();
        let block = crate::block::Block {
            header: tmpl.clone().into_header(0),
            transactions: tmpl.all_txs(),
        };
        crate::block::apply_block(&mut block_order_state, &block)
            .expect("template state root replays in coinbase-first block order");
        assert_eq!(block_order_state.state_root(), tmpl.state_root);
    }

    #[test]
    fn coinbase_anchor_binds_parent_hash_and_prevents_repeated_body_hash() {
        let parent = genesis_header();
        let mut state = fresh_state();
        let miner = Address([0xAB; 32]);

        let tmpl1 = build_block_template(
            &parent,
            &state,
            &[parent.active_slot_count],
            vec![],
            miner,
            GENESIS_TIMESTAMP + BLOCK_TIME,
            GENESIS_TARGET,
        )
        .unwrap();
        assert_eq!(tmpl1.coinbase.body.epoch_anchor, block_id(&parent));

        crate::state::apply_tx(&mut state, &tmpl1.coinbase.body).unwrap();
        let parent2 = tmpl1.clone().into_header(0);
        let tmpl2 = build_block_template(
            &parent2,
            &state,
            &[parent2.active_slot_count],
            vec![],
            miner,
            parent2.timestamp + BLOCK_TIME,
            GENESIS_TARGET,
        )
        .unwrap();

        assert_eq!(tmpl2.coinbase.body.epoch_anchor, block_id(&parent2));
        assert_ne!(tmpl1.coinbase.tx_body_hash, tmpl2.coinbase.tx_body_hash);
    }

    #[test]
    fn into_header_has_correct_fields() {
        let parent = genesis_header();
        let state = fresh_state();
        let miner = Address([0xAB; 32]);

        let tmpl = build_block_template(
            &parent,
            &state,
            &[parent.active_slot_count],
            vec![],
            miner,
            GENESIS_TIMESTAMP + BLOCK_TIME,
            GENESIS_TARGET,
        )
        .unwrap();

        let header = tmpl.clone().into_header(42u128);
        assert_eq!(header.height, 1);
        assert_eq!(header.nonce, 42);
        assert_eq!(header.state_root, tmpl.state_root);
    }
}
