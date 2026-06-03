// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Block template construction for the mining pipeline .
//!
//! A `BlockTemplate` is a fully computed block ready for PoW search:
//! - Transaction set selected and conflict-resolved
//! - State applied to scratch copy → `state_root` known
//! - All header fields computed except `nonce` and `proof_transcript_hash`
//!
//! The miner receives `header_core_bytes(nonce=0)` and searches for a valid nonce.
//! When found, the full node finalises: `header = header_core + nonce + proof_hash`.
//!
//! # Why state_root is in header_core (PoW input)
//!
//! Including `state_root` in the PoW hash prevents external miners from changing
//! the coinbase address: a different coinbase → different post-state → different
//! `state_root` → different `header_core` → must redo PoW from scratch.
//! This is Paranoid's block-withholding protection.

use noid_poseidon2b::primitives::{Address, Digest};
use noid_tx::Transaction;

use crate::block::compute_tx_root;
use crate::block_header::BlockHeader;
use crate::consensus::{emission::max_coinbase_value, pow::full_block_hash};
use crate::state::ChainState;

// ---------------------------------------------------------------------------
// BlockTemplate
// ---------------------------------------------------------------------------

/// A fully assembled block template ready for PoW search.
///
/// All header fields except `nonce` and `proof_transcript_hash` are fixed.
/// The miner iterates nonces over `header_core_bytes()` and returns a valid one.
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
    /// Build a `BlockHeader` from this template with the given nonce and
    /// proof_transcript_hash.
    ///
    /// Called after: (a) miner returns valid nonce, (b) BlockProof is ready.
    pub fn into_header(
        self,
        nonce: u128,
        proof_transcript_hash: Digest,
        witness_root: Digest,
    ) -> BlockHeader {
        BlockHeader {
            prev_block_hash: self.prev_block_hash,
            state_root: self.state_root,
            tx_root: self.tx_root,
            timestamp: self.timestamp,
            height: self.height,
            miner_address: self.miner_address,
            nonce,
            difficulty_target: self.difficulty_target,
            proof_transcript_hash,
            witness_root,
            log_slots: self.log_slots,
            active_slot_count: self.active_slot_count,
            alloc_counter: self.alloc_counter,
        }
    }

    /// Build a `BlockHeader` for PoW purposes (nonce=0, proof fields zeroed).
    /// Use `header_core_bytes(hdr)` from pow.rs to get the 212-byte PoW input.
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
            proof_transcript_hash: [0u8; 32], // excluded from PoW
            witness_root: [0u8; 32],          // excluded from PoW
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
    use crate::consensus::timestamps::median_u64;
    use crate::consensus::{conflict::resolve_slot_conflicts, ordering::order_block_txs};
    use crate::state::apply_tx;
    use noid_tx::{hash_tx_body, TxBody, TxOutput};

    // 1. Resolve slot conflicts among candidate txs.
    let (winners, _losers) = resolve_slot_conflicts(candidate_txs);

    // 2. Determine expansion trigger using median over prev_active_counts window.
    //    Must match validate_block_consensus exactly so the block we produce passes
    //    consensus validation.
    use crate::consensus::params::{EXPAND_DENOM, EXPAND_NUM, LOG_SLOTS_MAX};
    let prev_capacity = 1u64.checked_shl(parent.log_slots).unwrap_or(u64::MAX);
    let median_active = if prev_active_counts.is_empty() {
        parent.active_slot_count
    } else {
        median_u64(prev_active_counts)
    };
    let should_expand =
        median_active.saturating_mul(EXPAND_DENOM) >= prev_capacity.saturating_mul(EXPAND_NUM);
    let new_log_slots = if should_expand {
        (parent.log_slots + 1).min(LOG_SLOTS_MAX)
    } else {
        parent.log_slots
    };

    // 3. Apply non-coinbase txs to scratch state.
    let mut scratch = state.clone();
    if should_expand {
        // expand() does not return a Result; it panics on invalid state.
        scratch.state.expand();
    }

    // Apply txs one by one; exclude any that fail due to state conflicts
    // (e.g. output slot occupied by a coinbase from a block mined between
    // the wallet's proof and this template build). This is the standard
    // "soft" tx exclusion used by all UTXO miners.
    let mut applied_winners: Vec<Transaction> = Vec::new();
    let ordered_winners = order_block_txs(winners);
    for tx in ordered_winners {
        match apply_tx(&mut scratch, &tx.body) {
            Ok(_) => applied_winners.push(tx),
            Err(_e) => {
                // Skip: output slot occupied by a recently confirmed block.
                // The wallet must re-prove with fresh slot hints.
                // (debug logging requires tracing crate — omitted from noid_chain)
            }
        }
    }
    let ordered_winners = applied_winners;

    // 4. Build coinbase transaction.
    // Find an empty slot for coinbase output using the allocator.
    // Use the scratch state's actual capacity so hints are always in range.
    let coinbase_slot = {
        let state_log_slots = scratch.state.log_slots() as u32;
        // Use 256 hints to keep failure probability negligible even at high occupancy
        // (p_all_occupied = occupancy^256; at 90% occupancy ≈ 2×10^{-12}).
        let hints = generate_slot_hints(scratch.alloc_counter, state_log_slots, 256);
        hints
            .into_iter()
            .find(|&slot| scratch.state.slot(slot) == crate::fri_state::SlotValue::EMPTY)
            .ok_or(TemplateBuildError::NoCoinbaseSlot)?
    };

    let non_cb_bodies: Vec<_> = ordered_winners.iter().map(|tx| tx.body.clone()).collect();
    let coinbase_value = max_coinbase_value(new_log_slots, &non_cb_bodies);

    let cb_body = TxBody {
        epoch_anchor: [0u8; 32],
        fee: 0,
        inputs: vec![],
        outputs: vec![TxOutput {
            slot_index: coinbase_slot,
            value: coinbase_value,
            owner: miner_address,
            valid: true,
        }],
        is_coinbase: true,
    };
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

    // Apply coinbase to scratch state.
    apply_tx(&mut scratch, &coinbase.body)
        .map_err(|e| TemplateBuildError::StateApplyError(format!("{:?}", e)))?;

    // 5. Compute final header fields.
    let state_root = scratch.state_root();
    let all_txs_for_root = {
        let mut v = vec![coinbase.clone()];
        v.extend(ordered_winners.iter().cloned());
        v
    };
    let tx_root = compute_tx_root(&all_txs_for_root);
    let prev_block_hash = full_block_hash(parent);

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
    use crate::state::ChainState;
    use noid_poseidon2b::primitives::Address;

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

        let expected_tx_root = compute_tx_root(&tmpl.all_txs());
        assert_eq!(tmpl.tx_root, expected_tx_root);
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

        let header = tmpl.clone().into_header(42u128, [1u8; 32], [2u8; 32]);
        assert_eq!(header.height, 1);
        assert_eq!(header.nonce, 42);
        assert_eq!(header.proof_transcript_hash, [1u8; 32]);
        assert_eq!(header.witness_root, [2u8; 32]);
        assert_eq!(header.state_root, tmpl.state_root);
    }
}
