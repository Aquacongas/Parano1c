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

use std::collections::{BTreeSet, HashSet};

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

#[derive(Clone, Default)]
struct TemplateResourceSelection {
    user_tx_count: usize,
    live_input_count: usize,
    live_output_count: usize,
    touched_slots: HashSet<u32>,
    touched_segments: BTreeSet<u32>,
}

impl TemplateResourceSelection {
    /// Return the next bounded selection, reserving one possible new segment
    /// for the mandatory coinbase output.
    fn with_user_tx(&self, tx: &Transaction) -> Option<Self> {
        if tx.body.is_coinbase {
            return None;
        }
        let user_tx_count = self.user_tx_count + 1;
        let live_input_count = self.live_input_count + tx.body.live_input_count();
        let live_output_count = self.live_output_count + tx.body.live_output_count();
        if user_tx_count > crate::consensus::params::BLOCK_MAX_USER_TXS
            || live_input_count > crate::consensus::params::BLOCK_MAX_LIVE_INPUTS
            || live_output_count > crate::consensus::params::BLOCK_MAX_USER_OUTPUTS
            || live_input_count + live_output_count
                > crate::consensus::params::BLOCK_MAX_USER_ACTIONS
        {
            return None;
        }

        let mut touched_slots = self.touched_slots.clone();
        let mut touched_segments = self.touched_segments.clone();
        for slot in tx
            .body
            .live_inputs()
            .map(|(_, input)| input.slot_index)
            .chain(tx.body.live_outputs().map(|(_, output)| output.slot_index))
        {
            if !touched_slots.insert(slot) {
                return None;
            }
            touched_segments.insert(slot >> crate::consensus::params::LOG_SEGMENT_SIZE);
        }
        if touched_segments.len() >= crate::consensus::params::BLOCK_MAX_DISTINCT_SEGMENTS {
            return None;
        }

        Some(Self {
            user_tx_count,
            live_input_count,
            live_output_count,
            touched_slots,
            touched_segments,
        })
    }
}

/// Build a `BlockTemplate` from a set of candidate transactions.
///
/// Steps:
/// 1. Conflict-resolve candidate txs, then enforce full touched-slot
///    disjointness during bounded selection.
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
    use noid_tx::{TxBody, TxInput, TxOutput, TX_INPUTS};

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
    // Reserve one segment for coinbase. Typical templates place coinbase in
    // an already-populated segment, but this conservative reservation makes
    // the final 256-segment consensus bound unconditional.
    let mut resources = TemplateResourceSelection::default();
    let ordered_winners = order_block_txs(winners);
    for tx in ordered_winners {
        let Some(next_resources) = resources.with_user_tx(&tx) else {
            continue;
        };
        let required =
            required_fee_for_tx_body(&tx.body, parent.active_slot_count, parent.log_slots);
        let actual = tx.body.fee;
        if actual < required {
            continue;
        }
        match apply_tx_checked_deferred_root(&mut selection_scratch, &tx.body) {
            Ok(_) => {
                resources = next_resources;
                applied_winners.push(tx);
            }
            Err(_e) => {}
        }
    }
    let ordered_winners = applied_winners;

    // Selection and final replay need the same logical parent state, but never
    // at the same time.  Release the first dense scratch image before cloning
    // the final replay state; otherwise a maximal state keeps two additional
    // resident state images alive across the rest of template construction.
    drop(selection_scratch);

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
                    .live_inputs()
                    .map(|(_, input)| input.slot_index)
                    .chain(tx.body.live_outputs().map(|(_, output)| output.slot_index))
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
                            && !scratch.state.is_evicted(
                                (slot >> scratch.state.effective_log_segment_size()) as u16,
                            )
                            && scratch.state.slot(slot) == crate::fri_state::SlotValue::EMPTY
                    });
                count *= 2;
            }
            // The residency filter above means callers must keep the
            // allocator's hint-window segments resident (or hydrated from
            // durable storage) — see the miner snapshot's
            // hydrate_coinbase_allocator_segments. An all-evicted hint
            // window otherwise reports NoCoinbaseSlot with the whole state
            // nearly empty.
            found.ok_or(TemplateBuildError::NoCoinbaseSlot)?
        }
    };

    // Sum only claimable fees. The deterministic state-growth component is burned.
    let claimable_fee_sum: u128 = ordered_winners
        .iter()
        .filter(|tx| !tx.body.is_coinbase)
        .map(|tx| {
            u128::from(claimable_fee_for_tx_body(
                &tx.body,
                parent.active_slot_count,
                parent.log_slots,
            ))
        })
        .sum();
    // The mathematical ceiling may exceed the body amount lane. Claiming less
    // is canonical, so the miner selects the largest representable amount.
    let coinbase_value = (u128::from(block_reward(new_log_slots)) + claimable_fee_sum)
        .min(u128::from(u64::MAX)) as u64;

    let prev_block_hash = block_id(parent);
    let cb_body = TxBody {
        epoch_anchor: prev_block_hash,
        fee: 0,
        input_owner: Address([0u8; 32]),
        inputs: [TxInput::dummy(); TX_INPUTS],
        outputs: [
            TxOutput {
                slot_index: coinbase_slot,
                amount: coinbase_value,
                owner: miner_address,
            },
            TxOutput::dummy(),
        ],
        validity_bitmap: 1 << TX_INPUTS,
        is_coinbase: true,
    };
    let coinbase = Transaction::new(cb_body);

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
    let tx_hashes_for_root: Vec<[u8; 32]> = std::iter::once(coinbase.txid().0)
        .chain(ordered_winners.iter().map(|tx| tx.txid().0))
        .collect();
    let tx_root = crate::tx_tree::root_from_hashes(&tx_hashes_for_root);

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
    use crate::consensus::fees::required_fee_for_tx_body;
    use noid_tx::{output_bitmap_bit, TxBody, TxInput, TxOutput, TX_INPUTS, TX_OUTPUTS};

    fn parent(state: &mut ChainState) -> BlockHeader {
        BlockHeader {
            prev_block_hash: [0u8; 32],
            state_root: state.state_root(),
            tx_root: [0u8; 32],
            timestamp: 0,
            height: 0,
            miner_address: Address([0u8; 32]),
            nonce: 0,
            difficulty_target: [0xff; 32],
            log_slots: state.state.log_slots() as u32,
            active_slot_count: state.active_slot_count,
            alloc_counter: state.alloc_counter,
        }
    }

    fn user(
        input_slot: u32,
        output_slot: u32,
        amount: u64,
        owner: Address,
        parent: &BlockHeader,
    ) -> Transaction {
        let mut inputs = [TxInput::dummy(); TX_INPUTS];
        inputs[0] = TxInput {
            slot_index: input_slot,
            amount,
            creation_id: 1,
        };
        let mut outputs = [TxOutput::dummy(); TX_OUTPUTS];
        outputs[0] = TxOutput {
            slot_index: output_slot,
            amount,
            owner,
        };
        let mut body = TxBody {
            epoch_anchor: block_id(parent),
            fee: 0,
            input_owner: owner,
            inputs,
            outputs,
            validity_bitmap: 1 | output_bitmap_bit(0),
            is_coinbase: false,
        };
        body.fee = required_fee_for_tx_body(&body, parent.active_slot_count, parent.log_slots);
        body.outputs[0].amount -= body.fee;
        Transaction::new(body)
    }

    #[test]
    fn template_coinbase_is_exact_and_root_uses_shared_helper() {
        let mut state = ChainState::with_log_slots(8);
        let parent = parent(&mut state);
        let template = build_block_template(
            &parent,
            &state,
            &[0],
            vec![],
            Address([9u8; 32]),
            1,
            [0xff; 32],
        )
        .unwrap();
        assert!(template.coinbase.body.is_coinbase);
        assert_eq!(template.coinbase.body.validity_bitmap, output_bitmap_bit(0));
        assert_eq!(template.coinbase.body.input_owner, Address([0u8; 32]));
        assert_eq!(
            template.tx_root,
            crate::block::compute_tx_root(&template.all_txs())
        );
    }

    #[test]
    fn selection_never_builds_same_block_slot_chains() {
        let owner = Address([1u8; 32]);
        let mut state = ChainState::with_log_slots(8);
        for slot in [1u32, 2] {
            state
                .state
                .set_slot(
                    slot,
                    crate::fri_state::SlotValue::with_owner_fields(1_000_000, 1, owner.as_fields()),
                )
                .unwrap();
        }
        state.active_slot_count = 2;
        state.alloc_counter = 1;
        let parent = parent(&mut state);
        let a = user(1, 3, 1_000_000, owner, &parent);
        let b = user(2, 1, 1_000_000, owner, &parent);
        let template = build_block_template(
            &parent,
            &state,
            &[2],
            vec![a, b],
            Address([9u8; 32]),
            1,
            [0xff; 32],
        )
        .unwrap();
        assert!(template.txs.len() <= 1);
    }
}
