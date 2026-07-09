// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Accepted state-transition claim.
//!
//! This compact summary is emitted only after block validation has accepted the
//! exact transition. It is a local proof-worker witness, not standalone public
//! snapshot authority: a future public history proof must either derive it from
//! the full accepted-block relation or rely on a consensus commitment to its
//! digest.

use noid_chain::block::{compute_tx_root, Block};
use noid_chain::block_header::BlockHeader;
use noid_chain::consensus::fees::claimable_fee_for_tx_body;
use noid_chain::hash_block_header;
use noid_chain::state_delta::{ExactActionSurface, StateDeltaActionKind};
use noid_core::{Block128, TowerField};
use noid_poseidon2b::native::compression::Poseidon2bSponge;
use noid_poseidon2b::native::domain::{capacity_iv, TAG_HISTCLM, TAG_HISTTRN};
use noid_poseidon2b::primitives::Digest;

use crate::{AcceptedBlockValidationArtifacts, VerifyBlockError};

pub const ACCEPTED_STATE_TRANSITION_CLAIM_FIELDS: usize = 40;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AcceptedStateTransitionClaim {
    pub height: u64,
    pub block_id: Digest,
    pub parent_block_id: Digest,
    pub parent_state_root: Digest,
    pub child_state_root: Digest,
    pub tx_root: Digest,
    pub parent_log_slots: u32,
    pub child_log_slots: u32,
    pub parent_active_slot_count: u64,
    pub child_active_slot_count: u64,
    pub parent_alloc_counter: u64,
    pub child_alloc_counter: u64,
    pub parent_utxo_root: Digest,
    pub child_utxo_root: Digest,
    pub parent_guard_root: Digest,
    pub child_guard_root: Digest,
    pub touched_slot_count: u32,
    pub action_count: u32,
    pub spend_count: u32,
    pub mint_count: u32,
    pub user_body_count: u32,
    pub live_input_count: u32,
    pub live_output_count: u32,
    pub total_fee: u128,
    pub claimable_fee: u128,
    pub reward_value: u128,
    pub spent_value: u128,
    pub minted_value: u128,
    pub supply_delta: i128,
    pub exact_transition_digest: Digest,
    pub claim_digest: Digest,
}

impl AcceptedStateTransitionClaim {
    pub fn from_accepted_block(
        block: &Block,
        parent: &BlockHeader,
        artifacts: &AcceptedBlockValidationArtifacts,
    ) -> Result<Self, VerifyBlockError> {
        if block.header.prev_block_hash != hash_block_header(parent)
            || block.header.tx_root != compute_tx_root(&block.transactions)
        {
            return Err(VerifyBlockError::HistoryClaimMismatch);
        }
        let verified = &artifacts.verified_transition;
        let inputs = &artifacts.exact_state_inputs;
        if inputs.parent_state_root != parent.state_root
            || verified.parent_state_root() != parent.state_root
            || verified.child_state_root() != block.header.state_root
            || verified.log_slots() != block.header.log_slots
            || verified.active_slot_count() != block.header.active_slot_count
            || verified.alloc_counter() != block.header.alloc_counter
        {
            return Err(VerifyBlockError::HistoryClaimMismatch);
        }

        let mut counters = semantic_counters(block, parent);
        if counters.live_input_count != artifacts.exact_action_surface.spends
            || counters.live_output_count != artifacts.exact_action_surface.mints
        {
            return Err(VerifyBlockError::HistoryClaimMismatch);
        }
        let value_counters = transition_value_counters(&artifacts.exact_action_surface);
        counters.spent_value = value_counters.spent_value;
        counters.minted_value = value_counters.minted_value;
        counters.supply_delta = value_counters.supply_delta;

        let exact_transition_digest =
            exact_transition_digest(&artifacts.exact_action_surface, verified.child_utxo_root());

        let mut claim = Self {
            height: block.header.height,
            block_id: hash_block_header(&block.header),
            parent_block_id: hash_block_header(parent),
            parent_state_root: parent.state_root,
            child_state_root: block.header.state_root,
            tx_root: block.header.tx_root,
            parent_log_slots: inputs.parent_log_slots,
            child_log_slots: block.header.log_slots,
            parent_active_slot_count: inputs.parent_active_slot_count,
            child_active_slot_count: verified.active_slot_count(),
            parent_alloc_counter: inputs.parent_alloc_counter,
            child_alloc_counter: verified.alloc_counter(),
            parent_utxo_root: inputs.parent_utxo_root,
            child_utxo_root: verified.child_utxo_root(),
            parent_guard_root: inputs.parent_guard_root,
            child_guard_root: verified.child_guard_root(),
            touched_slot_count: artifacts.exact_action_surface.touched_indices.len() as u32,
            action_count: artifacts.exact_action_surface.actions.len() as u32,
            spend_count: artifacts.exact_action_surface.spends,
            mint_count: artifacts.exact_action_surface.mints,
            user_body_count: counters.user_body_count,
            live_input_count: counters.live_input_count,
            live_output_count: counters.live_output_count,
            total_fee: counters.total_fee,
            claimable_fee: counters.claimable_fee,
            reward_value: counters.reward_value,
            spent_value: counters.spent_value,
            minted_value: counters.minted_value,
            supply_delta: counters.supply_delta,
            exact_transition_digest,
            claim_digest: [0u8; 32],
        };
        claim.claim_digest = accepted_state_transition_claim_digest(&claim);
        Ok(claim)
    }

    pub fn fields(&self) -> [Block128; ACCEPTED_STATE_TRANSITION_CLAIM_FIELDS] {
        accepted_state_transition_claim_fields(self)
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct SemanticCounters {
    user_body_count: u32,
    live_input_count: u32,
    live_output_count: u32,
    total_fee: u128,
    claimable_fee: u128,
    reward_value: u128,
    spent_value: u128,
    minted_value: u128,
    supply_delta: i128,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct TransitionValueCounters {
    spent_value: u128,
    minted_value: u128,
    supply_delta: i128,
}

fn semantic_counters(block: &Block, parent: &BlockHeader) -> SemanticCounters {
    let mut counters = SemanticCounters::default();
    for tx in &block.transactions {
        let live_inputs = tx.body.inputs.iter().filter(|input| input.valid).count() as u32;
        let live_outputs = tx.body.outputs.iter().filter(|output| output.valid).count() as u32;
        counters.live_input_count = counters.live_input_count.saturating_add(live_inputs);
        counters.live_output_count = counters.live_output_count.saturating_add(live_outputs);

        if tx.body.is_coinbase {
            counters.reward_value = counters.reward_value.saturating_add(
                tx.body
                    .outputs
                    .iter()
                    .filter(|output| output.valid)
                    .map(|output| output.value as u128)
                    .sum::<u128>(),
            );
        } else {
            counters.user_body_count = counters.user_body_count.saturating_add(1);
            counters.total_fee = counters.total_fee.saturating_add(tx.body.fee);
            counters.claimable_fee =
                counters
                    .claimable_fee
                    .saturating_add(claimable_fee_for_tx_body(
                        &tx.body,
                        parent.active_slot_count,
                        parent.log_slots,
                    ) as u128);
        }
    }
    counters
}

fn transition_value_counters(surface: &ExactActionSurface) -> TransitionValueCounters {
    let mut counters = TransitionValueCounters::default();
    for action in &surface.actions {
        match action.kind {
            StateDeltaActionKind::Spend => {
                counters.spent_value = counters
                    .spent_value
                    .saturating_add(action.pre.value.to_u128());
            }
            StateDeltaActionKind::Mint => {
                counters.minted_value = counters
                    .minted_value
                    .saturating_add(action.post.value.to_u128());
            }
        }
    }
    counters.supply_delta = counters.minted_value.min(i128::MAX as u128) as i128
        - counters.spent_value.min(i128::MAX as u128) as i128;
    counters
}

fn exact_transition_digest(surface: &ExactActionSurface, child_utxo_root: Digest) -> Digest {
    let mut sponge = Poseidon2bSponge::with_iv(capacity_iv(TAG_HISTTRN));
    sponge.absorb(Block128::from(surface.actions.len() as u128));
    sponge.absorb(Block128::from(surface.touched_indices.len() as u128));
    sponge.absorb(Block128::from(surface.spends as u128));
    sponge.absorb(Block128::from(surface.mints as u128));
    for action in &surface.actions {
        sponge.absorb(Block128::from(action.tx_index as u128));
        sponge.absorb(Block128::from(action.op_index as u128));
        sponge.absorb(Block128::from(action.slot_index as u128));
        sponge.absorb(match action.kind {
            StateDeltaActionKind::Spend => Block128::ZERO,
            StateDeltaActionKind::Mint => Block128::ONE,
        });
        absorb_slot(&mut sponge, action.pre);
        absorb_slot(&mut sponge, action.post);
    }
    for ((&slot_index, old_slot), new_slot) in surface
        .touched_indices
        .iter()
        .zip(surface.old_slots.iter())
        .zip(surface.new_slots.iter())
    {
        sponge.absorb(Block128::from(slot_index as u128));
        absorb_slot(&mut sponge, *old_slot);
        absorb_slot(&mut sponge, *new_slot);
    }
    for &slot_index in &surface.spent_slots {
        sponge.absorb(Block128::from(slot_index as u128));
    }
    // The absorb schedule is VARIABLE-length (per-surface action/slot
    // counts) and can end on a half-filled rate block, so the padded
    // finalize is required: the no-pad squeeze would silently drop a
    // trailing buffered lane from the commitment.
    absorb_digest(&mut sponge, &child_utxo_root);
    sponge.finalize()
}

pub fn accepted_state_transition_claim_fields(
    claim: &AcceptedStateTransitionClaim,
) -> [Block128; ACCEPTED_STATE_TRANSITION_CLAIM_FIELDS] {
    let mut fields = Vec::with_capacity(ACCEPTED_STATE_TRANSITION_CLAIM_FIELDS);
    fields.push(Block128::from(claim.height as u128));
    push_digest_fields(&mut fields, &claim.block_id);
    push_digest_fields(&mut fields, &claim.parent_block_id);
    push_digest_fields(&mut fields, &claim.parent_state_root);
    push_digest_fields(&mut fields, &claim.child_state_root);
    push_digest_fields(&mut fields, &claim.tx_root);
    fields.push(Block128::from(claim.parent_log_slots as u128));
    fields.push(Block128::from(claim.child_log_slots as u128));
    fields.push(Block128::from(claim.parent_active_slot_count as u128));
    fields.push(Block128::from(claim.child_active_slot_count as u128));
    fields.push(Block128::from(claim.parent_alloc_counter as u128));
    fields.push(Block128::from(claim.child_alloc_counter as u128));
    push_digest_fields(&mut fields, &claim.parent_utxo_root);
    push_digest_fields(&mut fields, &claim.child_utxo_root);
    push_digest_fields(&mut fields, &claim.parent_guard_root);
    push_digest_fields(&mut fields, &claim.child_guard_root);
    fields.push(Block128::from(claim.touched_slot_count as u128));
    fields.push(Block128::from(claim.action_count as u128));
    fields.push(Block128::from(claim.spend_count as u128));
    fields.push(Block128::from(claim.mint_count as u128));
    fields.push(Block128::from(claim.user_body_count as u128));
    fields.push(Block128::from(claim.live_input_count as u128));
    fields.push(Block128::from(claim.live_output_count as u128));
    fields.push(Block128::from(claim.total_fee));
    fields.push(Block128::from(claim.claimable_fee));
    fields.push(Block128::from(claim.reward_value));
    fields.push(Block128::from(claim.spent_value));
    fields.push(Block128::from(claim.minted_value));
    fields.push(Block128::from(claim.supply_delta as u128));
    push_digest_fields(&mut fields, &claim.exact_transition_digest);
    fields
        .try_into()
        .expect("accepted state-transition claim schedule has fixed length")
}

pub fn accepted_state_transition_claim_digest(claim: &AcceptedStateTransitionClaim) -> Digest {
    let mut sponge = Poseidon2bSponge::with_iv(capacity_iv(TAG_HISTCLM));
    for pair in accepted_state_transition_claim_fields(claim).chunks_exact(2) {
        sponge.absorb_pair(pair[0], pair[1]);
    }
    sponge.finalize_no_pad()
}

pub fn accepted_state_transition_chain_claim(
    claim: &AcceptedStateTransitionClaim,
) -> [Block128; 2] {
    digest_to_fields(&claim.claim_digest)
}

fn push_digest_fields(fields: &mut Vec<Block128>, digest: &Digest) {
    let [lo, hi] = digest_to_fields(digest);
    fields.push(lo);
    fields.push(hi);
}

fn digest_to_fields(digest: &Digest) -> [Block128; 2] {
    [
        Block128::from(u128::from_le_bytes(digest[..16].try_into().unwrap())),
        Block128::from(u128::from_le_bytes(digest[16..].try_into().unwrap())),
    ]
}

fn absorb_digest(sponge: &mut Poseidon2bSponge, digest: &Digest) {
    let [lo, hi] = digest_to_fields(digest);
    sponge.absorb_pair(lo, hi);
}

fn absorb_slot(sponge: &mut Poseidon2bSponge, slot: noid_chain::fri_state::SlotValue) {
    sponge.absorb(slot.value);
    sponge.absorb(slot.owner_hi);
    sponge.absorb(slot.owner_lo);
}
