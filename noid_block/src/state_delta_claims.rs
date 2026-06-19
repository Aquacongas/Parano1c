// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Adapter from the canonical native state-delta action surface to the current
//! `BlockStateBindingAir` claim surface.
//!
//! This module intentionally does **not** change the proof format yet.  It makes
//! the ordered `StateDeltaActionSurface` the single semantic source for the
//! current per-segment BSB claims, so the later compact state-delta proof can
//! replace the proof backend without changing consensus semantics.

use std::collections::{BTreeMap, HashSet};

use noid_air::airs::block_state_binding::BlockStateBindingClaim;
use noid_chain::block::Block;
use noid_chain::segmented_state::SegmentedFriState;
use noid_chain::{
    build_state_delta_action_surface, SlotValue, StateDeltaActionKind, StateDeltaActionSurface,
    StateDeltaError,
};
use noid_core::Block128;
use noid_poseidon2b::primitives::Address;
use noid_tx::TxBody;

use crate::VerifyBlockError;

pub(crate) type StateBindingClaimMap = BTreeMap<u16, Vec<BlockStateBindingClaim>>;

#[inline]
fn segment_parts(slot_index: u32, eff_log: usize) -> (u16, u32) {
    let seg_mask = (1u32 << eff_log) - 1;
    ((slot_index >> eff_log) as u16, slot_index & seg_mask)
}

#[inline]
fn push_mint_claim(
    seg_claims: &mut StateBindingClaimMap,
    eff_log: usize,
    slot_index: u32,
    value: u64,
    owner: Address,
) {
    let (seg_id, local) = segment_parts(slot_index, eff_log);
    let [owner_hi, owner_lo] = owner.as_fields();
    seg_claims
        .entry(seg_id)
        .or_default()
        .push(BlockStateBindingClaim::mint(
            local,
            Block128::from(value as u128),
            owner_hi,
            owner_lo,
        ));
}

pub(crate) fn claims_from_action_surface(
    surface: &StateDeltaActionSurface,
    coinbase_bodies: &[&TxBody],
    eff_log: usize,
) -> StateBindingClaimMap {
    let mut seg_claims = BTreeMap::new();

    // Preserve the current proof surface: coinbase output mints are included
    // before user actions so post-state openings bind the header root, but
    // coinbase outputs are not visible to user tx prefix reads in this block.
    for body in coinbase_bodies {
        for output in body.outputs.iter().filter(|output| output.valid) {
            push_mint_claim(
                &mut seg_claims,
                eff_log,
                output.slot_index,
                output.value,
                output.owner,
            );
        }
    }

    for action in &surface.actions {
        let (seg_id, local) = segment_parts(action.slot_index, eff_log);
        let claim = match action.kind {
            StateDeltaActionKind::Spend => BlockStateBindingClaim::spend(
                local,
                action.pre.value,
                action.pre.owner_hi,
                action.pre.owner_lo,
            ),
            StateDeltaActionKind::Mint => BlockStateBindingClaim::mint(
                local,
                action.post.value,
                action.post.owner_hi,
                action.post.owner_lo,
            ),
        };
        seg_claims.entry(seg_id).or_default().push(claim);
    }

    seg_claims
}

pub(crate) fn collect_state_binding_claims_from_block(
    block: &Block,
    commitments_by_block_index: &[Option<[u8; 32]>],
    pre_state: &SegmentedFriState,
) -> Result<StateBindingClaimMap, VerifyBlockError> {
    let n_slots = pre_state.num_slots();
    let eff_log = pre_state.effective_log_segment_size();
    let mut coinbase_bodies = Vec::new();
    let mut coinbase_output_slots = HashSet::new();

    for (tx_idx, tx) in block.transactions.iter().enumerate() {
        if !tx.body.is_coinbase {
            continue;
        }
        coinbase_bodies.push(&tx.body);
        for (output_index, output) in tx.body.outputs.iter().enumerate() {
            if !output.valid {
                continue;
            }
            if (output.slot_index as u64) >= n_slots {
                return Err(VerifyBlockError::StateBindingSlotOutOfRange { tx_index: tx_idx });
            }
            if !coinbase_output_slots.insert(output.slot_index)
                || pre_state.slot(output.slot_index) != SlotValue::EMPTY
            {
                return Err(VerifyBlockError::StateBindingOutputOccupied {
                    tx_index: tx_idx,
                    output_index,
                });
            }
        }
    }

    let mut user_bodies = Vec::new();
    let mut user_commitments = Vec::new();
    let mut user_block_indices = Vec::new();

    for (tx_idx, tx) in block.transactions.iter().enumerate() {
        if tx.body.is_coinbase {
            continue;
        }
        let Some(expected_commitment) = commitments_by_block_index.get(tx_idx).and_then(|v| *v)
        else {
            return Err(VerifyBlockError::ShapeMismatch);
        };

        // Current BSB semantics include coinbase mints in the post root but do
        // not make them spendable or re-mintable by user txs in the same block.
        for (output_index, output) in tx.body.outputs.iter().enumerate() {
            if output.valid && coinbase_output_slots.contains(&output.slot_index) {
                return Err(VerifyBlockError::StateBindingOutputOccupied {
                    tx_index: tx_idx,
                    output_index,
                });
            }
        }

        user_bodies.push(tx.body.clone());
        user_commitments.push(expected_commitment);
        user_block_indices.push(tx_idx);
    }

    let surface = build_state_delta_action_surface(pre_state, &user_bodies, &user_commitments)
        .map_err(|err| map_state_delta_error(err, &user_block_indices))?;
    Ok(claims_from_action_surface(
        &surface,
        &coinbase_bodies,
        eff_log,
    ))
}

fn map_state_delta_error(err: StateDeltaError, block_indices: &[usize]) -> VerifyBlockError {
    let map_tx = |tx_index: usize| block_indices.get(tx_index).copied().unwrap_or(tx_index);
    match err {
        StateDeltaError::InputMismatch {
            tx_index,
            input_index,
        } => VerifyBlockError::StateBindingInputMismatch {
            tx_index: map_tx(tx_index),
            input_index,
        },
        StateDeltaError::OutputSlotOccupied {
            tx_index,
            output_index,
        } => VerifyBlockError::StateBindingOutputOccupied {
            tx_index: map_tx(tx_index),
            output_index,
        },
        StateDeltaError::ClaimsCommitmentMismatch { tx_index } => {
            VerifyBlockError::StateBindingClaimsCommitmentMismatch {
                tx_index: map_tx(tx_index),
            }
        }
        StateDeltaError::DuplicateInputSlot { tx_index } => {
            VerifyBlockError::StateBindingDuplicateInputSlot {
                tx_index: map_tx(tx_index),
            }
        }
        StateDeltaError::DuplicateOutputSlot { tx_index } => {
            VerifyBlockError::StateBindingDuplicateOutputSlot {
                tx_index: map_tx(tx_index),
            }
        }
        StateDeltaError::InputOutputSlotOverlap { tx_index } => {
            VerifyBlockError::StateBindingInputOutputSlotOverlap {
                tx_index: map_tx(tx_index),
            }
        }
        StateDeltaError::SlotOutOfRange { tx_index } => {
            VerifyBlockError::StateBindingSlotOutOfRange {
                tx_index: map_tx(tx_index),
            }
        }
    }
}
