// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid.

//! Full-node block proof orchestration (Phase 3 / Stage F.5–F.6).
//!
//! Combines LogicProof verification, BlockStateBinding, per-segment state
//! binding AIRs, Merkle Kill-Shot proofs, and the Stage G deferred-opening
//! BlockProof into a single coherent pipeline.
//!
//! # Full-node prove flow (segmented)
//!
//! 1. Verify each wallet-submitted `LogicProof`.
//! 2. Build `BlockStateBinding` — opens slots, verifies pre/post state.
//! 3. For each touched segment:
//!    a. Build `BlockStateBindingAir` + witness (F.6) with local 16-bit eval point.
//!    b. Derive `MerklePathInputs` from `SegmentedFriState` (F.5).
//!    c. Run `prove_merkle_killshot` for the segment Merkle path (F.5).
//! 4. Produce the `BlockProof` (one AIR participant per touched segment).
//!
//! # Single-segment / test mode
//!
//! When `log_slots <= LOG_SEGMENT_SIZE`, the state is monolithic (one segment,
//! `merkle_siblings` is empty, no Kill-Shot). The flow degenerates to the
//! legacy single-AIR path — all existing tests pass unchanged.

#![allow(clippy::too_many_arguments)]

use noid_air::airs::block_state_binding::{
    BlockStateBindingAir, BlockStateBindingClaim, BlockStateBindingWitness,
};
use noid_air::Air;
use noid_chain::segmented_state::SegmentedFriState;
use noid_chain::state_binding::{BlockStateBinding, StateBindingError};
use noid_chain::BlockHeader;
use noid_core::mle::evaluate::evaluate_slice;
use noid_core::Block128;
use noid_fri::Channel;
use noid_gkr::{AuthPublicInputs, MerkleCircuit, MerklePathInputs, SpineInputs, MAX_MERKLE_DEPTH};
use noid_recursive::{
    accumulator::ChainAccumulator,
    air::RecursiveBlockAir,
    prove::{prove_recursive_step, RecursiveBlockProof},
    verify::verify_tip,
    witness::BlockReplayWitness,
};
use noid_stark::prove_logic::{verify_logic, LogicProof, VerifyLogicError};
use noid_tx::{compute_claims_commitment, PublicInputs, TxBody};

use crate::{
    prove_block, verify_block, BlockProof, ProveBlockError, StateBindingBlockWitness,
    TxBlockWitness, VerifyBlockError,
};

pub use noid_gkr::{verify_merkle_killshot, MerkleProofKillShot};
use noid_poseidon2b::channel::Poseidon2bChannel;
pub use noid_recursive::accumulator::genesis_accumulator;

const STATE_BINDING_CHANNEL_TAG: u128 = 0xFFFC_5B00_0000_0000;

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum FullNodeProveError {
    LogicProofInvalid {
        tx_index: usize,
        inner: VerifyLogicError,
    },
    StateBinding(StateBindingError),
    BlockProof(ProveBlockError),
}

#[derive(Debug)]
pub enum FullNodeVerifyError {
    StateBinding(StateBindingError),
    StateRootMismatch,
    BlockProof(VerifyBlockError),
    MerkleKillShot { segment_idx: usize },
    RecursiveProofInvalid,
}

impl From<StateBindingError> for FullNodeProveError {
    fn from(e: StateBindingError) -> Self {
        Self::StateBinding(e)
    }
}
impl From<ProveBlockError> for FullNodeProveError {
    fn from(e: ProveBlockError) -> Self {
        Self::BlockProof(e)
    }
}
impl From<StateBindingError> for FullNodeVerifyError {
    fn from(e: StateBindingError) -> Self {
        Self::StateBinding(e)
    }
}
impl From<VerifyBlockError> for FullNodeVerifyError {
    fn from(e: VerifyBlockError) -> Self {
        Self::BlockProof(e)
    }
}

// ---------------------------------------------------------------------------
// Full prove result
// ---------------------------------------------------------------------------

pub struct FullBlockProof {
    pub block_proof: BlockProof,
    pub state_binding: BlockStateBinding,
    /// One Merkle Kill-Shot proof per touched segment (empty in single-segment mode).
    pub merkle_killshots: Vec<MerkleProofKillShot>,
    /// Recursive chain proof: O(1) constant-size proof covering the entire chain.
    /// ~11 KB regardless of chain length.
    pub rec_proof: RecursiveBlockProof,
    /// The updated chain accumulator after this block (for the next block's prover).
    pub new_acc: ChainAccumulator,
}

// ---------------------------------------------------------------------------
// Claims helpers
// ---------------------------------------------------------------------------

/// Build flat `BlockStateBindingClaim` list from all transactions in the block.
/// For each segment's AIR, we later filter to its own claims and convert to local_idx.
fn build_claims_from_bodies(bodies: &[TxBody]) -> Vec<BlockStateBindingClaim> {
    let mut claims = Vec::new();
    for body in bodies {
        for inp in body.inputs.iter().filter(|i| i.valid) {
            let [owner_hi, owner_lo] = inp.owner.as_fields();
            claims.push(BlockStateBindingClaim::spend(
                inp.slot_index,
                Block128::from(inp.value as u128),
                owner_hi,
                owner_lo,
            ));
        }
        for out in body.outputs.iter().filter(|o| o.valid) {
            let [owner_hi, owner_lo] = out.owner.as_fields();
            claims.push(BlockStateBindingClaim::mint(
                out.slot_index,
                Block128::from(out.value as u128),
                owner_hi,
                owner_lo,
            ));
        }
    }
    claims
}

/// Filter all claims to those belonging to `seg_id` and convert slot_index → local_idx.
fn claims_for_segment(
    all_claims: &[BlockStateBindingClaim],
    seg_id: u16,
    effective_log_seg: usize,
) -> Vec<BlockStateBindingClaim> {
    let seg_size = (1u32 << effective_log_seg) - 1; // mask for local bits
    all_claims
        .iter()
        .filter(|c| (c.slot_index >> effective_log_seg) as u16 == seg_id)
        .map(|c| {
            let mut lc = c.clone();
            lc.slot_index &= seg_size; // convert to segment-local index
            lc
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Fiat-Shamir challenges for one segment's state binding AIR
// ---------------------------------------------------------------------------

fn derive_state_binding_challenges(
    prev_state_root: &[u8; 32],
    claims: &[BlockStateBindingClaim],
    effective_log_seg: usize,
) -> (Vec<Block128>, Block128) {
    let mut ch = Channel::new();
    ch.observe_field_elem(Block128::from(STATE_BINDING_CHANNEL_TAG));

    let lo = u128::from_le_bytes(prev_state_root[..16].try_into().unwrap());
    let hi = u128::from_le_bytes(prev_state_root[16..].try_into().unwrap());
    ch.observe_field_elem(Block128::from(lo));
    ch.observe_field_elem(Block128::from(hi));

    ch.observe_field_elem(Block128::from(claims.len() as u128));
    ch.observe_field_elem(Block128::from(effective_log_seg as u128));

    for c in claims {
        ch.observe_field_elem(Block128::from(c.slot_index as u128));
        ch.observe_field_elem(c.value);
        ch.observe_field_elem(c.owner_hi);
        ch.observe_field_elem(c.owner_lo);
        let action = if c.is_spend {
            1u128
        } else if c.is_mint {
            2u128
        } else {
            0u128
        };
        ch.observe_field_elem(Block128::from(action));
    }

    let eval_point = ch.get_random_points(effective_log_seg);
    let gamma = ch.get_random_point();
    (eval_point, gamma)
}

// ---------------------------------------------------------------------------
// Evaluate segment columns at a random point
// ---------------------------------------------------------------------------

fn eval_segment_columns_at(
    state: &mut SegmentedFriState,
    seg_id: u16,
    point: &[Block128],
) -> [Block128; 3] {
    let (values, owners_hi, owners_lo) = state.columns_for_segment(seg_id);
    [
        evaluate_slice(values, point),
        evaluate_slice(owners_hi, point),
        evaluate_slice(owners_lo, point),
    ]
}

// ---------------------------------------------------------------------------
// Build one state binding AIR for one segment
// ---------------------------------------------------------------------------

fn build_state_binding_for_segment(
    prev_state_root: &[u8; 32],
    seg_id: u16,
    prev_state: &mut SegmentedFriState,
    new_state: &mut SegmentedFriState,
    bodies: &[TxBody],
) -> (BlockStateBindingAir, Vec<Vec<Block128>>) {
    let eff = prev_state.effective_log_segment_size();
    let all_claims = build_claims_from_bodies(bodies);
    let seg_claims = claims_for_segment(&all_claims, seg_id, eff);
    let (eval_point, gamma) = derive_state_binding_challenges(prev_state_root, &seg_claims, eff);

    let prev_openings = eval_segment_columns_at(prev_state, seg_id, &eval_point);
    let new_openings = eval_segment_columns_at(new_state, seg_id, &eval_point);

    let witness = BlockStateBindingWitness::new(
        seg_claims.clone(),
        eval_point.clone(),
        gamma,
        prev_openings,
        new_openings,
    );
    let expected_batched = witness.expected_batched_claims();
    let air = BlockStateBindingAir::new(
        &seg_claims,
        prev_openings,
        new_openings,
        &eval_point,
        gamma,
        expected_batched,
    );
    let columns = air.build_trace(&witness);
    (air, columns)
}

/// Reconstruct the `BlockStateBindingAir` on the verifier side.
pub fn reconstruct_state_binding_air_for_segment(
    prev_state_root: &[u8; 32],
    seg_id: u16,
    prev_lane_openings: [Block128; 3],
    new_lane_openings: [Block128; 3],
    bodies: &[TxBody],
    effective_log_seg: usize,
) -> BlockStateBindingAir {
    let all_claims = build_claims_from_bodies(bodies);
    let seg_claims = claims_for_segment(&all_claims, seg_id, effective_log_seg);
    let (eval_point, gamma) =
        derive_state_binding_challenges(prev_state_root, &seg_claims, effective_log_seg);

    let witness = BlockStateBindingWitness::new(
        seg_claims.clone(),
        eval_point.clone(),
        gamma,
        prev_lane_openings,
        new_lane_openings,
    );
    let expected_batched = witness.expected_batched_claims();
    BlockStateBindingAir::new(
        &seg_claims,
        prev_lane_openings,
        new_lane_openings,
        &eval_point,
        gamma,
        expected_batched,
    )
}

// ---------------------------------------------------------------------------
// prove_block_full
// ---------------------------------------------------------------------------

pub fn prove_block_full<'a>(
    airs: &[&dyn Air],
    state: &mut SegmentedFriState,
    bodies: &[TxBody],
    logic_proofs: &[LogicProof],
    pis: &[PublicInputs],
    spine_inputs_list: &[SpineInputs],
    auth_public_list: &[AuthPublicInputs],
    witnesses: &[TxBlockWitness<'a>],
    // Block header for this block (used to compute the chain hash).
    block_header: &BlockHeader,
    // Accumulator from the previous block (or genesis accumulator at block 0).
    prev_acc: &ChainAccumulator,
    // Previous recursive proof (None for the first block after genesis).
    prev_rec_proof: Option<&RecursiveBlockProof>,
) -> Result<FullBlockProof, FullNodeProveError> {
    let n_tx = bodies.len();
    assert_eq!(airs.len(), n_tx);
    assert_eq!(logic_proofs.len(), n_tx);
    assert_eq!(pis.len(), n_tx);
    assert_eq!(spine_inputs_list.len(), n_tx);
    assert_eq!(auth_public_list.len(), n_tx);
    assert_eq!(witnesses.len(), n_tx);

    // Step 1: Verify LogicProofs.
    for k in 0..n_tx {
        verify_logic(
            airs[k],
            &pis[k],
            &spine_inputs_list[k],
            &auth_public_list[k],
            &logic_proofs[k],
        )
        .map_err(|e| FullNodeProveError::LogicProofInvalid {
            tx_index: k,
            inner: e,
        })?;
    }

    // Step 2: Snapshot the pre-state, then apply all tx state transitions.
    let prev_state_root = state.root();
    let mut prev_state_snapshot = state.clone();

    let commitments: Vec<_> = bodies
        .iter()
        .map(|b| compute_claims_commitment(&b.inputs, &b.outputs))
        .collect();
    let state_binding = BlockStateBinding::build(state, bodies, &commitments)?;
    // `state` now holds the post-state; `prev_state_snapshot` holds the pre-state.

    // Step 3: Determine which segments were touched (F.4 dirty tracking).
    // Use the slot indices from the bodies to find touched segment IDs.
    let eff = state.effective_log_segment_size();
    let touched_segs: Vec<u16> = {
        let mut ids: std::collections::BTreeSet<u16> = std::collections::BTreeSet::new();
        for body in bodies {
            for inp in body.inputs.iter().filter(|i| i.valid) {
                ids.insert((inp.slot_index >> eff) as u16);
            }
            for out in body.outputs.iter().filter(|o| o.valid) {
                ids.insert((out.slot_index >> eff) as u16);
            }
        }
        // In single-segment mode, always include segment 0.
        if state.num_segments() == 1 {
            ids.insert(0);
        }
        ids.into_iter().collect()
    };

    // Step 4: For each touched segment, build a state binding AIR.
    let mut sb_witnesses_storage: Vec<(BlockStateBindingAir, Vec<Vec<Block128>>)> = Vec::new();
    for &seg_id in &touched_segs {
        let pair = build_state_binding_for_segment(
            &prev_state_root,
            seg_id,
            &mut prev_state_snapshot,
            state,
            bodies,
        );
        sb_witnesses_storage.push(pair);
    }

    let sb_witnesses: Vec<StateBindingBlockWitness<'_>> = sb_witnesses_storage
        .iter()
        .map(|(air, cols)| StateBindingBlockWitness {
            air,
            columns: cols.clone(),
        })
        .collect();

    // Step 5: Build BlockProof with all segment state binding AIRs.
    let block_proof = prove_block(prev_state_root, witnesses, &sb_witnesses)?;

    // Step 6: Merkle Kill-Shot proofs (F.5) — one per touched segment.
    // In single-segment mode this loop is empty (tree_depth == 0, no Merkle path).
    let merkle_circuit = MerkleCircuit::build();
    let state_root = state.root();
    let mut merkle_killshots: Vec<MerkleProofKillShot> = Vec::new();

    if state.tree_depth() > 0 {
        use noid_core::TowerField;
        fn to_pair(d: &[u8; 32]) -> [Block128; 2] {
            let lo = Block128::from(u128::from_le_bytes(d[..16].try_into().unwrap()));
            let hi = Block128::from(u128::from_le_bytes(d[16..].try_into().unwrap()));
            [lo, hi]
        }

        for &seg_id in &touched_segs {
            let seg_root_bytes = state.seg_root(seg_id); // already computed
            let siblings_raw = state.merkle_siblings(seg_id);
            let active_depth = state.tree_depth();
            let mut siblings = [[Block128::ZERO; 2]; MAX_MERKLE_DEPTH];
            for (i, sib) in siblings_raw.iter().enumerate() {
                siblings[i] = to_pair(sib);
            }
            let inputs = MerklePathInputs {
                leaf: to_pair(&seg_root_bytes),
                siblings,
                expected_root: to_pair(&state_root),
                active_depth,
            };
            let mut ch = Poseidon2bChannel::new();
            let (proof, _) = noid_gkr::prove_merkle_killshot(&merkle_circuit, &inputs, &mut ch);
            merkle_killshots.push(proof);
        }
    }

    // Step 7: Recursive chain proof (Phase 7 / Stage H).
    // Extract the algebraic replay witness (no FRI paths) and prove.
    let block_replay_witness = BlockReplayWitness::from_parts(
        block_proof.commitment.cap.clone(),
        block_proof.state_binding_algebraics.clone(),
        block_proof.block_col_openings.clone(),
        block_proof.block_multipoint_rounds.clone(),
        block_proof.mixed_opening.fri_proof.clone(),
        block_proof.mixed_opening.all_openings.clone(),
    );
    let rec_proof = prove_recursive_step(
        &block_replay_witness,
        block_header,
        prev_acc,
        prev_rec_proof,
    );
    let new_acc = rec_proof.acc.clone();

    Ok(FullBlockProof {
        block_proof,
        state_binding,
        merkle_killshots,
        rec_proof,
        new_acc,
    })
}

// ---------------------------------------------------------------------------
// Recursive verify inputs
// ---------------------------------------------------------------------------

/// Inputs needed to perform O(1) chain verification via `verify_tip`.
///
/// When provided to `verify_block_full`, the function additionally verifies
/// the recursive chain proof included in `FullBlockProof.rec_proof`.
pub struct RecVerifyInputs<'a> {
    /// The `RecursiveBlockAir` instance (reconstructed from public block data).
    pub rec_air: &'a dyn noid_air::Air,
    /// Genesis accumulator — the protocol-level constant for this chain.
    pub genesis_acc: &'a ChainAccumulator,
    /// The block header for the tip block (used for chain_hash verification).
    pub tip_header: &'a BlockHeader,
}

// ---------------------------------------------------------------------------
// verify_block_full
// ---------------------------------------------------------------------------

pub fn verify_block_full(
    airs: &[&dyn Air],
    full_proof: &FullBlockProof,
    expected_new_state_root: &[u8; 32],
    spine_inputs_list: &[SpineInputs],
    auth_public_list: &[AuthPublicInputs],
    bodies: &[TxBody],
    // Per-segment (seg_id, prev_openings, new_openings) tuples provided by the block producer.
    segment_openings: &[(u16, [Block128; 3], [Block128; 3])],
    effective_log_seg: usize,
    _state_root: &[u8; 32],
    // Pre-built Merkle path inputs for Kill-Shot verification (one per touched segment).
    merkle_inputs: &[MerklePathInputs],
    // Recursive proof verification (optional — pass None to skip O(1) chain verify).
    rec_verify_inputs: Option<RecVerifyInputs<'_>>,
) -> Result<(), FullNodeVerifyError> {
    let bp = &full_proof.block_proof;
    let sb = &full_proof.state_binding;

    if sb.prev_state_root != bp.meta.prev_block_state_root {
        return Err(FullNodeVerifyError::StateRootMismatch);
    }

    // Step 1: Verify final state root.
    sb.verify_final_root(expected_new_state_root)
        .map_err(|_| FullNodeVerifyError::StateRootMismatch)?;

    // Step 2: Reconstruct state binding AIRs for all segments.
    let sb_airs: Vec<BlockStateBindingAir> = segment_openings
        .iter()
        .map(|(seg_id, prev_op, new_op)| {
            reconstruct_state_binding_air_for_segment(
                &bp.meta.prev_block_state_root,
                *seg_id,
                *prev_op,
                *new_op,
                bodies,
                effective_log_seg,
            )
        })
        .collect();
    let sb_air_refs: Vec<&BlockStateBindingAir> = sb_airs.iter().collect();

    // Step 3: Verify the cryptographic block proof.
    verify_block(airs, bp, spine_inputs_list, auth_public_list, &sb_air_refs)?;

    // Step 4: Verify Merkle Kill-Shots (F.5) — one per touched segment.
    let _merkle_circuit = MerkleCircuit::build(); // kept for symmetry with prover
    for (i, (inputs, proof)) in merkle_inputs
        .iter()
        .zip(full_proof.merkle_killshots.iter())
        .enumerate()
    {
        let mut ch = Poseidon2bChannel::new();
        if noid_gkr::verify_merkle_killshot(proof, inputs, &mut ch).is_none() {
            return Err(FullNodeVerifyError::MerkleKillShot { segment_idx: i });
        }
    }

    // Step 5 (optional): O(1) chain verification via recursive proof.
    if let Some(rvi) = rec_verify_inputs {
        // verify_tip checks rec_proof STARK + accumulator consistency.
        // The tip block itself was already verified in Step 3.
        verify_tip(
            &full_proof.rec_proof,
            rvi.rec_air,
            &full_proof.block_proof.meta.prev_block_state_root,
            rvi.tip_header.height,
            rvi.genesis_acc,
        )
        .map_err(|_| FullNodeVerifyError::RecursiveProofInvalid)?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_node_error_types_are_debug() {
        let e = FullNodeProveError::StateBinding(StateBindingError::FinalRootMismatch);
        let _ = format!("{:?}", e);
        let e2 = FullNodeVerifyError::StateRootMismatch;
        let _ = format!("{:?}", e2);
    }
}
