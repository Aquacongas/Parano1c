// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! The tx-body spine killshots in the trace.
//!
//! Trace twins of:
//! - [`verify_block_spine_killshot_trace`] ←
//!   `noid_gkr::block_spine::verify_block_spine_killshot` (Standard4x8,
//!   59 slots/tx) + the component discharge
//!   (`standard_tx_body_slot_state_ins` →
//!   `discharge_block_spine_reductions_native`), and
//! - [`verify_sweep_block_spine_killshot_trace`] ←
//!   `noid_gkr::block_spine_sweep::verify_sweep_block_spine_killshot`
//!   (Sweep25x2, 142 slots/tx) + `discharge_sweep_block_spine_reductions_native`.
//!
//! The discharge walks the native `SpineCircuit` / `SweepSpineCircuit`
//! descriptor tables (build-time structure) and rebuilds every slot's
//! `state_in` as an AFFINE combination of the leaf payload wires, the IV
//! constants and previous slots' permutation outputs (the oracle
//! `build_state_in` / `chain_absorb_pair` relations are all XOR chains) —
//! the permutation replay itself lives in [`ColumnAccumulator::push_slot`].
//! The wrap digests are bound to the `tx_body_hashes` wires by the killshot's
//! own `tx_hash_pins` linear relation, exactly as native.

use noid_core::{Block128, TowerField};
use noid_gkr::block_spine::{
    num_vars_for, BlockSpineProof, BLOCK_SPINE_TX_HASH_PIN_TAG,
};
use noid_gkr::block_spine_sweep::{SweepBlockSpineProof, SWEEP_BLOCK_SPINE_TX_HASH_PIN_TAG};
use noid_gkr::circuit_sweep::{
    SweepSpineCircuit, SweepSpineInputs, SweepSpineSlotRole, N_SWEEP_SPINE_SLOTS,
};
use noid_gkr::spine_sumcheck::N_SPINE_SLOTS;
use noid_gkr::tx_body_layout::InstanceRole;
use noid_gkr::{SpineCircuit, SpineInputs};
use noid_poseidon2b::native::permutation::{N_ROUNDS, STATE_SIZE};

use super::batch_eval::{
    verify_linear_eval_prebound_trace, LinearEvalClaimTrace, LinearEvalProofTrace,
    LinearEvalTermTrace, MultiBatchEvalProofTrace,
};
use super::block_spine::{
    close_spine_family_batch, spine_point_index, verify_block_spine_shift_trace,
    verify_block_spine_unified_trace, BlockSpineShiftProofTrace, BlockSpineUnifiedProofTrace,
    ColumnAccumulator,
};
use super::{
    alloc_block, const_block, BatchEvalReductionTrace, FieldR1csBuilder, LinExpr, RawChannelTrace,
};

/// Trace twin of the oracles' `padding_absorb_block` (`[0x80, 0x01 << 120]`).
fn padding_absorb_block_const() -> [LinExpr; 2] {
    [
        const_block(Block128::from(0x80u128)),
        const_block(Block128::from(0x01u128 << 120)),
    ]
}

// ---------------------------------------------------------------------------
// Statement wire types
// ---------------------------------------------------------------------------

/// Trace twin of `SpineInputs` (Standard4x8 leaf payloads).
pub struct SpineInputsTrace {
    pub epoch_anchor: [LinExpr; 2],
    pub fee_leaf: [LinExpr; 2],
    pub input_leaves: Vec<[LinExpr; 4]>,
    pub output_leaves: Vec<[LinExpr; 4]>,
    pub is_coinbase_leaf: [LinExpr; 2],
    pub pad_leaf: [LinExpr; 2],
}

impl SpineInputsTrace {
    pub fn alloc(b: &mut FieldR1csBuilder, native: &SpineInputs) -> Self {
        let quad = |b: &mut FieldR1csBuilder, v: &[Block128; 4]| -> [LinExpr; 4] {
            std::array::from_fn(|i| alloc_block(b, v[i]))
        };
        Self {
            epoch_anchor: std::array::from_fn(|i| alloc_block(b, native.epoch_anchor[i])),
            fee_leaf: std::array::from_fn(|i| alloc_block(b, native.fee_leaf[i])),
            input_leaves: native.input_leaves.iter().map(|l| quad(b, l)).collect(),
            output_leaves: native.output_leaves.iter().map(|l| quad(b, l)).collect(),
            is_coinbase_leaf: std::array::from_fn(|i| alloc_block(b, native.is_coinbase_leaf[i])),
            pad_leaf: std::array::from_fn(|i| alloc_block(b, native.pad_leaf[i])),
        }
    }
}

/// Trace twin of `SweepSpineInputs` (Sweep25x2 leaf payloads).
pub struct SweepSpineInputsTrace {
    pub epoch_anchor: [LinExpr; 2],
    pub fee_leaf: [LinExpr; 2],
    pub shape_leaf: [LinExpr; 2],
    pub input_leaves: Vec<[LinExpr; 4]>,
    pub output_leaves: Vec<[LinExpr; 4]>,
    pub is_coinbase_leaf: [LinExpr; 2],
    pub pad_leaf: [LinExpr; 2],
}

impl SweepSpineInputsTrace {
    pub fn alloc(b: &mut FieldR1csBuilder, native: &SweepSpineInputs) -> Self {
        let quad = |b: &mut FieldR1csBuilder, v: &[Block128; 4]| -> [LinExpr; 4] {
            std::array::from_fn(|i| alloc_block(b, v[i]))
        };
        Self {
            epoch_anchor: std::array::from_fn(|i| alloc_block(b, native.epoch_anchor[i])),
            fee_leaf: std::array::from_fn(|i| alloc_block(b, native.fee_leaf[i])),
            shape_leaf: std::array::from_fn(|i| alloc_block(b, native.shape_leaf[i])),
            input_leaves: native.input_leaves.iter().map(|l| quad(b, l)).collect(),
            output_leaves: native.output_leaves.iter().map(|l| quad(b, l)).collect(),
            is_coinbase_leaf: std::array::from_fn(|i| alloc_block(b, native.is_coinbase_leaf[i])),
            pad_leaf: std::array::from_fn(|i| alloc_block(b, native.pad_leaf[i])),
        }
    }
}

/// Trace twin of `BlockSpineProof` / `SweepBlockSpineProof` (identical wire
/// shape; the tag and slot count differ at the call sites).
pub struct TxBodySpineProofTrace {
    pub main: BlockSpineUnifiedProofTrace,
    pub shift: BlockSpineShiftProofTrace,
    pub tx_hash_pins: LinearEvalProofTrace,
    pub batch: MultiBatchEvalProofTrace,
    pub num_vars: usize,
    pub live_slots: usize,
}

impl TxBodySpineProofTrace {
    pub fn alloc_standard(
        b: &mut FieldR1csBuilder,
        native: &BlockSpineProof,
        n_instances: usize,
    ) -> Self {
        let live_slots = n_instances * N_SPINE_SLOTS;
        let num_vars = num_vars_for(live_slots);
        assert_eq!(native.live_slots, live_slots, "proof off the trace shape");
        assert_eq!(native.num_vars, num_vars, "proof off the trace shape");
        Self {
            main: BlockSpineUnifiedProofTrace::alloc(b, &native.kill_shot.main, num_vars),
            shift: BlockSpineShiftProofTrace::alloc(b, &native.kill_shot.shift, num_vars),
            tx_hash_pins: LinearEvalProofTrace::alloc(b, &native.tx_hash_pins, num_vars),
            batch: MultiBatchEvalProofTrace::alloc(b, &native.batch, num_vars, 3),
            num_vars,
            live_slots,
        }
    }

    pub fn alloc_sweep(
        b: &mut FieldR1csBuilder,
        native: &SweepBlockSpineProof,
        n_instances: usize,
    ) -> Self {
        let live_slots = n_instances * N_SWEEP_SPINE_SLOTS;
        let num_vars = num_vars_for(live_slots);
        assert_eq!(native.live_slots, live_slots, "proof off the trace shape");
        assert_eq!(native.num_vars, num_vars, "proof off the trace shape");
        Self {
            main: BlockSpineUnifiedProofTrace::alloc(b, &native.kill_shot.main, num_vars),
            shift: BlockSpineShiftProofTrace::alloc(b, &native.kill_shot.shift, num_vars),
            tx_hash_pins: LinearEvalProofTrace::alloc(b, &native.tx_hash_pins, num_vars),
            batch: MultiBatchEvalProofTrace::alloc(b, &native.batch, num_vars, 3),
            num_vars,
            live_slots,
        }
    }
}

// ---------------------------------------------------------------------------
// [K] — verifier replay (shared skeleton, per-variant slot counts and tags)
// ---------------------------------------------------------------------------

/// Trace twin of `tx_hash_pin_claims` (same helper in both variants; only
/// the slots-per-tx constant differs).
fn tx_hash_pin_claims_trace(
    tx_body_hashes: &[[LinExpr; 2]],
    slots_per_tx: usize,
    num_vars: usize,
) -> Vec<LinearEvalClaimTrace> {
    let mut claims = Vec::with_capacity(tx_body_hashes.len() * 2);
    for (tx_idx, tx_hash) in tx_body_hashes.iter().enumerate() {
        let wrap_slot = tx_idx * slots_per_tx + (slots_per_tx - 1);
        for lane in 0..2 {
            claims.push(LinearEvalClaimTrace {
                terms: vec![LinearEvalTermTrace {
                    index: spine_point_index(num_vars, wrap_slot, N_ROUNDS, lane),
                    coeff: Block128::ONE,
                }],
                value: tx_hash[lane].clone(),
            });
        }
    }
    claims
}

fn verify_tx_body_spine_killshot_trace(
    b: &mut FieldR1csBuilder,
    ch: &mut RawChannelTrace,
    proof: &TxBodySpineProofTrace,
    tx_body_hashes: &[[LinExpr; 2]],
    slots_per_tx: usize,
    pin_tag: u128,
) -> [BatchEvalReductionTrace; 3] {
    assert_eq!(proof.live_slots, tx_body_hashes.len() * slots_per_tx);
    assert_eq!(proof.num_vars, num_vars_for(proof.live_slots));

    // Absorb all tx_body_hashes (binds block contents).
    for hash in tx_body_hashes {
        ch.absorb(b, &hash[0]);
        ch.absorb(b, &hash[1]);
    }

    let main_red =
        verify_block_spine_unified_trace(b, ch, &proof.main, proof.num_vars, proof.live_slots);
    let shift_red = verify_block_spine_shift_trace(b, ch, &proof.shift, &main_red, proof.num_vars);

    let pin_claims = tx_hash_pin_claims_trace(tx_body_hashes, slots_per_tx, proof.num_vars);
    let pin_red = verify_linear_eval_prebound_trace(
        b,
        ch,
        &proof.tx_hash_pins,
        &pin_claims,
        proof.num_vars,
        pin_tag,
    );

    close_spine_family_batch(b, ch, &main_red, &shift_red, &pin_red, &proof.batch, proof.num_vars)
}

/// Trace twin of `verify_block_spine_killshot` (Standard4x8).
pub fn verify_block_spine_killshot_trace(
    b: &mut FieldR1csBuilder,
    ch: &mut RawChannelTrace,
    proof: &TxBodySpineProofTrace,
    tx_body_hashes: &[[LinExpr; 2]],
) -> [BatchEvalReductionTrace; 3] {
    verify_tx_body_spine_killshot_trace(
        b,
        ch,
        proof,
        tx_body_hashes,
        N_SPINE_SLOTS,
        BLOCK_SPINE_TX_HASH_PIN_TAG,
    )
}

/// Trace twin of `verify_sweep_block_spine_killshot` (Sweep25x2).
pub fn verify_sweep_block_spine_killshot_trace(
    b: &mut FieldR1csBuilder,
    ch: &mut RawChannelTrace,
    proof: &TxBodySpineProofTrace,
    tx_body_hashes: &[[LinExpr; 2]],
) -> [BatchEvalReductionTrace; 3] {
    verify_tx_body_spine_killshot_trace(
        b,
        ch,
        proof,
        tx_body_hashes,
        N_SWEEP_SPINE_SLOTS,
        SWEEP_BLOCK_SPINE_TX_HASH_PIN_TAG,
    )
}

// ---------------------------------------------------------------------------
// [D] — discharge replay (oracle build_state_in transliterations)
// ---------------------------------------------------------------------------

fn chain_absorb_pair_trace(
    prev_out: &[[LinExpr; STATE_SIZE]],
    src: usize,
    absorb: [LinExpr; 2],
) -> [LinExpr; STATE_SIZE] {
    let s = &prev_out[src];
    [
        s[0].add(&absorb[0]),
        s[1].add(&absorb[1]),
        s[2].clone(),
        s[3].clone(),
    ]
}

/// Trace twin of `oracle::build_state_in` + `evaluate_spine`, pushing every
/// slot into the accumulator. Returns nothing — the wrap binding happens via
/// the killshot's tx_hash_pins relation.
fn push_standard_spine_slots(
    b: &mut FieldR1csBuilder,
    acc: &mut ColumnAccumulator,
    circuit: &SpineCircuit,
    inputs: &SpineInputsTrace,
) {
    let mut outs: Vec<[LinExpr; STATE_SIZE]> = Vec::with_capacity(circuit.slots.len());
    let digest = |outs: &[[LinExpr; STATE_SIZE]], id: usize| -> [LinExpr; 2] {
        [outs[id][0].clone(), outs[id][1].clone()]
    };
    for slot in &circuit.slots {
        let [iv_hi, iv_lo] = slot.capacity_iv;
        let state_in: [LinExpr; STATE_SIZE] = match slot.role {
            InstanceRole::InputLeafPermA { leaf_idx } => {
                let p = &inputs.input_leaves[leaf_idx as usize];
                [
                    p[0].clone(),
                    p[1].clone(),
                    const_block(iv_hi),
                    const_block(iv_lo),
                ]
            }
            InstanceRole::InputLeafPermB { leaf_idx } => {
                let p = &inputs.input_leaves[leaf_idx as usize];
                chain_absorb_pair_trace(
                    &outs,
                    slot.prev_output_src.unwrap(),
                    [p[2].clone(), p[3].clone()],
                )
            }
            InstanceRole::InputLeafPermC { .. } => chain_absorb_pair_trace(
                &outs,
                slot.prev_output_src.unwrap(),
                padding_absorb_block_const(),
            ),
            InstanceRole::OutputLeafPermA { leaf_idx } => {
                let p = &inputs.output_leaves[leaf_idx as usize];
                [
                    p[0].clone(),
                    p[1].clone(),
                    const_block(iv_hi),
                    const_block(iv_lo),
                ]
            }
            InstanceRole::OutputLeafPermB { leaf_idx } => {
                let p = &inputs.output_leaves[leaf_idx as usize];
                chain_absorb_pair_trace(
                    &outs,
                    slot.prev_output_src.unwrap(),
                    [p[2].clone(), p[3].clone()],
                )
            }
            InstanceRole::CompressPermA { level, pos } => {
                let left = match slot.left_child {
                    Some(id) => digest(&outs, id),
                    None => resolve_standard_leaf(inputs, level, pos, true),
                };
                [
                    left[0].clone(),
                    left[1].clone(),
                    const_block(iv_hi),
                    const_block(iv_lo),
                ]
            }
            InstanceRole::CompressPermB { level, pos } => {
                let right = match slot.right_child {
                    Some(id) => digest(&outs, id),
                    None => resolve_standard_leaf(inputs, level, pos, false),
                };
                chain_absorb_pair_trace(&outs, slot.prev_output_src.unwrap(), right)
            }
            InstanceRole::WrapPerm => {
                let root = digest(&outs, slot.left_child.unwrap());
                [
                    root[0].clone(),
                    root[1].clone(),
                    const_block(iv_hi),
                    const_block(iv_lo),
                ]
            }
        };
        let out = acc.push_slot(b, &state_in);
        outs.push(out);
    }
}

/// Trace twin of `oracle::resolve_child_digest`'s non-AIR branch.
fn resolve_standard_leaf(
    inputs: &SpineInputsTrace,
    level: u8,
    pos: u8,
    is_left: bool,
) -> [LinExpr; 2] {
    assert_eq!(level, 1, "non-AIR child outside level-1 compress");
    match (pos, is_left) {
        (0, true) => inputs.epoch_anchor.clone(),
        (0, false) => inputs.fee_leaf.clone(),
        (7, true) => inputs.is_coinbase_leaf.clone(),
        (7, false) => inputs.pad_leaf.clone(),
        _ => panic!("unexpected non-AIR child at compress (level={level}, pos={pos})"),
    }
}

/// Trace twin of `oracle_sweep::build_state_in` + `evaluate_sweep_spine`.
fn push_sweep_spine_slots(
    b: &mut FieldR1csBuilder,
    acc: &mut ColumnAccumulator,
    circuit: &SweepSpineCircuit,
    inputs: &SweepSpineInputsTrace,
) {
    let mut outs: Vec<[LinExpr; STATE_SIZE]> = Vec::with_capacity(circuit.slots.len());
    let digest = |outs: &[[LinExpr; STATE_SIZE]], id: usize| -> [LinExpr; 2] {
        [outs[id][0].clone(), outs[id][1].clone()]
    };
    for slot in &circuit.slots {
        let [iv_hi, iv_lo] = slot.capacity_iv;
        let state_in: [LinExpr; STATE_SIZE] = match slot.role {
            SweepSpineSlotRole::InputLeafPermA { leaf_idx } => {
                let p = &inputs.input_leaves[leaf_idx as usize];
                [
                    p[0].clone(),
                    p[1].clone(),
                    const_block(iv_hi),
                    const_block(iv_lo),
                ]
            }
            SweepSpineSlotRole::InputLeafPermB { leaf_idx } => {
                let p = &inputs.input_leaves[leaf_idx as usize];
                chain_absorb_pair_trace(
                    &outs,
                    slot.prev_output_src.unwrap(),
                    [p[2].clone(), p[3].clone()],
                )
            }
            SweepSpineSlotRole::InputLeafPermC { .. } => chain_absorb_pair_trace(
                &outs,
                slot.prev_output_src.unwrap(),
                padding_absorb_block_const(),
            ),
            SweepSpineSlotRole::OutputLeafPermA { leaf_idx } => {
                let p = &inputs.output_leaves[leaf_idx as usize];
                [
                    p[0].clone(),
                    p[1].clone(),
                    const_block(iv_hi),
                    const_block(iv_lo),
                ]
            }
            SweepSpineSlotRole::OutputLeafPermB { leaf_idx } => {
                let p = &inputs.output_leaves[leaf_idx as usize];
                chain_absorb_pair_trace(
                    &outs,
                    slot.prev_output_src.unwrap(),
                    [p[2].clone(), p[3].clone()],
                )
            }
            SweepSpineSlotRole::CompressPermA { level, pos } => {
                let left = match slot.left_child {
                    Some(id) => digest(&outs, id),
                    None => resolve_sweep_leaf(inputs, level, pos, true),
                };
                [
                    left[0].clone(),
                    left[1].clone(),
                    const_block(iv_hi),
                    const_block(iv_lo),
                ]
            }
            SweepSpineSlotRole::CompressPermB { level, pos } => {
                let right = match slot.right_child {
                    Some(id) => digest(&outs, id),
                    None => resolve_sweep_leaf(inputs, level, pos, false),
                };
                chain_absorb_pair_trace(&outs, slot.prev_output_src.unwrap(), right)
            }
            SweepSpineSlotRole::WrapPerm => {
                let root = digest(&outs, slot.left_child.unwrap());
                [
                    root[0].clone(),
                    root[1].clone(),
                    const_block(iv_hi),
                    const_block(iv_lo),
                ]
            }
        };
        let out = acc.push_slot(b, &state_in);
        outs.push(out);
    }
}

/// Trace twin of `oracle_sweep::resolve_child_digest`'s non-AIR branch.
fn resolve_sweep_leaf(
    inputs: &SweepSpineInputsTrace,
    level: u8,
    pos: u8,
    is_left: bool,
) -> [LinExpr; 2] {
    assert_eq!(level, 1, "non-AIR sweep child outside level-1 compress");
    match (pos, is_left) {
        (0, true) => inputs.epoch_anchor.clone(),
        (0, false) => inputs.fee_leaf.clone(),
        (1, true) => inputs.shape_leaf.clone(),
        (15, true) => inputs.is_coinbase_leaf.clone(),
        (15, false) => inputs.pad_leaf.clone(),
        _ => panic!("unexpected non-AIR sweep child at compress (level={level}, pos={pos})"),
    }
}

/// Trace twin of the standard component discharge
/// (`standard_tx_body_slot_state_ins` + `discharge_block_spine_reductions_native`).
pub fn discharge_standard_tx_body_trace(
    b: &mut FieldR1csBuilder,
    inputs: &[SpineInputsTrace],
    reductions: &[BatchEvalReductionTrace; 3],
) {
    assert!(!inputs.is_empty());
    let circuit = SpineCircuit::build();
    let live_slots = inputs.len() * N_SPINE_SLOTS;
    let mut acc = ColumnAccumulator::new(b, &reductions[0].point, live_slots);
    for input in inputs {
        push_standard_spine_slots(b, &mut acc, &circuit, input);
    }
    let (state_value, sin_value, sout_value) = acc.finish();
    super::pin_zero(b, &state_value.add(&reductions[0].value));
    super::pin_zero(b, &sin_value.add(&reductions[1].value));
    super::pin_zero(b, &sout_value.add(&reductions[2].value));
}

/// Trace twin of `discharge_sweep_block_spine_reductions_native`.
pub fn discharge_sweep_tx_body_trace(
    b: &mut FieldR1csBuilder,
    inputs: &[SweepSpineInputsTrace],
    reductions: &[BatchEvalReductionTrace; 3],
) {
    assert!(!inputs.is_empty());
    let circuit = SweepSpineCircuit::build();
    let live_slots = inputs.len() * N_SWEEP_SPINE_SLOTS;
    let mut acc = ColumnAccumulator::new(b, &reductions[0].point, live_slots);
    for input in inputs {
        push_sweep_spine_slots(b, &mut acc, &circuit, input);
    }
    let (state_value, sin_value, sout_value) = acc.finish();
    super::pin_zero(b, &state_value.add(&reductions[0].value));
    super::pin_zero(b, &sin_value.add(&reductions[1].value));
    super::pin_zero(b, &sout_value.add(&reductions[2].value));
}

// ---------------------------------------------------------------------------
// Full slot assembly (component twins of `verify_standard_tx_body_component`
// / `verify_sweep_tx_body_component`: killshot on a fresh channel + discharge)
// ---------------------------------------------------------------------------

/// Standard4x8 [K]+[D] slot. Returns the input wires and the tx-body-hash
/// wires (shared with any other slot that consumes the same hashes — e.g.
/// the tx-root Merkle leaves and the receipt bindings).
pub fn build_standard_tx_body_slot(
    b: &mut FieldR1csBuilder,
    proof: &BlockSpineProof,
    inputs: &[SpineInputs],
    tx_body_hashes: &[[Block128; 2]],
) -> (Vec<SpineInputsTrace>, Vec<[LinExpr; 2]>) {
    assert_eq!(inputs.len(), tx_body_hashes.len());
    let inputs_t: Vec<SpineInputsTrace> = inputs
        .iter()
        .map(|i| SpineInputsTrace::alloc(b, i))
        .collect();
    let hashes_t: Vec<[LinExpr; 2]> = tx_body_hashes
        .iter()
        .map(|h| std::array::from_fn(|i| alloc_block(b, h[i])))
        .collect();
    let proof_t = TxBodySpineProofTrace::alloc_standard(b, proof, inputs.len());
    let mut ch = RawChannelTrace::new();
    let reds = verify_block_spine_killshot_trace(b, &mut ch, &proof_t, &hashes_t);
    discharge_standard_tx_body_trace(b, &inputs_t, &reds);
    (inputs_t, hashes_t)
}

/// Sweep25x2 [K]+[D] slot.
pub fn build_sweep_tx_body_slot(
    b: &mut FieldR1csBuilder,
    proof: &SweepBlockSpineProof,
    inputs: &[SweepSpineInputs],
    tx_body_hashes: &[[Block128; 2]],
) -> (Vec<SweepSpineInputsTrace>, Vec<[LinExpr; 2]>) {
    assert_eq!(inputs.len(), tx_body_hashes.len());
    let inputs_t: Vec<SweepSpineInputsTrace> = inputs
        .iter()
        .map(|i| SweepSpineInputsTrace::alloc(b, i))
        .collect();
    let hashes_t: Vec<[LinExpr; 2]> = tx_body_hashes
        .iter()
        .map(|h| std::array::from_fn(|i| alloc_block(b, h[i])))
        .collect();
    let proof_t = TxBodySpineProofTrace::alloc_sweep(b, proof, inputs.len());
    let mut ch = RawChannelTrace::new();
    let reds = verify_sweep_block_spine_killshot_trace(b, &mut ch, &proof_t, &hashes_t);
    discharge_sweep_tx_body_trace(b, &inputs_t, &reds);
    (inputs_t, hashes_t)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use noid_gkr::block_spine::{
        discharge_block_spine_reductions_native, prove_block_spine_killshot,
        verify_block_spine_killshot, BlockSpineMle,
    };
    use noid_gkr::block_spine_sweep::{
        discharge_sweep_block_spine_reductions_native, prove_sweep_block_spine_killshot,
        verify_sweep_block_spine_killshot, SweepBlockSpineMle,
    };
    use noid_gkr::spine_sumcheck::reconstruct_slot_states;
    use noid_gkr::spine_sumcheck_sweep::reconstruct_sweep_spine_slot_states;
    use noid_poseidon2b::channel::Poseidon2bChannel;

    fn standard_inputs(seed: u128) -> SpineInputs {
        SpineInputs {
            epoch_anchor: [Block128::from(seed + 11), Block128::from(seed + 22)],
            fee_leaf: [Block128::from(seed + 33), Block128::from(seed + 44)],
            input_leaves: [[Block128::from(seed + 1); 4]; 4],
            output_leaves: [[Block128::from(seed + 2); 4]; 8],
            is_coinbase_leaf: [Block128::from(seed + 55), Block128::from(seed + 66)],
            pad_leaf: [Block128::from(0u128), Block128::from(0u128)],
        }
    }

    fn sweep_inputs(seed: u128) -> SweepSpineInputs {
        SweepSpineInputs {
            epoch_anchor: [Block128::from(seed + 11), Block128::from(seed + 22)],
            fee_leaf: [Block128::from(seed + 33), Block128::ZERO],
            shape_leaf: [Block128::ONE, Block128::ZERO],
            input_leaves: std::array::from_fn(|i| {
                [
                    Block128::from(seed + 100 + i as u128),
                    Block128::from(seed + 200 + i as u128),
                    Block128::from(seed + 300 + i as u128),
                    Block128::from(seed + 400 + i as u128),
                ]
            }),
            output_leaves: std::array::from_fn(|i| {
                [
                    Block128::from(seed + 500 + i as u128),
                    Block128::from(seed + 600 + i as u128),
                    Block128::from(seed + 700 + i as u128),
                    Block128::from(seed + 800 + i as u128),
                ]
            }),
            is_coinbase_leaf: [Block128::ZERO, Block128::ZERO],
            pad_leaf: [Block128::ZERO, Block128::ZERO],
        }
    }

    struct StandardFixture {
        proof: BlockSpineProof,
        inputs: Vec<SpineInputs>,
        hashes: Vec<[Block128; 2]>,
    }

    fn standard_fixture(n: usize) -> StandardFixture {
        let circuit = SpineCircuit::build();
        let inputs: Vec<SpineInputs> = (0..n).map(|i| standard_inputs(i as u128 * 97)).collect();
        let mut all_state_ins = Vec::new();
        let mut hashes = Vec::new();
        for input in &inputs {
            let states = reconstruct_slot_states(&circuit, input);
            all_state_ins.extend(states.iter().map(|(s, _)| *s));
            let wrap = states.last().unwrap();
            hashes.push([wrap.1[0], wrap.1[1]]);
        }
        let mle = BlockSpineMle::build(n, &all_state_ins);
        let mut ch = Poseidon2bChannel::new();
        let (proof, _) = prove_block_spine_killshot(n, &mle, &hashes, &mut ch);
        StandardFixture {
            proof,
            inputs,
            hashes,
        }
    }

    fn standard_native_accepts(f: &StandardFixture) -> bool {
        let circuit = SpineCircuit::build();
        let mut ch = Poseidon2bChannel::new();
        let Some(red) =
            verify_block_spine_killshot(&f.proof, f.inputs.len(), &f.hashes, &mut ch)
        else {
            return false;
        };
        let mut slot_state_ins = Vec::new();
        for input in &f.inputs {
            slot_state_ins.extend(
                reconstruct_slot_states(&circuit, input)
                    .iter()
                    .map(|(s, _)| *s),
            );
        }
        discharge_block_spine_reductions_native(f.inputs.len(), &slot_state_ins, &red)
    }

    fn standard_trace_accepts(f: &StandardFixture) -> bool {
        let mut b = FieldR1csBuilder::new();
        let _ = build_standard_tx_body_slot(&mut b, &f.proof, &f.inputs, &f.hashes);
        let (r1cs, z) = b.build();
        r1cs.satisfies(&z)
    }

    #[test]
    fn standard_tx_body_trace_positive() {
        for n in [1usize, 2] {
            let f = standard_fixture(n);
            assert!(standard_native_accepts(&f), "native fixture broken");
            let mut b = FieldR1csBuilder::new();
            let _ = build_standard_tx_body_slot(&mut b, &f.proof, &f.inputs, &f.hashes);
            let (r1cs, z) = b.build();
            assert!(r1cs.satisfies(&z), "honest standard spine trace unsat (n={n})");
            if n == 1 {
                eprintln!(
                    "standard tx-body slot (1 tx): {} useful rows (k_log = {})",
                    r1cs.useful_rows, r1cs.k_log
                );
            }
        }
    }

    #[test]
    fn sweep_tx_body_trace_positive() {
        let circuit = SweepSpineCircuit::build();
        let inputs = vec![sweep_inputs(5)];
        let states = reconstruct_sweep_spine_slot_states(&circuit, &inputs[0]);
        let wrap = states.last().unwrap();
        let hashes = vec![[wrap.1[0], wrap.1[1]]];
        let mle = SweepBlockSpineMle::build(&inputs);
        let mut ch = Poseidon2bChannel::new();
        let (proof, _) = prove_sweep_block_spine_killshot(1, &mle, &hashes, &mut ch);

        let mut ch_n = Poseidon2bChannel::new();
        let red = verify_sweep_block_spine_killshot(&proof, 1, &hashes, &mut ch_n)
            .expect("native sweep accepts");
        assert!(discharge_sweep_block_spine_reductions_native(&inputs, &red));

        let mut b = FieldR1csBuilder::new();
        let _ = build_sweep_tx_body_slot(&mut b, &proof, &inputs, &hashes);
        let (r1cs, z) = b.build();
        assert!(r1cs.satisfies(&z), "honest sweep spine trace unsatisfiable");
        eprintln!(
            "sweep tx-body slot (1 tx): {} useful rows (k_log = {})",
            r1cs.useful_rows, r1cs.k_log
        );

        // Negative twin: tampered terminal claim → native rejects, trace unsat.
        let mut bad = proof.clone();
        bad.kill_shot.shift.state_at_r2 += Block128::ONE;
        let mut ch_bad = Poseidon2bChannel::new();
        assert!(verify_sweep_block_spine_killshot(&bad, 1, &hashes, &mut ch_bad).is_none());
        let mut b2 = FieldR1csBuilder::new();
        let _ = build_sweep_tx_body_slot(&mut b2, &bad, &inputs, &hashes);
        let (r1cs2, z2) = b2.build();
        assert!(!r1cs2.satisfies(&z2), "tampered sweep trace satisfiable");
    }

    fn visit_spine_proof_fields(p: &mut BlockSpineProof, f: &mut dyn FnMut(&mut Block128)) {
        for rp in &mut p.kill_shot.main.round_polys {
            for c in &mut rp.coeffs {
                f(c);
            }
        }
        f(&mut p.kill_shot.main.s_in_dec_at_r);
        f(&mut p.kill_shot.main.s_out_dec_at_r);
        f(&mut p.kill_shot.main.state_dec_at_r);
        f(&mut p.kill_shot.main.state_at_r);
        for v in &mut p.kill_shot.main.s_out_lane_dec_at_r {
            f(v);
        }
        for v in &mut p.kill_shot.main.state_lane_dec_at_r {
            f(v);
        }
        for rp in &mut p.kill_shot.shift.round_polys {
            for c in &mut rp.coeffs {
                f(c);
            }
        }
        f(&mut p.kill_shot.shift.s_in_at_r2);
        f(&mut p.kill_shot.shift.s_out_at_r2);
        f(&mut p.kill_shot.shift.state_at_r2);
        for r in &mut p.tx_hash_pins.rounds {
            for e in &mut r.evals {
                f(e);
            }
        }
        f(&mut p.tx_hash_pins.b_final);
        for r in &mut p.batch.rounds {
            for e in &mut r.evals {
                f(e);
            }
        }
        for v in &mut p.batch.b_finals {
            f(v);
        }
    }

    /// Replay-completeness auto-mutator (proof side, Standard4x8 @1 tx).
    /// 0 surviving mutants.
    #[test]
    fn standard_tx_body_proof_mutator_kills_all() {
        let f = standard_fixture(1);
        let mut n_fields = 0usize;
        {
            let mut c = f.proof.clone();
            visit_spine_proof_fields(&mut c, &mut |_| n_fields += 1);
        }
        let stride: usize = std::env::var("NOID_TRACE_MUTATE_STRIDE")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(1);

        let mut survivors = Vec::new();
        for target in (0..n_fields).step_by(stride) {
            let mut bad_proof = f.proof.clone();
            let mut i = 0usize;
            visit_spine_proof_fields(&mut bad_proof, &mut |v| {
                if i == target {
                    *v += Block128::ONE;
                }
                i += 1;
            });
            let bad = StandardFixture {
                proof: bad_proof,
                inputs: f.inputs.clone(),
                hashes: f.hashes.clone(),
            };
            assert!(!standard_native_accepts(&bad), "native accepted mutant {target}");
            if standard_trace_accepts(&bad) {
                survivors.push(target);
            }
        }
        assert!(
            survivors.is_empty(),
            "surviving standard spine proof mutants: {survivors:?} of {n_fields}"
        );
    }

    /// Statement + discharge-data mutator: every leaf payload lane and
    /// tx hash lane.
    #[test]
    fn standard_tx_body_statement_mutator_kills_all() {
        let f = standard_fixture(1);
        // 2+2+16+32+2+2 = 56 input lanes + 2 hash lanes.
        let mutate = |target: usize| -> StandardFixture {
            let mut inputs = f.inputs.clone();
            let mut hashes = f.hashes.clone();
            let i0 = &mut inputs[0];
            match target {
                0 | 1 => i0.epoch_anchor[target] += Block128::ONE,
                2 | 3 => i0.fee_leaf[target - 2] += Block128::ONE,
                4..=19 => i0.input_leaves[(target - 4) / 4][(target - 4) % 4] += Block128::ONE,
                20..=51 => i0.output_leaves[(target - 20) / 4][(target - 20) % 4] += Block128::ONE,
                52 | 53 => i0.is_coinbase_leaf[target - 52] += Block128::ONE,
                54 | 55 => i0.pad_leaf[target - 54] += Block128::ONE,
                56 | 57 => hashes[0][target - 56] += Block128::ONE,
                _ => unreachable!(),
            }
            StandardFixture {
                proof: f.proof.clone(),
                inputs,
                hashes,
            }
        };
        let mut survivors = Vec::new();
        for target in 0..58 {
            let bad = mutate(target);
            assert!(
                !standard_native_accepts(&bad),
                "native accepted statement mutant {target}"
            );
            if standard_trace_accepts(&bad) {
                survivors.push(target);
            }
        }
        assert!(
            survivors.is_empty(),
            "surviving standard spine statement mutants: {survivors:?}"
        );
    }

    /// Cross-test "trace ⇔ native" on randomized honest/mutated cases.
    #[test]
    fn standard_tx_body_native_trace_equivalence() {
        let cases: usize = std::env::var("NOID_TRACE_CROSS_CASES")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(100);
        let mut seed = 0x5B1E_Fu128;
        let mut next = |m: u128| {
            seed = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(1);
            (seed >> 16) % m
        };

        let f = standard_fixture(1);
        let mut n_fields = 0usize;
        {
            let mut c = f.proof.clone();
            visit_spine_proof_fields(&mut c, &mut |_| n_fields += 1);
        }
        for case in 0..cases {
            let case_f = if case % 2 == 0 {
                StandardFixture {
                    proof: f.proof.clone(),
                    inputs: f.inputs.clone(),
                    hashes: f.hashes.clone(),
                }
            } else {
                let target = next(n_fields as u128) as usize;
                let mut bad_proof = f.proof.clone();
                let mut i = 0usize;
                visit_spine_proof_fields(&mut bad_proof, &mut |v| {
                    if i == target {
                        *v += Block128::ONE;
                    }
                    i += 1;
                });
                StandardFixture {
                    proof: bad_proof,
                    inputs: f.inputs.clone(),
                    hashes: f.hashes.clone(),
                }
            };
            assert_eq!(
                standard_native_accepts(&case_f),
                standard_trace_accepts(&case_f),
                "native/trace divergence on case {case}"
            );
        }
    }
}
